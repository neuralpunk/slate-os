// SPDX-License-Identifier: MIT OR Apache-2.0

//! The journal (jbd2), from the ext4 on-disk format documentation's
//! "Journal (jbd2)" chapter. Journal structures are big-endian.
//!
//! Recovery: a journal left needing recovery (the RECOVER incompat flag) is
//! replayed at mount, in the documented three steps: scan the log from
//! `s_start` for committed transactions, collect revocations, then copy
//! every logged block that is not revoked by the same or a later
//! transaction to its home location.
//!
//! Writing (ADR 0042): metadata blocks changed by operations collect in a
//! [`Txn`] in memory. A commit
//! 1. points the journal superblock at the log (`s_start` = `s_first`,
//!    `s_sequence` = this transaction);
//! 2. writes descriptor blocks and copies of the blocks there, then
//!    flushes: file data written before the commit (directly, "ordered"),
//!    the journal superblock and the log are all durable;
//! 3. writes the commit block and flushes: the transaction is committed;
//! 4. writes the blocks to their homes and flushes (the checkpoint).
//!
//! Every transaction starts again at `s_first`: once the next commit's
//! step 1 is on the disk, the previous transaction (checkpointed) no longer
//! matches the sequence there and cannot be replayed. Blocks freed in a
//! transaction are freed only by its commit and are never logged, so no
//! replay can write old metadata over a block that became file data;
//! revoke records are not needed. The log has no checksums: the flushes
//! order it (journal features other than 64-bit are cleared when Slate
//! takes the journal over).

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::layout::*;
use crate::{Disk, Error, Fs, Result, crc};

/// Journal superblock fields (byte offsets).
const JSB_BLOCKSIZE: usize = 0x0C;
const JSB_MAXLEN: usize = 0x10;
const JSB_FIRST: usize = 0x14;
const JSB_SEQUENCE: usize = 0x18;
const JSB_START: usize = 0x1C;
const JSB_COMPAT: usize = 0x24;
const JSB_INCOMPAT: usize = 0x28;
const JSB_UUID: usize = 0x30;
/// COMPAT_CHECKSUM: commit blocks carry a v1 checksum.
const COMPAT_CHECKSUM: u32 = 0x1;
/// Commit block: commit time, seconds (be64) and nanoseconds (be32).
const COMMIT_SEC: usize = 0x30;
const COMMIT_NSEC: usize = 0x38;

const MAGIC: u32 = 0xC03B_3998;
const DESCRIPTOR: u32 = 1;
const COMMIT: u32 = 2;
const SUPERBLOCK_V1: u32 = 3;
const SUPERBLOCK_V2: u32 = 4;
const REVOKE: u32 = 5;

const TAG_ESCAPE: u32 = 1;
const TAG_SAME_UUID: u32 = 2;
const TAG_LAST: u32 = 8;

const INCOMPAT_REVOKE: u32 = 0x1;
const INCOMPAT_64BIT: u32 = 0x2;
const INCOMPAT_ASYNC_COMMIT: u32 = 0x4;
const INCOMPAT_CSUM_V2: u32 = 0x8;
const INCOMPAT_CSUM_V3: u32 = 0x10;
const KNOWN_INCOMPAT: u32 =
    INCOMPAT_REVOKE | INCOMPAT_64BIT | INCOMPAT_ASYNC_COMMIT | INCOMPAT_CSUM_V2 | INCOMPAT_CSUM_V3;

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn put_be32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_be_bytes());
}

fn header(b: &mut [u8], kind: u32, seq: u32) {
    put_be32(b, 0, MAGIC);
    put_be32(b, 4, kind);
    put_be32(b, 8, seq);
}

/// A transaction being built: metadata blocks changed since the last
/// commit (their newest contents), and blocks freed meanwhile, which the
/// commit frees.
#[derive(Default)]
pub(crate) struct Txn {
    pub(crate) blocks: BTreeMap<u64, Vec<u8>>,
    pub(crate) deferred: Vec<(u64, u64)>,
    /// A commit is running: it must not start another.
    pub(crate) committing: bool,
}

/// The journal Slate writes to.
pub(crate) struct Writer {
    /// Where the journal's blocks are: (journal block, disk block, count).
    runs: Vec<(u32, u64, u32)>,
    maxlen: u32,
    first: u32,
    /// The sequence number of the next transaction.
    sequence: u32,
    incompat: u32,
    /// The journal superblock block, as last written.
    jsb: Vec<u8>,
}

impl Writer {
    fn tag_size(&self) -> usize {
        if self.incompat & INCOMPAT_64BIT != 0 { 12 } else { 8 }
    }

    /// Tags that fit in one descriptor block (the first one is followed by
    /// the journal's UUID).
    fn tags_per_descriptor(&self, block_size: usize) -> usize {
        (block_size - 12 - 16) / self.tag_size()
    }

    /// The most blocks one transaction can log.
    pub(crate) fn capacity(&self, block_size: usize) -> usize {
        let room = (self.maxlen - self.first) as usize - 1; // The commit block.
        let per = self.tags_per_descriptor(block_size);
        room * per / (per + 1)
    }

    /// The disk block holding journal block `l`.
    fn disk_block(&self, l: u32) -> u64 {
        for &(start, disk, len) in &self.runs {
            if l >= start && l < start + len {
                return disk + u64::from(l - start);
            }
        }
        unreachable!("journal block {l} is mapped at start")
    }
}

/// A block logged in a transaction: its home location and where its copy
/// is in the journal.
struct Logged {
    home: u64,
    journal_block: u32,
    escaped: bool,
}

struct Journal {
    ino: u32,
    raw: RawInode,
    maxlen: u32,
    first: u32,
    incompat: u32,
    seed: u32,
}

impl Journal {
    fn csum(&self) -> bool {
        self.incompat & (INCOMPAT_CSUM_V2 | INCOMPAT_CSUM_V3) != 0
    }
    fn tag_size(&self) -> usize {
        if self.incompat & INCOMPAT_CSUM_V3 != 0 {
            16
        } else if self.incompat & INCOMPAT_64BIT != 0 {
            12
        } else {
            8
        }
    }
    fn next(&self, b: u32) -> u32 {
        if b + 1 >= self.maxlen { self.first } else { b + 1 }
    }
}

impl<D: Disk> Fs<D> {
    fn journal_read(&mut self, j: &Journal, lblk: u32) -> Result<Vec<u8>> {
        let p = self.map(j.ino, &j.raw, lblk)?.start.ok_or(Error::Corrupt("hole in the journal"))?;
        let mut b = vec![0u8; self.block_size as usize];
        self.read_data(p, &mut b)?;
        Ok(b)
    }

    pub(crate) fn replay_journal(&mut self) -> Result<()> {
        let ino = self.sb.journal_inum();
        let raw = self.read_inode(ino)?;
        let mut j = Journal { ino, raw, maxlen: 0, first: 0, incompat: 0, seed: 0 };
        let mut jsb = self.journal_read(&j, 0)?;
        let kind = be32(&jsb, 4);
        if be32(&jsb, 0) != MAGIC || !(kind == SUPERBLOCK_V1 || kind == SUPERBLOCK_V2) {
            return Err(Error::Corrupt("bad journal superblock"));
        }
        if be32(&jsb, 0x0C) != self.block_size {
            return Err(Error::Unsupported("journal block size differs from the file system's"));
        }
        j.maxlen = be32(&jsb, 0x10);
        j.first = be32(&jsb, 0x14);
        let mut seq = be32(&jsb, 0x18);
        let start = be32(&jsb, 0x1C);
        if kind == SUPERBLOCK_V2 {
            j.incompat = be32(&jsb, 0x28);
            if j.incompat & !KNOWN_INCOMPAT != 0 {
                return Err(Error::Unsupported("journal features (fast commit?)"));
            }
        }
        if j.maxlen == 0 || j.first == 0 || j.first >= j.maxlen {
            return Err(Error::Corrupt("journal geometry"));
        }
        j.seed = crc::crc32c(!0, &jsb[0x30..0x40]);

        // Pass 1 and 2: committed transactions and their revocations.
        let mut transactions: Vec<(u32, Vec<Logged>)> = Vec::new();
        let mut revoked: BTreeMap<u64, u32> = BTreeMap::new();
        if start != 0 {
            let mut pos = start;
            let mut steps = 0u32;
            'log: loop {
                let mut logged = Vec::new();
                let mut revokes = Vec::new();
                loop {
                    steps += 1;
                    if steps > j.maxlen {
                        break 'log; // Wrapped all the way around.
                    }
                    let b = self.journal_read(&j, pos)?;
                    if be32(&b, 0) != MAGIC || be32(&b, 8) != seq {
                        break 'log; // The end of the log.
                    }
                    match be32(&b, 4) {
                        DESCRIPTOR => {
                            if j.csum() && !self.journal_tail_ok(&j, &b) {
                                break 'log;
                            }
                            let end = b.len() - if j.csum() { 4 } else { 0 };
                            let ts = j.tag_size();
                            let mut off = 12;
                            pos = j.next(pos);
                            while off + ts <= end {
                                let lo = u64::from(be32(&b, off));
                                let (flags, hi) = if j.incompat & INCOMPAT_CSUM_V3 != 0 {
                                    (be32(&b, off + 4), u64::from(be32(&b, off + 8)))
                                } else {
                                    let flags = u32::from(u16::from_be_bytes([b[off + 6], b[off + 7]]));
                                    let hi =
                                        if j.incompat & INCOMPAT_64BIT != 0 { u64::from(be32(&b, off + 8)) } else { 0 };
                                    (flags, hi)
                                };
                                let home = if j.incompat & INCOMPAT_64BIT != 0 { lo | (hi << 32) } else { lo };
                                logged.push(Logged { home, journal_block: pos, escaped: flags & TAG_ESCAPE != 0 });
                                pos = j.next(pos);
                                off += ts;
                                if flags & TAG_SAME_UUID == 0 {
                                    off += 16;
                                }
                                if flags & TAG_LAST != 0 {
                                    break;
                                }
                            }
                        }
                        COMMIT => {
                            if j.csum() && !self.journal_commit_ok(&j, &b) {
                                break 'log; // A torn commit: not committed.
                            }
                            pos = j.next(pos);
                            for blk in revokes {
                                let s = revoked.entry(blk).or_insert(seq);
                                *s = (*s).max(seq);
                            }
                            transactions.push((seq, logged));
                            seq = seq.wrapping_add(1);
                            continue 'log;
                        }
                        REVOKE => {
                            if j.csum() && !self.journal_tail_ok(&j, &b) {
                                break 'log;
                            }
                            let count = (be32(&b, 12) as usize).min(b.len());
                            let width = if j.incompat & INCOMPAT_64BIT != 0 { 8 } else { 4 };
                            let mut off = 16;
                            while off + width <= count {
                                let blk = if width == 8 {
                                    (u64::from(be32(&b, off)) << 32) | u64::from(be32(&b, off + 4))
                                } else {
                                    u64::from(be32(&b, off))
                                };
                                revokes.push(blk);
                                off += width;
                            }
                            pos = j.next(pos);
                        }
                        _ => break 'log,
                    }
                }
            }
        }

        // Pass 3: replay.
        let blocks = self.sb.blocks_count();
        for (tseq, logged) in &transactions {
            for l in logged {
                if revoked.get(&l.home).is_some_and(|&r| r >= *tseq) {
                    continue;
                }
                if l.home >= blocks {
                    return Err(Error::Corrupt("journal block out of range"));
                }
                let mut data = self.journal_read(&j, l.journal_block)?;
                if l.escaped {
                    data[..4].copy_from_slice(&MAGIC.to_be_bytes());
                }
                self.write_data(l.home, &data)?;
            }
        }

        // The log is empty now; the file system's superblock may itself have
        // been replayed, so re-read it before clearing the RECOVER flag.
        jsb[0x18..0x1C].copy_from_slice(&seq.to_be_bytes());
        jsb[0x1C..0x20].fill(0);
        if j.csum() {
            jsb[0xFC..0x100].fill(0);
            let c = crc::crc32c(!0, &jsb[..1024]);
            jsb[0xFC..0x100].copy_from_slice(&c.to_be_bytes());
        }
        let p = self.map(j.ino, &j.raw, 0)?.start.ok_or(Error::Corrupt("hole in the journal"))?;
        self.write_data(p, &jsb)?;
        let mut raw = vec![0u8; SUPERBLOCK_SIZE];
        self.disk.read(SUPERBLOCK_OFFSET, &mut raw)?;
        self.sb = Superblock(raw);
        if self.sb.magic() != MAGIC_EXT4 {
            return Err(Error::Corrupt("superblock after journal replay"));
        }
        let incompat = self.sb.incompat() & !feature::INCOMPAT_RECOVER;
        self.sb.set_incompat(incompat);
        self.write_superblock()?;
        self.disk.flush()
    }

    fn journal_tail_ok(&self, j: &Journal, b: &[u8]) -> bool {
        let n = b.len();
        let mut copy = b.to_vec();
        copy[n - 4..].fill(0);
        crc::crc32c(j.seed, &copy) == be32(b, n - 4)
    }

    fn journal_commit_ok(&self, j: &Journal, b: &[u8]) -> bool {
        let mut copy = b.to_vec();
        copy[16..20].fill(0);
        crc::crc32c(j.seed, &copy) == be32(b, 16)
    }
}

impl<D: Disk> Fs<D> {
    /// Take over the journal for writing, if the file system has one we
    /// can use (an inode journal, empty after recovery). Returns `None`
    /// without one. The caller sets RECOVER in the superblock and writes it
    /// before the first commit.
    pub(crate) fn open_journal(&mut self) -> Result<Option<Writer>> {
        if self.read_only
            || !self.sb.has_compat(feature::COMPAT_HAS_JOURNAL)
            || self.sb.has_incompat(feature::INCOMPAT_JOURNAL_DEV)
            || self.sb.journal_inum() == 0
        {
            return Ok(None);
        }
        let ino = self.sb.journal_inum();
        let raw = self.read_inode(ino)?;
        let j = Journal { ino, raw: raw.clone(), maxlen: 0, first: 0, incompat: 0, seed: 0 };
        let mut jsb = self.journal_read(&j, 0)?;
        let kind = be32(&jsb, 4);
        if be32(&jsb, 0) != MAGIC || !(kind == SUPERBLOCK_V1 || kind == SUPERBLOCK_V2) {
            return Err(Error::Corrupt("bad journal superblock"));
        }
        if be32(&jsb, JSB_BLOCKSIZE) != self.block_size {
            return Err(Error::Unsupported("journal block size differs from the file system's"));
        }
        let (maxlen, first) = (be32(&jsb, JSB_MAXLEN), be32(&jsb, JSB_FIRST));
        if first == 0 || first + 8 > maxlen || u64::from(maxlen) > raw.size() / u64::from(self.block_size) {
            return Err(Error::Corrupt("journal geometry"));
        }
        if be32(&jsb, JSB_START) != 0 {
            return Err(Error::Corrupt("journal not empty on a clean file system"));
        }
        let wide = self.sb.blocks_count() > u64::from(u32::MAX);
        let incompat = if wide { INCOMPAT_64BIT } else { 0 };
        if kind == SUPERBLOCK_V2 {
            let compat = be32(&jsb, JSB_COMPAT) & !COMPAT_CHECKSUM;
            put_be32(&mut jsb, JSB_COMPAT, compat);
            put_be32(&mut jsb, JSB_INCOMPAT, incompat);
            jsb[0xFC..0x100].fill(0);
        } else if wide {
            return Err(Error::Unsupported("a version 1 journal on a 64-bit file system"));
        }
        let mut runs = Vec::new();
        let mut l = 0;
        while l < maxlen {
            let run = self.map(ino, &raw, l)?;
            let disk = run.start.ok_or(Error::Corrupt("hole in the journal"))?;
            let len = run.len.min(maxlen - l).max(1);
            runs.push((l, disk, len));
            l += len;
        }
        let sequence = be32(&jsb, JSB_SEQUENCE);
        Ok(Some(Writer { runs, maxlen, first, sequence, incompat, jsb }))
    }

    /// Commit the running transaction. `apply_frees`: free the blocks
    /// freed in it first (not when an operation is half done and may hold
    /// copies of bitmaps).
    pub(crate) fn commit_txn(&mut self, apply_frees: bool) -> Result<()> {
        if self.journal.is_none() || self.txn.committing {
            return Ok(());
        }
        self.txn.committing = true;
        let r = self.commit_inner(apply_frees);
        self.txn.committing = false;
        r
    }

    fn commit_inner(&mut self, apply_frees: bool) -> Result<()> {
        if apply_frees {
            for (blk, count) in core::mem::take(&mut self.txn.deferred) {
                self.free_blocks_now(blk, count)?;
            }
        }
        let blocks: Vec<(u64, Vec<u8>)> = core::mem::take(&mut self.txn.blocks).into_iter().collect();
        let cap = self.journal.as_ref().map_or(1, |w| w.capacity(self.block_size as usize));
        // A transaction too big for the journal goes in pieces (only an
        // operation of hundreds of metadata blocks gets there).
        for piece in blocks.chunks(cap.max(1)) {
            self.log_and_checkpoint(piece)?;
        }
        // The frees are durable now: their blocks may go.
        self.issue_discards();
        Ok(())
    }

    fn log_and_checkpoint(&mut self, blocks: &[(u64, Vec<u8>)]) -> Result<()> {
        let bs = self.block_size as usize;
        let Some(mut w) = self.journal.take() else { return Ok(()) };
        let r = self.write_log(&mut w, blocks, bs);
        self.journal = Some(w);
        r
    }

    fn write_log(&mut self, w: &mut Writer, blocks: &[(u64, Vec<u8>)], bs: usize) -> Result<()> {
        let seq = w.sequence;
        // 1. The journal superblock points at this transaction.
        put_be32(&mut w.jsb, JSB_SEQUENCE, seq);
        put_be32(&mut w.jsb, JSB_START, w.first);
        self.disk.write(w.disk_block(0) * bs as u64, &w.jsb)?;
        // 2. Descriptors and copies, in journal order.
        let uuid: Vec<u8> = w.jsb[JSB_UUID..JSB_UUID + 16].to_vec();
        let per = w.tags_per_descriptor(bs);
        let ts = w.tag_size();
        let mut log: Vec<Vec<u8>> = Vec::with_capacity(blocks.len() + blocks.len() / per + 1);
        for group in blocks.chunks(per) {
            let mut desc = vec![0u8; bs];
            header(&mut desc, DESCRIPTOR, seq);
            let mut off = 12;
            let mut copies = Vec::with_capacity(group.len());
            for (i, (home, data)) in group.iter().enumerate() {
                let escaped = be32(data, 0) == MAGIC;
                let mut flags = 0;
                if i > 0 {
                    flags |= TAG_SAME_UUID;
                }
                if escaped {
                    flags |= TAG_ESCAPE;
                }
                if i + 1 == group.len() {
                    flags |= TAG_LAST;
                }
                put_be32(&mut desc, off, *home as u32);
                desc[off + 6..off + 8].copy_from_slice(&(flags as u16).to_be_bytes());
                if ts == 12 {
                    put_be32(&mut desc, off + 8, (*home >> 32) as u32);
                }
                off += ts;
                if i == 0 {
                    desc[off..off + 16].copy_from_slice(&uuid);
                    off += 16;
                }
                let mut copy = data.clone();
                if escaped {
                    copy[..4].fill(0);
                }
                copies.push(copy);
            }
            log.push(desc);
            log.extend(copies);
        }
        let mut pos = w.first;
        self.write_journal_blocks(w, pos, &log, bs)?;
        pos += log.len() as u32;
        self.disk.flush()?;
        // 3. The commit block.
        let mut commit = vec![0u8; bs];
        header(&mut commit, COMMIT, seq);
        let (sec, nsec) = self.disk.now();
        commit[COMMIT_SEC..COMMIT_SEC + 8].copy_from_slice(&(sec as u64).to_be_bytes());
        put_be32(&mut commit, COMMIT_NSEC, nsec);
        self.disk.write(w.disk_block(pos) * bs as u64, &commit)?;
        self.disk.flush()?;
        // 4. Checkpoint: the blocks to their homes, runs of neighbours at once.
        let mut i = 0;
        while i < blocks.len() {
            let mut n = 1;
            while i + n < blocks.len() && blocks[i + n].0 == blocks[i].0 + n as u64 && n < 64 {
                n += 1;
            }
            let mut buf = Vec::with_capacity(n * bs);
            for (_, data) in &blocks[i..i + n] {
                buf.extend_from_slice(data);
            }
            self.disk.write(blocks[i].0 * bs as u64, &buf)?;
            i += n;
        }
        self.disk.flush()?;
        w.sequence = seq.wrapping_add(1);
        Ok(())
    }

    /// Write `log` to the journal from journal block `pos`, joining blocks
    /// that are neighbours on the disk.
    fn write_journal_blocks(&mut self, w: &Writer, pos: u32, log: &[Vec<u8>], bs: usize) -> Result<()> {
        let mut i = 0;
        while i < log.len() {
            let start = w.disk_block(pos + i as u32);
            let mut n = 1;
            while i + n < log.len() && w.disk_block(pos + (i + n) as u32) == start + n as u64 && n < 64 {
                n += 1;
            }
            let mut buf = Vec::with_capacity(n * bs);
            for b in &log[i..i + n] {
                buf.extend_from_slice(b);
            }
            self.disk.write(start * bs as u64, &buf)?;
            i += n;
        }
        Ok(())
    }

    /// Commit everything and leave the journal empty (unmount).
    pub(crate) fn close_journal(&mut self) -> Result<()> {
        self.commit_txn(true)?;
        let Some(mut w) = self.journal.take() else { return Ok(()) };
        let bs = self.block_size as usize;
        put_be32(&mut w.jsb, JSB_SEQUENCE, w.sequence);
        put_be32(&mut w.jsb, JSB_START, 0);
        self.disk.write(w.disk_block(0) * bs as u64, &w.jsb)?;
        self.disk.flush()
    }
}

const MAGIC_EXT4: u16 = crate::layout::MAGIC;
