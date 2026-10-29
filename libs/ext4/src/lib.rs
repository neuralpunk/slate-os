// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ext4 file system, read and write, written from the ext4 on-disk
//! format documentation (ADR 0016).
//!
//! [`Fs`] works on any [`Disk`] and is single-threaded (`&mut self`); the
//! kernel wraps it in a sleeping lock. Metadata blocks go through a small
//! cache; with a journal, changed ones collect in a transaction that
//! [`Fs::commit`] writes through the journal (ADR 0042), else they are
//! written through. File data is transferred directly ("ordered": before
//! the commit that makes it reachable). Unlinked files still in use are
//! kept on the orphan list until freed. Supported:
//! extents and block maps (reading), flex_bg, 64bit, metadata_csum (and
//! gdt_csum), uninitialized groups, hashed (htree) directories for reading
//! (they become linear when modified), journal replay, symlinks, device
//! nodes. Not supported for writing: inline data, bigalloc, meta_bg,
//! encryption, casefolding, quotas, MMP.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod alloc_map;
mod cache;
pub mod crc;
mod dir;
mod extent;
mod journal;
pub mod layout;
mod ops;

use alloc::vec;
use alloc::vec::Vec;

use cache::Cache;
pub use dir::DirEntry;
use layout::*;
pub use ops::SetAttr;

/// Errors from file system operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The disk reported an error.
    Io,
    /// The on-disk structures are inconsistent.
    Corrupt(&'static str),
    /// The file system uses a feature Slate does not support.
    Unsupported(&'static str),
    /// Mounted read-only (or the features only allow reading).
    ReadOnly,
    NotFound,
    Exists,
    NotDir,
    IsDir,
    NotEmpty,
    NameTooLong,
    NoSpace,
    TooManyLinks,
    Invalid,
}

pub type Result<T> = core::result::Result<T, Error>;

/// Storage the file system lives on, addressed in bytes. Transfers are
/// always whole file-system blocks, aligned to the block size.
pub trait Disk {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()>;
    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<()>;
    /// Make written data durable.
    fn flush(&mut self) -> Result<()>;
    /// The current wall-clock time (seconds since the epoch, nanoseconds).
    fn now(&self) -> (i64, u32);
    /// The bytes hold nothing any more (TRIM); whole blocks. Disks that
    /// cannot take it do nothing.
    fn discard(&mut self, _offset: u64, _len: u64) -> Result<()> {
        Ok(())
    }
}

/// Inode metadata.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stat {
    pub ino: u32,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub links: u16,
    /// 512-byte sectors in use.
    pub blocks: u64,
    pub atime: (i64, u32),
    pub ctime: (i64, u32),
    pub mtime: (i64, u32),
    /// Device number for device nodes (Linux `dev_t` encoding).
    pub rdev: u64,
}

/// File system totals (statfs).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    pub block_size: u32,
    pub blocks: u64,
    pub free_blocks: u64,
    pub inodes: u64,
    pub free_inodes: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    pub read_only: bool,
}

/// A mounted ext4 file system.
pub struct Fs<D: Disk> {
    disk: D,
    sb: Superblock,
    block_size: u32,
    groups: Vec<GroupDesc>,
    group_count: u32,
    /// Seed for metadata checksums (crc32c of the UUID, or the stored seed).
    csum_seed: u32,
    metadata_csum: bool,
    gdt_csum: bool,
    read_only: bool,
    cache: Cache,
    /// Generation numbers for new inodes.
    next_generation: u32,
    /// Where the last block allocation ended (allocation goal).
    last_alloc: u64,
    /// The journal, when Slate writes through it.
    journal: Option<journal::Writer>,
    /// Metadata changed since the last commit.
    txn: journal::Txn,
    /// The mount replayed the journal (an unclean shutdown).
    recovered: bool,
    /// Online discard: freed blocks are discarded once the free is durable.
    discard: bool,
    /// Freed blocks waiting to be discarded: (first block, count).
    to_discard: Vec<(u64, u64)>,
}

impl<D: Disk> core::fmt::Debug for Fs<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Fs")
            .field("block_size", &self.block_size)
            .field("groups", &self.group_count)
            .finish_non_exhaustive()
    }
}

impl<D: Disk> Fs<D> {
    /// Read the superblock and group descriptors, replay the journal if it
    /// needs it, and get ready for use.
    pub fn mount(mut disk: D, opts: Options) -> Result<Fs<D>> {
        let mut raw = vec![0u8; SUPERBLOCK_SIZE];
        disk.read(SUPERBLOCK_OFFSET, &mut raw)?;
        let sb = Superblock(raw);
        if sb.magic() != MAGIC {
            return Err(Error::Corrupt("bad superblock magic"));
        }
        if sb.log_block_size() > 6 {
            return Err(Error::Corrupt("bad block size"));
        }
        let block_size = 1024u32 << sb.log_block_size();
        let unsupported = sb.incompat() & !feature::READ_INCOMPAT;
        if unsupported != 0 {
            return Err(Error::Unsupported(incompat_name(unsupported)));
        }
        if sb.blocks_per_group() == 0 || sb.inodes_per_group() == 0 || sb.inode_size() < 128 {
            return Err(Error::Corrupt("bad group geometry"));
        }
        if sb.blocks_per_group() != sb.clusters_per_group() {
            return Err(Error::Unsupported("bigalloc"));
        }
        let metadata_csum = sb.has_ro_compat(feature::RO_COMPAT_METADATA_CSUM);
        if metadata_csum && sb.checksum_type() != 1 {
            return Err(Error::Unsupported("checksum type"));
        }
        let csum_seed =
            if sb.has_incompat(feature::INCOMPAT_CSUM_SEED) { sb.checksum_seed() } else { crc::crc32c(!0, sb.uuid()) };
        if metadata_csum && crc::crc32c(!0, &sb.0[..0x3FC]) != sb.stored_checksum() {
            return Err(Error::Corrupt("superblock checksum"));
        }
        let data_blocks = sb.blocks_count() - u64::from(sb.first_data_block());
        let group_count = data_blocks.div_ceil(u64::from(sb.blocks_per_group())) as u32;
        if u64::from(group_count) * u64::from(sb.inodes_per_group()) < u64::from(sb.inodes_count()) {
            return Err(Error::Corrupt("inode count"));
        }
        let read_only = opts.read_only
            || sb.incompat() & !feature::WRITE_INCOMPAT & !feature::INCOMPAT_RECOVER != 0
            || sb.ro_compat() & !feature::WRITE_RO_COMPAT != 0;
        let mut fs = Fs {
            disk,
            block_size,
            groups: Vec::new(),
            group_count,
            csum_seed,
            metadata_csum,
            gdt_csum: sb.has_ro_compat(feature::RO_COMPAT_GDT_CSUM) && !metadata_csum,
            read_only,
            cache: Cache::new(),
            next_generation: 0,
            last_alloc: 0,
            journal: None,
            txn: journal::Txn::default(),
            recovered: false,
            discard: false,
            to_discard: Vec::new(),
            sb,
        };
        if fs.sb.has_incompat(feature::INCOMPAT_META_BG) {
            return Err(Error::Unsupported("meta_bg"));
        }
        // Before recovery the descriptors may be older than their checksums
        // (the journal holds the newer copies).
        let recover = fs.sb.has_incompat(feature::INCOMPAT_RECOVER);
        fs.read_groups(!recover)?;
        if recover {
            if fs.sb.has_incompat(feature::INCOMPAT_JOURNAL_DEV) || fs.sb.journal_inum() == 0 {
                return Err(Error::Unsupported("external journal"));
            }
            if fs.read_only {
                // Without replay the metadata may be stale; refuse rather
                // than show a half-updated file system.
                return Err(Error::ReadOnly);
            }
            fs.replay_journal()?;
            fs.recovered = true;
            fs.cache = Cache::new();
            fs.read_groups(true)?;
        }
        let (secs, nsec) = fs.disk.now();
        fs.next_generation = (secs as u32) ^ nsec;
        if !fs.read_only {
            // Mark the file system in use until `sync_and_close`: a crash
            // leaves it "not clean", so fsck checks it. With a journal it
            // also needs recovery from then on (until the journal is
            // emptied at unmount).
            let journal = fs.open_journal()?;
            if journal.is_some() {
                let incompat = fs.sb.incompat() | feature::INCOMPAT_RECOVER;
                fs.sb.set_incompat(incompat);
            }
            fs.sb.set_state(fs.sb.state() & !1);
            fs.sb.set_mnt_count(fs.sb.mnt_count().wrapping_add(1));
            fs.sb.set_mtime(secs as u32);
            fs.write_superblock()?;
            fs.disk.flush()?;
            fs.journal = journal;
            // Files unlinked while in use when the system stopped.
            fs.release_orphans()?;
            fs.commit()?;
        }
        Ok(fs)
    }

    fn read_groups(&mut self, verify: bool) -> Result<()> {
        let ds = self.sb.desc_size();
        let gdt_start = u64::from(self.sb.first_data_block()) + 1;
        let per_block = self.block_size as usize / ds;
        let mut groups = Vec::with_capacity(self.group_count as usize);
        let mut block = vec![0u8; self.block_size as usize];
        for g in 0..self.group_count as usize {
            if g % per_block == 0 {
                self.disk.read((gdt_start + (g / per_block) as u64) * u64::from(self.block_size), &mut block)?;
            }
            let at = (g % per_block) * ds;
            let d = GroupDesc(block[at..at + ds].to_vec());
            if verify && (self.metadata_csum || self.gdt_csum) && self.group_desc_csum(g as u32, &d) != d.checksum() {
                return Err(Error::Corrupt("group descriptor checksum"));
            }
            groups.push(d);
        }
        self.groups = groups;
        Ok(())
    }

    /// Unmount: commit, empty the journal, mark the file system clean and
    /// flush the disk.
    pub fn sync_and_close(&mut self) -> Result<()> {
        if !self.read_only {
            self.close_journal()?;
            let incompat = self.sb.incompat() & !feature::INCOMPAT_RECOVER;
            self.sb.set_incompat(incompat);
            self.sb.set_state(self.sb.state() | 1);
            self.write_superblock()?;
        }
        self.disk.flush()
    }

    /// Make everything written so far durable: commit the running
    /// transaction, then flush the disk's write cache.
    pub fn sync(&mut self) -> Result<()> {
        self.commit()?;
        self.disk.flush()
    }

    /// Commit the running transaction through the journal (without a
    /// journal, metadata is already written through).
    pub fn commit(&mut self) -> Result<()> {
        self.commit_txn(true)
    }

    /// Whether the running transaction has grown big enough to commit now
    /// (half of what the journal holds, or many freed ranges).
    pub fn commit_due(&self) -> bool {
        self.journal.as_ref().is_some_and(|w| {
            self.txn.blocks.len() >= w.capacity(self.block_size as usize) / 2 || self.txn.deferred.len() >= 256
        })
    }

    /// Whether the mount had to recover the journal (the file system was
    /// not unmounted cleanly).
    pub fn recovered(&self) -> bool {
        self.recovered
    }

    /// Online discard (the `discard` mount option): blocks are discarded
    /// as they are freed, once the free is committed.
    pub fn set_discard(&mut self, on: bool) {
        self.discard = on;
    }

    /// Discard the freed blocks waiting for it (errors are ignored: a
    /// discard is a hint).
    fn issue_discards(&mut self) {
        let bs = u64::from(self.block_size);
        for (blk, count) in core::mem::take(&mut self.to_discard) {
            let _ = self.disk.discard(blk * bs, count * bs);
        }
    }

    /// FITRIM: discard every free run of at least `min_len` bytes within
    /// `[start, start + len)` (bytes); returns the bytes discarded.
    pub fn trim(&mut self, start: u64, len: u64, min_len: u64) -> Result<u64> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        let bs = u64::from(self.block_size);
        let first = (start.div_ceil(bs)).max(u64::from(self.sb.first_data_block()));
        let end = (start.saturating_add(len) / bs).min(self.sb.blocks_count());
        let min_blocks = min_len.div_ceil(bs).max(1);
        let mut trimmed = 0;
        for (blk, count) in self.free_runs(first, end)? {
            if count >= min_blocks {
                self.disk.discard(blk * bs, count * bs)?;
                trimmed += count * bs;
            }
        }
        Ok(trimmed)
    }

    /// Whether writes go through a journal.
    pub fn journaled(&self) -> bool {
        self.journal.is_some()
    }

    pub fn read_only(&self) -> bool {
        self.read_only
    }

    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    pub fn label(&self) -> &[u8] {
        self.sb.volume_name()
    }

    pub fn totals(&self) -> Totals {
        Totals {
            block_size: self.block_size,
            blocks: self.sb.blocks_count(),
            // Blocks freed in the running transaction count as free already.
            free_blocks: self.sb.free_blocks() + self.txn.deferred.iter().map(|&(_, n)| n).sum::<u64>(),
            inodes: u64::from(self.sb.inodes_count()),
            free_inodes: u64::from(self.sb.free_inodes()),
        }
    }

    /// Give back the disk.
    pub fn into_disk(self) -> D {
        self.disk
    }

    // --- checksums ------------------------------------------------------

    fn group_desc_csum(&self, g: u32, d: &GroupDesc) -> u16 {
        if self.metadata_csum {
            let c = crc::crc32c(self.csum_seed, &g.to_le_bytes());
            let c = crc::crc32c(c, &d.0[..0x1E]);
            let c = crc::crc32c(c, &[0, 0]);
            let c = crc::crc32c(c, &d.0[0x20..]);
            c as u16
        } else {
            let c = crc::crc16(!0, self.sb.uuid());
            let c = crc::crc16(c, &g.to_le_bytes());
            let c = crc::crc16(c, &d.0[..0x1E]);
            if d.0.len() > 0x20 { crc::crc16(c, &d.0[0x20..]) } else { c }
        }
    }

    /// Per-inode checksum seed: crc32c of the inode number and generation.
    fn inode_seed(&self, ino: u32, generation: u32) -> u32 {
        let c = crc::crc32c(self.csum_seed, &ino.to_le_bytes());
        crc::crc32c(c, &generation.to_le_bytes())
    }

    fn inode_csum(&self, ino: u32, raw: &RawInode) -> u32 {
        let mut copy = raw.0.clone();
        put16(&mut copy, 0x7C, 0);
        let has_hi = raw.extra_isize() >= 4 && copy.len() > 128;
        if has_hi {
            put16(&mut copy, 0x82, 0);
        }
        let c = crc::crc32c(self.inode_seed(ino, raw.generation()), &copy);
        if has_hi { c } else { c & 0xFFFF }
    }

    fn write_superblock(&mut self) -> Result<()> {
        let (secs, _) = self.disk.now();
        self.sb.set_wtime(secs as u32);
        if self.metadata_csum {
            let c = crc::crc32c(!0, &self.sb.0[..0x3FC]);
            self.sb.set_checksum(c);
        }
        // The superblock is 1 KiB at byte 1024: write the block holding it.
        let bs = u64::from(self.block_size);
        let blk = SUPERBLOCK_OFFSET / bs;
        let mut b = self.read_block(blk)?;
        let at = (SUPERBLOCK_OFFSET % bs) as usize;
        b[at..at + SUPERBLOCK_SIZE].copy_from_slice(&self.sb.0);
        self.write_block(blk, &b)
    }

    fn write_group(&mut self, g: u32) -> Result<()> {
        let mut d = self.groups[g as usize].clone();
        if self.metadata_csum || self.gdt_csum {
            let c = self.group_desc_csum(g, &d);
            d.set_checksum(c);
            self.groups[g as usize] = d.clone();
        }
        let ds = self.sb.desc_size();
        let per_block = self.block_size as usize / ds;
        let blk = u64::from(self.sb.first_data_block()) + 1 + (g as usize / per_block) as u64;
        let mut b = self.read_block(blk)?;
        let at = (g as usize % per_block) * ds;
        b[at..at + ds].copy_from_slice(&d.0);
        self.write_block(blk, &b)
    }

    // --- blocks -----------------------------------------------------------

    /// A metadata block, through the cache.
    fn read_block(&mut self, blk: u64) -> Result<Vec<u8>> {
        if blk >= self.sb.blocks_count() {
            return Err(Error::Corrupt("block number out of range"));
        }
        if let Some(b) = self.txn.blocks.get(&blk) {
            return Ok(b.clone());
        }
        if let Some(b) = self.cache.get(blk) {
            return Ok(b.to_vec());
        }
        let mut b = vec![0u8; self.block_size as usize];
        self.disk.read(blk * u64::from(self.block_size), &mut b)?;
        self.cache.insert(blk, &b);
        Ok(b)
    }

    /// Write a metadata block: into the running transaction with a
    /// journal, else through to the disk.
    fn write_block(&mut self, blk: u64, data: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        if blk >= self.sb.blocks_count() {
            return Err(Error::Corrupt("block number out of range"));
        }
        self.cache.insert(blk, data);
        let Some(w) = &self.journal else {
            return self.disk.write(blk * u64::from(self.block_size), data);
        };
        let full = self.txn.blocks.len() >= w.capacity(self.block_size as usize);
        self.txn.blocks.insert(blk, data.to_vec());
        if full {
            // The journal cannot take more: commit mid-operation.
            self.commit_txn(false)?;
        }
        Ok(())
    }

    /// Read `n` consecutive data blocks straight from the disk.
    fn read_data(&mut self, blk: u64, buf: &mut [u8]) -> Result<()> {
        let n = (buf.len() / self.block_size as usize) as u64;
        if blk + n > self.sb.blocks_count() {
            return Err(Error::Corrupt("block number out of range"));
        }
        self.disk.read(blk * u64::from(self.block_size), buf)
    }

    /// Write consecutive data blocks straight to the disk.
    fn write_data(&mut self, blk: u64, buf: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        let n = (buf.len() / self.block_size as usize) as u64;
        if blk + n > self.sb.blocks_count() {
            return Err(Error::Corrupt("block number out of range"));
        }
        for b in blk..blk + n {
            self.cache.remove(b);
            self.txn.blocks.remove(&b);
        }
        self.disk.write(blk * u64::from(self.block_size), buf)
    }

    // --- inodes -----------------------------------------------------------

    fn inode_location(&self, ino: u32) -> Result<(u64, usize)> {
        if ino == 0 || ino > self.sb.inodes_count() {
            return Err(Error::Corrupt("inode number out of range"));
        }
        let ipg = self.sb.inodes_per_group();
        let g = (ino - 1) / ipg;
        let index = u64::from((ino - 1) % ipg);
        let isz = u64::from(self.sb.inode_size());
        let table = self.groups[g as usize].inode_table();
        let byte = index * isz;
        let bs = u64::from(self.block_size);
        Ok((table + byte / bs, (byte % bs) as usize))
    }

    fn read_inode(&mut self, ino: u32) -> Result<RawInode> {
        let (blk, at) = self.inode_location(ino)?;
        let b = self.read_block(blk)?;
        let raw = RawInode(b[at..at + usize::from(self.sb.inode_size())].to_vec());
        if self.metadata_csum {
            let want = self.inode_csum(ino, &raw);
            let mut got = u32::from(get16(&raw.0, 0x7C));
            if raw.extra_isize() >= 4 && raw.0.len() > 128 {
                got |= u32::from(get16(&raw.0, 0x82)) << 16;
            }
            if want != got {
                return Err(Error::Corrupt("inode checksum"));
            }
        }
        Ok(raw)
    }

    fn write_inode(&mut self, ino: u32, raw: &mut RawInode) -> Result<()> {
        if self.metadata_csum {
            let c = self.inode_csum(ino, raw);
            put16(&mut raw.0, 0x7C, c as u16);
            if raw.extra_isize() >= 4 && raw.0.len() > 128 {
                put16(&mut raw.0, 0x82, (c >> 16) as u16);
            }
        }
        let (blk, at) = self.inode_location(ino)?;
        let mut b = self.read_block(blk)?;
        b[at..at + raw.0.len()].copy_from_slice(&raw.0);
        self.write_block(blk, &b)
    }

    /// Bytes used per 512-byte unit of `i_blocks` for this inode.
    fn blocks_unit(&self, raw: &RawInode) -> u64 {
        if raw.flags() & HUGE_FILE_FL != 0 { u64::from(self.block_size) } else { 512 }
    }

    pub fn stat(&mut self, ino: u32) -> Result<Stat> {
        let raw = self.read_inode(ino)?;
        Ok(self.stat_of(ino, &raw))
    }

    fn stat_of(&self, ino: u32, raw: &RawInode) -> Stat {
        let rdev = match raw.file_type() {
            S_IFCHR | S_IFBLK => decode_rdev(raw.i_block()),
            _ => 0,
        };
        Stat {
            ino,
            mode: raw.mode(),
            uid: raw.uid(),
            gid: raw.gid(),
            size: raw.size(),
            links: raw.links(),
            blocks: raw.blocks_raw() * self.blocks_unit(raw) / 512,
            atime: raw.time(0),
            ctime: raw.time(1),
            mtime: raw.time(2),
            rdev,
        }
    }
}

/// Device numbers in `i_block`: the old 16-bit form in word 0, or the
/// 32-bit form in word 1, both converted to Linux's `dev_t` layout
/// (major in bits 8-19 and 32-43, minor in bits 0-7 and 12-31... as
/// `makedev` builds it).
fn decode_rdev(b: &[u8]) -> u64 {
    let w0 = get32(b, 0);
    let (major, minor) = if w0 != 0 {
        ((w0 >> 8) & 0xFF, w0 & 0xFF)
    } else {
        let w1 = get32(b, 4);
        ((w1 >> 8) & 0xFFF, (w1 & 0xFF) | ((w1 >> 12) & 0xFFF00))
    };
    makedev(major, minor)
}

fn encode_rdev(rdev: u64, b: &mut [u8]) {
    let (major, minor) = (dev_major(rdev), dev_minor(rdev));
    b[..8].fill(0);
    if major < 256 && minor < 256 {
        put32(b, 0, (major << 8) | minor);
    } else {
        put32(b, 4, (minor & 0xFF) | (major << 8) | ((minor & !0xFF) << 12));
    }
}

/// Linux `dev_t` encoding (glibc/musl `makedev`).
pub fn makedev(major: u32, minor: u32) -> u64 {
    let (ma, mi) = (u64::from(major), u64::from(minor));
    ((ma & 0xFFF) << 8) | ((ma & !0xFFF) << 32) | (mi & 0xFF) | ((mi & !0xFF) << 12)
}
pub fn dev_major(d: u64) -> u32 {
    (((d >> 32) & 0xFFFF_F000) | ((d >> 8) & 0xFFF)) as u32
}
pub fn dev_minor(d: u64) -> u32 {
    (((d >> 12) & 0xFFFF_FF00) | (d & 0xFF)) as u32
}

fn incompat_name(bits: u32) -> &'static str {
    use feature::*;
    match bits.isolate_lowest_one() {
        INCOMPAT_META_BG => "meta_bg",
        INCOMPAT_JOURNAL_DEV => "journal device",
        INCOMPAT_EA_INODE => "ea_inode",
        INCOMPAT_DIRDATA => "dirdata",
        INCOMPAT_INLINE_DATA => "inline_data",
        INCOMPAT_ENCRYPT => "encrypt",
        INCOMPAT_CASEFOLD => "casefold",
        _ => "unknown incompatible feature",
    }
}
