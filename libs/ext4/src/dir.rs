// SPDX-License-Identifier: MIT OR Apache-2.0

//! Directories: linked lists of entries in each block (ext4 on-disk format
//! documentation, "Directory Entries"), each leaf block ending in a
//! checksum tail with metadata_csum.
//!
//! Hashed (htree) directories are read by scanning every block: their
//! index blocks look like empty entries to a linear reader, by design of
//! the format. Before an htree directory is modified it is turned into a
//! plain linear one (the index blocks become empty leaf blocks and the
//! INDEX flag is cleared), which keeps it valid without maintaining the
//! hash index.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::layout::*;
use crate::{Disk, Error, Fs, Result, crc};

/// One directory entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: Vec<u8>,
    pub ino: u32,
    /// `FT_*` from the entry (0 if the file system does not record types).
    pub file_type: u8,
    /// Byte offset of the entry in the directory. Removing other entries
    /// does not move it (their space joins the previous record).
    pub pos: u64,
}

impl DirEntry {
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }
}

pub const NAME_MAX: usize = 255;

/// An entry as found in a block: (offset, inode, rec_len, file type, name).
type RawEntry = (usize, u32, usize, u8, Vec<u8>);

impl<D: Disk> Fs<D> {
    fn tail_len(&self) -> usize {
        if self.metadata_csum { DIRENT_TAIL } else { 0 }
    }

    fn dir_block_csum(&self, ino: u32, raw: &RawInode, b: &[u8]) -> u32 {
        crc::crc32c(self.inode_seed(ino, raw.generation()), &b[..b.len() - DIRENT_TAIL])
    }

    /// Whether block `b` ends in a directory checksum tail.
    fn has_tail(b: &[u8]) -> bool {
        let t = b.len() - DIRENT_TAIL;
        get32(b, t) == 0 && get16(b, t + 4) == DIRENT_TAIL as u16 && b[t + 6] == 0 && b[t + 7] == DIRENT_TAIL_TYPE
    }

    fn set_tail(&self, ino: u32, raw: &RawInode, b: &mut [u8]) {
        if !self.metadata_csum {
            return;
        }
        let t = b.len() - DIRENT_TAIL;
        b[t..].fill(0);
        put16(b, t + 4, DIRENT_TAIL as u16);
        b[t + 7] = DIRENT_TAIL_TYPE;
        let c = self.dir_block_csum(ino, raw, b);
        put32(b, t + 8, c);
    }

    /// Logical block `i` of directory `ino`, read through the cache.
    fn dir_block(&mut self, ino: u32, raw: &RawInode, i: u32) -> Result<Option<(u64, Vec<u8>)>> {
        let run = self.map(ino, raw, i)?;
        let Some(p) = run.start else { return Ok(None) };
        let b = self.read_block(p)?;
        if self.metadata_csum && Self::has_tail(&b) && get32(&b, b.len() - 4) != self.dir_block_csum(ino, raw, &b) {
            return Err(Error::Corrupt("directory block checksum"));
        }
        Ok(Some((p, b)))
    }

    fn dir_blocks(&self, raw: &RawInode) -> u32 {
        raw.size().div_ceil(u64::from(self.block_size)) as u32
    }

    /// Walk the entries of one block.
    fn entries_in(b: &[u8]) -> Result<Vec<RawEntry>> {
        let mut out = Vec::new();
        let mut at = 0;
        while at + DIRENT_HEADER <= b.len() {
            let ino = get32(b, at);
            let rec_len = usize::from(get16(b, at + 4));
            let name_len = usize::from(b[at + 6]);
            if rec_len < DIRENT_HEADER
                || at + rec_len > b.len()
                || rec_len % 4 != 0
                || DIRENT_HEADER + name_len > rec_len
            {
                return Err(Error::Corrupt("bad directory entry"));
            }
            out.push((at, ino, rec_len, b[at + 7], b[at + DIRENT_HEADER..at + DIRENT_HEADER + name_len].to_vec()));
            at += rec_len;
        }
        Ok(out)
    }

    /// Every entry of directory `ino`, including "." and "..".
    pub fn read_dir(&mut self, ino: u32) -> Result<Vec<DirEntry>> {
        let raw = self.read_inode(ino)?;
        if !raw.is_dir() {
            return Err(Error::NotDir);
        }
        let mut out = Vec::new();
        for i in 0..self.dir_blocks(&raw) {
            let Some((_, b)) = self.dir_block(ino, &raw, i)? else { continue };
            let base = u64::from(i) * u64::from(self.block_size);
            for (at, e_ino, _, ft, name) in Self::entries_in(&b)? {
                if e_ino != 0 && ft != DIRENT_TAIL_TYPE {
                    out.push(DirEntry { name, ino: e_ino, file_type: ft, pos: base + at as u64 });
                }
            }
        }
        Ok(out)
    }

    /// The inode number `name` refers to in directory `dir`.
    pub fn lookup(&mut self, dir: u32, name: &[u8]) -> Result<u32> {
        let raw = self.read_inode(dir)?;
        if !raw.is_dir() {
            return Err(Error::NotDir);
        }
        if name.len() > NAME_MAX {
            return Err(Error::NameTooLong);
        }
        for i in 0..self.dir_blocks(&raw) {
            let Some((_, b)) = self.dir_block(dir, &raw, i)? else { continue };
            for (_, e_ino, _, ft, n) in Self::entries_in(&b)? {
                if e_ino != 0 && ft != DIRENT_TAIL_TYPE && n == name {
                    return Ok(e_ino);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Turn an htree directory into a linear one (see the module comment).
    fn unindex_dir(&mut self, ino: u32, raw: &mut RawInode) -> Result<()> {
        if raw.flags() & INDEX_FL == 0 {
            return Ok(());
        }
        let bs = self.block_size as usize;
        let tail = self.tail_len();
        for i in 0..self.dir_blocks(raw) {
            let run = self.map(ino, raw, i)?;
            let Some(p) = run.start else { continue };
            let mut b = self.read_block(p)?;
            if i == 0 {
                // dx_root: "." (12 bytes), ".." spanning the rest.
                let dotdot = get32(&b, 12);
                b.fill(0);
                put32(&mut b, 0, ino);
                put16(&mut b, 4, 12);
                b[6] = 1;
                b[7] = FT_DIR;
                b[8] = b'.';
                put32(&mut b, 12, dotdot);
                put16(&mut b, 16, (bs - 12 - tail) as u16);
                b[18] = 2;
                b[19] = FT_DIR;
                b[20] = b'.';
                b[21] = b'.';
            } else if get32(&b, 0) == 0 && usize::from(get16(&b, 4)) == bs {
                // An interior index node: becomes an empty leaf.
                b.fill(0);
                put16(&mut b, 4, (bs - tail) as u16);
            } else {
                continue;
            }
            let r = raw.clone();
            self.set_tail(ino, &r, &mut b);
            self.write_block(p, &b)?;
        }
        raw.set_flags(raw.flags() & !INDEX_FL);
        Ok(())
    }

    /// Add `name` → `child` to directory `dir` (whose inode is `raw`; the
    /// caller writes it back).
    pub(crate) fn add_entry(&mut self, dir: u32, raw: &mut RawInode, name: &[u8], child: u32, ft: u8) -> Result<()> {
        if name.is_empty() || name.len() > NAME_MAX {
            return Err(Error::NameTooLong);
        }
        self.unindex_dir(dir, raw)?;
        let need = dirent_len(name.len());
        let bs = self.block_size as usize;
        let tail = self.tail_len();
        for i in 0..self.dir_blocks(raw) {
            let Some((p, mut b)) = self.dir_block(dir, raw, i)? else { continue };
            let limit = if Self::has_tail(&b) { bs - DIRENT_TAIL } else { bs };
            for (at, e_ino, rec_len, ft0, n) in Self::entries_in(&b[..limit])? {
                if ft0 == DIRENT_TAIL_TYPE {
                    continue;
                }
                let used = if e_ino == 0 { 0 } else { dirent_len(n.len()) };
                if rec_len - used >= need {
                    let (new_at, new_len) = if e_ino == 0 {
                        (at, rec_len)
                    } else {
                        put16(&mut b, at + 4, used as u16);
                        (at + used, rec_len - used)
                    };
                    write_dirent(&mut b, new_at, child, new_len, name, ft);
                    let r = raw.clone();
                    self.set_tail(dir, &r, &mut b);
                    return self.write_block(p, &b);
                }
            }
        }
        // No room: append a block.
        let lblk = self.dir_blocks(raw);
        let goal = match lblk.checked_sub(1) {
            Some(l) => self.map(dir, raw, l)?.start.map_or(0, |p| p + 1),
            None => self.goal_for_inode(dir),
        };
        let (p, _) = self.alloc_blocks(goal, 1)?;
        let mut b = vec![0u8; bs];
        write_dirent(&mut b, 0, child, bs - tail, name, ft);
        let r = raw.clone();
        self.set_tail(dir, &r, &mut b);
        self.write_block(p, &b)?;
        self.map_new_block(dir, raw, lblk, p)?;
        raw.set_size(u64::from(lblk + 1) * bs as u64);
        Ok(())
    }

    /// Record a freshly allocated block in a file's mapping.
    pub(crate) fn map_new_block(&mut self, ino: u32, raw: &mut RawInode, lblk: u32, p: u64) -> Result<()> {
        self.insert_extent(ino, raw, Extent { block: lblk, len: 1, start: p, uninit: false })?;
        let unit = self.blocks_unit(raw);
        raw.set_blocks_raw(raw.blocks_raw() + u64::from(self.block_size) / unit);
        Ok(())
    }

    /// Remove `name` from directory `dir`; returns the inode it named.
    pub(crate) fn remove_entry(&mut self, dir: u32, raw: &mut RawInode, name: &[u8]) -> Result<u32> {
        self.unindex_dir(dir, raw)?;
        let bs = self.block_size as usize;
        for i in 0..self.dir_blocks(raw) {
            let Some((p, mut b)) = self.dir_block(dir, raw, i)? else { continue };
            let limit = if Self::has_tail(&b) { bs - DIRENT_TAIL } else { bs };
            let entries = Self::entries_in(&b[..limit])?;
            for (k, (at, e_ino, rec_len, _, n)) in entries.iter().enumerate() {
                if *e_ino == 0 || n.as_slice() != name {
                    continue;
                }
                if k == 0 {
                    // First in its block: just mark it unused.
                    put32(&mut b, *at, 0);
                    b[at + 6] = 0;
                    b[at + 7] = 0;
                } else {
                    // Otherwise the previous entry absorbs its space.
                    let (prev_at, _, prev_len, _, _) = entries[k - 1];
                    put16(&mut b, prev_at + 4, (prev_len + rec_len) as u16);
                }
                let r = raw.clone();
                self.set_tail(dir, &r, &mut b);
                self.write_block(p, &b)?;
                return Ok(*e_ino);
            }
        }
        Err(Error::NotFound)
    }

    /// Point existing entry `name` in `dir` at `child` (rename over, "..").
    pub(crate) fn retarget_entry(
        &mut self,
        dir: u32,
        raw: &mut RawInode,
        name: &[u8],
        child: u32,
        ft: u8,
    ) -> Result<()> {
        self.unindex_dir(dir, raw)?;
        let bs = self.block_size as usize;
        for i in 0..self.dir_blocks(raw) {
            let Some((p, mut b)) = self.dir_block(dir, raw, i)? else { continue };
            let limit = if Self::has_tail(&b) { bs - DIRENT_TAIL } else { bs };
            for (at, e_ino, _, _, n) in Self::entries_in(&b[..limit])? {
                if e_ino != 0 && n == name {
                    put32(&mut b, at, child);
                    b[at + 7] = ft;
                    let r = raw.clone();
                    self.set_tail(dir, &r, &mut b);
                    return self.write_block(p, &b);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Whether a directory holds anything besides "." and "..".
    pub(crate) fn dir_is_empty(&mut self, ino: u32) -> Result<bool> {
        Ok(self.read_dir(ino)?.iter().all(|e| e.name == b"." || e.name == b".."))
    }

    /// The first block of a new directory: "." and "..".
    pub(crate) fn new_dir_block(&self, ino: u32, raw: &RawInode, parent: u32) -> Vec<u8> {
        let bs = self.block_size as usize;
        let mut b = vec![0u8; bs];
        write_dirent(&mut b, 0, ino, 12, b".", FT_DIR);
        write_dirent(&mut b, 12, parent, bs - 12 - self.tail_len(), b"..", FT_DIR);
        self.set_tail(ino, raw, &mut b);
        b
    }
}

fn write_dirent(b: &mut [u8], at: usize, ino: u32, rec_len: usize, name: &[u8], ft: u8) {
    put32(b, at, ino);
    put16(b, at + 4, rec_len as u16);
    b[at + 6] = name.len() as u8;
    b[at + 7] = ft;
    b[at + DIRENT_HEADER..at + DIRENT_HEADER + name.len()].copy_from_slice(name);
    // Zero the rest of the name padding.
    let pad_end = (at + dirent_len(name.len())).min(at + rec_len);
    b[at + DIRENT_HEADER + name.len()..pad_end].fill(0);
}
