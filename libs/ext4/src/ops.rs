// SPDX-License-Identifier: MIT OR Apache-2.0

//! File and directory operations: the public API used by the kernel's VFS
//! adapter and by host tools.

use alloc::vec;
use alloc::vec::Vec;

use crate::layout::*;
use crate::{Disk, Error, Fs, Result, Stat, crc, encode_rdev};

/// Attributes to change (`None` leaves a field alone).
#[derive(Clone, Copy, Debug, Default)]
pub struct SetAttr {
    pub mode: Option<u16>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub atime: Option<(i64, u32)>,
    pub mtime: Option<(i64, u32)>,
}

/// Largest single direct transfer, in blocks.
const CHUNK_BLOCKS: u32 = 64;
/// Fast symlinks keep their target in `i_block` when shorter than this.
const FAST_SYMLINK_MAX: usize = 60;
/// Directory link counts saturate at 1 ("many") past this (dir_nlink).
const LINK_MAX: u16 = 65000;

const XATTR_MAGIC: u32 = 0xEA02_0000;

impl<D: Disk> Fs<D> {
    fn writable(&self) -> Result<()> {
        if self.read_only { Err(Error::ReadOnly) } else { Ok(()) }
    }

    fn touch(&self, raw: &mut RawInode, which: &[usize]) {
        let (s, ns) = self.disk.now();
        for &w in which {
            raw.set_time(w, s, ns);
        }
    }

    // --- reading ------------------------------------------------------------

    /// Read file data from `offset`; returns the bytes read (short at EOF).
    pub fn read(&mut self, ino: u32, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let raw = self.read_inode(ino)?;
        if raw.is_dir() {
            return Err(Error::IsDir);
        }
        let size = raw.size();
        if offset >= size {
            return Ok(0);
        }
        let len = buf.len().min((size - offset) as usize);
        let bs = self.block_size as usize;
        let mut done = 0;
        while done < len {
            let pos = offset + done as u64;
            let lblk = (pos / bs as u64) as u32;
            let within = (pos % bs as u64) as usize;
            let run = self.map(ino, &raw, lblk)?;
            match run.start {
                Some(p) if !run.uninit => {
                    if within == 0 && len - done >= bs {
                        let blocks = (run.len.min(CHUNK_BLOCKS) as usize).min((len - done) / bs);
                        self.read_data(p, &mut buf[done..done + blocks * bs])?;
                        done += blocks * bs;
                    } else {
                        let mut tmp = vec![0u8; bs];
                        self.read_data(p, &mut tmp)?;
                        let n = (bs - within).min(len - done);
                        buf[done..done + n].copy_from_slice(&tmp[within..within + n]);
                        done += n;
                    }
                }
                _ => {
                    // A hole or preallocated space reads as zeros.
                    let hole = (run.len as u64).saturating_mul(bs as u64).saturating_sub(within as u64);
                    let n = (hole.min((len - done) as u64)) as usize;
                    let n = n.max(1).min(len - done);
                    buf[done..done + n].fill(0);
                    done += n;
                }
            }
        }
        Ok(len)
    }

    pub fn readlink(&mut self, ino: u32) -> Result<Vec<u8>> {
        let raw = self.read_inode(ino)?;
        if raw.file_type() != S_IFLNK {
            return Err(Error::Invalid);
        }
        let size = raw.size() as usize;
        if size < FAST_SYMLINK_MAX && raw.flags() & (EXTENTS_FL | INLINE_DATA_FL) == 0 && raw.blocks_raw() == 0 {
            return Ok(raw.i_block()[..size].to_vec());
        }
        if raw.flags() & INLINE_DATA_FL != 0 {
            return Err(Error::Unsupported("inline data"));
        }
        let mut out = vec![0u8; size];
        let n = self.read(ino, 0, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    // --- writing data -------------------------------------------------------

    /// Whether [`Fs::write`] can write file `ino`: a page cache asks before
    /// it accepts writes it will only hand over later.
    pub fn check_write(&mut self, ino: u32) -> Result<()> {
        self.writable()?;
        let raw = self.read_inode(ino)?;
        if raw.is_dir() {
            return Err(Error::IsDir);
        }
        if raw.flags() & EXTENTS_FL == 0 && (raw.blocks_raw() != 0 || raw.size() != 0) {
            return Err(Error::Unsupported("writing a block-mapped file"));
        }
        Ok(())
    }

    /// Write `data` at `offset`, allocating blocks as needed.
    pub fn write(&mut self, ino: u32, offset: u64, data: &[u8]) -> Result<usize> {
        self.writable()?;
        let mut raw = self.read_inode(ino)?;
        if raw.is_dir() {
            return Err(Error::IsDir);
        }
        if raw.flags() & EXTENTS_FL == 0 {
            if raw.blocks_raw() != 0 || raw.size() != 0 {
                return Err(Error::Unsupported("writing a block-mapped file"));
            }
            Self::init_extent_root(&mut raw);
        }
        let end = offset.checked_add(data.len() as u64).ok_or(Error::Invalid)?;
        if end.div_ceil(u64::from(self.block_size)) > u64::from(u32::MAX) {
            return Err(Error::Invalid);
        }
        let r = self.write_inner(ino, &mut raw, offset, data);
        if let Ok(n) = r
            && offset + n as u64 > raw.size()
        {
            raw.set_size(offset + n as u64);
        }
        self.touch(&mut raw, &[1, 2]);
        self.write_inode(ino, &mut raw)?;
        r
    }

    /// Returns the bytes written: short (not an error) if the disk fills or
    /// fails after some data went in, as write(2) reports it.
    fn write_inner(&mut self, ino: u32, raw: &mut RawInode, offset: u64, data: &[u8]) -> Result<usize> {
        let mut done = 0;
        match self.write_steps(ino, raw, offset, data, &mut done) {
            Ok(()) => Ok(done),
            Err(_) if done > 0 => Ok(done),
            Err(e) => Err(e),
        }
    }

    fn write_steps(&mut self, ino: u32, raw: &mut RawInode, offset: u64, data: &[u8], done: &mut usize) -> Result<()> {
        let bs = self.block_size as usize;
        while *done < data.len() {
            let pos = offset + *done as u64;
            let lblk = (pos / bs as u64) as u32;
            let within = (pos % bs as u64) as usize;
            let left = data.len() - *done;
            let mut run = self.map(ino, raw, lblk)?;
            if run.start.is_some() && run.uninit {
                self.initialize_extent_at(ino, raw, lblk)?;
                run = self.map(ino, raw, lblk)?;
            }
            let Some(p) = run.start else {
                // Allocate as much of the hole as this write covers.
                let want = ((within + left).div_ceil(bs) as u32).min(run.len).clamp(1, 32768);
                let goal = match lblk.checked_sub(1) {
                    Some(prev) => self.map(ino, raw, prev)?.start.map_or(0, |p| p + 1),
                    None => self.goal_for_inode(ino),
                };
                let (p, count) = self.alloc_blocks(goal, want)?;
                if let Err(e) =
                    self.insert_extent(ino, raw, Extent { block: lblk, len: count, start: p, uninit: false })
                {
                    self.free_blocks(p, u64::from(count))?;
                    return Err(e);
                }
                let unit = self.blocks_unit(raw);
                raw.set_blocks_raw(raw.blocks_raw() + u64::from(count) * u64::from(self.block_size) / unit);
                // New blocks: written now, zero-filled around the data.
                let span = (count as usize * bs).min(within + left);
                let mut chunk = vec![0u8; span.div_ceil(bs) * bs];
                let n = span - within;
                chunk[within..within + n].copy_from_slice(&data[*done..*done + n]);
                self.write_data(p, &chunk)?;
                *done += n;
                continue;
            };
            if within == 0 && left >= bs {
                let blocks = (run.len.min(CHUNK_BLOCKS) as usize).min(left / bs);
                self.write_data(p, &data[*done..*done + blocks * bs])?;
                *done += blocks * bs;
            } else {
                let mut tmp = vec![0u8; bs];
                self.read_data(p, &mut tmp)?;
                let n = (bs - within).min(left);
                tmp[within..within + n].copy_from_slice(&data[*done..*done + n]);
                self.write_data(p, &tmp)?;
                *done += n;
            }
        }
        Ok(())
    }

    /// Set the file size, freeing blocks past the end when shrinking (and
    /// zeroing the rest of a partial last block).
    pub fn truncate(&mut self, ino: u32, size: u64) -> Result<()> {
        self.writable()?;
        let mut raw = self.read_inode(ino)?;
        if raw.is_dir() {
            return Err(Error::IsDir);
        }
        let bs = u64::from(self.block_size);
        if size < raw.size() {
            if raw.flags() & EXTENTS_FL == 0 && size != 0 {
                return Err(Error::Unsupported("truncating a block-mapped file"));
            }
            let keep = size.div_ceil(bs) as u32;
            self.truncate_blocks(ino, &mut raw, keep)?;
            if size % bs != 0 {
                let run = self.map(ino, &raw, (size / bs) as u32)?;
                if let (Some(p), false) = (run.start, run.uninit) {
                    let mut tmp = vec![0u8; bs as usize];
                    self.read_data(p, &mut tmp)?;
                    tmp[(size % bs) as usize..].fill(0);
                    self.write_data(p, &tmp)?;
                }
            }
        }
        raw.set_size(size);
        self.touch(&mut raw, &[1, 2]);
        self.write_inode(ino, &mut raw)
    }

    // --- attributes -----------------------------------------------------------

    pub fn set_attr(&mut self, ino: u32, a: SetAttr) -> Result<()> {
        self.writable()?;
        let mut raw = self.read_inode(ino)?;
        if let Some(m) = a.mode {
            raw.set_mode((raw.mode() & S_IFMT) | (m & 0o7777));
        }
        if let Some(u) = a.uid {
            raw.set_uid(u);
        }
        if let Some(g) = a.gid {
            raw.set_gid(g);
        }
        if let Some((s, ns)) = a.atime {
            raw.set_time(0, s, ns);
        }
        if let Some((s, ns)) = a.mtime {
            raw.set_time(2, s, ns);
        }
        self.touch(&mut raw, &[1]);
        self.write_inode(ino, &mut raw)
    }

    /// Set the access time alone (a read's update): the change time stays.
    pub fn set_atime(&mut self, ino: u32, sec: i64, nsec: u32) -> Result<()> {
        self.writable()?;
        let mut raw = self.read_inode(ino)?;
        raw.set_time(0, sec, nsec);
        self.write_inode(ino, &mut raw)
    }

    // --- creating -------------------------------------------------------------

    fn new_inode(&mut self, parent: u32, mode: u16, uid: u32, gid: u32) -> Result<(u32, RawInode)> {
        let dir = mode & S_IFMT == S_IFDIR;
        let ino = self.alloc_inode(self.group_of_inode(parent), dir)?;
        let isz = usize::from(self.sb.inode_size());
        let mut raw = RawInode::new(isz);
        if isz > 128 {
            let want =
                if self.sb.has_ro_compat(feature::RO_COMPAT_EXTRA_ISIZE) { self.sb.want_extra_isize() } else { 32 };
            raw.set_extra_isize(want.clamp(4, 32).min((isz - 128) as u16));
        }
        raw.set_mode(mode);
        raw.set_uid(uid);
        raw.set_gid(gid);
        self.next_generation = self.next_generation.wrapping_mul(1_103_515_245).wrapping_add(12345);
        raw.set_generation(self.next_generation);
        self.touch(&mut raw, &[0, 1, 2, 3]);
        Ok((ino, raw))
    }

    fn uses_extents_feature(&self) -> bool {
        self.sb.has_incompat(feature::INCOMPAT_EXTENTS)
    }

    fn check_new_name(&mut self, dir: u32, name: &[u8]) -> Result<RawInode> {
        self.writable()?;
        if name.is_empty() || name.contains(&b'/') || name == b"." || name == b".." {
            return Err(Error::Invalid);
        }
        if name.len() > crate::dir::NAME_MAX {
            return Err(Error::NameTooLong);
        }
        let raw = self.read_inode(dir)?;
        if !raw.is_dir() {
            return Err(Error::NotDir);
        }
        match self.lookup(dir, name) {
            Ok(_) => Err(Error::Exists),
            Err(Error::NotFound) => Ok(raw),
            Err(e) => Err(e),
        }
    }

    /// Create a regular file, device node, FIFO or socket (`mode` includes
    /// the type).
    pub fn create(&mut self, dir: u32, name: &[u8], mode: u16, uid: u32, gid: u32, rdev: u64) -> Result<u32> {
        let mut draw = self.check_new_name(dir, name)?;
        let kind = mode & S_IFMT;
        if !matches!(kind, S_IFREG | S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK) {
            return Err(Error::Invalid);
        }
        let (ino, mut raw) = self.new_inode(dir, mode, uid, gid)?;
        raw.set_links(1);
        match kind {
            S_IFREG if self.uses_extents_feature() => Self::init_extent_root(&mut raw),
            S_IFCHR | S_IFBLK => encode_rdev(rdev, raw.i_block_mut()),
            _ => {}
        }
        self.write_inode(ino, &mut raw)?;
        self.add_entry(dir, &mut draw, name, ino, file_type_of_mode(mode))?;
        self.touch(&mut draw, &[1, 2]);
        self.write_inode(dir, &mut draw)?;
        Ok(ino)
    }

    pub fn mkdir(&mut self, dir: u32, name: &[u8], mode: u16, uid: u32, gid: u32) -> Result<u32> {
        let mut draw = self.check_new_name(dir, name)?;
        if draw.links() >= LINK_MAX && !self.sb.has_ro_compat(feature::RO_COMPAT_DIR_NLINK) {
            return Err(Error::TooManyLinks);
        }
        let (ino, mut raw) = self.new_inode(dir, S_IFDIR | (mode & 0o7777), uid, gid)?;
        raw.set_links(2);
        if self.uses_extents_feature() {
            Self::init_extent_root(&mut raw);
        }
        let (p, _) = self.alloc_blocks(self.goal_for_inode(ino), 1)?;
        let b = self.new_dir_block(ino, &raw, dir);
        self.write_block(p, &b)?;
        if raw.flags() & EXTENTS_FL != 0 {
            self.map_new_block(ino, &mut raw, 0, p)?;
        } else {
            put32(raw.i_block_mut(), 0, p as u32);
            let unit = self.blocks_unit(&raw);
            raw.set_blocks_raw(u64::from(self.block_size) / unit);
        }
        raw.set_size(u64::from(self.block_size));
        self.write_inode(ino, &mut raw)?;
        self.add_entry(dir, &mut draw, name, ino, FT_DIR)?;
        Self::inc_dir_links(&mut draw);
        self.touch(&mut draw, &[1, 2]);
        self.write_inode(dir, &mut draw)?;
        Ok(ino)
    }

    pub fn symlink(&mut self, dir: u32, name: &[u8], target: &[u8], uid: u32, gid: u32) -> Result<u32> {
        let mut draw = self.check_new_name(dir, name)?;
        if target.is_empty() || target.len() >= self.block_size as usize {
            return Err(Error::NameTooLong);
        }
        let (ino, mut raw) = self.new_inode(dir, S_IFLNK | 0o777, uid, gid)?;
        raw.set_links(1);
        if target.len() < FAST_SYMLINK_MAX {
            raw.i_block_mut()[..target.len()].copy_from_slice(target);
            raw.set_size(target.len() as u64);
            self.write_inode(ino, &mut raw)?;
        } else {
            Self::init_extent_root(&mut raw);
            self.write_inode(ino, &mut raw)?;
            self.write(ino, 0, target)?;
        }
        self.add_entry(dir, &mut draw, name, ino, FT_SYMLINK)?;
        self.touch(&mut draw, &[1, 2]);
        self.write_inode(dir, &mut draw)?;
        Ok(ino)
    }

    /// A new name for an existing (non-directory) inode.
    pub fn link(&mut self, dir: u32, name: &[u8], ino: u32) -> Result<()> {
        let mut draw = self.check_new_name(dir, name)?;
        let mut raw = self.read_inode(ino)?;
        if raw.is_dir() {
            return Err(Error::IsDir);
        }
        if raw.links() >= LINK_MAX {
            return Err(Error::TooManyLinks);
        }
        self.add_entry(dir, &mut draw, name, ino, file_type_of_mode(raw.mode()))?;
        self.touch(&mut draw, &[1, 2]);
        self.write_inode(dir, &mut draw)?;
        raw.set_links(raw.links() + 1);
        self.touch(&mut raw, &[1]);
        self.write_inode(ino, &mut raw)
    }

    fn inc_dir_links(raw: &mut RawInode) {
        let l = raw.links();
        raw.set_links(if l == 1 || l >= LINK_MAX - 1 { 1 } else { l + 1 });
    }

    fn dec_dir_links(raw: &mut RawInode) {
        let l = raw.links();
        if l > 2 {
            raw.set_links(l - 1);
        }
    }

    // --- removing -------------------------------------------------------------

    /// Remove a non-directory name. Returns the inode; when its link count
    /// reaches 0 the caller frees it with [`Fs::evict`] once unused.
    pub fn unlink(&mut self, dir: u32, name: &[u8]) -> Result<u32> {
        self.writable()?;
        let ino = self.lookup(dir, name)?;
        let mut raw = self.read_inode(ino)?;
        if raw.is_dir() {
            return Err(Error::IsDir);
        }
        let mut draw = self.read_inode(dir)?;
        self.remove_entry(dir, &mut draw, name)?;
        self.touch(&mut draw, &[1, 2]);
        self.write_inode(dir, &mut draw)?;
        raw.set_links(raw.links().saturating_sub(1));
        self.orphan_if_unlinked(ino, &mut raw)?;
        self.touch(&mut raw, &[1]);
        self.write_inode(ino, &mut raw)?;
        Ok(ino)
    }

    /// Remove an empty directory; its inode then has no links (free it
    /// with [`Fs::evict`]).
    pub fn rmdir(&mut self, dir: u32, name: &[u8]) -> Result<u32> {
        self.writable()?;
        if name == b"." || name == b".." {
            return Err(Error::Invalid);
        }
        let ino = self.lookup(dir, name)?;
        let mut raw = self.read_inode(ino)?;
        if !raw.is_dir() {
            return Err(Error::NotDir);
        }
        if !self.dir_is_empty(ino)? {
            return Err(Error::NotEmpty);
        }
        let mut draw = self.read_inode(dir)?;
        self.remove_entry(dir, &mut draw, name)?;
        Self::dec_dir_links(&mut draw);
        self.touch(&mut draw, &[1, 2]);
        self.write_inode(dir, &mut draw)?;
        raw.set_links(0);
        self.orphan_if_unlinked(ino, &mut raw)?;
        self.touch(&mut raw, &[1]);
        self.write_inode(ino, &mut raw)?;
        Ok(ino)
    }

    /// Free an inode with no links left: its blocks, extended attribute
    /// block and the inode itself (taking it off the orphan list). No-op
    /// while it still has links, or once it is free.
    pub fn evict(&mut self, ino: u32) -> Result<()> {
        if self.read_only {
            return Ok(());
        }
        let mut raw = self.read_inode(ino)?;
        if raw.links() != 0 || !self.inode_in_use(ino)? {
            return Ok(());
        }
        self.orphan_remove(ino, raw.dtime())?;
        let has_blocks = match raw.file_type() {
            S_IFREG | S_IFDIR => true,
            S_IFLNK => raw.flags() & EXTENTS_FL != 0 || raw.blocks_raw() != 0,
            _ => false,
        };
        if has_blocks {
            self.truncate_blocks(ino, &mut raw, 0)?;
        }
        let acl = raw.file_acl();
        if acl != 0 {
            self.release_xattr_block(acl)?;
            raw.set_file_acl(0);
        }
        let dir = raw.is_dir();
        let (s, _) = self.disk.now();
        raw.set_dtime(s.max(1) as u32);
        raw.set_size(0);
        raw.set_blocks_raw(0);
        self.write_inode(ino, &mut raw)?;
        self.free_inode(ino, dir)
    }

    // --- the orphan list -----------------------------------------------------
    //
    // Inodes with no links that are still in use are listed from the
    // superblock's `s_last_orphan`, each `i_dtime` naming the next (ext4
    // on-disk format documentation, "Orphan List"): after a crash, mount
    // (or e2fsck) frees them.

    /// `raw` (inode `ino`, written by the caller) lost its last link: put
    /// it on the orphan list until [`Fs::evict`] frees it.
    fn orphan_if_unlinked(&mut self, ino: u32, raw: &mut RawInode) -> Result<()> {
        if raw.links() != 0 {
            return Ok(());
        }
        raw.set_dtime(self.sb.last_orphan());
        self.sb.set_last_orphan(ino);
        self.write_superblock()
    }

    /// Take inode `ino`, whose `i_dtime` is `next`, off the orphan list.
    fn orphan_remove(&mut self, ino: u32, next: u32) -> Result<()> {
        if self.sb.last_orphan() == ino {
            self.sb.set_last_orphan(next);
            return self.write_superblock();
        }
        let mut at = self.sb.last_orphan();
        for _ in 0..self.sb.inodes_count() {
            if at == 0 {
                return Ok(()); // Not listed.
            }
            let mut raw = self.read_inode(at)?;
            if raw.dtime() == ino {
                raw.set_dtime(next);
                return self.write_inode(at, &mut raw);
            }
            at = raw.dtime();
        }
        Err(Error::Corrupt("orphan list loops"))
    }

    /// At mount: free the inodes left on the orphan list.
    pub(crate) fn release_orphans(&mut self) -> Result<()> {
        for _ in 0..self.sb.inodes_count() {
            let ino = self.sb.last_orphan();
            if ino == 0 {
                return Ok(());
            }
            let mut raw = self.read_inode(ino)?;
            if raw.links() == 0 && self.inode_in_use(ino)? {
                self.evict(ino)?;
            } else {
                // Still linked (or already free): only drop it from the list.
                self.sb.set_last_orphan(raw.dtime());
                self.write_superblock()?;
                if self.inode_in_use(ino)? {
                    raw.set_dtime(0);
                    self.write_inode(ino, &mut raw)?;
                }
            }
        }
        Err(Error::Corrupt("orphan list loops"))
    }

    /// Drop one reference to a shared extended attribute block.
    fn release_xattr_block(&mut self, blk: u64) -> Result<()> {
        let mut b = self.read_block(blk)?;
        if get32(&b, 0) != XATTR_MAGIC {
            return Err(Error::Corrupt("bad extended attribute block"));
        }
        let refs = get32(&b, 4);
        if refs <= 1 {
            return self.free_blocks(blk, 1);
        }
        put32(&mut b, 4, refs - 1);
        if self.metadata_csum {
            put32(&mut b, 0x10, 0);
            let c = crc::crc32c(self.csum_seed, &blk.to_le_bytes());
            let c = crc::crc32c(c, &b);
            put32(&mut b, 0x10, c);
        }
        self.write_block(blk, &b)
    }

    /// Whether directory `ancestor` is `ino` or contains it.
    fn is_ancestor(&mut self, ancestor: u32, mut ino: u32) -> Result<bool> {
        for _ in 0..4096 {
            if ino == ancestor {
                return Ok(true);
            }
            if ino == ROOT_INO {
                return Ok(false);
            }
            ino = self.lookup(ino, b"..")?;
        }
        Err(Error::Corrupt("directory loop"))
    }

    /// rename(2). Returns the inode the destination name used to refer to,
    /// if any (free it with [`Fs::evict`] once unused).
    pub fn rename(&mut self, old_dir: u32, old_name: &[u8], new_dir: u32, new_name: &[u8]) -> Result<Option<u32>> {
        self.writable()?;
        if [old_name, new_name].iter().any(|n| n.is_empty() || *n == b"." || *n == b"..") {
            return Err(Error::Invalid);
        }
        if new_name.len() > crate::dir::NAME_MAX {
            return Err(Error::NameTooLong);
        }
        let src = self.lookup(old_dir, old_name)?;
        let mut sraw = self.read_inode(src)?;
        let src_is_dir = sraw.is_dir();
        let target = match self.lookup(new_dir, new_name) {
            Ok(t) => Some(t),
            Err(Error::NotFound) => None,
            Err(e) => return Err(e),
        };
        if target == Some(src) {
            return Ok(None); // Same file: nothing to do.
        }
        if src_is_dir && old_dir != new_dir && self.is_ancestor(src, new_dir)? {
            return Err(Error::Invalid);
        }
        let ft = file_type_of_mode(sraw.mode());
        let mut new_raw = self.read_inode(new_dir)?;
        if let Some(t) = target {
            let mut traw = self.read_inode(t)?;
            match (src_is_dir, traw.is_dir()) {
                (true, false) => return Err(Error::NotDir),
                (false, true) => return Err(Error::IsDir),
                (true, true) if !self.dir_is_empty(t)? => return Err(Error::NotEmpty),
                _ => {}
            }
            self.retarget_entry(new_dir, &mut new_raw, new_name, src, ft)?;
            if traw.is_dir() {
                traw.set_links(0);
                Self::dec_dir_links(&mut new_raw);
            } else {
                traw.set_links(traw.links().saturating_sub(1));
            }
            self.orphan_if_unlinked(t, &mut traw)?;
            self.touch(&mut traw, &[1]);
            self.write_inode(t, &mut traw)?;
        } else {
            self.add_entry(new_dir, &mut new_raw, new_name, src, ft)?;
        }
        if src_is_dir && old_dir != new_dir {
            Self::inc_dir_links(&mut new_raw);
        }
        self.touch(&mut new_raw, &[1, 2]);
        self.write_inode(new_dir, &mut new_raw)?;
        // Remove the old name (re-reading the old directory: it may be the
        // same inode just written).
        let mut old_raw = self.read_inode(old_dir)?;
        self.remove_entry(old_dir, &mut old_raw, old_name)?;
        if src_is_dir && old_dir != new_dir {
            Self::dec_dir_links(&mut old_raw);
        }
        self.touch(&mut old_raw, &[1, 2]);
        self.write_inode(old_dir, &mut old_raw)?;
        if src_is_dir && old_dir != new_dir {
            self.retarget_entry(src, &mut sraw, b"..", new_dir, FT_DIR)?;
        }
        // Nothing else wrote the source inode since it was read: it is
        // neither directory involved (that would be a loop).
        self.touch(&mut sraw, &[1]);
        self.write_inode(src, &mut sraw)?;
        Ok(target)
    }

    /// Inode metadata, and the inode's raw bytes for tools.
    pub fn stat_raw(&mut self, ino: u32) -> Result<(Stat, Vec<u8>)> {
        let raw = self.read_inode(ino)?;
        Ok((self.stat_of(ino, &raw), raw.0))
    }
}
