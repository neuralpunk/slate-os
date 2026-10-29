// SPDX-License-Identifier: MIT OR Apache-2.0

//! tmpfs: a file system that lives entirely in memory (tmpfs(5)).
//!
//! File data is kept in individually allocated 4 KiB frames, so files are
//! not limited by the size of one heap allocation, sparse files cost
//! nothing for their holes, and shared mappings map the file's own pages.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::vfs::*;
use crate::abi::linux::errno::*;
use crate::mm::PhysAddr;
use crate::mm::frame::UserPage;
use crate::sync::IrqSpinLock;

const PAGE: usize = 4096;

static NEXT_DEV: AtomicU64 = AtomicU64::new(1);

/// A device number for a file system with no device (tmpfs, overlay).
pub fn anon_dev() -> u64 {
    NEXT_DEV.fetch_add(1, Ordering::Relaxed)
}

/// One tmpfs instance.
#[derive(Debug)]
pub struct TmpFs {
    dev: u64,
    next_ino: AtomicU64,
    /// What statfs(2) reports as the type (tmpfs also stands in for sysfs
    /// and mqueue).
    magic: i64,
    /// Held across a rename, so two renames cannot move the same entry at
    /// once (the entry is looked up in one directory and placed in
    /// another under separate locks).
    rename_lock: crate::sched::wait::Mutex<()>,
    /// The pages and inodes in use, and the mount's limits on them
    /// (tmpfs(5): `size=`/`nr_blocks=`, `nr_inodes=`; 0 is no limit).
    blocks: AtomicU64,
    inodes: AtomicU64,
    max_blocks: AtomicU64,
    max_inodes: AtomicU64,
    /// Every inode alive, by number, for handles (open_by_handle_at(2)):
    /// whether one still exists, before a search for its name.
    live: IrqSpinLock<BTreeMap<u64, alloc::sync::Weak<TmpInode>>>,
}

/// statfs(2) `f_type` values (statfs(2) lists them).
pub const TMPFS_MAGIC: i64 = 0x0102_1994;
pub const SYSFS_MAGIC: i64 = 0x6265_6572;
pub const MQUEUE_MAGIC: i64 = 0x1980_0202;

#[derive(Debug)]
struct Meta {
    mode: u32,
    nlink: u64,
    uid: u32,
    gid: u32,
    rdev: u64,
    atime: Timespec,
    mtime: Timespec,
    ctime: Timespec,
}

#[derive(Default)]
struct Pages {
    pages: Vec<Option<UserPage>>,
    size: u64,
}

enum Kind {
    File(IrqSpinLock<Pages>),
    Dir(IrqSpinLock<DirMap>),
    Symlink(String),
    /// Device nodes and FIFOs: only metadata; opening goes through devfs.
    Special,
    /// A read-only file whose contents are made when it is read (sysfs
    /// attributes that change, such as a PCI function's configuration
    /// space).
    Generated(Generator),
}

/// What a generated file holds, made on each read.
pub type Generator = Arc<dyn Fn(&mut Vec<u8>) + Send + Sync>;

/// Add a generated file `name` to tmpfs directory `dir` (sysfs): it reads
/// as what `make` writes, and cannot be written. Its size reads as 4096,
/// as sysfs attributes do (observed with stat(1) on Linux).
pub fn create_generated(dir: &Arc<dyn Inode>, name: &str, mode: u32, make: Generator) -> Result<Arc<dyn Inode>> {
    let d = to_tmp(dir).ok_or(EINVAL)?;
    let child = TmpInode::new(&d.fs, S_IFREG | (mode & 0o7777), 0, Kind::Generated(make));
    d.add(name, child)
}

/// A directory's entries by name, each with a position that stays the same
/// while it exists (creation order), so a listing in progress neither
/// skips nor repeats entries when others are added or removed.
#[derive(Default)]
pub struct DirMap {
    by_name: BTreeMap<String, (u64, Arc<TmpInode>)>,
    by_pos: BTreeMap<u64, String>,
    next_pos: u64,
}

impl DirMap {
    fn contains_key(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }

    fn get(&self, name: &str) -> Option<&Arc<TmpInode>> {
        self.by_name.get(name).map(|(_, c)| c)
    }

    fn insert(&mut self, name: String, child: Arc<TmpInode>) {
        self.remove(&name);
        let pos = self.next_pos;
        self.next_pos += 1;
        self.by_pos.insert(pos, name.clone());
        self.by_name.insert(name, (pos, child));
    }

    fn remove(&mut self, name: &str) -> Option<Arc<TmpInode>> {
        let (pos, child) = self.by_name.remove(name)?;
        self.by_pos.remove(&pos);
        Some(child)
    }

    fn len(&self) -> usize {
        self.by_name.len()
    }

    fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    fn iter_by_pos(&self) -> impl Iterator<Item = (u64, &String, &Arc<TmpInode>)> {
        self.by_pos.iter().map(|(pos, name)| (*pos, name, &self.by_name[name].1))
    }
}

pub struct TmpInode {
    fs: Arc<TmpFs>,
    ino: Ino,
    meta: IrqSpinLock<Meta>,
    kind: Kind,
    xattrs: IrqSpinLock<BTreeMap<String, Vec<u8>>>,
    /// fcntl(2) file seals; ordinary tmpfs files start sealed against
    /// sealing (F_SEAL_SEAL), memfds may start open.
    seals: AtomicU32,
}

// File seals (fcntl(2)). Source: musl `fcntl.h`.
pub const F_SEAL_SEAL: u32 = 0x1;
pub const F_SEAL_SHRINK: u32 = 0x2;
pub const F_SEAL_GROW: u32 = 0x4;
pub const F_SEAL_WRITE: u32 = 0x8;
pub const F_SEAL_FUTURE_WRITE: u32 = 0x10;
pub const F_SEAL_EXEC: u32 = 0x20;

/// Whether `inode` is sealed against writes (F_SEAL_WRITE or
/// F_SEAL_FUTURE_WRITE): no new writable shared mappings.
pub fn write_sealed(inode: &Arc<dyn Inode>) -> bool {
    inode.seals().is_some_and(|s| s.load(Ordering::SeqCst) & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0)
}

impl core::fmt::Debug for TmpInode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TmpInode").field("ino", &self.ino).finish()
    }
}

impl TmpInode {
    /// One link fewer (never below zero).
    fn unlink_one(&self) {
        let mut m = self.meta.lock();
        m.nlink = m.nlink.saturating_sub(1);
    }
}

impl TmpFs {
    /// A new, empty tmpfs; returns its root directory.
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Arc<TmpInode> {
        Self::with_magic(TMPFS_MAGIC)
    }

    /// A file of its own tmpfs, in no directory (memfd_create(2)), with
    /// permission bits `mode` and initial `seals`.
    pub fn memfd(mode: u32, seals: u32) -> Arc<TmpInode> {
        let fs = Arc::new(TmpFs {
            dev: NEXT_DEV.fetch_add(1, Ordering::Relaxed),
            next_ino: AtomicU64::new(1),
            magic: TMPFS_MAGIC,
            rename_lock: crate::sched::wait::Mutex::new(()),
            blocks: AtomicU64::new(0),
            inodes: AtomicU64::new(0),
            max_blocks: AtomicU64::new(0),
            max_inodes: AtomicU64::new(0),
            live: IrqSpinLock::new(BTreeMap::new()),
        });
        let f = TmpInode::new(&fs, S_IFREG | (mode & 0o7777), 0, Kind::File(IrqSpinLock::new(Pages::default())));
        f.seals.store(seals, Ordering::Release);
        f
    }

    /// A tmpfs that statfs(2) reports as `magic`.
    pub fn with_magic(magic: i64) -> Arc<TmpInode> {
        let fs = Arc::new(TmpFs {
            dev: NEXT_DEV.fetch_add(1, Ordering::Relaxed),
            next_ino: AtomicU64::new(1),
            magic,
            rename_lock: crate::sched::wait::Mutex::new(()),
            blocks: AtomicU64::new(0),
            inodes: AtomicU64::new(0),
            max_blocks: AtomicU64::new(0),
            max_inodes: AtomicU64::new(0),
            live: IrqSpinLock::new(BTreeMap::new()),
        });
        TmpInode::new(&fs, S_IFDIR | 0o755, 0, Kind::Dir(IrqSpinLock::new(DirMap::default())))
    }
}

/// Take `n` from `used` within `max` (0: no limit); ENOSPC past it.
fn charge(used: &AtomicU64, max: &AtomicU64, n: u64) -> Result<()> {
    let max = max.load(Ordering::Relaxed);
    used.try_update(Ordering::AcqRel, Ordering::Acquire, |u| {
        let v = u.checked_add(n)?;
        (max == 0 || v <= max).then_some(v)
    })
    .map(|_| ())
    .map_err(|_| ENOSPC)
}

fn uncharge(used: &AtomicU64, n: u64) {
    let _ = used.try_update(Ordering::AcqRel, Ordering::Acquire, |u| Some(u.saturating_sub(n)));
}

impl TmpFs {
    /// A page for a file, counted against the mount's size.
    fn new_page(&self) -> Result<UserPage> {
        charge(&self.blocks, &self.max_blocks, 1)?;
        UserPage::new().ok_or_else(|| {
            uncharge(&self.blocks, 1);
            ENOSPC
        })
    }
}

impl TmpInode {
    /// Limit this tmpfs (whose root this is) to `blocks` pages and `inodes`
    /// files; 0 is no limit (tmpfs(5)).
    pub fn limit(&self, blocks: u64, inodes: u64) {
        self.fs.max_blocks.store(blocks, Ordering::Relaxed);
        self.fs.max_inodes.store(inodes, Ordering::Relaxed);
    }

    /// A new file in a directory: ENOSPC once the mount has its
    /// `nr_inodes=`.
    fn new_in(fs: &Arc<TmpFs>, mode: u32, rdev: u64, kind: Kind) -> Result<Arc<TmpInode>> {
        charge(&fs.inodes, &fs.max_inodes, 1)?;
        Ok(Self::make(fs, mode, rdev, kind))
    }

    /// A file outside the limits (roots, memfds, generated files).
    fn new(fs: &Arc<TmpFs>, mode: u32, rdev: u64, kind: Kind) -> Arc<TmpInode> {
        fs.inodes.fetch_add(1, Ordering::AcqRel);
        Self::make(fs, mode, rdev, kind)
    }

    fn make(fs: &Arc<TmpFs>, mode: u32, rdev: u64, kind: Kind) -> Arc<TmpInode> {
        let now = Timespec::now();
        let nlink = if mode & S_IFMT == S_IFDIR { 2 } else { 1 };
        let i = Arc::new(TmpInode {
            fs: fs.clone(),
            ino: fs.next_ino.fetch_add(1, Ordering::Relaxed),
            meta: IrqSpinLock::new(Meta { mode, nlink, uid: 0, gid: 0, rdev, atime: now, mtime: now, ctime: now }),
            kind,
            xattrs: IrqSpinLock::new(BTreeMap::new()),
            seals: AtomicU32::new(F_SEAL_SEAL),
        });
        fs.live.lock().insert(i.ino, Arc::downgrade(&i));
        i
    }

    fn dir(&self) -> Result<&IrqSpinLock<DirMap>> {
        match &self.kind {
            Kind::Dir(d) => Ok(d),
            _ => Err(ENOTDIR),
        }
    }

    fn touch(&self) {
        let now = Timespec::now();
        let mut m = self.meta.lock();
        m.mtime = now;
        m.ctime = now;
    }

    fn add(&self, name: &str, child: Arc<TmpInode>) -> Result<Arc<dyn Inode>> {
        if name.is_empty() || name == "." || name == ".." {
            return Err(EEXIST);
        }
        let dir = self.dir()?;
        let mut d = dir.lock();
        if d.contains_key(name) {
            return Err(EEXIST);
        }
        if child.meta.lock().mode & S_IFMT == S_IFDIR {
            self.meta.lock().nlink += 1;
        }
        d.insert(String::from(name), child.clone());
        drop(d);
        self.touch();
        Ok(child)
    }

    fn downcast(i: &Arc<dyn Inode>) -> Option<&TmpInode> {
        i.as_any().downcast_ref::<TmpInode>()
    }
}

impl Inode for TmpInode {
    /// Handles find tmpfs files by searching the tree (vfs::find_by_number).
    fn handles(&self) -> bool {
        true
    }
    /// Whether file `ino` lives with a name (an unlinked one is stale, as
    /// its handle is).
    fn holds_number(&self, ino: u64) -> Option<bool> {
        let i = self.fs.live.lock().get(&ino).and_then(alloc::sync::Weak::upgrade);
        Some(i.is_some_and(|i| i.meta.lock().nlink > 0))
    }
    fn seals(&self) -> Option<&AtomicU32> {
        matches!(self.kind, Kind::File(_)).then_some(&self.seals)
    }
    fn shared_mmap(&self) -> bool {
        matches!(self.kind, Kind::File(_))
    }
    /// The file's own page (allocated if it is a hole), for a shared
    /// mapping. Pages past the end are refused (SIGBUS, as mmap(2) says).
    fn shared_page(&self, offset: u64) -> Result<PhysAddr> {
        let Kind::File(p) = &self.kind else { return Err(ENODEV) };
        let mut p = p.lock();
        if offset >= p.size.next_multiple_of(PAGE as u64) {
            return Err(EFAULT);
        }
        let i = (offset / PAGE as u64) as usize;
        if p.pages.len() <= i {
            p.pages.resize_with(i + 1, || None);
        }
        if p.pages[i].is_none() {
            p.pages[i] = Some(self.fs.new_page().map_err(|_| ENOMEM)?);
        }
        Ok(p.pages[i].as_ref().expect("just filled").share())
    }
    fn get_xattr(&self, name: &str) -> Result<Vec<u8>> {
        self.xattrs.lock().get(name).cloned().ok_or(ENODATA)
    }
    fn set_xattr(&self, name: &str, value: &[u8], flags: u32) -> Result<()> {
        set_xattr_in(&mut self.xattrs.lock(), name, value, flags)?;
        self.meta.lock().ctime = Timespec::now();
        Ok(())
    }
    fn remove_xattr(&self, name: &str) -> Result<()> {
        self.xattrs.lock().remove(name).map(|_| ()).ok_or(ENODATA)
    }
    fn list_xattr(&self) -> Result<Vec<String>> {
        Ok(self.xattrs.lock().keys().cloned().collect())
    }
    fn statfs(&self) -> Option<StatFs> {
        let s = crate::mm::frame::stats();
        let fs = &self.fs;
        let (max_blocks, max_inodes) = (fs.max_blocks.load(Ordering::Relaxed), fs.max_inodes.load(Ordering::Relaxed));
        let (blocks, free_blocks) = match max_blocks {
            0 => (s.usable_frames, s.free_frames),
            m => (m, m.saturating_sub(fs.blocks.load(Ordering::Relaxed)).min(s.free_frames)),
        };
        let (files, free_files) = match max_inodes {
            0 => (1 << 20, 1 << 20),
            m => (m, m.saturating_sub(fs.inodes.load(Ordering::Relaxed))),
        };
        Some(StatFs { magic: fs.magic, block_size: 4096, blocks, free_blocks, files, free_files, read_only: false })
    }
    fn metadata(&self) -> Metadata {
        let m = self.meta.lock();
        // A file's pages are its blocks: holes have none (tmpfs(5)).
        let (size, blocks) = match &self.kind {
            Kind::File(p) => {
                let p = p.lock();
                (p.size, Some(p.pages.iter().flatten().count() as u64 * 8))
            }
            Kind::Dir(d) => (d.lock().len() as u64 * 32, None),
            Kind::Symlink(t) => (t.len() as u64, None),
            Kind::Special => (0, None),
            Kind::Generated(_) => (4096, None),
        };
        Metadata {
            dev: self.fs.dev,
            ino: self.ino,
            mode: m.mode,
            nlink: m.nlink,
            uid: m.uid,
            gid: m.gid,
            rdev: m.rdev,
            size,
            blocks,
            atime: m.atime,
            mtime: m.mtime,
            ctime: m.ctime,
        }
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        let c = self.dir()?.lock().get(name).cloned().ok_or(ENOENT)?;
        Ok(c)
    }

    fn create(&self, name: &str, mode: u32, rdev: u64) -> Result<Arc<dyn Inode>> {
        let kind = match mode & S_IFMT {
            S_IFREG | 0 => Kind::File(IrqSpinLock::new(Pages::default())),
            S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK => Kind::Special,
            _ => return Err(EINVAL),
        };
        let mode = if mode & S_IFMT == 0 { mode | S_IFREG } else { mode };
        self.add(name, TmpInode::new_in(&self.fs, mode, rdev, kind)?)
    }

    fn mkdir(&self, name: &str, mode: u32) -> Result<Arc<dyn Inode>> {
        let d =
            TmpInode::new_in(&self.fs, S_IFDIR | (mode & 0o7777), 0, Kind::Dir(IrqSpinLock::new(DirMap::default())))?;
        self.add(name, d)
    }

    fn symlink(&self, name: &str, target: &str) -> Result<Arc<dyn Inode>> {
        self.add(name, TmpInode::new_in(&self.fs, S_IFLNK | 0o777, 0, Kind::Symlink(String::from(target)))?)
    }

    fn link(&self, name: &str, target: &Arc<dyn Inode>) -> Result<()> {
        let t = TmpInode::downcast(target).ok_or(EXDEV)?;
        if !Arc::ptr_eq(&t.fs, &self.fs) {
            return Err(EXDEV);
        }
        if t.meta.lock().mode & S_IFMT == S_IFDIR {
            return Err(EPERM);
        }
        let arc = to_tmp(target).ok_or(EXDEV)?;
        arc.meta.lock().nlink += 1;
        let dir = self.dir()?;
        let mut d = dir.lock();
        if d.contains_key(name) {
            arc.unlink_one();
            return Err(EEXIST);
        }
        d.insert(String::from(name), arc);
        Ok(())
    }

    fn unlink(&self, name: &str) -> Result<()> {
        let dir = self.dir()?;
        let mut d = dir.lock();
        let c = d.get(name).ok_or(ENOENT)?;
        if c.meta.lock().mode & S_IFMT == S_IFDIR {
            return Err(EISDIR);
        }
        let c = d.remove(name).unwrap();
        drop(d);
        c.unlink_one();
        self.touch();
        Ok(())
    }

    fn rmdir(&self, name: &str) -> Result<()> {
        let dir = self.dir()?;
        let mut d = dir.lock();
        let c = d.get(name).ok_or(ENOENT)?;
        match &c.kind {
            Kind::Dir(entries) if entries.lock().is_empty() => {}
            Kind::Dir(_) => return Err(ENOTEMPTY),
            _ => return Err(ENOTDIR),
        }
        d.remove(name);
        drop(d);
        self.unlink_one();
        self.touch();
        Ok(())
    }

    fn rename(&self, name: &str, new_dir: &Arc<dyn Inode>, new_name: &str) -> Result<()> {
        let target = TmpInode::downcast(new_dir).ok_or(EXDEV)?;
        if !Arc::ptr_eq(&target.fs, &self.fs) {
            return Err(EXDEV);
        }
        let _one_at_a_time = self.fs.rename_lock.lock();
        let same = core::ptr::eq(target, self);
        let moving = self.dir()?.lock().get(name).cloned().ok_or(ENOENT)?;
        let is_dir = moving.meta.lock().mode & S_IFMT == S_IFDIR;
        {
            let tdir = target.dir()?;
            let mut t = tdir.lock();
            if let Some(existing) = t.get(new_name) {
                if Arc::ptr_eq(existing, &moving) {
                    return Ok(());
                }
                let existing_dir = existing.meta.lock().mode & S_IFMT == S_IFDIR;
                match (is_dir, existing_dir) {
                    (true, false) => return Err(ENOTDIR),
                    (false, true) => return Err(EISDIR),
                    (true, true) => {
                        if let Kind::Dir(e) = &existing.kind
                            && !e.lock().is_empty()
                        {
                            return Err(ENOTEMPTY);
                        }
                    }
                    _ => {}
                }
                let old = t.remove(new_name).unwrap();
                old.unlink_one();
            }
            t.insert(String::from(new_name), moving.clone());
        }
        if !same || name != new_name {
            self.dir()?.lock().remove(name);
        }
        if is_dir && !same {
            self.unlink_one();
            target.meta.lock().nlink += 1;
        }
        self.touch();
        target.touch();
        Ok(())
    }

    fn readdir(&self) -> Result<Vec<DirEntry>> {
        Ok(self
            .dir()?
            .lock()
            .iter_by_pos()
            .map(|(pos, n, c)| DirEntry {
                name: n.clone(),
                ino: c.ino,
                kind: FileType::from_mode(c.meta.lock().mode),
                pos,
            })
            .collect())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if let Kind::Generated(make) = &self.kind {
            let mut v = Vec::new();
            make(&mut v);
            let Some(rest) = v.get(offset as usize..) else { return Ok(0) };
            let n = rest.len().min(buf.len());
            buf[..n].copy_from_slice(&rest[..n]);
            return Ok(n);
        }
        let Kind::File(p) = &self.kind else {
            return Err(if matches!(self.kind, Kind::Dir(_)) { EISDIR } else { EINVAL });
        };
        let p = p.lock();
        if offset >= p.size {
            return Ok(0);
        }
        let n = buf.len().min((p.size - offset) as usize);
        let mut done = 0;
        while done < n {
            let pos = offset as usize + done;
            let (page, off) = (pos / PAGE, pos % PAGE);
            let chunk = (PAGE - off).min(n - done);
            match p.pages.get(page).and_then(|x| x.as_ref()) {
                Some(pg) => pg.read(off, &mut buf[done..done + chunk]),
                None => buf[done..done + chunk].fill(0),
            }
            done += chunk;
        }
        Ok(n)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        let Kind::File(p) = &self.kind else {
            return Err(if matches!(self.kind, Kind::Dir(_)) { EISDIR } else { EINVAL });
        };
        let mut p = p.lock();
        let end = offset.checked_add(buf.len() as u64).ok_or(EFBIG)?;
        let seals = self.seals.load(Ordering::Acquire);
        if seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0 || (seals & F_SEAL_GROW != 0 && end > p.size) {
            return Err(EPERM);
        }
        let mut done = 0;
        let mut full = None;
        while done < buf.len() {
            let pos = offset as usize + done;
            let (page, off) = (pos / PAGE, pos % PAGE);
            let chunk = (PAGE - off).min(buf.len() - done);
            if p.pages.len() <= page {
                p.pages.resize_with(page + 1, || None);
            }
            if p.pages[page].is_none() {
                match self.fs.new_page() {
                    Ok(pg) => p.pages[page] = Some(pg),
                    Err(e) => {
                        full = Some(e);
                        break;
                    }
                }
            }
            p.pages[page].as_ref().expect("just filled").write(off, &buf[done..done + chunk]);
            done += chunk;
        }
        // A full file system ends the write short, or fails it if nothing
        // was written (write(2): ENOSPC).
        if let Some(e) = full
            && done == 0
        {
            return Err(e);
        }
        p.size = p.size.max(offset + done as u64);
        drop(p);
        self.touch();
        Ok(done)
    }

    /// Whole pages in the hole are freed, or zeroed in place while a
    /// mapping still uses them (so every mapping reads zeros, as
    /// fallocate(2) says); partial pages are zeroed over the range.
    fn punch_hole(&self, offset: u64, len: u64) -> Result<()> {
        let Kind::File(p) = &self.kind else { return Err(EISDIR) };
        if self.seals.load(Ordering::Acquire) & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0 {
            return Err(EPERM);
        }
        let mut p = p.lock();
        let end = offset.saturating_add(len).min(p.size.next_multiple_of(PAGE as u64));
        let mut pos = offset;
        while pos < end {
            let (i, off) = ((pos / PAGE as u64) as usize, (pos % PAGE as u64) as usize);
            let n = ((PAGE - off) as u64).min(end - pos) as usize;
            if let Some(slot) = p.pages.get_mut(i)
                && let Some(page) = slot
            {
                if n == PAGE && !page.shared() {
                    *slot = None;
                    uncharge(&self.fs.blocks, 1);
                } else {
                    page.write(off, &[0u8; PAGE][..n]);
                }
            }
            pos += n as u64;
        }
        drop(p);
        self.touch();
        Ok(())
    }

    fn truncate(&self, size: u64) -> Result<()> {
        let Kind::File(p) = &self.kind else { return Err(EISDIR) };
        let mut p = p.lock();
        let seals = self.seals.load(Ordering::Acquire);
        if (size < p.size && seals & F_SEAL_SHRINK != 0) || (size > p.size && seals & F_SEAL_GROW != 0) {
            return Err(EPERM);
        }
        let keep = (size as usize).div_ceil(PAGE);
        let freed = p.pages.get(keep..).map_or(0, |t| t.iter().flatten().count());
        p.pages.truncate(keep);
        uncharge(&self.fs.blocks, freed as u64);
        if size % PAGE as u64 != 0
            && let Some(Some(last)) = p.pages.get(keep - 1)
        {
            last.zero_from(size as usize % PAGE);
        }
        p.size = size;
        drop(p);
        self.touch();
        Ok(())
    }

    fn readlink(&self) -> Result<String> {
        match &self.kind {
            Kind::Symlink(t) => Ok(t.clone()),
            _ => Err(EINVAL),
        }
    }

    fn set_mode(&self, mode: u32) -> Result<()> {
        let mut m = self.meta.lock();
        m.mode = (m.mode & S_IFMT) | (mode & 0o7777);
        m.ctime = Timespec::now();
        Ok(())
    }

    fn set_owner(&self, uid: Option<u32>, gid: Option<u32>) -> Result<()> {
        let mut m = self.meta.lock();
        if let Some(u) = uid {
            m.uid = u;
        }
        if let Some(g) = gid {
            m.gid = g;
        }
        m.ctime = Timespec::now();
        Ok(())
    }

    fn touch_atime(&self, atime: Timespec) -> Result<()> {
        self.meta.lock().atime = atime;
        Ok(())
    }

    fn set_times(&self, atime: Option<Timespec>, mtime: Option<Timespec>) -> Result<()> {
        let mut m = self.meta.lock();
        if let Some(a) = atime {
            m.atime = a;
        }
        if let Some(t) = mtime {
            m.mtime = t;
        }
        m.ctime = Timespec::now();
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Drop for TmpInode {
    fn drop(&mut self) {
        if let Kind::File(p) = &self.kind {
            uncharge(&self.fs.blocks, p.lock().pages.iter().flatten().count() as u64);
        }
        uncharge(&self.fs.inodes, 1);
        self.fs.live.lock().remove(&self.ino);
    }
}

/// tmpfs(5)'s mount options for the size: (pages, inodes), each 0 for no
/// limit. `size=` is bytes with a k, m, g or t suffix, or a percentage of
/// RAM (`ram` bytes), rounded up to pages; `nr_blocks=` is pages and
/// `nr_inodes=` files, with the same suffixes but no percentage. Without
/// them, half of RAM and half as many files as RAM has pages. `None` for
/// a value that doesn't parse.
pub fn size_options<'a>(opts: impl Iterator<Item = &'a str>, ram: u64) -> Option<(u64, u64)> {
    fn number(v: &str, ram: Option<u64>) -> Option<u64> {
        if let (Some(pct), Some(ram)) = (v.strip_suffix('%'), ram) {
            return ram.checked_mul(pct.parse().ok()?).map(|b| b / 100);
        }
        let (digits, shift) = match v.as_bytes().last()? {
            b'k' | b'K' => (&v[..v.len() - 1], 10),
            b'm' | b'M' => (&v[..v.len() - 1], 20),
            b'g' | b'G' => (&v[..v.len() - 1], 30),
            b't' | b'T' => (&v[..v.len() - 1], 40),
            _ => (v, 0),
        };
        digits.parse::<u64>().ok()?.checked_mul(1 << shift)
    }
    let (mut blocks, mut inodes) = (None, None);
    for o in opts {
        if let Some(v) = o.strip_prefix("size=") {
            blocks = Some(number(v, Some(ram))?.div_ceil(PAGE as u64));
        } else if let Some(v) = o.strip_prefix("nr_blocks=") {
            blocks = Some(number(v, None)?);
        } else if let Some(v) = o.strip_prefix("nr_inodes=") {
            inodes = Some(number(v, None)?);
        }
    }
    let pages = ram / PAGE as u64;
    Some((blocks.unwrap_or(pages / 2), inodes.unwrap_or(pages / 2)))
}

pub const TESTS: &[crate::ktest::Test] = &[
    crate::ktest::Test { name: "fs::tmpfs_size_options", run: test_size_options },
    crate::ktest::Test { name: "fs::tmpfs_limits", run: test_limits },
];

fn test_size_options() -> core::result::Result<(), &'static str> {
    use crate::ktest::ensure;
    let ram = 4 << 30;
    let p = |s: &str| size_options(s.split(',').filter(|o| !o.is_empty()), ram);
    ensure(p("") == Some((1 << 19, 1 << 19)), "defaults")?;
    ensure(p("size=1m,nr_inodes=10") == Some((256, 10)), "size")?;
    ensure(p("size=4097") == Some((2, 1 << 19)), "rounded up")?;
    ensure(p("size=25%") == Some((1 << 18, 1 << 19)), "percent")?;
    ensure(p("nr_blocks=2k,nr_inodes=1k") == Some((2048, 1024)), "suffixes")?;
    ensure(p("size=0,nr_inodes=0") == Some((0, 0)), "unlimited")?;
    ensure(p("size=x").is_none() && p("nr_blocks=5%").is_none(), "bad values")
}

/// A tmpfs limited to 2 pages and 3 files: a write past them ends short,
/// then fails; files beyond the limit fail; freeing gives the room back.
fn test_limits() -> core::result::Result<(), &'static str> {
    use crate::ktest::ensure;
    let root = TmpFs::new();
    root.limit(2, 3);
    let a = root.create("a", S_IFREG | 0o644, 0).map_err(|_| "create a")?;
    ensure(a.write_at(0, &[1u8; 3 * PAGE]) == Ok(2 * PAGE), "short write")?;
    ensure(a.metadata().size == 2 * PAGE as u64, "size after short write")?;
    ensure(a.write_at(2 * PAGE as u64, b"x") == Err(ENOSPC), "full")?;
    ensure(root.statfs().is_some_and(|s| s.blocks == 2 && s.free_blocks == 0), "statfs blocks")?;
    root.create("b", S_IFREG | 0o644, 0).map_err(|_| "create b")?;
    ensure(root.mkdir("c", 0o755).err() == Some(ENOSPC), "inode limit")?;
    a.truncate(PAGE as u64).map_err(|_| "truncate")?;
    ensure(a.write_at(PAGE as u64, b"y") == Ok(1), "room after truncate")?;
    drop(a);
    root.unlink("a").map_err(|_| "unlink")?;
    ensure(root.statfs().is_some_and(|s| s.free_blocks == 2 && s.free_files == 1), "freed")?;
    ensure(root.mkdir("c", 0o755).is_ok(), "room for a file")
}

/// The `TmpInode` behind a generic inode handle, if it is one.
fn to_tmp(i: &Arc<dyn Inode>) -> Option<Arc<TmpInode>> {
    let any: Arc<dyn Any + Send + Sync> = i.clone();
    any.downcast::<TmpInode>().ok()
}
