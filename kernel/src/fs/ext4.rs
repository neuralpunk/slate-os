// SPDX-License-Identifier: MIT OR Apache-2.0

//! ext4 in the VFS: the slate-ext4 library on a block device, behind one
//! sleeping lock per file system (ADR 0016).
//!
//! Metadata changes go through the journal (ADR 0042): the running
//! transaction is committed every [`COMMIT_SECS`] seconds, on sync and
//! fsync, at unmount, and when an operation leaves it big (the lock's
//! guard commits as it is released, between operations).
//!
//! Inode objects are shared per inode number (a weak map), so every user
//! of a file sees one object. An inode whose last link goes away is freed
//! when its object is dropped; drops can happen with spinlocks held, so
//! they only queue the inode, and the queue is drained by the next
//! operation that takes the file system lock.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, Ordering};

use slate_ext4::layout::{FT_BLK, FT_CHR, FT_DIR, FT_FIFO, FT_SOCK, FT_SYMLINK};
use slate_ext4::{Disk, Error, Fs, Options, SetAttr};

use super::pagecache::{self, Cached, PageCache};
use super::vfs::{self, DirEntry, FileType, Inode, Metadata, Result, StatFs, Timespec};
use crate::abi::linux::errno::*;
use crate::block::{BlockDevice, SECTOR};
use crate::sched::wait::Mutex;
use crate::sync::IrqSpinLock;
use crate::{log_info, log_warn};

/// EXT4_SUPER_MAGIC (statfs(2)).
const EXT4_MAGIC: i64 = 0xEF53;
/// Seconds between background commits.
const COMMIT_SECS: u64 = 5;

struct BlockDisk(Arc<dyn BlockDevice>);

impl Disk for BlockDisk {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> slate_ext4::Result<()> {
        self.0.read(offset / SECTOR as u64, buf).map_err(|_| Error::Io)
    }
    fn write(&mut self, offset: u64, buf: &[u8]) -> slate_ext4::Result<()> {
        self.0.write(offset / SECTOR as u64, buf).map_err(|_| Error::Io)
    }
    fn flush(&mut self) -> slate_ext4::Result<()> {
        self.0.flush().map_err(|_| Error::Io)
    }
    fn now(&self) -> (i64, u32) {
        let t = Timespec::now();
        (t.sec, t.nsec as u32)
    }
    fn discard(&mut self, offset: u64, len: u64) -> slate_ext4::Result<()> {
        crate::block::discard_bytes(&self.0, offset, len).map_err(|_| Error::Io)
    }
}

fn errno(e: Error) -> Errno {
    match e {
        Error::Io => EIO,
        Error::Corrupt(what) => {
            log_warn!("ext4: corrupted file system: {what}");
            EIO
        }
        Error::Unsupported(what) => {
            log_warn!("ext4: unsupported: {what}");
            EOPNOTSUPP
        }
        Error::ReadOnly => EROFS,
        Error::NotFound => ENOENT,
        Error::Exists => EEXIST,
        Error::NotDir => ENOTDIR,
        Error::IsDir => EISDIR,
        Error::NotEmpty => ENOTEMPTY,
        Error::NameTooLong => ENAMETOOLONG,
        Error::NoSpace => ENOSPC,
        Error::TooManyLinks => EMLINK,
        Error::Invalid => EINVAL,
    }
}

pub struct Ext4 {
    fs: Mutex<Fs<BlockDisk>>,
    /// The device (also inside `fs`), for what it can do.
    disk: Arc<dyn BlockDevice>,
    dev: u64,
    read_only: bool,
    block_size: u32,
    inodes: IrqSpinLock<BTreeMap<u32, Weak<Ext4Inode>>>,
    /// Unlinked inodes whose last user went away, waiting to be freed.
    evict: IrqSpinLock<Vec<u32>>,
    closed: AtomicBool,
}

static MOUNTED: IrqSpinLock<Vec<Weak<Ext4>>> = IrqSpinLock::new(Vec::new());
static COMMITTER: AtomicBool = AtomicBool::new(false);

/// The file system, locked. Released between operations, it commits the
/// running transaction if that has grown big.
struct FsGuard<'a>(crate::sched::wait::MutexGuard<'a, Fs<BlockDisk>>);

impl core::ops::Deref for FsGuard<'_> {
    type Target = Fs<BlockDisk>;
    fn deref(&self) -> &Fs<BlockDisk> {
        &self.0
    }
}

impl core::ops::DerefMut for FsGuard<'_> {
    fn deref_mut(&mut self) -> &mut Fs<BlockDisk> {
        &mut self.0
    }
}

impl Drop for FsGuard<'_> {
    fn drop(&mut self) {
        if self.0.commit_due()
            && let Err(e) = self.0.commit()
        {
            log_warn!("ext4: commit failed: {e:?}");
        }
    }
}

/// Mount the ext4 file system on `dev`; returns its root inode.
/// `discard`: discard blocks as they are freed (where the device takes it).
pub fn mount(dev: Arc<dyn BlockDevice>, rdev: u64, read_only: bool, discard: bool) -> Result<Arc<dyn Inode>> {
    let name = String::from(dev.name());
    let ro = read_only || dev.read_only();
    let disk = dev.clone();
    let mut fs = Fs::mount(BlockDisk(dev), Options { read_only: ro }).map_err(errno)?;
    fs.set_discard(discard && disk.can_discard());
    let t = fs.totals();
    log_info!(
        "ext4: /dev/{name}: {} MiB, {} KiB blocks, {} free{}",
        (t.blocks * u64::from(t.block_size)) >> 20,
        t.block_size / 1024,
        (t.free_blocks * u64::from(t.block_size)) >> 20,
        if fs.read_only() {
            ", read-only"
        } else if fs.journaled() {
            ", journaled"
        } else {
            ", no journal"
        }
    );
    if fs.recovered() {
        log_info!("ext4: /dev/{name}: journal replayed after an unclean shutdown");
    }
    let e = Arc::new(Ext4 {
        read_only: fs.read_only(),
        block_size: t.block_size,
        fs: Mutex::new(fs),
        disk,
        dev: rdev,
        inodes: IrqSpinLock::new(BTreeMap::new()),
        evict: IrqSpinLock::new(Vec::new()),
        closed: AtomicBool::new(false),
    });
    MOUNTED.lock().push(Arc::downgrade(&e));
    pagecache::start();
    if !COMMITTER.swap(true, Ordering::AcqRel) {
        crate::sched::spawn("ext4-commit", || {
            loop {
                crate::time::sleep_ns(COMMIT_SECS * 1_000_000_000);
                let all: Vec<Arc<Ext4>> = MOUNTED.lock().iter().filter_map(Weak::upgrade).collect();
                for e in all {
                    if !e.closed.load(Ordering::Acquire)
                        && let Err(err) = e.lock().commit()
                    {
                        log_warn!("ext4: commit failed: {err:?}");
                    }
                }
            }
        });
    }
    Ok(e.inode(slate_ext4::layout::ROOT_INO))
}

/// Write everything out and mark every mounted ext4 file system clean
/// (before power-off or reboot).
pub fn sync_all() {
    let all: Vec<Arc<Ext4>> = MOUNTED.lock().iter().filter_map(Weak::upgrade).collect();
    for e in all {
        e.close();
    }
}

/// Flush every mounted ext4 file system's disk cache (sync(2)).
pub fn flush_all() {
    let all: Vec<Arc<Ext4>> = MOUNTED.lock().iter().filter_map(Weak::upgrade).collect();
    for e in all {
        if !e.closed.load(Ordering::Acquire) {
            let _ = e.lock().sync();
        }
    }
}

impl Ext4 {
    fn inode(self: &Arc<Self>, ino: u32) -> Arc<dyn Inode> {
        let mut map = self.inodes.lock();
        if let Some(i) = map.get(&ino).and_then(Weak::upgrade) {
            return i;
        }
        let i = Arc::new_cyclic(|me: &Weak<Ext4Inode>| Ext4Inode {
            fs: self.clone(),
            ino,
            unlinked: AtomicBool::new(false),
            cache: PageCache::new(me.clone()),
        });
        map.insert(ino, Arc::downgrade(&i));
        // Inodes gone are pruned at each power of two past 4096 entries:
        // amortized constant time, however many are alive.
        if map.len() >= 4096 && map.len().is_power_of_two() {
            map.retain(|_, w| w.strong_count() > 0);
        }
        i
    }

    /// Lock the file system, first freeing inodes queued for eviction.
    fn lock(&self) -> FsGuard<'_> {
        let mut fs = FsGuard(self.fs.lock());
        let pending = core::mem::take(&mut *self.evict.lock());
        for ino in pending {
            if let Err(e) = fs.evict(ino) {
                log_warn!("ext4: freeing inode {ino}: {e:?}");
            }
        }
        fs
    }

    /// An inode lost its last link: free it now if nobody uses it, else
    /// when its object goes away.
    fn unlinked(&self, fs: &mut Fs<BlockDisk>, ino: u32) {
        if fs.stat(ino).map(|s| s.links) != Ok(0) {
            return;
        }
        let live = self.inodes.lock().get(&ino).and_then(Weak::upgrade);
        match live {
            Some(i) => i.unlinked.store(true, Ordering::Release),
            None => {
                if let Err(e) = fs.evict(ino) {
                    log_warn!("ext4: freeing inode {ino}: {e:?}");
                }
            }
        }
    }

    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut fs = self.lock();
        // Unlinked files still open (by processes killed during shutdown)
        // can never be used again: free them now rather than leave them
        // allocated with no name (there is no on-disk orphan list yet).
        let orphans: Vec<u32> = self
            .inodes
            .lock()
            .iter()
            .filter_map(|(&ino, w)| w.upgrade().filter(|i| i.unlinked.swap(false, Ordering::AcqRel)).map(|_| ino))
            .collect();
        for ino in orphans {
            if let Err(e) = fs.evict(ino) {
                log_warn!("ext4: freeing inode {ino}: {e:?}");
            }
        }
        if let Err(e) = fs.sync_and_close() {
            log_warn!("ext4: sync on close failed: {e:?}");
        }
    }
}

pub struct Ext4Inode {
    fs: Arc<Ext4>,
    ino: u32,
    /// No links remain: free the inode when this object goes away.
    unlinked: AtomicBool,
    /// The file's data in memory (regular files).
    cache: PageCache,
}

impl Drop for Ext4Inode {
    fn drop(&mut self) {
        if self.unlinked.load(Ordering::Acquire) {
            self.fs.evict.lock().push(self.ino);
        }
    }
}

fn ts((sec, nsec): (i64, u32)) -> Timespec {
    Timespec { sec, nsec: i64::from(nsec) }
}

fn name_bytes(name: &str) -> Result<&[u8]> {
    if name.len() > vfs::NAME_MAX {
        return Err(ENAMETOOLONG);
    }
    Ok(name.as_bytes())
}

fn kind_of(ft: u8) -> FileType {
    match ft {
        FT_DIR => FileType::Directory,
        FT_SYMLINK => FileType::Symlink,
        FT_CHR => FileType::CharDevice,
        FT_BLK => FileType::BlockDevice,
        FT_FIFO => FileType::Fifo,
        FT_SOCK => FileType::Socket,
        _ => FileType::Regular,
    }
}

impl Ext4Inode {
    fn writable(&self) -> Result<()> {
        if self.fs.read_only || self.fs.closed.load(Ordering::Acquire) { Err(EROFS) } else { Ok(()) }
    }

    fn other<'a>(&self, i: &'a Arc<dyn Inode>) -> Result<&'a Ext4Inode> {
        let o = i.as_any().downcast_ref::<Ext4Inode>().ok_or(EXDEV)?;
        if Arc::ptr_eq(&o.fs, &self.fs) { Ok(o) } else { Err(EXDEV) }
    }

    fn creds() -> (u32, u32) {
        (0, 0) // Everyone is root for now.
    }
}

impl Inode for Ext4Inode {
    fn handles(&self) -> bool {
        true
    }
    /// A file in use (linked, with a type) by its number.
    /// ext4 directories list their parent as `..`.
    fn parent_number(&self) -> Option<u64> {
        self.fs.lock().lookup(self.ino, b"..").ok().map(u64::from)
    }
    fn by_number(&self, ino: u64) -> Result<Arc<dyn Inode>> {
        let ino = u32::try_from(ino).map_err(|_| ESTALE)?;
        match self.fs.lock().stat(ino) {
            Ok(st) if st.links > 0 && st.mode != 0 => Ok(self.fs.inode(ino)),
            _ => Err(ESTALE),
        }
    }
    fn metadata(&self) -> Metadata {
        let st = match self.fs.lock().stat(self.ino) {
            Ok(s) => s,
            Err(e) => {
                log_warn!("ext4: stat of inode {}: {e:?}", self.ino);
                return Metadata { dev: self.fs.dev, ino: u64::from(self.ino), ..Default::default() };
            }
        };
        let mut m = Metadata {
            dev: self.fs.dev,
            ino: u64::from(self.ino),
            mode: u32::from(st.mode),
            nlink: u64::from(st.links),
            uid: st.uid,
            gid: st.gid,
            rdev: st.rdev,
            size: st.size,
            blocks: Some(st.blocks),
            atime: ts(st.atime),
            mtime: ts(st.mtime),
            ctime: ts(st.ctime),
        };
        self.cache.overlay(&mut m);
        m
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        let ino = self.fs.lock().lookup(self.ino, name_bytes(name)?).map_err(errno)?;
        Ok(self.fs.inode(ino))
    }

    // Inodes come from `inodes` while anyone holds them, and every name
    // added below reports itself (`vfs::name_added`).
    fn dentry_reclaimable(&self) -> bool {
        true
    }

    fn cache_misses(&self) -> bool {
        true
    }

    fn create(&self, name: &str, mode: u32, rdev: u64) -> Result<Arc<dyn Inode>> {
        self.writable()?;
        let (uid, gid) = Self::creds();
        let ino = self.fs.lock().create(self.ino, name_bytes(name)?, mode as u16, uid, gid, rdev).map_err(errno)?;
        vfs::name_added(self, name);
        Ok(self.fs.inode(ino))
    }

    fn mkdir(&self, name: &str, mode: u32) -> Result<Arc<dyn Inode>> {
        self.writable()?;
        let (uid, gid) = Self::creds();
        let ino = self.fs.lock().mkdir(self.ino, name_bytes(name)?, mode as u16, uid, gid).map_err(errno)?;
        vfs::name_added(self, name);
        Ok(self.fs.inode(ino))
    }

    fn symlink(&self, name: &str, target: &str) -> Result<Arc<dyn Inode>> {
        self.writable()?;
        let (uid, gid) = Self::creds();
        let ino = self.fs.lock().symlink(self.ino, name_bytes(name)?, target.as_bytes(), uid, gid).map_err(errno)?;
        vfs::name_added(self, name);
        Ok(self.fs.inode(ino))
    }

    fn link(&self, name: &str, target: &Arc<dyn Inode>) -> Result<()> {
        self.writable()?;
        let t = self.other(target)?;
        self.fs.lock().link(self.ino, name_bytes(name)?, t.ino).map_err(errno)?;
        vfs::name_added(self, name);
        Ok(())
    }

    fn unlink(&self, name: &str) -> Result<()> {
        self.writable()?;
        let mut fs = self.fs.lock();
        let ino = fs.unlink(self.ino, name_bytes(name)?).map_err(errno)?;
        self.fs.unlinked(&mut fs, ino);
        Ok(())
    }

    fn rmdir(&self, name: &str) -> Result<()> {
        self.writable()?;
        let mut fs = self.fs.lock();
        let ino = fs.rmdir(self.ino, name_bytes(name)?).map_err(errno)?;
        self.fs.unlinked(&mut fs, ino);
        Ok(())
    }

    fn rename(&self, name: &str, new_dir: &Arc<dyn Inode>, new_name: &str) -> Result<()> {
        self.writable()?;
        let nd = self.other(new_dir)?;
        let mut fs = self.fs.lock();
        if let Some(old) = fs.rename(self.ino, name_bytes(name)?, nd.ino, name_bytes(new_name)?).map_err(errno)? {
            self.fs.unlinked(&mut fs, old);
        }
        drop(fs);
        vfs::name_added(&**new_dir, new_name);
        Ok(())
    }

    fn readdir(&self) -> Result<Vec<DirEntry>> {
        let entries = self.fs.lock().read_dir(self.ino).map_err(errno)?;
        Ok(entries
            .into_iter()
            .filter(|e| e.name != b"." && e.name != b"..")
            .map(|e| DirEntry { name: e.name_lossy(), ino: u64::from(e.ino), kind: kind_of(e.file_type), pos: e.pos })
            .collect())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        pagecache::read(self, offset, buf)
    }

    fn uncache(&self, offset: u64, len: u64) {
        pagecache::drop_range(self, offset, len);
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        self.writable()?;
        // Block numbers are 32-bit.
        let max = u64::from(u32::MAX) * u64::from(self.fs.block_size);
        if offset.checked_add(buf.len() as u64).is_none_or(|end| end > max) {
            return Err(EFBIG);
        }
        pagecache::write(self, offset, buf)
    }

    fn truncate(&self, size: u64) -> Result<()> {
        self.writable()?;
        pagecache::truncate(self, size)
    }

    fn shared_mmap(&self) -> bool {
        true
    }

    fn shared_page(&self, offset: u64) -> Result<crate::mm::PhysAddr> {
        pagecache::shared_page(self, offset)
    }

    fn mmap_writeback(&self) -> bool {
        true
    }

    fn mmap_written(&self, offset: u64) {
        pagecache::mmap_written(self, offset);
    }

    fn readlink(&self) -> Result<String> {
        let t = self.fs.lock().readlink(self.ino).map_err(errno)?;
        Ok(String::from_utf8_lossy(&t).into_owned())
    }

    fn set_mode(&self, mode: u32) -> Result<()> {
        self.writable()?;
        self.fs.lock().set_attr(self.ino, SetAttr { mode: Some(mode as u16), ..Default::default() }).map_err(errno)
    }

    fn set_owner(&self, uid: Option<u32>, gid: Option<u32>) -> Result<()> {
        self.writable()?;
        self.fs.lock().set_attr(self.ino, SetAttr { uid, gid, ..Default::default() }).map_err(errno)
    }

    fn set_times(&self, atime: Option<Timespec>, mtime: Option<Timespec>) -> Result<()> {
        if self.fs.read_only {
            return Err(EROFS);
        }
        // Cached data first: writing it back later would stamp its own time.
        if mtime.is_some() {
            pagecache::write_back(self)?;
        }
        let conv = |t: Timespec| (t.sec, t.nsec as u32);
        let a = SetAttr { atime: atime.map(conv), mtime: mtime.map(conv), ..Default::default() };
        self.fs.lock().set_attr(self.ino, a).map_err(errno)
    }

    /// O_DIRECT: whole sectors of the disk (ADR 0162).
    fn direct_align(&self) -> Option<u32> {
        Some(512)
    }

    fn touch_atime(&self, atime: Timespec) -> Result<()> {
        if self.fs.read_only {
            return Err(EROFS);
        }
        self.fs.lock().set_atime(self.ino, atime.sec, atime.nsec as u32).map_err(errno)
    }

    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64> {
        if cmd != vfs::FITRIM {
            return Err(ENOTTY);
        }
        vfs::fitrim(arg, &self.fs.disk, |start, len, min_len| self.fs.lock().trim(start, len, min_len).map_err(errno))
    }

    fn statfs(&self) -> Option<StatFs> {
        let t = self.fs.lock().totals();
        Some(StatFs {
            magic: EXT4_MAGIC,
            block_size: u64::from(t.block_size),
            blocks: t.blocks,
            free_blocks: t.free_blocks,
            files: t.inodes,
            free_files: t.free_inodes,
            read_only: self.fs.read_only,
        })
    }

    fn sync(&self) -> Result<()> {
        let written = pagecache::write_back(self);
        self.fs.lock().sync().map_err(errno)?;
        written
    }

    fn unmounted(&self) {
        self.fs.close();
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Cached for Ext4Inode {
    fn cache(&self) -> &PageCache {
        &self.cache
    }

    fn read_raw(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.fs.lock().read(self.ino, offset, buf).map_err(errno)
    }

    fn write_raw(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        self.writable()?;
        self.fs.lock().write(self.ino, offset, buf).map_err(errno)
    }

    fn truncate_raw(&self, size: u64) -> Result<()> {
        self.fs.lock().truncate(self.ino, size).map_err(errno)
    }

    fn size_raw(&self) -> Result<u64> {
        Ok(self.fs.lock().stat(self.ino).map_err(errno)?.size)
    }

    fn set_mtime_raw(&self, t: Timespec) -> Result<()> {
        self.writable()?;
        let a = SetAttr { mtime: Some((t.sec, t.nsec as u32)), ..Default::default() };
        self.fs.lock().set_attr(self.ino, a).map_err(errno)
    }

    fn check_write(&self) -> Result<()> {
        self.fs.lock().check_write(self.ino).map_err(errno)
    }

    fn free_bytes(&self) -> u64 {
        let t = self.fs.lock().totals();
        t.free_blocks * u64::from(t.block_size)
    }
}
