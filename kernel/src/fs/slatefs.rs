// SPDX-License-Identifier: MIT OR Apache-2.0

//! SlateFS in the VFS (ADR 0026): the slatefs library on a block device,
//! one instance per device behind a sleeping lock, shared by every
//! subvolume mounted from it. Changes are committed every few seconds, on
//! sync and at unmount and shutdown; a commit writes and counts free
//! space without the lock, so the file system stays usable meanwhile.
//! The root mount picks its subvolume by the boot state (ADR 0027).
//!
//! Like ext4's glue, inode objects are shared per (subvolume, inode)
//! through a weak map; an inode that lost its last link is freed when its
//! object goes away, through a queue drained under the lock.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use slatefs::{BootState, DT_BLK, DT_CHR, DT_DIR, DT_FIFO, DT_LNK, DT_SOCK, Disk, Error, Fs};

use super::pagecache::{self, Cached, PageCache};
use super::vfs::{self, DirEntry, FileType, Inode, Metadata, Result, StatFs, Timespec};
use crate::abi::linux::errno::*;
use crate::block::{BlockDevice, SECTOR};
use crate::sched::wait::Mutex;
use crate::sync::IrqSpinLock;
use crate::{log_info, log_warn};

/// The magic statfs(2) reports for SlateFS (Slate's own: "SLAT").
const SLATEFS_MAGIC: i64 = 0x534c_4154;
/// Seconds between background commits.
const COMMIT_SECS: u64 = 5;

struct BlockDisk(Arc<dyn BlockDevice>);

impl Disk for BlockDisk {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> slatefs::Result<()> {
        self.0.read(offset / SECTOR as u64, buf).map_err(|_| Error::Io)
    }
    fn write(&mut self, offset: u64, buf: &[u8]) -> slatefs::Result<()> {
        self.0.write(offset / SECTOR as u64, buf).map_err(|_| Error::Io)
    }
    fn flush(&mut self) -> slatefs::Result<()> {
        self.0.flush().map_err(|_| Error::Io)
    }
    fn now(&self) -> (i64, u32) {
        let t = Timespec::now();
        (t.sec, t.nsec as u32)
    }
    fn discard(&mut self, offset: u64, len: u64) -> slatefs::Result<()> {
        crate::block::discard_bytes(&self.0, offset, len).map_err(|_| Error::Io)
    }
}

fn errno(e: Error) -> Errno {
    match e {
        Error::Io => EIO,
        Error::Corrupt(what) => {
            log_warn!("slatefs: corrupted file system: {what}");
            EIO
        }
        Error::Checksum(block) => {
            log_warn!("slatefs: checksum mismatch in block {block}");
            EIO
        }
        Error::Unsupported(what) => {
            log_warn!("slatefs: unsupported: {what}");
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
        Error::TooBig => EFBIG,
        Error::Invalid => EINVAL,
    }
}

/// One SlateFS device.
pub struct Device {
    fs: Mutex<Fs<BlockDisk>>,
    /// Held for a whole commit, taken before `fs`: one commit at a time,
    /// and none while another holder of `fs` commits on its own.
    committing: Mutex<()>,
    /// The device (also inside `fs`), for what it can do.
    disk: Arc<dyn BlockDevice>,
    rdev: u64,
    read_only: bool,
    /// Unlinked inodes whose last user went away: (subvolume, inode).
    evict: IrqSpinLock<Vec<(u64, u64)>>,
    mounts: AtomicUsize,
    closed: AtomicBool,
}

static DEVICES: IrqSpinLock<BTreeMap<u64, Weak<Device>>> = IrqSpinLock::new(BTreeMap::new());

/// The device the root was mounted from (ADR 0090: its system subvolumes
/// are system images wherever they are mounted).
static ROOT_RDEV: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);
static COMMITTER: AtomicBool = AtomicBool::new(false);

/// Whether the booted system is waiting to be confirmed good (ADR 0027):
/// until then, init dying reboots so the next boot can count down.
pub static BOOT_PENDING: AtomicBool = AtomicBool::new(false);

impl Device {
    fn lock(&self) -> crate::sched::wait::MutexGuard<'_, Fs<BlockDisk>> {
        let mut fs = self.fs.lock();
        let pending = core::mem::take(&mut *self.evict.lock());
        for (sv, ino) in pending {
            if let Err(e) = fs.evict(sv, ino) {
                log_warn!("slatefs: freeing inode {ino}: {e:?}");
            }
        }
        fs
    }

    /// Commit, logging a failure.
    fn commit(&self) {
        if let Err(e) = self.try_commit() {
            log_warn!("slatefs: commit failed: {e:?}");
        }
    }

    /// Commit what changed. The lock is held only to place the changed
    /// nodes and to take the result: the nodes and the superblock are
    /// written without it (ADR 0026's addendum), so a `stat` or a read
    /// doesn't wait for the disk. Free space comes from what the
    /// transaction dropped; only a commit that asks for it walks the
    /// trees.
    fn try_commit(&self) -> slatefs::Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Ok(());
        }
        let _one = self.committing.lock();
        let Some(c) = self.lock().begin_commit()? else { return Ok(()) };
        let mut disk = BlockDisk(self.disk.clone());
        let reach =
            c.write(&mut disk).and_then(|()| if c.needs_walk() { c.reachable(&mut disk).map(Some) } else { Ok(None) });
        let mut fs = self.lock();
        match reach {
            Ok(r) => {
                fs.end_commit(c, r);
                Ok(())
            }
            Err(e) => {
                fs.abort_commit(c);
                Err(e)
            }
        }
    }

    /// The lock, for an operation that commits on its own (snapshots,
    /// boot state): no commit is in flight while it holds it.
    fn lock_committing(
        &self,
    ) -> (crate::sched::wait::MutexGuard<'_, ()>, crate::sched::wait::MutexGuard<'_, Fs<BlockDisk>>) {
        let one = self.committing.lock();
        (one, self.lock())
    }

    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let _one = self.committing.lock();
        let mut fs = self.fs.lock();
        let pending = core::mem::take(&mut *self.evict.lock());
        for (sv, ino) in pending {
            let _ = fs.evict(sv, ino);
        }
        if let Err(e) = fs.sync() {
            log_warn!("slatefs: sync at close failed: {e:?}");
        }
    }
}

/// The device's SlateFS, opened once and shared by its mounts.
fn device(dev: Arc<dyn BlockDevice>, rdev: u64, read_only: bool) -> Result<Arc<Device>> {
    let mut devs = DEVICES.lock();
    devs.retain(|_, w| w.strong_count() > 0);
    if let Some(d) = devs.get(&rdev).and_then(Weak::upgrade)
        && !d.closed.load(Ordering::Acquire)
    {
        return Ok(d);
    }
    drop(devs);
    let name = String::from(dev.name());
    let ro = read_only || dev.read_only();
    let disk = dev.clone();
    let fs = Fs::mount(BlockDisk(dev), ro).map_err(errno)?;
    let t = fs.totals();
    log_info!(
        "slatefs: /dev/{name}: {} MiB, {} MiB free, generation {}, {} subvolumes{}",
        t.blocks * 4 / 1024,
        t.free * 4 / 1024,
        fs.generation(),
        fs.subvolumes().len(),
        if ro { ", read-only" } else { "" }
    );
    let d = Arc::new(Device {
        fs: Mutex::new(fs),
        committing: Mutex::new(()),
        disk,
        rdev,
        read_only: ro,
        evict: IrqSpinLock::new(Vec::new()),
        mounts: AtomicUsize::new(0),
        closed: AtomicBool::new(false),
    });
    DEVICES.lock().insert(rdev, Arc::downgrade(&d));
    pagecache::start();
    if !COMMITTER.swap(true, Ordering::AcqRel) {
        crate::sched::spawn("slatefs-commit", || {
            loop {
                crate::time::sleep_ns(COMMIT_SECS * 1_000_000_000);
                let all: Vec<Arc<Device>> = DEVICES.lock().values().filter_map(Weak::upgrade).collect();
                for d in all {
                    d.commit();
                }
            }
        });
    }
    Ok(d)
}

/// Whether `dev` holds a SlateFS (its first superblock's magic).
pub fn probe(dev: &Arc<dyn BlockDevice>) -> bool {
    let mut b = alloc::vec![0u8; slatefs::layout::BLOCK];
    let ok = |b: &[u8]| &b[..8] == slatefs::layout::MAGIC;
    dev.read(0, &mut b).is_ok() && ok(&b)
        || dev.read(slatefs::layout::BLOCK as u64 / SECTOR as u64, &mut b).is_ok() && ok(&b)
}

/// Mount subvolume `subvol` (or the boot default, else the first one).
/// `discard`: discard blocks once they are free (for the whole device).
pub fn mount(
    dev: Arc<dyn BlockDevice>,
    rdev: u64,
    read_only: bool,
    subvol: Option<&str>,
    discard: bool,
) -> Result<Arc<dyn Inode>> {
    let d = device(dev, rdev, read_only)?;
    if discard && d.disk.can_discard() {
        d.lock().set_discard(true);
    }
    let sv = {
        let fs = d.lock();
        match subvol {
            Some(name) => fs.subvol_by_name(name).ok_or(ENOENT)?,
            None => default_subvol(&fs).ok_or(ENOENT)?,
        }
    };
    Ok(mount_subvol(d, sv))
}

fn default_subvol(fs: &Fs<BlockDisk>) -> Option<u64> {
    let ids: Vec<u64> = fs.subvolumes().iter().map(|s| s.id).collect();
    let b = fs.boot();
    if ids.contains(&b.default) { Some(b.default) } else { ids.first().copied() }
}

fn mount_subvol(d: Arc<Device>, sv: u64) -> Arc<dyn Inode> {
    d.mounts.fetch_add(1, Ordering::AcqRel);
    let m = Arc::new(Mount { dev: d, sv, inodes: IrqSpinLock::new(BTreeMap::new()) });
    m.inode(slatefs::ROOT_INO)
}

/// Mount the root: choose the subvolume by the boot state (ADR 0027).
/// `fallback` is `slate.boot=fallback` from the boot menu; `system` is
/// `slate.system=NAME`, the system the chosen menu entry belongs to (ADR
/// 0086): the default goes through the trial logic, any other boots once.
/// `rollback` is `slate.boot=rollback`: the loader counted the trial's
/// boots and none is left (ADR 0089), so a default on trial is rolled
/// back now, as if its own tries had run out.
pub fn mount_root(
    dev: Arc<dyn BlockDevice>,
    rdev: u64,
    read_only: bool,
    fallback: bool,
    rollback: bool,
    system: Option<&str>,
) -> Result<Arc<dyn Inode>> {
    let d = device(dev, rdev, read_only)?;
    ROOT_RDEV.store(rdev, Ordering::Relaxed);
    let sv = {
        let (_one, mut fs) = d.lock_committing();
        let ids: Vec<u64> = fs.subvolumes().iter().map(|s| s.id).collect();
        let name = |fs: &Fs<BlockDisk>, id: u64| {
            fs.subvolumes().into_iter().find(|s| s.id == id).map_or_else(|| format!("#{id}"), |s| s.name)
        };
        let mut b: BootState = fs.boot();
        let mut sv = default_subvol(&fs).ok_or(ENOENT)?;
        let has_fallback = b.fallback != 0 && ids.contains(&b.fallback);
        let chosen = system.and_then(|n| {
            let id = fs.subvol_by_name(n).filter(|id| ids.contains(id));
            if id.is_none() {
                log_warn!("slatefs: slate.system={n}: no such system; booting by the boot state");
            }
            id
        });
        let fallback = fallback || (chosen.is_some() && chosen == Some(b.fallback) && chosen != Some(sv));
        if rollback && b.pending && has_fallback && !read_only {
            log_warn!("slatefs: {} did not boot; rolling back to {}", name(&fs, b.default), name(&fs, b.fallback));
            b.default = b.fallback;
            b.pending = false;
            sv = b.fallback;
            fs.set_boot(b).map_err(errno)?;
            fs.commit().map_err(errno)?;
        } else if fallback && has_fallback {
            log_info!("slatefs: booting the previous system {} (requested)", name(&fs, b.fallback));
            sv = b.fallback;
        } else if let Some(id) = chosen.filter(|&id| id != sv) {
            log_info!("slatefs: booting {} (chosen in the boot menu)", name(&fs, id));
            sv = id;
        } else if b.pending && !read_only {
            if b.tries > 0 {
                b.tries -= 1;
                BOOT_PENDING.store(true, Ordering::Release);
                log_info!("slatefs: trying {} ({} more tries before falling back)", name(&fs, sv), b.tries);
            } else if has_fallback {
                log_warn!("slatefs: {} did not boot; rolling back to {}", name(&fs, b.default), name(&fs, b.fallback));
                b.default = b.fallback;
                b.pending = false;
                sv = b.fallback;
            } else {
                log_warn!("slatefs: {} did not boot and there is no fallback", name(&fs, sv));
                b.pending = false;
            }
            fs.set_boot(b).map_err(errno)?;
            fs.commit().map_err(errno)?;
        }
        log_info!("slatefs: root is subvolume {}", name(&fs, sv));
        sv
    };
    Ok(mount_subvol(d, sv))
}

/// Commit every SlateFS and close it (before power-off or reboot).
pub fn sync_all() {
    let all: Vec<Arc<Device>> = DEVICES.lock().values().filter_map(Weak::upgrade).collect();
    for d in all {
        d.close();
    }
}

/// Commit every SlateFS (sync(2)).
pub fn flush_all() {
    let all: Vec<Arc<Device>> = DEVICES.lock().values().filter_map(Weak::upgrade).collect();
    for d in all {
        d.commit();
    }
}

/// One mounted subvolume.
struct Mount {
    dev: Arc<Device>,
    sv: u64,
    inodes: IrqSpinLock<BTreeMap<u64, Weak<SInode>>>,
}

impl Mount {
    fn inode(self: &Arc<Self>, ino: u64) -> Arc<dyn Inode> {
        let mut map = self.inodes.lock();
        if let Some(i) = map.get(&ino).and_then(Weak::upgrade) {
            return i;
        }
        let i = Arc::new_cyclic(|me: &Weak<SInode>| SInode {
            m: self.clone(),
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

    /// An inode lost its last link: free it now if nobody uses it, else
    /// when its object goes away.
    fn unlinked(&self, fs: &mut Fs<BlockDisk>, ino: u64) {
        if fs.stat(self.sv, ino).map(|s| s.nlink) != Ok(0) {
            return;
        }
        let live = self.inodes.lock().get(&ino).and_then(Weak::upgrade);
        match live {
            Some(i) => i.unlinked.store(true, Ordering::Release),
            None => {
                if let Err(e) = fs.evict(self.sv, ino) {
                    log_warn!("slatefs: freeing inode {ino}: {e:?}");
                }
            }
        }
    }
}

pub struct SInode {
    m: Arc<Mount>,
    ino: u64,
    unlinked: AtomicBool,
    /// The file's data in memory (regular files).
    cache: PageCache,
}

impl Drop for SInode {
    fn drop(&mut self) {
        if self.unlinked.load(Ordering::Acquire) {
            self.m.dev.evict.lock().push((self.m.sv, self.ino));
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

fn kind_of(dt: u8) -> FileType {
    match dt {
        DT_DIR => FileType::Directory,
        DT_LNK => FileType::Symlink,
        DT_CHR => FileType::CharDevice,
        DT_BLK => FileType::BlockDevice,
        DT_FIFO => FileType::Fifo,
        DT_SOCK => FileType::Socket,
        _ => FileType::Regular,
    }
}

impl SInode {
    fn dev(&self) -> &Device {
        &self.m.dev
    }

    fn writable(&self) -> Result<()> {
        if self.dev().read_only || self.dev().closed.load(Ordering::Acquire) { Err(EROFS) } else { Ok(()) }
    }

    fn other<'a>(&self, i: &'a Arc<dyn Inode>) -> Result<&'a SInode> {
        let o = i.as_any().downcast_ref::<SInode>().ok_or(EXDEV)?;
        if Arc::ptr_eq(&o.m, &self.m) { Ok(o) } else { Err(EXDEV) }
    }
}

impl Inode for SInode {
    fn handles(&self) -> bool {
        true
    }
    /// A file in use (linked) by its number, in this subvolume.
    /// SlateFS keeps a directory's parent in its inode.
    fn parent_number(&self) -> Option<u64> {
        let st = self.dev().lock().stat(self.m.sv, self.ino).ok()?;
        (st.mode & 0o170000 == 0o040000 && st.parent != 0).then_some(st.parent)
    }
    fn by_number(&self, ino: u64) -> Result<Arc<dyn Inode>> {
        match self.dev().lock().stat(self.m.sv, ino) {
            Ok(st) if st.nlink > 0 => Ok(self.m.inode(ino)),
            _ => Err(ESTALE),
        }
    }
    fn metadata(&self) -> Metadata {
        let st = match self.dev().lock().stat(self.m.sv, self.ino) {
            Ok(s) => s,
            Err(e) => {
                log_warn!("slatefs: stat of inode {}: {e:?}", self.ino);
                return Metadata { dev: self.dev().rdev, ino: self.ino, ..Default::default() };
            }
        };
        let mut m = Metadata {
            dev: self.dev().rdev,
            ino: self.ino,
            mode: st.mode,
            nlink: u64::from(st.nlink),
            uid: st.uid,
            gid: st.gid,
            rdev: st.rdev,
            size: st.size,
            // SlateFS keeps no allocated count; holes count as data.
            blocks: None,
            atime: ts(st.atime),
            mtime: ts(st.mtime),
            ctime: ts(st.ctime),
        };
        self.cache.overlay(&mut m);
        m
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        let ino = self.dev().lock().lookup(self.m.sv, self.ino, name_bytes(name)?).map_err(errno)?;
        Ok(self.m.inode(ino))
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
        let ino = self.dev().lock().create(self.m.sv, self.ino, name_bytes(name)?, mode, 0, 0, rdev).map_err(errno)?;
        vfs::name_added(self, name);
        Ok(self.m.inode(ino))
    }

    fn mkdir(&self, name: &str, mode: u32) -> Result<Arc<dyn Inode>> {
        self.writable()?;
        let ino = self.dev().lock().mkdir(self.m.sv, self.ino, name_bytes(name)?, mode, 0, 0).map_err(errno)?;
        vfs::name_added(self, name);
        Ok(self.m.inode(ino))
    }

    fn symlink(&self, name: &str, target: &str) -> Result<Arc<dyn Inode>> {
        self.writable()?;
        let ino = self
            .dev()
            .lock()
            .symlink(self.m.sv, self.ino, name_bytes(name)?, target.as_bytes(), 0, 0)
            .map_err(errno)?;
        vfs::name_added(self, name);
        Ok(self.m.inode(ino))
    }

    fn link(&self, name: &str, target: &Arc<dyn Inode>) -> Result<()> {
        self.writable()?;
        let t = self.other(target)?;
        self.dev().lock().link(self.m.sv, self.ino, name_bytes(name)?, t.ino).map_err(errno)?;
        vfs::name_added(self, name);
        Ok(())
    }

    fn unlink(&self, name: &str) -> Result<()> {
        self.writable()?;
        let mut fs = self.dev().lock();
        let ino = fs.unlink(self.m.sv, self.ino, name_bytes(name)?).map_err(errno)?;
        self.m.unlinked(&mut fs, ino);
        Ok(())
    }

    fn rmdir(&self, name: &str) -> Result<()> {
        self.writable()?;
        let mut fs = self.dev().lock();
        let ino = fs.rmdir(self.m.sv, self.ino, name_bytes(name)?).map_err(errno)?;
        self.m.unlinked(&mut fs, ino);
        Ok(())
    }

    fn rename(&self, name: &str, new_dir: &Arc<dyn Inode>, new_name: &str) -> Result<()> {
        self.writable()?;
        let nd = self.other(new_dir)?;
        let mut fs = self.dev().lock();
        if let Some(old) =
            fs.rename(self.m.sv, self.ino, name_bytes(name)?, nd.ino, name_bytes(new_name)?).map_err(errno)?
        {
            self.m.unlinked(&mut fs, old);
        }
        drop(fs);
        vfs::name_added(&**new_dir, new_name);
        Ok(())
    }

    fn readdir(&self) -> Result<Vec<DirEntry>> {
        let entries = self.dev().lock().readdir(self.m.sv, self.ino).map_err(errno)?;
        Ok(entries
            .into_iter()
            .map(|(pos, e)| DirEntry {
                name: String::from_utf8_lossy(&e.name).into_owned(),
                ino: e.ino,
                kind: kind_of(e.kind),
                pos,
            })
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
        if offset.checked_add(buf.len() as u64).is_none_or(|end| end > slatefs::MAX_FILE_SIZE) {
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
        let t = self.dev().lock().readlink(self.m.sv, self.ino).map_err(errno)?;
        Ok(String::from_utf8_lossy(&t).into_owned())
    }

    fn set_mode(&self, mode: u32) -> Result<()> {
        self.writable()?;
        self.dev().lock().set_mode(self.m.sv, self.ino, mode).map_err(errno)
    }

    fn set_owner(&self, uid: Option<u32>, gid: Option<u32>) -> Result<()> {
        self.writable()?;
        self.dev().lock().set_owner(self.m.sv, self.ino, uid, gid).map_err(errno)
    }

    // Extended attributes live in the subvolume's tree (ADR 0026, 0028).
    fn get_xattr(&self, name: &str) -> Result<Vec<u8>> {
        match self.dev().lock().get_xattr(self.m.sv, self.ino, name.as_bytes()) {
            Err(Error::NotFound) => Err(ENODATA),
            r => r.map_err(errno),
        }
    }

    fn set_xattr(&self, name: &str, value: &[u8], flags: u32) -> Result<()> {
        self.writable()?;
        match self.dev().lock().set_xattr(self.m.sv, self.ino, name.as_bytes(), value, flags) {
            Err(Error::NotFound) => Err(ENODATA),
            r => r.map_err(errno),
        }
    }

    fn remove_xattr(&self, name: &str) -> Result<()> {
        self.writable()?;
        match self.dev().lock().remove_xattr(self.m.sv, self.ino, name.as_bytes()) {
            Err(Error::NotFound) => Err(ENODATA),
            r => r.map_err(errno),
        }
    }

    fn list_xattr(&self) -> Result<Vec<String>> {
        let names = self.dev().lock().list_xattrs(self.m.sv, self.ino).map_err(errno)?;
        Ok(names.into_iter().filter_map(|n| String::from_utf8(n).ok()).collect())
    }

    fn set_times(&self, atime: Option<Timespec>, mtime: Option<Timespec>) -> Result<()> {
        self.writable()?;
        // Cached data first: writing it back later would stamp its own time.
        if mtime.is_some() {
            pagecache::write_back(self)?;
        }
        let conv = |t: Timespec| (t.sec, t.nsec as u32);
        self.dev().lock().set_times(self.m.sv, self.ino, atime.map(conv), mtime.map(conv)).map_err(errno)
    }

    /// O_DIRECT: whole sectors of the disk (ADR 0162).
    fn direct_align(&self) -> Option<u32> {
        Some(512)
    }

    fn touch_atime(&self, atime: Timespec) -> Result<()> {
        self.writable()?;
        self.dev().lock().set_atime(self.m.sv, self.ino, (atime.sec, atime.nsec as u32)).map_err(errno)
    }

    fn statfs(&self) -> Option<StatFs> {
        let t = self.dev().lock().totals();
        Some(StatFs {
            magic: SLATEFS_MAGIC,
            block_size: slatefs::layout::BLOCK as u64,
            blocks: t.blocks,
            free_blocks: t.free,
            files: 0,
            free_files: 0,
            read_only: self.dev().read_only,
        })
    }

    fn sync(&self) -> Result<()> {
        let written = pagecache::write_back(self);
        self.dev().try_commit().map_err(errno)?;
        self.dev().disk.flush().map_err(|_| EIO)?;
        written
    }

    fn unmounted(&self) {
        let d = self.dev();
        if d.mounts.fetch_sub(1, Ordering::AcqRel) == 1 {
            d.close();
        } else {
            d.commit();
        }
    }

    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64> {
        if cmd == vfs::FITRIM {
            let d = self.dev();
            return vfs::fitrim(arg, &d.disk, |start, len, min_len| d.lock().trim(start, len, min_len).map_err(errno));
        }
        if cmd != SLATEFS_IOC_CTL {
            return Err(ENOTTY);
        }
        if !crate::proc::cred::current().capable(crate::proc::cred::CAP_SYS_ADMIN) {
            return Err(EPERM);
        }
        control(self, arg)
    }

    fn is_system_image(&self) -> bool {
        if self.ino != slatefs::ROOT_INO || self.dev().rdev != ROOT_RDEV.load(Ordering::Relaxed) {
            return false;
        }
        let sv = self.m.sv;
        self.dev().lock().subvolumes().iter().any(|v| v.id == sv && v.name.starts_with("system-"))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Whether `name` is one of the Linux runtime's subvolumes: `linux`, or
/// `linux.` and more.
fn runtime_subvol(name: &str) -> bool {
    name == "linux" || name.strip_prefix("linux.").is_some_and(|r| !r.is_empty())
}

/// `SLATEFS_IOC_CTL`: Slate's own ioctl on any file of a mounted SlateFS
/// (ADR 0027). The argument points to `{ cmd: u64, cmd_len: u64, out:
/// u64, out_len: u64 }`; the command is text, the answer is written to
/// `out` and its length returned. Commands:
///
/// - `list`: `id name flags` per subvolume (flags: ro, default, fallback, mounted-here)
/// - `snapshot NAME [ro]`: snapshot the subvolume this file is on
/// - `create NAME`: a new, empty subvolume
/// - `delete NAME`, `readonly NAME 0|1`
/// - `boot`: `default=… fallback=… tries=… pending=…`
/// - `boot default=NAME fallback=NAME tries=N pending=0|1`: set it
/// - `boot-ok`: the booted system is good (clears `pending`)
/// - `commit`
pub const SLATEFS_IOC_CTL: u32 = 0xC020_F501;

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct CtlArgs {
    cmd: u64,
    cmd_len: u64,
    out: u64,
    out_len: u64,
}

fn control(i: &SInode, arg: u64) -> Result<u64> {
    use crate::arch::uaccess::{copy_from_user, copy_to_user, read_user};
    let a: CtlArgs = read_user(arg).map_err(|_| EFAULT)?;
    if a.cmd_len > 4096 {
        return Err(EINVAL);
    }
    let mut cmd = alloc::vec![0u8; a.cmd_len as usize];
    copy_from_user(&mut cmd, a.cmd).map_err(|_| EFAULT)?;
    let cmd = core::str::from_utf8(&cmd).map_err(|_| EINVAL)?;
    let words: Vec<&str> = cmd.split_whitespace().collect();
    // Snapshots and commits must hold what was written: cached data first.
    if matches!(words.first(), Some(&"snapshot" | &"commit")) {
        pagecache::write_back_all();
    }
    // Changing the root's subvolumes or boot state changes the system
    // (ADR 0090); other SlateFS volumes are their owners' business.
    let changes =
        matches!(words.as_slice(), ["snapshot", ..] | ["create", ..] | ["delete", ..] | ["readonly", ..] | ["boot-ok"])
            || matches!(words.as_slice(), ["boot", _, ..]);
    let root = i.dev().rdev == ROOT_RDEV.load(Ordering::Relaxed);
    let (_one, mut fs) = i.dev().lock_committing();
    if changes && root && !crate::proc::domain::may_write_image() {
        // The Linux runtime's own subvolumes (`linux`, `linux.*`) are
        // root's to make, snapshot (from anything but a system) and delete
        // (ADR 0102's addendum), in either domain: slate-linux, which
        // keeps the runtime's state before an upgrade in them, runs in the
        // Linux domain (ADR 0038), and they hold no part of the system.
        // (The ioctl already asks for CAP_SYS_ADMIN.)
        let source_is_system = fs.subvolumes().iter().any(|v| v.id == i.m.sv && v.name.starts_with("system-"));
        let runtime_only = match words.as_slice() {
            ["create", n] | ["delete", n] => runtime_subvol(n),
            ["snapshot", n] | ["snapshot", n, "ro"] => runtime_subvol(n) && !source_is_system,
            _ => false,
        };
        if !runtime_only {
            return Err(EPERM);
        }
    }
    let by_name = |fs: &Fs<BlockDisk>, n: &str| fs.subvol_by_name(n).ok_or(ENOENT);
    let name_of = |fs: &Fs<BlockDisk>, id: u64| fs.subvolumes().into_iter().find(|s| s.id == id).map(|s| s.name);
    let mut out = String::new();
    match words.as_slice() {
        ["list"] => {
            let b = fs.boot();
            for s in fs.subvolumes() {
                let mut flags = Vec::new();
                if s.readonly {
                    flags.push("ro");
                }
                if s.id == b.default {
                    flags.push("default");
                }
                if s.id == b.fallback {
                    flags.push("fallback");
                }
                if s.id == i.m.sv {
                    flags.push("mounted-here");
                }
                out += &format!("{} {} {}\n", s.id, s.name, flags.join(","));
            }
        }
        ["snapshot", name] | ["snapshot", name, "ro"] => {
            let ro = words.len() == 3;
            let id = fs.snapshot(i.m.sv, name, ro).map_err(errno)?;
            out += &format!("{id}\n");
        }
        ["create", name] => {
            let id = fs.create_subvolume(name).map_err(errno)?;
            fs.commit().map_err(errno)?;
            out += &format!("{id}\n");
        }
        ["delete", name] => {
            let id = by_name(&fs, name)?;
            if id == i.m.sv {
                return Err(EBUSY);
            }
            fs.delete_subvolume(id).map_err(errno)?;
            fs.commit().map_err(errno)?;
        }
        ["readonly", name, v] => {
            let id = by_name(&fs, name)?;
            fs.set_readonly(id, *v == "1").map_err(errno)?;
            fs.commit().map_err(errno)?;
        }
        ["boot", settings @ ..] => {
            let mut b = fs.boot();
            for s in settings {
                let (k, v) = s.split_once('=').ok_or(EINVAL)?;
                match k {
                    "default" => b.default = by_name(&fs, v)?,
                    "fallback" => b.fallback = by_name(&fs, v)?,
                    "tries" => b.tries = v.parse().map_err(|_| EINVAL)?,
                    "pending" => b.pending = v == "1",
                    _ => return Err(EINVAL),
                }
            }
            if !settings.is_empty() {
                fs.set_boot(b).map_err(errno)?;
                fs.commit().map_err(errno)?;
            }
            out += &format!(
                "default={} fallback={} tries={} pending={}\n",
                name_of(&fs, b.default).unwrap_or_else(|| "-".into()),
                name_of(&fs, b.fallback).unwrap_or_else(|| "-".into()),
                b.tries,
                u8::from(b.pending)
            );
        }
        ["boot-ok"] => {
            let mut b = fs.boot();
            // Only the system on trial confirms itself: a boot of the
            // fallback from the menu leaves the trial pending.
            if b.pending && i.m.sv == b.default {
                b.pending = false;
                b.tries = 0;
                fs.set_boot(b).map_err(errno)?;
                fs.commit().map_err(errno)?;
            }
            BOOT_PENDING.store(false, Ordering::Release);
        }
        ["commit"] => fs.commit().map_err(errno)?,
        _ => return Err(EINVAL),
    }
    let n = out.len().min(a.out_len as usize);
    if n > 0 {
        copy_to_user(a.out, &out.as_bytes()[..n]).map_err(|_| EFAULT)?;
    }
    Ok(n as u64)
}

impl Cached for SInode {
    fn cache(&self) -> &PageCache {
        &self.cache
    }

    fn read_raw(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.dev().lock().read(self.m.sv, self.ino, offset, buf).map_err(errno)
    }

    fn write_raw(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        self.writable()?;
        self.dev().lock().write(self.m.sv, self.ino, offset, buf).map_err(errno)
    }

    fn truncate_raw(&self, size: u64) -> Result<()> {
        self.dev().lock().truncate(self.m.sv, self.ino, size).map_err(errno)
    }

    fn size_raw(&self) -> Result<u64> {
        Ok(self.dev().lock().stat(self.m.sv, self.ino).map_err(errno)?.size)
    }

    fn set_mtime_raw(&self, t: Timespec) -> Result<()> {
        self.writable()?;
        self.dev().lock().set_times(self.m.sv, self.ino, None, Some((t.sec, t.nsec as u32))).map_err(errno)
    }

    fn check_write(&self) -> Result<()> {
        self.dev().lock().check_write(self.m.sv, self.ino).map_err(errno)
    }

    fn free_bytes(&self) -> u64 {
        self.dev().lock().totals().free * slatefs::layout::BLOCK as u64
    }
}
