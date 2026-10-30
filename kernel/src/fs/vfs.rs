// SPDX-License-Identifier: MIT OR Apache-2.0

//! The virtual file system: inodes, the dentry tree, mounts and path
//! resolution.
//!
//! Every file system provides [`Inode`]s. The kernel keeps a tree of
//! [`Dentry`]s (names bound to inodes) on top, so `..` and `getcwd` work
//! across mount points: the root dentry of a mounted file system takes the
//! name and parent of the dentry it is mounted on.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use crate::abi::linux::errno::*;
use crate::sync::IrqSpinLock;

pub mod dcache;
pub use dcache::name_added;

pub type Ino = u64;
pub type Result<T> = core::result::Result<T, Errno>;

// File type and permission bits (inode(7)).
pub const S_IFMT: u32 = 0o170000;
pub const S_IFSOCK: u32 = 0o140000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFIFO: u32 = 0o010000;

/// Longest path accepted (PATH_MAX, limits.h).
pub const PATH_MAX: usize = 4096;
/// Longest single name (NAME_MAX).
pub const NAME_MAX: usize = 255;
/// Symlinks followed during one lookup before ELOOP (path_resolution(7)).
const MAX_SYMLINKS: usize = 40;

/// Kind of file, from the mode's type bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
}

impl FileType {
    pub fn from_mode(mode: u32) -> FileType {
        match mode & S_IFMT {
            S_IFDIR => FileType::Directory,
            S_IFLNK => FileType::Symlink,
            S_IFCHR => FileType::CharDevice,
            S_IFBLK => FileType::BlockDevice,
            S_IFIFO => FileType::Fifo,
            S_IFSOCK => FileType::Socket,
            _ => FileType::Regular,
        }
    }

    /// `d_type` for getdents64(2).
    pub fn dirent_type(self) -> u8 {
        match self {
            FileType::Fifo => 1,
            FileType::CharDevice => 2,
            FileType::Directory => 4,
            FileType::BlockDevice => 6,
            FileType::Regular => 8,
            FileType::Symlink => 10,
            FileType::Socket => 12,
        }
    }
}

/// A point in time as seconds and nanoseconds since the epoch (laid out as
/// the C `struct timespec`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Timespec {
    pub sec: i64,
    pub nsec: i64,
}

impl Timespec {
    pub fn now() -> Timespec {
        let ns = crate::time::realtime_ns();
        let s = i128::from(crate::time::NS_PER_SEC);
        Timespec { sec: ns.div_euclid(s) as i64, nsec: ns.rem_euclid(s) as i64 }
    }
}

/// What stat(2) reports.
#[derive(Clone, Copy, Debug, Default)]
pub struct Metadata {
    pub dev: u64,
    pub ino: Ino,
    /// Type and permission bits.
    pub mode: u32,
    pub nlink: u64,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    pub size: u64,
    /// 512-byte units allocated, where the file system knows (holes
    /// take none); `None` counts the size, rounded up.
    pub blocks: Option<u64>,
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
}

impl Metadata {
    /// `st_blocks` (stat(2)): 512-byte units allocated.
    pub fn blocks(&self) -> u64 {
        self.blocks.unwrap_or(self.size.div_ceil(512))
    }

    pub fn file_type(&self) -> FileType {
        FileType::from_mode(self.mode)
    }
}

/// Encode a device number the way Linux's `dev_t` does (musl
/// `sys/sysmacros.h` `makedev`, ADR 0009).
pub fn makedev(major: u32, minor: u32) -> u64 {
    let (ma, mi) = (u64::from(major), u64::from(minor));
    ((ma & 0xFFFF_F000) << 32) | ((ma & 0xFFF) << 8) | ((mi & 0xFFFF_FF00) << 12) | (mi & 0xFF)
}

pub fn major(dev: u64) -> u32 {
    (((dev >> 32) & 0xFFFF_F000) | ((dev >> 8) & 0xFFF)) as u32
}

pub fn minor(dev: u64) -> u32 {
    (((dev >> 12) & 0xFFFF_FF00) | (dev & 0xFF)) as u32
}

/// What statfs(2) reports for a file system.
#[derive(Clone, Copy, Debug, Default)]
pub struct StatFs {
    pub magic: i64,
    pub block_size: u64,
    pub blocks: u64,
    pub free_blocks: u64,
    pub files: u64,
    pub free_files: u64,
    pub read_only: bool,
}

// setxattr(2) flags. Source: musl `sys/xattr.h`.
pub const XATTR_CREATE: u32 = 1;
pub const XATTR_REPLACE: u32 = 2;

/// setxattr(2) on a map of attributes: XATTR_CREATE fails if the name
/// exists (EEXIST), XATTR_REPLACE if it does not (ENODATA).
pub fn set_xattr_in(
    map: &mut alloc::collections::BTreeMap<String, Vec<u8>>,
    name: &str,
    value: &[u8],
    flags: u32,
) -> Result<()> {
    let exists = map.contains_key(name);
    if flags & XATTR_CREATE != 0 && exists {
        return Err(EEXIST);
    }
    if flags & XATTR_REPLACE != 0 && !exists {
        return Err(ENODATA);
    }
    map.insert(String::from(name), value.to_vec());
    Ok(())
}

/// A directory entry as file systems list it.
#[derive(Clone, Debug)]
pub struct DirEntry {
    pub name: String,
    pub ino: Ino,
    pub kind: FileType,
    /// Position in the directory: increasing through a listing and stable
    /// while the entry exists (getdents offsets resume from it).
    pub pos: u64,
}
/// FITRIM, `_IOWR('X', 121, struct fstrim_range)`: discard a file
/// system's free space. Observed on the host (`strace -X raw fstrim`):
/// request 0xc0185879, argument `{start, len, minlen}` (three u64, bytes);
/// `len` comes back as the bytes discarded (fstrim(8) `-v`).
pub const FITRIM: u32 = 0xC018_5879;

/// FITRIM for a file system on `disk`: reads the range at user address
/// `arg`, runs `trim(start, len, minlen)` (which returns the bytes
/// discarded) and writes that back as `len`. Needs CAP_SYS_ADMIN.
pub fn fitrim(
    arg: u64,
    disk: &Arc<dyn crate::block::BlockDevice>,
    trim: impl FnOnce(u64, u64, u64) -> Result<u64>,
) -> Result<u64> {
    use crate::arch::uaccess::{read_user, write_user};
    if !crate::proc::cred::current().capable(crate::proc::cred::CAP_SYS_ADMIN) {
        return Err(EPERM);
    }
    if !disk.can_discard() {
        return Err(EOPNOTSUPP);
    }
    let range: [u64; 3] = read_user(arg).map_err(|_| EFAULT)?;
    let trimmed = trim(range[0], range[1], range[2])?;
    write_user(arg + 8, &trimmed).map_err(|_| EFAULT)?;
    Ok(0)
}

/// A file system object. Directory operations return `ENOTDIR` and data
/// operations `EISDIR`/`EINVAL` by default.
pub trait Inode: Send + Sync + Any {
    fn metadata(&self) -> Metadata;

    fn lookup(&self, _name: &str) -> Result<Arc<dyn Inode>> {
        Err(ENOTDIR)
    }
    /// Whether the child `name` must be looked up afresh every time, not
    /// cached in the dentry tree (/proc/<pid>: who may see it depends on
    /// the reader, ADR 0032).
    fn uncached_child(&self, _name: &str) -> bool {
        false
    }
    /// Whether the dentry cache may drop this inode's dentry while nothing
    /// else uses it and look the name up again later: the file system
    /// hands out the same inode object for a file while anyone holds it,
    /// and keeps nothing that only the dentry would hold (ext4, SlateFS).
    fn dentry_reclaimable(&self) -> bool {
        false
    }
    /// Whether names this directory doesn't have may be cached as misses:
    /// the file system calls [`name_added`] for every name it adds to the
    /// directory, whoever asked (ext4, SlateFS).
    fn cache_misses(&self) -> bool {
        false
    }
    /// Create a regular file, device node or FIFO (`mode` includes the type).
    fn create(&self, _name: &str, _mode: u32, _rdev: u64) -> Result<Arc<dyn Inode>> {
        Err(ENOTDIR)
    }
    fn mkdir(&self, _name: &str, _mode: u32) -> Result<Arc<dyn Inode>> {
        Err(ENOTDIR)
    }
    fn symlink(&self, _name: &str, _target: &str) -> Result<Arc<dyn Inode>> {
        Err(ENOTDIR)
    }
    fn link(&self, _name: &str, _target: &Arc<dyn Inode>) -> Result<()> {
        Err(ENOTDIR)
    }
    fn unlink(&self, _name: &str) -> Result<()> {
        Err(ENOTDIR)
    }
    fn rmdir(&self, _name: &str) -> Result<()> {
        Err(ENOTDIR)
    }
    /// Move `name` to `new_name` in `new_dir` (same file system).
    fn rename(&self, _name: &str, _new_dir: &Arc<dyn Inode>, _new_name: &str) -> Result<()> {
        Err(ENOTDIR)
    }
    fn readdir(&self) -> Result<Vec<DirEntry>> {
        Err(ENOTDIR)
    }

    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<usize> {
        Err(EISDIR)
    }
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> Result<usize> {
        Err(EISDIR)
    }
    fn truncate(&self, _size: u64) -> Result<()> {
        Err(EINVAL)
    }
    fn readlink(&self) -> Result<String> {
        Err(EINVAL)
    }

    fn set_mode(&self, _mode: u32) -> Result<()> {
        Err(EPERM)
    }
    fn set_owner(&self, _uid: Option<u32>, _gid: Option<u32>) -> Result<()> {
        Err(EPERM)
    }
    fn set_times(&self, _atime: Option<Timespec>, _mtime: Option<Timespec>) -> Result<()> {
        Ok(())
    }

    /// fallocate(2) FALLOC_FL_PUNCH_HOLE: make `[offset, offset + len)`
    /// read as zeros, freeing the space where it can; the size stays.
    fn punch_hole(&self, _offset: u64, _len: u64) -> Result<()> {
        Err(EOPNOTSUPP)
    }

    /// File seals (memfd_create(2), fcntl(2) F_ADD_SEALS), for files that
    /// support them.
    fn seals(&self) -> Option<&core::sync::atomic::AtomicU32> {
        None
    }

    /// Whether shared mappings (`MAP_SHARED`) can map the file's own pages
    /// ([`Inode::shared_page`]); otherwise they get copies, read-only.
    fn shared_mmap(&self) -> bool {
        false
    }
    /// The frame holding the file's page at `offset`, with a reference
    /// taken for the mapping. Called with no spinlock held.
    fn shared_page(&self, _offset: u64) -> Result<crate::mm::PhysAddr> {
        Err(ENODEV)
    }
    /// Whether writes through shared mappings must be noticed (the page
    /// cache writes them back): such pages are mapped read-only until
    /// written, and the write fault calls [`Inode::mmap_written`].
    fn mmap_writeback(&self) -> bool {
        false
    }
    /// A shared mapping is about to write the page at `offset`. Called with
    /// the address space's lock held: must not sleep.
    fn mmap_written(&self, _offset: u64) {}

    /// Extended attributes (xattr(7)), by full name (`user.foo`). The
    /// system calls check permissions; file systems only store them.
    fn get_xattr(&self, _name: &str) -> Result<Vec<u8>> {
        Err(ENODATA)
    }
    /// `flags`: XATTR_CREATE / XATTR_REPLACE (see `set_xattr_in`).
    fn set_xattr(&self, _name: &str, _value: &[u8], _flags: u32) -> Result<()> {
        Err(EOPNOTSUPP)
    }
    fn remove_xattr(&self, _name: &str) -> Result<()> {
        Err(EOPNOTSUPP)
    }
    fn list_xattr(&self) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    /// File system totals for statfs(2); `None` reports memory totals (the
    /// in-memory file systems).
    fn statfs(&self) -> Option<StatFs> {
        None
    }
    /// Make this file's data and metadata durable (fsync(2)): cached data
    /// is written back first.
    /// Drop what the page cache holds of bytes `[offset, offset + len)`
    /// that is written (O_DIRECT); file systems without one keep nothing.
    fn uncache(&self, _offset: u64, _len: u64) {}

    /// O_DIRECT's alignment (ADR 0162): buffers, lengths and offsets of
    /// direct transfers must be multiples of it (open(2): the logical
    /// block size; statx(2) STATX_DIOALIGN reports it). `None`: no limits
    /// (the file systems in memory).
    fn direct_align(&self) -> Option<u32> {
        None
    }

    /// Set the access time alone, the change time kept (a read's update,
    /// ADR 0162); file systems that keep no times ignore it.
    fn touch_atime(&self, _atime: Timespec) -> Result<()> {
        Ok(())
    }

    fn sync(&self) -> Result<()> {
        Ok(())
    }
    /// Called on a file system's root inode when it is unmounted.
    fn unmounted(&self) {}
    /// Whether file handles of this file can be opened again
    /// (name_to_handle_at(2); /proc's and pipes' only identify).
    fn handles(&self) -> bool {
        false
    }
    /// On a file system's root inode: the file numbered `ino`, if it
    /// exists (open_by_handle_at(2)). ESTALE when it doesn't, or the file
    /// system can't look files up by number.
    fn by_number(&self, _ino: u64) -> Result<Arc<dyn Inode>> {
        Err(ESTALE)
    }
    /// On a file system's root inode: whether a file numbered `ino` lives
    /// (None: it can't say without a search). Lets a handle's file be
    /// found, or found stale, without searching blindly.
    fn holds_number(&self, _ino: u64) -> Option<bool> {
        None
    }
    /// A directory's parent's number, where the file system keeps it
    /// (ext4's `..`, SlateFS's parent): a directory found by number
    /// gets its path back through them.
    fn parent_number(&self) -> Option<u64> {
        None
    }
    /// For "magic" symlinks (/proc/<pid>/fd/N, exe, cwd, root, ns/*): the
    /// dentry they stand for, which path lookup reaches without reading the
    /// link text (proc(5)), even if it has no name any more.
    fn magic_target(&self) -> Option<Arc<Dentry>> {
        None
    }
    /// A file-system-specific ioctl on an open file of this inode.
    fn ioctl(&self, _cmd: u32, _arg: u64) -> Result<u64> {
        Err(ENOTTY)
    }

    /// Open hook for inodes whose open files are not plain data (procfs
    /// files that snapshot their contents, for example).
    fn open_special(self: Arc<Self>, _flags: u32) -> Option<Result<Arc<dyn super::File>>> {
        None
    }

    /// Whether this is the root of a system image mounted somewhere other
    /// than the boot root (a SlateFS system subvolume, ADR 0090).
    fn is_system_image(&self) -> bool {
        false
    }

    fn as_any(&self) -> &dyn Any;
}

/// A name in the tree, bound to an inode.
pub struct Dentry {
    pub name: String,
    pub inode: Arc<dyn Inode>,
    pub parent: Option<Arc<Dentry>>,
    children: IrqSpinLock<BTreeMap<String, Arc<Dentry>>>,
    /// Roots of file systems mounted here, per mount namespace (ADR 0028).
    mounted: IrqSpinLock<BTreeMap<u64, Arc<Dentry>>>,
    /// File system type name, for /proc/mounts (set on mount roots).
    pub fs_type: Option<&'static str>,
    /// On mount roots: the mount's flags ([`MNT_RDONLY`] and the others)
    /// in each mount namespace that shows it (each has its own copy of a
    /// mount, ADR 0028). Kept here so they outlive a lazy unmount (files
    /// opened under a detached mount stay read-only).
    mnt_flags: IrqSpinLock<BTreeMap<u64, u32>>,
    /// Children are cached. Not below a dentry its file system said not
    /// to cache (a /proc/PID directory): its cached children would hold it
    /// (each child holds its parent) and nothing would ever free them.
    cache_children: bool,
    /// Listed in [`ALIASES`] (it has cached a child or a miss).
    aliased: core::sync::atomic::AtomicBool,
    /// Found in the cache since the shrinker last passed (its clock bit).
    referenced: core::sync::atomic::AtomicBool,
    /// Names this directory doesn't have (negative entries).
    missing: IrqSpinLock<dcache::Misses>,
}

/// The dentries that cache names for each directory inode (by its
/// object's address): one directory can have several, through bind mounts
/// and mount namespaces' copies, and a name removed or replaced through
/// one must be forgotten by all, or the others keep finding the old file
/// (flatpak's D-Bus proxy replaces its placeholder with its socket in a
/// namespace of its own). Only dentries that cached a child are listed.
static ALIASES: IrqSpinLock<BTreeMap<usize, Vec<alloc::sync::Weak<Dentry>>>> = IrqSpinLock::new(BTreeMap::new());

fn inode_key(i: &Arc<dyn Inode>) -> usize {
    Arc::as_ptr(i).cast::<()>() as usize
}

impl core::fmt::Debug for Dentry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Dentry").field("name", &self.name).finish()
    }
}

/// Dentries alive (for /proc/slate_sched and the shrinker).
pub static LIVE_DENTRIES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

impl Drop for Dentry {
    fn drop(&mut self) {
        LIVE_DENTRIES.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
        dcache::dropped_misses(self.missing.lock().len());
        if self.aliased.load(core::sync::atomic::Ordering::Relaxed) {
            let key = inode_key(&self.inode);
            let mut a = ALIASES.lock();
            if let Some(v) = a.get_mut(&key) {
                v.retain(|w| w.strong_count() > 0);
                if v.is_empty() {
                    a.remove(&key);
                }
            }
        }
    }
}

/// A dentry for a file that has no name in any directory (memfd_create).
pub fn anon_dentry(name: &str, inode: Arc<dyn Inode>, fs_type: &'static str) -> Arc<Dentry> {
    Dentry::new(name, inode, None, Some(fs_type))
}

impl Dentry {
    fn new(
        name: &str,
        inode: Arc<dyn Inode>,
        parent: Option<Arc<Dentry>>,
        fs_type: Option<&'static str>,
    ) -> Arc<Dentry> {
        LIVE_DENTRIES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Arc::new(Dentry {
            name: String::from(name),
            inode,
            parent,
            children: IrqSpinLock::new(BTreeMap::new()),
            mounted: IrqSpinLock::new(BTreeMap::new()),
            fs_type,
            mnt_flags: IrqSpinLock::new(BTreeMap::new()),
            cache_children: true,
            aliased: core::sync::atomic::AtomicBool::new(false),
            referenced: core::sync::atomic::AtomicBool::new(true),
            missing: IrqSpinLock::new(dcache::Misses::default()),
        })
    }

    /// List this directory dentry in [`ALIASES`], once.
    fn alias(self: &Arc<Self>) {
        if !self.aliased.swap(true, core::sync::atomic::Ordering::Relaxed) {
            ALIASES.lock().entry(inode_key(&self.inode)).or_default().push(Arc::downgrade(self));
        }
    }

    pub fn metadata(&self) -> Metadata {
        self.inode.metadata()
    }

    pub fn is_dir(&self) -> bool {
        self.metadata().file_type() == FileType::Directory
    }

    /// Follow mounts stacked on this dentry (in the caller's namespace).
    fn mount_top(self: &Arc<Self>) -> Arc<Dentry> {
        let ns = mnt_ns();
        let mut d = self.clone();
        loop {
            let next = d.mounted.lock().get(&ns).cloned();
            match next {
                Some(m) => d = m,
                None => return d,
            }
        }
    }

    /// The child `name` (without following a symlink it may be).
    pub fn child(self: &Arc<Self>, name: &str) -> Result<Arc<Dentry>> {
        match name {
            "" | "." => return Ok(self.clone()),
            ".." => return Ok(self.parent.clone().map_or_else(|| self.clone(), |p| p.mount_top())),
            _ => {}
        }
        if name.len() > NAME_MAX {
            return Err(ENAMETOOLONG);
        }
        if !self.is_dir() {
            return Err(ENOTDIR);
        }
        let uncached = !self.cache_children || self.inode.uncached_child(name);
        if !uncached && let Some(c) = self.children.lock().get(name).cloned() {
            c.referenced.store(true, core::sync::atomic::Ordering::Relaxed);
            return Ok(c.mount_top());
        }
        // A miss cached, or the generation a miss found now is noted at.
        let misses = !uncached && self.inode.cache_misses();
        let generation = if misses {
            self.alias();
            self.missing.lock().check(name)?
        } else {
            0
        };
        let inode = match self.inode.lookup(name) {
            Ok(i) => i,
            Err(e) => {
                if e == ENOENT && misses {
                    self.missing.lock().note(name, generation);
                }
                return Err(e);
            }
        };
        let mut d = Dentry::new(name, inode, Some(self.clone()), None);
        if uncached {
            // Not referenced by anyone else yet.
            if let Some(m) = Arc::get_mut(&mut d) {
                m.cache_children = false;
            }
        } else {
            self.alias();
            self.children.lock().insert(String::from(name), d.clone());
        }
        Ok(d.mount_top())
    }

    /// The child `name` if the dentry cache has it (RESOLVE_CACHED):
    /// EAGAIN when finding it would ask the file system, as for a name not
    /// looked up yet or one never cached (/proc's, efivarfs's).
    pub fn cached_child(self: &Arc<Self>, name: &str) -> Result<Arc<Dentry>> {
        if matches!(name, "" | "." | "..") {
            return self.child(name);
        }
        if !self.is_dir() {
            return Err(ENOTDIR);
        }
        if !self.cache_children || self.inode.uncached_child(name) {
            return Err(EAGAIN);
        }
        let Some(c) = self.children.lock().get(name).cloned() else {
            return Err(if self.missing.lock().has(name) { ENOENT } else { EAGAIN });
        };
        c.referenced.store(true, core::sync::atomic::Ordering::Relaxed);
        Ok(c.mount_top())
    }

    /// A dentry for `inode`, just created as `name`, when looking it up
    /// again does not find it: an uncached child a file system makes only
    /// on its first write (efivarfs). Never cached.
    pub fn just_created(self: &Arc<Self>, name: &str, inode: Arc<dyn Inode>) -> Arc<Dentry> {
        let mut d = Dentry::new(name, inode, Some(self.clone()), None);
        if let Some(m) = Arc::get_mut(&mut d) {
            m.cache_children = false;
        }
        d
    }

    /// The cached dentries below this one: (path, cached children) of the
    /// `top` directories holding the most (/proc/slate_sched).
    pub fn census(self: &Arc<Self>, top: usize) -> Vec<(String, usize)> {
        let mut out = Vec::new();
        let mut stack = alloc::vec![self.clone()];
        while let Some(d) = stack.pop() {
            let kids: Vec<Arc<Dentry>> = d.children.lock().values().cloned().collect();
            if !kids.is_empty() {
                out.push((d.path_from(None), kids.len()));
            }
            stack.extend(kids);
            stack.extend(d.mounted.lock().values().cloned());
        }
        out.sort_by_key(|a| core::cmp::Reverse(a.1));
        out.truncate(top);
        out
    }

    /// Forget a cached child (after unlink, rmdir or rename), and what is
    /// cached below it: the cache's links go both ways (a child holds its
    /// parent), so a detached subtree left cached would never be freed.
    /// Dentries still in use elsewhere (an open file, a working directory)
    /// stay valid.
    /// The other dentries of this directory forget it too ([`ALIASES`]).
    pub fn forget(&self, name: &str) {
        let gone = self.children.lock().remove(name);
        if let Some(d) = gone {
            d.prune();
        }
        // Taken out of the list before acting, so no dentry is dropped
        // with its lock held (dropping one takes it).
        let others: Vec<Arc<Dentry>> = ALIASES
            .lock()
            .get(&inode_key(&self.inode))
            .map(|v| v.iter().filter_map(alloc::sync::Weak::upgrade).collect())
            .unwrap_or_default();
        for o in &others {
            if !core::ptr::eq(Arc::as_ptr(o), self) {
                let gone = o.children.lock().remove(name);
                if let Some(d) = gone {
                    d.prune();
                }
            }
        }
        drop(others);
    }

    /// Drop everything cached below this dentry.
    pub fn prune(&self) {
        let mut stack: Vec<Arc<Dentry>> = core::mem::take(&mut *self.children.lock()).into_values().collect();
        while let Some(d) = stack.pop() {
            stack.extend(core::mem::take(&mut *d.children.lock()).into_values());
        }
    }

    /// Path of this dentry as seen from `root` (a chroot), or from the real
    /// root if `root` is `None` or not an ancestor.
    pub fn path_from(self: &Arc<Self>, root: Option<&Arc<Dentry>>) -> String {
        let mut parts = Vec::new();
        let mut d = self.clone();
        while let Some(p) = d.parent.clone() {
            if root.is_some_and(|r| Arc::ptr_eq(r, &d)) {
                break;
            }
            parts.push(d.name.clone());
            d = p;
        }
        if parts.is_empty() {
            return String::from("/");
        }
        let mut s = String::new();
        for p in parts.iter().rev() {
            s.push('/');
            s.push_str(p);
        }
        s
    }

    /// Whether `ancestor` is this dentry or one of its parents.
    pub fn is_under(self: &Arc<Self>, ancestor: &Arc<Dentry>) -> bool {
        let mut d = Some(self.clone());
        while let Some(x) = d {
            if Arc::ptr_eq(&x, ancestor) {
                return true;
            }
            d = x.parent.clone();
        }
        false
    }

    /// Whether something is mounted on this dentry (in the caller's
    /// namespace).
    pub fn is_mountpoint(&self) -> bool {
        self.mounted.lock().contains_key(&mnt_ns())
    }

    /// Whether something is mounted on this directory's entry `name` (in
    /// the caller's namespace): such names can't be removed or renamed
    /// (EBUSY).
    pub fn covered(&self, name: &str) -> bool {
        self.children.lock().get(name).is_some_and(|c| c.is_mountpoint())
    }
}

/// The boot root. Set once, except that the boot's unlock stage runs on a
/// temporary root first, which the real one then replaces (ADR 0038).
static ROOT: IrqSpinLock<Option<Arc<Dentry>>> = IrqSpinLock::new(None);

/// One mount in one mount namespace.
#[derive(Clone)]
struct MountEntry {
    /// The mount ID /proc/<pid>/mountinfo shows.
    id: u64,
    ns: u64,
    /// Where it is mounted (`None` for the initial root).
    at: Option<Arc<Dentry>>,
    root: Arc<Dentry>,
    /// The mount `at` belongs to (its root), for detaching subtrees.
    parent: Option<Arc<Dentry>>,
    source: String,
    /// The root inode of the file system the mount shows (a bind mount
    /// shares its source's): it is told when no mount shows it any more.
    sb: Arc<dyn Inode>,
    /// The mount's flags ([`MNT_RDONLY`] and the others; bind mounts can
    /// be read-only views).
    flags: u32,
}

// Per-mount flags: mount(2)'s MS_RDONLY, MS_NOSUID, MS_NODEV and
// MS_NOEXEC, which statfs(2)'s ST_* flags share; and its access-time
// flags MS_NOATIME (1024), MS_NODIRATIME (2048), MS_RELATIME (1 << 21)
// and MS_STRICTATIME (1 << 24) (ADR 0162). Source: musl `sys/mount.h`
// and `sys/statvfs.h`.
pub const MNT_RDONLY: u32 = 1;
pub const MNT_NOSUID: u32 = 2;
pub const MNT_NODEV: u32 = 4;
pub const MNT_NOEXEC: u32 = 8;
pub const MNT_NOATIME: u32 = 1024;
pub const MNT_NODIRATIME: u32 = 2048;
pub const MNT_RELATIME: u32 = 1 << 21;
pub const MNT_STRICTATIME: u32 = 1 << 24;
pub const MNT_ATIME: u32 = MNT_NOATIME | MNT_NODIRATIME | MNT_RELATIME | MNT_STRICTATIME;
pub const MNT_FLAGS: u32 = MNT_RDONLY | MNT_NOSUID | MNT_NODEV | MNT_NOEXEC | MNT_ATIME;

/// A mount's flags as mount(2) leaves them: without MS_NOATIME or
/// MS_STRICTATIME, relatime (mount(8): the default).
pub fn atime_default(flags: u32) -> u32 {
    if flags & (MNT_NOATIME | MNT_STRICTATIME) == 0 { flags | MNT_RELATIME } else { flags & !MNT_RELATIME }
}

/// relatime's day: an access time older than this is updated however it
/// stands to the other times (mount(8)).
const RELATIME_SECS: i64 = 24 * 60 * 60;

/// Whether a read at `now` updates the access time `m` has, by the mount's
/// `flags` (mount(8)'s noatime, nodiratime, relatime and strictatime).
pub fn atime_due(m: &Metadata, flags: u32, now: Timespec) -> bool {
    let dir = m.file_type() == FileType::Directory;
    if flags & (MNT_RDONLY | MNT_NOATIME) != 0 || dir && flags & MNT_NODIRATIME != 0 {
        return false;
    }
    let older = |a: Timespec, b: Timespec| (a.sec, a.nsec) <= (b.sec, b.nsec);
    if flags & MNT_STRICTATIME != 0 {
        return m.atime != now;
    }
    older(m.atime, m.mtime) || older(m.atime, m.ctime) || now.sec - m.atime.sec >= RELATIME_SECS
}

/// `d` was read (its data, its listing, mapped or run): its access time
/// is updated as its mount says (ADR 0162). Nothing on a read-only mount,
/// in the system image or the system tree for the Linux domain (they are
/// read-only there), and failures are only logged: a read never fails
/// for its access time.
pub fn accessed(d: &Arc<Dentry>) {
    let flags = mount_flags(d);
    if flags & (MNT_RDONLY | MNT_NOATIME) != 0 || writable(d).is_err() {
        return;
    }
    let now = Timespec::now();
    if !atime_due(&d.inode.metadata(), flags, now) {
        return;
    }
    if let Err(e) = d.inode.touch_atime(now) {
        crate::log_debug!("vfs: access time not kept: {e:?}");
    }
}

/// Every mount of every namespace.
static MOUNTS: IrqSpinLock<Vec<MountEntry>> = IrqSpinLock::new(Vec::new());
static NEXT_MOUNT_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

fn mount_id() -> u64 {
    NEXT_MOUNT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

/// The caller's mount namespace id (0, the initial one, for the kernel).
fn mnt_ns() -> u64 {
    crate::proc::current().map_or(0, |p| p.mnt_ns_id())
}

/// Install the root file system, replacing the temporary root of the
/// boot's unlock stage if there was one (by then no process uses it, and
/// its own mounts are gone).
pub fn set_root(inode: Arc<dyn Inode>, fs_type: &'static str, source: &str) {
    let d = Dentry::new("/", inode, None, Some(fs_type));
    d.mnt_flags.lock().insert(0, MNT_RELATIME);
    let old = ROOT.lock().replace(d.clone());
    let mut mounts = MOUNTS.lock();
    if let Some(old) = old {
        mounts.retain(|m| !Arc::ptr_eq(&m.root, &old));
    }
    mounts.push(MountEntry {
        id: mount_id(),
        ns: 0,
        at: None,
        root: d.clone(),
        parent: None,
        source: String::from(source),
        sb: d.inode.clone(),
        flags: MNT_RELATIME,
    });
}

pub fn root() -> Arc<Dentry> {
    ROOT.lock().clone().expect("no root file system")
}

/// The system directories of the boot root (ADR 0032).
pub const SYSTEM_DIRS: &[&str] = &["bin", "sbin", "lib", "usr", "etc", "boot"];

/// Whether `d` is in the system tree: under one of [`SYSTEM_DIRS`] on the
/// root file system the kernel mounted at boot, with no other mount in
/// between. Decided from the dentry's ancestors, so the path a program
/// used (chroots, bind mounts, `..`) does not matter.
pub fn in_system_tree(d: &Arc<Dentry>) -> bool {
    boot_root_entry(d).is_some_and(|c| SYSTEM_DIRS.contains(&c.name.as_str()))
}

/// The entry of the boot root's top directory that `d` is in (itself, or
/// an ancestor), with no other mount in between.
fn boot_root_entry(d: &Arc<Dentry>) -> Option<Arc<Dentry>> {
    let root = ROOT.lock().clone()?;
    let mut below: Option<Arc<Dentry>> = None;
    let mut at = d.clone();
    loop {
        if Arc::ptr_eq(&at, &root) {
            return below;
        }
        // Another mount's root (or a dentry with no parent) ends the walk.
        if at.fs_type.is_some() {
            return None;
        }
        let parent = at.parent.clone()?;
        below = Some(at);
        at = parent;
    }
}

/// The system image's part of the boot root (ADR 0090): the system tree's
/// code, and `/init`.
pub const IMAGE_DIRS: &[&str] = &["bin", "sbin", "lib", "lib64", "usr", "boot", "init"];

/// Whether `d` is part of a system image (ADR 0090): under [`IMAGE_DIRS`]
/// of the boot root, or anywhere in another mount of a system subvolume
/// of the root's file system (an update in /run/update).
pub fn in_image(d: &Arc<Dentry>) -> bool {
    if boot_root_entry(d).is_some_and(|c| IMAGE_DIRS.contains(&c.name.as_str())) {
        return true;
    }
    let mut at = Some(d.clone());
    while let Some(x) = at {
        if x.fs_type.is_some() {
            let boot_root = ROOT.lock().clone().is_some_and(|r| Arc::ptr_eq(&r, &x));
            return !boot_root && x.inode.is_system_image();
        }
        at = x.parent.clone();
    }
    false
}

/// The root of the mount that `d` lies in (in namespace `ns`).
fn containing_mount(mounts: &[MountEntry], ns: u64, d: &Arc<Dentry>) -> Option<Arc<Dentry>> {
    let mut at = Some(d.clone());
    while let Some(x) = at {
        if mounts.iter().any(|m| m.ns == ns && Arc::ptr_eq(&m.root, &x)) {
            return Some(x);
        }
        at = x.parent.clone();
    }
    None
}

fn attach(at: &Arc<Dentry>, root: Arc<Dentry>, source: &str, sb: Arc<dyn Inode>, flags: u32) {
    let ns = mnt_ns();
    let top = at.mount_top();
    let mut mounts = MOUNTS.lock();
    let parent = containing_mount(&mounts, ns, &top);
    top.mounted.lock().insert(ns, root.clone());
    root.mnt_flags.lock().insert(ns, flags);
    mounts.push(MountEntry {
        id: mount_id(),
        ns,
        at: Some(top),
        root,
        parent,
        source: String::from(source),
        sb,
        flags,
    });
}

/// The ID of the mount `d` lies in, in the caller's namespace (the one
/// /proc/<pid>/mountinfo shows; never reused).
pub fn mount_id_of(d: &Arc<Dentry>) -> Option<u64> {
    let ns = mnt_ns();
    let mounts = MOUNTS.lock();
    let r = containing_mount(&mounts, ns, d)?;
    mounts.iter().find(|m| m.ns == ns && Arc::ptr_eq(&m.root, &r)).map(|m| m.id)
}

/// The file system (root inode) and flags of the mount `d` lies in, in
/// the caller's namespace.
fn mount_of(d: &Arc<Dentry>) -> Option<(Arc<dyn Inode>, u32)> {
    let ns = mnt_ns();
    let mounts = MOUNTS.lock();
    let r = containing_mount(&mounts, ns, d)?;
    mounts.iter().find(|m| m.ns == ns && Arc::ptr_eq(&m.root, &r)).map(|m| (m.sb.clone(), m.flags))
}

/// The flags of the mount `d` lies in ([`MNT_RDONLY`] and the others), as
/// the caller's mount namespace has them: the nearest mount root above it
/// decides. A mount the caller's namespace does not show (a file opened
/// in another namespace, or under a detached mount) has every flag any
/// namespace gave it.
pub fn mount_flags(d: &Arc<Dentry>) -> u32 {
    let mut at = Some(d.clone());
    while let Some(x) = at {
        if x.fs_type.is_some() {
            let flags = x.mnt_flags.lock();
            return flags.get(&mnt_ns()).copied().unwrap_or_else(|| flags.values().fold(0, |a, f| a | f));
        }
        at = x.parent.clone();
    }
    0
}

/// EROFS if `d` lies in a read-only mount (checked before every change to
/// a file or directory): the nearest mount root above it decides.
pub fn writable(d: &Arc<Dentry>) -> Result<()> {
    // The system tree is read-only to the Linux domain (ADR 0032), the
    // system image to everyone without the system grant (ADR 0090).
    if crate::proc::domain::linux_caller() && in_system_tree(d) {
        return Err(EROFS);
    }
    if in_image(d) && !crate::proc::domain::may_write_image() {
        return Err(EROFS);
    }
    if mount_flags(d) & MNT_RDONLY != 0 { Err(EROFS) } else { Ok(()) }
}

/// Whether `d` lies in a read-only mount (statfs(2) ST_RDONLY).
pub fn on_read_only_mount(d: &Arc<Dentry>) -> bool {
    writable(d).is_err()
}

/// MS_REMOUNT: set the flags of the mount rooted at `mount_root` in the
/// caller's namespace (EINVAL if it is not a mount's root); flags not
/// given are cleared (mount(2)). Other namespaces' copies keep theirs.
pub fn remount(mount_root: &Arc<Dentry>, flags: u32) -> Result<()> {
    if flags & MNT_RDONLY != 0 {
        super::pagecache::write_back_all();
    }
    let ns = mnt_ns();
    let mut mounts = MOUNTS.lock();
    let m = mounts.iter_mut().find(|m| m.ns == ns && Arc::ptr_eq(&m.root, mount_root)).ok_or(EINVAL)?;
    m.flags = atime_default(flags & MNT_FLAGS);
    m.root.mnt_flags.lock().insert(ns, m.flags);
    Ok(())
}

/// Mount the file system rooted at `inode` on the directory `at`.
pub fn mount(at: &Arc<Dentry>, inode: Arc<dyn Inode>, fs_type: &'static str, source: &str, flags: u32) -> Result<()> {
    if !at.is_dir() {
        return Err(ENOTDIR);
    }
    let root = Dentry::new(&at.name, inode.clone(), at.parent.clone(), Some(fs_type));
    attach(at, root, source, inode, atime_default(flags & MNT_FLAGS));
    Ok(())
}

/// The file system type and source of the mount `d` lies in.
fn mount_info(d: &Arc<Dentry>) -> (&'static str, String) {
    let ns = mnt_ns();
    let mounts = MOUNTS.lock();
    let root = containing_mount(&mounts, ns, d);
    let e = root.and_then(|r| mounts.iter().find(|m| m.ns == ns && Arc::ptr_eq(&m.root, &r)).cloned());
    e.map_or(("?", String::from("none")), |e| (e.root.fs_type.unwrap_or("?"), e.source))
}

/// Bind mount (mount(2) MS_BIND): `src`'s tree also appears at `at`, with
/// the flags of the mount it is in; with `recursive`, so do the mounts
/// below `src`.
pub fn bind(src: &Arc<Dentry>, at: &Arc<Dentry>, recursive: bool) -> Result<()> {
    let (fs_type, source) = mount_info(src);
    let (sb, flags) = mount_of(src).unwrap_or_else(|| (src.inode.clone(), 0));
    let root = Dentry::new(&at.name, src.inode.clone(), at.parent.clone(), Some(fs_type));
    attach(at, root.clone(), &source, sb, flags);
    if !recursive {
        return Ok(());
    }
    // Mounts under `src`, outermost first, recreated under the new root.
    let ns = mnt_ns();
    let mut subs: Vec<MountEntry> = MOUNTS
        .lock()
        .iter()
        .filter(|m| m.ns == ns && m.at.as_ref().is_some_and(|a| a.is_under(src) && !Arc::ptr_eq(a, src)))
        .cloned()
        .collect();
    subs.sort_by_key(|m| m.at.as_ref().map_or(0, |a| a.path_from(None).matches('/').count()));
    for m in subs {
        let Some(a) = &m.at else { continue };
        let rel = a.path_from(Some(src));
        let Ok(target) = resolve_in(&root, &root, rel.trim_start_matches('/'), false) else { continue };
        let sub = Dentry::new(&target.name, m.root.inode.clone(), target.parent.clone(), m.root.fs_type);
        attach(&target, sub, &m.source, m.sb.clone(), m.flags);
    }
    Ok(())
}

/// The mounts below the mount rooted at `root` (namespace `ns`), deepest
/// first.
fn submounts(mounts: &[MountEntry], ns: u64, root: &Arc<Dentry>) -> Vec<Arc<Dentry>> {
    let mut out = Vec::new();
    for m in mounts.iter().filter(|m| m.ns == ns && m.parent.as_ref().is_some_and(|p| Arc::ptr_eq(p, root))) {
        out.extend(submounts(mounts, ns, &m.root));
        out.push(m.root.clone());
    }
    out
}

/// Unmount the mount whose root is `mount_root` (the top of the mounts at
/// a path). With `detach` (MNT_DETACH), the mounts below it go too;
/// without, they make it busy.
pub fn unmount(mount_root: &Arc<Dentry>, detach: bool) -> Result<()> {
    // The top mount on that point goes (after pivot_root(".", ".") the old
    // root is stacked on the new one).
    let mount_root = &mount_root.mount_top();
    let ns = mnt_ns();
    let gone = {
        let mut mounts = MOUNTS.lock();
        let Some(e) = mounts.iter().find(|m| m.ns == ns && Arc::ptr_eq(&m.root, mount_root)).cloned() else {
            return Err(EINVAL);
        };
        let at = e.at.clone().ok_or(EBUSY)?;
        let subs = submounts(&mounts, ns, mount_root);
        if !subs.is_empty() && !detach {
            return Err(EBUSY);
        }
        let mut gone = subs;
        gone.push(mount_root.clone());
        let removed: Vec<MountEntry> =
            mounts.iter().filter(|m| m.ns == ns && gone.iter().any(|r| Arc::ptr_eq(&m.root, r))).cloned().collect();
        for r in &gone {
            if let Some(m) = mounts.iter().find(|m| m.ns == ns && Arc::ptr_eq(&m.root, r))
                && let Some(a) = &m.at
            {
                a.mounted.lock().remove(&ns);
            }
            mounts.retain(|m| !(m.ns == ns && Arc::ptr_eq(&m.root, r)));
        }
        let _ = at;
        let mut sbs: Vec<Arc<dyn Inode>> = Vec::new();
        for r in &gone {
            if let Some(m) = removed.iter().find(|m| Arc::ptr_eq(&m.root, r)) {
                sbs.push(m.sb.clone());
            }
        }
        // What was cached below mount roots no namespace shows any more is
        // dropped (the cache's links go both ways).
        for r in &gone {
            if !mounts.iter().any(|m| Arc::ptr_eq(&m.root, r)) {
                r.prune();
            }
        }
        // File systems that no mount in any namespace shows any more are
        // told so.
        sbs.retain(|sb| !mounts.iter().any(|m| same_inode(&m.sb, sb)));
        sbs
    };
    if !gone.is_empty() {
        // Cached data must reach the file systems before they close.
        super::pagecache::write_back_all();
    }
    for sb in gone {
        sb.unmounted();
    }
    Ok(())
}

fn same_inode(a: &Arc<dyn Inode>, b: &Arc<dyn Inode>) -> bool {
    core::ptr::eq(Arc::as_ptr(a).cast::<u8>(), Arc::as_ptr(b).cast::<u8>())
}

/// A new mount namespace `new` starts with a copy of `old`'s mounts.
pub fn copy_mounts(old: u64, new: u64) {
    let mut mounts = MOUNTS.lock();
    let copies: Vec<MountEntry> = mounts.iter().filter(|m| m.ns == old).cloned().collect();
    for mut m in copies {
        if let Some(a) = &m.at {
            a.mounted.lock().insert(new, m.root.clone());
        }
        m.root.mnt_flags.lock().insert(new, m.flags);
        m.ns = new;
        m.id = mount_id();
        mounts.push(m);
    }
}

/// A mount namespace ended: drop its mounts.
pub fn drop_mounts(ns: u64) {
    let gone: Vec<Arc<dyn Inode>> = {
        let mut mounts = MOUNTS.lock();
        let mine: Vec<MountEntry> = mounts.iter().filter(|m| m.ns == ns).cloned().collect();
        for m in &mine {
            if let Some(a) = &m.at {
                a.mounted.lock().remove(&ns);
            }
            m.root.mnt_flags.lock().remove(&ns);
        }
        mounts.retain(|m| m.ns != ns);
        mine.into_iter().map(|m| m.sb).filter(|sb| !mounts.iter().any(|m| same_inode(&m.sb, sb))).collect()
    };
    if !gone.is_empty() {
        // Cached data must reach the file systems before they close.
        super::pagecache::write_back_all();
    }
    for sb in gone {
        sb.unmounted();
    }
}

/// pivot_root(2): `new_root` becomes the root of the caller's mount
/// namespace and the old root (`old_root`) is mounted at `put_old`.
/// Returns the old root's dentry so the caller can move processes.
pub fn pivot_root(new_root: &Arc<Dentry>, put_old: &Arc<Dentry>, old_root: &Arc<Dentry>) -> Result<()> {
    let ns = mnt_ns();
    let mut mounts = MOUNTS.lock();
    let new_i = mounts.iter().position(|m| m.ns == ns && Arc::ptr_eq(&m.root, new_root)).ok_or(EINVAL)?;
    let old_i = mounts.iter().position(|m| m.ns == ns && Arc::ptr_eq(&m.root, old_root)).ok_or(EINVAL)?;
    if new_i == old_i {
        return Err(EBUSY);
    }
    // The new root leaves its parent mount; the old root goes under it.
    if let Some(a) = mounts[new_i].at.take() {
        a.mounted.lock().remove(&ns);
    }
    mounts[new_i].parent = None;
    let top = put_old.mount_top();
    if let Some(a) = mounts[old_i].at.take() {
        a.mounted.lock().remove(&ns);
    }
    top.mounted.lock().insert(ns, old_root.clone());
    let parent = containing_mount(&mounts, ns, &top);
    mounts[old_i].at = Some(top);
    mounts[old_i].parent = parent;
    Ok(())
}

/// Where `d` stands, for walking up: its name and parent, or, for the
/// root of a mount in namespace `ns`, its mount point's (a mount's root
/// takes them when mounted, but pivot_root moves a mount and leaves its
/// root's own; ADR 0114). None at the top.
fn standing(d: &Arc<Dentry>, ns: u64, mounts: &[MountEntry]) -> (String, Option<Arc<Dentry>>, Option<Arc<Dentry>>) {
    match mounts.iter().find(|m| m.ns == ns && Arc::ptr_eq(&m.root, d)).and_then(|m| m.at.clone()) {
        Some(a) => (a.name.clone(), a.parent.clone(), Some(a)),
        None => (d.name.clone(), d.parent.clone(), None),
    }
}

/// The path of `d` from `root` in namespace `ns`, through its mounts.
fn path_in(d: &Arc<Dentry>, root: Option<&Arc<Dentry>>, ns: u64, mounts: &[MountEntry]) -> String {
    let mut parts = Vec::new();
    let mut d = d.clone();
    loop {
        if root.is_some_and(|r| Arc::ptr_eq(r, &d)) {
            break;
        }
        let (name, parent, at) = standing(&d, ns, mounts);
        if at.as_ref().is_some_and(|a| root.is_some_and(|r| Arc::ptr_eq(r, a))) {
            break;
        }
        let Some(p) = parent else { break };
        parts.push(name);
        d = p;
    }
    let mut s = String::new();
    for p in parts.iter().rev() {
        s.push('/');
        s.push_str(p);
    }
    if s.is_empty() { String::from("/") } else { s }
}

/// Whether `d` is `ancestor` or below it in namespace `ns`.
fn under_in(d: &Arc<Dentry>, ancestor: &Arc<Dentry>, ns: u64, mounts: &[MountEntry]) -> bool {
    let mut d = Some(d.clone());
    while let Some(x) = d {
        if Arc::ptr_eq(&x, ancestor) {
            return true;
        }
        let (_, parent, at) = standing(&x, ns, mounts);
        if at.as_ref().is_some_and(|a| Arc::ptr_eq(a, ancestor)) {
            return true;
        }
        d = parent;
    }
    false
}

/// The path of `d` from `root` as the calling process's mount namespace
/// has it.
pub fn path_seen(d: &Arc<Dentry>, root: &Arc<Dentry>) -> String {
    let ns = mnt_ns();
    let mounts = MOUNTS.lock();
    path_in(d, Some(root), ns, &mounts)
}

/// One mount as /proc/<pid>/mounts and mountinfo show it.
pub struct MountView {
    pub id: u64,
    pub parent_id: u64,
    pub dev: u64,
    /// The mount point, from the viewer's root.
    pub path: String,
    pub fs_type: &'static str,
    pub source: String,
    /// The mount's flags ([`MNT_RDONLY`] and the others).
    pub flags: u32,
}

/// The mounts of namespace `ns` under `root` (a process's root
/// directory), in mount order.
pub fn mounts_of(ns: u64, root: &Arc<Dentry>) -> Vec<MountView> {
    let mounts = MOUNTS.lock();
    let mine: Vec<&MountEntry> = mounts.iter().filter(|m| m.ns == ns && under_in(&m.root, root, ns, &mounts)).collect();
    let views: Vec<(Arc<Dentry>, MountView)> = mine
        .iter()
        .map(|m| {
            // The parent is the mount `at` lies in; the root mount is its
            // own parent, as on Linux.
            let parent_id = m
                .parent
                .as_ref()
                .and_then(|p| mounts.iter().find(|x| x.ns == ns && Arc::ptr_eq(&x.root, p)))
                .map_or(m.id, |x| x.id);
            let view = MountView {
                id: m.id,
                parent_id,
                dev: 0,
                path: path_in(&m.root, Some(root), ns, &mounts),
                fs_type: m.root.fs_type.unwrap_or("?"),
                source: m.source.clone(),
                flags: m.flags,
            };
            (m.root.clone(), view)
        })
        .collect();
    drop(mounts);
    // Inode calls happen without the mount table lock.
    views
        .into_iter()
        .map(|(d, mut v)| {
            v.dev = d.metadata().dev;
            if d.inode.statfs().is_some_and(|s| s.read_only) {
                v.flags |= MNT_RDONLY;
            }
            v
        })
        .collect()
}

/// Current mounts as the calling process sees them. Only the caller's
/// namespace, and in a chroot only the mounts inside it, with paths from
/// its root.
pub fn mounts() -> Vec<MountView> {
    let root = crate::proc::current().map_or_else(root, |p| p.root_dir());
    mounts_of(mnt_ns(), &root)
}

/// The path of `d` as the calling process sees it (from its root
/// directory, which differs from the real root in a chroot).
pub fn visible_path(d: &Arc<Dentry>) -> String {
    let root = crate::proc::current().map(|p| p.root_dir());
    let ns = mnt_ns();
    let mounts = MOUNTS.lock();
    path_in(d, root.as_ref(), ns, &mounts)
}

/// Resolve `path` relative to `cwd` (or the calling process's root
/// directory, for absolute paths). With `follow`, a symlink in the last
/// component is followed too.
pub fn resolve(cwd: &Arc<Dentry>, path: &str, follow: bool) -> Result<Arc<Dentry>> {
    resolve_restricted(cwd, path, follow, Restrict::default())
}

/// openat2(2)'s RESOLVE_* restrictions on a lookup (ADR 0115). Errors as
/// openat2(2) gives them and Linux was seen to: EXDEV for an escape from
/// the starting directory or its mount, ELOOP for a link not allowed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Restrict {
    /// RESOLVE_BENEATH: never above the starting directory; no absolute
    /// paths or symlinks, no magic links.
    pub beneath: bool,
    /// RESOLVE_IN_ROOT: the starting directory is the root; no magic links.
    pub in_root: bool,
    /// RESOLVE_NO_SYMLINKS (magic links too).
    pub no_symlinks: bool,
    /// RESOLVE_NO_MAGICLINKS: none of /proc's magic links.
    pub no_magiclinks: bool,
    /// RESOLVE_NO_XDEV: no mount crossed, bind mounts included.
    pub no_xdev: bool,
    /// RESOLVE_CACHED: only names already in the dentry cache; anything
    /// that would ask the file system is EAGAIN.
    pub cached: bool,
}

/// [`resolve`] under openat2's restrictions, from `cwd` (dirfd's).
pub fn resolve_restricted(cwd: &Arc<Dentry>, path: &str, follow: bool, r: Restrict) -> Result<Arc<Dentry>> {
    let root = if r.in_root { cwd.clone() } else { crate::proc::current().map_or_else(root, |p| p.root_dir()) };
    resolve_with(&root, cwd, path, follow, r)
}

/// [`resolve`] with an explicit root directory (`..` never leaves it).
pub fn resolve_in(root: &Arc<Dentry>, cwd: &Arc<Dentry>, path: &str, follow: bool) -> Result<Arc<Dentry>> {
    resolve_with(root, cwd, path, follow, Restrict::default())
}

fn resolve_with(root: &Arc<Dentry>, cwd: &Arc<Dentry>, path: &str, follow: bool, r: Restrict) -> Result<Arc<Dentry>> {
    let mut budget = MAX_SYMLINKS;
    let cred = crate::proc::cred::current();
    // Search permission on every directory walked (root may always).
    let check =
        !cred.capable(crate::proc::cred::CAP_DAC_OVERRIDE) && !cred.capable(crate::proc::cred::CAP_DAC_READ_SEARCH);
    let walk = Walk { root, base: cwd, mount: r.no_xdev.then(|| mount_root_of(cwd)).flatten(), r, cred: &cred, check };
    let d = resolve_inner(&walk, cwd, path, follow, &mut budget)?;
    // A confined app reaches only what it declared (ADR 0130).
    crate::proc::apps::may_reach(&d)?;
    Ok(d)
}

/// One lookup's fixed points: the root, the directory it started from
/// (RESOLVE_BENEATH's limit), and that directory's mount (RESOLVE_NO_XDEV);
/// who looks, and whether directories' search permission is checked.
struct Walk<'a> {
    root: &'a Arc<Dentry>,
    base: &'a Arc<Dentry>,
    mount: Option<Arc<Dentry>>,
    r: Restrict,
    cred: &'a crate::proc::cred::Cred,
    check: bool,
}

impl Walk<'_> {
    /// EXDEV if `d` is on another mount than the start (RESOLVE_NO_XDEV).
    fn same_mount(&self, d: &Arc<Dentry>) -> Result<()> {
        match &self.mount {
            Some(m) if !mount_root_of(d).is_some_and(|x| Arc::ptr_eq(&x, m)) => Err(EXDEV),
            _ => Ok(()),
        }
    }
}

/// The mount `d` lies in (the caller's namespace): its ID (as mountinfo
/// shows it) and its root.
pub fn mount_of_dentry(d: &Arc<Dentry>) -> Option<(u64, Arc<Dentry>)> {
    let ns = mnt_ns();
    let mounts = MOUNTS.lock();
    let r = containing_mount(&mounts, ns, d)?;
    let id = mounts.iter().find(|m| m.ns == ns && Arc::ptr_eq(&m.root, &r))?.id;
    Some((id, r))
}

/// The file numbered `ino` in the mount whose root is `root`, as a dentry
/// (open_by_handle_at(2)): one already known by name, else the file
/// system's own lookup by number, else a search of the mount's tree (at
/// most [`HANDLE_SEARCH`] names). A file found by number alone hangs under
/// the mount's root, so the mount's read-only state and the system
/// tree's rules still find it.
pub fn find_by_number(root: &Arc<Dentry>, ino: u64) -> Result<Arc<Dentry>> {
    if root.metadata().ino == ino {
        return Ok(root.clone());
    }
    let holds = root.inode.holds_number(ino);
    if holds == Some(false) {
        return Err(ESTALE);
    }
    // Names already looked up.
    let mut todo = alloc::vec![root.clone()];
    while let Some(d) = todo.pop() {
        for c in d.children.lock().values() {
            if c.metadata().ino == ino {
                return Ok(c.clone());
            }
            if c.is_dir() {
                todo.push(c.clone());
            }
        }
    }
    if let Ok(inode) = root.inode.by_number(ino) {
        // A directory gets its path back through its parents; a file
        // stays nameless, as a disconnected handle's does.
        if let Some(d) = reconnect(root, &inode, ino) {
            return Ok(d);
        }
        return Ok(Dentry::new(&alloc::format!("#{ino}"), inode, Some(root.clone()), None));
    }
    // A search of the tree, for file systems without numbers to look up:
    // bounded unless the file system says the file is there.
    let mut todo = alloc::vec![root.clone()];
    let mut seen = 0;
    while let Some(d) = todo.pop() {
        for e in d.inode.readdir().unwrap_or_default() {
            if e.name == "." || e.name == ".." {
                continue;
            }
            seen += 1;
            if seen > HANDLE_SEARCH && holds != Some(true) {
                return Err(ESTALE);
            }
            let Ok(c) = d.child(&e.name) else { continue };
            if c.metadata().ino == ino {
                return Ok(c);
            }
            if c.is_dir() && c.metadata().file_type() == FileType::Directory {
                todo.push(c);
            }
        }
    }
    Err(ESTALE)
}

/// The dentry of directory `inode` (number `ino`) by its path from
/// `root`: up through its parents' numbers to the root, then down by the
/// names under which each lists the next.
fn reconnect(root: &Arc<Dentry>, inode: &Arc<dyn Inode>, ino: u64) -> Option<Arc<Dentry>> {
    if inode.metadata().file_type() != FileType::Directory {
        return None;
    }
    let top = root.metadata().ino;
    let mut chain = alloc::vec![ino];
    let mut cur = inode.clone();
    loop {
        let p = cur.parent_number()?;
        if p == top {
            break;
        }
        // The file system's own root (outside this mount's), or a loop.
        if chain.contains(&p) || chain.len() > 4096 {
            return None;
        }
        chain.push(p);
        cur = root.inode.by_number(p).ok()?;
    }
    let mut d = root.clone();
    for want in chain.iter().rev() {
        let name =
            d.inode.readdir().ok()?.into_iter().find(|e| e.ino == *want && e.name != "." && e.name != "..")?.name;
        d = d.child(&name).ok()?;
    }
    Some(d)
}

/// The most names [`find_by_number`] searches.
const HANDLE_SEARCH: usize = 100_000;

/// The root of the mount `d` lies in (the caller's namespace).
fn mount_root_of(d: &Arc<Dentry>) -> Option<Arc<Dentry>> {
    containing_mount(&MOUNTS.lock(), mnt_ns(), d)
}

fn resolve_inner(w: &Walk<'_>, cwd: &Arc<Dentry>, path: &str, follow: bool, budget: &mut usize) -> Result<Arc<Dentry>> {
    let root = w.root;
    if path.is_empty() {
        return Err(ENOENT);
    }
    if path.len() > PATH_MAX {
        return Err(ENAMETOOLONG);
    }
    if w.r.beneath && path.starts_with('/') {
        return Err(EXDEV);
    }
    let mut d = if path.starts_with('/') { root.clone() } else { cwd.clone() };
    w.same_mount(&d)?;
    // A trailing slash follows a final symlink in any case (path_resolution(7)).
    let follow = follow || path.ends_with('/');
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    for (i, part) in parts.iter().enumerate() {
        let last = i == parts.len() - 1;
        if *part == ".." && w.r.beneath && Arc::ptr_eq(&d, w.base) {
            return Err(EXDEV);
        }
        if *part == ".." && Arc::ptr_eq(&d, root) {
            continue; // `..` at the root stays there (also in a chroot).
        }
        if w.check && d.is_dir() {
            w.cred.permission(&d.metadata(), crate::proc::cred::MAY_EXEC)?;
        }
        let next = if w.r.cached { d.cached_child(part)? } else { d.child(part)? };
        w.same_mount(&next)?;
        let meta = next.metadata();
        if meta.file_type() == FileType::Symlink && (!last || follow) {
            if *budget == 0 {
                return Err(ELOOP);
            }
            *budget -= 1;
            if let Some(t) = next.inode.magic_target() {
                if w.r.no_symlinks || w.r.no_magiclinks {
                    return Err(ELOOP);
                }
                if w.r.beneath || w.r.in_root {
                    return Err(EXDEV);
                }
                w.same_mount(&t)?;
                d = t;
                continue;
            }
            if w.r.no_symlinks {
                return Err(ELOOP);
            }
            // proc(5) protected_symlinks.
            if !super::protect::may_follow(&d.metadata(), &meta, w.cred) {
                return Err(EACCES);
            }
            let target = next.inode.readlink()?;
            d = resolve_inner(w, &d, &target, true, budget)?;
        } else {
            d = next;
        }
    }
    // A trailing slash requires a directory.
    if path.ends_with('/') && !d.is_dir() {
        return Err(ENOTDIR);
    }
    Ok(d)
}

/// Resolve all but the last component; returns the parent directory and
/// the final name (which may not exist).
pub fn resolve_parent(cwd: &Arc<Dentry>, path: &str) -> Result<(Arc<Dentry>, String)> {
    resolve_parent_restricted(cwd, path, Restrict::default())
}

/// [`resolve_parent`] under openat2's restrictions.
pub fn resolve_parent_restricted(cwd: &Arc<Dentry>, path: &str, r: Restrict) -> Result<(Arc<Dentry>, String)> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return if path.starts_with('/') { Err(EEXIST) } else { Err(ENOENT) };
    }
    let (dir, name) = match trimmed.rfind('/') {
        Some(0) => ("/", &trimmed[1..]),
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None => (".", trimmed),
    };
    // The parent is `dir` from `cwd` (RESOLVE_BENEATH refuses an absolute
    // `dir` itself; RESOLVE_IN_ROOT starts it at cwd).
    let parent = resolve_restricted(cwd, dir, true, r)?;
    if !parent.is_dir() {
        return Err(ENOTDIR);
    }
    if name.len() > NAME_MAX {
        return Err(ENAMETOOLONG);
    }
    Ok((parent, name.to_string()))
}
