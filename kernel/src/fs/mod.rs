// SPDX-License-Identifier: MIT OR Apache-2.0

//! Files: the VFS, file systems, open files and descriptor tables.

pub mod cgroup;
pub mod devices;
pub mod devpts;
pub mod efivarfs;
pub mod events;
pub mod ext4;
pub mod initramfs;
pub mod inotify;
pub mod locks;
pub mod overlay;
pub mod pagecache;
pub mod pipe;
pub mod procfs;
pub mod protect;
pub mod slatefs;
pub mod tmpfs;
pub mod tty;
pub mod vfs;
pub mod vt;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use vfs::{Dentry, DirEntry, FileType, Metadata, Result, S_IFMT, S_IFREG};

use crate::abi::linux::errno::*;
use crate::sync::IrqSpinLock;

/// sync(2): write back every cached file, then make every disk file
/// system durable.
pub fn sync_all() {
    pagecache::write_back_all();
    ext4::flush_all();
    slatefs::flush_all();
}

/// Before power-off or reboot: write back every cached file, close the
/// disk file systems (marked clean), flush and park the disks, and give
/// the hardware clock the time if it was set.
pub fn shutdown() {
    pagecache::write_back_all();
    ext4::sync_all();
    slatefs::sync_all();
    crate::block::shutdown_all();
    crate::drivers::rtc::sync_at_shutdown();
    crate::drivers::amd::shutdown();
}

// open(2) flags. Source: musl `fcntl.h`/`bits/fcntl.h` (ADR 0009).
pub const O_ACCMODE: u32 = 0o3;
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_CREAT: u32 = 0o100;
pub const O_EXCL: u32 = 0o200;
pub const O_NOCTTY: u32 = 0o400;
pub const O_TRUNC: u32 = 0o1000;
pub const O_APPEND: u32 = 0o2000;
pub const O_NONBLOCK: u32 = 0o4000;
pub const O_DSYNC: u32 = 0o10000;
/// O_SYNC includes O_DSYNC's bit.
pub const O_SYNC: u32 = 0o4010000;
/// Minimize cache effects (open(2)): what a transfer brings into the
/// page cache is written back and dropped after it (ADR 0145).
pub const O_DIRECT: u32 = 0o40000;
pub const O_DIRECTORY: u32 = 0o200000;
pub const O_NOFOLLOW: u32 = 0o400000;
/// Don't update the access time (open(2)): Slate updates none on reads,
/// so this asks only for open(2)'s ownership check.
pub const O_NOATIME: u32 = 0o1000000;
pub const O_CLOEXEC: u32 = 0o2000000;
pub const O_PATH: u32 = 0o10000000;
/// Status flags F_SETFL may change (fcntl(2)).
pub const SETFL_MASK: u32 = O_APPEND | O_NONBLOCK | O_DIRECT | O_NOATIME;

// lseek(2) whence values.
pub const SEEK_SET: u32 = 0;
pub const SEEK_CUR: u32 = 1;
pub const SEEK_END: u32 = 2;

/// Readiness bits for poll(2). Source: musl `poll.h` (ADR 0009).
pub const POLLIN: u16 = 0x001;
pub const POLLOUT: u16 = 0x004;
pub const POLLERR: u16 = 0x008;
pub const POLLHUP: u16 = 0x010;
pub const POLLNVAL: u16 = 0x020;
/// The peer shut down writing (poll(2), Linux-specific).
pub const POLLRDHUP: u16 = 0x2000;

static POLL_GENERATION: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static POLL_WAIT: crate::sched::wait::WaitQueue = crate::sched::wait::WaitQueue::new();

/// Something's readiness may have changed: wake poll(2)/select(2) waiters,
/// which re-check their descriptors.
pub fn poll_notify() {
    POLL_GENERATION.fetch_add(1, Ordering::Release);
    POLL_WAIT.wake_all();
}

/// Wait until [`poll_notify`] is called after `seen` was read from
/// [`poll_generation`], a signal arrives, or `deadline_ns` passes.
pub fn poll_wait(seen: u64, deadline_ns: Option<u64>) -> crate::sched::wait::WaitResult {
    let changed = || POLL_GENERATION.load(Ordering::Acquire) != seen;
    match deadline_ns {
        Some(d) => POLL_WAIT.wait_until_deadline(changed, d),
        None if POLL_WAIT.wait_until_interruptible(changed) => crate::sched::wait::WaitResult::Interrupted,
        None => crate::sched::wait::WaitResult::Ready,
    }
}

pub fn poll_generation() -> u64 {
    POLL_GENERATION.load(Ordering::Acquire)
}

/// Something a file descriptor refers to.
/// Whether a descriptor of `f` stays in the Slate domain (ADR 0098):
/// written into the system tree, which Linux programs may not write
/// (ADR 0032), or a connection to a Slate-domain server.
pub fn stays_in_slate(f: &Arc<dyn File>) -> bool {
    f.slate_only() || (f.status_flags() & O_ACCMODE != O_RDONLY && f.dentry().is_some_and(|d| vfs::in_system_tree(&d)))
}

pub trait File: Send + Sync + core::any::Any {
    fn read(&self, _buf: &mut [u8]) -> Result<usize> {
        Err(EINVAL)
    }
    /// Reads never wait for more to arrive (regular files, disks): read(2)
    /// keeps reading until the buffer is full or the end is reached, as
    /// on Linux. Pipes, sockets and terminals return what is there.
    fn fills_reads(&self) -> bool {
        false
    }
    /// The most one read(2) returns (for files that fill their reads).
    fn read_limit(&self) -> u64 {
        u64::MAX
    }
    fn write(&self, _buf: &[u8]) -> Result<usize> {
        Err(EINVAL)
    }
    fn pread(&self, _offset: u64, _buf: &mut [u8]) -> Result<usize> {
        Err(ESPIPE)
    }
    fn pwrite(&self, _offset: u64, _buf: &[u8]) -> Result<usize> {
        Err(ESPIPE)
    }
    fn seek(&self, _offset: i64, _whence: u32) -> Result<u64> {
        Err(ESPIPE)
    }
    /// Device control; `arg` is a user address or value.
    fn ioctl(&self, _cmd: u32, _arg: u64) -> Result<u64> {
        Err(ENOTTY)
    }
    fn stat(&self) -> Result<Metadata> {
        match self.dentry() {
            Some(d) => Ok(d.metadata()),
            None => Ok(Metadata { mode: vfs::S_IFIFO | 0o600, nlink: 1, ..Metadata::default() }),
        }
    }
    /// Directory listing: call `emit(entry, offset_after)` for each entry from
    /// the current position until it returns false.
    fn getdents(&self, _emit: &mut dyn FnMut(&DirEntry, u64) -> bool) -> Result<()> {
        Err(ENOTDIR)
    }
    fn truncate(&self, _len: u64) -> Result<()> {
        Err(EINVAL)
    }
    /// Current readiness (POLL* bits).
    fn poll(&self) -> u16 {
        POLLIN | POLLOUT
    }
    /// A counter that moves on every readiness event (data arriving, space
    /// freed, hang-up), for edge-triggered epoll. 0 means "not tracked":
    /// edges are then detected from changes in `poll` alone.
    fn event_count(&self) -> u64 {
        0
    }
    /// Access mode and status flags (F_GETFL).
    fn status_flags(&self) -> u32 {
        O_RDWR
    }
    fn set_status_flags(&self, _flags: u32) {}
    /// With O_DIRECT, the alignment its transfers need (ADR 0162): the
    /// user's buffer, the length and the offset must be multiples of it
    /// (open(2): EINVAL otherwise).
    fn direct_align(&self) -> Option<u64> {
        None
    }
    /// The name this file was opened through, if any.
    fn dentry(&self) -> Option<Arc<Dentry>> {
        None
    }
    /// It must not reach the Linux domain whatever it is (ADR 0098): a
    /// connection to a Slate-domain server.
    fn slate_only(&self) -> bool {
        false
    }
    /// The namespace a /proc/<pid>/ns file names (setns(2)).
    fn namespace(&self) -> Option<NsRef> {
        None
    }
    /// For files whose kind a system call needs to know (pidfds).
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        None
    }
    /// What `mmap` of this file at `offset` maps, for files that are not
    /// regular files but have pages of their own (DRM dumb buffers,
    /// dma-bufs): an inode whose `shared_page` gives the frame at each file
    /// offset, or why it can't be mapped.
    fn mmap_source(&self, _offset: u64) -> Option<Result<Arc<dyn vfs::Inode>>> {
        None
    }
}

/// A namespace of some kind (ADR 0028).
#[derive(Clone, Debug)]
pub enum NsRef {
    Uts(Arc<crate::proc::ns::UtsNs>),
    Ipc(Arc<crate::proc::ns::IpcNs>),
    Mnt(Arc<crate::proc::ns::MntNs>),
    Net(Arc<crate::proc::ns::NetNs>),
    Pid(Arc<crate::proc::ns::PidNs>),
    User(Arc<crate::proc::ns::UserNs>),
    Cgroup(Arc<crate::proc::ns::CgroupNs>),
}

/// statfs(2) totals for a pseudo file system of type `magic`.
fn anon_statfs(magic: i64) -> vfs::StatFs {
    vfs::StatFs { magic, block_size: 4096, blocks: 0, free_blocks: 0, files: 0, free_files: 0, read_only: false }
}

/// NSFS_MAGIC's device for namespace files.
const NSFS_DEV: u64 = 0xF3;

impl NsRef {
    pub fn ino(&self) -> u64 {
        match self {
            NsRef::Uts(n) => n.ino,
            NsRef::Ipc(n) => n.ino,
            NsRef::Mnt(n) => n.ino,
            NsRef::Net(n) => n.ino,
            NsRef::Pid(n) => n.ino,
            NsRef::User(n) => n.ino,
            NsRef::Cgroup(n) => n.ino,
        }
    }

    fn metadata(&self) -> Metadata {
        Metadata { dev: NSFS_DEV, ino: self.ino(), mode: vfs::S_IFREG | 0o444, nlink: 1, ..Metadata::default() }
    }
}

/// What a /proc/<pid>/ns link leads to.
pub struct NsInode(pub NsRef);

impl vfs::Inode for NsInode {
    fn metadata(&self) -> Metadata {
        self.0.metadata()
    }
    fn open_special(self: Arc<Self>, flags: u32) -> Option<Result<Arc<dyn File>>> {
        let f: Arc<dyn File> = Arc::new(NsFile { ns: self.0.clone(), flags });
        Some(Ok(f))
    }
    fn statfs(&self) -> Option<vfs::StatFs> {
        // NSFS_MAGIC (statfs(2)).
        Some(anon_statfs(0x6e73_6673))
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// An open namespace file.
pub struct NsFile {
    ns: NsRef,
    flags: u32,
}

impl File for NsFile {
    fn stat(&self) -> Result<Metadata> {
        Ok(self.ns.metadata())
    }
    fn status_flags(&self) -> u32 {
        self.flags
    }
    fn namespace(&self) -> Option<NsRef> {
        Some(self.ns.clone())
    }
}

/// What a /proc/<pid>/fd link to a pipe or socket leads to: opening it
/// gives that open file again (proc(5)).
pub struct FdInode(pub Arc<dyn File>);

impl vfs::Inode for FdInode {
    fn metadata(&self) -> Metadata {
        self.0.stat().unwrap_or_default()
    }
    fn open_special(self: Arc<Self>, _flags: u32) -> Option<Result<Arc<dyn File>>> {
        Some(Ok(self.0.clone()))
    }
    fn statfs(&self) -> Option<vfs::StatFs> {
        // ANON_INODE_FS_MAGIC (statfs(2)).
        Some(anon_statfs(0x0904_1934))
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// An open regular file or directory.
pub struct OpenFile {
    dentry: Arc<Dentry>,
    flags: AtomicU32,
    /// Byte offset, or for directories the position to continue a listing
    /// from: 0 and 1 are "." and "..", then 2 + the entry's `pos`.
    /// A sleeping lock: reads and writes hold it across the file system
    /// call, which may itself sleep (disk I/O, the file system's lock).
    offset: crate::sched::wait::Mutex<u64>,
    /// The monotonic second the access time was last looked at, plus one
    /// (0: never): reads look at most once a second (ADR 0162).
    atime_seen: AtomicU64,
}

impl OpenFile {
    pub fn new(dentry: Arc<Dentry>, flags: u32) -> OpenFile {
        OpenFile {
            dentry,
            flags: AtomicU32::new(flags & !(O_CREAT | O_EXCL | O_TRUNC | O_CLOEXEC)),
            offset: crate::sched::wait::Mutex::new(0),
            atime_seen: AtomicU64::new(0),
        }
    }

    /// The file was read: its access time is updated as its mount says,
    /// unless it was opened with O_NOATIME (ADR 0162), looked at no more
    /// than once a second.
    fn accessed(&self) {
        if self.flags.load(Ordering::Relaxed) & O_NOATIME != 0 {
            return;
        }
        let now = crate::time::monotonic_ns() / crate::time::NS_PER_SEC + 1;
        if self.atime_seen.swap(now, Ordering::Relaxed) != now {
            vfs::accessed(&self.dentry);
        }
    }

    fn readable(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & O_ACCMODE != O_WRONLY && self.flags.load(Ordering::Relaxed) & O_PATH == 0
    }

    fn writable(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & O_ACCMODE != O_RDONLY && self.flags.load(Ordering::Relaxed) & O_PATH == 0
    }

    /// After a write: O_SYNC and O_DSYNC make it durable before returning.
    fn synced(&self) -> Result<()> {
        if self.flags.load(Ordering::Relaxed) & O_DSYNC != 0 { self.dentry.inode.sync() } else { Ok(()) }
    }

    /// O_DIRECT's offsets are multiples of the file's alignment (open(2):
    /// EINVAL; ADR 0162). A read at or past the end has nothing to align:
    /// it reads nothing (after a short last read, the offset is the size).
    fn aligned(&self, offset: u64) -> Result<()> {
        match self.direct_align() {
            Some(a) if offset % a != 0 => Err(EINVAL),
            _ => Ok(()),
        }
    }

    fn aligned_read(&self, offset: u64) -> Result<()> {
        if self.direct_align().is_some() && offset >= self.dentry.metadata().size {
            return Ok(());
        }
        self.aligned(offset)
    }

    /// After a transfer with O_DIRECT: a write is made durable, then what
    /// it or a read left in the page cache is dropped.
    fn uncached(&self, offset: u64, len: usize, wrote: bool) -> Result<()> {
        if self.flags.load(Ordering::Relaxed) & O_DIRECT == 0 || len == 0 {
            return Ok(());
        }
        if wrote {
            self.dentry.inode.sync()?;
        }
        self.dentry.inode.uncache(offset, len as u64);
        Ok(())
    }
}

/// A file changed by a write or a truncation loses its set-user-ID bit,
/// and its set-group-ID bit if group-executable, unless the writer has
/// CAP_FSETID (capabilities(7); write(2) and truncate(2) say they "may be
/// cleared"; which bits, and that a truncation to the same size counts,
/// as Linux was seen to do).
pub fn drop_set_ids(inode: &Arc<dyn vfs::Inode>) {
    use crate::proc::cred::{CAP_FSETID, S_ISGID, S_ISUID};
    let m = inode.metadata();
    let bits = m.mode & (S_ISUID | if m.mode & 0o010 != 0 { S_ISGID } else { 0 });
    if bits == 0 || m.file_type() != FileType::Regular || crate::proc::cred::current().capable_wrt(&m, CAP_FSETID) {
        return;
    }
    let _ = inode.set_mode(m.mode & 0o7777 & !bits);
}

impl Drop for OpenFile {
    fn drop(&mut self) {
        // The open file description is gone: its flock and OFD locks too.
        locks::ofd_dropped(core::ptr::from_ref(self).cast::<u8>() as usize);
    }
}

impl File for OpenFile {
    fn fills_reads(&self) -> bool {
        self.dentry.inode.metadata().mode & vfs::S_IFMT == vfs::S_IFREG
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if !self.readable() {
            return Err(EBADF);
        }
        let mut off = self.offset.lock();
        self.aligned_read(*off)?;
        let n = self.dentry.inode.read_at(*off, buf)?;
        self.uncached(*off, n, false)?;
        *off += n as u64;
        drop(off);
        self.accessed();
        Ok(n)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        if !self.writable() {
            return Err(EBADF);
        }
        let mut off = self.offset.lock();
        if self.flags.load(Ordering::Relaxed) & O_APPEND != 0 {
            *off = self.dentry.metadata().size;
        }
        self.aligned(*off)?;
        let end = crate::proc::rlimit::file_size_limit(*off, off.saturating_add(buf.len() as u64))?;
        let buf = &buf[..(end - *off) as usize];
        let n = self.dentry.inode.write_at(*off, buf)?;
        pagecache::wrote(&self.dentry.inode, *off, &buf[..n]);
        let at = *off;
        *off += n as u64;
        if n > 0 {
            drop_set_ids(&self.dentry.inode);
        }
        self.synced()?;
        self.uncached(at, n, true)?;
        Ok(n)
    }

    fn pread(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if !self.readable() {
            return Err(EBADF);
        }
        self.aligned_read(offset)?;
        let n = self.dentry.inode.read_at(offset, buf)?;
        self.uncached(offset, n, false)?;
        self.accessed();
        Ok(n)
    }

    fn pwrite(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        if !self.writable() {
            return Err(EBADF);
        }
        // With O_APPEND the data goes at the end whatever the offset
        // (pwrite(2), BUGS: as Linux does).
        let offset =
            if self.flags.load(Ordering::Relaxed) & O_APPEND != 0 { self.dentry.metadata().size } else { offset };
        self.aligned(offset)?;
        let end = crate::proc::rlimit::file_size_limit(offset, offset.saturating_add(buf.len() as u64))?;
        let buf = &buf[..(end - offset) as usize];
        let n = self.dentry.inode.write_at(offset, buf)?;
        pagecache::wrote(&self.dentry.inode, offset, &buf[..n]);
        if n > 0 {
            drop_set_ids(&self.dentry.inode);
        }
        self.synced()?;
        self.uncached(offset, n, true)?;
        Ok(n)
    }

    fn seek(&self, offset: i64, whence: u32) -> Result<u64> {
        let mut off = self.offset.lock();
        let base = match whence {
            SEEK_SET => 0,
            SEEK_CUR => *off as i64,
            SEEK_END => self.dentry.metadata().size as i64,
            _ => return Err(EINVAL),
        };
        let new = base.checked_add(offset).filter(|&n| n >= 0).ok_or(EINVAL)?;
        *off = new as u64;
        Ok(new as u64)
    }

    fn getdents(&self, emit: &mut dyn FnMut(&DirEntry, u64) -> bool) -> Result<()> {
        let d = &self.dentry;
        if !d.is_dir() {
            return Err(ENOTDIR);
        }
        let meta = d.metadata();
        let parent_ino = d.parent.as_ref().map_or(meta.ino, |p| p.metadata().ino);
        let mut entries = alloc::vec![
            DirEntry { name: ".".into(), ino: meta.ino, kind: FileType::Directory, pos: 0 },
            DirEntry { name: "..".into(), ino: parent_ino, kind: FileType::Directory, pos: 1 },
        ];
        entries.extend(d.inode.readdir()?.into_iter().map(|e| DirEntry { pos: e.pos + 2, ..e }));
        // Continue at the first entry at or after the saved position, so
        // entries removed or added meanwhile do not shift the others.
        let mut off = self.offset.lock();
        let start = *off;
        for e in entries.iter().filter(|e| e.pos >= start) {
            if !emit(e, e.pos + 1) {
                break;
            }
            *off = e.pos + 1;
        }
        drop(off);
        self.accessed();
        Ok(())
    }

    fn truncate(&self, len: u64) -> Result<()> {
        if !self.writable() {
            return Err(EINVAL);
        }
        self.dentry.inode.truncate(len)?;
        pagecache::truncated(&self.dentry.inode, len);
        drop_set_ids(&self.dentry.inode);
        Ok(())
    }

    fn status_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }

    fn set_status_flags(&self, flags: u32) {
        let old = self.flags.load(Ordering::Relaxed);
        self.flags.store((old & !SETFL_MASK) | (flags & SETFL_MASK), Ordering::Relaxed);
    }

    fn direct_align(&self) -> Option<u64> {
        if self.flags.load(Ordering::Relaxed) & O_DIRECT == 0 {
            return None;
        }
        self.dentry.inode.direct_align().map(u64::from)
    }

    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64> {
        self.dentry.inode.ioctl(cmd, arg)
    }

    fn dentry(&self) -> Option<Arc<Dentry>> {
        Some(self.dentry.clone())
    }
}

/// A device or special file opened through a name: delegates I/O to the
/// device object and reports the node's metadata.
pub struct NodeFile {
    pub inner: Arc<dyn File>,
    pub dentry: Arc<Dentry>,
    flags: AtomicU32,
}

impl NodeFile {
    pub fn new(inner: Arc<dyn File>, dentry: Arc<Dentry>, flags: u32) -> NodeFile {
        NodeFile { inner, dentry, flags: AtomicU32::new(flags & !(O_CREAT | O_EXCL | O_TRUNC | O_CLOEXEC)) }
    }
}

impl File for NodeFile {
    /// The device's own file (a block device's, for the disk calls).
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        self.inner.as_any()
    }
    fn fills_reads(&self) -> bool {
        self.inner.fills_reads()
    }
    fn read_limit(&self) -> u64 {
        self.inner.read_limit()
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if self.flags.load(Ordering::Relaxed) & O_ACCMODE == O_WRONLY {
            return Err(EBADF);
        }
        self.inner.read(buf)
    }
    fn write(&self, buf: &[u8]) -> Result<usize> {
        if self.flags.load(Ordering::Relaxed) & O_ACCMODE == O_RDONLY {
            return Err(EBADF);
        }
        self.inner.write(buf)
    }
    fn pread(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if self.flags.load(Ordering::Relaxed) & O_ACCMODE == O_WRONLY {
            return Err(EBADF);
        }
        self.inner.pread(offset, buf)
    }
    fn pwrite(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        if self.flags.load(Ordering::Relaxed) & O_ACCMODE == O_RDONLY {
            return Err(EBADF);
        }
        self.inner.pwrite(offset, buf)
    }
    fn seek(&self, offset: i64, whence: u32) -> Result<u64> {
        self.inner.seek(offset, whence)
    }
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64> {
        self.inner.ioctl(cmd, arg)
    }
    fn poll(&self) -> u16 {
        self.inner.poll()
    }
    fn event_count(&self) -> u64 {
        self.inner.event_count()
    }
    fn status_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }
    fn set_status_flags(&self, flags: u32) {
        let old = self.flags.load(Ordering::Relaxed);
        self.flags.store((old & !SETFL_MASK) | (flags & SETFL_MASK), Ordering::Relaxed);
        self.inner.set_status_flags(flags);
    }
    fn direct_align(&self) -> Option<u64> {
        self.inner.direct_align()
    }
    fn dentry(&self) -> Option<Arc<Dentry>> {
        Some(self.dentry.clone())
    }
    fn namespace(&self) -> Option<NsRef> {
        self.inner.namespace()
    }
    fn truncate(&self, len: u64) -> Result<()> {
        self.inner.truncate(len)
    }
    fn mmap_source(&self, offset: u64) -> Option<Result<Arc<dyn vfs::Inode>>> {
        self.inner.mmap_source(offset)
    }
}

/// Give a newly created `child` of `parent` its owner: the caller's
/// file-system IDs, or the directory's group under a set-group-ID
/// directory (POSIX open(2), mkdir(2)).
pub fn own_new(parent: &Dentry, child: &Dentry) {
    let cred = crate::proc::cred::current();
    let (uid, gid) = cred.new_owner(&parent.metadata());
    let m = child.metadata();
    if m.uid != uid || m.gid != gid {
        let _ = child.inode.set_owner(Some(uid), Some(gid));
    }
}

/// The access an open(2) needs: read and/or write, and write for
/// O_TRUNC.
fn open_access(flags: u32) -> u32 {
    use crate::proc::cred::{MAY_READ, MAY_WRITE};
    let mut want = match flags & O_ACCMODE {
        O_RDONLY => MAY_READ,
        O_WRONLY => MAY_WRITE,
        _ => MAY_READ | MAY_WRITE,
    };
    if flags & O_TRUNC != 0 {
        want |= MAY_WRITE;
    }
    want
}

/// open(2) on a path, relative to `cwd`, under openat2(2)'s restrictions
/// on the lookup (none for open and openat). `mode` is already masked by
/// umask.
pub fn open_restricted(
    cwd: &Arc<Dentry>,
    path: &str,
    flags: u32,
    mode: u32,
    r: vfs::Restrict,
) -> Result<Arc<dyn File>> {
    let cred = crate::proc::cred::current();
    let (dentry, created) = if flags & O_CREAT != 0 {
        let (parent, name) = vfs::resolve_parent_restricted(cwd, path, r)?;
        match parent.child(&name) {
            Ok(_) if flags & O_EXCL != 0 => return Err(EEXIST),
            Ok(_) => {
                let d = vfs::resolve_restricted(cwd, path, flags & O_NOFOLLOW == 0, r)?;
                // Someone else's file in a shared sticky directory (proc(5),
                // protected_fifos and protected_regular).
                if let Some(dir) = &d.parent
                    && !protect::may_open_existing(&dir.metadata(), &d.metadata(), &cred)
                {
                    return Err(EACCES);
                }
                (d, false)
            }
            Err(e) if e == ENOENT => {
                vfs::writable(&parent)?;
                cred.permission(&parent.metadata(), crate::proc::cred::MAY_WRITE | crate::proc::cred::MAY_EXEC)?;
                let inode = parent.inode.create(&name, S_IFREG | (mode & 0o7777), 0)?;
                let d = match parent.child(&name) {
                    Err(e) if e == ENOENT && parent.inode.uncached_child(&name) => parent.just_created(&name, inode),
                    r => r?,
                };
                own_new(&parent, &d);
                (d, true)
            }
            Err(e) => return Err(e),
        }
    } else {
        (vfs::resolve_restricted(cwd, path, flags & O_NOFOLLOW == 0, r)?, false)
    };
    // The creator may open a new file whatever its mode (open(2)).
    if created {
        return open_dentry(dentry, flags);
    }
    open_found(dentry, flags)
}

/// Open a file found by name or by handle (open_by_handle_at(2)): its
/// permissions and its mount's read-only state are checked as open(2)
/// checks them.
pub fn open_found(dentry: Arc<Dentry>, flags: u32) -> Result<Arc<dyn File>> {
    if flags & O_PATH == 0 {
        let cred = crate::proc::cred::current();
        let meta = dentry.metadata();
        if meta.file_type() != FileType::Symlink {
            cred.permission(&meta, open_access(flags))?;
        }
        // Writing a file on a read-only mount (devices are not affected).
        if open_access(flags) & crate::proc::cred::MAY_WRITE != 0 && meta.file_type() == FileType::Regular {
            vfs::writable(&dentry)?;
        }
    }
    open_dentry(dentry, flags)
}

/// Open an already resolved name.
pub fn open_dentry(dentry: Arc<Dentry>, flags: u32) -> Result<Arc<dyn File>> {
    let meta = dentry.metadata();
    let kind = meta.file_type();
    // O_NOATIME: the owner's, or with CAP_FOWNER (open(2), EPERM).
    if flags & O_NOATIME != 0 && !crate::proc::cred::current().owns(&meta) {
        return Err(EPERM);
    }
    let write = flags & O_ACCMODE != O_RDONLY;
    if flags & O_PATH != 0 {
        return Ok(Arc::new(OpenFile::new(dentry, flags)));
    }
    match kind {
        FileType::Symlink => return Err(ELOOP), // O_NOFOLLOW on a symlink.
        FileType::Directory if write => return Err(EISDIR),
        _ if flags & O_DIRECTORY != 0 && kind != FileType::Directory => return Err(ENOTDIR),
        _ => {}
    }
    // Devices on a nodev mount don't open (mount(2) MS_NODEV; EACCES as
    // Linux was seen to give).
    if matches!(kind, FileType::CharDevice | FileType::BlockDevice) && vfs::mount_flags(&dentry) & vfs::MNT_NODEV != 0 {
        return Err(EACCES);
    }
    // Special files that don't know their name get it (fstat, fstatfs,
    // /proc/self/fd).
    if let Some(r) = dentry.inode.clone().open_special(flags) {
        return r.map(|f| {
            if f.dentry().is_some() { f } else { Arc::new(NodeFile::new(f, dentry, flags)) as Arc<dyn File> }
        });
    }
    match kind {
        FileType::CharDevice | FileType::BlockDevice => {
            // The cgroup device controller (ADR 0028).
            let acc = match flags & O_ACCMODE {
                O_RDONLY => cgroup::ACC_READ,
                O_WRONLY => cgroup::ACC_WRITE,
                _ => cgroup::ACC_READ | cgroup::ACC_WRITE,
            };
            let ty = if kind == FileType::CharDevice { cgroup::DEV_CHAR } else { cgroup::DEV_BLOCK };
            if !cgroup::device_allowed(ty, vfs::major(meta.rdev), vfs::minor(meta.rdev), acc) {
                return Err(EPERM);
            }
            if kind == FileType::BlockDevice {
                let dev = crate::block::open(meta.rdev, flags)?;
                return Ok(Arc::new(NodeFile::new(dev, dentry, flags)));
            }
            let dev = devices::open(meta.rdev, flags)?;
            Ok(Arc::new(NodeFile::new(dev, dentry, flags)))
        }
        FileType::Fifo => pipe::open_fifo(dentry, flags),
        FileType::Socket => Err(ENXIO),
        _ => {
            if flags & O_TRUNC != 0 && write && meta.mode & S_IFMT == S_IFREG {
                dentry.inode.truncate(0)?;
                drop_set_ids(&dentry.inode);
                pagecache::truncated(&dentry.inode, 0);
            }
            Ok(Arc::new(OpenFile::new(dentry, flags)))
        }
    }
}

/// The default `RLIMIT_NOFILE` soft limit: descriptors per process.
pub const MAX_FDS: usize = 1024;

#[derive(Clone)]
struct FdEntry {
    file: Arc<dyn File>,
    cloexec: bool,
}

/// A process's descriptor table.
#[derive(Clone)]
pub struct FdTable {
    fds: Vec<Option<FdEntry>>,
    /// One more than the highest descriptor that may be opened: the
    /// process's RLIMIT_NOFILE soft limit.
    limit: usize,
}

impl Default for FdTable {
    fn default() -> FdTable {
        FdTable { fds: Vec::new(), limit: MAX_FDS }
    }
}

impl core::fmt::Debug for FdTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FdTable").field("open", &self.fds.iter().filter(|x| x.is_some()).count()).finish()
    }
}

impl FdTable {
    /// Stdin, stdout and stderr on the console.
    pub fn with_console() -> FdTable {
        let c = tty::open_console();
        let e = || Some(FdEntry { file: c.clone(), cloexec: false });
        FdTable { fds: alloc::vec![e(), e(), e()], limit: MAX_FDS }
    }

    pub fn get(&self, fd: i32) -> Result<Arc<dyn File>> {
        usize::try_from(fd)
            .ok()
            .and_then(|i| self.fds.get(i))
            .and_then(|f| f.as_ref())
            .map(|e| e.file.clone())
            .ok_or(EBADF)
    }

    /// Set the RLIMIT_NOFILE soft limit.
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit;
    }

    /// The RLIMIT_NOFILE soft limit.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Install `f` at the lowest free descriptor `>= min`.
    pub fn insert_from(&mut self, min: usize, f: Arc<dyn File>, cloexec: bool) -> Result<i32> {
        if min >= self.limit {
            return Err(EINVAL);
        }
        let i = match (min..self.fds.len().min(self.limit)).find(|&i| self.fds[i].is_none()) {
            Some(i) => i,
            None if self.fds.len().max(min) < self.limit => {
                let i = self.fds.len().max(min);
                self.fds.resize(i + 1, None);
                i
            }
            None => return Err(EMFILE),
        };
        self.fds[i] = Some(FdEntry { file: f, cloexec });
        Ok(i as i32)
    }

    /// Install `f` at the lowest free descriptor.
    pub fn insert(&mut self, f: Arc<dyn File>, cloexec: bool) -> Result<i32> {
        self.insert_from(0, f, cloexec)
    }

    /// Install `f` at exactly `fd`, closing what was there (dup2(2)).
    pub fn insert_at(&mut self, fd: i32, f: Arc<dyn File>, cloexec: bool) -> Result<i32> {
        let i = usize::try_from(fd).ok().filter(|&i| i < self.limit).ok_or(EBADF)?;
        if self.fds.len() <= i {
            self.fds.resize(i + 1, None);
        }
        if let Some(old) = self.fds[i].replace(FdEntry { file: f, cloexec }) {
            locks::fd_closed(&old.file);
        }
        Ok(fd)
    }

    pub fn close(&mut self, fd: i32) -> Result<Arc<dyn File>> {
        let slot = usize::try_from(fd).ok().and_then(|i| self.fds.get_mut(i)).ok_or(EBADF)?;
        let f = slot.take().map(|e| e.file).ok_or(EBADF)?;
        // Closing any descriptor of a file drops the process's POSIX locks
        // on it (fcntl(2)).
        locks::fd_closed(&f);
        Ok(f)
    }

    pub fn cloexec(&self, fd: i32) -> Result<bool> {
        usize::try_from(fd).ok().and_then(|i| self.fds.get(i)).and_then(|f| f.as_ref()).map(|e| e.cloexec).ok_or(EBADF)
    }

    pub fn set_cloexec(&mut self, fd: i32, on: bool) -> Result<()> {
        let e = usize::try_from(fd).ok().and_then(|i| self.fds.get_mut(i)).and_then(|f| f.as_mut()).ok_or(EBADF)?;
        e.cloexec = on;
        Ok(())
    }

    /// Close every close-on-exec descriptor (execve(2)).
    /// Close the descriptors that must not reach the Linux domain (at a
    /// Slate → Linux exec, ADR 0098); returns how many.
    pub fn close_for_linux(&mut self) -> usize {
        let mut n = 0;
        for slot in &mut self.fds {
            if slot.as_ref().is_some_and(|e| stays_in_slate(&e.file))
                && let Some(e) = slot.take()
            {
                locks::fd_closed(&e.file);
                n += 1;
            }
        }
        n
    }

    pub fn close_on_exec(&mut self) {
        for slot in &mut self.fds {
            if slot.as_ref().is_some_and(|e| e.cloexec)
                && let Some(e) = slot.take()
            {
                locks::fd_closed(&e.file);
            }
        }
    }

    /// close_range(2): close descriptors `first..=last`, or with `cloexec`
    /// mark them close-on-exec. Returns the closed files, for the caller to
    /// drop without the table locked.
    pub fn close_range(&mut self, first: usize, last: usize, cloexec: bool) -> Vec<Arc<dyn File>> {
        let mut closed = Vec::new();
        let end = last.min(self.fds.len().saturating_sub(1));
        for slot in self.fds.iter_mut().take(end + 1).skip(first) {
            if cloexec {
                if let Some(e) = slot {
                    e.cloexec = true;
                }
            } else if let Some(e) = slot.take() {
                locks::fd_closed(&e.file);
                closed.push(e.file);
            }
        }
        closed
    }

    /// Close every descriptor (at exit).
    pub fn close_all(&mut self) {
        for e in self.fds.drain(..).flatten() {
            locks::fd_closed(&e.file);
        }
    }

    /// The open file at `fd`.
    pub fn peek(&self, fd: i32) -> Option<&Arc<dyn File>> {
        usize::try_from(fd).ok().and_then(|i| self.fds.get(i)).and_then(|e| e.as_ref()).map(|e| &e.file)
    }

    /// Open descriptors with their files (for /proc/<pid>/fd).
    pub fn iter(&self) -> impl Iterator<Item = (i32, &Arc<dyn File>)> {
        self.fds.iter().enumerate().filter_map(|(i, e)| e.as_ref().map(|e| (i as i32, &e.file)))
    }
}

/// A devtmpfs-style /dev: a tmpfs holding the standard device nodes.
/// Block devices registered later (USB disks, partitions found by a
/// rescan) are added to the first instance as they come.
pub fn devfs_root() -> Arc<dyn vfs::Inode> {
    use devices::*;
    use vfs::{S_IFCHR, makedev};
    let dev: Arc<dyn vfs::Inode> = tmpfs::TmpFs::new();
    let nodes = [
        ("null", MEM_MAJOR, NULL_MINOR, 0o666),
        ("zero", MEM_MAJOR, ZERO_MINOR, 0o666),
        ("full", MEM_MAJOR, FULL_MINOR, 0o666),
        ("random", MEM_MAJOR, RANDOM_MINOR, 0o666),
        ("urandom", MEM_MAJOR, URANDOM_MINOR, 0o666),
        ("tty", TTYAUX_MAJOR, TTY_MINOR, 0o666),
        ("console", TTYAUX_MAJOR, CONSOLE_MINOR, 0o600),
        ("ttyS0", TTY_MAJOR, TTYS0_MINOR, 0o660),
        ("ptmx", tty::PTMX_MAJOR, tty::PTMX_MINOR, 0o666),
    ];
    // The virtual consoles (ADR 0185): tty0 the one in front, tty1 the
    // console.
    for n in 0..=vt::COUNT as u32 {
        let _ = dev.create(&alloc::format!("tty{n}"), S_IFCHR | 0o620, makedev(TTY_MAJOR, n));
    }
    for (name, major, minor, perm) in nodes {
        let _ = dev.create(name, S_IFCHR | perm, makedev(major, minor));
    }
    // Hold the lock across the snapshot so a disk registered meanwhile is
    // added exactly once (here or by `block_added`).
    let mut first = DEVFS.lock();
    for (name, rdev) in crate::block::nodes() {
        let _ = dev.create(&name, vfs::S_IFBLK | 0o660, rdev);
    }
    if let Ok(net) = dev.mkdir("net", 0o755) {
        let _ = net.create("tun", S_IFCHR | 0o666, makedev(MISC_MAJOR, TUN_MINOR));
    }
    // HID devices from user space (ADR 0176): root's.
    let _ = dev.create("slate-hid", S_IFCHR | 0o600, makedev(MISC_MAJOR, crate::drivers::input::user::USER_HID_MINOR));
    for (name, target) in [
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
    ] {
        let _ = dev.symlink(name, target);
    }
    let _ = dev.mkdir("pts", 0o755);
    let _ = dev.mkdir("shm", 0o1777);
    for n in CHAR_NODES.lock().iter() {
        add_dev_node(&dev, n);
    }
    if first.is_none() {
        *first = Some(dev.clone());
    }
    dev
}

/// A character device a driver registered at run time, and its sysfs
/// entries (paths relative to /sys).
#[derive(Clone, Debug)]
pub struct CharNode {
    /// Path under /dev ("dri/card0", "input/event3").
    pub dev: alloc::string::String,
    pub rdev: u64,
    pub mode: u32,
    pub sys: Vec<SysEntry>,
}

#[derive(Clone)]
pub enum SysEntry {
    /// A directory of the device's own: `sys_device_remove` takes it out
    /// with all it holds. (Files and links make the directories they need,
    /// which stay.)
    Dir(alloc::string::String),
    File(alloc::string::String, alloc::string::String),
    Link(alloc::string::String, alloc::string::String),
    /// A file made when it is read (`tmpfs::create_generated`).
    Generated(alloc::string::String, tmpfs::Generator),
}

impl core::fmt::Debug for SysEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SysEntry::Dir(p) => write!(f, "Dir({p:?})"),
            SysEntry::File(p, t) => write!(f, "File({p:?}, {t:?})"),
            SysEntry::Link(p, t) => write!(f, "Link({p:?}, {t:?})"),
            SysEntry::Generated(p, _) => write!(f, "Generated({p:?})"),
        }
    }
}

/// Devices' sysfs entries (PCI functions, USB devices) by key, replayed
/// into each new /sys and taken out when the device goes.
static SYS_DEVICES: IrqSpinLock<Vec<(alloc::string::String, Vec<SysEntry>)>> = IrqSpinLock::new(Vec::new());

/// Add a device's sysfs entries under `key` (a PCI address, a USB path):
/// to /sys now and to every /sys mounted later.
pub fn sys_device_add(key: &str, entries: Vec<SysEntry>) {
    if let Some(sys) = SYSFS.lock().clone() {
        apply_sys_entries(&sys, &entries);
    }
    // Uevent listeners hear of it (ADR 0185): the device, then its
    // interfaces.
    announce_entries(&entries, "add", false);
    let mut all = SYS_DEVICES.lock();
    all.retain(|(k, _)| k != key);
    all.push((key.into(), entries));
}

/// Add entries to a device already added (a driver bound to it).
pub fn sys_device_extend(key: &str, entries: Vec<SysEntry>) {
    if let Some(sys) = SYSFS.lock().clone() {
        apply_sys_entries(&sys, &entries);
    }
    if let Some((_, e)) = SYS_DEVICES.lock().iter_mut().find(|(k, _)| k == key) {
        e.extend(entries);
    }
}

/// Take a device's sysfs entries out: its directories with what is in
/// them, and its links and files elsewhere.
pub fn sys_device_remove(key: &str) {
    let entries = {
        let mut all = SYS_DEVICES.lock();
        let Some(i) = all.iter().position(|(k, _)| k == key) else { return };
        all.remove(i).1
    };
    // Its interfaces go first, then the device, as on Linux.
    announce_entries(&entries, "remove", true);
    let Some(sys) = SYSFS.lock().clone() else { return };
    let dirs: Vec<&str> =
        entries.iter().filter_map(|e| if let SysEntry::Dir(p) = e { Some(p.as_str()) } else { None }).collect();
    for e in &entries {
        let p = match e {
            SysEntry::Dir(_) => continue,
            SysEntry::File(p, _) | SysEntry::Link(p, _) | SysEntry::Generated(p, _) => p.as_str(),
        };
        if dirs.iter().any(|d| p.starts_with(d) && p[d.len()..].starts_with('/')) {
            continue;
        }
        let (dir, name) = split_last(p);
        if let Some(d) = find_dir(&sys, dir) {
            let _ = d.unlink(name);
        }
    }
    for d in dirs.iter().rev() {
        let (parent, name) = split_last(d);
        if let Some(p) = find_dir(&sys, parent) {
            remove_tree(&p, name);
        }
    }
}

/// The directory `path` under `root` if it is there (a device below a
/// hub may go after the hub's directory went).
fn find_dir(root: &Arc<dyn vfs::Inode>, path: &str) -> Option<Arc<dyn vfs::Inode>> {
    let mut d = root.clone();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        d = d.lookup(part).ok()?;
    }
    Some(d)
}

fn apply_sys_entries(sys: &Arc<dyn vfs::Inode>, entries: &[SysEntry]) {
    for e in entries {
        match e {
            SysEntry::Dir(p) => {
                make_dirs(sys, p);
            }
            SysEntry::File(p, text) => {
                let (dir, name) = split_last(p);
                if let Some(d) = make_dirs(sys, dir) {
                    sysfs_file(&d, name, text);
                }
            }
            SysEntry::Link(p, target) => {
                let (dir, name) = split_last(p);
                if let Some(d) = make_dirs(sys, dir) {
                    let _ = d.symlink(name, target);
                }
            }
            SysEntry::Generated(p, make) => {
                let (dir, name) = split_last(p);
                if let Some(d) = make_dirs(sys, dir) {
                    let _ = tmpfs::create_generated(&d, name, 0o444, make.clone());
                }
            }
        }
    }
}

/// Every registered character device, replayed into each new /dev and
/// /sys and applied to the first ones as they come.
static CHAR_NODES: IrqSpinLock<Vec<CharNode>> = IrqSpinLock::new(Vec::new());

/// The directory `path` (relative, '/'-separated) under `root`, created
/// as needed.
fn make_dirs(root: &Arc<dyn vfs::Inode>, path: &str) -> Option<Arc<dyn vfs::Inode>> {
    let mut d = root.clone();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        d = match d.lookup(part) {
            Ok(x) => x,
            Err(_) => d.mkdir(part, 0o755).ok()?,
        };
    }
    Some(d)
}

fn split_last(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

fn add_dev_node(dev: &Arc<dyn vfs::Inode>, n: &CharNode) {
    let (dir, name) = split_last(&n.dev);
    if let Some(d) = make_dirs(dev, dir) {
        let _ = d.create(name, vfs::S_IFCHR | n.mode, n.rdev);
    }
}

fn add_sys_entries(sys: &Arc<dyn vfs::Inode>, n: &CharNode) {
    apply_sys_entries(sys, &n.sys);
}

/// A character device appeared: its /dev node and sysfs entries.
pub fn char_added(n: CharNode) {
    let dev = DEVFS.lock().clone();
    if let Some(dev) = dev {
        add_dev_node(&dev, &n);
    }
    let sys = SYSFS.lock().clone();
    if let Some(sys) = sys {
        add_sys_entries(&sys, &n);
    }
    announce(&n, "add");
    CHAR_NODES.lock().push(n);
}

/// A character device went (a USB device unplugged): its /dev node and
/// sysfs entries go, and uevent listeners hear `remove`.
pub fn char_removed(dev_path: &str) {
    let n = {
        let mut nodes = CHAR_NODES.lock();
        let Some(i) = nodes.iter().position(|n| n.dev == dev_path) else { return };
        nodes.remove(i)
    };
    if let Some(dev) = DEVFS.lock().clone() {
        let (dir, name) = split_last(&n.dev);
        if let Some(d) = find_dir(&dev, dir) {
            let _ = d.unlink(name);
        }
        if let Ok(d) = vfs::resolve(&vfs::root(), "/dev", true) {
            d.forget(name);
        }
    }
    if let Some(sys) = SYSFS.lock().clone() {
        for e in &n.sys {
            match e {
                SysEntry::Dir(_) => {}
                SysEntry::File(p, _) | SysEntry::Link(p, _) | SysEntry::Generated(p, _) => {
                    let (dir, name) = split_last(p);
                    if let Some(d) = find_dir(&sys, dir) {
                        let _ = d.unlink(name);
                    }
                }
            }
        }
    }
    announce(&n, "remove");
}

/// Tell uevent listeners about each device (each directory with a
/// uevent file) among `n`'s sysfs entries.
fn announce(n: &CharNode, action: &str) {
    announce_entries(&n.sys, action, false);
}

/// Tell uevent listeners about each device among `entries` (each
/// directory with a uevent file, made or generated), last first when
/// `reverse`.
fn announce_entries(entries: &[SysEntry], action: &str, reverse: bool) {
    if !crate::net::uevent::listening() {
        return;
    }
    let mut found: Vec<(&str, alloc::string::String)> = Vec::new();
    for e in entries {
        let (p, text) = match e {
            SysEntry::File(p, text) => (p, text.clone()),
            SysEntry::Generated(p, make) if p.ends_with("/uevent") => {
                let mut b = Vec::new();
                make(&mut b);
                (p, alloc::string::String::from_utf8_lossy(&b).into_owned())
            }
            _ => continue,
        };
        let Some(dir) = p.strip_suffix("/uevent") else { continue };
        found.push((dir, text));
    }
    if reverse {
        found.reverse();
    }
    for (dir, text) in found {
        let mut env: Vec<alloc::string::String> = Vec::new();
        for s in entries {
            if let SysEntry::Link(lp, target) = s
                && lp.strip_suffix("/subsystem") == Some(dir)
            {
                env.push(alloc::format!("SUBSYSTEM={}", split_last(target).1));
            }
        }
        env.extend(text.lines().filter(|l| !l.is_empty()).map(alloc::string::String::from));
        crate::net::uevent::announce(action, &alloc::format!("/{dir}"), &env);
    }
}

/// The first /dev, which follows block devices as they come and go, and
/// the one /sys.
static DEVFS: IrqSpinLock<Option<Arc<dyn vfs::Inode>>> = IrqSpinLock::new(None);
static SYSFS: IrqSpinLock<Option<Arc<dyn vfs::Inode>>> = IrqSpinLock::new(None);

/// A block device appeared: its /dev node and /sys/block entry.
pub fn block_added(name: &str, rdev: u64) {
    let dev = DEVFS.lock().clone();
    if let Some(dev) = dev {
        let _ = dev.create(name, vfs::S_IFBLK | 0o660, rdev);
    }
    let sys = SYSFS.lock().clone();
    if let Some(sys) = sys
        && let Some(info) = crate::block::list().into_iter().find(|i| i.name == name)
    {
        sysfs_block(&sys, &info);
        announce_block(&sys, name, "add");
    }
}

/// Tell uevent listeners about block device `name` (ADR 0185), from its
/// /sys/block entry: DEVPATH `/block/DISK[/PART]`, SUBSYSTEM `block`, and
/// its uevent file's lines.
fn announce_block(sys: &Arc<dyn vfs::Inode>, name: &str, action: &str) {
    if !crate::net::uevent::listening() {
        return;
    }
    let Ok(block) = sys.lookup("block") else { return };
    let mut at = None;
    if block.lookup(name).is_ok() {
        at = Some(alloc::format!("/block/{name}"));
    } else {
        for disk in block.readdir().unwrap_or_default() {
            if let Ok(d) = block.lookup(&disk.name)
                && disk.name != "."
                && disk.name != ".."
                && d.lookup(name).map(|p| p.metadata().mode & vfs::S_IFMT == vfs::S_IFDIR).unwrap_or(false)
            {
                at = Some(alloc::format!("/block/{}/{name}", disk.name));
                break;
            }
        }
    }
    let Some(devpath) = at else { return };
    let Some(text) = find_dir(sys, &devpath[1..]).and_then(|d| d.lookup("uevent").ok()).map(|f| {
        let mut b = alloc::vec![0u8; 512];
        let n = f.read_at(0, &mut b).unwrap_or(0);
        alloc::string::String::from_utf8_lossy(&b[..n]).into_owned()
    }) else {
        return;
    };
    let mut env = alloc::vec![alloc::string::String::from("SUBSYSTEM=block")];
    env.extend(text.lines().filter(|l| !l.is_empty()).map(alloc::string::String::from));
    crate::net::uevent::announce(action, &devpath, &env);
}

/// A partition went away (after a rescan).
pub fn block_removed(name: &str) {
    if let Some(sys) = SYSFS.lock().clone() {
        announce_block(&sys, name, "remove");
    }
    let dev = DEVFS.lock().clone();
    if let Some(dev) = dev {
        let _ = dev.unlink(name);
        // Cached lookups of the old node, in the caller's view of /dev.
        if let Ok(d) = vfs::resolve(&vfs::root(), "/dev", true) {
            d.forget(name);
        }
    }
    let sys = SYSFS.lock().clone();
    if let Some(sys) = sys
        && let Ok(block) = sys.lookup("block")
    {
        for disk in block.readdir().unwrap_or_default() {
            if let Ok(d) = block.lookup(&disk.name)
                && d.lookup(name).is_ok()
            {
                remove_tree(&d, name);
            }
        }
        // A device of its own (a closed mapped device).
        if block.lookup(name).is_ok() {
            remove_tree(&block, name);
        }
        if let Ok(d) = vfs::resolve(&vfs::root(), "/sys/block", true) {
            d.forget(name);
            for c in d.inode.readdir().unwrap_or_default() {
                if let Ok(cd) = d.child(&c.name) {
                    cd.forget(name);
                }
            }
        }
    }
}

/// Remove `dir/name` and everything under it (sysfs entries only).
fn remove_tree(dir: &Arc<dyn vfs::Inode>, name: &str) {
    if let Ok(d) = dir.lookup(name)
        && d.metadata().mode & vfs::S_IFMT == vfs::S_IFDIR
    {
        for e in d.readdir().unwrap_or_default() {
            if e.name != "." && e.name != ".." {
                remove_tree(&d, &e.name);
            }
        }
        let _ = dir.rmdir(name);
    } else {
        let _ = dir.unlink(name);
    }
}

/// Set `/sys/<path>` to `text` (a value the kernel keeps up to date, such
/// as a thermal zone's temperature), making the directories it needs.
pub fn sysfs_put(path: &str, text: &str) {
    let Some(mut dir) = SYSFS.lock().clone() else { return };
    let mut parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    let Some(name) = parts.pop() else { return };
    for p in parts {
        dir = match dir.lookup(p).or_else(|_| dir.mkdir(p, 0o755)) {
            Ok(d) => d,
            Err(_) => return,
        };
    }
    match dir.lookup(name) {
        Ok(f) => {
            let _ = f.truncate(0);
            let _ = f.write_at(0, text.as_bytes());
        }
        Err(_) => sysfs_file(&dir, name, text),
    }
}

fn sysfs_file(dir: &Arc<dyn vfs::Inode>, name: &str, text: &str) {
    if let Ok(f) = dir.create(name, vfs::S_IFREG | 0o444, 0) {
        let _ = f.write_at(0, text.as_bytes());
    }
}

/// /sys/block/<disk>/{dev,size,ro,removable,device/model}, and for a
/// partition /sys/block/<disk>/<part>/{dev,size,start,partition}, as
/// sysfs-block(5) in the Linux ABI documentation describes them.
fn sysfs_block(sys: &Arc<dyn vfs::Inode>, i: &crate::block::Info) {
    use alloc::format;
    let Ok(block) = sys.lookup("block") else { return };
    let dir = match &i.parent {
        Some(disk) => block.lookup(disk).and_then(|d| d.mkdir(&i.name, 0o755)),
        None => block.mkdir(&i.name, 0o755),
    };
    let Ok(dir) = dir else { return };
    sysfs_file(&dir, "dev", &format!("{}:{}\n", vfs::major(i.rdev), vfs::minor(i.rdev)));
    sysfs_file(&dir, "size", &format!("{}\n", i.sectors));
    sysfs_file(&dir, "ro", if i.read_only { "1\n" } else { "0\n" });
    // A mapped device names the partition under it (`slaves/sda2`).
    if let Some(under) = crate::block::crypt::slave_of(&i.name)
        && let Ok(slaves) = dir.mkdir("slaves", 0o755)
    {
        sysfs_file(&slaves, &under, "");
    }
    // uevent as sysfs-block(5) and the uevent ABI document describe it.
    let mut uevent = format!("MAJOR={}\nMINOR={}\nDEVNAME={}\n", vfs::major(i.rdev), vfs::minor(i.rdev), i.name);
    match &i.parent {
        Some(_) => {
            sysfs_file(&dir, "start", &format!("{}\n", i.start));
            let n = vfs::minor(i.rdev) % 16;
            sysfs_file(&dir, "partition", &format!("{n}\n"));
            uevent += &format!("DEVTYPE=partition\nPARTN={n}\n");
            if let Some(label) = label_of(&i.name) {
                uevent += &format!("PARTNAME={label}\n");
            }
            // Slate's own (ADR 0112): the partition's type.
            sysfs_file(&dir, "slate_type", &format!("{}\n", i.ptype.as_deref().unwrap_or("")));
        }
        None => {
            uevent += "DEVTYPE=disk\n";
            sysfs_file(&dir, "removable", if i.removable { "1\n" } else { "0\n" });
            if let Ok(d) = dir.mkdir("device", 0o755) {
                sysfs_file(&d, "model", &format!("{}\n", i.model));
            }
        }
    }
    sysfs_file(&dir, "uevent", &uevent);
    sysfs_holds(&dir, i);
}

/// A partition's GPT name.
fn label_of(name: &str) -> Option<alloc::string::String> {
    crate::block::label_of(name).filter(|l| !l.is_empty())
}

/// Slate's own files (ADR 0112): a disk's partition table (`gpt`, `mbr`
/// or nothing), and what a device holds: `slate_fs` (udev's ID_FS_TYPE
/// name, `vfat`), `slate_fs_kind` (`FAT32`), `slate_fs_label` and
/// `slate_fs_uuid`, each empty when not known.
fn sysfs_holds(dir: &Arc<dyn vfs::Inode>, i: &crate::block::Info) {
    let put = |name: &str, text: &str| match dir.lookup(name) {
        Ok(f) => {
            let _ = f.truncate(0);
            let _ = f.write_at(0, text.as_bytes());
        }
        Err(_) => sysfs_file(dir, name, text),
    };
    if i.parent.is_none() {
        put("slate_table", &alloc::format!("{}\n", i.table.unwrap_or("")));
    }
    let h = i.holds.as_ref();
    put("slate_fs", &alloc::format!("{}\n", h.map_or("", |f| f.kind.id())));
    put("slate_fs_kind", &alloc::format!("{}\n", h.map_or("", |f| f.kind.name())));
    put("slate_fs_label", &alloc::format!("{}\n", h.map_or("", |f| f.label.as_str())));
    put("slate_fs_uuid", &alloc::format!("{}\n", h.map_or("", |f| f.uuid.as_str())));
}

/// What block device `name` holds changed (a new file system, a new
/// partition table): its Slate files in /sys/block again.
pub fn block_changed(name: &str) {
    let Some(sys) = SYSFS.lock().clone() else { return };
    let Some(info) = crate::block::list().into_iter().find(|i| i.name == name) else { return };
    let Ok(block) = sys.lookup("block") else { return };
    let dir = match &info.parent {
        Some(disk) => block.lookup(disk).and_then(|d| d.lookup(name)),
        None => block.lookup(name),
    };
    if let Ok(dir) = dir {
        sysfs_holds(&dir, &info);
        announce_block(&sys, name, "change");
    }
}

/// sysfs: the directories software looks for, /sys/block, /sys/fs/cgroup
/// as the cgroup2 mount point (ADR 0028), and the devices (PCI functions
/// and USB devices, ADR 0084). There is one: every mount shows the same
/// tree (as sysfs(5) describes it), so devices that come and go change
/// what every mount shows.
pub fn sysfs_root() -> Arc<dyn vfs::Inode> {
    let mut first = SYSFS.lock();
    if let Some(sys) = first.as_ref() {
        return sys.clone();
    }
    let root: Arc<dyn vfs::Inode> = tmpfs::TmpFs::with_magic(tmpfs::SYSFS_MAGIC);
    for d in ["block", "bus", "class", "dev", "devices", "firmware", "fs", "kernel", "module", "power"] {
        let _ = root.mkdir(d, 0o755);
    }
    if let Ok(fs) = root.lookup("fs") {
        let _ = fs.mkdir("cgroup", 0o755);
    }
    let thp =
        root.lookup("kernel").and_then(|k| k.mkdir("mm", 0o755)).and_then(|m| m.mkdir("transparent_hugepage", 0o755));
    if let Ok(t) = thp
        && let Ok(f) = t.create("hpage_pmd_size", vfs::S_IFREG | 0o444, 0)
    {
        let _ = f.write_at(0, b"2097152\n");
    }
    // Booted through UEFI: /sys/firmware/efi exists, as installers check,
    // with efivarfs's mount point when the runtime services work (ADR
    // 0088).
    if crate::arch::boot::efi_booted()
        && let Ok(fw) = root.lookup("firmware")
        && let Ok(efi) = fw.mkdir("efi", 0o755)
        && crate::arch::efi::available()
    {
        let _ = efi.mkdir("efivars", 0o755);
    }
    // /sys/class/tty/tty0/active: the virtual console in front (ADR 0185),
    // as sysfs-tty in Linux's ABI documentation describes it.
    if let Ok(class) = root.lookup("class")
        && let Ok(tty) = class.mkdir("tty", 0o755)
        && let Ok(t0) = tty.mkdir("tty0", 0o755)
    {
        let _ = tmpfs::create_generated(
            &t0,
            "active",
            0o444,
            Arc::new(|o: &mut Vec<u8>| o.extend_from_slice(alloc::format!("tty{}\n", vt::active()).as_bytes())),
        );
    }
    for i in crate::block::list() {
        sysfs_block(&root, &i);
    }
    for (_, entries) in SYS_DEVICES.lock().iter() {
        apply_sys_entries(&root, entries);
    }
    for n in CHAR_NODES.lock().iter() {
        add_sys_entries(&root, n);
    }
    *first = Some(root.clone());
    root
}

/// The boot's unlock stage (ADR 0038): the unlock program from the
/// `unlock` module (a cpio archive) runs on a temporary root with /dev,
/// /proc, /sys and /tmp, asks for the password and hands over the key.
/// Returns the unlocked device, or None if the program ended without it.
/// Afterwards the temporary root and its mounts go, and process ids start
/// again from where they were, so init is still pid 1.
fn unlock_stage(
    dev: &Arc<dyn crate::block::BlockDevice>,
    h: &slatecrypt::Header,
    what: &str,
    archive: &[u8],
) -> Option<(Arc<dyn crate::block::BlockDevice>, u64)> {
    const PROGRAM: &str = "/bin/slate-unlock";
    let temp: Arc<dyn vfs::Inode> = tmpfs::TmpFs::new();
    vfs::set_root(temp, "tmpfs", "unlock");
    let r = vfs::root();
    let n = initramfs::unpack(&r, archive);
    crate::log_info!("crypt: unlocking {what} with {PROGRAM} ({n} files)");
    let mounts: [(&str, Arc<dyn vfs::Inode>, &'static str); 4] = [
        ("dev", devfs_root(), "devtmpfs"),
        ("proc", procfs::new(), "proc"),
        ("sys", sysfs_root(), "sysfs"),
        ("tmp", tmp_root(), "tmpfs"),
    ];
    let mut mounted = Vec::new();
    for (at, fs, kind) in mounts {
        if r.child(at).is_err() {
            let _ = r.inode.mkdir(at, 0o755);
        }
        match vfs::resolve(&r, at, true).and_then(|d| vfs::mount(&d, fs, kind, kind, 0)) {
            Ok(()) => mounted.push(at),
            Err(e) => crate::log_warn!("unlock stage: mounting {kind} on /{at} failed: {e:?}"),
        }
    }
    crate::block::crypt::begin_stage(dev, h, what);
    let first_id = crate::sched::next_id();
    let env: [&[u8]; 3] = [b"HOME=/", b"PATH=/bin", b"TERM=xterm"];
    match crate::proc::spawn(PROGRAM, &[PROGRAM.as_bytes(), what.as_bytes()], &env) {
        Ok(p) => {
            crate::block::crypt::stage_program(p.pid);
            tty::console().set_controlling(p.pid, p.pid);
            p.set_ctty(Some(tty::console().clone()));
            let status = p.wait();
            // Its threads finish leaving before its ids are given again.
            for _ in 0..1000 {
                if p.threads().is_empty() {
                    break;
                }
                crate::sched::yield_now();
            }
            crate::proc::reap(&p);
            tty::console().set_controlling(0, 0);
            if status != 0 {
                crate::log_warn!("unlock stage: {PROGRAM} exited with status {status:#x}");
            }
        }
        Err(e) => crate::log_warn!("unlock stage: cannot start {PROGRAM}: {e:?}"),
    }
    let unlocked = crate::block::crypt::end_stage();
    for at in mounted.into_iter().rev() {
        if let Ok(d) = vfs::resolve(&r, at, true)
            && let Err(e) = vfs::unmount(&d, true)
        {
            crate::log_warn!("unlock stage: unmounting /{at} failed: {e:?}");
        }
    }
    crate::sched::rewind_ids(first_id);
    unlocked
}

/// Build the root file system: the ext4 file system named by `root=` on
/// the command line (`root=/dev/vda3` or `root=PARTLABEL=slate-root`), or
/// else a tmpfs filled from the initramfs module; then mount /dev, /proc
/// and /tmp.
pub fn init_root(cmdline: &str) {
    let root_arg = cmdline.split_ascii_whitespace().find_map(|w| w.strip_prefix("root="));
    let disk_root = root_arg.and_then(|spec| {
        let ro = cmdline.split_ascii_whitespace().any(|w| w == "ro");
        let dev = if let Some(label) = spec.strip_prefix("PARTLABEL=") {
            crate::block::find_label(label)
        } else if let Some(uuid) = spec.strip_prefix("PARTUUID=") {
            crate::block::find_uuid(uuid)
        } else {
            crate::block::find(spec.strip_prefix("/dev/").unwrap_or(spec))
        };
        let Some((mut dev, mut rdev)) = dev else {
            crate::log_error!("root device {spec} not found; using the initramfs");
            return None;
        };
        // The root's disk is the system's (ADR 0090).
        crate::block::protect(rdev);
        // An encrypted root is unlocked first, by the unlock program the
        // boot loaded with the kernel (ADR 0038). Every system's boot entry
        // has it (ADR 0086), so the kernel asks for no password itself; a
        // program that stops without the key is started again.
        if let Some(h) = crate::block::crypt::header(&dev) {
            crate::block::open_key_area(rdev, h.data_offset * crate::block::SECTOR as u64);
            let what = alloc::format!("/dev/{}", dev.name());
            let Some(module) = crate::arch::boot::modules().iter().find(|m| m.name == "unlock") else {
                crate::log_error!("{what} is encrypted, and the boot entry loads no unlock program; cannot mount it");
                return None;
            };
            let Some(u) = (0..3).find_map(|_| unlock_stage(&dev, &h, &what, module.data)) else {
                crate::log_error!("{what}: the unlock program ended three times without the key");
                return None;
            };
            (dev, rdev) = u;
            crate::block::protect(rdev);
        }
        let source = alloc::format!("/dev/{}", dev.name());
        // SlateFS picks the system subvolume by its boot state (ADR 0027).
        let (r, kind) = if slatefs::probe(&dev) {
            let fallback = cmdline.split_ascii_whitespace().any(|w| w == "slate.boot=fallback");
            let rollback = cmdline.split_ascii_whitespace().any(|w| w == "slate.boot=rollback");
            let system = cmdline.split_ascii_whitespace().find_map(|w| w.strip_prefix("slate.system="));
            (slatefs::mount_root(dev, rdev, ro, fallback, rollback, system), "slatefs")
        } else {
            (ext4::mount(dev, rdev, ro, false), "ext4")
        };
        match r {
            Ok(inode) => Some((inode, source, kind)),
            Err(e) => {
                crate::log_error!("mounting {spec} as {kind} failed ({e:?}); using the initramfs");
                None
            }
        }
    });
    if let Some((inode, source, kind)) = disk_root {
        vfs::set_root(inode, kind, &source);
    } else {
        let root: Arc<dyn vfs::Inode> = tmpfs::TmpFs::new();
        vfs::set_root(root, "tmpfs", "rootfs");
        match crate::arch::boot::modules().iter().find(|m| m.name == "initramfs") {
            Some(m) => {
                let n = initramfs::unpack(&vfs::root(), m.data);
                crate::log_info!("initramfs: {n} entries, {} KiB", m.data.len() / 1024);
            }
            None => crate::log_warn!("no initramfs module; the root file system is empty"),
        }
    }
    let r = vfs::root();
    for d in ["dev", "proc", "tmp", "sys", "root"] {
        if r.child(d).is_err() {
            let _ = r.inode.mkdir(d, 0o755);
        }
    }
    let mounts: [(&str, Arc<dyn vfs::Inode>, &'static str); 6] = [
        ("dev", devfs_root(), "devtmpfs"),
        ("dev/pts", devpts::new(), "devpts"),
        ("proc", procfs::new(), "proc"),
        ("tmp", tmp_root(), "tmpfs"),
        ("sys", sysfs_root(), "sysfs"),
        ("sys/fs/cgroup", cgroup::new(), "cgroup2"),
    ];
    for (at, fs, kind) in mounts {
        let mounted = vfs::resolve(&r, at, true).and_then(|d| vfs::mount(&d, fs, kind, kind, 0));
        if let Err(e) = mounted {
            crate::log_warn!("mounting {kind} on /{at} failed: {e:?}");
        }
    }
}

/// The tmpfs for /tmp: everyone may create files there, and only remove
/// their own (mode 1777, the sticky bit; tmpfs(5)'s default).
fn tmp_root() -> Arc<dyn vfs::Inode> {
    let root = tmpfs::TmpFs::new();
    let _ = vfs::Inode::set_mode(&*root, 0o1777);
    // tmpfs(5)'s default limits, as a mount without options gets them.
    let ram = crate::mm::frame::stats().usable_frames * 4096;
    if let Some((blocks, inodes)) = tmpfs::size_options(core::iter::empty(), ram) {
        root.limit(blocks, inodes);
    }
    root
}
