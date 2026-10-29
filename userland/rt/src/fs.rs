// SPDX-License-Identifier: MIT OR Apache-2.0

//! Files and directories. Paths are byte strings (not necessarily UTF-8).
//! `struct stat` layout and flag values from musl `bits/stat.h`,
//! `bits/fcntl.h` (ADR 0009); natively the calls take counted paths and
//! slate-abi's flags and structures (ADR 0031), translated here.

use alloc::vec::Vec;

use slate_abi::{CWD, nr, path as pf};

use crate::errno::{Errno, Result};
use crate::sys;

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
pub const O_SYNC: u32 = 0o4010000;
/// Linux's values (musl `bits/fcntl.h`, x86-64).
pub const O_DIRECT: u32 = 0o40000;
pub const O_NOATIME: u32 = 0o1000000;
pub const O_DIRECTORY: u32 = 0o200000;
pub const O_NOFOLLOW: u32 = 0o400000;
pub const O_CLOEXEC: u32 = 0o2000000;

pub const S_IFMT: u32 = 0o170000;
pub const S_IFSOCK: u32 = 0o140000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFIFO: u32 = 0o010000;

const AT_FDCWD: i32 = -100;
const AT_SYMLINK_NOFOLLOW: u32 = 0x100;

/// A NUL-terminated copy of `path`.
pub fn cpath(path: &[u8]) -> Result<Vec<u8>> {
    if path.contains(&0) {
        return Err(Errno::EINVAL);
    }
    let mut v = Vec::with_capacity(path.len() + 1);
    v.extend_from_slice(path);
    v.push(0);
    Ok(v)
}

/// A path for a native call: its address and length. NUL bytes are
/// refused, as C strings would make them.
fn npath(path: &[u8]) -> Result<(usize, usize)> {
    if path.contains(&0) {
        return Err(Errno::EINVAL);
    }
    Ok((path.as_ptr() as usize, path.len()))
}

pub fn open(path: &[u8], flags: u32, mode: u32) -> Result<i32> {
    loop {
        let r = if sys::native() {
            let (p, n) = npath(path)?;
            crate::syscall!(nr::OPEN as usize, CWD, p, n, sys::open_flags_native(flags)?, mode)
        } else {
            let p = cpath(path)?;
            crate::syscall!(sys::OPEN, p.as_ptr(), flags, mode)
        };
        match r {
            Err(Errno::EINTR) => continue,
            r => return r.map(|fd| fd as i32),
        }
    }
}

/// Read a whole file.
pub fn read_file(path: &[u8]) -> Result<Vec<u8>> {
    let fd = open(path, O_RDONLY | O_CLOEXEC, 0)?;
    let r = crate::io::read_to_end(fd);
    let _ = crate::io::close(fd);
    r
}

/// Replace a file's contents.
pub fn write_file(path: &[u8], data: &[u8], mode: u32) -> Result<()> {
    let fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode)?;
    let r = crate::io::write_all(fd, data);
    let _ = crate::io::close(fd);
    r
}

/// File metadata (`struct stat`, x86-64).
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub nlink: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    _pad: i32,
    pub rdev: u64,
    pub size: i64,
    pub blksize: i64,
    pub blocks: i64,
    pub atime: i64,
    pub atime_nsec: i64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub ctime: i64,
    pub ctime_nsec: i64,
    _reserved: [i64; 3],
}

impl Stat {
    pub fn kind(&self) -> u32 {
        self.mode & S_IFMT
    }
    pub fn is_dir(&self) -> bool {
        self.kind() == S_IFDIR
    }
    pub fn is_file(&self) -> bool {
        self.kind() == S_IFREG
    }
    pub fn is_symlink(&self) -> bool {
        self.kind() == S_IFLNK
    }
}

impl From<slate_abi::Stat> for Stat {
    fn from(n: slate_abi::Stat) -> Stat {
        Stat {
            dev: n.dev,
            ino: n.ino,
            nlink: u64::from(n.nlink),
            mode: n.mode,
            uid: n.uid,
            gid: n.gid,
            rdev: n.rdev,
            size: n.size as i64,
            blksize: i64::from(n.block_size),
            blocks: n.blocks as i64,
            atime: n.atime.sec,
            atime_nsec: n.atime.nsec,
            mtime: n.mtime.sec,
            mtime_nsec: n.mtime.nsec,
            ctime: n.ctime.sec,
            ctime_nsec: n.ctime.nsec,
            ..Default::default()
        }
    }
}

/// Native stat of `path` relative to `dir` with `flags`.
fn native_stat(dir: i32, path: &[u8], flags: u32) -> Result<Stat> {
    let (p, n) = npath(path)?;
    let mut st = slate_abi::Stat::default();
    crate::syscall!(nr::STAT as usize, dir, p, n, flags, &mut st as *mut slate_abi::Stat)?;
    Ok(st.into())
}

fn stat_call(linux: usize, path: &[u8], flags: u32) -> Result<Stat> {
    if sys::native() {
        return native_stat(CWD, path, flags);
    }
    let p = cpath(path)?;
    let mut st = Stat::default();
    crate::syscall!(linux, p.as_ptr(), &mut st as *mut Stat)?;
    Ok(st)
}

pub fn stat(path: &[u8]) -> Result<Stat> {
    stat_call(sys::STAT, path, 0)
}

pub fn lstat(path: &[u8]) -> Result<Stat> {
    stat_call(sys::LSTAT, path, pf::NOFOLLOW)
}

pub fn fstat(fd: i32) -> Result<Stat> {
    if sys::native() {
        return native_stat(fd, b"", pf::EMPTY_PATH);
    }
    let mut st = Stat::default();
    crate::syscall!(sys::FSTAT, fd, &mut st as *mut Stat)?;
    Ok(st)
}

pub fn exists(path: &[u8]) -> bool {
    lstat(path).is_ok()
}

/// A call taking one path: natively (CWD, path, length, args...), on
/// Linux (C string, args...).
macro_rules! path_call {
    ($(#[$m:meta])* $name:ident, $linux:expr, $native:expr $(, $arg:ident: $t:ty)* ; $($extra:expr),*) => {
        $(#[$m])*
        pub fn $name(path: &[u8] $(, $arg: $t)*) -> Result<()> {
            if sys::native() {
                let (p, n) = npath(path)?;
                return crate::syscall!($native as usize, CWD, p, n $(, $arg)* $(, $extra)*).map(|_| ());
            }
            let p = cpath(path)?;
            crate::syscall!($linux, p.as_ptr() $(, $arg)*).map(|_| ())
        }
    };
}

path_call!(mkdir, sys::MKDIR, nr::MKDIR, mode: u32;);
path_call!(rmdir, sys::RMDIR, nr::UNLINK; pf::REMOVE_DIR);
path_call!(unlink, sys::UNLINK, nr::UNLINK; 0);
path_call!(chdir, sys::CHDIR, nr::CHDIR; 0);
path_call!(chroot, sys::CHROOT, nr::CHROOT;);
path_call!(chmod, sys::CHMOD, nr::CHMOD, mode: u32; 0);
path_call!(chown, sys::CHOWN, nr::CHOWN, uid: u32, gid: u32; 0);
path_call!(lchown, sys::LCHOWN, nr::CHOWN, uid: u32, gid: u32; pf::NOFOLLOW);
path_call!(access, sys::ACCESS, nr::ACCESS, mode: u32; 0);
path_call!(mknod, sys::MKNOD, nr::MKNOD, mode: u32, dev: u64;);

/// truncate(2). Natively: open for writing, then truncate the descriptor.
pub fn truncate(path: &[u8], len: u64) -> Result<()> {
    if sys::native() {
        let fd = open(path, O_WRONLY | O_CLOEXEC, 0)?;
        let r = crate::syscall!(nr::TRUNCATE as usize, fd, len).map(|_| ());
        let _ = crate::io::close(fd);
        return r;
    }
    let p = cpath(path)?;
    crate::syscall!(sys::TRUNCATE, p.as_ptr(), len).map(|_| ())
}

/// ftruncate(2).
pub fn ftruncate(fd: i32, len: u64) -> Result<()> {
    crate::syscall!(sys::pick(sys::FTRUNCATE, nr::TRUNCATE), fd, len).map(|_| ())
}

/// rename(2)/link(2): two paths.
fn two_paths(linux: usize, native: u64, a: &[u8], b: &[u8]) -> Result<()> {
    if sys::native() {
        let ((pa, na), (pb, nb)) = (npath(a)?, npath(b)?);
        return crate::syscall!(native as usize, CWD, pa, na, CWD, pb, nb).map(|_| ());
    }
    let (a, b) = (cpath(a)?, cpath(b)?);
    crate::syscall!(linux, a.as_ptr(), b.as_ptr()).map(|_| ())
}

pub fn rename(from: &[u8], to: &[u8]) -> Result<()> {
    two_paths(sys::RENAME, nr::RENAME, from, to)
}
pub fn link(target: &[u8], name: &[u8]) -> Result<()> {
    two_paths(sys::LINK, nr::LINK, target, name)
}
pub fn symlink(target: &[u8], name: &[u8]) -> Result<()> {
    if sys::native() {
        let ((pt, nt), (pn, nn)) = (npath(target)?, npath(name)?);
        return crate::syscall!(nr::SYMLINK as usize, pt, nt, CWD, pn, nn).map(|_| ());
    }
    let (a, b) = (cpath(target)?, cpath(name)?);
    crate::syscall!(sys::SYMLINK, a.as_ptr(), b.as_ptr()).map(|_| ())
}

pub fn readlink(path: &[u8]) -> Result<Vec<u8>> {
    let mut buf = alloc::vec![0u8; 4096];
    let n = if sys::native() {
        let (p, n) = npath(path)?;
        crate::syscall!(nr::READLINK as usize, CWD, p, n, buf.as_mut_ptr(), buf.len(), 0)?
    } else {
        let p = cpath(path)?;
        crate::syscall!(sys::READLINK, p.as_ptr(), buf.as_mut_ptr(), buf.len())?
    };
    buf.truncate(n);
    Ok(buf)
}

/// A watch descriptor (inotify(7)): reading it gives `slate_abi::watch`
/// events (ADR 0149). `nonblock`: reads return EAGAIN when there are none.
pub fn watch_open(nonblock: bool) -> Result<i32> {
    let fd = if sys::native() {
        let f = slate_abi::open::CLOEXEC | if nonblock { slate_abi::open::NONBLOCK } else { 0 };
        crate::syscall!(nr::WATCH_OPEN as usize, f)?
    } else {
        crate::syscall!(sys::INOTIFY_INIT1, O_CLOEXEC | if nonblock { O_NONBLOCK } else { 0 })?
    };
    Ok(fd as i32)
}

/// Watch `path` for `mask` (`slate_abi::watch::*`); the watch's number.
pub fn watch_add(fd: i32, path: &[u8], mask: u32) -> Result<i32> {
    let wd = if sys::native() {
        let (p, n) = npath(path)?;
        crate::syscall!(nr::WATCH_ADD as usize, fd, CWD, p, n, mask)?
    } else {
        let p = cpath(path)?;
        crate::syscall!(sys::INOTIFY_ADD_WATCH, fd, p.as_ptr(), mask)?
    };
    Ok(wd as i32)
}

pub fn watch_remove(fd: i32, wd: i32) -> Result<()> {
    let n = if sys::native() { nr::WATCH_REMOVE as usize } else { sys::INOTIFY_RM_WATCH };
    crate::syscall!(n, fd, wd).map(|_| ())
}

/// An extended attribute of an open file (xattr(7)).
pub fn xattr_get(fd: i32, name: &[u8]) -> Result<Vec<u8>> {
    let c = cpath(name)?;
    let call = |buf: &mut [u8]| -> Result<usize> {
        if sys::native() {
            crate::syscall!(nr::XATTR_GET as usize, fd, name.as_ptr(), name.len(), buf.as_mut_ptr(), buf.len())
        } else {
            crate::syscall!(sys::FGETXATTR, fd, c.as_ptr(), buf.as_mut_ptr(), buf.len())
        }
    };
    // Its size first; it may change between the two calls.
    loop {
        let size = call(&mut [])?;
        let mut buf = alloc::vec![0u8; size.max(1)];
        match call(&mut buf[..size]) {
            Ok(n) => {
                buf.truncate(n);
                return Ok(buf);
            }
            Err(Errno::ERANGE) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// `xattr_set`'s flags: fail if it exists / if it does not.
pub const XATTR_CREATE: u32 = 1;
pub const XATTR_REPLACE: u32 = 2;

pub fn xattr_set(fd: i32, name: &[u8], value: &[u8], flags: u32) -> Result<()> {
    if sys::native() {
        return crate::syscall!(
            nr::XATTR_SET as usize,
            fd,
            name.as_ptr(),
            name.len(),
            value.as_ptr(),
            value.len(),
            flags
        )
        .map(|_| ());
    }
    let c = cpath(name)?;
    crate::syscall!(sys::FSETXATTR, fd, c.as_ptr(), value.as_ptr(), value.len(), flags).map(|_| ())
}

/// The names of an open file's extended attributes (those the caller may
/// read).
pub fn xattr_list(fd: i32) -> Result<Vec<Vec<u8>>> {
    let call = |buf: &mut [u8]| -> Result<usize> {
        crate::syscall!(sys::pick(sys::FLISTXATTR, nr::XATTR_LIST), fd, buf.as_mut_ptr(), buf.len())
    };
    loop {
        let size = call(&mut [])?;
        let mut buf = alloc::vec![0u8; size.max(1)];
        match call(&mut buf[..size]) {
            Ok(n) => {
                return Ok(buf[..n].split(|&b| b == 0).filter(|s| !s.is_empty()).map(<[u8]>::to_vec).collect());
            }
            Err(Errno::ERANGE) => continue,
            Err(e) => return Err(e),
        }
    }
}

pub fn xattr_remove(fd: i32, name: &[u8]) -> Result<()> {
    if sys::native() {
        return crate::syscall!(nr::XATTR_REMOVE as usize, fd, name.as_ptr(), name.len()).map(|_| ());
    }
    let c = cpath(name)?;
    crate::syscall!(sys::FREMOVEXATTR, fd, c.as_ptr()).map(|_| ())
}

pub fn getcwd() -> Result<Vec<u8>> {
    let mut buf = alloc::vec![0u8; 4096];
    let n = crate::syscall!(sys::pick(sys::GETCWD, nr::GETCWD), buf.as_mut_ptr(), buf.len())?;
    // Linux counts the NUL; the native call does not.
    buf.truncate(if sys::native() { n } else { n.saturating_sub(1) });
    Ok(buf)
}

pub fn umask(mask: u32) -> u32 {
    crate::syscall!(sys::pick(sys::UMASK, nr::UMASK), mask).unwrap_or(0) as u32
}

/// Set access and modification times; `None` leaves one alone (UTIME_OMIT)
/// and `Some(None)` means "now" (UTIME_NOW).
pub fn set_times(
    path: &[u8],
    atime: Option<Option<(i64, i64)>>,
    mtime: Option<Option<(i64, i64)>>,
    follow: bool,
) -> Result<()> {
    const UTIME_NOW: i64 = (1 << 30) - 1;
    const UTIME_OMIT: i64 = (1 << 30) - 2;
    let enc = |t: Option<Option<(i64, i64)>>| match t {
        None => [0, UTIME_OMIT],
        Some(None) => [0, UTIME_NOW],
        Some(Some((s, ns))) => [s, ns],
    };
    let mut ts = [enc(atime), enc(mtime)];
    if sys::native() {
        for t in &mut ts {
            t[1] = match t[1] {
                UTIME_NOW => slate_abi::utime::NOW,
                UTIME_OMIT => slate_abi::utime::OMIT,
                n => n,
            };
        }
        let (p, n) = npath(path)?;
        let flags = if follow { 0 } else { pf::NOFOLLOW };
        return crate::syscall!(nr::UTIMES as usize, CWD, p, n, ts.as_ptr(), flags).map(|_| ());
    }
    let p = cpath(path)?;
    let flags = if follow { 0 } else { AT_SYMLINK_NOFOLLOW };
    crate::syscall!(sys::UTIMENSAT, AT_FDCWD, p.as_ptr(), ts.as_ptr(), flags).map(|_| ())
}

/// A directory entry.
#[derive(Clone, Debug)]
pub struct DirEntry {
    pub ino: u64,
    pub name: Vec<u8>,
    /// `d_type` (DT_DIR = 4, DT_REG = 8, DT_LNK = 10, 0 if unknown).
    pub kind: u8,
}

/// All entries of a directory except "." and "..".
pub fn read_dir(path: &[u8]) -> Result<Vec<DirEntry>> {
    let fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0)?;
    let mut out = Vec::new();
    let mut buf = alloc::vec![0u8; 32 * 1024];
    let r = loop {
        let n = match crate::syscall!(sys::pick(sys::GETDENTS64, nr::READDIR), fd, buf.as_mut_ptr(), buf.len()) {
            Ok(n) => n,
            Err(e) => break Err(e),
        };
        if n == 0 {
            break Ok(());
        }
        if sys::native() {
            // slate-abi's DirEntry: ino u64, rec_len u16, name_len u16,
            // kind u8, 3 reserved, then the name (no NUL).
            let mut at = 0;
            while at + slate_abi::DirEntry::SIZE <= n {
                let ino = u64::from_ne_bytes(buf[at..at + 8].try_into().unwrap());
                let rec = usize::from(u16::from_ne_bytes([buf[at + 8], buf[at + 9]]));
                let len = usize::from(u16::from_ne_bytes([buf[at + 10], buf[at + 11]]));
                let kind = buf[at + 12];
                let name = &buf[at + 16..(at + 16 + len).min(n)];
                if name != b"." && name != b".." {
                    out.push(DirEntry { ino, name: name.to_vec(), kind });
                }
                if rec == 0 {
                    break;
                }
                at += rec;
            }
            continue;
        }
        // struct linux_dirent64: ino u64, off i64, reclen u16, type u8, name.
        let mut at = 0;
        while at + 19 <= n {
            let ino = u64::from_ne_bytes(buf[at..at + 8].try_into().unwrap());
            let reclen = usize::from(u16::from_ne_bytes([buf[at + 16], buf[at + 17]]));
            let kind = buf[at + 18];
            let name_area = &buf[at + 19..at + reclen];
            let name = &name_area[..name_area.iter().position(|&b| b == 0).unwrap_or(name_area.len())];
            if name != b"." && name != b".." {
                out.push(DirEntry { ino, name: name.to_vec(), kind });
            }
            if reclen == 0 {
                break;
            }
            at += reclen;
        }
    };
    let _ = crate::io::close(fd);
    r.map(|_| out)
}

/// `a/b`, without doubling a slash.
pub fn join(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut v = a.to_vec();
    if !v.is_empty() && !v.ends_with(b"/") {
        v.push(b'/');
    }
    v.extend_from_slice(b);
    v
}

/// The last component of a path (basename(1) rules, without suffixes).
pub fn basename(p: &[u8]) -> &[u8] {
    let t = trim_trailing_slashes(p);
    if t.is_empty() {
        return if p.is_empty() { b"" } else { b"/" };
    }
    match t.iter().rposition(|&c| c == b'/') {
        Some(i) => &t[i + 1..],
        None => t,
    }
}

/// Everything but the last component (dirname(1) rules).
pub fn dirname(p: &[u8]) -> &[u8] {
    let t = trim_trailing_slashes(p);
    if t.is_empty() {
        return if p.starts_with(b"/") { b"/" } else { b"." };
    }
    match t.iter().rposition(|&c| c == b'/') {
        None => b".",
        Some(i) => {
            let d = trim_trailing_slashes(&t[..i]);
            if d.is_empty() { b"/" } else { d }
        }
    }
}

fn trim_trailing_slashes(p: &[u8]) -> &[u8] {
    let mut end = p.len();
    while end > 0 && p[end - 1] == b'/' {
        end -= 1;
    }
    &p[..end]
}

pub fn fsync(fd: i32) -> Result<()> {
    crate::syscall!(sys::pick(sys::FSYNC, nr::SYNC), fd).map(|_| ())
}

// flock(2) operations. Source: musl `sys/file.h`.
pub const LOCK_SH: u32 = 1;
pub const LOCK_EX: u32 = 2;
pub const LOCK_NB: u32 = 4;
pub const LOCK_UN: u32 = 8;

/// flock(2): `LOCK_SH`, `LOCK_EX` or `LOCK_UN`, maybe with `LOCK_NB`. The
/// lock belongs to the open file: it goes when its last descriptor closes.
pub fn flock(fd: i32, op: u32) -> Result<()> {
    if sys::native() {
        use slate_abi::flock as fl;
        let base = match op & !LOCK_NB {
            LOCK_SH => fl::SHARED,
            LOCK_EX => fl::EXCLUSIVE,
            LOCK_UN => fl::UNLOCK,
            _ => return Err(Errno::EINVAL),
        };
        let native = base | if op & LOCK_NB != 0 { fl::NONBLOCK } else { 0 };
        return crate::syscall!(nr::FLOCK as usize, fd, native as usize).map(|_| ());
    }
    crate::syscall!(sys::FLOCK, fd, op as usize).map(|_| ())
}

pub fn sync() {
    let _ = if sys::native() { crate::syscall!(nr::SYNC as usize, -1i32) } else { crate::syscall!(sys::SYNC) };
}

/// mount(2) flags (musl `sys/mount.h`).
pub const MS_RDONLY: usize = 1;
pub const MS_NOSUID: usize = 2;
pub const MS_NODEV: usize = 4;
pub const MS_NOEXEC: usize = 8;
pub const MS_REMOUNT: usize = 32;
pub const MS_NOATIME: usize = 1024;
pub const MS_NODIRATIME: usize = 2048;
pub const MS_BIND: usize = 4096;
pub const MS_REC: usize = 16384;
pub const MS_RELATIME: usize = 1 << 21;
pub const MS_STRICTATIME: usize = 1 << 24;

/// mount(2); `data` holds file-system options (may be empty).
pub fn mount(source: &[u8], target: &[u8], fstype: &[u8], flags: usize, data: &[u8]) -> Result<()> {
    if sys::native() {
        use slate_abi::mount as m;
        let table = [
            (MS_RDONLY, m::RDONLY),
            (MS_NOSUID, m::NOSUID),
            (MS_NODEV, m::NODEV),
            (MS_NOEXEC, m::NOEXEC),
            (MS_REMOUNT, m::REMOUNT),
            (MS_BIND, m::BIND),
            (MS_REC, m::RECURSIVE),
            (MS_NOATIME, m::NOATIME),
            (MS_NODIRATIME, m::NODIRATIME),
            (MS_RELATIME, m::RELATIME),
            (MS_STRICTATIME, m::STRICTATIME),
        ];
        let known = table.iter().fold(0, |a, (l, _)| a | l);
        if flags & !known != 0 {
            return Err(Errno::EINVAL);
        }
        let native = table.iter().filter(|(l, _)| flags & l != 0).fold(0, |a, (_, n)| a | n);
        for s in [source, target, fstype, data] {
            npath(s)?;
        }
        let args = slate_abi::MountArgs {
            source: slate_abi::Str::new(source),
            target: slate_abi::Str::new(target),
            fstype: slate_abi::Str::new(fstype),
            data: slate_abi::Str::new(data),
        };
        return crate::syscall!(nr::MOUNT as usize, &args as *const slate_abi::MountArgs, native).map(|_| ());
    }
    let (s, t, f, d) = (cpath(source)?, cpath(target)?, cpath(fstype)?, cpath(data)?);
    let d = if data.is_empty() { core::ptr::null() } else { d.as_ptr() };
    crate::syscall!(sys::MOUNT, s.as_ptr(), t.as_ptr(), f.as_ptr(), flags, d).map(|_| ())
}

/// umount(2).
pub fn umount(target: &[u8]) -> Result<()> {
    if sys::native() {
        let (p, n) = npath(target)?;
        return crate::syscall!(nr::UMOUNT as usize, p, n, 0).map(|_| ());
    }
    let t = cpath(target)?;
    crate::syscall!(sys::UMOUNT2, t.as_ptr(), 0).map(|_| ())
}

/// What statfs(2) says about the file system holding a path.
#[derive(Clone, Copy, Debug, Default)]
pub struct StatFs {
    /// The type's magic number (statfs(2)).
    pub kind: i64,
    pub block_size: i64,
    pub blocks: u64,
    pub free: u64,
    pub available: u64,
    pub files: u64,
    pub free_files: u64,
    /// The file system's ID (statfs(2)'s two words, the first high).
    pub fsid: u64,
    pub name_max: u64,
    /// The fundamental block size (f_frsize).
    pub fragment_size: i64,
}

pub fn statfs(path: &[u8]) -> Result<StatFs> {
    if sys::native() {
        let (p, n) = npath(path)?;
        let mut s = slate_abi::StatFs::default();
        crate::syscall!(nr::STATFS as usize, CWD, p, n, 0, &mut s as *mut slate_abi::StatFs)?;
        return Ok(StatFs {
            kind: s.kind as i64,
            block_size: s.block_size as i64,
            blocks: s.blocks,
            free: s.free,
            available: s.available,
            files: s.files,
            free_files: s.free_files,
            fsid: s.fsid,
            name_max: s.name_max,
            fragment_size: s.block_size as i64,
        });
    }
    // struct statfs (x86-64): f_type, f_bsize, f_blocks, f_bfree,
    // f_bavail, f_files, f_ffree, f_fsid (two ints), f_namelen,
    // f_frsize, ... as 64-bit words (statfs(2)).
    let c = cpath(path)?;
    let mut b = [0u64; 15];
    crate::syscall!(sys::STATFS, c.as_ptr(), b.as_mut_ptr())?;
    Ok(StatFs {
        kind: b[0] as i64,
        block_size: b[1] as i64,
        blocks: b[2],
        free: b[3],
        available: b[4],
        files: b[5],
        free_files: b[6],
        fsid: b[7].rotate_left(32),
        name_max: b[8],
        fragment_size: b[9] as i64,
    })
}
