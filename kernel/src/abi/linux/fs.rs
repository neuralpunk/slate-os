// SPDX-License-Identifier: MIT OR Apache-2.0

//! File and directory system calls: open(2), stat(2), getdents64(2),
//! mkdir(2), unlink(2), rename(2), symlink(2), readlink(2), chdir(2),
//! getcwd(2), dup(2), fcntl(2), pipe(2), poll(2), select(2), mount(2), ...

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::errno::*;
use super::{Args, Result};
use crate::arch::uaccess::{StrError, copy_from_user, copy_to_user, read_user, read_user_cstr, write_user};
use crate::fs::vfs::{self, Dentry, FileType, Metadata, PATH_MAX, Timespec};
use crate::fs::{self, File, inotify, poll_generation, poll_wait};
use crate::proc::cred::{CAP_CHOWN, CAP_FSETID, CAP_MKNOD, MAY_EXEC, MAY_WRITE, S_ISGID, S_ISUID};
use crate::proc::{self, Process};
use crate::sched::wait::WaitResult;

pub const AT_FDCWD: i32 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_REMOVEDIR: u64 = 0x200;
const AT_SYMLINK_FOLLOW: u64 = 0x400;
const AT_EMPTY_PATH: u64 = 0x1000;
/// faccessat(2) with the effective IDs (linux/fcntl.h value per the man page).
const AT_EACCESS: u64 = 0x200;
const F_DUPFD: u64 = 0;
const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const F_SETLK: u64 = 6;
const F_SETLKW: u64 = 7;
const F_GETLK: u64 = 5;
const F_OFD_GETLK: u64 = 36;
const F_OFD_SETLK: u64 = 37;
const F_OFD_SETLKW: u64 = 38;
const F_DUPFD_CLOEXEC: u64 = 1030;
const FD_CLOEXEC: u64 = 1;
pub(crate) const UTIME_NOW: i64 = (1 << 30) - 1;
pub(crate) const UTIME_OMIT: i64 = (1 << 30) - 2;

fn me() -> core::result::Result<Arc<Process>, Errno> {
    proc::current().ok_or(ESRCH)
}

/// Read a path argument.
pub fn user_path(addr: u64) -> core::result::Result<String, Errno> {
    let bytes = read_user_cstr(addr, PATH_MAX).map_err(|e| match e {
        StrError::Fault => EFAULT,
        StrError::TooLong => ENAMETOOLONG,
    })?;
    String::from_utf8(bytes).map_err(|_| EINVAL)
}

/// The directory a *at() call is relative to.
pub(crate) fn base_dir(p: &Process, dirfd: i32) -> core::result::Result<Arc<Dentry>, Errno> {
    if dirfd == AT_FDCWD {
        return Ok(p.cwd());
    }
    let f = p.files.lock().get(dirfd)?;
    let d = f.dentry().ok_or(ENOTDIR)?;
    if !d.is_dir() {
        return Err(ENOTDIR);
    }
    Ok(d)
}

/// The directory a `*at` call resolves `path` from: `dirfd`'s, unless the
/// path is absolute, when dirfd is ignored (openat(2)), even if it is no
/// directory at all (ADR 0114: Flatpak passes 0 with absolute paths).
pub(crate) fn dir_for(p: &Process, dirfd: i32, path: &str) -> core::result::Result<Arc<Dentry>, Errno> {
    if path.starts_with('/') { Ok(p.cwd()) } else { base_dir(p, dirfd) }
}

fn file(fd: i32) -> core::result::Result<Arc<dyn File>, Errno> {
    me()?.files.lock().get(fd)
}

// --- open/close ---------------------------------------------------------

fn do_open(dirfd: i32, path: u64, flags: u64, mode: u64) -> Result {
    open_at(dirfd, &user_path(path)?, flags as u32, mode as u32)
}

/// Open `path` relative to `dirfd` with `O_*` flags; returns the new
/// descriptor. Shared with the native interface.
pub(crate) fn open_at(dirfd: i32, path: &str, flags: u32, mode: u32) -> Result {
    open_at_restricted(dirfd, path, flags, mode, vfs::Restrict::default())
}

// openat2(2): `struct open_how` (u64 flags, mode, resolve; 24 bytes in
// its first version) and the RESOLVE_* bits (the man page; musl has no
// header for them, the values are the man page's and Linux's observed).
const OPEN_HOW_SIZE_VER0: u64 = 24;
const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;
const RESOLVE_CACHED: u64 = 0x20;
/// Every O_* flag open(2) knows (musl `fcntl.h`: O_ACCMODE up to
/// __O_TMPFILE, 0o20000000).
const O_KNOWN: u64 = 0o37777777;
const O_TMPFILE_BIT: u64 = 0o20000000;

/// openat2(2): openat with its flags checked strictly and the lookup
/// restricted (ADR 0115). Checked against Linux on the host: sizes under
/// 24 bytes are EINVAL, a larger struct must be zero past what is known
/// (E2BIG), and so must anything past a page.
pub fn openat2(a: Args) -> Result {
    let [dirfd, path, how, size, ..] = a.0;
    if size < OPEN_HOW_SIZE_VER0 {
        return Err(EINVAL);
    }
    if size > crate::mm::PAGE_SIZE {
        return Err(E2BIG);
    }
    let mut raw = alloc::vec![0u8; size as usize];
    copy_from_user(&mut raw, how).map_err(|_| EFAULT)?;
    if raw[24..].iter().any(|&b| b != 0) {
        return Err(E2BIG);
    }
    let word = |i: usize| u64::from_ne_bytes(raw[8 * i..8 * i + 8].try_into().unwrap());
    let (flags, mode, resolve) = (word(0), word(1), word(2));
    let known = RESOLVE_NO_XDEV
        | RESOLVE_NO_MAGICLINKS
        | RESOLVE_NO_SYMLINKS
        | RESOLVE_BENEATH
        | RESOLVE_IN_ROOT
        | RESOLVE_CACHED;
    if flags & !O_KNOWN != 0 || resolve & !known != 0 || mode & !0o7777 != 0 {
        return Err(EINVAL);
    }
    // A mode only for files being made (openat2(2)).
    if mode != 0 && flags & (u64::from(fs::O_CREAT) | O_TMPFILE_BIT) == 0 {
        return Err(EINVAL);
    }
    if resolve & (RESOLVE_BENEATH | RESOLVE_IN_ROOT) == RESOLVE_BENEATH | RESOLVE_IN_ROOT {
        return Err(EINVAL);
    }
    // Making or truncating a file is never cached (EAGAIN, as Linux
    // answers); lookups go through the dentry cache alone.
    if resolve & RESOLVE_CACHED != 0 && flags & (u64::from(fs::O_CREAT | fs::O_TRUNC) | O_TMPFILE_BIT) != 0 {
        return Err(EAGAIN);
    }
    let r = vfs::Restrict {
        beneath: resolve & RESOLVE_BENEATH != 0,
        in_root: resolve & RESOLVE_IN_ROOT != 0,
        no_symlinks: resolve & RESOLVE_NO_SYMLINKS != 0,
        no_magiclinks: resolve & RESOLVE_NO_MAGICLINKS != 0,
        no_xdev: resolve & RESOLVE_NO_XDEV != 0,
        cached: resolve & RESOLVE_CACHED != 0,
    };
    open_at_restricted(dirfd as i32, &user_path(path)?, flags as u32, mode as u32, r)
}

// name_to_handle_at(2) and open_by_handle_at(2): `struct file_handle` is
// a u32 handle_bytes, an i32 handle_type, then the handle; MAX_HANDLE_SZ
// is 128 (the man page; musl `fcntl.h`). AT_HANDLE_FID (since Linux 6.5)
// asks for a handle that only identifies the file.
const MAX_HANDLE_SZ: u32 = 128;
const AT_HANDLE_FID: u64 = 0x200;
/// Slate's handles: the file's device and inode numbers, 8 bytes each.
const HANDLE_TYPE: i32 = 0x534c;
const HANDLE_BYTES: u32 = 16;
/// What Linux writes as the type with EOVERFLOW (observed: 255).
const HANDLE_TYPE_INVALID: i32 = 255;

/// name_to_handle_at(2) (ADR 0115). As Linux was seen to: a buffer too
/// small is EOVERFLOW with the size needed (and the mount ID) written; a
/// file whose handle can't be opened again (/proc's, a pipe's) is
/// EOPNOTSUPP unless AT_HANDLE_FID asks only to identify it.
pub fn name_to_handle_at(a: Args) -> Result {
    let [dirfd, path, handle, mount_id, flags, _] = a.0;
    if flags & !(AT_EMPTY_PATH | AT_SYMLINK_FOLLOW | AT_HANDLE_FID) != 0 {
        return Err(EINVAL);
    }
    let want: u32 = read_user(handle).map_err(|_| EFAULT)?;
    if want > MAX_HANDLE_SZ {
        return Err(EINVAL);
    }
    let p = me()?;
    let path = user_path(path)?;
    // The file: by name, or the descriptor itself (AT_EMPTY_PATH).
    let (meta, dentry) = if path.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            return Err(ENOENT);
        }
        let f = p.files.lock().get(dirfd as i32)?;
        (f.stat()?, f.dentry())
    } else {
        let d = vfs::resolve(&dir_for(&p, dirfd as i32, &path)?, &path, flags & AT_SYMLINK_FOLLOW != 0)?;
        (d.metadata(), Some(d))
    };
    let reopenable = dentry.as_ref().is_some_and(|d| d.inode.handles());
    if !reopenable && flags & AT_HANDLE_FID == 0 {
        return Err(EOPNOTSUPP);
    }
    let mid = dentry.as_ref().and_then(vfs::mount_of_dentry).map_or(0, |(id, _)| id as i32);
    if want < HANDLE_BYTES {
        write_user(handle, &HANDLE_BYTES).map_err(|_| EFAULT)?;
        write_user(handle + 4, &HANDLE_TYPE_INVALID).map_err(|_| EFAULT)?;
        write_user(mount_id, &mid).map_err(|_| EFAULT)?;
        return Err(EOVERFLOW);
    }
    let mut b = alloc::vec::Vec::with_capacity(24);
    b.extend_from_slice(&HANDLE_BYTES.to_ne_bytes());
    b.extend_from_slice(&HANDLE_TYPE.to_ne_bytes());
    b.extend_from_slice(&meta.ino.to_ne_bytes());
    b.extend_from_slice(&meta.dev.to_ne_bytes());
    copy_to_user(handle, &b).map_err(|_| EFAULT)?;
    write_user(mount_id, &mid).map_err(|_| EFAULT)?;
    Ok(0)
}

/// open_by_handle_at(2): the file a handle names, in the mount `mount_fd`
/// lies in. CAP_DAC_READ_SEARCH only (a handle skips the path's
/// permission checks); the file's own are checked as open(2) checks them.
pub fn open_by_handle_at(a: Args) -> Result {
    let [mount_fd, handle, flags, ..] = a.0;
    if !crate::proc::cred::current().capable(crate::proc::cred::CAP_DAC_READ_SEARCH) {
        return Err(EPERM);
    }
    let bytes: u32 = read_user(handle).map_err(|_| EFAULT)?;
    if bytes > MAX_HANDLE_SZ || bytes == 0 {
        return Err(EINVAL);
    }
    let kind: i32 = read_user(handle + 4).map_err(|_| EFAULT)?;
    if kind != HANDLE_TYPE || bytes != HANDLE_BYTES {
        return Err(ESTALE);
    }
    let (ino, dev): (u64, u64) =
        (read_user(handle + 8).map_err(|_| EFAULT)?, read_user(handle + 16).map_err(|_| EFAULT)?);
    let p = me()?;
    let at = if mount_fd as i32 == AT_FDCWD {
        p.cwd()
    } else {
        p.files.lock().get(mount_fd as i32)?.dentry().ok_or(EBADF)?
    };
    let (_, root) = vfs::mount_of_dentry(&at).ok_or(ESTALE)?;
    if root.metadata().dev != dev || !root.inode.handles() {
        return Err(ESTALE);
    }
    let d = vfs::find_by_number(&root, ino)?;
    let flags = flags as u32 & !(fs::O_CREAT | fs::O_EXCL);
    let f = fs::open_found(d, flags)?;
    let fd = p.files.lock().insert(f, flags & fs::O_CLOEXEC != 0)?;
    Ok(fd as u64)
}

fn open_at_restricted(dirfd: i32, path: &str, flags: u32, mode: u32, r: vfs::Restrict) -> Result {
    let p = me()?;
    // Scoped lookups start at dirfd even for an absolute path (openat2(2):
    // RESOLVE_IN_ROOT takes it as the root, RESOLVE_BENEATH refuses it).
    let base = if r.in_root || r.beneath || r.no_xdev { base_dir(&p, dirfd)? } else { dir_for(&p, dirfd, path)? };
    let mode = mode & !p.umask();
    let created = inotify::active()
        && flags & fs::O_CREAT != 0
        && vfs::resolve_parent(&base, path).is_ok_and(|(dir, name)| dir.child(&name).is_err());
    let f = fs::open_restricted(&base, path, flags, mode, r)?;
    if let Some(d) = f.dentry().filter(|_| inotify::active()) {
        if created && let Some(dir) = &d.parent {
            inotify::report(dir, inotify::IN_CREATE, 0, &d.name, false);
        }
        inotify::report_self(&d, inotify::IN_OPEN);
    }
    let fd = p.files.lock().insert(f, flags & fs::O_CLOEXEC != 0)?;
    Ok(fd as u64)
}

pub fn open(a: Args) -> Result {
    do_open(AT_FDCWD, a.0[0], a.0[1], a.0[2])
}

pub fn openat(a: Args) -> Result {
    do_open(a.fd(0), a.0[1], a.0[2], a.0[3])
}

pub fn creat(a: Args) -> Result {
    do_open(AT_FDCWD, a.0[0], u64::from(fs::O_CREAT | fs::O_WRONLY | fs::O_TRUNC), a.0[1])
}

// --- offsets and positional I/O -----------------------------------------

pub fn lseek(a: Args) -> Result {
    file(a.fd(0))?.seek(a.0[1] as i64, a.0[2] as u32)
}

// --- directories --------------------------------------------------------

/// getdents64(2): `struct linux_dirent64 { u64 d_ino; i64 d_off; u16
/// d_reclen; u8 d_type; char d_name[]; }`, records padded to 8 bytes.
pub fn getdents64(a: Args) -> Result {
    let f = file(a.fd(0))?;
    let cap = a.0[2] as usize;
    let mut out: Vec<u8> = Vec::new();
    f.getdents(&mut |e, next| {
        let reclen = (19 + e.name.len() + 1).div_ceil(8) * 8;
        if out.len() + reclen > cap {
            return false;
        }
        let start = out.len();
        out.extend_from_slice(&e.ino.to_le_bytes());
        out.extend_from_slice(&(next as i64).to_le_bytes());
        out.extend_from_slice(&(reclen as u16).to_le_bytes());
        out.push(e.kind.dirent_type());
        out.extend_from_slice(e.name.as_bytes());
        out.resize(start + reclen, 0);
        true
    })?;
    if out.is_empty() && cap < 24 {
        // There was an entry, but the buffer cannot hold it.
        let mut any = false;
        let _ = f.getdents(&mut |_, _| {
            any = true;
            false
        });
        if any {
            return Err(EINVAL);
        }
    }
    copy_to_user(a.0[1], &out).map_err(|_| EFAULT)?;
    Ok(out.len() as u64)
}

pub fn mkdirat(a: Args) -> Result {
    mkdir_at(a.fd(0), &user_path(a.0[1])?, a.0[2] as u32)
}

pub(crate) fn mkdir_at(dirfd: i32, path: &str, mode: u32) -> Result {
    let p = me()?;
    let (parent, name) = vfs::resolve_parent(&dir_for(&p, dirfd, path)?, path)?;
    if parent.child(&name).is_ok() {
        return Err(EEXIST);
    }
    vfs::writable(&parent)?;
    let pm = parent.metadata();
    p.cred().permission(&pm, MAY_WRITE | MAY_EXEC)?;
    let mut mode = mode & 0o7777 & !p.umask();
    // Subdirectories of a set-group-ID directory are set-group-ID too.
    if pm.mode & S_ISGID != 0 {
        mode |= S_ISGID;
    }
    parent.inode.mkdir(&name, mode)?;
    let d = parent.child(&name)?;
    crate::fs::own_new(&parent, &d);
    inotify::report(&parent, inotify::IN_CREATE, 0, &name, true);
    if pm.mode & S_ISGID != 0 {
        let _ = d.inode.set_mode(mode);
    }
    Ok(0)
}

pub fn mkdir(a: Args) -> Result {
    mkdirat(Args([AT_FDCWD as u64, a.0[0], a.0[1], 0, 0, 0]))
}

pub fn mknodat(a: Args) -> Result {
    mknod_at(a.fd(0), &user_path(a.0[1])?, a.0[2] as u32, a.0[3])
}

pub(crate) fn mknod_at(dirfd: i32, path: &str, mode: u32, dev: u64) -> Result {
    let p = me()?;
    let (parent, name) = vfs::resolve_parent(&dir_for(&p, dirfd, path)?, path)?;
    if parent.child(&name).is_ok() {
        return Err(EEXIST);
    }
    let perm = mode & 0o7777 & !p.umask();
    let kind = mode & vfs::S_IFMT;
    let kind = if kind == 0 { vfs::S_IFREG } else { kind };
    let cred = p.cred();
    vfs::writable(&parent)?;
    cred.permission(&parent.metadata(), MAY_WRITE | MAY_EXEC)?;
    // Device nodes need CAP_MKNOD (mknod(2)); FIFOs, sockets and files do not.
    // Overlay whiteouts (character device 0/0) need it only in the
    // caller's user namespace.
    let whiteout = kind == vfs::S_IFCHR && dev == 0;
    if matches!(kind, vfs::S_IFCHR | vfs::S_IFBLK) && !(cred.capable(CAP_MKNOD) || whiteout && cred.has(CAP_MKNOD)) {
        return Err(EPERM);
    }
    if matches!(kind, vfs::S_IFCHR | vfs::S_IFBLK) && !whiteout {
        let ty = if kind == vfs::S_IFCHR { fs::cgroup::DEV_CHAR } else { fs::cgroup::DEV_BLOCK };
        if !fs::cgroup::device_allowed(ty, vfs::major(dev), vfs::minor(dev), fs::cgroup::ACC_MKNOD) {
            return Err(EPERM);
        }
    }
    parent.inode.create(&name, kind | perm, dev)?;
    crate::fs::own_new(&parent, &*parent.child(&name)?);
    inotify::report(&parent, inotify::IN_CREATE, 0, &name, false);
    Ok(0)
}

pub fn mknod(a: Args) -> Result {
    mknodat(Args([AT_FDCWD as u64, a.0[0], a.0[1], a.0[2], 0, 0]))
}

pub fn unlinkat(a: Args) -> Result {
    unlink_at(a.fd(0), &user_path(a.0[1])?, a.0[2] & AT_REMOVEDIR != 0)
}

pub(crate) fn unlink_at(dirfd: i32, path: &str, remove_dir: bool) -> Result {
    let p = me()?;
    let (parent, name) = vfs::resolve_parent(&dir_for(&p, dirfd, path)?, path)?;
    // rmdir(2): "." as the last component is EINVAL, before anything else.
    if remove_dir && name == "." {
        return Err(EINVAL);
    }
    let target = parent.child(&name)?;
    if target.is_mountpoint()
        || parent.covered(&name)
        || target.parent.as_ref().is_some_and(|tp| !Arc::ptr_eq(tp, &parent))
    {
        return Err(EBUSY);
    }
    vfs::writable(&parent)?;
    // The entry itself too: a top-level entry of the system image (ADR 0090).
    vfs::writable(&target)?;
    p.cred().may_delete(&parent.metadata(), &target.metadata())?;
    if remove_dir {
        parent.inode.rmdir(&name)?;
    } else {
        parent.inode.unlink(&name)?;
    }
    parent.forget(&name);
    if inotify::active() {
        // The inode's last name went (or a directory): its watches end
        // first, then the directory hears of it (Linux's order).
        if remove_dir || target.metadata().nlink == 0 {
            inotify::report_self(&target, inotify::IN_DELETE_SELF);
        }
        inotify::report(&parent, inotify::IN_DELETE, 0, &name, remove_dir);
    }
    Ok(0)
}

pub fn unlink(a: Args) -> Result {
    unlinkat(Args([AT_FDCWD as u64, a.0[0], 0, 0, 0, 0]))
}

pub fn rmdir(a: Args) -> Result {
    unlinkat(Args([AT_FDCWD as u64, a.0[0], AT_REMOVEDIR, 0, 0, 0]))
}

pub fn renameat2(a: Args) -> Result {
    rename_at(a.fd(0), &user_path(a.0[1])?, a.fd(2), &user_path(a.0[3])?)
}

pub(crate) fn rename_at(old_dir: i32, old: &str, new_dir: i32, new: &str) -> Result {
    let p = me()?;
    let (op, oname) = vfs::resolve_parent(&dir_for(&p, old_dir, old)?, old)?;
    let (np, nname) = vfs::resolve_parent(&dir_for(&p, new_dir, new)?, new)?;
    let moving = op.child(&oname)?;
    // Mount points stay put (rename(2) EBUSY).
    if op.covered(&oname) || np.covered(&nname) {
        return Err(EBUSY);
    }
    // A directory cannot move into itself.
    let mut d = Some(np.clone());
    while let Some(x) = d {
        if Arc::ptr_eq(&x, &moving) {
            return Err(EINVAL);
        }
        d = x.parent.clone();
    }
    if op.metadata().dev != np.metadata().dev {
        return Err(EXDEV);
    }
    let cred = p.cred();
    vfs::writable(&op)?;
    vfs::writable(&np)?;
    vfs::writable(&moving)?;
    cred.may_delete(&op.metadata(), &moving.metadata())?;
    match np.child(&nname) {
        Ok(existing) => cred.may_delete(&np.metadata(), &existing.metadata())?,
        Err(_) => cred.permission(&np.metadata(), MAY_WRITE | MAY_EXEC)?,
    }
    // A directory moving to a new parent rewrites its "..".
    if moving.is_dir() && !Arc::ptr_eq(&op, &np) {
        cred.permission(&moving.metadata(), MAY_WRITE)?;
    }
    op.inode.rename(&oname, &np.inode, &nname)?;
    op.forget(&oname);
    np.forget(&nname);
    if inotify::active() {
        let (cookie, isdir) = (inotify::cookie(), moving.is_dir());
        inotify::report(&op, inotify::IN_MOVED_FROM, cookie, &oname, isdir);
        inotify::report(&np, inotify::IN_MOVED_TO, cookie, &nname, isdir);
        inotify::report_self(&moving, inotify::IN_MOVE_SELF);
    }
    Ok(0)
}

pub fn renameat(a: Args) -> Result {
    renameat2(Args([a.0[0], a.0[1], a.0[2], a.0[3], 0, 0]))
}

pub fn rename(a: Args) -> Result {
    renameat2(Args([AT_FDCWD as u64, a.0[0], AT_FDCWD as u64, a.0[1], 0, 0]))
}

pub fn symlinkat(a: Args) -> Result {
    symlink_at(&user_path(a.0[0])?, a.fd(1), &user_path(a.0[2])?)
}

pub(crate) fn symlink_at(target: &str, dirfd: i32, path: &str) -> Result {
    let p = me()?;
    let (parent, name) = vfs::resolve_parent(&dir_for(&p, dirfd, path)?, path)?;
    if parent.child(&name).is_ok() {
        return Err(EEXIST);
    }
    vfs::writable(&parent)?;
    p.cred().permission(&parent.metadata(), MAY_WRITE | MAY_EXEC)?;
    parent.inode.symlink(&name, target)?;
    crate::fs::own_new(&parent, &*parent.child(&name)?);
    inotify::report(&parent, inotify::IN_CREATE, 0, &name, false);
    Ok(0)
}

pub fn symlink(a: Args) -> Result {
    symlinkat(Args([a.0[0], AT_FDCWD as u64, a.0[1], 0, 0, 0]))
}

pub fn linkat(a: Args) -> Result {
    link_at(a.fd(0), &user_path(a.0[1])?, a.fd(2), &user_path(a.0[3])?, a.0[4] & AT_SYMLINK_FOLLOW != 0)
}

pub(crate) fn link_at(old_dir: i32, old: &str, new_dir: i32, new: &str, follow: bool) -> Result {
    let p = me()?;
    let src = vfs::resolve(&dir_for(&p, old_dir, old)?, old, follow)?;
    let (np, nname) = vfs::resolve_parent(&dir_for(&p, new_dir, new)?, new)?;
    if np.child(&nname).is_ok() {
        return Err(EEXIST);
    }
    if src.metadata().dev != np.metadata().dev {
        return Err(EXDEV);
    }
    vfs::writable(&np)?;
    let cred = p.cred();
    cred.permission(&np.metadata(), MAY_WRITE | MAY_EXEC)?;
    // proc(5) protected_hardlinks.
    if !fs::protect::may_link(&src.metadata(), &cred) {
        return Err(EPERM);
    }
    np.inode.link(&nname, &src.inode)?;
    inotify::report(&np, inotify::IN_CREATE, 0, &nname, false);
    inotify::report_self(&src, inotify::IN_ATTRIB);
    Ok(0)
}

pub fn link(a: Args) -> Result {
    linkat(Args([AT_FDCWD as u64, a.0[0], AT_FDCWD as u64, a.0[1], 0, 0]))
}

pub fn readlinkat(a: Args) -> Result {
    let target = readlink_at(a.fd(0), &user_path(a.0[1])?)?;
    let n = target.len().min(a.0[3] as usize);
    copy_to_user(a.0[2], &target.as_bytes()[..n]).map_err(|_| EFAULT)?;
    Ok(n as u64)
}

/// A symbolic link's target. An empty path reads the link the descriptor
/// itself refers to (opened with O_PATH | O_NOFOLLOW; readlink(2)).
pub(crate) fn readlink_at(dirfd: i32, path: &str) -> core::result::Result<String, Errno> {
    let p = me()?;
    let d = if path.is_empty() {
        p.files.lock().get(dirfd)?.dentry().ok_or(ENOENT)?
    } else {
        vfs::resolve(&dir_for(&p, dirfd, path)?, path, false)?
    };
    d.inode.readlink()
}

pub fn readlink(a: Args) -> Result {
    readlinkat(Args([AT_FDCWD as u64, a.0[0], a.0[1], a.0[2], 0, 0]))
}

pub fn chdir(a: Args) -> Result {
    let p = me()?;
    let path = user_path(a.0[0])?;
    let d = vfs::resolve(&p.cwd(), &path, true)?;
    change_dir(&p, d)
}

pub fn fchdir(a: Args) -> Result {
    let p = me()?;
    let d = p.files.lock().get(a.fd(0))?.dentry().ok_or(ENOTDIR)?;
    change_dir(&p, d)
}

/// Make `d` the working directory, if it is a directory the caller may
/// search.
pub(crate) fn change_dir(p: &Process, d: Arc<Dentry>) -> Result {
    if !d.is_dir() {
        return Err(ENOTDIR);
    }
    p.cred().permission(&d.metadata(), MAY_EXEC)?;
    p.set_cwd(d);
    Ok(0)
}

pub fn getcwd(a: Args) -> Result {
    let cwd = me()?.cwd();
    let path = vfs::visible_path(&cwd);
    let bytes = path.as_bytes();
    if bytes.len() + 1 > a.0[1] as usize {
        return Err(ERANGE);
    }
    copy_to_user(a.0[0], bytes).map_err(|_| EFAULT)?;
    copy_to_user(a.0[0] + bytes.len() as u64, &[0]).map_err(|_| EFAULT)?;
    Ok(bytes.len() as u64 + 1)
}

// --- stat ---------------------------------------------------------------

/// x86-64 `struct stat` (musl `bits/stat.h`).
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Stat {
    dev: u64,
    ino: u64,
    nlink: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    _pad0: u32,
    rdev: u64,
    size: i64,
    blksize: i64,
    blocks: i64,
    atime: Timespec,
    mtime: Timespec,
    ctime: Timespec,
    _unused: [i64; 3],
}

fn to_stat(m: &Metadata) -> Stat {
    let c = crate::proc::cred::current();
    Stat {
        dev: m.dev,
        ino: m.ino,
        nlink: m.nlink,
        mode: m.mode,
        uid: c.uid_out(m.uid),
        gid: c.gid_out(m.gid),
        _pad0: 0,
        rdev: m.rdev,
        size: m.size as i64,
        blksize: 4096,
        blocks: m.blocks() as i64,
        atime: m.atime,
        mtime: m.mtime,
        ctime: m.ctime,
        _unused: [0; 3],
    }
}

fn stat_target(dirfd: i32, path: u64, flags: u64) -> core::result::Result<Metadata, Errno> {
    stat_at(dirfd, &user_path(path)?, flags & AT_SYMLINK_NOFOLLOW == 0, flags & AT_EMPTY_PATH != 0)
}

/// The metadata of `path`; with `empty_path`, an empty path means the
/// descriptor `dirfd` itself.
pub(crate) fn stat_at(dirfd: i32, path: &str, follow: bool, empty_path: bool) -> core::result::Result<Metadata, Errno> {
    let p = me()?;
    if path.is_empty() {
        if empty_path {
            // The table's lock is let go before the file is asked: a
            // file's stat may read this table itself (/proc's do), and
            // the lock masks interrupts (ADR 0115: Firefox hung here).
            let f = p.files.lock().get(dirfd)?;
            return f.stat();
        }
        return Err(ENOENT);
    }
    let d = vfs::resolve(&dir_for(&p, dirfd, path)?, path, follow)?;
    let mut m = d.metadata();
    // A terminal's node shows when the terminal was last read and
    // written (the console's nodes are on /dev's file system).
    if m.file_type() == vfs::FileType::CharDevice
        && let Some((atime, mtime)) = crate::fs::tty::times_of(m.rdev)
    {
        (m.atime, m.mtime) = (atime, mtime);
    }
    Ok(m)
}

/// The file a chmod/chown/utimes-style call acts on: `path` from `dirfd`,
/// or with `empty_path` and an empty path the descriptor itself (`None`
/// for a file with no name, such as a pipe).
pub(crate) fn path_target(
    dirfd: i32,
    path: &str,
    follow: bool,
    empty_path: bool,
) -> core::result::Result<Option<Arc<Dentry>>, Errno> {
    let p = me()?;
    if path.is_empty() {
        if empty_path {
            return Ok(p.files.lock().get(dirfd)?.dentry());
        }
        return Err(ENOENT);
    }
    vfs::resolve(&dir_for(&p, dirfd, path)?, path, follow).map(Some)
}

pub fn newfstatat(a: Args) -> Result {
    let m = stat_target(a.fd(0), a.0[1], a.0[3])?;
    write_user(a.0[2], &to_stat(&m)).map_err(|_| EFAULT)?;
    Ok(0)
}

pub fn stat(a: Args) -> Result {
    newfstatat(Args([AT_FDCWD as u64, a.0[0], a.0[1], 0, 0, 0]))
}

pub fn lstat(a: Args) -> Result {
    newfstatat(Args([AT_FDCWD as u64, a.0[0], a.0[1], AT_SYMLINK_NOFOLLOW, 0, 0]))
}

pub fn fstat(a: Args) -> Result {
    let m = file(a.fd(0))?.stat()?;
    write_user(a.0[1], &to_stat(&m)).map_err(|_| EFAULT)?;
    Ok(0)
}

/// `struct statx` (statx(2)).
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Statx {
    mask: u32,
    blksize: u32,
    attributes: u64,
    nlink: u32,
    uid: u32,
    gid: u32,
    mode: u16,
    _spare0: u16,
    ino: u64,
    size: u64,
    blocks: u64,
    attributes_mask: u64,
    atime: StatxTime,
    btime: StatxTime,
    ctime: StatxTime,
    mtime: StatxTime,
    rdev_major: u32,
    rdev_minor: u32,
    dev_major: u32,
    dev_minor: u32,
    mnt_id: u64,
    /// STATX_DIOALIGN: O_DIRECT's alignment of buffers and of offsets
    /// (0: no direct I/O).
    dio_mem_align: u32,
    dio_offset_align: u32,
    _spare: [u64; 12],
}

/// statx(2)'s STATX_DIOALIGN (`<linux/stat.h>` per the manual page).
const STATX_DIOALIGN: u32 = 0x2000;

/// O_DIRECT's alignment for what statx(2) asked about (ADR 0162): a
/// block device's sectors, a file system's own (`Inode::direct_align`),
/// else none.
fn dio_align(dirfd: i32, path: &str, follow: bool, empty_path: bool) -> u32 {
    let d = if path.is_empty() && empty_path {
        me().ok().and_then(|p| p.files.lock().get(dirfd).ok()).and_then(|f| f.dentry())
    } else {
        me().ok().and_then(|p| vfs::resolve(&dir_for(&p, dirfd, path).ok()?, path, follow).ok())
    };
    let Some(d) = d else { return 0 };
    match d.metadata().file_type() {
        vfs::FileType::BlockDevice => 512,
        vfs::FileType::Regular => d.inode.direct_align().unwrap_or(0),
        _ => 0,
    }
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct StatxTime {
    sec: i64,
    nsec: u32,
    _reserved: i32,
}

const _: () = assert!(size_of::<Statx>() == 256);

pub fn statx(a: Args) -> Result {
    let m = stat_target(a.fd(0), a.0[1], a.0[2])?;
    let (path, flags) = (user_path(a.0[1])?, a.0[2]);
    let dio = if a.0[3] as u32 & STATX_DIOALIGN != 0 {
        dio_align(a.fd(0), &path, flags & AT_SYMLINK_NOFOLLOW == 0, flags & AT_EMPTY_PATH != 0)
    } else {
        0
    };
    let t = |ts: Timespec| StatxTime { sec: ts.sec, nsec: ts.nsec as u32, _reserved: 0 };
    let c = crate::proc::cred::current();
    let sx = Statx {
        // STATX_BASIC_STATS, and STATX_DIOALIGN when asked for.
        mask: 0x7FF | if a.0[3] as u32 & STATX_DIOALIGN != 0 { STATX_DIOALIGN } else { 0 },
        dio_mem_align: dio,
        dio_offset_align: dio,
        blksize: 4096,
        nlink: m.nlink as u32,
        uid: c.uid_out(m.uid),
        gid: c.gid_out(m.gid),
        mode: m.mode as u16,
        ino: m.ino,
        size: m.size,
        blocks: m.blocks(),
        atime: t(m.atime),
        btime: t(m.ctime),
        ctime: t(m.ctime),
        mtime: t(m.mtime),
        rdev_major: vfs::major(m.rdev),
        rdev_minor: vfs::minor(m.rdev),
        dev_major: vfs::major(m.dev),
        dev_minor: vfs::minor(m.dev),
        ..Default::default()
    };
    write_user(a.0[4], &sx).map_err(|_| EFAULT)?;
    Ok(0)
}

/// faccessat(2)/faccessat2(2): the check uses the real IDs unless
/// AT_EACCESS. `flags` is 0 for plain faccessat, which has no flags
/// argument.
fn do_faccessat(dirfd: i32, path: u64, mode: u64, flags: u64) -> Result {
    access_at(dirfd, &user_path(path)?, mode as u32, flags & AT_EACCESS != 0, flags & AT_SYMLINK_NOFOLLOW != 0)
}

pub(crate) fn access_at(dirfd: i32, path: &str, mode: u32, effective: bool, nofollow: bool) -> Result {
    let p = me()?;
    let cred = p.cred();
    let c = if effective { (*cred).clone() } else { cred.for_access() };
    // The directories on the way are searched as the checked IDs too.
    let d = p.with_cred(c.clone(), || path_target(dirfd, path, !nofollow, false))?.ok_or(ENOENT)?;
    let m = d.metadata();
    let want = mode & 7;
    if want == 0 {
        return Ok(0);
    }
    c.permission(&m, want)?;
    let kind = m.file_type();
    // Writing to a file on a read-only file system (access(2): EROFS;
    // devices, FIFOs and sockets are not files of the file system);
    // running a program from a noexec mount (as execve(2) refuses it).
    if want & 2 != 0 && matches!(kind, FileType::Regular | FileType::Directory | FileType::Symlink) {
        vfs::writable(&d)?;
    }
    if want & 1 != 0 && kind == FileType::Regular && vfs::mount_flags(&d) & vfs::MNT_NOEXEC != 0 {
        return Err(EACCES);
    }
    Ok(0)
}

pub fn faccessat(a: Args) -> Result {
    do_faccessat(a.fd(0), a.0[1], a.0[2], 0)
}

pub fn faccessat2(a: Args) -> Result {
    do_faccessat(a.fd(0), a.0[1], a.0[2], a.0[3])
}

pub fn access(a: Args) -> Result {
    do_faccessat(AT_FDCWD, a.0[0], a.0[1], 0)
}

// --- attributes ---------------------------------------------------------

/// chmod on a resolved file: the owner (or CAP_FOWNER) only; without
/// CAP_FSETID the set-group-ID bit needs membership of the file's group
/// (chmod(2)).
pub(crate) fn do_chmod(d: &Arc<Dentry>, mode: u32) -> Result {
    vfs::writable(d)?;
    let cred = crate::proc::cred::current();
    let m = d.metadata();
    if !cred.owns(&m) {
        return Err(EPERM);
    }
    let mut mode = mode & 0o7777;
    if mode & S_ISGID != 0 && !cred.in_group(m.gid) && !cred.capable_wrt(&m, CAP_FSETID) {
        mode &= !S_ISGID;
    }
    d.inode.set_mode(mode)?;
    inotify::report_self(d, inotify::IN_ATTRIB);
    Ok(0)
}

pub fn fchmodat(a: Args) -> Result {
    let p = me()?;
    let path = user_path(a.0[1])?;
    let d = vfs::resolve(&dir_for(&p, a.fd(0), &path)?, &path, true)?;
    do_chmod(&d, a.0[2] as u32)
}

pub fn chmod(a: Args) -> Result {
    fchmodat(Args([AT_FDCWD as u64, a.0[0], a.0[1], 0, 0, 0]))
}

/// fchmod(2). Files with no name (sockets, pipes) have no mode kept
/// apart from their type: the call succeeds and changes nothing.
pub fn fchmod(a: Args) -> Result {
    match file(a.fd(0))?.dentry() {
        Some(d) => do_chmod(&d, a.0[1] as u32),
        None => Ok(0),
    }
}

/// A chown ID argument: None for -1, else the kernel ID it names in the
/// caller's user namespace (EINVAL if unmapped).
fn id_arg(
    v: u64,
    to_kernel: impl Fn(u32) -> core::result::Result<u32, Errno>,
) -> core::result::Result<Option<u32>, Errno> {
    (v as u32 != u32::MAX).then(|| to_kernel(v as u32)).transpose()
}

/// chown on a resolved file (chown(2)): changing the owner needs
/// CAP_CHOWN; the owner may change the group to one of their groups. A
/// change to a non-directory clears its set-user-ID bit, and its
/// set-group-ID bit if it is group-executable.
pub(crate) fn do_chown(d: &Arc<Dentry>, uid: u64, gid: u64) -> Result {
    vfs::writable(d)?;
    let cred = crate::proc::cred::current();
    let (uid, gid) = (id_arg(uid, |u| cred.uid_in(u))?, id_arg(gid, |g| cred.gid_in(g))?);
    let m = d.metadata();
    // An owner or group named (even the same one) clears the set-ID bits
    // of a non-directory (chown(2)).
    let named = uid.is_some() || gid.is_some();
    let uid = uid.filter(|&u| u != m.uid);
    let gid = gid.filter(|&g| g != m.gid);
    let privileged = cred.capable_wrt(&m, CAP_CHOWN);
    if uid.is_some() && !privileged {
        return Err(EPERM);
    }
    if let Some(g) = gid
        && !privileged
        && (cred.fsuid != m.uid || !cred.in_group(g))
    {
        return Err(EPERM);
    }
    if uid.is_none() && gid.is_none() {
        // Nothing to change, but the caller must still be allowed to.
        if !privileged && cred.fsuid != m.uid {
            return Err(EPERM);
        }
    } else {
        d.inode.set_owner(uid, gid)?;
    }
    if named && m.file_type() != FileType::Directory && m.mode & (S_ISUID | S_ISGID) != 0 {
        let mut mode = m.mode & 0o7777 & !S_ISUID;
        if m.mode & 0o010 != 0 {
            mode &= !S_ISGID;
        }
        let _ = d.inode.set_mode(mode);
    }
    inotify::report_self(d, inotify::IN_ATTRIB);
    Ok(0)
}

pub fn fchownat(a: Args) -> Result {
    let p = me()?;
    let path = user_path(a.0[1])?;
    // AT_EMPTY_PATH: the descriptor itself.
    if path.is_empty() && a.0[4] & 0x1000 != 0 {
        return fchown(Args([a.0[0], a.0[2], a.0[3], 0, 0, 0]));
    }
    let d = vfs::resolve(&dir_for(&p, a.fd(0), &path)?, &path, a.0[4] & AT_SYMLINK_NOFOLLOW == 0)?;
    do_chown(&d, a.0[2], a.0[3])
}

pub fn chown(a: Args) -> Result {
    fchownat(Args([AT_FDCWD as u64, a.0[0], a.0[1], a.0[2], 0, 0]))
}

pub fn lchown(a: Args) -> Result {
    fchownat(Args([AT_FDCWD as u64, a.0[0], a.0[1], a.0[2], AT_SYMLINK_NOFOLLOW, 0]))
}

/// fchown(2); like fchmod, a no-op on files with no name.
pub fn fchown(a: Args) -> Result {
    match file(a.fd(0))?.dentry() {
        Some(d) => do_chown(&d, a.0[1], a.0[2]),
        None => Ok(0),
    }
}

pub fn umask(a: Args) -> Result {
    Ok(u64::from(me()?.set_umask(a.0[0] as u32 & 0o777)))
}

pub fn truncate(a: Args) -> Result {
    let p = me()?;
    let path = user_path(a.0[0])?;
    let d = vfs::resolve(&p.cwd(), &path, true)?;
    if d.is_dir() {
        return Err(EISDIR);
    }
    vfs::writable(&d)?;
    p.cred().permission(&d.metadata(), MAY_WRITE)?;
    if (a.0[1] as i64) < 0 {
        return Err(EINVAL);
    }
    crate::proc::rlimit::file_size_limit(a.0[1], a.0[1])?;
    d.inode.truncate(a.0[1])?;
    fs::pagecache::truncated(&d.inode, a.0[1]);
    fs::drop_set_ids(&d.inode);
    inotify::report_self(&d, inotify::IN_MODIFY);
    Ok(0)
}

// fallocate(2) modes. Source: musl `fcntl.h`.
const FALLOC_FL_KEEP_SIZE: u64 = 1;
const FALLOC_FL_PUNCH_HOLE: u64 = 2;

/// fallocate(2): space isn't reserved ahead (files grow as written), so
/// mode 0 only extends the size and FALLOC_FL_KEEP_SIZE does nothing.
/// FALLOC_FL_PUNCH_HOLE (with KEEP_SIZE, as the man page requires) works
/// where the file system supports it (tmpfs); collapsing, inserting and
/// zeroing ranges aren't supported (EOPNOTSUPP).
pub fn fallocate(a: Args) -> Result {
    let f = file(a.fd(0))?;
    let (mode, offset, len) = (a.0[1], a.0[2] as i64, a.0[3] as i64);
    if offset < 0 || len <= 0 {
        return Err(EINVAL);
    }
    if f.status_flags() & fs::O_ACCMODE == fs::O_RDONLY {
        return Err(EBADF);
    }
    let end = offset.checked_add(len).ok_or(EFBIG)? as u64;
    match mode {
        0 => {
            let m = f.stat()?;
            if m.file_type() != vfs::FileType::Regular {
                return Err(ENODEV);
            }
            if m.size < end {
                crate::proc::rlimit::file_size_limit(m.size, end)
                    .and_then(|e| if e < end { Err(EFBIG) } else { Ok(e) })?;
                f.truncate(end)?;
            }
            if let Some(d) = f.dentry() {
                fs::drop_set_ids(&d.inode);
            }
            Ok(0)
        }
        FALLOC_FL_KEEP_SIZE => Ok(0),
        m if m == FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE => {
            let d = f.dentry().ok_or(ENODEV)?;
            d.inode.punch_hole(offset as u64, len as u64)?;
            fs::drop_set_ids(&d.inode);
            Ok(0)
        }
        FALLOC_FL_PUNCH_HOLE => Err(EINVAL),
        _ => Err(EOPNOTSUPP),
    }
}

pub fn ftruncate(a: Args) -> Result {
    let f = file(a.fd(0))?;
    // ftruncate(2): a negative length, or a file that is not a regular
    // one, is EINVAL.
    if (a.0[1] as i64) < 0 || f.stat()?.file_type() != vfs::FileType::Regular {
        return Err(EINVAL);
    }
    crate::proc::rlimit::file_size_limit(a.0[1], a.0[1])?;
    f.truncate(a.0[1])?;
    if let Some(d) = f.dentry().filter(|_| inotify::active()) {
        inotify::report_self(&d, inotify::IN_MODIFY);
    }
    Ok(0)
}

pub fn utimensat(a: Args) -> Result {
    let p = me()?;
    let d = if a.0[1] == 0 {
        p.files.lock().get(a.fd(0))?.dentry().ok_or(EINVAL)?
    } else {
        let path = user_path(a.0[1])?;
        vfs::resolve(&dir_for(&p, a.fd(0), &path)?, &path, a.0[3] & AT_SYMLINK_NOFOLLOW == 0)?
    };
    let times = if a.0[2] == 0 { None } else { Some(read_user::<[Timespec; 2]>(a.0[2]).map_err(|_| EFAULT)?) };
    set_times(&d, times)
}

/// Set access and modification times; `None` means both now, and a time
/// whose nsec is UTIME_NOW or UTIME_OMIT means now or unchanged.
pub(crate) fn set_times(d: &Arc<Dentry>, times: Option<[Timespec; 2]>) -> Result {
    let now = Timespec::now();
    let (at, mt) = match times {
        None => (Some(now), Some(now)),
        Some(ts) => {
            let pick = |t: Timespec| match t.nsec {
                UTIME_NOW => Some(now),
                UTIME_OMIT => None,
                _ => Some(t),
            };
            (pick(ts[0]), pick(ts[1]))
        }
    };
    // Explicit times need ownership; "now" also write permission
    // (utimensat(2)).
    let cred = me()?.cred();
    let m = d.metadata();
    let explicit = times.is_some_and(|ts| ts.iter().any(|t| t.nsec != UTIME_NOW && t.nsec != UTIME_OMIT));
    if !cred.owns(&m) && (explicit || cred.permission(&m, MAY_WRITE).is_err()) {
        return Err(if explicit { EPERM } else { EACCES });
    }
    vfs::writable(d)?;
    d.inode.set_times(at, mt)?;
    inotify::report_self(d, inotify::IN_ATTRIB);
    Ok(0)
}

// --- descriptors --------------------------------------------------------

pub fn dup(a: Args) -> Result {
    let p = me()?;
    let mut t = p.files.lock();
    let f = t.get(a.fd(0))?;
    Ok(t.insert(f, false)? as u64)
}

pub fn dup3(a: Args) -> Result {
    let (old, new) = (a.fd(0), a.fd(1));
    // dup3(2): flags other than O_CLOEXEC, or the same descriptor twice,
    // are EINVAL (before the descriptors are looked at).
    if old == new || a.0[2] & !u64::from(fs::O_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    let p = me()?;
    let mut t = p.files.lock();
    let f = t.get(old)?;
    Ok(t.insert_at(new, f, a.0[2] & u64::from(fs::O_CLOEXEC) != 0)? as u64)
}

pub fn dup2(a: Args) -> Result {
    let (old, new) = (a.fd(0), a.fd(1));
    if old == new {
        file(old)?;
        return Ok(new as u64);
    }
    dup3(Args([a.0[0], a.0[1], 0, 0, 0, 0]))
}

// memfd_create(2) flags. Source: musl `sys/mman.h`.
const MFD_CLOEXEC: u64 = 1;
const MFD_ALLOW_SEALING: u64 = 2;
const MFD_HUGETLB: u64 = 4;
const MFD_NOEXEC_SEAL: u64 = 8;
const MFD_EXEC: u64 = 0x10;

/// memfd_create(2): an anonymous tmpfs file. Executable unless
/// MFD_NOEXEC_SEAL; sealable only with MFD_ALLOW_SEALING. Huge pages are
/// not supported (EINVAL).
pub fn memfd_create(a: Args) -> Result {
    let p = me()?;
    let flags = a.0[1];
    if flags & !(MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL | MFD_EXEC) != 0
        || flags & MFD_HUGETLB != 0
        || flags & (MFD_EXEC | MFD_NOEXEC_SEAL) == (MFD_EXEC | MFD_NOEXEC_SEAL)
    {
        return Err(EINVAL);
    }
    let name = user_path(a.0[0])?;
    if name.len() > 249 {
        return Err(EINVAL); // NAME_MAX minus the "memfd:" prefix.
    }
    use fs::tmpfs::{F_SEAL_EXEC, F_SEAL_SEAL};
    let (mode, mut seals) = if flags & MFD_NOEXEC_SEAL != 0 { (0o666, F_SEAL_EXEC) } else { (0o777, 0) };
    if flags & (MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL) == 0 {
        seals |= F_SEAL_SEAL;
    }
    let inode: Arc<dyn vfs::Inode> = fs::tmpfs::TmpFs::memfd(mode, seals);
    let cred = p.cred();
    inode.set_owner(Some(cred.fsuid), Some(cred.fsgid))?;
    let d = vfs::anon_dentry(&alloc::format!("memfd:{name}"), inode, "tmpfs");
    let f: Arc<dyn File> = Arc::new(fs::OpenFile::new(d, fs::O_RDWR));
    Ok(p.files.lock().insert(f, flags & MFD_CLOEXEC != 0)? as u64)
}

// fcntl(2) seal and pipe-size commands. Source: musl `fcntl.h`.
const F_ADD_SEALS: u64 = 1033;
const F_GET_SEALS: u64 = 1034;
const F_SETPIPE_SZ: u64 = 1031;
const F_GETPIPE_SZ: u64 = 1032;
/// Every pipe's fixed capacity.
const PIPE_CAPACITY: u64 = fs::pipe::CAPACITY as u64;

pub fn fcntl(a: Args) -> Result {
    let p = me()?;
    let fd = a.fd(0);
    let mut t = p.files.lock();
    match a.0[1] {
        // Pipes keep their 64 KiB: asking for that or less is fine, more is
        // refused as for an unprivileged caller (fcntl(2) EPERM).
        F_GETPIPE_SZ => {
            t.get(fd)?;
            Ok(PIPE_CAPACITY)
        }
        F_SETPIPE_SZ => {
            t.get(fd)?;
            if a.0[2] <= PIPE_CAPACITY { Ok(PIPE_CAPACITY) } else { Err(EPERM) }
        }
        F_GET_SEALS => {
            let d = t.get(fd)?.dentry().ok_or(EINVAL)?;
            Ok(u64::from(d.inode.seals().ok_or(EINVAL)?.load(Ordering::Acquire)))
        }
        // Adding seals needs a writable descriptor and no F_SEAL_SEAL.
        F_ADD_SEALS => {
            let f = t.get(fd)?;
            drop(t);
            let d = f.dentry().ok_or(EINVAL)?;
            let seals = d.inode.seals().ok_or(EINVAL)?;
            let add = a.0[2] as u32;
            if add & !0x3F != 0 {
                return Err(EINVAL);
            }
            if f.status_flags() & fs::O_ACCMODE == fs::O_RDONLY {
                return Err(EPERM);
            }
            if seals.load(Ordering::Acquire) & fs::tmpfs::F_SEAL_SEAL != 0 {
                return Err(EPERM);
            }
            let before = seals.fetch_or(add, Ordering::SeqCst);
            // F_SEAL_WRITE while the file is mapped shared and writable is
            // EBUSY (memfd_create(2)). Sealed first, then looked for: an
            // mmap or mprotect checks the seal where the mapping changes.
            if add & fs::tmpfs::F_SEAL_WRITE != 0 && crate::proc::mapped_writable(&d.inode) {
                seals.fetch_and(!(add & !before), Ordering::SeqCst);
                return Err(EBUSY);
            }
            Ok(0)
        }
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let f = t.get(fd)?;
            Ok(t.insert_from(a.0[2] as usize, f, a.0[1] == F_DUPFD_CLOEXEC)? as u64)
        }
        F_GETFD => Ok(if t.cloexec(fd)? { FD_CLOEXEC } else { 0 }),
        F_SETFD => {
            t.set_cloexec(fd, a.0[2] & FD_CLOEXEC != 0)?;
            Ok(0)
        }
        F_GETFL => Ok(u64::from(t.get(fd)?.status_flags())),
        F_SETFL => {
            t.get(fd)?.set_status_flags(a.0[2] as u32);
            Ok(0)
        }
        // Record locks (fs/locks.rs), with the descriptor table unlocked:
        // F_SETLKW may sleep.
        F_GETLK | F_OFD_GETLK | F_SETLK | F_SETLKW | F_OFD_SETLK | F_OFD_SETLKW => {
            let f = t.get(fd)?;
            drop(t);
            record_lock(&f, a.0[1], a.0[2])
        }
        _ => Err(EINVAL),
    }
}

pub fn pipe2(a: Args) -> Result {
    let flags = a.0[1] as u32;
    let (r, w) = fs::pipe::new(flags);
    let p = me()?;
    let cloexec = flags & fs::O_CLOEXEC != 0;
    let (rfd, wfd) = {
        let mut t = p.files.lock();
        let rfd = t.insert(r, cloexec)?;
        match t.insert(w, cloexec) {
            Ok(wfd) => (rfd, wfd),
            Err(e) => {
                let _ = t.close(rfd);
                return Err(e);
            }
        }
    };
    if write_user(a.0[0], &[rfd, wfd]).is_err() {
        let mut t = p.files.lock();
        let _ = t.close(rfd);
        let _ = t.close(wfd);
        return Err(EFAULT);
    }
    Ok(0)
}

pub fn pipe(a: Args) -> Result {
    pipe2(Args([a.0[0], 0, 0, 0, 0, 0]))
}

pub fn fsync(a: Args) -> Result {
    let f = file(a.fd(0))?;
    match f.dentry() {
        Some(d) => d.inode.sync()?,
        // fsync(2): EINVAL for a pipe or a socket (nothing to sync).
        None if f.stat().is_ok_and(|m| matches!(m.file_type(), vfs::FileType::Fifo | vfs::FileType::Socket)) => {
            return Err(EINVAL);
        }
        None => {}
    }
    Ok(0)
}

/// flock(2) (fs/locks.rs).
pub fn flock(a: Args) -> Result {
    let f = file(a.fd(0))?;
    fs::locks::flock(&f, a.0[1] as u32)?;
    Ok(0)
}

/// fcntl(2) record locks: F_GETLK, F_SETLK, F_SETLKW and the OFD forms,
/// with a `struct flock` at `arg`.
fn record_lock(f: &Arc<dyn File>, cmd: u64, arg: u64) -> Result {
    use fs::locks::{self, Family, FlockArg};
    let mut l: FlockArg = read_user(arg).map_err(|_| EFAULT)?;
    let family = if matches!(cmd, F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW) { Family::Ofd } else { Family::Posix };
    match cmd {
        F_GETLK | F_OFD_GETLK => {
            locks::getlk(f, family, &mut l)?;
            write_user(arg, &l).map_err(|_| EFAULT)?;
        }
        _ => {
            let mode = f.status_flags() & fs::O_ACCMODE;
            let wait = matches!(cmd, F_SETLKW | F_OFD_SETLKW);
            locks::setlk(f, family, &l, wait, mode != fs::O_WRONLY, mode != fs::O_RDONLY)?;
        }
    }
    Ok(0)
}

pub fn sync(_a: Args) -> Result {
    fs::sync_all();
    Ok(0)
}

/// syncfs(2): every file system is synced (as sync(2)).
pub fn syncfs(a: Args) -> Result {
    file(a.fd(0))?;
    fs::sync_all();
    Ok(0)
}

// sync_file_range(2) flags. Source: man-pages sync_file_range(2).
const SYNC_FILE_RANGE_WAIT_BEFORE: u64 = 1;
const SYNC_FILE_RANGE_WRITE: u64 = 2;
const SYNC_FILE_RANGE_WAIT_AFTER: u64 = 4;

/// sync_file_range(2): any flag syncs the whole file (more than asked).
pub fn sync_file_range(a: Args) -> Result {
    let [_, offset, nbytes, flags, ..] = a.0;
    let all = SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
    if flags & !all != 0 || (offset as i64) < 0 || (nbytes as i64) < 0 {
        return Err(EINVAL);
    }
    let f = file(a.fd(0))?;
    if flags != 0
        && let Some(d) = f.dentry()
    {
        if !matches!(d.metadata().file_type(), FileType::Regular | FileType::BlockDevice) {
            return Err(ESPIPE);
        }
        d.inode.sync()?;
    }
    Ok(0)
}

// --- poll/select --------------------------------------------------------

/// `struct pollfd` (poll(2)).
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

pub(crate) fn deadline_from_timespec(addr: u64) -> core::result::Result<Option<u64>, Errno> {
    if addr == 0 {
        return Ok(None);
    }
    let ts: Timespec = read_user(addr).map_err(|_| EFAULT)?;
    if ts.sec < 0 || !(0..1_000_000_000).contains(&ts.nsec) {
        return Err(EINVAL);
    }
    let ns = (ts.sec as u64).saturating_mul(1_000_000_000).saturating_add(ts.nsec as u64);
    Ok(Some(crate::time::monotonic_ns().saturating_add(ns)))
}

fn do_poll(fds_addr: u64, nfds: u64, deadline: Option<u64>) -> Result {
    let p = me()?;
    // poll(2): EINVAL past RLIMIT_NOFILE.
    if nfds > p.files.lock().limit().max(fs::MAX_FDS) as u64 {
        return Err(EINVAL);
    }
    let mut fds: Vec<PollFd> = (0..nfds)
        .map(|i| read_user::<PollFd>(fds_addr + i * 8).map_err(|_| EFAULT))
        .collect::<core::result::Result<_, _>>()?;
    loop {
        let seen = poll_generation();
        let mut ready = 0;
        for pf in fds.iter_mut() {
            pf.revents = 0;
            if pf.fd < 0 {
                continue;
            }
            let r = match p.files.lock().get(pf.fd) {
                Ok(f) => f.poll(),
                Err(_) => fs::POLLNVAL,
            };
            let mask = (pf.events as u16) | fs::POLLERR | fs::POLLHUP | fs::POLLNVAL;
            pf.revents = (r & mask) as i16;
            if pf.revents != 0 {
                ready += 1;
            }
        }
        let expired = deadline.is_some_and(|d| crate::time::monotonic_ns() >= d);
        if ready > 0 || expired {
            for (i, pf) in fds.iter().enumerate() {
                write_user(fds_addr + i as u64 * 8, pf).map_err(|_| EFAULT)?;
            }
            return Ok(ready);
        }
        match poll_wait(seen, deadline) {
            WaitResult::Interrupted => return Err(EINTR),
            WaitResult::TimedOut | WaitResult::Ready => {}
        }
    }
}

pub fn poll(a: Args) -> Result {
    let t = a.0[2] as i32;
    let deadline = if t < 0 { None } else { Some(crate::time::monotonic_ns() + t as u64 * 1_000_000) };
    do_poll(a.0[0], a.0[1], deadline)
}

/// ppoll(2): poll with a timespec timeout and a signal mask in effect
/// while waiting (a.0[3], with a.0[4] its size).
pub fn ppoll(a: Args) -> Result {
    let deadline = deadline_from_timespec(a.0[2])?;
    with_sigmask(a.0[3], || do_poll(a.0[0], a.0[1], deadline))
}

fn do_select(n: u64, rd: u64, wr: u64, ex: u64, deadline: Option<u64>) -> Result {
    // select(2): a negative nfds is EINVAL.
    if (n as i32) < 0 {
        return Err(EINVAL);
    }
    let n = n.min(me()?.files.lock().limit().max(fs::MAX_FDS) as u64) as usize;
    let words = n.div_ceil(64);
    let load = |addr: u64| -> core::result::Result<Vec<u64>, Errno> {
        if addr == 0 {
            return Ok(vec![0; words]);
        }
        (0..words).map(|i| read_user::<u64>(addr + i as u64 * 8).map_err(|_| EFAULT)).collect()
    };
    let (rin, win, _ein) = (load(rd)?, load(wr)?, load(ex)?);
    let p = me()?;
    loop {
        let seen = poll_generation();
        let (mut rout, mut wout) = (vec![0u64; words], vec![0u64; words]);
        let mut ready = 0;
        for fd in 0..n {
            let (w, b) = (fd / 64, 1u64 << (fd % 64));
            if (rin[w] | win[w]) & b == 0 {
                continue;
            }
            let r = p.files.lock().get(fd as i32).map_err(|_| EBADF)?.poll();
            if rin[w] & b != 0 && r & (fs::POLLIN | fs::POLLHUP | fs::POLLERR) != 0 {
                rout[w] |= b;
                ready += 1;
            }
            if win[w] & b != 0 && r & (fs::POLLOUT | fs::POLLERR) != 0 {
                wout[w] |= b;
                ready += 1;
            }
        }
        let expired = deadline.is_some_and(|d| crate::time::monotonic_ns() >= d);
        if ready > 0 || expired {
            let store = |addr: u64, v: &[u64]| -> core::result::Result<(), Errno> {
                if addr != 0 {
                    for (i, w) in v.iter().enumerate() {
                        write_user(addr + i as u64 * 8, w).map_err(|_| EFAULT)?;
                    }
                }
                Ok(())
            };
            store(rd, &rout)?;
            store(wr, &wout)?;
            store(ex, &vec![0; words])?;
            return Ok(ready);
        }
        if poll_wait(seen, deadline) == WaitResult::Interrupted {
            return Err(EINTR);
        }
    }
}

/// `struct timeval`.
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Timeval {
    sec: i64,
    usec: i64,
}

pub fn select(a: Args) -> Result {
    let deadline = if a.0[4] == 0 {
        None
    } else {
        let tv: Timeval = read_user(a.0[4]).map_err(|_| EFAULT)?;
        let ns = (tv.sec.max(0) as u64).saturating_mul(1_000_000_000).saturating_add(tv.usec.max(0) as u64 * 1000);
        Some(crate::time::monotonic_ns().saturating_add(ns))
    };
    do_select(a.0[0], a.0[1], a.0[2], a.0[3], deadline)
}

/// pselect6: the raw system call behind pselect(3). Its sixth argument
/// points to `{ const sigset_t *ss; size_t ss_len; }` (select(2) "C
/// library/kernel differences"); the mask applies while waiting.
pub fn pselect6(a: Args) -> Result {
    let deadline = deadline_from_timespec(a.0[4])?;
    let mask_addr = if a.0[5] == 0 { 0 } else { read_user::<u64>(a.0[5]).map_err(|_| EFAULT)? };
    with_sigmask(mask_addr, || do_select(a.0[0], a.0[1], a.0[2], a.0[3], deadline))
}

// --- mounts and file systems --------------------------------------------

/// CAP_SYS_ADMIN over the caller's mount namespace: in the user namespace
/// that owns it (user_namespaces(7)).
fn mount_capable(p: &proc::Process) -> bool {
    p.cred().ns_capable(&p.namespaces().mnt.owner, crate::proc::cred::CAP_SYS_ADMIN)
}

// mount(2) flags. Source: musl `sys/mount.h`.
pub(crate) const MS_REMOUNT: u64 = 32;
pub(crate) const MS_BIND: u64 = 4096;
const MS_MOVE: u64 = 8192;
pub(crate) const MS_REC: u64 = 16384;
const MS_PROPAGATION: u64 = (1 << 17) | (1 << 18) | (1 << 19) | (1 << 20);
const MS_NOSUID: u64 = 2;
const MS_NODEV: u64 = 4;
const MS_NOEXEC: u64 = 8;
const MS_SILENT: u64 = 32768;
/// MS_SYNCHRONOUS (16), MS_MANDLOCK (64) and MS_DIRSYNC (128).
const MS_SYNC_FLAGS: u64 = 16 | 64 | 128;
/// MS_NOATIME (1024), MS_NODIRATIME (2048), MS_RELATIME (1 << 21) and
/// MS_STRICTATIME (1 << 24): the mount's own (`vfs::MNT_NOATIME` and the
/// others have their values).
const MS_ATIME_FLAGS: u64 = 1024 | 2048 | (1 << 21) | (1 << 24);
/// MS_SYNC_FLAGS, the access-time flags and MS_LAZYTIME (1 << 25).
const MS_ATIME_SYNC: u64 = MS_SYNC_FLAGS | MS_ATIME_FLAGS | (1 << 25);

pub fn mount(a: Args) -> Result {
    let target = user_path(a.0[1])?;
    let fstype = if a.0[2] != 0 { user_path(a.0[2])? } else { String::new() };
    // The source is shown in /proc/mounts: a device path, or any name.
    let source = if a.0[0] != 0 { user_path(a.0[0])? } else { String::from("none") };
    let data = || if a.0[4] != 0 { user_path(a.0[4]) } else { Ok(String::new()) };
    mount_at(&source, &target, &fstype, a.0[3], &data)
}

/// mount(2) with the strings already read; `data` reads the file-system
/// options when a file system wants them.
pub(crate) fn mount_at(
    source: &str,
    target: &str,
    fstype: &str,
    flags: u64,
    data: &dyn Fn() -> core::result::Result<String, Errno>,
) -> Result {
    // A confined app may not change what paths mean (ADR 0130).
    crate::proc::apps::unconfined()?;
    let p = me()?;
    if !mount_capable(&p) {
        return Err(EPERM);
    }
    let at = vfs::resolve(&p.cwd(), target, true)?;
    if !crate::proc::domain::may_change_mounts(&at) {
        return Err(EPERM);
    }
    // Remounting sets the mount's flags, in the caller's namespace only;
    // flags not given are cleared (mount(2)). With MS_BIND only the
    // mount's own flags change, which are all Slate's file systems have.
    // The access-time flags are the mount's (ADR 0162; MS_LAZYTIME is
    // accepted without effect); the sync flags ask for modes no file
    // system of Slate's has: they are accepted, and logged.
    let mount_flags = (flags & (MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_ATIME_FLAGS)) as u32 & vfs::MNT_FLAGS;
    if flags & MS_REMOUNT != 0 {
        if flags & !(MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_BIND | MS_SILENT | MS_ATIME_SYNC)
            != 0
        {
            crate::log::accepted_without_effect("mount(2): unknown remount flags");
        }
        if flags & MS_SYNC_FLAGS != 0 {
            crate::log::accepted_without_effect("mount(2): synchronous writes (no file system has them)");
        }
        vfs::remount(&at, mount_flags)?;
        return Ok(0);
    }
    if flags & MS_PROPAGATION != 0 && flags & (MS_BIND | MS_MOVE) == 0 {
        // Every mount is private (ADR 0028).
        crate::log::accepted_without_effect("mount(2): propagation (every mount is private)");
        return Ok(0);
    }
    if flags & (MS_BIND | MS_MOVE) != 0 {
        let src = vfs::resolve(&p.cwd(), source, true)?;
        if flags & MS_MOVE != 0 {
            vfs::bind(&src, &at, true)?;
            vfs::unmount(&src, true)?;
        } else {
            vfs::bind(&src, &at, flags & MS_REC != 0)?;
        }
        return Ok(0);
    }
    // Block devices and devtmpfs stay with the initial user namespace
    // (user_namespaces(7) lists the file systems a namespace may mount).
    if matches!(fstype, "devtmpfs" | "ext4" | "ext3" | "ext2" | "slatefs")
        && !p.cred().capable(crate::proc::cred::CAP_SYS_ADMIN)
    {
        return Err(EPERM);
    }
    let (inode, name): (Arc<dyn vfs::Inode>, &'static str) = match fstype {
        "tmpfs" | "ramfs" => {
            // tmpfs(5) options: mode= (default 1777), uid=, gid=, the size
            // and file limits (size=, nr_blocks=, nr_inodes=; half of RAM
            // without them). mpol= has one node to choose, noswap no swap
            // to keep from, and inode numbers already fit in 32 bits, so
            // those change nothing; huge= is accepted and logged (no huge
            // pages in tmpfs); others are refused, as Linux's tmpfs does.
            let data = data()?;
            let root = fs::tmpfs::TmpFs::new();
            let ram = crate::mm::frame::stats().usable_frames * 4096;
            let (blocks, inodes) = fs::tmpfs::size_options(data.split(','), ram).ok_or(EINVAL)?;
            root.limit(blocks, inodes);
            let mut mode = 0o1777;
            // The root belongs to the mounter (tmpfs(5): uid=/gid= default).
            let cred = p.cred();
            let (mut uid, mut gid) = (Some(cred.fsuid), Some(cred.fsgid));
            for o in data.split(',') {
                if let Some(m) = o.strip_prefix("mode=") {
                    mode = u32::from_str_radix(m, 8).map_err(|_| EINVAL)? & 0o7777;
                } else if let Some(u) = o.strip_prefix("uid=") {
                    uid = Some(cred.uid_in(u.parse().map_err(|_| EINVAL)?)?);
                } else if let Some(g) = o.strip_prefix("gid=") {
                    gid = Some(cred.gid_in(g.parse().map_err(|_| EINVAL)?)?);
                } else if ["size=", "nr_blocks=", "nr_inodes=", "mpol="].iter().any(|k| o.starts_with(k))
                    || matches!(o, "noswap" | "inode32" | "inode64")
                {
                } else if o.starts_with("huge=") {
                    crate::log::accepted_without_effect("tmpfs: huge-page option");
                } else if !o.is_empty() {
                    crate::log_warn!("tmpfs: unknown option {o:?}");
                    return Err(EINVAL);
                }
            }
            vfs::Inode::set_mode(&*root, mode)?;
            vfs::Inode::set_owner(&*root, uid, gid)?;
            (root, "tmpfs")
        }
        "proc" => (fs::procfs::new(), "proc"),
        "devtmpfs" => (fs::devfs_root(), "devtmpfs"),
        "devpts" => (fs::devpts::new(), "devpts"),
        "sysfs" => (fs::sysfs_root(), "sysfs"),
        "efivarfs" => (fs::efivarfs::new()?, "efivarfs"),
        "cgroup2" => (fs::cgroup::new(), "cgroup2"),
        // POSIX message queues are not implemented: an empty file system
        // for the mount point containers expect (ADR 0028).
        "mqueue" => (fs::tmpfs::TmpFs::with_magic(fs::tmpfs::MQUEUE_MAGIC), "mqueue"),
        "overlay" => {
            let data = data()?;
            let cwd = p.cwd();
            (fs::overlay::mount(&data, |path| vfs::resolve(&cwd, path, true))?, "overlay")
        }
        "ext4" | "ext3" | "ext2" => {
            let d = vfs::resolve(&p.cwd(), source, true)?;
            let meta = d.metadata();
            if meta.file_type() != vfs::FileType::BlockDevice {
                return Err(ENOTBLK);
            }
            let dev = crate::block::by_rdev(meta.rdev).ok_or(ENXIO)?;
            // The data argument: `discard` discards blocks as they are freed.
            let discard = data()?.split(',').any(|o| o == "discard");
            (fs::ext4::mount(dev, meta.rdev, flags & MS_RDONLY != 0, discard)?, "ext4")
        }
        "slatefs" => {
            let d = vfs::resolve(&p.cwd(), source, true)?;
            let meta = d.metadata();
            if meta.file_type() != vfs::FileType::BlockDevice {
                return Err(ENOTBLK);
            }
            let dev = crate::block::by_rdev(meta.rdev).ok_or(ENXIO)?;
            // The data argument: comma-separated options; `subvol=NAME` picks
            // the subvolume (ADR 0026), `discard` discards freed blocks.
            let data = data()?;
            let subvol = data.split(',').find_map(|o| o.strip_prefix("subvol="));
            let discard = data.split(',').any(|o| o == "discard");
            (fs::slatefs::mount(dev, meta.rdev, flags & MS_RDONLY != 0, subvol, discard)?, "slatefs")
        }
        _ => return Err(ENODEV),
    };
    vfs::mount(&at, inode, name, source, mount_flags)?;
    Ok(0)
}

// umount2(2) flags. Source: musl `sys/mount.h`.
const MNT_DETACH: u64 = 2;
const UMOUNT_NOFOLLOW: u64 = 8;

/// pivot_root(2): make `new_root` the root of the caller's mount namespace
/// and put the old root at `put_old`; processes whose root or working
/// directory was the old root move to the new one.
pub fn pivot_root(a: Args) -> Result {
    crate::proc::apps::unconfined()?;
    let p = me()?;
    if !mount_capable(&p) {
        return Err(EPERM);
    }
    let cwd = p.cwd();
    let new_root = vfs::resolve(&cwd, &user_path(a.0[0])?, true)?;
    let put_old = vfs::resolve(&cwd, &user_path(a.0[1])?, true)?;
    if !new_root.is_dir() || !put_old.is_dir() {
        return Err(ENOTDIR);
    }
    // The initial namespace's root stays put for Linux-domain processes.
    if crate::proc::domain::linux_caller() && p.mnt_ns_id() == 0 {
        return Err(EPERM);
    }
    let old_root = p.root_dir();
    vfs::pivot_root(&new_root, &put_old, &old_root)?;
    *p.namespaces().mnt.root.lock() = Some(new_root.clone());
    let ns = p.mnt_ns_id();
    for q in proc::all().iter().filter(|q| q.mnt_ns_id() == ns) {
        if Arc::ptr_eq(&q.root_dir(), &old_root) {
            q.set_root_dir(new_root.clone());
        }
        if Arc::ptr_eq(&q.cwd(), &old_root) {
            q.set_cwd(new_root.clone());
        }
    }
    Ok(0)
}

pub fn umount2(a: Args) -> Result {
    umount_at(&user_path(a.0[0])?, a.0[1] & UMOUNT_NOFOLLOW == 0, a.0[1] & MNT_DETACH != 0)
}

pub(crate) fn umount_at(target: &str, follow: bool, detach: bool) -> Result {
    crate::proc::apps::unconfined()?;
    let p = me()?;
    if !mount_capable(&p) {
        return Err(EPERM);
    }
    let d = vfs::resolve(&p.cwd(), target, follow)?;
    if !crate::proc::domain::may_change_mounts(&d) {
        return Err(EPERM);
    }
    vfs::unmount(&d, detach)?;
    Ok(0)
}

/// `struct statfs` (statfs(2)).
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub(crate) struct Statfs {
    pub kind: i64,
    pub bsize: i64,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub fsid: [i32; 2],
    pub namelen: i64,
    pub frsize: i64,
    pub flags: i64,
    pub spare: [i64; 4],
}

/// mount(2) flag (musl `sys/mount.h`).
const MS_RDONLY: u64 = 1;
/// statfs(2) `f_flags`: ST_RDONLY; ST_NOSUID (2), ST_NODEV (4) and
/// ST_NOEXEC (8) are the mount's flags of the same values, as are
/// ST_NOATIME (1024) and ST_NODIRATIME (2048); ST_RELATIME is 4096
/// (musl `sys/statvfs.h`).
pub(crate) const ST_RDONLY: i64 = 1;
const ST_RELATIME: i64 = 4096;

fn fill_statfs(addr: u64, d: &Arc<Dentry>) -> Result {
    write_user(addr, &statfs_of(d)).map_err(|_| EFAULT)?;
    Ok(0)
}

/// What statfs(2) reports about the file system holding `d`.
pub(crate) fn statfs_of(d: &Arc<Dentry>) -> Statfs {
    let inode = &d.inode;
    let mf = vfs::mount_flags(d);
    let same = vfs::MNT_NOSUID | vfs::MNT_NODEV | vfs::MNT_NOEXEC | vfs::MNT_NOATIME | vfs::MNT_NODIRATIME;
    let mount_ro = if vfs::on_read_only_mount(d) { ST_RDONLY } else { 0 }
        | i64::from(mf & same)
        | if mf & vfs::MNT_RELATIME != 0 { ST_RELATIME } else { 0 };
    if let Some(t) = inode.statfs() {
        return Statfs {
            kind: t.magic,
            bsize: t.block_size as i64,
            blocks: t.blocks,
            bfree: t.free_blocks,
            bavail: t.free_blocks,
            files: t.files,
            ffree: t.free_files,
            namelen: vfs::NAME_MAX as i64,
            frsize: t.block_size as i64,
            flags: if t.read_only { ST_RDONLY } else { 0 } | mount_ro,
            ..Default::default()
        };
    }
    let s = crate::mm::frame::stats();
    Statfs {
        kind: 0x0102_1994, // TMPFS_MAGIC (statfs(2))
        bsize: 4096,
        blocks: s.usable_frames,
        bfree: s.free_frames,
        bavail: s.free_frames,
        files: 1 << 20,
        ffree: 1 << 20,
        namelen: vfs::NAME_MAX as i64,
        frsize: 4096,
        flags: mount_ro,
        ..Default::default()
    }
}

pub fn statfs(a: Args) -> Result {
    let p = me()?;
    let path = user_path(a.0[0])?;
    let d = vfs::resolve(&p.cwd(), &path, true)?;
    fill_statfs(a.0[1], &d)
}

pub fn fstatfs(a: Args) -> Result {
    let f = file(a.fd(0))?;
    match f.dentry() {
        Some(d) => fill_statfs(a.0[1], &d),
        None => fill_statfs(a.0[1], &vfs::root()),
    }
}

// --- event files (eventfd, timerfd, signalfd, epoll) ----------------------

fn install(f: Arc<dyn File>, flags: u32) -> Result {
    Ok(me()?.files.lock().insert(f, flags & fs::O_CLOEXEC != 0)? as u64)
}

pub fn eventfd2(a: Args) -> Result {
    let flags = a.0[1] as u32;
    install(Arc::new(fs::events::EventFd::new(a.0[0] as u32, flags)), flags)
}

/// inotify_init1(2): IN_NONBLOCK and IN_CLOEXEC are O_NONBLOCK and
/// O_CLOEXEC (inotify_init(2)).
pub fn inotify_init1(a: Args) -> Result {
    let flags = a.0[0] as u32;
    if flags & !(fs::O_NONBLOCK | fs::O_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    install(inotify::Inotify::new(flags), flags)
}

pub fn inotify_init(_a: Args) -> Result {
    inotify_init1(Args([0; 6]))
}

fn inotify_of(fd: i32) -> core::result::Result<Arc<inotify::Inotify>, Errno> {
    let f: Arc<dyn core::any::Any + Send + Sync> = file(fd)?;
    f.downcast::<inotify::Inotify>().map_err(|_| EINVAL)
}

/// inotify_add_watch(2): the path must be readable by the caller.
pub fn inotify_add_watch(a: Args) -> Result {
    inotify_watch(a.fd(0), AT_FDCWD, &user_path(a.0[1])?, a.0[2] as u32)
}

/// A watch on `path` (from `dirfd`), for inotify_add_watch and the native
/// WATCH_ADD.
pub(crate) fn inotify_watch(fd: i32, dirfd: i32, path: &str, mask: u32) -> Result {
    let i = inotify_of(fd)?;
    if mask & !inotify::ACCEPTED_FLAGS != 0 {
        return Err(EINVAL);
    }
    let p = me()?;
    let d = vfs::resolve(&dir_for(&p, dirfd, path)?, path, mask & inotify::IN_DONT_FOLLOW == 0)?;
    if mask & inotify::IN_ONLYDIR != 0 && !d.is_dir() {
        return Err(ENOTDIR);
    }
    let m = d.metadata();
    p.cred().permission(&m, crate::proc::cred::MAY_READ)?;
    Ok(i.add_watch(&m, mask)? as u64)
}

pub fn inotify_rm_watch(a: Args) -> Result {
    inotify_of(a.fd(0))?.rm_watch(a.0[1] as i32)?;
    Ok(0)
}

pub fn eventfd(a: Args) -> Result {
    eventfd2(Args([a.0[0], 0, 0, 0, 0, 0]))
}

/// `struct itimerspec`.
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Itimerspec {
    interval: Timespec,
    value: Timespec,
}

fn ts_ns(t: Timespec) -> core::result::Result<u64, Errno> {
    if t.sec < 0 || !(0..1_000_000_000).contains(&t.nsec) {
        return Err(EINVAL);
    }
    Ok((t.sec as u64).saturating_mul(1_000_000_000).saturating_add(t.nsec as u64))
}

fn ns_ts(ns: u64) -> Timespec {
    Timespec { sec: (ns / 1_000_000_000) as i64, nsec: (ns % 1_000_000_000) as i64 }
}

pub fn timerfd_create(a: Args) -> Result {
    let (clock, flags) = (a.0[0] as u32, a.0[1] as u32);
    if !matches!(clock, 0 | 1 | 7) {
        return Err(EINVAL); // REALTIME, MONOTONIC, BOOTTIME
    }
    // timerfd_create(2): only TFD_NONBLOCK and TFD_CLOEXEC.
    if flags & !(fs::O_NONBLOCK | fs::O_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    install(fs::events::TimerFd::new(clock, flags), flags)
}

fn timerfd(fd: i32) -> core::result::Result<Arc<fs::events::TimerFd>, Errno> {
    let f = file(fd)?;
    let any: Arc<dyn core::any::Any + Send + Sync> = into_any(f);
    any.downcast::<fs::events::TimerFd>().map_err(|_| EINVAL)
}

/// Upcast a file to `Any`, to downcast it to a concrete file type.
fn into_any(f: Arc<dyn File>) -> Arc<dyn core::any::Any + Send + Sync> {
    f
}

pub fn timerfd_settime(a: Args) -> Result {
    let t = timerfd(a.fd(0))?;
    // TFD_TIMER_ABSTIME and TFD_TIMER_CANCEL_ON_SET only
    // (timerfd_create(2)).
    if a.0[1] & !3 != 0 {
        return Err(EINVAL);
    }
    let new: Itimerspec = read_user(a.0[2]).map_err(|_| EFAULT)?;
    let absolute = a.0[1] as u32 & fs::events::TFD_TIMER_ABSTIME != 0;
    let (old_value, old_interval) = t.set(ts_ns(new.value)?, ts_ns(new.interval)?, absolute);
    if a.0[3] != 0 {
        let old = Itimerspec { interval: ns_ts(old_interval), value: ns_ts(old_value) };
        write_user(a.0[3], &old).map_err(|_| EFAULT)?;
    }
    Ok(0)
}

pub fn timerfd_gettime(a: Args) -> Result {
    let (value, interval) = timerfd(a.fd(0))?.get();
    write_user(a.0[1], &Itimerspec { interval: ns_ts(interval), value: ns_ts(value) }).map_err(|_| EFAULT)?;
    Ok(0)
}

pub fn signalfd4(a: Args) -> Result {
    let (fd, mask_addr, size, flags) = (a.fd(0), a.0[1], a.0[2], a.0[3] as u32);
    if size != 8 {
        return Err(EINVAL);
    }
    let mask: u64 = read_user(mask_addr).map_err(|_| EFAULT)?;
    let mask = mask & !(crate::proc::signal::bit(9) | crate::proc::signal::bit(19)); // not SIGKILL/SIGSTOP
    if fd == -1 {
        return install(Arc::new(fs::events::SignalFd::new(mask, flags)), flags);
    }
    let any = into_any(file(fd)?);
    let sfd = any.downcast::<fs::events::SignalFd>().map_err(|_| EINVAL)?;
    sfd.mask.store(mask, core::sync::atomic::Ordering::Relaxed);
    Ok(fd as u64)
}

pub fn signalfd(a: Args) -> Result {
    signalfd4(Args([a.0[0], a.0[1], a.0[2], 0, 0, 0]))
}

pub fn epoll_create1(a: Args) -> Result {
    let flags = a.0[0] as u32;
    if flags & !fs::O_CLOEXEC != 0 {
        return Err(EINVAL);
    }
    install(Arc::new(fs::events::Epoll::new()), flags)
}

pub fn epoll_create(a: Args) -> Result {
    if a.0[0] as i32 <= 0 {
        return Err(EINVAL);
    }
    epoll_create1(Args([0; 6]))
}

/// `struct epoll_event` is packed on x86-64 (musl `sys/epoll.h`): 12 bytes.
fn read_event(addr: u64) -> core::result::Result<(u32, u64), Errno> {
    let mut b = [0u8; 12];
    copy_from_user(&mut b, addr).map_err(|_| EFAULT)?;
    Ok((u32::from_le_bytes(b[..4].try_into().unwrap()), u64::from_le_bytes(b[4..].try_into().unwrap())))
}

fn epoll(fd: i32) -> core::result::Result<Arc<fs::events::Epoll>, Errno> {
    into_any(file(fd)?).downcast::<fs::events::Epoll>().map_err(|_| EINVAL)
}

pub fn epoll_ctl(a: Args) -> Result {
    let ep = epoll(a.fd(0))?;
    let (op, fd) = (a.0[1] as u32, a.fd(2));
    let target = file(fd)?;
    if Arc::ptr_eq(&into_any(target.clone()), &(ep.clone() as Arc<dyn core::any::Any + Send + Sync>)) {
        return Err(EINVAL);
    }
    // epoll_ctl(2): regular files and directories don't support epoll.
    if target
        .dentry()
        .is_some_and(|d| matches!(d.metadata().file_type(), vfs::FileType::Regular | vfs::FileType::Directory))
    {
        return Err(EPERM);
    }
    let (events, data) = if op == fs::events::EPOLL_CTL_DEL { (0, 0) } else { read_event(a.0[3])? };
    ep.ctl(op, fd, &target, events, data)?;
    Ok(0)
}

fn epoll_wait_until(a: Args, deadline: Option<u64>) -> Result {
    let ep = epoll(a.fd(0))?;
    let max = a.0[2] as i32;
    if max <= 0 {
        return Err(EINVAL);
    }
    let ready = ep.wait(max as usize, deadline)?;
    for (i, r) in ready.iter().enumerate() {
        let mut b = [0u8; 12];
        b[..4].copy_from_slice(&r.events.to_le_bytes());
        b[4..].copy_from_slice(&r.data.to_le_bytes());
        copy_to_user(a.0[1] + i as u64 * 12, &b).map_err(|_| EFAULT)?;
    }
    Ok(ready.len() as u64)
}

pub fn epoll_wait(a: Args) -> Result {
    let t = a.0[3] as i32;
    let deadline = if t < 0 { None } else { Some(crate::time::monotonic_ns() + t as u64 * 1_000_000) };
    epoll_wait_until(a, deadline)
}

/// epoll_pwait(2): the temporary signal mask is applied for the wait.
pub fn epoll_pwait(a: Args) -> Result {
    with_sigmask(a.0[4], || epoll_wait(a))
}

pub fn epoll_pwait2(a: Args) -> Result {
    let deadline = deadline_from_timespec(a.0[3])?;
    with_sigmask(a.0[4], || epoll_wait_until(a, deadline))
}

/// Run `f` with the signal mask at `mask_addr` (if any) in effect; a signal
/// caught meanwhile is delivered with the old mask restored afterwards.
fn with_sigmask(mask_addr: u64, f: impl FnOnce() -> Result) -> Result {
    if mask_addr == 0 {
        return f();
    }
    let mask: u64 = read_user(mask_addr).map_err(|_| EFAULT)?;
    let t = crate::sched::current();
    let old = t.signal_mask();
    t.set_signal_mask(mask);
    let r = f();
    if r == Err(EINTR) {
        t.save_mask_for_delivery(old);
    } else {
        t.set_signal_mask(old);
    }
    r
}
