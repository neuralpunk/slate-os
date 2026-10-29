// SPDX-License-Identifier: MIT OR Apache-2.0

//! Native file, directory, mount and socket calls.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use slate_abi::{DirEntry, MountArgs, Stat, StatFs, Str, open as o, path as pf};

use super::{path, str_path, translate, user_path};
use crate::abi::linux::errno::*;
use crate::abi::linux::{Args, Result, fs as lfs, net};
use crate::arch::uaccess::{copy_from_user, copy_to_user, read_user, write_user};
use crate::fs::{self as k, vfs};

/// Native `open::*` flags and the kernel's `O_*` flags.
const OPEN_FLAGS: &[(u32, u32)] = &[
    (o::CREATE, k::O_CREAT),
    (o::EXCL, k::O_EXCL),
    (o::TRUNC, k::O_TRUNC),
    (o::APPEND, k::O_APPEND),
    (o::NONBLOCK, k::O_NONBLOCK),
    (o::CLOEXEC, k::O_CLOEXEC),
    (o::DIRECTORY, k::O_DIRECTORY),
    (o::NOFOLLOW, k::O_NOFOLLOW),
    (o::NOCTTY, k::O_NOCTTY),
    (o::PATH, k::O_PATH),
    (o::SYNC, k::O_SYNC),
    (o::DIRECT, k::O_DIRECT),
    (o::NOATIME, k::O_NOATIME),
];

/// Native `open::*` flags as the kernel's `O_*` flags.
pub(super) fn open_flags(f: u32) -> core::result::Result<u32, Errno> {
    if f & !o::ALL != 0 {
        return Err(EINVAL);
    }
    let mut out = match f & o::ACCESS_MASK {
        o::READ_ONLY => k::O_RDONLY,
        o::WRITE_ONLY => k::O_WRONLY,
        o::READ_WRITE => k::O_RDWR,
        _ => return Err(EINVAL),
    };
    for (native, linux) in OPEN_FLAGS {
        if f & native != 0 {
            out |= linux;
        }
    }
    Ok(out)
}

/// The kernel's `O_*` status flags as native flags (unknown bits drop).
fn native_open_flags(f: u32) -> u32 {
    let mut out = match f & k::O_ACCMODE {
        k::O_WRONLY => o::WRITE_ONLY,
        k::O_RDWR => o::READ_WRITE,
        _ => o::READ_ONLY,
    };
    for (native, linux) in OPEN_FLAGS {
        if f & linux != 0 {
            out |= native;
        }
    }
    out
}

/// `open::CLOEXEC | open::NONBLOCK` (dup, pipe, socket, accept) as `O_*`.
pub(super) fn fd_flags(f: u32) -> core::result::Result<u32, Errno> {
    Ok(translate(f, &[(o::CLOEXEC, u64::from(k::O_CLOEXEC)), (o::NONBLOCK, u64::from(k::O_NONBLOCK))])? as u32)
}

pub(super) fn open(a: Args) -> Result {
    lfs::open_at(a.fd(0), &path(a, 1)?, open_flags(a.0[3] as u32)?, a.0[4] as u32)
}

fn timespec(t: vfs::Timespec) -> slate_abi::Timespec {
    slate_abi::Timespec { sec: t.sec, nsec: t.nsec }
}

pub(super) fn stat(a: Args) -> Result {
    let flags = a.0[3] as u32;
    if flags & !(pf::NOFOLLOW | pf::EMPTY_PATH) != 0 {
        return Err(EINVAL);
    }
    let m = lfs::stat_at(a.fd(0), &path(a, 1)?, flags & pf::NOFOLLOW == 0, flags & pf::EMPTY_PATH != 0)?;
    let c = crate::proc::cred::current();
    let st = Stat {
        dev: m.dev,
        ino: m.ino,
        mode: m.mode,
        nlink: m.nlink.min(u64::from(u32::MAX)) as u32,
        uid: c.uid_out(m.uid),
        gid: c.gid_out(m.gid),
        rdev: m.rdev,
        size: m.size,
        blocks: m.blocks(),
        block_size: 4096,
        atime: timespec(m.atime),
        mtime: timespec(m.mtime),
        ctime: timespec(m.ctime),
        ..Default::default()
    };
    write_user(a.0[4], &st).map_err(|_| EFAULT)?;
    Ok(0)
}

/// dup: -1 for the lowest free descriptor; `newfd == fd` returns `fd`.
pub(super) fn dup(a: Args) -> Result {
    let (fd, new) = (a.fd(0), a.fd(1));
    let flags = a.0[2] as u32;
    if flags & !o::CLOEXEC != 0 {
        return Err(EINVAL);
    }
    let cloexec = flags & o::CLOEXEC != 0;
    let p = crate::proc::current().ok_or(ESRCH)?;
    let mut t = p.files.lock();
    let f = t.get(fd)?;
    if new == -1 {
        return Ok(t.insert(f, cloexec)? as u64);
    }
    if new == fd {
        return Ok(fd as u64);
    }
    Ok(t.insert_at(new, f, cloexec)? as u64)
}

pub(super) fn pipe(a: Args) -> Result {
    lfs::pipe2(Args([a.0[0], u64::from(fd_flags(a.0[1] as u32)?), 0, 0, 0, 0]))
}

pub(super) fn fcntl(a: Args) -> Result {
    use slate_abi::fcntl as c;
    // Linux fcntl(2) commands (musl `fcntl.h`, as in the Linux handler).
    const F_DUPFD: u64 = 0;
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    const F_GETFL: u64 = 3;
    const F_SETFL: u64 = 4;
    const F_DUPFD_CLOEXEC: u64 = 1030;
    let l = |cmd: u64, arg: u64| lfs::fcntl(Args([a.0[0], cmd, arg, 0, 0, 0]));
    match a.0[1] as u32 {
        c::DUPFD => l(F_DUPFD, a.0[2]),
        c::DUPFD_CLOEXEC => l(F_DUPFD_CLOEXEC, a.0[2]),
        // FD_CLOEXEC is 1 in both.
        c::GETFD => l(F_GETFD, 0),
        c::SETFD => l(F_SETFD, a.0[2] & u64::from(c::CLOEXEC)),
        c::GETFL => Ok(u64::from(native_open_flags(l(F_GETFL, 0)? as u32))),
        c::SETFL => {
            let f = a.0[2] as u32;
            let mut linux = 0;
            if f & o::APPEND != 0 {
                linux |= k::O_APPEND;
            }
            if f & o::NONBLOCK != 0 {
                linux |= k::O_NONBLOCK;
            }
            if f & o::DIRECT != 0 {
                linux |= k::O_DIRECT;
            }
            if f & o::NOATIME != 0 {
                linux |= k::O_NOATIME;
            }
            l(F_SETFL, u64::from(linux))
        }
        _ => Err(EINVAL),
    }
}

/// sync: one file, or every file system for -1.
pub(super) fn sync(a: Args) -> Result {
    if a.fd(0) == -1 { lfs::sync(a) } else { lfs::fsync(a) }
}

/// flock: `flock::*` operations as flock(2)'s.
pub(super) fn flock(a: Args) -> Result {
    use crate::fs::locks::{LOCK_EX, LOCK_NB, LOCK_SH, LOCK_UN};
    use slate_abi::flock as fl;
    let op = a.0[1] as u32;
    if op & !(fl::NONBLOCK | 3) != 0 {
        return Err(EINVAL);
    }
    let linux = match op & 3 {
        fl::SHARED => LOCK_SH,
        fl::EXCLUSIVE => LOCK_EX,
        fl::UNLOCK => LOCK_UN,
        _ => return Err(EINVAL),
    } | if op & fl::NONBLOCK != 0 { LOCK_NB } else { 0 };
    lfs::flock(Args([a.0[0], u64::from(linux), 0, 0, 0, 0]))
}

/// readdir: [`DirEntry`] records, as many as fit.
pub(super) fn readdir(a: Args) -> Result {
    let p = crate::proc::current().ok_or(ESRCH)?;
    let f = p.files.lock().get(a.fd(0))?;
    let cap = a.0[2] as usize;
    let mut out: Vec<u8> = Vec::new();
    let mut too_small = false;
    f.getdents(&mut |e, _next| {
        let rec = DirEntry::rec_len_for(e.name.len());
        if out.len() + rec > cap {
            too_small = out.is_empty();
            return false;
        }
        let start = out.len();
        out.extend_from_slice(&e.ino.to_le_bytes());
        out.extend_from_slice(&(rec as u16).to_le_bytes());
        out.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
        out.push(e.kind.dirent_type());
        out.extend_from_slice(&[0; 3]);
        out.extend_from_slice(e.name.as_bytes());
        out.resize(start + rec, 0);
        true
    })?;
    if too_small {
        return Err(EINVAL);
    }
    copy_to_user(a.0[1], &out).map_err(|_| EFAULT)?;
    Ok(out.len() as u64)
}

pub(super) fn unlink(a: Args) -> Result {
    let flags = a.0[3] as u32;
    if flags & !pf::REMOVE_DIR != 0 {
        return Err(EINVAL);
    }
    lfs::unlink_at(a.fd(0), &path(a, 1)?, flags & pf::REMOVE_DIR != 0)
}

pub(super) fn readlink(a: Args) -> Result {
    let p = path(a, 1)?;
    if p.is_empty() && a.0[5] as u32 & pf::EMPTY_PATH == 0 {
        return Err(ENOENT);
    }
    let target = lfs::readlink_at(a.fd(0), &p)?;
    let n = target.len().min(a.0[4] as usize);
    copy_to_user(a.0[3], &target.as_bytes()[..n]).map_err(|_| EFAULT)?;
    Ok(n as u64)
}

/// The file a chmod-style call acts on (`None`: a file with no name).
fn target(a: Args, flags: u32) -> core::result::Result<Option<alloc::sync::Arc<vfs::Dentry>>, Errno> {
    if flags & !(pf::NOFOLLOW | pf::EMPTY_PATH) != 0 {
        return Err(EINVAL);
    }
    lfs::path_target(a.fd(0), &path(a, 1)?, flags & pf::NOFOLLOW == 0, flags & pf::EMPTY_PATH != 0)
}

pub(super) fn chmod(a: Args) -> Result {
    match target(a, a.0[4] as u32)? {
        Some(d) => lfs::do_chmod(&d, a.0[3] as u32),
        None => Ok(0),
    }
}

pub(super) fn chown(a: Args) -> Result {
    match target(a, a.0[5] as u32)? {
        Some(d) => lfs::do_chown(&d, a.0[3] & 0xFFFF_FFFF, a.0[4] & 0xFFFF_FFFF),
        None => Ok(0),
    }
}

pub(super) fn utimes(a: Args) -> Result {
    use slate_abi::utime;
    let d = target(a, a.0[4] as u32)?.ok_or(EINVAL)?;
    let times = if a.0[3] == 0 {
        None
    } else {
        let ts: [slate_abi::Timespec; 2] = read_user(a.0[3]).map_err(|_| EFAULT)?;
        let conv = |t: slate_abi::Timespec| -> core::result::Result<vfs::Timespec, Errno> {
            let nsec = match t.nsec {
                utime::NOW => lfs::UTIME_NOW,
                utime::OMIT => lfs::UTIME_OMIT,
                n if (0..1_000_000_000).contains(&n) => n,
                _ => return Err(EINVAL),
            };
            Ok(vfs::Timespec { sec: t.sec, nsec })
        };
        Some([conv(ts[0])?, conv(ts[1])?])
    };
    lfs::set_times(&d, times)
}

pub(super) fn access(a: Args) -> Result {
    let flags = a.0[4] as u32;
    if flags & !(pf::EFFECTIVE_IDS | pf::NOFOLLOW) != 0 || a.0[3] & !7 != 0 {
        return Err(EINVAL);
    }
    lfs::access_at(a.fd(0), &path(a, 1)?, a.0[3] as u32, flags & pf::EFFECTIVE_IDS != 0, flags & pf::NOFOLLOW != 0)
}

pub(super) fn chdir(a: Args) -> Result {
    let p = crate::proc::current().ok_or(ESRCH)?;
    let flags = a.0[3] as u32;
    if flags & !pf::EMPTY_PATH != 0 {
        return Err(EINVAL);
    }
    let path = path(a, 1)?;
    let d = if path.is_empty() {
        if flags & pf::EMPTY_PATH == 0 {
            return Err(ENOENT);
        }
        p.files.lock().get(a.fd(0))?.dentry().ok_or(ENOTDIR)?
    } else {
        vfs::resolve(&lfs::dir_for(&p, a.fd(0), &path)?, &path, true)?
    };
    lfs::change_dir(&p, d)
}

/// getcwd: the path's length, without a NUL.
pub(super) fn getcwd(a: Args) -> Result {
    let cwd = crate::proc::current().ok_or(ESRCH)?.cwd();
    let path = vfs::visible_path(&cwd);
    if path.len() > a.0[1] as usize {
        return Err(ERANGE);
    }
    copy_to_user(a.0[0], path.as_bytes()).map_err(|_| EFAULT)?;
    Ok(path.len() as u64)
}

pub(super) fn statfs(a: Args) -> Result {
    let flags = a.0[3] as u32;
    if flags & !pf::EMPTY_PATH != 0 {
        return Err(EINVAL);
    }
    let d = target(a, flags)?.unwrap_or_else(vfs::root);
    let s = lfs::statfs_of(&d);
    let st = StatFs {
        kind: s.kind as u64,
        block_size: s.bsize as u64,
        blocks: s.blocks,
        free: s.bfree,
        available: s.bavail,
        files: s.files,
        free_files: s.ffree,
        fsid: 0,
        name_max: s.namelen as u64,
        // ST_RDONLY to ST_NOEXEC have the native mount flags' values (1,
        // 2, 4, 8); ST_NOATIME (1024), ST_NODIRATIME (2048) and
        // ST_RELATIME (4096) don't (musl `sys/statvfs.h`).
        flags: {
            use slate_abi::mount as m;
            let atime = [(1024, m::NOATIME), (2048, m::NODIRATIME), (4096, m::RELATIME)];
            atime.iter().filter(|(st, _)| s.flags & st != 0).fold((s.flags & 0xf) as u64, |f, (_, n)| f | u64::from(*n))
        },
        _reserved: [0; 2],
    };
    write_user(a.0[4], &st).map_err(|_| EFAULT)?;
    Ok(0)
}

pub(super) fn mount(a: Args) -> Result {
    use slate_abi::mount as m;
    let args: MountArgs = read_user(a.0[0]).map_err(|_| EFAULT)?;
    // mount(2) flag values (musl `sys/mount.h`): MS_RDONLY 1, MS_NOSUID 2,
    // MS_NODEV 4, MS_NOEXEC 8, MS_NOATIME 1024, MS_NODIRATIME 2048,
    // MS_RELATIME 1 << 21, MS_STRICTATIME 1 << 24.
    let flags = translate(
        a.0[1] as u32,
        &[
            (m::RDONLY, 1),
            (m::NOSUID, 2),
            (m::NODEV, 4),
            (m::NOEXEC, 8),
            (m::NOATIME, 1024),
            (m::NODIRATIME, 2048),
            (m::RELATIME, 1 << 21),
            (m::STRICTATIME, 1 << 24),
            (m::REMOUNT, lfs::MS_REMOUNT),
            (m::BIND, lfs::MS_BIND),
            (m::RECURSIVE, lfs::MS_REC),
        ],
    )?;
    let source = str_path(args.source)?;
    let source = if source.is_empty() { String::from("none") } else { source };
    let data = || str_path(args.data);
    lfs::mount_at(&source, &str_path(args.target)?, &str_path(args.fstype)?, flags, &data)
}

pub(super) fn umount(a: Args) -> Result {
    use slate_abi::umount as u;
    let flags = a.0[2] as u32;
    if flags & !(u::FORCE | u::DETACH) != 0 {
        return Err(EINVAL);
    }
    lfs::umount_at(&user_path(a.0[0], a.0[1])?, true, flags & u::DETACH != 0)
}

/// socket(family, kind, protocol, flags).
pub(super) fn socket(a: Args) -> Result {
    use slate_abi::socket as s;
    // Socket types (socket(2)): SOCK_STREAM 1, SOCK_DGRAM 2, SOCK_RAW 3;
    // SOCK_CLOEXEC and SOCK_NONBLOCK are the O_ values.
    let kind = match a.0[1] as u32 {
        s::STREAM => 1,
        s::DGRAM => 2,
        s::RAW => 3,
        _ => return Err(EINVAL),
    };
    net::socket(Args([a.0[0], kind | u64::from(fd_flags(a.0[3] as u32)?), a.0[2], 0, 0, 0]))
}

/// An attribute name given as pointer and length.
fn xattr_name(a: Args, i: usize) -> core::result::Result<String, Errno> {
    let len = a.0[i + 1] as usize;
    if len == 0 || len > 255 {
        return Err(ERANGE);
    }
    let mut b = vec![0u8; len];
    copy_from_user(&mut b, a.0[i]).map_err(|_| EFAULT)?;
    if b.contains(&0) {
        return Err(EINVAL);
    }
    crate::abi::linux::xattr::check_name(b)
}

/// Copy `v` out to a buffer of `size` bytes (0: only its length).
fn give(v: &[u8], addr: u64, size: u64) -> Result {
    if size == 0 {
        return Ok(v.len() as u64);
    }
    if v.len() as u64 > size {
        return Err(ERANGE);
    }
    copy_to_user(addr, v).map_err(|_| EFAULT)?;
    Ok(v.len() as u64)
}

/// watch_open(flags): an inotify descriptor (ADR 0149).
pub(super) fn watch_open(a: Args) -> Result {
    let flags = a.0[0] as u32;
    if flags & !(o::CLOEXEC | o::NONBLOCK) != 0 {
        return Err(EINVAL);
    }
    let mut linux = 0;
    if flags & o::CLOEXEC != 0 {
        linux |= k::O_CLOEXEC;
    }
    if flags & o::NONBLOCK != 0 {
        linux |= k::O_NONBLOCK;
    }
    lfs::inotify_init1(Args([u64::from(linux), 0, 0, 0, 0, 0]))
}

/// watch_add(fd, dir, path, path len, mask).
pub(super) fn watch_add(a: Args) -> Result {
    lfs::inotify_watch(a.fd(0), a.fd(1), &super::path(a, 2)?, a.0[4] as u32)
}

/// watch_remove(fd, watch number).
pub(super) fn watch_remove(a: Args) -> Result {
    lfs::inotify_rm_watch(Args([a.0[0], a.0[1], 0, 0, 0, 0]))
}

/// xattr_get(fd, name, name len, buf, buf len).
pub(super) fn xattr_get(a: Args) -> Result {
    let name = xattr_name(a, 1)?;
    let d = crate::abi::linux::xattr::fd_dentry(a.fd(0))?;
    let v = crate::abi::linux::xattr::get_value(&d, &name)?;
    give(&v, a.0[3], a.0[4])
}

/// xattr_set(fd, name, name len, value, value len, flags).
pub(super) fn xattr_set(a: Args) -> Result {
    use slate_abi::xattr as x;
    let name = xattr_name(a, 1)?;
    let len = a.0[4] as usize;
    if len > 65536 {
        return Err(E2BIG);
    }
    let mut value = vec![0u8; len];
    if len > 0 {
        copy_from_user(&mut value, a.0[3]).map_err(|_| EFAULT)?;
    }
    let flags = translate(
        a.0[5] as u32,
        &[(x::CREATE, u64::from(vfs::XATTR_CREATE)), (x::REPLACE, u64::from(vfs::XATTR_REPLACE))],
    )?;
    let d = crate::abi::linux::xattr::fd_dentry(a.fd(0))?;
    crate::abi::linux::xattr::set_value(&d, &name, value, flags as u32)
}

/// xattr_list(fd, buf, buf len).
pub(super) fn xattr_list(a: Args) -> Result {
    let d = crate::abi::linux::xattr::fd_dentry(a.fd(0))?;
    let names = crate::abi::linux::xattr::list_names(&d)?;
    give(&names, a.0[1], a.0[2])
}

/// xattr_remove(fd, name, name len).
pub(super) fn xattr_remove(a: Args) -> Result {
    let name = xattr_name(a, 1)?;
    let d = crate::abi::linux::xattr::fd_dentry(a.fd(0))?;
    crate::abi::linux::xattr::remove_value(&d, &name)
}

/// socketpair(family, kind, protocol, flags, fds): as socket, a pair.
pub(super) fn socketpair(a: Args) -> Result {
    use slate_abi::socket as s;
    let kind = match a.0[1] as u32 {
        s::STREAM => 1,
        s::DGRAM => 2,
        _ => return Err(EINVAL),
    };
    net::socketpair(Args([a.0[0], kind | u64::from(fd_flags(a.0[3] as u32)?), a.0[2], a.0[4], 0, 0]))
}

/// sendmsg(fd, *const Msg, flags): the buffers' bytes, to `addr` if
/// given, with the descriptors in `fds` (Unix sockets only).
pub(super) fn sendmsg(a: Args) -> Result {
    let f = net::sock(a.fd(0))?;
    let m: slate_abi::Msg = read_user(a.0[1]).map_err(|_| EFAULT)?;
    if m.bufs_len > 1024 || m.fds_len as usize > net::MAX_RIGHTS {
        return Err(EINVAL);
    }
    let mut data = Vec::new();
    for i in 0..m.bufs_len {
        let b: Str = read_user(m.bufs + i * 16).map_err(|_| EFAULT)?;
        let n = (b.len as usize).min(net::MAX_IO - data.len());
        let start = data.len();
        data.resize(start + n, 0);
        copy_from_user(&mut data[start..], b.ptr).map_err(|_| EFAULT)?;
    }
    let to = if m.addr != 0 && m.addr_len != 0 { Some(net::read_raw(m.addr, u64::from(m.addr_len))?) } else { None };
    let mut rights = Vec::new();
    for i in 0..u64::from(m.fds_len) {
        let fd: i32 = read_user(m.fds + i * 4).map_err(|_| EFAULT)?;
        rights.push(net::file(fd)?);
    }
    if !rights.is_empty() && !net::is_unix(&f) {
        return Err(EOPNOTSUPP);
    }
    net::send_on(&f, &data, to, a.0[2], rights)
}

/// recvmsg(fd, *mut Msg, flags): one receive scattered into the buffers;
/// the sender's address, received descriptors, flags and a datagram's TTL
/// go into `Msg`.
pub(super) fn recvmsg(a: Args) -> Result {
    let f = net::sock(a.fd(0))?;
    let flags = a.0[2];
    let mut m: slate_abi::Msg = read_user(a.0[1]).map_err(|_| EFAULT)?;
    if m.bufs_len > 1024 {
        return Err(EINVAL);
    }
    let bufs: Vec<Str> = (0..m.bufs_len)
        .map(|i| read_user::<Str>(m.bufs + i * 16).map_err(|_| EFAULT))
        .collect::<core::result::Result<_, _>>()?;
    let total = bufs.iter().map(|b| b.len as usize).sum::<usize>().min(net::MAX_IO);
    let mut data = vec![0u8; total];
    let ((copied, full, from, mut rights, _), ttl) = net::recv_on_ttl(&f, &mut data, flags)?;
    m.ttl = u32::from(ttl);
    let dropped = net::keep_from_linux(&mut rights);
    let mut done = 0;
    for b in bufs {
        let n = (b.len as usize).min(copied - done);
        copy_to_user(b.ptr, &data[done..done + n]).map_err(|_| EFAULT)?;
        done += n;
    }
    match from {
        Some(sa) if m.addr != 0 => {
            let n = (m.addr_len as usize).min(sa.len());
            copy_to_user(m.addr, &sa[..n]).map_err(|_| EFAULT)?;
            m.addr_len = sa.len() as u32;
        }
        _ => m.addr_len = 0,
    }
    m.flags = if full > copied { net::MSG_TRUNC as u32 } else { 0 };
    let room = m.fds_len as usize;
    if dropped {
        m.flags |= net::MSG_CTRUNC as u32;
    }
    if rights.len() > room {
        m.flags |= net::MSG_CTRUNC as u32;
    }
    let cloexec = flags & net::MSG_CMSG_CLOEXEC != 0;
    let mut n = 0u32;
    for r in rights.into_iter().take(room) {
        let fd = net::install(r, cloexec)?;
        write_user(m.fds + u64::from(n) * 4, &fd).map_err(|_| EFAULT)?;
        n += 1;
    }
    m.fds_len = n;
    write_user(a.0[1], &m).map_err(|_| EFAULT)?;
    Ok((if flags & net::MSG_TRUNC != 0 { full } else { copied }) as u64)
}
