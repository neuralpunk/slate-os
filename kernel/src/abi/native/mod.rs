// SPDX-License-Identifier: MIT OR Apache-2.0

//! Slate's native system-call interface (ADR 0031). The numbers, flags
//! and structures are defined in `slate-abi`; libs/abi/native-abi.md is the
//! reference. Calls that mean the same as a Linux call share its kernel
//! code; only argument decoding differs (strings are pointer and length,
//! flags are Slate's own). Linux flag values used in translation come
//! from the Linux handlers, which cite their sources.

mod files;
mod process;
mod seccomp;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

use slate_abi::{Str, nr};

use super::linux::errno::*;
use super::linux::{Args, Result, io, trace};
use crate::arch::trap::TrapFrame;
use crate::arch::uaccess::{copy_from_user, read_user};
use crate::fs::vfs::PATH_MAX;
use crate::log_warn;

/// Unimplemented numbers already reported (one bit each, 0..256).
static REPORTED: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

fn unimplemented(n: u64) -> Result {
    let (word, bit) = ((n / 64) as usize, n % 64);
    let first = word >= REPORTED.len() || REPORTED[word].fetch_or(1 << bit, Ordering::Relaxed) & (1 << bit) == 0;
    if first {
        let pid = crate::proc::current().map_or(0, |p| p.pid);
        log_warn!("pid {pid}: unimplemented native call {n} ({})", nr::name(n).unwrap_or("unknown"));
    }
    Err(ENOSYS)
}

/// Run the native system call described by `frame` and store its result.
pub fn syscall(frame: &mut TrapFrame) {
    let n = frame.rax;
    let a = Args([frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9]);
    {
        let t = crate::sched::current();
        t.syscall_arg.store(a.0[0], Ordering::Relaxed);
        t.syscall.store(n + 1, Ordering::Relaxed);
    }
    let traced = trace::wanted();
    // seccomp filters see the Linux call this amounts to (ADR 0097).
    let checked = if crate::proc::seccomp::IN_USE.load(Ordering::Acquire) {
        let (lnr, largs) = seccomp::linux_view(n, &a);
        super::linux::process::seccomp_check(lnr, &Args(largs), frame.rip).map(|r| match r {
            // A trapped native call fails; its handler got SIGSYS with the
            // Linux number.
            Ok(_) => Err(ENOSYS),
            e => e,
        })
    } else {
        None
    };
    let r = match checked {
        Some(r) => r,
        None => dispatch(n, a, frame),
    };
    crate::sched::current().syscall.store(0, Ordering::Relaxed);
    if traced {
        log(n, &a, &r);
    }
    frame.rax = match r {
        Ok(v) => v,
        Err(e) => (-(e.0 as i64)) as u64,
    };
}

fn dispatch(n: u64, a: Args, frame: &mut TrapFrame) -> Result {
    use super::linux::{cred, fs as lfs, net};
    match n {
        nr::READ => io::read(a),
        nr::WRITE => io::write(a),
        nr::PREAD => io::pread64(a),
        nr::PWRITE => io::pwrite64(a),
        nr::SEEK => lfs::lseek(a),
        nr::CLOSE => io::close(a),
        nr::DUP => files::dup(a),
        nr::PIPE => files::pipe(a),
        nr::IOCTL => io::ioctl(a),
        nr::FCNTL => files::fcntl(a),
        nr::POLL => lfs::poll(a),
        nr::TRUNCATE => lfs::ftruncate(a),
        nr::SYNC => files::sync(a),
        nr::READDIR => files::readdir(a),
        nr::FLOCK => files::flock(a),

        nr::OPEN => files::open(a),
        nr::STAT => files::stat(a),
        nr::MKDIR => lfs::mkdir_at(a.fd(0), &path(a, 1)?, a.0[3] as u32),
        nr::MKNOD => lfs::mknod_at(a.fd(0), &path(a, 1)?, a.0[3] as u32, a.0[4]),
        nr::UNLINK => files::unlink(a),
        nr::RENAME => lfs::rename_at(a.fd(0), &path(a, 1)?, a.fd(3), &path(a, 4)?),
        nr::LINK => lfs::link_at(a.fd(0), &path(a, 1)?, a.fd(3), &path(a, 4)?, false),
        nr::SYMLINK => lfs::symlink_at(&path(a, 0)?, a.fd(2), &path(a, 3)?),
        nr::READLINK => files::readlink(a),
        nr::CHMOD => files::chmod(a),
        nr::CHOWN => files::chown(a),
        nr::UTIMES => files::utimes(a),
        nr::ACCESS => files::access(a),
        nr::CHDIR => files::chdir(a),
        nr::GETCWD => files::getcwd(a),
        nr::CHROOT => super::linux::process::chroot_at(a.fd(0), &path(a, 1)?),
        nr::UMASK => lfs::umask(a),
        nr::STATFS => files::statfs(a),
        nr::MOUNT => files::mount(a),
        nr::UMOUNT => files::umount(a),

        nr::EXIT => super::linux::process::exit_group(a),
        nr::FORK => super::linux::process::fork(frame),
        nr::EXEC => process::exec(a, frame),
        nr::WAIT => process::wait(a),
        nr::GETPID => super::linux::process::getpid(),
        nr::GETPPID => super::linux::process::getppid(),
        nr::GETIDS => process::getids(a),
        nr::SETIDS => process::setids(a),
        nr::GETGROUPS => cred::getgroups(Args([a.0[1], a.0[0], 0, 0, 0, 0])),
        nr::SETGROUPS => cred::set_groups(Args([a.0[1], a.0[0], 0, 0, 0, 0]), true),
        nr::KILL => super::linux::process::kill(a),
        nr::SETPGID => super::linux::process::setpgid(a),
        nr::GETPGID => super::linux::process::getpgid(a),
        nr::SETSID => super::linux::process::setsid(),
        nr::GETSID => super::linux::process::getsid(a),
        nr::SIGACTION => process::sigaction(a),
        nr::SIGMASK => super::linux::process::rt_sigprocmask(Args([a.0[0], a.0[1], a.0[2], 8, 0, 0])),
        nr::SIGRETURN => super::linux::process::rt_sigreturn(frame),
        // The same Linux-compatible identification as for Linux programs
        // (ADR 0031): the Utsname layout is the same.
        nr::UNAME => super::linux::process::uname(a),
        nr::SETHOSTNAME => super::linux::process::sethostname(a),
        nr::GETRANDOM => process::getrandom(a),
        nr::REBOOT => process::reboot(a),
        nr::KLOG => process::klog(a),
        nr::SERVICE => process::service(a),
        nr::SETIDS_OF => process::setids_of(a),
        nr::UNLOCK => process::unlock(a),
        nr::CRYPT_OPEN => process::crypt_open(a),
        nr::CRYPT_CLOSE => process::crypt_close(a),
        nr::DISCARD => process::discard(a),
        nr::CRYPT_WRAP => process::crypt_wrap(a),

        nr::MAP => process::map(a),
        nr::UNMAP => super::linux::mem::munmap(a),
        nr::PROTECT => process::protect(a),

        nr::CLOCK_GET => process::clock_get(a),
        nr::CLOCK_SET => process::clock_set(a),
        nr::RLIMIT => super::linux::process::prlimit64(super::linux::Args([0, a.0[0], a.0[1], a.0[2], 0, 0])),
        // getpriority(2) and setpriority(2) for one process (PRIO_PROCESS).
        nr::PRIORITY => {
            let before = super::linux::process::getpriority(super::linux::Args([0, a.0[0], 0, 0, 0, 0]))?;
            if a.0[1] != 0 {
                super::linux::process::setpriority(super::linux::Args([0, a.0[0], a.0[2], 0, 0, 0]))?;
            }
            Ok(before)
        }
        nr::CPU_TIMES => process::cpu_times(a),
        nr::CLOCK_ADJUST => process::clock_adjust(a),
        nr::SLEEP => super::linux::time::nanosleep(a),

        nr::SOCKET => files::socket(a),
        nr::BIND => net::bind(a),
        nr::LISTEN => net::listen(a),
        nr::CONNECT => net::connect(a),
        nr::ACCEPT => net::accept4(Args([a.0[0], a.0[1], a.0[2], u64::from(files::fd_flags(a.0[3] as u32)?), 0, 0])),
        nr::SENDTO => net::sendto(a),
        nr::RECVFROM => net::recvfrom(a),
        nr::SETSOCKOPT => net::setsockopt(a),
        nr::GETSOCKOPT => net::getsockopt(a),
        nr::SHUTDOWN => net::shutdown(a),
        nr::GETSOCKNAME => net::getsockname(a),
        nr::GETPEERNAME => net::getpeername(a),
        nr::SENDMSG => files::sendmsg(a),
        nr::RECVMSG => files::recvmsg(a),
        nr::SOCKETPAIR => files::socketpair(a),

        nr::THREAD_START => process::thread_start(a, frame),
        nr::THREAD_EXIT => super::linux::process::exit(a),
        nr::GETTID => super::linux::process::gettid(),
        nr::FUTEX_WAIT => process::futex_wait(a),
        nr::FUTEX_WAKE => process::futex_wake(a),
        nr::SET_TLS => process::set_tls(a),
        nr::XATTR_GET => files::xattr_get(a),
        nr::XATTR_SET => files::xattr_set(a),
        nr::XATTR_LIST => files::xattr_list(a),
        nr::XATTR_REMOVE => files::xattr_remove(a),
        nr::WATCH_OPEN => files::watch_open(a),
        nr::WATCH_ADD => files::watch_add(a),
        nr::WATCH_REMOVE => files::watch_remove(a),
        _ => unimplemented(n),
    }
}

/// Log one finished call for /proc/slate_strace, with path arguments
/// shown as strings.
fn log(n: u64, a: &Args, r: &Result) {
    let Some(p) = crate::proc::current() else { return };
    let mut s = String::new();
    let _ = write!(s, "strace {}/{} {}: native ", p.pid, crate::sched::current().tid, *p.name.lock());
    match nr::name(n) {
        Some(name) => s.push_str(name),
        None => {
            let _ = write!(s, "call_{n}");
        }
    }
    s.push('(');
    let paths = path_args(n);
    let mut i = 0;
    while i < 6 {
        if i > 0 {
            s.push_str(", ");
        }
        if paths.contains(&i) && i + 1 < 6 {
            match user_string(a.0[i], a.0[i + 1].min(200)) {
                Ok(text) => {
                    let _ = write!(s, "{text:?}, {}", a.0[i + 1]);
                }
                Err(_) => {
                    let _ = write!(s, "{:#x}, {}", a.0[i], a.0[i + 1]);
                }
            }
            i += 2;
            continue;
        }
        let _ = write!(s, "{:#x}", a.0[i]);
        i += 1;
    }
    let _ = match r {
        Ok(v) => write!(s, ") = {v:#x}"),
        Err(e) => write!(s, ") = -{}", e.0),
    };
    crate::log_info!("{s}");
}

/// Which arguments start a (pointer, length) path, for tracing.
fn path_args(n: u64) -> &'static [usize] {
    match n {
        nr::OPEN
        | nr::STAT
        | nr::MKDIR
        | nr::MKNOD
        | nr::UNLINK
        | nr::READLINK
        | nr::CHMOD
        | nr::CHOWN
        | nr::UTIMES
        | nr::ACCESS
        | nr::CHDIR
        | nr::CHROOT
        | nr::STATFS
        | nr::EXEC => &[1],
        nr::RENAME | nr::LINK => &[1, 4],
        nr::SYMLINK => &[0, 3],
        nr::UMOUNT | nr::SETHOSTNAME => &[0],
        _ => &[],
    }
}

/// Bytes passed as (pointer, length), lossily as text.
fn user_string(ptr: u64, len: u64) -> core::result::Result<String, Errno> {
    let mut buf = vec![0u8; len as usize];
    copy_from_user(&mut buf, ptr).map_err(|_| EFAULT)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// A path passed as (pointer, length). Paths are UTF-8 (as everywhere in
/// Slate's VFS) and may not contain NUL.
fn user_path(ptr: u64, len: u64) -> core::result::Result<String, Errno> {
    if len >= PATH_MAX as u64 {
        return Err(ENAMETOOLONG);
    }
    let mut buf = vec![0u8; len as usize];
    copy_from_user(&mut buf, ptr).map_err(|_| EFAULT)?;
    if buf.contains(&0) {
        return Err(EINVAL);
    }
    String::from_utf8(buf).map_err(|_| EINVAL)
}

/// The path in arguments `i` (pointer) and `i + 1` (length).
fn path(a: Args, i: usize) -> core::result::Result<String, Errno> {
    user_path(a.0[i], a.0[i + 1])
}

/// A path given as a [`Str`].
fn str_path(s: Str) -> core::result::Result<String, Errno> {
    user_path(s.ptr, s.len)
}

/// An array of `count` [`Str`]s at `addr`, each copied in; `limit` caps
/// the total bytes.
fn user_strs(addr: u64, count: u64, limit: usize) -> core::result::Result<Vec<Vec<u8>>, Errno> {
    if count > (limit / 16) as u64 {
        return Err(E2BIG);
    }
    let mut out = Vec::with_capacity(count as usize);
    let mut total = 0usize;
    for i in 0..count {
        let s: Str = read_user(addr + i * 16).map_err(|_| EFAULT)?;
        total = total.saturating_add(s.len as usize + 1);
        if total > limit {
            return Err(E2BIG);
        }
        let mut b = vec![0u8; s.len as usize];
        copy_from_user(&mut b, s.ptr).map_err(|_| EFAULT)?;
        if b.contains(&0) {
            return Err(EINVAL);
        }
        out.push(b);
    }
    Ok(out)
}

/// Translate `bits` through a (from, to) table; any bit outside the
/// table is an error.
fn translate(bits: u32, table: &[(u32, u64)]) -> core::result::Result<u64, Errno> {
    let known = table.iter().fold(0, |m, (n, _)| m | n);
    if bits & !known != 0 {
        return Err(EINVAL);
    }
    Ok(table.iter().filter(|(n, _)| bits & n != 0).fold(0, |m, (_, l)| m | l))
}
