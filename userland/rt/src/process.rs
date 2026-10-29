// SPDX-License-Identifier: MIT OR Apache-2.0

//! Processes: fork, exec, wait, exit, process groups, pipes and
//! descriptors.

use alloc::vec::Vec;

use slate_abi::nr;

use crate::errno::{Errno, Result};
use crate::fs::cpath;
use crate::sys;

/// Flush standard output and leave.
pub fn exit(code: i32) -> ! {
    crate::io::flush_stdout();
    exit_now(code)
}

/// Leave without flushing (after fork, in the child).
pub fn exit_now(code: i32) -> ! {
    loop {
        let _ = crate::syscall!(sys::pick(sys::EXIT_GROUP, nr::EXIT), code);
    }
}

pub fn fork() -> Result<i32> {
    crate::io::flush_stdout();
    crate::syscall!(sys::pick(sys::FORK, nr::FORK)).map(|p| p as i32)
}

/// Replace the program. Returns only on failure.
pub fn execve(path: &[u8], argv: &[Vec<u8>], envp: &[Vec<u8>]) -> Errno {
    if sys::native() {
        // Counted strings; entries with a NUL are dropped, as below.
        let strs = |v: &[Vec<u8>]| -> Vec<slate_abi::Str> {
            v.iter().filter(|s| !s.contains(&0)).map(|s| slate_abi::Str::new(s)).collect()
        };
        let (a, e) = (strs(argv), strs(envp));
        let args = slate_abi::ExecArgs {
            argv: a.as_ptr() as u64,
            argc: a.len() as u64,
            envp: e.as_ptr() as u64,
            envc: e.len() as u64,
        };
        if path.contains(&0) {
            return Errno::EINVAL;
        }
        crate::io::flush_stdout();
        let r = crate::syscall!(
            nr::EXEC as usize,
            slate_abi::CWD,
            path.as_ptr(),
            path.len(),
            &args as *const slate_abi::ExecArgs,
            0
        );
        return match r {
            Ok(_) => Errno::EINVAL,
            Err(e) => e,
        };
    }
    let Ok(p) = cpath(path) else { return Errno::EINVAL };
    let cargs: Vec<Vec<u8>> = argv.iter().filter_map(|a| cpath(a).ok()).collect();
    let cenv: Vec<Vec<u8>> = envp.iter().filter_map(|e| cpath(e).ok()).collect();
    let mut aptr: Vec<*const u8> = cargs.iter().map(|a| a.as_ptr()).collect();
    aptr.push(core::ptr::null());
    let mut eptr: Vec<*const u8> = cenv.iter().map(|e| e.as_ptr()).collect();
    eptr.push(core::ptr::null());
    crate::io::flush_stdout();
    match crate::syscall!(sys::EXECVE, p.as_ptr(), aptr.as_ptr(), eptr.as_ptr()) {
        Ok(_) => Errno::EINVAL,
        Err(e) => e,
    }
}

/// Find `name` in `$PATH` (names containing a slash are used as is).
pub fn find_in_path(name: &[u8]) -> Option<Vec<u8>> {
    if name.contains(&b'/') {
        return Some(name.to_vec());
    }
    let path = crate::env::var(b"PATH").unwrap_or_else(|| b"/bin:/sbin:/usr/bin:/usr/sbin".to_vec());
    for dir in path.split(|&c| c == b':') {
        let dir = if dir.is_empty() { &b"."[..] } else { dir };
        let cand = crate::fs::join(dir, name);
        if let Ok(st) = crate::fs::stat(&cand)
            && st.is_file()
            && st.mode & 0o111 != 0
        {
            return Some(cand);
        }
    }
    None
}

pub const WNOHANG: u32 = 1;
pub const WUNTRACED: u32 = 2;
pub const WCONTINUED: u32 = 8;

/// A native [`slate_abi::WaitStatus`] as a wait(2) status word.
fn status_word(w: &slate_abi::WaitStatus) -> i32 {
    use slate_abi::wait as k;
    match w.kind {
        k::EXITED => (w.code & 0xFF) << 8,
        k::KILLED => w.code & 0x7F,
        k::DUMPED => (w.code & 0x7F) | 0x80,
        k::STOPPED => ((w.code & 0xFF) << 8) | 0x7F,
        _ => 0xFFFF,
    }
}

/// wait4(2): (pid, status).
pub fn wait(pid: i32, options: u32) -> Result<(i32, i32)> {
    if sys::native() {
        use slate_abi::wait as k;
        let mut native = 0;
        for (l, n) in [(WNOHANG, k::NOHANG), (WUNTRACED, k::UNTRACED), (WCONTINUED, k::CONTINUED)] {
            if options & l != 0 {
                native |= n;
            }
        }
        let mut w = slate_abi::WaitStatus::default();
        loop {
            match crate::syscall!(nr::WAIT as usize, pid, &mut w as *mut slate_abi::WaitStatus, native) {
                Err(Errno::EINTR) => continue,
                Ok(0) => return Ok((0, 0)),
                Ok(p) => return Ok((p as i32, status_word(&w))),
                Err(e) => return Err(e),
            }
        }
    }
    let mut status: i32 = 0;
    loop {
        match crate::syscall!(sys::WAIT4, pid, &mut status as *mut i32, options, 0) {
            Err(Errno::EINTR) => continue,
            Ok(p) => return Ok((p as i32, status)),
            Err(e) => return Err(e),
        }
    }
}

/// Decoding wait statuses (wait(2) macros).
pub fn exited(status: i32) -> Option<i32> {
    (status & 0x7F == 0).then_some((status >> 8) & 0xFF)
}
pub fn signaled(status: i32) -> Option<i32> {
    let s = status & 0x7F;
    (s != 0 && s != 0x7F).then_some(s)
}
pub fn stopped(status: i32) -> Option<i32> {
    (status & 0xFF == 0x7F).then_some((status >> 8) & 0xFF)
}
pub fn continued(status: i32) -> bool {
    status == 0xFFFF
}

/// The shell-style exit code of a wait status (128 + signal).
pub fn exit_code(status: i32) -> i32 {
    exited(status).or_else(|| signaled(status).map(|s| 128 + s)).unwrap_or(1)
}

pub fn getpid() -> i32 {
    crate::syscall!(sys::pick(sys::GETPID, nr::GETPID)).unwrap_or(0) as i32
}
pub fn getppid() -> i32 {
    crate::syscall!(sys::pick(sys::GETPPID, nr::GETPPID)).unwrap_or(0) as i32
}

/// The native IDs (all zero if the call fails, as the Linux calls cannot).
fn ids() -> slate_abi::Ids {
    let mut ids = slate_abi::Ids::default();
    let _ = crate::syscall!(nr::GETIDS as usize, &mut ids as *mut slate_abi::Ids);
    ids
}

pub fn getuid() -> u32 {
    if sys::native() {
        return ids().ruid;
    }
    crate::syscall!(sys::GETUID).unwrap_or(0) as u32
}
pub fn geteuid() -> u32 {
    if sys::native() {
        return ids().euid;
    }
    crate::syscall!(sys::GETEUID).unwrap_or(0) as u32
}
pub fn getgid() -> u32 {
    if sys::native() {
        return ids().rgid;
    }
    crate::syscall!(sys::GETGID).unwrap_or(0) as u32
}
pub fn getegid() -> u32 {
    if sys::native() {
        return ids().egid;
    }
    crate::syscall!(sys::GETEGID).unwrap_or(0) as u32
}

pub fn getgroups() -> Vec<u32> {
    let mut g = alloc::vec![0u32; 256];
    let n = if sys::native() {
        crate::syscall!(nr::GETGROUPS as usize, g.as_mut_ptr(), g.len())
    } else {
        crate::syscall!(sys::GETGROUPS, g.len(), g.as_mut_ptr())
    };
    g.truncate(n.unwrap_or(0));
    g
}

/// setuid(2)/setgid(2) natively: all three IDs with privilege, only the
/// effective one without (as POSIX setuid does).
fn set_ids(user: bool, id: u32) -> Result<()> {
    let privileged = if user { geteuid() == 0 } else { geteuid() == 0 || getegid() == 0 };
    let n = slate_abi::NO_ID;
    let (r, e, s) = if privileged { (id, id, id) } else { (n, id, n) };
    let ids = if user {
        slate_abi::Ids { ruid: r, euid: e, suid: s, rgid: n, egid: n, sgid: n }
    } else {
        slate_abi::Ids { ruid: n, euid: n, suid: n, rgid: r, egid: e, sgid: s }
    };
    crate::syscall!(nr::SETIDS as usize, &ids as *const slate_abi::Ids).map(|_| ())
}

pub fn setuid(uid: u32) -> Result<()> {
    if sys::native() {
        return set_ids(true, uid);
    }
    crate::syscall!(sys::SETUID, uid).map(|_| ())
}
pub fn setgid(gid: u32) -> Result<()> {
    if sys::native() {
        return set_ids(false, gid);
    }
    crate::syscall!(sys::SETGID, gid).map(|_| ())
}
pub fn setgroups(groups: &[u32]) -> Result<()> {
    if sys::native() {
        return crate::syscall!(nr::SETGROUPS as usize, groups.as_ptr(), groups.len()).map(|_| ());
    }
    crate::syscall!(sys::SETGROUPS, groups.len(), groups.as_ptr()).map(|_| ())
}

pub fn kill(pid: i32, sig: i32) -> Result<()> {
    crate::syscall!(sys::pick(sys::KILL, nr::KILL), pid, sig).map(|_| ())
}

/// Process `pid`'s nice value (-20 to 19; 0 for the caller).
pub fn nice_of(pid: i32) -> Result<i32> {
    // Both interfaces answer 20 − nice (getpriority(2)'s raw value).
    let raw = if sys::native() {
        crate::syscall!(nr::PRIORITY as usize, pid, 0, 0)?
    } else {
        // PRIO_PROCESS is 0 (sys/resource.h).
        crate::syscall!(sys::GETPRIORITY, 0, pid)?
    };
    Ok(20 - raw as i32)
}

/// Set process `pid`'s nice value (setpriority(2)'s rules).
pub fn set_nice(pid: i32, nice: i32) -> Result<()> {
    if sys::native() {
        return crate::syscall!(nr::PRIORITY as usize, pid, 1, nice as isize as usize).map(|_| ());
    }
    crate::syscall!(sys::SETPRIORITY, 0, pid, nice as isize as usize).map(|_| ())
}

pub fn setpgid(pid: i32, pgid: i32) -> Result<()> {
    crate::syscall!(sys::pick(sys::SETPGID, nr::SETPGID), pid, pgid).map(|_| ())
}
pub fn getpgrp() -> i32 {
    if sys::native() {
        return crate::syscall!(nr::GETPGID as usize, 0).unwrap_or(0) as i32;
    }
    crate::syscall!(sys::GETPGRP).unwrap_or(0) as i32
}
pub fn setsid() -> Result<i32> {
    crate::syscall!(sys::pick(sys::SETSID, nr::SETSID)).map(|s| s as i32)
}

/// A resource limit (setrlimit(2): Linux's `RLIMIT_*` numbers, from musl
/// `sys/resource.h`): (current, maximum), `u64::MAX` for none.
pub fn getrlimit(resource: u32) -> Result<(u64, u64)> {
    let mut l = [0u64; 2];
    if sys::native() {
        crate::syscall!(nr::RLIMIT as usize, resource, 0usize, l.as_mut_ptr())?;
    } else {
        crate::syscall!(sys::PRLIMIT64, 0, resource, 0usize, l.as_mut_ptr())?;
    }
    Ok((l[0], l[1]))
}

pub fn setrlimit(resource: u32, cur: u64, max: u64) -> Result<()> {
    let l = [cur, max];
    if sys::native() {
        crate::syscall!(nr::RLIMIT as usize, resource, l.as_ptr(), 0usize).map(|_| ())
    } else {
        crate::syscall!(sys::PRLIMIT64, 0, resource, l.as_ptr(), 0usize).map(|_| ())
    }
}

/// CPU time used, in nanoseconds: (user, system) of this process and of
/// its waited-for children.
pub fn cpu_times() -> Result<[u64; 4]> {
    if sys::native() {
        let mut t = [0u64; 4];
        crate::syscall!(nr::CPU_TIMES as usize, t.as_mut_ptr())?;
        return Ok(t);
    }
    // getrusage(2): `struct rusage` begins with two timevals.
    let mut out = [0u64; 4];
    for (i, who) in [0i64, -1].into_iter().enumerate() {
        let mut ru = [0i64; 18];
        crate::syscall!(sys::GETRUSAGE, who, ru.as_mut_ptr())?;
        out[2 * i] = (ru[0] * 1_000_000_000 + ru[1] * 1000) as u64;
        out[2 * i + 1] = (ru[2] * 1_000_000_000 + ru[3] * 1000) as u64;
    }
    Ok(out)
}

/// getsid(2): the session of `pid` (0: the caller).
pub fn getsid(pid: i32) -> Result<i32> {
    crate::syscall!(sys::pick(sys::GETSID, nr::GETSID), pid).map(|s| s as i32)
}

/// pipe2(2): (read end, write end).
pub fn pipe(flags: u32) -> Result<(i32, i32)> {
    let mut fds = [0i32; 2];
    let flags = if sys::native() { sys::open_flags_native(flags)? } else { flags };
    crate::syscall!(sys::pick(sys::PIPE2, nr::PIPE), fds.as_mut_ptr(), flags)?;
    Ok((fds[0], fds[1]))
}

pub fn dup(fd: i32) -> Result<i32> {
    if sys::native() {
        return crate::syscall!(nr::DUP as usize, fd, -1i32, 0).map(|f| f as i32);
    }
    crate::syscall!(sys::DUP, fd).map(|f| f as i32)
}

pub fn dup2(from: i32, to: i32) -> Result<i32> {
    if from == to {
        return Ok(to);
    }
    if sys::native() {
        return crate::syscall!(nr::DUP as usize, from, to, 0).map(|f| f as i32);
    }
    crate::syscall!(sys::DUP2, from, to).map(|f| f as i32)
}

pub const F_DUPFD_CLOEXEC: u32 = 1030;
pub const F_GETFD: u32 = 1;
pub const F_SETFD: u32 = 2;
pub const F_GETFL: u32 = 3;
pub const F_SETFL: u32 = 4;
pub const FD_CLOEXEC: usize = 1;

/// fcntl(2) with the commands above. Status flags are `O_*` values on
/// both interfaces (translated natively).
pub fn fcntl(fd: i32, cmd: u32, arg: usize) -> Result<usize> {
    if sys::native() {
        use slate_abi::fcntl as c;
        let n = |cmd: u32, arg: usize| crate::syscall!(nr::FCNTL as usize, fd, cmd, arg);
        return match cmd {
            F_DUPFD_CLOEXEC => n(c::DUPFD_CLOEXEC, arg),
            0 => n(c::DUPFD, arg),
            F_GETFD => n(c::GETFD, 0),
            F_SETFD => n(c::SETFD, arg & FD_CLOEXEC),
            F_GETFL => n(c::GETFL, 0).map(|f| sys::open_flags_linux(f as u32) as usize),
            F_SETFL => n(c::SETFL, sys::open_flags_native(arg as u32 & !3)? as usize),
            _ => Err(Errno::EINVAL),
        };
    }
    crate::syscall!(sys::FCNTL, fd, cmd, arg)
}

/// Run `path` with `argv` and wait for it; returns the wait status.
pub fn run(path: &[u8], argv: &[Vec<u8>]) -> Result<i32> {
    let pid = fork()?;
    if pid == 0 {
        let e = execve(path, argv, crate::env::vars());
        crate::eprintln!("{}: {}", alloc::string::String::from_utf8_lossy(path), e);
        exit_now(127);
    }
    wait(pid, 0).map(|(_, s)| s)
}

/// Fill `buf` from the kernel's random number generator (getrandom(2)).
pub fn random(buf: &mut [u8]) -> Result<()> {
    let mut done = 0;
    while done < buf.len() {
        match crate::syscall!(sys::pick(sys::GETRANDOM, nr::GETRANDOM), buf[done..].as_mut_ptr(), buf.len() - done, 0) {
            Ok(n) => done += n,
            Err(Errno::EINTR) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// The name of the terminal on `fd`, from /proc/self/fd.
pub fn ttyname(fd: i32) -> Option<Vec<u8>> {
    if !crate::term::isatty(fd) {
        return None;
    }
    crate::fs::readlink(alloc::format!("/proc/self/fd/{fd}").as_bytes()).ok()
}

/// reboot(2) commands (musl `sys/reboot.h`).
pub const RB_AUTOBOOT: u32 = 0x0123_4567;
pub const RB_HALT_SYSTEM: u32 = 0xcdef_0123;
pub const RB_POWER_OFF: u32 = 0x4321_fedc;

/// Ctrl-Alt-Del: restart at once (`true`, the kernel's default) or send
/// init SIGINT (reboot(2)'s CAD_ON and CAD_OFF).
pub fn set_ctrl_alt_del(restart: bool) -> Result<()> {
    if sys::native() {
        use slate_abi::reboot as r;
        crate::syscall!(nr::REBOOT as usize, if restart { r::CAD_ON } else { r::CAD_OFF })?;
    } else {
        crate::syscall!(sys::REBOOT, 0xfee1_deadusize, 672_274_793usize, if restart { 0x89ab_cdefusize } else { 0 })?;
    }
    Ok(())
}

/// Put init's child `pid` in service `name` (ADR 0060; Slate only).
pub fn set_service(pid: i32, name: &[u8]) -> Result<()> {
    if !sys::native() {
        return Err(Errno::ENOSYS);
    }
    crate::syscall!(nr::SERVICE as usize, slate_abi::service::SET, pid, name.as_ptr(), name.len())?;
    Ok(())
}

/// Signal every process of service `name` → how many there were.
pub fn kill_service(name: &[u8], sig: i32) -> Result<usize> {
    if !sys::native() {
        return Err(Errno::ENOSYS);
    }
    crate::syscall!(nr::SERVICE as usize, slate_abi::service::KILL, name.as_ptr(), name.len(), sig)
}

/// Whole lines of the kernel log written since `*pos`, which moves past
/// them (ADR 0060; Slate only) → bytes in `buf`.
pub fn kernel_log_from(buf: &mut [u8], pos: &mut u64) -> Result<usize> {
    if !sys::native() {
        return Err(Errno::ENOSYS);
    }
    crate::syscall!(nr::KLOG as usize, slate_abi::klog::READ_FROM, buf.as_mut_ptr(), buf.len(), pos as *mut u64)
}

/// reboot(2) with the magic numbers; returns only on failure.
pub fn reboot(cmd: u32) -> Errno {
    let r = if sys::native() {
        use slate_abi::reboot as r;
        let native = match cmd {
            RB_AUTOBOOT => r::RESTART,
            RB_HALT_SYSTEM => r::HALT,
            RB_POWER_OFF => r::POWER_OFF,
            _ => return Errno::EINVAL,
        };
        crate::syscall!(nr::REBOOT as usize, native)
    } else {
        crate::syscall!(sys::REBOOT, 0xfee1_deadusize, 672_274_793usize, cmd)
    };
    match r {
        Ok(_) => Errno::EINVAL,
        Err(e) => e,
    }
}

/// uname(2) fields: sysname, nodename, release, version, machine. (The
/// native `Utsname` has the same layout; its sysname is "Slate".)
pub fn uname() -> [Vec<u8>; 5] {
    let mut buf = [0u8; 65 * 6];
    let _ = crate::syscall!(sys::pick(sys::UNAME, nr::UNAME), buf.as_mut_ptr());
    let field = |i: usize| {
        let f = &buf[i * 65..(i + 1) * 65];
        f[..f.iter().position(|&b| b == 0).unwrap_or(65)].to_vec()
    };
    [field(0), field(1), field(2), field(3), field(4)]
}

pub fn sethostname(name: &[u8]) -> Result<()> {
    crate::syscall!(sys::pick(sys::SETHOSTNAME, nr::SETHOSTNAME), name.as_ptr(), name.len()).map(|_| ())
}

/// Give process `pid` user `uid`, group `gid` and supplementary
/// `groups` (native setids_of, ADR 0032): the privilege broker's grant.
/// Slate only (ENOSYS on Linux).
pub fn setids_of(pid: i32, uid: u32, gid: u32, groups: &[u32]) -> Result<()> {
    if !sys::native() {
        return Err(Errno::ENOSYS);
    }
    let ids = slate_abi::Ids { ruid: uid, euid: uid, suid: uid, rgid: gid, egid: gid, sgid: gid };
    crate::syscall!(nr::SETIDS_OF as usize, pid, &ids as *const slate_abi::Ids, groups.as_ptr(), groups.len())
        .map(|_| ())
}

/// unshare(2) flags. Source: musl `sched.h`.
pub const CLONE_NEWNS: usize = 0x0002_0000;
pub const CLONE_NEWUSER: usize = 0x1000_0000;

/// unshare(2): new namespaces of the kinds `flags` names. Linux interface
/// only (ENOSYS natively: Slate programs don't make namespaces yet).
pub fn unshare(flags: usize) -> Result<()> {
    if sys::native() {
        return Err(Errno::ENOSYS);
    }
    crate::syscall!(sys::UNSHARE, flags).map(|_| ())
}

/// Hand the kernel the key that opens key slot `slot` of the encrypted
/// root it is unlocking at boot (native unlock, ADR 0038). EACCES if the
/// key does not open the slot, EAGAIN if the kernel is not ready yet.
/// Slate only (ENOSYS on Linux).
pub fn unlock(slot: usize, key: &[u8; 32]) -> Result<()> {
    if !sys::native() {
        return Err(Errno::ENOSYS);
    }
    crate::syscall!(nr::UNLOCK as usize, slot, key.as_ptr(), key.len()).map(|_| ())
}

/// Open the encrypted partition `fd` is open on with the key for key slot
/// `slot` (native crypt_open, ADR 0039): the mapped device's number N
/// (`/dev/dm-N`). Slate only (ENOSYS on Linux).
pub fn crypt_open(fd: i32, slot: usize, key: &[u8; 32]) -> Result<u32> {
    if !sys::native() {
        return Err(Errno::ENOSYS);
    }
    crate::syscall!(nr::CRYPT_OPEN as usize, fd, slot, key.as_ptr(), key.len()).map(|n| n as u32)
}

/// `dm-N`'s master key wrapped under `key`, for a new key slot (native
/// crypt_wrap, ADR 0058). Slate only (ENOSYS on Linux).
pub fn crypt_wrap(n: u32, key: &[u8; 32]) -> Result<[u8; 72]> {
    if !sys::native() {
        return Err(Errno::ENOSYS);
    }
    let mut out = [0u8; 72];
    crate::syscall!(nr::CRYPT_WRAP as usize, n, key.as_ptr(), key.len(), out.as_mut_ptr(), out.len())?;
    Ok(out)
}

/// Discard `len` bytes at `offset` of the block device `fd` is open on
/// (native discard, ADR 0039): TRIM. Slate only (ENOSYS on Linux).
pub fn discard(fd: i32, offset: u64, len: u64) -> Result<()> {
    if !sys::native() {
        return Err(Errno::ENOSYS);
    }
    crate::syscall!(nr::DISCARD as usize, fd, offset, len).map(|_| ())
}

/// Close mapped device `dm-N` (native crypt_close). Slate only.
pub fn crypt_close(n: u32) -> Result<()> {
    if !sys::native() {
        return Err(Errno::ENOSYS);
    }
    crate::syscall!(nr::CRYPT_CLOSE as usize, n).map(|_| ())
}

/// Operations on the kernel log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelLog {
    /// Copy the log into the buffer.
    ReadAll,
    /// Copy it, then empty it.
    ReadClear,
    /// Empty it.
    Clear,
    /// The log's size.
    Size,
}

/// The kernel log (syslog(2) actions 3, 4, 5 and 10; native klog).
pub fn kernel_log(op: KernelLog, buf: &mut [u8]) -> Result<usize> {
    if sys::native() {
        use slate_abi::klog as k;
        let op = match op {
            KernelLog::ReadAll => k::READ_ALL,
            KernelLog::ReadClear => k::READ_CLEAR,
            KernelLog::Clear => k::CLEAR,
            KernelLog::Size => k::SIZE,
        };
        return crate::syscall!(nr::KLOG as usize, op, buf.as_mut_ptr(), buf.len());
    }
    let action: usize = match op {
        KernelLog::ReadAll => 3,
        KernelLog::ReadClear => 4,
        KernelLog::Clear => 5,
        KernelLog::Size => 10,
    };
    crate::syscall!(sys::SYSLOG, action, buf.as_mut_ptr(), buf.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_wait_status_decodes_like_linux() {
        use slate_abi::wait as k;
        let w = |kind, code| status_word(&slate_abi::WaitStatus { pid: 1, kind, code, _reserved: 0 });
        assert_eq!(exited(w(k::EXITED, 3)), Some(3));
        assert_eq!(signaled(w(k::KILLED, 9)), Some(9));
        assert_eq!(signaled(w(k::DUMPED, 11)), Some(11));
        assert_eq!(stopped(w(k::STOPPED, 20)), Some(20));
        assert!(continued(w(k::CONTINUED_KIND, 0)));
    }
}
