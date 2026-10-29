// SPDX-License-Identifier: MIT OR Apache-2.0

//! The POSIX system interfaces: <unistd.h>, <fcntl.h>, <sys/stat.h>,
//! <sys/wait.h>, <sys/file.h>, <dirent.h>, <signal.h> and <time.h>, on
//! slate-rt.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::{VaList, c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr::null_mut;

use slate_rt::{Errno, fs, io, process};

use crate::{cstr, cstr_array, ret, set_errno};

// --- descriptors --------------------------------------------------------------

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, n: usize) -> isize {
    // SAFETY: C guarantees `n` writable bytes.
    let b = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, n) };
    match io::read(fd, b) {
        Ok(k) => k as isize,
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn write(fd: c_int, buf: *const c_void, n: usize) -> isize {
    // SAFETY: C guarantees `n` readable bytes.
    let b = unsafe { core::slice::from_raw_parts(buf as *const u8, n) };
    match io::write(fd, b) {
        Ok(k) => k as isize,
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn close(fd: c_int) -> c_int {
    ret(io::close(fd).map(|_| 0))
}

/// flock(2), <sys/file.h>.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn flock(fd: c_int, op: c_int) -> c_int {
    ret(slate_rt::fs::flock(fd, op as u32).map(|_| 0))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn lseek(fd: c_int, offset: c_long, whence: c_int) -> c_long {
    match io::lseek(fd, offset, whence as u32) {
        Ok(p) => p as c_long,
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pipe(fds: *mut c_int) -> c_int {
    match process::pipe(0) {
        Ok((r, w)) => {
            // SAFETY: C passes an array of two ints.
            unsafe {
                *fds = r;
                *fds.add(1) = w;
            }
            0
        }
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn dup(fd: c_int) -> c_int {
    ret(process::dup(fd))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn dup2(from: c_int, to: c_int) -> c_int {
    ret(process::dup2(from, to))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn isatty(fd: c_int) -> c_int {
    if slate_rt::term::isatty(fd) {
        1
    } else {
        set_errno(Errno::ENOTTY);
        0
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn ftruncate(fd: c_int, length: c_long) -> c_int {
    ret(fs::ftruncate(fd, length as u64).map(|_| 0))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn fsync(fd: c_int) -> c_int {
    ret(fs::fsync(fd).map(|_| 0))
}

// fcntl(2) commands (musl bits/fcntl.h), as in <fcntl.h>.
const F_DUPFD: c_int = 0;
const F_SETFD: c_int = 2;
const F_SETFL: c_int = 4;
const F_DUPFD_CLOEXEC: c_int = 1030;

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn fcntl(fd: c_int, cmd: c_int, mut args: ...) -> c_int {
    let arg = match cmd {
        // SAFETY: These commands take an int argument.
        F_DUPFD | F_SETFD | F_SETFL | F_DUPFD_CLOEXEC => (unsafe { args.next_arg::<c_int>() }) as usize,
        _ => 0,
    };
    ret(process::fcntl(fd, cmd as u32, arg))
}

const O_CREAT: c_int = 0o100;

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, mut args: ...) -> c_int {
    // SAFETY: The mode argument is there with O_CREAT (C's contract).
    let mode = if flags & O_CREAT != 0 { unsafe { args.next_arg::<c_uint>() } } else { 0 };
    // SAFETY: `path` is NUL-terminated.
    ret(fs::open(unsafe { cstr(path) }, flags as u32, mode))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn creat(path: *const c_char, mode: c_uint) -> c_int {
    use slate_rt::fs::{O_CREAT, O_TRUNC, O_WRONLY};
    // SAFETY: `path` is NUL-terminated.
    ret(fs::open(unsafe { cstr(path) }, O_CREAT | O_WRONLY | O_TRUNC, mode))
}

// --- paths ------------------------------------------------------------------

macro_rules! path_fn {
    ($name:ident, $rt:path $(, $arg:ident: $t:ty => $conv:expr)*) => {
        #[cfg_attr(target_os = "none", unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(path: *const c_char $(, $arg: $t)*) -> c_int {
            // SAFETY: `path` is NUL-terminated.
            ret($rt(unsafe { cstr(path) } $(, $conv)*).map(|_| 0))
        }
    };
}

path_fn!(unlink, fs::unlink);
path_fn!(rmdir, fs::rmdir);
path_fn!(chdir, fs::chdir);
path_fn!(mkdir, fs::mkdir, mode: c_uint => mode);
path_fn!(chmod, fs::chmod, mode: c_uint => mode);
path_fn!(access, fs::access, mode: c_int => mode as u32);
path_fn!(truncate, fs::truncate, length: c_long => length as u64);

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn link(target: *const c_char, name: *const c_char) -> c_int {
    // SAFETY: Both are NUL-terminated.
    ret(unsafe { fs::link(cstr(target), cstr(name)) }.map(|_| 0))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn symlink(target: *const c_char, name: *const c_char) -> c_int {
    // SAFETY: Both are NUL-terminated.
    ret(unsafe { fs::symlink(cstr(target), cstr(name)) }.map(|_| 0))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn readlink(path: *const c_char, buf: *mut c_char, n: usize) -> isize {
    // SAFETY: `path` is NUL-terminated.
    match fs::readlink(unsafe { cstr(path) }) {
        Ok(t) => {
            let k = t.len().min(n);
            // SAFETY: `buf` holds `n` bytes (no NUL is added, as POSIX says).
            unsafe { core::ptr::copy_nonoverlapping(t.as_ptr(), buf as *mut u8, k) };
            k as isize
        }
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn getcwd(buf: *mut c_char, n: usize) -> *mut c_char {
    let cwd = match fs::getcwd() {
        Ok(c) => c,
        Err(e) => {
            set_errno(e);
            return null_mut();
        }
    };
    // A null buffer gets one of the right size (as glibc and musl do).
    let (buf, n) = if buf.is_null() {
        let size = if n == 0 { cwd.len() + 1 } else { n };
        (crate::stdlib::malloc(size) as *mut c_char, size)
    } else {
        (buf, n)
    };
    if buf.is_null() {
        return null_mut();
    }
    if cwd.len() + 1 > n {
        set_errno(Errno::ERANGE);
        return null_mut();
    }
    // SAFETY: `buf` holds `n` bytes, enough for the path and its NUL.
    unsafe {
        core::ptr::copy_nonoverlapping(cwd.as_ptr(), buf as *mut u8, cwd.len());
        *buf.add(cwd.len()) = 0;
    }
    buf
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn umask(mask: c_uint) -> c_uint {
    fs::umask(mask)
}

/// Copy a slate-rt `Stat` into C's `struct stat`, which has the same
/// layout (both are musl's x86-64 `struct stat`).
fn put_stat(r: slate_rt::Result<fs::Stat>, out: *mut c_void) -> c_int {
    const _: () = assert!(size_of::<fs::Stat>() == 144);
    match r {
        Ok(st) => {
            // SAFETY: C passes a `struct stat`, 144 bytes like `fs::Stat`.
            unsafe { (out as *mut fs::Stat).write_unaligned(st) };
            0
        }
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn stat(path: *const c_char, st: *mut c_void) -> c_int {
    // SAFETY: `path` is NUL-terminated.
    put_stat(fs::stat(unsafe { cstr(path) }), st)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn lstat(path: *const c_char, st: *mut c_void) -> c_int {
    // SAFETY: `path` is NUL-terminated.
    put_stat(fs::lstat(unsafe { cstr(path) }), st)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn fstat(fd: c_int, st: *mut c_void) -> c_int {
    put_stat(fs::fstat(fd), st)
}

// --- directories --------------------------------------------------------------

/// `struct dirent` as <dirent.h> declares it.
#[repr(C)]
pub struct Dirent {
    d_ino: u64,
    d_off: i64,
    d_reclen: u16,
    d_type: u8,
    d_name: [u8; 256],
}

/// A C `DIR`: the entries, read at opendir, and the one handed out last.
pub struct Dir {
    entries: Vec<fs::DirEntry>,
    next: usize,
    current: Dirent,
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn opendir(path: *const c_char) -> *mut Dir {
    // SAFETY: `path` is NUL-terminated.
    let p = unsafe { cstr(path) };
    let listed = match fs::read_dir(p) {
        Ok(l) => l,
        Err(e) => {
            set_errno(e);
            return null_mut();
        }
    };
    // POSIX readdir also returns "." and "..".
    let ino = |q: &[u8]| fs::stat(q).map_or(0, |s| s.ino);
    let mut entries = alloc::vec![
        fs::DirEntry { ino: ino(p), name: b".".to_vec(), kind: 4 },
        fs::DirEntry { ino: ino(&fs::join(p, b"..")), name: b"..".to_vec(), kind: 4 },
    ];
    entries.extend(listed);
    let current = Dirent { d_ino: 0, d_off: 0, d_reclen: size_of::<Dirent>() as u16, d_type: 0, d_name: [0; 256] };
    Box::into_raw(Box::new(Dir { entries, next: 0, current }))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn readdir(d: *mut Dir) -> *mut Dirent {
    // SAFETY: `d` came from opendir.
    let d = unsafe { &mut *d };
    let Some(e) = d.entries.get(d.next) else { return null_mut() };
    d.next += 1;
    let n = e.name.len().min(255);
    d.current.d_ino = e.ino;
    d.current.d_off = d.next as i64;
    d.current.d_type = e.kind;
    d.current.d_name[..n].copy_from_slice(&e.name[..n]);
    d.current.d_name[n] = 0;
    &mut d.current
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn closedir(d: *mut Dir) -> c_int {
    // SAFETY: Made by Box::into_raw in opendir.
    drop(unsafe { Box::from_raw(d) });
    0
}

// --- processes --------------------------------------------------------------

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn fork() -> c_int {
    let r = process::fork();
    if r == Ok(0) {
        crate::pthread::after_fork();
    }
    ret(r)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn execve(path: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int {
    // SAFETY: C passes a NUL-terminated path and NULL-terminated arrays.
    let e = unsafe { process::execve(cstr(path), &cstr_array(argv), &cstr_array(envp)) };
    set_errno(e);
    -1
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn execv(path: *const c_char, argv: *const *const c_char) -> c_int {
    // SAFETY: As for execve; the environment is ours.
    let e = unsafe { process::execve(cstr(path), &cstr_array(argv), &crate::stdlib::env_vec()) };
    set_errno(e);
    -1
}

// The exec functions do not flush stdio buffers (POSIX: buffered output
// is lost); a forked child's buffers belong to its parent.

/// Run `file`, searched for in `$PATH` unless it has a slash.
fn exec_path(file: &[u8], argv: &[Vec<u8>]) -> c_int {
    let Some(path) = process::find_in_path(file) else {
        set_errno(Errno::ENOENT);
        return -1;
    };
    set_errno(process::execve(&path, argv, &crate::stdlib::env_vec()));
    -1
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int {
    // SAFETY: As for execve.
    unsafe { exec_path(cstr(file), &cstr_array(argv)) }
}

/// The NULL-terminated list of execl's arguments after `first`.
///
/// # Safety
///
/// The variable arguments must be C strings ending with a null pointer.
unsafe fn arg_list(first: *const c_char, args: &mut VaList<'_>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut p = first;
    while !p.is_null() {
        // SAFETY: Each argument is a C string (C's contract).
        unsafe {
            out.push(cstr(p).to_vec());
            p = args.next_arg::<usize>() as *const c_char;
        }
    }
    out
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn execl(path: *const c_char, arg: *const c_char, mut args: ...) -> c_int {
    // SAFETY: C's execl contract.
    let e = unsafe { process::execve(cstr(path), &arg_list(arg, &mut args), &crate::stdlib::env_vec()) };
    set_errno(e);
    -1
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn execlp(file: *const c_char, arg: *const c_char, mut args: ...) -> c_int {
    // SAFETY: C's execlp contract.
    unsafe { exec_path(cstr(file), &arg_list(arg, &mut args)) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn _exit(status: c_int) -> ! {
    process::exit_now(status)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int {
    match process::wait(pid, options as u32) {
        Ok((child, st)) => {
            if !status.is_null() && child != 0 {
                // SAFETY: C passes a place for the status.
                unsafe { *status = st };
            }
            child
        }
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn wait(status: *mut c_int) -> c_int {
    // SAFETY: As for waitpid.
    unsafe { waitpid(-1, status, 0) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn getpid() -> c_int {
    process::getpid()
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn getppid() -> c_int {
    process::getppid()
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn getuid() -> c_uint {
    process::getuid()
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn geteuid() -> c_uint {
    process::geteuid()
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn getgid() -> c_uint {
    process::getgid()
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn getegid() -> c_uint {
    process::getegid()
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn setuid(uid: c_uint) -> c_int {
    ret(process::setuid(uid).map(|_| 0))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn setgid(gid: c_uint) -> c_int {
    ret(process::setgid(gid).map(|_| 0))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn setsid() -> c_int {
    ret(process::setsid())
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn setpgid(pid: c_int, pgid: c_int) -> c_int {
    ret(process::setpgid(pid, pgid).map(|_| 0))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn getpgrp() -> c_int {
    process::getpgrp()
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn gethostname(name: *mut c_char, n: usize) -> c_int {
    let [_, node, ..] = process::uname();
    if node.len() + 1 > n {
        set_errno(Errno::ENAMETOOLONG);
        return -1;
    }
    // SAFETY: `name` holds `n` bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(node.as_ptr(), name as *mut u8, node.len());
        *name.add(node.len()) = 0;
    }
    0
}

// --- signals ------------------------------------------------------------------

/// SIG_ERR.
const SIG_ERR: usize = usize::MAX;

/// signal(2) with BSD semantics: the handler stays installed and
/// interrupted calls restart.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn signal(sig: c_int, handler: usize) -> usize {
    match slate_rt::signal::set_handler(sig, handler, true) {
        Ok(old) => old,
        Err(e) => {
            set_errno(e);
            SIG_ERR
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn kill(pid: c_int, sig: c_int) -> c_int {
    ret(process::kill(pid, sig).map(|_| 0))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn raise(sig: c_int) -> c_int {
    kill(process::getpid(), sig)
}

// --- time ---------------------------------------------------------------------

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn time(t: *mut c_long) -> c_long {
    let now = slate_rt::time::unix();
    if !t.is_null() {
        // SAFETY: C passes a place for the time.
        unsafe { *t = now };
    }
    now
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn clock_gettime(clock: c_int, ts: *mut [c_long; 2]) -> c_int {
    use slate_rt::time::{CLOCK_MONOTONIC, CLOCK_REALTIME};
    if clock as u32 != CLOCK_REALTIME && clock as u32 != CLOCK_MONOTONIC {
        set_errno(Errno::EINVAL);
        return -1;
    }
    let (s, ns) = slate_rt::time::now(clock as u32);
    // SAFETY: C passes a `struct timespec`.
    unsafe { *ts = [s, ns] };
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn nanosleep(req: *const [c_long; 2], _rem: *mut [c_long; 2]) -> c_int {
    // SAFETY: C passes a `struct timespec`.
    let [s, ns] = unsafe { *req };
    if s < 0 || !(0..1_000_000_000).contains(&ns) {
        set_errno(Errno::EINVAL);
        return -1;
    }
    if slate_rt::time::sleep_ns(s as u64 * 1_000_000_000 + ns as u64) {
        0
    } else {
        set_errno(Errno::EINTR);
        -1
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn sleep(seconds: c_uint) -> c_uint {
    if slate_rt::time::sleep_ns(u64::from(seconds) * 1_000_000_000) { 0 } else { seconds }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn usleep(usec: c_ulong) -> c_int {
    if slate_rt::time::sleep_ns(usec * 1000) {
        0
    } else {
        set_errno(Errno::EINTR);
        -1
    }
}
