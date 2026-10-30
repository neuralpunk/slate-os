// SPDX-License-Identifier: MIT OR Apache-2.0

//! Raw system calls. Both interfaces use the same convention (number in
//! rax, arguments in rdi, rsi, rdx, r10, r8, r9; result in rax, `-errno`
//! on failure). On Slate, a program built with [`program!`](crate::program)
//! carries the native ABI note and gets Slate's native interface
//! (ADR 0031, numbers in `slate_abi::nr`); on Linux it makes Linux calls.
//! [`native`] says which, and every wrapper in this crate picks its call
//! accordingly. Linux numbers from musl `bits/syscall.h` (ADR 0009).

use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::errno::Errno;

static NATIVE: AtomicBool = AtomicBool::new(false);

/// Whether this process uses Slate's native interface (decided at start:
/// the kernel passed `AT_SLATE_ABI`).
#[inline]
pub fn native() -> bool {
    NATIVE.load(Ordering::Relaxed)
}

pub(crate) fn set_native() {
    NATIVE.store(true, Ordering::Relaxed);
}

/// The call number for this process's interface.
#[inline]
pub(crate) fn pick(linux: usize, native_nr: u64) -> usize {
    if native() { native_nr as usize } else { linux }
}

/// slate-rt's `O_*` flags (Linux values) and the native `open::*` ones.
const OPEN_FLAGS: &[(u32, u32)] = &[
    (crate::fs::O_CREAT, slate_abi::open::CREATE),
    (crate::fs::O_EXCL, slate_abi::open::EXCL),
    (crate::fs::O_TRUNC, slate_abi::open::TRUNC),
    (crate::fs::O_APPEND, slate_abi::open::APPEND),
    (crate::fs::O_NONBLOCK, slate_abi::open::NONBLOCK),
    (crate::fs::O_CLOEXEC, slate_abi::open::CLOEXEC),
    (crate::fs::O_DIRECTORY, slate_abi::open::DIRECTORY),
    (crate::fs::O_NOFOLLOW, slate_abi::open::NOFOLLOW),
    (crate::fs::O_NOCTTY, slate_abi::open::NOCTTY),
    // O_DSYNC is part of O_SYNC; both are the native SYNC (data and the
    // metadata needed to read it back).
    (crate::fs::O_SYNC, slate_abi::open::SYNC),
    (crate::fs::O_DIRECT, slate_abi::open::DIRECT),
    (crate::fs::O_NOATIME, slate_abi::open::NOATIME),
];

/// `O_*` flags as native `open::*` flags. The access modes have the same
/// values; unknown flags are an error.
pub(crate) fn open_flags_native(f: u32) -> Result<u32, Errno> {
    let mut out = f & 3;
    let mut rest = f & !3;
    for &(linux, native) in OPEN_FLAGS {
        if f & linux != 0 {
            out |= native;
            rest &= !linux;
        }
    }
    if rest != 0 { Err(Errno::EINVAL) } else { Ok(out) }
}

/// Native `open::*` flags as `O_*` flags.
pub(crate) fn open_flags_linux(f: u32) -> u32 {
    OPEN_FLAGS.iter().filter(|(_, n)| f & n != 0).fold(f & 3, |m, (l, _)| m | l)
}

pub const READ: usize = 0;
pub const WRITE: usize = 1;
pub const OPEN: usize = 2;
pub const CLOSE: usize = 3;
pub const STAT: usize = 4;
pub const FSTAT: usize = 5;
pub const LSTAT: usize = 6;
pub const POLL: usize = 7;
pub const LSEEK: usize = 8;
pub const MMAP: usize = 9;
pub const MUNMAP: usize = 11;
pub const RT_SIGACTION: usize = 13;
pub const RT_SIGPROCMASK: usize = 14;
pub const IOCTL: usize = 16;
pub const PREAD64: usize = 17;
pub const PWRITE64: usize = 18;
pub const ACCESS: usize = 21;
pub const PIPE2: usize = 293;
pub const DUP: usize = 32;
pub const DUP2: usize = 33;
pub const NANOSLEEP: usize = 35;
pub const GETPID: usize = 39;
pub const SENDFILE: usize = 40;
pub const SOCKET: usize = 41;
pub const CONNECT: usize = 42;
pub const FORK: usize = 57;
pub const EXECVE: usize = 59;
pub const EXIT: usize = 60;
pub const WAIT4: usize = 61;
pub const KILL: usize = 62;
pub const UNAME: usize = 63;
/// getpriority(2) and setpriority(2) (musl's arch/x86_64/bits/syscall.h).
pub const GETPRIORITY: usize = 140;
pub const SETPRIORITY: usize = 141;
pub const FCNTL: usize = 72;
pub const FLOCK: usize = 73;
pub const FSYNC: usize = 74;
pub const TRUNCATE: usize = 76;
pub const FTRUNCATE: usize = 77;
pub const FSETXATTR: usize = 190;
pub const FGETXATTR: usize = 193;
pub const FLISTXATTR: usize = 196;
pub const FREMOVEXATTR: usize = 199;
pub const INOTIFY_ADD_WATCH: usize = 254;
pub const INOTIFY_RM_WATCH: usize = 255;
pub const INOTIFY_INIT1: usize = 294;
pub const GETCWD: usize = 79;
pub const CHDIR: usize = 80;
pub const FCHDIR: usize = 81;
pub const RENAME: usize = 82;
pub const MKDIR: usize = 83;
pub const RMDIR: usize = 84;
pub const LINK: usize = 86;
pub const UNLINK: usize = 87;
pub const SYMLINK: usize = 88;
pub const READLINK: usize = 89;
pub const CHMOD: usize = 90;
pub const FCHMOD: usize = 91;
pub const CHOWN: usize = 92;
pub const LCHOWN: usize = 94;
pub const UMASK: usize = 95;
pub const GETTIMEOFDAY: usize = 96;
pub const SYSINFO: usize = 99;
pub const GETUID: usize = 102;
pub const GETGID: usize = 104;
pub const SETUID: usize = 105;
pub const SETGID: usize = 106;
pub const SETRESUID: usize = 117;
pub const SETRESGID: usize = 119;
pub const GETEUID: usize = 107;
pub const GETEGID: usize = 108;
pub const SETPGID: usize = 109;
pub const SYSLOG: usize = 103;
pub const GETPPID: usize = 110;
pub const GETPGRP: usize = 111;
pub const SETSID: usize = 112;
pub const SETGROUPS: usize = 116;
pub const GETGROUPS: usize = 115;
pub const GETPGID: usize = 121;
pub const GETSID: usize = 124;
pub const GETRUSAGE: usize = 98;
pub const PRLIMIT64: usize = 302;
pub const MKNOD: usize = 133;
pub const STATFS: usize = 137;
pub const PRCTL: usize = 157;
pub const CHROOT: usize = 161;
pub const SYNC: usize = 162;
pub const MOUNT: usize = 165;
pub const UMOUNT2: usize = 166;
pub const REBOOT: usize = 169;
pub const SETHOSTNAME: usize = 170;
pub const UNSHARE: usize = 272;
pub const PIVOT_ROOT: usize = 155;
pub const GETDENTS64: usize = 217;
pub const CLOCK_SETTIME: usize = 227;
pub const ADJTIMEX: usize = 159;
pub const CLOCK_GETTIME: usize = 228;
pub const EXIT_GROUP: usize = 231;
pub const UTIMENSAT: usize = 280;
pub const DUP3: usize = 292;
pub const GETRANDOM: usize = 318;
pub const BIND: usize = 49;
pub const LISTEN: usize = 50;
pub const ACCEPT4: usize = 288;
pub const SETSOCKOPT: usize = 54;
pub const GETSOCKOPT: usize = 55;
pub const SENDTO: usize = 44;
pub const RECVFROM: usize = 45;
pub const SENDMSG: usize = 46;
pub const RECVMSG: usize = 47;
pub const MPROTECT: usize = 10;
pub const CLONE: usize = 56;
pub const ARCH_PRCTL: usize = 158;
pub const GETTID: usize = 186;
pub const FUTEX: usize = 202;
pub const SHUTDOWN: usize = 48;
pub const GETSOCKNAME: usize = 51;
pub const GETPEERNAME: usize = 52;
pub const SOCKETPAIR: usize = 53;

/// # Safety
///
/// The arguments must be valid for system call `nr` (pointers to memory
/// the kernel may read or write as that call does).
#[inline]
pub(crate) unsafe fn syscall6(nr: usize, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> isize {
    let r: isize;
    // SAFETY: The caller guarantees the arguments are valid for `nr`; the
    // kernel clobbers only rcx and r11.
    unsafe {
        asm!("syscall", inlateout("rax") nr as isize => r, in("rdi") a, in("rsi") b, in("rdx") c,
             in("r10") d, in("r8") e, in("r9") f, lateout("rcx") _, lateout("r11") _, options(nostack))
    };
    r
}

/// A system call returning a non-negative value or `-errno`.
///
/// # Safety
///
/// As for [`syscall6`].
#[inline]
pub(crate) unsafe fn call(nr: usize, args: [usize; 6]) -> Result<usize, Errno> {
    // SAFETY: Forwarded from the caller.
    let r = unsafe { syscall6(nr, args[0], args[1], args[2], args[3], args[4], args[5]) };
    if (-4095..0).contains(&r) { Err(Errno(-r as i32)) } else { Ok(r as usize) }
}

/// System call wrapper taking up to six arguments; the number must be
/// right for this process's interface (see [`pick`]).
macro_rules! syscall {
    ($nr:expr $(, $a:expr)* $(,)?) => {{
        #[allow(unused_mut)]
        let mut args = [0usize; 6];
        let mut _i = 0;
        $( args[_i] = $a as usize; _i += 1; )*
        let nr: usize = $nr;
        // SAFETY: Each wrapper passes arguments valid for its call.
        unsafe { $crate::sys::call(nr, args) }
    }};
}
pub(crate) use syscall;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::*;

    #[test]
    fn open_flags_translate_both_ways() {
        let f = O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW | O_DIRECT | O_NOATIME;
        let n = open_flags_native(f).unwrap();
        assert_eq!(n & slate_abi::open::ACCESS_MASK, slate_abi::open::READ_WRITE);
        assert_ne!(n & slate_abi::open::CREATE, 0);
        assert_ne!(n & slate_abi::open::DIRECT, 0);
        assert_eq!(open_flags_linux(n), f);
        // A flag slate-rt does not know is refused, not dropped (O_ASYNC,
        // musl `bits/fcntl.h`).
        assert_eq!(open_flags_native(0o20000), Err(Errno::EINVAL));
    }

    #[test]
    fn note_in_program_matches_slate_abi() {
        // program! writes namesz 6 ("Slate\0"), descsz 4, type 1, version 1.
        assert_eq!(slate_abi::NOTE_NAME, b"Slate");
        assert_eq!(slate_abi::NT_SLATE_ABI, 1);
        assert_eq!(slate_abi::VERSION, 1);
    }
}
