// SPDX-License-Identifier: MIT OR Apache-2.0

//! seccomp filters over native calls (ADR 0097). Filters are written for
//! Linux's x86-64 calls, so a native call is shown to them as the Linux
//! call it amounts to: Linux's number (musl `bits/syscall.h`), its
//! arguments in Linux's order with Linux's flag values, and
//! AUDIT_ARCH_X86_64. A path argument (pointer and length) becomes its
//! pointer alone, as in the Linux call. A native call with no Linux
//! counterpart is shown with the x32 bit (`__X32_SYSCALL_BIT`, 0x40000000)
//! and its native number: filters that do not expect x32 calls refuse it,
//! the others decide by their default.

use slate_abi::nr;

use super::super::linux::Args;
use super::files::{fd_flags, open_flags};

/// The x32 bit (syscall(2)), for calls Linux has no counterpart of.
const SLATE_ONLY: u64 = 0x4000_0000;

// Linux's thread-creation flags, as `clone` for pthread_create (clone(2)).
const CLONE_THREAD_FLAGS: u64 = 0x0001_0000 // CLONE_THREAD
    | 0x0000_0100 // CLONE_VM
    | 0x0000_0200 // CLONE_FS
    | 0x0000_0400 // CLONE_FILES
    | 0x0000_0800 // CLONE_SIGHAND
    | 0x0004_0000 // CLONE_SYSVSEM
    | 0x0008_0000 // CLONE_SETTLS
    | 0x0020_0000 // CLONE_CHILD_CLEARTID
    | 0x0100_0000; // CLONE_CHILD_SETTID

/// The Linux call native call `n` with arguments `a` amounts to.
pub fn linux_view(n: u64, a: &Args) -> (u64, [u64; 6]) {
    let x = a.0;
    // (dir, path, len, rest...) -> (dir, path, rest...).
    let at = [x[0], x[1], x[3], x[4], x[5], 0];
    let flags = |f: u64| open_flags(f as u32).map_or(f, u64::from);
    let fdf = |f: u64| fd_flags(f as u32).map_or(f, u64::from);
    match n {
        nr::READ => (0, x),
        nr::WRITE => (1, x),
        nr::PREAD => (17, x),
        nr::PWRITE => (18, x),
        nr::SEEK => (8, x),
        nr::CLOSE => (3, x),
        nr::DUP if x[1] as i32 == -1 => (32, [x[0], 0, 0, 0, 0, 0]),
        nr::DUP => (292, [x[0], x[1], fdf(x[2]), 0, 0, 0]),
        nr::PIPE => (293, [x[0], fdf(x[1]), 0, 0, 0, 0]),
        nr::IOCTL => (16, x),
        nr::FCNTL => (72, x),
        nr::POLL => (7, x),
        nr::TRUNCATE => (77, x),
        nr::SYNC if x[0] as i32 == -1 => (162, [0; 6]),
        nr::SYNC => (306, x),
        nr::READDIR => (217, x),
        nr::FLOCK => (73, x),
        nr::OPEN => (257, [x[0], x[1], flags(x[3]), x[4], 0, 0]),
        nr::STAT => (262, [x[0], x[1], x[4], x[3], 0, 0]),
        nr::MKDIR => (258, at),
        nr::MKNOD => (259, at),
        nr::UNLINK => (263, at),
        nr::RENAME => (264, [x[0], x[1], x[3], x[4], 0, 0]),
        nr::LINK => (265, [x[0], x[1], x[3], x[4], 0, 0]),
        nr::SYMLINK => (266, [x[0], x[2], x[3], 0, 0, 0]),
        nr::READLINK => (267, at),
        nr::CHMOD => (268, at),
        nr::CHOWN => (260, at),
        nr::UTIMES => (280, at),
        nr::ACCESS => (439, at),
        nr::CHDIR => (80, [x[1], 0, 0, 0, 0, 0]),
        nr::GETCWD => (79, x),
        nr::CHROOT => (161, [x[1], 0, 0, 0, 0, 0]),
        nr::UMASK => (95, x),
        nr::STATFS => (137, [x[1], x[4], 0, 0, 0, 0]),
        nr::MOUNT => (165, x),
        nr::UMOUNT => (166, [x[0], x[2], 0, 0, 0, 0]),
        nr::EXIT => (231, x),
        nr::FORK => (57, x),
        nr::EXEC => (322, at),
        nr::WAIT => (61, x),
        nr::GETPID => (39, x),
        nr::GETPPID => (110, x),
        nr::GETIDS => (118, x),
        nr::SETIDS => (117, x),
        nr::GETGROUPS => (115, [x[1], x[0], 0, 0, 0, 0]),
        nr::SETGROUPS => (116, [x[1], x[0], 0, 0, 0, 0]),
        nr::KILL => (62, x),
        nr::SETPGID => (109, x),
        nr::GETPGID => (121, x),
        nr::SETSID => (112, x),
        nr::GETSID => (124, x),
        nr::SIGACTION => (13, [x[0], x[1], x[2], 8, 0, 0]),
        nr::SIGMASK => (14, [x[0], x[1], x[2], 8, 0, 0]),
        nr::SIGRETURN => (15, x),
        nr::RLIMIT => (302, [0, x[0], x[1], x[2], 0, 0]),
        nr::UNAME => (63, x),
        nr::SETHOSTNAME => (170, x),
        nr::GETRANDOM => (318, x),
        nr::REBOOT => (169, x),
        nr::KLOG => (103, x),
        nr::MAP => (9, x),
        nr::UNMAP => (11, x),
        nr::PROTECT => (10, x),
        nr::CLOCK_GET => (228, x),
        nr::CLOCK_SET => (227, x),
        nr::CPU_TIMES => (98, x),
        nr::CLOCK_ADJUST => (305, x),
        nr::SLEEP => (35, x),
        nr::SOCKET => (41, [x[0], x[1] | fdf(x[3]), x[2], 0, 0, 0]),
        nr::BIND => (49, x),
        nr::LISTEN => (50, x),
        nr::CONNECT => (42, x),
        nr::ACCEPT => (288, [x[0], x[1], x[2], fdf(x[3]), 0, 0]),
        nr::SENDTO => (44, x),
        nr::RECVFROM => (45, x),
        nr::SETSOCKOPT => (54, x),
        nr::GETSOCKOPT => (55, x),
        nr::SHUTDOWN => (48, x),
        nr::GETSOCKNAME => (51, x),
        nr::GETPEERNAME => (52, x),
        nr::SENDMSG => (46, x),
        nr::RECVMSG => (47, x),
        nr::SOCKETPAIR => (53, [x[0], x[1] | fdf(x[3]), x[2], x[4], 0, 0]),
        nr::THREAD_START => (56, [CLONE_THREAD_FLAGS, x[2], 0, x[4], x[3], 0]),
        nr::THREAD_EXIT => (60, x),
        nr::GETTID => (186, x),
        // FUTEX_WAIT and FUTEX_WAKE, private (futex(2)).
        nr::FUTEX_WAIT => (202, [x[0], 128, x[1], x[2], 0, 0]),
        nr::FUTEX_WAKE => (202, [x[0], 129, x[1], 0, 0, 0]),
        // ARCH_SET_FS (arch_prctl(2)).
        nr::SET_TLS => (158, [0x1002, x[0], 0, 0, 0, 0]),
        nr::XATTR_SET => (190, [x[0], x[1], x[3], x[4], x[5], 0]),
        nr::XATTR_GET => (193, [x[0], x[1], x[3], x[4], 0, 0]),
        nr::XATTR_LIST => (196, x),
        nr::XATTR_REMOVE => (199, [x[0], x[1], 0, 0, 0, 0]),
        // inotify_init1, inotify_add_watch, inotify_rm_watch.
        nr::WATCH_OPEN => (294, x),
        nr::WATCH_ADD => (254, [x[0], x[2], x[4], 0, 0, 0]),
        nr::WATCH_REMOVE => (255, [x[0], x[1], 0, 0, 0, 0]),
        _ => (SLATE_ONLY | n, x),
    }
}
