// SPDX-License-Identifier: MIT OR Apache-2.0

//! Slate's native system-call interface, version 1 (ADR 0031; the
//! reference is libs/abi/native-abi.md).
//!
//! These are Slate's own definitions: the numbers, flags and structures
//! below are not Linux's. A few value sets are shared on purpose, so that
//! the kernel and C programs need no translation where none buys
//! anything:
//!
//! - error codes are Linux errno numbers (musl `bits/errno.h`, ADR 0009;
//!   meanings per errno(3));
//! - signal numbers are Linux's (signal(7));
//! - file type and permission bits are the traditional POSIX
//!   `<sys/stat.h>` octal values;
//! - `ioctl` requests and their structures, socket address layouts and
//!   families, protocol numbers, message flags, and socket option levels
//!   and names are Linux's (ioctl_tty(2), socket(7), send(2), ip(7),
//!   unix(7));
//! - `poll` event bits and `seek` origins are the POSIX values (poll(2),
//!   lseek(2)), and directory entry types the traditional `DT_*` values
//!   (readdir(3)).
//!
//! Calling convention: the `syscall` instruction, the number in rax,
//! arguments in rdi, rsi, rdx, r10, r8, r9, the result in rax. A result
//! of zero or more is success; a negative result is an error code,
//! negated. Strings are a pointer and a length, never NUL-terminated.

#![no_std]

#[cfg(test)]
extern crate std;

/// The interface version this crate describes.
pub const VERSION: u32 = 1;

/// The ELF note that marks a native program: owner name `Slate`, type
/// [`NT_SLATE_ABI`], and a 4-byte little-endian descriptor holding the
/// version it was built for.
pub const NOTE_NAME: &[u8] = b"Slate";
pub const NT_SLATE_ABI: u32 = 1;

/// The ELF note the kernel carries (ADR 0086): owner `Slate`, this type,
/// and an 8-byte descriptor holding the oldest and the newest interface
/// versions it serves (two little-endian u32s). `slate-update` checks a
/// system's unlock program against it before booting the two together.
pub const NT_SLATE_KERNEL_ABI: u32 = 2;
/// The oldest interface version this kernel still serves.
pub const OLDEST_VERSION: u32 = 1;

/// The auxiliary vector entry the kernel gives a native process; its
/// value is the interface version the process gets.
pub const AT_SLATE_ABI: u64 = 0x5100;

/// Slate's error codes beyond Linux's errno numbers.
pub mod error {
    /// exec: the program would run in the Linux domain and Linux
    /// compatibility mode is off (ADR 0032).
    pub const LINUX_OFF: i32 = 200;
}

/// The directory handle that means "the working directory".
pub const CWD: i32 = -100;

/// System-call numbers. The comment on each gives its arguments.
/// `xattr_set`'s flags.
pub mod xattr {
    /// Fail if the attribute exists.
    pub const CREATE: u32 = 1;
    /// Fail if it does not.
    pub const REPLACE: u32 = 2;
}

/// What a watch reports (`WATCH_ADD`'s mask, and each event's): inotify(7)'s
/// IN_* values, so events read from a watch descriptor have its layout
/// (`struct inotify_event`: wd, mask, cookie, name length, the name).
pub mod watch {
    pub const MODIFY: u32 = 0x2;
    pub const ATTRIB: u32 = 0x4;
    pub const CLOSE_WRITE: u32 = 0x8;
    pub const CLOSE_NOWRITE: u32 = 0x10;
    pub const OPEN: u32 = 0x20;
    pub const MOVED_FROM: u32 = 0x40;
    pub const MOVED_TO: u32 = 0x80;
    pub const CREATE: u32 = 0x100;
    pub const DELETE: u32 = 0x200;
    pub const DELETE_SELF: u32 = 0x400;
    pub const MOVE_SELF: u32 = 0x800;
    pub const OVERFLOW: u32 = 0x4000;
    pub const IGNORED: u32 = 0x8000;
    pub const ONLYDIR: u32 = 0x0100_0000;
    pub const DONT_FOLLOW: u32 = 0x0200_0000;
    pub const ISDIR: u32 = 0x4000_0000;
    pub const ONESHOT: u32 = 0x8000_0000;
}

pub mod nr {
    // Descriptors and I/O.
    /// (fd, buf, len) → bytes read
    pub const READ: u64 = 0;
    /// (fd, buf, len) → bytes written
    pub const WRITE: u64 = 1;
    /// (fd, buf, len, offset) → bytes read
    pub const PREAD: u64 = 2;
    /// (fd, buf, len, offset) → bytes written
    pub const PWRITE: u64 = 3;
    /// (fd, offset, whence: `seek::*`) → new offset
    pub const SEEK: u64 = 4;
    /// (fd)
    pub const CLOSE: u64 = 5;
    /// (fd, newfd or -1 for the lowest free, flags: `open::CLOEXEC`) → new fd.
    /// `newfd == fd` is allowed and returns `fd`.
    pub const DUP: u64 = 6;
    /// (fds: *mut [i32; 2], flags: `open::CLOEXEC | open::NONBLOCK`)
    pub const PIPE: u64 = 7;
    /// (fd, request, arg) → request-specific; requests are Linux's
    pub const IOCTL: u64 = 8;
    /// (fd, cmd: `fcntl::*`, arg) → cmd-specific
    pub const FCNTL: u64 = 9;
    /// (fds: *mut [PollFd], count, timeout in ms or -1) → ready count
    pub const POLL: u64 = 10;
    /// (fd, length)
    pub const TRUNCATE: u64 = 11;
    /// (fd, or -1 for every file system)
    pub const SYNC: u64 = 12;
    /// (fd, buf, len) → bytes of [`DirEntry`] records, 0 at the end
    pub const READDIR: u64 = 13;
    /// (fd, op: `flock::*`): an advisory lock on the whole file, held by the
    /// open file (flock(2) semantics; M19). EWOULDBLOCK with `NONBLOCK`
    /// when another holds a conflicting one; EINTR if a signal ends the
    /// wait.
    pub const FLOCK: u64 = 14;
    /// (op: `service::*`, ...): the service a process belongs to (init
    /// only; ADR 0060). `SET` (pid, name, len): tag init's child `pid`;
    /// `KILL` (name, len, signal) → how many processes were signalled.
    pub const SERVICE: u64 = 15;
    /// (name, len): tag the caller as a process of the Linux box `name`
    /// (ADR 0183), once: inherited on fork and exec, never changed or
    /// removed; `Box:` in /proc/PID/status. EEXIST when tagged already.
    pub const BOX_TAG: u64 = 16;

    // Paths. `dir` is an open directory or `CWD`; paths are (ptr, len).
    /// (dir, path, len, flags: `open::*`, mode) → fd
    pub const OPEN: u64 = 20;
    /// (dir, path, len, flags: `path::NOFOLLOW | path::EMPTY_PATH`, *mut Stat)
    pub const STAT: u64 = 21;
    /// (dir, path, len, mode)
    pub const MKDIR: u64 = 22;
    /// (dir, path, len, mode with file type, device number)
    pub const MKNOD: u64 = 23;
    /// (dir, path, len, flags: `path::REMOVE_DIR`)
    pub const UNLINK: u64 = 24;
    /// (old dir, old path, old len, new dir, new path, new len)
    pub const RENAME: u64 = 25;
    /// (old dir, old path, old len, new dir, new path, new len)
    pub const LINK: u64 = 26;
    /// (target, target len, dir, path, len)
    pub const SYMLINK: u64 = 27;
    /// (dir, path, len, buf, buf len, flags: `path::EMPTY_PATH`) → bytes
    pub const READLINK: u64 = 28;
    /// (dir, path, len, mode, flags: `path::NOFOLLOW | path::EMPTY_PATH`)
    pub const CHMOD: u64 = 29;
    /// (dir, path, len, uid or `NO_ID`, gid or `NO_ID`, flags as for CHMOD)
    pub const CHOWN: u64 = 30;
    /// (dir, path, len, times: *const [Timespec; 2] or null for now, flags as for CHMOD)
    pub const UTIMES: u64 = 31;
    /// (dir, path, len, mode: `access::*`, flags: `path::EFFECTIVE_IDS | path::NOFOLLOW`)
    pub const ACCESS: u64 = 32;
    /// (dir, path, len, flags: `path::EMPTY_PATH`)
    pub const CHDIR: u64 = 33;
    /// (buf, len) → length of the path (no NUL)
    pub const GETCWD: u64 = 34;
    /// (dir, path, len)
    pub const CHROOT: u64 = 35;
    /// (mask) → previous mask
    pub const UMASK: u64 = 36;
    /// (dir, path, len, flags: `path::EMPTY_PATH`, *mut StatFs)
    pub const STATFS: u64 = 37;
    /// (*const MountArgs, flags: `mount::*`)
    pub const MOUNT: u64 = 38;
    /// (path, len, flags: `umount::*`)
    pub const UMOUNT: u64 = 39;

    // Processes.
    /// (status): ends the whole process
    pub const EXIT: u64 = 40;
    /// () → child pid in the parent, 0 in the child
    pub const FORK: u64 = 41;
    /// (dir, path, len, *const ExecArgs, flags: `path::EMPTY_PATH`)
    pub const EXEC: u64 = 42;
    /// (pid as for waitpid(2), *mut WaitStatus, options: `wait::*`) → pid, or 0
    pub const WAIT: u64 = 43;
    /// () → pid
    pub const GETPID: u64 = 44;
    /// () → parent's pid
    pub const GETPPID: u64 = 45;
    /// (*mut Ids)
    pub const GETIDS: u64 = 46;
    /// (*const Ids, `NO_ID` for fields to keep)
    pub const SETIDS: u64 = 47;
    /// (buf: *mut u32, count) → number of groups
    pub const GETGROUPS: u64 = 48;
    /// (buf: *const u32, count)
    pub const SETGROUPS: u64 = 49;
    /// (pid as for kill(2), signal)
    pub const KILL: u64 = 50;
    /// (pid or 0, process group or 0)
    pub const SETPGID: u64 = 51;
    /// (pid or 0) → process group
    pub const GETPGID: u64 = 52;
    /// () → new session id
    pub const SETSID: u64 = 53;
    /// (pid or 0) → session id
    pub const GETSID: u64 = 54;
    /// (signal, *const SigAction or null, *mut SigAction or null)
    pub const SIGACTION: u64 = 55;
    /// (how: `sigmask::*`, *const u64 or null, *mut u64 or null)
    pub const SIGMASK: u64 = 56;
    /// (): return from a signal handler (the restorer calls it)
    pub const SIGRETURN: u64 = 57;
    /// (pid or 0, set: 0 reads, 1 sets, nice: -20 to 19) → 20 − the
    /// process's nice value before (as getpriority(2)); setting needs the
    /// same user, and lowering it CAP_SYS_NICE or RLIMIT_NICE (as
    /// setpriority(2))
    pub const PRIORITY: u64 = 73;
    /// (resource: Linux's `RLIMIT_*` number, *const Rlimit or null,
    /// *mut Rlimit or null): the caller's resource limit, read and/or set
    /// (`struct rlimit`'s layout: two u64, current and maximum; M21 phase 3)
    pub const RLIMIT: u64 = 59;
    /// (*mut Utsname): the same Linux-compatible identification Linux
    /// programs get (sysname "Linux"; Slate's name is in `version`)
    pub const UNAME: u64 = 60;
    /// (name, len)
    pub const SETHOSTNAME: u64 = 61;
    /// (buf, len, flags: `random::*`) → bytes
    pub const GETRANDOM: u64 = 62;
    /// (cmd: `reboot::*`)
    pub const REBOOT: u64 = 63;
    /// (op: `klog::*`, buf, len) → op-specific
    pub const KLOG: u64 = 64;
    /// (pid, *const Ids, groups: *const u32 or null to keep them, group
    /// count): change another process's IDs. Root in the Slate domain
    /// only, for a Slate-domain process that is the peer of one of the
    /// caller's Unix sockets (the privilege broker, ADR 0032).
    pub const SETIDS_OF: u64 = 65;
    /// (slot, key: *const u8, key len = 32): hand the kernel the key that
    /// opens key slot `slot` of the encrypted root it is unlocking at boot
    /// (ADR 0038). Only the boot's unlock program may, while the kernel
    /// waits for it; EACCES if the key does not open the slot.
    pub const UNLOCK: u64 = 66;
    /// (fd of a block device, slot, key: *const u8, key len = 32) → the
    /// mapped device's number N (`dm-N`): open an encrypted partition
    /// with the key for key slot `slot` (ADR 0039). Root in the Slate
    /// domain only; EACCES if the key does not open the slot, EBUSY if the
    /// partition is open already.
    pub const CRYPT_OPEN: u64 = 67;
    /// (N): close mapped device `dm-N`. EBUSY while it is mounted or open.
    pub const CRYPT_CLOSE: u64 = 68;
    /// (fd of a block device, offset, length): the bytes hold nothing any
    /// more (TRIM; ADR 0039). Whole sectors; EOPNOTSUPP when the device
    /// takes no discards.
    pub const DISCARD: u64 = 69;
    /// (N, key: *const u8, key len = 32, out: *mut u8, out len = 72): the
    /// master key of mapped device `dm-N`, wrapped under the given key
    /// (AES key wrap) into `out`, for a new key slot (ADR 0058). Root in
    /// the Slate domain only; the master key itself never leaves the
    /// kernel.
    pub const CRYPT_WRAP: u64 = 58;

    // Memory.
    /// (addr, len, prot: `prot::*`, flags: `map::*`, fd, offset) → address
    pub const MAP: u64 = 70;
    /// (addr, len)
    pub const UNMAP: u64 = 71;
    /// (addr, len, prot)
    pub const PROTECT: u64 = 72;

    // Time.
    /// (clock: `clock::*`, *mut Timespec)
    pub const CLOCK_GET: u64 = 80;
    /// (*const Timespec, *mut Timespec or null for the time left)
    pub const SLEEP: u64 = 81;
    /// (clock: only `clock::REALTIME`, *const Timespec): set the wall clock
    /// (root; the hardware clock follows; M19, ADR 0044)
    pub const CLOCK_SET: u64 = 82;
    /// (*mut [u64; 4]): the CPU time used, in nanoseconds: user and system
    /// of the caller, and of its waited-for children (M21 phase 3)
    pub const CPU_TIMES: u64 = 83;
    /// (delta ns: i64, flags: `clock_adjust::*`, *mut i64 or null): slew the
    /// wall clock by up to ±0.5 s at 500 ppm (0: only read; root to
    /// change anything); gives the slew still to come (M23 phase 1, ADR
    /// 0078)
    pub const CLOCK_ADJUST: u64 = 84;

    // Sockets (address layouts and option names are Linux's).
    /// (family, kind: `socket::*`, protocol, flags: `open::CLOEXEC | open::NONBLOCK`) → fd
    pub const SOCKET: u64 = 90;
    /// (fd, addr, addr len)
    pub const BIND: u64 = 91;
    /// (fd, backlog)
    pub const LISTEN: u64 = 92;
    /// (fd, addr, addr len)
    pub const CONNECT: u64 = 93;
    /// (fd, addr or null, *mut u32 addr len or null, flags as for SOCKET) → fd
    pub const ACCEPT: u64 = 94;
    /// (fd, buf, len, flags, addr or null, addr len)
    pub const SENDTO: u64 = 95;
    /// (fd, buf, len, flags, addr or null, *mut u32 addr len or null)
    pub const RECVFROM: u64 = 96;
    /// (fd, level, name, value, value len)
    pub const SETSOCKOPT: u64 = 97;
    /// (fd, level, name, value, *mut u32 value len)
    pub const GETSOCKOPT: u64 = 98;
    /// (fd, how: `shutdown::*`)
    pub const SHUTDOWN: u64 = 99;
    /// (fd, addr, *mut u32 addr len)
    pub const GETSOCKNAME: u64 = 100;
    /// (fd, addr, *mut u32 addr len)
    pub const GETPEERNAME: u64 = 101;
    /// (fd, *const Msg, flags) → bytes; passes descriptors on Unix sockets
    pub const SENDMSG: u64 = 102;
    /// (fd, *mut Msg, flags) → bytes; `Msg` gets the address, descriptors and flags
    pub const RECVMSG: u64 = 103;
    /// (family, kind: `socket::*`, protocol, flags as for SOCKET,
    /// fds: *mut [i32; 2]): a connected pair (Unix sockets only; ADR 0075)
    pub const SOCKETPAIR: u64 = 104;

    // Threads (M21 phase 7, ADR 0073).
    /// (entry, arg, stack top (16-aligned), tls or 0, *mut u32 tid word
    /// or null) → thread ID. The new thread of the calling process starts
    /// at `entry` as if called with `arg` (rdi) and a zero return
    /// address just below `stack top`; `entry` must not return. It gets
    /// the caller's signal mask and FS base `tls` (when not 0). The kernel
    /// writes the thread ID to the tid word before either thread runs on,
    /// and at the thread's end writes 0 there and wakes one futex waiter.
    pub const THREAD_START: u64 = 110;
    /// (status): ends the calling thread; the process ends, with
    /// `status`, when its last thread does
    pub const THREAD_EXIT: u64 = 111;
    /// () → the calling thread's ID (the process ID for the first thread)
    pub const GETTID: u64 = 112;
    /// (addr: *const u32, expected, *const Timespec or null): sleep while
    /// the word at `addr` holds `expected`, until a `FUTEX_WAKE` on it,
    /// a signal (EINTR) or the relative timeout (ETIMEDOUT); EAGAIN at
    /// once if it holds something else. The process's own words only.
    pub const FUTEX_WAIT: u64 = 113;
    /// (addr: *const u32, count) → how many waiters were woken
    pub const FUTEX_WAKE: u64 = 114;
    /// (base): the calling thread's FS base (its thread pointer; x86-64
    /// psABI TLS variant II)
    pub const SET_TLS: u64 = 115;

    // Extended attributes (xattr(7)) of an open file.
    /// (fd, name, name len, buf, buf len) → the value's length (with buf
    /// len 0, only that)
    pub const XATTR_GET: u64 = 116;
    /// (fd, name, name len, value, value len, flags: `xattr::*`)
    pub const XATTR_SET: u64 = 117;
    /// (fd, buf, buf len) → bytes of names, each ending in a zero byte
    /// (with buf len 0, only the count)
    pub const XATTR_LIST: u64 = 118;
    /// (fd, name, name len)
    pub const XATTR_REMOVE: u64 = 119;
    // Watches on files and directories (inotify(7), ADR 0149).
    /// (flags: `open::CLOEXEC`, `NONBLOCK`) → a watch descriptor; reading
    /// it gives events.
    pub const WATCH_OPEN: u64 = 120;
    /// (fd, dir, path, path len, mask: `watch::*`) → the watch's number
    pub const WATCH_ADD: u64 = 121;
    /// (fd, watch number)
    pub const WATCH_REMOVE: u64 = 122;

    // Namespaces (ADR 0183: Linux boxes are made by Slate's own programs).
    /// (flags: `ns::*`): move the caller into new namespaces (unshare(2));
    /// `PID` only affects its later children.
    pub const UNSHARE: u64 = 130;
    /// (new root, len, put old, len): pivot_root(2) in the caller's mount
    /// namespace.
    pub const PIVOT_ROOT: u64 = 131;

    /// Every call's number and name, for tracing and documentation.
    pub const ALL: &[(u64, &str)] = &[
        (READ, "read"),
        (WRITE, "write"),
        (PREAD, "pread"),
        (PWRITE, "pwrite"),
        (SEEK, "seek"),
        (CLOSE, "close"),
        (DUP, "dup"),
        (PIPE, "pipe"),
        (IOCTL, "ioctl"),
        (FCNTL, "fcntl"),
        (POLL, "poll"),
        (TRUNCATE, "truncate"),
        (SYNC, "sync"),
        (READDIR, "readdir"),
        (FLOCK, "flock"),
        (SERVICE, "service"),
        (BOX_TAG, "box_tag"),
        (OPEN, "open"),
        (STAT, "stat"),
        (MKDIR, "mkdir"),
        (MKNOD, "mknod"),
        (UNLINK, "unlink"),
        (RENAME, "rename"),
        (LINK, "link"),
        (SYMLINK, "symlink"),
        (READLINK, "readlink"),
        (CHMOD, "chmod"),
        (CHOWN, "chown"),
        (UTIMES, "utimes"),
        (ACCESS, "access"),
        (CHDIR, "chdir"),
        (GETCWD, "getcwd"),
        (CHROOT, "chroot"),
        (UMASK, "umask"),
        (STATFS, "statfs"),
        (MOUNT, "mount"),
        (UMOUNT, "umount"),
        (EXIT, "exit"),
        (FORK, "fork"),
        (EXEC, "exec"),
        (WAIT, "wait"),
        (GETPID, "getpid"),
        (GETPPID, "getppid"),
        (GETIDS, "getids"),
        (SETIDS, "setids"),
        (GETGROUPS, "getgroups"),
        (SETGROUPS, "setgroups"),
        (KILL, "kill"),
        (SETPGID, "setpgid"),
        (GETPGID, "getpgid"),
        (SETSID, "setsid"),
        (GETSID, "getsid"),
        (SIGACTION, "sigaction"),
        (SIGMASK, "sigmask"),
        (SIGRETURN, "sigreturn"),
        (UNAME, "uname"),
        (SETHOSTNAME, "sethostname"),
        (GETRANDOM, "getrandom"),
        (REBOOT, "reboot"),
        (KLOG, "klog"),
        (SETIDS_OF, "setids_of"),
        (UNLOCK, "unlock"),
        (CRYPT_OPEN, "crypt_open"),
        (CRYPT_CLOSE, "crypt_close"),
        (DISCARD, "discard"),
        (CRYPT_WRAP, "crypt_wrap"),
        (RLIMIT, "rlimit"),
        (CPU_TIMES, "cpu_times"),
        (CLOCK_ADJUST, "clock_adjust"),
        (MAP, "map"),
        (UNMAP, "unmap"),
        (PROTECT, "protect"),
        (PRIORITY, "priority"),
        (CLOCK_GET, "clock_get"),
        (SLEEP, "sleep"),
        (CLOCK_SET, "clock_set"),
        (SOCKET, "socket"),
        (BIND, "bind"),
        (LISTEN, "listen"),
        (CONNECT, "connect"),
        (ACCEPT, "accept"),
        (SENDTO, "sendto"),
        (RECVFROM, "recvfrom"),
        (SETSOCKOPT, "setsockopt"),
        (GETSOCKOPT, "getsockopt"),
        (SHUTDOWN, "shutdown"),
        (GETSOCKNAME, "getsockname"),
        (GETPEERNAME, "getpeername"),
        (SENDMSG, "sendmsg"),
        (RECVMSG, "recvmsg"),
        (SOCKETPAIR, "socketpair"),
        (THREAD_START, "thread_start"),
        (THREAD_EXIT, "thread_exit"),
        (GETTID, "gettid"),
        (FUTEX_WAIT, "futex_wait"),
        (FUTEX_WAKE, "futex_wake"),
        (SET_TLS, "set_tls"),
        (XATTR_GET, "xattr_get"),
        (XATTR_SET, "xattr_set"),
        (XATTR_LIST, "xattr_list"),
        (XATTR_REMOVE, "xattr_remove"),
        (WATCH_OPEN, "watch_open"),
        (WATCH_ADD, "watch_add"),
        (WATCH_REMOVE, "watch_remove"),
        (UNSHARE, "unshare"),
        (PIVOT_ROOT, "pivot_root"),
    ];

    /// The name of call `n`.
    pub fn name(n: u64) -> Option<&'static str> {
        ALL.iter().find(|(k, _)| *k == n).map(|(_, s)| *s)
    }
}

/// `open` flags. The access mode is the low two bits.
pub mod open {
    pub const ACCESS_MASK: u32 = 3;
    pub const READ_ONLY: u32 = 0;
    pub const WRITE_ONLY: u32 = 1;
    pub const READ_WRITE: u32 = 2;
    pub const CREATE: u32 = 1 << 2;
    pub const EXCL: u32 = 1 << 3;
    pub const TRUNC: u32 = 1 << 4;
    pub const APPEND: u32 = 1 << 5;
    pub const NONBLOCK: u32 = 1 << 6;
    pub const CLOEXEC: u32 = 1 << 7;
    pub const DIRECTORY: u32 = 1 << 8;
    pub const NOFOLLOW: u32 = 1 << 9;
    pub const NOCTTY: u32 = 1 << 10;
    pub const SYNC: u32 = 1 << 11;
    /// A handle to the path only (no reading or writing).
    pub const PATH: u32 = 1 << 12;
    /// Leave nothing in the page cache (ADR 0145).
    pub const DIRECT: u32 = 1 << 13;
    /// Leave the access time alone; the owner's only (ADR 0145).
    pub const NOATIME: u32 = 1 << 14;
    /// Every flag version 1 knows.
    pub const ALL: u32 = (1 << 15) - 1;
}

/// Flags for the calls that take a path.
pub mod path {
    /// Act on a symbolic link itself.
    pub const NOFOLLOW: u32 = 1;
    /// An empty path means the directory handle itself (which may be any
    /// open file).
    pub const EMPTY_PATH: u32 = 2;
    /// `unlink`: remove a directory (which must be empty).
    pub const REMOVE_DIR: u32 = 4;
    /// `access`: check with the effective, not the real, IDs.
    pub const EFFECTIVE_IDS: u32 = 8;
}

/// `access` modes (POSIX values).
pub mod access {
    pub const EXISTS: u32 = 0;
    pub const EXECUTE: u32 = 1;
    pub const WRITE: u32 = 2;
    pub const READ: u32 = 4;
}

/// `seek` origins (POSIX values).
pub mod seek {
    pub const SET: u32 = 0;
    pub const CUR: u32 = 1;
    pub const END: u32 = 2;
}

/// `fcntl` commands. Status flags (GETFL/SETFL) are `open::*` values.
pub mod fcntl {
    /// (lowest fd) → new fd
    pub const DUPFD: u32 = 0;
    /// → `CLOEXEC` or 0
    pub const GETFD: u32 = 1;
    /// (`CLOEXEC` or 0)
    pub const SETFD: u32 = 2;
    /// → status flags
    pub const GETFL: u32 = 3;
    /// (status flags: only `open::APPEND | open::NONBLOCK` change)
    pub const SETFL: u32 = 4;
    /// (lowest fd) → new fd with `CLOEXEC`
    pub const DUPFD_CLOEXEC: u32 = 5;
    /// The descriptor flag.
    pub const CLOEXEC: u32 = 1;
}

/// `flock` operations: one of `SHARED`, `EXCLUSIVE` or `UNLOCK`, maybe with
/// `NONBLOCK`.
pub mod flock {
    pub const SHARED: u32 = 1;
    pub const EXCLUSIVE: u32 = 2;
    pub const UNLOCK: u32 = 3;
    pub const NONBLOCK: u32 = 1 << 4;
}

/// `poll` event bits (POSIX values, poll(2)).
pub mod poll {
    pub const IN: i16 = 0x1;
    pub const PRI: i16 = 0x2;
    pub const OUT: i16 = 0x4;
    pub const ERR: i16 = 0x8;
    pub const HUP: i16 = 0x10;
    pub const NVAL: i16 = 0x20;
}

/// `wait` options, and the kinds of [`WaitStatus`].
pub mod wait {
    pub const NOHANG: u32 = 1;
    /// Also report children that stopped.
    pub const UNTRACED: u32 = 2;
    /// Also report children that continued.
    pub const CONTINUED: u32 = 4;

    /// Exited; `code` is the exit status.
    pub const EXITED: u32 = 1;
    /// Killed by signal `code`.
    pub const KILLED: u32 = 2;
    /// Killed by signal `code`, which would have dumped core.
    pub const DUMPED: u32 = 3;
    /// Stopped by signal `code`.
    pub const STOPPED: u32 = 4;
    /// Continued (`code` is 0).
    pub const CONTINUED_KIND: u32 = 5;
}

/// [`SigAction`] flags and special handlers.
pub mod sigaction {
    /// The handler takes (signal, *siginfo, *context).
    pub const SIGINFO: u32 = 1;
    /// Restart interrupted calls.
    pub const RESTART: u32 = 2;
    /// Do not block the signal in its handler.
    pub const NODEFER: u32 = 4;
    /// Back to the default after one delivery.
    pub const RESETHAND: u32 = 8;
    /// Run on the alternate signal stack.
    pub const ONSTACK: u32 = 16;
    /// SIGCHLD: not for children that stop.
    pub const NOCLDSTOP: u32 = 32;
    /// SIGCHLD: children do not become zombies.
    pub const NOCLDWAIT: u32 = 64;

    pub const DEFAULT: u64 = 0;
    pub const IGNORE: u64 = 1;
}

/// `sigmask` operations (POSIX values).
pub mod sigmask {
    pub const BLOCK: u32 = 0;
    pub const UNBLOCK: u32 = 1;
    pub const SET: u32 = 2;
}

/// `map` and `protect` protections.
pub mod prot {
    pub const NONE: u32 = 0;
    pub const READ: u32 = 1;
    pub const WRITE: u32 = 2;
    pub const EXEC: u32 = 4;
}

/// `map` flags: exactly one of SHARED and PRIVATE.
pub mod map {
    pub const SHARED: u32 = 1;
    pub const PRIVATE: u32 = 2;
    /// Exactly at `addr`, replacing what is there.
    pub const FIXED: u32 = 4;
    /// Not backed by a file (`fd` is ignored).
    pub const ANONYMOUS: u32 = 8;
    pub const NORESERVE: u32 = 16;
    /// Exactly at `addr`, failing if anything is there.
    pub const FIXED_NOREPLACE: u32 = 32;
}

/// `mount` flags.
pub mod mount {
    pub const RDONLY: u32 = 1;
    pub const NOSUID: u32 = 2;
    pub const NODEV: u32 = 4;
    pub const NOEXEC: u32 = 8;
    /// Change the flags of an existing mount.
    pub const REMOUNT: u32 = 16;
    /// Mount a directory tree somewhere else.
    pub const BIND: u32 = 32;
    /// With BIND: the mounts below it too.
    pub const RECURSIVE: u32 = 64;
    /// Access times (ADR 0162): never updated; never for directories;
    /// updated as `relatime` does (the default); updated on every read.
    pub const NOATIME: u32 = 128;
    pub const NODIRATIME: u32 = 256;
    pub const RELATIME: u32 = 512;
    pub const STRICTATIME: u32 = 1024;
}

/// `umount` flags.
pub mod umount {
    pub const FORCE: u32 = 1;
    /// Detach now, clean up when no longer busy.
    pub const DETACH: u32 = 2;
}

/// Clocks.
pub mod clock {
    pub const REALTIME: u32 = 0;
    pub const MONOTONIC: u32 = 1;
    /// Monotonic, including time suspended.
    pub const BOOTTIME: u32 = 2;
    /// CPU time used by the process.
    pub const PROCESS_CPU: u32 = 3;
}

/// `clock_adjust` flags.
pub mod clock_adjust {
    /// The time came from a time source: the clock counts as synchronized.
    pub const SYNCED: u64 = 1;
}

/// Special `nsec` values in `utimes`.
pub mod utime {
    pub const NOW: i64 = -1;
    pub const OMIT: i64 = -2;
}

/// `reboot` commands.
pub mod reboot {
    pub const RESTART: u32 = 1;
    pub const HALT: u32 = 2;
    pub const POWER_OFF: u32 = 3;
    /// Ctrl-Alt-Del restarts at once (the default).
    pub const CAD_ON: u32 = 4;
    /// Ctrl-Alt-Del sends init SIGINT.
    pub const CAD_OFF: u32 = 5;
}

/// `service` operations (ADR 0060).
/// `unshare`'s namespace kinds (ADR 0183).
pub mod ns {
    pub const USER: u32 = 1;
    pub const MOUNT: u32 = 2;
    pub const PID: u32 = 4;
    pub const UTS: u32 = 8;
    pub const IPC: u32 = 16;
    pub const NET: u32 = 32;
}

/// `box_tag` (ADR 0183).
pub mod box_tag {
    /// The longest box name.
    pub const NAME_MAX: usize = 32;
}

pub mod service {
    /// (pid, name, len): put init's child `pid` in service `name`.
    pub const SET: u32 = 1;
    /// (name, len, signal): signal every process in the service.
    pub const KILL: u32 = 2;
    /// The longest service name.
    pub const NAME_MAX: usize = 64;
}

/// `klog` operations on the kernel log.
pub mod klog {
    /// Copy the whole log into the buffer → bytes.
    pub const READ_ALL: u32 = 1;
    /// Empty the log.
    pub const CLEAR: u32 = 2;
    /// → the log's size.
    pub const SIZE: u32 = 3;
    /// READ_ALL, then CLEAR.
    pub const READ_CLEAR: u32 = 4;
    /// (buf, len, *mut u64 position): whole lines written since the
    /// position (bytes ever written; the oldest kept if it was
    /// overwritten), which moves past them → bytes (ADR 0060).
    pub const READ_FROM: u32 = 5;
}

/// `getrandom` flags.
pub mod random {
    /// Fail with EAGAIN instead of waiting for entropy.
    pub const NONBLOCK: u32 = 1;
}

/// Socket kinds (address families are Linux's `AF_*`).
pub mod socket {
    pub const STREAM: u32 = 1;
    pub const DGRAM: u32 = 2;
    pub const RAW: u32 = 3;
}

/// `shutdown` directions.
pub mod shutdown {
    pub const READ: u32 = 0;
    pub const WRITE: u32 = 1;
    pub const BOTH: u32 = 2;
}

/// [`DirEntry`] types (the traditional `DT_*` values).
pub mod dirent {
    pub const UNKNOWN: u8 = 0;
    pub const FIFO: u8 = 1;
    pub const CHAR: u8 = 2;
    pub const DIR: u8 = 4;
    pub const BLOCK: u8 = 6;
    pub const REGULAR: u8 = 8;
    pub const SYMLINK: u8 = 10;
    pub const SOCKET: u8 = 12;
}

/// An ID field of [`Ids`], `chown` and `setids` that means "unchanged".
pub const NO_ID: u32 = u32::MAX;

/// A string or buffer passed by address and length.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Str {
    pub ptr: u64,
    pub len: u64,
}

impl Str {
    pub fn new(s: &[u8]) -> Str {
        Str { ptr: s.as_ptr() as u64, len: s.len() as u64 }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timespec {
    pub sec: i64,
    pub nsec: i64,
}

/// File status (`stat`), 128 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    /// File type and permission bits.
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    /// The device number, for device files.
    pub rdev: u64,
    pub size: u64,
    /// Space used, in 512-byte units.
    pub blocks: u64,
    /// Preferred I/O size.
    pub block_size: u32,
    pub _reserved: u32,
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
    /// Creation time; zero when the file system does not record it.
    pub btime: Timespec,
}

/// File system status (`statfs`), 96 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatFs {
    /// The file system's type number (Linux's statfs(2) magic numbers).
    pub kind: u64,
    pub block_size: u64,
    pub blocks: u64,
    pub free: u64,
    /// Free blocks for unprivileged users.
    pub available: u64,
    pub files: u64,
    pub free_files: u64,
    pub fsid: u64,
    pub name_max: u64,
    /// `mount::*` flags.
    pub flags: u64,
    pub _reserved: [u64; 2],
}

/// The fixed part of a `readdir` record. `name_len` bytes of name follow
/// (no NUL), and the record is padded to `rec_len`, a multiple of 8.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirEntry {
    pub ino: u64,
    pub rec_len: u16,
    pub name_len: u16,
    /// `dirent::*`
    pub kind: u8,
    pub _reserved: [u8; 3],
}

impl DirEntry {
    pub const SIZE: usize = 16;

    /// The record length for a name of `name_len` bytes.
    pub fn rec_len_for(name_len: usize) -> usize {
        (Self::SIZE + name_len).next_multiple_of(8)
    }
}

/// What `wait` reports about a child.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WaitStatus {
    pub pid: i32,
    /// `wait::EXITED` and so on.
    pub kind: u32,
    /// The exit status or the signal.
    pub code: i32,
    pub _reserved: u32,
}

/// Real, effective and saved user and group IDs.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ids {
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
    pub rgid: u32,
    pub egid: u32,
    pub sgid: u32,
}

/// A signal's disposition.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SigAction {
    /// The handler's address, or `sigaction::DEFAULT` / `IGNORE`.
    pub handler: u64,
    /// `sigaction::*` flags.
    pub flags: u32,
    pub _reserved: u32,
    /// Signals blocked while the handler runs (bit `n - 1` for signal `n`).
    pub mask: u64,
    /// Where the handler returns to: code that calls `SIGRETURN`.
    /// Required for a handler.
    pub restorer: u64,
}

/// System identification, each field NUL-padded.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Utsname {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
    pub domainname: [u8; 65],
}

impl Default for Utsname {
    fn default() -> Utsname {
        Utsname {
            sysname: [0; 65],
            nodename: [0; 65],
            release: [0; 65],
            version: [0; 65],
            machine: [0; 65],
            domainname: [0; 65],
        }
    }
}

/// One descriptor for `poll` (the POSIX layout).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

/// The argument and environment vectors for `exec`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExecArgs {
    /// Address of `argc` [`Str`]s.
    pub argv: u64,
    pub argc: u64,
    /// Address of `envc` [`Str`]s, each `NAME=value`.
    pub envp: u64,
    pub envc: u64,
}

/// The strings `mount` takes. `data` is file-system specific and may be
/// empty.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MountArgs {
    pub source: Str,
    pub target: Str,
    pub fstype: Str,
    pub data: Str,
}

/// A message for `sendmsg` and `recvmsg`: data gathered from or scattered
/// into buffers, the peer's address, and descriptors passed along (Unix
/// sockets).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Msg {
    /// Address of `bufs_len` [`Str`]s.
    pub bufs: u64,
    pub bufs_len: u64,
    /// `sendmsg`: the destination or 0. `recvmsg`: room for the sender's
    /// address or 0; `addr_len` becomes its length.
    pub addr: u64,
    pub addr_len: u32,
    /// `recvmsg` sets the Linux message flags `MSG_TRUNC` (0x20: data
    /// was cut) and `MSG_CTRUNC` (0x8: descriptors were dropped).
    pub flags: u32,
    /// Address of `fds_len` descriptors: the ones to pass, or room for
    /// the ones that come (`fds_len` becomes their count).
    pub fds: u64,
    pub fds_len: u32,
    /// `recvmsg` sets the TTL or hop limit of the datagram received (an
    /// internet datagram's; 0 for others).
    pub ttl: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn structure_sizes_are_fixed() {
        assert_eq!(size_of::<Str>(), 16);
        assert_eq!(size_of::<Timespec>(), 16);
        assert_eq!(size_of::<Stat>(), 128);
        assert_eq!(size_of::<StatFs>(), 96);
        assert_eq!(size_of::<DirEntry>(), DirEntry::SIZE);
        assert_eq!(size_of::<WaitStatus>(), 16);
        assert_eq!(size_of::<Ids>(), 24);
        assert_eq!(size_of::<SigAction>(), 32);
        assert_eq!(size_of::<Utsname>(), 390);
        assert_eq!(size_of::<PollFd>(), 8);
        assert_eq!(size_of::<ExecArgs>(), 32);
        assert_eq!(size_of::<MountArgs>(), 64);
        assert_eq!(size_of::<Msg>(), 48);
    }

    #[test]
    fn numbers_are_unique_and_named() {
        for (i, (n, name)) in nr::ALL.iter().enumerate() {
            assert!(nr::ALL[i + 1..].iter().all(|(m, other)| m != n && other != name), "{name}");
            assert_eq!(nr::name(*n), Some(*name));
        }
    }

    /// libs/abi/native-abi.md lists every call with its number, and nothing
    /// else.
    #[test]
    fn reference_matches() {
        let doc = include_str!("../native-abi.md");
        let mut rows = std::vec::Vec::new();
        for line in doc.lines() {
            let cells: std::vec::Vec<&str> = line.split('|').map(str::trim).collect();
            if let [_, n, call, ..] = cells[..]
                && let (Ok(n), Some(name)) =
                    (n.parse::<u64>(), call.strip_prefix('`').and_then(|c| c.strip_suffix('`')))
            {
                rows.push((n, name));
            }
        }
        for (n, name) in nr::ALL {
            assert!(rows.contains(&(*n, *name)), "{name} ({n}) is missing from libs/abi/native-abi.md");
        }
        assert_eq!(rows.len(), nr::ALL.len(), "libs/abi/native-abi.md lists calls slate-abi does not have");
    }

    #[test]
    fn records_are_aligned() {
        assert_eq!(DirEntry::rec_len_for(0), 16);
        assert_eq!(DirEntry::rec_len_for(1), 24);
        assert_eq!(DirEntry::rec_len_for(8), 24);
        assert_eq!(DirEntry::rec_len_for(255), 272);
    }
}
