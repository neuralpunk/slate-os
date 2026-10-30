# Slate's native interface (version 1)

Slate has two system-call interfaces: the Linux x86-64 one, for Linux
programs, and its own native one, described here.
Slate's own programs use the native one.
The definitions live in `libs/abi` (`slate-abi`), which the kernel,
slate-rt and slate-libc share. If this page and slate-abi disagree,
slate-abi is right (and a test fails: every call below must appear in
`slate_abi::nr::ALL`, and the reverse).

## Choosing the interface

- A program asks for the native interface with an ELF note: a `PT_NOTE`
  segment with owner `Slate`, type 1 (`NT_SLATE_ABI`) and a 4-byte
  little-endian descriptor holding the version it was built for (1).
  slate-rt's `program!` and slate-libc's start-up code emit it.
- `execve` reads the note. A process keeps its interface across `fork`,
  and the next exec decides again, so a native shell runs Linux
  programs and the other way round.
- The kernel tells a native process its version with the auxiliary
  vector entry `AT_SLATE_ABI` (0x5100). Linux ignores the note, so on
  Linux the entry is missing and slate-rt makes Linux calls: one binary
  runs on both.
- A process with seccomp filters cannot exec a native program (EPERM):
  its filters speak Linux numbers.
- `/proc/slate_sched` marks native threads, and `/proc/slate_strace`
  logs their calls with native names and paths.

## Conventions

- The `syscall` instruction: number in `rax`; arguments in `rdi`, `rsi`,
  `rdx`, `r10`, `r8`, `r9`; result in `rax`. `rcx` and `r11` are
  clobbered.
- A result of zero or more is success. A negative result is an error
  code, negated. Error codes have Linux's errno numbers, plus Slate's
  own: `LINUX_OFF` (200), from `exec` when the program would run in the
  Linux domain while Linux compatibility mode is off.
- **Strings and paths are a pointer and a length**, never
  NUL-terminated. Paths are UTF-8 and may not contain NUL (EINVAL);
  they must be shorter than 4096 bytes (ENAMETOOLONG).
- **Directory handles:** every call that takes a path takes a directory
  first: an open directory, or `CWD` (-100) for the working directory.
  Absolute paths ignore it.
- **`EMPTY_PATH`:** with this flag, an empty path means the handle
  itself, which may be any open file (stat, chmod, chown, utimes,
  readlink, chdir, statfs, exec). Without it an empty path is ENOENT.
- **Flags are Slate's own** (`slate_abi::open`, `path`, `map`, `mount`,
  `wait`, `sigaction`, ...), and unknown flags are EINVAL, never
  ignored.
- Shared on purpose with Linux: error numbers, signal numbers, the file
  type and permission bits, `ioctl` requests and their structures,
  socket address layouts, families, protocols, message flags and
  socket options, `poll` bits, `seek` origins and directory entry
  types.
- An unassigned number fails with ENOSYS and is logged once.

## The calls

Arguments are listed in register order. "path" stands for two
arguments, pointer and length.

### Descriptors and I/O

| # | Call | Arguments | Result |
|---|---|---|---|
| 0 | `read` | fd, buf, len | bytes read |
| 1 | `write` | fd, buf, len | bytes written |
| 2 | `pread` | fd, buf, len, offset | bytes read |
| 3 | `pwrite` | fd, buf, len, offset | bytes written |
| 4 | `seek` | fd, offset, whence (`seek::SET/CUR/END`) | new offset |
| 5 | `close` | fd | |
| 6 | `dup` | fd, newfd or -1 for the lowest free, flags (`open::CLOEXEC`) | new fd; `newfd == fd` returns fd |
| 7 | `pipe` | `*mut [i32; 2]`, flags (`CLOEXEC`, `NONBLOCK`) | |
| 8 | `ioctl` | fd, request, arg | request-specific (Linux requests) |
| 9 | `fcntl` | fd, cmd (`fcntl::*`), arg | DUPFD, DUPFD_CLOEXEC, GETFD, SETFD, GETFL, SETFL with `open::*` flags |
| 10 | `poll` | `*mut [PollFd]`, count, timeout ms or -1 | ready count |
| 11 | `truncate` | fd, length | |
| 12 | `sync` | fd, or -1 for every file system | |
| 13 | `readdir` | fd, buf, len | bytes of `DirEntry` records, 0 at the end |
| 14 | `flock` | fd, op (`flock::*`: `SHARED`, `EXCLUSIVE` or `UNLOCK`, maybe `NONBLOCK`) | flock(2) semantics; EWOULDBLOCK, EINTR |
| 15 | `service` | op (`service::SET`: pid, name, len; `service::KILL`: name, len, signal) | init's service tags: SET tags one of init's children, KILL signals every tagged process and returns how many; EPERM unless the caller is pid 1 |
| 16 | `box_tag` | name, len (at most 32 bytes: letters, digits, `-`, `_`, `.`) | tags the caller as a process of that Linux box, once: inherited on fork and exec, never changed or removed; `Box:` in /proc/PID/status; EEXIST when tagged already, EPERM outside the Slate domain |

### Paths

| # | Call | Arguments | Result |
|---|---|---|---|
| 20 | `open` | dir, path, flags (`open::*`; `DIRECT` leaves nothing in the page cache, `NOATIME` only for the file's owner), mode | fd |
| 21 | `stat` | dir, path, flags (`NOFOLLOW`, `EMPTY_PATH`), `*mut Stat` | |
| 22 | `mkdir` | dir, path, mode | |
| 23 | `mknod` | dir, path, mode with type, device | |
| 24 | `unlink` | dir, path, flags (`REMOVE_DIR` removes an empty directory) | |
| 25 | `rename` | old dir, old path, new dir, new path | |
| 26 | `link` | old dir, old path, new dir, new path | |
| 27 | `symlink` | target (pointer, length), dir, path | |
| 28 | `readlink` | dir, path, buf, buf len, flags (`EMPTY_PATH`) | bytes |
| 29 | `chmod` | dir, path, mode, flags (`NOFOLLOW`, `EMPTY_PATH`) | |
| 30 | `chown` | dir, path, uid or `NO_ID`, gid or `NO_ID`, flags | |
| 31 | `utimes` | dir, path, `*const [Timespec; 2]` or null (now), flags | `utime::NOW`/`OMIT` in `nsec` |
| 32 | `access` | dir, path, mode (`access::*`), flags (`EFFECTIVE_IDS`, `NOFOLLOW`) | |
| 33 | `chdir` | dir, path, flags (`EMPTY_PATH`) | |
| 34 | `getcwd` | buf, len | the path's length (no NUL); ERANGE if it does not fit |
| 35 | `chroot` | dir, path | |
| 36 | `umask` | mask | previous mask |
| 37 | `statfs` | dir, path, flags (`EMPTY_PATH`), `*mut StatFs` | |
| 38 | `mount` | `*const MountArgs`, flags (`mount::*`) | |
| 39 | `umount` | path, flags (`umount::FORCE`, `DETACH`) | |

### Processes and the system

| # | Call | Arguments | Result |
|---|---|---|---|
| 40 | `exit` | status | ends the whole process |
| 41 | `fork` | | child pid, 0 in the child |
| 42 | `exec` | dir, path, `*const ExecArgs`, flags (`EMPTY_PATH`) | only on failure |
| 43 | `wait` | pid (as waitpid: -1, 0, -pgid, pid), `*mut WaitStatus` or null, options (`wait::*`) | pid, or 0 with NOHANG |
| 44 | `getpid` | | pid |
| 45 | `getppid` | | parent's pid |
| 46 | `getids` | `*mut Ids` | |
| 47 | `setids` | `*const Ids`, `NO_ID` keeps a field | users and groups together, each checked against the IDs before the call; all or nothing; every thread |
| 48 | `getgroups` | `*mut u32`, count | number of groups |
| 49 | `setgroups` | `*const u32`, count | every thread |
| 50 | `kill` | pid (as kill(2)), signal | |
| 51 | `setpgid` | pid or 0, group or 0 | |
| 52 | `getpgid` | pid or 0 | group |
| 53 | `setsid` | | new session |
| 54 | `getsid` | pid or 0 | session |
| 55 | `sigaction` | signal, `*const SigAction` or null, `*mut SigAction` or null | a handler needs a restorer |
| 56 | `sigmask` | how (`sigmask::BLOCK/UNBLOCK/SET`), `*const u64` or null, `*mut u64` or null | |
| 57 | `sigreturn` | | returns from a handler |
| 59 | `rlimit` | resource (Linux's `RLIMIT_*`), `*const Rlimit` or null, `*mut Rlimit` or null | reads and/or sets the caller's limit; `Rlimit` is two u64 (current, maximum), as Linux's; EPERM raising a maximum without CAP_SYS_RESOURCE |
| 60 | `uname` | `*mut Utsname` | the Linux-compatible identification |
| 61 | `sethostname` | name, len | |
| 62 | `getrandom` | buf, len, flags (`random::NONBLOCK`) | bytes |
| 63 | `reboot` | cmd (`reboot::RESTART/HALT/POWER_OFF/CAD_ON/CAD_OFF`) | CAD_OFF: Ctrl-Alt-Del sends init SIGINT instead of restarting |
| 64 | `klog` | op (`klog::READ_ALL/CLEAR/SIZE/READ_CLEAR/READ_FROM`), buf, len, (READ_FROM) `*mut u64` position | op-specific; READ_FROM copies whole lines from the position and moves it |
| 65 | `setids_of` | pid, `*const Ids`, `*const u32` groups or null to keep them, group count | root in the Slate domain, for a Slate-domain peer of one of its Unix sockets |
| 66 | `unlock` | slot, `*const u8` key, key len (32) | the boot's unlock program only, while the kernel waits for it; EACCES if the key does not open the slot |
| 67 | `crypt_open` | fd of a block device, slot, `*const u8` key, key len (32) | N of the new `dm-N`; root in the Slate domain; EACCES if the key does not open the slot, EBUSY if the partition is open already |
| 68 | `crypt_close` | N | EBUSY while `dm-N` is mounted or open |
| 69 | `discard` | fd of a block device, offset, length | TRIM of whole sectors; EOPNOTSUPP when the device takes none |
| 58 | `crypt_wrap` | N, `*const u8` key, key len (32), `*mut u8` out, out len (72) | `dm-N`'s master key wrapped under the key, for a new slot; root in the Slate domain; ENXIO if no `dm-N` |

### Memory and time

| # | Call | Arguments | Result |
|---|---|---|---|
| 70 | `map` | addr, len, prot (`prot::*`), flags (`map::*`), fd, offset | address |
| 71 | `unmap` | addr, len | |
| 72 | `protect` | addr, len, prot | |
| 73 | `priority` | pid or 0, set (0 reads, 1 sets), nice (-20 to 19) | 20 − the nice value before, as getpriority(2); setting as setpriority(2): the same user, and CAP_SYS_NICE or RLIMIT_NICE to lower it |
| 80 | `clock_get` | clock (`clock::*`), `*mut Timespec` | |
| 81 | `sleep` | `*const Timespec`, `*mut Timespec` or null (time left) | |
| 83 | `cpu_times` | `*mut [u64; 4]` | the caller's user and system time and its waited-for children's, in nanoseconds |
| 84 | `clock_adjust` | `i64` delta (ns), `u64` flags (`clock_adjust::SYNCED`), `*mut i64` or null | slews the wall clock by the delta (at most ±0.5 s, at 500 ppm; 0: none), marking it synchronized with `SYNCED` (both root only), and writes the slew still to come |
| 82 | `clock_set` | clock (only `clock::REALTIME`), `*const Timespec` | sets the wall clock and, soon after, the hardware clock; EPERM without CAP_SYS_TIME |

### Sockets

| # | Call | Arguments | Result |
|---|---|---|---|
| 90 | `socket` | family, kind (`socket::STREAM/DGRAM/RAW`), protocol, flags (`CLOEXEC`, `NONBLOCK`) | fd |
| 91 | `bind` | fd, addr, addr len | |
| 92 | `listen` | fd, backlog | |
| 93 | `connect` | fd, addr, addr len | |
| 94 | `accept` | fd, addr or null, `*mut u32` or null, flags | fd |
| 95 | `sendto` | fd, buf, len, flags, addr or null, addr len | bytes |
| 96 | `recvfrom` | fd, buf, len, flags, addr or null, `*mut u32` or null | bytes |
| 97 | `setsockopt` | fd, level, name, value, value len | |
| 98 | `getsockopt` | fd, level, name, value, `*mut u32` | |
| 99 | `shutdown` | fd, how (`shutdown::*`) | |
| 100 | `getsockname` | fd, addr, `*mut u32` | |
| 101 | `getpeername` | fd, addr, `*mut u32` | |
| 102 | `sendmsg` | fd, `*const Msg`, flags (Linux `MSG_*`) | bytes; the descriptors in `Msg` travel with the data (Unix sockets) |
| 103 | `recvmsg` | fd, `*mut Msg`, flags (Linux `MSG_*`; `MSG_CMSG_CLOEXEC` makes received descriptors close-on-exec) | bytes; fills in the address, descriptors and flags |
| 104 | `socketpair` | family (only `AF_UNIX`), kind, protocol, flags, `*mut [i32; 2]` | a connected pair; EOPNOTSUPP for IP families |

### Threads

Joined version 1 with threads. Futex words are the process's own
(no shared-memory futexes); a thread pointer follows the x86-64 psABI's
TLS variant II (the word at FS:0 points to itself).

| # | Call | Arguments | Result |
|---|---|---|---|
| 110 | `thread_start` | entry, arg, stack top (16-aligned), tls or 0, `*mut u32` tid word or null | thread ID; the thread starts at `entry(arg)` on the given stack with a zero return address (it must not return), the caller's signal mask and FS base `tls`; the tid word gets the ID at once, and 0 with a futex wake when the thread ends |
| 111 | `thread_exit` | status | ends the calling thread; the last thread out ends the process with `status` |
| 112 | `gettid` | | the calling thread's ID |
| 113 | `futex_wait` | `*const u32`, expected, `*const Timespec` (relative) or null | 0 when woken; EAGAIN if the word differs, ETIMEDOUT, EINTR |
| 114 | `futex_wake` | `*const u32`, count | waiters woken |
| 115 | `set_tls` | base | sets the calling thread's FS base |
| 116 | `xattr_get` | fd, name, name length, buffer, buffer length | the value's length (a zero buffer length asks only that); ENODATA, ERANGE as xattr(7) |
| 117 | `xattr_set` | fd, name, name length, value, value length, flags (`xattr::CREATE`, `REPLACE`) | |
| 118 | `xattr_list` | fd, buffer, buffer length | bytes of names, each ending in a zero byte (only those the caller may read) |
| 119 | `xattr_remove` | fd, name, name length | |
| 120 | `watch_open` | flags (`open::CLOEXEC`, `NONBLOCK`) | a watch descriptor; reading it gives events laid out as inotify(7)'s `struct inotify_event` |
| 121 | `watch_add` | fd, dir, path, path length, mask (`watch::*`, inotify(7)'s values) | the watch's number |
| 122 | `watch_remove` | fd, watch number | |

### Namespaces

Joined for Linux boxes, which Slate's own programs make.
Confined apps get EPERM.

| # | Call | Arguments | Result |
|---|---|---|---|
| 130 | `unshare` | flags (`ns::USER`, `MOUNT`, `PID`, `UTS`, `IPC`, `NET`) | unshare(2): the caller moves into new namespaces of those kinds; `PID` only affects its later children; a new user namespace needs a process of one thread |
| 131 | `pivot_root` | new root, length, put old, length | pivot_root(2) in the caller's mount namespace: the new root (a mount point) becomes the root, the old one moves to put old |

## Structures

All are `#[repr(C)]`, little endian, with explicit reserved fields
(zero them). Sizes are checked by slate-abi's tests.

- `Str` (16 bytes): `ptr: u64, len: u64`.
- `Timespec` (16): `sec: i64, nsec: i64`.
- `Stat` (128): `dev, ino: u64; mode, nlink, uid, gid: u32; rdev,
  size, blocks (512-byte units): u64; block_size: u32; reserved: u32;
  atime, mtime, ctime, btime: Timespec` (btime is zero when unknown).
- `StatFs` (96): `kind` (Linux's statfs magic numbers), `block_size,
  blocks, free, available, files, free_files, fsid, name_max, flags`
  (`mount::*`), two reserved words; all `u64`.
- `DirEntry` (16, then the name): `ino: u64, rec_len: u16, name_len:
  u16, kind: u8` (`dirent::*`), three reserved bytes, then `name_len`
  bytes of name without a NUL; records are padded to `rec_len`, a
  multiple of 8.
- `WaitStatus` (16): `pid: i32, kind: u32` (`wait::EXITED, KILLED,
  DUMPED, STOPPED, CONTINUED_KIND`), `code: i32` (exit status or
  signal), reserved.
- `Ids` (24): `ruid, euid, suid, rgid, egid, sgid: u32`.
- `SigAction` (32): `handler: u64` (`sigaction::DEFAULT` 0, `IGNORE` 1,
  or an address), `flags: u32` (`SIGINFO, RESTART, NODEFER, RESETHAND,
  ONSTACK, NOCLDSTOP, NOCLDWAIT`), reserved, `mask: u64` (bit n-1 for
  signal n), `restorer: u64` (code that calls `sigreturn`). Handlers get
  the same frame as on Linux (signal number, siginfo, ucontext).
- `Utsname` (390): six NUL-padded 65-byte fields.
- `PollFd` (8): `fd: i32, events: i16, revents: i16`.
- `ExecArgs` (32): `argv, argc, envp, envc` (addresses of `Str` arrays
  and their counts); environment strings are `NAME=value`. At most
  128 KiB of strings in all.
- `MountArgs` (64): `source, target, fstype, data`, each a `Str`
  (`data` may be empty).
- `Msg` (48): `bufs, bufs_len` (address and count of `Str` buffers),
  `addr: u64, addr_len: u32` (the peer's address), `flags: u32` (set by
  `recvmsg`: `MSG_TRUNC` 0x20, `MSG_CTRUNC` 0x8 when descriptors did not
  fit), `fds: u64, fds_len: u32` (an array of descriptors to pass, or
  room for received ones; `recvmsg` sets the count), `ttl: u32` (set by
  `recvmsg`: an internet datagram's TTL or hop limit, else 0). There are
  no control messages: descriptors are a plain array, the TTL a field,
  and credentials come from `getsockopt` (`SO_PEERCRED`).

## Not in version 1

epoll and the other event files, namespaces and io_uring. They join
when a native program needs them. Calls join version 1
with new numbers only; existing calls never change meaning. Descriptor
passing (`sendmsg`, `recvmsg`) joined this way for seatd,
threads for slate-rt and slate-libc.

## Programs

- **Rust:** slate-rt (`userland/rt`) wraps every call and translates
  its Linux-style API (O_* flags, wait status words, `Stat`) to the
  native one. Its `program!` macro emits the note.
- **C:** slate-libc (`libs/libc`) and `tools/slate-cc`; see
  `tests/native/` for examples and `cargo xtask sysroot`.
- **Raw:** `tests/native/raw/abi.c` makes the calls directly, with its
  own note and `_start`.
