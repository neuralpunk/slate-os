// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Slate's native system-call interface, called directly (ADR 0031). Built
// freestanding (no C library) and marked native with the Slate ABI note.
// Call numbers, flags and structures are slate-abi's (libs/abi/src/lib.rs);
// keep them in sync. Prints one line per check and exits with the number
// of failures. Run with the argument "child" it exits with status 7 (the
// exec checks use that).

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef int i32;
typedef unsigned short u16;
typedef short i16;
typedef unsigned char u8;

// The note: name "Slate", type 1 (NT_SLATE_ABI), descriptor = version 1.
__asm__(".pushsection .note.slate,\"a\",@note\n"
        ".balign 4\n"
        ".long 6\n.long 4\n.long 1\n"
        ".asciz \"Slate\"\n"
        ".balign 4\n"
        ".long 1\n"
        ".popsection");

__asm__(".text\n"
        ".global _start\n"
        "_start:\n"
        "  xor %ebp, %ebp\n"
        "  mov %rsp, %rdi\n"
        "  and $-16, %rsp\n"
        "  call start_c\n"
        "  ud2\n"
        // Signal handlers return here: native sigreturn (57).
        ".global restorer\n"
        "restorer:\n"
        "  mov $57, %eax\n"
        "  syscall\n"
        "  ud2");
void restorer(void);

enum {
    NR_READ = 0,
    NR_WRITE = 1,
    NR_SEEK = 4,
    NR_CLOSE = 5,
    NR_DUP = 6,
    NR_PIPE = 7,
    NR_FCNTL = 9,
    NR_POLL = 10,
    NR_TRUNCATE = 11,
    NR_READDIR = 13,
    NR_FLOCK = 14,
    NR_SERVICE = 15,
    NR_OPEN = 20,
    NR_STAT = 21,
    NR_MKDIR = 22,
    NR_UNLINK = 24,
    NR_RENAME = 25,
    NR_LINK = 26,
    NR_SYMLINK = 27,
    NR_READLINK = 28,
    NR_CHMOD = 29,
    NR_UTIMES = 31,
    NR_ACCESS = 32,
    NR_CHDIR = 33,
    NR_GETCWD = 34,
    NR_UMASK = 36,
    NR_STATFS = 37,
    NR_EXIT = 40,
    NR_FORK = 41,
    NR_EXEC = 42,
    NR_WAIT = 43,
    NR_GETPID = 44,
    NR_GETPPID = 45,
    NR_GETIDS = 46,
    NR_SETIDS = 47,
    NR_KILL = 50,
    NR_SIGACTION = 55,
    NR_SIGMASK = 56,
    NR_UNAME = 60,
    NR_GETRANDOM = 62,
    NR_KLOG = 64,
    NR_UNLOCK = 66,
    NR_CRYPT_OPEN = 67,
    NR_CRYPT_CLOSE = 68,
    NR_DISCARD = 69,
    NR_CRYPT_WRAP = 58,
    NR_MAP = 70,
    NR_UNMAP = 71,
    NR_PROTECT = 72,
    NR_CLOCK_GET = 80,
    NR_SLEEP = 81,
    NR_CLOCK_SET = 82,
    NR_CPU_TIMES = 83,
    NR_CLOCK_ADJUST = 84,
    NR_PRIORITY = 73,
    NR_RLIMIT = 59,
    NR_SOCKET = 90,
    NR_BIND = 91,
    NR_LISTEN = 92,
    NR_CONNECT = 93,
    NR_ACCEPT = 94,
    NR_SENDMSG = 102,
    NR_RECVMSG = 103,
    NR_SOCKETPAIR = 104,
    NR_THREAD_START = 110,
    NR_THREAD_EXIT = 111,
    NR_GETTID = 112,
    NR_FUTEX_WAIT = 113,
    NR_FUTEX_WAKE = 114,
    NR_SET_TLS = 115,
    NR_XATTR_GET = 116,
    NR_XATTR_SET = 117,
    NR_XATTR_LIST = 118,
    NR_XATTR_REMOVE = 119,
    NR_WATCH_OPEN = 120,
    NR_WATCH_ADD = 121,
    NR_WATCH_REMOVE = 122,
};
#define CWD (-100L)
#define O_WRITE_ONLY 1
#define O_READ_WRITE 2
#define O_CREATE (1 << 2)
#define O_EXCL (1 << 3)
#define O_TRUNC (1 << 4)
#define O_APPEND (1 << 5)
#define O_NONBLOCK (1 << 6)
#define O_CLOEXEC (1 << 7)
#define O_DIRECTORY (1 << 8)
#define O_SYNC (1 << 11)
#define O_DIRECT_ (1 << 13)
#define O_NOATIME_ (1 << 14)
#define P_NOFOLLOW 1
#define P_EMPTY_PATH 2
#define P_REMOVE_DIR 4
#define F_GETFD 1
#define F_GETFL 3
#define F_SETFL 4
#define W_NOHANG 1
#define W_EXITED 1
#define W_KILLED 2
#define SA_RESTART 2
#define MAP_SHARED 1
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 8
#define AT_SLATE_ABI 0x5100
#define SIGUSR1 10
#define SIGKILL 9
#define POLL_IN 1
#define AF_UNIX 1
#define SOCK_STREAM 1
#define EPERM 1
#define ENOENT 2
#define ESRCH 3
#define ENXIO 6
#define EBADF 9
#define ECHILD 10
#define EWOULDBLOCK 11
#define ENOTBLK 15
#define EEXIST 17
#define ENOTDIR 20
#define EINVAL 22
#define ERANGE 34
#define ENODATA 61
#define ENOSYS 38
#define ETIMEDOUT 110

struct str {
    u64 ptr, len;
};
struct timespec {
    i64 sec, nsec;
};
struct stat {
    u64 dev, ino;
    u32 mode, nlink, uid, gid;
    u64 rdev, size, blocks;
    u32 block_size, reserved;
    struct timespec atime, mtime, ctime, btime;
};
struct statfs {
    u64 kind, block_size, blocks, free, available, files, free_files, fsid, name_max, flags, reserved[2];
};
struct wait_status {
    i32 pid;
    u32 kind;
    i32 code;
    u32 reserved;
};
struct ids {
    u32 ruid, euid, suid, rgid, egid, sgid;
};
struct sigaction {
    u64 handler;
    u32 flags, reserved;
    u64 mask, restorer;
};
struct exec_args {
    u64 argv, argc, envp, envc;
};
struct pollfd {
    i32 fd;
    i16 events, revents;
};

_Static_assert(sizeof(struct stat) == 128, "Stat is 128 bytes");
_Static_assert(sizeof(struct statfs) == 96, "StatFs is 96 bytes");

static i64 sys(u64 n, u64 a, u64 b, u64 c, u64 d, u64 e, u64 f) {
    register u64 r10 __asm__("r10") = d;
    register u64 r8 __asm__("r8") = e;
    register u64 r9 __asm__("r9") = f;
    i64 ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
}
// SYS(n, args...): missing arguments are 0. Arguments are expanded
// first, so P() below counts as two.
#define SYS_(n, a, b, c, d, e, f, ...) sys(n, (u64)(a), (u64)(b), (u64)(c), (u64)(d), (u64)(e), (u64)(f))
#define SYS(...) SYS_(__VA_ARGS__, 0, 0, 0, 0, 0, 0, 0)

static u64 len(const char *s) {
    u64 n = 0;
    while (s[n])
        n++;
    return n;
}

// A path argument pair: pointer and length.
#define P(s) (u64)(s), len(s)

static void put(const char *s) { SYS(NR_WRITE, 1, s, len(s)); }

static int failures;

static void check(const char *name, int ok) {
    put(ok ? "native-abi: ok " : "native-abi: FAIL ");
    put(name);
    put("\n");
    if (!ok)
        failures++;
}

static int same(const char *a, const char *b, u64 n) {
    for (u64 i = 0; i < n; i++)
        if (a[i] != b[i])
            return 0;
    return 1;
}

static int starts_with(const char *s, const char *p) { return same(s, p, len(p)); }

static volatile int got_signal;

static void on_usr1(int sig) { got_signal = sig; }

static const char self[] = "/test/native-abi";

static void files(void) {
    check("mkdir", SYS(NR_MKDIR, CWD, P("/tmp/nabi"), 0755) == 0);
    check("mkdir_exists", SYS(NR_MKDIR, CWD, P("/tmp/nabi"), 0755) == -EEXIST);
    i64 dir = SYS(NR_OPEN, CWD, P("/tmp/nabi"), O_DIRECTORY | O_CLOEXEC, 0);
    check("open_dir", dir >= 0);
    // Relative to a directory handle.
    i64 fd = SYS(NR_OPEN, dir, P("f"), O_READ_WRITE | O_CREATE | O_EXCL, 0640);
    check("open_create_at", fd >= 0);
    check("write", SYS(NR_WRITE, fd, "hello world", 11) == 11);
    check("seek", SYS(NR_SEEK, fd, 6, 0) == 6);
    char buf[64];
    check("read_after_seek", SYS(NR_READ, fd, buf, 5) == 5 && same(buf, "world", 5));
    check("truncate", SYS(NR_TRUNCATE, fd, 5) == 0);
    struct stat st;
    check("stat_empty_path", SYS(NR_STAT, fd, "", 0, P_EMPTY_PATH, &st) == 0 && st.size == 5 &&
                                 (st.mode & 0170777) == 0100640);
    check("stat_empty_needs_flag", SYS(NR_STAT, fd, "", 0, 0, &st) == -ENOENT);
    check("fcntl_getfl", SYS(NR_FCNTL, fd, F_GETFL, 0) == O_READ_WRITE);
    check("fcntl_setfl", SYS(NR_FCNTL, fd, F_SETFL, O_APPEND) == 0 && SYS(NR_FCNTL, fd, F_GETFL, 0) == (O_READ_WRITE | O_APPEND));
    check("fcntl_getfd", SYS(NR_FCNTL, dir, F_GETFD, 0) == 1);
    i64 d2 = SYS(NR_DUP, fd, -1, 0);
    check("dup_lowest", d2 > fd);
    check("dup_to", SYS(NR_DUP, fd, 40, O_CLOEXEC) == 40 && SYS(NR_FCNTL, 40, F_GETFD, 0) == 1);
    check("dup_same", SYS(NR_DUP, fd, fd, 0) == fd);
    check("dup_bad_flags", SYS(NR_DUP, fd, -1, O_NONBLOCK) == -EINVAL);
    // Extended attributes of an open file (tmpfs keeps them).
    check("xattr_set", SYS(NR_XATTR_SET, fd, "user.k", 6, "value", 5, 0) == 0);
    check("xattr_set_create_exists", SYS(NR_XATTR_SET, fd, "user.k", 6, "v", 1, 1) == -EEXIST);
    check("xattr_get_size", SYS(NR_XATTR_GET, fd, "user.k", 6, buf, 0) == 5);
    check("xattr_get", SYS(NR_XATTR_GET, fd, "user.k", 6, buf, sizeof buf) == 5 && same(buf, "value", 5));
    check("xattr_get_small", SYS(NR_XATTR_GET, fd, "user.k", 6, buf, 2) == -ERANGE);
    check("xattr_list", SYS(NR_XATTR_LIST, fd, buf, sizeof buf) == 7 && same(buf, "user.k", 7));
    check("xattr_remove", SYS(NR_XATTR_REMOVE, fd, "user.k", 6) == 0);
    check("xattr_gone", SYS(NR_XATTR_GET, fd, "user.k", 6, buf, sizeof buf) == -ENODATA);
    check("xattr_bad_flags", SYS(NR_XATTR_SET, fd, "user.k", 6, "v", 1, 4) == -EINVAL);
    SYS(NR_CLOSE, 40);
    SYS(NR_CLOSE, d2);
    SYS(NR_CLOSE, fd);
    check("close_twice", SYS(NR_CLOSE, fd) == -EBADF);
    // open::SYNC is kept: writes are durable when they return.
    fd = SYS(NR_OPEN, dir, P("synced"), O_READ_WRITE | O_CREATE | O_SYNC, 0640);
    check("open_sync", fd >= 0 && SYS(NR_WRITE, fd, "x", 1) == 1 &&
                           SYS(NR_FCNTL, fd, F_GETFL, 0) == (O_READ_WRITE | O_SYNC));
    SYS(NR_CLOSE, fd);
    // open::DIRECT and NOATIME (ADR 0145): kept, and settable.
    fd = SYS(NR_OPEN, dir, P("synced"), O_READ_WRITE | O_DIRECT_ | O_NOATIME_, 0);
    check("open_direct", fd >= 0 && SYS(NR_WRITE, fd, "y", 1) == 1 &&
                             SYS(NR_FCNTL, fd, F_GETFL, 0) == (O_READ_WRITE | O_DIRECT_ | O_NOATIME_));
    check("setfl_direct", SYS(NR_FCNTL, fd, F_SETFL, 0) == 0 && SYS(NR_FCNTL, fd, F_GETFL, 0) == O_READ_WRITE);
    SYS(NR_CLOSE, fd);
    check("open_unknown_flag", SYS(NR_OPEN, dir, P("synced"), O_READ_WRITE | (1 << 15), 0) == -EINVAL);
    // Watches (ADR 0149): a file made in a watched directory is an event
    // laid out as inotify(7)'s (wd, mask, cookie, len, name).
    {
        i64 w = SYS(NR_WATCH_OPEN, O_CLOEXEC | O_NONBLOCK);
        check("watch_open", w >= 0);
        i64 wd = SYS(NR_WATCH_ADD, w, dir, P("."), 0x100 /* CREATE */);
        check("watch_add", wd >= 1);
        i64 nf = SYS(NR_OPEN, dir, P("watched"), O_READ_WRITE | O_CREATE, 0640);
        SYS(NR_CLOSE, nf);
        unsigned char ev[64];
        i64 got = SYS(NR_READ, w, ev, sizeof ev);
        unsigned mask = ev[4] | ev[5] << 8 | ev[6] << 16 | (unsigned)ev[7] << 24;
        check("watch_event", got >= 16 && (i64)(ev[0] | ev[1] << 8) == wd && mask == 0x100 && same((char *)ev + 16, "watched", 7));
        check("watch_none_left", SYS(NR_READ, w, ev, sizeof ev) == -EWOULDBLOCK);
        check("watch_bad_mask", SYS(NR_WATCH_ADD, w, dir, P("."), 0x00010000) == -EINVAL);
        check("watch_remove", SYS(NR_WATCH_REMOVE, w, wd) == 0);
        check("watch_bad_flags", SYS(NR_WATCH_OPEN, 1 << 3) == -EINVAL);
        SYS(NR_UNLINK, dir, P("watched"), 0);
        SYS(NR_CLOSE, w);
    }
    SYS(NR_UNLINK, dir, P("synced"), 0);
    // flock: two opens of one file exclude each other.
    i64 l1 = SYS(NR_OPEN, dir, P("locked"), O_READ_WRITE | O_CREATE, 0640);
    i64 l2 = SYS(NR_OPEN, dir, P("locked"), O_READ_WRITE, 0);
    check("flock_exclusive", SYS(NR_FLOCK, l1, 2, 0) == 0);
    check("flock_nonblock_busy", SYS(NR_FLOCK, l2, 2 | 16, 0) == -EWOULDBLOCK);
    check("flock_shared_busy", SYS(NR_FLOCK, l2, 1 | 16, 0) == -EWOULDBLOCK);
    check("flock_unlock", SYS(NR_FLOCK, l1, 3, 0) == 0 && SYS(NR_FLOCK, l2, 1 | 16, 0) == 0);
    check("flock_bad_op", SYS(NR_FLOCK, l1, 4, 0) == -EINVAL);
    SYS(NR_CLOSE, l1);
    SYS(NR_CLOSE, l2);
    SYS(NR_UNLINK, dir, P("locked"), 0);

    check("link", SYS(NR_LINK, dir, P("f"), dir, P("g")) == 0);
    check("link_count", SYS(NR_STAT, CWD, P("/tmp/nabi/f"), 0, &st) == 0 && st.nlink == 2);
    check("rename", SYS(NR_RENAME, dir, P("g"), CWD, P("/tmp/nabi/h")) == 0);
    check("symlink", SYS(NR_SYMLINK, P("f"), dir, P("s")) == 0);
    check("readlink", SYS(NR_READLINK, dir, P("s"), buf, sizeof buf, 0) == 1 && buf[0] == 'f');
    check("stat_nofollow", SYS(NR_STAT, dir, P("s"), P_NOFOLLOW, &st) == 0 && (st.mode & 0170000) == 0120000);
    check("chmod", SYS(NR_CHMOD, dir, P("f"), 0600, 0) == 0 && SYS(NR_STAT, dir, P("f"), 0, &st) == 0 &&
                       (st.mode & 0777) == 0600);
    struct timespec times[2] = {{1000, 0}, {2000, 500}};
    check("utimes", SYS(NR_UTIMES, dir, P("f"), times, 0) == 0 && SYS(NR_STAT, dir, P("f"), 0, &st) == 0 &&
                        st.mtime.sec == 2000 && st.mtime.nsec == 500 && st.atime.sec == 1000);
    check("access", SYS(NR_ACCESS, dir, P("f"), 4, 0) == 0);
    check("access_missing", SYS(NR_ACCESS, dir, P("nope"), 0, 0) == -ENOENT);

    // Directory records: inode, length, name length, type, name.
    char ents[512];
    i64 n = SYS(NR_READDIR, dir, ents, sizeof ents);
    int seen = 0, sane = n > 0;
    for (i64 at = 0; at < n;) {
        u16 rec = *(u16 *)(ents + at + 8), nl = *(u16 *)(ents + at + 10);
        u8 kind = (u8)ents[at + 12];
        if (rec % 8 || rec < 16 + nl)
            sane = 0;
        if (nl == 1 && ents[at + 16] == 'f' && kind == 8)
            seen |= 1;
        if (nl == 1 && ents[at + 16] == 's' && kind == 10)
            seen |= 2;
        at += rec;
    }
    check("readdir", sane && seen == 3);
    check("readdir_end", SYS(NR_READDIR, dir, ents, sizeof ents) == 0);
    check("readdir_small", SYS(NR_SEEK, dir, 0, 0) == 0 && SYS(NR_READDIR, dir, ents, 8) == -EINVAL);

    // Working directory by handle; getcwd has no NUL.
    check("chdir_handle", SYS(NR_CHDIR, dir, "", 0, P_EMPTY_PATH) == 0);
    i64 cl = SYS(NR_GETCWD, buf, sizeof buf);
    check("getcwd", cl == 9 && same(buf, "/tmp/nabi", 9));
    check("getcwd_small", SYS(NR_GETCWD, buf, 4) == -ERANGE);
    check("open_relative_cwd", (fd = SYS(NR_OPEN, CWD, P("f"), 0, 0)) >= 0 && SYS(NR_CLOSE, fd) == 0);
    check("chdir_path", SYS(NR_CHDIR, CWD, P("/"), 0) == 0);

    check("unlink", SYS(NR_UNLINK, dir, P("f"), 0) == 0 && SYS(NR_UNLINK, dir, P("s"), 0) == 0 &&
                        SYS(NR_UNLINK, dir, P("h"), 0) == 0);
    check("unlink_dir_needs_flag", SYS(NR_UNLINK, CWD, P("/tmp/nabi"), 0) != 0);
    check("rmdir", SYS(NR_UNLINK, CWD, P("/tmp/nabi"), P_REMOVE_DIR) == 0);
    SYS(NR_CLOSE, dir);
    check("umask", SYS(NR_UMASK, 022) >= 0 && SYS(NR_UMASK, 022) == 022);
    struct statfs sf;
    check("statfs", SYS(NR_STATFS, CWD, P("/tmp"), 0, &sf) == 0 && sf.block_size > 0);
    check("not_a_dir", SYS(NR_OPEN, CWD, P("/etc/passwd/x"), 0, 0) == -ENOTDIR);
}

static void processes(char **envp, u64 envc) {
    struct ids ids;
    check("getids", SYS(NR_GETIDS, &ids) == 0 && ids.ruid == 0 && ids.egid == 0);
    check("getppid", SYS(NR_GETPPID) >= 0);
    char uts[390];
    check("uname", SYS(NR_UNAME, uts) == 0 && starts_with(uts, "Linux") && starts_with(uts + 4 * 65, "x86_64"));

    // A pipe between parent and child.
    i32 fds[2];
    check("pipe", SYS(NR_PIPE, fds, O_CLOEXEC) == 0);
    i64 pid = SYS(NR_FORK);
    if (pid == 0) {
        SYS(NR_WRITE, fds[1], "from child", 10);
        SYS(NR_EXIT, 3);
    }
    SYS(NR_CLOSE, fds[1]);
    char buf[32];
    struct pollfd pfd = {fds[0], POLL_IN, 0};
    check("poll", SYS(NR_POLL, &pfd, 1, 5000) == 1 && (pfd.revents & POLL_IN));
    check("pipe_read", SYS(NR_READ, fds[0], buf, sizeof buf) == 10 && same(buf, "from child", 10));
    struct wait_status ws;
    check("wait_exited", SYS(NR_WAIT, pid, &ws, 0) == pid && ws.pid == pid && ws.kind == W_EXITED && ws.code == 3);
    check("wait_none", SYS(NR_WAIT, -1, &ws, W_NOHANG) == -ECHILD);
    SYS(NR_CLOSE, fds[0]);

    // setids is all or nothing: a group change it allows doesn't happen
    // when the user change beside it is refused.
    pid = SYS(NR_FORK);
    if (pid == 0) {
        struct ids user = {1000, 1000, 1000, 1000, 1000, 1001};
        struct ids both = {0, 0, 0, 1001, 1001, 1001};
        struct ids now;
        int ok = SYS(NR_SETIDS, &user) == 0 && SYS(NR_SETIDS, &both) == -EPERM && SYS(NR_GETIDS, &now) == 0 &&
                 now.rgid == 1000 && now.egid == 1000 && now.sgid == 1001 && now.euid == 1000;
        SYS(NR_EXIT, ok ? 0 : 1);
    }
    check("setids_all_or_nothing", SYS(NR_WAIT, pid, &ws, 0) == pid && ws.kind == W_EXITED && ws.code == 0);

    // exec with counted argument and environment vectors.
    struct str argv[2] = {{(u64)self, len(self)}, {(u64) "child-and-junk", 5}};
    struct str env[1] = {{(u64) "NATIVE=1", 8}};
    struct exec_args ea = {(u64)argv, 2, (u64)env, 1};
    (void)envp;
    (void)envc;
    pid = SYS(NR_FORK);
    if (pid == 0) {
        SYS(NR_EXEC, CWD, P(self), &ea, 0);
        SYS(NR_EXIT, 99);
    }
    check("exec_native", SYS(NR_WAIT, pid, &ws, 0) == pid && ws.kind == W_EXITED && ws.code == 7);
    // A native process may exec a Linux program; it gets the Linux table.
    static const char hello[] = "/test/hello";
    struct str hargv[1] = {{(u64)hello, len(hello)}};
    struct exec_args hea = {(u64)hargv, 1, (u64)env, 0};
    pid = SYS(NR_FORK);
    if (pid == 0) {
        SYS(NR_EXEC, CWD, P(hello), &hea, 0);
        SYS(NR_EXIT, 99);
    }
    check("exec_linux", SYS(NR_WAIT, pid, &ws, 0) == pid && ws.kind == W_EXITED && ws.code == 0);
    check("exec_missing", SYS(NR_EXEC, CWD, P("/nonexistent"), &ea, 0) == -ENOENT);

    // Signals: a handler, its restorer, and kill.
    struct sigaction sa = {(u64)on_usr1, SA_RESTART, 0, 0, (u64)restorer}, old;
    check("sigaction", SYS(NR_SIGACTION, SIGUSR1, &sa, 0) == 0);
    check("sigaction_old", SYS(NR_SIGACTION, SIGUSR1, 0, &old) == 0 && old.handler == (u64)on_usr1 &&
                               old.flags == SA_RESTART);
    sa.restorer = 0;
    check("sigaction_needs_restorer", SYS(NR_SIGACTION, SIGUSR1, &sa, 0) == -EINVAL);
    check("kill_self", SYS(NR_KILL, SYS(NR_GETPID), SIGUSR1) == 0 && got_signal == SIGUSR1);
    u64 block = 1ul << (SIGUSR1 - 1), was;
    got_signal = 0;
    check("sigmask_block", SYS(NR_SIGMASK, 0, &block, 0) == 0);
    SYS(NR_KILL, SYS(NR_GETPID), SIGUSR1);
    check("signal_blocked", got_signal == 0);
    check("sigmask_unblock", SYS(NR_SIGMASK, 1, &block, &was) == 0 && (was & block) && got_signal == SIGUSR1);
    pid = SYS(NR_FORK);
    if (pid == 0) {
        struct timespec forever = {100, 0};
        SYS(NR_SLEEP, &forever, 0);
        SYS(NR_EXIT, 0);
    }
    SYS(NR_KILL, pid, SIGKILL);
    check("wait_killed", SYS(NR_WAIT, pid, &ws, 0) == pid && ws.kind == W_KILLED && ws.code == SIGKILL);
}

static void memory_and_time(void) {
    i64 m = SYS(NR_MAP, 0, 8192, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check("map", m > 0 && (m & 4095) == 0);
    char *p = (char *)m;
    p[0] = 'x';
    p[8191] = 'y';
    check("map_usable", p[0] == 'x' && p[8191] == 'y');
    check("protect", SYS(NR_PROTECT, m, 4096, 1) == 0);
    check("map_bad_flags", SYS(NR_MAP, 0, 4096, 3, MAP_ANONYMOUS, -1, 0) == -EINVAL);
    check("unmap", SYS(NR_UNMAP, m, 8192) == 0);
    struct timespec a, b, nap = {0, 20000000};
    check("clock_get", SYS(NR_CLOCK_GET, 1, &a) == 0);
    // clock_set: only the wall clock, with a sane time (set to itself).
    struct timespec wall, bad = {0, 1000000000};
    check("clock_set_only_realtime", SYS(NR_CLOCK_SET, 1, &a) == -EINVAL);
    check("clock_set_bad_nsec", SYS(NR_CLOCK_SET, 0, &bad) == -EINVAL);
    check("clock_set", SYS(NR_CLOCK_GET, 0, &wall) == 0 && SYS(NR_CLOCK_SET, 0, &wall) == 0);
    check("sleep", SYS(NR_SLEEP, &nap, 0) == 0);
    SYS(NR_CLOCK_GET, 1, &b);
    i64 ns = (b.sec - a.sec) * 1000000000 + (b.nsec - a.nsec);
    check("slept", ns >= 20000000);
    check("clock_bad", SYS(NR_CLOCK_GET, 99, &a) == -EINVAL);
    // rlimit (RLIMIT_NOFILE = 7) and cpu_times (M21 phase 3).
    u64 lim[2], lower[2], times[4];
    check("rlimit_get", SYS(NR_RLIMIT, 7, 0, lim) == 0 && lim[0] > 0 && lim[0] <= lim[1]);
    lower[0] = lim[0] - 1;
    lower[1] = lim[1];
    check("rlimit_set", SYS(NR_RLIMIT, 7, lower, 0) == 0 && SYS(NR_RLIMIT, 7, 0, lim) == 0 && lim[0] == lower[0]);
    check("rlimit_bad", SYS(NR_RLIMIT, 99, 0, lim) == -EINVAL);
    // priority: nice 0 reads as 20; set to 5, then back.
    check("priority_read", SYS(NR_PRIORITY, 0, 0, 0) == 20);
    check("priority_set", SYS(NR_PRIORITY, 0, 1, 5) == 20 && SYS(NR_PRIORITY, 0, 0, 0) == 15);
    check("priority_back", SYS(NR_PRIORITY, 0, 1, 0) == 15 && SYS(NR_PRIORITY, 0, 0, 0) == 20);
    check("priority_none", SYS(NR_PRIORITY, 999999, 0, 0) == -ESRCH);
    check("cpu_times", SYS(NR_CPU_TIMES, times) == 0 && times[0] + times[1] > 0);
    // clock_adjust (M23 phase 1): reading, a 1 µs slew, bad flags, too big.
    i64 left = -1;
    check("clock_adjust_read", SYS(NR_CLOCK_ADJUST, 0, 0, &left) == 0 && left >= 0);
    check("clock_adjust_slew", SYS(NR_CLOCK_ADJUST, 1000, 0, &left) == 0 && left >= 0 && left <= 1000);
    check("clock_adjust_bad", SYS(NR_CLOCK_ADJUST, 0, 2, &left) == -EINVAL &&
                                  SYS(NR_CLOCK_ADJUST, 600000000, 0, &left) == -EINVAL);
    // service is init's (ADR 0060); klog READ_FROM (5) reads whole lines
    // and moves the position past them.
    check("service_not_init", SYS(NR_SERVICE, 1, 1, "x", 1) == -EPERM);
    static char logbuf[4096];
    u64 logpos = 0;
    i64 got = SYS(NR_KLOG, 5, logbuf, sizeof logbuf, &logpos);
    check("klog_from", got > 0 && logbuf[got - 1] == '\n' && logpos > 0);
    u64 was = logpos;
    got = SYS(NR_KLOG, 5, logbuf, sizeof logbuf, &logpos);
    check("klog_from_moves", got >= 0 && logpos >= was && (got == 0 || logbuf[got - 1] == '\n'));
    check("klog_bad_op", SYS(NR_KLOG, 99, logbuf, 1) == -EINVAL);
    u64 r[2] = {0, 0};
    check("getrandom", SYS(NR_GETRANDOM, r, 16, 0) == 16 && (r[0] | r[1]));
    // Only the boot's unlock program may hand over a disk key (ADR 0038).
    static u8 key[32];
    check("unlock_outside_boot", SYS(NR_UNLOCK, 0, key, 32) == -EPERM);
    // crypt_open wants a block device (ADR 0039); stdin is not one, and no
    // dm-99 exists to close.
    check("crypt_open_not_block", SYS(NR_CRYPT_OPEN, 0, 0, key, 32) == -ENOTBLK || SYS(NR_CRYPT_OPEN, 0, 0, key, 32) == -EPERM);
    check("crypt_close_none", SYS(NR_CRYPT_CLOSE, 99) == -ENXIO || SYS(NR_CRYPT_CLOSE, 99) == -EPERM);
    check("discard_not_block", SYS(NR_DISCARD, 1, 0, 512) == -ENOTBLK || SYS(NR_DISCARD, 1, 0, 512) == -EBADF);
    // crypt_wrap (ADR 0058): root in the Slate domain, and no dm-99.
    static u8 wrapped[72];
    check("crypt_wrap_none", SYS(NR_CRYPT_WRAP, 99, key, 32, wrapped, 72) == -ENXIO || SYS(NR_CRYPT_WRAP, 99, key, 32, wrapped, 72) == -EPERM);
}

static void sockets(void) {
    // A Unix stream socket talking to itself through a listener.
    struct {
        u16 family;
        char path[32];
    } addr = {AF_UNIX, "/tmp/nabi.sock"};
    u64 alen = 2 + len(addr.path) + 1;
    i64 l = SYS(NR_SOCKET, AF_UNIX, SOCK_STREAM, 0, O_CLOEXEC);
    check("socket", l >= 0);
    check("bind", SYS(NR_BIND, l, &addr, alen) == 0);
    check("listen", SYS(NR_LISTEN, l, 4) == 0);
    i64 c = SYS(NR_SOCKET, AF_UNIX, SOCK_STREAM, 0, 0);
    check("connect", SYS(NR_CONNECT, c, &addr, alen) == 0);
    i64 s = SYS(NR_ACCEPT, l, 0, 0, O_CLOEXEC);
    check("accept", s >= 0);
    char buf[8];
    check("socket_io", SYS(NR_WRITE, c, "ping", 4) == 4 && SYS(NR_READ, s, buf, sizeof buf) == 4 && same(buf, "ping", 4));
    check("socket_bad_kind", SYS(NR_SOCKET, AF_UNIX, 9, 0, 0) == -EINVAL);
    // socketpair (ADR 0075): Unix only, flags as for socket.
    i32 pair[2] = {-1, -1};
    check("socketpair", SYS(NR_SOCKETPAIR, AF_UNIX, SOCK_STREAM, 0, O_CLOEXEC, pair) == 0 &&
                            SYS(NR_WRITE, pair[0], "pq", 2) == 2 && SYS(NR_READ, pair[1], buf, sizeof buf) == 2 &&
                            same(buf, "pq", 2) && SYS(NR_FCNTL, pair[0], F_GETFD, 0) == 1);
    check("socketpair_inet", SYS(NR_SOCKETPAIR, 2, SOCK_STREAM, 0, 0, pair) == -95);
    SYS(NR_CLOSE, pair[0]);
    SYS(NR_CLOSE, pair[1]);

    // Descriptors travel with the bytes (sendmsg/recvmsg and `Msg`).
    struct str { u64 ptr, len; };
    struct msg { u64 bufs, bufs_len, addr; u32 addr_len, flags; u64 fds; u32 fds_len, ttl; };
    i32 pass[2] = {(i32)SYS(NR_OPEN, CWD, P("/etc/passwd"), O_CLOEXEC, 0), 0};
    pass[1] = pass[0];
    struct str out = {(u64) "fd!", 3};
    struct msg m = {.bufs = (u64)&out, .bufs_len = 1, .fds = (u64)pass, .fds_len = 1};
    check("sendmsg", SYS(NR_SENDMSG, c, &m, 0) == 3);
    i32 got[2] = {-1, -1};
    struct str in = {(u64)buf, sizeof buf};
    struct msg r = {.bufs = (u64)&in, .bufs_len = 1, .fds = (u64)got, .fds_len = 2};
    char five[5];
    check("recvmsg", SYS(NR_RECVMSG, s, &r, 0) == 3 && same(buf, "fd!", 3) && r.fds_len == 1 && got[0] >= 0 &&
                         got[0] != pass[0] && SYS(NR_READ, got[0], five, 5) == 5 && starts_with(five, "root:"));
    m.fds_len = 2;
    r.fds_len = 1;
    check("recvmsg_fds_cut", SYS(NR_SENDMSG, c, &m, 0) == 3 && SYS(NR_RECVMSG, s, &r, 0) == 3 && r.fds_len == 1 &&
                                 (r.flags & 0x8));
    SYS(NR_CLOSE, s);
    SYS(NR_CLOSE, c);
    SYS(NR_CLOSE, l);
    SYS(NR_UNLINK, CWD, P("/tmp/nabi.sock"), 0);

    // An internet datagram's TTL comes in `Msg.ttl`: one sent to itself
    // over loopback has Slate's default, 64. AF_INET, SOCK_DGRAM;
    // `struct sockaddr_in` for 127.0.0.1:12345 (port and address in
    // network order).
    struct { u16 family, port; u32 addr; u8 zero[8]; } self_addr = {2, 0x3930, 0x0100007F, {0}};
    i64 u = SYS(NR_SOCKET, 2, 2, 0, O_CLOEXEC);
    struct str ttl_out = {(u64) "ttl", 3};
    struct msg tm = {.bufs = (u64)&ttl_out, .bufs_len = 1, .addr = (u64)&self_addr, .addr_len = 16};
    check("udp_bind", SYS(NR_BIND, u, &self_addr, 16) == 0 && SYS(NR_SENDMSG, u, &tm, 0) == 3);
    struct str ttl_in = {(u64)buf, sizeof buf};
    struct msg tr = {.bufs = (u64)&ttl_in, .bufs_len = 1};
    check("recvmsg_ttl", SYS(NR_RECVMSG, u, &tr, 0) == 3 && same(buf, "ttl", 3) && tr.ttl == 64);
    SYS(NR_CLOSE, u);
}

// Threads (ADR 0073): a thread on a static stack with its own thread
// pointer, which checks FS:0, adds to a word and wakes the main thread.
static u8 thread_stack[16384] __attribute__((aligned(16)));
static u64 thread_tcb[8] __attribute__((aligned(64)));
static volatile u32 thread_word, thread_tid;
static volatile u64 thread_saw_fs;

static void thread_entry(u64 arg) {
    u64 fs0;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(fs0));
    thread_saw_fs = fs0;
    thread_word = (u32)arg;
    SYS(NR_FUTEX_WAKE, &thread_word, 1);
    SYS(NR_THREAD_EXIT, 0);
    for (;;)
        ;
}

static void threads(void) {
    check("gettid_main", SYS(NR_GETTID) == SYS(NR_GETPID));
    struct timespec short_wait = {0, 10000000};
    u32 word = 5;
    check("futex_wait_differs", SYS(NR_FUTEX_WAIT, &word, 4, 0) == -EWOULDBLOCK);
    check("futex_wait_timeout", SYS(NR_FUTEX_WAIT, &word, 5, &short_wait) == -ETIMEDOUT);
    check("futex_wait_unaligned", SYS(NR_FUTEX_WAIT, (u8 *)&word + 1, 5, 0) == -EINVAL);
    check("futex_wake_none", SYS(NR_FUTEX_WAKE, &word, 1) == 0);
    u64 top = (u64)(thread_stack + sizeof thread_stack);
    check("thread_start_bad_stack", SYS(NR_THREAD_START, thread_entry, 0, top - 8, 0, 0) == -EINVAL);
    thread_tcb[0] = (u64)thread_tcb;
    i64 tid = SYS(NR_THREAD_START, thread_entry, 77, top, thread_tcb, &thread_tid);
    check("thread_start", tid > 0 && tid != SYS(NR_GETTID));
    // The tid word holds the ID until the thread ends, then 0 (and a wake).
    while (thread_word == 0)
        SYS(NR_FUTEX_WAIT, &thread_word, 0, 0);
    for (u32 t; (t = thread_tid) != 0;)
        SYS(NR_FUTEX_WAIT, &thread_tid, t, 0);
    check("thread_ran", thread_word == 77 && thread_saw_fs == (u64)thread_tcb);
    check("thread_ended", thread_tid == 0);
    // The main thread's own thread pointer.
    static u64 main_tcb[8] __attribute__((aligned(64)));
    main_tcb[0] = (u64)main_tcb;
    u64 fs0 = 0;
    check("set_tls", SYS(NR_SET_TLS, main_tcb) == 0);
    __asm__ volatile("mov %%fs:0, %0" : "=r"(fs0));
    check("set_tls_used", fs0 == (u64)main_tcb);
    check("set_tls_kernel", SYS(NR_SET_TLS, 0xffff800000000000UL) == -EPERM);
}

void start_c(u64 *sp) {
    u64 argc = sp[0];
    char **argv = (char **)(sp + 1);
    if (argc > 1 && same(argv[1], "child", 6))
        SYS(NR_EXIT, 7);
    // "wx": whether a writable and executable mapping is allowed (strict
    // W^X in the Slate domain, ADR 0032).
    if (argc > 1 && same(argv[1], "wx", 3)) {
        put(SYS(NR_MAP, 0, 4096, 7, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) > 0 ? "wx allowed\n" : "wx refused\n");
        SYS(NR_EXIT, 0);
    }
    // "keptsock": a connection to a Slate-domain server stays in the Slate
    // domain (ADR 0098): a Linux program run from here does not get it,
    // but gets the end of a socketpair (fds 20 and 21). Run in the Slate
    // domain; prints what busybox found.
    if (argc > 1 && same(argv[1], "keptsock", 9)) {
        struct {
            u16 family;
            char path[32];
        } sa = {AF_UNIX, "/tmp/keptsock.sock"};
        u64 salen = 2 + len(sa.path) + 1;
        SYS(NR_UNLINK, CWD, P("/tmp/keptsock.sock"), 0);
        i64 l = SYS(NR_SOCKET, AF_UNIX, SOCK_STREAM, 0, O_CLOEXEC);
        i64 c = SYS(NR_SOCKET, AF_UNIX, SOCK_STREAM, 0, 0);
        i32 pair[2];
        if (l < 0 || SYS(NR_BIND, l, &sa, salen) != 0 || SYS(NR_LISTEN, l, 4) != 0 ||
            SYS(NR_CONNECT, c, &sa, salen) != 0 || SYS(NR_SOCKETPAIR, AF_UNIX, SOCK_STREAM, 0, 0, pair) != 0 ||
            SYS(NR_DUP, c, 20, 0) != 20 || SYS(NR_DUP, pair[0], 21, 0) != 21) {
            put("keptsock setup failed\n");
            SYS(NR_EXIT, 1);
        }
        static const char bb[] = "/bin/busybox";
        static const char script[] =
            "(: >&20) 2>/dev/null && echo -n conn-open || echo -n conn-closed; "
            "(: >&21) 2>/dev/null && echo ' pair-open' || echo ' pair-closed'";
        struct str bargv[4] = {{(u64)bb, len(bb)}, {(u64) "sh", 2}, {(u64) "-c", 2}, {(u64)script, len(script)}};
        struct exec_args bea = {(u64)(bargv + 1), 3, 0, 0};
        SYS(NR_EXEC, CWD, P(bb), &bea, 0);
        put("keptsock exec failed\n");
        SYS(NR_EXIT, 1);
    }
    // "wxrules": the rest of the Slate domain's W^X (ADR 0093): a mapping
    // once writable never becomes executable ("flip"), anonymous memory is
    // never executable ("anonx"), and a file mapped executable beside a
    // writable mapping of it (a JIT's dual mapping) needs the JIT
    // permission.
    if (argc > 1 && same(argv[1], "wxrules", 8)) {
        i64 m = SYS(NR_MAP, 0, 4096, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        put(m > 0 && SYS(NR_PROTECT, m, 4096, 5) == 0 ? "flip-allowed " : "flip-refused ");
        put(SYS(NR_MAP, 0, 4096, 5, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) > 0 ? "anonx-allowed " : "anonx-refused ");
        SYS(NR_UNLINK, CWD, P("/tmp/jit-code"), 0);
        i64 fd = SYS(NR_OPEN, CWD, P("/tmp/jit-code"), O_READ_WRITE | O_CREATE | O_EXCL, 0600);
        int jit = 0;
        if (fd >= 0 && SYS(NR_TRUNCATE, fd, 4096) == 0) {
            i64 w = SYS(NR_MAP, 0, 4096, 3, MAP_SHARED, fd, 0);
            i64 x = SYS(NR_MAP, 0, 4096, 5, MAP_SHARED, fd, 0);
            if (w > 0 && x > 0) {
                // mov eax, 42; ret
                static const unsigned char code[] = {0xb8, 42, 0, 0, 0, 0xc3};
                for (u64 i = 0; i < sizeof code; i++)
                    ((volatile unsigned char *)w)[i] = code[i];
                jit = ((int (*)(void))x)() == 42;
            }
        }
        SYS(NR_UNLINK, CWD, P("/tmp/jit-code"), 0);
        put(jit ? "jit-works\n" : "jit-refused\n");
        SYS(NR_EXIT, 0);
    }
    char **envp = argv + argc + 1;
    u64 envc = 0;
    while (envp[envc])
        envc++;
    u64 *p = (u64 *)(envp + envc);
    u64 version = 0;
    for (p++; p[0]; p += 2)
        if (p[0] == AT_SLATE_ABI)
            version = p[1];
    check("auxv_version", version == 1);
    check("getpid", SYS(NR_GETPID) > 0);

    // Paths are (pointer, length): the bytes after the length don't count.
    static const char path[] = "/etc/passwd-and-more";
    i64 fd = SYS(NR_OPEN, CWD, path, 11, O_CLOEXEC, 0);
    check("open_counted_path", fd >= 0);
    char buf[5];
    check("read", SYS(NR_READ, fd, buf, 5) == 5 && starts_with(buf, "root:"));
    check("close", SYS(NR_CLOSE, fd) == 0);
    check("open_whole_path", SYS(NR_OPEN, CWD, P(path), 0, 0) == -ENOENT);
    check("open_bad_flags", SYS(NR_OPEN, CWD, path, 11, 1u << 30, 0) == -EINVAL);
    check("open_nul_in_path", SYS(NR_OPEN, CWD, "/etc\0passwd", 11, 0, 0) == -EINVAL);
    // Numbers outside the table fail, whatever they mean to Linux.
    check("unknown_call", SYS(250) == -ENOSYS);

    files();
    processes(envp, envc);
    memory_and_time();
    sockets();
    threads();
    SYS(NR_EXIT, failures);
    for (;;)
        ;
}
