// SPDX-License-Identifier: MIT OR Apache-2.0
// What real programs needed in M12 (OpenSSH, git, GCC, make, cargo/rustc):
// paths in a chroot, CPU time accounting, generic fd ioctls, alternate
// signal stacks and fault siginfo, listing a directory while deleting from
// it, pty ownership, named pipes, pselect/ppoll signal masks, per-thread
// names, and file mappings faulted in by several threads at once.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::compat::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

static int wait_exit(pid_t pid) {
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

static long long now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}

static volatile unsigned long spins;

static void spin(long long ns) {
    long long end = now_ns() + ns;
    while (now_ns() < end) spins++;
}

static long tv_ms(struct timeval tv) { return tv.tv_sec * 1000 + tv.tv_usec / 1000; }

// --- chroot: getcwd, /proc links and /proc/mounts follow the new root ---

static void chroot_paths(void) {
    char exe[256] = {0};
    readlink("/proc/self/exe", exe, sizeof exe - 1);
    check("proc_exe_absolute", exe[0] == '/' && strstr(exe, "compat") != NULL);

    mkdir("/tmp/cr", 0755);
    mkdir("/tmp/cr/sub", 0755);
    mkdir("/tmp/cr/proc", 0755);
    pid_t c = fork();
    if (c == 0) {
        int procfd = open("/proc/self", O_RDONLY | O_DIRECTORY);
        if (mount("proc", "/tmp/cr/proc", "proc", 0, 0) || chroot("/tmp/cr") || chdir("/sub")) _exit(1);
        char cwd[64] = {0}, link[64] = {0};
        if (!getcwd(cwd, sizeof cwd) || strcmp(cwd, "/sub")) _exit(2);
        if (readlinkat(procfd, "cwd", link, sizeof link - 1) < 0 || strcmp(link, "/sub")) _exit(3);
        memset(link, 0, sizeof link);
        if (readlinkat(procfd, "root", link, sizeof link - 1) < 0 || strcmp(link, "/")) _exit(4);
        // Only mounts inside the chroot, named from its root.
        FILE *m = fopen("/proc/mounts", "r");
        if (!m) _exit(5);
        char line[256];
        int proc_seen = 0;
        while (fgets(line, sizeof line, m)) {
            if (strstr(line, "/tmp/cr")) _exit(6);
            if (strstr(line, " /proc proc")) proc_seen = 1;
        }
        _exit(proc_seen ? 0 : 7);
    }
    int r = wait_exit(c);
    umount("/tmp/cr/proc");
    check("chroot_getcwd_proc_mounts", r == 0);
    if (r) printf("  chroot child exited %d\n", r);
}

// --- CPU time: getrusage, times, wait4's rusage ---

static void cpu_time(void) {
    spin(300000000LL);
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    long self_ms = tv_ms(ru.ru_utime) + tv_ms(ru.ru_stime);
    check("getrusage_self", self_ms >= 150);
    getrusage(RUSAGE_THREAD, &ru);
    check("getrusage_thread", tv_ms(ru.ru_utime) + tv_ms(ru.ru_stime) >= 150);
    struct tms t;
    times(&t);
    check("times", t.tms_utime + t.tms_stime >= 15);

    pid_t c = fork();
    if (c == 0) {
        spin(300000000LL);
        _exit(0);
    }
    int st;
    struct rusage cru;
    pid_t w = wait4(c, &st, 0, &cru);
    check("wait4_rusage", w == c && tv_ms(cru.ru_utime) + tv_ms(cru.ru_stime) >= 150);
    getrusage(RUSAGE_CHILDREN, &ru);
    check("getrusage_children", tv_ms(ru.ru_utime) + tv_ms(ru.ru_stime) >= 150);
}

// --- FIONBIO, FIOCLEX and FIONCLEX work on any descriptor ---

static void fd_ioctls(void) {
    int p[2];
    pipe(p);
    int on = 1;
    char b;
    int ok = ioctl(p[0], FIONBIO, &on) == 0 && (fcntl(p[0], F_GETFL) & O_NONBLOCK) && read(p[0], &b, 1) < 0 &&
             errno == EAGAIN;
    on = 0;
    ok = ok && ioctl(p[0], FIONBIO, &on) == 0 && !(fcntl(p[0], F_GETFL) & O_NONBLOCK);
    check("fionbio_pipe", ok);
    ok = ioctl(p[1], FIOCLEX) == 0 && (fcntl(p[1], F_GETFD) & FD_CLOEXEC);
    ok = ok && ioctl(p[1], FIONCLEX) == 0 && !(fcntl(p[1], F_GETFD) & FD_CLOEXEC);
    check("fioclex", ok);
    close(p[0]);
    close(p[1]);
}

// --- sigaltstack and SA_ONSTACK ---

static char altstack[64 * 1024];
static volatile uintptr_t handler_sp;
static volatile int handler_onstack;

static void on_usr1(int s) {
    (void)s;
    int local;
    handler_sp = (uintptr_t)&local;
    stack_t cur;
    sigaltstack(NULL, &cur);
    handler_onstack = (cur.ss_flags & SS_ONSTACK) != 0;
}

static void alt_stack(void) {
    stack_t ss = {.ss_sp = altstack, .ss_size = sizeof altstack, .ss_flags = 0};
    int ok = sigaltstack(&ss, NULL) == 0;
    struct sigaction sa = {0};
    sa.sa_handler = on_usr1;
    sa.sa_flags = SA_ONSTACK;
    sigaction(SIGUSR1, &sa, NULL);
    raise(SIGUSR1);
    uintptr_t lo = (uintptr_t)altstack, hi = lo + sizeof altstack;
    ok = ok && handler_sp > lo && handler_sp < hi && handler_onstack;
    stack_t cur;
    sigaltstack(NULL, &cur);
    ok = ok && !(cur.ss_flags & SS_ONSTACK) && cur.ss_sp == altstack && cur.ss_size == sizeof altstack;
    stack_t tiny = {.ss_sp = altstack, .ss_size = 100, .ss_flags = 0};
    ok = ok && sigaltstack(&tiny, NULL) < 0 && errno == ENOMEM;
    check("sigaltstack_onstack", ok);
    signal(SIGUSR1, SIG_DFL);
}

// A stack overflow is caught on the alternate stack (what Rust's runtime
// does to report "thread has overflowed its stack").
static void on_overflow(int s) {
    (void)s;
    _exit(42);
}

static volatile int depth_limit = 1 << 30;

static int recurse(int n) {
    volatile char pad[4096];
    pad[0] = (char)n;
    return n < depth_limit ? recurse(n + 1) + pad[0] : 0;
}

static void stack_overflow(void) {
    pid_t c = fork();
    if (c == 0) {
        stack_t ss = {.ss_sp = altstack, .ss_size = sizeof altstack, .ss_flags = 0};
        sigaltstack(&ss, NULL);
        struct sigaction sa = {0};
        sa.sa_handler = on_overflow;
        sa.sa_flags = SA_ONSTACK;
        sigaction(SIGSEGV, &sa, NULL);
        recurse(0);
        _exit(1);
    }
    check("stack_overflow_on_altstack", wait_exit(c) == 42);
}

// SIGSEGV's siginfo names the faulting address and why.
static sigjmp_buf fault_jmp;
static volatile uintptr_t fault_addr;
static volatile int fault_code;

static void on_segv(int s, siginfo_t *si, void *uc) {
    (void)s;
    (void)uc;
    fault_addr = (uintptr_t)si->si_addr;
    fault_code = si->si_code;
    siglongjmp(fault_jmp, 1);
}

static void fault_siginfo(void) {
    struct sigaction sa = {0}, old;
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, &old);
    if (!sigsetjmp(fault_jmp, 1)) *(volatile int *)0x1234 = 1;
    volatile int mapped = fault_addr == 0x1234 && fault_code == SEGV_MAPERR;
    char *ro = mmap(0, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!sigsetjmp(fault_jmp, 1)) ro[8] = 1;
    int ok = mapped && fault_addr == (uintptr_t)(ro + 8) && fault_code == SEGV_ACCERR;
    sigaction(SIGSEGV, &old, NULL);
    munmap(ro, 4096);
    check("segv_siginfo_addr", ok);
}

// --- readdir while unlinking (what rm -r does) ---

static void readdir_unlink(const char *dir) {
    char path[512];
    mkdir(dir, 0755);
    for (int i = 0; i < 300; i++) {
        snprintf(path, sizeof path, "%s/f%d", dir, i);
        close(open(path, O_CREAT | O_WRONLY, 0644));
    }
    DIR *d = opendir(dir);
    struct dirent *e;
    int removed = 0;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        if (unlink(path) == 0) removed++;
    }
    closedir(d);
    check("readdir_while_unlinking", removed == 300 && rmdir(dir) == 0);
}

// --- pty: grantpt changes the slave's owner and mode ---

static void pty_attrs(void) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    int ok = m >= 0 && grantpt(m) == 0 && unlockpt(m) == 0;
    char *name = ok ? ptsname(m) : NULL;
    struct stat st;
    ok = ok && name && stat(name, &st) == 0 && st.st_uid == getuid();
    ok = ok && chmod(name, 0600) == 0 && stat(name, &st) == 0 && (st.st_mode & 0777) == 0600;
    ok = ok && chown(name, 0, 5) == 0 && stat(name, &st) == 0 && st.st_gid == 5;
    check("pty_chown_chmod", ok);
    if (m >= 0) close(m);
}

// --- named pipes (fifo(7)) ---

static void fifos(void) {
    const char *p = "/tmp/compat-fifo";
    unlink(p);
    int ok = mkfifo(p, 0600) == 0;
    errno = 0;
    ok = ok && open(p, O_WRONLY | O_NONBLOCK) < 0 && errno == ENXIO;
    int r = open(p, O_RDONLY | O_NONBLOCK);
    int w = open(p, O_WRONLY | O_NONBLOCK);
    char b = 0;
    ok = ok && r >= 0 && w >= 0 && write(w, "x", 1) == 1 && read(r, &b, 1) == 1 && b == 'x';
    struct stat st;
    ok = ok && fstat(r, &st) == 0 && S_ISFIFO(st.st_mode);
    close(r);
    close(w);
    int rw = open(p, O_RDWR);
    ok = ok && rw >= 0 && write(rw, "y", 1) == 1 && read(rw, &b, 1) == 1 && b == 'y';
    close(rw);
    check("fifo_nonblocking", ok);

    // Blocking opens meet: the reader waits for the writer.
    pid_t c = fork();
    if (c == 0) {
        int fd = open(p, O_RDONLY);
        char buf[8] = {0};
        _exit(fd >= 0 && read(fd, buf, sizeof buf) == 5 && !strcmp(buf, "hello") ? 0 : 1);
    }
    usleep(100000);
    w = open(p, O_WRONLY);
    ok = w >= 0 && write(w, "hello", 5) == 5;
    close(w);
    check("fifo_blocking_rendezvous", ok && wait_exit(c) == 0);
    unlink(p);
}

// --- pselect/ppoll: the mask applies while waiting (GNU make) ---

static volatile sig_atomic_t chld;
static void on_chld(int s) {
    (void)s;
    chld++;
}

static void wait_masks(void) {
    struct sigaction sa = {0};
    sa.sa_handler = on_chld;
    sigaction(SIGCHLD, &sa, NULL);
    sigset_t block, empty;
    sigemptyset(&block);
    sigaddset(&block, SIGCHLD);
    sigemptyset(&empty);
    sigprocmask(SIG_BLOCK, &block, NULL);

    chld = 0;
    pid_t c = fork();
    if (c == 0) _exit(0);
    usleep(50000);
    int p[2];
    pipe(p);
    fd_set rd;
    FD_ZERO(&rd);
    FD_SET(p[0], &rd);
    struct timespec ts = {5, 0};
    long long t0 = now_ns();
    int r = pselect(p[0] + 1, &rd, NULL, NULL, &ts, &empty);
    int ok = r < 0 && errno == EINTR && chld == 1 && now_ns() - t0 < 2000000000LL;
    waitpid(c, NULL, 0);
    check("pselect_sigmask", ok);

    chld = 0;
    c = fork();
    if (c == 0) _exit(0);
    usleep(50000);
    struct pollfd pf = {.fd = p[0], .events = POLLIN};
    t0 = now_ns();
    r = ppoll(&pf, 1, &ts, &empty);
    ok = r < 0 && errno == EINTR && chld == 1 && now_ns() - t0 < 2000000000LL;
    waitpid(c, NULL, 0);
    check("ppoll_sigmask", ok);

    sigset_t now;
    sigprocmask(SIG_SETMASK, NULL, &now);
    check("wait_mask_restored", sigismember(&now, SIGCHLD));
    sigprocmask(SIG_UNBLOCK, &block, NULL);
    signal(SIGCHLD, SIG_DFL);
    close(p[0]);
    close(p[1]);
}

// --- thread names are per thread ---

static void *namer(void *arg) {
    (void)arg;
    prctl(PR_SET_NAME, "worker-thread");
    char got[16] = {0};
    prctl(PR_GET_NAME, got);
    return (void *)(intptr_t)(strcmp(got, "worker-thread") == 0);
}

static void thread_names(void) {
    pthread_t t;
    void *ok = 0;
    pthread_create(&t, NULL, namer, NULL);
    pthread_join(t, &ok);
    char comm[32] = {0};
    int fd = open("/proc/self/comm", O_RDONLY);
    read(fd, comm, sizeof comm - 1);
    close(fd);
    check("thread_name_per_thread", ok && strcmp(comm, "compat\n") == 0);
}

// --- a file mapping faulted in by several threads matches read() ---

static const char *map_path;
static unsigned char *map_base;
static size_t map_size;

static void *map_reader(void *arg) {
    long id = (long)arg;
    int fd = open(map_path, O_RDONLY);
    unsigned char buf[4096];
    size_t pages = (map_size + 4095) / 4096;
    long bad = 0;
    for (size_t k = 0; k < pages; k++) {
        size_t pg = (k * 7 + (size_t)id * 13) % pages, off = pg * 4096;
        size_t n = map_size - off < 4096 ? map_size - off : 4096;
        if (pread(fd, buf, n, off) != (ssize_t)n || memcmp(buf, map_base + off, n)) bad++;
    }
    close(fd);
    return (void *)bad;
}

static void threaded_file_faults(const char *self) {
    map_path = self;
    int fd = open(self, O_RDONLY);
    struct stat st;
    fstat(fd, &st);
    map_size = st.st_size;
    map_base = mmap(0, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    pthread_t t[8];
    for (long i = 0; i < 8; i++) pthread_create(&t[i], NULL, map_reader, (void *)i);
    long bad = 0;
    for (int i = 0; i < 8; i++) {
        void *r;
        pthread_join(t[i], &r);
        bad += (long)r;
    }
    munmap(map_base, map_size);
    check("threaded_file_mapping_faults", map_base != MAP_FAILED && bad == 0);
}

// --- MADV_DONTNEED: private pages read back as zeros or the file's data ---

static void madv_dontneed(void) {
    char *anon = mmap(0, 3 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(anon, 0xAA, 3 * 4096);
    int ok = madvise(anon + 4096, 2 * 4096, MADV_DONTNEED) == 0;
    ok = ok && anon[0] == (char)0xAA && anon[4096] == 0 && anon[3 * 4096 - 1] == 0;
    munmap(anon, 3 * 4096);
    int fd = open("/proc/self/exe", O_RDONLY);
    unsigned char *file = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);
    unsigned char first = file[1];
    file[1] = (unsigned char)~first;
    ok = ok && madvise(file, 4096, MADV_DONTNEED) == 0 && file[1] == first && file[0] == 0x7f;
    munmap(file, 4096);
    errno = 0;
    ok = ok && madvise((void *)0x10000, 4096, MADV_DONTNEED) < 0 && errno == ENOMEM;
    check("madvise_dontneed", ok);
}

int main(void) {
    chroot_paths();
    cpu_time();
    fd_ioctls();
    alt_stack();
    stack_overflow();
    fault_siginfo();
    readdir_unlink("/tmp/compat-dir");
    pty_attrs();
    fifos();
    wait_masks();
    thread_names();
    threaded_file_faults("/proc/self/exe");
    madv_dontneed();
    return failures;
}
