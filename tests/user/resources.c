// SPDX-License-Identifier: MIT OR Apache-2.0
// Resource control (M19 phase 5, ADR 0045): resource limits, nice values
// and real-time policies (with sched_setattr, RLIMIT_RTTIME and real-time
// threads moving to a CPU where they run at once: ADR 0184), CPU time
// measured by the clock, the load
// average, priority-inheritance and robust futexes, FUTEX_WAKE_OP, and the
// cgroup memory.max (with the out-of-memory killer) and cpu.max limits.
// Runs as root on Slate; never run it on the host (it makes cgroups).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* futex(2) operations and FUTEX_OP's encoding (futex(2); values from
 * musl's internal futex.h). */
#define FUTEX_WAIT_PRIVATE (0 | 128)
#define FUTEX_WAKE_OP_PRIVATE (5 | 128)
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_OP_SET 0
#define FUTEX_OP_ADD 1
#define FUTEX_OP_OPARG_SHIFT 8
#define FUTEX_OP_CMP_EQ 0
#define FUTEX_OP_CMP_GT 4
#define FUTEX_OP(op, oparg, cmp, cmparg) \
    ((((op) & 0xf) << 28) | (((cmp) & 0xf) << 24) | (((oparg) & 0xfff) << 12) | ((cmparg) & 0xfff))

/* musl leaves the process-wide sched_* calls unimplemented (ENOSYS):
 * make them directly. */
static int set_sched(int policy, int prio) {
    struct sched_param sp = {.sched_priority = prio};
    return syscall(SYS_sched_setscheduler, 0, policy, &sp);
}
static int get_sched(void) {
    return syscall(SYS_sched_getscheduler, 0);
}
static int get_param(void) {
    struct sched_param sp = {.sched_priority = -1};
    return syscall(SYS_sched_getparam, 0, &sp) == 0 ? sp.sched_priority : -1;
}

static int failures;
static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::resources::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

/* Run `f` in a child; returns its wait status. */
static int in_child(int (*f)(void)) {
    pid_t pid = fork();
    if (pid == 0) _exit(f());
    int status = -1;
    waitpid(pid, &status, 0);
    return status;
}

#define CHILD_CHECK(name, cond)                                                                 \
    do {                                                                                        \
        if (!(cond)) {                                                                          \
            printf("child check %s failed (errno %d)\n", name, errno);                          \
            fflush(stdout);                                                                     \
            return 1;                                                                           \
        }                                                                                       \
    } while (0)

static long long now_ns(clockid_t c) {
    struct timespec t;
    clock_gettime(c, &t);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}

static void spin_ms(int ms) {
    long long until = now_ns(CLOCK_MONOTONIC) + ms * 1000000LL;
    while (now_ns(CLOCK_MONOTONIC) < until) {
    }
}

static int put(const char *path, const char *text) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    int r = write(fd, text, strlen(text)) == (ssize_t)strlen(text) ? 0 : -1;
    close(fd);
    return r;
}

static int get(const char *path, char *buf, size_t len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, len - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n] = 0;
    return 0;
}

/* The value after `key ` in a "key value" file. */
static long long field(const char *text, const char *key) {
    const char *p = strstr(text, key);
    return p ? atoll(p + strlen(key) + 1) : -1;
}

static int become_user(void) {
    return setgid(1000) == 0 && setuid(1000) == 0;
}

/* --- resource limits ------------------------------------------------------- */

static int nofile_child(void) {
    struct rlimit r = {16, 4096};
    CHILD_CHECK("set", setrlimit(RLIMIT_NOFILE, &r) == 0);
    int last = -1, fd;
    while ((fd = open("/dev/null", O_RDONLY)) >= 0) last = fd;
    CHILD_CHECK("emfile", errno == EMFILE && last == 15);
    CHILD_CHECK("dup2_past", dup2(0, 16) < 0 && errno == EBADF);
    CHILD_CHECK("fcntl_dupfd_past", fcntl(0, F_DUPFD, 20) < 0 && errno == EINVAL);
    r.rlim_cur = 64;
    CHILD_CHECK("raise_soft", setrlimit(RLIMIT_NOFILE, &r) == 0 && open("/dev/null", O_RDONLY) == 16);
    CHILD_CHECK("drop_root", become_user());
    r.rlim_max = 8192;
    CHILD_CHECK("raise_hard_denied", setrlimit(RLIMIT_NOFILE, &r) < 0 && errno == EPERM);
    r.rlim_max = 2048;
    CHILD_CHECK("lower_hard", setrlimit(RLIMIT_NOFILE, &r) == 0);
    r.rlim_max = 4096;
    CHILD_CHECK("cannot_raise_again", setrlimit(RLIMIT_NOFILE, &r) < 0 && errno == EPERM);
    r.rlim_cur = 4096;
    r.rlim_max = 2048;
    CHILD_CHECK("soft_above_hard", setrlimit(RLIMIT_NOFILE, &r) < 0 && errno == EINVAL);
    return 0;
}

static int fsize_child(void) {
    signal(SIGXFSZ, SIG_IGN);
    struct rlimit r = {4096, RLIM_INFINITY};
    CHILD_CHECK("set", setrlimit(RLIMIT_FSIZE, &r) == 0);
    int fd = open("/tmp/fsize-test", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    CHILD_CHECK("open", fd >= 0);
    static char buf[8192];
    CHILD_CHECK("short_write", write(fd, buf, sizeof buf) == 4096);
    CHILD_CHECK("efbig", write(fd, buf, 1) < 0 && errno == EFBIG);
    CHILD_CHECK("truncate_efbig", ftruncate(fd, 10000) < 0 && errno == EFBIG);
    CHILD_CHECK("truncate_within", ftruncate(fd, 100) == 0);
    close(fd);
    unlink("/tmp/fsize-test");
    return 0;
}

static int fsize_signal_child(void) {
    struct rlimit r = {100, RLIM_INFINITY};
    setrlimit(RLIMIT_FSIZE, &r);
    int fd = open("/tmp/fsize-test2", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    static char buf[200];
    write(fd, buf, 100);
    write(fd, buf, 100); /* SIGXFSZ, by default fatal */
    return 0;
}

static int as_child(void) {
    struct rlimit r;
    getrlimit(RLIMIT_AS, &r);
    CHILD_CHECK("unlimited", r.rlim_cur == RLIM_INFINITY);
    /* Room for 16 MiB more than this process maps now. */
    char maps[64];
    snprintf(maps, sizeof maps, "/proc/%d/statm", getpid());
    char buf[128];
    CHILD_CHECK("statm", get(maps, buf, sizeof buf) == 0);
    long long pages = atoll(buf);
    r.rlim_cur = r.rlim_max = (pages + 4096) * 4096;
    CHILD_CHECK("set", setrlimit(RLIMIT_AS, &r) == 0);
    void *big = mmap(NULL, 64 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHILD_CHECK("big_refused", big == MAP_FAILED && errno == ENOMEM);
    void *small = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHILD_CHECK("small_fits", small != MAP_FAILED);
    return 0;
}

static int data_child(void) {
    struct rlimit r = {1 << 20, RLIM_INFINITY};
    long brk0 = syscall(SYS_brk, 0);
    CHILD_CHECK("set", setrlimit(RLIMIT_DATA, &r) == 0);
    long grown = syscall(SYS_brk, brk0 + (4 << 20));
    CHILD_CHECK("brk_refused", grown == brk0);
    grown = syscall(SYS_brk, brk0 + (64 << 10));
    CHILD_CHECK("brk_small", grown == brk0 + (64 << 10));
    return 0;
}

static int nproc_child(void) {
    struct rlimit r = {3, 3};
    CHILD_CHECK("set", setrlimit(RLIMIT_NPROC, &r) == 0);
    CHILD_CHECK("drop_root", become_user());
    pid_t kids[8];
    int made = 0;
    for (int i = 0; i < 8; i++) {
        pid_t p = fork();
        if (p == 0) {
            pause();
            _exit(0);
        }
        if (p < 0) {
            CHILD_CHECK("eagain", errno == EAGAIN);
            break;
        }
        kids[made++] = p;
    }
    for (int i = 0; i < made; i++) {
        kill(kids[i], SIGKILL);
        waitpid(kids[i], NULL, 0);
    }
    /* This process and two children make the three. */
    CHILD_CHECK("two_forks", made == 2);
    return 0;
}

static volatile int xcpu_seen;
static void on_xcpu(int s) {
    (void)s;
    xcpu_seen++;
}

static int cpu_child(void) {
    signal(SIGXCPU, on_xcpu);
    struct rlimit r = {1, 2};
    setrlimit(RLIMIT_CPU, &r);
    /* Spin until SIGKILL at two seconds of CPU time; report what came. */
    for (;;) {
        if (xcpu_seen) {
            /* Leave a mark the parent can see: SIGXCPU arrived. */
            int fd = open("/tmp/xcpu-seen", O_WRONLY | O_CREAT, 0644);
            close(fd);
            xcpu_seen = 0;
        }
    }
    return 0;
}

static int stack_child(void) {
    struct rlimit r = {256 << 10, RLIM_INFINITY};
    setrlimit(RLIMIT_STACK, &r);
    char *argv[] = {"resources", "stack", NULL};
    execv("/proc/self/exe", argv);
    return 1;
}

/* exec under a large and an unlimited RLIMIT_STACK (GCC raises its soft
 * limit to 64 MiB before running cc1): the bigger stack reservation must
 * not collide with the vDSO. */
static int big_stack_child(void) {
    struct rlimit r = {64 << 20, RLIM_INFINITY};
    setrlimit(RLIMIT_STACK, &r);
    pid_t c = fork();
    if (c == 0) {
        char *argv[] = {"resources", "noop", NULL};
        execv("/proc/self/exe", argv);
        _exit(100 + errno);
    }
    int st;
    waitpid(c, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return 1;
    r.rlim_cur = RLIM_INFINITY;
    setrlimit(RLIMIT_STACK, &r);
    char *argv[] = {"resources", "noop", NULL};
    execv("/proc/self/exe", argv);
    return 2;
}

static int deep(int n) {
    volatile char pad[16 << 10];
    pad[0] = (char)n;
    return n == 0 ? pad[0] : deep(n - 1) + pad[0];
}

static void limits(void) {
    struct rlimit r;
    check("nofile_default", getrlimit(RLIMIT_NOFILE, &r) == 0 && r.rlim_cur == 1024 && r.rlim_max == 4096);
    check("core_default", getrlimit(RLIMIT_CORE, &r) == 0 && r.rlim_cur == 0);
    check("stack_default", getrlimit(RLIMIT_STACK, &r) == 0 && r.rlim_cur == 8 << 20);
    check("nofile_enforced", in_child(nofile_child) == 0);
    check("fsize_enforced", in_child(fsize_child) == 0);
    int s = in_child(fsize_signal_child);
    check("fsize_signal", WIFSIGNALED(s) && WTERMSIG(s) == SIGXFSZ);
    unlink("/tmp/fsize-test2");
    check("as_enforced", in_child(as_child) == 0);
    check("data_enforced", in_child(data_child) == 0);
    check("nproc_enforced", in_child(nproc_child) == 0);

    unlink("/tmp/xcpu-seen");
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    s = in_child(cpu_child);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    struct stat st;
    check("cpu_kill_at_hard", WIFSIGNALED(s) && WTERMSIG(s) == SIGKILL);
    check("cpu_xcpu_at_soft", stat("/tmp/xcpu-seen", &st) == 0);
    check("cpu_took_two_seconds", t1.tv_sec - t0.tv_sec >= 1 && t1.tv_sec - t0.tv_sec <= 6);
    unlink("/tmp/xcpu-seen");

    s = in_child(stack_child);
    check("stack_limit_at_exec", WIFSIGNALED(s) && WTERMSIG(s) == SIGSEGV);
    check("big_stack_exec", in_child(big_stack_child) == 0);

    /* prlimit on another process, and /proc/<pid>/limits. */
    pid_t kid = fork();
    if (kid == 0) {
        pause();
        _exit(0);
    }
    struct rlimit nr = {77, 4096}, old;
    check("prlimit_other", prlimit(kid, RLIMIT_NOFILE, &nr, &old) == 0 && old.rlim_cur == 1024);
    char path[64], buf[4096];
    snprintf(path, sizeof path, "/proc/%d/limits", kid);
    check("proc_limits", get(path, buf, sizeof buf) == 0 && strstr(buf, "Max open files            77                   4096                 files") != NULL);
    check("proc_limits_header", strncmp(buf, "Limit                     Soft Limit           Hard Limit           Units", 73) == 0);
    kill(kid, SIGKILL);
    waitpid(kid, NULL, 0);
    check("bad_resource", getrlimit(99, &r) < 0 && errno == EINVAL);
}

/* --- priorities ------------------------------------------------------------- */

/* Field `n` (1-based) of /proc/self/stat. */
static long long stat_field(int n) {
    char buf[1024];
    if (get("/proc/self/stat", buf, sizeof buf) != 0) return -9999;
    char *p = strrchr(buf, ')');
    if (!p) return -9999;
    p += 2; /* field 3 */
    for (int i = 3; i < n; i++) {
        p = strchr(p, ' ');
        if (!p) return -9999;
        p++;
    }
    return atoll(p);
}

static int nice_child(void) {
    CHILD_CHECK("setpriority", setpriority(PRIO_PROCESS, 0, 5) == 0);
    errno = 0;
    CHILD_CHECK("getpriority", getpriority(PRIO_PROCESS, 0) == 5 && errno == 0);
    CHILD_CHECK("stat_nice", stat_field(19) == 5 && stat_field(18) == 25);
    CHILD_CHECK("nice_call", nice(2) == 7);
    CHILD_CHECK("drop_root", become_user());
    CHILD_CHECK("raise_denied", setpriority(PRIO_PROCESS, 0, 0) < 0 && errno == EACCES);
    CHILD_CHECK("lower_allowed", setpriority(PRIO_PROCESS, 0, 10) == 0);
    struct rlimit r = {20 - 8, 20 - 8};
    /* RLIMIT_NICE can't be raised without the privilege either. */
    CHILD_CHECK("rlimit_nice_denied", setrlimit(RLIMIT_NICE, &r) < 0 && errno == EPERM);
    CHILD_CHECK("fifo_denied", set_sched(SCHED_FIFO, 10) < 0 && errno == EPERM);
    return 0;
}

static int nice_rlimit_child(void) {
    struct rlimit r = {20 - 2, 20 - 2}; /* may go down to nice 2 */
    CHILD_CHECK("set", setrlimit(RLIMIT_NICE, &r) == 0);
    CHILD_CHECK("start_high", setpriority(PRIO_PROCESS, 0, 10) == 0);
    CHILD_CHECK("drop_root", become_user());
    CHILD_CHECK("within_rlimit", setpriority(PRIO_PROCESS, 0, 2) == 0);
    CHILD_CHECK("past_rlimit", setpriority(PRIO_PROCESS, 0, 1) < 0 && errno == EACCES);
    return 0;
}

static int policy_child(void) {
    CHILD_CHECK("fifo", set_sched(SCHED_FIFO, 10) == 0);
    CHILD_CHECK("getscheduler", get_sched() == SCHED_FIFO);
    CHILD_CHECK("getparam", get_param() == 10);
    CHILD_CHECK("stat_rt", stat_field(18) == -11 && stat_field(40) == 10 && stat_field(41) == SCHED_FIFO);
    CHILD_CHECK("fifo_needs_priority", set_sched(SCHED_FIFO, 0) < 0 && errno == EINVAL);
    CHILD_CHECK("rr", set_sched(SCHED_RR, 20) == 0 && get_sched() == SCHED_RR);
    struct timespec ts;
    CHILD_CHECK("rr_interval", sched_rr_get_interval(0, &ts) == 0 && ts.tv_sec == 0 && ts.tv_nsec == 100000000);
    CHILD_CHECK("back_to_other", set_sched(SCHED_OTHER, 0) == 0 && get_sched() == SCHED_OTHER);
    CHILD_CHECK("idle", set_sched(SCHED_IDLE, 0) == 0 && get_sched() == SCHED_IDLE);
    CHILD_CHECK("reset_on_fork", set_sched(SCHED_OTHER | SCHED_RESET_ON_FORK, 0) == 0 &&
                                     get_sched() == (SCHED_OTHER | SCHED_RESET_ON_FORK));
    /* The flag is not inherited, and a child of a real-time parent with it
     * starts normal. */
    CHILD_CHECK("rr_reset", set_sched(SCHED_RR | SCHED_RESET_ON_FORK, 5) == 0);
    pid_t kid = fork();
    if (kid == 0) _exit(get_sched() == SCHED_OTHER ? 0 : 1);
    int st;
    waitpid(kid, &st, 0);
    CHILD_CHECK("reset_child_normal", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    CHILD_CHECK("inherit", set_sched(SCHED_FIFO, 7) == 0);
    kid = fork();
    if (kid == 0) _exit(get_sched() == SCHED_FIFO && get_param() == 7 ? 0 : 1);
    waitpid(kid, &st, 0);
    CHILD_CHECK("child_inherits", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    return 0;
}

/* sched_setattr(2)'s structure: the man page's layout, 56 bytes with the
 * utilization hints; flags 0x01 SCHED_FLAG_RESET_ON_FORK, 0x10
 * KEEP_PARAMS (values seen on Linux). */
struct sched_attr_ {
    uint32_t size, policy;
    uint64_t flags;
    int32_t nice;
    uint32_t priority;
    uint64_t runtime, deadline, period;
    uint32_t util_min, util_max;
    uint8_t extra[8];
};

static long setattr(struct sched_attr_ *a) {
    return syscall(SYS_sched_setattr, 0, a, 0);
}

static int attr_child(void) {
    struct sched_attr_ a;
    memset(&a, 0xff, sizeof a);
    CHILD_CHECK("getattr", syscall(SYS_sched_getattr, 0, &a, sizeof a, 0) == 0 && a.size == 56 && a.policy == 0 &&
                               a.nice == 0 && a.util_max == 1024 && a.extra[0] == 0);
    memset(&a, 0, sizeof a);
    a.size = 48;
    a.policy = SCHED_FIFO;
    a.priority = 12;
    CHILD_CHECK("set_fifo", setattr(&a) == 0 && get_sched() == SCHED_FIFO && get_param() == 12);
    memset(&a, 0, sizeof a);
    a.size = 48;
    a.policy = SCHED_OTHER;
    a.nice = 3;
    CHILD_CHECK("set_other", setattr(&a) == 0 && get_sched() == SCHED_OTHER && getpriority(PRIO_PROCESS, 0) == 3);
    memset(&a, 0, sizeof a);
    CHILD_CHECK("getattr_48",
                syscall(SYS_sched_getattr, 0, &a, 48, 0) == 0 && a.size == 48 && a.nice == 3 && a.policy == 0);
    memset(&a, 0, sizeof a);
    a.size = 48;
    a.policy = SCHED_OTHER;
    a.flags = 0x10; /* KEEP_PARAMS: nice stays 3 */
    a.nice = 9;
    CHILD_CHECK("keep_params", setattr(&a) == 0 && getpriority(PRIO_PROCESS, 0) == 3);
    memset(&a, 0, sizeof a);
    a.size = 48;
    a.flags = 0x80;
    CHILD_CHECK("bad_flag", setattr(&a) < 0 && errno == EINVAL);
    memset(&a, 0, sizeof a);
    a.size = 40;
    CHILD_CHECK("small", setattr(&a) < 0 && errno == E2BIG && a.size == 56);
    memset(&a, 0, sizeof a);
    a.size = sizeof a;
    a.extra[2] = 1;
    CHILD_CHECK("big_nonzero", setattr(&a) < 0 && errno == E2BIG && a.size == 56);
    memset(&a, 0, sizeof a);
    a.size = 48;
    a.policy = 6; /* SCHED_DEADLINE: not offered */
    CHILD_CHECK("deadline", setattr(&a) < 0 && errno == EINVAL);
    memset(&a, 0, sizeof a);
    a.size = 48;
    a.policy = SCHED_RR;
    a.flags = 0x01;
    a.priority = 4;
    CHILD_CHECK("reset_flag", setattr(&a) == 0 && get_sched() == (SCHED_RR | SCHED_RESET_ON_FORK));
    memset(&a, 0, sizeof a);
    CHILD_CHECK("getattr_flags", syscall(SYS_sched_getattr, 0, &a, 56, 0) == 0 && a.flags == 1 && a.priority == 4);
    CHILD_CHECK("getattr_small", syscall(SYS_sched_getattr, 0, &a, 40, 0) < 0 && errno == EINVAL);
    return 0;
}

static volatile int rt_xcpus;
static void on_rt_xcpu(int sig) {
    (void)sig;
    rt_xcpus++;
}

/* Spin for `ms` of wall time without a system call (the clock is the
 * vDSO's), so the thread never blocks. */
static void spin_quiet(int ms) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    long long until = t.tv_sec * 1000000000LL + t.tv_nsec + ms * 1000000LL;
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &t);
        if (t.tv_sec * 1000000000LL + t.tv_nsec >= until) break;
    }
}

/* RLIMIT_RTTIME (getrlimit(2)): a real-time thread that runs past the soft
 * limit without blocking gets SIGXCPU, once until a second more passes. */
static int rttime_soft_child(void) {
    struct rlimit r = {50000, 5000000}; /* 50 ms, 5 s (microseconds) */
    CHILD_CHECK("set", setrlimit(RLIMIT_RTTIME, &r) == 0);
    signal(SIGXCPU, on_rt_xcpu);
    CHILD_CHECK("fifo", set_sched(SCHED_FIFO, 10) == 0);
    spin_quiet(300);
    int seen = rt_xcpus;
    set_sched(SCHED_OTHER, 0);
    if (seen != 1) printf("rttime: %d SIGXCPUs\n", seen);
    CHILD_CHECK("one_sigxcpu", seen == 1);
    return 0;
}

/* Past the hard limit, SIGKILL; blocking starts the count again. */
static int rttime_hard_child(void) {
    struct rlimit r = {100000, 150000}; /* 100 ms, 150 ms */
    if (setrlimit(RLIMIT_RTTIME, &r) != 0) return 2;
    signal(SIGXCPU, SIG_IGN);
    if (set_sched(SCHED_FIFO, 10) != 0) return 3;
    /* 100 ms at a time, sleeping between: never killed. */
    for (int i = 0; i < 4; i++) {
        spin_quiet(80);
        usleep(1000);
    }
    spin_quiet(1000);
    return 4; /* should have been killed */
}

/* A real-time thread whose CPU a higher one holds runs elsewhere at once
 * (ADR 0184): with every CPU busy with normal work and a FIFO 50 thread
 * spinning on CPU 0, a FIFO 40 thread that last ran there wakes from
 * 1 ms sleeps on time instead of waiting for it. */
static volatile int hog_go, hog_stop;
static void *hog(void *arg) {
    (void)arg;
    cpu_set_t one;
    CPU_ZERO(&one);
    CPU_SET(0, &one);
    sched_setaffinity(0, sizeof one, &one);
    struct sched_param sp = {.sched_priority = 50};
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);
    hog_go = 1;
    /* At most 2 s, so a thread left waiting behind it fails, not hangs. */
    long long until = now_ns(CLOCK_MONOTONIC) + 2000000000LL;
    while (!hog_stop && now_ns(CLOCK_MONOTONIC) < until) {
    }
    return 0;
}

static int rt_push_child(void) {
    int n = get_nprocs();
    if (n < 2) return 0;
    pid_t spinners[64];
    int k = n < 64 ? n : 64;
    for (int i = 0; i < k; i++) {
        spinners[i] = fork();
        if (spinners[i] == 0) {
            for (;;) {
            }
        }
    }
    /* This thread last runs on CPU 0. */
    cpu_set_t one, all;
    CPU_ZERO(&one);
    CPU_SET(0, &one);
    CPU_ZERO(&all);
    for (int i = 0; i < n && i < CPU_SETSIZE; i++) CPU_SET(i, &all);
    sched_setaffinity(0, sizeof one, &one);
    CHILD_CHECK("fifo", set_sched(SCHED_FIFO, 40) == 0);
    pthread_t h;
    pthread_create(&h, 0, hog, 0);
    while (!hog_go) usleep(1000);
    sched_setaffinity(0, sizeof all, &all);
    long long worst = 0;
    for (int i = 0; i < 50; i++) {
        long long t0 = now_ns(CLOCK_MONOTONIC);
        usleep(1000);
        long long late = now_ns(CLOCK_MONOTONIC) - t0 - 1000000;
        if (late > worst) worst = late;
    }
    hog_stop = 1;
    pthread_join(h, 0);
    set_sched(SCHED_OTHER, 0);
    for (int i = 0; i < k; i++) {
        kill(spinners[i], SIGKILL);
        waitpid(spinners[i], 0, 0);
    }
    printf("rt_push: worst wake-up %lld us late\n", worst / 1000);
    CHILD_CHECK("on_time", worst < 20000000LL);
    return 0;
}

static void priorities(void) {
    check("nice", in_child(nice_child) == 0);
    check("rlimit_nice", in_child(nice_rlimit_child) == 0);
    check("policies", in_child(policy_child) == 0);
    check("setattr", in_child(attr_child) == 0);
    check("rttime_soft", in_child(rttime_soft_child) == 0);
    int st = in_child(rttime_hard_child);
    if (!(WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL)) printf("rttime_hard: status %#x\n", st);
    check("rttime_hard", WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL);
    check("rt_push", in_child(rt_push_child) == 0);
    check("priority_range", sched_get_priority_max(SCHED_FIFO) == 99 && sched_get_priority_min(SCHED_RR) == 1);
    check("prio_user", setpriority(PRIO_USER, 4242, 1) < 0 && errno == ESRCH);
}

/* --- CPU time ---------------------------------------------------------------- */

static void cpu_time(void) {
    struct rusage a, b;
    getrusage(RUSAGE_SELF, &a);
    long long c0 = now_ns(CLOCK_PROCESS_CPUTIME_ID), t0 = now_ns(CLOCK_THREAD_CPUTIME_ID);
    long long w0 = now_ns(CLOCK_MONOTONIC);
    /* Spin in user mode until 100 ms of CPU time (a loaded machine takes
     * longer), looking at the clock (a system call) only now and then. */
    while (now_ns(CLOCK_THREAD_CPUTIME_ID) - t0 < 100000000 && now_ns(CLOCK_MONOTONIC) - w0 < 10000000000LL) {
        for (volatile int i = 0; i < 200000; i++) {
        }
    }
    long long w1 = now_ns(CLOCK_MONOTONIC);
    long long c1 = now_ns(CLOCK_PROCESS_CPUTIME_ID), t1 = now_ns(CLOCK_THREAD_CPUTIME_ID);
    usleep(100000);
    long long c2 = now_ns(CLOCK_PROCESS_CPUTIME_ID);
    getrusage(RUSAGE_SELF, &b);
    long long used = (b.ru_utime.tv_sec - a.ru_utime.tv_sec) * 1000000LL + (b.ru_utime.tv_usec - a.ru_utime.tv_usec) +
                     (b.ru_stime.tv_sec - a.ru_stime.tv_sec) * 1000000LL + (b.ru_stime.tv_usec - a.ru_stime.tv_usec);
    check("process_clock_spins", c1 - c0 >= 100000000 && c1 - c0 <= w1 - w0 + 5000000);
    check("thread_clock_spins", t1 - t0 >= 100000000 && t1 - t0 <= 130000000);
    check("sleep_is_not_cpu_time", c2 - c1 < 10000000);
    check("rusage_microseconds", used >= 95000 && used <= (w1 - w0) / 1000 + 20000 && used % 10000 != 0);
    check("utime_counts_user_mode", b.ru_utime.tv_sec * 1000000LL + b.ru_utime.tv_usec >
                                       a.ru_utime.tv_sec * 1000000LL + a.ru_utime.tv_usec + 80000);

    /* Another process's clock. */
    pid_t kid = fork();
    if (kid == 0) {
        spin_ms(60);
        pause();
        _exit(0);
    }
    usleep(150000);
    clockid_t cid;
    struct timespec ts;
    check("cpuclockid", clock_getcpuclockid(kid, &cid) == 0 && clock_gettime(cid, &ts) == 0 &&
                            ts.tv_sec * 1000000000LL + ts.tv_nsec >= 50000000);
    kill(kid, SIGKILL);
    int st;
    struct rusage ru;
    wait4(kid, &st, 0, &ru);
    check("wait4_rusage", ru.ru_utime.tv_sec * 1000000LL + ru.ru_utime.tv_usec >= 50000);
}

/* --- futexes -------------------------------------------------------------------- */

static pthread_mutex_t pi_lock;
static volatile int pi_got;

static void *pi_waiter(void *arg) {
    (void)arg;
    struct sched_param sp = {.sched_priority = 20};
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);
    pthread_mutex_lock(&pi_lock);
    pi_got = 1;
    pthread_mutex_unlock(&pi_lock);
    return NULL;
}

static void pi_futexes(void) {
    pthread_mutexattr_t a;
    pthread_mutexattr_init(&a);
    check("pi_attr", pthread_mutexattr_setprotocol(&a, PTHREAD_PRIO_INHERIT) == 0);
    pthread_mutex_init(&pi_lock, &a);
    check("pi_lock", pthread_mutex_lock(&pi_lock) == 0);
    pthread_t t;
    pthread_create(&t, NULL, pi_waiter, NULL);
    /* The waiter (SCHED_FIFO 20) blocks in FUTEX_LOCK_PI and lends its
     * priority to this thread, the owner: /proc shows it boosted. */
    int boosted = 0;
    for (int i = 0; i < 200 && !boosted; i++) {
        usleep(5000);
        boosted = stat_field(18) == -21;
    }
    check("pi_boosts_owner", boosted);
    check("pi_waiter_blocked", !pi_got);
    check("pi_trylock_busy", pthread_mutex_trylock(&pi_lock) == EBUSY || pthread_mutex_trylock(&pi_lock) == EDEADLK);
    check("pi_unlock", pthread_mutex_unlock(&pi_lock) == 0);
    pthread_join(t, NULL);
    check("pi_handed_over", pi_got);
    check("pi_boost_gone", stat_field(18) == 20);
    check("pi_unlock_not_owner", syscall(SYS_futex, &pi_lock, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0) < 0 && errno == EPERM);
    /* Raw: locking a PI futex one owns is EDEADLK, a free one is taken. */
    static uint32_t word;
    word = 0;
    check("pi_raw_take", syscall(SYS_futex, &word, FUTEX_LOCK_PI, 0, NULL, NULL, 0) == 0 &&
                             word == (uint32_t)syscall(SYS_gettid));
    check("pi_raw_deadlock", syscall(SYS_futex, &word, FUTEX_LOCK_PI, 0, NULL, NULL, 0) < 0 && errno == EDEADLK);
    check("pi_raw_unlock", syscall(SYS_futex, &word, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0) == 0 && word == 0);
}

/* A robust, process-shared mutex in shared memory. */
static pthread_mutex_t *shared_mutex(int pi) {
    pthread_mutex_t *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    pthread_mutexattr_t a;
    pthread_mutexattr_init(&a);
    pthread_mutexattr_setpshared(&a, PTHREAD_PROCESS_SHARED);
    pthread_mutexattr_setrobust(&a, PTHREAD_MUTEX_ROBUST);
    if (pi) pthread_mutexattr_setprotocol(&a, PTHREAD_PRIO_INHERIT);
    pthread_mutex_init(m, &a);
    return m;
}

static void robust_case(const char *name, int pi, int killed) {
    pthread_mutex_t *m = shared_mutex(pi);
    int pipefd[2];
    pipe(pipefd);
    pid_t kid = fork();
    if (kid == 0) {
        pthread_mutex_lock(m);
        write(pipefd[1], "x", 1);
        if (killed) pause();
        _exit(0); /* exits holding the lock */
    }
    char c;
    read(pipefd[0], &c, 1);
    if (killed) kill(kid, SIGKILL);
    waitpid(kid, NULL, 0);
    int r = pthread_mutex_lock(m);
    char full[64];
    snprintf(full, sizeof full, "robust_%s", name);
    check(full, r == EOWNERDEAD);
    if (r == EOWNERDEAD) {
        pthread_mutex_consistent(m);
        pthread_mutex_unlock(m);
    }
    snprintf(full, sizeof full, "robust_%s_relock", name);
    check(full, pthread_mutex_lock(m) == 0 && pthread_mutex_unlock(m) == 0);
    close(pipefd[0]);
    close(pipefd[1]);
    munmap(m, 4096);
}

static uint32_t wo_a, wo_b;
static volatile int wo_woken;
static void *wake_op_waiter(void *arg) {
    (void)arg;
    syscall(SYS_futex, &wo_a, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
    wo_woken = 1;
    return NULL;
}

static void futexes(void) {
    pi_futexes();
    robust_case("exit", 0, 0);
    robust_case("killed", 0, 1);
    robust_case("pi_exit", 1, 0);

    pthread_t t;
    pthread_create(&t, NULL, wake_op_waiter, NULL);
    usleep(50000);
    /* *b = 5 (old value 0); wake one on a; wake on b if old == 0. */
    int op = FUTEX_OP(FUTEX_OP_SET, 5, FUTEX_OP_CMP_EQ, 0);
    long n = syscall(SYS_futex, &wo_a, FUTEX_WAKE_OP_PRIVATE, 1, (void *)1, &wo_b, op);
    pthread_join(t, NULL);
    check("wake_op", n == 1 && wo_woken && wo_b == 5);
    op = FUTEX_OP(FUTEX_OP_ADD | FUTEX_OP_OPARG_SHIFT, 3, FUTEX_OP_CMP_GT, 100);
    n = syscall(SYS_futex, &wo_a, FUTEX_WAKE_OP_PRIVATE, 1, (void *)1, &wo_b, op);
    check("wake_op_shift", n == 0 && wo_b == 13);
}

/* --- cgroups ------------------------------------------------------------------------- */

static int memory_hog(void) {
    /* 64 MiB, touched, in a cgroup allowed 16 MiB: the killer stops it. */
    size_t len = 64 << 20;
    char *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    for (size_t i = 0; i < len; i += 4096) p[i] = 1;
    return 0;
}

static int memory_fits(void) {
    size_t len = 4 << 20;
    char *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    for (size_t i = 0; i < len; i += 4096) p[i] = 1;
    char buf[64];
    CHILD_CHECK("current", get("/sys/fs/cgroup/restest/memory.current", buf, sizeof buf) == 0 &&
                               atoll(buf) >= (4 << 20) && atoll(buf) < (16 << 20));
    return 0;
}

/* Touch `mib` MiB of private memory; 0 if all of it was touched. */
static int touch_mib(size_t mib) {
    size_t len = mib << 20;
    char *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 1;
    for (size_t i = 0; i < len; i += 4096) p[i] = 1;
    return 0;
}

static int join(const char *cg) {
    char me[16];
    snprintf(me, sizeof me, "%d", getpid());
    char path[128];
    snprintf(path, sizeof path, "/sys/fs/cgroup/%s/cgroup.procs", cg);
    return put(path, me);
}

static int memory_hog_in_cgroup(void) {
    if (join("restest") != 0) return 2;
    return memory_hog();
}

static int memory_fits_in_cgroup(void) {
    if (join("restest") != 0) return 2;
    return memory_fits();
}

static int cpu_hog_in_cgroup(void) {
    if (join("cputest") != 0) return 2;
    spin_ms(1000);
    return 0;
}

static void cgroups(void) {
    char buf[512];
    check("cg_mkdir", mkdir("/sys/fs/cgroup/restest", 0755) == 0);
    check("cg_memory_max", put("/sys/fs/cgroup/restest/memory.max", "16M") == 0 &&
                               get("/sys/fs/cgroup/restest/memory.max", buf, sizeof buf) == 0 &&
                               atoll(buf) == 16 << 20);
    check("cg_memory_fits", in_child(memory_fits_in_cgroup) == 0);
    int s = in_child(memory_hog_in_cgroup);
    check("cg_oom_kills", WIFSIGNALED(s) && WTERMSIG(s) == SIGKILL);
    check("cg_memory_events", get("/sys/fs/cgroup/restest/memory.events", buf, sizeof buf) == 0 &&
                                  field(buf, "oom_kill") >= 1 && field(buf, "max") >= 1);
    check("cg_memory_uncharged", get("/sys/fs/cgroup/restest/memory.current", buf, sizeof buf) == 0 && atoll(buf) == 0);
    check("cg_memory_peak", get("/sys/fs/cgroup/restest/memory.peak", buf, sizeof buf) == 0 &&
                                atoll(buf) >= 15 << 20 && atoll(buf) <= 16 << 20);
    /* A victim other than the process that ran out (an idle one holding
       more): it is killed and reaped, and the other's memory fits. */
    int ready[2];
    int piped = pipe(ready) == 0;
    pid_t idle = fork();
    if (idle == 0) {
        if (join("restest") != 0 || touch_mib(12) != 0) _exit(2);
        if (write(ready[1], "r", 1) != 1) _exit(3);
        for (;;) pause();
    }
    char r = 0;
    if (!piped || read(ready[0], &r, 1) != 1) r = 0;
    pid_t needy = fork();
    if (needy == 0) _exit(join("restest") != 0 || touch_mib(8) != 0 ? 2 : 0);
    int si = 0, sn = 0;
    waitpid(needy, &sn, 0);
    waitpid(idle, &si, 0);
    check("cg_oom_reaps_other", r == 'r' && WIFSIGNALED(si) && WTERMSIG(si) == SIGKILL && WIFEXITED(sn) &&
                                    WEXITSTATUS(sn) == 0);
    close(ready[0]);
    close(ready[1]);
    check("cg_rmdir", rmdir("/sys/fs/cgroup/restest") == 0);

    check("cg_cpu_mkdir", mkdir("/sys/fs/cgroup/cputest", 0755) == 0);
    check("cg_cpu_max_bad", put("/sys/fs/cgroup/cputest/cpu.max", "10 100000") != 0);
    check("cg_cpu_max", put("/sys/fs/cgroup/cputest/cpu.max", "20000 100000") == 0 &&
                            get("/sys/fs/cgroup/cputest/cpu.max", buf, sizeof buf) == 0 &&
                            strcmp(buf, "20000 100000\n") == 0);
    pid_t kid = fork();
    if (kid == 0) _exit(cpu_hog_in_cgroup());
    int st;
    struct rusage ru;
    wait4(kid, &st, 0, &ru);
    long long used = ru.ru_utime.tv_sec * 1000000LL + ru.ru_utime.tv_usec + ru.ru_stime.tv_sec * 1000000LL +
                     ru.ru_stime.tv_usec;
    /* 20% of the CPU for one second of wall time (spin_ms counts wall
     * time), give or take a period. */
    check("cg_cpu_quota_holds", WIFEXITED(st) && WEXITSTATUS(st) == 0 && used >= 100000 && used <= 350000);
    check("cg_cpu_stat", get("/sys/fs/cgroup/cputest/cpu.stat", buf, sizeof buf) == 0 &&
                             field(buf, "nr_throttled") >= 3 && field(buf, "usage_usec") >= 100000 &&
                             field(buf, "throttled_usec") > 0);
    check("cg_cpu_rmdir", rmdir("/sys/fs/cgroup/cputest") == 0);
}

/* --- the overcommit policy (ADR 0123) --------------------------------------------- */

static int set_sysctl(const char *name, const char *v) {
    char path[96];
    snprintf(path, sizeof path, "/proc/sys/vm/%s", name);
    return put(path, v);
}

static void overcommit(void) {
    char buf[2048];
    check("meminfo_commit", get("/proc/meminfo", buf, sizeof buf) == 0 && strstr(buf, "CommitLimit:") &&
                                strstr(buf, "Committed_AS:"));
    struct sysinfo si;
    sysinfo(&si);
    size_t ram = (size_t)si.totalram * si.mem_unit;
    size_t huge = ram * 2;
    int rw = PROT_READ | PROT_WRITE, priv = MAP_PRIVATE | MAP_ANONYMOUS;
    /* Mode 0: more than all of RAM at once is refused, unless it needs
       no reserve or can't be written. */
    void *p = mmap(NULL, huge, rw, priv, -1, 0);
    check("heuristic_refuses", p == MAP_FAILED && errno == ENOMEM);
    p = mmap(NULL, huge, rw, priv | MAP_NORESERVE, -1, 0);
    check("heuristic_noreserve", p != MAP_FAILED && munmap(p, huge) == 0);
    p = mmap(NULL, huge, PROT_NONE, priv, -1, 0);
    check("heuristic_prot_none", p != MAP_FAILED);
    /* Mode 2: everything committed stays under the limit, all of RAM
       here; making the reserved space writable is refused too. */
    check("strict_on", set_sysctl("overcommit_ratio", "100") == 0 && set_sysctl("overcommit_memory", "2") == 0);
    void *q = mmap(NULL, huge, rw, priv | MAP_NORESERVE, -1, 0);
    check("strict_refuses", q == MAP_FAILED && errno == ENOMEM);
    check("strict_mprotect", p != MAP_FAILED && mprotect(p, huge, rw) == -1 && errno == ENOMEM);
    q = mmap(NULL, 16 << 20, rw, priv, -1, 0);
    check("strict_fits", q != MAP_FAILED && munmap(q, 16 << 20) == 0);
    pid_t kid = fork();
    if (kid == 0) _exit(0);
    int st = -1;
    waitpid(kid, &st, 0);
    check("strict_fork", kid > 0 && WIFEXITED(st));
    check("strict_off", set_sysctl("overcommit_memory", "0") == 0 && set_sysctl("overcommit_ratio", "50") == 0 &&
                            get("/proc/sys/vm/overcommit_memory", buf, sizeof buf) == 0 && buf[0] == '0');
    check("bad_mode", set_sysctl("overcommit_memory", "3") != 0);
    if (p != MAP_FAILED) munmap(p, huge);
}

/* --- wait4 and stopped children ------------------------------------------------- */

static void on_alarm(int s) {
    (void)s;
}

static int wait_stopped_child(void) {
    /* Waiting (without WUNTRACED) for a child that stops: the wait goes on,
     * but a signal for the waiter still interrupts it. */
    pid_t kid = fork();
    if (kid == 0) {
        raise(SIGSTOP);
        _exit(0);
    }
    struct sigaction sa = {.sa_handler = on_alarm};
    sigaction(SIGALRM, &sa, NULL);
    alarm(1);
    int st;
    pid_t r = waitpid(kid, &st, 0);
    CHILD_CHECK("interrupted", r < 0 && errno == EINTR);
    kill(kid, SIGKILL);
    waitpid(kid, &st, 0);
    return 0;
}

static void waits(void) {
    struct rusage before, after;
    getrusage(RUSAGE_CHILDREN, &before);
    check("wait_stopped_child", in_child(wait_stopped_child) == 0);
    getrusage(RUSAGE_CHILDREN, &after);
    /* The waiting did not spin in the kernel. */
    check("wait_does_not_spin", (after.ru_stime.tv_sec - before.ru_stime.tv_sec) * 1000000LL +
                                    (after.ru_stime.tv_usec - before.ru_stime.tv_usec) < 200000);
}

/* --- load average -------------------------------------------------------------------- */

static void load_average(void) {
    pid_t kids[3];
    for (int i = 0; i < 3; i++) {
        kids[i] = fork();
        if (kids[i] == 0) {
            for (;;) {
            }
        }
    }
    sleep(6);
    char buf[128];
    double l1 = 0, l5 = 0, l15 = 0;
    int run = 0, all = 0, last = 0;
    check("loadavg_format", get("/proc/loadavg", buf, sizeof buf) == 0 &&
                                sscanf(buf, "%lf %lf %lf %d/%d %d", &l1, &l5, &l15, &run, &all, &last) == 6);
    check("loadavg_rises", l1 > 0.1 && run >= 3 && all > run);
    struct sysinfo si;
    check("sysinfo_loads", sysinfo(&si) == 0 && si.loads[0] > 0);
    for (int i = 0; i < 3; i++) {
        kill(kids[i], SIGKILL);
        waitpid(kids[i], NULL, 0);
    }
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "stack") == 0) {
        /* Under a 256 KiB RLIMIT_STACK, 1 MiB of frames overflows. */
        return deep(64) & 0;
    }
    if (argc > 1 && strcmp(argv[1], "noop") == 0) return 0;
    limits();
    priorities();
    cpu_time();
    futexes();
    cgroups();
    overcommit();
    waits();
    load_average();
    return failures;
}
