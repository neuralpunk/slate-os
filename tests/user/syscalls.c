// SPDX-License-Identifier: MIT OR Apache-2.0
// Exercises the system calls a static musl program uses at M5.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::%s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) failures++;
}

static __thread int tls_value = 42;

static long ns_between(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) * 1000000000L + (b.tv_nsec - a.tv_nsec);
}

int main(int argc, char **argv, char **envp) {
    check("argv", argc == 2 && strcmp(argv[0], "syscalls") == 0 && strcmp(argv[1], "--check") == 0);
    check("envp", envp[0] != NULL && strcmp(envp[0], "SLATE=1") == 0);
    check("getpid", getpid() > 0);

    struct utsname u;
    check("uname", uname(&u) == 0 && strcmp(u.sysname, "Linux") == 0 && strcmp(u.machine, "x86_64") == 0);

    check("tls", tls_value == 42 && (tls_value = 7, tls_value == 7));
    check("isatty_stdout", isatty(1) == 1);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    struct timespec req = {0, 10 * 1000 * 1000};
    nanosleep(&req, NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long slept = ns_between(t0, t1);
    check("nanosleep", slept >= 10000000L && slept < 50000000L);

    struct timespec rt;
    check("realtime", clock_gettime(CLOCK_REALTIME, &rt) == 0 && rt.tv_sec > 1577836800L);

    // musl calls the vDSO's clock_gettime; it must agree with the system call.
    const unsigned char *vdso = (const unsigned char *)getauxval(AT_SYSINFO_EHDR);
    check("vdso_mapped", vdso && memcmp(vdso, "\177ELF", 4) == 0);
    int vdso_ok = 1;
    for (int i = 0; i < 1000 && vdso_ok; i++) {
        struct timespec a, b, c;
        clock_gettime(CLOCK_MONOTONIC, &a);
        syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &b);
        clock_gettime(CLOCK_MONOTONIC, &c);
        vdso_ok = ns_between(a, b) >= 0 && ns_between(b, c) >= 0 && ns_between(a, c) < 5000000L;
    }
    struct timeval tv;
    struct timespec rt2;
    syscall(SYS_clock_gettime, CLOCK_REALTIME, &rt2);
    gettimeofday(&tv, NULL);
    time_t now = time(NULL);
    vdso_ok = vdso_ok && tv.tv_sec - rt2.tv_sec <= 1 && tv.tv_sec >= rt2.tv_sec && now >= tv.tv_sec && now - tv.tv_sec <= 1;
    check("vdso_clock", vdso_ok);
    unsigned cpu = 99, node = 99;
    long t_sys = syscall(SYS_time, NULL);
    check("time_getcpu", syscall(SYS_getcpu, &cpu, &node, NULL) == 0 && cpu < 64 && node == 0 &&
                             t_sys >= now && t_sys - now <= 1);

    // malloc exercises brk and (for large sizes) mmap.
    char *small = malloc(100);
    char *big = malloc(4 << 20);
    int heap_ok = small && big;
    if (heap_ok) {
        memset(small, 'a', 100);
        memset(big, 'b', 4 << 20);
        heap_ok = small[99] == 'a' && big[(4 << 20) - 1] == 'b';
    }
    free(big);
    free(small);
    check("malloc", heap_ok);

    // musl's sbrk() only supports sbrk(0), so use the raw system call.
    long brk0 = syscall(SYS_brk, 0);
    long brk1 = syscall(SYS_brk, brk0 + 65536);
    int brk_ok = brk1 == brk0 + 65536;
    if (brk_ok) {
        ((volatile char *)brk0)[65535] = 1;
        brk_ok = syscall(SYS_brk, brk0) == brk0;
    }
    check("brk", brk_ok);

    size_t len = 1 << 20;
    unsigned char *m = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int map_ok = m != MAP_FAILED && m[12345] == 0;
    if (map_ok) {
        for (size_t i = 0; i < len; i += 4096) m[i] = (unsigned char)(i >> 12);
        for (size_t i = 0; i < len; i += 4096) map_ok &= m[i] == (unsigned char)(i >> 12);
        map_ok &= mprotect(m, 4096, PROT_READ) == 0 && m[0] == 0;
        map_ok &= munmap(m, len) == 0;
    }
    check("mmap", map_ok);

    // A regular file's data moves in one call however big (read(2),
    // pread(2), pwrite(2) and readv(2): up to 0x7ffff000 bytes).
    size_t big_len = 3 << 20;
    unsigned char *w = malloc(big_len), *r = malloc(big_len + 4096);
    int big_ok = w && r;
    if (big_ok) {
        for (size_t i = 0; i < big_len; i++) w[i] = (unsigned char)(i * 7 + (i >> 13));
        int fd = open("/tmp/bigio", O_RDWR | O_CREAT | O_TRUNC, 0600);
        big_ok = fd >= 0 && pwrite(fd, w, big_len, 4096) == (ssize_t)big_len;
        big_ok = big_ok && pread(fd, r, big_len, 4096) == (ssize_t)big_len && memcmp(w, r, big_len) == 0;
        big_ok = big_ok && lseek(fd, 0, SEEK_SET) == 0 && read(fd, r, big_len + 4096) == (ssize_t)(big_len + 4096);
        memset(r, 0, big_len);
        struct iovec iov[2] = {{.iov_base = r, .iov_len = 1 << 20},
                               {.iov_base = r + (1 << 20), .iov_len = big_len - (1 << 20)}};
        big_ok = big_ok && lseek(fd, 4096, SEEK_SET) == 4096 && readv(fd, iov, 2) == (ssize_t)big_len &&
                 memcmp(w, r, big_len) == 0;
        close(fd);
        unlink("/tmp/bigio");
    }
    free(w);
    free(r);
    check("big_io", big_ok);

    unsigned char rnd[32] = {0};
    int nonzero = 0;
    check("getrandom_len", getrandom(rnd, sizeof rnd, 0) == (ssize_t)sizeof rnd);
    for (size_t i = 0; i < sizeof rnd; i++) nonzero |= rnd[i];
    check("getrandom_data", nonzero != 0);

    errno = 0;
    check("enosys", syscall(9999) == -1 && errno == ENOSYS);
    errno = 0;
    check("efault", write(1, (void *)0x10, 5) == -1 && errno == EFAULT);
    errno = 0;
    check("ebadf", write(77, "x", 1) == -1 && errno == EBADF);

    volatile double x = 1.5, y = 2.25;
    char buf[32];
    snprintf(buf, sizeof buf, "%.4f", x * y);
    check("float_printf", strcmp(buf, "3.3750") == 0);

    // CPU affinity: pinned to CPU 0, the thread runs there, and the mask
    // reads back; then all CPUs again.
    cpu_set_t all, one, back;
    check("getaffinity", sched_getaffinity(0, sizeof all, &all) == 0 && CPU_COUNT(&all) >= 1);
    CPU_ZERO(&one);
    CPU_SET(0, &one);
    int pinned = sched_setaffinity(0, sizeof one, &one) == 0;
    for (int i = 0; i < 20 && pinned; i++) {
        sched_yield();
        pinned = sched_getcpu() == 0;
    }
    check("setaffinity_runs_there", pinned);
    check("affinity_reads_back", sched_getaffinity(0, sizeof back, &back) == 0 && CPU_EQUAL(&back, &one));
    CPU_ZERO(&one);
    errno = 0;
    check("affinity_empty_einval", sched_setaffinity(0, sizeof one, &one) == -1 && errno == EINVAL);
    check("affinity_restored", sched_setaffinity(0, sizeof all, &all) == 0);
    // One memory node: the default policy.
    int mode = -1;
    unsigned long mask = 7;
    check("get_mempolicy", syscall(SYS_get_mempolicy, &mode, &mask, 64UL, 0, 0UL) == 0 && mode == 0 && mask == 0);

    // /tmp is for everyone: mode 1777 (tmpfs(5)'s default).
    struct stat tmp;
    check("tmp_sticky_and_open", stat("/tmp", &tmp) == 0 && (tmp.st_mode & 07777) == 01777);

    /* ioprio_get(2)/ioprio_set(2) (ADR 0115): kept and read back, as Linux
       was seen to answer: NONE by default; a group's or user's best
       priority counts NONE as best-effort at nice's level (4); unknown
       classes and `which` are EINVAL, a missing process ESRCH. */
    check("ioprio_default", syscall(SYS_ioprio_get, 1, 0) == 0);
    check("ioprio_group", syscall(SYS_ioprio_get, 2, 0) == ((2 << 13) | 4));
    check("ioprio_set", syscall(SYS_ioprio_set, 1, 0, (2 << 13) | 7) == 0 &&
                            syscall(SYS_ioprio_get, 1, 0) == ((2 << 13) | 7));
    check("ioprio_idle", syscall(SYS_ioprio_set, 1, 0, 3 << 13) == 0 && syscall(SYS_ioprio_get, 1, 0) == (3 << 13));
    check("ioprio_bad_class", syscall(SYS_ioprio_set, 1, 0, 5 << 13) == -1 && errno == EINVAL);
    check("ioprio_bad_which", syscall(SYS_ioprio_get, 4, 0) == -1 && errno == EINVAL);
    check("ioprio_missing", syscall(SYS_ioprio_get, 1, 999999) == -1 && errno == ESRCH);
    check("ioprio_reset", syscall(SYS_ioprio_set, 1, 0, 0) == 0 && syscall(SYS_ioprio_get, 1, 0) == 0);
    return failures;
}
