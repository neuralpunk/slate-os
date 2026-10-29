// SPDX-License-Identifier: MIT OR Apache-2.0
// getrusage(2) beyond the times: the largest resident set, page faults,
// context switches and blocks read, for the process, a thread and
// waited-for children (wait4(2) and RUSAGE_CHILDREN); /proc/self/status's
// VmHWM and context switch lines. Runs on the host too (Linux updates
// its peak lazily, hence the slack below the sizes touched).
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::rusage::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

/// Map and touch `mib` MiB; returns the mapping.
static char *touch(long mib) {
    long len = mib << 20;
    char *p = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;
    for (long i = 0; i < len; i += 4096) p[i] = 1;
    return p;
}

static long status_field(const char *name) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    long v = -1;
    size_t n = strlen(name);
    while (f && fgets(line, sizeof line, f))
        if (!strncmp(line, name, n) && line[n] == ':') v = atol(line + n + 1);
    if (f) fclose(f);
    return v;
}

static long thread_minflt, thread_nvcsw;

static void *in_thread(void *arg) {
    (void)arg;
    struct rusage before, after;
    getrusage(RUSAGE_THREAD, &before);
    char *p = touch(8);
    for (int i = 0; i < 5; i++) usleep(1000);
    getrusage(RUSAGE_THREAD, &after);
    thread_minflt = after.ru_minflt - before.ru_minflt;
    thread_nvcsw = after.ru_nvcsw - before.ru_nvcsw;
    munmap(p, 8 << 20);
    return 0;
}

int main(void) {
    struct rusage before, after;
    getrusage(RUSAGE_SELF, &before);
    char *p = touch(32);
    for (int i = 0; i < 10; i++) usleep(1000);
    getrusage(RUSAGE_SELF, &after);
    check("self_maxrss", p && after.ru_maxrss >= 28 * 1024);
    check("self_minflt", after.ru_minflt - before.ru_minflt >= 8192);
    check("self_nvcsw", after.ru_nvcsw - before.ru_nvcsw >= 10);
    check("self_times", after.ru_utime.tv_sec + after.ru_stime.tv_sec + after.ru_utime.tv_usec + after.ru_stime.tv_usec > 0);
    munmap(p, 32 << 20);
    getrusage(RUSAGE_SELF, &before);
    check("maxrss_is_a_peak", before.ru_maxrss >= after.ru_maxrss);

    long hwm = status_field("VmHWM"), vol = status_field("voluntary_ctxt_switches");
    check("status_vmhwm", hwm >= 28 * 1024);
    check("status_ctxt_switches", vol >= after.ru_nvcsw && status_field("nonvoluntary_ctxt_switches") >= 0);

    pthread_t t;
    pthread_create(&t, 0, in_thread, 0);
    pthread_join(t, 0);
    check("thread_minflt", thread_minflt >= 2048);
    check("thread_nvcsw", thread_nvcsw >= 5);
    struct rusage self, me;
    getrusage(RUSAGE_SELF, &self);
    getrusage(RUSAGE_THREAD, &me);
    check("thread_within_process", me.ru_minflt < self.ru_minflt && me.ru_maxrss == self.ru_maxrss);

    pid_t pid = fork();
    if (pid == 0) {
        touch(48);
        _exit(0);
    }
    int st;
    struct rusage child, children;
    check("wait4", wait4(pid, &st, 0, &child) == pid && WIFEXITED(st));
    check("wait4_maxrss", child.ru_maxrss >= 44 * 1024);
    check("wait4_minflt", child.ru_minflt >= 12288);
    getrusage(RUSAGE_CHILDREN, &children);
    check("children_maxrss", children.ru_maxrss >= 44 * 1024);
    check("children_minflt", children.ru_minflt >= child.ru_minflt);

    // Blocks read: a disk's end, which nothing has read (Slate's scratch
    // disk; skipped where there is none).
    int fd = open("/dev/vdb", O_RDONLY);
    if (fd >= 0) {
        static char buf[1 << 20];
        off_t end = lseek(fd, 0, SEEK_END);
        getrusage(RUSAGE_SELF, &before);
        ssize_t n = pread(fd, buf, sizeof buf, end - (4 << 20));
        getrusage(RUSAGE_SELF, &after);
        check("inblock", n == sizeof buf && after.ru_inblock - before.ru_inblock >= 2048);
        close(fd);
    }
    return failures != 0;
}
