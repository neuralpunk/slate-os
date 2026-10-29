// SPDX-License-Identifier: MIT OR Apache-2.0
// Process churn must not leak (M19 phase 7): thousands of fork/exit/wait
// rounds, of threads made and joined, and of exec, leave the free memory
// and the kernel heap where they were.
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;
static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::churn::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

/* A /proc/meminfo field in KiB. */
static long field(const char *key) {
    FILE *f = fopen("/proc/meminfo", "r");
    char line[128];
    long v = -1;
    while (f && fgets(line, sizeof line, f))
        if (strncmp(line, key, strlen(key)) == 0) v = atol(line + strlen(key));
    if (f) fclose(f);
    return v;
}

static void *nothing(void *a) { return a; }

static void forks(int n) {
    for (int i = 0; i < n; i++) {
        pid_t p = fork();
        if (p == 0) _exit(0);
        waitpid(p, NULL, 0);
    }
}

static void threads(int n) {
    for (int i = 0; i < n; i++) {
        pthread_t t;
        pthread_create(&t, NULL, nothing, NULL);
        pthread_join(t, NULL);
    }
}

static void execs(int n) {
    for (int i = 0; i < n; i++) {
        pid_t p = fork();
        if (p == 0) {
            execl("/test/hello", "hello", (char *)NULL);
            _exit(1);
        }
        waitpid(p, NULL, 0);
    }
}

/* Run `f` once to warm caches, then `rounds` times, and report how far
 * free memory and the heap moved (KiB). */
static void measure(const char *name, void (*f)(int), int rounds, long allowed_kib) {
    f(rounds / 10);
    sleep(1);
    long free0 = field("MemFree:"), heap0 = field("Slab:");
    f(rounds);
    sleep(1);
    long free1 = field("MemFree:"), heap1 = field("Slab:");
    printf("churn: %s x%d: free %ld -> %ld KiB, heap %ld -> %ld KiB\n", name, rounds, free0, free1, heap0, heap1);
    FILE *sched = fopen("/proc/slate_sched", "r");
    char line[256];
    while (sched && fgets(line, sizeof line, sched))
        if (strncmp(line, "objects alive", 13) == 0 || strncmp(line, "heap objects", 12) == 0) printf("churn: %s", line);
    if (sched) fclose(sched);
    char n1[64], n2[64];
    snprintf(n1, sizeof n1, "%s_free_memory_kept", name);
    snprintf(n2, sizeof n2, "%s_heap_kept", name);
    check(n1, free0 - free1 < allowed_kib);
    check(n2, heap1 - heap0 < allowed_kib);
}

int main(void) {
    measure("fork", forks, 20000, 2048);
    measure("thread", threads, 20000, 2048);
    measure("exec", execs, 2000, 2048);
    return failures;
}
