// SPDX-License-Identifier: MIT OR Apache-2.0
// POSIX threads on Slate: clone(CLONE_THREAD), futexes, TLS, signals to
// threads, concurrent memory changes (TLB shootdowns), fork and exit from
// multi-threaded processes.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;
static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::threads::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

static pid_t tid(void) { return (pid_t)syscall(SYS_gettid); }

#define THREADS 8
#define ITERS 50000
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static long counter;
static __thread int tls = 0;
static pid_t tids[THREADS];

static void *adder(void *arg) {
    int me = (int)(long)arg;
    tls = me + 100;
    tids[me] = tid();
    for (int i = 0; i < ITERS; i++) {
        pthread_mutex_lock(&lock);
        counter++;
        pthread_mutex_unlock(&lock);
    }
    return (void *)(long)(tls == me + 100);
}

static pthread_mutex_t qlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t qcond = PTHREAD_COND_INITIALIZER;
static int queue[64], qhead, qtail, produced_sum;

static void *producer(void *arg) {
    (void)arg;
    for (int i = 1; i <= 1000; i++) {
        pthread_mutex_lock(&qlock);
        while (qtail - qhead == 64) pthread_cond_wait(&qcond, &qlock);
        queue[qtail++ % 64] = i;
        pthread_cond_broadcast(&qcond);
        pthread_mutex_unlock(&qlock);
    }
    return NULL;
}

static volatile pid_t signalled_tid;
static void on_usr1(int s) {
    (void)s;
    signalled_tid = tid();
}

static volatile int stop_waiting;
static void *sleeper(void *arg) {
    *(pid_t *)arg = tid();
    while (!stop_waiting) usleep(1000);
    return NULL;
}

static void *mapper(void *arg) {
    (void)arg;
    for (int i = 0; i < 300; i++) {
        unsigned char *p = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) return (void *)0;
        for (int j = 0; j < 65536; j += 4096) p[j] = (unsigned char)i;
        for (int j = 0; j < 65536; j += 4096)
            if (p[j] != (unsigned char)i) return (void *)0;
        munmap(p, 65536);
    }
    return (void *)1;
}

static void *exiter(void *arg) {
    (void)arg;
    usleep(20000);
    exit(5);  // exit(3) ends the whole process
}

// A non-private futex word in an ordinary (private) page: musl's thread
// list lock is one. FUTEX_WAIT and FUTEX_WAKE are 0 and 1 (futex(2)).
static volatile int cow_word;
static volatile int cow_waiting, cow_woken;

static void *cow_waiter(void *arg) {
    (void)arg;
    cow_waiting = 1;
    while (cow_word == 0) syscall(SYS_futex, &cow_word, 0, 0, NULL, NULL, 0);
    cow_woken = 1;
    return NULL;
}

/* tmpfs's locks (ADR 0183): one thread makes and removes a directory in
   /tmp while another stats it and the directory around it; tmpfs once
   took a directory's entries and an inode's metadata in opposite orders
   in the two paths, and parallel builds deadlocked on it. */
static volatile int race_done;
static void *race_stat(void *arg) {
    (void)arg;
    struct stat st;
    while (!race_done) {
        stat("/tmp/tmpfs-race", &st);
        stat("/tmp/tmpfs-race/d", &st);
    }
    return NULL;
}

int main(void) {
    pthread_t t[THREADS];
    for (long i = 0; i < THREADS; i++) pthread_create(&t[i], NULL, adder, (void *)i);
    int tls_ok = 1;
    for (int i = 0; i < THREADS; i++) {
        void *r;
        pthread_join(t[i], &r);
        tls_ok &= r == (void *)1;
    }
    check("mutex_counter", counter == (long)THREADS * ITERS);
    check("tls_per_thread", tls_ok && tls == 0);
    int distinct = 1;
    for (int i = 0; i < THREADS; i++) {
        distinct &= tids[i] != getpid() && tids[i] > 0;
        for (int j = 0; j < i; j++) distinct &= tids[i] != tids[j];
    }
    check("distinct_tids", distinct && tid() == getpid());

    pthread_t p;
    pthread_create(&p, NULL, producer, NULL);
    int got = 0;
    while (got < 1000) {
        pthread_mutex_lock(&qlock);
        while (qhead == qtail) pthread_cond_wait(&qcond, &qlock);
        produced_sum += queue[qhead++ % 64];
        got++;
        pthread_cond_broadcast(&qcond);
        pthread_mutex_unlock(&qlock);
    }
    pthread_join(p, NULL);
    check("condvar", produced_sum == 1000 * 1001 / 2);

    // A signal sent to one thread runs its handler on that thread.
    signal(SIGUSR1, on_usr1);
    pid_t target = 0;
    pthread_t s;
    pthread_create(&s, NULL, sleeper, &target);
    while (!target) usleep(1000);
    pthread_kill(s, SIGUSR1);
    for (int i = 0; i < 200 && !signalled_tid; i++) usleep(1000);
    stop_waiting = 1;
    pthread_join(s, NULL);
    check("pthread_kill", signalled_tid == target);

    // Concurrent mmap/munmap in several threads (TLB shootdowns).
    pthread_t m[4];
    for (int i = 0; i < 4; i++) pthread_create(&m[i], NULL, mapper, NULL);
    int mapped_ok = 1;
    for (int i = 0; i < 4; i++) {
        void *r;
        pthread_join(m[i], &r);
        mapped_ok &= r == (void *)1;
    }
    check("concurrent_mmap", mapped_ok);

    // fork in a multi-threaded process: the child has one thread.
    pthread_create(&s, NULL, sleeper, &target);
    stop_waiting = 0;
    pid_t c = fork();
    if (c == 0) {
        _exit(tid() == getpid() ? 0 : 1);
    }
    int st;
    waitpid(c, &st, 0);
    stop_waiting = 1;
    pthread_join(s, NULL);
    check("fork_from_threads", WIFEXITED(st) && WEXITSTATUS(st) == 0);

    // A wait queued before a fork is still found after the page is copied
    // on write by the wakeup's store (the futex is keyed by address, not by
    // physical page, in a private mapping).
    pthread_t w;
    pthread_create(&w, NULL, cow_waiter, NULL);
    while (!cow_waiting) usleep(1000);
    usleep(20000);
    c = fork();
    if (c == 0) {
        pause(); // Keeps sharing the page, so the store below copies it.
        _exit(0);
    }
    cow_word = 1;
    syscall(SYS_futex, &cow_word, 1, 1, NULL, NULL, 0);
    for (int i = 0; i < 1000 && !cow_woken; i++) usleep(1000);
    kill(c, SIGKILL);
    waitpid(c, &st, 0);
    check("futex_after_fork_cow", cow_woken);
    if (!cow_woken) syscall(SYS_futex, &cow_word, 1, 1, NULL, NULL, 0);
    pthread_join(w, NULL);

    // exit() from a non-main thread ends the whole process.
    c = fork();
    if (c == 0) {
        pthread_t e;
        pthread_create(&e, NULL, exiter, NULL);
        for (;;) pause();
    }
    waitpid(c, &st, 0);
    check("exit_from_thread", WIFEXITED(st) && WEXITSTATUS(st) == 5);

    // A detached thread that just returns.
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    stop_waiting = 1;
    check("detached", pthread_create(&s, &a, sleeper, &target) == 0);
    usleep(10000);

    mkdir("/tmp/tmpfs-race", 0755);
    pthread_t r;
    int ok = pthread_create(&r, NULL, race_stat, NULL) == 0;
    for (int i = 0; i < 20000 && ok; i++) {
        ok = mkdir("/tmp/tmpfs-race/d", 0755) == 0 && rmdir("/tmp/tmpfs-race/d") == 0;
    }
    race_done = 1;
    pthread_join(r, NULL);
    rmdir("/tmp/tmpfs-race");
    check("tmpfs_stat_while_adding", ok);
    return failures;
}
