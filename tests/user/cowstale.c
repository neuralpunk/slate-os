// SPDX-License-Identifier: MIT OR Apache-2.0
// Copy-on-write splits must not let other CPUs read the old frame after
// the new one has been written. Two writers bump a counter in one page and
// then publish it in another; readers check that the counter is never
// behind what was published. The main thread forks again and again, so
// the counter's page keeps becoming copy-on-write: one writer's fault
// copies it, the other's finds it already writable, while a reader's CPU
// may still hold a read-only translation of the old copy. (Seen in M18a
// as musl's malloc reading stale metadata in foot's render threads.)
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define WRITERS 2
#define READERS 3
#define HOGS 3
#define FORKS 600

static atomic_long *counter; // its own page
static atomic_long *published; // another page
static atomic_int stop;
static atomic_long stale;
static int crash;

static void *writer(void *arg) {
    (void)arg;
    while (!atomic_load(&stop)) {
        long v = atomic_fetch_add(counter, 1) + 1;
        long p = atomic_load(published);
        while (p < v && !atomic_compare_exchange_weak(published, &p, v)) {
        }
    }
    return NULL;
}

static void *reader(void *arg) {
    long id = (long)arg;
    struct timespec nap = {0, 50000};
    for (long i = 0; !atomic_load(&stop); i++) {
        atomic_long *pp = published, *cp = counter;
        // The pointers never change after start: a NULL one was read from a
        // stale copy of this page. `cowstale crash` faults with the
        // variable's address in rbx for the kernel's dump.
        if (!pp || !cp) {
            atomic_fetch_add(&stale, 1);
            if (crash) __asm__ volatile("movq $0, (%%rax)" ::"a"(0L), "b"(&counter) : "memory");
            continue;
        }
        long p = atomic_load(pp);
        long c = atomic_load(cp);
        if (c < p) {
            atomic_fetch_add(&stale, 1);
            // `cowstale crash`: fault right away with the counter's address
            // in rbx and the two values in r12/r13, for the kernel's dump.
            if (crash) __asm__ volatile("movq $0, (%%rax)" ::"a"(0L), "b"(counter), "S"(c), "D"(p) : "memory");
        }
        // Some readers sleep so they come back on CPUs other processes used.
        if (id % 2 && i % 256 == 0) nanosleep(&nap, NULL);
    }
    return NULL;
}

int main(int argc, char **argv) {
    crash = argc > 1 && argv[1][0] == 'c';
    char *pages = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pages == MAP_FAILED) return 1;
    counter = (atomic_long *)pages;
    published = (atomic_long *)(pages + 4096);
    pid_t hogs[HOGS];
    for (int i = 0; i < HOGS; i++) {
        hogs[i] = fork();
        if (hogs[i] == 0) { volatile long s = 0; for (;;) if (++s % 4096 == 0) sched_yield(); }
    }
    pthread_t w[WRITERS], r[READERS];
    for (long i = 0; i < WRITERS; i++) pthread_create(&w[i], NULL, writer, (void *)i);
    for (long i = 0; i < READERS; i++) pthread_create(&r[i], NULL, reader, (void *)i);
    int forked = 0;
    for (int i = 0; i < FORKS; i++) {
        pid_t c = fork();
        if (c == 0) _exit(0);
        if (c > 0 && waitpid(c, NULL, 0) == c) forked++;
    }
    atomic_store(&stop, 1);
    for (int i = 0; i < WRITERS; i++) pthread_join(w[i], NULL);
    for (int i = 0; i < READERS; i++) pthread_join(r[i], NULL);
    for (int i = 0; i < HOGS; i++) { kill(hogs[i], SIGKILL); waitpid(hogs[i], NULL, 0); }
    printf("cowstale: %d forks, %ld stale reads\n", forked, atomic_load(&stale));
    return forked == FORKS && atomic_load(&stale) == 0 ? 0 : 1;
}
