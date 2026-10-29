// SPDX-License-Identifier: MIT OR Apache-2.0
// fork(2) in a multi-threaded process. fork makes the parent's writable
// pages copy-on-write; until every CPU running the parent's threads has
// dropped its old translations, a thread that faults on such a page must
// not copy it, or writes other threads still make through stale writable
// translations land in the frame the child keeps and are lost (seen in
// M18a as foot's malloc state diverging between CPUs). Here some workers
// keep writing their slots of shared pages while others sleep between
// rounds, so they come back on CPUs that ran other processes (whose TLB
// holds nothing of ours) and fault, and the main thread forks again and
// again. Every value a worker wrote must read back.
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

#define WORKERS 6
#define HOGS 3
#define PAGES 32
#define FORKS 400

static atomic_int stop;
static atomic_long lost;
// One 64-byte slot per worker in each page, so one thread may split a page
// another is still writing.
static volatile long *shared;

static void *worker(void *arg) {
    long id = (long)arg;
    long slot = id * 8;
    long last = 0;
    struct timespec nap = {0, 100000};
    for (long round = 1; !atomic_load(&stop); round++) {
        for (int p = 0; p < PAGES; p++) {
            if (shared[p * 512 + slot] != last) atomic_fetch_add(&lost, 1);
            shared[p * 512 + slot] = round;
        }
        last = round;
        if (id % 2) nanosleep(&nap, NULL);
    }
    return NULL;
}

int main(void) {
    shared = mmap(NULL, PAGES * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED) return 1;
    // Other processes to run on the CPUs the sleeping workers leave.
    pid_t hogs[HOGS];
    for (int i = 0; i < HOGS; i++) {
        hogs[i] = fork();
        if (hogs[i] == 0) {
            volatile long spin = 0;
            for (;;) {
                spin++;
                if (spin % 4096 == 0) sched_yield();
            }
        }
    }
    pthread_t t[WORKERS];
    for (long i = 0; i < WORKERS; i++) pthread_create(&t[i], NULL, worker, (void *)i);
    usleep(50000);
    int forked = 0;
    for (int i = 0; i < FORKS; i++) {
        pid_t c = fork();
        if (c == 0) _exit(0);
        if (c > 0 && waitpid(c, NULL, 0) == c) forked++;
    }
    atomic_store(&stop, 1);
    for (int i = 0; i < WORKERS; i++) pthread_join(t[i], NULL);
    for (int i = 0; i < HOGS; i++) {
        kill(hogs[i], SIGKILL);
        waitpid(hogs[i], NULL, 0);
    }
    long l = atomic_load(&lost);
    printf("forkthreads: %d forks, %ld lost writes\n", forked, l);
    return forked == FORKS && l == 0 ? 0 : 1;
}
