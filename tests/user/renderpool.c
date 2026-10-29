// SPDX-License-Identifier: MIT OR Apache-2.0
// A render pool shaped like foot's (seen crashing in M18a): workers wait
// on a start semaphore, pop rows from a mutex-protected queue and grow
// their own malloc'd "damage" lists; each posts a done semaphore when it
// pops its end marker. The main thread waits for every done, checks that
// each worker really finished, frees all the lists and starts the next
// frame, while it also forks and hog processes force context switches.
// Semaphores, mutexes and malloc must hold up: no early done, no crash.
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define WORKERS 4
#define HOGS 3
#define ROWS 48
#define FRAMES 2000

static sem_t start, done;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int queue[ROWS + WORKERS], head, tail;
static int *damage[WORKERS];
static int count[WORKERS];
static atomic_int busy[WORKERS];
static atomic_int quit;

static void *worker(void *arg) {
    long id = (long)arg;
    for (;;) {
        sem_wait(&start);
        if (atomic_load(&quit)) return NULL;
        atomic_store(&busy[id], 1);
        for (;;) {
            pthread_mutex_lock(&lock);
            int row = head < tail ? queue[head++] : -2;
            pthread_mutex_unlock(&lock);
            if (row == -1 || row == -2) break;
            // Grow this worker's list, as pixman grows a region's boxes.
            int *grown = realloc(damage[id], (count[id] + 1) * sizeof *grown);
            if (!grown) abort();
            damage[id] = grown;
            damage[id][count[id]++] = row;
            char *tmp = malloc(16 + row * 7);
            memset(tmp, row, 16 + row * 7);
            free(tmp);
        }
        atomic_store(&busy[id], 0);
        sem_post(&done);
    }
}

int main(void) {
    pid_t hogs[HOGS];
    for (int i = 0; i < HOGS; i++) {
        hogs[i] = fork();
        if (hogs[i] == 0) { volatile long s = 0; for (;;) if (++s % 4096 == 0) sched_yield(); }
    }
    sem_init(&start, 0, 0);
    sem_init(&done, 0, 0);
    pthread_t t[WORKERS];
    for (long i = 0; i < WORKERS; i++) pthread_create(&t[i], NULL, worker, (void *)i);
    int early = 0;
    for (int f = 0; f < FRAMES; f++) {
        pthread_mutex_lock(&lock);
        head = tail = 0;
        for (int i = 0; i < WORKERS; i++) sem_post(&start);
        for (int r = 0; r < ROWS; r++) queue[tail++] = r;
        for (int i = 0; i < WORKERS; i++) queue[tail++] = -1;
        pthread_mutex_unlock(&lock);
        for (int i = 0; i < WORKERS; i++) sem_wait(&done);
        for (int i = 0; i < WORKERS; i++) early += atomic_load(&busy[i]);
        for (int i = 0; i < WORKERS; i++) { free(damage[i]); damage[i] = NULL; count[i] = 0; }
        if (f % 50 == 0) {
            pid_t c = fork();
            if (c == 0) _exit(0);
            if (c > 0) waitpid(c, NULL, 0);
        }
    }
    atomic_store(&quit, 1);
    for (int i = 0; i < WORKERS; i++) sem_post(&start);
    for (int i = 0; i < WORKERS; i++) pthread_join(t[i], NULL);
    for (int i = 0; i < HOGS; i++) { kill(hogs[i], SIGKILL); waitpid(hogs[i], NULL, 0); }
    printf("renderpool: %d frames, %d early dones\n", FRAMES, early);
    return early == 0 ? 0 : 1;
}
