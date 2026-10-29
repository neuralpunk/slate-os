// SPDX-License-Identifier: MIT OR Apache-2.0
// Stress: threads doing malloc/free with data checks while the main thread
// forks + execs, with hog processes forcing context switches.
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define WORKERS 6
#define HOGS 3
#define SLOTS 256
#define FORKS 300

static atomic_int stop;
static atomic_long bad;

static void *worker(void *arg) {
    unsigned seed = (unsigned)(uintptr_t)arg * 2654435761u;
    unsigned char *p[SLOTS] = {0};
    size_t n[SLOTS] = {0};
    unsigned char tag[SLOTS] = {0};
    struct timespec nap = {0, 50000};
    while (!atomic_load(&stop)) {
        for (int k = 0; k < 64; k++) {
            seed = seed * 1103515245u + 12345u;
            int i = (seed >> 8) % SLOTS;
            if (p[i]) {
                for (size_t j = 0; j < n[i]; j += 61)
                    if (p[i][j] != tag[i]) { atomic_fetch_add(&bad, 1); break; }
                free(p[i]);
                p[i] = NULL;
            } else {
                n[i] = 16 + (seed >> 4) % 3000;
                tag[i] = (unsigned char)(seed >> 20) | 1;
                p[i] = malloc(n[i]);
                if (!p[i]) { atomic_fetch_add(&bad, 1); continue; }
                memset(p[i], tag[i], n[i]);
            }
        }
        if ((uintptr_t)arg % 2) nanosleep(&nap, NULL);
    }
    for (int i = 0; i < SLOTS; i++) free(p[i]);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc > 1) return 0;  // the exec'd child
    pid_t hogs[HOGS];
    for (int i = 0; i < HOGS; i++) {
        hogs[i] = fork();
        if (hogs[i] == 0) { volatile long s = 0; for (;;) if (++s % 4096 == 0) sched_yield(); }
    }
    pthread_t t[WORKERS];
    for (long i = 0; i < WORKERS; i++) pthread_create(&t[i], NULL, worker, (void *)i);
    int ok = 0;
    for (int i = 0; i < FORKS; i++) {
        pid_t c = fork();
        if (c == 0) { execl(argv[0], argv[0], "child", (char *)NULL); _exit(127); }
        int st;
        if (c > 0 && waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0) ok++;
    }
    atomic_store(&stop, 1);
    for (int i = 0; i < WORKERS; i++) pthread_join(t[i], NULL);
    for (int i = 0; i < HOGS; i++) { kill(hogs[i], SIGKILL); waitpid(hogs[i], NULL, 0); }
    printf("mallocfork: %d/%d children ok, %ld bad\n", ok, FORKS, atomic_load(&bad));
    return ok == FORKS && atomic_load(&bad) == 0 ? 0 : 1;
}
