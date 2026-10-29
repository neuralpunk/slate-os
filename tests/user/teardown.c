// SPDX-License-Identifier: MIT OR Apache-2.0
// Address-space teardown under load: multithreaded processes whose
// threads are running on other CPUs end (exit_group) or exec while those
// threads are still leaving. The kernel must not free page tables a CPU
// is still using (seen as an intermittent panic in `cargo xtask accept`,
// 2026-10-18). Exits 0 if every child ended as expected.
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile unsigned long counter;

static void *spin(void *arg) {
    (void)arg;
    for (;;)
        counter++;
    return NULL;
}

static void *spin_then_exit(void *arg) {
    volatile unsigned long n = 0;
    while (n < 20000)
        n++;
    (void)arg;
    pthread_exit(NULL);
}

int main(int argc, char **argv) {
    int rounds = argc > 1 ? atoi(argv[1]) : 300;
    for (int i = 0; i < rounds; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            return 1;
        }
        if (pid == 0) {
            pthread_t t;
            for (int k = 0; k < 3; k++)
                pthread_create(&t, NULL, k == 0 ? spin_then_exit : spin, NULL);
            // Give the threads a moment to get onto other CPUs.
            for (volatile int d = 0; d < 20000 * (i % 7); d++)
                ;
            if (i % 3 == 0) {
                char *args[] = {"true", NULL};
                char *env[] = {NULL};
                execve("/bin/true", args, env);
                _exit(99);
            }
            exit(0);
        }
        int status;
        if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "teardown: round %d: child status %#x\n", i, status);
            return 1;
        }
    }
    printf("teardown: %d rounds\n", rounds);
    return 0;
}
