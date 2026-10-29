/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Threads split a sum, a temporary file round-trips the result. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "stats.h"

#define THREADS 4
#define N 1000000ULL

struct part {
    unsigned long long from, to, result;
};

static void *work(void *arg) {
    struct part *p = arg;
    p->result = sum_squares(p->from, p->to);
    return NULL;
}

int main(void) {
    pthread_t t[THREADS];
    struct part parts[THREADS];
    for (int i = 0; i < THREADS; i++) {
        parts[i].from = N / THREADS * i;
        parts[i].to = N / THREADS * (i + 1);
        pthread_create(&t[i], NULL, work, &parts[i]);
    }
    unsigned long long total = 0;
    for (int i = 0; i < THREADS; i++) {
        pthread_join(t[i], NULL);
        total += parts[i].result;
    }
    int ok = total == sum_squares(0, N);

    char path[] = "/tmp/c-demo-XXXXXX";
    int fd = mkstemp(path);
    FILE *f = fdopen(fd, "w+");
    fprintf(f, "%llu\n", total);
    rewind(f);
    unsigned long long back = 0;
    ok = ok && fscanf(f, "%llu", &back) == 1 && back == total;
    fclose(f);
    unlink(path);

    double v[] = {3, 4, 12};
    ok = ok && rms(v, 3) > 7.50 && rms(v, 3) < 7.51; /* sqrt(169 / 3) */
    printf("c-demo: sum=%llu threads=%d %s\n", total, THREADS, ok ? "ok" : "FAILED");
    return ok ? 0 : 1;
}
