// SPDX-License-Identifier: MIT OR Apache-2.0
// Address space layout randomization (M25): runs itself RUNS times, each
// child reporting where its program, stack, break, first anonymous mapping
// and vDSO landed, and measures each one's entropy as the number of
// address bits that vary (a bit counts when it is set in between a quarter
// and three quarters of the runs). With personality(ADDR_NO_RANDOMIZE)
// (personality(2)) the layout must not change.
//
// Run as a static PIE (the `aslr-pie` variant in tools/xtask/src/user.rs).
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/wait.h>
#include <unistd.h>

#define RUNS 256
#define FIELDS 5

static const char *names[FIELDS] = {"program", "stack", "brk", "mmap", "vdso"};
// Bits each must show at least (the kernel's choices are in ADR 0092).
static const int least[FIELDS] = {28, 28, 16, 28, 26};

static int failures;

static void check(int ok, const char *name) {
    printf("SLATE-TEST: %s user::aslr::%s\n", ok ? "PASS" : "FAIL", name);
    if (!ok)
        failures++;
}

static int child(void) {
    int local = 0;
    void *m = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint64_t v[FIELDS] = {(uint64_t)(uintptr_t)&child, (uint64_t)(uintptr_t)&local, (uint64_t)(uintptr_t)sbrk(0),
                          (uint64_t)(uintptr_t)m, (uint64_t)getauxval(AT_SYSINFO_EHDR)};
    return write(1, v, sizeof v) == sizeof v ? 0 : 1;
}

// One run: the child's addresses, through a pipe.
static int sample(const char *self, int norandom, uint64_t out[FIELDS]) {
    int fds[2];
    if (pipe(fds) != 0)
        return -1;
    pid_t pid = fork();
    if (pid == 0) {
        dup2(fds[1], 1);
        close(fds[0]);
        close(fds[1]);
        if (norandom)
            personality(ADDR_NO_RANDOMIZE);
        execl(self, self, "child", (char *)0);
        _exit(127);
    }
    close(fds[1]);
    ssize_t got = 0, n;
    while (got < (ssize_t)(FIELDS * 8) && (n = read(fds[0], (char *)out + got, FIELDS * 8 - got)) > 0)
        got += n;
    close(fds[0]);
    int status;
    waitpid(pid, &status, 0);
    return got == FIELDS * 8 && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int cmp(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "child") == 0)
        return child();
    static uint64_t s[FIELDS][RUNS];
    for (int r = 0; r < RUNS; r++) {
        uint64_t v[FIELDS];
        if (sample(argv[0], 0, v) != 0) {
            check(0, "runs");
            return failures;
        }
        for (int f = 0; f < FIELDS; f++)
            s[f][r] = v[f];
    }
    check(1, "runs");
    for (int f = 0; f < FIELDS; f++) {
        int bits = 0;
        for (int b = 0; b < 64; b++) {
            int ones = 0;
            for (int r = 0; r < RUNS; r++)
                ones += (s[f][r] >> b) & 1;
            bits += ones > RUNS / 4 && ones < RUNS * 3 / 4;
        }
        qsort(s[f], RUNS, 8, cmp);
        int distinct = 1;
        for (int r = 1; r < RUNS; r++)
            distinct += s[f][r] != s[f][r - 1];
        printf("aslr: %s %d bits, %d of %d distinct\n", names[f], bits, distinct, RUNS);
        char name[32];
        snprintf(name, sizeof name, "%s_entropy", names[f]);
        check(bits >= least[f], name);
    }
    uint64_t a[FIELDS], b[FIELDS];
    int same = sample(argv[0], 1, a) == 0 && sample(argv[0], 1, b) == 0 && memcmp(a, b, sizeof a) == 0;
    check(same, "no_randomize");
    return failures;
}
