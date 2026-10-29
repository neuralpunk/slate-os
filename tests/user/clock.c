// SPDX-License-Identifier: MIT OR Apache-2.0
// Setting the clock (M19): clock_settime(2) and settimeofday(2), the vDSO
// following the kernel, their errors, and root only; adjtimex(2) and
// clock_adjtime(2) (ADR 0078): the slew and its rate, the frequency,
// ADJ_SETOFFSET, the status and errors. Puts the clock back at the end.
// Never run it on the host: it sets the clock.
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;
static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::clock::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

/// The time from the kernel itself (musl's clock_gettime uses the vDSO).
static long long kernel_secs(clockid_t c) {
    struct timespec t;
    syscall(SYS_clock_gettime, c, &t);
    return t.tv_sec;
}

static long long near(long long a, long long b) {
    return llabs(a - b) <= 2;
}

/// The wall clock less the monotonic one, in nanoseconds: what slewing and
/// the frequency move.
static long long wall_less_mono(void) {
    struct timespec r, m;
    clock_gettime(CLOCK_REALTIME, &r);
    clock_gettime(CLOCK_MONOTONIC, &m);
    return (r.tv_sec - m.tv_sec) * 1000000000LL + (r.tv_nsec - m.tv_nsec);
}

static void adjtimex_checks(void) {
    struct timex tx = {0};
    int state = adjtimex(&tx);
    check("adjtimex_read", state >= 0 && tx.tick == 10000 && tx.tolerance == 32768000 && tx.precision == 1);
    // The single shot: +50 ms at 500 ppm, so about 200 µs in 0.4 s.
    long long d0 = wall_less_mono();
    struct timex ss = {.modes = ADJ_OFFSET_SINGLESHOT, .offset = 50000};
    check("singleshot", adjtimex(&ss) >= 0);
    usleep(400000);
    struct timex rd = {.modes = ADJ_OFFSET_SS_READ};
    adjtimex(&rd);
    long long moved = wall_less_mono() - d0;
    check("slew_rate", rd.offset > 48000 && rd.offset < 49900 && moved > 100000 && moved < 1100000);
    // ADJ_OFFSET in nanoseconds: at most half a second.
    struct timex off = {.modes = ADJ_OFFSET | ADJ_NANO, .offset = 2000000000};
    struct timex rd2 = {0};
    check("offset_clamped", adjtimex(&off) >= 0 && adjtimex(&rd2) >= 0 && (rd2.status & STA_NANO) &&
                                rd2.offset <= 500000000 && rd2.offset > 490000000);
    // The frequency (offset 0 ends the slew): +100 ppm, about 50 µs in 0.5 s.
    struct timex fr = {.modes = ADJ_FREQUENCY | ADJ_OFFSET | ADJ_MICRO, .freq = 100 << 16, .offset = 0};
    check("frequency_set", adjtimex(&fr) >= 0);
    d0 = wall_less_mono();
    usleep(500000);
    moved = wall_less_mono() - d0;
    check("frequency", moved > 25000 && moved < 300000);
    struct timex big = {.modes = ADJ_FREQUENCY, .freq = 1000 << 16}, rd3 = {0};
    adjtimex(&big);
    adjtimex(&rd3);
    check("frequency_clamped", rd3.freq == 500 << 16);
    struct timex zero = {.modes = ADJ_FREQUENCY, .freq = 0};
    adjtimex(&zero);
    struct timex badtick = {.modes = ADJ_TICK, .tick = 20000};
    check("bad_tick", adjtimex(&badtick) == -1 && errno == EINVAL);
    struct timex badmodes = {.modes = 0x8003};
    check("bad_modes", adjtimex(&badmodes) == -1 && errno == EINVAL);
    // ADJ_SETOFFSET: a step of ten seconds.
    long long before = time(NULL);
    struct timex so = {.modes = ADJ_SETOFFSET, .time = {10, 0}};
    check("setoffset", adjtimex(&so) >= 0 && near(time(NULL), before + 10));
    check("clock_adjtime_other", clock_adjtime(CLOCK_MONOTONIC, &rd3) == -1 && errno == EINVAL);
    // TIME_ERROR while unsynchronized, TIME_OK once not.
    struct timex synced = {.modes = ADJ_STATUS, .status = 0};
    struct timex unsynced = {.modes = ADJ_STATUS, .status = STA_UNSYNC};
    check("status", adjtimex(&synced) == TIME_OK && adjtimex(&unsynced) == TIME_ERROR);
    // Reading needs nothing; changing needs root.
    pid_t pid = fork();
    if (pid == 0) {
        if (setuid(65534) != 0) _exit(2);
        struct timex r = {0}, w = {.modes = ADJ_FREQUENCY, .freq = 1};
        _exit(adjtimex(&r) >= 0 && adjtimex(&w) == -1 && errno == EPERM ? 0 : 1);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    check("adjtimex_needs_root", WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

int main(void) {
    struct timespec wall, mono0;
    clock_gettime(CLOCK_REALTIME, &wall);
    clock_gettime(CLOCK_MONOTONIC, &mono0);

    struct timespec later = {wall.tv_sec + 3600, wall.tv_nsec};
    check("clock_settime", clock_settime(CLOCK_REALTIME, &later) == 0);
    struct timespec v;
    clock_gettime(CLOCK_REALTIME, &v);
    check("kernel_follows", near(kernel_secs(CLOCK_REALTIME), wall.tv_sec + 3600));
    check("vdso_follows", near(v.tv_sec, wall.tv_sec + 3600));
    struct timeval tv;
    gettimeofday(&tv, NULL);
    check("gettimeofday_follows", near(tv.tv_sec, wall.tv_sec + 3600) && near(time(NULL), wall.tv_sec + 3600));
    // The monotonic clock does not jump.
    struct timespec mono1;
    clock_gettime(CLOCK_MONOTONIC, &mono1);
    check("monotonic_unmoved", mono1.tv_sec - mono0.tv_sec < 5);

    struct timeval tv2 = {wall.tv_sec + 7200, 500000};
    check("settimeofday", settimeofday(&tv2, NULL) == 0);
    clock_gettime(CLOCK_REALTIME, &v);
    check("settimeofday_follows", near(v.tv_sec, wall.tv_sec + 7200));
    check("settimeofday_nothing", settimeofday(NULL, NULL) == 0);

    struct timespec bad = {wall.tv_sec, 1000000000};
    check("bad_nsec", clock_settime(CLOCK_REALTIME, &bad) == -1 && errno == EINVAL);
    check("only_realtime", clock_settime(CLOCK_MONOTONIC, &wall) == -1 && errno == EINVAL);
    struct timeval badtv = {wall.tv_sec, 1000000};
    check("bad_usec", settimeofday(&badtv, NULL) == -1 && errno == EINVAL);
    struct timespec negative = {-5, 0};
    check("negative", clock_settime(CLOCK_REALTIME, &negative) == -1 && errno == EINVAL);

    // Only root (CAP_SYS_TIME) sets the clock.
    pid_t pid = fork();
    if (pid == 0) {
        if (setuid(65534) != 0) _exit(2);
        _exit(clock_settime(CLOCK_REALTIME, &wall) == -1 && errno == EPERM ? 0 : 1);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    check("needs_root", WIFEXITED(st) && WEXITSTATUS(st) == 0);

    adjtimex_checks();

    // Back to the right time, with what passed meanwhile.
    struct timespec mono2;
    clock_gettime(CLOCK_MONOTONIC, &mono2);
    long long ns = (wall.tv_sec + (mono2.tv_sec - mono0.tv_sec)) * 1000000000LL + wall.tv_nsec +
                   (mono2.tv_nsec - mono0.tv_nsec);
    struct timespec back = {ns / 1000000000LL, ns % 1000000000LL};
    check("restored", clock_settime(CLOCK_REALTIME, &back) == 0 && near(time(NULL), back.tv_sec));
    return failures;
}
