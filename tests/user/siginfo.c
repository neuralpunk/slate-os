// SPDX-License-Identifier: MIT OR Apache-2.0
// What siginfo says about a signal's sender: kill(2), tgkill(2) and
// sigqueue(3), in a handler, from sigtimedwait(2) and from signalfd(2);
// checked as Linux was seen to fill it (the same program run on the host).
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::siginfo::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

static volatile siginfo_t seen;
static volatile int count;

static void on_signal(int s, siginfo_t *si, void *ctx) {
    (void)s, (void)ctx;
    seen = *si;
    count++;
}

static void on_alarm(int s) {
    (void)s;
}

static sigset_t only(int sig) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, sig);
    return set;
}

int main(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = on_signal;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, NULL);

    /* kill(2): SI_USER, the sender's PID and real user ID. */
    kill(getpid(), SIGUSR1);
    check("kill_sender", count == 1 && seen.si_code == SI_USER && seen.si_pid == getpid() && seen.si_uid == getuid());

    /* tgkill(2): SI_TKILL. */
    syscall(SYS_tgkill, getpid(), (pid_t)syscall(SYS_gettid), SIGUSR1);
    check("tgkill_sender",
          count == 2 && seen.si_code == SI_TKILL && seen.si_pid == getpid() && seen.si_uid == getuid());

    /* sigqueue(3): SI_QUEUE and the value. */
    sigqueue(getpid(), SIGUSR1, (union sigval){.sival_int = 42});
    check("sigqueue_value", count == 3 && seen.si_code == SI_QUEUE && seen.si_value.sival_int == 42 &&
                                seen.si_pid == getpid());

    /* sigtimedwait(2): a signal another process queued, with its info. */
    sigset_t usr2 = only(SIGUSR2);
    sigprocmask(SIG_BLOCK, &usr2, NULL);
    pid_t kid = fork();
    if (kid == 0) _exit(sigqueue(getppid(), SIGUSR2, (union sigval){.sival_int = 7}) == 0 ? 0 : 1);
    siginfo_t si;
    memset(&si, 0, sizeof si);
    struct timespec two = {2, 0};
    int got = sigtimedwait(&usr2, &si, &two);
    check("sigtimedwait_takes",
          got == SIGUSR2 && si.si_code == SI_QUEUE && si.si_pid == kid && si.si_value.sival_int == 7);
    waitpid(kid, NULL, 0);

    /* Nothing comes: EAGAIN at the timeout. */
    struct timespec brief = {0, 20000000};
    errno = 0;
    check("sigtimedwait_timeout", sigtimedwait(&usr2, &si, &brief) == -1 && errno == EAGAIN);

    /* Another signal, handled, interrupts the wait: EINTR. (The system
       call itself: musl's sigwaitinfo waits again.) */
    signal(SIGALRM, on_alarm);
    struct itimerval it = {{0, 0}, {0, 50000}};
    setitimer(ITIMER_REAL, &it, NULL);
    errno = 0;
    check("sigtimedwait_interrupted", syscall(SYS_rt_sigtimedwait, &usr2, &si, NULL, 8) == -1 && errno == EINTR);

    /* A pending one is taken at once. (glibc's sigwaitinfo shows
       SI_TKILL as SI_USER; the kernel says SI_TKILL, as musl shows.) */
    syscall(SYS_tgkill, getpid(), (pid_t)syscall(SYS_gettid), SIGUSR2);
    check("sigwaitinfo_pending", sigwaitinfo(&usr2, &si) == SIGUSR2 && si.si_code == SI_TKILL);

    /* signalfd(2): the same fields. */
    int fd = signalfd(-1, &usr2, 0);
    sigqueue(getpid(), SIGUSR2, (union sigval){.sival_int = 9});
    struct signalfd_siginfo ssi;
    check("signalfd_queued", fd >= 0 && read(fd, &ssi, sizeof ssi) == sizeof ssi && ssi.ssi_code == SI_QUEUE &&
                                 ssi.ssi_int == 9 && ssi.ssi_pid == (unsigned)getpid());
    close(fd);

    /* A queued signal claiming a kernel or kill(2) origin may only go to
       oneself (rt_sigqueueinfo(2): EPERM). */
    kid = fork();
    if (kid == 0) {
        pause();
        _exit(0);
    }
    siginfo_t forged;
    memset(&forged, 0, sizeof forged);
    forged.si_signo = SIGUSR1;
    forged.si_code = SI_USER;
    errno = 0;
    check("forged_code_refused", syscall(SYS_rt_sigqueueinfo, kid, SIGUSR1, &forged) == -1 && errno == EPERM);
    kill(kid, SIGKILL);
    waitpid(kid, NULL, 0);
    return failures;
}
