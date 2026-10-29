// SPDX-License-Identifier: MIT OR Apache-2.0
// eventfd, timerfd, signalfd, epoll and interval timers.
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

static int failures;
static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::events::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

static long ms_since(struct timespec a) {
    struct timespec b;
    clock_gettime(CLOCK_MONOTONIC, &b);
    return (b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;
}

static volatile int alarms;
static void on_alarm(int s) { (void)s; alarms++; }

int main(void) {
    // eventfd: counter and semaphore modes
    int e = eventfd(0, EFD_NONBLOCK);
    uint64_t v = 3, r = 0;
    errno = 0;
    check("eventfd_empty", read(e, &r, 8) == -1 && errno == EAGAIN);
    write(e, &v, 8);
    write(e, &v, 8);
    check("eventfd_sum", read(e, &r, 8) == 8 && r == 6);
    int es = eventfd(2, EFD_SEMAPHORE | EFD_NONBLOCK);
    uint64_t a1 = 0, a2 = 0, a3 = 0;
    read(es, &a1, 8);
    read(es, &a2, 8);
    check("eventfd_semaphore", a1 == 1 && a2 == 1 && read(es, &a3, 8) == -1);

    // timerfd: 30 ms then every 10 ms
    int t = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec its = {{0, 10000000}, {0, 30000000}};
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    timerfd_settime(t, 0, &its, NULL);
    uint64_t exp = 0;
    read(t, &exp, 8);  // blocks until the first expiry
    long waited = ms_since(start);
    check("timerfd_first", exp >= 1 && waited >= 29 && waited < 200);
    usleep(55000);
    read(t, &exp, 8);
    check("timerfd_interval", exp >= 4 && exp <= 8);
    struct itimerspec cur;
    timerfd_gettime(t, &cur);
    check("timerfd_gettime", cur.it_interval.tv_nsec == 10000000);

    // epoll: level-triggered pipe and eventfd
    int ep = epoll_create1(EPOLL_CLOEXEC);
    int p[2];
    pipe(p);
    struct epoll_event ev = {.events = EPOLLIN, .data.u64 = 0x1111};
    epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev);
    ev.data.u64 = 0x2222;
    epoll_ctl(ep, EPOLL_CTL_ADD, e, &ev);
    struct epoll_event out[4];
    check("epoll_timeout", epoll_wait(ep, out, 4, 20) == 0);
    write(p[1], "x", 1);
    int n = epoll_wait(ep, out, 4, 1000);
    check("epoll_pipe_ready", n == 1 && out[0].data.u64 == 0x1111 && (out[0].events & EPOLLIN));
    n = epoll_wait(ep, out, 4, 0);
    check("epoll_level_triggered", n == 1);  // still readable: reported again
    char c;
    read(p[0], &c, 1);
    write(e, &v, 8);
    n = epoll_wait(ep, out, 4, 1000);
    check("epoll_eventfd", n == 1 && out[0].data.u64 == 0x2222);
    read(e, &r, 8);
    check("epoll_dup_add", epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev) == -1 && errno == EEXIST);

    // edge-triggered: one report per new readiness
    ev.events = EPOLLIN | EPOLLET;
    ev.data.u64 = 0x3333;
    epoll_ctl(ep, EPOLL_CTL_MOD, p[0], &ev);
    write(p[1], "y", 1);
    n = epoll_wait(ep, out, 4, 1000);
    int second = epoll_wait(ep, out, 4, 20);
    check("epoll_edge_triggered", n == 1 && second == 0);
    read(p[0], &c, 1);
    write(p[1], "z", 1);
    check("epoll_new_edge", epoll_wait(ep, out, 4, 1000) == 1);
    read(p[0], &c, 1);

    // one-shot: reported once until re-armed
    ev.events = EPOLLIN | EPOLLONESHOT;
    epoll_ctl(ep, EPOLL_CTL_MOD, p[0], &ev);
    write(p[1], "w", 1);
    n = epoll_wait(ep, out, 4, 1000);
    check("epoll_oneshot", n == 1 && epoll_wait(ep, out, 4, 20) == 0);
    epoll_ctl(ep, EPOLL_CTL_MOD, p[0], &ev);
    check("epoll_rearm", epoll_wait(ep, out, 4, 1000) == 1);
    epoll_ctl(ep, EPOLL_CTL_DEL, p[0], NULL);

    // epoll wakes when a timerfd fires
    its.it_interval.tv_nsec = 0;
    its.it_value.tv_nsec = 40000000;
    timerfd_settime(t, 0, &its, NULL);
    ev.events = EPOLLIN;
    ev.data.u64 = 0x4444;
    epoll_ctl(ep, EPOLL_CTL_ADD, t, &ev);
    clock_gettime(CLOCK_MONOTONIC, &start);
    n = epoll_wait(ep, out, 4, 2000);
    waited = ms_since(start);
    check("epoll_timerfd", n == 1 && out[0].data.u64 == 0x4444 && waited >= 30 && waited < 500);

    // signalfd
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGUSR1);
    sigprocmask(SIG_BLOCK, &m, NULL);
    int sf = signalfd(-1, &m, SFD_NONBLOCK);
    struct signalfd_siginfo si;
    errno = 0;
    check("signalfd_empty", read(sf, &si, sizeof si) == -1 && errno == EAGAIN);
    kill(getpid(), SIGUSR1);
    check("signalfd_read", read(sf, &si, sizeof si) == sizeof si && si.ssi_signo == SIGUSR1);
    sigset_t pend;
    sigpending(&pend);
    check("signalfd_consumed", !sigismember(&pend, SIGUSR1));

    // setitimer / alarm: SIGALRM
    signal(SIGALRM, on_alarm);
    struct itimerval itv = {{0, 20000}, {0, 20000}};
    setitimer(ITIMER_REAL, &itv, NULL);
    while (alarms < 3) pause();
    struct itimerval off = {{0, 0}, {0, 0}};
    setitimer(ITIMER_REAL, &off, NULL);
    check("setitimer", alarms >= 3);
    alarms = 0;
    alarm(1);
    check("alarm_remaining", alarm(0) == 1);

    // inotify: create, modify, close, move, delete in a watched directory,
    // and a watch on a file ending when it is deleted.
    mkdir("/tmp/inw", 0755);
    int in = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    int wd = inotify_add_watch(in, "/tmp/inw", IN_CREATE | IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE);
    check("inotify_watch", in >= 0 && wd > 0);
    char evbuf[4096];
    errno = 0;
    check("inotify_empty", read(in, evbuf, sizeof evbuf) == -1 && errno == EAGAIN);
    int f = open("/tmp/inw/a", O_CREAT | O_WRONLY, 0644);
    write(f, "x", 1);
    close(f);
    rename("/tmp/inw/a", "/tmp/inw/b");
    int fw = inotify_add_watch(in, "/tmp/inw/b", IN_DELETE_SELF);
    unlink("/tmp/inw/b");
    // Expect, in order: CREATE a, MODIFY a, CLOSE_WRITE a, MOVED_FROM a,
    // MOVED_TO b (same cookie), DELETE b; DELETE_SELF and IGNORED on fw.
    uint32_t want[] = {IN_CREATE, IN_MODIFY, IN_CLOSE_WRITE, IN_MOVED_FROM, IN_MOVED_TO, IN_DELETE_SELF, IN_IGNORED, IN_DELETE};
    uint32_t got[16];
    int ngot = 0;
    uint32_t cookies[2] = {0, 0};
    ssize_t nev = read(in, evbuf, sizeof evbuf);
    for (char *p = evbuf; nev > 0 && p < evbuf + nev && ngot < 16;) {
        struct inotify_event *ev = (struct inotify_event *)p;
        got[ngot++] = ev->mask & ~IN_ISDIR;
        if (ev->mask & IN_MOVED_FROM) cookies[0] = ev->cookie;
        if (ev->mask & IN_MOVED_TO) cookies[1] = ev->cookie;
        p += sizeof *ev + ev->len;
    }
    int same = ngot == 8;
    for (int i = 0; same && i < 8; i++) same = got[i] == want[i];
    check("inotify_events", same);
    check("inotify_move_cookie", cookies[0] != 0 && cookies[0] == cookies[1]);
    check("inotify_rm_watch", inotify_rm_watch(in, wd) == 0 && inotify_rm_watch(in, fw) == -1);
    close(in);
    return failures;
}
