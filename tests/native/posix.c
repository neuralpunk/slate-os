// SPDX-License-Identifier: MIT OR Apache-2.0
//
// slate-libc's POSIX additions (ADR 0075), checked from C: setjmp and
// sigsetjmp, sigaction and signal masks, sockets (TCP and UDP over
// loopback, a socket pair, poll and select, addresses and getaddrinfo),
// termios on a pseudo-terminal, and the calendar functions. Built by
// tools/slate-cc, run on Slate (native calls) and on the Linux host (cargo
// xtask check). Prints one line per check and exits with the number of
// failures.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void check(const char *name, int ok) {
    printf("native-posix: %s %s\n", ok ? "ok" : "FAIL", name);
    if (!ok)
        failures++;
}

// --- setjmp ---

static jmp_buf env;
static int depth;

static void dive(int n) {
    depth = n;
    if (n >= 5)
        longjmp(env, 42);
    else if (n > 0)
        dive(n + 1);
}

static sigjmp_buf senv;
static volatile sig_atomic_t handled_sig;

static void jump_out(int sig) {
    handled_sig = sig;
    siglongjmp(senv, 7);
}

static void jumps(void) {
    volatile int counter = 0;
    int r = setjmp(env);
    counter++;
    if (r == 0)
        dive(1);
    check("longjmp", r == 42 && depth == 5 && counter == 2);
    r = setjmp(env);
    if (r == 0)
        longjmp(env, 0);
    check("longjmp_zero_is_one", r == 1);

    // Out of a signal handler; sigsetjmp(…, 1) gives the mask back.
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = jump_out;
    sigaction(SIGUSR1, &sa, NULL);
    sigset_t before, after;
    sigprocmask(SIG_BLOCK, NULL, &before);
    r = sigsetjmp(senv, 1);
    if (r == 0) {
        raise(SIGUSR1);
        check("siglongjmp", 0);
    }
    sigprocmask(SIG_BLOCK, NULL, &after);
    check("siglongjmp", r == 7 && handled_sig == SIGUSR1);
    check("siglongjmp_mask", !sigismember(&after, SIGUSR1) && sigismember(&before, SIGUSR1) == sigismember(&after, SIGUSR1));
    signal(SIGUSR1, SIG_DFL);
}

// --- signals ---

static volatile int info_signo, info_pid, plain;

static void with_info(int sig, siginfo_t *si, void *ctx) {
    (void)ctx;
    info_signo = si->si_signo;
    info_pid = si->si_pid;
    (void)sig;
}

static void count(int sig) {
    (void)sig;
    plain++;
}

static void signals(void) {
    struct sigaction sa, old;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = with_info;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    check("sigaction", sigaction(SIGUSR2, &sa, NULL) == 0);
    kill(getpid(), SIGUSR2);
    check("siginfo", info_signo == SIGUSR2 && info_pid == getpid());
    check("sigaction_old", sigaction(SIGUSR2, NULL, &old) == 0 && old.sa_sigaction == with_info &&
                               (old.sa_flags & SA_SIGINFO));
    check("sigaction_bad", sigaction(0, &sa, NULL) == -1 && errno == EINVAL);

    sa.sa_handler = count;
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);
    sigset_t set, old_set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, &old_set);
    raise(SIGUSR1);
    int held = plain == 0;
    sigprocmask(SIG_SETMASK, &old_set, NULL);
    check("sigprocmask", held && plain == 1);
    signal(SIGUSR1, SIG_DFL);
    signal(SIGUSR2, SIG_DFL);
}

// --- sockets ---

static void sockets(void) {
    char buf[64];
    struct in_addr a;
    check("inet_pton", inet_pton(AF_INET, "10.0.2.15", &a) == 1 && ntohl(a.s_addr) == 0x0a00020f &&
                           inet_pton(AF_INET, "10.0.2", &a) == 0);
    unsigned char six[16];
    check("inet_ntop6", inet_pton(AF_INET6, "fe80::1:2", six) == 1 && inet_ntop(AF_INET6, six, buf, sizeof buf) &&
                            strcmp(buf, "fe80::1:2") == 0);
    a.s_addr = inet_addr("127.0.0.1");
    check("inet_addr_ntoa", strcmp(inet_ntoa(a), "127.0.0.1") == 0 && inet_addr("bad") == INADDR_NONE);

    // TCP over loopback.
    int l = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int one = 1;
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof sin;
    int ok = l >= 0 && bind(l, (struct sockaddr *)&sin, sizeof sin) == 0 && listen(l, 4) == 0 &&
             getsockname(l, (struct sockaddr *)&sin, &len) == 0 && ntohs(sin.sin_port) != 0;
    check("tcp_listen", ok);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    check("tcp_connect", connect(c, (struct sockaddr *)&sin, sizeof sin) == 0);
    struct sockaddr_in peer;
    len = sizeof peer;
    int s = accept(l, (struct sockaddr *)&peer, &len);
    check("tcp_accept", s >= 0 && len == sizeof peer && peer.sin_family == AF_INET &&
                            ntohl(peer.sin_addr.s_addr) == INADDR_LOOPBACK);
    check("tcp_send", send(c, "ping", 4, 0) == 4);
    struct pollfd p = {s, POLLIN, 0};
    check("poll", poll(&p, 1, 2000) == 1 && (p.revents & POLLIN));
    memset(buf, 0, sizeof buf);
    check("tcp_recv", recv(s, buf, sizeof buf, 0) == 4 && strcmp(buf, "ping") == 0);
    fd_set r;
    FD_ZERO(&r);
    FD_SET(c, &r);
    struct timeval tv = {0, 50000};
    check("select_timeout", select(c + 1, &r, NULL, NULL, &tv) == 0 && !FD_ISSET(c, &r));
    send(s, "pong", 4, 0);
    FD_ZERO(&r);
    FD_SET(c, &r);
    tv.tv_sec = 2;
    check("select_ready", select(c + 1, &r, NULL, NULL, &tv) == 1 && FD_ISSET(c, &r));
    check("getpeername", getpeername(c, (struct sockaddr *)&peer, &len) == 0 && peer.sin_port == sin.sin_port);
    int err = -1;
    len = sizeof err;
    check("getsockopt", getsockopt(c, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0);
    check("shutdown", shutdown(c, SHUT_WR) == 0 && recv(s, buf, sizeof buf, 0) == 0);
    close(c);
    close(s);
    close(l);

    // UDP over loopback.
    int u1 = socket(AF_INET, SOCK_DGRAM, 0), u2 = socket(AF_INET, SOCK_DGRAM, 0);
    sin.sin_port = 0;
    len = sizeof sin;
    bind(u1, (struct sockaddr *)&sin, sizeof sin);
    getsockname(u1, (struct sockaddr *)&sin, &len);
    check("udp_sendto", sendto(u2, "dgram", 5, 0, (struct sockaddr *)&sin, sizeof sin) == 5);
    len = sizeof peer;
    memset(buf, 0, sizeof buf);
    check("udp_recvfrom", recvfrom(u1, buf, sizeof buf, 0, (struct sockaddr *)&peer, &len) == 5 &&
                              strcmp(buf, "dgram") == 0 && peer.sin_family == AF_INET);
    close(u1);
    close(u2);

    int sv[2];
    check("socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0 && write(sv[0], "x", 1) == 1 &&
                            read(sv[1], buf, 1) == 1 && buf[0] == 'x');
    close(sv[0]);
    close(sv[1]);

    // Names: a literal, a passive wildcard, /etc/hosts' localhost.
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    ok = getaddrinfo("10.0.2.2", "http", &hints, &res) == 0;
    if (ok) {
        struct sockaddr_in *ai = (struct sockaddr_in *)res->ai_addr;
        ok = res->ai_family == AF_INET && res->ai_socktype == SOCK_STREAM && ntohs(ai->sin_port) == 80 &&
             ntohl(ai->sin_addr.s_addr) == 0x0a000202 && res->ai_next == NULL;
        freeaddrinfo(res);
    }
    check("getaddrinfo_literal", ok);
    hints.ai_flags = AI_PASSIVE;
    ok = getaddrinfo(NULL, "8080", &hints, &res) == 0;
    if (ok) {
        ok = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr == INADDR_ANY;
        freeaddrinfo(res);
    }
    check("getaddrinfo_passive", ok);
    hints.ai_flags = 0;
    ok = getaddrinfo("localhost", NULL, &hints, &res) == 0;
    if (ok) {
        ok = ntohl(((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr) == INADDR_LOOPBACK;
        freeaddrinfo(res);
    }
    check("getaddrinfo_hosts", ok);
    hints.ai_flags = AI_NUMERICHOST;
    check("getaddrinfo_numeric", getaddrinfo("localhost", NULL, &hints, &res) == EAI_NONAME &&
                                     strlen(gai_strerror(EAI_NONAME)) > 0);
    char host[NI_MAXHOST], serv[NI_MAXSERV];
    sin.sin_port = htons(443);
    sin.sin_addr.s_addr = htonl(0x7f000001);
    check("getnameinfo", getnameinfo((struct sockaddr *)&sin, sizeof sin, host, sizeof host, serv, sizeof serv,
                                     NI_NUMERICHOST | NI_NUMERICSERV) == 0 &&
                             strcmp(host, "127.0.0.1") == 0 && strcmp(serv, "443") == 0);
}

// --- termios ---

static void terminals(void) {
    int m = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    int unlock = 0, n = -1;
    int ok = m >= 0 && ioctl(m, 0x40045431, &unlock) == 0 && ioctl(m, 0x80045430, &n) == 0;
    char name[32];
    snprintf(name, sizeof name, "/dev/pts/%d", n);
    int s = ok ? open(name, O_RDWR | O_NOCTTY) : -1;
    check("pty", s >= 0 && isatty(s));
    struct termios t, back;
    ok = tcgetattr(s, &t) == 0 && (t.c_lflag & ICANON) && (t.c_lflag & ECHO);
    check("tcgetattr", ok);
    cfmakeraw(&t);
    cfsetspeed(&t, B115200);
    ok = tcsetattr(s, TCSANOW, &t) == 0 && tcgetattr(s, &back) == 0 && !(back.c_lflag & (ICANON | ECHO | ISIG)) &&
         !(back.c_oflag & OPOST) && (back.c_cflag & CSIZE) == CS8 && back.c_cc[VMIN] == 1 &&
         cfgetospeed(&back) == B115200;
    check("tcsetattr_raw", ok);
    check("tcflush_drain", tcflush(s, TCIFLUSH) == 0 && tcdrain(s) == 0);
    struct winsize ws = {24, 80, 0, 0}, got = {0, 0, 0, 0};
    check("winsize", ioctl(s, TIOCSWINSZ, &ws) == 0 && ioctl(s, TIOCGWINSZ, &got) == 0 && got.ws_row == 24 &&
                         got.ws_col == 80);
    check("not_a_tty", tcgetattr(1000, &t) == -1 && errno == EBADF);
    close(s);
    close(m);
}

// --- time ---

static void calendar(void) {
    time_t t = 1792240496; // 2026-10-17T12:34:56Z, a Saturday
    struct tm tm;
    char buf[64];
    gmtime_r(&t, &tm);
    check("gmtime", tm.tm_year == 126 && tm.tm_mon == 9 && tm.tm_mday == 17 && tm.tm_hour == 12 && tm.tm_wday == 6 &&
                        tm.tm_yday == 289);
    check("strftime", strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%S %a %j %V", &tm) > 0 &&
                          strcmp(buf, "2026-10-17T12:34:56 Sat 290 42") == 0);
    check("strftime_small", strftime(buf, 5, "%Y-%m", &tm) == 0);
    check("asctime", strcmp(asctime(&tm), "Sat Oct 17 12:34:56 2026\n") == 0);
    tm.tm_mday += 20; // 2026-11-06
    check("timegm", timegm(&tm) == t + 20 * 86400 && tm.tm_mon == 10 && tm.tm_mday == 6 && tm.tm_wday == 5);
    struct tm local;
    localtime_r(&t, &local);
    time_t back = mktime(&local);
    check("localtime_mktime", back == t && local.tm_zone != NULL);
    check("ctime", strlen(ctime(&t)) == 25);
    check("difftime", difftime(t + 90, t) == 90.0);
    struct timeval tv;
    check("gettimeofday", gettimeofday(&tv, NULL) == 0 && tv.tv_sec > 1700000000 && tv.tv_usec < 1000000);
    volatile double x = 0;
    for (int i = 0; i < 2000000; i++)
        x += i;
    check("clock", clock() > 0 && x > 0);
}

int main(void) {
    jumps();
    signals();
    sockets();
    terminals();
    calendar();
    printf("native-posix: %d failures\n", failures);
    return failures;
}
