// SPDX-License-Identifier: MIT OR Apache-2.0
// TCP sockets: loopback (listen/accept/connect, bulk data, shutdown, EOF,
// RST, non-blocking connect, SIGPIPE) and the host's echo server.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;
static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::tcp::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

static struct sockaddr_in addr(const char *ip, int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
}

static int cmdline_int(const char *key) {
    static char buf[1024];
    int fd = open("/proc/cmdline", O_RDONLY);
    int n = read(fd, buf, sizeof buf - 1);
    close(fd);
    buf[n > 0 ? n : 0] = 0;
    char *p = strstr(buf, key);
    return p ? atoi(p + strlen(key)) : 0;
}

static unsigned char pattern_at(size_t i) {
    return (unsigned char)(i * 131 + (i >> 9));
}

#define BULK (3u << 20)

/// Write all of buf.
static int write_all(int fd, const unsigned char *buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, buf + done, len - done);
        if (n <= 0) return -1;
        done += n;
    }
    return 0;
}

/// Read until `len` bytes or EOF; returns bytes read.
static size_t read_all(int fd, unsigned char *buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, buf + done, len - done);
        if (n <= 0) break;
        done += n;
    }
    return done;
}

struct sender {
    int fd;
    unsigned char *data;
    size_t len;
};

static void *send_thread(void *p) {
    struct sender *s = p;
    write_all(s->fd, s->data, s->len);
    return NULL;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    int l = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in lo = addr("127.0.0.1", 0);
    socklen_t len = sizeof lo;
    check("listen", bind(l, (struct sockaddr *)&lo, sizeof lo) == 0 && listen(l, 8) == 0 &&
                        getsockname(l, (struct sockaddr *)&lo, &len) == 0 && lo.sin_port != 0);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    check("connect", connect(c, (struct sockaddr *)&lo, sizeof lo) == 0);
    struct sockaddr_in peer;
    len = sizeof peer;
    int s = accept(l, (struct sockaddr *)&peer, &len);
    struct sockaddr_in me;
    socklen_t mlen = sizeof me;
    getsockname(c, (struct sockaddr *)&me, &mlen);
    check("accept", s >= 0 && peer.sin_port == me.sin_port && peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    struct sockaddr_in pn;
    len = sizeof pn;
    check("getpeername", getpeername(c, (struct sockaddr *)&pn, &len) == 0 && pn.sin_port == lo.sin_port);

    // Bulk data one way while the other side reads.
    unsigned char *data = malloc(BULK), *got = malloc(BULK);
    for (size_t i = 0; i < BULK; i++) data[i] = pattern_at(i);
    struct sender snd = {c, data, BULK};
    pthread_t t;
    pthread_create(&t, NULL, send_thread, &snd);
    size_t n = read_all(s, got, BULK);
    pthread_join(t, NULL);
    check("bulk", n == BULK && memcmp(data, got, BULK) == 0);

    // Half close: the reader sees EOF; the other direction still works.
    shutdown(c, SHUT_WR);
    char b[64];
    struct pollfd pfd = {.fd = s, .events = POLLIN | POLLRDHUP};
    check("rdhup", poll(&pfd, 1, 2000) == 1 && (pfd.revents & POLLRDHUP));
    check("eof", read(s, b, sizeof b) == 0);
    check("half_close", write(s, "back", 4) == 4 && read(c, b, sizeof b) == 4 && memcmp(b, "back", 4) == 0);
    close(s);
    check("eof_both", read(c, b, sizeof b) == 0);
    close(c);

    // Writing to a reset connection: EPIPE (SIGPIPE ignored).
    c = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (struct sockaddr *)&lo, sizeof lo);
    s = accept(l, NULL, NULL);
    write(c, "unread", 6);
    usleep(20000);
    close(s); // Unread data: the stack resets.
    usleep(20000);
    int w1 = write(c, "x", 1);
    int e1 = errno;
    check("reset", w1 == -1 && (e1 == ECONNRESET || e1 == EPIPE));
    close(c);

    // Refused, and a non-blocking connect completing through poll.
    c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in closed = addr("127.0.0.1", 1);
    check("refused", connect(c, (struct sockaddr *)&closed, sizeof closed) == -1 && errno == ECONNREFUSED);
    close(c);
    c = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    int r = connect(c, (struct sockaddr *)&lo, sizeof lo);
    int inprogress = r == -1 && errno == EINPROGRESS;
    pfd = (struct pollfd){.fd = c, .events = POLLOUT};
    int soerr = -1;
    socklen_t elen = sizeof soerr;
    check("nonblock_connect", inprogress && poll(&pfd, 1, 2000) == 1 && (pfd.revents & POLLOUT) &&
                                  getsockopt(c, SOL_SOCKET, SO_ERROR, &soerr, &elen) == 0 && soerr == 0);
    s = accept(l, NULL, NULL);
    check("nonblock_read", read(c, b, sizeof b) == -1 && errno == EAGAIN);
    close(s);
    close(c);
    // Accept with nothing pending on a non-blocking listener.
    fcntl(l, F_SETFL, O_NONBLOCK);
    check("accept_eagain", accept(l, NULL, NULL) == -1 && errno == EAGAIN);
    close(l);

    // The host's echo server, through the virtual network.
    int port = cmdline_int("slate.tcpecho=");
    c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in host = addr("10.0.2.2", port);
    int ok = connect(c, (struct sockaddr *)&host, sizeof host) == 0;
    check("host_connect", port && ok);
    size_t big = 2u << 20;
    snd = (struct sender){c, data, big};
    pthread_create(&t, NULL, send_thread, &snd);
    n = read_all(c, got, big);
    pthread_join(t, NULL);
    check("host_echo", n == big && memcmp(data, got, big) == 0);

    // Keep-alives (ADR 0051): probes every second after a second idle,
    // answered by the host, so the connection lives on.
    int idle = 1, cnt = 2, v = 0;
    socklen_t vl = sizeof v;
    check("keepalive_set", setsockopt(c, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one) == 0 &&
                               setsockopt(c, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle) == 0 &&
                               setsockopt(c, IPPROTO_TCP, TCP_KEEPINTVL, &idle, sizeof idle) == 0 &&
                               setsockopt(c, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof cnt) == 0 &&
                               getsockopt(c, IPPROTO_TCP, TCP_KEEPCNT, &v, &vl) == 0 && v == 2);
    sleep(4);
    unsigned char ping[4] = {'p', 'i', 'n', 'g'}, pong[4];
    check("keepalive_answered", write(c, ping, 4) == 4 && read_all(c, pong, 4) == 4 && memcmp(ping, pong, 4) == 0);
    close(c);

    // Options and TCP_INFO over loopback: SACK and timestamps agreed.
    l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in lo2 = addr("127.0.0.1", 0);
    socklen_t ll = sizeof lo2;
    bind(l, (struct sockaddr *)&lo2, sizeof lo2);
    listen(l, 1);
    getsockname(l, (struct sockaddr *)&lo2, &ll);
    c = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (struct sockaddr *)&lo2, sizeof lo2);
    s = accept(l, NULL, NULL);
    check("nodelay", setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) == 0 &&
                         getsockopt(c, IPPROTO_TCP, TCP_NODELAY, &v, &vl) == 0 && v == 1);
    check("cork", setsockopt(c, IPPROTO_TCP, TCP_CORK, &one, sizeof one) == 0 &&
                      getsockopt(c, IPPROTO_TCP, TCP_CORK, &v, &vl) == 0 && v == 1);
    int zero = 0;
    setsockopt(c, IPPROTO_TCP, TCP_CORK, &zero, sizeof zero);
    write(c, "x", 1);
    read(s, b, 1);
    // SO_PEEK_OFF (socket(7)): peeks start at the offset and move it on, a
    // read takes off what it consumes (pasta forwards data this way).
    write(c, "abcdef", 6);
    char pk[8] = {0};
    int off = 0, offv = -2;
    socklen_t ol = sizeof offv;
    struct pollfd pp = {.fd = s, .events = POLLIN};
    poll(&pp, 1, 2000);
    usleep(100000);
    int peek_ok = setsockopt(s, SOL_SOCKET, SO_PEEK_OFF, &off, sizeof off) == 0;
    peek_ok &= recv(s, pk, 2, MSG_PEEK) == 2 && memcmp(pk, "ab", 2) == 0;
    peek_ok &= recv(s, pk, 2, MSG_PEEK) == 2 && memcmp(pk, "cd", 2) == 0;
    peek_ok &= read(s, pk, 3) == 3 && memcmp(pk, "abc", 3) == 0;
    peek_ok &= recv(s, pk, sizeof pk, MSG_PEEK | MSG_DONTWAIT) == 2 && memcmp(pk, "ef", 2) == 0;
    peek_ok &= recv(s, pk, sizeof pk, MSG_PEEK | MSG_DONTWAIT) == -1 && errno == EAGAIN;
    peek_ok &= getsockopt(s, SOL_SOCKET, SO_PEEK_OFF, &offv, &ol) == 0 && offv == 3;
    off = -1;
    setsockopt(s, SOL_SOCKET, SO_PEEK_OFF, &off, sizeof off);
    peek_ok &= recv(s, pk, sizeof pk, MSG_PEEK) == 3 && memcmp(pk, "def", 3) == 0;
    peek_ok &= read(s, pk, sizeof pk) == 3;
    check("peek_off", peek_ok);
    struct tcp_info ti;
    socklen_t tl = sizeof ti;
    check("tcp_info", getsockopt(c, IPPROTO_TCP, TCP_INFO, &ti, &tl) == 0 && ti.tcpi_state == TCP_ESTABLISHED &&
                          (ti.tcpi_options & TCPI_OPT_SACK) && (ti.tcpi_options & TCPI_OPT_TIMESTAMPS) &&
                          ti.tcpi_snd_mss > 0 && ti.tcpi_snd_cwnd > 0);
    close(c);
    close(s);
    close(l);
    // SO_BINDTODEVICE on a TCP socket: lo works, an unknown card does not.
    c = socket(AF_INET, SOCK_STREAM, 0);
    char dev[16] = {0};
    socklen_t dl = sizeof dev;
    check("tcp_bind_device", setsockopt(c, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3) == 0 &&
                                 getsockopt(c, SOL_SOCKET, SO_BINDTODEVICE, dev, &dl) == 0 && strcmp(dev, "lo") == 0 &&
                                 setsockopt(c, SOL_SOCKET, SO_BINDTODEVICE, "nosuch0", 8) == -1 && errno == ENODEV);
    close(c);
    return failures != 0;
}
