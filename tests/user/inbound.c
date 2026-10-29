// SPDX-License-Identifier: MIT OR Apache-2.0
// SlateOS's default-deny inbound firewall (ADR 0134), from outside: a
// namespace on a veth pair talks to the initial namespace (whose firewall
// the kernel loaded). A datagram to a port nothing opened doesn't arrive,
// a TCP connection to one isn't answered; an echo request is; the
// initial namespace's own datagram gets its answer back; a port opened in
// the firewall's set lets a connection in, and closing it again doesn't.
// Numbers from rtnetlink(7), linux/if_link.h, linux/veth.h (ADR 0131) and
// linux/netfilter/nf_tables.h, nfnetlink.h (ADR 0128).
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define NLMSG_ERROR 2
#define NLMSG_DONE 3
#define NLM_F_REQUEST 0x1
#define NLM_F_ACK 0x4
#define NLM_F_EXCL 0x200
#define NLM_F_CREATE 0x400
#define NLA_F_NESTED 0x8000

static int failures;
static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::inbound::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

/// A request being built: header, body, attributes, nests.
static unsigned char msg[2048];
static size_t mlen, nests[8], mstart;
static int depth;
static uint32_t seqno;

static void put(const void *p, size_t n) {
    memcpy(msg + mlen, p, n);
    mlen += n;
    while (mlen % 4) msg[mlen++] = 0;
}
static void start(uint16_t type, uint16_t flags, const void *body, size_t n) {
    mstart = mlen;
    uint32_t h[4] = {0, type | (uint32_t)(NLM_F_REQUEST | flags) << 16, ++seqno, 0};
    put(h, 16);
    put(body, n);
}
static void end(void) {
    uint32_t n = mlen - mstart;
    memcpy(msg + mstart, &n, 4);
}
static void attr(uint16_t type, const void *v, uint16_t n) {
    uint16_t h[2] = {4 + n, type};
    memcpy(msg + mlen, h, 4);
    memcpy(msg + mlen + 4, v, n);
    mlen += 4 + n;
    while (mlen % 4) msg[mlen++] = 0;
}
static void str(uint16_t type, const char *s) { attr(type, s, strlen(s) + 1); }
static void nest(uint16_t type) {
    nests[depth++] = mlen;
    uint16_t h[2] = {4, type | NLA_F_NESTED};
    memcpy(msg + mlen, h, 4);
    mlen += 4;
}
static void close_nest(void) {
    size_t at = nests[--depth];
    uint16_t n = mlen - at;
    memcpy(msg + at, &n, 2);
}

/// Send what was built on `s`; the first error among `acks`
/// acknowledgements.
static int send_all(int s, int acks) {
    send(s, msg, mlen, 0);
    mlen = 0;
    int err = 0;
    while (acks > 0) {
        struct pollfd p = {s, POLLIN, 0};
        if (poll(&p, 1, 2000) != 1) return -1;
        unsigned char r[4096];
        int n = recv(s, r, sizeof r, 0);
        for (int at = 0; at + 16 <= n;) {
            uint32_t len;
            uint16_t type;
            memcpy(&len, r + at, 4);
            memcpy(&type, r + at + 4, 2);
            if (type == NLMSG_ERROR) {
                int e;
                memcpy(&e, r + at + 16, 4);
                if (e && !err) err = -e;
                acks--;
            }
            if (len < 16) break;
            at += (len + 3) & ~3;
        }
    }
    return err;
}

static uint32_t ip(int a, int b, int c, int d) { return htonl((a << 24) | (b << 16) | (c << 8) | d); }

/// struct ifinfomsg: family, pad, type, index, flags, change.
static void ifinfo(int index, unsigned flags) {
    unsigned char b[16] = {0};
    unsigned change = flags ? IFF_UP : 0;
    memcpy(b + 4, &index, 4);
    memcpy(b + 8, &flags, 4);
    memcpy(b + 12, &change, 4);
    put(b, 16);
}

/// The set of open TCP ports in table inet slate: PORT added or taken
/// away (NFT_MSG_NEWSETELEM 12, NFT_MSG_DESTROYSETELEM 30).
static int tcp_port(int s, int open, uint16_t port) {
    uint32_t begin[4] = {0, 16 | (uint32_t)NLM_F_REQUEST << 16, ++seqno, 0};
    unsigned char g[4] = {0, 0, 0, 10};
    mstart = mlen;
    put(begin, 16);
    put(g, 4);
    end();
    unsigned char inet[4] = {1, 0, 0, 0};
    start((10 << 8) | (open ? 12 : 30), NLM_F_ACK | (open ? NLM_F_CREATE : 0), inet, 4);
    str(1, "slate"), str(2, "tcp");
    nest(3);
    nest(1);
    nest(1);
    uint16_t p = htons(port);
    attr(1, &p, 2);
    close_nest();
    close_nest();
    close_nest();
    end();
    uint32_t fin[4] = {0, 17 | (uint32_t)NLM_F_REQUEST << 16, ++seqno, 0};
    mstart = mlen;
    put(fin, 16);
    put(g, 4);
    end();
    return send_all(s, 1);
}

static int ns_main, ns_out;
static void enter(int fd) { setns(fd, CLONE_NEWNET); }

static int socket_in(int ns, int type) {
    enter(ns);
    int s = socket(AF_INET, type, 0);
    enter(ns_main);
    return s;
}

/// A socket made in namespace `ns` and bound (from here: a socket works
/// in the namespace it was made in, whichever its caller is in now).
static int bound(int ns, int type, uint32_t addr, int port) {
    int s = socket_in(ns, type);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr = {addr}};
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) printf("inbound: bind: %s\n", strerror(errno));
    if (type == SOCK_STREAM) listen(s, 4);
    return s;
}

/// Whether `to` gets `from`'s datagram to ADDR:PORT within a second.
static int arrives(int from, int to, uint32_t addr, int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr = {addr}};
    sendto(from, "in", 2, 0, (struct sockaddr *)&a, sizeof a);
    struct pollfd p = {to, POLLIN, 0};
    if (poll(&p, 1, 1000) != 1) return 0;
    char b[8];
    return recv(to, b, sizeof b, 0) == 2;
}

/// Whether a TCP connection from namespace `ns` to ADDR:PORT is answered
/// within a second.
static int connects(int ns, uint32_t addr, int port) {
    int s = socket_in(ns, SOCK_STREAM);
    fcntl(s, F_SETFL, O_NONBLOCK);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr = {addr}};
    connect(s, (struct sockaddr *)&a, sizeof a);
    struct pollfd p = {s, POLLOUT, 0};
    int ok = poll(&p, 1, 1000) == 1;
    int err = 0;
    socklen_t l = sizeof err;
    getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &l);
    close(s);
    return ok && err == 0;
}

int main(void) {
    ns_main = open("/proc/self/ns/net", O_RDONLY);
    int pipefd[2];
    pipe(pipefd);
    pid_t child = fork();
    if (child == 0) {
        char c = unshare(CLONE_NEWNET) == 0 ? 'y' : 'n';
        write(pipefd[1], &c, 1);
        for (;;) pause();
    }
    char c = 0;
    read(pipefd[0], &c, 1);
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/ns/net", child);
    ns_out = open(path, O_RDONLY);
    check("namespaces", c == 'y' && ns_main >= 0 && ns_out >= 0);

    // fw0 here, fw1 in the other namespace: 10.78.0.1 and .2.
    int rt = socket(AF_NETLINK, SOCK_RAW, 0);
    start(16, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, "", 0);
    ifinfo(0, 0);
    str(3, "fw0");
    nest(18);
    str(1, "veth");
    nest(2);
    nest(1);
    ifinfo(0, 0);
    str(3, "fw1");
    attr(28, &ns_out, 4);
    close_nest();
    close_nest();
    close_nest();
    end();
    check("veth", send_all(rt, 1) == 0);
    int fw0 = if_nametoindex("fw0");
    enter(ns_out);
    int rt_out = socket(AF_NETLINK, SOCK_RAW, 0);
    int fw1 = if_nametoindex("fw1");
    enter(ns_main);
    struct { int ns_rt; int index; uint32_t addr; } sides[2] = {{rt, fw0, ip(10, 78, 0, 1)}, {rt_out, fw1, ip(10, 78, 0, 2)}};
    int up = 1;
    for (int i = 0; i < 2; i++) {
        start(16, NLM_F_ACK, "", 0);
        ifinfo(sides[i].index, IFF_UP);
        end();
        up = up && send_all(sides[i].ns_rt, 1) == 0;
        unsigned char body[8] = {AF_INET, 24, 0, 0};
        memcpy(body + 4, &sides[i].index, 4);
        start(20, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, body, 8);
        attr(2, &sides[i].addr, 4);
        end();
        up = up && send_all(sides[i].ns_rt, 1) == 0;
    }
    check("configured", up);
    uint32_t here = ip(10, 78, 0, 1), there = ip(10, 78, 0, 2);

    // Nothing opened: nothing new comes in.
    int u_here = bound(ns_main, SOCK_DGRAM, here, 9300), u_there = bound(ns_out, SOCK_DGRAM, there, 9300);
    check("udp_refused", !arrives(u_there, u_here, here, 9300));
    int t_here = bound(ns_main, SOCK_STREAM, here, 9301);
    check("tcp_refused", !connects(ns_out, here, 9301));
    // An answer to what this namespace sent comes in.
    check("answer_in", arrives(u_here, u_there, there, 9300) && arrives(u_there, u_here, here, 9300));
    // An echo request is answered (a ping socket in the other namespace).
    enter(ns_out);
    int ping = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    enter(ns_main);
    unsigned char echo[16] = {8, 0, 0, 0, 0, 1, 0, 1, 'p', 'i', 'n', 'g'};
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_addr = {here}};
    sendto(ping, echo, 12, 0, (struct sockaddr *)&to, sizeof to);
    struct pollfd pp = {ping, POLLIN, 0};
    check("echo_answered", ping >= 0 && poll(&pp, 1, 1000) == 1);

    // Port 9301 opened: the connection comes in; closed: it doesn't.
    int nf = socket(AF_NETLINK, SOCK_RAW, 12);
    check("opened", tcp_port(nf, 1, 9301) == 0 && connects(ns_out, here, 9301));
    check("closed", tcp_port(nf, 0, 9301) == 0 && !connects(ns_out, here, 9301));

    close(t_here);
    start(17, NLM_F_ACK, "", 0);
    ifinfo(fw0, 0);
    end();
    send_all(rt, 1);
    kill(child, SIGKILL);
    waitpid(child, 0, 0);
    return failures != 0;
}
