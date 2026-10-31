// SPDX-License-Identifier: MIT OR Apache-2.0
// Socket options (ADR 0077): what Slate does, what it accepts because it
// already behaves as asked, and what it refuses (ENOPROTOOPT, or
// EOPNOTSUPP at a level a Unix socket lacks), with their readbacks.
// Numbers from socket(7), ip(7), tcp(7) and netlink(7), as musl's headers
// define them.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define NETLINK_ROUTE_ 0
#define SOL_NETLINK_ 270
#define NETLINK_GET_STRICT_CHK_ 12

static int failures;
static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::sockopts::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

static int set_int(int fd, int level, int name, int v) { return setsockopt(fd, level, name, &v, sizeof v); }

static int get_int(int fd, int level, int name) {
    int v = -1;
    socklen_t l = sizeof v;
    return getsockopt(fd, level, name, &v, &l) == 0 ? v : -1000 - errno;
}

/// The call failed with `e`.
static int fails(int r, int e) { return r < 0 && errno == e; }

static struct sockaddr_in at(const char *ip, int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void refused(void) {
    int u = socket(AF_INET, SOCK_DGRAM, 0), x = socket(AF_UNIX, SOCK_STREAM, 0);
    check("unknown_socket_option", fails(set_int(u, SOL_SOCKET, 9999, 1), ENOPROTOOPT) &&
                                       get_int(u, SOL_SOCKET, 9999) == -1000 - ENOPROTOOPT);
    check("unknown_ip_option", fails(set_int(u, IPPROTO_IP, 9999, 1), ENOPROTOOPT));
    check("unknown_level", fails(set_int(u, 9999, 1, 1), ENOPROTOOPT));
    /* SO_PRIORITY (socket(7)): kept and read back on any socket. */
    check("priority", set_int(u, SOL_SOCKET, SO_PRIORITY, 5) == 0 && get_int(u, SOL_SOCKET, SO_PRIORITY) == 5 &&
                          set_int(x, SOL_SOCKET, SO_PRIORITY, 2) == 0 && get_int(x, SOL_SOCKET, SO_PRIORITY) == 2);
    check("tcp_option_on_udp", fails(set_int(u, IPPROTO_TCP, TCP_NODELAY, 1), ENOPROTOOPT));
    check("tcp_option_on_unix", fails(set_int(x, IPPROTO_TCP, TCP_NODELAY, 1), EOPNOTSUPP) &&
                                    get_int(x, IPPROTO_TCP, TCP_NODELAY) == -1000 - EOPNOTSUPP);
    int n = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE_);
    check("netlink_strict_check", fails(set_int(n, SOL_NETLINK_, NETLINK_GET_STRICT_CHK_, 1), ENOPROTOOPT));
    // A netlink socket's sends never block: SO_SNDTIMEO is kept to read.
    struct timeval tv = {2, 500000}, back = {0};
    socklen_t l = sizeof back;
    check("netlink_sndtimeo", setsockopt(n, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) == 0 &&
                                  getsockopt(n, SOL_SOCKET, SO_SNDTIMEO, &back, &l) == 0 && back.tv_sec == 2 &&
                                  back.tv_usec == 500000);
    close(n);
    close(u);
    close(x);
}

static void accepted(void) {
    int u = socket(AF_INET, SOCK_DGRAM, 0), t = socket(AF_INET, SOCK_STREAM, 0), x = socket(AF_UNIX, SOCK_STREAM, 0);
    check("reuseaddr", set_int(t, SOL_SOCKET, SO_REUSEADDR, 1) == 0 && get_int(t, SOL_SOCKET, SO_REUSEADDR) == 1 &&
                           set_int(x, SOL_SOCKET, SO_REUSEADDR, 1) == 0 && get_int(x, SOL_SOCKET, SO_REUSEADDR) == 1);
    check("broadcast", get_int(u, SOL_SOCKET, SO_BROADCAST) == 0 && set_int(u, SOL_SOCKET, SO_BROADCAST, 1) == 0 &&
                           get_int(u, SOL_SOCKET, SO_BROADCAST) == 1);
    // Buffer sizes are fixed: the readback is the real one, whatever is asked.
    int before = get_int(t, SOL_SOCKET, SO_RCVBUF);
    check("buffer_sizes", before > 0 && set_int(t, SOL_SOCKET, SO_RCVBUF, 4096) == 0 &&
                              set_int(u, SOL_SOCKET, SO_SNDBUF, 1 << 20) == 0 &&
                              get_int(t, SOL_SOCKET, SO_RCVBUF) == before);
    // No IPv4 options until set; no lingering (read only).
    char opts[40];
    socklen_t ol = sizeof opts;
    struct linger lg = {1, 1};
    socklen_t gl = sizeof lg;
    check("readbacks", getsockopt(t, IPPROTO_IP, IP_OPTIONS, opts, &ol) == 0 && ol == 0 &&
                           getsockopt(t, SOL_SOCKET, SO_LINGER, &lg, &gl) == 0 && lg.l_onoff == 0 &&
                           fails(setsockopt(t, SOL_SOCKET, SO_LINGER, &lg, sizeof lg), ENOPROTOOPT));
    close(u);
    close(t);
    close(x);
}

static void ip_options(void) {
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    check("tos_udp", set_int(u, IPPROTO_IP, IP_TOS, 0x10) == 0 && get_int(u, IPPROTO_IP, IP_TOS) == 0x10);
    check("pmtudisc_default", get_int(u, IPPROTO_IP, IP_MTU_DISCOVER) == IP_PMTUDISC_WANT);
    check("pmtudisc_bad_mode", fails(set_int(u, IPPROTO_IP, IP_MTU_DISCOVER, 9), EINVAL));
    // IP_PMTUDISC_DO: a datagram bigger than the card's MTU (1500) is
    // EMSGSIZE; with IP_PMTUDISC_DONT it goes in fragments. (QEMU's host,
    // 10.0.2.2, port 9: nobody needs to listen.)
    char big[2000] = {0};
    struct sockaddr_in host = at("10.0.2.2", 9);
    int r_do = (set_int(u, IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO), (int)sendto(u, big, sizeof big, 0,
                                                                                   (void *)&host, sizeof host));
    int e_do = errno;
    check("pmtudisc_do", get_int(u, IPPROTO_IP, IP_MTU_DISCOVER) == IP_PMTUDISC_DO && r_do < 0 && e_do == EMSGSIZE &&
                             sendto(u, big, 1000, 0, (void *)&host, sizeof host) == 1000);
    check("pmtudisc_dont", set_int(u, IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT) == 0 &&
                               sendto(u, big, sizeof big, 0, (void *)&host, sizeof host) == (ssize_t)sizeof big);
    close(u);
    // SO_DONTROUTE: 192.0.2.1 (RFC 5737) is only reachable through the
    // gateway, 10.0.2.2 directly.
    int d = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in far = at("192.0.2.1", 9);
    check("dontroute", set_int(d, SOL_SOCKET, SO_DONTROUTE, 1) == 0 && get_int(d, SOL_SOCKET, SO_DONTROUTE) == 1 &&
                           fails(connect(d, (void *)&far, sizeof far), ENETUNREACH) &&
                           fails((int)sendto(d, "x", 1, 0, (void *)&far, sizeof far), ENETUNREACH) &&
                           connect(d, (void *)&host, sizeof host) == 0 && set_int(d, SOL_SOCKET, SO_DONTROUTE, 0) == 0 &&
                           connect(d, (void *)&far, sizeof far) == 0);
    close(d);
}

/// IP_OPTIONS (ip(7)): a raw ICMP socket's Record Route (RFC 791) comes
/// back in the echo reply with the host's entries; the readback is the
/// field padded to whole words; malformed fields are EINVAL; TCP carries
/// a field too.
static void option_field(void) {
    unsigned char rr[39] = {7, 39, 4};
    int r = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    unsigned char back[40];
    socklen_t bl = sizeof back;
    check("ip_options_set", setsockopt(r, IPPROTO_IP, IP_OPTIONS, rr, sizeof rr) == 0 &&
                                getsockopt(r, IPPROTO_IP, IP_OPTIONS, back, &bl) == 0 && bl == 40 &&
                                memcmp(back, rr, 3) == 0 && back[39] == 0);
    unsigned char bad[3] = {7, 3, 3};
    check("ip_options_malformed", fails(setsockopt(r, IPPROTO_IP, IP_OPTIONS, bad, sizeof bad), EINVAL));
    // An echo request (type 8, identifier 0x5151) to ourselves.
    unsigned char echo[16] = {8, 0, 0, 0, 0x51, 0x51, 0, 1, 'r', 'e', 'c', 'o', 'r', 'd', 0, 0};
    unsigned sum = 0;
    for (int i = 0; i < 16; i += 2) sum += echo[i] << 8 | echo[i + 1];
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    echo[2] = ~sum >> 8, echo[3] = ~sum;
    struct sockaddr_in lo = at("127.0.0.1", 0);
    int got = 0, addrs = 0;
    if (sendto(r, echo, sizeof echo, 0, (void *)&lo, sizeof lo) == (ssize_t)sizeof echo) {
        struct pollfd p = {r, POLLIN, 0};
        unsigned char pkt[512];
        while (!got && poll(&p, 1, 2000) == 1) {
            ssize_t n = recv(r, pkt, sizeof pkt, 0);
            int hl = (pkt[0] & 15) * 4;
            if (n < hl + 8 || pkt[hl] != 0 || pkt[hl + 4] != 0x51) continue;
            got = 1;
            // The option field: Record Route, its pointer past two entries,
            // both 127.0.0.1.
            if (hl == 60 && pkt[20] == 7 && pkt[22] == 12 && pkt[23] == 127 && pkt[27] == 127) addrs = 2;
        }
    }
    check("record_route_echoed", got && addrs == 2);
    close(r);
    // TCP over loopback with a field of no-operations and an end.
    unsigned char nops[4] = {1, 1, 1, 0};
    int l = socket(AF_INET, SOCK_STREAM, 0), c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = at("127.0.0.1", 0);
    socklen_t al = sizeof a;
    int ok = setsockopt(c, IPPROTO_IP, IP_OPTIONS, nops, sizeof nops) == 0 && bind(l, (void *)&a, sizeof a) == 0 &&
             listen(l, 1) == 0 && getsockname(l, (void *)&a, &al) == 0 && connect(c, (void *)&a, sizeof a) == 0;
    int s = ok ? accept(l, 0, 0) : -1;
    char buf[8] = {0};
    ok = ok && s >= 0 && write(c, "opts", 4) == 4 && read(s, buf, sizeof buf) == 4 && memcmp(buf, "opts", 4) == 0;
    bl = sizeof back;
    check("ip_options_tcp", ok && getsockopt(c, IPPROTO_IP, IP_OPTIONS, back, &bl) == 0 && bl == 4);
    close(s);
    close(c);
    close(l);
}

static void tcp(void) {
    // TCP_MAXSEG on the listener and the client, before the connection.
    int l = socket(AF_INET, SOCK_STREAM, 0), c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in lo = at("127.0.0.1", 0);
    socklen_t ll = sizeof lo;
    int ok = set_int(l, IPPROTO_TCP, TCP_MAXSEG, 1200) == 0 && bind(l, (void *)&lo, sizeof lo) == 0 &&
             getsockname(l, (void *)&lo, &ll) == 0 && listen(l, 1) == 0 &&
             set_int(c, IPPROTO_TCP, TCP_MAXSEG, 1000) == 0 && set_int(c, IPPROTO_IP, IP_TOS, 0x10) == 0 &&
             connect(c, (void *)&lo, sizeof lo) == 0;
    int s = ok ? accept(l, NULL, NULL) : -1;
    int mc = get_int(c, IPPROTO_TCP, TCP_MAXSEG), ms = get_int(s, IPPROTO_TCP, TCP_MAXSEG);
    check("maxseg", ok && s >= 0 && mc > 0 && mc <= 1000 && ms > 0 && ms <= 1000);
    check("tos_tcp", get_int(c, IPPROTO_IP, IP_TOS) == 0x10 && get_int(c, IPPROTO_IP, IP_MTU_DISCOVER) == IP_PMTUDISC_WANT);
    close(s);
    close(c);
    close(l);
}

static void timeouts(void) {
    // A Unix socket's sends wait by SO_SNDTIMEO, not by SO_RCVTIMEO.
    int p[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, p);
    struct timeval rcv = {30, 0}, snd = {0, 200000}, back = {0};
    socklen_t l = sizeof back;
    setsockopt(p[0], SOL_SOCKET, SO_RCVTIMEO, &rcv, sizeof rcv);
    check("unix_sndtimeo_readback", setsockopt(p[0], SOL_SOCKET, SO_SNDTIMEO, &snd, sizeof snd) == 0 &&
                                        getsockopt(p[0], SOL_SOCKET, SO_SNDTIMEO, &back, &l) == 0 &&
                                        back.tv_sec == 0 && back.tv_usec == 200000);
    char buf[4096] = {0};
    while (send(p[0], buf, sizeof buf, MSG_DONTWAIT) > 0) {
    }
    double t0 = now();
    ssize_t r = send(p[0], buf, sizeof buf, 0);
    int e = errno;
    double waited = now() - t0;
    check("unix_send_timeout", r < 0 && e == EAGAIN && waited > 0.15 && waited < 5);
    close(p[0]);
    close(p[1]);
}

/* IP_RECVERR and IPV6_RECVERR (ip(7), ipv6(7)): glibc's resolver needs
   them. The error queue is empty: MSG_ERRQUEUE says EAGAIN (as on the
   host), and never returns the socket's data. */
static void recverr(void) {
    int u = socket(AF_INET, SOCK_DGRAM, 0), u6 = socket(AF_INET6, SOCK_DGRAM, 0);
    int on = 1, got = 0;
    socklen_t gl = sizeof got;
    check("ip_recverr", setsockopt(u, IPPROTO_IP, IP_RECVERR, &on, sizeof on) == 0 &&
                            getsockopt(u, IPPROTO_IP, IP_RECVERR, &got, &gl) == 0 && got == 1);
    got = 0;
    check("ipv6_recverr", setsockopt(u6, IPPROTO_IPV6, IPV6_RECVERR, &on, sizeof on) == 0 &&
                              getsockopt(u6, IPPROTO_IPV6, IPV6_RECVERR, &got, &gl) == 0 && got == 1);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t al = sizeof a;
    bind(u, (struct sockaddr *)&a, sizeof a);
    getsockname(u, (struct sockaddr *)&a, &al);
    sendto(u, "x", 1, 0, (struct sockaddr *)&a, sizeof a);
    char b[8], c[64];
    struct iovec iov = {b, sizeof b};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = c, .msg_controllen = sizeof c};
    check("errqueue_empty", recvmsg(u, &m, MSG_ERRQUEUE | MSG_DONTWAIT) == -1 && errno == EAGAIN &&
                                recv(u, b, sizeof b, MSG_DONTWAIT) == 1);
    close(u);
    close(u6);
}

/* The control messages' shapes and the error queue, as Linux was seen to
   give them on the host (ip(7), ipv6(7), cmsg(3); ADR 0115). */
static struct cmsghdr *find(struct msghdr *m, int level, int type) {
    for (struct cmsghdr *c = CMSG_FIRSTHDR(m); c; c = CMSG_NXTHDR(m, c))
        if (c->cmsg_level == level && c->cmsg_type == type) return c;
    return 0;
}

static void control_messages(void) {
    int on = 1, tos = 0x28;
    /* IP_PKTINFO and IP_RECVTOS: the interface, the local address and the
       header's destination; the TOS byte. */
    int r = socket(AF_INET, SOCK_DGRAM, 0), s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t al = sizeof a;
    bind(r, (struct sockaddr *)&a, sizeof a);
    getsockname(r, (struct sockaddr *)&a, &al);
    check("pktinfo_set", setsockopt(r, IPPROTO_IP, IP_PKTINFO, &on, sizeof on) == 0 &&
                             setsockopt(r, IPPROTO_IP, IP_RECVTOS, &on, sizeof on) == 0);
    setsockopt(s, IPPROTO_IP, IP_TOS, &tos, sizeof tos);
    sendto(s, "hello", 5, 0, (struct sockaddr *)&a, sizeof a);
    char b[64], c[256];
    struct iovec v = {b, sizeof b};
    struct msghdr m = {.msg_iov = &v, .msg_iovlen = 1, .msg_control = c, .msg_controllen = sizeof c};
    ssize_t n = recvmsg(r, &m, 0);
    struct cmsghdr *pi = find(&m, IPPROTO_IP, IP_PKTINFO), *t = find(&m, IPPROTO_IP, IP_TOS);
    struct in_pktinfo p;
    if (pi) memcpy(&p, CMSG_DATA(pi), sizeof p);
    check("pktinfo", n == 5 && pi && pi->cmsg_len == CMSG_LEN(sizeof p) && p.ipi_ifindex == 1 &&
                         p.ipi_addr.s_addr == htonl(INADDR_LOOPBACK) && p.ipi_spec_dst.s_addr == htonl(INADDR_LOOPBACK));
    check("recvtos", t && t->cmsg_len == CMSG_LEN(1) && *CMSG_DATA(t) == 0x28);
    check("controllen", m.msg_controllen == CMSG_SPACE(sizeof p) + CMSG_SPACE(1));
    /* Too little room: what fits, and MSG_CTRUNC. */
    sendto(s, "again", 5, 0, (struct sockaddr *)&a, sizeof a);
    struct msghdr m2 = {.msg_iov = &v, .msg_iovlen = 1, .msg_control = c, .msg_controllen = CMSG_SPACE(sizeof p)};
    check("ctrunc", recvmsg(r, &m2, 0) == 5 && (m2.msg_flags & MSG_CTRUNC) && m2.msg_controllen == CMSG_SPACE(sizeof p));
    close(r);
    close(s);
    /* IPV6_RECVPKTINFO and IPV6_RECVTCLASS. */
    int r6 = socket(AF_INET6, SOCK_DGRAM, 0), s6 = socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_in6 a6 = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    socklen_t a6l = sizeof a6;
    bind(r6, (struct sockaddr *)&a6, sizeof a6);
    getsockname(r6, (struct sockaddr *)&a6, &a6l);
    check("pktinfo6_set", setsockopt(r6, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof on) == 0 &&
                              setsockopt(r6, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof on) == 0);
    /* IPV6_TCLASS: what the sender sets, the receiver reads (ipv6(7)). */
    int tcv = 0x28, tcg = 0, bad = 256;
    socklen_t tcl = sizeof tcg;
    check("tclass_set", setsockopt(s6, IPPROTO_IPV6, IPV6_TCLASS, &tcv, sizeof tcv) == 0 &&
                            getsockopt(s6, IPPROTO_IPV6, IPV6_TCLASS, &tcg, &tcl) == 0 && tcg == 0x28 &&
                            setsockopt(s6, IPPROTO_IPV6, IPV6_TCLASS, &bad, sizeof bad) == -1 && errno == EINVAL);
    sendto(s6, "hi6", 3, 0, (struct sockaddr *)&a6, sizeof a6);
    struct msghdr m6 = {.msg_iov = &v, .msg_iovlen = 1, .msg_control = c, .msg_controllen = sizeof c};
    n = recvmsg(r6, &m6, 0);
    struct cmsghdr *pi6 = find(&m6, IPPROTO_IPV6, IPV6_PKTINFO), *tc = find(&m6, IPPROTO_IPV6, IPV6_TCLASS);
    struct in6_pktinfo p6;
    if (pi6) memcpy(&p6, CMSG_DATA(pi6), sizeof p6);
    check("pktinfo6", n == 3 && pi6 && pi6->cmsg_len == CMSG_LEN(sizeof p6) && p6.ipi6_ifindex == 1 &&
                          IN6_IS_ADDR_LOOPBACK(&p6.ipi6_addr));
    int tcr = -1;
    if (tc) memcpy(&tcr, CMSG_DATA(tc), sizeof tcr);
    check("recvtclass", tc && tc->cmsg_len == CMSG_LEN(sizeof(int)) && tcr == 0x28);
    close(r6);
    close(s6);
    /* An IPv4 datagram on a dual-stack IPv6 socket: IPV6_PKTINFO with the
       address mapped (::ffff:127.0.0.1). */
    int rd = socket(AF_INET6, SOCK_DGRAM, 0), off = 0, s4 = socket(AF_INET, SOCK_DGRAM, 0);
    setsockopt(rd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off);
    struct sockaddr_in6 any6 = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_ANY_INIT};
    socklen_t anyl = sizeof any6;
    bind(rd, (struct sockaddr *)&any6, sizeof any6);
    getsockname(rd, (struct sockaddr *)&any6, &anyl);
    setsockopt(rd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof on);
    struct sockaddr_in to4 = {.sin_family = AF_INET, .sin_port = any6.sin6_port, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    sendto(s4, "v4", 2, 0, (struct sockaddr *)&to4, sizeof to4);
    struct msghdr md = {.msg_iov = &v, .msg_iovlen = 1, .msg_control = c, .msg_controllen = sizeof c};
    n = recvmsg(rd, &md, 0);
    struct cmsghdr *pim = find(&md, IPPROTO_IPV6, IPV6_PKTINFO);
    struct in6_pktinfo pm;
    if (pim) memcpy(&pm, CMSG_DATA(pim), sizeof pm);
    check("pktinfo6_mapped", n == 2 && pim && IN6_IS_ADDR_V4MAPPED(&pm.ipi6_addr) &&
                                 memcmp(&pm.ipi6_addr.s6_addr[12], "\x7f\0\0\x01", 4) == 0);
    close(rd);
    close(s4);
    /* IP_RECVERR: an unconnected socket's datagram to a closed port. The
       error is POLLERR and SO_ERROR, and queued with the payload, the
       destination and `struct sock_extended_err` with the offender. */
    int e = socket(AF_INET, SOCK_DGRAM, 0);
    setsockopt(e, IPPROTO_IP, IP_RECVERR, &on, sizeof on);
    struct sockaddr_in dead = {.sin_family = AF_INET, .sin_port = htons(9), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    sendto(e, "payload!", 8, 0, (struct sockaddr *)&dead, sizeof dead);
    struct pollfd pf = {e, POLLIN, 0};
    poll(&pf, 1, 1000);
    check("errqueue_pollerr", pf.revents == POLLERR);
    int err = 0;
    socklen_t el = sizeof err;
    check("errqueue_so_error", getsockopt(e, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == ECONNREFUSED);
    struct sockaddr_in from;
    struct msghdr me = {.msg_name = &from, .msg_namelen = sizeof from, .msg_iov = &v, .msg_iovlen = 1,
                        .msg_control = c, .msg_controllen = sizeof c};
    n = recvmsg(e, &me, MSG_ERRQUEUE);
    struct cmsghdr *ec = find(&me, IPPROTO_IP, IP_RECVERR);
    struct { uint32_t errno_; uint8_t origin, type, code, pad; uint32_t info, data; struct sockaddr_in off; } ee;
    if (ec) memcpy(&ee, CMSG_DATA(ec), sizeof ee);
    check("errqueue_read", n == 8 && memcmp(b, "payload!", 8) == 0 && (me.msg_flags & MSG_ERRQUEUE) &&
                               from.sin_port == htons(9) && from.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    check("errqueue_extended_err", ec && ec->cmsg_len == CMSG_LEN(32) && ee.errno_ == ECONNREFUSED && ee.origin == 2 &&
                                       ee.type == 3 && ee.code == 3 && ee.off.sin_family == AF_INET &&
                                       ee.off.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    check("errqueue_then_empty", recvmsg(e, &me, MSG_ERRQUEUE) == -1 && errno == EAGAIN);
    /* Without IP_RECVERR an unconnected socket hears nothing; a connected
       one with it gets ECONNREFUSED from recv, the queue all the same. */
    int q = socket(AF_INET, SOCK_DGRAM, 0);
    sendto(q, "x", 1, 0, (struct sockaddr *)&dead, sizeof dead);
    poll(&(struct pollfd){q, POLLIN, 0}, 1, 200);
    err = 0;
    check("no_recverr_nothing", getsockopt(q, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0);
    int k = socket(AF_INET, SOCK_DGRAM, 0);
    setsockopt(k, IPPROTO_IP, IP_RECVERR, &on, sizeof on);
    connect(k, (struct sockaddr *)&dead, sizeof dead);
    send(k, "x", 1, 0);
    poll(&(struct pollfd){k, POLLIN, 0}, 1, 1000);
    check("connected_refused", recv(k, b, sizeof b, MSG_DONTWAIT) == -1 && errno == ECONNREFUSED);
    me.msg_controllen = sizeof c;
    check("connected_queue_too", recvmsg(k, &me, MSG_ERRQUEUE) == 1);
    int tcp = socket(AF_INET, SOCK_STREAM, 0);
    check("tcp_no_errqueue", recvmsg(tcp, &me, MSG_ERRQUEUE) == -1 && errno == EAGAIN);
    close(e);
    close(q);
    close(k);
    close(tcp);
}

/* UDP_SEGMENT and UDP_GRO (udp(7)), SO_TIMESTAMPNS (socket(7)): as Linux
   was seen to answer on the host (ADR 0115). */
static void udp_offloads(void) {
    int r = socket(AF_INET, SOCK_DGRAM, 0), s = socket(AF_INET, SOCK_DGRAM, 0), v = 100, got = 0;
    socklen_t gl = sizeof got;
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t al = sizeof a;
    bind(r, (struct sockaddr *)&a, sizeof a);
    getsockname(r, (struct sockaddr *)&a, &al);
    check("udp_segment_set", setsockopt(s, IPPROTO_UDP, 103, &v, sizeof v) == 0 &&
                                 getsockopt(s, IPPROTO_UDP, 103, &got, &gl) == 0 && got == 100);
    static char data[13000];
    char b[2000];
    int sizes[4] = {0}, n = 0;
    check("udp_segment_send", sendto(s, data, 250, 0, (struct sockaddr *)&a, sizeof a) == 250);
    for (ssize_t k; n < 4 && (k = recv(r, b, sizeof b, MSG_DONTWAIT)) > 0;) sizes[n++] = (int)k;
    check("udp_segment_split", n == 3 && sizes[0] == 100 && sizes[1] == 100 && sizes[2] == 50);
    check("udp_segment_max", sendto(s, data, 12900, 0, (struct sockaddr *)&a, sizeof a) == -1 && errno == EINVAL);
    v = 70000;
    check("udp_segment_range", setsockopt(s, IPPROTO_UDP, 103, &v, sizeof v) == -1 && errno == EINVAL);
    /* A segment size for one send, as a control message. */
    v = 0;
    setsockopt(s, IPPROTO_UDP, 103, &v, sizeof v);
    char cb[CMSG_SPACE(2)] = {0};
    struct iovec iov = {data, 300};
    struct msghdr m = {.msg_name = &a, .msg_namelen = sizeof a, .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cb,
                       .msg_controllen = sizeof cb};
    struct cmsghdr *cm = CMSG_FIRSTHDR(&m);
    cm->cmsg_level = IPPROTO_UDP;
    cm->cmsg_type = 103;
    cm->cmsg_len = CMSG_LEN(2);
    uint16_t seg = 120;
    memcpy(CMSG_DATA(cm), &seg, 2);
    n = 0;
    check("udp_segment_cmsg", sendmsg(s, &m, 0) == 300);
    for (ssize_t k; n < 4 && (k = recv(r, b, sizeof b, MSG_DONTWAIT)) > 0;) sizes[n++] = (int)k;
    check("udp_segment_cmsg_split", n == 3 && sizes[0] == 120 && sizes[2] == 60);
    v = 1;
    got = 0;
    check("udp_gro", setsockopt(r, IPPROTO_UDP, 104, &v, sizeof v) == 0 &&
                         getsockopt(r, IPPROTO_UDP, 104, &got, &gl) == 0 && got == 1);
    int t = socket(AF_INET, SOCK_STREAM, 0), u = socket(AF_UNIX, SOCK_DGRAM, 0);
    check("tcp_no_udp_options", setsockopt(t, IPPROTO_UDP, 103, &v, sizeof v) == -1 && errno == ENOPROTOOPT &&
                                    setsockopt(t, IPPROTO_UDP, 104, &v, sizeof v) == -1 && errno == ENOPROTOOPT);
    check("timestampns_any_socket", setsockopt(u, SOL_SOCKET, 35, &v, sizeof v) == 0 &&
                                        setsockopt(t, SOL_SOCKET, 35, &v, sizeof v) == 0);
    /* The arrival time, as a timespec, close to now. */
    v = 0;
    setsockopt(r, IPPROTO_UDP, 104, &v, sizeof v);
    v = 1;
    setsockopt(r, SOL_SOCKET, 35, &v, sizeof v);
    struct timespec t0;
    clock_gettime(CLOCK_REALTIME, &t0);
    sendto(s, "ts", 2, 0, (struct sockaddr *)&a, sizeof a);
    char c[128];
    struct iovec ri = {b, sizeof b};
    struct msghdr rm = {.msg_iov = &ri, .msg_iovlen = 1, .msg_control = c, .msg_controllen = sizeof c};
    ssize_t k = recvmsg(r, &rm, 0);
    struct cmsghdr *tc = find(&rm, SOL_SOCKET, 35);
    struct timespec ts = {0, 0};
    if (tc) memcpy(&ts, CMSG_DATA(tc), sizeof ts);
    long long diff = (long long)(ts.tv_sec - t0.tv_sec) * 1000000000LL + (ts.tv_nsec - t0.tv_nsec);
    check("timestampns", k == 2 && tc && tc->cmsg_len == CMSG_LEN(sizeof ts) && diff > -1000000000LL && diff < 1000000000LL);
    /* A Unix datagram's arrival time too. */
    int up[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, up);
    setsockopt(up[1], SOL_SOCKET, 35, &v, sizeof v);
    clock_gettime(CLOCK_REALTIME, &t0);
    write(up[0], "ux", 2);
    struct msghdr um = {.msg_iov = &ri, .msg_iovlen = 1, .msg_control = c, .msg_controllen = sizeof c};
    k = recvmsg(up[1], &um, 0);
    tc = find(&um, SOL_SOCKET, 35);
    ts.tv_sec = ts.tv_nsec = 0;
    if (tc) memcpy(&ts, CMSG_DATA(tc), sizeof ts);
    diff = (long long)(ts.tv_sec - t0.tv_sec) * 1000000000LL + (ts.tv_nsec - t0.tv_nsec);
    check("timestampns_unix", k == 2 && tc && diff > -1000000000LL && diff < 1000000000LL);
    close(up[0]);
    close(up[1]);
    close(r);
    close(s);
    close(t);
    close(u);
}

int main(void) {
    recverr();
    control_messages();
    udp_offloads();
    refused();
    accepted();
    ip_options();
    option_field();
    tcp();
    timeouts();
    return failures != 0;
}
