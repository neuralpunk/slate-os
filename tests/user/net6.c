// SPDX-License-Identifier: MIT OR Apache-2.0
// IPv6 (ADR 0050): loopback ::1, the card's link-local address, an address
// from QEMU's router advertisement (fec0::/64), ICMPv6 echo, UDP and TCP
// to the host (fec0::2) and over loopback, dual-stack sockets, IPV6_V6ONLY,
// and IPv4 datagrams fragmented and put back together.
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static int failures;
static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::net6::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

static int arg(const char *key) {
    char line[1024] = {0};
    FILE *f = fopen("/proc/cmdline", "r");
    if (!f) return 0;
    fgets(line, sizeof line, f);
    fclose(f);
    char *p = strstr(line, key);
    return p ? atoi(p + strlen(key)) : 0;
}

static struct sockaddr_in6 addr6(const char *ip, int port) {
    struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
    inet_pton(AF_INET6, ip, &a.sin6_addr);
    return a;
}

/// Whether /proc/net/if_inet6 has `hex` (32 digits) on `dev` with state
/// flags `flags` masked by `mask`.
static int has_addr(const char *hex, const char *dev) {
    char line[256];
    FILE *f = fopen("/proc/net/if_inet6", "r");
    int found = 0;
    while (f && fgets(line, sizeof line, f)) {
        unsigned idx, plen, scope, flags;
        char a[64], name[32];
        if (sscanf(line, "%63s %x %x %x %x %31s", a, &idx, &plen, &scope, &flags, name) == 6 &&
            strcmp(a, hex) == 0 && strcmp(name, dev) == 0 && !(flags & 0x40))
            found = 1;
    }
    if (f) fclose(f);
    return found;
}

static int wait_addr(const char *hex, const char *dev, int ms) {
    for (int i = 0; i < ms / 100; i++) {
        if (has_addr(hex, dev)) return 1;
        usleep(100000);
    }
    return has_addr(hex, dev);
}

static void timeout(int s, int ms) {
    struct timeval tv = {ms / 1000, (ms % 1000) * 1000};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
}

int main(void) {
    // QEMU's default MAC 52:54:00:12:34:56: EUI-64 5054:ff:fe12:3456.
    check("loopback_address", has_addr("00000000000000000000000000000001", "lo"));
    check("link_local", wait_addr("fe80000000000000505400fffe123456", "eth0", 3000));
    check("slaac", wait_addr("fec0000000000000505400fffe123456", "eth0", 12000));

    // UDP over ::1.
    int rx = socket(AF_INET6, SOCK_DGRAM, 0), tx = socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_in6 lo = addr6("::1", 0), got;
    socklen_t len = sizeof got;
    check("udp_bind", bind(rx, (struct sockaddr *)&lo, sizeof lo) == 0 &&
                          getsockname(rx, (struct sockaddr *)&got, &len) == 0 && got.sin6_family == AF_INET6);
    sendto(tx, "six", 3, 0, (struct sockaddr *)&got, sizeof got);
    char buf[8192];
    struct sockaddr_in6 from;
    len = sizeof from;
    timeout(rx, 2000);
    int n = recvfrom(rx, buf, sizeof buf, 0, (struct sockaddr *)&from, &len);
    check("udp_loopback", n == 3 && memcmp(buf, "six", 3) == 0 && IN6_IS_ADDR_LOOPBACK(&from.sin6_addr));

    // TCP over ::1, and a dual-stack listener taking IPv4.
    int l = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 any = addr6("::", 0);
    int zero = 0;
    setsockopt(l, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero);
    bind(l, (struct sockaddr *)&any, sizeof any);
    listen(l, 4);
    len = sizeof got;
    getsockname(l, (struct sockaddr *)&got, &len);
    int port = ntohs(got.sin6_port);
    int c = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 to = addr6("::1", port);
    check("tcp_connect", connect(c, (struct sockaddr *)&to, sizeof to) == 0);
    len = sizeof from;
    int a = accept(l, (struct sockaddr *)&from, &len);
    check("tcp_accept", a >= 0 && IN6_IS_ADDR_LOOPBACK(&from.sin6_addr));
    check("tcp_data", write(c, "hello6", 6) == 6 && read(a, buf, sizeof buf) == 6 && memcmp(buf, "hello6", 6) == 0);
    close(a);
    close(c);
    int c4 = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in to4 = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    check("dual_stack_connect", connect(c4, (struct sockaddr *)&to4, sizeof to4) == 0);
    len = sizeof from;
    a = accept(l, (struct sockaddr *)&from, &len);
    check("dual_stack_mapped_peer", a >= 0 && IN6_IS_ADDR_V4MAPPED(&from.sin6_addr) &&
                                        from.sin6_addr.s6_addr[15] == 1 && from.sin6_addr.s6_addr[12] == 127);
    close(a);
    close(c4);
    int only = socket(AF_INET6, SOCK_STREAM, 0), one = 1, v = 0;
    setsockopt(only, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
    socklen_t vl = sizeof v;
    getsockopt(only, IPPROTO_IPV6, IPV6_V6ONLY, &v, &vl);
    bind(only, (struct sockaddr *)&any, sizeof any);
    listen(only, 1);
    len = sizeof got;
    getsockname(only, (struct sockaddr *)&got, &len);
    c4 = socket(AF_INET, SOCK_STREAM, 0);
    to4.sin_port = got.sin6_port;
    check("v6only_refuses_v4", v == 1 && connect(c4, (struct sockaddr *)&to4, sizeof to4) == -1 && errno == ECONNREFUSED);
    close(c4);

    // ICMPv6 echo to QEMU's host address.
    int p = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    unsigned char echo[16] = {128, 0, 0, 0, 0, 0, 0, 1, 'p', 'i', 'n', 'g', '6'};
    struct sockaddr_in6 host = addr6("fec0::2", 0);
    timeout(p, 3000);
    int got_reply = 0;
    for (int i = 0; i < 3 && !got_reply; i++) {
        sendto(p, echo, 13, 0, (struct sockaddr *)&host, sizeof host);
        n = recv(p, buf, sizeof buf, 0);
        got_reply = n >= 8 && (unsigned char)buf[0] == 129;
    }
    check("ping_host", got_reply);

    // UDP to xtask's echo server, a datagram bigger than the link both
    // ways (fragments out, fragments back).
    int echo_port = arg("slate.echo=");
    int u = socket(AF_INET6, SOCK_DGRAM, 0);
    timeout(u, 3000);
    struct sockaddr_in6 eh = addr6("fec0::2", echo_port);
    sendto(u, "udp6", 4, 0, (struct sockaddr *)&eh, sizeof eh);
    n = recv(u, buf, sizeof buf, 0);
    check("udp_host", n == 4 && memcmp(buf, "udp6", 4) == 0);
    // (QEMU's user network does not put IPv6 fragments back together, so
    // IPv6 fragments are checked on a tap in user::rtnl.)
    static char big[3000], back[4000];
    for (int i = 0; i < (int)sizeof big; i++) big[i] = (char)(i * 13);
    int u4 = socket(AF_INET, SOCK_DGRAM, 0);
    timeout(u4, 3000);
    struct sockaddr_in eh4 = {.sin_family = AF_INET, .sin_port = htons(echo_port)};
    inet_pton(AF_INET, "10.0.2.2", &eh4.sin_addr);
    sendto(u4, big, sizeof big, 0, (struct sockaddr *)&eh4, sizeof eh4);
    n = recv(u4, back, sizeof back, 0);
    check("udp4_fragments", n == (int)sizeof big && memcmp(back, big, sizeof big) == 0);

    // TCP to the host's web server.
    int w = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 wh = addr6("fec0::2", arg("slate.http="));
    timeout(w, 5000);
    int ok = connect(w, (struct sockaddr *)&wh, sizeof wh) == 0;
    const char *req = "GET /file HTTP/1.0\r\n\r\n";
    ok = ok && write(w, req, strlen(req)) == (int)strlen(req);
    n = ok ? read(w, buf, 64) : -1;
    check("tcp_host", n > 12 && memcmp(buf, "HTTP/1.0 200", 12) == 0);
    close(w);

    // getifaddrs (musl, over netlink) sees the IPv6 addresses.
    struct ifaddrs *ifs, *i;
    int seen = 0;
    if (getifaddrs(&ifs) == 0) {
        for (i = ifs; i; i = i->ifa_next)
            if (i->ifa_addr && i->ifa_addr->sa_family == AF_INET6 && strcmp(i->ifa_name, "eth0") == 0) seen++;
        freeifaddrs(ifs);
    }
    check("getifaddrs", seen >= 2);
    return failures;
}
