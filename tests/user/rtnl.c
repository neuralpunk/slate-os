// SPDX-License-Identifier: MIT OR Apache-2.0
// Route netlink as netd uses it (ADR 0048), in a network namespace of its
// own so the machine's configuration stays: adding and removing addresses
// and routes, the notifications every change sends to sockets that joined
// the groups, dumps, blocking reads with a timeout, and SO_BINDTODEVICE.
// Then, on a tap in that namespace (ADR 0049): ARP entries set by hand
// (netlink and /proc/net/arp), packet sockets both ways, a socket filter,
// and ip_forward.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

// netlink(7), rtnetlink(7). (musl has no <linux/rtnetlink.h>.)
#define NETLINK_ROUTE 0
#define NLMSG_ERROR 2
#define NLMSG_DONE 3
#define RTM_NEWADDR 20
#define RTM_DELADDR 21
#define RTM_GETADDR 22
#define RTM_NEWROUTE 24
#define RTM_DELROUTE 25
#define RTM_GETROUTE 26
#define NLM_F_REQUEST 0x1
#define NLM_F_ACK 0x4
#define NLM_F_EXCL 0x200
#define NLM_F_CREATE 0x400
#define NLM_F_DUMP 0x300
#define RTMGRP_IPV4_IFADDR 0x10
#define RTMGRP_IPV4_ROUTE 0x40
#define IFA_LOCAL 2
#define RTA_DST 1
#define RTA_OIF 4
#define RTA_GATEWAY 5
#define RTA_PRIORITY 6
#define RTM_NEWLINK 16
#define RTM_NEWNEIGH 28
#define RTM_DELNEIGH 29
#define RTM_GETNEIGH 30
#define RTMGRP_NEIGH 0x4
#define NDA_DST 1
#define NDA_LLADDR 2
#define NUD_PERMANENT 0x80
// packet(7), tun ioctls (musl's numbers; the kernel docs' layout).
#define AF_PACKET_ 17
#define ETH_P_ALL_ 0x0003
#define ETH_P_ARP_ 0x0806
#define TUNSETIFF_ 0x400454ca
#define IFF_TAP_ 0x0002
#define IFF_NO_PI_ 0x1000
#define SO_ATTACH_FILTER_ 26

struct sockaddr_ll_ {
    uint16_t family, protocol;
    int ifindex;
    uint16_t hatype;
    uint8_t pkttype, halen, addr[8];
};

struct filter_insn {
    uint16_t code;
    uint8_t jt, jf;
    uint32_t k;
};
struct filter_prog {
    unsigned short len;
    struct filter_insn *insns;
};

static int failures;
static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::rtnl::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

struct nlh {
    uint32_t len;
    uint16_t type, flags;
    uint32_t seq, pid;
};

static int route_socket(unsigned groups) {
    int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    struct sockaddr_nl {
        uint16_t family, pad;
        uint32_t pid, groups;
    } a = {AF_NETLINK, 0, 0, groups};
    bind(s, (struct sockaddr *)&a, sizeof a);
    return s;
}

static unsigned char msg[512];
static int mlen;
static void start(uint16_t type, uint16_t flags, int seq, const void *body, int n) {
    struct nlh h = {0, type, NLM_F_REQUEST | flags, seq, 0};
    memcpy(msg, &h, 16);
    memcpy(msg + 16, body, n);
    mlen = 16 + n;
}
static void attr(uint16_t type, const void *data, int n) {
    uint16_t hdr[2] = {4 + n, type};
    memcpy(msg + mlen, hdr, 4);
    memcpy(msg + mlen + 4, data, n);
    mlen += (4 + n + 3) & ~3;
}
/// Send the message; the error its acknowledgement reports.
static int request(int s) {
    ((struct nlh *)msg)->len = mlen;
    send(s, msg, mlen, 0);
    unsigned char r[1024];
    int n = recv(s, r, sizeof r, 0);
    struct nlh *h = (struct nlh *)r;
    if (n < 20 || h->type != NLMSG_ERROR) return -9999;
    int e;
    memcpy(&e, r + 16, 4);
    return -e;
}

static uint32_t ip(int a, int b, int c, int d) { return htonl((a << 24) | (b << 16) | (c << 8) | d); }

/// An address request on link `index`: struct ifaddrmsg (family, prefix
/// length, flags, scope, index), then IFA_LOCAL.
static void address(uint16_t type, uint16_t flags, int index, uint32_t a, int prefix) {
    unsigned char body[8] = {AF_INET, prefix, 0, 0};
    memcpy(body + 4, &index, 4);
    start(type, flags, 1, body, 8);
    attr(IFA_LOCAL, &a, 4);
}

/// A route request: struct rtmsg (family, dst_len, src_len, tos, table,
/// protocol, scope, type, flags), then its attributes.
static void route(uint16_t type, uint16_t flags, uint32_t dst, int len, uint32_t gw, int oif, uint32_t metric) {
    unsigned char body[12] = {AF_INET, len, 0, 0, 254, 4, 0, 1};
    start(type, flags, 2, body, 12);
    attr(RTA_DST, &dst, 4);
    if (gw) attr(RTA_GATEWAY, &gw, 4);
    attr(RTA_OIF, &oif, 4);
    attr(RTA_PRIORITY, &metric, 4);
}

/// The next notification's type (0: none within the socket's timeout).
static int notified(int mon, unsigned char *buf, int size) {
    int n = recv(mon, buf, size, 0);
    return n >= 16 ? ((struct nlh *)buf)->type : 0;
}

/// Whether a dump of `type` (RTM_GETADDR, RTM_GETROUTE) has a message
/// whose body holds `needle` (4 bytes).
static int dump_has(int s, uint16_t type, uint32_t needle) {
    unsigned char body[12] = {AF_INET};
    start(type, NLM_F_DUMP, 3, body, type == RTM_GETADDR ? 8 : 12);
    ((struct nlh *)msg)->len = mlen;
    send(s, msg, mlen, 0);
    static unsigned char r[16384];
    int n = recv(s, r, sizeof r, 0), found = 0;
    for (int at = 0; at + 16 <= n;) {
        struct nlh *h = (struct nlh *)(r + at);
        if (h->type == NLMSG_DONE || h->len < 16) break;
        for (unsigned i = at + 16; i + 4 <= at + h->len; i++) found |= memcmp(r + i, &needle, 4) == 0;
        at += (h->len + 3) & ~3;
    }
    return found;
}

/// Dump every route of `family` and send each back as it came, as pasta
/// does when it copies a namespace's routes (NLM_F_CREATE | NLM_F_EXCL):
/// each must be added or already exist, never be refused. Returns the
/// number refused, or -1 if the dump had no routes.
static int copy_routes_back(int s, unsigned char family) {
    unsigned char body[12] = {family};
    start(RTM_GETROUTE, NLM_F_DUMP, 4, body, 12);
    ((struct nlh *)msg)->len = mlen;
    send(s, msg, mlen, 0);
    static unsigned char all[65536];
    int total = 0, done = 0;
    while (!done && total < (int)sizeof all - 16384) {
        int n = recv(s, all + total, sizeof all - total, 0);
        if (n <= 0) break;
        for (int at = total; at + 16 <= total + n;) {
            struct nlh *h = (struct nlh *)(all + at);
            if (h->type == NLMSG_DONE || h->len < 16) done = 1;
            if (h->len < 16) break;
            at += (h->len + 3) & ~3;
        }
        total += n;
    }
    int routes = 0, refused = 0;
    for (int at = 0; at + 16 <= total;) {
        struct nlh *h = (struct nlh *)(all + at);
        if (h->type == NLMSG_DONE || h->len < 16 || h->len > sizeof msg) break;
        if (h->type == RTM_NEWROUTE) {
            routes++;
            memcpy(msg, h, h->len);
            mlen = h->len;
            ((struct nlh *)msg)->flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
            ((struct nlh *)msg)->seq = 100 + routes;
            int e = request(s);
            if (e != 0 && e != EEXIST) {
                printf("route %d (table %d, type %d) refused: %d\n", routes, msg[16 + 4], msg[16 + 7], e);
                refused++;
            }
        }
        at += (h->len + 3) & ~3;
    }
    return routes ? refused : -1;
}

int main(void) {
    check("own_namespace", unshare(CLONE_NEWNET) == 0);
    // Its loopback starts down, as on Linux (ADR 0114): up first.
    struct ifreq lo_req;
    memset(&lo_req, 0, sizeof lo_req);
    strcpy(lo_req.ifr_name, "lo");
    int ifs = socket(AF_INET, SOCK_DGRAM, 0);
    lo_req.ifr_flags = IFF_UP;
    check("lo_up", ioctl(ifs, SIOCSIFFLAGS, &lo_req) == 0);
    close(ifs);
    int ctl = route_socket(0), mon = route_socket(RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE);
    struct timeval tv = {0, 300000};
    setsockopt(mon, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    unsigned char buf[1024];
    // Nothing yet: the read waits for the timeout and gives up.
    check("blocking_read_times_out", notified(mon, buf, sizeof buf) == 0 && errno == EAGAIN);

    int lo = 1;
    uint32_t a = ip(10, 9, 0, 1);
    address(RTM_NEWADDR, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, lo, a, 24);
    check("add_address", request(ctl) == 0);
    check("address_notified", notified(mon, buf, sizeof buf) == RTM_NEWADDR);
    check("address_dumped", dump_has(ctl, RTM_GETADDR, a));
    address(RTM_NEWADDR, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, lo, a, 24);
    check("add_twice_exists", request(ctl) == EEXIST);
    address(RTM_NEWADDR, NLM_F_ACK, 77, ip(10, 9, 1, 1), 24);
    check("no_such_link", request(ctl) == ENODEV);

    uint32_t net = ip(10, 10, 0, 0), gw = ip(10, 9, 0, 254);
    route(RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, net, 16, gw, lo, 7);
    check("add_route", request(ctl) == 0);
    check("route_notified", notified(mon, buf, sizeof buf) == RTM_NEWROUTE);
    check("route_dumped", dump_has(ctl, RTM_GETROUTE, net));
    route(RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE, ip(10, 11, 0, 0), 16, ip(192, 0, 2, 1), lo, 0);
    check("gateway_must_be_on_link", request(ctl) == ENETUNREACH);
    route(RTM_DELROUTE, NLM_F_ACK, net, 16, 0, lo, 7);
    check("del_route", request(ctl) == 0 && notified(mon, buf, sizeof buf) == RTM_DELROUTE);
    route(RTM_DELROUTE, NLM_F_ACK, net, 16, 0, lo, 7);
    check("del_route_again", request(ctl) == ESRCH);

    address(RTM_DELADDR, NLM_F_ACK, lo, a, 24);
    check("del_address", request(ctl) == 0 && notified(mon, buf, sizeof buf) == RTM_DELADDR);
    check("address_gone", !dump_has(ctl, RTM_GETADDR, a));

    // SO_BINDTODEVICE: a socket on lo only; an unknown name is refused.
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    check("bind_to_device", setsockopt(u, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3) == 0);
    char name[IFNAMSIZ] = {0};
    socklen_t nlen = sizeof name;
    check("device_read_back", getsockopt(u, SOL_SOCKET, SO_BINDTODEVICE, name, &nlen) == 0 && strcmp(name, "lo") == 0);
    check("unknown_device", setsockopt(u, SOL_SOCKET, SO_BINDTODEVICE, "nosuch0", 8) == -1 && errno == ENODEV);
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(9), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    check("bound_socket_sends", sendto(u, "x", 1, 0, (struct sockaddr *)&to, sizeof to) == 1);

    // A tap: interface 2 of this namespace, brought up, with an address.
    int tun = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    unsigned char ifr[40] = "tap0";
    unsigned short tf = IFF_TAP_ | IFF_NO_PI_;
    memcpy(ifr + 16, &tf, 2);
    check("tap", tun >= 0 && ioctl(tun, TUNSETIFF_, ifr) == 0);
    int tap = 2;
    unsigned char link[16] = {0};
    unsigned up = 1;
    memcpy(link + 4, &tap, 4);
    memcpy(link + 8, &up, 4);
    memcpy(link + 12, &up, 4);
    start(RTM_NEWLINK, NLM_F_ACK, 4, link, 16);
    check("tap_up", request(ctl) == 0);
    address(RTM_NEWADDR, NLM_F_ACK | NLM_F_CREATE, tap, ip(10, 20, 0, 1), 24);
    check("tap_address", request(ctl) == 0);

    // An ARP entry set by hand: notified, dumped, in /proc/net/arp, gone.
    int nmon = route_socket(RTMGRP_NEIGH);
    setsockopt(nmon, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    uint32_t peer = ip(10, 20, 0, 7);
    unsigned char hw[6] = {2, 0, 0, 0, 0x20, 7};
    unsigned char nd[12] = {AF_INET};
    uint16_t state = NUD_PERMANENT;
    memcpy(nd + 4, &tap, 4);
    memcpy(nd + 8, &state, 2);
    start(RTM_NEWNEIGH, NLM_F_ACK | NLM_F_CREATE, 5, nd, 12);
    attr(NDA_DST, &peer, 4);
    attr(NDA_LLADDR, hw, 6);
    check("neigh_add", request(ctl) == 0);
    check("neigh_notified", notified(nmon, buf, sizeof buf) == RTM_NEWNEIGH);
    check("neigh_dumped", dump_has(ctl, RTM_GETNEIGH, peer));
    char line[256] = {0};
    FILE *arp = fopen("/proc/net/arp", "r");
    int listed = 0;
    while (arp && fgets(line, sizeof line, arp))
        listed |= strstr(line, "10.20.0.7") && strstr(line, "02:00:00:00:20:07") && strstr(line, "0x6") &&
                  strstr(line, "tap0");
    if (arp) fclose(arp);
    check("proc_net_arp", listed);

    // Packet sockets: a raw one for everything on the tap, a cooked ARP one.
    int all = socket(AF_PACKET_, SOCK_RAW, htons(ETH_P_ALL_));
    struct sockaddr_ll_ sll = {.family = AF_PACKET_, .protocol = htons(ETH_P_ALL_), .ifindex = tap};
    check("packet_bind", all >= 0 && bind(all, (struct sockaddr *)&sll, sizeof sll) == 0);
    setsockopt(all, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    // A datagram to the neighbour set by hand goes straight out (no ARP):
    // the raw socket sees it leave, and the tap's reader gets it.
    int u2 = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in to_peer = {.sin_family = AF_INET, .sin_port = htons(9), .sin_addr.s_addr = peer};
    sendto(u2, "hi", 2, 0, (struct sockaddr *)&to_peer, sizeof to_peer);
    struct sockaddr_ll_ from;
    socklen_t flen = sizeof from;
    int n = recvfrom(all, buf, sizeof buf, 0, (struct sockaddr *)&from, &flen);
    check("packet_sees_outgoing", n >= 42 && from.pkttype == 4 && from.ifindex == tap && memcmp(buf, hw, 6) == 0);
    unsigned char frame[1600];
    check("tap_reads_it", read(tun, frame, sizeof frame) >= 42 && memcmp(frame, hw, 6) == 0);
    // A frame written to the tap comes in: the raw socket sees all of it,
    // the cooked ARP socket the payload of an ARP frame only.
    int arpsock = socket(AF_PACKET_, SOCK_DGRAM, htons(ETH_P_ARP_));
    setsockopt(arpsock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    unsigned char in[60] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0, 0x20, 7, 0x08, 0x06};
    write(tun, in, sizeof in);
    flen = sizeof from;
    n = recvfrom(arpsock, buf, sizeof buf, 0, (struct sockaddr *)&from, &flen);
    check("cooked_in", n == 46 && from.pkttype == 1 && ntohs(from.protocol) == ETH_P_ARP_ && from.addr[5] == 7);
    check("raw_in", recv(all, buf, sizeof buf, 0) == 60 && buf[12] == 0x08 && buf[13] == 0x06);
    // A filter that keeps nothing (BPF_RET 0).
    struct filter_insn drop = {0x06, 0, 0, 0};
    struct filter_prog prog = {1, &drop};
    check("filter_attach", setsockopt(arpsock, SOL_SOCKET, SO_ATTACH_FILTER_, &prog, sizeof prog) == 0);
    write(tun, in, sizeof in);
    check("filter_drops", recv(arpsock, buf, sizeof buf, 0) == -1 && errno == EAGAIN);
    // Sending a cooked frame to an address: out of the tap.
    struct sockaddr_ll_ dst = {AF_PACKET_, htons(0x88B5), tap, 1, 0, 6, {2, 0, 0, 0, 0x20, 7}};
    int raw = socket(AF_PACKET_, SOCK_DGRAM, 0);
    while (read(tun, frame, sizeof frame) > 0) {
    }
    check("packet_send", sendto(raw, "payload", 7, 0, (struct sockaddr *)&dst, sizeof dst) == 7 &&
                             read(tun, frame, sizeof frame) == 60 && frame[12] == 0x88 && frame[13] == 0xB5 &&
                             memcmp(frame + 14, "payload", 7) == 0);
    check("packet_needs_card", send(raw, "x", 1, 0) == -1 && errno == ENXIO);

    start(RTM_DELNEIGH, NLM_F_ACK, 6, nd, 12);
    attr(NDA_DST, &peer, 4);
    check("neigh_del", request(ctl) == 0 && notified(nmon, buf, sizeof buf) == RTM_DELNEIGH);
    start(RTM_DELNEIGH, NLM_F_ACK, 7, nd, 12);
    attr(NDA_DST, &peer, 4);
    check("neigh_del_again", request(ctl) == ENOENT);

    // IPv6 on the tap: a 3000-byte datagram to a neighbour set by hand
    // leaves in fragments (next header 44) that fit the tap's 1280-byte MTU.
    unsigned char mtu_link[16] = {0};
    memcpy(mtu_link + 4, &tap, 4);
    start(RTM_NEWLINK, NLM_F_ACK, 8, mtu_link, 16);
    uint32_t mtu = 1280;
    attr(4, &mtu, 4); // IFLA_MTU
    check("tap_mtu", request(ctl) == 0);
    unsigned char a6[16] = {0x20, 0x01, 0x0d, 0xb8, [15] = 1}, p6[16] = {0x20, 0x01, 0x0d, 0xb8, [15] = 2};
    unsigned char am[8] = {10, 64, 0, 0};
    memcpy(am + 4, &tap, 4);
    start(RTM_NEWADDR, NLM_F_ACK | NLM_F_CREATE, 9, am, 8);
    attr(IFA_LOCAL, a6, 16);
    check("addr6_add", request(ctl) == 0);
    unsigned char nd6[12] = {10};
    memcpy(nd6 + 4, &tap, 4);
    memcpy(nd6 + 8, &state, 2);
    start(RTM_NEWNEIGH, NLM_F_ACK | NLM_F_CREATE, 10, nd6, 12);
    attr(NDA_DST, p6, 16);
    attr(NDA_LLADDR, hw, 6);
    check("neigh6_add", request(ctl) == 0);
    usleep(1200000); // Past duplicate address detection.
    while (read(tun, frame, sizeof frame) > 0) {
    }
    int u6 = socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_in6 to6 = {.sin6_family = AF_INET6, .sin6_port = htons(9)};
    memcpy(&to6.sin6_addr, p6, 16);
    static char big6[3000];
    int sent6 = sendto(u6, big6, sizeof big6, 0, (struct sockaddr *)&to6, sizeof to6);
    int frags = 0, fits = 1;
    for (int i = 0; i < 10; i++) {
        n = read(tun, frame, sizeof frame);
        if (n <= 0) break;
        if (frame[12] == 0x86 && frame[13] == 0xdd && frame[14 + 6] == 44) {
            frags++;
            fits &= n - 14 <= 1280;
        }
    }
    check("ipv6_fragments_out", sent6 == 3000 && frags == 3 && fits);

    // ip_forward reads back what was written.
    FILE *fw = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    if (fw) {
        fputs("1\n", fw);
        fclose(fw);
    }
    char v[8] = {0};
    fw = fopen("/proc/sys/net/ipv4/ip_forward", "r");
    if (fw) {
        fgets(v, sizeof v, fw);
        fclose(fw);
    }
    check("ip_forward", strcmp(v, "1\n") == 0);

    // Every route a dump shows, the kernel's local ones included, can be
    // sent back (pasta copies routes this way).
    int ctl2 = route_socket(0);
    check("routes_copy_back", copy_routes_back(ctl2, AF_INET) == 0);
    check("routes6_copy_back", copy_routes_back(ctl2, AF_INET6) == 0);
    // A local route for an address the namespace does not have (pasta
    // copies the host's into a container): kept and listed.
    for (int six = 0; six < 2; six++) {
        unsigned char a6[16] = {0xfe, 0x80, [14] = 0x12, [15] = 0x34};
        uint32_t a4 = ip(192, 0, 2, 77);
        int lo_index = 1;
        unsigned char body[12] = {six ? AF_INET6 : AF_INET, six ? 128 : 32, 0, 0, 255, 3, 254, 2};
        int r[4];
        for (int step = 0; step < 4; step++) {
            uint16_t type = step < 2 ? RTM_NEWROUTE : RTM_DELROUTE;
            start(type, NLM_F_ACK | (step < 2 ? NLM_F_CREATE | NLM_F_EXCL : 0), 50 + step, body, 12);
            if (six) attr(RTA_DST, a6, 16); else attr(RTA_DST, &a4, 4);
            attr(RTA_OIF, &lo_index, 4);
            r[step] = request(ctl2);
            if (step == 0 && !six) check("local_route_listed", dump_has(ctl2, RTM_GETROUTE, a4));
        }
        check(six ? "local_route6_foreign" : "local_route_foreign",
              r[0] == 0 && r[1] == EEXIST && r[2] == 0 && r[3] == ESRCH);
    }
    return failures;
}
