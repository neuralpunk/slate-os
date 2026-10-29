// SPDX-License-Identifier: MIT OR Apache-2.0
// Interfaces between network namespaces (ADR 0131), made over route
// netlink as `ip link` makes them: a veth pair with its peer in another
// namespace, datagrams both ways; a bridge with two ports whose other
// ends are in two namespaces, the two talking through it and to the
// bridge's own address; forwarding from one namespace to another through
// the first; a rename (refused while up); kinds and masters reported;
// deleting one veth end takes the other; a namespace that ends takes its
// veth ends, and their peers, with it.
// The test works from its own namespace (A) and two children's (B, C),
// making sockets in theirs by setns(2) into them and back.
// Then NAT in A (ADR 0132): what leaves by the veth toward B is
// masqueraded, and UDP to A's port 8080 goes to B; the answers come back
// translated. nf_tables' numbers from linux/netfilter/nf_tables.h,
// nfnetlink.h and nf_nat.h (ADR 0128).
// Then the namespace's per-interface settings under /proc/sys/net/*/conf
// and taps: one with packet information, one kept after its file closes.
// Numbers from rtnetlink(7) and linux/if_link.h, linux/veth.h (ADR 0131);
// tun ioctls as tests/user/rtnl.c has them.
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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define NETLINK_ROUTE 0
#define NLMSG_ERROR 2
#define RTM_NEWLINK 16
#define RTM_DELLINK 17
#define RTM_GETLINK 18
#define RTM_NEWADDR 20
#define RTM_NEWROUTE 24
#define NLM_F_REQUEST 0x1
#define NLM_F_ACK 0x4
#define NLM_F_EXCL 0x200
#define NLM_F_CREATE 0x400
#define IFLA_IFNAME 3
#define IFLA_LINK 5
#define IFLA_MASTER 10
#define IFLA_LINKINFO 18
#define IFLA_NET_NS_FD 28
#define IFLA_INFO_KIND 1
#define IFLA_INFO_DATA 2
#define VETH_INFO_PEER 1
#define IFA_LOCAL 2
#define RTA_DST 1
#define RTA_GATEWAY 5
#define NLA_F_NESTED 0x8000
#define NLM_F_APPEND 0x800

static int failures;
static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::links::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

struct nlh {
    uint32_t len;
    uint16_t type, flags;
    uint32_t seq, pid;
};

/// A request being built: a header, a body, attributes and nests.
static unsigned char msg[1024];
static int mlen, nests[4], depth;

static void start(uint16_t type, uint16_t flags, const void *body, int n) {
    struct nlh h = {0, type, NLM_F_REQUEST | NLM_F_ACK | flags, 1, 0};
    memcpy(msg, &h, 16);
    memcpy(msg + 16, body, n);
    mlen = 16 + n;
    depth = 0;
}
static void attr(uint16_t type, const void *data, int n) {
    uint16_t hdr[2] = {4 + n, type};
    memcpy(msg + mlen, hdr, 4);
    memcpy(msg + mlen + 4, data, n);
    mlen += 4 + n;
    while (mlen % 4) msg[mlen++] = 0;
}
static void str(uint16_t type, const char *s) { attr(type, s, strlen(s) + 1); }
static void u32(uint16_t type, uint32_t v) { attr(type, &v, 4); }
static void nest(uint16_t type) {
    nests[depth++] = mlen;
    uint16_t hdr[2] = {4, type | NLA_F_NESTED};
    memcpy(msg + mlen, hdr, 4);
    mlen += 4;
}
static void end(void) {
    int at = nests[--depth];
    uint16_t n = mlen - at;
    memcpy(msg + at, &n, 2);
}

/// Send the request on `s`: the error its acknowledgement reports (0 for
/// success).
static int request(int s) {
    ((struct nlh *)msg)->len = mlen;
    send(s, msg, mlen, 0);
    unsigned char r[1024];
    for (;;) {
        int n = recv(s, r, sizeof r, 0);
        struct nlh *h = (struct nlh *)r;
        if (n < 20) return -9999;
        if (h->type != NLMSG_ERROR) continue;
        int e;
        memcpy(&e, r + 16, 4);
        return -e;
    }
}

/// struct ifinfomsg: family, pad, type, index, flags, change.
static void ifinfo(unsigned char b[16], int index, unsigned flags, unsigned change) {
    memset(b, 0, 16);
    memcpy(b + 4, &index, 4);
    memcpy(b + 8, &flags, 4);
    memcpy(b + 12, &change, 4);
}

/// `ip link add A type veth peer name B netns FD` (FD < 0: here).
static int add_veth(int s, const char *a, const char *b, int fd) {
    unsigned char body[16], peer[16];
    ifinfo(body, 0, 0, 0);
    start(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, body, 16);
    str(IFLA_IFNAME, a);
    nest(IFLA_LINKINFO);
    str(IFLA_INFO_KIND, "veth");
    nest(IFLA_INFO_DATA);
    nest(VETH_INFO_PEER);
    ifinfo(peer, 0, 0, 0);
    memcpy(msg + mlen, peer, 16);
    mlen += 16;
    str(IFLA_IFNAME, b);
    if (fd >= 0) u32(IFLA_NET_NS_FD, fd);
    end();
    end();
    end();
    return request(s);
}

static int add_bridge(int s, const char *name) {
    unsigned char body[16];
    ifinfo(body, 0, 0, 0);
    start(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, body, 16);
    str(IFLA_IFNAME, name);
    nest(IFLA_LINKINFO);
    str(IFLA_INFO_KIND, "bridge");
    end();
    return request(s);
}

/// `ip link set NAME up|down [master M]`.
static int set_link(int s, int index, int up, int master) {
    unsigned char body[16];
    ifinfo(body, index, up ? IFF_UP : 0, IFF_UP);
    start(RTM_NEWLINK, 0, body, 16);
    if (master >= 0) u32(IFLA_MASTER, master);
    return request(s);
}

static int rename_link(int s, int index, const char *name) {
    unsigned char body[16];
    ifinfo(body, index, 0, 0);
    start(RTM_NEWLINK, 0, body, 16);
    str(IFLA_IFNAME, name);
    return request(s);
}

static int del_link(int s, const char *name) {
    unsigned char body[16];
    ifinfo(body, 0, 0, 0);
    start(RTM_DELLINK, 0, body, 16);
    str(IFLA_IFNAME, name);
    return request(s);
}

static uint32_t ip(int a, int b, int c, int d) { return htonl((a << 24) | (b << 16) | (c << 8) | d); }

static int add_addr(int s, int index, uint32_t a, int prefix) {
    unsigned char body[8] = {AF_INET, prefix, 0, 0};
    memcpy(body + 4, &index, 4);
    start(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, body, 8);
    attr(IFA_LOCAL, &a, 4);
    return request(s);
}

/// `ip route add DST/LEN via GW`.
static int add_route(int s, uint32_t dst, int len, uint32_t gw) {
    // struct rtmsg: family, dst_len, src_len, tos, table (main), protocol
    // (static), scope (universe), type (unicast), flags.
    unsigned char body[12] = {AF_INET, len, 0, 0, 254, 4, 0, 1};
    start(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, body, 12);
    attr(RTA_DST, &dst, 4);
    attr(RTA_GATEWAY, &gw, 4);
    return request(s);
}

/// What RTM_GETLINK says of NAME: its kind, master and veth peer (or -1
/// if it isn't there).
static int get_link(int s, const char *name, char kind[16], int *master, int *peer) {
    unsigned char body[16];
    ifinfo(body, 0, 0, 0);
    start(RTM_GETLINK, 0, body, 16);
    ((struct nlh *)msg)->flags = NLM_F_REQUEST;
    str(IFLA_IFNAME, name);
    ((struct nlh *)msg)->len = mlen;
    send(s, msg, mlen, 0);
    unsigned char r[2048];
    int n = recv(s, r, sizeof r, 0);
    struct nlh *h = (struct nlh *)r;
    if (n < 32 || h->type != RTM_NEWLINK) return -1;
    kind[0] = 0;
    *master = *peer = 0;
    int at = 32;
    while (at + 4 <= (int)h->len) {
        uint16_t alen, atype;
        memcpy(&alen, r + at, 2);
        memcpy(&atype, r + at + 2, 2);
        atype &= 0x3FFF;
        if (alen < 4) break;
        if (atype == IFLA_MASTER) memcpy(master, r + at + 4, 4);
        if (atype == IFLA_LINK) memcpy(peer, r + at + 4, 4);
        if (atype == IFLA_LINKINFO && alen >= 8) {
            uint16_t klen, ktype;
            memcpy(&klen, r + at + 4, 2);
            memcpy(&ktype, r + at + 6, 2);
            if ((ktype & 0x3FFF) == IFLA_INFO_KIND && klen > 4 && klen - 4 < 16) {
                memcpy(kind, r + at + 8, klen - 4);
                kind[klen - 4] = 0;
            }
        }
        at += (alen + 3) & ~3;
    }
    return 0;
}

static int route_socket(void) { return socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE); }

/// The namespaces' files: the test's own, then the children's.
static int ns_a, ns_b, ns_c;
static void enter(int fd) { setns(fd, CLONE_NEWNET); }

/// A child that sits in a network namespace of its own until killed.
static pid_t child(int *fd) {
    int p[2];
    pipe(p);
    pid_t pid = fork();
    if (pid == 0) {
        char c = unshare(CLONE_NEWNET) == 0 ? 'y' : 'n';
        write(p[1], &c, 1);
        for (;;) pause();
    }
    char c = 0;
    read(p[0], &c, 1);
    close(p[0]);
    close(p[1]);
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/ns/net", pid);
    *fd = c == 'y' ? open(path, O_RDONLY) : -1;
    return pid;
}

/// A UDP socket bound to ADDR:PORT, made in namespace `ns`.
static int udp_in(int ns, uint32_t addr, int port) {
    enter(ns);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr = {addr}};
    bind(s, (struct sockaddr *)&a, sizeof a);
    enter(ns_a);
    return s;
}

/// Send TEXT from `from` to ADDR:PORT; whether `to` receives it in 2 s.
static int datagram(int from, int to, uint32_t addr, int port, const char *text) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr = {addr}};
    if (sendto(from, text, strlen(text), 0, (struct sockaddr *)&a, sizeof a) < 0) return 0;
    struct pollfd p = {to, POLLIN, 0};
    if (poll(&p, 1, 2000) != 1) return 0;
    char buf[64] = {0};
    int n = recv(to, buf, sizeof buf - 1, 0);
    return n == (int)strlen(text) && memcmp(buf, text, n) == 0;
}

// --- nf_tables batches -----------------------------------------------------

static unsigned char nb_buf[2048];
static size_t nb_len, nb_msg, nb_nests[8];
static int nb_depth;
static uint32_t nb_seq;

static void nb_put(const void *p, size_t n) {
    memcpy(nb_buf + nb_len, p, n);
    nb_len += n;
    while (nb_len % 4) nb_buf[nb_len++] = 0;
}
/// A message: a netlink header, then struct nfgenmsg (family, version,
/// resource id: the subsystem for batch markers).
static void nb_start(uint16_t type, uint16_t flags, uint8_t family, uint16_t res) {
    nb_msg = nb_len;
    uint32_t hdr[4] = {0, type | (uint32_t)(flags | NLM_F_REQUEST) << 16, ++nb_seq, 0};
    nb_put(hdr, 16);
    unsigned char g[4] = {family, 0, res >> 8, res & 0xff};
    nb_put(g, 4);
}
static void nb_end(void) {
    uint32_t n = nb_len - nb_msg;
    memcpy(nb_buf + nb_msg, &n, 4);
}
static void nb_attr(uint16_t type, const void *v, uint16_t n) {
    uint16_t h[2] = {4 + n, type};
    memcpy(nb_buf + nb_len, h, 4);
    memcpy(nb_buf + nb_len + 4, v, n);
    nb_len += 4 + n;
    while (nb_len % 4) nb_buf[nb_len++] = 0;
}
static void nb_str(uint16_t type, const char *s) { nb_attr(type, s, strlen(s) + 1); }
static void nb_be32(uint16_t type, uint32_t v) {
    uint32_t b = htonl(v);
    nb_attr(type, &b, 4);
}
static void nb_nest(uint16_t type) {
    nb_nests[nb_depth++] = nb_len;
    uint16_t h[2] = {4, type | NLA_F_NESTED};
    memcpy(nb_buf + nb_len, h, 4);
    nb_len += 4;
}
static void nb_close(void) {
    size_t at = nb_nests[--nb_depth];
    uint16_t n = nb_len - at;
    memcpy(nb_buf + at, &n, 2);
}
/// An expression: NFTA_LIST_ELEM { NFTA_EXPR_NAME, NFTA_EXPR_DATA { ... } };
/// the caller fills the data and closes both.
static void nb_expr(const char *name) {
    nb_nest(1);
    nb_str(1, name);
    nb_nest(2);
}
/// A value in a NFTA_DATA_VALUE nest.
static void nb_value(uint16_t type, const void *v, uint16_t n) {
    nb_nest(type);
    nb_attr(1, v, n);
    nb_close();
}

#define SUBSYS_NFTABLES 10
#define NFT(m) ((SUBSYS_NFTABLES << 8) | (m))
#define NFPROTO_IPV4 2

/// A nat base chain of table "nat": `type nat hook HOOK priority PRIO`.
static void nb_chain(const char *name, uint32_t hook, int32_t prio) {
    nb_start(NFT(3), NLM_F_CREATE | NLM_F_ACK, NFPROTO_IPV4, 0);
    nb_str(1, "nat"), nb_str(3, name);
    nb_nest(4);
    nb_be32(1, hook), nb_be32(2, (uint32_t)prio);
    nb_close();
    nb_be32(5, 1), nb_str(7, "nat");
    nb_end();
}

/// Send the batch on `s`; the first error its acknowledgements report.
static int nb_send(int s, int acks) {
    send(s, nb_buf, nb_len, 0);
    nb_len = 0;
    int err = 0;
    while (acks > 0) {
        struct pollfd p = {s, POLLIN, 0};
        if (poll(&p, 1, 2000) != 1) return -1;
        unsigned char r[4096];
        int n = recv(s, r, sizeof r, 0);
        for (int at = 0; at + 16 <= n;) {
            struct nlh *h = (struct nlh *)(r + at);
            if (h->type == NLMSG_ERROR) {
                int e;
                memcpy(&e, r + at + 16, 4);
                if (e && !err) err = -e;
                acks--;
            }
            if (h->len < 16) break;
            at += (h->len + 3) & ~3;
        }
    }
    return err;
}

/// table ip nat; chain post (postrouting, srcnat): `oif OUT masquerade`;
/// chain pre (prerouting, dstnat): `udp dport 8080 dnat to TO:7000`.
static int nat_rules(int s, int out, uint32_t to) {
    nb_start(16, 0, 0, SUBSYS_NFTABLES); // NFNL_MSG_BATCH_BEGIN
    nb_end();
    nb_start(NFT(0), NLM_F_CREATE | NLM_F_ACK, NFPROTO_IPV4, 0);
    nb_str(1, "nat");
    nb_end();
    nb_chain("post", 4, 100);
    nb_chain("pre", 0, -100);
    // oif OUT masquerade: meta oif (key 5) to register 1, cmp eq, masq.
    nb_start(NFT(6), NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK, NFPROTO_IPV4, 0);
    nb_str(1, "nat"), nb_str(2, "post");
    nb_nest(4);
    nb_expr("meta"), nb_be32(2, 5), nb_be32(1, 1), nb_close(), nb_close();
    nb_expr("cmp"), nb_be32(1, 1), nb_be32(2, 0), nb_value(3, &out, 4), nb_close(), nb_close();
    nb_expr("masq"), nb_close(), nb_close();
    nb_close();
    nb_end();
    // udp dport 8080 dnat to TO:7000: meta l4proto, cmp 17, payload
    // (transport header, offset 2, 2 bytes), cmp 8080, the address to
    // register 1 and the port to register 2, nat (dnat, ipv4, registers 1
    // and 2, flags: proto given).
    nb_start(NFT(6), NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK, NFPROTO_IPV4, 0);
    nb_str(1, "nat"), nb_str(2, "pre");
    nb_nest(4);
    unsigned char udp = 17;
    uint16_t port = htons(8080), dport = htons(7000);
    nb_expr("meta"), nb_be32(2, 16), nb_be32(1, 1), nb_close(), nb_close();
    nb_expr("cmp"), nb_be32(1, 1), nb_be32(2, 0), nb_value(3, &udp, 1), nb_close(), nb_close();
    nb_expr("payload"), nb_be32(1, 1), nb_be32(2, 2), nb_be32(3, 2), nb_be32(4, 2), nb_close(), nb_close();
    nb_expr("cmp"), nb_be32(1, 1), nb_be32(2, 0), nb_value(3, &port, 2), nb_close(), nb_close();
    nb_expr("immediate"), nb_be32(1, 1), nb_value(2, &to, 4), nb_close(), nb_close();
    nb_expr("immediate"), nb_be32(1, 2), nb_value(2, &dport, 2), nb_close(), nb_close();
    nb_expr("nat"), nb_be32(1, 1), nb_be32(2, NFPROTO_IPV4), nb_be32(3, 1), nb_be32(5, 2), nb_be32(7, 2);
    nb_close(), nb_close();
    nb_close();
    nb_end();
    nb_start(17, 0, 0, SUBSYS_NFTABLES); // NFNL_MSG_BATCH_END
    nb_end();
    return nb_send(s, 5);
}

/// What `to` receives in 2 s from `from`'s datagram: whether it came, and
/// from where.
static int datagram_from(int from, int to, uint32_t addr, int port, struct sockaddr_in *seen) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr = {addr}};
    if (sendto(from, "nat", 3, 0, (struct sockaddr *)&a, sizeof a) < 0) return 0;
    struct pollfd p = {to, POLLIN, 0};
    if (poll(&p, 1, 2000) != 1) return 0;
    char buf[16];
    socklen_t l = sizeof *seen;
    return recvfrom(to, buf, sizeof buf, 0, (struct sockaddr *)seen, &l) == 3;
}

/// A /proc file's first line (empty if it can't be read).
static void read_line(const char *path, char *out, size_t n) {
    out[0] = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return;
    ssize_t r = read(fd, out, n - 1);
    close(fd);
    out[r > 0 ? r : 0] = 0;
    char *nl = strchr(out, '\n');
    if (nl) *nl = 0;
}

static int write_value(const char *path, const char *v) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    int ok = write(fd, v, strlen(v)) == (ssize_t)strlen(v);
    close(fd);
    return ok ? 0 : -1;
}

#define TUNSETIFF_ 0x400454ca
#define TUNGETIFF_ 0x800454d2
#define TUNSETPERSIST_ 0x400454cb
#define IFF_TAP_ 0x0002
#define IFF_NO_PI_ 0x1000

/// A tap called NAME (FLAGS: IFF_TAP and maybe IFF_NO_PI); its file.
static int tap_open(const char *name, short flags) {
    int fd = open("/dev/net/tun", O_RDWR);
    unsigned char ifr[40] = {0};
    strncpy((char *)ifr, name, 15);
    memcpy(ifr + 16, &flags, 2);
    if (fd < 0 || ioctl(fd, TUNSETIFF_, ifr) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
}

/// The index of NAME in namespace `ns`.
static int index_in(int ns, const char *name) {
    enter(ns);
    int i = if_nametoindex(name);
    enter(ns_a);
    return i;
}

int main(void) {
    if (unshare(CLONE_NEWNET) != 0) {
        check("unshare", 0);
        return 1;
    }
    ns_a = open("/proc/self/ns/net", O_RDONLY);
    pid_t pb = child(&ns_b), pc = child(&ns_c);
    check("namespaces", ns_a >= 0 && ns_b >= 0 && ns_c >= 0);
    int na = route_socket();
    enter(ns_b);
    int nb = route_socket();
    enter(ns_c);
    int nc = route_socket();
    enter(ns_a);

    // A veth pair, its peer in B.
    check("veth_add", add_veth(na, "va", "vb", ns_b) == 0);
    check("veth_exists", add_veth(na, "va", "vx", -1) == EEXIST);
    char kind[16];
    int master, peer;
    int va = if_nametoindex("va"), vb = index_in(ns_b, "vb");
    check("veth_places", va > 1 && vb > 1 && if_nametoindex("vb") == 0);
    check("veth_kind", get_link(na, "va", kind, &master, &peer) == 0 && strcmp(kind, "veth") == 0 && peer == vb);
    check("veth_peer_kind", get_link(nb, "vb", kind, &master, &peer) == 0 && strcmp(kind, "veth") == 0 && peer == va);
    check("lo_up", set_link(na, 1, 1, -1) == 0 && set_link(nb, 1, 1, -1) == 0 && set_link(nc, 1, 1, -1) == 0);
    check("rename", rename_link(nb, vb, "eth0") == 0 && index_in(ns_b, "eth0") == vb);
    check("veth_up", set_link(na, va, 1, -1) == 0 && set_link(nb, vb, 1, -1) == 0);
    check("rename_up_busy", rename_link(nb, vb, "eth1") == EBUSY);
    check("veth_addrs", add_addr(na, va, ip(10, 9, 0, 1), 24) == 0 && add_addr(nb, vb, ip(10, 9, 0, 2), 24) == 0);
    int ua = udp_in(ns_a, ip(10, 9, 0, 1), 7000), ub = udp_in(ns_b, ip(10, 9, 0, 2), 7000);
    check("veth_a_to_b", datagram(ua, ub, ip(10, 9, 0, 2), 7000, "over the veth"));
    check("veth_b_to_a", datagram(ub, ua, ip(10, 9, 0, 1), 7000, "and back"));

    // A bridge in A, a port toward B and one toward C.
    check("bridge_add", add_bridge(na, "br0") == 0);
    int br = if_nametoindex("br0");
    check("bridge_kind", get_link(na, "br0", kind, &master, &peer) == 0 && strcmp(kind, "bridge") == 0);
    check("ports_add", add_veth(na, "pb", "qb", ns_b) == 0 && add_veth(na, "pc", "qc", ns_c) == 0);
    int pbi = if_nametoindex("pb"), pci = if_nametoindex("pc");
    int qb = index_in(ns_b, "qb"), qc = index_in(ns_c, "qc");
    check("enslave", set_link(na, pbi, 1, br) == 0 && set_link(na, pci, 1, br) == 0 && set_link(na, br, 1, -1) == 0);
    check("master_shown", get_link(na, "pb", kind, &master, &peer) == 0 && master == br);
    check("not_a_bridge", set_link(na, pbi, 1, va) == EOPNOTSUPP);
    check("bridge_addrs", add_addr(na, br, ip(10, 9, 1, 1), 24) == 0 && set_link(nb, qb, 1, -1) == 0 &&
                              add_addr(nb, qb, ip(10, 9, 1, 2), 24) == 0 && set_link(nc, qc, 1, -1) == 0 &&
                              add_addr(nc, qc, ip(10, 9, 1, 3), 24) == 0);
    int ub1 = udp_in(ns_b, ip(10, 9, 1, 2), 7001), uc1 = udp_in(ns_c, ip(10, 9, 1, 3), 7001);
    int ubr = udp_in(ns_a, ip(10, 9, 1, 1), 7001);
    check("bridge_b_to_c", datagram(ub1, uc1, ip(10, 9, 1, 3), 7001, "across the bridge"));
    check("bridge_c_to_b", datagram(uc1, ub1, ip(10, 9, 1, 2), 7001, "learned"));
    check("bridge_to_self", datagram(uc1, ubr, ip(10, 9, 1, 1), 7001, "to the bridge"));
    check("bridge_from_self", datagram(ubr, ub1, ip(10, 9, 1, 2), 7001, "from the bridge"));

    // Forwarding through A: C (10.9.1.3, on the bridge only) to B's veth
    // end (10.9.0.2).
    int f = open("/proc/sys/net/ipv4/ip_forward", O_WRONLY);
    check("forwarding_on", f >= 0 && write(f, "1\n", 2) == 2);
    close(f);
    check("route", add_route(nc, ip(10, 9, 0, 0), 24, ip(10, 9, 1, 1)) == 0);
    int uc2 = udp_in(ns_c, ip(10, 9, 1, 3), 7002);
    check("forwarded", datagram(uc2, ub, ip(10, 9, 0, 2), 7000, "routed through A"));

    // NAT in A. C's datagram to B leaves A by the veth from A's address
    // there; B's answer to that comes back to C. C's datagram to A's port
    // 8080 on the bridge goes to B (masqueraded too, leaving by the veth),
    // whose answer reaches C from A:8080.
    int nf = socket(AF_NETLINK, SOCK_RAW, 12);
    check("nat_rules", nf >= 0 && nat_rules(nf, va, ip(10, 9, 0, 2)) == 0);
    int uc3 = udp_in(ns_c, ip(10, 9, 1, 3), 7003), uc4 = udp_in(ns_c, ip(10, 9, 1, 3), 7004);
    struct sockaddr_in seen = {0};
    check("masqueraded", datagram_from(uc3, ub, ip(10, 9, 0, 2), 7000, &seen) &&
                             seen.sin_addr.s_addr == ip(10, 9, 0, 1) && seen.sin_port == htons(7003));
    check("masquerade_answer", datagram_from(ub, uc3, seen.sin_addr.s_addr, ntohs(seen.sin_port), &seen) &&
                                   seen.sin_addr.s_addr == ip(10, 9, 0, 2) && seen.sin_port == htons(7000));
    check("dnat", datagram_from(uc4, ub, ip(10, 9, 1, 1), 8080, &seen) && seen.sin_addr.s_addr == ip(10, 9, 0, 1));
    check("dnat_answer", datagram_from(ub, uc4, seen.sin_addr.s_addr, ntohs(seen.sin_port), &seen) &&
                             seen.sin_addr.s_addr == ip(10, 9, 1, 1) && seen.sin_port == htons(8080));
    close(nf);
    close(uc3);
    close(uc4);

    // Per-interface settings: va's directory with Linux's defaults; a value
    // written reads back; `default` is what a new interface starts with;
    // IPv4's all/forwarding is ip_forward.
    char v[32];
    read_line("/proc/sys/net/ipv4/conf/va/rp_filter", v, sizeof v);
    check("conf_default_value", strcmp(v, "0") == 0);
    check("conf_written", write_value("/proc/sys/net/ipv4/conf/va/route_localnet", "1") == 0 &&
                              (read_line("/proc/sys/net/ipv4/conf/va/route_localnet", v, sizeof v), strcmp(v, "1") == 0));
    read_line("/proc/sys/net/ipv4/conf/all/forwarding", v, sizeof v);
    check("conf_all_forwarding", strcmp(v, "1") == 0);
    check("conf_default_inherited", write_value("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1") == 0 &&
                                         add_bridge(na, "br1") == 0 &&
                                         (read_line("/proc/sys/net/ipv6/conf/br1/disable_ipv6", v, sizeof v),
                                          strcmp(v, "1") == 0));
    check("conf_missing", open("/proc/sys/net/ipv4/conf/nowhere/rp_filter", O_RDONLY) < 0 && errno == ENOENT);

    // A tap with packet information: what it reads starts with struct
    // tun_pi (flags, then the ethertype: ARP's, asking for a neighbour).
    int pt = tap_open("pt0", IFF_TAP_);
    int pti = if_nametoindex("pt0");
    check("tap_pi", pt >= 0 && pti > 0 && set_link(na, pti, 1, -1) == 0 && add_addr(na, pti, ip(10, 9, 5, 1), 24) == 0);
    int up = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in far = {.sin_family = AF_INET, .sin_port = htons(9), .sin_addr = {ip(10, 9, 5, 2)}};
    sendto(up, "x", 1, 0, (struct sockaddr *)&far, sizeof far);
    unsigned char frame[2048];
    struct pollfd pf = {pt, POLLIN, 0};
    int got = poll(&pf, 1, 2000) == 1 ? read(pt, frame, sizeof frame) : -1;
    check("tap_pi_header", got > 18 && frame[0] == 0 && frame[1] == 0 && frame[2] == 0x08 && frame[3] == 0x06 &&
                               frame[4 + 12] == 0x08 && frame[4 + 13] == 0x06);
    close(up);
    close(pt);
    check("tap_gone_on_close", if_nametoindex("pt0") == 0);
    // A persistent tap stays, is taken up again by name, and `ip link del`
    // removes it.
    int pp = tap_open("pp0", IFF_TAP_ | IFF_NO_PI_);
    int ppi = if_nametoindex("pp0");
    check("persist", pp >= 0 && ioctl(pp, TUNSETPERSIST_, 1) == 0);
    close(pp);
    check("persist_kept", ppi > 0 && if_nametoindex("pp0") == (unsigned)ppi);
    pp = tap_open("pp0", IFF_TAP_ | IFF_NO_PI_);
    check("persist_reopened", pp >= 0 && if_nametoindex("pp0") == (unsigned)ppi);
    close(pp);
    check("tap_deleted", del_link(na, "pp0") == 0 && if_nametoindex("pp0") == 0);

    // Deleting one end takes the other.
    check("unenslave", set_link(na, pci, 1, 0) == 0 && get_link(na, "pc", kind, &master, &peer) == 0 && master == 0);
    check("delete", del_link(na, "va") == 0 && if_nametoindex("va") == 0 && index_in(ns_b, "eth0") == 0);
    check("delete_card_refused", del_link(na, "lo") == EOPNOTSUPP);

    // C ends: its end of the pc/qc pair goes, and pc with it.
    close(nc);
    close(uc1);
    close(uc2);
    close(ns_c);
    kill(pc, SIGKILL);
    waitpid(pc, 0, 0);
    int gone = 0;
    for (int i = 0; i < 50 && !gone; i++) {
        gone = if_nametoindex("pc") == 0;
        if (!gone) usleep(20000);
    }
    check("namespace_end", gone && if_nametoindex("pb") != 0);
    kill(pb, SIGKILL);
    waitpid(pb, 0, 0);
    return failures != 0;
}
