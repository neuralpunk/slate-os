// SPDX-License-Identifier: MIT OR Apache-2.0
// The firewall through its own interface (nf_tables over NETLINK_NETFILTER,
// ADRs 0128, 0129): a batch makes a table, an input chain and a rule that
// drops UDP to port 5555; datagrams to it on loopback no longer arrive
// while others do; the table is listed back; a rule for a chain that
// isn't there is refused with ENOENT; deleting the table lifts the drop.
// Then xtables' compatibility (ADR 0133): the revision of an extension
// Slate has, ENOENT for one it hasn't.
// Numbers from linux/netfilter/nf_tables.h, nfnetlink.h and netfilter.h
// (ADR 0128), and netlink(7).
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define NETLINK_NETFILTER_ 12
#define AF_NETLINK_ 16
#define NLM_F_REQUEST_ 0x1
#define NLM_F_ACK_ 0x4
#define NLM_F_DUMP_ 0x300
#define NLM_F_CREATE_ 0x400
#define NLM_F_APPEND_ 0x800
#define NLMSG_ERROR_ 2
#define NLMSG_DONE_ 3
#define NLA_F_NESTED_ 0x8000
#define BATCH_BEGIN 16
#define BATCH_END 17
#define SUBSYS_NFTABLES 10
#define NFT(m) ((SUBSYS_NFTABLES << 8) | (m))
#define NEWTABLE 0
#define GETTABLE 1
#define DELTABLE 2
#define NEWCHAIN 3
#define NEWRULE 6
#define NFPROTO_INET_ 1
#define NFPROTO_IPV4_ 2
#define NF_INET_LOCAL_IN_ 1
#define NF_ACCEPT_ 1
#define NF_DROP_ 0

static int failures;
static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::nftables::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

/// A datagram being built: messages, each with attributes and nests.
static unsigned char buf[4096];
static size_t len, msg_at, nests[8];
static int depth;
static uint32_t seq;

static void put(const void *p, size_t n) {
    memcpy(buf + len, p, n);
    len += n;
    while (len % 4) buf[len++] = 0;
}

static void msg(uint16_t type, uint16_t flags, uint8_t family, uint16_t res) {
    msg_at = len;
    uint32_t hdr[4] = {0, type | (uint32_t)flags << 16, ++seq, 0};
    put(hdr, 16);
    unsigned char g[4] = {family, 0, res >> 8, res & 0xff};
    put(g, 4);
}

static void end_msg(void) { *(uint32_t *)(buf + msg_at) = len - msg_at; }

static void attr(uint16_t type, const void *v, uint16_t n) {
    uint16_t h[2] = {4 + n, type};
    memcpy(buf + len, h, 4);
    memcpy(buf + len + 4, v, n);
    len += 4 + n;
    while (len % 4) buf[len++] = 0;
}

static void str(uint16_t type, const char *s) { attr(type, s, strlen(s) + 1); }

static void be32(uint16_t type, uint32_t v) {
    uint32_t b = htonl(v);
    attr(type, &b, 4);
}

static void nest(uint16_t type) {
    nests[depth++] = len;
    uint16_t h[2] = {0, type | NLA_F_NESTED_};
    memcpy(buf + len, h, 4);
    len += 4;
}

static void end_nest(void) {
    size_t at = nests[--depth];
    *(uint16_t *)(buf + at) = len - at;
}

/// One expression: its name, then its data nest's attributes by `fill`.
static void expr(const char *name, void (*fill)(void)) {
    nest(1); // NFTA_LIST_ELEM
    str(1, name); // NFTA_EXPR_NAME
    nest(2); // NFTA_EXPR_DATA
    fill();
    end_nest();
    end_nest();
}

/// A NFTA_DATA_VALUE nest holding `v`.
static void value(uint16_t type, const void *v, uint16_t n) {
    nest(type);
    attr(1, v, n);
    end_nest();
}

// udp dport 5555 drop, as nft compiles it: meta l4proto (key 16) into
// register 1, cmp eq 17; payload (transport header, offset 2, 2 bytes)
// into register 1, cmp eq 5555; immediate drop to the verdict register.
static void meta_l4proto(void) { be32(2, 16), be32(1, 1); }
static void cmp_udp(void) {
    unsigned char p = 17;
    be32(1, 1), be32(2, 0), value(3, &p, 1);
}
static void payload_dport(void) { be32(1, 1), be32(2, 2), be32(3, 2), be32(4, 2); }
static void cmp_5555(void) {
    uint16_t port = htons(5555);
    be32(1, 1), be32(2, 0), value(3, &port, 2);
}
static void verdict_drop(void) {
    be32(1, 0);
    nest(2); // NFTA_IMMEDIATE_DATA
    nest(2); // NFTA_DATA_VERDICT
    be32(1, NF_DROP_);
    end_nest();
    end_nest();
}

static int sock;

static void send_batch(void) {
    struct sockaddr_nl { uint16_t family, pad; uint32_t pid, groups; } k = {AF_NETLINK_, 0, 0, 0};
    sendto(sock, buf, len, 0, (void *)&k, sizeof k);
    len = 0;
}

/// Read answers until `want` acknowledgements or a dump's end; returns the
/// first non-zero error (positive), and copies everything into `all`.
static int answers(int want, unsigned char *all, size_t *all_len) {
    int err = 0, acks = 0;
    if (all_len) *all_len = 0;
    while (acks < want) {
        struct pollfd p = {sock, POLLIN, 0};
        if (poll(&p, 1, 2000) != 1) return -1;
        unsigned char r[8192];
        ssize_t n = recv(sock, r, sizeof r, 0);
        if (n <= 0) return -1;
        if (all && *all_len + n < 16384) memcpy(all + *all_len, r, n), *all_len += n;
        for (ssize_t at = 0; at + 16 <= n;) {
            uint32_t l = *(uint32_t *)(r + at);
            uint16_t type = *(uint16_t *)(r + at + 4);
            if (type == NLMSG_ERROR_) {
                int e = *(int32_t *)(r + at + 16);
                if (e && !err) err = -e;
                acks++;
            } else if (type == NLMSG_DONE_) {
                acks++;
            }
            if (l < 16) break;
            at += (l + 3) & ~3;
        }
    }
    return err;
}

/// Whether a datagram to 127.0.0.1:`port` arrives.
static int arrives(int port) {
    int r = socket(AF_INET, SOCK_DGRAM, 0), s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    a.sin_addr.s_addr = htonl(0x7f000001);
    bind(r, (void *)&a, sizeof a);
    sendto(s, "x", 1, 0, (void *)&a, sizeof a);
    struct pollfd p = {r, POLLIN, 0};
    int got = poll(&p, 1, 300) == 1;
    close(r);
    close(s);
    return got;
}

static void batch_begin(void) {
    msg(BATCH_BEGIN, NLM_F_REQUEST_, 0, SUBSYS_NFTABLES);
    end_msg();
}

static void batch_end(void) {
    msg(BATCH_END, NLM_F_REQUEST_, 0, SUBSYS_NFTABLES);
    end_msg();
}

int main(void) {
    sock = socket(AF_NETLINK_, SOCK_RAW, NETLINK_NETFILTER_);
    check("socket", sock >= 0);
    if (sock < 0) return 1;

    // table inet t; chain in { type filter hook input priority 0; policy
    // accept; }; rule udp dport 5555 drop.
    batch_begin();
    msg(NFT(NEWTABLE), NLM_F_REQUEST_ | NLM_F_CREATE_ | NLM_F_ACK_, NFPROTO_INET_, 0);
    str(1, "t");
    end_msg();
    msg(NFT(NEWCHAIN), NLM_F_REQUEST_ | NLM_F_CREATE_ | NLM_F_ACK_, NFPROTO_INET_, 0);
    str(1, "t"), str(3, "in");
    nest(4);
    be32(1, NF_INET_LOCAL_IN_), be32(2, 0);
    end_nest();
    be32(5, NF_ACCEPT_), str(7, "filter");
    end_msg();
    msg(NFT(NEWRULE), NLM_F_REQUEST_ | NLM_F_CREATE_ | NLM_F_APPEND_ | NLM_F_ACK_, NFPROTO_INET_, 0);
    str(1, "t"), str(2, "in");
    nest(4);
    expr("meta", meta_l4proto), expr("cmp", cmp_udp), expr("payload", payload_dport);
    expr("cmp", cmp_5555), expr("immediate", verdict_drop);
    end_nest();
    end_msg();
    batch_end();
    send_batch();
    check("batch_applied", answers(3, 0, 0) == 0);
    check("rule_drops", !arrives(5555) && arrives(5556));

    // The table in a dump.
    static unsigned char all[16384];
    size_t all_len;
    msg(NFT(GETTABLE), NLM_F_REQUEST_ | NLM_F_DUMP_, NFPROTO_INET_, 0);
    end_msg();
    send_batch();
    int e = answers(1, all, &all_len);
    check("table_listed", e == 0 && memmem(all, all_len, "t\0", 2) != NULL);

    // A rule for a chain that isn't there: ENOENT, and nothing changed.
    batch_begin();
    msg(NFT(NEWRULE), NLM_F_REQUEST_ | NLM_F_CREATE_ | NLM_F_APPEND_ | NLM_F_ACK_, NFPROTO_INET_, 0);
    str(1, "t"), str(2, "nowhere");
    end_msg();
    batch_end();
    send_batch();
    check("missing_chain_enoent", answers(1, 0, 0) == ENOENT && !arrives(5555));

    // Deleting the table lifts the drop.
    batch_begin();
    msg(NFT(DELTABLE), NLM_F_REQUEST_ | NLM_F_ACK_, NFPROTO_INET_, 0);
    str(1, "t");
    end_msg();
    batch_end();
    send_batch();
    check("table_deleted", answers(1, 0, 0) == 0 && arrives(5555));
    // NFNL_MSG_COMPAT_GET (subsystem 11): conntrack, a match (type 0),
    // revision 3; then a match Slate hasn't. The answer repeats the name
    // and gives the revision (NFTA_COMPAT_REV, big-endian).
    msg((11 << 8) | 0, NLM_F_REQUEST_ | NLM_F_ACK_, NFPROTO_IPV4_, 0);
    str(1, "conntrack"), be32(2, 3), be32(3, 0);
    end_msg();
    send_batch();
    e = answers(1, all, &all_len);
    unsigned char rev3[8] = {8, 0, 2, 0, 0, 0, 0, 3};
    check("compat_revision", e == 0 && memmem(all, all_len, rev3, 8) != NULL);
    msg((11 << 8) | 0, NLM_F_REQUEST_ | NLM_F_ACK_, NFPROTO_IPV4_, 0);
    str(1, "hashlimit"), be32(2, 0), be32(3, 0);
    end_msg();
    send_batch();
    check("compat_unknown", answers(1, 0, 0) == ENOENT);
    close(sock);
    return failures != 0;
}
