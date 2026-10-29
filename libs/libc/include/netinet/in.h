/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0075): <netinet/in.h> (POSIX; ip(7), ipv6(7)). */
#ifndef _NETINET_IN_H
#define _NETINET_IN_H
#include <stdint.h>
#include <sys/socket.h>
typedef uint16_t in_port_t;
typedef uint32_t in_addr_t;
struct in_addr {
    in_addr_t s_addr;
};
struct sockaddr_in {
    sa_family_t sin_family;
    in_port_t sin_port;
    struct in_addr sin_addr;
    unsigned char sin_zero[8];
};
struct in6_addr {
    unsigned char s6_addr[16];
};
struct sockaddr_in6 {
    sa_family_t sin6_family;
    in_port_t sin6_port;
    uint32_t sin6_flowinfo;
    struct in6_addr sin6_addr;
    uint32_t sin6_scope_id;
};
#define IPPROTO_IP 0
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_IPV6 41
#define IPPROTO_ICMPV6 58
#define IPPROTO_RAW 255
#define INADDR_ANY ((in_addr_t)0x00000000)
#define INADDR_BROADCAST ((in_addr_t)0xffffffff)
#define INADDR_NONE ((in_addr_t)0xffffffff)
#define INADDR_LOOPBACK ((in_addr_t)0x7f000001)
#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46
#define IP_TOS 1
#define IP_TTL 2
#define IP_MULTICAST_TTL 33
#define IP_ADD_MEMBERSHIP 35
#define IPV6_V6ONLY 26
#define IN6ADDR_ANY_INIT {{0}}
#define IN6ADDR_LOOPBACK_INIT {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}
extern const struct in6_addr in6addr_any;
extern const struct in6_addr in6addr_loopback;
uint16_t htons(uint16_t v);
uint16_t ntohs(uint16_t v);
uint32_t htonl(uint32_t v);
uint32_t ntohl(uint32_t v);
#endif
