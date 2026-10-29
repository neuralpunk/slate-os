/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0075): <netdb.h> (POSIX getaddrinfo(3)). Names resolve
 * through /etc/hosts and DNS; getnameinfo answers numerically only. */
#ifndef _NETDB_H
#define _NETDB_H
#include <netinet/in.h>
struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    socklen_t ai_addrlen;
    struct sockaddr *ai_addr;
    char *ai_canonname;
    struct addrinfo *ai_next;
};
struct hostent {
    char *h_name;
    char **h_aliases;
    int h_addrtype;
    int h_length;
    char **h_addr_list;
};
#define h_addr h_addr_list[0]
#define AI_PASSIVE 0x01
#define AI_CANONNAME 0x02
#define AI_NUMERICHOST 0x04
#define AI_V4MAPPED 0x08
#define AI_ALL 0x10
#define AI_ADDRCONFIG 0x20
#define AI_NUMERICSERV 0x400
#define NI_NUMERICHOST 0x01
#define NI_NUMERICSERV 0x02
#define NI_NOFQDN 0x04
#define NI_NAMEREQD 0x08
#define NI_DGRAM 0x10
#define NI_MAXHOST 1025
#define NI_MAXSERV 32
#define EAI_BADFLAGS (-1)
#define EAI_NONAME (-2)
#define EAI_AGAIN (-3)
#define EAI_FAIL (-4)
#define EAI_FAMILY (-6)
#define EAI_SOCKTYPE (-7)
#define EAI_SERVICE (-8)
#define EAI_MEMORY (-10)
#define EAI_SYSTEM (-11)
#define EAI_OVERFLOW (-12)
#define HOST_NOT_FOUND 1
#define TRY_AGAIN 2
#define NO_RECOVERY 3
#define NO_DATA 4
int *__h_errno_location(void);
#define h_errno (*__h_errno_location())
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
void freeaddrinfo(struct addrinfo *ai);
const char *gai_strerror(int e);
int getnameinfo(const struct sockaddr *addr, socklen_t len, char *host, socklen_t hostlen, char *serv,
                socklen_t servlen, int flags);
struct hostent *gethostbyname(const char *name);
#endif
