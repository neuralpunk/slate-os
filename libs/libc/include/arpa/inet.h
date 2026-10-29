/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0075): <arpa/inet.h> (POSIX; inet(3)). */
#ifndef _ARPA_INET_H
#define _ARPA_INET_H
#include <netinet/in.h>
int inet_pton(int family, const char *src, void *dst);
const char *inet_ntop(int family, const void *src, char *dst, socklen_t size);
int inet_aton(const char *s, struct in_addr *out);
in_addr_t inet_addr(const char *s);
char *inet_ntoa(struct in_addr a);
#endif
