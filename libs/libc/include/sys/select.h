/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0075): <sys/select.h> (POSIX; select(2) over poll). */
#ifndef _SYS_SELECT_H
#define _SYS_SELECT_H
#include <sys/types.h>
#define FD_SETSIZE 1024
typedef struct {
    unsigned long fds_bits[FD_SETSIZE / 64];
} fd_set;
#define FD_ZERO(s) __builtin_memset((s), 0, sizeof(fd_set))
#define FD_SET(fd, s) ((s)->fds_bits[(fd) / 64] |= 1UL << ((fd) % 64))
#define FD_CLR(fd, s) ((s)->fds_bits[(fd) / 64] &= ~(1UL << ((fd) % 64)))
#define FD_ISSET(fd, s) (((s)->fds_bits[(fd) / 64] >> ((fd) % 64)) & 1)
struct timeval;
int select(int n, fd_set *r, fd_set *w, fd_set *e, struct timeval *timeout);
#endif
