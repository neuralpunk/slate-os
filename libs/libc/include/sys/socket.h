/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0075): <sys/socket.h> (POSIX). Families, kinds, levels,
 * options and flags are Linux's, which Slate's native interface shares
 * (socket(7), unix(7)). No sendmsg/recvmsg. */
#ifndef _SYS_SOCKET_H
#define _SYS_SOCKET_H
#include <sys/types.h>
typedef unsigned int socklen_t;
typedef unsigned short sa_family_t;
struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};
struct sockaddr_storage {
    sa_family_t ss_family;
    char __ss_data[126];
} __attribute__((aligned(8)));
struct linger {
    int l_onoff;
    int l_linger;
};
#define AF_UNSPEC 0
#define AF_UNIX 1
#define AF_LOCAL AF_UNIX
#define AF_INET 2
#define AF_INET6 10
#define PF_UNSPEC AF_UNSPEC
#define PF_UNIX AF_UNIX
#define PF_LOCAL AF_LOCAL
#define PF_INET AF_INET
#define PF_INET6 AF_INET6
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_RAW 3
#define SOCK_SEQPACKET 5
#define SOCK_NONBLOCK 04000
#define SOCK_CLOEXEC 02000000
#define SOL_SOCKET 1
#define SO_DEBUG 1
#define SO_REUSEADDR 2
#define SO_TYPE 3
#define SO_ERROR 4
#define SO_DONTROUTE 5
#define SO_BROADCAST 6
#define SO_SNDBUF 7
#define SO_RCVBUF 8
#define SO_KEEPALIVE 9
#define SO_OOBINLINE 10
#define SO_LINGER 13
#define SO_REUSEPORT 15
#define SO_PEERCRED 17
#define SO_RCVLOWAT 18
#define SO_SNDLOWAT 19
#define SO_RCVTIMEO 20
#define SO_SNDTIMEO 21
#define SO_ACCEPTCONN 30
#define SOMAXCONN 4096
#define MSG_OOB 1
#define MSG_PEEK 2
#define MSG_DONTROUTE 4
#define MSG_TRUNC 0x20
#define MSG_DONTWAIT 0x40
#define MSG_EOR 0x80
#define MSG_WAITALL 0x100
#define MSG_NOSIGNAL 0x4000
#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2
int socket(int family, int kind, int protocol);
int socketpair(int family, int kind, int protocol, int fds[2]);
int bind(int fd, const struct sockaddr *addr, socklen_t len);
int connect(int fd, const struct sockaddr *addr, socklen_t len);
int listen(int fd, int backlog);
int accept(int fd, struct sockaddr *addr, socklen_t *len);
int accept4(int fd, struct sockaddr *addr, socklen_t *len, int flags);
ssize_t send(int fd, const void *buf, size_t n, int flags);
ssize_t recv(int fd, void *buf, size_t n, int flags);
ssize_t sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *addr, socklen_t len);
ssize_t recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *addr, socklen_t *len);
int setsockopt(int fd, int level, int name, const void *value, socklen_t len);
int getsockopt(int fd, int level, int name, void *value, socklen_t *len);
int shutdown(int fd, int how);
int getsockname(int fd, struct sockaddr *addr, socklen_t *len);
int getpeername(int fd, struct sockaddr *addr, socklen_t *len);
#endif
