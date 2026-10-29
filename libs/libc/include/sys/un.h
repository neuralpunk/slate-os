/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0075): <sys/un.h> (POSIX; unix(7)). */
#ifndef _SYS_UN_H
#define _SYS_UN_H
#include <sys/socket.h>
struct sockaddr_un {
    sa_family_t sun_family;
    char sun_path[108];
};
#endif
