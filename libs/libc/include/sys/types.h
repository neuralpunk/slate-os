/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0031): <sys/types.h> (POSIX) for x86-64. */
#ifndef _SYS_TYPES_H
#define _SYS_TYPES_H
#include <stddef.h>
typedef long ssize_t;
typedef long off_t;
typedef int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef unsigned int mode_t;
typedef unsigned long ino_t;
typedef unsigned long dev_t;
typedef unsigned long nlink_t;
typedef long blksize_t;
typedef long blkcnt_t;
typedef long time_t;
#endif
