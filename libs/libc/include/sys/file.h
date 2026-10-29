/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0031): <sys/file.h>, flock(2) (values as musl
   sys/file.h). */
#ifndef _SYS_FILE_H
#define _SYS_FILE_H
#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_NB 4
#define LOCK_UN 8
int flock(int fd, int op);
#endif
