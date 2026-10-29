/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0075): <sys/time.h> (POSIX). */
#ifndef _SYS_TIME_H
#define _SYS_TIME_H
#include <sys/types.h>
typedef long suseconds_t;
struct timeval {
    time_t tv_sec;
    suseconds_t tv_usec;
};
struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};
int gettimeofday(struct timeval *tv, void *tz);
#include <sys/select.h>
#endif
