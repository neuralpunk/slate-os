/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0031, ADR 0075): <time.h> (C11 7.27, POSIX clocks and
 * calendar functions; local time from Slate's zones). */
#ifndef _TIME_H
#define _TIME_H
#include <sys/types.h>
struct timespec {
    time_t tv_sec;
    long tv_nsec;
};
typedef int clockid_t;
typedef long clock_t;
#define CLOCKS_PER_SEC 1000000L
struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
    long tm_gmtoff;
    const char *tm_zone;
};
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
time_t time(time_t *t);
int clock_gettime(clockid_t clock, struct timespec *ts);
int nanosleep(const struct timespec *req, struct timespec *rem);
clock_t clock(void);
double difftime(time_t a, time_t b);
struct tm *gmtime(const time_t *t);
struct tm *gmtime_r(const time_t *t, struct tm *out);
struct tm *localtime(const time_t *t);
struct tm *localtime_r(const time_t *t, struct tm *out);
time_t mktime(struct tm *tm);
time_t timegm(struct tm *tm);
size_t strftime(char *s, size_t max, const char *fmt, const struct tm *tm);
char *asctime(const struct tm *tm);
char *asctime_r(const struct tm *tm, char *buf);
char *ctime(const time_t *t);
char *ctime_r(const time_t *t, char *buf);
void tzset(void);
#endif
