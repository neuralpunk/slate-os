/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0031): <limits.h> (C11 5.2.4.2.1) for x86-64; PATH_MAX
   and NAME_MAX as Slate's VFS uses them. */
#ifndef _LIMITS_H
#define _LIMITS_H
#define CHAR_BIT 8
#define SCHAR_MIN (-128)
#define SCHAR_MAX 127
#define UCHAR_MAX 255
#define CHAR_MIN SCHAR_MIN
#define CHAR_MAX SCHAR_MAX
#define SHRT_MIN (-32768)
#define SHRT_MAX 32767
#define USHRT_MAX 65535
#define INT_MIN (-2147483647 - 1)
#define INT_MAX 2147483647
#define UINT_MAX 4294967295U
#define LONG_MIN (-9223372036854775807L - 1)
#define LONG_MAX 9223372036854775807L
#define ULONG_MAX 18446744073709551615UL
#define LLONG_MIN LONG_MIN
#define LLONG_MAX LONG_MAX
#define ULLONG_MAX ULONG_MAX
#define SSIZE_MAX LONG_MAX
#define PATH_MAX 4096
#define NAME_MAX 255
#define PTHREAD_STACK_MIN 16384
#endif
