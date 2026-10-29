/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0031): <strings.h> (POSIX). */
#ifndef _STRINGS_H
#define _STRINGS_H
#include <stddef.h>
int strcasecmp(const char *a, const char *b);
int strncasecmp(const char *a, const char *b, size_t n);
#endif
