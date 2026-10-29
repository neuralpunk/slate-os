/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0031): <inttypes.h> (C11 7.8), printf formats for LP64. */
#ifndef _INTTYPES_H
#define _INTTYPES_H
#include <stdint.h>
#define PRId8 "d"
#define PRId16 "d"
#define PRId32 "d"
#define PRId64 "ld"
#define PRIi64 "li"
#define PRIu8 "u"
#define PRIu16 "u"
#define PRIu32 "u"
#define PRIu64 "lu"
#define PRIx32 "x"
#define PRIx64 "lx"
#define PRIX64 "lX"
#define PRIdMAX "ld"
#define PRIuMAX "lu"
#define PRIdPTR "ld"
#define PRIuPTR "lu"
#define PRIxPTR "lx"
#endif
