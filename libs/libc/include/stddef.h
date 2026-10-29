/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0031): <stddef.h> (C11 7.19). */
#ifndef _STDDEF_H
#define _STDDEF_H
typedef unsigned long size_t;
typedef long ptrdiff_t;
typedef int wchar_t;
#define NULL ((void *)0)
#define offsetof(type, member) __builtin_offsetof(type, member)
#endif
