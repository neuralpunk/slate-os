/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0031): <stdarg.h> (C11 7.16), on the compiler's builtins. */
#ifndef _STDARG_H
#define _STDARG_H
typedef __builtin_va_list va_list;
#define va_start(ap, last) __builtin_va_start(ap, last)
#define va_arg(ap, type) __builtin_va_arg(ap, type)
#define va_copy(dst, src) __builtin_va_copy(dst, src)
#define va_end(ap) __builtin_va_end(ap)
#endif
