/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0031): <assert.h> (C11 7.2). */
#undef assert
#ifdef NDEBUG
#define assert(e) ((void)0)
#else
void __assert_fail(const char *expr, const char *file, int line, const char *func);
#define assert(e) ((e) ? (void)0 : __assert_fail(#e, __FILE__, __LINE__, __func__))
#endif
