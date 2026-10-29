/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0075): <setjmp.h> (C11 7.13, POSIX sigsetjmp). One
 * buffer type for both: the callee-saved registers, the stack pointer and
 * the return address, then the signal mask sigsetjmp may keep. */
#ifndef _SETJMP_H
#define _SETJMP_H
typedef struct __slate_jmp_buf {
    unsigned long __regs[8];
    unsigned long __saved;
    unsigned long __mask;
} jmp_buf[1];
typedef jmp_buf sigjmp_buf;
int setjmp(jmp_buf env) __attribute__((returns_twice));
int _setjmp(jmp_buf env) __attribute__((returns_twice));
int sigsetjmp(sigjmp_buf env, int savemask) __attribute__((returns_twice));
_Noreturn void longjmp(jmp_buf env, int val);
_Noreturn void _longjmp(jmp_buf env, int val);
_Noreturn void siglongjmp(sigjmp_buf env, int val);
#endif
