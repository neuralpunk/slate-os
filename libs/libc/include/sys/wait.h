/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0031): <sys/wait.h> (POSIX), the traditional status
   encoding (as musl sys/wait.h). */
#ifndef _SYS_WAIT_H
#define _SYS_WAIT_H
#include <sys/types.h>
#define WNOHANG 1
#define WUNTRACED 2
#define WCONTINUED 8
#define WEXITSTATUS(s) (((s) >> 8) & 0xff)
#define WTERMSIG(s) ((s) & 0x7f)
#define WSTOPSIG(s) WEXITSTATUS(s)
#define WIFEXITED(s) (!WTERMSIG(s))
#define WIFSTOPPED(s) (((s) & 0xff) == 0x7f)
#define WIFSIGNALED(s) (WTERMSIG(s) && !WIFSTOPPED(s))
#define WIFCONTINUED(s) ((s) == 0xffff)
pid_t wait(int *status);
pid_t waitpid(pid_t pid, int *status, int options);
#endif
