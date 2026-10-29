/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0031, ADR 0075): <signal.h> (C11 7.14, POSIX). Signal
   numbers, sigaction flags and siginfo_t's layout are Linux's, which
   Slate's native interface shares (signal(7), sigaction(2)). */
#ifndef _SIGNAL_H
#define _SIGNAL_H
#include <sys/types.h>
typedef void (*sighandler_t)(int);
typedef int sig_atomic_t;
#define SIG_DFL ((sighandler_t)0)
#define SIG_IGN ((sighandler_t)1)
#define SIG_ERR ((sighandler_t)-1)
#define SIGHUP 1
#define SIGINT 2
#define SIGQUIT 3
#define SIGILL 4
#define SIGTRAP 5
#define SIGABRT 6
#define SIGBUS 7
#define SIGFPE 8
#define SIGKILL 9
#define SIGUSR1 10
#define SIGSEGV 11
#define SIGUSR2 12
#define SIGPIPE 13
#define SIGALRM 14
#define SIGTERM 15
#define SIGCHLD 17
#define SIGCONT 18
#define SIGSTOP 19
#define SIGTSTP 20
#define SIGTTIN 21
#define SIGTTOU 22
#define SIGWINCH 28
#define NSIG 65
typedef struct {
    unsigned long __bits;
} sigset_t;
typedef struct {
    int si_signo;
    int si_errno;
    int si_code;
    int __pad;
    union {
        struct {
            pid_t __pid;
            uid_t __uid;
            int __status;
        } __kill;
        void *__addr;
        char __reserved[112];
    } __u;
} siginfo_t;
#define si_pid __u.__kill.__pid
#define si_uid __u.__kill.__uid
#define si_status __u.__kill.__status
#define si_addr __u.__addr
struct sigaction {
    union {
        void (*sa_handler)(int);
        void (*sa_sigaction)(int, siginfo_t *, void *);
    };
    sigset_t sa_mask;
    int sa_flags;
    void (*sa_restorer)(void);
};
#define SA_NOCLDSTOP 1
#define SA_NOCLDWAIT 2
#define SA_SIGINFO 4
#define SA_ONSTACK 0x08000000
#define SA_RESTART 0x10000000
#define SA_NODEFER 0x40000000
#define SA_RESETHAND 0x80000000
#define SIG_BLOCK 0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2
int sigaction(int sig, const struct sigaction *act, struct sigaction *old);
int sigprocmask(int how, const sigset_t *set, sigset_t *old);
int pthread_sigmask(int how, const sigset_t *set, sigset_t *old);
int sigemptyset(sigset_t *set);
int sigfillset(sigset_t *set);
int sigaddset(sigset_t *set, int sig);
int sigdelset(sigset_t *set, int sig);
int sigismember(const sigset_t *set, int sig);
sighandler_t signal(int sig, sighandler_t handler);
int raise(int sig);
int kill(pid_t pid, int sig);
#endif
