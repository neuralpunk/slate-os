// SPDX-License-Identifier: MIT OR Apache-2.0
// Processes, pipes, signals and files: what a shell needs from the kernel.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::procs::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

static volatile sig_atomic_t got_usr1, got_chld, got_usr2;
static void on_usr1(int s) { (void)s; got_usr1++; }
static void on_chld(int s) { (void)s; got_chld++; }
static void on_usr2(int s) { (void)s; got_usr2++; }

static int exit_status(pid_t pid) {
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) return -1;
    return st;
}

int main(void) {
    // fork + exit status
    pid_t c = fork();
    if (c == 0) _exit(7);
    int st = exit_status(c);
    check("fork_wait_status", c > 0 && WIFEXITED(st) && WEXITSTATUS(st) == 7);

    // copy-on-write: the child's writes stay in the child
    static int shared = 1;
    int p1[2];
    pipe(p1);
    c = fork();
    if (c == 0) {
        shared = 99;
        char b = (char)shared;
        write(p1[1], &b, 1);
        _exit(0);
    }
    char got = 0;
    read(p1[0], &got, 1);
    exit_status(c);
    check("cow", got == 99 && shared == 1);
    close(p1[0]);
    close(p1[1]);

    // getppid in the child
    pid_t me = getpid();
    int p2[2];
    pipe(p2);
    c = fork();
    if (c == 0) {
        pid_t pp = getppid();
        write(p2[1], &pp, sizeof pp);
        _exit(0);
    }
    pid_t pp = 0;
    read(p2[0], &pp, sizeof pp);
    exit_status(c);
    check("getppid", pp == me);

    // pipe + dup2 + execve: capture another program's output
    int p3[2];
    pipe(p3);
    c = fork();
    if (c == 0) {
        dup2(p3[1], 1);
        close(p3[0]);
        close(p3[1]);
        char *argv[] = {"hello", NULL};
        char *envp[] = {NULL};
        execve("/test/hello", argv, envp);
        _exit(127);
    }
    close(p3[1]);
    char out[128] = {0};
    int n = 0, r;
    while ((r = read(p3[0], out + n, sizeof out - 1 - n)) > 0) n += r;
    close(p3[0]);
    st = exit_status(c);
    check("exec_with_pipe", strstr(out, "Hello from musl on Slate!") != NULL && WIFEXITED(st) && WEXITSTATUS(st) == 0);

    // execve failure keeps the process
    c = fork();
    if (c == 0) {
        char *argv[] = {"nope", NULL};
        execve("/does/not/exist", argv, NULL);
        _exit(errno == ENOENT ? 3 : 4);
    }
    st = exit_status(c);
    check("execve_enoent", WIFEXITED(st) && WEXITSTATUS(st) == 3);

    // vfork + exec
    c = vfork();
    if (c == 0) {
        char *argv[] = {"hello", NULL};
        execve("/test/hello", argv, NULL);
        _exit(127);
    }
    st = exit_status(c);
    check("vfork_exec", WIFEXITED(st) && WEXITSTATUS(st) == 0);

    // a signal handler runs and returns
    struct sigaction sa = {0};
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, NULL);
    kill(getpid(), SIGUSR1);
    check("handler", got_usr1 == 1);

    // a blocked signal waits until unblocked
    sigset_t set, old;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, &old);
    kill(getpid(), SIGUSR1);
    int still = got_usr1;
    sigset_t pend;
    sigpending(&pend);
    int was_pending = sigismember(&pend, SIGUSR1);
    sigprocmask(SIG_SETMASK, &old, NULL);
    check("blocked_then_delivered", still == 1 && was_pending && got_usr1 == 2);

    // SIGCHLD arrives when a child exits
    sa.sa_handler = on_chld;
    sigaction(SIGCHLD, &sa, NULL);
    c = fork();
    if (c == 0) _exit(0);
    exit_status(c);
    check("sigchld", got_chld >= 1);
    signal(SIGCHLD, SIG_DFL);

    // default SIGTERM kills; wait reports the signal
    c = fork();
    if (c == 0) {
        for (;;) pause();
    }
    kill(c, SIGTERM);
    st = exit_status(c);
    check("kill_sigterm", WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM);

    // writing to a pipe with no reader raises SIGPIPE
    int p4[2];
    pipe(p4);
    close(p4[0]);
    c = fork();
    if (c == 0) {
        write(p4[1], "x", 1);
        _exit(0);
    }
    close(p4[1]);
    st = exit_status(c);
    check("sigpipe", WIFSIGNALED(st) && WTERMSIG(st) == SIGPIPE);

    // a handler without SA_RESTART interrupts a blocking read (EINTR)
    sa.sa_handler = on_usr2;
    sa.sa_flags = 0;
    sigaction(SIGUSR2, &sa, NULL);
    int p5[2];
    pipe(p5);
    c = fork();
    if (c == 0) {
        usleep(50000);
        kill(getppid(), SIGUSR2);
        usleep(50000);
        write(p5[1], "z", 1);
        _exit(0);
    }
    char z;
    errno = 0;
    ssize_t rr = read(p5[0], &z, 1);
    check("eintr", rr == -1 && errno == EINTR && got_usr2 == 1);
    exit_status(c);
    read(p5[0], &z, 1);  // drain the byte the child wrote after the signal

    // with SA_RESTART the read resumes and completes
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR2, &sa, NULL);
    c = fork();
    if (c == 0) {
        usleep(50000);
        kill(getppid(), SIGUSR2);
        usleep(50000);
        write(p5[1], "y", 1);
        _exit(0);
    }
    rr = read(p5[0], &z, 1);
    check("sa_restart", rr == 1 && z == 'y' && got_usr2 == 2);
    exit_status(c);

    // WNOHANG
    c = fork();
    if (c == 0) {
        usleep(100000);
        _exit(0);
    }
    int early = waitpid(c, &st, WNOHANG);
    int later = exit_status(c);
    check("wnohang", early == 0 && WIFEXITED(later));
    errno = 0;
    check("echild", waitpid(-1, &st, 0) == -1 && errno == ECHILD);

    // files in /tmp
    mkdir("/tmp/t", 0755);
    int fd = open("/tmp/t/a.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    write(fd, "hello world", 11);
    lseek(fd, 6, SEEK_SET);
    char rb[8] = {0};
    read(fd, rb, 5);
    struct stat sb;
    fstat(fd, &sb);
    close(fd);
    check("file_rw", strcmp(rb, "world") == 0 && sb.st_size == 11 && S_ISREG(sb.st_mode));
    check("rename", rename("/tmp/t/a.txt", "/tmp/t/b.txt") == 0 && access("/tmp/t/b.txt", F_OK) == 0 &&
                        access("/tmp/t/a.txt", F_OK) == -1);
    check("symlink", symlink("b.txt", "/tmp/t/l") == 0);
    char lb[16] = {0};
    check("readlink", readlink("/tmp/t/l", lb, sizeof lb) == 5 && strcmp(lb, "b.txt") == 0);
    check("stat_via_link", stat("/tmp/t/l", &sb) == 0 && sb.st_size == 11);
    int entries = 0;
    DIR *d = opendir("/tmp/t");
    struct dirent *de;
    while (d && (de = readdir(d))) entries++;
    if (d) closedir(d);
    check("readdir", entries == 4);  // . .. b.txt l
    check("chdir_getcwd", chdir("/tmp/t") == 0 && getcwd(lb, sizeof lb) && strcmp(lb, "/tmp/t") == 0);
    check("relative_open", open("b.txt", O_RDONLY) >= 0);
    errno = 0;
    check("rmdir_notempty", rmdir("/tmp/t") == -1 && errno == ENOTEMPTY);
    check("unlink", unlink("/tmp/t/b.txt") == 0 && unlink("/tmp/t/l") == 0);
    chdir("/");
    check("rmdir", rmdir("/tmp/t") == 0);

    // /dev and /proc
    fd = open("/dev/null", O_WRONLY);
    check("dev_null", fd >= 0 && write(fd, "abc", 3) == 3);
    close(fd);
    fd = open("/proc/self/cmdline", O_RDONLY);
    char cl[64] = {0};
    read(fd, cl, sizeof cl - 1);
    close(fd);
    check("proc_self_cmdline", strcmp(cl, "procs") == 0);

    // An orphan that has already ended, handed to a subreaper, is
    // announced with SIGCHLD (prctl(2), PR_SET_CHILD_SUBREAPER): here the
    // grandchild ends, then its parent, while the parent's parent stays,
    // so the only SIGCHLD this process can get is the adoption's.
    prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    signal(SIGCHLD, on_chld);
    got_chld = 0;
    int gp[2];
    pipe(gp);
    pid_t mid = fork();
    if (mid == 0) {
        pid_t a = fork();
        if (a == 0) {
            pid_t g = fork();
            if (g == 0) _exit(5);
            usleep(100000);  // g has ended: a zombie of ours
            write(gp[1], &g, sizeof g);
            _exit(0);
        }
        waitpid(a, NULL, 0);
        pause();
        _exit(0);
    }
    pid_t g = 0;
    read(gp[0], &g, sizeof g);
    for (int i = 0; i < 200 && got_chld == 0; i++) usleep(10000);
    int adopted = -1;
    pid_t reaped = waitpid(g, &adopted, WNOHANG);
    check("adopted_zombie_sigchld", got_chld >= 1 && reaped == g && WIFEXITED(adopted) && WEXITSTATUS(adopted) == 5);
    kill(mid, SIGKILL);
    waitpid(mid, &st, 0);
    prctl(PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0);

    return failures;
}
