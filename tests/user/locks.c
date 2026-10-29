// SPDX-License-Identifier: MIT OR Apache-2.0
// Advisory file locks (M19): flock(2), POSIX record locks and OFD locks,
// between processes, with the semantics of their man pages. Runs in a
// directory given as the argument (default /tmp); it passes on Linux too.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;
static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::locks::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

static char path[256], path2[256];

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static int open_rw(const char *p) {
    return open(p, O_RDWR | O_CREAT, 0644);
}

/// Run `f` in a child; its exit status (f's return value).
static int in_child(int (*f)(void)) {
    pid_t pid = fork();
    if (pid == 0) _exit(f());
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 100;
}

static int setlk(int fd, int cmd, short type, off_t start, off_t len) {
    struct flock l = {.l_type = type, .l_whence = SEEK_SET, .l_start = start, .l_len = len};
    return fcntl(fd, cmd, &l);
}

// --- children ---------------------------------------------------------------

static int child_flock_nb_ex(void) {
    int fd = open_rw(path);
    int r = flock(fd, LOCK_EX | LOCK_NB);
    return r == -1 && errno == EWOULDBLOCK ? 0 : 1;
}

static int child_flock_nb_sh(void) {
    int fd = open_rw(path);
    return flock(fd, LOCK_SH | LOCK_NB) == 0 ? 0 : 1;
}

static int child_flock_ex_ok(void) {
    int fd = open_rw(path);
    return flock(fd, LOCK_EX | LOCK_NB) == 0 ? 0 : 1;
}

static int child_posix_blocked(void) {
    int fd = open_rw(path);
    if (setlk(fd, F_SETLK, F_WRLCK, 50, 10) != -1 || (errno != EAGAIN && errno != EACCES)) return 1;
    struct flock l = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 50, .l_len = 10};
    if (fcntl(fd, F_GETLK, &l) != 0) return 2;
    if (l.l_type != F_WRLCK || l.l_start != 0 || l.l_len != 100 || l.l_pid != getppid()) return 3;
    // Elsewhere is free.
    if (setlk(fd, F_SETLK, F_RDLCK, 100, 100) != 0) return 4;
    return 0;
}

static int child_posix_hole(void) {
    int fd = open_rw(path);
    // The parent unlocked [20, 30) inside its lock: only that is free.
    if (setlk(fd, F_SETLK, F_WRLCK, 20, 10) != 0) return 1;
    if (setlk(fd, F_SETLK, F_WRLCK, 19, 1) != -1) return 2;
    if (setlk(fd, F_SETLK, F_WRLCK, 30, 1) != -1) return 3;
    return 0;
}

static int child_posix_free(void) {
    int fd = open_rw(path);
    return setlk(fd, F_SETLK, F_WRLCK, 0, 0) == 0 ? 0 : 1;
}

static int child_hold_and_exit(void) {
    int fd = open_rw(path2);
    return setlk(fd, F_SETLK, F_WRLCK, 0, 0) == 0 ? 0 : 1; // Exits holding it.
}

static void on_alarm(int sig) {
    (void)sig;
}

static int child_flock_eintr(void) {
    int fd = open_rw(path);
    struct sigaction sa = {.sa_handler = on_alarm};
    sigaction(SIGALRM, &sa, NULL); // No SA_RESTART.
    alarm(1);
    int r = flock(fd, LOCK_EX);
    return r == -1 && errno == EINTR ? 0 : 1;
}

static int child_setlkw_eintr(void) {
    int fd = open_rw(path);
    struct sigaction sa = {.sa_handler = on_alarm};
    sigaction(SIGALRM, &sa, NULL);
    alarm(1);
    int r = setlk(fd, F_SETLKW, F_WRLCK, 0, 1);
    return r == -1 && errno == EINTR ? 0 : 1;
}

// --- tests ------------------------------------------------------------------

static void flock_tests(void) {
    int fd = open_rw(path);
    check("flock_ex", flock(fd, LOCK_EX) == 0);
    check("flock_ex_excludes", in_child(child_flock_nb_ex) == 0);
    check("flock_ex_excludes_sh", in_child(child_flock_nb_sh) == 1);
    // A dup shares the lock; closing one copy keeps it.
    int d = dup(fd);
    close(fd);
    check("flock_dup_keeps", in_child(child_flock_nb_ex) == 0);
    close(d);
    check("flock_close_releases", in_child(child_flock_ex_ok) == 0);
    // Shared locks coexist; an exclusive one waits for them.
    fd = open_rw(path);
    check("flock_sh", flock(fd, LOCK_SH) == 0);
    check("flock_sh_shares", in_child(child_flock_nb_sh) == 0);
    check("flock_sh_excludes_ex", in_child(child_flock_nb_ex) == 0);
    // Conversion to exclusive, then an explicit unlock.
    check("flock_convert", flock(fd, LOCK_EX | LOCK_NB) == 0 && in_child(child_flock_nb_sh) == 1);
    check("flock_un", flock(fd, LOCK_UN) == 0 && in_child(child_flock_ex_ok) == 0);
    check("flock_bad_op", flock(fd, 0) == -1 && errno == EINVAL);
    // A blocked flock waits until the holder lets go.
    flock(fd, LOCK_EX);
    pid_t pid = fork();
    if (pid == 0) {
        int f2 = open_rw(path);
        long t0 = now_ms();
        int r = flock(f2, LOCK_EX);
        _exit(r == 0 && now_ms() - t0 >= 250 ? 0 : 1);
    }
    usleep(400000);
    flock(fd, LOCK_UN);
    int st = 0;
    waitpid(pid, &st, 0);
    check("flock_waits", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    // A signal ends the wait.
    flock(fd, LOCK_EX);
    check("flock_eintr", in_child(child_flock_eintr) == 0);
    close(fd);
}

static void posix_tests(void) {
    int fd = open_rw(path);
    check("posix_setlk", setlk(fd, F_SETLK, F_WRLCK, 0, 100) == 0);
    check("posix_conflict_getlk", in_child(child_posix_blocked) == 0);
    check("posix_unlock_middle", setlk(fd, F_SETLK, F_UNLCK, 20, 10) == 0);
    check("posix_split", in_child(child_posix_hole) == 0);
    // Closing any descriptor of the file drops all the process's locks.
    int other = open_rw(path);
    close(other);
    check("posix_close_any_releases", in_child(child_posix_free) == 0);
    // A child's locks go when it exits.
    check("posix_exit_releases", in_child(child_hold_and_exit) == 0);
    int fd2 = open_rw(path2);
    check("posix_after_exit", setlk(fd2, F_SETLK, F_WRLCK, 0, 0) == 0);
    close(fd2);
    // Locks need a matching access mode.
    int ro = open(path, O_RDONLY);
    check("posix_write_lock_needs_write", setlk(ro, F_SETLK, F_WRLCK, 0, 1) == -1 && errno == EBADF);
    check("posix_read_lock_ok", setlk(ro, F_SETLK, F_RDLCK, 0, 1) == 0);
    close(ro);
    // Ranges from the end, and backwards.
    fd = open_rw(path);
    ftruncate(fd, 1000);
    struct flock l = {.l_type = F_WRLCK, .l_whence = SEEK_END, .l_start = -100, .l_len = -50};
    check("posix_seek_end_negative", fcntl(fd, F_SETLK, &l) == 0);
    pid_t pid = fork();
    if (pid == 0) {
        int f2 = open_rw(path);
        struct flock q = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 0};
        fcntl(f2, F_GETLK, &q);
        _exit(q.l_type == F_WRLCK && q.l_start == 850 && q.l_len == 50 ? 0 : 1);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    check("posix_range_reported", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    // F_SETLKW waits for the holder.
    setlk(fd, F_SETLK, F_WRLCK, 0, 1);
    pid = fork();
    if (pid == 0) {
        int f2 = open_rw(path);
        long t0 = now_ms();
        int r = setlk(f2, F_SETLKW, F_WRLCK, 0, 1);
        _exit(r == 0 && now_ms() - t0 >= 250 ? 0 : 1);
    }
    usleep(400000);
    setlk(fd, F_SETLK, F_UNLCK, 0, 1);
    waitpid(pid, &st, 0);
    check("posix_setlkw_waits", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    setlk(fd, F_SETLK, F_WRLCK, 0, 1);
    check("posix_setlkw_eintr", in_child(child_setlkw_eintr) == 0);
    // Deadlock: the parent holds [0,1) and waits for [1,2), which a child
    // holds while it asks for [0,1).
    int pipefd[2];
    pipe(pipefd);
    pid = fork();
    if (pid == 0) {
        int f2 = open_rw(path);
        setlk(f2, F_SETLK, F_WRLCK, 1, 1);
        write(pipefd[1], "x", 1);
        usleep(300000); // Let the parent block on [1,2).
        int r = setlk(f2, F_SETLKW, F_WRLCK, 0, 1);
        _exit(r == -1 && errno == EDEADLK ? 0 : 1);
    }
    char c;
    read(pipefd[0], &c, 1);
    int r = setlk(fd, F_SETLKW, F_WRLCK, 1, 1); // Granted once the child gives up and exits.
    waitpid(pid, &st, 0);
    check("posix_edeadlk", r == 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    close(fd);
}

static void ofd_tests(void) {
    int a = open_rw(path), b = open_rw(path);
    check("ofd_setlk", setlk(a, F_OFD_SETLK, F_WRLCK, 0, 10) == 0);
    // Another open file description conflicts, even in the same process.
    check("ofd_conflict_same_process", setlk(b, F_OFD_SETLK, F_WRLCK, 5, 1) == -1 && errno == EAGAIN);
    struct flock l = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 5, .l_len = 1};
    check("ofd_getlk_pid", fcntl(b, F_OFD_GETLK, &l) == 0 && l.l_type == F_WRLCK && l.l_pid == -1);
    // POSIX and OFD locks conflict with each other.
    check("ofd_vs_posix", setlk(b, F_SETLK, F_WRLCK, 0, 1) == -1);
    struct flock bad = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 50, .l_len = 1, .l_pid = 1};
    check("ofd_pid_must_be_zero", fcntl(b, F_OFD_SETLK, &bad) == -1 && errno == EINVAL);
    // A dup shares it; closing every copy releases it.
    int d = dup(a);
    close(a);
    check("ofd_dup_keeps", setlk(b, F_OFD_SETLK, F_WRLCK, 0, 1) == -1);
    close(d);
    check("ofd_close_releases", setlk(b, F_OFD_SETLK, F_WRLCK, 0, 1) == 0);
    close(b);
}

static void proc_locks_test(void) {
    int fd = open_rw(path);
    flock(fd, LOCK_SH);
    setlk(fd, F_SETLK, F_WRLCK, 0, 5);
    char buf[4096] = {0};
    int p = open("/proc/locks", O_RDONLY);
    if (p >= 0) {
        read(p, buf, sizeof buf - 1);
        close(p);
    }
    check("proc_locks", strstr(buf, "FLOCK") && strstr(buf, "POSIX") && strstr(buf, "ADVISORY"));
    close(fd);
}

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "/tmp";
    snprintf(path, sizeof path, "%s/locks-test", dir);
    snprintf(path2, sizeof path2, "%s/locks-test-2", dir);
    flock_tests();
    posix_tests();
    ofd_tests();
    proc_locks_test();
    unlink(path);
    unlink(path2);
    return failures;
}
