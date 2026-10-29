// SPDX-License-Identifier: MIT OR Apache-2.0
// Pseudo-terminals and job control: drive an interactive shell through a
// pty master the way a terminal emulator or sshd would; then the queues'
// bounds (64 KiB of output for the master, 4 KiB of input for the slave).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static int failures;
static char seen[65536];
static size_t seen_len;

static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::pty::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

// Read from the master until `needle` appears after offset `from`.
static int expect(int m, const char *needle, size_t from, int timeout_ms) {
    long end = now_ms() + timeout_ms;
    for (;;) {
        seen[seen_len] = 0;
        if (from <= seen_len && strstr(seen + from, needle)) return 1;
        long left = end - now_ms();
        if (left <= 0) return 0;
        struct pollfd p = {m, POLLIN, 0};
        if (poll(&p, 1, (int)left) <= 0) continue;
        ssize_t n = read(m, seen + seen_len, sizeof seen - 1 - seen_len);
        if (n <= 0) return 0;
        seen_len += n;
    }
}

static void send(int m, const char *s) { write(m, s, strlen(s)); }

/// Write `c` to `fd` (non-blocking) until it refuses; the bytes taken.
static long fill(int fd, char c) {
    char b[1024];
    memset(b, c, sizeof b);
    long total = 0;
    for (;;) {
        ssize_t n = write(fd, b, sizeof b);
        if (n <= 0) return n < 0 && errno == EAGAIN ? total : -1;
        total += n;
    }
}

static int writable(int fd) {
    struct pollfd p = {fd, POLLOUT, 0};
    return poll(&p, 1, 0) == 1 && (p.revents & POLLOUT);
}

/// The queues are bounded: writers wait (or get EAGAIN) instead of
/// growing them, and ^C still reaches a full input.
static void bounds(void) {
    int m = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (m < 0 || grantpt(m) || unlockpt(m)) {
        check("bounds_open", 0);
        return;
    }
    int s = open(ptsname(m), O_RDWR | O_NOCTTY | O_NONBLOCK);
    struct termios t;
    tcgetattr(s, &t);
    cfmakeraw(&t);
    tcsetattr(s, TCSANOW, &t);

    check("output_bounded", fill(s, 'o') == 65536 && !writable(s));
    char b[4096];
    check("output_drains", read(m, b, sizeof b) == (ssize_t)sizeof b && writable(s) && write(s, "x", 1) == 1);
    while (read(m, b, sizeof b) > 0) {
    }

    check("input_bounded", fill(m, 'i') == 4096 && !writable(m));
    check("input_drains", read(s, b, 100) == 100 && writable(m) && write(m, "y", 1) == 1);
    t.c_lflag |= ISIG;
    tcsetattr(s, TCSANOW, &t);
    check("full_input_takes_ctrl_c", fill(m, 'z') == 99 && write(m, "\x03", 1) == 1 && write(m, "a", 1) == 1);
    t.c_lflag &= ~ISIG;
    tcsetattr(s, TCSANOW, &t);
    tcflush(s, TCIFLUSH);

    // A blocking writer waits for the reader and loses nothing.
    pid_t c = fork();
    if (c == 0) {
        int fl = fcntl(s, F_GETFL);
        fcntl(s, F_SETFL, fl & ~O_NONBLOCK);
        static char big[200000];
        memset(big, 'w', sizeof big);
        _exit(write(s, big, sizeof big) == (ssize_t)sizeof big ? 0 : 1);
    }
    long got = 0, end = now_ms() + 10000;
    while (got < 200000 && now_ms() < end) {
        struct pollfd p = {m, POLLIN, 0};
        if (poll(&p, 1, 100) > 0) {
            ssize_t n = read(m, b, sizeof b);
            if (n > 0) got += n;
        }
    }
    int st = 1;
    waitpid(c, &st, 0);
    check("blocking_writer_waits", got == 200000 && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    close(s);
    close(m);
}

int main(void) {
    bounds();
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    check("openpt", m >= 0 && grantpt(m) == 0 && unlockpt(m) == 0);
    char *name = ptsname(m);
    struct stat st;
    check("ptsname", name && strncmp(name, "/dev/pts/", 9) == 0 && stat(name, &st) == 0 && S_ISCHR(st.st_mode));

    pid_t c = fork();
    if (c == 0) {
        setsid();
        int s = open(name, O_RDWR);  // the session leader acquires its terminal
        // Asking for it again, as terminal emulators do, succeeds.
        if (ioctl(s, TIOCSCTTY, 0) != 0) _exit(126);
        dup2(s, 0);
        dup2(s, 1);
        dup2(s, 2);
        if (s > 2) close(s);
        char *argv[] = {"sh", "-i", NULL};
        char *envp[] = {"PS1=PTY$ ", "PATH=/bin:/usr/bin", NULL};
        execve("/bin/sh", argv, envp);
        _exit(127);
    }

    check("prompt", expect(m, "PTY$ ", 0, 5000));
    size_t mark = seen_len;
    send(m, "echo pty-$((40+2))\n");
    check("command", expect(m, "pty-42\r\n", mark, 5000));

    // Ctrl-C interrupts the foreground job.
    mark = seen_len;
    send(m, "sleep 10\n");
    usleep(300000);
    send(m, "\x03");
    send(m, "echo after-int\n");
    check("ctrl_c", expect(m, "after-int\r\n", mark, 5000));

    // Ctrl-Z stops it; jobs lists it; fg resumes it; Ctrl-C ends it.
    mark = seen_len;
    send(m, "sleep 10\n");
    usleep(300000);
    send(m, "\x1a");
    check("ctrl_z_stops", expect(m, "Stopped", mark, 5000));
    mark = seen_len;
    send(m, "jobs\n");
    check("jobs", expect(m, "sleep 10", mark, 5000));
    mark = seen_len;
    send(m, "fg\n");
    check("fg", expect(m, "sleep 10", mark, 5000));
    usleep(300000);
    send(m, "\x03");
    mark = seen_len;
    send(m, "echo jc-done\n");
    check("fg_then_ctrl_c", expect(m, "jc-done\r\n", mark, 5000));

    // A background job that reads the terminal is stopped (SIGTTIN).
    mark = seen_len;
    send(m, "cat &\n");
    usleep(300000);
    send(m, "jobs\n");
    check("sigttin", expect(m, "Stopped", mark, 5000));
    mark = seen_len;
    send(m, "kill -9 %1; sleep 0.3; jobs; echo re''aped\n");
    check("kill_stopped_job", expect(m, "reaped\r\n", mark, 5000));

    send(m, "exit\n");
    int status = 0;
    long end = now_ms() + 5000;
    pid_t w = 0;
    while (now_ms() < end && (w = waitpid(c, &status, WNOHANG)) == 0) {
        struct pollfd p = {m, POLLIN, 0};
        if (poll(&p, 1, 50) > 0) {
            ssize_t n = read(m, seen + seen_len, sizeof seen - 1 - seen_len);
            if (n > 0) seen_len += n;
        }
    }
    check("exit", w == c && WIFEXITED(status));
    if (failures) {
        seen[seen_len] = 0;
        printf("--- pty transcript ---\n%s\n---\n", seen);
    }
    return failures;
}
