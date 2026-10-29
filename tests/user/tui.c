// SPDX-License-Identifier: MIT OR Apache-2.0
// Full-screen programs through a pseudo-terminal: edit a file with etch
// and page through one with less, typing keys like a user.
#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;
static char seen[1 << 20];
static size_t seen_len;

static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::tui::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void pump(int m, int ms) {
    long end = now_ms() + ms;
    for (;;) {
        long left = end - now_ms();
        if (left <= 0) return;
        struct pollfd p = {m, POLLIN, 0};
        if (poll(&p, 1, (int)left) <= 0) continue;
        ssize_t n = read(m, seen + seen_len, sizeof seen - 1 - seen_len);
        if (n <= 0) return;
        seen_len += n;
        seen[seen_len] = 0;
    }
}

static int expect(int m, const char *needle, size_t from, int timeout_ms) {
    long end = now_ms() + timeout_ms;
    while (now_ms() < end) {
        seen[seen_len] = 0;
        if (from <= seen_len && strstr(seen + from, needle)) return 1;
        pump(m, 50);
    }
    return strstr(seen + from, needle) != NULL;
}

static void keys(int m, const char *s) {
    if (write(m, s, strlen(s)) < 0) perror("write");
    pump(m, 150);
}

/* Start `argv` on a new pty (80x24); returns the master, sets *pid. */
static int start(char *const argv[], pid_t *pid) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    grantpt(m);
    unlockpt(m);
    struct winsize ws = {24, 80, 0, 0};
    char *name = ptsname(m);
    *pid = fork();
    if (*pid == 0) {
        setsid();
        int s = open(name, O_RDWR);
        ioctl(s, TIOCSWINSZ, &ws);
        dup2(s, 0);
        dup2(s, 1);
        dup2(s, 2);
        if (s > 2) close(s);
        char *envp[] = {"TERM=xterm", "PATH=/bin:/usr/bin", "HOME=/tmp", NULL};
        execve(argv[0], argv, envp);
        _exit(127);
    }
    return m;
}

static int finish(int m, pid_t pid) {
    int status = -1;
    long end = now_ms() + 5000;
    while (now_ms() < end) {
        if (waitpid(pid, &status, WNOHANG) == pid) break;
        pump(m, 50);
    }
    close(m);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static char *slurp(const char *path) {
    static char buf[4096];
    int fd = open(path, O_RDONLY);
    ssize_t n = fd >= 0 ? read(fd, buf, sizeof buf - 1) : -1;
    if (fd >= 0) close(fd);
    buf[n > 0 ? n : 0] = 0;
    return buf;
}

int main(void) {
    pid_t pid;
    unlink("/tmp/tui.txt");
    char *etch[] = {"/bin/etch", "/tmp/tui.txt", NULL};
    int m = start(etch, &pid);
    check("etch_starts", expect(m, "New File", 0, 5000) && expect(m, "^X", 0, 1000));
    keys(m, "hello slate");
    keys(m, "\r");
    keys(m, "second line");
    size_t mark = seen_len;
    keys(m, "\x0f");  // ^O: write out
    check("etch_write_prompt", expect(m, "File Name to Write", mark, 3000));
    mark = seen_len;
    keys(m, "\r");
    check("etch_wrote", expect(m, "Wrote 2 lines", mark, 3000));
    keys(m, "\x18");  // ^X
    check("etch_exit", finish(m, pid) == 0);
    check("etch_file", strcmp(slurp("/tmp/tui.txt"), "hello slate\nsecond line\n") == 0);

    // Search, an edit, undo, cut; exit saving.
    m = start(etch, &pid);
    expect(m, "Read 2 lines", 0, 5000);
    keys(m, "\x17");  // ^W
    keys(m, "second\r");
    keys(m, "X");
    keys(m, "\x1bu");  // M-U undo
    keys(m, "\x0b");   // ^K cut "second line"
    keys(m, "\x1bOH"); // Home (SS3 form)
    keys(m, "\x15");   // ^U paste it back above
    mark = seen_len;
    keys(m, "\x18");
    check("etch_save_question", expect(m, "Save modified buffer", mark, 3000));
    keys(m, "y");
    keys(m, "\r");
    check("etch_exit_saved", finish(m, pid) == 0);
    check("etch_edits", strcmp(slurp("/tmp/tui.txt"), "hello slate\nsecond line\n") == 0);

    // less: page, search, go to the end, quit.
    FILE *f = fopen("/tmp/pages.txt", "w");
    for (int i = 1; i <= 100; i++) fprintf(f, "line %d\n", i);
    fclose(f);
    char *less[] = {"/bin/less", "/tmp/pages.txt", NULL};
    seen_len = 0;
    m = start(less, &pid);
    check("less_first_screen", expect(m, "line 23", 0, 5000) && expect(m, "pages.txt", 0, 1000));
    mark = seen_len;
    keys(m, " ");
    check("less_next_page", expect(m, "line 46", mark, 3000));
    mark = seen_len;
    keys(m, "/line 77\r");
    check("less_search", expect(m, "line 77", mark, 3000) && expect(m, "line 99", mark, 1000));
    mark = seen_len;
    keys(m, "G");
    check("less_end", expect(m, "(END)", mark, 3000) && expect(m, "line 100", mark, 1000));
    mark = seen_len;
    keys(m, "g");
    check("less_top", expect(m, "line 1\x1b[0m", mark, 3000));
    keys(m, "q");
    check("less_quit", finish(m, pid) == 0);
    return failures;
}
