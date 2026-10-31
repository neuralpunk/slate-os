// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Uevent sockets and network namespaces (ADR 0185), and a listener for
// the scenarios.
//
//   uevent check             programs' messages stay in their namespace
//   uevent watch SECS [sandbox]  (a listener for trying things by hand)
//                            print "uevent: ACTION SUBSYSTEM DEVPATH DEVTYPE"
//                            for each kernel message for SECS seconds;
//                            `sandbox` listens from a user and network
//                            namespace of its own (which hears nothing)
//
// netlink(7): NETLINK_KOBJECT_UEVENT is 15, AF_NETLINK 16; the kernel
// sends on group 1, udev re-announces on group 2. unshare(2): CLONE_NEWNET
// 0x40000000, CLONE_NEWUSER 0x10000000.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

struct nl {
    unsigned short family, pad;
    unsigned port, groups;
};

static int failures;

static void check(int ok, const char *name) {
    printf("SLATE-TEST: %s user::uevent::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

static int listener(unsigned groups) {
    struct nl a = {16, 0, 0, groups};
    int s = socket(16, SOCK_RAW | SOCK_CLOEXEC, 15);
    if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof a) != 0) return -1;
    return s;
}

/// Whether `s` gets a message within `ms`.
static int hears(int s, int ms) {
    struct pollfd p = {.fd = s, .events = POLLIN};
    if (poll(&p, 1, ms) != 1) return 0;
    char b[512];
    return recv(s, b, sizeof b, 0) > 0;
}

static int send_group2(int s) {
    struct nl to = {16, 0, 0, 2};
    const char m[] = "libudev\0test";
    return sendto(s, m, sizeof m, 0, (struct sockaddr *)&to, sizeof to) == (ssize_t)sizeof m;
}

static void write_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY);
    if (fd >= 0) {
        ssize_t n = write(fd, text, strlen(text));
        (void)n;
        close(fd);
    }
}

/// A user namespace (with this uid mapped) and a network namespace.
static int sandbox(void) {
    uid_t uid = geteuid();
    gid_t gid = getegid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) return -1;
    char m[64];
    write_file("/proc/self/setgroups", "deny");
    snprintf(m, sizeof m, "%u %u 1", uid, uid);
    write_file("/proc/self/uid_map", m);
    snprintf(m, sizeof m, "%u %u 1", gid, gid);
    write_file("/proc/self/gid_map", m);
    return 0;
}

static int check_all(void) {
    // Two sockets in this namespace: one sends on group 2, the other hears.
    int here = listener(2), sender = listener(0);
    check(here >= 0 && sender >= 0, "sockets");
    check(send_group2(sender) && hears(here, 1000), "same_namespace_hears");

    // A child in a network namespace of its own (root's: owned by the
    // initial user namespace) sends on group 2: nobody here hears it, and
    // its own listener does.
    int pipefd[2];
    if (pipe(pipefd) != 0) return 1;
    pid_t pid = fork();
    if (pid == 0) {
        close(pipefd[0]);
        int ok = unshare(CLONE_NEWNET) == 0;
        int mine = listener(2), out = listener(0);
        ok = ok && mine >= 0 && out >= 0 && send_group2(out) && hears(mine, 1000);
        char c = ok ? 'y' : 'n';
        ssize_t n = write(pipefd[1], &c, 1);
        (void)n;
        _exit(0);
    }
    close(pipefd[1]);
    char c = 'n';
    ssize_t n = read(pipefd[0], &c, 1);
    (void)n;
    waitpid(pid, NULL, 0);
    check(c == 'y', "other_namespace_hears_its_own");
    check(!hears(here, 300), "other_namespace_not_heard_here");

    // Unicast to a port in another namespace is refused.
    struct nl self;
    socklen_t len = sizeof self;
    getsockname(here, (struct sockaddr *)&self, &len);
    pid = fork();
    if (pid == 0) {
        int ok = unshare(CLONE_NEWNET) == 0;
        int s = listener(0);
        struct nl to = {16, 0, self.port, 0};
        ok = ok && s >= 0 && sendto(s, "x", 1, 0, (struct sockaddr *)&to, sizeof to) < 0 && errno == ECONNREFUSED;
        _exit(ok ? 0 : 1);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "unicast_other_namespace_refused");
    return failures;
}

static int watch(int secs, int boxed) {
    if (boxed && sandbox() != 0) {
        printf("uevent: no sandbox (%s)\n", strerror(errno));
        return 1;
    }
    int s = listener(1);
    if (s < 0) {
        printf("uevent: no socket (%s)\n", strerror(errno));
        return 1;
    }
    printf("uevent: listening%s\n", boxed ? " in a sandbox" : "");
    fflush(stdout);
    int count = 0;
    char b[8192];
    struct pollfd p = {.fd = s, .events = POLLIN};
    int left = secs * 1000;
    while (left > 0) {
        int step = left < 200 ? left : 200;
        left -= step;
        if (poll(&p, 1, step) != 1) continue;
        ssize_t n = recv(s, b, sizeof b - 1, 0);
        if (n <= 0) break;
        b[n] = 0;
        const char *action = "-", *subsystem = "-", *devpath = "-", *devtype = "-";
        for (char *k = b; k < b + n; k += strlen(k) + 1) {
            if (strncmp(k, "ACTION=", 7) == 0) action = k + 7;
            if (strncmp(k, "SUBSYSTEM=", 10) == 0) subsystem = k + 10;
            if (strncmp(k, "DEVPATH=", 8) == 0) devpath = k + 8;
            if (strncmp(k, "DEVTYPE=", 8) == 0) devtype = k + 8;
        }
        printf("uevent: %s %s %s %s\n", action, subsystem, devpath, devtype);
        fflush(stdout);
        count++;
    }
    printf("uevent: done %d\n", count);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "check") == 0) return check_all();
    if (argc > 2 && strcmp(argv[1], "watch") == 0) return watch(atoi(argv[2]), argc > 3 && strcmp(argv[3], "sandbox") == 0);
    fprintf(stderr, "usage: uevent check | uevent watch SECS [sandbox]\n");
    return 2;
}
