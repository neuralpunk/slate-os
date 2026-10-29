// SPDX-License-Identifier: MIT OR Apache-2.0
// Error numbers in corner cases, each as Linux was seen to give it (the
// same program run on the host): GAPS.md's "Errno details still
// differing", from the LTP subset. `errnos print` prints every outcome
// instead of checking it (to compare with the host's).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures, printing;

/* futex(2): FUTEX_CMP_REQUEUE. */
#define FUTEX_CMP_REQUEUE_ 4

/* The outcome of a call: its errno's name, or "ok". */
static const char *outcome(long r) {
    static const struct {
        int e;
        const char *name;
    } names[] = {
        {EINVAL, "EINVAL"}, {EPROTONOSUPPORT, "EPROTONOSUPPORT"}, {ECHILD, "ECHILD"}, {EBADF, "EBADF"},
        {EOPNOTSUPP, "EOPNOTSUPP"}, {EISDIR, "EISDIR"}, {EFAULT, "EFAULT"}, {ESRCH, "ESRCH"},
        {EPERM, "EPERM"}, {EACCES, "EACCES"}, {ENOSYS, "ENOSYS"}, {ENOENT, "ENOENT"},
        {EEXIST, "EEXIST"}, {ENOTDIR, "ENOTDIR"}, {ESOCKTNOSUPPORT, "ESOCKTNOSUPPORT"}, {EROFS, "EROFS"},
    };
    static char buf[32];
    if (r != -1) return "ok";
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        if (names[i].e == errno) return names[i].name;
    snprintf(buf, sizeof buf, "errno %d", errno);
    return buf;
}

static void expect(const char *name, long r, const char *want) {
    const char *got = outcome(r);
    if (printing) {
        printf("%s %s\n", name, got);
        return;
    }
    int ok = strcmp(got, want) == 0;
    printf("SLATE-TEST: %s user::errnos::%s%s%s%s\n", ok ? "PASS" : "FAIL", name, ok ? "" : " (got ", ok ? "" : got,
           ok ? "" : ")");
    fflush(stdout);
    failures += !ok;
}

static volatile int handled;
static void on_usr1(int s, siginfo_t *si, void *ctx) {
    (void)s, (void)si, (void)ctx;
    handled++;
}

int main(int argc, char **argv) {
    printing = argc > 1 && strcmp(argv[1], "print") == 0;
    char dir[] = "/tmp/errnosXXXXXX";
    if (!mkdtemp(dir)) return 1;
    if (chdir(dir) != 0) return 1;
    close(open("plain", O_CREAT | O_WRONLY, 0644));
    mkdir("sub", 0755);
    symlink("sub", "to-sub");

    expect("readlink_not_link", readlink("plain", (char[16]){0}, 16), "EINVAL");
    expect("rmdir_dot", rmdir("."), "EINVAL");
    expect("rmdir_dot_in_path", rmdir("sub/."), "EINVAL");
    expect("select_negative", select(-1, NULL, NULL, NULL, &(struct timeval){0, 0}), "EINVAL");
    expect("socket_bad_type", socket(AF_INET, 77, 0), "EINVAL");
    expect("socketpair_bad_protocol", socketpair(AF_UNIX, SOCK_STREAM, 7, (int[2]){0}), "EPROTONOSUPPORT");
    expect("wait4_no_such_child", wait4(999999, NULL, 0, NULL), "ECHILD");
    expect("waitpid_bad_options", waitpid(-1, NULL, 0x10000), "EINVAL");
    expect("mmap_bad_fd_and_offset", (long)mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 99, 1) == (long)MAP_FAILED ? -1 : 0,
           "EINVAL");
    expect("mmap_bad_fd", (long)mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 99, 0) == (long)MAP_FAILED ? -1 : 0, "EBADF");
    int fd = open("plain", O_RDWR);
    expect("map_shared_validate_unknown",
           (long)mmap(NULL, 4096, PROT_READ, MAP_SHARED_VALIDATE | 0x800000, fd, 0) == (long)MAP_FAILED ? -1 : 0,
           "EOPNOTSUPP");
    close(fd);
    expect("creat_through_link_to_dir", open("to-sub", O_CREAT | O_WRONLY, 0644), "EISDIR");
    expect("prctl_bad_pointer", prctl(PR_GET_PDEATHSIG, (void *)8), "EFAULT");
    int word = 0;
    expect("futex_requeue_negative", syscall(SYS_futex, &word, FUTEX_CMP_REQUEUE_, -1, -1, &word, 0), "EINVAL");
    int p[2];
    if (pipe(p) == 0) {
        expect("fsync_pipe", fsync(p[0]), "EINVAL");
        close(p[0]);
        close(p[1]);
    }
    expect("setpgid_negative", setpgid(0, -1), "EINVAL");
    expect("setpgid_no_such_process", setpgid(999999, 0), "ESRCH");
    pid_t kid = fork();
    if (kid == 0) {
        setsid();
        pause();
        _exit(0);
    }
    usleep(100000);
    /* A child in another session: its group can't be changed, nor can we
       join its group. */
    expect("setpgid_other_session", setpgid(kid, kid), "EPERM");
    expect("setpgid_group_elsewhere", setpgid(0, kid), "EPERM");
    kill(kid, SIGKILL);
    waitpid(kid, NULL, 0);

    /* pwrite on an O_APPEND file appends (pwrite(2), BUGS). */
    fd = open("plain", O_WRONLY | O_APPEND);
    long w = write(fd, "abcd", 4) + pwrite(fd, "XY", 2, 0);
    close(fd);
    char buf[16] = {0};
    fd = open("plain", O_RDONLY);
    long n = read(fd, buf, sizeof buf - 1);
    close(fd);
    expect("pwrite_append", w == 6 && n == 6 && strcmp(buf, "abcdXY") == 0 ? 0 : -1, "ok");

    /* SA_RESETHAND: the handler goes back to the default, but the flags
       stay, SA_SIGINFO included. */
    struct sigaction sa = {0}, now = {0};
    sa.sa_sigaction = on_usr1;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigaction(SIGUSR1, &sa, NULL);
    raise(SIGUSR1);
    sigaction(SIGUSR1, NULL, &now);
    expect("resethand_keeps_flags",
           handled == 1 && now.sa_handler == SIG_DFL && (now.sa_flags & (SA_SIGINFO | SA_RESETHAND)) ==
                   (SA_SIGINFO | SA_RESETHAND)
               ? 0
               : -1,
           "ok");

    /* A file mapped shared sees writes past its first 64 KiB, and they
       see writes through the mapping (GAPS.md's "lost update"). */
    fd = open("mapped", O_RDWR | O_CREAT | O_TRUNC, 0600);
    size_t len = 128 << 10;
    char *m = fd >= 0 && ftruncate(fd, len) == 0 ? mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) : MAP_FAILED;
    int coherent = m != MAP_FAILED;
    if (coherent) {
        char c = 0;
        coherent = pwrite(fd, "w", 1, 65537) == 1 && m[65537] == 'w';
        m[65538] = 'm';
        coherent = coherent && pread(fd, &c, 1, 65538) == 1 && c == 'm';
        coherent = coherent && msync(m, len, MS_SYNC) == 0 && munmap(m, len) == 0;
        m = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
        coherent = coherent && m != MAP_FAILED && m[65537] == 'w' && m[65538] == 'm';
        if (m != MAP_FAILED) munmap(m, len);
    }
    if (fd >= 0) close(fd);
    unlink("mapped");
    expect("mapped_writes_coherent", coherent ? 0 : -1, "ok");

    /* Root may run a file with any execute bit, but not one with none. */
    if (geteuid() == 0) expect("root_access_no_exec_bit", access("plain", X_OK), "EACCES");

    unlink("to-sub");
    unlink("plain");
    rmdir("sub");
    if (chdir("/") != 0) return 1;
    rmdir(dir);
    return failures;
}
