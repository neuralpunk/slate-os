// SPDX-License-Identifier: MIT OR Apache-2.0
// Users and permissions: credential system calls, file permission checks,
// set-user-ID programs, capabilities and signal permission.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

static int failures;

static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::creds::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

#define DIR "/tmp/creds"

static int fails_with(int r, int err) { return r == -1 && errno == err; }

static void put(const char *path, const char *text, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        if (write(fd, text, strlen(text)) < 0) perror("write");
        close(fd);
    }
    chmod(path, mode);
}

/* Copy this program (for the set-user-ID probe). */
static void copy_self(const char *to) {
    int in = open("/proc/self/exe", O_RDONLY), out = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0700);
    char buf[65536];
    ssize_t n;
    while (in >= 0 && out >= 0 && (n = read(in, buf, sizeof buf)) > 0)
        if (write(out, buf, (size_t)n) != n) break;
    close(in);
    close(out);
}

static int become_user(void) {
    gid_t g = 100;
    return setgroups(1, &g) == 0 && setgid(1000) == 0 && setuid(1000) == 0;
}

struct caphdr { unsigned version; int pid; };
struct capdata { unsigned eff, perm, inh; };

/* Everything an unprivileged user may and may not do. */
static void as_user(void) {
    check("drop_privileges", become_user());
    gid_t groups[4];
    int ng = getgroups(4, groups);
    check("ids", getuid() == 1000 && geteuid() == 1000 && getgid() == 1000 && getegid() == 1000);
    check("groups", ng == 1 && groups[0] == 100);
    uid_t r, e, s;
    check("getresuid", getresuid(&r, &e, &s) == 0 && r == 1000 && e == 1000 && s == 1000);
    check("setuid_root_denied", fails_with(setuid(0), EPERM));
    check("setgroups_denied", fails_with(setgroups(0, NULL), EPERM));
    check("read_private_denied", fails_with(open(DIR "/private", O_RDONLY), EACCES));
    int fd = open(DIR "/public", O_RDONLY);
    check("read_public", fd >= 0);
    close(fd);
    check("write_public_denied", fails_with(open(DIR "/public", O_WRONLY), EACCES));
    check("truncate_denied", fails_with(truncate(DIR "/public", 0), EACCES));
    struct stat st;
    check("search_denied", fails_with(stat(DIR "/closed/inside", &st), EACCES));
    check("chdir_denied", fails_with(chdir(DIR "/closed"), EACCES));
    check("create_in_root_dir_denied", fails_with(open(DIR "/new", O_WRONLY | O_CREAT, 0644), EACCES));
    check("mkdir_denied", fails_with(mkdir(DIR "/newdir", 0755), EACCES));
    fd = open(DIR "/sticky/mine", O_WRONLY | O_CREAT, 0644);
    check("create_in_sticky", fd >= 0);
    close(fd);
    check("new_file_owner", stat(DIR "/sticky/mine", &st) == 0 && st.st_uid == 1000 && st.st_gid == 1000);
    check("sticky_unlink_denied", fails_with(unlink(DIR "/sticky/rootfile"), EPERM));
    check("sticky_rename_denied", fails_with(rename(DIR "/sticky/rootfile", DIR "/sticky/x"), EPERM));
    check("chmod_other_denied", fails_with(chmod(DIR "/public", 0666), EPERM));
    check("chmod_own", chmod(DIR "/sticky/mine", 0600) == 0);
    check("chown_to_root_denied", fails_with(chown(DIR "/sticky/mine", 0, -1), EPERM));
    check("chgrp_member", chown(DIR "/sticky/mine", -1, 100) == 0 && stat(DIR "/sticky/mine", &st) == 0 && st.st_gid == 100);
    check("chgrp_nonmember_denied", fails_with(chown(DIR "/sticky/mine", -1, 5), EPERM));
    struct timespec ts[2] = {{1, 0}, {1, 0}};
    check("utimes_other_denied", fails_with(utimensat(AT_FDCWD, DIR "/public", ts, 0), EPERM));
    check("unlink_own", unlink(DIR "/sticky/mine") == 0);
    check("access_r", access(DIR "/public", R_OK) == 0);
    check("access_w_denied", fails_with(access(DIR "/public", W_OK), EACCES));
    check("kill_root_denied", fails_with(kill(getppid(), 0), EPERM));
    check("kill_self", kill(getpid(), 0) == 0);
    check("mknod_device_denied", fails_with(mknod(DIR "/sticky/dev", S_IFCHR | 0600, makedev(1, 3)), EPERM));
    check("chroot_denied", fails_with(chroot("/"), EPERM));
    struct caphdr h = {0x20080522, 0};
    struct capdata d[2];
    check("no_capabilities", syscall(SYS_capget, &h, d) == 0 && d[0].eff == 0 && d[0].perm == 0);
    // Set-group-ID directories hand down their group.
    check("mkdir_in_setgid", mkdir(DIR "/sgid/sub", 0755) == 0 && stat(DIR "/sgid/sub", &st) == 0 && st.st_gid == 100 &&
                                 (st.st_mode & S_ISGID));
    fd = open(DIR "/sgid/f", O_WRONLY | O_CREAT, 0644);
    check("file_in_setgid", fd >= 0 && fstat(fd, &st) == 0 && st.st_gid == 100);
    close(fd);
    char buf[512] = {0};
    fd = open("/proc/self/status", O_RDONLY);
    ssize_t n = fd >= 0 ? read(fd, buf, sizeof buf - 1) : -1;
    close(fd);
    check("proc_status_uid", n > 0 && strstr(buf, "Uid:\t1000\t1000\t1000\t1000") != NULL);
    // A set-user-ID root program runs with euid 0 (and AT_SECURE).
    pid_t c = fork();
    if (c == 0) {
        execl(DIR "/suidprobe", "suidprobe", "probe", (char *)NULL);
        _exit(127);
    }
    int status = 0;
    waitpid(c, &status, 0);
    check("setuid_exec", WIFEXITED(status) && WEXITSTATUS(status) == 42);
    exit(failures);
}

/* Saved IDs let a process drop and regain privileges. */
static void saved_ids(void) {
    check("setresuid_keep_saved", setresuid(1000, 1000, 0) == 0 && geteuid() == 1000);
    check("dropped_access", fails_with(open(DIR "/private", O_RDONLY), EACCES));
    check("regain_via_saved", setuid(0) == 0 && geteuid() == 0);
    int fd = open(DIR "/private", O_RDONLY);
    check("regained_access", fd >= 0);
    close(fd);
    check("setreuid_swap", setreuid(1000, 0) == 0 && getuid() == 1000 && geteuid() == 0);
    /* access(2) searches the directories on the way as the real user too;
       AT_EACCESS checks as the effective one. */
    check("access_searches_as_real", fails_with(access(DIR "/closed/inside", R_OK), EACCES));
    check("access_eaccess", faccessat(AT_FDCWD, DIR "/closed/inside", R_OK, AT_EACCESS) == 0);
    check("setfsuid", syscall(SYS_setfsuid, 1000) == 0 && fails_with(open(DIR "/private", O_RDONLY), EACCES));
    syscall(SYS_setfsuid, 0);
    check("setuid_all", setuid(1000) == 0);
    uid_t r, e, s;
    check("all_dropped", getresuid(&r, &e, &s) == 0 && r == 1000 && e == 1000 && s == 1000 && fails_with(setuid(0), EPERM));
    exit(failures);
}

/* --- threads, set-ID bits, link restrictions, /proc, file capabilities ------ */

static long raw_geteuid(void) { return syscall(SYS_geteuid); }

static void *thread_setuid(void *arg) {
    (void)arg;
    /* The raw call changes only this thread (credentials(7)). */
    long ok = syscall(SYS_setresuid, 1000, 1000, 1000) == 0 && raw_geteuid() == 1000;
    return (void *)ok;
}

static int mode_of(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 ? (int)(st.st_mode & 07777) : -1;
}

static int read_text(const char *path, char *buf, size_t len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, len - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n] = 0;
    return 0;
}

/* File capabilities as Linux writes them: revision 2 (0x02000000), the
   effective flag, then permitted and inheritable, low halves first. */
static void cap_value(unsigned char v[20], unsigned permitted, int effective) {
    unsigned w[5] = {0x02000000u | (effective ? 1u : 0u), permitted, 0, 0, 0};
    memcpy(v, w, sizeof w);
}

static void as_user_details(void) {
    become_user();
    /* Writes by the owner clear the set-ID bits (set-group-ID only when
       group-executable); truncating does too. */
    put(DIR "/sticky/mine-sid", "x\n", 0600);
    chmod(DIR "/sticky/mine-sid", 06755);
    int fd = open(DIR "/sticky/mine-sid", O_WRONLY | O_APPEND);
    check("write_clears_setid", fd >= 0 && write(fd, "y", 1) == 1 && mode_of(DIR "/sticky/mine-sid") == 0755);
    close(fd);
    chmod(DIR "/sticky/mine-sid", 02644);
    fd = open(DIR "/sticky/mine-sid", O_WRONLY | O_APPEND);
    check("write_keeps_lock_bit", fd >= 0 && write(fd, "y", 1) == 1 && mode_of(DIR "/sticky/mine-sid") == 02644);
    close(fd);
    chmod(DIR "/sticky/mine-sid", 04755);
    check("truncate_clears_setid", truncate(DIR "/sticky/mine-sid", 0) == 0 && mode_of(DIR "/sticky/mine-sid") == 0755);
    unlink(DIR "/sticky/mine-sid");
    /* protected_hardlinks: no link to someone else's file we can't write. */
    check("hardlink_denied", fails_with(link(DIR "/public", DIR "/sticky/hl"), EPERM));
    put(DIR "/sticky/own", "o\n", 0644);
    check("hardlink_own", link(DIR "/sticky/own", DIR "/sticky/own2") == 0);
    unlink(DIR "/sticky/own2");
    unlink(DIR "/sticky/own");
    /* Another user's processes are hidden (ADR 0032; our parent runs as
       root). */
    char buf[256], path[64];
    snprintf(path, sizeof path, "/proc/%d/status", (int)getppid());
    check("proc_other_user_hidden", fails_with(open(path, O_RDONLY), ENOENT));
    /* Changing IDs made this process not dumpable: then even our user's
       other processes can't read its private entries (ptrace(2)'s access
       check), only the public ones; we read our own. */
    check("not_dumpable_after_setuid", prctl(PR_GET_DUMPABLE) == 0);
    check("proc_maps_own", read_text("/proc/self/maps", buf, sizeof buf) == 0);
    check("proc_exe_own", readlink("/proc/self/exe", buf, sizeof buf) > 0);
    pid_t me = getpid(), c;
    int st = 0;
    if ((c = fork()) == 0) {
        int bad = 0;
        snprintf(path, sizeof path, "/proc/%d/environ", (int)me);
        bad += !fails_with(open(path, O_RDONLY), EACCES);
        snprintf(path, sizeof path, "/proc/%d/maps", (int)me);
        bad += !fails_with(open(path, O_RDONLY), EACCES);
        snprintf(path, sizeof path, "/proc/%d/exe", (int)me);
        bad += !fails_with(readlink(path, buf, sizeof buf), EACCES);
        snprintf(path, sizeof path, "/proc/%d/fd", (int)me);
        bad += !fails_with(open(path, O_RDONLY | O_DIRECTORY), EACCES);
        snprintf(path, sizeof path, "/proc/%d/status", (int)me);
        bad += read_text(path, buf, sizeof buf) != 0;
        _exit(bad);
    }
    waitpid(c, &st, 0);
    check("proc_private_not_dumpable", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    prctl(PR_SET_DUMPABLE, 1);
    if ((c = fork()) == 0) {
        snprintf(path, sizeof path, "/proc/%d/maps", (int)me);
        _exit(read_text(path, buf, sizeof buf) == 0 ? 0 : 1);
    }
    waitpid(c, &st, 0);
    check("proc_private_dumpable", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    /* signalfd reports kill(2)'s sender. */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);
    int sfd = signalfd(-1, &set, 0);
    c = fork();
    if (c == 0) _exit(kill(getppid(), SIGUSR1) == 0 ? 0 : 1);
    struct signalfd_siginfo si;
    int got = sfd >= 0 && read(sfd, &si, sizeof si) == sizeof si;
    check("signalfd_sender", got && si.ssi_signo == SIGUSR1 && si.ssi_pid == (unsigned)c && si.ssi_uid == 1000);
    waitpid(c, NULL, 0);
    close(sfd);
    /* File capabilities: CAP_KILL (5), permitted and effective. */
    c = fork();
    if (c == 0) {
        execl(DIR "/capprobe", "capprobe", "caps", (char *)NULL);
        _exit(127);
    }
    waitpid(c, &st, 0);
    check("file_caps_exec", WIFEXITED(st) && WEXITSTATUS(st) == 43);
    /* Capabilities set for another namespace's root don't count. */
    c = fork();
    if (c == 0) {
        execl(DIR "/capprobe3", "capprobe3", "caps", (char *)NULL);
        _exit(127);
    }
    waitpid(c, &st, 0);
    check("file_caps_other_root", WIFEXITED(st) && WEXITSTATUS(st) == 1);
    /* Set in a user namespace, they name its root (revision 3). */
    put(DIR "/sticky/nscap", "n\n", 0755);
    c = fork();
    if (c == 0) {
        unsigned char v[20];
        cap_value(v, 1u << 5, 1);
        int ok = unshare(CLONE_NEWUSER) == 0;
        int f = open("/proc/self/setgroups", O_WRONLY);
        ok = ok && f >= 0 && write(f, "deny", 4) == 4;
        close(f);
        f = open("/proc/self/uid_map", O_WRONLY);
        ok = ok && f >= 0 && write(f, "0 1000 1", 8) == 8;
        close(f);
        f = open("/proc/self/gid_map", O_WRONLY);
        ok = ok && f >= 0 && write(f, "0 1000 1", 8) == 8;
        close(f);
        ok = ok && setxattr(DIR "/sticky/nscap", "security.capability", v, sizeof v, 0) == 0;
        unsigned char back[32];
        ok = ok && getxattr(DIR "/sticky/nscap", "security.capability", back, sizeof back) == 20;
        _exit(ok ? 0 : 1);
    }
    waitpid(c, &st, 0);
    check("file_caps_set_in_userns", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    exit(failures);
}

static void cred_details(void) {
    /* Each thread has its own IDs. */
    pthread_t t;
    void *ok = 0;
    pid_t c = fork();
    if (c == 0) {
        int good = pthread_create(&t, NULL, thread_setuid, NULL) == 0 && pthread_join(t, &ok) == 0 && ok;
        _exit(good && raw_geteuid() == 0 ? 0 : 1);
    }
    int st = 0;
    waitpid(c, &st, 0);
    check("per_thread_ids", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    /* Root (CAP_FSETID) keeps the set-ID bits when it writes. */
    put(DIR "/root-sid", "x\n", 06755);
    int fd = open(DIR "/root-sid", O_WRONLY | O_APPEND);
    check("root_write_keeps_setid", fd >= 0 && write(fd, "y", 1) == 1 && mode_of(DIR "/root-sid") == 06755);
    close(fd);
    unlink(DIR "/root-sid");
    /* protected_symlinks, protected_regular and protected_fifos: another
       user's link or file in a sticky world-writable directory. */
    char buf[8] = "";
    check("protected_sysctl", read_text("/proc/sys/fs/protected_symlinks", buf, sizeof buf) == 0 && buf[0] == '1');
    symlink(DIR "/public", DIR "/sticky/evil");
    lchown(DIR "/sticky/evil", 2000, 2000);
    check("symlink_protected", fails_with(open(DIR "/sticky/evil", O_RDONLY), EACCES));
    put(DIR "/sticky/theirs", "t\n", 0666);
    chown(DIR "/sticky/theirs", 2000, 2000);
    check("regular_protected", fails_with(open(DIR "/sticky/theirs", O_WRONLY | O_CREAT, 0644), EACCES));
    fd = open(DIR "/sticky/theirs", O_WRONLY);
    check("regular_without_creat", fd >= 0);
    close(fd);
    mkfifo(DIR "/sticky/fifo", 0666);
    chown(DIR "/sticky/fifo", 2000, 2000);
    check("fifo_protected", fails_with(open(DIR "/sticky/fifo", O_RDONLY | O_CREAT | O_NONBLOCK, 0644), EACCES));
    fd = open("/proc/sys/fs/protected_symlinks", O_WRONLY);
    check("protected_off", fd >= 0 && write(fd, "0", 1) == 1);
    close(fd);
    fd = open(DIR "/sticky/evil", O_RDONLY);
    check("symlink_unprotected", fd >= 0);
    close(fd);
    fd = open("/proc/sys/fs/protected_symlinks", O_WRONLY);
    check("protected_on", fd >= 0 && write(fd, "1", 1) == 1);
    close(fd);
    unlink(DIR "/sticky/evil");
    unlink(DIR "/sticky/theirs");
    unlink(DIR "/sticky/fifo");
    /* File capabilities on copies of this program; one for the root of
       another namespace (revision 3, root ID 1000). */
    unsigned char v[20];
    cap_value(v, 1u << 5, 1);
    copy_self(DIR "/capprobe");
    chmod(DIR "/capprobe", 0755);
    check("set_file_caps", setxattr(DIR "/capprobe", "security.capability", v, sizeof v, 0) == 0);
    copy_self(DIR "/capprobe3");
    chmod(DIR "/capprobe3", 0755);
    unsigned w3[6] = {0x03000001u, 1u << 5, 0, 0, 0, 1000};
    unsigned char back[32];
    check("set_file_caps_v3", setxattr(DIR "/capprobe3", "security.capability", w3, sizeof w3, 0) == 0 &&
                                  getxattr(DIR "/capprobe3", "security.capability", back, sizeof back) == 24);
    check("bad_file_caps", fails_with(setxattr(DIR "/capprobe3", "security.capability", v, 7, 0), EINVAL));
    c = fork();
    if (c == 0) as_user_details();
    waitpid(c, &st, 0);
    failures += WIFEXITED(st) ? WEXITSTATUS(st) : 1;
    /* The user namespace's capabilities read as revision 3 from outside. */
    check("userns_caps_v3", getxattr(DIR "/sticky/nscap", "security.capability", back, sizeof back) == 24 &&
                                memcmp(back + 20, &(unsigned){1000}, 4) == 0);
    unlink(DIR "/sticky/nscap");
    unlink(DIR "/capprobe");
    unlink(DIR "/capprobe3");
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "probe") == 0)
        return geteuid() == 0 && getuid() == 1000 && getauxval(AT_SECURE) == 1 ? 42 : 1;
    if (argc > 1 && strcmp(argv[1], "caps") == 0) {
        struct caphdr h = {0x20080522, 0};
        struct capdata d[2];
        int have = syscall(SYS_capget, &h, d) == 0 && (d[0].eff & (1u << 5)) && (d[0].perm & (1u << 5));
        return have && getuid() == 1000 && getauxval(AT_SECURE) == 1 ? 43 : 1;
    }

    mkdir(DIR, 0755);
    put(DIR "/private", "secret\n", 0600);
    put(DIR "/public", "hello\n", 0644);
    put(DIR "/zero", "z\n", 0000);
    put(DIR "/noexec", "#!/bin/sh\n", 0644);
    mkdir(DIR "/closed", 0700);
    put(DIR "/closed/inside", "x\n", 0644);
    mkdir(DIR "/sticky", 0777);
    chmod(DIR "/sticky", 01777);
    put(DIR "/sticky/rootfile", "r\n", 0644);
    mkdir(DIR "/sgid", 0777);
    chown(DIR "/sgid", 0, 100);
    chmod(DIR "/sgid", 02777);
    copy_self(DIR "/suidprobe");
    chmod(DIR "/suidprobe", 04755);

    struct stat st;
    check("root_ids", getuid() == 0 && geteuid() == 0);
    check("suid_bit_kept", stat(DIR "/suidprobe", &st) == 0 && (st.st_mode & 07777) == 04755);
    int fd = open(DIR "/zero", O_RDONLY);
    check("root_reads_mode_0", fd >= 0);
    close(fd);
    check("root_needs_exec_bit", fails_with(access(DIR "/noexec", X_OK), EACCES));
    check("root_exec_denied", fails_with(execl(DIR "/noexec", "noexec", (char *)NULL), EACCES));
    struct caphdr h = {0x20080522, 0};
    struct capdata d[2];
    check("root_capabilities", syscall(SYS_capget, &h, d) == 0 && d[0].eff == 0xffffffff && d[0].perm == 0xffffffff);
    check("bad_cap_version", syscall(SYS_capget, &(struct caphdr){1, 0}, d) == -1 && errno == EINVAL);

    int status = 0;
    pid_t c = fork();
    if (c == 0) as_user();
    waitpid(c, &status, 0);
    failures += WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    c = fork();
    if (c == 0) saved_ids();
    waitpid(c, &status, 0);
    failures += WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    cred_details();

    // chown by root clears set-user-ID.
    check("chown_clears_suid", chown(DIR "/suidprobe", 1000, -1) == 0 && stat(DIR "/suidprobe", &st) == 0 &&
                                   !(st.st_mode & S_ISUID));
    check("summary", failures == 0);
    return failures;
}
