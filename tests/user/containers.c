// SPDX-License-Identifier: MIT OR Apache-2.0
// Container building blocks (M15, ADR 0028): UTS, mount, PID, user and
// network namespaces, setns through /proc/<pid>/ns, pivot_root, cgroup v2
// and its device programs, xattrs, memfd and seals, shared tmpfs mappings,
// overlayfs, seccomp, pidfds, waitid, close_range and /proc/sys; and what
// Flatpak's bubblewrap needs (ADR 0114).
// Constants and structures come from the man pages named next to them.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <ucontext.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

static int failures;

static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::containers::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

/* Run `fn` in a child (made with clone flags `flags`); its exit status is
   the number of failed checks it saw. */
static int in_child(int (*fn)(void), int flags) {
    pid_t pid = (pid_t)syscall(SYS_clone, SIGCHLD | flags, 0, 0, 0, 0);
    if (pid == 0) _exit(fn());
    if (pid < 0) return -1;
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static int put(const char *path, const char *text) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, text, strlen(text));
    close(fd);
    return n == (ssize_t)strlen(text) ? 0 : -1;
}

static int get(const char *path, char *buf, size_t len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, len - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n] = 0;
    return 0;
}

#define CHILD_CHECK(name, ok)                                   \
    do {                                                        \
        int ok_ = (ok);                                         \
        if (!ok_) fprintf(stderr, "containers: %s failed (errno %d)\n", name, errno); \
        bad += !ok_;                                            \
    } while (0)

/* --- UTS ------------------------------------------------------------------ */

static int uts_child(void) {
    int bad = 0;
    CHILD_CHECK("unshare", unshare(CLONE_NEWUTS) == 0);
    CHILD_CHECK("sethostname", sethostname("box", 3) == 0);
    char h[64] = "";
    gethostname(h, sizeof h);
    CHILD_CHECK("own_name", strcmp(h, "box") == 0);
    return bad;
}

static void uts(void) {
    char before[64] = "", after[64] = "";
    gethostname(before, sizeof before);
    check("uts_child", in_child(uts_child, 0) == 0);
    gethostname(after, sizeof after);
    check("uts_isolated", strcmp(before, after) == 0);
}

/* --- mount namespaces and pivot_root -------------------------------------- */

static int mnt_child(void) {
    int bad = 0;
    CHILD_CHECK("unshare", unshare(CLONE_NEWNS) == 0);
    CHILD_CHECK("mount", mount("t", "/tmp/nsmnt", "tmpfs", 0, 0) == 0);
    int fd = open("/tmp/nsmnt/inside", O_CREAT | O_WRONLY, 0644);
    CHILD_CHECK("create", fd >= 0);
    close(fd);
    return bad;
}

static int pivot_child(void) {
    int bad = 0;
    CHILD_CHECK("unshare", unshare(CLONE_NEWNS) == 0);
    CHILD_CHECK("private", mount("none", "/", 0, MS_REC | MS_PRIVATE, 0) == 0);
    CHILD_CHECK("mount", mount("t", "/tmp/newroot", "tmpfs", 0, 0) == 0);
    CHILD_CHECK("mkdir_old", mkdir("/tmp/newroot/old", 0755) == 0);
    CHILD_CHECK("marker", mkdir("/tmp/newroot/marker", 0755) == 0);
    CHILD_CHECK("mkdir_proc", mkdir("/tmp/newroot/proc", 0755) == 0);
    CHILD_CHECK("chdir", chdir("/tmp/newroot") == 0);
    CHILD_CHECK("pivot_root", syscall(SYS_pivot_root, ".", "old") == 0);
    CHILD_CHECK("chdir_root", chdir("/") == 0);
    struct stat st;
    CHILD_CHECK("new_root", stat("/marker", &st) == 0);
    /* Paths are seen from the new root (proc(5): /proc/[pid]/fd/ links
       name the file as the reader's root sees it; bwrap reads them). */
    char link[64] = "";
    CHILD_CHECK("proc_mount", mount("proc", "/proc", "proc", 0, 0) == 0);
    int mfd = open("/marker", O_RDONLY | O_DIRECTORY);
    char fdpath[40];
    snprintf(fdpath, sizeof fdpath, "/proc/self/fd/%d", mfd);
    ssize_t ln = readlink(fdpath, link, sizeof link - 1);
    if (ln >= 0) link[ln] = 0;
    CHILD_CHECK("fd_path_in_new_root", mfd >= 0 && strcmp(link, "/marker") == 0);
    close(mfd);
    CHILD_CHECK("umount_proc", umount2("/proc", 0) == 0);
    /* The old root is under /old; the new root's mount left its old place. */
    CHILD_CHECK("old_root_there", stat("/old/tmp/nsmnt", &st) == 0);
    CHILD_CHECK("moved_away", stat("/old/tmp/newroot/marker", &st) == -1);
    CHILD_CHECK("detach_old", umount2("/old", MNT_DETACH) == 0);
    CHILD_CHECK("old_gone", stat("/old/tmp", &st) == -1 && errno == ENOENT);
    return bad;
}

static void mounts(void) {
    mkdir("/tmp/nsmnt", 0755);
    check("mnt_child", in_child(mnt_child, 0) == 0);
    struct stat st;
    check("mnt_isolated", stat("/tmp/nsmnt/inside", &st) == -1 && errno == ENOENT);
    mkdir("/tmp/newroot", 0755);
    check("pivot_root", in_child(pivot_child, 0) == 0);
    check("pivot_isolated", stat("/tmp/newroot/marker", &st) == -1 && stat("/proc/self", &st) == 0);
}

/* --- PID namespaces --------------------------------------------------------- */

static int pid_init(void) {
    int bad = 0;
    CHILD_CHECK("is_init", getpid() == 1);
    CHILD_CHECK("no_parent", getppid() == 0);
    CHILD_CHECK("tid", syscall(SYS_gettid) == 1);
    pid_t c = fork();
    if (c == 0) {
        if (getpid() != 2 || getppid() != 1) _exit(1);
        pause();
        _exit(0);
    }
    CHILD_CHECK("child_pid", c == 2);
    CHILD_CHECK("kill", kill(c, SIGKILL) == 0);
    int st = 0;
    CHILD_CHECK("wait", waitpid(c, &st, 0) == 2 && WIFSIGNALED(st));
    CHILD_CHECK("outside_invisible", kill(1000000, 0) == -1 && errno == ESRCH);
    /* A process left behind dies with init. */
    if (fork() == 0) {
        pause();
        _exit(0);
    }
    return bad;
}

static int pid_unshare(void) {
    int bad = 0;
    CHILD_CHECK("unshare", unshare(CLONE_NEWPID) == 0);
    CHILD_CHECK("self_unchanged", getpid() != 1);
    pid_t c = fork();
    if (c == 0) _exit(getpid() == 1 ? 0 : 1);
    int st = 0;
    CHILD_CHECK("first_child_is_init", waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    /* Its init is gone: the namespace takes no one else. */
    CHILD_CHECK("dead_ns", fork() == -1 && errno == ENOMEM);
    return bad;
}

static void pids(void) {
    check("pid_init", in_child(pid_init, CLONE_NEWPID) == 0);
    check("pid_unshare", in_child(pid_unshare, 0) == 0);
}

/* --- user namespaces -------------------------------------------------------- */

static int userns_child(void) {
    int bad = 0;
    char buf[128];
    CHILD_CHECK("drop", setgid(1000) == 0 && setuid(1000) == 0);
    CHILD_CHECK("no_caps_outside", sethostname("x", 1) == -1 && errno == EPERM);
    CHILD_CHECK("unshare", unshare(CLONE_NEWUSER) == 0);
    CHILD_CHECK("unmapped_id", getuid() == 65534);
    CHILD_CHECK("other_uid_refused", put("/proc/self/uid_map", "0 0 1") == -1 && errno == EPERM);
    CHILD_CHECK("uid_map", put("/proc/self/uid_map", "0 1000 1") == 0);
    CHILD_CHECK("uid_map_once", put("/proc/self/uid_map", "0 1000 1") == -1 && errno == EPERM);
    CHILD_CHECK("gid_map_needs_deny", put("/proc/self/gid_map", "0 1000 1") == -1 && errno == EPERM);
    CHILD_CHECK("setgroups_deny", put("/proc/self/setgroups", "deny") == 0);
    CHILD_CHECK("gid_map", put("/proc/self/gid_map", "0 1000 1") == 0);
    CHILD_CHECK("root_inside", getuid() == 0 && geteuid() == 0 && getgid() == 0);
    CHILD_CHECK("map_shown", get("/proc/self/uid_map", buf, sizeof buf) == 0 && strstr(buf, "1000") != 0);
    /* Capabilities count only inside: the host's UTS namespace is not ours. */
    CHILD_CHECK("host_uts_refused", sethostname("x", 1) == -1 && errno == EPERM);
    CHILD_CHECK("own_uts", unshare(CLONE_NEWUTS) == 0 && sethostname("inner", 5) == 0);
    CHILD_CHECK("own_mnt", unshare(CLONE_NEWNS) == 0 && mount("t", "/tmp/nsmnt", "tmpfs", 0, 0) == 0);
    CHILD_CHECK("no_block_fs", mount("/dev/vda", "/tmp/nsmnt", "ext4", 0, 0) == -1 && errno == EPERM);
    /* Host root's files: unmapped (65534) and no override. */
    struct stat st;
    CHILD_CHECK("root_file_unmapped", stat("/etc/shadow", &st) == 0 && st.st_uid == 65534);
    CHILD_CHECK("no_dac_override", open("/etc/shadow", O_RDONLY) == -1 && errno == EACCES);
    CHILD_CHECK("setgroups_denied", setgroups(0, 0) == -1 && errno == EPERM);
    int fd = open("/tmp/uns/file", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    CHILD_CHECK("create", fd >= 0);
    close(fd);
    CHILD_CHECK("owned_by_root_inside", stat("/tmp/uns/file", &st) == 0 && st.st_uid == 0);
    return bad;
}

static void userns(void) {
    mkdir("/tmp/uns", 0777);
    chmod("/tmp/uns", 0777);
    check("userns_child", in_child(userns_child, 0) == 0);
    struct stat st;
    check("userns_owner_outside", stat("/tmp/uns/file", &st) == 0 && st.st_uid == 1000 && st.st_gid == 1000);
    unlink("/tmp/uns/file");
    rmdir("/tmp/uns");
}

/* --- /proc/<pid>/ns and setns ----------------------------------------------- */

static int setns_child(void) {
    int bad = 0;
    char path[64], h[64] = "";
    snprintf(path, sizeof path, "/proc/%d/ns/uts", getppid());
    int fd = open(path, O_RDONLY);
    CHILD_CHECK("open_ns", fd >= 0);
    CHILD_CHECK("setns", setns(fd, CLONE_NEWUTS) == 0);
    CHILD_CHECK("wrong_kind", setns(fd, CLONE_NEWNS) == -1 && errno == EINVAL);
    gethostname(h, sizeof h);
    CHILD_CHECK("joined", strcmp(h, "nsbox") == 0);
    close(fd);
    return bad;
}

static int setns_parent(void) {
    int bad = 0;
    CHILD_CHECK("unshare", unshare(CLONE_NEWUTS) == 0 && sethostname("nsbox", 5) == 0);
    char link[64] = "";
    ssize_t n = readlink("/proc/self/ns/uts", link, sizeof link - 1);
    if (n > 0) link[n] = 0;
    struct stat st;
    unsigned long ino = 0;
    CHILD_CHECK("link_format", n > 0 && sscanf(link, "uts:[%lu]", &ino) == 1);
    CHILD_CHECK("inode_names_it", stat("/proc/self/ns/uts", &st) == 0 && st.st_ino == ino);
    CHILD_CHECK("join", in_child(setns_child, 0) == 0);
    return bad;
}

static void namespace_files(void) {
    check("setns", in_child(setns_parent, 0) == 0);
}

/* --- cgroup v2 -------------------------------------------------------------- */

static int cgroup_child(void) {
    int bad = 0;
    char buf[128], me[16];
    snprintf(me, sizeof me, "%d", getpid());
    CHILD_CHECK("limit", put("/sys/fs/cgroup/ctest/pids.max", "2") == 0);
    CHILD_CHECK("join", put("/sys/fs/cgroup/ctest/cgroup.procs", me) == 0);
    CHILD_CHECK("proc_cgroup", get("/proc/self/cgroup", buf, sizeof buf) == 0 && strcmp(buf, "0::/ctest\n") == 0);
    pid_t a = fork();
    if (a == 0) {
        pause();
        _exit(0);
    }
    CHILD_CHECK("first_fork", a > 0);
    CHILD_CHECK("current", get("/sys/fs/cgroup/ctest/pids.current", buf, sizeof buf) == 0 && atoi(buf) == 2);
    pid_t b = fork();
    if (b == 0) _exit(0);
    CHILD_CHECK("limit_enforced", b == -1 && errno == EAGAIN);
    kill(a, SIGKILL);
    waitpid(a, 0, 0);
    return bad;
}

static void cgroups(void) {
    struct stat st;
    check("cgroupfs_mounted", stat("/sys/fs/cgroup/cgroup.controllers", &st) == 0);
    check("cgroup_mkdir", mkdir("/sys/fs/cgroup/ctest", 0755) == 0);
    check("cgroup_files", stat("/sys/fs/cgroup/ctest/pids.max", &st) == 0);
    check("cgroup_limit", in_child(cgroup_child, 0) == 0);
    check("cgroup_rmdir", rmdir("/sys/fs/cgroup/ctest") == 0);
}

/* --- extended attributes ---------------------------------------------------- */

static void xattrs(void) {
    const char *f = "/tmp/xattr-file";
    int fd = open(f, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    close(fd);
    char buf[64] = "";
    check("xattr_set", setxattr(f, "user.color", "blue", 4, 0) == 0);
    check("xattr_get", getxattr(f, "user.color", buf, sizeof buf) == 4 && memcmp(buf, "blue", 4) == 0);
    check("xattr_size_query", getxattr(f, "user.color", 0, 0) == 4);
    check("xattr_create_exists", setxattr(f, "user.color", "red", 3, XATTR_CREATE) == -1 && errno == EEXIST);
    check("xattr_replace_missing", setxattr(f, "user.size", "1", 1, XATTR_REPLACE) == -1 && errno == ENODATA);
    check("xattr_trusted", setxattr(f, "trusted.t", "x", 1, 0) == 0);
    ssize_t n = listxattr(f, buf, sizeof buf);
    check("xattr_list", n == (ssize_t)(sizeof "user.color" + sizeof "trusted.t") && memmem(buf, (size_t)n, "user.color", 10));
    check("xattr_range", getxattr(f, "user.color", buf, 2) == -1 && errno == ERANGE);
    check("xattr_remove", removexattr(f, "user.color") == 0 && getxattr(f, "user.color", buf, sizeof buf) == -1 && errno == ENODATA);
    check("xattr_no_acls", setxattr(f, "system.posix_acl_access", "x", 1, 0) == -1 && errno == EOPNOTSUPP);
    unlink(f);
}

/* --- memfd, seals, shared mappings, fexecve ----------------------------------- */

/* memfd_create(2) and fcntl(2) seal values. */
#define MFD_CLOEXEC_ 1U
#define MFD_ALLOW_SEALING_ 2U
#define F_ADD_SEALS_ 1033
#define F_GET_SEALS_ 1034
#define F_SEAL_SEAL_ 1
#define F_SEAL_SHRINK_ 2
#define F_SEAL_GROW_ 4
#define F_SEAL_WRITE_ 8

static void memfds(void) {
    int fd = (int)syscall(SYS_memfd_create, "test", MFD_CLOEXEC_ | MFD_ALLOW_SEALING_);
    check("memfd_create", fd >= 0);
    check("memfd_write", write(fd, "hello", 5) == 5);
    char link[64] = "";
    char path[32];
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(path, link, sizeof link - 1);
    check("memfd_name", n > 0 && strstr(link, "memfd:test") != 0);
    /* A shared mapping sees writes made through the file and the other way. */
    char *m = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check("memfd_mmap_shared", m != MAP_FAILED);
    if (m != MAP_FAILED) {
        check("shared_sees_file", memcmp(m, "hello", 5) == 0);
        memcpy(m, "HE", 2);
        char b[6] = "";
        check("file_sees_shared", pread(fd, b, 5, 0) == 5 && memcmp(b, "HEllo", 5) == 0);
        munmap(m, 4096);
    }
    /* fallocate(2) FALLOC_FL_PUNCH_HOLE (2) | KEEP_SIZE (1): the range reads
       as zeros, through the file and a shared mapping; the size stays. */
    int h = (int)syscall(SYS_memfd_create, "hole", MFD_CLOEXEC_);
    char *hm = MAP_FAILED;
    if (h >= 0 && ftruncate(h, 3 * 4096) == 0)
        hm = mmap(0, 3 * 4096, PROT_READ | PROT_WRITE, MAP_SHARED, h, 0);
    if (hm != MAP_FAILED) {
        memset(hm, 'A', 3 * 4096);
        check("punch_hole", syscall(SYS_fallocate, h, 3, 100, 8192) == 0);
        int zeros = 1;
        for (int i = 100; i < 100 + 8192; i++) zeros &= hm[i] == 0;
        char c = 0;
        struct stat hs;
        check("punch_hole_zeros", zeros && hm[99] == 'A' && hm[100 + 8192] == 'A' &&
                                      pread(h, &c, 1, 5000) == 1 && c == 0);
        check("punch_hole_keeps_size", fstat(h, &hs) == 0 && hs.st_size == 3 * 4096);
        check("punch_hole_needs_keep_size", syscall(SYS_fallocate, h, 2, 0, 4096) == -1 && errno == EINVAL);
        munmap(hm, 3 * 4096);
    } else {
        check("punch_hole", 0);
    }
    if (h >= 0) close(h);
    check("seals_none", fcntl(fd, F_GET_SEALS_) == 0);
    check("seal_shrink_grow", fcntl(fd, F_ADD_SEALS_, F_SEAL_SHRINK_ | F_SEAL_GROW_) == 0);
    check("sealed_truncate", ftruncate(fd, 1) == -1 && errno == EPERM);
    check("sealed_grow", pwrite(fd, "x", 1, 100) == -1 && errno == EPERM);
    check("seal_write", fcntl(fd, F_ADD_SEALS_, F_SEAL_WRITE_ | F_SEAL_SEAL_) == 0);
    check("sealed_write", pwrite(fd, "x", 1, 0) == -1 && errno == EPERM);
    check("sealed_shared_mmap", mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) == MAP_FAILED && errno == EPERM);
    check("sealed_seal", fcntl(fd, F_ADD_SEALS_, F_SEAL_GROW_) == -1 && errno == EPERM);
    close(fd);
    int plain = open("/tmp/plain", O_CREAT | O_RDWR | O_TRUNC, 0644);
    check("tmpfs_not_sealable", fcntl(plain, F_ADD_SEALS_, F_SEAL_WRITE_) == -1 && errno == EPERM);
    close(plain);
    unlink("/tmp/plain");

    /* fexecve: run a copy of a program from a memfd (execveat AT_EMPTY_PATH). */
    int src = open("/bin/true", O_RDONLY);
    int exe = (int)syscall(SYS_memfd_create, "true", 0);
    char buf[65536];
    ssize_t r;
    while (src >= 0 && (r = read(src, buf, sizeof buf)) > 0)
        if (write(exe, buf, (size_t)r) != r) break;
    close(src);
    pid_t c = fork();
    if (c == 0) {
        char *argv[] = {"true", 0}, *envp[] = {0};
        syscall(SYS_execveat, exe, "", argv, envp, 0x1000 /* AT_EMPTY_PATH */);
        _exit(99);
    }
    int st = 0;
    check("fexecve_memfd", waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    close(exe);
}

/* --- read-only bind mounts and magic links ------------------------------------ */

static int robind_child(void) {
    int bad = 0;
    CHILD_CHECK("unshare", unshare(CLONE_NEWNS) == 0);
    mkdir("/tmp/ro-src", 0755);
    mkdir("/tmp/ro-dst", 0755);
    close(open("/tmp/ro-src/f", O_CREAT | O_WRONLY, 0644));
    CHILD_CHECK("bind", mount("/tmp/ro-src", "/tmp/ro-dst", 0, MS_BIND, 0) == 0);
    CHILD_CHECK("remount_ro", mount("none", "/tmp/ro-dst", 0, MS_BIND | MS_REMOUNT | MS_RDONLY, 0) == 0);
    CHILD_CHECK("ro_create", open("/tmp/ro-dst/g", O_CREAT | O_WRONLY, 0644) == -1 && errno == EROFS);
    CHILD_CHECK("ro_write", open("/tmp/ro-dst/f", O_WRONLY) == -1 && errno == EROFS);
    CHILD_CHECK("ro_unlink", unlink("/tmp/ro-dst/f") == -1 && errno == EROFS);
    CHILD_CHECK("rw_source", open("/tmp/ro-src/f", O_WRONLY) >= 0);
    char line[512];
    FILE *mi = fopen("/proc/self/mountinfo", "r");
    int seen = 0;
    while (mi && fgets(line, sizeof line, mi))
        if (strstr(line, " /tmp/ro-dst ro,")) seen = 1;
    if (mi) fclose(mi);
    CHILD_CHECK("mountinfo_ro", seen);
    /* The file stays reachable through /proc/self/fd after its name goes. */
    int fd = open("/tmp/ro-src/f", O_RDONLY);
    unlink("/tmp/ro-src/f");
    char p[32];
    snprintf(p, sizeof p, "/proc/self/fd/%d", fd);
    CHILD_CHECK("magic_fd_link", open(p, O_RDONLY) >= 0);
    return bad;
}

static void robind(void) {
    check("ro_bind_mount", in_child(robind_child, 0) == 0);
    rmdir("/tmp/ro-src");
    rmdir("/tmp/ro-dst");
}

/* A file bound over another (slate-linux binds passwd and resolv.conf so). */
static int filebind_child(void) {
    int bad = 0;
    char buf[32] = "";
    CHILD_CHECK("unshare", unshare(CLONE_NEWNS) == 0);
    CHILD_CHECK("bind", mount("/tmp/fb-new", "/tmp/fb-old", 0, MS_BIND, 0) == 0);
    CHILD_CHECK("read_new", get("/tmp/fb-old", buf, sizeof buf) == 0 && strcmp(buf, "new\n") == 0);
    CHILD_CHECK("unmount", umount2("/tmp/fb-old", 0) == 0);
    CHILD_CHECK("read_old", get("/tmp/fb-old", buf, sizeof buf) == 0 && strcmp(buf, "old\n") == 0);
    return bad;
}

static void filebind(void) {
    char buf[32] = "";
    FILE *f = fopen("/tmp/fb-old", "w");
    if (f) fputs("old\n", f), fclose(f);
    f = fopen("/tmp/fb-new", "w");
    if (f) fputs("new\n", f), fclose(f);
    check("file_bind_mount", in_child(filebind_child, 0) == 0);
    check("file_bind_private", get("/tmp/fb-old", buf, sizeof buf) == 0 && strcmp(buf, "old\n") == 0);
    unlink("/tmp/fb-old");
    unlink("/tmp/fb-new");
}

/* --- mount flags: nosuid, nodev, noexec, remounts ---------------------------- */

/* Copy this program to `path` with `mode`. */
static int copy_self(const char *path, mode_t mode) {
    int in = open("/proc/self/exe", O_RDONLY), out = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0700);
    char buf[65536];
    ssize_t n;
    int ok = in >= 0 && out >= 0;
    while (ok && (n = read(in, buf, sizeof buf)) > 0) ok = write(out, buf, n) == n;
    close(in);
    close(out);
    return ok && chmod(path, mode) == 0 ? 0 : -1;
}

/* Run `path euid` as `uid`: the exit status is the effective user ID the
   program got (see main), or -1. */
static int euid_as(const char *path, uid_t uid) {
    pid_t pid = fork();
    if (pid == 0) {
        if (setuid(uid) != 0) _exit(255);
        execl(path, path, "euid", (char *)0);
        _exit(254);
    }
    int st = 0;
    if (pid < 0 || waitpid(pid, &st, 0) != pid || !WIFEXITED(st)) return -1;
    return WEXITSTATUS(st);
}

static int mount_has(const char *at, const char *opts) {
    char line[512], want[256];
    snprintf(want, sizeof want, " %s tmpfs %s,", at, opts);
    FILE *f = fopen("/proc/self/mounts", "r");
    int seen = 0;
    while (f && fgets(line, sizeof line, f))
        if (strstr(line, want)) seen = 1;
    if (f) fclose(f);
    return seen;
}

static int mntflags_child(void) {
    int bad = 0;
    CHILD_CHECK("unshare", unshare(CLONE_NEWNS) == 0);
    mkdir("/tmp/mf", 0755);
    CHILD_CHECK("mount", mount("none", "/tmp/mf", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, 0) == 0);
    CHILD_CHECK("copy", copy_self("/tmp/mf/prog", 04755) == 0);
    CHILD_CHECK("mounts_line", mount_has("/tmp/mf", "rw,nosuid,nodev,noexec"));
    struct statvfs sv;
    CHILD_CHECK("statvfs", statvfs("/tmp/mf", &sv) == 0 && (sv.f_flag & (ST_NOSUID | ST_NODEV | ST_NOEXEC)) ==
                                                                 (ST_NOSUID | ST_NODEV | ST_NOEXEC));
    /* noexec: execve(2) EACCES, access(2) too, mmap(2) EPERM, mprotect(2)
       EACCES. */
    errno = 0;
    execl("/tmp/mf/prog", "/tmp/mf/prog", "euid", (char *)0);
    CHILD_CHECK("noexec_execve", errno == EACCES);
    CHILD_CHECK("noexec_access", access("/tmp/mf/prog", X_OK) == -1 && errno == EACCES);
    CHILD_CHECK("noexec_access_read", access("/tmp/mf/prog", R_OK) == 0);
    int fd = open("/tmp/mf/prog", O_RDONLY);
    void *m = mmap(0, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    CHILD_CHECK("noexec_mmap", m == MAP_FAILED && errno == EPERM);
    m = mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    CHILD_CHECK("noexec_mprotect", m != MAP_FAILED && mprotect(m, 4096, PROT_READ | PROT_EXEC) == -1 && errno == EACCES);
    if (m != MAP_FAILED) munmap(m, 4096);
    close(fd);
    /* nodev: a device node doesn't open (EACCES). */
    CHILD_CHECK("mknod", mknod("/tmp/mf/null", S_IFCHR | 0666, makedev(1, 3)) == 0);
    CHILD_CHECK("nodev_open", open("/tmp/mf/null", O_RDWR) == -1 && errno == EACCES);
    /* A remount sets the flags given and clears the others: now the program
       runs, and its set-user-ID bit applies... */
    CHILD_CHECK("remount_exec", mount("none", "/tmp/mf", 0, MS_REMOUNT, 0) == 0);
    CHILD_CHECK("remount_line", mount_has("/tmp/mf", "rw"));
    CHILD_CHECK("suid_applies", euid_as("/tmp/mf/prog", 1000) == 0);
    fd = open("/tmp/mf/null", O_RDWR);
    CHILD_CHECK("dev_open", fd >= 0);
    close(fd);
    /* ...but not on a nosuid mount. */
    CHILD_CHECK("remount_nosuid", mount("none", "/tmp/mf", 0, MS_REMOUNT | MS_BIND | MS_NOSUID, 0) == 0);
    CHILD_CHECK("nosuid_ignored", euid_as("/tmp/mf/prog", 1000) == 1000 % 256);
    /* A bind mount keeps the flags of the mount it shows. */
    mkdir("/tmp/mf2", 0755);
    CHILD_CHECK("bind", mount("/tmp/mf", "/tmp/mf2", 0, MS_BIND, 0) == 0);
    CHILD_CHECK("bind_flags", mount_has("/tmp/mf2", "rw,nosuid"));
    umount2("/tmp/mf2", 0);
    rmdir("/tmp/mf2");
    umount2("/tmp/mf", 0);
    return bad;
}

/* A remount in one mount namespace leaves the other namespaces' copies of
   the mount as they were. */
static int nsro_child(void) {
    int bad = 0;
    CHILD_CHECK("remount_ro", mount("none", "/tmp/nsro", 0, MS_REMOUNT | MS_RDONLY, 0) == 0);
    CHILD_CHECK("ro_here", open("/tmp/nsro/a", O_CREAT | O_WRONLY, 0644) == -1 && errno == EROFS);
    CHILD_CHECK("access_erofs", access("/tmp/nsro", W_OK) == -1 && errno == EROFS);
    return bad;
}

static void mount_flags(void) {
    check("mount_flags", in_child(mntflags_child, 0) == 0);
    rmdir("/tmp/mf");
    mkdir("/tmp/nsro", 0755);
    if (mount("none", "/tmp/nsro", "tmpfs", 0, 0) != 0) {
        check("ns_readonly", 0);
        return;
    }
    check("ns_readonly", in_child(nsro_child, CLONE_NEWNS) == 0);
    int fd = open("/tmp/nsro/a", O_CREAT | O_WRONLY, 0644);
    check("ns_readonly_others_rw", fd >= 0);
    close(fd);
    umount2("/tmp/nsro", 0);
    rmdir("/tmp/nsro");
}

/* --- overlayfs ---------------------------------------------------------------- */

static int put_file(const char *path, const char *text) {
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) return -1;
    ssize_t n = write(fd, text, strlen(text));
    close(fd);
    return n == (ssize_t)strlen(text) ? 0 : -1;
}

static int overlay_child(void) {
    int bad = 0;
    char buf[64];
    struct stat st;
    CHILD_CHECK("unshare", unshare(CLONE_NEWNS) == 0);
    CHILD_CHECK("tmpfs", mount("t", "/tmp/ovl", "tmpfs", 0, 0) == 0);
    mkdir("/tmp/ovl/l1", 0755);
    mkdir("/tmp/ovl/l2", 0755);
    mkdir("/tmp/ovl/u", 0755);
    mkdir("/tmp/ovl/w", 0755);
    mkdir("/tmp/ovl/m", 0755);
    put_file("/tmp/ovl/l1/a", "top");
    put_file("/tmp/ovl/l2/a", "bottom");
    put_file("/tmp/ovl/l2/b", "b");
    mkdir("/tmp/ovl/l1/d", 0755);
    mkdir("/tmp/ovl/l2/d", 0755);
    put_file("/tmp/ovl/l1/d/x", "x");
    put_file("/tmp/ovl/l2/d/y", "y");
    CHILD_CHECK("mount", mount("ov", "/tmp/ovl/m", "overlay", 0,
                               "lowerdir=/tmp/ovl/l1:/tmp/ovl/l2,upperdir=/tmp/ovl/u,workdir=/tmp/ovl/w") == 0);
    CHILD_CHECK("top_wins", get("/tmp/ovl/m/a", buf, sizeof buf) == 0 && strcmp(buf, "top") == 0);
    CHILD_CHECK("merged_dir", stat("/tmp/ovl/m/d/x", &st) == 0 && stat("/tmp/ovl/m/d/y", &st) == 0);
    CHILD_CHECK("copy_up", put_file("/tmp/ovl/m/a", "changed") == 0 && get("/tmp/ovl/u/a", buf, sizeof buf) == 0 &&
                               strcmp(buf, "changed") == 0 && get("/tmp/ovl/l1/a", buf, sizeof buf) == 0 &&
                               strcmp(buf, "top") == 0);
    CHILD_CHECK("whiteout", unlink("/tmp/ovl/m/b") == 0 && stat("/tmp/ovl/m/b", &st) == -1 &&
                                stat("/tmp/ovl/u/b", &st) == 0 && S_ISCHR(st.st_mode) && st.st_rdev == 0);
    CHILD_CHECK("rmdir_merged", unlink("/tmp/ovl/m/d/x") == 0 && unlink("/tmp/ovl/m/d/y") == 0 &&
                                    rmdir("/tmp/ovl/m/d") == 0);
    CHILD_CHECK("opaque_new_dir", mkdir("/tmp/ovl/m/d", 0755) == 0 && stat("/tmp/ovl/m/d/y", &st) == -1 &&
                                      getxattr("/tmp/ovl/u/d", "trusted.overlay.opaque", buf, sizeof buf) == 1);
    CHILD_CHECK("hidden_xattr", getxattr("/tmp/ovl/m/d", "trusted.overlay.opaque", buf, sizeof buf) == -1);
    mkdir("/tmp/ovl/l2/merged", 0755);
    mkdir("/tmp/ovl/l1/merged", 0755);
    CHILD_CHECK("rename_merged_exdev", rename("/tmp/ovl/m/merged", "/tmp/ovl/m/moved") == -1 && errno == EXDEV);
    CHILD_CHECK("rename_file", rename("/tmp/ovl/m/a", "/tmp/ovl/m/a2") == 0 && stat("/tmp/ovl/m/a", &st) == -1 &&
                                   get("/tmp/ovl/m/a2", buf, sizeof buf) == 0 && strcmp(buf, "changed") == 0);
    struct statfs { long type; long rest[14]; } sf;
    CHILD_CHECK("statfs_magic", syscall(SYS_statfs, "/tmp/ovl/m", &sf) == 0 && sf.type == 0x794c7630);
    return bad;
}

static void overlay(void) {
    mkdir("/tmp/ovl", 0755);
    check("overlayfs", in_child(overlay_child, 0) == 0);
    rmdir("/tmp/ovl");
}

/* --- network namespaces and sysctls -------------------------------------------- */

static int netns_child(void) {
    int bad = 0;
    char buf[64];
    CHILD_CHECK("unshare", unshare(CLONE_NEWNET) == 0);
    /* As on Linux, the new namespace's loopback is down, with no
     * address, until brought up (ADR 0114). */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strcpy(ifr.ifr_name, "lo");
    CHILD_CHECK("lo_starts_down", ioctl(s, SIOCGIFFLAGS, &ifr) == 0 && !(ifr.ifr_flags & IFF_UP));
    /* netdevice(7): SIOCGIFADDR; EADDRNOTAVAIL without one, as on the host. */
    struct ifreq ar = ifr;
    CHILD_CHECK("no_loopback_address_yet", ioctl(s, SIOCGIFADDR, &ar) == -1 && errno == EADDRNOTAVAIL);
    ifr.ifr_flags |= IFF_UP;
    CHILD_CHECK("lo_up", ioctl(s, SIOCSIFFLAGS, &ifr) == 0);
    close(s);
    /* Only loopback: 127.0.0.1 works, the outside does not. */
    s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(9)};
    a.sin_addr.s_addr = htonl(0x0a00020f); /* 10.0.2.15, the host side's address */
    CHILD_CHECK("no_route_out", connect(s, (struct sockaddr *)&a, sizeof a) == -1);
    close(s);
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in lo = {.sin_family = AF_INET, .sin_port = htons(7777)};
    lo.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHILD_CHECK("loopback_bind", bind(l, (struct sockaddr *)&lo, sizeof lo) == 0 && listen(l, 1) == 0);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    CHILD_CHECK("loopback_connect", connect(c, (struct sockaddr *)&lo, sizeof lo) == 0);
    close(c);
    close(l);
    CHILD_CHECK("sysctl_write", put("/proc/sys/net/ipv4/ping_group_range", "0 0") == 0);
    CHILD_CHECK("sysctl_read", get("/proc/sys/net/ipv4/ping_group_range", buf, sizeof buf) == 0 && strcmp(buf, "0\t0\n") == 0);
    CHILD_CHECK("sysctl_checked", put("/proc/sys/net/ipv4/ping_group_range", "x") == -1 && errno == EINVAL);
    return bad;
}

static void netns(void) {
    char before[64] = "", after[64] = "";
    get("/proc/sys/net/ipv4/ping_group_range", before, sizeof before);
    check("netns", in_child(netns_child, 0) == 0);
    get("/proc/sys/net/ipv4/ping_group_range", after, sizeof after);
    check("sysctl_per_netns", strcmp(before, after) == 0);
    /* A port that the namespace's stack took is free in the host's. */
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in lo = {.sin_family = AF_INET, .sin_port = htons(7777)};
    lo.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    check("netns_separate_ports", bind(l, (struct sockaddr *)&lo, sizeof lo) == 0);
    close(l);
}

/* --- seccomp ------------------------------------------------------------------ */

/* struct sock_filter / sock_fprog and the values seccomp(2) lists. */
struct sock_filter_ { unsigned short code; unsigned char jt, jf; unsigned int k; };
struct sock_fprog_ { unsigned short len; struct sock_filter_ *filter; };
#define LD_W_ABS 0x20
#define JEQ_K 0x15
#define RET_K 0x06
#define RET_ALLOW 0x7fff0000U
#define RET_ERRNO 0x00050000U
#define RET_KILL_PROCESS 0x80000000U
/* SECCOMP_RET_TRAP and SIGSYS's si_code SYS_SECCOMP (seccomp(2)). */
#define RET_TRAP 0x00030000U
#define SYS_SECCOMP_ 1
#define AUDIT_ARCH_X86_64_ 0xC000003EU

/* A SIGSYS handler emulating the trapped call: it finds the call's number
 * in RAX (the call did not run) and puts its own result there, as
 * sandboxes that broker calls do. */
static volatile int trap_info_ok;
static void on_sigsys(int sig, siginfo_t *si, void *ctx) {
    ucontext_t *uc = ctx;
    (void)sig;
    trap_info_ok = si->si_code == SYS_SECCOMP_ && si->si_syscall == SYS_sched_yield && si->si_errno == 77 &&
        si->si_arch == AUDIT_ARCH_X86_64_ && uc->uc_mcontext.gregs[REG_RAX] == SYS_sched_yield;
    uc->uc_mcontext.gregs[REG_RAX] = 4242;
}
#define SECCOMP_SET_MODE_FILTER_ 1

static int install_filter(unsigned nr, unsigned action) {
    struct sock_filter_ f[] = {
        {LD_W_ABS, 0, 0, 4},              /* arch */
        {JEQ_K, 1, 0, 0xC000003E},
        {RET_K, 0, 0, RET_KILL_PROCESS},
        {LD_W_ABS, 0, 0, 0},              /* nr */
        {JEQ_K, 0, 1, nr},
        {RET_K, 0, 0, action},
        {RET_K, 0, 0, RET_ALLOW},
    };
    struct sock_fprog_ p = {sizeof f / sizeof f[0], f};
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER_, 0, &p);
}

static int seccomp_child(void) {
    int bad = 0;
    CHILD_CHECK("needs_nnp", setuid(1000) == 0 && install_filter(SYS_getppid, RET_ERRNO | 1) == -1 && errno == EACCES);
    CHILD_CHECK("nnp", prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 && prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
    CHILD_CHECK("filter", install_filter(SYS_getppid, RET_ERRNO | EPERM) == 0);
    CHILD_CHECK("errno_action", syscall(SYS_getppid) == -1 && errno == EPERM);
    CHILD_CHECK("others_allowed", getpid() > 0);
    CHILD_CHECK("get_seccomp", prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 2);
    /* Inherited across fork; KILL_PROCESS ends the process with SIGSYS. */
    pid_t c = fork();
    if (c == 0) {
        install_filter(SYS_getuid, RET_KILL_PROCESS);
        syscall(SYS_getppid);
        syscall(SYS_getuid);
        _exit(0);
    }
    int st = 0;
    CHILD_CHECK("kill_process", waitpid(c, &st, 0) == c && WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_sigsys;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSYS, &sa, 0);
    CHILD_CHECK("trap_filter", install_filter(SYS_sched_yield, RET_TRAP | 77) == 0);
    long r = syscall(SYS_sched_yield);
    CHILD_CHECK("trap_emulated", r == 4242 && trap_info_ok);
    /* A filtered process may run Slate's native programs, and the filter
     * sees their calls as Linux ones (ADR 0097): native mkdir under a
     * filter refusing mkdirat fails, under another it works. */
    for (int refuse = 1; refuse >= 0; refuse--) {
        const char *dir = refuse ? "/tmp/seccomp-native-no" : "/tmp/seccomp-native-yes";
        rmdir(dir);
        pid_t m = fork();
        if (m == 0) {
            install_filter(refuse ? SYS_mkdirat : SYS_getppid, RET_ERRNO | EPERM);
            execl("/bin/mkdir", "mkdir", dir, (char *)0);
            _exit(127);
        }
        int ms = 0;
        waitpid(m, &ms, 0);
        struct stat sb;
        int made = stat(dir, &sb) == 0;
        if (refuse)
            CHILD_CHECK("native_filtered", WIFEXITED(ms) && WEXITSTATUS(ms) != 0 && WEXITSTATUS(ms) != 127 && !made);
        else
            CHILD_CHECK("native_runs", WIFEXITED(ms) && WEXITSTATUS(ms) == 0 && made);
        rmdir(dir);
    }
    struct sock_filter_ bad_jump[] = {{JEQ_K, 9, 0, 0}, {RET_K, 0, 0, RET_ALLOW}};
    struct sock_fprog_ p = {2, bad_jump};
    CHILD_CHECK("checked", syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER_, 0, &p) == -1 && errno == EINVAL);
    return bad;
}

static void seccomp(void) {
    check("seccomp", in_child(seccomp_child, 0) == 0);
}

/* --- cgroup device programs (bpf(2)) -------------------------------------------- */

/* bpf(2) commands and types, and eBPF opcodes (RFC 9669). */
#define BPF_PROG_LOAD_ 5
#define BPF_PROG_ATTACH_ 8
#define BPF_PROG_QUERY_ 16
#define BPF_PROG_TYPE_CGROUP_DEVICE_ 15
#define BPF_CGROUP_DEVICE_ 6
struct ebpf_insn { unsigned char code; unsigned char regs; short off; int imm; };

static int devices_child(void) {
    int bad = 0;
    char me[16];
    snprintf(me, sizeof me, "%d", getpid());
    CHILD_CHECK("join", put("/sys/fs/cgroup/devtest/cgroup.procs", me) == 0);
    /* Allow character device 1:3 (/dev/null); deny the rest. */
    struct ebpf_insn prog[] = {
        {0x61, 0x12, 0, 0},  /* r2 = *(u32 *)(r1 + 0)   access_type */
        {0x54, 0x02, 0, 0xFFFF}, /* w2 &= 0xffff     device type */
        {0x61, 0x13, 4, 0},  /* r3 = major */
        {0x61, 0x14, 8, 0},  /* r4 = minor */
        {0x56, 0x02, 4, 2},  /* if w2 != CHAR goto deny */
        {0x56, 0x03, 3, 1},  /* if w3 != 1 goto deny */
        {0x56, 0x04, 2, 3},  /* if w4 != 3 goto deny */
        {0xb7, 0x00, 0, 1},  /* r0 = 1 */
        {0x95, 0x00, 0, 0},  /* exit */
        {0xb7, 0x00, 0, 0},  /* deny: r0 = 0 */
        {0x95, 0x00, 0, 0},
    };
    char license[] = "GPL";
    unsigned long long attr[16] = {0};
    unsigned int *a32 = (unsigned int *)attr;
    a32[0] = BPF_PROG_TYPE_CGROUP_DEVICE_;
    a32[1] = sizeof prog / sizeof prog[0];
    attr[1] = (unsigned long)prog;
    attr[2] = (unsigned long)license;
    int pfd = (int)syscall(SYS_bpf, BPF_PROG_LOAD_, attr, sizeof attr);
    CHILD_CHECK("prog_load", pfd >= 0);
    int cg = open("/sys/fs/cgroup/devtest", O_RDONLY | O_DIRECTORY);
    unsigned int at[4] = {(unsigned)cg, (unsigned)pfd, BPF_CGROUP_DEVICE_, 0};
    CHILD_CHECK("prog_attach", syscall(SYS_bpf, BPF_PROG_ATTACH_, at, sizeof at) == 0);
    unsigned int ids[4] = {0};
    unsigned long long q[4] = {0};
    unsigned int *q32 = (unsigned int *)q;
    q32[0] = (unsigned)cg;
    q32[1] = BPF_CGROUP_DEVICE_;
    q[2] = (unsigned long)ids;
    q32[6] = 4;
    CHILD_CHECK("prog_query", syscall(SYS_bpf, BPF_PROG_QUERY_, q, 28) == 0 && q32[6] == 1 && ids[0] != 0);
    int null = open("/dev/null", O_RDWR);
    CHILD_CHECK("allowed_device", null >= 0);
    close(null);
    CHILD_CHECK("denied_device", open("/dev/zero", O_RDONLY) == -1 && errno == EPERM);
    CHILD_CHECK("denied_mknod", mknod("/tmp/zero-node", S_IFCHR | 0600, makedev(1, 5)) == -1 && errno == EPERM);
    return bad;
}

static void devices(void) {
    check("devcg_mkdir", mkdir("/sys/fs/cgroup/devtest", 0755) == 0);
    check("device_programs", in_child(devices_child, 0) == 0);
    rmdir("/sys/fs/cgroup/devtest");
}

/* --- pidfds, waitid, close_range ----------------------------------------------- */

/* waitid(2) and close_range(2) values. */
#define P_PIDFD_ 3
#define CLOSE_RANGE_CLOEXEC_ 4

static void process_fds(void) {
    pid_t c = fork();
    if (c == 0) {
        usleep(100000);
        _exit(7);
    }
    int pfd = (int)syscall(SYS_pidfd_open, c, 0);
    check("pidfd_open", pfd >= 0);
    struct pollfd p = {pfd, POLLIN, 0};
    check("pidfd_not_ready", poll(&p, 1, 0) == 0);
    check("pidfd_ready_on_exit", poll(&p, 1, 2000) == 1 && (p.revents & POLLIN));
    siginfo_t si;
    memset(&si, 0, sizeof si);
    check("waitid_nowait", syscall(SYS_waitid, P_PIDFD_, pfd, &si, WEXITED | WNOWAIT, 0) == 0 && si.si_pid == c &&
                               si.si_code == CLD_EXITED && si.si_status == 7);
    memset(&si, 0, sizeof si);
    check("waitid_reaps", syscall(SYS_waitid, P_PID, c, &si, WEXITED, 0) == 0 && si.si_pid == c);
    check("reaped", waitpid(c, 0, WNOHANG) == -1 && errno == ECHILD);
    close(pfd);
    int a = open("/dev/null", O_RDONLY), b = dup(a);
    check("close_range_cloexec", syscall(SYS_close_range, a, b, CLOSE_RANGE_CLOEXEC_) == 0 &&
                                     (fcntl(a, F_GETFD) & FD_CLOEXEC) && (fcntl(b, F_GETFD) & FD_CLOEXEC));
    check("close_range", syscall(SYS_close_range, a, b, 0) == 0 && fcntl(a, F_GETFD) == -1 && fcntl(b, F_GETFD) == -1);
}

/* --- vfork sharing, per-thread namespaces, mount points ------------------------ */

static volatile int vfork_mark;
static int vfork_fd = -1;
static char vfork_stack[16384];

static int vfork_child(void *arg) {
    (void)arg;
    vfork_mark = 42;
    vfork_fd = open("/dev/null", O_RDONLY);
    return 0;
}

static void *thread_unshare(void *arg) {
    char *out = arg;
    if (unshare(CLONE_NEWNET) == 0) {
        ssize_t n = readlink("/proc/thread-self/ns/net", out, 63);
        if (n > 0) out[n] = 0;
    }
    return 0;
}

/* The umask goes with the root and working directory (CLONE_FS): a
   thread changes everyone's, until unshare(CLONE_FS) gives it its own. */
static void *thread_umask(void *arg) {
    int *got = arg;
    umask(0027);
    got[0] = unshare(CLONE_FS) == 0;
    umask(0077);
    got[1] = umask(0077) == 0077;
    return 0;
}

static int umask_child(void *arg) {
    (void)arg;
    umask(0007);
    return 0;
}

static void sharing(void) {
    /* clone(CLONE_VM | CLONE_VFORK | CLONE_FILES), as pasta does it. */
    pid_t c = clone(vfork_child, vfork_stack + sizeof vfork_stack, CLONE_VM | CLONE_VFORK | CLONE_FILES | SIGCHLD, 0);
    int st = 0;
    check("vfork_child", c > 0 && waitpid(c, &st, 0) == c);
    check("vfork_shares_memory", vfork_mark == 42);
    check("vfork_shares_files", vfork_fd >= 0 && fcntl(vfork_fd, F_GETFD) >= 0);
    close(vfork_fd);

    /* unshare in one thread leaves the others where they were. */
    char before[64] = "", after[64] = "", in_thread[64] = "";
    readlink("/proc/self/ns/net", before, sizeof before - 1);
    pthread_t t;
    pthread_create(&t, 0, thread_unshare, in_thread);
    pthread_join(t, 0);
    readlink("/proc/self/ns/net", after, sizeof after - 1);
    check("thread_netns", in_thread[0] && strcmp(in_thread, before) != 0 && strcmp(before, after) == 0);

    mode_t old = umask(0022);
    int got[2] = {0, 0};
    pthread_create(&t, 0, thread_umask, got);
    pthread_join(t, 0);
    check("umask_thread_shared", umask(0022) == 0027);
    check("umask_thread_own", got[0] && got[1]);
    /* A process made with clone(CLONE_FS) shares it too; fork doesn't. */
    c = clone(umask_child, vfork_stack + sizeof vfork_stack, CLONE_FS | SIGCHLD, 0);
    check("umask_clone_fs", c > 0 && waitpid(c, &st, 0) == c && umask(0022) == 0007);
    if ((c = fork()) == 0) {
        umask(0077);
        _exit(0);
    }
    check("umask_fork_own", c > 0 && waitpid(c, &st, 0) == c && umask(old) == 0022);

    /* A name with something mounted on it can't be removed. */
    close(open("/tmp/mp-src", O_CREAT | O_WRONLY, 0644));
    close(open("/tmp/mp-dst", O_CREAT | O_WRONLY, 0644));
    int ok = mount("/tmp/mp-src", "/tmp/mp-dst", 0, MS_BIND, 0) == 0;
    check("mountpoint_busy", ok && unlink("/tmp/mp-dst") == -1 && errno == EBUSY &&
                                 rename("/tmp/mp-dst", "/tmp/mp-x") == -1 && errno == EBUSY);
    umount2("/tmp/mp-dst", 0);
    unlink("/tmp/mp-dst");
    unlink("/tmp/mp-src");
}

/* --- tun/tap and netlink configuration ------------------------------------------ */

/* tun ioctl and flags; rtnetlink message types (rtnetlink(7)). */
#define TUNSETIFF_ 0x400454ca
#define IFF_TAP_ 0x0002
#define IFF_NO_PI_ 0x1000
#define RTM_NEWLINK_ 16
#define RTM_NEWADDR_ 20
#define NLM_F_REQUEST_ 1
#define NLM_F_ACK_ 4

/* Send one rtnetlink request (header + body) and return its ack's error. */
static int nl_request(int nl, unsigned short type, const void *body, size_t len) {
    unsigned char msg[256] = {0};
    unsigned int total = 16 + (unsigned)len;
    memcpy(msg, &total, 4);
    memcpy(msg + 4, &type, 2);
    unsigned short flags = NLM_F_REQUEST_ | NLM_F_ACK_;
    memcpy(msg + 6, &flags, 2);
    memcpy(msg + 16, body, len);
    if (send(nl, msg, total, 0) != (ssize_t)total) return -1;
    unsigned char reply[256];
    if (recv(nl, reply, sizeof reply, 0) < 20) return -1;
    int err;
    memcpy(&err, reply + 16, 4);
    return err;
}

static int tap_child(void) {
    int bad = 0;
    CHILD_CHECK("unshare", unshare(CLONE_NEWNET) == 0);
    int tun = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    CHILD_CHECK("open_tun", tun >= 0);
    unsigned char ifr[40] = "tap0";
    unsigned short f = IFF_TAP_ | IFF_NO_PI_;
    memcpy(ifr + 16, &f, 2);
    CHILD_CHECK("tunsetiff", ioctl(tun, TUNSETIFF_, ifr) == 0);
    int nl = socket(AF_NETLINK, SOCK_RAW, 0);
    /* struct ifinfomsg: family, pad, type, index 2, flags IFF_UP, change. */
    unsigned char link[16] = {0};
    int idx = 2;
    unsigned int up = 1;
    memcpy(link + 4, &idx, 4);
    memcpy(link + 8, &up, 4);
    memcpy(link + 12, &up, 4);
    CHILD_CHECK("link_up", nl_request(nl, RTM_NEWLINK_, link, sizeof link) == 0);
    /* struct ifaddrmsg (AF_INET, /24, index 2) + IFA_LOCAL 10.9.0.2. */
    unsigned char addr[16] = {AF_INET, 24, 0, 0};
    memcpy(addr + 4, &idx, 4);
    unsigned short alen = 8, atype = 2;
    memcpy(addr + 8, &alen, 2);
    memcpy(addr + 10, &atype, 2);
    unsigned char ip[4] = {10, 9, 0, 2};
    memcpy(addr + 12, ip, 4);
    CHILD_CHECK("add_address", nl_request(nl, RTM_NEWADDR_, addr, sizeof addr) == 0);
    /* Traffic to the subnet comes out of the tap: first an ARP request. */
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(9)};
    to.sin_addr.s_addr = htonl(0x0a090001);
    sendto(u, "x", 1, 0, (struct sockaddr *)&to, sizeof to);
    unsigned char frame[2048];
    struct pollfd p = {tun, POLLIN, 0};
    ssize_t n = poll(&p, 1, 2000) == 1 ? read(tun, frame, sizeof frame) : -1;
    static const unsigned char target_ip[4] = {10, 9, 0, 1};
    CHILD_CHECK("arp_on_tap", n >= 42 && frame[12] == 0x08 && frame[13] == 0x06 && memcmp(frame + 38, target_ip, 4) == 0);
    return bad;
}

static void tap(void) {
    check("tun_tap", in_child(tap_child, 0) == 0);
}

/* --- recvmmsg and TCP_INFO --------------------------------------------------------- */

#define TCP_INFO_ 11

static void sockets(void) {
    int r = socket(AF_INET, SOCK_DGRAM, 0), w = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(7778)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(r, (struct sockaddr *)&a, sizeof a);
    for (int i = 0; i < 3; i++) sendto(w, "abc", 3, 0, (struct sockaddr *)&a, sizeof a);
    char bufs[4][8];
    struct iovec iov[4];
    struct mmsghdr m[4];
    memset(m, 0, sizeof m);
    for (int i = 0; i < 4; i++) {
        iov[i] = (struct iovec){bufs[i], sizeof bufs[i]};
        m[i].msg_hdr.msg_iov = &iov[i];
        m[i].msg_hdr.msg_iovlen = 1;
    }
    int got = recvmmsg(r, m, 4, MSG_DONTWAIT, 0);
    check("recvmmsg", got == 3 && m[0].msg_len == 3 && m[2].msg_len == 3);
    close(r);
    close(w);

    int l = socket(AF_INET, SOCK_STREAM, 0), c = socket(AF_INET, SOCK_STREAM, 0);
    bind(l, (struct sockaddr *)&a, sizeof a);
    listen(l, 1);
    connect(c, (struct sockaddr *)&a, sizeof a);
    unsigned char info[232];
    socklen_t len = sizeof info;
    check("tcp_info", getsockopt(c, IPPROTO_TCP, TCP_INFO_, info, &len) == 0 && len == 232 && info[0] == 1);
    close(c);
    close(l);
}

/* --- what docker needed --------------------------------------------------------- */

static void *thread_chroot(void *arg) {
    int *ok = arg;
    *ok = unshare(CLONE_FS) == 0 && chroot("/tmp") == 0 && access("/test", F_OK) == -1;
    return 0;
}

static int pagecache_child(void) {
    int bad = 0;
    CHILD_CHECK("unshare", unshare(CLONE_NEWNS) == 0);
    CHILD_CHECK("tmpfs", mount("t", "/tmp/pc", "tmpfs", 0, 0) == 0);
    mkdir("/tmp/pc/l", 0755);
    mkdir("/tmp/pc/u", 0755);
    mkdir("/tmp/pc/w", 0755);
    mkdir("/tmp/pc/m", 0755);
    put_file("/tmp/pc/l/db", "old-data");
    CHILD_CHECK("mount", mount("ov", "/tmp/pc/m", "overlay", 0, "lowerdir=/tmp/pc/l,upperdir=/tmp/pc/u,workdir=/tmp/pc/w") == 0);
    struct stat st;
    CHILD_CHECK("work_dir_made", stat("/tmp/pc/w/work", &st) == 0 && S_ISDIR(st.st_mode));
    int fd = open("/tmp/pc/m/db", O_RDWR);
    char *m = mmap(0, 4096, PROT_READ, MAP_SHARED, fd, 0);
    CHILD_CHECK("shared_ro_map", m != MAP_FAILED);
    if (m != MAP_FAILED) {
        CHILD_CHECK("sees_file", memcmp(m, "old-data", 8) == 0);
        CHILD_CHECK("pwrite", pwrite(fd, "NEW", 3, 0) == 3);
        CHILD_CHECK("sees_write", memcmp(m, "NEW-data", 8) == 0);
        CHILD_CHECK("no_write_upgrade", mprotect(m, 4096, PROT_READ | PROT_WRITE) == -1 && errno == EACCES);
        munmap(m, 4096);
    }
    CHILD_CHECK("no_shared_writable", mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) == MAP_FAILED);
    close(fd);
    return bad;
}

/* --- What Flatpak and bubblewrap need (ADR 0114) ------------------------------ */

static int bwrap_child(void) {
    int bad = 0;
    char buf[64] = "";
    CHILD_CHECK("drop", setgid(1000) == 0 && setuid(1000) == 0);
    CHILD_CHECK("unshare", unshare(CLONE_NEWUSER) == 0);
    CHILD_CHECK("deny", put("/proc/self/setgroups", "deny") == 0);
    CHILD_CHECK("maps", put("/proc/self/uid_map", "0 1000 1") == 0 && put("/proc/self/gid_map", "0 1000 1") == 0);
    /* user_namespaces(7): the limit is per user namespace; its root may
       set its own (bwrap --disable-userns writes 1). */
    CHILD_CHECK("limit_set", put("/proc/sys/user/max_user_namespaces", "1") == 0);
    CHILD_CHECK("limit_read", get("/proc/sys/user/max_user_namespaces", buf, sizeof buf) == 0 && strcmp(buf, "1\n") == 0);
    CHILD_CHECK("one_below", unshare(CLONE_NEWUSER) == 0);
    /* A child namespace starts with its parent's setgroups (user_namespaces(7)). */
    CHILD_CHECK("setgroups_inherited", get("/proc/self/setgroups", buf, sizeof buf) == 0 && strcmp(buf, "deny\n") == 0);
    CHILD_CHECK("allow_refused", put("/proc/self/setgroups", "allow") == -1 && errno == EPERM);
    CHILD_CHECK("over_limit", unshare(CLONE_NEWUSER) == -1 && errno == ENOSPC);
    return bad;
}

static void flatpak_needs(void) {
    check("bwrap_userns", in_child(bwrap_child, 0) == 0);
    /* openat(2): an absolute path ignores dirfd, even one that isn't a
       directory (flatpak checks /usr links with faccessat(0, "/bin")). */
    check("absolute_ignores_dirfd", syscall(SYS_faccessat2, 0, "/bin", F_OK, AT_SYMLINK_NOFOLLOW) == 0
                                        && faccessat(-1, "/etc", F_OK, 0) == 0);
    int file = open("/etc/passwd", O_RDONLY);
    int fd = openat(file, "/etc/passwd", O_RDONLY);
    check("openat_absolute", fd >= 0);
    close(fd);
    /* copy_file_range(2). */
    int a = open("/tmp/cfr-a", O_CREAT | O_RDWR | O_TRUNC, 0644);
    int b = open("/tmp/cfr-b", O_CREAT | O_RDWR | O_TRUNC, 0644);
    char got[16] = "";
    ssize_t n = write(a, "copied bytes", 12);
    loff_t from = 7;
    ssize_t c = copy_file_range(a, &from, b, 0, 64, 0);
    check("copy_file_range", n == 12 && c == 5 && from == 12 && pread(b, got, sizeof got, 0) == 5
                                 && memcmp(got, "bytes", 5) == 0);
    close(a);
    close(b);
    unlink("/tmp/cfr-a");
    unlink("/tmp/cfr-b");
    close(file);
    /* mlock(2): accepted (memory isn't swapped out). */
    static char page[4096];
    check("mlock", mlock(page, sizeof page) == 0 && munlock(page, sizeof page) == 0
                       && syscall(SYS_mlock2, page, sizeof page, 1) == 0 && mlockall(MCL_CURRENT) == 0
                       && munlockall() == 0);
}

static void docker_needs(void) {
    /* SOCK_SEQPACKET keeps message boundaries; peeking with MSG_TRUNC and
       no buffer gives the next message's length. */
    int sv[2];
    socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv);
    send(sv[0], "first", 5, 0);
    send(sv[0], "second!", 7, 0);
    char b[16];
    check("seqpacket_peek_len", recv(sv[1], 0, 0, MSG_PEEK | MSG_TRUNC) == 5);
    check("seqpacket_one", recv(sv[1], b, sizeof b, 0) == 5);
    check("seqpacket_trunc", recv(sv[1], b, 3, 0) == 3 && memcmp(b, "sec", 3) == 0);
    close(sv[0]);
    check("seqpacket_eof", recv(sv[1], b, sizeof b, 0) == 0);
    close(sv[1]);

    /* unshare(CLONE_FS) in a thread: its chroot is its own. */
    int ok = 0;
    pthread_t t;
    pthread_create(&t, 0, thread_chroot, &ok);
    pthread_join(t, 0);
    check("thread_chroot", ok && access("/test", F_OK) == 0);

    /* readlinkat(fd, "") on an O_PATH | O_NOFOLLOW link; a trailing slash
       follows the link. */
    int l = open("/proc/self", O_PATH | O_NOFOLLOW);
    char link[32] = "";
    check("readlinkat_empty", readlinkat(l, "", link, sizeof link - 1) > 0 && atoi(link) == getpid());
    close(l);
    check("trailing_slash_follows", readlink("/proc/self/", link, sizeof link) == -1 && errno == EINVAL);

    /* /proc writes stop at a NUL. */
    int o = open("/proc/self/oom_score_adj", O_WRONLY);
    check("proc_write_nul", write(o, "0", 2) == 2);
    close(o);

    /* cgroup files are read afresh after seeking back. */
    mkdir("/sys/fs/cgroup/seek", 0755);
    int cg = open("/sys/fs/cgroup/seek/pids.max", O_RDWR);
    char v[16] = "";
    put("/sys/fs/cgroup/seek/pids.max", "7");
    check("cgroup_reread", lseek(cg, 0, SEEK_SET) == 0 && read(cg, v, sizeof v - 1) > 0 && atoi(v) == 7);
    close(cg);
    rmdir("/sys/fs/cgroup/seek");

    mkdir("/tmp/pc", 0755);
    check("page_cache", in_child(pagecache_child, 0) == 0);
    rmdir("/tmp/pc");
}

/* --- xattrs on SlateFS (the scratch disk the SlateFS test used) ------------------- */

static void slatefs_xattrs(void) {
    mkdir("/tmp/sfsx", 0755);
    if (mount("/dev/vdd", "/tmp/sfsx", "slatefs", 0, 0) != 0) {
        check("slatefs_mount", 0);
        return;
    }
    char v[32] = "";
    close(open("/tmp/sfsx/xa", O_CREAT | O_WRONLY, 0644));
    mkdir("/tmp/sfsx/xd", 0755);
    check("slatefs_setxattr", setxattr("/tmp/sfsx/xa", "user.k", "value", 5, 0) == 0 &&
                                  setxattr("/tmp/sfsx/xd", "trusted.overlay.opaque", "y", 1, 0) == 0);
    check("slatefs_getxattr", getxattr("/tmp/sfsx/xa", "user.k", v, sizeof v) == 5 && memcmp(v, "value", 5) == 0);
    check("slatefs_missing", getxattr("/tmp/sfsx/xa", "user.none", v, sizeof v) == -1 && errno == ENODATA);
    check("slatefs_listxattr", listxattr("/tmp/sfsx/xa", v, sizeof v) == (ssize_t)sizeof "user.k");
    sync();
    umount2("/tmp/sfsx", 0);
    check("slatefs_remount", mount("/dev/vdd", "/tmp/sfsx", "slatefs", 0, 0) == 0);
    check("slatefs_xattr_kept", getxattr("/tmp/sfsx/xd", "trusted.overlay.opaque", v, sizeof v) == 1 && v[0] == 'y');
    check("slatefs_removexattr", removexattr("/tmp/sfsx/xa", "user.k") == 0 &&
                                     getxattr("/tmp/sfsx/xa", "user.k", v, sizeof v) == -1);
    unlink("/tmp/sfsx/xa");
    sync();
    umount2("/tmp/sfsx", 0);
    rmdir("/tmp/sfsx");
}

int main(int argc, char **argv) {
    /* `euid`: report the effective user ID (mount_flags runs a copy so). */
    if (argc > 1 && strcmp(argv[1], "euid") == 0) return (int)(geteuid() % 256);
    uts();
    mounts();
    pids();
    userns();
    namespace_files();
    cgroups();
    xattrs();
    memfds();
    robind();
    mount_flags();
    filebind();
    overlay();
    netns();
    seccomp();
    devices();
    process_fds();
    sharing();
    tap();
    sockets();
    docker_needs();
    flatpak_needs();
    slatefs_xattrs();
    return failures;
}
