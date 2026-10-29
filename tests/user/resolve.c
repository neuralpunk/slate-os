// SPDX-License-Identifier: MIT OR Apache-2.0
// openat2(2)'s restricted lookups and file handles, name_to_handle_at(2)
// and open_by_handle_at(2) (ADR 0115). Each expectation is what Linux was
// seen to answer on the host; structures and flags from the man pages.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::resolve::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

/* struct open_how (openat2(2)): flags, mode, resolve; 24 bytes. */
struct how { uint64_t flags, mode, resolve; };
enum { NO_XDEV = 1, NO_MAGICLINKS = 2, NO_SYMLINKS = 4, BENEATH = 8, IN_ROOT = 16, CACHED = 32 };

/* The descriptor, or -errno. */
static int o2(int dirfd, const char *path, uint64_t flags, uint64_t mode, uint64_t resolve, size_t size) {
    char raw[64] = {0};
    struct how h = {flags, mode, resolve};
    memcpy(raw, &h, sizeof h);
    int fd = (int)syscall(437, dirfd, path, raw, size);
    if (fd < 0) return -errno;
    close(fd);
    return fd;
}

static void openat2_checks(void) {
    mkdir("/tmp/o2", 0755);
    mkdir("/tmp/o2/sub", 0755);
    close(open("/tmp/o2/sub/f", O_CREAT | O_WRONLY, 0644));
    unlink("/tmp/o2/abs");
    symlink("/etc/passwd", "/tmp/o2/abs");
    unlink("/tmp/o2/rel");
    symlink("sub/f", "/tmp/o2/rel");
    unlink("/tmp/o2/up");
    symlink("../o2/sub/f", "/tmp/o2/up");
    int d = open("/tmp/o2", O_RDONLY | O_DIRECTORY);
    int pd = open("/proc/self", O_RDONLY | O_DIRECTORY);
    int root = open("/", O_RDONLY | O_DIRECTORY);
    check("plain", o2(d, "sub/f", O_RDONLY, 0, 0, 24) >= 0);
    /* Sizes: under 24 bytes EINVAL; longer only if zero past what is known. */
    check("size_small", o2(d, "sub/f", O_RDONLY, 0, 0, 16) == -EINVAL);
    check("size_larger_zero", o2(d, "sub/f", O_RDONLY, 0, 0, 32) >= 0);
    {
        char raw[64] = {0};
        struct how h = {O_RDONLY, 0, 0};
        memcpy(raw, &h, sizeof h);
        raw[30] = 1;
        check("size_nonzero_tail", syscall(437, d, "sub/f", raw, 32) == -1 && errno == E2BIG);
    }
    check("size_huge", o2(d, "sub/f", O_RDONLY, 0, 0, 5000) == -E2BIG);
    /* Values: a mode without O_CREAT, unknown resolve or open flags. */
    check("mode_without_creat", o2(d, "sub/f", O_RDONLY, 0644, 0, 24) == -EINVAL);
    check("unknown_resolve", o2(d, "sub/f", O_RDONLY, 0, 0x40, 24) == -EINVAL);
    check("unknown_flags", o2(d, "sub/f", O_RDONLY | (1ull << 40), 0, 0, 24) == -EINVAL);
    check("mode_bits", o2(d, "newf", O_CREAT | O_WRONLY, 010000, 0, 24) == -EINVAL);
    /* RESOLVE_BENEATH: nothing above dirfd, nothing absolute, no magic links. */
    check("beneath_inside", o2(d, "sub/../sub/f", O_RDONLY, 0, BENEATH, 24) >= 0);
    check("beneath_relative_link", o2(d, "rel", O_RDONLY, 0, BENEATH, 24) >= 0);
    check("beneath_absolute", o2(d, "/etc/passwd", O_RDONLY, 0, BENEATH, 24) == -EXDEV);
    check("beneath_dotdot", o2(d, "../o2/sub/f", O_RDONLY, 0, BENEATH, 24) == -EXDEV);
    check("beneath_absolute_link", o2(d, "abs", O_RDONLY, 0, BENEATH, 24) == -EXDEV);
    check("beneath_escaping_link", o2(d, "up", O_RDONLY, 0, BENEATH, 24) == -EXDEV);
    check("beneath_magic", o2(pd, "exe", O_RDONLY, 0, BENEATH, 24) == -EXDEV);
    /* RESOLVE_IN_ROOT: dirfd is the root. */
    check("in_root_absolute", o2(d, "/sub/f", O_RDONLY, 0, IN_ROOT, 24) >= 0);
    check("in_root_dotdot", o2(d, "../../sub/f", O_RDONLY, 0, IN_ROOT, 24) >= 0);
    check("in_root_absolute_link", o2(d, "abs", O_RDONLY, 0, IN_ROOT, 24) == -ENOENT);
    check("in_root_magic", o2(pd, "exe", O_RDONLY, 0, IN_ROOT, 24) == -EXDEV);
    /* RESOLVE_NO_SYMLINKS and RESOLVE_NO_MAGICLINKS: ELOOP, but O_PATH |
       O_NOFOLLOW gives the link itself. */
    check("no_symlinks", o2(d, "rel", O_RDONLY, 0, NO_SYMLINKS, 24) == -ELOOP);
    check("no_symlinks_nofollow", o2(d, "rel", O_RDONLY | O_NOFOLLOW, 0, NO_SYMLINKS, 24) == -ELOOP);
    check("no_symlinks_opath", o2(d, "rel", O_PATH | O_NOFOLLOW, 0, NO_SYMLINKS, 24) >= 0);
    check("no_symlinks_plain", o2(d, "sub/f", O_RDONLY, 0, NO_SYMLINKS, 24) >= 0);
    check("no_magiclinks", o2(pd, "exe", O_RDONLY, 0, NO_MAGICLINKS, 24) == -ELOOP);
    check("no_magiclinks_fd", o2(pd, "fd/0", O_RDONLY, 0, NO_MAGICLINKS, 24) == -ELOOP);
    check("no_magiclinks_symlink_ok", o2(d, "rel", O_RDONLY, 0, NO_MAGICLINKS, 24) >= 0);
    /* RESOLVE_NO_XDEV: no mount crossed, either way. */
    check("no_xdev_down", o2(root, "proc/self/status", O_RDONLY, 0, NO_XDEV, 24) == -EXDEV);
    check("no_xdev_same", o2(d, "sub/f", O_RDONLY, 0, NO_XDEV, 24) >= 0);
    check("no_xdev_up", o2(pd, "../..", O_RDONLY, 0, NO_XDEV, 24) == -EXDEV);
    /* A bind mount of the same file system is a crossing too, both ways. */
    mkdir("/tmp/o2/bound", 0755);
    if (mount("/tmp/o2/sub", "/tmp/o2/bound", NULL, MS_BIND, NULL) == 0) {
        int bd = open("/tmp/o2/bound", O_RDONLY | O_DIRECTORY);
        check("no_xdev_bind_down", o2(d, "bound/f", O_RDONLY, 0, NO_XDEV, 24) == -EXDEV);
        check("no_xdev_bind_inside", o2(bd, "f", O_RDONLY, 0, NO_XDEV, 24) >= 0);
        check("no_xdev_bind_up", o2(bd, "../sub/f", O_RDONLY, 0, NO_XDEV, 24) == -EXDEV);
        close(bd);
        umount("/tmp/o2/bound");
    } else {
        check("no_xdev_bind_mount", 0);
    }
    rmdir("/tmp/o2/bound");
    /* One directory seen through a bind mount: a name replaced through
       one path is the new file through the other (the dentry caches of
       both agree), as flatpak's D-Bus proxy needs. */
    mkdir("/tmp/o2/real", 0755);
    mkdir("/tmp/o2/alias", 0755);
    int aliased = mount("/tmp/o2/real", "/tmp/o2/alias", NULL, MS_BIND, NULL) == 0;
    close(open("/tmp/o2/real/x", O_CREAT | O_WRONLY, 0644));
    struct stat s1, s2;
    int seen = stat("/tmp/o2/alias/x", &s1) == 0;
    unlink("/tmp/o2/real/x");
    int gone = stat("/tmp/o2/alias/x", &s2) == -1 && errno == ENOENT;
    close(open("/tmp/o2/real/x", O_CREAT | O_WRONLY, 0600));
    struct stat s3;
    stat("/tmp/o2/real/x", &s3);
    int fresh = stat("/tmp/o2/alias/x", &s2) == 0 && s2.st_ino == s3.st_ino && s2.st_nlink == 1;
    check("alias_sees_unlink", aliased && seen && gone);
    check("alias_sees_new_file", aliased && fresh && s2.st_ino != s1.st_ino);
    unlink("/tmp/o2/real/x");
    umount("/tmp/o2/alias");
    rmdir("/tmp/o2/alias");
    rmdir("/tmp/o2/real");
    /* RESOLVE_CACHED: making a file is never cached. */
    check("cached_open", o2(d, "sub/f", O_RDONLY, 0, CACHED, 24) >= 0);
    check("cached_creat", o2(d, "sub/f", O_RDONLY | O_CREAT, 0, CACHED, 24) == -EAGAIN);
    /* Only what the cache holds: a name never looked up, and /proc's
       (never cached), would ask the file system. */
    check("cached_unknown", o2(d, "sub/never-looked-up", O_RDONLY, 0, CACHED, 24) == -EAGAIN);
    check("cached_proc", o2(pd, "status", O_RDONLY, 0, CACHED, 24) == -EAGAIN);
    check("cached_after_lookup", access("/tmp/o2/sub/f", F_OK) == 0 && o2(d, "sub/../sub/f", O_RDONLY, 0, CACHED, 24) >= 0);
    close(d);
    close(pd);
    close(root);
}

/* struct file_handle (name_to_handle_at(2)). */
struct fh { uint32_t bytes; int32_t type; unsigned char h[128]; };
enum { HANDLE_FID = 0x200 };

static void handle_checks(void) {
    int fd = open("/tmp/o2/handled", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    check("handle_file", fd >= 0 && write(fd, "by handle", 9) == 9);
    close(fd);
    struct fh f;
    int mid = -7;
    f.bytes = 128;
    check("name_to_handle", syscall(303, AT_FDCWD, "/tmp/o2/handled", &f, &mid, 0) == 0 && f.bytes > 0 && mid >= 0);
    /* Too small: EOVERFLOW with the size needed, and the mount ID. */
    struct fh small;
    int mid2 = -7;
    small.bytes = 0;
    check("handle_overflow", syscall(303, AT_FDCWD, "/tmp/o2/handled", &small, &mid2, 0) == -1 &&
                                 errno == EOVERFLOW && small.bytes == f.bytes && mid2 == mid);
    check("handle_too_big", (f.bytes = 129, syscall(303, AT_FDCWD, "/tmp/o2/handled", &f, &mid, 0) == -1) &&
                                errno == EINVAL);
    check("handle_bad_flags", (f.bytes = 128, syscall(303, AT_FDCWD, "/tmp/o2/handled", &f, &mid, 4) == -1) &&
                                  errno == EINVAL);
    /* /proc's files and pipes only identify (AT_HANDLE_FID). */
    f.bytes = 128;
    check("proc_no_handle", syscall(303, AT_FDCWD, "/proc/self/status", &f, &mid, 0) == -1 && errno == EOPNOTSUPP);
    f.bytes = 128;
    check("proc_fid", syscall(303, AT_FDCWD, "/proc/self/status", &f, &mid, HANDLE_FID) == 0);
    int pp[2];
    pipe(pp);
    f.bytes = 128;
    check("pipe_no_handle", syscall(303, pp[0], "", &f, &mid, AT_EMPTY_PATH) == -1 && errno == EOPNOTSUPP);
    f.bytes = 128;
    check("pipe_fid", syscall(303, pp[0], "", &f, &mid, AT_EMPTY_PATH | HANDLE_FID) == 0);
    close(pp[0]);
    close(pp[1]);
    /* Open it again by its handle (root may: CAP_DAC_READ_SEARCH). */
    f.bytes = 128;
    syscall(303, AT_FDCWD, "/tmp/o2/handled", &f, &mid, 0);
    int m = open("/tmp", O_RDONLY | O_DIRECTORY);
    int h = (int)syscall(304, m, &f, O_RDONLY);
    char got[16] = "";
    check("open_by_handle", h >= 0 && read(h, got, sizeof got) == 9 && memcmp(got, "by handle", 9) == 0);
    close(h);
    /* A file gone: ESTALE. */
    unlink("/tmp/o2/handled");
    check("handle_stale", syscall(304, m, &f, O_RDONLY) == -1 && errno == ESTALE);
    /* An ext4 directory by handle, after a remount (no name cached): its
       path comes back through its parents (the test disk's dir/sub). */
    mkdir("/tmp/o2/e4", 0755);
    if (mount("/dev/vdc", "/tmp/o2/e4", "ext4", MS_RDONLY, NULL) == 0) {
        struct fh dh;
        dh.bytes = 128;
        int dok = syscall(303, AT_FDCWD, "/tmp/o2/e4/dir/sub", &dh, &mid, 0) == 0;
        umount("/tmp/o2/e4");
        mount("/dev/vdc", "/tmp/o2/e4", "ext4", MS_RDONLY, NULL);
        int em = open("/tmp/o2/e4", O_RDONLY | O_DIRECTORY);
        int dfd = dok ? (int)syscall(304, em, &dh, O_RDONLY | O_DIRECTORY) : -1;
        char link[64], path[128] = "";
        snprintf(link, sizeof link, "/proc/self/fd/%d", dfd);
        ssize_t pl = readlink(link, path, sizeof path - 1);
        if (pl > 0) path[pl] = 0;
        check("handle_dir_path", dfd >= 0 && strcmp(path, "/tmp/o2/e4/dir/sub") == 0);
        if (dfd < 0 || strcmp(path, "/tmp/o2/e4/dir/sub") != 0) printf("handle dir: fd %d path %s\n", dfd, path);
        close(dfd);
        close(em);
        umount("/tmp/o2/e4");
    } else {
        check("handle_dir_mount", 0);
    }
    rmdir("/tmp/o2/e4");
    /* Not for everyone. */
    pid_t c = fork();
    if (c == 0) {
        if (setuid(1000) != 0) _exit(2);
        _exit(syscall(304, m, &f, O_RDONLY) == -1 && errno == EPERM ? 0 : 1);
    }
    int st = 0;
    waitpid(c, &st, 0);
    check("open_by_handle_needs_cap", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    close(m);
}

int main(void) {
    openat2_checks();
    handle_checks();
    return failures != 0;
}
