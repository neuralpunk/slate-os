// SPDX-License-Identifier: MIT OR Apache-2.0
// efivarfs's immutable flag and appends (ADR 0088; efivarfs.rst,
// ioctl_iflags(2)): a variable made through the mount is writable, the
// same variable seen through a new mount is immutable until the flag is
// cleared, the standard boot variables are not, and a write with O_APPEND
// appends. Run as root on a UEFI boot; the argument is the mount
// (default /sys/firmware/efi/efivars).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

// ioctl_iflags(2): the requests take an int, the flags are its bits.
#define FS_IOC_GETFLAGS 0x80086601
#define FS_IOC_SETFLAGS 0x40086602
#define FS_IMMUTABLE_FL 0x10
#define FS_APPEND_FL 0x20

static int failures;
static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::efivars::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

#define VAR "SlateFlags-5a4d1c2e-8f3b-4c1a-9e7d-3b2a1c0d9e8f"
#define BOOT_ORDER "BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"

/// The file's flags, or -1.
static int flags_of(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int f = 0;
    int r = ioctl(fd, FS_IOC_GETFLAGS, &f);
    close(fd);
    return r < 0 ? -1 : f;
}

static int set_flags(const char *path, int f) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int r = ioctl(fd, FS_IOC_SETFLAGS, &f);
    close(fd);
    return r;
}

/// Write attributes (non-volatile, boot and runtime access) and `data`.
static int put(const char *path, int extra, const char *data) {
    unsigned char b[64] = {7, 0, 0, 0};
    size_t n = strlen(data);
    memcpy(b + 4, data, n);
    int fd = open(path, O_WRONLY | O_CREAT | extra, 0644);
    if (fd < 0) return -errno;
    ssize_t w = write(fd, b, 4 + n);
    int e = errno;
    close(fd);
    return w == (ssize_t)(4 + n) ? 0 : -e;
}

/// The variable's data (after its attributes) into `out`.
static int get(const char *path, char *out, size_t len) {
    char b[128];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, b, sizeof b);
    close(fd);
    if (n < 4 || (size_t)(n - 4) >= len) return -1;
    memcpy(out, b + 4, n - 4);
    out[n - 4] = 0;
    return 0;
}

int main(int argc, char **argv) {
    const char *ev = argc > 1 ? argv[1] : "/sys/firmware/efi/efivars";
    char path[256], path2[256], got[64];
    snprintf(path, sizeof path, "%s/" VAR, ev);

    check("create", put(path, O_TRUNC, "one") == 0);
    check("created_mutable", flags_of(path) == 0);
    check("append", put(path, O_APPEND, "two") == 0 && get(path, got, sizeof got) == 0 && !strcmp(got, "onetwo"));

    // A new mount starts from the defaults: a vendor variable is immutable.
    mkdir("/tmp/ev2", 0755);
    check("mount_again", mount("efivarfs", "/tmp/ev2", "efivarfs", 0, NULL) == 0);
    snprintf(path2, sizeof path2, "/tmp/ev2/" VAR);
    check("vendor_immutable", flags_of(path2) == FS_IMMUTABLE_FL);
    check("immutable_write", put(path2, O_TRUNC, "three") == -EPERM);
    check("immutable_unlink", unlink(path2) < 0 && errno == EPERM);
    check("still_there", get(path2, got, sizeof got) == 0 && !strcmp(got, "onetwo"));
    snprintf(path2, sizeof path2, "/tmp/ev2/" BOOT_ORDER);
    check("boot_order_mutable", flags_of(path2) == 0);
    snprintf(path2, sizeof path2, "/tmp/ev2/" VAR);
    check("other_flags_refused", set_flags(path2, FS_IMMUTABLE_FL | FS_APPEND_FL) < 0 && errno == EOPNOTSUPP);
    // Changing the flag needs CAP_LINUX_IMMUTABLE.
    pid_t pid = fork();
    if (pid == 0) _exit(setuid(65534) == 0 && set_flags(path2, 0) < 0 && errno == EPERM ? 0 : 1);
    int st = 1;
    waitpid(pid, &st, 0);
    check("clear_needs_cap", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    check("clear", set_flags(path2, 0) == 0 && flags_of(path2) == 0);
    check("unlink", unlink(path2) == 0 && access(path, F_OK) < 0);
    umount("/tmp/ev2");
    rmdir("/tmp/ev2");
    return failures;
}
