// SPDX-License-Identifier: MIT OR Apache-2.0
// The page cache with write-back (M19): writes through write(2) and
// through writable shared mappings, msync, fsync and friends, the size
// and times of data not yet on the disk, and the flusher. Run by
// tests/shell/ext4.sh and slatefs.sh on a mounted disk file system:
// `pagecache write DIR TAG` writes, the script unmounts and mounts again
// (so nothing comes from the cache), and `pagecache verify DIR TAG`
// checks what reached the disk.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;
static const char *tag;
static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s pagecache::%s::%s\n", ok ? "PASS" : "FAIL", tag, name);
    fflush(stdout);
    if (!ok) failures++;
}

#define PAGE 4096
#define BIG (8L << 20)
#define UTIME 1000000000

static const char *dir;
static char *path(const char *name) {
    static char buf[4][512];
    static int n;
    char *b = buf[n++ % 4];
    snprintf(b, 512, "%s/%s", dir, name);
    return b;
}

static unsigned char pat(long i, int seed) {
    return (unsigned char)((i * 31 + seed * 7 + i / 4093) & 0xff);
}

static void fill(unsigned char *b, long off, long len, int seed) {
    for (long i = 0; i < len; i++) b[i] = pat(off + i, seed);
}

static int same(const unsigned char *b, long off, long len, int seed) {
    for (long i = 0; i < len; i++)
        if (b[i] != pat(off + i, seed)) return 0;
    return 1;
}

static int zeros(const unsigned char *b, long len) {
    for (long i = 0; i < len; i++)
        if (b[i]) return 0;
    return 1;
}

static int open_new(const char *name, long size) {
    int fd = open(path(name), O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0 && size && ftruncate(fd, size) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// The whole file, or NULL; its length in *len.
static unsigned char *slurp(const char *name, long *len) {
    int fd = open(path(name), O_RDONLY);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return NULL;
    }
    unsigned char *b = malloc(st.st_size + 1);
    long done = 0;
    while (done < st.st_size) {
        ssize_t r = read(fd, b + done, st.st_size - done);
        if (r <= 0) break;
        done += r;
    }
    close(fd);
    *len = done;
    return b;
}

// pread until `len` bytes or the end (reads may be short).
static long pread_all(int fd, unsigned char *b, long len, long off) {
    long done = 0;
    while (done < len) {
        ssize_t r = pread(fd, b + done, len - done, off + done);
        if (r <= 0) break;
        done += r;
    }
    return done;
}

static long meminfo(const char *key) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;
    char line[128];
    long v = -1;
    size_t k = strlen(key);
    while (fgets(line, sizeof line, f))
        if (strncmp(line, key, k) == 0 && line[k] == ':') v = atol(line + k + 1);
    fclose(f);
    return v;
}

static uint64_t checksum(const unsigned char *b, long len) {
    uint64_t h = 1469598103934665603ULL;
    for (long i = 0; i < len; i++) h = (h ^ b[i]) * 1099511628211ULL;
    return h;
}

// --- writing ---------------------------------------------------------------

static void write_phase(void) {
    // A writable shared mapping, synced twice: the second write comes after
    // write-back made the page read-only again and must still be seen.
    int fd = open_new("mapped", 3 * PAGE);
    unsigned char *m = fd < 0 ? MAP_FAILED : mmap(NULL, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check("map_shared_writable", m != MAP_FAILED);
    if (m != MAP_FAILED) {
        fill(m, 0, 3 * PAGE, 1);
        check("msync", msync(m, 3 * PAGE, MS_SYNC) == 0);
        unsigned char back[PAGE];
        check("read_sees_mapping", pread(fd, back, PAGE, PAGE) == PAGE && same(back, PAGE, PAGE, 1));
        fill(m + PAGE, PAGE, PAGE, 2);
        check("msync_again", msync(m, 3 * PAGE, MS_SYNC) == 0);
        check("read_sees_second_write", pread(fd, back, PAGE, PAGE) == PAGE && same(back, PAGE, PAGE, 2));
        // write(2) shows through the mapping.
        unsigned char w[100];
        fill(w, 2 * PAGE + 50, 100, 3);
        check("mapping_sees_write", pwrite(fd, w, 100, 2 * PAGE + 50) == 100 && same(m + 2 * PAGE + 50, 2 * PAGE + 50, 100, 3));
        munmap(m, 3 * PAGE);
    }
    if (fd >= 0) close(fd);

    // Written through a mapping and never synced: unmapping and closing
    // keep the data, and unmount writes it.
    fd = open_new("unsynced", 2 * PAGE);
    m = fd < 0 ? MAP_FAILED : mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m != MAP_FAILED) {
        fill(m, 0, 2 * PAGE, 4);
        munmap(m, 2 * PAGE);
    }
    if (fd >= 0) close(fd);
    long len = 0;
    unsigned char *b = slurp("unsynced", &len);
    check("unsynced_kept", b && len == 2 * PAGE && same(b, 0, len, 4));
    free(b);

    // A child writes the shared mapping; the parent sees it.
    fd = open_new("forked", PAGE);
    m = fd < 0 ? MAP_FAILED : mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m != MAP_FAILED) {
        m[0] = 'p';
        msync(m, PAGE, MS_SYNC); // Clean again, so the child's write faults.
        pid_t pid = fork();
        if (pid == 0) {
            m[100] = 'c';
            _exit(0);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        check("fork_shared", m[0] == 'p' && m[100] == 'c');
        munmap(m, PAGE);
    } else {
        check("fork_shared", 0);
    }
    if (fd >= 0) close(fd);

    // mprotect makes a read-only shared mapping writable.
    fd = open_new("protected", PAGE);
    m = fd < 0 ? MAP_FAILED : mmap(NULL, PAGE, PROT_READ, MAP_SHARED, fd, 0);
    if (m != MAP_FAILED) {
        int ok = m[0] == 0 && mprotect(m, PAGE, PROT_READ | PROT_WRITE) == 0;
        if (ok) fill(m, 0, PAGE, 5);
        check("mprotect_writable", ok && msync(m, PAGE, MS_SYNC) == 0);
        munmap(m, PAGE);
    } else {
        check("mprotect_writable", 0);
    }
    if (fd >= 0) close(fd);

    // Size and offsets follow cached writes at once.
    fd = open_new("sized", 0);
    b = malloc(10000);
    fill(b, 0, 10000, 6);
    struct stat st;
    int ok = write(fd, b, 10000) == 10000 && fstat(fd, &st) == 0 && st.st_size == 10000;
    check("size_after_write", ok && lseek(fd, 0, SEEK_END) == 10000);
    close(fd);
    fd = open(path("sized"), O_WRONLY | O_APPEND);
    ok = fd >= 0 && write(fd, "tail!", 5) == 5 && fstat(fd, &st) == 0 && st.st_size == 10005;
    check("append", ok);
    if (fd >= 0) close(fd);
    free(b);

    // A write far past the end leaves a hole of zeros.
    fd = open_new("sparse", 0);
    ok = fd >= 0 && pwrite(fd, "x", 1, 1 << 20) == 1 && fstat(fd, &st) == 0 && st.st_size == (1 << 20) + 1;
    unsigned char hole[PAGE];
    memset(hole, 0xff, PAGE);
    check("sparse", ok && pread(fd, hole, PAGE, 12345) == PAGE && zeros(hole, PAGE));
    if (fd >= 0) close(fd);

    // Shrinking drops cached data; growing again reads zeros.
    fd = open_new("truncated", 0);
    b = malloc(10000);
    memset(b, 'a', 10000);
    ok = fd >= 0 && write(fd, b, 10000) == 10000 && ftruncate(fd, 5000) == 0 && ftruncate(fd, 8000) == 0;
    memset(b, 0xff, 10000);
    ok = ok && pread(fd, b, 10000, 0) == 8000;
    int shape = 1;
    for (int i = 0; i < 8000; i++)
        if (b[i] != (i < 5000 ? 'a' : 0)) shape = 0;
    check("truncate_dirty", ok && shape);
    if (fd >= 0) close(fd);
    free(b);

    // An explicit modification time survives the later write-back.
    fd = open_new("timed", 0);
    struct timespec t[2] = {{UTIME, 0}, {UTIME, 0}};
    ok = fd >= 0 && write(fd, "data", 4) == 4 && futimens(fd, t) == 0 && fsync(fd) == 0;
    check("utime_after_write", ok && fstat(fd, &st) == 0 && st.st_mtime == UTIME);
    // A write moves it on, before the data reaches the disk.
    ok = pwrite(fd, "more", 4, 4) == 4 && fstat(fd, &st) == 0 && st.st_mtime > UTIME;
    check("write_sets_mtime", ok);
    if (fd >= 0) close(fd);
    fd = open_new("timed2", 0);
    ok = fd >= 0 && write(fd, "data", 4) == 4 && futimens(fd, t) == 0;
    if (fd >= 0) close(fd);

    // O_SYNC is kept and honoured; the sync calls take their arguments.
    fd = open(path("osync"), O_RDWR | O_CREAT | O_TRUNC | O_SYNC, 0644);
    ok = fd >= 0 && write(fd, "synced", 6) == 6 && (fcntl(fd, F_GETFL) & O_SYNC) == O_SYNC;
    check("o_sync", ok);
    check("fsync", fd >= 0 && fsync(fd) == 0 && fdatasync(fd) == 0);
    check("syncfs", fd >= 0 && syncfs(fd) == 0);
    check("sync_file_range", fd >= 0 && sync_file_range(fd, 0, 0, SYNC_FILE_RANGE_WRITE) == 0);
    check("sync_file_range_bad_flags", sync_file_range(fd, 0, 0, 8) == -1 && errno == EINVAL);
    if (fd >= 0) close(fd);
    void *anon = mmap(NULL, 2 * PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check("msync_bad_flags", msync(anon, PAGE, MS_SYNC | MS_ASYNC) == -1 && errno == EINVAL);
    munmap((char *)anon + PAGE, PAGE);
    check("msync_unmapped", msync(anon, 2 * PAGE, MS_SYNC) == -1 && errno == ENOMEM);
    check("msync_async", msync(anon, PAGE, MS_ASYNC) == 0);
    munmap(anon, PAGE);

    // A big file through write(2), read back.
    fd = open_new("big", 0);
    b = malloc(BIG);
    fill(b, 0, BIG, 7);
    ok = fd >= 0;
    for (long off = 0; ok && off < BIG; off += 65536) ok = write(fd, b + off, 65536) == 65536;
    memset(b, 0, BIG);
    ok = ok && pread_all(fd, b, BIG, 0) == BIG && same(b, 0, BIG, 7);
    check("big_write", ok);
    if (fd >= 0) close(fd);
    free(b);

    // The flusher writes dirty data back within a few seconds.
    if (strcmp(tag, "ext4") == 0) {
        fd = open_new("flushed", 0);
        b = malloc(1 << 20);
        fill(b, 0, 1 << 20, 8);
        ok = fd >= 0 && write(fd, b, 1 << 20) == 1 << 20;
        free(b);
        if (fd >= 0) close(fd);
        check("dirty_counted", ok && meminfo("Dirty") >= 1024);
        long dirty = -1;
        for (int i = 0; i < 150; i++) {
            dirty = meminfo("Dirty");
            if (dirty >= 0 && dirty < 256) break;
            usleep(100000);
        }
        check("flusher", dirty >= 0 && dirty < 256);
        check("cached_counted", meminfo("Cached") >= 1024);
    }
}

// --- verifying (after a fresh mount) ----------------------------------------

static void verify_phase(void) {
    long len = 0;
    unsigned char *b = slurp("mapped", &len);
    int ok = b && len == 3 * PAGE && same(b, 0, PAGE, 1) && same(b + PAGE, PAGE, PAGE, 2) &&
             same(b + 2 * PAGE, 2 * PAGE, 50, 1) && same(b + 2 * PAGE + 50, 2 * PAGE + 50, 100, 3) &&
             same(b + 2 * PAGE + 150, 2 * PAGE + 150, PAGE - 150, 1);
    check("persisted_mapped", ok);
    free(b);
    b = slurp("unsynced", &len);
    check("persisted_unsynced", b && len == 2 * PAGE && same(b, 0, len, 4));
    free(b);
    b = slurp("forked", &len);
    check("persisted_forked", b && len == PAGE && b[0] == 'p' && b[100] == 'c');
    free(b);
    b = slurp("protected", &len);
    check("persisted_mprotect", b && len == PAGE && same(b, 0, PAGE, 5));
    free(b);
    b = slurp("sized", &len);
    check("persisted_sized", b && len == 10005 && same(b, 0, 10000, 6) && memcmp(b + 10000, "tail!", 5) == 0);
    free(b);
    b = slurp("sparse", &len);
    check("persisted_sparse", b && len == (1 << 20) + 1 && zeros(b, 1 << 20) && b[1 << 20] == 'x');
    free(b);
    b = slurp("truncated", &len);
    ok = b && len == 8000;
    for (int i = 0; ok && i < 8000; i++)
        if (b[i] != (i < 5000 ? 'a' : 0)) ok = 0;
    check("persisted_truncate", ok);
    free(b);
    struct stat st;
    check("persisted_utime", stat(path("timed2"), &st) == 0 && st.st_mtime == UTIME && st.st_size == 4);
    b = slurp("osync", &len);
    check("persisted_o_sync", b && len == 6 && memcmp(b, "synced", 6) == 0);
    free(b);
    b = slurp("big", &len);
    unsigned char *want = malloc(BIG);
    fill(want, 0, BIG, 7);
    check("persisted_big", b && len == BIG && checksum(b, len) == checksum(want, BIG));
    free(want);
    free(b);
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: pagecache write|verify DIR TAG\n");
        return 2;
    }
    dir = argv[2];
    tag = argv[3];
    if (strcmp(argv[1], "write") == 0)
        write_phase();
    else
        verify_phase();
    return failures;
}
