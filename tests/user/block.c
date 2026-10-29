// SPDX-License-Identifier: MIT OR Apache-2.0
// Block devices: the boot disk's GPT through /dev/vda, partitions, and
// reads and writes on the scratch disk /dev/vdb (checked again on the host
// by xtask after the run); O_DIRECT on /dev/vda.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;
static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::block::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

#define SCRATCH_SIZE (16L << 20)
#define PATTERN_OFFSET 12345L
#define PATTERN_LEN 300000L

int main(void) {
    char sector[512];
    int vda = open("/dev/vda", O_RDONLY);
    check("gpt_header", vda >= 0 && pread(vda, sector, 512, 512) == 512 && memcmp(sector, "EFI PART", 8) == 0);
    struct stat st;
    check("stat_blockdev", stat("/dev/vda1", &st) == 0 && S_ISBLK(st.st_mode) && major(st.st_rdev) == 253 &&
                               minor(st.st_rdev) == 1);
    // The ESP is FAT32: boot signature at the end of its first sector.
    int esp = open("/dev/vda1", O_RDONLY);
    check("partition_read", esp >= 0 && read(esp, sector, 512) == 512 && (uint8_t)sector[510] == 0x55 &&
                                (uint8_t)sector[511] == 0xAA && memcmp(sector + 82, "FAT32", 5) == 0);
    close(esp);
    close(vda);

    // O_DIRECT (ADR 0162): whole sectors into sector-aligned buffers, else
    // EINVAL (open(2)); F_GETFL shows it, F_SETFL takes it off; statx(2)'s
    // STATX_DIOALIGN (0x2000) says the alignment (stx_dio_mem_align and
    // stx_dio_offset_align at 0x98 and 0x9c).
    static char page[8192] __attribute__((aligned(4096)));
    int dv = open("/dev/vda", O_RDONLY | O_DIRECT);
    check("direct_aligned", dv >= 0 && pread(dv, page, 512, 512) == 512 && memcmp(page, "EFI PART", 8) == 0);
    errno = 0;
    check("direct_unaligned_buffer", pread(dv, page + 1, 512, 512) == -1 && errno == EINVAL);
    errno = 0;
    check("direct_unaligned_length", pread(dv, page, 100, 512) == -1 && errno == EINVAL);
    errno = 0;
    check("direct_unaligned_offset", pread(dv, page, 512, 100) == -1 && errno == EINVAL);
    check("direct_getfl", (fcntl(dv, F_GETFL) & O_DIRECT) != 0);
    check("direct_setfl_off", fcntl(dv, F_SETFL, fcntl(dv, F_GETFL) & ~O_DIRECT) == 0 &&
                                  pread(dv, page + 1, 100, 512) == 100 && memcmp(page + 1, "EFI PART", 8) == 0);
    close(dv);
    unsigned char sx[256] = {0};
    uint32_t mask, mem_align, offset_align;
    long r = syscall(SYS_statx, AT_FDCWD, "/dev/vda", 0, 0x2000, sx);
    memcpy(&mask, sx, 4);
    memcpy(&mem_align, sx + 0x98, 4);
    memcpy(&offset_align, sx + 0x9c, 4);
    check("statx_dioalign", r == 0 && (mask & 0x2000) && mem_align == 512 && offset_align == 512);

    int fd = open("/dev/vdb", O_RDWR);
    uint64_t size = 0;
    check("size_ioctl", fd >= 0 && ioctl(fd, BLKGETSIZE64, &size) == 0 && size == SCRATCH_SIZE &&
                            lseek(fd, 0, SEEK_END) == SCRATCH_SIZE);

    // An unaligned write spanning many sectors and more than one request.
    unsigned char *buf = malloc(PATTERN_LEN), *back = malloc(PATTERN_LEN);
    for (long i = 0; i < PATTERN_LEN; i++) buf[i] = (i * 7 + 3) % 251;
    check("unaligned_write", pwrite(fd, buf, PATTERN_LEN, PATTERN_OFFSET) == PATTERN_LEN);
    memset(back, 0, PATTERN_LEN);
    check("read_back", pread(fd, back, PATTERN_LEN, PATTERN_OFFSET) == PATTERN_LEN &&
                           memcmp(buf, back, PATTERN_LEN) == 0);
    // Neighbouring bytes in the partial sectors were preserved.
    unsigned char edge[2];
    check("neighbours_kept", pread(fd, edge, 1, PATTERN_OFFSET - 1) == 1 && edge[0] == 0 &&
                                 pread(fd, edge, 1, PATTERN_OFFSET + PATTERN_LEN) == 1 && edge[0] == 0);
    // Writes stop at the end of the device.
    check("write_at_end", pwrite(fd, buf, 200, SCRATCH_SIZE - 100) == 100 && pread(fd, back, 200, SCRATCH_SIZE - 100) == 100 &&
                              memcmp(back, buf, 100) == 0);
    check("read_past_end", pread(fd, back, 10, SCRATCH_SIZE) == 0);
    // One read of a disk fills the whole buffer, as on Linux (dd counts
    // short reads as partial records); at the end it returns what is left.
    unsigned char *big = malloc(1 << 20);
    check("full_read", lseek(fd, 0, SEEK_SET) == 0 && read(fd, big, 1 << 20) == (1 << 20) &&
                           lseek(fd, SCRATCH_SIZE - 4096, SEEK_SET) >= 0 && read(fd, big, 1 << 20) == 4096);
    free(big);

    // Concurrent writers and readers on separate regions.
    for (int c = 0; c < 4; c++) {
        if (fork() == 0) {
            int f = open("/dev/vdb", O_RDWR);
            static unsigned char mine[65536], got[65536];
            int ok = 1;
            for (int round = 0; round < 8 && ok; round++) {
                memset(mine, c * 16 + round, sizeof mine);
                off_t at = (4L << 20) + c * 65536L;
                ok = pwrite(f, mine, sizeof mine, at) == sizeof mine && pread(f, got, sizeof got, at) == sizeof got &&
                     memcmp(mine, got, sizeof mine) == 0;
            }
            _exit(ok ? 0 : 1);
        }
    }
    int all = 1, status;
    for (int c = 0; c < 4; c++) all &= wait(&status) > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    check("concurrent", all);
    check("fsync", fsync(fd) == 0 && ioctl(fd, BLKFLSBUF, 0) == 0);
    // Leave the region after the pattern zeroed again for the host check.
    memset(back, 0, 200);
    pwrite(fd, back, 100, SCRATCH_SIZE - 100);
    close(fd);
    return failures != 0;
}
