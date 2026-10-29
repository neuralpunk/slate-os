// SPDX-License-Identifier: MIT OR Apache-2.0
// Real-hardware disk drivers (M16): an AHCI disk (/dev/sda, empty) and an
// NVMe disk (/dev/nvme0n1, with a GPT made by xtask), their /proc and /sys
// entries, transfers larger than one command, and BLKRRPART. xtask checks
// the written patterns on the host images after the run.
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static int failures;
static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::disks::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

#define DISK_SIZE (32L << 20)
// Keep in sync with tools/xtask/src/qemu.rs (check_hw_disks).
#define SDA_OFFSET ((1L << 20) + 7)
#define SDA_LEN 700000L
#define NVME_PART_START (9L << 20)
#define NVME_OFFSET 12388L
#define NVME_LEN 600000L

static int read_file(const char *path, char *buf, size_t n) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, n - 1);
    close(fd);
    if (r < 0) return -1;
    buf[r] = 0;
    return (int)r;
}

static int file_is(const char *path, const char *want) {
    char buf[256];
    return read_file(path, buf, sizeof buf) >= 0 && strcmp(buf, want) == 0;
}

static int pattern(int fd, long off, long len, int mul, int add, int mod) {
    unsigned char *buf = malloc(len), *back = malloc(len);
    for (long i = 0; i < len; i++) buf[i] = (i * mul + add) % mod;
    int ok = pwrite(fd, buf, len, off) == len && fsync(fd) == 0;
    memset(back, 0, len);
    ok = ok && pread(fd, back, len, off) == len && memcmp(buf, back, len) == 0;
    free(buf);
    free(back);
    return ok;
}

// One record of an MBR-shaped sector (UEFI 2.10 §5.2.1): type at 4,
// first sector at 8, size at 12; and the 0xAA55 signature.
static void mbr_record(unsigned char *s, int slot, int type, uint32_t start, uint32_t size) {
    unsigned char *e = s + 446 + 16 * slot;
    e[4] = (unsigned char)type;
    memcpy(e + 8, &start, 4);
    memcpy(e + 12, &size, 4);
    s[510] = 0x55;
    s[511] = 0xAA;
}

static int exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

int main(void) {
    char parts[4096];
    int n = read_file("/proc/partitions", parts, sizeof parts);
    check("proc_partitions", n > 0 && strstr(parts, " sda\n") && strstr(parts, " nvme0n1\n") &&
                                 strstr(parts, " nvme0n1p1\n") && strstr(parts, " nvme0n1p2\n") &&
                                 strstr(parts, "   8        0      32768 sda\n"));

    struct stat st;
    check("sda_node", stat("/dev/sda", &st) == 0 && S_ISBLK(st.st_mode) && major(st.st_rdev) == 8 &&
                          minor(st.st_rdev) == 0);
    check("nvme_partition_node", stat("/dev/nvme0n1p2", &st) == 0 && S_ISBLK(st.st_mode) &&
                                     major(st.st_rdev) == 259 && minor(st.st_rdev) == 2);

    check("sys_model_ahci", file_is("/sys/block/sda/device/model", "QEMU HARDDISK\n"));
    check("sys_model_nvme", file_is("/sys/block/nvme0n1/device/model", "QEMU NVMe Ctrl\n"));
    check("sys_size", file_is("/sys/block/sda/size", "65536\n") && file_is("/sys/block/sda/removable", "0\n") &&
                          file_is("/sys/block/sda/dev", "8:0\n"));
    check("sys_partition", file_is("/sys/block/nvme0n1/nvme0n1p2/start", "18432\n") &&
                               file_is("/sys/block/nvme0n1/nvme0n1p2/partition", "2\n"));

    int sda = open("/dev/sda", O_RDWR);
    uint64_t size = 0;
    check("ahci_size", sda >= 0 && ioctl(sda, BLKGETSIZE64, &size) == 0 && size == DISK_SIZE);
    // 700000 bytes: unaligned at both ends and several commands long.
    check("ahci_pattern", pattern(sda, SDA_OFFSET, SDA_LEN, 13, 5, 253));

    int p2 = open("/dev/nvme0n1p2", O_RDWR);
    check("nvme_pattern", p2 >= 0 && pattern(p2, NVME_OFFSET, NVME_LEN, 11, 1, 241));

    // A partition in use keeps its disk's table from being re-read.
    int nvme = open("/dev/nvme0n1", O_RDONLY);
    check("rescan_busy", nvme >= 0 && ioctl(nvme, BLKRRPART) == -1 && errno == EBUSY);
    close(p2);
    check("rescan_nvme", ioctl(nvme, BLKRRPART) == 0 && exists("/dev/nvme0n1p2"));

    // Give sda the NVMe disk's table (same size), and have it re-read.
    char table[34 * 512];
    check("copy_gpt", pread(nvme, table, sizeof table, 0) == sizeof table &&
                          pwrite(sda, table, sizeof table, 0) == sizeof table && fsync(sda) == 0);
    check("rescan_new_table", ioctl(sda, BLKRRPART) == 0 && exists("/dev/sda1") && exists("/dev/sda2") &&
                                  file_is("/sys/block/sda/sda2/start", "18432\n"));
    n = read_file("/proc/partitions", parts, sizeof parts);
    check("rescan_proc", n > 0 && strstr(parts, " sda2\n"));
    // And take it away again.
    char zero[512] = {0};
    check("rescan_removed", pwrite(sda, zero, 512, 512) == 512 && ioctl(sda, BLKRRPART) == 0 &&
                                !exists("/dev/sda1") && !exists("/dev/sda2") &&
                                !exists("/sys/block/sda/sda1"));

    // An MBR (M23 phase 4): primary 1, an extended partition 2 holding
    // two logical partitions, numbered 5 and 6 as sfdisk lists them; the
    // extended container is no device of its own.
    unsigned char mbr[512] = {0}, ebr1[512] = {0}, ebr2[512] = {0};
    mbr_record(mbr, 0, 0x83, 2048, 4096);
    mbr_record(mbr, 1, 0x0F, 8192, 16384);
    mbr_record(ebr1, 0, 0x83, 2048, 2048);
    mbr_record(ebr1, 1, 0x05, 4096, 4096);
    mbr_record(ebr2, 0, 0x83, 2048, 2048);
    check("mbr_write", pwrite(sda, ebr1, 512, 8192L * 512) == 512 && pwrite(sda, ebr2, 512, 12288L * 512) == 512 &&
                           pwrite(sda, mbr, 512, 0) == 512 && fsync(sda) == 0);
    check("mbr_partitions", ioctl(sda, BLKRRPART) == 0 && exists("/dev/sda1") && exists("/dev/sda5") &&
                                exists("/dev/sda6") && !exists("/dev/sda2") &&
                                file_is("/sys/block/sda/sda1/start", "2048\n") &&
                                file_is("/sys/block/sda/sda5/start", "10240\n") &&
                                file_is("/sys/block/sda/sda6/start", "14336\n") &&
                                file_is("/sys/block/sda/sda6/size", "2048\n"));
    check("mbr_removed", pwrite(sda, zero, 512, 0) == 512 && ioctl(sda, BLKRRPART) == 0 && !exists("/dev/sda1") &&
                             !exists("/dev/sda5"));
    close(nvme);
    close(sda);
    return failures ? 1 : 0;
}
