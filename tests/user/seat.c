// SPDX-License-Identifier: MIT OR Apache-2.0
// Slate's seatd (ADR 0033) from a client's side, speaking the protocol
// libseat's seatd backend speaks: open the seat, get enabled, open an
// input device and the DRM card (descriptors passed back), refused
// paths, ping, a second session waiting its turn, and devices taken back
// (input revoked, DRM master dropped) when a session closes or leaves.
// Message layouts: seatd's include/protocol.h (MIT).
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define OPEN_SEAT 1
#define CLOSE_SEAT 2
#define OPEN_DEVICE 3
#define CLOSE_DEVICE 4
#define PING 7
#define S(n) (0x8000 + (n))
#define SEAT_OPENED S(1)
#define SEAT_CLOSED S(2)
#define DEVICE_OPENED S(3)
#define DEVICE_CLOSED S(4)
#define ENABLE_SEAT S(6)
#define PONG S(7)
#define ERROR 0xFFFF

// EVIOCGNAME(len) = _IOC(_IOC_READ, 'E', 0x06, len); DRM_IOCTL_AUTH_MAGIC
// = _IOW('d', 0x11, 4) (input.h numbers, libdrm drm.h).
#define EVIOCGNAME(len) (0x80000000u | ((unsigned)(len) << 16) | ('E' << 8) | 0x06)
#define DRM_AUTH_MAGIC 0x40046411u

static int failures;
static void check(const char *name, int ok) {
    printf("%s seat::%s\n", ok ? "SLATE-TEST: PASS" : "SLATE-TEST: FAIL", name);
    if (!ok) failures++;
}

static int conn(void) {
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    strcpy(a.sun_path, "/run/seatd.sock");
    return connect(s, (struct sockaddr *)&a, sizeof a) == 0 ? s : -1;
}

static void put(int s, uint16_t op, const void *body, uint16_t size) {
    uint16_t h[2] = {op, size};
    write(s, h, 4);
    if (size) write(s, body, size);
}

// Read exactly n bytes; collect a passed descriptor into *fd.
static int get(int s, void *buf, size_t n, int *fd) {
    size_t got = 0;
    while (got < n) {
        char c[CMSG_SPACE(sizeof(int))];
        struct iovec iov = {(char *)buf + got, n - got};
        struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = c, .msg_controllen = sizeof c};
        ssize_t r = recvmsg(s, &m, MSG_CMSG_CLOEXEC);
        if (r <= 0) return -1;
        struct cmsghdr *cm = CMSG_FIRSTHDR(&m);
        if (cm && cm->cmsg_type == SCM_RIGHTS && fd) memcpy(fd, CMSG_DATA(cm), sizeof(int));
        got += r;
    }
    return 0;
}

// One message: its opcode; the body goes to body (up to 64 bytes).
static int msg(int s, uint8_t *body, uint16_t *size, int *fd) {
    uint16_t h[2];
    if (get(s, h, 4, fd) || h[1] > 64 || get(s, body, h[1], fd)) return -1;
    *size = h[1];
    return h[0];
}

static int quiet(int s, int ms) {
    struct pollfd p = {s, POLLIN, 0};
    return poll(&p, 1, ms) == 0;
}

static int open_device(int s, const char *path, int *fd, int32_t *code) {
    uint8_t body[2 + 64];
    uint16_t len = strlen(path) + 1, size;
    memcpy(body, &len, 2);
    memcpy(body + 2, path, len);
    put(s, OPEN_DEVICE, body, 2 + len);
    *fd = -1;
    int op = msg(s, body, &size, fd);
    memcpy(code, body, 4);
    return op;
}

int main(void) {
    uint8_t body[64];
    uint16_t size;
    int s1 = conn();
    check("connect", s1 >= 0);
    put(s1, OPEN_SEAT, NULL, 0);
    int op = msg(s1, body, &size, NULL);
    check("seat_opened", op == SEAT_OPENED && size == 8 && memcmp(body, "\x06\0seat0\0", 8) == 0);
    check("enabled", msg(s1, body, &size, NULL) == ENABLE_SEAT && size == 0);

    int ev = -1;
    int32_t id;
    op = open_device(s1, "/dev/input/event0", &ev, &id);
    char name[64] = "";
    check("input_opened", op == DEVICE_OPENED && ev >= 0 && ioctl(ev, EVIOCGNAME(sizeof name), name) > 0);
    int junk;
    int32_t code;
    check("refused_path", open_device(s1, "/dev/sda", &junk, &code) == ERROR && code == EPERM);
    put(s1, PING, NULL, 0);
    check("pong", msg(s1, body, &size, NULL) == PONG);

    // A second session waits for the first.
    int s2 = conn();
    put(s2, OPEN_SEAT, NULL, 0);
    check("second_waits", msg(s2, body, &size, NULL) == SEAT_OPENED && quiet(s2, 300));
    check("second_no_devices", open_device(s2, "/dev/input/event0", &junk, &code) == ERROR && code == EPERM);

    put(s1, CLOSE_DEVICE, &id, 4);
    check("input_closed", msg(s1, body, &size, NULL) == DEVICE_CLOSED);
    check("input_revoked", ioctl(ev, EVIOCGNAME(sizeof name), name) < 0 && errno == ENODEV);
    put(s1, CLOSE_SEAT, NULL, 0);
    check("seat_closed", msg(s1, body, &size, NULL) == SEAT_CLOSED);
    check("second_enabled", msg(s2, body, &size, NULL) == ENABLE_SEAT);

    // The DRM card comes with master, which goes when the session does.
    int card = -1;
    uint32_t zero = 0;
    op = open_device(s2, "/dev/dri/card0", &card, &id);
    check("drm_master", op == DEVICE_OPENED && card >= 0 && ioctl(card, DRM_AUTH_MAGIC, &zero) < 0 && errno == EINVAL);
    close(s2);
    usleep(300000);
    check("drm_master_dropped", ioctl(card, DRM_AUTH_MAGIC, &zero) < 0 && errno == EACCES);
    close(card);
    close(ev);
    close(s1);
    return failures != 0;
}
