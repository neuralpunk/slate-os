// SPDX-License-Identifier: MIT OR Apache-2.0
// Slate's seatd (ADR 0033) from a client's side, speaking the protocol
// libseat's seatd backend speaks: open the seat, get enabled, open an
// input device and the DRM card (descriptors passed back), refused
// paths, ping, a second session waiting its turn, and devices taken back
// (input revoked, DRM master dropped) when a session closes or leaves;
// then sessions on two virtual consoles switching (ADR 0185).
// Message layouts: seatd's include/protocol.h (MIT); VT ioctls:
// console_ioctl(2).
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define KDGETMODE 0x4B3B
#define KD_TEXT 0x00
#define VT_GETSTATE 0x5603
#define VT_ACTIVATE 0x5606

#define OPEN_SEAT 1
#define CLOSE_SEAT 2
#define OPEN_DEVICE 3
#define CLOSE_DEVICE 4
#define DISABLE_SEAT 5
#define SWITCH_SESSION 6
#define PING 7
#define S(n) (0x8000 + (n))
#define SEAT_OPENED S(1)
#define SEAT_CLOSED S(2)
#define DEVICE_OPENED S(3)
#define DEVICE_CLOSED S(4)
#define DISABLE_SEAT_EV S(5)
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

// The next message within `ms`, or -1.
static int msg_within(int s, int ms, uint8_t *body, uint16_t *size, int *fd) {
    struct pollfd p = {s, POLLIN, 0};
    if (poll(&p, 1, ms) != 1) return -1;
    return msg(s, body, size, fd);
}

static int front(void) {
    int t = open("/dev/tty0", O_RDWR | O_NOCTTY);
    unsigned short st[3] = {0};
    ioctl(t, VT_GETSTATE, st);
    close(t);
    return st[0];
}

static void activate(int vt) {
    int t = open("/dev/tty0", O_RDWR | O_NOCTTY);
    ioctl(t, VT_ACTIVATE, vt);
    close(t);
}

/// A session on virtual console `vt`: a child that takes the VT as its
/// controlling terminal (seatd reads the session from the opener) and
/// speaks to seatd as the parent tells it, one command byte at a time,
/// answering 'y' or 'n'. (The connection itself can't be handed to this
/// Linux-domain parent: it stays in the Slate domain, ADR 0098.)
struct session {
    pid_t pid;
    int cmd, res;
};

static void session_loop(int vt, int cmd, int res) {
    setsid();
    char path[16];
    snprintf(path, sizeof path, "/dev/tty%d", vt);
    int t = open(path, O_RDWR);
    int s = conn();
    uint8_t body[64];
    uint16_t size;
    put(s, OPEN_SEAT, NULL, 0);
    char ok = t >= 0 && msg(s, body, &size, NULL) == SEAT_OPENED ? 'y' : 'n';
    write(res, &ok, 1);
    int ev = -1, card = -1, junk;
    int32_t id, code;
    uint32_t zero = 0;
    char name[64];
    for (;;) {
        char c;
        if (read(cmd, &c, 1) != 1) _exit(0);
        int r = 0;
        switch (c) {
        case 'E': r = msg_within(s, 4000, body, &size, NULL) == ENABLE_SEAT; break;
        case 'D': r = msg_within(s, 1000, body, &size, NULL) == DISABLE_SEAT_EV; break;
        case 'Q': r = quiet(s, 300); break;
        case 'A': put(s, DISABLE_SEAT, NULL, 0); r = 1; break;
        case 'O':
            open_device(s, "/dev/input/event0", &ev, &id);
            open_device(s, "/dev/dri/card0", &card, &id);
            r = ev >= 0 && card >= 0;
            break;
        case 'M': r = ioctl(card, DRM_AUTH_MAGIC, &zero) < 0 && errno == EINVAL; break;
        case 'R':
            r = ioctl(ev, EVIOCGNAME(sizeof name), name) < 0 && errno == ENODEV &&
                ioctl(card, DRM_AUTH_MAGIC, &zero) < 0 && errno == EACCES;
            break;
        case 'N': r = open_device(s, "/dev/input/event0", &junk, &code) == ERROR && code == EPERM; break;
        case 'X': _exit(0);
        default:
            if (c >= '1' && c <= '9') {
                int32_t to = c - '0';
                put(s, SWITCH_SESSION, &to, 4);
                r = 1;
            }
        }
        char a = r ? 'y' : 'n';
        write(res, &a, 1);
    }
}

static struct session session_on(int vt, int *ok) {
    int cmd[2], res[2];
    struct session x = {-1, -1, -1};
    if (pipe(cmd) || pipe(res)) return x;
    x.pid = fork();
    if (x.pid == 0) {
        close(cmd[1]);
        close(res[0]);
        session_loop(vt, cmd[0], res[1]);
    }
    close(cmd[0]);
    close(res[1]);
    x.cmd = cmd[1];
    x.res = res[0];
    char c = 'n';
    read(x.res, &c, 1);
    *ok = c == 'y';
    return x;
}

/// Ask session `x` to do `c`; whether it says it went as expected.
static int ask(struct session x, char c) {
    char a = 'n';
    if (write(x.cmd, &c, 1) != 1 || read(x.res, &a, 1) != 1) return 0;
    return a == 'y';
}

static void end(struct session x) {
    char c = 'X';
    write(x.cmd, &c, 1);
    waitpid(x.pid, NULL, 0);
    close(x.cmd);
    close(x.res);
}

static void switching(void) {
    activate(3);
    check("vt3_in_front", front() == 3);
    int ok_a = 0, ok_b = 0;
    struct session a = session_on(3, &ok_a);
    check("session_on_vt3", ok_a && ask(a, 'E'));
    struct session b = session_on(4, &ok_b);
    check("vt4_waits", ok_b && ask(b, 'Q'));
    check("a_has_devices", ask(a, 'O') && ask(a, 'M'));

    // a asks for VT 4: it is told to step aside, and the switch waits for
    // its answer.
    ask(a, '4');
    check("a_disabled", ask(a, 'D'));
    check("switch_waits", front() == 3 && ask(b, 'Q'));
    ask(a, 'A');
    check("b_enabled", ask(b, 'E') && front() == 4);
    check("a_devices_taken", ask(a, 'R'));
    check("a_no_devices", ask(a, 'N'));

    // b asks for VT 3 and never answers: after the grace time it is
    // disabled anyway, and a gets the seat and its card's master back.
    ask(b, '3');
    check("b_disabled", ask(b, 'D'));
    check("a_enabled_after_grace", ask(a, 'E') && front() == 3);
    check("a_master_back", ask(a, 'M'));

    // To a text console (no client) and back with VT_ACTIVATE.
    ask(a, '2');
    check("a_disabled_for_text", ask(a, 'D'));
    ask(a, 'A');
    usleep(300000);
    check("text_vt_in_front", front() == 2);
    activate(3);
    check("a_enabled_from_text", ask(a, 'E') && front() == 3);

    // Both go: seatd gives the VTs back to the console.
    end(a);
    end(b);
    usleep(300000);
    int t3 = open("/dev/tty3", O_RDWR | O_NOCTTY);
    int mode = -1;
    check("vt3_given_back", t3 >= 0 && ioctl(t3, KDGETMODE, &mode) == 0 && mode == KD_TEXT);
    close(t3);
    activate(1);
    check("vt1_again", front() == 1);
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
    switching();
    return failures != 0;
}
