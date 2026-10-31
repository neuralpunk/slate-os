// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Virtual consoles (ADR 0185): the console_ioctl(2) interface on
// /dev/tty0 to /dev/tty12. Leaves VT 1 in front, as it found it.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

// console_ioctl(2).
#define KDGKBTYPE 0x4B33
#define KDSETMODE 0x4B3A
#define KDGETMODE 0x4B3B
#define KDGKBMODE 0x4B44
#define KDSKBMODE 0x4B45
#define KD_TEXT 0x00
#define KD_GRAPHICS 0x01
#define K_UNICODE 0x03
#define K_OFF 0x04
#define VT_OPENQRY 0x5600
#define VT_GETMODE 0x5601
#define VT_SETMODE 0x5602
#define VT_GETSTATE 0x5603
#define VT_RELDISP 0x5605
#define VT_ACTIVATE 0x5606
#define VT_WAITACTIVE 0x5607
#define VT_AUTO 0x00
#define VT_PROCESS 0x01
#define VT_ACKACQ 0x02

struct vt_mode {
    char mode, waitv;
    short relsig, acqsig, frsig;
};
struct vt_stat {
    unsigned short v_active, v_signal, v_state;
};

static int failures;
static volatile sig_atomic_t released, acquired;

static void check(int ok, const char *name) {
    printf("SLATE-TEST: %s user::vt::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

static void on_release(int s) {
    (void)s;
    released++;
}
static void on_acquire(int s) {
    (void)s;
    acquired++;
}

static int active(int fd) {
    struct vt_stat st;
    return ioctl(fd, VT_GETSTATE, &st) == 0 ? st.v_active : -1;
}

/// Wait up to a second for `flag` to be set.
static int waited(volatile sig_atomic_t *flag) {
    for (int i = 0; i < 100 && !*flag; i++) usleep(10000);
    return *flag != 0;
}

int main(void) {
    int t0 = open("/dev/tty0", O_RDWR | O_NOCTTY);
    check(t0 >= 0, "open_tty0");
    if (t0 < 0) return 1;
    char kb = 0;
    check(ioctl(t0, KDGKBTYPE, &kb) == 0 && kb == 0x02, "kbtype");
    check(active(t0) == 1, "vt1_in_front");

    int free = 0;
    check(ioctl(t0, VT_OPENQRY, &free) == 0 && free >= 2, "openqry");
    char path[32];
    snprintf(path, sizeof path, "/dev/tty%d", free);
    int t2 = open(path, O_RDWR | O_NOCTTY);
    struct vt_stat st;
    check(t2 >= 0 && ioctl(t0, VT_GETSTATE, &st) == 0 && (st.v_state & (1 << free)), "opened_in_state");
    int next = 0;
    check(ioctl(t0, VT_OPENQRY, &next) == 0 && next != free, "openqry_skips_open");

    // VT_AUTO: a switch happens at once.
    check(ioctl(t0, VT_ACTIVATE, free) == 0 && ioctl(t0, VT_WAITACTIVE, free) == 0 && active(t0) == free,
          "activate_auto");
    check(write(t2, "on a virtual console\r\n", 22) == 22, "write");
    check(ioctl(t0, VT_ACTIVATE, 1) == 0 && active(t0) == 1, "back_to_1");

    // Modes.
    int mode = -1;
    check(ioctl(t2, KDGETMODE, &mode) == 0 && mode == KD_TEXT, "kd_text");
    check(ioctl(t2, KDSETMODE, KD_GRAPHICS) == 0 && ioctl(t2, KDGETMODE, &mode) == 0 && mode == KD_GRAPHICS,
          "kd_graphics");
    check(ioctl(t2, KDGKBMODE, &mode) == 0 && mode == K_UNICODE, "kb_unicode");
    check(ioctl(t2, KDSKBMODE, K_OFF) == 0 && ioctl(t2, KDGKBMODE, &mode) == 0 && mode == K_OFF, "kb_off");
    check(ioctl(t2, KDSETMODE, 7) < 0 && errno == EINVAL, "kd_bad_mode");

    // VT_PROCESS: the owner is told when its VT comes and is to go, and
    // the switch waits for VT_RELDISP.
    signal(SIGUSR1, on_release);
    signal(SIGUSR2, on_acquire);
    struct vt_mode vm = {VT_PROCESS, 0, SIGUSR1, SIGUSR2, 0};
    check(ioctl(t2, VT_SETMODE, &vm) == 0, "setmode_process");
    struct vt_mode got;
    check(ioctl(t2, VT_GETMODE, &got) == 0 && got.mode == VT_PROCESS && got.relsig == SIGUSR1, "getmode");
    check(ioctl(t0, VT_ACTIVATE, free) == 0 && waited(&acquired) && active(t0) == free, "acquire_signal");
    check(ioctl(t2, VT_RELDISP, VT_ACKACQ) == 0, "ack_acquire");
    check(ioctl(t0, VT_ACTIVATE, 1) == 0 && waited(&released) && active(t0) == free, "release_waits");
    check(ioctl(t2, VT_RELDISP, 0) == 0 && active(t0) == free, "release_refused");
    released = 0;
    check(ioctl(t0, VT_ACTIVATE, 1) == 0 && waited(&released) && ioctl(t2, VT_RELDISP, 1) == 0 && active(t0) == 1,
          "release_allowed");

    // Back as it was.
    vm.mode = VT_AUTO;
    ioctl(t2, VT_SETMODE, &vm);
    ioctl(t2, KDSKBMODE, K_UNICODE);
    ioctl(t2, KDSETMODE, KD_TEXT);
    check(ioctl(t2, VT_RELDISP, 1) < 0 && errno == EINVAL, "reldisp_needs_process");
    close(t2);
    check(ioctl(t0, VT_GETSTATE, &st) == 0 && !(st.v_state & (1 << free)), "closed_in_state");
    check(ioctl(t0, VT_ACTIVATE, 13) < 0 && errno == ENXIO, "no_vt_13");
    return failures;
}
