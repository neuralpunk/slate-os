// SPDX-License-Identifier: MIT OR Apache-2.0
// evdev on Slate (ADR 0033), as libevdev queries it.
//   evdev            list /dev/input/event*: name, id, what it reports
//   evdev watch N T  print events from /dev/input/eventN for T seconds,
//                    one per line: "event TYPE CODE VALUE"
// Numbers: the UAPI linux/input.h, as a table of facts (ADR 0033).
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#define IOR(nr, size) (0x80000000u | ((unsigned)(size) << 16) | ('E' << 8) | (nr))
#define IOW(nr, size) (0x40000000u | ((unsigned)(size) << 16) | ('E' << 8) | (nr))
#define EVIOCGVERSION IOR(0x01, 4)
#define EVIOCGID IOR(0x02, 8)
#define EVIOCGNAME(len) IOR(0x06, len)
#define EVIOCGBIT(ev, len) IOR(0x20 + (ev), len)
#define EVIOCGABS(abs) IOR(0x40 + (abs), 24)
#define EVIOCGREP IOR(0x03, 8)
#define EVIOCGLED(len) IOR(0x19, len)
#define EVIOCGRAB IOW(0x90, 4)
#define EVIOCSCLOCKID IOW(0xa0, 4)

struct event { int64_t sec, usec; uint16_t type, code; int32_t value; };
struct absinfo { int32_t value, min, max, fuzz, flat, res; };

static int has(const uint8_t *bits, int n) { return bits[n / 8] & (1 << (n % 8)); }

static int list(void) {
    int found = 0;
    for (int n = 0; n < 32; n++) {
        char path[32];
        snprintf(path, sizeof path, "/dev/input/event%d", n);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        found++;
        int version = 0;
        uint16_t id[4] = {0};
        char name[64] = {0};
        uint8_t types[4] = {0}, keys[96] = {0}, rel[2] = {0}, abs[8] = {0};
        int ok = ioctl(fd, EVIOCGVERSION, &version) == 0 && version == 0x010001 && ioctl(fd, EVIOCGID, id) == 0 &&
                 ioctl(fd, EVIOCGNAME(sizeof name), name) > 0 && ioctl(fd, EVIOCGBIT(0, sizeof types), types) > 0;
        ioctl(fd, EVIOCGBIT(1, sizeof keys), keys);
        ioctl(fd, EVIOCGBIT(2, sizeof rel), rel);
        ioctl(fd, EVIOCGBIT(3, sizeof abs), abs);
        printf("event%d: %s \"%s\" bus %04x%s%s%s%s%s", n, ok ? "ok" : "BAD", name, id[0],
               has(keys, 30) ? " keyboard" : "", has(keys, 0x110) ? " buttons" : "", has(rel, 0) ? " rel" : "",
               has(abs, 0) ? " abs" : "", has(types, 0x14) ? " rep" : "");
        if (has(abs, 0)) {
            struct absinfo a;
            if (ioctl(fd, EVIOCGABS(0), &a) == 0) printf(" x:%d..%d", a.min, a.max);
        }
        printf("\n");
        close(fd);
    }
    printf("devices: %d\n", found);
    return found > 0 ? 0 : 1;
}

static int watch(int n, int secs) {
    char path[32];
    snprintf(path, sizeof path, "/dev/input/event%d", n);
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) { perror(path); return 1; }
    int clock = CLOCK_MONOTONIC;
    if (ioctl(fd, EVIOCSCLOCKID, &clock) != 0) { perror("EVIOCSCLOCKID"); return 1; }
    printf("watching\n");
    fflush(stdout);
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long left = secs * 1000 - ((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000);
        if (left <= 0) break;
        struct pollfd p = {.fd = fd, .events = POLLIN};
        if (poll(&p, 1, left) <= 0) continue;
        struct event ev[16];
        ssize_t got = read(fd, ev, sizeof ev);
        for (ssize_t i = 0; i < got / (ssize_t)sizeof ev[0]; i++)
            if (ev[i].type != 0) printf("event %u %u %d\n", ev[i].type, ev[i].code, ev[i].value);
        fflush(stdout);
    }
    close(fd);
    return 0;
}

/* A keyboard's lights (EVIOCGLED) and repeat settings (EVIOCGREP); with a
   code and value, an EV_LED event written first. */
static int leds(int n, int code, int value) {
    char path[32];
    snprintf(path, sizeof path, "/dev/input/event%d", n);
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) { perror(path); return 1; }
    if (code >= 0) {
        struct event e = {.type = 0x11, .code = code, .value = value};
        struct event syn = {0};
        if (write(fd, &e, sizeof e) != sizeof e || write(fd, &syn, sizeof syn) != sizeof syn) { perror("write"); return 1; }
    }
    uint8_t bits[2] = {0};
    uint32_t r[2] = {0};
    if (ioctl(fd, EVIOCGLED(sizeof bits), bits) < 0 || ioctl(fd, EVIOCGREP, r) != 0) { perror("ioctl"); return 1; }
    printf("leds 0x%x repeat %u %u\n", bits[0], r[0], r[1]);
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "watch") == 0) return watch(atoi(argv[2]), atoi(argv[3]));
    if (argc == 3 && strcmp(argv[1], "leds") == 0) return leds(atoi(argv[2]), -1, 0);
    if (argc == 5 && strcmp(argv[1], "setled") == 0) return leds(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
    return list();
}
