// SPDX-License-Identifier: MIT OR Apache-2.0
// DRM/KMS on Slate (ADR 0033, ADR 0100), driven the way libdrm and
// wlroots drive it.
//
// Legacy: version and capabilities, resources, connector and modes,
// planes, dumb buffers mapped and shown with SETCRTC, a page flip with its
// event, PRIME export and import, an empty lease (wlroots' buffer
// allocator), CLOSEFB and DIRTYFB with a clip.
//
// Atomic (ADR 0100): the properties by name, the connector's EDID, a
// MODE_ID blob, test-only commits (and refused ones: a modeset without
// ALLOW_MODESET, a primary plane that doesn't cover the screen), flips
// with events counted by the vblank clock and EBUSY while one is pending,
// the cursor plane, gamma where the card has it, WAIT_VBLANK and the CRTC
// sequence calls, authentication (magic, GETFB's handle) and mmap kept to
// a file's own buffers. With two outputs, the second one lights up red.
//
// "hotplug-wait N" waits up to N seconds for the kernel's uevent of a DRM
// hotplug (a "change" with HOTPLUG=1) and prints it.
//
// "hold N" keeps the picture up N seconds for the scenario's screenshot:
// green, a blue strip at the top (a second strip, drawn but never marked
// dirty, must not reach a virtio-gpu screen), a white 64 x 64 cursor at
// (200, 200), and, where the card has gamma, an inverting table (green
// shows magenta, the cursor black).
//
// SLATE_DRM_CARD=PATH tries another card than /dev/dri/card0 (a GPU
// driver's on the GPU bench, ADR 0171).
// Structures and numbers: libdrm 2.4.124 drm.h / drm_mode.h (MIT).
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define IOWR(nr, size) (0xC0000000u | ((unsigned)(size) << 16) | ('d' << 8) | (nr))
#define IOW(nr, size) (0x40000000u | ((unsigned)(size) << 16) | ('d' << 8) | (nr))
#define IOR(nr, size) (0x80000000u | ((unsigned)(size) << 16) | ('d' << 8) | (nr))
#define IO(nr) (('d' << 8) | (nr))

struct version { int major, minor, patch; size_t name_len; char *name; size_t date_len; char *date; size_t desc_len; char *desc; };
struct cap { uint64_t cap, value; };
struct res { uint64_t fbs, crtcs, conns, encs; uint32_t n_fbs, n_crtcs, n_conns, n_encs, minw, maxw, minh, maxh; };
struct modeinfo { uint32_t clock; uint16_t hd, hss, hse, ht, hsk, vd, vss, vse, vt, vs; uint32_t vrefresh, flags, type; char name[32]; };
struct conn { uint64_t encs, modes, props, values; uint32_t n_modes, n_props, n_encs, enc, id, type, type_id, connection, mmw, mmh, subpixel, pad; };
struct encoder { uint32_t id, type, crtc, possible_crtcs, possible_clones; };
struct crtc { uint64_t set_conns; uint32_t n_conns, id, fb, x, y, gamma, mode_valid; struct modeinfo mode; };
struct planeres { uint64_t ids; uint32_t n; };
struct plane { uint32_t id, crtc, fb, possible, gamma, n_formats; uint64_t formats; };
struct objprops { uint64_t props, values; uint32_t n, id, type; };
struct prop { uint64_t values, enums; uint32_t id, flags; char name[32]; uint32_t n_values, n_enums; };
struct dumb { uint32_t height, width, bpp, flags, handle, pitch; uint64_t size; };
struct mapdumb { uint32_t handle, pad; uint64_t offset; };
struct fb2 { uint32_t id, w, h, format, flags, handles[4], pitches[4], offsets[4]; uint64_t modifier[4]; };
struct fbcmd { uint32_t id, w, h, pitch, bpp, depth, handle; };
struct flip { uint32_t crtc, fb, flags, reserved; uint64_t user_data; };
struct prime { uint32_t handle, flags; int32_t fd; };
struct event { uint32_t type, length; uint64_t user_data; uint32_t sec, usec, seq, crtc; };
struct seq_event { uint32_t type, length; uint64_t user_data; int64_t time_ns; uint64_t seq; };
struct cursor { uint32_t flags, crtc, x, y, w, h, handle; };
struct lease { uint64_t ids; uint32_t n, flags, lessee, fd; };
struct closefb { uint32_t fb, pad; };
struct dirtyfb { uint32_t fb, flags, color, n_clips; uint64_t clips; };
struct clip { uint16_t x1, y1, x2, y2; };
struct blob { uint32_t id, length; uint64_t data; };
struct createblob { uint64_t data; uint32_t length, id; };
struct atomic { uint32_t flags, n_objs; uint64_t objs, n_props, props, values, reserved, user_data; };
struct waitvbl { uint32_t type, seq; int64_t a, b; };
struct getseq { uint32_t crtc, active; uint64_t seq; int64_t ns; };
struct queueseq { uint32_t crtc, flags; uint64_t seq, user_data; };
#define CURSOR_BO 1u

#define XR24 0x34325258u /* fourcc_code('X','R','2','4') */
#define AR24 0x34325241u /* fourcc_code('A','R','2','4') */
#define OBJECT_CRTC 0xccccccccu
#define OBJECT_CONNECTOR 0xc0c0c0c0u
#define OBJECT_PLANE 0xeeeeeeeeu
#define PAGE_FLIP_EVENT 1u
#define ATOMIC_TEST_ONLY 0x100u
#define ATOMIC_NONBLOCK 0x200u
#define ATOMIC_ALLOW_MODESET 0x400u
#define EVENT_VBLANK 1u
#define EVENT_FLIP_COMPLETE 2u
#define EVENT_CRTC_SEQUENCE 3u
#define VBLANK_RELATIVE 1u
#define VBLANK_EVENT 0x4000000u
#define GREEN 0x0000ff00u
#define BLUE 0x000000ffu
#define RED 0x00ff0000u

static int failures;
static void check(const char *name, int ok) {
    printf("drm: %s %s\n", ok ? "ok" : "FAIL", name);
    if (!ok) failures++;
}

static uint32_t *buffer(int fd, uint32_t w, uint32_t h, uint32_t color, uint32_t *handle, uint32_t *pitch,
                        uint64_t *offset) {
    struct dumb d = {.height = h, .width = w, .bpp = 32};
    if (ioctl(fd, IOWR(0xB2, sizeof d), &d) != 0) return NULL;
    struct mapdumb m = {.handle = d.handle};
    if (ioctl(fd, IOWR(0xB3, sizeof m), &m) != 0) return NULL;
    uint32_t *p = mmap(NULL, d.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, m.offset);
    if (p == MAP_FAILED) return NULL;
    for (uint64_t i = 0; i < d.size / 4; i++) p[i] = color;
    *handle = d.handle;
    *pitch = d.pitch;
    if (offset) *offset = m.offset;
    return p;
}

/// A framebuffer of format `fmt` over a new buffer filled with `color`.
static uint32_t framebuffer(int fd, uint32_t w, uint32_t h, uint32_t fmt, uint32_t color, uint32_t **pixels,
                            uint32_t *pitch) {
    uint32_t handle;
    uint32_t *p = buffer(fd, w, h, color, &handle, pitch, NULL);
    if (!p) return 0;
    if (pixels) *pixels = p;
    struct fb2 f = {.w = w, .h = h, .format = fmt, .handles = {handle}, .pitches = {*pitch}};
    return ioctl(fd, IOWR(0xB8, sizeof f), &f) == 0 ? f.id : 0;
}

/// The id of property `name` on object `obj`, and its value.
static uint32_t prop(int fd, uint32_t obj, uint32_t type, const char *name, uint64_t *value) {
    uint32_t ids[32];
    uint64_t values[32];
    struct objprops op = {.props = (uint64_t)ids, .values = (uint64_t)values, .n = 32, .id = obj, .type = type};
    if (ioctl(fd, IOWR(0xB9, sizeof op), &op) != 0) return 0;
    for (uint32_t i = 0; i < op.n && i < 32; i++) {
        struct prop p = {.id = ids[i]};
        if (ioctl(fd, IOWR(0xAA, sizeof p), &p) == 0 && strcmp(p.name, name) == 0) {
            if (value) *value = values[i];
            return ids[i];
        }
    }
    return 0;
}

/// An atomic request being built.
struct req {
    uint32_t objs[16], counts[16], props[64];
    uint64_t values[64];
    uint32_t n_objs, n;
};
static void add(struct req *r, uint32_t obj, uint32_t prop, uint64_t value) {
    if (r->n_objs == 0 || r->objs[r->n_objs - 1] != obj) {
        r->objs[r->n_objs] = obj;
        r->counts[r->n_objs++] = 0;
    }
    r->counts[r->n_objs - 1]++;
    r->props[r->n] = prop;
    r->values[r->n++] = value;
}
static int commit(int fd, struct req *r, uint32_t flags, uint64_t user_data) {
    struct atomic a = {.flags = flags, .n_objs = r->n_objs, .objs = (uint64_t)r->objs, .n_props = (uint64_t)r->counts,
                       .props = (uint64_t)r->props, .values = (uint64_t)r->values, .user_data = user_data};
    return ioctl(fd, IOWR(0xBC, sizeof a), &a) == 0 ? 0 : errno;
}

/// The properties of a plane, a CRTC and a connector that commits use.
struct planeprops { uint32_t fb, crtc, sx, sy, sw, sh, cx, cy, cw, ch; };
static struct planeprops plane_props(int fd, uint32_t id) {
    struct planeprops p = {
        prop(fd, id, OBJECT_PLANE, "FB_ID", NULL),  prop(fd, id, OBJECT_PLANE, "CRTC_ID", NULL),
        prop(fd, id, OBJECT_PLANE, "SRC_X", NULL),  prop(fd, id, OBJECT_PLANE, "SRC_Y", NULL),
        prop(fd, id, OBJECT_PLANE, "SRC_W", NULL),  prop(fd, id, OBJECT_PLANE, "SRC_H", NULL),
        prop(fd, id, OBJECT_PLANE, "CRTC_X", NULL), prop(fd, id, OBJECT_PLANE, "CRTC_Y", NULL),
        prop(fd, id, OBJECT_PLANE, "CRTC_W", NULL), prop(fd, id, OBJECT_PLANE, "CRTC_H", NULL)};
    return p;
}
static void place(struct req *r, uint32_t plane, struct planeprops *p, uint32_t fb, uint32_t crtc, int x, int y,
                  uint32_t w, uint32_t h) {
    add(r, plane, p->fb, fb);
    add(r, plane, p->crtc, crtc);
    add(r, plane, p->sx, 0);
    add(r, plane, p->sy, 0);
    add(r, plane, p->sw, (uint64_t)w << 16);
    add(r, plane, p->sh, (uint64_t)h << 16);
    add(r, plane, p->cx, (uint64_t)(int64_t)x);
    add(r, plane, p->cy, (uint64_t)(int64_t)y);
    add(r, plane, p->cw, w);
    add(r, plane, p->ch, h);
}

static int read_event(int fd, void *ev, size_t len, int ms) {
    struct pollfd pf = {.fd = fd, .events = POLLIN};
    return poll(&pf, 1, ms) == 1 && read(fd, ev, len) == (ssize_t)len;
}

/// Planes per output: a primary, a cursor and, on cards with one, an
/// overlay.
static uint32_t per_output = 2;

/// The planes of output `k`: each output's plane ids together, primary,
/// cursor, then any overlay.
static void planes_of(int fd, uint32_t k, uint32_t *primary, uint32_t *cursor) {
    uint32_t ids[32];
    struct planeres pr = {.ids = (uint64_t)ids, .n = 32};
    ioctl(fd, IOWR(0xB5, sizeof pr), &pr);
    *primary = ids[per_output * k];
    *cursor = ids[per_output * k + 1];
}

/// Wait for a DRM hotplug uevent (netlink(7): NETLINK_KOBJECT_UEVENT 15,
/// the kernel's group 1).
static int hotplug_wait(int secs) {
    struct { unsigned short family, pad; unsigned port, groups; } nl = {16, 0, 0, 1};
    int s = socket(16, SOCK_RAW | SOCK_CLOEXEC, 15);
    if (s < 0 || bind(s, (struct sockaddr *)&nl, sizeof nl) != 0) return 1;
    printf("drm: listening\n");
    fflush(stdout);
    char b[2048];
    struct pollfd pf = {.fd = s, .events = POLLIN};
    while (poll(&pf, 1, secs * 1000) == 1) {
        ssize_t n = recv(s, b, sizeof b - 1, 0);
        if (n <= 0) break;
        b[n] = 0;
        int drm = 0, hotplug = 0;
        for (char *k = b; k < b + n; k += strlen(k) + 1) {
            drm |= strcmp(k, "SUBSYSTEM=drm") == 0;
            hotplug |= strcmp(k, "HOTPLUG=1") == 0;
        }
        if (drm && hotplug) {
            printf("drm: hotplug %s\n", b);
            return 0;
        }
    }
    printf("drm: no hotplug\n");
    return 1;
}

int main(int argc, char **argv) {
    if (argc > 2 && strcmp(argv[1], "hotplug-wait") == 0) return hotplug_wait(atoi(argv[2]));
    int hold_secs = argc > 2 && strcmp(argv[1], "hold") == 0 ? argv[2][0] - '0' : 0;
    const char *card = getenv("SLATE_DRM_CARD") ? getenv("SLATE_DRM_CARD") : "/dev/dri/card0";
    int fd = open(card, O_RDWR | O_CLOEXEC);
    check("open", fd >= 0);
    if (fd < 0) return 1;
    char name[32] = {0};
    struct version v = {.name_len = sizeof name - 1, .name = name};
    check("version", ioctl(fd, IOWR(0x00, sizeof v), &v) == 0 && v.name_len > 0);
    struct cap c = {.cap = 1};
    check("cap_dumb", ioctl(fd, IOWR(0x0c, sizeof c), &c) == 0 && c.value == 1);
    c = (struct cap){.cap = 5};
    check("cap_prime", ioctl(fd, IOWR(0x0c, sizeof c), &c) == 0 && c.value == 3);
    c = (struct cap){.cap = 8};
    check("cap_cursor", ioctl(fd, IOWR(0x0c, sizeof c), &c) == 0 && c.value == 64);
    struct planeres none = {0};
    check("no_planes_without_universal", ioctl(fd, IOWR(0xB5, sizeof none), &none) == 0 && none.n == 0);
    c = (struct cap){.cap = 2, .value = 1};
    check("universal_planes", ioctl(fd, IOW(0x0d, sizeof c), &c) == 0);

    struct res r = {0};
    check("resources_count", ioctl(fd, IOWR(0xA0, sizeof r), &r) == 0 && r.n_crtcs >= 1 && r.n_conns == r.n_crtcs);
    uint32_t outputs = r.n_crtcs > 4 ? 4 : r.n_crtcs;
    uint32_t crtcs[4], conns[4], encs[4];
    r.crtcs = (uint64_t)crtcs; r.conns = (uint64_t)conns; r.encs = (uint64_t)encs;
    r.n_crtcs = r.n_conns = r.n_encs = outputs; r.n_fbs = 0;
    check("resources", ioctl(fd, IOWR(0xA0, sizeof r), &r) == 0);
    printf("drm: %u outputs\n", r.n_crtcs);
    uint32_t crtc_id = crtcs[0], conn_id = conns[0], enc_id = encs[0];

    struct conn cn = {.id = conn_id};
    check("connector_count", ioctl(fd, IOWR(0xA7, sizeof cn), &cn) == 0 && cn.n_modes >= 1 && cn.connection == 1);
    struct modeinfo modes[16], mode;
    uint32_t props[8]; uint64_t values[8];
    if (cn.n_modes > 16) cn.n_modes = 16;
    cn.modes = (uint64_t)modes; cn.encs = (uint64_t)&enc_id; cn.n_encs = 1;
    cn.props = (uint64_t)props; cn.values = (uint64_t)values; if (cn.n_props > 8) cn.n_props = 8;
    check("connector", ioctl(fd, IOWR(0xA7, sizeof cn), &cn) == 0 && modes[0].hd > 0 && modes[0].vd > 0 &&
                           modes[0].vrefresh > 0 && (modes[0].type & 8));
    mode = modes[0];
    printf("drm: mode %s %ux%u@%u, %u modes\n", mode.name, mode.hd, mode.vd, mode.vrefresh, cn.n_modes);
    struct encoder e = {.id = enc_id};
    check("encoder", ioctl(fd, IOWR(0xA6, sizeof e), &e) == 0 && e.possible_crtcs == 1);

    // Universal planes: a primary and a cursor plane per output, and an
    // overlay on cards with one.
    struct planeres pr = {0};
    check("plane_resources", ioctl(fd, IOWR(0xB5, sizeof pr), &pr) == 0 &&
                                 (pr.n == 2 * r.n_crtcs || pr.n == 3 * r.n_crtcs));
    per_output = pr.n / r.n_crtcs;
    uint32_t primary, cursor_plane;
    planes_of(fd, 0, &primary, &cursor_plane);
    uint32_t formats[8];
    struct plane pl = {.id = primary, .formats = (uint64_t)formats, .n_formats = 8};
    check("plane", ioctl(fd, IOWR(0xB6, sizeof pl), &pl) == 0 && pl.n_formats >= 1 && formats[0] == XR24);
    uint64_t type = 9;
    check("plane_type_primary", prop(fd, primary, OBJECT_PLANE, "type", &type) && type == 1);
    check("plane_type_cursor", prop(fd, cursor_plane, OBJECT_PLANE, "type", &type) && type == 2);
    pl = (struct plane){.id = cursor_plane, .formats = (uint64_t)formats, .n_formats = 8};
    check("cursor_plane_argb", ioctl(fd, IOWR(0xB6, sizeof pl), &pl) == 0 && pl.n_formats == 1 && formats[0] == AR24);

    uint32_t h1, pitch1, h2, pitch2;
    uint64_t off1;
    uint32_t *red = buffer(fd, mode.hd, mode.vd, RED, &h1, &pitch1, &off1);
    uint32_t *green = buffer(fd, mode.hd, mode.vd, GREEN, &h2, &pitch2, NULL);
    check("dumb_buffers", red && green && pitch1 >= mode.hd * 4u);
    struct fb2 f1 = {.w = mode.hd, .h = mode.vd, .format = XR24, .handles = {h1}, .pitches = {pitch1}};
    struct fb2 f2 = {.w = mode.hd, .h = mode.vd, .format = XR24, .handles = {h2}, .pitches = {pitch2}};
    check("addfb2", ioctl(fd, IOWR(0xB8, sizeof f1), &f1) == 0 && ioctl(fd, IOWR(0xB8, sizeof f2), &f2) == 0 && f1.id != f2.id);
    struct crtc cr = {.set_conns = (uint64_t)&conn_id, .n_conns = 1, .id = crtc_id, .fb = f1.id, .mode_valid = 1, .mode = mode};
    check("setcrtc", ioctl(fd, IOWR(0xA2, sizeof cr), &cr) == 0);
    struct crtc got = {.id = crtc_id};
    check("getcrtc", ioctl(fd, IOWR(0xA1, sizeof got), &got) == 0 && got.fb == f1.id && got.mode_valid);
    struct crtc wrong = cr;
    wrong.n_conns = 0;
    check("setcrtc_needs_connector", ioctl(fd, IOWR(0xA2, sizeof wrong), &wrong) != 0 && errno == EINVAL);

    struct flip fl = {.crtc = crtc_id, .fb = f2.id, .flags = PAGE_FLIP_EVENT, .user_data = 0x5eed};
    check("page_flip", ioctl(fd, IOWR(0xB0, sizeof fl), &fl) == 0);
    check("flip_busy", ioctl(fd, IOWR(0xB0, sizeof fl), &fl) != 0 && errno == EBUSY);
    struct event ev = {0};
    check("flip_event", read_event(fd, &ev, sizeof ev, 1000) && ev.type == EVENT_FLIP_COMPLETE && ev.user_data == 0x5eed &&
                            ev.crtc == crtc_id);

    struct prime pm = {.handle = h2, .flags = O_CLOEXEC | O_RDWR};
    check("prime_export", ioctl(fd, IOWR(0x2d, sizeof pm), &pm) == 0 && pm.fd >= 0);
    uint32_t *viadmabuf = mmap(NULL, pitch2 * mode.vd, PROT_READ, MAP_SHARED, pm.fd, 0);
    check("prime_mmap", viadmabuf != MAP_FAILED && viadmabuf[0] == GREEN && viadmabuf[1000] == GREEN);
    struct prime back = {.fd = pm.fd};
    check("prime_import", ioctl(fd, IOWR(0x2e, sizeof back), &back) == 0 && back.handle == h2);

    // Authentication: the master authenticates another file's magic, not
    // an unknown one; another opener is not master. Only an authenticated
    // file gets a handle (so the pixels) from GETFB, and no file maps a
    // buffer it holds no handle to.
    uint32_t magic = 0;
    check("get_magic", ioctl(fd, IOR(0x02, 4), &magic) == 0 && magic != 0);
    uint32_t zero = 0, bogus = 0x7fff1234;
    check("auth_zero_einval", ioctl(fd, IOW(0x11, 4), &zero) != 0 && errno == EINVAL);
    check("auth_unknown_einval", ioctl(fd, IOW(0x11, 4), &bogus) != 0 && errno == EINVAL);
    int other = open(card, O_RDWR | O_CLOEXEC);
    uint32_t magic2 = 0;
    check("auth_not_master", other >= 0 && ioctl(other, IOW(0x11, 4), &magic) != 0 && errno == EACCES);
    struct fbcmd gf = {.id = f2.id};
    check("getfb_no_handle", ioctl(other, IOWR(0xAD, sizeof gf), &gf) == 0 && gf.w == mode.hd && gf.handle == 0);
    check("mmap_not_yours", mmap(NULL, 4096, PROT_READ, MAP_SHARED, other, off1) == MAP_FAILED && errno == EINVAL);
    check("auth_magic", ioctl(other, IOR(0x02, 4), &magic2) == 0 && magic2 != magic && ioctl(fd, IOW(0x11, 4), &magic2) == 0);
    gf = (struct fbcmd){.id = f2.id};
    check("getfb_handle", ioctl(other, IOWR(0xAD, sizeof gf), &gf) == 0 && gf.handle != 0);
    close(other);

    // An empty lease: a second file that sees no objects but makes buffers.
    struct lease ls = {.flags = O_CLOEXEC};
    check("lease", ioctl(fd, IOWR(0xC6, sizeof ls), &ls) == 0 && (int)ls.fd >= 0);
    struct res lr = {0};
    check("lease_no_objects", ioctl(ls.fd, IOWR(0xA0, sizeof lr), &lr) == 0 && lr.n_crtcs == 0);
    struct dumb ld = {.height = 16, .width = 16, .bpp = 32};
    check("lease_dumb", ioctl(ls.fd, IOWR(0xB2, sizeof ld), &ld) == 0 && ld.handle != 0);
    close(ls.fd);

    // The legacy cursor: shown, moved, hidden.
    uint32_t ch, cpitch;
    uint32_t *cimg = buffer(fd, 64, 64, 0xffffffffu, &ch, &cpitch, NULL);
    struct cursor cu = {.flags = CURSOR_BO, .crtc = crtc_id, .w = 64, .h = 64, .handle = ch};
    check("cursor_set", cimg && ioctl(fd, IOWR(0xA3, sizeof cu), &cu) == 0);
    cu = (struct cursor){.flags = 2, .crtc = crtc_id, .x = 10, .y = 10};
    check("cursor_move", ioctl(fd, IOWR(0xA3, sizeof cu), &cu) == 0);
    cu = (struct cursor){.flags = CURSOR_BO, .crtc = crtc_id};
    check("cursor_hide", ioctl(fd, IOWR(0xA3, sizeof cu), &cu) == 0);

    // CLOSEFB: the framebuffer goes (f2 stays on the screen).
    struct closefb cf = {.fb = f1.id};
    check("closefb", ioctl(fd, IOWR(0xD0, sizeof cf), &cf) == 0 && ioctl(fd, IOWR(0xAF, 4), &f1.id) != 0);

    // ---- Atomic (ADR 0100) ----
    c = (struct cap){.cap = 3, .value = 1};
    check("atomic_cap", ioctl(fd, IOW(0x0d, sizeof c), &c) == 0);
    uint64_t edid_id = 0, active = 9, mode_id = 9, link = 0;
    uint32_t p_active = prop(fd, crtc_id, OBJECT_CRTC, "ACTIVE", &active);
    uint32_t p_mode = prop(fd, crtc_id, OBJECT_CRTC, "MODE_ID", &mode_id);
    uint32_t p_link = prop(fd, conn_id, OBJECT_CONNECTOR, "CRTC_ID", &link);
    check("atomic_props", p_active && p_mode && p_link && active == 1 && link == crtc_id);
    check("edid_prop", prop(fd, conn_id, OBJECT_CONNECTOR, "EDID", &edid_id) && edid_id != 0);
    uint8_t edid[1024] = {0};
    struct blob eb = {.id = (uint32_t)edid_id, .length = sizeof edid, .data = (uint64_t)edid};
    uint8_t sum = 0;
    int got_edid = ioctl(fd, IOWR(0xAC, sizeof eb), &eb) == 0 && eb.length >= 128;
    for (int i = 0; i < 128; i++) sum += edid[i];
    check("edid_blob", got_edid && edid[0] == 0 && edid[1] == 0xff && edid[7] == 0 && sum == 0);
    printf("drm: EDID %u bytes, maker %c%c%c\n", eb.length, '@' + ((edid[8] >> 2) & 31),
           '@' + (((edid[8] & 3) << 3) | (edid[9] >> 5)), '@' + (edid[9] & 31));
    struct createblob mb = {.data = (uint64_t)&mode, .length = sizeof mode};
    check("mode_blob", ioctl(fd, IOWR(0xBD, sizeof mb), &mb) == 0 && mb.id != 0);
    struct planeprops pp = plane_props(fd, primary), cp = plane_props(fd, cursor_plane);
    check("plane_props", pp.fb && pp.ch && cp.fb && cp.ch);

    uint32_t fr = framebuffer(fd, mode.hd, mode.vd, XR24, RED, NULL, &pitch1);
    struct req q = {0};
    place(&q, primary, &pp, fr, crtc_id, 0, 0, mode.hd, mode.vd);
    check("atomic_test", commit(fd, &q, ATOMIC_TEST_ONLY, 0) == 0);
    q = (struct req){0};
    place(&q, primary, &pp, fr, crtc_id, 0, 0, mode.hd / 2, mode.vd);
    check("atomic_partial_primary_refused", commit(fd, &q, ATOMIC_TEST_ONLY, 0) == EINVAL);
    // Switching the CRTC off takes its planes off too.
    q = (struct req){0};
    add(&q, crtc_id, p_active, 0);
    add(&q, primary, pp.fb, 0);
    add(&q, primary, pp.crtc, 0);
    check("atomic_modeset_needs_allow", commit(fd, &q, ATOMIC_TEST_ONLY, 0) == EINVAL);
    check("atomic_modeset_allowed", commit(fd, &q, ATOMIC_TEST_ONLY | ATOMIC_ALLOW_MODESET, 0) == 0);

    // A modeset through atomic: the same mode by blob, the red framebuffer.
    q = (struct req){0};
    add(&q, crtc_id, p_active, 1);
    add(&q, crtc_id, p_mode, mb.id);
    add(&q, conn_id, p_link, crtc_id);
    place(&q, primary, &pp, fr, crtc_id, 0, 0, mode.hd, mode.vd);
    check("atomic_modeset", commit(fd, &q, ATOMIC_ALLOW_MODESET, 0) == 0);
    check("atomic_mode_id", prop(fd, crtc_id, OBJECT_CRTC, "MODE_ID", &mode_id) && mode_id == mb.id);

    // Flips with events: completed at vblanks of the CRTC's clock, one
    // frame or more apart, EBUSY while one is pending.
    q = (struct req){0};
    add(&q, primary, pp.fb, f2.id);
    struct event e1 = {0}, e2 = {0};
    check("atomic_flip", commit(fd, &q, PAGE_FLIP_EVENT | ATOMIC_NONBLOCK, 0xa1) == 0);
    check("atomic_flip_busy", commit(fd, &q, PAGE_FLIP_EVENT | ATOMIC_NONBLOCK, 0xa2) == EBUSY);
    int ok1 = read_event(fd, &e1, sizeof e1, 1000);
    q = (struct req){0};
    add(&q, primary, pp.fb, fr);
    int ok2 = commit(fd, &q, PAGE_FLIP_EVENT | ATOMIC_NONBLOCK, 0xa3) == 0 && read_event(fd, &e2, sizeof e2, 1000);
    long gap = (long)(e2.sec - e1.sec) * 1000000 + (long)e2.usec - (long)e1.usec;
    long frame = 1000000 / mode.vrefresh;
    check("atomic_flip_event", ok1 && e1.type == EVENT_FLIP_COMPLETE && e1.user_data == 0xa1 && e1.crtc == crtc_id);
    long expect = (long)(e2.seq - e1.seq) * frame;
    check("vblank_paced", ok2 && e2.seq > e1.seq && gap >= expect - 200 && gap <= expect + 200);
    printf("drm: flips %u -> %u, %ld us apart (frame %ld us)\n", e1.seq, e2.seq, gap, frame);

    // WAIT_VBLANK, blocking and with an event; the CRTC sequence calls.
    struct waitvbl wv = {.type = VBLANK_RELATIVE, .seq = 1};
    check("wait_vblank", ioctl(fd, IOWR(0x3a, sizeof wv), &wv) == 0 && wv.seq > e2.seq);
    uint32_t after = wv.seq;
    wv = (struct waitvbl){.type = VBLANK_RELATIVE | VBLANK_EVENT, .seq = 2, .a = 0x77};
    struct event ve = {0};
    check("wait_vblank_event", ioctl(fd, IOWR(0x3a, sizeof wv), &wv) == 0 && read_event(fd, &ve, sizeof ve, 1000) &&
                                   ve.type == EVENT_VBLANK && ve.user_data == 0x77 && ve.seq == wv.seq &&
                                   wv.seq >= after + 2);
    struct getseq gs = {.crtc = crtc_id};
    check("crtc_get_sequence", ioctl(fd, IOWR(0x3b, sizeof gs), &gs) == 0 && gs.active == 1 && gs.seq >= after + 2);
    struct queueseq qs = {.crtc = crtc_id, .flags = 1, .seq = 1, .user_data = 0x88};
    struct seq_event se = {0};
    check("crtc_queue_sequence", ioctl(fd, IOWR(0x3c, sizeof qs), &qs) == 0 && read_event(fd, &se, sizeof se, 1000) &&
                                     se.type == EVENT_CRTC_SEQUENCE && se.user_data == 0x88 && se.seq == qs.seq);

    // Back to the green framebuffer, then DIRTYFB: rows 0-15 and 100-115
    // turn blue, but only the first strip is marked dirty.
    q = (struct req){0};
    add(&q, primary, pp.fb, f2.id);
    check("atomic_blocking_flip", commit(fd, &q, 0, 0) == 0);
    for (uint32_t y = 0; y < 16; y++) {
        for (uint32_t x = 0; x < mode.hd; x++) {
            green[y * (pitch2 / 4) + x] = BLUE;
            green[(100 + y) * (pitch2 / 4) + x] = BLUE;
        }
    }
    struct clip cl = {0, 0, mode.hd, 16};
    struct dirtyfb df = {.fb = f2.id, .n_clips = 1, .clips = (uint64_t)&cl};
    check("dirtyfb", ioctl(fd, IOWR(0xB1, sizeof df), &df) == 0);

    // The cursor plane: a white 64 x 64 square at (200, 200).
    uint32_t *cw;
    uint32_t cfb = framebuffer(fd, 64, 64, AR24, 0xffffffffu, &cw, &cpitch);
    q = (struct req){0};
    place(&q, cursor_plane, &cp, cfb, crtc_id, 200, 200, 128, 128);
    check("cursor_scaled_refused", commit(fd, &q, ATOMIC_TEST_ONLY, 0) == EINVAL);
    q = (struct req){0};
    place(&q, cursor_plane, &cp, cfb, crtc_id, 200, 200, 64, 64);
    check("cursor_plane", cfb && commit(fd, &q, 0, 0) == 0);

    // The overlay plane, where the card has one: a half-transparent
    // (premultiplied) green square at (100, 100), moved partly off the
    // screen, its pixels changed, then off.
    if (per_output == 3) {
        uint32_t ids[32];
        struct planeres all = {.ids = (uint64_t)ids, .n = 32};
        ioctl(fd, IOWR(0xB5, sizeof all), &all);
        uint32_t overlay = ids[2];
        check("plane_type_overlay", prop(fd, overlay, OBJECT_PLANE, "type", &type) && type == 0);
        struct planeprops op = plane_props(fd, overlay);
        uint32_t *opx, opitch;
        uint32_t ofb = framebuffer(fd, 256, 256, AR24, 0x80008000u, &opx, &opitch);
        q = (struct req){0};
        place(&q, overlay, &op, ofb, crtc_id, 100, 100, 256, 256);
        check("overlay_plane", ofb && commit(fd, &q, 0, 0) == 0);
        usleep(100000);
        q = (struct req){0};
        place(&q, overlay, &op, ofb, crtc_id, -50, (int)mode.vd - 100, 256, 256);
        check("overlay_moved", commit(fd, &q, 0, 0) == 0);
        q = (struct req){0};
        place(&q, overlay, &op, ofb, crtc_id, 0, 0, 128, 128);
        add(&q, overlay, op.cw, 256);
        check("overlay_scaled_refused", commit(fd, &q, ATOMIC_TEST_ONLY, 0) == EINVAL);
        for (uint32_t y = 0; y < 16; y++)
            for (uint32_t x = 0; x < 256; x++) opx[y * (opitch / 4) + x] = 0xff0000ffu;
        struct clip ocl = {0, 0, 256, 16};
        struct dirtyfb odf = {.fb = ofb, .n_clips = 1, .clips = (uint64_t)&ocl};
        check("overlay_dirtyfb", ioctl(fd, IOWR(0xB1, sizeof odf), &odf) == 0);
        usleep(100000);
        q = (struct req){0};
        add(&q, overlay, op.fb, 0);
        add(&q, overlay, op.crtc, 0);
        check("overlay_off", commit(fd, &q, 0, 0) == 0);
    } else {
        printf("drm: no overlay planes\n");
    }

    // Gamma, where the card has it: an inverting table.
    uint64_t gsize = 0;
    uint32_t p_gamma = prop(fd, crtc_id, OBJECT_CRTC, "GAMMA_LUT", NULL);
    if (prop(fd, crtc_id, OBJECT_CRTC, "GAMMA_LUT_SIZE", &gsize) && gsize > 0 && gsize <= 1024) {
        static uint16_t lut[1024][4];
        for (uint32_t i = 0; i < gsize; i++) {
            uint16_t v = (uint16_t)(0xffff - i * 0xffff / (gsize - 1));
            lut[i][0] = lut[i][1] = lut[i][2] = v;
        }
        struct createblob gb = {.data = (uint64_t)lut, .length = (uint32_t)(gsize * 8)};
        check("gamma_blob", p_gamma && ioctl(fd, IOWR(0xBD, sizeof gb), &gb) == 0);
        q = (struct req){0};
        add(&q, crtc_id, p_gamma, gb.id);
        check("gamma_lut", commit(fd, &q, 0, 0) == 0);
        printf("drm: gamma %lu entries, inverted\n", (unsigned long)gsize);
    } else {
        printf("drm: no gamma\n");
    }

    // A second output: red, on its own CRTC and connector.
    if (r.n_crtcs >= 2) {
        struct conn c2 = {.id = conns[1]};
        struct modeinfo m2[16];
        int ok = ioctl(fd, IOWR(0xA7, sizeof c2), &c2) == 0 && c2.connection == 1 && c2.n_modes >= 1;
        c2.modes = (uint64_t)m2; c2.n_modes = c2.n_modes > 16 ? 16 : c2.n_modes; c2.n_props = 0; c2.n_encs = 0;
        ok = ok && ioctl(fd, IOWR(0xA7, sizeof c2), &c2) == 0;
        uint32_t p2, cur2;
        planes_of(fd, 1, &p2, &cur2);
        struct planeprops pp2 = plane_props(fd, p2);
        uint32_t fred = framebuffer(fd, m2[0].hd, m2[0].vd, XR24, RED, NULL, &pitch1);
        struct createblob mb2 = {.data = (uint64_t)&m2[0], .length = sizeof m2[0]};
        ok = ok && ioctl(fd, IOWR(0xBD, sizeof mb2), &mb2) == 0;
        q = (struct req){0};
        add(&q, crtcs[1], p_active, 1);
        add(&q, crtcs[1], p_mode, mb2.id);
        add(&q, conns[1], p_link, crtcs[1]);
        place(&q, p2, &pp2, fred, crtcs[1], 0, 0, m2[0].hd, m2[0].vd);
        check("second_output", ok && fred && commit(fd, &q, ATOMIC_ALLOW_MODESET, 0) == 0);
        // Its connector can't drive the first CRTC.
        q = (struct req){0};
        add(&q, conns[1], p_link, crtc_id);
        check("second_connector_own_crtc", commit(fd, &q, ATOMIC_TEST_ONLY | ATOMIC_ALLOW_MODESET, 0) == EINVAL);
        printf("drm: second output %ux%u\n", m2[0].hd, m2[0].vd);
    }

    // Hold the picture for the scenario to see.
    fflush(stdout);
    struct timespec hold = {hold_secs, 500000000};
    nanosleep(&hold, NULL);
    check("drop_master", ioctl(fd, IO(0x1f)) == 0);
    close(fd);
    return failures;
}
