// SPDX-License-Identifier: MIT OR Apache-2.0
// A card's 2D requests (ADR 0172's addendum, M32 phase 6): Slate's own
// driver-private DRM ioctls (kernel/src/drivers/drm/twod.rs has them and
// their structures). Images from a dumb buffer and from this program's
// own shared memory; a copy, a fill and a blend between them, each pixel
// checked against the CPU's result, the pixels around each rectangle
// checked untouched. The blend's reference does the shader's float
// operations in its order (slate_amdgpu::rdna2::blend_pixel).
//
// SLATE_DRM_CARD=PATH picks the card (/dev/dri/card0 otherwise). A card
// without 2D requests answers ENOTTY: "gpu2d: no 2D requests".
// Dumb buffers: libdrm 2.4.124 drm_mode.h (MIT).
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define IOWR(nr, size) (0xC0000000u | ((unsigned)(size) << 16) | ('d' << 8) | (nr))
#define IOW(nr, size) (0x40000000u | ((unsigned)(size) << 16) | ('d' << 8) | (nr))

struct dumb { uint32_t height, width, bpp, flags, handle, pitch; uint64_t size; };
struct mapdumb { uint32_t handle, pad; uint64_t offset; };
struct image { uint64_t addr; uint32_t handle, width, height, pitch, id, pad; };
struct submit { uint64_t ops; uint32_t count, pad; };
struct op { uint32_t kind, src, dst, value; int32_t sx, sy, w, h, dx, dy; uint32_t pad[2]; };

enum { COPY = 1, FILL = 2, BLEND = 3, BLEND_STRAIGHT = 4 };
#define W 256
#define H 128
#define PITCH (W * 4)

static int failures;
static void check(const char *name, int ok) {
    printf("gpu2d: %s %s\n", ok ? "ok" : "FAIL", name);
    if (!ok) failures++;
}

static uint32_t to_byte(float v) {
    if (!(v > 0.0f)) return 0;
    if (v >= 255.0f) return 255;
    uint32_t i = (uint32_t)v;
    float frac = v - (float)i;
    int up = frac > 0.5f || (frac == 0.5f && (i & 1));
    i += up;
    return i > 255 ? 255 : i;
}

// The shader's blend: each channel d * (1 - sa * k / 255) + s * k; for
// a source that isn't premultiplied, the colours weighted sa * k / 255
// and the alpha sa * k.
static uint32_t blend_any(uint32_t s, uint32_t d, float k, int straight) {
    float sa = k * (float)(s >> 24);
    float inv = 1.0f + (-1.0f / 255.0f) * sa;
    float weight = straight ? (1.0f / 255.0f) * sa : k;
    uint32_t out = 0;
    for (int c = 0; c < 4; c++) {
        float dc = inv * (float)((d >> (8 * c)) & 0xFF);
        float sc = straight && c == 3 ? sa : weight * (float)((s >> (8 * c)) & 0xFF);
        out |= to_byte(dc + sc) << (8 * c);
    }
    return out;
}
static uint32_t blend_pixel(uint32_t s, uint32_t d, float k) { return blend_any(s, d, k, 0); }

// Premultiplied, with alpha varying across the image.
static uint32_t src_px(int x, int y) {
    uint32_t a = (x * 7 + y * 13) & 0xFF;
    uint32_t r = (x * 3) & 0xFF, g = (y * 4) & 0xFF, b = 0x80;
    return (a << 24) | ((r * a + 127) / 255) << 16 | ((g * a + 127) / 255) << 8 | (b * a + 127) / 255;
}
static uint32_t dst_px(int x, int y) { return 0xFF000000u | (((x + y) & 0xFF) << 16) | 0x8040; }

static uint32_t image(int fd, uint64_t addr, uint32_t handle) {
    struct image im = {.addr = addr, .handle = handle, .width = W, .height = H, .pitch = PITCH};
    return ioctl(fd, IOWR(0x40, sizeof im), &im) == 0 ? im.id : 0;
}

static int run(int fd, struct op *ops, uint32_t n) {
    struct submit s = {.ops = (uint64_t)ops, .count = n};
    return ioctl(fd, IOW(0x42, sizeof s), &s) == 0 ? 0 : errno;
}

// Whether `got` is `want` inside the w x h rectangle at (x, y) and `was`
// outside it; says where it first isn't.
static int matches(const uint32_t *got, int x, int y, int w, int h, uint32_t (*want)(int, int), const uint32_t *was) {
    for (int j = 0; j < H; j++)
        for (int i = 0; i < W; i++) {
            int in = i >= x && i < x + w && j >= y && j < y + h;
            uint32_t e = in ? want(i - x, j - y) : was[j * W + i];
            if (got[j * W + i] != e) {
                printf("gpu2d: (%d, %d) is %08x, not %08x\n", i, j, got[j * W + i], e);
                return 0;
            }
        }
    return 1;
}

static const uint32_t *ref_src;
static uint32_t copied(int i, int j) { return ref_src[(j + 5) * W + i + 10]; }
static uint32_t filled(int i, int j) { (void)i; (void)j; return 0x12345678; }
static const uint32_t *ref_dst;
static uint32_t blended(int i, int j) { return blend_pixel(src_px(i + 10, j + 5), ref_dst[(j + 30) * W + i + 20], 0.75f); }
static uint32_t straight(int i, int j) { return blend_any(src_px(i + 10, j + 5), ref_dst[(j + 30) * W + i + 20], 1.0f, 1); }

int main(void) {
    const char *card = getenv("SLATE_DRM_CARD") ? getenv("SLATE_DRM_CARD") : "/dev/dri/card0";
    int fd = open(card, O_RDWR | O_CLOEXEC);
    check("open", fd >= 0);
    if (fd < 0) return 1;
    // A: a dumb buffer, the source; B and C: this program's own memory.
    struct dumb d = {.height = H, .width = W, .bpp = 32};
    check("dumb", ioctl(fd, IOWR(0xB2, sizeof d), &d) == 0 && d.pitch == PITCH);
    struct mapdumb m = {.handle = d.handle};
    check("map_dumb", ioctl(fd, IOWR(0xB3, sizeof m), &m) == 0);
    uint32_t *a = mmap(NULL, d.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, m.offset);
    uint32_t *b = mmap(NULL, PITCH * H, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    uint32_t *c = mmap(NULL, PITCH * H, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    check("mappings", a != MAP_FAILED && b != MAP_FAILED && c != MAP_FAILED);
    for (int y = 0; y < H; y++)
        for (int x = 0; x < W; x++) {
            a[y * W + x] = src_px(x, y);
            b[y * W + x] = dst_px(x, y);
            c[y * W + x] = 0xDEADBEEF;
        }
    uint32_t ia = image(fd, 0, d.handle);
    if (!ia && errno == ENOTTY) {
        printf("gpu2d: no 2D requests on %s\n", card);
        return 0;
    }
    uint32_t ib = image(fd, (uint64_t)b, 0), ic = image(fd, (uint64_t)c, 0);
    check("images", ia && ib && ic);
    static uint32_t before_b[W * H], before_c[W * H];
    memcpy(before_b, b, sizeof before_b);
    memcpy(before_c, c, sizeof before_c);
    ref_src = a;

    // A 100 x 50 rectangle of A at (10, 5) to (20, 30) of C.
    struct op cp = {.kind = COPY, .src = ia, .dst = ic, .sx = 10, .sy = 5, .w = 100, .h = 50, .dx = 20, .dy = 30};
    check("copy", run(fd, &cp, 1) == 0);
    ref_src = a;
    check("copy_pixels", matches(c, 20, 30, 100, 50, copied, before_c));

    // A 50 x 20 rectangle of C at (3, 4) filled.
    memcpy(before_c, c, sizeof before_c);
    struct op fl = {.kind = FILL, .dst = ic, .value = 0x12345678, .w = 50, .h = 20, .dx = 3, .dy = 4};
    check("fill", run(fd, &fl, 1) == 0);
    check("fill_pixels", matches(c, 3, 4, 50, 20, filled, before_c));

    // A over B: a 200 x 60 rectangle of A at (10, 5) at (20, 30) of B, at
    // three quarters' opacity.
    float k = 0.75f;
    uint32_t kb;
    memcpy(&kb, &k, 4);
    struct op bl = {.kind = BLEND, .src = ia, .dst = ib, .value = kb, .sx = 10, .sy = 5, .w = 200, .h = 60, .dx = 20, .dy = 30};
    int r = run(fd, &bl, 1);
    if (r == EIO) {
        printf("gpu2d: no blends (the card's shaders aren't running)\n");
    } else {
        check("blend", r == 0);
        ref_dst = before_b;
        check("blend_pixels", matches(b, 20, 30, 200, 60, blended, before_b));
        // The same pixels taken as not premultiplied, at full opacity,
        // over B as the first blend left it.
        memcpy(before_b, b, sizeof before_b);
        float one = 1.0f;
        memcpy(&kb, &one, 4);
        struct op st = bl;
        st.kind = BLEND_STRAIGHT;
        st.value = kb;
        check("blend_straight", run(fd, &st, 1) == 0);
        check("blend_straight_pixels", matches(b, 20, 30, 200, 60, straight, before_b));
    }

    // Requests that don't fit are refused.
    struct op bad = cp;
    bad.w = W;
    check("outside_refused", run(fd, &bad, 1) == EINVAL);
    check("free", ioctl(fd, IOW(0x41, 4), &ib) == 0 && ioctl(fd, IOW(0x41, 4), &ib) != 0);
    printf("gpu2d: %s\n", failures ? "FAILED" : "all ok");
    return failures != 0;
}
