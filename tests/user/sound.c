// SPDX-License-Identifier: MIT OR Apache-2.0
// Sound cards through ALSA's kernel interface (ADR 0184), driven the way
// alsa-lib drives them, with no alsa-lib.
//
// "check" (the sound scenario): every card in /proc/asound/cards: the
// control device (version, card info, the elements: info, read, write,
// the dB scale, a change event for a subscriber; the PCM devices), and
// each playback device: one opener at a time, refinement and hw_params,
// sw_params, the mapped status and control pages, a start at the
// threshold, an underrun (XRUN, EPIPE, prepare again), pause and resume,
// rewind and forward, a drain; capture devices start, and the one named
// records.
//
// "wav FREQ SECONDS PATH" writes such a tone to a WAV file (48 kHz,
// 16-bit stereo), for other players (aplay, PipeWire's).
//
// "play CARD FREQ SECONDS [mmap]" plays a sine tone at FREQ Hz (48 kHz,
// 16-bit stereo) for the scenario to find in what QEMU recorded: with
// WRITEI_FRAMES, or written into the mapped buffer.
//
// Numbers and layouts: Linux's sound/asound.h (ADR 0184), retyped here.
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define IOC(dir, ty, nr, size) (((unsigned)(dir) << 30) | ((unsigned)(size) << 16) | ((ty) << 8) | (nr))
#define IO_(ty, nr) IOC(0, ty, nr, 0)
#define IOR_(ty, nr, s) IOC(2, ty, nr, s)
#define IOW_(ty, nr, s) IOC(1, ty, nr, s)
#define IOWR_(ty, nr, s) IOC(3, ty, nr, s)

#define PCM_PVERSION IOR_('A', 0x00, 4)
#define PCM_INFO IOR_('A', 0x01, 288)
#define PCM_TTSTAMP IOW_('A', 0x03, 4)
#define PCM_HW_REFINE IOWR_('A', 0x10, 608)
#define PCM_HW_PARAMS IOWR_('A', 0x11, 608)
#define PCM_HW_FREE IO_('A', 0x12)
#define PCM_SW_PARAMS IOWR_('A', 0x13, 136)
#define PCM_STATUS IOR_('A', 0x20, 152)
#define PCM_DELAY IOR_('A', 0x21, 8)
#define PCM_HWSYNC IO_('A', 0x22)
#define PCM_SYNC_PTR IOWR_('A', 0x23, 136)
#define PCM_PREPARE IO_('A', 0x40)
#define PCM_START IO_('A', 0x42)
#define PCM_DROP IO_('A', 0x43)
#define PCM_DRAIN IO_('A', 0x44)
#define PCM_PAUSE IOW_('A', 0x45, 4)
#define PCM_REWIND IOW_('A', 0x46, 8)
#define PCM_FORWARD IOW_('A', 0x49, 8)
#define PCM_WRITEI IOW_('A', 0x50, 24)
#define PCM_READI IOR_('A', 0x51, 24)
#define CTL_PVERSION IOR_('U', 0x00, 4)
#define CTL_CARD_INFO IOR_('U', 0x01, 376)
#define CTL_ELEM_LIST IOWR_('U', 0x10, 80)
#define CTL_ELEM_INFO IOWR_('U', 0x11, 272)
#define CTL_ELEM_READ IOWR_('U', 0x12, 1224)
#define CTL_ELEM_WRITE IOWR_('U', 0x13, 1224)
#define CTL_SUBSCRIBE IOWR_('U', 0x16, 4)
#define CTL_TLV_READ IOWR_('U', 0x1a, 8)
#define CTL_PCM_NEXT IOR_('U', 0x30, 4)
#define CTL_PCM_INFO IOWR_('U', 0x31, 288)

enum { ST_OPEN, ST_SETUP, ST_PREPARED, ST_RUNNING, ST_XRUN, ST_DRAINING, ST_PAUSED };
enum { ACCESS_MMAP_INTERLEAVED = 0, ACCESS_RW_INTERLEAVED = 3 };
enum { FORMAT_S16_LE = 2 };
enum { P_ACCESS, P_FORMAT, P_SUBFORMAT, P_SAMPLE_BITS = 8, P_FRAME_BITS, P_CHANNELS, P_RATE, P_PERIOD_TIME,
       P_PERIOD_SIZE, P_PERIOD_BYTES, P_PERIODS, P_BUFFER_TIME, P_BUFFER_SIZE, P_BUFFER_BYTES, P_TICK_TIME };

struct interval { uint32_t min, max, bits; };
struct mask { uint32_t bits[8]; };
struct hw_params {
    uint32_t flags;
    struct mask masks[3], mres[5];
    struct interval iv[12], ires[9];
    uint32_t rmask, cmask, info, msbits, rate_num, rate_den;
    uint64_t fifo_size;
    unsigned char sync[16], reserved[48];
};
struct sw_params {
    int32_t tstamp_mode;
    uint32_t period_step, sleep_min;
    uint64_t avail_min, xfer_align, start_threshold, stop_threshold, silence_threshold, silence_size, boundary;
    uint32_t proto, tstamp_type;
    unsigned char reserved[56];
};
struct timespec64 { int64_t sec, nsec; };
struct status {
    int32_t state, pad;
    struct timespec64 trigger, tstamp;
    uint64_t appl, hw;
    int64_t delay;
    uint64_t avail, avail_max, overrange;
    int32_t suspended;
    uint32_t audio_data;
    struct timespec64 audio, driver;
    uint32_t accuracy;
    unsigned char reserved[20];
};
struct mmap_status { int32_t state, pad; uint64_t hw; struct timespec64 tstamp; int32_t suspended, pad2; struct timespec64 audio; };
struct mmap_control { uint64_t appl, avail_min; };
struct xferi { int64_t result; void *buf; uint64_t frames; };
struct elem_id { uint32_t numid, iface, device, subdevice; char name[44]; uint32_t index; };
struct elem_list { uint32_t offset, space, used, count; struct elem_id *pids; unsigned char reserved[50]; };
struct elem_info {
    struct elem_id id;
    int32_t type;
    uint32_t access, count;
    int32_t owner;
    union { struct { long min, max, step; } integer; unsigned char reserved[128]; } value;
    unsigned char reserved[64];
};
struct elem_value { struct elem_id id; uint32_t indirect; uint32_t pad; long value[128]; unsigned char reserved[128]; };
struct ctl_event { int32_t type; uint32_t mask; struct elem_id id; };
struct card_info { int32_t card, pad; char id[16], driver[16], name[32], longname[80], reserved[16], mixername[80], components[128]; };
struct pcm_info {
    uint32_t device, subdevice;
    int32_t stream, card;
    char id[64], name[80], subname[32];
    int32_t dev_class, dev_subclass;
    uint32_t count, avail;
    unsigned char pad[16], reserved[64];
};

_Static_assert(sizeof(struct hw_params) == 608, "hw_params");
_Static_assert(sizeof(struct sw_params) == 136, "sw_params");
_Static_assert(sizeof(struct status) == 152, "status");
_Static_assert(sizeof(struct mmap_status) == 56, "mmap status");
_Static_assert(sizeof(struct elem_info) == 272, "elem_info");
_Static_assert(sizeof(struct elem_value) == 1224, "elem_value");
_Static_assert(sizeof(struct card_info) == 376, "card_info");
_Static_assert(sizeof(struct pcm_info) == 288, "pcm_info");
_Static_assert(sizeof(struct ctl_event) == 72, "ctl_event");

static int failures;
static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::sound::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

static void any(struct hw_params *p) {
    memset(p, 0, sizeof *p);
    for (int i = 0; i < 3; i++) memset(p->masks[i].bits, 0xff, sizeof p->masks[i].bits);
    for (int i = 0; i < 12; i++) p->iv[i] = (struct interval){0, ~0u, 0};
    p->rmask = ~0u;
}
static struct interval *iv(struct hw_params *p, int param) { return &p->iv[param - P_SAMPLE_BITS]; }
static void set_mask(struct hw_params *p, int param, unsigned v) {
    memset(p->masks[param].bits, 0, 32);
    p->masks[param].bits[v / 32] = 1u << (v % 32);
}
static void set_iv(struct hw_params *p, int param, unsigned v) { *iv(p, param) = (struct interval){v, v, 4}; }

static int set_params(int fd, int access, unsigned rate, unsigned period, unsigned periods) {
    struct hw_params p;
    any(&p);
    if (ioctl(fd, PCM_HW_REFINE, &p) < 0) return -1;
    set_mask(&p, P_ACCESS, access);
    set_mask(&p, P_FORMAT, FORMAT_S16_LE);
    set_iv(&p, P_CHANNELS, 2);
    set_iv(&p, P_RATE, rate);
    set_iv(&p, P_PERIOD_SIZE, period);
    set_iv(&p, P_PERIODS, periods);
    return ioctl(fd, PCM_HW_PARAMS, &p);
}

static int set_sw(int fd, uint64_t start, uint64_t stop, uint64_t avail_min, struct sw_params *out) {
    struct sw_params s;
    memset(&s, 0, sizeof s);
    s.tstamp_type = 1; /* monotonic */
    s.avail_min = avail_min;
    s.start_threshold = start;
    s.stop_threshold = stop;
    s.period_step = 1;
    int r = ioctl(fd, PCM_SW_PARAMS, &s);
    if (out) *out = s;
    return r;
}

static int state(int fd) {
    struct status st;
    memset(&st, 0, sizeof st);
    if (ioctl(fd, PCM_STATUS, &st) < 0) return -1;
    return st.state;
}

/* `n` frames of a sine at `freq` Hz, continuing from frame `*t`. */
static void tone(int16_t *out, size_t n, double freq, unsigned rate, uint64_t *t) {
    for (size_t i = 0; i < n; i++, (*t)++) {
        int16_t v = (int16_t)(12000 * sin(2 * M_PI * freq * (double)*t / rate));
        out[2 * i] = v;
        out[2 * i + 1] = v;
    }
}

static long long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000LL + t.tv_nsec / 1000000;
}

static int open_pcm(int card, int dir, int flags) {
    char path[64];
    snprintf(path, sizeof path, "/dev/snd/pcmC%dD0%c", card, dir ? 'c' : 'p');
    return open(path, O_RDWR | O_CLOEXEC | flags);
}

static void check_control(int card) {
    char path[64];
    snprintf(path, sizeof path, "/dev/snd/controlC%d", card);
    int fd = open(path, O_RDWR | O_CLOEXEC);
    check("control_open", fd >= 0);
    if (fd < 0) return;
    int v = 0;
    check("control_version", ioctl(fd, CTL_PVERSION, &v) == 0 && v >> 16 == 2);
    struct card_info ci;
    memset(&ci, 0, sizeof ci);
    check("card_info", ioctl(fd, CTL_CARD_INFO, &ci) == 0 && ci.card == card && ci.driver[0] && ci.id[0]);
    printf("card %d: id %s, driver %s, name %s, mixer %s\n", card, ci.id, ci.driver, ci.name, ci.mixername);
    struct elem_list l;
    memset(&l, 0, sizeof l);
    check("elem_count", ioctl(fd, CTL_ELEM_LIST, &l) == 0 && l.count >= 1);
    struct elem_id ids[32];
    memset(ids, 0, sizeof ids);
    l.space = l.count < 32 ? l.count : 32;
    l.pids = ids;
    check("elem_list", ioctl(fd, CTL_ELEM_LIST, &l) == 0 && l.used == l.space && ids[0].numid == 1);
    int volume = -1;
    for (unsigned i = 0; i < l.used; i++) {
        printf("  control %u: %s\n", ids[i].numid, ids[i].name);
        if (strstr(ids[i].name, "Playback Volume") && volume < 0) volume = (int)i;
    }
    if (volume >= 0) {
        struct elem_info info;
        memset(&info, 0, sizeof info);
        info.id.numid = ids[volume].numid;
        check("volume_info", ioctl(fd, CTL_ELEM_INFO, &info) == 0 && info.type == 2 && info.value.integer.max > 0 &&
                                 info.count >= 1 && !strcmp(info.id.name, ids[volume].name));
        /* By name as well as by number. */
        struct elem_info by_name;
        memset(&by_name, 0, sizeof by_name);
        by_name.id = ids[volume];
        by_name.id.numid = 0;
        check("info_by_name", ioctl(fd, CTL_ELEM_INFO, &by_name) == 0 && by_name.id.numid == ids[volume].numid);
        unsigned tlv[8] = {ids[volume].numid, 16};
        check("tlv_db_scale", ioctl(fd, CTL_TLV_READ, tlv) == 0 && tlv[2] == 1 && tlv[3] == 8);
        int sub = 1;
        check("subscribe", ioctl(fd, CTL_SUBSCRIBE, &sub) == 0);
        struct elem_value val;
        memset(&val, 0, sizeof val);
        val.id.numid = ids[volume].numid;
        check("volume_read", ioctl(fd, CTL_ELEM_READ, &val) == 0);
        long was = val.value[0];
        val.value[0] = val.value[1] = info.value.integer.max / 2;
        check("volume_write", ioctl(fd, CTL_ELEM_WRITE, &val) == 0);
        memset(val.value, 0, sizeof val.value);
        check("volume_reads_back", ioctl(fd, CTL_ELEM_READ, &val) == 0 && val.value[0] == info.value.integer.max / 2);
        struct pollfd pf = {fd, POLLIN, 0};
        struct ctl_event ev;
        memset(&ev, 0, sizeof ev);
        check("change_event", poll(&pf, 1, 1000) == 1 && read(fd, &ev, sizeof ev) == sizeof ev && ev.mask == 1 &&
                                  ev.id.numid == ids[volume].numid);
        val.value[0] = val.value[1] = info.value.integer.max + 1;
        check("volume_range", ioctl(fd, CTL_ELEM_WRITE, &val) < 0 && errno == EINVAL);
        val.value[0] = val.value[1] = was;
        ioctl(fd, CTL_ELEM_WRITE, &val);
    }
    int dev = -1;
    check("pcm_next", ioctl(fd, CTL_PCM_NEXT, &dev) == 0 && dev == 0);
    check("pcm_last", ioctl(fd, CTL_PCM_NEXT, &dev) == 0 && dev == -1);
    struct pcm_info pi;
    memset(&pi, 0, sizeof pi);
    check("pcm_info", ioctl(fd, CTL_PCM_INFO, &pi) == 0 && pi.card == card && pi.name[0] && pi.count == 1);
    close(fd);
}

static void check_playback(int card) {
    int fd = open_pcm(card, 0, O_NONBLOCK);
    check("pcm_open", fd >= 0);
    if (fd < 0) return;
    check("pcm_busy", open_pcm(card, 0, 0) < 0 && errno == EBUSY);
    int v = 0;
    check("pcm_version", ioctl(fd, PCM_PVERSION, &v) == 0 && v >> 16 == 2);
    struct hw_params p;
    any(&p);
    check("refine", ioctl(fd, PCM_HW_REFINE, &p) == 0 && iv(&p, P_CHANNELS)->min >= 1 && iv(&p, P_RATE)->min >= 8000 &&
                        p.cmask != 0);
    any(&p);
    set_iv(&p, P_CHANNELS, 7);
    check("refine_refuses", ioctl(fd, PCM_HW_REFINE, &p) < 0 && errno == EINVAL);
    check("hw_params", set_params(fd, ACCESS_RW_INTERLEAVED, 48000, 1024, 4) == 0);
    struct sw_params sw;
    check("sw_params", set_sw(fd, 2048, 4096, 1024, &sw) == 0 && sw.boundary >= 4096 && sw.boundary % 4096 == 0);
    /* Never stop on an underrun while pausing and resuming (an emulated
     * card's position may run ahead of what it has really played). */
    set_sw(fd, 2048, sw.boundary, 1024, 0);
    check("prepare", ioctl(fd, PCM_PREPARE) == 0 && state(fd) == ST_PREPARED);

    /* The status and control pages, as alsa-lib maps them. */
    struct mmap_status *ms = mmap(0, 4096, PROT_READ, MAP_SHARED, fd, 0x80000000);
    struct mmap_control *mc = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0x81000000);
    check("mmap_pages", ms != MAP_FAILED && mc != MAP_FAILED && ms->state == ST_PREPARED && mc->appl == 0);

    int16_t buf[2 * 1024];
    uint64_t t = 0;
    tone(buf, 1024, 440, 48000, &t);
    struct xferi x = {0, buf, 1024};
    check("write_below_threshold", ioctl(fd, PCM_WRITEI, &x) == 0 && x.result == 1024 && state(fd) == ST_PREPARED &&
                                        mc->appl == 1024);
    x.result = 0;
    check("write_starts", ioctl(fd, PCM_WRITEI, &x) == 0 && x.result == 1024 && state(fd) == ST_RUNNING);
    int64_t delay = 0;
    check("delay", ioctl(fd, PCM_DELAY, &delay) == 0 && delay > 0 && delay <= 2048);
    uint64_t frames = 100;
    check("rewind", ioctl(fd, PCM_REWIND, &frames) == 0 && frames == 100 && mc->appl == 1948);
    frames = 100;
    check("forward", ioctl(fd, PCM_FORWARD, &frames) == 0 && frames == 100 && mc->appl == 2048);
    /* The buffer filled (4096 frames: 85 ms), so the pause below has room
     * on either side. */
    tone(buf, 1024, 440, 48000, &t);
    for (int i = 0; i < 2; i++) {
        x = (struct xferi){0, buf, 1024};
        ioctl(fd, PCM_WRITEI, &x);
    }
    /* The hardware moves on its own: hw_ptr in the status page grows. */
    usleep(15000);
    check("hwsync", ioctl(fd, PCM_HWSYNC) == 0);
    check("hw_ptr_moves", ms->hw > 0);
    int on = 1;
    check("pause", ioctl(fd, PCM_PAUSE, &on) == 0 && state(fd) == ST_PAUSED);
    uint64_t held = ms->hw;
    usleep(40000);
    ioctl(fd, PCM_HWSYNC);
    check("paused_holds", ms->hw == held);
    on = 0;
    int rr = ioctl(fd, PCM_PAUSE, &on);
    int rs = state(fd);
    if (rr != 0 || rs != ST_RUNNING)
        printf("resume: ioctl %d (errno %d), state %d, hw %llu, appl %llu\n", rr, errno, rs,
               (unsigned long long)ms->hw, (unsigned long long)mc->appl);
    check("resume", rr == 0 && rs == ST_RUNNING);
    /* Nothing more written, and a stop threshold of the buffer: an
     * underrun. */
    set_sw(fd, 2048, 4096, 1024, 0);
    long long t0 = now_ms();
    while (state(fd) == ST_RUNNING && now_ms() - t0 < 2000) usleep(10000);
    check("underrun", state(fd) == ST_XRUN);
    x.result = 0;
    check("write_after_xrun", ioctl(fd, PCM_WRITEI, &x) < 0 && errno == EPIPE);
    check("prepare_again", ioctl(fd, PCM_PREPARE) == 0 && state(fd) == ST_PREPARED && mc->appl == 0);

    /* SYNC_PTR: the program's position in, the kernel's out. */
    struct { uint32_t flags, pad; struct mmap_status s; unsigned char spad[8]; struct mmap_control c; unsigned char cpad[48]; } sp;
    _Static_assert(sizeof sp == 136, "sync_ptr");
    memset(&sp, 0, sizeof sp);
    sp.flags = 1; /* hwsync */
    sp.c.appl = 0;
    sp.c.avail_min = 512;
    check("sync_ptr", ioctl(fd, PCM_SYNC_PTR, &sp) == 0 && sp.s.state == ST_PREPARED && mc->avail_min == 512);

    /* A blocking write and a drain to the end. */
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    set_sw(fd, 1024, 4096, 1024, 0);
    t0 = now_ms();
    for (int i = 0; i < 12; i++) {
        tone(buf, 1024, 440, 48000, &t);
        x = (struct xferi){0, buf, 1024};
        if (ioctl(fd, PCM_WRITEI, &x) < 0 || x.result != 1024) break;
    }
    check("blocking_writes", state(fd) == ST_RUNNING);
    /* alsa-lib's drain first asks for silence after the last frames: a
     * threshold of the whole buffer and a size beside it. */
    struct sw_params ds;
    memset(&ds, 0, sizeof ds);
    ds.tstamp_type = 1;
    ds.avail_min = 1024;
    ds.start_threshold = 1024;
    ds.stop_threshold = 4096;
    ds.period_step = 1;
    ds.silence_threshold = 4096;
    ds.silence_size = 1024;
    check("drain_silence", ioctl(fd, PCM_SW_PARAMS, &ds) == 0);
    check("drain", ioctl(fd, PCM_DRAIN) == 0 && state(fd) == ST_SETUP);
    long long took = now_ms() - t0;
    /* 12288 frames at 48 kHz: 256 ms. */
    printf("12288 frames took %lld ms\n", took);
    check("drain_in_time", took >= 200 && took < 1500);

    check("hw_free", ioctl(fd, PCM_HW_FREE) == 0 && state(fd) == ST_OPEN);
    munmap(ms, 4096);
    munmap(mc, 4096);
    close(fd);
    fd = open_pcm(card, 0, 0);
    check("reopen", fd >= 0);
    close(fd);
}

/* Recording: started explicitly, read without blocking once poll says
 * frames are there. `must`: the card's recording moves (QEMU's "none"
 * backend records silence; its WAV backend records nothing). */
static void check_capture(int card, int must) {
    int fd = open_pcm(card, 1, O_NONBLOCK);
    if (fd < 0) {
        printf("card %d: no capture device\n", card);
        check("capture_present", !must);
        return;
    }
    check("capture_params", set_params(fd, ACCESS_RW_INTERLEAVED, 48000, 512, 4) == 0);
    set_sw(fd, 1, 2048, 512, 0);
    check("capture_prepare", ioctl(fd, PCM_PREPARE) == 0);
    check("capture_start", ioctl(fd, PCM_START) == 0 && state(fd) == ST_RUNNING);
    int16_t buf[2 * 1024];
    long long t0 = now_ms();
    struct pollfd pf = {fd, POLLIN, 0};
    int ready = poll(&pf, 1, 1500);
    struct xferi x = {0, buf, 1024};
    int r = ioctl(fd, PCM_READI, &x);
    long long took = now_ms() - t0;
    printf("card %d: capture: poll %d, read %lld frames in %lld ms\n", card, ready, r == 0 ? (long long)x.result : -1, took);
    if (must) check("capture_reads", ready == 1 && r == 0 && x.result >= 512 && took < 1000);
    check("capture_drop", ioctl(fd, PCM_DROP) == 0 && state(fd) == ST_SETUP);
    close(fd);
}

/* Play a tone: with WRITEI, or written into the mapped buffer. */
static int play(int card, double freq, double secs, int use_mmap) {
    int fd = open_pcm(card, 0, 0);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    unsigned period = 1024, periods = 4, size = period * periods;
    if (set_params(fd, use_mmap ? ACCESS_MMAP_INTERLEAVED : ACCESS_RW_INTERLEAVED, 48000, period, periods) < 0) {
        perror("hw_params");
        return 1;
    }
    set_sw(fd, size, size, period, 0);
    if (ioctl(fd, PCM_PREPARE) < 0) {
        perror("prepare");
        return 1;
    }
    uint64_t total = (uint64_t)(secs * 48000), t = 0;
    int16_t buf[2 * 1024];
    if (!use_mmap) {
        while (t < total) {
            tone(buf, period, freq, 48000, &t);
            struct xferi x = {0, buf, period};
            if (ioctl(fd, PCM_WRITEI, &x) < 0) {
                perror("write");
                return 1;
            }
        }
    } else {
        int16_t *data = mmap(0, size * 4, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        struct mmap_status *ms = mmap(0, 4096, PROT_READ, MAP_SHARED, fd, 0x80000000);
        struct mmap_control *mc = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0x81000000);
        if (data == MAP_FAILED || ms == MAP_FAILED || mc == MAP_FAILED) {
            perror("mmap");
            return 1;
        }
        struct pollfd pf = {fd, POLLOUT, 0};
        int xruns = 0;
        while (t < total) {
            ioctl(fd, PCM_HWSYNC);
            if (ms->state == ST_XRUN) {
                xruns++;
                ioctl(fd, PCM_PREPARE);
            }
            uint64_t queued = mc->appl - ms->hw;
            if (queued >= size) {
                if (ms->state == ST_PREPARED) ioctl(fd, PCM_START);
                poll(&pf, 1, 100);
                continue;
            }
            unsigned at = (unsigned)(mc->appl % size);
            unsigned n = period - at % period;
            if (n > size - queued) n = (unsigned)(size - queued);
            tone(data + 2 * at, n, freq, 48000, &t);
            mc->appl += n;
        }
        if (ms->state == ST_PREPARED) ioctl(fd, PCM_START);
        if (xruns) printf("%d underruns\n", xruns);
    }
    ioctl(fd, PCM_DRAIN);
    printf("played %.0f Hz for %.1f s on card %d (%s)\n", freq, secs, card, use_mmap ? "mmap" : "writei");
    close(fd);
    return 0;
}

/* A WAV file of a tone (48 kHz, 16-bit stereo), for other players. */
static int write_wav(double freq, double secs, const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        perror(path);
        return 1;
    }
    uint32_t frames = (uint32_t)(secs * 48000), bytes = frames * 4;
    uint32_t h[11] = {0x46464952, 36 + bytes, 0x45564157, 0x20746d66, 16, 0x00020001, 48000, 48000 * 4, 0x00100004,
                      0x61746164, bytes};
    fwrite(h, sizeof h, 1, f);
    int16_t buf[2 * 1024];
    uint64_t t = 0;
    while (t < frames) {
        size_t n = frames - t < 1024 ? frames - t : 1024;
        tone(buf, n, freq, 48000, &t);
        fwrite(buf, 4, n, f);
    }
    return fclose(f) == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc >= 5 && !strcmp(argv[1], "play")) return play(atoi(argv[2]), atof(argv[3]), atof(argv[4]), argc > 5);
    if (argc >= 5 && !strcmp(argv[1], "wav")) return write_wav(atof(argv[2]), atof(argv[3]), argv[4]);
    FILE *f = fopen("/proc/asound/cards", "r");
    check("proc_cards", f != 0);
    int cards = 0;
    char line[256];
    while (f && fgets(line, sizeof line, f)) {
        int n;
        if (sscanf(line, "%d [", &n) == 1) {
            cards++;
            check_control(n);
            check_playback(n);
            /* "check CARDS RECORDING-CARD": that card's recording moves. */
            check_capture(n, argc > 3 && atoi(argv[3]) == n);
        }
    }
    if (f) fclose(f);
    printf("%d cards\n", cards);
    check("cards", cards >= (argc > 2 && !strcmp(argv[1], "check") ? atoi(argv[2]) : 1));
    return failures;
}
