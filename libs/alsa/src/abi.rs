// SPDX-License-Identifier: MIT OR Apache-2.0

//! The numbers and layouts of ALSA's kernel interface on x86-64.
//!
//! Source (ADR 0184, extending ADR 0033's exception): Linux's UAPI headers
//! `sound/asound.h` and `sound/tlv.h` as Fedora's `kernel-headers` 7.2.4
//! publishes them (`GPL-2.0 WITH Linux-syscall-note`), retyped as a list
//! of facts; the sizes and offsets were checked against the header with
//! the host's C compiler (`sizeof`, `offsetof`). Device numbers are from
//! the kernel's `devices.txt` (major 116, "Advanced Linux Sound Driver").

/// The character major of `/dev/snd` (devices.txt).
pub const SOUND_MAJOR: u32 = 116;
/// Minors: 32 per card; the control device first, playback devices from
/// 16, capture devices from 24 (devices.txt's static numbering).
pub const MINORS_PER_CARD: u32 = 32;
pub const MINOR_PLAYBACK: u32 = 16;
pub const MINOR_CAPTURE: u32 = 24;
/// Devices of each direction a card may have under this numbering.
pub const DEVICES_PER_DIRECTION: u32 = 8;

/// `SNDRV_PROTOCOL_VERSION(major, minor, subminor)`.
pub const fn protocol_version(major: u32, minor: u32, sub: u32) -> u32 {
    (major << 16) | (minor << 8) | sub
}
/// `SNDRV_PCM_VERSION`: 2.0.18.
pub const PCM_VERSION: u32 = protocol_version(2, 0, 18);
/// `SNDRV_CTL_VERSION`: 2.0.9.
pub const CTL_VERSION: u32 = protocol_version(2, 0, 9);

// ioctl(2) numbers: `_IOC(dir, type, nr, size)` = dir << 30 | size << 16 |
// type << 8 | nr, dir 1 write (from the caller), 2 read.
const fn ioc(dir: u32, ty: u8, nr: u32, size: u32) -> u32 {
    (dir << 30) | (size << 16) | ((ty as u32) << 8) | nr
}
const fn io(ty: u8, nr: u32) -> u32 {
    ioc(0, ty, nr, 0)
}
const fn ior(ty: u8, nr: u32, size: u32) -> u32 {
    ioc(2, ty, nr, size)
}
const fn iow(ty: u8, nr: u32, size: u32) -> u32 {
    ioc(1, ty, nr, size)
}
const fn iowr(ty: u8, nr: u32, size: u32) -> u32 {
    ioc(3, ty, nr, size)
}

// Structure sizes on x86-64.
pub const PCM_INFO_SIZE: usize = 288;
pub const HW_PARAMS_SIZE: usize = 608;
pub const SW_PARAMS_SIZE: usize = 136;
pub const STATUS_SIZE: usize = 152;
pub const MMAP_STATUS_SIZE: usize = 56;
pub const MMAP_CONTROL_SIZE: usize = 16;
pub const SYNC_PTR_SIZE: usize = 136;
pub const XFERI_SIZE: usize = 24;
pub const CHANNEL_INFO_SIZE: usize = 24;
pub const CARD_INFO_SIZE: usize = 376;
pub const ELEM_ID_SIZE: usize = 64;
pub const ELEM_LIST_SIZE: usize = 80;
pub const ELEM_INFO_SIZE: usize = 272;
pub const ELEM_VALUE_SIZE: usize = 1224;
pub const CTL_EVENT_SIZE: usize = 72;

// PCM ioctls (type 'A').
pub const PCM_IOCTL_PVERSION: u32 = ior(b'A', 0x00, 4);
pub const PCM_IOCTL_INFO: u32 = ior(b'A', 0x01, PCM_INFO_SIZE as u32);
pub const PCM_IOCTL_TSTAMP: u32 = iow(b'A', 0x02, 4);
pub const PCM_IOCTL_TTSTAMP: u32 = iow(b'A', 0x03, 4);
pub const PCM_IOCTL_USER_PVERSION: u32 = iow(b'A', 0x04, 4);
pub const PCM_IOCTL_HW_REFINE: u32 = iowr(b'A', 0x10, HW_PARAMS_SIZE as u32);
pub const PCM_IOCTL_HW_PARAMS: u32 = iowr(b'A', 0x11, HW_PARAMS_SIZE as u32);
pub const PCM_IOCTL_HW_FREE: u32 = io(b'A', 0x12);
pub const PCM_IOCTL_SW_PARAMS: u32 = iowr(b'A', 0x13, SW_PARAMS_SIZE as u32);
pub const PCM_IOCTL_STATUS: u32 = ior(b'A', 0x20, STATUS_SIZE as u32);
pub const PCM_IOCTL_DELAY: u32 = ior(b'A', 0x21, 8);
pub const PCM_IOCTL_HWSYNC: u32 = io(b'A', 0x22);
pub const PCM_IOCTL_SYNC_PTR: u32 = iowr(b'A', 0x23, SYNC_PTR_SIZE as u32);
pub const PCM_IOCTL_STATUS_EXT: u32 = iowr(b'A', 0x24, STATUS_SIZE as u32);
pub const PCM_IOCTL_CHANNEL_INFO: u32 = ior(b'A', 0x32, CHANNEL_INFO_SIZE as u32);
pub const PCM_IOCTL_PREPARE: u32 = io(b'A', 0x40);
pub const PCM_IOCTL_RESET: u32 = io(b'A', 0x41);
pub const PCM_IOCTL_START: u32 = io(b'A', 0x42);
pub const PCM_IOCTL_DROP: u32 = io(b'A', 0x43);
pub const PCM_IOCTL_DRAIN: u32 = io(b'A', 0x44);
pub const PCM_IOCTL_PAUSE: u32 = iow(b'A', 0x45, 4);
pub const PCM_IOCTL_REWIND: u32 = iow(b'A', 0x46, 8);
pub const PCM_IOCTL_RESUME: u32 = io(b'A', 0x47);
pub const PCM_IOCTL_XRUN: u32 = io(b'A', 0x48);
pub const PCM_IOCTL_FORWARD: u32 = iow(b'A', 0x49, 8);
pub const PCM_IOCTL_WRITEI_FRAMES: u32 = iow(b'A', 0x50, XFERI_SIZE as u32);
pub const PCM_IOCTL_READI_FRAMES: u32 = ior(b'A', 0x51, XFERI_SIZE as u32);
pub const PCM_IOCTL_WRITEN_FRAMES: u32 = iow(b'A', 0x52, XFERI_SIZE as u32);
pub const PCM_IOCTL_READN_FRAMES: u32 = ior(b'A', 0x53, XFERI_SIZE as u32);
pub const PCM_IOCTL_LINK: u32 = iow(b'A', 0x60, 4);
pub const PCM_IOCTL_UNLINK: u32 = io(b'A', 0x61);

// Control ioctls (type 'U').
pub const CTL_IOCTL_PVERSION: u32 = ior(b'U', 0x00, 4);
pub const CTL_IOCTL_CARD_INFO: u32 = ior(b'U', 0x01, CARD_INFO_SIZE as u32);
pub const CTL_IOCTL_ELEM_LIST: u32 = iowr(b'U', 0x10, ELEM_LIST_SIZE as u32);
pub const CTL_IOCTL_ELEM_INFO: u32 = iowr(b'U', 0x11, ELEM_INFO_SIZE as u32);
pub const CTL_IOCTL_ELEM_READ: u32 = iowr(b'U', 0x12, ELEM_VALUE_SIZE as u32);
pub const CTL_IOCTL_ELEM_WRITE: u32 = iowr(b'U', 0x13, ELEM_VALUE_SIZE as u32);
pub const CTL_IOCTL_ELEM_LOCK: u32 = iow(b'U', 0x14, ELEM_ID_SIZE as u32);
pub const CTL_IOCTL_ELEM_UNLOCK: u32 = iow(b'U', 0x15, ELEM_ID_SIZE as u32);
pub const CTL_IOCTL_SUBSCRIBE_EVENTS: u32 = iowr(b'U', 0x16, 4);
pub const CTL_IOCTL_ELEM_ADD: u32 = iowr(b'U', 0x17, ELEM_INFO_SIZE as u32);
pub const CTL_IOCTL_ELEM_REPLACE: u32 = iowr(b'U', 0x18, ELEM_INFO_SIZE as u32);
pub const CTL_IOCTL_ELEM_REMOVE: u32 = iowr(b'U', 0x19, ELEM_ID_SIZE as u32);
pub const CTL_IOCTL_TLV_READ: u32 = iowr(b'U', 0x1a, 8);
pub const CTL_IOCTL_HWDEP_NEXT_DEVICE: u32 = iowr(b'U', 0x20, 4);
pub const CTL_IOCTL_PCM_NEXT_DEVICE: u32 = ior(b'U', 0x30, 4);
pub const CTL_IOCTL_PCM_INFO: u32 = iowr(b'U', 0x31, PCM_INFO_SIZE as u32);
pub const CTL_IOCTL_PCM_PREFER_SUBDEVICE: u32 = iow(b'U', 0x32, 4);
pub const CTL_IOCTL_RAWMIDI_NEXT_DEVICE: u32 = iowr(b'U', 0x40, 4);
pub const CTL_IOCTL_UMP_NEXT_DEVICE: u32 = iowr(b'U', 0x43, 4);
pub const CTL_IOCTL_POWER: u32 = iowr(b'U', 0xd0, 4);
pub const CTL_IOCTL_POWER_STATE: u32 = ior(b'U', 0xd1, 4);

/// Stream directions (`SNDRV_PCM_STREAM_*`).
pub const STREAM_PLAYBACK: u32 = 0;
pub const STREAM_CAPTURE: u32 = 1;

/// Access types (`SNDRV_PCM_ACCESS_*`).
pub const ACCESS_MMAP_INTERLEAVED: u32 = 0;
pub const ACCESS_MMAP_NONINTERLEAVED: u32 = 1;
pub const ACCESS_MMAP_COMPLEX: u32 = 2;
pub const ACCESS_RW_INTERLEAVED: u32 = 3;
pub const ACCESS_RW_NONINTERLEAVED: u32 = 4;

/// Sample formats (`SNDRV_PCM_FORMAT_*`) Slate's drivers use.
pub const FORMAT_S8: u32 = 0;
pub const FORMAT_U8: u32 = 1;
pub const FORMAT_S16_LE: u32 = 2;
pub const FORMAT_S24_LE: u32 = 6;
pub const FORMAT_S32_LE: u32 = 10;
pub const FORMAT_FLOAT_LE: u32 = 14;
pub const FORMAT_S24_3LE: u32 = 32;
pub const FORMAT_S20_LE: u32 = 25;

/// A format's widths: (bits that carry the sample, bits it takes in
/// memory), from the header's comments on each format; None for formats
/// Slate doesn't know.
pub fn format_widths(f: u32) -> Option<(u32, u32)> {
    Some(match f {
        FORMAT_S8 | FORMAT_U8 => (8, 8),
        // S16/U16, LE and BE.
        2..=5 => (16, 16),
        // S24/U24 in the low three bytes of four.
        6..=9 => (24, 32),
        // S32/U32, FLOAT.
        10..=15 => (32, 32),
        // FLOAT64.
        16 | 17 => (64, 64),
        // S20/U20 in four bytes.
        25..=28 => (20, 32),
        // Three-byte formats: 24, 20 and 18 bits.
        32..=35 => (24, 24),
        36..=39 => (20, 24),
        40..=43 => (18, 24),
        _ => return None,
    })
}

/// Subformats (`SNDRV_PCM_SUBFORMAT_*`).
pub const SUBFORMAT_STD: u32 = 0;

/// Stream states (`SNDRV_PCM_STATE_*`).
pub const STATE_OPEN: u32 = 0;
pub const STATE_SETUP: u32 = 1;
pub const STATE_PREPARED: u32 = 2;
pub const STATE_RUNNING: u32 = 3;
pub const STATE_XRUN: u32 = 4;
pub const STATE_DRAINING: u32 = 5;
pub const STATE_PAUSED: u32 = 6;
pub const STATE_SUSPENDED: u32 = 7;
pub const STATE_DISCONNECTED: u32 = 8;

/// The info flags of a stream (`SNDRV_PCM_INFO_*`).
pub const INFO_MMAP: u32 = 0x0000_0001;
pub const INFO_MMAP_VALID: u32 = 0x0000_0002;
pub const INFO_DOUBLE: u32 = 0x0000_0004;
pub const INFO_BATCH: u32 = 0x0000_0010;
pub const INFO_INTERLEAVED: u32 = 0x0000_0100;
pub const INFO_BLOCK_TRANSFER: u32 = 0x0001_0000;
pub const INFO_PAUSE: u32 = 0x0008_0000;
pub const INFO_HALF_DUPLEX: u32 = 0x0010_0000;
pub const INFO_JOINT_DUPLEX: u32 = 0x0020_0000;

/// Device classes (`SNDRV_PCM_CLASS_*`, `SNDRV_PCM_SUBCLASS_*`).
pub const PCM_CLASS_GENERIC: u32 = 0;
pub const PCM_SUBCLASS_GENERIC_MIX: u32 = 0;

/// The hardware parameters (`SNDRV_PCM_HW_PARAM_*`): three masks, then
/// twelve intervals numbered from 8.
pub const HW_PARAM_ACCESS: usize = 0;
pub const HW_PARAM_FORMAT: usize = 1;
pub const HW_PARAM_SUBFORMAT: usize = 2;
pub const HW_PARAM_SAMPLE_BITS: usize = 8;
pub const HW_PARAM_FRAME_BITS: usize = 9;
pub const HW_PARAM_CHANNELS: usize = 10;
pub const HW_PARAM_RATE: usize = 11;
pub const HW_PARAM_PERIOD_TIME: usize = 12;
pub const HW_PARAM_PERIOD_SIZE: usize = 13;
pub const HW_PARAM_PERIOD_BYTES: usize = 14;
pub const HW_PARAM_PERIODS: usize = 15;
pub const HW_PARAM_BUFFER_TIME: usize = 16;
pub const HW_PARAM_BUFFER_SIZE: usize = 17;
pub const HW_PARAM_BUFFER_BYTES: usize = 18;
pub const HW_PARAM_TICK_TIME: usize = 19;
pub const HW_PARAM_FIRST_INTERVAL: usize = 8;
pub const HW_PARAM_LAST_INTERVAL: usize = 19;
/// hw_params' flags: don't resample, don't wake every period, don't fill
/// with silence when draining.
pub const HW_PARAMS_NORESAMPLE: u32 = 1 << 0;
pub const HW_PARAMS_NO_PERIOD_WAKEUP: u32 = 1 << 2;
pub const HW_PARAMS_NO_DRAIN_SILENCE: u32 = 1 << 3;

// `struct snd_pcm_hw_params`: flags at 0, the masks at 4 (32 bytes each),
// five reserved masks, the intervals at 260 (12 bytes each: min, max, and
// a word of bits openmin 0, openmax 1, integer 2, empty 3), nine reserved
// intervals, then rmask 512, cmask 516, info 520, msbits 524, rate_num
// 528, rate_den 532, fifo_size 536 (8 bytes), sync 544.
pub const HWP_FLAGS: usize = 0;
pub const HWP_MASKS: usize = 4;
pub const HWP_MASK_SIZE: usize = 32;
pub const HWP_INTERVALS: usize = 260;
pub const HWP_INTERVAL_SIZE: usize = 12;
pub const HWP_RMASK: usize = 512;
pub const HWP_CMASK: usize = 516;
pub const HWP_INFO: usize = 520;
pub const HWP_MSBITS: usize = 524;
pub const HWP_RATE_NUM: usize = 528;
pub const HWP_RATE_DEN: usize = 532;
pub const HWP_FIFO_SIZE: usize = 536;

// `struct snd_pcm_sw_params`.
pub const SWP_TSTAMP_MODE: usize = 0;
pub const SWP_PERIOD_STEP: usize = 4;
pub const SWP_AVAIL_MIN: usize = 16;
pub const SWP_START_THRESHOLD: usize = 32;
pub const SWP_STOP_THRESHOLD: usize = 40;
pub const SWP_SILENCE_THRESHOLD: usize = 48;
pub const SWP_SILENCE_SIZE: usize = 56;
pub const SWP_BOUNDARY: usize = 64;
pub const SWP_PROTO: usize = 72;
pub const SWP_TSTAMP_TYPE: usize = 76;

// `struct snd_pcm_status` (timespecs are two i64s).
pub const ST_STATE: usize = 0;
pub const ST_TRIGGER_TSTAMP: usize = 8;
pub const ST_TSTAMP: usize = 24;
pub const ST_APPL_PTR: usize = 40;
pub const ST_HW_PTR: usize = 48;
pub const ST_DELAY: usize = 56;
pub const ST_AVAIL: usize = 64;
pub const ST_AVAIL_MAX: usize = 72;
pub const ST_SUSPENDED_STATE: usize = 88;
pub const ST_AUDIO_TSTAMP_DATA: usize = 92;
pub const ST_AUDIO_TSTAMP: usize = 96;
pub const ST_DRIVER_TSTAMP: usize = 112;

// The mmap status page: state 0, hw_ptr 8, tstamp 16, suspended_state
// 32, audio_tstamp 40. The control page: appl_ptr 0, avail_min 8.
pub const MS_STATE: usize = 0;
pub const MS_HW_PTR: usize = 8;
pub const MS_TSTAMP: usize = 16;
pub const MS_SUSPENDED_STATE: usize = 32;
pub const MS_AUDIO_TSTAMP: usize = 40;
pub const MC_APPL_PTR: usize = 0;
pub const MC_AVAIL_MIN: usize = 8;

/// mmap offsets of a PCM device: the buffer, then the status and control
/// pages at their old (64-bit) and new (time64) offsets, which are the
/// same layouts on x86-64.
pub const MMAP_OFFSET_DATA: u64 = 0x0000_0000;
pub const MMAP_OFFSET_STATUS_OLD: u64 = 0x8000_0000;
pub const MMAP_OFFSET_CONTROL_OLD: u64 = 0x8100_0000;
pub const MMAP_OFFSET_STATUS_NEW: u64 = 0x8200_0000;
pub const MMAP_OFFSET_CONTROL_NEW: u64 = 0x8300_0000;

// `struct snd_pcm_sync_ptr`: flags at 0, the status at 8, the control at
// 72; flags: HWSYNC 1 (bring hw_ptr up to date first), APPL 2 (report
// appl_ptr rather than take it), AVAIL_MIN 4 (report avail_min rather
// than take it).
pub const SP_FLAGS: usize = 0;
pub const SP_STATUS: usize = 8;
pub const SP_CONTROL: usize = 72;
pub const SYNC_PTR_HWSYNC: u32 = 1 << 0;
pub const SYNC_PTR_APPL: u32 = 1 << 1;
pub const SYNC_PTR_AVAIL_MIN: u32 = 1 << 2;

/// Timestamp types (`SNDRV_PCM_TSTAMP_TYPE_*`).
pub const TSTAMP_TYPE_GETTIMEOFDAY: u32 = 0;
pub const TSTAMP_TYPE_MONOTONIC: u32 = 1;
pub const TSTAMP_TYPE_MONOTONIC_RAW: u32 = 2;

// `struct snd_pcm_info`: device 0, subdevice 4, stream 8, card 12, id 16
// (64 bytes), name 80 (80), subname 160 (32), dev_class 192, dev_subclass
// 196, subdevices_count 200, subdevices_avail 204.
pub const PI_DEVICE: usize = 0;
pub const PI_SUBDEVICE: usize = 4;
pub const PI_STREAM: usize = 8;
pub const PI_CARD: usize = 12;
pub const PI_ID: usize = 16;
pub const PI_NAME: usize = 80;
pub const PI_SUBNAME: usize = 160;
pub const PI_DEV_CLASS: usize = 192;
pub const PI_DEV_SUBCLASS: usize = 196;
pub const PI_SUBDEVICES_COUNT: usize = 200;
pub const PI_SUBDEVICES_AVAIL: usize = 204;

// `struct snd_ctl_card_info`.
pub const CI_CARD: usize = 0;
pub const CI_ID: usize = 8;
pub const CI_DRIVER: usize = 24;
pub const CI_NAME: usize = 40;
pub const CI_LONGNAME: usize = 72;
pub const CI_MIXERNAME: usize = 168;
pub const CI_COMPONENTS: usize = 248;

// `struct snd_ctl_elem_id`: numid 0, iface 4, device 8, subdevice 12,
// name 16 (44 bytes), index 60.
pub const EID_NUMID: usize = 0;
pub const EID_IFACE: usize = 4;
pub const EID_DEVICE: usize = 8;
pub const EID_SUBDEVICE: usize = 12;
pub const EID_NAME: usize = 16;
pub const EID_NAME_LEN: usize = 44;
pub const EID_INDEX: usize = 60;

// `struct snd_ctl_elem_list`: offset 0, space 4, used 8, count 12, pids 16.
pub const EL_OFFSET: usize = 0;
pub const EL_SPACE: usize = 4;
pub const EL_USED: usize = 8;
pub const EL_COUNT: usize = 12;
pub const EL_PIDS: usize = 16;

// `struct snd_ctl_elem_info`: the id, type 64, access 68, count 72, owner
// 76, the value's union at 80: integers' min 80, max 88, step 96 (longs);
// enumerated items 80, item 84, name 88 (64 bytes).
pub const EI_TYPE: usize = 64;
pub const EI_ACCESS: usize = 68;
pub const EI_COUNT: usize = 72;
pub const EI_OWNER: usize = 76;
pub const EI_INT_MIN: usize = 80;
pub const EI_INT_MAX: usize = 88;
pub const EI_INT_STEP: usize = 96;
pub const EI_ENUM_ITEMS: usize = 80;
pub const EI_ENUM_ITEM: usize = 84;
pub const EI_ENUM_NAME: usize = 88;

/// `struct snd_ctl_elem_value`: the id, then the values from 72 (longs for
/// booleans and integers, u32 items for enumerations).
pub const EV_VALUE: usize = 72;

/// Element types (`SNDRV_CTL_ELEM_TYPE_*`).
pub const ELEM_TYPE_BOOLEAN: u32 = 1;
pub const ELEM_TYPE_INTEGER: u32 = 2;
pub const ELEM_TYPE_ENUMERATED: u32 = 3;

/// Element interfaces (`SNDRV_CTL_ELEM_IFACE_*`).
pub const ELEM_IFACE_CARD: u32 = 0;
pub const ELEM_IFACE_MIXER: u32 = 2;
pub const ELEM_IFACE_PCM: u32 = 3;

/// Element access (`SNDRV_CTL_ELEM_ACCESS_*`).
pub const ELEM_ACCESS_READ: u32 = 1 << 0;
pub const ELEM_ACCESS_WRITE: u32 = 1 << 1;
pub const ELEM_ACCESS_READWRITE: u32 = ELEM_ACCESS_READ | ELEM_ACCESS_WRITE;
pub const ELEM_ACCESS_VOLATILE: u32 = 1 << 2;
pub const ELEM_ACCESS_TLV_READ: u32 = 1 << 4;

/// Control events (`SNDRV_CTL_EVENT_*`): an element event, whose mask says
/// what changed (value 1, info 2, added 4, TLV 8; all ones: removed).
pub const CTL_EVENT_ELEM: u32 = 0;
pub const CTL_EVENT_MASK_VALUE: u32 = 1 << 0;
pub const CTL_EVENT_MASK_INFO: u32 = 1 << 1;
pub const CTL_EVENT_MASK_ADD: u32 = 1 << 2;
pub const CTL_EVENT_MASK_REMOVE: u32 = !0;
/// `struct snd_ctl_event`: type 0, mask 4, the element's id 8.
pub const CE_TYPE: usize = 0;
pub const CE_MASK: usize = 4;
pub const CE_ID: usize = 8;

/// Power states (`SNDRV_CTL_POWER_*`): D0, fully on.
pub const CTL_POWER_D0: u32 = 0x0000;

/// TLV types (`sound/tlv.h`): a dB scale is [type, length 8, minimum in
/// hundredths of a dB, step in hundredths | 0x10000 if the minimum
/// mutes].
pub const TLVT_DB_SCALE: u32 = 1;
pub const TLV_DB_SCALE_MUTE: u32 = 0x10000;

/// Little-endian reads and writes into the structures above.
pub fn get_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
pub fn get_u64(b: &[u8], off: usize) -> u64 {
    let mut x = [0u8; 8];
    x.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(x)
}
pub fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
pub fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
/// A string into a fixed field, cut to leave a NUL.
pub fn put_str(b: &mut [u8], off: usize, len: usize, s: &str) {
    let field = &mut b[off..off + len];
    field.fill(0);
    let n = s.len().min(len - 1);
    field[..n].copy_from_slice(&s.as_bytes()[..n]);
}
/// A NUL-terminated string from a fixed field.
pub fn get_str(b: &[u8], off: usize, len: usize) -> &[u8] {
    let field = &b[off..off + len];
    let end = field.iter().position(|&c| c == 0).unwrap_or(len);
    &field[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The numbers the host's C compiler gave for the header's macros.
    #[test]
    fn ioctl_numbers_match_the_header() {
        assert_eq!(PCM_IOCTL_INFO, 0x8120_4101);
        assert_eq!(PCM_IOCTL_HW_REFINE, 0xc260_4110);
        assert_eq!(PCM_IOCTL_HW_PARAMS, 0xc260_4111);
        assert_eq!(PCM_IOCTL_SW_PARAMS, 0xc088_4113);
        assert_eq!(PCM_IOCTL_STATUS, 0x8098_4120);
        assert_eq!(PCM_IOCTL_STATUS_EXT, 0xc098_4124);
        assert_eq!(PCM_IOCTL_DELAY, 0x8008_4121);
        assert_eq!(PCM_IOCTL_SYNC_PTR, 0xc088_4123);
        assert_eq!(PCM_IOCTL_CHANNEL_INFO, 0x8018_4132);
        assert_eq!(PCM_IOCTL_WRITEI_FRAMES, 0x4018_4150);
        assert_eq!(PCM_IOCTL_READI_FRAMES, 0x8018_4151);
        assert_eq!(PCM_IOCTL_PAUSE, 0x4004_4145);
        assert_eq!(PCM_IOCTL_REWIND, 0x4008_4146);
        assert_eq!(PCM_IOCTL_TTSTAMP, 0x4004_4103);
        assert_eq!(PCM_IOCTL_USER_PVERSION, 0x4004_4104);
        assert_eq!(CTL_IOCTL_CARD_INFO, 0x8178_5501);
        assert_eq!(CTL_IOCTL_ELEM_LIST, 0xc050_5510);
        assert_eq!(CTL_IOCTL_ELEM_INFO, 0xc110_5511);
        assert_eq!(CTL_IOCTL_ELEM_READ, 0xc4c8_5512);
        assert_eq!(CTL_IOCTL_ELEM_WRITE, 0xc4c8_5513);
        assert_eq!(CTL_IOCTL_SUBSCRIBE_EVENTS, 0xc004_5516);
        assert_eq!(CTL_IOCTL_TLV_READ, 0xc008_551a);
        assert_eq!(CTL_IOCTL_PCM_NEXT_DEVICE, 0x8004_5530);
        assert_eq!(CTL_IOCTL_PCM_INFO, 0xc120_5531);
        assert_eq!(CTL_IOCTL_PCM_PREFER_SUBDEVICE, 0x4004_5532);
        assert_eq!(CTL_IOCTL_POWER_STATE, 0x8004_55d1);
        assert_eq!(CTL_IOCTL_PVERSION, 0x8004_5500);
        assert_eq!(PCM_VERSION, 0x20012);
        assert_eq!(CTL_VERSION, 0x20009);
    }

    #[test]
    fn strings_fit_their_fields() {
        let mut b = [0xffu8; 16];
        put_str(&mut b, 2, 8, "Intel HDA");
        assert_eq!(get_str(&b, 2, 8), b"Intel H");
        assert_eq!(b[9], 0);
        assert_eq!(b[10], 0xff);
    }
}
