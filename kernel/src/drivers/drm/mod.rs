// SPDX-License-Identifier: MIT OR Apache-2.0

//! DRM/KMS (ADR 0033, ADR 0100): each display adapter is a
//! `/dev/dri/cardN` with the kernel mode-setting interface that libdrm and
//! wlroots use.
//!
//! A card has one or more outputs. Each is a CRTC, an encoder that drives
//! only that CRTC, a connector with its modes and EDID, a primary plane
//! (XRGB8888 or ARGB8888 framebuffers made from dumb buffers) and a 64 × 64
//! ARGB8888 cursor plane. Their state (the CRTC's ACTIVE, MODE_ID and
//! GAMMA_LUT, the connector's CRTC_ID, the planes' FB_ID, CRTC_ID, SRC_*
//! and CRTC_*) changes through atomic commits, and the legacy calls
//! (SETCRTC, PAGE_FLIP, SETPLANE, CURSOR, SETGAMMA, DPMS) build commits of
//! their own on the same state.
//!
//! Neither of Slate's displays has a vblank interrupt, so each active CRTC
//! has a vblank clock of its own: vblanks every frame of its mode from the
//! moment it was switched on. Flips are shown at once and complete, with
//! their events, at the next vblank; WAIT_VBLANK and the CRTC sequence
//! calls count the same clock.
//!
//! Interface facts (ioctl numbers, structure layouts, constants) come
//! from libdrm 2.4.124's `drm.h`, `drm_mode.h` and `drm_fourcc.h` (MIT
//! license, ADR 0033); behaviour from the kernel's DRM uAPI documentation
//! (KMS properties, atomic mode-setting, primary-node authentication).

pub mod bootfb;
pub mod twod;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::abi::linux::errno::*;
use crate::arch::uaccess::{copy_from_user, copy_to_user, read_user, write_user};
use crate::fs::vfs::{self, Inode, Metadata, Result};
use crate::fs::{CharNode, File, O_ACCMODE, O_CLOEXEC, O_NONBLOCK, O_RDWR, POLLIN, POLLOUT, SysEntry};
use crate::mm::{PAGE_SIZE, PhysAddr, frame};
use crate::sched::wait::WaitQueue;
use crate::sync::IrqSpinLock;

/// DRM character devices (devices.txt: major 226; card minors from 0).
pub const DRM_MAJOR: u32 = 226;

// ioctl numbers (drm.h): type 'd', these numbers.
const VERSION: u32 = 0x00;
const GET_UNIQUE: u32 = 0x01;
const GET_MAGIC: u32 = 0x02;
const GEM_CLOSE: u32 = 0x09;
const GET_CAP: u32 = 0x0c;
const SET_CLIENT_CAP: u32 = 0x0d;
const AUTH_MAGIC: u32 = 0x11;
const SET_MASTER: u32 = 0x1e;
const DROP_MASTER: u32 = 0x1f;
const PRIME_HANDLE_TO_FD: u32 = 0x2d;
const PRIME_FD_TO_HANDLE: u32 = 0x2e;
const WAIT_VBLANK: u32 = 0x3a;
const CRTC_GET_SEQUENCE: u32 = 0x3b;
const CRTC_QUEUE_SEQUENCE: u32 = 0x3c;
const MODE_GETRESOURCES: u32 = 0xA0;
const MODE_GETCRTC: u32 = 0xA1;
const MODE_SETCRTC: u32 = 0xA2;
const MODE_CURSOR: u32 = 0xA3;
const MODE_GETGAMMA: u32 = 0xA4;
const MODE_SETGAMMA: u32 = 0xA5;
const MODE_GETENCODER: u32 = 0xA6;
const MODE_GETCONNECTOR: u32 = 0xA7;
const MODE_GETPROPERTY: u32 = 0xAA;
const MODE_SETPROPERTY: u32 = 0xAB;
const MODE_GETPROPBLOB: u32 = 0xAC;
const MODE_GETFB: u32 = 0xAD;
const MODE_ADDFB: u32 = 0xAE;
const MODE_RMFB: u32 = 0xAF;
const MODE_PAGE_FLIP: u32 = 0xB0;
const MODE_DIRTYFB: u32 = 0xB1;
/// DIRTYFB clips shown one by one; more are merged into one rectangle.
const MAX_SEPARATE_CLIPS: usize = 8;
const MODE_CREATE_DUMB: u32 = 0xB2;
const MODE_MAP_DUMB: u32 = 0xB3;
const MODE_DESTROY_DUMB: u32 = 0xB4;
const MODE_GETPLANERESOURCES: u32 = 0xB5;
const MODE_GETPLANE: u32 = 0xB6;
const MODE_SETPLANE: u32 = 0xB7;
const MODE_ADDFB2: u32 = 0xB8;
const MODE_OBJ_GETPROPERTIES: u32 = 0xB9;
const MODE_OBJ_SETPROPERTY: u32 = 0xBA;
const MODE_CURSOR2: u32 = 0xBB;
const MODE_ATOMIC: u32 = 0xBC;
const MODE_CREATEPROPBLOB: u32 = 0xBD;
const MODE_DESTROYPROPBLOB: u32 = 0xBE;
const MODE_CREATE_LEASE: u32 = 0xC6;
const MODE_CLOSEFB: u32 = 0xD0;

// Capabilities (drm.h DRM_CAP_*, DRM_CLIENT_CAP_*).
const CAP_DUMB_BUFFER: u64 = 0x1;
const CAP_VBLANK_HIGH_CRTC: u64 = 0x2;
const CAP_DUMB_PREFERRED_DEPTH: u64 = 0x3;
const CAP_DUMB_PREFER_SHADOW: u64 = 0x4;
const CAP_PRIME: u64 = 0x5;
const PRIME_CAP_IMPORT: u64 = 0x1;
const PRIME_CAP_EXPORT: u64 = 0x2;
const CAP_TIMESTAMP_MONOTONIC: u64 = 0x6;
const CAP_ASYNC_PAGE_FLIP: u64 = 0x7;
const CAP_CURSOR_WIDTH: u64 = 0x8;
const CAP_CURSOR_HEIGHT: u64 = 0x9;
const CAP_ADDFB2_MODIFIERS: u64 = 0x10;
const CAP_PAGE_FLIP_TARGET: u64 = 0x11;
const CAP_CRTC_IN_VBLANK_EVENT: u64 = 0x12;
const CAP_SYNCOBJ: u64 = 0x13;
const CAP_SYNCOBJ_TIMELINE: u64 = 0x14;
const CAP_ATOMIC_ASYNC_PAGE_FLIP: u64 = 0x15;
const CLIENT_CAP_STEREO_3D: u64 = 1;
const CLIENT_CAP_UNIVERSAL_PLANES: u64 = 2;
const CLIENT_CAP_ATOMIC: u64 = 3;
const CLIENT_CAP_ASPECT_RATIO: u64 = 4;
const CLIENT_CAP_WRITEBACK_CONNECTORS: u64 = 5;

// Mode-setting constants (drm_mode.h).
const DISPLAY_MODE_LEN: usize = 32;
const PROP_NAME_LEN: usize = 32;
const MODE_TYPE_PREFERRED: u32 = 1 << 3;
const MODE_TYPE_DRIVER: u32 = 1 << 6;
const MODE_FLAG_NHSYNC: u32 = 1 << 1;
const MODE_FLAG_NVSYNC: u32 = 1 << 3;
pub const CONNECTOR_UNKNOWN: u32 = 0;
pub const CONNECTOR_HDMIA: u32 = 11;
pub const CONNECTOR_VIRTUAL: u32 = 15;
const ENCODER_NONE: u32 = 0;
const ENCODER_TMDS: u32 = 2;
const ENCODER_VIRTUAL: u32 = 5;
const CONNECTED: u32 = 1;
const DISCONNECTED: u32 = 2;
const SUBPIXEL_UNKNOWN: u32 = 1;
const PROP_RANGE: u32 = 1 << 1;
const PROP_IMMUTABLE: u32 = 1 << 2;
const PROP_ENUM: u32 = 1 << 3;
const PROP_BLOB: u32 = 1 << 4;
/// DRM_MODE_PROP_TYPE(1) and (2): object and signed range properties.
const PROP_OBJECT: u32 = 1 << 6;
const PROP_SIGNED_RANGE: u32 = 2 << 6;
/// Shown only to clients that asked for atomic mode-setting.
const PROP_ATOMIC: u32 = 0x8000_0000;
const OBJECT_CRTC: u32 = 0xcccc_cccc;
const OBJECT_CONNECTOR: u32 = 0xc0c0_c0c0;
const OBJECT_ENCODER: u32 = 0xe0e0_e0e0;
const OBJECT_PLANE: u32 = 0xeeee_eeee;
const OBJECT_FB: u32 = 0xfbfb_fbfb;
const OBJECT_ANY: u32 = 0;
const MODE_FB_MODIFIERS: u32 = 1 << 1;
const PAGE_FLIP_EVENT: u32 = 0x01;
const PAGE_FLIP_ASYNC: u32 = 0x02;
const ATOMIC_TEST_ONLY: u32 = 0x0100;
const ATOMIC_NONBLOCK: u32 = 0x0200;
const ATOMIC_ALLOW_MODESET: u32 = 0x0400;
const ATOMIC_FLAGS: u32 = PAGE_FLIP_EVENT | PAGE_FLIP_ASYNC | ATOMIC_TEST_ONLY | ATOMIC_NONBLOCK | ATOMIC_ALLOW_MODESET;
const MODE_CURSOR_BO: u32 = 0x01;
const MODE_CURSOR_MOVE: u32 = 0x02;
const DPMS_ON: u64 = 0;
const DPMS_OFF: u64 = 3;
/// drm_event types (drm.h).
const EVENT_VBLANK: u32 = 0x01;
const EVENT_FLIP_COMPLETE: u32 = 0x02;
const EVENT_CRTC_SEQUENCE: u32 = 0x03;
// drm_wait_vblank's request type (drm.h).
const VBLANK_RELATIVE: u32 = 0x1;
const VBLANK_HIGH_CRTC_MASK: u32 = 0x3e;
const VBLANK_EVENT: u32 = 0x400_0000;
const VBLANK_FLIP: u32 = 0x800_0000;
const VBLANK_NEXTONMISS: u32 = 0x1000_0000;
const VBLANK_SECONDARY: u32 = 0x2000_0000;
const VBLANK_SIGNAL: u32 = 0x4000_0000;
// CRTC_QUEUE_SEQUENCE flags (drm.h).
const CRTC_SEQUENCE_RELATIVE: u32 = 0x1;
const CRTC_SEQUENCE_NEXT_ON_MISS: u32 = 0x2;

// Pixel formats (drm_fourcc.h): fourcc_code(a, b, c, d) is the four
// bytes little-endian.
const fn fourcc(s: &[u8; 4]) -> u32 {
    s[0] as u32 | (s[1] as u32) << 8 | (s[2] as u32) << 16 | (s[3] as u32) << 24
}
pub const FORMAT_XRGB8888: u32 = fourcc(b"XR24");
pub const FORMAT_ARGB8888: u32 = fourcc(b"AR24");
const FORMATS: [u32; 2] = [FORMAT_XRGB8888, FORMAT_ARGB8888];
const CURSOR_FORMATS: [u32; 1] = [FORMAT_ARGB8888];
/// DRM_FORMAT_MOD_LINEAR (drm_fourcc.h: fourcc_mod_code(NONE, 0)).
const MOD_LINEAR: u64 = 0;
/// The cursor plane's largest image (CAP_CURSOR_WIDTH and HEIGHT).
pub const CURSOR_SIZE: u32 = 64;

/// Most outputs a card has.
pub const MAX_OUTPUTS: usize = 16;

// Object IDs: each output's CRTC, encoder, connector, primary and cursor
// planes; then framebuffers, connectors' EDID blobs and other blobs.
const OBJ_BASE: u32 = 32;
const OBJ_STRIDE: u32 = 8;
const FIRST_FB: u32 = 0x1000;
const EDID_BLOB: u32 = 0x8000;
const FIRST_BLOB: u32 = 0x10000;

fn crtc_id(i: usize) -> u32 {
    OBJ_BASE + OBJ_STRIDE * i as u32
}
fn encoder_id(i: usize) -> u32 {
    crtc_id(i) + 1
}
fn connector_id(i: usize) -> u32 {
    crtc_id(i) + 2
}
fn primary_id(i: usize) -> u32 {
    crtc_id(i) + 3
}
fn cursor_id(i: usize) -> u32 {
    crtc_id(i) + 4
}
fn overlay_id(i: usize) -> u32 {
    crtc_id(i) + 5
}

/// A mode-setting object of output `.1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Obj {
    Crtc(usize),
    Encoder(usize),
    Connector(usize),
    Primary(usize),
    Cursor(usize),
    Overlay(usize),
}

impl Obj {
    fn output(self) -> usize {
        match self {
            Obj::Crtc(i) | Obj::Encoder(i) | Obj::Connector(i) | Obj::Primary(i) | Obj::Cursor(i) | Obj::Overlay(i) => {
                i
            }
        }
    }

    fn kind(self) -> u32 {
        match self {
            Obj::Crtc(_) => OBJECT_CRTC,
            Obj::Encoder(_) => OBJECT_ENCODER,
            Obj::Connector(_) => OBJECT_CONNECTOR,
            Obj::Primary(_) | Obj::Cursor(_) | Obj::Overlay(_) => OBJECT_PLANE,
        }
    }
}

// Property IDs.
const PROP_TYPE: u32 = 1;
const PROP_DPMS: u32 = 2;
const PROP_EDID: u32 = 3;
const PROP_CRTC_ID: u32 = 4;
const PROP_FB_ID: u32 = 5;
const PROP_SRC_X: u32 = 6;
const PROP_SRC_Y: u32 = 7;
const PROP_SRC_W: u32 = 8;
const PROP_SRC_H: u32 = 9;
const PROP_CRTC_X: u32 = 10;
const PROP_CRTC_Y: u32 = 11;
const PROP_CRTC_W: u32 = 12;
const PROP_CRTC_H: u32 = 13;
const PROP_ACTIVE: u32 = 14;
const PROP_MODE_ID: u32 = 15;
const PROP_GAMMA_LUT: u32 = 16;
const PROP_GAMMA_LUT_SIZE: u32 = 17;
/// Planes' "type" (DRM KMS documentation, plane properties: the enum
/// Overlay, Primary, Cursor).
const PLANE_TYPE_OVERLAY: u64 = 0;
const PLANE_TYPE_PRIMARY: u64 = 1;
const PLANE_TYPE_CURSOR: u64 = 2;

/// What one output of a display offers now.
#[derive(Clone, Debug, Default)]
pub struct OutputInfo {
    pub connected: bool,
    /// Width, height and refresh rate; the preferred one first.
    pub modes: Vec<(u32, u32, u32)>,
    /// Physical size in millimetres (0 if unknown).
    pub size_mm: (u32, u32),
    /// The display's own EDID, if it has one.
    pub edid: Option<Vec<u8>>,
}

/// A cursor image: ARGB8888 pixels (premultiplied alpha, row after row),
/// at most [`CURSOR_SIZE`] square, and its hotspot (CURSOR2).
#[derive(Clone, Debug)]
pub struct CursorImage {
    pub pixels: Vec<u32>,
    pub width: u32,
    pub height: u32,
    pub hot: (i32, i32),
}

/// What an output's overlay plane shows: the part of `fb` from `src`
/// (its top left pixel), `size` pixels, unscaled, with its top left corner
/// at `at` on the screen; only the part on the screen.
#[derive(Clone, Debug)]
pub struct Overlay {
    pub fb: Arc<Framebuffer>,
    pub src: (u32, u32),
    pub size: (u32, u32),
    pub at: (u32, u32),
}

/// The display hardware behind a card.
pub trait Display: Send + Sync {
    /// The driver name drmGetVersion reports.
    fn driver(&self) -> &'static str;
    fn description(&self) -> &'static str;
    /// How many outputs (CRTCs and connectors) the card has; fixed.
    fn outputs(&self) -> usize {
        1
    }
    /// Output `out`'s connection, modes and size now.
    fn output(&self, out: usize) -> OutputInfo;
    fn connector_type(&self) -> u32;
    /// Show framebuffer `fb` on output `out` in a `mode` (width, height).
    fn present(&self, out: usize, fb: &Arc<Framebuffer>, mode: (u32, u32));
    /// Show only the rectangle `cols` × `rows` of `fb` changed (one
    /// DIRTYFB clip) on output `out`; by default all of it.
    fn present_rect(
        &self,
        out: usize,
        fb: &Arc<Framebuffer>,
        cols: core::ops::Range<u32>,
        rows: core::ops::Range<u32>,
    ) {
        let _ = (cols, rows);
        self.present(out, fb, (fb.width, fb.height));
    }
    /// Output `out` shows nothing (its CRTC is off, DPMS is off, or its
    /// primary plane has no framebuffer).
    fn blank(&self, _out: usize) {}
    /// The cursor image of output `out`, or none.
    fn cursor(&self, _out: usize, _image: Option<CursorImage>) {}
    /// Where the cursor image's top left corner is on output `out`.
    fn move_cursor(&self, _out: usize, _x: i32, _y: i32) {}
    /// Whether each output has an overlay plane (above the primary,
    /// below the cursor).
    fn overlays(&self) -> bool {
        false
    }
    /// What output `out`'s overlay plane shows, or nothing.
    fn overlay(&self, _out: usize, _plane: Option<Overlay>) {}
    /// Only the rectangle `cols` × `rows` of the overlay's framebuffer
    /// `fb` changed (in its own pixels; a DIRTYFB clip).
    fn overlay_rect(
        &self,
        _out: usize,
        _fb: &Arc<Framebuffer>,
        _cols: core::ops::Range<u32>,
        _rows: core::ops::Range<u32>,
    ) {
    }
    /// Entries in each output's gamma table (0: no gamma).
    fn gamma_size(&self) -> u32 {
        0
    }
    /// Output `out`'s gamma table (red, green, blue), or the identity.
    fn set_gamma(&self, _out: usize, _lut: Option<Vec<[u16; 3]>>) {}
    /// When output `out`'s last vertical blank began (monotonic
    /// nanoseconds) and its frame's length, for a display that knows
    /// (else the DRM's clock counts from when the CRTC came on).
    fn vblank(&self, _out: usize) -> Option<(u64, u64)> {
        None
    }
    /// The card's 2D requests, if it does them ([`twod`]).
    fn twod(&self) -> Option<&dyn twod::TwoD> {
        None
    }
    /// The master let go of the screen.
    fn release(&self) {}
    /// Framebuffer `id` is gone (RMFB, or its file closed).
    fn forget(&self, _id: u32) {}
}

/// A dumb buffer: zeroed user frames, refcounted so mappings keep them.
#[derive(Debug)]
pub struct Buffer {
    id: u64,
    frames: Vec<PhysAddr>,
    pub size: u64,
    pub pitch: u32,
}

impl Drop for Buffer {
    fn drop(&mut self) {
        for f in &self.frames {
            frame::put_user_page(*f);
        }
    }
}

impl Buffer {
    /// Copy `out.len()` bytes from byte `offset` of the buffer.
    pub fn read(&self, offset: u64, out: &mut [u8]) {
        let mut done = 0;
        while done < out.len() {
            let at = offset + done as u64;
            let page = (at / PAGE_SIZE) as usize;
            let Some(f) = self.frames.get(page) else { break };
            let within = (at % PAGE_SIZE) as usize;
            let n = (PAGE_SIZE as usize - within).min(out.len() - done);
            // SAFETY: The frame is ours (refcounted) and in the direct map.
            unsafe { core::ptr::copy_nonoverlapping(f.to_virt().add(within), out[done..].as_mut_ptr(), n) };
            done += n;
        }
    }

    /// The frames, for drivers that hand them to a device.
    pub fn frames(&self) -> &[PhysAddr] {
        &self.frames
    }
}

static NEXT_BUFFER: AtomicU64 = AtomicU64::new(1);

fn new_buffer(width: u32, height: u32, bpp: u32) -> Result<Arc<Buffer>> {
    if width == 0 || height == 0 || width > 16384 || height > 16384 || bpp == 0 || bpp > 32 {
        return Err(EINVAL);
    }
    let pitch = (width * bpp.div_ceil(8)).next_multiple_of(64);
    let size = (u64::from(pitch) * u64::from(height)).next_multiple_of(PAGE_SIZE);
    let mut frames = Vec::with_capacity((size / PAGE_SIZE) as usize);
    for _ in 0..size / PAGE_SIZE {
        match frame::alloc_user_page() {
            Some(f) => frames.push(f),
            None => {
                for f in frames {
                    frame::put_user_page(f);
                }
                return Err(ENOMEM);
            }
        }
    }
    let id = NEXT_BUFFER.fetch_add(1, Ordering::Relaxed);
    Ok(Arc::new(Buffer { id, frames, size, pitch }))
}

/// A framebuffer: a buffer seen as an image.
#[derive(Debug)]
pub struct Framebuffer {
    pub id: u32,
    pub buffer: Arc<Buffer>,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub offset: u32,
    pub format: u32,
    /// The file that made it (removed when it closes).
    owner: u64,
}

impl Framebuffer {
    /// The image as a cursor: `w` × `h` pixels from its top left.
    fn cursor_image(&self, w: u32, h: u32, hot: (i32, i32)) -> CursorImage {
        let mut pixels = alloc::vec![0u32; (w * h) as usize];
        let mut row = alloc::vec![0u8; w as usize * 4];
        for y in 0..h {
            self.buffer.read(u64::from(self.offset) + u64::from(y) * u64::from(self.pitch), &mut row);
            for x in 0..w as usize {
                pixels[(y * w) as usize + x] =
                    u32::from_le_bytes([row[x * 4], row[x * 4 + 1], row[x * 4 + 2], row[x * 4 + 3]]);
            }
        }
        CursorImage { pixels, width: w, height: h, hot }
    }
}

/// A plane's state: its framebuffer, whether it is on its CRTC (CRTC_ID),
/// the source rectangle (16.16 fixed point) and where it goes.
#[derive(Clone, Default)]
struct Plane {
    fb: Option<Arc<Framebuffer>>,
    on: bool,
    src: [u32; 4],
    dst: [i64; 4],
    /// The cursor's hotspot (CURSOR2).
    hot: (i32, i32),
}

impl Plane {
    fn same_fb(&self, o: &Plane) -> bool {
        match (&self.fb, &o.fb) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        }
    }
}

/// An output's mode-setting state: what a commit replaces.
#[derive(Clone, Default)]
struct OutState {
    active: bool,
    mode: Option<ModeInfo>,
    /// The MODE_ID blob (0: set by a legacy call, or none).
    mode_blob: u32,
    /// The connector is routed to the CRTC (its CRTC_ID).
    linked: bool,
    primary: Plane,
    cursor: Plane,
    overlay: Plane,
    gamma_blob: u32,
    gamma: Option<Vec<[u16; 3]>>,
    dpms: u64,
}

impl OutState {
    fn mode_size(&self) -> (u32, u32) {
        self.mode.map_or((0, 0), |m| (u32::from(m.hdisplay), u32::from(m.vdisplay)))
    }

    fn shows(&self) -> bool {
        self.active && self.dpms == DPMS_ON
    }

    /// The overlay plane's part on the screen, if it shows one.
    fn overlay_shown(&self) -> Option<Overlay> {
        let p = &self.overlay;
        let fb = p.fb.as_ref().filter(|_| p.on && self.shows())?;
        let (w, h) = self.mode_size();
        let (x0, y0) = (p.dst[0].max(0), p.dst[1].max(0));
        let (x1, y1) = ((p.dst[0] + p.dst[2]).min(i64::from(w)), (p.dst[1] + p.dst[3]).min(i64::from(h)));
        if x0 >= x1 || y0 >= y1 {
            return None;
        }
        let src = ((p.src[0] >> 16) + (x0 - p.dst[0]) as u32, (p.src[1] >> 16) + (y0 - p.dst[1]) as u32);
        Some(Overlay { fb: fb.clone(), src, size: ((x1 - x0) as u32, (y1 - y0) as u32), at: (x0 as u32, y0 as u32) })
    }
}

/// An output: its state, a flip waiting for its vblank, and its vblank
/// clock (vblank `n` is at `epoch + n * period`).
struct Output {
    st: OutState,
    flip_pending: bool,
    epoch: u64,
    period: u64,
}

impl Output {
    /// The vblanks counted by `now` (0 before the CRTC is on).
    fn count(&self, now: u64) -> u64 {
        now.saturating_sub(self.epoch).checked_div(self.period).unwrap_or(0)
    }

    /// When vblank `n` is.
    fn at(&self, n: u64) -> u64 {
        self.epoch + n * self.period
    }
}

struct State {
    fbs: BTreeMap<u32, Arc<Framebuffer>>,
    next_fb: u32,
    outputs: Vec<Output>,
    master: Option<u64>,
    blobs: BTreeMap<u32, Arc<Vec<u8>>>,
    next_blob: u32,
    /// 2D images ([`twod`]): the file that made each.
    images: BTreeMap<u32, (u64, Arc<twod::Image>)>,
    next_image: u32,
}

/// A display card.
pub struct Device {
    pub minor: u32,
    display: Box<dyn Display>,
    state: IrqSpinLock<State>,
    /// The card under /sys (for its uevents).
    devpath: String,
    /// Its open files, for authentication.
    files: IrqSpinLock<Vec<Weak<DrmFile>>>,
    /// Woken when a flip completes.
    flips: WaitQueue,
}

static DEVICES: IrqSpinLock<Vec<Arc<Device>>> = IrqSpinLock::new(Vec::new());

/// Add a display; returns its card number. `sys_device` is its device
/// directory under /sys (`devices/platform/simple-framebuffer.0`) and
/// `subsystem` the bus it hangs on ("platform", "pci").
pub fn register(display: Box<dyn Display>, sys_device: &str, subsystem: &str) -> u32 {
    let mut devs = DEVICES.lock();
    let minor = devs.len() as u32;
    let n = display.outputs().clamp(1, MAX_OUTPUTS);
    let modes: Vec<String> = (0..n)
        .map(|i| match display.output(i).modes.first() {
            Some((w, h, hz)) => alloc::format!("{w}x{h}@{hz}"),
            None => String::from("off"),
        })
        .collect();
    crate::log_info!("drm: card{minor}: {} {}", display.driver(), modes.join(", "));
    let card = alloc::format!("card{minor}");
    let dir = alloc::format!("{sys_device}/drm/{card}");
    let outputs =
        (0..n).map(|_| Output { st: OutState::default(), flip_pending: false, epoch: 0, period: 0 }).collect();
    devs.push(Arc::new(Device {
        minor,
        display,
        state: IrqSpinLock::new(State {
            fbs: BTreeMap::new(),
            next_fb: FIRST_FB,
            outputs,
            master: None,
            blobs: BTreeMap::new(),
            next_blob: FIRST_BLOB,
            images: BTreeMap::new(),
            next_image: 0,
        }),
        devpath: alloc::format!("/{dir}"),
        files: IrqSpinLock::new(Vec::new()),
        flips: WaitQueue::new(),
    }));
    drop(devs);
    let rdev = vfs::makedev(DRM_MAJOR, minor);
    let up = "../../../../..";
    let mut sys = alloc::vec![
        SysEntry::File(alloc::format!("{dir}/dev"), alloc::format!("{DRM_MAJOR}:{minor}\n")),
        SysEntry::File(
            alloc::format!("{dir}/uevent"),
            alloc::format!("MAJOR={DRM_MAJOR}\nMINOR={minor}\nDEVNAME=dri/{card}\nDEVTYPE=drm_minor\n"),
        ),
        SysEntry::Link(alloc::format!("{dir}/subsystem"), alloc::format!("{up}/class/drm")),
        SysEntry::Link(alloc::format!("{dir}/device"), String::from("../..")),
        SysEntry::Link(alloc::format!("{sys_device}/subsystem"), alloc::format!("../../../bus/{subsystem}")),
        SysEntry::Dir(alloc::format!("bus/{subsystem}/devices")),
        SysEntry::Link(alloc::format!("class/drm/{card}"), alloc::format!("../../{dir}")),
        SysEntry::Link(alloc::format!("dev/char/{DRM_MAJOR}:{minor}"), alloc::format!("../../{dir}")),
    ];
    sys.extend(connector_entries(minor, &dir, n));
    crate::fs::char_added(CharNode { dev: alloc::format!("dri/{card}"), rdev, mode: 0o660, sys });
    minor
}

/// A connector type's name in /sys (`card0-Virtual-1`): the names
/// drmModeGetConnectorTypeName gives (libdrm's manual).
fn connector_type_name(t: u32) -> &'static str {
    match t {
        CONNECTOR_VIRTUAL => "Virtual",
        CONNECTOR_HDMIA => "HDMI-A",
        _ => "Unknown",
    }
}

/// Each output's connector directory under its card, as Linux has them
/// (observed on the host: `card1/card1-HDMI-A-2/` with `status`
/// "connected", "disconnected" or "unknown"; `enabled` "enabled" or
/// "disabled"; `modes`, one `WxH` a line, the preferred first; `edid`, the
/// display's EDID), read as they are now.
fn connector_entries(minor: u32, dir: &str, outputs: usize) -> Vec<SysEntry> {
    let kind = device(minor).map_or("Unknown", |d| connector_type_name(d.display.connector_type()));
    let mut out = Vec::new();
    for i in 0..outputs {
        let name = alloc::format!("card{minor}-{kind}-{}", i + 1);
        let at = alloc::format!("{dir}/{name}");
        let live = |make: fn(&Device, usize, &OutputInfo, &mut Vec<u8>)| -> crate::fs::tmpfs::Generator {
            Arc::new(move |buf: &mut Vec<u8>| {
                if let Ok(dev) = device(minor) {
                    let info = dev.display.output(i);
                    make(&dev, i, &info, buf);
                }
            })
        };
        out.push(SysEntry::Dir(at.clone()));
        out.push(SysEntry::Generated(
            alloc::format!("{at}/status"),
            live(|_, _, info, buf| {
                buf.extend_from_slice(if info.connected { b"connected\n" } else { b"disconnected\n" })
            }),
        ));
        out.push(SysEntry::Generated(
            alloc::format!("{at}/enabled"),
            live(|dev, i, _, buf| {
                let on = dev.state.lock().outputs.get(i).is_some_and(|o| o.st.active && o.st.linked);
                buf.extend_from_slice(if on { b"enabled\n" } else { b"disabled\n" });
            }),
        ));
        out.push(SysEntry::Generated(
            alloc::format!("{at}/modes"),
            live(|_, _, info, buf| {
                if info.connected {
                    for (w, h, _) in &info.modes {
                        buf.extend_from_slice(alloc::format!("{w}x{h}\n").as_bytes());
                    }
                }
            }),
        ));
        out.push(SysEntry::Generated(
            alloc::format!("{at}/edid"),
            live(|dev, i, info, buf| {
                if info.connected {
                    buf.extend_from_slice(&info.edid.clone().unwrap_or_else(|| made_edid(dev, i, info)));
                }
            }),
        ));
        out.push(SysEntry::Link(alloc::format!("{at}/device"), String::from("..")));
        out.push(SysEntry::Link(alloc::format!("{at}/subsystem"), String::from("../../../../../../class/drm")));
        out.push(SysEntry::Link(alloc::format!("class/drm/{name}"), alloc::format!("../../{dir}/{name}")));
    }
    out
}

/// The displays of card `minor` changed (connected, resized): tell user
/// space with a "change" uevent carrying HOTPLUG=1, as compositors expect
/// (the DRM uAPI documentation's connector hotplug).
pub fn hotplug(minor: u32) {
    let Ok(dev) = device(minor) else { return };
    crate::log_info!("drm: card{minor}: displays changed");
    let env = [
        String::from("SUBSYSTEM=drm"),
        alloc::format!("MAJOR={DRM_MAJOR}"),
        alloc::format!("MINOR={minor}"),
        alloc::format!("DEVNAME=dri/card{minor}"),
        String::from("DEVTYPE=drm_minor"),
        String::from("HOTPLUG=1"),
    ];
    crate::net::uevent::announce("change", &dev.devpath, &env);
}

fn device(minor: u32) -> Result<Arc<Device>> {
    DEVICES.lock().get(minor as usize).cloned().ok_or(ENXIO)
}

static NEXT_FILE: AtomicU64 = AtomicU64::new(1);

/// Open card `minor`.
pub fn open(minor: u32, flags: u32) -> Result<Arc<dyn File>> {
    let dev = device(minor)?;
    let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
    // The first opener becomes master, as on Linux.
    {
        let mut st = dev.state.lock();
        if st.master.is_none() {
            st.master = Some(id);
        }
    }
    Ok(new_file(id, dev, flags, false))
}

fn new_file(id: u64, dev: Arc<Device>, flags: u32, lessee: bool) -> Arc<DrmFile> {
    let f = Arc::new(DrmFile {
        id,
        dev: dev.clone(),
        lessee,
        flags: AtomicU32::new(flags),
        universal: AtomicBool::new(false),
        atomic: AtomicBool::new(false),
        authenticated: AtomicBool::new(lessee),
        inner: Arc::new(IrqSpinLock::new(FileState { handles: BTreeMap::new(), next_handle: 1 })),
        events: Arc::new(Events {
            list: IrqSpinLock::new(VecDeque::new()),
            queue: WaitQueue::new(),
            count: AtomicU64::new(0),
        }),
    });
    let mut files = dev.files.lock();
    files.retain(|w| w.strong_count() > 0);
    files.push(Arc::downgrade(&f));
    f
}

struct FileState {
    handles: BTreeMap<u32, Arc<Buffer>>,
    next_handle: u32,
}

/// A file's pending events (flips, vblanks), shared with the timers that
/// deliver them.
struct Events {
    list: IrqSpinLock<VecDeque<Vec<u8>>>,
    queue: WaitQueue,
    count: AtomicU64,
}

impl Events {
    fn push(&self, ev: Vec<u8>) {
        self.list.lock().push_back(ev);
        self.count.fetch_add(1, Ordering::Release);
        self.queue.wake_all();
        crate::fs::poll_notify();
    }
}

/// `struct drm_event_vblank` (drm.h): the event's type and length, the
/// caller's data, the vblank's time, its number and the CRTC.
fn vblank_event(kind: u32, user_data: u64, ns: u64, seq: u64, crtc: u32) -> Vec<u8> {
    let mut ev = Vec::with_capacity(32);
    ev.extend_from_slice(&kind.to_le_bytes());
    ev.extend_from_slice(&32u32.to_le_bytes());
    ev.extend_from_slice(&user_data.to_le_bytes());
    ev.extend_from_slice(&((ns / 1_000_000_000) as u32).to_le_bytes());
    ev.extend_from_slice(&((ns % 1_000_000_000 / 1000) as u32).to_le_bytes());
    ev.extend_from_slice(&(seq as u32).to_le_bytes());
    ev.extend_from_slice(&crtc.to_le_bytes());
    ev
}

/// `struct drm_event_crtc_sequence` (drm.h): type, length, the caller's
/// data, the time in nanoseconds and the 64-bit sequence.
fn sequence_event(user_data: u64, ns: u64, seq: u64) -> Vec<u8> {
    let mut ev = Vec::with_capacity(32);
    ev.extend_from_slice(&EVENT_CRTC_SEQUENCE.to_le_bytes());
    ev.extend_from_slice(&32u32.to_le_bytes());
    ev.extend_from_slice(&user_data.to_le_bytes());
    ev.extend_from_slice(&ns.to_le_bytes());
    ev.extend_from_slice(&seq.to_le_bytes());
    ev
}

/// An open card.
struct DrmFile {
    id: u64,
    dev: Arc<Device>,
    /// Made by CREATE_LEASE: the master of an empty lease, which holds
    /// no mode-setting objects but may make and share buffers.
    lessee: bool,
    flags: AtomicU32,
    /// The client asked for universal planes and for atomic.
    universal: AtomicBool,
    atomic: AtomicBool,
    /// The master authenticated this file's magic (AUTH_MAGIC).
    authenticated: AtomicBool,
    inner: Arc<IrqSpinLock<FileState>>,
    events: Arc<Events>,
}

impl Drop for DrmFile {
    fn drop(&mut self) {
        let images_gone;
        let (release, gone) = {
            let mut st = self.dev.state.lock();
            let gone: Vec<u32> = st.fbs.values().filter(|fb| fb.owner == self.id).map(|fb| fb.id).collect();
            st.fbs.retain(|_, fb| fb.owner != self.id);
            let images: Vec<u32> = st.images.iter().filter(|(_, (o, _))| *o == self.id).map(|(id, _)| *id).collect();
            st.images.retain(|_, (o, _)| *o != self.id);
            images_gone = images;
            let master = st.master == Some(self.id);
            if master {
                st.master = None;
                reset(&mut st);
            }
            (master, gone)
        };
        for id in gone {
            self.dev.display.forget(id);
        }
        if let Some(t) = self.dev.display.twod() {
            for id in images_gone {
                t.free(id);
            }
        }
        if release {
            self.dev.display.release();
        }
    }
}

/// Every output off, as when the master goes.
fn reset(st: &mut State) {
    for o in &mut st.outputs {
        o.st = OutState::default();
        o.flip_pending = false;
        o.period = 0;
    }
}

/// A user structure read in, changed and written back.
fn rw<T: Copy + Default>(arg: u64, f: impl FnOnce(&mut T) -> Result<u64>) -> Result<u64> {
    let mut v: T = read_user(arg).map_err(|_| EFAULT)?;
    let r = f(&mut v)?;
    write_user(arg, &v).map_err(|_| EFAULT)?;
    Ok(r)
}

/// Copy `items` to a user array of `*count` entries at `ptr` (if it has
/// room) and report how many there are, as the DRM get-calls do.
fn put_array<T: Copy>(ptr: u64, count: &mut u32, items: &[T]) -> Result<()> {
    if *count as usize >= items.len() && ptr != 0 {
        for (i, it) in items.iter().enumerate() {
            write_user(ptr + (i * size_of::<T>()) as u64, it).map_err(|_| EFAULT)?;
        }
    }
    *count = items.len() as u32;
    Ok(())
}

/// Copy a string into a user buffer of `*len` bytes and report its length.
fn put_string(ptr: u64, len: &mut u64, s: &str) -> Result<()> {
    let n = s.len().min(*len as usize);
    if ptr != 0 && n > 0 {
        copy_to_user(ptr, &s.as_bytes()[..n]).map_err(|_| EFAULT)?;
    }
    *len = s.len() as u64;
    Ok(())
}

fn name_bytes<const N: usize>(s: &str) -> [u8; N] {
    let mut b = [0u8; N];
    let n = s.len().min(N - 1);
    b[..n].copy_from_slice(&s.as_bytes()[..n]);
    b
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Version {
    major: i32,
    minor: i32,
    patch: i32,
    name_len: u64,
    name: u64,
    date_len: u64,
    date: u64,
    desc_len: u64,
    desc: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Unique {
    len: u64,
    ptr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Cap {
    cap: u64,
    value: u64,
}

/// `struct drm_mode_create_lease` (drm_mode.h).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CreateLease {
    object_ids: u64,
    object_count: u32,
    flags: u32,
    lessee_id: u32,
    fd: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct GemClose {
    handle: u32,
    pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PrimeHandle {
    handle: u32,
    flags: u32,
    fd: i32,
}

/// `struct drm_mode_modeinfo` (drm_mode.h), also a MODE_ID blob's
/// contents.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct ModeInfo {
    clock: u32,
    hdisplay: u16,
    hsync_start: u16,
    hsync_end: u16,
    htotal: u16,
    hskew: u16,
    vdisplay: u16,
    vsync_start: u16,
    vsync_end: u16,
    vtotal: u16,
    vscan: u16,
    vrefresh: u32,
    flags: u32,
    kind: u32,
    name: [u8; DISPLAY_MODE_LEN],
}

impl Default for ModeInfo {
    fn default() -> ModeInfo {
        // SAFETY: All-zero is a valid ModeInfo (integers and bytes).
        unsafe { core::mem::zeroed() }
    }
}

impl ModeInfo {
    fn from_bytes(b: &[u8]) -> Option<ModeInfo> {
        if b.len() != size_of::<ModeInfo>() {
            return None;
        }
        // SAFETY: The length matches and every bit pattern is a valid
        // ModeInfo (integers and bytes); the read is unaligned.
        Some(unsafe { core::ptr::read_unaligned(b.as_ptr() as *const ModeInfo) })
    }

    /// The refresh rate: as given, or from the timings.
    fn refresh(&self) -> u32 {
        let frame = u32::from(self.htotal) * u32::from(self.vtotal);
        if self.vrefresh != 0 {
            self.vrefresh
        } else if frame != 0 {
            (self.clock * 1000).div_ceil(frame)
        } else {
            60
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CardRes {
    fb_ptr: u64,
    crtc_ptr: u64,
    connector_ptr: u64,
    encoder_ptr: u64,
    count_fbs: u32,
    count_crtcs: u32,
    count_connectors: u32,
    count_encoders: u32,
    min_width: u32,
    max_width: u32,
    min_height: u32,
    max_height: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Crtc {
    set_connectors_ptr: u64,
    count_connectors: u32,
    crtc_id: u32,
    fb_id: u32,
    x: u32,
    y: u32,
    gamma_size: u32,
    mode_valid: u32,
    mode: ModeInfo,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct GetEncoder {
    encoder_id: u32,
    encoder_type: u32,
    crtc_id: u32,
    possible_crtcs: u32,
    possible_clones: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct GetConnector {
    encoders_ptr: u64,
    modes_ptr: u64,
    props_ptr: u64,
    prop_values_ptr: u64,
    count_modes: u32,
    count_props: u32,
    count_encoders: u32,
    encoder_id: u32,
    connector_id: u32,
    connector_type: u32,
    connector_type_id: u32,
    connection: u32,
    mm_width: u32,
    mm_height: u32,
    subpixel: u32,
    pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PropEnum {
    value: u64,
    name: [u8; PROP_NAME_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct GetProperty {
    values_ptr: u64,
    enum_blob_ptr: u64,
    prop_id: u32,
    flags: u32,
    name: [u8; PROP_NAME_LEN],
    count_values: u32,
    count_enum_blobs: u32,
}

impl Default for GetProperty {
    fn default() -> GetProperty {
        // SAFETY: All-zero is a valid GetProperty (integers and bytes).
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ConnectorSetProperty {
    value: u64,
    prop_id: u32,
    connector_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ObjGetProperties {
    props_ptr: u64,
    prop_values_ptr: u64,
    count_props: u32,
    obj_id: u32,
    obj_type: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ObjSetProperty {
    value: u64,
    prop_id: u32,
    obj_id: u32,
    obj_type: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct GetBlob {
    blob_id: u32,
    length: u32,
    data: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FbCmd {
    fb_id: u32,
    width: u32,
    height: u32,
    pitch: u32,
    bpp: u32,
    depth: u32,
    handle: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FbCmd2 {
    fb_id: u32,
    width: u32,
    height: u32,
    pixel_format: u32,
    flags: u32,
    handles: [u32; 4],
    pitches: [u32; 4],
    offsets: [u32; 4],
    modifier: [u64; 4],
}

/// `struct drm_mode_cursor2` (drm_mode.h); `drm_mode_cursor` is the same
/// without the hotspot.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Cursor {
    flags: u32,
    crtc_id: u32,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    handle: u32,
    hot_x: i32,
    hot_y: i32,
}

/// `struct drm_mode_closefb` (drm_mode.h).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CloseFb {
    fb_id: u32,
    pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PageFlip {
    crtc_id: u32,
    fb_id: u32,
    flags: u32,
    reserved: u32,
    user_data: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CreateDumb {
    height: u32,
    width: u32,
    bpp: u32,
    flags: u32,
    handle: u32,
    pitch: u32,
    size: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MapDumb {
    handle: u32,
    pad: u32,
    offset: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PlaneRes {
    plane_ptr: u64,
    count_planes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct GetPlane {
    plane_id: u32,
    crtc_id: u32,
    fb_id: u32,
    possible_crtcs: u32,
    gamma_size: u32,
    count_format_types: u32,
    format_type_ptr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SetPlane {
    plane_id: u32,
    crtc_id: u32,
    fb_id: u32,
    flags: u32,
    crtc_x: i32,
    crtc_y: i32,
    crtc_w: u32,
    crtc_h: u32,
    src_x: u32,
    src_y: u32,
    src_h: u32,
    src_w: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CreateBlob {
    data: u64,
    length: u32,
    blob_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DirtyFb {
    fb_id: u32,
    flags: u32,
    color: u32,
    num_clips: u32,
    clips_ptr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CrtcLut {
    crtc_id: u32,
    gamma_size: u32,
    red: u64,
    green: u64,
    blue: u64,
}

/// `struct drm_mode_atomic` (drm_mode.h).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct AtomicReq {
    flags: u32,
    count_objs: u32,
    objs_ptr: u64,
    count_props_ptr: u64,
    props_ptr: u64,
    prop_values_ptr: u64,
    reserved: u64,
    user_data: u64,
}

/// `union drm_wait_vblank` (drm.h): a request (type, sequence, signal)
/// read in, a reply (type, sequence, seconds, microseconds) written back.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct WaitVblank {
    kind: u32,
    sequence: u32,
    a: i64,
    b: i64,
}

/// `struct drm_crtc_get_sequence` (drm.h).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct GetSequence {
    crtc_id: u32,
    active: u32,
    sequence: u64,
    sequence_ns: i64,
}

/// `struct drm_crtc_queue_sequence` (drm.h).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct QueueSequence {
    crtc_id: u32,
    flags: u32,
    sequence: u64,
    user_data: u64,
}

/// A mode of `w` × `h` at `hz`, with plausible blanking for a panel.
fn mode_info(w: u32, h: u32, hz: u32, preferred: bool) -> ModeInfo {
    let (hs, he, ht) = (w + 48, w + 80, w + 160);
    let (vs, ve, vt) = (h + 3, h + 9, h + 30);
    ModeInfo {
        clock: ht * vt * hz / 1000,
        hdisplay: w as u16,
        hsync_start: hs as u16,
        hsync_end: he as u16,
        htotal: ht as u16,
        hskew: 0,
        vdisplay: h as u16,
        vsync_start: vs as u16,
        vsync_end: ve as u16,
        vtotal: vt as u16,
        vscan: 0,
        vrefresh: hz,
        flags: MODE_FLAG_NHSYNC | MODE_FLAG_NVSYNC,
        kind: if preferred { MODE_TYPE_PREFERRED | MODE_TYPE_DRIVER } else { MODE_TYPE_DRIVER },
        name: name_bytes(&alloc::format!("{w}x{h}")),
    }
}

/// An EDID for an output that has none of its own (slate-edid, ADR 0100).
fn made_edid(dev: &Device, out: usize, info: &OutputInfo) -> Vec<u8> {
    let m = info.modes.first().map_or(mode_info(1024, 768, 60, true), |&(w, h, hz)| mode_info(w, h, hz, true));
    let name = alloc::format!("{} {}", dev.display.driver(), out + 1);
    let d = slate_edid::Display {
        vendor: *b"SLT",
        product: dev.minor as u16,
        serial: out as u32 + 1,
        year: 2026,
        name: &name,
        size_mm: info.size_mm,
        timing: slate_edid::Timing {
            clock_khz: m.clock,
            hactive: m.hdisplay.into(),
            hsync_start: m.hsync_start.into(),
            hsync_end: m.hsync_end.into(),
            htotal: m.htotal.into(),
            vactive: m.vdisplay.into(),
            vsync_start: m.vsync_start.into(),
            vsync_end: m.vsync_end.into(),
            vtotal: m.vtotal.into(),
            hsync_positive: false,
            vsync_positive: false,
        },
    };
    slate_edid::build(&d).to_vec()
}

/// The identity gamma table of `n` entries.
fn identity_gamma(n: u32) -> Vec<[u16; 3]> {
    (0..n).map(|i| [(i * 0xFFFF / (n - 1).max(1)) as u16; 3]).collect()
}

/// A GAMMA_LUT blob's entries (`struct drm_color_lut`: red, green, blue,
/// reserved, each 16 bits).
fn gamma_from_blob(b: &[u8]) -> Vec<[u16; 3]> {
    b.as_chunks::<8>()
        .0
        .iter()
        .map(|c| {
            let v = |i: usize| u16::from_le_bytes([c[i], c[i + 1]]);
            [v(0), v(2), v(4)]
        })
        .collect()
}

/// What a commit changed on an output, to do once the state is in place.
#[derive(Default)]
struct Work {
    present: Option<(Arc<Framebuffer>, (u32, u32))>,
    blank: bool,
    cursor: Option<Option<CursorImage>>,
    cursor_at: Option<(i32, i32)>,
    gamma: Option<Option<Vec<[u16; 3]>>>,
    overlay: Option<Option<Overlay>>,
}

impl DrmFile {
    fn is_master(&self) -> bool {
        self.dev.state.lock().master == Some(self.id)
    }

    fn need_master(&self) -> Result<()> {
        if self.is_master() { Ok(()) } else { Err(EACCES) }
    }

    /// The master, its lessees and the files it authenticated.
    fn trusted(&self) -> bool {
        self.authenticated.load(Ordering::Relaxed) || self.is_master()
    }

    /// The file's authentication token: its ID, never 0.
    fn magic(&self) -> u32 {
        (self.id as u32).max(1)
    }

    fn buffer(&self, handle: u32) -> Result<Arc<Buffer>> {
        self.inner.lock().handles.get(&handle).cloned().ok_or(ENOENT)
    }

    fn add_handle(&self, b: Arc<Buffer>) -> u32 {
        let mut f = self.inner.lock();
        if let Some((&h, _)) = f.handles.iter().find(|(_, x)| Arc::ptr_eq(x, &b)) {
            return h;
        }
        let h = f.next_handle;
        f.next_handle += 1;
        f.handles.insert(h, b);
        h
    }

    fn outputs(&self) -> usize {
        self.dev.state.lock().outputs.len()
    }

    /// The object `id`, if this file may see it (an empty lease sees none).
    fn obj(&self, id: u32) -> Option<Obj> {
        if self.lessee || id < OBJ_BASE {
            return None;
        }
        let (i, k) = (((id - OBJ_BASE) / OBJ_STRIDE) as usize, (id - OBJ_BASE) % OBJ_STRIDE);
        if i >= self.outputs() {
            return None;
        }
        Some(match k {
            0 => Obj::Crtc(i),
            1 => Obj::Encoder(i),
            2 => Obj::Connector(i),
            3 if self.universal.load(Ordering::Relaxed) => Obj::Primary(i),
            4 if self.universal.load(Ordering::Relaxed) => Obj::Cursor(i),
            5 if self.universal.load(Ordering::Relaxed) && self.dev.display.overlays() => Obj::Overlay(i),
            _ => return None,
        })
    }

    fn crtc(&self, id: u32) -> Result<usize> {
        match self.obj(id) {
            Some(Obj::Crtc(i)) => Ok(i),
            _ => Err(ENOENT),
        }
    }

    /// A property's value on an object, if it has it; `None` for
    /// properties atomic clients alone see when this one isn't.
    fn props_of(&self, obj: Obj) -> Vec<(u32, u64)> {
        let atomic = self.atomic.load(Ordering::Relaxed);
        let st = self.dev.state.lock();
        let o = &st.outputs[obj.output()].st;
        let gamma_size = self.dev.display.gamma_size();
        let plane = |p: &Plane, kind: u64, i: usize| {
            let mut v = alloc::vec![(PROP_TYPE, kind)];
            if atomic {
                v.extend_from_slice(&[
                    (PROP_FB_ID, p.fb.as_ref().map_or(0, |f| u64::from(f.id))),
                    (PROP_CRTC_ID, if p.on { u64::from(crtc_id(i)) } else { 0 }),
                    (PROP_SRC_X, u64::from(p.src[0])),
                    (PROP_SRC_Y, u64::from(p.src[1])),
                    (PROP_SRC_W, u64::from(p.src[2])),
                    (PROP_SRC_H, u64::from(p.src[3])),
                    (PROP_CRTC_X, p.dst[0] as u64),
                    (PROP_CRTC_Y, p.dst[1] as u64),
                    (PROP_CRTC_W, p.dst[2] as u64),
                    (PROP_CRTC_H, p.dst[3] as u64),
                ]);
            }
            v
        };
        match obj {
            Obj::Primary(i) => plane(&o.primary, PLANE_TYPE_PRIMARY, i),
            Obj::Cursor(i) => plane(&o.cursor, PLANE_TYPE_CURSOR, i),
            Obj::Overlay(i) => plane(&o.overlay, PLANE_TYPE_OVERLAY, i),
            Obj::Connector(i) => {
                let mut v = alloc::vec![(PROP_DPMS, o.dpms), (PROP_EDID, u64::from(EDID_BLOB + i as u32))];
                if atomic {
                    v.push((PROP_CRTC_ID, if o.linked { u64::from(crtc_id(i)) } else { 0 }));
                }
                v
            }
            Obj::Crtc(_) => {
                let mut v = Vec::new();
                if atomic {
                    v.push((PROP_ACTIVE, u64::from(o.active)));
                    v.push((PROP_MODE_ID, u64::from(o.mode_blob)));
                }
                if gamma_size > 0 {
                    v.push((PROP_GAMMA_LUT, u64::from(o.gamma_blob)));
                    v.push((PROP_GAMMA_LUT_SIZE, u64::from(gamma_size)));
                }
                v
            }
            Obj::Encoder(_) => Vec::new(),
        }
    }

    fn add_fb(
        &self,
        buffer: Arc<Buffer>,
        width: u32,
        height: u32,
        pitch: u32,
        offset: u32,
        format: u32,
    ) -> Result<u32> {
        if !FORMATS.contains(&format) {
            return Err(EINVAL);
        }
        if width == 0 || height == 0 || pitch < width * 4 {
            return Err(EINVAL);
        }
        if u64::from(offset) + u64::from(pitch) * u64::from(height) > buffer.size {
            return Err(EINVAL);
        }
        let mut st = self.dev.state.lock();
        let id = st.next_fb;
        st.next_fb += 1;
        st.fbs.insert(id, Arc::new(Framebuffer { id, buffer, width, height, pitch, offset, format, owner: self.id }));
        Ok(id)
    }

    fn fb(&self, id: u32) -> Result<Arc<Framebuffer>> {
        self.dev.state.lock().fbs.get(&id).cloned().ok_or(ENOENT)
    }

    fn blob(&self, id: u32) -> Result<Arc<Vec<u8>>> {
        self.dev.state.lock().blobs.get(&id).cloned().ok_or(EINVAL)
    }

    /// Whether output `i`'s new state `n` (after `old`) can be shown. A
    /// mode is checked against the display's modes when it is set, not
    /// on every flip after (the display may have changed meanwhile).
    fn check(&self, i: usize, n: &OutState, old: &OutState) -> Result<()> {
        if n.active {
            let (w, h) = n.mode_size();
            let set = !old.active || old.mode != n.mode;
            if n.mode.is_none()
                || !n.linked
                || (set && !self.dev.display.output(i).modes.iter().any(|m| (m.0, m.1) == (w, h)))
            {
                return Err(EINVAL);
            }
        } else if n.primary.on || n.cursor.on || n.overlay.on {
            // Planes only on a CRTC that is on.
            return Err(EINVAL);
        }
        let (w, h) = n.mode_size();
        let p = &n.primary;
        if p.fb.is_some() != p.on {
            return Err(EINVAL);
        }
        if let Some(fb) = &p.fb {
            // The primary plane covers the screen, unscaled.
            let full = [0, 0, w << 16, h << 16];
            if p.src != full || p.dst != [0, 0, i64::from(w), i64::from(h)] || fb.width < w || fb.height < h {
                return Err(EINVAL);
            }
        }
        let c = &n.cursor;
        if c.fb.is_some() != c.on {
            return Err(EINVAL);
        }
        if let Some(fb) = &c.fb {
            let (sw, sh) = (c.src[2] >> 16, c.src[3] >> 16);
            if fb.format != FORMAT_ARGB8888
                || c.src[0] != 0
                || c.src[1] != 0
                || i64::from(sw) != c.dst[2]
                || i64::from(sh) != c.dst[3]
                || sw == 0
                || sh == 0
                || sw > CURSOR_SIZE
                || sh > CURSOR_SIZE
                || fb.width < sw
                || fb.height < sh
            {
                return Err(EINVAL);
            }
        }
        let v = &n.overlay;
        if v.fb.is_some() != v.on {
            return Err(EINVAL);
        }
        if let Some(fb) = &v.fb {
            // Unscaled, whole pixels, inside its framebuffer; the part on
            // the screen is shown.
            let (sx, sy, sw, sh) = (v.src[0] >> 16, v.src[1] >> 16, v.src[2] >> 16, v.src[3] >> 16);
            if v.src.iter().any(|c| c & 0xFFFF != 0)
                || i64::from(sw) != v.dst[2]
                || i64::from(sh) != v.dst[3]
                || sw == 0
                || sh == 0
                || u64::from(sx) + u64::from(sw) > u64::from(fb.width)
                || u64::from(sy) + u64::from(sh) > u64::from(fb.height)
            {
                return Err(EINVAL);
            }
        }
        if let Some(g) = &n.gamma
            && g.len() != self.dev.display.gamma_size() as usize
        {
            return Err(EINVAL);
        }
        Ok(())
    }

    /// Commit `new` (every output's state) for the outputs in `touched`
    /// (a bit each). `flags` are the atomic ones; `wait`: block until the
    /// commit's vblank (atomic calls without NONBLOCK). Only commits that
    /// flip (`flips`: atomic ones and PAGE_FLIP) wait for, or fail on, a
    /// flip still pending; the legacy cursor, gamma and DPMS calls go
    /// through at once.
    fn commit(
        &self,
        new: Vec<OutState>,
        touched: u32,
        flags: u32,
        user_data: u64,
        wait: bool,
        flips: bool,
    ) -> Result<()> {
        let n = new.len();
        let old = self.current();
        if old.len() != n {
            return Err(EINVAL);
        }
        for (i, s) in new.iter().enumerate() {
            if touched & (1 << i) != 0 {
                self.check(i, s, &old[i])?;
            }
        }
        let event = flags & PAGE_FLIP_EVENT != 0;
        if event && (touched == 0 || (0..n).any(|i| touched & (1 << i) != 0 && !new[i].active)) {
            return Err(EINVAL);
        }
        loop {
            let mut st = self.dev.state.lock();
            if st.outputs.len() != n {
                return Err(EINVAL);
            }
            let modeset = (0..n).any(|i| {
                let (a, b) = (&st.outputs[i].st, &new[i]);
                a.active != b.active || a.mode != b.mode || a.linked != b.linked
            });
            if modeset && flags & ATOMIC_ALLOW_MODESET == 0 {
                return Err(EINVAL);
            }
            let busy = flips && (0..n).any(|i| touched & (1 << i) != 0 && st.outputs[i].flip_pending);
            if flags & ATOMIC_TEST_ONLY != 0 {
                return if busy && flags & ATOMIC_NONBLOCK != 0 { Err(EBUSY) } else { Ok(()) };
            }
            if busy {
                if flags & ATOMIC_NONBLOCK != 0 || !wait {
                    return Err(EBUSY);
                }
                drop(st);
                let dev = &self.dev;
                let free = || (0..n).all(|i| touched & (1 << i) == 0 || !dev.state.lock().outputs[i].flip_pending);
                if dev.flips.wait_until_interruptible(free) {
                    return Err(EINTR);
                }
                continue;
            }
            // In place: what changed, to do after the lock.
            let now = crate::time::monotonic_ns();
            let mut work: Vec<Work> = (0..n).map(|_| Work::default()).collect();
            let mut closed = Vec::new();
            for (i, s) in new.into_iter().enumerate() {
                let o = &mut st.outputs[i];
                let old = core::mem::replace(&mut o.st, s);
                let s = &o.st;
                let w = &mut work[i];
                if s.active && (!old.active || old.mode != s.mode) {
                    o.epoch = now;
                    o.period = 1_000_000_000 / u64::from(s.mode.map_or(60, |m| m.refresh()).max(1));
                    // The display's own vblanks, where it has them (in its
                    // mode: the one it shows now).
                    if let Some((last, period)) = self.dev.display.vblank(i).filter(|&(l, p)| p > 0 && l <= now) {
                        o.epoch = last;
                        o.period = period;
                    }
                } else if !s.active {
                    o.period = 0;
                }
                let screen_changed = old.shows() != s.shows() || old.mode != s.mode || !old.primary.same_fb(&s.primary);
                if screen_changed {
                    match (&s.primary.fb, s.shows()) {
                        (Some(fb), true) => w.present = Some((fb.clone(), s.mode_size())),
                        _ => w.blank = true,
                    }
                }
                if !old.cursor.same_fb(&s.cursor) || old.cursor.hot != s.cursor.hot || old.shows() != s.shows() {
                    w.cursor = Some(match (&s.cursor.fb, s.shows()) {
                        (Some(fb), true) => {
                            Some(fb.cursor_image(s.cursor.src[2] >> 16, s.cursor.src[3] >> 16, s.cursor.hot))
                        }
                        _ => None,
                    });
                }
                if s.cursor.on && (old.cursor.dst[..2] != s.cursor.dst[..2] || w.cursor.is_some()) {
                    w.cursor_at = Some((s.cursor.dst[0] as i32, s.cursor.dst[1] as i32));
                }
                if old.gamma != s.gamma {
                    w.gamma = Some(s.gamma.clone());
                }
                let (was, now) = (old.overlay_shown(), s.overlay_shown());
                let moved = match (&was, &now) {
                    (Some(a), Some(b)) => !Arc::ptr_eq(&a.fb, &b.fb) || (a.src, a.size, a.at) != (b.src, b.size, b.at),
                    (None, None) => false,
                    _ => true,
                };
                if moved {
                    w.overlay = Some(now);
                }
                // A framebuffer removed while on the screen goes now.
                for p in [&old.primary, &old.cursor, &old.overlay] {
                    if let Some(f) = &p.fb
                        && !st.fbs.contains_key(&f.id)
                        && !st.outputs.iter().any(|x| {
                            [&x.st.primary, &x.st.cursor, &x.st.overlay]
                                .iter()
                                .any(|q| q.fb.as_ref().is_some_and(|g| Arc::ptr_eq(f, g)))
                        })
                    {
                        closed.push(f.id);
                    }
                }
            }
            let mut vblanks = Vec::new();
            for (i, o) in st.outputs.iter_mut().enumerate() {
                if touched & (1 << i) != 0 && o.st.active && (event || wait) {
                    let next = o.count(now) + 1;
                    if event {
                        o.flip_pending = true;
                    }
                    vblanks.push((i, next, o.at(next)));
                }
            }
            drop(st);
            let display = &self.dev.display;
            if work.iter().any(|w| w.present.is_some()) {
                crate::drivers::fbcon::set_suspended(true);
            }
            for (i, w) in work.into_iter().enumerate() {
                if let Some(g) = w.gamma {
                    display.set_gamma(i, g);
                }
                if let Some((fb, mode)) = &w.present {
                    display.present(i, fb, *mode);
                } else if w.blank {
                    display.blank(i);
                }
                if let Some(v) = w.overlay {
                    display.overlay(i, v);
                }
                if let Some(c) = w.cursor {
                    display.cursor(i, c);
                }
                if let Some((x, y)) = w.cursor_at {
                    display.move_cursor(i, x, y);
                }
            }
            for id in closed {
                display.forget(id);
            }
            // A card that copies may have taken past the vblank chosen
            // above: the flip completes at the first one after the frame
            // is there (so it stays pending until then).
            let after = crate::time::monotonic_ns();
            if vblanks.iter().any(|&(_, _, at)| at <= after) {
                let st = self.dev.state.lock();
                for v in vblanks.iter_mut().filter(|v| v.2 <= after) {
                    let o = &st.outputs[v.0];
                    v.1 = o.count(after) + 1;
                    v.2 = o.at(v.1);
                }
            }
            let mut last = 0;
            for &(i, seq, at) in &vblanks {
                last = last.max(at);
                if !event {
                    continue;
                }
                let events = Arc::downgrade(&self.events);
                let dev = self.dev.clone();
                crate::time::add_timer(at, move || {
                    dev.state.lock().outputs[i].flip_pending = false;
                    dev.flips.wake_all();
                    if let Some(events) = events.upgrade() {
                        events.push(vblank_event(EVENT_FLIP_COMPLETE, user_data, at, seq, crtc_id(i)));
                    }
                });
            }
            if wait && last > 0 {
                let now = crate::time::monotonic_ns();
                if last > now {
                    crate::time::sleep_ns(last - now);
                }
            }
            return Ok(());
        }
    }

    fn current(&self) -> Vec<OutState> {
        self.dev.state.lock().outputs.iter().map(|o| o.st.clone()).collect()
    }

    /// Set property `prop` of `obj` to `value` in `s` (an atomic commit's
    /// state). Atomic-only properties need `atomic`.
    fn set_prop(&self, s: &mut [OutState], obj: Obj, prop: u32, value: u64) -> Result<()> {
        let i = obj.output();
        let o = &mut s[i];
        let on_crtc = |v: u64| match v {
            0 => Ok(false),
            v if v == u64::from(crtc_id(i)) => Ok(true),
            _ => Err(EINVAL),
        };
        let u32v = || u32::try_from(value).map_err(|_| EINVAL);
        match (obj, prop) {
            (Obj::Crtc(_), PROP_ACTIVE) if value <= 1 => o.active = value == 1,
            (Obj::Crtc(_), PROP_MODE_ID) => {
                if value == 0 {
                    (o.mode, o.mode_blob) = (None, 0);
                } else {
                    let id = u32v()?;
                    o.mode = Some(ModeInfo::from_bytes(&self.blob(id)?).ok_or(EINVAL)?);
                    o.mode_blob = id;
                }
            }
            (Obj::Crtc(_), PROP_GAMMA_LUT) => {
                if value == 0 {
                    (o.gamma, o.gamma_blob) = (None, 0);
                } else {
                    let id = u32v()?;
                    o.gamma = Some(gamma_from_blob(&self.blob(id)?));
                    o.gamma_blob = id;
                }
            }
            (Obj::Connector(_), PROP_CRTC_ID) => o.linked = on_crtc(value)?,
            (Obj::Primary(_) | Obj::Cursor(_) | Obj::Overlay(_), _) => {
                let p = match obj {
                    Obj::Primary(_) => &mut o.primary,
                    Obj::Cursor(_) => &mut o.cursor,
                    _ => &mut o.overlay,
                };
                match prop {
                    PROP_FB_ID => p.fb = if value == 0 { None } else { Some(self.fb(u32v()?)?) },
                    PROP_CRTC_ID => p.on = on_crtc(value)?,
                    PROP_SRC_X..=PROP_SRC_H => p.src[(prop - PROP_SRC_X) as usize] = u32v()?,
                    PROP_CRTC_X | PROP_CRTC_Y => {
                        p.dst[(prop - PROP_CRTC_X) as usize] =
                            i64::from(i32::try_from(value as i64).map_err(|_| EINVAL)?)
                    }
                    PROP_CRTC_W | PROP_CRTC_H => {
                        p.dst[(prop - PROP_CRTC_X) as usize] = i64::from(i32::try_from(value).map_err(|_| EINVAL)?)
                    }
                    _ => return Err(EINVAL),
                }
            }
            _ => return Err(EINVAL),
        }
        Ok(())
    }

    /// DRM_IOCTL_MODE_ATOMIC.
    fn atomic(&self, a: &AtomicReq) -> Result<()> {
        self.need_master()?;
        if !self.atomic.load(Ordering::Relaxed)
            || a.flags & !ATOMIC_FLAGS != 0
            || a.flags & PAGE_FLIP_ASYNC != 0
            || (a.flags & ATOMIC_TEST_ONLY != 0 && a.flags & PAGE_FLIP_EVENT != 0)
            || a.reserved != 0
            || a.count_objs > 1024
        {
            return Err(EINVAL);
        }
        let mut s = self.current();
        let mut touched = 0u32;
        let mut at = 0u64;
        for k in 0..u64::from(a.count_objs) {
            let id: u32 = read_user(a.objs_ptr + 4 * k).map_err(|_| EFAULT)?;
            let count: u32 = read_user(a.count_props_ptr + 4 * k).map_err(|_| EFAULT)?;
            let obj = self.obj(id).ok_or(ENOENT)?;
            if at + u64::from(count) > 4096 {
                return Err(EINVAL);
            }
            for _ in 0..count {
                let prop: u32 = read_user(a.props_ptr + 4 * at).map_err(|_| EFAULT)?;
                let value: u64 = read_user(a.prop_values_ptr + 8 * at).map_err(|_| EFAULT)?;
                self.set_prop(&mut s, obj, prop, value)?;
                at += 1;
            }
            touched |= 1 << obj.output();
        }
        let wait = a.flags & ATOMIC_NONBLOCK == 0;
        self.commit(s, touched, a.flags, a.user_data, wait, true)
    }

    /// Output `i`'s primary plane showing `fb` full screen (legacy calls).
    fn full_screen(s: &mut OutState, fb: Arc<Framebuffer>) {
        let (w, h) = s.mode_size();
        s.primary = Plane {
            fb: Some(fb),
            on: true,
            src: [0, 0, w << 16, h << 16],
            dst: [0, 0, w.into(), h.into()],
            hot: (0, 0),
        };
    }

    /// The vblank count and its time on CRTC `i`, if it is on.
    fn vblank_now(&self, i: usize) -> Result<(u64, u64)> {
        let st = self.dev.state.lock();
        let o = &st.outputs[i];
        if !o.st.active || o.period == 0 {
            return Err(EINVAL);
        }
        let n = o.count(crate::time::monotonic_ns());
        Ok((n, o.at(n)))
    }

    /// Wait for, or ask for an event at, vblank `target` of CRTC `i`.
    fn at_vblank(&self, i: usize, target: u64, event: Option<Vec<u8>>) -> Result<u64> {
        let at = {
            let st = self.dev.state.lock();
            st.outputs[i].at(target)
        };
        match event {
            Some(ev) => {
                let events = Arc::downgrade(&self.events);
                crate::time::add_timer(at, move || {
                    if let Some(events) = events.upgrade() {
                        events.push(ev);
                    }
                });
            }
            None => {
                let now = crate::time::monotonic_ns();
                if at > now {
                    crate::time::sleep_ns(at - now);
                }
            }
        }
        Ok(at)
    }

    fn ioctl_impl(&self, cmd: u32, arg: u64) -> Result<u64> {
        if (cmd >> 8) & 0xff != u32::from(b'd') {
            return Err(ENOTTY);
        }
        let dev = &self.dev;
        let n = self.outputs();
        match cmd & 0xff {
            VERSION => rw(arg, |v: &mut Version| {
                (v.major, v.minor, v.patch) = (1, 1, 0);
                put_string(v.name, &mut v.name_len, dev.display.driver())?;
                put_string(v.date, &mut v.date_len, "20261024")?;
                put_string(v.desc, &mut v.desc_len, dev.display.description())?;
                Ok(0)
            }),
            GET_UNIQUE => rw(arg, |u: &mut Unique| {
                u.len = 0;
                Ok(0)
            }),
            // Authentication (the DRM uAPI's primary-node rules): a file's
            // token is its magic; the master authenticates a token of an
            // open file on this card (EINVAL for any other).
            GET_MAGIC => {
                write_user(arg, &self.magic()).map_err(|_| EFAULT)?;
                Ok(0)
            }
            AUTH_MAGIC => {
                let magic: u32 = read_user(arg).map_err(|_| EFAULT)?;
                self.need_master()?;
                let f = dev
                    .files
                    .lock()
                    .iter()
                    .filter_map(Weak::upgrade)
                    .find(|f| magic != 0 && f.magic() == magic)
                    .ok_or(EINVAL)?;
                f.authenticated.store(true, Ordering::Relaxed);
                Ok(0)
            }
            GET_CAP => rw(arg, |c: &mut Cap| {
                c.value = match c.cap {
                    CAP_DUMB_BUFFER | CAP_VBLANK_HIGH_CRTC | CAP_TIMESTAMP_MONOTONIC | CAP_CRTC_IN_VBLANK_EVENT => 1,
                    CAP_DUMB_PREFERRED_DEPTH => 24,
                    CAP_DUMB_PREFER_SHADOW => 0,
                    CAP_PRIME => PRIME_CAP_IMPORT | PRIME_CAP_EXPORT,
                    CAP_ASYNC_PAGE_FLIP | CAP_ADDFB2_MODIFIERS | CAP_PAGE_FLIP_TARGET => 0,
                    CAP_SYNCOBJ | CAP_SYNCOBJ_TIMELINE | CAP_ATOMIC_ASYNC_PAGE_FLIP => 0,
                    CAP_CURSOR_WIDTH | CAP_CURSOR_HEIGHT => u64::from(CURSOR_SIZE),
                    _ => return Err(EINVAL),
                };
                Ok(0)
            }),
            SET_CLIENT_CAP => {
                let c: Cap = read_user(arg).map_err(|_| EFAULT)?;
                match (c.cap, c.value) {
                    (CLIENT_CAP_UNIVERSAL_PLANES, v @ 0..=1) => self.universal.store(v == 1, Ordering::Relaxed),
                    // Atomic implies universal planes.
                    (CLIENT_CAP_ATOMIC, v @ 0..=1) => {
                        self.atomic.store(v == 1, Ordering::Relaxed);
                        if v == 1 {
                            self.universal.store(true, Ordering::Relaxed);
                        }
                    }
                    (CLIENT_CAP_STEREO_3D | CLIENT_CAP_ASPECT_RATIO, 0..=1) => {}
                    // No writeback connectors here.
                    (CLIENT_CAP_WRITEBACK_CONNECTORS, _) => return Err(EINVAL),
                    _ => return Err(EINVAL),
                }
                Ok(0)
            }
            SET_MASTER => {
                let mut st = dev.state.lock();
                match st.master {
                    Some(m) if m != self.id => Err(EBUSY),
                    _ => {
                        st.master = Some(self.id);
                        Ok(0)
                    }
                }
            }
            DROP_MASTER => {
                let release = {
                    let mut st = dev.state.lock();
                    if st.master != Some(self.id) {
                        return Err(EINVAL);
                    }
                    st.master = None;
                    let shown = st.outputs.iter().any(|o| o.st.active);
                    reset(&mut st);
                    shown
                };
                if release {
                    dev.display.release();
                }
                Ok(0)
            }
            GEM_CLOSE => {
                let g: GemClose = read_user(arg).map_err(|_| EFAULT)?;
                self.inner.lock().handles.remove(&g.handle).map(|_| 0).ok_or(EINVAL)
            }
            PRIME_HANDLE_TO_FD => rw(arg, |p: &mut PrimeHandle| {
                let b = self.buffer(p.handle)?;
                let f: Arc<dyn File> = Arc::new(DmaBuf { buffer: b, flags: p.flags & O_ACCMODE });
                let proc = crate::proc::current().ok_or(ESRCH)?;
                p.fd = proc.files.lock().insert(f, p.flags & O_CLOEXEC != 0)?;
                Ok(0)
            }),
            PRIME_FD_TO_HANDLE => rw(arg, |p: &mut PrimeHandle| {
                let proc = crate::proc::current().ok_or(ESRCH)?;
                let f = proc.files.lock().get(p.fd)?;
                let any: &dyn core::any::Any = &*f;
                let d = any.downcast_ref::<DmaBuf>().ok_or(EINVAL)?;
                p.handle = self.add_handle(d.buffer.clone());
                Ok(0)
            }),
            WAIT_VBLANK => rw(arg, |w: &mut WaitVblank| {
                if w.kind & (VBLANK_SIGNAL | VBLANK_FLIP) != 0 {
                    return Err(EINVAL);
                }
                let i =
                    if w.kind & VBLANK_SECONDARY != 0 { 1 } else { ((w.kind & VBLANK_HIGH_CRTC_MASK) >> 1) as usize };
                if i >= n {
                    return Err(EINVAL);
                }
                let (now, _) = self.vblank_now(i)?;
                let mut target = if w.kind & VBLANK_RELATIVE != 0 {
                    now + u64::from(w.sequence)
                } else {
                    // Absolute: the low 32 bits of the count.
                    (now & !0xFFFF_FFFF) | u64::from(w.sequence)
                };
                if w.kind & VBLANK_NEXTONMISS != 0 && target <= now {
                    target = now + 1;
                }
                let event = (w.kind & VBLANK_EVENT != 0)
                    .then(|| vblank_event(EVENT_VBLANK, w.a as u64, self.vblank_time(i, target), target, crtc_id(i)));
                let at = self.at_vblank(i, target.max(now), event)?;
                w.sequence = target as u32;
                (w.a, w.b) = ((at / 1_000_000_000) as i64, (at % 1_000_000_000 / 1000) as i64);
                Ok(0)
            }),
            CRTC_GET_SEQUENCE => rw(arg, |g: &mut GetSequence| {
                let i = self.crtc(g.crtc_id)?;
                match self.vblank_now(i) {
                    Ok((seq, at)) => (g.active, g.sequence, g.sequence_ns) = (1, seq, at as i64),
                    Err(_) => (g.active, g.sequence, g.sequence_ns) = (0, 0, 0),
                }
                Ok(0)
            }),
            CRTC_QUEUE_SEQUENCE => rw(arg, |q: &mut QueueSequence| {
                let i = self.crtc(q.crtc_id)?;
                if q.flags & !(CRTC_SEQUENCE_RELATIVE | CRTC_SEQUENCE_NEXT_ON_MISS) != 0 {
                    return Err(EINVAL);
                }
                let (now, _) = self.vblank_now(i)?;
                let mut target = if q.flags & CRTC_SEQUENCE_RELATIVE != 0 { now + q.sequence } else { q.sequence };
                if q.flags & CRTC_SEQUENCE_NEXT_ON_MISS != 0 && target <= now {
                    target = now + 1;
                }
                let ev = sequence_event(q.user_data, self.vblank_time(i, target), target);
                self.at_vblank(i, target.max(now), Some(ev))?;
                q.sequence = target;
                Ok(0)
            }),
            MODE_GETRESOURCES => rw(arg, |r: &mut CardRes| {
                let fbs: Vec<u32> = dev.state.lock().fbs.keys().copied().collect();
                put_array(r.fb_ptr, &mut r.count_fbs, &fbs)?;
                // An empty lease sees none of the card's objects.
                let held = if self.lessee { 0 } else { n };
                let ids = |f: fn(usize) -> u32| (0..held).map(f).collect::<Vec<u32>>();
                put_array(r.crtc_ptr, &mut r.count_crtcs, &ids(crtc_id))?;
                put_array(r.connector_ptr, &mut r.count_connectors, &ids(connector_id))?;
                put_array(r.encoder_ptr, &mut r.count_encoders, &ids(encoder_id))?;
                (r.min_width, r.max_width, r.min_height, r.max_height) = (1, 16384, 1, 16384);
                Ok(0)
            }),
            MODE_GETCRTC => rw(arg, |c: &mut Crtc| {
                let i = self.crtc(c.crtc_id)?;
                let st = dev.state.lock();
                let o = &st.outputs[i].st;
                c.fb_id = o.primary.fb.as_ref().map_or(0, |f| f.id);
                (c.x, c.y, c.gamma_size) = (0, 0, dev.display.gamma_size());
                c.mode_valid = u32::from(o.active);
                c.mode = if o.active { o.mode.unwrap_or_default() } else { ModeInfo::default() };
                Ok(0)
            }),
            MODE_SETCRTC => {
                self.need_master()?;
                let c: Crtc = read_user(arg).map_err(|_| EFAULT)?;
                let i = self.crtc(c.crtc_id)?;
                let mut s = self.current();
                if c.fb_id == 0 || c.mode_valid == 0 {
                    s[i] = OutState {
                        dpms: s[i].dpms,
                        gamma: s[i].gamma.clone(),
                        gamma_blob: s[i].gamma_blob,
                        ..OutState::default()
                    };
                } else {
                    if c.x != 0 || c.y != 0 || c.count_connectors == 0 {
                        return Err(EINVAL);
                    }
                    // Its connectors: this output's only.
                    for k in 0..u64::from(c.count_connectors) {
                        let id: u32 = read_user(c.set_connectors_ptr + 4 * k).map_err(|_| EFAULT)?;
                        if self.obj(id) != Some(Obj::Connector(i)) {
                            return Err(EINVAL);
                        }
                    }
                    let fb = self.fb(c.fb_id)?;
                    let o = &mut s[i];
                    if o.mode != Some(c.mode) {
                        o.mode_blob = 0;
                    }
                    (o.active, o.linked, o.mode) = (true, true, Some(c.mode));
                    Self::full_screen(o, fb);
                }
                self.commit(s, 1 << i, ATOMIC_ALLOW_MODESET, 0, false, false).map(|_| 0)
            }
            MODE_GETENCODER => rw(arg, |e: &mut GetEncoder| {
                let Some(Obj::Encoder(i)) = self.obj(e.encoder_id) else { return Err(ENOENT) };
                e.encoder_type = match dev.display.connector_type() {
                    CONNECTOR_VIRTUAL => ENCODER_VIRTUAL,
                    CONNECTOR_HDMIA => ENCODER_TMDS,
                    _ => ENCODER_NONE,
                };
                let linked = dev.state.lock().outputs[i].st.linked;
                e.crtc_id = if linked { crtc_id(i) } else { 0 };
                (e.possible_crtcs, e.possible_clones) = (1 << i, 0);
                Ok(0)
            }),
            MODE_GETCONNECTOR => rw(arg, |c: &mut GetConnector| {
                let Some(Obj::Connector(i)) = self.obj(c.connector_id) else { return Err(ENOENT) };
                let info = dev.display.output(i);
                put_array(c.encoders_ptr, &mut c.count_encoders, &[encoder_id(i)])?;
                let modes: Vec<ModeInfo> =
                    info.modes.iter().enumerate().map(|(k, &(w, h, hz))| mode_info(w, h, hz, k == 0)).collect();
                put_array(c.modes_ptr, &mut c.count_modes, &modes)?;
                let props = self.props_of(Obj::Connector(i));
                let ids: Vec<u32> = props.iter().map(|p| p.0).collect();
                let values: Vec<u64> = props.iter().map(|p| p.1).collect();
                let mut k = c.count_props;
                put_array(c.props_ptr, &mut k, &ids)?;
                put_array(c.prop_values_ptr, &mut c.count_props, &values)?;
                c.encoder_id = if dev.state.lock().outputs[i].st.linked { encoder_id(i) } else { 0 };
                c.connector_type = dev.display.connector_type();
                c.connector_type_id = i as u32 + 1;
                c.connection = if info.connected { CONNECTED } else { DISCONNECTED };
                (c.mm_width, c.mm_height) = info.size_mm;
                c.subpixel = SUBPIXEL_UNKNOWN;
                Ok(0)
            }),
            MODE_GETPROPERTY => rw(arg, |p: &mut GetProperty| {
                const ALL: u64 = u32::MAX as u64;
                let (name, flags, values, enums): (&str, u32, &[u64], &[(u64, &str)]) = match p.prop_id {
                    PROP_TYPE => (
                        "type",
                        PROP_ENUM | PROP_IMMUTABLE,
                        &[],
                        &[(0, "Overlay"), (PLANE_TYPE_PRIMARY, "Primary"), (PLANE_TYPE_CURSOR, "Cursor")],
                    ),
                    PROP_DPMS => ("DPMS", PROP_ENUM, &[], &[(0, "On"), (1, "Standby"), (2, "Suspend"), (3, "Off")]),
                    PROP_EDID => ("EDID", PROP_BLOB | PROP_IMMUTABLE, &[], &[]),
                    PROP_CRTC_ID => ("CRTC_ID", PROP_OBJECT | PROP_ATOMIC, &[OBJECT_CRTC as u64], &[]),
                    PROP_FB_ID => ("FB_ID", PROP_OBJECT | PROP_ATOMIC, &[OBJECT_FB as u64], &[]),
                    PROP_SRC_X => ("SRC_X", PROP_RANGE | PROP_ATOMIC, &[0, ALL], &[]),
                    PROP_SRC_Y => ("SRC_Y", PROP_RANGE | PROP_ATOMIC, &[0, ALL], &[]),
                    PROP_SRC_W => ("SRC_W", PROP_RANGE | PROP_ATOMIC, &[0, ALL], &[]),
                    PROP_SRC_H => ("SRC_H", PROP_RANGE | PROP_ATOMIC, &[0, ALL], &[]),
                    PROP_CRTC_X => {
                        ("CRTC_X", PROP_SIGNED_RANGE | PROP_ATOMIC, &[i32::MIN as i64 as u64, i32::MAX as u64], &[])
                    }
                    PROP_CRTC_Y => {
                        ("CRTC_Y", PROP_SIGNED_RANGE | PROP_ATOMIC, &[i32::MIN as i64 as u64, i32::MAX as u64], &[])
                    }
                    PROP_CRTC_W => ("CRTC_W", PROP_RANGE | PROP_ATOMIC, &[0, i32::MAX as u64], &[]),
                    PROP_CRTC_H => ("CRTC_H", PROP_RANGE | PROP_ATOMIC, &[0, i32::MAX as u64], &[]),
                    PROP_ACTIVE => ("ACTIVE", PROP_RANGE | PROP_ATOMIC, &[0, 1], &[]),
                    PROP_MODE_ID => ("MODE_ID", PROP_BLOB | PROP_ATOMIC, &[], &[]),
                    PROP_GAMMA_LUT => ("GAMMA_LUT", PROP_BLOB, &[], &[]),
                    PROP_GAMMA_LUT_SIZE => ("GAMMA_LUT_SIZE", PROP_RANGE | PROP_IMMUTABLE, &[0, ALL], &[]),
                    _ => return Err(ENOENT),
                };
                p.name = name_bytes(name);
                p.flags = flags;
                if flags & PROP_ENUM != 0 {
                    let vals: Vec<u64> = enums.iter().map(|e| e.0).collect();
                    let blobs: Vec<PropEnum> =
                        enums.iter().map(|e| PropEnum { value: e.0, name: name_bytes(e.1) }).collect();
                    put_array(p.values_ptr, &mut p.count_values, &vals)?;
                    put_array(p.enum_blob_ptr, &mut p.count_enum_blobs, &blobs)?;
                } else {
                    put_array(p.values_ptr, &mut p.count_values, values)?;
                    p.count_enum_blobs = 0;
                }
                Ok(0)
            }),
            MODE_SETPROPERTY => {
                self.need_master()?;
                let s: ConnectorSetProperty = read_user(arg).map_err(|_| EFAULT)?;
                let obj = self.obj(s.connector_id).ok_or(ENOENT)?;
                self.set_property(obj, s.prop_id, s.value).map(|_| 0)
            }
            MODE_OBJ_SETPROPERTY => {
                self.need_master()?;
                let s: ObjSetProperty = read_user(arg).map_err(|_| EFAULT)?;
                let obj = self.obj(s.obj_id).ok_or(ENOENT)?;
                if s.obj_type != OBJECT_ANY && s.obj_type != obj.kind() {
                    return Err(ENOENT);
                }
                self.set_property(obj, s.prop_id, s.value).map(|_| 0)
            }
            MODE_OBJ_GETPROPERTIES => rw(arg, |o: &mut ObjGetProperties| {
                let obj = self.obj(o.obj_id).ok_or(ENOENT)?;
                if o.obj_type != OBJECT_ANY && o.obj_type != obj.kind() {
                    return Err(ENOENT);
                }
                let props = self.props_of(obj);
                let ids: Vec<u32> = props.iter().map(|p| p.0).collect();
                let values: Vec<u64> = props.iter().map(|p| p.1).collect();
                let mut k = o.count_props;
                put_array(o.props_ptr, &mut k, &ids)?;
                put_array(o.prop_values_ptr, &mut o.count_props, &values)?;
                Ok(0)
            }),
            MODE_GETPROPBLOB => rw(arg, |b: &mut GetBlob| {
                let data: Arc<Vec<u8>> = match b.blob_id.checked_sub(EDID_BLOB) {
                    Some(i) if (i as usize) < n && !self.lessee => {
                        let info = dev.display.output(i as usize);
                        Arc::new(match info.edid.clone() {
                            Some(e) => e,
                            None => made_edid(dev, i as usize, &info),
                        })
                    }
                    _ => dev.state.lock().blobs.get(&b.blob_id).cloned().ok_or(ENOENT)?,
                };
                if b.length as usize >= data.len() && b.data != 0 {
                    copy_to_user(b.data, &data).map_err(|_| EFAULT)?;
                }
                b.length = data.len() as u32;
                Ok(0)
            }),
            MODE_CREATEPROPBLOB => rw(arg, |b: &mut CreateBlob| {
                if b.length == 0 || b.length > 1 << 20 {
                    return Err(EINVAL);
                }
                let mut data = alloc::vec![0u8; b.length as usize];
                copy_from_user(&mut data, b.data).map_err(|_| EFAULT)?;
                let mut st = dev.state.lock();
                let id = st.next_blob;
                st.next_blob += 1;
                st.blobs.insert(id, Arc::new(data));
                b.blob_id = id;
                Ok(0)
            }),
            MODE_DESTROYPROPBLOB => {
                let id: u32 = read_user(arg).map_err(|_| EFAULT)?;
                dev.state.lock().blobs.remove(&id).map(|_| 0).ok_or(ENOENT)
            }
            MODE_GETFB => rw(arg, |c: &mut FbCmd| {
                let fb = self.fb(c.fb_id)?;
                (c.width, c.height, c.pitch, c.bpp, c.depth) = (fb.width, fb.height, fb.pitch, 32, 24);
                // A handle, so its pixels, only for the master and the
                // files it authenticated (the documentation asks for at
                // least the master).
                c.handle = if self.trusted() { self.add_handle(fb.buffer.clone()) } else { 0 };
                Ok(0)
            }),
            MODE_ADDFB => rw(arg, |c: &mut FbCmd| {
                let format = match (c.bpp, c.depth) {
                    (32, 24) => FORMAT_XRGB8888,
                    (32, 32) => FORMAT_ARGB8888,
                    _ => return Err(EINVAL),
                };
                c.fb_id = self.add_fb(self.buffer(c.handle)?, c.width, c.height, c.pitch, 0, format)?;
                Ok(0)
            }),
            MODE_ADDFB2 => rw(arg, |c: &mut FbCmd2| {
                if c.flags & MODE_FB_MODIFIERS != 0 && c.modifier[0] != MOD_LINEAR {
                    return Err(EINVAL);
                }
                let b = self.buffer(c.handles[0])?;
                c.fb_id = self.add_fb(b, c.width, c.height, c.pitches[0], c.offsets[0], c.pixel_format)?;
                Ok(0)
            }),
            MODE_RMFB => {
                let id: u32 = read_user(arg).map_err(|_| EFAULT)?;
                let fb = dev.state.lock().fbs.remove(&id).ok_or(ENOENT)?;
                // Planes showing it are switched off (the uAPI's RMFB).
                let mut s = self.current();
                let mut touched = 0;
                for (i, o) in s.iter_mut().enumerate() {
                    for p in [&mut o.primary, &mut o.cursor, &mut o.overlay] {
                        if p.fb.as_ref().is_some_and(|f| Arc::ptr_eq(f, &fb)) {
                            *p = Plane::default();
                            touched |= 1 << i;
                        }
                    }
                }
                if touched != 0 {
                    let _ = self.commit(s, touched, ATOMIC_ALLOW_MODESET, 0, false, false);
                }
                dev.display.forget(id);
                Ok(0)
            }
            MODE_PAGE_FLIP => {
                self.need_master()?;
                let f: PageFlip = read_user(arg).map_err(|_| EFAULT)?;
                let i = self.crtc(f.crtc_id)?;
                if f.flags & !PAGE_FLIP_EVENT != 0 {
                    return Err(EINVAL);
                }
                let mut s = self.current();
                if !s[i].active {
                    return Err(EINVAL);
                }
                let fb = self.fb(f.fb_id)?;
                Self::full_screen(&mut s[i], fb);
                // Legacy flips fail while one is pending (EBUSY).
                self.commit(s, 1 << i, (f.flags & PAGE_FLIP_EVENT) | ATOMIC_NONBLOCK, f.user_data, false, true)
                    .map(|_| 0)
            }
            MODE_DIRTYFB => {
                let d: DirtyFb = read_user(arg).map_err(|_| EFAULT)?;
                let fb = self.fb(d.fb_id)?;
                let showing: Vec<(usize, (u32, u32))> = dev
                    .state
                    .lock()
                    .outputs
                    .iter()
                    .enumerate()
                    .filter(|(_, o)| o.st.shows() && o.st.primary.fb.as_ref().is_some_and(|s| Arc::ptr_eq(s, &fb)))
                    .map(|(i, o)| (i, o.st.mode_size()))
                    .collect();
                // Overlays showing it.
                let overlaid: Vec<usize> = dev
                    .state
                    .lock()
                    .outputs
                    .iter()
                    .enumerate()
                    .filter(|(_, o)| o.st.overlay_shown().is_some_and(|v| Arc::ptr_eq(&v.fb, &fb)))
                    .map(|(i, _)| i)
                    .collect();
                if showing.is_empty() && overlaid.is_empty() {
                    return Ok(0);
                }
                // struct drm_clip_rect (libdrm drm.h): x1, y1, x2, y2 as
                // unsigned shorts. A few clips are shown one by one, more
                // as the rectangle around them all.
                let mut clips = Vec::new();
                for k in 0..d.num_clips.min(64) {
                    let c: [u16; 4] = read_user(d.clips_ptr + 8 * u64::from(k)).map_err(|_| EFAULT)?;
                    let [x1, y1, x2, y2] = c.map(u32::from);
                    if x1 < x2 && y1 < y2 {
                        clips.push((x1, y1, x2, y2));
                    }
                }
                if clips.len() > MAX_SEPARATE_CLIPS {
                    let all =
                        clips.iter().fold(clips[0], |a, c| (a.0.min(c.0), a.1.min(c.1), a.2.max(c.2), a.3.max(c.3)));
                    clips = alloc::vec![all];
                }
                for (i, mode) in showing {
                    if d.num_clips == 0 {
                        dev.display.present(i, &fb, mode);
                    }
                    for &(x1, y1, x2, y2) in &clips {
                        dev.display.present_rect(i, &fb, x1..x2, y1..y2);
                    }
                }
                for i in overlaid {
                    if d.num_clips == 0 {
                        dev.display.overlay_rect(i, &fb, 0..fb.width, 0..fb.height);
                    }
                    for &(x1, y1, x2, y2) in &clips {
                        dev.display.overlay_rect(i, &fb, x1..x2, y1..y2);
                    }
                }
                Ok(0)
            }
            MODE_CREATE_DUMB => rw(arg, |c: &mut CreateDumb| {
                let b = new_buffer(c.width, c.height, c.bpp)?;
                (c.pitch, c.size) = (b.pitch, b.size);
                c.handle = self.add_handle(b);
                Ok(0)
            }),
            MODE_MAP_DUMB => rw(arg, |m: &mut MapDumb| {
                m.offset = self.buffer(m.handle)?.id << 32;
                Ok(0)
            }),
            MODE_DESTROY_DUMB => {
                let h: u32 = read_user(arg).map_err(|_| EFAULT)?;
                self.inner.lock().handles.remove(&h).map(|_| 0).ok_or(EINVAL)
            }
            MODE_GETPLANERESOURCES => rw(arg, |r: &mut PlaneRes| {
                // Primary, cursor and overlay planes only for
                // universal-plane clients; overlays where the display has
                // them.
                let held = if self.lessee || !self.universal.load(Ordering::Relaxed) { 0 } else { n };
                let overlays = dev.display.overlays();
                let ids: Vec<u32> = (0..held)
                    .flat_map(|i| [primary_id(i), cursor_id(i)].into_iter().chain(overlays.then(|| overlay_id(i))))
                    .collect();
                put_array(r.plane_ptr, &mut r.count_planes, &ids)?;
                Ok(0)
            }),
            MODE_GETPLANE => rw(arg, |p: &mut GetPlane| {
                let obj = self.obj(p.plane_id);
                let (i, cursor) = match obj {
                    Some(Obj::Primary(i) | Obj::Overlay(i)) => (i, false),
                    Some(Obj::Cursor(i)) => (i, true),
                    _ => return Err(ENOENT),
                };
                let st = dev.state.lock();
                let o = &st.outputs[i].st;
                let plane = match obj {
                    Some(Obj::Cursor(_)) => &o.cursor,
                    Some(Obj::Overlay(_)) => &o.overlay,
                    _ => &o.primary,
                };
                p.fb_id = plane.fb.as_ref().map_or(0, |f| f.id);
                p.crtc_id = if plane.on { crtc_id(i) } else { 0 };
                drop(st);
                (p.possible_crtcs, p.gamma_size) = (1 << i, 0);
                put_array(
                    p.format_type_ptr,
                    &mut p.count_format_types,
                    if cursor { &CURSOR_FORMATS } else { &FORMATS },
                )?;
                Ok(0)
            }),
            MODE_SETPLANE => {
                self.need_master()?;
                let sp: SetPlane = read_user(arg).map_err(|_| EFAULT)?;
                let obj = self.obj(sp.plane_id);
                let i = match obj {
                    Some(Obj::Primary(i) | Obj::Cursor(i) | Obj::Overlay(i)) => i,
                    _ => return Err(ENOENT),
                };
                let mut s = self.current();
                let plane = if sp.fb_id == 0 {
                    Plane::default()
                } else {
                    if self.crtc(sp.crtc_id)? != i {
                        return Err(EINVAL);
                    }
                    Plane {
                        fb: Some(self.fb(sp.fb_id)?),
                        on: true,
                        src: [sp.src_x, sp.src_y, sp.src_w, sp.src_h],
                        dst: [sp.crtc_x.into(), sp.crtc_y.into(), sp.crtc_w.into(), sp.crtc_h.into()],
                        hot: (0, 0),
                    }
                };
                match obj {
                    Some(Obj::Cursor(_)) => s[i].cursor = plane,
                    Some(Obj::Overlay(_)) => s[i].overlay = plane,
                    _ => s[i].primary = plane,
                }
                self.commit(s, 1 << i, 0, 0, false, false).map(|_| 0)
            }
            MODE_GETGAMMA => {
                let l: CrtcLut = read_user(arg).map_err(|_| EFAULT)?;
                let i = self.crtc(l.crtc_id)?;
                let size = dev.display.gamma_size();
                if size == 0 || l.gamma_size != size {
                    return Err(EINVAL);
                }
                let lut = dev.state.lock().outputs[i].st.gamma.clone().unwrap_or_else(|| identity_gamma(size));
                for (c, ptr) in [l.red, l.green, l.blue].into_iter().enumerate() {
                    let v: Vec<u8> = lut.iter().flat_map(|e| e[c].to_le_bytes()).collect();
                    copy_to_user(ptr, &v).map_err(|_| EFAULT)?;
                }
                Ok(0)
            }
            MODE_SETGAMMA => {
                self.need_master()?;
                let l: CrtcLut = read_user(arg).map_err(|_| EFAULT)?;
                let i = self.crtc(l.crtc_id)?;
                let size = dev.display.gamma_size();
                if size == 0 || l.gamma_size != size {
                    return Err(EINVAL);
                }
                let mut lut = alloc::vec![[0u16; 3]; size as usize];
                for (c, ptr) in [l.red, l.green, l.blue].into_iter().enumerate() {
                    let mut v = alloc::vec![0u8; size as usize * 2];
                    copy_from_user(&mut v, ptr).map_err(|_| EFAULT)?;
                    for (k, e) in lut.iter_mut().enumerate() {
                        e[c] = u16::from_le_bytes([v[2 * k], v[2 * k + 1]]);
                    }
                }
                let mut s = self.current();
                (s[i].gamma, s[i].gamma_blob) = (Some(lut), 0);
                self.commit(s, 1 << i, 0, 0, false, false).map(|_| 0)
            }
            MODE_CURSOR | MODE_CURSOR2 => {
                self.need_master()?;
                let size = if cmd & 0xff == MODE_CURSOR2 { size_of::<Cursor>() } else { size_of::<Cursor>() - 8 };
                let mut raw = [0u8; size_of::<Cursor>()];
                copy_from_user(&mut raw[..size], arg).map_err(|_| EFAULT)?;
                // SAFETY: Cursor is plain integers; the bytes were copied in
                // (the hotspot stays 0 for CURSOR).
                let c: Cursor = unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const Cursor) };
                let i = self.crtc(c.crtc_id)?;
                let mut s = self.current();
                let p = &mut s[i].cursor;
                if c.flags & MODE_CURSOR_BO != 0 {
                    if c.handle == 0 {
                        *p = Plane { dst: p.dst, ..Plane::default() };
                    } else {
                        if c.width == 0 || c.height == 0 || c.width > CURSOR_SIZE || c.height > CURSOR_SIZE {
                            return Err(EINVAL);
                        }
                        let buffer = self.buffer(c.handle)?;
                        let pitch = buffer.pitch.max(c.width * 4);
                        if u64::from(pitch) * u64::from(c.height) > buffer.size {
                            return Err(EINVAL);
                        }
                        let fb = Framebuffer {
                            id: 0,
                            buffer,
                            width: c.width,
                            height: c.height,
                            pitch,
                            offset: 0,
                            format: FORMAT_ARGB8888,
                            owner: self.id,
                        };
                        p.fb = Some(Arc::new(fb));
                        p.on = true;
                        p.src = [0, 0, c.width << 16, c.height << 16];
                        (p.dst[2], p.dst[3]) = (c.width.into(), c.height.into());
                        p.hot = (c.hot_x, c.hot_y);
                    }
                }
                if c.flags & MODE_CURSOR_MOVE != 0 {
                    (p.dst[0], p.dst[1]) = (c.x.into(), c.y.into());
                }
                if c.flags & (MODE_CURSOR_BO | MODE_CURSOR_MOVE) == 0 {
                    return Err(EINVAL);
                }
                self.commit(s, 1 << i, 0, 0, false, false).map(|_| 0)
            }
            // RMFB that leaves the screen alone: a framebuffer on the
            // screen lives on until it is replaced.
            MODE_CLOSEFB => {
                let c: CloseFb = read_user(arg).map_err(|_| EFAULT)?;
                let shown = {
                    let mut st = dev.state.lock();
                    let fb = st.fbs.remove(&c.fb_id).ok_or(ENOENT)?;
                    st.outputs.iter().any(|o| {
                        [&o.st.primary, &o.st.cursor, &o.st.overlay]
                            .iter()
                            .any(|p| p.fb.as_ref().is_some_and(|s| Arc::ptr_eq(s, &fb)))
                    })
                };
                if !shown {
                    dev.display.forget(c.fb_id);
                }
                Ok(0)
            }
            MODE_ATOMIC => {
                let a: AtomicReq = read_user(arg).map_err(|_| EFAULT)?;
                self.atomic(&a).map(|_| 0)
            }
            // Only empty leases (what wlroots asks for to get a second
            // file for its buffers): leasing objects is a GAP.
            MODE_CREATE_LEASE => rw(arg, |l: &mut CreateLease| {
                self.need_master()?;
                if l.object_count != 0 {
                    return Err(EINVAL);
                }
                let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
                let f: Arc<dyn File> = new_file(id, dev.clone(), O_RDWR | (l.flags & O_NONBLOCK), true);
                let proc = crate::proc::current().ok_or(ESRCH)?;
                l.fd = proc.files.lock().insert(f, l.flags & O_CLOEXEC != 0)? as u32;
                l.lessee_id = id as u32;
                Ok(0)
            }),
            twod::IMAGE => rw(arg, |r: &mut twod::ImageReq| {
                let t = dev.display.twod().ok_or(ENOTTY)?;
                let image = if r.addr != 0 {
                    twod::Image::of_user(r.addr, r.width, r.height, r.pitch)
                } else {
                    twod::Image::of_buffer(self.buffer(r.handle)?, r.width, r.height, r.pitch)
                };
                let image = Arc::new(image.ok_or(EINVAL)?);
                let id = {
                    let mut st = dev.state.lock();
                    st.next_image += 1;
                    st.next_image
                };
                if !t.image(id, &image) {
                    return Err(ENOMEM);
                }
                dev.state.lock().images.insert(id, (self.id, image));
                r.id = id;
                Ok(0)
            }),
            twod::FREE => {
                let id: u32 = read_user(arg).map_err(|_| EFAULT)?;
                let t = dev.display.twod().ok_or(ENOTTY)?;
                let mut st = dev.state.lock();
                match st.images.get(&id) {
                    Some((o, _)) if *o == self.id => {
                        st.images.remove(&id);
                    }
                    _ => return Err(EINVAL),
                }
                drop(st);
                t.free(id);
                Ok(0)
            }
            twod::SUBMIT => {
                let r: twod::SubmitReq = read_user(arg).map_err(|_| EFAULT)?;
                let t = dev.display.twod().ok_or(ENOTTY)?;
                if r.count > twod::MAX_OPS {
                    return Err(EINVAL);
                }
                let mut ops = Vec::with_capacity(r.count as usize);
                for i in 0..u64::from(r.count) {
                    let op: twod::Op = read_user(r.ops + i * size_of::<twod::Op>() as u64).map_err(|_| EFAULT)?;
                    ops.push(op);
                }
                // Each request's images, the file's own, holding its
                // rectangles.
                let mut work = Vec::with_capacity(ops.len());
                {
                    let st = dev.state.lock();
                    let mine = |id: u32| st.images.get(&id).filter(|(o, _)| *o == self.id).map(|(_, i)| i.clone());
                    for op in ops {
                        let dst = mine(op.dst).ok_or(EINVAL)?;
                        if !dst.holds(op.dx, op.dy, op.w, op.h) {
                            return Err(EINVAL);
                        }
                        let src = match op.kind {
                            twod::COPY | twod::BLEND | twod::BLEND_STRAIGHT => {
                                let s = mine(op.src).ok_or(EINVAL)?;
                                if !s.holds(op.sx, op.sy, op.w, op.h) {
                                    return Err(EINVAL);
                                }
                                Some(s)
                            }
                            twod::FILL => None,
                            _ => return Err(EINVAL),
                        };
                        work.push((op, src, dst));
                    }
                }
                if t.submit(&work) { Ok(0) } else { Err(EIO) }
            }
            n => {
                crate::log_warn!("drm: unimplemented ioctl {n:#x}");
                Err(ENOTTY)
            }
        }
    }

    /// When vblank `n` of CRTC `i` is (or was).
    fn vblank_time(&self, i: usize, n: u64) -> u64 {
        self.dev.state.lock().outputs[i].at(n)
    }

    /// A legacy property change: DPMS on a connector, GAMMA_LUT on a CRTC.
    fn set_property(&self, obj: Obj, prop: u32, value: u64) -> Result<()> {
        let i = obj.output();
        let mut s = self.current();
        match (obj, prop) {
            (Obj::Connector(_), PROP_DPMS) if value <= DPMS_OFF => s[i].dpms = value,
            (Obj::Crtc(_), PROP_GAMMA_LUT) if self.dev.display.gamma_size() > 0 => {
                self.set_prop(&mut s, obj, prop, value)?
            }
            _ => return Err(EINVAL),
        }
        self.commit(s, 1 << i, 0, 0, false, false)
    }
}

impl File for DrmFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            {
                let mut list = self.events.list.lock();
                if !list.is_empty() {
                    let mut n = 0;
                    while let Some(ev) = list.front() {
                        if n + ev.len() > buf.len() {
                            break;
                        }
                        buf[n..n + ev.len()].copy_from_slice(ev);
                        n += ev.len();
                        list.pop_front();
                    }
                    return if n == 0 { Err(EINVAL) } else { Ok(n) };
                }
            }
            if self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0 {
                return Err(EAGAIN);
            }
            if self.events.queue.wait_until_interruptible(|| !self.events.list.lock().is_empty()) {
                return Err(EINTR);
            }
        }
    }

    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64> {
        self.ioctl_impl(cmd, arg)
    }

    fn poll(&self) -> u16 {
        if self.events.list.lock().is_empty() { POLLOUT } else { POLLIN | POLLOUT }
    }

    fn event_count(&self) -> u64 {
        self.events.count.load(Ordering::Acquire)
    }

    fn status_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }

    fn set_status_flags(&self, flags: u32) {
        let keep = self.flags.load(Ordering::Relaxed) & !O_NONBLOCK;
        self.flags.store(keep | (flags & O_NONBLOCK), Ordering::Relaxed);
    }

    fn stat(&self) -> Result<Metadata> {
        Ok(Metadata {
            mode: vfs::S_IFCHR | 0o660,
            rdev: vfs::makedev(DRM_MAJOR, self.dev.minor),
            nlink: 1,
            ..Metadata::default()
        })
    }

    /// A card maps buffer `id` at offset `id << 32` (MAP_DUMB), and only a
    /// buffer the file holds a handle to: another client's are out of reach
    /// (ADR 0100). The mapping keeps it, as a handle would.
    fn mmap_source(&self, offset: u64) -> Option<Result<Arc<dyn Inode>>> {
        let id = offset >> 32;
        let found = self.inner.lock().handles.values().find(|b| b.id == id).cloned();
        Some(found.map(|buffer| Arc::new(MapSource { buffer, mask: 0xffff_ffff }) as Arc<dyn Inode>).ok_or(EINVAL))
    }
}

/// A dumb buffer exported as a dma-buf (PRIME).
struct DmaBuf {
    buffer: Arc<Buffer>,
    flags: u32,
}

impl File for DmaBuf {
    fn status_flags(&self) -> u32 {
        self.flags
    }
    fn mmap_source(&self, _offset: u64) -> Option<Result<Arc<dyn Inode>>> {
        Some(Ok(Arc::new(MapSource { buffer: self.buffer.clone(), mask: u64::MAX })))
    }
    fn seek(&self, offset: i64, whence: u32) -> Result<u64> {
        // dma-bufs report their size through lseek(SEEK_END).
        match whence {
            0 => Ok(offset as u64),
            2 => Ok(self.buffer.size),
            _ => Err(EINVAL),
        }
    }
}

/// A buffer's pages for mmap: file offsets masked with `mask` are offsets
/// in the buffer (a card's mappings start at `id << 32`, a dma-buf's at 0).
struct MapSource {
    buffer: Arc<Buffer>,
    mask: u64,
}

impl Inode for MapSource {
    fn metadata(&self) -> Metadata {
        Metadata { mode: vfs::S_IFREG | 0o600, nlink: 1, ..Metadata::default() }
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn shared_mmap(&self) -> bool {
        true
    }
    fn shared_page(&self, offset: u64) -> Result<PhysAddr> {
        let f = *self.buffer.frames.get(((offset & self.mask) / PAGE_SIZE) as usize).ok_or(EFAULT)?;
        frame::get_user_page(f);
        Ok(f)
    }
}
