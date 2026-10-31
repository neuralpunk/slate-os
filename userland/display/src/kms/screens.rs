// SPDX-License-Identifier: MIT OR Apache-2.0

//! Several displays at once (ADR 0170, M32 phase 3): every connected
//! output of a card, each lit in a mode of its own and placed in one
//! picture (device pixels, the outputs side by side or as the person
//! arranged them). The program draws that whole picture, and each output
//! shows its part: a frame's damage is copied to the outputs it touches
//! and marked dirty there (DIRTYFB), at most once per vblank on each (a
//! vblank event says when the last one was shown). A HOTPLUG uevent asks
//! the program to [`Screens::rebuild`].
//!
//! Structures and numbers: libdrm 2.4.124 `drm.h` and `drm_mode.h` (MIT,
//! ADR 0033), as in the parent module.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use alloc::{borrow::ToOwned, format};

use slate_rt::io;
use slate_rt::mem::Mapping;

use super::{
    ADDFB2, CONNECTED, CREATE_DUMB, CardRes, CreateDumb, Crtc, DIRTYFB, DirtyCmd, FbCmd2, GETCONNECTOR, GETENCODER,
    GETRESOURCES, GetConnector, GetEncoder, MAP_DUMB, MapDumb, ModeInfo, SETCRTC, XRGB8888, ioctl,
};

const RMFB: u32 = 0xAF;
const DESTROY_DUMB: u32 = 0xB4;
const WAIT_VBLANK: u32 = 0x3A;
/// drm_wait_vblank's type: relative, an event, the CRTC's index above 1
/// in bits 5:1 (drm.h: _DRM_VBLANK_RELATIVE, _DRM_VBLANK_EVENT,
/// _DRM_VBLANK_HIGH_CRTC_SHIFT).
const VBLANK_RELATIVE: u32 = 0x1;
const VBLANK_EVENT: u32 = 0x400_0000;
/// DRM_EVENT_VBLANK.
const EVENT_VBLANK: u32 = 0x01;
/// DRM_MODE_TYPE_PREFERRED (drm_mode.h).
const TYPE_PREFERRED: u32 = 1 << 3;
/// DRM_IOCTL_MODE_GETPROPERTY, _OBJ_GETPROPERTIES, _OBJ_SETPROPERTY.
const GETPROPERTY: u32 = 0xAA;
const OBJ_GETPROPERTIES: u32 = 0xB9;
const OBJ_SETPROPERTY: u32 = 0xBA;
/// DRM_MODE_OBJECT_CONNECTOR.
const OBJECT_CONNECTOR: u32 = 0xc0c0_c0c0;
/// DRM_MODE_DPMS_ON, DRM_MODE_DPMS_OFF.
const DPMS_ON: u64 = 0;
const DPMS_OFF: u64 = 3;

/// `struct drm_mode_obj_get_properties`.
#[repr(C)]
#[derive(Default)]
struct ObjGetProperties {
    props_ptr: u64,
    prop_values_ptr: u64,
    count_props: u32,
    obj_id: u32,
    obj_type: u32,
    pad: u32,
}

/// `struct drm_mode_get_property` (DRM_PROP_NAME_LEN is 32).
#[repr(C)]
#[derive(Default)]
struct GetProperty {
    values_ptr: u64,
    enum_blob_ptr: u64,
    prop_id: u32,
    flags: u32,
    name: [u8; 32],
    count_values: u32,
    count_enum_blobs: u32,
}

/// `struct drm_mode_obj_set_property`.
#[repr(C)]
#[derive(Default)]
struct ObjSetProperty {
    value: u64,
    prop_id: u32,
    obj_id: u32,
    obj_type: u32,
    pad: u32,
}

/// `union drm_wait_vblank` (drm.h): the request's type, sequence and
/// signal (the event's user data).
#[repr(C)]
#[derive(Default)]
struct WaitVblank {
    kind: u32,
    sequence: u32,
    signal: u64,
    pad: u64,
}

/// A connector's name as the kernel's /sys names it (drm_mode.h's
/// DRM_MODE_CONNECTOR_* numbers): its type, a dash, its number.
pub fn connector_name(kind: u32, id: u32) -> String {
    const NAMES: [&str; 21] = [
        "Unknown",
        "VGA",
        "DVI-I",
        "DVI-D",
        "DVI-A",
        "Composite",
        "SVIDEO",
        "LVDS",
        "Component",
        "DIN",
        "DP",
        "HDMI-A",
        "HDMI-B",
        "TV",
        "eDP",
        "Virtual",
        "DSI",
        "DPI",
        "Writeback",
        "SPI",
        "USB",
    ];
    format!("{}-{id}", NAMES.get(kind as usize).copied().unwrap_or("Unknown"))
}

/// A mode a display offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mode {
    pub width: u32,
    pub height: u32,
    pub refresh: u32,
    pub preferred: bool,
}

/// A connected display.
#[derive(Clone, Debug)]
pub struct Head {
    /// "Virtual-1", "DP-2", "HDMI-A-1".
    pub name: String,
    pub size_mm: (u32, u32),
    pub modes: Vec<Mode>,
    connector: u32,
    encoders: Vec<u32>,
    infos: Vec<ModeInfo>,
}

impl Head {
    /// The display's own mode: the one it prefers, else its first.
    pub fn preferred(&self) -> usize {
        self.modes.iter().position(|m| m.preferred).unwrap_or(0)
    }

    /// The mode closest to `want` (size, then refresh), if it has that size.
    fn find(&self, want: (u32, u32, u32)) -> Option<usize> {
        let (w, h, hz) = want;
        self.modes
            .iter()
            .enumerate()
            .filter(|(_, m)| (m.width, m.height) == (w, h))
            .min_by_key(|(_, m)| m.refresh.abs_diff(hz))
            .map(|(i, _)| i)
    }
}

/// What the person asked of a display (by its name): on or off, where its
/// top left corner is (logical pixels: [`Screens::rebuild`] scales them),
/// its mode, whether it is primary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Want {
    pub name: String,
    pub on: bool,
    pub x: i32,
    pub y: i32,
    /// Width, height, refresh rate; None for the display's own.
    pub mode: Option<(u32, u32, u32)>,
    pub primary: bool,
}

/// Where a display goes, in one picture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placed {
    pub head: usize,
    pub mode: usize,
    pub x: i32,
    pub y: i32,
}

/// The displays to light and where, from what is connected and what the
/// person asked: displays they placed go where they said, in the mode
/// they chose if it is still offered (else the display's own); displays
/// they never placed go to the right of the others, tops aligned, in
/// their own mode. Off ones stay off, unless all are: then the first is
/// on. At most `crtcs` are lit. The picture starts at (0, 0). The first
/// placed is the primary: the one asked to be, else the first lit.
pub fn arrange(heads: &[Head], wants: &[Want], crtcs: usize) -> Vec<Placed> {
    let mut out: Vec<Placed> = Vec::new();
    let mut primary: Option<usize> = None;
    let mut unplaced = Vec::new();
    for (i, h) in heads.iter().enumerate() {
        if h.modes.is_empty() {
            continue;
        }
        match wants.iter().find(|w| w.name == h.name) {
            Some(w) if !w.on => {}
            Some(w) => {
                let mode = w.mode.and_then(|m| h.find(m)).unwrap_or(h.preferred());
                if w.primary && primary.is_none() {
                    primary = Some(out.len());
                }
                out.push(Placed { head: i, mode, x: w.x, y: w.y });
            }
            None => unplaced.push(i),
        }
    }
    for i in unplaced {
        let x = out.iter().map(|p| p.x + heads[p.head].modes[p.mode].width as i32).max().unwrap_or(0);
        let y = out.iter().map(|p| p.y).min().unwrap_or(0);
        out.push(Placed { head: i, mode: heads[i].preferred(), x, y });
    }
    if out.is_empty()
        && let Some(i) = heads.iter().position(|h| !h.modes.is_empty())
    {
        out.push(Placed { head: i, mode: heads[i].preferred(), x: 0, y: 0 });
    }
    out.truncate(crtcs);
    if let Some(p) = primary.filter(|&p| p < out.len()) {
        let first = out.remove(p);
        out.insert(0, first);
    }
    let (x0, y0) = (out.iter().map(|p| p.x).min().unwrap_or(0), out.iter().map(|p| p.y).min().unwrap_or(0));
    for p in &mut out {
        p.x -= x0;
        p.y -= y0;
    }
    out
}

/// A lit display.
#[derive(Debug)]
pub struct Output {
    pub name: String,
    pub mode: Mode,
    /// Where it is in the picture (device pixels).
    pub x: i32,
    pub y: i32,
    crtc_index: usize,
    fb: u32,
    handle: u32,
    pitch: usize,
    buffer: Mapping,
    /// A vblank event asked for and not yet come (when it was asked, ns):
    /// it has not shown the last frame yet.
    waiting: Option<i64>,
    /// When its last vblank event said it showed a frame (ns, the
    /// monotonic clock).
    shown_at: Option<i64>,
}

impl Output {
    pub fn rect(&self) -> (i32, i32, i32, i32) {
        (self.x, self.y, self.mode.width as i32, self.mode.height as i32)
    }
}

/// Every lit display of a card.
#[derive(Debug)]
pub struct Screens {
    fd: i32,
    /// The connected displays (lit or not).
    pub heads: Vec<Head>,
    /// The lit ones, the primary first.
    pub outputs: Vec<Output>,
    /// The picture's size (device pixels).
    pub width: i32,
    pub height: i32,
    /// Device pixels a logical one, the same on every display.
    pub scale: f32,
    crtcs: Vec<u32>,
    /// Night Light's tint (ADR 0186), applied as frames are shown.
    pub tint: Option<[u32; 3]>,
}

/// `a` ∩ `b`, each (x, y, w, h).
fn meet(a: (i32, i32, i32, i32), b: (i32, i32, i32, i32)) -> Option<(i32, i32, i32, i32)> {
    let (x0, y0) = (a.0.max(b.0), a.1.max(b.1));
    let (x1, y1) = ((a.0 + a.2).min(b.0 + b.2), (a.1 + a.3).min(b.1 + b.3));
    (x1 > x0 && y1 > y0).then_some((x0, y0, x1 - x0, y1 - y0))
}

impl Screens {
    /// Light the displays of the card open on `fd` as `wants` asks, at
    /// the scale `scale_of` gives for the primary display's size.
    pub fn open(fd: i32, wants: &[Want], scale_of: &dyn Fn(u32, u32) -> f32) -> Result<Screens, String> {
        let mut s = Screens {
            fd,
            heads: Vec::new(),
            outputs: Vec::new(),
            width: 0,
            height: 0,
            scale: 1.0,
            crtcs: Vec::new(),
            tint: None,
        };
        s.rebuild(wants, scale_of)?;
        Ok(s)
    }

    pub fn fd(&self) -> i32 {
        self.fd
    }

    /// Whether the displays connected now differ from those lit (one
    /// plugged in or taken out before anything listened for hotplugs).
    pub fn heads_changed(&self) -> bool {
        let Ok((_, conns)) = resources(self.fd) else { return false };
        let now: Vec<String> =
            conns.iter().filter_map(|&id| head(self.fd, id).ok().flatten()).map(|h| h.name).collect();
        now != self.heads.iter().map(|h| h.name.clone()).collect::<Vec<_>>()
    }

    /// Read what is connected again and light it as `wants` asks (after
    /// a hotplug, or the person's new arrangement), at the scale
    /// `scale_of` gives for the primary display's size. The old buffers go.
    pub fn rebuild(&mut self, wants: &[Want], scale_of: &dyn Fn(u32, u32) -> f32) -> Result<(), String> {
        self.release();
        let (crtcs, conns) = resources(self.fd)?;
        self.crtcs = crtcs;
        self.heads = conns.iter().filter_map(|&id| head(self.fd, id).ok().flatten()).collect();
        // The primary display and its mode give the scale; then the
        // places, in device pixels.
        let first = arrange(&self.heads, wants, self.crtcs.len());
        let p = first.first().ok_or("no connected display")?;
        let m = self.heads[p.head].modes[p.mode];
        self.scale = scale_of(m.width, m.height);
        let k = self.scale;
        let device: Vec<Want> = wants
            .iter()
            .map(|w| Want { x: (w.x as f32 * k) as i32, y: (w.y as f32 * k) as i32, ..w.clone() })
            .collect();
        let placed = arrange(&self.heads, &device, self.crtcs.len());
        if placed.is_empty() {
            return Err("no connected display".to_owned());
        }
        let mut used = vec![false; self.crtcs.len()];
        for p in placed {
            let h = &self.heads[p.head];
            let Some(ci) = self.crtc_for(h, &used) else { continue };
            used[ci] = true;
            let info = h.infos[p.mode];
            let (w, h_px) = (u32::from(info.hdisplay), u32::from(info.vdisplay));
            let mut dumb = CreateDumb { width: w, height: h_px, bpp: 32, ..CreateDumb::default() };
            ioctl(self.fd, CREATE_DUMB, &mut dumb, "dumb buffer")?;
            let mut map = MapDumb { handle: dumb.handle, ..MapDumb::default() };
            ioctl(self.fd, MAP_DUMB, &mut map, "mapping the buffer")?;
            let buffer = Mapping::shared(self.fd, dumb.size as usize, map.offset).map_err(|e| format!("mmap: {e}"))?;
            let mut fb = FbCmd2 { width: w, height: h_px, pixel_format: XRGB8888, ..FbCmd2::default() };
            fb.handles[0] = dumb.handle;
            fb.pitches[0] = dumb.pitch;
            ioctl(self.fd, ADDFB2, &mut fb, "framebuffer")?;
            let mut conn_id = h.connector;
            let mut set = Crtc {
                set_connectors_ptr: &mut conn_id as *mut u32 as u64,
                count_connectors: 1,
                crtc_id: self.crtcs[ci],
                fb_id: fb.fb_id,
                mode_valid: 1,
                mode: info,
                ..Crtc::default()
            };
            ioctl(self.fd, SETCRTC, &mut set, "setting the mode")?;
            self.outputs.push(Output {
                name: h.name.clone(),
                mode: h.modes[p.mode],
                x: p.x,
                y: p.y,
                crtc_index: ci,
                fb: fb.fb_id,
                handle: dumb.handle,
                pitch: dumb.pitch as usize / 4,
                buffer,
                waiting: None,
                shown_at: None,
            });
        }
        // CRTCs not used: off (a display left on would show the console).
        for (ci, &crtc) in self.crtcs.iter().enumerate() {
            if !used[ci] {
                let mut off = Crtc { crtc_id: crtc, ..Crtc::default() };
                let _ = ioctl(self.fd, SETCRTC, &mut off, "switching off");
            }
        }
        self.width = self.outputs.iter().map(|o| o.x + o.mode.width as i32).max().unwrap_or(0);
        self.height = self.outputs.iter().map(|o| o.y + o.mode.height as i32).max().unwrap_or(0);
        Ok(())
    }

    /// A free CRTC an encoder of `h` can drive (its possible_crtcs bits).
    fn crtc_for(&self, h: &Head, used: &[bool]) -> Option<usize> {
        for &e in &h.encoders {
            let mut enc = GetEncoder { encoder_id: e, ..GetEncoder::default() };
            if ioctl(self.fd, GETENCODER, &mut enc, "encoder").is_err() {
                continue;
            }
            if let Some(i) = (0..self.crtcs.len()).find(|&i| !used[i] && enc.possible_crtcs & (1 << i) != 0) {
                return Some(i);
            }
        }
        (0..self.crtcs.len()).find(|&i| !used[i])
    }

    /// Remove the buffers and framebuffers of the lit outputs.
    fn release(&mut self) {
        for o in self.outputs.drain(..) {
            let mut fb = o.fb;
            let _ = ioctl(self.fd, RMFB, &mut fb, "removing the framebuffer");
            drop(o.buffer);
            let mut h = o.handle;
            let _ = ioctl(self.fd, DESTROY_DUMB, &mut h, "destroying the buffer");
        }
    }

    /// Whether any output has yet to show the last frame given it: the
    /// next frame waits for its vblank. An event that hasn't come in 50 ms
    /// isn't waited for.
    pub fn waiting(&self) -> bool {
        let now = now_ns();
        self.outputs.iter().any(|o| o.waiting.is_some_and(|at| now - at < 50_000_000))
    }

    /// Turn the displays' power on or off (their connectors' DPMS
    /// property): blanking after a while without input (ADR 0186).
    pub fn set_power(&mut self, on: bool) -> Result<(), String> {
        let names: Vec<String> = self.outputs.iter().map(|o| o.name.clone()).collect();
        for name in names {
            let Some(conn) = self.heads.iter().find(|h| h.name == name).map(|h| h.connector) else { continue };
            let Some(prop) = self.property(conn, "DPMS")? else { continue };
            let mut set = ObjSetProperty {
                value: if on { DPMS_ON } else { DPMS_OFF },
                prop_id: prop,
                obj_id: conn,
                obj_type: OBJECT_CONNECTOR,
                pad: 0,
            };
            ioctl(self.fd, OBJ_SETPROPERTY, &mut set, "setting DPMS")?;
        }
        Ok(())
    }

    /// The id of connector `conn`'s property `name`.
    fn property(&self, conn: u32, name: &str) -> Result<Option<u32>, String> {
        let mut g = ObjGetProperties { obj_id: conn, obj_type: OBJECT_CONNECTOR, ..ObjGetProperties::default() };
        ioctl(self.fd, OBJ_GETPROPERTIES, &mut g, "connector properties")?;
        let n = g.count_props as usize;
        let mut ids = vec![0u32; n];
        let mut values = vec![0u64; n];
        g.props_ptr = ids.as_mut_ptr() as u64;
        g.prop_values_ptr = values.as_mut_ptr() as u64;
        ioctl(self.fd, OBJ_GETPROPERTIES, &mut g, "connector properties")?;
        for &id in ids.iter().take(g.count_props as usize) {
            let mut p = GetProperty { prop_id: id, ..GetProperty::default() };
            ioctl(self.fd, GETPROPERTY, &mut p, "a property")?;
            let end = p.name.iter().position(|&b| b == 0).unwrap_or(p.name.len());
            if &p.name[..end] == name.as_bytes() {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    /// When the next frame will be seen (ns, the monotonic clock): the
    /// primary output's first vblank after `now`, from its last one and
    /// its refresh rate (ADR 0186: motion is worked out for when it is
    /// shown, so its steps are even). `now` when unknown.
    pub fn next_vblank(&self, now: i64) -> i64 {
        let Some(o) = self.outputs.first() else { return now };
        next_vblank(o.shown_at, o.mode.refresh, now)
    }

    /// Read the card's events: each vblank event frees its output.
    pub fn read_events(&mut self) {
        let mut ev = [0u8; 1024];
        let Ok(n) = io::read(self.fd, &mut ev) else { return };
        let mut at = 0;
        while at + 8 <= n {
            let kind = u32::from_le_bytes(ev[at..at + 4].try_into().unwrap());
            let len = u32::from_le_bytes(ev[at + 4..at + 8].try_into().unwrap()) as usize;
            // struct drm_event_vblank: the user data at 8.
            if kind == EVENT_VBLANK && at + 16 <= n {
                let i = u64::from_le_bytes(ev[at + 8..at + 16].try_into().unwrap()) as usize;
                if let Some(o) = self.outputs.get_mut(i) {
                    o.waiting = None;
                    // tv_sec and tv_usec at 16 and 20.
                    if at + 24 <= n {
                        let sec = u32::from_le_bytes(ev[at + 16..at + 20].try_into().unwrap()) as i64;
                        let usec = u32::from_le_bytes(ev[at + 20..at + 24].try_into().unwrap()) as i64;
                        o.shown_at = Some(sec * 1_000_000_000 + usec * 1000);
                    }
                }
            }
            at += len.max(8);
        }
    }

    /// Ask for output `i`'s next vblank as an event.
    fn ask_vblank(&mut self, i: usize) {
        let o = &mut self.outputs[i];
        let high = ((o.crtc_index as u32) << 1) & 0x3E;
        let mut w = WaitVblank { kind: VBLANK_RELATIVE | VBLANK_EVENT | high, sequence: 1, signal: i as u64, pad: 0 };
        // Without the event (an older kernel), frames just aren't paced.
        o.waiting = ioctl(self.fd, WAIT_VBLANK, &mut w, "vblank event").is_ok().then(now_ns);
    }

    /// Show the rectangles `rects` (x, y, w, h in the picture) of
    /// `pixels` (the whole picture, `self.width` wide): each output gets
    /// the parts on it, marked dirty, and waits for its vblank.
    pub fn present_rects(&mut self, pixels: &[u32], rects: &[(i32, i32, i32, i32)]) {
        self.present(pixels, rects, false);
    }

    /// The whole picture changed (written into each output's buffer
    /// through [`Screens::each_buffer`]); `rects` of `pixels` go over it.
    pub fn present_rects_over(&mut self, pixels: &[u32], rects: &[(i32, i32, i32, i32)]) {
        self.present(pixels, rects, true);
    }

    fn present(&mut self, pixels: &[u32], rects: &[(i32, i32, i32, i32)], whole: bool) {
        let pw = self.width as usize;
        for i in 0..self.outputs.len() {
            let o = &mut self.outputs[i];
            let r = o.rect();
            let words = o.buffer.words_mut();
            let mut clips: Vec<[u16; 4]> = Vec::new();
            for &rect in rects.iter() {
                let Some((x, y, w, h)) = meet(rect, r) else { continue };
                for row in y..y + h {
                    let (lx, ly) = ((x - r.0) as usize, (row - r.1) as usize);
                    let src = pixels.get(row as usize * pw + x as usize..row as usize * pw + (x + w) as usize);
                    let dst = words.get_mut(ly * o.pitch + lx..ly * o.pitch + lx + w as usize);
                    if let (Some(d), Some(s)) = (dst, src) {
                        match self.tint.filter(|_| !whole) {
                            Some(t) => tint_row(d, s, t),
                            None => d.copy_from_slice(s),
                        }
                    }
                }
                // struct drm_clip_rect (libdrm drm.h): x1, y1, x2, y2.
                let (lx, ly) = ((x - r.0) as u16, (y - r.1) as u16);
                clips.push([lx, ly, lx + w as u16, ly + h as u16]);
            }
            if whole {
                clips = vec![[0, 0, r.2 as u16, r.3 as u16]];
                // The whole buffer, put there by the caller too: tinted
                // once, in place.
                if let Some(t) = self.tint {
                    for row in 0..r.3 as usize {
                        let line = &mut words[row * o.pitch..row * o.pitch + r.2 as usize];
                        tint_in_place(line, t);
                    }
                }
            }
            if clips.is_empty() {
                continue;
            }
            clips.truncate(64);
            let mut d = DirtyCmd {
                fb_id: o.fb,
                num_clips: clips.len() as u32,
                clips_ptr: clips.as_ptr() as u64,
                ..DirtyCmd::default()
            };
            let _ = ioctl(self.fd, DIRTYFB, &mut d, "dirtyfb");
            self.ask_vblank(i);
        }
    }

    /// Each output's buffer, with its place in the picture and its pitch
    /// in words: to write a frame straight to the screens.
    pub fn each_buffer(&mut self, mut f: impl FnMut((i32, i32, i32, i32), &mut [u32], usize)) {
        for o in &mut self.outputs {
            let r = o.rect();
            f(r, o.buffer.words_mut(), o.pitch);
        }
    }
}

impl Drop for Screens {
    fn drop(&mut self) {
        self.release();
        // Give the screens back to the console.
        let _ = io::ioctl(self.fd, super::io_(super::DROP_MASTER), 0);
        let _ = io::close(self.fd);
    }
}

/// Each channel of `src`'s pixels scaled by `t` (red, green, blue, of
/// 256) into `dst`: Night Light (ADR 0186).
pub fn tint_row(dst: &mut [u32], src: &[u32], t: [u32; 3]) {
    for (d, &p) in dst.iter_mut().zip(src) {
        *d = tint(p, t);
    }
}

/// [`tint_row`] in place.
pub fn tint_in_place(row: &mut [u32], t: [u32; 3]) {
    for p in row.iter_mut() {
        *p = tint(*p, t);
    }
}

#[inline(always)]
fn tint(p: u32, t: [u32; 3]) -> u32 {
    let r = (((p >> 16) & 0xFF) * t[0]) >> 8;
    let g = (((p >> 8) & 0xFF) * t[1]) >> 8;
    let b = ((p & 0xFF) * t[2]) >> 8;
    (p & 0xFF00_0000) | (r.min(255) << 16) | (g.min(255) << 8) | b.min(255)
}

/// Night Light's tint at `warmth` (1 to 5): red kept, green and blue
/// lowered toward a candle's colour, roughly 5500 K to 3000 K.
pub fn warmth_tint(warmth: u8) -> [u32; 3] {
    match warmth.clamp(1, 5) {
        1 => [256, 236, 206],
        2 => [256, 225, 184],
        3 => [256, 214, 163],
        4 => [256, 199, 137],
        _ => [256, 180, 107],
    }
}

/// The first vblank after `now`, for a display that last showed a frame
/// at `shown_at` and refreshes `hz` times a second.
pub fn next_vblank(shown_at: Option<i64>, hz: u32, now: i64) -> i64 {
    let (Some(at), true) = (shown_at, hz > 0) else { return now };
    let period = 1_000_000_000 / i64::from(hz);
    if at > now {
        return at;
    }
    at + ((now - at) / period + 1) * period
}

fn now_ns() -> i64 {
    let (s, ns) = slate_rt::time::now(slate_rt::time::CLOCK_MONOTONIC);
    s * 1_000_000_000 + ns
}

/// The card's CRTCs and connectors.
fn resources(fd: i32) -> Result<(Vec<u32>, Vec<u32>), String> {
    let mut res = CardRes::default();
    ioctl(fd, GETRESOURCES, &mut res, "resources")?;
    let mut crtcs = vec![0u32; res.count_crtcs as usize];
    let mut conns = vec![0u32; res.count_connectors as usize];
    let mut encs = vec![0u32; res.count_encoders as usize];
    res = CardRes {
        crtcs: crtcs.as_mut_ptr() as u64,
        connectors: conns.as_mut_ptr() as u64,
        encoders: encs.as_mut_ptr() as u64,
        count_crtcs: crtcs.len() as u32,
        count_connectors: conns.len() as u32,
        count_encoders: encs.len() as u32,
        ..CardRes::default()
    };
    ioctl(fd, GETRESOURCES, &mut res, "resources")?;
    Ok((crtcs, conns))
}

/// A connector, if something is connected to it.
fn head(fd: i32, id: u32) -> Result<Option<Head>, String> {
    let mut c = GetConnector { connector_id: id, ..GetConnector::default() };
    ioctl(fd, GETCONNECTOR, &mut c, "connector")?;
    if c.connection != CONNECTED || c.count_modes == 0 {
        return Ok(None);
    }
    let mut infos = vec![ModeInfo::default(); c.count_modes as usize];
    let mut encoders: Vec<u32> = vec![0; c.count_encoders as usize];
    let mut c2 = GetConnector {
        connector_id: id,
        modes: infos.as_mut_ptr() as u64,
        count_modes: infos.len() as u32,
        encoders: encoders.as_mut_ptr() as u64,
        count_encoders: encoders.len() as u32,
        ..GetConnector::default()
    };
    ioctl(fd, GETCONNECTOR, &mut c2, "connector")?;
    infos.truncate(c2.count_modes as usize);
    if c2.encoder_id != 0 {
        encoders.insert(0, c2.encoder_id);
    }
    let modes = infos
        .iter()
        .map(|m| Mode {
            width: u32::from(m.hdisplay),
            height: u32::from(m.vdisplay),
            refresh: m.vrefresh,
            preferred: m.kind & TYPE_PREFERRED != 0,
        })
        .collect();
    Ok(Some(Head {
        name: connector_name(c2.connector_type, c2.connector_type_id),
        size_mm: (c2.mm_width, c2.mm_height),
        modes,
        connector: id,
        encoders,
        infos,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tinted() {
        let mut d = [0u32; 2];
        tint_row(&mut d, &[0xFFFF_FFFF, 0xFF10_2030], [256, 128, 0]);
        assert_eq!(d, [0xFFFF_7F00, 0xFF10_1000]);
        let mut row = [0xFF80_8080];
        tint_in_place(&mut row, warmth_tint(3));
        assert_eq!(row[0] >> 16 & 0xFF, 0x80);
        assert!((row[0] & 0xFF) < (row[0] >> 8 & 0xFF));
    }

    #[test]
    fn vblanks_ahead() {
        // 60 Hz: a period of 16 666 666 ns.
        let p = 16_666_666;
        assert_eq!(next_vblank(None, 60, 5), 5);
        assert_eq!(next_vblank(Some(1000), 0, 5000), 5000);
        assert_eq!(next_vblank(Some(1000), 60, 1000), 1000 + p);
        assert_eq!(next_vblank(Some(1000), 60, 1000 + p - 1), 1000 + p);
        assert_eq!(next_vblank(Some(1000), 60, 1000 + p), 1000 + 2 * p);
        assert_eq!(next_vblank(Some(1000), 60, 1000 + 10 * p + 7), 1000 + 11 * p);
        // One the event names ahead of now.
        assert_eq!(next_vblank(Some(9000), 60, 1000), 9000);
    }

    fn head(name: &str, modes: &[(u32, u32, u32)]) -> Head {
        Head {
            name: name.into(),
            size_mm: (0, 0),
            modes: modes
                .iter()
                .enumerate()
                .map(|(i, &(width, height, refresh))| Mode { width, height, refresh, preferred: i == 0 })
                .collect(),
            connector: 0,
            encoders: Vec::new(),
            infos: Vec::new(),
        }
    }

    fn want(name: &str, x: i32, y: i32) -> Want {
        Want { name: name.into(), on: true, x, y, mode: None, primary: false }
    }

    #[test]
    fn side_by_side_unless_placed() {
        let heads = [head("Virtual-1", &[(1280, 800, 60)]), head("Virtual-2", &[(1024, 768, 60), (800, 600, 60)])];
        // Never placed: left to right, tops aligned, own modes.
        let p = arrange(&heads, &[], 4);
        assert_eq!(p, [Placed { head: 0, mode: 0, x: 0, y: 0 }, Placed { head: 1, mode: 0, x: 1280, y: 0 }]);
        // Placed: the second left of and below the first, in 800x600; the
        // picture starts at (0, 0).
        let mut b = want("Virtual-2", -800, 100);
        b.mode = Some((800, 600, 60));
        let p = arrange(&heads, &[want("Virtual-1", 0, 0), b], 4);
        assert_eq!(p, [Placed { head: 0, mode: 0, x: 800, y: 0 }, Placed { head: 1, mode: 1, x: 0, y: 100 }]);
        // A mode no longer offered: the display's own.
        let mut c = want("Virtual-2", 1280, 0);
        c.mode = Some((640, 480, 60));
        assert_eq!(arrange(&heads, &[c], 4)[0].mode, 0);
    }

    #[test]
    fn primary_off_and_too_many() {
        let heads = [head("DP-1", &[(1920, 1080, 144)]), head("HDMI-A-1", &[(3840, 2160, 60)])];
        // The primary comes first, wherever it is.
        let mut b = want("HDMI-A-1", 1920, 0);
        b.primary = true;
        let p = arrange(&heads, &[want("DP-1", 0, 0), b], 4);
        assert_eq!((p[0].head, p[0].x), (1, 1920));
        // Off is off; all off lights the first.
        let mut off = want("DP-1", 0, 0);
        off.on = false;
        assert_eq!(arrange(&heads, &[off.clone()], 4), [Placed { head: 1, mode: 0, x: 0, y: 0 }]);
        let mut off2 = want("HDMI-A-1", 0, 0);
        off2.on = false;
        assert_eq!(arrange(&heads, &[off, off2], 4), [Placed { head: 0, mode: 0, x: 0, y: 0 }]);
        // More displays than CRTCs: the first ones.
        assert_eq!(arrange(&heads, &[], 1).len(), 1);
    }

    #[test]
    fn names_and_rects() {
        assert_eq!(connector_name(15, 2), "Virtual-2");
        assert_eq!(connector_name(11, 1), "HDMI-A-1");
        assert_eq!(connector_name(10, 3), "DP-3");
        assert_eq!(connector_name(99, 1), "Unknown-1");
        assert_eq!(meet((0, 0, 100, 100), (50, 20, 100, 100)), Some((50, 20, 50, 80)));
        assert_eq!(meet((0, 0, 10, 10), (10, 0, 10, 10)), None);
    }
}
