// SPDX-License-Identifier: MIT OR Apache-2.0

//! The graphical installer's and the login screen's screen: the first
//! connected display of the card ([`card`]: a GPU driver's before the
//! firmware framebuffer's), the others dark, through legacy
//! kernel mode setting (ADR 0033's DRM, ADR 0034). Strata uses every
//! display ([`screens`], ADR 0170). A program draws into a canvas and either copies
//! it into the one buffer and marks it dirty (Strata, with its own
//! damage), or, double-buffered (the installer, ADR 0101), finds what
//! changed since the last frame, copies only that into the buffer not on
//! the screen and flips to it, a frame at a time.
//!
//! Structures and numbers: libdrm 2.4.124 `drm.h` and `drm_mode.h` (MIT,
//! ADR 0033), as in tests/user/drm.c.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use slate_rt::mem::Mapping;
use slate_rt::{fs, io};

pub mod screens;

/// `_IOWR('d', nr, size)` (the ioctl number encoding of asm-generic/ioctl.h).
const fn iowr(nr: u32, size: usize) -> u32 {
    0xC000_0000 | ((size as u32) << 16) | ((b'd' as u32) << 8) | nr
}

const fn io_(nr: u32) -> u32 {
    ((b'd' as u32) << 8) | nr
}

// drm.h / drm_mode.h ioctl numbers.
const VERSION: u32 = 0x00;
const GETRESOURCES: u32 = 0xA0;
const SETCRTC: u32 = 0xA2;
const GETENCODER: u32 = 0xA6;
const GETCONNECTOR: u32 = 0xA7;
const DIRTYFB: u32 = 0xB1;
const PAGE_FLIP: u32 = 0xB0;
const PAGE_FLIP_EVENT: u32 = 1;
/// The flip-complete event's type (drm.h DRM_EVENT_FLIP_COMPLETE).
const EVENT_FLIP_COMPLETE: u32 = 2;
const CREATE_DUMB: u32 = 0xB2;
const MAP_DUMB: u32 = 0xB3;
const ADDFB2: u32 = 0xB8;
const DROP_MASTER: u32 = 0x1f;
/// DRM_FORMAT_XRGB8888, fourcc_code('X', 'R', '2', '4') (drm_fourcc.h).
const XRGB8888: u32 = 0x3432_5258;
/// DRM_MODE_CONNECTED.
const CONNECTED: u32 = 1;

/// struct drm_mode_card_res.
#[repr(C)]
#[derive(Default)]
struct CardRes {
    fbs: u64,
    crtcs: u64,
    connectors: u64,
    encoders: u64,
    count_fbs: u32,
    count_crtcs: u32,
    count_connectors: u32,
    count_encoders: u32,
    min_width: u32,
    max_width: u32,
    min_height: u32,
    max_height: u32,
}

/// struct drm_mode_modeinfo.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
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
    name: [u8; 32],
}

/// struct drm_mode_get_connector.
#[repr(C)]
#[derive(Default)]
struct GetConnector {
    encoders: u64,
    modes: u64,
    props: u64,
    prop_values: u64,
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

/// struct drm_mode_get_encoder.
#[repr(C)]
#[derive(Default)]
struct GetEncoder {
    encoder_id: u32,
    encoder_type: u32,
    crtc_id: u32,
    possible_crtcs: u32,
    possible_clones: u32,
}

/// struct drm_mode_crtc.
#[repr(C)]
#[derive(Default)]
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

/// struct drm_mode_create_dumb.
#[repr(C)]
#[derive(Default)]
struct CreateDumb {
    height: u32,
    width: u32,
    bpp: u32,
    flags: u32,
    handle: u32,
    pitch: u32,
    size: u64,
}

/// struct drm_mode_map_dumb.
#[repr(C)]
#[derive(Default)]
struct MapDumb {
    handle: u32,
    pad: u32,
    offset: u64,
}

/// struct drm_mode_fb_cmd2.
#[repr(C)]
#[derive(Default)]
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

/// struct drm_mode_fb_dirty_cmd.
#[repr(C)]
#[derive(Default)]
struct DirtyCmd {
    fb_id: u32,
    flags: u32,
    color: u32,
    num_clips: u32,
    clips_ptr: u64,
}

/// struct drm_version (drm.h).
#[repr(C)]
#[derive(Default)]
struct Version {
    major: i32,
    minor: i32,
    patchlevel: i32,
    name_len: usize,
    name: u64,
    date_len: usize,
    date: u64,
    desc_len: usize,
    desc: u64,
}

/// The firmware framebuffer's driver name (the kernel's drm::bootfb).
const FIRMWARE_FB: &[u8] = b"slate-fb";

/// The card to show on: the first whose driver is a GPU's (a card that
/// lit a display itself), else the first card, the firmware framebuffer
/// the loader left. A GPU driver's card may come after the firmware's:
/// it lights its display once its firmware is loaded.
pub fn card() -> Vec<u8> {
    for n in 0..8u8 {
        let path = format!("/dev/dri/card{n}");
        let Ok(fd) = fs::open(path.as_bytes(), fs::O_RDWR | fs::O_CLOEXEC, 0) else { break };
        let mut name = [0u8; 32];
        let mut v = Version { name_len: name.len(), name: name.as_mut_ptr() as u64, ..Default::default() };
        let got = ioctl(fd, VERSION, &mut v, "version").is_ok();
        let _ = io::close(fd);
        if got && &name[..v.name_len.min(name.len())] != FIRMWARE_FB {
            return path.into_bytes();
        }
    }
    b"/dev/dri/card0".to_vec()
}

fn ioctl<T>(fd: i32, nr: u32, arg: &mut T, what: &str) -> Result<(), String> {
    io::ioctl(fd, iowr(nr, core::mem::size_of::<T>()), arg as *mut T as usize)
        .map(|_| ())
        .map_err(|e| format!("{what}: {e}"))
}

/// The display, showing our buffer.
#[derive(Debug)]
pub struct Display {
    fd: i32,
    pub width: i32,
    pub height: i32,
    fb: u32,
    pitch: usize,
    buffer: Mapping,
    crtc: u32,
    /// Double buffering: the other buffer, what it still lacks, the last
    /// frame shown, and whether a flip is on its way.
    back: Option<Back>,
}

#[derive(Debug)]
struct Back {
    fb: u32,
    buffer: Mapping,
    /// Rectangles changed on the screen since this buffer was last shown.
    stale: Vec<(usize, usize, usize, usize)>,
    last: Vec<u32>,
    flipping: bool,
}

/// struct drm_mode_crtc_page_flip.
#[repr(C)]
#[derive(Default)]
struct PageFlip {
    crtc_id: u32,
    fb_id: u32,
    flags: u32,
    reserved: u32,
    user_data: u64,
}

/// The rectangles (x, y, width, height) where `new` differs from `old`
/// (both `w` wide): runs of changed rows, each as wide as its changes.
pub fn changes(old: &[u32], new: &[u32], w: usize) -> Vec<(usize, usize, usize, usize)> {
    let mut out: Vec<(usize, usize, usize, usize)> = Vec::new();
    let mut run: Option<(usize, usize, usize, usize)> = None;
    for (y, (a, b)) in old.chunks(w).zip(new.chunks(w)).enumerate() {
        let first = a.iter().zip(b).position(|(p, q)| p != q);
        match first {
            Some(x0) => {
                let x1 = w - a.iter().zip(b).rev().position(|(p, q)| p != q).unwrap_or(0);
                run = Some(match run {
                    Some((rx0, ry, rx1, _)) => (rx0.min(x0), ry, rx1.max(x1), y + 1),
                    None => (x0, y, x1, y + 1),
                });
            }
            None => {
                if let Some((x0, y0, x1, y1)) = run.take() {
                    out.push((x0, y0, x1 - x0, y1 - y0));
                }
            }
        }
    }
    if let Some((x0, y0, x1, y1)) = run {
        out.push((x0, y0, x1 - x0, y1 - y0));
    }
    out
}

impl Display {
    /// Open the [`card`] and show a black buffer on its first connected
    /// output, in its first (preferred) mode.
    pub fn open() -> Result<Display, String> {
        let card = card();
        let fd = fs::open(&card, fs::O_RDWR | fs::O_CLOEXEC, 0)
            .map_err(|e| format!("{}: {e}", String::from_utf8_lossy(&card)))?;
        Display::setup(fd).inspect_err(|_| {
            let _ = io::close(fd);
        })
    }

    /// Show on a card already open (from seatd).
    pub fn from_fd(fd: i32) -> Result<Display, String> {
        Display::setup(fd).inspect_err(|_| {
            let _ = io::close(fd);
        })
    }

    fn setup(fd: i32) -> Result<Display, String> {
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
        let (conn, mode, encoder) = conns
            .iter()
            .find_map(|&id| connector(fd, id).ok().flatten())
            .ok_or_else(|| String::from("no connected display"))?;
        let crtc = if encoder != 0 {
            let mut e = GetEncoder { encoder_id: encoder, ..GetEncoder::default() };
            ioctl(fd, GETENCODER, &mut e, "encoder")?;
            e.crtc_id
        } else {
            0
        };
        let crtc = if crtc != 0 { crtc } else { *crtcs.first().ok_or("no CRTC")? };
        let (w, h) = (u32::from(mode.hdisplay), u32::from(mode.vdisplay));
        let mut dumb = CreateDumb { width: w, height: h, bpp: 32, ..CreateDumb::default() };
        ioctl(fd, CREATE_DUMB, &mut dumb, "dumb buffer")?;
        let mut map = MapDumb { handle: dumb.handle, ..MapDumb::default() };
        ioctl(fd, MAP_DUMB, &mut map, "mapping the buffer")?;
        let buffer = Mapping::shared(fd, dumb.size as usize, map.offset).map_err(|e| format!("mmap: {e}"))?;
        let mut fb = FbCmd2 { width: w, height: h, pixel_format: XRGB8888, ..FbCmd2::default() };
        fb.handles[0] = dumb.handle;
        fb.pitches[0] = dumb.pitch;
        ioctl(fd, ADDFB2, &mut fb, "framebuffer")?;
        let mut conn_id = conn;
        let mut set = Crtc {
            set_connectors_ptr: &mut conn_id as *mut u32 as u64,
            count_connectors: 1,
            crtc_id: crtc,
            fb_id: fb.fb_id,
            mode_valid: 1,
            mode,
            ..Crtc::default()
        };
        ioctl(fd, SETCRTC, &mut set, "setting the mode")?;
        // The program is on the first display only (the installer, the
        // login screen; ADR 0170): the card's other outputs go dark rather
        // than keep the console.
        for &other in crtcs.iter().filter(|&&c| c != crtc) {
            let mut off = Crtc { crtc_id: other, ..Crtc::default() };
            let _ = ioctl(fd, SETCRTC, &mut off, "switching off");
        }
        Ok(Display {
            fd,
            width: w as i32,
            height: h as i32,
            fb: fb.fb_id,
            pitch: dumb.pitch as usize,
            buffer,
            crtc,
            back: None,
        })
    }

    /// A buffer and framebuffer like the shown one.
    fn new_buffer(&self) -> Result<(u32, Mapping), String> {
        let (w, h) = (self.width as u32, self.height as u32);
        let mut dumb = CreateDumb { width: w, height: h, bpp: 32, ..CreateDumb::default() };
        ioctl(self.fd, CREATE_DUMB, &mut dumb, "dumb buffer")?;
        let mut map = MapDumb { handle: dumb.handle, ..MapDumb::default() };
        ioctl(self.fd, MAP_DUMB, &mut map, "mapping the buffer")?;
        let buffer = Mapping::shared(self.fd, dumb.size as usize, map.offset).map_err(|e| format!("mmap: {e}"))?;
        let mut fb = FbCmd2 { width: w, height: h, pixel_format: XRGB8888, ..FbCmd2::default() };
        fb.handles[0] = dumb.handle;
        fb.pitches[0] = dumb.pitch;
        ioctl(self.fd, ADDFB2, &mut fb, "framebuffer")?;
        Ok((fb.fb_id, buffer))
    }

    /// Show frames double-buffered from now on ([`Display::show`]).
    pub fn double_buffer(&mut self) -> Result<(), String> {
        let (fb, buffer) = self.new_buffer()?;
        let n = (self.width * self.height) as usize;
        // The screen is black so far: so is the frame "last" shown.
        self.back = Some(Back { fb, buffer, stale: Vec::new(), last: vec![0xFF00_0000; n], flipping: false });
        Ok(())
    }

    /// Wait (up to `ms`) for the last flip to complete.
    fn wait_flip(&mut self, ms: i32) {
        let Some(b) = self.back.as_mut() else { return };
        while b.flipping {
            let mut p = [io::PollFd { fd: self.fd, events: io::POLLIN, revents: 0 }];
            if io::poll(&mut p, ms).unwrap_or(0) == 0 {
                // No event: carry on rather than hang.
                b.flipping = false;
                break;
            }
            let mut ev = [0u8; 256];
            let n = io::read(self.fd, &mut ev).unwrap_or(0);
            let mut at = 0;
            while at + 8 <= n {
                let kind = u32::from_le_bytes(ev[at..at + 4].try_into().unwrap());
                let len = u32::from_le_bytes(ev[at + 4..at + 8].try_into().unwrap()) as usize;
                if kind == EVENT_FLIP_COMPLETE {
                    b.flipping = false;
                }
                at += len.max(8);
            }
        }
    }

    /// Show `pixels` (`width` × `height`, 0xAARRGGBB): double-buffered,
    /// what changed since the last frame goes to the buffer off the screen
    /// (with what that buffer missed meanwhile), and a page flip shows it.
    /// Without double buffering, as [`Display::present`]. False if nothing
    /// changed.
    pub fn show(&mut self, pixels: &[u32]) -> bool {
        if self.back.is_none() {
            self.present(pixels);
            return true;
        }
        let w = self.width as usize;
        let changed = changes(&self.back.as_ref().unwrap().last, pixels, w);
        if changed.is_empty() {
            return false;
        }
        self.wait_flip(100);
        let (pitch, fd, crtc) = (self.pitch / 4, self.fd, self.crtc);
        let b = self.back.as_mut().unwrap();
        let words = b.buffer.words_mut();
        for &(x, y, rw, rh) in b.stale.iter().chain(&changed) {
            for row in y..y + rh {
                if let (Some(dst), Some(src)) =
                    (words.get_mut(row * pitch + x..row * pitch + x + rw), pixels.get(row * w + x..row * w + x + rw))
                {
                    dst.copy_from_slice(src);
                }
            }
        }
        let mut f = PageFlip { crtc_id: crtc, fb_id: b.fb, flags: PAGE_FLIP_EVENT, ..PageFlip::default() };
        if ioctl(fd, PAGE_FLIP, &mut f, "page flip").is_err() {
            return true;
        }
        b.flipping = true;
        let n = b.last.len();
        b.last.copy_from_slice(&pixels[..n]);
        // The buffer leaving the screen lacks what just changed.
        b.stale = changed;
        core::mem::swap(&mut b.fb, &mut self.fb);
        core::mem::swap(&mut b.buffer, &mut self.buffer);
        true
    }

    /// Show rows `top..bottom` of `pixels` (`width` × `height`,
    /// 0xAARRGGBB): only they are copied, and only they are shown.
    pub fn present_rows(&mut self, pixels: &[u32], top: usize, bottom: usize) {
        let (w, pitch) = (self.width as usize, self.pitch / 4);
        let bottom = bottom.min(self.height as usize);
        let words = self.buffer.words_mut();
        for y in top..bottom {
            if let (Some(dst), Some(src)) = (words.get_mut(y * pitch..y * pitch + w), pixels.get(y * w..y * w + w)) {
                dst.copy_from_slice(src);
            }
        }
        // struct drm_clip_rect (libdrm drm.h): x1, y1, x2, y2.
        let clip: [u16; 4] = [0, top as u16, w as u16, bottom as u16];
        let mut d = DirtyCmd { fb_id: self.fb, num_clips: 1, clips_ptr: clip.as_ptr() as u64, ..DirtyCmd::default() };
        let _ = ioctl(self.fd, DIRTYFB, &mut d, "dirtyfb");
    }

    /// The buffer on the screen, as words, and its pitch in words: a frame
    /// written straight into it (M32 phase 2), then shown with
    /// [`Display::present_rects_over`].
    pub fn screen_words(&mut self) -> (&mut [u32], usize) {
        let pitch = self.pitch / 4;
        (self.buffer.words_mut(), pitch)
    }

    /// The whole screen changed (written through [`Display::screen_words`]),
    /// and `rects` of `pixels` go over it: they are copied, and all of it
    /// is shown.
    pub fn present_rects_over(&mut self, pixels: &[u32], rects: &[(usize, usize, usize, usize)]) {
        self.copy_rects(pixels, rects);
        let clip: [u16; 4] = [0, 0, self.width as u16, self.height as u16];
        let mut d = DirtyCmd { fb_id: self.fb, num_clips: 1, clips_ptr: clip.as_ptr() as u64, ..DirtyCmd::default() };
        let _ = ioctl(self.fd, DIRTYFB, &mut d, "dirtyfb");
    }

    /// Show the rectangles `rects` (x, y, width, height) of `pixels`
    /// changed: only they are copied, and they go to the kernel as
    /// DIRTYFB's clips (at most 64).
    pub fn present_rects(&mut self, pixels: &[u32], rects: &[(usize, usize, usize, usize)]) {
        let clips = self.copy_rects(pixels, rects);
        if clips.is_empty() {
            return;
        }
        let mut d = DirtyCmd {
            fb_id: self.fb,
            num_clips: clips.len() as u32,
            clips_ptr: clips.as_ptr() as u64,
            ..DirtyCmd::default()
        };
        let _ = ioctl(self.fd, DIRTYFB, &mut d, "dirtyfb");
    }

    /// Copy `rects` of `pixels` to the screen's buffer; their clips.
    fn copy_rects(&mut self, pixels: &[u32], rects: &[(usize, usize, usize, usize)]) -> Vec<[u16; 4]> {
        let (w, h, pitch) = (self.width as usize, self.height as usize, self.pitch / 4);
        let words = self.buffer.words_mut();
        let mut clips: Vec<[u16; 4]> = Vec::new();
        for &(x, y, rw, rh) in rects.iter().take(64) {
            let (x1, y1) = ((x + rw).min(w), (y + rh).min(h));
            if x >= x1 || y >= y1 {
                continue;
            }
            for row in y..y1 {
                if let (Some(dst), Some(src)) =
                    (words.get_mut(row * pitch + x..row * pitch + x1), pixels.get(row * w + x..row * w + x1))
                {
                    dst.copy_from_slice(src);
                }
            }
            // struct drm_clip_rect (libdrm drm.h): x1, y1, x2, y2.
            clips.push([x as u16, y as u16, x1 as u16, y1 as u16]);
        }
        clips
    }

    /// Show `pixels` (`width` × `height`, 0xAARRGGBB).
    pub fn present(&mut self, pixels: &[u32]) {
        let (w, pitch) = (self.width as usize, self.pitch / 4);
        let words = self.buffer.words_mut();
        for (y, row) in pixels.chunks_exact(w).enumerate().take(self.height as usize) {
            if let Some(dst) = words.get_mut(y * pitch..y * pitch + w) {
                dst.copy_from_slice(row);
            }
        }
        let mut d = DirtyCmd { fb_id: self.fb, ..DirtyCmd::default() };
        let _ = ioctl(self.fd, DIRTYFB, &mut d, "dirtyfb");
    }
}

impl Drop for Display {
    fn drop(&mut self) {
        // Give the screen back to the console.
        let _ = io::ioctl(self.fd, io_(DROP_MASTER), 0);
        let _ = io::close(self.fd);
    }
}

/// A connector's id, first mode and encoder, if something is connected.
fn connector(fd: i32, id: u32) -> Result<Option<(u32, ModeInfo, u32)>, String> {
    let mut c = GetConnector { connector_id: id, ..GetConnector::default() };
    ioctl(fd, GETCONNECTOR, &mut c, "connector")?;
    if c.connection != CONNECTED || c.count_modes == 0 {
        return Ok(None);
    }
    let mut modes = vec![ModeInfo::default(); c.count_modes as usize];
    let mut encoders: Vec<u32> = vec![0; c.count_encoders as usize];
    let mut c2 = GetConnector {
        connector_id: id,
        modes: modes.as_mut_ptr() as u64,
        count_modes: modes.len() as u32,
        encoders: encoders.as_mut_ptr() as u64,
        count_encoders: encoders.len() as u32,
        ..GetConnector::default()
    };
    ioctl(fd, GETCONNECTOR, &mut c2, "connector")?;
    let encoder = if c2.encoder_id != 0 { c2.encoder_id } else { encoders.first().copied().unwrap_or(0) };
    Ok(Some((id, modes[0], encoder)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_rectangles() {
        let w = 8;
        let old = vec![0u32; w * 6];
        let mut new = old.clone();
        assert!(changes(&old, &new, w).is_empty());
        // Rows 1-2 change at columns 2 and 5; row 4 at column 7.
        new[w + 2] = 1;
        new[2 * w + 5] = 1;
        new[4 * w + 7] = 1;
        assert_eq!(changes(&old, &new, w), [(2, 1, 4, 2), (7, 4, 1, 1)]);
    }
}
