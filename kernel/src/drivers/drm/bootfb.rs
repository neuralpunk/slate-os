// SPDX-License-Identifier: MIT OR Apache-2.0

//! The display the firmware set up (the GOP or VBE framebuffer the loader
//! hands over) as a DRM card (ADR 0033): one output with one fixed mode;
//! showing a framebuffer copies its pixels to the screen. It is what PCs
//! without a supported GPU driver use, the reference PC included.
//!
//! The copy is where the hardware's other parts are done in software (ADR
//! 0100): a 256-entry gamma table maps each channel, and the cursor
//! plane's image is blended over the pixels it covers. Moving the cursor
//! copies the rectangles it left and entered again.
//!
//! A GPU driver's scanout may do some of that in hardware ([`Hardware`]):
//! with a second buffer, each change is copied into the buffer not shown
//! and the card flips to it, so that frames show whole; a hardware cursor
//! moves without copying; an overlay plane shows a framebuffer over the
//! screen's, copied into buffers of its own, and moves without copying.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use super::{
    CONNECTOR_UNKNOWN, CursorImage, Display, FORMAT_ARGB8888, FORMAT_XRGB8888, Framebuffer, OutputInfo, Overlay,
};
use crate::arch::boot;
use crate::sched::wait::Mutex;

/// Entries in the gamma table.
const GAMMA: u32 = 256;

/// What is on the screen.
struct Shown {
    fb: Option<Arc<Framebuffer>>,
    /// The cursor's image and where its top left corner is.
    cursor: Option<CursorImage>,
    at: (i32, i32),
    /// Per entry: red, green, blue (the high bytes of the table).
    gamma: Option<Vec<[u8; 3]>>,
    /// With two buffers: the one shown (0: the first) and the rectangle
    /// the other lacks (what changed since it was shown; all of it at
    /// first).
    front: usize,
    behind: Option<Rect>,
    /// The hardware shows the cursor (`cursor` is then none): its image.
    hw_cursor: Option<CursorImage>,
    /// The overlay plane, if it shows one.
    overlay: Option<OverlayShown>,
}

/// What the overlay plane shows: the plane, which of its buffers is shown
/// and the rectangle the other lacks (in the plane's pixels).
struct OverlayShown {
    plane: Overlay,
    front: usize,
    behind: Option<Rect>,
}

/// Columns and rows.
type Rect = (core::ops::Range<u32>, core::ops::Range<u32>);

impl Shown {
    fn new(width: usize, height: usize, front: usize) -> Self {
        Shown {
            fb: None,
            cursor: None,
            at: (0, 0),
            gamma: None,
            front,
            behind: Some((0..width as u32, 0..height as u32)),
            hw_cursor: None,
            overlay: None,
        }
    }
}

/// The smallest rectangle holding `a` and `b` (either may be empty).
fn union(a: Rect, b: Rect) -> Rect {
    let empty = |r: &Rect| r.0.is_empty() || r.1.is_empty();
    match (empty(&a), empty(&b)) {
        (true, _) => b,
        (_, true) => a,
        _ => (a.0.start.min(b.0.start)..a.0.end.max(b.0.end), a.1.start.min(b.1.start)..a.1.end.max(b.1.end)),
    }
}

/// What a GPU driver's scanout does in hardware, for its card.
pub trait Hardware: Send + Sync {
    /// Where the second buffer is mapped (as the first: write-combining,
    /// the first's size and layout), if there is one.
    fn second(&self) -> Option<u64>;
    /// Show buffer `i` (0: the first) from the next frame.
    fn flip(&self, i: usize);
    /// Whether the last flip took: the buffer shown before it is free.
    fn flipped(&self) -> bool;
    /// Show `image` (premultiplied ARGB) as the cursor with its top left
    /// corner at `at`, or no cursor. False: the hardware shows none, and
    /// the copy blends the image.
    fn cursor(&self, image: Option<&CursorImage>, at: (i32, i32)) -> bool;
    /// Move the cursor [`Hardware::cursor`] showed.
    fn move_cursor(&self, at: (i32, i32));
    /// When the last vertical blank began and the frame's length
    /// ([`Display::vblank`]).
    fn vblank(&self) -> Option<(u64, u64)> {
        None
    }
    /// Where the overlay plane's two buffers are mapped (write-combining,
    /// rows the screen's pitch apart, room for the whole screen), if
    /// there is an overlay plane.
    fn overlay_buffers(&self) -> Option<[u64; 2]> {
        None
    }
    /// Show the overlay as `at` says, or none.
    fn show_overlay(&self, _at: Option<OverlayAt>) {}
    /// Whether the overlay's last change took: the buffer it showed
    /// before is free.
    fn overlay_flipped(&self) -> bool {
        true
    }
    /// Copy `size` pixels of `fb` from its pixel `from` into buffer `to`
    /// at `at` (unchanged pixels: no gamma, no cursor blended), on the
    /// GPU, done when it returns. False: not done, the CPU copies.
    fn copy(&self, _fb: &Arc<Framebuffer>, _from: (u32, u32), _to: Target, _at: (u32, u32), _size: (u32, u32)) -> bool {
        false
    }
    /// Framebuffer `id` is gone ([`Display::forget`]).
    fn forget(&self, _id: u32) {}
    /// The card's 2D requests, if the hardware does them.
    fn twod(&self) -> Option<&dyn super::twod::TwoD> {
        None
    }
}

/// A buffer the card shows: the screen's `.0`, or the overlay's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Screen(usize),
    Overlay(usize),
}

/// Where the overlay plane shows: `size` pixels of buffer `buffer` from
/// its top left, with that corner at `at` on the screen, blended by its
/// pixels' (premultiplied) alpha if `alpha`, else opaque.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverlayAt {
    pub buffer: usize,
    pub at: (u32, u32),
    pub size: (u32, u32),
    pub alpha: bool,
}

impl OverlayAt {
    fn of(v: &Overlay, buffer: usize) -> Self {
        OverlayAt { buffer, at: v.at, size: v.size, alpha: v.fb.format == FORMAT_ARGB8888 }
    }
}

/// How long a flip may take before the card copies anyway (a frame at
/// 24 Hz, and some).
const FLIP_WAIT_NS: u64 = 50_000_000;

struct BootFb {
    fb: boot::Framebuffer,
    shown: Mutex<Shown>,
    card: Scanout,
    hw: Option<Box<dyn Hardware>>,
}

/// What a card over a scanout buffer says about itself: the firmware's
/// framebuffer, or a GPU driver's that lit a display but has no planes of
/// its own to show framebuffers with yet (it copies, as this card does,
/// with what it has in [`Hardware`]).
#[derive(Clone, Debug)]
pub struct Scanout {
    pub driver: &'static str,
    pub description: &'static str,
    pub connector: u32,
    pub refresh: u32,
    pub size_mm: (u32, u32),
    pub edid: Option<Vec<u8>>,
}

impl Scanout {
    fn firmware() -> Self {
        Scanout {
            driver: "slate-fb",
            description: "firmware framebuffer",
            connector: CONNECTOR_UNKNOWN,
            refresh: 60,
            size_mm: (0, 0),
            edid: None,
        }
    }
}

/// `over` (premultiplied ARGB) blended onto the colour `under`.
fn blend(over: u32, under: u32) -> u32 {
    let a = over >> 24;
    if a == 0xFF {
        return over & 0x00ff_ffff;
    }
    let ch = |s: u32| {
        let (o, u) = ((over >> s) & 0xFF, (under >> s) & 0xFF);
        (o + u * (255 - a) / 255).min(255) << s
    };
    ch(16) | ch(8) | ch(0)
}

impl BootFb {
    /// Where buffer `i` is mapped.
    fn buffer(&self, i: usize) -> u64 {
        match (i, self.hw.as_ref().and_then(|h| h.second())) {
            (1, Some(a)) => a,
            _ => self.fb.addr,
        }
    }

    /// The rectangle `cols` × `rows` of what is shown changed: copy it to
    /// the screen, or with two buffers to the one not shown (with what it
    /// lacks) and flip to it.
    fn update(&self, s: &mut Shown, cols: core::ops::Range<u32>, rows: core::ops::Range<u32>) {
        let Some(hw) = self.hw.as_ref().filter(|h| h.second().is_some()) else {
            self.draw(self.buffer(0), s, cols, rows);
            return;
        };
        // The other buffer is free once the last flip took.
        let end = crate::time::monotonic_ns() + FLIP_WAIT_NS;
        while !hw.flipped() && crate::time::monotonic_ns() < end {
            crate::time::sleep_ns(200_000);
        }
        let back = 1 - s.front;
        let (c, r) = match s.behind.take() {
            Some(b) => union(b, (cols.clone(), rows.clone())),
            None => (cols.clone(), rows.clone()),
        };
        if !self.copy_on_gpu(hw.as_ref(), s, c.clone(), r.clone(), back) {
            self.draw(self.buffer(back), s, c, r);
        }
        hw.flip(back);
        s.front = back;
        s.behind = Some((cols, rows));
    }

    /// The rectangle `cols` × `rows` of what is shown into screen buffer
    /// `i` on the GPU, where nothing in it needs the CPU (the screen's own
    /// layout, no gamma, no cursor blended in software). Whether it was.
    fn copy_on_gpu(
        &self,
        hw: &dyn Hardware,
        s: &Shown,
        cols: core::ops::Range<u32>,
        rows: core::ops::Range<u32>,
        i: usize,
    ) -> bool {
        let Some(f) = &s.fb else { return true };
        let native = (self.fb.red_shift, self.fb.green_shift, self.fb.blue_shift) == (16, 8, 0);
        if !native || s.gamma.is_some() || s.cursor.is_some() || !matches!(f.format, FORMAT_XRGB8888 | FORMAT_ARGB8888)
        {
            return false;
        }
        let (w, h) = (f.width.min(self.fb.width as u32), f.height.min(self.fb.height as u32));
        let (x0, x1) = (cols.start.min(w), cols.end.min(w));
        let (y0, y1) = (rows.start.min(h), rows.end.min(h));
        if x0 >= x1 || y0 >= y1 {
            return true;
        }
        hw.copy(f, (x0, y0), Target::Screen(i), (x0, y0), (x1 - x0, y1 - y0))
    }

    /// Copy the rectangle `cols` × `rows` of what is shown to the buffer
    /// mapped at `base`.
    fn draw(&self, base: u64, s: &Shown, cols: core::ops::Range<u32>, rows: core::ops::Range<u32>) {
        let Some(f) = &s.fb else { return };
        if f.format != FORMAT_XRGB8888 && f.format != FORMAT_ARGB8888 {
            return;
        }
        let w = (f.width as usize).min(self.fb.width);
        let h = (f.height as usize).min(self.fb.height);
        let (top, bottom) = ((rows.start as usize).min(h), (rows.end as usize).min(h));
        let (left, right) = ((cols.start as usize).min(w), (cols.end as usize).min(w));
        if left >= right {
            return;
        }
        // XRGB8888 is 0x00RRGGBB in a little-endian word: the screen's own
        // layout when red is at bit 16, green 8 and blue 0.
        let native = (self.fb.red_shift, self.fb.green_shift, self.fb.blue_shift) == (16, 8, 0);
        let mut row = vec![0u8; (right - left) * 4];
        for y in top..bottom {
            let src = u64::from(f.offset) + y as u64 * u64::from(f.pitch) + left as u64 * 4;
            let dst = (base + (y * self.fb.pitch + left * 4) as u64) as *mut u32;
            // The cursor's pixels on this row, if it crosses it.
            let cursor = s.cursor.as_ref().filter(|c| {
                let cy = y as i32 - s.at.1;
                cy >= 0 && (cy as u32) < c.height
            });
            // The screen's own layout and no gamma (the usual case, M32
            // phase 2): the row goes from the buffer's pages to the screen
            // in one copy, and only the cursor's pixels are blended after.
            // At 4K this is most of a frame's cost.
            if native && s.gamma.is_none() {
                // SAFETY: the row's `right - left` pixels are inside the
                // firmware framebuffer, which stays mapped (write-combining,
                // ADR 0066) and which nothing else in Rust refers to.
                let out = unsafe { core::slice::from_raw_parts_mut(dst.cast::<u8>(), (right - left) * 4) };
                f.buffer.read(src, out);
                if let Some(c) = cursor {
                    let cy = (y as i32 - s.at.1) as u32;
                    let from = s.at.0.max(left as i32);
                    let to = (s.at.0 + c.width as i32).min(right as i32);
                    for x in from..to {
                        let mut p = [0u8; 4];
                        f.buffer.read(src + (x as usize - left) as u64 * 4, &mut p);
                        let over = c.pixels[(cy * c.width + (x - s.at.0) as u32) as usize];
                        // SAFETY: x is inside the row copied above.
                        unsafe { dst.add(x as usize - left).write_volatile(blend(over, u32::from_le_bytes(p))) };
                    }
                }
                continue;
            }
            f.buffer.read(src, &mut row);
            for x in 0..right - left {
                let mut p = u32::from_le_bytes([row[x * 4], row[x * 4 + 1], row[x * 4 + 2], row[x * 4 + 3]]);
                if let Some(c) = cursor {
                    let cx = (left + x) as i32 - s.at.0;
                    if cx >= 0 && (cx as u32) < c.width {
                        p = blend(c.pixels[((y as i32 - s.at.1) as u32 * c.width + cx as u32) as usize], p);
                    }
                }
                let (mut r, mut g, mut b) = ((p >> 16) & 0xff, (p >> 8) & 0xff, p & 0xff);
                if let Some(t) = &s.gamma {
                    (r, g, b) = (t[r as usize][0].into(), t[g as usize][1].into(), t[b as usize][2].into());
                }
                let px = if native {
                    (r << 16) | (g << 8) | b
                } else {
                    (r << self.fb.red_shift) | (g << self.fb.green_shift) | (b << self.fb.blue_shift)
                };
                // SAFETY: (x, y) is inside the firmware framebuffer, which
                // stays mapped (write-combining, ADR 0066).
                unsafe { dst.add(x).write_volatile(px) };
            }
        }
    }

    /// Copy the cursor's rectangle (where it is now) again.
    fn draw_cursor_area(&self, s: &mut Shown) {
        if let Some(c) = &s.cursor {
            let (x, y) = (s.at.0.max(0) as u32, s.at.1.max(0) as u32);
            let x1 = (s.at.0 + c.width as i32).max(0) as u32;
            let y1 = (s.at.1 + c.height as i32).max(0) as u32;
            self.update(s, x..x1, y..y1);
        }
    }

    /// The buffer shown goes black; the other then lacks everything.
    fn clear(&self, s: &mut Shown) {
        let base = self.buffer(s.front);
        for y in 0..self.fb.height {
            let row = (base + (y * self.fb.pitch) as u64) as *mut u32;
            for x in 0..self.fb.width {
                // SAFETY: (x, y) is inside the buffer, which stays mapped.
                unsafe { row.add(x).write_volatile(0) };
            }
        }
        s.behind = Some((0..self.fb.width as u32, 0..self.fb.height as u32));
    }

    /// The overlay's buffers, if the hardware has an overlay plane.
    fn overlay_hw(&self) -> Option<(&dyn Hardware, [u64; 2])> {
        let hw = self.hw.as_deref()?;
        Some((hw, hw.overlay_buffers()?))
    }

    /// The rectangle `cols` × `rows` (in the plane's pixels) of the
    /// overlay changed: copy it, with what the buffer not shown lacks,
    /// into that buffer and show it.
    fn update_overlay(&self, o: &mut OverlayShown, cols: core::ops::Range<u32>, rows: core::ops::Range<u32>) {
        let Some((hw, buffers)) = self.overlay_hw() else { return };
        let end = crate::time::monotonic_ns() + FLIP_WAIT_NS;
        while !hw.overlay_flipped() && crate::time::monotonic_ns() < end {
            crate::time::sleep_ns(200_000);
        }
        let back = 1 - o.front;
        let (c, r) = match o.behind.take() {
            Some(b) => union(b, (cols.clone(), rows.clone())),
            None => (cols.clone(), rows.clone()),
        };
        let v = &o.plane;
        let (right, bottom) = (c.end.min(v.size.0), r.end.min(v.size.1));
        let (left, top) = (c.start.min(right), r.start.min(bottom));
        let on_gpu = left >= right
            || top >= bottom
            || hw.copy(
                &v.fb,
                (v.src.0 + left, v.src.1 + top),
                Target::Overlay(back),
                (left, top),
                (right - left, bottom - top),
            );
        if !on_gpu {
            self.draw_overlay(buffers[back], &o.plane, c, r);
        }
        hw.show_overlay(Some(OverlayAt::of(&o.plane, back)));
        o.front = back;
        o.behind = Some((cols, rows));
    }

    /// Copy the rectangle `cols` × `rows` of overlay `v` (in its pixels)
    /// into the overlay buffer mapped at `base`, rows the screen's pitch
    /// apart; its pixels as they are.
    fn draw_overlay(&self, base: u64, v: &Overlay, cols: core::ops::Range<u32>, rows: core::ops::Range<u32>) {
        let f = &v.fb;
        let (right, bottom) = (cols.end.min(v.size.0), rows.end.min(v.size.1));
        let left = cols.start.min(right);
        for y in rows.start.min(bottom)..bottom {
            let src = u64::from(f.offset) + u64::from(v.src.1 + y) * u64::from(f.pitch) + u64::from(v.src.0 + left) * 4;
            let dst = base + y as u64 * self.fb.pitch as u64 + u64::from(left) * 4;
            // SAFETY: the row's pixels are inside the overlay buffer (as
            // big as the screen, the plane on it), which stays mapped
            // (write-combining) and which nothing else in Rust refers to.
            let out = unsafe { core::slice::from_raw_parts_mut(dst as *mut u8, ((right - left) * 4) as usize) };
            f.buffer.read(src, out);
        }
    }

    /// A picture again after none: the hardware's cursor comes back.
    fn cursor_back(&self, s: &Shown) {
        if let (Some(hw), Some(c)) = (&self.hw, &s.hw_cursor) {
            hw.cursor(Some(c), s.at);
        }
    }
}

impl Display for BootFb {
    fn driver(&self) -> &'static str {
        self.card.driver
    }
    fn description(&self) -> &'static str {
        self.card.description
    }
    fn output(&self, _out: usize) -> OutputInfo {
        OutputInfo {
            connected: true,
            modes: vec![(self.fb.width as u32, self.fb.height as u32, self.card.refresh)],
            size_mm: self.card.size_mm,
            edid: self.card.edid.clone(),
        }
    }
    fn connector_type(&self) -> u32 {
        self.card.connector
    }
    fn present(&self, _out: usize, f: &Arc<Framebuffer>, _mode: (u32, u32)) {
        let mut s = self.shown.lock();
        let shown_none = s.fb.is_none();
        s.fb = Some(f.clone());
        self.update(&mut s, 0..f.width, 0..f.height);
        if shown_none {
            self.cursor_back(&s);
        }
    }
    fn present_rect(
        &self,
        _out: usize,
        f: &Arc<Framebuffer>,
        cols: core::ops::Range<u32>,
        rows: core::ops::Range<u32>,
    ) {
        let mut s = self.shown.lock();
        let shown_none = s.fb.is_none();
        s.fb = Some(f.clone());
        self.update(&mut s, cols, rows);
        if shown_none {
            self.cursor_back(&s);
        }
    }
    fn blank(&self, _out: usize) {
        let mut s = self.shown.lock();
        s.fb = None;
        self.clear(&mut s);
        // The hardware's cursor goes with the picture (and comes back with
        // the next one).
        if let (Some(hw), Some(_)) = (&self.hw, &s.hw_cursor) {
            hw.cursor(None, s.at);
        }
    }
    fn cursor(&self, _out: usize, image: Option<CursorImage>) {
        let mut s = self.shown.lock();
        let old = s.cursor.take();
        if let Some(old) = old {
            // Uncover what the old image hid.
            s.cursor = Some(CursorImage { pixels: vec![0; old.pixels.len()], ..old });
            self.draw_cursor_area(&mut s);
            s.cursor = None;
        }
        let shown = s.fb.is_some();
        if let Some(hw) = &self.hw
            && hw.cursor(image.as_ref().filter(|_| shown), s.at)
        {
            s.hw_cursor = image;
            return;
        }
        s.hw_cursor = None;
        s.cursor = image;
        self.draw_cursor_area(&mut s);
    }
    fn move_cursor(&self, _out: usize, x: i32, y: i32) {
        let mut s = self.shown.lock();
        if s.at == (x, y) {
            return;
        }
        if let (Some(hw), Some(_)) = (&self.hw, &s.hw_cursor) {
            s.at = (x, y);
            if s.fb.is_some() {
                hw.move_cursor(s.at);
            }
            return;
        }
        let Some(c) = s.cursor.take() else {
            s.at = (x, y);
            return;
        };
        // The old rectangle without the cursor, then the new one with it.
        let blank = CursorImage { pixels: vec![0; c.pixels.len()], ..c.clone() };
        s.cursor = Some(blank);
        self.draw_cursor_area(&mut s);
        s.at = (x, y);
        s.cursor = Some(c);
        self.draw_cursor_area(&mut s);
    }
    fn gamma_size(&self) -> u32 {
        GAMMA
    }
    fn set_gamma(&self, _out: usize, lut: Option<Vec<[u16; 3]>>) {
        let mut s = self.shown.lock();
        s.gamma = lut.map(|l| l.iter().map(|e| e.map(|v| (v >> 8) as u8)).collect());
        if let Some(f) = s.fb.clone() {
            self.update(&mut s, 0..f.width, 0..f.height);
        }
    }
    fn vblank(&self, _out: usize) -> Option<(u64, u64)> {
        self.hw.as_ref()?.vblank()
    }
    fn overlays(&self) -> bool {
        self.overlay_hw().is_some()
    }
    fn forget(&self, id: u32) {
        if let Some(hw) = &self.hw {
            hw.forget(id);
        }
    }
    fn twod(&self) -> Option<&dyn super::twod::TwoD> {
        self.hw.as_ref()?.twod()
    }
    fn overlay(&self, _out: usize, plane: Option<Overlay>) {
        let Some((hw, _)) = self.overlay_hw() else { return };
        let mut s = self.shown.lock();
        let Some(v) = plane else {
            if s.overlay.take().is_some() {
                hw.show_overlay(None);
            }
            return;
        };
        match &mut s.overlay {
            // The same pixels somewhere else: moved, not copied.
            Some(o) if Arc::ptr_eq(&o.plane.fb, &v.fb) && (o.plane.src, o.plane.size) == (v.src, v.size) => {
                o.plane = v;
                hw.show_overlay(Some(OverlayAt::of(&o.plane, o.front)));
            }
            o => {
                let front = o.as_ref().map_or(1, |o| o.front);
                let (w, h) = v.size;
                let mut n = OverlayShown { plane: v, front, behind: None };
                self.update_overlay(&mut n, 0..w, 0..h);
                // The other buffer lacks all of it.
                n.behind = Some((0..w, 0..h));
                *o = Some(n);
            }
        }
        // The cursor goes on the overlay too.
        if let Some(c) = &s.hw_cursor {
            hw.cursor(Some(c), s.at);
        }
    }
    fn overlay_rect(
        &self,
        _out: usize,
        fb: &Arc<Framebuffer>,
        cols: core::ops::Range<u32>,
        rows: core::ops::Range<u32>,
    ) {
        let mut s = self.shown.lock();
        let Some(o) = s.overlay.as_mut().filter(|o| Arc::ptr_eq(&o.plane.fb, fb)) else { return };
        // The clip in the plane's pixels.
        let (src, size) = (o.plane.src, o.plane.size);
        let c = cols.start.max(src.0) - src.0..cols.end.min(src.0 + size.0).saturating_sub(src.0);
        let r = rows.start.max(src.1) - src.1..rows.end.min(src.1 + size.1).saturating_sub(src.1);
        if c.start < c.end && r.start < r.end {
            self.update_overlay(o, c, r);
        }
    }
    fn release(&self) {
        let mut s = self.shown.lock();
        if let (Some(hw), Some(_)) = (&self.hw, &s.hw_cursor) {
            hw.cursor(None, s.at);
        }
        if let (Some(hw), Some(_)) = (&self.hw, &s.overlay) {
            hw.show_overlay(None);
        }
        *s = Shown::new(self.fb.width, self.fb.height, s.front);
        drop(s);
        crate::drivers::fbcon::set_suspended(false);
    }
}

/// A GPU driver took over the screen the firmware framebuffer was on.
static CLAIMED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn claim() {
    CLAIMED.store(true, core::sync::atomic::Ordering::Release);
}

/// Offer the firmware framebuffer as a card, if it has 32-bit pixels and
/// no GPU driver took the screen over (call after the drivers probed).
pub fn register(fb: boot::Framebuffer) {
    if CLAIMED.load(core::sync::atomic::Ordering::Acquire) {
        return;
    }
    if fb.bpp != 32 {
        crate::log_info!("drm: firmware framebuffer has {} bits per pixel; no card", fb.bpp);
        return;
    }
    // The card writes through a write-combining mapping of its own (ADR
    // 0066): the direct map's is write-back by the page tables, which the
    // firmware's MTRRs usually make uncached.
    let mut fb = fb;
    if let Some(phys) = crate::mm::virt_to_phys(fb.addr) {
        fb.addr = crate::mm::vmap::map_wc(phys, (fb.pitch * fb.height) as u64) as u64;
    }
    let memory = crate::arch::paging::kernel_mapper().memory_type(fb.addr).unwrap_or("unmapped");
    crate::log_info!(
        "drm: firmware framebuffer at {:#x}, {}x{}, pitch {}, {memory}",
        crate::arch::paging::kernel_mapper().translate(fb.addr).map_or(0, |p| p.0),
        fb.width,
        fb.height,
        fb.pitch
    );
    super::register(
        Box::new(BootFb {
            shown: Mutex::new(Shown::new(fb.width, fb.height, 0)),
            fb,
            card: Scanout::firmware(),
            hw: None,
        }),
        "devices/platform/simple-framebuffer.0",
        "platform",
    );
}

/// Offer a GPU driver's scanout buffer (`fb`, already mapped
/// write-combining, 32-bit XRGB, shown) as a card, with what its hardware
/// does; its minor.
pub fn register_scanout(
    fb: boot::Framebuffer,
    card: Scanout,
    hw: Option<Box<dyn Hardware>>,
    sys_device: &str,
    subsystem: &str,
) -> u32 {
    let shown = Mutex::new(Shown::new(fb.width, fb.height, 0));
    super::register(Box::new(BootFb { fb, shown, card, hw }), sys_device, subsystem)
}
