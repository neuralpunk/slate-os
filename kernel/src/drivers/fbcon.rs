// SPDX-License-Identifier: MIT OR Apache-2.0

//! The framebuffer console: a terminal emulator (`slate-term`) drawn with
//! Slate's font on the bootloader's linear framebuffer, one per virtual
//! console (ADR 0185), the one in front drawn.

use alloc::vec::Vec;

use slate_term::font::{self, HEIGHT, WIDTH};
use slate_term::vt::{Cell, Color, Term, rgb};

use crate::arch::boot::Framebuffer;
use crate::sync::IrqSpinLock;

#[derive(Debug)]
struct FbCon {
    fb: Framebuffer,
    /// Each virtual console's terminal (VT 1 first), made when first
    /// written to.
    terms: Vec<Term>,
    /// The one in front (0: VT 1).
    active: usize,
    /// Pixel values for the 256 palette colors, in the framebuffer's format.
    palette: [u32; 256],
    /// Where the cursor was last drawn.
    cursor: Option<(usize, usize)>,
}

static CONSOLE: IrqSpinLock<Option<FbCon>> = IrqSpinLock::new(None);

/// While a DRM master owns the screen, the console keeps its text but
/// does not draw (ADR 0033).
static SUSPENDED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Virtual consoles in graphics mode (KD_GRAPHICS, bit n for VT n): the
/// console doesn't draw them.
static GRAPHICS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn graphics(vt: usize) -> bool {
    GRAPHICS.load(core::sync::atomic::Ordering::Acquire) & (1 << vt) != 0
}

/// Whether the console draws now: no DRM master, the VT in front in text
/// mode, no boot splash.
fn drawing(con: &FbCon) -> bool {
    !suspended() && !graphics(con.active + 1) && !splash_showing()
}

// The boot splash (ADR 0186): with `quiet` on the command line (and not
// `slate.splash=off`), the console keeps its text but shows a dark screen
// with Slate's mark and a line moving under it, from early boot until a
// program takes the screen (the login screen), a program waits for typing
// on a console (a text login), Esc is pressed, something goes wrong (an
// error logged, a panic) or two minutes pass. Then the text is there.

/// The splash: none, showing, or over.
static SPLASH: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
const SPLASH_SHOWING: u8 = 1;
const SPLASH_OVER: u8 = 2;
/// Waiting while the disk's password is asked for on the screen: it
/// comes back when the screen is given back.
const SPLASH_PAUSED: u8 = 3;
/// Why the splash is to end, for its thread to act on (set where taking
/// the console's lock could deadlock: logging, input, a tty's read).
static SPLASH_END: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
const END_ESC: u8 = 1;
const END_ERROR: u8 = 2;
const END_READ: u8 = 3;

/// The mark's coverage, 96 and 192 pixels square (kernel/build.rs draws
/// them with slate-ui).
static LOGO_96: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/splash-logo-96.bin"));
static LOGO_192: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/splash-logo-192.bin"));

/// The splash's colours (WM_STYLE's graphite: the desktop, chalk, a
/// raised grey for the track, a muted one for what moves on it).
const SPLASH_BG: (u8, u8, u8) = (0x12, 0x12, 0x11);
const SPLASH_INK: (u8, u8, u8) = (0xE3, 0xE1, 0xDC);
const SPLASH_TRACK: (u8, u8, u8) = (0x2A, 0x2A, 0x27);
const SPLASH_MOVING: (u8, u8, u8) = (0x8F, 0x8C, 0x86);

pub fn splash_showing() -> bool {
    SPLASH.load(core::sync::atomic::Ordering::Acquire) == SPLASH_SHOWING
}

/// Show the splash if the command line asks for a quiet boot.
pub fn splash_start(cmdline: &str) {
    let words = || cmdline.split_ascii_whitespace();
    if !words().any(|w| w == "quiet") || words().any(|w| w == "slate.splash=off") {
        return;
    }
    let mut g = CONSOLE.lock();
    let Some(con) = g.as_mut() else { return };
    SPLASH.store(SPLASH_SHOWING, core::sync::atomic::Ordering::Release);
    con.paint_splash();
    drop(g);
    crate::kprintln!("splash: shown");
}

/// Ask for the splash to end (safe anywhere: its thread does it); true
/// if this was the first to ask.
pub fn splash_end_soon(why: u8) -> bool {
    splash_showing()
        && SPLASH_END
            .compare_exchange(0, why, core::sync::atomic::Ordering::AcqRel, core::sync::atomic::Ordering::Relaxed)
            .is_ok()
}

/// Esc was pressed, an error logged, a program reads a console.
pub fn splash_esc() {
    splash_end_soon(END_ESC);
}
pub fn splash_error() {
    splash_end_soon(END_ERROR);
}
pub fn splash_read() -> bool {
    splash_end_soon(END_READ)
}

/// End the splash now and show the console's text (unless a program has
/// the screen).
pub fn splash_end(why: &str) {
    if SPLASH
        .compare_exchange(
            SPLASH_SHOWING,
            SPLASH_OVER,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Relaxed,
        )
        .is_ok()
    {
        crate::kprintln!("splash: ended ({why})");
        redraw();
    }
}

/// Start the splash's thread (once the scheduler runs): it moves the line
/// and ends the splash when asked.
pub fn splash_animate() {
    if !splash_showing() {
        return;
    }
    crate::sched::spawn("splash", || {
        let mut start = crate::time::monotonic_ns();
        let mut step = 0u32;
        loop {
            match SPLASH.load(core::sync::atomic::Ordering::Acquire) {
                SPLASH_SHOWING => {}
                // (The two minutes start again after the disk's password.)
                SPLASH_PAUSED => {
                    start = crate::time::monotonic_ns();
                    crate::sched::sleep_until(start + 100_000_000);
                    continue;
                }
                _ => break,
            }
            let why = match SPLASH_END.load(core::sync::atomic::Ordering::Acquire) {
                END_ESC => Some("Esc"),
                END_ERROR => Some("an error"),
                END_READ => Some("a program waits for typing"),
                _ if crate::time::monotonic_ns() - start > 120_000_000_000 => Some("two minutes"),
                _ => None,
            };
            if let Some(why) = why {
                splash_end(why);
                break;
            }
            if !suspended() {
                let mut g = CONSOLE.lock();
                if let Some(con) = g.as_mut()
                    && splash_showing()
                {
                    con.splash_step(step);
                }
            }
            step = step.wrapping_add(1);
            crate::sched::sleep_until(crate::time::monotonic_ns() + 33_000_000);
        }
    });
}

/// Where the splash's line is, on a `w` × `h` screen with the mark `size`
/// square: the track (x, y, width, height).
pub fn splash_track(w: usize, h: usize, size: usize) -> (usize, usize, usize, usize) {
    let tw = (size * 2).min(w);
    let th = if size > 96 { 4 } else { 2 };
    let y = (h * 2 / 5 + size / 2 + size / 2).min(h.saturating_sub(th));
    ((w - tw) / 2, y, tw, th)
}

/// Where the moving part is along a track `tw` long at step `n`: (start,
/// length), sweeping across and back in 80 steps.
pub fn splash_segment(tw: usize, n: u32) -> (usize, usize) {
    let len = tw / 4;
    let span = tw - len;
    let phase = (n % 80) as usize;
    let t = if phase < 40 { phase } else { 80 - phase };
    (span * t / 40, len)
}

/// Draw virtual console `vt` (1 to 12) or not (KD_GRAPHICS); a VT in
/// front coming back to text is redrawn.
pub fn set_graphics(vt: usize, on: bool) {
    if on {
        GRAPHICS.fetch_or(1 << vt, core::sync::atomic::Ordering::AcqRel);
    } else if GRAPHICS.fetch_and(!(1 << vt), core::sync::atomic::Ordering::AcqRel) & (1 << vt) != 0 {
        redraw();
    }
}

/// Put virtual console `vt` (1 to 12) in front and draw it.
pub fn switch(vt: usize) {
    let mut g = CONSOLE.lock();
    if let Some(con) = g.as_mut() {
        con.term_mut(vt);
        con.active = vt - 1;
    }
    drop(g);
    redraw();
}

/// Draw the VT in front again, all of it, if the console draws now.
fn redraw() {
    let mut g = CONSOLE.lock();
    if let Some(con) = g.as_mut()
        && drawing(con)
    {
        con.clear();
        con.term_mut(con.active + 1).mark_all_dirty();
        con.render();
        crate::drivers::virtio::gpu::console_damage(0, con.fb.height as u32);
    }
}

/// Stop drawing (a DRM master took the screen) or start again, redrawing
/// everything.
pub fn set_suspended(on: bool) {
    SUSPENDED.store(on, core::sync::atomic::Ordering::Release);
    // A program took the screen (the login screen): the splash's work is
    // done.
    if on
        && SPLASH
            .compare_exchange(
                SPLASH_SHOWING,
                SPLASH_OVER,
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
    {
        crate::kprintln!("splash: ended (a program took the screen)");
    }
    // The disk unlocked: the splash again, until the login screen.
    if !on
        && SPLASH
            .compare_exchange(
                SPLASH_PAUSED,
                SPLASH_SHOWING,
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
    {
        // (Its reads from the console while it asked don't count.)
        SPLASH_END.store(0, core::sync::atomic::Ordering::Release);
        let mut g = CONSOLE.lock();
        if let Some(con) = g.as_mut() {
            con.paint_splash();
        }
        drop(g);
        crate::kprintln!("splash: back after the disk's password");
        return;
    }
    if !on {
        redraw();
    }
}

/// A program takes the screen while the splash shows: slate-unlock
/// (`unlock`) pauses it, anything else ends it (in [`set_suspended`]).
pub fn splash_pause(unlock: bool) {
    if unlock
        && SPLASH
            .compare_exchange(
                SPLASH_SHOWING,
                SPLASH_PAUSED,
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
    {
        crate::kprintln!("splash: paused for the disk's password");
    }
}

pub fn suspended() -> bool {
    SUSPENDED.load(core::sync::atomic::Ordering::Acquire)
}

/// Set up the console on `fb`. Only 32-bit pixels are supported; other
/// formats leave the console on the serial port alone.
pub fn init(fb: Framebuffer) -> bool {
    if fb.bpp != 32 || fb.width < WIDTH || fb.height < HEIGHT {
        crate::log_warn!("fbcon: unsupported framebuffer {}x{}x{}", fb.width, fb.height, fb.bpp);
        return false;
    }
    let mut palette = [0u32; 256];
    for (i, p) in palette.iter_mut().enumerate() {
        let (r, g, b) = rgb(i as u8);
        *p = (u32::from(r) << fb.red_shift) | (u32::from(g) << fb.green_shift) | (u32::from(b) << fb.blue_shift);
    }
    let mut con = FbCon {
        fb,
        terms: alloc::vec![Term::new(fb.width / WIDTH, fb.height / HEIGHT)],
        active: 0,
        palette,
        cursor: None,
    };
    // (A new framebuffer, virtio-gpu's, shows the splash again.)
    if splash_showing() {
        con.paint_splash();
    } else {
        con.clear();
        con.render();
    }
    *CONSOLE.lock() = Some(con);
    true
}

/// The framebuffer the console draws on.
pub fn framebuffer() -> Option<Framebuffer> {
    CONSOLE.lock().as_ref().map(|c| c.fb)
}

/// Console size in (rows, columns), if there is a framebuffer console.
pub fn size() -> Option<(u16, u16)> {
    CONSOLE.lock().as_ref().map(|c| (c.terms[0].rows() as u16, c.terms[0].cols() as u16))
}

/// Show `bytes` on VT 1; returns what the terminal answers (cursor
/// reports).
pub fn write(bytes: &[u8]) -> Vec<u8> {
    write_vt(1, bytes)
}

/// Show `bytes` on virtual console `vt` (1 to 12); returns what its
/// terminal answers.
pub fn write_vt(vt: usize, bytes: &[u8]) -> Vec<u8> {
    let mut g = CONSOLE.lock();
    let Some(con) = g.as_mut() else { return Vec::new() };
    con.term_mut(vt).feed(bytes);
    if con.active + 1 == vt && drawing(con) {
        con.render();
    }
    con.term_mut(vt).take_responses()
}

/// Show kernel text (which never contains terminal queries), on VT 1.
pub fn show(bytes: &[u8]) {
    let mut g = CONSOLE.lock();
    if let Some(con) = g.as_mut() {
        con.terms[0].feed(bytes);
        if con.active == 0 && drawing(con) {
            con.render();
        }
    }
}

/// Like [`show`], but gives up instead of waiting if the console is busy
/// (for the panic path, where this CPU may hold the lock forever). A boot
/// splash ends at once: a panic must be seen.
pub fn try_show(bytes: &[u8]) {
    if !CONSOLE.is_locked() {
        if SPLASH.swap(SPLASH_OVER, core::sync::atomic::Ordering::AcqRel) == SPLASH_SHOWING {
            let mut g = CONSOLE.lock();
            if let Some(con) = g.as_mut() {
                con.clear();
                con.term_mut(1).mark_all_dirty();
            }
        }
        show(bytes);
    }
}

impl FbCon {
    /// Virtual console `vt`'s terminal, made blank if it is new.
    fn term_mut(&mut self, vt: usize) -> &mut Term {
        let (cols, rows) = (self.fb.width / WIDTH, self.fb.height / HEIGHT);
        while self.terms.len() < vt {
            self.terms.push(Term::new(cols, rows));
        }
        &mut self.terms[vt - 1]
    }

    /// The terminal in front.
    fn term(&self) -> &Term {
        &self.terms[self.active]
    }

    /// A colour's pixel value in the framebuffer's format.
    fn pixel(&self, c: Color) -> u32 {
        match c {
            Color::Index(i) => self.palette[i as usize],
            Color::Rgb(r, g, b) => {
                (u32::from(r) << self.fb.red_shift)
                    | (u32::from(g) << self.fb.green_shift)
                    | (u32::from(b) << self.fb.blue_shift)
            }
        }
    }

    /// A pixel in the framebuffer's format.
    fn rgb(&self, (r, g, b): (u8, u8, u8)) -> u32 {
        (u32::from(r) << self.fb.red_shift)
            | (u32::from(g) << self.fb.green_shift)
            | (u32::from(b) << self.fb.blue_shift)
    }

    fn put(&self, x: usize, y: usize, px: u32) {
        if x < self.fb.width && y < self.fb.height {
            let p = (self.fb.addr + (y * self.fb.pitch + x * 4) as u64) as *mut u32;
            // SAFETY: (x, y) is inside the framebuffer, which is mapped.
            unsafe { p.write_volatile(px) };
        }
    }

    /// The splash's mark size for this screen.
    fn splash_size(&self) -> (usize, &'static [u8]) {
        if self.fb.height >= 1400 { (192, LOGO_192) } else { (96, LOGO_96) }
    }

    /// The whole splash: the background, the mark a little above the
    /// middle, the empty track under it.
    fn paint_splash(&mut self) {
        let bg = self.rgb(SPLASH_BG);
        for y in 0..self.fb.height {
            for x in 0..self.fb.width {
                self.put(x, y, bg);
            }
        }
        let (size, mask) = self.splash_size();
        let (x0, y0) = ((self.fb.width.saturating_sub(size)) / 2, (self.fb.height * 2 / 5).saturating_sub(size / 2));
        let mix = |a: u8, b: u8, k: u32| ((u32::from(a) * (255 - k) + u32::from(b) * k + 127) / 255) as u8;
        for (i, &k) in mask.iter().enumerate().filter(|(_, k)| **k > 0) {
            let (x, y) = (x0 + i % size, y0 + i / size);
            let k = u32::from(k);
            let c = (
                mix(SPLASH_BG.0, SPLASH_INK.0, k),
                mix(SPLASH_BG.1, SPLASH_INK.1, k),
                mix(SPLASH_BG.2, SPLASH_INK.2, k),
            );
            self.put(x, y, self.rgb(c));
        }
        self.splash_step(0);
        crate::drivers::virtio::gpu::console_damage(0, self.fb.height as u32);
    }

    /// The track and the line moving along it at step `n`.
    fn splash_step(&mut self, n: u32) {
        let (size, _) = self.splash_size();
        let (tx, ty, tw, th) = splash_track(self.fb.width, self.fb.height, size);
        let (start, len) = splash_segment(tw, n);
        let (track, moving) = (self.rgb(SPLASH_TRACK), self.rgb(SPLASH_MOVING));
        for y in ty..ty + th {
            for x in 0..tw {
                self.put(tx + x, y, if (start..start + len).contains(&x) { moving } else { track });
            }
        }
        crate::drivers::virtio::gpu::console_damage(ty as u32, (ty + th) as u32);
    }

    fn clear(&mut self) {
        let bg = self.palette[0];
        for y in 0..self.fb.height {
            let row = (self.fb.addr + (y * self.fb.pitch) as u64) as *mut u32;
            for x in 0..self.fb.width {
                // SAFETY: (x, y) is inside the framebuffer, which the direct
                // map covers (the memory map lists it).
                unsafe { row.add(x).write_volatile(bg) };
            }
        }
    }

    fn draw_cell(&self, row: usize, col: usize, cell: Cell, invert: bool) {
        let (mut fg, mut bg) = cell.attr.resolved();
        if invert {
            core::mem::swap(&mut fg, &mut bg);
        }
        let (fg, bg) = (self.pixel(fg), self.pixel(bg));
        // Faint (SGR 2): half way to the background.
        let fg = if cell.attr.dim { ((fg & 0xFEFEFE) >> 1) + ((bg & 0xFEFEFE) >> 1) } else { fg };
        // A wide character: the box with its code point, over both cells
        // (the font has no wide glyphs).
        if cell.width() == 2 && !cell.is_tail() && col + 1 < self.term().cols() {
            let wide = font::wide_box(cell.ch);
            let left: [u8; HEIGHT] = core::array::from_fn(|i| (wide[i] >> 8) as u8);
            let right: [u8; HEIGHT] = core::array::from_fn(|i| wide[i] as u8);
            self.draw_bits(row, col, &left, cell, fg, bg);
            self.draw_bits(row, col + 1, &right, cell, fg, bg);
            return;
        }
        let glyph = font::glyph(if cell.is_tail() { ' ' } else { cell.ch });
        self.draw_bits(row, col, glyph, cell, fg, bg);
    }

    /// Draw one cell's bitmap with `cell`'s italic, underline and
    /// crossed-out lines.
    fn draw_bits(&self, row: usize, col: usize, glyph: &[u8; HEIGHT], cell: Cell, fg: u32, bg: u32) {
        let (x0, y0) = (col * WIDTH, row * HEIGHT);
        for (dy, &bits) in glyph.iter().enumerate() {
            // Italic: the upper half leans a pixel right; crossed out: a
            // line through the middle; underline: one near the bottom.
            let bits = if cell.attr.italic && dy < HEIGHT / 2 { bits >> 1 } else { bits };
            let line_here = (cell.attr.underline && dy == HEIGHT - 2) || (cell.attr.strike && dy == HEIGHT / 2);
            let bits = if line_here { 0xFF } else { bits };
            let line = (self.fb.addr + ((y0 + dy) * self.fb.pitch + x0 * 4) as u64) as *mut u32;
            for dx in 0..WIDTH {
                let px = if bits & (0x80 >> dx) != 0 { fg } else { bg };
                // SAFETY: The cell lies within the framebuffer (the grid is
                // sized from it) and the framebuffer is mapped.
                unsafe { line.add(dx).write_volatile(px) };
            }
        }
    }

    fn render(&mut self) {
        let active = self.active + 1;
        let mut rows = self.term_mut(active).take_dirty();
        if let Some((r, _)) = self.cursor
            && !rows.contains(&r)
        {
            rows.push(r);
        }
        let (mut top, mut bottom) = (usize::MAX, 0);
        for r in rows {
            for c in 0..self.term().cols() {
                // A wide character's tail was drawn with it.
                let cell = self.term().cell(r, c);
                if cell.is_tail() && c > 0 && self.term().cell(r, c - 1).width() == 2 {
                    continue;
                }
                self.draw_cell(r, c, cell, false);
            }
            (top, bottom) = (top.min(r), bottom.max(r + 1));
        }
        self.cursor = None;
        if self.term().cursor_visible {
            let (r, c) = self.term().cursor();
            self.draw_cell(r, c, self.term().cell(r, c), true);
            self.cursor = Some((r, c));
            (top, bottom) = (top.min(r), bottom.max(r + 1));
        }
        // A GPU that shows this framebuffer through host resources needs
        // to hear what changed.
        if top < bottom {
            crate::drivers::virtio::gpu::console_damage((top * HEIGHT) as u32, (bottom * HEIGHT) as u32);
        }
    }
}

/// The colour at (x, y) as (red, green, blue) (for tests).
pub fn pixel_rgb(x: usize, y: usize) -> Option<(u8, u8, u8)> {
    let px = pixel(x, y)?;
    let g = CONSOLE.lock();
    let fb = g.as_ref()?.fb;
    Some(((px >> fb.red_shift) as u8, (px >> fb.green_shift) as u8, (px >> fb.blue_shift) as u8))
}

/// Read back the pixel at (x, y) (for tests).
pub fn pixel(x: usize, y: usize) -> Option<u32> {
    let g = CONSOLE.lock();
    let con = g.as_ref()?;
    if x >= con.fb.width || y >= con.fb.height {
        return None;
    }
    let p = (con.fb.addr + (y * con.fb.pitch + x * 4) as u64) as *const u32;
    // SAFETY: Inside the mapped framebuffer.
    Some(unsafe { p.read_volatile() })
}

/// The pixel value of palette color `c` (for tests).
pub fn color(c: u8) -> Option<u32> {
    CONSOLE.lock().as_ref().map(|con| con.palette[c as usize])
}
