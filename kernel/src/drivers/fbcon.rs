// SPDX-License-Identifier: MIT OR Apache-2.0

//! The framebuffer console: a terminal emulator (`slate-term`) drawn with
//! Slate's font on the bootloader's linear framebuffer.

use alloc::vec::Vec;

use slate_term::font::{self, HEIGHT, WIDTH};
use slate_term::vt::{Cell, Color, Term, rgb};

use crate::arch::boot::Framebuffer;
use crate::sync::IrqSpinLock;

#[derive(Debug)]
struct FbCon {
    fb: Framebuffer,
    term: Term,
    /// Pixel values for the 256 palette colors, in the framebuffer's format.
    palette: [u32; 256],
    /// Where the cursor was last drawn.
    cursor: Option<(usize, usize)>,
}

static CONSOLE: IrqSpinLock<Option<FbCon>> = IrqSpinLock::new(None);

/// While a DRM master owns the screen, the console keeps its text but
/// does not draw (ADR 0033).
static SUSPENDED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Stop drawing (a DRM master took the screen) or start again, redrawing
/// everything.
pub fn set_suspended(on: bool) {
    SUSPENDED.store(on, core::sync::atomic::Ordering::Release);
    if !on {
        let mut g = CONSOLE.lock();
        if let Some(con) = g.as_mut() {
            con.clear();
            con.term.mark_all_dirty();
            con.render();
            crate::drivers::virtio::gpu::console_damage(0, con.fb.height as u32);
        }
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
    let mut con = FbCon { fb, term: Term::new(fb.width / WIDTH, fb.height / HEIGHT), palette, cursor: None };
    con.clear();
    con.render();
    *CONSOLE.lock() = Some(con);
    true
}

/// The framebuffer the console draws on.
pub fn framebuffer() -> Option<Framebuffer> {
    CONSOLE.lock().as_ref().map(|c| c.fb)
}

/// Console size in (rows, columns), if there is a framebuffer console.
pub fn size() -> Option<(u16, u16)> {
    CONSOLE.lock().as_ref().map(|c| (c.term.rows() as u16, c.term.cols() as u16))
}

/// Show `bytes`; returns what the terminal answers (cursor reports).
pub fn write(bytes: &[u8]) -> Vec<u8> {
    let mut g = CONSOLE.lock();
    let Some(con) = g.as_mut() else { return Vec::new() };
    con.term.feed(bytes);
    if !suspended() {
        con.render();
    }
    con.term.take_responses()
}

/// Show kernel text (which never contains terminal queries).
pub fn show(bytes: &[u8]) {
    let mut g = CONSOLE.lock();
    if let Some(con) = g.as_mut() {
        con.term.feed(bytes);
        if !suspended() {
            con.render();
        }
    }
}

/// Like [`show`], but gives up instead of waiting if the console is busy
/// (for the panic path, where this CPU may hold the lock forever).
pub fn try_show(bytes: &[u8]) {
    if !CONSOLE.is_locked() {
        show(bytes);
    }
}

impl FbCon {
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
        if cell.width() == 2 && !cell.is_tail() && col + 1 < self.term.cols() {
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
        let mut rows = self.term.take_dirty();
        if let Some((r, _)) = self.cursor
            && !rows.contains(&r)
        {
            rows.push(r);
        }
        let (mut top, mut bottom) = (usize::MAX, 0);
        for r in rows {
            for c in 0..self.term.cols() {
                // A wide character's tail was drawn with it.
                let cell = self.term.cell(r, c);
                if cell.is_tail() && c > 0 && self.term.cell(r, c - 1).width() == 2 {
                    continue;
                }
                self.draw_cell(r, c, cell, false);
            }
            (top, bottom) = (top.min(r), bottom.max(r + 1));
        }
        self.cursor = None;
        if self.term.cursor_visible {
            let (r, c) = self.term.cursor();
            self.draw_cell(r, c, self.term.cell(r, c), true);
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
