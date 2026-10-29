// SPDX-License-Identifier: MIT OR Apache-2.0

//! A screen test for machines where the picture comes out wrong (ADR
//! 0111): with a `slate-screen-test` file on the boot volume, the loader
//! shows a test pattern in the firmware's first mode and in the mode it
//! chose, each drawn twice, 12 seconds apiece: by writing the
//! framebuffer as the kernel does (A), and by the firmware's own Blt (B).
//! A photo of each shows the real line length and any offset: the
//! corners are coloured, the diagonal is at 45 degrees, and the grid
//! lines are 100 pixels apart.

use alloc::format;

use slate_ui::paint::Painter;
use slate_ui::text::GlyphCache;
use slate_ui::ui::Area;
use slate_ui::{Canvas, Color, Rect};

use crate::{bs, efi};

/// The pattern for a `w` × `h` screen, labelled `what`.
fn pattern(w: u32, h: u32, what: &str) -> Canvas {
    let (wi, hi) = (w as i32, h as i32);
    let mut c = Canvas::new(wi, hi, Color::rgb(0x202020));
    for x in (0..wi).step_by(100) {
        let colour = if x % 500 == 0 { 0xA0A0A0 } else { 0x505050 };
        c.fill_rect(Rect::new(x, 0, 1, hi), Color::rgb(colour));
    }
    for y in (0..hi).step_by(100) {
        let colour = if y % 500 == 0 { 0xA0A0A0 } else { 0x505050 };
        c.fill_rect(Rect::new(0, y, wi, 1), Color::rgb(colour));
    }
    for i in 0..hi.min(wi) {
        c.fill_rect(Rect::new(i, i, 2, 1), Color::rgb(0xFFFFFF));
    }
    // A white frame round the whole screen, and the corners.
    for r in [Rect::new(0, 0, wi, 2), Rect::new(0, hi - 2, wi, 2), Rect::new(0, 0, 2, hi), Rect::new(wi - 2, 0, 2, hi)]
    {
        c.fill_rect(r, Color::rgb(0xFFFFFF));
    }
    c.fill_rect(Rect::new(0, 0, 120, 120), Color::rgb(0xFF0000));
    c.fill_rect(Rect::new(wi - 120, 0, 120, 120), Color::rgb(0x00FF00));
    c.fill_rect(Rect::new(0, hi - 120, 120, 120), Color::rgb(0x0000FF));
    c.fill_rect(Rect::new(wi - 120, hi - 120, 120, 120), Color::rgb(0xFFFF00));
    if let Some(f) = slate_loader::screen::Fonts::new() {
        let mut cache = GlyphCache::new();
        let mut p = Painter::new(&mut c, &mut cache, 1.0);
        let st = p.style(&f.medium, 36.0, Color::rgb(0xFFFFFF));
        let at = Area::new(160.0, 160.0, 0.0, 0.0);
        p.fill(Area::new(150.0, 150.0, 1100.0f32.min(w as f32 - 300.0), 70.0), 6.0, Color::rgb(0x000000));
        p.line(&st, at.x, at.y, 50.0, what);
    }
    c
}

/// Show the pattern in each of `modes` (numbers), both ways.
pub fn run(g: *mut efi::GraphicsOutput, modes: &[u32]) {
    // SAFETY: The firmware's graphics output protocol.
    let (set, blt) = unsafe { ((*g).set_mode, (*g).blt) };
    for &number in modes {
        if efi::is_error(set(g, number)) {
            continue;
        }
        // SAFETY: The protocol's mode, just set, and its information.
        let (base, i) = unsafe { ((*(*g).mode).frame_buffer_base, &*(*(*g).mode).info) };
        let (w, h, line) = (i.horizontal_resolution, i.vertical_resolution, i.pixels_per_scan_line);
        let a = pattern(w, h, &format!("A: written  mode {number}: {w}x{h}, {line} a line"));
        for y in 0..h as usize {
            let row = &a.pixels[y * w as usize..(y + 1) * w as usize];
            let dst = (base as usize + y * line as usize * 4) as *mut u32;
            for (x, &px) in row.iter().enumerate() {
                let (r, g, b) = ((px >> 16) & 0xff, (px >> 8) & 0xff, px & 0xff);
                let v = if i.pixel_format == efi::PIXEL_RGB { b << 16 | g << 8 | r } else { r << 16 | g << 8 | b };
                // SAFETY: The firmware's framebuffer: `line` pixels a row
                // and `h` rows, identity mapped.
                unsafe { core::ptr::write_volatile(dst.add(x), v) };
            }
        }
        (bs().stall)(12_000_000);
        let mut b = pattern(w, h, &format!("B: firmware Blt  mode {number}: {w}x{h}, {line} a line"));
        blt(g, b.pixels.as_mut_ptr(), efi::BLT_BUFFER_TO_VIDEO, 0, 0, 0, 0, w as usize, h as usize, 0);
        (bs().stall)(12_000_000);
    }
}
