// SPDX-License-Identifier: MIT OR Apache-2.0

//! A canvas: an opaque ARGB8888 pixel buffer with a clip rectangle.

use alloc::vec;
use alloc::vec::Vec;

use crate::color::{Color, blend, div255, over_opaque};
use crate::raster::Mask;

/// A rectangle in whole pixels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    pub const fn new(x: i32, y: i32, w: i32, h: i32) -> Rect {
        Rect { x, y, w, h }
    }

    pub fn right(&self) -> i32 {
        self.x + self.w
    }

    pub fn bottom(&self) -> i32 {
        self.y + self.h
    }

    pub fn is_empty(&self) -> bool {
        self.w <= 0 || self.h <= 0
    }

    pub fn intersect(&self, o: &Rect) -> Rect {
        let (x, y) = (self.x.max(o.x), self.y.max(o.y));
        let (r, b) = (self.right().min(o.right()), self.bottom().min(o.bottom()));
        Rect::new(x, y, (r - x).max(0), (b - y).max(0))
    }

    pub fn contains(&self, px: i32, py: i32) -> bool {
        px >= self.x && py >= self.y && px < self.right() && py < self.bottom()
    }

    /// The smallest rectangle holding both (an empty one adds nothing).
    pub fn union(&self, o: &Rect) -> Rect {
        if self.is_empty() {
            return *o;
        }
        if o.is_empty() {
            return *self;
        }
        let (x, y) = (self.x.min(o.x), self.y.min(o.y));
        Rect::new(x, y, self.right().max(o.right()) - x, self.bottom().max(o.bottom()) - y)
    }
}

pub struct Canvas {
    pub width: i32,
    pub height: i32,
    pub pixels: Vec<u32>,
    clip: Rect,
}

impl core::fmt::Debug for Canvas {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Canvas({}x{})", self.width, self.height)
    }
}

impl Canvas {
    /// A canvas filled with `background`, which may be transparent (a
    /// layer to composite).
    pub fn new(width: i32, height: i32, background: Color) -> Canvas {
        Canvas {
            width,
            height,
            pixels: vec![background.0; (width * height).max(0) as usize],
            clip: Rect::new(0, 0, width, height),
        }
    }

    pub fn bounds(&self) -> Rect {
        Rect::new(0, 0, self.width, self.height)
    }

    /// Limit drawing to `r` (within the canvas); returns the old clip.
    pub fn set_clip(&mut self, r: Rect) -> Rect {
        let old = self.clip;
        self.clip = r.intersect(&self.bounds());
        old
    }

    pub fn clip(&self) -> Rect {
        self.clip
    }

    pub fn pixel(&self, x: i32, y: i32) -> u32 {
        self.pixels[(y * self.width + x) as usize]
    }

    /// Fill `r` with `c` (blended by its alpha).
    pub fn fill_rect(&mut self, r: Rect, c: Color) {
        let r = r.intersect(&self.clip);
        if r.is_empty() {
            return;
        }
        let a = c.alpha() as u32;
        for y in r.y..r.bottom() {
            let at = (y * self.width + r.x) as usize;
            let row = &mut self.pixels[at..at + r.w as usize];
            match a {
                0 => {}
                255 => row.fill(c.0),
                _ if opaque(row) => {
                    for p in row {
                        *p = over_opaque(*p, c.0, a);
                    }
                }
                _ => {
                    for p in row {
                        *p = if *p >> 24 == 255 { over_opaque(*p, c.0, a) } else { blend(*p, c, 255) };
                    }
                }
            }
        }
    }

    /// Composite `c` through the coverage of `mask`.
    pub fn fill_mask(&mut self, mask: &Mask, c: Color) {
        self.fill_coverage(mask.x, mask.y, mask.w, mask.h, &mask.data, c);
    }

    /// Composite `c` through `w` × `h` coverage values placed at (x, y).
    pub fn fill_coverage(&mut self, mx: i32, my: i32, w: i32, h: i32, data: &[u8], c: Color) {
        self.fill_coverage_except(mx, my, w, h, data, c, Rect::new(0, 0, 0, 0));
    }

    /// [`Canvas::fill_coverage`], leaving the pixels in `hole` alone.
    #[allow(clippy::too_many_arguments)]
    pub fn fill_coverage_except(&mut self, mx: i32, my: i32, w: i32, h: i32, data: &[u8], c: Color, hole: Rect) {
        let area = Rect::new(mx, my, w, h).intersect(&self.clip);
        let hole = hole.intersect(&area);
        let alpha = c.alpha() as u32;
        for y in area.y..area.bottom() {
            let mrow = ((y - my) * w) as usize;
            let row = (y * self.width) as usize;
            let spans = if hole.is_empty() || y < hole.y || y >= hole.bottom() {
                [(area.x, area.right()), (0, 0)]
            } else {
                [(area.x, hole.x), (hole.right(), area.right())]
            };
            for (x0, x1) in spans {
                if x0 >= x1 {
                    continue;
                }
                let n = (x1 - x0) as usize;
                let cov = &data[mrow + (x0 - mx) as usize..][..n];
                let px = &mut self.pixels[row + x0 as usize..][..n];
                if opaque(px) {
                    for (p, &k) in px.iter_mut().zip(cov) {
                        *p = over_opaque(*p, c.0, div255(alpha * k as u32 + 127));
                    }
                    continue;
                }
                // A transparent run of a layer (a shadow drawn first):
                // the colour at each pixel's alpha.
                if px.iter().fold(0, |a, &p| a | p) == 0 {
                    let rgb = c.0 & 0x00FF_FFFF;
                    for (p, &k) in px.iter_mut().zip(cov) {
                        let a = div255(alpha * k as u32 + 127);
                        *p = if a == 0 { 0 } else { rgb | (a << 24) };
                    }
                    continue;
                }
                for (p, &k) in px.iter_mut().zip(cov) {
                    if k != 0 {
                        *p = if *p >> 24 == 255 {
                            over_opaque(*p, c.0, div255(alpha * k as u32 + 127))
                        } else {
                            blend(*p, c, k)
                        };
                    }
                }
            }
        }
    }

    /// Composite `layer` (the same size) over this canvas at `opacity`,
    /// shifted down by `dy` pixels, within the clip (motion: fades and
    /// rises).
    pub fn composite(&mut self, layer: &Canvas, opacity: f32, dy: i32) {
        self.composite_within(layer, opacity, dy, layer.bounds());
    }

    /// [`Canvas::composite`], only the layer's part `within` (where
    /// something was drawn on it).
    pub fn composite_within(&mut self, layer: &Canvas, opacity: f32, dy: i32, within: Rect) {
        let k = (opacity.clamp(0.0, 1.0) * 255.0 + 0.5) as u32;
        if k == 0 {
            return;
        }
        let within = within.intersect(&layer.bounds());
        let area = self.clip.intersect(&Rect::new(within.x, within.y + dy, within.w, within.h));
        if area.is_empty() {
            return;
        }
        let n = area.w as usize;
        for py in area.y..area.bottom() {
            let src = &layer.pixels[((py - dy) * layer.width + area.x) as usize..][..n];
            let dst = &mut self.pixels[(py * self.width + area.x) as usize..][..n];
            if opaque(dst) {
                for (d, &s) in dst.iter_mut().zip(src) {
                    *d = over_opaque(*d, s, div255((s >> 24) * k + 127));
                }
                continue;
            }
            for (d, &s) in dst.iter_mut().zip(src) {
                let a = div255((s >> 24) * k + 127);
                if a != 0 {
                    *d = if *d >> 24 == 255 {
                        over_opaque(*d, s, a)
                    } else {
                        blend(*d, Color((s & 0x00FF_FFFF) | (a << 24)), 255)
                    };
                }
            }
        }
    }

    /// `src` (the same size) within the clip, with `c` blended over it
    /// at its alpha: copying a picture and dimming it in one pass, as
    /// [`Canvas::fill_rect`] over a copy would (M32 phase 2).
    pub fn copy_dimmed(&mut self, src: &Canvas, c: Color) {
        let r = self.clip.intersect(&src.bounds());
        if r.is_empty() {
            return;
        }
        let n = r.w as usize;
        for y in r.y..r.bottom() {
            let from = &src.pixels[(y * src.width + r.x) as usize..][..n];
            dim_row(&mut self.pixels[(y * self.width + r.x) as usize..][..n], from, c);
        }
    }

    /// The smallest rectangle within `r` holding every pixel that isn't
    /// wholly transparent (on a layer: where something was drawn).
    pub fn drawn_within(&self, r: Rect) -> Rect {
        let r = r.intersect(&self.bounds());
        let (mut x0, mut y0, mut x1, mut y1) = (i32::MAX, i32::MAX, i32::MIN, i32::MIN);
        for y in r.y..r.bottom() {
            let row = &self.pixels[(y * self.width + r.x) as usize..][..r.w as usize];
            let (Some(a), Some(b)) = (row.iter().position(|&p| p >> 24 != 0), row.iter().rposition(|&p| p >> 24 != 0))
            else {
                continue;
            };
            (x0, x1) = (x0.min(r.x + a as i32), x1.max(r.x + b as i32 + 1));
            (y0, y1) = (y0.min(y), y + 1);
        }
        if x0 > x1 { Rect::default() } else { Rect::new(x0, y0, x1 - x0, y1 - y0) }
    }

    /// Clear to transparent (a layer about to be drawn into).
    pub fn clear(&mut self) {
        self.pixels.fill(0);
    }

    /// Clear `r` to transparent: where a layer was last drawn, rather than
    /// all of it (33 MB at 4K).
    pub fn clear_area(&mut self, r: Rect) {
        let r = r.intersect(&self.bounds());
        for y in r.y..r.bottom() {
            let at = (y * self.width + r.x) as usize;
            self.pixels[at..at + r.w as usize].fill(0);
        }
    }

    /// Copy an opaque image at (x, y): its pixels' fourth byte means
    /// nothing (XRGB8888), so it is made opaque on the way.
    pub fn copy_opaque(&mut self, x: i32, y: i32, w: i32, h: i32, data: &[u32]) {
        let area = Rect::new(x, y, w, h).intersect(&self.clip);
        if area.is_empty() {
            return;
        }
        let n = area.w as usize;
        for py in area.y..area.bottom() {
            let src = &data[((py - y) * w + (area.x - x)) as usize..][..n];
            let dst = &mut self.pixels[(py * self.width + area.x) as usize..][..n];
            for (d, &s) in dst.iter_mut().zip(src) {
                *d = s | 0xFF00_0000;
            }
        }
    }

    /// Composite an image (0xAARRGGBB, not premultiplied) at (x, y).
    pub fn draw_image(&mut self, x: i32, y: i32, w: i32, h: i32, data: &[u32]) {
        let area = Rect::new(x, y, w, h).intersect(&self.clip);
        if area.is_empty() {
            return;
        }
        let n = area.w as usize;
        for py in area.y..area.bottom() {
            let src = &data[((py - y) * w + (area.x - x)) as usize..][..n];
            let dst = &mut self.pixels[(py * self.width + area.x) as usize..][..n];
            // An opaque row (a window's content, usually) is copied.
            if opaque(src) {
                dst.copy_from_slice(src);
                continue;
            }
            for (d, &s) in dst.iter_mut().zip(src) {
                let a = s >> 24;
                *d = match a {
                    0 => *d,
                    255 => s,
                    _ if *d >> 24 == 255 => over_opaque(*d, s, a),
                    _ => blend(*d, Color(s), 255),
                };
            }
        }
    }
}

/// `from` with `c` blended over it at its alpha, into `to`.
fn dim_row(to: &mut [u32], from: &[u32], c: Color) {
    let a = c.alpha() as u32;
    if a == 0 {
        to.copy_from_slice(from);
    } else if opaque(from) {
        for (d, &s) in to.iter_mut().zip(from) {
            *d = over_opaque(s, c.0, a);
        }
    } else {
        for (d, &s) in to.iter_mut().zip(from) {
            *d = blend(s, c, 255);
        }
    }
}

/// The part `from` of `src`, with `c` blended over it, into a screen's
/// buffer `to` (its top left corner at `from`'s) whose rows are `pitch`
/// words apart: a dimmed picture written straight to a display, without a
/// canvas copied after (M32 phase 2; a display each, ADR 0170). The
/// rectangles in `holes` (in `src`) are left alone: something else goes
/// there.
pub fn dim_into(to: &mut [u32], pitch: usize, src: &Canvas, from: Rect, c: Color, holes: &[Rect]) {
    let from = from.intersect(&src.bounds());
    let holes: Vec<Rect> = holes.iter().map(|h| h.intersect(&from)).filter(|h| !h.is_empty()).collect();
    let mut cuts: Vec<(usize, usize)> = Vec::new();
    let w = from.w as usize;
    for y in from.y..from.bottom() {
        let at = (y * src.width + from.x) as usize;
        let row_from = &src.pixels[at..at + w];
        let ly = (y - from.y) as usize;
        let Some(row) = to.get_mut(ly * pitch..ly * pitch + w) else { continue };
        cuts.clear();
        cuts.extend(
            holes
                .iter()
                .filter(|h| (h.y..h.bottom()).contains(&y))
                .map(|h| ((h.x - from.x) as usize, (h.right() - from.x) as usize)),
        );
        cuts.sort_unstable();
        let mut x = 0;
        for &(a, b) in cuts.iter().chain(&[(w, w)]) {
            if a > x {
                dim_row(&mut row[x..a], &row_from[x..a], c);
            }
            x = x.max(b);
        }
    }
}

/// Whether every pixel of `row` is opaque: then the blends need no
/// per-pixel test, and their loops vectorize (M32 phase 2).
fn opaque(row: &[u32]) -> bool {
    row.iter().fold(0xFF00_0000, |a, &p| a & p) >> 24 == 0xFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_images_are_copied_whatever_their_fourth_byte() {
        let mut c = Canvas::new(4, 2, Color::rgb(0x111111));
        c.set_clip(Rect::new(0, 0, 3, 2));
        // XRGB8888 with nothing (or anything) in the fourth byte.
        c.copy_opaque(1, 0, 3, 1, &[0x0012_3456, 0x7F65_4321, 0x00AB_CDEF]);
        assert_eq!(c.pixel(0, 0), 0xFF11_1111);
        assert_eq!(c.pixel(1, 0), 0xFF12_3456);
        assert_eq!(c.pixel(2, 0), 0xFF65_4321);
        // Outside the clip.
        assert_eq!(c.pixel(3, 0), 0xFF11_1111);
        assert_eq!(c.pixel(1, 1), 0xFF11_1111);
    }

    #[test]
    fn clipping() {
        let mut c = Canvas::new(10, 10, Color::rgb(0xFFFFFF));
        c.set_clip(Rect::new(2, 2, 3, 3));
        c.fill_rect(Rect::new(0, 0, 10, 10), Color::rgb(0x000000));
        assert_eq!(c.pixel(1, 1), 0xFFFF_FFFF);
        assert_eq!(c.pixel(2, 2), 0xFF00_0000);
        assert_eq!(c.pixel(4, 4), 0xFF00_0000);
        assert_eq!(c.pixel(5, 5), 0xFFFF_FFFF);
    }

    #[test]
    fn copied_and_dimmed_as_filled() {
        let mut src = Canvas::new(8, 3, Color::rgb(0x336699));
        src.fill_rect(Rect::new(2, 0, 3, 3), Color::rgb(0xF0E0D0));
        let dim = Color::rgb(0x101010).with_alpha(97);
        let mut want = Canvas::new(8, 3, Color::rgb(0));
        want.pixels.copy_from_slice(&src.pixels);
        want.fill_rect(want.bounds(), dim);
        let mut got = Canvas::new(8, 3, Color::rgb(0));
        got.copy_dimmed(&src, dim);
        assert_eq!(got.pixels, want.pixels);
        got.copy_dimmed(&src, Color::TRANSPARENT);
        assert_eq!(got.pixels, src.pixels);
        // Into a screen buffer with a wider pitch: the same rows.
        let mut screen = std::vec![7u32; 10 * 3];
        dim_into(&mut screen, 10, &src, src.bounds(), dim, &[]);
        for y in 0..3 {
            assert_eq!(&screen[y * 10..y * 10 + 8], &want.pixels[y * 8..y * 8 + 8]);
            assert_eq!(&screen[y * 10 + 8..y * 10 + 10], &[7, 7]);
        }
        // Holes (overlapping) are left alone.
        let mut screen = std::vec![7u32; 10 * 3];
        dim_into(&mut screen, 10, &src, src.bounds(), dim, &[Rect::new(1, 1, 3, 2), Rect::new(2, 2, 4, 5)]);
        for y in 0..3usize {
            for x in 0..8usize {
                let hole = (y >= 1 && (1..4).contains(&x)) || (y >= 2 && (2..6).contains(&x));
                let want_px = if hole { 7 } else { want.pixels[y * 8 + x] };
                assert_eq!(screen[y * 10 + x], want_px, "({x}, {y})");
            }
        }
        // A part of it (a display's), written at the buffer's corner.
        let mut screen = std::vec![7u32; 4 * 2];
        dim_into(&mut screen, 4, &src, Rect::new(3, 1, 4, 2), dim, &[]);
        assert_eq!(&screen[..4], &want.pixels[8 + 3..8 + 7]);
        assert_eq!(&screen[4..], &want.pixels[16 + 3..16 + 7]);
    }

    #[test]
    fn where_a_layer_was_drawn() {
        let mut l = Canvas::new(20, 10, Color::TRANSPARENT);
        assert!(l.drawn_within(l.bounds()).is_empty());
        l.fill_rect(Rect::new(3, 2, 5, 4), Color::rgb(0).with_alpha(1));
        assert_eq!(l.drawn_within(l.bounds()), Rect::new(3, 2, 5, 4));
        assert_eq!(l.drawn_within(Rect::new(5, 0, 20, 4)), Rect::new(5, 2, 3, 2));
    }

    #[test]
    fn layers() {
        let mut c = Canvas::new(4, 4, Color::rgb(0x000000));
        let mut l = Canvas::new(4, 4, Color::rgb(0xFFFFFF));
        l.clear();
        l.fill_rect(Rect::new(0, 0, 4, 1), Color::rgb(0xFFFFFF));
        c.composite(&l, 1.0, 2);
        assert_eq!(c.pixel(0, 2), 0xFFFF_FFFF);
        assert_eq!(c.pixel(0, 0), 0xFF00_0000);
        let mut d = Canvas::new(4, 4, Color::rgb(0x000000));
        d.composite(&l, 0.5, 0);
        let v = d.pixel(1, 0) & 0xFF;
        assert!((120..=135).contains(&v), "{v}");
    }
}
