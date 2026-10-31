// SPDX-License-Identifier: MIT OR Apache-2.0

//! Drawing in logical pixels on a whole canvas: the primitives a desktop
//! surface needs (Strata, ADR 0037), without the installer window that
//! `ui` centres everything in.

use crate::canvas::{Canvas, Rect};
use crate::color::Color;
use crate::icon::{self, Icon};
use crate::math::round;
use crate::path::{Path, Transform};
use crate::shadow::{self, BoxShadow};
use crate::stroke;
use crate::text::{self, Face, GlyphCache, Style};
use crate::ui::Area;

/// A canvas and glyph cache at `scale` device pixels per logical pixel.
pub struct Painter<'a> {
    pub canvas: &'a mut Canvas,
    pub cache: &'a mut GlyphCache,
    pub scale: f32,
    /// The logical point at the canvas's top left corner, and the size
    /// [`Painter::size`] gives: on several displays (Strata, ADR 0170) the
    /// canvas holds them all, the primary one's corner is (0, 0) and its
    /// size is the screen's; otherwise (0, 0) and the canvas's size.
    origin: (f32, f32),
    view: Option<(f32, f32)>,
}

impl core::fmt::Debug for Painter<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Painter({}x{} at {})", self.canvas.width, self.canvas.height, self.scale)
    }
}

/// Every text's size is multiplied by this (the person's text size;
/// ADR 0186), as an `f32`'s bits: the program's, set once its settings
/// are read.
static TEXT_SCALE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0x3F80_0000);

/// Make text this much bigger (1 as designed).
pub fn set_text_scale(k: f32) {
    TEXT_SCALE.store(k.clamp(0.5, 3.0).to_bits(), core::sync::atomic::Ordering::Relaxed);
}

/// The text scale now.
pub fn text_scale() -> f32 {
    f32::from_bits(TEXT_SCALE.load(core::sync::atomic::Ordering::Relaxed))
}

impl<'a> Painter<'a> {
    pub fn new(canvas: &'a mut Canvas, cache: &'a mut GlyphCache, scale: f32) -> Painter<'a> {
        Painter { canvas, cache, scale, origin: (0.0, 0.0), view: None }
    }

    /// The canvas's top left corner at logical `origin`, and `view` the
    /// screen's logical size (the primary display's, ADR 0170).
    pub fn at(mut self, origin: (f32, f32), view: (f32, f32)) -> Painter<'a> {
        self.origin = origin;
        self.view = Some(view);
        self
    }

    /// Another canvas, placed as this one is (a layer of the same size).
    pub fn placed_as(&self, canvas: &'a mut Canvas, cache: &'a mut GlyphCache) -> Painter<'a> {
        Painter { canvas, cache, scale: self.scale, origin: self.origin, view: self.view }
    }

    /// The screen's size in logical pixels (the canvas's, unless placed).
    pub fn size(&self) -> (f32, f32) {
        self.view.unwrap_or((self.canvas.width as f32 / self.scale, self.canvas.height as f32 / self.scale))
    }

    /// The logical point at the canvas's top left corner.
    pub fn origin(&self) -> (f32, f32) {
        self.origin
    }

    /// A logical point in device pixels.
    pub fn to_device(&self, x: f32, y: f32) -> (f32, f32) {
        (self.dx(x), self.dy(y))
    }

    /// Logical x and y to device pixels.
    fn dx(&self, x: f32) -> f32 {
        (x - self.origin.0) * self.scale
    }

    fn dy(&self, y: f32) -> f32 {
        (y - self.origin.1) * self.scale
    }

    fn t(&self) -> Transform {
        Transform::new(self.scale, -self.origin.0 * self.scale, -self.origin.1 * self.scale)
    }

    /// The device rectangle of `a`, rounded to whole pixels.
    pub fn device(&self, a: &Area) -> Rect {
        let (x0, y0) = (round(self.dx(a.x)) as i32, round(self.dy(a.y)) as i32);
        let (x1, y1) = (round(self.dx(a.right())) as i32, round(self.dy(a.bottom())) as i32);
        Rect::new(x0, y0, x1 - x0, y1 - y0)
    }

    /// Fill `a` with `c` (corner radius `r`).
    pub fn fill(&mut self, a: Area, r: f32, c: Color) {
        if r == 0.0 {
            let d = self.device(&a);
            self.canvas.fill_rect(d, c);
        } else {
            self.fill_rounded(a, r, c);
        }
    }

    /// A rounded rectangle, filled band by band ([`Painter::fill_banded`]).
    fn fill_rounded(&mut self, a: Area, r: f32, c: Color) {
        let r = r.min(a.w.min(a.h) * 0.5).max(0.0);
        self.fill_banded(&Path::rounded_rect(a.x, a.y, a.w, a.h, r), a.y + r, a.bottom() - r, c);
    }

    /// Fill `path`, whose rows from `top` to `bottom` (logical) are all
    /// crossed by the same vertical edges and nothing else: those rows'
    /// coverage is one row's, so one is rasterized and used for all; its
    /// whole runs are filled across the band at once, its empty runs
    /// skipped, and only its edge pixels blended row by row. The rows
    /// above and below are rasterized as any path is. The same pixels as
    /// filling the path, without rasterizing window-sized masks each frame
    /// (at 4K most of a frame's work; M32 phase 2).
    fn fill_banded(&mut self, path: &Path, top: f32, bottom: f32, c: Color) {
        let t = self.t();
        let clip = self.canvas.clip();
        let from = crate::math::ceil(self.dy(top)) as i32;
        let to = crate::math::floor(self.dy(bottom)) as i32;
        let (band_from, band_to) = (from.max(clip.y), to.min(clip.bottom()));
        if band_to - band_from < 8 {
            path.fill(self.canvas, &t, c);
            return;
        }
        let lines = path.flatten(&t);
        for (y0, y1) in [(clip.y, band_from), (band_to, clip.bottom())] {
            if y0 < y1 {
                let m = crate::raster::rasterize_rows(&lines, y0, y1);
                self.canvas.fill_mask(&m, c);
            }
        }
        let row = crate::raster::rasterize_rows(&lines, band_from, band_from + 1);
        if row.h != 1 {
            return;
        }
        let d = &row.data;
        let n = band_to - band_from;
        let mut i = 0;
        while i < d.len() {
            let v = d[i];
            let run =
                d[i..].iter().position(|&x| (x == 255) != (v == 255) || (x == 0) != (v == 0)).unwrap_or(d.len() - i);
            let x = row.x + i as i32;
            match v {
                0 => {}
                255 => self.canvas.fill_rect(Rect::new(x, band_from, run as i32, n), c),
                _ => {
                    for y in band_from..band_to {
                        self.canvas.fill_coverage(x, y, run as i32, 1, &d[i..i + run], c);
                    }
                }
            }
            i += run;
        }
    }

    /// A border `width` wide inside `a`.
    pub fn border(&mut self, a: Area, r: f32, width: f32, c: Color) {
        // The inner corners end where the outer ones do, or `width` down.
        let edge = r.min(a.w.min(a.h) * 0.5).max(width);
        self.fill_banded(&Path::rounded_ring(a.x, a.y, a.w, a.h, r, width), a.y + edge, a.bottom() - edge, c);
    }

    /// A box shadow under `a`, its offsets and sizes in logical pixels.
    pub fn shadow(&mut self, a: Area, r: f32, s: &BoxShadow) {
        self.shadow_with_hole(a, r, s, Rect::new(0, 0, 0, 0));
    }

    /// A box shadow under `a`, which is filled next with an opaque colour
    /// (corner radius `r`): the shadow's pixels it will cover are skipped.
    pub fn shadow_under(&mut self, a: Area, r: f32, s: &BoxShadow) {
        // Inside the box inset by its radius the fill covers every pixel
        // whole.
        let inner = self.device(&a.grow(-r - 1.0));
        self.shadow_with_hole(a, r, s, inner);
    }

    fn shadow_with_hole(&mut self, a: Area, r: f32, s: &BoxShadow, hole: Rect) {
        let k = self.scale;
        let d = BoxShadow { dx: s.dx * k, dy: s.dy * k, blur: s.blur * k, spread: s.spread * k, color: s.color };
        let cache = Some(&mut self.cache.shadows);
        let (x, y) = ((a.x - self.origin.0) * k, (a.y - self.origin.1) * k);
        shadow::draw_cached(self.canvas, cache, x, y, a.w * k, a.h * k, r * k, &d, hole);
    }

    /// A polyline `width` logical pixels wide through logical points.
    pub fn polyline(&mut self, points: &[(f32, f32)], width: f32, c: Color) {
        let t = self.t();
        stroke::polyline(points, width).fill(self.canvas, &t, c);
    }

    /// Fill `path`, given in logical pixels.
    pub fn path(&mut self, path: &Path, c: Color) {
        let t = self.t();
        path.fill(self.canvas, &t, c);
    }

    /// A style for `face` at a logical size, with tracking in ems.
    pub fn style<'s, 'f>(&self, face: &'s Face<'f>, size: f32, c: Color) -> Style<'s, 'f> {
        Style::new(face, size * self.scale * text_scale(), c)
    }

    /// Draw text with its baseline at logical `baseline`; returns the
    /// logical advance.
    pub fn text(&mut self, style: &Style<'_, '_>, x: f32, baseline: f32, s: &str) -> f32 {
        let (x, y) = (self.dx(x), self.dy(baseline));
        text::draw(self.canvas, self.cache, style, x, y, s) / self.scale
    }

    /// Text centred vertically in a line box `height` tall at `top`.
    pub fn line(&mut self, style: &Style<'_, '_>, x: f32, top: f32, height: f32, s: &str) -> f32 {
        let base = top + style.face.baseline(style.size / self.scale, height);
        self.text(style, x, base, s)
    }

    /// The logical width of text.
    pub fn measure(&self, style: &Style<'_, '_>, s: &str) -> f32 {
        text::width(style, s) / self.scale
    }

    pub fn icon(&mut self, i: Icon, x: f32, y: f32, size: f32, c: Color) {
        let (x, y) = (self.dx(x), self.dy(y));
        icon::draw(self.canvas, i, x, y, size * self.scale, c);
    }

    /// The logo mark, `size` logical pixels square.
    pub fn logo(&mut self, x: f32, y: f32, size: f32, c: Color) {
        let (x, y) = (self.dx(x), self.dy(y));
        crate::logo::draw(self.canvas, x, y, size * self.scale, c);
    }

    /// Clip drawing to `a`; returns the previous clip, for [`Painter::unclip`].
    pub fn clip(&mut self, a: Area) -> Rect {
        let d = self.device(&a).intersect(&self.canvas.clip());
        self.canvas.set_clip(d)
    }

    pub fn unclip(&mut self, previous: Rect) {
        self.canvas.set_clip(previous);
    }
}
