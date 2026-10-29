// SPDX-License-Identifier: MIT OR Apache-2.0

//! Text: laying out a line (the font's ligatures and contextual
//! alternates, advances, kerning, letter-spacing), placing it in a line
//! box as CSS does, wrapping, caret positions, and drawing through a glyph
//! cache.
//!
//! Shaping is the font's GSUB `liga` and `calt` features (ADR 0101), for
//! Latin text: no right-to-left or complex scripts (docs/GAPS.md).
//!
//! Hinting is light and vertical only (ADR 0101): at UI sizes a glyph's
//! heights are scaled so the font's x-height lands on a whole pixel, which
//! makes the tops of lowercase letters crisp. The font's own TrueType
//! instructions are not run; widths, and so layout, are unchanged.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::canvas::Canvas;
use crate::color::Color;
use crate::font::Font;
use crate::math::{floor, round};
use crate::path::Transform;
use crate::raster::Mask;

/// A font with a number for the glyph cache.
#[derive(Clone, Debug)]
pub struct Face<'a> {
    pub font: Font<'a>,
    pub id: u32,
}

impl<'a> Face<'a> {
    pub fn new(bytes: &'a [u8], id: u32) -> Option<Face<'a>> {
        Some(Face { font: Font::new(bytes)?, id })
    }

    fn scale(&self, size: f32) -> f32 {
        size / self.font.units_per_em as f32
    }

    /// Ascent and descent (positive, below the baseline) at `size`.
    pub fn extent(&self, size: f32) -> (f32, f32) {
        let s = self.scale(size);
        (self.font.ascender as f32 * s, -(self.font.descender as f32) * s)
    }

    /// Where the baseline sits in a line box `line_height` tall: CSS puts
    /// half the leading above the ascent and half below the descent.
    pub fn baseline(&self, size: f32, line_height: f32) -> f32 {
        let (asc, desc) = self.extent(size);
        (line_height - (asc + desc)) * 0.5 + asc
    }
}

/// The lean of [`Style::oblique`] text: about 11 degrees.
pub const OBLIQUE: f32 = 0.2;
/// The largest size (device pixels) hinted; larger text is sharp enough.
pub const HINT_MAX: f32 = 24.0;

/// The vertical stretch that puts the x-height of `face` at `size` on a
/// whole pixel (1 when not hinted).
pub fn hint_scale(face: &Face<'_>, size: f32) -> f32 {
    let xh = f32::from(face.font.x_height) * face.scale(size);
    if size > HINT_MAX || xh < 1.0 {
        return 1.0;
    }
    round(xh) / xh
}

/// How a run of text looks: face, size in device pixels, letter-spacing
/// in ems (the style guide's tracking), colour, and whether it leans.
#[derive(Clone, Copy, Debug)]
pub struct Style<'f, 'a> {
    pub face: &'f Face<'a>,
    pub size: f32,
    pub tracking: f32,
    pub color: Color,
    /// Slanted (an oblique made from the upright face, for italics when
    /// there is no italic face).
    pub oblique: bool,
    /// The font's ligatures and contextual alternates (off in text being
    /// edited, so each character keeps a glyph of its own).
    pub ligatures: bool,
}

impl<'f, 'a> Style<'f, 'a> {
    pub fn new(face: &'f Face<'a>, size: f32, color: Color) -> Style<'f, 'a> {
        Style { face, size, tracking: 0.0, color, oblique: false, ligatures: true }
    }

    pub fn tracking(mut self, em: f32) -> Style<'f, 'a> {
        self.tracking = em;
        self
    }

    pub fn oblique(mut self, on: bool) -> Style<'f, 'a> {
        self.oblique = on;
        self
    }

    pub fn ligatures(mut self, on: bool) -> Style<'f, 'a> {
        self.ligatures = on;
        self
    }
}

/// A placed glyph: its id, pen position from the start of the line, and
/// the character it starts at.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Placed {
    pub glyph: u16,
    pub x: f32,
    pub cluster: usize,
}

/// Lay out one line. Returns the glyphs and the advance (which, as in
/// CSS, includes the letter-spacing after the last character).
pub fn layout(style: &Style<'_, '_>, text: &str) -> (Vec<Placed>, f32) {
    let f = &style.face.font;
    let s = style.face.scale(style.size);
    let spacing = style.tracking * style.size;
    let mut glyphs: Vec<u16> = text.chars().map(|c| f.glyph(c)).collect();
    let mut clusters: Vec<usize> = (0..glyphs.len()).collect();
    if style.ligatures {
        f.substitute(&mut glyphs, &mut clusters);
    }
    let mut out = Vec::with_capacity(glyphs.len());
    let mut x = 0.0;
    let mut prev: Option<u16> = None;
    for (&g, &cluster) in glyphs.iter().zip(&clusters) {
        if let Some(p) = prev {
            x += f.kerning(p, g) as f32 * s;
        }
        out.push(Placed { glyph: g, x, cluster });
        x += f.advance(g) as f32 * s + spacing;
        prev = Some(g);
    }
    (out, x)
}

/// Where the caret goes at each character boundary of `text` (one more
/// than the characters), from the line's start; a ligature's width is
/// shared by the characters it stands for.
pub fn caret_positions(style: &Style<'_, '_>, text: &str) -> Vec<f32> {
    let n = text.chars().count();
    let (glyphs, end) = layout(style, text);
    let mut xs = Vec::with_capacity(n + 1);
    for (k, g) in glyphs.iter().enumerate() {
        let (next_cluster, next_x) = glyphs.get(k + 1).map_or((n, end), |h| (h.cluster, h.x));
        let chars = next_cluster.saturating_sub(g.cluster).max(1);
        for j in 0..chars {
            xs.push(g.x + (next_x - g.x) * j as f32 / chars as f32);
        }
    }
    xs.truncate(n);
    xs.push(end);
    xs
}

/// The character boundary nearest `x` in `positions` (from
/// [`caret_positions`]).
pub fn boundary_at(positions: &[f32], x: f32) -> usize {
    let mut best = 0;
    for (i, &p) in positions.iter().enumerate() {
        if (p - x).abs() < (positions[best] - x).abs() {
            best = i;
        }
    }
    best
}

/// The width of `text` in `style`.
pub fn width(style: &Style<'_, '_>, text: &str) -> f32 {
    layout(style, text).1
}

/// Break `text` into lines no wider than `max` (greedy, at spaces; a word
/// longer than the line stays whole).
pub fn wrap(style: &Style<'_, '_>, text: &str, max: f32) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split(' ').filter(|w| !w.is_empty()) {
        let candidate = if line.is_empty() { String::from(word) } else { alloc::format!("{line} {word}") };
        if !line.is_empty() && width(style, &candidate) > max {
            lines.push(core::mem::replace(&mut line, String::from(word)));
        } else {
            line = candidate;
        }
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// What a painter keeps from one frame to the next: glyph masks already
/// rasterized, by face, glyph, size (1/64 px), horizontal sub-pixel
/// position (quarters) and slant, and the last few shadows blurred.
#[derive(Debug, Default)]
pub struct GlyphCache {
    masks: BTreeMap<(u32, u16, u32, u8, bool), Mask>,
    pub shadows: crate::shadow::ShadowCache,
}

impl GlyphCache {
    pub fn new() -> GlyphCache {
        GlyphCache::default()
    }

    fn mask(&mut self, face: &Face<'_>, glyph: u16, size: f32, quarter: u8, oblique: bool) -> &Mask {
        let key = (face.id, glyph, (size * 64.0) as u32, quarter, oblique);
        self.masks.entry(key).or_insert_with(|| {
            let s = face.scale(size);
            let slant = if oblique { OBLIQUE } else { 0.0 };
            let sy = s * hint_scale(face, size);
            face.font.outline_scaled(glyph, (s, sy), quarter as f32 * 0.25, 0.0, slant).mask(&Transform::IDENTITY)
        })
    }
}

/// Draw `text` with its baseline at `baseline` starting at `x`; returns
/// the advance.
pub fn draw(
    canvas: &mut Canvas,
    cache: &mut GlyphCache,
    style: &Style<'_, '_>,
    x: f32,
    baseline: f32,
    text: &str,
) -> f32 {
    let (glyphs, advance) = layout(style, text);
    let by = round(baseline) as i32;
    for g in glyphs {
        let px = x + g.x;
        let mut ix = floor(px) as i32;
        let mut quarter = round((px - floor(px)) * 4.0) as u8;
        if quarter == 4 {
            ix += 1;
            quarter = 0;
        }
        let m = cache.mask(style.face, g.glyph, style.size, quarter, style.oblique);
        if m.w == 0 {
            continue;
        }
        canvas.fill_coverage(m.x + ix, m.y + by, m.w, m.h, &m.data, style.color);
    }
    advance
}

#[cfg(test)]
mod tests {
    use super::*;

    fn face() -> Face<'static> {
        let path = alloc::format!("{}/../../assets/fonts/HostGrotesk-500.ttf", env!("CARGO_MANIFEST_DIR"));
        let bytes: &'static [u8] = alloc::boxed::Box::leak(std::fs::read(path).unwrap().into_boxed_slice());
        Face::new(bytes, 1).unwrap()
    }

    #[test]
    fn kerning_and_tracking_move_the_pen() {
        let f = face();
        let st = Style::new(&f, 100.0, Color::rgb(0));
        // 'A' advances 674 units, AV kerns −116.
        let (g, w) = layout(&st, "AV");
        assert!((g[1].x - (674.0 - 116.0) * 0.1).abs() < 1e-3);
        assert!((w - (674.0 - 116.0 + 710.0) * 0.1).abs() < 1e-3);
        let tracked = width(&st.tracking(-0.03), "AV");
        assert!((tracked - (w - 2.0 * 3.0)).abs() < 1e-3);
    }

    #[test]
    fn wrapping() {
        let f = face();
        let st = Style::new(&f, 15.0, Color::rgb(0));
        let lines = wrap(&st, "one two three four five six seven", 80.0);
        assert!(lines.len() > 1);
        assert!(lines.iter().all(|l| width(&st, l) <= 80.0 || !l.contains(' ')));
        assert_eq!(lines.join(" "), "one two three four five six seven");
    }

    #[test]
    fn oblique_leans_right() {
        let f = face();
        let mut cache = GlyphCache::new();
        // An "l": upright, its ink's top and bottom start at the same x;
        // oblique, the top starts further right.
        let leftmost = |c: &Canvas, y: i32| (0..c.width).find(|&x| c.pixel(x, y) != 0xFF00_0000);
        let mut up = Canvas::new(60, 60, Color::rgb(0));
        draw(&mut up, &mut cache, &Style::new(&f, 40.0, Color::rgb(0xFFFFFF)), 10.0, 50.0, "l");
        let mut ob = Canvas::new(60, 60, Color::rgb(0));
        draw(&mut ob, &mut cache, &Style::new(&f, 40.0, Color::rgb(0xFFFFFF)).oblique(true), 10.0, 50.0, "l");
        let (ut, ub) = (leftmost(&up, 22).unwrap(), leftmost(&up, 48).unwrap());
        let (ot, ob_) = (leftmost(&ob, 22).unwrap(), leftmost(&ob, 48).unwrap());
        assert!((ut - ub).abs() <= 1);
        assert!(ot - ob_ >= 4, "{ot} {ob_}");
    }

    #[test]
    fn carets_and_ligatures() {
        let f = face();
        let st = Style::new(&f, 20.0, Color::rgb(0));
        // "fit" shapes as "fi" + "t", yet has four caret positions; the
        // ligature's width is split between f and i.
        let xs = caret_positions(&st, "fit");
        assert_eq!(xs.len(), 4);
        assert!(xs.windows(2).all(|w| w[1] > w[0]));
        assert_eq!(xs[3], width(&st, "fit"));
        let plain = caret_positions(&st.ligatures(false), "fit");
        assert_eq!(plain.len(), 4);
        assert_eq!(boundary_at(&plain, plain[2] + 0.4), 2);
        assert_eq!(boundary_at(&plain, -5.0), 0);
        assert_eq!(caret_positions(&st, ""), [0.0]);
    }

    #[test]
    fn hinting_puts_the_x_height_on_a_pixel() {
        let f = face();
        for size in [11.0, 12.5, 13.0, 14.5, 15.0, 18.0] {
            let xh = f32::from(f.font.x_height) * f.scale(size) * hint_scale(&f, size);
            assert!((xh - round(xh)).abs() < 1e-3, "{size}: {xh}");
        }
        assert_eq!(hint_scale(&f, 36.0), 1.0);
    }

    #[test]
    fn baseline_in_a_line_box() {
        let f = face();
        // Ascent 1015, descent 315 at 1000 units/em: 36 px in a 41.4 px box.
        let b = f.baseline(36.0, 41.4);
        assert!((b - ((41.4 - 47.88) / 2.0 + 36.54)).abs() < 1e-3, "{b}");
    }
}
