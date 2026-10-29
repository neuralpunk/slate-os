// SPDX-License-Identifier: MIT OR Apache-2.0

//! Drop shadows as CSS draws `box-shadow`: the box's shape, offset, grown
//! by the spread, blurred by a Gaussian with σ = blur / 2 (approximated by
//! three box blurs), in the shadow colour.
//!
//! Blurring is most of a shadow's cost, and the same shadows come back
//! every frame (a window moved, a damaged rectangle drawn again), so a
//! [`ShadowCache`] keeps the last few blurred masks; then only the part
//! of the mask inside the canvas's clip is drawn.
//!
//! A mask is built small: along a box's straight edges, away from its
//! corners by more than the blur reaches, every column (and every row)
//! of the blurred mask is the same. So the box is shrunk by whole pixels
//! to just its corners and their reach, blurred, and the middle column
//! and row are repeated back to its size; the cost is the corners', not
//! the box's area (ADR 0124's addendum: the launcher's contact shadow).

use alloc::vec;
use alloc::vec::Vec;

use crate::canvas::{Canvas, Rect};
use crate::color::Color;
use crate::math::{ceil, floor, max, round, sqrt};
use crate::path::{Path, Transform};
use crate::raster::Mask;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BoxShadow {
    pub dx: f32,
    pub dy: f32,
    pub blur: f32,
    pub spread: f32,
    pub color: Color,
}

/// How many blurred shadows a cache keeps (each is the size of its box
/// and blur, up to a few megabytes for a maximised window): a desktop's
/// four windows (the focused one's two) and the launcher's two, with
/// room to spare, so a frame drawn whole doesn't push out its own.
const CACHED: usize = 8;

/// A shadow's shape: its box's size, corner radius, blur and spread, and
/// its position's fractions of a pixel (as bits).
type Key = [u32; 7];

/// Blurred shadow masks, positioned relative to their box's whole-pixel
/// corner, most recently used last.
#[derive(Debug, Default)]
pub struct ShadowCache {
    entries: Vec<(Key, Mask)>,
}

/// Draw `s` for the rounded box at (x, y), w × h, corner radius `r`
/// (device pixels).
pub fn draw(canvas: &mut Canvas, x: f32, y: f32, w: f32, h: f32, r: f32, s: &BoxShadow) {
    draw_cached(canvas, None, x, y, w, h, r, s, Rect::new(0, 0, 0, 0));
}

/// [`draw`], keeping the blurred mask in `cache` for the next time, and
/// leaving out the pixels in `hole` (under an opaque surface drawn next,
/// which would cover them).
#[allow(clippy::too_many_arguments)]
pub fn draw_cached(
    canvas: &mut Canvas,
    cache: Option<&mut ShadowCache>,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    r: f32,
    s: &BoxShadow,
    hole: Rect,
) {
    let (bx, by) = (x + s.dx - s.spread, y + s.dy - s.spread);
    let (bw, bh) = (w + 2.0 * s.spread, h + 2.0 * s.spread);
    if bw <= 0.0 || bh <= 0.0 {
        return;
    }
    let sigma = s.blur * 0.5;
    let pad = ceil(sigma * 3.0) as i32 + 1;
    let (ix, iy) = (floor(bx), floor(by));
    // Nothing to draw if the blur's reach misses the clip.
    let reach = Rect::new(
        ix as i32 - pad - 1,
        iy as i32 - pad - 1,
        ceil(bw) as i32 + 2 * pad + 3,
        ceil(bh) as i32 + 2 * pad + 3,
    );
    if reach.intersect(&canvas.clip()).is_empty() {
        return;
    }
    let (fx, fy) = (bx - ix, by - iy);
    let radius = max(r + s.spread, 0.0);
    let make = || {
        let sizes = if sigma > 0.0 { box_sizes(sigma) } else { [1; 3] };
        // Columns (rows) this far from the box's ends are all alike.
        let reach: i32 = sizes.iter().map(|s| (s - 1) / 2).sum();
        let corner = ceil(radius) as i32 + reach + 2;
        let cut = |len: f32| (floor(len) as i32 - 2 * corner - 1).max(0);
        let (cut_x, cut_y) = (cut(bw), cut(bh));
        let shape = Path::rounded_rect(fx, fy, bw - cut_x as f32, bh - cut_y as f32, radius).mask(&Transform::IDENTITY);
        let mut m = padded(&shape, pad);
        for size in sizes {
            blur(&mut m, (size - 1) / 2);
        }
        stretch(m, cut_x, cut_y)
    };
    let (ox, oy) = (ix as i32, iy as i32);
    let Some(cache) = cache else {
        let m = make();
        canvas.fill_coverage_except(m.x + ox, m.y + oy, m.w, m.h, &m.data, s.color, hole);
        return;
    };
    let key = [bw, bh, radius, s.blur, s.spread, fx, fy].map(f32::to_bits);
    let at = match cache.entries.iter().position(|(k, _)| *k == key) {
        Some(i) => {
            let e = cache.entries.remove(i);
            cache.entries.push(e);
            cache.entries.len() - 1
        }
        None => {
            if cache.entries.len() >= CACHED {
                cache.entries.remove(0);
            }
            cache.entries.push((key, make()));
            cache.entries.len() - 1
        }
    };
    let m = &cache.entries[at].1;
    canvas.fill_coverage_except(m.x + ox, m.y + oy, m.w, m.h, &m.data, s.color, hole);
}

/// `m` with `cut_x` copies of its middle column and `cut_y` of its
/// middle row put in, at the middle.
fn stretch(m: Mask, cut_x: i32, cut_y: i32) -> Mask {
    if cut_x == 0 && cut_y == 0 {
        return m;
    }
    let (w, h) = (m.w + cut_x, m.h + cut_y);
    let (mx, my) = ((m.w / 2) as usize, m.h / 2);
    let mut data = Vec::with_capacity((w * h) as usize);
    let mut row = Vec::with_capacity(w as usize);
    for y in 0..m.h {
        let src = &m.data[(y * m.w) as usize..((y + 1) * m.w) as usize];
        row.clear();
        row.extend_from_slice(&src[..mx]);
        row.resize(mx + cut_x as usize, src[mx]);
        row.extend_from_slice(&src[mx..]);
        let times = if y == my { cut_y + 1 } else { 1 };
        for _ in 0..times {
            data.extend_from_slice(&row);
        }
    }
    Mask { x: m.x, y: m.y, w, h, data }
}

/// `m` with `pad` empty pixels around it.
fn padded(m: &Mask, pad: i32) -> Mask {
    let (w, h) = (m.w + 2 * pad, m.h + 2 * pad);
    let mut data = vec![0u8; (w * h) as usize];
    for y in 0..m.h {
        let src = &m.data[(y * m.w) as usize..((y + 1) * m.w) as usize];
        let at = ((y + pad) * w + pad) as usize;
        data[at..at + m.w as usize].copy_from_slice(src);
    }
    Mask { x: m.x - pad, y: m.y - pad, w, h, data }
}

/// Widths of three box blurs whose combination approximates a Gaussian
/// of deviation σ (each box adds (w² − 1) / 12 to the variance).
fn box_sizes(sigma: f32) -> [i32; 3] {
    let n = 3.0;
    let ideal = sqrt(12.0 * sigma * sigma / n + 1.0);
    let mut wl = floor(ideal) as i32;
    if wl % 2 == 0 {
        wl -= 1;
    }
    let wl = wl.max(1);
    let wu = wl + 2;
    let wlf = wl as f32;
    let m = round((12.0 * sigma * sigma - n * wlf * wlf - 4.0 * n * wlf - 3.0 * n) / (-4.0 * wlf - 4.0)) as i32;
    let mut out = [0; 3];
    for (i, o) in out.iter_mut().enumerate() {
        *o = if (i as i32) < m { wl } else { wu };
    }
    out
}

/// `(n + d / 2) / d`, rounded to nearest, by a multiplication: exact for
/// the box blur's sums (n below 2^17, d odd up to 2^9; see the test).
#[derive(Clone, Copy)]
struct Divider {
    d: u32,
    m: u64,
}

impl Divider {
    fn new(d: u32) -> Divider {
        Divider { d, m: (1u64 << 40) / u64::from(d) + 1 }
    }

    fn div(self, n: u32) -> u8 {
        ((u64::from(n + self.d / 2) * self.m) >> 40) as u8
    }
}

/// One box blur of radius `r`, horizontally then vertically (zero beyond
/// the edges). The vertical pass keeps a running sum per column and goes
/// down the rows, so it reads memory in order.
fn blur(m: &mut Mask, r: i32) {
    if r <= 0 {
        return;
    }
    let (w, h) = (m.w as usize, m.h as usize);
    let mut tmp: Vec<u8> = vec![0; w * h];
    let div = Divider::new((2 * r + 1) as u32);
    for y in 0..h {
        line(&m.data[y * w..(y + 1) * w], &mut tmp[y * w..(y + 1) * w], r, div);
    }
    let r = r as usize;
    let mut sums = vec![0u32; w];
    for row in tmp.chunks_exact(w).take(r + 1) {
        for (s, &v) in sums.iter_mut().zip(row) {
            *s += u32::from(v);
        }
    }
    for y in 0..h {
        for (out, &s) in m.data[y * w..(y + 1) * w].iter_mut().zip(&sums) {
            *out = div.div(s);
        }
        if y + r + 1 < h {
            for (s, &v) in sums.iter_mut().zip(&tmp[(y + r + 1) * w..(y + r + 2) * w]) {
                *s += u32::from(v);
            }
        }
        if y >= r {
            for (s, &v) in sums.iter_mut().zip(&tmp[(y - r) * w..(y - r + 1) * w]) {
                *s -= u32::from(v);
            }
        }
    }
}

/// A running-sum box filter over one line (zero beyond its ends).
fn line(src: &[u8], dst: &mut [u8], r: i32, div: Divider) {
    let n = src.len() as i32;
    let get = |i: i32| if i < 0 || i >= n { 0 } else { src[i as usize] as u32 };
    let mut sum: u32 = (-r..=r).map(get).sum();
    for i in 0..n {
        dst[i as usize] = div.div(sum);
        sum += get(i + r + 1);
        sum -= get(i - r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_the_variance() {
        for sigma in [2.0f32, 10.0, 45.0] {
            let v: f32 = box_sizes(sigma).iter().map(|&w| ((w * w - 1) as f32) / 12.0).sum();
            assert!((v - sigma * sigma).abs() / (sigma * sigma) < 0.2, "sigma {sigma}: {v}");
        }
    }

    #[test]
    fn division_by_multiplication_is_exact() {
        for d in (1..=511u32).step_by(2) {
            let div = Divider::new(d);
            for n in 0..=(d * 255) {
                assert_eq!(u32::from(div.div(n)), (n + d / 2) / d, "{n} / {d}");
            }
        }
    }

    #[test]
    fn cached_shadows_match() {
        let s = BoxShadow { dx: 0.0, dy: 8.0, blur: 24.0, spread: -8.0, color: Color::rgb(0).with_alpha(128) };
        let mut plain = Canvas::new(300, 300, Color::rgb(0xFFFFFF));
        draw(&mut plain, 60.25, 40.0, 120.0, 90.0, 10.0, &s);
        let mut cache = ShadowCache::default();
        let mut cached = Canvas::new(300, 300, Color::rgb(0xFFFFFF));
        // The second time comes from the cache, moved by whole pixels.
        let none = Rect::new(0, 0, 0, 0);
        draw_cached(&mut cached, Some(&mut cache), 20.25, 10.0, 120.0, 90.0, 10.0, &s, none);
        cached = Canvas::new(300, 300, Color::rgb(0xFFFFFF));
        draw_cached(&mut cached, Some(&mut cache), 60.25, 40.0, 120.0, 90.0, 10.0, &s, none);
        assert_eq!(cache.entries.len(), 1);
        assert_eq!(plain.pixels, cached.pixels);
        // Drawn within a clip: the same pixels there, none outside.
        let mut clipped = Canvas::new(300, 300, Color::rgb(0xFFFFFF));
        clipped.set_clip(Rect::new(100, 120, 40, 30));
        draw_cached(&mut clipped, Some(&mut cache), 60.25, 40.0, 120.0, 90.0, 10.0, &s, none);
        for y in 0..300 {
            for x in 0..300 {
                let inside = (100..140).contains(&x) && (120..150).contains(&y);
                let want = if inside { plain.pixel(x, y) } else { 0xFFFF_FFFF };
                assert_eq!(clipped.pixel(x, y), want, "({x}, {y})");
            }
        }
        // Old shapes leave the cache.
        for i in 0..CACHED as i32 + 2 {
            draw_cached(&mut cached, Some(&mut cache), 10.0, 10.0, 50.0 + i as f32, 50.0, 4.0, &s, none);
        }
        assert_eq!(cache.entries.len(), CACHED);
        // A hole leaves its pixels alone and draws the rest the same.
        let mut holed = Canvas::new(300, 300, Color::rgb(0xFFFFFF));
        let hole = Rect::new(80, 60, 50, 40);
        draw_cached(&mut holed, Some(&mut cache), 60.25, 40.0, 120.0, 90.0, 10.0, &s, hole);
        for y in 0..300 {
            for x in 0..300 {
                let inside = (80..130).contains(&x) && (60..100).contains(&y);
                let want = if inside { 0xFFFF_FFFF } else { plain.pixel(x, y) };
                assert_eq!(holed.pixel(x, y), want, "({x}, {y})");
            }
        }
    }

    /// The mask built shrunk and stretched is the one blurred whole.
    #[test]
    fn stretched_masks_match() {
        let whole = |fx: f32, fy: f32, w: f32, h: f32, r: f32, sigma: f32, pad: i32| {
            let shape = Path::rounded_rect(fx, fy, w, h, r).mask(&Transform::IDENTITY);
            let mut m = padded(&shape, pad);
            if sigma > 0.0 {
                for size in box_sizes(sigma) {
                    blur(&mut m, (size - 1) / 2);
                }
            }
            m
        };
        for (w, h, r, blur_px) in
            [(640.0, 512.5, 16.0, 8.0), (640.0, 512.5, 16.0, 100.0), (300.25, 90.0, 12.0, 6.0), (40.0, 30.0, 4.0, 24.0)]
        {
            let s = BoxShadow { dx: 0.0, dy: 0.0, blur: blur_px, spread: 0.0, color: Color::rgb(0).with_alpha(255) };
            let (x, y) = (20.25, 10.5);
            let mut fast = Canvas::new(1200, 1000, Color::rgb(0xFFFFFF));
            draw(&mut fast, x, y, w, h, r, &s);
            let sigma = blur_px * 0.5;
            let pad = ceil(sigma * 3.0) as i32 + 1;
            let m = whole(x - floor(x), y - floor(y), w, h, r, sigma, pad);
            let mut slow = Canvas::new(1200, 1000, Color::rgb(0xFFFFFF));
            let none = Rect::new(0, 0, 0, 0);
            slow.fill_coverage_except(m.x + floor(x) as i32, m.y + floor(y) as i32, m.w, m.h, &m.data, s.color, none);
            let worst = fast.pixels.iter().zip(&slow.pixels).map(|(a, b)| (a & 0xFF).abs_diff(b & 0xFF)).max();
            assert!(worst.unwrap_or(0) <= 1, "{w} x {h}, blur {blur_px}: off by {worst:?}");
        }
    }

    #[test]
    fn shadow_falls_off() {
        let mut c = Canvas::new(200, 200, Color::rgb(0xFFFFFF));
        let s = BoxShadow { dx: 0.0, dy: 0.0, blur: 20.0, spread: 0.0, color: Color::rgb(0).with_alpha(255) };
        draw(&mut c, 50.0, 50.0, 100.0, 100.0, 0.0, &s);
        let level = |x| 255 - (c.pixel(x, 100) & 0xFF);
        assert!(level(100) > 240, "inside {}", level(100));
        assert!((100..160).contains(&level(50)), "edge {}", level(50));
        assert!(level(25) < 20, "outside {}", level(25));
        assert_eq!(level(5), 0);
    }
}
