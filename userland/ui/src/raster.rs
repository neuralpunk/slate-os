// SPDX-License-Identifier: MIT OR Apache-2.0

//! Anti-aliased polygon rasterizing by signed-area accumulation.
//!
//! Every edge adds, for each pixel row it crosses, the signed area it
//! leaves to its right in the pixels it passes through, and the full row
//! height to every pixel beyond (as a difference, so one prefix sum per row
//! finishes the job). The accumulated value is the winding-weighted
//! coverage; its magnitude, clamped to 1, is the non-zero fill rule with
//! anti-aliasing. Shapes that overlap with the same orientation unite;
//! opposite orientations cut holes (as font outlines expect).

use alloc::vec;
use alloc::vec::Vec;

use crate::math::{ceil, floor, max, min};

/// Coverage (0-255) over a rectangle of the canvas.
#[derive(Clone, Debug, Default)]
pub struct Mask {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub data: Vec<u8>,
}

/// A line segment in canvas pixels.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Line {
    pub x0: f32,
    pub y0: f32,
    pub x1: f32,
    pub y1: f32,
}

/// Rasterize closed polygons given as their edges.
pub fn rasterize(lines: &[Line]) -> Mask {
    rasterize_rows(lines, i32::MIN, i32::MAX)
}

/// [`rasterize`], only the canvas rows from `from` to `to` (exclusive): a
/// shape drawn into a clip that takes part of it. Each row's coverage
/// depends only on the edges crossing it.
pub fn rasterize_rows(lines: &[Line], from: i32, to: i32) -> Mask {
    if lines.is_empty() {
        return Mask::default();
    }
    let (mut x0, mut y0, mut x1, mut y1) = (f32::MAX, f32::MAX, f32::MIN, f32::MIN);
    for l in lines {
        x0 = min(x0, min(l.x0, l.x1));
        y0 = min(y0, min(l.y0, l.y1));
        x1 = max(x1, max(l.x0, l.x1));
        y1 = max(y1, max(l.y0, l.y1));
    }
    let (mx, my) = (floor(x0) as i32, (floor(y0) as i32).max(from));
    let (mw, mh) = (ceil(x1) as i32 - mx + 1, (ceil(y1) as i32).min(to) - my);
    if mw <= 0 || mh <= 0 || (mw as i64) * (mh as i64) > 64 << 20 {
        return Mask::default();
    }
    // One extra column per row takes the spill past the last pixel.
    let stride = (mw + 1) as usize;
    let mut acc = vec![0f32; stride * mh as usize];
    for l in lines {
        add_line(&mut acc, stride, l.x0 - mx as f32, l.y0 - my as f32, l.x1 - mx as f32, l.y1 - my as f32);
    }
    let mut data = vec![0u8; (mw * mh) as usize];
    for row in 0..mh as usize {
        let mut sum = 0f32;
        for col in 0..mw as usize {
            sum += acc[row * stride + col];
            let a = if sum < 0.0 { -sum } else { sum };
            data[row * mw as usize + col] = (min(a, 1.0) * 255.0 + 0.5) as u8;
        }
    }
    Mask { x: mx, y: my, w: mw, h: mh, data }
}

/// Add one edge (local coordinates) to the accumulation buffer.
fn add_line(acc: &mut [f32], stride: usize, x0: f32, y0: f32, x1: f32, y1: f32) {
    if y0 == y1 {
        return;
    }
    let (dir, x0, y0, x1, y1) = if y0 < y1 { (1.0, x0, y0, x1, y1) } else { (-1.0, x1, y1, x0, y0) };
    let rows = acc.len() / stride;
    let dxdy = (x1 - x0) / (y1 - y0);
    let mut row = max(floor(y0), 0.0) as usize;
    while row < rows && (row as f32) < y1 {
        let top = max(y0, row as f32);
        let bottom = min(y1, row as f32 + 1.0);
        if bottom > top {
            let xa = x0 + (top - y0) * dxdy;
            let xb = x0 + (bottom - y0) * dxdy;
            add_row_piece(&mut acc[row * stride..(row + 1) * stride], dir * (bottom - top), xa, xb);
        }
        row += 1;
    }
}

/// Within one row: the piece from x = `xa` to `xb` covering a height of
/// `dy` (signed). Split it where it crosses pixel columns.
fn add_row_piece(row: &mut [f32], dy: f32, xa: f32, xb: f32) {
    let width = row.len() - 1;
    let (lo, hi) = if xa < xb { (xa, xb) } else { (xb, xa) };
    if hi - lo < 1e-6 || floor(lo) == floor(hi) || (ceil(lo) == hi && floor(lo) + 1.0 == hi) {
        cell(row, width, dy, (lo + hi) * 0.5);
        return;
    }
    // Pieces between consecutive column boundaries, each with its share of
    // the height (the piece is a straight line, so in proportion to x).
    let total = hi - lo;
    let mut x = lo;
    while x < hi {
        let next = min(floor(x) + 1.0, hi);
        cell(row, width, dy * (next - x) / total, (x + next) * 0.5);
        x = next;
    }
}

/// A piece inside one pixel column with mid-point `xm`: the pixel gets the
/// area right of it, every later pixel the full `dy`.
fn cell(row: &mut [f32], width: usize, dy: f32, xm: f32) {
    if xm < 0.0 {
        row[0] += dy;
        return;
    }
    let col = floor(xm) as usize;
    if col >= width {
        return;
    }
    let frac = xm - col as f32;
    row[col] += dy * (1.0 - frac);
    row[col + 1] += dy * frac;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn some_rows_match_the_whole() {
        let mut lines = std::vec::Vec::new();
        // A slanted quadrilateral and a square hole.
        for (a, b) in [
            ((3.3, 2.7), (40.2, 9.1)),
            ((40.2, 9.1), (35.6, 44.4)),
            ((35.6, 44.4), (1.2, 30.8)),
            ((1.2, 30.8), (3.3, 2.7)),
        ] {
            lines.push(Line { x0: a.0, y0: a.1, x1: b.0, y1: b.1 });
        }
        lines.extend(square(14.0, 14.0, 24.0, 24.0).iter().map(|l| Line { x0: l.x1, y0: l.y1, x1: l.x0, y1: l.y0 }));
        let whole = rasterize(&lines);
        let part = rasterize_rows(&lines, 10, 20);
        assert_eq!((part.y, part.h, part.x, part.w), (10, 10, whole.x, whole.w));
        for row in 0..10 {
            let w = whole.w as usize;
            let a = &part.data[row * w..(row + 1) * w];
            let b = &whole.data[(row + 10 - whole.y as usize) * w..(row + 11 - whole.y as usize) * w];
            for (p, q) in a.iter().zip(b) {
                assert!(p.abs_diff(*q) <= 1, "row {}: {p} {q}", row + 10);
            }
        }
        assert!(rasterize_rows(&lines, 50, 60).data.is_empty());
    }

    fn square(x0: f32, y0: f32, x1: f32, y1: f32) -> [Line; 4] {
        [
            Line { x0, y0, x1, y1: y0 },
            Line { x0: x1, y0, x1, y1 },
            Line { x0: x1, y0: y1, x1: x0, y1 },
            Line { x0, y0: y1, x1: x0, y1: y0 },
        ]
    }

    fn at(m: &Mask, x: i32, y: i32) -> u8 {
        m.data[((y - m.y) * m.w + (x - m.x)) as usize]
    }

    #[test]
    fn whole_and_half_pixels() {
        let m = rasterize(&square(1.0, 1.0, 4.0, 3.0));
        assert_eq!(at(&m, 1, 1), 255);
        assert_eq!(at(&m, 3, 2), 255);
        let m = rasterize(&square(1.5, 1.0, 3.5, 2.0));
        assert_eq!((at(&m, 1, 1), at(&m, 2, 1), at(&m, 3, 1)), (128, 255, 128));
    }

    #[test]
    fn triangle_area() {
        // A right triangle over two pixels: half of each.
        let m = rasterize(&[
            Line { x0: 0.0, y0: 0.0, x1: 2.0, y1: 0.0 },
            Line { x0: 2.0, y0: 0.0, x1: 0.0, y1: 1.0 },
            Line { x0: 0.0, y0: 1.0, x1: 0.0, y1: 0.0 },
        ]);
        let total: u32 = m.data.iter().map(|&v| v as u32).sum();
        assert!((250..=260).contains(&total), "total {total}");
    }

    #[test]
    fn holes_and_unions() {
        // An inner square of the opposite orientation is a hole; of the same
        // orientation it stays filled.
        let mut lines = square(0.0, 0.0, 6.0, 6.0).to_vec();
        let mut inner = square(2.0, 2.0, 4.0, 4.0).to_vec();
        for l in &mut inner {
            *l = Line { x0: l.x1, y0: l.y1, x1: l.x0, y1: l.y0 };
        }
        lines.extend(inner);
        let m = rasterize(&lines);
        assert_eq!((at(&m, 1, 1), at(&m, 3, 3)), (255, 0));
        let mut lines = square(0.0, 0.0, 6.0, 6.0).to_vec();
        lines.extend(square(2.0, 2.0, 4.0, 4.0));
        assert_eq!(at(&rasterize(&lines), 3, 3), 255);
    }
}
