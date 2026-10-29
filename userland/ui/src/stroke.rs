// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strokes of open polylines: butt caps and round joins (SVG's defaults
//! with `stroke-linejoin="round"`), built as a union of segment
//! rectangles and join discs, all of one orientation so the non-zero fill
//! unites them.

use crate::math::sqrt;
use crate::path::Path;

/// The outline of a stroke `width` wide along `points`.
pub fn polyline(points: &[(f32, f32)], width: f32) -> Path {
    let mut p = Path::new();
    let h = width * 0.5;
    for w in points.windows(2) {
        let ((x0, y0), (x1, y1)) = (w[0], w[1]);
        let (dx, dy) = (x1 - x0, y1 - y0);
        let l = sqrt(dx * dx + dy * dy);
        if l == 0.0 {
            continue;
        }
        let (nx, ny) = (-dy / l * h, dx / l * h);
        let quad = [(x0 + nx, y0 + ny), (x1 + nx, y1 + ny), (x1 - nx, y1 - ny), (x0 - nx, y0 - ny)];
        p.extend(&oriented(&quad));
    }
    for &(x, y) in points.iter().skip(1).take(points.len().saturating_sub(2)) {
        p.extend(&Path::circle(x, y, h));
    }
    p
}

/// A polygon path with positive (clockwise on screen) orientation, the
/// orientation of [`Path::circle`] and [`Path::rect`].
fn oriented(pts: &[(f32, f32)]) -> Path {
    let mut area = 0.0;
    for i in 0..pts.len() {
        let (a, b) = (pts[i], pts[(i + 1) % pts.len()]);
        area += a.0 * b.1 - b.0 * a.1;
    }
    if area >= 0.0 {
        Path::polygon(pts)
    } else {
        let rev: alloc::vec::Vec<(f32, f32)> = pts.iter().rev().copied().collect();
        Path::polygon(&rev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::Transform;

    #[test]
    fn joined_stroke_has_no_gaps_or_holes() {
        // A V shape: the join's disc overlaps both segments without
        // cancelling them.
        let p = polyline(&[(2.0, 2.0), (10.0, 10.0), (18.0, 2.0)], 2.0);
        let m = p.mask(&Transform::IDENTITY);
        let at = |x: i32, y: i32| m.data[((y - m.y) * m.w + (x - m.x)) as usize];
        assert!(at(10, 10) >= 250, "join {}", at(10, 10));
        assert!(at(6, 6) >= 200, "segment {}", at(6, 6));
        assert_eq!(at(10, 4), 0);
    }
}
