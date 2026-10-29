// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SlateOS logo mark (docs/design/INSTALLER_STYLE.md §8): an isometric slab
//! over fading strata, drawn from the guide's SVG (a 32-unit view box).

use crate::canvas::Canvas;
use crate::color::Color;
use crate::path::{Path, Transform};
use crate::stroke;

/// Draw the mark `size` device pixels square with its top-left at (x, y).
pub fn draw(canvas: &mut Canvas, x: f32, y: f32, size: f32, ink: Color) {
    let t = Transform::new(size / 32.0, x, y);
    // Small marks drop the bottom stratum and use heavier strokes; large
    // ones lighter (§8).
    let small = size <= 20.0;
    let width = if small {
        2.4
    } else if size >= 120.0 {
        1.4
    } else {
        1.6
    };
    Path::polygon(&[(16.0, 3.0), (29.0, 9.5), (16.0, 16.0), (3.0, 9.5)]).fill(canvas, &t, ink);
    Path::polygon(&[(3.0, 9.5), (3.0, 12.5), (16.0, 19.0), (16.0, 16.0)]).fill(canvas, &t, ink.faded(0.6));
    Path::polygon(&[(29.0, 9.5), (29.0, 12.5), (16.0, 19.0), (16.0, 16.0)]).fill(canvas, &t, ink.faded(0.35));
    stroke::polyline(&[(3.0, 17.5), (16.0, 24.0), (29.0, 17.5)], width).fill(canvas, &t, ink.faded(0.45));
    if !small {
        stroke::polyline(&[(3.0, 23.5), (16.0, 30.0), (29.0, 23.5)], width).fill(canvas, &t, ink.faded(0.2));
    }
}

/// The mark as a monument (Atelier's lock screen, ADR 0124): the same
/// shapes `size` device pixels square, as outlines `stroke` units wide
/// (of the 32-unit view box): the slab's top face filled `faces[0]` and
/// outlined `lines[0]`, its sides `faces[1]` and `faces[2]` outlined
/// `lines[1]`, and both strata as lines, the upper `lines[0]`.
pub fn monument(canvas: &mut Canvas, x: f32, y: f32, size: f32, faces: [Color; 3], lines: [Color; 2], stroke: f32) {
    let t = Transform::new(size / 32.0, x, y);
    let outline = |canvas: &mut Canvas, pts: &[(f32, f32)], fill: Color, line: Color| {
        Path::polygon(pts).fill(canvas, &t, fill);
        // Closed: back to the first point and on to the second, so the
        // last corner joins.
        let mut ring = pts.to_vec();
        ring.extend_from_slice(&pts[..2]);
        stroke::polyline(&ring, stroke).fill(canvas, &t, line);
    };
    outline(canvas, &[(3.0, 9.5), (3.0, 12.5), (16.0, 19.0), (16.0, 16.0)], faces[1], lines[1]);
    outline(canvas, &[(29.0, 9.5), (29.0, 12.5), (16.0, 19.0), (16.0, 16.0)], faces[2], lines[1]);
    outline(canvas, &[(16.0, 3.0), (29.0, 9.5), (16.0, 16.0), (3.0, 9.5)], faces[0], lines[0]);
    stroke::polyline(&[(3.0, 17.5), (16.0, 24.0), (29.0, 17.5)], stroke).fill(canvas, &t, lines[0]);
    stroke::polyline(&[(3.0, 23.5), (16.0, 30.0), (29.0, 23.5)], stroke).fill(canvas, &t, lines[1]);
}
