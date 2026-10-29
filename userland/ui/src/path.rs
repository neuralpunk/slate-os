// SPDX-License-Identifier: MIT OR Apache-2.0

//! Vector paths: lines and quadratic and cubic Béziers, flattened to line
//! segments and filled with the non-zero rule.

use alloc::vec::Vec;

use crate::canvas::Canvas;
use crate::color::Color;
use crate::math::{abs, ceil, max, min, sqrt};
use crate::raster::{Line, Mask, rasterize};

/// The circle's control-point distance for a quarter arc as a cubic
/// Bézier: 4/3·(√2 − 1).
pub const KAPPA: f32 = 0.552_284_8;

/// Flattening tolerance in device pixels.
const TOLERANCE: f32 = 0.05;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Cmd {
    Move(f32, f32),
    Line(f32, f32),
    Quad(f32, f32, f32, f32),
    Cubic(f32, f32, f32, f32, f32, f32),
    Close,
}

/// Scale then translate: (x·s + dx, y·s + dy).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Transform {
    pub scale: f32,
    pub dx: f32,
    pub dy: f32,
}

impl Transform {
    pub const IDENTITY: Transform = Transform { scale: 1.0, dx: 0.0, dy: 0.0 };

    pub fn new(scale: f32, dx: f32, dy: f32) -> Transform {
        Transform { scale, dx, dy }
    }

    fn apply(&self, x: f32, y: f32) -> (f32, f32) {
        (x * self.scale + self.dx, y * self.scale + self.dy)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Path {
    cmds: Vec<Cmd>,
}

impl Path {
    pub fn new() -> Path {
        Path::default()
    }

    pub fn move_to(&mut self, x: f32, y: f32) -> &mut Path {
        self.cmds.push(Cmd::Move(x, y));
        self
    }

    pub fn line_to(&mut self, x: f32, y: f32) -> &mut Path {
        self.cmds.push(Cmd::Line(x, y));
        self
    }

    pub fn quad_to(&mut self, cx: f32, cy: f32, x: f32, y: f32) -> &mut Path {
        self.cmds.push(Cmd::Quad(cx, cy, x, y));
        self
    }

    pub fn cubic_to(&mut self, c1x: f32, c1y: f32, c2x: f32, c2y: f32, x: f32, y: f32) -> &mut Path {
        self.cmds.push(Cmd::Cubic(c1x, c1y, c2x, c2y, x, y));
        self
    }

    pub fn close(&mut self) -> &mut Path {
        self.cmds.push(Cmd::Close);
        self
    }

    /// Append another path's subpaths.
    pub fn extend(&mut self, other: &Path) -> &mut Path {
        self.cmds.extend_from_slice(&other.cmds);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.cmds.is_empty()
    }

    /// A rectangle (clockwise on screen: positive orientation).
    pub fn rect(x: f32, y: f32, w: f32, h: f32) -> Path {
        let mut p = Path::new();
        p.move_to(x, y).line_to(x + w, y).line_to(x + w, y + h).line_to(x, y + h).close();
        p
    }

    /// A rectangle with corners of radius `r` (clamped to half the
    /// shorter side).
    pub fn rounded_rect(x: f32, y: f32, w: f32, h: f32, r: f32) -> Path {
        let r = min(r, min(w, h) * 0.5);
        if r <= 0.0 {
            return Path::rect(x, y, w, h);
        }
        let k = r * KAPPA;
        let (x1, y1) = (x + w, y + h);
        let mut p = Path::new();
        p.move_to(x + r, y)
            .line_to(x1 - r, y)
            .cubic_to(x1 - r + k, y, x1, y + r - k, x1, y + r)
            .line_to(x1, y1 - r)
            .cubic_to(x1, y1 - r + k, x1 - r + k, y1, x1 - r, y1)
            .line_to(x + r, y1)
            .cubic_to(x + r - k, y1, x, y1 - r + k, x, y1 - r)
            .line_to(x, y + r)
            .cubic_to(x, y + r - k, x + r - k, y, x + r, y)
            .close();
        p
    }

    /// A rounded rectangle traced the other way round (negative
    /// orientation): inside a positive shape it cuts a hole.
    pub fn rounded_rect_reversed(x: f32, y: f32, w: f32, h: f32, r: f32) -> Path {
        let r = max(min(r, min(w, h) * 0.5), 0.0);
        let k = r * KAPPA;
        let (x1, y1) = (x + w, y + h);
        let mut p = Path::new();
        p.move_to(x + r, y)
            .cubic_to(x + r - k, y, x, y + r - k, x, y + r)
            .line_to(x, y1 - r)
            .cubic_to(x, y1 - r + k, x + r - k, y1, x + r, y1)
            .line_to(x1 - r, y1)
            .cubic_to(x1 - r + k, y1, x1, y1 - r + k, x1, y1 - r)
            .line_to(x1, y + r)
            .cubic_to(x1, y + r - k, x1 - r + k, y, x1 - r, y)
            .close();
        p
    }

    /// A border `width` wide just inside a rounded rectangle (CSS's
    /// `border` with `border-radius`).
    pub fn rounded_ring(x: f32, y: f32, w: f32, h: f32, r: f32, width: f32) -> Path {
        let mut p = Path::rounded_rect(x, y, w, h, r);
        p.extend(&Path::rounded_rect_reversed(
            x + width,
            y + width,
            w - 2.0 * width,
            h - 2.0 * width,
            max(r - width, 0.0),
        ));
        p
    }

    /// A circle (positive orientation).
    pub fn circle(cx: f32, cy: f32, r: f32) -> Path {
        let k = r * KAPPA;
        let mut p = Path::new();
        p.move_to(cx, cy - r)
            .cubic_to(cx + k, cy - r, cx + r, cy - k, cx + r, cy)
            .cubic_to(cx + r, cy + k, cx + k, cy + r, cx, cy + r)
            .cubic_to(cx - k, cy + r, cx - r, cy + k, cx - r, cy)
            .cubic_to(cx - r, cy - k, cx - k, cy - r, cx, cy - r)
            .close();
        p
    }

    /// A closed polygon through `points`.
    pub fn polygon(points: &[(f32, f32)]) -> Path {
        let mut p = Path::new();
        for (i, &(x, y)) in points.iter().enumerate() {
            if i == 0 {
                p.move_to(x, y);
            } else {
                p.line_to(x, y);
            }
        }
        p.close();
        p
    }

    /// The path's outline as device-space line segments (every subpath
    /// closed).
    pub fn flatten(&self, t: &Transform) -> Vec<Line> {
        let mut out = Vec::new();
        let (mut sx, mut sy) = (0.0, 0.0);
        let (mut cx, mut cy) = (0.0, 0.0);
        let mut open = false;
        let close = |out: &mut Vec<Line>, cx: f32, cy: f32, sx: f32, sy: f32| {
            if cx != sx || cy != sy {
                out.push(Line { x0: cx, y0: cy, x1: sx, y1: sy });
            }
        };
        for cmd in &self.cmds {
            match *cmd {
                Cmd::Move(x, y) => {
                    if open {
                        close(&mut out, cx, cy, sx, sy);
                    }
                    (sx, sy) = t.apply(x, y);
                    (cx, cy) = (sx, sy);
                    open = true;
                }
                Cmd::Line(x, y) => {
                    let (x, y) = t.apply(x, y);
                    out.push(Line { x0: cx, y0: cy, x1: x, y1: y });
                    (cx, cy) = (x, y);
                }
                Cmd::Quad(qx, qy, x, y) => {
                    let (qx, qy) = t.apply(qx, qy);
                    let (x, y) = t.apply(x, y);
                    // The deviation of a quadratic from its chord is at most
                    // |p0 − 2p1 + p2| / 4; split so each piece's is within
                    // tolerance.
                    let dd = len(cx - 2.0 * qx + x, cy - 2.0 * qy + y);
                    let n = segments(dd * 0.25);
                    let (mut px, mut py) = (cx, cy);
                    for i in 1..=n {
                        let s = i as f32 / n as f32;
                        let u = 1.0 - s;
                        let nx = u * u * cx + 2.0 * u * s * qx + s * s * x;
                        let ny = u * u * cy + 2.0 * u * s * qy + s * s * y;
                        out.push(Line { x0: px, y0: py, x1: nx, y1: ny });
                        (px, py) = (nx, ny);
                    }
                    (cx, cy) = (x, y);
                }
                Cmd::Cubic(ax, ay, bx, by, x, y) => {
                    let (ax, ay) = t.apply(ax, ay);
                    let (bx, by) = t.apply(bx, by);
                    let (x, y) = t.apply(x, y);
                    // A bound on a cubic's deviation from its chord:
                    // 3/4 · max(|p0 − 2p1 + p2|, |p1 − 2p2 + p3|).
                    let d1 = len(cx - 2.0 * ax + bx, cy - 2.0 * ay + by);
                    let d2 = len(ax - 2.0 * bx + x, ay - 2.0 * by + y);
                    let n = segments(max(d1, d2) * 0.75);
                    let (mut px, mut py) = (cx, cy);
                    for i in 1..=n {
                        let s = i as f32 / n as f32;
                        let u = 1.0 - s;
                        let (b0, b1, b2, b3) = (u * u * u, 3.0 * u * u * s, 3.0 * u * s * s, s * s * s);
                        let nx = b0 * cx + b1 * ax + b2 * bx + b3 * x;
                        let ny = b0 * cy + b1 * ay + b2 * by + b3 * y;
                        out.push(Line { x0: px, y0: py, x1: nx, y1: ny });
                        (px, py) = (nx, ny);
                    }
                    (cx, cy) = (x, y);
                }
                Cmd::Close => {
                    close(&mut out, cx, cy, sx, sy);
                    (cx, cy) = (sx, sy);
                    open = false;
                }
            }
        }
        if open {
            close(&mut out, cx, cy, sx, sy);
        }
        out
    }

    pub fn mask(&self, t: &Transform) -> Mask {
        rasterize(&self.flatten(t))
    }

    /// Fill the path with `c` on `canvas` (rasterizing only the rows in
    /// its clip).
    pub fn fill(&self, canvas: &mut Canvas, t: &Transform, c: Color) {
        let clip = canvas.clip();
        if clip.is_empty() {
            return;
        }
        let m = crate::raster::rasterize_rows(&self.flatten(t), clip.y, clip.bottom());
        canvas.fill_mask(&m, c);
    }
}

fn len(x: f32, y: f32) -> f32 {
    sqrt(x * x + y * y)
}

/// How many line segments keep a curve with chord deviation `dev` within
/// tolerance (deviation falls with the square of the count).
fn segments(dev: f32) -> usize {
    let n = ceil(sqrt(abs(dev) / TOLERANCE)) as usize;
    n.clamp(1, 100)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coverage(p: &Path) -> f32 {
        let m = p.mask(&Transform::IDENTITY);
        m.data.iter().map(|&v| v as f32 / 255.0).sum()
    }

    #[test]
    fn areas() {
        let near = |a: f32, b: f32| abs(a - b) / b < 0.01;
        assert!(near(coverage(&Path::rect(1.0, 1.0, 10.0, 5.0)), 50.0));
        let c = coverage(&Path::circle(20.0, 20.0, 10.0));
        assert!(near(c, core::f32::consts::PI * 100.0), "circle {c}");
        let r = coverage(&Path::rounded_rect(0.0, 0.0, 40.0, 20.0, 8.0));
        let want = 40.0 * 20.0 - (4.0 - core::f32::consts::PI) * 64.0;
        assert!(near(r, want), "rounded {r} want {want}");
    }

    #[test]
    fn rings() {
        let near = |a: f32, b: f32| abs(a - b) / b < 0.02;
        let ring = coverage(&Path::rounded_ring(0.0, 0.0, 40.0, 20.0, 0.0, 1.0));
        assert!(near(ring, 40.0 * 20.0 - 38.0 * 18.0), "ring {ring}");
    }

    #[test]
    fn transform_scales() {
        let m = Path::rect(0.0, 0.0, 2.0, 2.0).mask(&Transform::new(2.0, 10.0, 10.0));
        assert_eq!((m.x, m.y), (10, 10));
        let total: u32 = m.data.iter().map(|&v| v as u32).sum();
        assert_eq!(total, 16 * 255);
    }
}
