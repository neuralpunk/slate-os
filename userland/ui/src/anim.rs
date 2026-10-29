// SPDX-License-Identifier: MIT OR Apache-2.0

//! Animations (ADR 0101): values that move from where they were to a new
//! target over a duration, with CSS's timing curves. The widgets use them
//! for colour and border changes (INSTALLER_STYLE.md: "150 ms ease on
//! colour and border changes only"); with reduced motion every change is
//! at once.

use alloc::collections::BTreeMap;

use crate::color::Color;

/// How long colour and border changes take (ms).
pub const COLOUR_MS: i64 = 150;

/// A cubic Bézier timing curve from (0, 0) to (1, 1) through two control
/// points, as CSS's `cubic-bezier()`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Curve(pub f32, pub f32, pub f32, pub f32);

impl Curve {
    /// CSS's `ease`.
    pub const EASE: Curve = Curve(0.25, 0.1, 0.25, 1.0);
    pub const EASE_OUT: Curve = Curve(0.0, 0.0, 0.58, 1.0);
    pub const LINEAR: Curve = Curve(0.0, 0.0, 1.0, 1.0);

    /// The curve's value where its x is `t` (0 to 1).
    pub fn at(&self, t: f32) -> f32 {
        let t = t.clamp(0.0, 1.0);
        let b = |p1: f32, p2: f32, s: f32| {
            let u = 1.0 - s;
            3.0 * u * u * s * p1 + 3.0 * u * s * s * p2 + s * s * s
        };
        // x(s) rises with s: find s by bisection, then y(s).
        let (mut lo, mut hi) = (0.0f32, 1.0f32);
        for _ in 0..24 {
            let mid = (lo + hi) / 2.0;
            if b(self.0, self.2, mid) < t {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        b(self.1, self.3, (lo + hi) / 2.0)
    }
}

/// `a` to `b` by `t` (0 to 1), alpha included.
pub fn mix(a: Color, b: Color, t: f32) -> Color {
    let ch = |s: u32| {
        let (x, y) = ((a.0 >> s) & 0xFF, (b.0 >> s) & 0xFF);
        let v = x as f32 + (y as f32 - x as f32) * t.clamp(0.0, 1.0);
        ((v + 0.5) as u32).min(255) << s
    };
    Color(ch(24) | ch(16) | ch(8) | ch(0))
}

/// One colour on its way: from, to, and when it set off.
#[derive(Clone, Copy, Debug)]
struct Moving {
    from: Color,
    to: Color,
    start: i64,
}

/// The colours of a window's controls, each moving to its target.
#[derive(Clone, Debug, Default)]
pub struct Transitions {
    /// The time now (ms, any clock that only goes forward).
    pub now: i64,
    /// Reduced motion: changes are at once.
    pub reduced: bool,
    colours: BTreeMap<(u32, u8), Moving>,
}

impl Transitions {
    /// The colour of slot `slot` of control `id` now, given its target;
    /// and whether it is still moving. A control seen for the first time
    /// starts at its target.
    pub fn colour(&mut self, id: u32, slot: u8, target: Color) -> (Color, bool) {
        let now = self.now;
        let reduced = self.reduced;
        let m = self.colours.entry((id, slot)).or_insert(Moving { from: target, to: target, start: now - COLOUR_MS });
        if m.to != target {
            // A new target: set off from where it is now.
            let t = ((now - m.start) as f32 / COLOUR_MS as f32).clamp(0.0, 1.0);
            let here = mix(m.from, m.to, Curve::EASE.at(t));
            *m = Moving { from: if reduced { target } else { here }, to: target, start: now };
        }
        let t = ((now - m.start) as f32 / COLOUR_MS as f32).clamp(0.0, 1.0);
        if reduced || t >= 1.0 {
            return (m.to, false);
        }
        (mix(m.from, m.to, Curve::EASE.at(t)), true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curves() {
        for c in [Curve::EASE, Curve::EASE_OUT, Curve::LINEAR] {
            assert!(c.at(0.0).abs() < 1e-3 && (c.at(1.0) - 1.0).abs() < 1e-3);
        }
        assert!((Curve::LINEAR.at(0.3) - 0.3).abs() < 1e-3);
        // `ease` is ahead of linear in its middle (it is 0.8 at 0.5).
        assert!((Curve::EASE.at(0.5) - 0.8024).abs() < 0.01);
    }

    #[test]
    fn colours_move_to_their_targets() {
        let (a, b) = (Color::rgb(0x000000), Color::rgb(0xFFFFFF));
        let mut t = Transitions::default();
        assert_eq!(t.colour(1, 0, a), (a, false));
        t.now = 1000;
        let (c, moving) = t.colour(1, 0, b);
        assert!(moving && c == a);
        t.now = 1075;
        let (mid, moving) = t.colour(1, 0, b);
        assert!(moving && mid.0 & 0xFF > 0x80);
        t.now = 1150;
        assert_eq!(t.colour(1, 0, b), (b, false));
        // Turning back half way starts from where it was.
        t.now = 2000;
        t.colour(1, 0, a);
        t.now = 2075;
        let (half, _) = t.colour(1, 0, a);
        t.now = 2076;
        let (back, _) = t.colour(1, 0, b);
        assert!((back.0 & 0xFF).abs_diff(half.0 & 0xFF) <= 3);
        // Reduced motion: at once.
        t.reduced = true;
        assert_eq!(t.colour(1, 0, a), (a, false));
        assert_eq!(mix(Color::rgb(0).with_alpha(0), Color::rgb(0).with_alpha(200), 0.5).alpha(), 100);
    }
}
