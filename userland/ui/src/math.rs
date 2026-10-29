// SPDX-License-Identifier: MIT OR Apache-2.0

//! The few float functions the toolkit needs, for a target without libm.

/// Largest integer not above `x` (for the ranges geometry uses).
pub fn floor(x: f32) -> f32 {
    let t = x as i32 as f32;
    if t > x { t - 1.0 } else { t }
}

pub fn ceil(x: f32) -> f32 {
    let t = x as i32 as f32;
    if t < x { t + 1.0 } else { t }
}

/// Nearest integer, halves away from zero.
pub fn round(x: f32) -> f32 {
    if x < 0.0 { -floor(-x + 0.5) } else { floor(x + 0.5) }
}

pub fn abs(x: f32) -> f32 {
    if x < 0.0 { -x } else { x }
}

pub fn sqrt(x: f32) -> f32 {
    if x <= 0.0 || x.is_nan() {
        return 0.0;
    }
    // A first guess from the exponent, then Newton's iteration.
    let mut y = f32::from_bits((x.to_bits() >> 1) + (127u32 << 22));
    for _ in 0..4 {
        y = 0.5 * (y + x / y);
    }
    y
}

pub fn min(a: f32, b: f32) -> f32 {
    if a < b { a } else { b }
}

pub fn max(a: f32, b: f32) -> f32 {
    if a > b { a } else { b }
}

pub fn clamp(x: f32, lo: f32, hi: f32) -> f32 {
    max(lo, min(hi, x))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn functions() {
        assert_eq!(floor(-1.5), -2.0);
        assert_eq!(floor(2.0), 2.0);
        assert_eq!(ceil(1.2), 2.0);
        assert_eq!(ceil(-1.2), -1.0);
        assert_eq!(round(2.5), 3.0);
        assert!(abs(sqrt(2.0) - core::f32::consts::SQRT_2) < 1e-6);
        assert!(abs(sqrt(1e6) - 1000.0) < 1e-3);
    }
}
