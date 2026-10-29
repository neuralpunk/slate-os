// SPDX-License-Identifier: MIT OR Apache-2.0

//! Colours: 0xAARRGGBB, not premultiplied, composited in sRGB space (as
//! browsers composite CSS, which the style guide's values assume).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Color(pub u32);

impl Color {
    /// An opaque colour from 0xRRGGBB.
    pub const fn rgb(hex: u32) -> Color {
        Color(0xFF00_0000 | (hex & 0x00FF_FFFF))
    }

    /// The colour with alpha `a` (0-255).
    pub const fn with_alpha(self, a: u8) -> Color {
        Color((self.0 & 0x00FF_FFFF) | ((a as u32) << 24))
    }

    /// The colour with its alpha scaled by `opacity` (0.0-1.0).
    pub fn faded(self, opacity: f32) -> Color {
        let a = (self.alpha() as f32 * opacity + 0.5) as u32;
        self.with_alpha(a.min(255) as u8)
    }

    pub const fn alpha(self) -> u8 {
        (self.0 >> 24) as u8
    }

    pub const TRANSPARENT: Color = Color(0);
}

/// Composite `src` with `coverage` (0-255) over the pixel `dst` (Porter
/// and Duff's "over"). Over an opaque pixel the result is opaque; over a
/// transparent or translucent one (a layer drawn before it is composited:
/// the launcher, menus, dialogs, fading windows) the alphas combine, so a
/// shadow drawn on a layer stays a shadow.
pub fn blend(dst: u32, src: Color, coverage: u8) -> u32 {
    let a = div255(src.alpha() as u32 * coverage as u32 + 127);
    if a == 0 {
        return dst;
    }
    if a == 255 {
        return 0xFF00_0000 | (src.0 & 0x00FF_FFFF);
    }
    let da = dst >> 24;
    if da == 255 {
        return over_opaque(dst, src.0, a);
    }
    // Onto a transparent pixel (a layer): the colour at alpha a, as the
    // formula below gives it.
    if da == 0 {
        return (src.0 & 0x00FF_FFFF) | (a << 24);
    }
    // Not premultiplied: each colour is weighted by its own alpha, and
    // the sum divided by the alpha of the result.
    let dw = da * (255 - a);
    let out = a * 255 + dw;
    let mix = |shift: u32| {
        let s = (src.0 >> shift) & 0xFF;
        let d = (dst >> shift) & 0xFF;
        ((s * a * 255 + d * dw + out / 2) / out) << shift
    };
    (((out + 127) / 255) << 24) | mix(16) | mix(8) | mix(0)
}

/// `x / 255` for `x` up to 65534 without a division: the slow part of
/// blending at 4K (M32 phase 2). Exact (the tests try every value).
#[inline(always)]
pub fn div255(x: u32) -> u32 {
    (x + 1 + (x >> 8)) >> 8
}

/// [`blend`] onto an opaque pixel: the colour `src` (its alpha ignored)
/// at alpha `a` (0-255) over `dst`, each channel `(s a + d (255 - a) +
/// 127) / 255` as [`blend`] has it, red and blue side by side in one
/// word. Opaque.
#[inline(always)]
pub fn over_opaque(dst: u32, src: u32, a: u32) -> u32 {
    let na = 255 - a;
    // Each lane is at most 255 × 255 + 127 = 65152, so neither carries.
    let rb = (src & 0x00FF_00FF) * a + (dst & 0x00FF_00FF) * na + 0x007F_007F;
    let rb = ((rb + 0x0001_0001 + ((rb >> 8) & 0x00FF_00FF)) >> 8) & 0x00FF_00FF;
    let g = div255(((src >> 8) & 0xFF) * a + ((dst >> 8) & 0xFF) * na + 127);
    0xFF00_0000 | rb | (g << 8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn division_free() {
        for x in 0..65535 {
            assert_eq!(div255(x), x / 255, "{x}");
        }
        // over_opaque is the formula it replaces, for every alpha and a
        // spread of channel values.
        let slow = |d: u32, s: u32, a: u32| {
            let mix = |sh: u32| ((((s >> sh) & 0xFF) * a + ((d >> sh) & 0xFF) * (255 - a) + 127) / 255) << sh;
            0xFF00_0000 | mix(16) | mix(8) | mix(0)
        };
        // Onto a transparent pixel, as the general formula has it.
        for a in 1..=255u32 {
            let src = Color(0x00AB_CDEF | (a << 24));
            let dw = 0u32;
            let out = a * 255 + dw;
            let slow = (((out + 127) / 255) << 24)
                | ((0xAB * a * 255 + out / 2) / out) << 16
                | ((0xCD * a * 255 + out / 2) / out) << 8
                | ((0xEF * a * 255 + out / 2) / out);
            assert_eq!(blend(0x0012_3456, src, 255), slow, "a {a}");
        }
        for a in 0..=255 {
            for v in (0..=255u32).step_by(3) {
                let (d, s) =
                    (0xFF00_0000 | v << 16 | (255 - v) << 8 | (v * 7 % 256), (v * 13 % 256) << 16 | v << 8 | (255 - v));
                assert_eq!(over_opaque(d, s, a), slow(d, s, a), "a {a} d {d:x} s {s:x}");
            }
        }
    }

    #[test]
    fn blending() {
        let white = 0xFFFF_FFFF;
        assert_eq!(blend(white, Color::rgb(0x000000), 255), 0xFF00_0000);
        assert_eq!(blend(white, Color::rgb(0x000000), 0), white);
        assert_eq!(blend(white, Color::rgb(0x000000).with_alpha(128), 255), 0xFF7F_7F7F);
        assert_eq!(blend(white, Color::rgb(0x000000), 128), 0xFF7F_7F7F);
    }

    #[test]
    fn blending_onto_a_layer() {
        // A half-covered shadow pixel on a transparent layer is a
        // translucent black, not an opaque one.
        let shadow = Color::rgb(0).with_alpha(217);
        assert_eq!(blend(0, shadow, 128), 0x6D00_0000);
        // Twice over the same layer pixel: 1 - (1 - a)^2.
        let once = blend(0, Color::rgb(0xFFFFFF).with_alpha(128), 255);
        assert_eq!(once, 0x80FF_FFFF);
        assert_eq!(blend(once, Color::rgb(0xFFFFFF).with_alpha(128), 255) >> 24, 0xC0);
        // Red over half-transparent blue: the alphas weigh the colours.
        let p = blend(0x8000_00FF, Color::rgb(0xFF0000).with_alpha(128), 255);
        assert_eq!(p >> 24, 0xC0);
        assert_eq!((p >> 16) & 0xFF, 0xAA);
        assert_eq!(p & 0xFF, 0x55);
        // Composited onto an opaque pixel, the layer gives what drawing
        // straight onto it gives (within rounding).
        let layer = blend(0, shadow, 128);
        let direct = blend(0xFF80_8080, shadow, 128);
        let via = blend(0xFF80_8080, Color(layer), 255);
        for shift in [0, 8, 16] {
            let (x, y) = ((direct >> shift) & 0xFF, (via >> shift) & 0xFF);
            assert!(x.abs_diff(y) <= 1, "{direct:08x} {via:08x}");
        }
    }
}
