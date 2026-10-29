// SPDX-License-Identifier: MIT OR Apache-2.0

//! The built-in wallpapers (ADR 0110, ADR 0124): seven designs drawn from the
//! palette, so each has a graphite and a light version (and follows high
//! contrast). They are greys only: tones between `desktop` and `chalk`,
//! a few percent apart, as WM_STYLE §8's contours are. Each design is
//! drawn within its area, so Settings draws the same code small.
//!
//! Two more are the themes' own (ADR 0167), in colour and the same in
//! every palette: Copper glow (Copper Noir's) and Sediment (Sediment's),
//! from docs/design/STRATA_THEMES_COPPER_SEDIMENT.md §2.5 and §3.5.

use alloc::vec::Vec;

use crate::color::Color;
use crate::graphite::{Palette, mix};
use crate::icon::{cos, sin};
use crate::math::sqrt;
use crate::paint::Painter;
use crate::path::Path;
use crate::ui::Area;

/// A wallpaper design.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Design {
    /// Fine engraved lines, almost flat at the top left and swelling
    /// towards the bottom right (Atelier, ADR 0124).
    Lineation,
    /// WM_STYLE §8: seven contour lines across the lower part.
    Contours,
    /// Layered dunes rising to the bottom, each crest lit: the default
    /// (the owner, 2026-10-26).
    #[default]
    Dunes,
    /// Orbits around a point below the bottom right corner.
    Orbits,
    /// A field of dots, brightest around one point.
    Dots,
    /// Low-poly facets, darkening across the screen.
    Facets,
    /// Bands of sediment across the screen, tilted.
    Strata,
    /// A low copper glow from the bottom left, with faint rings around
    /// it (Copper Noir's).
    CopperGlow,
    /// Seven wavy rock strata under a sand sky and a pale sun
    /// (Sediment's).
    Sediment,
}

impl Design {
    pub const ALL: [Design; 9] = [
        Design::Lineation,
        Design::Contours,
        Design::Dunes,
        Design::Orbits,
        Design::Dots,
        Design::Facets,
        Design::Strata,
        Design::CopperGlow,
        Design::Sediment,
    ];

    /// Whether it is drawn in the palette's greys (else in its own
    /// colours).
    pub fn greys(self) -> bool {
        !matches!(self, Design::CopperGlow | Design::Sediment)
    }

    /// Its name in the settings file.
    pub fn key(self) -> &'static str {
        match self {
            Design::Lineation => "lineation",
            Design::Contours => "contours",
            Design::Dunes => "dunes",
            Design::Orbits => "orbits",
            Design::Dots => "dots",
            Design::Facets => "facets",
            Design::Strata => "strata",
            Design::CopperGlow => "copper-glow",
            Design::Sediment => "sediment",
        }
    }

    /// Its name as Settings shows it.
    pub fn name(self) -> &'static str {
        match self {
            Design::Lineation => "Lineation",
            Design::Contours => "Contours",
            Design::Dunes => "Dunes",
            Design::Orbits => "Orbits",
            Design::Dots => "Dots",
            Design::Facets => "Facets",
            Design::Strata => "Strata",
            Design::CopperGlow => "Copper glow",
            Design::Sediment => "Sediment",
        }
    }

    pub fn from_key(k: &str) -> Option<Design> {
        Design::ALL.into_iter().find(|d| d.key() == k)
    }
}

/// A tone `t` of the way from `desktop` to `chalk`.
fn tone(pal: &Palette, t: f32) -> Color {
    mix(pal.desktop, pal.chalk, t)
}

/// A number in [0, 1) from two integers, the same every time.
fn hash(a: i32, b: i32) -> f32 {
    let mut h = (a as u32).wrapping_mul(0x9E37_79B1) ^ (b as u32).wrapping_mul(0x85EB_CA77);
    h ^= h >> 15;
    h = h.wrapping_mul(0x2C1B_3C6D);
    h ^= h >> 12;
    (h & 0xFFFF) as f32 / 65536.0
}

/// Draw `design` over `area`.
pub fn draw(p: &mut Painter<'_>, pal: &Palette, area: Area, design: Design) {
    let saved = p.clip(area);
    match design {
        Design::Lineation => lineation(p, pal, area),
        Design::Contours => crate::graphite::wallpaper(p, pal, area),
        Design::Dunes => dunes(p, pal, area),
        Design::Orbits => orbits(p, pal, area),
        Design::Dots => dots(p, pal, area),
        Design::Facets => facets(p, pal, area),
        Design::Strata => strata(p, pal, area),
        Design::CopperGlow => copper_glow(p, area),
        Design::Sediment => sediment(p, area),
    }
    p.unclip(saved);
}

/// The 4 × 4 ordered (Bayer) dither's thresholds, in sixteenths.
const BAYER: [[u8; 4]; 4] = [[0, 8, 2, 10], [12, 4, 14, 6], [3, 11, 1, 9], [15, 7, 13, 5]];

/// A channel value (0 to 255, fractional) to 8 bits, dithered by ±0.5
/// with threshold `b` (sixteenths, from [`BAYER`]): long, dark, gentle
/// gradients band without it. In sixteenths, `floor(v + (b + 0.5) / 16)`.
fn dither(v: f32, b: i32) -> u32 {
    (((v * 16.0 + 0.5) as i32 + b) >> 4).clamp(0, 255) as u32
}

/// An 0xRRGGBB colour's channels as floats.
fn channels(c: u32) -> [f32; 3] {
    [((c >> 16) & 0xFF) as f32, ((c >> 8) & 0xFF) as f32, (c & 0xFF) as f32]
}

/// The span over which [`per_pixel`] interpolates its fields.
const SPAN: i32 = 8;

/// Set each device pixel of `a` (within the clip): `field` gives `N`
/// smoothly varying values at a device position, computed exactly every
/// [`SPAN`] pixels along a row and linearly between (they are distances,
/// whose curvature over a span is far below a step of colour); `shade`
/// makes the channels (0 to 255, fractional) from them, dithered to 8
/// bits.
fn per_pixel<const N: usize>(
    p: &mut Painter<'_>,
    a: Area,
    field: impl Fn(f32, f32) -> [f32; N],
    shade: impl Fn(&[f32; N]) -> [f32; 3],
) {
    let r = p.device(&a).intersect(&p.canvas.clip());
    let width = p.canvas.width;
    for y in r.y..r.bottom() {
        let fy = y as f32 + 0.5;
        let bayer = &BAYER[(y & 3) as usize];
        let mut x0 = r.x;
        let mut f0 = field(x0 as f32 + 0.5, fy);
        let row = &mut p.canvas.pixels[(y * width) as usize..((y + 1) * width) as usize];
        while x0 < r.right() {
            let x1 = (x0 + SPAN).min(r.right());
            let f1 = field(x1 as f32 + 0.5, fy);
            let n = (x1 - x0) as f32;
            let mut step = [0.0; N];
            for i in 0..N {
                step[i] = (f1[i] - f0[i]) / n;
            }
            let mut f = f0;
            for x in x0..x1 {
                let [cr, cg, cb] = shade(&f);
                let b = i32::from(bayer[(x & 3) as usize]);
                row[x as usize] = 0xFF00_0000 | dither(cr, b) << 16 | dither(cg, b) << 8 | dither(cb, b);
                for i in 0..N {
                    f[i] += step[i];
                }
            }
            (x0, f0) = (x1, f1);
        }
    }
}

/// Copper Noir's wallpaper (the handoff, §2.5): near-black, a copper glow
/// from below the bottom left and a fainter one from above the top
/// right, each fading linearly to nothing at 70% of its radii; nine
/// faint 1 px rings around a point below the bottom left; all in one
/// dithered pass. Laid out for 1440 × 900: positions scale with the
/// area, radii with its smaller ratio.
fn copper_glow(p: &mut Painter<'_>, a: Area) {
    let k = p.scale;
    let (sx, sy) = (a.w / 1440.0, a.h / 900.0);
    let s = sx.min(sy);
    let base = channels(0x121211);
    let glow = channels(0xC8875A);
    let ring = channels(0xE0A97E);
    // Centre, radii and peak, in device pixels.
    let glows = [
        ((a.x + 0.12 * a.w) * k, (a.y + 1.08 * a.h) * k, 900.0 * s * k, 600.0 * s * k, 0.30),
        (a.right() * k, (a.y - 0.10 * a.h) * k, 700.0 * s * k, 500.0 * s * k, 0.10),
    ];
    let (rx, ry) = ((a.x + 140.0 * sx) * k, (a.bottom() + 80.0 * sy) * k);
    let (r0, gap) = (320.0 * s * k, 70.0 * s * k);
    // The ring's half width, in device pixels (1 logical pixel wide).
    let half = 0.5 * k;
    per_pixel(
        p,
        a,
        |x, y| {
            let d = |(cx, cy, rx, ry, _): (f32, f32, f32, f32, f32)| {
                let (u, v) = ((x - cx) / rx, (y - cy) / ry);
                sqrt(u * u + v * v)
            };
            [d(glows[0]), d(glows[1]), sqrt((x - rx) * (x - rx) + (y - ry) * (y - ry))]
        },
        |f| {
            let mut c = base;
            for (g, d) in glows.iter().zip(f) {
                if *d < 0.70 {
                    let t = g.4 * (1.0 - d / 0.70);
                    for i in 0..3 {
                        c[i] += (glow[i] - c[i]) * t;
                    }
                }
            }
            // The nearest ring, its coverage of this pixel, and its alpha
            // (0.16 for the first, 0.015 less for each after).
            let i = crate::math::round((f[2] - r0) / gap).clamp(0.0, 8.0);
            let cover = (half + 0.5 - crate::math::abs(f[2] - (r0 + gap * i))).clamp(0.0, 1.0);
            if cover > 0.0 {
                let t = cover * (0.16 - 0.015 * i);
                for j in 0..3 {
                    c[j] += (ring[j] - c[j]) * t;
                }
            }
            c
        },
    );
}

/// Sediment's wallpaper (the handoff, §3.5): a sand sky in a dithered
/// vertical gradient, a pale sun, and seven wavy bands of rock (ochre,
/// rust, terracotta, sage, olive, slate, ink) over its lower half, back
/// to front. Laid out for 1440 × 900: heights and amplitudes scale with
/// the height; wavelengths stay in logical pixels on larger screens and
/// shrink with smaller areas (Settings' thumbnails).
fn sediment(p: &mut Painter<'_>, a: Area) {
    let (sx, sy) = (a.w / 1440.0, a.h / 900.0);
    let stops = [(0.0, channels(0xF1E6D6)), (0.55, channels(0xEAD9C2)), (1.0, channels(0xE2CDB0))];
    let k = p.scale;
    per_pixel(
        p,
        a,
        |_, y| {
            let t = ((y / k - a.y) / a.h).clamp(0.0, 1.0);
            let (lo, hi) = if t < stops[1].0 { (stops[0], stops[1]) } else { (stops[1], stops[2]) };
            let u = (t - lo.0) / (hi.0 - lo.0);
            let mut c = lo.1;
            for i in 0..3 {
                c[i] += (hi.1[i] - lo.1[i]) * u;
            }
            c
        },
        |c| *c,
    );
    p.path(&Path::circle(a.x + 1180.0 * sx, a.y + 210.0 * sy, 70.0 * sy), Color::rgb(0xF7EFE2).with_alpha(230));
    let colours = [0xD9A441, 0xC9874B, 0xB5643C, 0x8A9A6B, 0x6E7A5A, 0x4B5563, 0x2F3340];
    let tops = [520.0, 580.0, 640.0, 700.0, 750.0, 800.0, 850.0];
    // Logical pixels per design pixel along x.
    let kx = sx.min(1.0);
    let steps = (a.w / (40.0 * kx)) as usize + 1;
    for (i, (&c, &y0)) in colours.iter().zip(tops.iter()).enumerate() {
        let amp = 26.0 + 4.0 * i as f32;
        let phase = 0.9 * i as f32;
        let mut outline: Vec<(f32, f32)> = (0..=steps)
            .map(|s| {
                let x = (s as f32 * 40.0 * kx).min(a.w);
                let u = x / kx;
                let y = y0 + amp * sin(u / 210.0 + phase) + 10.0 * sin(u / 70.0 + 2.0 * phase);
                (a.x + x, a.y + y * sy)
            })
            .collect();
        outline.push((a.right(), a.bottom()));
        outline.push((a.x, a.bottom()));
        p.path(&Path::polygon(&outline), Color::rgb(c));
    }
}

/// Lines 8 px apart from y = 44 down, each a sine sampled every 48 px
/// whose amplitude grows from 1.5 px at the top left to 8.5 at the bottom
/// right; every ninth line a step brighter (STRATA_ATELIER.md §3.6). A
/// small area (Settings' thumbnails) draws the same design scaled down,
/// to half size at most, so its lines stay apart.
fn lineation(p: &mut Painter<'_>, pal: &Palette, a: Area) {
    p.fill(a, 0.0, pal.desktop);
    let k = (a.w / 1440.0).clamp(0.5, 1.0);
    let (w, h) = (a.w / k, a.h / k);
    let steps = (w / 48.0) as usize + 1;
    let mut i = 0;
    let mut y = 44.0;
    while y < h {
        let points: Vec<(f32, f32)> = (0..=steps)
            .map(|s| {
                let x = (s as f32 * 48.0).min(w);
                let amp = 1.5 + 7.0 * (y / h) * (0.4 + 0.6 * x / w);
                (a.x + x * k, a.y + (y + amp * sin(x / 260.0 + y / 70.0)) * k)
            })
            .collect();
        let c = if i % 9 == 4 { pal.lineation_accent } else { pal.lineation_fine };
        p.polyline(&points, k, c);
        y += 8.0;
        i += 1;
    }
}

/// A wave across `a` at height `base`: two sines, `amp` tall, the first
/// `freq` times across.
fn wave(a: Area, base: f32, amp: f32, freq: f32, phase: f32, steps: usize) -> Vec<(f32, f32)> {
    (0..=steps)
        .map(|k| {
            let u = k as f32 / steps as f32;
            let t = u * core::f32::consts::TAU;
            let y = base + amp * (0.75 * sin(t * freq + phase) + 0.25 * sin(t * freq * 2.7 + phase * 1.9));
            (a.x + a.w * u, y)
        })
        .collect()
}

/// Five dunes in broad swells, closer together towards the bottom, the
/// far ones faint and each nearer one standing out more, with a lit
/// crest.
fn dunes(p: &mut Painter<'_>, pal: &Palette, a: Area) {
    p.fill(a, 0.0, pal.desktop);
    let n = 5;
    let mut base = a.y + a.h * 0.5;
    for i in 0..n {
        let f = i as f32 / (n - 1) as f32;
        let amp = a.h * (0.075 - 0.01 * i as f32);
        let crest = wave(a, base, amp, 0.55 + 0.12 * i as f32, 0.9 + i as f32 * 2.3, 96);
        let mut outline = crest.clone();
        outline.push((a.right(), a.bottom()));
        outline.push((a.x, a.bottom()));
        p.path(&Path::polygon(&outline), tone(pal, 0.02 + 0.04 * f));
        p.polyline(&crest, 1.0, tone(pal, 0.09 + 0.05 * f));
        base += a.h * (0.13 - 0.02 * i as f32);
    }
}

/// Ten orbits around a centre below the bottom right, their lines fading
/// outwards, with a small moon on one.
fn orbits(p: &mut Painter<'_>, pal: &Palette, a: Area) {
    p.fill(a, 0.0, pal.desktop);
    let (cx, cy) = (a.x + a.w * 0.8, a.y + a.h * 1.08);
    let r0 = a.h * 0.2;
    p.path(&Path::circle(cx, cy, r0), tone(pal, 0.045));
    let mut r = r0;
    for k in 0..10 {
        let ring: Vec<(f32, f32)> = (0..=160)
            .map(|i| {
                let t = i as f32 / 160.0 * core::f32::consts::TAU;
                (cx + r * cos(t), cy + r * sin(t))
            })
            .collect();
        p.polyline(&ring, 1.0, tone(pal, 0.16 - 0.011 * k as f32));
        if k == 4 {
            let t = -2.35;
            let (mx, my) = (cx + r * cos(t), cy + r * sin(t));
            p.path(&Path::circle(mx, my, 6.0), tone(pal, 0.3));
        }
        r *= 1.3;
    }
}

/// Dots 28 px apart, brightest around a point in the upper left third.
fn dots(p: &mut Painter<'_>, pal: &Palette, a: Area) {
    p.fill(a, 0.0, pal.desktop);
    let gap = 28.0;
    let (fx, fy) = (a.x + a.w * 0.3, a.y + a.h * 0.38);
    let reach = sqrt(a.w * a.w + a.h * a.h) * 0.7;
    let (cols, rows) = ((a.w / gap) as i32 + 1, (a.h / gap) as i32 + 1);
    let (ox, oy) = (a.x + (a.w - (cols - 1) as f32 * gap) / 2.0, a.y + (a.h - (rows - 1) as f32 * gap) / 2.0);
    for j in 0..rows {
        for i in 0..cols {
            let (x, y) = (ox + i as f32 * gap, oy + j as f32 * gap);
            let d = sqrt((x - fx) * (x - fx) + (y - fy) * (y - fy));
            let near = (1.0 - d / reach).max(0.0);
            p.path(&Path::circle(x, y, 1.1 + 0.7 * near), tone(pal, 0.07 + 0.3 * near * near));
        }
    }
}

/// A jittered grid of triangles, lighter at the top left, each a little
/// different.
fn facets(p: &mut Painter<'_>, pal: &Palette, a: Area) {
    let (cols, rows) = (12, 8);
    let (cw, rh) = (a.w / cols as f32, a.h / rows as f32);
    let shade = |u: f32, v: f32| 0.01 + 0.055 * (1.0 - (0.6 * u + 0.4 * v)).clamp(0.0, 1.0);
    // The average under the seams, so no edge shows the desktop through.
    p.fill(a, 0.0, tone(pal, shade(0.5, 0.5)));
    let point = |i: i32, j: i32| {
        let edge_x = i == 0 || i == cols;
        let edge_y = j == 0 || j == rows;
        let jx = if edge_x { 0.0 } else { (hash(i, j) - 0.5) * 0.55 * cw };
        let jy = if edge_y { 0.0 } else { (hash(j + 101, i) - 0.5) * 0.55 * rh };
        (a.x + i as f32 * cw + jx, a.y + j as f32 * rh + jy)
    };
    for j in 0..rows {
        for i in 0..cols {
            let (p00, p10, p01, p11) = (point(i, j), point(i + 1, j), point(i, j + 1), point(i + 1, j + 1));
            // Alternate the diagonal, so the facets don't line up.
            let tris =
                if (i + j) % 2 == 0 { [[p00, p10, p11], [p00, p11, p01]] } else { [[p00, p10, p01], [p10, p11, p01]] };
            for (k, t) in tris.iter().enumerate() {
                let (mx, my) = ((t[0].0 + t[1].0 + t[2].0) / 3.0, (t[0].1 + t[1].1 + t[2].1) / 3.0);
                let (u, v) = ((mx - a.x) / a.w, (my - a.y) / a.h);
                let jitter = (hash(i * 2 + k as i32, j + 57) - 0.5) * 0.014;
                p.path(&Path::polygon(t), tone(pal, (shade(u, v) + jitter).max(0.0)));
            }
        }
    }
}

/// Fourteen tilted bands with gently waving edges, their tones varying a
/// little, and a fine line along some of the edges.
fn strata(p: &mut Painter<'_>, pal: &Palette, a: Area) {
    p.fill(a, 0.0, pal.desktop);
    let n = 14;
    let tilt = a.h * 0.32;
    let step = (a.h + tilt) / n as f32;
    let edge = |j: i32| -> Vec<(f32, f32)> {
        let mut w = wave(a, a.y - tilt + step * j as f32, step * 0.22, 1.0, j as f32 * 0.8, 64);
        // Rising to the right.
        for (x, y) in w.iter_mut() {
            *y += tilt * (1.0 - (*x - a.x) / a.w);
        }
        w
    };
    let mut top = edge(0);
    for j in 0..=n {
        let bottom = edge(j + 1);
        let mut band = top.clone();
        band.extend(bottom.iter().rev());
        p.path(&Path::polygon(&band), tone(pal, 0.012 + 0.05 * hash(j, 7)));
        if hash(j, 31) > 0.55 {
            p.polyline(&bottom, 1.0, tone(pal, 0.11));
        }
        top = bottom;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Canvas;
    use crate::text::GlyphCache;

    /// A design drawn over `w` × `h` at `scale`.
    fn drawn(d: Design, w: i32, h: i32, scale: f32) -> Canvas {
        let mut c = Canvas::new(w, h, Color::rgb(0xFF0000));
        let mut cache = GlyphCache::new();
        let mut p = Painter::new(&mut c, &mut cache, scale);
        let (lw, lh) = p.size();
        draw(&mut p, &Palette::GRAPHITE, Area::new(0.0, 0.0, lw, lh), d);
        c
    }

    /// Copper glow (the handoff, §2.5): near-black at the top left, the
    /// glow warmest at the bottom left and never above its centre's
    /// colour, the rings faint.
    #[test]
    fn copper_glow() {
        let c = drawn(Design::CopperGlow, 1440, 900, 1.0);
        let rgb = |x, y| {
            let px = c.pixel(x, y);
            ((px >> 16) & 0xFF, (px >> 8) & 0xFF, px & 0xFF)
        };
        let (r, g, b) = rgb(700, 200);
        assert!(r <= 0x14 && g <= 0x14 && b <= 0x13, "{r:x} {g:x} {b:x}");
        let (r, g, b) = rgb(170, 895);
        assert!(r > g && g > b && r >= 0x30 && r <= 0x49, "{r:x} {g:x} {b:x}");
        // The glow falls off: brighter at the bottom left than half way up.
        assert!(rgb(170, 895).0 > rgb(170, 500).0);
        // No pixel brighter than the glow's peak (#493527, with a step
        // of dither and a ring over it).
        assert!(c.pixels.iter().all(|px| (px >> 16) & 0xFF <= 0x4E), "too bright");
    }

    /// Sediment (the handoff, §3.5): the sky's top colour, the sun, and
    /// the ink band at the bottom.
    #[test]
    fn sediment() {
        let c = drawn(Design::Sediment, 1440, 900, 1.0);
        let near = |x, y, want: u32| {
            let px = c.pixel(x, y);
            let d = |s: u32| ((px >> s) & 0xFF).abs_diff((want >> s) & 0xFF);
            assert!(d(16) <= 1 && d(8) <= 1 && d(0) <= 1, "({x}, {y}) is {:06x}, not {want:06x}", px & 0xFF_FFFF);
        };
        near(100, 2, 0xF1E6D6);
        near(1180, 210, 0xF6EDDF);
        near(720, 898, 0x2F3340);
        // The ochre band shows under the sky, above the others.
        let px = c.pixel(300, 540) & 0xFF_FFFF;
        assert!([0xD9A441, 0xC9874B].contains(&px) || px >> 16 > 0xE0, "{px:06x}");
    }

    /// Each bakes quickly at 2880 × 1800 (the reference machine's display
    /// at 2×), well inside what a change of settings may take.
    #[test]
    fn designs_bake_quickly() {
        for d in Design::ALL {
            let t = std::time::Instant::now();
            drawn(d, 2880, 1800, 2.0);
            let ms = t.elapsed().as_millis();
            std::println!("{d:?}: {ms} ms at 2880 × 1800");
            assert!(ms < 5000, "{d:?} took {ms} ms");
        }
    }

    #[test]
    fn keys() {
        for d in Design::ALL {
            assert_eq!(Design::from_key(d.key()), Some(d));
        }
        assert_eq!(Design::from_key("nope"), None);
    }

    /// Every design stays within its area, and differs from a plain fill.
    #[test]
    fn drawn_within_the_area() {
        for pal in [Palette::GRAPHITE, Palette::DAY] {
            for d in Design::ALL {
                let mut c = Canvas::new(320, 200, Color::rgb(0xFF0000));
                let mut cache = GlyphCache::new();
                let mut p = Painter::new(&mut c, &mut cache, 1.0);
                draw(&mut p, &pal, Area::new(20.0, 10.0, 280.0, 180.0), d);
                assert_eq!(c.pixel(5, 5) & 0xFF_FFFF, 0xFF0000, "{d:?} drew outside");
                assert_eq!(c.pixel(310, 195) & 0xFF_FFFF, 0xFF0000, "{d:?} drew outside");
                let inside: Vec<u32> =
                    (10..190).flat_map(|y| (20..300).map(move |x| (x, y))).map(|(x, y)| c.pixel(x, y)).collect();
                assert!(inside.iter().all(|&px| px & 0xFF_FFFF != 0xFF0000), "{d:?} left a gap");
                let distinct = inside.iter().collect::<alloc::collections::BTreeSet<_>>().len();
                assert!(distinct > 3, "{d:?} is flat");
                // Greys only: each pixel's channels within a few steps
                // (the themes' own designs are in colour).
                if !d.greys() {
                    continue;
                }
                for px in inside {
                    let (r, g, b) = ((px >> 16) & 0xFF, (px >> 8) & 0xFF, px & 0xFF);
                    assert!(r.abs_diff(g) <= 8 && g.abs_diff(b) <= 8, "{d:?} has colour {px:06x}");
                }
            }
        }
    }
}
