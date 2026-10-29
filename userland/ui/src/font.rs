// SPDX-License-Identifier: MIT OR Apache-2.0

//! A TrueType font reader: what text rendering needs and no more.
//!
//! Formats per Microsoft's OpenType specification and Apple's TrueType
//! Reference Manual:
//! - the table directory;
//! - `head` (units per em, loca format), `hhea` (ascender, descender,
//!   line gap, metrics count), `maxp` (glyph count);
//! - `cmap` subtable formats 4 and 12, `hmtx`, `loca`;
//! - `glyf`, simple and composite glyphs;
//! - kerning from `GPOS` lookups of the `kern` feature: pair adjustments
//!   (lookup type 2, formats 1 and 2, possibly through extension lookups,
//!   type 9), coverage formats 1 and 2, class definitions formats 1 and 2;
//! - substitutions from `GSUB` lookups of the `liga` (standard
//!   ligatures) and `calt` (contextual alternates) features (ADR 0101):
//!   single substitutions (type 1, formats 1 and 2), ligatures (type 4),
//!   chained contexts by coverage (type 6, format 3) applying nested
//!   lookups, through extension lookups (type 7). Lookup flags (skipping
//!   marks) are not read: Slate's fonts are Latin.
//!
//! Every read is bounds-checked: a damaged font yields missing glyphs,
//! never a panic.

use alloc::vec::Vec;

use crate::path::Path;

/// Big-endian reads that fail softly.
#[derive(Clone, Copy)]
struct Data<'a>(&'a [u8]);

impl<'a> Data<'a> {
    fn u8(&self, at: usize) -> Option<u8> {
        self.0.get(at).copied()
    }
    fn u16(&self, at: usize) -> Option<u16> {
        Some(u16::from_be_bytes(self.0.get(at..at + 2)?.try_into().ok()?))
    }
    fn i16(&self, at: usize) -> Option<i16> {
        self.u16(at).map(|v| v as i16)
    }
    fn u32(&self, at: usize) -> Option<u32> {
        Some(u32::from_be_bytes(self.0.get(at..at + 4)?.try_into().ok()?))
    }
}

/// A parsed font. Glyph outlines and kerning are read on demand.
#[derive(Clone)]
pub struct Font<'a> {
    data: Data<'a>,
    pub units_per_em: u16,
    /// hhea ascender (font units, positive up).
    pub ascender: i16,
    /// hhea descender (negative).
    pub descender: i16,
    pub line_gap: i16,
    /// The height of lowercase letters (OS/2 sxHeight, else the top of
    /// 'x'), for hinting; 0 if unknown.
    pub x_height: i16,
    num_glyphs: u16,
    num_hmetrics: u16,
    loca_long: bool,
    cmap: Option<(usize, u16)>,
    glyf: usize,
    loca: usize,
    hmtx: usize,
    /// PairPos subtables (offsets into the font) of the `kern` feature.
    kern: Vec<usize>,
    /// GSUB's lookup list and the lookups `liga` and `calt` name, in
    /// lookup order.
    gsub: Option<(usize, Vec<u16>)>,
}

impl core::fmt::Debug for Font<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Font({} glyphs, {} units/em)", self.num_glyphs, self.units_per_em)
    }
}

/// A point of a glyph outline (font units) and whether it is on the curve.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Point {
    x: f32,
    y: f32,
    on: bool,
}

impl<'a> Font<'a> {
    /// Parse `bytes`; None if it isn't a TrueType font this reader
    /// handles (glyf outlines).
    pub fn new(bytes: &'a [u8]) -> Option<Font<'a>> {
        let d = Data(bytes);
        let version = d.u32(0)?;
        if version != 0x0001_0000 && version != u32::from_be_bytes(*b"true") {
            return None;
        }
        let count = d.u16(4)? as usize;
        let table = |tag: &[u8; 4]| -> Option<usize> {
            (0..count).find_map(|i| {
                let rec = 12 + 16 * i;
                (d.0.get(rec..rec + 4)? == tag).then(|| d.u32(rec + 8).map(|o| o as usize)).flatten()
            })
        };
        let head = table(b"head")?;
        let hhea = table(b"hhea")?;
        let maxp = table(b"maxp")?;
        let mut font = Font {
            data: d,
            units_per_em: d.u16(head + 18)?,
            ascender: d.i16(hhea + 4)?,
            descender: d.i16(hhea + 6)?,
            line_gap: d.i16(hhea + 8)?,
            x_height: 0,
            num_glyphs: d.u16(maxp + 4)?,
            num_hmetrics: d.u16(hhea + 34)?,
            loca_long: d.i16(head + 50)? == 1,
            cmap: None,
            glyf: table(b"glyf")?,
            loca: table(b"loca")?,
            hmtx: table(b"hmtx")?,
            kern: Vec::new(),
            gsub: None,
        };
        if font.units_per_em == 0 {
            return None;
        }
        font.cmap = table(b"cmap").and_then(|c| best_cmap(d, c));
        if let Some(gpos) = table(b"GPOS") {
            font.kern = kern_subtables(d, gpos).unwrap_or_default();
        }
        if let Some(gsub) = table(b"GSUB") {
            font.gsub = gsub_lookups(d, gsub);
        }
        // OS/2 version 2 and later carry sxHeight at offset 86.
        font.x_height = table(b"OS/2")
            .and_then(|o| if d.u16(o)? >= 2 { d.i16(o + 86) } else { None })
            .filter(|&h| h > 0)
            .unwrap_or_else(|| font.y_max(font.glyph('x')));
        Some(font)
    }

    /// Apply the font's ligatures and contextual alternates to `glyphs`;
    /// `clusters` (the character each glyph starts at) follow: a ligature
    /// keeps its first component's.
    pub fn substitute(&self, glyphs: &mut Vec<u16>, clusters: &mut Vec<usize>) {
        let Some((list, lookups)) = &self.gsub else { return };
        for &l in lookups {
            let mut i = 0;
            while i < glyphs.len() {
                apply_lookup(self.data, *list, l, glyphs, clusters, i, 0);
                i += 1;
            }
        }
    }

    /// The glyph for `c` (0, the missing glyph, if none).
    pub fn glyph(&self, c: char) -> u16 {
        let Some((at, format)) = self.cmap else { return 0 };
        let d = self.data;
        let c = c as u32;
        let r = match format {
            4 => cmap4(d, at, c),
            12 => cmap12(d, at, c),
            _ => None,
        };
        r.unwrap_or(0)
    }

    /// The top of glyph `g`'s bounding box (glyf yMax; 0 if empty).
    fn y_max(&self, g: u16) -> i16 {
        let d = self.data;
        let start = if self.loca_long {
            d.u32(self.loca + 4 * g as usize).map(|v| v as usize)
        } else {
            d.u16(self.loca + 2 * g as usize).map(|v| v as usize * 2)
        };
        start.and_then(|s| d.i16(self.glyf + s + 8)).unwrap_or(0)
    }

    /// The advance width of glyph `g` (font units).
    pub fn advance(&self, g: u16) -> u16 {
        let n = self.num_hmetrics.max(1);
        let i = g.min(n - 1) as usize;
        self.data.u16(self.hmtx + 4 * i).unwrap_or(0)
    }

    /// The kerning adjustment between glyphs `left` and `right` (font
    /// units; usually negative).
    pub fn kerning(&self, left: u16, right: u16) -> i16 {
        for &st in &self.kern {
            if let Some(v) = pair_value(self.data, st, left, right) {
                return v;
            }
        }
        0
    }

    /// Glyph `g`'s outline, scaled by `scale` (pixels per font unit) with
    /// its origin (baseline, left) at (x, y) in pixels, y growing down.
    pub fn outline(&self, g: u16, scale: f32, x: f32, y: f32) -> Path {
        self.outline_slanted(g, scale, x, y, 0.0)
    }

    /// As [`Font::outline`], leaning right by `slant` (the shear, x per y;
    /// an oblique made from the upright design).
    pub fn outline_slanted(&self, g: u16, scale: f32, x: f32, y: f32, slant: f32) -> Path {
        self.outline_scaled(g, (scale, scale), x, y, slant)
    }

    /// As [`Font::outline_slanted`], with separate horizontal and vertical
    /// scales (hinting stretches heights alone).
    pub fn outline_scaled(&self, g: u16, (sx, sy): (f32, f32), x: f32, y: f32, slant: f32) -> Path {
        let mut contours = Vec::new();
        self.contours(g, &mut contours, 0);
        let mut p = Path::new();
        for c in &contours {
            add_contour(&mut p, c, |pt| (x + (pt.x + slant * pt.y) * sx, y - pt.y * sy));
        }
        p
    }

    /// The contours of glyph `g` in font units (composites resolved).
    fn contours(&self, g: u16, out: &mut Vec<Vec<Point>>, depth: u32) {
        if depth > 8 || g >= self.num_glyphs {
            return;
        }
        let d = self.data;
        let (start, end) = if self.loca_long {
            let o = self.loca + 4 * g as usize;
            (d.u32(o).unwrap_or(0) as usize, d.u32(o + 4).unwrap_or(0) as usize)
        } else {
            let o = self.loca + 2 * g as usize;
            (d.u16(o).unwrap_or(0) as usize * 2, d.u16(o + 2).unwrap_or(0) as usize * 2)
        };
        if end <= start {
            return; // An empty glyph (a space).
        }
        let at = self.glyf + start;
        let Some(n) = d.i16(at) else { return };
        if n >= 0 {
            if let Some(cs) = simple_glyph(d, at, n as usize) {
                out.extend(cs);
            }
        } else {
            self.composite(at + 10, out, depth);
        }
    }

    /// A composite glyph's components, each transformed.
    fn composite(&self, mut at: usize, out: &mut Vec<Vec<Point>>, depth: u32) {
        const ARG_WORDS: u16 = 0x0001;
        const ARGS_XY: u16 = 0x0002;
        const SCALE: u16 = 0x0008;
        const MORE: u16 = 0x0020;
        const XY_SCALE: u16 = 0x0040;
        const TWO_BY_TWO: u16 = 0x0080;
        let d = self.data;
        loop {
            let (Some(flags), Some(glyph)) = (d.u16(at), d.u16(at + 2)) else { return };
            at += 4;
            let (dx, dy) = if flags & ARG_WORDS != 0 {
                let r = (d.i16(at).unwrap_or(0), d.i16(at + 2).unwrap_or(0));
                at += 4;
                (r.0 as f32, r.1 as f32)
            } else {
                let r = (d.u8(at).unwrap_or(0) as i8, d.u8(at + 1).unwrap_or(0) as i8);
                at += 2;
                (r.0 as f32, r.1 as f32)
            };
            // F2DOT14 numbers.
            let f2 = |o: usize| d.i16(o).unwrap_or(0) as f32 / 16384.0;
            let (mut a, mut b, mut c, mut e) = (1.0, 0.0, 0.0, 1.0);
            if flags & SCALE != 0 {
                a = f2(at);
                e = a;
                at += 2;
            } else if flags & XY_SCALE != 0 {
                a = f2(at);
                e = f2(at + 2);
                at += 4;
            } else if flags & TWO_BY_TWO != 0 {
                (a, b, c, e) = (f2(at), f2(at + 2), f2(at + 4), f2(at + 6));
                at += 8;
            }
            let mut parts = Vec::new();
            self.contours(glyph, &mut parts, depth + 1);
            // Point-matching placement (ARGS_XY clear) is rare and not
            // supported: the component is placed at its own origin.
            let (dx, dy) = if flags & ARGS_XY != 0 { (dx, dy) } else { (0.0, 0.0) };
            for mut contour in parts {
                for p in &mut contour {
                    let (x, y) = (p.x, p.y);
                    p.x = a * x + c * y + dx;
                    p.y = b * x + e * y + dy;
                }
                out.push(contour);
            }
            if flags & MORE == 0 {
                return;
            }
        }
    }
}

/// A simple glyph's contours (glyf, "Simple Glyph Description").
fn simple_glyph(d: Data<'_>, at: usize, n: usize) -> Option<Vec<Vec<Point>>> {
    const ON: u8 = 0x01;
    const X_SHORT: u8 = 0x02;
    const Y_SHORT: u8 = 0x04;
    const REPEAT: u8 = 0x08;
    const X_SAME: u8 = 0x10;
    const Y_SAME: u8 = 0x20;
    let mut ends = Vec::with_capacity(n);
    for i in 0..n {
        ends.push(d.u16(at + 10 + 2 * i)? as usize);
    }
    let count = ends.last().map_or(0, |&e| e + 1);
    let ins = d.u16(at + 10 + 2 * n)? as usize;
    let mut p = at + 12 + 2 * n + ins;
    let mut flags = Vec::with_capacity(count);
    while flags.len() < count {
        let f = d.u8(p)?;
        p += 1;
        flags.push(f);
        if f & REPEAT != 0 {
            let r = d.u8(p)?;
            p += 1;
            for _ in 0..r {
                flags.push(f);
            }
        }
    }
    flags.truncate(count);
    let mut coords = |short: u8, same: u8| -> Option<Vec<i32>> {
        let mut v = Vec::with_capacity(count);
        let mut cur = 0i32;
        for &f in &flags {
            if f & short != 0 {
                let b = d.u8(p)? as i32;
                p += 1;
                cur += if f & same != 0 { b } else { -b };
            } else if f & same == 0 {
                cur += d.i16(p)? as i32;
                p += 2;
            }
            v.push(cur);
        }
        Some(v)
    };
    let xs = coords(X_SHORT, X_SAME)?;
    let ys = coords(Y_SHORT, Y_SAME)?;
    let mut out = Vec::with_capacity(n);
    let mut start = 0;
    for &e in &ends {
        if e < start || e >= count {
            return None;
        }
        out.push((start..=e).map(|i| Point { x: xs[i] as f32, y: ys[i] as f32, on: flags[i] & ON != 0 }).collect());
        start = e + 1;
    }
    Some(out)
}

/// Add a TrueType contour (quadratic B-spline: two off-curve points in a
/// row imply an on-curve point between them) to `p`.
fn add_contour(p: &mut Path, c: &[Point], map: impl Fn(&Point) -> (f32, f32)) {
    if c.is_empty() {
        return;
    }
    let mid = |a: &Point, b: &Point| Point { x: (a.x + b.x) * 0.5, y: (a.y + b.y) * 0.5, on: true };
    // Start on an on-curve point, or between the first two off-curve ones.
    let first = match c.iter().position(|q| q.on) {
        Some(i) => c[i],
        None => mid(&c[0], &c[1 % c.len()]),
    };
    let start_index = c.iter().position(|q| q.on).map_or(0, |i| i + 1);
    let (x, y) = map(&first);
    p.move_to(x, y);
    let mut pending: Option<Point> = None;
    for k in 0..c.len() {
        let q = c[(start_index + k) % c.len()];
        if q.on {
            match pending.take() {
                Some(ctrl) => {
                    let (cx, cy) = map(&ctrl);
                    let (x, y) = map(&q);
                    p.quad_to(cx, cy, x, y);
                }
                None => {
                    let (x, y) = map(&q);
                    p.line_to(x, y);
                }
            }
        } else {
            if let Some(ctrl) = pending {
                let m = mid(&ctrl, &q);
                let (cx, cy) = map(&ctrl);
                let (x, y) = map(&m);
                p.quad_to(cx, cy, x, y);
            }
            pending = Some(q);
        }
    }
    if let Some(ctrl) = pending {
        let (cx, cy) = map(&ctrl);
        let (x, y) = map(&first);
        p.quad_to(cx, cy, x, y);
    }
    p.close();
}

/// The Unicode cmap subtable to use: (offset, format), preferring full
/// Unicode (format 12) over the BMP (format 4).
fn best_cmap(d: Data<'_>, cmap: usize) -> Option<(usize, u16)> {
    let n = d.u16(cmap + 2)? as usize;
    let mut best: Option<(usize, u16)> = None;
    for i in 0..n {
        let rec = cmap + 4 + 8 * i;
        let (platform, encoding) = (d.u16(rec)?, d.u16(rec + 2)?);
        let at = cmap + d.u32(rec + 4)? as usize;
        let unicode = platform == 0 || (platform == 3 && (encoding == 1 || encoding == 10));
        if !unicode {
            continue;
        }
        let format = d.u16(at)?;
        match format {
            12 => return Some((at, 12)),
            4 if best.is_none() => best = Some((at, 4)),
            _ => {}
        }
    }
    best
}

/// Segment mapping to delta values (format 4).
fn cmap4(d: Data<'_>, at: usize, c: u32) -> Option<u16> {
    if c > 0xFFFF {
        return None;
    }
    let segs = d.u16(at + 6)? as usize / 2;
    let ends = at + 14;
    let starts = ends + 2 * segs + 2;
    let deltas = starts + 2 * segs;
    let ranges = deltas + 2 * segs;
    for i in 0..segs {
        if c as u16 > d.u16(ends + 2 * i)? {
            continue;
        }
        let start = d.u16(starts + 2 * i)?;
        if (c as u16) < start {
            return None;
        }
        let delta = d.u16(deltas + 2 * i)?;
        let range = d.u16(ranges + 2 * i)? as usize;
        if range == 0 {
            return Some((c as u16).wrapping_add(delta));
        }
        let g = d.u16(ranges + 2 * i + range + 2 * (c as usize - start as usize))?;
        return Some(if g == 0 { 0 } else { g.wrapping_add(delta) });
    }
    None
}

/// Segmented coverage (format 12).
fn cmap12(d: Data<'_>, at: usize, c: u32) -> Option<u16> {
    let groups = d.u32(at + 12)? as usize;
    let (mut lo, mut hi) = (0, groups);
    while lo < hi {
        let mid = (lo + hi) / 2;
        let g = at + 16 + 12 * mid;
        let (start, end) = (d.u32(g)?, d.u32(g + 4)?);
        if c < start {
            hi = mid;
        } else if c > end {
            lo = mid + 1;
        } else {
            return Some((d.u32(g + 8)? + (c - start)) as u16);
        }
    }
    None
}

/// The PairPos subtables of every lookup the `kern` feature names, in
/// lookup order.
fn kern_subtables(d: Data<'_>, gpos: usize) -> Option<Vec<usize>> {
    let features = gpos + d.u16(gpos + 6)? as usize;
    let lookups = gpos + d.u16(gpos + 8)? as usize;
    let mut indices = Vec::new();
    for i in 0..d.u16(features)? as usize {
        let rec = features + 2 + 6 * i;
        if d.0.get(rec..rec + 4)? != b"kern" {
            continue;
        }
        let f = features + d.u16(rec + 4)? as usize;
        for j in 0..d.u16(f + 2)? as usize {
            let l = d.u16(f + 4 + 2 * j)?;
            if !indices.contains(&l) {
                indices.push(l);
            }
        }
    }
    indices.sort_unstable();
    let mut out = Vec::new();
    for l in indices {
        let lk = lookups + d.u16(lookups + 2 + 2 * l as usize)? as usize;
        let kind = d.u16(lk)?;
        for s in 0..d.u16(lk + 4)? as usize {
            let mut st = lk + d.u16(lk + 6 + 2 * s)? as usize;
            let mut kind = kind;
            if kind == 9 {
                // Extension: the real type, and a 32-bit offset to it.
                kind = d.u16(st + 2)?;
                st += d.u32(st + 4)? as usize;
            }
            if kind == 2 {
                out.push(st);
            }
        }
    }
    Some(out)
}

/// The number of 16-bit fields a ValueRecord of `format` has.
fn value_size(format: u16) -> usize {
    (format & 0xFF).count_ones() as usize * 2
}

/// The XAdvance (if present) of the ValueRecord at `at`.
fn x_advance(d: Data<'_>, at: usize, format: u16) -> i16 {
    if format & 0x0004 == 0 {
        return 0;
    }
    // XPlacement and YPlacement come first when present.
    let skip = (format & 0x0003).count_ones() as usize * 2;
    d.i16(at + skip).unwrap_or(0)
}

/// The adjustment a PairPos subtable gives (`left`, `right`), or None if
/// it doesn't apply to the pair (the next subtable may).
fn pair_value(d: Data<'_>, st: usize, left: u16, right: u16) -> Option<i16> {
    let format = d.u16(st)?;
    let index = coverage(d, st + d.u16(st + 2)? as usize, left)?;
    let (vf1, vf2) = (d.u16(st + 4)?, d.u16(st + 6)?);
    let (s1, s2) = (value_size(vf1), value_size(vf2));
    match format {
        1 => {
            let set = st + d.u16(st + 10 + 2 * index)? as usize;
            let n = d.u16(set)? as usize;
            let rec = 2 + s1 + s2;
            let (mut lo, mut hi) = (0, n);
            while lo < hi {
                let mid = (lo + hi) / 2;
                let r = set + 2 + rec * mid;
                let g = d.u16(r)?;
                match g.cmp(&right) {
                    core::cmp::Ordering::Less => lo = mid + 1,
                    core::cmp::Ordering::Greater => hi = mid,
                    core::cmp::Ordering::Equal => return Some(x_advance(d, r + 2, vf1)),
                }
            }
            // No pair: the subtable doesn't apply; a later one may.
            None
        }
        2 => {
            let c1 = class(d, st + d.u16(st + 8)? as usize, left);
            let c2 = class(d, st + d.u16(st + 10)? as usize, right);
            let (n1, n2) = (d.u16(st + 12)? as usize, d.u16(st + 14)? as usize);
            if c1 >= n1 || c2 >= n2 {
                return None;
            }
            let r = st + 16 + (c1 * n2 + c2) * (s1 + s2);
            Some(x_advance(d, r, vf1))
        }
        _ => None,
    }
}

/// The coverage index of `g`, if covered.
fn coverage(d: Data<'_>, at: usize, g: u16) -> Option<usize> {
    match d.u16(at)? {
        1 => {
            let n = d.u16(at + 2)? as usize;
            let (mut lo, mut hi) = (0, n);
            while lo < hi {
                let mid = (lo + hi) / 2;
                let v = d.u16(at + 4 + 2 * mid)?;
                match v.cmp(&g) {
                    core::cmp::Ordering::Less => lo = mid + 1,
                    core::cmp::Ordering::Greater => hi = mid,
                    core::cmp::Ordering::Equal => return Some(mid),
                }
            }
            None
        }
        2 => {
            for i in 0..d.u16(at + 2)? as usize {
                let r = at + 4 + 6 * i;
                let (start, end, index) = (d.u16(r)?, d.u16(r + 2)?, d.u16(r + 4)?);
                if (start..=end).contains(&g) {
                    return Some(index as usize + (g - start) as usize);
                }
            }
            None
        }
        _ => None,
    }
}

/// The class of `g` in a class definition (0 when not listed).
fn class(d: Data<'_>, at: usize, g: u16) -> usize {
    let r = || -> Option<usize> {
        match d.u16(at)? {
            1 => {
                let start = d.u16(at + 2)?;
                let n = d.u16(at + 4)?;
                if g < start || g - start >= n {
                    return Some(0);
                }
                Some(d.u16(at + 6 + 2 * (g - start) as usize)? as usize)
            }
            2 => {
                for i in 0..d.u16(at + 2)? as usize {
                    let r = at + 4 + 6 * i;
                    if (d.u16(r)?..=d.u16(r + 2)?).contains(&g) {
                        return Some(d.u16(r + 4)? as usize);
                    }
                }
                Some(0)
            }
            _ => Some(0),
        }
    };
    r().unwrap_or(0)
}

/// GSUB's lookup list, and the lookups of `liga` and `calt` in lookup
/// order (OpenType applies a feature set's lookups in that order).
fn gsub_lookups(d: Data<'_>, gsub: usize) -> Option<(usize, Vec<u16>)> {
    let features = gsub + d.u16(gsub + 6)? as usize;
    let lookups = gsub + d.u16(gsub + 8)? as usize;
    let mut indices = Vec::new();
    for i in 0..d.u16(features)? as usize {
        let rec = features + 2 + 6 * i;
        if !matches!(d.0.get(rec..rec + 4)?, b"liga" | b"calt") {
            continue;
        }
        let f = features + d.u16(rec + 4)? as usize;
        for j in 0..d.u16(f + 2)? as usize {
            let l = d.u16(f + 4 + 2 * j)?;
            if !indices.contains(&l) {
                indices.push(l);
            }
        }
    }
    indices.sort_unstable();
    Some((lookups, indices))
}

/// Lookup `l`'s type and subtables (extensions resolved).
fn subtables(d: Data<'_>, list: usize, l: u16) -> Option<(u16, Vec<usize>)> {
    let lk = list + d.u16(list + 2 + 2 * l as usize)? as usize;
    let kind = d.u16(lk)?;
    let mut out = Vec::new();
    let mut real = kind;
    for s in 0..d.u16(lk + 4)? as usize {
        let mut st = lk + d.u16(lk + 6 + 2 * s)? as usize;
        if kind == 7 {
            // Extension: the real type, and a 32-bit offset to it.
            real = d.u16(st + 2)?;
            st += d.u32(st + 4)? as usize;
        }
        out.push(st);
    }
    Some((real, out))
}

/// Apply lookup `l` at position `i` of `glyphs`; true if it substituted.
fn apply_lookup(
    d: Data<'_>,
    list: usize,
    l: u16,
    glyphs: &mut Vec<u16>,
    clusters: &mut Vec<usize>,
    i: usize,
    depth: u32,
) -> bool {
    if depth > 4 || i >= glyphs.len() {
        return false;
    }
    let Some((kind, subs)) = subtables(d, list, l) else { return false };
    for st in subs {
        let done = match kind {
            1 => single(d, st, glyphs[i]).map(|g| glyphs[i] = g).is_some(),
            4 => ligature(d, st, glyphs, clusters, i).is_some(),
            6 => chain_context(d, list, st, glyphs, clusters, i, depth).unwrap_or(false),
            _ => false,
        };
        if done {
            return true;
        }
    }
    false
}

/// A single substitution's replacement for `g`.
fn single(d: Data<'_>, st: usize, g: u16) -> Option<u16> {
    let index = coverage(d, st + d.u16(st + 2)? as usize, g)?;
    match d.u16(st)? {
        1 => Some(g.wrapping_add(d.u16(st + 4)?)),
        2 if index < d.u16(st + 4)? as usize => d.u16(st + 6 + 2 * index),
        _ => None,
    }
}

/// A ligature starting at `i`: its components become one glyph.
fn ligature(d: Data<'_>, st: usize, glyphs: &mut Vec<u16>, clusters: &mut Vec<usize>, i: usize) -> Option<()> {
    let index = coverage(d, st + d.u16(st + 2)? as usize, glyphs[i])?;
    if index >= d.u16(st + 4)? as usize {
        return None;
    }
    let set = st + d.u16(st + 6 + 2 * index)? as usize;
    for k in 0..d.u16(set)? as usize {
        let lig = set + d.u16(set + 2 + 2 * k)? as usize;
        let (glyph, count) = (d.u16(lig)?, d.u16(lig + 2)? as usize);
        if count == 0 || i + count > glyphs.len() {
            continue;
        }
        if (1..count).all(|c| d.u16(lig + 4 + 2 * (c - 1)) == Some(glyphs[i + c])) {
            glyphs.splice(i..i + count, [glyph]);
            clusters.drain(i + 1..i + count);
            return Some(());
        }
    }
    None
}

/// A chained context by coverage (format 3) at `i`: the backtrack,
/// input and lookahead sequences must match; then the nested lookups
/// apply at their input positions.
fn chain_context(
    d: Data<'_>,
    list: usize,
    st: usize,
    glyphs: &mut Vec<u16>,
    clusters: &mut Vec<usize>,
    i: usize,
    depth: u32,
) -> Option<bool> {
    if d.u16(st)? != 3 {
        return Some(false);
    }
    let mut at = st + 2;
    let nb = d.u16(at)? as usize;
    let back = at + 2;
    at = back + 2 * nb;
    let ni = d.u16(at)? as usize;
    let input = at + 2;
    at = input + 2 * ni;
    let nl = d.u16(at)? as usize;
    let ahead = at + 2;
    at = ahead + 2 * nl;
    let ns = d.u16(at)? as usize;
    let records = at + 2;
    let covers = |table: usize, k: usize, g: u16| -> Option<bool> {
        Some(coverage(d, st + d.u16(table + 2 * k)? as usize, g).is_some())
    };
    if ni == 0 || i + ni + nl > glyphs.len() || i < nb {
        return Some(false);
    }
    for k in 0..nb {
        if !covers(back, k, glyphs[i - 1 - k])? {
            return Some(false);
        }
    }
    for k in 0..ni {
        if !covers(input, k, glyphs[i + k])? {
            return Some(false);
        }
    }
    for k in 0..nl {
        if !covers(ahead, k, glyphs[i + ni + k])? {
            return Some(false);
        }
    }
    for r in 0..ns {
        let (seq, lookup) = (d.u16(records + 4 * r)? as usize, d.u16(records + 4 * r + 2)?);
        apply_lookup(d, list, lookup, glyphs, clusters, i + seq, depth + 1);
    }
    Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::Transform;

    fn load(name: &str) -> Vec<u8> {
        let path = alloc::format!("{}/../../assets/fonts/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read(path).unwrap()
    }

    // Reference values from fonttools (glyph order, hmtx, GPOS).
    #[test]
    fn host_grotesk_metrics_and_kerning() {
        let bytes = load("HostGrotesk-500.ttf");
        let f = Font::new(&bytes).unwrap();
        assert_eq!((f.units_per_em, f.ascender, f.descender), (1000, 1015, -315));
        let g = |c| f.glyph(c);
        assert_eq!([g('A'), g('V'), g('T'), g('o'), g('0'), g(' ')], [1, 22, 20, 41, 302, 323]);
        assert_eq!([f.advance(1), f.advance(22), f.advance(323)], [674, 710, 307]);
        for (pair, want) in [("AV", -116), ("To", -116), ("Wo", -76), ("yo", -46), ("LT", -106)] {
            let mut cs = pair.chars();
            let (a, b) = (cs.next().unwrap(), cs.next().unwrap());
            assert_eq!(f.kerning(g(a), g(b)), want, "{pair}");
        }
        assert_eq!(f.kerning(g('o'), g('o')), 0);
    }

    #[test]
    fn dm_mono_is_monospaced() {
        let bytes = load("DMMono-Regular.ttf");
        let f = Font::new(&bytes).unwrap();
        for (c, gid) in [('A', 1), ('V', 104), ('o', 186), ('0', 262)] {
            assert_eq!(f.glyph(c), gid);
            assert_eq!(f.advance(gid), 600);
        }
        assert_eq!(f.kerning(f.glyph('A'), f.glyph('V')), 0);
    }

    #[test]
    fn ligatures_and_contextual_alternates() {
        let bytes = load("HostGrotesk-400.ttf");
        let f = Font::new(&bytes).unwrap();
        let shape = |s: &str| {
            let mut g: Vec<u16> = s.chars().map(|c| f.glyph(c)).collect();
            let mut c: Vec<usize> = (0..g.len()).collect();
            f.substitute(&mut g, &mut c);
            (g, c)
        };
        // "fi" is one glyph, kept at the first character.
        let (g, c) = shape("fit");
        assert_eq!(g.len(), 2);
        assert_ne!(g[0], f.glyph('f'));
        assert_eq!(c, [0, 2]);
        // An x between digits becomes the multiplication sign; elsewhere not.
        let (g, _) = shape("1920x1080");
        assert_eq!(g[4], f.glyph('×'));
        assert_eq!(shape("box").0[2], f.glyph('x'));
        // DM Mono has neither.
        let mono = load("DMMono-Regular.ttf");
        let m = Font::new(&mono).unwrap();
        let mut g: Vec<u16> = "fi 2x2".chars().map(|c| m.glyph(c)).collect();
        let want = g.clone();
        m.substitute(&mut g, &mut (0..6).collect());
        assert_eq!(g, want);
    }

    #[test]
    fn outlines_fill_sensibly() {
        let bytes = load("HostGrotesk-500.ttf");
        let f = Font::new(&bytes).unwrap();
        // 'o' at 100 px: a ring (the counter is a hole); 'l' a bar.
        let m = f.outline(f.glyph('o'), 0.1, 0.0, 100.0).mask(&Transform::IDENTITY);
        let at = |m: &crate::raster::Mask, x: i32, y: i32| m.data[((y - m.y) * m.w + (x - m.x)) as usize];
        let (cx, cy) = (m.x + m.w / 2, m.y + m.h / 2);
        assert_eq!(at(&m, cx, cy), 0, "the counter is empty");
        assert_eq!(at(&m, m.x + 3, cy), 255, "the bowl is filled");
        assert!(f.outline(f.glyph(' '), 0.1, 0.0, 100.0).is_empty());
    }
}
