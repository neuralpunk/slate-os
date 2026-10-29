// SPDX-License-Identifier: MIT OR Apache-2.0

//! EDID (ADR 0100): the 128-byte base block a display describes itself
//! with, as the VESA Enhanced EDID standard (release A, revision 2: EDID
//! 1.4) lays it out. Slate's DRM cards that have no EDID of their own (the
//! firmware framebuffer, a virtio-gpu without one) give compositors one
//! made here, naming the display and its preferred mode; [`parse`] reads
//! those back from any base block. [`read`] reads every mode a display
//! offers, from its extensions too (CTA-861, DisplayID), and [`timings`]
//! has the formulas and tables behind modes named only by size and rate
//! (ADR 0157).

#![no_std]

#[cfg(test)]
extern crate std;

pub mod displayid;
pub mod modes;
pub mod timings;

pub use modes::{Info, Limits, Mode, Source, read};

/// What a block says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Display<'a> {
    /// Three letters (A to Z): the manufacturer's PNP ID.
    pub vendor: [u8; 3],
    pub product: u16,
    pub serial: u32,
    /// The model year (the block holds it from 1990).
    pub year: u16,
    /// The name, at most 13 characters.
    pub name: &'a str,
    /// Physical size in millimetres (0 if unknown).
    pub size_mm: (u32, u32),
    pub timing: Timing,
}

/// A detailed timing (the preferred mode), in pixels and lines.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timing {
    /// Pixel clock in kHz (stored in 10 kHz steps).
    pub clock_khz: u32,
    pub hactive: u32,
    pub hsync_start: u32,
    pub hsync_end: u32,
    pub htotal: u32,
    pub vactive: u32,
    pub vsync_start: u32,
    pub vsync_end: u32,
    pub vtotal: u32,
    /// Sync polarities: true for positive.
    pub hsync_positive: bool,
    pub vsync_positive: bool,
}

impl Timing {
    /// The refresh rate in Hz, rounded.
    pub fn refresh(&self) -> u32 {
        let frame = u64::from(self.htotal) * u64::from(self.vtotal);
        (u64::from(self.clock_khz) * 1000 + frame / 2).checked_div(frame).unwrap_or(0) as u32
    }
}

const HEADER: [u8; 8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

/// sRGB's primaries and white point (IEC 61966-2-1) as 10-bit fractions:
/// red, green, blue, white, each x then y.
const SRGB: [u16; 8] = [655, 338, 307, 614, 154, 61, 320, 337];

/// The base block for `d`.
pub fn build(d: &Display<'_>) -> [u8; 128] {
    let mut e = [0u8; 128];
    e[..8].copy_from_slice(&HEADER);
    // The PNP ID: three 5-bit letters (A = 1), big-endian.
    let letter = |c: u8| u16::from(c.saturating_sub(b'A' - 1) & 0x1F);
    let id = (letter(d.vendor[0]) << 10) | (letter(d.vendor[1]) << 5) | letter(d.vendor[2]);
    e[8..10].copy_from_slice(&id.to_be_bytes());
    e[10..12].copy_from_slice(&d.product.to_le_bytes());
    e[12..16].copy_from_slice(&d.serial.to_le_bytes());
    // No week; the model year (week 0xFF marks it a model year).
    e[16] = 0xFF;
    e[17] = d.year.saturating_sub(1990).min(255) as u8;
    (e[18], e[19]) = (1, 4);
    // A digital input, colour depth and interface not given.
    e[20] = 0x80;
    // Size in centimetres; a gamma of 2.2 (stored as 100 × gamma − 100).
    e[21] = (d.size_mm.0 / 10).min(255) as u8;
    e[22] = (d.size_mm.1 / 10).min(255) as u8;
    e[23] = 120;
    // Features: sRGB is the default colour space, and the first detailed
    // timing is the preferred, native mode; RGB 4:4:4.
    e[24] = 0x06;
    // Chromaticity: the low two bits of each, then the high eight.
    let lo = |i: usize| (SRGB[i] & 3) as u8;
    e[25] = (lo(0) << 6) | (lo(1) << 4) | (lo(2) << 2) | lo(3);
    e[26] = (lo(4) << 6) | (lo(5) << 4) | (lo(6) << 2) | lo(7);
    for (i, v) in SRGB.iter().enumerate() {
        e[27 + i] = (v >> 2) as u8;
    }
    // No established timings; standard timings unused (01 01).
    for i in 0..8 {
        e[38 + 2 * i] = 1;
        e[39 + 2 * i] = 1;
    }
    timing(&mut e[54..72], &d.timing, d.size_mm);
    text(&mut e[72..90], 0xFC, d.name);
    // A dummy descriptor (tag 10h), then the serial number as text.
    e[90 + 3] = 0x10;
    let mut serial = [0u8; 10];
    text(&mut e[108..126], 0xFF, decimal(d.serial, &mut serial));
    // No extensions; the checksum makes the block sum to 0.
    e[126] = 0;
    let sum = e[..127].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    e[127] = 0u8.wrapping_sub(sum);
    e
}

fn decimal(mut v: u32, buf: &mut [u8; 10]) -> &str {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    core::str::from_utf8(&buf[i..]).unwrap_or("0")
}

/// An 18-byte detailed timing descriptor.
fn timing(b: &mut [u8], t: &Timing, size_mm: (u32, u32)) {
    let clock = (t.clock_khz / 10).min(0xFFFF) as u16;
    b[0..2].copy_from_slice(&clock.to_le_bytes());
    let hblank = t.htotal - t.hactive;
    let vblank = t.vtotal - t.vactive;
    let (hso, hsw) = (t.hsync_start - t.hactive, t.hsync_end - t.hsync_start);
    let (vso, vsw) = (t.vsync_start - t.vactive, t.vsync_end - t.vsync_start);
    b[2] = t.hactive as u8;
    b[3] = hblank as u8;
    b[4] = (((t.hactive >> 8) & 0xF) << 4 | ((hblank >> 8) & 0xF)) as u8;
    b[5] = t.vactive as u8;
    b[6] = vblank as u8;
    b[7] = (((t.vactive >> 8) & 0xF) << 4 | ((vblank >> 8) & 0xF)) as u8;
    b[8] = hso as u8;
    b[9] = hsw as u8;
    b[10] = (((vso & 0xF) << 4) | (vsw & 0xF)) as u8;
    b[11] = ((((hso >> 8) & 3) << 6) | (((hsw >> 8) & 3) << 4) | (((vso >> 4) & 3) << 2) | ((vsw >> 4) & 3)) as u8;
    let (w, h) = (size_mm.0.min(0xFFF), size_mm.1.min(0xFFF));
    b[12] = w as u8;
    b[13] = h as u8;
    b[14] = (((w >> 8) << 4) | (h >> 8)) as u8;
    // No borders; digital separate sync with its polarities.
    b[17] = 0x18 | (u8::from(t.vsync_positive) << 2) | (u8::from(t.hsync_positive) << 1);
}

/// A display descriptor holding up to 13 characters of text: ended by a
/// line feed and padded with spaces.
fn text(b: &mut [u8], tag: u8, s: &str) {
    b[3] = tag;
    let s = &s.as_bytes()[..s.len().min(13)];
    b[5..5 + s.len()].copy_from_slice(s);
    if s.len() < 13 {
        b[5 + s.len()] = 0x0A;
        b[6 + s.len()..18].fill(0x20);
    }
}

/// What [`parse`] finds in a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parsed {
    pub vendor: [u8; 3],
    pub product: u16,
    /// The display name's bytes (`name_len` of them).
    pub name: [u8; 13],
    pub name_len: usize,
    pub size_mm: (u32, u32),
    /// The first detailed timing (the preferred mode), if any.
    pub preferred: Option<Timing>,
}

/// Read a base block: None if it is too short, lacks the header or its
/// checksum is wrong.
pub fn parse(e: &[u8]) -> Option<Parsed> {
    if e.len() < 128 || e[..8] != HEADER || e[..128].iter().fold(0u8, |a, &b| a.wrapping_add(b)) != 0 {
        return None;
    }
    let id = u16::from_be_bytes([e[8], e[9]]);
    let letter = |v: u16| b'A' - 1 + (v & 0x1F) as u8;
    let mut p = Parsed {
        vendor: [letter(id >> 10), letter(id >> 5), letter(id)],
        product: u16::from_le_bytes([e[10], e[11]]),
        name: [0; 13],
        name_len: 0,
        size_mm: (u32::from(e[21]) * 10, u32::from(e[22]) * 10),
        preferred: None,
    };
    for d in e[54..126].chunks(18) {
        if d[0] != 0 || d[1] != 0 {
            if p.preferred.is_none() {
                p.preferred = Some(read_timing(d));
                let (w, h) =
                    (u32::from(d[12]) | (u32::from(d[14] >> 4) << 8), u32::from(d[13]) | (u32::from(d[14] & 0xF) << 8));
                if w > 0 && h > 0 {
                    p.size_mm = (w, h);
                }
            }
        } else if d[3] == 0xFC {
            let t = &d[5..18];
            let n = t.iter().position(|&c| c == 0x0A).unwrap_or(13);
            p.name[..n].copy_from_slice(&t[..n]);
            p.name_len = n;
        }
    }
    Some(p)
}

pub(crate) fn read_timing(b: &[u8]) -> Timing {
    let hactive = u32::from(b[2]) | (u32::from(b[4] >> 4) << 8);
    let hblank = u32::from(b[3]) | (u32::from(b[4] & 0xF) << 8);
    let vactive = u32::from(b[5]) | (u32::from(b[7] >> 4) << 8);
    let vblank = u32::from(b[6]) | (u32::from(b[7] & 0xF) << 8);
    let hso = u32::from(b[8]) | (u32::from(b[11] >> 6) << 8);
    let hsw = u32::from(b[9]) | (u32::from((b[11] >> 4) & 3) << 8);
    let vso = u32::from(b[10] >> 4) | (u32::from((b[11] >> 2) & 3) << 4);
    let vsw = u32::from(b[10] & 0xF) | (u32::from(b[11] & 3) << 4);
    Timing {
        clock_khz: u32::from(u16::from_le_bytes([b[0], b[1]])) * 10,
        hactive,
        hsync_start: hactive + hso,
        hsync_end: hactive + hso + hsw,
        htotal: hactive + hblank,
        vactive,
        vsync_start: vactive + vso,
        vsync_end: vactive + vso + vsw,
        vtotal: vactive + vblank,
        hsync_positive: b[17] & 2 != 0,
        vsync_positive: b[17] & 4 != 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn display() -> Display<'static> {
        Display {
            vendor: *b"SLT",
            product: 2,
            serial: 1234,
            year: 2026,
            name: "virtio-gpu 1",
            size_mm: (339, 212),
            timing: Timing {
                clock_khz: 83_460,
                hactive: 1280,
                hsync_start: 1328,
                hsync_end: 1360,
                htotal: 1440,
                vactive: 800,
                vsync_start: 803,
                vsync_end: 809,
                vtotal: 830,
                hsync_positive: false,
                vsync_positive: false,
            },
        }
    }

    #[test]
    fn a_block_reads_back() {
        let e = build(&display());
        assert_eq!(&e[..8], &HEADER);
        assert_eq!(e.iter().fold(0u8, |a, &b| a.wrapping_add(b)), 0);
        // "SLT" packs as 0x4D94; EDID 1.4; 2026 is 36 after 1990.
        assert_eq!((e[8], e[9], e[18], e[19], e[17]), (0x4D, 0x94, 1, 4, 36));
        let p = parse(&e).unwrap();
        assert_eq!(&p.vendor, b"SLT");
        assert_eq!(&p.name[..p.name_len], b"virtio-gpu 1");
        assert_eq!(p.size_mm, (339, 212));
        assert_eq!(p.preferred, Some(display().timing));
        assert_eq!(p.preferred.unwrap().refresh(), 70);
        // A broken checksum or header is refused.
        let mut bad = e;
        bad[60] ^= 1;
        assert_eq!(parse(&bad), None);
        assert_eq!(parse(&e[..100]), None);
    }

    #[test]
    fn large_modes_and_long_names() {
        let mut d = display();
        d.name = "a name longer than thirteen";
        d.timing = Timing {
            clock_khz: 533_250,
            hactive: 3840,
            hsync_start: 3888,
            hsync_end: 3920,
            htotal: 4000,
            vactive: 2160,
            vsync_start: 2163,
            vsync_end: 2168,
            vtotal: 2222,
            hsync_positive: true,
            vsync_positive: false,
        };
        let p = parse(&build(&d)).unwrap();
        assert_eq!(p.preferred, Some(d.timing));
        assert_eq!(&p.name[..p.name_len], b"a name longer");
        assert_eq!(p.preferred.unwrap().refresh(), 60);
    }
}
