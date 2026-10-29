// SPDX-License-Identifier: MIT OR Apache-2.0

//! DisplayID (ADR 0157, M32 phase 1): the block structure 4K and
//! high-refresh displays describe their larger modes in, where EDID's
//! detailed timings (at most 655.35 MHz, 4095 pixels) run out. It comes
//! as an EDID extension block (tag 70h, CTA-861-I §7 and VESA DisplayID
//! 2.0 §2.2) or on its own.
//!
//! - VESA DisplayID 1.3 (2013) §2.1: the section (version, payload
//!   bytes, product type, extension count, data blocks, a checksum over
//!   the section); §4.4: the Type I detailed timing block (tag 03h).
//! - VESA DisplayID 2.0 (2017) §2.1, §4.4: the Type VII detailed timing
//!   block (tag 22h, pixel clock in 1 kHz steps) and the Type IX
//!   formula-based block (tag 24h, CVT modes named by size and rate).
//!
//! Each data block is a tag, a revision, a payload length and the payload.

use crate::Timing;
use crate::modes::{Mode, Source};
use crate::timings::{Blanking, cvt};

/// The data blocks read.
const TYPE_I: u8 = 0x03;
const TYPE_VII: u8 = 0x22;
const TYPE_IX: u8 = 0x24;

/// The modes in a DisplayID section at the start of `s` (as an EDID
/// extension, the 126 bytes after its tag). Sections that fail their
/// checksum give nothing.
pub fn modes(s: &[u8], add: &mut dyn FnMut(Mode)) {
    let Some(&len) = s.get(1) else { return };
    let Some(section) = s.get(..5 + usize::from(len)) else { return };
    if section.iter().fold(0u8, |a, &b| a.wrapping_add(b)) != 0 {
        return;
    }
    let payload = &section[4..section.len() - 1];
    let mut at = 0;
    while at + 3 <= payload.len() {
        let (tag, rev, n) = (payload[at], payload[at + 1], usize::from(payload[at + 2]));
        // Tag 0 is padding: the rest of the section is empty.
        if tag == 0 {
            break;
        }
        let Some(body) = payload.get(at + 3..at + 3 + n) else { break };
        match tag {
            TYPE_I | TYPE_VII => {
                // Type VII's descriptors may grow (revision bits 6:4 add
                // bytes to the 20); Type I's are 20.
                let size = 20 + if tag == TYPE_VII { usize::from((rev >> 4) & 7) } else { 0 };
                for d in body.chunks_exact(size) {
                    let (t, preferred) = detailed(d, if tag == TYPE_I { 10 } else { 1 });
                    add(Mode { timing: t, preferred, source: Source::DisplayId });
                }
            }
            TYPE_IX => {
                for d in body.as_chunks::<6>().0 {
                    let blanking = match d[0] & 7 {
                        0 => Blanking::Standard,
                        1 => Blanking::Reduced,
                        2 => Blanking::ReducedV2,
                        _ => continue,
                    };
                    let w = u32::from(u16::from_le_bytes([d[1], d[2]])) + 1;
                    let h = u32::from(u16::from_le_bytes([d[3], d[4]])) + 1;
                    if let Some(t) = cvt(w, h, u32::from(d[5]) + 1, blanking) {
                        add(Mode { timing: t, preferred: false, source: Source::DisplayId });
                    }
                }
            }
            _ => {}
        }
        at += 3 + n;
    }
}

/// A 20-byte Type I or Type VII descriptor: the pixel clock (three bytes,
/// in `step_khz` units, less one), an options byte (bit 7: preferred),
/// then horizontal and vertical active, blanking, sync offset (bit 15 the
/// sync polarity, set for positive) and sync width, each two bytes less
/// one.
fn detailed(d: &[u8], step_khz: u32) -> (Timing, bool) {
    let word = |i: usize| u32::from(u16::from_le_bytes([d[i], d[i + 1]]));
    let clock = (u32::from(d[0]) | u32::from(d[1]) << 8 | u32::from(d[2]) << 16) + 1;
    let (hactive, hblank) = (word(4) + 1, word(6) + 1);
    let (hoff, hsync) = ((word(8) & 0x7FFF) + 1, word(10) + 1);
    let (vactive, vblank) = (word(12) + 1, word(14) + 1);
    let (voff, vsync) = ((word(16) & 0x7FFF) + 1, word(18) + 1);
    let t = Timing {
        clock_khz: clock.saturating_mul(step_khz),
        hactive,
        hsync_start: hactive + hoff,
        hsync_end: hactive + hoff + hsync,
        htotal: hactive + hblank,
        vactive,
        vsync_start: vactive + voff,
        vsync_end: vactive + voff + vsync,
        vtotal: vactive + vblank,
        hsync_positive: word(8) & 0x8000 != 0,
        vsync_positive: word(16) & 0x8000 != 0,
    };
    (t, d[3] & 0x80 != 0)
}

/// A Type VII descriptor for `t` (for tests and for cards that make
/// their own DisplayID): the inverse of [`detailed`] at 1 kHz.
pub fn type_vii(t: &Timing, preferred: bool) -> [u8; 20] {
    let mut d = [0u8; 20];
    let c = t.clock_khz.saturating_sub(1);
    d[..3].copy_from_slice(&c.to_le_bytes()[..3]);
    d[3] = u8::from(preferred) << 7;
    let mut put = |i: usize, v: u32| d[i..i + 2].copy_from_slice(&((v - 1) as u16).to_le_bytes());
    put(4, t.hactive);
    put(6, t.htotal - t.hactive);
    put(8, t.hsync_start - t.hactive);
    put(10, t.hsync_end - t.hsync_start);
    put(12, t.vactive);
    put(14, t.vtotal - t.vactive);
    put(16, t.vsync_start - t.vactive);
    put(18, t.vsync_end - t.vsync_start);
    d[9] |= u8::from(t.hsync_positive) << 7;
    d[17] |= u8::from(t.vsync_positive) << 7;
    d
}
