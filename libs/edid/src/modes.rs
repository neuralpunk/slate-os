// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every mode a display offers (ADR 0157, M32 phase 1), from its base
//! block and its extensions:
//!
//! - the base block (VESA E-EDID release A revision 2, EDID 1.4): the
//!   detailed timings (§3.10.2), the established timings (§3.8), the
//!   standard timings (§3.9) and the range limits descriptor (§3.10.3.3);
//! - CTA-861 extensions (CTA-861-I §7.3): their detailed timings, the
//!   short video descriptors' VICs (§7.5.1), the HDMI vendor-specific
//!   data block's and the HDMI Forum's maximum TMDS rates (HDMI 1.4b
//!   §8.3.2, HDMI 2.1 §10.3.2);
//! - DisplayID sections, in an extension block (tag 70h) or on their own
//!   ([`crate::displayid`]).
//!
//! A display's block count is in byte 126 of the base block; each
//! extension is 128 bytes with its own checksum. Blocks that fail it are
//! skipped, not trusted.

use crate::timings::{Blanking, ESTABLISHED, cvt, dmt, gtf, vic};
use crate::{Timing, displayid, read_timing};

/// Where a mode came from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Source {
    #[default]
    Detailed,
    Established,
    Standard,
    Cta,
    DisplayId,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Mode {
    pub timing: Timing,
    /// The display's preferred (native) mode.
    pub preferred: bool,
    pub source: Source,
}

/// The range limits descriptor (tag FDh).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    pub min_vhz: u32,
    pub max_vhz: u32,
    pub min_hkhz: u32,
    pub max_hkhz: u32,
    /// The largest pixel clock in kHz (0 if not given).
    pub max_clock_khz: u32,
    /// Byte 10 is 04h: the display wants CVT for modes the EDID names
    /// without timings (GTF otherwise)...
    pub cvt: bool,
    /// ... and prefers reduced blanking.
    pub cvt_reduced: bool,
}

/// The most modes kept (more are dropped, the earlier blocks' first).
pub const MAX_MODES: usize = 64;

/// What a display's blocks say.
#[derive(Clone, Copy, Debug)]
pub struct Info {
    pub base: crate::Parsed,
    modes: [Mode; MAX_MODES],
    len: usize,
    pub limits: Option<Limits>,
    /// The HDMI vendor-specific data block's maximum TMDS clock (kHz),
    /// raised by the HDMI Forum's block; None for a display without HDMI.
    pub hdmi_max_tmds_khz: Option<u32>,
    /// How many extension blocks were read (good checksums) and skipped.
    pub extensions: (u8, u8),
}

impl Info {
    pub fn modes(&self) -> &[Mode] {
        &self.modes[..self.len]
    }

    /// The preferred mode: the first one marked so, else the first mode.
    pub fn preferred(&self) -> Option<&Mode> {
        self.modes().iter().find(|m| m.preferred).or(self.modes().first())
    }

    /// The fastest mode at a size, if the display has that size.
    pub fn fastest(&self, w: u32, h: u32) -> Option<&Mode> {
        self.modes()
            .iter()
            .filter(|m| m.timing.hactive == w && m.timing.vactive == h)
            .max_by_key(|m| m.timing.refresh())
    }

    /// Add a mode once; only the first preferred one stays preferred.
    pub(crate) fn push(&mut self, mut m: Mode) {
        m.preferred &= !self.modes().iter().any(|h| h.preferred);
        if let Some(have) = self.modes[..self.len].iter_mut().find(|h| h.timing == m.timing) {
            have.preferred |= m.preferred;
            return;
        }
        if self.len < MAX_MODES && m.timing.hactive > 0 && m.timing.vactive > 0 && m.timing.clock_khz > 0 {
            self.modes[self.len] = m;
            self.len += 1;
        }
    }
}

fn sums_to_zero(b: &[u8]) -> bool {
    b.iter().fold(0u8, |a, &v| a.wrapping_add(v)) == 0
}

/// Read a display's EDID: the base block and any extensions after it.
/// None if the base block is bad.
pub fn read(e: &[u8]) -> Option<Info> {
    let base = crate::parse(e)?;
    let mut info = Info {
        base,
        modes: [Mode::default(); MAX_MODES],
        len: 0,
        limits: None,
        hdmi_max_tmds_khz: None,
        extensions: (0, 0),
    };
    base_modes(&e[..128], &mut info);
    let count = usize::from(e[126]);
    for i in 1..=count {
        let Some(b) = e.get(i * 128..(i + 1) * 128) else { break };
        if !sums_to_zero(b) {
            info.extensions.1 += 1;
            continue;
        }
        match b[0] {
            0x02 => cta(b, &mut info),
            0x70 => displayid::modes(&b[1..127], &mut |m| info.push(m)),
            _ => {
                info.extensions.1 += 1;
                continue;
            }
        }
        info.extensions.0 += 1;
    }
    Some(info)
}

fn base_modes(e: &[u8], info: &mut Info) {
    // The range limits first: the standard timings without DMT entries
    // follow what it says.
    let rev = e[19];
    for d in e[54..126].chunks(18) {
        if d[..3] == [0, 0, 0] && d[3] == 0xFD {
            // EDID 1.4: byte 4's offsets add 255 to the rates.
            let (vmin, vmax) = (u32::from(d[4] & 3 == 3) * 255, u32::from(d[4] & 2 != 0) * 255);
            let (hmin, hmax) = (u32::from(d[4] & 0xC == 0xC) * 255, u32::from(d[4] & 8 != 0) * 255);
            info.limits = Some(Limits {
                min_vhz: u32::from(d[5]) + vmin,
                max_vhz: u32::from(d[6]) + vmax,
                min_hkhz: u32::from(d[7]) + hmin,
                max_hkhz: u32::from(d[8]) + hmax,
                max_clock_khz: u32::from(d[9]) * 10_000,
                // CVT support information: byte 15 bit 4, reduced blanking preferred.
                cvt: d[10] == 0x04,
                cvt_reduced: d[10] == 0x04 && d[15] & 0x10 != 0,
            });
        }
    }
    let mut first = true;
    for d in e[54..126].chunks(18) {
        if d[0] != 0 || d[1] != 0 {
            // EDID 1.4: the first detailed timing is the preferred mode.
            info.push(Mode { timing: read_timing(d), preferred: first, source: Source::Detailed });
            first = false;
        }
    }
    for (i, mode) in ESTABLISHED.iter().enumerate() {
        let (byte, bit) = (35 + i / 8, 7 - i % 8);
        if let Some((w, h, hz)) = mode
            && e[byte] >> bit & 1 != 0
            && let Some(t) = dmt(*w, *h, *hz)
        {
            info.push(Mode { timing: t, preferred: false, source: Source::Established });
        }
    }
    let formula = match info.limits {
        Some(l) if l.cvt && l.cvt_reduced => Formula::Cvt(Blanking::Reduced),
        Some(l) if l.cvt => Formula::Cvt(Blanking::Standard),
        _ => Formula::Gtf,
    };
    for s in e[38..54].chunks(2) {
        if let Some(t) = standard(s[0], s[1], rev, formula) {
            info.push(Mode { timing: t, preferred: false, source: Source::Standard });
        }
    }
}

#[derive(Clone, Copy)]
enum Formula {
    Gtf,
    Cvt(Blanking),
}

/// A standard timing (EDID 1.4 §3.9): two bytes, 01 01 when unused. The
/// mode is DMT's when DMT has it, else the formula's: CVT where the range
/// limits ask for it, GTF otherwise.
fn standard(a: u8, b: u8, rev: u8, formula: Formula) -> Option<Timing> {
    if (a, b) == (1, 1) || a == 0 {
        return None;
    }
    let w = (u32::from(a) + 31) * 8;
    // The aspect ratio: 16:10 (1:1 before EDID 1.3), 4:3, 5:4, 16:9.
    let h = match b >> 6 {
        0 if rev < 3 => w,
        0 => w * 10 / 16,
        1 => w * 3 / 4,
        2 => w * 4 / 5,
        _ => w * 9 / 16,
    };
    let hz = u32::from(b & 0x3F) + 60;
    dmt(w, h, hz).or_else(|| match formula {
        Formula::Gtf => gtf(w, h, hz),
        Formula::Cvt(b) => cvt(w, h, hz, b),
    })
}

/// A CTA-861 extension (CTA-861-I §7.3, Table 41): byte 2 is where the
/// detailed timings start (data blocks before it, from byte 4), byte 3's
/// low four bits how many of them are native.
fn cta(b: &[u8], info: &mut Info) {
    let dtd_at = usize::from(b[2]).min(127);
    if b[1] >= 3 && dtd_at >= 4 {
        let mut at = 4;
        while at < dtd_at {
            let (tag, len) = (b[at] >> 5, usize::from(b[at] & 0x1F));
            let Some(body) = b.get(at + 1..at + 1 + len).filter(|_| at + 1 + len <= dtd_at) else { break };
            match tag {
                // A video data block: short video descriptors (§7.5.1).
                2 => {
                    for &svd in body {
                        // VICs 1 to 64 carry a native flag in bit 7; from
                        // 65 the whole byte is the VIC (CTA-861-F on).
                        let (code, native) = if (129..=192).contains(&svd) { (svd & 0x7F, true) } else { (svd, false) };
                        if let Some(t) = vic(code) {
                            info.push(Mode { timing: t, preferred: native, source: Source::Cta });
                        }
                    }
                }
                // Vendor-specific: HDMI Licensing's OUI 00-0C-03 (its byte 7
                // the maximum TMDS clock in 5 MHz steps), the HDMI Forum's
                // C4-5D-D8 (its byte 5 the maximum TMDS character rate).
                3 if body.len() >= 3 => {
                    let oui = [body[2], body[1], body[0]];
                    if oui == [0x00, 0x0C, 0x03] {
                        let max = body.get(6).map_or(0, |&v| u32::from(v) * 5000);
                        let have = info.hdmi_max_tmds_khz.unwrap_or(0);
                        info.hdmi_max_tmds_khz = Some(have.max(if max > 0 { max } else { 165_000 }));
                    } else if oui == [0xC4, 0x5D, 0xD8] && body.len() >= 5 {
                        let max = u32::from(body[4]) * 5000;
                        info.hdmi_max_tmds_khz = Some(info.hdmi_max_tmds_khz.unwrap_or(0).max(max));
                    }
                }
                _ => {}
            }
            at += 1 + len;
        }
    }
    let mut at = dtd_at.max(4);
    while at + 18 <= 127 {
        let d = &b[at..at + 18];
        if d[0] == 0 && d[1] == 0 {
            break;
        }
        info.push(Mode { timing: read_timing(d), preferred: false, source: Source::Detailed });
        at += 18;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::displayid::type_vii;
    use std::vec::Vec;

    fn checksum(b: &mut [u8]) {
        let sum = b[..127].iter().fold(0u8, |a, &v| a.wrapping_add(v));
        b[127] = 0u8.wrapping_sub(sum);
    }

    /// A display with every kind of block: the base block's established
    /// and standard timings and range limits, a CTA-861 extension (VICs,
    /// HDMI's and the HDMI Forum's blocks, a detailed timing), a
    /// DisplayID 2.0 extension (Type VII, Type IX) and a DisplayID 1.3 one
    /// (Type I). `SLATE_EDID_OUT=FILE` saves it, to compare with
    /// edid-decode.
    fn crafted() -> Vec<u8> {
        let mut base = crate::build(&crate::Display {
            vendor: *b"SLT",
            product: 7,
            serial: 1,
            year: 2026,
            name: "crafted",
            size_mm: (600, 340),
            timing: crate::timings::cvt(3840, 2160, 60, Blanking::Reduced).unwrap(),
        });
        // Every established timing.
        (base[35], base[36], base[37]) = (0xFF, 0xFF, 0x80);
        // Standard timings: 1920x1200@60, 1280x720@60, 1600x1200@60 (DMT)
        // and 2048x1536@60 (CVT).
        base[38..46].copy_from_slice(&[0xD1, 0x00, 0x81, 0xC0, 0xA9, 0x40, 0xE1, 0x40]);
        // Range limits instead of the dummy descriptor: 48–144 Hz, 30–160 kHz,
        // 600 MHz, range limits only.
        let mut r = [0u8; 18];
        r[3] = 0xFD;
        r[5..11].copy_from_slice(&[48, 144, 30, 160, 60, 0x01]);
        r[11] = 0x0A;
        r[12..18].fill(0x20);
        base[90..108].copy_from_slice(&r);
        base[126] = 3;
        checksum(&mut base);

        let mut cta = [0u8; 128];
        (cta[0], cta[1], cta[3]) = (0x02, 0x03, 0xF0);
        let mut blocks = Vec::new();
        // Video: VIC 16 (native), 97, 118, 5 (interlaced: not kept), 63.
        blocks.extend_from_slice(&[0x40 | 5, 0x80 | 16, 97, 118, 5, 63]);
        // HDMI's VSDB: 00-0C-03, physical address 1.0.0.0, flags, 300 MHz.
        blocks.extend_from_slice(&[0x60 | 7, 0x03, 0x0C, 0x00, 0x10, 0x00, 0x00, 60]);
        // The HDMI Forum's: C4-5D-D8, version 1, 600 MHz, SCDC.
        blocks.extend_from_slice(&[0x60 | 7, 0xD8, 0x5D, 0xC4, 0x01, 120, 0x80, 0x00]);
        cta[4..4 + blocks.len()].copy_from_slice(&blocks);
        cta[2] = (4 + blocks.len()) as u8;
        let mut d = [0u8; 128];
        crate::timing(&mut d[..18], &crate::timings::vic(64).unwrap(), (600, 340));
        let at = usize::from(cta[2]);
        cta[at..at + 18].copy_from_slice(&d[..18]);
        checksum(&mut cta);

        // DisplayID 2.0: Type VII for 3840x2160 at 144 Hz (CVT-RB2, over
        // EDID's 655 MHz), Type IX for 5120x1440 at 120 (RB2).
        let k144 = crate::timings::cvt(3840, 2160, 144, Blanking::ReducedV2).unwrap();
        let mut did = [0u8; 128];
        did[0] = 0x70;
        let mut s = Vec::from([0x20, 0, 0, 0]);
        s.extend_from_slice(&[0x22, 0x00, 20]);
        s.extend_from_slice(&type_vii(&k144, true));
        s.extend_from_slice(&[0x24, 0x00, 6, 0x02]);
        s.extend_from_slice(&(5120u16 - 1).to_le_bytes());
        s.extend_from_slice(&(1440u16 - 1).to_le_bytes());
        s.push(119);
        s[1] = (s.len() - 4) as u8;
        let sum = s.iter().fold(0u8, |a, &v| a.wrapping_add(v));
        s.push(0u8.wrapping_sub(sum));
        did[1..1 + s.len()].copy_from_slice(&s);
        checksum(&mut did);

        // DisplayID 1.3: Type I (10 kHz steps) for 1080p at 120 (VIC 63's).
        let mut old = [0u8; 128];
        old[0] = 0x70;
        let mut s = Vec::from([0x12, 0, 0, 0]);
        s.extend_from_slice(&[0x03, 0x00, 20]);
        let mut d = type_vii(&crate::timings::vic(63).unwrap(), false);
        let c = 297_000 / 10 - 1u32;
        d[..3].copy_from_slice(&c.to_le_bytes()[..3]);
        s.extend_from_slice(&d);
        s[1] = (s.len() - 4) as u8;
        let sum = s.iter().fold(0u8, |a, &v| a.wrapping_add(v));
        s.push(0u8.wrapping_sub(sum));
        old[1..1 + s.len()].copy_from_slice(&s);
        checksum(&mut old);

        let mut all = Vec::from(base);
        for b in [cta, did, old] {
            all.extend_from_slice(&b);
        }
        if let Ok(path) = std::env::var("SLATE_EDID_OUT") {
            std::fs::write(path, &all).unwrap();
        }
        all
    }

    fn has(i: &Info, w: u32, h: u32, hz: u32) -> Option<Mode> {
        i.modes().iter().copied().find(|m| (m.timing.hactive, m.timing.vactive, m.timing.refresh()) == (w, h, hz))
    }

    #[test]
    fn every_block_kind() {
        let e = crafted();
        let i = read(&e).unwrap();
        assert_eq!(i.extensions, (3, 0));
        // The preferred mode is the base block's first detailed timing.
        let p = i.preferred().unwrap();
        assert_eq!((p.timing.hactive, p.timing.clock_khz, p.source), (3840, 533_250, Source::Detailed));
        assert_eq!(i.modes().iter().filter(|m| m.preferred).count(), 1);
        // Established: 16 modes (the interlaced one is skipped).
        assert_eq!(i.modes().iter().filter(|m| m.source == Source::Established).count(), 16);
        for (w, h, hz) in [(720, 400, 70), (640, 480, 67), (832, 624, 75), (1152, 870, 75)] {
            assert_eq!(has(&i, w, h, hz).map(|m| m.source), Some(Source::Established), "{w}x{h}@{hz}");
        }
        // Standard: DMT's 1920x1200 (normal blanking), GTF's 2048x1536
        // (the range limits don't ask for CVT): as edid-decode reads them.
        assert_eq!(has(&i, 1920, 1200, 60).unwrap().timing.clock_khz, 193_250);
        assert_eq!(has(&i, 2048, 1536, 60).unwrap().timing, gtf(2048, 1536, 60).unwrap());
        assert_eq!(has(&i, 1280, 720, 60).unwrap().timing, crate::timings::vic(4).unwrap());
        let l = i.limits.unwrap();
        assert_eq!((l.min_vhz, l.max_vhz, l.min_hkhz, l.max_hkhz, l.max_clock_khz), (48, 144, 30, 160, 600_000));
        // CTA: VICs (5 is interlaced), the HDMI Forum's 600 MHz over HDMI's 300.
        for (w, h, hz) in [(1920, 1080, 60), (3840, 2160, 60), (3840, 2160, 120), (1920, 1080, 120), (1920, 1080, 100)]
        {
            assert!(has(&i, w, h, hz).is_some(), "{w}x{h}@{hz}");
        }
        assert_eq!(i.hdmi_max_tmds_khz, Some(600_000));
        // DisplayID: 4K at 144 (over 1 GHz), 5120x1440 at 120.
        let k = has(&i, 3840, 2160, 144).unwrap();
        assert_eq!((k.source, k.preferred), (Source::DisplayId, false));
        assert_eq!(k.timing, cvt(3840, 2160, 144, Blanking::ReducedV2).unwrap());
        assert!(k.timing.clock_khz > 1_000_000);
        assert!(has(&i, 5120, 1440, 120).is_some());
        assert_eq!(i.fastest(3840, 2160).unwrap().timing.refresh(), 144);
        // A broken extension is skipped, the rest still read.
        let mut bad = e.clone();
        bad[128 + 10] ^= 0x55;
        let i = read(&bad).unwrap();
        assert_eq!(i.extensions, (2, 1));
        assert!(has(&i, 3840, 2160, 120).is_none() && has(&i, 3840, 2160, 144).is_some());
        // Cut short: the missing blocks are just not there.
        assert_eq!(read(&e[..256]).unwrap().extensions, (1, 0));
    }

    #[test]
    fn a_real_monitor() {
        // The reference PC's ASUS VG278 (1080p at up to 144 Hz), its serial number
        // blanked: a base block and a CTA-861 extension.
        let e = include_bytes!("../fixtures/asus-vg278.bin");
        let i = read(e).unwrap();
        for m in i.modes() {
            std::println!(
                "{:?} {}x{}@{} {} kHz",
                m.source,
                m.timing.hactive,
                m.timing.vactive,
                m.timing.refresh(),
                m.timing.clock_khz
            );
        }
        assert_eq!(&i.base.vendor, b"AUS");
        assert_eq!(&i.base.name[..i.base.name_len], b"VG278");
        let p = i.preferred().unwrap();
        assert_eq!((p.timing.hactive, p.timing.vactive, p.timing.refresh()), (1920, 1080, 60));
        assert_eq!(i.fastest(1920, 1080).unwrap().timing.refresh(), 144);
        let l = i.limits.unwrap();
        assert_eq!((l.min_vhz, l.max_vhz, l.max_clock_khz), (40, 144, 330_000));
        assert_eq!(i.extensions, (1, 0));
    }
}
