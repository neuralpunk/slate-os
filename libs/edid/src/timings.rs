// SPDX-License-Identifier: MIT OR Apache-2.0

//! Mode timings (ADR 0157, M32 phase 1): the formulas and tables a mode
//! named only by its size and refresh rate comes from.
//!
//! - [`cvt`]: VESA Coordinated Video Timings Standard, version 1.2
//!   (2013): §3.4 (standard blanking), §3.5 (reduced blanking, version 1)
//!   and §3.6 (reduced blanking, version 2). The standard works in real
//!   numbers; here the same steps run on exact integer fractions, so the
//!   floors land where the standard's do.
//! - [`gtf`]: the VESA Generalized Timing Formula Standard, version 1.1
//!   (1999), with its default parameters: what EDID's standard timings
//!   mean on displays that don't say they want CVT.
//! - [`dmt`]: the VESA Display Monitor Timing Standard, version 1.0
//!   revision 13 (2013): the modes EDID's established and standard
//!   timings name.
//! - [`vic`]: CTA-861-I (2023), Table 1 and §4: the Video Identification
//!   Codes a CTA extension lists, progressive formats only.

use crate::Timing;

/// Which CVT blanking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blanking {
    /// §3.4: CRT-style blanking.
    Standard,
    /// §3.5: reduced blanking, version 1 (160-pixel blanking).
    Reduced,
    /// §3.6: reduced blanking, version 2 (80-pixel blanking, 1 kHz clock steps).
    ReducedV2,
}

/// CVT §3.4's vertical sync width by aspect ratio (Table 3-2): 4:3,
/// 16:9, 16:10, 5:4 and 15:9 have their own; anything else takes 10.
fn vsync_for_aspect(w: u32, h: u32) -> u32 {
    let is = |a: u32, b: u32| w * b == h * a;
    if is(4, 3) {
        4
    } else if is(16, 9) {
        5
    } else if is(16, 10) {
        6
    } else if is(5, 4) || is(15, 9) {
        7
    } else {
        10
    }
}

/// A CVT mode: `w` × `h` at `hz` (progressive, no margins). None for sizes
/// or rates the formula can't serve (a frame shorter than its blanking).
pub fn cvt(w: u32, h: u32, hz: u32, blanking: Blanking) -> Option<Timing> {
    if w < 8 || h < 2 || hz == 0 {
        return None;
    }
    // §3.2: the active width in whole 8-pixel character cells.
    let w = w / 8 * 8;
    let (w64, h64, hz64) = (u128::from(w), u128::from(h), u128::from(hz));
    match blanking {
        Blanking::Standard => {
            // §3.4's constants: 3 lines of front porch, at least 550 µs of
            // sync and back porch, at least 6 lines of back porch; the
            // blanking formula's C' = 30 and M' = 300; 8% sync; 0.25 MHz
            // clock steps.
            let vsync = u128::from(vsync_for_aspect(w, h));
            // The estimated line period in µs, as num / den:
            // (1 / hz − 550 µs) / (h + 3).
            let num = 1_000_000 - 550 * hz64;
            let den = hz64 * (h64 + 3);
            if num == 0 || num > 1_000_000 {
                return None;
            }
            let vsync_bp = (550 * den / num + 1).max(vsync + 6);
            let vtotal = h64 + vsync_bp + 3;
            // The ideal duty cycle in %, 30 − 300 × period / 1000, as a / b:
            // (300 den − 3 num) / (10 den). Below 20% it is 20%.
            let (a, b) = ((300 * den).saturating_sub(3 * num), 10 * den);
            let hblank = if a < 20 * b {
                // At least 20%.
                w64 * 20 / 80 / 16 * 16
            } else {
                w64 * a / (100 * b - a) / 16 * 16
            };
            let htotal = w64 + hblank;
            // Clock steps of 0.25 MHz: htotal / period / 0.25.
            let steps = htotal * 4 * den / num;
            let hsync = htotal * 8 / 100 / 8 * 8;
            let hfront = hblank - hsync - hblank / 2;
            Some(Timing {
                clock_khz: (steps * 250) as u32,
                hactive: w,
                hsync_start: (w64 + hfront) as u32,
                hsync_end: (w64 + hfront + hsync) as u32,
                htotal: htotal as u32,
                vactive: h,
                vsync_start: h + 3,
                vsync_end: (h64 + 3 + vsync) as u32,
                vtotal: vtotal as u32,
                hsync_positive: false,
                vsync_positive: true,
            })
        }
        Blanking::Reduced | Blanking::ReducedV2 => {
            let v2 = blanking == Blanking::ReducedV2;
            // §3.5 and §3.6: at least 460 µs of vertical blanking; v1 has 3
            // lines of front porch, the aspect's sync and at least 6 lines of
            // back porch; v2 at least 1 line of front porch, 8 of sync and
            // exactly 6 of back porch.
            let vsync = if v2 { 8 } else { u128::from(vsync_for_aspect(w, h)) };
            // The line period in µs, as num / den: (1 / hz − 460 µs) / h.
            let num = 1_000_000u128.checked_sub(460 * hz64).filter(|&n| n > 0)?;
            let den = hz64 * h64;
            let vbi = 460 * den / num + 1;
            let vbi = if v2 { vbi.max(1 + vsync + 6) } else { vbi.max(3 + vsync + 6) };
            let vtotal = h64 + vbi;
            let (hblank, hfront, hsync) = if v2 { (80, 8, 32) } else { (160, 48, 32) };
            let htotal = w64 + hblank;
            // v1 in 0.25 MHz steps, v2 in 1 kHz steps.
            let clock_khz = if v2 { hz64 * vtotal * htotal / 1000 } else { hz64 * vtotal * htotal / 250_000 * 250 };
            let vfront = if v2 { vbi - vsync - 6 } else { 3 };
            Some(Timing {
                clock_khz: clock_khz as u32,
                hactive: w,
                hsync_start: (w64 + hfront) as u32,
                hsync_end: (w64 + hfront + hsync) as u32,
                htotal: htotal as u32,
                vactive: h,
                vsync_start: (h64 + vfront) as u32,
                vsync_end: (h64 + vfront + vsync) as u32,
                vtotal: vtotal as u32,
                hsync_positive: true,
                vsync_positive: false,
            })
        }
    }
}

/// A GTF mode (GTF 1.1 §3, default parameters C' = 30, M' = 300; 1 line
/// of front porch, 3 of sync, at least 550 µs of sync and back porch,
/// 8% horizontal sync), progressive, without margins. GTF rounds where
/// CVT floors, and its clock isn't stepped.
pub fn gtf(w: u32, h: u32, hz: u32) -> Option<Timing> {
    if w < 8 || h < 2 || hz == 0 {
        return None;
    }
    let w = (w + 4) / 8 * 8;
    let (w64, h64, hz64) = (u128::from(w), u128::from(h), u128::from(hz));
    // The estimated line period, num / den µs: (1 / hz − 550 µs) / (h + 1).
    let num = 1_000_000u128.checked_sub(550 * hz64).filter(|&n| n > 0)?;
    let den = hz64 * (h64 + 1);
    // round(550 / period).
    let vsync_bp = (1100 * den + num) / (2 * num);
    let vtotal = h64 + vsync_bp + 1;
    if vsync_bp < 3 {
        return None;
    }
    // The line period scaled to the exact rate is 1 / (hz × vtotal), so
    // with p = hz × vtotal the duty cycle is (30p − 300000) / p and the
    // blanking round(w × duty / (100 − duty) / 16) × 16.
    let p = hz64 * vtotal;
    let a = (30 * p).checked_sub(300_000)?;
    let b = 70 * p + 300_000;
    let hblank = (2 * w64 * a + 16 * b) / (32 * b) * 16;
    let htotal = w64 + hblank;
    let hsync = (htotal + 50) / 100 * 8;
    let hfront = (hblank / 2).checked_sub(hsync)?;
    Some(Timing {
        clock_khz: ((htotal * p + 500) / 1000) as u32,
        hactive: w,
        hsync_start: (w64 + hfront) as u32,
        hsync_end: (w64 + hfront + hsync) as u32,
        htotal: htotal as u32,
        vactive: h,
        vsync_start: h + 1,
        vsync_end: h + 4,
        vtotal: vtotal as u32,
        hsync_positive: false,
        vsync_positive: true,
    })
}

/// A table row: clock in kHz, the horizontal four, the vertical four,
/// and the sync polarities (true for positive).
type Row = (u32, [u32; 4], [u32; 4], bool, bool);

const fn t(r: Row) -> Timing {
    let (clock_khz, h, v, hp, vp) = r;
    Timing {
        clock_khz,
        hactive: h[0],
        hsync_start: h[1],
        hsync_end: h[2],
        htotal: h[3],
        vactive: v[0],
        vsync_start: v[1],
        vsync_end: v[2],
        vtotal: v[3],
        hsync_positive: hp,
        vsync_positive: vp,
    }
}

/// DMT 1.0 r13's modes that EDID names (established timings, standard
/// timings of common sizes), as (refresh, timing). Each row is the DMT
/// table's entry for that mode, its "DMT ID" noted (where a size has a
/// normal and a reduced-blanking entry, the one EDID's standard timing
/// code names); the three EDID-only established modes (IBM's and Apple's)
/// are from EDID 1.4's Table 3.18. Checked against edid-decode 1.32's
/// `--dmt` (v4l-utils, run on the reference PC's Fedora).
const DMT: &[(u32, Row)] = &[
    (85, (31_500, [640, 672, 736, 832], [350, 382, 385, 445], true, false)), // 01h 640x350@85
    (70, (28_320, [720, 738, 846, 900], [400, 412, 414, 449], false, true)), // EDID's 720x400@70 (IBM VGA)
    (88, (35_500, [720, 738, 846, 900], [400, 421, 423, 449], false, true)), // EDID's 720x400@88 (IBM XGA2)
    (60, (25_175, [640, 656, 752, 800], [480, 490, 492, 525], false, false)), // 04h 640x480@60
    (67, (30_240, [640, 704, 768, 864], [480, 483, 486, 525], false, false)), // EDID's 640x480@67 (Apple)
    (72, (31_500, [640, 664, 704, 832], [480, 489, 492, 520], false, false)), // 05h 640x480@72
    (75, (31_500, [640, 656, 720, 840], [480, 481, 484, 500], false, false)), // 06h 640x480@75
    (56, (36_000, [800, 824, 896, 1024], [600, 601, 603, 625], true, true)), // 08h 800x600@56
    (60, (40_000, [800, 840, 968, 1056], [600, 601, 605, 628], true, true)), // 09h 800x600@60
    (72, (50_000, [800, 856, 976, 1040], [600, 637, 643, 666], true, true)), // 0Ah 800x600@72
    (75, (49_500, [800, 816, 896, 1056], [600, 601, 604, 625], true, true)), // 0Bh 800x600@75
    (75, (57_284, [832, 864, 928, 1152], [624, 625, 628, 667], false, false)), // EDID's 832x624@75 (Apple)
    (60, (65_000, [1024, 1048, 1184, 1344], [768, 771, 777, 806], false, false)), // 10h 1024x768@60
    (70, (75_000, [1024, 1048, 1184, 1328], [768, 771, 777, 806], false, false)), // 11h 1024x768@70
    (75, (78_750, [1024, 1040, 1136, 1312], [768, 769, 772, 800], true, true)), // 12h 1024x768@75
    (75, (100_000, [1152, 1216, 1344, 1456], [870, 873, 876, 915], false, false)), // EDID's 1152x870@75 (Apple)
    (75, (108_000, [1152, 1216, 1344, 1600], [864, 865, 868, 900], true, true)), // 15h 1152x864@75
    (60, (74_250, [1280, 1390, 1430, 1650], [720, 725, 730, 750], true, true)), // 55h 1280x720@60
    (60, (83_500, [1280, 1352, 1480, 1680], [800, 803, 809, 831], false, true)), // 1Ch 1280x800@60
    (60, (108_000, [1280, 1376, 1488, 1800], [960, 961, 964, 1000], true, true)), // 20h 1280x960@60
    (60, (108_000, [1280, 1328, 1440, 1688], [1024, 1025, 1028, 1066], true, true)), // 23h 1280x1024@60
    (75, (135_000, [1280, 1296, 1440, 1688], [1024, 1025, 1028, 1066], true, true)), // 24h 1280x1024@75
    (60, (85_500, [1360, 1424, 1536, 1792], [768, 771, 777, 795], true, true)), // 27h 1360x768@60
    (60, (85_500, [1366, 1436, 1579, 1792], [768, 771, 774, 798], true, true)), // 51h 1366x768@60
    (60, (106_500, [1440, 1520, 1672, 1904], [900, 903, 909, 934], false, true)), // 2Fh 1440x900@60
    (60, (108_000, [1600, 1624, 1704, 1800], [900, 901, 904, 1000], true, true)), // 53h 1600x900@60 (RB)
    (60, (162_000, [1600, 1664, 1856, 2160], [1200, 1201, 1204, 1250], true, true)), // 33h 1600x1200@60
    (60, (146_250, [1680, 1784, 1960, 2240], [1050, 1053, 1059, 1089], false, true)), // 3Ah 1680x1050@60
    (60, (148_500, [1920, 2008, 2052, 2200], [1080, 1084, 1089, 1125], true, true)), // 52h 1920x1080@60
    (60, (193_250, [1920, 2056, 2256, 2592], [1200, 1203, 1209, 1245], false, true)), // 45h 1920x1200@60
    (60, (268_500, [2560, 2608, 2640, 2720], [1600, 1603, 1609, 1646], true, false)), // 4Ch 2560x1600@60 (RB)
];

/// The DMT mode `w` × `h` at `hz`, if DMT has one.
pub fn dmt(w: u32, h: u32, hz: u32) -> Option<Timing> {
    DMT.iter().map(|&(r, row)| (r, t(row))).find(|(r, t)| *r == hz && t.hactive == w && t.vactive == h).map(|(_, t)| t)
}

/// The established timings (EDID 1.4 §3.8, Table 3.18): bytes 35 and 36
/// and bit 7 of byte 37, most significant bit first, as (w, h, hz). The
/// interlaced 1024x768@87 is left out.
pub const ESTABLISHED: [Option<(u32, u32, u32)>; 17] = [
    Some((720, 400, 70)),
    Some((720, 400, 88)),
    Some((640, 480, 60)),
    Some((640, 480, 67)),
    Some((640, 480, 72)),
    Some((640, 480, 75)),
    Some((800, 600, 56)),
    Some((800, 600, 60)),
    Some((800, 600, 72)),
    Some((800, 600, 75)),
    Some((832, 624, 75)),
    None,
    Some((1024, 768, 60)),
    Some((1024, 768, 70)),
    Some((1024, 768, 75)),
    Some((1280, 1024, 75)),
    Some((1152, 870, 75)),
];

/// CTA-861-I's progressive formats by VIC (Table 1, with the timings of
/// §4's tables). VICs that share a timing with another (the 64:27
/// pictures, and the 4:3 and 16:9 pairs at 720x480 and 720x576) are listed
/// with it. Rates are nominal: each format also runs at 1000/1001 of it.
const VICS: &[(&[u8], Row)] = &[
    (&[1], (25_175, [640, 656, 752, 800], [480, 490, 492, 525], false, false)),
    (&[2, 3], (27_000, [720, 736, 798, 858], [480, 489, 495, 525], false, false)),
    (&[4, 69], (74_250, [1280, 1390, 1430, 1650], [720, 725, 730, 750], true, true)),
    (&[16, 76], (148_500, [1920, 2008, 2052, 2200], [1080, 1084, 1089, 1125], true, true)),
    (&[17, 18], (27_000, [720, 732, 796, 864], [576, 581, 586, 625], false, false)),
    (&[19, 68], (74_250, [1280, 1720, 1760, 1980], [720, 725, 730, 750], true, true)),
    (&[31, 75], (148_500, [1920, 2448, 2492, 2640], [1080, 1084, 1089, 1125], true, true)),
    (&[32, 72], (74_250, [1920, 2558, 2602, 2750], [1080, 1084, 1089, 1125], true, true)),
    (&[33, 73], (74_250, [1920, 2448, 2492, 2640], [1080, 1084, 1089, 1125], true, true)),
    (&[34, 74], (74_250, [1920, 2008, 2052, 2200], [1080, 1084, 1089, 1125], true, true)),
    (&[41, 70], (148_500, [1280, 1720, 1760, 1980], [720, 725, 730, 750], true, true)),
    (&[47, 71], (148_500, [1280, 1390, 1430, 1650], [720, 725, 730, 750], true, true)),
    (&[60, 65], (59_400, [1280, 3040, 3080, 3300], [720, 725, 730, 750], true, true)),
    (&[61, 66], (74_250, [1280, 3700, 3740, 3960], [720, 725, 730, 750], true, true)),
    (&[62, 67], (74_250, [1280, 3040, 3080, 3300], [720, 725, 730, 750], true, true)),
    (&[63, 78], (297_000, [1920, 2008, 2052, 2200], [1080, 1084, 1089, 1125], true, true)),
    (&[64, 77], (297_000, [1920, 2448, 2492, 2640], [1080, 1084, 1089, 1125], true, true)),
    (&[93, 103], (297_000, [3840, 5116, 5204, 5500], [2160, 2168, 2178, 2250], true, true)),
    (&[94, 104], (297_000, [3840, 4896, 4984, 5280], [2160, 2168, 2178, 2250], true, true)),
    (&[95, 105], (297_000, [3840, 4016, 4104, 4400], [2160, 2168, 2178, 2250], true, true)),
    (&[96, 106], (594_000, [3840, 4896, 4984, 5280], [2160, 2168, 2178, 2250], true, true)),
    (&[97, 107], (594_000, [3840, 4016, 4104, 4400], [2160, 2168, 2178, 2250], true, true)),
    (&[98], (297_000, [4096, 5116, 5204, 5500], [2160, 2168, 2178, 2250], true, true)),
    (&[99], (297_000, [4096, 5064, 5152, 5280], [2160, 2168, 2178, 2250], true, true)),
    (&[100], (297_000, [4096, 4184, 4272, 4400], [2160, 2168, 2178, 2250], true, true)),
    (&[101], (594_000, [4096, 5064, 5152, 5280], [2160, 2168, 2178, 2250], true, true)),
    (&[102], (594_000, [4096, 4184, 4272, 4400], [2160, 2168, 2178, 2250], true, true)),
    (&[117, 119], (1_188_000, [3840, 4896, 4984, 5280], [2160, 2168, 2178, 2250], true, true)),
    (&[118, 120], (1_188_000, [3840, 4016, 4104, 4400], [2160, 2168, 2178, 2250], true, true)),
];

/// The timing of CTA-861 VIC `n`, if it is a progressive format listed here.
pub fn vic(n: u8) -> Option<Timing> {
    VICS.iter().find(|(ns, _)| ns.contains(&n)).map(|&(_, row)| t(row))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn four(t: &Timing) -> ([u32; 4], [u32; 4]) {
        ([t.hactive, t.hsync_start, t.hsync_end, t.htotal], [t.vactive, t.vsync_start, t.vsync_end, t.vtotal])
    }

    #[test]
    fn cvt_standard_blanking() {
        // Checked by hand against §3.4's steps, and against edid-decode's
        // `--cvt` (as every CVT mode here).
        let m = cvt(1920, 1080, 60, Blanking::Standard).unwrap();
        assert_eq!(m.clock_khz, 173_000);
        assert_eq!(four(&m), ([1920, 2048, 2248, 2576], [1080, 1083, 1088, 1120]));
        assert!(!m.hsync_positive && m.vsync_positive);
        let m = cvt(1280, 800, 60, Blanking::Standard).unwrap();
        assert_eq!(m.clock_khz, 83_500);
        assert_eq!(four(&m), ([1280, 1352, 1480, 1680], [800, 803, 809, 831]));
        // DMT's 1280x800@60 is this CVT mode.
        assert_eq!(dmt(1280, 800, 60), Some(m));
        let m = cvt(1024, 768, 60, Blanking::Standard).unwrap();
        assert_eq!(m.clock_khz, 63_500);
        assert_eq!(four(&m), ([1024, 1072, 1176, 1328], [768, 771, 775, 798]));
    }

    #[test]
    fn cvt_reduced_blanking() {
        let m = cvt(1920, 1080, 60, Blanking::Reduced).unwrap();
        assert_eq!(m.clock_khz, 138_500);
        assert_eq!(four(&m), ([1920, 1968, 2000, 2080], [1080, 1083, 1088, 1111]));
        assert!(m.hsync_positive && !m.vsync_positive);
        // DMT's reduced-blanking 2560x1600 is CVT-RB's; 4K and 1440p
        // (CVT-RB modes DMT doesn't list) as edid-decode gives them.
        assert_eq!(cvt(2560, 1600, 60, Blanking::Reduced), dmt(2560, 1600, 60));
        let m = cvt(3840, 2160, 60, Blanking::Reduced).unwrap();
        assert_eq!(m.clock_khz, 533_250);
        assert_eq!(four(&m), ([3840, 3888, 3920, 4000], [2160, 2163, 2168, 2222]));
        let m = cvt(2560, 1440, 60, Blanking::Reduced).unwrap();
        assert_eq!(m.clock_khz, 241_500);
        assert_eq!(four(&m), ([2560, 2608, 2640, 2720], [1440, 1443, 1448, 1481]));
        let m = cvt(3840, 2160, 60, Blanking::ReducedV2).unwrap();
        assert_eq!(m.clock_khz, 522_614);
        assert_eq!(four(&m), ([3840, 3848, 3880, 3920], [2160, 2208, 2216, 2222]));
        // A high refresh rate: the blanking stays 460 µs.
        let m = cvt(2560, 1440, 144, Blanking::ReducedV2).unwrap();
        assert_eq!(m.clock_khz, 586_586);
        assert_eq!(four(&m), ([2560, 2568, 2600, 2640], [1440, 1529, 1537, 1543]));
        assert_eq!(cvt(640, 480, 0, Blanking::Standard), None);
        // GTF, as edid-decode's `--gtf` gives it.
        let m = gtf(2048, 1536, 60).unwrap();
        assert_eq!(m.clock_khz, 266_952);
        assert_eq!(m.htotal, 2800);
        assert_eq!(m.vtotal, 1589);
        assert!(!m.hsync_positive && m.vsync_positive);
        let m = gtf(1366, 768, 75).unwrap();
        assert_eq!(m.clock_khz, 110_195);
        assert_eq!(four(&m), ([1368, 1456, 1600, 1832], [768, 769, 772, 802]));
        assert_eq!(cvt(640, 480, 5000, Blanking::Reduced), None);
    }

    #[test]
    fn tables_hold_together() {
        // Every row's refresh is its name's (within the 1000/1001 and the
        // rounding of old clocks), and its numbers run in order.
        for &(hz, row) in DMT {
            let m = t(row);
            assert!(m.refresh().abs_diff(hz) <= 1, "DMT {}x{}@{hz}: {}", m.hactive, m.vactive, m.refresh());
            assert!(m.hactive < m.hsync_start && m.hsync_start < m.hsync_end && m.hsync_end <= m.htotal);
            assert!(m.vactive < m.vsync_start && m.vsync_start < m.vsync_end && m.vsync_end <= m.vtotal);
        }
        for (ns, row) in VICS {
            let m = t(*row);
            assert!(m.hactive < m.hsync_start && m.hsync_end < m.htotal, "VIC {ns:?}");
            assert!([24, 25, 30, 50, 60, 100, 120].contains(&m.refresh()), "VIC {ns:?}: {}", m.refresh());
        }
        assert_eq!(vic(16).unwrap().refresh(), 60);
        assert_eq!(vic(97).unwrap().hactive, 3840);
        assert_eq!(vic(5), None);
        for e in ESTABLISHED.iter().flatten() {
            assert!(dmt(e.0, e.1, e.2).is_some(), "{e:?}");
        }
    }
}
