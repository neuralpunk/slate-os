// SPDX-License-Identifier: MIT OR Apache-2.0

//! The output timing generator (OTG; ADR 0171, M32 phase 4, step 7): a
//! mode's timing as DCN 3.1's OTG registers hold it.
//!
//! Facts from DC (Linux v7.2.12, read as documentation, ADR 0157's
//! addendum; Slate's own code): optc/dcn10/dcn10_optc.c,
//! `optc1_program_timing`. The OTG counts from the start of sync: H_TOTAL
//! and V_TOTAL are the totals less one; sync runs from 0 to its width;
//! blank starts at the total less the front porch and ends that less the
//! active size (so it ends at sync width plus back porch); the sync
//! polarity bits are set for negative sync; V_TOTAL_MIN and _MAX equal
//! V_TOTAL (no variable refresh). Registers: dcn_3_1_5_offset.h (DCN's
//! segment 2, OTG0 from 1B2Ah, each OTG 80h words after the last) and
//! dcn_3_1_5_sh_mask.h (15-bit fields, the second at bit 16).
//!
//! Checked against amdgpu's registers for 1080p60 on the reference PC's HDMI.

use crate::interp::Card;

/// Segment 2 register words of OTG0 (dcn_3_1_5_offset.h).
pub mod reg {
    pub const H_TOTAL: u32 = 0x1B2A;
    pub const H_BLANK_START_END: u32 = 0x1B2B;
    pub const H_SYNC_A: u32 = 0x1B2C;
    pub const H_SYNC_A_CNTL: u32 = 0x1B2D;
    pub const V_TOTAL: u32 = 0x1B2F;
    pub const V_TOTAL_MIN: u32 = 0x1B30;
    pub const V_TOTAL_MAX: u32 = 0x1B31;
    pub const V_BLANK_START_END: u32 = 0x1B36;
    pub const V_SYNC_A: u32 = 0x1B37;
    pub const V_SYNC_A_CNTL: u32 = 0x1B38;
    pub const CONTROL: u32 = 0x1B41;
    /// Each OTG's registers are this many words after the last's.
    pub const STRIDE: u32 = 0x80;
}

/// A mode as the EDID gives it (in pixels and lines; sync positions from
/// the start of active).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    pub clock_khz: u32,
    pub hactive: u32,
    pub hsync_start: u32,
    pub hsync_end: u32,
    pub htotal: u32,
    pub vactive: u32,
    pub vsync_start: u32,
    pub vsync_end: u32,
    pub vtotal: u32,
    pub hsync_positive: bool,
    pub vsync_positive: bool,
}

const FIELD: u32 = 0x7FFF;

/// The timing's registers (OTG0's; add `STRIDE` per instance), or None
/// for a timing the OTG can't hold.
pub fn registers(t: &Timing) -> Option<[(u32, u32); 10]> {
    let ok = t.hactive > 0
        && t.hactive <= t.hsync_start
        && t.hsync_start < t.hsync_end
        && t.hsync_end <= t.htotal
        && t.vactive > 0
        && t.vactive <= t.vsync_start
        && t.vsync_start < t.vsync_end
        && t.vsync_end <= t.vtotal
        && t.htotal <= FIELD + 1
        && t.vtotal <= FIELD + 1;
    if !ok {
        return None;
    }
    let pair = |start: u32, end: u32| (start & FIELD) | ((end & FIELD) << 16);
    let (h_front, v_front) = (t.hsync_start - t.hactive, t.vsync_start - t.vactive);
    let (h_blank_start, v_blank_start) = (t.htotal - h_front, t.vtotal - v_front);
    let v_total = t.vtotal - 1;
    Some([
        (reg::H_TOTAL, t.htotal - 1),
        (reg::H_SYNC_A, pair(0, t.hsync_end - t.hsync_start)),
        (reg::H_BLANK_START_END, pair(h_blank_start, h_blank_start - t.hactive)),
        (reg::H_SYNC_A_CNTL, u32::from(!t.hsync_positive)),
        (reg::V_TOTAL, v_total),
        (reg::V_TOTAL_MIN, v_total),
        (reg::V_TOTAL_MAX, v_total),
        (reg::V_SYNC_A, pair(0, t.vsync_end - t.vsync_start)),
        (reg::V_BLANK_START_END, pair(v_blank_start, v_blank_start - t.vactive)),
        (reg::V_SYNC_A_CNTL, u32::from(!t.vsync_positive)),
    ])
}

/// Program OTG `instance`'s timing (DCN's segment 2 base `seg2`).
pub fn program(card: &mut impl Card, seg2: u32, instance: u32, t: &Timing) -> bool {
    let Some(regs) = registers(t) else { return false };
    for (r, v) in regs {
        card.write(seg2 + r + instance * reg::STRIDE, v);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CTA-861's 1920x1080 at 60 Hz (VIC 16), as the VG278's EDID gives it.
    const P1080: Timing = Timing {
        clock_khz: 148_500,
        hactive: 1920,
        hsync_start: 2008,
        hsync_end: 2052,
        htotal: 2200,
        vactive: 1080,
        vsync_start: 1084,
        vsync_end: 1089,
        vtotal: 1125,
        hsync_positive: true,
        vsync_positive: true,
    };

    /// What amdgpu leaves in OTG0 for that mode on the reference PC's HDMI (umr).
    #[test]
    fn as_amdgpu_programs_1080p() {
        let r = registers(&P1080).unwrap();
        assert_eq!(
            r,
            [
                (reg::H_TOTAL, 0x897),
                (reg::H_SYNC_A, 0x002C_0000),
                (reg::H_BLANK_START_END, 0x00C0_0840),
                (reg::H_SYNC_A_CNTL, 0),
                (reg::V_TOTAL, 0x464),
                (reg::V_TOTAL_MIN, 0x464),
                (reg::V_TOTAL_MAX, 0x464),
                (reg::V_SYNC_A, 0x0005_0000),
                (reg::V_BLANK_START_END, 0x0029_0461),
                (reg::V_SYNC_A_CNTL, 0),
            ]
        );
    }

    #[test]
    fn polarity_instances_and_bad_timings() {
        let t = Timing { hsync_positive: false, vsync_positive: false, ..P1080 };
        let r = registers(&t).unwrap();
        assert_eq!((r[3].1, r[9].1), (1, 1));
        #[derive(Default)]
        struct Regs(std::collections::BTreeMap<u32, u32>);
        impl Card for Regs {
            fn read(&mut self, r: u32) -> u32 {
                self.0.get(&r).copied().unwrap_or(0)
            }
            fn write(&mut self, r: u32, v: u32) {
                self.0.insert(r, v);
            }
            fn delay_us(&mut self, _: u32) {}
        }
        let mut c = Regs::default();
        assert!(program(&mut c, 0x34C0, 1, &P1080));
        assert_eq!(c.0.get(&(0x34C0 + 0x1BAA)), Some(&0x897));
        for bad in [
            Timing { hsync_start: 1900, ..P1080 },
            Timing { vsync_end: 1084, ..P1080 },
            Timing { htotal: 40_000, ..P1080 },
            Timing { hactive: 0, ..P1080 },
        ] {
            assert!(registers(&bad).is_none(), "{bad:?}");
            assert!(!program(&mut c, 0x34C0, 0, &bad));
        }
    }

    /// The same, from amdgpu's dump in target/ when it is there.
    #[test]
    fn refpc_dump() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/gpu/refpc/dcn315-hdmi-1080p60.txt");
        let Ok(d) = std::fs::read_to_string(path) else { return };
        let names = [
            "H_TOTAL",
            "H_SYNC_A",
            "H_BLANK_START_END",
            "H_SYNC_A_CNTL",
            "V_TOTAL",
            "V_TOTAL_MIN",
            "V_TOTAL_MAX",
            "V_SYNC_A",
            "V_BLANK_START_END",
            "V_SYNC_A_CNTL",
        ];
        for ((_, v), name) in registers(&P1080).unwrap().iter().zip(names) {
            let key = std::format!("dcn315.regOTG0_OTG_{name} => ");
            let line = d.lines().find(|l| l.starts_with(&key)).unwrap();
            let have = u32::from_str_radix(line[key.len()..].trim_start_matches("0x"), 16).unwrap();
            assert_eq!(*v, have, "{name}");
        }
    }
}
