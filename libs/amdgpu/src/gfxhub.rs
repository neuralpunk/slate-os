// SPDX-License-Identifier: MIT OR Apache-2.0

//! The GFX hub's context 0 on GC 10.3 (ADR 0172, M32 phase 6, step 2):
//! how GC's engines (SDMA, the CP, the shaders) reach memory when they
//! run as the kernel's (VMID 0). Addresses inside the system aperture go
//! to the carve-out; the rest go through a flat, one-level GART table of
//! 8-byte entries.
//!
//! Facts from amdgpu (Linux v7.2.12, read as documentation, ADR 0157's
//! addendum; Slate's own code): gfxhub_v2_1.c (`gfxhub_v2_1_gart_enable`
//! and the functions it calls: the GART's aperture, the system aperture,
//! the L1 TLB, the L2, context 0, the identity aperture off; the
//! invalidation engines), gmc_v10_0.c (`gmc_v10_0_flush_gpu_tlb`: engine
//! 17 for the driver's own flushes), amdgpu_gmc.c (`amdgpu_gmc_vram_pa`:
//! a carve-out address as the hub's L2 sees it, the frame buffer offset
//! added), amdgpu_vm.h (the PTE bits). Registers and fields:
//! gc_10_3_0_offset.h, gc_10_3_0_sh_mask.h and gc_10_3_0_default.h (GC's
//! segment 0).

use crate::interp::Card;

/// Register words in GC's segment 0.
pub mod reg {
    pub const L2_CNTL: u32 = 0x15BC;
    pub const L2_CNTL2: u32 = 0x15BD;
    pub const L2_CNTL3: u32 = 0x15BE;
    pub const L2_PROTECTION_FAULT_CNTL2: u32 = 0x15C5;
    pub const L2_PROTECTION_FAULT_STATUS: u32 = 0x15C8;
    pub const L2_PROTECTION_FAULT_ADDR_LO32: u32 = 0x15C9;
    pub const L2_PROTECTION_FAULT_DEFAULT_ADDR_LO32: u32 = 0x15CB;
    pub const L2_PROTECTION_FAULT_DEFAULT_ADDR_HI32: u32 = 0x15CC;
    pub const L2_CONTEXT1_IDENTITY_APERTURE_LOW_ADDR_LO32: u32 = 0x15CE;
    pub const L2_CNTL4: u32 = 0x15D4;
    pub const L2_CNTL5: u32 = 0x15DC;
    pub const CONTEXT0_CNTL: u32 = 0x15FC;
    pub const INVALIDATE_ENG17_REQ: u32 = 0x1630;
    pub const INVALIDATE_ENG17_ACK: u32 = 0x1642;
    /// Engine `n`'s range is at twice `n` after engine 0's.
    pub const INVALIDATE_ENG0_ADDR_RANGE_LO32: u32 = 0x1643;
    pub const INVALIDATE_ENG0_ADDR_RANGE_HI32: u32 = 0x1644;
    pub const CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32: u32 = 0x1667;
    pub const CONTEXT0_PAGE_TABLE_BASE_ADDR_HI32: u32 = 0x1668;
    pub const CONTEXT0_PAGE_TABLE_START_ADDR_LO32: u32 = 0x1687;
    pub const CONTEXT0_PAGE_TABLE_START_ADDR_HI32: u32 = 0x1688;
    pub const CONTEXT0_PAGE_TABLE_END_ADDR_LO32: u32 = 0x16A7;
    pub const CONTEXT0_PAGE_TABLE_END_ADDR_HI32: u32 = 0x16A8;
    pub const FB_OFFSET: u32 = 0x16E7;
    pub const SYSTEM_APERTURE_DEFAULT_ADDR_LSB: u32 = 0x16E8;
    pub const SYSTEM_APERTURE_DEFAULT_ADDR_MSB: u32 = 0x16E9;
    pub const FB_LOCATION_BASE: u32 = 0x16FC;
    pub const FB_LOCATION_TOP: u32 = 0x16FD;
    pub const AGP_TOP: u32 = 0x16FE;
    pub const AGP_BOT: u32 = 0x16FF;
    pub const AGP_BASE: u32 = 0x1700;
    pub const SYSTEM_APERTURE_LOW_ADDR: u32 = 0x1701;
    pub const SYSTEM_APERTURE_HIGH_ADDR: u32 = 0x1702;
    pub const MX_L1_TLB_CNTL: u32 = 0x1703;
}

/// PTE bits (amdgpu_vm.h): valid, system memory, snooped, executable,
/// readable, writeable; the memory type at bits 48 to 50 on GC 10
/// (`AMDGPU_PTE_MTYPE_NV10`), uncached 3.
pub mod pte {
    pub const VALID: u64 = 1 << 0;
    pub const SYSTEM: u64 = 1 << 1;
    pub const SNOOPED: u64 = 1 << 2;
    pub const EXECUTABLE: u64 = 1 << 4;
    pub const READABLE: u64 = 1 << 5;
    pub const WRITEABLE: u64 = 1 << 6;
    pub const MTYPE_UC: u64 = 3 << 48;
}

/// The memory context 0 sees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// The carve-out's first and last GPU addresses, and its first byte's
    /// system address (FB_OFFSET, as the firmware set it).
    pub fb_start: u64,
    pub fb_end: u64,
    pub fb_system: u64,
    /// The GART's range of GPU addresses (a 4 KiB page each entry).
    pub gart_start: u64,
    pub gart_end: u64,
    /// The GART table and a scratch page (for accesses that miss), in
    /// the carve-out (GPU addresses).
    pub table: u64,
    pub scratch: u64,
}

impl Layout {
    /// A carve-out address as the hub's L2 sees it (`amdgpu_gmc_vram_pa`).
    pub fn system(&self, gpu: u64) -> u64 {
        gpu - self.fb_start + self.fb_system
    }

    /// GART entries (and so the table's size in 8-byte words).
    pub fn entries(&self) -> u64 {
        (self.gart_end + 1 - self.gart_start) >> 12
    }
}

/// A GART entry for the carve-out page at GPU address `gpu`.
pub fn vram_entry(l: &Layout, gpu: u64) -> u64 {
    (l.system(gpu) & !0xFFF) | pte::VALID | pte::READABLE | pte::WRITEABLE | pte::EXECUTABLE
}

/// A GART entry for the system-memory page at physical address `phys`
/// (snooped, uncached: what the CPU wrote is what the GPU reads).
pub fn system_entry(phys: u64) -> u64 {
    (phys & !0xFFF) | pte::VALID | pte::SYSTEM | pte::SNOOPED | pte::READABLE | pte::WRITEABLE | pte::MTYPE_UC
}

/// The registers `enable` writes outright, in its order (the others are
/// changed field by field).
pub fn registers(l: &Layout) -> [(u32, u32); 15] {
    let pt = l.system(l.table) | 1;
    let scratch = l.system(l.scratch);
    [
        // The GART's aperture: the table (its system address, PDE valid)
        // and its range in pages.
        (reg::CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32, pt as u32),
        (reg::CONTEXT0_PAGE_TABLE_BASE_ADDR_HI32, (pt >> 32) as u32),
        (reg::CONTEXT0_PAGE_TABLE_START_ADDR_LO32, (l.gart_start >> 12) as u32),
        (reg::CONTEXT0_PAGE_TABLE_START_ADDR_HI32, (l.gart_start >> 44) as u32),
        (reg::CONTEXT0_PAGE_TABLE_END_ADDR_LO32, (l.gart_end >> 12) as u32),
        (reg::CONTEXT0_PAGE_TABLE_END_ADDR_HI32, (l.gart_end >> 44) as u32),
        // The system aperture over the carve-out; AGP off (its bottom
        // above its top).
        (reg::AGP_BASE, 0),
        (reg::AGP_BOT, 0x00FF_FFFF),
        (reg::AGP_TOP, 0),
        (reg::SYSTEM_APERTURE_LOW_ADDR, (l.fb_start >> 18) as u32),
        (reg::SYSTEM_APERTURE_HIGH_ADDR, (l.fb_end >> 18) as u32),
        // Where accesses that miss go.
        (reg::SYSTEM_APERTURE_DEFAULT_ADDR_LSB, (scratch >> 12) as u32),
        (reg::SYSTEM_APERTURE_DEFAULT_ADDR_MSB, (scratch >> 44) as u32),
        (reg::L2_PROTECTION_FAULT_DEFAULT_ADDR_LO32, (scratch >> 12) as u32),
        (reg::L2_PROTECTION_FAULT_DEFAULT_ADDR_HI32, (scratch >> 44) as u32),
    ]
}

/// Context 0 on, as `gfxhub_v2_1_gart_enable` turns it on (`seg0`: GC's
/// segment 0), the GART table already written:
/// - the GART's aperture and the system aperture ([`registers`]),
///   ACTIVE_PAGE_MIGRATION_PTE_READ_RETRY;
/// - the L1 TLB on in system access mode 3 (the aperture, then the GART)
///   with the advanced driver model, unmapped accesses to the default
///   page, uncached;
/// - the L2 on with pages that miss out to system memory, context 1's
///   identity mode 1, both caches invalidated, CNTL3 to 5 from their
///   defaults (banks 9, big fragments 6, no table walks in physical
///   mode, small fragments 0);
/// - context 0 on with a flat table (depth 0), no retries;
/// - the identity aperture off;
/// - each of the 18 invalidation engines over every address
///   (`gfxhub_v2_1_program_invalidation`: LO32 FFFF_FFFFh, HI32 1Fh);
///   without it a flush through engine 17 left translations from an
///   earlier guest in place on the reference PC.
pub fn enable(card: &mut impl Card, seg0: u32, l: &Layout) {
    let mut u = |r: u32, clear: u32, set: u32| {
        let v = card.read(seg0 + r);
        card.write(seg0 + r, (v & !clear) | set);
    };
    u(reg::L2_PROTECTION_FAULT_CNTL2, 0, 1 << 18);
    // ENABLE_L1_TLB, SYSTEM_ACCESS_MODE (bits 3 and 4), UNMAPPED_ACCESS
    // (5), ADVANCED_DRIVER_MODEL (6), MTYPE (11 to 13).
    u(reg::MX_L1_TLB_CNTL, 1 | (3 << 3) | (1 << 5) | (1 << 6) | (7 << 11), 1 | (3 << 3) | (1 << 6) | (3 << 11));
    // ENABLE_L2_CACHE, FRAGMENT_PROCESSING (1), DEFAULT_PAGE_OUT (11),
    // PDE0 tag mode (8), PDE_FAULT_CLASSIFICATION (18), CONTEXT1
    // identity mode (19 and 20), IDENTITY_MODE_FRAGMENT_SIZE (21 to 25).
    u(
        reg::L2_CNTL,
        1 | (1 << 1) | (1 << 8) | (1 << 11) | (1 << 18) | (3 << 19) | (0x1F << 21),
        1 | (1 << 11) | (1 << 19),
    );
    u(reg::L2_CNTL2, 0, 0b11);
    for (r, v) in [
        (reg::L2_CNTL3, (L2_CNTL3_DEFAULT & !(0x3F | (0x1F << 15))) | 9 | (6 << 15)),
        (reg::L2_CNTL4, L2_CNTL4_DEFAULT & !(0b11 << 6)),
        (reg::L2_CNTL5, L2_CNTL5_DEFAULT & !0x1F),
    ] {
        card.write(seg0 + r, v);
    }
    for (r, v) in registers(l) {
        card.write(seg0 + r, v);
    }
    // ENABLE_CONTEXT, PAGE_TABLE_DEPTH (bits 1 and 2), RETRY (7).
    let v = card.read(seg0 + reg::CONTEXT0_CNTL);
    card.write(seg0 + reg::CONTEXT0_CNTL, (v & !(0b111 | (1 << 7))) | 1);
    for (r, v) in [(0, 0xFFFF_FFFF), (1, 0xF), (2, 0), (3, 0)] {
        card.write(seg0 + reg::L2_CONTEXT1_IDENTITY_APERTURE_LOW_ADDR_LO32 + r, v);
    }
    for n in 0..18 {
        card.write(seg0 + reg::INVALIDATE_ENG0_ADDR_RANGE_LO32 + 2 * n, 0xFFFF_FFFF);
        card.write(seg0 + reg::INVALIDATE_ENG0_ADDR_RANGE_HI32 + 2 * n, 0x1F);
    }
}

/// gc_10_3_0_default.h.
const L2_CNTL3_DEFAULT: u32 = 0x8010_0007;
const L2_CNTL4_DEFAULT: u32 = 0x0000_00C1;
const L2_CNTL5_DEFAULT: u32 = 0x0000_3FE0;

/// Flush context 0's TLBs (the GART's entries changed) through
/// invalidation engine 17, as `gmc_v10_0_flush_gpu_tlb` asks for a flush
/// of type 0: VMID 0, the L2's PTEs and PDEs and the L1's, then wait for
/// its acknowledgement. Whether it was acknowledged.
pub fn flush(card: &mut impl Card, seg0: u32) -> bool {
    let req = 1 | (0b1_1111 << 19);
    card.write(seg0 + reg::INVALIDATE_ENG17_REQ, req);
    for _ in 0..100_000 {
        if card.read(seg0 + reg::INVALIDATE_ENG17_ACK) & 1 != 0 {
            return true;
        }
        card.delay_us(1);
    }
    false
}

/// The L2's protection fault status and the page that faulted (its
/// address >> 12), if any.
pub fn fault(card: &mut impl Card, seg0: u32) -> Option<(u32, u32)> {
    let status = card.read(seg0 + reg::L2_PROTECTION_FAULT_STATUS);
    (status != 0).then(|| (status, card.read(seg0 + reg::L2_PROTECTION_FAULT_ADDR_LO32)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const SEG0: u32 = 0x1260;

    /// The reference PC's carve-out (the hub's FB F400h to F41Fh, offset 2040h) and
    /// a 1 GiB GART at GPU address 0.
    const L: Layout = Layout {
        fb_start: 0xF4_0000_0000,
        fb_end: 0xF4_1FFF_FFFF,
        fb_system: 0x20_4000_0000,
        gart_start: 0,
        gart_end: (1 << 30) - 1,
        table: 0xF4_0C80_0000,
        scratch: 0xF4_0CA0_0000,
    };

    #[derive(Default)]
    struct Regs {
        r: BTreeMap<u32, u32>,
        writes: std::vec::Vec<(u32, u32)>,
    }

    impl Card for Regs {
        fn read(&mut self, r: u32) -> u32 {
            match r - SEG0 {
                reg::INVALIDATE_ENG17_ACK => 1,
                _ => self.r.get(&r).copied().unwrap_or(0),
            }
        }
        fn write(&mut self, r: u32, v: u32) {
            self.r.insert(r, v);
            self.writes.push((r, v));
        }
        fn delay_us(&mut self, _: u32) {}
    }

    #[test]
    fn context_0_over_the_carve_out() {
        let mut c = Regs::default();
        // As the reference PC's guest finds them after amdgpu (`slate.amd.gc`).
        c.r.insert(SEG0 + reg::MX_L1_TLB_CNTL, 0x501);
        c.r.insert(SEG0 + reg::L2_CNTL, 0x8_0E00);
        c.r.insert(SEG0 + reg::CONTEXT0_CNTL, 0x7F_FE80);
        enable(&mut c, SEG0, &L);
        let g = |r: u32| c.r[&(SEG0 + r)];
        // The table: 0xF4_0C80_0000 is 0x20_4C80_0000 to the L2, valid.
        assert_eq!(g(reg::CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32), 0x4C80_0001);
        assert_eq!(g(reg::CONTEXT0_PAGE_TABLE_BASE_ADDR_HI32), 0x20);
        assert_eq!(g(reg::CONTEXT0_PAGE_TABLE_END_ADDR_LO32), 0x3_FFFF);
        // The system aperture in 256 KiB units (the reference PC: low 3D_0000h).
        assert_eq!(g(reg::SYSTEM_APERTURE_LOW_ADDR), 0x3D_0000);
        assert_eq!(g(reg::SYSTEM_APERTURE_HIGH_ADDR), 0x3D_07FF);
        assert_eq!(g(reg::AGP_BOT), 0xFF_FFFF);
        // The L1 TLB: on, mode 3, advanced driver model, uncached.
        assert_eq!(g(reg::MX_L1_TLB_CNTL), 0x501 | (3 << 3) | (1 << 6) | (3 << 11));
        // The L2: on, default page out, context 1 identity mode 1.
        assert_eq!(g(reg::L2_CNTL) & (1 | (1 << 11) | (3 << 19)), 1 | (1 << 11) | (1 << 19));
        assert_eq!(g(reg::L2_CNTL3), 0x8010_0009 | (6 << 15));
        assert_eq!(g(reg::L2_CNTL4), 0x01);
        assert_eq!(g(reg::L2_CNTL5), 0x3FE0);
        // Context 0 on, flat, no retries; its fault bits kept.
        assert_eq!(g(reg::CONTEXT0_CNTL), 0x7F_FE01);
        // Context 0 comes on after its table is set.
        let pos = |r: u32| c.writes.iter().position(|&(w, _)| w == SEG0 + r).unwrap();
        assert!(pos(reg::CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32) < pos(reg::CONTEXT0_CNTL));
        // Engine 17's range (dcn_3_1_5's ENG17_ADDR_RANGE_LO32 is 1665h).
        assert_eq!((g(0x1665), g(0x1666)), (0xFFFF_FFFF, 0x1F));
        assert!(flush(&mut c, SEG0));
        assert_eq!(c.r[&(SEG0 + reg::INVALIDATE_ENG17_REQ)], 0x00F8_0001);
    }

    #[test]
    fn entries() {
        assert_eq!(L.entries(), 1 << 18);
        assert_eq!(vram_entry(&L, 0xF4_0D00_0000), 0x20_4D00_0000 | 0x71);
        assert_eq!(system_entry(0x1_2345_6789), 0x1_2345_6000 | 0x67 | (3 << 48));
    }
}
