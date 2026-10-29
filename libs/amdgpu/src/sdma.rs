// SPDX-License-Identifier: MIT OR Apache-2.0

//! SDMA 5.2's copy engine (ADR 0172, M32 phase 6, step 2): its gfx ring
//! started without a doorbell (the write pointer written to its
//! register), and the packets for copies, fills, writes and fences.
//!
//! Facts from amdgpu (Linux v7.2.12, read as documentation, ADR 0157's
//! addendum; Slate's own code): sdma_v5_2.c (`sdma_v5_2_start`: a soft
//! reset through GRBM, the engine unhalted, then
//! `sdma_v5_2_gfx_resume_instance`'s ring registers in its order;
//! `sdma_v5_2_ring_set_wptr` without a doorbell; the copy, fill, write
//! and fence packets in `sdma_v5_2_emit_copy_buffer`, `_emit_fill_buffer`,
//! `_ring_test_ring`, `_ring_emit_fence`), sdma_common.h (the L2 cache
//! policies), navi10_sdma_pkt_open.h (the packets' layouts). Registers
//! and fields: gc_10_3_0_offset.h and gc_10_3_0_sh_mask.h (SDMA0's
//! registers are in GC's segment 0).

use alloc::vec::Vec;

use crate::interp::Card;

/// Register words in GC's segment 0.
pub mod reg {
    pub const GRBM_SOFT_RESET: u32 = 0xDA8;
    pub const CNTL: u32 = 0x1C;
    pub const SEM_WAIT_FAIL_TIMER_CNTL: u32 = 0x21;
    pub const STATUS_REG: u32 = 0x25;
    pub const F32_CNTL: u32 = 0x2A;
    pub const UTCL1_CNTL: u32 = 0x3C;
    pub const UTCL1_PAGE: u32 = 0x48;
    pub const ERROR_LOG: u32 = 0x50;
    pub const RB_CNTL: u32 = 0x80;
    pub const RB_BASE: u32 = 0x81;
    pub const RB_BASE_HI: u32 = 0x82;
    pub const RB_RPTR: u32 = 0x83;
    pub const RB_RPTR_HI: u32 = 0x84;
    pub const RB_WPTR: u32 = 0x85;
    pub const RB_WPTR_HI: u32 = 0x86;
    pub const RB_WPTR_POLL_CNTL: u32 = 0x87;
    pub const RB_RPTR_ADDR_HI: u32 = 0x88;
    pub const RB_RPTR_ADDR_LO: u32 = 0x89;
    pub const IB_CNTL: u32 = 0x8A;
    pub const DOORBELL: u32 = 0x92;
    pub const RB_WPTR_POLL_ADDR_HI: u32 = 0xB2;
    pub const RB_WPTR_POLL_ADDR_LO: u32 = 0xB3;
    pub const MINOR_PTR_UPDATE: u32 = 0xB5;
}

/// Packet opcodes (navi10_sdma_pkt_open.h).
pub mod op {
    pub const NOP: u32 = 0;
    pub const COPY: u32 = 1;
    pub const WRITE: u32 = 2;
    pub const FENCE: u32 = 5;
    pub const CONST_FILL: u32 = 11;
}

/// The most one copy or fill packet moves: the count fields have 22
/// bits in navi10_sdma_pkt_open.h (amdgpu allows more; this is what the
/// header promises). Sub-window copies are kept to it too.
pub const MAX_BYTES: u32 = 1 << 22;

/// STATUS_REG's IDLE and RB_EMPTY.
pub const IDLE: u32 = 1;
pub const RB_EMPTY: u32 = 1 << 2;

/// A ring in GPU memory: its address (256-byte aligned), its size in
/// bytes (a power of two), and where the engine writes its read pointer
/// back (8 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ring {
    pub address: u64,
    pub size: u32,
    pub rptr: u64,
}

/// The engine restarted on `r`, empty, as amdgpu starts it (`seg0`: GC's
/// segment 0): SDMA0 soft reset through GRBM for 50 µs, unhalted (its
/// firmware is already loaded), then the ring: the semaphore timer off,
/// its size (in dwords, log 2), pointers 0, write-pointer polling off
/// (the pointer is written to its register), the read pointer's
/// write-back, the base, MINOR_PTR_UPDATE around the write pointer, no
/// doorbell, UTC L1 and mid-command preemption on, UTCL1's response mode
/// 3 and redo delay 9, the L2 read policy NOA and write policy BYPASS
/// with LLC_NOALLOC, the engine unhalted, the ring and IBs on.
pub fn start(card: &mut impl Card, seg0: u32, r: &Ring) {
    let rmw = |card: &mut dyn Card, reg: u32, clear: u32, set: u32| {
        let v = card.read(seg0 + reg);
        card.write(seg0 + reg, (v & !clear) | set);
    };
    rmw(card, reg::GRBM_SOFT_RESET, 0, 1 << 23);
    card.read(seg0 + reg::GRBM_SOFT_RESET);
    card.delay_us(50);
    rmw(card, reg::GRBM_SOFT_RESET, 1 << 23, 0);
    card.read(seg0 + reg::GRBM_SOFT_RESET);
    rmw(card, reg::F32_CNTL, 1, 0);
    // The ring.
    card.write(seg0 + reg::SEM_WAIT_FAIL_TIMER_CNTL, 0);
    let order = (r.size / 4).trailing_zeros();
    rmw(card, reg::RB_CNTL, 1 | (0x1F << 1), order << 1);
    for p in [
        reg::RB_RPTR,
        reg::RB_RPTR_HI,
        reg::RB_WPTR,
        reg::RB_WPTR_HI,
        reg::RB_WPTR_POLL_ADDR_LO,
        reg::RB_WPTR_POLL_ADDR_HI,
    ] {
        card.write(seg0 + p, 0);
    }
    rmw(card, reg::RB_WPTR_POLL_CNTL, 1 << 2, 0);
    card.write(seg0 + reg::RB_RPTR_ADDR_HI, (r.rptr >> 32) as u32);
    card.write(seg0 + reg::RB_RPTR_ADDR_LO, r.rptr as u32 & !3);
    rmw(card, reg::RB_CNTL, 0, 1 << 12);
    card.write(seg0 + reg::RB_BASE, (r.address >> 8) as u32);
    card.write(seg0 + reg::RB_BASE_HI, (r.address >> 40) as u32);
    card.write(seg0 + reg::MINOR_PTR_UPDATE, 1);
    card.write(seg0 + reg::RB_WPTR, 0);
    card.write(seg0 + reg::RB_WPTR_HI, 0);
    rmw(card, reg::DOORBELL, 1 << 28, 0);
    card.write(seg0 + reg::MINOR_PTR_UPDATE, 0);
    rmw(card, reg::CNTL, 0, (1 << 1) | (1 << 5));
    rmw(card, reg::UTCL1_CNTL, (0x1F << 1) | (0x1F << 9), (9 << 1) | (3 << 9));
    rmw(card, reg::UTCL1_PAGE, 0xF << 12, (2 << 12) | (3 << 14) | (1 << 24));
    rmw(card, reg::F32_CNTL, 1, 0);
    rmw(card, reg::RB_CNTL, 0, 1);
    rmw(card, reg::IB_CNTL, 0, 1);
}

/// The ring off and the engine halted, as `sdma_v5_2_hw_fini` leaves
/// it (`sdma_v5_2_gfx_stop`, `sdma_v5_2_enable(false)`).
pub fn stop(card: &mut impl Card, seg0: u32) {
    for (r, bit) in [(reg::RB_CNTL, 0), (reg::IB_CNTL, 0)] {
        let v = card.read(seg0 + r);
        card.write(seg0 + r, v & !(1 << bit));
    }
    let v = card.read(seg0 + reg::F32_CNTL);
    card.write(seg0 + reg::F32_CNTL, v | 1);
}

/// The engine is to read up to `wptr` (bytes into the ring).
pub fn kick(card: &mut impl Card, seg0: u32, wptr: u64) {
    card.write(seg0 + reg::RB_WPTR, wptr as u32);
    card.write(seg0 + reg::RB_WPTR_HI, (wptr >> 32) as u32);
}

/// STATUS_REG and ERROR_LOG.
pub fn status(card: &mut impl Card, seg0: u32) -> (u32, u32) {
    (card.read(seg0 + reg::STATUS_REG), card.read(seg0 + reg::ERROR_LOG))
}

fn header(op: u32, sub: u32) -> u32 {
    op | (sub << 8)
}

/// Copy `bytes` (1 to [`MAX_BYTES`]) from `src` to `dst` (COPY_LINEAR).
pub fn copy(src: u64, dst: u64, bytes: u32) -> [u32; 7] {
    [header(op::COPY, 0), bytes - 1, 0, src as u32, (src >> 32) as u32, dst as u32, (dst >> 32) as u32]
}

/// A linear image of 32-bit pixels in GPU memory: its address, its
/// pitch and height in pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Image {
    pub address: u64,
    pub pitch: u32,
    pub height: u32,
}

/// Copy the `size` (width, height) rectangle at `from` in `src` to `to` in
/// `dst` (COPY_LINEAR_SUB_WINDOW, sub-op 4, navi10_sdma_pkt_open.h: the
/// element size as a power of two (2: 4 bytes) in bits 29 to 31; x and y
/// in 14 bits each, the pitch (19 bits) and the slice pitch (28 bits) in
/// elements, the rectangle's width and height; the pitches, the slice
/// pitch and the rectangle's sizes are less one, which the reference PC checked at
/// the rectangle's edges).
pub fn copy_rect(src: Image, from: (u32, u32), dst: Image, to: (u32, u32), size: (u32, u32)) -> [u32; 13] {
    let slice = |i: &Image| i.pitch * i.height - 1;
    [
        header(op::COPY, 4) | (2 << 29),
        src.address as u32,
        (src.address >> 32) as u32,
        from.0 | (from.1 << 16),
        (src.pitch - 1) << 13,
        slice(&src),
        dst.address as u32,
        (dst.address >> 32) as u32,
        to.0 | (to.1 << 16),
        (dst.pitch - 1) << 13,
        slice(&dst),
        (size.0 - 1) | ((size.1 - 1) << 16),
        0,
    ]
}

/// Fill `bytes` (a multiple of 4, up to [`MAX_BYTES`]) at `dst` with
/// `pattern` (CONSTANT_FILL with FILLSIZE 2, bits 30 and 31: the pattern
/// is a dword; at 0, as amdgpu leaves it for its zero fills, only the
/// pattern's low byte is repeated, which the reference PC showed).
pub fn fill(dst: u64, pattern: u32, bytes: u32) -> [u32; 5] {
    [header(op::CONST_FILL, 0) | (2 << 30), dst as u32, (dst >> 32) as u32, pattern, bytes - 1]
}

/// Write `data` (at least one dword) at `dst` (WRITE_LINEAR).
pub fn write(dst: u64, data: &[u32]) -> Vec<u32> {
    let mut p = alloc::vec![header(op::WRITE, 0), dst as u32, (dst >> 32) as u32, data.len() as u32 - 1];
    p.extend_from_slice(data);
    p
}

/// Write `value` at `addr` (4-byte aligned) once what came before is done
/// (FENCE, uncached: MTYPE 3).
pub fn fence(addr: u64, value: u32) -> [u32; 4] {
    [header(op::FENCE, 0) | (3 << 16), addr as u32, (addr >> 32) as u32, value]
}

/// NOPs (zero dwords, one each) to bring `n` dwords to a multiple of 8,
/// as amdgpu pads (its ring's alignment).
pub fn padding(n: usize) -> usize {
    (8 - n % 8) % 8
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const SEG0: u32 = 0x1260;

    #[derive(Default)]
    struct Regs {
        r: BTreeMap<u32, u32>,
        writes: std::vec::Vec<(u32, u32)>,
    }

    impl Card for Regs {
        fn read(&mut self, r: u32) -> u32 {
            self.r.get(&r).copied().unwrap_or(0)
        }
        fn write(&mut self, r: u32, v: u32) {
            self.r.insert(r, v);
            self.writes.push((r, v));
        }
        fn delay_us(&mut self, _: u32) {}
    }

    #[test]
    fn starts_a_ring_as_amdgpu_does() {
        let mut c = Regs::default();
        // As the reference PC's guest finds SDMA0 after amdgpu (`slate.amd.gc`).
        c.r.insert(SEG0 + reg::F32_CNTL, 1);
        c.r.insert(SEG0 + reg::RB_CNTL, 0x8084_0000);
        c.r.insert(SEG0 + reg::RB_WPTR_POLL_CNTL, 0x4);
        c.r.insert(SEG0 + reg::DOORBELL, 1 << 28);
        let ring = Ring { address: 0xF4_0C00_0000, size: 4096, rptr: 0xF4_0C00_1000 };
        start(&mut c, SEG0, &ring);
        let g = |r: u32| c.r[&(SEG0 + r)];
        // 1024 dwords (2^10), the write-back and the ring on.
        assert_eq!(g(reg::RB_CNTL), 0x8084_0000 | (10 << 1) | (1 << 12) | 1);
        assert_eq!(g(reg::RB_BASE), 0xF40C_0000);
        assert_eq!(g(reg::RB_BASE_HI), 0);
        assert_eq!((g(reg::RB_RPTR_ADDR_LO), g(reg::RB_RPTR_ADDR_HI)), (0x0C00_1000, 0xF4));
        assert_eq!(g(reg::RB_WPTR_POLL_CNTL) & 4, 0, "no polling");
        assert_eq!(g(reg::DOORBELL) & (1 << 28), 0, "no doorbell");
        assert_eq!(g(reg::F32_CNTL) & 1, 0, "unhalted");
        assert_eq!(g(reg::IB_CNTL) & 1, 1);
        assert_eq!(g(reg::CNTL), 0x22);
        assert_eq!(g(reg::UTCL1_CNTL), (9 << 1) | (3 << 9));
        assert_eq!(g(reg::UTCL1_PAGE), (2 << 12) | (3 << 14) | (1 << 24));
        // The soft reset pulsed and released before the ring is set.
        let w = |r: u32, v: u32| c.writes.iter().position(|&x| x == (SEG0 + r, v)).unwrap();
        assert!(w(reg::GRBM_SOFT_RESET, 1 << 23) < w(reg::GRBM_SOFT_RESET, 0));
        assert!(w(reg::GRBM_SOFT_RESET, 0) < w(reg::RB_BASE, 0xF40C_0000));
        // The ring comes on last.
        let on = c.writes.iter().rposition(|&(r, _)| r == SEG0 + reg::RB_CNTL).unwrap();
        assert!(w(reg::MINOR_PTR_UPDATE, 0) < on);
    }

    #[test]
    fn packets() {
        // navi10_sdma_pkt_open.h's layouts.
        assert_eq!(copy(0xF4_0000_1000, 0x1_0000_2000, 4096), [1, 4095, 0, 0x1000, 0xF4, 0x2000, 1]);
        assert_eq!(fill(0xF4_0000_1000, 0xDEAD_BEEF, 64), [0x8000_000B, 0x1000, 0xF4, 0xDEAD_BEEF, 63]);
        assert_eq!(write(0xF4_0000_1000, &[7, 8]), [2, 0x1000, 0xF4, 1, 7, 8]);
        assert_eq!(fence(0xF4_0000_1000, 5), [0x3_0005, 0x1000, 0xF4, 5]);
        assert_eq!((padding(8), padding(7), padding(9)), (0, 1, 7));
        let src = Image { address: 0x1000, pitch: 64, height: 64 };
        let dst = Image { address: 0xF4_0000_2000, pitch: 1920, height: 1080 };
        assert_eq!(
            copy_rect(src, (3, 2), dst, (10, 7), (37, 5)),
            [
                0x4000_0401,
                0x1000,
                0,
                3 | (2 << 16),
                63 << 13,
                64 * 64 - 1,
                0x2000,
                0xF4,
                10 | (7 << 16),
                1919 << 13,
                1920 * 1080 - 1,
                36 | (4 << 16),
                0
            ]
        );
    }
}
