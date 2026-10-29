// SPDX-License-Identifier: MIT OR Apache-2.0

//! GC 10.3's compute: one queue on MEC1 (ME 1, pipe 0, queue 0) set up
//! through registers, with no MES, no KIQ and no doorbell (the MEC polls
//! the write pointer in memory), and the PM4 packets it runs (ADR 0172,
//! M32 phase 6, step 5).
//!
//! Facts from amdgpu (Linux v7.2.12, read as documentation, ADR 0157's
//! addendum; Slate's own code): gfx_v10_0.c (`gfx_v10_0_kiq_init_register`
//! for the queue's registers and their order, `gfx_v10_0_compute_mqd_init`
//! for their values, `gfx_v10_0_cp_compute_enable`, `GFX10_MEC_HPD_SIZE`),
//! nv.c (`nv_grbm_select`), amdgpu_amdkfd_gfx_v10_3.c (`hqd_load_v10_3`:
//! the write pointer polled from memory, CP_PQ_WPTR_POLL_CNTL and its
//! queue mask), nvd.h (the PM4 packets: WRITE_DATA, RELEASE_MEM,
//! SET_SH_REG, DISPATCH_DIRECT), v10_structs.h (the MQD's header).
//! Registers and fields: gc_10_3_0_offset.h, gc_10_3_0_sh_mask.h (GC's
//! segment 0).

use alloc::vec::Vec;

use crate::interp::Card;

/// Register words in GC's segment 0.
pub mod reg {
    pub const GRBM_GFX_CNTL: u32 = 0xDC2;
    pub const CP_MEC_CNTL: u32 = 0xF55;
    pub const CP_PQ_WPTR_POLL_CNTL: u32 = 0x1E23;
    pub const CP_PQ_WPTR_POLL_CNTL1: u32 = 0x1E24;
    pub const CP_MQD_BASE_ADDR: u32 = 0x1FA9;
    pub const CP_MQD_BASE_ADDR_HI: u32 = 0x1FAA;
    pub const CP_HQD_ACTIVE: u32 = 0x1FAB;
    pub const CP_HQD_VMID: u32 = 0x1FAC;
    pub const CP_HQD_PERSISTENT_STATE: u32 = 0x1FAD;
    pub const CP_HQD_PQ_BASE: u32 = 0x1FB1;
    pub const CP_HQD_PQ_BASE_HI: u32 = 0x1FB2;
    pub const CP_HQD_PQ_RPTR: u32 = 0x1FB3;
    pub const CP_HQD_PQ_RPTR_REPORT_ADDR: u32 = 0x1FB4;
    pub const CP_HQD_PQ_RPTR_REPORT_ADDR_HI: u32 = 0x1FB5;
    pub const CP_HQD_PQ_WPTR_POLL_ADDR: u32 = 0x1FB6;
    pub const CP_HQD_PQ_WPTR_POLL_ADDR_HI: u32 = 0x1FB7;
    pub const CP_HQD_PQ_DOORBELL_CONTROL: u32 = 0x1FB8;
    pub const CP_HQD_PQ_CONTROL: u32 = 0x1FBA;
    pub const CP_HQD_DEQUEUE_REQUEST: u32 = 0x1FC1;
    pub const CP_MQD_CONTROL: u32 = 0x1FCB;
    pub const CP_HQD_EOP_BASE_ADDR: u32 = 0x1FCE;
    pub const CP_HQD_EOP_BASE_ADDR_HI: u32 = 0x1FCF;
    pub const CP_HQD_EOP_CONTROL: u32 = 0x1FD0;
    pub const CP_HQD_EOP_RPTR: u32 = 0x1FD1;
    pub const CP_HQD_PQ_WPTR_LO: u32 = 0x1FDF;
    pub const CP_HQD_PQ_WPTR_HI: u32 = 0x1FE0;
    pub const SH_MEM_CONFIG: u32 = 0x10AD;
    /// The compute shader registers (the SH range).
    pub const COMPUTE_START_X: u32 = 0x1BA4;
    pub const COMPUTE_NUM_THREAD_X: u32 = 0x1BA7;
    pub const COMPUTE_PGM_LO: u32 = 0x1BAC;
    pub const COMPUTE_PGM_RSRC1: u32 = 0x1BB2;
    pub const COMPUTE_RESOURCE_LIMITS: u32 = 0x1BB5;
    pub const COMPUTE_PGM_RSRC3: u32 = 0x1BC8;
    pub const COMPUTE_USER_DATA_0: u32 = 0x1BE0;
}

/// SH_MEM_CONFIG for VMID 0 as amdgpu sets it (gfx_v10_0.c,
/// `DEFAULT_SH_MEM_CONFIG`: 64-bit addresses, unaligned accesses allowed
/// (ALIGNMENT_MODE 3 at bit 2), INITIAL_INST_PREFETCH 3 at bit 14).
pub const SH_MEM_CONFIG: u32 = 0xC00C;

/// A wave32 compute shader's resources (COMPUTE_PGM_RSRC1 and 2): `vgprs`
/// and `sgprs` allocated (VGPRS and SGPRS fields at bits 0 and 6, in
/// blocks of 8 less one), denormals on (FLOAT_MODE C0h at bit 12),
/// MEM_ORDERED (bit 30); `user_sgprs` user data SGPRs (bits 1 to 5) and
/// the thread group's X ID after them (TGID_X_EN, bit 7), and its Y ID
/// after that with `tgid_y` (TGID_Y_EN, bit 8), thread IDs in X only
/// (TIDIG_COMP_CNT 0).
pub fn resources(vgprs: u32, sgprs: u32, user_sgprs: u32, tgid_y: bool) -> [u32; 2] {
    let blocks = |n: u32| n.div_ceil(8).max(1) - 1;
    [
        blocks(vgprs) | (blocks(sgprs) << 6) | (0xC0 << 12) | (1 << 30),
        (user_sgprs << 1) | (1 << 7) | (u32::from(tgid_y) << 8),
    ]
}

/// A shader in GPU memory: its address (256-byte aligned), its
/// resources ([`resources`]) and its threads a group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shader {
    pub address: u64,
    pub rsrc: [u32; 2],
    pub threads: u32,
}

/// Run `s` as `groups` thread groups, wave32, with `user` in its user
/// SGPRs, then write `fence.1` at `fence.0` once its stores are out of the
/// caches: the program's address and resources, the threads a group, no
/// limits or scratch and every compute unit, the start at 0, the user
/// data, DISPATCH_DIRECT, RELEASE_MEM.
pub fn dispatch_packets(seg0: u32, s: &Shader, groups: (u32, u32), user: &[u32], fence: (u64, u32)) -> Vec<u32> {
    let mut p = Vec::new();
    p.extend(set_sh_reg(seg0 + reg::COMPUTE_PGM_LO, &[(s.address >> 8) as u32, (s.address >> 40) as u32]));
    p.extend(set_sh_reg(seg0 + reg::COMPUTE_PGM_RSRC1, &s.rsrc));
    p.extend(set_sh_reg(seg0 + reg::COMPUTE_PGM_RSRC3, &[0]));
    p.extend(set_sh_reg(seg0 + reg::COMPUTE_START_X, &[0, 0, 0, s.threads, 1, 1]));
    // RESOURCE_LIMITS, STATIC_THREAD_MGMT_SE0 and 1, TMPRING_SIZE,
    // STATIC_THREAD_MGMT_SE2 and 3 (in that order in the register file).
    let all = 0xFFFF_FFFF;
    p.extend(set_sh_reg(seg0 + reg::COMPUTE_RESOURCE_LIMITS, &[0, all, all, 0, all, all]));
    p.extend(set_sh_reg(seg0 + reg::COMPUTE_USER_DATA_0, user));
    p.extend(dispatch((groups.0, groups.1, 1), true));
    p.extend(release_mem(fence.0, fence.1));
    p
}

/// GRBM_GFX_CNTL selecting MEC1 (ME 1), pipe 0, queue 0, VMID 0 (MEID at
/// bits 2 and 3).
pub const MEC1_PIPE0_QUEUE0: u32 = 1 << 2;

/// Each queue's end-of-pipe buffer (`GFX10_MEC_HPD_SIZE`).
pub const EOP_SIZE: u32 = 2048;

/// Where the queue lives in GPU memory: its MQD (256-byte aligned, 2
/// KiB), end-of-pipe buffer (256-byte aligned, [`EOP_SIZE`]), ring (a
/// power of two of bytes, 256-byte aligned), where the MEC writes its read
/// pointer, and the write pointer it polls (8 bytes each).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Queue {
    pub mqd: u64,
    pub eop: u64,
    pub ring: u64,
    pub size: u32,
    pub rptr: u64,
    pub wptr: u64,
}

/// The MQD's fields amdgpu sets before the queue is loaded
/// (`gfx_v10_0_compute_mqd_init`): its header (dword 0), the static thread
/// management masks for the four shader engines (dwords 24 to 27, all
/// compute units), the reserved misc field (3) and the pipeline statistics
/// on (v10_structs.h's `struct v10_compute_mqd`). The queue's state itself
/// is in the registers on this path; the MEC saves into the MQD.
pub fn mqd() -> Vec<(usize, u32)> {
    let mut v = alloc::vec![(0, 0xC031_0800)];
    v.extend((24..28).map(|d| (d, 0xFFFF_FFFF)));
    v
}

/// The queue's registers in `gfx_v10_0_kiq_init_register`'s order (the
/// queue selected through GRBM_GFX_CNTL first, write-pointer polling off
/// while they change): no doorbell, the end-of-pipe buffer (its size as
/// log2 of dwords less one), the MQD (VMID 0), the ring (QUEUE_SIZE log2
/// of dwords less one, RPTR_BLOCK_SIZE 9, unordered dispatch, privileged,
/// the kernel's), the read pointer's report and the polled write pointer,
/// both pointers 0, VMID 0, PRELOAD_SIZE 53h, the EOP fetcher started,
/// then the queue on.
pub fn registers(q: &Queue) -> Vec<(u32, u32)> {
    let log2 = |bytes: u32| (bytes / 4).trailing_zeros() - 1;
    alloc::vec![
        (reg::CP_HQD_PQ_DOORBELL_CONTROL, 0),
        (reg::CP_HQD_EOP_BASE_ADDR, (q.eop >> 8) as u32),
        (reg::CP_HQD_EOP_BASE_ADDR_HI, (q.eop >> 40) as u32),
        (reg::CP_HQD_EOP_CONTROL, log2(EOP_SIZE)),
        (reg::CP_MQD_BASE_ADDR, q.mqd as u32 & !3),
        (reg::CP_MQD_BASE_ADDR_HI, (q.mqd >> 32) as u32),
        (reg::CP_MQD_CONTROL, 0),
        (reg::CP_HQD_PQ_BASE, (q.ring >> 8) as u32),
        (reg::CP_HQD_PQ_BASE_HI, (q.ring >> 40) as u32),
        (reg::CP_HQD_PQ_CONTROL, log2(q.size) | (9 << 8) | (1 << 28) | (1 << 30) | (1 << 31)),
        (reg::CP_HQD_PQ_RPTR_REPORT_ADDR, q.rptr as u32 & !3),
        (reg::CP_HQD_PQ_RPTR_REPORT_ADDR_HI, (q.rptr >> 32) as u32 & 0xFFFF),
        (reg::CP_HQD_PQ_WPTR_POLL_ADDR, q.wptr as u32 & !3),
        (reg::CP_HQD_PQ_WPTR_POLL_ADDR_HI, (q.wptr >> 32) as u32 & 0xFFFF),
        (reg::CP_HQD_PQ_WPTR_LO, 0),
        (reg::CP_HQD_PQ_WPTR_HI, 0),
        (reg::CP_HQD_VMID, 0),
        (reg::CP_HQD_PERSISTENT_STATE, 0x53 << 8),
        (reg::CP_HQD_EOP_RPTR, 1 << 31),
        (reg::CP_HQD_ACTIVE, 1),
    ]
}

/// What the queue's start found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Started {
    /// CP_HQD_ACTIVE after (bit 0: the queue is on).
    pub active: u32,
    /// Whether a queue left active had to be dequeued first.
    pub dequeued: bool,
    /// Whether it didn't dequeue (a halted MEC can't), so that MEC1's
    /// pipe 0 was reset (CP_MEC_CNTL's MEC_ME1_PIPE0_RESET, bit 16;
    /// inferred, amdgpu doesn't on GC 10).
    pub reset: bool,
}

/// Dequeue `select`'s queue if it is active (the MEC running); whether
/// it went off within 10 ms.
fn dequeue(card: &mut impl Card, seg0: u32) -> bool {
    card.write(seg0 + reg::CP_HQD_DEQUEUE_REQUEST, 1);
    let mut off = false;
    for _ in 0..10_000 {
        if card.read(seg0 + reg::CP_HQD_ACTIVE) & 1 == 0 {
            off = true;
            break;
        }
        card.delay_us(1);
    }
    card.write(seg0 + reg::CP_HQD_DEQUEUE_REQUEST, 0);
    off
}

/// The queue off while the MEC still runs (before it is halted at
/// shutdown), so that the next driver finds it off.
pub fn stop(card: &mut impl Card, seg0: u32) -> bool {
    card.write(seg0 + reg::CP_PQ_WPTR_POLL_CNTL, 0);
    card.write(seg0 + reg::GRBM_GFX_CNTL, MEC1_PIPE0_QUEUE0);
    let off = card.read(seg0 + reg::CP_HQD_ACTIVE) & 1 == 0 || dequeue(card, seg0);
    card.write(seg0 + reg::GRBM_GFX_CNTL, 0);
    off
}

/// MEC1's queue 0 started on `q` (`seg0`: GC's segment 0): polling off,
/// the queue selected, a queue left active dequeued, the registers, the
/// selection back to 0, then the MEC polling the write pointer every 16
/// cycles for queue 0 (`hqd_load_v10_3`: PERIOD at bits 0 to 7, EN at
/// 31, the queue mask in CNTL1), and the MECs unhalted (CP_MEC_CNTL 0).
pub fn start(card: &mut impl Card, seg0: u32, q: &Queue) -> Started {
    card.write(seg0 + reg::CP_PQ_WPTR_POLL_CNTL, 0);
    card.write(seg0 + reg::GRBM_GFX_CNTL, MEC1_PIPE0_QUEUE0);
    let (mut dequeued, mut reset) = (false, false);
    if card.read(seg0 + reg::CP_HQD_ACTIVE) & 1 != 0 {
        dequeued = true;
        if !dequeue(card, seg0) {
            reset = true;
            let v = card.read(seg0 + reg::CP_MEC_CNTL);
            card.write(seg0 + reg::CP_MEC_CNTL, v | (1 << 16));
            card.delay_us(50);
            card.write(seg0 + reg::CP_MEC_CNTL, v & !(1 << 16));
        }
        card.write(seg0 + reg::CP_HQD_PQ_RPTR, 0);
    }
    for (r, v) in registers(q) {
        card.write(seg0 + r, v);
    }
    let active = card.read(seg0 + reg::CP_HQD_ACTIVE);
    card.write(seg0 + reg::GRBM_GFX_CNTL, 0);
    card.write(seg0 + reg::CP_PQ_WPTR_POLL_CNTL1, 1);
    card.write(seg0 + reg::CP_PQ_WPTR_POLL_CNTL, (1 << 31) | 0x10);
    card.write(seg0 + reg::CP_MEC_CNTL, 0);
    card.delay_us(50);
    Started { active, dequeued, reset }
}

/// A PM4 type 3 header for the compute queue: `op`, `count` dwords after
/// it, the shader type bit (bit 1, `PACKET3_COMPUTE`).
fn packet3(op: u32, count: usize) -> u32 {
    (3 << 30) | ((count as u32 - 1) << 16) | (op << 8) | (1 << 1)
}

/// Write `value` at `addr` (WRITE_DATA, 37h: memory asynchronously
/// direct (DST_SEL 5), confirmed (WR_CONFIRM, bit 20), from the ME).
pub fn write_data(addr: u64, value: u32) -> [u32; 5] {
    [packet3(0x37, 4), (5 << 8) | (1 << 20), addr as u32, (addr >> 32) as u32, value]
}

/// Once what came before is done and its writes are out of the caches,
/// write `value` at `addr` (RELEASE_MEM, 49h: CACHE_FLUSH_AND_INV_TS_EVENT
/// 14h at EVENT_INDEX 5, the GL2 written back and invalidated with the
/// GLM, GCR_SEQ, cache policy 3; a 32-bit value (DATA_SEL 1) to memory, no
/// interrupt), as `gfx_v10_0_ring_emit_fence` writes its fences.
pub fn release_mem(addr: u64, value: u32) -> [u32; 8] {
    let gcr = (1 << 22) | (1 << 21) | (1 << 20) | (1 << 13) | (1 << 12);
    [packet3(0x49, 7), 0x14 | (5 << 8) | gcr | (3 << 25), 1 << 29, addr as u32, (addr >> 32) as u32, value, 0, 0]
}

/// Make what came before visible to what follows: the GL2, GLM, GL1,
/// GLV, GLK and GLI caches written back and invalidated (ACQUIRE_MEM,
/// 58h, over every address; `gfx_v10_0_emit_mem_sync`'s GCR_CNTL).
pub fn acquire_mem() -> [u32; 8] {
    let gcr = (1 << 14) | (1 << 15) | (1 << 5) | (1 << 4) | (1 << 9) | (1 << 8) | (1 << 7) | 1;
    [packet3(0x58, 7), 0, 0xFFFF_FFFF, 0x00FF_FFFF, 0, 0, 0x0A, gcr]
}

/// One dword of nothing (PACKET3 NOP with count 3FFFh, as amdgpu pads its
/// compute rings).
pub const NOP: u32 = 0xFFFF_1000;

/// Set the shader registers from `reg` (absolute: GC's segment 0 base
/// plus the register's offset) on (SET_SH_REG, 76h: the index from the SH
/// registers' start, 2C00h).
pub fn set_sh_reg(reg: u32, values: &[u32]) -> Vec<u32> {
    let mut p = alloc::vec![packet3(0x76, values.len() + 1), reg - 0x2C00];
    p.extend_from_slice(values);
    p
}

/// Dispatch `groups` thread groups (DISPATCH_DIRECT, 15h), with
/// COMPUTE_DISPATCH_INITIATOR's COMPUTE_SHADER_EN and, for wave32,
/// CS_W32_EN (bit 15).
pub fn dispatch(groups: (u32, u32, u32), wave32: bool) -> [u32; 5] {
    [packet3(0x15, 4), groups.0, groups.1, groups.2, 1 | (u32::from(wave32) << 15)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const SEG0: u32 = 0x1260;
    const Q: Queue = Queue {
        mqd: 0xF4_0D00_0000,
        eop: 0xF4_0D00_1000,
        ring: 0xF4_0D00_2000,
        size: 4096,
        rptr: 0xF4_0D00_3000,
        wptr: 0xF4_0D00_3008,
    };

    #[derive(Default)]
    struct Regs {
        r: BTreeMap<u32, u32>,
        writes: std::vec::Vec<(u32, u32)>,
    }

    impl Card for Regs {
        fn read(&mut self, r: u32) -> u32 {
            match r - SEG0 {
                // A queue left on goes off when dequeued.
                reg::CP_HQD_ACTIVE if self.r.get(&(SEG0 + reg::CP_HQD_DEQUEUE_REQUEST)) == Some(&1) => 0,
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
    fn a_queue_as_amdgpu_sets_one() {
        let r: BTreeMap<u32, u32> = registers(&Q).into_iter().collect();
        // A 4 KiB ring: 1024 dwords, QUEUE_SIZE 9; RPTR_BLOCK_SIZE 9,
        // unordered, privileged, the kernel's.
        assert_eq!(r[&reg::CP_HQD_PQ_CONTROL], 9 | (9 << 8) | 0xD000_0000);
        assert_eq!(r[&reg::CP_HQD_EOP_CONTROL], 8, "2 KiB: 512 dwords");
        assert_eq!((r[&reg::CP_HQD_PQ_BASE], r[&reg::CP_HQD_PQ_BASE_HI]), (0xF40D_0020, 0));
        assert_eq!((r[&reg::CP_MQD_BASE_ADDR], r[&reg::CP_MQD_BASE_ADDR_HI]), (0x0D00_0000, 0xF4));
        assert_eq!(r[&reg::CP_HQD_PERSISTENT_STATE], 0x5300);
        // The queue goes on last.
        assert_eq!(registers(&Q).last(), Some(&(reg::CP_HQD_ACTIVE, 1)));
    }

    #[test]
    fn starts_with_polling_and_the_mec_on() {
        let mut c = Regs::default();
        c.r.insert(SEG0 + reg::CP_HQD_ACTIVE, 1);
        c.r.insert(SEG0 + reg::CP_MEC_CNTL, 0x5000_0000);
        let s = start(&mut c, SEG0, &Q);
        assert!(s.dequeued);
        let g = |r: u32| c.r[&(SEG0 + r)];
        assert_eq!(g(reg::GRBM_GFX_CNTL), 0, "the selection back");
        assert_eq!(g(reg::CP_PQ_WPTR_POLL_CNTL), 0x8000_0010);
        assert_eq!(g(reg::CP_PQ_WPTR_POLL_CNTL1), 1);
        assert_eq!(g(reg::CP_MEC_CNTL), 0);
        // The queue's registers were written with it selected.
        let sel = c.writes.iter().position(|&w| w == (SEG0 + reg::GRBM_GFX_CNTL, 4)).unwrap();
        let base = c.writes.iter().position(|&(r, _)| r == SEG0 + reg::CP_HQD_PQ_BASE).unwrap();
        let back = c.writes.iter().position(|&w| w == (SEG0 + reg::GRBM_GFX_CNTL, 0)).unwrap();
        assert!(sel < base && base < back);
    }

    #[test]
    fn packets() {
        assert_eq!(write_data(0xF4_0000_1000, 7), [0xC003_3702, 0x0010_0500, 0x1000, 0xF4, 7]);
        let rm = release_mem(0xF4_0000_1000, 9);
        assert_eq!(rm[0], 0xC006_4902);
        assert_eq!(rm[1] & 0xFFF, 0x514);
        assert_eq!(rm[2], 1 << 29);
        // COMPUTE_PGM_LO, absolute 2E0Ch on GC's segment at 1260h: index 20Ch.
        assert_eq!(set_sh_reg(0x1260 + 0x1BAC, &[1, 2]), [0xC002_7602, 0x20C, 1, 2]);
        assert_eq!(dispatch((1, 1, 1), true), [0xC003_1502, 1, 1, 1, 0x8001]);
        assert_eq!(mqd()[0], (0, 0xC031_0800));
        // Three VGPRs and four SGPRs: one block of each; three user SGPRs
        // and the group's X ID.
        assert_eq!(resources(3, 4, 3, false), [0x400C_0000, 0x86]);
        assert_eq!(resources(12, 16, 8, true)[1], (8 << 1) | (1 << 7) | (1 << 8));
        let sh = Shader { address: 0xF4_0D00_4000, rsrc: [1, 2], threads: 64 };
        let p = dispatch_packets(0x1260, &sh, (16, 1), &[3, 4, 5], (0xF4_0000_1000, 6));
        // PGM_LO first (its index 20Ch), the dispatch of 16 groups, the
        // fence last.
        assert_eq!(&p[..4], &[0xC002_7602, 0x20C, 0xF40D_0040, 0]);
        let d = p.iter().position(|&w| w == 0xC003_1502).unwrap();
        assert_eq!(&p[d + 1..d + 5], &[16, 1, 1, 0x8001]);
        assert_eq!(p[p.len() - 3], 6);
    }
}
