// SPDX-License-Identifier: MIT OR Apache-2.0

//! GC 10.3's and SDMA 5.2's firmware for the PSP to load (ADR 0172, M32
//! phase 6, step 5): which images of which files, of what type, in what
//! order, before the PSP's AUTOLOAD_RLC starts the RLC, which brings up
//! the rest.
//!
//! Facts from amdgpu (Linux v7.2.12, read as documentation, ADR 0157's
//! addendum; Slate's own code): amdgpu_ucode.h (the files' headers:
//! `common_firmware_header`, `gfx_firmware_header_v1_0`,
//! `rlc_firmware_header_v2_0` to `_v2_2`), amdgpu_ucode.c
//! (`amdgpu_ucode_init_single_fw`: what part of a file each image is; a
//! MEC's without its jump table), amdgpu_psp.c (`psp_get_fw_type`, the
//! load order of `AMDGPU_UCODE_ID`, the jump tables skipped with
//! autoload, then `GFX_CMD_ID_AUTOLOAD_RLC`), psp_gfx_if.h (the types),
//! gfx_v10_0.c (`gfx_v10_0_wait_for_rlc_autoload_complete`: CP_STAT 0 and
//! RLC_RLCS_BOOTLOAD_STATUS's BOOTLOAD_COMPLETE).

use alloc::vec::Vec;

use crate::u32_at;

/// The files, as linux-firmware names them for GC 10.3.6 and SDMA 5.2.6.
pub const SDMA: &str = "amdgpu/sdma_5_2_6.bin";
pub const CE: &str = "amdgpu/gc_10_3_6_ce.bin";
pub const PFP: &str = "amdgpu/gc_10_3_6_pfp.bin";
pub const ME: &str = "amdgpu/gc_10_3_6_me.bin";
pub const MEC: &str = "amdgpu/gc_10_3_6_mec.bin";
pub const MEC2: &str = "amdgpu/gc_10_3_6_mec2.bin";
pub const RLC: &str = "amdgpu/gc_10_3_6_rlc.bin";

/// The PSP's firmware types (psp_gfx_if.h, `GFX_FW_TYPE_*`).
pub mod kind {
    pub const CP_ME: u32 = 1;
    pub const CP_PFP: u32 = 2;
    pub const CP_CE: u32 = 3;
    pub const CP_MEC: u32 = 4;
    pub const RLC_G: u32 = 8;
    pub const SDMA0: u32 = 9;
    pub const RLC_RESTORE_LIST_GPM_MEM: u32 = 20;
    pub const RLC_RESTORE_LIST_SRM_MEM: u32 = 21;
    pub const RLC_RESTORE_LIST_SRM_CNTL: u32 = 22;
    pub const RLC_IRAM: u32 = 26;
    pub const RLC_DRAM_BOOT: u32 = 48;
}

/// The PSP command that starts the RLC's autoload once every image is in
/// (`GFX_CMD_ID_AUTOLOAD_RLC`).
pub const AUTOLOAD_RLC: u32 = 0x21;

/// RLC_RLCS_BOOTLOAD_STATUS (GC's segment 1) and its BOOTLOAD_COMPLETE;
/// CP_STAT (segment 0), 0 when the CP is idle (gc_10_3_0_offset.h,
/// _sh_mask.h).
pub const RLC_RLCS_BOOTLOAD_STATUS: u32 = 0x4E8D;
pub const BOOTLOAD_COMPLETE: u32 = 1 << 31;
pub const CP_STAT: u32 = 0xF40;

/// CP_ME_CNTL's ME, PFP and CE halts, CP_MEC_CNTL (GC 10.3's offset,
/// `mmCP_MEC_CNTL_Sienna_Cichlid`) with both MECs halted, and RLC_CNTL's
/// RLC_ENABLE_F32 (segment 1) (gc_10_3_0_offset.h, _sh_mask.h).
pub const CP_ME_CNTL: u32 = 0xF56;
pub const CP_ME_HALTS: u32 = (1 << 28) | (1 << 26) | (1 << 24);
pub const CP_MEC_CNTL: u32 = 0xF55;
pub const CP_MEC_HALTS: u32 = (1 << 30) | (1 << 28);
pub const RLC_CNTL: u32 = 0x4C00;

/// GC's engines stopped as amdgpu leaves them (gfx_v10_0.c,
/// `gfx_v10_0_cp_enable(false)`: the CP's and the MECs' halts;
/// `gfx_v10_0_rlc_stop`: RLC_ENABLE_F32 off), so that a later PSP can
/// start the RLC's autoload again (one left running makes it refuse,
/// the reference PC showed: status FFFF_000Dh).
pub fn stop(card: &mut impl crate::interp::Card, gc0: u32, gc1: u32) {
    let v = card.read(gc0 + CP_ME_CNTL);
    card.write(gc0 + CP_ME_CNTL, v | CP_ME_HALTS);
    card.write(gc0 + CP_MEC_CNTL, CP_MEC_HALTS);
    card.delay_us(50);
    let v = card.read(gc1 + RLC_CNTL);
    card.write(gc1 + RLC_CNTL, v & !1);
}

/// GRBM_SOFT_RESET (segment 0) and the blocks `soft_reset` resets: CP
/// (bit 0), RLC (2), GFX (16), CPF (17), CPC (18), CPG (19).
pub const GRBM_SOFT_RESET: u32 = 0xDA8;
pub const RESET_CP_RLC_GFX: u32 = 1 | (1 << 2) | (0xF << 16);

/// GC's command processors, compute and the RLC reset, as amdgpu's
/// `gfx_v10_0_soft_reset` resets them: [`stop`], then GRBM_SOFT_RESET's
/// bits for 50 µs and off again. Before the PSP loads GC's firmware over
/// what an earlier driver left: without it, a MEC an earlier Slate had
/// run stayed busy at one instruction after the next autoload (the reference PC).
pub fn soft_reset(card: &mut impl crate::interp::Card, gc0: u32, gc1: u32) {
    stop(card, gc0, gc1);
    let v = card.read(gc0 + GRBM_SOFT_RESET);
    card.write(gc0 + GRBM_SOFT_RESET, v | RESET_CP_RLC_GFX);
    card.read(gc0 + GRBM_SOFT_RESET);
    card.delay_us(50);
    card.write(gc0 + GRBM_SOFT_RESET, v & !RESET_CP_RLC_GFX);
    card.read(gc0 + GRBM_SOFT_RESET);
    card.delay_us(50);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A file is too short for its header, or an image runs past its end.
    Short(&'static str),
    /// A header version this doesn't read.
    Version(&'static str, u16, u16),
}

/// The image `size` bytes at `offset` of `file`.
fn part<'a>(file: &'a [u8], name: &'static str, offset: usize, size: usize) -> Result<&'a [u8], Error> {
    file.get(offset..offset.checked_add(size).ok_or(Error::Short(name))?).ok_or(Error::Short(name))
}

fn word(file: &[u8], name: &'static str, at: usize) -> Result<usize, Error> {
    u32_at(file, at).map(|v| v as usize).ok_or(Error::Short(name))
}

/// The common header's image: `ucode_size_bytes` (at 14h) from
/// `ucode_array_offset_bytes` (18h), less `less` bytes at its end.
fn ucode<'a>(file: &'a [u8], name: &'static str, less: usize) -> Result<&'a [u8], Error> {
    let (size, offset) = (word(file, name, 0x14)?, word(file, name, 0x18)?);
    part(file, name, offset, size.checked_sub(less).ok_or(Error::Short(name))?)
}

fn version(file: &[u8]) -> (u16, u16) {
    let at = |i: usize| file.get(i..i + 2).map_or(0, |b| u16::from_le_bytes([b[0], b[1]]));
    (at(8), at(10))
}

/// The files, read (by their names above).
#[derive(Clone, Copy, Debug)]
pub struct Files<'a> {
    pub sdma: &'a [u8],
    pub ce: &'a [u8],
    pub pfp: &'a [u8],
    pub me: &'a [u8],
    pub mec: &'a [u8],
    pub mec2: &'a [u8],
    pub rlc: &'a [u8],
}

/// The images in amdgpu's order (`AMDGPU_UCODE_ID`'s): SDMA0, CE, PFP,
/// ME, MEC1 and MEC2 (each without its jump table, `jt_size` dwords at
/// the image's end, from `gfx_firmware_header_v1_0` at 28h: with autoload
/// the RLC loads those), then the RLC's: its save and restore list's
/// CNTL, GPM and SRM, IRAM, DRAM (`rlc_firmware_header_v2_1`'s and
/// `_v2_2`'s sizes and offsets at 74h to A8h), and RLC_G last.
pub fn images<'a>(f: &Files<'a>) -> Result<Vec<(u32, &'a [u8])>, Error> {
    let rlc = f.rlc;
    match version(rlc) {
        (2, minor) if minor >= 2 => {}
        (major, minor) => return Err(Error::Version("rlc", major, minor)),
    }
    let mec = |file: &'a [u8], name| -> Result<&'a [u8], Error> { ucode(file, name, word(file, name, 0x28)? * 4) };
    let rlc_part = |size_at: usize, name| -> Result<&'a [u8], Error> {
        part(rlc, name, word(rlc, name, size_at + 4)?, word(rlc, name, size_at)?)
    };
    Ok(alloc::vec![
        (kind::SDMA0, ucode(f.sdma, "sdma", 0)?),
        (kind::CP_CE, ucode(f.ce, "ce", 0)?),
        (kind::CP_PFP, ucode(f.pfp, "pfp", 0)?),
        (kind::CP_ME, ucode(f.me, "me", 0)?),
        (kind::CP_MEC, mec(f.mec, "mec")?),
        (kind::CP_MEC, mec(f.mec2, "mec2")?),
        (kind::RLC_RESTORE_LIST_SRM_CNTL, rlc_part(0x74, "rlc cntl")?),
        (kind::RLC_RESTORE_LIST_GPM_MEM, rlc_part(0x84, "rlc gpm")?),
        (kind::RLC_RESTORE_LIST_SRM_MEM, rlc_part(0x94, "rlc srm")?),
        (kind::RLC_IRAM, rlc_part(0x9C, "rlc iram")?),
        (kind::RLC_DRAM_BOOT, rlc_part(0xA4, "rlc dram")?),
        (kind::RLC_G, ucode(rlc, "rlc", 0)?),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    /// A file with a common header (version `v`), `ucode` bytes of image
    /// at 100h (each byte `fill`), and `extra` header words from 20h.
    fn file(v: (u16, u16), ucode: usize, fill: u8, extra: &[(usize, u32)]) -> Vec<u8> {
        let mut b = vec![0u8; 0x100 + ucode];
        b[8..10].copy_from_slice(&v.0.to_le_bytes());
        b[10..12].copy_from_slice(&v.1.to_le_bytes());
        b[0x14..0x18].copy_from_slice(&(ucode as u32).to_le_bytes());
        b[0x18..0x1C].copy_from_slice(&0x100u32.to_le_bytes());
        for &(at, w) in extra {
            b[at..at + 4].copy_from_slice(&w.to_le_bytes());
        }
        for x in &mut b[0x100..] {
            *x = fill;
        }
        b
    }

    #[test]
    fn images_in_amdgpus_order() {
        let sdma = file((1, 0), 64, 1, &[]);
        let ce = file((1, 0), 32, 2, &[]);
        let pfp = file((1, 0), 32, 3, &[]);
        let me = file((1, 0), 32, 4, &[]);
        // MECs with a 4-dword jump table at the end.
        let mec = file((1, 0), 48, 5, &[(0x24, 0x100 + 32), (0x28, 4)]);
        let mec2 = file((1, 0), 48, 6, &[(0x24, 0x100 + 32), (0x28, 4)]);
        // An RLC v2.2: its pieces after the image (16 bytes each).
        let pieces: Vec<(usize, u32)> = [0x74, 0x84, 0x94, 0x9C, 0xA4]
            .iter()
            .enumerate()
            .flat_map(|(i, &at)| [(at, 16), (at + 4, 0x100 + 32 + 16 * i as u32)])
            .collect();
        let mut rlc = file((2, 2), 32 + 5 * 16, 7, &pieces);
        for i in 0..5 {
            for b in &mut rlc[0x120 + 16 * i..0x130 + 16 * i] {
                *b = 0x10 + i as u8;
            }
        }
        let f = Files { sdma: &sdma, ce: &ce, pfp: &pfp, me: &me, mec: &mec, mec2: &mec2, rlc: &rlc };
        let got = images(&f).unwrap();
        let kinds: Vec<u32> = got.iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds, [9, 3, 2, 1, 4, 4, 22, 20, 21, 26, 48, 8]);
        assert_eq!(got[0].1, &[1u8; 64][..]);
        assert_eq!(got[4].1.len(), 32, "the MEC without its jump table");
        assert_eq!(got[6].1, &[0x10u8; 16][..]);
        assert_eq!(got[10].1, &[0x14u8; 16][..]);
        // RLC_G is the image the common header names (here the 32 bytes
        // and the pieces after them).
        assert_eq!(got[11].1.len(), 32 + 5 * 16);
        // An older RLC header, and a short file.
        let old = file((2, 1), 32, 7, &[]);
        assert!(matches!(images(&Files { rlc: &old, ..f }), Err(Error::Version("rlc", 2, 1))));
        assert!(matches!(images(&Files { sdma: &sdma[..0x80], ..f }), Err(Error::Short("sdma"))));
    }

    /// The reference PC's own files, when gpu-bench has copied them into
    /// target/gpu/refpc (AMD's, never committed).
    #[test]
    fn refpc_files() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/gpu/refpc");
        let read = |name: &str| std::fs::read(dir.join(name.rsplit('/').next().unwrap()));
        let (Ok(sdma), Ok(ce), Ok(pfp), Ok(me), Ok(mec), Ok(mec2), Ok(rlc)) =
            (read(SDMA), read(CE), read(PFP), read(ME), read(MEC), read(MEC2), read(RLC))
        else {
            return;
        };
        let f = Files { sdma: &sdma, ce: &ce, pfp: &pfp, me: &me, mec: &mec, mec2: &mec2, rlc: &rlc };
        let got = images(&f).unwrap();
        let sizes: Vec<usize> = got.iter().map(|(_, i)| i.len()).collect();
        // SDMA, CE, PFP, ME, the MECs less their 224-dword jump tables,
        // the RLC's CNTL, GPM, SRM, IRAM, DRAM, RLC_G (2026-10 linux-firmware).
        assert_eq!(sizes[6..11], [0x250, 0x600, 0x4480, 0x10200, 0x10200]);
        assert_eq!(sizes[11], 0x6200);
        assert_eq!(sizes[4], sizes[5]);
        assert!(got.iter().all(|(_, image)| !image.is_empty() && image.len() % 4 == 0));
    }
}
