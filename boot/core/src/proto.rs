// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Limine boot protocol as the loader answers it (ADR 0089). Source:
//! the protocol's specification (PROTOCOL.md, base revision 6). The
//! identifiers and layouts are the ones the kernel's binding crate
//! (`limine` 0.6.5) defines, written out here because a loader builds the
//! responses that crate only reads.
//!
//! A request is 8-byte aligned in the kernel's image: the common magic,
//! its own two-word identifier, its revision, a pointer the loader fills
//! with the response, then what the request carries. The loader looks for
//! them between the start and end markers when the image has them.

/// The first two words of every request.
pub const COMMON_MAGIC: [u64; 2] = [0xc7b1_dd30_df4c_8b88, 0x0a82_e883_a194_f07b];
/// The base revision tag: two magic words and the revision the kernel
/// wants. A loader that supports it writes 0 over the revision, and the
/// revision it loaded with over the second word.
pub const BASE_REVISION_MAGIC: [u64; 2] = [0xf956_2b2d_5c95_a6c8, 0x6a7b_3849_4453_6bdc];
pub const START_MARKER: [u64; 4] =
    [0xf6b8_f4b3_9de7_d1ae, 0xfab9_1a69_40fc_b9cf, 0x785c_6ed0_15d3_e316, 0x181e_920a_7852_b9d9];
pub const END_MARKER: [u64; 2] = [0xadc0_e053_1bb1_0d03, 0x9572_709f_3176_4c62];
/// The base revision the loader speaks.
pub const REVISION: u64 = 6;

/// The higher-half direct map's offset (4-level paging).
pub const HHDM: u64 = 0xffff_8000_0000_0000;

/// Request identifiers (their two words after the common magic).
pub mod id {
    pub const BOOTLOADER_INFO: [u64; 2] = [0xf550_38d8_e2a1_202f, 0x2794_26fc_f5f5_9740];
    pub const EXECUTABLE_CMDLINE: [u64; 2] = [0x4b16_1536_e598_651e, 0xb390_ad4a_2f1f_303a];
    pub const FIRMWARE_TYPE: [u64; 2] = [0x8c2f_75d9_0bef_28a8, 0x7045_a468_8eac_00c3];
    pub const STACK_SIZE: [u64; 2] = [0x224e_f046_0a8e_8926, 0xe1cb_0fc2_5f46_ea3d];
    pub const HHDM: [u64; 2] = [0x48dc_f1cb_8ad2_b852, 0x6398_4e95_9a98_244b];
    pub const FRAMEBUFFER: [u64; 2] = [0x9d58_27dc_d881_dd75, 0xa314_8604_f6fa_b11b];
    pub const MP: [u64; 2] = [0x95a6_7b81_9a1b_857e, 0xa0b6_1b72_3b6a_73e0];
    pub const MEMMAP: [u64; 2] = [0x67cf_3d9d_378a_806f, 0xe304_acdf_c50c_3c62];
    pub const ENTRY_POINT: [u64; 2] = [0x13d8_6c03_5a1c_d3e1, 0x2b0c_aa89_d8f3_026a];
    pub const EXECUTABLE_FILE: [u64; 2] = [0xad97_e90e_83f1_ed67, 0x31eb_5d1c_5ff2_3b69];
    pub const MODULES: [u64; 2] = [0x3e7e_2797_02be_32af, 0xca1c_4f3b_d128_0cee];
    pub const RSDP: [u64; 2] = [0xc5e7_7b6b_397e_7b43, 0x2763_7845_accd_cf3c];
    pub const EFI: [u64; 2] = [0x5ceb_a516_3eaa_f6d6, 0x0a69_8161_0cf6_5fcc];
    pub const EFI_MEMMAP: [u64; 2] = [0x7df6_2a43_1d68_72d5, 0xa4fc_dfb3_e573_06c8];
    pub const DATE_AT_BOOT: [u64; 2] = [0x5027_46e1_84c0_88aa, 0xfbc5_ec83_e632_7893];
    pub const EXECUTABLE_ADDRESS: [u64; 2] = [0x71ba_7686_3cc5_5f63, 0xb264_4a48_c516_a487];
}

/// Memory map entry types.
pub mod memtype {
    pub const USABLE: u64 = 0;
    pub const RESERVED: u64 = 1;
    pub const ACPI_RECLAIMABLE: u64 = 2;
    pub const ACPI_NVS: u64 = 3;
    pub const BAD_MEMORY: u64 = 4;
    pub const BOOTLOADER_RECLAIMABLE: u64 = 5;
    pub const EXECUTABLE_AND_MODULES: u64 = 6;
    pub const FRAMEBUFFER: u64 = 7;
}

pub const FIRMWARE_X86_BIOS: u64 = 0;
pub const FIRMWARE_EFI64: u64 = 2;
/// The MP request's flag asking for x2APIC, and the response's saying so.
pub const MP_X2APIC: u64 = 1;
/// A framebuffer's memory model: RGB.
pub const MEMORY_MODEL_RGB: u8 = 1;

// Offsets in a request.
pub const REQ_ID: usize = 16;
pub const REQ_REVISION: usize = 32;
pub const REQ_RESPONSE: usize = 40;
/// What the request carries (the MP flags, a stack size, an entry point).
pub const REQ_DATA: usize = 48;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MemmapEntry {
    pub base: u64,
    pub length: u64,
    pub kind: u64,
}

/// A file the loader loaded: the kernel or a module.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct File {
    pub revision: u64,
    pub address: u64,
    pub size: u64,
    pub path: u64,
    pub cmdline: u64,
    pub media_type: u32,
    pub tftp_ip: u32,
    pub tftp_port: u32,
    pub partition_index: u32,
    pub mbr_disk_id: u32,
    pub gpt_disk_uuid: [u8; 16],
    pub gpt_part_uuid: [u8; 16],
    pub part_uuid: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Framebuffer {
    pub address: u64,
    pub width: u64,
    pub height: u64,
    pub pitch: u64,
    pub bpp: u16,
    pub memory_model: u8,
    pub red_mask_size: u8,
    pub red_mask_shift: u8,
    pub green_mask_size: u8,
    pub green_mask_shift: u8,
    pub blue_mask_size: u8,
    pub blue_mask_shift: u8,
    pub reserved: [u8; 7],
    pub edid_size: u64,
    pub edid: u64,
}

/// One CPU in the MP response. The kernel starts it by writing
/// `extra_argument` and then `goto_address`; the CPU, waiting since the
/// handoff, jumps there with this structure's address in `rdi`.
#[repr(C)]
#[derive(Debug, Default)]
pub struct MpInfo {
    pub processor_id: u32,
    pub lapic_id: u32,
    pub reserved: u64,
    pub goto_address: u64,
    pub extra_argument: u64,
}

/// Where `goto_address` is in [`MpInfo`] (the CPUs' wait loop reads it).
pub const MP_GOTO: usize = 16;

/// A request found in the kernel's image: its identifier and where it is
/// (an offset in the image).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Found {
    pub id: [u64; 2],
    pub at: usize,
}

fn word(image: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(image.get(at..at + 8)?.try_into().ok()?))
}

/// The requests in a loaded image, and the base revision tag's offset.
/// Only the part between the markers is searched when both are there.
pub fn scan(image: &[u8]) -> (Option<usize>, alloc::vec::Vec<Found>) {
    let words = |at: usize, n: usize| (0..n).map(|i| word(image, at + 8 * i)).collect::<Option<alloc::vec::Vec<_>>>();
    let aligned = (0..image.len().saturating_sub(7)).step_by(8);
    let start = aligned.clone().find(|&at| words(at, 4).as_deref() == Some(&START_MARKER[..]));
    let end = start.and_then(|s| {
        aligned.clone().skip_while(|&at| at <= s).find(|&at| words(at, 2).as_deref() == Some(&END_MARKER[..]))
    });
    let (from, to) = match (start, end) {
        (Some(s), Some(e)) => (s + 32, e),
        _ => (0, image.len()),
    };
    let mut base = None;
    let mut found = alloc::vec::Vec::new();
    let mut at = from;
    while at + 16 <= to {
        match words(at, 2).as_deref() {
            Some(w) if w == COMMON_MAGIC && at + REQ_DATA <= to => {
                if let (Some(a), Some(b)) = (word(image, at + REQ_ID), word(image, at + REQ_ID + 8)) {
                    found.push(Found { id: [a, b], at });
                }
                at += REQ_DATA;
                continue;
            }
            Some(w) if w == BASE_REVISION_MAGIC && at + 24 <= to => {
                base = Some(at);
                at += 24;
                continue;
            }
            _ => {}
        }
        at += 8;
    }
    (base, found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn put(v: &mut Vec<u8>, words: &[u64]) {
        for w in words {
            v.extend_from_slice(&w.to_le_bytes());
        }
    }

    #[test]
    fn finds_requests_between_the_markers() {
        let mut img = Vec::new();
        // A request before the start marker is not one.
        put(&mut img, &[COMMON_MAGIC[0], COMMON_MAGIC[1], id::RSDP[0], id::RSDP[1], 0, 0]);
        put(&mut img, &START_MARKER);
        put(&mut img, &[BASE_REVISION_MAGIC[0], BASE_REVISION_MAGIC[1], 6]);
        put(&mut img, &[COMMON_MAGIC[0], COMMON_MAGIC[1], id::HHDM[0], id::HHDM[1], 0, 0]);
        put(&mut img, &[COMMON_MAGIC[0], COMMON_MAGIC[1], id::MP[0], id::MP[1], 0, 0, 1]);
        put(&mut img, &END_MARKER);
        put(&mut img, &[COMMON_MAGIC[0], COMMON_MAGIC[1], id::MEMMAP[0], id::MEMMAP[1], 0, 0]);
        let (base, found) = scan(&img);
        assert_eq!(base, Some(48 + 32));
        let ids: Vec<[u64; 2]> = found.iter().map(|f| f.id).collect();
        assert_eq!(ids, [id::HHDM, id::MP]);
        assert_eq!(word(&img, found[1].at + REQ_DATA), Some(1));
    }

    #[test]
    fn without_markers_the_whole_image() {
        let mut img = alloc::vec![0u8; 16];
        put(&mut img, &[COMMON_MAGIC[0], COMMON_MAGIC[1], id::RSDP[0], id::RSDP[1], 0, 0]);
        let (base, found) = scan(&img);
        assert_eq!((base, found.len(), found[0].at), (None, 1, 16));
    }

    #[test]
    fn layouts() {
        assert_eq!(core::mem::size_of::<File>(), 112);
        assert_eq!(core::mem::size_of::<Framebuffer>(), 64);
        assert_eq!(core::mem::size_of::<MpInfo>(), 32);
        assert_eq!(core::mem::offset_of!(MpInfo, goto_address), MP_GOTO);
    }
}
