// SPDX-License-Identifier: MIT OR Apache-2.0

//! MediaTek's MT79xx Bluetooth controllers' firmware download (ADR 0176's
//! phase 4): which file a chip wants, the file's sections, and the
//! vendor ("WMT") commands and events that carry it. The kernel's USB
//! driver does the I/O (`kernel/src/drivers/usb/btmtk.rs`).
//!
//! MediaTek documents none of this publicly. The facts are read from
//! Linux v7.2.12's `drivers/bluetooth/btmtk.c` and `btmtk.h` as
//! documentation, under the owner's exception for MediaTek's Bluetooth
//! firmware download (ADR 0176, CLAUDE.md); no code is copied or
//! translated. Each fact cites where it was read.

use alloc::string::String;
use alloc::vec::Vec;

/// The vendor command that carries WMT commands (btmtk.c,
/// `btmtk_usb_hci_wmt_sync`: `__hci_cmd_send(hdev, 0xfc6f, ...)`).
pub const OP_WMT: u16 = 0xFC6F;
/// The event code of WMT answers (btmtk.h, `HCI_EV_WMT`).
pub const EV_WMT: u8 = 0xE4;

// WMT operations (btmtk.h, the first anonymous enum).
pub const WMT_PATCH_DOWNLOAD: u8 = 0x01;
pub const WMT_FUNC_CTRL: u8 = 0x06;
pub const WMT_SEMAPHORE: u8 = 0x17;

/// The chip's registers read through a vendor request (btmtk.c,
/// `btmtk_usb_setup`): its ID, its firmware version and its flavour.
pub const REG_CHIP_ID: u32 = 0x7001_0200;
pub const REG_FW_VERSION: u32 = 0x8002_1004;
pub const REG_FW_FLAVOR: u32 = 0x7001_0020;
/// The endpoint reset option register and the value set after the
/// download (btmtk.h, `MTK_EP_RST_OPT`, `MTK_EP_RST_IN_OUT_OPT`).
pub const REG_EP_RST_OPT: u32 = 0x7401_1890;
pub const EP_RST_IN_OUT: u32 = 0x0001_0001;

/// The USB requests (btmtk.c): reading a chip register (vendor, IN,
/// request 0x63, `btmtk_usb_reg_read`); writing an "uhw" register
/// (request type 0x5E, request 0x02, `btmtk_usb_uhw_reg_write`); asking
/// for a WMT event (vendor, IN, request 0x01, value 48, 64 bytes,
/// `btmtk_usb_submit_wmt_recv_urb`). Each register's address goes as the
/// value (high half) and index (low half).
pub const REQ_REG_READ: (u8, u8) = (0xC0, 0x63);
pub const REQ_UHW_WRITE: (u8, u8) = (0x5E, 0x02);
pub const REQ_WMT_EVENT: (u8, u8, u16, usize) = (0xC0, 0x01, 48, 64);

/// The firmware file a chip wants, under /lib/firmware, from its ID, its
/// firmware version's low byte and its flavour bit (btmtk.c,
/// `btmtk_fw_get_filename`, with `btmtk_usb_setup`'s flavour: bit 7 of
/// the flavour register). None for chips Slate doesn't download to.
pub fn firmware_name(chip: u32, fw_version: u32, flavor: u32) -> Option<String> {
    let n = (fw_version & 0xFF) + 1;
    let alt = flavor & 0x80 != 0;
    Some(match chip {
        0x7961 if alt => alloc::format!("mediatek/BT_RAM_CODE_MT7961_1a_{n:x}_hdr.bin"),
        0x7961 | 0x7922 | 0x7902 => alloc::format!("mediatek/BT_RAM_CODE_MT{chip:04x}_1_{n:x}_hdr.bin"),
        0x7925 => alloc::format!("mediatek/mt7925/BT_RAM_CODE_MT7925_1_{n:x}_hdr.bin"),
        _ => return None,
    })
}

/// The file's layout (btmtk.c: `MTK_FW_ROM_PATCH_HEADER_SIZE` 32, the
/// global descriptor `MTK_FW_ROM_PATCH_GD_SIZE` 64 whose fourth word is
/// the number of sections, then a 64-byte map per section: its type,
/// offset and size, then 52 bytes sent as they are, of which the second
/// word is how much to download).
const HEADER: usize = 32;
const GLOBAL: usize = 64;
const MAP: usize = 64;
const MAP_COMMON: usize = 12;
const MAP_SENT: usize = 52;

/// A section to download: the 52 bytes of its map the chip is told
/// first, and its data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section<'a> {
    pub map: [u8; MAP_SENT],
    pub data: &'a [u8],
}

fn word(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// The firmware's header: its hardware and software versions and build
/// date (btmtk.c, `struct btmtk_patch_header`).
pub fn describe(fw: &[u8]) -> Option<String> {
    let date = core::str::from_utf8(fw.get(..16)?).ok()?.trim_end_matches('\0');
    let hw = u16::from_le_bytes(fw.get(20..22)?.try_into().ok()?);
    let sw = u16::from_le_bytes(fw.get(22..24)?.try_into().ok()?);
    Some(alloc::format!("version {hw:04x}{sw:04x}, built {date}"))
}

/// The sections that have something to download, in order; None if the
/// file is too short for what it says.
pub fn sections(fw: &[u8]) -> Option<Vec<Section<'_>>> {
    let count = word(fw, HEADER + 12)? as usize;
    if count > 64 {
        return None;
    }
    let mut out = Vec::new();
    for i in 0..count {
        let m = HEADER + GLOBAL + MAP * i;
        let offset = word(fw, m + 4)? as usize;
        let size = word(fw, m + MAP_COMMON + 4)? as usize;
        if size == 0 {
            continue;
        }
        let map: [u8; MAP_SENT] = fw.get(m + MAP_COMMON..m + MAP_COMMON + MAP_SENT)?.try_into().ok()?;
        out.push(Section { map, data: fw.get(offset..offset.checked_add(size)?)? });
    }
    Some(out)
}

/// The most a download command carries (btmtk.c,
/// `btmtk_setup_firmware_79xx`: 250 bytes at a time).
pub const BLOCK: usize = 250;

/// Each block of `len` bytes with its flag: 1 the first, 3 the last, 2
/// those between (btmtk.c, `btmtk_setup_firmware_79xx`; a section of one
/// block is "first").
pub fn blocks(len: usize) -> impl Iterator<Item = (u8, core::ops::Range<usize>)> {
    (0..len.div_ceil(BLOCK)).map(move |i| {
        let r = i * BLOCK..((i + 1) * BLOCK).min(len);
        let flag = if i == 0 {
            1
        } else if r.end == len {
            3
        } else {
            2
        };
        (flag, r)
    })
}

/// A WMT command, as the parameters of [`OP_WMT`] (btmtk.h,
/// `struct btmtk_wmt_hdr`: direction 1, the operation, the data's length
/// plus one, a flag; then the data).
pub fn wmt_command(op: u8, flag: u8, data: &[u8]) -> Vec<u8> {
    let mut p = alloc::vec![1, op];
    p.extend_from_slice(&(data.len() as u16 + 1).to_le_bytes());
    p.push(flag);
    p.extend_from_slice(data);
    super::command(OP_WMT, &p)
}

/// What a WMT event says (btmtk.c, `btmtk_usb_hci_wmt_sync`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wmt {
    /// A download (or the first section question): this section isn't
    /// there yet, is being taken, or is there (flag 0, 1, 2).
    Undone,
    InProgress,
    Done,
    /// Function control: on (status 0x404, or a bare acknowledgement with
    /// flag 0), turning on (0x420), or not.
    On,
    TurningOn,
    Off,
}

/// A WMT event (as the event-request answers it: the event code, its
/// length, then the WMT header and any status) for operation `op`; None
/// if it isn't one, or answers another operation.
pub fn parse_wmt_event(b: &[u8], op: u8) -> Option<Wmt> {
    if *b.first()? != EV_WMT || b.len() < 7 || b[3] != op {
        return None;
    }
    let flag = b[6];
    Some(match op {
        WMT_SEMAPHORE => {
            if flag == 2 {
                Wmt::Undone
            } else {
                Wmt::Done
            }
        }
        WMT_PATCH_DOWNLOAD => match flag {
            2 => Wmt::Done,
            1 => Wmt::InProgress,
            _ => Wmt::Undone,
        },
        WMT_FUNC_CTRL => match b.get(7..9).map(|s| u16::from_be_bytes([s[0], s[1]])) {
            None if flag == 0 => Wmt::On,
            None => Wmt::Off,
            Some(0x404) => Wmt::On,
            Some(0x420) => Wmt::TurningOn,
            Some(_) => Wmt::Off,
        },
        _ => Wmt::Done,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        // The development machine's and the reference PC's controllers, as linux-firmware
        // names their files.
        assert_eq!(firmware_name(0x7961, 0x01, 0).as_deref(), Some("mediatek/BT_RAM_CODE_MT7961_1_2_hdr.bin"));
        assert_eq!(firmware_name(0x7961, 0x01, 0x80).as_deref(), Some("mediatek/BT_RAM_CODE_MT7961_1a_2_hdr.bin"));
        assert_eq!(firmware_name(0x7922, 0x00, 0).as_deref(), Some("mediatek/BT_RAM_CODE_MT7922_1_1_hdr.bin"));
        assert_eq!(firmware_name(0x7663, 0, 0), None);
    }

    /// A made-up file of two sections (one empty) in the layout above.
    #[test]
    fn sections_blocks_and_commands() {
        let mut fw = alloc::vec![0u8; 32 + 64 + 2 * 64];
        fw[..15].copy_from_slice(b"20260101120000a");
        fw[20..24].copy_from_slice(&[0x61, 0x79, 0x01, 0x00]);
        fw[32 + 12..32 + 16].copy_from_slice(&2u32.to_le_bytes());
        let data_at = fw.len();
        fw.extend((0..600u32).map(|i| i as u8));
        let m0 = 32 + 64;
        fw[m0 + 4..m0 + 8].copy_from_slice(&(data_at as u32).to_le_bytes());
        fw[m0 + 16..m0 + 20].copy_from_slice(&600u32.to_le_bytes());
        fw[m0 + 12] = 0xAA;
        let s = sections(&fw).unwrap();
        assert_eq!(s.len(), 1, "the empty section is skipped");
        assert_eq!((s[0].map[0], s[0].data.len(), s[0].data[599]), (0xAA, 600, 599u32 as u8));
        assert!(describe(&fw).unwrap().contains("79610001"));
        let b: Vec<_> = blocks(600).collect();
        assert_eq!(b, [(1, 0..250), (2, 250..500), (3, 500..600)]);
        assert_eq!(blocks(100).collect::<Vec<_>>(), [(1, 0..100)]);
        // Too short for its sections.
        assert_eq!(sections(&fw[..data_at + 10]), None);
        assert_eq!(wmt_command(WMT_FUNC_CTRL, 0, &[1]), [1, 0x6F, 0xFC, 6, 1, 6, 2, 0, 0, 1]);
        assert_eq!(parse_wmt_event(&[0xE4, 5, 2, 1, 1, 0, 2], WMT_PATCH_DOWNLOAD), Some(Wmt::Done));
        assert_eq!(parse_wmt_event(&[0xE4, 7, 2, 6, 3, 0, 0, 4, 4], WMT_FUNC_CTRL), Some(Wmt::On));
        assert_eq!(parse_wmt_event(&[0xE4, 5, 2, 6, 1, 0, 0], WMT_FUNC_CTRL), Some(Wmt::On));
        assert_eq!(parse_wmt_event(&[0xE4, 5, 2, 1, 1, 0, 2], WMT_FUNC_CTRL), None, "another operation's");
    }
}
