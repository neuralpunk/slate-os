// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a partition (or a whole disk) holds, from its first bytes (ADR
//! 0112): the kernel reads [`PROBE_BYTES`] of every block device and shows
//! the answer in /sys/block, so Disks and Files can say what is there
//! without reading the disks themselves.
//!
//! Each signature is from its format's public description:
//! - SlateFS and SlateCrypt: libs/slatefs/src/layout.rs and
//!   libs/slatecrypt (ADR 0026, ADR 0036);
//! - ext2, ext3 and ext4: the superblock in "ext4 Data Structures and
//!   Algorithms" (the kernel's ext4 documentation), at byte 1024;
//! - FAT12, FAT16 and FAT32: Microsoft's FAT specification (the boot
//!   sector's BPB and its extended fields);
//! - exFAT: Microsoft's exFAT specification (the main boot sector);
//! - NTFS: the boot sector's OEM name and volume serial number, as
//!   documented by Microsoft;
//! - ISO 9660: ECMA-119's primary volume descriptor at sector 16;
//! - swap: the signature at the end of the first 4 KiB page, and the
//!   label and UUID in its header (mkswap(8)).
//!
//! The names in [`Kind::id`] are the ones udev's `ID_FS_TYPE` uses, which
//! programs that read the device database expect.

#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::String;

/// How much of a device [`probe`] looks at (ISO 9660's descriptor ends
/// at 34 KiB).
pub const PROBE_BYTES: usize = 36 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    SlateFs,
    SlateCrypt,
    Ext2,
    Ext3,
    Ext4,
    Fat12,
    Fat16,
    Fat32,
    ExFat,
    Ntfs,
    Iso9660,
    Swap,
}

impl Kind {
    /// udev's `ID_FS_TYPE` name.
    pub fn id(self) -> &'static str {
        match self {
            Kind::SlateFs => "slatefs",
            Kind::SlateCrypt => "slatecrypt",
            Kind::Ext2 => "ext2",
            Kind::Ext3 => "ext3",
            Kind::Ext4 => "ext4",
            Kind::Fat12 | Kind::Fat16 | Kind::Fat32 => "vfat",
            Kind::ExFat => "exfat",
            Kind::Ntfs => "ntfs",
            Kind::Iso9660 => "iso9660",
            Kind::Swap => "swap",
        }
    }

    /// The name people read.
    pub fn name(self) -> &'static str {
        match self {
            Kind::SlateFs => "SlateFS",
            Kind::SlateCrypt => "Encrypted (SlateCrypt)",
            Kind::Ext2 => "ext2",
            Kind::Ext3 => "ext3",
            Kind::Ext4 => "ext4",
            Kind::Fat12 => "FAT12",
            Kind::Fat16 => "FAT16",
            Kind::Fat32 => "FAT32",
            Kind::ExFat => "exFAT",
            Kind::Ntfs => "NTFS",
            Kind::Iso9660 => "ISO 9660",
            Kind::Swap => "Swap",
        }
    }

    /// The kind from its [`Kind::name`] (as /sys shows it).
    pub fn from_name(s: &str) -> Option<Kind> {
        ALL.iter().copied().find(|k| k.name() == s)
    }
}

const ALL: [Kind; 12] = [
    Kind::SlateFs,
    Kind::SlateCrypt,
    Kind::Ext2,
    Kind::Ext3,
    Kind::Ext4,
    Kind::Fat12,
    Kind::Fat16,
    Kind::Fat32,
    Kind::ExFat,
    Kind::Ntfs,
    Kind::Iso9660,
    Kind::Swap,
];

/// What was found: the kind, its label and its UUID (as udev writes
/// them: `ID_FS_LABEL`, `ID_FS_UUID`), empty when it has none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub kind: Kind,
    pub label: String,
    pub uuid: String,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// Text from a fixed field: up to the first NUL, without trailing spaces.
fn text(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from(String::from_utf8_lossy(&b[..end]).trim_end())
}

/// 16 bytes as a UUID: 8-4-4-4-12 hex digits, in the bytes' order.
fn uuid(b: &[u8]) -> String {
    if b.len() < 16 || b.iter().all(|&c| c == 0) {
        return String::new();
    }
    let h = |r: core::ops::Range<usize>| b[r].iter().map(|c| format!("{c:02x}")).collect::<String>();
    format!("{}-{}-{}-{}-{}", h(0..4), h(4..6), h(6..8), h(8..10), h(10..16))
}

/// What `head`, a device's first bytes (up to [`PROBE_BYTES`]), holds.
pub fn probe(head: &[u8]) -> Option<Found> {
    slatecrypt(head)
        .or_else(|| slatefs(head))
        .or_else(|| ext(head))
        .or_else(|| iso9660(head))
        .or_else(|| swap(head))
        .or_else(|| boot_sector(head))
}

fn slatecrypt(b: &[u8]) -> Option<Found> {
    // magic at 0, the UUID at 32 (libs/slatecrypt's header).
    (b.get(..8)? == b"SLCRYPT\0").then(|| Found {
        kind: Kind::SlateCrypt,
        label: String::new(),
        uuid: uuid(&b[32..48]),
    })
}

fn slatefs(b: &[u8]) -> Option<Found> {
    // Two superblock slots, at 0 and 4096: the newer generation (u64 at
    // 24) is the one in use. The UUID is at 64, the label's length at 80
    // and the label after it.
    let slot = |at: usize| -> Option<(u64, &[u8])> {
        let s = b.get(at..at + 4096)?;
        (&s[..8] == b"SLATEFS1").then(|| (u64_at(s, 24).unwrap_or(0), s))
    };
    let s = match (slot(0), slot(4096)) {
        (Some(a), Some(c)) => {
            if c.0 > a.0 {
                c.1
            } else {
                a.1
            }
        }
        (Some(a), None) | (None, Some(a)) => a.1,
        (None, None) => return None,
    };
    let n = usize::from(s[80]).min(63);
    Some(Found { kind: Kind::SlateFs, label: text(&s[81..81 + n]), uuid: uuid(&s[64..80]) })
}

fn ext(b: &[u8]) -> Option<Found> {
    // The superblock at 1024: s_magic 0xEF53 at 0x38, s_feature_compat at
    // 0x5C, s_feature_incompat at 0x60, s_uuid at 0x68, s_volume_name at
    // 0x78.
    let sb = b.get(1024..2048)?;
    if u16_at(sb, 0x38)? != 0xEF53 {
        return None;
    }
    let (compat, incompat) = (u32_at(sb, 0x5C)?, u32_at(sb, 0x60)?);
    // INCOMPAT_EXTENTS 0x40, INCOMPAT_64BIT 0x80, INCOMPAT_FLEX_BG 0x200;
    // COMPAT_HAS_JOURNAL 0x4.
    let kind = if incompat & (0x40 | 0x80 | 0x200) != 0 {
        Kind::Ext4
    } else if compat & 0x4 != 0 {
        Kind::Ext3
    } else {
        Kind::Ext2
    };
    Some(Found { kind, label: text(&sb[0x78..0x88]), uuid: uuid(&sb[0x68..0x78]) })
}

fn iso9660(b: &[u8]) -> Option<Found> {
    // The primary volume descriptor at sector 16 (2048-byte sectors):
    // type 1, "CD001", the volume identifier at 40 (32 characters).
    let d = b.get(32768..34816)?;
    (d[0] == 1 && &d[1..6] == b"CD001").then(|| Found {
        kind: Kind::Iso9660,
        label: text(&d[40..72]),
        uuid: String::new(),
    })
}

fn swap(b: &[u8]) -> Option<Found> {
    // The signature ends the first 4 KiB page; the header after the boot
    // block has the UUID at 1024+12 and the label at 1024+28.
    let sig = b.get(4086..4096)?;
    if sig != b"SWAPSPACE2" && sig != b"SWAP-SPACE" {
        return None;
    }
    Some(Found { kind: Kind::Swap, label: text(&b[1052..1068]), uuid: uuid(&b[1036..1052]) })
}

fn boot_sector(b: &[u8]) -> Option<Found> {
    let s = b.get(..512)?;
    if &s[3..11] == b"EXFAT   " {
        let serial = u32_at(s, 100)?;
        return Some(Found { kind: Kind::ExFat, label: String::new(), uuid: fat_serial(serial) });
    }
    if &s[3..11] == b"NTFS    " {
        return Some(Found { kind: Kind::Ntfs, label: String::new(), uuid: format!("{:016X}", u64_at(s, 72)?) });
    }
    // FAT: a jump at 0, the boot signature, a power-of-two sector size.
    let bps = u16_at(s, 11)?;
    if !matches!(s[0], 0xEB | 0xE9)
        || s[510..512] != [0x55, 0xAA]
        || !(512..=4096).contains(&bps)
        || !bps.is_power_of_two()
    {
        return None;
    }
    let label = |at: usize| {
        let l = text(&s[at..at + 11]);
        if l == "NO NAME" { String::new() } else { l }
    };
    // FAT32: BPB_FATSz16 is 0, "FAT32   " at 82, the label at 71 and the
    // serial at 67. FAT12/16: the type at 54, the label at 43, the serial
    // at 39.
    if u16_at(s, 22)? == 0 && &s[82..90] == b"FAT32   " {
        return Some(Found { kind: Kind::Fat32, label: label(71), uuid: fat_serial(u32_at(s, 67)?) });
    }
    let kind = match &s[54..62] {
        b"FAT12   " => Kind::Fat12,
        b"FAT16   " | b"FAT     " => Kind::Fat16,
        _ => return None,
    };
    Some(Found { kind, label: label(43), uuid: fat_serial(u32_at(s, 39)?) })
}

/// A FAT or exFAT volume serial number as udev writes it: `1A2B-3C4D`.
fn fat_serial(n: u32) -> String {
    format!("{:04X}-{:04X}", n >> 16, n & 0xFFFF)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::vec;

    #[test]
    fn slate_formats() {
        let mut b = vec![0u8; PROBE_BYTES];
        b[..8].copy_from_slice(b"SLCRYPT\0");
        b[32..48].copy_from_slice(&[0x12; 16]);
        let f = probe(&b).unwrap();
        assert_eq!((f.kind, f.uuid.as_str()), (Kind::SlateCrypt, "12121212-1212-1212-1212-121212121212"));
        // Two SlateFS superblocks: the newer one's label.
        let mut b = vec![0u8; PROBE_BYTES];
        for (at, generation, label) in [(0usize, 7u64, "old"), (4096, 9, "slate-root")] {
            b[at..at + 8].copy_from_slice(b"SLATEFS1");
            b[at + 24..at + 32].copy_from_slice(&generation.to_le_bytes());
            b[at + 80] = label.len() as u8;
            b[at + 81..at + 81 + label.len()].copy_from_slice(label.as_bytes());
        }
        let f = probe(&b).unwrap();
        assert_eq!((f.kind, f.label.as_str(), f.uuid.as_str()), (Kind::SlateFs, "slate-root", ""));
        assert_eq!(Kind::from_name(f.kind.name()), Some(Kind::SlateFs));
    }

    #[test]
    fn others() {
        let mut b = vec![0u8; PROBE_BYTES];
        assert_eq!(probe(&b), None);
        // ext4: extents.
        b[1024 + 0x38..1024 + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        b[1024 + 0x60] = 0x40;
        b[1024 + 0x78..1024 + 0x7D].copy_from_slice(b"data\0");
        let f = probe(&b).unwrap();
        assert_eq!((f.kind, f.label.as_str(), f.kind.id()), (Kind::Ext4, "data", "ext4"));
        b[1024 + 0x60] = 0;
        assert_eq!(probe(&b).unwrap().kind, Kind::Ext2);
        b[1024 + 0x5C] = 0x4;
        assert_eq!(probe(&b).unwrap().kind, Kind::Ext3);
        // FAT32.
        let mut b = vec![0u8; 4096];
        b[0] = 0xEB;
        b[11..13].copy_from_slice(&512u16.to_le_bytes());
        b[510] = 0x55;
        b[511] = 0xAA;
        b[67..71].copy_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
        b[71..82].copy_from_slice(b"STICK      ");
        b[82..90].copy_from_slice(b"FAT32   ");
        let f = probe(&b).unwrap();
        assert_eq!(
            (f.kind, f.label.as_str(), f.uuid.as_str(), f.kind.id()),
            (Kind::Fat32, "STICK", "1A2B-3C4D", "vfat")
        );
        // FAT16 without a label.
        b[22] = 9;
        b[39..43].copy_from_slice(&1u32.to_le_bytes());
        b[43..54].copy_from_slice(b"NO NAME    ");
        b[54..62].copy_from_slice(b"FAT16   ");
        let f = probe(&b).unwrap();
        assert_eq!((f.kind, f.label.as_str(), f.uuid.as_str()), (Kind::Fat16, "", "0000-0001"));
        // NTFS and exFAT.
        b[3..11].copy_from_slice(b"NTFS    ");
        assert_eq!(probe(&b).unwrap().kind, Kind::Ntfs);
        b[3..11].copy_from_slice(b"EXFAT   ");
        assert_eq!(probe(&b).unwrap().kind, Kind::ExFat);
        // ISO 9660 and swap.
        let mut b = vec![0u8; PROBE_BYTES];
        b[32768] = 1;
        b[32769..32774].copy_from_slice(b"CD001");
        b[32808..32816].copy_from_slice(b"SLATE   ");
        assert_eq!(probe(&b).map(|f| (f.kind, f.label)), Some((Kind::Iso9660, "SLATE".into())));
        let mut b = vec![0u8; 8192];
        b[4086..4096].copy_from_slice(b"SWAPSPACE2");
        assert_eq!(probe(&b).unwrap().kind, Kind::Swap);
        // Too short to tell.
        assert_eq!(probe(&b[..100]), None);
    }
}
