// SPDX-License-Identifier: MIT OR Apache-2.0

//! MBR partition tables: the four primary entries of a disk's first
//! sector and the logical partitions of an extended partition.
//!
//! Sources: UEFI Specification 2.10 §5.2.1 (the legacy MBR: boot code,
//! disk signature at 440, four 16-byte partition records at 446, the
//! 0xAA55 signature at 510; the record's type at 4, starting LBA at 8 and
//! size at 12) and §5.2.3 (the protective MBR, type 0xEE, in front of a
//! GPT). Extended partitions (types 0x05, 0x0F, 0x85) hold a chain of
//! extended boot records laid out as an MBR: the first record is a
//! logical partition, relative to that boot record, and the second the
//! next boot record, relative to the extended partition's start; logical
//! partitions are numbered from 5, as Linux shows them (observed with
//! sfdisk and /proc/partitions on the host).

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;

pub const SECTOR: usize = 512;
/// The protective MBR's partition type (UEFI §5.2.3).
pub const TYPE_GPT_PROTECTIVE: u8 = 0xEE;
/// The most extended boot records followed (a loop in the chain stops).
const MAX_LOGICAL: usize = 128;

/// A partition: its number (1 to 4 primary, 5 on logical), type, first
/// sector and length in sectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Partition {
    pub number: u32,
    pub kind: u8,
    pub bootable: bool,
    pub start: u64,
    pub sectors: u64,
}

/// What a disk's first sector holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Table {
    /// No 0xAA55 signature, or no valid entries.
    None,
    /// A protective MBR: the disk has a GPT.
    Gpt,
    /// An MBR: its disk signature and primary entries (empty slots left
    /// out; extended partitions included).
    Mbr { signature: u32, primary: Vec<Partition> },
}

fn is_extended(kind: u8) -> bool {
    matches!(kind, 0x05 | 0x0F | 0x85)
}

/// A partition record: type, bootable, first sector, sectors.
type Record = (u8, bool, u64, u64);

/// The four records of an MBR-shaped sector, with empty ones as `None`;
/// `None` without the 0xAA55 signature.
fn records(sector: &[u8]) -> Option<[Option<Record>; 4]> {
    if sector.len() < SECTOR || sector[510] != 0x55 || sector[511] != 0xAA {
        return None;
    }
    let mut out = [None; 4];
    for (i, r) in out.iter_mut().enumerate() {
        let e = &sector[446 + 16 * i..462 + 16 * i];
        let kind = e[4];
        let start = u64::from(u32::from_le_bytes([e[8], e[9], e[10], e[11]]));
        let size = u64::from(u32::from_le_bytes([e[12], e[13], e[14], e[15]]));
        if kind != 0 && size != 0 {
            *r = Some((kind, e[0] & 0x80 != 0, start, size));
        }
    }
    Some(out)
}

/// Read the first sector of a disk of `disk_sectors` sectors.
pub fn parse(sector: &[u8], disk_sectors: u64) -> Table {
    let Some(recs) = records(sector) else { return Table::None };
    if recs.iter().flatten().any(|r| r.0 == TYPE_GPT_PROTECTIVE) {
        return Table::Gpt;
    }
    let primary: Vec<Partition> = recs
        .iter()
        .enumerate()
        .filter_map(|(i, r)| {
            let (kind, bootable, start, sectors) = (*r)?;
            (start > 0 && start.checked_add(sectors)? <= disk_sectors).then_some(Partition {
                number: i as u32 + 1,
                kind,
                bootable,
                start,
                sectors,
            })
        })
        .collect();
    if primary.is_empty() {
        return Table::None;
    }
    let signature = u32::from_le_bytes([sector[440], sector[441], sector[442], sector[443]]);
    Table::Mbr { signature, primary }
}

/// The logical partitions of `extended`, following its chain of extended
/// boot records with `read` (a sector by number; `None` if it cannot be
/// read). Records outside the extended partition end the chain.
pub fn logical(extended: &Partition, mut read: impl FnMut(u64) -> Option<[u8; SECTOR]>) -> Vec<Partition> {
    let mut out = Vec::new();
    if !is_extended(extended.kind) {
        return out;
    }
    let (base, end) = (extended.start, extended.start + extended.sectors);
    let mut ebr = base;
    for _ in 0..MAX_LOGICAL {
        let Some(sector) = read(ebr) else { break };
        let Some(recs) = records(&sector) else { break };
        if let Some((kind, bootable, rel, sectors)) = recs[0] {
            let start = ebr + rel;
            if rel > 0 && start + sectors <= end {
                out.push(Partition { number: 5 + out.len() as u32, kind, bootable, start, sectors });
            }
        }
        match recs[1] {
            Some((kind, _, rel, _)) if is_extended(kind) && rel > 0 && base + rel < end && base + rel > ebr => {
                ebr = base + rel;
            }
            _ => break,
        }
    }
    out
}

/// Whether a primary partition is an extended one (a container, not a
/// file system).
pub fn extended(p: &Partition) -> bool {
    is_extended(p.kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::vec;

    fn record(s: &mut [u8; SECTOR], slot: usize, kind: u8, start: u32, size: u32) {
        let e = &mut s[446 + 16 * slot..462 + 16 * slot];
        e[4] = kind;
        e[8..12].copy_from_slice(&start.to_le_bytes());
        e[12..16].copy_from_slice(&size.to_le_bytes());
    }

    fn signed() -> [u8; SECTOR] {
        let mut s = [0u8; SECTOR];
        s[510] = 0x55;
        s[511] = 0xAA;
        s
    }

    #[test]
    fn primaries_and_protective() {
        let mut s = signed();
        s[440..444].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        record(&mut s, 0, 0x83, 2048, 4096);
        record(&mut s, 2, 0x07, 8192, 100);
        s[446] = 0x80;
        let Table::Mbr { signature, primary } = parse(&s, 1 << 20) else { panic!() };
        assert_eq!(signature, 0x1234_5678);
        assert_eq!(
            primary,
            vec![
                Partition { number: 1, kind: 0x83, bootable: true, start: 2048, sectors: 4096 },
                Partition { number: 3, kind: 0x07, bootable: false, start: 8192, sectors: 100 },
            ]
        );
        // Past the end of the disk: left out.
        assert!(matches!(parse(&s, 8000), Table::Mbr { primary, .. } if primary.len() == 1));
        let mut p = signed();
        record(&mut p, 0, TYPE_GPT_PROTECTIVE, 1, 0xFFFF_FFFF);
        assert_eq!(parse(&p, 1 << 20), Table::Gpt);
        assert_eq!(parse(&[0u8; SECTOR], 1 << 20), Table::None);
        assert_eq!(parse(&signed(), 1 << 20), Table::None);
    }

    #[test]
    fn logical_partitions() {
        // Extended partition at 8192, 16384 sectors: logical 5 at
        // 8192 + 2048 (2048 sectors), next boot record at 8192 + 6144 with
        // logical 6 at + 2048 (2048 sectors), and a chain end.
        let mut disk: HashMap<u64, [u8; SECTOR]> = HashMap::new();
        let mut e1 = signed();
        record(&mut e1, 0, 0x83, 2048, 2048);
        record(&mut e1, 1, 0x05, 6144, 4096);
        disk.insert(8192, e1);
        let mut e2 = signed();
        record(&mut e2, 0, 0x83, 2048, 2048);
        disk.insert(8192 + 6144, e2);
        let ext = Partition { number: 2, kind: 0x0F, bootable: false, start: 8192, sectors: 16384 };
        let l = logical(&ext, |n| disk.get(&n).copied());
        assert_eq!(
            l,
            vec![
                Partition { number: 5, kind: 0x83, bootable: false, start: 10240, sectors: 2048 },
                Partition { number: 6, kind: 0x83, bootable: false, start: 16384, sectors: 2048 },
            ]
        );
        // A chain pointing back at itself stops.
        let mut lo = signed();
        record(&mut lo, 0, 0x83, 2048, 2048);
        record(&mut lo, 1, 0x05, 0, 4096);
        disk.insert(8192, lo);
        assert_eq!(logical(&ext, |n| disk.get(&n).copied()).len(), 1);
        // Not extended: nothing.
        let plain = Partition { kind: 0x83, ..ext };
        assert!(logical(&plain, |n| disk.get(&n).copied()).is_empty());
    }
}
