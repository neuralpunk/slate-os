// SPDX-License-Identifier: MIT OR Apache-2.0

//! The memory map the kernel gets (ADR 0089): sorted, without overlaps,
//! page-aligned, neighbours of one type merged. Where the firmware's
//! ranges overlap (the framebuffer inside a reserved range), the more
//! restrictive type wins, and the framebuffer over anything but bad memory.

use alloc::vec::Vec;

use crate::paging::PAGE;
use crate::proto::{MemmapEntry, memtype::*};

/// A range of physical memory and its type (`proto::memtype`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub base: u64,
    pub len: u64,
    pub kind: u64,
}

/// Which type wins an overlap: the higher.
fn rank(kind: u64) -> u8 {
    match kind {
        USABLE => 0,
        BOOTLOADER_RECLAIMABLE => 1,
        ACPI_RECLAIMABLE => 2,
        ACPI_NVS => 3,
        EXECUTABLE_AND_MODULES => 4,
        // The framebuffer is often inside a range the firmware calls
        // reserved or I/O.
        FRAMEBUFFER => 6,
        BAD_MEMORY => 7,
        _ => 5,
    }
}

/// Memory the kernel may take for itself, now or after it is done with
/// the loader's data: only whole pages of it count.
fn shrinks(kind: u64) -> bool {
    matches!(kind, USABLE | BOOTLOADER_RECLAIMABLE)
}

/// The direct map holds these (ADR 0089); the kernel maps the rest as it
/// needs it.
pub fn in_direct_map(kind: u64) -> bool {
    matches!(kind, USABLE | BOOTLOADER_RECLAIMABLE | EXECUTABLE_AND_MODULES | ACPI_RECLAIMABLE | ACPI_NVS | FRAMEBUFFER)
}

/// The map from the firmware's ranges, in any order. The first page is
/// never usable: a physical address of 0 reads as a null pointer.
pub fn normalize(regions: &[Region]) -> Vec<MemmapEntry> {
    let mut rs: Vec<Region> = regions
        .iter()
        .filter_map(|r| {
            let end = r.base.checked_add(r.len)?;
            let (base, end) = if shrinks(r.kind) {
                (r.base.div_ceil(PAGE) * PAGE, end / PAGE * PAGE)
            } else {
                (r.base / PAGE * PAGE, end.div_ceil(PAGE) * PAGE)
            };
            (end > base).then_some(Region { base, len: end - base, kind: r.kind })
        })
        .collect();
    rs.push(Region { base: 0, len: PAGE, kind: RESERVED });
    let mut edges: Vec<u64> = rs.iter().flat_map(|r| [r.base, r.base + r.len]).collect();
    edges.sort_unstable();
    edges.dedup();
    let mut out: Vec<MemmapEntry> = Vec::new();
    for w in edges.windows(2) {
        let (a, b) = (w[0], w[1]);
        let Some(kind) =
            rs.iter().filter(|r| r.base <= a && r.base + r.len >= b).map(|r| r.kind).max_by_key(|&k| rank(k))
        else {
            continue;
        };
        match out.last_mut() {
            Some(l) if l.kind == kind && l.base + l.length == a => l.length += b - a,
            _ => out.push(MemmapEntry { base: a, length: b - a, kind }),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(base: u64, len: u64, kind: u64) -> Region {
        Region { base, len, kind }
    }

    #[test]
    fn sorted_merged_aligned() {
        let m = normalize(&[
            r(0x10_0000, 0x10_0000, USABLE),
            r(0, 0xa_0000, USABLE),
            r(0x20_0000, 0x1800, USABLE),
            r(0x30_0800, 0x1000, ACPI_NVS),
        ]);
        let got: Vec<(u64, u64, u64)> = m.iter().map(|e| (e.base, e.length, e.kind)).collect();
        assert_eq!(
            got,
            [
                (0, 0x1000, RESERVED),
                (0x1000, 0x9_f000, USABLE),
                (0x10_0000, 0x10_1000, USABLE),
                (0x30_0000, 0x2000, ACPI_NVS),
            ]
        );
    }

    #[test]
    fn restrictive_types_win() {
        let m = normalize(&[
            r(0x1000, 0x9000, USABLE),
            r(0x4000, 0x2000, RESERVED),
            r(0x8000_0000, 0x100_0000, RESERVED),
            r(0x8000_0000, 0x80_0000, FRAMEBUFFER),
        ]);
        let got: Vec<(u64, u64, u64)> = m.iter().map(|e| (e.base, e.length, e.kind)).collect();
        assert_eq!(
            got,
            [
                (0, 0x1000, RESERVED),
                (0x1000, 0x3000, USABLE),
                (0x4000, 0x2000, RESERVED),
                (0x6000, 0x4000, USABLE),
                (0x8000_0000, 0x80_0000, FRAMEBUFFER),
                (0x8080_0000, 0x80_0000, RESERVED),
            ]
        );
    }
}
