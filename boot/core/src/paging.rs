// SPDX-License-Identifier: MIT OR Apache-2.0

//! The page tables the kernel starts on (ADR 0089): 4-level paging (Intel
//! SDM vol. 3A §4.5), the direct map and the kernel's image in the upper
//! half, nothing in the lower half. Built over [`Frames`], so the host
//! tests run it on plain memory.

/// Page-table entry bits (SDM vol. 3A §4.5, tables 4-15 to 4-20).
const PRESENT: u64 = 1;
const WRITE: u64 = 1 << 1;
const PWT: u64 = 1 << 3;
const PCD: u64 = 1 << 4;
const HUGE: u64 = 1 << 7;
const NO_EXEC: u64 = 1 << 63;
const ADDR: u64 = 0x000f_ffff_ffff_f000;

pub const PAGE: u64 = 4096;
const SIZE_2M: u64 = 2 << 20;
const SIZE_1G: u64 = 1 << 30;

/// Where page tables come from.
pub trait Frames {
    /// A zeroed 4 KiB frame.
    fn alloc(&mut self) -> Option<u64>;
    /// The table in the frame at `phys`.
    fn table(&mut self, phys: u64) -> &mut [u64; 512];
}

/// How a range is mapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flags {
    pub write: bool,
    pub exec: bool,
    /// Uncached (PCD and PWT: the PAT's entry 3, UC, at its power-on
    /// value, SDM vol. 3A §12.12.4), for memory-mapped I/O.
    pub uncached: bool,
}

impl Flags {
    pub const RWX: Flags = Flags { write: true, exec: true, uncached: false };

    fn bits(self) -> u64 {
        let mut b = PRESENT;
        if self.write {
            b |= WRITE;
        }
        if !self.exec {
            b |= NO_EXEC;
        }
        if self.uncached {
            b |= PCD | PWT;
        }
        b
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    OutOfMemory,
    /// The range is already mapped differently.
    Conflict(u64),
    Unaligned,
}

/// A set of tables: the root's physical address.
#[derive(Clone, Copy, Debug)]
pub struct Tables {
    pub root: u64,
    /// 1 GiB pages may be used (CPUID 80000001h:EDX[26]).
    pub gigabyte_pages: bool,
}

fn index(virt: u64, level: u32) -> usize {
    ((virt >> (12 + 9 * level)) & 0x1ff) as usize
}

impl Tables {
    pub fn new(f: &mut dyn Frames, gigabyte_pages: bool) -> Result<Tables, Error> {
        Ok(Tables { root: f.alloc().ok_or(Error::OutOfMemory)?, gigabyte_pages })
    }

    /// The table one level down from entry `i` of `table`, made if missing.
    fn next(f: &mut dyn Frames, table: u64, i: usize, virt: u64) -> Result<u64, Error> {
        let e = f.table(table)[i];
        if e & PRESENT != 0 {
            if e & HUGE != 0 {
                return Err(Error::Conflict(virt));
            }
            return Ok(e & ADDR);
        }
        let t = f.alloc().ok_or(Error::OutOfMemory)?;
        f.table(table)[i] = t | PRESENT | WRITE;
        Ok(t)
    }

    /// Map `len` bytes at `virt` to `phys`, with the largest pages that
    /// fit. Mapping a page again the same way is allowed.
    pub fn map(&mut self, f: &mut dyn Frames, virt: u64, phys: u64, len: u64, flags: Flags) -> Result<(), Error> {
        if virt % PAGE != 0 || phys % PAGE != 0 || len % PAGE != 0 {
            return Err(Error::Unaligned);
        }
        let mut done = 0;
        while done < len {
            let (v, p, left) = (virt + done, phys + done, len - done);
            let fits = |size: u64| v % size == 0 && p % size == 0 && left >= size;
            let (level, size) = if self.gigabyte_pages && fits(SIZE_1G) {
                (2, SIZE_1G)
            } else if fits(SIZE_2M) {
                (1, SIZE_2M)
            } else {
                (0, PAGE)
            };
            let mut table = self.root;
            for l in (level + 1..=3).rev() {
                table = Self::next(f, table, index(v, l), v)?;
            }
            let entry = p | flags.bits() | if level > 0 { HUGE } else { 0 };
            let slot = &mut f.table(table)[index(v, level)];
            if *slot & PRESENT != 0 && *slot != entry {
                return Err(Error::Conflict(v));
            }
            *slot = entry;
            done += size;
        }
        Ok(())
    }

    /// The physical address `virt` maps to, if any.
    pub fn translate(&self, f: &mut dyn Frames, virt: u64) -> Option<u64> {
        let mut table = self.root;
        for level in (0..=3).rev() {
            let e = f.table(table)[index(virt, level)];
            if e & PRESENT == 0 {
                return None;
            }
            if level == 0 || e & HUGE != 0 {
                let size = PAGE << (9 * level);
                return Some((e & ADDR & !(size - 1)) + (virt & (size - 1)));
            }
            table = e & ADDR;
        }
        None
    }

    /// These tables with their upper half also seen in the lower half: the
    /// direct map at `0xffff800000000000` becomes a one-to-one map, so code
    /// running at physical addresses can switch to them and jump to its
    /// direct-map alias (ADR 0089).
    pub fn with_identity(&self, f: &mut dyn Frames) -> Result<Tables, Error> {
        let root = f.alloc().ok_or(Error::OutOfMemory)?;
        let upper: [u64; 512] = *f.table(self.root);
        let t = f.table(root);
        t.copy_from_slice(&upper);
        t[..256].copy_from_slice(&upper[256..]);
        Ok(Tables { root, gigabyte_pages: self.gigabyte_pages })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Frames from a vector: frame `n` is at `BASE + n * 4096`.
    #[derive(Debug)]
    pub struct Arena(pub Vec<[u64; 512]>);
    const BASE: u64 = 0x10_0000;

    impl Frames for Arena {
        fn alloc(&mut self) -> Option<u64> {
            self.0.push([0; 512]);
            Some(BASE + (self.0.len() as u64 - 1) * PAGE)
        }
        fn table(&mut self, phys: u64) -> &mut [u64; 512] {
            &mut self.0[((phys - BASE) / PAGE) as usize]
        }
    }

    #[test]
    fn largest_pages_that_fit() {
        let mut f = Arena(Vec::new());
        let mut t = Tables::new(&mut f, true).unwrap();
        let hhdm = crate::proto::HHDM;
        // 4 KiB at the edges, 2 MiB pages, a 1 GiB page in the middle.
        t.map(&mut f, hhdm + 0x1ff000, 0x1ff000, (2 << 30) - 0x1ff000 + PAGE, Flags::RWX).unwrap();
        assert_eq!(t.translate(&mut f, hhdm + 0x1ff123), Some(0x1ff123));
        assert_eq!(t.translate(&mut f, hhdm + (1 << 30) + 5), Some((1 << 30) + 5));
        assert_eq!(t.translate(&mut f, hhdm + (2 << 30)), Some(2 << 30));
        assert_eq!(t.translate(&mut f, hhdm + (2 << 30) + PAGE), None);
        assert_eq!(t.translate(&mut f, 0x1ff000), None);
        // Root, PDPT, two page directories, two page tables.
        assert_eq!(f.0.len(), 6);
        // The same again is fine; another target is not.
        t.map(&mut f, hhdm + (1 << 30), 1 << 30, 1 << 30, Flags::RWX).unwrap();
        assert_eq!(
            t.map(&mut f, hhdm + 0x200000, 0x400000, SIZE_2M, Flags::RWX),
            Err(Error::Conflict(hhdm + 0x200000))
        );
    }

    #[test]
    fn identity_alias_and_flags() {
        let mut f = Arena(Vec::new());
        let mut t = Tables::new(&mut f, false).unwrap();
        let ro = Flags { write: false, exec: false, uncached: false };
        t.map(&mut f, crate::proto::HHDM + 0x5000, 0x5000, PAGE, ro).unwrap();
        t.map(&mut f, 0xffff_ffff_8000_0000, 0x20_0000, SIZE_2M, Flags::RWX).unwrap();
        let both = t.with_identity(&mut f).unwrap();
        assert_eq!(both.translate(&mut f, 0x5000), Some(0x5000));
        assert_eq!(both.translate(&mut f, crate::proto::HHDM + 0x5000), Some(0x5000));
        assert_eq!(both.translate(&mut f, 0xffff_ffff_8000_1000), Some(0x20_1000));
        assert_eq!(t.translate(&mut f, 0x5000), None);
        let pte = {
            let pdpt = f.table(t.root)[256] & ADDR;
            let pd = f.table(pdpt)[0] & ADDR;
            let pt = f.table(pd)[0] & ADDR;
            f.table(pt)[5]
        };
        assert_eq!(pte, 0x5000 | PRESENT | NO_EXEC);
    }
}
