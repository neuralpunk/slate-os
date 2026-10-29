// SPDX-License-Identifier: MIT OR Apache-2.0

//! The kernel's ELF image (ADR 0089): its loadable segments (ELF-64
//! Object File Format 1.5, program headers), placed in one physically
//! contiguous block in the order of their addresses, as the protocol's
//! executable address response describes it (a physical and a virtual
//! base).

use alloc::vec::Vec;

use slate_elf::{Elf, PF_W, PF_X, PT_LOAD};

use crate::paging::{Flags, PAGE};

/// A segment's pages: where they go, and where they are in the image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub virt: u64,
    pub len: u64,
    /// From the image's start.
    pub offset: u64,
    pub flags: Flags,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// The lowest segment's first page, where the kernel runs.
    pub virt_base: u64,
    /// The image's size, whole pages.
    pub size: u64,
    pub entry: u64,
    pub segments: Vec<Segment>,
    /// How far a position-independent kernel was moved from its link
    /// address (0 for one linked at a fixed address).
    pub slide: u64,
    /// The lowest segment's link address.
    link_base: u64,
}

/// Where a position-independent kernel may go (KASLR, ADR 0095): page by
/// page in the first gigabyte of the top 2 GiB (the kernel code model's
/// range), below what the top gigabyte keeps free.
pub const KASLR_LOW: u64 = 0xffff_ffff_8000_0000;
pub const KASLR_HIGH: u64 = 0xffff_ffff_c000_0000;

// Dynamic section tags and the relocation kind a position-independent
// kernel has (gABI "Dynamic Section", x86-64 psABI §4.4; DT_RELR from the
// gABI's 2022 addition).
const DT_NULL: u64 = 0;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;
const DT_RELRSZ: u64 = 35;
const DT_RELR: u64 = 36;
const R_X86_64_NONE: u32 = 0;
const R_X86_64_RELATIVE: u32 = 8;
const PT_DYNAMIC: u32 = 2;

/// Lay a kernel out: an executable linked for the upper half, its
/// segments not sharing pages. A position-independent one (ET_DYN) goes
/// at a random page of the KASLR range when `random` is given, else where
/// it was linked.
pub fn plan(file: &[u8], random: Option<u64>) -> Result<Plan, &'static str> {
    let elf = Elf::parse(file).map_err(|_| "not an x86-64 ELF executable")?;
    let movable = elf.header.kind == slate_elf::ET_DYN;
    if elf.header.kind != slate_elf::ET_EXEC && !movable {
        return Err("not an executable");
    }
    let mut loads: Vec<_> = elf.program_headers().filter(|p| p.kind == PT_LOAD && p.memsz > 0).collect();
    loads.sort_by_key(|p| p.vaddr);
    let first = loads.first().ok_or("no loadable segments")?;
    let link_base = first.vaddr / PAGE * PAGE;
    if link_base < 0xffff_8000_0000_0000 {
        return Err("not linked for the upper half");
    }
    let mut segments: Vec<Segment> = Vec::new();
    for p in &loads {
        let virt = p.vaddr / PAGE * PAGE;
        let end = p.vaddr.checked_add(p.memsz).ok_or("a segment wraps")?.div_ceil(PAGE) * PAGE;
        if segments.last().is_some_and(|s| s.virt + s.len > virt) {
            return Err("segments share a page");
        }
        segments.push(Segment {
            virt,
            len: end - virt,
            offset: virt - link_base,
            flags: Flags { write: p.flags & PF_W != 0, exec: p.flags & PF_X != 0, uncached: false },
        });
    }
    let last = segments.last().unwrap();
    let size = last.offset + last.len;
    if size > 1 << 30 {
        return Err("larger than 1 GiB");
    }
    let slide = match random {
        Some(r) if movable => {
            let slots = (KASLR_HIGH - KASLR_LOW).checked_sub(size).ok_or("too large to move")? / PAGE + 1;
            (KASLR_LOW + r % slots * PAGE).wrapping_sub(link_base)
        }
        _ => 0,
    };
    for s in &mut segments {
        s.virt = s.virt.wrapping_add(slide);
    }
    Ok(Plan {
        virt_base: link_base.wrapping_add(slide),
        size,
        entry: elf.header.entry.wrapping_add(slide),
        segments,
        slide,
        link_base,
    })
}

/// Copy the segments into `image` (`plan.size` bytes), zeroing the rest,
/// and apply a position-independent kernel's relocations for where it
/// goes.
pub fn load(file: &[u8], plan: &Plan, image: &mut [u8]) -> Result<(), &'static str> {
    image.fill(0);
    let elf = Elf::parse(file).expect("planned");
    for p in elf.program_headers().filter(|p| p.kind == PT_LOAD && p.memsz > 0) {
        let at = (p.vaddr - plan.link_base) as usize;
        let data = elf.segment_data(&p).expect("checked by the parser");
        image[at..at + data.len()].copy_from_slice(data);
    }
    if elf.header.kind != slate_elf::ET_DYN {
        return Ok(());
    }
    let Some(dynamic) = elf.program_headers().find(|p| p.kind == PT_DYNAMIC) else {
        return Err("a position-independent kernel without a dynamic section");
    };
    let word = |image: &[u8], at: u64| -> Result<u64, &'static str> {
        let at = usize::try_from(at.wrapping_sub(plan.link_base)).map_err(|_| "a relocation outside the kernel")?;
        let b = image
            .get(at..at.checked_add(8).ok_or("a relocation outside the kernel")?)
            .ok_or("a relocation outside the kernel")?;
        Ok(u64::from_le_bytes(b.try_into().unwrap()))
    };
    let put = |image: &mut [u8], at: u64, v: u64| -> Result<(), &'static str> {
        let at = usize::try_from(at.wrapping_sub(plan.link_base)).map_err(|_| "a relocation outside the kernel")?;
        image.get_mut(at..at + 8).ok_or("a relocation outside the kernel")?.copy_from_slice(&v.to_le_bytes());
        Ok(())
    };
    let (mut rela, mut relasz, mut relaent, mut relr, mut relrsz) = (0, 0, 24, 0, 0);
    let mut d = dynamic.vaddr;
    loop {
        let (tag, val) = (word(image, d)?, word(image, d + 8)?);
        match tag {
            DT_NULL => break,
            DT_RELA => rela = val,
            DT_RELASZ => relasz = val,
            DT_RELAENT => relaent = val,
            DT_RELR => relr = val,
            DT_RELRSZ => relrsz = val,
            _ => {}
        }
        d += 16;
    }
    if relaent < 24 {
        return Err("relocations of an odd size");
    }
    // Elf64_Rela: offset, info (the type in its low 32 bits), addend. The
    // table's link addresses are read from the image before it is moved.
    let mut at = 0;
    while at + 24 <= relasz {
        let r = rela + at;
        let (offset, info, addend) = (word(image, r)?, word(image, r + 8)?, word(image, r + 16)?);
        match info as u32 {
            R_X86_64_NONE => {}
            R_X86_64_RELATIVE => put(image, offset, addend.wrapping_add(plan.slide))?,
            _ => return Err("a relocation other than a relative one"),
        }
        at += relaent;
    }
    // RELR: an address, then bitmaps of the words after it.
    let (mut next, mut at) = (0u64, 0);
    while at + 8 <= relrsz {
        let e = word(image, relr + at)?;
        if e & 1 == 0 {
            put(image, e, word(image, e)?.wrapping_add(plan.slide))?;
            next = e + 8;
        } else {
            for bit in 0..63 {
                if e >> (bit + 1) & 1 != 0 {
                    let w = next + bit * 8;
                    put(image, w, word(image, w)?.wrapping_add(plan.slide))?;
                }
            }
            next += 63 * 8;
        }
        at += 8;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ELF header and program headers for `segs` (vaddr, offset, filesz,
    /// memsz, flags), followed by the file's data.
    fn elf(segs: &[(u64, u64, u64, u64, u32)], kind: u16, size: usize) -> Vec<u8> {
        let mut f = alloc::vec![0u8; size];
        f[..4].copy_from_slice(b"\x7fELF");
        f[4] = 2;
        f[5] = 1;
        f[6] = 1;
        f[16..18].copy_from_slice(&kind.to_le_bytes());
        f[18..20].copy_from_slice(&62u16.to_le_bytes());
        f[24..32].copy_from_slice(&0xffff_ffff_8000_1000u64.to_le_bytes());
        f[32..40].copy_from_slice(&64u64.to_le_bytes());
        f[54..56].copy_from_slice(&56u16.to_le_bytes());
        f[56..58].copy_from_slice(&(segs.len() as u16).to_le_bytes());
        for (i, &(vaddr, offset, filesz, memsz, flags)) in segs.iter().enumerate() {
            let p = &mut f[64 + 56 * i..64 + 56 * (i + 1)];
            p[0..4].copy_from_slice(&1u32.to_le_bytes());
            p[4..8].copy_from_slice(&flags.to_le_bytes());
            p[8..16].copy_from_slice(&offset.to_le_bytes());
            p[16..24].copy_from_slice(&vaddr.to_le_bytes());
            p[32..40].copy_from_slice(&filesz.to_le_bytes());
            p[40..48].copy_from_slice(&memsz.to_le_bytes());
        }
        f
    }

    const K: u64 = 0xffff_ffff_8000_0000;

    #[test]
    fn segments_in_one_block() {
        let mut f = elf(
            &[(K + 0x1000, 0x1000, 0x10, 0x10, 5), (K, 0x200, 8, 8, 4), (K + 0x2000, 0x2000, 4, 0x3000, 6)],
            2,
            0x3000,
        );
        f[0x1000..0x1010].copy_from_slice(&[0xC3; 16]);
        f[0x2000..0x2004].copy_from_slice(&[1, 2, 3, 4]);
        let p = plan(&f, Some(12345)).unwrap();
        assert_eq!((p.virt_base, p.size, p.entry), (K, 0x5000, K + 0x1000));
        let kinds: Vec<(u64, bool, bool)> =
            p.segments.iter().map(|s| (s.offset, s.flags.write, s.flags.exec)).collect();
        assert_eq!(kinds, [(0, false, false), (0x1000, false, true), (0x2000, true, false)]);
        let mut img = alloc::vec![0xAAu8; p.size as usize];
        load(&f, &p, &mut img).unwrap();
        assert_eq!(&img[0x1000..0x1011], &[0xC3; 16].iter().copied().chain([0]).collect::<Vec<_>>()[..]);
        assert_eq!(&img[0x2000..0x2006], &[1, 2, 3, 4, 0, 0]);
        assert!(img[0x3000..].iter().all(|&b| b == 0));
    }

    /// A position-independent kernel: one segment holding a dynamic section
    /// (at +0x100), a relative relocation (at +0x200) for the word at
    /// +0x300, whose addend points at +0x10.
    #[test]
    fn moved_and_relocated() {
        let mut f = elf(&[(K, 0x1000, 0x400, 0x1000, 6)], 3, 0x1400);
        // A second program header: PT_DYNAMIC over the dynamic section.
        f[56..58].copy_from_slice(&2u16.to_le_bytes());
        let ph = &mut f[120..176];
        ph[0..4].copy_from_slice(&2u32.to_le_bytes());
        ph[8..16].copy_from_slice(&0x1100u64.to_le_bytes());
        ph[16..24].copy_from_slice(&(K + 0x100).to_le_bytes());
        fn put(f: &mut [u8], at: usize, v: u64) {
            f[at..at + 8].copy_from_slice(&v.to_le_bytes());
        }
        for (i, (tag, val)) in
            [(DT_RELA, K + 0x200), (DT_RELASZ, 24), (DT_RELAENT, 24), (DT_NULL, 0)].iter().enumerate()
        {
            put(&mut f, 0x1100 + 16 * i, *tag);
            put(&mut f, 0x1108 + 16 * i, *val);
        }
        put(&mut f, 0x1200, K + 0x300);
        put(&mut f, 0x1208, u64::from(R_X86_64_RELATIVE));
        put(&mut f, 0x1210, K + 0x10);
        // Where it was linked, with no random number.
        let p = plan(&f, None).unwrap();
        assert_eq!((p.virt_base, p.slide), (K, 0));
        // Moved: page-aligned, inside the range, entry and relocation along.
        let p = plan(&f, Some(0x1234_5678)).unwrap();
        assert!(p.virt_base >= KASLR_LOW && p.virt_base + p.size <= KASLR_HIGH);
        assert_eq!(p.virt_base % PAGE, 0);
        assert_ne!(p.slide, 0);
        assert_eq!(p.entry, K + 0x1000 + p.slide);
        let mut img = alloc::vec![0u8; p.size as usize];
        load(&f, &p, &mut img).unwrap();
        assert_eq!(u64::from_le_bytes(img[0x300..0x308].try_into().unwrap()), p.virt_base + 0x10);
        // Other relocations are refused.
        put(&mut f, 0x1208, 1); // R_X86_64_64
        assert!(load(&f, &plan(&f, Some(7)).unwrap(), &mut img).is_err());
    }

    #[test]
    fn refused() {
        assert!(plan(&elf(&[(K, 0, 8, 8, 4)], 1, 0x100), None).is_err());
        assert!(plan(&elf(&[(0x40_0000, 0, 8, 8, 4)], 2, 0x100), None).is_err());
        assert!(plan(&elf(&[(K, 0, 8, 0x1800, 4), (K + 0x1000, 0, 8, 8, 4)], 2, 0x100), None).is_err());
        assert!(plan(b"MZ", None).is_err());
    }
}
