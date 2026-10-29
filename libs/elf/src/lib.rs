// SPDX-License-Identifier: MIT OR Apache-2.0

//! ELF-64 parsing for loading programs.
//!
//! Structures from the System V gABI ("ELF-64 Object File Format" and the
//! generic ABI chapters 4-5): the file header (e_*) and program headers
//! (p_*). Only what a program loader needs is parsed.

#![no_std]

#[cfg(test)]
extern crate std;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NotElf,
    Not64Bit,
    NotLittleEndian,
    BadVersion,
    WrongMachine,
    NotExecutable,
    Truncated,
    BadProgramHeader,
}

/// Object file types (e_type).
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
/// AMD x86-64 (e_machine).
pub const EM_X86_64: u16 = 62;

/// Segment types (p_type).
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_STACK: u32 = 0x6474_E551;

/// Segment permission flags (p_flags).
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

/// Size of one program header entry we accept.
pub const PHDR_SIZE: usize = 56;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: u16,
    pub entry: u64,
    pub phoff: u64,
    pub phentsize: u16,
    pub phnum: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramHeader {
    pub kind: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

fn t<T>(v: Option<T>) -> Result<T, Error> {
    v.ok_or(Error::Truncated)
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

/// A parsed x86-64 executable or shared object.
///
/// `data` may be only a prefix of the file (enough to hold the file and
/// program headers); `file_len` is the whole file's size, which segment
/// bounds are checked against.
#[derive(Clone, Copy, Debug)]
pub struct Elf<'a> {
    pub data: &'a [u8],
    pub file_len: u64,
    pub header: Header,
}

impl<'a> Elf<'a> {
    /// Parse a complete file held in memory.
    pub fn parse(data: &'a [u8]) -> Result<Elf<'a>, Error> {
        Elf::parse_prefix(data, data.len() as u64)
    }

    /// Bytes of the file needed to parse its headers, given the first 64.
    pub fn headers_len(first64: &[u8]) -> Option<usize> {
        let phoff = u64_at(first64, 32)? as usize;
        let phnum = u16_at(first64, 56)? as usize;
        Some(phoff.checked_add(phnum.checked_mul(PHDR_SIZE)?)?.max(64))
    }

    /// Parse from a prefix of a file of `file_len` bytes.
    pub fn parse_prefix(data: &'a [u8], file_len: u64) -> Result<Elf<'a>, Error> {
        if data.get(..4) != Some(b"\x7fELF") {
            return Err(Error::NotElf);
        }
        let ident = data.get(..16).ok_or(Error::Truncated)?;
        if ident[4] != 2 {
            return Err(Error::Not64Bit); // EI_CLASS = ELFCLASS64
        }
        if ident[5] != 1 {
            return Err(Error::NotLittleEndian); // EI_DATA = ELFDATA2LSB
        }
        if ident[6] != 1 {
            return Err(Error::BadVersion); // EI_VERSION = EV_CURRENT
        }
        let header = Header {
            kind: t(u16_at(data, 16))?,
            entry: t(u64_at(data, 24))?,
            phoff: t(u64_at(data, 32))?,
            phentsize: t(u16_at(data, 54))?,
            phnum: t(u16_at(data, 56))?,
        };
        if t(u16_at(data, 18))? != EM_X86_64 {
            return Err(Error::WrongMachine);
        }
        if header.kind != ET_EXEC && header.kind != ET_DYN {
            return Err(Error::NotExecutable);
        }
        if header.phentsize as usize != PHDR_SIZE {
            return Err(Error::BadProgramHeader);
        }
        let end = header.phoff as usize + header.phnum as usize * PHDR_SIZE;
        if end > data.len() {
            return Err(Error::Truncated);
        }
        let elf = Elf { data, file_len, header };
        for ph in elf.program_headers() {
            if ph.filesz > ph.memsz || ph.offset.checked_add(ph.filesz).is_none_or(|e| e > file_len) {
                return Err(Error::BadProgramHeader);
            }
        }
        Ok(elf)
    }

    pub fn program_headers(&self) -> impl Iterator<Item = ProgramHeader> + 'a {
        let (data, off) = (self.data, self.header.phoff as usize);
        (0..self.header.phnum as usize).map(move |i| {
            let p = &data[off + i * PHDR_SIZE..off + (i + 1) * PHDR_SIZE];
            ProgramHeader {
                kind: u32_at(p, 0).unwrap(),
                flags: u32_at(p, 4).unwrap(),
                offset: u64_at(p, 8).unwrap(),
                vaddr: u64_at(p, 16).unwrap(),
                filesz: u64_at(p, 32).unwrap(),
                memsz: u64_at(p, 40).unwrap(),
                align: u64_at(p, 48).unwrap(),
            }
        })
    }

    /// The bytes a segment loads from the file, if they are in `data`.
    pub fn segment_data(&self, ph: &ProgramHeader) -> Option<&'a [u8]> {
        self.data.get(ph.offset as usize..(ph.offset + ph.filesz) as usize)
    }

    /// Whether the file names a program interpreter (PT_INTERP).
    pub fn has_interpreter(&self) -> bool {
        self.program_headers().any(|p| p.kind == PT_INTERP)
    }

    /// The program interpreter path, without its NUL, if it lies in `data`.
    pub fn interpreter(&self) -> Option<&'a [u8]> {
        let ph = self.program_headers().find(|p| p.kind == PT_INTERP)?;
        let s = self.segment_data(&ph)?;
        Some(s.strip_suffix(&[0]).unwrap_or(s))
    }

    /// Virtual address of the program headers once loaded, if a PT_LOAD
    /// segment covers them (needed for the AT_PHDR auxv entry).
    pub fn phdr_vaddr(&self) -> Option<u64> {
        if let Some(p) = self.program_headers().find(|p| p.kind == PT_PHDR) {
            return Some(p.vaddr);
        }
        let off = self.header.phoff;
        self.program_headers()
            .find(|p| p.kind == PT_LOAD && p.offset <= off && off < p.offset + p.filesz)
            .map(|p| p.vaddr + (off - p.offset))
    }
}

/// One entry of a note segment (gABI "Note Section"): an owner name
/// (without its NUL), a type and the descriptor bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note<'a> {
    pub name: &'a [u8],
    pub kind: u32,
    pub desc: &'a [u8],
}

/// The notes in a PT_NOTE segment's bytes. Each entry is namesz, descsz,
/// type (32-bit words), then the name and the descriptor, each padded to
/// `align` (the segment's p_align: 4, or 8 in some 64-bit files).
/// Iteration stops at the first malformed entry.
pub fn notes(data: &[u8], align: u64) -> impl Iterator<Item = Note<'_>> {
    let align = if align == 8 { 8 } else { 4 };
    let mut at = 0usize;
    core::iter::from_fn(move || {
        let namesz = u32_at(data, at)? as usize;
        let descsz = u32_at(data, at + 4)? as usize;
        let kind = u32_at(data, at + 8)?;
        let name_at = at + 12;
        let desc_at = name_at.checked_add(namesz)?.next_multiple_of(align);
        let end = desc_at.checked_add(descsz)?;
        let name = data.get(name_at..name_at + namesz)?;
        let desc = data.get(desc_at..end)?;
        at = end.next_multiple_of(align);
        Some(Note { name: name.strip_suffix(&[0]).unwrap_or(name), kind, desc })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// A minimal static executable: one PT_LOAD covering the headers.
    fn tiny() -> Vec<u8> {
        let mut f = std::vec![0u8; 64 + PHDR_SIZE + 16];
        f[..4].copy_from_slice(b"\x7fELF");
        f[4] = 2;
        f[5] = 1;
        f[6] = 1;
        f[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        f[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        f[24..32].copy_from_slice(&0x40_1000u64.to_le_bytes());
        f[32..40].copy_from_slice(&64u64.to_le_bytes());
        f[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
        f[56..58].copy_from_slice(&1u16.to_le_bytes());
        let p = &mut f[64..64 + PHDR_SIZE];
        p[0..4].copy_from_slice(&PT_LOAD.to_le_bytes());
        p[4..8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
        p[16..24].copy_from_slice(&0x40_0000u64.to_le_bytes());
        p[32..40].copy_from_slice(&(64 + PHDR_SIZE as u64 + 16).to_le_bytes());
        p[40..48].copy_from_slice(&0x2000u64.to_le_bytes());
        p[48..56].copy_from_slice(&0x1000u64.to_le_bytes());
        f
    }

    #[test]
    fn parses_tiny_executable() {
        let f = tiny();
        let e = Elf::parse(&f).unwrap();
        assert_eq!(e.header.entry, 0x40_1000);
        let phs: Vec<_> = e.program_headers().collect();
        assert_eq!(phs.len(), 1);
        assert_eq!(phs[0].memsz, 0x2000);
        assert_eq!(e.phdr_vaddr(), Some(0x40_0040));
        assert_eq!(e.interpreter(), None);
    }

    #[test]
    fn rejects_bad_files() {
        assert_eq!(Elf::parse(b"hello").unwrap_err(), Error::NotElf);
        let mut f = tiny();
        f[18] = 3; // EM_386
        assert_eq!(Elf::parse(&f).unwrap_err(), Error::WrongMachine);
        let mut f = tiny();
        f[64 + 32..64 + 40].copy_from_slice(&0x10_0000u64.to_le_bytes()); // filesz past the end
        assert_eq!(Elf::parse(&f).unwrap_err(), Error::BadProgramHeader);
    }

    #[test]
    fn parses_prefix_of_larger_file() {
        let mut f = tiny();
        f[64 + 32..64 + 40].copy_from_slice(&0x10_0000u64.to_le_bytes());
        f[64 + 40..64 + 48].copy_from_slice(&0x10_0000u64.to_le_bytes());
        let e = Elf::parse_prefix(&f, 0x20_0000).unwrap();
        assert_eq!(Elf::headers_len(&f), Some(64 + PHDR_SIZE));
        let ph = e.program_headers().next().unwrap();
        assert_eq!(e.segment_data(&ph), None);
    }

    #[test]
    fn parses_host_binary_if_present() {
        // Any real x86-64 executable on the build host is a good smoke test.
        if let Ok(data) = std::fs::read("/bin/sh") {
            let e = Elf::parse(&data).unwrap();
            assert!(e.program_headers().any(|p| p.kind == PT_LOAD));
        }
    }

    #[test]
    fn reads_notes() {
        let mut seg = Vec::new();
        // "GNU" note with an 8-byte descriptor, then "Slate" with 4 bytes.
        for (name, kind, desc) in [(&b"GNU\0"[..], 3u32, &[1u8; 8][..]), (b"Slate\0", 1, &[1, 0, 0, 0])] {
            seg.extend((name.len() as u32).to_le_bytes());
            seg.extend((desc.len() as u32).to_le_bytes());
            seg.extend(kind.to_le_bytes());
            seg.extend(name);
            seg.resize(seg.len().next_multiple_of(4), 0);
            seg.extend(desc);
        }
        let n: Vec<_> = notes(&seg, 4).collect();
        assert_eq!(n.len(), 2);
        assert_eq!(n[1], Note { name: b"Slate", kind: 1, desc: &[1, 0, 0, 0] });
        // A truncated entry ends the list.
        assert_eq!(notes(&seg[..seg.len() - 1], 4).count(), 1);
    }
}
