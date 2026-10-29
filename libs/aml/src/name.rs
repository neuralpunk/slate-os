// SPDX-License-Identifier: MIT OR Apache-2.0

//! Names (§20.2.2): a NameSeg is four characters, a NameString an optional
//! root or parent prefixes and a path of segments.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{Error, Result};

/// Four characters, `_` padded (§20.2.2: LeadNameChar NameChar NameChar
/// NameChar).
pub type NameSeg = [u8; 4];

/// A parsed NameString.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Path {
    /// Starts at the root (`\`).
    pub root: bool,
    /// Parent prefixes (`^`).
    pub up: usize,
    pub segs: Vec<NameSeg>,
}

impl Path {
    /// A path from ASL-like text: `\_SB.PCI0`, `^^FOO`, `_STA`.
    pub fn parse_text(text: &str) -> Option<Path> {
        let mut s = text.as_bytes();
        let root = s.first() == Some(&b'\\');
        if root {
            s = &s[1..];
        }
        let mut up = 0;
        while s.first() == Some(&b'^') {
            up += 1;
            s = &s[1..];
        }
        let mut segs = Vec::new();
        if !s.is_empty() {
            for part in s.split(|&c| c == b'.') {
                if part.is_empty() || part.len() > 4 {
                    return None;
                }
                let mut seg = *b"____";
                seg[..part.len()].copy_from_slice(part);
                segs.push(seg);
            }
        }
        Some(Path { root, up, segs })
    }

    /// A single segment with no prefix: the one kind of name that is
    /// searched for up the scopes (§5.3).
    pub fn is_single(&self) -> bool {
        !self.root && self.up == 0 && self.segs.len() == 1
    }
}

impl core::fmt::Display for Path {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.root {
            f.write_str("\\")?;
        }
        for _ in 0..self.up {
            f.write_str("^")?;
        }
        for (i, s) in self.segs.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            f.write_str(&seg_text(s))?;
        }
        Ok(())
    }
}

/// A segment as text, trailing `_` padding left in (as ACPI writes it).
pub fn seg_text(s: &NameSeg) -> String {
    s.iter().map(|&c| if c.is_ascii_graphic() { c as char } else { '?' }).collect()
}

/// Whether `b` can start a NameString (§20.2.2: RootChar, ParentPrefix,
/// DualNamePrefix, MultiNamePrefix, LeadNameChar).
pub fn starts_name(b: u8) -> bool {
    matches!(b, b'\\' | b'^' | 0x2E | 0x2F | b'A'..=b'Z' | b'_')
}

/// Parse a NameString at `b[*pos..end]`.
pub fn parse(b: &[u8], pos: &mut usize, end: usize) -> Result<Path> {
    let byte = |p: usize| if p < end { b.get(p).copied().ok_or(Error::Truncated) } else { Err(Error::Truncated) };
    let mut p = *pos;
    let mut path = Path { root: false, up: 0, segs: Vec::new() };
    if byte(p)? == b'\\' {
        path.root = true;
        p += 1;
    } else {
        while byte(p)? == b'^' {
            path.up += 1;
            p += 1;
        }
    }
    let count = match byte(p)? {
        0x00 => {
            p += 1;
            0
        }
        0x2E => {
            p += 1;
            2
        }
        0x2F => {
            let n = byte(p + 1)? as usize;
            p += 2;
            n
        }
        _ => 1,
    };
    for _ in 0..count {
        if p + 4 > end || p + 4 > b.len() {
            return Err(Error::Truncated);
        }
        let seg: NameSeg = b[p..p + 4].try_into().unwrap();
        if !matches!(seg[0], b'A'..=b'Z' | b'_')
            || !seg[1..].iter().all(|c| matches!(c, b'A'..=b'Z' | b'0'..=b'9' | b'_'))
        {
            return Err(Error::BadOpcode(u16::from(seg[0])));
        }
        path.segs.push(seg);
        p += 4;
    }
    *pos = p;
    Ok(path)
}

/// Parse a PkgLength (§20.2.4) at `b[*pos]`: the length it gives counts
/// from its own first byte.
pub fn pkg_length(b: &[u8], pos: &mut usize) -> Result<usize> {
    let lead = *b.get(*pos).ok_or(Error::Truncated)?;
    let extra = usize::from(lead >> 6);
    if extra == 0 {
        *pos += 1;
        return Ok(usize::from(lead & 0x3F));
    }
    let mut len = usize::from(lead & 0x0F);
    for i in 0..extra {
        len |= usize::from(*b.get(*pos + 1 + i).ok_or(Error::Truncated)?) << (4 + 8 * i);
    }
    *pos += 1 + extra;
    Ok(len)
}
