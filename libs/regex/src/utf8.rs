// SPDX-License-Identifier: MIT OR Apache-2.0

//! Characters in a UTF-8 locale: sets of code points, and the byte
//! sequences that encode them (UTF-8, RFC 3629), so the byte-level
//! matchers match whole characters. A range of code points becomes a few
//! runs of byte ranges, one per encoded length and alignment.

use alloc::vec::Vec;

use crate::{ByteSet, Node};

/// The highest code point, and the surrogates UTF-8 never encodes.
const MAX: u32 = 0x10FFFF;
const SURROGATES: (u32, u32) = (0xD800, 0xDFFF);

/// A set of code points as sorted, disjoint, non-adjacent ranges.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CharSet(pub Vec<(u32, u32)>);

impl CharSet {
    pub fn add(&mut self, c: u32) {
        self.add_range(c, c);
    }

    pub fn add_range(&mut self, lo: u32, hi: u32) {
        self.0.push((lo, hi));
        self.normalize();
    }

    pub fn union(&mut self, o: &CharSet) {
        self.0.extend_from_slice(&o.0);
        self.normalize();
    }

    fn normalize(&mut self) {
        self.0.sort_unstable();
        let mut out: Vec<(u32, u32)> = Vec::with_capacity(self.0.len());
        for &(lo, hi) in &self.0 {
            match out.last_mut() {
                Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
                _ => out.push((lo, hi)),
            }
        }
        self.0 = out;
    }

    /// Every character not in the set (surrogates excepted).
    pub fn negate(&mut self) {
        let mut out = Vec::new();
        let mut next = 0u32;
        for &(lo, hi) in &self.0 {
            if lo > next {
                out.push((next, lo - 1));
            }
            next = hi.saturating_add(1);
        }
        if next <= MAX {
            out.push((next, MAX));
        }
        self.0 = out;
        self.remove(SURROGATES.0, SURROGATES.1);
    }

    pub fn remove(&mut self, lo: u32, hi: u32) {
        let mut out = Vec::new();
        for &(a, b) in &self.0 {
            if b < lo || a > hi {
                out.push((a, b));
                continue;
            }
            if a < lo {
                out.push((a, lo - 1));
            }
            if b > hi {
                out.push((hi + 1, b));
            }
        }
        self.0 = out;
    }

    /// Every character, the surrogates excepted.
    pub fn all() -> CharSet {
        let mut s = CharSet(alloc::vec![(0, MAX)]);
        s.remove(SURROGATES.0, SURROGATES.1);
        s
    }

    /// The characters `f` holds for (all of Unicode, in ranges). Planes 4
    /// to 13 have no characters assigned: one answer stands for them all.
    pub fn of(f: impl Fn(char) -> bool) -> CharSet {
        const EMPTY: (u32, u32) = (0x40000, 0xDFFFF);
        let mut out: Vec<(u32, u32)> = Vec::new();
        let mut push = |lo: u32, hi: u32| match out.last_mut() {
            Some(last) if last.1 + 1 == lo => last.1 = hi,
            _ => out.push((lo, hi)),
        };
        for cp in (0..EMPTY.0).chain(EMPTY.1 + 1..=MAX) {
            if char::from_u32(cp).is_some_and(&f) {
                push(cp, cp);
            }
            if cp == EMPTY.0 - 1 && char::from_u32(EMPTY.0).is_some_and(&f) {
                push(EMPTY.0, EMPTY.1);
            }
        }
        CharSet(out)
    }

    /// Add the other cases of every character (simple, one-character
    /// mappings only).
    pub fn fold_case(&mut self) {
        let mut extra = Vec::new();
        for &(lo, hi) in &self.0 {
            for cp in lo..=hi {
                let Some(c) = char::from_u32(cp) else { continue };
                for other in variants(c) {
                    extra.push((other as u32, other as u32));
                }
            }
        }
        self.0.extend(extra);
        self.normalize();
    }

    /// A node matching one character of the set: one byte set for the
    /// one-byte characters, and for the longer ones a tree of byte ranges
    /// in which encodings that start alike share their start (a class such
    /// as `\w` is a thousand runs, but under forty first bytes).
    pub fn node(&self) -> Node {
        let mut seqs: Vec<Vec<(u8, u8)>> = self.0.iter().flat_map(|&(lo, hi)| sequences(lo, hi)).collect();
        seqs.sort();
        tree(&seqs)
    }
}

/// The node for sorted runs of byte ranges, sharing equal first ranges
/// (first ranges are equal or apart: the runs encode disjoint characters).
fn tree(seqs: &[Vec<(u8, u8)>]) -> Node {
    let set = |(a, b): (u8, u8)| {
        let mut s = ByteSet::default();
        s.add_range(a, b);
        s
    };
    let mut single = ByteSet::default();
    let mut alts: Vec<Node> = Vec::new();
    let mut i = 0;
    while i < seqs.len() {
        let head = seqs[i][0];
        let mut j = i;
        while j < seqs.len() && seqs[j][0] == head {
            j += 1;
        }
        if seqs[i].len() == 1 {
            single.union(&set(head));
        } else {
            let tails: Vec<Vec<(u8, u8)>> = seqs[i..j].iter().map(|s| s[1..].to_vec()).collect();
            alts.push(Node::Concat(alloc::vec![Node::Set(set(head)), tree(&tails)]));
        }
        i = j;
    }
    if !single.is_empty() {
        alts.insert(0, Node::Set(single));
    }
    match alts.len() {
        // An empty set matches nothing.
        0 => Node::Set(ByteSet::default()),
        1 => alts.pop().unwrap_or(Node::Empty),
        _ => Node::Alt(alts),
    }
}

/// The other cases of `c` that are one character each.
pub(crate) fn variants(c: char) -> Vec<char> {
    let mut v = Vec::new();
    let mut one = |mut it: core::char::ToLowercase| {
        if let (Some(x), None) = (it.next(), it.next())
            && x != c
        {
            v.push(x);
        }
    };
    one(c.to_lowercase());
    let mut up = c.to_uppercase();
    if let (Some(x), None) = (up.next(), up.next())
        && x != c
        && !v.contains(&x)
    {
        v.push(x);
    }
    v
}

/// The UTF-8 encoding of `c`.
pub(crate) fn encode(c: char) -> Vec<u8> {
    let mut b = [0u8; 4];
    c.encode_utf8(&mut b).as_bytes().to_vec()
}

/// The character encoded at the start of `p`, and its length.
pub(crate) fn decode(p: &[u8]) -> Option<(char, usize)> {
    let len = match *p.first()? {
        0x00..=0x7F => 1,
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return None,
    };
    let s = core::str::from_utf8(p.get(..len)?).ok()?;
    s.chars().next().map(|c| (c, len))
}

/// The encoded length of code point `c`.
fn width(c: u32) -> usize {
    match c {
        0..=0x7F => 1,
        0x80..=0x7FF => 2,
        0x800..=0xFFFF => 3,
        _ => 4,
    }
}

/// Code points `lo..=hi` as runs of byte ranges: each run is, byte by
/// byte, the ranges its encodings take (every combination valid).
pub(crate) fn sequences(lo: u32, hi: u32) -> Vec<Vec<(u8, u8)>> {
    let mut out = Vec::new();
    let mut stack = alloc::vec![(lo, hi)];
    while let Some((lo, hi)) = stack.pop() {
        if lo > hi {
            continue;
        }
        // Split at the encoded lengths' boundaries.
        if let Some(&b) = [0x7Fu32, 0x7FF, 0xFFFF].iter().find(|&&b| lo <= b && b < hi) {
            stack.push((b + 1, hi));
            stack.push((lo, b));
            continue;
        }
        // Surrogates are never encoded.
        if lo <= SURROGATES.1 && hi >= SURROGATES.0 {
            if hi > SURROGATES.1 {
                stack.push((SURROGATES.1 + 1, hi));
            }
            if lo < SURROGATES.0 {
                stack.push((lo, SURROGATES.0 - 1));
            }
            continue;
        }
        let n = width(lo);
        if n == 1 {
            out.push(alloc::vec![(lo as u8, hi as u8)]);
            continue;
        }
        // Split until the trailing bytes of the range cover their whole
        // span (0x80..=0xBF) wherever the leading ones vary.
        let mut split = false;
        for i in 1..n {
            let m = (1u32 << (6 * i)) - 1;
            if lo & !m != hi & !m {
                if lo & m != 0 {
                    stack.push(((lo | m) + 1, hi));
                    stack.push((lo, lo | m));
                    split = true;
                    break;
                }
                if hi & m != m {
                    stack.push((hi & !m, hi));
                    stack.push((lo, (hi & !m) - 1));
                    split = true;
                    break;
                }
            }
        }
        if split {
            continue;
        }
        let (a, b) = (encode(char::from_u32(lo).unwrap_or('\0')), encode(char::from_u32(hi).unwrap_or('\0')));
        out.push(a.iter().zip(&b).map(|(&x, &y)| (x, y)).collect());
    }
    out.sort();
    out
}

/// A POSIX class over Unicode, as a UTF-8 locale classifies characters.
pub(crate) fn class(name: &[u8]) -> Option<CharSet> {
    let f: fn(char) -> bool = match name {
        b"alpha" => char::is_alphabetic,
        b"digit" => |c| c.is_ascii_digit(),
        b"alnum" => char::is_alphanumeric,
        b"upper" => char::is_uppercase,
        b"lower" => char::is_lowercase,
        b"space" => char::is_whitespace,
        b"blank" => |c| {
            c == ' '
                || c == '\t'
                || (c.is_whitespace() && !matches!(c, '\n'..='\r' | '\u{85}' | '\u{2028}' | '\u{2029}'))
        },
        b"punct" => |c| {
            !c.is_control() && !c.is_alphanumeric() && !c.is_whitespace() && (c as u32 > 0x7F || c.is_ascii_graphic())
        },
        b"print" => |c| !c.is_control(),
        b"graph" => |c| !c.is_control() && !c.is_whitespace(),
        b"cntrl" => char::is_control,
        b"xdigit" => |c| c.is_ascii_hexdigit(),
        _ => return None,
    };
    Some(CharSet::of(f))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every code point in `lo..=hi` encodes to bytes one of the runs
    /// covers, and no other code point does.
    fn check(lo: u32, hi: u32) {
        let seqs = sequences(lo, hi);
        let covered = |bytes: &[u8]| {
            seqs.iter().any(|s| s.len() == bytes.len() && s.iter().zip(bytes).all(|(&(a, b), &x)| a <= x && x <= b))
        };
        for cp in lo.saturating_sub(300)..=(hi + 300).min(MAX) {
            let Some(c) = char::from_u32(cp) else { continue };
            assert_eq!(covered(&encode(c)), (lo..=hi).contains(&cp), "{cp:#x} in {lo:#x}..={hi:#x}: {seqs:?}");
        }
    }

    #[test]
    fn ranges_to_bytes() {
        check(0, 0x7F);
        check(0x41, 0x2000);
        check(0x7F0, 0x1080);
        check(0xD000, 0xE100);
        check(0xFFF0, 0x10100);
        check(0x10FFF0, MAX);
        assert_eq!(sequences(0x80, 0x7FF), alloc::vec![alloc::vec![(0xC2, 0xDF), (0x80, 0xBF)]]);
    }

    #[test]
    fn sets_and_text() {
        let mut s = CharSet::default();
        s.add_range(b'a' as u32, b'c' as u32);
        s.add(0xE9);
        s.fold_case();
        assert_eq!(s.0, alloc::vec![(0x41, 0x43), (0x61, 0x63), (0xC9, 0xC9), (0xE9, 0xE9)]);
        s.negate();
        assert!(!s.0.iter().any(|&(a, b)| a <= 0x61 && 0x61 <= b));
        assert!(!s.0.iter().any(|&(a, b)| a <= 0xD800 && 0xD800 <= b));
        assert_eq!(decode("é!".as_bytes()), Some(('é', 2)));
        assert_eq!(decode(&[0xC3]), None);
        assert_eq!(decode(&[0xFF, 0x41]), None);
        assert_eq!(variants('é'), alloc::vec!['É']);
        assert_eq!(variants('Σ'), alloc::vec!['σ']);
        assert!(variants('ß').is_empty(), "SS is two characters");
        let alpha = class(b"alpha").unwrap();
        assert!(alpha.0.iter().any(|&(a, b)| a <= 0x3B1 && 0x3B1 <= b), "Greek alpha");
    }
}
