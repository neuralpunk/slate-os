// SPDX-License-Identifier: MIT OR Apache-2.0

//! Literal search: finding a byte or a string fast, and the literal part
//! of a pattern every match must contain (the prefilter: text without it
//! cannot match, and a pattern that is only a literal is found by search
//! alone).

use alloc::vec::Vec;

use crate::{ByteSet, Node};

const LO: u64 = 0x0101_0101_0101_0101;
const HI: u64 = 0x8080_8080_8080_8080;

/// The bytes of `w` equal to the byte repeated in `rep`, as their high
/// bits; the lowest is the first such byte (little-endian).
#[inline]
fn eq_bits(w: u64, rep: u64) -> u64 {
    let x = w ^ rep;
    x.wrapping_sub(LO) & !x & HI
}

#[inline]
fn word(h: &[u8], i: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&h[i..i + 8]);
    u64::from_le_bytes(b)
}

/// The first `n` in `h`, eight bytes at a time.
pub fn memchr(n: u8, h: &[u8]) -> Option<usize> {
    let rep = LO * u64::from(n);
    let mut i = 0;
    while i + 16 <= h.len() {
        let (a, b) = (eq_bits(word(h, i), rep), eq_bits(word(h, i + 8), rep));
        if a | b != 0 {
            return Some(if a != 0 {
                i + (a.trailing_zeros() / 8) as usize
            } else {
                i + 8 + (b.trailing_zeros() / 8) as usize
            });
        }
        i += 16;
    }
    h[i..].iter().position(|&b| b == n).map(|p| i + p)
}

/// The first `a` or `b` in `h`.
pub fn memchr2(a: u8, b: u8, h: &[u8]) -> Option<usize> {
    let (ra, rb) = (LO * u64::from(a), LO * u64::from(b));
    let mut i = 0;
    while i + 8 <= h.len() {
        let w = word(h, i);
        let m = eq_bits(w, ra) | eq_bits(w, rb);
        if m != 0 {
            return Some(i + (m.trailing_zeros() / 8) as usize);
        }
        i += 8;
    }
    h[i..].iter().position(|&c| c == a || c == b).map(|p| i + p)
}

/// How common a byte is in text (higher: more common), to search for the
/// rarest byte of a needle. A rough order of our own: blanks, then the
/// most frequent letters, digits and punctuation, then the rest.
fn commonness(b: u8) -> u8 {
    const LETTERS: &[u8] = b"etaoinsrhldcumfpgwybvkxjqz";
    match b {
        b' ' => 255,
        b'\t' | b'\n' => 240,
        b'a'..=b'z' => 230 - LETTERS.iter().position(|&l| l == b).unwrap_or(25) as u8 * 3,
        b'A'..=b'Z' => 130 - LETTERS.iter().position(|&l| l == b.to_ascii_lowercase()).unwrap_or(25) as u8 * 2,
        b'0'..=b'9' => 140,
        b'.' | b',' | b'_' | b'-' | b'/' | b'=' | b':' | b'"' | b'\'' | b'(' | b')' => 120,
        0x21..=0x7e => 60,
        _ => 20,
    }
}

/// A literal to search for: its bytes (lower case when `fold`), and the
/// offset of its rarest byte, which the search looks for first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Literal {
    pub bytes: Vec<u8>,
    pub fold: bool,
    rare: usize,
}

impl Literal {
    pub fn new(bytes: Vec<u8>, fold: bool) -> Literal {
        let rare = (0..bytes.len()).min_by_key(|&i| commonness(bytes[i])).unwrap_or(0);
        Literal { bytes, fold, rare }
    }

    /// The first place in `h` the literal is.
    pub fn find(&self, h: &[u8]) -> Option<usize> {
        let n = &self.bytes;
        if n.is_empty() {
            return Some(0);
        }
        if h.len() < n.len() {
            return None;
        }
        let r = n[self.rare];
        let (lo, up) = (r, r.to_ascii_uppercase());
        // Where the rare byte can be: its offset in the needle on.
        let mut at = self.rare;
        let last = h.len() - n.len() + self.rare;
        while at <= last {
            let found = if self.fold && lo != up { memchr2(lo, up, &h[at..=last]) } else { memchr(r, &h[at..=last]) };
            let p = at + found?;
            let s = p - self.rare;
            let cand = &h[s..s + n.len()];
            if if self.fold { cand.eq_ignore_ascii_case(n) } else { cand == n.as_slice() } {
                return Some(s);
            }
            at = p + 1;
        }
        None
    }
}

/// The one byte a set holds (with `fold`, the lower case of a letter
/// whose two cases it holds), if that is all it holds.
fn single(s: &ByteSet, fold: bool) -> Option<u8> {
    let mut found = None;
    for b in 0..=255u8 {
        if s.contains(b) {
            let key = if fold { b.to_ascii_lowercase() } else { b };
            match found {
                None => found = Some(key),
                Some(k) if k == key && fold => {}
                Some(_) => return None,
            }
        }
    }
    let k = found?;
    // Folded, a letter must come in both cases (and nothing else).
    if fold && k.is_ascii_alphabetic() && !(s.contains(k) && s.contains(k.to_ascii_uppercase())) {
        return None;
    }
    Some(k)
}

/// The nodes a concatenation is made of, groups opened up (they change
/// what is captured, not what matches).
fn flatten<'a>(n: &'a Node, out: &mut Vec<&'a Node>) {
    match n {
        Node::Concat(v) => v.iter().for_each(|x| flatten(x, out)),
        Node::Group(_, b) => flatten(b, out),
        Node::Empty => {}
        other => out.push(other),
    }
}

/// What the literal analysis found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Analysis {
    /// The longest run of single bytes every match contains.
    pub required: Option<Literal>,
    /// The whole pattern is that literal.
    pub pure: bool,
}

pub(crate) fn analyse(n: &Node, fold: bool) -> Analysis {
    let mut parts = Vec::new();
    flatten(n, &mut parts);
    let mut best: Vec<u8> = Vec::new();
    let mut run: Vec<u8> = Vec::new();
    let mut all_single = true;
    for p in &parts {
        match p {
            Node::Set(s) if single(s, fold).is_some() => run.push(single(s, fold).unwrap_or(0)),
            _ => {
                all_single = false;
                if run.len() > best.len() {
                    best = core::mem::take(&mut run);
                }
                run.clear();
            }
        }
    }
    if run.len() > best.len() {
        best = run;
    }
    let fold = fold && best.iter().any(u8::is_ascii_alphabetic);
    let pure = all_single && !best.is_empty();
    Analysis { required: (!best.is_empty()).then(|| Literal::new(best, fold)), pure }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    #[test]
    fn byte_search() {
        let h: Vec<u8> = (0..100u8).collect();
        for n in [0u8, 7, 8, 15, 16, 17, 63, 99] {
            assert_eq!(memchr(n, &h), Some(n as usize), "{n}");
        }
        assert_eq!(memchr(200, &h), None);
        assert_eq!(memchr2(50, 30, &h), Some(30));
        assert_eq!(memchr(b'x', b""), None);
        // 0x80 next to a match must not confuse the bit trick.
        let h = [0x80u8, 0x81, 1, 0, 0x80, 0x01, 2, 3, 1, 1, 1, 1, 1, 1, 1, 1, 0];
        assert_eq!(memchr(0, &h), Some(3));
        assert_eq!(memchr(2, &h), Some(6));
    }

    #[test]
    fn literal_search() {
        let l = Literal::new(b"zebra".to_vec(), false);
        assert_eq!(l.find(b"a zebra and zebra"), Some(2));
        assert_eq!(l.find(b"zebr"), None);
        assert_eq!(l.find(b"xxxxxxxxxxxxxxxxxxxxxxxxzebra"), Some(24));
        let f = Literal::new(b"error".to_vec(), true);
        assert_eq!(f.find(b"An ERROR here"), Some(3));
        assert_eq!(f.find(b"An ERRO here"), None);
        let aa = Literal::new(b"aab".to_vec(), false);
        assert_eq!(aa.find(b"aaaaaaaaaaaaaaaaaaab"), Some(17));
        assert_eq!(Literal::new(vec![], false).find(b"x"), Some(0));
    }

    #[test]
    fn analysis() {
        let set = |b: &[u8]| {
            let mut s = ByteSet::default();
            for &x in b {
                s.add(x);
            }
            Node::Set(s)
        };
        let n = Node::Concat(vec![
            set(b"f"),
            set(b"o"),
            Node::Repeat(alloc::boxed::Box::new(set(b"0123456789")), 1, None),
            Node::Group(1, alloc::boxed::Box::new(Node::Concat(vec![set(b"b"), set(b"a"), set(b"r")]))),
        ]);
        let a = analyse(&n, false);
        assert_eq!(a.required.unwrap().bytes, b"bar".to_vec());
        assert!(!a.pure);
        let pure = analyse(&Node::Concat(vec![set(b"aA"), set(b"bB")]), true);
        assert!(pure.pure && pure.required.as_ref().unwrap().bytes == b"ab".to_vec() && pure.required.unwrap().fold);
        assert!(analyse(&Node::Concat(vec![set(b"aA")]), false).required.is_none());
        assert!(analyse(&Node::Alt(vec![set(b"a"), set(b"b")]), false).required.is_none());
    }
}
