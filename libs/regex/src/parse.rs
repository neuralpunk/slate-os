// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pattern syntax (XBD §9.3 BREs, §9.4 EREs, §9.3.5 bracket expressions)
//! into a [`Node`] tree.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::utf8::{self, CharSet};
use crate::{ByteSet, Error, Look, Node, Options, Syntax};

/// RE_DUP_MAX (XBD <limits.h>).
const DUP_MAX: u32 = 32767;

fn err<T>(m: &str) -> Result<T, Error> {
    Err(Error(String::from(m)))
}

const UNMATCHED_BRACKET: &str = "Unmatched [, [^, [:, [., or [=";

pub(crate) fn parse(p: &[u8], o: Options) -> Result<(Node, usize), Error> {
    let mut ps = P { p, i: 0, o, groups: 0, closed: vec![false], depth: 0 };
    let n = ps.alt()?;
    if ps.i < p.len() {
        // Only an unmatched close can stop the top level.
        return err("Unmatched ) or \\)");
    }
    Ok((n, ps.groups))
}

struct P<'a> {
    p: &'a [u8],
    i: usize,
    o: Options,
    groups: usize,
    /// Which groups are closed (back-references may only name those).
    closed: Vec<bool>,
    depth: usize,
}

/// One character in a UTF-8 pattern: its bytes, or with `icase` any of
/// its cases.
pub(crate) fn char_node(c: char, icase: bool) -> Node {
    if icase && !utf8::variants(c).is_empty() {
        let mut s = CharSet::default();
        s.add(c as u32);
        s.fold_case();
        return s.node();
    }
    Node::Concat(utf8::encode(c).into_iter().map(|b| byte(b, false)).collect())
}

/// A set holding one byte (both cases when ignoring case).
pub(crate) fn byte(b: u8, icase: bool) -> Node {
    let mut s = ByteSet::default();
    s.add(b);
    if icase {
        s.fold_case();
    }
    Node::Set(s)
}

pub(crate) fn class_set(name: &[u8]) -> Option<ByteSet> {
    let f: fn(u8) -> bool = match name {
        b"alpha" => |c| c.is_ascii_alphabetic(),
        b"digit" => |c| c.is_ascii_digit(),
        b"alnum" => |c| c.is_ascii_alphanumeric(),
        b"upper" => |c| c.is_ascii_uppercase(),
        b"lower" => |c| c.is_ascii_lowercase(),
        b"space" => |c| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 11 | 12),
        b"blank" => |c| c == b' ' || c == b'\t',
        b"punct" => |c| c.is_ascii_punctuation(),
        b"print" => |c| (32..127).contains(&c),
        b"graph" => |c| (33..127).contains(&c),
        b"cntrl" => |c| c < 32 || c == 127,
        b"xdigit" => |c| c.is_ascii_hexdigit(),
        _ => return None,
    };
    let mut s = ByteSet::default();
    for b in 0..=255u8 {
        if f(b) {
            s.add(b);
        }
    }
    Some(s)
}

impl P<'_> {
    fn ere(&self) -> bool {
        self.o.syntax == Syntax::Extended
    }

    fn at(&self, k: usize) -> Option<u8> {
        self.p.get(self.i + k).copied()
    }

    fn at_alt(&self) -> bool {
        if self.ere() { self.at(0) == Some(b'|') } else { self.at(0) == Some(b'\\') && self.at(1) == Some(b'|') }
    }

    fn at_close(&self) -> bool {
        if self.ere() { self.at(0) == Some(b')') } else { self.at(0) == Some(b'\\') && self.at(1) == Some(b')') }
    }

    fn alt(&mut self) -> Result<Node, Error> {
        let mut alts = vec![self.concat()?];
        while self.at_alt() {
            self.i += if self.ere() { 1 } else { 2 };
            alts.push(self.concat()?);
        }
        Ok(if alts.len() == 1 { alts.pop().unwrap() } else { Node::Alt(alts) })
    }

    fn concat(&mut self) -> Result<Node, Error> {
        let mut items: Vec<Node> = Vec::new();
        while self.i < self.p.len() && !self.at_alt() && !(self.at_close() && self.depth > 0) {
            if self.at_close() && !self.ere() {
                return err("Unmatched ) or \\)");
            }
            let after_anchor = items.last() == Some(&Node::Look(Look::LineStart));
            let atom = self.atom(!self.ere() && (items.is_empty() || after_anchor), items.is_empty())?;
            // In a BRE, `*` right after a leading `^` is ordinary.
            let atom = if atom == Node::Look(Look::LineStart) && !self.ere() { atom } else { self.repeats(atom)? };
            items.push(atom);
        }
        Ok(match items.len() {
            0 => Node::Empty,
            1 => items.pop().unwrap(),
            _ => Node::Concat(items),
        })
    }

    /// Whether a BRE `$` here ends the expression (an anchor).
    fn bre_dollar_anchors(&self) -> bool {
        let rest = &self.p[self.i + 1..];
        rest.is_empty() || (self.depth > 0 && rest.starts_with(b"\\)")) || rest.starts_with(b"\\|")
    }

    /// One atom. `star_literal`: a `*` here is an ordinary character (BRE
    /// start, after `^`); `first`: first in its branch.
    fn atom(&mut self, star_literal: bool, first: bool) -> Result<Node, Error> {
        let c = self.p[self.i];
        let icase = self.o.icase;
        match c {
            b'.' if self.o.utf8 => {
                self.i += 1;
                let mut s = CharSet::all();
                if self.o.newline {
                    s.remove(10, 10);
                }
                Ok(s.node())
            }
            b'.' => {
                self.i += 1;
                let mut s = ByteSet::default();
                s.negate();
                if self.o.newline {
                    s.0[0] &= !(1 << b'\n');
                }
                Ok(Node::Set(s))
            }
            b'[' if self.o.utf8 => self.bracket_utf8(),
            b'[' => self.bracket(),
            b'^' if self.ere() || first => {
                self.i += 1;
                Ok(Node::Look(Look::LineStart))
            }
            b'$' if self.ere() || self.bre_dollar_anchors() => {
                self.i += 1;
                Ok(Node::Look(Look::LineEnd))
            }
            b'*' if star_literal => {
                self.i += 1;
                Ok(byte(b'*', icase))
            }
            // A leading repetition operator in an ERE applies to nothing
            // (GNU ignores it, with a warning).
            b'*' | b'+' | b'?' if self.ere() => {
                self.i += 1;
                Ok(Node::Empty)
            }
            // So does a leading interval; a `{` that starts none is literal.
            b'{' if self.ere() && first => {
                let save = self.i;
                self.i += 1;
                if self.interval().is_ok() {
                    return Ok(Node::Empty);
                }
                self.i = save + 1;
                Ok(byte(c, icase))
            }
            b'(' if self.ere() => {
                self.i += 1;
                self.group()
            }
            // An unmatched `)` is ordinary in an ERE (XBD §9.4.3).
            b'\\' => self.escape(first),
            0x80..
                if self.o.utf8
                    && let Some((ch, len)) = utf8::decode(&self.p[self.i..]) =>
            {
                self.i += len;
                Ok(char_node(ch, icase))
            }
            _ => {
                self.i += 1;
                Ok(byte(c, icase))
            }
        }
    }

    fn group(&mut self) -> Result<Node, Error> {
        self.groups += 1;
        let idx = self.groups;
        self.closed.push(false);
        self.depth += 1;
        let inner = self.alt()?;
        self.depth -= 1;
        if !self.at_close() {
            return err("Unmatched ( or \\(");
        }
        self.i += if self.ere() { 1 } else { 2 };
        self.closed[idx] = true;
        Ok(Node::Group(idx, Box::new(inner)))
    }

    fn escape(&mut self, first: bool) -> Result<Node, Error> {
        let Some(e) = self.at(1) else { return err("Trailing backslash") };
        self.i += 2;
        let icase = self.o.icase;
        let set = |f: fn(u8) -> bool, neg: bool| {
            let mut s = ByteSet::default();
            for b in 0..=255u8 {
                if f(b) != neg {
                    s.add(b);
                }
            }
            Node::Set(s)
        };
        let space = |c: u8| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 11 | 12);
        if self.o.utf8 && matches!(e, b'w' | b'W' | b's' | b'S') {
            let mut s = match e {
                b'w' | b'W' => CharSet::of(|c| c.is_alphanumeric() || c == '_'),
                _ => CharSet::of(char::is_whitespace),
            };
            if e.is_ascii_uppercase() {
                s.negate();
            }
            return Ok(s.node());
        }
        Ok(match e {
            b'(' if !self.ere() => return self.group(),
            b'{' if !self.ere() && first => return err("Invalid preceding regular expression"),
            b'1'..=b'9' => {
                let n = (e - b'0') as usize;
                if !self.closed.get(n).copied().unwrap_or(false) {
                    return err("Invalid back reference");
                }
                Node::Backref(n)
            }
            b'w' => set(crate::is_word, false),
            b'W' => set(crate::is_word, true),
            b's' => set(space, false),
            b'S' => set(space, true),
            b'b' => Node::Look(Look::Word),
            b'B' => Node::Look(Look::NotWord),
            b'<' => Node::Look(Look::WordStart),
            b'>' => Node::Look(Look::WordEnd),
            b'`' => Node::Look(Look::TextStart),
            b'\'' => Node::Look(Look::TextEnd),
            b'n' => byte(b'\n', icase),
            b't' if self.o.escapes => byte(b'\t', icase),
            b'r' if self.o.escapes => byte(b'\r', icase),
            b'f' if self.o.escapes => byte(12, icase),
            b'v' if self.o.escapes => byte(11, icase),
            b'a' if self.o.escapes => byte(7, icase),
            _ => byte(e, icase),
        })
    }

    /// Repetition operators after an atom.
    fn repeats(&mut self, mut atom: Node) -> Result<Node, Error> {
        loop {
            let (min, max) = match (self.at(0), self.at(1)) {
                (Some(b'*'), _) => {
                    self.i += 1;
                    (0, None)
                }
                (Some(b'+'), _) if self.ere() => {
                    self.i += 1;
                    (1, None)
                }
                (Some(b'?'), _) if self.ere() => {
                    self.i += 1;
                    (0, Some(1))
                }
                (Some(b'\\'), Some(b'+')) if !self.ere() => {
                    self.i += 2;
                    (1, None)
                }
                (Some(b'\\'), Some(b'?')) if !self.ere() => {
                    self.i += 2;
                    (0, Some(1))
                }
                (Some(b'\\'), Some(b'{')) if !self.ere() => {
                    self.i += 2;
                    self.interval()?
                }
                (Some(b'{'), _) if self.ere() => {
                    // `{` that does not start a valid interval is literal (GNU).
                    let save = self.i;
                    self.i += 1;
                    match self.interval() {
                        Ok(r) => r,
                        Err(_) => {
                            self.i = save;
                            return Ok(atom);
                        }
                    }
                }
                _ => return Ok(atom),
            };
            if max.is_some_and(|m| m < min) {
                return err("Invalid content of \\{\\}");
            }
            if min > DUP_MAX || max.is_some_and(|m| m > DUP_MAX) {
                return err("Regular expression too big");
            }
            atom = Node::Repeat(Box::new(atom), min, max);
        }
    }

    /// `m`, `m,`, `m,n` (or `,n`) and the closing brace.
    fn interval(&mut self) -> Result<(u32, Option<u32>), Error> {
        let num = |ps: &mut P<'_>| -> Option<u32> {
            let s = ps.i;
            while ps.at(0).is_some_and(|c| c.is_ascii_digit()) {
                ps.i += 1;
            }
            if s == ps.i {
                return None;
            }
            core::str::from_utf8(&ps.p[s..ps.i]).ok()?.parse().ok().or(Some(u32::MAX))
        };
        let min = num(self);
        let max = if self.at(0) == Some(b',') {
            self.i += 1;
            num(self)
        } else {
            Some(min.ok_or_else(|| Error(String::from("Invalid content of \\{\\}")))?)
        };
        let close: &[u8] = if self.ere() { b"}" } else { b"\\}" };
        if !self.p[self.i..].starts_with(close) {
            return if self.i >= self.p.len() { err("Unmatched \\{") } else { err("Invalid content of \\{\\}") };
        }
        self.i += close.len();
        Ok((min.unwrap_or(0), max))
    }

    /// A bracket expression, `p[i]` being `[`.
    fn bracket(&mut self) -> Result<Node, Error> {
        self.i += 1;
        let mut set = ByteSet::default();
        let negate = self.at(0) == Some(b'^');
        if negate {
            self.i += 1;
        }
        if self.i >= self.p.len() {
            return err("Invalid regular expression");
        }
        let mut first = true;
        loop {
            let Some(c) = self.at(0) else { return err(UNMATCHED_BRACKET) };
            if c == b']' && !first {
                self.i += 1;
                break;
            }
            first = false;
            // [:class:], [=c=], [.c.]
            if c == b'['
                && let Some(kind @ (b':' | b'=' | b'.')) = self.at(1)
            {
                let start = self.i + 2;
                let mut k = start;
                while k + 1 < self.p.len() && !(self.p[k] == kind && self.p[k + 1] == b']') {
                    k += 1;
                }
                if k + 1 >= self.p.len() {
                    return err(UNMATCHED_BRACKET);
                }
                let name = &self.p[start..k];
                self.i = k + 2;
                match kind {
                    b':' => match class_set(name) {
                        Some(s) => set.union(&s),
                        None => return err("Invalid character class name"),
                    },
                    _ => {
                        if name.len() != 1 {
                            return err("Invalid collation character");
                        }
                        self.range_or_char(name[0], &mut set)?;
                    }
                }
                continue;
            }
            self.i += 1;
            self.range_or_char(c, &mut set)?;
        }
        if self.o.icase {
            set.fold_case();
        }
        if negate {
            set.negate();
            if self.o.newline {
                set.0[0] &= !(1 << b'\n');
            }
        }
        Ok(Node::Set(set))
    }

    /// The character at `i` (a byte that starts none counts as itself).
    fn char_at(&self, i: usize) -> Option<(u32, usize)> {
        let b = *self.p.get(i)?;
        Some(match utf8::decode(&self.p[i..]) {
            Some((c, len)) => (c as u32, len),
            None => (u32::from(b), 1),
        })
    }

    /// A bracket expression in a UTF-8 pattern: its members are
    /// characters, ranges run by code point (as in C.UTF-8), and classes
    /// are Unicode's.
    fn bracket_utf8(&mut self) -> Result<Node, Error> {
        self.i += 1;
        let mut set = CharSet::default();
        let negate = self.at(0) == Some(b'^');
        if negate {
            self.i += 1;
        }
        if self.i >= self.p.len() {
            return err("Invalid regular expression");
        }
        let mut first = true;
        loop {
            let Some(c) = self.at(0) else { return err(UNMATCHED_BRACKET) };
            if c == b']' && !first {
                self.i += 1;
                break;
            }
            first = false;
            let lo = if c == b'['
                && let Some(kind @ (b':' | b'=' | b'.')) = self.at(1)
            {
                let start = self.i + 2;
                let mut k = start;
                while k + 1 < self.p.len() && !(self.p[k] == kind && self.p[k + 1] == b']') {
                    k += 1;
                }
                if k + 1 >= self.p.len() {
                    return err(UNMATCHED_BRACKET);
                }
                let name = &self.p[start..k];
                self.i = k + 2;
                if kind == b':' {
                    match utf8::class(name) {
                        Some(s) => set.union(&s),
                        None => return err("Invalid character class name"),
                    }
                    continue;
                }
                match self.char_in(name) {
                    Some(c) => c,
                    None => return err("Invalid collation character"),
                }
            } else {
                let (c, len) = self.char_at(self.i).ok_or_else(|| Error(String::from(UNMATCHED_BRACKET)))?;
                self.i += len;
                c
            };
            // A range, `lo-hi`.
            if self.at(0) == Some(b'-') && self.at(1).is_some_and(|c| c != b']') {
                self.i += 1;
                let hi = if self.at(0) == Some(b'[') && self.at(1) == Some(b'.') {
                    let start = self.i + 2;
                    let mut k = start;
                    while k + 1 < self.p.len() && !(self.p[k] == b'.' && self.p[k + 1] == b']') {
                        k += 1;
                    }
                    let name = &self.p[start..k.min(self.p.len())];
                    self.i = k + 2;
                    self.char_in(name).ok_or_else(|| Error(String::from("Invalid collation character")))?
                } else {
                    let (c, len) = self.char_at(self.i).ok_or_else(|| Error(String::from(UNMATCHED_BRACKET)))?;
                    self.i += len;
                    c
                };
                if hi < lo {
                    return err("Invalid range end");
                }
                set.add_range(lo, hi);
            } else {
                set.add(lo);
            }
        }
        if self.o.icase {
            set.fold_case();
        }
        if negate {
            set.negate();
            if self.o.newline {
                set.remove(10, 10);
            }
        }
        Ok(set.node())
    }

    /// The one character `name` is (`[=c=]`, `[.c.]`).
    fn char_in(&self, name: &[u8]) -> Option<u32> {
        match utf8::decode(name) {
            Some((c, len)) if len == name.len() => Some(c as u32),
            _ if name.len() == 1 => Some(u32::from(name[0])),
            _ => None,
        }
    }

    /// `lo` just read: a range `lo-hi` or the single byte.
    fn range_or_char(&mut self, lo: u8, set: &mut ByteSet) -> Result<(), Error> {
        if self.at(0) == Some(b'-') && self.at(1).is_some_and(|c| c != b']') {
            self.i += 1;
            let hi = if self.at(0) == Some(b'[') && self.at(1) == Some(b'.') {
                let v = self.at(2).ok_or_else(|| Error(String::from(UNMATCHED_BRACKET)))?;
                if self.at(3) != Some(b'.') || self.at(4) != Some(b']') {
                    return err("Invalid collation character");
                }
                self.i += 5;
                v
            } else {
                let v = self.p[self.i];
                self.i += 1;
                v
            };
            if hi < lo {
                return err("Invalid range end");
            }
            set.add_range(lo, hi);
        } else {
            set.add(lo);
        }
        Ok(())
    }
}
