// SPDX-License-Identifier: MIT OR Apache-2.0

//! Perl-compatible patterns (grep -P), as the PCRE2 documentation
//! (pcre2pattern) describes their syntax: `\d \w \s \h \v \N` and their
//! negations, `\b \B \A \z \Z \K`, `\Q...\E`, `\xHH \x{H...} \o{...} \cX`,
//! classes with escapes and POSIX names, lazy (`*?`) and possessive (`*+`)
//! repeats, non-capturing, named and atomic groups, lookahead and bounded
//! lookbehind, back-references by number and name, `\p{...}` for the main
//! Unicode categories, and the `i`, `s`, `m`, `x` and `n` options inline.
//! Recursion, conditionals, `\G` and backtracking verbs are refused.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::parse::{byte, char_node, class_set};
use crate::utf8::{self, CharSet};
use crate::{ByteSet, Error, Look, Node, Options};

fn err<T>(m: &str) -> Result<T, Error> {
    Err(Error(String::from(m)))
}

const NOTHING_TO_REPEAT: &str = "quantifier does not follow a repeatable item";

pub(crate) fn parse(p: &[u8], o: Options) -> Result<(Node, usize), Error> {
    let mut ps =
        Pl { p, i: 0, o, icase: o.icase, dotall: false, extended: false, no_auto: false, groups: 0, names: Vec::new() };
    let n = ps.alt()?;
    if ps.i < p.len() {
        return err("unmatched closing parenthesis");
    }
    Ok((n, ps.groups))
}

struct Pl<'a> {
    p: &'a [u8],
    i: usize,
    o: Options,
    /// The options in force here (`(?i)` and friends change them until
    /// the end of the group).
    icase: bool,
    dotall: bool,
    extended: bool,
    /// `n`: plain parentheses don't capture.
    no_auto: bool,
    groups: usize,
    names: Vec<(Vec<u8>, usize)>,
}

/// A set of characters being built: code points, which become bytes
/// outside UTF-8.
type Set = CharSet;

fn ascii(f: fn(u8) -> bool) -> Set {
    let mut s = CharSet::default();
    for b in 0..=127u8 {
        if f(b) {
            s.add(u32::from(b));
        }
    }
    s
}

impl Pl<'_> {
    fn at(&self, k: usize) -> Option<u8> {
        self.p.get(self.i + k).copied()
    }

    fn eat(&mut self, s: &[u8]) -> bool {
        if self.p[self.i..].starts_with(s) {
            self.i += s.len();
            true
        } else {
            false
        }
    }

    /// With `x`, blanks and `#` comments between items are nothing.
    fn skip_extended(&mut self) {
        if !self.extended {
            return;
        }
        while let Some(c) = self.at(0) {
            if c.is_ascii_whitespace() {
                self.i += 1;
            } else if c == b'#' {
                while self.at(0).is_some_and(|c| c != b'\n') {
                    self.i += 1;
                }
            } else {
                break;
            }
        }
    }

    fn alt(&mut self) -> Result<Node, Error> {
        let mut alts = vec![self.concat()?];
        while self.at(0) == Some(b'|') {
            self.i += 1;
            alts.push(self.concat()?);
        }
        Ok(if alts.len() == 1 { alts.pop().unwrap_or(Node::Empty) } else { Node::Alt(alts) })
    }

    fn concat(&mut self) -> Result<Node, Error> {
        let mut items = Vec::new();
        loop {
            self.skip_extended();
            match self.at(0) {
                None | Some(b'|' | b')') => break,
                _ => {}
            }
            let Some(atom) = self.atom()? else { continue };
            let atom = self.quantifier(atom)?;
            items.push(atom);
        }
        Ok(match items.len() {
            0 => Node::Empty,
            1 => items.pop().unwrap_or(Node::Empty),
            _ => Node::Concat(items),
        })
    }

    /// A set node: bytes, or characters in UTF-8.
    fn set_node(&self, mut s: Set) -> Result<Node, Error> {
        if self.icase {
            s.fold_case();
        }
        if self.o.utf8 {
            return Ok(s.node());
        }
        let mut b = ByteSet::default();
        for &(lo, hi) in &s.0 {
            if lo > 255 {
                continue;
            }
            b.add_range(lo as u8, hi.min(255) as u8);
        }
        Ok(Node::Set(b))
    }

    /// Every character (byte outside UTF-8), but those of `s`.
    fn not(&self, mut s: Set) -> Set {
        s.negate();
        if !self.o.utf8 {
            s.remove(256, 0x10FFFF);
        }
        s
    }

    fn char_node(&self, c: u32) -> Result<Node, Error> {
        if self.o.utf8 {
            let ch = char::from_u32(c).ok_or_else(|| Error(String::from("invalid code point")))?;
            return Ok(char_node(ch, self.icase));
        }
        if c > 255 {
            return err("character code point value in \\x{} or \\o{} is too large");
        }
        Ok(byte(c as u8, self.icase))
    }

    fn atom(&mut self) -> Result<Option<Node>, Error> {
        let c = self.p[self.i];
        Ok(Some(match c {
            b'.' => {
                self.i += 1;
                let mut s = if self.o.utf8 { CharSet::all() } else { self.not(CharSet::default()) };
                if !self.dotall {
                    s.remove(10, 10);
                }
                let icase = core::mem::replace(&mut self.icase, false);
                let n = self.set_node(s);
                self.icase = icase;
                n?
            }
            b'^' => {
                self.i += 1;
                Node::Look(Look::LineStart)
            }
            b'$' => {
                self.i += 1;
                Node::Look(Look::LineEnd)
            }
            b'[' => self.class()?,
            b'(' => return self.group(),
            b'\\' => return self.escape(),
            b'*' | b'+' | b'?' => return err(NOTHING_TO_REPEAT),
            b'{' if self.quantifier_at() => return err(NOTHING_TO_REPEAT),
            0x80..
                if self.o.utf8
                    && let Some((ch, len)) = utf8::decode(&self.p[self.i..]) =>
            {
                self.i += len;
                char_node(ch, self.icase)
            }
            _ => {
                self.i += 1;
                byte(c, self.icase)
            }
        }))
    }

    /// Whether a `{...}` quantifier starts here.
    fn quantifier_at(&self) -> bool {
        let rest = &self.p[self.i..];
        let Some(body) = rest.strip_prefix(b"{") else { return false };
        let Some(end) = body.iter().position(|&c| c == b'}') else { return false };
        let inner = &body[..end];
        let (a, b) = match inner.iter().position(|&c| c == b',') {
            Some(k) => (&inner[..k], Some(&inner[k + 1..])),
            None => (inner, None),
        };
        let digits = |x: &[u8]| x.iter().all(u8::is_ascii_digit);
        digits(a) && b.is_none_or(digits) && !(a.is_empty() && b.is_none_or(<[u8]>::is_empty))
    }

    fn quantifier(&mut self, atom: Node) -> Result<Node, Error> {
        self.skip_extended();
        let (min, max) = match self.at(0) {
            Some(b'*') => {
                self.i += 1;
                (0, None)
            }
            Some(b'+') => {
                self.i += 1;
                (1, None)
            }
            Some(b'?') => {
                self.i += 1;
                (0, Some(1))
            }
            Some(b'{') if self.quantifier_at() => {
                let end = self.i + self.p[self.i..].iter().position(|&c| c == b'}').unwrap_or(0);
                let inner = &self.p[self.i + 1..end];
                let num = |x: &[u8]| -> Result<u32, Error> {
                    let n: u32 = core::str::from_utf8(x).ok().and_then(|s| s.parse().ok()).unwrap_or(u32::MAX);
                    if n > 65535 { err("number too big in {} quantifier") } else { Ok(n) }
                };
                let r = match inner.iter().position(|&c| c == b',') {
                    Some(k) => {
                        let lo = if k == 0 { 0 } else { num(&inner[..k])? };
                        let hi = if k + 1 == inner.len() { None } else { Some(num(&inner[k + 1..])?) };
                        (lo, hi)
                    }
                    None => {
                        let n = num(inner)?;
                        (n, Some(n))
                    }
                };
                if r.1.is_some_and(|h| h < r.0) {
                    return err("numbers out of order in {} quantifier");
                }
                self.i = end + 1;
                r
            }
            _ => return Ok(atom),
        };
        if matches!(atom, Node::Empty) {
            return err(NOTHING_TO_REPEAT);
        }
        Ok(match self.at(0) {
            Some(b'?') => {
                self.i += 1;
                Node::Lazy(Box::new(atom), min, max)
            }
            Some(b'+') => {
                self.i += 1;
                Node::Atomic(Box::new(Node::Repeat(Box::new(atom), min, max)))
            }
            _ => Node::Repeat(Box::new(atom), min, max),
        })
    }

    /// The group's body and its `)`, the options put back after.
    fn body(&mut self) -> Result<Node, Error> {
        let saved = (self.icase, self.dotall, self.extended, self.no_auto);
        let n = self.alt()?;
        (self.icase, self.dotall, self.extended, self.no_auto) = saved;
        if !self.eat(b")") {
            return err("missing closing parenthesis");
        }
        Ok(n)
    }

    fn capture(&mut self, name: Option<Vec<u8>>) -> Result<Option<Node>, Error> {
        self.groups += 1;
        let k = self.groups;
        if let Some(n) = name {
            if self.names.iter().any(|(m, _)| *m == n) {
                return err("two named subpatterns have the same name (PCRE2_DUPNAMES not set)");
            }
            self.names.push((n, k));
        }
        Ok(Some(Node::Group(k, Box::new(self.body()?))))
    }

    /// A name up to `end`.
    fn name(&mut self, end: u8) -> Result<Vec<u8>, Error> {
        let start = self.i;
        while self.at(0).is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_') {
            self.i += 1;
        }
        let name = self.p[start..self.i].to_vec();
        if name.is_empty() || name[0].is_ascii_digit() {
            return err("subpattern name expected");
        }
        if !self.eat(&[end]) {
            return err("syntax error in subpattern name (missing terminator?)");
        }
        Ok(name)
    }

    fn named_ref(&self, name: &[u8]) -> Result<Node, Error> {
        match self.names.iter().find(|(n, _)| n == name) {
            Some(&(_, k)) => Ok(Node::Backref(k)),
            None => err("reference to non-existent subpattern"),
        }
    }

    fn group(&mut self) -> Result<Option<Node>, Error> {
        self.i += 1;
        if self.at(0) == Some(b'*') {
            return err("(*VERB) not recognized or malformed");
        }
        if self.at(0) != Some(b'?') {
            if self.no_auto {
                return Ok(Some(self.body()?));
            }
            return self.capture(None);
        }
        self.i += 1;
        let ahead = |negate: bool, node: Node| Node::Around { ahead: true, negate, node: Box::new(node) };
        let behind = |negate: bool, node: Node| Node::Around { ahead: false, negate, node: Box::new(node) };
        if self.eat(b"#") {
            while self.at(0).is_some_and(|c| c != b')') {
                self.i += 1;
            }
            if !self.eat(b")") {
                return err("missing ) at end of (?# comment");
            }
            return Ok(None);
        }
        if self.eat(b":") {
            return Ok(Some(self.body()?));
        }
        if self.eat(b"=") {
            return Ok(Some(ahead(false, self.body()?)));
        }
        if self.eat(b"!") {
            return Ok(Some(ahead(true, self.body()?)));
        }
        if self.eat(b"<=") {
            return Ok(Some(behind(false, self.body()?)));
        }
        if self.eat(b"<!") {
            return Ok(Some(behind(true, self.body()?)));
        }
        if self.eat(b">") {
            return Ok(Some(Node::Atomic(Box::new(self.body()?))));
        }
        if self.eat(b"P=") {
            let name = self.name(b')')?;
            return self.named_ref(&name).map(Some);
        }
        if self.eat(b"P<") {
            let name = self.name(b'>')?;
            return self.capture(Some(name));
        }
        if self.at(0) == Some(b'<') && self.at(1).is_some_and(|c| c.is_ascii_alphabetic() || c == b'_') {
            self.i += 1;
            let name = self.name(b'>')?;
            return self.capture(Some(name));
        }
        if self.eat(b"'") {
            let name = self.name(b'\'')?;
            return self.capture(Some(name));
        }
        if matches!(self.at(0), Some(b'|' | b'(' | b'R' | b'&' | b'+' | b'0'..=b'9'))
            || self.p[self.i..].starts_with(b"P>")
        {
            return err("this construct is not supported by Slate's grep -P (recursion, conditionals, branch reset)");
        }
        // Options: (?imsxn-imsxn) for the rest of the group, or with `:`
        // for a group of their own.
        let saved = (self.icase, self.dotall, self.extended, self.no_auto);
        let mut on = true;
        if self.eat(b"^") {
            (self.icase, self.dotall, self.extended, self.no_auto) = (false, false, false, false);
        }
        loop {
            match self.at(0) {
                Some(b'i') => self.icase = on,
                Some(b's') => self.dotall = on,
                Some(b'x') => self.extended = on,
                Some(b'n') => self.no_auto = on,
                // ^ and $ work on lines already (grep's records).
                Some(b'm' | b'J' | b'U') => {}
                Some(b'-') if on => on = false,
                Some(b')') => {
                    self.i += 1;
                    return Ok(None);
                }
                Some(b':') => {
                    self.i += 1;
                    let n = self.body()?;
                    (self.icase, self.dotall, self.extended, self.no_auto) = saved;
                    return Ok(Some(n));
                }
                _ => return err("unrecognized character after (? or (?-"),
            }
            self.i += 1;
        }
    }

    /// Hex digits from `i` (at most `max`).
    fn hex(&mut self, max: usize) -> Option<u32> {
        let start = self.i;
        while self.i - start < max && self.at(0).is_some_and(|c| c.is_ascii_hexdigit()) {
            self.i += 1;
        }
        if start == self.i {
            return None;
        }
        u32::from_str_radix(core::str::from_utf8(&self.p[start..self.i]).ok()?, 16).ok()
    }

    /// `\x`, `\o`, `\c`, `\0`, the letters for control characters: the
    /// character, after the backslash and the letter.
    fn char_escape(&mut self, e: u8) -> Result<Option<u32>, Error> {
        Ok(Some(match e {
            b't' => 9,
            b'n' => 10,
            b'r' => 13,
            b'f' => 12,
            b'e' => 27,
            b'a' => 7,
            b'x' => {
                if self.eat(b"{") {
                    let v = self.hex(8).ok_or_else(|| Error(String::from("\\x{ is not followed by hex digits")))?;
                    if !self.eat(b"}") {
                        return err("missing terminating } in \\x{}");
                    }
                    v
                } else {
                    self.hex(2).unwrap_or(0)
                }
            }
            b'o' => {
                if !self.eat(b"{") {
                    return err("missing opening brace after \\o");
                }
                let start = self.i;
                while self.at(0).is_some_and(|c| (b'0'..=b'7').contains(&c)) {
                    self.i += 1;
                }
                let v =
                    u32::from_str_radix(core::str::from_utf8(&self.p[start..self.i]).unwrap_or("0"), 8).unwrap_or(0);
                if !self.eat(b"}") {
                    return err("missing terminating } in \\o{}");
                }
                v
            }
            b'0' => {
                let start = self.i;
                while self.i - start < 2 && self.at(0).is_some_and(|c| (b'0'..=b'7').contains(&c)) {
                    self.i += 1;
                }
                u32::from_str_radix(core::str::from_utf8(&self.p[start..self.i]).unwrap_or("0"), 8).unwrap_or(0)
            }
            b'c' => {
                let Some(x) = self.at(0) else { return err("\\c at end of pattern") };
                self.i += 1;
                u32::from(x.to_ascii_uppercase() ^ 0x40)
            }
            _ => return Ok(None),
        }))
    }

    /// `\d`, `\w`, `\s`, `\h`, `\v`, `\N` and their negations, `\p`, `\P`.
    fn set_escape(&mut self, e: u8) -> Result<Option<Set>, Error> {
        let base = match e.to_ascii_lowercase() {
            b'd' => ascii(|c| c.is_ascii_digit()),
            b'w' => ascii(|c| c.is_ascii_alphanumeric() || c == b'_'),
            b's' => ascii(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 11 | 12)),
            b'h' => {
                let mut s = ascii(|c| c == b' ' || c == b'\t');
                s.add(0xA0);
                s
            }
            b'v' => ascii(|c| (10..=13).contains(&c)),
            b'p' => {
                let name = if self.eat(b"{") {
                    let start = self.i;
                    while self.at(0).is_some_and(|c| c != b'}') {
                        self.i += 1;
                    }
                    let n = self.p[start..self.i].to_vec();
                    if !self.eat(b"}") {
                        return err("malformed \\P or \\p sequence");
                    }
                    n
                } else {
                    let Some(c) = self.at(0) else { return err("malformed \\P or \\p sequence") };
                    self.i += 1;
                    alloc::vec![c]
                };
                let (neg, name) = match name.strip_prefix(b"^") {
                    Some(n) => (true, n.to_vec()),
                    None => (false, name),
                };
                let s = property(&name, self.o.utf8)
                    .ok_or_else(|| Error(String::from("unknown property after \\P or \\p")))?;
                return Ok(Some(if (e == b'P') != neg { self.not(s) } else { s }));
            }
            _ => return Ok(None),
        };
        Ok(Some(if e.is_ascii_uppercase() { self.not(base) } else { base }))
    }

    fn escape(&mut self) -> Result<Option<Node>, Error> {
        let Some(e) = self.at(1) else { return err("\\ at end of pattern") };
        self.i += 2;
        if e == b'N' {
            let mut s = if self.o.utf8 { CharSet::all() } else { self.not(CharSet::default()) };
            s.remove(10, 10);
            return self.set_node(s).map(Some);
        }
        if let Some(s) = self.set_escape(e)? {
            let icase = core::mem::replace(&mut self.icase, false);
            let n = self.set_node(s);
            self.icase = icase;
            return n.map(Some);
        }
        if let Some(c) = self.char_escape(e)? {
            return self.char_node(c).map(Some);
        }
        Ok(Some(match e {
            b'b' => Node::Look(Look::Word),
            b'B' => Node::Look(Look::NotWord),
            b'A' => Node::Look(Look::TextStart),
            b'z' | b'Z' => Node::Look(Look::TextEnd),
            b'K' => Node::Keep,
            b'E' => return Ok(None),
            b'Q' => {
                let start = self.i;
                let end = self.p[start..].windows(2).position(|w| w == b"\\E").map_or(self.p.len(), |k| start + k);
                let text = &self.p[start..end];
                self.i = (end + 2).min(self.p.len());
                let mut items = Vec::new();
                let mut k = 0;
                while k < text.len() {
                    match utf8::decode(&text[k..]).filter(|_| self.o.utf8 && text[k] >= 0x80) {
                        Some((ch, len)) => {
                            items.push(char_node(ch, self.icase));
                            k += len;
                        }
                        None => {
                            items.push(byte(text[k], self.icase));
                            k += 1;
                        }
                    }
                }
                return Ok(Some(Node::Concat(items)));
            }
            b'1'..=b'9' => {
                let start = self.i - 1;
                while self.at(0).is_some_and(|c| c.is_ascii_digit()) {
                    self.i += 1;
                }
                let n: usize =
                    core::str::from_utf8(&self.p[start..self.i]).ok().and_then(|s| s.parse().ok()).unwrap_or(0);
                if n > self.groups {
                    return err("reference to non-existent subpattern");
                }
                Node::Backref(n)
            }
            b'g' => {
                let braced = self.eat(b"{");
                let start = self.i;
                while self.at(0).is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-') {
                    self.i += 1;
                }
                let r = self.p[start..self.i].to_vec();
                if braced && !self.eat(b"}") {
                    return err(
                        "\\g is not followed by a braced, angle-bracketed, or quoted name/number or by a plain number",
                    );
                }
                let num = core::str::from_utf8(&r).ok().and_then(|s| s.parse::<i64>().ok());
                match num {
                    Some(n) if n < 0 => {
                        let k = self.groups as i64 + 1 + n;
                        if k < 1 {
                            return err("reference to non-existent subpattern");
                        }
                        Node::Backref(k as usize)
                    }
                    Some(n) if n > 0 && n as usize <= self.groups => Node::Backref(n as usize),
                    Some(_) => return err("reference to non-existent subpattern"),
                    None => self.named_ref(&r)?,
                }
            }
            b'k' => {
                let end = match self.at(0) {
                    Some(b'<') => b'>',
                    Some(b'\'') => b'\'',
                    Some(b'{') => b'}',
                    _ => return err("\\k is not followed by a braced, angle-bracketed, or quoted name"),
                };
                self.i += 1;
                let name = self.name(end)?;
                self.named_ref(&name)?
            }
            b'G' => return err("\\G is not supported by Slate's grep -P"),
            c if c.is_ascii_alphanumeric() => return err("unrecognized character follows \\"),
            c => byte(c, self.icase),
        }))
    }

    /// A character class: members, ranges, escapes, POSIX names.
    fn class(&mut self) -> Result<Node, Error> {
        self.i += 1;
        let negate = self.eat(b"^");
        let mut set = CharSet::default();
        let mut first = true;
        loop {
            let Some(c) = self.at(0) else { return err("missing terminating ] for character class") };
            if c == b']' && !first {
                self.i += 1;
                break;
            }
            first = false;
            if c == b'['
                && self.at(1) == Some(b':')
                && let Some(end) = self.p[self.i + 2..].windows(2).position(|w| w == b":]")
            {
                let name = &self.p[self.i + 2..self.i + 2 + end];
                let (neg, name) = match name.strip_prefix(b"^") {
                    Some(n) => (true, n),
                    None => (false, name),
                };
                let s = if self.o.utf8 {
                    utf8::class(name)
                } else {
                    class_set(name).map(|b| {
                        let mut s = CharSet::default();
                        for x in 0..=255u8 {
                            if b.contains(x) {
                                s.add(u32::from(x));
                            }
                        }
                        s
                    })
                };
                let s = s.ok_or_else(|| Error(String::from("unknown POSIX class name")))?;
                set.union(&if neg { self.not(s) } else { s });
                self.i += 2 + end + 2;
                continue;
            }
            let lo = match self.member()? {
                Member::Set(s) => {
                    set.union(&s);
                    continue;
                }
                Member::Char(c) => c,
            };
            if self.at(0) == Some(b'-') && self.at(1).is_some_and(|c| c != b']') {
                self.i += 1;
                match self.member()? {
                    Member::Char(hi) => {
                        if hi < lo {
                            return err("range out of order in character class");
                        }
                        set.add_range(lo, hi);
                    }
                    // `a-\d`: the `-` is a member.
                    Member::Set(s) => {
                        set.add(lo);
                        set.add(u32::from(b'-'));
                        set.union(&s);
                    }
                }
            } else {
                set.add(lo);
            }
        }
        let set = if negate {
            if self.icase {
                set.fold_case();
            }
            self.not(set)
        } else {
            set
        };
        // A negated set was folded before it was turned round.
        let fold = self.icase && !negate;
        let icase = core::mem::replace(&mut self.icase, fold);
        let n = self.set_node(set);
        self.icase = icase;
        n
    }

    /// One member of a class: a character or an escape's set.
    fn member(&mut self) -> Result<Member, Error> {
        let c = self.p[self.i];
        if c != b'\\' {
            if self.o.utf8
                && c >= 0x80
                && let Some((ch, len)) = utf8::decode(&self.p[self.i..])
            {
                self.i += len;
                return Ok(Member::Char(ch as u32));
            }
            self.i += 1;
            return Ok(Member::Char(u32::from(c)));
        }
        let Some(e) = self.at(1) else { return err("\\ at end of pattern") };
        self.i += 2;
        if let Some(s) = self.set_escape(e)? {
            return Ok(Member::Set(s));
        }
        if let Some(c) = self.char_escape(e)? {
            return Ok(Member::Char(c));
        }
        match e {
            // Backspace, in a class.
            b'b' => Ok(Member::Char(8)),
            b'Q' | b'E' => Ok(Member::Set(CharSet::default())),
            c if c.is_ascii_alphanumeric() => err("unrecognized character follows \\"),
            c => Ok(Member::Char(u32::from(c))),
        }
    }
}

enum Member {
    Char(u32),
    Set(Set),
}

/// `\p{...}`: the main Unicode categories (and PCRE's `Xan`, `Xsp`,
/// `Xwd`, `Any`), over every character in UTF-8, or the 256 code points a
/// byte can be outside it.
fn property(name: &[u8], utf8: bool) -> Option<Set> {
    let f: fn(char) -> bool = match name {
        b"Any" => |_| true,
        b"L" | b"L&" | b"Letter" => char::is_alphabetic,
        b"Lu" => char::is_uppercase,
        b"Ll" => char::is_lowercase,
        b"N" => char::is_numeric,
        b"Nd" => |c| c.is_ascii_digit(),
        b"P" => |c| {
            c.is_ascii_punctuation() || (!c.is_ascii() && !c.is_alphanumeric() && !c.is_whitespace() && !c.is_control())
        },
        b"Z" | b"Zs" => |c| c.is_whitespace() && !c.is_control(),
        b"Cc" => char::is_control,
        b"Xan" => char::is_alphanumeric,
        b"Xsp" | b"Xps" => char::is_whitespace,
        b"Xwd" => |c| c.is_alphanumeric() || c == '_',
        _ => return None,
    };
    if utf8 {
        return Some(CharSet::of(f));
    }
    let mut s = CharSet::default();
    for b in 0..=255u8 {
        if f(char::from(b)) {
            s.add(u32::from(b));
        }
    }
    Some(s)
}
