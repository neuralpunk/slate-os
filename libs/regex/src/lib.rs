// SPDX-License-Identifier: MIT OR Apache-2.0

//! Regular expressions as POSIX.1-2017 XBD chapter 9 defines them: basic
//! (BRE) and extended (ERE) syntax, plus the GNU extensions scripts rely on
//! (`\+ \? \|` in BREs, back-references in EREs, `\w \W \s \S \b \B \< \>
//! \` \'`). Matching is leftmost-longest, as POSIX requires, on bytes (the C
//! locale).
//!
//! Patterns compile to a small program run by a Pike VM (one pass, linear
//! time); patterns with back-references, which no automaton can match, run
//! on a bounded backtracker instead. Two things spare most of that work
//! (ADR 0160): a literal every match must contain is looked for first (and
//! a pattern that is only a literal is found by search alone), and a lazy
//! DFA, built as the text needs it and kept with the pattern, says whether
//! there is a match at all before the Pike VM finds where. Written from the
//! specification and observed behaviour (ADR 0012).

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod compile;
mod dfa;
pub mod fnmatch;
mod literal;
mod parse;
mod perl;
mod utf8;
mod vm;

pub use fnmatch::fnmatch;
pub use literal::{memchr, memchr2};

use core::cell::RefCell;

use alloc::string::String;
use alloc::vec::Vec;

/// Which grammar a pattern uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Syntax {
    #[default]
    Basic,
    Extended,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    pub syntax: Syntax,
    /// Ignore case (ASCII letters).
    pub icase: bool,
    /// REG_NEWLINE: `.` and `[^...]` do not match a newline; `^` and `$`
    /// also match after and before one.
    pub newline: bool,
    /// `\t`, `\r`, `\f`, `\v`, `\a` mean their control characters (sed);
    /// `\n` always means a newline.
    pub escapes: bool,
    /// Matches must be whole words or whole lines (grep -w, -x).
    pub whole: Whole,
    /// The text is UTF-8 (a UTF-8 locale): `.`, bracket expressions,
    /// classes and `\w` match whole characters, `-i` folds every letter,
    /// and bytes from 0x80 up count as word bytes for `\b` and `-w`.
    pub utf8: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Whole {
    #[default]
    Any,
    /// Preceded and followed by a non-word byte or the text's ends.
    Word,
    /// The whole text.
    Line,
}

impl Options {
    pub fn basic() -> Options {
        Options::default()
    }
    pub fn extended() -> Options {
        Options { syntax: Syntax::Extended, ..Options::default() }
    }
}

/// A pattern that does not compile; the messages follow regerror(3)'s.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub String);

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A set of bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ByteSet([u64; 4]);

impl ByteSet {
    pub fn add(&mut self, b: u8) {
        self.0[(b >> 6) as usize] |= 1 << (b & 63);
    }
    pub fn add_range(&mut self, lo: u8, hi: u8) {
        for b in lo..=hi {
            self.add(b);
        }
    }
    pub fn contains(&self, b: u8) -> bool {
        self.0[(b >> 6) as usize] & (1 << (b & 63)) != 0
    }
    pub fn negate(&mut self) {
        for w in &mut self.0 {
            *w = !*w;
        }
    }
    pub fn union(&mut self, o: &ByteSet) {
        for (a, b) in self.0.iter_mut().zip(o.0) {
            *a |= b;
        }
    }
    pub fn is_empty(&self) -> bool {
        self.0 == [0; 4]
    }
    /// Add the other case of every ASCII letter.
    pub fn fold_case(&mut self) {
        for b in b'a'..=b'z' {
            if self.contains(b) || self.contains(b.to_ascii_uppercase()) {
                self.add(b);
                self.add(b.to_ascii_uppercase());
            }
        }
    }
}

/// Zero-width assertions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Look {
    /// `^`
    LineStart,
    /// `$`
    LineEnd,
    /// `` \` ``
    TextStart,
    /// `\'`
    TextEnd,
    /// `\b`
    Word,
    /// `\B`
    NotWord,
    /// `\<`
    WordStart,
    /// `\>`
    WordEnd,
    /// The previous byte is not a word byte (or there is none).
    NoWordBefore,
    /// The next byte is not a word byte (or there is none).
    NoWordAfter,
}

/// The syntax tree.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Node {
    Empty,
    Set(ByteSet),
    Look(Look),
    Group(usize, alloc::boxed::Box<Node>),
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    Repeat(alloc::boxed::Box<Node>, u32, Option<u32>),
    Backref(usize),
    /// Perl's (grep -P): a repetition that takes as little as it can.
    Lazy(alloc::boxed::Box<Node>, u32, Option<u32>),
    /// `(?>...)` (and possessive repeats): the first way it matches, never
    /// tried again another way.
    Atomic(alloc::boxed::Box<Node>),
    /// `(?=...)`, `(?!...)` (ahead) and `(?<=...)`, `(?<!...)`: whether the
    /// node matches here (or ends here), consuming nothing.
    Around {
        ahead: bool,
        negate: bool,
        node: alloc::boxed::Box<Node>,
    },
    /// `\K`: the match starts here.
    Keep,
}

/// Where a match and its subexpressions are: `[0]` is the whole match,
/// `[n]` the nth parenthesized subexpression (`None` if it took no part).
pub type Captures = Vec<Option<(usize, usize)>>;

/// A compiled regular expression.
#[derive(Clone, Debug)]
pub struct Regex {
    prog: compile::Program,
    groups: usize,
    backrefs: bool,
    /// Perl's semantics (grep -P): the first match in priority order, not
    /// the longest; run by the backtracker.
    perl: bool,
    icase: bool,
    newline: bool,
    utf8: bool,
    /// Bytes a match can start with (`None`: any, or the empty string).
    first: Option<ByteSet>,
    /// The pattern can only match at the start of the text.
    anchored: bool,
    /// A literal every match contains, and whether the pattern is just
    /// that literal (with no subexpressions to report).
    literal: Option<literal::Literal>,
    pure: bool,
    /// The lazy DFAs (searching, and anchored at a position), made on
    /// first use, and the Pike VM's lists.
    search: RefCell<Option<dfa::Dfa>>,
    at: RefCell<Option<dfa::Dfa>>,
    scratch: RefCell<Option<vm::Scratch>>,
    /// For patterns the DFA can't run (back-references, assertions,
    /// atomic groups): a looser one it can, matching wherever the pattern
    /// does and maybe more, so its "no match" still holds.
    relaxed: Option<compile::Program>,
}

/// A word character for `\w`, `\b` and friends.
pub fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

impl Regex {
    pub fn new(pattern: &[u8], opts: Options) -> Result<Regex, Error> {
        let (node, groups) = parse::parse(pattern, opts)?;
        Regex::build(node, groups, opts, false)
    }

    /// A Perl-compatible pattern (grep -P): PCRE's syntax and leftmost-first
    /// matching. `opts.syntax` is ignored.
    pub fn perl(pattern: &[u8], opts: Options) -> Result<Regex, Error> {
        let (node, groups) = perl::parse(pattern, opts)?;
        Regex::build(node, groups, opts, true)
    }

    /// A pattern that matches `text` literally (grep -F).
    pub fn literal(text: &[u8], opts: Options) -> Regex {
        let mut parts = Vec::new();
        let mut i = 0;
        while i < text.len() {
            // In UTF-8, a letter beyond ASCII folds as a whole character.
            if opts.utf8
                && opts.icase
                && text[i] >= 0x80
                && let Some((c, len)) = utf8::decode(&text[i..])
            {
                let mut s = utf8::CharSet::default();
                s.add(c as u32);
                s.fold_case();
                parts.push(s.node());
                i += len;
                continue;
            }
            let mut s = ByteSet::default();
            s.add(text[i]);
            if opts.icase {
                s.fold_case();
            }
            parts.push(Node::Set(s));
            i += 1;
        }
        let node = Node::Concat(parts);
        // Literal patterns always compile.
        Regex::build(node, 0, opts, false).unwrap_or_else(|_| Regex::build(Node::Empty, 0, opts, false).unwrap())
    }

    fn build(node: Node, groups: usize, opts: Options, perl: bool) -> Result<Regex, Error> {
        let node = match opts.whole {
            Whole::Any => node,
            Whole::Word => {
                Node::Concat(alloc::vec![Node::Look(Look::NoWordBefore), node, Node::Look(Look::NoWordAfter)])
            }
            Whole::Line => Node::Concat(alloc::vec![Node::Look(Look::TextStart), node, Node::Look(Look::TextEnd)]),
        };
        let backrefs = has_backref(&node);
        let first = compile::first_bytes(&node);
        let anchored = compile::anchored(&node) && !opts.newline;
        let prog = compile::compile(&node, groups)?;
        let lit = literal::analyse(&node, opts.icase);
        let relaxed =
            if backrefs || !prog.subs.is_empty() { Some(compile::compile(&relax(&node), groups)?) } else { None };
        Ok(Regex {
            prog,
            groups,
            backrefs,
            perl,
            icase: opts.icase,
            newline: opts.newline,
            utf8: opts.utf8,
            first,
            anchored,
            pure: lit.pure && groups == 0,
            literal: lit.required,
            search: RefCell::new(None),
            at: RefCell::new(None),
            scratch: RefCell::new(None),
            relaxed,
        })
    }

    /// Whether a match can start at or after `start`, by the DFA (`None`:
    /// it gave up, or the pattern has back-references).
    fn dfa_says(&self, text: &[u8], start: usize, not_bol: bool, anchored: bool) -> Option<bool> {
        let prog = self.relaxed.as_ref().unwrap_or(&self.prog);
        let cell = if anchored || self.anchored { &self.at } else { &self.search };
        let mut d = cell.borrow_mut();
        let every = !(anchored || self.anchored);
        let dfa =
            d.get_or_insert_with(|| dfa::Dfa::new(prog, every, self.newline, self.utf8, self.first.filter(|_| every)));
        let says = dfa.first_end(prog, text, start, not_bol).map(|e| e.is_some());
        // The looser pattern's "match" proves nothing.
        if self.relaxed.is_some() && says == Some(true) { None } else { says }
    }

    fn pike(&self, ctx: &vm::Ctx<'_>, start: usize, first: Option<&ByteSet>, anchored: bool) -> Option<Captures> {
        let mut s = self.scratch.borrow_mut();
        let sc = s.get_or_insert_with(|| vm::Scratch::new(&self.prog, self.groups));
        vm::pike(&self.prog, self.groups, ctx, start, first, anchored, sc)
    }

    /// The number of parenthesized subexpressions.
    pub fn groups(&self) -> usize {
        self.groups
    }

    pub fn is_match(&self, text: &[u8]) -> bool {
        if self.literal.as_ref().is_some_and(|l| l.find(text).is_none()) {
            return false;
        }
        if self.pure {
            return true;
        }
        match self.dfa_says(text, 0, false, false) {
            Some(m) => m,
            // Any match will do: the backtracker stops at the first.
            None if self.backrefs || self.perl => {
                let ctx = vm::Ctx { text, newline: self.newline, not_bol: false, icase: self.icase, utf8: self.utf8 };
                vm::backtrack(&self.prog, self.groups, &ctx, 0, self.anchored, true, self.first.as_ref()).is_some()
            }
            None => self.find_at(text, 0).is_some(),
        }
    }

    /// The leftmost-longest match starting at or after `start`.
    /// Positions are offsets in `text`; `^` matches only at offset 0 (or
    /// after a newline in REG_NEWLINE mode).
    pub fn find_at(&self, text: &[u8], start: usize) -> Option<Captures> {
        self.find_from(text, start, false)
    }

    /// The longest match starting exactly at `pos` (expr's anchored match).
    pub fn match_at(&self, text: &[u8], pos: usize) -> Option<Captures> {
        if pos > text.len() {
            return None;
        }
        let ctx = vm::Ctx { text, newline: self.newline, not_bol: false, icase: self.icase, utf8: self.utf8 };
        if self.dfa_says(text, pos, false, true) == Some(false) {
            return None;
        }
        if self.backrefs || self.perl {
            vm::backtrack(&self.prog, self.groups, &ctx, pos, true, self.perl, None)
        } else {
            self.pike(&ctx, pos, None, true)
        }
    }

    /// Like [`Regex::find_at`]; `not_bol` keeps `^` from matching at offset
    /// 0 (REG_NOTBOL, for text that continues a line).
    pub fn find_from(&self, text: &[u8], start: usize, not_bol: bool) -> Option<Captures> {
        if start > text.len() {
            return None;
        }
        // Text without the required literal can't match; a pure literal's
        // leftmost-longest match is where it first is.
        if let Some(l) = &self.literal {
            let at = l.find(&text[start..])?;
            if self.pure {
                return Some(alloc::vec![Some((start + at, start + at + l.bytes.len()))]);
            }
        }
        let ctx = vm::Ctx { text, newline: self.newline, not_bol, icase: self.icase, utf8: self.utf8 };
        if self.dfa_says(text, start, not_bol, false) == Some(false) {
            return None;
        }
        if self.backrefs || self.perl {
            vm::backtrack(&self.prog, self.groups, &ctx, start, self.anchored, self.perl, self.first.as_ref())
        } else {
            self.pike(&ctx, start, self.first.as_ref(), self.anchored)
        }
    }
}

impl Regex {
    /// [`Regex::find_from`] by the Pike VM alone: no literal, no DFA (for
    /// the tests that check those against it).
    #[cfg(test)]
    fn find_slow(&self, text: &[u8], start: usize, not_bol: bool) -> Option<Captures> {
        let ctx = vm::Ctx { text, newline: self.newline, not_bol, icase: self.icase, utf8: self.utf8 };
        let mut sc = vm::Scratch::new(&self.prog, self.groups);
        vm::pike(&self.prog, self.groups, &ctx, start, self.first.as_ref(), self.anchored, &mut sc)
    }
}

/// `n` loosened for the DFA: assertions and `\K` match anywhere, atomic
/// groups and lazy repeats as plain ones, a back-reference any bytes.
fn relax(n: &Node) -> Node {
    use alloc::boxed::Box;
    match n {
        Node::Around { .. } | Node::Keep => Node::Empty,
        Node::Backref(_) => {
            let mut any = ByteSet::default();
            any.negate();
            Node::Repeat(Box::new(Node::Set(any)), 0, None)
        }
        Node::Atomic(b) => relax(b),
        Node::Group(k, b) => Node::Group(*k, Box::new(relax(b))),
        Node::Repeat(b, lo, hi) | Node::Lazy(b, lo, hi) => Node::Repeat(Box::new(relax(b)), *lo, *hi),
        Node::Concat(v) => Node::Concat(v.iter().map(relax).collect()),
        Node::Alt(v) => Node::Alt(v.iter().map(relax).collect()),
        other => other.clone(),
    }
}

fn has_backref(n: &Node) -> bool {
    match n {
        Node::Backref(_) => true,
        Node::Group(_, b) | Node::Repeat(b, _, _) | Node::Lazy(b, _, _) | Node::Atomic(b) => has_backref(b),
        Node::Around { node, .. } => has_backref(node),
        Node::Concat(v) | Node::Alt(v) => v.iter().any(has_backref),
        _ => false,
    }
}

#[cfg(test)]
mod tests;
