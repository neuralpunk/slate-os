// SPDX-License-Identifier: MIT OR Apache-2.0

//! A lazy DFA: says whether a pattern matches (and where the first match
//! ends) in one pass over the text, building its states from the program
//! as the text needs them and keeping them for the next call.
//!
//! A state is the set of program counters waiting for a byte, before the
//! empty moves are followed, and what the byte before was (the text's
//! start, a newline, a word byte or another). The empty moves are followed
//! when the next byte is known, so `^`, `$`, `\b`, `\<` and `\>` are
//! decided on both sides. Bytes no instruction tells apart share a class,
//! so a state has a row per class, not per byte. Patterns with
//! back-references never come here.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::compile::{Inst, Program};
use crate::{ByteSet, Look, is_word};

/// States kept before the cache is emptied and rebuilt, and the most
/// transitions kept (1 MiB of table, however many classes there are).
const MAX_STATES: usize = 2048;
const MAX_TABLE: usize = 256 * 1024;
/// Times the cache may be emptied in one search before the DFA gives up
/// (the caller then uses the Pike VM).
const MAX_RESETS: usize = 8;

const UNKNOWN: u32 = u32::MAX;
/// A transition's flag: a match ended before the byte it reads.
const MATCHED: u32 = 1 << 31;

/// What the byte before a position was.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Prev {
    /// The text's start, where `^` holds.
    Start,
    /// The text's start where `^` doesn't hold (REG_NOTBOL).
    StartNotBol,
    Newline,
    Word,
    Other,
}

#[derive(Clone, Debug)]
pub(crate) struct Dfa {
    /// The class of each byte.
    class: [u8; 256],
    /// A byte of each class.
    sample: Vec<u8>,
    /// Classes, and one more for the end of the text.
    stride: usize,
    /// Each state's waiting counters and the byte before.
    states: Vec<(Vec<u32>, Prev)>,
    index: BTreeMap<(Vec<u32>, Prev), u32>,
    /// `states.len() * stride` transitions: the next state, with
    /// [`MATCHED`], or [`UNKNOWN`].
    table: Vec<u32>,
    /// Each search may start a match at every position (unanchored).
    every: bool,
    newline: bool,
    /// UTF-8 text: bytes from 0x80 up are word bytes.
    utf8: bool,
    /// The bytes a match can start with, when they are one or two:
    /// where nothing is under way, the search skips to the next of them
    /// by `memchr` (more would be no faster than the DFA itself).
    first_bytes: Vec<u8>,
    /// The states with nothing under way but the next start.
    idle: Vec<bool>,
    /// The state where only a start waits, after each kind of byte, once
    /// made: where every search begins, and where skips land.
    start_ids: [u32; 5],
    // Scratch for the empty moves.
    seen: Vec<u32>,
    generation: u32,
    stack: Vec<u32>,
}

impl Dfa {
    /// A DFA for `prog`; `every` starts a match at each position.
    pub fn new(prog: &Program, every: bool, newline: bool, utf8: bool, first: Option<ByteSet>) -> Dfa {
        // The sets the program reads, and what the assertions look at.
        let mut sets: Vec<ByteSet> = Vec::new();
        for i in &prog.insts {
            if let Inst::Set(s) = i
                && !sets.contains(s)
            {
                sets.push(*s);
            }
        }
        if prog.insts.iter().any(|i| matches!(i, Inst::Look(_))) {
            let mut word = ByteSet::default();
            let mut nl = ByteSet::default();
            for b in 0..=255u8 {
                if is_word(b) || (utf8 && b >= 0x80) {
                    word.add(b);
                }
            }
            nl.add(b'\n');
            sets.push(word);
            sets.push(nl);
        }
        let mut class = [0u8; 256];
        let mut sample = Vec::new();
        let mut by_signature: BTreeMap<Vec<bool>, u8> = BTreeMap::new();
        for b in 0..=255u8 {
            let sig: Vec<bool> = sets.iter().map(|s| s.contains(b)).collect();
            let next = by_signature.len() as u8;
            let c = *by_signature.entry(sig).or_insert_with(|| {
                sample.push(b);
                next
            });
            class[b as usize] = c;
        }
        let stride = sample.len() + 1;
        Dfa {
            class,
            sample,
            stride,
            states: Vec::new(),
            index: BTreeMap::new(),
            table: Vec::new(),
            every,
            newline,
            utf8,
            first_bytes: first
                .map(|f| (0..=255u8).filter(|&b| f.contains(b)).collect::<Vec<u8>>())
                .filter(|b| b.len() <= 2)
                .unwrap_or_default(),
            idle: Vec::new(),
            start_ids: [UNKNOWN; 5],
            seen: vec![0; prog.insts.len()],
            generation: 0,
            stack: Vec::new(),
        }
    }

    fn intern(&mut self, key: (Vec<u32>, Prev)) -> u32 {
        if let Some(&id) = self.index.get(&key) {
            return id;
        }
        let id = self.states.len() as u32;
        self.idle.push(self.every && key.0 == [0]);
        self.states.push(key.clone());
        self.index.insert(key, id);
        self.table.extend(core::iter::repeat_n(UNKNOWN, self.stride));
        id
    }

    fn word(&self, b: u8) -> bool {
        is_word(b) || (self.utf8 && b >= 0x80)
    }

    fn start(&mut self, prev: Prev) -> u32 {
        let slot = prev as usize;
        if self.start_ids[slot] == UNKNOWN {
            self.start_ids[slot] = self.intern((vec![0], prev));
        }
        self.start_ids[slot]
    }

    fn reset(&mut self) {
        self.idle.clear();
        self.start_ids = [UNKNOWN; 5];
        self.states.clear();
        self.index.clear();
        self.table.clear();
    }

    /// Follow `state`'s empty moves knowing the next byte (`None`: the
    /// text ends), then read it: the next state, and whether a match
    /// ended before it.
    fn step(&mut self, prog: &Program, state: u32, next: Option<u8>) -> (Vec<u32>, Prev, bool) {
        let (kernel, prev) = self.states[state as usize].clone();
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.seen.fill(0);
            self.generation = 1;
        }
        let mut matched = false;
        let mut out: Vec<u32> = Vec::new();
        let start = matches!(prev, Prev::Start | Prev::StartNotBol);
        // Threads are explored in reverse so the stack visits in order;
        // order doesn't matter to a DFA, only the set.
        self.stack.clear();
        self.stack.extend(kernel.iter().rev());
        while let Some(pc) = self.stack.pop() {
            let p = pc as usize;
            if self.seen[p] == self.generation {
                continue;
            }
            self.seen[p] = self.generation;
            match &prog.insts[p] {
                Inst::Jmp(t) | Inst::Loop(t, _) => self.stack.push(*t as u32),
                Inst::Split(a, b) => {
                    self.stack.push(*b as u32);
                    self.stack.push(*a as u32);
                }
                Inst::Save(_) | Inst::Mark(_) | Inst::Keep => self.stack.push(pc + 1),
                Inst::Look(l) => {
                    let ok = match l {
                        Look::LineStart => prev == Prev::Start || (self.newline && prev == Prev::Newline),
                        Look::LineEnd => next.is_none() || (self.newline && next == Some(b'\n')),
                        Look::TextStart => start,
                        Look::TextEnd => next.is_none(),
                        _ => {
                            let wp = prev == Prev::Word;
                            let wn = next.is_some_and(|b| self.word(b));
                            match l {
                                Look::Word => wp != wn,
                                Look::NotWord => wp == wn,
                                Look::WordStart => !wp && wn,
                                Look::WordEnd => wp && !wn,
                                Look::NoWordBefore => !wp,
                                _ => !wn,
                            }
                        }
                    };
                    if ok {
                        self.stack.push(pc + 1);
                    }
                }
                Inst::Set(s) => {
                    if next.is_some_and(|b| s.contains(b)) {
                        out.push(pc + 1);
                    }
                }
                Inst::Match => matched = true,
                // Patterns with these never come here.
                Inst::Backref(_) | Inst::Sub(_) => {}
            }
        }
        if self.every {
            out.push(0);
        }
        out.sort_unstable();
        out.dedup();
        let prev = match next {
            Some(b'\n') => Prev::Newline,
            Some(b) if self.word(b) => Prev::Word,
            _ => Prev::Other,
        };
        (out, prev, matched)
    }

    /// The transition from `state` on class `c` (`stride - 1`: the end).
    fn next(&mut self, prog: &Program, state: u32, c: usize) -> u32 {
        let t = self.table[state as usize * self.stride + c];
        if t != UNKNOWN {
            return t;
        }
        let byte = self.sample.get(c).copied();
        let (kernel, prev, matched) = self.step(prog, state, byte);
        let id = self.intern((kernel, prev));
        let t = id | if matched { MATCHED } else { 0 };
        self.table[state as usize * self.stride + c] = t;
        t
    }

    /// Where the first match ends, searching `text` from `start`
    /// (`not_bol`: `^` doesn't hold at the text's start); `Some(None)`
    /// if there is no match, `None` if the DFA gave up.
    pub fn first_end(&mut self, prog: &Program, text: &[u8], start: usize, not_bol: bool) -> Option<Option<usize>> {
        let utf8 = self.utf8;
        let prev_of = |p: usize| match p.checked_sub(1).map(|p| text[p]) {
            None if not_bol => Prev::StartNotBol,
            None => Prev::Start,
            Some(b'\n') => Prev::Newline,
            Some(b) if is_word(b) || (utf8 && b >= 0x80) => Prev::Word,
            Some(_) => Prev::Other,
        };
        let mut state = self.start(prev_of(start));
        let mut resets = 0;
        let mut pos = start;
        let end_class = self.stride - 1;
        loop {
            // Nothing under way: on to where a match can start.
            if !self.first_bytes.is_empty() && self.idle[state as usize] {
                let rest = &text[pos..];
                let skip = match self.first_bytes[..] {
                    [b] => crate::memchr(b, rest),
                    [a, b, ..] => crate::memchr2(a, b, rest),
                    [] => Some(0),
                };
                match skip {
                    // No match can start in the rest (nor an empty one end
                    // there: a pattern with first bytes can't match empty).
                    None => return Some(None),
                    Some(0) => {}
                    Some(n) => {
                        pos += n;
                        state = self.start(prev_of(pos));
                    }
                }
            }
            let c = match text.get(pos) {
                Some(&b) => self.class[b as usize] as usize,
                None => end_class,
            };
            let mut t = self.table[state as usize * self.stride + c];
            if t == UNKNOWN {
                if self.states.len() >= MAX_STATES || self.table.len() >= MAX_TABLE {
                    if resets == MAX_RESETS {
                        return None;
                    }
                    resets += 1;
                    let key = self.states[state as usize].clone();
                    self.reset();
                    state = self.intern(key);
                }
                t = self.next(prog, state, c);
            }
            if t & MATCHED != 0 {
                return Some(Some(pos));
            }
            if pos >= text.len() {
                return Some(None);
            }
            state = t & !MATCHED;
            // Anchored and nothing waiting: no match can come.
            if !self.every && self.states[state as usize].0.is_empty() {
                return Some(None);
            }
            pos += 1;
        }
    }
}
