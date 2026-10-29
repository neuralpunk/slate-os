// SPDX-License-Identifier: MIT OR Apache-2.0

//! The matchers: a Pike VM (threads advance in lock step over the text,
//! one per program counter, so time is linear) and, for back-references, a
//! depth-first backtracker with a step budget. Both find the leftmost
//! match and, among matches starting there, the longest.

use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;

use crate::compile::{Inst, Program, SubKind};
use crate::{ByteSet, Captures, Look, is_word};

const NONE: usize = usize::MAX;

/// Backtracking steps allowed per start position. States already tried
/// are not tried again, so this bounds only patterns with very many
/// distinct states.
const STEP_BUDGET: usize = 20_000_000;
/// States remembered as tried, at most (beyond it, they are tried again),
/// and the steps after which they start to be remembered: most searches
/// end long before, and remembering costs more than it saves for them.
const MEMO_MAX: usize = 4_000_000;
const MEMO_AFTER: usize = 4096;

pub(crate) struct Ctx<'a> {
    pub text: &'a [u8],
    pub newline: bool,
    pub not_bol: bool,
    pub icase: bool,
    /// UTF-8 text: bytes from 0x80 up are word bytes.
    pub utf8: bool,
}

fn look(ctx: &Ctx<'_>, l: Look, pos: usize) -> bool {
    let t = ctx.text;
    let prev = pos.checked_sub(1).map(|p| t[p]);
    let next = t.get(pos).copied();
    let word = |b: u8| is_word(b) || (ctx.utf8 && b >= 0x80);
    let (wp, wn) = (prev.is_some_and(word), next.is_some_and(word));
    match l {
        Look::LineStart => (pos == 0 && !ctx.not_bol) || (ctx.newline && prev == Some(b'\n')),
        Look::LineEnd => pos == t.len() || (ctx.newline && next == Some(b'\n')),
        Look::TextStart => pos == 0,
        Look::TextEnd => pos == t.len(),
        Look::Word => wp != wn,
        Look::NotWord => wp == wn,
        Look::WordStart => !wp && wn,
        Look::WordEnd => wp && !wn,
        Look::NoWordBefore => !wp,
        Look::NoWordAfter => !wn,
    }
}

fn to_captures(slots: &[usize], groups: usize) -> Captures {
    (0..=groups)
        .map(|g| {
            let (a, b) = (slots[2 * g], slots[2 * g + 1]);
            (a != NONE && b != NONE && a <= b).then_some((a, b))
        })
        .collect()
}

/// A thread list: program counters in priority order, each with its
/// capture slots; a generation mark per pc makes membership O(1).
struct List {
    pcs: Vec<usize>,
    slots: Vec<usize>,
    mark: Vec<u32>,
    generation: u32,
    nslots: usize,
}

impl List {
    fn new(n: usize, nslots: usize) -> List {
        List { pcs: Vec::new(), slots: vec![NONE; n * nslots], mark: vec![0; n], generation: 1, nslots }
    }
    fn clear(&mut self) {
        self.pcs.clear();
        // Lists live as long as their pattern: a generation wrapping
        // round must not find old marks current.
        if self.generation == u32::MAX {
            self.mark.fill(0);
            self.generation = 0;
        }
        self.generation += 1;
    }
    /// Mark `pc` visited; false if it already was.
    fn visit(&mut self, pc: usize) -> bool {
        if self.mark[pc] == self.generation {
            return false;
        }
        self.mark[pc] = self.generation;
        true
    }
    fn push(&mut self, pc: usize, caps: &[usize]) {
        self.pcs.push(pc);
        let n = self.nslots;
        self.slots[pc * n..pc * n + n].copy_from_slice(caps);
    }
    fn caps(&self, pc: usize) -> &[usize] {
        &self.slots[pc * self.nslots..(pc + 1) * self.nslots]
    }
}

enum Frame {
    Explore(usize),
    Restore(usize, usize),
}

/// The Pike VM's lists and stacks, kept with the pattern so a search
/// allocates nothing.
pub(crate) struct Scratch {
    clist: List,
    nlist: List,
    caps: Vec<usize>,
    stack: Vec<Frame>,
}

impl Scratch {
    pub fn new(prog: &Program, groups: usize) -> Scratch {
        let n = prog.insts.len();
        let nslots = 2 * (groups + 1);
        Scratch {
            clist: List::new(n, nslots),
            nlist: List::new(n, nslots),
            caps: vec![NONE; nslots],
            stack: Vec::new(),
        }
    }
}

impl core::fmt::Debug for Scratch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Scratch")
    }
}

impl Clone for Scratch {
    /// A copy of a pattern starts with lists of its own.
    fn clone(&self) -> Scratch {
        let n = self.clist.mark.len();
        let nslots = self.caps.len();
        Scratch {
            clist: List::new(n, nslots),
            nlist: List::new(n, nslots),
            caps: vec![NONE; nslots],
            stack: Vec::new(),
        }
    }
}

/// Follow the empty transitions from `pc` at `pos`, adding the threads
/// that wait for a byte (or match) to `list`.
fn add(
    prog: &Program,
    list: &mut List,
    pc: usize,
    pos: usize,
    caps: &mut [usize],
    ctx: &Ctx<'_>,
    stack: &mut Vec<Frame>,
) {
    stack.push(Frame::Explore(pc));
    while let Some(f) = stack.pop() {
        let pc = match f {
            Frame::Restore(slot, v) => {
                caps[slot] = v;
                continue;
            }
            Frame::Explore(pc) => pc,
        };
        if !list.visit(pc) {
            continue;
        }
        match &prog.insts[pc] {
            Inst::Jmp(t) | Inst::Loop(t, _) => stack.push(Frame::Explore(*t)),
            Inst::Split(a, b) => {
                stack.push(Frame::Explore(*b));
                stack.push(Frame::Explore(*a));
            }
            Inst::Save(s) => {
                stack.push(Frame::Restore(*s, caps[*s]));
                caps[*s] = pos;
                stack.push(Frame::Explore(pc + 1));
            }
            Inst::Mark(_) => stack.push(Frame::Explore(pc + 1)),
            Inst::Look(l) => {
                if look(ctx, *l, pos) {
                    stack.push(Frame::Explore(pc + 1));
                }
            }
            Inst::Keep => {
                stack.push(Frame::Restore(0, caps[0]));
                caps[0] = pos;
                stack.push(Frame::Explore(pc + 1));
            }
            Inst::Set(_) | Inst::Match => list.push(pc, caps),
            // Patterns with back-references, assertions or atomic groups
            // never run here.
            Inst::Backref(_) | Inst::Sub(_) => {}
        }
    }
}

pub(crate) fn pike(
    prog: &Program,
    groups: usize,
    ctx: &Ctx<'_>,
    start: usize,
    first: Option<&ByteSet>,
    anchored: bool,
    sc: &mut Scratch,
) -> Option<Captures> {
    let text = ctx.text;
    let Scratch { clist, nlist, caps, stack } = sc;
    clist.clear();
    nlist.clear();
    let mut best: Option<Vec<usize>> = None;
    let mut pos = start;
    loop {
        if best.is_none() && (!anchored || pos == start) {
            if clist.pcs.is_empty()
                && let Some(f) = first
            {
                while pos < text.len() && !f.contains(text[pos]) {
                    pos += 1;
                }
                if pos >= text.len() {
                    break;
                }
                clist.clear();
            }
            caps.fill(NONE);
            add(prog, clist, 0, pos, caps, ctx, stack);
        }
        if clist.pcs.is_empty() {
            if best.is_some() || anchored || pos >= text.len() {
                break;
            }
            // A fresh step: forget what the failed start visited.
            clist.clear();
            pos += 1;
            continue;
        }
        nlist.clear();
        for k in 0..clist.pcs.len() {
            let pc = clist.pcs[k];
            let tc = clist.caps(pc);
            if let Some(b) = &best
                && tc[0] > b[0]
            {
                continue;
            }
            match &prog.insts[pc] {
                Inst::Match => {
                    let better = match &best {
                        None => true,
                        Some(b) => tc[0] < b[0] || (tc[0] == b[0] && pos > b[1]),
                    };
                    if better {
                        best = Some(tc.to_vec());
                    }
                }
                Inst::Set(s) if pos < text.len() && s.contains(text[pos]) => {
                    caps.copy_from_slice(tc);
                    add(prog, nlist, pc + 1, pos + 1, caps, ctx, stack);
                }
                _ => {}
            }
        }
        core::mem::swap(clist, nlist);
        if pos >= text.len() {
            break;
        }
        pos += 1;
    }
    best.map(|b| to_captures(&b, groups))
}

enum BFrame {
    Explore(usize, usize),
    RestoreSlot(usize, usize),
    RestoreReg(usize, usize),
}

/// The capture slots that back-references read: what, beside the
/// program counter, the position and the loop registers, decides where a
/// path can go from here.
fn backref_slots(prog: &Program) -> Vec<usize> {
    let mut v: Vec<usize> =
        prog.insts.iter().filter_map(|i| if let Inst::Backref(g) = i { Some(*g) } else { None }).collect();
    v.sort_unstable();
    v.dedup();
    v.iter().flat_map(|g| [2 * g, 2 * g + 1]).collect()
}

/// How a depth-first run picks its match.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pick {
    /// The longest from the start (POSIX).
    Longest,
    /// The first in priority order (Perl).
    First,
}

/// The match starting exactly at `s`, depth-first over the paths:
/// `Longest` or the `First` found, ending anywhere or only at `end_at`
/// (a lookbehind). Returns the capture slots and where the match ends.
/// A state already explored (the same instruction, position, loop
/// registers and back-referenced captures) leads nowhere new: the first
/// path there had priority, so it is not explored again.
fn run(
    prog: &Program,
    ctx: &Ctx<'_>,
    s: usize,
    init: Vec<usize>,
    pick: Pick,
    end_at: Option<usize>,
) -> Option<(Vec<usize>, usize)> {
    let text = ctx.text;
    let limit = end_at.unwrap_or(text.len());
    let mut slots = init;
    let mut regs = vec![NONE; prog.regs];
    let mut stack = vec![BFrame::Explore(0, s)];
    let mut best: Option<(Vec<usize>, usize)> = None;
    let mut steps = 0;
    let keyed = backref_slots(prog);
    let mut tried: BTreeSet<Vec<usize>> = BTreeSet::new();
    // Take the slots a sub-program set, to be put back on the way back.
    let adopt = |slots: &mut Vec<usize>, got: &[usize], stack: &mut Vec<BFrame>| {
        for (k, &v) in got.iter().enumerate() {
            if slots[k] != v {
                stack.push(BFrame::RestoreSlot(k, slots[k]));
                slots[k] = v;
            }
        }
    };
    while let Some(f) = stack.pop() {
        let (pc, pos) = match f {
            BFrame::RestoreSlot(k, v) => {
                slots[k] = v;
                continue;
            }
            BFrame::RestoreReg(k, v) => {
                regs[k] = v;
                continue;
            }
            BFrame::Explore(pc, pos) => (pc, pos),
        };
        steps += 1;
        if steps > STEP_BUDGET {
            break;
        }
        // Only where paths meet: splits and loop ends.
        if steps > MEMO_AFTER && matches!(prog.insts[pc], Inst::Split(..) | Inst::Loop(..)) && tried.len() < MEMO_MAX {
            let mut key = Vec::with_capacity(2 + keyed.len() + regs.len());
            key.push(pc);
            key.push(pos);
            key.extend(keyed.iter().map(|&k| slots[k]));
            key.extend_from_slice(&regs);
            if !tried.insert(key) {
                continue;
            }
        }
        match &prog.insts[pc] {
            Inst::Set(set) => {
                if pos < limit && set.contains(text[pos]) {
                    stack.push(BFrame::Explore(pc + 1, pos + 1));
                }
            }
            Inst::Split(a, b) => {
                stack.push(BFrame::Explore(*b, pos));
                stack.push(BFrame::Explore(*a, pos));
            }
            Inst::Jmp(t) => stack.push(BFrame::Explore(*t, pos)),
            Inst::Save(k) => {
                stack.push(BFrame::RestoreSlot(*k, slots[*k]));
                slots[*k] = pos;
                stack.push(BFrame::Explore(pc + 1, pos));
            }
            Inst::Keep => {
                stack.push(BFrame::RestoreSlot(0, slots[0]));
                slots[0] = pos;
                stack.push(BFrame::Explore(pc + 1, pos));
            }
            Inst::Look(l) => {
                if look(ctx, *l, pos) {
                    stack.push(BFrame::Explore(pc + 1, pos));
                }
            }
            Inst::Mark(r) => {
                stack.push(BFrame::RestoreReg(*r, regs[*r]));
                regs[*r] = pos;
                stack.push(BFrame::Explore(pc + 1, pos));
            }
            Inst::Loop(head, r) => {
                // An iteration that consumed nothing ends the loop.
                let next = if regs[*r] != NONE && pos > regs[*r] { *head } else { pc + 1 };
                stack.push(BFrame::Explore(next, pos));
            }
            Inst::Backref(g) => {
                let (a, b) = (slots[2 * g], slots[2 * g + 1]);
                if a == NONE || b == NONE || a > b {
                    continue;
                }
                let len = b - a;
                if pos + len <= limit {
                    let (x, y) = (&text[a..b], &text[pos..pos + len]);
                    if if ctx.icase { x.eq_ignore_ascii_case(y) } else { x == y } {
                        stack.push(BFrame::Explore(pc + 1, pos + len));
                    }
                }
            }
            Inst::Sub(i) => {
                let (sub, kind) = &prog.subs[*i];
                match *kind {
                    SubKind::Ahead { negate } => {
                        let got = run(sub, ctx, pos, slots.clone(), Pick::First, None);
                        match (got, negate) {
                            (Some((got, _)), false) => {
                                adopt(&mut slots, &got, &mut stack);
                                stack.push(BFrame::Explore(pc + 1, pos));
                            }
                            (None, true) => stack.push(BFrame::Explore(pc + 1, pos)),
                            _ => {}
                        }
                    }
                    SubKind::Behind { negate, min, max } => {
                        let got = (min as usize..=max as usize)
                            .filter(|&k| k <= pos)
                            .find_map(|k| run(sub, ctx, pos - k, slots.clone(), Pick::First, Some(pos)));
                        match (got, negate) {
                            (Some((got, _)), false) => {
                                adopt(&mut slots, &got, &mut stack);
                                stack.push(BFrame::Explore(pc + 1, pos));
                            }
                            (None, true) => stack.push(BFrame::Explore(pc + 1, pos)),
                            _ => {}
                        }
                    }
                    // The first way it matches, and no other.
                    SubKind::Atomic => {
                        if let Some((got, end)) = run(sub, ctx, pos, slots.clone(), Pick::First, None) {
                            adopt(&mut slots, &got, &mut stack);
                            stack.push(BFrame::Explore(pc + 1, end));
                        }
                    }
                }
            }
            Inst::Match => {
                if end_at.is_some_and(|e| pos != e) {
                    continue;
                }
                if pick == Pick::First {
                    return Some((slots, pos));
                }
                if best.as_ref().is_none_or(|b| pos > b.1) {
                    best = Some((slots.clone(), pos));
                    if pos == text.len() {
                        // Nothing can be longer.
                        break;
                    }
                }
            }
        }
    }
    best
}

/// The leftmost match at or after `start` (only at `start` if
/// `anchored`): the longest there, or with `first` (Perl) the first in
/// priority order. `starts`, when known, are the bytes a match can
/// start with.
pub(crate) fn backtrack(
    prog: &Program,
    groups: usize,
    ctx: &Ctx<'_>,
    start: usize,
    anchored: bool,
    first: bool,
    starts: Option<&ByteSet>,
) -> Option<Captures> {
    let pick = if first { Pick::First } else { Pick::Longest };
    for s in start..=ctx.text.len() {
        if anchored && s != start {
            break;
        }
        // No match starts with this byte (`starts`: the bytes one can).
        if let Some(f) = starts
            && !ctx.text.get(s).is_some_and(|&b| f.contains(b))
        {
            continue;
        }
        if let Some((b, _)) = run(prog, ctx, s, vec![NONE; 2 * (groups + 1)], pick, None) {
            return Some(to_captures(&b, groups));
        }
    }
    None
}
