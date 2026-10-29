// SPDX-License-Identifier: MIT OR Apache-2.0

//! Syntax trees to VM programs, and the facts about a pattern the
//! matchers use to skip work.

use alloc::vec::Vec;

use crate::{ByteSet, Error, Look, Node};

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Inst {
    /// Consume one byte in the set.
    Set(ByteSet),
    /// Try both, the first one first.
    Split(usize, usize),
    Jmp(usize),
    /// Record the position in capture slot n.
    Save(usize),
    Look(Look),
    /// Match what group n matched.
    Backref(usize),
    /// Start of a `*`/`{m,}` loop body: remember the position in register
    /// n (for the backtracker's empty-iteration check).
    Mark(usize),
    /// End of a loop body: back to the loop head if the iteration consumed
    /// something (register n), else fall through.
    Loop(usize, usize),
    /// `\K`: capture slot 0 (the match's start) is here.
    Keep,
    /// Run sub-program n (Perl's assertions and atomic groups; only the
    /// backtracker runs these).
    Sub(usize),
    Match,
}

/// What a sub-program is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubKind {
    Ahead {
        negate: bool,
    },
    /// Ends where the assertion stands, starting `min..=max` bytes before.
    Behind {
        negate: bool,
        min: u32,
        max: u32,
    },
    Atomic,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Program {
    pub insts: Vec<Inst>,
    /// Loop registers (Mark/Loop).
    pub regs: usize,
    /// Sub-programs (assertions, atomic groups), sharing the capture slots.
    pub subs: Vec<(Program, SubKind)>,
}

/// Programs beyond this size are refused (`a{1000}{1000}`).
const MAX_INSTS: usize = 200_000;

pub(crate) fn compile(n: &Node, _groups: usize) -> Result<Program, Error> {
    let mut c = Program::default();
    c.insts.push(Inst::Save(0));
    emit(&mut c, n)?;
    c.insts.push(Inst::Save(1));
    c.insts.push(Inst::Match);
    Ok(c)
}

fn push(c: &mut Program, i: Inst) -> Result<usize, Error> {
    if c.insts.len() >= MAX_INSTS {
        return Err(Error(alloc::string::String::from("Regular expression too big")));
    }
    c.insts.push(i);
    Ok(c.insts.len() - 1)
}

fn emit(c: &mut Program, n: &Node) -> Result<(), Error> {
    match n {
        Node::Empty => {}
        Node::Set(s) => {
            push(c, Inst::Set(*s))?;
        }
        Node::Look(l) => {
            push(c, Inst::Look(*l))?;
        }
        Node::Backref(k) => {
            push(c, Inst::Backref(*k))?;
        }
        Node::Group(k, b) => {
            push(c, Inst::Save(2 * k))?;
            emit(c, b)?;
            push(c, Inst::Save(2 * k + 1))?;
        }
        Node::Concat(v) => {
            for x in v {
                emit(c, x)?;
            }
        }
        Node::Alt(v) => {
            let mut jumps = Vec::new();
            for (i, x) in v.iter().enumerate() {
                if i + 1 < v.len() {
                    let split = push(c, Inst::Split(0, 0))?;
                    emit(c, x)?;
                    jumps.push(push(c, Inst::Jmp(0))?);
                    let next = c.insts.len();
                    c.insts[split] = Inst::Split(split + 1, next);
                } else {
                    emit(c, x)?;
                }
            }
            let end = c.insts.len();
            for j in jumps {
                c.insts[j] = Inst::Jmp(end);
            }
        }
        Node::Repeat(b, min, max) => repeat(c, b, *min, *max, true)?,
        Node::Lazy(b, min, max) => repeat(c, b, *min, *max, false)?,
        Node::Keep => {
            push(c, Inst::Keep)?;
        }
        Node::Atomic(b) => sub(c, b, SubKind::Atomic)?,
        Node::Around { ahead, negate, node } => {
            let kind = if *ahead {
                SubKind::Ahead { negate: *negate }
            } else {
                let (min, max) = lengths(node);
                let Some(max) = max else {
                    return Err(Error(alloc::string::String::from("length of lookbehind assertion is not limited")));
                };
                SubKind::Behind { negate: *negate, min, max }
            };
            sub(c, node, kind)?;
        }
    }
    Ok(())
}

/// A repetition; `greedy` tries another iteration before leaving.
fn repeat(c: &mut Program, b: &Node, min: u32, max: Option<u32>, greedy: bool) -> Result<(), Error> {
    let split = |stay: usize, out: usize| if greedy { Inst::Split(stay, out) } else { Inst::Split(out, stay) };
    for _ in 0..min {
        emit(c, b)?;
    }
    match max {
        None => {
            let reg = c.regs;
            c.regs += 1;
            let head = push(c, Inst::Split(0, 0))?;
            push(c, Inst::Mark(reg))?;
            emit(c, b)?;
            push(c, Inst::Loop(head, reg))?;
            let out = c.insts.len();
            c.insts[head] = split(head + 1, out);
        }
        Some(max) => {
            let mut splits = Vec::new();
            for _ in min..max {
                splits.push(push(c, Inst::Split(0, 0))?);
                emit(c, b)?;
            }
            let out = c.insts.len();
            for s in splits {
                c.insts[s] = split(s + 1, out);
            }
        }
    }
    Ok(())
}

/// A sub-program for `n`: the node and a match, sharing the capture slots.
fn sub(c: &mut Program, n: &Node, kind: SubKind) -> Result<(), Error> {
    let mut p = Program::default();
    emit(&mut p, n)?;
    p.insts.push(Inst::Match);
    c.regs = c.regs.max(p.regs);
    let idx = c.subs.len();
    c.subs.push((p, kind));
    push(c, Inst::Sub(idx))?;
    Ok(())
}

/// The fewest and most bytes `n` can match (`None`: no bound).
pub(crate) fn lengths(n: &Node) -> (u32, Option<u32>) {
    match n {
        Node::Empty | Node::Look(_) | Node::Keep | Node::Around { .. } => (0, Some(0)),
        Node::Set(_) => (1, Some(1)),
        Node::Backref(_) => (0, None),
        Node::Group(_, b) | Node::Atomic(b) => lengths(b),
        Node::Concat(v) => v.iter().fold((0, Some(0)), |(a, b), x| {
            let (c, d) = lengths(x);
            (a.saturating_add(c), b.zip(d).map(|(b, d)| b.saturating_add(d)))
        }),
        Node::Alt(v) => {
            let all: Vec<(u32, Option<u32>)> = v.iter().map(lengths).collect();
            let min = all.iter().map(|x| x.0).min().unwrap_or(0);
            let max = all.iter().try_fold(0u32, |m, x| x.1.map(|y| m.max(y)));
            (min, max)
        }
        Node::Repeat(b, lo, hi) | Node::Lazy(b, lo, hi) => {
            let (a, m) = lengths(b);
            (a.saturating_mul(*lo), hi.zip(m).map(|(h, m)| h.saturating_mul(m)).filter(|_| hi.is_some()))
        }
    }
}

/// (first bytes, can match empty, the set is exact).
fn first(n: &Node) -> (ByteSet, bool, bool) {
    match n {
        Node::Empty | Node::Look(_) | Node::Keep | Node::Around { .. } => (ByteSet::default(), true, true),
        Node::Atomic(b) => first(b),
        Node::Set(s) => (*s, false, true),
        Node::Backref(_) => (ByteSet::default(), true, false),
        Node::Group(_, b) => first(b),
        Node::Concat(v) => {
            let mut set = ByteSet::default();
            for x in v {
                let (s, nullable, ok) = first(x);
                if !ok {
                    return (set, true, false);
                }
                set.union(&s);
                if !nullable {
                    return (set, false, true);
                }
            }
            (set, true, true)
        }
        Node::Alt(v) => {
            let mut set = ByteSet::default();
            let mut nullable = false;
            for x in v {
                let (s, nl, ok) = first(x);
                if !ok {
                    return (set, true, false);
                }
                set.union(&s);
                nullable |= nl;
            }
            (set, nullable, true)
        }
        Node::Repeat(b, min, max) | Node::Lazy(b, min, max) => {
            let (s, nullable, ok) = first(b);
            (s, nullable || *min == 0 || *max == Some(0), ok)
        }
    }
}

/// The bytes every match starts with, if the pattern cannot match empty.
pub(crate) fn first_bytes(n: &Node) -> Option<ByteSet> {
    let (s, nullable, ok) = first(n);
    (ok && !nullable).then_some(s)
}

/// Every match starts at a `^` or `` \` `` (outside REG_NEWLINE).
pub(crate) fn anchored(n: &Node) -> bool {
    match n {
        Node::Look(Look::LineStart | Look::TextStart) => true,
        Node::Group(_, b) => anchored(b),
        Node::Concat(v) => v.first().is_some_and(anchored),
        Node::Alt(v) => !v.is_empty() && v.iter().all(anchored),
        _ => false,
    }
}
