// SPDX-License-Identifier: MIT OR Apache-2.0

//! The text being edited: lines of bytes (UTF-8 expected, any bytes
//! kept), edits as insertions and deletions, and undo/redo of them.

use alloc::vec::Vec;

/// A place in the text: line index and byte offset in the line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pos {
    pub line: usize,
    pub col: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Edit {
    Insert { at: Pos, text: Vec<u8> },
    Delete { at: Pos, text: Vec<u8> },
}

#[derive(Debug)]
pub struct Buffer {
    pub lines: Vec<Vec<u8>>,
    /// Edits to undo and redo, each marked when it goes with the one
    /// before it (a replacement: undone and redone together).
    undo: Vec<(Edit, bool)>,
    redo: Vec<(Edit, bool)>,
    /// The undo depth at the last save (`None`: that state is gone).
    saved: Option<usize>,
    /// The next edit may merge with the previous one (typing).
    merge: bool,
}

/// Whether `b` starts a character (not a UTF-8 continuation byte).
pub fn is_start(b: u8) -> bool {
    b & 0xC0 != 0x80
}

impl Buffer {
    /// The lines of `data`. A final newline leaves an empty last line (as
    /// in nano, the place after the text).
    pub fn from_bytes(data: &[u8]) -> Buffer {
        let lines: Vec<Vec<u8>> = data.split(|&c| c == b'\n').map(<[u8]>::to_vec).collect();
        Buffer { lines, undo: Vec::new(), redo: Vec::new(), saved: Some(0), merge: false }
    }

    /// The file's bytes: the lines joined by newlines, with a final
    /// newline added when the last line has text.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.lines.join(&b'\n');
        if self.lines.last().is_some_and(|l| !l.is_empty()) {
            out.push(b'\n');
        }
        out
    }

    /// Lines of text (the empty line after a final newline does not count).
    pub fn text_lines(&self) -> usize {
        self.lines.len() - usize::from(self.lines.last().is_some_and(Vec::is_empty))
    }

    /// Whether the text differs from the last save.
    pub fn modified(&self) -> bool {
        self.saved != Some(self.undo.len())
    }

    pub fn mark_saved(&mut self) {
        self.merge = false;
        self.saved = Some(self.undo.len());
    }

    /// A new edit discards redo history (and a save point inside it).
    fn forget_redo(&mut self) {
        if !self.redo.is_empty() && self.saved.is_some_and(|s| s > self.undo.len()) {
            self.saved = None;
        }
        self.redo.clear();
    }

    pub fn clamp(&self, p: Pos) -> Pos {
        let line = p.line.min(self.lines.len() - 1);
        let mut col = p.col.min(self.lines[line].len());
        while col > 0 && col < self.lines[line].len() && !is_start(self.lines[line][col]) {
            col -= 1;
        }
        Pos { line, col }
    }

    /// The position after `text` inserted at `at`.
    fn end_of(at: Pos, text: &[u8]) -> Pos {
        match text.iter().rposition(|&c| c == b'\n') {
            Some(i) => Pos { line: at.line + text.iter().filter(|&&c| c == b'\n').count(), col: text.len() - i - 1 },
            None => Pos { line: at.line, col: at.col + text.len() },
        }
    }

    fn raw_insert(&mut self, at: Pos, text: &[u8]) -> Pos {
        let tail = self.lines[at.line].split_off(at.col);
        let mut parts = text.split(|&c| c == b'\n');
        self.lines[at.line].extend_from_slice(parts.next().unwrap_or_default());
        let mut line = at.line;
        for p in parts {
            line += 1;
            self.lines.insert(line, p.to_vec());
        }
        let end = Pos { line, col: self.lines[line].len() };
        self.lines[line].extend_from_slice(&tail);
        end
    }

    fn raw_delete(&mut self, from: Pos, to: Pos) -> Vec<u8> {
        if from.line == to.line {
            return self.lines[from.line].drain(from.col..to.col).collect();
        }
        let mut text: Vec<u8> = self.lines[from.line].drain(from.col..).collect();
        for _ in from.line + 1..to.line {
            text.push(b'\n');
            text.extend_from_slice(&self.lines.remove(from.line + 1));
        }
        text.push(b'\n');
        let last = self.lines.remove(from.line + 1);
        text.extend_from_slice(&last[..to.col]);
        self.lines[from.line].extend_from_slice(&last[to.col..]);
        text
    }

    /// Insert `text` at `at`; returns the position after it.
    pub fn insert(&mut self, at: Pos, text: &[u8]) -> Pos {
        if text.is_empty() {
            return at;
        }
        let end = self.raw_insert(at, text);
        // Typing merges into one undo step (up to a word boundary).
        let merge = self.merge
            && !text.contains(&b'\n')
            && matches!(self.undo.last(), Some((Edit::Insert { at: a, text: t }, _)) if Self::end_of(*a, t) == at && !t.ends_with(b" "));
        self.forget_redo();
        if merge {
            if let Some((Edit::Insert { text: t, .. }, _)) = self.undo.last_mut() {
                t.extend_from_slice(text);
            }
        } else {
            self.undo.push((Edit::Insert { at, text: text.to_vec() }, false));
        }
        self.merge = true;
        end
    }

    /// Delete from `from` to `to`; returns the text.
    pub fn delete(&mut self, from: Pos, to: Pos) -> Vec<u8> {
        if from >= to {
            return Vec::new();
        }
        let text = self.raw_delete(from, to);
        self.forget_redo();
        self.undo.push((Edit::Delete { at: from, text: text.clone() }, false));
        self.merge = false;
        text
    }

    /// Replace `from..to` with `text`, one step for undo and redo; returns
    /// the position after the new text.
    pub fn replace(&mut self, from: Pos, to: Pos, text: &[u8]) -> Pos {
        let deleted = from < to;
        self.delete(from, to);
        if text.is_empty() {
            return from;
        }
        let end = self.raw_insert(from, text);
        self.forget_redo();
        self.undo.push((Edit::Insert { at: from, text: text.to_vec() }, deleted));
        self.merge = false;
        end
    }

    /// End a group of merged edits (cursor movement, commands).
    pub fn seal(&mut self) {
        self.merge = false;
    }

    /// Undo the last edit (with those that go with it); the cursor
    /// position to show.
    pub fn undo(&mut self) -> Option<Pos> {
        let mut pos = None;
        while let Some((e, joined)) = self.undo.pop() {
            self.merge = false;
            pos = Some(match &e {
                Edit::Insert { at, text } => {
                    self.raw_delete(*at, Self::end_of(*at, text));
                    *at
                }
                Edit::Delete { at, text } => self.raw_insert(*at, text),
            });
            self.redo.push((e, joined));
            if !joined {
                break;
            }
        }
        pos
    }

    pub fn redo(&mut self) -> Option<Pos> {
        let (e, joined) = self.redo.pop()?;
        let mut pos = self.apply(&e);
        self.undo.push((e, joined));
        // The edits that go with it.
        while self.redo.last().is_some_and(|(_, j)| *j) {
            let (e, j) = self.redo.pop()?;
            pos = self.apply(&e);
            self.undo.push((e, j));
        }
        Some(pos)
    }

    fn apply(&mut self, e: &Edit) -> Pos {
        match e {
            Edit::Insert { at, text } => self.raw_insert(*at, text),
            Edit::Delete { at, text } => {
                self.raw_delete(*at, Self::end_of(*at, text));
                *at
            }
        }
    }

    /// The previous character boundary before `p` (across lines).
    pub fn prev(&self, p: Pos) -> Pos {
        if p.col == 0 {
            return if p.line == 0 { p } else { Pos { line: p.line - 1, col: self.lines[p.line - 1].len() } };
        }
        let l = &self.lines[p.line];
        let mut c = p.col - 1;
        while c > 0 && !is_start(l[c]) {
            c -= 1;
        }
        Pos { line: p.line, col: c }
    }

    pub fn next(&self, p: Pos) -> Pos {
        let l = &self.lines[p.line];
        if p.col >= l.len() {
            return if p.line + 1 < self.lines.len() { Pos { line: p.line + 1, col: 0 } } else { p };
        }
        let mut c = p.col + 1;
        while c < l.len() && !is_start(l[c]) {
            c += 1;
        }
        Pos { line: p.line, col: c }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_replacement_is_one_step() {
        let mut b = Buffer::from_bytes(b"a cat\nsat\n");
        b.insert(Pos { line: 1, col: 3 }, b"!");
        b.seal();
        let end = b.replace(Pos { line: 0, col: 2 }, Pos { line: 1, col: 3 }, b"dog\nran");
        assert_eq!((b.to_bytes().as_slice(), end), (b"a dog\nran!\n".as_slice(), Pos { line: 1, col: 3 }));
        assert_eq!(b.undo(), Some(Pos { line: 1, col: 3 }));
        assert_eq!(b.to_bytes(), b"a cat\nsat!\n");
        assert_eq!(b.redo(), Some(Pos { line: 1, col: 3 }));
        assert_eq!(b.to_bytes(), b"a dog\nran!\n");
        b.undo();
        b.undo();
        assert_eq!(b.to_bytes(), b"a cat\nsat\n");
        assert!(!b.modified());
        // Replacing with nothing is a deletion.
        assert_eq!(b.replace(Pos { line: 0, col: 0 }, Pos { line: 0, col: 2 }, b""), Pos::default());
        assert_eq!(b.to_bytes(), b"cat\nsat\n");
    }

    #[test]
    fn edits_and_undo() {
        let mut b = Buffer::from_bytes(b"one\ntwo\n");
        assert_eq!(b.lines.len(), 3);
        assert_eq!(b.text_lines(), 2);
        assert_eq!(b.to_bytes(), b"one\ntwo\n");
        let p = b.insert(Pos { line: 0, col: 3 }, b"!");
        b.insert(p, b"?");
        assert_eq!(b.lines[0], b"one!?");
        b.seal();
        let end = b.insert(Pos { line: 1, col: 0 }, b"x\ny");
        assert_eq!(end, Pos { line: 2, col: 1 });
        assert_eq!(b.to_bytes(), b"one!?\nx\nytwo\n");
        let gone = b.delete(Pos { line: 0, col: 3 }, Pos { line: 2, col: 1 });
        assert_eq!(gone, b"!?\nx\ny");
        assert_eq!(b.to_bytes(), b"onetwo\n");
        b.undo();
        assert_eq!(b.to_bytes(), b"one!?\nx\nytwo\n");
        b.undo();
        b.undo();
        assert_eq!(b.to_bytes(), b"one\ntwo\n");
        assert!(!b.modified());
        b.redo();
        assert_eq!(b.lines[0], b"one!?");
        assert!(b.modified());
        b.mark_saved();
        assert!(!b.modified());
        b.insert(Pos { line: 0, col: 0 }, b"z");
        assert!(b.modified());
        b.undo();
        assert!(!b.modified());
        let mut u = Buffer::from_bytes("aé".as_bytes());
        assert_eq!(u.prev(Pos { line: 0, col: 3 }), Pos { line: 0, col: 1 });
        assert_eq!(u.next(Pos { line: 0, col: 1 }), Pos { line: 0, col: 3 });
        u.delete(Pos { line: 0, col: 1 }, Pos { line: 0, col: 3 });
        assert_eq!(u.to_bytes(), b"a\n");
        assert_eq!(Buffer::from_bytes(b"").to_bytes(), b"");
        assert_eq!(Buffer::from_bytes(b"no newline").to_bytes(), b"no newline\n");
    }
}
