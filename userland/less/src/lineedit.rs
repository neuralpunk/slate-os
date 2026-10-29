// SPDX-License-Identifier: MIT OR Apache-2.0

//! The command line at the bottom of the screen (less(1), LINE EDITING;
//! ADR 0164): a cursor that moves by characters and words, deleting
//! either way, and the history of earlier lines (UPARROW retrieves the
//! previous one, or the previous one starting with what was typed).

use alloc::vec::Vec;

use crate::keys::Edit;

/// A command line being edited.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Line {
    pub text: Vec<u8>,
    /// A byte offset at a character's start.
    pub cursor: usize,
    /// Insert (the default) or overwrite (`insert` toggles).
    pub overwrite: bool,
    /// Where UPARROW and DOWNARROW are in the history, and what was typed
    /// before the first of them (the prefix they look for).
    at: Option<usize>,
    typed: Vec<u8>,
}

fn is_word(c: u8) -> bool {
    !c.is_ascii_whitespace()
}

impl Line {
    fn prev_char(&self, i: usize) -> usize {
        let mut j = i.saturating_sub(1);
        while j > 0 && self.text[j] & 0xC0 == 0x80 {
            j -= 1;
        }
        j
    }

    fn next_char(&self, i: usize) -> usize {
        let mut j = (i + 1).min(self.text.len());
        while j < self.text.len() && self.text[j] & 0xC0 == 0x80 {
            j += 1;
        }
        j
    }

    /// The start of the word left of `i` (spaces before it skipped).
    fn word_left(&self, mut i: usize) -> usize {
        while i > 0 && !is_word(self.text[i - 1]) {
            i -= 1;
        }
        while i > 0 && is_word(self.text[i - 1]) {
            i -= 1;
        }
        i
    }

    /// The start of the next word right of `i`.
    fn word_right(&self, mut i: usize) -> usize {
        while i < self.text.len() && is_word(self.text[i]) {
            i += 1;
        }
        while i < self.text.len() && !is_word(self.text[i]) {
            i += 1;
        }
        i
    }

    /// Type `bytes` (one character) at the cursor.
    pub fn insert(&mut self, bytes: &[u8]) {
        if self.overwrite && self.cursor < self.text.len() {
            let end = self.next_char(self.cursor);
            self.text.drain(self.cursor..end);
        }
        self.text.splice(self.cursor..self.cursor, bytes.iter().copied());
        self.cursor += bytes.len();
        self.at = None;
    }

    /// BACKSPACE: the character left of the cursor; false when the line
    /// is empty (the command is cancelled).
    pub fn backspace(&mut self) -> bool {
        if self.text.is_empty() {
            return false;
        }
        if self.cursor > 0 {
            let from = self.prev_char(self.cursor);
            self.text.drain(from..self.cursor);
            self.cursor = from;
        }
        true
    }

    /// ^U: the whole line; false when the cursor was at its start (the
    /// command is cancelled).
    pub fn kill(&mut self) -> bool {
        if self.cursor == 0 {
            return false;
        }
        self.text.clear();
        self.cursor = 0;
        true
    }

    /// A line-editing command; `history` is the list UPARROW and
    /// DOWNARROW walk (oldest first).
    pub fn apply(&mut self, e: Edit, history: &[Vec<u8>]) {
        match e {
            Edit::Left => self.cursor = self.prev_char(self.cursor),
            Edit::Right => self.cursor = self.next_char(self.cursor),
            Edit::WordLeft => self.cursor = self.word_left(self.cursor),
            Edit::WordRight => self.cursor = self.word_right(self.cursor),
            Edit::Home => self.cursor = 0,
            Edit::End => self.cursor = self.text.len(),
            Edit::Insert => self.overwrite = !self.overwrite,
            Edit::Delete if self.cursor < self.text.len() => {
                let end = self.next_char(self.cursor);
                self.text.drain(self.cursor..end);
            }
            Edit::WordBackspace => {
                let from = self.word_left(self.cursor);
                self.text.drain(from..self.cursor);
                self.cursor = from;
            }
            Edit::WordDelete => {
                let to = self.word_right(self.cursor);
                self.text.drain(self.cursor..to);
            }
            Edit::Up | Edit::Down => self.recall(e == Edit::Up, history),
            _ => {}
        }
    }

    /// The previous (or next) history line starting with what was typed.
    fn recall(&mut self, up: bool, history: &[Vec<u8>]) {
        if self.at.is_none() {
            self.typed = self.text.clone();
        }
        let from = self.at.unwrap_or(history.len());
        let hit = if up {
            (0..from).rev().find(|&i| history[i].starts_with(&self.typed))
        } else {
            (from + 1..history.len()).find(|&i| history[i].starts_with(&self.typed))
        };
        match hit {
            Some(i) => {
                self.at = Some(i);
                self.text = history[i].clone();
            }
            // Down past the newest: back to what was typed.
            None if !up => {
                self.at = None;
                self.text = self.typed.clone();
            }
            None => return,
        }
        self.cursor = self.text.len();
    }

    /// The display column of the cursor (control bytes show as `^X`).
    pub fn column(&self) -> usize {
        self.text[..self.cursor]
            .iter()
            .filter(|&&c| c & 0xC0 != 0x80)
            .map(|&c| if c < 0x20 || c == 0x7f { 2 } else { 1 })
            .sum()
    }

    /// The text as shown: control bytes as `^X`.
    pub fn shown(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for &c in &self.text {
            if c < 0x20 || c == 0x7f {
                out.extend_from_slice(&[b'^', c ^ 0x40]);
            } else {
                out.push(c);
            }
        }
        out
    }
}

/// TAB completion (`forw-complete`, `back-complete`): the names in `dir`
/// listing `entries` that start with the word left of the cursor, in
/// order; the `n`-th (wrapping), with `/` after a directory.
pub fn complete(line: &Line, entries: &[(Vec<u8>, bool)], n: usize) -> Option<Line> {
    let start = line.text[..line.cursor].iter().rposition(|&c| c == b' ').map_or(0, |p| p + 1);
    let word = &line.text[start..line.cursor];
    let (dir, base) = match word.iter().rposition(|&c| c == b'/') {
        Some(p) => (&word[..=p], &word[p + 1..]),
        None => (&b""[..], word),
    };
    let mut hits: Vec<&(Vec<u8>, bool)> = entries.iter().filter(|(e, _)| e.starts_with(base)).collect();
    hits.sort();
    if hits.is_empty() {
        return None;
    }
    let (name, is_dir) = hits[n % hits.len()];
    let mut text = line.text[..start].to_vec();
    text.extend_from_slice(dir);
    text.extend_from_slice(name);
    if *is_dir {
        text.push(b'/');
    }
    let cursor = text.len();
    text.extend_from_slice(&line.text[line.cursor..]);
    Some(Line { text, cursor, ..Line::default() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(s: &str) -> Line {
        let mut l = Line::default();
        for c in s.bytes() {
            l.insert(&[c]);
        }
        l
    }

    #[test]
    fn moving_and_deleting() {
        let mut l = typed("one two three");
        l.apply(Edit::WordLeft, &[]);
        assert_eq!(l.cursor, 8);
        l.apply(Edit::WordBackspace, &[]);
        assert_eq!((l.text.as_slice(), l.cursor), (&b"one three"[..], 4));
        l.apply(Edit::WordDelete, &[]);
        assert_eq!(l.text, b"one ");
        l.apply(Edit::Home, &[]);
        l.apply(Edit::Delete, &[]);
        l.insert(b"O");
        assert_eq!(l.text, b"One ");
        l.apply(Edit::Insert, &[]);
        l.insert(b"N");
        assert_eq!(l.text, b"ONe ");
        l.apply(Edit::End, &[]);
        assert!(l.backspace() && l.kill());
        assert!(!l.kill() && !l.backspace(), "empty: cancel");
        // UTF-8 moves by characters; control bytes show as ^X.
        let mut u = typed("a");
        u.insert("é".as_bytes());
        u.apply(Edit::Left, &[]);
        assert_eq!(u.cursor, 1);
        let c = typed("x\x01");
        assert_eq!((c.shown(), c.column()), (b"x^A".to_vec(), 3));
    }

    #[test]
    fn history() {
        let h = [b"foo".to_vec(), b"bar".to_vec(), b"food".to_vec()];
        let mut l = Line::default();
        l.apply(Edit::Up, &h);
        assert_eq!(l.text, b"food");
        l.apply(Edit::Up, &h);
        assert_eq!(l.text, b"bar");
        l.apply(Edit::Down, &h);
        l.apply(Edit::Down, &h);
        assert_eq!(l.text, b"", "past the newest: what was typed");
        // With a prefix typed, only lines starting with it.
        let mut l = typed("fo");
        l.apply(Edit::Up, &h);
        l.apply(Edit::Up, &h);
        assert_eq!(l.text, b"foo");
    }

    #[test]
    fn completion() {
        let entries = [(b"notes.txt".to_vec(), false), (b"notes".to_vec(), true), (b"other".to_vec(), false)];
        let l = typed("x no");
        assert_eq!(complete(&l, &entries, 0).unwrap().text, b"x notes/");
        assert_eq!(complete(&l, &entries, 1).unwrap().text, b"x notes.txt");
        let d = typed("dir/ot");
        assert_eq!(complete(&d, &entries, 0).unwrap().text, b"dir/other");
        assert!(complete(&typed("zz"), &entries, 0).is_none());
    }
}
