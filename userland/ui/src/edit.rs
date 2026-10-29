// SPDX-License-Identifier: MIT OR Apache-2.0

//! Editing one line of text (ADR 0101): a caret, a selection (from an
//! anchor to the caret), and the moves and edits text fields have
//! everywhere: characters and words left and right (ctrl), Home and End,
//! shift to select, Backspace and Delete (ctrl: a word), select all,
//! and cut, copy and paste through whatever clipboard the program has.
//! Positions are character indices. A secret field (a password) copies
//! and cuts nothing, and its words are the whole text.

use alloc::string::String;
use alloc::vec::Vec;

/// What a shortcut asks of the program's clipboard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Clip {
    /// Nothing to do with the clipboard.
    None,
    /// Put this text on the clipboard (copy, or cut: the text is gone).
    Copy(String),
    /// Ask the clipboard for text, then [`LineEdit::insert`] it.
    Paste,
}

/// Keys an editor takes (the program maps its own to these).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditKey {
    Left,
    Right,
    Home,
    End,
    Backspace,
    Delete,
    /// ctrl + a, c, x, v.
    SelectAll,
    Copy,
    Cut,
    Paste,
}

/// What a key did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// The text changed.
    pub changed: bool,
    /// The caret or the selection moved (or the text changed).
    pub moved: bool,
    pub clip: Clip,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LineEdit {
    chars: Vec<char>,
    caret: usize,
    anchor: Option<usize>,
    /// The most characters it holds (0: no limit).
    pub max: usize,
    pub secret: bool,
}

fn wordy(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

impl LineEdit {
    pub fn new(text: &str) -> LineEdit {
        let chars: Vec<char> = text.chars().collect();
        LineEdit { caret: chars.len(), chars, ..LineEdit::default() }
    }

    pub fn with_max(mut self, max: usize) -> LineEdit {
        self.max = max;
        self
    }

    pub fn secret(mut self) -> LineEdit {
        self.secret = true;
        self
    }

    pub fn text(&self) -> String {
        self.chars.iter().collect()
    }

    pub fn len(&self) -> usize {
        self.chars.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chars.is_empty()
    }

    /// Replace the text; the caret goes to its end.
    pub fn set_text(&mut self, text: &str) {
        self.chars = text.chars().collect();
        self.caret = self.chars.len();
        self.anchor = None;
    }

    pub fn clear(&mut self) {
        self.set_text("");
    }

    /// Clear it, overwriting what it held first (for passwords).
    pub fn wipe(&mut self) {
        self.chars.iter_mut().for_each(|c| *c = '\0');
        self.clear();
    }

    pub fn caret(&self) -> usize {
        self.caret
    }

    /// The anchor of the selection, if there is one (the caret is its
    /// other end).
    pub fn anchor(&self) -> Option<usize> {
        self.anchor.filter(|&a| a != self.caret)
    }

    /// The selection as (start, end), if any.
    pub fn selection(&self) -> Option<(usize, usize)> {
        self.anchor().map(|a| (a.min(self.caret), a.max(self.caret)))
    }

    pub fn selected_text(&self) -> Option<String> {
        self.selection().map(|(s, e)| self.chars[s..e].iter().collect())
    }

    /// Move the caret to `to`, extending the selection or dropping it.
    fn go(&mut self, to: usize, extend: bool) {
        let to = to.min(self.chars.len());
        if extend {
            self.anchor.get_or_insert(self.caret);
        } else {
            self.anchor = None;
        }
        self.caret = to;
    }

    /// Where a word move from `at` lands.
    fn word(&self, at: usize, forward: bool) -> usize {
        if self.secret {
            return if forward { self.chars.len() } else { 0 };
        }
        let mut i = at;
        if forward {
            while i < self.chars.len() && !wordy(self.chars[i]) {
                i += 1;
            }
            while i < self.chars.len() && wordy(self.chars[i]) {
                i += 1;
            }
        } else {
            while i > 0 && !wordy(self.chars[i - 1]) {
                i -= 1;
            }
            while i > 0 && wordy(self.chars[i - 1]) {
                i -= 1;
            }
        }
        i
    }

    fn delete_selection(&mut self) -> bool {
        let Some((s, e)) = self.selection() else { return false };
        self.chars.drain(s..e);
        self.caret = s;
        self.anchor = None;
        true
    }

    /// Insert `text` (control characters and line breaks dropped) in place
    /// of the selection, as much as the limit lets in. True if anything
    /// changed.
    pub fn insert(&mut self, text: &str) -> bool {
        let mut changed = self.delete_selection();
        // An anchor at the caret (an empty selection) goes too, so the
        // next insertion doesn't take this one for a selection.
        self.anchor = None;
        for c in text.chars().filter(|c| !c.is_control()) {
            if self.max != 0 && self.chars.len() >= self.max {
                break;
            }
            self.chars.insert(self.caret, c);
            self.caret += 1;
            changed = true;
        }
        changed
    }

    /// The caret at character boundary `at` (a click), extending the
    /// selection with shift or a drag.
    pub fn place(&mut self, at: usize, extend: bool) {
        self.go(at, extend);
    }

    /// Select the word around boundary `at` (a double click).
    pub fn select_word(&mut self, at: usize) {
        let at = at.min(self.chars.len());
        let (s, e) = (self.word(at.min(self.chars.len()), false), self.word(at, true));
        // On a gap between words, the word after it.
        let s = if s == at && at < self.chars.len() && !wordy(self.chars[at]) { at } else { s };
        self.anchor = Some(s);
        self.caret = e;
    }

    pub fn select_all(&mut self) {
        self.anchor = Some(0);
        self.caret = self.chars.len();
    }

    /// A key, with shift (extend the selection) and ctrl (by words).
    pub fn key(&mut self, k: EditKey, shift: bool, ctrl: bool) -> Outcome {
        let before = (self.caret, self.anchor());
        let mut changed = false;
        let mut clip = Clip::None;
        match k {
            EditKey::Left => {
                let to = match (self.selection(), shift, ctrl) {
                    (Some((s, _)), false, false) => s,
                    (_, _, true) => self.word(self.caret, false),
                    _ => self.caret.saturating_sub(1),
                };
                self.go(to, shift);
            }
            EditKey::Right => {
                let to = match (self.selection(), shift, ctrl) {
                    (Some((_, e)), false, false) => e,
                    (_, _, true) => self.word(self.caret, true),
                    _ => self.caret + 1,
                };
                self.go(to, shift);
            }
            EditKey::Home => self.go(0, shift),
            EditKey::End => self.go(self.chars.len(), shift),
            EditKey::Backspace | EditKey::Delete => {
                changed = self.delete_selection();
                if !changed {
                    let forward = k == EditKey::Delete;
                    let to = match (forward, ctrl) {
                        (false, true) => self.word(self.caret, false),
                        (false, false) => self.caret.saturating_sub(1),
                        (true, true) => self.word(self.caret, true),
                        (true, false) => (self.caret + 1).min(self.chars.len()),
                    };
                    let (s, e) = (to.min(self.caret), to.max(self.caret));
                    self.chars.drain(s..e);
                    self.caret = s;
                    changed = e > s;
                }
            }
            EditKey::SelectAll => self.select_all(),
            EditKey::Copy | EditKey::Cut => {
                if !self.secret
                    && let Some(t) = self.selected_text()
                {
                    clip = Clip::Copy(t);
                    if k == EditKey::Cut {
                        changed = self.delete_selection();
                    }
                }
            }
            EditKey::Paste => clip = Clip::Paste,
        }
        Outcome { changed, moved: changed || before != (self.caret, self.anchor()), clip }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(e: &mut LineEdit, ks: &[(EditKey, bool, bool)]) -> Vec<Outcome> {
        ks.iter().map(|&(k, s, c)| e.key(k, s, c)).collect()
    }

    #[test]
    fn caret_moves_and_inserts() {
        let mut e = LineEdit::new("/24");
        assert_eq!(e.caret(), 3);
        e.key(EditKey::Home, false, false);
        assert!(e.insert("10.0.2.15"));
        assert_eq!((e.text().as_str(), e.caret()), ("10.0.2.15/24", 9));
        e.key(EditKey::Right, false, false);
        e.key(EditKey::Delete, false, false);
        e.insert("1");
        assert_eq!(e.text(), "10.0.2.15/14");
        // Control characters and line breaks don't go in.
        e.insert("\n\t");
        assert_eq!(e.text(), "10.0.2.15/14");
    }

    #[test]
    fn words_and_selections() {
        let mut e = LineEdit::new("ada lovelace, 1815");
        let out = keys(&mut e, &[(EditKey::Left, false, true), (EditKey::Left, true, true)]);
        assert!(out.iter().all(|o| o.moved && !o.changed));
        assert_eq!(e.selection(), Some((4, 14)));
        assert_eq!(e.selected_text().as_deref(), Some("lovelace, "));
        // Typing replaces the selection; left without shift collapses it.
        e.insert("byron ");
        assert_eq!(e.text(), "ada byron 1815");
        e.key(EditKey::Home, true, false);
        e.key(EditKey::Left, false, false);
        assert_eq!((e.caret(), e.selection()), (0, None));
        // ctrl + backspace and delete take words.
        e.key(EditKey::End, false, false);
        e.key(EditKey::Backspace, false, true);
        assert_eq!(e.text(), "ada byron ");
        e.key(EditKey::Home, false, false);
        e.key(EditKey::Delete, false, true);
        assert_eq!(e.text(), " byron ");
        e.select_word(3);
        assert_eq!(e.selected_text().as_deref(), Some("byron"));
    }

    #[test]
    fn the_clipboard() {
        let mut e = LineEdit::new("10.0.2.2");
        assert_eq!(e.key(EditKey::Copy, false, true).clip, Clip::None);
        e.key(EditKey::SelectAll, false, true);
        assert_eq!(e.key(EditKey::Copy, false, true).clip, Clip::Copy("10.0.2.2".into()));
        let cut = e.key(EditKey::Cut, false, true);
        assert!(cut.changed && cut.clip == Clip::Copy("10.0.2.2".into()) && e.is_empty());
        assert_eq!(e.key(EditKey::Paste, false, true).clip, Clip::Paste);
        e.insert("10.0.2.2");
        e.key(EditKey::Backspace, false, false);
        e.insert("3");
        assert_eq!(e.text(), "10.0.2.3");
        // A password copies nothing, and its words are all of it.
        let mut p = LineEdit::new("hunter two").secret();
        p.key(EditKey::SelectAll, false, true);
        assert_eq!(p.key(EditKey::Copy, false, true).clip, Clip::None);
        p.key(EditKey::End, false, false);
        p.key(EditKey::Left, false, true);
        assert_eq!(p.caret(), 0);
    }

    #[test]
    fn a_limit_and_clicks() {
        let mut e = LineEdit::new("abc").with_max(5);
        assert!(e.insert("defgh"));
        assert_eq!(e.text(), "abcde");
        e.place(1, false);
        e.place(4, true);
        assert_eq!(e.selection(), Some((1, 4)));
        e.place(9, false);
        assert_eq!((e.caret(), e.selection()), (5, None));
        assert!(!e.insert(""));
        // All of nothing selected, then typing: each character stays.
        let mut f = LineEdit::new("");
        f.select_all();
        f.insert("t");
        f.insert("w");
        assert_eq!(f.text(), "tw");
    }
}
