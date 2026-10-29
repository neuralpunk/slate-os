// SPDX-License-Identifier: MIT OR Apache-2.0

//! Selecting text with the mouse (ADR 0038): a drag selects characters, a
//! double-click words, a triple-click whole lines (words and lines both
//! go on across rows that wrapped, ADR 0099). Positions are lines as the emulator numbers them for good
//! ([`Term::dropped`] plus the index), so a selection stays on its text
//! as output scrolls it up.

use alloc::string::String;

use slate_term::vt::{Cell, Term};

/// A place in the text: a line and a column. In character selections the
/// column is a boundary between cells (0 to the width); otherwise it is a
/// cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Point {
    pub line: u64,
    pub col: usize,
}

/// What a selection grows by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    Char,
    Word,
    Line,
}

impl Unit {
    /// The unit for the `n`th click in a row (1, 2, 3, then 1 again).
    pub fn for_clicks(n: u32) -> Unit {
        match (n.max(1) - 1) % 3 {
            0 => Unit::Char,
            1 => Unit::Word,
            _ => Unit::Line,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    pub anchor: Point,
    pub head: Point,
    pub unit: Unit,
}

/// Line `line`'s cells and whether it wrapped (blank if gone).
fn line_of(term: &Term, line: u64) -> (&[Cell], bool) {
    line.checked_sub(term.dropped())
        .and_then(|i| usize::try_from(i).ok())
        .and_then(|i| term.line(i))
        .unwrap_or((&[], false))
}

/// The number of the last line (the screen's bottom row).
pub fn last_line(term: &Term) -> u64 {
    term.dropped() + (term.history_len() + term.rows()) as u64 - 1
}

/// Everything from the oldest line kept to the last with text in it.
pub fn all(term: &Term) -> Selection {
    let mut end = last_line(term);
    while end > term.dropped() && line_of(term, end).0.iter().all(|c| *c == Cell::BLANK) {
        end -= 1;
    }
    Selection {
        anchor: Point { line: term.dropped(), col: 0 },
        head: Point { line: end, col: term.cols() },
        unit: Unit::Char,
    }
}

fn ch(cells: &[Cell], col: usize) -> char {
    cells.get(col).map_or(' ', |c| c.ch)
}

/// Characters that belong to words: anything but blanks, quotes,
/// brackets and the separators shells use, so that a double-click takes
/// a whole path or address.
fn wordy(c: char) -> bool {
    !c.is_whitespace() && !"\"'`()[]{}<>|;,".contains(c)
}

impl Selection {
    pub fn new(at: Point, unit: Unit) -> Selection {
        Selection { anchor: at, head: at, unit }
    }

    /// The selected text's start and end (end exclusive), as boundaries.
    pub fn span(&self, term: &Term) -> (Point, Point) {
        let (a, b) = if self.anchor <= self.head { (self.anchor, self.head) } else { (self.head, self.anchor) };
        let cols = term.cols();
        match self.unit {
            Unit::Char => (a, b),
            Unit::Word => {
                let at = |p: Point| ch(line_of(term, p.line).0, p.col);
                let (mut s, mut e) = (a, Point { line: b.line, col: b.col + 1 });
                if wordy(at(a)) {
                    loop {
                        let prev = if s.col > 0 {
                            Point { line: s.line, col: s.col - 1 }
                        } else if s.line > term.dropped() && line_of(term, s.line - 1).1 {
                            Point { line: s.line - 1, col: cols - 1 }
                        } else {
                            break;
                        };
                        if !wordy(at(prev)) {
                            break;
                        }
                        s = prev;
                    }
                }
                if wordy(at(b)) {
                    loop {
                        let next = if e.col < cols {
                            e
                        } else if e.line < last_line(term) && line_of(term, e.line).1 {
                            Point { line: e.line + 1, col: 0 }
                        } else {
                            break;
                        };
                        if !wordy(at(next)) {
                            break;
                        }
                        e = Point { line: next.line, col: next.col + 1 };
                    }
                }
                (s, Point { line: e.line, col: e.col.min(cols) })
            }
            Unit::Line => {
                let (mut s, mut e) = (a.line, b.line);
                while s > term.dropped() && line_of(term, s - 1).1 {
                    s -= 1;
                }
                while e < last_line(term) && line_of(term, e).1 {
                    e += 1;
                }
                (Point { line: s, col: 0 }, Point { line: e, col: cols })
            }
        }
    }

    pub fn is_empty(&self, term: &Term) -> bool {
        let (s, e) = self.span(term);
        s >= e
    }

    /// The selected text: each line's trailing blanks dropped, lines
    /// joined by newlines except where a line wrapped onto the next.
    pub fn text(&self, term: &Term) -> String {
        let (s, e) = self.span(term);
        let mut out = String::new();
        if s >= e {
            return out;
        }
        for line in s.line..=e.line {
            let (cells, wrapped) = line_of(term, line);
            let from = if line == s.line { s.col } else { 0 };
            let to = if line == e.line { e.col } else { term.cols() };
            let mut part = String::new();
            for c in from..to.max(from) {
                term.push_cell(&cells.get(c).copied().unwrap_or(Cell::BLANK), &mut part);
            }
            // A wrapped line's last cells are part of the text; others'
            // trailing blanks are padding.
            let joined = wrapped && line != e.line;
            out.push_str(if joined { &part } else { part.trim_end() });
            if line != e.line && !joined {
                out.push('\n');
            }
        }
        out
    }

    /// Whether the cell at (`line`, `col`) is selected, given the span.
    pub fn covers(span: (Point, Point), line: u64, col: usize) -> bool {
        let (s, e) = span;
        let p = Point { line, col };
        p >= s && p < e && (line != e.line || col < e.col)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn term() -> Term {
        let mut t = Term::new(10, 3);
        t.set_scrollback(100);
        // "echo /tmp/a b" wraps after 10 columns.
        t.feed(b"$ ls -l\r\necho /tmp/a b\r\nend");
        t
    }

    #[test]
    fn characters_words_and_lines() {
        let t = term();
        // "$ ls -l" went to the scrollback; "echo /tmp/" wrapped.
        assert_eq!((t.history_len(), last_line(&t)), (1, 3));
        let at = |line, col| Point { line, col };
        let mut s = Selection::new(at(0, 2), Unit::Char);
        assert!(s.is_empty(&t));
        s.head = at(0, 4);
        assert_eq!(s.text(&t), "ls");
        // Backwards, across lines.
        s.head = at(3, 3);
        s.anchor = at(0, 5);
        assert_eq!(s.text(&t), "-l\necho /tmp/a b\nend");
        // A word goes on across the wrap, both ways.
        let w = Selection::new(at(1, 7), Unit::Word);
        assert_eq!(w.text(&t), "/tmp/a");
        let w = Selection::new(at(2, 0), Unit::Word);
        assert_eq!(w.text(&t), "/tmp/a");
        assert_eq!(w.span(&t), (at(1, 5), at(2, 1)));
        let w = Selection::new(at(2, 2), Unit::Word);
        assert_eq!(w.text(&t), "b");
        let l = Selection::new(at(2, 1), Unit::Line);
        assert_eq!(l.text(&t), "echo /tmp/a b");
        assert_eq!(l.span(&t), (at(1, 0), at(2, 10)));
        assert!(Selection::covers(l.span(&t), 1, 9) && !Selection::covers(s.span(&t), 0, 4));
        assert_eq!(Unit::for_clicks(4), Unit::Char);
    }

    #[test]
    fn selecting_all() {
        let t = term();
        assert_eq!(all(&t).text(&t), "$ ls -l\necho /tmp/a b\nend");
        let mut t = Term::new(10, 4);
        t.feed(b"one\r\n");
        assert_eq!(all(&t).text(&t), "one");
    }

    #[test]
    fn wide_characters_copy_once() {
        let mut t = Term::new(12, 2);
        t.feed("ls 中文.txt".as_bytes());
        let s = Selection { anchor: Point { line: 0, col: 0 }, head: Point { line: 0, col: 11 }, unit: Unit::Char };
        assert_eq!(s.text(&t), "ls 中文.txt");
        assert_eq!(Selection::new(Point { line: 0, col: 4 }, Unit::Word).text(&t), "中文.txt");
    }

    #[test]
    fn lines_keep_their_numbers() {
        let mut t = term();
        let s = Selection::new(Point { line: 0, col: 0 }, Unit::Line);
        t.feed(b"\r\nmore\r\nlines\r\n");
        assert_eq!(s.text(&t), "$ ls -l");
        assert!(t.history_len() > 0);
    }
}
