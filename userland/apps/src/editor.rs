// SPDX-License-Identifier: MIT OR Apache-2.0

//! Text Editor (ADR 0107), `text-editor [FILE]`: a graphical editor for
//! plain text and code, on etch's buffer (UTF-8 lines, undo and redo).
//!
//! Keys:
//! - the arrows, Home (the line's text, then its start) and End, Page Up
//!   and Down; with ctrl, by words and to the file's ends; with shift,
//!   selecting;
//! - Enter keeps the line's indent; Tab and shift + Tab indent and
//!   outdent (the chosen lines, or at the caret); ctrl + Backspace and
//!   Delete take words;
//! - ctrl + a, c, x and v; ctrl + z undoes, ctrl + shift + z or ctrl + y
//!   redoes;
//! - ctrl + s saves (asking for a name the first time), ctrl + shift + s
//!   saves as;
//! - ctrl + f finds: Enter goes to the next match, shift + Enter to the
//!   one before, Esc closes it; ctrl + h finds and replaces: Tab moves
//!   between the fields, Enter replaces the match and finds the next,
//!   ctrl + Enter replaces them all (one undo). In both, alt + c matches
//!   case and alt + r takes the text as a regular expression (POSIX
//!   extended, within a line; `\1`..`\9` and `\0` in the replacement
//!   give its groups and the whole match);
//! - alt + z wraps long lines at the window's edge (and back);
//! - ctrl + o opens another file in the window (once changes are saved).
//!
//! The mouse places the caret, drags select, a double click selects a
//! word, and the wheel scrolls. Closing with unsaved changes asks first.
//! Files are kept as they were found: their line endings (LF or CRLF),
//! their mode, and a final newline.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_display::input::{
    KEY_BACKSPACE, KEY_DELETE, KEY_DOWN, KEY_END, KEY_ENTER, KEY_ESC, KEY_HOME, KEY_KPENTER, KEY_LEFT, KEY_PAGEDOWN,
    KEY_PAGEUP, KEY_RIGHT, KEY_TAB, KEY_UP,
};
use slate_etch::buffer::{Buffer, Pos};
use slate_strata::fonts::Fonts;
use slate_strata_client::mods::{ALT, CTRL, LOGO, SHIFT};
use slate_ui::edit::{EditKey, LineEdit};
use slate_ui::graphite::Palette;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;

use slate_regex::{Captures, Options, Regex, Syntax};

use crate::kit::{self, App, Effect, Hints};
use crate::syntax::{Lang, Token};

/// The largest file opened.
const MAX_FILE: u64 = 16 << 20;
const TAB: usize = 4;
const FONT: f32 = 13.0;
const LINE_H: f32 = 21.0;

/// A bar at the bottom asking for something.
#[derive(Clone, Debug)]
pub enum Bar {
    Find(LineEdit),
    /// Find and replace; `on_with`: typing goes to the replacement.
    Replace {
        find: LineEdit,
        with: LineEdit,
        on_with: bool,
    },
    SaveAs(LineEdit),
    /// A file to open instead.
    Open(LineEdit),
    /// Closing with unsaved changes.
    Close,
}

/// How searches match (alt + c, alt + r in the bars).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Search {
    pub case: bool,
    pub regex: bool,
}

#[derive(Debug)]
pub struct Editor {
    pub path: Option<String>,
    pub buf: Buffer,
    pub caret: Pos,
    pub anchor: Option<Pos>,
    /// The column up and down keep to (display columns).
    want: Option<usize>,
    pub top: usize,
    pub left: usize,
    pub lang: Lang,
    pub crlf: bool,
    /// Indent with tabs (the file did), else spaces.
    pub tabs: bool,
    pub bar: Option<Bar>,
    pub search: Search,
    /// Long lines wrap at the window's edge (alt + z); `top_seg` is the
    /// part of the top line shown first.
    pub wrap: bool,
    top_seg: usize,
    pub status: String,
    /// The file's mode, kept when saving.
    mode: u32,
    // From the last frame: the text's area, a character's width, and how
    // many rows and columns fit.
    text: Area,
    char_w: f32,
    rows: usize,
    cols: usize,
    dragging: bool,
    shown_title: Option<String>,
}

/// The display width of a character (tabs counted where they are).
fn cw(c: char, col: usize) -> usize {
    if c == '\t' { TAB - col % TAB } else { slate_term::width::width(c).max(1) }
}

/// The non-empty matches of `re` on `line`, in order: start, end, groups.
fn matches(re: &Regex, line: &[u8]) -> Vec<(usize, usize, Captures)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos <= line.len() {
        let Some(c) = re.find_at(line, pos) else { break };
        let Some((s, e)) = c.first().copied().flatten() else { break };
        if e > s {
            out.push((s, e, c));
            pos = e;
        } else {
            pos = s + 1;
        }
    }
    out
}

/// A replacement as it goes in for one match: with regular expressions,
/// `\0` is the match, `\1`..`\9` its groups and `\\` a backslash.
fn expand(with: &str, line: &[u8], caps: &Captures, regex: bool) -> Vec<u8> {
    let w = with.as_bytes();
    if !regex {
        return w.to_vec();
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < w.len() {
        match (w[i], w.get(i + 1)) {
            (b'\\', Some(d)) if d.is_ascii_digit() => {
                if let Some(Some((s, e))) = caps.get(usize::from(d - b'0')) {
                    out.extend_from_slice(&line[*s..*e]);
                }
                i += 2;
            }
            (b'\\', Some(b'\\')) => {
                out.push(b'\\');
                i += 2;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

impl Editor {
    pub fn new(path: Option<String>, data: &[u8]) -> Editor {
        let crlf =
            data.windows(2).filter(|w| w == b"\r\n").count() * 2 > data.iter().filter(|&&b| b == b'\n').count().max(1);
        let text: Vec<u8> = if crlf { data.iter().copied().filter(|&b| b != b'\r').collect() } else { data.to_vec() };
        let buf = Buffer::from_bytes(&text);
        let tabs = buf.lines.iter().filter(|l| l.first() == Some(&b'\t')).count()
            > buf.lines.iter().filter(|l| l.starts_with(b"  ")).count();
        let lang = path.as_deref().map_or(Lang::Plain, |p| Lang::of(p.rsplit('/').next().unwrap_or(p)));
        Editor {
            path,
            buf,
            caret: Pos::default(),
            anchor: None,
            want: None,
            top: 0,
            left: 0,
            lang,
            crlf,
            tabs,
            bar: None,
            search: Search::default(),
            wrap: false,
            top_seg: 0,
            status: String::new(),
            mode: 0o644,
            text: Area::new(0.0, 0.0, 0.0, 0.0),
            char_w: 8.0,
            rows: 30,
            cols: 80,
            dragging: false,
            shown_title: None,
        }
    }

    /// Open `path` (a new file if it isn't there yet).
    pub fn open(path: &str) -> Result<Editor, String> {
        match slate_rt::fs::stat(path.as_bytes()) {
            Ok(st) => {
                if st.mode & slate_rt::fs::S_IFMT == slate_rt::fs::S_IFDIR {
                    return Err(alloc::format!("{path} is a folder"));
                }
                if st.size as u64 > MAX_FILE {
                    return Err(alloc::format!("{path} is larger than the editor opens (16 MiB)"));
                }
                let data = slate_rt::fs::read_file(path.as_bytes()).map_err(|e| alloc::format!("{path}: {e}"))?;
                let mut e = Editor::new(Some(path.to_string()), &data);
                e.mode = st.mode & 0o7777;
                if data.contains(&0) {
                    e.status = String::from("This file has bytes that aren't text; saving keeps them.");
                }
                Ok(e)
            }
            Err(_) => {
                let mut e = Editor::new(Some(path.to_string()), b"");
                e.status = String::from("A new file: it is made when you save.");
                Ok(e)
            }
        }
    }

    pub fn line_chars(&self, l: usize) -> Vec<char> {
        String::from_utf8_lossy(&self.buf.lines[l]).chars().collect()
    }

    /// The display column of byte `col` on line `l`.
    pub fn column(&self, p: Pos) -> usize {
        let text =
            String::from_utf8_lossy(&self.buf.lines[p.line][..p.col.min(self.buf.lines[p.line].len())]).into_owned();
        text.chars().fold(0, |c, ch| c + cw(ch, c))
    }

    /// The byte offset on line `l` nearest display column `col`.
    pub fn at_column(&self, l: usize, col: usize) -> Pos {
        let line = &self.buf.lines[l];
        let (mut c, mut b) = (0, 0);
        for ch in String::from_utf8_lossy(line).chars() {
            let w = cw(ch, c);
            if c + w / 2 >= col && c + w > col {
                break;
            }
            c += w;
            b += ch.len_utf8();
            if c >= col {
                break;
            }
        }
        self.buf.clamp(Pos { line: l, col: b.min(line.len()) })
    }

    pub fn selection(&self) -> Option<(Pos, Pos)> {
        self.anchor.filter(|a| *a != self.caret).map(|a| (a.min(self.caret), a.max(self.caret)))
    }

    pub fn selected_text(&self) -> Option<String> {
        let (s, e) = self.selection()?;
        let mut out = Vec::new();
        for (l, line) in self.buf.lines.iter().enumerate().take(e.line + 1).skip(s.line) {
            let from = if l == s.line { s.col } else { 0 };
            let to = if l == e.line { e.col } else { line.len() };
            out.extend_from_slice(&line[from..to]);
            if l < e.line {
                out.push(b'\n');
            }
        }
        Some(String::from_utf8_lossy(&out).into_owned())
    }

    fn go(&mut self, to: Pos, extend: bool) {
        if extend {
            self.anchor.get_or_insert(self.caret);
        } else {
            self.anchor = None;
        }
        self.caret = self.buf.clamp(to);
        self.buf.seal();
    }

    /// Delete the selection; true if there was one.
    fn delete_selection(&mut self) -> bool {
        let Some((s, e)) = self.selection() else { return false };
        self.buf.delete(s, e);
        self.caret = s;
        self.anchor = None;
        true
    }

    pub fn insert(&mut self, text: &str) {
        self.delete_selection();
        // Line breaks in pasted text, whatever they were.
        let text = text.replace("\r\n", "\n").replace('\r', "\n");
        self.caret = self.buf.insert(self.caret, text.as_bytes());
        self.want = None;
    }

    fn is_word(c: u8) -> bool {
        c.is_ascii_alphanumeric() || c == b'_' || c >= 0x80
    }

    /// The word boundary from `p` (forward or back), across lines.
    fn word(&self, p: Pos, forward: bool) -> Pos {
        let mut p = p;
        if forward {
            let l = &self.buf.lines[p.line];
            if p.col >= l.len() {
                return self.buf.next(p);
            }
            while p.col < l.len() && !Self::is_word(l[p.col]) {
                p.col += 1;
            }
            while p.col < l.len() && Self::is_word(l[p.col]) {
                p.col += 1;
            }
        } else {
            if p.col == 0 {
                return self.buf.prev(p);
            }
            let l = &self.buf.lines[p.line];
            while p.col > 0 && !Self::is_word(l[p.col - 1]) {
                p.col -= 1;
            }
            while p.col > 0 && Self::is_word(l[p.col - 1]) {
                p.col -= 1;
            }
        }
        self.buf.clamp(p)
    }

    fn select_word(&mut self, p: Pos) {
        let l = &self.buf.lines[p.line];
        let (mut s, mut e) = (p.col, p.col);
        while s > 0 && Self::is_word(l[s - 1]) {
            s -= 1;
        }
        while e < l.len() && Self::is_word(l[e]) {
            e += 1;
        }
        self.anchor = Some(Pos { line: p.line, col: s });
        self.caret = Pos { line: p.line, col: e };
    }

    fn indent_unit(&self) -> String {
        if self.tabs { String::from("\t") } else { " ".repeat(TAB) }
    }

    /// Indent (or outdent) lines `a..=b`.
    fn indent_lines(&mut self, a: usize, b: usize, out: bool) {
        for l in a..=b {
            if out {
                let line = &self.buf.lines[l];
                let n = if line.first() == Some(&b'\t') {
                    1
                } else {
                    line.iter().take(TAB).take_while(|&&c| c == b' ').count()
                };
                if n > 0 {
                    self.buf.delete(Pos { line: l, col: 0 }, Pos { line: l, col: n });
                }
            } else if !self.buf.lines[l].is_empty() {
                let unit = self.indent_unit();
                self.buf.insert(Pos { line: l, col: 0 }, unit.as_bytes());
                self.buf.seal();
            }
        }
        self.buf.seal();
        if let Some(a2) = self.anchor {
            self.anchor = Some(
                self.buf.clamp(Pos { line: a2.line, col: if a2.line == a.min(b) && a2.col > 0 { a2.col } else { 0 } }),
            );
        }
        self.caret = self.buf.clamp(self.caret);
    }

    /// What the find or replace bar looks for.
    fn query(&self) -> Option<String> {
        match &self.bar {
            Some(Bar::Find(q) | Bar::Replace { find: q, .. }) => Some(q.text()).filter(|t| !t.is_empty()),
            _ => None,
        }
    }

    /// The search as a pattern: the text itself, or a regular expression
    /// (a bad one says why in the status line).
    fn pattern(&mut self, q: &str) -> Option<Regex> {
        let opts = Options { syntax: Syntax::Extended, icase: !self.search.case, ..Options::default() };
        if !self.search.regex {
            return Some(Regex::literal(q.as_bytes(), opts));
        }
        match Regex::new(q.as_bytes(), opts) {
            Ok(r) => Some(r),
            Err(e) => {
                self.status = alloc::format!("Not a regular expression: {e}");
                None
            }
        }
    }

    fn find(&mut self, forward: bool, from_next: bool) -> bool {
        let Some(q) = self.query() else { return false };
        let Some(re) = self.pattern(&q) else { return false };
        let n = self.buf.lines.len();
        let start = if forward {
            self.selection().map_or(self.caret, |(s, e)| if from_next { e } else { s })
        } else {
            self.selection().map_or(self.caret, |(s, _)| s)
        };
        for k in 0..=n {
            let l = if forward { (start.line + k) % n } else { (start.line + n - k % n) % n };
            let ms = matches(&re, &self.buf.lines[l]);
            let found = if forward {
                let from = if k == 0 { start.col } else { 0 };
                ms.iter().find(|m| m.0 >= from)
            } else {
                let to = if k == 0 { start.col } else { usize::MAX };
                ms.iter().rev().find(|m| m.0 < to)
            };
            if let Some(&(s, e, _)) = found {
                self.anchor = Some(Pos { line: l, col: s });
                self.caret = Pos { line: l, col: e };
                self.reveal_centre();
                return true;
            }
        }
        false
    }

    /// The replace bar's replacement.
    fn replacement(&self) -> String {
        match &self.bar {
            Some(Bar::Replace { with, .. }) => with.text(),
            _ => String::new(),
        }
    }

    /// Replace the selected match (when the selection is one) and find
    /// the next.
    fn replace_one(&mut self) -> bool {
        let Some(q) = self.query() else { return false };
        let Some(re) = self.pattern(&q) else { return false };
        let with = self.replacement();
        if let Some((s, e)) = self.selection()
            && s.line == e.line
            && let Some(m) = matches(&re, &self.buf.lines[s.line]).into_iter().find(|m| m.0 == s.col && m.1 == e.col)
        {
            let text = expand(&with, &self.buf.lines[s.line], &m.2, self.search.regex);
            self.buf.seal();
            self.caret = self.buf.replace(s, e, &text);
            self.anchor = None;
        }
        self.find(true, true)
    }

    /// Replace every match, as one step for undo; how many.
    fn replace_all(&mut self) -> usize {
        let Some(q) = self.query() else { return 0 };
        let Some(re) = self.pattern(&q) else { return 0 };
        let with = self.replacement();
        let (mut count, mut first, mut last) = (0, None, 0);
        let mut changed: Vec<(usize, Vec<u8>)> = Vec::new();
        for (l, line) in self.buf.lines.iter().enumerate() {
            let ms = matches(&re, line);
            if ms.is_empty() {
                continue;
            }
            let mut out = Vec::with_capacity(line.len());
            let mut pos = 0;
            for (s, e, caps) in &ms {
                out.extend_from_slice(&line[pos..*s]);
                out.extend_from_slice(&expand(&with, line, caps, self.search.regex));
                pos = *e;
            }
            out.extend_from_slice(&line[pos..]);
            count += ms.len();
            first.get_or_insert(l);
            last = l;
            changed.push((l, out));
        }
        let Some(first) = first else { return 0 };
        // One replacement from the first changed line to the last.
        let mut text = Vec::new();
        let mut next = changed.iter().peekable();
        for (l, line) in self.buf.lines.iter().enumerate().take(last + 1).skip(first) {
            if l > first {
                text.push(b'\n');
            }
            match next.peek() {
                Some((c, new)) if *c == l => {
                    text.extend_from_slice(new);
                    next.next();
                }
                _ => text.extend_from_slice(line),
            }
        }
        self.buf.seal();
        let end = Pos { line: last, col: self.buf.lines[last].len() };
        self.buf.replace(Pos { line: first, col: 0 }, end, &text);
        self.buf.seal();
        self.caret = self.buf.clamp(self.caret);
        self.anchor = None;
        count
    }

    /// Open `path` in this window instead (ctrl + o).
    fn open_instead(&mut self, path: &str) {
        match Editor::open(path) {
            Ok(mut e) => {
                e.search = self.search;
                e.wrap = self.wrap;
                (e.text, e.char_w, e.rows, e.cols) = (self.text, self.char_w, self.rows, self.cols);
                e.shown_title = self.shown_title.take();
                if e.status.is_empty() {
                    e.status = alloc::format!("Opened {}.", path.rsplit('/').next().unwrap_or(path));
                }
                *self = e;
            }
            Err(msg) => self.status = msg,
        }
    }

    // --- wrapping: a line takes one row, or as many as its width needs ---

    /// The display columns line `l`'s rows start at: 0, and with wrapping
    /// each place a row is full, after the row's last space where there
    /// is one (else wherever it is full).
    fn row_starts(&self, l: usize) -> Vec<usize> {
        let mut starts = alloc::vec![0];
        if !self.wrap {
            return starts;
        }
        let cols = self.cols.max(1);
        let (mut col, mut start, mut after_space) = (0, 0, None);
        for ch in String::from_utf8_lossy(&self.buf.lines[l]).chars() {
            let w = cw(ch, col);
            if col + w > start + cols && col > start {
                start = after_space.filter(|&a| a > start).unwrap_or(col);
                starts.push(start);
                after_space = None;
            }
            col += w;
            if ch == ' ' || ch == '\t' {
                after_space = Some(col);
            }
        }
        starts
    }

    /// How many rows line `l` takes.
    fn segs(&self, l: usize) -> usize {
        self.row_starts(l).len()
    }

    /// The row of line `l` that display column `col` is on.
    fn seg_of(&self, l: usize, col: usize) -> usize {
        self.row_starts(l).iter().rposition(|&s| s <= col).unwrap_or(0)
    }

    /// Where row `s` of line `l` starts and ends (display columns; the
    /// last row has no end).
    fn row_span(&self, l: usize, s: usize) -> (usize, usize) {
        let starts = self.row_starts(l);
        (starts.get(s).copied().unwrap_or(0), starts.get(s + 1).copied().unwrap_or(usize::MAX))
    }

    /// The caret's row: its line and the part of it.
    fn caret_row(&self) -> (usize, usize) {
        (self.caret.line, self.seg_of(self.caret.line, self.column(self.caret)))
    }

    /// The row after (or before) `(l, s)`, if any.
    fn row_step(&self, (l, s): (usize, usize), down: bool) -> Option<(usize, usize)> {
        if down {
            if s + 1 < self.segs(l) {
                Some((l, s + 1))
            } else if l + 1 < self.buf.lines.len() {
                Some((l + 1, 0))
            } else {
                None
            }
        } else if s > 0 {
            Some((l, s - 1))
        } else if l > 0 {
            Some((l - 1, self.segs(l - 1) - 1))
        } else {
            None
        }
    }

    /// Move the top row `n` rows down (up when negative).
    fn scroll_rows(&mut self, n: i64) {
        let mut at = (self.top, self.top_seg.min(self.segs(self.top) - 1));
        for _ in 0..n.unsigned_abs() {
            match self.row_step(at, n > 0) {
                Some(r) => at = r,
                None => break,
            }
        }
        (self.top, self.top_seg) = at;
    }

    /// Whether row `r` shows: at or below the top, within `rows` of it.
    fn row_shown(&self, r: (usize, usize)) -> bool {
        let mut at = (self.top, self.top_seg);
        if r < at {
            return false;
        }
        for _ in 0..self.rows.max(1) {
            if at == r {
                return true;
            }
            match self.row_step(at, true) {
                Some(n) => at = n,
                None => return false,
            }
        }
        false
    }

    /// Scroll so the caret shows.
    fn reveal(&mut self) {
        let rows = self.rows.max(1);
        if self.wrap {
            self.left = 0;
            let caret = self.caret_row();
            if caret < (self.top, self.top_seg) {
                (self.top, self.top_seg) = caret;
            } else if !self.row_shown(caret) {
                // The caret on the last row.
                (self.top, self.top_seg) = caret;
                self.scroll_rows(1 - rows as i64);
            }
            return;
        }
        if self.caret.line < self.top {
            self.top = self.caret.line;
        } else if self.caret.line >= self.top + rows {
            self.top = self.caret.line + 1 - rows;
        }
        let col = self.column(self.caret);
        let cols = self.cols.max(8);
        if col < self.left {
            self.left = col.saturating_sub(4);
        } else if col >= self.left + cols {
            self.left = col + 8 - cols;
        }
    }

    fn reveal_centre(&mut self) {
        let rows = self.rows.max(1);
        if self.wrap {
            let caret = self.caret_row();
            if !self.row_shown(caret) {
                (self.top, self.top_seg) = caret;
                self.scroll_rows(-((rows / 2) as i64));
            }
            return;
        }
        if self.caret.line < self.top || self.caret.line >= self.top + rows {
            self.top = self.caret.line.saturating_sub(rows / 2);
        }
        self.reveal();
    }

    pub fn save_to(&mut self, path: &str) -> Result<(), String> {
        let mut data = self.buf.to_bytes();
        if self.crlf {
            let mut out = Vec::with_capacity(data.len() + self.buf.lines.len());
            for b in data {
                if b == b'\n' {
                    out.push(b'\r');
                }
                out.push(b);
            }
            data = out;
        }
        // A new file beside the old, put in its place whole.
        let tmp = alloc::format!("{path}.saving");
        slate_rt::fs::write_file(tmp.as_bytes(), &data, self.mode).map_err(|e| alloc::format!("{e}"))?;
        let _ = slate_rt::fs::chmod(tmp.as_bytes(), self.mode);
        if let Err(e) = slate_rt::fs::rename(tmp.as_bytes(), path.as_bytes()) {
            let _ = slate_rt::fs::unlink(tmp.as_bytes());
            return Err(alloc::format!("{e}"));
        }
        self.buf.mark_saved();
        if self.path.as_deref() != Some(path) {
            self.lang = Lang::of(path.rsplit('/').next().unwrap_or(path));
        }
        self.path = Some(path.to_string());
        crate::trace!("text-editor: saved {path} ({} bytes)", data.len());
        self.status = alloc::format!("Saved {}.", path.rsplit('/').next().unwrap_or(path));
        Ok(())
    }

    fn save(&mut self, ask: bool) -> Effect {
        match self.path.clone() {
            Some(p) if !ask => {
                if let Err(e) = self.save_to(&p) {
                    self.status = alloc::format!("Couldn't save: {e}");
                }
            }
            p => {
                let home = slate_rt::env::var(b"HOME").map(|h| String::from(slate_rt::lossy(&h))).unwrap_or_default();
                let start = p.unwrap_or_else(|| alloc::format!("{home}/Documents/untitled.txt"));
                self.bar = Some(Bar::SaveAs(LineEdit::new(&start).with_max(1024)));
            }
        }
        Effect::Redraw
    }

    /// The title: the file's name (with a dot when changed) and its
    /// folder.
    pub fn title(&self) -> (String, Option<String>) {
        let name = self.path.as_deref().map_or("untitled", |p| p.rsplit('/').next().unwrap_or(p));
        let dot = if self.buf.modified() { " •" } else { "" };
        let home = slate_rt::env::var(b"HOME").map(|h| String::from(slate_rt::lossy(&h))).unwrap_or_default();
        let dir = self.path.as_deref().and_then(|p| p.rsplit_once('/')).map(|(d, _)| {
            if !home.is_empty() && d.starts_with(&home) {
                alloc::format!("~{}", &d[home.len()..])
            } else {
                d.to_string()
            }
        });
        (alloc::format!("{name}{dot}"), dir)
    }

    /// Look again from the match chosen (or the caret), as typing does.
    fn search_as_typed(&mut self) {
        if let Some((s, _)) = self.selection() {
            self.caret = s;
            self.anchor = None;
        }
        self.find(true, false);
    }

    fn bar_key(&mut self, code: u16, ch: Option<char>, mods: u8) -> Effect {
        let (shift, ctrl) = (mods & SHIFT != 0, mods & CTRL != 0);
        let letter = ch.map(|c| c.to_ascii_lowercase());
        // The search's switches, in the find and replace bars.
        if mods & ALT != 0 && matches!(self.bar, Some(Bar::Find(_) | Bar::Replace { .. })) {
            match letter {
                Some('c') => self.search.case = !self.search.case,
                Some('r') => self.search.regex = !self.search.regex,
                _ => return Effect::None,
            }
            self.status.clear();
            self.search_as_typed();
            return Effect::Redraw;
        }
        match (&mut self.bar, code) {
            (Some(Bar::Close), _) => {
                return match (code, ch.map(|c| c.to_ascii_lowercase())) {
                    (KEY_ESC, _) => {
                        self.bar = None;
                        Effect::Redraw
                    }
                    (_, Some('s')) if ctrl => {
                        self.bar = None;
                        let e = self.save(false);
                        if !self.buf.modified() { Effect::Quit } else { e }
                    }
                    (_, Some('q')) if ctrl => Effect::Quit,
                    _ => Effect::None,
                };
            }
            (_, KEY_ESC) => {
                self.bar = None;
                return Effect::Redraw;
            }
            (Some(Bar::Find(_)), KEY_ENTER | KEY_KPENTER) => {
                self.status.clear();
                if !self.find(!shift, true) && self.status.is_empty() {
                    self.status = String::from("Not found.");
                }
                return Effect::Redraw;
            }
            // From finding to replacing, the text kept.
            (Some(Bar::Find(f)), _) if ctrl && letter == Some('h') => {
                let on_with = !f.text().is_empty();
                self.bar = Some(Bar::Replace { find: f.clone(), with: LineEdit::new("").with_max(200), on_with });
                return Effect::Redraw;
            }
            (Some(Bar::Replace { on_with, .. }), KEY_TAB) => {
                *on_with = !*on_with;
                return Effect::Redraw;
            }
            (Some(Bar::Replace { .. }), KEY_ENTER | KEY_KPENTER) => {
                self.status.clear();
                if ctrl {
                    let n = self.replace_all();
                    if n > 0 {
                        self.status = alloc::format!("Replaced {n}.");
                    }
                } else {
                    self.replace_one();
                }
                if self.selection().is_none() && self.status.is_empty() {
                    self.status = String::from("Not found.");
                }
                self.reveal();
                return Effect::Redraw;
            }
            (Some(Bar::Open(field)), KEY_ENTER | KEY_KPENTER) => {
                let path = field.text().trim().to_string();
                if path.is_empty() || path.ends_with('/') {
                    return Effect::None;
                }
                self.bar = None;
                self.open_instead(&path);
                return Effect::Redraw;
            }
            (Some(Bar::SaveAs(field)), KEY_ENTER | KEY_KPENTER) => {
                let path = field.text().trim().to_string();
                if path.is_empty() || path.ends_with('/') {
                    return Effect::None;
                }
                self.bar = None;
                if let Err(e) = self.save_to(&path) {
                    self.status = alloc::format!("Couldn't save {path}: {e}");
                }
                return Effect::Redraw;
            }
            _ => {}
        }
        let field = match &mut self.bar {
            Some(Bar::Find(f) | Bar::SaveAs(f) | Bar::Open(f)) => f,
            Some(Bar::Replace { find, with, on_with }) => {
                if *on_with {
                    with
                } else {
                    find
                }
            }
            _ => return Effect::None,
        };
        let edit = match (code, ch.map(|c| c.to_ascii_lowercase())) {
            (KEY_LEFT, _) => Some(EditKey::Left),
            (KEY_RIGHT, _) => Some(EditKey::Right),
            (KEY_HOME, _) => Some(EditKey::Home),
            (KEY_END, _) => Some(EditKey::End),
            (KEY_BACKSPACE, _) => Some(EditKey::Backspace),
            (KEY_DELETE, _) => Some(EditKey::Delete),
            (_, Some('a')) if ctrl => Some(EditKey::SelectAll),
            _ => None,
        };
        let shortcut = mods & (CTRL | ALT | LOGO) != 0;
        let changed = match (edit, ch.filter(|c| !shortcut && !c.is_control())) {
            (Some(k), _) => field.key(k, shift, ctrl).moved,
            (None, Some(c)) => field.insert(c.encode_utf8(&mut [0u8; 4])),
            _ => false,
        };
        // Find as you type.
        if changed && matches!(self.bar, Some(Bar::Find(_) | Bar::Replace { on_with: false, .. })) {
            self.status.clear();
            self.search_as_typed();
        }
        if changed { Effect::Redraw } else { Effect::None }
    }

    fn click_pos(&self, x: f32, y: f32) -> Pos {
        let row = ((y - self.text.y) / LINE_H).max(0.0) as usize;
        if self.wrap {
            let mut at = (self.top, self.top_seg);
            for _ in 0..row {
                match self.row_step(at, true) {
                    Some(r) => at = r,
                    None => break,
                }
            }
            let (start, end) = self.row_span(at.0, at.1);
            let col = start + ((x - self.text.x).max(0.0) / self.char_w + 0.5) as usize;
            // Within this row: before the next one starts.
            return self.at_column(at.0, col.min(end.saturating_sub(1)));
        }
        let line = (self.top + row).min(self.buf.lines.len() - 1);
        let col = self.left + ((x - self.text.x).max(0.0) / self.char_w + 0.5) as usize;
        self.at_column(line, col)
    }
}

/// One field of a bar, in `row` (44 high): its name, the field, and for
/// searches the switches (match case, regular expression), lit when on.
#[allow(clippy::too_many_arguments)]
fn field_row(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    row: Area,
    name: &str,
    field: &LineEdit,
    focused: bool,
    search: Option<Search>,
) {
    let by = row.y;
    let label = p.style(&f.mono, 11.5, pal.muted);
    let mut typed = p.style(&f.regular, 13.5, pal.text_1);
    typed.ligatures = false;
    p.line(&label, row.x + 16.0, by + 13.0, 18.0, name);
    let fx = row.x + 80.0;
    let room = if search.is_some() { 160.0 } else { 96.0 };
    let fa = Area::new(fx, by + 6.0, row.w - room, 32.0);
    p.fill(fa, 6.0, pal.well);
    p.border(fa, 6.0, 1.0, if focused { pal.field_focus } else { pal.border });
    let text = field.text();
    p.line(&typed, fx + 10.0, by + 12.0, 20.0, &text);
    if focused {
        let before: String = text.chars().take(field.caret()).collect();
        let cx = p.measure(&typed, &before);
        p.fill(Area::new(fx + 10.0 + cx, by + 12.0, 1.5, 20.0), 0.0, pal.chalk);
    }
    if let Some(s) = search {
        for (i, (on, mark)) in [(s.case, "Aa"), (s.regex, ".*")].into_iter().enumerate() {
            let x = row.x + row.w - 70.0 + i as f32 * 30.0;
            if on {
                p.fill(Area::new(x - 4.0, by + 10.0, 26.0, 24.0), 5.0, pal.well);
            }
            let st = p.style(&f.mono, 12.0, if on { pal.chalk } else { pal.text_4 });
            p.line(&st, x, by + 13.0, 18.0, mark);
        }
    }
}

/// The colour and face of a token (WM_STYLE §7).
fn token_style<'s, 'f>(p: &Painter<'_>, pal: &Palette, f: &'s Fonts<'f>, t: Token) -> slate_ui::text::Style<'s, 'f> {
    let (face, colour, slant) = match t {
        Token::Keyword => (&f.mono_medium, pal.chalk, false),
        Token::Heading => (&f.mono_medium, pal.chalk, false),
        Token::Type => (&f.mono, pal.text_1, false),
        Token::Ident => (&f.mono, pal.text_2, false),
        Token::Punct => (&f.mono, pal.text_4, false),
        Token::Comment => (&f.mono, pal.muted, true),
        Token::String => (&f.mono, pal.text_1, false),
    };
    let mut s = p.style(face, FONT, colour).oblique(slant);
    s.ligatures = false;
    s
}

impl App for Editor {
    /// A file dropped on the window opens in it (ADR 0156's addendum),
    /// as ctrl + o would: not over unsaved changes, and one file a window.
    fn dropped(&mut self, _x: f32, _y: f32, paths: &[String], _copy: bool) -> Effect {
        let Some(path) = paths.first() else { return Effect::None };
        let name = path.rsplit('/').next().unwrap_or(path);
        if self.buf.modified() {
            self.status = String::from("Save the changes first (ctrl s), or undo them, then drop it again.");
        } else if slate_rt::fs::stat(path.as_bytes())
            .is_ok_and(|s| s.mode & slate_rt::fs::S_IFMT == slate_rt::fs::S_IFDIR)
        {
            self.status = alloc::format!("{name} is a folder: drop a file to open it.");
        } else {
            crate::trace!("editor: {name} dropped");
            self.open_instead(path);
            if paths.len() > 1 {
                self.status = alloc::format!("Opened {name}; a window opens one file at a time.");
            }
        }
        Effect::Redraw
    }

    fn draw(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area) {
        let bar_h = match self.bar {
            Some(Bar::Replace { .. }) => 84.0,
            Some(_) => 44.0,
            None => 0.0,
        };
        let status_h = 28.0;
        let n = self.buf.lines.len();
        let mono = p.style(&f.mono, FONT, pal.text_2);
        self.char_w = p.measure(&mono, "0").max(1.0);
        let digits = n.to_string().len().max(3) as f32;
        let gutter = digits * self.char_w + 28.0;
        self.text = Area::new(a.x + gutter, a.y + 8.0, a.w - gutter - 12.0, a.h - 8.0 - status_h - bar_h);
        self.rows = (self.text.h / LINE_H).max(1.0) as usize;
        self.cols = (self.text.w / self.char_w).max(1.0) as usize;
        self.top = self.top.min(n.saturating_sub(1));
        if self.wrap {
            self.left = 0;
            self.top_seg = self.top_seg.min(self.segs(self.top) - 1);
        } else {
            self.top_seg = 0;
        }
        // Block comments: the state each visible line starts in, from the
        // file's start.
        let mut state = false;
        for l in 0..self.top {
            state = crate::syntax::tokens(self.lang, &self.line_chars(l), state).1;
        }
        let sel = self.selection();
        let caret_line = self.caret.line;
        let num = p.style(&f.mono, 12.0, pal.decor);
        let num_cur = p.style(&f.mono, 12.0, pal.text_2);
        let caret_seg = self.caret_row().1;
        let clip = p.clip(Area::new(a.x, a.y, a.w, a.h - status_h - bar_h));
        // Row by row: a line, or with wrapping a part of one (`seg`), shown
        // from display column `left`.
        let mut at = Some((self.top, self.top_seg));
        for row in 0..=self.rows {
            let Some((l, seg)) = at else { break };
            at = self.row_step((l, seg), true);
            let (left, right) = if self.wrap { self.row_span(l, seg) } else { (self.left, usize::MAX) };
            let y = self.text.y + row as f32 * LINE_H;
            if l == caret_line && sel.is_none() {
                p.fill(Area::new(a.x, y, a.w, LINE_H), 0.0, pal.line_current);
            }
            if seg == 0 {
                let label = (l + 1).to_string();
                let s = if l == caret_line { &num_cur } else { &num };
                let lw = p.measure(s, &label);
                p.line(s, a.x + gutter - 14.0 - lw, y, LINE_H, &label);
            }
            let chars = self.line_chars(l);
            // The selection on this line, in display columns.
            if let Some((s0, s1)) = sel
                && (s0.line..=s1.line).contains(&l)
            {
                let c0 = if l == s0.line { self.column(s0) } else { 0 };
                let c1 = if l == s1.line {
                    self.column(s1)
                } else {
                    self.column(Pos { line: l, col: self.buf.lines[l].len() }) + 1
                }
                .min(right);
                let x0 = self.text.x + (c0 as f32 - left as f32) * self.char_w;
                let x1 = self.text.x + (c1 as f32 - left as f32) * self.char_w;
                if x1 > x0 {
                    p.fill(
                        Area::new(x0.max(self.text.x), y, (x1 - x0.max(self.text.x)).max(0.0), LINE_H),
                        0.0,
                        pal.raised,
                    );
                }
            }
            let (runs, next) = crate::syntax::tokens(self.lang, &chars, state);
            if at.is_none_or(|(nl, _)| nl != l) {
                state = next;
            }
            let inner = p.clip(self.text);
            let mut col = 0usize;
            let mut ci = 0usize;
            for (s, e, t) in runs {
                // Characters before the run (shouldn't happen) are skipped.
                while ci < s {
                    col += cw(chars[ci], col);
                    ci += 1;
                }
                let style = token_style(p, pal, f, t);
                let mut piece = String::new();
                let mut piece_col = col;
                for &c in &chars[s..e] {
                    let w = cw(c, col);
                    // Tabs, and with wrapping what belongs to other rows.
                    if c == '\t' || col < left || col >= right {
                        if !piece.is_empty() {
                            let x = self.text.x + (piece_col as f32 - left as f32) * self.char_w;
                            p.line(&style, x, y, LINE_H, &piece);
                            piece.clear();
                        }
                        col += w;
                        piece_col = col;
                    } else {
                        piece.push(c);
                        col += w;
                    }
                }
                if !piece.is_empty() && col > left {
                    let x = self.text.x + (piece_col as f32 - left as f32) * self.char_w;
                    p.line(&style, x, y, LINE_H, &piece);
                }
                ci = e;
            }
            p.unclip(inner);
            if l == caret_line && seg == caret_seg {
                let x = self.text.x + (self.column(self.caret) as f32 - left as f32) * self.char_w;
                if x >= self.text.x - 1.0 && x <= self.text.x + self.text.w {
                    p.fill(Area::new(x, y + 2.0, 2.0, LINE_H - 4.0), 0.0, pal.chalk);
                }
            }
        }
        p.unclip(clip);
        // The bar, if any.
        if let Some(b) = &self.bar {
            let by = a.y + a.h - status_h - bar_h;
            p.fill(Area::new(a.x, by, a.w, bar_h), 0.0, pal.raised);
            match b {
                Bar::Close => {
                    let t = p.style(&f.medium, 13.0, pal.chalk);
                    p.line(&t, a.x + 16.0, by + 12.0, 20.0, "Unsaved changes.");
                    let hint = p.style(&f.mono, 11.5, pal.text_3);
                    p.line(
                        &hint,
                        a.x + 150.0,
                        by + 13.0,
                        18.0,
                        "ctrl s save and close · ctrl q close anyway · esc keep editing",
                    );
                }
                Bar::Find(field) | Bar::SaveAs(field) | Bar::Open(field) => {
                    let (name, search) = match b {
                        Bar::Find(_) => ("find", Some(self.search)),
                        Bar::Open(_) => ("open", None),
                        _ => ("save as", None),
                    };
                    field_row(p, pal, f, Area::new(a.x, by, a.w, 44.0), name, field, true, search);
                }
                Bar::Replace { find, with, on_with } => {
                    let row = |y| Area::new(a.x, y, a.w, 44.0);
                    field_row(p, pal, f, row(by), "find", find, !on_with, Some(self.search));
                    field_row(p, pal, f, row(by + 40.0), "replace", with, *on_with, None);
                }
            }
        }
        // The status line.
        let sy = a.y + a.h - status_h;
        p.fill(Area::new(a.x, sy, a.w, status_h), 0.0, pal.header);
        let st = p.style(&f.mono, 11.0, pal.muted);
        let pos = alloc::format!(
            "ln {}, col {} · {} lines · {} · {} · {}{}",
            self.caret.line + 1,
            self.column(self.caret) + 1,
            self.buf.text_lines(),
            self.lang.name(),
            if self.tabs { "tabs" } else { "spaces" },
            if self.crlf { "CRLF" } else { "LF" },
            if self.wrap { " · wrap" } else { "" }
        );
        let pw = p.measure(&st, &pos);
        p.line(&st, a.x + a.w - 14.0 - pw, sy + 5.0, 18.0, &pos);
        if !self.status.is_empty() {
            let msg = p.style(&f.regular, 12.0, pal.text_3);
            p.line(&msg, a.x + 14.0, sy + 5.0, 18.0, &self.status);
        }
    }

    fn key(&mut self, code: u16, ch: Option<char>, mods: u8) -> Effect {
        if self.bar.is_some() && !(matches!(self.bar, Some(Bar::Find(_))) && mods & CTRL != 0 && ch == Some('f')) {
            return self.bar_key(code, ch, mods);
        }
        let (shift, ctrl) = (mods & SHIFT != 0, mods & CTRL != 0);
        let shortcut = mods & (CTRL | ALT | LOGO) != 0;
        self.status.clear();
        let n = self.buf.lines.len();
        let letter = ch.map(|c| c.to_ascii_lowercase());
        match (code, letter) {
            (_, Some('s')) if ctrl => return self.save(shift),
            (_, Some('f')) if ctrl => {
                // The selection to start with, chosen, so typing replaces it.
                let start = self.selected_text().filter(|t| !t.contains('\n')).unwrap_or_default();
                let mut field = LineEdit::new(&start).with_max(200);
                field.select_all();
                self.bar = Some(Bar::Find(field));
                return Effect::Redraw;
            }
            (_, Some('h')) if ctrl => {
                let start = self.selected_text().filter(|t| !t.contains('\n')).unwrap_or_default();
                let mut find = LineEdit::new(&start).with_max(200);
                find.select_all();
                let on_with = !start.is_empty();
                self.bar = Some(Bar::Replace { find, with: LineEdit::new("").with_max(200), on_with });
                return Effect::Redraw;
            }
            (_, Some('o')) if ctrl => {
                if self.buf.modified() {
                    self.status = String::from("Save the changes first (ctrl s), or undo them.");
                    return Effect::Redraw;
                }
                let home = slate_rt::env::var(b"HOME").map(|h| String::from(slate_rt::lossy(&h))).unwrap_or_default();
                let dir = self.path.as_deref().and_then(|p| p.rsplit_once('/')).map_or(home, |(d, _)| d.to_string());
                self.bar = Some(Bar::Open(LineEdit::new(&alloc::format!("{dir}/")).with_max(1024)));
                return Effect::Redraw;
            }
            (_, Some('z')) if mods & ALT != 0 => {
                self.wrap = !self.wrap;
                (self.left, self.top_seg, self.want) = (0, 0, None);
                self.status = String::from(if self.wrap { "Long lines wrap." } else { "Long lines scroll sideways." });
            }
            (_, Some('a')) if ctrl => {
                self.anchor = Some(Pos::default());
                self.caret = Pos { line: n - 1, col: self.buf.lines[n - 1].len() };
            }
            (_, Some('c')) if ctrl => return self.selected_text().map_or(Effect::None, Effect::Copy),
            (_, Some('x')) if ctrl => {
                let Some(t) = self.selected_text() else { return Effect::None };
                self.delete_selection();
                self.buf.seal();
                self.reveal();
                return Effect::Copy(t);
            }
            (_, Some('v')) if ctrl => return Effect::Paste,
            (_, Some('z')) if ctrl && !shift => {
                if let Some(p) = self.buf.undo() {
                    self.caret = self.buf.clamp(p);
                    self.anchor = None;
                }
            }
            (_, Some('z' | 'y')) if ctrl => {
                if let Some(p) = self.buf.redo() {
                    self.caret = self.buf.clamp(p);
                    self.anchor = None;
                }
            }
            (KEY_LEFT, _) => {
                let to = match (self.selection(), shift, ctrl) {
                    (Some((s, _)), false, false) => s,
                    (_, _, true) => self.word(self.caret, false),
                    _ => self.buf.prev(self.caret),
                };
                self.go(to, shift);
                self.want = None;
            }
            (KEY_RIGHT, _) => {
                let to = match (self.selection(), shift, ctrl) {
                    (Some((_, e)), false, false) => e,
                    (_, _, true) => self.word(self.caret, true),
                    _ => self.buf.next(self.caret),
                };
                self.go(to, shift);
                self.want = None;
            }
            // Wrapping: by rows, keeping to a column within the row.
            (KEY_UP | KEY_DOWN | KEY_PAGEUP | KEY_PAGEDOWN, _) if self.wrap => {
                let mut at = self.caret_row();
                let want = *self.want.get_or_insert(self.column(self.caret) - self.row_span(at.0, at.1).0);
                let page = matches!(code, KEY_PAGEUP | KEY_PAGEDOWN);
                let step = if page { self.rows.max(2) - 1 } else { 1 };
                let down = matches!(code, KEY_DOWN | KEY_PAGEDOWN);
                for _ in 0..step {
                    match self.row_step(at, down) {
                        Some(r) => at = r,
                        None => break,
                    }
                }
                if page {
                    self.scroll_rows(if down { step as i64 } else { -(step as i64) });
                }
                let (start, end) = self.row_span(at.0, at.1);
                let to = self.at_column(at.0, (start + want).min(end.saturating_sub(1)));
                self.go(to, shift);
                self.want = Some(want);
            }
            (KEY_UP | KEY_DOWN | KEY_PAGEUP | KEY_PAGEDOWN, _) => {
                let want = *self.want.get_or_insert(self.column(self.caret));
                let step = if matches!(code, KEY_PAGEUP | KEY_PAGEDOWN) { self.rows.max(2) - 1 } else { 1 };
                let line = if matches!(code, KEY_UP | KEY_PAGEUP) {
                    self.caret.line.saturating_sub(step)
                } else {
                    (self.caret.line + step).min(n - 1)
                };
                if matches!(code, KEY_PAGEUP | KEY_PAGEDOWN) {
                    self.top =
                        if code == KEY_PAGEUP { self.top.saturating_sub(step) } else { (self.top + step).min(n - 1) };
                }
                let to = self.at_column(line, want);
                self.go(to, shift);
                self.want = Some(want);
            }
            (KEY_HOME, _) => {
                let to = if ctrl {
                    Pos::default()
                } else {
                    // The line's text first, then its very start.
                    let indent = self.buf.lines[self.caret.line].iter().take_while(|c| c.is_ascii_whitespace()).count();
                    Pos { line: self.caret.line, col: if self.caret.col == indent { 0 } else { indent } }
                };
                self.go(to, shift);
                self.want = None;
            }
            (KEY_END, _) => {
                let line = if ctrl { n - 1 } else { self.caret.line };
                let to = Pos { line, col: self.buf.lines[line].len() };
                self.go(to, shift);
                self.want = None;
            }
            (KEY_ESC, _) => {
                if self.anchor.take().is_none() {
                    return Effect::None;
                }
            }
            (KEY_ENTER | KEY_KPENTER, _) => {
                self.delete_selection();
                let line = &self.buf.lines[self.caret.line];
                let indent: Vec<u8> = line[..self.caret.col.min(line.len())]
                    .iter()
                    .take_while(|c| **c == b' ' || **c == b'\t')
                    .copied()
                    .collect();
                let mut text = alloc::vec![b'\n'];
                text.extend_from_slice(&indent);
                self.buf.seal();
                self.caret = self.buf.insert(self.caret, &text);
                self.buf.seal();
                self.want = None;
            }
            (KEY_TAB, _) => {
                match self.selection() {
                    Some((s, e)) if s.line != e.line => {
                        let last = if e.col == 0 { e.line - 1 } else { e.line };
                        self.indent_lines(s.line, last, shift);
                    }
                    _ if shift => {
                        let l = self.caret.line;
                        self.indent_lines(l, l, true);
                    }
                    _ => {
                        self.delete_selection();
                        let unit = if self.tabs {
                            String::from("\t")
                        } else {
                            " ".repeat(TAB - self.column(self.caret) % TAB)
                        };
                        self.insert(&unit);
                    }
                }
                self.want = None;
            }
            (KEY_BACKSPACE | KEY_DELETE, _) => {
                if !self.delete_selection() {
                    let forward = code == KEY_DELETE;
                    let to = match (forward, ctrl) {
                        (false, true) => self.word(self.caret, false),
                        (false, false) => self.buf.prev(self.caret),
                        (true, true) => self.word(self.caret, true),
                        (true, false) => self.buf.next(self.caret),
                    };
                    let (s, e) = (to.min(self.caret), to.max(self.caret));
                    self.buf.delete(s, e);
                    self.caret = s;
                }
                self.want = None;
            }
            _ => match ch.filter(|c| !shortcut && (!c.is_control() || *c == '\t')) {
                Some(c) => {
                    let mut b = [0u8; 4];
                    self.insert(c.encode_utf8(&mut b));
                }
                None => return Effect::None,
            },
        }
        self.reveal();
        Effect::Redraw
    }

    fn click(&mut self, x: f32, y: f32) -> Effect {
        if !self.text.contains(x, y) {
            return Effect::None;
        }
        let p = self.click_pos(x, y);
        self.go(p, false);
        self.want = None;
        self.dragging = true;
        Effect::Redraw
    }

    fn double_click(&mut self, x: f32, y: f32) -> Effect {
        if !self.text.contains(x, y) {
            return Effect::None;
        }
        let p = self.click_pos(x, y);
        self.select_word(p);
        self.dragging = false;
        Effect::Redraw
    }

    fn drag(&mut self, x: f32, y: f32) -> Effect {
        if !self.dragging {
            return Effect::None;
        }
        // Past the top or bottom, it scrolls.
        if self.wrap && (y < self.text.y || y > self.text.y + self.text.h) {
            self.scroll_rows(if y < self.text.y { -1 } else { 1 });
        } else if y < self.text.y && self.top > 0 {
            self.top -= 1;
        } else if y > self.text.y + self.text.h && self.top + 1 < self.buf.lines.len() {
            self.top += 1;
        }
        let p = self.click_pos(x, y.clamp(self.text.y, self.text.y + self.text.h - 1.0));
        if p == self.caret {
            return Effect::None;
        }
        self.go(p, true);
        Effect::Redraw
    }

    fn release(&mut self) -> Effect {
        self.dragging = false;
        Effect::None
    }

    fn scroll(&mut self, lines: i32) -> Effect {
        if self.wrap {
            let before = (self.top, self.top_seg);
            self.scroll_rows(i64::from(lines) * 3);
            return if (self.top, self.top_seg) == before { Effect::None } else { Effect::Redraw };
        }
        let n = self.buf.lines.len();
        let top = (self.top as i64 + i64::from(lines) * 3).clamp(0, n.saturating_sub(1) as i64) as usize;
        if top == self.top {
            return Effect::None;
        }
        self.top = top;
        Effect::Redraw
    }

    fn paste(&mut self, text: &str) -> Effect {
        match &mut self.bar {
            Some(Bar::Find(f) | Bar::SaveAs(f) | Bar::Open(f)) => {
                f.insert(text.lines().next().unwrap_or(""));
            }
            Some(Bar::Replace { find, with, on_with }) => {
                (if *on_with { with } else { find }).insert(text.lines().next().unwrap_or(""));
            }
            Some(Bar::Close) => return Effect::None,
            None => {
                self.buf.seal();
                self.insert(text);
                self.buf.seal();
                self.reveal();
            }
        }
        Effect::Redraw
    }

    fn close(&mut self) -> bool {
        if self.buf.modified() {
            self.bar = Some(Bar::Close);
            return false;
        }
        true
    }

    fn title(&self) -> Option<(String, Option<String>)> {
        Some(Editor::title(self))
    }
}

pub fn main() -> i32 {
    let arg = slate_rt::env::args().get(1).map(|a| String::from(slate_rt::lossy(a)));
    let mut e = match arg {
        Some(p) => match Editor::open(&p) {
            Ok(e) => e,
            Err(msg) => {
                let mut e = Editor::new(None, b"");
                e.status = msg;
                e
            }
        },
        None => Editor::new(None, b""),
    };
    let (name, dir) = Editor::title(&e);
    e.shown_title = Some(name.clone());
    kit::run("text-editor", &name, dir.as_deref(), Hints { min: (420, 300), size: (760, 620) }, &mut e)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(e: &mut Editor, s: &str) {
        for c in s.chars() {
            match c {
                '\n' => e.key(KEY_ENTER, None, 0),
                '\t' => e.key(KEY_TAB, None, 0),
                c => e.key(0, Some(c), 0),
            };
        }
    }

    #[test]
    fn typing_indent_and_undo() {
        let mut e = Editor::new(Some("/tmp/x.rs".into()), b"");
        typed(&mut e, "fn main() {\n\tlet x = 1;\nx");
        assert_eq!(e.buf.to_bytes(), b"fn main() {\n    let x = 1;\n    x\n");
        assert!(e.buf.modified());
        e.key(0, Some('z'), CTRL);
        assert_eq!(e.buf.to_bytes(), b"fn main() {\n    let x = 1;\n    \n");
        e.key(0, Some('z'), CTRL | SHIFT);
        assert_eq!(e.buf.to_bytes(), b"fn main() {\n    let x = 1;\n    x\n");
        // Home: to the text, then the line's start.
        e.key(KEY_HOME, None, 0);
        assert_eq!(e.caret.col, 4);
        e.key(KEY_HOME, None, 0);
        assert_eq!(e.caret.col, 0);
        // Select across two lines and outdent them (a selection ending at
        // a line's very start would leave that line out).
        e.key(KEY_END, None, 0);
        e.key(KEY_UP, None, SHIFT);
        e.key(KEY_TAB, None, SHIFT);
        assert_eq!(e.buf.to_bytes(), b"fn main() {\nlet x = 1;\nx\n");
        assert_eq!(e.lang, Lang::Rust);
    }

    #[test]
    fn words_selection_and_clipboard() {
        let mut e = Editor::new(None, b"alpha beta\ngamma\n");
        e.key(KEY_RIGHT, None, CTRL);
        assert_eq!(e.caret, Pos { line: 0, col: 5 });
        e.key(KEY_RIGHT, None, CTRL | SHIFT);
        assert_eq!(e.selected_text().as_deref(), Some(" beta"));
        assert_eq!(e.key(0, Some('c'), CTRL), Effect::Copy(" beta".into()));
        assert_eq!(e.key(0, Some('x'), CTRL), Effect::Copy(" beta".into()));
        assert_eq!(e.buf.lines[0], b"alpha");
        e.key(KEY_DOWN, None, 0);
        e.paste("é\r\nz");
        assert_eq!(e.buf.to_bytes(), "alpha\ngammaé\nz\n".as_bytes());
        e.key(KEY_BACKSPACE, None, CTRL);
        assert_eq!(e.buf.lines[2], b"");
        e.key(0, Some('a'), CTRL);
        assert_eq!(e.selected_text().unwrap(), "alpha\ngammaé\n\n");
        e.select_word(Pos { line: 1, col: 2 });
        assert_eq!(e.selected_text().as_deref(), Some("gammaé"));
    }

    #[test]
    fn find_and_columns() {
        let mut e = Editor::new(None, b"one Two\n\tthree two\ntwo\n");
        e.key(0, Some('f'), CTRL);
        typed(&mut e, "two");
        assert_eq!(
            (e.caret, e.anchor),
            (Pos { line: 0, col: 7 }, Some(Pos { line: 0, col: 4 })),
            "found as typed, any case"
        );
        e.key(KEY_ENTER, None, 0);
        assert_eq!(e.anchor, Some(Pos { line: 1, col: 7 }));
        e.key(KEY_ENTER, None, SHIFT);
        assert_eq!(e.anchor, Some(Pos { line: 0, col: 4 }));
        e.key(KEY_ESC, None, 0);
        assert!(e.bar.is_none());
        // A tab is four columns from the start.
        assert_eq!(e.column(Pos { line: 1, col: 1 }), 4);
        assert_eq!(e.at_column(1, 5), Pos { line: 1, col: 2 });
        assert!(e.tabs, "the file indents with tabs");
    }

    #[test]
    fn replacing_one_and_all() {
        let mut e = Editor::new(None, b"cat Cat\ndog cat\n");
        e.key(0, Some('h'), CTRL);
        typed(&mut e, "cat");
        assert_eq!(e.anchor, Some(Pos { line: 0, col: 0 }), "found as typed");
        e.key(KEY_TAB, None, 0);
        typed(&mut e, "fox");
        e.key(KEY_ENTER, None, 0);
        assert_eq!(e.buf.lines[0], b"fox Cat");
        assert_eq!(e.anchor, Some(Pos { line: 0, col: 4 }), "the next match chosen");
        // Matching case: only the lower-case one is left.
        e.key(0, Some('c'), ALT);
        e.key(KEY_ENTER, None, CTRL);
        assert_eq!(e.buf.to_bytes(), b"fox Cat\ndog fox\n");
        assert_eq!(e.status, "Replaced 1.");
        // All of it is one undo.
        e.key(KEY_ESC, None, 0);
        e.key(0, Some('z'), CTRL);
        assert_eq!(e.buf.to_bytes(), b"fox Cat\ndog cat\n");
        e.key(0, Some('z'), CTRL);
        assert_eq!(e.buf.to_bytes(), b"cat Cat\ndog cat\n");
    }

    #[test]
    fn regular_expressions() {
        let mut e = Editor::new(None, b"x = 10;\ny = 200;\nz;\n");
        e.key(0, Some('h'), CTRL);
        e.key(0, Some('r'), ALT);
        typed(&mut e, "([a-z]) = ([0-9]+)");
        assert_eq!(e.selected_text().as_deref(), Some("x = 10"));
        e.key(KEY_TAB, None, 0);
        typed(&mut e, "\\2 -> \\1");
        e.key(KEY_ENTER, None, CTRL);
        assert_eq!(e.buf.to_bytes(), b"10 -> x;\n200 -> y;\nz;\n");
        assert_eq!(e.status, "Replaced 2.");
        // A bad one says so.
        e.key(KEY_TAB, None, 0);
        e.key(0, Some('a'), CTRL);
        typed(&mut e, "(");
        assert!(e.status.starts_with("Not a regular expression"), "{}", e.status);
    }

    #[test]
    fn wrapping_long_lines() {
        let mut e = Editor::new(None, b"0123456789abcdefghij\nshort\n");
        (e.cols, e.rows) = (8, 4);
        e.key(0, Some('z'), ALT);
        assert!(e.wrap);
        assert_eq!((e.segs(0), e.segs(1)), (3, 1));
        // Down goes by rows within a line, then to the next line.
        e.key(KEY_RIGHT, None, 0);
        e.key(KEY_DOWN, None, 0);
        assert_eq!(e.caret, Pos { line: 0, col: 9 });
        e.key(KEY_DOWN, None, 0);
        e.key(KEY_DOWN, None, 0);
        assert_eq!(e.caret, Pos { line: 1, col: 1 });
        e.key(KEY_UP, None, 0);
        assert_eq!(e.caret, Pos { line: 0, col: 17 });
        // Scrolling by rows, and back so the caret shows.
        e.key(KEY_END, None, CTRL);
        assert_eq!((e.top, e.top_seg), (0, 1));
        e.scroll(-1);
        assert_eq!((e.top, e.top_seg), (0, 0));
        e.key(0, Some('z'), ALT);
        assert!(!e.wrap);
        assert_eq!(e.segs(0), 1);
        // Words stay whole: rows break after a space.
        let mut w = Editor::new(None, b"one two three four\n");
        (w.cols, w.rows, w.wrap) = (10, 4, true);
        assert_eq!(w.row_starts(0), [0, 8]);
        assert_eq!((w.seg_of(0, 7), w.seg_of(0, 8)), (0, 1));
        w.key(KEY_DOWN, None, 0);
        assert_eq!(w.caret, Pos { line: 0, col: 8 });
    }

    #[test]
    fn dropped_files() {
        let dir = std::env::temp_dir().join(alloc::format!("slate-editor-drop-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let other = dir.join("other.rs").to_string_lossy().into_owned();
        std::fs::write(&other, b"fn y() {}\n").unwrap();
        let mut e = Editor::new(None, b"");
        typed(&mut e, "changed");
        e.dropped(0.0, 0.0, &[other.clone()], false);
        assert!(e.status.starts_with("Save the changes first"), "not over unsaved changes");
        e.key(0, Some('z'), CTRL);
        e.dropped(0.0, 0.0, &[dir.to_string_lossy().into_owned()], false);
        assert!(e.status.ends_with("is a folder: drop a file to open it."));
        e.dropped(0.0, 0.0, &[other.clone(), other], false);
        assert_eq!(e.buf.to_bytes(), b"fn y() {}\n");
        assert_eq!(e.status, "Opened other.rs; a window opens one file at a time.");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn opening_another_file() {
        let dir = std::env::temp_dir().join(alloc::format!("slate-editor-open-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let other = dir.join("other.rs").to_string_lossy().into_owned();
        std::fs::write(&other, b"fn x() {}\n").unwrap();
        let mut e = Editor::new(None, b"");
        typed(&mut e, "changed");
        e.key(0, Some('o'), CTRL);
        assert!(e.bar.is_none(), "not while there are unsaved changes");
        e.key(0, Some('z'), CTRL);
        e.key(0, Some('o'), CTRL);
        if let Some(Bar::Open(f)) = &mut e.bar {
            f.set_text(&other);
        }
        e.key(KEY_ENTER, None, 0);
        assert_eq!((e.buf.to_bytes().as_slice(), e.lang), (b"fn x() {}\n".as_slice(), Lang::Rust));
        assert_eq!(e.title().0, "other.rs");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn saving_keeps_the_file_as_it_was() {
        let dir = std::env::temp_dir().join(alloc::format!("slate-editor-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("dos.txt").to_string_lossy().into_owned();
        std::fs::write(&path, b"a\r\nb\r\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut e = Editor::open(&path).unwrap();
        assert!(e.crlf);
        e.key(KEY_END, None, 0);
        typed(&mut e, "!");
        assert_eq!(e.title().0, "dos.txt •");
        assert!(!e.close());
        assert!(matches!(e.bar, Some(Bar::Close)));
        assert_eq!(e.key(0, Some('s'), CTRL), Effect::Quit);
        assert_eq!(std::fs::read(&path).unwrap(), b"a!\r\nb\r\n");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        // A new file asks for its name.
        let mut n = Editor::new(None, b"");
        typed(&mut n, "hi");
        n.key(0, Some('s'), CTRL);
        assert!(matches!(n.bar, Some(Bar::SaveAs(_))));
        if let Some(Bar::SaveAs(f)) = &mut n.bar {
            f.set_text(&dir.join("new.md").to_string_lossy());
        }
        n.key(KEY_ENTER, None, 0);
        assert_eq!(std::fs::read(dir.join("new.md")).unwrap(), b"hi\n");
        assert_eq!((n.lang, n.title().0.as_str()), (Lang::Markdown, "new.md"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
