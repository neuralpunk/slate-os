// SPDX-License-Identifier: MIT OR Apache-2.0

//! A terminal emulator: turns a byte stream into a grid of character cells.
//!
//! It implements the subset of ECMA-48 / VT100 / xterm control functions
//! that shells, line editors and full-screen tools use: cursor movement
//! (CUU, CUD, CUF, CUB, CNL, CPL, CHA, CUP, VPA), erasing (ED, EL, ECH),
//! insertion and deletion (ICH, DCH, IL, DL), scrolling (SU, SD, IND, RI,
//! DECSTBM), SGR attributes (bold, dim, italic, underline, reverse,
//! crossed out) with 16, 256 and direct (24-bit) colours, save/restore
//! cursor, the cursor-position report (DSR 6), cursor visibility, autowrap,
//! application cursor keys (DECCKM), bracketed paste (DECSET 2004), mouse
//! reporting (DECSET 9, 1000, 1002, 1003, with 1006's encoding) and the
//! alternate screen (DECSET 1049). The sequences are xterm's ctlseqs.
//!
//! Input is decoded as UTF-8. Wide characters (UAX #11) take two cells,
//! the second a [`Cell::TAIL`]; combining marks join the character before
//! them, kept in the terminal's table of extra characters (a cell holds
//! an index into it). With DEC mode 2027 set (grapheme clusters, as other
//! terminals have it; DECRQM reports it), a cluster takes one cell, two
//! when it is an emoji presentation: ZWJ sequences, skin-tone modifiers,
//! flags (regional indicator pairs), tags and variation selectors join
//! the character before them (ADR 0166). The grid can be resized (a terminal window):
//! the main screen's lines and the scrollback are wrapped again to the
//! new width (ADR 0099).
//!
//! Optionally it keeps a scrollback: lines scrolled off the top of the
//! main screen, each remembering whether it wrapped onto the next (so a
//! long line copies as one). ED 3 clears it (xterm's ctlseqs).

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use crate::width::width;

/// A colour: an index into the palette (0-15 the ANSI/aixterm colours,
/// 16-255 the xterm 256-colour cube and grey ramp) or a direct one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Color {
    Index(u8),
    Rgb(u8, u8, u8),
}

pub const DEFAULT_FG: Color = Color::Index(7);
pub const DEFAULT_BG: Color = Color::Index(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attr {
    pub fg: Color,
    pub bg: Color,
    pub bold: bool,
    /// Faint (SGR 2).
    pub dim: bool,
    pub italic: bool,
    pub underline: bool,
    /// Crossed out (SGR 9).
    pub strike: bool,
    pub reverse: bool,
}

impl Attr {
    pub const DEFAULT: Attr = Attr {
        fg: DEFAULT_FG,
        bg: DEFAULT_BG,
        bold: false,
        dim: false,
        italic: false,
        underline: false,
        strike: false,
        reverse: false,
    };

    /// Colours after applying bold (bright) and reverse.
    pub fn resolved(&self) -> (Color, Color) {
        let fg = match self.fg {
            Color::Index(i) if self.bold && i < 8 => Color::Index(i + 8),
            c => c,
        };
        if self.reverse { (self.bg, fg) } else { (fg, self.bg) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    pub ch: char,
    /// The characters drawn with it (combining marks, a cluster's rest):
    /// 0 for none, else 1 + their index in the terminal's table
    /// ([`Term::extras`]).
    pub ext: u32,
    /// It takes two cells (a wide character, or a cluster made wide).
    pub wide: bool,
    pub attr: Attr,
}

/// The most characters a cell's cluster keeps besides its own (more are
/// dropped), and the most clusters the table keeps.
pub const CLUSTER_MAX: usize = 31;
const TABLE_MAX: usize = 1 << 16;

impl Cell {
    pub const BLANK: Cell = Cell { ch: ' ', ext: 0, wide: false, attr: Attr::DEFAULT };
    /// The `ch` of the cell after a wide character, which it covers; also
    /// of the cell left empty when a wide character wrapped to the next
    /// line early.
    pub const TAIL: char = '\0';

    pub fn is_tail(&self) -> bool {
        self.ch == Cell::TAIL
    }

    /// The columns the character takes (1 or 2; tails count as 1).
    pub fn width(&self) -> usize {
        if self.is_tail() {
            1
        } else if self.wide {
            2
        } else {
            width(self.ch).max(1)
        }
    }
}

/// Whether `c` joins the grapheme cluster before it (with mode 2027):
/// ZWJ, variation selectors, emoji modifiers, tags; regional indicators
/// pair up (checked by the caller).
fn joins(c: char) -> bool {
    matches!(c as u32, 0x200D | 0xFE00..=0xFE0F | 0x1F3FB..=0x1F3FF | 0xE0020..=0xE007F)
}

fn regional(c: char) -> bool {
    matches!(c as u32, 0x1F1E6..=0x1F1FF)
}

/// What mouse events a program asked to hear (xterm's ctlseqs, "Mouse
/// Tracking").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseMode {
    Off,
    /// DECSET 9 (X10): presses only.
    Press,
    /// DECSET 1000: presses and releases.
    Click,
    /// DECSET 1002: also moves while a button is held.
    Drag,
    /// DECSET 1003: every move.
    Motion,
}

/// How mouse reports are written (xterm's ctlseqs, "Extended
/// coordinates"): the last of DECSET 1005, 1006 and 1015 set wins, and
/// resetting it returns to the old one-byte form.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MouseEncoding {
    /// `CSI M Cb Cx Cy`, each value plus 32 in one byte.
    #[default]
    X10,
    /// DECSET 1005: the same values as UTF-8 characters (positions up to
    /// 2015).
    Utf8,
    /// DECSET 1006: `CSI < Cb ; Cx ; Cy M` (`m` for a release).
    Sgr,
    /// DECSET 1015 (urxvt): `CSI Cb ; Cx ; Cy M`, Cb plus 32, in decimal.
    Urxvt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum State {
    Ground,
    Escape,
    /// ESC followed by an intermediate byte (charset selection etc.).
    EscapeIntermediate,
    Csi,
    /// Operating system command: ignored until BEL or ST.
    Osc,
    OscEscape,
}

/// A line of the scrollback: its cells (trailing blanks dropped) and
/// whether the text went on in the next line (autowrap).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub cells: Vec<Cell>,
    pub wrapped: bool,
}

/// The emulator state.
#[derive(Clone, Debug)]
pub struct Term {
    cols: usize,
    rows: usize,
    cells: Vec<Cell>,
    /// Per row: the text went on in the next row (autowrap).
    wrapped: Vec<bool>,
    /// The main screen (and its wrap marks) while the alternate screen is
    /// shown.
    saved_screen: Option<(Vec<Cell>, Vec<bool>)>,
    /// Lines scrolled off the main screen, oldest first, at most
    /// `scrollback` of them.
    history: VecDeque<Line>,
    scrollback: usize,
    /// How many lines have left the history's far end, ever (so lines keep
    /// their numbers as it moves).
    dropped: u64,
    row: usize,
    col: usize,
    /// The last column was written; the next printable character wraps.
    wrap_pending: bool,
    attr: Attr,
    saved: (usize, usize, Attr),
    top: usize,
    bottom: usize,
    autowrap: bool,
    pub cursor_visible: bool,
    /// Application cursor keys (DECCKM, DECSET 1): arrows send ESC O x.
    pub app_cursor: bool,
    /// Bracketed paste (DECSET 2004): pasted text is marked.
    pub bracketed_paste: bool,
    /// Mouse reporting (DECSET 9, 1000, 1002, 1003).
    pub mouse: MouseMode,
    /// How mouse reports are written (DECSET 1005, 1006, 1015).
    pub mouse_encoding: MouseEncoding,
    state: State,
    params: Vec<u16>,
    /// Per parameter: it followed a colon (a sub-parameter, ITU T.416).
    sub: Vec<bool>,
    private: bool,
    utf8: (u32, u8),
    dirty: Vec<bool>,
    responses: Vec<u8>,
    /// The CSI's intermediate byte (DECRQM's `$`), if any.
    intermediate: u8,
    /// Extra characters of cells (combining marks, clusters' rests), and
    /// each list's index (cells refer to them by [`Cell::ext`]).
    extras: Vec<Vec<char>>,
    extra_ids: alloc::collections::BTreeMap<Vec<char>, u32>,
    /// DEC mode 2027: grapheme clusters take one cell.
    pub graphemes: bool,
}

impl Term {
    pub fn new(cols: usize, rows: usize) -> Term {
        let (cols, rows) = (cols.max(1), rows.max(1));
        Term {
            cols,
            rows,
            cells: vec![Cell::BLANK; cols * rows],
            wrapped: vec![false; rows],
            saved_screen: None,
            history: VecDeque::new(),
            scrollback: 0,
            dropped: 0,
            row: 0,
            col: 0,
            wrap_pending: false,
            attr: Attr::DEFAULT,
            saved: (0, 0, Attr::DEFAULT),
            top: 0,
            bottom: rows - 1,
            autowrap: true,
            cursor_visible: true,
            app_cursor: false,
            bracketed_paste: false,
            mouse: MouseMode::Off,
            mouse_encoding: MouseEncoding::X10,
            state: State::Ground,
            params: Vec::new(),
            sub: Vec::new(),
            private: false,
            intermediate: 0,
            extras: Vec::new(),
            extra_ids: alloc::collections::BTreeMap::new(),
            graphemes: false,
            utf8: (0, 0),
            dirty: vec![true; rows],
            responses: Vec::new(),
        }
    }

    /// A new size. The main screen's lines and the scrollback are wrapped
    /// again to the new width, keeping the cursor on its character, and
    /// the bottom of the text in view; the alternate screen's text stays
    /// at the top left, cut or padded (its program redraws it). The
    /// scrolling region becomes the whole screen.
    pub fn resize(&mut self, cols: usize, rows: usize) {
        let (cols, rows) = (cols.max(1), rows.max(1));
        if (cols, rows) == (self.cols, self.rows) {
            return;
        }
        let old = (self.cols, self.rows);
        let alt = self.saved_screen.is_some();
        let main_cursor =
            if alt { (self.saved.0, self.saved.1, false) } else { (self.row, self.col, self.wrap_pending) };
        let main = match self.saved_screen.take() {
            Some(saved) => saved,
            None => (core::mem::take(&mut self.cells), core::mem::take(&mut self.wrapped)),
        };
        let keep = if self.scrollback > 0 { Some(&mut self.history) } else { None };
        let (cells, wrapped, (row, col, pending)) = reflow(keep, main, old, main_cursor, (cols, rows));
        if !alt {
            (self.cells, self.wrapped) = (cells, wrapped);
            (self.row, self.col, self.wrap_pending) = (row, col, pending);
        } else {
            // The alternate screen is shown: cut or pad it.
            let mut alt = vec![Cell::BLANK; cols * rows];
            for r in 0..old.1.min(rows) {
                for c in 0..old.0.min(cols) {
                    alt[r * cols + c] = self.cells[r * old.0 + c];
                }
            }
            self.cells = alt;
            self.wrapped = vec![false; rows];
            self.saved_screen = Some((cells, wrapped));
            (self.saved.0, self.saved.1) = (row, col);
            self.row = self.row.min(rows - 1);
            self.col = self.col.min(cols - 1);
            self.wrap_pending = false;
        }
        self.trim_history();
        (self.cols, self.rows) = (cols, rows);
        self.saved.0 = self.saved.0.min(rows - 1);
        self.saved.1 = self.saved.1.min(cols - 1);
        self.top = 0;
        self.bottom = rows - 1;
        self.dirty = vec![true; rows];
    }

    pub fn cols(&self) -> usize {
        self.cols
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Cursor position as (row, column), 0-based.
    pub fn cursor(&self) -> (usize, usize) {
        (self.row, self.col)
    }

    pub fn cell(&self, row: usize, col: usize) -> Cell {
        self.cells[row * self.cols + col]
    }

    /// Keep up to `lines` lines of scrollback (0, the default: none).
    pub fn set_scrollback(&mut self, lines: usize) {
        self.scrollback = lines;
        self.trim_history();
    }

    fn trim_history(&mut self) {
        while self.history.len() > self.scrollback {
            self.history.pop_front();
            self.dropped += 1;
        }
    }

    /// Forget the scrollback (ED 3).
    pub fn clear_scrollback(&mut self) {
        self.dropped += self.history.len() as u64;
        self.history.clear();
    }

    /// The lines in the scrollback.
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// How many lines have left the scrollback's far end: line `i` of
    /// [`Term::line`] has been the `dropped() + i`th line all along.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Line `i` counting from the oldest in the scrollback, through the
    /// screen's rows after it: its cells (perhaps fewer than the columns;
    /// the rest are blank) and whether it wrapped. None past the screen.
    pub fn line(&self, i: usize) -> Option<(&[Cell], bool)> {
        match i.checked_sub(self.history.len()) {
            None => self.history.get(i).map(|l| (l.cells.as_slice(), l.wrapped)),
            Some(r) if r < self.rows => Some((&self.cells[r * self.cols..(r + 1) * self.cols], self.wrapped[r])),
            Some(_) => None,
        }
    }

    /// Whether the alternate screen is shown (full-screen programs).
    pub fn alternate(&self) -> bool {
        self.saved_screen.is_some()
    }

    /// Text of a row, trailing blanks removed (for tests and diagnostics).
    pub fn row_text(&self, row: usize) -> alloc::string::String {
        let mut s = alloc::string::String::new();
        (0..self.cols).for_each(|c| self.push_cell(&self.cell(row, c), &mut s));
        alloc::string::String::from(s.trim_end())
    }

    /// Rows changed since the last call, as a list of indices.
    /// Mark every row for redrawing (the screen was taken over and given
    /// back).
    pub fn mark_all_dirty(&mut self) {
        self.dirty.iter_mut().for_each(|x| *x = true);
    }

    pub fn take_dirty(&mut self) -> Vec<usize> {
        let d: Vec<usize> = (0..self.rows).filter(|&r| self.dirty[r]).collect();
        self.dirty.iter_mut().for_each(|x| *x = false);
        d
    }

    /// Mark the row with the cursor dirty (for redrawing the cursor).
    pub fn touch_cursor_row(&mut self) {
        self.dirty[self.row] = true;
    }

    /// Bytes the terminal sends back to the host (replies to queries).
    pub fn take_responses(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.responses)
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.byte(b);
        }
    }

    fn byte(&mut self, b: u8) {
        match self.state {
            State::Ground => self.ground(b),
            State::Escape => self.escape(b),
            State::EscapeIntermediate => self.state = State::Ground,
            State::Csi => self.csi(b),
            State::Osc => match b {
                0x07 => self.state = State::Ground,
                0x1B => self.state = State::OscEscape,
                _ => {}
            },
            State::OscEscape => self.state = if b == b'\\' { State::Ground } else { State::Osc },
        }
    }

    fn ground(&mut self, b: u8) {
        // UTF-8 continuation of a multi-byte character.
        if self.utf8.1 > 0 {
            if b & 0xC0 == 0x80 {
                self.utf8.0 = (self.utf8.0 << 6) | u32::from(b & 0x3F);
                self.utf8.1 -= 1;
                if self.utf8.1 == 0 {
                    let c = char::from_u32(self.utf8.0).unwrap_or('\u{FFFD}');
                    self.print(c);
                }
                return;
            }
            self.utf8 = (0, 0);
            self.print('\u{FFFD}');
        }
        match b {
            0x1B => {
                self.state = State::Escape;
            }
            b'\r' => {
                self.col = 0;
                self.wrap_pending = false;
            }
            b'\n' | 0x0B | 0x0C => self.linefeed(),
            0x08 => {
                self.col = self.col.saturating_sub(1);
                self.wrap_pending = false;
            }
            b'\t' => {
                self.col = ((self.col / 8 + 1) * 8).min(self.cols - 1);
                self.wrap_pending = false;
            }
            0x07 | 0x00 | 0x7F => {}
            0x20..=0x7E => self.print(b as char),
            0xC0..=0xDF => self.utf8 = (u32::from(b & 0x1F), 1),
            0xE0..=0xEF => self.utf8 = (u32::from(b & 0x0F), 2),
            0xF0..=0xF7 => self.utf8 = (u32::from(b & 0x07), 3),
            _ => {}
        }
    }

    fn print(&mut self, c: char) {
        // Mode 2027: a character that joins the cluster before it.
        if self.graphemes && self.joins_cluster(c) {
            self.combine(c);
            if c == '\u{FE0F}' || regional(c) {
                self.widen_cluster();
            }
            return;
        }
        let w = width(c);
        if w == 0 {
            self.combine(c);
            return;
        }
        if self.wrap_pending && self.autowrap {
            self.wrapped[self.row] = true;
            self.col = 0;
            self.linefeed();
        }
        self.wrap_pending = false;
        let w = if self.cols < 2 { 1 } else { w };
        if self.col + w > self.cols {
            // No room for both halves: the character goes to the next line
            // (the last cell left empty), or into the last two columns.
            if self.autowrap {
                self.clear_halves(self.col, 1);
                self.cells[self.row * self.cols + self.col] = Cell { ch: Cell::TAIL, ..self.blank_cell() };
                self.wrapped[self.row] = true;
                self.col = 0;
                self.linefeed();
            } else {
                self.col = self.cols - w;
            }
        }
        self.clear_halves(self.col, w);
        let i = self.row * self.cols + self.col;
        self.cells[i] = Cell { ch: c, ext: 0, wide: w == 2, attr: self.attr };
        if w == 2 {
            self.cells[i + 1] = Cell { ch: Cell::TAIL, ext: 0, wide: false, attr: self.attr };
        }
        self.dirty[self.row] = true;
        if self.col + w < self.cols {
            self.col += w;
        } else {
            self.col = self.cols - 1;
            self.wrap_pending = true;
        }
    }

    /// Before `w` cells from column `col` of the cursor's row are written:
    /// a wide character they cut in half loses its other half.
    fn clear_halves(&mut self, col: usize, w: usize) {
        let start = self.row * self.cols;
        let blank = self.blank_cell();
        if col > 0 && self.cells[start + col].is_tail() {
            self.cells[start + col - 1] = blank;
        }
        let end = col + w;
        if end < self.cols && self.cells[start + end].is_tail() {
            self.cells[start + end] = blank;
        }
    }

    /// The extra characters of `c` (none: an empty slice).
    pub fn extras(&self, c: &Cell) -> &[char] {
        if c.ext == 0 { &[] } else { self.extras.get(c.ext as usize - 1).map_or(&[], |v| v.as_slice()) }
    }

    /// Push a cell's text (its character and extras; nothing for a tail).
    pub fn push_cell(&self, c: &Cell, s: &mut alloc::string::String) {
        if !c.is_tail() {
            s.push(c.ch);
            s.extend(self.extras(c).iter());
        }
    }

    /// The table index for `list` (made if new; 0 if the table is full).
    fn intern(&mut self, list: Vec<char>) -> u32 {
        if let Some(&id) = self.extra_ids.get(&list) {
            return id;
        }
        if self.extras.len() >= TABLE_MAX {
            return 0;
        }
        self.extras.push(list.clone());
        let id = self.extras.len() as u32;
        self.extra_ids.insert(list, id);
        id
    }

    /// The column of the cell before the cursor (a cluster's start), on
    /// the cursor's row.
    fn previous_col(&self) -> Option<usize> {
        let start = self.row * self.cols;
        let mut col = if self.wrap_pending {
            self.col
        } else if self.col > 0 {
            self.col - 1
        } else {
            return None;
        };
        if self.cells[start + col].is_tail() && col > 0 {
            col -= 1;
        }
        (!self.cells[start + col].is_tail()).then_some(col)
    }

    /// A combining mark (or, with mode 2027, a character that joins the
    /// cluster): it joins the character before the cursor (on the same
    /// row; past [`CLUSTER_MAX`], later ones are dropped).
    fn combine(&mut self, c: char) {
        let Some(col) = self.previous_col() else { return };
        let i = self.row * self.cols + col;
        let mut list = self.extras(&self.cells[i]).to_vec();
        if list.len() >= CLUSTER_MAX {
            return;
        }
        list.push(c);
        let id = self.intern(list);
        if id != 0 {
            self.cells[i].ext = id;
            self.dirty[self.row] = true;
        }
    }

    /// With mode 2027: whether `c` joins the cluster before the cursor
    /// (after a ZWJ anything does; a regional indicator after a lone one).
    fn joins_cluster(&self, c: char) -> bool {
        let Some(col) = self.previous_col() else { return false };
        let cell = &self.cells[self.row * self.cols + col];
        let extras = self.extras(cell);
        joins(c) || extras.last() == Some(&'\u{200D}') || (regional(c) && regional(cell.ch) && extras.is_empty())
    }

    /// A cluster made an emoji presentation (VS16, a flag) takes two cells
    /// if its cell can grow into the one after it.
    fn widen_cluster(&mut self) {
        let Some(col) = self.previous_col() else { return };
        let i = self.row * self.cols + col;
        if self.cells[i].width() == 2 || col + 1 >= self.cols || col + 1 != self.col || self.wrap_pending {
            return;
        }
        self.cells[i].wide = true;
        self.cells[i + 1] = Cell { ch: Cell::TAIL, ext: 0, wide: false, attr: self.cells[i].attr };
        if self.col + 1 < self.cols {
            self.col += 1;
        } else {
            self.wrap_pending = true;
        }
        self.dirty[self.row] = true;
    }

    fn linefeed(&mut self) {
        self.wrap_pending = false;
        if self.row == self.bottom {
            self.scroll_up(1);
        } else if self.row + 1 < self.rows {
            self.row += 1;
        }
    }

    fn reverse_index(&mut self) {
        if self.row == self.top {
            self.scroll_down(1);
        } else {
            self.row = self.row.saturating_sub(1);
        }
    }

    fn blank_cell(&self) -> Cell {
        Cell { attr: Attr { fg: self.attr.fg, bg: self.attr.bg, ..Attr::DEFAULT }, ..Cell::BLANK }
    }

    /// Scroll the region [top, bottom] up by `n` lines. Lines leaving the
    /// top of the main screen go to the scrollback.
    fn scroll_up(&mut self, n: usize) {
        let (top, bottom, cols) = (self.top, self.bottom, self.cols);
        let n = n.min(bottom - top + 1);
        if top == 0 && self.scrollback > 0 && self.saved_screen.is_none() {
            for r in 0..n {
                let row = &self.cells[r * cols..(r + 1) * cols];
                // A wrapped row's blanks are part of its line's text.
                let len = if self.wrapped[r] { cols } else { trimmed_len(row) };
                self.history.push_back(Line { cells: row[..len].to_vec(), wrapped: self.wrapped[r] });
            }
            self.trim_history();
        }
        self.cells.copy_within((top + n) * cols..(bottom + 1) * cols, top * cols);
        self.wrapped.copy_within(top + n..bottom + 1, top);
        let blank = self.blank_cell();
        self.cells[(bottom + 1 - n) * cols..(bottom + 1) * cols].fill(blank);
        self.wrapped[bottom + 1 - n..=bottom].fill(false);
        self.dirty[top..=bottom].iter_mut().for_each(|d| *d = true);
    }

    fn scroll_down(&mut self, n: usize) {
        let (top, bottom, cols) = (self.top, self.bottom, self.cols);
        let n = n.min(bottom - top + 1);
        self.cells.copy_within(top * cols..(bottom + 1 - n) * cols, (top + n) * cols);
        self.wrapped.copy_within(top..bottom + 1 - n, top + n);
        let blank = self.blank_cell();
        self.cells[top * cols..(top + n) * cols].fill(blank);
        self.wrapped[top..top + n].fill(false);
        self.dirty[top..=bottom].iter_mut().for_each(|d| *d = true);
    }

    fn escape(&mut self, b: u8) {
        self.state = State::Ground;
        match b {
            b'[' => {
                self.state = State::Csi;
                self.params.clear();
                self.params.push(0);
                self.sub.clear();
                self.sub.push(false);
                self.private = false;
                self.intermediate = 0;
            }
            b']' => self.state = State::Osc,
            b'(' | b')' | b'*' | b'+' | b'#' => self.state = State::EscapeIntermediate,
            b'7' => self.saved = (self.row, self.col, self.attr),
            b'8' => {
                (self.row, self.col, self.attr) = self.saved;
                self.wrap_pending = false;
            }
            b'D' => self.linefeed(),
            b'E' => {
                self.col = 0;
                self.linefeed();
            }
            b'M' => self.reverse_index(),
            b'c' => {
                // A full reset keeps the scrollback.
                let mut t = Term::new(self.cols, self.rows);
                t.history = core::mem::take(&mut self.history);
                (t.scrollback, t.dropped) = (self.scrollback, self.dropped);
                *self = t;
            }
            _ => {}
        }
    }

    fn param(&self, i: usize, default: u16) -> usize {
        match self.params.get(i).copied() {
            Some(0) | None => usize::from(default),
            Some(v) => usize::from(v),
        }
    }

    fn csi(&mut self, b: u8) {
        match b {
            b'0'..=b'9' => {
                let last = self.params.last_mut().unwrap();
                *last = last.saturating_mul(10).saturating_add(u16::from(b - b'0'));
            }
            b';' | b':' => {
                self.params.push(0);
                self.sub.push(b == b':');
            }
            b'?' | b'>' | b'=' => self.private = true,
            // Intermediate bytes: DECRQM's `$` is kept, the rest ignored.
            0x20..=0x2F => self.intermediate = b,
            0x40..=0x7E => {
                self.state = State::Ground;
                self.csi_dispatch(b);
            }
            0x1B => self.state = State::Escape,
            _ => {}
        }
    }

    fn erase(&mut self, from: usize, to: usize) {
        // A wide character half inside goes whole (looked at before the
        // blanks hide which half was which).
        self.mend_edges(from, to);
        let blank = self.blank_cell();
        self.cells[from..to].fill(blank);
        for r in from / self.cols..=((to.max(1) - 1) / self.cols).min(self.rows - 1) {
            self.dirty[r] = true;
            // Erased to its end, a row no longer goes on in the next.
            if to >= (r + 1) * self.cols {
                self.wrapped[r] = false;
            }
        }
    }

    /// Before cells `[from, to)` are blanked or moved (or cut apart at
    /// `from`, when `from == to`): a wide character with one half in the
    /// range and one outside loses the outside half too, on the rows at
    /// the ends of the range; a head left at a row's end without its
    /// tail goes.
    fn mend_edges(&mut self, from: usize, to: usize) {
        let cols = self.cols;
        let blank = self.blank_cell();
        // The cell before `from`: a wide head whose tail is at `from`.
        if from % cols != 0 && from < self.cells.len() && self.cells[from].is_tail() {
            let head = &self.cells[from - 1];
            if !head.is_tail() && head.width() == 2 {
                self.cells[from - 1] = blank;
                self.cells[from] = blank;
                self.dirty[from / cols] = true;
            }
        }
        // The cell at `to`: a tail whose head was at `to - 1`, or (at the
        // end of a row) a head whose tail went past it.
        if to % cols != 0 && to < self.cells.len() && self.cells[to].is_tail() && to > from {
            self.cells[to] = blank;
            self.dirty[to / cols] = true;
        }
        if to % cols == 0 && to > 0 {
            let last = &self.cells[to - 1];
            if !last.is_tail() && last.width() == 2 {
                self.cells[to - 1] = blank;
                self.dirty[(to - 1) / cols] = true;
            }
        }
    }

    fn csi_dispatch(&mut self, f: u8) {
        let (rows, cols) = (self.rows, self.cols);
        // DECRQM (CSI ? Ps $ p): whether a private mode is set (1), reset
        // (2) or unknown (0), as xterm's ctlseqs give the reply.
        if self.private && f == b'p' && self.intermediate == b'$' {
            let mode = self.param(0, 0);
            let state = match mode {
                25 => Some(self.cursor_visible),
                7 => Some(self.autowrap),
                1 => Some(self.app_cursor),
                2004 => Some(self.bracketed_paste),
                1049 | 1047 | 47 => Some(self.saved_screen.is_some()),
                2027 => Some(self.graphemes),
                _ => None,
            };
            let pm = match state {
                Some(true) => 1,
                Some(false) => 2,
                None => 0,
            };
            let reply = alloc::format!("\x1b[?{mode};{pm}$y");
            self.responses.extend_from_slice(reply.as_bytes());
            return;
        }
        if self.private {
            if matches!(f, b'h' | b'l') {
                let on = f == b'h';
                for i in 0..self.params.len() {
                    match self.params[i] {
                        25 => {
                            self.cursor_visible = on;
                            self.dirty[self.row] = true;
                        }
                        7 => self.autowrap = on,
                        1 => self.app_cursor = on,
                        2004 => self.bracketed_paste = on,
                        2027 => self.graphemes = on,
                        9 | 1000 | 1002 | 1003 => {
                            let mode = match self.params[i] {
                                9 => MouseMode::Press,
                                1000 => MouseMode::Click,
                                1002 => MouseMode::Drag,
                                _ => MouseMode::Motion,
                            };
                            if on {
                                self.mouse = mode;
                            } else if self.mouse == mode {
                                self.mouse = MouseMode::Off;
                            }
                        }
                        1005 | 1006 | 1015 => {
                            let which = match self.params[i] {
                                1005 => MouseEncoding::Utf8,
                                1006 => MouseEncoding::Sgr,
                                _ => MouseEncoding::Urxvt,
                            };
                            if on {
                                self.mouse_encoding = which;
                            } else if self.mouse_encoding == which {
                                self.mouse_encoding = MouseEncoding::X10;
                            }
                        }
                        47 | 1047 | 1049 => self.alternate_screen(on),
                        _ => {}
                    }
                }
            }
            return;
        }
        self.wrap_pending = false;
        match f {
            b'A' => {
                self.row =
                    self.row.saturating_sub(self.param(0, 1)).max(if self.row >= self.top { self.top } else { 0 })
            }
            b'B' => {
                self.row =
                    (self.row + self.param(0, 1)).min(if self.row <= self.bottom { self.bottom } else { rows - 1 })
            }
            b'C' => self.col = (self.col + self.param(0, 1)).min(cols - 1),
            b'D' => self.col = self.col.saturating_sub(self.param(0, 1)),
            b'E' => {
                self.row = (self.row + self.param(0, 1)).min(rows - 1);
                self.col = 0;
            }
            b'F' => {
                self.row = self.row.saturating_sub(self.param(0, 1));
                self.col = 0;
            }
            b'G' | b'`' => self.col = (self.param(0, 1) - 1).min(cols - 1),
            b'd' => self.row = (self.param(0, 1) - 1).min(rows - 1),
            b'H' | b'f' => {
                self.row = (self.param(0, 1) - 1).min(rows - 1);
                self.col = (self.param(1, 1) - 1).min(cols - 1);
            }
            b'J' => {
                let here = self.row * cols + self.col;
                match self.param(0, 0) {
                    0 => self.erase(here, rows * cols),
                    1 => self.erase(0, here + 1),
                    3 => self.clear_scrollback(),
                    _ => self.erase(0, rows * cols),
                }
            }
            b'K' => {
                let start = self.row * cols;
                match self.param(0, 0) {
                    0 => self.erase(start + self.col, start + cols),
                    1 => self.erase(start, start + self.col + 1),
                    _ => self.erase(start, start + cols),
                }
            }
            b'X' => {
                let start = self.row * cols + self.col;
                let n = self.param(0, 1).min(cols - self.col);
                self.erase(start, start + n);
            }
            b'@' => {
                let n = self.param(0, 1).min(cols - self.col);
                let start = self.row * cols;
                // A wide character the insertion splits goes whole.
                self.mend_edges(start + self.col, start + self.col);
                self.cells.copy_within(start + self.col..start + cols - n, start + self.col + n);
                self.erase(start + self.col, start + self.col + n);
                // One pushed half off the end too.
                self.mend_edges(start + cols, start + cols);
            }
            b'P' => {
                let n = self.param(0, 1).min(cols - self.col);
                let start = self.row * cols;
                self.mend_edges(start + self.col, start + self.col + n);
                self.cells.copy_within(start + self.col + n..start + cols, start + self.col);
                self.erase(start + cols - n, start + cols);
            }
            b'L' | b'M' if (self.top..=self.bottom).contains(&self.row) => {
                let saved_top = self.top;
                self.top = self.row;
                let n = self.param(0, 1);
                if f == b'L' {
                    self.scroll_down(n)
                } else {
                    self.scroll_up(n)
                }
                self.top = saved_top;
                self.col = 0;
            }
            b'S' => self.scroll_up(self.param(0, 1)),
            b'T' => self.scroll_down(self.param(0, 1)),
            b'm' => self.sgr(),
            b'n' => match self.param(0, 0) {
                5 => self.responses.extend_from_slice(b"\x1b[0n"),
                6 => {
                    let reply = alloc::format!("\x1b[{};{}R", self.row + 1, self.col + 1);
                    self.responses.extend_from_slice(reply.as_bytes());
                }
                _ => {}
            },
            b'c' => self.responses.extend_from_slice(b"\x1b[?6c"), // VT102
            b'r' => {
                let top = self.param(0, 1) - 1;
                let bottom = self.param(1, rows as u16) - 1;
                if top < bottom && bottom < rows {
                    self.top = top;
                    self.bottom = bottom;
                    self.row = 0;
                    self.col = 0;
                }
            }
            b's' => self.saved = (self.row, self.col, self.attr),
            b'u' => (self.row, self.col, self.attr) = self.saved,
            _ => {}
        }
        self.dirty[self.row] = true;
    }

    fn alternate_screen(&mut self, on: bool) {
        match (on, self.saved_screen.is_some()) {
            (true, false) => {
                self.saved = (self.row, self.col, self.attr);
                let cells = core::mem::replace(&mut self.cells, vec![Cell::BLANK; self.rows * self.cols]);
                let wrapped = core::mem::replace(&mut self.wrapped, vec![false; self.rows]);
                self.saved_screen = Some((cells, wrapped));
            }
            (false, true) => {
                (self.cells, self.wrapped) = self.saved_screen.take().unwrap();
                (self.row, self.col, self.attr) = self.saved;
            }
            _ => return,
        }
        self.dirty.iter_mut().for_each(|d| *d = true);
    }

    fn sgr(&mut self) {
        let p = core::mem::take(&mut self.params);
        let sub = core::mem::take(&mut self.sub);
        let mut i = 0;
        while i < p.len() {
            match p[i] {
                0 => self.attr = Attr::DEFAULT,
                1 => self.attr.bold = true,
                2 => self.attr.dim = true,
                3 => self.attr.italic = true,
                4 | 21 => self.attr.underline = true,
                7 => self.attr.reverse = true,
                9 => self.attr.strike = true,
                22 => (self.attr.bold, self.attr.dim) = (false, false),
                23 => self.attr.italic = false,
                24 => self.attr.underline = false,
                27 => self.attr.reverse = false,
                29 => self.attr.strike = false,
                n @ 30..=37 => self.attr.fg = Color::Index((n - 30) as u8),
                39 => self.attr.fg = DEFAULT_FG,
                n @ 40..=47 => self.attr.bg = Color::Index((n - 40) as u8),
                49 => self.attr.bg = DEFAULT_BG,
                n @ 90..=97 => self.attr.fg = Color::Index((n - 90 + 8) as u8),
                n @ 100..=107 => self.attr.bg = Color::Index((n - 100 + 8) as u8),
                // 58 is the underline's colour: read, not shown.
                n @ (38 | 48 | 58) => {
                    let (color, used) = extended_color(&p[i + 1..], &sub[(i + 1).min(sub.len())..]);
                    i += used;
                    match (n, color) {
                        (38, Some(c)) => self.attr.fg = c,
                        (48, Some(c)) => self.attr.bg = c,
                        _ => {}
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }
}

/// An SGR 38/48 colour from the parameters after it: `5;n` (an index) or
/// `2;r;g;b` (direct), or with colons, `5:n`, `2:r:g:b` and `2::r:g:b`
/// (ITU T.416, with a colour space id). The colour, and how many
/// parameters it took.
fn extended_color(p: &[u16], sub: &[bool]) -> (Option<Color>, usize) {
    let byte = |v: u16| v.min(255) as u8;
    // Sub-parameters directly following (colon form).
    let subs = sub.iter().take_while(|&&s| s).count();
    match p.first() {
        Some(5) => (p.get(1).map(|&n| Color::Index(byte(n))), 2.min(p.len())),
        Some(2) => {
            let skip = usize::from(subs >= 5);
            match (p.get(1 + skip), p.get(2 + skip), p.get(3 + skip)) {
                (Some(&r), Some(&g), Some(&b)) => (Some(Color::Rgb(byte(r), byte(g), byte(b))), 4 + skip),
                _ => (None, p.len()),
            }
        }
        Some(_) => (None, subs),
        None => (None, 0),
    }
}

/// How many cells of `row` are left without its trailing default blanks.
fn trimmed_len(row: &[Cell]) -> usize {
    row.iter().rposition(|c| *c != Cell::BLANK).map_or(0, |i| i + 1)
}

/// Wrap a screen's lines (and the scrollback's, if kept) to a new size.
/// `screen` is the old screen's cells and wrap marks at `old` (columns,
/// rows), `cursor` its row, column and pending wrap. Returns the new
/// screen's cells, wrap marks and cursor; lines that no longer fit go to
/// the end of `history` (which the caller trims).
fn reflow(
    history: Option<&mut VecDeque<Line>>,
    screen: (Vec<Cell>, Vec<bool>),
    old: (usize, usize),
    cursor: (usize, usize, bool),
    (cols, rows): (usize, usize),
) -> (Vec<Cell>, Vec<bool>, (usize, usize, bool)) {
    let (oc, or) = old;
    let (cells, wrapped) = screen;
    // The old rows, oldest first: the scrollback's, then the screen's.
    let mut old_rows: Vec<(Vec<Cell>, bool)> = Vec::new();
    let mut history = history;
    if let Some(h) = history.as_deref_mut() {
        old_rows.extend(h.drain(..).map(|l| (l.cells, l.wrapped)));
    }
    let first_screen_row = old_rows.len();
    for r in 0..or {
        old_rows.push((cells[r * oc..(r + 1) * oc].to_vec(), wrapped[r]));
    }
    let cursor_row = first_screen_row + cursor.0;
    // Logical lines (rows joined by their wrap marks) without tails, and
    // the cursor as (line, cells before it in the line).
    let mut lines: Vec<Vec<Cell>> = Vec::new();
    let mut at = (0usize, 0usize);
    let mut line: Vec<Cell> = Vec::new();
    for (i, (row, wraps)) in old_rows.into_iter().enumerate() {
        if i == cursor_row {
            let before = row.iter().take(cursor.1).filter(|c| !c.is_tail()).count();
            at = (lines.len(), line.len() + before + usize::from(cursor.2));
        }
        if wraps {
            line.extend(row.into_iter().filter(|c| !c.is_tail()));
        } else {
            let len = trimmed_len(&row);
            line.extend(row.into_iter().take(len).filter(|c| !c.is_tail()));
            lines.push(core::mem::take(&mut line));
        }
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    // Blank lines below both the cursor and the text are dropped.
    let last_text = lines.iter().rposition(|l| !l.is_empty()).unwrap_or(0);
    lines.truncate(last_text.max(at.0) + 1);
    // Lay them out again.
    let mut out: Vec<(Vec<Cell>, bool)> = Vec::new();
    let mut new_cursor = (0usize, 0usize, false);
    for (li, l) in lines.into_iter().enumerate() {
        let mut row: Vec<Cell> = Vec::with_capacity(cols);
        for (ci, cell) in l.iter().enumerate() {
            let w = if cols >= 2 { cell.width() } else { 1 };
            if row.len() + w > cols {
                // A wide character that doesn't fit leaves an empty tail.
                while row.len() < cols {
                    row.push(Cell { ch: Cell::TAIL, ..Cell::BLANK });
                }
                out.push((core::mem::take(&mut row), true));
            }
            if (li, ci) == at {
                new_cursor = (out.len(), row.len(), false);
            }
            row.push(*cell);
            if w == 2 {
                row.push(Cell { ch: Cell::TAIL, ..*cell });
            }
        }
        if li == at.0 && at.1 >= l.len() {
            // The cursor is past the line's text.
            let (r, c) = (out.len(), row.len() + (at.1 - l.len()));
            new_cursor = if c >= cols { (r, cols - 1, c == cols && !l.is_empty()) } else { (r, c, false) };
        }
        out.push((row, false));
    }
    // The bottom of the text in view, and the cursor.
    let mut top = out.len().saturating_sub(rows);
    if new_cursor.0 < top {
        top = new_cursor.0;
    }
    let mut new_cells = vec![Cell::BLANK; cols * rows];
    let mut new_wrapped = vec![false; rows];
    for (i, (row, wraps)) in out.iter().skip(top).take(rows).enumerate() {
        new_cells[i * cols..i * cols + row.len()].copy_from_slice(row);
        new_wrapped[i] = *wraps;
    }
    if let Some(h) = history {
        for (row, wraps) in out.into_iter().take(top) {
            let len = if wraps { row.len() } else { trimmed_len(&row) };
            let mut cells = row;
            cells.truncate(len);
            h.push_back(Line { cells, wrapped: wraps });
        }
    }
    (new_cells, new_wrapped, (new_cursor.0 - top, new_cursor.1, new_cursor.2))
}

/// RGB of a palette index. 0-15 are Slate's console palette; 16-231 the
/// xterm 6x6x6 color cube; 232-255 a 24-step gray ramp.
pub fn rgb(c: u8) -> (u8, u8, u8) {
    const BASE: [(u8, u8, u8); 16] = [
        (0x16, 0x18, 0x1D), // black (the background: a dark slate)
        (0xCC, 0x44, 0x44),
        (0x5F, 0xB3, 0x5F),
        (0xD7, 0xAF, 0x5F),
        (0x55, 0x88, 0xCC),
        (0xAF, 0x77, 0xCC),
        (0x4E, 0xB0, 0xB0),
        (0xC8, 0xCC, 0xD2), // white (the default text)
        (0x5A, 0x5F, 0x68),
        (0xFF, 0x6B, 0x6B),
        (0x8A, 0xE2, 0x8A),
        (0xFF, 0xD8, 0x7A),
        (0x7F, 0xB2, 0xFF),
        (0xD8, 0x9C, 0xFF),
        (0x7A, 0xE6, 0xE6),
        (0xFF, 0xFF, 0xFF),
    ];
    match c {
        0..=15 => BASE[c as usize],
        16..=231 => {
            let v = c - 16;
            let level = |x: u8| if x == 0 { 0 } else { 55 + x * 40 };
            (level(v / 36), level(v / 6 % 6), level(v % 6))
        }
        _ => {
            let g = 8 + (c - 232) * 10;
            (g, g, g)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn term() -> Term {
        Term::new(20, 5)
    }

    #[test]
    fn prints_and_wraps() {
        let mut t = term();
        t.feed(b"hello\r\nworld");
        assert_eq!(t.row_text(0), "hello");
        assert_eq!(t.row_text(1), "world");
        assert_eq!(t.cursor(), (1, 5));
        t.feed(b"\r\n0123456789012345678901");
        assert_eq!(t.row_text(2), "01234567890123456789");
        assert_eq!(t.row_text(3), "01");
    }

    #[test]
    fn scrolls_at_bottom() {
        let mut t = term();
        t.feed(b"1\n2\n3\n4\n5\n6");
        // LF alone moves down without returning; the tty adds CR.
        assert_eq!(t.row_text(0), " 2");
        assert_eq!(t.cell(4, 5).ch, '6');
    }

    #[test]
    fn cursor_movement_and_erase() {
        let mut t = term();
        t.feed(b"abcdef\x1b[3D\x1b[K");
        assert_eq!(t.row_text(0), "abc");
        t.feed(b"\x1b[3;4HX");
        assert_eq!(t.cell(2, 3).ch, 'X');
        t.feed(b"\x1b[2J");
        assert!((0..5).all(|r| t.row_text(r).is_empty()));
    }

    #[test]
    fn insert_delete_chars() {
        let mut t = term();
        t.feed(b"abcdef\r\x1b[2C\x1b[2@XY");
        assert_eq!(t.row_text(0), "abXYcdef");
        t.feed(b"\r\x1b[3P");
        assert_eq!(t.row_text(0), "Ycdef");
    }

    #[test]
    fn colors_and_attributes() {
        let mut t = term();
        t.feed(b"\x1b[1;31mR\x1b[0mN\x1b[38;5;196mX\x1b[44mB");
        assert_eq!(t.cell(0, 0).attr.fg, Color::Index(1));
        assert!(t.cell(0, 0).attr.bold);
        assert_eq!(t.cell(0, 0).attr.resolved().0, Color::Index(9));
        assert_eq!(t.cell(0, 1).attr, Attr::DEFAULT);
        assert_eq!(t.cell(0, 2).attr.fg, Color::Index(196));
        assert_eq!(t.cell(0, 3).attr.bg, Color::Index(4));
    }

    #[test]
    fn direct_colours_and_more_attributes() {
        let mut t = term();
        // Semicolons, colons, colons with a colour space; then 256 by colon.
        t.feed(b"\x1b[38;2;1;2;3mA\x1b[48:2:4:5:6mB\x1b[38:2::7:8:9mC\x1b[38:5:33;1mD");
        assert_eq!(t.cell(0, 0).attr.fg, Color::Rgb(1, 2, 3));
        assert_eq!(t.cell(0, 1).attr.bg, Color::Rgb(4, 5, 6));
        assert_eq!(t.cell(0, 2).attr.fg, Color::Rgb(7, 8, 9));
        assert_eq!(t.cell(0, 3).attr.fg, Color::Index(33));
        assert!(t.cell(0, 3).attr.bold);
        // Bold doesn't brighten a direct colour.
        t.feed(b"\x1b[0;1;38;2;10;20;30mE");
        assert_eq!(t.cell(0, 4).attr.resolved().0, Color::Rgb(10, 20, 30));
        // An underline colour is read and skipped.
        t.feed(b"\x1b[0;58;2;1;1;1;3mF\x1b[2;9mG\x1b[22;23;29mH");
        let (f, g, h) = (t.cell(0, 5).attr, t.cell(0, 6).attr, t.cell(0, 7).attr);
        assert!(f.italic && !f.bold && !f.underline);
        assert!(g.dim && g.strike && g.italic);
        assert!(!h.dim && !h.strike && !h.italic);
        // Values over 255 are clamped.
        t.feed(b"\x1b[38;2;300;0;0mI");
        assert_eq!(t.cell(0, 8).attr.fg, Color::Rgb(255, 0, 0));
    }

    #[test]
    fn wide_characters_and_marks() {
        let mut t = Term::new(5, 3);
        t.feed("中a".as_bytes());
        assert_eq!(t.cell(0, 0).ch, '中');
        assert!(t.cell(0, 1).is_tail());
        assert_eq!(t.cursor(), (0, 3));
        assert_eq!(t.row_text(0), "中a");
        // At column 4 a wide character doesn't fit: it goes to the next row.
        t.feed("b文".as_bytes());
        assert!(t.cell(0, 4).is_tail());
        assert_eq!(t.cell(1, 0).ch, '文');
        assert_eq!(t.row_text(0), "中ab");
        // Writing over half of one blanks the other half.
        t.feed(b"\x1b[1;2Hx");
        assert_eq!((t.cell(0, 0).ch, t.cell(0, 1).ch), (' ', 'x'));
        // A combining mark joins the character before it.
        t.feed("\x1b[3;1He\u{301}".as_bytes());
        assert_eq!((t.cell(2, 0).ch, t.extras(&t.cell(2, 0))), ('e', &['\u{301}'][..]));
        assert_eq!(t.cursor(), (2, 1));
        assert_eq!(t.row_text(2), "e\u{301}");
    }

    /// Erasing, inserting or deleting over half a wide character takes
    /// the other half too: no half is left behind.
    #[test]
    fn wide_characters_go_whole() {
        // 中 (U+4E2D) is two columns wide.
        let row = |t: &Term| t.row_text(0);
        let mut t = Term::new(6, 2);
        t.feed("ab中cd".as_bytes());
        // ECH on its right half (column 3).
        t.feed(b"\x1b[1;4H\x1b[X");
        assert_eq!((row(&t).as_str(), t.cell(0, 2).ch, t.cell(0, 3).is_tail()), ("ab  cd", ' ', false));
        t.feed("\x1b[1;1H\x1b[2Kab中cd".as_bytes());
        // ECH on its left half (column 2).
        t.feed(b"\x1b[1;3H\x1b[X");
        assert_eq!((t.cell(0, 2).ch, t.cell(0, 3).is_tail()), (' ', false));
        // ICH in its middle splits nothing apart: it goes.
        t.feed("\x1b[1;1H\x1b[2Kab中cd\x1b[1;4H\x1b[@".as_bytes());
        assert!((0..6).all(|c| !t.cell(0, c).is_tail()), "{:?}", row(&t));
        // DCH of its left half takes the right one.
        t.feed("\x1b[1;1H\x1b[2Kab中cd\x1b[1;3H\x1b[P".as_bytes());
        assert!((0..6).all(|c| !t.cell(0, c).is_tail()), "{:?}", row(&t));
        // ICH pushing it to the row's end leaves no head without a tail.
        t.feed("\x1b[1;1H\x1b[2Kabc中\x1b[1;1H\x1b[@".as_bytes());
        let last = t.cell(0, 5);
        assert!(last.is_tail() || last.width() == 1, "{:?}", row(&t));
    }

    /// Several combining marks stay on their character, shared through the
    /// table.
    #[test]
    fn combining_marks_stack() {
        let mut t = term();
        t.feed("a\u{301}\u{323}\u{308}\u{30a}b e\u{301}".as_bytes());
        assert_eq!(t.extras(&t.cell(0, 0)), ['\u{301}', '\u{323}', '\u{308}', '\u{30a}']);
        assert_eq!(t.row_text(0), "a\u{301}\u{323}\u{308}\u{30a}b e\u{301}");
        assert_eq!(t.cell(0, 3).ext, t.intern(alloc::vec!['\u{301}']), "the same list, the same entry");
        // Past the most a cell keeps, more are dropped.
        let many: alloc::string::String = core::iter::once('x').chain(core::iter::repeat_n('\u{301}', 40)).collect();
        t.feed(many.as_bytes());
        assert_eq!(t.extras(&t.cell(0, 4)).len(), CLUSTER_MAX);
    }

    /// Mode 2027 (DECSET, DECRQM): clusters take one cell, two for an
    /// emoji presentation; without it each character has its own.
    #[test]
    fn grapheme_clusters() {
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}";
        let mut t = term();
        t.feed(family.as_bytes());
        assert_eq!(t.cursor().1, 6, "three people, two cells each");
        let mut t = term();
        t.feed(b"\x1b[?2027$p");
        assert_eq!(t.take_responses(), b"\x1b[?2027;2$y");
        t.feed(b"\x1b[?2027h\x1b[?2027$p");
        assert_eq!(t.take_responses(), b"\x1b[?2027;1$y");
        t.feed(family.as_bytes());
        assert_eq!(t.cursor().1, 2, "one cluster");
        assert_eq!(t.row_text(0), family);
        // A thumbs up with a skin tone; a flag; a heart made emoji by VS16.
        t.feed("\u{1F44D}\u{1F3FD}\u{1F1EB}\u{1F1F7}\u{2764}\u{FE0F}x".as_bytes());
        assert_eq!(t.cursor().1, 9);
        assert_eq!(t.extras(&t.cell(0, 2)), ['\u{1F3FD}']);
        assert!(t.cell(0, 4).wide && t.cell(0, 5).is_tail(), "the flag is two cells");
        assert!(t.cell(0, 6).wide && t.cell(0, 7).is_tail(), "and the emoji heart");
        assert_eq!(t.cell(0, 8).ch, 'x');
        // Two flags in a row stay two flags.
        let mut t = term();
        t.feed("\x1b[?2027h\u{1F1EB}\u{1F1F7}\u{1F1E9}\u{1F1EA}".as_bytes());
        assert_eq!(t.cursor().1, 4);
        // An unknown mode reports 0.
        t.feed(b"\x1b[?4242$p");
        assert_eq!(t.take_responses(), b"\x1b[?4242;0$y");
    }

    #[test]
    fn mouse_modes() {
        let mut t = term();
        assert_eq!(t.mouse, MouseMode::Off);
        t.feed(b"\x1b[?1000h\x1b[?1006h");
        assert_eq!((t.mouse, t.mouse_encoding), (MouseMode::Click, MouseEncoding::Sgr));
        t.feed(b"\x1b[?1002h");
        assert_eq!(t.mouse, MouseMode::Drag);
        // Turning off another mode leaves this one.
        t.feed(b"\x1b[?1000l");
        assert_eq!(t.mouse, MouseMode::Drag);
        t.feed(b"\x1b[?1002l\x1b[?1003;1006h");
        assert_eq!(t.mouse, MouseMode::Motion);
        t.feed(b"\x1bc");
        assert_eq!((t.mouse, t.mouse_encoding), (MouseMode::Off, MouseEncoding::X10));
        t.feed(b"\x1b[?9h");
        assert_eq!(t.mouse, MouseMode::Press);
        // The last encoding set wins; resetting another leaves it.
        t.feed(b"\x1b[?1005h\x1b[?1015h\x1b[?1005l");
        assert_eq!(t.mouse_encoding, MouseEncoding::Urxvt);
        t.feed(b"\x1b[?1015l");
        assert_eq!(t.mouse_encoding, MouseEncoding::X10);
    }

    fn lines(t: &Term) -> alloc::vec::Vec<(alloc::string::String, bool)> {
        (0..t.history_len() + t.rows())
            .map(|i| t.line(i).map(|(c, w)| (text(c).trim_end().into(), w)).unwrap())
            .collect()
    }

    #[test]
    fn reflow_on_resize() {
        let mut t = Term::new(10, 4);
        t.set_scrollback(100);
        t.feed(b"0123456789abcde\r\n$ ");
        // The long line wrapped into two rows.
        assert_eq!(t.row_text(0), "0123456789");
        assert_eq!(t.cursor(), (2, 2));
        // Wider: one row again, the cursor follows its prompt.
        t.resize(20, 4);
        assert_eq!(t.row_text(0), "0123456789abcde");
        assert_eq!(t.row_text(1), "$");
        assert_eq!(t.cursor(), (1, 2));
        // Narrower: three rows; the text and the cursor stay in view.
        t.resize(5, 4);
        assert_eq!(
            lines(&t),
            [("01234".into(), true), ("56789".into(), true), ("abcde".into(), false), ("$".into(), false)]
        );
        assert_eq!(t.cursor(), (3, 2));
        // Shorter: the top goes to the scrollback, and comes back.
        t.resize(5, 2);
        assert_eq!(t.history_len(), 2);
        assert_eq!(t.row_text(1), "$");
        t.resize(15, 4);
        assert_eq!(t.history_len(), 0);
        assert_eq!(t.row_text(0), "0123456789abcde");
        assert_eq!(t.cursor(), (1, 2));
    }

    #[test]
    fn reflow_keeps_blanks_wide_characters_and_the_pending_wrap() {
        let mut t = Term::new(4, 3);
        t.set_scrollback(10);
        // "ab  cd": the blanks at the wrap are text.
        t.feed(b"ab  cd");
        t.resize(8, 3);
        assert_eq!(t.row_text(0), "ab  cd");
        // A wide character at the edge moves down whole, and back.
        let mut t = Term::new(5, 3);
        t.set_scrollback(10);
        t.feed("abcd中".as_bytes());
        assert!(t.cell(0, 4).is_tail());
        t.resize(6, 3);
        assert_eq!(t.row_text(0), "abcd中");
        assert_eq!(t.cursor(), (0, 5));
        // The cursor after the last column (a pending wrap) stays there.
        let mut t = Term::new(4, 3);
        t.feed(b"abcd");
        t.resize(2, 3);
        assert_eq!((t.row_text(0).as_str(), t.row_text(1).as_str()), ("ab", "cd"));
        assert_eq!(t.cursor(), (1, 1));
        t.feed(b"e");
        assert_eq!(t.row_text(2), "e");
    }

    #[test]
    fn resizing_the_alternate_screen() {
        let mut t = Term::new(10, 3);
        t.set_scrollback(10);
        t.feed(b"0123456789xy\x1b[?1049hfull");
        t.resize(20, 3);
        // The alternate screen is cut or padded; the main one reflows.
        assert_eq!(t.row_text(1), "  full");
        t.feed(b"\x1b[?1049l");
        assert_eq!(t.row_text(0), "0123456789xy");
        assert_eq!(t.cursor(), (0, 12));
    }

    #[test]
    fn cursor_position_report() {
        let mut t = term();
        t.feed(b"\x1b[2;7H\x1b[6n");
        assert_eq!(t.take_responses(), b"\x1b[2;7R");
        assert!(t.take_responses().is_empty());
    }

    #[test]
    fn utf8_and_osc() {
        let mut t = term();
        t.feed("é\x1b]0;title\x07x".as_bytes());
        assert_eq!(t.cell(0, 0).ch, 'é');
        assert_eq!(t.cell(0, 1).ch, 'x');
    }

    #[test]
    fn scroll_region_and_alternate_screen() {
        let mut t = term();
        t.feed(b"top\r\n\x1b[2;4r\x1b[4;1Ha\nb\nc");
        assert_eq!(t.row_text(0), "top");
        t.feed(b"\x1b[?1049h");
        assert!(t.row_text(0).is_empty());
        t.feed(b"\x1b[?1049l");
        assert_eq!(t.row_text(0), "top");
    }

    #[test]
    fn dirty_rows() {
        let mut t = term();
        t.take_dirty();
        t.feed(b"\x1b[3;1Hx");
        assert_eq!(t.take_dirty(), [2]);
    }

    #[test]
    fn palette() {
        assert_eq!(rgb(16), (0, 0, 0));
        assert_eq!(rgb(231), (255, 255, 255));
    }

    #[test]
    fn resizing_and_cursor_keys() {
        let mut t = Term::new(10, 4);
        t.feed(b"hello\r\nworld\x1b[?1h");
        assert!(t.app_cursor);
        // Without a scrollback, rows that leave the top are gone.
        t.resize(3, 2);
        assert_eq!((t.row_text(0).as_str(), t.row_text(1).as_str()), ("wor", "ld"));
        assert_eq!(t.cursor(), (1, 2));
        t.resize(20, 5);
        assert_eq!(t.row_text(0), "world");
        assert_eq!((t.cols(), t.rows()), (20, 5));
        t.feed(b"\x1b[?1l");
        assert!(!t.app_cursor);
    }

    fn text(cells: &[Cell]) -> alloc::string::String {
        cells.iter().map(|c| c.ch).collect()
    }

    #[test]
    fn scrollback() {
        let mut t = Term::new(4, 2);
        t.feed(b"one\r\ntwo\r\nthree!\r\n");
        // Nothing kept by default.
        assert_eq!(t.history_len(), 0);
        let mut t = Term::new(4, 2);
        t.set_scrollback(3);
        t.feed(b"one\r\ntwo\r\nthree!\r\nx");
        // "three!" wrapped: "thre" + "e!"; "one", "two", "thre" scrolled off.
        assert_eq!(t.history_len(), 3);
        let lines: alloc::vec::Vec<_> = (0..5).map(|i| t.line(i).map(|(c, w)| (text(c), w))).collect();
        assert_eq!(lines[0], Some(("one".into(), false)));
        assert_eq!(lines[2], Some(("thre".into(), true)));
        assert_eq!(lines[3], Some(("e!  ".into(), false)));
        assert_eq!(lines[4], Some(("x   ".into(), false)));
        assert_eq!(t.line(5), None);
        // The oldest line goes when the limit is reached.
        t.feed(b"\r\nmore\r\n");
        assert_eq!((t.history_len(), t.dropped()), (3, 2));
        assert_eq!(t.line(0).map(|l| text(l.0)), Some("thre".into()));
        // The alternate screen and scrolling regions keep nothing.
        t.feed(b"\x1b[?1049h1\r\n2\r\n3\r\n\x1b[?1049l");
        assert!(!t.alternate());
        assert_eq!(t.dropped(), 2);
        // ED 3 clears it; a reset keeps it.
        t.feed(b"a\r\nb\r\n\x1bc");
        assert_eq!(t.history_len(), 3);
        t.feed(b"\x1b[3J");
        assert_eq!((t.history_len(), t.dropped()), (0, 7));
        t.feed(b"\x1b[?2004h");
        assert!(t.bracketed_paste);
    }
}
