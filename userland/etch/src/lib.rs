// SPDX-License-Identifier: MIT OR Apache-2.0

//! etch, Slate's text editor, in the manner of nano and pico: a title
//! bar, the text, a status line and the shortcut list; Ctrl keys for
//! commands (^O write, ^X exit, ^W search, ^\ replace, ^K/^U cut and
//! paste, ^_ go to line, ^J justify, ^T run a command), Alt-U/Alt-E undo
//! and redo. Several files open at once (Alt-< and Alt-> between them),
//! syntax colours for the common kinds of file, backups (-B), the mouse
//! (-m), and settings in ~/.config/etch/etchrc. Only the rows that change
//! are redrawn.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod buffer;
pub mod syntax;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use buffer::{Buffer, Pos};
use slate_regex::{Options, Regex};
use slate_rt::{fs, io, lossy, process, signal, term};
use slate_tui::{Key, Term, char_width};
use syntax::Syntax;

const VERSION: &str = "0.2";
const TAB: usize = 8;
/// Block comments are looked for this far above the screen's top line.
const BLOCK_LOOKBACK: usize = 2000;

const HELP: &str = "etch help

etch is a small editor in the manner of nano. Type to insert text; the
arrow keys, Home, End, PageUp and PageDown move. Commands (^ is Ctrl,
M- is Alt or Esc):

  ^G  this help            ^X  close the file (asks to save changes)
  ^O  write the file       ^R  insert a file (M-F: into a new buffer)
  ^W  search               M-W search again
  ^\\  search and replace   ^_  go to line (and column)
  ^K  cut the line         ^U  paste what was cut
  ^J  justify the paragraph ^T run a command, its output inserted
  ^C  show the position    ^L  redraw the screen
  ^A  start of line        ^E  end of line
  ^Y  page up              ^V  page down
  ^D  delete forward       ^Z  suspend
  M-U undo                 M-E redo
  M-< previous file        M-> next file
  M-N line numbers on/off  M-I auto-indent on/off
  M-Y syntax colours on/off

In the search prompt, M-C toggles case sensitivity and M-R regular
expressions (POSIX extended). Settings: ~/.config/etch/etchrc (set or
unset linenumbers, autoindent, backup, mouse, syntax; set fill N).

Press any key to return.";

/// The display column after the bytes `line[..col]`.
pub fn display_col(line: &[u8], col: usize) -> usize {
    let s = String::from_utf8_lossy(&line[..col.min(line.len())]);
    let mut x = 0;
    for c in s.chars() {
        x = if c == '\t' { (x / TAB + 1) * TAB } else { x + char_width(c) };
    }
    x
}

/// The byte offset in `line` closest to display column `x`.
pub fn col_for(line: &[u8], x: usize) -> usize {
    let mut cx = 0;
    let mut i = 0;
    while i < line.len() {
        let len = match line[i] {
            0xC0..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF7 => 4,
            _ => 1,
        }
        .min(line.len() - i);
        let c = String::from_utf8_lossy(&line[i..i + len]).chars().next().unwrap_or('?');
        let next = if c == '\t' { (cx / TAB + 1) * TAB } else { cx + char_width(c) };
        if next > x {
            break;
        }
        cx = next;
        i += len;
    }
    i
}

/// The paragraph's words in lines of at most `width` columns: the first
/// line keeps its indentation, the others take the second line's (or the
/// first's). Long words get a line of their own.
pub fn justify(lines: &[Vec<u8>], width: usize) -> Vec<Vec<u8>> {
    let indent = |l: &[u8]| l.iter().take_while(|c| **c == b' ' || **c == b'\t').count();
    let Some(first) = lines.first() else { return Vec::new() };
    let lead = first[..indent(first)].to_vec();
    let rest = lines.get(1).map_or(lead.clone(), |l| l[..indent(l)].to_vec());
    let words: Vec<&[u8]> =
        lines.iter().flat_map(|l| l.split(|c| c.is_ascii_whitespace())).filter(|w| !w.is_empty()).collect();
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut cur = lead.clone();
    let mut empty = true;
    for w in words {
        let len = display_col(&cur, cur.len()) + usize::from(!empty) + display_col(w, w.len());
        if !empty && len > width {
            out.push(core::mem::replace(&mut cur, rest.clone()));
            empty = true;
        }
        if !empty {
            cur.push(b' ');
        }
        cur.extend_from_slice(w);
        empty = false;
    }
    if !empty || out.is_empty() {
        out.push(cur);
    }
    out
}

/// What the settings file and the command line set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub line_numbers: bool,
    pub autoindent: bool,
    pub backup: bool,
    pub mouse: bool,
    pub syntax: bool,
    /// The justify width: columns, or (negative) that many fewer than the
    /// screen's.
    pub fill: i32,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings { line_numbers: false, autoindent: false, backup: false, mouse: false, syntax: true, fill: -8 }
    }
}

impl Settings {
    /// Read an etchrc (`set NAME [VALUE]`, `unset NAME`, `#` comments);
    /// the problems, by line.
    pub fn read(&mut self, text: &str) -> Vec<String> {
        let mut problems = Vec::new();
        for (n, line) in text.lines().enumerate() {
            let words: Vec<&str> = line.split('#').next().unwrap_or("").split_whitespace().collect();
            let ok = match words.as_slice() {
                [] => true,
                ["set", "fill", v] => match v.parse::<i32>() {
                    Ok(f) if f != 0 => {
                        self.fill = f;
                        true
                    }
                    _ => false,
                },
                [op @ ("set" | "unset"), name] => {
                    let on = *op == "set";
                    match *name {
                        "linenumbers" => self.line_numbers = on,
                        "autoindent" => self.autoindent = on,
                        "backup" => self.backup = on,
                        "mouse" => self.mouse = on,
                        "syntax" => self.syntax = on,
                        "nosyntax" => self.syntax = !on,
                        _ => {}
                    }
                    matches!(*name, "linenumbers" | "autoindent" | "backup" | "mouse" | "syntax" | "nosyntax")
                }
                _ => false,
            };
            if !ok {
                problems.push(alloc::format!("line {}: {}", n + 1, line.trim()));
            }
        }
        problems
    }
}

/// What a prompt gave.
enum Answer {
    Text(Vec<u8>),
    Cancel,
    /// One of the keys the caller handles (option toggles).
    Toggle(char),
}

/// A file open in a buffer other than the one shown, with where one was.
#[derive(Debug)]
struct Doc {
    buf: Buffer,
    path: Option<Vec<u8>>,
    cur: Pos,
    want_x: usize,
    top: usize,
    left: usize,
    syntax: Option<&'static Syntax>,
}

#[derive(Debug)]
pub struct Editor {
    buf: Buffer,
    path: Option<Vec<u8>>,
    cur: Pos,
    /// The display column vertical moves try to keep.
    want_x: usize,
    top: usize,
    left: usize,
    syntax: Option<&'static Syntax>,
    /// The other open files, the next first; and where this one is among
    /// all of them (from 0).
    others: VecDeque<Doc>,
    index: usize,
    message: Option<String>,
    cut: Vec<u8>,
    last_cut: bool,
    search: Option<Vec<u8>>,
    case_sensitive: bool,
    regex: bool,
    settings: Settings,
    view_only: bool,
    term: Term,
    /// The rows as last drawn (`None`: unknown), to redraw only changes.
    shown: Vec<Option<Vec<u8>>>,
}

impl Editor {
    fn text_rows(&self) -> usize {
        self.term.rows.saturating_sub(4).max(1)
    }

    fn gutter(&self) -> usize {
        if self.settings.line_numbers { alloc::format!("{}", self.buf.lines.len()).len() + 1 } else { 0 }
    }

    fn text_cols(&self) -> usize {
        self.term.cols.saturating_sub(self.gutter()).max(1)
    }

    fn msg(&mut self, m: impl Into<String>) {
        self.message = Some(m.into());
    }

    /// Forget what the screen shows (it was cleared or written over).
    fn invalidate(&mut self) {
        self.shown.clear();
    }

    // --- buffers -----------------------------------------------------------------

    fn files(&self) -> usize {
        self.others.len() + 1
    }

    fn take_doc(&mut self) -> Doc {
        Doc {
            buf: core::mem::replace(&mut self.buf, Buffer::from_bytes(b"")),
            path: self.path.take(),
            cur: self.cur,
            want_x: self.want_x,
            top: self.top,
            left: self.left,
            syntax: self.syntax,
        }
    }

    fn put_doc(&mut self, d: Doc) {
        self.buf = d.buf;
        self.path = d.path;
        self.cur = d.cur;
        self.want_x = d.want_x;
        self.top = d.top;
        self.left = d.left;
        self.syntax = d.syntax;
    }

    fn switched(&mut self) {
        let name = self.path.as_ref().map_or(String::from("New Buffer"), |p| String::from(lossy(p)));
        self.msg(alloc::format!("Switched to {name}"));
    }

    /// The next file (or the one before).
    fn switch(&mut self, forward: bool) {
        if self.others.is_empty() {
            self.msg("No more open file buffers");
            return;
        }
        let here = self.take_doc();
        let n = self.files();
        if forward {
            self.others.push_back(here);
            let d = self.others.pop_front().unwrap_or_else(|| unreachable!());
            self.put_doc(d);
            self.index = (self.index + 1) % n;
        } else {
            self.others.push_front(here);
            let d = self.others.pop_back().unwrap_or_else(|| unreachable!());
            self.put_doc(d);
            self.index = (self.index + n - 1) % n;
        }
        self.switched();
    }

    /// Close this file and show the next; false if it was the last.
    fn close(&mut self) -> bool {
        let Some(d) = self.others.pop_front() else { return false };
        self.put_doc(d);
        if self.index == self.files() {
            self.index = 0;
        }
        self.switched();
        true
    }

    // --- drawing ------------------------------------------------------------

    /// Show `row` as `bytes` (with its own colours and attributes), unless
    /// it already is.
    fn row(&mut self, row: usize, bytes: Vec<u8>) {
        if self.shown.len() <= row {
            self.shown.resize(row + 1, None);
        }
        if self.shown[row].as_ref() == Some(&bytes) {
            return;
        }
        let t = &mut self.term;
        t.goto(row, 0);
        t.put(&bytes);
        t.put(b"\x1b[0m");
        t.clear_eol();
        self.shown[row] = Some(bytes);
    }

    /// The colours of the lines from `top` on that are shown, or none.
    fn colors(&self, rows: usize) -> Vec<Vec<Option<u8>>> {
        let Some(s) = self.syntax.filter(|_| self.settings.syntax) else { return Vec::new() };
        let lines = &self.buf.lines;
        let mut open = false;
        for l in &lines[self.top.saturating_sub(BLOCK_LOOKBACK)..self.top.min(lines.len())] {
            open = s.block_after(l, open);
        }
        let mut out = Vec::new();
        for l in lines.iter().skip(self.top).take(rows) {
            out.push(s.colors(l, open));
            open = s.block_after(l, open);
        }
        out
    }

    fn draw(&mut self) {
        let rows = self.text_rows();
        if self.cur.line < self.top {
            self.top = self.cur.line;
        }
        if self.cur.line >= self.top + rows {
            self.top = self.cur.line + 1 - rows;
        }
        let cx = display_col(&self.buf.lines[self.cur.line], self.cur.col);
        let cols = self.text_cols();
        if cx < self.left {
            self.left = cx.saturating_sub(cols / 2);
        }
        if cx >= self.left + cols {
            self.left = cx + 1 - cols + cols / 4;
        }
        let width = self.term.cols;
        self.term.cursor(false);
        // Title bar.
        let name = self.path.as_ref().map_or(String::from("New Buffer"), |p| alloc::format!("File: {}", lossy(p)));
        let name = if self.files() > 1 { alloc::format!("{name} [{}/{}]", self.index + 1, self.files()) } else { name };
        let state = if self.view_only {
            "View"
        } else if self.buf.modified() {
            "Modified"
        } else {
            ""
        };
        let left = alloc::format!("  etch {VERSION}");
        let mut bar = Vec::with_capacity(width + 8);
        bar.extend_from_slice(b"\x1b[7m");
        let mut text = Vec::with_capacity(width);
        text.extend_from_slice(left.as_bytes());
        let mid = width.saturating_sub(name.len()) / 2;
        while text.len() < mid {
            text.push(b' ');
        }
        text.extend_from_slice(name.as_bytes());
        let right_at = width.saturating_sub(state.len() + 2);
        while text.len() < right_at {
            text.push(b' ');
        }
        text.extend_from_slice(state.as_bytes());
        text.resize(width, b' ');
        text.truncate(width);
        bar.extend_from_slice(&text);
        self.row(0, bar);
        // The text.
        let gutter = self.gutter();
        let colors = self.colors(rows);
        for r in 0..rows {
            let n = self.top + r;
            let mut out = Vec::new();
            if let Some(line) = self.buf.lines.get(n) {
                if gutter > 0 {
                    out.extend_from_slice(alloc::format!("{:>w$} ", n + 1, w = gutter - 1).as_bytes());
                }
                let colors = colors.get(r);
                let mut x = 0;
                let mut at = 0;
                let mut color: Option<u8> = None;
                for c in String::from_utf8_lossy(line).chars() {
                    let len = if c == char::REPLACEMENT_CHARACTER { 1 } else { c.len_utf8() };
                    let want = colors.and_then(|cs| cs.get(at).copied().flatten());
                    at += len;
                    let (shown, w): (Vec<u8>, usize) = if c == '\t' {
                        let w = (x / TAB + 1) * TAB - x;
                        (alloc::vec![b' '; w], w)
                    } else if (c as u32) < 0x20 || c == '\u{7f}' {
                        (alloc::vec![b'^', ((c as u8) ^ 0x40)], 2)
                    } else {
                        let mut b = [0u8; 4];
                        (c.encode_utf8(&mut b).as_bytes().to_vec(), char_width(c))
                    };
                    if x + w > self.left && x < self.left + cols {
                        if want != color {
                            match want {
                                Some(k) => out.extend_from_slice(alloc::format!("\x1b[{}m", 30 + k).as_bytes()),
                                None => out.extend_from_slice(b"\x1b[39m"),
                            }
                            color = want;
                        }
                        // A wide character cut by an edge shows as blanks.
                        if x < self.left {
                            out.resize(out.len() + (x + w - self.left), b' ');
                        } else if x + w > self.left + cols {
                            out.resize(out.len() + (self.left + cols - x), b' ');
                        } else {
                            out.extend_from_slice(&shown);
                        }
                    }
                    x += w;
                    if x >= self.left + cols {
                        break;
                    }
                }
            }
            self.row(1 + r, out);
        }
        // Status line.
        let mut status = Vec::new();
        if let Some(m) = self.message.take() {
            let m = alloc::format!("[ {m} ]");
            let pad = width.saturating_sub(m.len()) / 2;
            status.resize(pad, b' ');
            status.extend_from_slice(b"\x1b[7m");
            status.extend_from_slice(m.as_bytes());
        }
        self.row(rows + 1, status);
        // Shortcuts.
        let rows_help: [&[(&str, &str)]; 2] = [
            &[
                ("^G", "Help"),
                ("^O", "Write Out"),
                ("^W", "Where Is"),
                ("^K", "Cut"),
                ("^T", "Execute"),
                ("^C", "Location"),
            ],
            &[
                ("^X", "Exit"),
                ("^R", "Read File"),
                ("^\\", "Replace"),
                ("^U", "Paste"),
                ("^J", "Justify"),
                ("^_", "Go To Line"),
            ],
        ];
        for (i, items) in rows_help.iter().enumerate() {
            let slot = width / items.len();
            let mut out = Vec::new();
            for (k, label) in items.iter() {
                out.extend_from_slice(b"\x1b[7m");
                out.extend_from_slice(k.as_bytes());
                out.extend_from_slice(b"\x1b[0m");
                let mut l = alloc::format!(" {label}");
                let room = slot.saturating_sub(k.len());
                l.truncate(room);
                while l.len() < room {
                    l.push(' ');
                }
                out.extend_from_slice(l.as_bytes());
            }
            self.row(rows + 2 + i, out);
        }
        let row = 1 + self.cur.line - self.top;
        let col = gutter + cx - self.left;
        let t = &mut self.term;
        t.goto(row, col.min(width - 1));
        t.cursor(true);
        t.flush();
    }

    // --- prompts ----------------------------------------------------------------

    /// A one-line prompt on the status line.
    fn prompt(&mut self, label: &str, initial: &[u8], toggles: &[char]) -> Answer {
        let a = self.prompt_inner(label, initial, toggles);
        // The status line was written over.
        let row = self.text_rows() + 1;
        if let Some(r) = self.shown.get_mut(row) {
            *r = None;
        }
        a
    }

    fn prompt_inner(&mut self, label: &str, initial: &[u8], toggles: &[char]) -> Answer {
        let mut text = initial.to_vec();
        let mut pos = text.len();
        loop {
            let rows = self.text_rows();
            let t = &mut self.term;
            t.goto(rows + 1, 0);
            t.reverse(true);
            let mut line = Vec::from(label.as_bytes());
            line.extend_from_slice(&text);
            let width = t.cols;
            let shown_from = line.len().saturating_sub(width - 1);
            let mut padded = line[shown_from..].to_vec();
            padded.resize(width, b' ');
            t.put(&padded);
            t.reverse(false);
            let cursor = (label.len() + display_col(&text, pos)).saturating_sub(shown_from).min(width - 1);
            t.goto(rows + 1, cursor);
            t.flush();
            match t.key(None) {
                Some(Key::Enter | Key::Ctrl(b'j')) => return Answer::Text(text),
                Some(Key::Ctrl(b'c') | Key::Esc) | Some(Key::Eof) | None => return Answer::Cancel,
                Some(Key::Alt(c)) if toggles.contains(&c) => return Answer::Toggle(c),
                Some(Key::Backspace) => {
                    if pos > 0 {
                        let mut p = pos - 1;
                        while p > 0 && !buffer::is_start(text[p]) {
                            p -= 1;
                        }
                        text.drain(p..pos);
                        pos = p;
                    }
                }
                Some(Key::Delete | Key::Ctrl(b'd')) => {
                    if pos < text.len() {
                        let mut e = pos + 1;
                        while e < text.len() && !buffer::is_start(text[e]) {
                            e += 1;
                        }
                        text.drain(pos..e);
                    }
                }
                Some(Key::Left | Key::Ctrl(b'b')) => {
                    while pos > 0 {
                        pos -= 1;
                        if buffer::is_start(text[pos]) {
                            break;
                        }
                    }
                }
                Some(Key::Right | Key::Ctrl(b'f')) => {
                    if pos < text.len() {
                        pos += 1;
                        while pos < text.len() && !buffer::is_start(text[pos]) {
                            pos += 1;
                        }
                    }
                }
                Some(Key::Home | Key::Ctrl(b'a')) => pos = 0,
                Some(Key::End | Key::Ctrl(b'e')) => pos = text.len(),
                Some(Key::Ctrl(b'u')) => {
                    text.clear();
                    pos = 0;
                }
                Some(Key::Char(c)) => {
                    let mut b = [0u8; 4];
                    let s = c.encode_utf8(&mut b).as_bytes();
                    for (i, &x) in s.iter().enumerate() {
                        text.insert(pos + i, x);
                    }
                    pos += s.len();
                }
                Some(Key::Tab) => {
                    text.insert(pos, b'\t');
                    pos += 1;
                }
                Some(Key::Resize) => {
                    self.invalidate();
                    self.draw();
                }
                _ => {}
            }
        }
    }

    /// A question with one-letter answers; `None` for ^C.
    fn ask(&mut self, question: &str, choices: &[char]) -> Option<char> {
        let a = self.ask_inner(question, choices);
        let row = self.text_rows() + 1;
        if let Some(r) = self.shown.get_mut(row) {
            *r = None;
        }
        a
    }

    fn ask_inner(&mut self, question: &str, choices: &[char]) -> Option<char> {
        loop {
            let rows = self.text_rows();
            let t = &mut self.term;
            t.goto(rows + 1, 0);
            t.reverse(true);
            let mut q = Vec::from(question.as_bytes());
            q.resize(t.cols, b' ');
            q.truncate(t.cols);
            t.put(&q);
            t.reverse(false);
            t.goto(rows + 1, question.len().min(t.cols - 1));
            t.flush();
            match t.key(None) {
                Some(Key::Char(c)) if choices.contains(&c.to_ascii_lowercase()) => return Some(c.to_ascii_lowercase()),
                Some(Key::Ctrl(b'c') | Key::Esc | Key::Eof) | None => return None,
                Some(Key::Resize) => {
                    self.invalidate();
                    self.draw();
                }
                _ => {}
            }
        }
    }

    // --- files --------------------------------------------------------------------

    fn save(&mut self, path: &[u8]) -> bool {
        let data = self.buf.to_bytes();
        let mode = fs::stat(path).map_or(0o666, |s| s.mode & 0o7777);
        // -B: what the file held, kept as FILE~ first.
        if self.settings.backup
            && let Ok(old) = fs::read_file(path)
        {
            let backup = [path, b"~"].concat();
            if let Err(e) = fs::write_file(&backup, &old, mode) {
                self.msg(alloc::format!("Error writing backup file {}: {e}", lossy(&backup)));
                return false;
            }
        }
        let r = fs::open(path, fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC | fs::O_CLOEXEC, mode).and_then(|fd| {
            let r = io::write_all(fd, &data);
            let _ = io::close(fd);
            r
        });
        match r {
            Ok(()) => {
                let n = self.buf.text_lines();
                self.msg(alloc::format!("Wrote {n} line{}", if n == 1 { "" } else { "s" }));
                self.buf.mark_saved();
                if self.path.as_deref() != Some(path) {
                    self.syntax = syntax::find(Some(path), self.buf.lines.first().map_or(&[][..], |l| l));
                }
                self.path = Some(path.to_vec());
                true
            }
            Err(e) => {
                self.msg(alloc::format!("Error writing {}: {e}", lossy(path)));
                false
            }
        }
    }

    fn write_out(&mut self) -> bool {
        let initial = self.path.clone().unwrap_or_default();
        match self.prompt("File Name to Write: ", &initial, &[]) {
            Answer::Text(p) if !p.is_empty() => self.save(&p),
            Answer::Text(_) | Answer::Cancel | Answer::Toggle(_) => {
                self.msg("Cancelled");
                false
            }
        }
    }

    fn read_file(&mut self) {
        let mut new_buffer = false;
        let p = loop {
            let label = if new_buffer { "File to read into new buffer: " } else { "File to insert: " };
            match self.prompt(label, b"", &['f']) {
                Answer::Text(p) => break p,
                Answer::Toggle(_) => new_buffer = !new_buffer,
                Answer::Cancel => {
                    self.msg("Cancelled");
                    return;
                }
            }
        };
        if new_buffer {
            // The new file comes right after the one shown (which is
            // then the one before it).
            let (doc, message) = open_doc(Some(p));
            let here = self.take_doc();
            self.others.push_back(here);
            self.put_doc(doc);
            self.index += 1;
            self.msg(message);
            return;
        }
        match fs::read_file(&p) {
            Ok(data) => {
                self.buf.seal();
                let n = data.iter().filter(|&&c| c == b'\n').count();
                self.cur = self.buf.insert(self.cur, &data);
                self.buf.seal();
                self.msg(alloc::format!("Read {n} lines"));
            }
            Err(e) => self.msg(alloc::format!("Error reading {}: {e}", lossy(&p))),
        }
    }

    /// ^T: a command run by the shell, its output (and errors) inserted
    /// where the cursor is.
    fn execute(&mut self) {
        let Answer::Text(cmd) = self.prompt("Command to execute: ", b"", &[]) else {
            self.msg("Cancelled");
            return;
        };
        if cmd.is_empty() {
            self.msg("Cancelled");
            return;
        }
        let Ok((r, w)) = process::pipe(fs::O_CLOEXEC) else {
            self.msg("Couldn't make a pipe");
            return;
        };
        let pid = match process::fork() {
            Ok(0) => {
                // Not the terminal's input: the keys stay etch's.
                if let Ok(null) = fs::open(b"/dev/null", fs::O_RDONLY, 0) {
                    let _ = process::dup2(null, 0);
                }
                let _ = process::dup2(w, 1);
                let _ = process::dup2(w, 2);
                let argv = [b"sh".to_vec(), b"-c".to_vec(), cmd.clone()];
                let _ = process::execve(b"/bin/sh", &argv, slate_rt::env::vars());
                process::exit_now(127);
            }
            Ok(pid) => pid,
            Err(e) => {
                self.msg(alloc::format!("Couldn't run it: {e}"));
                return;
            }
        };
        let _ = io::close(w);
        let out = io::read_to_end(r).unwrap_or_default();
        let _ = io::close(r);
        let _ = process::wait(pid, 0);
        self.buf.seal();
        self.cur = self.buf.insert(self.cur, &out);
        self.buf.seal();
        let n = out.iter().filter(|&&c| c == b'\n').count();
        self.msg(alloc::format!("Read {n} line{}", if n == 1 { "" } else { "s" }));
    }

    // --- search -------------------------------------------------------------------

    /// The next match of `pat` after `from` (wrapping): (start, end).
    fn find(&self, pat: &[u8], from: Pos) -> Option<(Pos, Pos, bool)> {
        let re = if self.regex {
            Regex::new(pat, Options { icase: !self.case_sensitive, ..Options::extended() }).ok()?
        } else {
            Regex::literal(pat, Options { icase: !self.case_sensitive, ..Options::extended() })
        };
        let n = self.buf.lines.len();
        for k in 0..=n {
            let line = (from.line + k) % n;
            let wrapped = from.line + k >= n;
            let start = if k == 0 { from.col } else { 0 };
            let text = &self.buf.lines[line];
            let mut s = start;
            while s <= text.len() {
                if let Some((a, b)) = re.find_from(text, s, false).and_then(|c| c[0]) {
                    if k == n && a >= from.col {
                        return None;
                    }
                    if b > a || !pat.is_empty() {
                        return Some((Pos { line, col: a }, Pos { line, col: b }, wrapped));
                    }
                    s = a + 1;
                } else {
                    break;
                }
            }
        }
        None
    }

    fn search_prompt(&mut self, label: &str) -> Option<Vec<u8>> {
        let mut text: Vec<u8> = Vec::new();
        loop {
            let opts = alloc::format!(
                "{}{}{}",
                label,
                if self.case_sensitive { " [Case Sensitive]" } else { "" },
                if self.regex { " [Regexp]" } else { "" }
            );
            let last = self.search.as_ref().map(|s| alloc::format!(" [{}]", lossy(s))).unwrap_or_default();
            match self.prompt(&alloc::format!("{opts}{last}: "), &text, &['c', 'r']) {
                Answer::Text(t) if t.is_empty() => return self.search.clone(),
                Answer::Text(t) => return Some(t),
                Answer::Cancel => return None,
                Answer::Toggle(c) => {
                    if c == 'c' {
                        self.case_sensitive = !self.case_sensitive;
                    } else {
                        self.regex = !self.regex;
                    }
                    text = Vec::new();
                }
            }
        }
    }

    fn search_next(&mut self, pat: &[u8]) {
        let from = self.buf.next(self.cur);
        let from = if from == self.cur { Pos { line: self.cur.line, col: self.cur.col + 1 } } else { from };
        match self
            .find(pat, from)
            .or_else(|| self.find(pat, Pos { line: 0, col: 0 }).filter(|(a, _, _)| *a == self.cur))
        {
            Some((a, _, wrapped)) => {
                if a == self.cur {
                    self.msg("This is the only occurrence");
                } else if wrapped {
                    self.msg("Search Wrapped");
                }
                self.cur = a;
                self.want_x = display_col(&self.buf.lines[a.line], a.col);
            }
            None => self.msg(alloc::format!("\"{}\" not found", lossy(pat))),
        }
    }

    fn replace(&mut self) {
        let Some(pat) = self.search_prompt("Search (to replace)") else {
            self.msg("Cancelled");
            return;
        };
        self.search = Some(pat.clone());
        let Answer::Text(with) = self.prompt("Replace with: ", b"", &[]) else {
            self.msg("Cancelled");
            return;
        };
        let mut all = false;
        let mut count = 0;
        let start = self.cur;
        let mut at = self.cur;
        let mut passed_start = false;
        self.buf.seal();
        while let Some((a, b, wrapped)) = self.find(&pat, at) {
            if wrapped && a >= start || passed_start && a >= start {
                break;
            }
            if wrapped {
                passed_start = true;
            }
            self.cur = a;
            let mut yes = all;
            if !all {
                self.draw();
                match self.ask("Replace this instance?  Y Yes  N No  A All  ^C Cancel", &['y', 'n', 'a']) {
                    Some('y') => yes = true,
                    Some('a') => {
                        all = true;
                        yes = true;
                    }
                    Some(_) => {}
                    None => break,
                }
            }
            if yes {
                self.buf.delete(a, b);
                let end = self.buf.insert(a, &with);
                self.buf.seal();
                count += 1;
                at = if end == a { Pos { line: a.line, col: a.col + 1 } } else { end };
            } else {
                at = Pos { line: b.line, col: b.col.max(a.col + 1) };
            }
            if at.col > self.buf.lines[at.line].len() {
                if at.line + 1 >= self.buf.lines.len() {
                    break;
                }
                at = Pos { line: at.line + 1, col: 0 };
            }
        }
        self.cur = self.buf.clamp(self.cur);
        self.msg(alloc::format!("Replaced {count} occurrence{}", if count == 1 { "" } else { "s" }));
    }

    fn goto_line(&mut self) {
        let Answer::Text(t) = self.prompt("Enter line number, column number: ", b"", &[]) else {
            self.msg("Cancelled");
            return;
        };
        let parts: Vec<usize> = t
            .split(|&c| c == b',' || c == b' ')
            .filter(|p| !p.is_empty())
            .filter_map(|p| core::str::from_utf8(p).ok()?.parse().ok())
            .collect();
        let Some(&line) = parts.first() else {
            self.msg("Invalid line or column number");
            return;
        };
        let line = line.clamp(1, self.buf.lines.len()) - 1;
        let col = parts.get(1).map_or(0, |c| col_for(&self.buf.lines[line], c.saturating_sub(1)));
        self.cur = self.buf.clamp(Pos { line, col });
        self.want_x = display_col(&self.buf.lines[line], self.cur.col);
    }

    fn location(&mut self) {
        let lines = self.buf.lines.len();
        let line = &self.buf.lines[self.cur.line];
        let cols = String::from_utf8_lossy(line).chars().count() + 1;
        let col = String::from_utf8_lossy(&line[..self.cur.col]).chars().count() + 1;
        let total: usize = self.buf.lines.iter().map(|l| l.len() + 1).sum();
        let here: usize = self.buf.lines[..self.cur.line].iter().map(|l| l.len() + 1).sum::<usize>() + self.cur.col;
        let pct = |a: usize, b: usize| (a * 100).checked_div(b).unwrap_or(100);
        self.msg(alloc::format!(
            "line {}/{lines} ({}%), col {col}/{cols} ({}%), char {here}/{total} ({}%)",
            self.cur.line + 1,
            pct(self.cur.line + 1, lines),
            pct(col, cols),
            pct(here, total)
        ));
    }

    fn help(&mut self) {
        let t = &mut self.term;
        t.clear();
        for (i, l) in HELP.lines().enumerate() {
            if i + 1 >= t.rows {
                break;
            }
            t.goto(i, 0);
            t.put(l.as_bytes());
        }
        t.flush();
        let _ = t.key(None);
        t.clear();
        self.invalidate();
    }

    // --- editing ------------------------------------------------------------------------

    fn cut_line(&mut self) {
        if !self.last_cut {
            self.cut.clear();
        }
        let l = self.cur.line;
        let n = self.buf.lines.len();
        let len = self.buf.lines[l].len();
        if l + 1 < n {
            let text = self.buf.delete(Pos { line: l, col: 0 }, Pos { line: l + 1, col: 0 });
            self.cut.extend_from_slice(&text);
        } else if len > 0 {
            // A last line without a newline: its text (a line when pasted).
            let mut text = self.buf.delete(Pos { line: l, col: 0 }, Pos { line: l, col: len });
            text.push(b'\n');
            self.cut.extend_from_slice(&text);
        }
        self.cur = self.buf.clamp(Pos { line: l, col: 0 });
        self.buf.seal();
    }

    fn paste(&mut self) {
        if self.cut.is_empty() {
            return;
        }
        let text = self.cut.clone();
        self.buf.seal();
        self.cur = self.buf.insert(self.cur, &text);
        self.buf.seal();
    }

    fn insert_char(&mut self, c: char) {
        let mut b = [0u8; 4];
        self.cur = self.buf.insert(self.cur, c.encode_utf8(&mut b).as_bytes());
    }

    fn newline(&mut self) {
        let mut text = alloc::vec![b'\n'];
        if self.settings.autoindent {
            let line = &self.buf.lines[self.cur.line];
            text.extend(line.iter().take_while(|c| **c == b' ' || **c == b'\t').take(self.cur.col));
        }
        self.buf.seal();
        self.cur = self.buf.insert(self.cur, &text);
        self.buf.seal();
    }

    /// ^J: the paragraph the cursor is in (or the next one) filled to the
    /// fill width, one step for undo.
    fn justify_here(&mut self) {
        let blank = |l: &[u8]| l.iter().all(|c| c.is_ascii_whitespace());
        let lines = &self.buf.lines;
        let mut start = self.cur.line;
        while start < lines.len() && blank(&lines[start]) {
            start += 1;
        }
        if start >= lines.len() {
            self.msg("No paragraph");
            return;
        }
        while start > 0 && !blank(&lines[start - 1]) {
            start -= 1;
        }
        let mut end = start;
        while end < lines.len() && !blank(&lines[end]) {
            end += 1;
        }
        let width = if self.settings.fill > 0 {
            self.settings.fill as usize
        } else {
            self.term.cols.saturating_sub(self.settings.fill.unsigned_abs() as usize).max(10)
        };
        let new = justify(&lines[start..end], width).join(&b'\n');
        let to = Pos { line: end - 1, col: lines[end - 1].len() };
        self.buf.seal();
        self.cur = self.buf.replace(Pos { line: start, col: 0 }, to, &new);
        self.buf.seal();
        self.msg("Justified");
    }

    fn vertical(&mut self, delta: isize) {
        let target = (self.cur.line as isize + delta).clamp(0, self.buf.lines.len() as isize - 1) as usize;
        self.cur = Pos { line: target, col: col_for(&self.buf.lines[target], self.want_x) };
    }

    /// A click in the text puts the cursor there; the wheel scrolls.
    fn mouse(&mut self, button: u8, row: usize, col: usize) {
        let rows = self.text_rows();
        match button {
            64 | 65 => {
                let n = self.buf.lines.len();
                self.top =
                    if button == 64 { self.top.saturating_sub(3) } else { (self.top + 3).min(n.saturating_sub(1)) };
                // The cursor stays on the screen.
                let line = self.cur.line.clamp(self.top, (self.top + rows - 1).min(n - 1));
                if line != self.cur.line {
                    self.cur = Pos { line, col: col_for(&self.buf.lines[line], self.want_x) };
                }
            }
            0 if (1..=rows).contains(&row) => {
                let line = (self.top + row - 1).min(self.buf.lines.len() - 1);
                let x = (self.left + col).saturating_sub(self.gutter());
                self.cur = Pos { line, col: col_for(&self.buf.lines[line], x) };
                self.buf.seal();
            }
            _ => {}
        }
    }

    fn suspend(&mut self) {
        self.term.suspend();
        let _ = process::kill(0, signal::SIGTSTP);
        self.term.resume();
        self.invalidate();
    }

    /// Ask to save changes; true to close the file.
    fn exit(&mut self) -> bool {
        if !self.buf.modified() || self.view_only {
            return true;
        }
        match self.ask("Save modified buffer?  Y Yes  N No  ^C Cancel", &['y', 'n']) {
            Some('y') => match self.path.clone() {
                Some(p) => {
                    let Answer::Text(p) = self.prompt("File Name to Write: ", &p, &[]) else { return false };
                    self.save(&p)
                }
                None => self.write_out(),
            },
            Some(_) => true,
            None => false,
        }
    }

    /// The main loop; returns the exit status.
    fn run(&mut self) -> i32 {
        self.term.alt_screen(true);
        if self.settings.mouse {
            self.term.mouse(true);
        }
        loop {
            self.draw();
            let Some(key) = self.term.key(None) else { continue };
            let was_cut = self.last_cut;
            self.last_cut = false;
            let editing = !self.view_only;
            match key {
                Key::Eof => return 1,
                Key::Resize | Key::Ctrl(b'l') => {
                    self.term.clear();
                    self.invalidate();
                }
                Key::Ctrl(b'x') => {
                    if self.exit() && !self.close() {
                        return 0;
                    }
                }
                Key::Ctrl(b'o') if editing => {
                    self.write_out();
                }
                Key::Ctrl(b'r') if editing => self.read_file(),
                Key::Ctrl(b'g') => self.help(),
                Key::Ctrl(b'w') => {
                    if let Some(p) = self.search_prompt("Search") {
                        self.search = Some(p.clone());
                        self.search_next(&p);
                    } else {
                        self.msg("Cancelled");
                    }
                }
                Key::Alt('w') => match self.search.clone() {
                    Some(p) => self.search_next(&p),
                    None => self.msg("No current search pattern"),
                },
                Key::Ctrl(b'\\') if editing => self.replace(),
                Key::Ctrl(b'_') | Key::Alt('g') => self.goto_line(),
                Key::Ctrl(b'c') => self.location(),
                Key::Ctrl(b'k') if editing => {
                    self.last_cut = was_cut;
                    self.cut_line();
                    self.last_cut = true;
                }
                Key::Ctrl(b'u') if editing => self.paste(),
                Key::Ctrl(b'j') if editing => self.justify_here(),
                Key::Ctrl(b't') if editing => self.execute(),
                Key::Ctrl(b'z') => self.suspend(),
                Key::Alt('u') if editing => match self.buf.undo() {
                    Some(p) => self.cur = self.buf.clamp(p),
                    None => self.msg("Nothing to undo"),
                },
                Key::Alt('e') if editing => match self.buf.redo() {
                    Some(p) => self.cur = self.buf.clamp(p),
                    None => self.msg("Nothing to redo"),
                },
                Key::Alt('<' | ',') => self.switch(false),
                Key::Alt('>' | '.') => self.switch(true),
                Key::Alt('n') => self.settings.line_numbers = !self.settings.line_numbers,
                Key::Alt('i') => {
                    self.settings.autoindent = !self.settings.autoindent;
                    self.msg(if self.settings.autoindent { "Auto indent enabled" } else { "Auto indent disabled" });
                }
                Key::Alt('y') => {
                    self.settings.syntax = !self.settings.syntax;
                    self.msg(if self.settings.syntax { "Syntax colours on" } else { "Syntax colours off" });
                }
                Key::Mouse { button, row, col, press: true } => self.mouse(button, row, col),
                Key::Up | Key::Ctrl(b'p') => self.vertical(-1),
                Key::Down | Key::Ctrl(b'n') => self.vertical(1),
                Key::PageUp | Key::Ctrl(b'y') => self.vertical(-(self.text_rows() as isize)),
                Key::PageDown | Key::Ctrl(b'v') => self.vertical(self.text_rows() as isize),
                Key::Left | Key::Ctrl(b'b') => {
                    self.cur = self.buf.prev(self.cur);
                    self.buf.seal();
                }
                Key::Right | Key::Ctrl(b'f') => {
                    self.cur = self.buf.next(self.cur);
                    self.buf.seal();
                }
                Key::Home | Key::Ctrl(b'a') => self.cur.col = 0,
                Key::End | Key::Ctrl(b'e') => self.cur.col = self.buf.lines[self.cur.line].len(),
                Key::Enter if editing => self.newline(),
                Key::Tab if editing => self.insert_char('\t'),
                Key::Char(c) if editing => self.insert_char(c),
                Key::Backspace if editing => {
                    let p = self.buf.prev(self.cur);
                    if p != self.cur {
                        self.buf.delete(p, self.cur);
                        self.cur = p;
                    }
                }
                Key::Delete | Key::Ctrl(b'd') if editing => {
                    let n = self.buf.next(self.cur);
                    self.buf.delete(self.cur, n);
                }
                Key::Mouse { .. } => {}
                _ if !editing => self.msg("Key invalid in view mode"),
                _ => {}
            }
            let vertical = matches!(
                key,
                Key::Up
                    | Key::Down
                    | Key::PageUp
                    | Key::PageDown
                    | Key::Ctrl(b'p' | b'n' | b'y' | b'v')
                    | Key::Mouse { .. }
            );
            if !vertical {
                self.want_x = display_col(&self.buf.lines[self.cur.line], self.cur.col);
            }
        }
    }
}

/// A file opened into a buffer (`None` or `-`: standard input or nothing)
/// and the message that says so.
fn open_doc(path: Option<Vec<u8>>) -> (Doc, String) {
    let mut path = path;
    let mut message = String::new();
    let data = match &path {
        Some(p) if p == b"-" => {
            let d = io::read_to_end(0).unwrap_or_default();
            path = None;
            d
        }
        Some(p) => match fs::stat(p) {
            Ok(s) if s.is_dir() => {
                message = alloc::format!("{} is a directory", lossy(p));
                path = None;
                Vec::new()
            }
            Ok(_) => match fs::read_file(p) {
                Ok(d) => d,
                Err(e) => {
                    message = alloc::format!("Error reading {}: {e}", lossy(p));
                    Vec::new()
                }
            },
            Err(_) => {
                message = String::from("New File");
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    let buf = Buffer::from_bytes(&data);
    if message.is_empty() && path.is_some() {
        let lines = buf.text_lines();
        message = alloc::format!("Read {lines} line{}", if lines == 1 { "" } else { "s" });
    }
    let syntax = syntax::find(path.as_deref(), buf.lines.first().map_or(&[][..], |l| l));
    (Doc { buf, path, cur: Pos::default(), want_x: 0, top: 0, left: 0, syntax }, message)
}

/// The settings file: $XDG_CONFIG_HOME/etch/etchrc, else
/// ~/.config/etch/etchrc, else ~/.etchrc.
fn rc_text() -> Option<Vec<u8>> {
    let var = |n: &[u8]| slate_rt::env::var(n).filter(|v| !v.is_empty());
    let mut tries = Vec::new();
    if let Some(x) = var(b"XDG_CONFIG_HOME") {
        tries.push([x.as_slice(), b"/etch/etchrc"].concat());
    }
    if let Some(h) = var(b"HOME") {
        tries.push([h.as_slice(), b"/.config/etch/etchrc"].concat());
        tries.push([h.as_slice(), b"/.etchrc"].concat());
    }
    tries.iter().find_map(|p| fs::read_file(p).ok())
}

fn usage() -> i32 {
    io::err(b"usage: etch [-l] [-i] [-v] [-B] [-m] [-Y] [+LINE[,COLUMN]] [FILE...]\n");
    2
}

pub fn main() -> i32 {
    let args = slate_rt::env::args();
    let mut paths: Vec<Vec<u8>> = Vec::new();
    let mut settings = Settings::default();
    let mut rc_problem = None;
    if let Some(text) = rc_text() {
        rc_problem = settings.read(&String::from(lossy(&text))).into_iter().next();
    }
    let mut view_only = false;
    let mut start: Option<(usize, usize)> = None;
    for a in &args[1..] {
        match a.as_slice() {
            b"-l" | b"--linenumbers" => settings.line_numbers = true,
            b"-i" | b"--autoindent" => settings.autoindent = true,
            b"-v" | b"--view" => view_only = true,
            b"-B" | b"--backup" => settings.backup = true,
            b"-m" | b"--mouse" => settings.mouse = true,
            b"-Y" | b"--nosyntax" => settings.syntax = false,
            b"--version" => {
                io::out(alloc::format!("etch {VERSION} (Slate)\n").as_bytes());
                return 0;
            }
            b"-h" | b"--help" => return usage(),
            _ if a.starts_with(b"+") => {
                let nums: Vec<usize> =
                    a[1..].split(|&c| c == b',').filter_map(|p| core::str::from_utf8(p).ok()?.parse().ok()).collect();
                start = Some((nums.first().copied().unwrap_or(1), nums.get(1).copied().unwrap_or(1)));
            }
            _ if a.starts_with(b"-") && a.len() > 1 => return usage(),
            _ => paths.push(a.clone()),
        }
    }
    if !term::isatty(1) {
        io::err(b"etch: standard output is not a terminal\n");
        return 1;
    }
    if paths.len() == 1
        && let Ok(s) = fs::stat(&paths[0])
        && s.is_dir()
    {
        io::err(alloc::format!("etch: {} is a directory\n", lossy(&paths[0])).as_bytes());
        return 1;
    }
    // Keys come from the terminal even when the text came from a pipe.
    let fd_in = if term::isatty(0) { 0 } else { fs::open(b"/dev/tty", fs::O_RDWR | fs::O_CLOEXEC, 0).unwrap_or(0) };
    let mut docs = paths.into_iter().map(|p| open_doc(Some(p)));
    let (first, message) = docs.next().unwrap_or_else(|| open_doc(None));
    let others: VecDeque<Doc> = docs.map(|d| d.0).collect();
    let mut ed = Editor {
        buf: first.buf,
        path: first.path,
        cur: Pos::default(),
        want_x: 0,
        top: 0,
        left: 0,
        syntax: first.syntax,
        others,
        index: 0,
        message: (!message.is_empty()).then_some(message),
        cut: Vec::new(),
        last_cut: false,
        search: None,
        case_sensitive: false,
        regex: false,
        settings,
        view_only,
        term: Term::new(fd_in, 1, false),
        shown: Vec::new(),
    };
    if let Some(p) = rc_problem {
        ed.message = Some(alloc::format!("Unknown setting in etchrc, {p}"));
    }
    if let Some((l, c)) = start {
        let line = l.clamp(1, ed.buf.lines.len()) - 1;
        ed.cur = ed.buf.clamp(Pos { line, col: col_for(&ed.buf.lines[line], c.saturating_sub(1)) });
    }
    let status = ed.run();
    drop(ed);
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns() {
        assert_eq!(display_col(b"a\tb", 2), 8);
        assert_eq!(display_col("é\x01x".as_bytes(), 3), 3);
        assert_eq!(col_for(b"a\tbc", 8), 2);
        assert_eq!(col_for(b"a\tbc", 5), 1);
        assert_eq!(col_for("éé".as_bytes(), 1), 2);
        assert_eq!(col_for(b"ab", 10), 2);
        // A wide character takes two columns.
        assert_eq!(display_col("漢x".as_bytes(), 3), 2);
        assert_eq!(col_for("漢x".as_bytes(), 1), 0, "inside the character: before it");
        assert_eq!(col_for("漢x".as_bytes(), 2), 3);
    }

    #[test]
    fn justified() {
        let lines: Vec<Vec<u8>> =
            ["  one two three four", "five six", "seven"].iter().map(|l| l.as_bytes().to_vec()).collect();
        let out = justify(&lines, 14);
        let text: Vec<&str> = out.iter().map(|l| core::str::from_utf8(l).unwrap()).collect();
        assert_eq!(text, ["  one two", "three four", "five six seven"]);
        let long = justify(&[b"a verylongwordindeed b".to_vec()], 5);
        assert_eq!(long.len(), 3);
        assert_eq!(justify(&[b"   ".to_vec()], 10), [b"   ".to_vec()]);
    }

    #[test]
    fn settings_file() {
        let mut s = Settings::default();
        let problems =
            s.read("# etch\nset linenumbers\nset backup\nunset syntax\nset fill 60\nset mouse\nbogus\nset fill x\n");
        assert!(s.line_numbers && s.backup && !s.syntax && s.mouse);
        assert_eq!(s.fill, 60);
        assert_eq!(problems, ["line 7: bogus", "line 8: set fill x"]);
    }
}
