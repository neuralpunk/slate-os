// SPDX-License-Identifier: MIT OR Apache-2.0

//! The interactive line editor: emacs-style keys, history and tab
//! completion on a terminal in non-canonical mode. Output uses the VT100
//! / ECMA-48 control sequences every terminal emulator understands
//! (CR, EL `ESC [ K`, ED `ESC [ J` and `ESC [ 2 J`, CUP `ESC [ H`, CUU
//! and CUF `ESC [ n A` / `C`). A line longer than the terminal is wide
//! wraps; the editor keeps track of the row the cursor is on, and wide
//! characters take two columns (slate-term's Unicode table).

use alloc::vec::Vec;

use slate_rt::term::{self, Termios};
use slate_rt::{fs, io};

/// What reading a line gave.
#[derive(Debug, PartialEq, Eq)]
pub enum Input {
    Line(Vec<u8>),
    /// Ctrl-D on an empty line.
    Eof,
    /// Ctrl-C: the line is abandoned.
    Interrupt,
}

/// Completion: given the line and the cursor, the start of the word being
/// completed and the candidates (directories end in `/`).
pub type Completer<'a> = &'a mut dyn FnMut(&[u8], usize) -> (usize, Vec<Vec<u8>>);

#[derive(Debug)]
pub struct Editor {
    fd: i32,
    /// The terminal's modes outside the editor: read again before each
    /// line, so what a program set (`stty -echo`) stays.
    cooked: Termios,
    pub history_file: Option<Vec<u8>>,
    pub history_size: usize,
}

fn is_cont(c: u8) -> bool {
    c & 0xC0 == 0x80
}

/// The characters of UTF-8 text with their columns; escape sequences
/// (a prompt's colours) take none.
fn cells(s: &[u8]) -> Vec<usize> {
    let text = alloc::string::String::from_utf8_lossy(s);
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // CSI: parameters up to a final byte; OSC: up to BEL or ST.
            match chars.peek() {
                Some('[') => {
                    chars.next();
                    for n in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&n) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    for n in chars.by_ref() {
                        if n == '\x07' || n == '\\' {
                            break;
                        }
                    }
                }
                _ => {
                    chars.next();
                }
            }
            continue;
        }
        out.push(if (c as u32) < 0x20 { 0 } else { slate_term::width::width(c) });
    }
    out
}

/// Display columns of UTF-8 text.
fn width(s: &[u8]) -> usize {
    cells(s).iter().sum()
}

/// The row the terminal's cursor is on after writing `s`: a line that
/// fills the last column leaves it there (until the next character), not
/// on the next row.
fn cursor_row(s: &[u8], cols: usize) -> usize {
    match place(s, cols) {
        (r, 0) if r > 0 => r - 1,
        (r, _) => r,
    }
}

/// Where text ends on a terminal `cols` wide, starting at column 0: (row,
/// column). A wide character that does not fit wraps whole; text that
/// fills the last column leaves the cursor at the start of the next row.
fn place(s: &[u8], cols: usize) -> (usize, usize) {
    let cols = cols.max(1);
    let (mut row, mut col) = (0, 0);
    for w in cells(s) {
        if col + w > cols {
            row += 1;
            col = 0;
        }
        col += w;
        if col >= cols {
            row += 1;
            col = 0;
        }
    }
    (row, col)
}

impl Editor {
    pub fn new(fd: i32) -> Option<Editor> {
        let cooked = term::get(fd).ok()?;
        Some(Editor { fd, cooked, history_file: None, history_size: 1000 })
    }

    /// The editor's own mode: no echo, canonical input or signals.
    fn raw(&self) -> Termios {
        let mut raw = self.cooked;
        raw.lflag &= !(term::ICANON | term::ECHO | term::ISIG | term::IEXTEN);
        raw.iflag &= !(term::ICRNL | term::IXON);
        raw.cc[term::VMIN] = 1;
        raw.cc[term::VTIME] = 0;
        raw
    }

    /// Put the terminal back the way the shell found it.
    pub fn restore_modes(&self) {
        let _ = term::set(self.fd, &self.cooked, false);
    }

    pub fn load_history(&self) -> Vec<Vec<u8>> {
        let Some(f) = &self.history_file else { return Vec::new() };
        let Ok(data) = fs::read_file(f) else { return Vec::new() };
        let mut h: Vec<Vec<u8>> = data.split(|&c| c == b'\n').filter(|l| !l.is_empty()).map(<[u8]>::to_vec).collect();
        let excess = h.len().saturating_sub(self.history_size);
        h.drain(..excess);
        h
    }

    pub fn save_history(&self, h: &[Vec<u8>]) {
        let Some(f) = &self.history_file else { return };
        let start = h.len().saturating_sub(self.history_size);
        let mut data = Vec::new();
        for l in &h[start..] {
            data.extend_from_slice(l);
            data.push(b'\n');
        }
        let _ = fs::write_file(f, &data, 0o600);
    }

    fn read_byte(&self) -> Option<u8> {
        let mut b = [0u8; 1];
        match io::read(self.fd, &mut b) {
            Ok(1) => Some(b[0]),
            _ => None,
        }
    }

    fn out(&self, b: &[u8]) {
        let _ = io::write_all(self.fd, b);
    }

    /// Read a line, showing `prompt`.
    pub fn read_line(&mut self, prompt: &[u8], history: &[Vec<u8>], complete: Completer<'_>) -> Input {
        match term::get(self.fd) {
            Ok(t) => self.cooked = t,
            Err(_) => return Input::Eof,
        }
        if term::set(self.fd, &self.raw(), false).is_err() {
            return Input::Eof;
        }
        // The prompt's last line is redrawn with the text.
        let last_prompt = prompt.rsplit(|&c| c == b'\n').next().unwrap_or(prompt).to_vec();
        self.out(prompt);
        let mut st = State { buf: Vec::new(), cur: 0, hist: history.len(), saved: Vec::new(), last_tab: false, row: 0 };
        st.row = place(&last_prompt, self.cols()).0;
        let r = loop {
            let Some(c) = self.read_byte() else { break Input::Eof };
            let tab = c == b'\t';
            match c {
                b'\r' | b'\n' => {
                    // Below the whole line, wherever the cursor was in it.
                    let end = cursor_row(&[last_prompt.as_slice(), &st.buf].concat(), self.cols());
                    if end > st.row {
                        self.out(alloc::format!("\x1b[{}B", end - st.row).as_bytes());
                    }
                    self.out(b"\r\n");
                    break Input::Line(core::mem::take(&mut st.buf));
                }
                0x03 => {
                    self.out(b"^C\r\n");
                    break Input::Interrupt;
                }
                0x04 if st.buf.is_empty() => {
                    self.out(b"\r\n");
                    break Input::Eof;
                }
                0x04 => st.delete(),
                0x01 => st.cur = 0,
                0x05 => st.cur = st.buf.len(),
                0x02 => st.left(),
                0x06 => st.right(),
                0x08 | 0x7F => {
                    if st.cur > 0 {
                        st.left();
                        st.delete();
                    }
                }
                0x0B => st.buf.truncate(st.cur),
                0x15 => {
                    st.buf.drain(..st.cur);
                    st.cur = 0;
                }
                0x17 => {
                    let mut s = st.cur;
                    while s > 0 && st.buf[s - 1] == b' ' {
                        s -= 1;
                    }
                    while s > 0 && st.buf[s - 1] != b' ' {
                        s -= 1;
                    }
                    st.buf.drain(s..st.cur);
                    st.cur = s;
                }
                0x0C => {
                    self.out(b"\x1b[H\x1b[2J");
                    st.row = 0;
                }
                0x12 => {
                    if self.reverse_search(&mut st, history) {
                        self.out(b"\r\n");
                        break Input::Line(core::mem::take(&mut st.buf));
                    }
                }
                0x10 => st.history(history, -1),
                0x0E => st.history(history, 1),
                b'\t' => self.complete(&mut st, &last_prompt, complete),
                0x1B => self.escape(&mut st, history),
                c if c >= 0x20 => {
                    let start = st.cur;
                    let at_end = st.cur == st.buf.len();
                    st.buf.insert(st.cur, c);
                    st.cur += 1;
                    // Read the rest of a UTF-8 sequence before redrawing.
                    let more = match c {
                        0xC0..=0xDF => 1,
                        0xE0..=0xEF => 2,
                        0xF0..=0xF7 => 3,
                        _ => 0,
                    };
                    for _ in 0..more {
                        if let Some(b) = self.read_byte() {
                            st.buf.insert(st.cur, b);
                            st.cur += 1;
                        }
                    }
                    // Typing at the end of the line only needs an echo;
                    // the terminal wraps it.
                    if at_end {
                        self.out(&st.buf[start..]);
                        st.row = cursor_row(&[last_prompt.as_slice(), &st.buf].concat(), self.cols());
                        st.last_tab = false;
                        continue;
                    }
                }
                _ => {}
            }
            st.last_tab = tab;
            self.redraw(&mut st, &last_prompt);
        };
        self.restore_modes();
        r
    }

    fn escape(&self, st: &mut State, history: &[Vec<u8>]) {
        let Some(k) = self.read_byte() else { return };
        if k != b'[' && k != b'O' {
            // Meta keys: M-b / M-f move by words.
            match k {
                b'b' => st.word_left(),
                b'f' => st.word_right(),
                _ => {}
            }
            return;
        }
        let mut param = Vec::new();
        let fin = loop {
            match self.read_byte() {
                Some(c) if c.is_ascii_digit() || c == b';' => param.push(c),
                Some(c) => break c,
                None => return,
            }
        };
        match (fin, param.as_slice()) {
            (b'A', _) => st.history(history, -1),
            (b'B', _) => st.history(history, 1),
            (b'C', p) if p.ends_with(b"5") => st.word_right(),
            (b'D', p) if p.ends_with(b"5") => st.word_left(),
            (b'C', _) => st.right(),
            (b'D', _) => st.left(),
            (b'H', _) | (b'~', b"1" | b"7") => st.cur = 0,
            (b'F', _) | (b'~', b"4" | b"8") => st.cur = st.buf.len(),
            (b'~', b"3") => st.delete(),
            _ => {}
        }
    }

    /// Ctrl-R: reverse incremental search through the history, as
    /// readline's: typing narrows, Ctrl-R finds the next older match,
    /// Enter runs the match, Ctrl-G or Ctrl-C gives the line back, and any
    /// other key keeps the match for editing. True: run it now.
    fn reverse_search(&self, st: &mut State, history: &[Vec<u8>]) -> bool {
        let (orig, orig_cur) = (st.buf.clone(), st.cur);
        let mut query: Vec<u8> = Vec::new();
        // The match: history index and where in it the query starts.
        let mut at: Option<(usize, usize)> = None;
        let mut failed = false;
        loop {
            let shown: &[u8] = at.map_or(&st.buf, |(i, _)| &history[i]);
            let mut o = Vec::new();
            o.extend_from_slice(b"\r");
            o.extend_from_slice(if failed { b"(failed reverse-i-search)`" } else { b"(reverse-i-search)`" });
            o.extend_from_slice(&query);
            o.extend_from_slice(b"': ");
            o.extend_from_slice(shown);
            o.extend_from_slice(b"\x1b[K");
            self.out(&o);
            let Some(c) = self.read_byte() else { return false };
            match c {
                0x12 => {
                    let before = at.map_or(history.len(), |(i, _)| i);
                    match search(history, &query, before) {
                        Some(m) => {
                            at = Some(m);
                            failed = false;
                        }
                        None => failed = true,
                    }
                    continue;
                }
                0x07 | 0x03 => {
                    st.buf = orig;
                    st.cur = orig_cur;
                    return false;
                }
                0x08 | 0x7F => {
                    query.pop();
                }
                c if c >= 0x20 => query.push(c),
                c => {
                    if let Some((i, pos)) = at {
                        st.buf = history[i].clone();
                        st.cur = pos;
                        st.hist = i;
                    }
                    return c == b'\r' || c == b'\n';
                }
            }
            // The query changed: search again from the newest entry.
            match search(history, &query, history.len()) {
                Some(m) => {
                    at = Some(m);
                    failed = false;
                }
                None => failed = !query.is_empty(),
            }
        }
    }

    fn cols(&self) -> usize {
        term::size(self.fd).map_or(80, |s| usize::from(s.1))
    }

    /// Draw the prompt's last line and the text again from the row it
    /// starts on, clear what an older, longer line left, and put the
    /// cursor back.
    fn redraw(&self, st: &mut State, prompt: &[u8]) {
        let cols = self.cols();
        let mut o = Vec::with_capacity(prompt.len() + st.buf.len() + 32);
        if st.row > 0 {
            o.extend_from_slice(alloc::format!("\x1b[{}A", st.row).as_bytes());
        }
        o.push(b'\r');
        o.extend_from_slice(prompt);
        o.extend_from_slice(&st.buf);
        let all = [prompt, st.buf.as_slice()].concat();
        let end = place(&all, cols);
        // Text that filled the last column: step onto the next row.
        if end.1 == 0 && end.0 > 0 && !all.is_empty() {
            o.extend_from_slice(b" \r");
        }
        o.extend_from_slice(b"\x1b[J");
        let at = place(&[prompt, &st.buf[..st.cur]].concat(), cols);
        if end.0 > at.0 {
            o.extend_from_slice(alloc::format!("\x1b[{}A", end.0 - at.0).as_bytes());
        }
        o.push(b'\r');
        if at.1 > 0 {
            o.extend_from_slice(alloc::format!("\x1b[{}C", at.1).as_bytes());
        }
        st.row = at.0;
        self.out(&o);
    }

    fn complete(&self, st: &mut State, prompt: &[u8], complete: Completer<'_>) {
        let (start, cands) = complete(&st.buf, st.cur);
        if cands.is_empty() {
            self.out(b"\x07");
            return;
        }
        let word = st.buf[start..st.cur].to_vec();
        let common = common_prefix(&cands);
        if cands.len() == 1 {
            let mut ins = cands[0][word.len().min(cands[0].len())..].to_vec();
            if !cands[0].ends_with(b"/") {
                ins.push(b' ');
            }
            st.insert(&ins);
            return;
        }
        if common.len() > word.len() {
            st.insert(&common[word.len()..]);
            return;
        }
        if !st.last_tab {
            self.out(b"\x07");
            return;
        }
        // A second tab lists the candidates in columns, under the line.
        let cols = self.cols();
        let end = place(&[prompt, st.buf.as_slice()].concat(), cols).0;
        if end > st.row {
            self.out(alloc::format!("\x1b[{}B", end - st.row).as_bytes());
        }
        // The prompt starts afresh below the list.
        st.row = 0;
        let w = cands.iter().map(|c| width(display_name(c))).max().unwrap_or(1) + 2;
        let per = (cols / w).max(1);
        let mut o = alloc::vec![b'\r', b'\n'];
        for (i, c) in cands.iter().enumerate() {
            let name = display_name(c);
            o.extend_from_slice(name);
            if (i + 1) % per == 0 || i + 1 == cands.len() {
                o.extend_from_slice(b"\r\n");
            } else {
                o.resize(o.len() + w - width(name), b' ');
            }
        }
        self.out(&o);
        let _ = prompt;
    }
}

/// The last path component of a candidate (for listings).
fn display_name(c: &[u8]) -> &[u8] {
    let t = c.strip_suffix(b"/").unwrap_or(c);
    match t.iter().rposition(|&b| b == b'/') {
        Some(i) => &c[i + 1..],
        None => c,
    }
}

fn common_prefix(c: &[Vec<u8>]) -> Vec<u8> {
    let mut p = c[0].clone();
    for s in &c[1..] {
        let n = p.iter().zip(s).take_while(|(a, b)| a == b).count();
        p.truncate(n);
    }
    while p.last().is_some_and(|&b| is_cont(b)) {
        p.pop();
    }
    p
}

/// The newest history entry before `before` that contains `q`, and
/// where.
fn search(h: &[Vec<u8>], q: &[u8], before: usize) -> Option<(usize, usize)> {
    if q.is_empty() {
        return None;
    }
    (0..before.min(h.len())).rev().find_map(|i| h[i].windows(q.len()).rposition(|w| w == q).map(|p| (i, p)))
}

struct State {
    buf: Vec<u8>,
    cur: usize,
    /// Position in history (len = the line being edited).
    hist: usize,
    /// The line being edited while browsing history.
    saved: Vec<u8>,
    last_tab: bool,
    /// The row the cursor is on, counted from the prompt's.
    row: usize,
}

impl State {
    fn left(&mut self) {
        while self.cur > 0 {
            self.cur -= 1;
            if !is_cont(self.buf[self.cur]) {
                break;
            }
        }
    }
    fn right(&mut self) {
        if self.cur < self.buf.len() {
            self.cur += 1;
            while self.cur < self.buf.len() && is_cont(self.buf[self.cur]) {
                self.cur += 1;
            }
        }
    }
    fn word_left(&mut self) {
        while self.cur > 0 && !self.buf[self.cur - 1].is_ascii_alphanumeric() {
            self.cur -= 1;
        }
        while self.cur > 0 && self.buf[self.cur - 1].is_ascii_alphanumeric() {
            self.cur -= 1;
        }
    }
    fn word_right(&mut self) {
        let n = self.buf.len();
        while self.cur < n && !self.buf[self.cur].is_ascii_alphanumeric() {
            self.cur += 1;
        }
        while self.cur < n && self.buf[self.cur].is_ascii_alphanumeric() {
            self.cur += 1;
        }
    }
    fn delete(&mut self) {
        if self.cur < self.buf.len() {
            let mut end = self.cur + 1;
            while end < self.buf.len() && is_cont(self.buf[end]) {
                end += 1;
            }
            self.buf.drain(self.cur..end);
        }
    }
    fn insert(&mut self, s: &[u8]) {
        for (i, &c) in s.iter().enumerate() {
            self.buf.insert(self.cur + i, c);
        }
        self.cur += s.len();
    }
    fn history(&mut self, h: &[Vec<u8>], dir: isize) {
        let next = self.hist as isize + dir;
        if next < 0 || next as usize > h.len() {
            return;
        }
        if self.hist == h.len() {
            self.saved = self.buf.clone();
        }
        self.hist = next as usize;
        self.buf = if self.hist == h.len() { self.saved.clone() } else { h[self.hist].clone() };
        self.cur = self.buf.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_search() {
        let h: Vec<Vec<u8>> = [&b"ls -l"[..], b"make all", b"ls /tmp", b"echo hi"].iter().map(|l| l.to_vec()).collect();
        assert_eq!(search(&h, b"ls", 4), Some((2, 0)));
        assert_eq!(search(&h, b"ls", 2), Some((0, 0)));
        assert_eq!(search(&h, b"ls", 0), None);
        assert_eq!(search(&h, b"all", 4), Some((1, 5)));
        assert_eq!(search(&h, b"", 4), None);
    }

    #[test]
    fn editing_state() {
        let mut s = State { buf: b"echo hi".to_vec(), cur: 7, hist: 0, saved: Vec::new(), last_tab: false, row: 0 };
        s.word_left();
        assert_eq!(s.cur, 5);
        s.insert(b"x");
        assert_eq!(s.buf, b"echo xhi");
        s.left();
        s.delete();
        assert_eq!(s.buf, b"echo hi");
        let h = alloc::vec![b"ls".to_vec(), b"pwd".to_vec()];
        s.hist = 2;
        s.history(&h, -1);
        assert_eq!(s.buf, b"pwd");
        s.history(&h, 1);
        assert_eq!(s.buf, b"echo hi");
        let mut u =
            State { buf: "aé".as_bytes().to_vec(), cur: 3, hist: 0, saved: Vec::new(), last_tab: false, row: 0 };
        u.left();
        assert_eq!(u.cur, 1);
        assert_eq!(width("aé".as_bytes()), 2);
        assert_eq!(common_prefix(&[b"abc".to_vec(), b"abd".to_vec()]), b"ab");
        assert_eq!(display_name(b"/usr/bin/"), b"bin/");
    }

    #[test]
    fn widths_and_wrapping() {
        assert_eq!(width("中文".as_bytes()), 4);
        assert_eq!(width(b"\x1b[1;32m$ \x1b[0m"), 2);
        assert_eq!(width("e\u{301}".as_bytes()), 1);
        // 10 columns: 9 then a wide character that does not fit wraps.
        assert_eq!(place("abcdefghi中".as_bytes(), 10), (1, 2));
        assert_eq!(place(b"abcdefghij", 10), (1, 0));
        assert_eq!(place(b"abc", 10), (0, 3));
        assert_eq!(place(&[b'x'; 25], 10), (2, 5));
        assert_eq!(cursor_row(b"abcdefghij", 10), 0);
        assert_eq!(cursor_row(b"abcdefghijk", 10), 1);
    }
}
