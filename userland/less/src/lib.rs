// SPDX-License-Identifier: MIT OR Apache-2.0

//! less, Slate's pager: files or standard input a screen at a time,
//! forward and back, with searching, marks, several files and the
//! commands and options of the traditional pager (space/b/j/k/g/G,
//! /pattern, ?pattern, n/N, -N, -S, -i, -I, -F, -R, -X, +cmd). ADR 0149
//! added lesskey bindings, prompt strings (-P, -m, -M, =), LESSOPEN and
//! LESSCLOSE, tags, `!`, `#` and `|`, -j, -z and -x, F woken by a watch
//! on the file, and files read again rather than held in memory. ADR 0164
//! added `&` filtering, bracket matching, horizontal scrolling, OSC 8
//! links, `_`, `s` and `-o`/`-O`, `-b`/`-B`, command-line editing keys
//! (#line-edit) and history.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use slate_regex::{Options, Regex};
use slate_rt::{fs, io, lossy, process, signal, term};
use slate_tui::{Key, Term};

mod history;
mod keys;
mod lineedit;
mod links;
mod prompt;
mod tags;

const TAB: usize = 8;

const HELP: &str = "less help

  SPACE f ^F ^V PgDn  forward a screen     b ^B ESC-v PgUp  back a screen
  RETURN j e ^N Down   forward a line       k y ^P ^Y Up     back a line
  d ^D                 forward half         u ^U             back half
  g < Home             first line (Ng: N)   G > End          last line
  /pattern ?pattern    search forward/back  n N              repeat search
  m<x> '<x>            set/go to mark       ''               previous place
  -N -S -i             toggle numbers, chopping, case     = file info
  :n :p :x            next/previous/first  v                edit the file
  F                    follow the file      r ^L ^R          redraw
  !cmd #cmd            shell command        |<m>cmd          pipe to mark m
  -t :t  t T           find a tag, next/previous tag
  &pattern             only matching lines  (&!: not; &RETURN: all)
  { ( [   } ) ]        to the matching bracket
  RIGHT LEFT ESC-} ESC-{  scroll sideways (-# the step)
  ^O^N ^O^P ^O^O       next/previous link, open it
  _x  s file           show option x; save a pipe (-o)
  R                    reload               q Q :q ZZ        quit

  A number before a command repeats it (or names a line for g and G).

Press any key to return.";

/// Display attributes of a character cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Attr {
    Normal,
    Bold,
    Underline,
    Match,
}

#[derive(Debug)]
struct Cell {
    bytes: Vec<u8>,
    width: usize,
    attr: Attr,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Opts {
    pub numbers: bool,
    pub chop: bool,
    /// -i: ignore case unless the pattern has capitals; -I always.
    pub smart_case: bool,
    pub ignore_case: bool,
    pub quit_if_one_screen: bool,
    pub raw_control: bool,
    pub no_init: bool,
}

/// Tab stops (`-x`): the columns listed, then every last gap after them
/// (one number: every that many columns).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tabs(pub Vec<usize>);

impl Default for Tabs {
    fn default() -> Tabs {
        Tabs(alloc::vec![TAB])
    }
}

impl Tabs {
    /// The next stop after column `col`.
    fn next(&self, col: usize) -> usize {
        if let Some(&s) = self.0.iter().find(|&&s| s > col) {
            return s;
        }
        let last = *self.0.last().unwrap_or(&TAB);
        let step = match self.0.len() {
            0 | 1 => last.max(1),
            n => (last - self.0[n - 2]).max(1),
        };
        if self.0.len() <= 1 { (col / step + 1) * step } else { last + ((col - last) / step + 1) * step }
    }

    /// `-xN[,M...]`.
    fn parse(v: &[u8]) -> Option<Tabs> {
        let stops: Option<Vec<usize>> =
            v.split(|&c| c == b',').map(|n| core::str::from_utf8(n).ok()?.parse().ok().filter(|&n| n > 0)).collect();
        let stops = stops?;
        (!stops.is_empty() && stops.windows(2).all(|w| w[0] < w[1])).then_some(Tabs(stops))
    }
}

/// The cells of `line`: tabs expanded, overstrikes as bold/underline,
/// control characters as `^X`, matches (byte ranges) highlighted.
fn cells(line: &[u8], matches: &[(usize, usize)], raw: bool, tabs: &Tabs) -> Vec<Cell> {
    let mut out: Vec<Cell> = Vec::new();
    let mut col = 0;
    let mut i = 0;
    let in_match = |i: usize| matches.iter().any(|&(a, b)| a <= i && i < b);
    while i < line.len() {
        let c = line[i];
        // Overstrike: x BS x is bold, _ BS x underlined.
        if i + 2 < line.len() && line[i + 1] == 8 {
            let next = line[i + 2];
            let attr = if c == b'_' {
                Attr::Underline
            } else if c == next {
                Attr::Bold
            } else {
                Attr::Normal
            };
            out.push(Cell { bytes: alloc::vec![next], width: 1, attr: if in_match(i) { Attr::Match } else { attr } });
            col += 1;
            i += 3;
            continue;
        }
        // An OSC 8 hyperlink passes through with -R (less(1)); other OSC
        // sequences show as text.
        if c == 0x1B
            && raw
            && line.get(i + 1) == Some(&b']')
            && let Some((body, next)) = links::osc_at(line, i)
            && body.starts_with(b"8;")
        {
            out.push(Cell { bytes: line[i..next].to_vec(), width: 0, attr: Attr::Normal });
            i = next;
            continue;
        }
        if c == 0x1B && raw && line.get(i + 1) != Some(&b']') {
            // An SGR (or other CSI) sequence passes through unchanged.
            let mut j = i + 1;
            if line.get(j) == Some(&b'[') {
                j += 1;
                while j < line.len() && !(0x40..=0x7E).contains(&line[j]) {
                    j += 1;
                }
                j = (j + 1).min(line.len());
            }
            out.push(Cell { bytes: line[i..j].to_vec(), width: 0, attr: Attr::Normal });
            i = j;
            continue;
        }
        let attr = if in_match(i) { Attr::Match } else { Attr::Normal };
        match c {
            b'\t' => {
                let w = tabs.next(col) - col;
                out.push(Cell { bytes: alloc::vec![b' '; w], width: w, attr });
                col += w;
                i += 1;
            }
            0..=0x1F | 0x7F => {
                let shown = if c == 0x1B { b"ESC".to_vec() } else { alloc::vec![b'^', c ^ 0x40] };
                let w = shown.len();
                out.push(Cell { bytes: shown, width: w, attr: if attr == Attr::Match { attr } else { Attr::Bold } });
                col += w;
                i += 1;
            }
            _ => {
                let len = match c {
                    0xC0..=0xDF => 2,
                    0xE0..=0xEF => 3,
                    0xF0..=0xF7 => 4,
                    _ => 1,
                }
                .min(line.len() - i);
                out.push(Cell { bytes: line[i..i + len].to_vec(), width: 1, attr });
                col += 1;
                i += len;
            }
        }
    }
    out
}

/// Split cells into screen rows of `width` columns (one row when chopping),
/// the first `skip` columns left out (scrolled horizontally, which chops).
fn rows_of(cells: Vec<Cell>, width: usize, chop: bool, skip: usize) -> Vec<Vec<Cell>> {
    let mut rows = alloc::vec![Vec::new()];
    let mut w = 0;
    let chop = chop || skip > 0;
    let mut col = 0;
    for c in cells {
        // Columns scrolled past go; sequences (no width) stay.
        if col < skip && c.width > 0 {
            col += c.width;
            continue;
        }
        if w + c.width > width && w > 0 {
            if chop {
                continue;
            }
            rows.push(Vec::new());
            w = 0;
        }
        w += c.width;
        rows.last_mut().unwrap().push(c);
    }
    rows
}

/// The names TAB completes the word left of the cursor with: its
/// directory's entries (the current directory's without a `/`), and
/// whether each is a directory.
fn complete_names(line: &lineedit::Line) -> Vec<(Vec<u8>, bool)> {
    let start = line.text[..line.cursor].iter().rposition(|&c| c == b' ').map_or(0, |p| p + 1);
    let word = &line.text[start..line.cursor];
    let dir = match word.iter().rposition(|&c| c == b'/') {
        Some(0) => b"/".to_vec(),
        Some(p) => word[..p].to_vec(),
        None => b".".to_vec(),
    };
    let entries = fs::read_dir(&dir).unwrap_or_default();
    entries
        .iter()
        .filter(|e| e.name != b"." && e.name != b"..")
        .map(|e| {
            let full = [dir.as_slice(), b"/", &e.name].concat();
            (e.name.clone(), fs::stat(&full).is_ok_and(|s| s.mode & fs::S_IFMT == fs::S_IFDIR))
        })
        .collect()
}

/// `{`'s search (less(1)): from the `nth` (1-based) `open` in line
/// `from`, the line holding its matching `close`; backward from the
/// `nth` `close` for `}`. `line` gives a line's text.
pub fn bracket_match(
    line: &mut dyn FnMut(usize) -> Option<Vec<u8>>,
    from: usize,
    (open, close): (u8, u8),
    nth: usize,
    forward: bool,
) -> Option<usize> {
    let first = line(from)?;
    let (mine, other) = if forward { (open, close) } else { (close, open) };
    let at = first.iter().enumerate().filter(|(_, c)| **c == mine).nth(nth.max(1) - 1)?.0;
    let mut depth = 0usize;
    let mut l = from;
    let mut text = first;
    let mut i = at as isize;
    loop {
        while (0..text.len() as isize).contains(&i) {
            let c = text[i as usize];
            if c == mine {
                depth += 1;
            } else if c == other {
                depth -= 1;
                if depth == 0 {
                    return Some(l);
                }
            }
            i += if forward { 1 } else { -1 };
        }
        if forward {
            l += 1;
            text = line(l)?;
            i = 0;
        } else {
            l = l.checked_sub(1)?;
            text = line(l)?;
            i = text.len() as isize - 1;
        }
    }
}

/// `text` as an extended regular expression matching it as it is (^R).
fn escape(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for &c in text {
        if b"\\.[]()*+?{}|^$".contains(&c) {
            out.push(b'\\');
        }
        out.push(c);
    }
    out
}

/// A log file (`-o`, `s`): made, emptied or appended to.
fn open_log(name: &[u8], append: bool) -> Result<i32, slate_rt::Errno> {
    let how = if append { fs::O_APPEND } else { fs::O_TRUNC };
    fs::open(name, fs::O_WRONLY | fs::O_CREAT | fs::O_CLOEXEC | how, 0o644)
}

/// `-L`: LESSOPEN is not used.
static NO_LESSOPEN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Lines read back from a file, kept for the screens that need them.
const CACHED_LINES: usize = 512;

/// One input: a file (or LESSOPEN's replacement for it) or a pipe, read
/// as needed. A file keeps only where its lines start and reads them
/// again when shown; a pipe's lines are kept, as they cannot be read
/// again.
struct Input {
    name: Vec<u8>,
    fd: i32,
    seekable: bool,
    /// Where each complete line starts.
    starts: Vec<u64>,
    /// Bytes read so far, and how many of them are past the last newline.
    scanned: u64,
    partial: Vec<u8>,
    /// A pipe's complete lines, from line `dropped` on (the ones before
    /// went for `-B`'s limit), and their bytes.
    kept: Vec<Vec<u8>>,
    dropped: usize,
    kept_bytes: usize,
    /// `-B`: the most bytes of a pipe kept.
    limit: Option<usize>,
    /// `-o`, `s`: a pipe's text is copied here as it is read.
    log: Option<i32>,
    eof: bool,
    cache: BTreeMap<usize, Vec<u8>>,
    /// LESSOPEN's work: the replacement file (`-` for an input pipe) and
    /// the command that made it, for LESSCLOSE.
    preprocessed: Option<(Vec<u8>, Option<i32>)>,
}

/// `name` quoted for the shell.
fn shell_quote(name: &[u8]) -> Vec<u8> {
    let mut q = alloc::vec![b'\''];
    for &c in name {
        if c == b'\'' {
            q.extend_from_slice(b"'\\''");
        } else {
            q.push(c);
        }
    }
    q.push(b'\'');
    q
}

/// A LESSOPEN or LESSCLOSE command: each `%s` the next of `names`
/// (quoted), `%%` a percent sign.
fn preprocessor_command(template: &[u8], names: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut next = names.iter();
    let mut i = 0;
    while i < template.len() {
        match (template[i], template.get(i + 1)) {
            (b'%', Some(b's')) => {
                out.extend(shell_quote(next.next().copied().unwrap_or(b"")));
                i += 2;
            }
            (b'%', Some(b'%')) => {
                out.push(b'%');
                i += 2;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Run `cmd` with the shell, its output on a pipe: (pid, read end).
fn spawn_reading(cmd: &[u8]) -> Option<(i32, i32)> {
    let (r, w) = process::pipe(fs::O_CLOEXEC).ok()?;
    match process::fork() {
        Ok(0) => {
            let _ = process::dup2(w, 1);
            let argv = [b"sh".to_vec(), b"-c".to_vec(), cmd.to_vec()];
            let _ = process::execve(b"/bin/sh", &argv, slate_rt::env::vars());
            process::exit_now(127);
        }
        Ok(pid) => {
            let _ = io::close(w);
            Some((pid, r))
        }
        Err(_) => {
            let _ = io::close(r);
            let _ = io::close(w);
            None
        }
    }
}

impl Input {
    fn open(name: &[u8]) -> Result<Input, (Vec<u8>, slate_rt::Errno)> {
        match Input::preprocessed(name) {
            Ok(Some(i)) => return Ok(i),
            Ok(None) => {}
            Err(e) => return Err(e),
        }
        let fd = Input::open_plain(name).map_err(|e| (name.to_vec(), e))?;
        Ok(Input::from_fd(name, fd))
    }

    fn open_plain(name: &[u8]) -> Result<i32, slate_rt::Errno> {
        let fd = if name == b"-" {
            0
        } else {
            if fs::stat(name)?.is_dir() {
                return Err(slate_rt::Errno::EISDIR);
            }
            fs::open(name, fs::O_RDONLY | fs::O_CLOEXEC, 0)?
        };
        Ok(fd)
    }

    fn from_fd(name: &[u8], fd: i32) -> Input {
        let seekable = fd != 0 && fs::fstat(fd).is_ok_and(|s| s.is_file());
        Input {
            name: name.to_vec(),
            fd,
            seekable,
            starts: alloc::vec![0],
            scanned: 0,
            partial: Vec::new(),
            kept: Vec::new(),
            dropped: 0,
            kept_bytes: 0,
            limit: None,
            log: None,
            eof: false,
            cache: BTreeMap::new(),
            preprocessed: None,
        }
    }

    /// LESSOPEN (less(1), INPUT PREPROCESSOR): `|cmd %s` gives the text
    /// on its output (`||` lets an empty output with status 0 count), a
    /// plain `cmd %s` names a replacement file; `-` after the bars covers
    /// standard input too. None: the original file is shown.
    fn preprocessed(name: &[u8]) -> Result<Option<Input>, (Vec<u8>, slate_rt::Errno)> {
        if NO_LESSOPEN.load(core::sync::atomic::Ordering::Relaxed) {
            return Ok(None);
        }
        let Some(open) = slate_rt::env::var(b"LESSOPEN").filter(|v| !v.is_empty()) else { return Ok(None) };
        let (bars, rest) = match open.as_slice() {
            [b'|', b'|', rest @ ..] => (2, rest),
            [b'|', rest @ ..] => (1, rest),
            rest => (0, rest),
        };
        let (stdin_too, template) = match rest.strip_prefix(b"-") {
            Some(r) => (true, r),
            None => (false, rest),
        };
        // Exactly one %s (`%%` is a percent sign), as less(1) asks.
        let mut count = 0;
        let mut k = 0;
        while k < template.len() {
            match (template[k], template.get(k + 1)) {
                (b'%', Some(b's')) => {
                    count += 1;
                    k += 2;
                }
                (b'%', Some(b'%')) => k += 2,
                _ => k += 1,
            }
        }
        if count != 1 {
            io::err(b"LESSOPEN ignored: must contain exactly one %s\n");
            return Ok(None);
        }
        if name == b"-" && !stdin_too {
            return Ok(None);
        }
        let cmd = preprocessor_command(template, &[name]);
        let Some((pid, r)) = spawn_reading(&cmd) else { return Ok(None) };
        if bars == 0 {
            let out = io::read_to_end(r).unwrap_or_default();
            let _ = io::close(r);
            let _ = process::wait(pid, 0);
            let replacement = out.split(|&c| c == b'\n').next().unwrap_or_default().to_vec();
            if replacement.is_empty() {
                return Ok(None);
            }
            // A replacement that cannot be opened is that file's error.
            let fd = Input::open_plain(&replacement).map_err(|e| (replacement.clone(), e))?;
            let mut i = Input::from_fd(name, fd);
            i.preprocessed = Some((replacement, None));
            return Ok(Some(i));
        }
        // An input pipe: the text is its output, unless there is none.
        let mut first = [0u8; 4096];
        let n = io::read(r, &mut first).unwrap_or(0);
        if n == 0 {
            let _ = io::close(r);
            let st = process::wait(pid, 0).map_or(1, |(_, s)| s);
            if !(bars == 2 && process::exited(st) == Some(0)) {
                return Ok(None);
            }
            let mut i = Input::from_fd(name, -1);
            i.eof = true;
            i.preprocessed = Some((b"-".to_vec(), None));
            return Ok(Some(i));
        }
        let mut i = Input::from_fd(name, r);
        i.seekable = false;
        i.preprocessed = Some((b"-".to_vec(), Some(pid)));
        i.take(&first[..n]);
        Ok(Some(i))
    }

    /// Lines known so far (the last one may still be growing).
    fn count(&self) -> usize {
        let complete = self.starts.len() - 1;
        complete + usize::from(self.eof && self.tail_len() > 0)
    }

    /// Bytes after the last newline (a file's are not kept).
    fn tail_len(&self) -> u64 {
        self.scanned - self.starts.last().copied().unwrap_or(0)
    }

    /// Record `data`, the next bytes of the input.
    fn take(&mut self, data: &[u8]) {
        let base = self.scanned;
        for (i, &c) in data.iter().enumerate() {
            if c == b'\n' {
                self.starts.push(base + i as u64 + 1);
            }
        }
        self.scanned += data.len() as u64;
        if !self.seekable {
            if let Some(fd) = self.log {
                let _ = io::write_all(fd, data);
            }
            // A pipe's lines are kept whole.
            let mut rest = data;
            while let Some(p) = rest.iter().position(|&c| c == b'\n') {
                let mut line = core::mem::take(&mut self.partial);
                line.extend_from_slice(&rest[..p]);
                self.kept_bytes += line.len() + 1;
                self.kept.push(line);
                rest = &rest[p + 1..];
            }
            self.partial.extend_from_slice(rest);
            // -B: past the limit the oldest lines go (shown as `?`).
            if let Some(max) = self.limit {
                let mut gone = 0;
                while self.kept_bytes > max && gone + 1 < self.kept.len() {
                    self.kept_bytes -= self.kept[gone].len() + 1;
                    gone += 1;
                }
                self.kept.drain(..gone);
                self.dropped += gone;
            }
        }
    }

    /// `-o`, `s`: copy a pipe's text to `fd`, what was read already first.
    fn start_log(&mut self, fd: i32) {
        for l in &self.kept {
            let _ = io::write_all(fd, l);
            let _ = io::write_all(fd, b"\n");
        }
        let _ = io::write_all(fd, &self.partial);
        self.log = Some(fd);
    }

    /// Read more; `wait`: block for it (else only what is there now).
    /// False at the end.
    fn read_more(&mut self, wait: bool) -> bool {
        if self.fd < 0 {
            self.eof = true;
            return false;
        }
        if !wait && !self.seekable {
            let mut fds = [io::PollFd { fd: self.fd, events: io::POLLIN, revents: 0 }];
            if io::poll(&mut fds, 0).unwrap_or(0) == 0 {
                return false;
            }
        }
        let mut buf = alloc::vec![0u8; 64 * 1024];
        let r = if self.seekable { io::pread(self.fd, &mut buf, self.scanned) } else { io::read(self.fd, &mut buf) };
        match r {
            Ok(n) if n > 0 => {
                self.take(&buf[..n]);
                // A file read to its size is at its end (its last line
                // and the count are known), as less(1) shows them.
                if self.seekable && n < buf.len() && fs::fstat(self.fd).is_ok_and(|st| self.scanned >= st.size as u64) {
                    self.eof = true;
                }
                true
            }
            _ => {
                self.eof = true;
                false
            }
        }
    }

    /// Read until line `n` exists (or the end).
    fn ensure(&mut self, n: usize) {
        while self.count() <= n && !self.eof {
            self.read_more(true);
        }
    }

    fn all(&mut self) {
        while !self.eof {
            self.read_more(true);
        }
    }

    /// Line `n` without its newline, if there is one.
    fn line(&mut self, n: usize) -> Option<Vec<u8>> {
        self.ensure(n);
        if n >= self.count() {
            return None;
        }
        if !self.seekable {
            if n < self.dropped {
                return Some(b"?".to_vec());
            }
            return Some(self.kept.get(n - self.dropped).cloned().unwrap_or_else(|| self.partial.clone()));
        }
        if let Some(l) = self.cache.get(&n) {
            return Some(l.clone());
        }
        let from = self.starts[n];
        let to = self.starts.get(n + 1).copied().unwrap_or(self.scanned);
        let mut buf = alloc::vec![0u8; (to - from) as usize];
        let mut got = 0;
        while got < buf.len() {
            match io::pread(self.fd, &mut buf[got..], from + got as u64) {
                Ok(0) | Err(_) => break,
                Ok(k) => got += k,
            }
        }
        buf.truncate(got);
        if buf.last() == Some(&b'\n') {
            buf.pop();
        }
        if self.cache.len() >= CACHED_LINES {
            // Forget the line farthest from this one.
            let far = *self.cache.keys().max_by_key(|&&k| k.abs_diff(n)).unwrap_or(&n);
            self.cache.remove(&far);
        }
        self.cache.insert(n, buf.clone());
        Some(buf)
    }

    /// Where line `n` starts, if read that far.
    fn offset(&self, n: usize) -> Option<u64> {
        self.starts.get(n).copied()
    }

    /// The file's size when known (the end was read, or it is a file).
    fn size(&self) -> Option<u64> {
        if self.eof {
            return Some(self.scanned);
        }
        if self.seekable { fs::fstat(self.fd).ok().map(|s| s.size as u64) } else { None }
    }

    /// More data may have come (F): look again from where reading stopped.
    fn refresh(&mut self) {
        self.eof = false;
        // A last line without its newline may grow: read it again.
        self.cache.retain(|&k, _| k + 1 < self.starts.len());
    }
}

impl Drop for Input {
    fn drop(&mut self) {
        if self.fd > 0 {
            let _ = io::close(self.fd);
        }
        if let Some(fd) = self.log.take() {
            let _ = io::close(fd);
        }
        if let Some((replacement, pid)) = self.preprocessed.take() {
            if let Some(p) = pid {
                let _ = process::kill(p, 13); // SIGPIPE, as a reader leaving would
                let _ = process::wait(p, 0);
            }
            // LESSCLOSE (less(1)): the original name and the replacement.
            if let Some(close) = slate_rt::env::var(b"LESSCLOSE").filter(|v| !v.is_empty()) {
                let cmd = preprocessor_command(&close, &[&self.name, &replacement]);
                let argv = [b"sh".to_vec(), b"-c".to_vec(), cmd];
                let _ = process::run(b"/bin/sh", &argv);
            }
        }
    }
}

/// `-j`: where on the screen the target line goes (a search's match, a
/// line jumped to).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Jump {
    /// Row N (1 the top); negative counts from the bottom.
    Row(i64),
    /// This fraction of the way down.
    Fraction(f64),
}

impl Jump {
    fn parse(v: &[u8]) -> Option<Jump> {
        let s = core::str::from_utf8(v).ok()?;
        if let Some(f) = s.strip_prefix('.') {
            let n: u64 = f.parse().ok()?;
            let scale = f.bytes().fold(1.0, |s, _| s * 10.0);
            return Some(Jump::Fraction(n as f64 / scale));
        }
        s.parse().ok().map(Jump::Row)
    }
}

/// Which prompt string (`-P` sets each; `-m` and `-M` choose).
#[derive(Clone, Debug)]
struct Prompts {
    short: Vec<u8>,
    medium: Vec<u8>,
    long: Vec<u8>,
    equals: Vec<u8>,
    /// 0 short, 1 medium (-m), 2 long (-M).
    style: u8,
}

impl Default for Prompts {
    fn default() -> Prompts {
        Prompts {
            short: prompt::SHORT.as_bytes().to_vec(),
            medium: prompt::MEDIUM.as_bytes().to_vec(),
            long: prompt::LONG.as_bytes().to_vec(),
            equals: prompt::EQUALS.as_bytes().to_vec(),
            style: 0,
        }
    }
}

/// What a prompt says, gathered before it is expanded.
struct Snapshot {
    name: Option<Vec<u8>>,
    index: usize,
    files: usize,
    next: Option<Vec<u8>>,
    lines: [Option<usize>; 5],
    offsets: [Option<u64>; 5],
    size: Option<u64>,
    total: Option<usize>,
    end: bool,
    first: bool,
    page: usize,
    tags: bool,
    editor: Vec<u8>,
}

fn which_index(w: prompt::Which) -> usize {
    match w {
        prompt::Which::Top => 0,
        prompt::Which::Middle => 1,
        prompt::Which::Bottom => 2,
        prompt::Which::After => 3,
        prompt::Which::Target => 4,
    }
}

impl prompt::Facts for Snapshot {
    fn name(&self) -> Option<Vec<u8>> {
        self.name.clone()
    }
    fn index(&self) -> usize {
        self.index
    }
    fn files(&self) -> usize {
        self.files
    }
    fn next_name(&self) -> Option<Vec<u8>> {
        self.next.clone()
    }
    fn line(&self, w: prompt::Which) -> Option<usize> {
        self.lines[which_index(w)]
    }
    fn offset(&self, line: usize) -> Option<u64> {
        self.lines.iter().position(|&l| l == Some(line)).and_then(|i| self.offsets[i])
    }
    fn size(&self) -> Option<u64> {
        self.size
    }
    fn lines(&self) -> Option<usize> {
        self.total
    }
    fn at_end(&self) -> bool {
        self.end
    }
    fn first(&self) -> bool {
        self.first
    }
    fn page(&self) -> usize {
        self.page
    }
    fn tags(&self) -> bool {
        self.tags
    }
    fn editor(&self) -> Vec<u8> {
        self.editor.clone()
    }
}

/// Where a tag search stands: its entries and the one shown.
struct TagList {
    tags: Vec<tags::Tag>,
    at: usize,
}

struct Pager {
    files: Vec<Vec<u8>>,
    index: usize,
    input: Input,
    top: usize,
    opts: Opts,
    term: Term,
    pattern: Option<(Vec<u8>, bool)>,
    regex: Option<Regex>,
    marks: BTreeMap<char, (usize, usize)>,
    previous: (usize, usize),
    message: Option<String>,
    first_screen: bool,
    tabs: Tabs,
    jump: Option<Jump>,
    /// `-z`: the rows a screen moves.
    window: Option<i64>,
    prompts: Prompts,
    bindings: Vec<keys::Binding>,
    /// Keys an extra string typed, before the terminal's.
    queued: alloc::collections::VecDeque<Key>,
    last_shell: Option<Vec<u8>>,
    tag_list: Option<TagList>,
    tags_file: Vec<u8>,
    /// The file shown before this one (`#` in shell commands).
    previous_file: Option<Vec<u8>>,
    /// `&`: lines shown only if they match each (or, negated, don't).
    filters: Vec<(Regex, bool)>,
    /// Columns scrolled right, and the step (`-#`, a count given).
    shift: usize,
    shift_step: Option<usize>,
    /// The selected OSC 8 link: its line and where it is.
    link: Option<(usize, links::Link)>,
    /// Command lines' keys and history (and where it is kept).
    edits: Vec<keys::EditBinding>,
    history: history::History,
    history_file: Option<Vec<u8>>,
    /// `-B`'s limit for pipes.
    buffers: Option<usize>,
}

/// Which history a command line uses.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Hist {
    Search,
    Shell,
    None,
}

/// A key as lesskey symbols.
fn syms(k: Key) -> Vec<keys::Sym> {
    use keys::*;
    match k {
        Key::Char(c) => {
            let mut b = [0u8; 4];
            c.encode_utf8(&mut b).bytes().map(Sym::from).collect()
        }
        Key::Ctrl(c) => alloc::vec![Sym::from(c & 0x1f)],
        Key::Alt(c) => {
            let mut v = alloc::vec![0x1b];
            let mut b = [0u8; 4];
            v.extend(c.encode_utf8(&mut b).bytes().map(Sym::from));
            v
        }
        Key::Enter => alloc::vec![Sym::from(b'\r')],
        Key::Tab => alloc::vec![Sym::from(b'\t')],
        Key::Backspace => alloc::vec![K_BACKSPACE],
        Key::Delete => alloc::vec![K_DELETE],
        Key::Esc => alloc::vec![0x1b],
        Key::Up => alloc::vec![K_UP],
        Key::Down => alloc::vec![K_DOWN],
        Key::Left => alloc::vec![K_LEFT],
        Key::Right => alloc::vec![K_RIGHT],
        Key::Home => alloc::vec![K_HOME],
        Key::End => alloc::vec![K_END],
        Key::PageUp => alloc::vec![K_PAGE_UP],
        Key::PageDown => alloc::vec![K_PAGE_DOWN],
        Key::Insert => alloc::vec![K_INSERT],
        // less never turns mouse reporting on.
        Key::Resize | Key::Eof | Key::Mouse { .. } => Vec::new(),
    }
}

/// An extra string's bytes as keys.
fn typed(extra: &[u8]) -> Vec<Key> {
    extra
        .iter()
        .map(|&b| match b {
            b'\n' | b'\r' => Key::Enter,
            0x1b => Key::Esc,
            0..=0x1f => Key::Ctrl(b | 0x60),
            b => Key::Char(char::from(b)),
        })
        .collect()
}

impl Pager {
    fn text_rows(&self) -> usize {
        self.term.rows.saturating_sub(1).max(1)
    }

    fn gutter(&self) -> usize {
        if self.opts.numbers { 8 } else { 0 }
    }

    /// The target row (`-j`), 0 the top.
    fn jump_row(&self) -> usize {
        let rows = self.text_rows();
        match self.jump {
            None => 0,
            Some(Jump::Row(n)) if n > 0 => (n as usize - 1).min(rows - 1),
            Some(Jump::Row(n)) if n < 0 => rows.saturating_sub(n.unsigned_abs() as usize),
            Some(Jump::Row(_)) => 0,
            Some(Jump::Fraction(f)) => ((rows as f64 * f) as usize).min(rows - 1),
        }
    }

    /// Show line `l` at the target row.
    fn show_at(&mut self, l: usize) {
        let mut top = self.next_shown(l).or_else(|| self.prev_shown(l)).unwrap_or(l);
        for _ in 0..self.jump_row() {
            match self.prev_shown(top) {
                Some(p) => top = p,
                None => break,
            }
        }
        self.top = top;
    }

    /// Whether line `l` passes the filters (`&`).
    fn visible(&mut self, l: usize) -> bool {
        if self.filters.is_empty() {
            return true;
        }
        let Some(text) = self.input.line(l) else { return false };
        self.filters.iter().all(|(re, negate)| re.is_match(&text) != *negate)
    }

    /// The first shown line at or after `l`.
    fn next_shown(&mut self, mut l: usize) -> Option<usize> {
        loop {
            self.input.ensure(l);
            if l >= self.input.count() {
                return None;
            }
            if self.visible(l) {
                return Some(l);
            }
            l += 1;
        }
    }

    /// The last shown line before `l`.
    fn prev_shown(&mut self, l: usize) -> Option<usize> {
        (0..l).rev().find(|&k| self.visible(k))
    }

    /// The rows a screen moves (`-z`).
    fn screenful(&self) -> usize {
        let rows = self.text_rows();
        match self.window {
            Some(n) if n > 0 => n as usize,
            Some(n) if n < 0 => rows.saturating_sub(n.unsigned_abs() as usize).max(1),
            _ => rows,
        }
    }

    fn matches(&self, line: &[u8]) -> Vec<(usize, usize)> {
        let mut v = Vec::new();
        let Some(re) = &self.regex else { return v };
        let mut pos = 0;
        while pos <= line.len() {
            match re.find_at(line, pos).and_then(|c| c[0]) {
                Some((a, b)) if b > a => {
                    v.push((a, b));
                    pos = b;
                }
                Some((a, _)) => pos = a + 1,
                None => break,
            }
        }
        v
    }

    /// The screen rows from line `top`: (line index, cells), at most `n`.
    fn screen(&mut self, top: usize, n: usize) -> Vec<(usize, Vec<Cell>, bool)> {
        let width = self.term.cols.saturating_sub(self.gutter()).max(1);
        let mut out = Vec::new();
        let mut l = top;
        while out.len() < n {
            let Some(at) = self.next_shown(l) else { break };
            l = at;
            let Some(line) = self.input.line(l) else { break };
            let mut m = self.matches(&line);
            // The selected link shows as a match does.
            if let Some((ll, k)) = &self.link
                && *ll == l
            {
                m.push((k.start, k.end));
            }
            let c = cells(&line, &m, self.opts.raw_control, &self.tabs);
            let rows = rows_of(c, width, self.opts.chop, self.shift);
            for (k, r) in rows.into_iter().enumerate() {
                if out.len() >= n {
                    break;
                }
                out.push((l, r, k == 0));
            }
            l += 1;
        }
        out
    }

    fn at_end(&mut self) -> bool {
        let rows = self.text_rows();
        let shown = self.screen(self.top, rows + 1);
        shown.len() <= rows && shown.last().is_none_or(|(l, _, _)| self.next_shown(*l + 1).is_none())
    }

    /// What prompts and messages can say about the screen now.
    fn snapshot(&mut self, end: bool) -> Snapshot {
        let rows = self.text_rows();
        let shown = self.screen(self.top, rows);
        let bottom = shown.last().map(|s| s.0);
        let middle = shown.get(shown.len() / 2).map(|s| s.0);
        let target = shown.get(self.jump_row()).map(|s| s.0).or(bottom);
        let after = bottom.map(|b| b + 1);
        let lines = [(!shown.is_empty()).then_some(self.top), middle, bottom, after, target];
        let offsets = lines.map(|l| l.and_then(|l| self.input.offset(l)));
        let editor =
            slate_rt::env::var(b"VISUAL").or_else(|| slate_rt::env::var(b"EDITOR")).unwrap_or_else(|| b"etch".to_vec());
        Snapshot {
            name: (self.input.name != b"-").then(|| self.input.name.clone()),
            index: self.index + 1,
            files: self.files.len(),
            next: self.files.get(self.index + 1).cloned(),
            lines,
            offsets,
            size: self.input.size(),
            total: self.input.eof.then(|| self.input.count()),
            end,
            first: self.first_screen,
            page: rows,
            tags: self.tag_list.is_some(),
            editor,
        }
    }

    fn draw(&mut self) {
        let rows = self.text_rows();
        let shown = self.screen(self.top, rows);
        let gutter = self.gutter();
        let t = &mut self.term;
        t.cursor(false);
        for r in 0..rows {
            t.goto(r, 0);
            match shown.get(r) {
                Some((l, cells, first)) => {
                    if gutter > 0 {
                        if *first {
                            t.put(alloc::format!("{:>7} ", l + 1).as_bytes());
                        } else {
                            t.put(b"        ");
                        }
                    }
                    let mut attr = Attr::Normal;
                    for c in cells {
                        if c.attr != attr {
                            t.put(b"\x1b[0m");
                            match c.attr {
                                Attr::Bold => t.put(b"\x1b[1m"),
                                Attr::Underline => t.put(b"\x1b[4m"),
                                Attr::Match => t.put(b"\x1b[7m"),
                                Attr::Normal => {}
                            }
                            attr = c.attr;
                        }
                        t.put(&c.bytes);
                    }
                    t.put(b"\x1b[0m");
                }
                None => t.put(b"~"),
            }
            t.clear_eol();
        }
        t.goto(rows, 0);
        let end = shown.len() < rows || {
            let last = shown.last().map_or(0, |s| s.0);
            self.input.ensure(last + 1);
            last + 1 >= self.input.count() && self.screen_fits_tail(&shown)
        };
        // The prompt (-P, -m, -M); an empty one shows a colon.
        let prompt = match self.message.take() {
            Some(m) => m,
            None => {
                let snap = self.snapshot(end);
                let p = match self.prompts.style {
                    1 => &self.prompts.medium,
                    2 => &self.prompts.long,
                    _ => &self.prompts.short,
                };
                // While filtering, `&` starts the prompt (less(1)).
                let amp = if self.filters.is_empty() { "" } else { "&" };
                alloc::format!("{amp}{}", prompt::text(p, &snap))
            }
        };
        let t = &mut self.term;
        if prompt.is_empty() {
            t.put(b":");
        } else {
            t.reverse(true);
            t.put(prompt.as_bytes());
            t.reverse(false);
        }
        t.clear_eol();
        t.cursor(true);
        t.flush();
        self.first_screen = false;
    }

    fn screen_fits_tail(&mut self, shown: &[(usize, Vec<Cell>, bool)]) -> bool {
        // The last shown row is the last row of the last line.
        let Some((l, _, _)) = shown.last() else { return true };
        let rows = self.screen(*l, usize::MAX / 2);
        let count = rows.iter().filter(|r| r.0 == *l).count();
        shown.iter().filter(|r| r.0 == *l).count() == count
    }

    /// Move forward by `n` screen rows (whole lines).
    fn forward(&mut self, n: usize) {
        for _ in 0..n {
            if self.at_end() {
                return;
            }
            if let Some(next) = self.next_shown(self.top + 1) {
                self.top = next;
            }
        }
    }

    fn back(&mut self, n: usize) {
        for _ in 0..n {
            match self.prev_shown(self.top) {
                Some(p) => self.top = p,
                None => break,
            }
        }
    }

    fn goto_end(&mut self) {
        self.input.all();
        let count = self.input.count();
        let Some(last) = self.prev_shown(count) else {
            self.top = 0;
            return;
        };
        self.bottom_at(last);
    }

    /// Show line `l` on the bottom row (as far as there are lines above).
    fn bottom_at(&mut self, l: usize) {
        let rows = self.text_rows();
        let mut top = l;
        while let Some(p) = self.prev_shown(top) {
            // The rows from `p` through line `l` must fit.
            if self.screen(p, rows + 1).iter().filter(|s| s.0 <= l).count() > rows {
                break;
            }
            top = p;
        }
        self.top = top;
    }

    fn set_pattern(&mut self, pat: &[u8], forward: bool) -> bool {
        let icase = self.opts.ignore_case || (self.opts.smart_case && !pat.iter().any(u8::is_ascii_uppercase));
        match Regex::new(pat, Options { icase, ..Options::extended() }) {
            Ok(r) => {
                self.regex = Some(r);
                self.pattern = Some((pat.to_vec(), forward));
                true
            }
            Err(e) => {
                self.message = Some(alloc::format!("{e}"));
                false
            }
        }
    }

    /// Search for the next matching line after (or before) the target
    /// line, and show it there.
    fn search(&mut self, forward: bool, count: usize) {
        let Some(re) = &self.regex else {
            self.message = Some(String::from("No previous regular expression"));
            return;
        };
        let re = re.clone();
        let mut line = self.top + self.jump_row();
        for _ in 0..count.max(1) {
            let found = if forward {
                let mut l = line + 1;
                loop {
                    match self.input.line(l) {
                        Some(t) if re.is_match(&t) && self.visible(l) => break Some(l),
                        Some(_) => l += 1,
                        None => break None,
                    }
                }
            } else {
                (0..line).rev().find(|&l| self.input.line(l).is_some_and(|t| re.is_match(&t)) && self.visible(l))
            };
            match found {
                Some(l) => line = l,
                None => {
                    self.message = Some(String::from("Pattern not found"));
                    return;
                }
            }
        }
        self.previous = (self.index, self.top);
        self.show_at(line);
    }

    /// The next key: one an extra string typed, else the terminal's.
    fn next_key(&mut self) -> Option<Key> {
        if let Some(k) = self.queued.pop_front() {
            return Some(k);
        }
        self.term.key(None)
    }

    /// Read a command line (for /, ?, &, !, |, -, :e), with less(1)'s
    /// LINE EDITING keys (and #line-edit's) and `hist`'s history.
    fn read_line(&mut self, prompt: &str) -> Option<Vec<u8>> {
        self.read_line_in(prompt, Hist::None)
    }

    fn read_line_in(&mut self, prompt: &str, hist: Hist) -> Option<Vec<u8>> {
        use keys::Edit;
        let mut line = lineedit::Line::default();
        let mut seq: Vec<keys::Sym> = Vec::new();
        // TAB's place among the names it completes, and the line before.
        let mut completing: Option<(usize, lineedit::Line)> = None;
        let mut literal = false;
        let list = match hist {
            Hist::Search => self.history.search.clone(),
            Hist::Shell => self.history.shell.clone(),
            Hist::None => Vec::new(),
        };
        let done = loop {
            let rows = self.text_rows();
            let t = &mut self.term;
            t.goto(rows, 0);
            t.put(prompt.as_bytes());
            t.put(&line.shown());
            t.clear_eol();
            t.goto(rows, prompt.chars().count() + line.column());
            t.flush();
            let k = self.next_key()?;
            if literal {
                // ^V: the next key as it is (a control key as its byte).
                literal = false;
                match k {
                    Key::Ctrl(c) => line.insert(&[c & 0x1f]),
                    Key::Esc => line.insert(&[0x1b]),
                    Key::Tab => line.insert(b"\t"),
                    Key::Char(c) => line.insert(c.encode_utf8(&mut [0u8; 4]).as_bytes()),
                    _ => {}
                }
                continue;
            }
            seq.extend(syms(k));
            let edit = match keys::lookup_edit(&self.edits, &seq) {
                Some(None) => continue,
                Some(Some(e)) => Some(e),
                None => None,
            };
            seq.clear();
            if !matches!(edit, Some(Edit::ForwComplete | Edit::BackComplete)) {
                completing = None;
            }
            match (edit, k) {
                (Some(Edit::Abort), _) => return None,
                (Some(Edit::Literal), _) => literal = true,
                (Some(e @ (Edit::ForwComplete | Edit::BackComplete | Edit::Expand)), _) => {
                    let (n, base) = match completing.take() {
                        Some((n, b)) if e == Edit::ForwComplete => (n + 1, b),
                        Some((n, b)) => (n.wrapping_sub(1), b),
                        None => (if e == Edit::BackComplete { usize::MAX } else { 0 }, line.clone()),
                    };
                    let names = complete_names(&base);
                    if e == Edit::Expand {
                        // ^L: every match, if they fit.
                        let mut all = base.clone();
                        for i in 0..names.len() {
                            if let Some(c) = lineedit::complete(&base, &names, i) {
                                let word = &c.text[..c.cursor];
                                let start = word.iter().rposition(|&c| c == b' ').map_or(0, |p| p + 1);
                                if i > 0 {
                                    all.insert(b" ");
                                }
                                all.insert(&word[start..]);
                            }
                        }
                        if !names.is_empty() {
                            let start = base.text[..base.cursor].iter().rposition(|&c| c == b' ').map_or(0, |p| p + 1);
                            all.text.drain(start..base.cursor);
                            all.cursor -= base.cursor - start;
                        }
                        line = all;
                    } else if let Some(c) = lineedit::complete(&base, &names, n % names.len().max(1)) {
                        line = c;
                        completing = Some((n % names.len(), base));
                    } else {
                        self.term.bell();
                    }
                }
                (Some(e), _) => line.apply(e, &list),
                (None, Key::Enter | Key::Ctrl(b'j')) => break line.text,
                (None, Key::Esc | Key::Ctrl(b'c') | Key::Ctrl(b'g') | Key::Eof) => return None,
                (None, Key::Backspace) => {
                    if !line.backspace() {
                        return None;
                    }
                }
                (None, Key::Ctrl(b'u')) => {
                    if !line.kill() {
                        return None;
                    }
                }
                (None, Key::Char(c)) => line.insert(c.encode_utf8(&mut [0u8; 4]).as_bytes()),
                (None, Key::Ctrl(c)) if prompt.starts_with('&') || prompt.starts_with('/') => {
                    // ^N and ^R are the search and filter modifiers.
                    line.insert(&[c & 0x1f]);
                }
                _ => {}
            }
        };
        let list = match hist {
            Hist::Search => Some(&mut self.history.search),
            Hist::Shell => Some(&mut self.history.shell),
            Hist::None => None,
        };
        if let Some(list) = list {
            history::History::add(list, &done);
            self.save_history();
        }
        Some(done)
    }

    /// `_`: an option's setting, unchanged (`-`'s words).
    fn display_option(&mut self, o: char) {
        let on = |b: bool| if b { "on" } else { "off" };
        self.message = Some(match o {
            'N' => alloc::format!("Line numbers {}", on(self.opts.numbers)),
            'S' => alloc::format!("Chop long lines {}", on(self.opts.chop)),
            'i' | 'I' => {
                alloc::format!("Ignore case in searches {}", on(self.opts.smart_case || self.opts.ignore_case))
            }
            'R' | 'r' => alloc::format!("Raw control characters {}", on(self.opts.raw_control)),
            'F' => alloc::format!("Quit if one screen {}", on(self.opts.quit_if_one_screen)),
            'X' => alloc::format!("No termcap init {}", on(self.opts.no_init)),
            '#' => alloc::format!("Horizontal shift {} columns", self.shift_step.unwrap_or(self.half_width())),
            'o' | 'O' => match self.input.log {
                Some(_) => String::from("Log file is open"),
                None => String::from("No log file"),
            },
            'B' | 'b' => match self.buffers {
                Some(n) => alloc::format!("Buffers for pipes: {} KB", n / 1024),
                None => String::from("Buffers for pipes: as needed"),
            },
            o => alloc::format!("There is no -{o} option"),
        });
    }

    fn half_width(&self) -> usize {
        (self.term.cols.saturating_sub(self.gutter()) / 2).max(1)
    }

    /// `&`: only lines matching the pattern (`!` or ^N first: not
    /// matching; ^R: the text as it is); an empty one shows them all.
    fn filter(&mut self) {
        let Some(mut p) = self.read_line_in("&/", Hist::Search) else { return };
        if p.is_empty() {
            self.filters.clear();
            return;
        }
        let (mut negate, mut literal) = (false, false);
        while let Some(&c) = p.first() {
            match c {
                b'!' | 0x0e => negate = true,
                0x12 => literal = true,
                _ => break,
            }
            p.remove(0);
        }
        let pat = if literal { escape(&p) } else { p };
        let icase = self.opts.ignore_case || (self.opts.smart_case && !pat.iter().any(u8::is_ascii_uppercase));
        match Regex::new(&pat, Options { icase, ..Options::extended() }) {
            Ok(r) => self.filters.push((r, negate)),
            Err(e) => {
                self.message = Some(alloc::format!("{e}"));
                return;
            }
        }
        let top = self.top;
        match self.next_shown(top).or_else(|| self.prev_shown(top)) {
            Some(t) => self.top = t,
            None => self.message = Some(String::from("Pattern not found")),
        }
    }

    /// `{ ( [` (`forward`) and `} ) ]`: the matching bracket's line on the
    /// bottom row (or the top one).
    fn bracket(&mut self, forward: bool, pair: (u8, u8), nth: usize) {
        let rows = self.text_rows();
        let shown = self.screen(self.top, rows);
        let from = if forward { self.top } else { shown.last().map_or(self.top, |s| s.0) };
        let input = &mut self.input;
        let mut get = |l: usize| input.line(l);
        match bracket_match(&mut get, from, pair, nth, forward) {
            Some(l) if forward => self.bottom_at(l),
            Some(l) => self.top = l,
            None => self.message = Some(String::from("No bracket in top line")),
        }
    }

    /// The widest line shown (columns), for ESC-} and ESC-].
    fn widest(&mut self) -> usize {
        let rows = self.text_rows();
        let (shift, chop) = (self.shift, self.opts.chop);
        self.shift = 0;
        self.opts.chop = true;
        let mut widest = 0;
        let mut l = self.top;
        for _ in 0..rows {
            let Some(at) = self.next_shown(l) else { break };
            if let Some(line) = self.input.line(at) {
                widest = widest.max(cells(&line, &[], self.opts.raw_control, &self.tabs).iter().map(|c| c.width).sum());
            }
            l = at + 1;
        }
        (self.shift, self.opts.chop) = (shift, chop);
        widest
    }

    /// The OSC 8 link after (or before) the selected one, or the top
    /// line's start: selected, and its line shown.
    fn next_link(&mut self, forward: bool, n: usize) {
        let (mut line, mut pos) = match &self.link {
            Some((l, k)) => (*l, k.start),
            None => (self.top, if forward { 0 } else { usize::MAX }),
        };
        if self.link.is_none() && !forward {
            line = self.top;
        }
        for _ in 0..n.max(1) {
            let mut found = None;
            let mut l = line;
            while let Some(text) = self.input.line(l) {
                let ls = links::links(&text);
                let hit = if forward {
                    ls.into_iter().find(|k| l > line || k.start > pos || (self.link.is_none() && k.start >= pos))
                } else {
                    ls.into_iter().rev().find(|k| l < line || k.start < pos)
                };
                if hit.is_some() && self.visible(l) {
                    found = hit.map(|k| (l, k));
                    break;
                }
                if forward {
                    l += 1;
                } else if l == 0 {
                    break;
                } else {
                    l -= 1;
                }
            }
            let Some((l, k)) = found else {
                self.message = Some(String::from("No OSC 8 hyperlink"));
                return;
            };
            (line, pos) = (l, k.start);
            self.link = Some((l, k));
        }
        self.show_link();
    }

    /// ^O^L: the selected link's line, at the target row unless shown.
    fn show_link(&mut self) {
        let Some((l, _)) = self.link.clone() else {
            self.message = Some(String::from("No OSC 8 hyperlink selected"));
            return;
        };
        let rows = self.text_rows();
        if !self.screen(self.top, rows).iter().any(|s| s.0 == l) {
            self.show_at(l);
        }
    }

    /// ^O^O: the selected link opened by LESS_OSC8_OPEN_<scheme> (or _ANY);
    /// a `#id` link jumps to the link with that id.
    fn open_link(&mut self) {
        let Some((_, k)) = self.link.clone() else {
            self.message = Some(String::from("No OSC 8 hyperlink selected"));
            return;
        };
        if let Some(id) = k.uri.strip_prefix('#') {
            self.input.all();
            for l in 0..self.input.count() {
                let Some(text) = self.input.line(l) else { break };
                if let Some(t) = links::links(&text).into_iter().find(|t| t.id.as_deref() == Some(id)) {
                    self.link = Some((l, t));
                    self.show_link();
                    return;
                }
            }
            self.message = Some(alloc::format!("No link with id {id}"));
            return;
        }
        let scheme = links::scheme(&k.uri);
        let var = |n: &str| slate_rt::env::var(n.as_bytes()).filter(|v| !v.is_empty());
        let Some(handler) = var(&alloc::format!("LESS_OSC8_OPEN_{scheme}")).or_else(|| var("LESS_OSC8_OPEN_ANY"))
        else {
            self.message = Some(alloc::format!("No handler for \"{scheme}\" link type"));
            return;
        };
        // A leading ^P: no "link done"; then `-`: the command not shown.
        let (quiet, rest) = match handler.strip_prefix(&[0x10]) {
            Some(r) => (true, r),
            None => (false, handler.as_slice()),
        };
        let rest = rest.strip_prefix(b"-").unwrap_or(rest);
        let cmd = [rest, b" ", &shell_quote(k.uri.as_bytes())].concat();
        self.term.suspend();
        let argv = alloc::vec![b"sh".to_vec(), b"-c".to_vec(), cmd];
        let _ = process::run(b"/bin/sh", &argv);
        if !quiet {
            io::err(b"link done  (press RETURN)");
            let _ = self.term.key(None);
        }
        self.term.resume();
        self.term.clear();
    }

    /// `-o` and `s`: a pipe's text copied to a file, after asking before
    /// one that is there (`-O`: overwritten at once).
    fn log_file(&mut self, overwrite: bool) {
        if self.input.seekable {
            self.message = Some(String::from("Input is not a pipe"));
            return;
        }
        if self.input.log.is_some() {
            self.message = Some(String::from("Log file is already in use"));
            return;
        }
        let Some(name) = self.read_line("log file: ").filter(|n| !n.is_empty()) else { return };
        let mut append = false;
        if !overwrite && fs::exists(&name) {
            let q = alloc::format!("Warning: \"{}\" exists; Overwrite, Append or Don't log? ", lossy(&name));
            match self.read_line(&q).as_deref().and_then(|a| a.first().copied()) {
                Some(b'O' | b'o') => {}
                Some(b'A' | b'a') => append = true,
                _ => return,
            }
        }
        match open_log(&name, append) {
            Ok(fd) => self.input.start_log(fd),
            Err(e) => self.message = Some(alloc::format!("{}: {e}", lossy(&name))),
        }
    }

    /// Write the history file (LESSHISTFILE), keeping LESSHISTSIZE lines.
    fn save_history(&mut self) {
        let Some(path) = self.history_file.clone() else { return };
        let size = slate_rt::env::var(b"LESSHISTSIZE")
            .and_then(|v| core::str::from_utf8(&v).ok()?.parse().ok())
            .unwrap_or(history::SIZE);
        let _ = fs::write_file(&path, &self.history.text(size), 0o600);
    }

    fn open(&mut self, index: usize) -> bool {
        match Input::open(&self.files[index]) {
            Ok(i) => {
                self.marks.insert('\0', (self.index, self.top));
                if self.index != index || self.input.name != self.files[index] {
                    self.previous_file = Some(self.input.name.clone());
                }
                self.input = i;
                self.input.limit = self.buffers;
                self.index = index;
                self.top = 0;
                self.link = None;
                self.shift = 0;
                self.first_screen = true;
                true
            }
            Err((n, e)) => {
                self.message = Some(alloc::format!("{}: {e}", lossy(&n)));
                false
            }
        }
    }

    /// Run `cmd` with the shell on the terminal, then wait for RETURN.
    fn run_shell(&mut self, cmd: &[u8], input: Option<Vec<u8>>) {
        self.term.suspend();
        let argv = alloc::vec![b"sh".to_vec(), b"-c".to_vec(), cmd.to_vec()];
        match input {
            None => {
                let _ = process::run(b"/bin/sh", &argv);
            }
            Some(text) => {
                // `|`: the text on the command's standard input.
                if let Ok((r, w)) = process::pipe(fs::O_CLOEXEC) {
                    match process::fork() {
                        Ok(0) => {
                            let _ = process::dup2(r, 0);
                            let _ = process::execve(b"/bin/sh", &argv, slate_rt::env::vars());
                            process::exit_now(127);
                        }
                        Ok(pid) => {
                            let _ = io::close(r);
                            let _ = signal::set(signal::SIGPIPE, signal::Disposition::Ignore);
                            let _ = io::write_all(w, &text);
                            let _ = io::close(w);
                            let _ = process::wait(pid, 0);
                        }
                        Err(_) => {
                            let _ = io::close(r);
                            let _ = io::close(w);
                        }
                    }
                }
            }
        }
        io::err(b"!done  (press RETURN)");
        let _ = self.term.key(None);
        self.term.resume();
        self.term.clear();
    }

    /// `!`: a shell command, `%` the file's name, `#` the one before,
    /// `!` the last command (as less(1) says); empty, a shell.
    fn shell(&mut self) {
        let Some(line) = self.read_line_in("!", Hist::Shell) else { return };
        let mut cmd = Vec::new();
        for &c in &line {
            match c {
                b'%' => cmd.extend_from_slice(&self.input.name),
                b'#' => cmd.extend_from_slice(self.previous_file.as_deref().unwrap_or_default()),
                b'!' => cmd.extend_from_slice(self.last_shell.as_deref().unwrap_or_default()),
                c => cmd.push(c),
            }
        }
        if cmd.is_empty() {
            cmd = slate_rt::env::var(b"SHELL").unwrap_or_else(|| b"/bin/sh".to_vec());
        }
        self.last_shell = Some(cmd.clone());
        self.run_shell(&cmd, None);
    }

    /// `#`: a shell command with prompt escapes expanded (`%f` and the rest).
    fn pshell(&mut self) {
        let Some(line) = self.read_line_in("#", Hist::Shell) else { return };
        let end = self.at_end();
        let snap = self.snapshot(end);
        let cmd = prompt::expand(&line, &snap);
        self.run_shell(&cmd, None);
    }

    /// `|m cmd`: the text from the top line to mark m (`.` the screen,
    /// `^` the start, `$` the end) through a shell command.
    fn pipe(&mut self) {
        let Some(Key::Char(m)) = self.next_key() else { return };
        let rows = self.text_rows();
        let (from, to) = match m {
            '.' => {
                let shown = self.screen(self.top, rows);
                (self.top, shown.last().map_or(self.top, |s| s.0))
            }
            '^' => (0, self.top),
            '$' => {
                self.input.all();
                (self.top, self.input.count().saturating_sub(1))
            }
            m => match self.marks.get(&m).copied() {
                Some((i, l)) if i == self.index => (self.top.min(l), self.top.max(l)),
                _ => {
                    self.message = Some(String::from("Mark not set"));
                    return;
                }
            },
        };
        let Some(cmd) = self.read_line_in("!", Hist::Shell) else { return };
        let mut text = Vec::new();
        for l in from..=to {
            if let Some(line) = self.input.line(l) {
                text.extend(line);
                text.push(b'\n');
            }
        }
        self.run_shell(&cmd, Some(text));
    }

    /// `v`: LESSEDIT (default `%E ?lm+%lm. %g`) with the shell.
    fn edit(&mut self) {
        if self.input.name == b"-" {
            self.message = Some(String::from("Cannot edit standard input"));
            return;
        }
        let template = slate_rt::env::var(b"LESSEDIT").unwrap_or_else(|| prompt::EDIT.as_bytes().to_vec());
        let end = self.at_end();
        let snap = self.snapshot(end);
        let cmd = prompt::expand(&template, &snap);
        self.term.suspend();
        let argv = alloc::vec![b"sh".to_vec(), b"-c".to_vec(), cmd];
        let _ = process::run(b"/bin/sh", &argv);
        self.term.resume();
        let top = self.top;
        if self.open(self.index) {
            self.top = top;
        }
    }

    /// `=`: the message less(1) gives.
    fn info(&mut self) {
        let end = self.at_end();
        let snap = self.snapshot(end);
        self.message = Some(prompt::text(&self.prompts.equals.clone(), &snap));
    }

    /// A tag (`-t`, `:t`): its entries in the tags file, the first shown.
    fn find_tag(&mut self, name: &[u8]) {
        let data = fs::read_file(&self.tags_file).unwrap_or_default();
        let list = tags::find(&data, name);
        if list.is_empty() {
            self.message = Some(String::from("No such tag in tags file"));
            return;
        }
        self.tag_list = Some(TagList { tags: list, at: 0 });
        self.show_tag();
    }

    fn show_tag(&mut self) {
        let Some(t) = self.tag_list.as_ref().map(|l| l.tags[l.at].clone()) else { return };
        let i = match self.files.iter().position(|f| *f == t.file) {
            Some(i) => i,
            None => {
                self.files.push(t.file.clone());
                self.files.len() - 1
            }
        };
        if !self.open(i) {
            return;
        }
        let line = match &t.address {
            tags::Address::Line(n) => Some(n.saturating_sub(1)),
            a => {
                let mut l = 0;
                loop {
                    match self.input.line(l) {
                        Some(text) if a.matches(&text) => break Some(l),
                        Some(_) => l += 1,
                        None => break None,
                    }
                }
            }
        };
        match line {
            Some(l) => self.show_at(l),
            None => self.message = Some(String::from("Tag not found")),
        }
    }

    fn follow(&mut self) {
        let watch = if self.input.name == b"-" {
            None
        } else {
            use slate_abi::watch as w;
            fs::watch_open(true).ok().filter(|&fd| {
                fs::watch_add(fd, &self.input.name, w::MODIFY | w::ATTRIB | w::MOVE_SELF | w::DELETE_SELF).is_ok()
            })
        };
        loop {
            self.input.refresh();
            // What has come, without waiting for a pipe's end.
            while self.input.read_more(false) {}
            self.input.eof = true;
            self.goto_end();
            self.message = Some(String::from("Waiting for data... (interrupt to abort)"));
            self.draw();
            // A pipe tells by being readable; a file, by its watch (ADR
            // 0149): no timer.
            let other = watch.unwrap_or(self.input.fd);
            match self.term.key_or(other) {
                None => {
                    if let Some(w) = watch {
                        let mut events = [0u8; 4096];
                        let _ = io::read(w, &mut events);
                    }
                }
                Some(Key::Resize) => {}
                Some(_) => break,
            }
        }
        if let Some(w) = watch {
            let _ = io::close(w);
        }
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
        let _ = self.next_key();
    }

    /// The next command: keys read until they name a binding.
    fn command(&mut self) -> Option<(keys::Action, Vec<u8>, Option<Key>)> {
        let mut seq: Vec<keys::Sym> = Vec::new();
        loop {
            let k = self.next_key()?;
            if k == Key::Resize {
                return Some((keys::Action::Repaint, Vec::new(), Some(k)));
            }
            if k == Key::Eof {
                return Some((keys::Action::Quit, Vec::new(), Some(k)));
            }
            seq.extend(syms(k));
            match keys::lookup(&self.bindings, &seq) {
                keys::Lookup::Found(b) => return Some((b.action, b.extra.clone(), Some(k))),
                keys::Lookup::More => {}
                keys::Lookup::None => {
                    self.term.bell();
                    return Some((keys::Action::Nothing, Vec::new(), Some(k)));
                }
            }
        }
    }

    fn run(&mut self) -> i32 {
        use keys::Action as A;
        let mut count: Option<usize> = None;
        loop {
            self.draw();
            let Some((action, extra, key)) = self.command() else { continue };
            if action == A::Digit {
                if let Some(Key::Char(d @ '0'..='9')) = key {
                    count = Some(count.unwrap_or(0) * 10 + (d as usize - '0' as usize));
                }
                continue;
            }
            let n = count.take();
            let half = (self.text_rows() / 2).max(1);
            match action {
                A::Quit => return extra.first().map_or(0, |&c| i32::from(c)),
                A::ForwScreen => {
                    let n = n.unwrap_or(self.screenful());
                    self.forward(n)
                }
                A::BackScreen => {
                    let n = n.unwrap_or(self.screenful());
                    self.back(n)
                }
                A::ForwWindow => {
                    if let Some(w) = n {
                        self.window = Some(w as i64);
                    }
                    let n = self.screenful();
                    self.forward(n)
                }
                A::BackWindow => {
                    if let Some(w) = n {
                        self.window = Some(w as i64);
                    }
                    let n = self.screenful();
                    self.back(n)
                }
                A::ForwLine => self.forward(n.unwrap_or(1)),
                A::BackLine => self.back(n.unwrap_or(1)),
                A::ForwScroll => self.forward(n.unwrap_or(half)),
                A::BackScroll => self.back(n.unwrap_or(half)),
                A::GotoLine => {
                    self.previous = (self.index, self.top);
                    let l = n.map_or(0, |n| n.saturating_sub(1));
                    self.input.ensure(l);
                    let l = l.min(self.input.count().saturating_sub(1));
                    if n.is_some() { self.show_at(l) } else { self.top = 0 }
                }
                A::GotoEnd => {
                    self.previous = (self.index, self.top);
                    match n {
                        Some(n) => {
                            self.input.ensure(n.saturating_sub(1));
                            let l = n.saturating_sub(1).min(self.input.count().saturating_sub(1));
                            self.show_at(l);
                        }
                        None => self.goto_end(),
                    }
                }
                A::Percent => {
                    self.input.all();
                    let l = self.input.count() * n.unwrap_or(0).min(100) / 100;
                    self.show_at(l);
                }
                A::ForwSearch | A::BackSearch => {
                    let forward = action == A::ForwSearch;
                    if let Some(p) = self.read_line_in(if forward { "/" } else { "?" }, Hist::Search) {
                        let ok = if p.is_empty() { self.regex.is_some() } else { self.set_pattern(&p, forward) };
                        if ok {
                            if let Some(pt) = &mut self.pattern {
                                pt.1 = forward;
                            }
                            self.search(forward, n.unwrap_or(1));
                        }
                    }
                }
                A::RepeatSearch => {
                    let fwd = self.pattern.as_ref().is_none_or(|p| p.1);
                    self.search(fwd, n.unwrap_or(1));
                }
                A::ReverseSearch => {
                    let fwd = self.pattern.as_ref().is_none_or(|p| p.1);
                    self.search(!fwd, n.unwrap_or(1));
                }
                A::SetMark => {
                    if let Some(Key::Char(c)) = self.next_key() {
                        self.marks.insert(c, (self.index, self.top));
                    }
                }
                A::GotoMark => match self.next_key() {
                    Some(Key::Char('\'')) => {
                        let (i, t) = self.previous;
                        self.previous = (self.index, self.top);
                        if i == self.index {
                            self.top = t;
                        }
                    }
                    Some(Key::Char(c)) => match self.marks.get(&c).copied() {
                        Some((i, t)) if i == self.index => {
                            self.previous = (self.index, self.top);
                            self.top = t;
                        }
                        _ => self.message = Some(String::from("Mark not set")),
                    },
                    _ => {}
                },
                A::ToggleOption => {
                    self.queued.extend(typed(&extra));
                    let Some(Key::Char(o)) = self.next_key() else { continue };
                    if o == 't' {
                        // -t: a tag to find.
                        if let Some(tag) = self.read_line("Tag: ") {
                            self.find_tag(&tag);
                        }
                        continue;
                    }
                    if o == 'o' || o == 'O' {
                        // -o, s: a log file for a pipe.
                        self.log_file(o == 'O');
                        continue;
                    }
                    let (flag, name) = match o {
                        'N' => (&mut self.opts.numbers, "Line numbers"),
                        'S' => (&mut self.opts.chop, "Chop long lines"),
                        'i' => (&mut self.opts.smart_case, "Ignore case in searches"),
                        'I' => (&mut self.opts.ignore_case, "Ignore case in searches"),
                        _ => {
                            self.message = Some(alloc::format!("There is no -{o} option"));
                            continue;
                        }
                    };
                    *flag = !*flag;
                    self.message = Some(alloc::format!("{name} {}", if *flag { "on" } else { "off" }));
                    if let Some((p, f)) = self.pattern.clone() {
                        self.set_pattern(&p, f);
                    }
                }
                A::NextFile => {
                    if self.index + 1 < self.files.len() {
                        self.open(self.index + 1);
                    } else {
                        self.message = Some(String::from("No next file"));
                    }
                }
                A::PrevFile => {
                    if self.index > 0 {
                        self.open(self.index - 1);
                    } else {
                        self.message = Some(String::from("No previous file"));
                    }
                }
                A::IndexFile => {
                    self.open(n.map_or(0, |n| n.saturating_sub(1)).min(self.files.len() - 1));
                }
                A::Examine => {
                    if let Some(f) = self.read_line("Examine: ").filter(|f| !f.is_empty()) {
                        self.files.insert(self.index + 1, f);
                        self.open(self.index + 1);
                    }
                }
                A::NextTag | A::PrevTag => match self.tag_list.as_mut() {
                    Some(l) if action == A::NextTag && l.at + 1 < l.tags.len() => {
                        l.at += 1;
                        self.show_tag();
                    }
                    Some(l) if action == A::PrevTag && l.at > 0 => {
                        l.at -= 1;
                        self.show_tag();
                    }
                    Some(_) => self.message = Some(String::from("No more tags")),
                    None => self.message = Some(String::from("No tags")),
                },
                A::Status => self.info(),
                A::Visual => self.edit(),
                A::Shell => self.shell(),
                A::Pshell => self.pshell(),
                A::Pipe => self.pipe(),
                A::ForwForever => self.follow(),
                A::Help => self.help(),
                A::Version => self.message = Some(String::from("less (Slate) 0.2")),
                A::RepaintFlush => {
                    let top = self.top;
                    if self.input.name != b"-" && self.open(self.index) {
                        self.top = top;
                    }
                }
                A::Repaint => self.term.clear(),
                A::Invalid => self.term.bell(),
                A::DisplayOption => {
                    if let Some(Key::Char(o)) = self.next_key() {
                        self.display_option(o);
                    }
                }
                A::Filter => self.filter(),
                A::ForwBracket | A::BackBracket => {
                    // The pair: the extra string's, else the next two keys.
                    let pair = match extra.as_slice() {
                        [a, b, ..] => Some((*a, *b)),
                        _ => match (self.next_key(), self.next_key()) {
                            (Some(Key::Char(a)), Some(Key::Char(b))) if a.is_ascii() && b.is_ascii() => {
                                Some((a as u8, b as u8))
                            }
                            _ => None,
                        },
                    };
                    if let Some(pair) = pair {
                        self.bracket(action == A::ForwBracket, pair, n.unwrap_or(1));
                    }
                    count = None;
                    continue;
                }
                A::LeftScroll | A::RightScroll | A::RightLimitScroll => {
                    if let Some(n) = n {
                        self.shift_step = Some(n);
                    }
                    let step = self.shift_step.unwrap_or(self.half_width());
                    if action == A::LeftScroll {
                        self.shift = self.shift.saturating_sub(step);
                    } else {
                        let next = self.shift + step;
                        self.shift = if action == A::RightLimitScroll {
                            let width = self.term.cols.saturating_sub(self.gutter());
                            next.min(self.widest().saturating_sub(width)).max(self.shift)
                        } else {
                            next
                        };
                    }
                }
                A::NoScroll => self.shift = 0,
                A::EndScroll => {
                    let width = self.term.cols.saturating_sub(self.gutter());
                    self.shift = self.widest().saturating_sub(width);
                }
                A::Osc8Forw => self.next_link(true, n.unwrap_or(1)),
                A::Osc8Back => self.next_link(false, n.unwrap_or(1)),
                A::Osc8Jump => self.show_link(),
                A::Osc8Open => self.open_link(),
                A::Nothing | A::Digit => {}
            }
            if !matches!(action, A::Quit | A::ToggleOption) {
                self.queued.extend(typed(&extra));
            }
        }
    }
}

fn cat(files: &[Vec<u8>]) -> i32 {
    let mut status = 0;
    for f in files {
        // LESSOPEN applies here too: its text is what is copied.
        let mut input = match Input::open(f) {
            Ok(i) => i,
            Err((n, e)) => {
                io::err(alloc::format!("{}: {e}\n", lossy(&n)).as_bytes());
                status = 1;
                continue;
            }
        };
        let mut l = 0;
        while let Some(line) = input.line(l) {
            io::out(&line);
            if l + 1 < input.count() || input.tail_len() == 0 {
                io::out(b"\n");
            }
            l += 1;
            // A pipe's lines are not needed again.
            if !input.seekable {
                input.kept.get_mut(l - 1).map(core::mem::take);
            }
        }
    }
    status
}

/// The lesskey source files to read (lesskey(5), less(1) KEY BINDINGS):
/// `--lesskey-src` and LESSKEYIN, else the user's default place; then the
/// system's; and LESSKEY_CONTENT / `--lesskey-content` text.
fn lesskey_sources(src: &[Vec<u8>], content: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut texts = Vec::new();
    let env = |n: &[u8]| slate_rt::env::var(n).filter(|v| !v.is_empty());
    let mut user: Vec<Vec<u8>> = src.to_vec();
    if let Some(f) = env(b"LESSKEYIN") {
        user.push(f);
    }
    if user.is_empty() {
        let home = env(b"HOME").unwrap_or_default();
        let config = env(b"XDG_CONFIG_HOME").unwrap_or_else(|| [home.as_slice(), b"/.config"].concat());
        for f in [[config.as_slice(), b"/lesskey"].concat(), [home.as_slice(), b"/.lesskey"].concat()] {
            if fs::exists(&f) {
                user.push(f);
                break;
            }
        }
    }
    for f in user {
        if let Ok(t) = fs::read_file(&f) {
            texts.push(t);
        }
    }
    for c in content.iter().cloned().chain(env(b"LESSKEY_CONTENT")) {
        // Lines may be separated by semicolons (`\;` is one).
        let mut t = Vec::new();
        let mut i = 0;
        while i < c.len() {
            match (c[i], c.get(i + 1)) {
                (b'\\', Some(b';')) => {
                    t.push(b';');
                    i += 2;
                }
                (b';', _) => {
                    t.push(b'\n');
                    i += 1;
                }
                (x, _) => {
                    t.push(x);
                    i += 1;
                }
            }
        }
        texts.push(t);
    }
    let system = env(b"LESSKEYIN_SYSTEM").unwrap_or_else(|| b"/etc/syslesskey".to_vec());
    if let Ok(t) = fs::read_file(&system) {
        texts.push(t);
    }
    texts
}

pub fn main() -> i32 {
    let args = slate_rt::env::args();
    let mut opts = Opts::default();
    let mut files = Vec::new();
    let mut start_cmd: Option<Vec<u8>> = None;
    let mut tabs = Tabs::default();
    let (mut jump, mut window) = (None, None);
    let mut prompts = Prompts::default();
    let mut tag: Option<Vec<u8>> = None;
    let mut tags_file = b"tags".to_vec();
    let (mut key_src, mut key_content): (Vec<Vec<u8>>, Vec<Vec<u8>>) = (Vec::new(), Vec::new());
    let mut no_lessopen = false;
    // -o/-O (and whether to overwrite), -b, -B, -#.
    let mut log: Option<(Vec<u8>, bool)> = None;
    let (mut buffers_kb, mut auto_buffers_off) = (None::<i64>, false);
    let mut shift_step: Option<usize> = None;
    let num = |v: &[u8]| core::str::from_utf8(v).ok().and_then(|s| s.trim().parse::<i64>().ok());
    // Lesskey files may set variables less reads, LESS among them.
    let mut early_src = Vec::new();
    for a in &args[1..] {
        if let Some(f) = a.strip_prefix(b"--lesskey-src=") {
            early_src.push(f.to_vec());
        }
    }
    let lookup = |n: &[u8]| slate_rt::env::var(n);
    let lesskeys: Vec<keys::Lesskey> =
        lesskey_sources(&early_src, &[]).iter().map(|t| keys::parse(t, &lookup)).collect();
    let env = |n: &[u8]| {
        lesskeys.iter().flat_map(|k| k.env.iter()).find(|(a, _)| a == n).map(|(_, v)| v.clone()).or_else(|| lookup(n))
    };
    // LESS in the environment holds default options.
    let env_opts: Vec<Vec<u8>> = env(b"LESS")
        .map(|v| {
            v.split(|c| c.is_ascii_whitespace())
                .filter(|w| !w.is_empty())
                .map(|w| if w.starts_with(b"-") { w.to_vec() } else { [b"-".as_slice(), w].concat() })
                .collect()
        })
        .unwrap_or_default();
    let all: Vec<Vec<u8>> = env_opts.iter().chain(args[1..].iter()).cloned().collect();
    let mut i = 0;
    let bad = |what: &str| -> i32 {
        io::err(alloc::format!("{what}\n").as_bytes());
        1
    };
    while i < all.len() {
        let a = &all[i];
        i += 1;
        if let Some(cmd) = a.strip_prefix(b"+") {
            start_cmd = Some(cmd.to_vec());
            continue;
        }
        if a.len() > 1 && a[0] == b'-' && a != b"--" {
            if let Some(long) = a.strip_prefix(b"--") {
                let (k, v) = match long.iter().position(|&c| c == b'=') {
                    Some(e) => (&long[..e], Some(long[e + 1..].to_vec())),
                    None => (long, None),
                };
                let mut value = || v.clone().or_else(|| all.get(i).cloned().inspect(|_| i += 1)).unwrap_or_default();
                match k {
                    b"LINE-NUMBERS" => opts.numbers = true,
                    b"chop-long-lines" => opts.chop = true,
                    b"ignore-case" => opts.smart_case = true,
                    b"IGNORE-CASE" => opts.ignore_case = true,
                    b"quit-if-one-screen" => opts.quit_if_one_screen = true,
                    b"RAW-CONTROL-CHARS" | b"raw-control-chars" => opts.raw_control = true,
                    b"no-init" => opts.no_init = true,
                    b"long-prompt" => prompts.style = 2,
                    b"no-lessopen" => no_lessopen = true,
                    b"tabs" => match Tabs::parse(&value()) {
                        Some(t) => tabs = t,
                        None => return bad("Invalid number for -x"),
                    },
                    b"jump-target" => jump = Jump::parse(&value()),
                    b"window" => window = core::str::from_utf8(&value()).ok().and_then(|s| s.parse().ok()),
                    b"tag" => tag = Some(value()),
                    b"tag-file" => tags_file = value(),
                    b"prompt" => set_prompt(&mut prompts, &value()),
                    b"lesskey-src" => key_src.push(value()),
                    b"lesskey-content" => key_content.push(value()),
                    b"lesskey-file" => match lesskey_file(&value()) {
                        Ok(src) => key_src.push(src),
                        Err(e) => return bad(&e),
                    },
                    b"log-file" => log = Some((value(), false)),
                    b"LOG-FILE" => log = Some((value(), true)),
                    b"buffers" => buffers_kb = num(&value()),
                    b"auto-buffers" => auto_buffers_off = true,
                    b"shift" => shift_step = num(&value()).filter(|&n| n > 0).map(|n| n as usize),
                    b"version" => {
                        io::out(b"less (Slate) 0.2\n");
                        return 0;
                    }
                    _ => {}
                }
                continue;
            }
            let mut j = 1;
            while j < a.len() {
                let c = a[j];
                j += 1;
                // An option's value: the rest of this word, or the next.
                let mut value = || {
                    let v = if j < a.len() {
                        a[j..].to_vec()
                    } else {
                        all.get(i).cloned().inspect(|_| i += 1).unwrap_or_default()
                    };
                    j = a.len();
                    v
                };
                match c {
                    b'N' => opts.numbers = true,
                    b'S' => opts.chop = true,
                    b'i' => opts.smart_case = true,
                    b'I' => opts.ignore_case = true,
                    b'F' => opts.quit_if_one_screen = true,
                    b'R' | b'r' => opts.raw_control = true,
                    b'X' => opts.no_init = true,
                    b'm' => prompts.style = 1,
                    b'M' => prompts.style = 2,
                    b'L' => no_lessopen = true,
                    b'x' => match Tabs::parse(&value()) {
                        Some(t) => tabs = t,
                        None => return bad("Invalid number for -x"),
                    },
                    b'j' => jump = Jump::parse(&value()),
                    b'z' => window = core::str::from_utf8(&value()).ok().and_then(|s| s.parse().ok()),
                    b't' => tag = Some(value()),
                    b'T' => tags_file = value(),
                    b'P' => set_prompt(&mut prompts, &value()),
                    b'o' => log = Some((value(), false)),
                    b'O' => log = Some((value(), true)),
                    b'b' => buffers_kb = num(&value()),
                    b'B' => auto_buffers_off = true,
                    b'#' => shift_step = num(&value()).filter(|&n| n > 0).map(|n| n as usize),
                    b'k' => match lesskey_file(&value()) {
                        Ok(src) => key_src.push(src),
                        Err(e) => return bad(&e),
                    },
                    // Accepted and not needed: -e -E -s -q -Q -K.
                    _ => {}
                }
            }
            continue;
        }
        if a != b"--" {
            files.push(a.clone());
        }
    }
    if no_lessopen {
        NO_LESSOPEN.store(true, core::sync::atomic::Ordering::Relaxed);
    }
    if files.is_empty() && tag.is_none() {
        if term::isatty(0) {
            io::err(b"Missing filename (\"less --help\" for help)\n");
            return 1;
        }
        files.push(b"-".to_vec());
    }
    if !term::isatty(1) {
        return cat(&files);
    }
    let lesskeys: Vec<keys::Lesskey> =
        lesskey_sources(&key_src, &key_content).iter().map(|t| keys::parse(t, &lookup)).collect();
    let bindings = keys::table(&lesskeys);
    let edits = keys::edit_table(&lesskeys);
    // -B: a pipe keeps -b's kilobytes (64 by default; -1 is no limit).
    let buffers = match (auto_buffers_off, buffers_kb) {
        (true, Some(n)) if n < 0 => None,
        (true, n) => Some(n.unwrap_or(64).max(1) as usize * 1024),
        (false, _) => None,
    };
    let history_file = history_path();
    let history = history_file
        .as_ref()
        .and_then(|f| fs::read_file(f).ok())
        .map(|t| history::History::parse(&t))
        .unwrap_or_default();
    let mut first = None;
    if files.is_empty() {
        files.push(b"-".to_vec());
    }
    for (i, f) in files.iter().enumerate() {
        match Input::open(f) {
            Ok(input) => {
                first = Some((i, input));
                break;
            }
            Err((n, e)) => io::err(alloc::format!("{}: {e}\n", lossy(&n)).as_bytes()),
        }
    }
    let Some((index, mut input)) = first else { return 1 };
    input.limit = buffers;
    // Keys from the terminal (standard input may be the text).
    let fd_in = if term::isatty(0) { 0 } else { fs::open(b"/dev/tty", fs::O_RDONLY | fs::O_CLOEXEC, 0).unwrap_or(2) };
    let _ = signal::set(signal::SIGINT, signal::Disposition::CatchInterrupt);
    let mut p = Pager {
        files,
        index,
        input,
        top: 0,
        opts,
        term: Term::new(fd_in, 1, true),
        pattern: None,
        regex: None,
        marks: BTreeMap::new(),
        previous: (index, 0),
        message: None,
        first_screen: true,
        tabs,
        jump,
        window,
        prompts,
        bindings,
        queued: alloc::collections::VecDeque::new(),
        last_shell: None,
        tag_list: None,
        tags_file,
        previous_file: None,
        filters: Vec::new(),
        shift: 0,
        shift_step,
        link: None,
        edits,
        history,
        history_file,
        buffers,
    };
    // -o/-O: the pipe's text copied to a file (asked first for -o if the
    // file is there).
    if let Some((name, overwrite)) = log {
        if p.input.seekable {
            io::err(b"Log file applies only to a pipe\n");
        } else if !overwrite && fs::exists(&name) {
            p.queued.extend(typed(&name));
            p.queued.push_back(Key::Enter);
            p.log_file(false);
        } else {
            match open_log(&name, false) {
                Ok(fd) => p.input.start_log(fd),
                Err(e) => io::err(alloc::format!("{}: {e}\n", lossy(&name)).as_bytes()),
            }
        }
    }
    if let Some(t) = tag {
        p.find_tag(&t);
    }
    // -F: short enough for one screen means just print it.
    if p.opts.quit_if_one_screen && p.files.len() == 1 {
        let rows = p.text_rows();
        p.input.ensure(rows);
        if p.input.eof && p.screen(0, rows + 1).len() <= rows {
            let lines: Vec<Vec<u8>> = (0..p.input.count()).filter_map(|i| p.input.line(i)).collect();
            drop(p);
            for l in lines {
                io::out(&l);
                io::out(b"\n");
            }
            return 0;
        }
    }
    if !p.opts.no_init {
        p.term.alt_screen(true);
    }
    if let Some(cmd) = start_cmd {
        match cmd.as_slice() {
            b"G" => p.goto_end(),
            c if c.starts_with(b"/") => {
                if p.set_pattern(&c[1..], true) {
                    // A match on the first line counts too.
                    let first = p.input.line(0);
                    if first.is_none_or(|l| !p.regex.as_ref().is_some_and(|r| r.is_match(&l))) {
                        p.search(true, 1);
                    }
                }
            }
            c => {
                let digits: Vec<u8> = c.iter().copied().take_while(u8::is_ascii_digit).collect();
                if let Some(n) = core::str::from_utf8(&digits).ok().and_then(|d| d.parse::<usize>().ok()) {
                    p.input.ensure(n.saturating_sub(1));
                    let l = n.saturating_sub(1).min(p.input.count().saturating_sub(1));
                    p.show_at(l);
                }
            }
        }
    }
    let st = p.run();
    drop(p);
    st
}

/// `-k`: a lesskey file. The binary format of lesskey's before version
/// 582 is not documented and no tool makes it here, so a binary file is
/// refused; a source file is read as `--lesskey-src` would.
fn lesskey_file(name: &[u8]) -> Result<Vec<u8>, String> {
    let data = fs::read_file(name).map_err(|e| alloc::format!("{}: {e}", lossy(name)))?;
    let text = data.iter().all(|&c| c == b'\n' || c == b'\t' || c == b'\r' || c >= 0x20);
    if text {
        Ok(name.to_vec())
    } else {
        Err(alloc::format!("{}: a binary lesskey file; give its source with --lesskey-src", lossy(name)))
    }
}

/// The history file (less(1), LESSHISTFILE): that variable's (`-` or
/// /dev/null: none), else $XDG_STATE_HOME/lesshst, ~/.local/state/lesshst
/// (if the directory is there), else ~/.lesshst.
fn history_path() -> Option<Vec<u8>> {
    let env = |n: &[u8]| slate_rt::env::var(n).filter(|v| !v.is_empty());
    if let Some(f) = env(b"LESSHISTFILE") {
        return (f != b"-" && f != b"/dev/null").then_some(f);
    }
    if let Some(d) = env(b"XDG_STATE_HOME") {
        return Some([d.as_slice(), b"/lesshst"].concat());
    }
    let home = env(b"HOME")?;
    let state = [home.as_slice(), b"/.local/state"].concat();
    if fs::stat(&state).is_ok_and(|s| s.mode & fs::S_IFMT == fs::S_IFDIR) {
        return Some([state.as_slice(), b"/lesshst"].concat());
    }
    Some([home.as_slice(), b"/.lesshst"].concat())
}

/// `-P`: `s`, `m`, `M` or `=` first names the prompt it sets (`h` and
/// `w`, help's and F's, are taken and not used); anything else the short
/// one.
fn set_prompt(p: &mut Prompts, v: &[u8]) {
    match v.split_first() {
        Some((b's', r)) => p.short = r.to_vec(),
        Some((b'm', r)) => p.medium = r.to_vec(),
        Some((b'M', r)) => p.long = r.to_vec(),
        Some((b'=', r)) => p.equals = r.to_vec(),
        Some((b'h' | b'w', _)) => {}
        _ => p.short = v.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(rows: &[Vec<Cell>]) -> Vec<String> {
        rows.iter().map(|r| r.iter().map(|c| String::from_utf8_lossy(&c.bytes).into_owned()).collect()).collect()
    }

    #[test]
    fn rendering() {
        let c = cells(b"a\tb", &[], false, &Tabs::default());
        assert_eq!(c[1].width, 7);
        let c = cells(b"x\x08x_\x08y\x01", &[], false, &Tabs::default());
        assert_eq!((c[0].attr, c[1].attr, c[2].bytes.as_slice()), (Attr::Bold, Attr::Underline, &b"^A"[..]));
        let c = cells(b"\x1b[31mred\x1b[0m", &[], true, &Tabs::default());
        assert_eq!(c.iter().map(|x| x.width).sum::<usize>(), 3);
        let r = rows_of(cells(b"abcdefgh", &[], false, &Tabs::default()), 3, false, 0);
        assert_eq!(text(&r), ["abc", "def", "gh"]);
        let r = rows_of(cells(b"abcdefgh", &[], false, &Tabs::default()), 3, true, 0);
        assert_eq!(text(&r), ["abc"]);
        let c = cells(b"find me", &[(5, 7)], false, &Tabs::default());
        assert_eq!(c[5].attr, Attr::Match);
        // Scrolled right: the first columns go, the line is chopped, and
        // sequences stay.
        let r = rows_of(cells(b"\x1b[1mabcdefgh", &[], true, &Tabs::default()), 3, false, 2);
        assert_eq!(text(&r), ["\x1b[1mcde"]);
        // An OSC 8 link passes through with -R, taking no columns.
        let c = cells(b"\x1b]8;;https://x/\x1b\\x\x1b]8;;\x1b\\", &[], true, &Tabs::default());
        assert_eq!(c.iter().map(|x| x.width).sum::<usize>(), 1);
        assert_eq!(c.len(), 3);
        // Without -R it shows as text.
        let c = cells(b"\x1b]8;;u\x1b\\", &[], false, &Tabs::default());
        assert!(c.iter().map(|x| x.width).sum::<usize>() > 3);
    }

    #[test]
    fn brackets() {
        let lines = [&b"fn x() {"[..], b"    if a { b }", b"}", b"(a [b] (c)"];
        let mut get = |l: usize| lines.get(l).map(|t| t.to_vec());
        assert_eq!(bracket_match(&mut get, 0, (b'{', b'}'), 1, true), Some(2));
        assert_eq!(bracket_match(&mut get, 2, (b'{', b'}'), 1, false), Some(0));
        assert_eq!(bracket_match(&mut get, 1, (b'{', b'}'), 1, true), Some(1));
        assert_eq!(bracket_match(&mut get, 0, (b'(', b')'), 1, true), Some(0));
        assert_eq!(bracket_match(&mut get, 3, (b'(', b')'), 1, true), None, "never closed");
        assert_eq!(bracket_match(&mut get, 3, (b'(', b')'), 2, true), Some(3), "the second one");
        assert_eq!(escape(b"a.b*"), b"a\\.b\\*");
    }
}
