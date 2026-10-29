// SPDX-License-Identifier: MIT OR Apache-2.0

//! Full-screen terminal programs: raw mode, the window size, key input
//! (the VT100/xterm escape sequences terminals send, ECMA-48 syntax) and
//! output with the control functions every terminal emulator supports
//! (CUP, EL, ED, SGR, DECTCEM, the xterm alternate screen).

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;

use slate_rt::term::{self, Termios};
use slate_rt::{io, signal};

/// A key press.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Char(char),
    /// Ctrl and a letter (or `@[\]^_`): the byte's letter, lower case.
    Ctrl(u8),
    Alt(char),
    Enter,
    Tab,
    Backspace,
    Delete,
    Esc,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Insert,
    /// The window changed size (or the program continued after a stop).
    Resize,
    /// End of input: the terminal went away.
    Eof,
    /// The mouse (xterm's SGR reporting, when [`Term::mouse`] is on):
    /// the button (0 left, 1 middle, 2 right, 64 and 65 the wheel up and
    /// down), the cell (from 0), and whether it was pressed or let go.
    Mouse {
        button: u8,
        row: usize,
        col: usize,
        press: bool,
    },
}

/// Decode one key from `buf`: (key, bytes used). `None` if `buf` holds an
/// incomplete sequence.
pub fn decode(buf: &[u8]) -> Option<(Key, usize)> {
    let &c = buf.first()?;
    Some(match c {
        // Enter sends a carriage return; Ctrl-J (a line feed) is a key of
        // its own (etch's justify), and accepts a line where Enter does.
        b'\r' => (Key::Enter, 1),
        b'\n' => (Key::Ctrl(b'j'), 1),
        b'\t' => (Key::Tab, 1),
        0x7F | 0x08 => (Key::Backspace, 1),
        0x1B => {
            let Some(&n) = buf.get(1) else { return Some((Key::Esc, 1)) };
            match n {
                // SGR mouse reporting: CSI < Cb ; Cx ; Cy M (pressed) or m.
                b'[' if buf.get(2) == Some(&b'<') => {
                    let mut i = 3;
                    while buf.get(i).is_some_and(|b| b.is_ascii_digit() || *b == b';') {
                        i += 1;
                    }
                    let fin = *buf.get(i)?;
                    let nums: Vec<usize> = buf[3..i]
                        .split(|&b| b == b';')
                        .map(|p| core::str::from_utf8(p).ok().and_then(|s| s.parse().ok()).unwrap_or(0))
                        .collect();
                    let key = match (fin, nums.as_slice()) {
                        (b'M' | b'm', [b, x, y]) => Key::Mouse {
                            // Shift, Meta and Ctrl (4, 8, 16) and motion (32) aside.
                            button: (*b & !(4 | 8 | 16 | 32)) as u8,
                            row: y.saturating_sub(1),
                            col: x.saturating_sub(1),
                            press: fin == b'M',
                        },
                        _ => Key::Esc,
                    };
                    (key, i + 1)
                }
                b'[' | b'O' => {
                    // CSI/SS3: parameters, then a final byte.
                    let mut i = 2;
                    while buf.get(i).is_some_and(|b| b.is_ascii_digit() || *b == b';') {
                        i += 1;
                    }
                    let fin = *buf.get(i)?;
                    let params = &buf[2..i];
                    let key = match (fin, params) {
                        (b'A', _) => Key::Up,
                        (b'B', _) => Key::Down,
                        (b'C', _) => Key::Right,
                        (b'D', _) => Key::Left,
                        (b'H', _) => Key::Home,
                        (b'F', _) => Key::End,
                        (b'~', b"1" | b"7") => Key::Home,
                        (b'~', b"4" | b"8") => Key::End,
                        (b'~', b"2") => Key::Insert,
                        (b'~', b"3") => Key::Delete,
                        (b'~', b"5") => Key::PageUp,
                        (b'~', b"6") => Key::PageDown,
                        _ => Key::Esc,
                    };
                    (key, i + 1)
                }
                0x1B => (Key::Esc, 1),
                n if n < 0x80 => {
                    let ch = n as char;
                    (Key::Alt(ch.to_ascii_lowercase()), 2)
                }
                _ => (Key::Esc, 1),
            }
        }
        0x00 => (Key::Ctrl(b'@'), 1),
        1..=26 => (Key::Ctrl(b'a' + c - 1), 1),
        28..=31 => (Key::Ctrl(b"\\]^_"[(c - 28) as usize]), 1),
        c if c < 0x80 => (Key::Char(c as char), 1),
        c => {
            // A UTF-8 sequence.
            let n = match c {
                0xC0..=0xDF => 2,
                0xE0..=0xEF => 3,
                0xF0..=0xF7 => 4,
                _ => return Some((Key::Char(char::REPLACEMENT_CHARACTER), 1)),
            };
            if buf.len() < n {
                return None;
            }
            let ch = core::str::from_utf8(&buf[..n])
                .ok()
                .and_then(|s| s.chars().next())
                .unwrap_or(char::REPLACEMENT_CHARACTER);
            (Key::Char(ch), n)
        }
    })
}

/// Display columns of a character: control characters show as `^X`
/// (two); others as Unicode's width table has them (two for wide ones,
/// none for combining marks; slate-term, ADR 0099).
pub fn char_width(c: char) -> usize {
    if (c as u32) < 0x20 || c == '\u{7f}' { 2 } else { slate_term::width::width(c) }
}

/// A terminal in raw mode; restored when dropped.
#[derive(Debug)]
pub struct Term {
    fd_in: i32,
    fd_out: i32,
    saved: Option<Termios>,
    pub rows: usize,
    pub cols: usize,
    out: Vec<u8>,
    pending: Vec<u8>,
    alt: bool,
    signals: bool,
    /// Mouse reporting is on.
    mouse: bool,
}

impl Term {
    /// Raw mode on `fd_in`; output to `fd_out`. With `signals`, Ctrl-C/Z
    /// still signal (less); without, they arrive as keys (etch).
    pub fn new(fd_in: i32, fd_out: i32, signals: bool) -> Term {
        let saved = term::get(fd_in).ok();
        if let Some(t) = saved {
            let mut raw = t;
            raw.lflag &= !(term::ICANON | term::ECHO | term::IEXTEN);
            if !signals {
                raw.lflag &= !term::ISIG;
            }
            raw.iflag &= !(term::ICRNL | term::IXON);
            raw.cc[term::VMIN] = 1;
            raw.cc[term::VTIME] = 0;
            let _ = term::set(fd_in, &raw, true);
        }
        let _ = signal::set(signal::SIGWINCH, signal::Disposition::CatchInterrupt);
        let _ = signal::set(signal::SIGCONT, signal::Disposition::CatchInterrupt);
        let mut t = Term {
            fd_in,
            fd_out,
            saved,
            rows: 24,
            cols: 80,
            out: Vec::new(),
            pending: Vec::new(),
            alt: false,
            signals,
            mouse: false,
        };
        t.update_size();
        t
    }

    pub fn update_size(&mut self) {
        if let Some((r, c)) = term::size(self.fd_out).or_else(|| term::size(self.fd_in)) {
            self.rows = (r as usize).max(3);
            self.cols = (c as usize).max(10);
        }
    }

    /// Switch to (or from) the alternate screen.
    pub fn alt_screen(&mut self, on: bool) {
        self.alt = on;
        self.put(if on { b"\x1b[?1049h" } else { b"\x1b[?1049l" });
    }

    pub fn put(&mut self, b: &[u8]) {
        self.out.extend_from_slice(b);
    }

    pub fn goto(&mut self, row: usize, col: usize) {
        self.put(alloc::format!("\x1b[{};{}H", row + 1, col + 1).as_bytes());
    }

    pub fn clear(&mut self) {
        self.put(b"\x1b[H\x1b[2J");
    }

    pub fn clear_eol(&mut self) {
        self.put(b"\x1b[K");
    }

    pub fn reverse(&mut self, on: bool) {
        self.put(if on { b"\x1b[7m" } else { b"\x1b[0m" });
    }

    /// The colour of what follows (an SGR colour, 0 to 7; `None`: the
    /// terminal's own).
    pub fn fg(&mut self, color: Option<u8>) {
        match color {
            Some(c) => self.put(alloc::format!("\x1b[{}m", 30 + c.min(7)).as_bytes()),
            None => self.put(b"\x1b[39m"),
        }
    }

    /// Report the mouse (xterm's button events, in SGR form) or stop.
    pub fn mouse(&mut self, on: bool) {
        self.mouse = on;
        self.put(if on { b"\x1b[?1000h\x1b[?1006h" } else { b"\x1b[?1006l\x1b[?1000l" });
    }

    pub fn bold(&mut self, on: bool) {
        self.put(if on { b"\x1b[1m" } else { b"\x1b[0m" });
    }

    pub fn cursor(&mut self, visible: bool) {
        self.put(if visible { b"\x1b[?25h" } else { b"\x1b[?25l" });
    }

    pub fn bell(&mut self) {
        self.put(b"\x07");
    }

    pub fn flush(&mut self) {
        if !self.out.is_empty() {
            let _ = io::write_all(self.fd_out, &self.out);
            self.out.clear();
        }
    }

    /// Wait for a key (forever with `None`, else up to `timeout_ms`).
    pub fn key(&mut self, timeout_ms: Option<i32>) -> Option<Key> {
        self.wait(timeout_ms, None)
    }

    /// Wait for a key or for `other` to become readable, whichever comes
    /// first: `None` when `other` is (a followed file changed, a pipe has
    /// more). A caught SIGINT comes as Ctrl-C.
    pub fn key_or(&mut self, other: i32) -> Option<Key> {
        self.wait(None, Some(other))
    }

    fn wait(&mut self, timeout_ms: Option<i32>, other: Option<i32>) -> Option<Key> {
        loop {
            if let Some((k, n)) = decode(&self.pending) {
                // A lone ESC may begin a sequence: wait a moment for more.
                let lone_esc = k == Key::Esc && n == 1 && self.pending.len() == 1;
                if !lone_esc || !self.wait_readable(30) {
                    self.pending.drain(..n);
                    return Some(k);
                }
            }
            let caught = signal::take();
            if caught & ((1 << signal::SIGWINCH) | (1 << signal::SIGCONT)) != 0 {
                self.update_size();
                return Some(Key::Resize);
            }
            if other.is_some() && caught & (1 << signal::SIGINT) != 0 {
                return Some(Key::Ctrl(b'c'));
            }
            let mut fds = [
                io::PollFd { fd: self.fd_in, events: io::POLLIN, revents: 0 },
                io::PollFd { fd: other.unwrap_or(-1), events: io::POLLIN, revents: 0 },
            ];
            match io::poll(&mut fds, timeout_ms.unwrap_or(-1)) {
                Ok(0) => return None,
                Ok(_) => {}
                Err(_) => continue,
            }
            if fds[1].revents != 0 && fds[0].revents == 0 {
                return None;
            }
            let mut buf = [0u8; 64];
            match io::read(self.fd_in, &mut buf) {
                Ok(0) | Err(_) => return Some(Key::Eof),
                Ok(n) => self.pending.extend_from_slice(&buf[..n]),
            }
        }
    }

    fn wait_readable(&mut self, ms: i32) -> bool {
        let mut fds = [io::PollFd { fd: self.fd_in, events: io::POLLIN, revents: 0 }];
        if io::poll(&mut fds, ms).unwrap_or(0) == 0 {
            return false;
        }
        let mut buf = [0u8; 64];
        match io::read(self.fd_in, &mut buf) {
            Ok(n) if n > 0 => {
                self.pending.extend_from_slice(&buf[..n]);
                true
            }
            _ => false,
        }
    }

    /// Leave raw mode (for a subprocess or suspension); `resume` re-enters it.
    pub fn suspend(&mut self) {
        if self.mouse {
            self.put(b"\x1b[?1006l\x1b[?1000l");
        }
        if self.alt {
            self.put(b"\x1b[?1049l");
        }
        self.cursor(true);
        self.flush();
        if let Some(t) = self.saved {
            let _ = term::set(self.fd_in, &t, true);
        }
    }

    pub fn resume(&mut self) {
        if let Some(t) = self.saved {
            let mut raw = t;
            raw.lflag &= !(term::ICANON | term::ECHO | term::IEXTEN);
            if !self.signals {
                raw.lflag &= !term::ISIG;
            }
            raw.iflag &= !(term::ICRNL | term::IXON);
            let _ = term::set(self.fd_in, &raw, true);
        }
        if self.alt {
            self.put(b"\x1b[?1049h");
        }
        if self.mouse {
            self.put(b"\x1b[?1000h\x1b[?1006h");
        }
        self.update_size();
    }
}

impl Drop for Term {
    fn drop(&mut self) {
        self.reverse(false);
        if self.mouse {
            self.put(b"\x1b[?1006l\x1b[?1000l");
        }
        if self.alt {
            self.put(b"\x1b[?1049l");
        }
        self.cursor(true);
        self.flush();
        if let Some(t) = self.saved {
            let _ = term::set(self.fd_in, &t, true);
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn mouse_and_widths() {
        assert_eq!(decode(b"\x1b[<0;10;5M"), Some((Key::Mouse { button: 0, row: 4, col: 9, press: true }, 10)));
        assert_eq!(decode(b"\x1b[<0;10;5m").map(|k| k.0), Some(Key::Mouse { button: 0, row: 4, col: 9, press: false }));
        assert_eq!(decode(b"\x1b[<65;1;1M").map(|k| k.0), Some(Key::Mouse { button: 65, row: 0, col: 0, press: true }));
        assert_eq!(
            decode(b"\x1b[<4;2;3M").map(|k| k.0),
            Some(Key::Mouse { button: 0, row: 2, col: 1, press: true }),
            "shift held"
        );
        assert_eq!(decode(b"\x1b[<0;10"), None, "not all there yet");
        assert_eq!(char_width('a'), 1);
        assert_eq!(char_width('漢'), 2);
        assert_eq!(char_width('\u{301}'), 0);
        assert_eq!(char_width('\u{1}'), 2);
    }

    use super::*;

    #[test]
    fn keys() {
        assert_eq!(decode(b"a"), Some((Key::Char('a'), 1)));
        assert_eq!(decode(b"\x18"), Some((Key::Ctrl(b'x'), 1)));
        assert_eq!(decode(b"\x1b[A"), Some((Key::Up, 3)));
        assert_eq!(decode(b"\x1b[5~x"), Some((Key::PageUp, 4)));
        assert_eq!(decode(b"\x1bOH"), Some((Key::Home, 3)));
        assert_eq!(decode(b"\x1b[1;5C"), Some((Key::Right, 6)));
        assert_eq!(decode(b"\x1bu"), Some((Key::Alt('u'), 2)));
        assert_eq!(decode(b"\x1b"), Some((Key::Esc, 1)));
        assert_eq!(decode(b"\x1b["), None);
        assert_eq!(decode("é".as_bytes()), Some((Key::Char('é'), 2)));
        assert_eq!(decode(&"é".as_bytes()[..1]), None);
        assert_eq!(decode(b"\x7f"), Some((Key::Backspace, 1)));
        assert_eq!(decode(b"\x1f"), Some((Key::Ctrl(b'_'), 1)));
        assert_eq!(char_width('\t'), 2);
    }
}
