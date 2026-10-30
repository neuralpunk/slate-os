// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a key press sends to the program in the terminal: the bytes an
//! xterm sends (the sequences in ECMA-48 syntax that xterm's terminfo
//! entry describes), so programs that expect `TERM=xterm-256color` work.
//! Key codes are evdev's (input-event-codes.h, ADR 0033).

use alloc::string::String;
use alloc::vec::Vec;

use slate_strata_client::mods::{ALT, CTRL, SHIFT};

const KEY_ESC: u16 = 1;
const KEY_BACKSPACE: u16 = 14;
const KEY_TAB: u16 = 15;
const KEY_ENTER: u16 = 28;
const KEY_W: u16 = 17;
const KEY_T: u16 = 20;
const KEY_A: u16 = 30;
const KEY_C: u16 = 46;
const KEY_V: u16 = 47;
const KEY_F1: u16 = 59;
const KEY_F10: u16 = 68;
const KEY_F11: u16 = 87;
const KEY_F12: u16 = 88;
const KEY_KPENTER: u16 = 96;
const KEY_HOME: u16 = 102;
const KEY_UP: u16 = 103;
const KEY_PAGEUP: u16 = 104;
const KEY_LEFT: u16 = 105;
const KEY_RIGHT: u16 = 106;
const KEY_END: u16 = 107;
const KEY_DOWN: u16 = 108;
const KEY_PAGEDOWN: u16 = 109;
const KEY_INSERT: u16 = 110;
const KEY_DELETE: u16 = 111;

/// Keys the terminal keeps for itself (ADR 0038).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Local {
    /// shift + PgUp / PgDn: a page back or forward in the scrollback.
    PageUp,
    PageDown,
    /// ctrl + shift + c / v: the clipboard.
    Copy,
    Paste,
    /// ctrl + shift + a: select all the text.
    SelectAll,
    /// shift + Insert: paste the selection.
    PasteSelection,
    /// ctrl + t (ctrl + shift + t in full-screen programs): a new tab.
    NewTab,
    /// ctrl + shift + w: close the tab.
    CloseTab,
    /// ctrl + PgDn / ctrl + tab, ctrl + PgUp / ctrl + shift + tab: the
    /// next or the previous tab.
    NextTab,
    PreviousTab,
}

/// What a key means to the terminal itself, if anything. `full_screen`:
/// a program has the alternate screen (an editor, top), and ctrl + t is
/// its own (nano's, for one), so only ctrl + shift + t opens a tab.
pub fn local(code: u16, mods: u8, full_screen: bool) -> Option<Local> {
    let only = |m: u8| mods & (SHIFT | CTRL | ALT) == m;
    Some(match code {
        KEY_T if only(CTRL) && !full_screen => Local::NewTab,
        KEY_T if only(SHIFT | CTRL) => Local::NewTab,
        KEY_W if only(SHIFT | CTRL) => Local::CloseTab,
        KEY_PAGEDOWN if only(CTRL) => Local::NextTab,
        KEY_PAGEUP if only(CTRL) => Local::PreviousTab,
        KEY_TAB if only(CTRL) => Local::NextTab,
        KEY_TAB if only(SHIFT | CTRL) => Local::PreviousTab,
        KEY_PAGEUP if only(SHIFT) => Local::PageUp,
        KEY_PAGEDOWN if only(SHIFT) => Local::PageDown,
        KEY_C if only(SHIFT | CTRL) => Local::Copy,
        KEY_V if only(SHIFT | CTRL) => Local::Paste,
        KEY_A if only(SHIFT | CTRL) => Local::SelectAll,
        KEY_INSERT if only(SHIFT) => Local::PasteSelection,
        _ => return None,
    })
}

/// The bytes that paste `text`: newlines become carriage returns (what
/// Enter sends), and with bracketed paste (DECSET 2004) the text is marked
/// with `CSI 200 ~` and `CSI 201 ~` and loses its escape characters, so it
/// cannot end the marking early (xterm's ctlseqs).
pub fn paste(text: &str, bracketed: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() + 12);
    if bracketed {
        out.extend_from_slice(b"\x1b[200~");
    }
    let mut cr = false;
    for &b in text.as_bytes() {
        match b {
            b'\n' if cr => {}
            b'\n' | b'\r' => out.push(b'\r'),
            0x1B if bracketed => {}
            _ => out.push(b),
        }
        cr = b == b'\r';
    }
    if bracketed {
        out.extend_from_slice(b"\x1b[201~");
    }
    out
}

/// xterm's modifier parameter: 1 + shift + 2 alt + 4 ctrl.
fn modifier(mods: u8) -> u8 {
    1 + u8::from(mods & SHIFT != 0) + 2 * u8::from(mods & ALT != 0) + 4 * u8::from(mods & CTRL != 0)
}

/// `CSI 1 ; m X` with modifiers, else `CSI X` (or `SS3 X` in application
/// mode).
fn cursor_key(x: u8, mods: u8, app: bool) -> Vec<u8> {
    match modifier(mods) {
        1 if app => alloc::vec![0x1B, b'O', x],
        1 => alloc::vec![0x1B, b'[', x],
        m => alloc::format!("\x1b[1;{m}{}", x as char).into_bytes(),
    }
}

/// `CSI n ~` with modifiers as `CSI n ; m ~`.
fn tilde(n: u8, mods: u8) -> Vec<u8> {
    match modifier(mods) {
        1 => alloc::format!("\x1b[{n}~").into_bytes(),
        m => alloc::format!("\x1b[{n};{m}~").into_bytes(),
    }
}

/// The bytes for a key: its evdev code, the character it types (None for
/// keys without one) and the protocol's modifier bits. `app_cursor` is
/// the terminal's application-cursor-keys mode (DECCKM).
pub fn encode(code: u16, ch: Option<char>, mods: u8, app_cursor: bool) -> Vec<u8> {
    let alt = mods & ALT != 0;
    let prefix = |mut v: Vec<u8>| {
        if alt {
            v.insert(0, 0x1B);
        }
        v
    };
    match code {
        KEY_ENTER | KEY_KPENTER => prefix(alloc::vec![b'\r']),
        KEY_BACKSPACE => prefix(alloc::vec![if mods & CTRL != 0 { 0x08 } else { 0x7F }]),
        KEY_TAB if mods & SHIFT != 0 => b"\x1b[Z".to_vec(),
        KEY_TAB => prefix(alloc::vec![b'\t']),
        KEY_ESC => prefix(alloc::vec![0x1B]),
        KEY_UP => cursor_key(b'A', mods, app_cursor),
        KEY_DOWN => cursor_key(b'B', mods, app_cursor),
        KEY_RIGHT => cursor_key(b'C', mods, app_cursor),
        KEY_LEFT => cursor_key(b'D', mods, app_cursor),
        KEY_HOME => cursor_key(b'H', mods, app_cursor),
        KEY_END => cursor_key(b'F', mods, app_cursor),
        KEY_INSERT => tilde(2, mods),
        KEY_DELETE => tilde(3, mods),
        KEY_PAGEUP => tilde(5, mods),
        KEY_PAGEDOWN => tilde(6, mods),
        // F1-F4 are SS3 P-S; F5 on are CSI 15, 17-21, 23, 24 ~.
        KEY_F1..=KEY_F10 | KEY_F11 | KEY_F12 => {
            let n = match code {
                KEY_F11 => 11,
                KEY_F12 => 12,
                c => c - KEY_F1 + 1,
            };
            match n {
                1..=4 if modifier(mods) == 1 => alloc::vec![0x1B, b'O', b'P' + (n - 1) as u8],
                1..=4 => cursor_key(b'P' + (n - 1) as u8, mods, false),
                _ => tilde([0, 0, 0, 0, 0, 15, 17, 18, 19, 20, 21, 23, 24][n as usize], mods),
            }
        }
        _ => {
            let Some(c) = ch else { return Vec::new() };
            if mods & CTRL != 0 {
                // Ctrl with a letter or @[\]^_ gives its C0 control; Ctrl
                // with space gives NUL.
                let b = match c {
                    'a'..='z' => c as u8 - b'a' + 1,
                    'A'..='Z' => c as u8 - b'A' + 1,
                    '@' | ' ' | '2' => 0,
                    '[' | '3' => 0x1B,
                    '\\' | '4' => 0x1C,
                    ']' | '5' => 0x1D,
                    '^' | '6' => 0x1E,
                    '_' | '-' | '7' => 0x1F,
                    '?' | '8' => 0x7F,
                    _ => return Vec::new(),
                };
                return prefix(alloc::vec![b]);
            }
            let mut buf = [0u8; 4];
            prefix(c.encode_utf8(&mut buf).as_bytes().to_vec())
        }
    }
}

/// Files dropped on the terminal (ADR 0156), as the text they paste:
/// each path quoted for the shell, with a space after it.
pub fn dropped(paths: &str) -> String {
    let mut out = String::new();
    for p in paths.lines().filter(|l| !l.is_empty()) {
        let plain = p.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-+,:@%".contains(&b));
        if plain {
            out.push_str(p);
        } else {
            out.push('\'');
            out.push_str(&p.replace('\'', "'\\''"));
            out.push('\'');
        }
        out.push(' ');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        assert_eq!(encode(30, Some('a'), 0, false), b"a");
        assert_eq!(encode(30, Some('a'), CTRL, false), b"\x01");
        assert_eq!(encode(46, Some('c'), CTRL, false), b"\x03");
        assert_eq!(encode(30, Some('a'), ALT, false), b"\x1ba");
        assert_eq!(encode(4, Some('£'), 0, false), "£".as_bytes());
        assert_eq!(encode(KEY_ENTER, None, 0, false), b"\r");
        assert_eq!(encode(KEY_BACKSPACE, None, 0, false), b"\x7f");
        assert_eq!(encode(KEY_UP, None, 0, false), b"\x1b[A");
        assert_eq!(encode(KEY_UP, None, 0, true), b"\x1bOA");
        assert_eq!(encode(KEY_RIGHT, None, CTRL, true), b"\x1b[1;5C");
        assert_eq!(encode(KEY_DELETE, None, 0, false), b"\x1b[3~");
        assert_eq!(encode(KEY_PAGEDOWN, None, SHIFT, false), b"\x1b[6;2~");
        assert_eq!(encode(KEY_F1, None, 0, false), b"\x1bOP");
        assert_eq!(encode(KEY_F1 + 4, None, 0, false), b"\x1b[15~");
        assert_eq!(encode(KEY_F10, None, 0, false), b"\x1b[21~");
        assert_eq!(encode(KEY_F12, None, 0, false), b"\x1b[24~");
        assert_eq!(encode(KEY_TAB, None, SHIFT, false), b"\x1b[Z");
        assert_eq!(encode(200, None, 0, false), b"");
    }

    #[test]
    fn local_keys_and_pasting() {
        assert_eq!(local(KEY_PAGEUP, SHIFT, false), Some(Local::PageUp));
        assert_eq!(local(KEY_PAGEUP, 0, false), None);
        assert_eq!(local(KEY_C, SHIFT | CTRL, false), Some(Local::Copy));
        assert_eq!(local(KEY_C, CTRL, false), None);
        assert_eq!(local(KEY_V, SHIFT | CTRL, false), Some(Local::Paste));
        assert_eq!(local(KEY_A, SHIFT | CTRL, false), Some(Local::SelectAll));
        assert_eq!(local(KEY_INSERT, SHIFT, false), Some(Local::PasteSelection));
        // Tabs: ctrl + t at the shell, ctrl + shift + t everywhere; in a
        // full-screen program ctrl + t is the program's.
        assert_eq!(local(KEY_T, CTRL, false), Some(Local::NewTab));
        assert_eq!(local(KEY_T, CTRL, true), None);
        assert_eq!(local(KEY_T, CTRL | SHIFT, true), Some(Local::NewTab));
        assert_eq!(local(KEY_W, CTRL | SHIFT, false), Some(Local::CloseTab));
        assert_eq!(local(KEY_W, CTRL, false), None);
        assert_eq!(local(KEY_PAGEDOWN, CTRL, false), Some(Local::NextTab));
        assert_eq!(local(KEY_TAB, CTRL | SHIFT, false), Some(Local::PreviousTab));
        assert_eq!(paste("a\nb\r\nc", false), b"a\rb\rc");
        assert_eq!(paste("x\x1b[201~y", true), b"\x1b[200~x[201~y\x1b[201~");
        assert_eq!(dropped("/root/a.txt\n/root/My Files/it's"), "/root/a.txt '/root/My Files/it'\\''s' ");
    }
}
