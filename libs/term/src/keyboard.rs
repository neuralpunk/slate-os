// SPDX-License-Identifier: MIT OR Apache-2.0

//! PC keyboard scancodes to terminal input bytes.
//!
//! Decodes IBM PC scancode set 1 (what an i8042 controller delivers with
//! translation on): make codes, break codes (make | 0x80) and the 0xE0
//! extended prefix. Keys map through a [`Layout`] (US unless set), with
//! AltGr (the right Alt key) where the layout has it, and dead keys
//! composing with the next key (ADR 0117); characters come out as UTF-8. Special keys produce the escape
//! sequences xterm sends (ESC [ A for Up, ESC [ 3 ~ for Delete, ESC O P for
//! F1, ...); Ctrl turns letters into control characters, and Alt prefixes
//! ESC.

use alloc::vec::Vec;

use crate::keymap::{self, Composer, Layout, Sym};

const NORMAL: [u8; 0x3A] = *b"\x00\x1b1234567890-=\x7f\tqwertyuiop[]\r\x00asdfghjkl;'`\x00\\zxcvbnm,./\x00*\x00 ";
const SHIFTED: [u8; 0x3A] = *b"\x00\x1b!@#$%^&*()_+\x7f\tQWERTYUIOP{}\r\x00ASDFGHJKL:\"~\x00|ZXCVBNM<>?\x00*\x00 ";

const LCTRL: u8 = 0x1D;
const LSHIFT: u8 = 0x2A;
const RSHIFT: u8 = 0x36;
const LALT: u8 = 0x38;
const CAPS: u8 = 0x3A;

/// Keyboard state: the layout, modifiers and a pending extended prefix.
#[derive(Clone, Debug, Default)]
pub struct Keyboard {
    layout: Layout,
    shift: bool,
    ctrl: bool,
    alt: bool,
    altgr: bool,
    caps: bool,
    extended: bool,
    dead: Composer,
}

impl Keyboard {
    pub fn new() -> Keyboard {
        Keyboard::default()
    }

    /// For statics.
    pub const fn new_const() -> Keyboard {
        Keyboard {
            layout: Layout::US,
            shift: false,
            ctrl: false,
            alt: false,
            altgr: false,
            caps: false,
            extended: false,
            dead: Composer::new(),
        }
    }

    pub fn set_layout(&mut self, layout: Layout) {
        if layout != self.layout {
            self.layout = layout;
            self.dead.reset();
        }
    }

    /// Whether Caps Lock is on (for the keyboard's light).
    pub fn caps_lock(&self) -> bool {
        self.caps
    }

    /// Feed one scancode byte; returns the bytes the key produces (often none).
    pub fn scancode(&mut self, code: u8) -> Vec<u8> {
        if code == 0xE0 {
            self.extended = true;
            return Vec::new();
        }
        let extended = core::mem::take(&mut self.extended);
        let released = code & 0x80 != 0;
        let key = code & 0x7F;
        match key {
            LSHIFT | RSHIFT if !extended => {
                self.shift = !released;
                return Vec::new();
            }
            LCTRL => {
                self.ctrl = !released; // left or right (E0 1D)
                return Vec::new();
            }
            // The right Alt (E0 38) is AltGr in layouts that have one.
            LALT if extended && self.layout.has_altgr() => {
                self.altgr = !released;
                return Vec::new();
            }
            LALT => {
                self.alt = !released; // left or right (E0 38)
                return Vec::new();
            }
            CAPS if !extended => {
                if !released {
                    self.caps = !self.caps;
                }
                return Vec::new();
            }
            _ => {}
        }
        if released {
            return Vec::new();
        }
        if extended {
            self.dead.reset();
        }
        let mut out: Vec<u8> = if extended { extended_key(key) } else { self.plain_key(key) };
        if self.alt && !out.is_empty() && !extended {
            out.insert(0, 0x1B);
        }
        out
    }

    fn plain_key(&mut self, key: u8) -> Vec<u8> {
        if let Some(seq) = function_key(key) {
            self.dead.reset();
            return seq.to_vec();
        }
        if let Some(c) = keypad(key) {
            self.dead.reset();
            return alloc::vec![c];
        }
        let sym = keymap::key(self.layout, u16::from(key), self.shift, self.caps, self.altgr);
        // A dead key waits; the next character takes its accent (not with
        // Ctrl or Alt, which make shortcuts).
        let typed = match sym {
            Some(Sym::Dead(_)) if self.ctrl || self.alt => return Vec::new(),
            Some(s @ Sym::Dead(_)) => {
                self.dead.feed(s);
                return Vec::new();
            }
            Some(Sym::Char(c)) if self.dead.pending() && !self.ctrl && !self.alt => {
                let mut out = Vec::new();
                for c in self.dead.feed(Sym::Char(c)).chars() {
                    out.extend_from_slice(c.encode_utf8(&mut [0u8; 4]).as_bytes());
                }
                return out;
            }
            Some(Sym::Char(c)) => Some(c),
            None => {
                self.dead.reset();
                None
            }
        };
        let c = match typed {
            Some(c) if !c.is_ascii() => {
                let mut b = [0u8; 4];
                return c.encode_utf8(&mut b).as_bytes().to_vec();
            }
            Some(c) => c as u8,
            // Keys the layout doesn't type (Escape, Backspace, Tab,
            // Enter, keypad *), but nothing for a dead key on AltGr.
            None if self.altgr => return Vec::new(),
            None => {
                let Some(&base) = NORMAL.get(key as usize) else { return Vec::new() };
                if base == 0 || base.is_ascii_alphanumeric() {
                    return Vec::new();
                }
                if self.shift { SHIFTED[key as usize] } else { base }
            }
        };
        if self.ctrl {
            return match c {
                b'a'..=b'z' | b'A'..=b'Z' => alloc::vec![c & 0x1F],
                b'[' | b'{' => alloc::vec![0x1B],
                b'\\' | b'|' => alloc::vec![0x1C],
                b']' | b'}' => alloc::vec![0x1D],
                b'^' | b'6' => alloc::vec![0x1E],
                b'_' | b'-' => alloc::vec![0x1F],
                b' ' | b'@' | b'2' => alloc::vec![0x00],
                b'?' | b'/' => alloc::vec![0x7F],
                _ => alloc::vec![c],
            };
        }
        alloc::vec![c]
    }
}

fn function_key(key: u8) -> Option<&'static [u8]> {
    Some(match key {
        0x3B => b"\x1bOP",
        0x3C => b"\x1bOQ",
        0x3D => b"\x1bOR",
        0x3E => b"\x1bOS",
        0x3F => b"\x1b[15~",
        0x40 => b"\x1b[17~",
        0x41 => b"\x1b[18~",
        0x42 => b"\x1b[19~",
        0x43 => b"\x1b[20~",
        0x44 => b"\x1b[21~",
        0x57 => b"\x1b[23~",
        0x58 => b"\x1b[24~",
        _ => return None,
    })
}

/// The numeric keypad, as digits (NumLock on).
fn keypad(key: u8) -> Option<u8> {
    const PAD: &[u8; 13] = b"789-456+1230.";
    (0x47..=0x53).contains(&key).then(|| PAD[(key - 0x47) as usize])
}

fn extended_key(key: u8) -> Vec<u8> {
    let s: &[u8] = match key {
        0x48 => b"\x1b[A",
        0x50 => b"\x1b[B",
        0x4D => b"\x1b[C",
        0x4B => b"\x1b[D",
        0x47 => b"\x1b[H",
        0x4F => b"\x1b[F",
        0x49 => b"\x1b[5~",
        0x51 => b"\x1b[6~",
        0x52 => b"\x1b[2~",
        0x53 => b"\x1b[3~",
        0x1C => b"\r", // keypad Enter
        0x35 => b"/",  // keypad /
        _ => b"",
    };
    s.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(codes: &[u8]) -> Vec<u8> {
        let mut k = Keyboard::new();
        codes.iter().flat_map(|&c| k.scancode(c)).collect()
    }

    #[test]
    fn letters_digits_and_shift() {
        // h, i, Enter
        assert_eq!(typed(&[0x23, 0xA3, 0x17, 0x97, 0x1C, 0x9C]), b"hi\r");
        // Shift down, 1, Shift up, 1
        assert_eq!(typed(&[0x2A, 0x02, 0x82, 0xAA, 0x02, 0x82]), b"!1");
    }

    #[test]
    fn caps_lock_affects_letters_only() {
        assert_eq!(typed(&[0x3A, 0xBA, 0x1E, 0x02]), b"A1");
    }

    #[test]
    fn control_and_alt() {
        // Ctrl-C, then Alt-x
        assert_eq!(typed(&[0x1D, 0x2E, 0xAE, 0x9D, 0x38, 0x2D, 0xAD, 0xB8]), b"\x03\x1bx");
    }

    #[test]
    fn extended_keys() {
        assert_eq!(typed(&[0xE0, 0x48, 0xE0, 0xC8]), b"\x1b[A");
        assert_eq!(typed(&[0xE0, 0x53]), b"\x1b[3~");
        // Right Ctrl (E0 1D) works like left.
        assert_eq!(typed(&[0xE0, 0x1D, 0x20, 0xA0, 0xE0, 0x9D]), b"\x04");
    }

    #[test]
    fn layouts_and_altgr() {
        let mut k = Keyboard::new();
        k.set_layout(Layout::named("gb"));
        let mut typed = |codes: &[u8]| codes.iter().flat_map(|&c| k.scancode(c)).collect::<Vec<u8>>();
        // Shift 2 is " and Shift 3 is £ (UTF-8) on gb.
        assert_eq!(typed(&[0x2A, 0x03, 0x04, 0xAA]), "\"£".as_bytes());
        // AltGr (right Alt) 4 is €; left Alt still prefixes ESC.
        assert_eq!(typed(&[0xE0, 0x38, 0x05, 0x85, 0xE0, 0xB8]), "€".as_bytes());
        assert_eq!(typed(&[0x38, 0x2D, 0xAD, 0xB8]), b"\x1bx");
        assert!(!k.caps_lock());
    }

    /// German: ´ then e is é, ^ then Space is ^, ´ then q is ´q (ADR 0117).
    #[test]
    fn dead_keys() {
        let mut k = Keyboard::new();
        k.set_layout(Layout::named("de"));
        let mut typed = |codes: &[u8]| codes.iter().flat_map(|&c| k.scancode(c)).collect::<Vec<u8>>();
        assert_eq!(typed(&[0x0D, 0x8D, 0x12, 0x92]), "é".as_bytes());
        assert_eq!(typed(&[0x29, 0xA9, 0x39, 0xB9]), b"^");
        assert_eq!(typed(&[0x0D, 0x8D, 0x10, 0x90]), "´q".as_bytes());
        // Shift ´ is `: ` then a is à.
        assert_eq!(typed(&[0x2A, 0x0D, 0x8D, 0xAA, 0x1E, 0x9E]), "à".as_bytes());
        // An arrow forgets it.
        assert_eq!(typed(&[0x0D, 0x8D, 0xE0, 0x48, 0x12]), b"\x1b[Ae");
    }

    #[test]
    fn special_keys() {
        assert_eq!(typed(&[0x0E, 0x0F, 0x01, 0x3B]), b"\x7f\t\x1b\x1bOP");
        assert_eq!(typed(&[0x39]), b" ");
    }
}
