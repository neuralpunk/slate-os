// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the boot menu does with keys (ADR 0089), whatever draws it: Up
//! and Down choose, Enter boots, any key stops the countdown, `e` edits
//! the chosen entry's command line (Enter boots with it, Esc goes back).

use alloc::string::String;

use crate::config::Menu;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Enter,
    Esc,
    Backspace,
    Char(char),
    /// A key the menu has no use for.
    Other,
}

/// The menu's state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub sel: usize,
    /// Hundredths of a second left; None once a key was pressed.
    pub left: Option<u64>,
    /// The command line being edited.
    pub editing: Option<String>,
}

/// What to boot: the entry and its command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Boot {
    pub entry: usize,
    pub cmdline: String,
}

/// The longest command line the editor takes.
pub const MAX_CMDLINE: usize = 1024;

impl State {
    pub fn new(menu: &Menu) -> State {
        State { sel: menu.default, left: menu.timeout.map(|s| u64::from(s) * 100), editing: None }
    }

    /// Whole seconds left, for the countdown.
    pub fn secs(&self) -> Option<u64> {
        self.left.map(|l| l.div_ceil(100))
    }

    /// A hundredth of a second passed without a key.
    pub fn tick(&mut self, menu: &Menu) -> Option<Boot> {
        match self.left.as_mut() {
            Some(0) => Some(Boot { entry: self.sel, cmdline: menu.entries[self.sel].cmdline.clone() }),
            Some(l) => {
                *l -= 1;
                None
            }
            None => None,
        }
    }

    pub fn key(&mut self, menu: &Menu, k: Key) -> Option<Boot> {
        self.left = None;
        if let Some(line) = self.editing.as_mut() {
            match k {
                Key::Enter => return Some(Boot { entry: self.sel, cmdline: line.clone() }),
                Key::Esc => self.editing = None,
                Key::Backspace => {
                    line.pop();
                }
                Key::Char(c) if !c.is_control() && line.len() < MAX_CMDLINE => line.push(c),
                _ => {}
            }
            return None;
        }
        let n = menu.entries.len();
        match k {
            Key::Up => self.sel = (self.sel + n - 1) % n,
            Key::Down => self.sel = (self.sel + 1) % n,
            Key::Enter => return Some(Boot { entry: self.sel, cmdline: menu.entries[self.sel].cmdline.clone() }),
            Key::Char('e') => self.editing = Some(menu.entries[self.sel].cmdline.clone()),
            _ => {}
        }
        None
    }
}

/// `s` in lines of at most `width` characters, broken at spaces where it
/// can.
pub fn wrap(s: &str, width: usize) -> alloc::vec::Vec<String> {
    let mut out = alloc::vec::Vec::new();
    let mut line = String::new();
    for word in s.split(' ') {
        let mut word = String::from(word);
        loop {
            let used = line.chars().count();
            let fits = used + usize::from(used > 0) + word.chars().count() <= width;
            if fits {
                if used > 0 {
                    line.push(' ');
                }
                line.push_str(&word);
                break;
            }
            if used > 0 {
                out.push(core::mem::take(&mut line));
                continue;
            }
            // A word longer than a line: break it.
            let rest: String = word.chars().skip(width).collect();
            out.push(word.chars().take(width).collect());
            word = rest;
        }
    }
    out.push(line);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;

    const MENU: &str = "timeout: 1\n/A\n path: boot():/a\n cmdline: root=x quiet\n/B\n path: boot():/b\n cmdline: b\n";

    #[test]
    fn countdown_and_choice() {
        let m = parse(MENU).unwrap();
        let mut s = State::new(&m);
        assert_eq!(s.secs(), Some(1));
        for _ in 0..100 {
            assert_eq!(s.tick(&m), None);
        }
        assert_eq!(s.tick(&m), Some(Boot { entry: 0, cmdline: "root=x quiet".into() }));
        let mut s = State::new(&m);
        assert_eq!(s.key(&m, Key::Up), None);
        assert_eq!((s.sel, s.left), (1, None));
        assert_eq!(s.tick(&m), None);
        assert_eq!(s.key(&m, Key::Down), None);
        assert_eq!(s.key(&m, Key::Enter), Some(Boot { entry: 0, cmdline: "root=x quiet".into() }));
    }

    #[test]
    fn editing_the_command_line() {
        let m = parse(MENU).unwrap();
        let mut s = State::new(&m);
        s.key(&m, Key::Char('e'));
        assert_eq!(s.editing.as_deref(), Some("root=x quiet"));
        for _ in 0.."quiet".len() {
            s.key(&m, Key::Backspace);
        }
        for c in "slate.ip=10.0.0.2/24".chars() {
            s.key(&m, Key::Char(c));
        }
        // Up and Down do nothing while editing; Esc goes back.
        s.key(&m, Key::Down);
        assert_eq!(s.sel, 0);
        let mut back = s.clone();
        back.key(&m, Key::Esc);
        assert_eq!(back.editing, None);
        assert_eq!(s.key(&m, Key::Enter), Some(Boot { entry: 0, cmdline: "root=x slate.ip=10.0.0.2/24".into() }));
    }

    #[test]
    fn wrapping() {
        assert_eq!(wrap("root=PARTUUID=abc quiet slate.ip=1", 20), ["root=PARTUUID=abc", "quiet slate.ip=1"]);
        assert_eq!(wrap("aaaaaaaaaaaa b", 5), ["aaaaa", "aaaaa", "aa b"]);
        assert_eq!(wrap("", 5), [""]);
    }
}
