// SPDX-License-Identifier: MIT OR Apache-2.0

//! The boot menu in text (ADR 0089), for consoles without graphics: a
//! title, the systems in a box with the chosen one inverted and each
//! system's name on the right, then the keys and the countdown under the
//! box. The lines come with their colours as text attributes, a foreground
//! colour and a background one shifted left by four, the encoding UEFI's
//! console (UEFI 2.10 §12.4.7) and VGA text mode share.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::config::Menu;
use crate::menu::{State, wrap};

pub const PLAIN: u8 = 0x07;
pub const DIM: u8 = 0x08;
pub const BRIGHT: u8 = 0x0f;
/// Black on light grey: selection is inversion (docs/design/INSTALLER_STYLE.md).
pub const SELECTED: u8 = 0x70;

/// One line of the screen: column, row, attribute, text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub col: usize,
    pub row: usize,
    pub attr: u8,
    pub text: String,
}

fn fit(s: &str, width: usize) -> String {
    let n = s.chars().count();
    if n <= width {
        let mut t = String::from(s);
        t.extend(core::iter::repeat_n(' ', width - n));
        t
    } else {
        let mut t: String = s.chars().take(width.saturating_sub(3)).collect();
        t.push_str("...");
        t
    }
}

fn centred(s: &str, cols: usize) -> usize {
    cols.saturating_sub(s.chars().count()) / 2
}

/// The screen for `menu` in `state` on a `cols` by `rows` console.
pub fn lines(menu: &Menu, state: &State, cols: usize, rows: usize) -> Vec<Line> {
    let width = cols.saturating_sub(6).clamp(30, 74);
    let left = cols.saturating_sub(width) / 2;
    let inner = width - 2;
    // Title, gap, box (borders, a blank row each side), gap, two lines.
    let room = rows.saturating_sub(10).max(1);
    // The box holds the entries, or the command line being edited (with
    // `_` for the caret).
    let edited: Option<Vec<String>> = state.editing.as_deref().map(|l| {
        let mut w = wrap(&alloc::format!("{l}_"), inner - 4);
        w.truncate(room);
        w
    });
    let shown = match &edited {
        Some(w) => w.len(),
        None => menu.entries.len().min(room),
    };
    let first = (state.sel + 1).saturating_sub(shown).min(menu.entries.len().saturating_sub(shown));
    let height = 1 + 1 + shown + 4 + 1 + 2;
    let top = rows.saturating_sub(height) / 3;
    let mut out = Vec::new();
    let mut put = |col: usize, row: usize, attr: u8, text: String| out.push(Line { col, row, attr, text });
    let heading = if edited.is_some() { "Edit the command line" } else { "Slate" };
    put(centred(heading, cols), top, BRIGHT, heading.into());
    let b = top + 2;
    let rule: String = core::iter::repeat_n('\u{2500}', inner).collect();
    put(left, b, PLAIN, format!("\u{250c}{rule}\u{2510}"));
    put(left, b + 1, PLAIN, format!("\u{2502}{}\u{2502}", fit("", inner)));
    let row_of = |put: &mut dyn FnMut(usize, usize, u8, String), row: usize, attr: u8, text: String| {
        put(left, row, PLAIN, "\u{2502}".into());
        put(left + 1, row, attr, text);
        put(left + 1 + inner, row, PLAIN, "\u{2502}".into());
    };
    match &edited {
        Some(w) => {
            for (i, l) in w.iter().enumerate() {
                row_of(&mut put, b + 2 + i, PLAIN, format!("  {}  ", fit(l, inner - 4)));
            }
        }
        None => {
            for (i, e) in menu.entries.iter().enumerate().skip(first).take(shown) {
                let name = e.system().unwrap_or("");
                let title = fit(&e.title, inner - 4 - name.chars().count() - 1);
                let attr = if i == state.sel { SELECTED } else { PLAIN };
                row_of(&mut put, b + 2 + (i - first), attr, format!("  {title} {name}  "));
            }
        }
    }
    put(left, b + 2 + shown, PLAIN, format!("\u{2502}{}\u{2502}", fit("", inner)));
    put(left, b + 3 + shown, PLAIN, format!("\u{2514}{rule}\u{2518}"));
    // The long words when they fit, short ones on narrow consoles.
    let either = |long: String, short: String| if long.chars().count() <= inner - 2 { long } else { short };
    let keys = if edited.is_some() {
        either("Enter starts it with this command line, Esc goes back.".into(), "Enter to start, Esc back".into())
    } else {
        either(
            "Use \u{2191} and \u{2193} to choose a system, Enter to start it.".into(),
            "\u{2191} \u{2193} to choose, Enter to start".into(),
        )
    };
    let h = b + 5 + shown;
    put(left + 2, h, PLAIN, fit(&keys, inner - 2));
    let count = match (state.secs(), &edited) {
        (Some(s), None) => either(
            format!("The highlighted system starts in {s} second{}.", if s == 1 { "" } else { "s" }),
            format!("Starting in {s} s"),
        ),
        (None, None) => either("E edits the command line.".into(), "E to edit".into()),
        _ => String::new(),
    };
    put(left + 2, h + 1, DIM, fit(&count, inner - 2));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;

    const MENU: &str = "timeout: 3\n/Slate\n path: boot():/boot/slate/system-2/kernel\n\
        /Slate (previous system)\n path: boot():/boot/slate/system-1/kernel\n";

    fn st(sel: usize, secs: Option<u64>) -> State {
        State { sel, left: secs.map(|s| s * 100), editing: None }
    }

    fn screen(lines: &[Line], cols: usize, rows: usize) -> Vec<String> {
        let mut s: Vec<Vec<char>> = alloc::vec![alloc::vec![' '; cols]; rows];
        for l in lines {
            for (i, c) in l.text.chars().enumerate() {
                s[l.row][l.col + i] = c;
            }
        }
        s.into_iter().map(|r| r.into_iter().collect::<String>().trim_end().into()).collect()
    }

    #[test]
    fn grub_like_box() {
        let m = parse(MENU).unwrap();
        let l = lines(&m, &st(0, Some(3)), 80, 25);
        let s = screen(&l, 80, 25);
        let rows: Vec<&str> = s.iter().map(String::as_str).filter(|r| !r.is_empty()).collect();
        assert_eq!(rows[0].trim(), "Slate");
        assert!(rows[1].trim_start().starts_with('\u{250c}') && rows[1].ends_with('\u{2510}'));
        assert!(rows[3].contains("  Slate ") && rows[3].trim_end_matches('\u{2502}').trim_end().ends_with("system-2"));
        assert!(rows[4].contains("Slate (previous system)") && rows[4].contains("system-1"));
        assert!(rows[6].trim_start().starts_with('\u{2514}'));
        assert_eq!(rows[8].trim(), "The highlighted system starts in 3 seconds.");
        // Every box row is the box's width.
        let w = rows[1].trim_start().chars().count();
        assert!(rows[2..7].iter().all(|r| r.trim_start().chars().count() == w));
        // The chosen entry is inverted, the other plain.
        let sel: Vec<&Line> = l.iter().filter(|x| x.attr == SELECTED).collect();
        assert_eq!((sel.len(), sel[0].row), (1, s.iter().position(|r| r.contains("system-2")).unwrap()));
        let after_key = lines(&m, &st(1, None), 80, 25);
        let sel = after_key.iter().find(|x| x.attr == SELECTED).unwrap();
        assert!(sel.text.contains("previous system"));
        assert_eq!(after_key.last().unwrap().text.trim(), "E edits the command line.");
        // Editing: the line in the box, the caret after it.
        let e = State { sel: 0, left: None, editing: Some("root=x quiet slate.ip=10.0.0.2/24".into()) };
        let s = screen(&lines(&m, &e, 80, 25), 80, 25);
        assert!(s.iter().any(|r| r.trim() == "Edit the command line"));
        assert!(s.iter().any(|r| r.contains("root=x quiet slate.ip=10.0.0.2/24_")));
        assert!(s.iter().any(|r| r.contains("Esc goes back")));
    }

    #[test]
    fn small_and_crowded_consoles() {
        let many: String = (0..30).map(|i| alloc::format!("/Entry {i}\n path: boot():/k\n")).collect();
        let m = parse(&many).unwrap();
        let l = lines(&m, &st(29, Some(1)), 40, 20);
        assert!(l.iter().all(|x| x.row < 20 && x.col + x.text.chars().count() <= 40));
        assert!(l.iter().any(|x| x.attr == SELECTED && x.text.contains("Entry 29")));
        assert!(l.iter().any(|x| x.text.trim_end() == "Starting in 1 s"));
        assert!(lines(&m, &st(0, Some(1)), 80, 25).iter().any(|x| x.text.trim_end().ends_with("starts in 1 second.")));
        let long =
            parse("/A very long title that will not fit in the box at all, not even close to it\n path: boot():/k\n")
                .unwrap();
        let l = lines(&long, &st(0, None), 40, 25);
        assert!(l.iter().any(|x| x.text.contains("...")));
    }
}
