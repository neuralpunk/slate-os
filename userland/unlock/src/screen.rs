// SPDX-License-Identifier: MIT OR Apache-2.0

//! The unlock screen, in graphite (docs/design/WM_STYLE.md), composed as the lock
//! screen is (Atelier, ADR 0124): the wallpaper and the monument, "Unlock
//! this disk", the disk's name, the password field, a status line and the
//! keys' hints. Tab switches to a
//! recovery key (ADR 0039), whose characters show as typed; F2 switches
//! to the high-contrast palette.

use slate_strata::fonts::Fonts;
use slate_ui::Color;
use slate_ui::graphite::Palette;
use slate_ui::math::round;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;

use alloc::string::String;
use alloc::vec::Vec;

/// What the screen says under the field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Asking,
    /// Deriving the key (Argon2id takes a moment).
    Working,
    /// The last password opened no key slot.
    Wrong,
    /// What was typed as a recovery key is not one (32 characters).
    NotAKey,
}

/// What is being asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Password,
    RecoveryKey,
}

#[derive(Clone, Copy, Debug)]
pub struct Unlock<'a> {
    /// The encrypted partition, as `/dev/sda2`.
    pub device: &'a str,
    pub password_len: usize,
    pub status: Status,
    pub caps_lock: bool,
    pub mode: Mode,
    /// A recovery key as typed (shown; a password never is).
    pub typed: &'a str,
    /// The disk has a recovery-key slot (Tab offers it).
    pub has_recovery: bool,
}

/// The status line's words and colour.
fn status_line(u: &Unlock<'_>, pal: &Palette) -> (&'static str, Color) {
    match (u.status, u.mode) {
        (Status::Working, _) => ("Unlocking…", pal.muted),
        (Status::Wrong, Mode::Password) => ("That password does not unlock the disk.", pal.text_1),
        (Status::Wrong, Mode::RecoveryKey) => ("That recovery key does not unlock the disk.", pal.text_1),
        (Status::NotAKey, _) => ("A recovery key has 32 letters and digits.", pal.text_1),
        (Status::Asking, Mode::Password) if u.caps_lock => ("Caps Lock is on.", pal.text_3),
        (Status::Asking, Mode::Password) => ("It's your account's password.", pal.muted),
        (Status::Asking, Mode::RecoveryKey) => ("Case, dashes and spaces don't matter.", pal.muted),
    }
}

/// The keys' hints under the status line.
fn hints(u: &Unlock<'_>) -> &'static str {
    match (u.mode, u.has_recovery) {
        (Mode::Password, true) => "Tab: use a recovery key  ·  F2: high contrast",
        (Mode::Password, false) => "F2: high contrast",
        (Mode::RecoveryKey, _) => "Tab: use the password  ·  F2: high contrast",
    }
}

/// Draw the whole screen: the lock screen's composition (ADR 0124), a
/// title where the clock goes (the time zone isn't known before the root
/// is open) and the disk where the person goes.
pub fn draw(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, u: &Unlock<'_>) {
    use slate_strata::lock;
    let (w, h) = p.size();
    lock::backdrop(p, pal, f, None, "slateos", None, None);
    let k = lock::scale_of(w, h);
    let x = lock::column_x(k);
    let mut y = round(176.0 * k);
    let recovery = u.mode == Mode::RecoveryKey;
    let over = p.style(&f.mono, 13.0, pal.muted).tracking(0.06);
    p.line(&over, x, y, 18.0, "encrypted disk");
    y += 18.0 + 18.0;
    let title = p.style(&f.regular, 64.0 * k, pal.chalk).tracking(-0.04);
    let line = round(72.0 * k);
    p.line(&title, x - 3.0 * k, y, line, if recovery { "Recovery key" } else { "Unlock this disk" });
    y += line + 48.0 * k;
    y = lock::ruled_mark(p, pal, f, x, y, "locked") + 28.0;
    let what = if recovery { "the 32 characters you wrote down" } else { "enter the password to unlock it" };
    lock::identity(p, pal, f, x, y, lock::Tile::Icon(slate_ui::icon::Icon::Disk), u.device, what);
    y += 40.0 + 20.0;
    // The field: always focused; dots for a password, the key as typed
    // (its last 36 characters) in DM Mono.
    let working = u.status == Status::Working;
    if recovery {
        let field = lock::column_field(p, pal, f, x, y, true, &slate_ui::edit::LineEdit::new(""), false);
        let text = p.style(&f.mono, 14.0, pal.chalk);
        let shown: String = u.typed.chars().rev().take(36).collect::<Vec<_>>().into_iter().rev().collect();
        let end = p.line(&text, field.x + 16.0, field.y, 46.0, &shown);
        if !working {
            p.fill(Area::new(field.x + 16.0 + end + 1.0, field.y + 13.0, 2.0, 20.0), 0.0, pal.chalk);
        }
    } else {
        // (Dots for what is typed: this screen edits at the end.)
        let dots = slate_ui::edit::LineEdit::new(&"x".repeat(u.password_len)).secret();
        lock::column_field(p, pal, f, x, y, true, &dots, !working);
    }
    y += 46.0 + 12.0;
    let (line, colour) = status_line(u, pal);
    let st = p.style(&f.regular, 12.5, colour);
    p.line(&st, x, y, 18.0, line);
    // The keys, bottom left.
    let hint = p.style(&f.mono, 11.0, pal.muted).tracking(0.02);
    p.line(&hint, x, h - 48.0 - 36.0, 36.0, hints(u));
}

#[cfg(test)]
mod tests {
    use super::*;
    use slate_ui::Canvas;
    use slate_ui::text::GlyphCache;
    use std::format;
    use std::string::String;
    use std::vec::Vec;

    fn fonts() -> Fonts<'static> {
        let read = |n: &str| -> &'static [u8] {
            let p = format!("{}/../../assets/fonts/{n}", env!("CARGO_MANIFEST_DIR"));
            std::boxed::Box::leak(std::fs::read(p).unwrap().into_boxed_slice())
        };
        Fonts::new(slate_strata::fonts::FILES.map(read)).unwrap()
    }

    fn fingerprint(c: &Canvas) -> u64 {
        c.pixels
            .iter()
            .flat_map(|p| p.to_le_bytes())
            .fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3))
    }

    /// The screens look as they did when last reviewed (tests/screens.txt;
    /// `SLATE_UI_OUT=DIR` saves them, `SLATE_UI_BLESS=1` records a change).
    #[test]
    fn screens_match_references() {
        let f = fonts();
        let pal = Palette::GRAPHITE;
        let base = Unlock {
            device: "/dev/sda2",
            password_len: 0,
            status: Status::Asking,
            caps_lock: false,
            mode: Mode::Password,
            typed: "",
            has_recovery: true,
        };
        let cases = [
            ("asking", base, false),
            ("typing", Unlock { password_len: 9, caps_lock: true, has_recovery: false, ..base }, false),
            ("working", Unlock { device: "/dev/nvme0n1p2", password_len: 9, status: Status::Working, ..base }, false),
            ("wrong", Unlock { status: Status::Wrong, ..base }, false),
            ("recovery", Unlock { mode: Mode::RecoveryKey, typed: "7K2Q-9XMB-AH3", ..base }, false),
            ("not-a-key", Unlock { mode: Mode::RecoveryKey, typed: "1234", status: Status::NotAKey, ..base }, false),
            ("high-contrast", base, true),
        ];
        let all: Vec<(&str, Canvas)> = cases
            .iter()
            .map(|(name, u, contrast)| {
                let pal = if *contrast { Palette::HIGH_CONTRAST } else { pal };
                let mut c = Canvas::new(1280, 800, pal.desktop);
                let mut cache = GlyphCache::new();
                let mut p = Painter::new(&mut c, &mut cache, 1.0);
                draw(&mut p, &pal, &f, u);
                (*name, c)
            })
            .collect();
        if let Ok(dir) = std::env::var("SLATE_UI_OUT") {
            for (name, c) in &all {
                std::fs::write(format!("{dir}/unlock-{name}.png"), slate_ui::png::encode(c)).unwrap();
            }
        }
        // The field is in the column, `well` coloured (the graphical
        // scenario looks there too).
        assert_eq!(all[0].1.pixel(300, 428) & 0xFF_FFFF, 0x161615);
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/screens.txt");
        let got: String = all.iter().map(|(n, c)| format!("{n} {:016x}\n", fingerprint(c))).collect();
        if std::env::var_os("SLATE_UI_BLESS").is_some() {
            std::fs::write(path, &got).unwrap();
            return;
        }
        let want = std::fs::read_to_string(path).unwrap_or_default();
        assert_eq!(got, want, "unlock screens changed; look at them (SLATE_UI_OUT=DIR), record with SLATE_UI_BLESS=1");
    }
}
