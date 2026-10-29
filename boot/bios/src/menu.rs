// SPDX-License-Identifier: MIT OR Apache-2.0

//! The boot menu on BIOS (ADR 0089): drawn in graphite on the VBE
//! framebuffer (`slate_loader::screen`), or in VGA text at 0xB8000
//! (`slate_loader::textmenu`, its characters in code page 437).

use alloc::vec::Vec;

use slate_loader::config::Menu;
use slate_loader::menu::{Boot, Key, State};
use slate_loader::textmenu::{self, Line};

use crate::bios::{self, Mode};

/// A BIOS key as the menu's (scan codes of the PC keyboard's set 1).
fn key(scan: u8, ch: u8) -> Key {
    match (scan, ch) {
        (0x48, _) => Key::Up,
        (0x50, _) => Key::Down,
        (0x01, _) => Key::Esc,
        (_, 0x0d) => Key::Enter,
        (_, 0x08) => Key::Backspace,
        (_, c) if (0x20..0x7f).contains(&c) => Key::Char(char::from(c)),
        _ => Key::Other,
    }
}

/// What to boot (see the UEFI loader's `choose`), on `mode` when there is
/// a graphical one.
pub fn choose(menu: &Menu, mode: Option<&Mode>) -> Boot {
    let mut state = State::new(menu);
    if menu.timeout == Some(0) {
        return Boot { entry: state.sel, cmdline: menu.entries[state.sel].cmdline.clone() };
    }
    let mut graphics = mode.and_then(|m| {
        let fonts = slate_loader::screen::Fonts::new()?;
        let canvas = slate_ui::Canvas::new(m.width as i32, m.height as i32, slate_ui::Color::rgb(0));
        Some((m, fonts, canvas, slate_ui::text::GlyphCache::new()))
    });
    if graphics.is_none() {
        clear_text();
    }
    let mut drawn: Option<(State, Option<u64>)> = None;
    let mut shown: Vec<Line> = Vec::new();
    loop {
        if let Some((m, fonts, canvas, cache)) = graphics.as_mut() {
            let now = (state.clone(), state.secs());
            if drawn.as_ref() != Some(&now) {
                slate_loader::screen::draw(canvas, cache, fonts, menu, &state);
                blit(m, canvas);
                drawn = Some(now);
            }
        } else {
            let now = textmenu::lines(menu, &state, 80, 25);
            for l in now.iter().filter(|l| !shown.contains(l)) {
                text(l);
            }
            shown = now;
        }
        let done = match bios::key() {
            Some((scan, ch)) => state.key(menu, key(scan, ch)),
            None => {
                bios::wait_us(10_000);
                state.tick(menu)
            }
        };
        if let Some(b) = done {
            return b;
        }
    }
}

/// Copy the canvas to the framebuffer, in the mode's pixel layout.
fn blit(m: &Mode, c: &slate_ui::Canvas) {
    let place = |(size, pos): (u8, u8), v: u32| (v >> (8 - u32::from(size).min(8))) << pos;
    for y in 0..m.height as usize {
        let row = &c.pixels[y * m.width as usize..(y + 1) * m.width as usize];
        let dst = (m.base as usize + y * m.pitch as usize) as *mut u32;
        for (x, &p) in row.iter().enumerate() {
            let (r, g, b) = ((p >> 16) & 0xff, (p >> 8) & 0xff, p & 0xff);
            let v = place(m.masks[0], r) | place(m.masks[1], g) | place(m.masks[2], b);
            // SAFETY: The mode's linear framebuffer, `pitch` bytes a row,
            // inside the boot tables' first 4 GiB.
            unsafe { core::ptr::write_volatile(dst.add(x), v) };
        }
    }
}

const VGA: usize = 0xb8000;

/// Code page 437 for what the text menu draws.
fn cp437(c: char) -> u8 {
    match c {
        '\u{2500}' => 0xc4,
        '\u{2502}' => 0xb3,
        '\u{250c}' => 0xda,
        '\u{2510}' => 0xbf,
        '\u{2514}' => 0xc0,
        '\u{2518}' => 0xd9,
        '\u{2191}' => 0x18,
        '\u{2193}' => 0x19,
        c if (' '..='~').contains(&c) => c as u8,
        _ => b'?',
    }
}

fn clear_text() {
    for i in 0..80 * 25 {
        // SAFETY: VGA text memory, 80 by 25 cells of character and
        // attribute.
        unsafe { core::ptr::write_volatile((VGA + 2 * i) as *mut u16, 0x0720) };
    }
}

fn text(l: &Line) {
    for (i, c) in l.text.chars().enumerate() {
        let (col, row) = (l.col + i, l.row);
        if col < 80 && row < 25 {
            let cell = u16::from(l.attr) << 8 | u16::from(cp437(c));
            // SAFETY: A cell of VGA text memory (see `clear_text`).
            unsafe { core::ptr::write_volatile((VGA + 2 * (row * 80 + col)) as *mut u16, cell) };
        }
    }
}
