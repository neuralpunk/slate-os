// SPDX-License-Identifier: MIT OR Apache-2.0

//! The boot menu (ADR 0089): drawn in graphite on the firmware's screen
//! (`slate_loader::screen`), or in text on its console
//! (`slate_loader::textmenu`), where only lines that change are written
//! again. `slate_loader::menu` decides what keys do.

use alloc::vec::Vec;

use slate_loader::config::Menu;
use slate_loader::menu::{Boot, Key, State};
use slate_loader::textmenu::{self, Line};

use crate::{Screen, bs, console, efi};

/// A firmware key as the menu's (scan codes, UEFI 2.10 §12.3 table 12-1).
fn key(scan: u16, ch: u16) -> Key {
    match (scan, ch) {
        (efi::SCAN_UP, _) => Key::Up,
        (efi::SCAN_DOWN, _) => Key::Down,
        (efi::SCAN_ESC, _) => Key::Esc,
        (_, 0x0d) => Key::Enter,
        (_, 0x08) => Key::Backspace,
        (0, c) => char::from_u32(u32::from(c)).map_or(Key::Other, Key::Char),
        _ => Key::Other,
    }
}

/// What to boot: the default when the menu has no wait, else the user's
/// choice (with the command line as edited), or the default when the wait
/// runs out untouched.
pub fn choose(menu: &Menu, screen: Option<&mut Screen>) -> Boot {
    let mut state = State::new(menu);
    if menu.timeout == Some(0) {
        return Boot { entry: state.sel, cmdline: menu.entries[state.sel].cmdline.clone() };
    }
    let (cols, rows) = console::size();
    console::clear();
    let mut graphics = screen.and_then(|s| Some((s, slate_loader::screen::Fonts::new()?)));
    let mut drawn: Option<(State, Option<u64>)> = None;
    let mut shown: Vec<Line> = Vec::new();
    let chosen = loop {
        if let Some((s, fonts)) = graphics.as_mut() {
            let now = (state.clone(), state.secs());
            // The console may have changed the mode (ADR 0111).
            let restored = s.keep();
            if drawn.as_ref() != Some(&now) || restored {
                paint(s, fonts, menu, &state);
                drawn = Some(now);
            }
        } else {
            let now = textmenu::lines(menu, &state, cols, rows);
            for l in now.iter().filter(|l| !shown.contains(l)) {
                console::at(l.col, l.row, usize::from(l.attr), &l.text);
            }
            shown = now;
        }
        let done = match console::key() {
            Some((scan, ch)) => state.key(menu, key(scan, ch)),
            None => {
                (bs().stall)(10_000);
                state.tick(menu)
            }
        };
        if let Some(b) = done {
            break b;
        }
    };
    console::reset();
    console::clear();
    chosen
}

/// Draw the menu and copy it to the framebuffer, in its pixel format.
fn paint(s: &Screen, fonts: &slate_loader::screen::Fonts, menu: &Menu, state: &State) {
    let mut c = slate_ui::Canvas::new(s.width as i32, s.height as i32, slate_ui::graphite::Palette::GRAPHITE.desktop);
    let mut cache = slate_ui::text::GlyphCache::new();
    slate_loader::screen::draw(&mut c, &mut cache, fonts, menu, state);
    let place = |mask: u32, v: u32| {
        if mask == 0 { 0 } else { ((v * (mask >> mask.trailing_zeros())) / 255) << mask.trailing_zeros() }
    };
    for y in 0..s.height as usize {
        let row = &c.pixels[y * s.width as usize..(y + 1) * s.width as usize];
        let dst = (s.base as usize + y * s.stride as usize * 4) as *mut u32;
        for (x, &p) in row.iter().enumerate() {
            let (r, g, b) = ((p >> 16) & 0xff, (p >> 8) & 0xff, p & 0xff);
            let v = match s.format {
                efi::PIXEL_BGR => r << 16 | g << 8 | b,
                efi::PIXEL_RGB => b << 16 | g << 8 | r,
                _ => place(s.masks[0], r) | place(s.masks[1], g) | place(s.masks[2], b),
            };
            // SAFETY: The firmware's framebuffer, `stride` pixels a row and
            // `height` rows, identity mapped.
            unsafe { core::ptr::write_volatile(dst.add(x), v) };
        }
    }
}
