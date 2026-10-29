// SPDX-License-Identifier: MIT OR Apache-2.0

//! The boot menu on a graphical screen (ADR 0089), in graphite
//! (docs/design/WM_STYLE.md) with slate-ui: the contour wallpaper, and a card
//! with Slate's mark, "Choose a system", the systems as rows (the chosen
//! one inverted in chalk, each system's name in DM Mono on the right), a
//! line that counts down quietly, and the keys under a divider.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_ui::graphite::{self, Palette};
use slate_ui::math::round;
use slate_ui::paint::Painter;
use slate_ui::shadow::BoxShadow;
use slate_ui::text::Face;
use slate_ui::ui::Area;
use slate_ui::{Canvas, Color};

use crate::config::Menu;
use crate::menu::{State, wrap};

/// The faces the menu uses, built in (Host Grotesk 400 and 500, DM Mono
/// 400; OFL, `assets/fonts`).
#[derive(Debug)]
pub struct Fonts {
    pub regular: Face<'static>,
    pub medium: Face<'static>,
    pub mono: Face<'static>,
}

static REGULAR: &[u8] = include_bytes!("../../../assets/fonts/HostGrotesk-400.ttf");
static MEDIUM: &[u8] = include_bytes!("../../../assets/fonts/HostGrotesk-500.ttf");
static MONO: &[u8] = include_bytes!("../../../assets/fonts/DMMono-Regular.ttf");

impl Fonts {
    pub fn new() -> Option<Fonts> {
        Some(Fonts { regular: Face::new(REGULAR, 1)?, medium: Face::new(MEDIUM, 2)?, mono: Face::new(MONO, 3)? })
    }
}

/// The card's shadow: the floating one of the launcher and dialogs (§2).
const FLOATING: BoxShadow =
    BoxShadow { dx: 0.0, dy: 40.0, blur: 100.0, spread: -30.0, color: Color::rgb(0).with_alpha(217) };
const CARD_W: f32 = 460.0;
const PAD: f32 = 32.0;
const ROW_H: f32 = 48.0;
/// Text on the inverted row (§5).
const ON_CHALK: Color = Color::rgb(0x121211);

/// The scale for a screen `height` pixels tall: 1 up to 900, in quarter
/// steps above, 2.5 at most.
pub fn scale_for(height: u32) -> f32 {
    let s = height as f32 / 900.0;
    if s <= 1.0 { 1.0 } else { (round(s * 4.0) / 4.0).min(2.5) }
}

fn countdown(secs: Option<u64>) -> String {
    match secs {
        Some(1) => String::from("The highlighted system starts in 1 second."),
        Some(s) => format!("The highlighted system starts in {s} seconds."),
        None => String::from("The highlighted system starts when you press Enter."),
    }
}

/// The field's text: DM Mono 13 on lines 20 tall.
const FIELD_LINE: f32 = 20.0;

/// Draw the menu in `state` on the whole canvas.
pub fn draw(c: &mut Canvas, cache: &mut slate_ui::text::GlyphCache, f: &Fonts, menu: &Menu, state: &State) {
    let pal = Palette::GRAPHITE;
    let scale = scale_for(c.height as u32);
    let mut p = Painter::new(c, cache, scale);
    let (w, h) = p.size();
    graphite::wallpaper(&mut p, &pal, Area::new(0.0, 0.0, w, h));
    let mono = p.style(&f.mono, 13.0, pal.chalk);
    let per_line = ((CARD_W - 28.0) / p.measure(&mono, "0").max(1.0)) as usize;
    // The middle of the card: the rows, or the field being edited.
    let fixed = 28.0 + 20.0 + 30.0 + 6.0 + 21.0 + 24.0 + 20.0 + 1.0 + 16.0 + 18.0;
    let room = (((h - 80.0 - fixed - 2.0 * PAD) / ROW_H) as usize).max(1);
    let shown = menu.entries.len().min(room);
    let first = (state.sel + 1).saturating_sub(shown).min(menu.entries.len() - shown);
    let field: Option<Vec<String>> = state.editing.as_deref().map(|l| wrap(l, per_line.max(8)));
    let middle = match &field {
        Some(lines) => lines.len() as f32 * FIELD_LINE + 24.0,
        None => shown as f32 * ROW_H,
    };
    let inner = fixed + middle;
    let a = Area::new(
        round((w - CARD_W) / 2.0 - PAD),
        round((h - inner - 2.0 * PAD) / 2.0 - h * 0.04),
        CARD_W + 2.0 * PAD,
        inner + 2.0 * PAD,
    );
    p.shadow_under(a, 14.0, &FLOATING);
    p.fill(a, 14.0, pal.overlay);
    p.border(a, 14.0, 1.0, pal.border);
    let x = a.x + PAD;
    let mut y = a.y + PAD;
    p.logo(x, y, 28.0, pal.chalk);
    y += 28.0 + 20.0;
    let title = p.style(&f.medium, 24.0, pal.chalk).tracking(-0.025);
    let body = p.style(&f.regular, 14.0, pal.text_4);
    let hint = p.style(&f.regular, 12.0, pal.muted);
    let keys = match &field {
        Some(lines) => {
            p.line(&title, x, y, 30.0, "Edit the command line");
            y += 30.0 + 6.0;
            let for_entry = format!("For {}, this boot only.", menu.entries[state.sel].title);
            p.line(&body, x, y, 21.0, &for_entry);
            y += 21.0 + 24.0;
            // The field: always focused, the caret after the text.
            let box_ = Area::new(x - 12.0, y, CARD_W + 24.0, middle - 4.0);
            p.fill(box_, 8.0, pal.well);
            p.border(box_.grow(3.0), 11.0, 3.0, pal.chalk.with_alpha(26));
            p.border(box_, 8.0, 1.0, pal.field_focus);
            let mut ly = y + 10.0;
            let mut end = 0.0;
            for l in lines {
                end = p.line(&mono, x + 2.0, ly, FIELD_LINE, l);
                ly += FIELD_LINE;
            }
            p.fill(Area::new(x + 3.0 + end, ly - FIELD_LINE + 3.0, 2.0, FIELD_LINE - 6.0), 0.0, pal.chalk);
            y += middle;
            "Enter  start      Esc  back"
        }
        None => {
            p.line(&title, x, y, 30.0, "Choose a system");
            y += 30.0 + 6.0;
            p.line(&body, x, y, 21.0, &countdown(state.secs()));
            y += 21.0 + 24.0;
            for (i, e) in menu.entries.iter().enumerate().skip(first).take(shown) {
                let row = Area::new(x - 12.0, y, CARD_W + 24.0, ROW_H - 4.0);
                let chosen = i == state.sel;
                if chosen {
                    p.fill(row, 9.0, pal.chalk);
                }
                let name = p.style(&f.medium, 15.0, if chosen { ON_CHALK } else { pal.text_1 });
                let meta = p.style(&f.mono, 12.0, if chosen { pal.selected_meta } else { pal.muted });
                let system = e.system().unwrap_or("");
                let mw = p.measure(&meta, system);
                p.line(&meta, row.x + row.w - 14.0 - mw, row.y, row.h, system);
                let saved = p.clip(Area::new(row.x, row.y, row.w - 28.0 - mw, row.h));
                p.line(&name, row.x + 14.0, row.y, row.h, &e.title);
                p.unclip(saved);
                y += ROW_H;
            }
            "\u{2191} \u{2193}  choose      Enter  start      E  edit"
        }
    };
    y += 20.0;
    p.fill(Area::new(a.x, y, a.w, 1.0), 0.0, pal.active_ws);
    y += 1.0 + 16.0;
    p.line(&hint, x, y, 18.0, keys);
    let version = p.style(&f.mono, 11.5, pal.decor);
    let v = format!("slate-loader {}", crate::VERSION);
    let vw = p.measure(&version, &v);
    p.line(&version, x + CARD_W - vw, y, 18.0, &v);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;
    use slate_ui::text::GlyphCache;
    use std::string::String;
    use std::vec::Vec;

    fn fingerprint(c: &Canvas) -> u64 {
        c.pixels
            .iter()
            .flat_map(|p| p.to_le_bytes())
            .fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3))
    }

    const UPDATED: &str = "timeout: 3\n/Slate\n path: boot():/boot/slate/system-2/kernel\n\
        /Slate (previous system)\n path: boot():/boot/slate/system-1/kernel\n";
    const MEDIA: &str = "timeout: 3\n/Install Slate\n path: boot():/boot/slate/kernel\n\
        /Install Slate (text mode)\n path: boot():/boot/slate/kernel\n";

    /// The screens look as they did when last reviewed (tests/screens.txt;
    /// `SLATE_UI_OUT=DIR` saves them, `SLATE_UI_BLESS=1` records a change).
    #[test]
    fn screens_match_references() {
        let f = Fonts::new().unwrap();
        let updated = parse(UPDATED).unwrap();
        let media = parse(MEDIA).unwrap();
        let many = parse(
            &(1..=12)
                .map(|i| format!("/System {i}\n path: boot():/boot/slate/system-{i}/kernel\n"))
                .collect::<String>(),
        )
        .unwrap();
        // Name, menu, chosen entry, seconds left, width and height.
        type Case<'a> = (&'a str, &'a Menu, usize, Option<u64>, i32, i32);
        let cases: [Case<'_>; 6] = [
            ("counting", &updated, 0, Some(3), 1280, 800),
            ("chosen", &updated, 1, None, 1280, 800),
            ("install-media", &media, 0, Some(1), 1280, 800),
            ("many", &many, 11, None, 1280, 800),
            ("hidpi", &updated, 0, Some(5), 2560, 1440),
            ("editing", &media, 0, None, 1280, 800),
        ];
        let all: Vec<(&str, Canvas)> = cases
            .iter()
            .map(|(name, m, sel, secs, w, h)| {
                let mut c = Canvas::new(*w, *h, Palette::GRAPHITE.desktop);
                let mut cache = GlyphCache::new();
                let editing = (*name == "editing").then(|| {
                    String::from("slate.live quiet slate.ip=192.168.1.202/24,192.168.1.1,8.8.8.8 slate.installer=text")
                });
                let state = State { sel: *sel, left: secs.map(|s| s * 100), editing };
                draw(&mut c, &mut cache, &f, m, &state);
                (*name, c)
            })
            .collect();
        if let Ok(dir) = std::env::var("SLATE_UI_OUT") {
            for (name, c) in &all {
                std::fs::write(format!("{dir}/boot-menu-{name}.png"), slate_ui::png::encode(c)).unwrap();
            }
        }
        // The chosen row is chalk, the card around it `overlay`.
        let (c, s) = (&all[0].1, 1.0);
        assert!((0..c.height).any(|y| c.pixel(640, y) & 0xFF_FFFF == 0xE3E1DC));
        assert!((0..c.height).any(|y| c.pixel((640.0 + 240.0 * s) as i32, y) & 0xFF_FFFF == 0x1C1C1B));
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/screens.txt");
        let got: String = all.iter().map(|(n, c)| format!("{n} {:016x}\n", fingerprint(c))).collect();
        if std::env::var_os("SLATE_UI_BLESS").is_some() {
            std::fs::write(path, &got).unwrap();
            return;
        }
        let want = std::fs::read_to_string(path).unwrap_or_default();
        assert_eq!(
            got, want,
            "boot menu screens changed; look at them (SLATE_UI_OUT=DIR), record with SLATE_UI_BLESS=1"
        );
    }

    #[test]
    fn scales() {
        assert_eq!(
            (scale_for(800), scale_for(1080), scale_for(1440), scale_for(2160), scale_for(4320)),
            (1.0, 1.25, 1.5, 2.5, 2.5)
        );
    }
}
