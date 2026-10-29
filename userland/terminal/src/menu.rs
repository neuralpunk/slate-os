// SPDX-License-Identifier: MIT OR Apache-2.0

//! The right-click menu (ADR 0099): Copy, Paste, Select all and Clear
//! scrollback, drawn inside the window as Strata draws its Applications
//! menu (docs/design/WM_STYLE.md §2, §5): an `overlay` surface with a `border`
//! edge and the menu shadow, the chosen row inverted in chalk. The mouse
//! or the arrow keys, Enter and Esc work it.

use slate_strata::draw::MENU;
use slate_strata::fonts::Fonts;
use slate_ui::graphite::Palette;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;

/// What the menu offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Item {
    Copy,
    Paste,
    SelectAll,
    ClearScrollback,
}

pub const ITEMS: [Item; 4] = [Item::Copy, Item::Paste, Item::SelectAll, Item::ClearScrollback];

impl Item {
    fn label(self) -> &'static str {
        match self {
            Item::Copy => "Copy",
            Item::Paste => "Paste",
            Item::SelectAll => "Select all",
            Item::ClearScrollback => "Clear scrollback",
        }
    }

    fn hint(self) -> &'static str {
        match self {
            Item::Copy => "ctrl+shift+c",
            Item::Paste => "ctrl+shift+v",
            Item::SelectAll => "ctrl+shift+a",
            Item::ClearScrollback => "",
        }
    }
}

/// Sizes in logical pixels.
const WIDTH: f32 = 232.0;
const ROW_H: f32 = 30.0;
const PAD: f32 = 6.0;
/// The divider after Paste: 1 px with 4 px either side.
const DIVIDER: f32 = 9.0;
const HEIGHT: f32 = 2.0 * PAD + ROW_H * ITEMS.len() as f32 + DIVIDER;

/// How a key or a click left the menu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Still open (perhaps with another row chosen).
    Open,
    Closed,
    Chose(Item),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Menu {
    /// The top left corner, in logical pixels.
    pub x: f32,
    pub y: f32,
    /// The chosen row (under the pointer or moved to with the keys).
    pub chosen: Option<usize>,
    /// There is a selection to copy.
    pub can_copy: bool,
}

impl Menu {
    /// A menu at the pointer (`x`, `y`), moved to fit a `w` × `h` window
    /// (all logical pixels).
    pub fn open(x: f32, y: f32, w: f32, h: f32, can_copy: bool) -> Menu {
        let x = if x + WIDTH > w { (x - WIDTH).max(0.0) } else { x };
        let y = if y + HEIGHT > h { (h - HEIGHT).max(0.0) } else { y };
        Menu { x, y, chosen: None, can_copy }
    }

    pub fn area(&self) -> Area {
        Area::new(self.x, self.y, WIDTH, HEIGHT)
    }

    fn enabled(&self, i: usize) -> bool {
        ITEMS[i] != Item::Copy || self.can_copy
    }

    /// Row `i`'s area.
    fn row(&self, i: usize) -> Area {
        let gap = if i >= 2 { DIVIDER } else { 0.0 };
        Area::new(self.x + PAD, self.y + PAD + ROW_H * i as f32 + gap, WIDTH - 2.0 * PAD, ROW_H)
    }

    /// The enabled row under (`x`, `y`), if any.
    pub fn item_at(&self, x: f32, y: f32) -> Option<usize> {
        (0..ITEMS.len()).find(|&i| self.enabled(i) && self.row(i).contains(x, y))
    }

    /// The pointer moved: the row under it is chosen. True if that changed.
    pub fn hover(&mut self, x: f32, y: f32) -> bool {
        let at = self.item_at(x, y);
        let changed = at != self.chosen;
        self.chosen = at;
        changed
    }

    /// A click (a button went up) at (`x`, `y`).
    pub fn click(&self, x: f32, y: f32) -> Outcome {
        match self.item_at(x, y) {
            Some(i) => Outcome::Chose(ITEMS[i]),
            None if self.area().contains(x, y) => Outcome::Open,
            None => Outcome::Closed,
        }
    }

    /// A key: the arrows move between enabled rows, Enter chooses, Esc
    /// closes; others close the menu too (and are not typed).
    pub fn key(&mut self, code: u16) -> Outcome {
        const KEY_ESC: u16 = 1;
        const KEY_ENTER: u16 = 28;
        const KEY_KPENTER: u16 = 96;
        const KEY_UP: u16 = 103;
        const KEY_DOWN: u16 = 108;
        let n = ITEMS.len();
        let step = |from: Option<usize>, down: bool| {
            let mut i = from.unwrap_or(if down { n - 1 } else { 0 });
            for _ in 0..n {
                i = if down { (i + 1) % n } else { (i + n - 1) % n };
                if self.enabled(i) {
                    return Some(i);
                }
            }
            None
        };
        match code {
            KEY_UP | KEY_DOWN => {
                self.chosen = step(self.chosen, code == KEY_DOWN);
                Outcome::Open
            }
            KEY_ENTER | KEY_KPENTER => self.chosen.map_or(Outcome::Open, |i| Outcome::Chose(ITEMS[i])),
            KEY_ESC => Outcome::Closed,
            _ => Outcome::Closed,
        }
    }

    pub fn draw(&self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>) {
        let a = self.area();
        p.shadow_under(a, 10.0, &MENU);
        p.fill(a, 10.0, pal.overlay);
        for (i, item) in ITEMS.iter().enumerate() {
            let row = self.row(i);
            let chosen = self.chosen == Some(i);
            let (text, hint) = match (chosen, self.enabled(i)) {
                (true, _) => {
                    p.fill(row, 8.0, pal.chalk);
                    (pal.desktop, pal.selected_meta)
                }
                (false, true) => (pal.chalk, pal.muted),
                (false, false) => (pal.inactive, pal.inactive),
            };
            let st = p.style(&f.regular, 13.0, text);
            p.line(&st, row.x + 10.0, row.y, row.h, item.label());
            if !item.hint().is_empty() {
                let st = p.style(&f.mono, 11.0, hint);
                let w = p.measure(&st, item.hint());
                p.line(&st, row.right() - 10.0 - w, row.y, row.h, item.hint());
            }
        }
        let y = self.row(1).bottom() + 4.0;
        p.fill(Area::new(a.x + 1.0, y, a.w - 2.0, 1.0), 0.0, pal.active_ws);
        p.border(a, 10.0, 1.0, pal.border);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placing_choosing_and_keys() {
        // Near the bottom right, it opens up and to the left.
        let m = Menu::open(700.0, 500.0, 800.0, 560.0, false);
        assert_eq!((m.x, m.y), (700.0 - WIDTH, 560.0 - HEIGHT));
        let mut m = Menu::open(10.0, 10.0, 800.0, 560.0, false);
        // Copy is disabled without a selection; Paste is the first row on.
        let paste = m.row(1);
        assert_eq!(m.item_at(m.row(0).x + 5.0, m.row(0).y + 5.0), None);
        assert_eq!(m.click(paste.x + 5.0, paste.y + 5.0), Outcome::Chose(Item::Paste));
        assert_eq!(m.click(m.x + 2.0, m.y + 2.0), Outcome::Open);
        assert_eq!(m.click(5.0, 5.0), Outcome::Closed);
        // Below the divider.
        let clear = m.row(3);
        assert_eq!(m.click(clear.x + 5.0, clear.bottom() - 2.0), Outcome::Chose(Item::ClearScrollback));
        assert!(m.hover(clear.x + 5.0, clear.y + 5.0));
        assert!(!m.hover(clear.x + 6.0, clear.y + 5.0));
        // Keys skip the disabled row, round the ends.
        m.chosen = None;
        assert_eq!(m.key(108), Outcome::Open);
        assert_eq!(m.chosen, Some(1));
        m.key(103);
        assert_eq!(m.chosen, Some(3));
        assert_eq!(m.key(28), Outcome::Chose(Item::ClearScrollback));
        assert_eq!(m.key(1), Outcome::Closed);
        let mut m = Menu::open(10.0, 10.0, 800.0, 560.0, true);
        m.key(108);
        assert_eq!(m.chosen, Some(0));
    }
}
