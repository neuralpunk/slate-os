// SPDX-License-Identifier: MIT OR Apache-2.0

//! The tab strip: a row above the grid with a tab for each shell the
//! window holds and a + button after the last one, which opens another.
//! Each tab shows what its title says (the program, or the shell's folder
//! for the shell itself) and a close button; the chosen one is raised in
//! the window's colour, joined to the grid below it, as Strata's quarters
//! join their windows (docs/design/WM_STYLE.md §2). A dot marks a tab
//! that printed something while it was not shown.
//!
//! Everything here is in logical pixels; the window's scale is the
//! painter's.

use alloc::string::String;
use alloc::vec::Vec;

use slate_strata::draw::truncate_middle;
use slate_strata::fonts::Fonts;
use slate_ui::graphite::Palette;
use slate_ui::icon::Icon;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;

/// The strip's height, its bottom edge included.
pub const STRIP_H: f32 = 36.0;
/// A tab's height and its widest and narrowest.
const TAB_H: f32 = 28.0;
const TAB_MAX: f32 = 220.0;
const TAB_MIN: f32 = 72.0;
/// The space before the first tab, between tabs, and the + button's side.
const LEFT: f32 = 8.0;
const GAP: f32 = 4.0;
const PLUS: f32 = 28.0;
/// The close button's side, inside a tab's right end.
const CLOSE: f32 = 18.0;

/// What a tab shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Label {
    pub text: String,
    /// It printed something while another tab was shown.
    pub unseen: bool,
}

/// What a point of the strip is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hit {
    Tab(usize),
    Close(usize),
    Plus,
    /// The strip, between things.
    Strip,
}

/// The strip's layout for `n` tabs in a window `width` wide.
#[derive(Clone, Debug, PartialEq)]
pub struct Strip {
    pub tabs: Vec<Area>,
    pub plus: Area,
}

impl Strip {
    pub fn new(n: usize, width: f32) -> Strip {
        let y = (STRIP_H - 1.0 - TAB_H) / 2.0 + 1.0;
        let room = (width - LEFT - GAP - PLUS - LEFT).max(0.0);
        let each = if n == 0 { TAB_MAX } else { (room / n as f32 - GAP).clamp(TAB_MIN, TAB_MAX) };
        let tabs: Vec<Area> = (0..n).map(|i| Area::new(LEFT + i as f32 * (each + GAP), y, each, TAB_H)).collect();
        // The + follows the last tab, or keeps to the right edge when the
        // tabs no longer fit (they are then cut off under it).
        let after = tabs.last().map_or(LEFT, |t| t.right() + GAP);
        let px = after.min((width - LEFT - PLUS).max(LEFT));
        Strip { tabs, plus: Area::new(px, y, PLUS, TAB_H) }
    }

    /// The close button of tab `i`.
    pub fn close(&self, i: usize) -> Area {
        let t = self.tabs[i];
        Area::new(t.right() - 6.0 - CLOSE, t.y + (t.h - CLOSE) / 2.0, CLOSE, CLOSE)
    }

    /// What is at (`x`, `y`), if it is in the strip.
    pub fn hit(&self, x: f32, y: f32) -> Option<Hit> {
        if y >= STRIP_H {
            return None;
        }
        if self.plus.contains(x, y) {
            return Some(Hit::Plus);
        }
        for (i, t) in self.tabs.iter().enumerate() {
            if t.contains(x, y) {
                return Some(if self.close(i).contains(x, y) { Hit::Close(i) } else { Hit::Tab(i) });
            }
        }
        Some(Hit::Strip)
    }

    /// Draw the strip across a window `width` wide: `labels` for the tabs,
    /// `active` the one shown, `hover` what the pointer is over.
    #[allow(clippy::too_many_arguments)]
    pub fn draw(
        &self,
        p: &mut Painter<'_>,
        pal: &Palette,
        f: &Fonts<'_>,
        width: f32,
        labels: &[Label],
        active: usize,
        hover: Option<Hit>,
    ) {
        p.fill(Area::new(0.0, 0.0, width, STRIP_H), 0.0, pal.header);
        p.fill(Area::new(0.0, STRIP_H - 1.0, width, 1.0), 0.0, pal.border);
        for (i, (t, label)) in self.tabs.iter().zip(labels).enumerate() {
            let chosen = i == active;
            let over = matches!(hover, Some(Hit::Tab(j) | Hit::Close(j)) if j == i);
            if chosen {
                // Raised in the grid's colour, open at the bottom into it.
                let a = Area::new(t.x, t.y, t.w, STRIP_H - t.y);
                p.fill(a, 7.0, pal.window);
                // Its edge drawn taller, so its bottom corners fall below
                // the strip, then cut off there (the grid's padding).
                p.border(Area::new(a.x, a.y, a.w, a.h + 8.0), 7.0, 1.0, pal.border);
                p.fill(Area::new(a.x, STRIP_H - 1.0, a.w, 9.0), 0.0, pal.window);
                p.fill(Area::new(0.0, STRIP_H - 1.0, a.x, 1.0), 0.0, pal.border);
                p.fill(Area::new(a.right(), STRIP_H - 1.0, width - a.right(), 1.0), 0.0, pal.border);
            } else if over {
                p.fill(*t, 7.0, pal.raised);
            }
            let text = if chosen {
                pal.chalk
            } else if over {
                pal.text_2
            } else {
                pal.muted
            };
            let st = p.style(&f.regular, 12.5, text);
            let mut x = t.x + 12.0;
            if label.unseen && !chosen {
                p.fill(Area::new(x, t.y + t.h / 2.0 - 3.0, 6.0, 6.0), 3.0, pal.accent);
                x += 12.0;
            }
            let room = self.close(i).x - 6.0 - x;
            let shown = truncate_middle(p, &st, &label.text, room.max(0.0));
            p.line(&st, x, t.y, t.h, &shown);
            // The close button: always on the chosen tab, on others under
            // the pointer.
            if chosen || over {
                let c = self.close(i);
                if hover == Some(Hit::Close(i)) {
                    p.fill(c, 4.0, pal.active_ws);
                }
                let colour = if hover == Some(Hit::Close(i)) { pal.chalk } else { pal.muted };
                p.icon(Icon::Close, c.x + 3.0, c.y + 3.0, CLOSE - 6.0, colour);
            }
        }
        let a = self.plus;
        let over = hover == Some(Hit::Plus);
        if over {
            p.fill(a, 7.0, pal.raised);
        }
        let c = if over { pal.chalk } else { pal.muted };
        let (cx, cy) = (a.x + a.w / 2.0, a.y + a.h / 2.0);
        p.fill(Area::new(cx - 6.0, cy - 0.75, 12.0, 1.5), 0.75, c);
        p.fill(Area::new(cx - 0.75, cy - 6.0, 1.5, 12.0), 0.75, c);
    }
}

/// What a tab is called: the folder for the shell itself, else the
/// program in front (with its folder, if there is room).
pub fn label(app: &str, path: &str) -> String {
    match (app, path) {
        ("terminal", "") => String::from("terminal"),
        ("terminal", p) => String::from(p),
        (a, "") => String::from(a),
        (a, p) => alloc::format!("{a} · {p}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_and_hits() {
        let s = Strip::new(1, 800.0);
        assert_eq!(s.tabs[0].w, TAB_MAX);
        assert_eq!(s.plus.x, s.tabs[0].right() + GAP);
        let t = s.tabs[0];
        assert_eq!(s.hit(t.x + 10.0, t.y + 10.0), Some(Hit::Tab(0)));
        let c = s.close(0);
        assert_eq!(s.hit(c.x + 2.0, c.y + 2.0), Some(Hit::Close(0)));
        assert_eq!(s.hit(s.plus.x + 5.0, s.plus.y + 5.0), Some(Hit::Plus));
        assert_eq!(s.hit(790.0, 10.0), Some(Hit::Strip));
        assert_eq!(s.hit(10.0, STRIP_H + 1.0), None);
        // Many tabs share the room, down to their narrowest; the + stays
        // inside the window.
        let s = Strip::new(5, 800.0);
        assert!(s.tabs[0].w < TAB_MAX && s.tabs[0].w >= TAB_MIN);
        assert!(s.plus.right() <= 800.0);
        let s = Strip::new(40, 800.0);
        assert_eq!(s.tabs[0].w, TAB_MIN);
        assert!(s.plus.right() <= 800.0 - LEFT + 0.01);
        assert_eq!(s.hit(s.plus.x + 5.0, s.plus.y + 5.0), Some(Hit::Plus));
    }

    /// The strip drawn: three tabs, the second shown, a dot on the third,
    /// the pointer on the first's close button. `SLATE_UI_OUT=DIR` saves it.
    #[test]
    fn drawn() {
        use alloc::string::ToString;
        use slate_ui::text::GlyphCache;
        use slate_ui::{Canvas, Color};
        let read = |n: &str| -> &'static [u8] {
            let p = alloc::format!("{}/../../assets/fonts/{n}", env!("CARGO_MANIFEST_DIR"));
            std::boxed::Box::leak(std::fs::read(p).unwrap().into_boxed_slice())
        };
        let f = Fonts::new(slate_strata::fonts::FILES.map(read)).unwrap();
        let pal = Palette::GRAPHITE;
        let mut canvas = Canvas::new(800, 120, pal.window);
        let mut cache = GlyphCache::new();
        let s = Strip::new(3, 800.0);
        let labels = [
            Label { text: "~/src/hello-2.12.3".to_string(), unseen: false },
            Label { text: "htop · ~".to_string(), unseen: false },
            Label { text: "~".to_string(), unseen: true },
        ];
        let mut p = Painter::new(&mut canvas, &mut cache, 1.0);
        s.draw(&mut p, &pal, &f, 800.0, &labels, 1, Some(Hit::Close(0)));
        if let Ok(dir) = std::env::var("SLATE_UI_OUT") {
            std::fs::write(alloc::format!("{dir}/terminal-tabs.png"), slate_ui::png::encode(&canvas)).unwrap();
        }
        // The shown tab is the window's colour down into the grid; the
        // strip around it is the header's.
        let t = s.tabs[1];
        assert_eq!(canvas.pixel((t.x + t.w / 2.0) as i32, (STRIP_H - 1.0) as i32), pal.window.0 | 0xFF00_0000);
        assert_eq!(canvas.pixel(799, 2), pal.header.0 | 0xFF00_0000);
        let _ = Color::rgb(0);
    }

    #[test]
    fn labels() {
        assert_eq!(label("terminal", "~/src"), "~/src");
        assert_eq!(label("htop", "~"), "htop · ~");
        assert_eq!(label("terminal", ""), "terminal");
    }
}
