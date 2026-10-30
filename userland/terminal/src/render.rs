// SPDX-License-Identifier: MIT OR Apache-2.0

//! Drawing the terminal's grid in graphite's terminal style
//! (docs/design/WM_STYLE.md §7): DM Mono 13 on 21 px lines, the `window`
//! background, `text-2` text, the desaturated 16 colours (the light
//! variant's in day mode, §9) plus the xterm 256-colour cube and grey
//! ramp, direct colours as they are, bold as DM Mono 500, italics in DM
//! Mono's italic faces (slanted when they aren't installed, ADR 0166),
//! faint text halfway to the background, and an 8 × 16 block cursor in
//! `muted` that turns `chalk` while typing. Wide characters take two
//! cells (ADR 0099).
//!
//! Scrolled back, it shows the scrollback, with a thin `decor` bar at the
//! right edge for where the view is. Selected text is `chalk` on
//! `border-strong`: the guide keeps inversion for small things, and a
//! selection can cover the window (ADR 0038).

use slate_term::vt::{self, Attr, Cell, Term};
use slate_ui::Color;
use slate_ui::canvas::{Canvas, Rect};
use slate_ui::graphite::{self, Palette};
use slate_ui::math::{floor, round};
use slate_ui::text::{self, Face, GlyphCache, Style};

use slate_strata::fonts::Fonts;

use crate::select::{Point, Selection};

/// The font size and line height, in logical pixels.
pub const SIZE: f32 = 13.0;
pub const LINE: f32 = 21.0;
/// A cell's width at scale 1: DM Mono's 600-unit advance at 13 px.
pub const CELL_W: f32 = 7.8;
/// The space around the grid, in logical pixels.
pub const PAD_X: f32 = 16.0;
pub const PAD_Y: f32 = 12.0;

/// The grid's geometry in device pixels.
#[derive(Clone, Copy, Debug)]
pub struct Metrics {
    pub scale: f32,
    pub cell_w: f32,
    pub line_h: f32,
    pub pad_x: f32,
    pub pad_y: f32,
    /// The tab strip's height above the grid (device pixels).
    pub top: f32,
}

impl Metrics {
    pub fn new(f: &Fonts<'_>, scale: f32) -> Metrics {
        let st = Style::new(&f.mono, SIZE * scale, Color::rgb(0));
        Metrics {
            scale,
            cell_w: text::width(&st, "M"),
            line_h: round(LINE * scale),
            pad_x: PAD_X * scale,
            pad_y: PAD_Y * scale,
            top: crate::tabs::STRIP_H * scale,
        }
    }

    /// The columns and rows that fit `width` × `height` device pixels.
    pub fn grid(&self, width: u32, height: u32) -> (usize, usize) {
        let cols = floor((width as f32 - 2.0 * self.pad_x) / self.cell_w).max(1.0) as usize;
        let rows = floor((height as f32 - 2.0 * self.pad_y - self.top) / self.line_h).max(1.0) as usize;
        (cols, rows)
    }
}

/// The colours the terminal draws with: the desktop's palette and the
/// 16 terminal colours that go with it.
#[derive(Clone, Copy, Debug)]
pub struct Theme {
    pub pal: Palette,
    pub ansi: &'static [Color; 16],
    /// The prompt's `user@host` (bright white when None) and its sign
    /// (ADR 0124, ADR 0167), for /etc/profile's PS1.
    pub prompt_user: Option<Color>,
    pub prompt_sign: Color,
}

impl Theme {
    pub const GRAPHITE: Theme = Theme {
        pal: Palette::GRAPHITE,
        ansi: &graphite::ANSI,
        prompt_user: None,
        prompt_sign: Palette::GRAPHITE.inactive,
    };

    /// The colours for a person's theme and high contrast (ADR 0167;
    /// Sediment's terminal is dark).
    pub fn pick(theme: slate_ui::themes::Theme, high_contrast: bool) -> Theme {
        use slate_ui::themes::Theme as Look;
        let pal = theme.terminal(high_contrast);
        // The themes in colour sign the prompt in their accent, and
        // Sediment's names the user in its clock's gold (the handoff,
        // §2.6, §3.6); graphite and Light (and high contrast) in greys.
        let (prompt_user, prompt_sign) = match (theme, high_contrast) {
            (Look::CopperNoir, false) => (None, pal.accent),
            (Look::Sediment, false) => (Some(Color::rgb(0xF3C98B)), pal.accent),
            _ => (None, pal.inactive),
        };
        Theme { pal, ansi: pal.ansi, prompt_user, prompt_sign }
    }

    /// A colour index's colour: the 16, then xterm's 6 × 6 × 6 cube and 24
    /// greys (xterm's 256-colour palette); direct colours as they are.
    pub fn colour(&self, c: vt::Color) -> Color {
        let rgb = |r: u32, g: u32, b: u32| Color::rgb((r << 16) | (g << 8) | b);
        match c {
            vt::Color::Rgb(r, g, b) => rgb(r.into(), g.into(), b.into()),
            vt::Color::Index(index @ 0..=15) => self.ansi[index as usize],
            vt::Color::Index(index @ 16..=231) => {
                let i = index - 16;
                let level = |v: u8| if v == 0 { 0 } else { 55 + 40 * v as u32 };
                rgb(level(i / 36), level(i / 6 % 6), level(i % 6))
            }
            vt::Color::Index(index) => {
                let g = 8 + 10 * (index - 232) as u32;
                rgb(g, g, g)
            }
        }
    }
}

/// The cursor's look.
#[derive(Clone, Copy, Debug)]
pub struct Cursor {
    pub focused: bool,
    /// A key was pressed just now: the cursor is chalk.
    pub typing: bool,
}

/// What part of the text is shown, and what is selected.
#[derive(Clone, Copy, Debug, Default)]
pub struct View {
    /// Lines scrolled back from the live screen.
    pub offset: usize,
    /// The selection's span (from [`Selection::span`]).
    pub span: Option<(Point, Point)>,
}

impl Metrics {
    /// The row and the column boundary nearest a point in device pixels
    /// (for character selections), and the cell under it.
    pub fn locate(&self, x: i32, y: i32, rows: usize, cols: usize) -> (usize, usize, usize) {
        let row = floor((y as f32 - self.top - self.pad_y) / self.line_h).clamp(0.0, rows as f32 - 1.0) as usize;
        let at = (x as f32 - self.pad_x) / self.cell_w;
        let boundary = round(at).clamp(0.0, cols as f32) as usize;
        let cell = floor(at).clamp(0.0, cols as f32 - 1.0) as usize;
        (row, boundary, cell)
    }
}

/// The foreground and background of a cell. Colour 0 as a background is
/// the window's own (the emulator's default background); faint text is
/// halfway to its background.
fn colours(t: &Theme, a: &Attr) -> (Color, Option<Color>) {
    let (fg, bg) = a.resolved();
    let index0 = |c: vt::Color| c == vt::Color::Index(0);
    let bg = if index0(bg) && !a.reverse { None } else { Some(if index0(bg) { t.pal.window } else { t.colour(bg) }) };
    let fg = if index0(fg) && a.reverse { t.pal.window } else { t.colour(fg) };
    let fg = if a.dim { graphite::mix(fg, bg.unwrap_or(t.pal.window), 0.5) } else { fg };
    (fg, bg)
}

/// A cell's text: its character and extras (as many as fit).
fn glyphs(term: &Term, cell: &Cell, out: &mut [u8; 64]) -> usize {
    let mut n = cell.ch.encode_utf8(&mut out[..4]).len();
    for m in term.extras(cell) {
        if n + m.len_utf8() > out.len() {
            break;
        }
        n += m.encode_utf8(&mut out[n..]).len();
    }
    n
}

/// DM Mono's italic faces, regular and medium, when installed.
#[derive(Debug, Default)]
pub struct Italics<'a> {
    pub regular: Option<Face<'a>>,
    pub medium: Option<Face<'a>>,
}

impl<'a> Italics<'a> {
    /// From the files [`slate_strata::session::load_italics`] read.
    pub fn new(files: &'a [alloc::vec::Vec<u8>]) -> Italics<'a> {
        Italics {
            regular: files.first().and_then(|b| Face::new(b, 6)),
            medium: files.get(1).and_then(|b| Face::new(b, 7)),
        }
    }
}

/// The face for a cell's attributes, and whether it must be slanted (an
/// italic with no italic face).
fn face_for<'f, 'a>(f: &'f Fonts<'a>, it: &'f Italics<'a>, a: &Attr) -> (&'f Face<'a>, bool) {
    match (a.italic, a.bold) {
        (true, true) => it.medium.as_ref().map_or((&f.mono_medium, true), |x| (x, false)),
        (true, false) => it.regular.as_ref().map_or((&f.mono, true), |x| (x, false)),
        (false, true) => (&f.mono_medium, false),
        (false, false) => (&f.mono, false),
    }
}

/// Draw `term` filling `canvas`, as `view` says.
#[allow(clippy::too_many_arguments)]
pub fn draw(
    canvas: &mut Canvas,
    cache: &mut GlyphCache,
    f: &Fonts<'_>,
    it: &Italics<'_>,
    theme: &Theme,
    term: &Term,
    m: &Metrics,
    c: Cursor,
    view: &View,
) {
    let pal = &theme.pal;
    canvas.fill_rect(canvas.bounds(), pal.window);
    let size = SIZE * m.scale;
    let base = f.mono.baseline(size, m.line_h);
    let x_of = |col: usize| m.pad_x + col as f32 * m.cell_w;
    let offset = view.offset.min(term.history_len());
    let first = term.history_len() - offset;
    for row in 0..term.rows() {
        let top = m.top + m.pad_y + row as f32 * m.line_h;
        let (cells, _) = term.line(first + row).unwrap_or((&[], false));
        let number = term.dropped() + (first + row) as u64;
        let cell = |col: usize| cells.get(col).copied().unwrap_or(Cell::BLANK);
        let selected = |col: usize| view.span.is_some_and(|s| Selection::covers(s, number, col));
        // Backgrounds first, then the characters.
        for col in 0..term.cols() {
            let bg = if selected(col) { Some(pal.border_strong) } else { colours(theme, &cell(col).attr).1 };
            if let Some(bg) = bg {
                let (x0, x1) = (round(x_of(col)) as i32, round(x_of(col + 1)) as i32);
                canvas.fill_rect(Rect::new(x0, top as i32, x1 - x0, m.line_h as i32), bg);
            }
        }
        for col in 0..term.cols() {
            let cell = cell(col);
            if cell.is_tail() {
                continue;
            }
            let fg = if selected(col) { pal.chalk } else { colours(theme, &cell.attr).0 };
            let span = cell.width().min(term.cols() - col);
            if cell.ch != ' ' {
                let (face, slant) = face_for(f, it, &cell.attr);
                let st = Style::new(face, size, fg).oblique(slant);
                let mut s = [0u8; 64];
                let n = glyphs(term, &cell, &mut s);
                // Wide characters are centred in their two cells.
                let w = if span == 2 { text::width(&st, cell.ch.encode_utf8(&mut [0u8; 4])) } else { m.cell_w };
                let x = x_of(col) + (span as f32 * m.cell_w - w).max(0.0) / 2.0;
                text::draw(canvas, cache, &st, x, top + base, core::str::from_utf8(&s[..n]).unwrap_or(" "));
            }
            let (x0, x1) = (round(x_of(col)) as i32, round(x_of(col + span)) as i32);
            if cell.attr.underline {
                canvas.fill_rect(Rect::new(x0, (top + base + 2.0 * m.scale) as i32, x1 - x0, m.scale as i32), fg);
            }
            if cell.attr.strike {
                let y = top + base - 0.3 * size;
                canvas.fill_rect(Rect::new(x0, y as i32, x1 - x0, m.scale.max(1.0) as i32), fg);
            }
        }
    }
    if offset > 0 {
        // Where the view is in the scrollback.
        let total = (term.history_len() + term.rows()) as f32;
        let h = canvas.height as f32;
        let thumb = (h * term.rows() as f32 / total).max(16.0 * m.scale);
        let y = (h - thumb) * first as f32 / term.history_len() as f32;
        let w = (3.0 * m.scale) as i32;
        canvas.fill_rect(Rect::new(canvas.width - w - (2.0 * m.scale) as i32, y as i32, w, thumb as i32), pal.decor);
    }
    // The cursor, if its row is in view.
    if term.cursor_visible && term.cursor().0 + offset < term.rows() {
        let (row, col) = term.cursor();
        let row = row + offset;
        let under = term.cell(row - offset, col);
        let wide = under.width() == 2 && col + 1 < term.cols();
        let (w, h) = (if wide { 16.0 * m.scale } else { (8.0 * m.scale).min(m.cell_w) }, 16.0 * m.scale);
        let x = round(x_of(col)) as i32;
        let y = round(m.top + m.pad_y + row as f32 * m.line_h + (m.line_h - h) / 2.0) as i32;
        let r = Rect::new(x, y, w as i32, h as i32);
        if c.focused {
            // The theme's accent while typing (chalk in graphite).
            canvas.fill_rect(r, if c.typing { pal.accent } else { pal.muted });
            let cell = under;
            if cell.ch != ' ' && !cell.is_tail() {
                let (face, slant) = face_for(f, it, &cell.attr);
                let mut s = [0u8; 64];
                let n = glyphs(term, &cell, &mut s);
                let top = m.top + m.pad_y + row as f32 * m.line_h;
                let st = Style::new(face, size, pal.window).oblique(slant);
                let x = if wide {
                    x_of(col) + (2.0 * m.cell_w - text::width(&st, cell.ch.encode_utf8(&mut [0u8; 4]))) / 2.0
                } else {
                    x_of(col)
                };
                text::draw(canvas, cache, &st, x, top + base, core::str::from_utf8(&s[..n]).unwrap_or(" "));
            }
        } else {
            let k = m.scale.max(1.0) as i32;
            for edge in [
                Rect::new(r.x, r.y, r.w, k),
                Rect::new(r.x, r.bottom() - k, r.w, k),
                Rect::new(r.x, r.y, k, r.h),
                Rect::new(r.right() - k, r.y, k, r.h),
            ] {
                canvas.fill_rect(edge, pal.muted);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;

    fn fonts() -> Fonts<'static> {
        let read = |n: &str| -> &'static [u8] {
            let p = format!("{}/../../assets/fonts/{n}", env!("CARGO_MANIFEST_DIR"));
            std::boxed::Box::leak(std::fs::read(p).unwrap().into_boxed_slice())
        };
        Fonts::new(slate_strata::fonts::FILES.map(read)).unwrap()
    }

    fn italics() -> Italics<'static> {
        let files: std::vec::Vec<std::vec::Vec<u8>> = slate_strata::session::ITALIC_FILES
            .iter()
            .map(|n| std::fs::read(format!("{}/../../assets/fonts/{n}", env!("CARGO_MANIFEST_DIR"))).unwrap())
            .collect();
        Italics::new(std::boxed::Box::leak(files.into_boxed_slice()))
    }

    #[test]
    fn palette() {
        let t = Theme::GRAPHITE;
        let i = vt::Color::Index;
        assert_eq!(t.colour(i(7)), Color::rgb(0xBEBCB7));
        assert_eq!(t.colour(i(15)), Color::rgb(0xE3E1DC));
        assert_eq!(t.colour(i(16)), Color::rgb(0x000000));
        assert_eq!(t.colour(i(196)), Color::rgb(0xFF0000));
        assert_eq!(t.colour(i(244)), Color::rgb(0x808080));
        assert_eq!(t.colour(vt::Color::Rgb(0x12, 0x34, 0x56)), Color::rgb(0x123456));
        // The light variant's 16, the cube unchanged.
        let day = Theme::pick(slate_ui::themes::Theme::Light, false);
        assert_eq!(day.colour(i(7)), Color::rgb(0x2A2A2A));
        assert_eq!(day.colour(i(196)), Color::rgb(0xFF0000));
        // Sediment's terminal is dark inside the light theme (ADR 0167),
        // Copper Noir's the theme's own window.
        let sediment = Theme::pick(slate_ui::themes::Theme::Sediment, false);
        assert_eq!((sediment.pal.window, sediment.colour(i(7))), (Color::rgb(0x2B2622), Color::rgb(0xD9CBB7)));
        let copper = Theme::pick(slate_ui::themes::Theme::CopperNoir, false);
        assert_eq!((copper.pal.window, copper.colour(i(3))), (Color::rgb(0x1A1918), Color::rgb(0xE0B472)));
        // Faint text is halfway to the background.
        let a = Attr { dim: true, ..Attr::DEFAULT };
        assert_eq!(colours(&t, &a), (graphite::mix(Color::rgb(0xBEBCB7), t.pal.window, 0.5), None));
    }

    #[test]
    fn grid_and_rendering() {
        let f = fonts();
        // The grid alone, at the window's top (no tab strip above it).
        let m = Metrics { top: 0.0, ..Metrics::new(&f, 1.0) };
        // DM Mono advances 600 units of 1000: 7.8 px at 13.
        assert!((m.cell_w - 7.8).abs() < 0.01);
        assert_eq!(m.grid(560, 400), (67, 17));
        // The tab strip above it takes a row's room.
        assert_eq!(Metrics::new(&f, 1.0).grid(560, 400), (67, 16));
        let mut t = Term::new(40, 6);
        t.feed(b"\x1b[1;97malex@workstation\x1b[0m \x1b[38;5;245m~/slate\x1b[0m $ ls\r\n\x1b[31mred\x1b[0m \x1b[7minverse\x1b[0m");
        let mut canvas = Canvas::new(400, 160, Color::rgb(0));
        let mut cache = GlyphCache::new();
        let c = Cursor { focused: true, typing: false };
        draw(&mut canvas, &mut cache, &f, &italics(), &Theme::GRAPHITE, &t, &m, c, &View::default());
        if let Ok(dir) = std::env::var("SLATE_UI_OUT") {
            std::fs::write(format!("{dir}/terminal.png"), slate_ui::png::encode(&canvas)).unwrap();
        }
        // The background, a chalk prompt pixel, the inverse block.
        assert_eq!(canvas.pixel(399, 159), 0xFF1A_1A19);
        let row0 = (12..33).flat_map(|y| (16..140).map(move |x| (x, y)));
        assert!(row0.into_iter().any(|(x, y)| canvas.pixel(x, y) == 0xFFE3_E1DC));
        let inverse_x = (16.0 + 4.0 * m.cell_w + 2.0) as i32;
        assert_eq!(canvas.pixel(inverse_x, 12 + 21 + 2), 0xFFBE_BCB7);
    }

    #[test]
    fn direct_colours_wide_characters_and_the_light_variant() {
        let f = fonts();
        // The grid alone, at the window's top (no tab strip above it).
        let m = Metrics { top: 0.0, ..Metrics::new(&f, 1.0) };
        let mut t = Term::new(30, 3);
        // A direct-colour block, a wide character, italic and crossed-out text.
        t.feed("\x1b[48;2;18;52;86m  \x1b[0m 中 \x1b[3mitalic\x1b[0m \x1b[9mx\x1b[0m".as_bytes());
        let mut canvas = Canvas::new(300, 80, Color::rgb(0));
        let mut cache = GlyphCache::new();
        let c = Cursor { focused: false, typing: false };
        draw(&mut canvas, &mut cache, &f, &italics(), &Theme::GRAPHITE, &t, &m, c, &View::default());
        if let Ok(dir) = std::env::var("SLATE_UI_OUT") {
            std::fs::write(format!("{dir}/terminal-colours.png"), slate_ui::png::encode(&canvas)).unwrap();
        }
        // The block is exactly its colour.
        assert_eq!(canvas.pixel(16 + 4, 12 + 10), 0xFF12_3456);
        // The wide character's ink spreads over both its cells.
        let ink =
            |x0: f32, x1: f32| (12..33).any(|y| (x0 as i32..x1 as i32).any(|x| canvas.pixel(x, y) != 0xFF1A_1A19));
        let x = |col: usize| 16.0 + col as f32 * m.cell_w;
        assert!(ink(x(3), x(4)) && ink(x(4), x(5)));
        // The same text in day mode: the window and text-2 of the light variant.
        let day = Theme::pick(slate_ui::themes::Theme::Light, false);
        draw(&mut canvas, &mut cache, &f, &italics(), &day, &t, &m, c, &View::default());
        assert_eq!(canvas.pixel(299, 79), 0xFFF3_F2F2);
        assert_eq!(canvas.pixel(16 + 4, 12 + 10), 0xFF12_3456);
    }

    #[test]
    fn scrollback_and_selection() {
        let f = fonts();
        // The grid alone, at the window's top (no tab strip above it).
        let m = Metrics { top: 0.0, ..Metrics::new(&f, 1.0) };
        let mut t = Term::new(20, 3);
        t.set_scrollback(10);
        t.feed(b"first\r\nsecond\r\nthird\r\nfourth\r\nfifth");
        assert_eq!(t.history_len(), 2);
        // A pointer on "second"'s third character, scrolled back by one.
        let (row, boundary, cell) = m.locate(16 + 2 * 8 + 3, 12 + 21 + 4, 3, 20);
        assert_eq!((row, boundary, cell), (1, 2, 2));
        let sel = Selection::new(Point { line: 1, col: 0 }, crate::select::Unit::Line);
        let view = View { offset: 1, span: Some(sel.span(&t)) };
        let mut canvas = Canvas::new(400, 100, Color::rgb(0));
        let mut cache = GlyphCache::new();
        let c = Cursor { focused: true, typing: false };
        draw(&mut canvas, &mut cache, &f, &italics(), &Theme::GRAPHITE, &t, &m, c, &view);
        if let Ok(dir) = std::env::var("SLATE_UI_OUT") {
            std::fs::write(format!("{dir}/terminal-scrolled.png"), slate_ui::png::encode(&canvas)).unwrap();
        }
        // Row 0 shows "second", selected; the bar marks the view.
        assert_eq!(canvas.pixel(150, 12 + 2), 0xFF3A_3A38);
        assert_eq!(canvas.pixel(150, 12 + 21 + 2), 0xFF1A_1A19);
        assert_eq!(canvas.pixel(400 - 4, 30), 0xFF5F_5D59);
        assert_eq!(sel.text(&t), "second");
    }
}
