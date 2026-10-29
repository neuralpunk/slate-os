// SPDX-License-Identifier: MIT OR Apache-2.0

//! Widgets: the components of docs/design/INSTALLER_STYLE.md §3-§4, drawn in
//! logical pixels (the window's own coordinates) onto a canvas at a
//! whole-number scale.
//!
//! A front end draws a frame by calling the widget functions on a [`Ui`];
//! they record where each control is (`Frame::hits`) and the keyboard
//! order (`Frame::focus`). The front end routes the next event with them.

use alloc::string::String;
use alloc::vec::Vec;

use crate::anim::Transitions;
use crate::canvas::{Canvas, Rect};
use crate::color::Color;
use crate::edit::EditKey;
use crate::icon::{self, Icon};
use crate::logo;
use crate::path::{Path, Transform};
use crate::shadow::{self, BoxShadow};
use crate::text::{self, Face, GlyphCache, Style};
use crate::theme::{Fonts, Theme};

/// A control's identity, chosen by the front end.
pub type Id = u32;

/// A rectangle in logical pixels.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Area {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

impl Area {
    pub const fn new(x: f32, y: f32, w: f32, h: f32) -> Area {
        Area { x, y, w, h }
    }

    pub fn contains(&self, x: f32, y: f32) -> bool {
        x >= self.x && y >= self.y && x < self.x + self.w && y < self.y + self.h
    }

    pub fn right(&self) -> f32 {
        self.x + self.w
    }

    pub fn bottom(&self) -> f32 {
        self.y + self.h
    }

    /// Grown by `d` on every side.
    pub fn grow(&self, d: f32) -> Area {
        Area::new(self.x - d, self.y - d, self.w + 2.0 * d, self.h + 2.0 * d)
    }

    /// The part inside `o` too (zero-sized if none).
    pub fn intersect(&self, o: &Area) -> Area {
        let (x, y) = (self.x.max(o.x), self.y.max(o.y));
        let (r, b) = (self.right().min(o.right()), self.bottom().min(o.bottom()));
        Area::new(x, y, (r - x).max(0.0), (b - y).max(0.0))
    }
}

/// Keys the widgets understand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Tab,
    BackTab,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    Enter,
    Escape,
    Space,
    Backspace,
    Delete,
    /// A character, or with ctrl held a shortcut's letter.
    Char(char),
}

/// The modifiers held with a key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Mods {
    pub shift: bool,
    pub ctrl: bool,
}

impl Mods {
    pub const NONE: Mods = Mods { shift: false, ctrl: false };
}

/// What a key means to a text field (ADR 0101): the moves, deleting,
/// and ctrl + a, c, x and v.
pub fn edit_key(k: Key, m: Mods) -> Option<EditKey> {
    Some(match k {
        Key::Left => EditKey::Left,
        Key::Right => EditKey::Right,
        Key::Home => EditKey::Home,
        Key::End => EditKey::End,
        Key::Backspace => EditKey::Backspace,
        Key::Delete => EditKey::Delete,
        Key::Char(c) if m.ctrl => match c.to_ascii_lowercase() {
            'a' => EditKey::SelectAll,
            'c' => EditKey::Copy,
            'x' => EditKey::Cut,
            'v' => EditKey::Paste,
            _ => return None,
        },
        _ => return None,
    })
}

/// Input, in device pixels for the pointer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Event {
    Key(Key, Mods),
    PointerMove(f32, f32),
    PointerDown(f32, f32),
    PointerUp(f32, f32),
}

/// A text field as drawn: where its text starts (logical x, after
/// scrolling) and its character boundaries from there.
#[derive(Clone, Debug, Default)]
pub struct FieldText {
    pub id: Id,
    pub x: f32,
    pub carets: Vec<f32>,
}

/// What one frame drew: clickable areas, the tab order, text fields'
/// caret positions, and whether a transition is still running.
#[derive(Clone, Debug, Default)]
pub struct Frame {
    pub hits: Vec<(Id, Area)>,
    pub focus: Vec<Id>,
    pub fields: Vec<FieldText>,
    /// Draw again soon: a colour is still changing (ADR 0101).
    pub animating: bool,
}

impl Frame {
    /// The character boundary of field `id` nearest logical `x`.
    pub fn caret_at(&self, id: Id, x: f32) -> Option<usize> {
        let f = self.fields.iter().find(|f| f.id == id)?;
        Some(text::boundary_at(&f.carets, x - f.x))
    }

    /// The control under the pointer (the last drawn wins).
    pub fn hit(&self, x: f32, y: f32) -> Option<Id> {
        self.hits.iter().rev().find(|(_, a)| a.contains(x, y)).map(|&(id, _)| id)
    }

    /// The next (or previous) tab stop after `from`.
    pub fn next_focus(&self, from: Option<Id>, back: bool) -> Option<Id> {
        if self.focus.is_empty() {
            return None;
        }
        let n = self.focus.len();
        let i = from.and_then(|f| self.focus.iter().position(|&x| x == f));
        let j = match (i, back) {
            (None, false) => 0,
            (None, true) => n - 1,
            (Some(i), false) => (i + 1) % n,
            (Some(i), true) => (i + n - 1) % n,
        };
        Some(self.focus[j])
    }
}

/// Button styles (§4, "Buttons").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    Primary,
    Secondary,
    Ghost,
    Disabled,
}

/// A text field's contents and how to show them.
#[derive(Clone, Copy, Debug)]
pub struct Field<'s> {
    pub label: &'s str,
    pub value: &'s str,
    /// The caret and the selection's anchor (character indices), shown
    /// when the field has the focus; None: the caret at the end.
    pub cursor: Option<(usize, Option<usize>)>,
    /// Usernames and computer names are shown in DM Mono.
    pub mono: bool,
    pub password: bool,
    /// Help (text-3) or, if `error`, an error message.
    pub note: Option<&'s str>,
    pub error: bool,
}

/// A choice row's contents (§4, "Choice row").
#[derive(Clone, Copy, Debug, Default)]
pub struct Choice<'s> {
    pub title: &'s str,
    /// Metadata under the title, in DM Mono ("nvme0n1").
    pub meta: Option<&'s str>,
    /// The right-aligned value, in DM Mono ("1 TB").
    pub value: Option<&'s str>,
    /// Lines of description under the title, for the taller rows.
    pub description: &'s [&'s str],
}

/// The window's fixed size (§3).
pub const WINDOW_W: f32 = 860.0;
pub const WINDOW_H: f32 = 560.0;
pub const TITLE_H: f32 = 44.0;
pub const SIDEBAR_W: f32 = 196.0;
pub const FOOTER_H: f32 = 72.0;
/// The close button in the title bar.
pub const CLOSE: Id = 0xFFFF_0001;

pub struct Ui<'a, 'f> {
    pub canvas: &'a mut Canvas,
    pub cache: &'a mut GlyphCache,
    pub fonts: &'a Fonts<'f>,
    pub theme: Theme,
    /// Device pixels per logical pixel.
    pub scale: f32,
    /// Where the window's logical (0, 0) is, in device pixels.
    pub origin: (f32, f32),
    /// The pointer in logical pixels, if there is one.
    pub pointer: Option<(f32, f32)>,
    pub focus: Option<Id>,
    /// Focus outlines show only once the keyboard has been used.
    pub focus_visible: bool,
    pub frame: Frame,
    /// Colour and border changes, eased over time (ADR 0101); None: at
    /// once.
    pub anim: Option<&'a mut Transitions>,
}

impl core::fmt::Debug for Ui<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ui(scale {}, focus {:?})", self.scale, self.focus)
    }
}

impl<'a, 'f> Ui<'a, 'f> {
    pub fn new(canvas: &'a mut Canvas, cache: &'a mut GlyphCache, fonts: &'a Fonts<'f>, scale: f32) -> Ui<'a, 'f> {
        let origin = (
            crate::math::round((canvas.width as f32 - WINDOW_W * scale) / 2.0),
            crate::math::round((canvas.height as f32 - WINDOW_H * scale) / 2.0),
        );
        Ui {
            canvas,
            cache,
            fonts,
            theme: Theme::LIGHT,
            scale,
            origin,
            pointer: None,
            focus: None,
            focus_visible: false,
            frame: Frame::default(),
            anim: None,
        }
    }

    /// Control `id`'s colour in `slot` on its way to `target`.
    fn animated(&mut self, id: Id, slot: u8, target: Color) -> Color {
        match self.anim.as_deref_mut() {
            Some(t) => {
                let (c, moving) = t.colour(id, slot, target);
                self.frame.animating |= moving;
                c
            }
            None => target,
        }
    }

    /// A hover fill that fades in and out: transparent when not hovered.
    fn hover_fill(&mut self, id: Id, a: Area, r: f32, on: bool, c: Color) {
        let c = self.animated(id, 0, if on { c } else { c.faded(0.0) });
        if c.alpha() > 0 {
            self.fill(a, r, c);
        }
    }

    /// The window coordinates of a device position.
    pub fn to_logical(&self, x: f32, y: f32) -> (f32, f32) {
        ((x - self.origin.0) / self.scale, (y - self.origin.1) / self.scale)
    }

    fn t(&self) -> Transform {
        Transform::new(self.scale, self.origin.0, self.origin.1)
    }

    fn device(&self, a: &Area) -> Rect {
        let x0 = crate::math::round(self.origin.0 + a.x * self.scale) as i32;
        let y0 = crate::math::round(self.origin.1 + a.y * self.scale) as i32;
        let x1 = crate::math::round(self.origin.0 + a.right() * self.scale) as i32;
        let y1 = crate::math::round(self.origin.1 + a.bottom() * self.scale) as i32;
        Rect::new(x0, y0, x1 - x0, y1 - y0)
    }

    fn hovered(&self, a: &Area) -> bool {
        self.pointer.is_some_and(|(x, y)| a.contains(x, y))
    }

    fn focused(&self, id: Id) -> bool {
        self.focus_visible && self.focus == Some(id)
    }

    // --- drawing primitives -------------------------------------------

    /// Fill `a` with `c` (corner radius `r`).
    pub fn fill(&mut self, a: Area, r: f32, c: Color) {
        if r == 0.0 {
            let d = self.device(&a);
            self.canvas.fill_rect(d, c);
        } else {
            let t = self.t();
            Path::rounded_rect(a.x, a.y, a.w, a.h, r).fill(self.canvas, &t, c);
        }
    }

    /// A border `width` wide inside `a`.
    pub fn border(&mut self, a: Area, r: f32, width: f32, c: Color) {
        let t = self.t();
        Path::rounded_ring(a.x, a.y, a.w, a.h, r, width).fill(self.canvas, &t, c);
    }

    /// `s` wrapped to `width` logical pixels at the given face and size.
    pub fn wrap_lines(&self, face: &Face<'f>, size: f32, s: &str, width: f32) -> Vec<String> {
        let st = self.style(face, size, self.theme.ink);
        text::wrap(&st, s, width * self.scale)
    }

    /// A style for the face at a logical size.
    fn style<'s>(&self, face: &'s Face<'f>, size: f32, c: Color) -> Style<'s, 'f> {
        Style::new(face, size * self.scale, c)
    }

    /// Draw text with its baseline at logical `baseline`; returns the
    /// logical advance.
    pub fn text(&mut self, style: &Style<'_, 'f>, x: f32, baseline: f32, s: &str) -> f32 {
        let (dx, dy) = (self.origin.0 + x * self.scale, self.origin.1 + baseline * self.scale);
        text::draw(self.canvas, self.cache, style, dx, dy, s) / self.scale
    }

    /// The logical width of text.
    pub fn measure(&self, style: &Style<'_, 'f>, s: &str) -> f32 {
        text::width(style, s) / self.scale
    }

    /// `s`, cut at the end with an ellipsis if need be to fit `max`.
    pub fn fit_end(&self, style: &Style<'_, 'f>, s: &str, max: f32) -> String {
        if self.measure(style, s) <= max {
            return String::from(s);
        }
        let mut t = String::from(s);
        while t.pop().is_some() {
            let c = alloc::format!("{}\u{2026}", t.trim_end());
            if self.measure(style, &c) <= max {
                return c;
            }
        }
        String::new()
    }

    /// Text in a line box of `line_height` whose top is `top`.
    fn line(&mut self, style: &Style<'_, 'f>, x: f32, top: f32, line_height: f32, s: &str) -> f32 {
        let base = top + style.face.baseline(style.size / self.scale, line_height);
        self.text(style, x, base, s)
    }

    pub fn icon(&mut self, i: Icon, x: f32, y: f32, size: f32, c: Color) {
        icon::draw(
            self.canvas,
            i,
            self.origin.0 + x * self.scale,
            self.origin.1 + y * self.scale,
            size * self.scale,
            c,
        );
    }

    /// The keyboard focus outline: 2 px ink, 2 px away (§4, "Focus").
    fn focus_ring(&mut self, a: Area, r: f32) {
        let ink = self.theme.ink;
        self.border(a.grow(4.0), r + 4.0, 2.0, ink);
    }

    fn hit(&mut self, id: Id, a: Area) {
        self.frame.hits.push((id, a));
    }

    /// Make `id` a tab stop (call in visual order).
    pub fn tab_stop(&mut self, id: Id) {
        self.frame.focus.push(id);
    }

    // --- window --------------------------------------------------------

    /// The backdrop, the window (shadow, surface, title bar with the mark,
    /// title and close button).
    pub fn window(&mut self, title: &str) {
        let desktop = self.theme.desktop;
        self.canvas.fill_rect(self.canvas.bounds(), desktop);
        let s = self.scale;
        let (x, y) = self.origin;
        let (w, h) = (WINDOW_W * s, WINDOW_H * s);
        for sh in [
            BoxShadow { dx: 0.0, dy: 40.0 * s, blur: 90.0 * s, spread: -30.0 * s, color: Color::rgb(0).faded(0.35) },
            BoxShadow { dx: 0.0, dy: 2.0 * s, blur: 6.0 * s, spread: 0.0, color: Color::rgb(0).faded(0.06) },
            BoxShadow { dx: 0.0, dy: 0.0, blur: 0.0, spread: 1.0 * s, color: Color::rgb(0).faded(0.08) },
        ] {
            shadow::draw(self.canvas, x, y, w, h, 12.0 * s, &sh);
        }
        let window = self.theme.window;
        self.fill(Area::new(0.0, 0.0, WINDOW_W, WINDOW_H), 12.0, window);
        let hairline = self.theme.hairline;
        self.fill(Area::new(0.0, TITLE_H - 1.0, WINDOW_W, 1.0), 0.0, hairline);
        let ink = self.theme.ink;
        logo::draw(self.canvas, x + 16.0 * s, y + 14.0 * s, 16.0 * s, ink);
        let st = self.style(&self.fonts.medium, 13.0, ink);
        self.line(&st, 44.0, 0.0, TITLE_H - 1.0, title);
        let close = Area::new(WINDOW_W - 52.0, 4.0, 44.0, 36.0);
        let (on, fill) = (self.hovered(&close), self.theme.hover_fill);
        self.hover_fill(CLOSE, close, 8.0, on, fill);
        let text2 = self.theme.text_2;
        self.icon(Icon::Close, close.x + 15.0, close.y + 11.0, 14.0, text2);
        if self.focused(CLOSE) {
            self.focus_ring(close, 8.0);
        }
        self.hit(CLOSE, close);
    }

    /// The step sidebar (§4): `current` is 0-based; earlier steps are done.
    pub fn sidebar(&mut self, steps: &[&str], current: usize) {
        let (sidebar, hairline) = (self.theme.sidebar, self.theme.hairline);
        // The sidebar's bottom-left corner follows the window's radius.
        let t = self.t();
        let mut p = Path::rounded_rect(0.0, TITLE_H, SIDEBAR_W + 12.0, WINDOW_H - TITLE_H, 12.0);
        p.extend(&Path::rect(0.0, TITLE_H, SIDEBAR_W, 12.0));
        let clip = self.device(&Area::new(0.0, TITLE_H, SIDEBAR_W, WINDOW_H - TITLE_H));
        let old = self.canvas.set_clip(clip);
        p.fill(self.canvas, &t, sidebar);
        self.canvas.set_clip(old);
        self.fill(Area::new(SIDEBAR_W, TITLE_H, 1.0, WINDOW_H - TITLE_H), 0.0, hairline);
        for (i, label) in steps.iter().enumerate() {
            let top = TITLE_H + 28.0 + 38.0 * i as f32;
            let (face, color) = match i.cmp(&current) {
                core::cmp::Ordering::Less => (&self.fonts.regular, self.theme.text_2),
                core::cmp::Ordering::Equal => (&self.fonts.semibold, self.theme.ink),
                core::cmp::Ordering::Greater => (&self.fonts.regular, self.theme.text_3),
            };
            if i == current {
                let ink = self.theme.ink;
                self.fill(Area::new(0.0, top, 2.0, 38.0), 0.0, ink);
            }
            let num = self.style(&self.fonts.mono, 11.5, color);
            self.line(&num, 26.0, top, 38.0, &alloc::format!("{:02}", i + 1));
            let st = self.style(face, 14.0, color);
            self.line(&st, 54.0, top, 38.0, label);
        }
    }

    /// The content column's left edge and width (beside the sidebar).
    pub fn content(&self, with_sidebar: bool) -> (f32, f32) {
        let left = if with_sidebar { SIDEBAR_W + 1.0 } else { 0.0 };
        (left + 44.0, WINDOW_W - left - 88.0)
    }

    /// A step heading (28/1.2, 500, −0.03em) at `top`; returns its bottom.
    pub fn heading(&mut self, x: f32, top: f32, s: &str) -> f32 {
        let st = self.style(&self.fonts.medium, 28.0, self.theme.ink).tracking(-0.03);
        self.line(&st, x, top, 33.6, s);
        top + 33.6
    }

    /// The Welcome heading with the wordmark: "Welcome to Slate" at 500
    /// and "OS" at 800 (36/1.15), centred on `cx`.
    pub fn welcome_heading(&mut self, cx: f32, top: f32, before: &str, os: &str) -> f32 {
        let a = self.style(&self.fonts.medium, 36.0, self.theme.ink).tracking(-0.035);
        let b = self.style(&self.fonts.extrabold, 36.0, self.theme.ink).tracking(-0.02);
        let w = self.measure(&a, before) + self.measure(&b, os);
        let x = cx - w / 2.0;
        let adv = self.line(&a, x, top, 41.4, before);
        self.line(&b, x + adv, top, 41.4, os);
        top + 41.4
    }

    /// A heading centred on `cx` (the Done screen).
    pub fn heading_centred(&mut self, cx: f32, top: f32, s: &str) -> f32 {
        let st = self.style(&self.fonts.medium, 28.0, self.theme.ink).tracking(-0.03);
        let w = self.measure(&st, s);
        self.line(&st, cx - w / 2.0, top, 33.6, s);
        top + 33.6
    }

    /// The supporting line (15/1.5, text-3), wrapped to `width`, left
    /// aligned or centred; returns its bottom.
    pub fn supporting(&mut self, x: f32, top: f32, width: f32, s: &str, centred: bool) -> f32 {
        let st = self.style(&self.fonts.regular, 15.0, self.theme.text_3);
        let lines = text::wrap(&st, s, width * self.scale);
        let mut y = top;
        for l in lines {
            let lx = if centred { x + (width - self.measure(&st, &l)) / 2.0 } else { x };
            self.line(&st, lx, y, 22.5, &l);
            y += 22.5;
        }
        y
    }

    /// A title (15, 500, ink) with an optional line of metadata under it
    /// in DM Mono (12.5, text-3), as choice rows show them; returns the
    /// bottom.
    pub fn detail(&mut self, x: f32, top: f32, title: &str, meta: Option<&str>) -> f32 {
        let st = self.style(&self.fonts.medium, 15.0, self.theme.ink);
        self.line(&st, x, top, 19.5, title);
        let Some(m) = meta else { return top + 19.5 };
        let st = self.style(&self.fonts.mono, 12.5, self.theme.text_3);
        self.line(&st, x, top + 19.5, 16.0, m);
        top + 19.5 + 16.0
    }

    /// One line of note text (13.5, text-3).
    pub fn note(&mut self, x: f32, top: f32, s: &str) -> f32 {
        let st = self.style(&self.fonts.regular, 13.5, self.theme.text_3);
        self.line(&st, x, top, 20.0, s);
        top + 20.0
    }

    // --- controls --------------------------------------------------------

    /// A button (§4): primary, secondary, ghost or disabled.
    pub fn button(&mut self, id: Id, a: Area, label: &str, v: Variant) {
        let hover = self.hovered(&a) && v != Variant::Disabled;
        let th = self.theme;
        let text_color = match v {
            Variant::Primary => {
                let c = self.animated(id, 0, if hover { th.ink_hover } else { th.ink });
                self.fill(a, 8.0, c);
                th.on_ink
            }
            Variant::Secondary => {
                self.hover_fill(id, a, 8.0, hover, th.hover_fill);
                self.border(a, 8.0, 1.0, th.border);
                th.ink
            }
            Variant::Ghost => {
                self.hover_fill(id, a, 8.0, hover, th.hover_fill);
                th.text_2
            }
            Variant::Disabled => {
                self.border(a, 8.0, 1.0, th.border);
                th.text_3.faded(0.5)
            }
        };
        let st = self.style(&self.fonts.medium, 14.0, text_color);
        let w = self.measure(&st, label);
        self.line(&st, a.x + (a.w - w) / 2.0, a.y, a.h, label);
        if v != Variant::Disabled {
            if self.focused(id) {
                self.focus_ring(a, 8.0);
            }
            self.hit(id, a);
            self.tab_stop(id);
        }
    }

    /// The width a button needs for `label` (primary pads 22, secondary 18).
    pub fn button_width(&self, label: &str, v: Variant) -> f32 {
        let st = self.style(&self.fonts.medium, 14.0, self.theme.ink);
        let pad = if v == Variant::Primary { 22.0 } else { 18.0 };
        crate::math::ceil(self.measure(&st, label)) + 2.0 * pad
    }

    /// An icon button (44 wide target, 18 px icon).
    pub fn icon_button(&mut self, id: Id, a: Area, i: Icon) {
        let (on, fill) = (self.hovered(&a), self.theme.hover_fill);
        self.hover_fill(id, a, 8.0, on, fill);
        let c = self.theme.text_2;
        self.icon(i, a.x + (a.w - 18.0) / 2.0, a.y + (a.h - 18.0) / 2.0, 18.0, c);
        if self.focused(id) {
            self.focus_ring(a, 8.0);
        }
        self.hit(id, a);
        self.tab_stop(id);
    }

    /// The height a choice row needs: 64, or more for description lines.
    pub fn choice_height(c: &Choice<'_>) -> f32 {
        if c.description.is_empty() { 64.0 } else { 40.0 + 19.5 + 19.0 * c.description.len() as f32 }
    }

    /// A choice row (§4). `focus_id` is the radio group's tab stop: the
    /// focus outline goes on the selected row.
    pub fn choice_row(&mut self, id: Id, focus_id: Id, a: Area, c: &Choice<'_>, selected: bool) {
        let th = self.theme;
        let hover = self.hovered(&a) && !selected;
        let border = self.animated(id, 1, if hover { th.ink } else { th.border_row });
        if selected {
            self.fill(a, 8.0, th.ink);
        } else {
            self.border(a, 8.0, 1.0, border);
        }
        let (title_c, meta_c) = if selected { (th.on_ink, th.on_ink_muted) } else { (th.ink, th.text_3) };
        // The radio: a 12 px ring, or a filled dot when selected.
        let (rx, ry) = (a.x + 18.0 + 6.0, a.y + a.h / 2.0);
        let t = self.t();
        if selected {
            Path::circle(rx, ry, 6.0).fill(self.canvas, &t, th.on_ink);
        } else {
            let mut ring = Path::circle(rx, ry, 6.0);
            let inner = Path::rounded_rect_reversed(rx - 4.5, ry - 4.5, 9.0, 9.0, 4.5);
            ring.extend(&inner);
            ring.fill(self.canvas, &t, th.ink);
        }
        let x = a.x + 18.0 + 12.0 + 16.0;
        let title = self.style(&self.fonts.medium, 15.0, title_c);
        if !c.description.is_empty() {
            let mut top = a.y + 20.0;
            self.line(&title, x, top, 19.5, c.title);
            top += 19.5;
            let d = self.style(&self.fonts.regular, 13.5, meta_c);
            for l in c.description {
                self.line(&d, x, top, 19.0, l);
                top += 19.0;
            }
        } else if let Some(meta) = c.meta {
            let block = 19.5 + 16.0;
            let top = a.y + (a.h - block) / 2.0;
            self.line(&title, x, top, 19.5, c.title);
            let m = self.style(&self.fonts.mono, 12.5, meta_c);
            self.line(&m, x, top + 19.5, 16.0, meta);
        } else {
            // A value at the right end keeps its room: a long title ends
            // in an ellipsis before it.
            let room = match c.value {
                Some(v) => {
                    let st = self.style(&self.fonts.mono, 13.0, meta_c);
                    a.right() - 18.0 - self.measure(&st, v) - 12.0 - x
                }
                None => a.right() - 18.0 - x,
            };
            let t = self.fit_end(&title, c.title, room);
            self.line(&title, x, a.y, a.h, &t);
        }
        if let Some(v) = c.value {
            let st = self.style(&self.fonts.mono, 13.0, meta_c);
            let w = self.measure(&st, v);
            let top = if c.description.is_empty() { a.y } else { a.y + 20.0 - (a.h - 19.5) / 2.0 + 0.0 };
            let lh = if c.description.is_empty() { a.h } else { a.h - 2.0 * (top - a.y) };
            self.line(&st, a.right() - 18.0 - w, top, lh.max(19.5), v);
        }
        if selected && self.focused(focus_id) {
            self.focus_ring(a, 8.0);
        }
        self.hit(id, a);
    }

    /// A checkbox with its label (§4); the whole line is the target.
    pub fn checkbox(&mut self, id: Id, x: f32, top: f32, label: &str, checked: bool) -> Area {
        let th = self.theme;
        let line = Area::new(x, top, 0.0, 44.0);
        let box_ = Area::new(x, top + 14.0, 16.0, 16.0);
        if checked {
            self.fill(box_, 4.0, th.ink);
            self.icon(Icon::Check, box_.x + 3.0, box_.y + 3.0, 10.0, th.on_ink);
        } else {
            self.border(box_, 4.0, 1.5, th.ink);
        }
        let st = self.style(&self.fonts.regular, 14.5, th.ink);
        let w = self.line(&st, x + 16.0 + 12.0, top, 44.0, label);
        let target = Area { w: 28.0 + w, ..line };
        if self.focused(id) {
            self.focus_ring(box_, 4.0);
        }
        self.hit(id, target);
        self.tab_stop(id);
        target
    }

    /// A dropdown (§4): leading icon, value, chevron.
    pub fn dropdown(&mut self, id: Id, a: Area, i: Icon, value: &str) {
        let th = self.theme;
        let hover = self.hovered(&a);
        let border = self.animated(id, 1, if hover { th.ink } else { th.border });
        self.border(a, 8.0, 1.0, border);
        self.icon(i, a.x + 14.0, a.y + (a.h - 16.0) / 2.0, 16.0, th.text_3);
        let st = self.style(&self.fonts.regular, 14.5, th.ink);
        self.line(&st, a.x + 14.0 + 16.0 + 12.0, a.y, a.h, value);
        self.icon(Icon::ChevronDown, a.right() - 15.0 - 14.0, a.y + (a.h - 14.0) / 2.0, 14.0, th.ink);
        if self.focused(id) {
            self.focus_ring(a, 8.0);
        }
        self.hit(id, a);
        self.tab_stop(id);
    }

    /// An open dropdown's list under `anchor`: one row per option, the
    /// selected one in ink (selection by inversion). Option `i` gets id
    /// `first + i`.
    pub fn dropdown_list(&mut self, first: Id, anchor: Area, options: &[&str], selected: usize) {
        let th = self.theme;
        let a = Area::new(anchor.x, anchor.bottom() + 6.0, anchor.w, 8.0 + 40.0 * options.len() as f32);
        self.fill(a, 8.0, th.window);
        self.border(a, 8.0, 1.0, th.border);
        for (i, o) in options.iter().enumerate() {
            let row = Area::new(a.x + 4.0, a.y + 4.0 + 40.0 * i as f32, a.w - 8.0, 40.0);
            let c = if i == selected {
                self.fill(row, 6.0, th.ink);
                th.on_ink
            } else {
                if self.hovered(&row) {
                    self.fill(row, 6.0, th.hover_fill);
                }
                th.ink
            };
            let st = self.style(&self.fonts.regular, 14.5, c);
            self.line(&st, row.x + 12.0, row.y, row.h, o);
            self.hit(first + i as Id, row);
        }
    }

    /// A text field (§4) with its label above and note below; `a` is the
    /// 44 px box. Returns the bottom of the note line.
    pub fn text_field(&mut self, id: Id, a: Area, f: &Field<'_>) -> f32 {
        let th = self.theme;
        let label = self.style(&self.fonts.medium, 13.0, th.text_2);
        self.line(&label, a.x, a.y - 6.0 - 17.0, 17.0, f.label);
        let focus = self.focus == Some(id);
        if focus {
            // A 3 px ring of ink at 12%, then the 1 px ink border.
            self.border(a.grow(3.0), 11.0, 3.0, th.ink.faded(0.12));
        }
        let border = if f.error || focus {
            th.ink
        } else if self.hovered(&a) {
            th.field_hover
        } else {
            th.border
        };
        let border = self.animated(id, 1, border);
        self.border(a, 8.0, if f.error { 1.5 } else { 1.0 }, border);
        let shown: String = if f.password { f.value.chars().map(|_| '•').collect() } else { String::from(f.value) };
        // Each character its own glyph, so the caret can stand between
        // any two.
        let st = if f.mono {
            self.style(&self.fonts.mono, 14.0, th.ink)
        } else {
            self.style(&self.fonts.regular, 15.0, th.ink)
        }
        .ligatures(false);
        let carets: Vec<f32> = text::caret_positions(&st, &shown).iter().map(|x| x / self.scale).collect();
        let n = carets.len() - 1;
        let (caret, anchor) = f.cursor.map_or((n, None), |(c, a)| (c.min(n), a.map(|a| a.min(n))));
        // Scrolled so the caret stays inside the field.
        let inner = a.w - 28.0;
        let scroll = if focus { (carets[caret] - inner + 2.0).max(0.0) } else { 0.0 };
        let tx = a.x + 14.0 - scroll;
        let clip = self.device(&Area::new(a.x + 2.0, a.y + 2.0, a.w - 4.0, a.h - 4.0));
        let old = self.canvas.set_clip(clip);
        self.line(&st, tx, a.y, a.h, &shown);
        if focus && let Some(anchor) = anchor.filter(|&x| x != caret) {
            // The selection by inversion (§1): an ink block, the text on it
            // in on-ink.
            let (s, e) = (anchor.min(caret), anchor.max(caret));
            let sel = Area::new(tx + carets[s], a.y + 11.0, carets[e] - carets[s], 22.0);
            self.fill(sel, 3.0, th.ink);
            let inner_clip = self.device(&sel);
            let r = clip.intersect(&inner_clip);
            self.canvas.set_clip(r);
            let on = if f.mono {
                self.style(&self.fonts.mono, 14.0, th.on_ink)
            } else {
                self.style(&self.fonts.regular, 15.0, th.on_ink)
            }
            .ligatures(false);
            self.line(&on, tx, a.y, a.h, &shown);
            self.canvas.set_clip(clip);
        }
        if focus {
            self.fill(Area::new(tx + carets[caret], a.y + 12.0, 1.0, 20.0), 0.0, th.ink);
        }
        self.canvas.set_clip(old);
        self.frame.fields.push(FieldText { id, x: tx, carets });
        let mut bottom = a.bottom();
        if let Some(n) = f.note {
            let (c, x) = if f.error { (th.ink, a.x + 18.0) } else { (th.text_3, a.x) };
            if f.error {
                self.icon(Icon::Warning, a.x, a.bottom() + 8.0, 13.0, th.ink);
            }
            let st = self.style(&self.fonts.regular, 12.5, c);
            self.line(&st, x, a.bottom() + 6.0, 18.0, n);
            bottom += 24.0;
        }
        self.hit(id, a);
        self.tab_stop(id);
        bottom
    }

    /// The progress bar (§4): percentage above in DM Mono, a 4 px bar.
    pub fn progress(&mut self, x: f32, top: f32, w: f32, fraction: f32) {
        let th = self.theme;
        let f = crate::math::clamp(fraction, 0.0, 1.0);
        let st = self.style(&self.fonts.mono, 13.0, th.text_3);
        self.line(&st, x, top, 18.0, &alloc::format!("{}%", (f * 100.0) as u32));
        let bar = Area::new(x, top + 26.0, w, 4.0);
        self.fill(bar, 2.0, th.border_row);
        if f > 0.0 {
            self.fill(Area { w: w * f, ..bar }, 2.0, th.ink);
        }
    }

    /// The logo mark, `size` logical pixels, at (x, y).
    pub fn logo(&mut self, x: f32, y: f32, size: f32) {
        let ink = self.theme.ink;
        logo::draw(self.canvas, self.origin.0 + x * self.scale, self.origin.1 + y * self.scale, size * self.scale, ink);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tab_order_wraps() {
        let f = Frame { focus: alloc::vec![1, 2, 3], ..Frame::default() };
        assert_eq!(f.next_focus(None, false), Some(1));
        assert_eq!(f.next_focus(Some(3), false), Some(1));
        assert_eq!(f.next_focus(Some(1), true), Some(3));
        assert_eq!(f.next_focus(Some(9), true), Some(3));
    }

    #[test]
    fn hits_prefer_the_topmost() {
        let f = Frame {
            hits: alloc::vec![(1, Area::new(0.0, 0.0, 10.0, 10.0)), (2, Area::new(5.0, 5.0, 10.0, 10.0))],
            ..Frame::default()
        };
        assert_eq!(f.hit(7.0, 7.0), Some(2));
        assert_eq!(f.hit(2.0, 2.0), Some(1));
        assert_eq!(f.hit(50.0, 50.0), None);
    }
}
