// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strata's surfaces, drawn as docs/design/WM_STYLE.md describes them: the
//! wallpaper (§8), the top bar (§3), window frames (§4), the launcher (§5)
//! and the system approval dialog (§6); the Applications menu and the
//! power dialog (ADR 0110). Everything is in logical pixels;
//! the [`Painter`] scales.

use alloc::string::String;
use alloc::vec::Vec;

use slate_ui::Color;
use slate_ui::edit::LineEdit;
use slate_ui::graphite::{Palette, Workspaces};
use slate_ui::icon::{self, Icon};
use slate_ui::math::round;
use slate_ui::paint::Painter;
use slate_ui::shadow::BoxShadow;
use slate_ui::text::{self, Face, Style};
use slate_ui::themes::{Stratum, app_accent};
use slate_ui::ui::Area;

use crate::fonts::Fonts;
use crate::layout::BAR_H;

/// Graphite's title bar height, its groove included (§4; Atelier, ADR
/// 0124); each theme has its own (`Palette::shape`, ADR 0167).
pub const TITLE_H: f32 = slate_ui::graphite::Shape::GRAPHITE.title_h;

pub use slate_ui::graphite::mix;

/// The floating shadow of the launcher and dialogs (§2).
pub const FLOATING: BoxShadow =
    BoxShadow { dx: 0.0, dy: 40.0, blur: 100.0, spread: -30.0, color: Color::rgb(0).with_alpha(217) };
/// The launcher's contact shadow (ADR 0124), over [`FLOATING`]: it
/// grounds the surface's edge.
pub const CONTACT: BoxShadow =
    BoxShadow { dx: 0.0, dy: 2.0, blur: 8.0, spread: 0.0, color: Color::rgb(0).with_alpha(102) };
/// The Applications menu's shadow (§2): it hangs from the top bar, lower
/// than the launcher and dialogs.
pub const MENU: BoxShadow =
    BoxShadow { dx: 0.0, dy: 12.0, blur: 32.0, spread: -8.0, color: Color::rgb(0).with_alpha(153) };

/// `s` cut in the middle with an ellipsis to fit `max` (§3).
pub fn truncate_middle(p: &Painter<'_>, st: &Style<'_, '_>, s: &str, max: f32) -> String {
    if p.measure(st, s) <= max {
        return String::from(s);
    }
    let chars: Vec<char> = s.chars().collect();
    let mut keep = chars.len();
    while keep > 1 {
        keep -= 1;
        let head: String = chars[..keep.div_ceil(2)].iter().collect();
        let tail: String = chars[chars.len() - keep / 2..].iter().collect();
        let t = alloc::format!("{head}…{tail}");
        if p.measure(st, &t) <= max {
            return t;
        }
    }
    String::from("…")
}

/// The default wallpaper (Dunes, the owner's choice of 2026-10-26), for screens without the
/// person's choice: the login, lock and unlock screens' fallback.
pub fn wallpaper(p: &mut Painter<'_>, pal: &Palette, a: Area) {
    slate_ui::wallpaper::draw(p, pal, a, slate_ui::wallpaper::Design::default());
}

/// A workspace's state in the top bar (§3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Workspace {
    Active,
    Used,
    Empty,
}

/// A window in the panel's window list.
#[derive(Clone, Debug)]
pub struct PanelWindow<'a> {
    pub name: &'a str,
    pub focused: bool,
    pub minimized: bool,
}

/// What the panel shows (ADR 0038: the top bar of §3 with an
/// Applications button and a window list).
#[derive(Clone, Debug)]
pub struct Bar<'a> {
    pub workspaces: [Workspace; 4],
    /// The active workspace's windows, in the order they opened.
    pub windows: &'a [PanelWindow<'a>],
    /// The Applications menu is open.
    pub menu: bool,
    /// The power dialog is open (ADR 0110).
    pub power: bool,
    /// The focused window's program runs in the Linux domain.
    pub linux: bool,
    /// ... in a Linux runtime's sandbox (ADR 0038).
    pub sandboxed: bool,
    /// Whether the network has a link; None hides the icon.
    pub network: Option<bool>,
    /// The battery's charge; None (no battery) hides it.
    pub battery: Option<u8>,
    /// Updates waiting (the Software Updater's last check); 0 hides it.
    pub updates: usize,
    /// A restart or shut down set for later ("Shutting down at 21:45").
    pub pending: Option<&'a str>,
    pub clock: &'a str,
    /// The date, for themes that show it apart (the clock is then the
    /// time alone).
    pub date: Option<&'a str>,
    /// The first window shown when the list scrolls.
    pub first: usize,
    /// The live system (M27): an "Install SlateOS" button.
    pub live: bool,
}

/// Where the panel's controls are.
#[derive(Clone, Debug, Default)]
pub struct PanelHits {
    pub applications: Area,
    /// The power button, at the far right (ADR 0110).
    pub power: Area,
    pub workspaces: [Area; 4],
    /// Each window button, by index into [`Bar::windows`].
    pub windows: Vec<(usize, Area)>,
    /// The list's scroll buttons, when it has more windows than fit.
    pub earlier: Option<Area>,
    pub later: Option<Area>,
    /// The first window shown, and how many are.
    pub first: usize,
    pub shown: usize,
    /// "Install SlateOS", on the live system.
    pub install: Option<Area>,
    /// The updates waiting, when there are some.
    pub updates: Option<Area>,
    /// What is set for later, when something is.
    pub pending: Option<Area>,
}

/// The narrowest a window button gets before the list scrolls.
pub const LIST_MIN: f32 = 110.0;
/// The scroll buttons' width.
const LIST_ARROW: f32 = 22.0;

/// `s` cut at the end with an ellipsis to fit `max`.
fn truncate_end(p: &Painter<'_>, st: &Style<'_, '_>, s: &str, max: f32) -> String {
    if p.measure(st, s) <= max {
        return String::from(s);
    }
    let mut t: String = s.chars().collect();
    while !t.is_empty() {
        t.pop();
        let c = alloc::format!("{}…", t.trim_end());
        if p.measure(st, &c) <= max {
            return c;
        }
    }
    String::new()
}

/// A ruled label (ADR 0124, Atelier's signature motif): a lowercase DM
/// Mono 11 label tracked +0.04 em, a 1 px `active_ws` rule `gap` after it
/// to `right`, and an optional count at the rule's end, centred in a line
/// box `h` tall at `top`.
#[allow(clippy::too_many_arguments)]
pub fn ruled_label(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    x: f32,
    top: f32,
    h: f32,
    right: f32,
    label: &str,
    count: Option<&str>,
) {
    let gap = 10.0;
    let st = p.style(&f.mono, 11.0, pal.muted).tracking(0.04);
    let end = x + p.line(&st, x, top, h, label) + gap;
    let mut rule_end = right;
    if let Some(n) = count {
        let nw = p.measure(&st, n);
        p.line(&st, right - nw, top, h, n);
        rule_end = right - nw - gap;
    }
    if rule_end > end {
        p.fill(Area::new(end, round(top + h / 2.0), rule_end - end, 1.0), 0.0, pal.active_ws);
    }
}

/// The panel: the theme's height (graphite's 32 px; ADR 0167) of its fill
/// (graphite's `desktop`; none, the wallpaper showing, in Copper Noir),
/// 16 px side padding; its controls centred in it.
pub fn bar(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, b: &Bar<'_>) -> PanelHits {
    let (w, _) = p.size();
    let mut hits = PanelHits::default();
    let bar_h = pal.shape.bar_h;
    // How far the controls, laid out for 32 px, move down.
    let t = (bar_h - BAR_H) / 2.0;
    if pal.topbar_fill.alpha() > 0 {
        p.fill(Area::new(0.0, 0.0, w, bar_h), 0.0, pal.topbar_fill);
    }
    // The logo and "Applications".
    let apps_label = p.style(&f.regular, 12.5, if b.menu { pal.topbar_strong } else { pal.topbar_text });
    let aw = p.measure(&apps_label, "Applications");
    let apps = Area::new(8.0, t + 4.0, 8.0 + 14.0 + 8.0 + aw + 10.0, 24.0);
    if b.menu {
        p.fill(apps, 6.0, pal.topbar_raised);
    }
    p.logo(16.0, t + 9.0, 14.0, pal.topbar_logo);
    p.line(&apps_label, 38.0, 0.0, bar_h, "Applications");
    hits.applications = apps;
    // Workspaces: 26 × 22 cells, 2 px apart, the number in a 14 px box
    // with a mark 2 px under it (ADR 0124): a long chalk one for the
    // active workspace, a short one for a used one, none for an empty one.
    // Copper Noir fills the active cell with its accent instead of the
    // long mark, and numbers the others alike (ADR 0167).
    let filled = pal.workspaces == Workspaces::Filled;
    let mut x = apps.right() + 12.0;
    // Sediment's strata pills (ADR 0167): one per workspace in its colour,
    // the active one wider at full strength, the others at 55%; each in a
    // cell 22 px tall to click.
    if let Workspaces::Pills(colours) = pal.workspaces {
        for (i, ws) in b.workspaces.iter().enumerate() {
            let active = *ws == Workspace::Active;
            let pw = if active { 28.0 } else { 16.0 };
            let cell = Area::new(x, t + 5.0, pw + 6.0, 22.0);
            let c = if active { colours[i] } else { mix(pal.topbar_fill, colours[i], 0.55) };
            p.fill(Area::new(cell.x + 3.0, cell.y + 7.0, pw, 8.0), 4.0, c);
            hits.workspaces[i] = cell;
            x += cell.w;
        }
        x += 2.0;
    }
    for (i, ws) in b.workspaces.iter().enumerate().filter(|_| !matches!(pal.workspaces, Workspaces::Pills(_))) {
        let cell = Area::new(x, t + 5.0, 26.0, 22.0);
        let (colour, mark) = match ws {
            Workspace::Active if filled => {
                p.fill(cell, 6.0, pal.accent);
                (pal.accent_on, None)
            }
            Workspace::Active => {
                p.fill(cell, 6.0, pal.topbar_raised);
                (pal.topbar_strong, Some((10.0, pal.topbar_strong)))
            }
            Workspace::Used => (pal.topbar_muted, Some((4.0, pal.topbar_dim))),
            Workspace::Empty if filled => (pal.topbar_muted, None),
            Workspace::Empty => (pal.topbar_dim, None),
        };
        let st = if filled && *ws == Workspace::Active {
            p.style(&f.mono_medium, 12.0, colour)
        } else {
            p.style(&f.mono, 12.0, colour)
        };
        let label = alloc::format!("{}", i + 1);
        let lw = p.measure(&st, &label);
        p.line(&st, cell.x + (cell.w - lw) / 2.0, cell.y + 2.0, 14.0, &label);
        if let Some((mw, c)) = mark {
            p.fill(Area::new(cell.x + (cell.w - mw) / 2.0, cell.y + 18.0, mw, 1.0), 0.0, c);
        }
        hits.workspaces[i] = cell;
        x += 28.0;
    }
    // A separator between the workspaces and the window list.
    let sep = x - 2.0 + 12.0;
    p.fill(Area::new(sep, t + 9.0, 1.0, 14.0), 0.0, pal.topbar_raised);
    let list_x = sep + 1.0 + 12.0;

    // The right side, laid out from the right edge: the power button,
    // clock, battery, network, domain, 16 px apart.
    let power = Area::new(w - 8.0 - 28.0, t + 4.0, 28.0, 24.0);
    if b.power {
        p.fill(power, 6.0, pal.topbar_raised);
    }
    p.icon(Icon::Power, power.x + 7.0, power.y + 5.0, 14.0, if b.power { pal.topbar_strong } else { pal.topbar_text });
    hits.power = power;
    let mut right = power.x - 12.0;
    let clock = p.style(&f.mono, 12.0, pal.topbar_clock);
    right -= p.measure(&clock, b.clock);
    p.line(&clock, right, 0.0, bar_h, b.clock);
    // The themes in colour put the date before the clock (ADR 0167), in
    // their serif (ADR 0175), else Host Grotesk (13 px in Copper Noir,
    // 12.5 in Sediment). Sediment, the light one, writes "Wednesday,
    // 28 October".
    if let Some(date) = b.date.filter(|_| pal.topbar_date.alpha() > 0) {
        let date = match date.split_once(' ') {
            Some((day, rest)) if pal.light() => alloc::format!("{day}, {rest}"),
            _ => String::from(date),
        };
        let st = match pal.shape.date_serif.and_then(|(s, size)| Some((f.serif(s)?, size))) {
            Some((face, size)) => p.style(face, size, pal.topbar_date),
            None => p.style(&f.regular, if pal.light() { 12.5 } else { 13.0 }, pal.topbar_date),
        };
        right -= 12.0 + p.measure(&st, &date);
        p.line(&st, right, 0.0, bar_h, &date);
    }
    let label = p.style(&f.regular, 12.5, pal.topbar_text);
    if let Some(level) = b.battery {
        let pct = alloc::format!("{level}%");
        right -= 16.0 + p.measure(&label, &pct);
        p.line(&label, right, 0.0, bar_h, &pct);
        right -= 5.0 + 16.0;
        let (x, y) = p.to_device(right, t + 8.0);
        icon::battery(p.canvas, x, y, 16.0 * p.scale, level, pal.topbar_text);
    }
    if let Some(link) = b.network {
        right -= 16.0 + 14.0;
        p.icon(Icon::Wifi, right, t + 9.0, 14.0, if link { pal.topbar_text } else { pal.topbar_dim });
    }
    // Updates waiting (ADR 0112): information, so steel (STRATA_COLORS),
    // with the count in words; it opens the Software Updater.
    if b.updates > 0 {
        let steel = pal.accents.steel;
        let st = p.style(&f.regular, 12.5, steel.text);
        let text = if b.updates == 1 { String::from("1 update") } else { alloc::format!("{} updates", b.updates) };
        let w = p.measure(&st, &text) + 8.0 + 13.0 + 18.0;
        right -= 16.0 + w;
        let a = Area::new(right, t + 5.0, w, 22.0);
        p.fill(a, 6.0, steel.tint);
        p.border(a, 6.0, 1.0, steel.border);
        p.icon(Icon::Download, a.x + 9.0, t + 9.5, 13.0, steel.text);
        p.line(&st, a.x + 9.0 + 13.0 + 8.0, 0.0, bar_h, &text);
        hits.updates = Some(a);
    }
    // A restart or shut down set for later (ADR 0110's addendum): a
    // pending state, so ochre, with a clock; it opens the power dialog.
    if let Some(text) = b.pending {
        let ochre = pal.accents.ochre;
        let st = p.style(&f.regular, 12.5, ochre.text);
        let w = p.measure(&st, text) + 8.0 + 13.0 + 18.0;
        right -= 16.0 + w;
        let a = Area::new(right, t + 5.0, w, 22.0);
        p.fill(a, 6.0, ochre.tint);
        p.border(a, 6.0, 1.0, ochre.border);
        p.icon(Icon::Clock, a.x + 9.0, t + 9.5, 13.0, ochre.text);
        p.line(&st, a.x + 9.0 + 13.0 + 8.0, 0.0, bar_h, text);
        hits.pending = Some(a);
    }
    let (domain_icon, domain) = match (b.linux, b.sandboxed) {
        (true, true) => (Icon::SplitPane, "linux sandbox"),
        (true, false) => (Icon::SplitPane, "linux"),
        _ => (Icon::Shield, "slate mode"),
    };
    right -= 16.0 + p.measure(&label, domain);
    p.line(&label, right, 0.0, bar_h, domain);
    right -= 6.0 + 13.0;
    p.icon(domain_icon, right, t + 9.5, 13.0, pal.topbar_text);
    // The live system's way back to the installer (M27), in chalk on the
    // active cell's grey, where it is always in view.
    if b.live {
        let st = p.style(&f.medium, 12.5, pal.topbar_strong);
        let w = p.measure(&st, "Install SlateOS") + 8.0 + 14.0 + 20.0;
        right -= 16.0 + w;
        let a = Area::new(right, t + 4.0, w, 24.0);
        p.fill(a, 6.0, pal.topbar_raised);
        p.icon(Icon::Disk, a.x + 10.0, t + 9.0, 14.0, pal.topbar_strong);
        p.line(&st, a.x + 10.0 + 14.0 + 8.0, 0.0, bar_h, "Install SlateOS");
        hits.install = Some(a);
    }

    // The window list: up to 180 px per window, between the workspaces
    // and the right side; with more windows than fit at LIST_MIN each, it
    // scrolls, with a button at each end (ADR 0039).
    let room = (right - 24.0 - list_x).max(0.0);
    let n = b.windows.len();
    if n > 0 {
        let (mut x0, mut avail, mut first, mut count) = (list_x, room, 0, n);
        if n as f32 * LIST_MIN > room && room >= 2.0 * LIST_ARROW + LIST_MIN {
            avail = room - 2.0 * LIST_ARROW;
            count = ((avail / LIST_MIN) as usize).max(1);
            first = b.first.min(n - count);
            let arrow = |p: &mut Painter<'_>, x: f32, text: &str, on: bool| {
                let st = p.style(&f.regular, 15.0, if on { pal.topbar_text } else { pal.topbar_dim });
                p.line(&st, x + 6.0, t + 4.0, 24.0, text);
                Area::new(x, t + 4.0, LIST_ARROW, 24.0)
            };
            hits.earlier = Some(arrow(p, list_x, "‹", first > 0));
            hits.later = Some(arrow(p, list_x + room - LIST_ARROW, "›", first + count < n));
            x0 = list_x + LIST_ARROW;
        }
        hits.first = first;
        hits.shown = count;
        let each = (avail / count as f32).min(180.0);
        for (i, win) in b.windows.iter().enumerate().skip(first).take(count) {
            let a = Area::new(round(x0 + each * (i - first) as f32), t + 4.0, round(each - 4.0), 24.0);
            if a.w < 24.0 {
                break;
            }
            // A dot before the name (ADR 0124): the accent (chalk in
            // graphite) for the focused window, dim for open ones, none
            // for minimised ones.
            let (colour, dot) = if win.focused {
                p.fill(a, 6.0, pal.topbar_raised);
                (pal.topbar_focus_text, Some(pal.accent))
            } else if win.minimized {
                (pal.topbar_muted, None)
            } else {
                (pal.topbar_text, Some(pal.topbar_dim))
            };
            if let Some(c) = dot {
                p.path(&slate_ui::Path::circle(a.x + 12.0, a.y + a.h / 2.0, 2.0), c);
            }
            let st = p.style(&f.regular, 12.5, colour);
            let name = truncate_end(p, &st, win.name, a.w - 31.0);
            p.line(&st, a.x + 21.0, a.y, a.h, &name);
            hits.windows.push((i, a));
        }
    }
    hits
}

/// A window frame's title and state.
#[derive(Clone, Debug)]
pub struct Frame<'a> {
    pub app: &'a str,
    pub path: Option<&'a str>,
    pub linux: bool,
    /// The program runs in a Linux runtime's sandbox (ADR 0038).
    pub sandboxed: bool,
    /// The app's glyph (its entry's `icon`), before the name; the
    /// generic window when None.
    pub icon: Option<Icon>,
    /// Its app's accent, as its entry declares it (ADR 0167 and its
    /// addendum).
    pub accent: Option<Stratum>,
    /// From unfocused (0) to focused (1), for the cross-fade.
    pub focus: f32,
    /// Maximised or snapped: square corners, no shadow.
    pub flush: bool,
    pub maximized: bool,
    /// The title bar button under the pointer, and how far its fill has
    /// faded in (80 ms, ADR 0124).
    pub hover: Option<TitleButton>,
    pub hover_in: f32,
    /// The title bar button with the keyboard focus (alt + space): a
    /// 2 px chalk ring, 2 px outside.
    pub keyed: Option<TitleButton>,
}

/// The title bar's buttons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TitleButton {
    Minimize,
    Maximize,
    Close,
}

/// The tag a Linux-domain window or launcher row carries (§4): "linux" in
/// DM Mono 10.5, 18 px tall, 1 px border, radius 4. Returns its width.
fn domain_tag(p: &mut Painter<'_>, f: &Fonts<'_>, x: f32, mid: f32, border: Color, text: Color) -> f32 {
    let st = p.style(&f.mono, 10.5, text);
    let w = p.measure(&st, "linux") + 12.0;
    let a = Area::new(x, mid - 9.0, w, 18.0);
    p.border(a, 4.0, 1.0, border);
    p.line(&st, x + 6.0, a.y, a.h, "linux");
    w
}

/// The tag of a window whose program runs in a Linux runtime's sandbox
/// (ADR 0038): the domain tag's shape, with a 10 px shield and
/// "linux sandbox". Returns its width.
fn sandbox_tag(p: &mut Painter<'_>, f: &Fonts<'_>, x: f32, mid: f32, border: Color, text: Color) -> f32 {
    let st = p.style(&f.mono, 10.5, text);
    let w = 6.0 + 10.0 + 5.0 + p.measure(&st, "linux sandbox") + 6.0;
    let a = Area::new(x, mid - 9.0, w, 18.0);
    p.border(a, 4.0, 1.0, border);
    p.icon(Icon::Shield, x + 6.0, mid - 5.0, 10.0, text);
    p.line(&st, x + 21.0, a.y, a.h, "linux sandbox");
    w
}

/// Where a frame's minimise, maximise and close buttons are: 28 × 24
/// targets, 2 px apart, 6 px from the right (ADR 0124), centred in a
/// title bar `title_h` tall.
pub fn buttons(a: Area, title_h: f32) -> [Area; 3] {
    let y = a.y + slate_ui::math::floor((title_h - 24.0) / 2.0);
    let close = Area::new(a.right() - 1.0 - 6.0 - 28.0, y, 28.0, 24.0);
    let max = Area::new(close.x - 30.0, y, 28.0, 24.0);
    let min = Area::new(max.x - 30.0, y, 28.0, 24.0);
    [min, max, close]
}

/// A desktop icon's picture in its 56-unit square `pic`: folders and
/// files as slate-ui's file icons (a file's extension on a badge), apps
/// on a tile with their glyph (Files' a folder).
fn desk_picture(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, pic: Area, item: &crate::desk::Item, lit: bool) {
    use crate::desk::Kind;
    use slate_ui::fileicon;
    match &item.kind {
        Kind::Folder => fileicon::draw(p, pal, fileicon::Kind::Folder, pic.x, pic.y, pic.w, None),
        Kind::File(kind) => {
            let badge = fileicon::badge_of(&item.name);
            let b = badge.as_deref().map(|t| (&f.mono_medium, t));
            fileicon::draw(p, pal, *kind, pic.x, pic.y, pic.w, b);
        }
        Kind::App(_) => {
            let tile = pic.grow(-4.0);
            p.fill(tile, 12.0, pal.raised.with_alpha(235));
            p.border(tile, 12.0, 1.0, pal.border);
            if item.icon == Icon::Folder {
                fileicon::draw(p, pal, fileicon::Kind::Folder, tile.x + 6.0, tile.y + 5.0, 36.0, None);
            } else {
                let c = if lit { pal.chalk } else { pal.text_1 };
                p.icon(item.icon, tile.x + 12.0, tile.y + 12.0, 24.0, c);
            }
        }
    }
}

/// The picture's square in cell `a`.
fn desk_pic(a: Area) -> Area {
    Area::new(round(a.x + (a.w - 56.0) / 2.0), a.y + 2.0, 56.0, 56.0)
}

/// The desktop's icons (ADR 0102's third addendum, ADR 0156): each in
/// its cell, the name below in up to two lines; the chosen ones and a
/// folder a drag would drop into in chalk; with `keys` (no window
/// focused) the one the keys are on ringed; a rename's field under its
/// icon; "N more" in the last cell when some don't fit.
pub fn desk_icons(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, work: Area, desk: &crate::desk::Desk, keys: bool) {
    let st = p.style(&f.medium, 12.0, pal.text_1);
    let layout = desk.layout(work);
    for (i, (cell, item)) in layout.cells.iter().zip(desk.items.iter()).enumerate() {
        let Some(a) = *cell else { continue };
        let selected = desk.selected.binary_search(&i).is_ok();
        let target = desk.target == Some(i);
        let pic = desk_pic(a);
        if selected || target {
            p.fill(a.grow(-3.0), 10.0, pal.chalk.with_alpha(if target { 60 } else { 36 }));
            p.border(a.grow(-3.0), 10.0, if target { 1.5 } else { 1.0 }, pal.chalk.with_alpha(110));
        }
        if keys && desk.cursor == Some(i) {
            p.border(a.grow(1.0), 14.0, 2.0, pal.chalk);
        }
        desk_picture(p, pal, f, pic, item, selected);
        if desk.rename.as_ref().is_some_and(|r| r.0 == i) {
            continue;
        }
        let max = a.w - 10.0;
        let mut lines = text::wrap(&st, &item.name, max);
        if lines.len() > 2 {
            let rest: Vec<String> = lines.split_off(1);
            lines.push(truncate_end(p, &st, &rest.join(" "), max));
        }
        for (k, line) in lines.iter().enumerate() {
            let lw = p.measure(&st, line);
            let row =
                Area::new(round(a.x + (a.w - lw) / 2.0) - 4.0, pic.bottom() + 2.0 + k as f32 * 15.0, lw + 8.0, 15.0);
            p.fill(row, 4.0, pal.desktop.with_alpha(if selected { 235 } else { 190 }));
            p.line(&st, row.x + 4.0, row.y, row.h, line);
        }
    }
    if let Some((a, n)) = layout.more {
        let tile = desk_pic(a).grow(-4.0);
        p.fill(tile, 12.0, pal.raised.with_alpha(235));
        p.border(tile, 12.0, 1.0, pal.border);
        let big = p.style(&f.medium, 15.0, pal.text_1);
        let label = alloc::format!("+{n}");
        let w = p.measure(&big, &label);
        p.line(&big, round(tile.x + (tile.w - w) / 2.0), tile.y, tile.h, &label);
        let lw = p.measure(&st, "more");
        let row = Area::new(round(a.x + (a.w - lw) / 2.0) - 4.0, tile.bottom() + 6.0, lw + 8.0, 15.0);
        p.fill(row, 4.0, pal.desktop.with_alpha(190));
        p.line(&st, row.x + 4.0, row.y, row.h, "more");
    }
    // A rename's field last, over the icons below it.
    if let Some((i, e, why)) = &desk.rename
        && let Some(Some(a)) = layout.cells.get(*i)
    {
        desk_rename(p, pal, f, work, *a, desk_pic(*a).bottom() + 2.0, e, why.as_deref());
    }
}

/// A rename's field under an icon in cell `a`, from `top`: the text,
/// its selection and caret, scrolled to keep the caret in view; why the
/// last name was refused below it, in clay.
#[allow(clippy::too_many_arguments)]
fn desk_rename(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    work: Area,
    a: Area,
    top: f32,
    e: &LineEdit,
    why: Option<&str>,
) {
    let st = p.style(&f.medium, 12.0, pal.chalk);
    // Kept on the work area.
    let inside = |x: f32, w: f32| x.min(work.right() - w - 4.0).max(work.x + 4.0);
    let field = Area::new(inside(a.x - 12.0, a.w + 24.0), top, a.w + 24.0, 22.0);
    p.fill(field, 6.0, pal.well);
    p.border(field, 6.0, 1.0, if why.is_some() { pal.accents.clay.border } else { pal.field_focus });
    let text = e.text();
    let at = |p: &Painter<'_>, n: usize| p.measure(&st, &text.chars().take(n).collect::<String>());
    let caret = at(p, e.caret());
    let sel = e.selection().map(|(s, t)| (at(p, s), at(p, t)));
    let room = field.w - 12.0;
    let shift = (caret - room).max(0.0);
    let x0 = field.x + 6.0 - shift;
    let saved = p.clip(field.grow(-2.0));
    if let Some((sx, tx)) = sel {
        p.fill(Area::new(x0 + sx, field.y + 3.0, tx - sx, field.h - 6.0), 2.0, pal.chalk.with_alpha(70));
    }
    p.line(&st, x0, field.y, field.h, &text);
    p.fill(Area::new(x0 + caret, field.y + 4.0, 1.5, field.h - 8.0), 0.0, pal.chalk);
    p.unclip(saved);
    if let Some(why) = why {
        let clay = pal.accents.clay;
        let note = p.style(&f.regular, 11.0, clay.text);
        let lines = text::wrap(&note, why, 180.0);
        let h = 6.0 + 14.0 * lines.len() as f32;
        let w = lines.iter().map(|l| p.measure(&note, l)).fold(0.0, f32::max) + 12.0;
        let box_ = Area::new(round(inside(a.x + (a.w - w) / 2.0, w)), field.bottom() + 4.0, w, h);
        p.fill(box_, 6.0, clay.tint);
        p.border(box_, 6.0, 1.0, clay.border);
        for (k, l) in lines.iter().enumerate() {
            p.line(&note, box_.x + 6.0, box_.y + 3.0 + 14.0 * k as f32, 14.0, l);
        }
    }
}

/// What goes over the windows for the desktop (ADR 0156): where dragged
/// icons would land, and the icon under the pointer; the selection box;
/// the right button's menu.
pub fn desk_over(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, work: Area, desk: &crate::desk::Desk) {
    use crate::desk::Press;
    if let Some((cells, dx, dy)) = desk.dragged(work) {
        if desk.target.is_none() {
            for c in &cells {
                p.fill(c.grow(-3.0), 10.0, pal.chalk.with_alpha(18));
                p.border(c.grow(-3.0), 10.0, 1.5, pal.focus.with_alpha(150));
            }
        }
        if let Some(Press::Icon { i, .. }) = &desk.press
            && let (Some(Some(a)), Some(item)) = (desk.cells(work).get(*i), desk.items.get(*i))
        {
            let pic = desk_pic(*a);
            let pic = Area::new(pic.x + dx, pic.y + dy, pic.w, pic.h);
            desk_picture(p, pal, f, pic, item, true);
            if desk.selected.len() > 1 {
                count_chip(p, pal, f, pic.right() - 6.0, pic.y - 4.0, desk.selected.len());
            }
        }
    }
    if let Some(Press::Band { x0, y0, x, y, .. }) = &desk.press {
        let band = Area::new(x0.min(*x), y0.min(*y), (x - x0).abs(), (y - y0).abs());
        if band.w >= 2.0 || band.h >= 2.0 {
            p.fill(band, 2.0, pal.chalk.with_alpha(18));
            p.border(band, 2.0, 1.0, pal.chalk.with_alpha(110));
        }
    }
    if let Some(m) = &desk.menu {
        let (a, rows) = m.area(desk.screen);
        p.shadow_under(a, 12.0, &MENU);
        p.fill(a, 12.0, pal.overlay);
        rim(p, pal, a, 12.0);
        for (k, (row, (label, action))) in rows.iter().zip(m.items.iter()).enumerate() {
            let on = k == m.selected;
            if on {
                p.fill(*row, 7.0, pal.chalk);
            }
            let ink = match (on, action) {
                (true, _) => pal.window,
                // Destructive: clay, and the words say so too.
                (false, crate::desk::Action::Trash) => pal.accents.clay.text,
                _ => pal.text_1,
            };
            let st = p.style(&f.medium, 13.0, ink);
            p.line(&st, row.x + 12.0, row.y, row.h, label);
        }
        p.border(a, 12.0, 1.0, pal.border);
    }
}

/// A chip with a count in it, its right edge at `right`.
fn count_chip(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, right: f32, top: f32, n: usize) {
    let st = p.style(&f.mono_medium, 11.0, pal.window);
    let label = alloc::format!("{n}");
    let w = (p.measure(&st, &label) + 10.0).max(20.0);
    let a = Area::new(right - w, top, w, 20.0);
    p.fill(a, 10.0, pal.chalk);
    p.line(&st, round(a.x + (w - p.measure(&st, &label)) / 2.0), a.y, a.h, &label);
}

/// Files an app is dragging, beside the pointer at (x, y) once it has
/// left the app's window (ADR 0156): a page and how many, and "Copy"
/// while ctrl is held (also for the desktop's icons).
pub fn drag_badge(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, x: f32, y: f32, n: usize, copy: bool) {
    let st = p.style(&f.medium, 12.0, pal.text_1);
    let files = if n == 1 { String::from("1 file") } else { alloc::format!("{n} files") };
    let label = if copy { alloc::format!("Copy {files}") } else { files };
    let w = 10.0 + 14.0 + 6.0 + p.measure(&st, &label) + 10.0;
    let a = Area::new(x + 14.0, y + 16.0, w, 26.0);
    p.fill(a, 8.0, pal.raised);
    p.border(a, 8.0, 1.0, pal.border_strong);
    p.icon(Icon::Document, a.x + 10.0, a.y + 6.0, 14.0, pal.text_3);
    p.line(&st, a.x + 30.0, a.y, a.h, &label);
}

/// A window's size in its steps ("80 × 24") over the middle of its
/// content, while the person resizes it (ADR 0102's third addendum).
pub fn step_size(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, c: Area, (cols, rows): (u32, u32)) {
    let st = p.style(&f.mono_medium, 13.0, pal.text_1);
    let label = alloc::format!("{cols} × {rows}");
    let w = round(p.measure(&st, &label)) + 24.0;
    let a = Area::new(round(c.x + (c.w - w) / 2.0), round(c.y + (c.h - 30.0) / 2.0), w, 30.0);
    p.fill(a, 8.0, pal.raised);
    p.border(a, 8.0, 1.0, pal.border_strong);
    p.line(&st, a.x + 12.0, a.y, a.h, &label);
}

/// The area inside a frame where the app draws: under the groove (the
/// theme's title bar `title_h` tall), inset 1 px at the sides and bottom.
pub fn content(a: Area, title_h: f32) -> Area {
    Area::new(a.x + 1.0, a.y + title_h, a.w - 2.0, a.h - title_h - 1.0)
}

/// The frame's body and title bar (§4, ADR 0038; Atelier, ADR 0124; the
/// theme's geometry and shadows, ADR 0167): the bar a tone off the
/// content, a groove under it and, focused, a rim of light along its top;
/// the app's content goes inside [`content`], then [`frame_outline`] on
/// top.
pub fn frame(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area, fr: &Frame<'_>) {
    let shape = &pal.shape;
    let radius = if fr.flush { 0.0 } else { shape.frame_r };
    let focused = fr.focus > 0.5;
    if !fr.flush {
        if focused {
            for s in &shape.shadow_focused {
                p.shadow_under(a, radius, s);
            }
        } else {
            p.shadow_under(a, radius, &shape.shadow_unfocused);
        }
    }
    p.fill(a, radius, pal.window);
    // The bar: the frame's shape clipped to its top, so its corners
    // follow the frame's.
    let bar_h = shape.title_h - 1.0;
    let saved = p.clip(Area::new(a.x, a.y, a.w, bar_h));
    p.fill(a, radius, mix(pal.titlebar_unfocused, pal.titlebar, fr.focus));
    p.unclip(saved);
    // The rim, just inside the outline, fading in with the focus.
    if pal.titlebar_rim.alpha() > 0 && fr.focus > 0.0 {
        let saved = p.clip(Area::new(a.x, a.y + 1.0, a.w, 1.0));
        p.fill(a.grow(-1.0), (radius - 1.0).max(0.0), pal.titlebar_rim.faded(fr.focus));
        p.unclip(saved);
    }
    p.fill(Area::new(a.x + 1.0, a.y + bar_h, a.w - 2.0, 1.0), 0.0, pal.titlebar_groove);
    let [min, max, close] = buttons(a, shape.title_h);
    let saved = p.clip(Area::new(a.x, a.y, (min.x - a.x - 6.0).max(0.0), bar_h));
    let fade = |off: Color, on: Color| mix(off, on, fr.focus);
    let mid = a.y + bar_h / 2.0;
    let mut x = a.x + 14.0;
    // A window whose program is no app's (a Linux app's client is
    // slate-linux-app or Sway's bridge) gets the generic window. Its
    // colour is the app's own ink where the theme has them (Sediment).
    let glyph = if pal.app_accents { app_accent(pal, fr.accent).ink } else { pal.title_glyph };
    p.icon(fr.icon.unwrap_or(Icon::Window), x, mid - 7.0, 14.0, fade(pal.title_button_unfocused, glyph));
    x += 14.0 + 10.0;
    // The theme's serif when it is installed (ADR 0175), else Host
    // Grotesk as the handoff's fallback.
    let ink = fade(pal.title_text_unfocused, pal.title_text);
    let name = match shape.title_serif.and_then(|(s, size)| Some((f.serif(s)?, size))) {
        Some((face, size)) => p.style(face, size, ink),
        None => {
            let face = if shape.title_semibold { &f.semibold } else { &f.medium };
            p.style(face, shape.title_size, ink).tracking(shape.title_tracking)
        }
    };
    x += p.line(&name, x, a.y, bar_h, fr.app) + 10.0;
    // The path, cut to leave room for the domain tag after it.
    let tag = if fr.sandboxed {
        let st = p.style(&f.mono, 10.5, pal.text_4);
        6.0 + 10.0 + 5.0 + p.measure(&st, "linux sandbox") + 6.0 + 10.0
    } else if fr.linux {
        let st = p.style(&f.mono, 10.5, pal.text_4);
        p.measure(&st, "linux") + 12.0 + 10.0
    } else {
        0.0
    };
    if let Some(path) = fr.path {
        let st = p.style(&f.mono, 11.5, fade(pal.title_button_unfocused, pal.titlebar_path));
        let room = min.x - 6.0 - x - tag;
        let shown = truncate_middle(p, &st, path, room.max(0.0));
        if !shown.is_empty() && room > 0.0 {
            x += p.line(&st, x, a.y, bar_h, &shown) + 10.0;
        }
    }
    if fr.sandboxed {
        sandbox_tag(p, f, x, mid, pal.border_strong, pal.text_4);
    } else if fr.linux {
        domain_tag(p, f, x, mid, pal.border_strong, pal.text_4);
    }
    p.unclip(saved);
    let max_icon = if fr.maximized { Icon::Restore } else { Icon::Maximize };
    for (b, area, icon) in [
        (TitleButton::Minimize, min, Icon::Minimize),
        (TitleButton::Maximize, max, max_icon),
        (TitleButton::Close, close, Icon::Close),
    ] {
        let hover = if fr.hover == Some(b) { fr.hover_in.clamp(0.0, 1.0) } else { 0.0 };
        if hover > 0.0 {
            p.fill(area, 6.0, pal.title_hover.faded(hover));
        }
        let keyed = fr.keyed == Some(b);
        let lit = if keyed { 1.0 } else { hover };
        let ink = mix(fade(pal.title_button_unfocused, pal.titlebar_button), pal.title_text, lit);
        p.icon(icon, area.x + 8.5, area.y + 6.5, 11.0, ink);
        if keyed {
            p.border(area.grow(4.0), 6.0 + 4.0, 2.0, pal.title_text);
        }
    }
}

/// The frame's 1 px outline, drawn over the content (§4); `focus` mixes
/// it from the unfocused colour (0) to the focused (1), for the
/// cross-fade; the focused colour is the app's ink where the theme has
/// app accents. Focused and floating, the theme's halo rings it
/// (ADR 0167).
pub fn frame_outline(p: &mut Painter<'_>, pal: &Palette, a: Area, focus: f32, flush: bool, accent: Option<Stratum>) {
    let shape = &pal.shape;
    let radius = if flush { 0.0 } else { shape.frame_r };
    let (focused, halo) = if pal.app_accents {
        let ink = app_accent(pal, accent).ink;
        (ink, ink.with_alpha(pal.focus_halo.alpha()))
    } else {
        (pal.focus, pal.focus_halo)
    };
    p.border(a, radius, 1.0, mix(pal.unfocused, focused, focus));
    if shape.halo > 0.0 && !flush && focus > 0.0 && halo.alpha() > 0 {
        p.border(a.grow(shape.halo), radius + shape.halo, shape.halo, halo.faded(focus));
    }
}

/// The dim layer behind a centred launcher or a dialog (§2), at
/// `opacity` (for fading).
pub fn dim(p: &mut Painter<'_>, colour: Color, opacity: f32) {
    let (w, h) = p.size();
    p.fill(Area::new(0.0, 0.0, w, h), 0.0, colour.faded(opacity));
}

/// A launcher result row (§5).
#[derive(Clone, Debug)]
pub struct Row<'a> {
    pub icon: Icon,
    pub name: &'a str,
    pub linux: bool,
    /// Right-aligned: "app", "settings", "system".
    pub meta: &'a str,
    /// What it is for (the app's `comment`), a second line; may be empty.
    pub comment: &'a str,
}

/// A labelled group of rows ("apps", "actions").
#[derive(Clone, Debug)]
pub struct Section<'a> {
    pub label: &'a str,
    pub rows: &'a [Row<'a>],
}

/// What the launcher shows.
#[derive(Clone, Debug)]
pub struct Launcher<'a> {
    pub query: &'a str,
    pub sections: &'a [Section<'a>],
    /// The selected row, counting through all sections.
    pub selected: usize,
    /// The list's window when it scrolls: the first row shown, how many
    /// are, and how many there are (ADR 0102).
    pub scroll: Option<(usize, usize, usize)>,
}

pub const LAUNCHER_W: f32 = 680.0;
const LAUNCHER_R: f32 = 16.0;
const QUERY_H: f32 = 66.0;
const LABEL_H: f32 = 28.0;
const ROW_H: f32 = 54.0;
const FOOTER_H: f32 = 42.0;

/// The launcher's surface for `l` on a `w` × `h` screen.
pub fn launcher_area(w: f32, h: f32, l: &Launcher<'_>) -> Area {
    let mut list = 16.0;
    for (i, s) in l.sections.iter().enumerate() {
        list += if i > 0 { 4.0 } else { 0.0 } + LABEL_H + ROW_H * s.rows.len() as f32;
    }
    let height = QUERY_H + list + FOOTER_H;
    Area::new(round((w - LAUNCHER_W) / 2.0), round(h * 0.19), LAUNCHER_W, height)
}

/// A keycap: DM Mono 10.5 in a 1 px `border-strong` outline, 22 tall.
fn keycap(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, right: f32, mid: f32, key: &str) {
    let st = p.style(&f.mono, 10.5, pal.text_3);
    let w = p.measure(&st, key) + 14.0;
    let a = Area::new(right - w, mid - 11.0, w, 22.0);
    p.border(a, 5.0, 1.0, pal.border_strong);
    p.line(&st, a.x + 7.0, a.y, a.h, key);
}

/// Key hints: each key in `text-1`, its label in `muted` (§2). The fonts
/// have no ↵ or ↑↓, so those keys are icons.
fn hints(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, x: f32, top: f32, h: f32, items: &[(&str, &str)]) -> f32 {
    let key = p.style(&f.mono, 11.0, pal.text_1);
    let label = p.style(&f.mono, 11.0, pal.muted);
    let mut x = x;
    for (i, (k, l)) in items.iter().enumerate() {
        if i > 0 {
            x += 16.0;
        }
        let symbol = match *k {
            "↵" => Some(Icon::Enter),
            "↑↓" => Some(Icon::UpDown),
            "←→" => Some(Icon::LeftRight),
            _ => None,
        };
        x += match symbol {
            Some(icon) => {
                p.icon(icon, x, top + (h - 12.0) / 2.0, 12.0, pal.text_1);
                12.0
            }
            None => p.line(&key, x, top, h, k),
        };
        if !l.is_empty() {
            x += 6.0 + p.line(&label, x + 6.0, top, h, l);
        }
    }
    x
}

/// The launcher (§5), over [`dim`].
/// Returns where each row is, in selection order.
pub fn launcher(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, l: &Launcher<'_>) -> Vec<Area> {
    let (w, h) = p.size();
    let a = launcher_area(w, h, l);
    p.shadow_under(a, LAUNCHER_R, &FLOATING);
    p.shadow_under(a, LAUNCHER_R, &CONTACT);
    p.fill(a, LAUNCHER_R, pal.overlay);
    rim(p, pal, a, LAUNCHER_R);
    // The query row.
    p.icon(Icon::Search, a.x + 22.0, a.y + (QUERY_H - 17.0) / 2.0, 17.0, pal.text_4);
    let q = p.style(&f.regular, 21.0, pal.chalk).tracking(-0.02);
    let qx = a.x + 54.0;
    let end = qx + p.line(&q, qx, a.y, QUERY_H, l.query);
    p.fill(Area::new(end + 1.0, a.y + QUERY_H / 2.0 - 12.0, 2.0, 24.0), 0.0, pal.chalk);
    keycap(p, pal, f, a.right() - 18.0, a.y + QUERY_H / 2.0, "esc");
    p.fill(Area::new(a.x + 1.0, a.y + QUERY_H - 1.0, a.w - 2.0, 1.0), 0.0, pal.active_ws);
    // The sections.
    let mut y = a.y + QUERY_H + 8.0;
    let mut index = 0;
    let mut rows = Vec::new();
    for (si, s) in l.sections.iter().enumerate() {
        if si > 0 {
            y += 4.0;
        }
        ruled_label(p, pal, f, a.x + 20.0, y + 1.0, 26.0, a.right() - 20.0, s.label, None);
        y += LABEL_H;
        for r in s.rows {
            let row = Area::new(a.x + 8.0, y, a.w - 16.0, ROW_H);
            launcher_row(p, pal, f, row, r, index == l.selected);
            rows.push(row);
            y += ROW_H;
            index += 1;
        }
    }
    // Where the window is in a list longer than it: a thin bar.
    if let Some((first, shown, total)) = l.scroll {
        let (top, bottom) = (a.y + QUERY_H + 8.0, a.bottom() - FOOTER_H - 8.0);
        let h = bottom - top;
        let bar = (h * shown as f32 / total as f32).max(16.0);
        let y = top + (h - bar) * first as f32 / (total - shown).max(1) as f32;
        p.fill(Area::new(a.right() - 7.0, y, 3.0, bar), 1.5, pal.decor);
    }
    // The footer.
    let foot = Area::new(a.x, a.bottom() - FOOTER_H, a.w, FOOTER_H);
    p.fill(Area::new(a.x + 1.0, foot.y, a.w - 2.0, 1.0), 0.0, pal.active_ws);
    hints(p, pal, f, a.x + 21.0, foot.y, foot.h, &[("↵", "open"), ("tab", "actions"), ("↑↓", "move")]);
    let st = p.style(&f.mono, 11.0, pal.text_1);
    let sw = p.measure(&st, "super + space");
    p.line(&st, a.right() - 21.0 - sw, foot.y, foot.h, "super + space");
    p.border(a, LAUNCHER_R, 1.0, pal.border);
    rows
}

/// A floating surface's rim (ADR 0124): a 1 px line of light just inside
/// its top edge, following its corners; none in high contrast.
fn rim(p: &mut Painter<'_>, pal: &Palette, a: Area, r: f32) {
    if pal.titlebar_rim.alpha() > 0 {
        let saved = p.clip(Area::new(a.x, a.y + 1.0, a.w, 1.0));
        p.fill(a.grow(-1.0), r - 1.0, pal.titlebar_rim);
        p.unclip(saved);
    }
}

fn launcher_row(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, row: Area, r: &Row<'_>, selected: bool) {
    let (name_c, tile_c, icon_c, meta_c, tag_border, tag_text) = if selected {
        p.fill(row, 10.0, pal.chalk);
        (pal.desktop, pal.selected_tile, pal.desktop, pal.selected_meta, pal.selected_tag, pal.selected_meta)
    } else {
        (pal.chalk, pal.raised, pal.text_3, pal.muted, pal.border_strong, pal.text_4)
    };
    let mid = row.y + ROW_H / 2.0;
    let tile = Area::new(row.x + 12.0, mid - 17.0, 34.0, 34.0);
    p.fill(tile, 9.0, tile_c);
    p.icon(r.icon, tile.x + 8.5, tile.y + 8.5, 17.0, icon_c);
    let meta = p.style(&f.mono, 11.5, meta_c);
    let mw = p.measure(&meta, r.meta);
    p.line(&meta, row.right() - 12.0 - mw, row.y, ROW_H, r.meta);
    // The name, and what the app is for under it (ADR 0124).
    let name = p.style(&f.medium, 15.0, name_c).tracking(-0.01);
    let x = tile.right() + 14.0;
    let room = row.right() - 12.0 - mw - 16.0 - x - if r.linux { 72.0 } else { 0.0 };
    if r.comment.is_empty() {
        p.line(&name, x, row.y, ROW_H, &truncate_end(p, &name, r.name, room));
    } else {
        p.line(&name, x, row.y + 9.0, 20.0, &truncate_end(p, &name, r.name, room));
        let c = p.style(&f.regular, 12.0, meta_c);
        p.line(&c, x, row.y + 29.0, 16.0, &truncate_end(p, &c, r.comment, room));
    }
    if r.linux {
        let st = p.style(&f.mono, 10.5, tag_text);
        let tw = p.measure(&st, "linux") + 12.0;
        domain_tag(p, f, row.right() - 12.0 - 72.0 - 6.0 - tw, mid, tag_border, tag_text);
    }
}

/// Which control of the approval dialog has the keyboard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalFocus {
    Password,
    Cancel,
    Approve,
}

/// What the system approval dialog shows (§6).
#[derive(Clone, Debug)]
pub struct Approval<'a> {
    pub title: &'a str,
    pub body: &'a str,
    /// The detail well's rows: requested by, change, signature.
    pub details: &'a [(&'a str, &'a str)],
    pub user: &'a str,
    pub password: &'a slate_ui::edit::LineEdit,
    pub focus: ApprovalFocus,
    /// Show the keyboard focus on buttons (after Tab).
    pub focus_visible: bool,
    /// Shown in place of the scope line (a wrong password).
    pub error: Option<&'a str>,
}

/// Where the approval dialog's controls are, for pointer events.
#[derive(Clone, Copy, Debug, Default)]
pub struct ApprovalHits {
    pub dialog: Area,
    pub password: Area,
    pub cancel: Area,
    pub approve: Area,
}

const DIALOG_W: f32 = 440.0;
const DIALOG_PAD: f32 = 28.0;

/// The body's lines, wrapped to the dialog.
fn body_lines(p: &Painter<'_>, face: &Face<'_>, body: &str) -> Vec<String> {
    let st = p.style(face, 14.0, Color::rgb(0));
    text::wrap(&st, body, DIALOG_W * p.scale)
}

/// The system approval dialog (§6), over [`dim`].
pub fn approval(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, d: &Approval<'_>) -> ApprovalHits {
    let (w, h) = p.size();
    let lines = body_lines(p, &f.regular, d.body);
    let well_h = 24.0 + 22.0 * d.details.len() as f32;
    let inner =
        22.0 + 18.0 + 27.5 + 8.0 + 21.0 * lines.len() as f32 + 20.0 + well_h + 18.0 + 18.0 + 8.0 + 42.0 + 24.0 + 38.0;
    let a = Area::new(
        round((w - DIALOG_W) / 2.0 - DIALOG_PAD),
        round(h * 0.22),
        DIALOG_W + 2.0 * DIALOG_PAD,
        inner + 28.0 + 24.0,
    );
    p.shadow_under(a, 14.0, &FLOATING);
    p.fill(a, 14.0, pal.overlay);
    p.border(a, 14.0, 1.0, pal.border);
    let x = a.x + DIALOG_PAD;
    let mut y = a.y + DIALOG_PAD;
    // The header: Slate's mark, which apps cannot draw here.
    p.logo(x, y, 22.0, pal.chalk);
    let st = p.style(&f.mono, 11.5, pal.muted);
    p.line(&st, x + 22.0 + 12.0, y, 22.0, "system approval");
    y += 22.0 + 18.0;
    let title = p.style(&f.medium, 22.0, pal.chalk).tracking(-0.025);
    p.line(&title, x, y, 27.5, d.title);
    y += 27.5 + 8.0;
    let body = p.style(&f.regular, 14.0, pal.text_4);
    for l in &lines {
        p.line(&body, x, y, 21.0, l);
        y += 21.0;
    }
    y += 20.0;
    // The detail well: a key/value grid.
    let well = Area::new(x, y, DIALOG_W, well_h);
    p.fill(well, 8.0, pal.well);
    p.border(well, 8.0, 1.0, pal.active_ws);
    let (key, value) = (p.style(&f.mono, 12.0, pal.muted), p.style(&f.mono, 12.0, pal.text_1));
    for (i, (k, v)) in d.details.iter().enumerate() {
        let top = y + 12.0 + 22.0 * i as f32;
        p.line(&key, x + 14.0, top, 22.0, k);
        p.line(&value, x + 14.0 + 122.0, top, 22.0, v);
    }
    y += well_h + 18.0;
    // The password.
    let label = p.style(&f.medium, 12.5, pal.text_3);
    p.line(&label, x, y, 18.0, &alloc::format!("Password for {}", d.user));
    y += 18.0 + 8.0;
    let field = Area::new(x, y, DIALOG_W, 42.0);
    p.fill(field, 8.0, pal.well);
    if d.focus == ApprovalFocus::Password {
        p.border(field.grow(3.0), 11.0, 3.0, pal.chalk.with_alpha(26));
        p.border(field, 8.0, 1.0, pal.field_focus);
    } else {
        p.border(field, 8.0, 1.0, pal.border);
    }
    crate::lock::draw_dots(p, pal, field.x + 18.0, field.y + 21.0, d.password, d.focus == ApprovalFocus::Password);
    y += 42.0 + 24.0;
    // The buttons, right-aligned; the scope line (or the error) left.
    let text = p.style(&f.medium, 15.0, pal.chalk);
    let (aw, cw) = (p.measure(&text, "Approve") + 44.0, p.measure(&text, "Cancel") + 44.0);
    let approve = Area::new(x + DIALOG_W - aw, y, aw, 38.0);
    let cancel = Area::new(approve.x - 10.0 - cw, y, cw, 38.0);
    p.border(cancel, 8.0, 1.0, pal.border_strong);
    p.line(&text, cancel.x + 22.0, cancel.y, cancel.h, "Cancel");
    p.fill(approve, 8.0, pal.chalk);
    let dark = p.style(&f.medium, 15.0, pal.desktop);
    p.line(&dark, approve.x + 22.0, approve.y, approve.h, "Approve");
    for (focus, b) in [(ApprovalFocus::Cancel, cancel), (ApprovalFocus::Approve, approve)] {
        if d.focus_visible && d.focus == focus {
            p.border(b.grow(4.0), 12.0, 2.0, pal.chalk);
        }
    }
    let (line, colour) = match d.error {
        Some(e) => (e, pal.text_1),
        None => ("Approves this change only.", pal.muted),
    };
    let scope = p.style(&f.regular, 12.0, colour);
    p.line(&scope, x, y, 38.0, line);
    ApprovalHits { dialog: a, password: field, cancel, approve }
}

// --- the Applications menu (ADR 0110) ------------------------------------

/// The menu's size: the categories' column and the apps' column.
const MENU_CATS_W: f32 = 200.0;
const MENU_APPS_W: f32 = 380.0;
const MENU_SEARCH_H: f32 = 52.0;
const MENU_R: f32 = 14.0;
const MENU_CAT_H: f32 = 34.0;
const MENU_APP_H: f32 = 50.0;
const MENU_FOOT_H: f32 = 36.0;

/// Where the menu's rows are.
#[derive(Clone, Debug, Default)]
pub struct MenuHits {
    pub area: Area,
    pub categories: Vec<Area>,
    /// The app rows drawn, in order.
    pub apps: Vec<Area>,
    /// The apps' column, for the wheel.
    pub apps_column: Area,
}

/// The menu's surface, hanging from the Applications button (under a
/// top bar `bar_h` tall).
pub fn menu_area(m: &crate::menu::Menu, bar_h: f32) -> Area {
    let cats = 16.0 + MENU_CAT_H * m.categories.len() as f32;
    let apps = 16.0 + 26.0 + MENU_APP_H * crate::menu::APPS_SHOWN as f32;
    Area::new(6.0, bar_h + 2.0, MENU_CATS_W + MENU_APPS_W, MENU_SEARCH_H + cats.max(apps) + MENU_FOOT_H)
}

/// The Applications menu: a search field, the categories, the chosen
/// category's apps (each with what it is for), and key hints.
pub fn apps_menu(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, m: &crate::menu::Menu) -> MenuHits {
    use crate::menu::Pane;
    let a = menu_area(m, pal.shape.bar_h);
    let mut hits = MenuHits { area: a, ..MenuHits::default() };
    p.shadow_under(a, MENU_R, &MENU);
    p.fill(a, MENU_R, pal.overlay);
    rim(p, pal, a, MENU_R);
    // The search field.
    let field = Area::new(a.x + 10.0, a.y + 9.0, a.w - 20.0, MENU_SEARCH_H - 18.0);
    p.fill(field, 8.0, pal.well);
    p.border(field, 8.0, 1.0, if m.searching() { pal.field_focus } else { pal.border });
    p.icon(Icon::Search, field.x + 11.0, field.y + 9.0, 14.0, pal.muted);
    let tx = field.x + 34.0;
    // The caret before the placeholder, after what is typed.
    let end = if m.query.is_empty() {
        let ghost = p.style(&f.regular, 13.0, pal.muted);
        p.line(&ghost, tx + 4.0, field.y, field.h, "Search applications");
        tx - 2.0
    } else {
        let typed = p.style(&f.regular, 13.0, pal.chalk);
        tx + p.line(&typed, tx, field.y, field.h, &m.query)
    };
    p.fill(Area::new(end + 1.0, field.y + 8.0, 1.5, field.h - 16.0), 0.0, pal.chalk);
    let body = Area::new(a.x, a.y + MENU_SEARCH_H, a.w, a.h - MENU_SEARCH_H - MENU_FOOT_H);
    p.fill(Area::new(a.x + 1.0, body.y, a.w - 2.0, 1.0), 0.0, pal.active_ws);
    p.fill(Area::new(a.x + MENU_CATS_W, body.y + 1.0, 1.0, body.h - 1.0), 0.0, pal.active_ws);
    // The categories.
    let mut y = body.y + 8.0;
    for (i, c) in m.categories.iter().enumerate() {
        let row = Area::new(a.x + 8.0, y, MENU_CATS_W - 16.0, MENU_CAT_H - 2.0);
        let chosen = i == m.category && !m.searching();
        let (fg, icon) = if chosen && m.pane == Pane::Categories {
            p.fill(row, 7.0, pal.chalk);
            (pal.desktop, pal.desktop)
        } else if chosen {
            p.fill(row, 7.0, pal.raised);
            (pal.chalk, pal.text_3)
        } else if m.searching() {
            (pal.muted, pal.decor)
        } else {
            (pal.text_1, pal.text_4)
        };
        p.icon(c.icon(), row.x + 10.0, row.y + (row.h - 15.0) / 2.0, 15.0, icon);
        let st = p.style(&f.regular, 13.0, fg);
        p.line(&st, row.x + 34.0, row.y, row.h, &c.label());
        if chosen {
            p.icon(Icon::ChevronRight, row.right() - 22.0, row.y + (row.h - 12.0) / 2.0, 12.0, icon);
        }
        hits.categories.push(row);
        y += MENU_CAT_H;
    }
    // The apps.
    let col = Area::new(a.x + MENU_CATS_W + 1.0, body.y + 1.0, MENU_APPS_W - 1.0, body.h - 1.0);
    hits.apps_column = col;
    let shown = m.shown();
    let header = if m.searching() {
        String::from(if shown.is_empty() { "no app has that name" } else { "results" })
    } else {
        m.categories.get(m.category).map(|c| c.label().to_lowercase()).unwrap_or_default()
    };
    // The header, a ruled label with the count (ADR 0124).
    let count = alloc::format!("{}", shown.len());
    let count = (!shown.is_empty()).then_some(count.as_str());
    ruled_label(p, pal, f, col.x + 18.0, col.y + 6.0, 26.0, col.right() - 18.0, &header, count);
    let mut y = col.y + 34.0;
    for (i, app) in m.window() {
        let row = Area::new(col.x + 8.0, y, col.w - 16.0, MENU_APP_H - 2.0);
        let chosen = i == m.item && m.pane == Pane::Apps;
        let (name_c, comment_c, tile_c, icon_c) = if chosen {
            p.fill(row, 8.0, pal.chalk);
            (pal.desktop, pal.selected_meta, pal.selected_tile, pal.desktop)
        } else {
            (pal.chalk, pal.muted, pal.raised, pal.text_3)
        };
        let tile = Area::new(row.x + 8.0, row.y + (row.h - 32.0) / 2.0, 32.0, 32.0);
        p.fill(tile, 8.0, tile_c);
        p.icon(app.icon, tile.x + 8.0, tile.y + 8.0, 16.0, icon_c);
        let name = p.style(&f.medium, 13.5, name_c);
        let x = tile.right() + 12.0;
        let room = row.right() - 10.0 - x;
        if app.comment.is_empty() {
            p.line(&name, x, row.y, row.h, &app.name);
        } else {
            p.line(&name, x, row.y + 6.0, 19.0, &truncate_end(p, &name, &app.name, room));
            let c = p.style(&f.regular, 11.5, comment_c);
            p.line(&c, x, row.y + 25.0, 16.0, &truncate_end(p, &c, &app.comment, room));
        }
        if app.linux {
            let st = p.style(&f.mono, 10.5, if chosen { pal.selected_meta } else { pal.text_4 });
            let tw = p.measure(&st, "linux") + 12.0;
            let border = if chosen { pal.selected_tag } else { pal.border_strong };
            domain_tag(
                p,
                f,
                row.right() - 10.0 - tw,
                row.y + row.h / 2.0,
                border,
                if chosen { pal.selected_meta } else { pal.text_4 },
            );
        }
        hits.apps.push(row);
        y += MENU_APP_H;
    }
    // Where the window is in a longer list.
    if shown.len() > crate::menu::APPS_SHOWN {
        let (top, h) = (col.y + 34.0, MENU_APP_H * crate::menu::APPS_SHOWN as f32);
        let bar = (h * crate::menu::APPS_SHOWN as f32 / shown.len() as f32).max(16.0);
        let y = top + (h - bar) * m.first as f32 / (shown.len() - crate::menu::APPS_SHOWN) as f32;
        p.fill(Area::new(col.right() - 5.0, y, 3.0, bar), 1.5, pal.decor);
    }
    // The footer.
    let foot = Area::new(a.x, a.bottom() - MENU_FOOT_H, a.w, MENU_FOOT_H);
    p.fill(Area::new(a.x + 1.0, foot.y, a.w - 2.0, 1.0), 0.0, pal.active_ws);
    hints(p, pal, f, a.x + 18.0, foot.y, foot.h, &[("↵", "open"), ("↑↓", "move"), ("←→", "columns")]);
    keycap(p, pal, f, a.right() - 16.0, foot.y + foot.h / 2.0, "esc");
    p.border(a, MENU_R, 1.0, pal.border);
    hits
}

// --- the power dialog (ADR 0110) -------------------------------------------

/// The power dialog's choices, left to right.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerChoice {
    Lock,
    LogOut,
    Restart,
    ShutDown,
}

impl PowerChoice {
    pub const ALL: [PowerChoice; 4] =
        [PowerChoice::Lock, PowerChoice::LogOut, PowerChoice::Restart, PowerChoice::ShutDown];

    pub fn label(self) -> &'static str {
        match self {
            PowerChoice::Lock => "Lock",
            PowerChoice::LogOut => "Log out",
            PowerChoice::Restart => "Restart",
            PowerChoice::ShutDown => "Shut down",
        }
    }

    fn icon(self) -> Icon {
        match self {
            PowerChoice::Lock => Icon::Lock,
            PowerChoice::LogOut => Icon::LogOut,
            PowerChoice::Restart => Icon::Restart,
            PowerChoice::ShutDown => Icon::Power,
        }
    }
}

/// What the power dialog shows.
#[derive(Clone, Debug)]
pub struct PowerView<'a> {
    /// The person's name and login.
    pub name: &'a str,
    pub user: &'a str,
    pub power: &'a crate::power::Power,
}

/// Where the power dialog's choices are.
#[derive(Clone, Copy, Debug, Default)]
pub struct PowerHits {
    pub dialog: Area,
    pub choices: [Area; 4],
    /// The times under them (`power::WHEN`), and the updates' box.
    pub when: [Area; 4],
    pub install: Option<Area>,
    /// "Don't shut down", for what is set for later.
    pub unschedule: Option<Area>,
    pub cancel: Area,
    /// The other face's Cancel and "anyway".
    pub ask: [Area; 2],
}

const POWER_TILE_W: f32 = 108.0;
const POWER_TILE_H: f32 = 96.0;
const POWER_GAP: f32 = 12.0;
/// The options' row (the times, or what is set for later), and the
/// updates' box under it.
const POWER_ROW_H: f32 = 28.0;
const POWER_BOX_H: f32 = 22.0;
/// The most apps the other face names.
const POWER_ASK_MAX: usize = 5;

/// A text button 36 px high ending at `right`: its area. `colour` is a
/// semantic one (clay for "anyway") or None for chalk; `focused` rings it.
#[allow(clippy::too_many_arguments)]
fn dialog_button(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    right: f32,
    y: f32,
    label: &str,
    colour: Option<slate_ui::graphite::Accent>,
    focused: bool,
) -> Area {
    let text = p.style(&f.medium, 14.0, colour.map_or(pal.chalk, |c| c.text));
    let bw = p.measure(&text, label) + 40.0;
    let a = Area::new(right - bw, y, bw, 36.0);
    match colour {
        Some(c) => {
            p.fill(a, 8.0, c.tint);
            p.border(a, 8.0, 1.0, c.border);
        }
        None => p.border(a, 8.0, 1.0, pal.border_strong),
    }
    if focused {
        p.border(a.grow(3.0), 11.0, 2.0, pal.chalk);
    }
    p.line(&text, a.x + 20.0, a.y, a.h, label);
    a
}

/// The power dialog, over [`dim`]: four tiles (lock, log out, restart,
/// shut down), when and whether to install updates first, and Cancel; or
/// its other face, the apps still open.
pub fn power_dialog(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, v: &PowerView<'_>) -> PowerHits {
    if let Some(ask) = &v.power.ask {
        return power_ask(p, pal, f, v, ask);
    }
    let pw = v.power;
    let (w, h) = p.size();
    let inner_w = 4.0 * POWER_TILE_W + 3.0 * POWER_GAP;
    let boxed = pw.updates > 0 && pw.pending.is_none();
    let options_h = 20.0 + POWER_ROW_H + if boxed { 12.0 + POWER_BOX_H } else { 0.0 };
    let inner_h = 22.0 + 6.0 + 18.0 + 24.0 + POWER_TILE_H + options_h + 24.0 + 36.0;
    let a = Area::new(
        round((w - inner_w) / 2.0 - DIALOG_PAD),
        round((h - inner_h) / 2.0 - DIALOG_PAD - h * 0.04),
        inner_w + 2.0 * DIALOG_PAD,
        inner_h + 2.0 * DIALOG_PAD,
    );
    p.shadow_under(a, 14.0, &FLOATING);
    p.fill(a, 14.0, pal.overlay);
    p.border(a, 14.0, 1.0, pal.border);
    let x = a.x + DIALOG_PAD;
    let mut y = a.y + DIALOG_PAD;
    let title = p.style(&f.medium, 18.0, pal.chalk).tracking(-0.02);
    p.line(&title, x, y, 22.0, "Power");
    y += 22.0 + 6.0;
    let who = p.style(&f.regular, 13.0, pal.muted);
    let line = if v.name.is_empty() || v.name == v.user {
        String::from(v.user)
    } else {
        alloc::format!("{} · {}", v.name, v.user)
    };
    p.line(&who, x, y, 18.0, &line);
    y += 18.0 + 24.0;
    let mut hits = PowerHits { dialog: a, ..PowerHits::default() };
    let on_tiles = pw.row == crate::power::Row::Choices;
    for (i, c) in PowerChoice::ALL.iter().enumerate() {
        let tile = Area::new(x + i as f32 * (POWER_TILE_W + POWER_GAP), y, POWER_TILE_W, POWER_TILE_H);
        let focused = *c == pw.focus;
        let (fg, icon) = if focused {
            p.fill(tile, 10.0, pal.chalk);
            (pal.desktop, pal.desktop)
        } else {
            p.fill(tile, 10.0, pal.raised);
            p.border(tile, 10.0, 1.0, pal.border);
            (pal.text_1, pal.text_3)
        };
        if focused && pw.focus_visible && on_tiles {
            p.border(tile.grow(4.0), 14.0, 2.0, pal.chalk);
        }
        p.icon(c.icon(), tile.x + (tile.w - 24.0) / 2.0, tile.y + 22.0, 24.0, icon);
        let st = p.style(&f.medium, 13.5, fg);
        let lw = p.measure(&st, c.label());
        p.line(&st, tile.x + (tile.w - lw) / 2.0, tile.y + 58.0, 20.0, c.label());
        hits.choices[i] = tile;
    }
    y += POWER_TILE_H + 20.0;
    let ring = |p: &mut Painter<'_>, i: usize, area: Area, r: f32| {
        if !on_tiles && pw.focus_visible && pw.at == i {
            p.border(area.grow(3.0), r + 3.0, 2.0, pal.chalk);
        }
    };
    if let Some(pending) = &pw.pending {
        // What is set for later: a pending state, so ochre with a clock
        // (STRATA_COLORS), and the button that calls it off.
        let ochre = pal.accents.ochre;
        p.icon(Icon::Clock, x, y + 7.0, 14.0, ochre.text);
        let st = p.style(&f.regular, 13.0, ochre.text);
        let mut text = pending.text();
        if pending.install {
            text.push_str(", after installing the updates");
        }
        let label = p.style(&f.medium, 12.5, pal.chalk);
        let bw = p.measure(&label, pending.undo()) + 28.0;
        let undo = Area::new(x + inner_w - bw, y, bw, POWER_ROW_H);
        p.border(undo, 7.0, 1.0, pal.border_strong);
        p.line(&label, undo.x + 14.0, undo.y, undo.h, pending.undo());
        ring(p, 0, undo, 7.0);
        hits.unschedule = Some(undo);
        let room = undo.x - 12.0 - (x + 22.0);
        p.line(&st, x + 22.0, y, POWER_ROW_H, &truncate_end(p, &st, &text, room));
    } else {
        // When: a ruled-off mono label, then the times as small chips;
        // they only mean something for restarting and shutting down.
        let live = pw.timed();
        let label = p.style(&f.mono, 11.0, if live { pal.muted } else { pal.decor }).tracking(0.04);
        let lx = x + p.line(&label, x, y, POWER_ROW_H, "when") + 14.0;
        let mut cx = lx;
        for (i, (name, _)) in crate::power::WHEN.iter().enumerate() {
            let chosen = live && i == pw.when;
            let st = p.style(
                &f.regular,
                12.5,
                if chosen {
                    pal.desktop
                } else if live {
                    pal.text_1
                } else {
                    pal.decor
                },
            );
            let chip = Area::new(cx, y, p.measure(&st, name) + 24.0, POWER_ROW_H);
            if chosen {
                p.fill(chip, 7.0, pal.chalk);
            } else {
                p.border(chip, 7.0, 1.0, if live { pal.border } else { pal.active_ws });
            }
            p.line(&st, chip.x + 12.0, chip.y, chip.h, name);
            ring(p, i, chip, 7.0);
            hits.when[i] = chip;
            cx = chip.right() + 8.0;
        }
        if boxed {
            y += POWER_ROW_H + 12.0;
            let b = Area::new(lx, y + 3.0, 16.0, 16.0);
            if live && pw.install {
                p.fill(b, 4.0, pal.chalk);
                p.icon(Icon::Check, b.x + 2.0, b.y + 2.0, 12.0, pal.desktop);
            } else {
                p.border(b, 4.0, 1.0, if live { pal.border_strong } else { pal.active_ws });
            }
            let st = p.style(&f.regular, 13.0, if live { pal.text_1 } else { pal.decor });
            let text = if pw.updates == 1 {
                String::from("Install the update first")
            } else {
                alloc::format!("Install the {} updates first", pw.updates)
            };
            let tw = p.line(&st, b.right() + 10.0, y, POWER_BOX_H, &text);
            let area = Area::new(b.x, y, 16.0 + 10.0 + tw, POWER_BOX_H);
            ring(p, crate::power::WHEN.len(), Area::new(area.x - 3.0, area.y, area.w + 9.0, area.h), 4.0);
            hits.install = Some(area);
            y -= POWER_ROW_H + 12.0;
        }
    }
    y += options_h - 20.0 + 24.0;
    // Cancel at the right; a problem (in clay) or the keys at the left.
    let cancel = dialog_button(p, pal, f, x + inner_w, y, "Cancel", None, false);
    hits.cancel = cancel;
    match &pw.error {
        Some(e) => {
            let clay = pal.accents.clay;
            let st = p.style(&f.regular, 12.5, clay.text);
            let room = cancel.x - 16.0 - x;
            p.line(&st, x, y, 36.0, &truncate_end(p, &st, e, room));
        }
        None => {
            let keys: &[(&str, &str)] = match (on_tiles, pw.pending.is_some(), pw.options() > 0) {
                (true, true, _) => &[("←→", "choose"), ("↑↓", "call off"), ("↵", "go")],
                (true, false, true) => &[("←→", "choose"), ("↑↓", "when"), ("↵", "go")],
                (true, false, false) => &[("←→", "choose"), ("↵", "go")],
                (false, true, _) => &[("↑↓", "back"), ("↵", "call off")],
                (false, false, _) => &[("←→", "move"), ("space", "pick"), ("↵", "go")],
            };
            hints(p, pal, f, x, y, 36.0, keys);
        }
    }
    hits
}

/// The power dialog's other face: going on would close apps that are
/// still open (unsaved work), or the updates weren't installed.
fn power_ask(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    v: &PowerView<'_>,
    ask: &crate::power::Ask,
) -> PowerHits {
    use crate::power::Why;
    let (w, h) = p.size();
    let inner_w = 4.0 * POWER_TILE_W + 3.0 * POWER_GAP;
    let shown = ask.apps.len().min(POWER_ASK_MAX);
    let more = ask.apps.len() > POWER_ASK_MAX;
    let list_h = if shown > 0 { 16.0 + 30.0 * (shown + usize::from(more)) as f32 } else { 0.0 };
    let inner_h = 22.0 + 10.0 + 40.0 + list_h + 28.0 + 36.0;
    let a = Area::new(
        round((w - inner_w) / 2.0 - DIALOG_PAD),
        round((h - inner_h) / 2.0 - DIALOG_PAD - h * 0.04),
        inner_w + 2.0 * DIALOG_PAD,
        inner_h + 2.0 * DIALOG_PAD,
    );
    p.shadow_under(a, 14.0, &FLOATING);
    p.fill(a, 14.0, pal.overlay);
    p.border(a, 14.0, 1.0, pal.border);
    let x = a.x + DIALOG_PAD;
    let mut y = a.y + DIALOG_PAD;
    // A warning: ochre's icon beside the title, the words in chalk.
    let ochre = pal.accents.ochre;
    p.icon(Icon::Warning, x, y + 3.0, 16.0, ochre.text);
    let title = p.style(&f.medium, 18.0, pal.chalk).tracking(-0.02);
    let (head, body) = match ask.why {
        Why::Unsaved if ask.apps.len() == 1 => (
            "An app is still open",
            "It may be asking about unsaved work. Save it there, or go on and lose what isn't saved.",
        ),
        Why::Unsaved => (
            "Apps are still open",
            "They may be asking about unsaved work. Save it there, or go on and lose what isn't saved.",
        ),
        Why::NotInstalled => (
            "The updates weren't installed",
            "The Software Updater stopped before it finished. They can be installed later.",
        ),
    };
    p.line(&title, x + 26.0, y, 22.0, head);
    y += 22.0 + 10.0;
    let st = p.style(&f.regular, 13.0, pal.text_3);
    let lines = text::wrap(&st, body, inner_w * p.scale);
    for (i, l) in lines.iter().take(2).enumerate() {
        p.line(&st, x, y + 20.0 * i as f32, 20.0, l);
    }
    y += 40.0;
    if shown > 0 {
        y += 16.0;
        let st = p.style(&f.regular, 13.5, pal.text_1);
        for app in ask.apps.iter().take(shown) {
            let row = Area::new(x, y, inner_w, 30.0);
            p.fill(Area::new(row.x, row.bottom() - 1.0, row.w, 1.0), 0.0, pal.active_ws);
            p.icon(Icon::Document, x + 2.0, y + 8.0, 14.0, pal.text_3);
            p.line(&st, x + 26.0, y, 30.0, &truncate_end(p, &st, app, inner_w - 26.0));
            y += 30.0;
        }
        if more {
            let st = p.style(&f.regular, 13.0, pal.muted);
            p.line(&st, x + 26.0, y, 30.0, &alloc::format!("and {} more", ask.apps.len() - shown));
            y += 30.0;
        }
    }
    y += 28.0;
    let mut hits = PowerHits { dialog: a, ..PowerHits::default() };
    let focused = |i: usize| v.power.focus_visible && ask.focus == i;
    let anyway = dialog_button(p, pal, f, x + inner_w, y, &ask.anyway(), Some(pal.accents.clay), focused(1));
    let cancel = dialog_button(p, pal, f, anyway.x - 10.0, y, "Cancel", None, focused(0));
    hits.ask = [cancel, anyway];
    hits.cancel = cancel;
    hits
}
