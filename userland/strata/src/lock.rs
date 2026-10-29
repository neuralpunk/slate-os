// SPDX-License-Identifier: MIT OR Apache-2.0

//! The lock screen (ADR 0039): super + L, "Lock screen" in the launcher,
//! or a while without input (ADR 0102) covers the desktop with a screen
//! asking for the person's password (Atelier's composition, ADR 0124); apps get no keys or pointer events
//! until it is given. The privilege broker checks it (`check`), so Strata
//! never reads /etc/shadow.
//!
//! "Switch person" (Tab, or a click) lets someone else log in: after a
//! second Enter it ends this session, its windows closing, and the login
//! screen comes back (ADR 0102; keeping the session while another runs
//! needs session switching in seatd, M30).

use alloc::string::String;
use alloc::vec::Vec;

use slate_display::input::{KEY_BACKSPACE, KEY_ENTER, KEY_ESC, KEY_KPENTER, KEY_TAB, Mods};
use slate_rt::{io, lossy, net};
use slate_ui::edit::LineEdit;
use slate_ui::graphite::Palette;
use slate_ui::math::round;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;
use slate_ui::{Canvas, Path, Transform};

use crate::draw;
use crate::fonts::Fonts;

/// What the line under the field says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Asking,
    Working,
    Wrong,
}

/// Where the keys go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Focus {
    Password,
    Switch,
    /// "Switch person" was chosen: Enter confirms, Esc goes back.
    Confirm,
}

/// What the lock screen asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Check this password.
    Check(Vec<u8>),
    /// End the session for someone else.
    SwitchPerson,
}

/// The lock screen's state.
#[derive(Clone, Debug)]
pub struct Lock {
    /// The password typed (ADR 0101's line editor: the caret moves).
    pub password: LineEdit,
    pub status: Status,
    pub focus: Focus,
    /// When it was shown, and when a password was last wrong (ms).
    pub opened: i64,
    pub shaken: Option<i64>,
    /// Accessibility's high contrast, while locked.
    pub high_contrast: bool,
}

impl Default for Lock {
    fn default() -> Lock {
        Lock {
            password: LineEdit::new("").with_max(256).secret(),
            status: Status::Asking,
            focus: Focus::Password,
            opened: i64::MIN / 2,
            shaken: None,
            high_contrast: false,
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        self.password.wipe();
    }
}

/// A key for a field on Strata's own screens (the lock and login screens,
/// the approval dialog; ADR 0101's line editor): left and right (ctrl: a
/// word), Home and End move, with shift choosing; Backspace and Delete
/// remove (ctrl: a word); ctrl + a chooses all; characters type when no
/// ctrl, alt or super is held. True if it took the key.
pub fn edit_field(field: &mut LineEdit, code: u16, ch: Option<char>, shift: bool, ctrl: bool, plain: bool) -> bool {
    use slate_display::input::{KEY_DELETE, KEY_END, KEY_HOME, KEY_LEFT, KEY_RIGHT};
    use slate_ui::edit::EditKey;
    let k = match (code, ch) {
        (KEY_LEFT, _) => Some(EditKey::Left),
        (KEY_RIGHT, _) => Some(EditKey::Right),
        (KEY_HOME, _) => Some(EditKey::Home),
        (KEY_END, _) => Some(EditKey::End),
        (KEY_BACKSPACE, _) => Some(EditKey::Backspace),
        (KEY_DELETE, _) => Some(EditKey::Delete),
        (_, Some('a' | 'A')) if ctrl => Some(EditKey::SelectAll),
        _ => None,
    };
    match (k, ch.filter(|c| plain && !c.is_control())) {
        (Some(k), _) => {
            field.key(k, shift, ctrl);
            true
        }
        (None, Some(c)) => {
            field.insert(c.encode_utf8(&mut [0u8; 4]));
            true
        }
        _ => false,
    }
}

/// A secret field's dots from `x0` (logical pixels) along `mid`, the
/// selection behind them, and the caret where it is when `caret`.
pub fn draw_dots(p: &mut Painter<'_>, pal: &Palette, x0: f32, mid: f32, field: &LineEdit, caret: bool) -> f32 {
    let n = field.len().min(36);
    if let Some((s, e)) = field.selection() {
        let (s, e) = (s.min(n), e.min(n));
        p.fill(Area::new(x0 - 4.5 + 9.0 * s as f32, mid - 9.0, 9.0 * (e - s) as f32, 18.0), 3.0, pal.raised);
    }
    let d = p.scale;
    for i in 0..n {
        Path::circle(x0 + 9.0 * i as f32, mid, 2.5).fill(p.canvas, &Transform::new(d, 0.0, 0.0), pal.chalk);
    }
    let at = x0 - 5.0 + 9.0 * field.caret().min(n) as f32;
    if caret {
        p.fill(Area::new(at, mid - 10.0, 2.0, 20.0), 0.0, pal.chalk);
    }
    x0 - 4.0 + 9.0 * n as f32
}

impl Lock {
    /// A key: the password to check when Enter is pressed, or switching
    /// person once confirmed.
    pub fn key(&mut self, code: u16, ch: Option<char>, mods: Mods) -> Option<Outcome> {
        let (shift, ctrl, ctrl_alt_logo) = (mods.shift, mods.ctrl, mods.ctrl || mods.alt || mods.logo);
        if self.status == Status::Wrong {
            self.status = Status::Asking;
        }
        match (self.focus, code) {
            (Focus::Confirm, KEY_ENTER | KEY_KPENTER) => return Some(Outcome::SwitchPerson),
            (Focus::Confirm, _) => {
                self.focus = Focus::Password;
                return None;
            }
            (_, KEY_TAB) => {
                self.focus = if self.focus == Focus::Password { Focus::Switch } else { Focus::Password };
                return None;
            }
            (Focus::Switch, KEY_ENTER | KEY_KPENTER) => {
                self.focus = Focus::Confirm;
                return None;
            }
            (Focus::Switch, KEY_ESC) => {
                self.focus = Focus::Password;
                return None;
            }
            (Focus::Switch, _) => return None,
            (_, KEY_ENTER | KEY_KPENTER) => {
                let pw = self.password.text().into_bytes();
                self.password.wipe();
                return Some(Outcome::Check(pw));
            }
            (_, KEY_ESC) => self.password.wipe(),
            _ => {
                edit_field(&mut self.password, code, ch, shift, ctrl, !ctrl_alt_logo);
            }
        }
        None
    }

    /// A click at (x, y), logical pixels: on "Switch person", on
    /// Accessibility (high contrast while locked) or elsewhere.
    pub fn click_at(&mut self, hits: &Hits, x: f32, y: f32) {
        if hits.accessibility.contains(x, y) {
            self.high_contrast = !self.high_contrast;
        } else {
            self.click(hits.switch.contains(x, y));
        }
    }

    /// A click on "Switch person" (`on`) or elsewhere on the screen.
    pub fn click(&mut self, on: bool) {
        self.focus = match (on, self.focus) {
            (true, Focus::Confirm) => Focus::Confirm,
            (true, _) => Focus::Confirm,
            (false, _) => Focus::Password,
        };
    }
}

/// Ask the broker whether `password` is this user's (`check`).
pub fn check(password: &[u8]) -> Result<(), String> {
    let fd =
        net::connect(crate::agent::BROKER).map_err(|e| alloc::format!("the privilege broker is not running ({e})"))?;
    let mut m = b"check\n".to_vec();
    m.extend(password.iter().filter(|&&b| b != b'\n'));
    m.extend_from_slice(b"\n\n");
    let r = io::write_all(fd, &m).and_then(|()| io::read_to_end(fd));
    m.fill(0);
    let _ = io::close(fd);
    let reply = r.map_err(|e| alloc::format!("{e}"))?;
    let line = reply.split(|&c| c == b'\n').next().unwrap_or(&[]);
    if line == b"ok" { Ok(()) } else { Err(String::from(lossy(line.strip_prefix(b"error: ").unwrap_or(line)))) }
}

/// When the column has risen into place, and how long the field shakes
/// after a wrong password (ms; STRATA_ATELIER.md §5).
const RISE_MS: i64 = 200;
const SHAKE_MS: i64 = 160;

/// "sunday · 25 october": the lock screen's date, lowercase.
pub fn date_line(tm: &slate_rt::time::Tm) -> String {
    let mut s = String::new();
    slate_rt::time::format(tm, "%A", &mut s);
    s.push_str(&alloc::format!(" · {} ", tm.day));
    slate_rt::time::format(tm, "%B", &mut s);
    s.to_lowercase()
}

/// A person's initials for the tile: the first letters of the name's
/// first and last words, or the login's first letter.
pub fn initials(name: &str, user: &str) -> String {
    let words: Vec<&str> = name.split_whitespace().collect();
    let first = |w: &str| w.chars().next().map(|c| c.to_uppercase().collect::<String>()).unwrap_or_default();
    match words.as_slice() {
        [] => first(user),
        [one] => first(one),
        [a, .., b] => first(a) + &first(b),
    }
}

/// What the lock screen shows: whose session, the time, the computer, and
/// the person's wallpaper drawn once (the default when None).
#[derive(Clone, Copy, Debug)]
pub struct Screen<'a> {
    pub name: &'a str,
    pub user: &'a str,
    /// "14:32" and "sunday · 25 october".
    pub time: &'a str,
    pub date: &'a str,
    /// The computer's name, top left.
    pub host: &'a str,
    pub network: Option<bool>,
    pub battery: Option<u8>,
    pub wall: Option<&'a Canvas>,
    /// The person's picture ([`crate::faces`]), else their initials.
    pub face: Option<&'a slate_image::Image>,
    /// Now (ms on the monotonic clock), for the motions.
    pub now: i64,
    pub reduced_motion: bool,
}

/// Where the lock screen's buttons are.
#[derive(Clone, Copy, Debug, Default)]
pub struct Hits {
    pub switch: Area,
    pub accessibility: Area,
}

impl Lock {
    /// A lock screen shown at `now` (ms), for its entrance.
    pub fn opened_at(now: i64) -> Lock {
        let mut l = Lock::default();
        l.opened = now;
        l
    }

    /// The password was wrong at `now`: the field shakes.
    pub fn wrong(&mut self, now: i64) {
        self.status = Status::Wrong;
        self.shaken = Some(now);
    }

    /// Whether something still moves at `now`.
    pub fn moving(&self, now: i64, reduced: bool) -> bool {
        !reduced && (now - self.opened < RISE_MS || self.shaken.is_some_and(|t| now - t < SHAKE_MS))
    }

    /// The column's opacity and how far below its place it is.
    fn rise(&self, now: i64, reduced: bool) -> (f32, f32) {
        if reduced {
            return (1.0, 0.0);
        }
        let t = ((now - self.opened) as f32 / RISE_MS as f32).clamp(0.0, 1.0);
        let e = crate::motion::ease_out(t);
        (e, 6.0 * (1.0 - e))
    }

    /// The field's shift: 6 px left, right, then back.
    fn shake(&self, now: i64, reduced: bool) -> f32 {
        match self.shaken {
            Some(at) if !reduced && now - at < SHAKE_MS => {
                let t = (now - at) as f32 / SHAKE_MS as f32;
                -6.0 * slate_ui::icon::sin(t * core::f32::consts::TAU)
            }
            _ => 0.0,
        }
    }
}

/// The screen's scale: positions are for 1440 × 900 (STRATA_ATELIER.md
/// §3.5), and follow the screen's size.
pub fn scale_of(w: f32, h: f32) -> f32 {
    (w / 1440.0).min(h / 900.0).clamp(0.75, 1.5)
}

/// The column's left edge.
pub fn column_x(k: f32) -> f32 {
    round(120.0 * k)
}

/// What the lock, login and unlock screens share behind their column:
/// the wallpaper (`wall`, else the default), the monument, and the header
/// (the mark and `host`; the network and battery when known).
pub fn backdrop(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    wall: Option<&Canvas>,
    host: &str,
    network: Option<bool>,
    battery: Option<u8>,
) {
    let (w, h) = p.size();
    match wall.filter(|c| c.pixels.len() == p.canvas.pixels.len()) {
        Some(c) => p.canvas.pixels.copy_from_slice(&c.pixels),
        None => draw::wallpaper(p, pal, Area::new(0.0, 0.0, w, h)),
    }
    let k = scale_of(w, h);
    // The monument: the mark 620 tall at the right, in outlines, its
    // faces `window`, `well` and `desktop`; in the light variant, whose
    // `window` is far lighter than its desktop, 40% of the way there.
    let size = 620.0 * k;
    let d = p.scale;
    let lift = if pal.light() { 0.4 } else { 1.0 };
    slate_ui::logo::monument(
        p.canvas,
        (w + 40.0 * k - size) * d,
        150.0 * k * d,
        size * d,
        [draw::mix(pal.desktop, pal.window, lift), draw::mix(pal.desktop, pal.well, lift), pal.desktop],
        [pal.contour_top, pal.lineation_accent],
        0.06,
    );
    // The header: the mark and the computer's name; the network and the
    // battery.
    p.logo(48.0, 24.0, 16.0, pal.chalk);
    let st = p.style(&f.mono, 11.5, pal.muted).tracking(0.04);
    p.line(&st, 48.0 + 16.0 + 12.0, 0.0, 64.0, host);
    let mut right = w - 48.0;
    if let Some(level) = battery {
        let st = p.style(&f.regular, 12.5, pal.text_3);
        let pct = alloc::format!("{level}%");
        right -= p.measure(&st, &pct);
        p.line(&st, right, 0.0, 64.0, &pct);
        right -= 5.0 + 16.0;
        slate_ui::icon::battery(p.canvas, right * d, 24.0 * d, 16.0 * d, level, pal.text_3);
        right -= 14.0;
    }
    if let Some(link) = network {
        right -= 14.0;
        p.icon(slate_ui::icon::Icon::Wifi, right, 25.0, 14.0, if link { pal.text_3 } else { pal.decor });
    }
}

/// "slateos", bottom right (decorative).
pub fn signature(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>) {
    let (w, h) = p.size();
    let sig = p.style(&f.mono, 11.0, pal.inactive).tracking(0.08);
    let sw = p.measure(&sig, "slateos");
    p.line(&sig, w - 48.0 - sw, h - 48.0 - 36.0, 36.0, "slateos");
}

/// The date and, 18 px under it, the large clock, at the column's top.
/// Returns where the clock ends.
pub fn date_and_clock(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, k: f32, date: &str, time: &str) -> f32 {
    let x = column_x(k);
    let mut y = round(176.0 * k);
    let st = p.style(&f.mono, 13.0, pal.muted).tracking(0.06);
    p.line(&st, x, y, 18.0, date);
    y += 18.0 + 18.0;
    // Each digit centred in the widest digit's advance, so the time
    // doesn't shift as it changes; nudged left for the optical edge.
    let (size, line) = (208.0 * k, round(179.0 * k));
    let clock = p.style(&f.regular, size, pal.chalk).tracking(-0.065);
    let advance = (0..10).map(|n| p.measure(&clock, &alloc::format!("{n}"))).fold(0.0f32, f32::max);
    let mut cx = x - 10.0 * k;
    for c in time.chars() {
        let mut b = [0u8; 4];
        let t = c.encode_utf8(&mut b);
        let cw = p.measure(&clock, t);
        if c.is_ascii_digit() {
            p.line(&clock, cx + (advance - cw) / 2.0, y, line, t);
            cx += advance;
        } else {
            p.line(&clock, cx, y, line, t);
            cx += cw;
        }
    }
    y + line
}

/// The column's ruled label at `y` ("locked", "log in"): a 64 px chalk
/// stroke, the label, a rule to 560 px wide. Returns where it ends.
pub fn ruled_mark(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, x: f32, y: f32, label: &str) -> f32 {
    let st = p.style(&f.mono, 11.0, pal.text_3).tracking(0.08);
    let mid = y + 9.0;
    p.fill(Area::new(x, mid, 64.0, 1.0), 0.0, pal.chalk);
    let lx = x + 64.0 + 16.0;
    let end = lx + p.line(&st, lx, y, 18.0, label) + 16.0;
    // `active_ws` disappears on the light desktop: `border` there.
    let rule = if pal.light() { pal.border } else { pal.active_ws };
    p.fill(Area::new(end, mid, (x + 560.0 - end).max(0.0), 1.0), 0.0, rule);
    y + 18.0
}

/// A 40 px tile with `initials` (or an icon), a name in Medium 15 and a
/// line in DM Mono 12 `muted` beside it.
#[allow(clippy::too_many_arguments)]
pub fn identity(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    x: f32,
    y: f32,
    tile: Tile<'_>,
    name: &str,
    line: &str,
) {
    let t = Area::new(x, y, 40.0, 40.0);
    p.fill(t, 10.0, pal.raised);
    match tile {
        Tile::Initials(s) => {
            let st = p.style(&f.medium, 14.0, pal.chalk);
            let iw = p.measure(&st, s);
            p.line(&st, t.x + (40.0 - iw) / 2.0, t.y, 40.0, s);
        }
        Tile::Icon(i) => p.icon(i, t.x + 11.0, t.y + 11.0, 18.0, pal.text_3),
        Tile::Face(img) => crate::faces::draw(p, img, t, 10.0),
    }
    let st = p.style(&f.medium, 15.0, pal.chalk);
    p.line(&st, t.right() + 14.0, y + 1.0, 20.0, name);
    let st = p.style(&f.mono, 12.0, pal.muted);
    p.line(&st, t.right() + 14.0, y + 21.0, 18.0, line);
}

/// What an [`identity`] tile shows.
#[derive(Clone, Copy, Debug)]
pub enum Tile<'a> {
    Initials(&'a str),
    Icon(slate_ui::icon::Icon),
    Face(&'a slate_image::Image),
}

/// The column's field, 400 × 46 at (x, y): `well`, the focus ring when
/// `focused`, `dots` dots and an enter glyph at the right (or `text`
/// when given), and the caret when `caret`.
#[allow(clippy::too_many_arguments)]
pub fn column_field(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    x: f32,
    y: f32,
    focused: bool,
    field_text: &LineEdit,
    caret: bool,
) -> Area {
    let field = Area::new(x, y, FIELD_W, 46.0);
    p.fill(field, 10.0, pal.well);
    if focused {
        p.border(field.grow(3.0), 13.0, 3.0, pal.chalk.with_alpha(26));
        p.border(field, 10.0, 1.0, pal.field_focus);
    } else {
        p.border(field, 10.0, 1.0, pal.border);
    }
    let secret = field_text.secret;
    if secret {
        draw_dots(p, pal, field.x + 20.0, field.y + 23.0, field_text, caret);
    } else {
        // Typed text: the selection behind it, the caret where it is.
        let st = p.style(&f.regular, 14.0, pal.chalk);
        let text = field_text.text();
        let upto = |p: &Painter<'_>, n: usize| -> f32 {
            let s: String = text.chars().take(n).collect();
            p.measure(&st, &s)
        };
        let x0 = field.x + 16.0;
        if let Some((a, b)) = field_text.selection() {
            let (xa, xb) = (upto(p, a), upto(p, b));
            p.fill(Area::new(x0 + xa, field.y + 12.0, xb - xa, 22.0), 3.0, pal.raised);
        }
        p.line(&st, x0, field.y, 46.0, &text);
        if caret {
            let cx = x0 + upto(p, field_text.caret()) + 1.0;
            p.fill(Area::new(cx, field.y + 13.0, 2.0, 20.0), 0.0, pal.chalk);
        }
    }
    if secret {
        p.icon(slate_ui::icon::Icon::Enter, field.right() - 16.0 - 12.0, field.y + 17.0, 12.0, pal.muted);
    }
    field
}

/// The column's width: the field's.
pub const FIELD_W: f32 = 400.0;

/// The width of an [`outlined`] button with `label`.
pub fn outlined_width(p: &Painter<'_>, f: &Fonts<'_>, label: &str) -> f32 {
    let st = p.style(&f.medium, 13.0, slate_ui::Color::rgb(0));
    if label.is_empty() { 36.0 } else { 14.0 + 15.0 + 8.0 + p.measure(&st, label) + 16.0 }
}

/// An outlined button at the bottom (36 tall, radius 9): an icon and, if
/// any, a label; chalk when `chosen`.
#[allow(clippy::too_many_arguments)]
pub fn outlined(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    x: f32,
    y: f32,
    icon: slate_ui::icon::Icon,
    label: &str,
    chosen: bool,
) -> Area {
    let (fg, line) = if chosen { (pal.chalk, pal.chalk) } else { (pal.text_3, pal.border_strong) };
    let st = p.style(&f.medium, 13.0, fg);
    let w = outlined_width(p, f, label);
    let a = Area::new(x, y, w, 36.0);
    p.border(a, 9.0, 1.0, line);
    if label.is_empty() {
        p.icon(icon, a.x + 10.0, y + 10.0, 16.0, fg);
    } else {
        p.icon(icon, a.x + 14.0, y + 10.5, 15.0, fg);
        p.line(&st, a.x + 14.0 + 15.0 + 8.0, y, 36.0, label);
    }
    a
}

/// The whole screen (STRATA_ATELIER.md §3.5): no card, the screen itself
/// composed: the wallpaper and the monument, the computer's name, a large
/// clock under the date, a ruled "locked", the person, the field, and the
/// buttons at the bottom left.
pub fn draw(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, s: &Screen<'_>, l: &Lock) -> Hits {
    backdrop(p, pal, f, s.wall, s.host, s.network, s.battery);
    signature(p, pal, f);
    let (w, h) = p.size();
    let k = scale_of(w, h);
    // The column rises and fades in: drawn into a layer while it moves.
    let (opacity, dy) = l.rise(s.now, s.reduced_motion);
    if opacity >= 1.0 {
        column(p, pal, f, s, l, k)
    } else {
        let d = p.scale;
        let mut layer = Canvas::new(p.canvas.width, p.canvas.height, slate_ui::Color::TRANSPARENT);
        let hits = {
            let mut lp = Painter::new(&mut layer, &mut *p.cache, d);
            column(&mut lp, pal, f, s, l, k)
        };
        p.canvas.composite(&layer, opacity, round(dy * d) as i32);
        hits
    }
}

/// The date, the clock, "locked", the person, the field, the status and
/// the buttons.
fn column(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, s: &Screen<'_>, l: &Lock, k: f32) -> Hits {
    let (_, h) = p.size();
    let x = column_x(k);
    let mut y = date_and_clock(p, pal, f, k, s.date, s.time) + 64.0 * k;
    y = ruled_mark(p, pal, f, x, y, "locked") + 28.0;
    let ini = initials(s.name, s.user);
    let tile = s.face.map_or(Tile::Initials(&ini), Tile::Face);
    identity(p, pal, f, x, y, tile, if s.name.is_empty() { s.user } else { s.name }, s.user);
    y += 40.0 + 20.0;
    // The field, shaking after a wrong password.
    let caret = l.status != Status::Working && l.focus == Focus::Password;
    let fx = x + l.shake(s.now, s.reduced_motion);
    column_field(p, pal, f, fx, y, l.focus == Focus::Password, &l.password, caret);
    y += 46.0 + 12.0;
    let (line, colour) = match (l.focus, l.status) {
        (Focus::Confirm, _) => ("Your windows will close. Enter to switch, Esc to stay.", pal.text_1),
        (_, Status::Asking) => ("Enter your password to unlock.", pal.muted),
        (_, Status::Working) => ("Unlocking…", pal.muted),
        (_, Status::Wrong) => ("That password didn't work. Try again.", pal.text_1),
    };
    let st = p.style(&f.regular, 12.5, colour);
    p.line(&st, x, y, 18.0, line);
    // "Switch person" and Accessibility, bottom left.
    let by = h - 48.0 - 36.0;
    let people = slate_ui::icon::Icon::People;
    let switch = outlined(p, pal, f, x, by, people, "Switch person", l.focus != Focus::Password);
    let acc = outlined(p, pal, f, switch.right() + 10.0, by, slate_ui::icon::Icon::Accessibility, "", false);
    Hits { switch, accessibility: acc }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switching_person() {
        let mut l = Lock::default();
        l.key(0, Some('x'), Mods::default());
        // Tab to the button; Enter asks; Esc stays; Enter twice switches.
        l.key(KEY_TAB, None, Mods::default());
        assert_eq!(l.key(0, Some('y'), Mods::default()), None);
        assert_eq!(l.password.text(), "x", "the button types nothing");
        l.key(KEY_ENTER, None, Mods::default());
        assert_eq!(l.focus, Focus::Confirm);
        l.key(KEY_ESC, None, Mods::default());
        assert_eq!(l.focus, Focus::Password);
        l.click(true);
        assert_eq!(l.key(KEY_ENTER, None, Mods::default()), Some(Outcome::SwitchPerson));
    }

    #[test]
    fn date_and_initials() {
        let tm = slate_rt::time::Tm { year: 2026, month: 10, day: 25, weekday: 0, ..Default::default() };
        assert_eq!(date_line(&tm), "sunday · 25 october");
        assert_eq!(initials("Alex Rivera", "alex"), "AR");
        assert_eq!(initials("Ada King Lovelace", "ada"), "AL");
        assert_eq!(initials("", "ada"), "A");
        assert_eq!(initials("ada", "ada"), "A");
    }

    #[test]
    fn motions() {
        let mut l = Lock::opened_at(1000);
        assert!(l.moving(1100, false));
        assert!(!l.moving(1100, true), "reduced motion: nothing moves");
        assert!(!l.moving(1200, false));
        assert_eq!(l.rise(1200, false), (1.0, 0.0));
        l.wrong(5000);
        assert_eq!(l.status, Status::Wrong);
        assert!(l.moving(5100, false));
        assert!(l.shake(5040, false) < -5.0, "a quarter in, 6 px left");
        assert_eq!(l.shake(5200, false), 0.0);
    }

    #[test]
    fn keys() {
        let mut l = Lock::default();
        for c in "pw é".chars() {
            assert_eq!(l.key(0, Some(c), Mods::default()), None);
        }
        assert_eq!(l.password.len(), 4);
        l.key(KEY_BACKSPACE, None, Mods::default());
        assert_eq!(l.password.text(), "pw ");
        // The caret moves (ADR 0101): a letter typed before the space.
        l.key(slate_display::input::KEY_LEFT, None, Mods::default());
        l.key(0, Some('d'), Mods::default());
        l.key(slate_display::input::KEY_END, None, Mods::default());
        l.key(KEY_BACKSPACE, None, Mods::default());
        assert_eq!(l.password.text(), "pwd");
        // Shortcuts type nothing.
        l.key(0, Some('q'), Mods { ctrl: true, ..Mods::default() });
        assert_eq!(l.key(KEY_ENTER, None, Mods::default()), Some(Outcome::Check(b"pwd".to_vec())));
        assert!(l.password.is_empty());
        l.status = Status::Wrong;
        l.key(0, Some('x'), Mods::default());
        assert_eq!(l.status, Status::Asking);
        l.key(KEY_ESC, None, Mods::default());
        assert!(l.password.is_empty());
    }
}
