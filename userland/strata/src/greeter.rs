// SPDX-License-Identifier: MIT OR Apache-2.0

//! `strata-login`, the graphical login screen (ADR 0038). getty starts it
//! on the console as the unprivileged `greeter` user where Strata is
//! installed. It draws the computer's name, the people who can log in,
//! the password field, the clock, and Restart and Power off, composed as
//! the lock screen is (Atelier, ADR 0124), on a seat
//! from seatd; it also takes a login typed on the console (the serial
//! line), as getty would. ADR 0039: the list scrolls; its last row,
//! "Someone else", asks for a name; Restart and Power off ask before
//! acting; Accessibility switches to high contrast.
//!
//! It never reads /etc/shadow: the privilege broker checks the password
//! (`login`) and, once this program has let go of the display (`start`),
//! starts the person's session on the console; when that ends (`ended`)
//! this program exits, and getty starts it again. Without a display, a
//! seat, its fonts or anyone to log in, it exits with 3 and getty asks on
//! the text console instead.

use alloc::string::String;
use alloc::vec::Vec;

use slate_display::input::{Input, Inputs, KEY_DOWN, KEY_ENTER, KEY_ESC, KEY_KPENTER, KEY_TAB, KEY_UP};
use slate_display::kms::Display;
use slate_display::seat::Seat;
use slate_rt::{fs, io, lossy, net, term};
use slate_ui::Canvas;
use slate_ui::edit::LineEdit;
use slate_ui::graphite::Palette;
use slate_ui::icon::Icon;
use slate_ui::paint::Painter;
use slate_ui::text::GlyphCache;
use slate_ui::ui::{Area, Event};

use crate::fonts::Fonts;
use crate::session::{load_fonts, local_now, scale_for};

/// getty's cue to ask on the text console (slate-login's `NO_SCREEN`).
pub const NO_SCREEN: i32 = 3;
/// The broker's socket (an abstract name; slate-login's `broker::SOCKET`).
const BROKER: &[u8] = b"slate-broker";

/// Someone who can log in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Person {
    pub name: String,
    /// The comment field's first part, or the name.
    pub full_name: String,
    pub uid: u32,
    /// Their picture ([`crate::faces`]), else their initials show.
    pub face: Option<slate_image::Image>,
}

/// The people in /etc/passwd who can log in: user IDs from 1000, with a
/// shell that isn't nologin or false (passwd(5)).
pub fn people(passwd: &str) -> Vec<Person> {
    passwd
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            let [name, _, uid, _, gecos, _, shell] = f[..] else { return None };
            let uid: u32 = uid.parse().ok()?;
            let closed = shell.ends_with("nologin") || shell.ends_with("false");
            if uid < 1000 || uid == 65534 || closed || name.is_empty() {
                return None;
            }
            let full = gecos.split(',').next().unwrap_or("").trim();
            Some(Person {
                name: name.into(),
                full_name: if full.is_empty() { name.into() } else { full.into() },
                uid,
                face: None,
            })
        })
        .collect()
}

/// What the line under the field says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Asking,
    Working,
    /// The broker's answer to a failed login.
    Refused(String),
}

/// Which field has the keys.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Focus {
    /// The name field ("Someone else").
    Name,
    #[default]
    Password,
    /// The new password and its confirmation, when the old has expired.
    New,
    Confirm,
}

/// A restart or power-off waiting for its confirmation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confirm {
    Restart,
    PowerOff,
}

/// The login screen's state, for drawing.
#[derive(Clone, Copy, Debug)]
pub struct View<'a> {
    pub host: &'a str,
    pub people: &'a [Person],
    /// Index into `people`, or `people.len()` for "Someone else".
    pub selected: usize,
    /// The first row shown.
    pub first: usize,
    /// The name typed for "Someone else", and the password (ADR 0101's
    /// line editor: the caret moves).
    pub name: &'a LineEdit,
    pub focus: Focus,
    pub password: &'a LineEdit,
    pub status: &'a Status,
    /// "14:32" and "sunday · 25 october".
    pub time: &'a str,
    pub date: &'a str,
    pub confirm: Option<Confirm>,
    /// The password has expired: the new one and its confirmation.
    pub change: Option<(&'a LineEdit, &'a LineEdit)>,
}

impl View<'_> {
    fn someone_else(&self) -> bool {
        self.selected >= self.people.len()
    }
}

/// Where the screen's controls are.
#[derive(Clone, Debug, Default)]
pub struct Hits {
    /// Each row shown, with its index (`people.len()`: someone else).
    pub people: Vec<(usize, Area)>,
    pub name: Option<Area>,
    pub password: Area,
    /// The new password's fields, when asking for one.
    pub new_password: Option<Area>,
    pub confirm_password: Option<Area>,
    pub restart: Area,
    pub power_off: Area,
    pub accessibility: Area,
    /// The confirmation's buttons.
    pub cancel: Option<Area>,
    pub confirm: Option<Area>,
}

/// The first row to show so that `selected` is in view, of `rows`.
pub fn first_shown(first: usize, selected: usize, rows: usize) -> usize {
    first_shown_in(first, selected, rows, rows.min(MAX_LISTED))
}

/// The same, with `visible` rows shown.
pub fn first_shown_in(first: usize, selected: usize, rows: usize, visible: usize) -> usize {
    let visible = visible.clamp(1, rows);
    let first = first.min(rows - visible);
    if selected < first {
        selected
    } else if selected >= first + visible {
        selected + 1 - visible
    } else {
        first
    }
}

const ROW_H: f32 = 48.0;
/// At most this many rows show; the list scrolls. Fewer show when the
/// screen has no room for them.
pub const MAX_LISTED: usize = 5;

/// A person's row: the initial in a tile, the full name and the user
/// name; inverted when selected (docs/design/WM_STYLE.md §5).
fn person_row(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area, who: &Person, selected: bool) {
    let dark = pal.desktop;
    if selected {
        p.fill(a, 10.0, pal.chalk);
    }
    let tile = Area::new(a.x + 8.0, a.y + 8.0, 32.0, 32.0);
    p.fill(tile, 8.0, if selected { pal.selected_tile } else { pal.raised });
    match &who.face {
        Some(img) => crate::faces::draw(p, img, tile, 8.0),
        None => {
            let initials = crate::lock::initials(&who.full_name, &who.name);
            let st = p.style(&f.medium, 13.0, if selected { dark } else { pal.chalk });
            let w = p.measure(&st, &initials);
            p.line(&st, tile.x + (32.0 - w) / 2.0, tile.y, 32.0, &initials);
        }
    }
    let name = p.style(&f.medium, 14.0, if selected { dark } else { pal.text_1 });
    p.line(&name, a.x + 52.0, a.y + 6.0, 20.0, &who.full_name);
    let user = p.style(&f.mono, 11.5, if selected { pal.selected_meta } else { pal.muted });
    p.line(&user, a.x + 52.0, a.y + 25.0, 16.0, &who.name);
}

/// The "Someone else" row: a tile with a plus, the words.
fn someone_else_row(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area, selected: bool) {
    let dark = pal.desktop;
    if selected {
        p.fill(a, 10.0, pal.chalk);
    }
    let tile = Area::new(a.x + 8.0, a.y + 8.0, 32.0, 32.0);
    p.fill(tile, 8.0, if selected { pal.selected_tile } else { pal.raised });
    let mark = if selected { dark } else { pal.text_3 };
    p.fill(Area::new(tile.x + 10.0, tile.y + 15.0, 12.0, 2.0), 0.0, mark);
    p.fill(Area::new(tile.x + 15.0, tile.y + 10.0, 2.0, 12.0), 0.0, mark);
    let name = p.style(&f.medium, 14.0, if selected { dark } else { pal.text_1 });
    p.line(&name, a.x + 52.0, a.y, ROW_H, "Someone else");
}

/// Draw the whole screen: the lock screen's composition (ADR 0124), the
/// people where the lock screen has the person.
/// The login screen's backdrop alone (the default wallpaper, the mark, the
/// computer's name): what it leaves when a login succeeds, and what
/// Strata's desktop fades in from (ADR 0186).
pub fn backdrop_canvas(
    pal: &Palette,
    f: &Fonts<'_>,
    host: &str,
    w: i32,
    h: i32,
    scale: f32,
    cache: &mut GlyphCache,
) -> Canvas {
    let mut c = Canvas::new(w, h, pal.desktop);
    let mut p = Painter::new(&mut c, cache, scale);
    crate::lock::backdrop(&mut p, pal, f, None, host, None, None);
    c
}

/// The login screen's first frame `first` fading in from a screen of
/// `colour`, in about 200 ms (at once with reduced motion).
fn fade_in(d: &mut Display, first: &Canvas, colour: slate_ui::Color) {
    if !crate::settings::Settings::system().reduced_motion {
        let mut c = Canvas::new(first.width, first.height, colour);
        let plain = Canvas::new(first.width, first.height, colour);
        const STEPS: u32 = 12;
        for i in 1..STEPS {
            let t = crate::motion::ease_out(i as f32 / STEPS as f32);
            c.pixels.copy_from_slice(&plain.pixels);
            c.composite(first, t, 0);
            d.present(&c.pixels);
            slate_rt::time::sleep_ns(16_000_000);
        }
    }
    d.present(&first.pixels);
}

/// The login screen's last frame `last` fading to its backdrop, in about
/// 200 ms (at once with reduced motion).
fn fade_to_backdrop(
    d: &mut Display,
    last: Canvas,
    pal: &Palette,
    f: &Fonts<'_>,
    host: &str,
    scale: f32,
    cache: &mut GlyphCache,
) {
    if crate::settings::Settings::system().reduced_motion {
        return;
    }
    let back = backdrop_canvas(pal, f, host, last.width, last.height, scale, cache);
    let mut c = Canvas::new(last.width, last.height, pal.desktop);
    const STEPS: u32 = 12;
    for i in 1..=STEPS {
        let t = crate::motion::ease_out(i as f32 / STEPS as f32);
        c.pixels.copy_from_slice(&back.pixels);
        c.composite(&last, 1.0 - t, 0);
        d.present(&c.pixels);
        slate_rt::time::sleep_ns(16_000_000);
    }
}

pub fn draw(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, v: &View<'_>) -> Hits {
    use crate::lock::{self, FIELD_W};
    let (w, h) = p.size();
    lock::backdrop(p, pal, f, None, v.host, None, None);
    let k = lock::scale_of(w, h);
    let x = lock::column_x(k);
    let mut y = lock::date_and_clock(p, pal, f, k, v.date, v.time) + 40.0 * k;
    y = lock::ruled_mark(p, pal, f, x, y, "log in") + 20.0;
    // As many rows as fit above the buttons, with the fields under them.
    let rows = v.people.len() + 1;
    let bottom = h - 48.0 - 36.0;
    let labelled = 18.0 + 8.0 + 46.0 + 12.0;
    let fields = 18.0
        + if v.someone_else() { labelled } else { 0.0 }
        + if v.change.is_some() { 2.0 * labelled } else { 46.0 + 12.0 }
        + 18.0
        + 24.0;
    let room = bottom - y - fields;
    let fit = |extra: f32| (((room - extra) / ROW_H) as usize).max(1);
    let mut listed = rows.min(MAX_LISTED).min(fit(0.0));
    if listed < rows {
        listed = rows.min(MAX_LISTED).min(fit(22.0));
    }
    let more = rows > listed;
    let mut hits = Hits::default();
    let first = first_shown_in(v.first, v.selected, rows, listed);
    for i in first..first + listed {
        let row = Area::new(x, y, FIELD_W, ROW_H);
        match v.people.get(i) {
            Some(who) => person_row(p, pal, f, row, who, i == v.selected),
            None => someone_else_row(p, pal, f, row, v.someone_else()),
        }
        hits.people.push((i, row));
        y += ROW_H;
    }
    if more {
        // Where the list goes on.
        let st = p.style(&f.mono, 11.0, pal.muted);
        let above = if first > 0 { "more above" } else { "" };
        let below = if first + listed < rows { "more below" } else { "" };
        p.line(&st, x + 8.0, y + 2.0, 18.0, above);
        let bw = p.measure(&st, below);
        p.line(&st, x + FIELD_W - 8.0 - bw, y + 2.0, 18.0, below);
        y += 22.0;
    }
    y += 18.0;
    let working = *v.status == Status::Working;
    if v.someone_else() {
        let label = p.style(&f.medium, 12.5, pal.text_3);
        p.line(&label, x, y, 18.0, "Name");
        y += 18.0 + 8.0;
        let focused = v.focus == Focus::Name;
        hits.name = Some(lock::column_field(p, pal, f, x, y, focused, v.name, focused && !working));
        y += 46.0 + 12.0;
    }
    if let Some((new, again)) = v.change {
        // The old password was right but has expired (shadow(5)).
        for (label, field, which) in
            [("New password", new, Focus::New), ("Confirm new password", again, Focus::Confirm)]
        {
            let st = p.style(&f.medium, 12.5, pal.text_3);
            p.line(&st, x, y, 18.0, label);
            y += 18.0 + 8.0;
            let focused = v.focus == which;
            let a = lock::column_field(p, pal, f, x, y, focused, field, focused && !working);
            if which == Focus::New {
                hits.new_password = Some(a);
            } else {
                hits.confirm_password = Some(a);
            }
            y += 46.0 + 12.0;
        }
    } else {
        let pw_focus = v.focus == Focus::Password || !v.someone_else();
        hits.password = lock::column_field(p, pal, f, x, y, pw_focus, v.password, pw_focus && !working);
        y += 46.0 + 12.0;
    }
    let (line, colour) = match v.status {
        Status::Asking if v.change.is_some() => ("Your password has expired. Choose a new one.", pal.text_1),
        Status::Asking => ("Enter your password and press Enter.", pal.muted),
        Status::Working => ("Logging in…", pal.muted),
        Status::Refused(why) => (why.as_str(), pal.text_1),
    };
    let st = p.style(&f.regular, 12.5, colour);
    p.line(&st, x, y, 18.0, line);
    // Accessibility, bottom left; Restart and Power off, bottom right, or
    // the question one of them asks.
    hits.accessibility = lock::outlined(p, pal, f, x, bottom, Icon::Accessibility, "Accessibility", false);
    let right = |p: &Painter<'_>, edge: f32, label: &str| edge - lock::outlined_width(p, f, label);
    match v.confirm {
        None => {
            let px = right(p, w - 48.0, "Power off");
            hits.power_off = lock::outlined(p, pal, f, px, bottom, Icon::Power, "Power off", false);
            let rx = right(p, px - 10.0, "Restart");
            hits.restart = lock::outlined(p, pal, f, rx, bottom, Icon::Undo, "Restart", false);
        }
        Some(c) => {
            let (q, yes, icon) = match c {
                Confirm::Restart => ("Restart now?", "Restart", Icon::Undo),
                Confirm::PowerOff => ("Power off now?", "Power off", Icon::Power),
            };
            let ox = right(p, w - 48.0, yes);
            let ok = lock::outlined(p, pal, f, ox, bottom, icon, yes, true);
            let nx = right(p, ox - 10.0, "Cancel");
            let no = lock::outlined(p, pal, f, nx, bottom, Icon::Close, "Cancel", false);
            let st = p.style(&f.medium, 13.0, pal.text_1);
            let qw = p.measure(&st, q);
            p.line(&st, no.x - 16.0 - qw, bottom, 36.0, q);
            hits.confirm = Some(ok);
            hits.cancel = Some(no);
        }
    }
    hits
}

/// The broker's first answer: Ok, or its message.
fn ask_broker(fd: i32, fields: &[&[u8]]) -> Result<(), String> {
    let mut msg = fields.join(&b'\n');
    msg.extend_from_slice(b"\n\n");
    io::write_all(fd, &msg).map_err(|e| alloc::format!("talking to the privilege broker: {e}"))?;
    let mut reply = Vec::new();
    let mut b = [0u8; 256];
    while !reply.contains(&b'\n') {
        match io::read(fd, &mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => reply.extend_from_slice(&b[..n]),
        }
    }
    let line = reply.split(|&c| c == b'\n').next().unwrap_or(&[]);
    if line == b"ok" { Ok(()) } else { Err(String::from(lossy(line.strip_prefix(b"error: ").unwrap_or(line)))) }
}

fn connect_broker() -> Result<i32, String> {
    net::connect(BROKER).map_err(|e| alloc::format!("cannot reach the privilege broker ({e})"))
}

/// The screen: the display, and the input devices with the seat they
/// come from. Dropping it gives everything back to seatd.
struct Screen {
    display: Display,
    inputs: Inputs,
}

impl Screen {
    fn open() -> Result<Screen, String> {
        let mut seat = Seat::open()?;
        let fd = seat.open_device(&slate_display::kms::card())?;
        let display = Display::from_fd(fd)?;
        let mut inputs = Inputs::with_seat(display.width, display.height, Some(seat));
        // The layout chosen at install, with which the password was typed.
        inputs.layout = slate_display::input::system_layout();
        Ok(Screen { display, inputs })
    }
}

pub fn hostname() -> String {
    let h = fs::read_file(b"/etc/hostname").map(|b| String::from(lossy(&b).trim())).unwrap_or_default();
    if h.is_empty() { String::from("slate") } else { h }
}

/// Where the console's own login is.
enum Console {
    Name,
    Password(String),
    /// The password expired: who, the old one, and the new one once typed.
    New(String, Vec<u8>),
    Retype(String, Vec<u8>, Vec<u8>),
}

/// A login on the screen waiting for its new password: who, and the old
/// password.
struct Expired {
    who: String,
    old: Vec<u8>,
}

/// A login to try: who, the password, whether it was typed on the
/// screen, and the new password for an expired one.
type Attempt = (String, Vec<u8>, bool, Option<Vec<u8>>);

/// The broker's answer when the password is right but has expired
/// (`slate_login::broker::EXPIRED`).
const EXPIRED: &str = "Your password has expired. Choose a new one.";

fn console_prompt(text: &str, echo: bool) {
    if let Ok(mut t) = term::get(0) {
        if echo {
            t.lflag |= term::ECHO;
        } else {
            t.lflag &= !term::ECHO;
        }
        t.lflag |= term::ICANON;
        let _ = term::set(0, &t, true);
    }
    io::flush_stdout();
    let _ = io::write_all(1, text.as_bytes());
}

pub fn main() -> i32 {
    let passwd = String::from(lossy(&fs::read_file(b"/etc/passwd").unwrap_or_default()));
    let mut people = people(&passwd);
    for who in &mut people {
        who.face = crate::faces::load(&who.name, who.uid);
    }
    if people.is_empty() {
        slate_rt::eprintln!("strata-login: no one to log in; the text login instead");
        return NO_SCREEN;
    }
    let files = match load_fonts() {
        Ok(f) => f,
        Err(e) => {
            slate_rt::eprintln!("strata-login: {e}; the text login instead");
            return NO_SCREEN;
        }
    };
    let refs: [&[u8]; 5] = core::array::from_fn(|i| files[i].as_slice());
    let Some(fonts) = Fonts::new(refs) else { return NO_SCREEN };
    let screen = match Screen::open() {
        Ok(s) => s,
        Err(e) => {
            slate_rt::eprintln!("strata-login: no display ({e}); the text login instead");
            return NO_SCREEN;
        }
    };
    match run(&fonts, &people, screen) {
        Ok(()) => 0,
        Err(e) => {
            slate_rt::eprintln!("strata-login: {e}");
            1
        }
    }
}

fn run(fonts: &Fonts<'_>, people: &[Person], screen: Screen) -> Result<(), String> {
    let host = hostname();
    let mut screen = Some(screen);
    let (w, h) = screen.as_ref().map_or((0, 0), |s| (s.display.width, s.display.height));
    let scale = scale_for(w, h);
    let mut cache = GlyphCache::new();
    let mut selected = 0usize;
    let mut first = 0usize;
    let mut name = LineEdit::new("").with_max(32);
    let mut focus = Focus::Password;
    let mut confirm: Option<Confirm> = None;
    let mut high_contrast = crate::session::cmdline_word("slate.contrast=").is_some_and(|v| v == "high");
    let mut password = LineEdit::new("").with_max(256).secret();
    let mut new_pw = LineEdit::new("").with_max(256).secret();
    let mut again_pw = LineEdit::new("").with_max(256).secret();
    let mut expired: Option<Expired> = None;
    let mut status = Status::Asking;
    let mut console = Console::Name;
    let mut line: Vec<u8> = Vec::new();
    let mut hits = Hits::default();
    let (mut shown_time, mut shown_date) = (String::new(), String::new());
    // The time zone, worked out again when its files change.
    let mut zone = crate::watch::Watcher::new(b"", crate::watch::ZONE);
    let mut dirty = true;
    // Whether the login screen has been shown (its first frame fades in).
    let mut shown_once = false;
    let rows = people.len() + 1;
    slate_rt::eprintln!("strata-login: showing the login screen ({} to choose from)", people.len());
    console_prompt(&alloc::format!("\n{host} login: "), true);
    loop {
        if (zone.retry() | zone.read()) != 0 {
            crate::session::zone_changed();
        }
        crate::session::zone_watched(zone.unwatched() == 0);
        let tm = local_now();
        let mut now_time = String::new();
        slate_rt::time::format(&tm, "%H:%M", &mut now_time);
        if now_time != shown_time {
            shown_time = now_time;
            shown_date = crate::lock::date_line(&tm);
            dirty = true;
        }
        let pal = if high_contrast { Palette::HIGH_CONTRAST } else { Palette::GRAPHITE };
        first = first_shown(first, selected, rows);
        if dirty && let Some(s) = screen.as_mut() {
            let mut c = Canvas::new(w, h, pal.desktop);
            let mut p = Painter::new(&mut c, &mut cache, scale);
            let v = View {
                host: &host,
                people,
                selected,
                first,
                name: &name,
                focus,
                password: &password,
                status: &status,
                time: &shown_time,
                date: &shown_date,
                confirm,
                change: expired.as_ref().map(|_| (&new_pw, &again_pw)),
            };
            hits = draw(&mut p, &pal, fonts, &v);
            // The first frame fades in from the boot splash's colour, the
            // desktop's graphite (ADR 0186).
            if shown_once {
                s.display.present(&c.pixels);
            } else {
                shown_once = true;
                fade_in(&mut s.display, &c, Palette::GRAPHITE.desktop);
            }
            dirty = false;
        }
        let mut con = alloc::vec![io::PollFd { fd: 0, events: io::POLLIN, revents: 0 }];
        if let Some(fd) = zone.fd() {
            con.push(io::PollFd { fd, events: io::POLLIN, revents: 0 });
        }
        let inputs = match screen.as_mut() {
            Some(s) => s.inputs.wait_input_with(1000, &mut con),
            None => Vec::new(),
        };
        let someone_else = |sel: usize| sel >= people.len();
        // Move to row `to`: its field takes the keys.
        let choose = |to: usize, name_empty: bool, selected: &mut usize, focus: &mut Focus, password: &mut LineEdit| {
            if to != *selected {
                *selected = to;
                password.wipe();
            }
            *focus = if someone_else(to) && name_empty { Focus::Name } else { Focus::Password };
        };
        // A login to try: who, the password, whether it was typed on the
        // screen, and a new password for an expired one; or a power action.
        let mut attempt: Option<Attempt> = None;
        let mut act: Option<Confirm> = None;
        for i in inputs {
            dirty = true;
            match i {
                // A question waits for its answer.
                Input::Key { code, .. } if confirm.is_some() => match code {
                    KEY_ENTER | KEY_KPENTER => act = confirm.take(),
                    KEY_ESC => confirm = None,
                    _ => {}
                },
                Input::Key { code, ch, mods, .. } if expired.is_some() => {
                    if matches!(status, Status::Refused(_)) {
                        status = Status::Asking;
                    }
                    match code {
                        KEY_TAB => focus = if focus == Focus::New { Focus::Confirm } else { Focus::New },
                        KEY_ENTER | KEY_KPENTER if focus == Focus::New => {
                            if !new_pw.is_empty() {
                                focus = Focus::Confirm;
                            }
                        }
                        KEY_ENTER | KEY_KPENTER => {
                            if new_pw.text() != again_pw.text() {
                                status = Status::Refused(String::from("The new passwords don't match. Try again."));
                                new_pw.wipe();
                                again_pw.wipe();
                                focus = Focus::New;
                            } else if let Some(e) = expired.take() {
                                attempt = Some((e.who, e.old, true, Some(new_pw.text().into_bytes())));
                                new_pw.wipe();
                                again_pw.wipe();
                                focus = Focus::Password;
                            }
                        }
                        // Escape gives up: back to the password.
                        KEY_ESC => {
                            expired = None;
                            new_pw.wipe();
                            again_pw.wipe();
                            focus = Focus::Password;
                        }
                        _ => {
                            let plain = !mods.ctrl && !mods.alt && !mods.logo;
                            let field = if focus == Focus::New { &mut new_pw } else { &mut again_pw };
                            crate::lock::edit_field(field, code, ch, mods.shift, mods.ctrl, plain);
                        }
                    }
                }
                Input::Key { code, ch, mods, .. } => {
                    if matches!(status, Status::Refused(_)) {
                        status = Status::Asking;
                    }
                    let typing_name = someone_else(selected) && focus == Focus::Name;
                    match code {
                        KEY_TAB if someone_else(selected) => {
                            focus = if focus == Focus::Name { Focus::Password } else { Focus::Name };
                        }
                        KEY_ENTER | KEY_KPENTER if typing_name => {
                            if !name.is_empty() {
                                focus = Focus::Password;
                            }
                        }
                        KEY_ENTER | KEY_KPENTER => {
                            let who = if someone_else(selected) { name.text() } else { people[selected].name.clone() };
                            if !who.is_empty() {
                                attempt = Some((who, password.text().into_bytes(), true, None));
                                password.wipe();
                            }
                        }
                        KEY_ESC => password.wipe(),
                        KEY_UP => choose(
                            selected.saturating_sub(1),
                            name.is_empty(),
                            &mut selected,
                            &mut focus,
                            &mut password,
                        ),
                        KEY_DOWN => choose(
                            (selected + 1).min(rows - 1),
                            name.is_empty(),
                            &mut selected,
                            &mut focus,
                            &mut password,
                        ),
                        _ => {
                            let plain = !mods.ctrl && !mods.alt && !mods.logo;
                            if typing_name {
                                // A login name: letters, digits, `.`, `_`, `-`.
                                let ch =
                                    ch.filter(|c| c.is_ascii_alphanumeric() || "._-".contains(*c) || c.is_control());
                                crate::lock::edit_field(&mut name, code, ch, mods.shift, mods.ctrl, plain);
                            } else {
                                crate::lock::edit_field(&mut password, code, ch, mods.shift, mods.ctrl, plain);
                            }
                        }
                    }
                }
                Input::Wheel { lines, .. } => {
                    let to = if lines < 0 { selected.saturating_sub(1) } else { (selected + 1).min(rows - 1) };
                    choose(to, name.is_empty(), &mut selected, &mut focus, &mut password);
                }
                Input::Pointer(Event::PointerDown(px, py)) => {
                    let (x, y) = (px / scale, py / scale);
                    if hits.new_password.is_some_and(|a| a.contains(x, y)) {
                        focus = Focus::New;
                    } else if hits.confirm_password.is_some_and(|a| a.contains(x, y)) {
                        focus = Focus::Confirm;
                    } else if expired.is_some() {
                        // The list waits while a new password is asked for.
                    } else if let Some(&(i, _)) = hits.people.iter().find(|(_, a)| a.contains(x, y)) {
                        choose(i, name.is_empty(), &mut selected, &mut focus, &mut password);
                    } else if hits.name.is_some_and(|a| a.contains(x, y)) {
                        focus = Focus::Name;
                    } else if hits.password.contains(x, y) {
                        focus = Focus::Password;
                    } else if hits.accessibility.contains(x, y) {
                        high_contrast = !high_contrast;
                    } else if hits.cancel.is_some_and(|a| a.contains(x, y)) {
                        confirm = None;
                    } else if hits.confirm.is_some_and(|a| a.contains(x, y)) {
                        act = confirm.take();
                    } else if confirm.is_none() && hits.restart.contains(x, y) {
                        confirm = Some(Confirm::Restart);
                    } else if confirm.is_none() && hits.power_off.contains(x, y) {
                        confirm = Some(Confirm::PowerOff);
                    }
                }
                _ => {}
            }
        }
        if let Some(c) = act {
            let what: &[u8] = if c == Confirm::Restart { b"restart" } else { b"poweroff" };
            slate_rt::eprintln!("strata-login: {}", if c == Confirm::Restart { "restarting" } else { "powering off" });
            let fd = connect_broker()?;
            let r = ask_broker(fd, &[b"action", what]);
            let _ = io::close(fd);
            if let Err(e) = r {
                status = Status::Refused(e);
            }
        }
        // The console's own login, line by line.
        if con[0].revents != 0 {
            let mut b = [0u8; 256];
            if let Ok(n) = io::read(0, &mut b)
                && n > 0
            {
                line.extend_from_slice(&b[..n]);
            }
            while let Some(end) = line.iter().position(|&c| c == b'\n' || c == b'\r') {
                let typed: Vec<u8> = line.drain(..=end).take(end).collect();
                match core::mem::replace(&mut console, Console::Name) {
                    Console::Name if typed.is_empty() => console_prompt(&alloc::format!("{host} login: "), true),
                    Console::Name => {
                        console = Console::Password(String::from(lossy(&typed)));
                        console_prompt("Password: ", false);
                    }
                    Console::Password(who) => {
                        let _ = io::write_all(1, b"\n");
                        attempt = Some((who, typed, false, None));
                    }
                    Console::New(who, old) => {
                        let _ = io::write_all(1, b"\n");
                        console = Console::Retype(who, old, typed);
                        console_prompt("Retype new password: ", false);
                    }
                    Console::Retype(who, old, new) => {
                        let _ = io::write_all(1, b"\n");
                        if new == typed && !new.is_empty() {
                            attempt = Some((who, old, false, Some(new)));
                        } else {
                            let _ = io::write_all(1, b"Sorry, passwords do not match.\n");
                            console = Console::New(who, old);
                            console_prompt("New password: ", false);
                        }
                    }
                }
            }
        }
        let Some((who, mut pw, on_screen, mut new)) = attempt else { continue };
        let mut last_frame: Option<Canvas> = None;
        status = Status::Working;
        if let Some(s) = screen.as_mut() {
            let mut c = Canvas::new(w, h, pal.desktop);
            let mut p = Painter::new(&mut c, &mut cache, scale);
            let v = View {
                host: &host,
                people,
                selected,
                first,
                name: &name,
                focus,
                password: &password,
                status: &status,
                time: &shown_time,
                date: &shown_date,
                confirm: None,
                change: None,
            };
            draw(&mut p, &pal, fonts, &v);
            s.display.present(&c.pixels);
            last_frame = Some(c);
        }
        let fd = connect_broker()?;
        // A login on the screen is Strata alone; one typed on the console
        // keeps its shell for super + shift + e (ADR 0039).
        let how: &[u8] = if on_screen { b"screen" } else { b"console" };
        let r = match &new {
            Some(n) => ask_broker(fd, &[b"login", who.as_bytes(), &pw, how, &[b"n".as_slice(), n].concat()]),
            None => ask_broker(fd, &[b"login", who.as_bytes(), &pw, how]),
        };
        if let Some(n) = new.as_mut() {
            n.fill(0);
        }
        match r {
            Ok(()) => {
                pw.fill(0);
                // The column fades away, leaving the backdrop the
                // desktop fades in from (ADR 0186).
                if let (Some(sc), Some(c)) = (screen.as_mut(), last_frame.take()) {
                    fade_to_backdrop(&mut sc.display, c, &pal, fonts, &host, scale, &mut cache);
                }
                // Let go of the display and the input devices, then the
                // broker starts the session. One on the screen goes to a
                // virtual console of its own (ADR 0185): this login screen
                // ends, and getty starts a fresh one, which waits on the
                // first virtual console for "Switch person". One on the
                // console waits for the session to end.
                drop(screen.take());
                slate_rt::eprintln!("strata-login: session for {who}");
                let started = io::write_all(fd, b"start\n\n");
                let mut b = [0u8; 64];
                while !on_screen && started.is_ok() && matches!(io::read(fd, &mut b), Ok(n) if n > 0) {}
                let _ = io::close(fd);
                return Ok(());
            }
            // Their session is running (switched away from): the broker
            // brings it to the front once this login screen has gone; its
            // lock screen asks for the password.
            Err(e) if e.starts_with("switch ") => {
                pw.fill(0);
                drop(screen.take());
                slate_rt::eprintln!("strata-login: back to {who}'s session");
                let _ = io::close(fd);
                return Ok(());
            }
            Err(e) if e == EXPIRED => {
                // Right, but expired: ask for a new one, keeping the old.
                let _ = io::close(fd);
                slate_rt::eprintln!("strata-login: {who}: the password has expired");
                status = Status::Asking;
                if on_screen {
                    expired = Some(Expired { who, old: pw });
                    focus = Focus::New;
                } else {
                    let _ =
                        io::write_all(1, b"You are required to change your password immediately (password expired).\n");
                    console = Console::New(who, pw);
                    console_prompt("New password: ", false);
                }
                dirty = true;
            }
            Err(e) => {
                pw.fill(0);
                let _ = io::close(fd);
                slate_rt::eprintln!("strata-login: {who}: {e}");
                let _ = io::write_all(1, b"\nLogin incorrect\n");
                console_prompt(&alloc::format!("{host} login: "), true);
                status = Status::Refused(if e == "Login incorrect" {
                    String::from("That password didn't work. Try again.")
                } else {
                    e
                });
                dirty = true;
            }
        }
    }
}
