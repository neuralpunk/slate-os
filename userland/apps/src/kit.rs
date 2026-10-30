// SPDX-License-Identifier: MIT OR Apache-2.0

//! What Slate's apps share (ADR 0104): Strata's fonts and colours (the
//! person's settings, followed as they change, as the shortcuts app
//! does), and the loop that draws a window and hands it keys, clicks,
//! the wheel and pastes. An app is an [`App`]: it draws itself, says what
//! an event did ([`Effect`]), and when it wants to be drawn again without
//! one (a running stopwatch).

use alloc::string::String;
use alloc::vec::Vec;

use slate_strata::fonts::Fonts;
use slate_strata::settings::{self, Settings};
use slate_strata_client::{Connection, Event, PointerKind, clipboard};
use slate_ui::color::Color;
use slate_ui::edit::{EditKey, LineEdit};
use slate_ui::graphite::Palette;
use slate_ui::paint::Painter;
use slate_ui::text::GlyphCache;
use slate_ui::ui::Area;

/// What an event did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Nothing to show.
    None,
    Redraw,
    /// Put this text on Strata's clipboard (ADR 0038).
    Copy(String),
    /// Ask Strata's clipboard for its text ([`App::paste`] gets it).
    Paste,
    /// Close the window.
    Quit,
    /// These files are being dragged out of the window (ADR 0156):
    /// Strata takes them where the button comes up outside it. Redraws.
    Drag(Vec<String>),
}

pub trait App {
    /// Draw into `a` (the window, in logical pixels). Apps keep where
    /// their controls were drawn for [`App::click`].
    fn draw(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area);
    /// A key: its evdev code, its character, and the modifiers
    /// (`slate_strata_client::mods`).
    fn key(&mut self, code: u16, ch: Option<char>, mods: u8) -> Effect;
    /// A click of the first button at (x, y), in logical pixels.
    fn click(&mut self, _x: f32, _y: f32) -> Effect {
        Effect::None
    }
    /// A click with the modifiers held (ctrl + click, shift + click).
    fn click_mods(&mut self, x: f32, y: f32, _mods: u8) -> Effect {
        self.click(x, y)
    }
    /// The right button: a menu.
    fn right_click(&mut self, _x: f32, _y: f32) -> Effect {
        Effect::None
    }
    /// A second click soon after the first, near it.
    fn double_click(&mut self, x: f32, y: f32) -> Effect {
        self.click(x, y)
    }
    /// The pointer moved with the first button held.
    fn drag(&mut self, _x: f32, _y: f32) -> Effect {
        Effect::None
    }
    /// A drag with the modifiers held (ctrl copies what is dragged).
    fn drag_mods(&mut self, x: f32, y: f32, _mods: u8) -> Effect {
        self.drag(x, y)
    }
    /// The first button let go.
    fn release(&mut self) -> Effect {
        Effect::None
    }
    /// The first button let go with the modifiers held.
    fn release_mods(&mut self, _mods: u8) -> Effect {
        self.release()
    }
    /// The person closed the window: false keeps it open (unsaved
    /// work; the app asks).
    fn close(&mut self) -> bool {
        true
    }
    /// The window's title (the app's name and a path), when it changes
    /// with what the app shows.
    fn title(&self) -> Option<(String, Option<String>)> {
        None
    }
    /// The wheel: positive lines are down.
    fn scroll(&mut self, _lines: i32) -> Effect {
        Effect::None
    }
    /// Files dragged from the desktop or another app were dropped at
    /// (x, y) (ADR 0156); `copy`: with ctrl held, to be copied, not
    /// moved.
    fn dropped(&mut self, _x: f32, _y: f32, _paths: &[String], _copy: bool) -> Effect {
        Effect::None
    }

    fn paste(&mut self, _text: &str) -> Effect {
        Effect::None
    }
    /// Whether the app has finished: its window closes (the Web Browser,
    /// once it has started the browser).
    fn done(&self) -> bool {
        false
    }
    /// The time now (ms since the epoch, and monotonic ms) before each
    /// frame and after each wait: true if the app changed by itself (an
    /// alarm went off).
    fn tick(&mut self, _now: Now) -> bool {
        false
    }
    /// How long until the app wants to draw again by itself (ms), if it
    /// does: a clock showing seconds, a running timer.
    fn wake(&self, _now: Now) -> Option<i64> {
        None
    }
    /// New size hints to send (the calculator growing its scientific
    /// keys), once.
    fn take_hints(&mut self) -> Option<Hints> {
        None
    }
}

/// The time, in two clocks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Now {
    /// Milliseconds since the epoch (the wall clock, which can be set).
    pub wall: i64,
    /// Milliseconds on the monotonic clock (for intervals).
    pub mono: i64,
}

impl Now {
    pub fn read() -> Now {
        let (s, ns) = slate_rt::time::now(slate_rt::time::CLOCK_REALTIME);
        Now { wall: s * 1000 + ns / 1_000_000, mono: (slate_rt::time::monotonic_ns() / 1_000_000) as i64 }
    }
}

/// The window's size hints (ADR 0102): the least and the wanted content
/// size, in logical pixels.
#[derive(Clone, Copy, Debug)]
pub struct Hints {
    pub min: (u32, u32),
    pub size: (u32, u32),
}

/// Run `app` in a window titled `name` (and `path`) until it is closed.
/// `program` names the program in error messages. Returns the exit
/// status.
pub fn run(program: &str, name: &str, path: Option<&str>, hints: Hints, app: &mut dyn App) -> i32 {
    let files = match slate_strata::session::load_fonts() {
        Ok(f) => f,
        Err(e) => {
            slate_rt::eprintln!("{program}: {e}");
            return 1;
        }
    };
    let refs: [&[u8]; 5] = core::array::from_fn(|i| files[i].as_slice());
    let Some(fonts) = Fonts::new(refs) else { return 1 };
    match window(name, path, hints, app, &fonts) {
        Ok(()) => 0,
        Err(e) => {
            slate_rt::eprintln!("{program}: {e}");
            1
        }
    }
}

/// How often the person's settings are looked at (ms).
const SETTINGS_MS: i64 = 2000;
/// Two clicks within this long (ms) are a double click.
const DOUBLE_CLICK_MS: i64 = 400;

fn window(name: &str, path: Option<&str>, hints: Hints, app: &mut dyn App, fonts: &Fonts<'_>) -> Result<(), String> {
    // Frames free and allocate large buffers all the time: keep some
    // mappings for reuse (ADR 0094's addendum).
    slate_rt::alloc_impl::keep_freed(16 << 20);
    let mut conn = Connection::connect()?;
    let mut win = conn.create(name, path)?;
    conn.set_hints(&win, hints.min, hints.size)?;
    let mut cache = GlyphCache::new();
    let mut pal = Settings::load().palette();
    let mut stamp = settings::stamp();
    let mut checked = Now::read().mono;
    let mut title: Option<(String, Option<String>)> = None;
    // The first button: held, and the last click (when and where), for
    // drags and double clicks.
    let mut held = false;
    let mut last_click = (i64::MIN / 2, 0.0f32, 0.0f32);
    loop {
        if let Some(t) = app.title().filter(|t| title.as_ref() != Some(t)) {
            conn.set_title(&win, &t.0, t.1.as_deref(), 0)?;
            title = Some(t);
        }
        app.tick(Now::read());
        let mut canvas = win.canvas(pal.window);
        {
            let mut p = Painter::new(&mut canvas, &mut cache, win.scale);
            let (w, h) = p.size();
            app.draw(&mut p, &pal, fonts, Area::new(0.0, 0.0, w, h));
        }
        conn.present(&mut win, &canvas)?;
        // Wait for an event, the app's own next frame, or the settings.
        let mut redraw = false;
        while !redraw {
            let now = Now::read();
            let settings_in = (checked + SETTINGS_MS - now.mono).max(0);
            let wait = app.wake(now).map_or(settings_in, |w| w.clamp(0, settings_in));
            let events: Vec<Event> = conn.poll(wait.min(i64::from(i32::MAX)) as i32)?;
            let now = Now::read();
            if now.mono - checked >= SETTINGS_MS {
                checked = now.mono;
                if settings::stamp() != stamp {
                    stamp = settings::stamp();
                    let new = Settings::load().palette();
                    redraw |= new != pal;
                    pal = new;
                }
            }
            redraw |= app.tick(now) || app.wake(now).is_some_and(|w| w <= 0);
            if app.done() {
                return Ok(());
            }
            for e in events {
                let effect = match e {
                    Event::Close { .. } => {
                        if app.close() {
                            return Ok(());
                        }
                        Effect::Redraw
                    }
                    Event::Configure { .. } => {
                        win.configure(&e);
                        Effect::Redraw
                    }
                    Event::Key { code, ch, mods, .. } => app.key(code, char::from_u32(ch).filter(|_| ch != 0), mods),
                    Event::Pointer { kind: PointerKind::Down, button: 3, x, y, .. } => {
                        app.right_click(x as f32 / win.scale, y as f32 / win.scale)
                    }
                    Event::Pointer { kind: PointerKind::Down, button: 1, x, y, mods, .. } => {
                        let (x, y) = (x as f32 / win.scale, y as f32 / win.scale);
                        held = true;
                        let t = Now::read().mono;
                        let near = (x - last_click.1).abs() < 5.0 && (y - last_click.2).abs() < 5.0;
                        if t - last_click.0 < DOUBLE_CLICK_MS && near {
                            last_click.0 = i64::MIN / 2;
                            app.double_click(x, y)
                        } else {
                            last_click = (t, x, y);
                            app.click_mods(x, y, mods)
                        }
                    }
                    Event::Pointer { kind: PointerKind::Move, x, y, mods, .. } if held => {
                        app.drag_mods(x as f32 / win.scale, y as f32 / win.scale, mods)
                    }
                    Event::Pointer { kind: PointerKind::Up, button: 1, mods, .. } => {
                        held = false;
                        app.release_mods(mods)
                    }
                    Event::Scroll { lines, .. } => app.scroll(lines),
                    Event::Paste { text, .. } => app.paste(&text),
                    Event::Drop { x, y, paths, copy, .. } => {
                        let paths: Vec<String> = paths.lines().filter(|l| !l.is_empty()).map(String::from).collect();
                        app.dropped(x as f32 / win.scale, y as f32 / win.scale, &paths, copy)
                    }
                    _ => Effect::None,
                };
                match effect {
                    Effect::None => {}
                    Effect::Redraw => redraw = true,
                    Effect::Copy(t) => conn.copy(clipboard::CLIPBOARD, &t)?,
                    Effect::Paste => conn.paste(&win, clipboard::CLIPBOARD)?,
                    Effect::Quit => return Ok(()),
                    Effect::Drag(paths) => {
                        conn.drag(&win, &paths)?;
                        redraw = true;
                    }
                }
            }
            if let Some(h) = app.take_hints() {
                conn.set_hints(&win, h.min, h.size)?;
            }
        }
    }
}

/// A button: a raised block with its label centred, outlined when it is
/// the one the keyboard or the last key pressed points at.
pub fn button(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area, label: &str, strong: bool, lit: bool) {
    p.fill(a, 8.0, if strong { pal.chalk } else { pal.raised });
    if lit {
        p.border(a.grow(2.0), 10.0, 2.0, pal.chalk);
    }
    let ink = if strong { pal.window } else { pal.text_1 };
    // The backspace key has an icon, not a glyph (Host Grotesk has no ⌫).
    if label == "⌫" {
        p.icon(slate_ui::icon::Icon::Backspace, a.x + (a.w - 20.0) / 2.0, a.y + (a.h - 20.0) / 2.0, 20.0, ink);
        return;
    }
    let style = p.style(&f.medium, 15.0, ink);
    let w = p.measure(&style, label);
    p.line(&style, a.x + (a.w - w) / 2.0, a.y + (a.h - 20.0) / 2.0, 20.0, label);
}

/// Tabs across the top: their labels, which is chosen, and where each
/// was drawn.
pub fn tabs(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    x: f32,
    y: f32,
    labels: &[&str],
    on: usize,
) -> Vec<Area> {
    let mut out = Vec::new();
    let mut x = x;
    let style = p.style(&f.medium, 13.0, pal.text_3);
    let chosen = p.style(&f.medium, 13.0, pal.chalk);
    for (i, l) in labels.iter().enumerate() {
        let w = p.measure(&style, l) + 24.0;
        let a = Area::new(x, y, w, 30.0);
        if i == on {
            p.fill(a, 6.0, pal.raised);
        }
        p.line(if i == on { &chosen } else { &style }, x + 12.0, y + 5.0, 20.0, l);
        out.push(a);
        x += w + 4.0;
    }
    out
}

/// A key hint line at the bottom of `a`: keys in `text_1`, labels muted
/// (WM_STYLE §2). The fonts have no arrows, so ↑↓ and ←→ are icons.
pub fn hints(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area, items: &[(&str, &str)]) {
    let key = p.style(&f.mono, 11.0, pal.text_1);
    let label = p.style(&f.mono, 11.0, pal.muted);
    let mut x = a.x + 20.0;
    let y = a.y + a.h - 28.0;
    for (k, l) in items {
        let icon = match *k {
            "↑↓" => Some(slate_ui::icon::Icon::UpDown),
            "←→" => Some(slate_ui::icon::Icon::LeftRight),
            _ => None,
        };
        x += match icon {
            Some(i) => {
                p.icon(i, x, y + 3.0, 12.0, pal.text_1);
                12.0
            }
            None => p.line(&key, x, y, 18.0, k),
        } + 6.0;
        x += p.line(&label, x, y, 18.0, l) + 16.0;
    }
}

/// `$HOME/.config/strata/NAME`, where the apps keep what they remember.
pub fn config_path(name: &str) -> Option<Vec<u8>> {
    let home = slate_rt::env::var(b"HOME")?;
    Some(slate_rt::fs::join(&home, alloc::format!(".config/strata/{name}").as_bytes()))
}

/// Write `text` to `NAME` in the apps' configuration directory (made if
/// missing), atomically.
pub fn save_config(name: &str, text: &str) -> Result<(), String> {
    let path = config_path(name).ok_or("no HOME")?;
    let home = slate_rt::env::var(b"HOME").ok_or("no HOME")?;
    for d in [slate_rt::fs::join(&home, b".config"), slate_rt::fs::join(&home, b".config/strata")] {
        let _ = slate_rt::fs::mkdir(&d, 0o700);
    }
    let mut tmp = path.clone();
    tmp.extend_from_slice(b".new");
    slate_rt::fs::write_file(&tmp, text.as_bytes(), 0o600).map_err(|e| alloc::format!("{e}"))?;
    slate_rt::fs::rename(&tmp, &path).map_err(|e| alloc::format!("{e}"))
}

pub fn load_config(name: &str) -> Option<String> {
    let path = config_path(name)?;
    slate_rt::fs::read_file(&path).ok().map(|b| String::from(slate_rt::lossy(&b)))
}

/// Whether the apps say what they do on stderr (`SLATE_APPS_TRACE` set):
/// the desktop scenarios follow them so (ADR 0104).
pub fn tracing() -> bool {
    slate_rt::env::var(b"SLATE_APPS_TRACE").is_some()
}

/// A line on stderr when [`tracing`].
#[macro_export]
macro_rules! trace {
    ($($t:tt)*) => {
        if $crate::kit::tracing() {
            slate_rt::eprintln!($($t)*);
        }
    };
}

/// `s` cut to fit `max` with an ellipsis.
pub fn fit(p: &Painter<'_>, style: &slate_ui::text::Style<'_, '_>, s: &str, max: f32) -> String {
    if p.measure(style, s) <= max {
        return String::from(s);
    }
    let chars: Vec<char> = s.chars().collect();
    let mut n = chars.len();
    while n > 0 {
        n -= 1;
        let t: String = chars[..n].iter().chain(core::iter::once(&'…')).collect();
        if p.measure(style, &t) <= max {
            return t;
        }
    }
    String::new()
}

/// Work done away from the window (ADR 0112): a request to the privilege
/// broker, which waits while Strata's approval dialog is up, or a long
/// command (an upgrade). A child process does it and writes the outcome
/// on a pipe; the app looks with [`Job::poll`] from `tick` and draws on
/// meanwhile. Work started with [`Job::reporting`] also says how far it
/// is ([`Job::progress`]): NUL-ended `p` records before the outcome.
#[derive(Debug)]
pub struct Job {
    pid: i32,
    fd: i32,
    got: Vec<u8>,
    /// What the work last said of how far it is.
    pub progress: Option<String>,
    /// Everything the work said, in order, when it was started with
    /// [`Job::listing`] (results as they are found).
    pub said: Option<Vec<String>>,
}

/// How a [`Job`]'s work says how far it is.
#[derive(Debug)]
pub struct Report {
    fd: i32,
}

impl Report {
    pub fn say(&mut self, text: &str) {
        let _ = slate_rt::io::write_all(self.fd, alloc::format!("p{text}\0").as_bytes());
    }
}

impl Job {
    /// Start `work` in a child process.
    pub fn start(work: impl FnOnce() -> Result<String, String>) -> Result<Job, String> {
        Job::reporting(|_| work())
    }

    /// Start `work` in a child process, which may say how far it is.
    pub fn reporting(work: impl FnOnce(&mut Report) -> Result<String, String>) -> Result<Job, String> {
        let (r, w) = slate_rt::process::pipe(slate_rt::fs::O_CLOEXEC).map_err(|e| alloc::format!("{e}"))?;
        match slate_rt::process::fork() {
            Ok(0) => {
                let _ = slate_rt::io::close(r);
                let msg = match work(&mut Report { fd: w }) {
                    Ok(s) => alloc::format!("o{s}"),
                    Err(e) => alloc::format!("e{e}"),
                };
                let _ = slate_rt::io::write_all(w, msg.as_bytes());
                slate_rt::process::exit_now(0)
            }
            Ok(pid) => {
                let _ = slate_rt::io::close(w);
                Ok(Job { pid, fd: r, got: Vec::new(), progress: None, said: None })
            }
            Err(e) => {
                let _ = slate_rt::io::close(r);
                let _ = slate_rt::io::close(w);
                Err(alloc::format!("{e}"))
            }
        }
    }

    /// Start `work` in a child process, keeping everything it says (in
    /// [`Job::said`], for the caller to take).
    pub fn listing(work: impl FnOnce(&mut Report) -> Result<String, String>) -> Result<Job, String> {
        let mut j = Job::reporting(work)?;
        j.said = Some(Vec::new());
        Ok(j)
    }

    /// The outcome, once the work is done.
    pub fn poll(&mut self) -> Option<Result<String, String>> {
        loop {
            let mut p = [slate_rt::io::PollFd { fd: self.fd, events: slate_rt::io::POLLIN, revents: 0 }];
            if slate_rt::io::poll(&mut p, 0).unwrap_or(0) == 0 {
                return None;
            }
            let mut chunk = [0u8; 4096];
            match slate_rt::io::read(self.fd, &mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => self.got.extend_from_slice(&chunk[..n]),
            }
            // Progress records, as they come.
            while self.got.first() == Some(&b'p')
                && let Some(end) = self.got.iter().position(|&b| b == 0)
            {
                let text = String::from(slate_rt::lossy(&self.got[1..end]));
                match &mut self.said {
                    Some(all) => all.push(text),
                    None => self.progress = Some(text),
                }
                self.got.drain(..=end);
            }
        }
        let text = String::from(slate_rt::lossy(&self.got));
        let _ = slate_rt::process::wait(self.pid, 0);
        self.pid = 0;
        Some(match text.split_at_checked(1) {
            Some(("o", s)) => Ok(String::from(s)),
            Some(("e", e)) => Err(String::from(e)),
            _ => Err(String::from("it stopped without saying why")),
        })
    }
}

impl Job {
    /// Stop the work where it is.
    pub fn cancel(mut self) {
        if self.pid > 0 {
            let _ = slate_rt::process::kill(self.pid, slate_rt::signal::SIGTERM);
            let _ = slate_rt::process::wait(self.pid, 0);
            self.pid = 0;
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        let _ = slate_rt::io::close(self.fd);
        if self.pid > 0 {
            let _ = slate_rt::process::wait(self.pid, slate_rt::process::WNOHANG);
        }
    }
}

/// How often an app with a [`Job`] running looks at it (ms).
pub const JOB_MS: i64 = 100;

/// How often a window with a spinner turning redraws it (ms).
pub const SPIN_MS: i64 = 50;

/// A spinner, `size` across at (x, y), at `ms` (the monotonic clock): a
/// faint ring with a chalk arc going round once a second. Work under way
/// whose end can't be told.
pub fn spinner(p: &mut Painter<'_>, pal: &Palette, x: f32, y: f32, size: f32, ms: i64) {
    use slate_ui::icon::{cos, sin};
    let r = size / 2.0 - 1.5;
    let (cx, cy) = (x + size / 2.0, y + size / 2.0);
    let ring = |a0: f32, a1: f32| -> Vec<(f32, f32)> {
        let n = 24;
        (0..=n)
            .map(|i| {
                let a = a0 + (a1 - a0) * i as f32 / n as f32;
                (cx + r * cos(a), cy + r * sin(a))
            })
            .collect()
    };
    let tau = 2.0 * core::f32::consts::PI;
    p.polyline(&ring(0.0, tau), 2.0, pal.border);
    let start = (ms.rem_euclid(1000) as f32 / 1000.0) * tau;
    p.polyline(&ring(start, start + tau * 0.28), 2.0, pal.chalk);
}

/// A progress bar in `a`: filled to `fraction` (0 to 1), or, with None,
/// a band sliding across it (the total isn't known yet), at `ms`.
pub fn progress_bar(p: &mut Painter<'_>, pal: &Palette, a: Area, fraction: Option<f32>, ms: i64) {
    let r = a.h / 2.0;
    p.fill(a, r, pal.well);
    p.border(a, r, 1.0, pal.border);
    match fraction {
        Some(f) => {
            let w = (a.w * f.clamp(0.0, 1.0)).max(if f > 0.0 { a.h } else { 0.0 });
            if w > 0.0 {
                p.fill(Area::new(a.x, a.y, w, a.h), r, pal.chalk);
            }
        }
        None => {
            // A third of the bar, across and back in 1.6 s.
            let band = a.w / 3.0;
            let t = ms.rem_euclid(1600) as f32 / 1600.0;
            let along = if t < 0.5 { t * 2.0 } else { 2.0 - t * 2.0 };
            p.fill(Area::new(a.x + (a.w - band) * along, a.y, band, a.h), r, pal.chalk.with_alpha(200));
        }
    }
}

/// How far an install or update is, from the line slate-flatpak says
/// (M31 phase 3; `flatpak::Progress` in userland/linux-app):
/// `slate-flatpak: 42% of 173.8 MB: org.mozilla.firefox (2 of 2)`, as a
/// fraction.
pub fn flatpak_fraction(line: &str) -> Option<f32> {
    let rest = line.trim().strip_prefix("slate-flatpak: ")?;
    let pct: u32 = rest.split_once('%')?.0.parse().ok()?;
    Some(pct.min(100) as f32 / 100.0)
}

/// How far `slate-linux setup` is, from its progress file (ADR 0126):
/// `STAGE STEP STEPS TEXT`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupProgress {
    pub stage: String,
    pub step: usize,
    pub steps: usize,
    pub text: String,
}

/// Where `slate-linux setup` says how far it is.
pub const SETUP_PROGRESS: &str = "/run/slate-linux-progress";

impl SetupProgress {
    pub fn parse(line: &str) -> Option<SetupProgress> {
        let line = line.trim_end_matches('\n');
        let mut w = line.splitn(4, ' ');
        let stage = String::from(w.next()?);
        let (step, steps) = (w.next()?.parse().ok()?, w.next()?.parse().ok()?);
        let text = String::from(w.next().unwrap_or(""));
        matches!(stage.as_str(), "base" | "lists" | "packages" | "finishing").then_some(SetupProgress {
            stage,
            step,
            steps,
            text,
        })
    }

    /// The file's line now, if setup is under way.
    pub fn read() -> Option<SetupProgress> {
        let t = slate_rt::fs::read_file(SETUP_PROGRESS.as_bytes()).ok()?;
        SetupProgress::parse(&slate_rt::lossy(&t))
    }

    /// How far, of the whole setup: the packages are most of it.
    pub fn fraction(&self) -> f32 {
        match self.stage.as_str() {
            "base" => 0.03,
            "lists" => 0.07,
            "packages" if self.steps > 0 => 0.1 + 0.85 * self.step.min(self.steps) as f32 / self.steps as f32,
            "finishing" => 0.96,
            _ => 0.1,
        }
    }

    /// What it is doing, in words.
    pub fn say(&self) -> String {
        match self.stage.as_str() {
            "base" => String::from("Fetching Alpine Linux's base system"),
            "lists" => String::from("Reading the package lists"),
            "packages" => alloc::format!("Installing {} · {} of {}", self.text, self.step, self.steps),
            _ if self.text.is_empty() => String::from("Finishing"),
            _ => alloc::format!("Finishing: {}", self.text),
        }
    }
}

/// Ask the privilege broker for system action `action`; it asks Strata
/// for approval when it must (ADR 0037). Blocks: run it in a [`Job`].
pub fn broker(action: &str) -> Result<(), String> {
    slate_strata::agent::request(action, "")
}

/// Run `path` with `args` and its standard output; on failure, the last
/// thing it said on standard error.
pub fn output(path: &str, args: &[&str]) -> Result<String, String> {
    let argv: Vec<Vec<u8>> =
        core::iter::once(path).chain(args.iter().copied()).map(|a| a.as_bytes().to_vec()).collect();
    let (or, ow) = slate_rt::process::pipe(slate_rt::fs::O_CLOEXEC).map_err(|e| alloc::format!("{e}"))?;
    let (er, ew) = slate_rt::process::pipe(slate_rt::fs::O_CLOEXEC).map_err(|e| alloc::format!("{e}"))?;
    let pid = slate_rt::process::fork().map_err(|e| alloc::format!("{e}"))?;
    if pid == 0 {
        let _ = slate_rt::process::dup2(ow, 1);
        let _ = slate_rt::process::dup2(ew, 2);
        let e = slate_rt::process::execve(path.as_bytes(), &argv, slate_rt::env::vars());
        slate_rt::eprintln!("{path}: {e}");
        slate_rt::process::exit_now(127);
    }
    let _ = slate_rt::io::close(ow);
    let _ = slate_rt::io::close(ew);
    // Small outputs: standard error after standard output is fine.
    let out = slate_rt::io::read_to_end(or).unwrap_or_default();
    let err = slate_rt::io::read_to_end(er).unwrap_or_default();
    let _ = slate_rt::io::close(or);
    let _ = slate_rt::io::close(er);
    let status = slate_rt::process::wait(pid, 0).map(|(_, s)| s).unwrap_or(-1);
    if status == 0 {
        return Ok(String::from(slate_rt::lossy(&out)));
    }
    let err = String::from(slate_rt::lossy(&err));
    let last = err.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("it failed");
    Err(String::from(last.split_once(": ").filter(|(p, _)| !p.contains(' ')).map_or(last, |(_, m)| m)))
}

/// [`output`], passing on each line `path` writes as it comes (lines end
/// at a newline or a carriage return, as progress counters overwrite
/// themselves) to `report`, for a [`Job::reporting`].
pub fn output_reporting(path: &str, args: &[&str], report: &mut Report) -> Result<String, String> {
    let argv: Vec<Vec<u8>> =
        core::iter::once(path).chain(args.iter().copied()).map(|a| a.as_bytes().to_vec()).collect();
    let (or, ow) = slate_rt::process::pipe(slate_rt::fs::O_CLOEXEC).map_err(|e| alloc::format!("{e}"))?;
    let (er, ew) = slate_rt::process::pipe(slate_rt::fs::O_CLOEXEC).map_err(|e| alloc::format!("{e}"))?;
    let pid = slate_rt::process::fork().map_err(|e| alloc::format!("{e}"))?;
    if pid == 0 {
        let _ = slate_rt::process::dup2(ow, 1);
        let _ = slate_rt::process::dup2(ew, 2);
        let e = slate_rt::process::execve(path.as_bytes(), &argv, slate_rt::env::vars());
        slate_rt::eprintln!("{path}: {e}");
        slate_rt::process::exit_now(127);
    }
    let _ = slate_rt::io::close(ow);
    let _ = slate_rt::io::close(ew);
    let (mut out, mut err, mut line) = (Vec::new(), Vec::new(), Vec::new());
    let mut buf = [0u8; 4096];
    // Both, as they come: a full standard error mustn't stall the program.
    let mut open = [true, true];
    while open[0] || open[1] {
        let mut fds = [
            slate_rt::io::PollFd { fd: if open[0] { or } else { -1 }, events: slate_rt::io::POLLIN, revents: 0 },
            slate_rt::io::PollFd { fd: if open[1] { er } else { -1 }, events: slate_rt::io::POLLIN, revents: 0 },
        ];
        if slate_rt::io::poll(&mut fds, -1).is_err() {
            break;
        }
        if open[1] && fds[1].revents != 0 {
            match slate_rt::io::read(er, &mut buf) {
                Ok(0) | Err(_) => open[1] = false,
                Ok(n) => err.extend_from_slice(&buf[..n]),
            }
        }
        if open[0] && fds[0].revents != 0 {
            let n = match slate_rt::io::read(or, &mut buf) {
                Ok(0) | Err(_) => {
                    open[0] = false;
                    continue;
                }
                Ok(n) => n,
            };
            out.extend_from_slice(&buf[..n]);
            for &b in &buf[..n] {
                if b == b'\n' || b == b'\r' {
                    let l = String::from(slate_rt::lossy(&line));
                    if !l.trim().is_empty() {
                        report.say(l.trim());
                    }
                    line.clear();
                } else {
                    line.push(b);
                }
            }
        }
    }
    let _ = slate_rt::io::close(or);
    let _ = slate_rt::io::close(er);
    let status = slate_rt::process::wait(pid, 0).map(|(_, s)| s).unwrap_or(-1);
    if status == 0 {
        return Ok(String::from(slate_rt::lossy(&out)));
    }
    let err = String::from(slate_rt::lossy(&err));
    let last = err.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("it failed");
    Err(String::from(last.split_once(": ").filter(|(p, _)| !p.contains(' ')).map_or(last, |(_, m)| m)))
}

/// A text field: `edit` in a well, its caret shown when `focused`, and
/// `ghost` (muted) when it is empty.
pub fn field(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area, edit: &LineEdit, focused: bool, ghost: &str) {
    p.fill(a, 7.0, pal.well);
    p.border(a, 7.0, 1.0, if focused { pal.field_focus } else { pal.border });
    let mut typed = p.style(&f.regular, 13.5, pal.text_1);
    typed.ligatures = false;
    let text = edit.text();
    let top = a.y + (a.h - 20.0) / 2.0;
    if text.is_empty() && !ghost.is_empty() {
        let g = p.style(&f.regular, 13.5, pal.muted);
        p.line(&g, a.x + 10.0, top, 20.0, ghost);
    }
    p.line(&typed, a.x + 10.0, top, 20.0, &text);
    if focused {
        let before: String = text.chars().take(edit.caret()).collect();
        let cx = p.measure(&typed, &before);
        p.fill(Area::new(a.x + 10.0 + cx, top, 1.5, 20.0), 0.0, pal.chalk);
    }
}

/// A key typed into `edit`: true if it changed or moved. `allowed`
/// filters the characters it takes.
pub fn edit_key(edit: &mut LineEdit, code: u16, ch: Option<char>, mods: u8, allowed: impl Fn(char) -> bool) -> bool {
    use slate_display::input::{KEY_BACKSPACE, KEY_DELETE, KEY_END, KEY_HOME, KEY_LEFT, KEY_RIGHT};
    use slate_strata_client::mods::{ALT, CTRL, LOGO, SHIFT};
    let (shift, ctrl) = (mods & SHIFT != 0, mods & CTRL != 0);
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
    match (k, ch.filter(|c| mods & (CTRL | ALT | LOGO) == 0 && !c.is_control() && allowed(*c))) {
        (Some(k), _) => edit.key(k, shift, ctrl).moved,
        (None, Some(c)) => edit.insert(c.encode_utf8(&mut [0u8; 4])),
        _ => false,
    }
}

/// A line chart of `values` (0 to 1, the newest last) across `a`, its
/// area under the line filled faintly: the System Monitor's history.
pub fn chart(p: &mut Painter<'_>, a: Area, values: &[f32], max_points: usize, line: Color, fill: Color) {
    if values.is_empty() || max_points < 2 {
        return;
    }
    let step = a.w / (max_points - 1) as f32;
    let start = max_points.saturating_sub(values.len());
    let pts: Vec<(f32, f32)> = values
        .iter()
        .enumerate()
        .map(|(i, v)| (a.x + (start + i) as f32 * step, a.y + a.h - v.clamp(0.0, 1.0) * a.h))
        .collect();
    if pts.len() >= 2 {
        let mut poly = pts.clone();
        poly.push((pts[pts.len() - 1].0, a.y + a.h));
        poly.push((pts[0].0, a.y + a.h));
        p.path(&slate_ui::path::Path::polygon(&poly), fill);
        p.polyline(&pts, 1.5, line);
    }
}

/// `n` bytes a second, as people read it: "1.2 MiB/s".
pub fn rate(n: f64) -> String {
    alloc::format!("{}/s", slate_sysinfo::size(n.max(0.0) as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_progress() {
        let p = SetupProgress::parse("packages 34 159 mesa\n").unwrap();
        assert_eq!((p.step, p.steps, p.text.as_str()), (34, 159, "mesa"));
        assert_eq!(p.say(), "Installing mesa · 34 of 159");
        let f = p.fraction();
        assert!(f > 0.25 && f < 0.35, "{f}");
        // Each stage further along than the one before.
        let at = |l: &str| SetupProgress::parse(l).unwrap().fraction();
        assert!(at("base 0 0 Alpine") < at("lists 0 0 ") && at("lists 0 0 ") < at("packages 1 159 a"));
        assert!(at("packages 159 159 z") < at("finishing 0 0 fontconfig"));
        assert_eq!(SetupProgress::parse("lists 0 0").unwrap().say(), "Reading the package lists");
        assert_eq!(SetupProgress::parse("finishing 0 0 fontconfig").unwrap().say(), "Finishing: fontconfig");
        assert!(SetupProgress::parse("done 1 1 x").is_none() && SetupProgress::parse("packages x").is_none());
    }
}
