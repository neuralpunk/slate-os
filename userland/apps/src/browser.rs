// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Web Browser (ADR 0115), `web-browser`: Slate's own entry for the
//! web. Slate ships no browser (ADR 0012); on first use this fetches one
//! from Flathub, as its makers publish it there (Firefox, by Mozilla),
//! and runs it in Flatpak's sandbox in the Linux runtime (ADR 0114).
//! After that, "Web Browser" starts it, and Strata keeps it up to date in
//! the background (`slate-flatpak update --auto`).
//!
//! - `web-browser [URL...]`: the chosen browser, or the first-use window.
//! - `web-browser --get`: first use's steps on the terminal.
//! - `web-browser --use APP-ID`: another browser from Flathub, installed
//!   with slate-flatpak, becomes the one started.
//!
//! First use asks the broker for `browser=setup` (Linux compatibility on,
//! the runtime with Flatpak) only if something is missing, behind the
//! approval dialog; the browser itself is the person's own install,
//! which needs no password. slate-flatpak checks Flathub's key.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_display::input::{KEY_DOWN, KEY_ENTER, KEY_ESC, KEY_KPENTER, KEY_TAB, KEY_UP};
use slate_strata::fonts::Fonts;
use slate_ui::graphite::Palette;
use slate_ui::icon::Icon;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;

use crate::kit::{self, App, Effect, Hints, Job, Now};

/// The browser first use offers first: Firefox, as Mozilla publishes it
/// on Flathub.
pub const FIREFOX: &str = "org.mozilla.firefox";
/// LibreWolf, a Firefox without its telemetry, as its community publishes
/// it on Flathub.
pub const LIBREWOLF: &str = "io.gitlab.librewolf-community";
/// The browsers first use offers (ID, name, who publishes it): those
/// tried in Slate's sandbox. Chromium's need the session bus inside it
/// (GAPS.md, "Portals").
pub const OFFERED: &[(&str, &str, &str)] =
    &[(FIREFOX, "Firefox", "Mozilla"), (LIBREWOLF, "LibreWolf", "the LibreWolf community")];
/// The person's choice, in their Strata settings: `app=ID`.
const CHOICE: &str = "browser";
/// What the browser needs of the system (the broker's `browser=setup`
/// makes them): the runtime with Flatpak, its compositor and D-Bus.
const RUNTIME_NEEDS: &[&str] = &[
    "/var/lib/slate/linux/usr/bin/flatpak",
    "/var/lib/slate/linux/usr/bin/sway",
    "/var/lib/slate/linux/usr/bin/dbus-daemon",
];
const SLATE_FLATPAK: &str = "/bin/slate-flatpak";

/// The browser in a choice file, if it names one.
pub fn parse_choice(text: &str) -> Option<String> {
    let id = text.lines().find_map(|l| l.trim().strip_prefix("app="))?.trim();
    let ok = id.split('.').count() >= 3
        && id.split('.').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'));
    ok.then(|| id.to_string())
}

pub fn choice_text(id: &str) -> String {
    alloc::format!("# The Web Browser's browser (ADR 0115).\napp={id}\n")
}

/// The browser's name and who publishes it, for the window's words.
pub fn describe(id: &str) -> (&str, &str) {
    match OFFERED.iter().find(|(i, _, _)| *i == id) {
        Some((_, name, maker)) => (name, maker),
        None => (id.rsplit('.').next().unwrap_or(id), "its makers"),
    }
}

/// What first use has left to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Needs {
    /// Linux compatibility, or the runtime with Flatpak (the broker's).
    pub setup: bool,
    /// The browser itself (the person's).
    pub fetch: bool,
}

impl Needs {
    pub fn read(id: &str) -> Needs {
        let compat = slate_rt::fs::read_file(b"/proc/sys/slate/linux_compat").is_ok_and(|t| t.first() == Some(&b'1'));
        let runtime = RUNTIME_NEEDS.iter().all(|p| slate_rt::fs::exists(p.as_bytes()));
        Needs { setup: !compat || !runtime, fetch: !installed(id) }
    }
}

/// Whether the person has `id` installed (their Flatpak installation).
fn installed(id: &str) -> bool {
    let Some(home) = slate_rt::env::var(b"HOME") else { return false };
    let path = slate_rt::fs::join(&home, alloc::format!(".local/share/flatpak/app/{id}/current").as_bytes());
    slate_rt::fs::exists(&path)
}

/// Where first use is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stage {
    Offer,
    SettingUp,
    Fetching,
    /// What went wrong, and whether it was a refusal (nothing changed).
    Failed(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Button {
    Get,
    NotNow,
    /// One of [`OFFERED`].
    Pick(usize),
}

#[derive(Debug)]
pub struct Browser {
    pub id: String,
    pub needs: Needs,
    pub stage: Stage,
    /// First use, before anything is fetched: the person picks one of
    /// [`OFFERED`] (up and down, or a click).
    pub choosing: bool,
    /// The URLs to open once it runs.
    args: Vec<String>,
    /// When the current step began (monotonic ms), and now.
    since: i64,
    focus: usize,
    job: Option<Job>,
    hits: Vec<(Area, Button)>,
    done: bool,
    /// How far setting the runtime up is, and what Flatpak last said.
    pub setup: Option<kit::SetupProgress>,
    pub said: Option<String>,
    /// How far fetching is (slate-flatpak's percentage lines, M31 phase 3),
    /// and the steps first use has (1 or 2: the runtime, the browser).
    pub fetched: Option<f32>,
    steps: usize,
    /// The monotonic clock, as last ticked (ms).
    pub now: i64,
}

impl Browser {
    pub fn new(id: &str, needs: Needs, args: Vec<String>) -> Browser {
        Browser {
            id: id.to_string(),
            needs,
            stage: Stage::Offer,
            choosing: needs.fetch && OFFERED.iter().any(|(i, _, _)| *i == id),
            args,
            since: 0,
            now: 0,
            focus: 0,
            job: None,
            hits: Vec::new(),
            done: false,
            setup: None,
            said: None,
            fetched: None,
            steps: usize::from(needs.setup) + usize::from(needs.fetch),
        }
    }

    fn start(&mut self) {
        if self.job.is_some() {
            return;
        }
        // Installed but it didn't start: Try again starts it again.
        if !self.needs.setup && !self.needs.fetch {
            self.launch();
            return;
        }
        let id = self.id.clone();
        let (stage, job) = if self.needs.setup {
            (Stage::SettingUp, Job::start(|| kit::broker("browser=setup").map(|()| String::new())))
        } else {
            (
                Stage::Fetching,
                Job::reporting(move |report| kit::output_reporting(SLATE_FLATPAK, &["install", &id], report)),
            )
        };
        match job {
            Ok(j) => {
                crate::trace!("web-browser: {}", if stage == Stage::SettingUp { "setting up" } else { "fetching" });
                self.job = Some(j);
                self.stage = stage;
                self.since = self.now;
                self.setup = None;
                self.said = None;
                self.fetched = None;
            }
            Err(e) => self.stage = Stage::Failed(alloc::format!("Couldn't start: {e}")),
        }
    }

    /// The outcome of the step under way; the next one starts, or the
    /// browser does.
    pub fn finished(&mut self, r: Result<String, String>) {
        let was = core::mem::replace(&mut self.stage, Stage::Offer);
        match (was, r) {
            (_, Err(e)) if e == "cancelled" => {
                self.stage = Stage::Failed(String::from("Nothing was changed."));
            }
            (Stage::SettingUp, Ok(_)) => {
                self.needs.setup = false;
                if self.needs.fetch {
                    self.start();
                } else {
                    self.launch();
                }
            }
            (Stage::SettingUp, Err(e)) => {
                self.stage = Stage::Failed(alloc::format!("The Linux runtime wasn't set up: {e}"));
            }
            (_, Ok(_)) => {
                self.needs.fetch = false;
                self.launch();
            }
            (_, Err(e)) => {
                let (name, _) = describe(&self.id);
                self.stage = Stage::Failed(alloc::format!("{name} wasn't fetched: {e}"));
            }
        }
    }

    /// Remember the choice, start the browser, and close.
    fn launch(&mut self) {
        let _ = kit::save_config(CHOICE, &choice_text(&self.id));
        crate::trace!("web-browser: starting {}", self.id);
        start_browser(&self.id, &self.args);
        self.done = true;
    }

    fn press(&mut self, b: Button) -> Effect {
        match b {
            Button::Get => {
                self.start();
                Effect::Redraw
            }
            Button::NotNow => {
                crate::trace!("web-browser: not now");
                Effect::Quit
            }
            Button::Pick(i) => {
                self.pick(i);
                Effect::Redraw
            }
        }
    }

    /// Choose the `i`th offered browser.
    pub fn pick(&mut self, i: usize) {
        if let Some((id, _, _)) = OFFERED.get(i)
            && self.choosing
            && self.job.is_none()
        {
            self.id = id.to_string();
            self.needs.fetch = !installed(id);
            crate::trace!("web-browser: chose {id}");
        }
    }

    fn picked(&self) -> usize {
        OFFERED.iter().position(|(i, _, _)| *i == self.id).unwrap_or(0)
    }

    fn elapsed(&self) -> String {
        let s = ((self.now - self.since) / 1000).max(0);
        alloc::format!("{}:{:02}", s / 60, s % 60)
    }
}

/// Start the browser in the background, apart from this program. A
/// watcher waits for it: if it ends with a failure (its window closed by
/// the person is no failure), the Web Browser's window comes back to say
/// so, with what the browser said last.
fn start_browser(id: &str, args: &[String]) {
    use slate_rt::process;
    let mut argv: Vec<Vec<u8>> = [SLATE_FLATPAK, "run", id].iter().map(|a| a.as_bytes().to_vec()).collect();
    argv.extend(args.iter().map(|a| a.as_bytes().to_vec()));
    if let Ok(0) = process::fork() {
        let _ = process::setsid();
        let status = match process::fork() {
            Ok(0) => {
                log_output();
                let e = process::execve(SLATE_FLATPAK.as_bytes(), &argv, slate_rt::env::vars());
                slate_rt::eprintln!("web-browser: {SLATE_FLATPAK}: {e}");
                process::exit_now(127)
            }
            Ok(pid) => process::wait(pid, 0).map_or(0, |(_, s)| s),
            Err(_) => process::exit_now(1),
        };
        let code = process::exited(status).unwrap_or(128 + (status & 0x7f));
        if code == 0 {
            process::exit_now(0);
        }
        process::exit_now(show_failure(id, args, code));
    }
}

/// What the window says when the browser didn't start: the status, the
/// last thing it said (its log, `log`), and where the rest is.
pub fn failure_text(id: &str, code: i32, log: &str) -> String {
    let (name, _) = describe(id);
    let last = log
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("slate-linux-app:") && !l.starts_with("slate-flatpak:"));
    let said = match last {
        Some(l) if l.chars().count() > 160 => {
            alloc::format!(": \u{201c}{}…\u{201d}", l.chars().take(160).collect::<String>())
        }
        Some(l) => alloc::format!(": \u{201c}{l}\u{201d}"),
        None => String::new(),
    };
    alloc::format!("{name} didn't start (status {code}){said}. Everything it said is in ~/{LOG}.")
}

/// The window again, saying why the browser didn't start.
fn show_failure(id: &str, args: &[String], code: i32) -> i32 {
    let log = slate_rt::env::var(b"HOME")
        .and_then(|h| slate_rt::fs::read_file(&slate_rt::fs::join(&h, LOG.as_bytes())).ok())
        .map(|t| String::from(slate_rt::lossy(&t)))
        .unwrap_or_default();
    crate::trace!("web-browser: {id} didn't start (status {code})");
    let mut b = Browser::new(id, Needs { setup: false, fetch: false }, args.to_vec());
    b.stage = Stage::Failed(failure_text(id, code, &log));
    kit::run("web-browser", "browser", None, Hints { min: (520, 300), size: (600, 320) }, &mut b)
}

/// The browser's output goes to [`LOG`] in the person's home, where it
/// can be read when the browser doesn't start (otherwise it would reach
/// Strata's console, which nobody sees).
fn log_output() {
    use slate_rt::fs;
    let Some(home) = slate_rt::env::var(b"HOME") else { return };
    for dir in [".cache", ".cache/slate"] {
        let _ = fs::mkdir(&fs::join(&home, dir.as_bytes()), 0o755);
    }
    if let Ok(fd) = fs::open(&fs::join(&home, LOG.as_bytes()), fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC, 0o644) {
        let _ = slate_rt::process::dup2(fd, 1);
        let _ = slate_rt::process::dup2(fd, 2);
        let _ = slate_rt::io::close(fd);
    }
}

/// Where the browser's output goes, from the home directory.
pub const LOG: &str = ".cache/slate/browser.log";

impl App for Browser {
    fn draw(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area) {
        self.hits.clear();
        let (x, w) = (a.x + 32.0, a.w - 64.0);
        let mut y = a.y + 30.0;
        let (name, maker) = describe(&self.id);
        let title = p.style(&f.medium, 20.0, pal.chalk);
        let body = p.style(&f.regular, 14.0, pal.text_2);
        let meta = p.style(&f.mono, 11.5, pal.text_4);
        p.icon(Icon::Globe, x, y + 2.0, 30.0, pal.text_1);
        p.line(&title, x + 46.0, y + 2.0, 28.0, "Web Browser");
        y += 58.0;
        let para = |p: &mut Painter<'_>, y: &mut f32, text: &str| {
            for l in slate_ui::text::wrap(&body, text, w * p.scale) {
                p.line(&body, x, *y, 21.0, &l);
                *y += 21.0;
            }
            *y += 10.0;
        };
        // Installed already: the window is only here to say it didn't start.
        let installed = !self.needs.setup && !self.needs.fetch;
        if !installed {
            para(
                p,
                &mut y,
                &alloc::format!(
                    "Slate doesn't come with a web browser of its own. It can fetch {name} from Flathub, as {maker} \
                     publishes it there, check that it is signed, and keep it up to date for you."
                ),
            );
            para(
                p,
                &mut y,
                &alloc::format!(
                    "{name} runs in a sandbox of its own, apart from Slate; of your files, it sees only Downloads."
                ),
            );
        }
        if self.needs.setup {
            para(
                p,
                &mut y,
                "First it sets up the Linux runtime it runs in (a few hundred megabytes), which asks for your password.",
            );
        }
        // Which browser: a row each, the chosen one marked.
        if self.choosing && !matches!(self.stage, Stage::SettingUp | Stage::Fetching) {
            let picked = self.picked();
            for (i, (_, bname, bmaker)) in OFFERED.iter().enumerate() {
                let row = Area::new(x, y, w, 30.0);
                let on = i == picked;
                let dot = Area::new(x + 2.0, y + 8.0, 14.0, 14.0);
                p.border(dot, 7.0, 1.5, if on { pal.chalk } else { pal.text_4 });
                if on {
                    p.fill(dot.grow(-4.0), 3.0, pal.chalk);
                }
                let st = p.style(&f.medium, 14.0, if on { pal.text_1 } else { pal.text_2 });
                let nw = p.line(&st, x + 26.0, y, 30.0, bname);
                p.line(&meta, x + 26.0 + nw + 10.0, y + 1.0, 30.0, &alloc::format!("from {bmaker}"));
                self.hits.push((row, Button::Pick(i)));
                y += 30.0;
            }
            y += 8.0;
        }
        y += 6.0;
        match &self.stage {
            Stage::SettingUp | Stage::Fetching => {
                // One step of two when both are needed, and how far it is.
                let (step, pct) = if self.stage == Stage::SettingUp {
                    (1, self.setup.as_ref().map(|s| s.fraction()))
                } else {
                    (self.steps, self.fetched)
                };
                let mut what = if self.stage == Stage::SettingUp {
                    String::from("Setting up the Linux runtime")
                } else {
                    alloc::format!("Fetching {name} from Flathub")
                };
                if self.steps > 1 {
                    what = alloc::format!("{what} ({step} of {})", self.steps);
                }
                let what = match pct {
                    Some(f) => alloc::format!("{what}: {}%", (f * 100.0) as u32),
                    None => alloc::format!("{what}…"),
                };
                // A spinner, what is under way and how long it has taken,
                // a bar (how far setup is; sliding while fetching), and
                // what the work said last.
                kit::spinner(p, pal, x, y + 1.0, 20.0, self.now);
                let s = p.style(&f.medium, 14.0, pal.text_1);
                let tw = p.line(&s, x + 30.0, y, 22.0, &what);
                p.line(&meta, x + 30.0 + tw + 12.0, y + 4.0, 16.0, &self.elapsed());
                let fraction = if self.stage == Stage::SettingUp {
                    Some(self.setup.as_ref().map_or(0.0, |s| s.fraction()))
                } else {
                    self.fetched
                };
                kit::progress_bar(p, pal, Area::new(x, y + 34.0, w, 6.0), fraction, self.now);
                let detail = match (&self.stage, &self.setup, &self.said) {
                    (Stage::SettingUp, Some(s), _) => s.say(),
                    (Stage::SettingUp, None, _) => String::from("Waiting for approval…"),
                    (_, _, Some(said)) => String::from(said.strip_prefix("slate-flatpak: ").unwrap_or(said)),
                    _ => String::from("the browser opens by itself"),
                };
                p.line(&meta, x, y + 50.0, 16.0, &kit::fit(p, &meta, &detail, w));
            }
            stage => {
                if let Stage::Failed(why) = stage {
                    let c = pal.accents.clay;
                    let st = p.style(&f.regular, 13.0, c.text);
                    for l in slate_ui::text::wrap(&st, why, w * p.scale) {
                        p.line(&st, x, y, 20.0, &l);
                        y += 20.0;
                    }
                    y += 12.0;
                }
                let get = if matches!(stage, Stage::Failed(_)) {
                    String::from("Try again")
                } else {
                    alloc::format!("Get {name}")
                };
                let mut bx = x;
                let close = String::from(if installed { "Close" } else { "Not now" });
                for (i, (b, text)) in [(Button::Get, get), (Button::NotNow, close)].into_iter().enumerate() {
                    let s = p.style(&f.medium, 13.0, pal.text_1);
                    let bw = p.measure(&s, &text) + 36.0;
                    let r = Area::new(bx, y, bw, 38.0);
                    kit::button(p, pal, f, r, &text, i == 0, i == self.focus);
                    self.hits.push((r, b));
                    bx += bw + 10.0;
                }
            }
        }
        let working = matches!(self.stage, Stage::SettingUp | Stage::Fetching);
        let installed = !self.needs.setup && !self.needs.fetch;
        let hints: &[(&str, &str)] = match (working, installed, self.choosing) {
            (true, _, _) => &[],
            (_, true, _) => &[("enter", "go"), ("tab", "next"), ("esc", "close")],
            (_, _, true) => &[("up down", "browser"), ("enter", "go"), ("tab", "next"), ("esc", "not now")],
            _ => &[("enter", "go"), ("tab", "next"), ("esc", "not now")],
        };
        kit::hints(p, pal, f, a, hints);
    }

    fn key(&mut self, code: u16, _ch: Option<char>, _mods: u8) -> Effect {
        if self.job.is_some() {
            return Effect::None;
        }
        match code {
            // Two buttons: either way round is the other one.
            KEY_TAB => {
                self.focus = (self.focus + 1) % 2;
                Effect::Redraw
            }
            KEY_UP | KEY_DOWN if self.choosing => {
                let n = OFFERED.len();
                let i = if code == KEY_UP { self.picked() + n - 1 } else { self.picked() + 1 };
                self.pick(i % n);
                Effect::Redraw
            }
            KEY_ENTER | KEY_KPENTER => self.press(if self.focus == 0 { Button::Get } else { Button::NotNow }),
            KEY_ESC => self.press(Button::NotNow),
            _ => Effect::None,
        }
    }

    fn click(&mut self, x: f32, y: f32) -> Effect {
        if self.job.is_some() {
            return Effect::None;
        }
        match self.hits.iter().find(|(a, _)| a.contains(x, y)).map(|(_, b)| *b) {
            Some(b) => self.press(b),
            None => Effect::None,
        }
    }

    fn done(&self) -> bool {
        self.done
    }

    fn tick(&mut self, now: Now) -> bool {
        self.now = now.mono;
        if let Some(j) = &mut self.job {
            if let Some(r) = j.poll() {
                self.job = None;
                self.finished(r);
                return true;
            }
            if let Some(t) = &j.progress {
                // How far, when slate-flatpak says so; said at each tenth.
                if let Some(f) = kit::flatpak_fraction(t) {
                    if self.fetched.is_none_or(|was| (was * 10.0) as u32 != (f * 10.0) as u32) {
                        crate::trace!("web-browser: fetching {}%: {t}", (f * 100.0) as u32);
                    }
                    self.fetched = Some(f);
                }
                self.said = Some(t.clone());
            }
        }
        if self.stage == Stage::SettingUp {
            let p = kit::SetupProgress::read();
            if p.is_some() && p != self.setup {
                if let Some(s) = &p {
                    crate::trace!("web-browser: setup: {}", s.say());
                }
                self.setup = p;
            }
        }
        // The spinner turns while the work goes on.
        self.job.is_some()
    }

    fn wake(&self, _now: Now) -> Option<i64> {
        self.job.is_some().then_some(kit::SPIN_MS)
    }
}

/// The broker's `browser=setup`, saying how far it is as setup goes on
/// (it can take minutes, and the broker's child says nothing itself).
fn setup_on_terminal() -> Result<(), String> {
    let mut job = Job::start(|| kit::broker("browser=setup").map(|()| String::new()))?;
    let mut said = String::new();
    loop {
        if let Some(r) = job.poll() {
            return r.map(|_| ());
        }
        if let Some(p) = kit::SetupProgress::read() {
            let now = p.say();
            if now != said {
                slate_rt::println!("web-browser: {now}");
                said = now;
            }
        }
        slate_rt::time::sleep_ns(500_000_000);
    }
}

/// `web-browser --get`: first use on the terminal.
fn get_on_terminal(id: &str) -> i32 {
    let needs = Needs::read(id);
    let (name, maker) = describe(id);
    if needs.setup {
        slate_rt::println!("web-browser: setting up the Linux runtime (it asks for approval)");
        if let Err(e) = setup_on_terminal() {
            slate_rt::eprintln!("web-browser: the Linux runtime wasn't set up: {e}");
            return 1;
        }
    }
    if needs.fetch {
        slate_rt::println!("web-browser: fetching {name} from Flathub, as {maker} publishes it");
        let argv: Vec<Vec<u8>> = [SLATE_FLATPAK, "install", id].iter().map(|a| a.as_bytes().to_vec()).collect();
        let ok = match slate_rt::process::fork() {
            Ok(0) => {
                let e = slate_rt::process::execve(SLATE_FLATPAK.as_bytes(), &argv, slate_rt::env::vars());
                slate_rt::eprintln!("web-browser: {SLATE_FLATPAK}: {e}");
                slate_rt::process::exit_now(127)
            }
            Ok(pid) => slate_rt::process::wait(pid, 0).is_ok_and(|(_, s)| s == 0),
            Err(_) => false,
        };
        if !ok {
            slate_rt::eprintln!("web-browser: {name} wasn't fetched");
            return 1;
        }
    }
    if let Err(e) = kit::save_config(CHOICE, &choice_text(id)) {
        slate_rt::eprintln!("web-browser: {e}");
        return 1;
    }
    slate_rt::println!("web-browser: {name} is ready");
    0
}

pub fn main() -> i32 {
    let args: Vec<String> = slate_rt::env::args().iter().skip(1).map(|a| String::from(slate_rt::lossy(a))).collect();
    let chosen = kit::load_config(CHOICE).and_then(|t| parse_choice(&t));
    match args.first().map(String::as_str) {
        Some("--get") => return get_on_terminal(chosen.as_deref().unwrap_or(FIREFOX)),
        Some("--use") => {
            return match args.get(1).and_then(|id| parse_choice(&alloc::format!("app={id}"))) {
                Some(id) if installed(&id) => match kit::save_config(CHOICE, &choice_text(&id)) {
                    Ok(()) => 0,
                    Err(e) => {
                        slate_rt::eprintln!("web-browser: {e}");
                        1
                    }
                },
                Some(id) => {
                    slate_rt::eprintln!("web-browser: {id} isn't installed (slate-flatpak install {id})");
                    1
                }
                None => {
                    slate_rt::eprintln!("usage: web-browser [--get | --use APP-ID | URL...]");
                    2
                }
            };
        }
        _ => {}
    }
    let id = chosen.unwrap_or_else(|| String::from(FIREFOX));
    let needs = Needs::read(&id);
    if !needs.setup && !needs.fetch {
        // The browser is there: start it, nothing of our own to show.
        start_browser(&id, &args);
        return 0;
    }
    crate::trace!(
        "web-browser: offering {id} (set up: {}, fetch: {})",
        if needs.setup { "needed" } else { "done" },
        if needs.fetch { "needed" } else { "done" }
    );
    let mut b = Browser::new(&id, needs, args);
    kit::run("web-browser", "browser", None, Hints { min: (520, 380), size: (600, 440) }, &mut b)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn choices() {
        assert_eq!(parse_choice(&choice_text(FIREFOX)).as_deref(), Some(FIREFOX));
        assert_eq!(parse_choice("app=com.brave.Browser\n").as_deref(), Some("com.brave.Browser"));
        assert_eq!(parse_choice("app=firefox\n"), None);
        assert_eq!(parse_choice("app=org.evil.x;rm -rf\n"), None);
        assert_eq!(describe(FIREFOX), ("Firefox", "Mozilla"));
        assert_eq!(describe("com.brave.Browser").0, "Browser");
        assert_eq!(describe(LIBREWOLF), ("LibreWolf", "the LibreWolf community"));
    }

    #[test]
    fn first_use() {
        let mut b = Browser::new(FIREFOX, Needs { setup: true, fetch: true }, Vec::new());
        // The approval refused: nothing changed, and Get again.
        b.stage = Stage::SettingUp;
        b.finished(Err("cancelled".into()));
        assert_eq!(b.stage, Stage::Failed("Nothing was changed.".into()));
        b.stage = Stage::SettingUp;
        b.finished(Err("slate-linux setup flatpak failed".into()));
        assert!(matches!(&b.stage, Stage::Failed(w) if w.starts_with("The Linux runtime wasn't set up")));
        b.stage = Stage::Fetching;
        b.needs.setup = false;
        b.finished(Err("no network".into()));
        assert_eq!(b.stage, Stage::Failed("Firefox wasn't fetched: no network".into()));
        assert!(!b.done);
    }

    #[test]
    fn progress() {
        assert_eq!(kit::flatpak_fraction("slate-flatpak: 42% of 173.8 MB: org.mozilla.firefox (2 of 2)"), Some(0.42));
        assert_eq!(kit::flatpak_fraction("Installing app/org.mozilla.firefox/x86_64/stable"), None);
        let b = Browser::new(FIREFOX, Needs { setup: true, fetch: true }, Vec::new());
        assert_eq!(b.steps, 2);
        assert_eq!(Browser::new(FIREFOX, Needs { setup: false, fetch: true }, Vec::new()).steps, 1);
    }

    #[test]
    fn choosing() {
        let mut b = Browser::new(FIREFOX, Needs { setup: false, fetch: true }, Vec::new());
        assert!(b.choosing);
        b.key(KEY_DOWN, None, 0);
        assert_eq!(b.id, LIBREWOLF);
        b.key(KEY_DOWN, None, 0);
        assert_eq!(b.id, FIREFOX, "round again");
        b.key(KEY_UP, None, 0);
        assert_eq!(b.id, LIBREWOLF);
        // A browser chosen with --use, or installed, offers no choice.
        assert!(!Browser::new("com.brave.Browser", Needs { setup: false, fetch: true }, Vec::new()).choosing);
        assert!(!Browser::new(FIREFOX, Needs { setup: false, fetch: false }, Vec::new()).choosing);
    }

    #[test]
    fn didnt_start() {
        let log = "Gtk-Message: a theme\nError: no DISPLAY environment variable specified\n\
                   slate-linux-app: /usr/bin/flatpak ended with status 1\n";
        assert_eq!(
            failure_text(FIREFOX, 1, log),
            "Firefox didn't start (status 1): \u{201c}Error: no DISPLAY environment variable specified\u{201d}. \
             Everything it said is in ~/.cache/slate/browser.log."
        );
        assert_eq!(
            failure_text(FIREFOX, 127, ""),
            "Firefox didn't start (status 127). Everything it said is in ~/.cache/slate/browser.log."
        );
    }
}
