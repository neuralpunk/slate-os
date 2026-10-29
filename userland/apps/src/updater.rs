// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Software Updater (ADR 0112), `software-updater`: Slate's release
//! and the running system; what the repositories offer that is newer
//! (`quarry upgrades`); installing it; and the systems kept on the disk,
//! with a rollback to the one before.
//!
//! - **Check for updates** asks the privilege broker for `update=check`
//!   (`quarry update`: the signed indexes), granted to Slate's own
//!   programs without asking. It is done on opening when the last check
//!   is a day old.
//! - **Install** asks for `update=install` (`quarry upgrade`), behind the
//!   approval dialog. quarry installs into a snapshot of the system,
//!   which starts at the next restart, and then into the running system;
//!   the system before stays on the disk as the fallback (ADR 0070).
//! - **Roll back** asks for `rollback` (`slate-update rollback`): the
//!   fallback starts at the next restart. It asks first (Enter twice).
//! - **Restart** asks for `restart`.
//! - `software-updater --install` (Strata's power dialog, "install the
//!   updates first": ADR 0110's addendum) installs at once in its window
//!   and closes it when they are in, ending with 0; if they aren't, the
//!   window says why and the program ends with 1 when it is closed.
//! - **Apps** (ADR 0114): the person's Flatpak apps, from `slate-flatpak
//!   status`, with the newer versions Flathub offers. **Update apps** runs
//!   `slate-flatpak update` (their own installation: no approval), which
//!   keeps each app's version before; **Roll back** on a chosen app
//!   (up and down choose) returns it to that one. Strata also updates
//!   them in the background (ADR 0115); the section says when it last
//!   did, and turns that off and on (`~/.config/strata/app-updates`).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_display::input::{KEY_DOWN, KEY_ENTER, KEY_ESC, KEY_KPENTER, KEY_TAB, KEY_UP};
use slate_rt::subvol::Subvol;
use slate_strata::fonts::Fonts;
use slate_strata_client::mods::{ALT, CTRL, LOGO, SHIFT};
use slate_ui::graphite::Palette;
use slate_ui::icon::Icon;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;

use crate::kit::{self, App, Effect, Hints, Job, Now};

/// Where quarry keeps the verified indexes; their age is the last check.
const INDEXES: &str = "/var/lib/quarry/index";
/// The Linux runtime's Flatpak: with it, the Apps section is shown.
const FLATPAK: &str = "/var/lib/slate/linux/usr/bin/flatpak";
const SLATE_FLATPAK: &str = "/bin/slate-flatpak";
/// The background app updates' setting and log (slate-flatpak's, ADR
/// 0115), in the person's home.
const AUTO_SETTINGS: &str = "app-updates";
const AUTO_LOG: &[u8] = b".cache/slate/app-updates.log";
/// What separates quarry's lines from the apps' in a check's output.
const APPS_AFTER: &str = "\n\x1eapps\n";
/// A check older than this is done again on opening (seconds).
const STALE_S: i64 = 24 * 3600;
/// How many updates the last check found, in the person's home: Strata's
/// top bar shows them (`software-updater --check` writes it).
pub const COUNT: &[u8] = b".cache/slate/updates";
/// quarry's account of an upgrade under way (its `PROGRESS`).
const PROGRESS: &[u8] = b"/run/quarry-progress";

/// How far an upgrade is: in the new system (downloading) or the
/// running one, the package of how many, and its bytes so far.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Progress {
    pub running: bool,
    pub step: usize,
    pub steps: usize,
    pub got: u64,
    pub size: u64,
    pub name: String,
}

/// quarry's progress line: `PASS STEP STEPS GOT SIZE NAME`.
pub fn parse_progress(text: &str) -> Option<Progress> {
    let mut w = text.split_whitespace();
    let running = match w.next()? {
        "new" => false,
        "running" => true,
        _ => return None,
    };
    let (step, steps, got, size) =
        (w.next()?.parse().ok()?, w.next()?.parse().ok()?, w.next()?.parse().ok()?, w.next()?.parse().ok()?);
    Some(Progress { running, step, steps, got, size, name: w.next()?.to_string() })
}

/// What the window says while installing.
pub fn installing_text(p: Option<&Progress>) -> String {
    match p {
        Some(p) if p.running => alloc::format!("Bringing the running system up to date: {} of {}", p.step, p.steps),
        Some(p) => {
            let pct = (p.got.min(p.size) * 100).checked_div(p.size).map_or(String::new(), |n| alloc::format!("{n}%, "));
            alloc::format!("Installing the updates: {} ({pct}{} of {})", p.name, p.step, p.steps)
        }
        None => String::from("Installing the updates…"),
    }
}

/// Keep how many updates there are where Strata's top bar reads it.
fn save_count(n: usize) {
    use slate_rt::fs;
    // Host tests leave the developer's home alone.
    if cfg!(test) {
        return;
    }
    let Some(home) = slate_rt::env::var(b"HOME") else { return };
    for d in [".cache", ".cache/slate"] {
        let _ = fs::mkdir(&fs::join(&home, d.as_bytes()), 0o755);
    }
    let _ = fs::write_file(&fs::join(&home, COUNT), alloc::format!("{n}\n").as_bytes(), 0o644);
}

/// `software-updater --check`: fetch the indexes and keep the count, for
/// Strata's background check (no window).
fn check_quietly() -> i32 {
    let r = kit::broker("update=check").and_then(|()| kit::output("/bin/quarry", &["upgrades"]));
    match r {
        Ok(t) => {
            let n = parse_upgrades(&t).len();
            crate::trace!("software-updater: background check: {n} updates");
            save_count(n);
            0
        }
        Err(e) => {
            slate_rt::eprintln!("software-updater: couldn't check for updates: {e}");
            1
        }
    }
}

/// A package with a newer version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub name: String,
    /// None: new to the system (another needs it).
    pub old: Option<String>,
    pub new: String,
    pub size: u64,
    pub summary: String,
}

/// `quarry upgrades`' lines: NAME OLD NEW SIZE SUMMARY, tab-separated.
pub fn parse_upgrades(text: &str) -> Vec<Update> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.splitn(5, '\t').collect();
            Some(Update {
                name: f.first()?.to_string(),
                old: f.get(1).filter(|o| **o != "-").map(|o| o.to_string()),
                new: f.get(2)?.to_string(),
                size: f.get(3).and_then(|s| s.parse().ok()).unwrap_or(0),
                summary: f.get(4).unwrap_or(&"").to_string(),
            })
        })
        .collect()
}

/// A Flatpak app (`slate-flatpak status`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlatApp {
    pub id: String,
    pub name: String,
    pub version: String,
    /// The newer version on offer.
    pub new: Option<String>,
    /// An earlier version is kept to go back to.
    pub back: bool,
}

/// The background updates' last run from their log: when, and whether it
/// failed (its lines are `SECONDS updated` or `SECONDS failed: ...`).
pub fn parse_auto_log(text: &str) -> Option<(i64, bool)> {
    let last = text.lines().rev().find(|l| !l.trim().is_empty())?;
    let (t, what) = last.split_once(' ')?;
    Some((t.parse().ok()?, what.starts_with("failed")))
}

/// `slate-flatpak status`' lines: ID NAME VERSION NEW BACK, tab-separated.
pub fn parse_apps(text: &str) -> Vec<FlatApp> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            Some(FlatApp {
                id: f.first().filter(|i| !i.is_empty())?.to_string(),
                name: f.get(1)?.to_string(),
                version: f.get(2)?.to_string(),
                new: f.get(3).filter(|n| **n != "-").map(|n| n.to_string()),
                back: f.get(4) == Some(&"yes"),
            })
        })
        .collect()
}

/// What is going on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Work {
    Checking,
    Installing,
    RollingBack,
    Restarting,
    /// Only the apps (on opening, and after their changes).
    CheckingApps,
    UpdatingApps,
    RollingBackApp,
}

/// The buttons, in their order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Button {
    Install,
    Check,
    RollBack,
    Restart,
    UpdateApps,
    RollBackApp,
    /// Background app updates on or off.
    AutoApps,
}

#[derive(Debug)]
pub struct Updater {
    pub release: String,
    /// The system subvolumes (`system-N`), the newest first.
    pub systems: Vec<Subvol>,
    pub updates: Vec<Update>,
    /// The Flatpak apps; None without Flatpak.
    pub apps: Option<Vec<FlatApp>>,
    /// The app chosen (for its rollback).
    pub app: usize,
    /// Background app updates are on; when they last ran (seconds), and
    /// whether that run failed.
    pub auto: bool,
    pub auto_last: Option<(i64, bool)>,
    /// When the indexes were last fetched (seconds since the epoch).
    pub checked: Option<i64>,
    /// The time now (seconds since the epoch), for "an hour ago".
    pub now: i64,
    pub work: Option<Work>,
    /// What the last action did, and whether it failed.
    pub status: Option<(String, bool)>,
    /// How far an install is, as quarry says.
    pub progress: Option<Progress>,
    /// A restart would start a different system than the running one.
    pub restart_wanted: bool,
    /// The rollback asked about: Enter again does it.
    pub confirm: bool,
    pub focus: usize,
    /// Installing for a restart or shut down: the window closes once the
    /// updates are in.
    pub then: bool,
    pub installed: bool,
    job: Option<Job>,
    hits: Vec<(Area, Button)>,
    hits_apps: Vec<(Area, usize)>,
}

fn system_number(s: &Subvol) -> u64 {
    slate_rt::subvol::system_number(&s.name).unwrap_or(0)
}

impl Updater {
    pub fn new(
        release: String,
        mut systems: Vec<Subvol>,
        updates: Vec<Update>,
        checked: Option<i64>,
        now: i64,
    ) -> Updater {
        systems.retain(|s| slate_rt::subvol::system_number(&s.name).is_some());
        systems.sort_by_key(|s| core::cmp::Reverse(system_number(s)));
        let mut u = Updater {
            release,
            systems,
            updates,
            apps: None,
            app: 0,
            auto: true,
            auto_last: None,
            checked,
            now,
            work: None,
            status: None,
            progress: None,
            restart_wanted: false,
            confirm: false,
            focus: 0,
            then: false,
            installed: false,
            job: None,
            hits: Vec::new(),
            hits_apps: Vec::new(),
        };
        u.restart_wanted = u.running() != u.next();
        u
    }

    /// The release, systems and pending updates as they are now.
    pub fn read() -> Updater {
        let release = slate_rt::fs::read_file(b"/usr/share/slate/release")
            .map(|b| String::from(slate_rt::lossy(&b).trim()))
            .unwrap_or_else(|_| String::from("Slate"));
        let updates = kit::output("/bin/quarry", &["upgrades"]).map(|t| parse_upgrades(&t)).unwrap_or_default();
        let checked = slate_rt::fs::read_dir(INDEXES.as_bytes()).ok().and_then(|es| {
            es.iter()
                .filter_map(|e| slate_rt::fs::stat(&slate_rt::fs::join(INDEXES.as_bytes(), &e.name)).ok())
                .map(|s| s.mtime)
                .max()
        });
        let now = Now::read().wall / 1000;
        save_count(updates.len());
        let mut u = Updater::new(release, slate_rt::subvol::list().unwrap_or_default(), updates, checked, now);
        // Filled in by a check of the apps.
        if slate_rt::fs::exists(FLATPAK.as_bytes()) {
            u.apps = Some(Vec::new());
        }
        u.auto = kit::load_config(AUTO_SETTINGS).is_none_or(|t| !t.lines().any(|l| l.trim() == "auto=off"));
        let log =
            slate_rt::env::var(b"HOME").and_then(|h| slate_rt::fs::read_file(&slate_rt::fs::join(&h, AUTO_LOG)).ok());
        u.auto_last = log.and_then(|l| parse_auto_log(&slate_rt::lossy(&l)));
        u
    }

    fn reload(&mut self) {
        let fresh = Updater::read();
        self.release = fresh.release;
        self.systems = fresh.systems;
        self.updates = fresh.updates;
        self.checked = fresh.checked;
        self.now = fresh.now;
        // (The apps keep what their last check said.)
        self.restart_wanted = self.running() != self.next();
    }

    fn flagged(&self, flag: &str) -> Option<&str> {
        self.systems.iter().find(|s| s.has(flag)).map(|s| s.name.as_str())
    }

    pub fn running(&self) -> Option<&str> {
        self.flagged("mounted-here")
    }

    /// The system the next restart starts.
    pub fn next(&self) -> Option<&str> {
        self.flagged("default")
    }

    /// The system a rollback would start: the fallback, if it isn't the
    /// one starting next anyway.
    pub fn rollback_to(&self) -> Option<&str> {
        self.flagged("fallback").filter(|f| Some(*f) != self.next())
    }

    /// Whether the check on opening is due.
    pub fn stale(&self) -> bool {
        self.checked.is_none_or(|t| self.now - t > STALE_S)
    }

    fn app_updates(&self) -> usize {
        self.apps.as_ref().map_or(0, |a| a.iter().filter(|a| a.new.is_some()).count())
    }

    /// The chosen app, if it can be rolled back.
    fn app_back(&self) -> Option<&FlatApp> {
        self.apps.as_ref()?.get(self.app).filter(|a| a.back)
    }

    /// The buttons offered now, in order.
    pub fn buttons(&self) -> Vec<Button> {
        let mut b = Vec::new();
        if !self.updates.is_empty() {
            b.push(Button::Install);
        }
        if self.app_updates() > 0 {
            b.push(Button::UpdateApps);
        }
        b.push(Button::Check);
        if self.app_back().is_some() {
            b.push(Button::RollBackApp);
        }
        if self.apps.as_ref().is_some_and(|a| !a.is_empty()) {
            b.push(Button::AutoApps);
        }
        if self.rollback_to().is_some() {
            b.push(Button::RollBack);
        }
        if self.restart_wanted {
            b.push(Button::Restart);
        }
        b
    }

    pub fn say(&self) {
        crate::trace!(
            "software-updater: {}, running {}, {} starts next",
            self.release,
            self.running().unwrap_or("?"),
            self.next().unwrap_or("?")
        );
    }

    fn start(&mut self, work: Work) {
        if self.job.is_some() {
            return;
        }
        let flatpak = self.apps.is_some();
        let app = self.app_back().map(|a| a.id.clone()).unwrap_or_default();
        let job = match work {
            Work::Checking => Job::start(move || {
                kit::broker("update=check")?;
                let mut out = kit::output("/bin/quarry", &["upgrades"])?;
                if flatpak {
                    // The apps' check failing (offline) isn't the system's.
                    out.push_str(APPS_AFTER);
                    out.push_str(&kit::output(SLATE_FLATPAK, &["status"]).unwrap_or_default());
                }
                Ok(out)
            }),
            Work::CheckingApps => Job::start(|| kit::output(SLATE_FLATPAK, &["status"])),
            Work::UpdatingApps => Job::start(|| kit::output(SLATE_FLATPAK, &["update"])),
            Work::RollingBackApp => Job::start(move || kit::output(SLATE_FLATPAK, &["rollback", &app])),
            Work::Installing => Job::start(|| kit::broker("update=install").map(|()| String::new())),
            Work::RollingBack => Job::start(|| kit::broker("rollback").map(|()| String::new())),
            Work::Restarting => Job::start(|| kit::broker("restart").map(|()| String::new())),
        };
        match job {
            Ok(j) => {
                self.job = Some(j);
                self.work = Some(work);
                self.status = None;
            }
            Err(e) => self.status = Some((alloc::format!("Couldn't start: {e}"), true)),
        }
    }

    /// The outcome of `work`; the caller reads the system again after
    /// one that changed it.
    pub fn finished(&mut self, work: Work, r: Result<String, String>) {
        self.work = None;
        self.status = match (work, r) {
            (_, Err(e)) if e == "cancelled" => Some((String::from("Nothing was changed."), false)),
            (Work::Checking, Err(e)) => Some((alloc::format!("Couldn't check for updates: {e}"), true)),
            (Work::Checking, Ok(text)) => {
                let (system, apps) = match text.split_once(APPS_AFTER) {
                    Some((s, a)) => (s, Some(a)),
                    None => (text.as_str(), None),
                };
                if let Some(a) = apps {
                    self.set_apps(parse_apps(a));
                }
                self.updates = parse_upgrades(system);
                save_count(self.updates.len());
                self.checked = Some(self.now);
                let list: Vec<String> = self
                    .updates
                    .iter()
                    .map(|u| alloc::format!("{} {} -> {}", u.name, u.old.as_deref().unwrap_or("new"), u.new))
                    .collect();
                crate::trace!("software-updater: checked: {} updates: {}", self.updates.len(), list.join(", "));
                if self.updates.is_empty() && self.app_updates() == 0 {
                    Some((String::from("Slate is up to date."), false))
                } else {
                    None
                }
            }
            (Work::CheckingApps, Ok(text)) => {
                self.set_apps(parse_apps(&text));
                None
            }
            // Offline, say: the apps stay as they were.
            (Work::CheckingApps, Err(_)) => None,
            (Work::UpdatingApps, Ok(_)) => {
                crate::trace!("software-updater: apps updated");
                Some((String::from("The apps are updated. Each one's version before is kept to go back to."), false))
            }
            (Work::UpdatingApps, Err(e)) => Some((alloc::format!("The apps weren't updated: {e}"), true)),
            (Work::RollingBackApp, Ok(_)) => {
                let name = self.app_back().map_or_else(|| String::from("The app"), |a| a.name.clone());
                crate::trace!("software-updater: rolled back {name}");
                Some((alloc::format!("{name} is back to its version before."), false))
            }
            (Work::RollingBackApp, Err(e)) => Some((alloc::format!("Couldn't roll back the app: {e}"), true)),
            (Work::Installing, Ok(_)) => {
                self.updates.clear();
                self.installed = true;
                save_count(0);
                let next = self.next().unwrap_or("The new system").to_string();
                let before = self.running().unwrap_or("the system before").to_string();
                crate::trace!("software-updater: installed; {next} starts next");
                Some((
                    alloc::format!(
                        "The updates are installed and in use. {next} starts from the next restart; {before} is kept to go back to."
                    ),
                    false,
                ))
            }
            (Work::Installing, Err(e)) if self.then => Some((
                alloc::format!("The updates weren't installed: {e}. Close this window to choose what happens next."),
                true,
            )),
            (Work::Installing, Err(e)) => Some((alloc::format!("The updates weren't installed: {e}"), true)),
            (Work::RollingBack, Ok(_)) => {
                let next = self.next().unwrap_or("The system before").to_string();
                crate::trace!("software-updater: rolled back; {next} starts next");
                Some((alloc::format!("{next} starts at the next restart."), false))
            }
            (Work::RollingBack, Err(e)) => Some((alloc::format!("Couldn't roll back: {e}"), true)),
            (Work::Restarting, Ok(_)) => Some((String::from("Restarting…"), false)),
            (Work::Restarting, Err(e)) => Some((alloc::format!("Couldn't restart: {e}"), true)),
        };
    }

    fn set_apps(&mut self, apps: Vec<FlatApp>) {
        let list: Vec<String> = apps
            .iter()
            .map(|a| match &a.new {
                Some(n) => alloc::format!("{} {} -> {n}", a.id, a.version),
                None => alloc::format!("{} {}", a.id, a.version),
            })
            .collect();
        crate::trace!("software-updater: apps: {}", list.join(", "));
        self.app = self.app.min(apps.len().saturating_sub(1));
        self.apps = Some(apps);
    }

    fn press(&mut self, b: Button) -> Effect {
        match b {
            Button::UpdateApps => self.start(Work::UpdatingApps),
            Button::AutoApps => {
                self.auto = !self.auto;
                let text = if self.auto { "auto=on\n" } else { "auto=off\n" };
                self.status = Some(match kit::save_config(AUTO_SETTINGS, text) {
                    Ok(()) if self.auto => (String::from("Apps update by themselves again."), false),
                    Ok(()) => (String::from("Apps update only when you say so."), false),
                    Err(e) => (alloc::format!("Couldn't change that: {e}"), true),
                });
                crate::trace!("software-updater: automatic app updates {}", if self.auto { "on" } else { "off" });
            }
            Button::RollBackApp => self.start(Work::RollingBackApp),
            Button::Install => self.start(Work::Installing),
            Button::Check => self.start(Work::Checking),
            Button::RollBack if self.confirm => {
                self.confirm = false;
                self.start(Work::RollingBack);
            }
            Button::RollBack => self.confirm = true,
            Button::Restart => self.start(Work::Restarting),
        }
        Effect::Redraw
    }

    fn ago(&self, t: i64) -> String {
        let s = (self.now - t).max(0);
        match s {
            0..60 => String::from("just now"),
            60..3600 => plural(s / 60, "minute"),
            3600..86_400 => plural(s / 3600, "hour"),
            _ => plural(s / 86_400, "day"),
        }
    }
}

fn plural(n: i64, unit: &str) -> String {
    if n == 1 { alloc::format!("1 {unit} ago") } else { alloc::format!("{n} {unit}s ago") }
}

impl App for Updater {
    fn draw(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area) {
        self.hits.clear();
        self.hits_apps.clear();
        let (x, w) = (a.x + 28.0, a.w - 56.0);
        let mut y = a.y + 24.0;
        let title = p.style(&f.medium, 20.0, pal.chalk);
        let desc = p.style(&f.regular, 13.0, pal.text_3);
        let label = p.style(&f.mono, 11.0, pal.muted);
        let name_s = p.style(&f.medium, 14.0, pal.text_1);
        let meta = p.style(&f.mono, 11.5, pal.text_4);
        p.logo(x, y + 2.0, 34.0, pal.text_1);
        p.line(&title, x + 50.0, y, 26.0, &self.release);
        let last = match (self.work, self.checked) {
            (Some(Work::Checking), _) => String::from("Checking for updates…"),
            (_, Some(t)) => alloc::format!("Last checked {}", self.ago(t)),
            (_, None) => String::from("Not checked yet"),
        };
        p.line(&desc, x + 50.0, y + 26.0, 18.0, &last);
        y += 76.0;
        // The updates.
        let headline = match (self.work, self.updates.len()) {
            (Some(Work::Installing), _) => installing_text(self.progress.as_ref()),
            (_, 0) => String::from("Slate is up to date"),
            (_, 1) => String::from("1 update"),
            (_, n) => alloc::format!("{n} updates"),
        };
        let h = p.style(&f.medium, 15.0, pal.text_1);
        p.line(&h, x, y, 22.0, &headline);
        if !self.updates.is_empty() {
            let total: u64 = self.updates.iter().map(|u| u.size).sum();
            let s = alloc::format!("{} to download", slate_sysinfo::size(total));
            let sw = p.measure(&meta, &s);
            p.line(&meta, x + w - sw, y + 4.0, 16.0, &s);
        }
        y += 32.0;
        let room = ((a.y + a.h * 0.55 - y) / 48.0).max(1.0) as usize;
        for u in self.updates.iter().take(room) {
            let r = Area::new(x, y, w, 42.0);
            p.fill(r, 8.0, pal.raised);
            p.icon(Icon::Archive, r.x + 12.0, r.y + 12.0, 18.0, pal.text_3);
            let n = p.line(&name_s, r.x + 42.0, r.y + 3.0, 20.0, &u.name);
            let ver = alloc::format!("{} to {}", u.old.as_deref().unwrap_or("new"), u.new);
            p.line(&meta, r.x + 52.0 + n, r.y + 5.0, 16.0, &ver);
            let sum = kit::fit(p, &desc, &u.summary, r.w - 60.0);
            p.line(&desc, r.x + 42.0, r.y + 21.0, 18.0, &sum);
            y += 48.0;
        }
        if self.updates.len() > room {
            p.line(&label, x, y, 16.0, &alloc::format!("and {} more", self.updates.len() - room));
            y += 22.0;
        }
        // The apps.
        if let Some(apps) = &self.apps
            && !apps.is_empty()
        {
            y += 8.0;
            let n = self.app_updates();
            let mut head = match n {
                0 => String::from("apps · up to date"),
                1 => String::from("apps · 1 update"),
                n => alloc::format!("apps · {n} updates"),
            };
            head.push_str(&match (self.auto, self.auto_last) {
                (false, _) => String::from(" · automatic updates off"),
                (true, Some((t, false))) => alloc::format!(" · updated by themselves {}", self.ago(t)),
                (true, Some((t, true))) => alloc::format!(" · the last automatic update failed, {}", self.ago(t)),
                (true, None) => String::from(" · they update by themselves"),
            });
            p.line(&label, x, y, 16.0, &head);
            y += 22.0;
            for (i, app) in apps.iter().enumerate().take(4) {
                let r = Area::new(x, y, w, 34.0);
                // The chosen one inverted, as list rows are.
                let sel = i == self.app && apps.len() > 1;
                p.fill(r, 8.0, if sel { pal.list_selected } else { pal.raised });
                let (ink, ink_meta) = if sel { (pal.window, pal.window) } else { (pal.text_1, pal.text_4) };
                p.icon(Icon::Grid, r.x + 12.0, r.y + 8.0, 18.0, if sel { pal.window } else { pal.text_3 });
                let ns = p.style(&f.medium, 14.0, ink);
                let ms = p.style(&f.mono, 11.5, ink_meta);
                let nw = p.line(&ns, r.x + 42.0, r.y + 6.0, 20.0, &app.name);
                p.line(&ms, r.x + 52.0 + nw, r.y + 9.0, 16.0, &app.version);
                let (what, c) = match &app.new {
                    // Selection stays chalk: no colour on it.
                    Some(v) if sel => (alloc::format!("{v} available"), pal.window),
                    Some(v) => (alloc::format!("{v} available"), pal.accents.steel.text),
                    None => (String::from("up to date"), ink_meta),
                };
                let st = p.style(&f.mono, 11.5, c);
                let ww = p.measure(&st, &what);
                p.line(&st, r.x + r.w - 14.0 - ww, r.y + 9.0, 16.0, &what);
                self.hits_apps.push((r, i));
                y += 40.0;
            }
        }
        // The buttons.
        y += 8.0;
        let mut bx = x;
        let buttons = self.buttons();
        self.focus = self.focus.min(buttons.len().saturating_sub(1));
        for (i, b) in buttons.iter().enumerate() {
            let text = match b {
                Button::Install => alloc::format!(
                    "Install {}",
                    if self.updates.len() == 1 {
                        "the update".into()
                    } else {
                        alloc::format!("{} updates", self.updates.len())
                    }
                ),
                Button::Check => {
                    String::from(if self.updates.is_empty() { "Check for updates" } else { "Check again" })
                }
                Button::RollBack => alloc::format!("Roll back to {}", self.rollback_to().unwrap_or("?")),
                Button::Restart => String::from("Restart now"),
                Button::UpdateApps => match self.app_updates() {
                    1 => String::from("Update the app"),
                    n => alloc::format!("Update {n} apps"),
                },
                Button::RollBackApp => alloc::format!("Roll back {}", self.app_back().map_or("", |a| a.name.as_str())),
                Button::AutoApps => {
                    String::from(if self.auto { "Stop automatic updates" } else { "Update apps automatically" })
                }
            };
            let s = p.style(&f.medium, 13.0, pal.text_1);
            let bw = p.measure(&s, &text) + 36.0;
            // A row of its own for those that don't fit.
            if bx > x && bx + bw > x + w {
                bx = x;
                y += 46.0;
            }
            let r = Area::new(bx, y, bw, 38.0);
            kit::button(p, pal, f, r, &text, i == 0, i == self.focus && self.job.is_none());
            self.hits.push((r, *b));
            bx += bw + 10.0;
        }
        y += 62.0;
        // The systems on the disk.
        p.line(&label, x, y, 16.0, "systems on this computer");
        y += 24.0;
        for s in self.systems.iter().take(4) {
            let mut flags: Vec<&str> = Vec::new();
            if s.has("mounted-here") {
                flags.push("running");
            }
            if s.has("default") {
                flags.push("starts next");
            }
            if s.has("fallback") {
                flags.push("kept to go back to");
            }
            p.line(&name_s, x, y, 22.0, &s.name);
            p.line(&meta, x + 120.0, y + 3.0, 16.0, &flags.join(" · "));
            y += 26.0;
        }
        if self.systems.is_empty() {
            p.line(&desc, x, y, 20.0, "This system isn't on SlateFS: it keeps no snapshots to go back to.");
        }
        // The question or the outcome.
        let bottom = a.y + a.h - 76.0;
        if self.confirm {
            let c = pal.accents.ochre;
            let strip = Area::new(x - 10.0, bottom - 12.0, w + 20.0, 44.0);
            p.fill(strip, 8.0, c.tint);
            p.border(strip, 8.0, 1.0, c.border);
            let s = p.style(&f.regular, 13.5, pal.text_1);
            let q = alloc::format!(
                "Start {} at the next restart? {} is kept, to return to. Enter again to roll back.",
                self.rollback_to().unwrap_or("the system before"),
                self.next().unwrap_or("The other system")
            );
            let q = kit::fit(p, &s, &q, strip.w - 28.0);
            p.line(&s, strip.x + 14.0, strip.y + 12.0, 20.0, &q);
        } else if let Some((s, err)) = &self.status {
            let st = p.style(&f.regular, 13.0, if *err { pal.accents.clay.text } else { pal.text_2 });
            let lines = slate_ui::text::wrap(&st, s, w * p.scale);
            let mut sy = bottom - 20.0 * (lines.len().saturating_sub(1)) as f32;
            for l in lines {
                p.line(&st, x, sy, 20.0, &l);
                sy += 20.0;
            }
        }
        let hints: &[(&str, &str)] = if self.confirm {
            &[("enter", "roll back"), ("esc", "cancel")]
        } else {
            if self.apps.as_ref().is_some_and(|a| a.len() > 1) {
                &[("enter", "go"), ("tab", "next"), ("↑↓", "app"), ("c", "check")]
            } else {
                &[("enter", "go"), ("tab", "next"), ("c", "check")]
            }
        };
        kit::hints(p, pal, f, a, hints);
    }

    fn key(&mut self, code: u16, ch: Option<char>, mods: u8) -> Effect {
        if self.job.is_some() {
            return Effect::None;
        }
        let buttons = self.buttons();
        if self.confirm {
            match code {
                KEY_ENTER | KEY_KPENTER => return self.press(Button::RollBack),
                KEY_ESC => {
                    self.confirm = false;
                    return Effect::Redraw;
                }
                _ => return Effect::None,
            }
        }
        match (code, ch.filter(|_| mods & (CTRL | ALT | LOGO) == 0)) {
            (KEY_TAB, _) => {
                let n = buttons.len().max(1);
                self.focus = if mods & SHIFT != 0 { (self.focus + n - 1) % n } else { (self.focus + 1) % n };
                Effect::Redraw
            }
            (KEY_ENTER | KEY_KPENTER, _) => match buttons.get(self.focus) {
                Some(b) => self.press(*b),
                None => Effect::None,
            },
            (KEY_UP | KEY_DOWN, _) if self.apps.as_ref().is_some_and(|a| !a.is_empty()) => {
                let n = self.apps.as_ref().map_or(1, Vec::len);
                self.app = if code == KEY_UP { (self.app + n - 1) % n } else { (self.app + 1) % n };
                Effect::Redraw
            }
            (_, Some('c')) => self.press(Button::Check),
            (_, Some('r')) if buttons.contains(&Button::RollBack) => self.press(Button::RollBack),
            _ => Effect::None,
        }
    }

    fn click(&mut self, x: f32, y: f32) -> Effect {
        if self.job.is_some() {
            return Effect::None;
        }
        if let Some(i) = self.hits_apps.iter().find(|(a, _)| a.contains(x, y)).map(|(_, i)| *i) {
            self.app = i;
            return Effect::Redraw;
        }
        match self.hits.iter().find(|(a, _)| a.contains(x, y)).map(|(_, b)| *b) {
            Some(b) => {
                if b != Button::RollBack {
                    self.confirm = false;
                }
                self.press(b)
            }
            None => Effect::None,
        }
    }

    fn tick(&mut self, now: Now) -> bool {
        self.now = now.wall / 1000;
        // How far an install is.
        let mut moved = false;
        if self.work == Some(Work::Installing) {
            let p = slate_rt::fs::read_file(PROGRESS).ok().and_then(|t| parse_progress(&slate_rt::lossy(&t)));
            if p.is_some() && p != self.progress {
                self.progress = p;
                crate::trace!("software-updater: {}", installing_text(self.progress.as_ref()));
                moved = true;
            }
        }
        if let Some(j) = &mut self.job
            && let Some(r) = j.poll()
        {
            self.job = None;
            self.progress = None;
            let work = self.work.unwrap_or(Work::Checking);
            let changed = r.is_ok() && matches!(work, Work::Installing | Work::RollingBack);
            let r_ok = r.is_ok();
            if changed {
                self.reload();
            }
            self.finished(work, r);
            let said = self.status.clone();
            if changed {
                self.say();
            }
            // What the apps are now.
            if r_ok && matches!(work, Work::UpdatingApps | Work::RollingBackApp) {
                self.start(Work::CheckingApps);
                // (The outcome stays said.)
                self.status = said;
            }
            return true;
        }
        moved
    }

    fn wake(&self, _now: Now) -> Option<i64> {
        // The minute changes "an hour ago" too.
        Some(if self.job.is_some() { kit::JOB_MS } else { 60_000 })
    }

    fn done(&self) -> bool {
        self.then && self.installed
    }
}

pub fn main() -> i32 {
    if slate_rt::env::args().get(1).is_some_and(|a| a == b"--check") {
        return check_quietly();
    }
    let then = slate_rt::env::args().get(1).is_some_and(|a| a == b"--install");
    let mut u = Updater::read();
    u.say();
    if then {
        // Nothing to install (since done): nothing stands in the way.
        if u.updates.is_empty() {
            crate::trace!("software-updater: nothing to install");
            return 0;
        }
        crate::trace!("software-updater: installing before the session ends");
        u.then = true;
        u.start(Work::Installing);
    } else if u.stale() {
        u.start(Work::Checking);
    } else if u.apps.is_some() {
        u.start(Work::CheckingApps);
    }
    let r = kit::run("software-updater", "updater", None, Hints { min: (560, 560), size: (680, 760) }, &mut u);
    if then { i32::from(r != 0 || !u.installed) } else { r }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn sample() -> Updater {
        let sv = |id: u64, name: &str, flags: &[&str]| Subvol {
            id,
            name: name.into(),
            flags: flags.iter().map(|f| f.to_string()).collect(),
        };
        let updates = parse_upgrades(
            "slate-base\t0.1.0\t0.1.1\t48000000\tSlate's base system\nslate-apps\t0.1.0\t0.1.1\t9000000\tSlate's own apps for Strata\nlibnew\t-\t1\t1000\tA library\n",
        );
        Updater::new(
            "Slate 0.1.0".into(),
            std::vec![
                sv(1, "home", &[]),
                sv(3, "system-3", &["default", "mounted-here"]),
                sv(2, "system-2", &["fallback"])
            ],
            updates,
            Some(1_792_870_000),
            1_792_879_170,
        )
    }

    #[test]
    fn progress() {
        let p = parse_progress("new 2 5 524288 1048576 slate-apps\n").unwrap();
        assert_eq!((p.running, p.step, p.steps, p.name.as_str()), (false, 2, 5, "slate-apps"));
        assert_eq!(installing_text(Some(&p)), "Installing the updates: slate-apps (50%, 2 of 5)");
        let r = parse_progress("running 3 5 0 100 slate-base").unwrap();
        assert_eq!(installing_text(Some(&r)), "Bringing the running system up to date: 3 of 5");
        assert_eq!(installing_text(None), "Installing the updates…");
        assert!(parse_progress("half a line").is_none() && parse_progress("").is_none());
    }

    #[test]
    fn what_is_offered() {
        let mut u = sample();
        assert_eq!(u.updates.len(), 3);
        assert_eq!(u.updates[2].old, None);
        assert_eq!((u.running(), u.next(), u.rollback_to()), (Some("system-3"), Some("system-3"), Some("system-2")));
        assert_eq!(u.systems.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["system-3", "system-2"]);
        assert_eq!(u.buttons(), [Button::Install, Button::Check, Button::RollBack]);
        assert!(!u.stale());
        assert_eq!(u.ago(1_792_870_000), "2 hours ago");
        // Rolling back asks first.
        u.key(0, Some('r'), 0);
        assert!(u.confirm);
        u.key(KEY_ESC, None, 0);
        assert!(!u.confirm);
        // After an install: a new system starts next; restart is offered.
        u.finished(Work::Installing, Ok(String::new()));
        u.systems.insert(0, Subvol { id: 4, name: "system-4".into(), flags: std::vec!["default".into()] });
        u.systems[1].flags.retain(|f| f == "mounted-here");
        u.systems[1].flags.push("fallback".into());
        u.restart_wanted = u.running() != u.next();
        assert_eq!(u.buttons(), [Button::Check, Button::RollBack, Button::Restart]);
        assert_eq!(u.rollback_to(), Some("system-3"));
        u.finished(Work::Checking, Ok(String::new()));
        assert_eq!(u.status, Some(("Slate is up to date.".into(), false)));
        u.finished(Work::Checking, Err("main: INDEX: connection refused".into()));
        assert!(u.status.as_ref().unwrap().1);
    }

    /// Installing for Strata's power dialog: the window closes once the
    /// updates are in, and stays to say why when they aren't.
    #[test]
    fn installing_before_a_restart() {
        let mut u = sample();
        u.then = true;
        assert!(!u.done());
        u.finished(Work::Installing, Err("cancelled".into()));
        assert!(!u.done() && !u.installed);
        u.finished(Work::Installing, Err("quarry: no space left".into()));
        assert!(u.status.as_ref().unwrap().0.ends_with("Close this window to choose what happens next."));
        assert!(!u.done());
        u.finished(Work::Installing, Ok(String::new()));
        assert!(u.done() && u.updates.is_empty());
        // Not for the person's own window.
        let mut v = sample();
        v.finished(Work::Installing, Ok(String::new()));
        assert!(!v.done());
    }

    pub fn with_apps() -> Updater {
        let mut u = sample();
        u.updates.clear();
        u.apps = Some(Vec::new());
        u.finished(
            Work::Checking,
            Ok(std::format!(
                "{APPS_AFTER}fi.skyjake.Lagrange\tLagrange\t1.21.1\t1.21.2\tno\norg.gnome.Calculator\tCalculator\t48.1\t-\tyes\n"
            )),
        );
        u
    }

    #[test]
    fn apps() {
        let mut u = with_apps();
        let apps = u.apps.clone().unwrap();
        assert_eq!(apps.len(), 2);
        assert_eq!((apps[0].new.as_deref(), apps[0].back), (Some("1.21.2"), false));
        assert_eq!((apps[1].new.as_deref(), apps[1].back), (None, true));
        assert_eq!(u.status, None);
        assert_eq!(u.buttons(), [Button::UpdateApps, Button::Check, Button::AutoApps, Button::RollBack]);
        // Choosing the calculator offers its rollback.
        u.key(KEY_DOWN, None, 0);
        assert_eq!(u.app, 1);
        assert_eq!(
            u.buttons(),
            [Button::UpdateApps, Button::Check, Button::RollBackApp, Button::AutoApps, Button::RollBack]
        );
        u.finished(Work::RollingBackApp, Ok(String::new()));
        assert_eq!(u.status, Some(("Calculator is back to its version before.".into(), false)));
        // Offline: the apps stay.
        u.finished(Work::CheckingApps, Err("couldn't reach Flathub".into()));
        assert_eq!(u.apps.as_ref().map(Vec::len), Some(2));
        u.finished(Work::CheckingApps, Ok("fi.skyjake.Lagrange\tLagrange\t1.21.2\t-\tyes\n".into()));
        assert_eq!((u.app, u.app_updates()), (0, 0));
        assert_eq!(parse_apps("\nbad\n"), []);
        assert_eq!(parse_auto_log("100 updated\n200 failed: flatpak said 1\n"), Some((200, true)));
        assert_eq!(parse_auto_log("100 updated\n"), Some((100, false)));
        assert_eq!(parse_auto_log(""), None);
    }
}
