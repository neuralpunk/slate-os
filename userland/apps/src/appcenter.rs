// SPDX-License-Identifier: MIT OR Apache-2.0

//! App Center (ADR 0125), `app-center`: Flathub's apps, to find, install,
//! open and remove.
//!
//! - The catalog is Flathub's AppStream data, which `slate-flatpak
//!   catalog` fetches signed with the repository (at most once a day, or
//!   with F5) into the person's installation; App Center reads it with
//!   `slate_appstream` and keeps a line per app in `~/.cache/slate/
//!   catalog`, remade when the data changes. Both run in a `kit::Job`.
//! - A sidebar of categories, "All apps" and "Installed"; a search over
//!   names, summaries and IDs (typing searches); a grid of apps with
//!   their icons (Flathub's, beside the catalog), two to a row.
//! - Enter (or a click) opens an app's page: its icon, name, developer,
//!   summary, description, version, licence and homepage. Enter there
//!   installs it (`slate-flatpak install`, the person's own) or opens it
//!   (`slate-flatpak run`); `e` installs it for everyone on the computer
//!   instead (`--system`, through the broker and its approval); Delete
//!   removes it (pressed twice). Esc goes back.
//! - Without the Linux runtime's Flatpak, the window offers to set it up
//!   (the broker's `flatpak=setup`).

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_appstream::{Component, Para};
use slate_display::input::{
    KEY_BACKSPACE, KEY_DELETE, KEY_DOWN, KEY_ENTER, KEY_ESC, KEY_KPENTER, KEY_LEFT, KEY_PAGEDOWN, KEY_PAGEUP,
    KEY_RIGHT, KEY_TAB, KEY_UP,
};
use slate_image::Image;
use slate_strata::fonts::Fonts;
use slate_strata_client::mods::{ALT, CTRL, LOGO, SHIFT};
use slate_ui::edit::LineEdit;
use slate_ui::graphite::Palette;
use slate_ui::icon::Icon;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;

use crate::kit::{self, App, Effect, Hints, Job, Now};

/// The runtime's Flatpak: without it, the window offers to set it up.
pub const FLATPAK: &str = "/var/lib/slate/linux/usr/bin/flatpak";
const SLATE_FLATPAK: &str = "/bin/slate-flatpak";
/// Where Flatpak keeps Flathub's catalog, in the person's home.
pub const CATALOG_DIR: &str = ".local/share/flatpak/appstream/flathub/x86_64/active";
/// App Center's line per app, in the person's home.
pub const CACHE: &str = ".cache/slate/catalog";
/// The catalog is fetched again when it is older than this (seconds).
const STALE_S: i64 = 24 * 3600;
/// F5 (input-event-codes.h).
const KEY_F5: u16 = 63;

const SIDEBAR_W: f32 = 210.0;
const CARD_H: f32 = 76.0;
const CARD_GAP: f32 = 10.0;
const COLS: usize = 2;

/// Flathub's main categories (the freedesktop menu specification's), as
/// the sidebar names them.
pub const CATEGORIES: [(&str, &str); 10] = [
    ("Audio and video", "AudioVideo"),
    ("Development", "Development"),
    ("Education", "Education"),
    ("Games", "Game"),
    ("Graphics", "Graphics"),
    ("Internet", "Network"),
    ("Office", "Office"),
    ("Science", "Science"),
    ("System", "System"),
    ("Utilities", "Utility"),
];

/// What the grid shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    All,
    Category(usize),
    Installed,
}

/// Work under way, in a child process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Work {
    SettingUp,
    /// Fetching the catalog (if due) and reading it.
    Catalog,
    /// What is installed (`slate-flatpak list`).
    Listing,
    /// Installing (for everyone or not) or removing an app.
    Installing(String, bool),
    Removing(String),
}

#[derive(Debug)]
pub struct Center {
    /// The runtime's Flatpak is there.
    pub ready: bool,
    pub home: String,
    pub apps: Vec<Component>,
    /// The installed apps' IDs.
    pub installed: Vec<String>,
    pub place: Place,
    pub query: LineEdit,
    /// The chosen card, in the visible list.
    pub selected: usize,
    first: usize,
    /// The app whose page is open.
    pub page: Option<String>,
    page_scroll: usize,
    /// Delete was pressed once on the page: the next one removes.
    confirm_remove: bool,
    pub status: Option<(String, bool)>,
    pub work: Vec<Work>,
    jobs: Vec<(Job, Work)>,
    /// The monotonic clock at the last tick (ms), for the spinner and the
    /// time taken.
    pub now: i64,
    /// When the work under way began (ms).
    since: i64,
    /// How far setting the runtime up is (`slate-linux setup`'s file).
    pub setup: Option<kit::SetupProgress>,
    /// What the work under way last said (Flatpak's lines).
    pub said: Option<String>,
    /// Icons by file name (None: not readable), loaded as cards show.
    icons: BTreeMap<String, Option<Image>>,
    shown: usize,
    side_hits: Vec<(Area, Place)>,
    card_hits: Vec<(Area, usize)>,
    button_hits: Vec<(Area, char)>,
}

/// A path under the home.
fn at(home: &str, rel: &str) -> String {
    alloc::format!("{home}/{rel}")
}

/// Read the catalog's AppStream data and write the cache's lines.
pub fn build_cache(home: &str) -> Result<usize, String> {
    let dir = at(home, CATALOG_DIR);
    let gz = alloc::format!("{dir}/appstream.xml.gz");
    let plain = alloc::format!("{dir}/appstream.xml");
    let xml = match slate_rt::fs::read_file(gz.as_bytes()) {
        Ok(data) => slate_flate::gunzip(&data).map_err(|e| alloc::format!("the catalog: {e:?}"))?.0,
        Err(_) => slate_rt::fs::read_file(plain.as_bytes()).map_err(|e| alloc::format!("the catalog: {e}"))?,
    };
    let comps = slate_appstream::parse(&String::from_utf8_lossy(&xml));
    let mut text = String::new();
    for c in &comps {
        text.push_str(&c.line());
        text.push('\n');
    }
    let _ = slate_rt::fs::mkdir(at(home, ".cache").as_bytes(), 0o755);
    let _ = slate_rt::fs::mkdir(at(home, ".cache/slate").as_bytes(), 0o755);
    let path = at(home, CACHE);
    let tmp = alloc::format!("{path}.new");
    slate_rt::fs::write_file(tmp.as_bytes(), text.as_bytes(), 0o644).map_err(|e| alloc::format!("{e}"))?;
    slate_rt::fs::rename(tmp.as_bytes(), path.as_bytes()).map_err(|e| alloc::format!("{e}"))?;
    Ok(comps.len())
}

/// The cache's apps, by name.
pub fn load_cache(text: &str) -> Vec<Component> {
    let mut v: Vec<Component> = text.lines().filter_map(Component::from_line).collect();
    v.sort_by(|a, b| crate::fsops::natural(&a.name, &b.name));
    v.dedup_by(|a, b| a.id == b.id);
    v
}

fn mtime(path: &str) -> Option<i64> {
    slate_rt::fs::stat(path.as_bytes()).ok().map(|s| s.mtime)
}

/// The installed apps' IDs from `slate-flatpak list`'s lines.
pub fn parse_installed(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.split('\t').next())
        .map(str::trim)
        .filter(|id| id.contains('.'))
        .map(String::from)
        .collect()
}

impl Center {
    pub fn new(home: &str, ready: bool) -> Center {
        Center {
            ready,
            home: String::from(home),
            apps: Vec::new(),
            installed: Vec::new(),
            place: Place::All,
            query: LineEdit::new("").with_max(64),
            selected: 0,
            first: 0,
            page: None,
            page_scroll: 0,
            confirm_remove: false,
            status: None,
            work: Vec::new(),
            jobs: Vec::new(),
            now: 0,
            since: 0,
            setup: None,
            said: None,
            icons: BTreeMap::new(),
            shown: 8,
            side_hits: Vec::new(),
            card_hits: Vec::new(),
            button_hits: Vec::new(),
        }
    }

    /// The window as it starts: the cache read, the catalog fetched when
    /// due, and what is installed asked for.
    pub fn start(&mut self) {
        if !self.ready {
            crate::trace!("app-center: the Linux runtime isn't set up");
            return;
        }
        if let Ok(t) = slate_rt::fs::read_file(at(&self.home, CACHE).as_bytes()) {
            self.apps = load_cache(&String::from_utf8_lossy(&t));
        }
        self.begin(Work::Catalog, false);
        self.begin(Work::Listing, false);
    }

    /// Start `work` in the background (`force`: fetch the catalog even
    /// when it is fresh).
    fn begin(&mut self, work: Work, force: bool) {
        if self.jobs.iter().any(|(_, w)| *w == work) {
            return;
        }
        let home = self.home.clone();
        let job = match work.clone() {
            Work::SettingUp => Job::start(|| kit::broker("flatpak=setup").map(|()| String::new())),
            Work::Catalog => Job::reporting(move |report| {
                // The catalog as Flatpak keeps it (compressed, or not).
                let gz = at(&home, &alloc::format!("{CATALOG_DIR}/appstream.xml.gz"));
                let plain = at(&home, &alloc::format!("{CATALOG_DIR}/appstream.xml"));
                let data = if mtime(&gz).is_some() { gz } else { plain };
                let age = mtime(&data).map(|m| slate_rt::time::unix() - m);
                if force || age.is_none_or(|a| a > STALE_S) {
                    // Offline with an older catalog: that one is read.
                    if let Err(e) = kit::output_reporting(SLATE_FLATPAK, &["catalog"], report)
                        && age.is_none()
                    {
                        return Err(e);
                    }
                }
                let cache = at(&home, CACHE);
                if mtime(&cache) < mtime(&data) || mtime(&cache).is_none() || force {
                    build_cache(&home)?;
                }
                Ok(String::new())
            }),
            Work::Listing => Job::start(|| kit::output(SLATE_FLATPAK, &["list"])),
            Work::Installing(id, everyone) => Job::reporting(move |report| {
                let args: &[&str] = if everyone { &["--system", "install", &id] } else { &["install", &id] };
                kit::output_reporting(SLATE_FLATPAK, args, report)
            }),
            Work::Removing(id) => {
                Job::reporting(move |report| kit::output_reporting(SLATE_FLATPAK, &["remove", &id], report))
            }
        };
        match job {
            Ok(j) => {
                self.status = match &work {
                    Work::SettingUp => Some((String::from("Setting up the Linux runtime…"), false)),
                    Work::Catalog if self.apps.is_empty() => Some((String::from("Fetching Flathub's catalog…"), false)),
                    Work::Installing(id, _) => Some((alloc::format!("Installing {}…", self.name_of(id)), false)),
                    Work::Removing(id) => Some((alloc::format!("Removing {}…", self.name_of(id)), false)),
                    _ => self.status.take(),
                };
                if self.jobs.is_empty() {
                    self.since = self.now;
                    self.said = None;
                }
                self.work.push(work.clone());
                self.jobs.push((j, work));
            }
            Err(e) => self.status = Some((alloc::format!("Couldn't start: {e}"), true)),
        }
    }

    /// Work the person waits on is under way (not the quiet listing).
    pub fn busy(&self) -> bool {
        self.work.iter().any(|w| *w != Work::Listing)
    }

    /// How long the work under way has taken, as m:ss.
    fn elapsed(&self) -> String {
        let s = ((self.now - self.since) / 1000).max(0);
        alloc::format!("{}:{:02}", s / 60, s % 60)
    }

    fn name_of(&self, id: &str) -> String {
        self.apps.iter().find(|a| a.id == id).map_or_else(|| id.to_string(), |a| a.name.clone())
    }

    /// Work that ended.
    pub fn finished(&mut self, work: &Work, r: Result<String, String>) {
        self.work.retain(|w| w != work);
        match (work, r) {
            (_, Err(e)) if e == "cancelled" => self.status = Some((String::from("Nothing was changed."), false)),
            (Work::SettingUp, Ok(_)) => {
                self.ready = slate_rt::fs::exists(FLATPAK.as_bytes());
                crate::trace!("app-center: the Linux runtime is set up");
                self.status = None;
                self.start();
            }
            (Work::SettingUp, Err(e)) => {
                crate::trace!("app-center: the runtime wasn't set up: {e}");
                self.status = Some((alloc::format!("The runtime wasn't set up: {e}"), true));
            }
            (Work::Catalog, Ok(_)) => {
                if let Ok(t) = slate_rt::fs::read_file(at(&self.home, CACHE).as_bytes()) {
                    self.apps = load_cache(&String::from_utf8_lossy(&t));
                }
                crate::trace!("app-center: {} apps in the catalog", self.apps.len());
                if matches!(&self.status, Some((s, false)) if s.starts_with("Fetching")) {
                    self.status = None;
                }
            }
            (Work::Catalog, Err(e)) => {
                self.status = Some((alloc::format!("Couldn't fetch Flathub's catalog: {e}"), true));
            }
            (Work::Listing, Ok(t)) => self.installed = parse_installed(&t),
            (Work::Listing, Err(_)) => {}
            (Work::Installing(id, everyone), Ok(_)) => {
                crate::trace!("app-center: installed {id}{}", if *everyone { " for everyone" } else { "" });
                self.status = Some((alloc::format!("{} is installed: Enter opens it.", self.name_of(id)), false));
                if !self.installed.contains(id) {
                    self.installed.push(id.clone());
                }
                self.begin(Work::Listing, false);
            }
            (Work::Installing(id, _), Err(e)) => {
                self.status = Some((alloc::format!("{} wasn't installed: {e}", self.name_of(id)), true));
            }
            (Work::Removing(id), Ok(_)) => {
                crate::trace!("app-center: removed {id}");
                self.status = Some((alloc::format!("{} is removed.", self.name_of(id)), false));
                self.installed.retain(|i| i != id);
                self.begin(Work::Listing, false);
            }
            (Work::Removing(id), Err(e)) => {
                self.status = Some((alloc::format!("{} wasn't removed: {e}", self.name_of(id)), true));
            }
        }
    }

    /// The apps the place and the search let through, in order.
    pub fn visible(&self) -> Vec<&Component> {
        let q = self.query.text().trim().to_lowercase();
        self.apps
            .iter()
            .filter(|a| match self.place {
                Place::All => true,
                Place::Category(i) => a.categories.iter().any(|c| c == CATEGORIES[i].1),
                Place::Installed => self.installed.contains(&a.id),
            })
            .filter(|a| a.matches(&q))
            .collect()
    }

    fn go(&mut self, p: Place) {
        self.place = p;
        self.selected = 0;
        self.first = 0;
        self.page = None;
        let what = match p {
            Place::All => "all apps",
            Place::Category(i) => CATEGORIES[i].0,
            Place::Installed => "installed",
        };
        crate::trace!("app-center: {what}: {} apps", self.visible().len());
    }

    fn places() -> Vec<Place> {
        let mut v = alloc::vec![Place::All];
        v.extend((0..CATEGORIES.len()).map(Place::Category));
        v.push(Place::Installed);
        v
    }

    fn open_page(&mut self) -> Effect {
        let Some(id) = self.visible().get(self.selected).map(|a| a.id.clone()) else { return Effect::None };
        crate::trace!("app-center: the page of {id}");
        self.page = Some(id);
        self.page_scroll = 0;
        self.confirm_remove = false;
        Effect::Redraw
    }

    /// Enter on a page: install, or open.
    fn primary(&mut self, everyone: bool) -> Effect {
        let Some(id) = self.page.clone() else { return Effect::None };
        if self.work.iter().any(|w| matches!(w, Work::Installing(i, _) | Work::Removing(i) if *i == id)) {
            return Effect::None;
        }
        if self.installed.contains(&id) {
            match crate::fsops::start(SLATE_FLATPAK, &[String::from("run"), id.clone()]) {
                Ok(()) => {
                    crate::trace!("app-center: opened {id}");
                    self.status = Some((alloc::format!("Opening {}…", self.name_of(&id)), false));
                }
                Err(e) => self.status = Some((e, true)),
            }
        } else {
            self.begin(Work::Installing(id, everyone), false);
        }
        Effect::Redraw
    }

    fn remove(&mut self) -> Effect {
        let Some(id) = self.page.clone().filter(|i| self.installed.contains(i)) else { return Effect::None };
        if !self.confirm_remove {
            self.confirm_remove = true;
            self.status = Some((alloc::format!("Remove {}? Press Delete again.", self.name_of(&id)), true));
            return Effect::Redraw;
        }
        self.confirm_remove = false;
        self.begin(Work::Removing(id), false);
        Effect::Redraw
    }

    /// Icons for the cards in view, and the page's, not yet read.
    fn wanted_icons(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .visible()
            .iter()
            .skip(self.first)
            .take(self.shown + COLS)
            .map(|a| a.icon.clone())
            .chain(self.page.iter().filter_map(|id| self.apps.iter().find(|a| a.id == *id).map(|a| a.icon.clone())))
            .filter(|i| !i.is_empty() && !self.icons.contains_key(i))
            .collect();
        v.dedup();
        v
    }

    /// An icon, as if read (the scenes).
    pub fn set_icon(&mut self, name: &str, img: Option<Image>) {
        self.icons.insert(String::from(name), img);
    }

    fn icon_of(&self, name: &str) -> Option<&Image> {
        self.icons.get(name).and_then(|i| i.as_ref())
    }

    fn draw_setup(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area) {
        let w = 460.0;
        let (x, mut y) = (a.x + (a.w - w) / 2.0, a.y + a.h * 0.28);
        p.icon(Icon::Grid, x, y, 40.0, pal.text_3);
        y += 60.0;
        let title = p.style(&f.medium, 20.0, pal.chalk);
        p.line(&title, x, y, 26.0, "Apps from Flathub");
        y += 36.0;
        let body = p.style(&f.regular, 13.5, pal.text_2);
        let text = "Flathub's apps run in the Linux runtime, each in a sandbox of its own. The runtime isn't set up \
                    on this computer yet: setting it up turns Linux compatibility on and fetches a few hundred \
                    megabytes, after approval.";
        for (k, l) in slate_ui::text::wrap(&body, text, w * p.scale).iter().enumerate() {
            p.line(&body, x, y + 21.0 * k as f32, 20.0, l);
        }
        y += 21.0 * 4.0 + 16.0;
        if self.work.contains(&Work::SettingUp) {
            // Under way: what it is doing, how far, and for how long.
            kit::spinner(p, pal, x, y + 1.0, 20.0, self.now);
            let what = p.style(&f.medium, 14.0, pal.text_1);
            let text = self.setup.as_ref().map_or_else(|| String::from("Starting…"), |s| s.say());
            p.line(&what, x + 30.0, y, 22.0, &kit::fit(p, &what, &text, w - 80.0));
            let meta = p.style(&f.mono, 11.5, pal.text_4);
            let el = self.elapsed();
            let ew = p.measure(&meta, &el);
            p.line(&meta, x + w - ew, y + 3.0, 16.0, &el);
            let bar = Area::new(x, y + 34.0, w, 6.0);
            kit::progress_bar(p, pal, bar, self.setup.as_ref().map(|s| s.fraction()), self.now);
            return;
        }
        let b = Area::new(x, y, 150.0, 38.0);
        kit::button(p, pal, f, b, "Set it up", true, false);
        self.button_hits.push((b, 's'));
    }

    fn draw_sidebar(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area) {
        let side = Area::new(a.x, a.y, SIDEBAR_W, a.h);
        p.fill(side, 0.0, pal.header);
        p.fill(Area::new(side.right() - 1.0, side.y, 1.0, side.h), 0.0, pal.divider);
        let label = p.style(&f.mono, 11.0, pal.muted);
        let mut y = a.y + 16.0;
        for place in Center::places() {
            let (name, icon) = match place {
                Place::All => ("All apps", Icon::Grid),
                Place::Category(i) => (CATEGORIES[i].0, Icon::Folder),
                Place::Installed => ("Installed", Icon::Download),
            };
            match place {
                Place::All => {
                    p.line(&label, side.x + 16.0, y, 16.0, "flathub");
                    y += 22.0;
                }
                Place::Category(0) => {
                    p.line(&label, side.x + 16.0, y + 4.0, 16.0, "categories");
                    y += 26.0;
                }
                Place::Installed => y += 10.0,
                _ => {}
            }
            let r = Area::new(side.x + 8.0, y, side.w - 16.0, 28.0);
            let on = place == self.place && self.page.is_none();
            if on {
                p.fill(r, 7.0, pal.raised);
            }
            p.icon(icon, r.x + 8.0, r.y + 6.0, 16.0, if on { pal.chalk } else { pal.text_3 });
            let st = p.style(&f.medium, 13.0, if on { pal.chalk } else { pal.text_2 });
            p.line(&st, r.x + 32.0, r.y + 4.0, 20.0, name);
            self.side_hits.push((r, place));
            y += 30.0;
        }
    }

    fn draw_grid(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, main: Area) {
        let field = Area::new(main.x + 20.0, main.y + 16.0, main.w - 40.0, 36.0);
        kit::field(p, pal, f, field, &self.query, true, "Search Flathub's apps");
        let list: Vec<Component> = self.visible().into_iter().cloned().collect();
        let count = match list.len() {
            1 => String::from("1 app"),
            n => alloc::format!("{n} apps"),
        };
        let meta = p.style(&f.mono, 11.0, pal.muted);
        let cw = p.measure(&meta, &count);
        p.line(&meta, field.right() - 12.0 - cw, field.y + 9.0, 18.0, &count);
        let top = field.bottom() + 16.0;
        let bottom = main.bottom() - 60.0;
        let card_w = (main.w - 40.0 - CARD_GAP * (COLS - 1) as f32) / COLS as f32;
        let rows = ((bottom - top + CARD_GAP) / (CARD_H + CARD_GAP)).max(1.0) as usize;
        self.shown = rows * COLS;
        let n = list.len();
        if self.selected >= n {
            self.selected = n.saturating_sub(1);
        }
        let row = self.selected / COLS;
        let first_row = self.first / COLS;
        let first_row = if row < first_row {
            row
        } else if row >= first_row + rows {
            row + 1 - rows
        } else {
            first_row
        };
        self.first = first_row * COLS;
        let quiet = p.style(&f.regular, 14.0, pal.muted);
        if n == 0 {
            let msg = if self.apps.is_empty() {
                if self.work.contains(&Work::Catalog) {
                    "Fetching Flathub's catalog…"
                } else {
                    "No catalog yet: F5 fetches it."
                }
            } else if self.place == Place::Installed && self.query.is_empty() {
                "No app from Flathub is installed yet."
            } else {
                "No app matches."
            };
            let w = p.measure(&quiet, msg);
            p.line(&quiet, main.x + (main.w - w) / 2.0, top + 60.0, 20.0, msg);
        }
        let name_s = p.style(&f.medium, 14.0, pal.text_1);
        let sum_s = p.style(&f.regular, 12.5, pal.muted);
        let tag = p.style(&f.mono, 10.5, pal.text_3);
        let cards: Vec<(usize, Component)> = list.into_iter().enumerate().skip(self.first).take(self.shown).collect();
        for (i, c) in cards {
            let k = i - self.first;
            let x = main.x + 20.0 + (k % COLS) as f32 * (card_w + CARD_GAP);
            let y = top + (k / COLS) as f32 * (CARD_H + CARD_GAP);
            let r = Area::new(x, y, card_w, CARD_H);
            p.fill(r, 10.0, pal.raised);
            if i == self.selected {
                p.border(r, 10.0, 1.5, pal.chalk);
            }
            let ic = Area::new(r.x + 14.0, r.y + 14.0, 48.0, 48.0);
            match self.icon_of(&c.icon) {
                Some(img) => slate_strata::faces::draw(p, img, ic, 10.0),
                None => {
                    p.fill(ic, 10.0, pal.well);
                    p.icon(Icon::Grid, ic.x + 14.0, ic.y + 14.0, 20.0, pal.text_4);
                }
            }
            let tx = ic.right() + 14.0;
            let room = r.right() - 14.0 - tx;
            let installed = self.installed.contains(&c.id);
            let tag_w = if installed { p.measure(&tag, "installed") + 14.0 } else { 0.0 };
            p.line(&name_s, tx, r.y + 15.0, 20.0, &kit::fit(p, &name_s, &c.name, room - tag_w));
            if installed {
                let t = Area::new(r.right() - 14.0 - tag_w + 6.0, r.y + 16.0, tag_w - 6.0, 18.0);
                p.border(t, 4.0, 1.0, pal.border);
                p.line(&tag, t.x + 4.0, t.y, t.h, "installed");
            }
            p.line(&sum_s, tx, r.y + 39.0, 18.0, &kit::fit(p, &sum_s, &c.summary, room));
            self.card_hits.push((r, i));
        }
    }

    fn draw_page(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, main: Area, c: &Component) {
        let (x, w) = (main.x + 28.0, main.w - 56.0);
        let mut y = main.y + 18.0;
        let back = p.style(&f.medium, 13.0, pal.text_3);
        p.icon(Icon::ChevronLeft, x - 4.0, y + 2.0, 16.0, pal.text_3);
        let bw = p.line(&back, x + 16.0, y, 20.0, "Back");
        self.button_hits.push((Area::new(x - 6.0, y - 4.0, bw + 26.0, 28.0), 'b'));
        y += 36.0;
        let ic = Area::new(x, y, 96.0, 96.0);
        match self.icon_of(&c.icon) {
            Some(img) => slate_strata::faces::draw(p, img, ic, 18.0),
            None => {
                p.fill(ic, 18.0, pal.raised);
                p.icon(Icon::Grid, ic.x + 32.0, ic.y + 32.0, 32.0, pal.text_4);
            }
        }
        let tx = ic.right() + 22.0;
        let title = p.style(&f.medium, 22.0, pal.chalk);
        p.line(&title, tx, y + 4.0, 28.0, &kit::fit(p, &title, &c.name, w - (tx - x)));
        let dev = p.style(&f.regular, 13.0, pal.muted);
        let by = if c.developer.is_empty() { c.id.clone() } else { c.developer.clone() };
        p.line(&dev, tx, y + 36.0, 18.0, &kit::fit(p, &dev, &by, w - (tx - x)));
        // The action, and what it is for.
        let installed = self.installed.contains(&c.id);
        let busy = self.work.iter().find(|wk| matches!(wk, Work::Installing(i, _) | Work::Removing(i) if *i == c.id));
        let (label, strong) = match busy {
            Some(Work::Installing(..)) => ("Installing…", false),
            Some(_) => ("Removing…", false),
            None if installed => ("Open", true),
            None => ("Install", true),
        };
        let b = Area::new(tx, y + 62.0, 120.0, 34.0);
        kit::button(p, pal, f, b, label, strong && busy.is_none(), false);
        self.button_hits.push((b, 'i'));
        if installed && busy.is_none() {
            let r = Area::new(b.right() + 10.0, b.y, 100.0, 34.0);
            let clay = pal.accents.clay;
            p.fill(r, 8.0, clay.tint);
            p.border(r, 8.0, 1.0, clay.border);
            let s = p.style(&f.medium, 14.0, clay.text);
            let lw = p.measure(&s, "Remove");
            p.line(&s, r.x + (r.w - lw) / 2.0, r.y + 7.0, 20.0, "Remove");
            self.button_hits.push((r, 'r'));
        } else if busy.is_none() {
            // For every account on the computer (after approval).
            let e = Area::new(b.right() + 10.0, b.y, 190.0, 34.0);
            kit::button(p, pal, f, e, "Install for everyone", false, false);
            self.button_hits.push((e, 'e'));
        }
        y += 116.0;
        let sum = p.style(&f.medium, 15.0, pal.text_1);
        for (k, l) in slate_ui::text::wrap(&sum, &c.summary, w * p.scale).iter().take(2).enumerate() {
            p.line(&sum, x, y + 22.0 * k as f32, 20.0, l);
        }
        y += 52.0;
        // The facts at the right, the description at the left.
        let facts_w = 220.0;
        let label = p.style(&f.mono, 11.0, pal.muted);
        let value = p.style(&f.regular, 12.5, pal.text_2);
        let fx = x + w - facts_w;
        let mut fy = y;
        for (l, v) in [
            ("version", c.version.as_str()),
            ("licence", c.license.as_str()),
            ("homepage", c.homepage.as_str()),
            ("id", &c.id),
        ] {
            if v.is_empty() {
                continue;
            }
            p.line(&label, fx, fy, 16.0, l);
            p.line(&value, fx, fy + 16.0, 18.0, &kit::fit(p, &value, v, facts_w));
            fy += 42.0;
        }
        let body = p.style(&f.regular, 13.5, pal.text_2);
        let dw = w - facts_w - 30.0;
        // (bullet, indented, text): list items indented, a bullet on
        // their first line.
        let mut lines: Vec<(bool, bool, String)> = Vec::new();
        for (n, para) in c.description.iter().enumerate() {
            let (item, t) = match para {
                Para::P(t) => (false, t),
                Para::Item(t) => (true, t),
            };
            let wrapped = slate_ui::text::wrap(&body, t, (dw - if item { 18.0 } else { 0.0 }) * p.scale);
            for (k, l) in wrapped.into_iter().enumerate() {
                lines.push((item && k == 0, item, l));
            }
            // A gap after a paragraph, and after the last item of a list.
            let next_item = matches!(c.description.get(n + 1), Some(Para::Item(_)));
            if !(item && next_item) {
                lines.push((false, false, String::new()));
            }
        }
        let room = ((main.bottom() - 60.0 - y) / 21.0).max(1.0) as usize;
        self.page_scroll = self.page_scroll.min(lines.len().saturating_sub(room));
        for (k, (bullet, indent, l)) in lines.iter().skip(self.page_scroll).take(room).enumerate() {
            let ly = y + 21.0 * k as f32;
            if *bullet {
                p.fill(Area::new(x + 4.0, ly + 8.0, 4.0, 4.0), 2.0, pal.text_3);
            }
            p.line(&body, x + if *indent { 18.0 } else { 0.0 }, ly, 20.0, l);
        }
    }
}

impl App for Center {
    fn draw(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area) {
        self.side_hits.clear();
        self.card_hits.clear();
        self.button_hits.clear();
        if !self.ready {
            self.draw_setup(p, pal, f, a);
        } else {
            self.draw_sidebar(p, pal, f, a);
            let main = Area::new(a.x + SIDEBAR_W, a.y, a.w - SIDEBAR_W, a.h);
            match self.page.clone().and_then(|id| self.apps.iter().find(|c| c.id == id).cloned()) {
                Some(c) => self.draw_page(p, pal, f, main, &c),
                None => {
                    self.page = None;
                    self.draw_grid(p, pal, f, main);
                }
            }
        }
        if let Some((s, bad)) = &self.status
            && !(self.setup.is_some() || self.work.contains(&Work::SettingUp))
        {
            let st = p.style(&f.regular, 13.0, if *bad { pal.accents.clay.text } else { pal.text_2 });
            let mut x = if self.ready { a.x + SIDEBAR_W + 20.0 } else { a.x + 20.0 };
            let y = a.bottom() - 54.0;
            // Under way: a spinner, the time taken and what Flatpak says.
            let busy = self.busy() && !*bad;
            if busy {
                kit::spinner(p, pal, x, y + 2.0, 16.0, self.now);
                x += 24.0;
            }
            let tw = p.line(&st, x, y, 20.0, &kit::fit(p, &st, s, a.right() - x - 20.0));
            if busy {
                let meta = p.style(&f.mono, 11.5, pal.text_4);
                let el = self.elapsed();
                let ew = p.line(&meta, x + tw + 10.0, y + 2.0, 16.0, &el);
                if let Some(said) = &self.said {
                    let sx = x + tw + 10.0 + ew + 12.0;
                    if sx < a.right() - 80.0 {
                        p.line(&meta, sx, y + 2.0, 16.0, &kit::fit(p, &meta, said, a.right() - sx - 20.0));
                    }
                }
            }
        }
        let main = Area::new(
            a.x + if self.ready { SIDEBAR_W } else { 0.0 },
            a.y,
            a.w - if self.ready { SIDEBAR_W } else { 0.0 },
            a.h,
        );
        let hints: &[(&str, &str)] = match (self.ready, &self.page) {
            (false, _) if self.work.contains(&Work::SettingUp) => &[],
            (false, _) => &[("enter", "set it up")],
            (true, Some(_)) => {
                &[("enter", "install or open"), ("e", "for everyone"), ("del", "remove"), ("esc", "back")]
            }
            (true, None) => {
                &[("type", "search"), ("↑↓", "choose"), ("enter", "open"), ("tab", "category"), ("f5", "refresh")]
            }
        };
        kit::hints(p, pal, f, main, hints);
    }

    fn key(&mut self, code: u16, ch: Option<char>, mods: u8) -> Effect {
        let shortcut = mods & (CTRL | ALT | LOGO) != 0;
        if !self.ready {
            if matches!(code, KEY_ENTER | KEY_KPENTER) && !self.work.contains(&Work::SettingUp) {
                self.begin(Work::SettingUp, false);
                return Effect::Redraw;
            }
            return Effect::None;
        }
        if code == KEY_F5 {
            self.begin(Work::Catalog, true);
            return Effect::Redraw;
        }
        if self.page.is_some() {
            if code != KEY_DELETE {
                self.confirm_remove = false;
            }
            return match (code, ch) {
                (KEY_ESC | KEY_BACKSPACE, _) => {
                    self.page = None;
                    Effect::Redraw
                }
                (KEY_ENTER | KEY_KPENTER, _) => self.primary(false),
                (_, Some('e')) if !shortcut => self.primary(true),
                (KEY_DELETE, _) => self.remove(),
                (KEY_DOWN, _) => {
                    self.page_scroll += 1;
                    Effect::Redraw
                }
                (KEY_UP, _) => {
                    self.page_scroll = self.page_scroll.saturating_sub(1);
                    Effect::Redraw
                }
                _ => Effect::None,
            };
        }
        let n = self.visible().len();
        match code {
            KEY_TAB => {
                let places = Center::places();
                let at = places.iter().position(|p| *p == self.place).unwrap_or(0);
                let to =
                    if mods & SHIFT != 0 { (at + places.len() - 1) % places.len() } else { (at + 1) % places.len() };
                self.go(places[to]);
            }
            KEY_UP => self.selected = self.selected.saturating_sub(COLS),
            KEY_DOWN => self.selected = (self.selected + COLS).min(n.saturating_sub(1)),
            KEY_LEFT if self.query.is_empty() || self.selected % COLS == 1 => {
                self.selected = self.selected.saturating_sub(1)
            }
            KEY_RIGHT if self.query.is_empty() || self.selected % COLS == 0 => {
                self.selected = (self.selected + 1).min(n.saturating_sub(1))
            }
            KEY_PAGEUP => self.selected = self.selected.saturating_sub(self.shown),
            KEY_PAGEDOWN => self.selected = (self.selected + self.shown).min(n.saturating_sub(1)),
            KEY_ENTER | KEY_KPENTER => return self.open_page(),
            KEY_ESC if !self.query.is_empty() => {
                self.query.clear();
                self.selected = 0;
            }
            _ => {
                if kit::edit_key(&mut self.query, code, ch, mods, |_| true) {
                    self.selected = 0;
                    self.first = 0;
                    let q = self.query.text();
                    if !q.trim().is_empty() {
                        crate::trace!("app-center: {} apps for \"{}\"", self.visible().len(), q.trim());
                    }
                    return Effect::Redraw;
                }
                return Effect::None;
            }
        }
        Effect::Redraw
    }

    fn click(&mut self, x: f32, y: f32) -> Effect {
        if let Some((_, k)) = self.button_hits.iter().find(|(a, _)| a.contains(x, y)).copied() {
            return match k {
                's' => self.key(KEY_ENTER, None, 0),
                'b' => {
                    self.page = None;
                    Effect::Redraw
                }
                'i' => self.primary(false),
                'e' => self.primary(true),
                _ => self.remove(),
            };
        }
        if let Some((_, place)) = self.side_hits.iter().find(|(a, _)| a.contains(x, y)).copied() {
            self.go(place);
            return Effect::Redraw;
        }
        if let Some((_, i)) = self.card_hits.iter().find(|(a, _)| a.contains(x, y)).copied() {
            self.selected = i;
            return self.open_page();
        }
        Effect::None
    }

    fn scroll(&mut self, lines: i32) -> Effect {
        if self.page.is_some() {
            self.page_scroll = (self.page_scroll as i64 + i64::from(lines)).max(0) as usize;
        } else {
            let n = self.visible().len();
            let step = lines.signum() as i64 * COLS as i64;
            self.selected = (self.selected as i64 + step).clamp(0, n.saturating_sub(1) as i64) as usize;
        }
        Effect::Redraw
    }

    fn paste(&mut self, text: &str) -> Effect {
        if self.page.is_none() && self.query.insert(text.lines().next().unwrap_or("")) {
            self.selected = 0;
            return Effect::Redraw;
        }
        Effect::None
    }

    fn tick(&mut self, now: Now) -> bool {
        let mut changed = false;
        // Icons: four each time round, so the window keeps answering.
        for name in self.wanted_icons().into_iter().take(4) {
            let dir = at(&self.home, CATALOG_DIR);
            let img = ["128x128", "64x64"]
                .iter()
                .find_map(|s| slate_rt::fs::read_file(alloc::format!("{dir}/icons/{s}/{name}").as_bytes()).ok())
                .and_then(|d| slate_image::decode(&d).ok());
            self.icons.insert(name, img);
            changed = true;
        }
        self.now = now.mono;
        let mut done = Vec::new();
        for (j, w) in self.jobs.iter_mut() {
            if let Some(r) = j.poll() {
                done.push((w.clone(), r));
            } else if *w != Work::Listing
                && let Some(t) = &j.progress
                && self.said.as_ref() != Some(t)
            {
                self.said = Some(t.clone());
            }
        }
        if self.work.contains(&Work::SettingUp) {
            let p = kit::SetupProgress::read();
            if p.is_some() && p != self.setup {
                if let Some(s) = &p {
                    crate::trace!("app-center: setup: {}", s.say());
                }
                self.setup = p;
            }
        } else {
            self.setup = None;
        }
        // The spinner turns while anything is under way.
        changed |= self.busy();
        for (w, r) in done {
            self.jobs.retain(|(_, x)| *x != w);
            self.finished(&w, r);
            changed = true;
        }
        changed
    }

    fn wake(&self, _now: Now) -> Option<i64> {
        if !self.wanted_icons().is_empty() {
            return Some(0);
        }
        if self.busy() {
            return Some(kit::SPIN_MS);
        }
        (!self.jobs.is_empty()).then_some(kit::JOB_MS)
    }
}

pub fn main() -> i32 {
    let home = slate_rt::env::var(b"HOME").map(|h| String::from(slate_rt::lossy(&h))).unwrap_or_else(|| "/".into());
    let mut c = Center::new(&home, slate_rt::fs::exists(FLATPAK.as_bytes()));
    c.start();
    kit::run("app-center", "app center", None, Hints { min: (760, 520), size: (980, 680) }, &mut c)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::format;

    pub fn catalog() -> Vec<Component> {
        let line = |id: &str, name: &str, sum: &str, cat: &str| Component {
            id: id.into(),
            name: name.into(),
            summary: sum.into(),
            developer: "Someone".into(),
            license: "GPL-3.0-or-later".into(),
            categories: std::vec![cat.into()],
            icon: format!("{id}.png"),
            homepage: format!("https://example.org/{name}"),
            version: "1.0".into(),
            description: std::vec![Para::P(format!("{name} does things.")), Para::Item("One".into())],
        };
        load_cache(
            &[
                line("org.gnome.Calculator", "Calculator", "Perform calculations", "Utility"),
                line("org.inkscape.Inkscape", "Inkscape", "Vector graphics editor", "Graphics"),
                line(
                    "org.gimp.GIMP",
                    "GNU Image Manipulation Program",
                    "Create images and edit photographs",
                    "Graphics",
                ),
                line("org.libreoffice.LibreOffice", "LibreOffice", "The office suite", "Office"),
                line("com.valvesoftware.Steam", "Steam", "Launcher for the Steam software", "Game"),
            ]
            .iter()
            .map(|c| c.line())
            .collect::<Vec<_>>()
            .join("\n"),
        )
    }

    pub fn center() -> Center {
        let mut c = Center::new("/nonexistent", true);
        c.apps = catalog();
        c.installed = std::vec!["org.gnome.Calculator".into()];
        c
    }

    #[test]
    fn browsing_and_searching() {
        let mut c = center();
        assert_eq!(c.visible().len(), 5);
        assert_eq!(c.visible()[0].name, "Calculator", "by name");
        // Tab to the categories: Audio and video (none), Development...
        c.go(Place::Category(4));
        let names: Vec<&str> = c.visible().iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["GNU Image Manipulation Program", "Inkscape"]);
        c.go(Place::Installed);
        assert_eq!(c.visible().len(), 1);
        c.go(Place::All);
        for ch in "vector".chars() {
            c.key(0, Some(ch), 0);
        }
        assert_eq!(c.visible().len(), 1);
        c.key(KEY_ENTER, None, 0);
        assert_eq!(c.page.as_deref(), Some("org.inkscape.Inkscape"));
        c.key(KEY_ESC, None, 0);
        assert!(c.page.is_none());
        c.key(KEY_ESC, None, 0);
        assert!(c.query.is_empty());
        c.key(KEY_TAB, None, 0);
        assert_eq!(c.place, Place::Category(0));
        c.key(KEY_TAB, None, SHIFT);
        c.key(KEY_TAB, None, SHIFT);
        assert_eq!(c.place, Place::Installed);
        assert_eq!(
            parse_installed("org.gnome.Calculator\tCalculator\t48.1\tstable\tabc\n\n"),
            ["org.gnome.Calculator"]
        );
    }

    #[test]
    fn removing_asks() {
        let mut c = center();
        c.page = Some("org.gnome.Calculator".into());
        c.key(KEY_DELETE, None, 0);
        assert!(c.confirm_remove && c.status.as_ref().is_some_and(|s| s.1));
        c.key(KEY_UP, None, 0);
        assert!(!c.confirm_remove, "anything else forgets it");
        // Not installed: Delete does nothing.
        c.page = Some("org.inkscape.Inkscape".into());
        assert_eq!(c.key(KEY_DELETE, None, 0), Effect::None);
    }

    #[test]
    fn the_cache() {
        let dir = std::env::temp_dir().join(format!("slate-appcenter-{}", std::process::id()));
        let home = dir.to_string_lossy().into_owned();
        std::fs::create_dir_all(format!("{home}/{CATALOG_DIR}")).unwrap();
        std::fs::write(
            format!("{home}/{CATALOG_DIR}/appstream.xml"),
            "<components><component type=\"desktop-application\"><id>a.b.C</id><name>C</name>\
             <summary>s</summary></component></components>",
        )
        .unwrap();
        assert_eq!(build_cache(&home), Ok(1));
        let apps = load_cache(&std::fs::read_to_string(format!("{home}/{CACHE}")).unwrap());
        assert_eq!(apps[0].id, "a.b.C");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
