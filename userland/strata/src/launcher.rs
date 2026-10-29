// SPDX-License-Identifier: MIT OR Apache-2.0

//! The launcher (docs/design/WM_STYLE.md §5, ADR 0037): apps from
//! `/usr/share/strata/apps` and Strata's actions in one filtered list,
//! driven by the keyboard or the pointer. Matching is fuzzy and ranked
//! (ADR 0039); with nothing typed, the apps opened last come first, from
//! `~/.config/strata/recent`.
//!
//! An app entry is a small text file of `key=value` lines: `name`, `exec`
//! (an absolute path), and optionally `icon` (terminal, folder, letter,
//! document, globe, search...), `kind` (the right-hand label, "app" by default),
//! `category` (its group, ADR 0102), `comment` (a line saying what it is
//! for, which the Applications menu shows, ADR 0110) and `linux=yes` for
//! a Linux program (its row gets the tag).
//!
//! With nothing typed the apps are listed by category; typing lists every
//! match. The list shows a window of rows that follows the selection and
//! the wheel (ADR 0102).

use alloc::string::String;
use alloc::vec::Vec;

use slate_ui::icon::Icon;
use slate_ui::themes::Stratum;

use crate::draw::{Row, Section};

/// An app the launcher offers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct App {
    pub name: String,
    pub exec: String,
    pub icon: Icon,
    pub kind: String,
    pub linux: bool,
    /// The group it is listed in ("system", "internet"...).
    pub category: String,
    /// What it is for, in a line.
    pub comment: String,
    /// Its colour in themes with app accents (`accent=`, one of the five
    /// strata; ADR 0167's addendum).
    pub accent: Option<Stratum>,
}

/// The categories in the order they are listed; others follow by name.
const CATEGORIES: [&str; 10] = [
    "accessories",
    "internet",
    "office",
    "graphics",
    "sound & video",
    "development",
    "games",
    "system",
    "settings",
    "help",
];

/// A desktop entry's `Categories` (the Desktop Menu Specification's main
/// categories) as Strata's group.
fn category_of(categories: &str) -> &'static str {
    for c in categories.split(';') {
        let group = match c {
            "Network" | "WebBrowser" | "Email" | "Chat" => "internet",
            "Office" => "office",
            "Graphics" => "graphics",
            "AudioVideo" | "Audio" | "Video" => "sound & video",
            "Development" => "development",
            "Game" => "games",
            "Settings" => "settings",
            "System" => "system",
            "Utility" | "Accessories" => "accessories",
            _ => continue,
        };
        return group;
    }
    "other"
}

/// Read an app entry; None if it lacks a name or an absolute `exec`.
pub fn parse_app(text: &str) -> Option<App> {
    let mut app = App {
        name: String::new(),
        exec: String::new(),
        icon: Icon::Terminal,
        kind: String::from("app"),
        linux: false,
        category: String::from("other"),
        comment: String::new(),
        accent: None,
    };
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        let v = v.trim();
        match k.trim() {
            "name" => app.name = String::from(v),
            "exec" => app.exec = String::from(v),
            "kind" => app.kind = String::from(v),
            "linux" => app.linux = v == "yes",
            "category" => app.category = v.to_lowercase(),
            "comment" => app.comment = String::from(v),
            // Anything but the five is ignored: no app brings its own hue.
            "accent" => app.accent = Stratum::parse(v),
            "icon" => {
                app.icon = match v {
                    "folder" => Icon::Folder,
                    "letter" => Icon::Letter,
                    "document" => Icon::Document,
                    "globe" => Icon::Globe,
                    "search" => Icon::Search,
                    "sliders" => Icon::Sliders,
                    "calculator" => Icon::Calculator,
                    "cards" => Icon::Cards,
                    "flag" => Icon::Flag,
                    "clock" => Icon::Clock,
                    "info" => Icon::Info,
                    "picture" => Icon::Picture,
                    "archive" => Icon::Archive,
                    "folder-home" => Icon::Home,
                    "calendar" => Icon::Calendar,
                    "person" => Icon::Person,
                    "activity" => Icon::Activity,
                    "disk" => Icon::Disk,
                    "download" => Icon::Download,
                    _ => Icon::Terminal,
                }
            }
            _ => {}
        }
    }
    (!app.name.is_empty() && app.exec.starts_with('/')).then_some(app)
}

/// A Linux runtime's app (ADR 0038) from its desktop entry (the
/// freedesktop.org Desktop Entry Specification): the `[Desktop Entry]`
/// group's Name and Exec, without Exec's field codes (`%u`, `%F`...);
/// None for entries that are hidden, not applications, or for terminals.
/// It runs through slate-linux-app, tagged "linux".
pub fn parse_desktop_entry(text: &str) -> Option<App> {
    let (mut name, mut exec, mut web, mut comment) = (String::new(), String::new(), false, String::new());
    let mut category = "other";
    let mut in_entry = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        let Some((k, v)) = line.split_once('=').filter(|_| in_entry) else { continue };
        match (k.trim(), v.trim()) {
            ("Name", v) => name = String::from(v),
            ("Exec", v) => exec = String::from(v),
            ("Comment", v) => comment = String::from(v),
            ("Type", t) if t != "Application" => return None,
            ("NoDisplay" | "Hidden" | "Terminal", "true") => return None,
            ("Categories", c) => {
                web = c.split(';').any(|c| c == "WebBrowser");
                category = category_of(c);
            }
            _ => {}
        }
    }
    let words: alloc::vec::Vec<&str> = exec.split_whitespace().filter(|w| !w.starts_with('%')).collect();
    if name.is_empty() || words.is_empty() {
        return None;
    }
    Some(App {
        name,
        exec: alloc::format!("/bin/slate-linux-app {}", words.join(" ")),
        icon: if web { Icon::Globe } else { Icon::Terminal },
        kind: String::from("app"),
        linux: true,
        category: String::from(category),
        comment,
        accent: None,
    })
}

/// Strata's own actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Lock,
    LogOut,
    Restart,
    PowerOff,
    Rollback,
    /// The live system's (M27): leave the live session for the installer.
    Install,
}

impl Action {
    pub const ALL: [Action; 5] = [Action::Lock, Action::LogOut, Action::Restart, Action::PowerOff, Action::Rollback];

    pub fn name(self) -> &'static str {
        match self {
            Action::Lock => "Lock screen",
            Action::LogOut => "Log out",
            Action::Restart => "Restart",
            Action::PowerOff => "Power off",
            Action::Rollback => "Roll back to the previous system",
            Action::Install => "Install SlateOS",
        }
    }

    fn icon(self) -> Icon {
        match self {
            Action::Lock => Icon::Shield,
            Action::LogOut | Action::PowerOff => Icon::Power,
            Action::Restart | Action::Rollback => Icon::Undo,
            Action::Install => Icon::Disk,
        }
    }

    fn meta(self) -> &'static str {
        if matches!(self, Action::LogOut | Action::Lock | Action::Install) { "session" } else { "system" }
    }

    /// The broker's name for it, if it needs system approval.
    pub fn system(self) -> Option<&'static str> {
        match self {
            Action::LogOut | Action::Lock | Action::Install => None,
            Action::Restart => Some("restart"),
            Action::PowerOff => Some("poweroff"),
            Action::Rollback => Some("rollback"),
        }
    }
}

/// What the launcher asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Close,
    Open(App),
    Do(Action),
}

#[derive(Clone, Debug, Default)]
pub struct Launcher {
    pub query: String,
    /// The selected row, counting through the whole list.
    pub selected: usize,
    /// The first row shown (the list scrolls).
    pub first: usize,
    apps: Vec<App>,
    /// The `exec` of the apps opened last, the latest first.
    recent: Vec<String>,
    /// On the live system: "Install SlateOS" is an action too.
    live: bool,
}

/// How many recent apps the launcher shows, and remembers.
pub const RECENT_SHOWN: usize = 3;
const RECENT_KEPT: usize = 8;
/// How tall the list may be (logical pixels): as many rows and section
/// labels as fit are shown, and the list scrolls past them. A row is 54
/// tall, a label 28, with 4 between sections (draw.rs, ADR 0124).
const LIST_H: f32 = 470.0;
const ROW_H: f32 = 54.0;
const LABEL_H: f32 = 32.0;

/// How well `name` matches `query`, ignoring case; None for not at all.
/// Better: the name starts with the query; a word does; the name holds
/// it; every word of the query starts a word of the name; and last the
/// query's letters in order (fuzzy: from the start of a word, within
/// three times the query's length, at least 8), the fewer and shorter the
/// gaps and the more at word starts the better.
pub fn score(name: &str, query: &str) -> Option<i32> {
    let (n, q) = (name.to_lowercase(), query.trim().to_lowercase());
    if q.is_empty() {
        return Some(0);
    }
    let words: Vec<&str> = n.split_whitespace().collect();
    if n.starts_with(&q) {
        return Some(1000);
    }
    if words.iter().any(|w| w.starts_with(&q)) {
        return Some(900);
    }
    if n.contains(&q) {
        return Some(800);
    }
    if q.split_whitespace().all(|w| words.iter().any(|x| x.starts_with(w))) {
        return Some(700);
    }
    // The letters in order, each as early as it can be.
    let name: Vec<char> = n.chars().collect();
    let letters: Vec<char> = q.chars().filter(|c| !c.is_whitespace()).collect();
    let (mut at, mut points, mut last, mut first) = (0usize, 500i32, None::<usize>, 0usize);
    for (k, &c) in letters.iter().enumerate() {
        let i = at + name[at..].iter().position(|&x| x == c)?;
        let word_start = i == 0 || !name[i - 1].is_alphanumeric();
        if k == 0 {
            if !word_start {
                return None;
            }
            first = i;
        }
        if i + 1 - first > (3 * letters.len()).max(8) {
            return None;
        }
        if word_start {
            points += 15;
        }
        if let Some(l) = last {
            points -= 5 * (i - l - 1).min(20) as i32;
        }
        last = Some(i);
        at = i + 1;
    }
    Some(points.clamp(1, 699))
}

/// One row of the list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry<'a> {
    App(&'a App),
    Action(Action),
}

impl<'a> Entry<'a> {
    fn row(self) -> Row<'a> {
        match self {
            Entry::App(a) => Row { icon: a.icon, name: &a.name, linux: a.linux, meta: &a.kind, comment: &a.comment },
            Entry::Action(x) => Row { icon: x.icon(), name: x.name(), linux: false, meta: x.meta(), comment: "" },
        }
    }
}

/// Where category `c` is listed.
pub fn category_rank(c: &str) -> (usize, &str) {
    (CATEGORIES.iter().position(|x| *x == c).unwrap_or(CATEGORIES.len()), c)
}

impl Launcher {
    pub fn new(mut apps: Vec<App>) -> Launcher {
        apps.sort_by(|a, b| a.name.cmp(&b.name));
        Launcher { apps, ..Launcher::default() }
    }

    /// With the apps opened last (their `exec`, the latest first).
    pub fn with_recent(mut self, recent: Vec<String>) -> Launcher {
        self.recent = recent;
        self
    }

    /// On the live system (`/etc/slate/live`).
    pub fn with_live(mut self, live: bool) -> Launcher {
        self.live = live;
        self
    }

    /// Where `app` is among the recent ones (0 the latest).
    fn recency(&self, app: &App) -> usize {
        self.recent.iter().position(|e| *e == app.exec).unwrap_or(usize::MAX)
    }

    /// The whole list, in selection order, each row with its section's
    /// label: the recent apps (the launcher, nothing typed), the apps by
    /// category (nothing typed) or the matches best first, and the
    /// actions.
    pub fn entries(&self) -> Vec<(String, Entry<'_>)> {
        let mut out = Vec::new();
        if self.query.trim().is_empty() {
            let mut shown_recent: Vec<&App> = self.apps.iter().filter(|a| self.recency(a) < usize::MAX).collect();
            shown_recent.sort_by_key(|a| self.recency(a));
            shown_recent.truncate(RECENT_SHOWN);
            out.extend(shown_recent.iter().map(|a| (String::from("recent"), Entry::App(a))));
            let mut rest: Vec<&App> =
                self.apps.iter().filter(|a| !shown_recent.iter().any(|x| x.exec == a.exec)).collect();
            rest.sort_by(|a, b| category_rank(&a.category).cmp(&category_rank(&b.category)).then(a.name.cmp(&b.name)));
            out.extend(rest.into_iter().map(|a| (a.category.clone(), Entry::App(a))));
        } else {
            let mut found: Vec<(i32, &App)> =
                self.apps.iter().filter_map(|a| score(&a.name, &self.query).map(|s| (s, a))).collect();
            // Best first; among equals, the recent ones (order kept: names).
            found.sort_by_key(|(s, a)| (-s, self.recency(a)));
            // The section says how many (ADR 0124).
            let label = match found.len() {
                1 => String::from("1 match"),
                n => alloc::format!("{n} matches"),
            };
            out.extend(found.into_iter().map(|(_, a)| (label.clone(), Entry::App(a))));
        }
        let live = self.live.then_some(Action::Install);
        let mut actions: Vec<(i32, Action)> =
            live.into_iter().chain(Action::ALL).filter_map(|a| score(a.name(), &self.query).map(|s| (s, a))).collect();
        actions.sort_by_key(|(s, _)| -s);
        out.extend(actions.into_iter().map(|(_, a)| (String::from("actions"), Entry::Action(a))));
        out
    }

    fn count(&self) -> usize {
        self.entries().len()
    }

    /// How many rows fit, from row `first`, with their sections' labels.
    fn fit_from(&self, entries: &[(String, Entry<'_>)], first: usize) -> usize {
        let budget = LIST_H;
        let (mut h, mut n, mut label): (f32, usize, Option<&str>) = (0.0, 0, None);
        for (l, _) in entries.iter().skip(first) {
            let add = ROW_H + if label != Some(l.as_str()) { LABEL_H } else { 0.0 };
            if h + add > budget {
                break;
            }
            (h, n, label) = (h + add, n + 1, Some(l.as_str()));
        }
        n.max(1)
    }

    /// How many rows are shown now.
    pub fn shown(&self) -> usize {
        self.fit_from(&self.entries(), self.first)
    }

    /// The first row that keeps the list's end in view.
    fn last_first(&self, entries: &[(String, Entry<'_>)]) -> usize {
        (0..entries.len()).find(|&f| f + self.fit_from(entries, f) >= entries.len()).unwrap_or(0)
    }

    /// Keep the selection in the rows shown.
    fn follow(&mut self) {
        let first = {
            let e = self.entries();
            let mut f = self.first.min(self.selected);
            while self.selected >= f + self.fit_from(&e, f) {
                f += 1;
            }
            f
        };
        self.first = first;
    }

    /// The wheel: `lines` < 0 is up. The selection stays in view.
    pub fn scroll(&mut self, lines: i32) -> bool {
        let (first, n, len) = {
            let e = self.entries();
            let max = self.last_first(&e);
            let first = (self.first as i64 + i64::from(lines)).clamp(0, max as i64) as usize;
            (first, self.fit_from(&e, first), e.len())
        };
        if first == self.first {
            return false;
        }
        self.first = first;
        self.selected = self.selected.clamp(first, (first + n).min(len).saturating_sub(1));
        true
    }

    /// What the selected row asks for.
    pub fn activate(&self) -> Option<Outcome> {
        match self.entries().get(self.selected)?.1 {
            Entry::App(a) => Some(Outcome::Open(a.clone())),
            Entry::Action(x) => Some(Outcome::Do(x)),
        }
    }

    /// The pointer over shown row `i` (as drawn): select it.
    pub fn hover(&mut self, i: usize) -> bool {
        let j = self.first + i;
        let changed = j != self.selected && j < self.count();
        if changed {
            self.selected = j;
        }
        changed
    }

    /// Handle a key: the evdev code (Escape 1, Enter 28, Backspace 14, Tab
    /// 15, Up 103, Down 108, Page Up 104, Page Down 109) and the character
    /// it types.
    pub fn key(&mut self, code: u16, ch: Option<char>) -> Option<Outcome> {
        match code {
            1 => return Some(Outcome::Close),
            28 | 96 => return self.activate(),
            14 => {
                self.query.pop();
                (self.selected, self.first) = (0, 0);
            }
            // Tab: to the first action (§5's "tab actions").
            15 => {
                let e = self.entries();
                self.selected = e.iter().position(|(_, x)| matches!(x, Entry::Action(_))).unwrap_or(0);
            }
            103 => self.selected = self.selected.saturating_sub(1),
            108 => self.selected = (self.selected + 1).min(self.count().saturating_sub(1)),
            104 => self.selected = self.selected.saturating_sub(self.shown().max(1)),
            109 => self.selected = (self.selected + self.shown().max(1)).min(self.count().saturating_sub(1)),
            _ => {
                if let Some(c) = ch.filter(|c| !c.is_control()) {
                    self.query.push(c);
                    (self.selected, self.first) = (0, 0);
                }
            }
        }
        self.follow();
        None
    }

    /// The rows shown, by section (consecutive rows with one label).
    pub fn rows(&self) -> Vec<(String, Vec<Row<'_>>)> {
        let mut out: Vec<(String, Vec<Row<'_>>)> = Vec::new();
        let entries = self.entries();
        for (label, e) in entries.into_iter().skip(self.first).take(self.shown()) {
            let row = e.row();
            match out.last_mut() {
                Some((l, rows)) if *l == label => rows.push(row),
                _ => out.push((label, alloc::vec![row])),
            }
        }
        out
    }

    /// The selected row among those shown, and the scroll position
    /// (first, shown, total) when the list is longer than the window.
    pub fn view(&self) -> (usize, Option<(usize, usize, usize)>) {
        let total = self.count();
        let shown = self.shown();
        let scroll = (total > shown).then_some((self.first, shown, total));
        (self.selected.saturating_sub(self.first), scroll)
    }
}

/// The sections for [`crate::draw::launcher`].
pub fn sections<'a>(rows: &'a [(String, Vec<Row<'a>>)]) -> Vec<Section<'a>> {
    rows.iter().map(|(label, rows)| Section { label, rows }).collect()
}

/// `~/.config/strata/recent`.
fn recent_path() -> Option<Vec<u8>> {
    let home = slate_rt::env::var(b"HOME").filter(|h| !h.is_empty())?;
    Some(slate_rt::fs::join(&home, b".config/strata/recent"))
}

/// The apps opened last (their `exec`, the latest first).
pub fn load_recent() -> Vec<String> {
    let text = recent_path().and_then(|p| slate_rt::fs::read_file(&p).ok()).unwrap_or_default();
    slate_rt::lossy(&text).lines().filter(|l| !l.is_empty()).take(RECENT_KEPT).map(String::from).collect()
}

/// `recent` with `exec` the latest.
pub fn note_recent(recent: &mut Vec<String>, exec: &str) {
    recent.retain(|e| e != exec);
    recent.insert(0, String::from(exec));
    recent.truncate(RECENT_KEPT);
}

/// Remember that `exec` was opened.
pub fn remember(exec: &str) {
    let mut recent = load_recent();
    note_recent(&mut recent, exec);
    let Some(p) = recent_path() else { return };
    let home = slate_rt::env::var(b"HOME").unwrap_or_default();
    for d in [slate_rt::fs::join(&home, b".config"), slate_rt::fs::join(&home, b".config/strata")] {
        let _ = slate_rt::fs::mkdir(&d, 0o755);
    }
    let mut text = recent.join("\n");
    text.push('\n');
    let _ = slate_rt::fs::write_file(&p, text.as_bytes(), 0o644);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apps() -> Vec<App> {
        [
            "name=Terminal\nexec=/bin/terminal\nicon=terminal\ncategory=System",
            "name=Shortcuts\nexec=/bin/strata-keys\nicon=letter\nkind=help\ncategory=Help",
        ]
        .iter()
        .filter_map(|t| parse_app(t))
        .collect()
    }

    #[test]
    fn accents() {
        let with = |v: &str| parse_app(&alloc::format!("name=X\nexec=/bin/x\naccent={v}")).unwrap().accent;
        assert_eq!(with("sage"), Some(Stratum::Sage));
        assert_eq!(with(" Slate "), Some(Stratum::Slate));
        // A hue of its own is ignored.
        assert_eq!(with("#ff00ff"), None);
        assert_eq!(apps()[0].accent, None);
    }

    #[test]
    fn entries() {
        let a = apps();
        assert_eq!(a.len(), 2);
        assert_eq!((a[0].name.as_str(), a[0].exec.as_str(), a[0].kind.as_str()), ("Terminal", "/bin/terminal", "app"));
        assert_eq!(a[1].icon, Icon::Letter);
        assert!(parse_app("name=X\nexec=relative").is_none());
        assert!(parse_app("name=F\nexec=/usr/bin/firefox\nlinux=yes").is_some_and(|a| a.linux));
    }

    fn names(l: &Launcher) -> Vec<String> {
        l.entries()
            .iter()
            .map(|(_, e)| match e {
                Entry::App(a) => a.name.clone(),
                Entry::Action(x) => String::from(x.name()),
            })
            .collect()
    }

    #[test]
    fn filtering_and_keys() {
        let mut l = Launcher::new(apps());
        // By category (system before help); then the actions.
        assert_eq!(names(&l)[..2], ["Terminal", "Shortcuts"]);
        for c in "term".chars() {
            l.key(0, Some(c));
        }
        assert_eq!(names(&l), ["Terminal"]);
        assert_eq!(l.key(28, None), Some(Outcome::Open(apps()[0].clone())));
        for _ in 0..4 {
            l.key(14, None);
        }
        for c in "pow".chars() {
            l.key(0, Some(c));
        }
        assert_eq!(l.key(28, None), Some(Outcome::Do(Action::PowerOff)));
        l.query.clear();
        l.key(15, None);
        assert_eq!(l.selected, 2);
        // The first action is the lock screen; down, logging out.
        l.key(108, None);
        assert_eq!(l.key(28, None), Some(Outcome::Do(Action::LogOut)));
        // The live system's "Install SlateOS" (M27), only there.
        let mut live = Launcher::new(Vec::new()).with_live(true);
        for c in "install".chars() {
            live.key(0, Some(c));
        }
        assert_eq!(live.key(28, None), Some(Outcome::Do(Action::Install)));
        let mut installed = Launcher::new(Vec::new());
        for c in "install".chars() {
            installed.key(0, Some(c));
        }
        assert_ne!(installed.key(28, None), Some(Outcome::Do(Action::Install)));
        assert_eq!(l.key(1, None), Some(Outcome::Close));
    }

    #[test]
    fn categories_and_scrolling() {
        let mut all = apps();
        for (i, cat) in ["internet", "office", "games", "internet"].iter().enumerate() {
            all.extend(parse_app(&alloc::format!("name=App {i}\nexec=/bin/app{i}\ncategory={cat}")));
        }
        all.extend(parse_desktop_entry(
            "[Desktop Entry]\nType=Application\nName=Firefox\nExec=firefox %u\nCategories=Network;WebBrowser;\n",
        ));
        let mut l = Launcher::new(all);
        let labels: Vec<String> = l.entries().iter().map(|(c, _)| c.clone()).collect();
        assert_eq!(labels[..6], ["internet", "internet", "internet", "office", "games", "system"]);
        assert_eq!(names(&l)[..3], ["App 0", "App 3", "Firefox"]);
        // 7 apps and 5 actions: 12 rows in 6 sections. With their labels,
        // the launcher holds 6 of them.
        assert_eq!(l.count(), 12);
        assert_eq!(l.view().1, Some((0, 6, 12)));
        // Going down past them scrolls.
        for _ in 0..10 {
            l.key(108, None);
        }
        assert_eq!(l.selected, 10);
        assert!(l.first > 0 && l.selected < l.first + l.shown());
        let shown: usize = l.rows().iter().map(|(_, r)| r.len()).sum();
        assert_eq!(shown, l.shown());
        // The wheel scrolls back; the selection stays in view.
        assert!(l.scroll(-20));
        assert_eq!(l.first, 0);
        assert!(l.selected < l.shown());
        assert!(!l.scroll(-1));
        // Hovering shown row 0 after scrolling selects the row there.
        l.scroll(3);
        let first = l.first;
        assert!(first > 0 && l.hover(0));
        assert_eq!(l.selected, first);
        // Typing starts at the top.
        l.key(0, Some('a'));
        assert_eq!((l.selected, l.first), (0, 0));
    }

    #[test]
    fn fuzzy_ranking() {
        assert_eq!(score("Terminal", ""), Some(0));
        assert_eq!(score("Terminal", "TER"), Some(1000));
        assert_eq!(score("Lock screen", "scr"), Some(900));
        assert_eq!(score("Terminal", "min"), Some(800));
        assert_eq!(score("Roll back to the previous system", "roll prev"), Some(700));
        // Letters in order: "trml" finds Terminal, "fx" Firefox.
        assert!(score("Terminal", "trml").is_some_and(|s| s < 700));
        assert!(score("Firefox", "fx").is_some());
        assert_eq!(score("Terminal", "xyz"), None);
        assert_eq!(score("Terminal", "lt"), None);
        // Closer letters rank higher.
        assert!(score("Shortcuts", "sht") > score("Settings", "sts"));
    }

    #[test]
    fn recent_and_pointer() {
        let mut all = apps();
        all.extend(parse_app("name=Settings\nexec=/bin/strata-settings"));
        let mut recent = Vec::new();
        note_recent(&mut recent, "/bin/terminal");
        note_recent(&mut recent, "/bin/strata-settings");
        note_recent(&mut recent, "/bin/terminal");
        assert_eq!(recent, ["/bin/terminal", "/bin/strata-settings"]);
        let mut l = Launcher::new(all).with_recent(recent);
        assert_eq!(names(&l)[..3], ["Terminal", "Settings", "Shortcuts"]);
        let rows = l.rows();
        let labels: Vec<&str> = sections(&rows).iter().map(|s| s.label).collect();
        assert_eq!(labels, ["recent", "help", "actions"]);
        // The pointer selects the third row, Shortcuts; a click opens it.
        assert!(l.hover(2));
        assert!(!l.hover(2));
        assert!(!l.hover(99));
        assert!(matches!(l.activate(), Some(Outcome::Open(a)) if a.name == "Shortcuts"));
        // Typing: "s" ranks Settings and Shortcuts (name starts), recent first.
        l.key(0, Some('s'));
        assert_eq!(names(&l)[..2], ["Settings", "Shortcuts"]);
    }
}
