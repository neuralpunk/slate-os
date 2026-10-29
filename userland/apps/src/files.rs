// SPDX-License-Identifier: MIT OR Apache-2.0

//! Files (ADR 0108), `files [FOLDER]`: Slate's file manager, in the
//! manner of GNOME's Files.
//!
//! - A sidebar of places (Home and its usual folders that exist, the
//!   disks mounted, the trash), a path bar of the folders above, back
//!   and forward.
//! - A list (name, size, modified; a header click sorts) or a grid with
//!   thumbnails of pictures (ctrl + 1, ctrl + 2); hidden files with
//!   ctrl + h; typing filters the folder, ctrl + f searches under it.
//! - Enter or a double click opens: a folder in place, a file in Slate's
//!   app for it (pictures, archives, text).
//! - ctrl + c, x and v copy, cut and paste; F2 renames; ctrl + shift + n
//!   makes a folder; Delete moves to the trash; ctrl + z undoes the last
//!   of these. The right button has them all, and Compress.
//! - In the trash, Enter restores, Delete deletes for good (pressed
//!   twice), and the menu empties it. Each disk has its own trash; the
//!   Trash place shows them all.
//! - Copies, and moves across disks, run in the background a mebibyte at
//!   a time, the status line saying how far they are (Esc stops them).
//!   Dragging chosen items onto a folder or a place moves them there
//!   (onto the trash: trashes them).
//! - Removable disks Slate can open show under "disks" before they are
//!   mounted: a click mounts one (in `/run/media/USER`, through the
//!   broker, without asking) and goes in; the right button on a mounted
//!   one unmounts it, to remove it (ADR 0112's addendum).
//! - ctrl + d bookmarks the folder (the sidebar's bookmarks; the right
//!   button removes one); alt + Enter shows a file's properties, its
//!   permissions changed there; "Open with" picks another of Slate's apps;
//!   Tab in the search field searches the files' text too.
//!
//! What it does to files is [`crate::fsops`].

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_display::input::{
    KEY_BACKSPACE, KEY_DELETE, KEY_DOWN, KEY_END, KEY_ENTER, KEY_ESC, KEY_HOME, KEY_KPENTER, KEY_LEFT, KEY_PAGEDOWN,
    KEY_PAGEUP, KEY_RIGHT, KEY_TAB, KEY_UP,
};
use slate_image::Image;
use slate_strata::fonts::Fonts;
use slate_strata_client::mods::{ALT, CTRL, LOGO, SHIFT};
use slate_ui::edit::{EditKey, LineEdit};
use slate_ui::graphite::Palette;
use slate_ui::icon::Icon;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;

use crate::fsops::{self, Entry, Kind, Sort, Trash};
use crate::kit::{self, App, Effect, Hints, Now};

/// F2 and F5 (input-event-codes.h, as slate-display's other keys).
const KEY_F2: u16 = 60;
const KEY_F5: u16 = 63;

const SIDEBAR_W: f32 = 196.0;
const ROW_H: f32 = 32.0;
const TILE_W: f32 = 112.0;
const TILE_H: f32 = 124.0;
const THUMB: (u32, u32) = (96, 72);
/// Pictures larger than this get no thumbnail (bytes).
const THUMB_MAX: i64 = 32 << 20;
/// How often the folder is looked at for changes (ms).
const REFRESH_MS: i64 = 2000;
/// A search stops after this many results.
const SEARCH_MAX: usize = 2000;
/// A search of the files' text reads files up to this size, and this
/// much in all.
const SEARCH_FILE_MAX: i64 = 4 << 20;
const SEARCH_READ_MAX: u64 = 256 << 20;
/// The bookmarks' file, in `~/.config/strata`.
const BOOKMARKS: &str = "bookmarks";
/// How far the pointer moves before a press on a row is a drag.
const DRAG_START: f32 = 6.0;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Place {
    Folder(String),
    Trash,
    /// A removable disk's partition not mounted yet: a click mounts it.
    Device(String),
    /// Search results under a folder: names, or names and text.
    Search {
        root: String,
        query: String,
        contents: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    List,
    Grid,
}

/// What ctrl + z undoes, here and on the desktop.
pub use slate_strata::undo::Op;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Open,
    Cut,
    Copy,
    Paste,
    Rename,
    Trash,
    NewFolder,
    Compress,
    Restore,
    DeleteForGood,
    EmptyTrash,
    ToggleHidden,
    Properties,
    /// The menu of apps to open with.
    OpenWith,
    /// Open with [`OPEN_WITH`]'s app.
    OpenWithApp(u8),
    Bookmark,
    /// Remove the bookmark the menu was opened on.
    Unbookmark,
    /// Unmount the disk the menu was opened on.
    Unmount,
    /// Make the picture the desktop's wallpaper (ADR 0110's second
    /// addendum).
    SetWallpaper,
}

/// The apps "Open with" offers: their names and programs.
pub const OPEN_WITH: [(&str, &str); 5] = [
    ("Text Editor", "/bin/text-editor"),
    ("Image Viewer", "/bin/image-viewer"),
    ("Archive Manager", "/bin/archive-manager"),
    ("Calendar", "/bin/calendar"),
    ("Contacts", "/bin/contacts"),
];

/// Copies, and moves across disks, under way (in a [`kit::Job`]).
#[derive(Debug)]
pub struct Transfer {
    /// (from, to), in order.
    pub list: Vec<(String, String)>,
    pub cut: bool,
    /// The bytes to copy, and copied so far.
    pub total: u64,
    pub done: u64,
    /// The item being copied, and whether its copy is finished (a move
    /// then removes the original).
    pub at: usize,
    pub removing: bool,
    pub(crate) job: Option<kit::Job>,
}

/// The properties dialog (alt + Enter).
#[derive(Clone, Debug, PartialEq)]
pub struct Props {
    pub paths: Vec<String>,
    pub name: String,
    pub kind: String,
    /// Bytes, things counted, and whether the count stopped short.
    pub size: (u64, usize, bool),
    pub location: String,
    pub modified: i64,
    pub owner: String,
    /// The mode bits, for one file or folder (not a link) the person owns
    /// or can see.
    pub mode: Option<u32>,
    /// Whether the person may change them (owns it, or is root).
    pub mine: bool,
    /// Which of the nine permission boxes the keys are on.
    pub focus: usize,
    hits: Vec<Area>,
}

/// A drag of chosen items: where to, if somewhere takes them.
#[derive(Clone, Debug, PartialEq)]
pub struct Dragging {
    pub paths: Vec<String>,
    pub x: f32,
    pub y: f32,
    pub target: Option<Place>,
    /// ctrl is held: dropped, they are copied.
    pub copy: bool,
}

#[derive(Clone, Debug)]
pub struct Menu {
    pub x: f32,
    pub y: f32,
    pub items: Vec<(&'static str, Action)>,
    pub selected: usize,
    hits: Vec<Area>,
}

/// One row shown: a folder entry, or a search result or trash item with
/// its path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub entry: Entry,
    /// Its full path (in the trash: where it is in the trash).
    pub path: String,
    /// Shown under the name in search and the trash: where it is, or
    /// came from.
    pub note: Option<String>,
}

#[derive(Debug)]
pub struct Files {
    pub place: Place,
    back: Vec<Place>,
    forward: Vec<Place>,
    pub items: Vec<Item>,
    pub selected: Vec<bool>,
    pub cursor: usize,
    anchor: Option<usize>,
    first: usize,
    pub view: View,
    pub sort: Sort,
    pub reverse: bool,
    pub hidden: bool,
    /// Typed to filter the folder.
    pub filter: String,
    pub rename: Option<LineEdit>,
    pub location: Option<LineEdit>,
    pub search: Option<LineEdit>,
    /// Copied or cut paths, and whether cut.
    pub clip: Option<(Vec<String>, bool)>,
    pub undo: Vec<Op>,
    pub menu: Option<Menu>,
    pub status: String,
    /// Delete pressed once in the trash: the next one deletes.
    confirm_delete: bool,
    pub home: String,
    /// The home trash; disks' own are found beside it.
    pub trash: Option<Trash>,
    /// Folders bookmarked (the sidebar's, `~/.config/strata/bookmarks`).
    pub bookmarks: Vec<String>,
    /// The running app (not a test or a scene): copies go to the
    /// background and bookmarks are saved.
    pub live: bool,
    pub transfer: Option<Transfer>,
    pub props: Option<Props>,
    pub dragging: Option<Dragging>,
    /// The first row as last said (traced, for the scenarios' pointer).
    traced_row: Option<Area>,
    /// Search the files' text too (Tab in the search field).
    pub search_contents: bool,
    /// Where the button went down on a row (x, y, item), and whether the
    /// click only chooses it when it comes up (it was chosen already, so
    /// a drag takes all that are).
    press: Option<(f32, f32, usize, bool)>,
    /// The bookmark the menu was opened on.
    menu_bookmark: Option<String>,
    /// Where the last menu opened ("Open with" opens there too).
    last_menu: Option<(f32, f32)>,
    /// Removable disks' partitions not mounted that Slate can open:
    /// (device, what to call it).
    pub unmounted: Vec<(String, String)>,
    /// A mount or unmount asked of the broker: its job, the device, and
    /// whether mounting.
    disk_job: Option<(kit::Job, String, bool)>,
    /// The mounted disk the menu was opened on (its device).
    menu_disk: Option<String>,
    /// (label, path, icon) in the sidebar, and the disks.
    pub places: Vec<(String, String, Icon)>,
    pub disks: Vec<fsops::Mount>,
    /// Whether the status line says how much space is free (off in the
    /// scenes, which must look the same on every machine).
    pub show_free: bool,
    thumbs: BTreeMap<(String, i64), Option<Image>>,
    /// The folder's modification time when read, and when last looked at.
    stamp: Option<(i64, i64)>,
    checked: i64,
    // Where things were drawn.
    rows: Vec<Area>,
    side: Vec<(Area, Place)>,
    crumbs: Vec<(Area, String)>,
    headers: Vec<(Area, Sort)>,
    nav: Vec<(Area, u8)>,
    per_row: usize,
    shown: usize,
}

fn now_s() -> i64 {
    slate_rt::time::unix()
}

impl Files {
    pub fn new(home: &str, start: Place) -> Files {
        let mut places = alloc::vec![(String::from("Home"), String::from(home), Icon::Home)];
        for (name, icon) in [
            ("Desktop", Icon::Grid),
            ("Documents", Icon::Folder),
            ("Downloads", Icon::Folder),
            ("Pictures", Icon::Picture),
            ("Music", Icon::Folder),
            ("Videos", Icon::Folder),
        ] {
            let p = fsops::join(home, name);
            if slate_rt::fs::stat(p.as_bytes()).is_ok_and(|s| s.mode & slate_rt::fs::S_IFMT == slate_rt::fs::S_IFDIR) {
                places.push((String::from(name), p, icon));
            }
        }
        let disks =
            slate_rt::fs::read_file(b"/proc/mounts").map(|t| fsops::mounts(&slate_rt::lossy(&t))).unwrap_or_default();
        let mut f = Files {
            place: start,
            back: Vec::new(),
            forward: Vec::new(),
            items: Vec::new(),
            selected: Vec::new(),
            cursor: 0,
            anchor: None,
            first: 0,
            view: View::List,
            sort: Sort::Name,
            reverse: false,
            hidden: false,
            filter: String::new(),
            rename: None,
            location: None,
            search: None,
            clip: None,
            undo: Vec::new(),
            menu: None,
            status: String::new(),
            confirm_delete: false,
            home: String::from(home),
            trash: Trash::home(),
            bookmarks: Vec::new(),
            live: false,
            transfer: None,
            props: None,
            dragging: None,
            traced_row: None,
            search_contents: false,
            press: None,
            menu_bookmark: None,
            last_menu: None,
            unmounted: Vec::new(),
            disk_job: None,
            menu_disk: None,
            places,
            disks,
            show_free: true,
            thumbs: BTreeMap::new(),
            stamp: None,
            checked: 0,
            rows: Vec::new(),
            side: Vec::new(),
            crumbs: Vec::new(),
            headers: Vec::new(),
            nav: Vec::new(),
            per_row: 1,
            shown: 1,
        };
        f.load();
        f
    }

    /// The folder shown, if a folder is.
    pub fn folder(&self) -> Option<&str> {
        match &self.place {
            Place::Folder(p) => Some(p),
            _ => None,
        }
    }

    /// Read the place again, keeping the selection by name.
    pub fn load(&mut self) {
        let keep: Vec<String> = self.chosen_paths();
        let cursor_path = self.items.get(self.cursor).map(|i| i.path.clone());
        self.items = match &self.place {
            // (Never shown: a click mounts it and goes there.)
            Place::Device(_) => Vec::new(),
            Place::Folder(dir) => match fsops::list(dir) {
                Ok(mut es) => {
                    fsops::sort(&mut es, self.sort, self.reverse);
                    es.into_iter()
                        .filter(|e| self.hidden || !e.hidden())
                        .map(|e| Item { path: fsops::join(dir, &e.name), entry: e, note: None })
                        .collect()
                }
                Err(e) => {
                    self.status = alloc::format!("Can't open {e}");
                    Vec::new()
                }
            },
            Place::Trash => {
                let mut all: Vec<(String, Item)> = Vec::new();
                for t in self.trashes() {
                    for x in t.list() {
                        let path = t.path_of(&x.name);
                        let mut entry = item_entry(&path, &x.name);
                        entry.name = fsops::base(&x.from).to_string();
                        if entry.name == "/" || x.from.is_empty() {
                            entry.name = x.name.clone();
                        }
                        let note = Some(alloc::format!("from {}", self.pretty(&fsops::parent(&x.from))));
                        all.push((x.date, Item { entry, path, note }));
                    }
                }
                // The latest first, whichever disk.
                all.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.path.cmp(&b.1.path)));
                all.into_iter().map(|(_, i)| i).collect()
            }
            Place::Search { root, query, contents } => search(root, query, self.hidden, *contents)
                .into_iter()
                .map(|p| {
                    let entry = item_entry(&p, fsops::base(&p));
                    Item { note: Some(self.pretty(&fsops::parent(&p))), path: p, entry }
                })
                .collect(),
        };
        if !self.filter.is_empty() {
            let f = self.filter.to_lowercase();
            self.items.retain(|i| i.entry.name.to_lowercase().contains(&f));
        }
        self.selected = self.items.iter().map(|i| keep.contains(&i.path)).collect();
        self.cursor = cursor_path.and_then(|c| self.items.iter().position(|i| i.path == c)).unwrap_or(0);
        self.cursor = self.cursor.min(self.items.len().saturating_sub(1));
        self.stamp = self.folder().and_then(|d| slate_rt::fs::stat(d.as_bytes()).ok()).map(|s| (s.mtime, s.mtime_nsec));
    }

    /// A path for people: ~ for home.
    pub fn pretty(&self, p: &str) -> String {
        match p.strip_prefix(&self.home) {
            Some(rest) if rest.is_empty() || rest.starts_with('/') => alloc::format!("~{rest}"),
            _ => p.to_string(),
        }
    }

    /// Every trash: home's, then each disk's that exists.
    pub fn trashes(&self) -> Vec<Trash> {
        let mut out: Vec<Trash> = self.trash.iter().cloned().collect();
        let uid = slate_rt::process::getuid();
        for d in &self.disks {
            let t = Trash::on_disk(&d.at, uid);
            if !out.contains(&t) && slate_rt::fs::stat(t.dir.as_bytes()).is_ok() {
                out.push(t);
            }
        }
        out
    }

    /// The trash `path` (something in a trash) is in.
    fn trash_holding(&self, path: &str) -> Option<Trash> {
        self.trashes().into_iter().find(|t| t.holds(path))
    }

    /// Removable disks' partitions Slate can open that aren't mounted.
    pub fn read_unmounted() -> Vec<(String, String)> {
        let (disks, _) = slate_sysinfo::block::read(&slate_sysinfo::block::RealSys);
        let mounts =
            slate_rt::fs::read_file(b"/proc/mounts").map(|t| String::from(slate_rt::lossy(&t))).unwrap_or_default();
        let mounted = |dev: &str| mounts.lines().any(|l| l.split(' ').next() == Some(&alloc::format!("/dev/{dev}")));
        let mut out = Vec::new();
        for d in disks.iter().filter(|d| d.removable) {
            for p in &d.parts {
                if let Some(h) = &p.holds
                    && slate_diskutil::mountable(&h.fs)
                    && !mounted(&p.name)
                {
                    let name = if h.label.is_empty() {
                        alloc::format!("{} ({})", d.model.trim(), p.name)
                    } else {
                        h.label.clone()
                    };
                    out.push((p.name.clone(), name));
                }
            }
        }
        out
    }

    /// Ask the broker to mount (or unmount) `dev`, in the background.
    fn ask_disk(&mut self, dev: &str, mount: bool) {
        if self.disk_job.is_some() {
            return;
        }
        let words = alloc::format!("disk={} {dev}", if mount { "mount" } else { "unmount" });
        crate::trace!("files: asking for {words}");
        match kit::Job::start(move || kit::broker(&words).map(|()| String::new())) {
            Ok(j) => {
                self.status = String::from(if mount { "Opening the disk…" } else { "Unmounting…" });
                self.disk_job = Some((j, dev.to_string(), mount));
            }
            Err(e) => self.status = alloc::format!("Couldn't ask: {e}"),
        }
    }

    /// The mounts and removable disks as they are now.
    fn reread_disks(&mut self) {
        self.disks =
            slate_rt::fs::read_file(b"/proc/mounts").map(|t| fsops::mounts(&slate_rt::lossy(&t))).unwrap_or_default();
        self.unmounted = Files::read_unmounted();
    }

    /// Move `path` to its disk's trash (else home's): where it went.
    fn put_in_trash(&self, path: &str) -> Result<String, String> {
        let home = self.trash.clone().ok_or_else(|| String::from("there is no trash"))?;
        let t = fsops::trash_for(path, &home, &self.home, &self.disks, slate_rt::process::getuid());
        let (t, name) = match t.put(path, now_s()) {
            Ok(n) => (t, n),
            // A disk's trash that can't be made (no rights there): home's.
            Err(_) if t != home => {
                let n = home.put(path, now_s())?;
                (home, n)
            }
            Err(e) => return Err(e),
        };
        Ok(t.path_of(&name))
    }

    pub fn go(&mut self, place: Place) {
        if place == self.place {
            return;
        }
        let old = core::mem::replace(&mut self.place, place);
        self.back.push(old);
        self.forward.clear();
        self.arrive();
    }

    fn arrive(&mut self) {
        self.items.clear();
        self.selected.clear();
        self.filter.clear();
        self.cursor = 0;
        self.first = 0;
        self.anchor = None;
        self.rename = None;
        self.confirm_delete = false;
        self.load();
        crate::trace!("files: in {}", self.title_path());
    }

    fn back(&mut self) {
        if let Some(p) = self.back.pop() {
            let now = core::mem::replace(&mut self.place, p);
            self.forward.push(now);
            self.arrive();
        }
    }

    fn forward_(&mut self) {
        if let Some(p) = self.forward.pop() {
            let now = core::mem::replace(&mut self.place, p);
            self.back.push(now);
            self.arrive();
        }
    }

    fn up(&mut self) {
        let to = match &self.place {
            Place::Folder(p) if p != "/" => fsops::parent(p),
            Place::Search { root, .. } => root.clone(),
            _ => return,
        };
        let from = self.folder().map(String::from);
        self.go(Place::Folder(to));
        if let Some(f) = from {
            self.cursor = self.items.iter().position(|i| i.path == f).unwrap_or(0);
            self.select_only(self.cursor);
        }
    }

    /// The items selected.
    pub fn chosen(&self) -> Vec<usize> {
        (0..self.items.len()).filter(|&i| self.selected.get(i) == Some(&true)).collect()
    }

    fn chosen_paths(&self) -> Vec<String> {
        self.chosen().iter().map(|&i| self.items[i].path.clone()).collect()
    }

    fn select_only(&mut self, i: usize) {
        self.selected = alloc::vec![false; self.items.len()];
        if let Some(s) = self.selected.get_mut(i) {
            *s = true;
        }
        self.anchor = Some(i);
    }

    fn move_cursor(&mut self, to: usize, extend: bool) {
        if self.items.is_empty() {
            return;
        }
        let to = to.min(self.items.len() - 1);
        self.cursor = to;
        if extend {
            let a = *self.anchor.get_or_insert(to);
            let (lo, hi) = (a.min(to), a.max(to));
            self.selected = (0..self.items.len()).map(|i| (lo..=hi).contains(&i)).collect();
        } else {
            self.select_only(to);
        }
        self.confirm_delete = false;
    }

    /// Open what is chosen.
    pub fn open(&mut self) -> Effect {
        let chosen = self.chosen();
        let which = if chosen.is_empty() { alloc::vec![self.cursor] } else { chosen };
        let Some(&first) = which.first().filter(|&&i| i < self.items.len()) else { return Effect::None };
        if self.place == Place::Trash {
            return self.act(Action::Restore);
        }
        if self.items[first].entry.is_folder() {
            let p = self.items[first].path.clone();
            self.go(Place::Folder(p));
            return Effect::Redraw;
        }
        let mut opened = 0;
        for i in which {
            let it = &self.items[i];
            if it.entry.is_folder() {
                continue;
            }
            let o = fsops::opener(&it.entry.name, &fsops::head(&it.path));
            match o.program() {
                Some(prog) => match fsops::start(prog, core::slice::from_ref(&it.path)) {
                    Ok(()) => {
                        crate::trace!("files: opened {} with {prog}", it.path);
                        opened += 1;
                    }
                    Err(e) => self.status = e,
                },
                None => self.status = alloc::format!("No app in Slate opens {} yet.", it.entry.name),
            }
        }
        if opened > 0 {
            self.status.clear();
        }
        Effect::Redraw
    }

    fn paste(&mut self) {
        let Some(dir) = self.folder().map(String::from) else {
            self.status = String::from("Paste into a folder.");
            return;
        };
        let Some((paths, cut)) = self.clip.clone() else { return };
        if self.transfer_into(&paths, &dir, cut) && cut {
            self.clip = None;
        }
    }

    /// Copy (or move) `paths` into `dir`: moves on the same disk at once,
    /// the rest in the background when the app is live. Whether anything
    /// was started.
    pub fn transfer_into(&mut self, paths: &[String], dir: &str, cut: bool) -> bool {
        if self.transfer.is_some() {
            self.status = String::from("Wait for the copy under way, or stop it with Esc.");
            return false;
        }
        let mut list: Vec<(String, String)> = Vec::new();
        for p in paths {
            if cut && fsops::parent(p) == dir {
                continue;
            }
            let mut name = fsops::free_name(dir, fsops::base(p), "copy");
            // Two from different folders with one name: apart here too.
            while list.iter().any(|(_, t)| fsops::base(t) == name) {
                name = alloc::format!("{name} (2)");
            }
            list.push((p.clone(), fsops::join(dir, &name)));
        }
        if list.is_empty() {
            return false;
        }
        // Moves on one disk are renames: at once.
        if cut && list.iter().all(|(f, _)| fsops::same_disk(f, dir)) {
            let mut done = Vec::new();
            for (f, t) in &list {
                match fsops::move_to(f, t) {
                    Ok(()) => done.push((f.clone(), t.clone())),
                    Err(e) => {
                        self.status = alloc::format!("Couldn't move: {e}");
                        break;
                    }
                }
            }
            self.finish_transfer(&list, done.len(), true, None);
            return true;
        }
        let total = list.iter().map(|(f, _)| fsops::size_of(f, 200_000).0).sum();
        let mut t = Transfer { list, cut, total, done: 0, at: 0, removing: false, job: None };
        if !self.live {
            let (n, e) = transfer_work(&t.list, cut, &mut |_, _, _| {});
            let list = core::mem::take(&mut t.list);
            self.finish_transfer(&list, n, cut, e);
            return true;
        }
        let work = t.list.clone();
        match kit::Job::reporting(move |r| {
            let mut last = 0i64;
            let (n, e) = transfer_work(&work, cut, &mut |done, at, removing| {
                let now = Now::read().mono;
                if now - last >= 100 || removing {
                    last = now;
                    r.say(&alloc::format!("{done}\t{at}\t{}", u8::from(removing)));
                }
            });
            Ok(alloc::format!("{n}\n{}", e.unwrap_or_default()))
        }) {
            Ok(j) => {
                t.job = Some(j);
                crate::trace!("files: {} {} in the background", if cut { "moving" } else { "copying" }, t.list.len());
                self.transfer = Some(t);
            }
            Err(e) => self.status = alloc::format!("Couldn't start copying: {e}"),
        }
        true
    }

    /// The first `n` of `list` were copied or moved (`e`: why the rest
    /// weren't).
    fn finish_transfer(&mut self, list: &[(String, String)], n: usize, cut: bool, e: Option<String>) {
        let done: Vec<(String, String)> = list[..n.min(list.len())].to_vec();
        if let Some(e) = e {
            self.status = alloc::format!("Couldn't {}: {e}", if cut { "move" } else { "copy" });
        }
        if done.is_empty() {
            return;
        }
        let into = fsops::parent(&done[0].1);
        crate::trace!("files: {} {} into {into}", if cut { "moved" } else { "copied" }, done.len());
        let names: Vec<String> = done.iter().map(|(_, t)| t.clone()).collect();
        if n == list.len() {
            self.status = alloc::format!("{} {}.", if cut { "Moved" } else { "Copied" }, count(done.len(), "item"));
        }
        self.undo.push(if cut { Op::Moved(done) } else { Op::Copied(names.clone()) });
        self.load();
        self.selected = self.items.iter().map(|i| names.contains(&i.path)).collect();
    }

    /// Stop the copy under way: what was finished stays (and can be
    /// undone); a half-made copy goes, the original untouched.
    fn stop_transfer(&mut self) {
        let Some(mut t) = self.transfer.take() else { return };
        if let Some(j) = t.job.take() {
            j.cancel();
        }
        if let Some((from, to)) = t.list.get(t.at).cloned()
            && !t.removing
            && slate_rt::fs::lstat(from.as_bytes()).is_ok()
        {
            let _ = fsops::remove(&to);
        }
        let n = t.at;
        let list = core::mem::take(&mut t.list);
        self.finish_transfer(&list, n, t.cut, None);
        self.status = alloc::format!("Stopped: {} of {} done.", n, list.len());
        crate::trace!("files: stopped after {n}");
        self.load();
    }

    /// How far the copy is, for the status line.
    pub fn transfer_text(&self) -> Option<(String, f32)> {
        let t = self.transfer.as_ref()?;
        let frac = if t.total == 0 { 0.0 } else { (t.done as f32 / t.total as f32).min(1.0) };
        let what = if t.cut { "Moving" } else { "Copying" };
        let text = alloc::format!(
            "{what} {} of {} · {} of {} · esc stops",
            (t.at + 1).min(t.list.len()),
            t.list.len(),
            crate::help::size(t.done),
            crate::help::size(t.total)
        );
        Some((text, frac))
    }

    fn trash_chosen(&mut self) {
        let paths = {
            let c = self.chosen();
            let c = if c.is_empty() && self.cursor < self.items.len() { alloc::vec![self.cursor] } else { c };
            c.iter().map(|&i| self.items[i].path.clone()).collect::<Vec<_>>()
        };
        self.trash_paths(&paths);
    }

    fn trash_paths(&mut self, paths: &[String]) {
        let mut done = Vec::new();
        for p in paths {
            match self.put_in_trash(p) {
                Ok(at) => done.push((p.clone(), at)),
                Err(e) => {
                    self.status = alloc::format!("Couldn't move it to the trash: {e}");
                    break;
                }
            }
        }
        if !done.is_empty() {
            crate::trace!("files: trashed {}", done.len());
            self.status = alloc::format!("Moved {} to the trash. ctrl z puts back.", count(done.len(), "item"));
            self.undo.push(Op::Trashed(done));
            self.load();
        }
    }

    pub fn undo_last(&mut self) {
        let Some(op) = self.undo.pop() else {
            self.status = String::from("Nothing to undo.");
            return;
        };
        self.undo_op(op);
    }

    /// Undo `op` (the window's last change, or the desktop's).
    fn undo_op(&mut self, op: Op) {
        let r: Result<(), String> = match &op {
            Op::Trashed(list) => list.iter().try_for_each(|(_, at)| {
                self.trash_holding(at).ok_or_else(|| String::from("no trash"))?.restore(fsops::base(at)).map(|_| ())
            }),
            Op::Renamed(from, to) => fsops::move_to(to, from),
            Op::Moved(list) => list.iter().try_for_each(|(from, to)| fsops::move_to(to, from)),
            Op::Copied(list) => list.iter().try_for_each(|p| self.put_in_trash(p).map(|_| ())),
            Op::MadeFolder(p) => slate_rt::fs::rmdir(p.as_bytes()).map_err(|e| alloc::format!("{e}")),
        };
        self.status = match r {
            Ok(()) => String::from("Undone."),
            Err(e) => alloc::format!("Couldn't undo: {e}"),
        };
        crate::trace!("files: undid {op:?}");
        self.load();
    }

    fn new_folder(&mut self) {
        let Some(dir) = self.folder().map(String::from) else { return };
        let name = fsops::free_name(&dir, "New folder", "new");
        let path = fsops::join(&dir, &name);
        if let Err(e) = slate_rt::fs::mkdir(path.as_bytes(), 0o755) {
            self.status = alloc::format!("Couldn't make a folder: {e}");
            return;
        }
        self.undo.push(Op::MadeFolder(path.clone()));
        self.load();
        if let Some(i) = self.items.iter().position(|it| it.path == path) {
            self.cursor = i;
            self.select_only(i);
            self.start_rename();
        }
    }

    fn start_rename(&mut self) {
        if self.folder().is_none() {
            return;
        }
        let Some(it) = self.items.get(self.cursor) else { return };
        let mut e = LineEdit::new(&it.entry.name).with_max(255);
        // The name without its extension, chosen.
        let stem = it
            .entry
            .name
            .rsplit_once('.')
            .filter(|(s, _)| !s.is_empty())
            .map_or(it.entry.name.chars().count(), |(s, _)| s.chars().count());
        e.place(0, false);
        e.place(stem, true);
        self.rename = Some(e);
    }

    fn finish_rename(&mut self) {
        let Some(e) = self.rename.take() else { return };
        let Some(it) = self.items.get(self.cursor) else { return };
        let name = e.text();
        let name = name.trim();
        if name.is_empty() || name == it.entry.name {
            return;
        }
        if name.contains('/') || name == "." || name == ".." {
            self.status = String::from("A name can't hold a / or be . or ..");
            return;
        }
        let to = fsops::join(&fsops::parent(&it.path), name);
        match fsops::move_to(&it.path, &to) {
            Ok(()) => {
                crate::trace!("files: renamed {} to {name}", it.entry.name);
                self.undo.push(Op::Renamed(it.path.clone(), to.clone()));
                self.load();
                if let Some(i) = self.items.iter().position(|x| x.path == to) {
                    self.cursor = i;
                    self.select_only(i);
                }
            }
            Err(e) => self.status = alloc::format!("Couldn't rename: {e}"),
        }
    }

    pub fn act(&mut self, a: Action) -> Effect {
        self.menu = None;
        let paths = {
            let c = self.chosen();
            let c = if c.is_empty() && self.cursor < self.items.len() { alloc::vec![self.cursor] } else { c };
            c.iter().map(|&i| self.items[i].path.clone()).collect::<Vec<_>>()
        };
        match a {
            Action::Open => return self.open(),
            Action::Copy | Action::Cut if !paths.is_empty() && self.place != Place::Trash => {
                self.status = alloc::format!(
                    "{} {}: paste where it should go.",
                    if a == Action::Cut { "Cut" } else { "Copied" },
                    count(paths.len(), "item")
                );
                let text = paths.join("\n");
                self.clip = Some((paths, a == Action::Cut));
                return Effect::Copy(text);
            }
            Action::Paste => self.paste(),
            Action::Rename => self.start_rename(),
            Action::Trash if self.place != Place::Trash => self.trash_chosen(),
            Action::NewFolder => self.new_folder(),
            Action::Compress if !paths.is_empty() => match fsops::start("/bin/archive-manager", &paths) {
                Ok(()) => self.status = String::from("Making an archive…"),
                Err(e) => self.status = e,
            },
            Action::Restore => {
                let mut n = 0;
                for p in &paths {
                    let name = fsops::base(p);
                    let Some(t) = self.trash_holding(p) else { continue };
                    match t.restore(name) {
                        Ok(to) => {
                            crate::trace!("files: restored {to}");
                            n += 1;
                        }
                        Err(e) => self.status = alloc::format!("Couldn't restore {name}: {e}"),
                    }
                }
                if n > 0 {
                    self.status = alloc::format!("Put back {}.", count(n, "item"));
                }
                self.load();
            }
            Action::DeleteForGood => {
                if !self.confirm_delete {
                    self.confirm_delete = true;
                    self.status = String::from("Delete for good? Press Delete again; this can't be undone.");
                    return Effect::Redraw;
                }
                self.confirm_delete = false;
                for p in &paths {
                    let Some(t) = self.trash_holding(p) else { continue };
                    if let Err(e) = t.delete(fsops::base(p)) {
                        self.status = alloc::format!("Couldn't delete: {e}");
                    }
                }
                crate::trace!("files: deleted {} for good", paths.len());
                self.load();
            }
            Action::EmptyTrash => {
                if !self.confirm_delete {
                    self.confirm_delete = true;
                    self.status = String::from("Empty the trash? Choose it again; this can't be undone.");
                    return Effect::Redraw;
                }
                self.confirm_delete = false;
                for t in self.trashes() {
                    for x in t.list() {
                        let _ = t.delete(&x.name);
                    }
                }
                self.status = String::from("The trash is empty.");
                self.load();
            }
            Action::ToggleHidden => {
                self.hidden = !self.hidden;
                self.load();
            }
            Action::Properties if !paths.is_empty() => self.props = Some(Props::of(&paths, &self.home)),
            Action::OpenWith if !paths.is_empty() => {
                let first = self.items.iter().find(|i| i.path == paths[0]).map(|i| i.entry.name.clone());
                let default = first.map(|n| fsops::opener(&n, &fsops::head(&paths[0])).program());
                let mut items: Vec<(&'static str, Action)> = Vec::new();
                for (k, (name, prog)) in OPEN_WITH.iter().enumerate() {
                    let entry = (*name, Action::OpenWithApp(k as u8));
                    if default == Some(Some(*prog)) { items.insert(0, entry) } else { items.push(entry) }
                }
                let (x, y) = self.last_menu.unwrap_or((40.0, 40.0));
                self.menu = Some(Menu { x, y, items, selected: 0, hits: Vec::new() });
            }
            Action::OpenWithApp(k) => {
                let Some((name, prog)) = OPEN_WITH.get(usize::from(k)) else { return Effect::None };
                let files: Vec<String> = paths.into_iter().filter(|p| !is_folder_path(p)).collect();
                if files.is_empty() {
                    return Effect::None;
                }
                match fsops::start(prog, &files) {
                    Ok(()) => {
                        crate::trace!("files: opened {} with {prog}", files.join(" "));
                        self.status = alloc::format!("Opened in {name}.");
                    }
                    Err(e) => self.status = e,
                }
            }
            Action::Bookmark => self.toggle_bookmark(),
            Action::Unmount => {
                if let Some(dev) = self.menu_disk.take() {
                    let dev = dev.trim_start_matches("/dev/").to_string();
                    // Not from inside it.
                    if let Some(at) = self.disks.iter().find(|d| d.device.ends_with(&dev)).map(|d| d.at.clone())
                        && self.folder().is_some_and(|f| f == at || f.starts_with(&alloc::format!("{at}/")))
                    {
                        self.go(Place::Folder(self.home.clone()));
                    }
                    self.ask_disk(&dev, false);
                }
            }
            Action::SetWallpaper => {
                let Some(pic) = paths.first() else { return Effect::None };
                let r = slate_strata::faces::set_wallpaper(pic).and_then(|()| {
                    let mut s = slate_strata::settings::Settings::load();
                    s.picture = true;
                    s.save()
                });
                match r {
                    Ok(()) => {
                        crate::trace!("files: the wallpaper is {pic}");
                        self.status = alloc::format!("{} is the wallpaper now.", fsops::base(pic));
                    }
                    Err(e) => self.status = alloc::format!("Couldn't make it the wallpaper: {e}"),
                }
            }
            Action::Unbookmark => {
                if let Some(b) = self.menu_bookmark.take() {
                    self.bookmarks.retain(|x| *x != b);
                    self.save_bookmarks();
                    self.status = alloc::format!("Removed the bookmark of {}.", self.pretty(&b));
                }
            }
            _ => return Effect::None,
        }
        Effect::Redraw
    }

    /// Bookmark the folder shown, or remove its bookmark.
    fn toggle_bookmark(&mut self) {
        let Some(dir) = self.folder().map(String::from) else { return };
        if let Some(i) = self.bookmarks.iter().position(|b| *b == dir) {
            self.bookmarks.remove(i);
            self.status = alloc::format!("Removed the bookmark of {}.", self.pretty(&dir));
        } else {
            self.bookmarks.push(dir.clone());
            self.status = alloc::format!("Bookmarked {}.", self.pretty(&dir));
            crate::trace!("files: bookmarked {}", self.pretty(&dir));
        }
        self.save_bookmarks();
    }

    fn save_bookmarks(&self) {
        if self.live {
            let mut text = self.bookmarks.join("\n");
            text.push('\n');
            if let Err(e) = kit::save_config(BOOKMARKS, &text) {
                slate_rt::eprintln!("files: the bookmarks: {e}");
            }
        }
    }

    /// The bookmarks saved, those that are still folders.
    pub fn load_bookmarks() -> Vec<String> {
        kit::load_config(BOOKMARKS)
            .map(|t| t.lines().map(|l| l.trim().to_string()).filter(|l| l.starts_with('/')).collect())
            .unwrap_or_default()
    }

    fn menu_at(&mut self, x: f32, y: f32, on_item: bool) {
        self.last_menu = Some((x, y));
        let marked = self.folder().is_some_and(|d| self.bookmarks.iter().any(|b| b == d));
        let items: Vec<(&'static str, Action)> = match (&self.place, on_item) {
            (Place::Trash, true) => {
                alloc::vec![("Restore", Action::Restore), ("Delete for good", Action::DeleteForGood)]
            }
            (Place::Trash, false) => alloc::vec![("Empty the trash", Action::EmptyTrash)],
            (_, true) => {
                let mut v = alloc::vec![
                    ("Open", Action::Open),
                    ("Open with…", Action::OpenWith),
                    ("Cut", Action::Cut),
                    ("Copy", Action::Copy),
                    ("Rename", Action::Rename),
                    ("Compress", Action::Compress),
                    ("Move to the trash", Action::Trash),
                    ("Properties", Action::Properties),
                ];
                let picture = self
                    .items
                    .get(self.cursor)
                    .is_some_and(|i| i.entry.kind == Kind::File && crate::viewer::is_image(&i.entry.name));
                if picture && self.chosen().len() <= 1 {
                    v.insert(2, ("Set as wallpaper", Action::SetWallpaper));
                }
                v
            }
            (Place::Folder(_), false) => alloc::vec![
                ("New folder", Action::NewFolder),
                ("Paste", Action::Paste),
                (if self.hidden { "Hide hidden files" } else { "Show hidden files" }, Action::ToggleHidden),
                (if marked { "Remove the bookmark" } else { "Bookmark this folder" }, Action::Bookmark),
            ],
            (_, false) => {
                alloc::vec![
                    (if self.hidden { "Hide hidden files" } else { "Show hidden files" }, Action::ToggleHidden,)
                ]
            }
        };
        self.menu = Some(Menu { x, y, items, selected: 0, hits: Vec::new() });
    }

    fn title_path(&self) -> String {
        match &self.place {
            Place::Folder(p) => self.pretty(p),
            Place::Trash => String::from("trash"),
            Place::Device(d) => d.clone(),
            Place::Search { root, query, .. } => alloc::format!("{} ({query})", self.pretty(root)),
        }
    }

    fn field_key(f: &mut LineEdit, code: u16, ch: Option<char>, mods: u8) -> bool {
        let (shift, ctrl) = (mods & SHIFT != 0, mods & CTRL != 0);
        let edit = match (code, ch.map(|c| c.to_ascii_lowercase())) {
            (KEY_LEFT, _) => Some(EditKey::Left),
            (KEY_RIGHT, _) => Some(EditKey::Right),
            (KEY_HOME, _) => Some(EditKey::Home),
            (KEY_END, _) => Some(EditKey::End),
            (KEY_BACKSPACE, _) => Some(EditKey::Backspace),
            (KEY_DELETE, _) => Some(EditKey::Delete),
            (_, Some('a')) if ctrl => Some(EditKey::SelectAll),
            _ => None,
        };
        let shortcut = mods & (CTRL | ALT | LOGO) != 0;
        match (edit, ch.filter(|c| !shortcut && !c.is_control())) {
            (Some(k), _) => f.key(k, shift, ctrl).moved,
            (None, Some(c)) => f.insert(c.encode_utf8(&mut [0u8; 4])),
            _ => false,
        }
    }

    /// Where a drag at (x, y) would drop: a folder in view that isn't
    /// being dragged, or a place in the sidebar.
    fn drop_target(&self, x: f32, y: f32) -> Option<Place> {
        let dragged = self.dragging.as_ref().map(|d| d.paths.as_slice()).unwrap_or_default();
        if let Some((_, place)) = self.side.iter().find(|(r, _)| r.contains(x, y)) {
            return match place {
                Place::Folder(p) if !dragged.contains(p) => Some(place.clone()),
                Place::Trash => Some(Place::Trash),
                _ => None,
            };
        }
        let k = self.rows.iter().position(|r| r.contains(x, y))?;
        let it = self.items.get(self.first + k)?;
        (it.entry.is_folder() && !dragged.contains(&it.path) && self.folder().is_some())
            .then(|| Place::Folder(it.path.clone()))
    }

    /// Thumbnails still wanted for pictures in view.
    fn wanted_thumbs(&self) -> Vec<(String, i64)> {
        if self.view != View::Grid {
            return Vec::new();
        }
        self.items
            .iter()
            .skip(self.first)
            .take(self.shown + self.per_row)
            .filter(|i| {
                i.entry.kind == Kind::File
                    && crate::viewer::is_image(&i.entry.name)
                    && (i.entry.size as i64) <= THUMB_MAX
            })
            .map(|i| (i.path.clone(), i.entry.mtime))
            .filter(|k| !self.thumbs.contains_key(k))
            .collect()
    }
}

/// An entry for a path found elsewhere (search, the trash).
fn item_entry(path: &str, name: &str) -> Entry {
    let st = slate_rt::fs::lstat(path.as_bytes()).ok();
    let mode = st.as_ref().map_or(0, |s| s.mode);
    let kind = match mode & slate_rt::fs::S_IFMT {
        slate_rt::fs::S_IFDIR => Kind::Folder,
        slate_rt::fs::S_IFREG => Kind::File,
        slate_rt::fs::S_IFLNK => Kind::Link,
        _ => Kind::Other,
    };
    Entry {
        name: String::from(name),
        kind,
        size: st.as_ref().map_or(0, |s| s.size.max(0) as u64),
        mtime: st.as_ref().map_or(0, |s| s.mtime),
        mode,
        target: None,
        to_folder: false,
    }
}

/// Paths under `root` whose names hold `query` (case ignored), or with
/// `contents` whose text does (files up to [`SEARCH_FILE_MAX`] that look
/// like text); folders walked breadth first, links not followed.
pub fn search(root: &str, query: &str, hidden: bool, contents: bool) -> Vec<String> {
    let q = query.to_lowercase();
    let mut out = Vec::new();
    let mut queue = alloc::collections::VecDeque::from([String::from(root)]);
    let mut seen = 0usize;
    let mut read = 0u64;
    while let Some(dir) = queue.pop_front() {
        let Ok(es) = fsops::list(&dir) else { continue };
        let mut es = es;
        fsops::sort(&mut es, Sort::Name, false);
        for e in es {
            seen += 1;
            if seen > 100_000 || out.len() >= SEARCH_MAX {
                return out;
            }
            if !hidden && e.hidden() {
                continue;
            }
            let p = fsops::join(&dir, &e.name);
            let found = e.name.to_lowercase().contains(&q)
                || (contents
                    && e.kind == Kind::File
                    && (e.size as i64) <= SEARCH_FILE_MAX
                    && read < SEARCH_READ_MAX
                    && text_holds(&p, &q, &mut read));
            if found {
                out.push(p.clone());
            }
            if e.kind == Kind::Folder {
                queue.push_back(p);
            }
        }
    }
    out
}

/// Whether the file at `path` is text holding `q` (lower case), counting
/// what is read.
fn text_holds(path: &str, q: &str, read: &mut u64) -> bool {
    let Ok(data) = slate_rt::fs::read_file(path.as_bytes()) else { return false };
    *read += data.len() as u64;
    if data[..data.len().min(4096)].contains(&0) {
        return false;
    }
    String::from(slate_rt::lossy(&data)).to_lowercase().contains(q)
}

/// Whether `path` is a folder (a link to one counts).
fn is_folder_path(path: &str) -> bool {
    slate_rt::fs::stat(path.as_bytes()).is_ok_and(|s| s.mode & slate_rt::fs::S_IFMT == slate_rt::fs::S_IFDIR)
}

/// Copy or move each of `list` in turn, telling `say` the bytes done so
/// far, the item it is on, and whether that item's copy is finished (a
/// move then removes the original): how many were done, and why the rest
/// weren't.
pub fn transfer_work(
    list: &[(String, String)],
    cut: bool,
    say: &mut dyn FnMut(u64, usize, bool),
) -> (usize, Option<String>) {
    let mut done = 0u64;
    for (k, (from, to)) in list.iter().enumerate() {
        say(done, k, false);
        let mut moved = |n: u64| {
            done += n;
            say(done, k, false);
        };
        let r = if cut {
            // A rename, or a copy and then the original removed.
            if fsops::same_disk(from, &fsops::parent(to)) {
                fsops::move_to(from, to)
            } else {
                match fsops::copy_with(from, to, &mut moved) {
                    Ok(()) => {
                        say(done, k, true);
                        fsops::remove(from)
                    }
                    Err(e) => {
                        let _ = fsops::remove(to);
                        Err(e)
                    }
                }
            }
        } else {
            fsops::copy_with(from, to, &mut moved)
        };
        if let Err(e) = r {
            return (k, Some(e));
        }
    }
    (list.len(), None)
}

impl Props {
    /// The properties of `paths` (one, or several together).
    pub fn of(paths: &[String], home: &str) -> Props {
        let size = paths.iter().fold((0, 0, false), |acc, p| {
            let s = fsops::size_of(p, 100_000);
            (acc.0 + s.0, acc.1 + s.1, acc.2 || s.2)
        });
        let one = paths.len() == 1;
        let st = slate_rt::fs::lstat(paths[0].as_bytes()).ok();
        let mode = st.as_ref().map_or(0, |s| s.mode);
        let kind = match (one, mode & slate_rt::fs::S_IFMT) {
            (false, _) => String::from("several"),
            (_, slate_rt::fs::S_IFDIR) => String::from("folder"),
            (_, slate_rt::fs::S_IFLNK) => alloc::format!(
                "link to {}",
                slate_rt::fs::readlink(paths[0].as_bytes())
                    .map(|t| String::from(slate_rt::lossy(&t)))
                    .unwrap_or_default()
            ),
            (_, slate_rt::fs::S_IFREG) => {
                let o = fsops::opener(fsops::base(&paths[0]), &fsops::head(&paths[0]));
                String::from(o.kind_name())
            }
            _ => String::from("device, pipe or socket"),
        };
        let parent = fsops::parent(&paths[0]);
        let location = match parent.strip_prefix(home) {
            Some(r) if r.is_empty() || r.starts_with('/') => alloc::format!("~{r}"),
            _ => parent,
        };
        let me = slate_rt::process::getuid();
        let owner = st.as_ref().map_or_else(String::new, |s| {
            let user = id_name(b"/etc/passwd", s.uid);
            let group = id_name(b"/etc/group", s.gid);
            alloc::format!("{user}, group {group}")
        });
        let is_link = mode & slate_rt::fs::S_IFMT == slate_rt::fs::S_IFLNK;
        Props {
            paths: paths.to_vec(),
            name: if one { fsops::base(&paths[0]).to_string() } else { count(paths.len(), "item") },
            kind,
            size,
            location,
            modified: st.as_ref().map_or(0, |s| s.mtime),
            owner: if one { owner } else { String::new() },
            mode: (one && !is_link && st.is_some()).then_some(mode & 0o777),
            mine: st.as_ref().is_some_and(|s| s.uid == me || me == 0),
            focus: 0,
            hits: Vec::new(),
        }
    }

    /// Turn permission box `k` (owner, group, others; read, write, run)
    /// on or off: the file's mode changes at once.
    pub fn toggle(&mut self, k: usize) -> Result<(), String> {
        let Some(mode) = self.mode else { return Ok(()) };
        if !self.mine {
            return Err(String::from("Only its owner can change its permissions."));
        }
        let bit = 0o400 >> k;
        let new = mode ^ bit;
        slate_rt::fs::chmod(self.paths[0].as_bytes(), new).map_err(|e| alloc::format!("Couldn't change it: {e}"))?;
        self.mode = Some(new);
        crate::trace!("files: {} is now {new:03o}", fsops::base(&self.paths[0]));
        Ok(())
    }
}

/// The name of user or group `id` in `file` (/etc/passwd, /etc/group),
/// else the number.
fn id_name(file: &[u8], id: u32) -> String {
    let text = slate_rt::fs::read_file(file).map(|t| String::from(slate_rt::lossy(&t))).unwrap_or_default();
    let want = alloc::format!("{id}");
    text.lines()
        .find(|l| l.split(':').nth(2) == Some(want.as_str()))
        .and_then(|l| l.split(':').next())
        .map_or(want.clone(), String::from)
}

fn count(n: usize, what: &str) -> String {
    if n == 1 { alloc::format!("1 {what}") } else { alloc::format!("{n} {what}s") }
}

/// "today 14:05", "Mon 19 Oct", "19 Oct 2024".
fn when(t: i64, now: i64) -> String {
    let tm = slate_rt::tz::localtime(t);
    let today = slate_rt::tz::localtime(now);
    let month = slate_rt::time::MONTHS[(tm.month as usize).saturating_sub(1) % 12];
    if (tm.year, tm.yearday) == (today.year, today.yearday) {
        alloc::format!("today {:02}:{:02}", tm.hour, tm.min)
    } else if tm.year == today.year {
        alloc::format!("{} {} {month}", slate_rt::time::DAYS[tm.weekday as usize % 7], tm.day)
    } else {
        alloc::format!("{} {month} {}", tm.day, tm.year)
    }
}

fn icon_for(e: &Entry) -> Icon {
    if e.is_folder() {
        return Icon::Folder;
    }
    if crate::viewer::is_image(&e.name) {
        return Icon::Picture;
    }
    if crate::archive::is_archive(&e.name) {
        return Icon::Archive;
    }
    if e.mode & 0o111 != 0 && e.kind == Kind::File {
        return Icon::Terminal;
    }
    Icon::Document
}

/// An entry's large icon (the grid without a thumbnail): slate-ui's file
/// icons, as on the desktop.
fn file_icon(e: &Entry) -> slate_ui::fileicon::Kind {
    use slate_ui::fileicon::{Kind as K, kind_of};
    if e.is_folder() {
        return K::Folder;
    }
    if crate::viewer::is_image(&e.name) {
        return K::Picture;
    }
    if crate::archive::is_archive(&e.name) {
        return K::Archive;
    }
    kind_of(&e.name, e.mode & 0o111 != 0 && e.kind == Kind::File)
}

/// The properties dialog over the window: facts, then the permissions as
/// nine boxes (owner, group, others; read, write, run).
fn draw_props(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area, pr: &mut Props) {
    p.fill(a, 0.0, pal.dim_dialog);
    let w = 420.0;
    let rows = [
        ("kind", pr.kind.clone()),
        (
            "size",
            if pr.kind == "folder" || pr.paths.len() > 1 {
                let more = if pr.size.2 { "+" } else { "" };
                alloc::format!(
                    "{}{more} · {} inside",
                    crate::help::size(pr.size.0),
                    count(pr.size.1.saturating_sub(usize::from(pr.paths.len() == 1)), "item")
                )
            } else {
                alloc::format!("{} ({} bytes)", crate::help::size(pr.size.0), pr.size.0)
            },
        ),
        ("in", pr.location.clone()),
        ("modified", when(pr.modified, now_s())),
        ("owner", pr.owner.clone()),
    ];
    let rows: Vec<(&str, String)> = rows.into_iter().filter(|(_, v)| !v.is_empty()).collect();
    let perm_h = if pr.mode.is_some() { 30.0 + 3.0 * 32.0 + 8.0 } else { 0.0 };
    let h = 24.0 + 26.0 + 16.0 + rows.len() as f32 * 26.0 + perm_h + 46.0;
    let d = Area::new(a.x + (a.w - w) / 2.0, a.y + ((a.h - h) / 2.0).max(8.0), w, h);
    p.fill(d, 12.0, pal.overlay);
    p.border(d, 12.0, 1.0, pal.border);
    let x = d.x + 24.0;
    let mut y = d.y + 24.0;
    let title = p.style(&f.medium, 17.0, pal.chalk);
    p.line(&title, x, y, 26.0, &kit::fit(p, &title, &pr.name, w - 48.0));
    y += 26.0 + 16.0;
    let label = p.style(&f.mono, 11.0, pal.muted);
    let value = p.style(&f.regular, 13.0, pal.text_1);
    for (l, v) in &rows {
        p.line(&label, x, y + 4.0, 18.0, l);
        p.line(&value, x + 96.0, y + 2.0, 20.0, &kit::fit(p, &value, v, w - 48.0 - 96.0));
        y += 26.0;
    }
    pr.hits.clear();
    if let Some(mode) = pr.mode {
        y += 8.0;
        let cols = ["read", "write", "run"];
        for (c, name) in cols.iter().enumerate() {
            p.line(&label, x + 96.0 + c as f32 * 88.0, y, 18.0, name);
        }
        y += 22.0;
        for (r, who) in ["owner", "group", "others"].iter().enumerate() {
            p.line(&label, x, y + 6.0, 18.0, who);
            for c in 0..3 {
                let k = r * 3 + c;
                let on = mode & (0o400 >> k) != 0;
                let b = Area::new(x + 96.0 + c as f32 * 88.0, y + 5.0, 18.0, 18.0);
                let ink = if pr.mine { pal.chalk } else { pal.muted };
                if on {
                    p.fill(b, 4.0, ink);
                    p.icon(Icon::Check, b.x + 2.0, b.y + 2.0, 14.0, pal.window);
                } else {
                    p.border(b, 4.0, 1.0, if pr.mine { pal.border_strong } else { pal.border });
                }
                if k == pr.focus && pr.mine {
                    p.border(b.grow(3.0), 6.0, 1.5, pal.chalk);
                }
                pr.hits.push(b);
            }
            y += 32.0;
        }
    }
    let hint = p.style(&f.mono, 11.0, pal.muted);
    let text = if pr.mode.is_some() && pr.mine {
        "space changes · esc closes"
    } else if pr.mode.is_some() {
        "only its owner changes these · esc closes"
    } else {
        "esc closes"
    };
    p.line(&hint, x, d.bottom() - 34.0, 18.0, text);
}

impl App for Files {
    fn draw(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area) {
        self.rows.clear();
        self.side.clear();
        self.crumbs.clear();
        self.headers.clear();
        self.nav.clear();
        // The sidebar.
        let side = Area::new(a.x, a.y, SIDEBAR_W, a.h);
        p.fill(side, 0.0, pal.header);
        p.fill(Area::new(side.x + side.w - 1.0, side.y, 1.0, side.h), 0.0, pal.divider);
        let label = p.style(&f.mono, 11.0, pal.muted);
        let item = p.style(&f.medium, 13.0, pal.text_2);
        let item_on = p.style(&f.medium, 13.0, pal.chalk);
        let mut y = a.y + 16.0;
        let mut entries: Vec<(String, Place, Icon)> =
            self.places.iter().map(|(n, path, i)| (n.clone(), Place::Folder(path.clone()), *i)).collect();
        let first_mark = entries.len();
        for b in &self.bookmarks {
            entries.push((fsops::base(b).to_string(), Place::Folder(b.clone()), Icon::Folder));
        }
        let first_disk = entries.len();
        for d in &self.disks {
            let name = if d.at == "/" { String::from("Slate") } else { fsops::base(&d.at).to_string() };
            entries.push((name, Place::Folder(d.at.clone()), Icon::Disk));
        }
        for (dev, name) in &self.unmounted {
            entries.push((name.clone(), Place::Device(dev.clone()), Icon::Disk));
        }
        entries.push((String::from("Trash"), Place::Trash, Icon::Trash));
        let target = self.dragging.as_ref().and_then(|d| d.target.clone());
        for (i, (name, place, icon)) in entries.iter().enumerate() {
            let heading = if i == 0 {
                Some("places")
            } else if i == first_mark && first_mark < first_disk {
                Some("bookmarks")
            } else if i == first_disk && i < entries.len() - 1 {
                Some("disks")
            } else if i == entries.len() - 1 {
                Some("")
            } else {
                None
            };
            match heading {
                Some("") => y += 8.0,
                Some(l) => {
                    p.line(&label, side.x + 16.0, y, 16.0, l);
                    y += 22.0;
                }
                None => {}
            }
            let r = Area::new(side.x + 8.0, y, side.w - 16.0, 30.0);
            let on = *place == self.place;
            if on {
                p.fill(r, 7.0, pal.accent_soft);
            }
            if target.as_ref() == Some(place) {
                p.border(r, 7.0, 1.5, pal.chalk);
            }
            // Not mounted yet: quieter, until clicked.
            let quiet = matches!(place, Place::Device(_));
            p.icon(
                *icon,
                r.x + 8.0,
                r.y + 7.0,
                16.0,
                if on {
                    pal.place_icon
                } else if quiet {
                    pal.decor
                } else {
                    pal.text_3
                },
            );
            let st = if on {
                item_on
            } else if quiet {
                p.style(&f.medium, 13.0, pal.muted)
            } else {
                item
            };
            p.line(&st, r.x + 32.0, r.y + 5.0, 20.0, &kit::fit(p, &st, name, r.w - 40.0));
            self.side.push((r, place.clone()));
            y += 32.0;
        }
        // The path bar: back, forward, and the folders above.
        let main = Area::new(a.x + SIDEBAR_W, a.y, a.w - SIDEBAR_W, a.h);
        let bar = Area::new(main.x, main.y, main.w, 48.0);
        let mut x = bar.x + 12.0;
        for (k, icon) in [(0u8, Icon::ChevronLeft), (1u8, Icon::ChevronRight)] {
            let b = Area::new(x, bar.y + 10.0, 28.0, 28.0);
            let enabled = if k == 0 { !self.back.is_empty() } else { !self.forward.is_empty() };
            p.icon(icon, b.x + 6.0, b.y + 6.0, 16.0, if enabled { pal.text_2 } else { pal.decor });
            self.nav.push((b, k));
            x += 30.0;
        }
        x += 6.0;
        let crumb = p.style(&f.medium, 13.0, pal.text_3);
        let crumb_last = p.style(&f.medium, 13.0, pal.chalk);
        if let Some(loc) = &self.location {
            let fa = Area::new(x, bar.y + 9.0, bar.x + bar.w - x - 12.0, 30.0);
            p.fill(fa, 6.0, pal.well);
            p.border(fa, 6.0, 1.0, pal.field_focus);
            let mut typed = p.style(&f.regular, 13.0, pal.text_1);
            typed.ligatures = false;
            let text = loc.text();
            let before: String = text.chars().take(loc.caret()).collect();
            let cx = p.measure(&typed, &before);
            p.line(&typed, fa.x + 10.0, fa.y + 5.0, 20.0, &text);
            p.fill(Area::new(fa.x + 10.0 + cx, fa.y + 5.0, 1.5, 20.0), 0.0, pal.chalk);
        } else {
            let parts: Vec<(String, String)> = match &self.place {
                Place::Folder(path) | Place::Search { root: path, .. } => {
                    let shown = self.pretty(path);
                    let mut acc = String::new();
                    let mut out = Vec::new();
                    let (start, rest) = if let Some(r) = shown.strip_prefix('~') {
                        acc = self.home.clone();
                        (Some(("Home".to_string(), self.home.clone())), r.to_string())
                    } else {
                        (Some(("/".to_string(), "/".to_string())), shown.clone())
                    };
                    out.extend(start);
                    for c in rest.split('/').filter(|c| !c.is_empty()) {
                        acc = fsops::join(if acc.is_empty() { "/" } else { &acc }, c);
                        out.push((c.to_string(), acc.clone()));
                    }
                    out
                }
                Place::Trash => alloc::vec![("Trash".into(), String::new())],
                Place::Device(d) => alloc::vec![(d.clone(), String::new())],
            };
            let n = parts.len();
            for (i, (name, path)) in parts.into_iter().enumerate() {
                let last = i + 1 == n;
                let s = if last { &crumb_last } else { &crumb };
                let w = p.measure(s, &name) + 16.0;
                let r = Area::new(x, bar.y + 10.0, w, 28.0);
                if last {
                    p.fill(r, 6.0, pal.raised);
                }
                p.line(s, x + 8.0, bar.y + 14.0, 20.0, &name);
                if !path.is_empty() {
                    self.crumbs.push((r, path));
                }
                x += w + 2.0;
                if !last {
                    p.line(&label, x, bar.y + 15.0, 18.0, "/");
                    x += 10.0;
                }
            }
            if let Place::Search { query, .. } = &self.place {
                p.line(&label, x + 8.0, bar.y + 15.0, 18.0, &alloc::format!("search: {query}"));
            }
        }
        if let Some(s) = &self.search {
            let fa = Area::new(main.x + 12.0, bar.y + 48.0, main.w - 24.0, 32.0);
            p.fill(fa, 6.0, pal.well);
            p.border(fa, 6.0, 1.0, pal.field_focus);
            p.icon(Icon::Search, fa.x + 10.0, fa.y + 8.0, 16.0, pal.muted);
            let typed = p.style(&f.regular, 13.0, pal.text_1);
            let text = s.text();
            if text.is_empty() {
                let ghost = p.style(&f.regular, 13.0, pal.muted);
                p.line(&ghost, fa.x + 34.0, fa.y + 6.0, 20.0, "Search in this folder and the ones in it");
            }
            // What is searched (Tab changes it).
            let mode = if self.search_contents { "names and text · tab" } else { "names · tab" };
            let ms = p.style(&f.mono, 11.0, pal.muted);
            let mw = p.measure(&ms, mode);
            let chip = Area::new(fa.x + fa.w - mw - 22.0, fa.y + 5.0, mw + 14.0, 22.0);
            p.fill(chip, 5.0, pal.raised);
            p.line(&ms, chip.x + 7.0, chip.y + 2.0, 18.0, mode);
            let before: String = text.chars().take(s.caret()).collect();
            let cx = p.measure(&typed, &before);
            p.line(&typed, fa.x + 34.0, fa.y + 6.0, 20.0, &text);
            p.fill(Area::new(fa.x + 34.0 + cx, fa.y + 6.0, 1.5, 20.0), 0.0, pal.chalk);
        }
        let top = bar.y + bar.h + if self.search.is_some() { 40.0 } else { 0.0 };
        let status_h = 28.0;
        let body = Area::new(main.x, top, main.w, main.y + main.h - status_h - top);
        let name_s = p.style(&f.regular, 13.5, pal.text_1);
        let meta = p.style(&f.mono, 11.5, pal.text_4);
        let note = p.style(&f.mono, 11.0, pal.muted);
        let quiet = p.style(&f.regular, 14.0, pal.muted);
        if self.items.is_empty() {
            let msg = match (&self.place, self.filter.is_empty()) {
                (Place::Trash, _) => "The trash is empty.",
                (Place::Search { contents: true, .. }, _) => "Nothing here has that in its name or text.",
                (Place::Search { .. }, _) => "Nothing here has that in its name.",
                (_, false) => "Nothing here matches.",
                _ => "This folder is empty.",
            };
            let w = p.measure(&quiet, msg);
            p.line(&quiet, body.x + (body.w - w) / 2.0, body.y + body.h / 2.0 - 10.0, 20.0, msg);
        }
        match self.view {
            View::List => {
                let header = Area::new(body.x, body.y, body.w, 26.0);
                p.fill(header, 0.0, pal.header);
                let cols = [
                    ("name", Sort::Name, body.x + 44.0),
                    ("size", Sort::Size, body.x + body.w - 260.0),
                    ("modified", Sort::Modified, body.x + body.w - 150.0),
                ];
                for (l, s, cx) in cols {
                    let text = if s == self.sort {
                        alloc::format!("{l} {}", if self.reverse { "^" } else { "v" })
                    } else {
                        l.to_string()
                    };
                    p.line(&label, cx, header.y + 5.0, 16.0, &text);
                    self.headers.push((Area::new(cx - 6.0, header.y, 100.0, header.h), s));
                }
                let list_top = header.y + header.h + 4.0;
                self.shown = ((body.y + body.h - list_top) / ROW_H).max(1.0) as usize;
                self.per_row = 1;
                if self.cursor < self.first {
                    self.first = self.cursor;
                } else if self.cursor >= self.first + self.shown {
                    self.first = self.cursor + 1 - self.shown;
                }
                let clip = p.clip(body);
                let now = now_s();
                for (i, it) in self.items.iter().enumerate().skip(self.first).take(self.shown) {
                    let y = list_top + (i - self.first) as f32 * ROW_H;
                    let r = Area::new(body.x + 8.0, y, body.w - 16.0, ROW_H - 2.0);
                    let sel = self.selected.get(i) == Some(&true);
                    if sel {
                        p.fill(r, 6.0, pal.list_selected);
                    } else if i == self.cursor {
                        p.border(r, 6.0, 1.0, pal.border);
                    }
                    if target.as_ref().is_some_and(|t| *t == Place::Folder(it.path.clone())) {
                        p.border(r, 6.0, 1.5, pal.chalk);
                    }
                    let icon = icon_for(&it.entry);
                    let ink = match (sel, icon) {
                        (true, _) => pal.window,
                        (false, Icon::Folder) => pal.folder,
                        _ => pal.text_3,
                    };
                    p.icon(icon, r.x + 10.0, r.y + 7.0, 16.0, ink);
                    let ns = if sel { p.style(&f.regular, 13.5, pal.window) } else { name_s };
                    let ms = if sel { p.style(&f.mono, 11.5, pal.window) } else { meta };
                    let name_w = body.w - 340.0;
                    if self.rename.is_some() && i == self.cursor {
                        if let Some(e) = &self.rename {
                            let fa = Area::new(r.x + 34.0, r.y + 2.0, name_w, ROW_H - 6.0);
                            p.fill(fa, 5.0, pal.well);
                            p.border(fa, 5.0, 1.0, pal.field_focus);
                            let mut typed = p.style(&f.regular, 13.5, pal.text_1);
                            typed.ligatures = false;
                            let text = e.text();
                            if let Some((s0, s1)) = e.selection() {
                                let a0: String = text.chars().take(s0).collect();
                                let a1: String = text.chars().take(s1).collect();
                                let (x0, x1) = (p.measure(&typed, &a0), p.measure(&typed, &a1));
                                p.fill(Area::new(fa.x + 8.0 + x0, fa.y + 3.0, x1 - x0, fa.h - 6.0), 0.0, pal.raised);
                            }
                            let before: String = text.chars().take(e.caret()).collect();
                            let cx = p.measure(&typed, &before);
                            p.line(&typed, fa.x + 8.0, fa.y + 3.0, 20.0, &text);
                            p.fill(Area::new(fa.x + 8.0 + cx, fa.y + 4.0, 1.5, 18.0), 0.0, pal.chalk);
                        }
                    } else {
                        let shown = kit::fit(p, &ns, &it.entry.name, name_w);
                        let nx = r.x + 34.0;
                        let end = p.line(&ns, nx, r.y + 5.0, 20.0, &shown);
                        if let Some(n) = &it.note {
                            let ns2 = if sel { ms } else { note };
                            let room = name_w - end - 12.0;
                            if room > 40.0 {
                                p.line(&ns2, nx + end + 10.0, r.y + 6.0, 18.0, &kit::fit(p, &ns2, n, room));
                            }
                        }
                    }
                    let size =
                        if it.entry.is_folder() { String::from("—") } else { crate::help::size(it.entry.size) };
                    p.line(&ms, body.x + body.w - 260.0, r.y + 6.0, 18.0, &size);
                    p.line(&ms, body.x + body.w - 150.0, r.y + 6.0, 18.0, &when(it.entry.mtime, now));
                    self.rows.push(r);
                }
                p.unclip(clip);
            }
            View::Grid => {
                let gx = body.x + 12.0;
                self.per_row = ((body.w - 24.0) / TILE_W).max(1.0) as usize;
                let rows_shown = ((body.h - 8.0) / TILE_H).max(1.0) as usize;
                self.shown = rows_shown * self.per_row;
                let row_of = |i: usize, per: usize| i / per;
                let first_row = self.first / self.per_row;
                let cur_row = row_of(self.cursor, self.per_row);
                let first_row = if cur_row < first_row {
                    cur_row
                } else if cur_row >= first_row + rows_shown {
                    cur_row + 1 - rows_shown
                } else {
                    first_row
                };
                self.first = first_row * self.per_row;
                let clip = p.clip(body);
                for (i, it) in self.items.iter().enumerate().skip(self.first).take(self.shown) {
                    let k = i - self.first;
                    let tx = gx + (k % self.per_row) as f32 * TILE_W;
                    let ty = body.y + 8.0 + (k / self.per_row) as f32 * TILE_H;
                    let r = Area::new(tx + 4.0, ty, TILE_W - 8.0, TILE_H - 6.0);
                    let sel = self.selected.get(i) == Some(&true);
                    let dropping = target.as_ref().is_some_and(|t| *t == Place::Folder(it.path.clone()));
                    if sel {
                        p.fill(r, 8.0, pal.raised);
                        p.border(r, 8.0, 1.5, pal.chalk);
                    } else if dropping {
                        p.border(r, 8.0, 1.5, pal.chalk);
                    } else if i == self.cursor {
                        p.border(r, 8.0, 1.0, pal.border);
                    }
                    let thumb = self.thumbs.get(&(it.path.clone(), it.entry.mtime)).and_then(|t| t.as_ref());
                    match thumb {
                        Some(img) => {
                            let dr = p.device(&Area::new(
                                r.x + (r.w - img.width as f32 / p.scale) / 2.0,
                                r.y + 8.0 + (72.0 - img.height as f32 / p.scale) / 2.0,
                                0.0,
                                0.0,
                            ));
                            p.canvas.draw_image(dr.x, dr.y, img.width as i32, img.height as i32, &img.pixels);
                        }
                        None => {
                            let kind = file_icon(&it.entry);
                            let badge = (kind != slate_ui::fileicon::Kind::Folder)
                                .then(|| slate_ui::fileicon::badge_of(&it.entry.name))
                                .flatten();
                            let b = badge.as_deref().map(|t| (&f.mono, t));
                            slate_ui::fileicon::draw(p, pal, kind, r.x + (r.w - 60.0) / 2.0, r.y + 14.0, 60.0, b);
                        }
                    }
                    let ns = p.style(&f.regular, 12.5, if sel { pal.chalk } else { pal.text_1 });
                    let shown = kit::fit(p, &ns, &it.entry.name, r.w - 8.0);
                    let w = p.measure(&ns, &shown);
                    if self.rename.is_some() && i == self.cursor {
                        if let Some(e) = &self.rename {
                            let fa = Area::new(r.x - 4.0, r.y + 86.0, r.w + 8.0, 26.0);
                            p.fill(fa, 5.0, pal.well);
                            p.border(fa, 5.0, 1.0, pal.field_focus);
                            let mut typed = p.style(&f.regular, 12.5, pal.text_1);
                            typed.ligatures = false;
                            p.line(&typed, fa.x + 6.0, fa.y + 3.0, 20.0, &kit::fit(p, &typed, &e.text(), fa.w - 10.0));
                        }
                    } else {
                        p.line(&ns, r.x + (r.w - w) / 2.0, r.y + 88.0, 20.0, &shown);
                    }
                    self.rows.push(r);
                }
                p.unclip(clip);
            }
        }
        // The status line: counts, the size chosen, free space, messages.
        let sy = main.y + main.h - status_h;
        p.fill(Area::new(main.x, sy, main.w, status_h), 0.0, pal.header);
        let st = p.style(&f.mono, 11.0, pal.muted);
        let chosen = self.chosen();
        let mut facts = count(self.items.len(), "item");
        if !chosen.is_empty() {
            let size: u64 =
                chosen.iter().filter(|&&i| !self.items[i].entry.is_folder()).map(|&i| self.items[i].entry.size).sum();
            facts.push_str(&alloc::format!(", {} chosen ({})", chosen.len(), crate::help::size(size)));
        }
        if let Some(dir) = self.folder().filter(|_| self.show_free)
            && let Ok(sf) = slate_rt::fs::statfs(dir.as_bytes())
        {
            let free = sf.available * sf.block_size.max(0) as u64;
            facts.push_str(&alloc::format!(" · {} free", crate::help::size(free)));
        }
        let fw = p.measure(&st, &facts);
        p.line(&st, main.x + main.w - 14.0 - fw, sy + 5.0, 18.0, &facts);
        // A copy under way: how far, and a thin bar along the line's top.
        if let Some((_, frac)) = self.transfer_text() {
            p.fill(Area::new(main.x, sy, main.w * frac, 2.0), 0.0, pal.chalk);
        }
        let msg = match self.transfer_text() {
            Some((t, _)) => t,
            None if !self.filter.is_empty() => alloc::format!("filter: {}", self.filter),
            None => self.status.clone(),
        };
        if !msg.is_empty() {
            let m = p.style(&f.regular, 12.0, pal.text_3);
            p.line(&m, main.x + 14.0, sy + 5.0, 18.0, &kit::fit(p, &m, &msg, main.w - fw - 40.0));
        }
        // The menu, over everything.
        if let Some(menu) = &mut self.menu {
            let mw = 200.0;
            let mh = menu.items.len() as f32 * 30.0 + 10.0;
            let mx = menu.x.min(a.x + a.w - mw - 4.0);
            let my = menu.y.min(a.y + a.h - mh - 4.0);
            let r = Area::new(mx, my, mw, mh);
            p.fill(r, 9.0, pal.overlay);
            p.border(r, 9.0, 1.0, pal.border);
            menu.hits.clear();
            let s = p.style(&f.regular, 13.0, pal.text_1);
            for (k, (l, _)) in menu.items.iter().enumerate() {
                let row = Area::new(mx + 5.0, my + 5.0 + k as f32 * 30.0, mw - 10.0, 28.0);
                if k == menu.selected {
                    p.fill(row, 6.0, pal.raised);
                }
                p.line(&s, row.x + 10.0, row.y + 4.0, 20.0, l);
                menu.hits.push(row);
            }
        }
        // Where the first row is, when it moves (the apps scenario drags
        // from it).
        if kit::tracing() && self.rows.first() != self.traced_row.as_ref() {
            self.traced_row = self.rows.first().copied();
            if let Some(r) = self.traced_row {
                crate::trace!("files: first row at {} {} {} {}", r.x, r.y, r.w, r.h);
            }
        }
        // What is being dragged, beside the pointer.
        if let Some(d) = &self.dragging {
            let s = p.style(&f.medium, 12.5, pal.text_1);
            let verb = if d.copy { "Copy" } else { "Move" };
            let text = match &d.target {
                Some(Place::Trash) => alloc::format!("Move {} to the trash", count(d.paths.len(), "item")),
                Some(Place::Folder(t)) => {
                    alloc::format!("{verb} {} to {}", count(d.paths.len(), "item"), fsops::base(t))
                }
                _ => count(d.paths.len(), "item"),
            };
            let w = p.measure(&s, &text) + 20.0;
            let chip = Area::new((d.x + 14.0).min(a.x + a.w - w - 4.0), d.y + 12.0, w, 26.0);
            p.fill(chip, 7.0, pal.overlay);
            p.border(chip, 7.0, 1.0, pal.border_strong);
            p.line(&s, chip.x + 10.0, chip.y + 3.0, 20.0, &text);
        }
        if let Some(pr) = &mut self.props {
            draw_props(p, pal, f, a, pr);
        }
    }

    fn key(&mut self, code: u16, ch: Option<char>, mods: u8) -> Effect {
        let (shift, ctrl, alt) = (mods & SHIFT != 0, mods & CTRL != 0, mods & ALT != 0);
        let letter = ch.map(|c| c.to_ascii_lowercase());
        // The menu takes the keys while it is open.
        if let Some(m) = &mut self.menu {
            match code {
                KEY_UP => m.selected = m.selected.saturating_sub(1),
                KEY_DOWN | KEY_TAB => m.selected = (m.selected + 1).min(m.items.len() - 1),
                KEY_ENTER | KEY_KPENTER => {
                    let a = m.items[m.selected].1;
                    return self.act(a);
                }
                KEY_ESC => self.menu = None,
                _ => return Effect::None,
            }
            return Effect::Redraw;
        }
        // Renaming.
        if let Some(e) = &mut self.rename {
            match code {
                KEY_ENTER | KEY_KPENTER => self.finish_rename(),
                KEY_ESC => self.rename = None,
                _ => {
                    return if Self::field_key(e, code, ch, mods) { Effect::Redraw } else { Effect::None };
                }
            }
            return Effect::Redraw;
        }
        // The location field.
        if let Some(e) = &mut self.location {
            match code {
                KEY_ENTER | KEY_KPENTER => {
                    let raw = e.text();
                    let path = raw.trim();
                    let path = match path.strip_prefix('~') {
                        Some(r) => alloc::format!("{}{r}", self.home),
                        None => path.to_string(),
                    };
                    self.location = None;
                    if slate_rt::fs::stat(path.as_bytes())
                        .is_ok_and(|s| s.mode & slate_rt::fs::S_IFMT == slate_rt::fs::S_IFDIR)
                    {
                        let t = path.trim_end_matches('/');
                        self.go(Place::Folder(if t.is_empty() { String::from("/") } else { t.to_string() }));
                    } else {
                        self.status = alloc::format!("There is no folder {path}.");
                    }
                }
                KEY_ESC => self.location = None,
                _ => return if Self::field_key(e, code, ch, mods) { Effect::Redraw } else { Effect::None },
            }
            return Effect::Redraw;
        }
        // The search field.
        if let Some(e) = &mut self.search {
            match code {
                KEY_ENTER | KEY_KPENTER => {
                    let q = e.text().trim().to_string();
                    let root = match &self.place {
                        Place::Folder(p) => p.clone(),
                        Place::Search { root, .. } => root.clone(),
                        Place::Trash | Place::Device(_) => self.home.clone(),
                    };
                    self.search = None;
                    if !q.is_empty() {
                        let contents = self.search_contents;
                        self.go(Place::Search { root, query: q.clone(), contents });
                        let what = if contents { " in names and text" } else { "" };
                        crate::trace!("files: found {} for {q}{what}", self.items.len());
                    }
                }
                // Names, or names and the files' text.
                KEY_TAB => self.search_contents = !self.search_contents,
                KEY_ESC => self.search = None,
                _ => return if Self::field_key(e, code, ch, mods) { Effect::Redraw } else { Effect::None },
            }
            return Effect::Redraw;
        }
        // The properties dialog: the arrows move among the permissions,
        // Space changes one, Esc or Enter closes it.
        if let Some(pr) = &mut self.props {
            match code {
                KEY_ESC | KEY_ENTER | KEY_KPENTER => self.props = None,
                KEY_LEFT => pr.focus = pr.focus - pr.focus % 3 + (pr.focus % 3).saturating_sub(1),
                KEY_RIGHT => pr.focus = pr.focus - pr.focus % 3 + (pr.focus % 3 + 1).min(2),
                KEY_UP => pr.focus = pr.focus.saturating_sub(3),
                KEY_DOWN => pr.focus = (pr.focus + 3).min(8),
                _ if ch == Some(' ') => {
                    let k = pr.focus;
                    if let Err(e) = pr.toggle(k) {
                        self.status = e;
                    }
                }
                _ => return Effect::None,
            }
            return Effect::Redraw;
        }
        // A copy under way: Esc stops it.
        if code == KEY_ESC && self.transfer.is_some() {
            self.stop_transfer();
            return Effect::Redraw;
        }
        let n = self.items.len();
        let step = if self.view == View::Grid { self.per_row.max(1) } else { 1 };
        match (code, letter) {
            (_, Some('d')) if ctrl => return self.act(Action::Bookmark),
            (KEY_ENTER | KEY_KPENTER, _) if alt => return self.act(Action::Properties),
            (_, Some('c')) if ctrl => return self.act(Action::Copy),
            (_, Some('x')) if ctrl => return self.act(Action::Cut),
            (_, Some('v')) if ctrl => return self.act(Action::Paste),
            (_, Some('z')) if ctrl => self.undo_last(),
            (_, Some('a')) if ctrl => {
                self.selected = alloc::vec![true; n];
            }
            (_, Some('h')) if ctrl => return self.act(Action::ToggleHidden),
            (_, Some('l')) if ctrl => {
                let shown = self.folder().map(|p| self.pretty(p)).unwrap_or_default();
                let mut e = LineEdit::new(&shown).with_max(1024);
                e.select_all();
                self.location = Some(e);
            }
            (_, Some('f')) if ctrl => self.search = Some(LineEdit::new("").with_max(200)),
            (_, Some('n')) if ctrl && shift => return self.act(Action::NewFolder),
            (_, Some('1')) if ctrl => self.view = View::List,
            (_, Some('2')) if ctrl => self.view = View::Grid,
            (KEY_LEFT, _) if alt => self.back(),
            (KEY_RIGHT, _) if alt => self.forward_(),
            (KEY_UP, _) if alt => self.up(),
            (KEY_F2, _) => return self.act(Action::Rename),
            (KEY_F5, _) => self.load(),
            (KEY_DELETE, _) => {
                return self.act(if self.place == Place::Trash { Action::DeleteForGood } else { Action::Trash });
            }
            (KEY_ENTER | KEY_KPENTER, _) => return self.open(),
            (KEY_BACKSPACE, _) if !self.filter.is_empty() => {
                self.filter.pop();
                self.load();
            }
            (KEY_BACKSPACE, _) => self.up(),
            (KEY_ESC, _) => {
                if !self.filter.is_empty() {
                    self.filter.clear();
                    self.load();
                } else if self.selected.iter().any(|&s| s) {
                    self.selected = alloc::vec![false; n];
                } else if matches!(self.place, Place::Search { .. }) {
                    self.back();
                } else {
                    return Effect::None;
                }
            }
            (KEY_UP, _) => self.move_cursor(self.cursor.saturating_sub(step), shift),
            (KEY_DOWN, _) => self.move_cursor((self.cursor + step).min(n.saturating_sub(1)), shift),
            (KEY_LEFT, _) if self.view == View::Grid => self.move_cursor(self.cursor.saturating_sub(1), shift),
            (KEY_RIGHT, _) if self.view == View::Grid => self.move_cursor(self.cursor + 1, shift),
            (KEY_HOME, _) => self.move_cursor(0, shift),
            (KEY_END, _) => self.move_cursor(n.saturating_sub(1), shift),
            (KEY_PAGEUP, _) => self.move_cursor(self.cursor.saturating_sub(self.shown.max(1)), shift),
            (KEY_PAGEDOWN, _) => self.move_cursor(self.cursor + self.shown.max(1), shift),
            // Typing filters the folder.
            (_, _) => match ch.filter(|c| mods & (CTRL | ALT | LOGO) == 0 && !c.is_control()) {
                Some(c) if self.place != Place::Trash => {
                    self.filter.push(c);
                    self.load();
                    self.cursor = 0;
                    if !self.items.is_empty() {
                        self.select_only(0);
                    }
                }
                _ => return Effect::None,
            },
        }
        Effect::Redraw
    }

    fn click_mods(&mut self, x: f32, y: f32, mods: u8) -> Effect {
        // The properties dialog: a permission box changes; elsewhere
        // closes it.
        if let Some(pr) = &mut self.props {
            match pr.hits.iter().position(|h| h.contains(x, y)) {
                Some(k) => {
                    pr.focus = k;
                    if let Err(e) = pr.toggle(k) {
                        self.status = e;
                    }
                }
                None => self.props = None,
            }
            return Effect::Redraw;
        }
        if let Some(m) = &self.menu {
            let hit = m.hits.iter().position(|h| h.contains(x, y)).map(|k| m.items[k].1);
            self.menu = None;
            return match hit {
                Some(a) => self.act(a),
                None => Effect::Redraw,
            };
        }
        if self.rename.is_some() {
            self.finish_rename();
        }
        if let Some((_, place)) = self.side.iter().find(|(r, _)| r.contains(x, y)) {
            let place = place.clone();
            match place {
                Place::Device(dev) => self.ask_disk(&dev, true),
                place => self.go(place),
            }
            return Effect::Redraw;
        }
        if let Some((_, path)) = self.crumbs.iter().find(|(r, _)| r.contains(x, y)) {
            let path = path.clone();
            self.go(Place::Folder(path));
            return Effect::Redraw;
        }
        if let Some(&(_, k)) = self.nav.iter().find(|(r, _)| r.contains(x, y)) {
            if k == 0 {
                self.back()
            } else {
                self.forward_()
            }
            return Effect::Redraw;
        }
        if let Some(&(_, s)) = self.headers.iter().find(|(r, _)| r.contains(x, y)) {
            if self.sort == s {
                self.reverse = !self.reverse;
            } else {
                self.sort = s;
                self.reverse = false;
            }
            self.load();
            return Effect::Redraw;
        }
        match self.rows.iter().position(|r| r.contains(x, y)) {
            Some(k) => {
                let i = self.first + k;
                let chosen = self.selected.get(i) == Some(&true);
                if mods & CTRL != 0 {
                    if let Some(s) = self.selected.get_mut(i) {
                        *s = !*s;
                    }
                    self.cursor = i;
                    self.anchor = Some(i);
                } else if chosen && mods & SHIFT == 0 {
                    // Chosen already: a drag takes all that are; a plain
                    // click chooses it alone when the button comes up.
                    self.cursor = i;
                } else {
                    self.move_cursor(i, mods & SHIFT != 0);
                }
                self.press = Some((x, y, i, chosen && mods & (SHIFT | CTRL) == 0));
            }
            None => {
                self.selected = alloc::vec![false; self.items.len()];
            }
        }
        Effect::Redraw
    }

    fn double_click(&mut self, x: f32, y: f32) -> Effect {
        if self.rows.iter().any(|r| r.contains(x, y)) {
            return self.open();
        }
        self.click_mods(x, y, 0)
    }

    fn drag(&mut self, x: f32, y: f32) -> Effect {
        self.drag_mods(x, y, 0)
    }

    /// A drag; ctrl held makes it a copy (the chip says so).
    fn drag_mods(&mut self, x: f32, y: f32, mods: u8) -> Effect {
        let Some((x0, y0, i, _)) = self.press else { return Effect::None };
        let copy = mods & CTRL != 0;
        if self.dragging.is_none() {
            if (x - x0).abs() < DRAG_START && (y - y0).abs() < DRAG_START || self.place == Place::Trash {
                return Effect::None;
            }
            let paths = self.chosen_paths();
            let paths =
                if paths.is_empty() { self.items.get(i).map(|it| alloc::vec![it.path.clone()]) } else { Some(paths) };
            let Some(paths) = paths.filter(|p| !p.is_empty()) else { return Effect::None };
            self.dragging = Some(Dragging { paths: paths.clone(), x, y, target: None, copy });
            // Strata takes them if they leave the window (ADR 0156).
            return Effect::Drag(paths);
        }
        let target = self.drop_target(x, y);
        if let Some(d) = &mut self.dragging {
            (d.x, d.y, d.target, d.copy) = (x, y, target, copy);
        }
        Effect::Redraw
    }

    /// Files from the desktop or another app (ADR 0156): moved (with
    /// ctrl, copied) into the folder or place they were dropped on, else
    /// into the folder shown, as a drag here would. A folder isn't moved
    /// or copied into itself.
    fn dropped(&mut self, x: f32, y: f32, paths: &[String], copy: bool) -> Effect {
        let target = self.drop_target(x, y).or_else(|| self.folder().map(|d| Place::Folder(String::from(d))));
        match target {
            Some(Place::Trash) => self.trash_paths(paths),
            Some(Place::Folder(dir)) => {
                let inside = |p: &String| dir == *p || dir.starts_with(&alloc::format!("{p}/"));
                let paths: Vec<String> = paths.iter().filter(|p| !inside(p)).cloned().collect();
                crate::trace!("files: {} dropped from outside on {}", paths.len(), self.pretty(&dir));
                self.transfer_into(&paths, &dir, !copy);
            }
            _ => return Effect::None,
        }
        Effect::Redraw
    }

    fn release(&mut self) -> Effect {
        self.release_mods(0)
    }

    /// The button came up: what was dragged goes where it was dropped,
    /// copied when ctrl is held then.
    fn release_mods(&mut self, mods: u8) -> Effect {
        let press = self.press.take();
        let Some(d) = self.dragging.take() else {
            // A plain click on something chosen: it alone is, now.
            if let Some((_, _, i, true)) = press {
                self.move_cursor(i, false);
                return Effect::Redraw;
            }
            return Effect::None;
        };
        match d.target {
            Some(Place::Trash) => self.trash_paths(&d.paths),
            Some(Place::Folder(dir)) => {
                let copy = mods & CTRL != 0;
                crate::trace!(
                    "files: {} {} on {}",
                    if copy { "copied" } else { "dropped" },
                    d.paths.len(),
                    self.pretty(&dir)
                );
                self.transfer_into(&d.paths, &dir, !copy);
            }
            _ => {}
        }
        Effect::Redraw
    }

    fn right_click(&mut self, x: f32, y: f32) -> Effect {
        self.rename = None;
        // A disk mounted in /run/media: unmount it.
        if let Some((_, Place::Folder(path))) = self.side.iter().find(|(r, _)| r.contains(x, y))
            && path.starts_with(&alloc::format!("{}/", slate_diskutil::MEDIA))
            && let Some(d) = self.disks.iter().find(|d| d.at == *path)
        {
            self.menu_disk = Some(d.device.clone());
            self.last_menu = Some((x, y));
            self.menu =
                Some(Menu { x, y, items: alloc::vec![("Unmount", Action::Unmount)], selected: 0, hits: Vec::new() });
            return Effect::Redraw;
        }
        // A bookmark in the sidebar: remove it.
        if let Some((_, Place::Folder(path))) = self.side.iter().find(|(r, _)| r.contains(x, y))
            && self.bookmarks.contains(path)
        {
            self.menu_bookmark = Some(path.clone());
            self.last_menu = Some((x, y));
            self.menu = Some(Menu {
                x,
                y,
                items: alloc::vec![("Remove the bookmark", Action::Unbookmark)],
                selected: 0,
                hits: Vec::new(),
            });
            return Effect::Redraw;
        }
        let on = self.rows.iter().position(|r| r.contains(x, y)).map(|k| self.first + k);
        if let Some(i) = on
            && self.selected.get(i) != Some(&true)
        {
            self.move_cursor(i, false);
        }
        self.menu_at(x, y, on.is_some());
        Effect::Redraw
    }

    fn scroll(&mut self, lines: i32) -> Effect {
        let step = if self.view == View::Grid { self.per_row.max(1) } else { 1 };
        let n = self.items.len();
        let first =
            (self.first as i64 + i64::from(lines) * 3 * step as i64).clamp(0, n.saturating_sub(1) as i64) as usize;
        // Moving the view moves the cursor with it, as needed.
        self.first = first;
        if self.cursor < first {
            self.cursor = first;
        } else if self.cursor >= first + self.shown {
            self.cursor = (first + self.shown).saturating_sub(1).min(n.saturating_sub(1));
        }
        Effect::Redraw
    }

    fn paste(&mut self, text: &str) -> Effect {
        let field = self.rename.as_mut().or(self.location.as_mut()).or(self.search.as_mut());
        match field {
            Some(f) => {
                f.insert(text.lines().next().unwrap_or(""));
                Effect::Redraw
            }
            None => Effect::None,
        }
    }

    fn tick(&mut self, now: Now) -> bool {
        // Thumbnails: two each time round, so the window keeps answering.
        let mut changed = false;
        // A mount or unmount asked for.
        if let Some((j, dev, mount)) = &mut self.disk_job
            && let Some(r) = j.poll()
        {
            let (dev, mount) = (dev.clone(), *mount);
            self.disk_job = None;
            self.reread_disks();
            match r {
                Ok(_) if mount => {
                    let at = self.disks.iter().find(|d| d.device == alloc::format!("/dev/{dev}")).map(|d| d.at.clone());
                    if let Some(at) = at {
                        crate::trace!("files: mounted {dev} at {at}");
                        self.status.clear();
                        self.go(Place::Folder(at));
                    }
                }
                Ok(_) => {
                    crate::trace!("files: unmounted {dev}");
                    self.status = String::from("Unmounted: the disk can be removed.");
                }
                Err(e) => {
                    self.status = alloc::format!("Couldn't {}: {e}", if mount { "open it" } else { "unmount it" })
                }
            }
            changed = true;
        }
        // The copy under way.
        let mut outcome = None;
        if let Some(t) = &mut self.transfer
            && let Some(j) = &mut t.job
        {
            outcome = j.poll();
            if let Some(p) = j.progress.take() {
                let mut w = p.split('\t');
                t.done = w.next().and_then(|v| v.parse().ok()).unwrap_or(t.done);
                t.at = w.next().and_then(|v| v.parse().ok()).unwrap_or(t.at);
                t.removing = w.next() == Some("1");
                changed = true;
            }
        }
        if let Some(r) = outcome
            && let Some(t) = self.transfer.take()
        {
            {
                let (n, e) = match r {
                    Ok(text) => {
                        let (n, e) = text.split_once('\n').unwrap_or((&text, ""));
                        (n.parse().unwrap_or(0), Some(e.to_string()).filter(|e| !e.is_empty()))
                    }
                    Err(e) => (0, Some(e)),
                };
                self.finish_transfer(&t.list, n, t.cut, e);
                changed = true;
            }
        }
        for key in self.wanted_thumbs().into_iter().take(2) {
            let thumb =
                slate_rt::fs::read_file(key.0.as_bytes()).ok().and_then(|d| slate_image::decode(&d).ok()).map(|img| {
                    let s = (THUMB.0 as f32 / img.width as f32).min(THUMB.1 as f32 / img.height as f32).min(1.0);
                    img.scaled(((img.width as f32 * s) as u32).max(1), ((img.height as f32 * s) as u32).max(1))
                });
            self.thumbs.insert(key, thumb);
            changed = true;
        }
        // The folder changed underneath: read it again.
        if now.mono - self.checked >= REFRESH_MS {
            self.checked = now.mono;
            if let Some(d) = self.folder() {
                let st = slate_rt::fs::stat(d.as_bytes()).ok().map(|s| (s.mtime, s.mtime_nsec));
                if st != self.stamp && self.rename.is_none() {
                    self.load();
                    changed = true;
                }
            }
        }
        changed
    }

    fn wake(&self, now: Now) -> Option<i64> {
        if !self.wanted_thumbs().is_empty() {
            return Some(0);
        }
        if self.transfer.is_some() || self.disk_job.is_some() {
            return Some(kit::JOB_MS);
        }
        Some((self.checked + REFRESH_MS - now.mono).max(0))
    }

    fn title(&self) -> Option<(String, Option<String>)> {
        Some((String::from("files"), Some(self.title_path())))
    }
}

/// `files --open PATH` (the desktop's icons, ADR 0102's third
/// addendum): the app that opens the file, as a double click here would;
/// when none does, the window opens on its folder with it chosen, and
/// says so.
fn open_file(path: &str) -> Result<(), String> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let prog = fsops::opener(name, &fsops::head(path))
        .program()
        .ok_or_else(|| alloc::format!("No app in Slate opens {name} yet."))?;
    fsops::start(prog, &[String::from(path)])?;
    crate::trace!("files: opened {path} with {prog}");
    Ok(())
}

/// The options that work without a window.
const HEADLESS: [&str; 4] = ["--move-to", "--copy-to", "--trash", "--undo"];

/// `files --move-to DIR PATH...`, `--copy-to DIR PATH...`, `--trash
/// PATH...` and `--undo`: what the desktop's drops, its Move to Trash
/// and its ctrl + z ask (ADR 0156 and its addendum), done without a
/// window as a drop, Delete or ctrl + z here would (names that are taken
/// get " (copy)"; across disks, a copy). The changes go to the desktop's
/// undo journal, which `--undo` takes the last one from. What it did, or
/// why not, goes to stderr; 1 when something couldn't be done.
fn headless(home: &str, op: &str, args: &[String]) -> i32 {
    headless_in(Files::new(home, Place::Folder(String::from(home))), home, op, args)
}

/// [`headless`] with `f` (the tests' own trash).
fn headless_in(mut f: Files, home: &str, op: &str, args: &[String]) -> i32 {
    let config = alloc::format!("{home}/.config/strata");
    match (op, args.split_first()) {
        ("--move-to" | "--copy-to", Some((dir, paths))) if !paths.is_empty() => {
            f.transfer_into(paths, dir, op == "--move-to");
        }
        ("--trash", Some(_)) => f.trash_paths(args),
        ("--undo", None) => match slate_strata::undo::pop(&config) {
            Some(op) => f.undo_op(op),
            None => f.status = String::from("Nothing to undo."),
        },
        _ => {
            slate_rt::eprintln!(
                "files: usage: files --move-to DIR PATH... | --copy-to DIR PATH... | --trash PATH... | --undo"
            );
            return 2;
        }
    }
    if let Some(done) = f.undo.pop() {
        slate_strata::undo::push(&config, done);
    }
    if !f.status.is_empty() {
        slate_rt::eprintln!("files: {}", f.status);
    }
    i32::from(f.status.starts_with("Couldn't"))
}

pub fn main() -> i32 {
    let home = slate_rt::env::var(b"HOME").map(|h| String::from(slate_rt::lossy(&h))).unwrap_or_else(|| "/".into());
    let args = slate_rt::env::args();
    let arg = |i: usize| args.get(i).map(|a| String::from(slate_rt::lossy(a)));
    if let Some(op) = arg(1).filter(|a| HEADLESS.contains(&a.as_str())) {
        let rest: Vec<String> = args.iter().skip(2).map(|a| String::from(slate_rt::lossy(a))).collect();
        return headless(&home, &op, &rest);
    }
    let mut chosen = None;
    let mut status = String::new();
    let start = match (arg(1).as_deref(), arg(2)) {
        (Some("--open"), Some(path)) => {
            let folder = slate_rt::fs::stat(path.as_bytes())
                .is_ok_and(|s| s.mode & slate_rt::fs::S_IFMT == slate_rt::fs::S_IFDIR);
            if folder {
                path
            } else {
                match open_file(&path) {
                    Ok(()) => return 0,
                    Err(e) => {
                        status = e;
                        chosen = Some(String::from(path.rsplit('/').next().unwrap_or(&path)));
                        fsops::parent(&path)
                    }
                }
            }
        }
        (Some(p), _) => String::from(p),
        (None, _) => home.clone(),
    };
    let mut f = Files::new(&home, Place::Folder(start));
    if let Some(name) = chosen
        && let Some(i) = f.items.iter().position(|it| it.entry.name == name)
    {
        f.select_only(i);
    }
    f.status = status;
    f.live = true;
    f.bookmarks = Files::load_bookmarks();
    f.unmounted = Files::read_unmounted();
    let path = f.title_path();
    kit::run("files", "files", Some(&path), Hints { min: (560, 400), size: (900, 600) }, &mut f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;

    fn scratch(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("slate-filesapp-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }

    fn files_at(home: &str) -> Files {
        let mut f = Files::new(home, Place::Folder(home.to_string()));
        f.trash = Some(Trash { dir: format!("{home}/.local/share/Trash"), top: None });
        f.load();
        f
    }

    fn names(f: &Files) -> Vec<String> {
        f.items.iter().map(|i| i.entry.name.clone()).collect()
    }

    fn typed(f: &mut Files, s: &str) {
        for c in s.chars() {
            f.key(0, Some(c), 0);
        }
    }

    #[test]
    fn browsing_and_filtering() {
        let h = scratch("browse");
        std::fs::create_dir_all(format!("{h}/Documents/letters")).unwrap();
        std::fs::write(format!("{h}/Documents/letters/to-ada.txt"), b"hi").unwrap();
        std::fs::write(format!("{h}/Documents/plan.txt"), b"x").unwrap();
        std::fs::write(format!("{h}/.secret"), b"x").unwrap();
        let mut f = files_at(&h);
        assert_eq!(names(&f), ["Documents"]);
        assert!(f.places.iter().any(|p| p.0 == "Documents"));
        f.key(0, Some('h'), CTRL);
        assert_eq!(names(&f), ["Documents", ".secret"]);
        f.key(0, Some('h'), CTRL);
        f.key(KEY_ENTER, None, 0);
        assert_eq!(f.folder(), Some(format!("{h}/Documents").as_str()));
        assert_eq!(names(&f), ["letters", "plan.txt"]);
        typed(&mut f, "pla");
        assert_eq!(names(&f), ["plan.txt"]);
        f.key(KEY_ESC, None, 0);
        assert_eq!(names(&f).len(), 2);
        f.key(KEY_BACKSPACE, None, 0);
        assert_eq!(f.folder(), Some(h.as_str()));
        assert_eq!(f.cursor, 0, "on the folder it came from");
        // Going up was a step: back returns to Documents, forward comes
        // up again.
        f.key(KEY_LEFT, None, ALT);
        assert_eq!(f.folder(), Some(format!("{h}/Documents").as_str()));
        f.key(KEY_RIGHT, None, ALT);
        assert_eq!(f.folder(), Some(h.as_str()));
        // Search under home.
        f.key(0, Some('f'), CTRL);
        typed(&mut f, "ada");
        f.key(KEY_ENTER, None, 0);
        assert!(matches!(f.place, Place::Search { .. }));
        assert_eq!(names(&f), ["to-ada.txt"]);
        assert_eq!(f.items[0].note.as_deref(), Some("~/Documents/letters"));
        std::fs::remove_dir_all(&h).unwrap();
    }

    #[test]
    fn copy_paste_rename_trash_and_undo() {
        let h = scratch("ops");
        std::fs::create_dir_all(format!("{h}/a")).unwrap();
        std::fs::write(format!("{h}/a/n.txt"), b"note").unwrap();
        let mut f = files_at(&h);
        f.key(KEY_ENTER, None, 0);
        // Copy n.txt, paste beside itself: n (copy).txt.
        assert_eq!(f.key(0, Some('c'), CTRL), Effect::Copy(format!("{h}/a/n.txt")));
        f.key(0, Some('v'), CTRL);
        assert_eq!(names(&f), ["n (copy).txt", "n.txt"]);
        // Rename the copy: F2 chooses the name without .txt.
        f.key(KEY_HOME, None, 0);
        f.key(KEY_F2, None, 0);
        typed(&mut f, "m");
        f.key(KEY_ENTER, None, 0);
        assert_eq!(names(&f), ["m.txt", "n.txt"]);
        f.key(0, Some('z'), CTRL);
        assert_eq!(names(&f), ["n (copy).txt", "n.txt"]);
        // To the trash and back.
        f.key(KEY_DELETE, None, 0);
        assert_eq!(names(&f), ["n.txt"]);
        assert_eq!(f.trash.as_ref().unwrap().list().len(), 1);
        f.key(0, Some('z'), CTRL);
        assert_eq!(names(&f), ["n (copy).txt", "n.txt"]);
        // Cut into a new folder.
        f.key(0, Some('n'), CTRL | SHIFT);
        assert!(f.rename.is_some());
        typed(&mut f, "box");
        f.key(KEY_ENTER, None, 0);
        assert_eq!(names(&f), ["box", "n (copy).txt", "n.txt"]);
        f.key(KEY_END, None, 0);
        f.key(0, Some('x'), CTRL);
        f.key(KEY_HOME, None, 0);
        f.key(KEY_ENTER, None, 0);
        f.key(0, Some('v'), CTRL);
        assert_eq!(names(&f), ["n.txt"]);
        f.key(KEY_BACKSPACE, None, 0);
        assert_eq!(names(&f), ["box", "n (copy).txt"]);
        // The trash: restore, and delete for good (twice).
        f.key(KEY_END, None, 0);
        f.key(KEY_DELETE, None, 0);
        f.go(Place::Trash);
        assert_eq!(names(&f), ["n (copy).txt"]);
        assert_eq!(f.items[0].note.as_deref().map(|n| n.starts_with("from ")), Some(true));
        f.key(KEY_ENTER, None, 0);
        assert!(f.items.is_empty());
        assert!(std::path::Path::new(&format!("{h}/a/n (copy).txt")).exists());
        std::fs::write(format!("{h}/gone.txt"), b"x").unwrap();
        f.trash.as_ref().unwrap().put(&format!("{h}/gone.txt"), 1).unwrap();
        f.load();
        f.key(KEY_DELETE, None, 0);
        assert_eq!(f.items.len(), 1, "asked first");
        f.key(KEY_DELETE, None, 0);
        assert!(f.items.is_empty());
        std::fs::remove_dir_all(&h).unwrap();
    }

    #[test]
    fn menus_and_views() {
        let h = scratch("menu");
        std::fs::write(format!("{h}/one.txt"), b"1").unwrap();
        let mut f = files_at(&h);
        f.menu_at(10.0, 10.0, true);
        let labels: Vec<&str> = f.menu.as_ref().unwrap().items.iter().map(|x| x.0).collect();
        assert_eq!(
            labels,
            ["Open", "Open with…", "Cut", "Copy", "Rename", "Compress", "Move to the trash", "Properties"]
        );
        for _ in 0..3 {
            f.key(KEY_DOWN, None, 0);
        }
        assert_eq!(f.key(KEY_ENTER, None, 0), Effect::Copy(format!("{h}/one.txt")));
        assert!(f.menu.is_none());
        f.key(0, Some('2'), CTRL);
        assert_eq!(f.view, View::Grid);
        assert!(when(1_792_879_170, 1_792_879_170 + 60).starts_with("today"));
        // Open with: the default app (text, for a .txt) first.
        f.menu_at(10.0, 10.0, true);
        f.act(Action::OpenWith);
        let labels: Vec<&str> = f.menu.as_ref().unwrap().items.iter().map(|x| x.0).collect();
        assert_eq!(labels[0], "Text Editor");
        assert_eq!(labels.len(), OPEN_WITH.len());
        std::fs::remove_dir_all(&h).unwrap();
    }

    #[test]
    fn bookmarks_properties_and_search() {
        let h = scratch("props");
        std::fs::create_dir_all(format!("{h}/work")).unwrap();
        std::fs::write(format!("{h}/work/plan.txt"), b"meet the Analytical Engine team").unwrap();
        std::fs::write(format!("{h}/work/other.txt"), b"nothing here").unwrap();
        let mut f = files_at(&h);
        // ctrl + d bookmarks the folder, and again removes it.
        f.key(KEY_ENTER, None, 0);
        f.key(0, Some('d'), CTRL);
        assert_eq!(f.bookmarks, [format!("{h}/work")]);
        f.menu_at(300.0, 300.0, false);
        let labels: Vec<&str> = f.menu.as_ref().unwrap().items.iter().map(|x| x.0).collect();
        assert!(labels.contains(&"Remove the bookmark"));
        f.menu = None;
        f.key(0, Some('d'), CTRL);
        assert!(f.bookmarks.is_empty());
        // Properties: alt + Enter; space turns the group's write on.
        f.key(KEY_ENTER, None, ALT);
        let pr = f.props.as_ref().unwrap();
        assert_eq!((pr.name.as_str(), pr.kind.as_str(), pr.size.0), ("other.txt", "text", 12));
        assert_eq!(pr.location, "~/work");
        let before = pr.mode.unwrap();
        f.key(KEY_DOWN, None, 0);
        f.key(KEY_RIGHT, None, 0);
        f.key(0, Some(' '), 0);
        assert_eq!(f.props.as_ref().unwrap().mode, Some(before | 0o020));
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(format!("{h}/work/other.txt")).unwrap().permissions().mode();
        assert_eq!(m & 0o777, before | 0o020);
        f.key(KEY_ESC, None, 0);
        assert!(f.props.is_none());
        // A folder's properties count what is in it.
        f.key(KEY_BACKSPACE, None, 0);
        f.act(Action::Properties);
        let pr = f.props.take().unwrap();
        assert_eq!((pr.kind.as_str(), pr.size.0, pr.size.1), ("folder", 43, 3));
        // Searching the text: Tab in the search field.
        f.key(0, Some('f'), CTRL);
        typed(&mut f, "engine");
        f.key(KEY_ENTER, None, 0);
        assert!(f.items.is_empty(), "no name holds it");
        f.key(0, Some('f'), CTRL);
        typed(&mut f, "engine");
        f.key(KEY_TAB, None, 0);
        f.key(KEY_ENTER, None, 0);
        assert_eq!(names(&f), ["plan.txt"]);
        std::fs::remove_dir_all(&h).unwrap();
    }

    #[test]
    fn copies_report_and_drags_move() {
        let h = scratch("drag");
        std::fs::create_dir_all(format!("{h}/box")).unwrap();
        std::fs::write(format!("{h}/big.bin"), std::vec![7u8; 3 << 20]).unwrap();
        std::fs::write(format!("{h}/small.txt"), b"s").unwrap();
        // The work says each mebibyte, and the item it is on.
        let list = std::vec![(format!("{h}/big.bin"), format!("{h}/box/big.bin"))];
        let mut said = Vec::new();
        let (n, e) = transfer_work(&list, false, &mut |done, at, _| said.push((done, at)));
        assert_eq!((n, e), (1, None));
        assert_eq!(said.last(), Some(&(3 << 20, 0)));
        assert!(said.len() >= 4);
        std::fs::remove_file(format!("{h}/box/big.bin")).unwrap();
        // Dragging the two chosen files onto the folder moves them.
        let mut f = files_at(&h);
        assert_eq!(names(&f), ["box", "big.bin", "small.txt"]);
        f.rows = (0..3).map(|k| Area::new(200.0, 100.0 + 32.0 * k as f32, 600.0, 30.0)).collect();
        f.click_mods(300.0, 140.0, 0);
        f.click_mods(300.0, 172.0, SHIFT);
        assert_eq!(f.chosen(), [1, 2]);
        // Pressed on a chosen one: both are dragged.
        f.click_mods(300.0, 140.0, 0);
        assert_eq!(f.chosen(), [1, 2]);
        // The drag's start tells Strata what is dragged (ADR 0156).
        let paths = std::vec![format!("{h}/big.bin"), format!("{h}/small.txt")];
        assert_eq!(f.drag(305.0, 125.0), Effect::Drag(paths));
        assert_eq!(f.drag(300.0, 110.0), Effect::Redraw);
        let d = f.dragging.clone().unwrap();
        assert_eq!((d.paths.len(), d.target), (2, Some(Place::Folder(format!("{h}/box")))));
        f.release();
        assert_eq!(names(&f), ["box"]);
        let inside: Vec<String> = std::fs::read_dir(format!("{h}/box"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(inside.len(), 2);
        // Undone: back where they were.
        f.key(0, Some('z'), CTRL);
        assert_eq!(names(&f), ["box", "big.bin", "small.txt"]);
        // With ctrl held, a copy: the chip says so, the originals stay.
        f.rows = (0..3).map(|k| Area::new(200.0, 100.0 + 32.0 * k as f32, 600.0, 30.0)).collect();
        f.click_mods(300.0, 172.0, 0);
        f.drag_mods(305.0, 160.0, CTRL);
        f.drag_mods(300.0, 110.0, CTRL);
        assert!(f.dragging.as_ref().is_some_and(|d| d.copy));
        f.release_mods(CTRL);
        assert_eq!(names(&f), ["box", "big.bin", "small.txt"]);
        assert!(std::fs::metadata(format!("{h}/box/small.txt")).is_ok());
        f.key(0, Some('z'), CTRL);
        assert!(std::fs::metadata(format!("{h}/box/small.txt")).is_err(), "the copy undone");
        // A plain click on a chosen item chooses it alone when let go.
        f.key(0, Some('a'), CTRL);
        f.rows = (0..3).map(|k| Area::new(200.0, 100.0 + 32.0 * k as f32, 600.0, 30.0)).collect();
        f.click_mods(300.0, 172.0, 0);
        f.release();
        assert_eq!(f.chosen(), [2]);
        std::fs::remove_dir_all(&h).unwrap();
    }

    /// The desktop's changes through `files` without a window, and their
    /// undoing from the journal (ADR 0156's addendum).
    #[test]
    fn headless_changes_undone_from_the_journal() {
        let h = scratch("headless");
        std::fs::create_dir_all(format!("{h}/Desktop/box")).unwrap();
        std::fs::write(format!("{h}/Desktop/a.txt"), b"a").unwrap();
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let desk = format!("{h}/Desktop");
        assert_eq!(
            headless_in(files_at(&h), &h, "--copy-to", &s(&[&format!("{desk}/box"), &format!("{desk}/a.txt")])),
            0
        );
        assert_eq!(headless_in(files_at(&h), &h, "--move-to", &s(&[&desk, &format!("{desk}/box/a.txt")])), 0);
        assert!(std::fs::metadata(format!("{desk}/a (copy).txt")).is_ok());
        let journal = std::fs::read_to_string(format!("{h}/.config/strata/desktop-undo")).unwrap();
        assert_eq!(journal.lines().count(), 2);
        // Undone newest first: the move, then the copy (into the trash).
        assert_eq!(headless_in(files_at(&h), &h, "--undo", &[]), 0);
        assert!(std::fs::metadata(format!("{desk}/box/a.txt")).is_ok());
        assert!(std::fs::metadata(format!("{desk}/a (copy).txt")).is_err());
        assert_eq!(headless_in(files_at(&h), &h, "--undo", &[]), 0);
        assert!(std::fs::metadata(format!("{desk}/box/a.txt")).is_err());
        assert!(std::fs::metadata(format!("{desk}/a.txt")).is_ok());
        assert_eq!(headless_in(files_at(&h), &h, "--undo", &[]), 0, "nothing left: said, not an error");
        std::fs::remove_dir_all(&h).unwrap();
    }

    #[test]
    fn drops_from_outside_move_in() {
        let h = scratch("dropped");
        let out = scratch("dropped-desktop");
        std::fs::create_dir_all(format!("{h}/box")).unwrap();
        std::fs::write(format!("{h}/here.txt"), b"h").unwrap();
        std::fs::write(format!("{out}/notes.txt"), b"n").unwrap();
        std::fs::create_dir_all(format!("{out}/Projects")).unwrap();
        let mut f = files_at(&h);
        f.rows = (0..2).map(|k| Area::new(200.0, 100.0 + 32.0 * k as f32, 600.0, 30.0)).collect();
        // On a folder in view: into it.
        f.dropped(300.0, 110.0, &[format!("{out}/notes.txt")], false);
        assert!(std::fs::metadata(format!("{h}/box/notes.txt")).is_ok());
        // Anywhere else: into the folder shown; a taken name gets " (copy)".
        std::fs::write(format!("{out}/here.txt"), b"o").unwrap();
        f.dropped(300.0, 400.0, &[format!("{out}/Projects"), format!("{out}/here.txt")], false);
        assert_eq!(names(&f), ["box", "Projects", "here (copy).txt", "here.txt"]);
        assert!(std::fs::read_dir(&out).unwrap().next().is_none());
        // A folder dropped on itself stays.
        f.rows = (0..2).map(|k| Area::new(200.0, 100.0 + 32.0 * k as f32, 600.0, 30.0)).collect();
        f.dropped(300.0, 110.0, &[format!("{h}/box")], false);
        assert_eq!(names(&f)[0], "box");
        // With ctrl, copied: the original stays where it was.
        std::fs::write(format!("{out}/kept.txt"), b"k").unwrap();
        f.dropped(300.0, 400.0, &[format!("{out}/kept.txt")], true);
        assert!(std::fs::metadata(format!("{out}/kept.txt")).is_ok());
        assert!(names(&f).iter().any(|n| n == "kept.txt"));
        std::fs::remove_dir_all(&h).unwrap();
        std::fs::remove_dir_all(&out).unwrap();
    }
}
