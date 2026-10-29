// SPDX-License-Identifier: MIT OR Apache-2.0

//! Desktop icons (ADR 0102's third addendum, ADR 0156): what is in
//! `~/Desktop`, shown on the wallpaper in a grid of cells. Icons stay in
//! the cells they were dragged to (`~/.config/strata/desktop-positions`);
//! the rest fill the free cells from the top left, down then across,
//! folders first, then by name. When there are more than cells, the last
//! cell says how many more, and opens the folder in Files.
//!
//! A click selects an icon (ctrl adds or takes it away, shift a run in
//! the icons' order); a box dragged on the wallpaper selects what it
//! touches; a double click opens one: a folder in Files, an app entry
//! (`.app`, or a Linux runtime's `.desktop` file) by its program,
//! anything else as Files would open it (`files --open`). Dragged, the
//! selection moves to other cells, into a folder icon, or onto a
//! window, whose app is told (the session drops them there). The right
//! button gives a menu; with no window focused, the keys work the icons.
//! Moving into a folder and Move to Trash go through Files, without a
//! window (`files --move-to`, `files --trash`); renaming and new folders
//! happen here. With ctrl held when the button comes up, a drag copies
//! (`files --copy-to`). Every change goes to the desktop's undo journal
//! (`crate::undo`), which ctrl + z and the menu's Undo take back
//! (`files --undo`).
//!
//! Strata reads the folder again when its watch says it changed
//! (`crate::watch`). A person's first session puts a "Files" icon there,
//! which opens their home folder; once taken away it stays away.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use slate_display::input::*;
use slate_rt::{fs, lossy};
use slate_ui::edit::{EditKey, LineEdit};
use slate_ui::fileicon;
use slate_ui::icon::Icon;
use slate_ui::math::floor;
use slate_ui::ui::Area;

use crate::launcher;

/// A cell of the grid (logical pixels).
pub const CELL_W: f32 = 96.0;
pub const CELL_H: f32 = 96.0;
/// The space between the grid and the work area's edges.
const MARGIN: f32 = 12.0;
/// Two clicks on one icon within this long open it (ms).
const DOUBLE_CLICK_MS: i64 = 400;
/// How far the pointer moves with the button down before it drags.
const DRAG_START: f32 = 5.0;
/// Where icons were put (`~/.config/strata/`): a line per icon, its
/// column, row and file name.
const POSITIONS: &str = "desktop-positions";
const FILES: &str = "/bin/files";
const SETTINGS: &str = "/bin/strata-settings";
/// The longest name a rename takes (bytes, as file systems count).
const NAME_MAX: usize = 255;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Folder,
    /// A file, and what its icon shows.
    File(fileicon::Kind),
    /// An app entry, and the command it runs (by spaces, as the launcher
    /// runs it).
    App(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// What the icon is called: the file's name, or the app's.
    pub name: String,
    pub path: String,
    pub kind: Kind,
    /// An app's glyph (folders and files are drawn by their kind).
    pub icon: Icon,
}

impl Item {
    /// The name of its file in the folder.
    pub fn file_name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }
}

/// Where the icons are on a work area.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Layout {
    /// Each item's cell; None for those past the last cell.
    pub cells: Vec<Option<Area>>,
    /// The last cell when some don't fit, and how many don't.
    pub more: Option<(Area, usize)>,
}

/// What the right button's menu offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Open,
    Rename,
    Trash,
    NewFolder,
    ShowInFiles,
    Wallpaper,
    Undo,
}

/// The right button's menu, at (x, y).
#[derive(Clone, Debug, PartialEq)]
pub struct Menu {
    pub x: f32,
    pub y: f32,
    pub items: Vec<(&'static str, Action)>,
    pub selected: usize,
}

/// A menu row's height and the menu's width (logical pixels).
const MENU_ROW: f32 = 32.0;
const MENU_W: f32 = 232.0;

impl Menu {
    /// The menu's box on a `w` × `h` screen (below and right of where it
    /// was opened, kept on the screen), and its rows.
    pub fn area(&self, (w, h): (f32, f32)) -> (Area, Vec<Area>) {
        let bh = 12.0 + MENU_ROW * self.items.len() as f32;
        let x = self.x.min(w - MENU_W - 8.0).max(8.0);
        let y = self.y.min(h - bh - 8.0).max(8.0);
        let rows =
            (0..self.items.len()).map(|k| Area::new(x + 6.0, y + 6.0 + MENU_ROW * k as f32, MENU_W - 12.0, MENU_ROW));
        (Area::new(x, y, MENU_W, bh), rows.collect())
    }
}

/// What a held left button is doing.
#[derive(Clone, Debug, PartialEq)]
pub enum Press {
    /// On icon `i`, from (x0, y0); dragging the selection once it moved.
    Icon { i: usize, x0: f32, y0: f32, x: f32, y: f32, dragging: bool, mods: bool },
    /// On the wallpaper: a box from (x0, y0) to (x, y); `before` what was
    /// selected with ctrl held, which stays.
    Band { x0: f32, y0: f32, x: f32, y: f32, before: Vec<usize> },
}

/// What the session is to do after an event.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Out {
    pub redraw: bool,
    /// Programs to start: an icon opened, Files' moves and trash.
    pub run: Vec<Vec<String>>,
    /// Icons dropped on a window: their paths, for its app.
    pub drop: Option<Vec<String>>,
}

impl Out {
    fn redraw() -> Out {
        Out { redraw: true, ..Out::default() }
    }

    fn run(cmd: Vec<String>) -> Out {
        Out { redraw: true, run: alloc::vec![cmd], drop: None }
    }
}

/// The desktop's icons.
#[derive(Clone, Debug, Default)]
pub struct Desk {
    /// `~/Desktop`.
    pub dir: String,
    /// `~/.config/strata`.
    config: String,
    pub items: Vec<Item>,
    /// The chosen icons, in the items' order.
    pub selected: Vec<usize>,
    /// The icon the keys are on.
    pub cursor: Option<usize>,
    /// Where icons were put, by file name: (column, row).
    places: BTreeMap<String, (u16, u16)>,
    pub press: Option<Press>,
    pub menu: Option<Menu>,
    /// Renaming icon `i`: the editor, and why the last name was refused.
    pub rename: Option<(usize, LineEdit, Option<String>)>,
    /// The folder icon a drag would drop into.
    pub target: Option<usize>,
    /// A file name to start renaming once it shows (a new folder).
    pending_rename: Option<String>,
    /// The screen's size (logical pixels), where the menu fits.
    pub screen: (f32, f32),
    stamp: i64,
    /// The last click: which icon, when.
    last_click: Option<(usize, i64)>,
}

/// The icon a person's first session puts on the desktop: Files, which
/// opens on their home folder (a copy of its app entry).
const FILES_ENTRY: &str = "# Files, on the desktop from the first session (ADR 0102's third addendum).\n\
name=Files\n\
exec=/bin/files\n\
icon=folder\n\
category=Accessories\n\
comment=Browse and organise your files\n";

/// Marks that the desktop's first icons were put there
/// (`~/.config/strata/`), so they aren't put back once removed.
const SEEDED: &str = "desktop-seeded";

/// What a double click asks for: a program and its arguments.
pub type Open = Vec<String>;

/// Files' command that moves `paths` into `dir`, or with `copy` copies
/// them there.
fn transfer(dir: String, paths: Vec<String>, copy: bool) -> Vec<String> {
    let op = if copy { "--copy-to" } else { "--move-to" };
    let mut cmd = alloc::vec![String::from(FILES), String::from(op), dir];
    cmd.extend(paths);
    cmd
}

/// `text`, an app entry, with its name `name`: a `.app` file's `name=`
/// line, or a `.desktop` file's `Name=` (the first, in its main group).
/// A name line is added when there is none.
pub fn renamed_entry(text: &str, desktop: bool, name: &str) -> String {
    let key = if desktop { "Name=" } else { "name=" };
    let mut out = String::new();
    let mut done = false;
    for line in text.lines() {
        if !done && line.starts_with(key) {
            out.push_str(key);
            out.push_str(name);
            done = true;
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    if !done {
        let at = if desktop { out.find("[Desktop Entry]\n").map(|i| i + 16) } else { Some(0) };
        out.insert_str(at.unwrap_or(out.len()), &alloc::format!("{key}{name}\n"));
    }
    out
}

/// Why `name` can't be a file's name, if it can't.
pub fn bad_name(name: &str) -> Option<&'static str> {
    if name.trim().is_empty() {
        Some("A name can't be empty.")
    } else if name.contains('/') {
        Some("A name can't have a / in it.")
    } else if name == "." || name == ".." {
        Some("That name is taken by the system.")
    } else if name.len() > NAME_MAX {
        Some("That name is too long.")
    } else {
        None
    }
}

impl Desk {
    /// The icons of `home`'s Desktop folder, made if it isn't there, with
    /// Files on it the first time.
    pub fn new(home: &str) -> Desk {
        let home = home.trim_end_matches('/');
        let dir = alloc::format!("{home}/Desktop");
        let _ = fs::mkdir(dir.as_bytes(), 0o755);
        let config = alloc::format!("{home}/.config/strata");
        let seeded = alloc::format!("{config}/{SEEDED}");
        if !home.is_empty() && !fs::exists(seeded.as_bytes()) {
            let files = alloc::format!("{dir}/Files.app");
            if !fs::exists(files.as_bytes()) {
                let _ = fs::write_file(files.as_bytes(), FILES_ENTRY.as_bytes(), 0o644);
            }
            let _ = fs::mkdir(alloc::format!("{home}/.config").as_bytes(), 0o755);
            let _ = fs::mkdir(config.as_bytes(), 0o755);
            if fs::write_file(seeded.as_bytes(), b"", 0o644).is_ok() {
                slate_rt::eprintln!("strata: desktop: Files put on the desktop");
            }
        }
        let mut d = Desk { dir, config, ..Desk::default() };
        d.load_places();
        d.refresh();
        d
    }

    fn places_file(&self) -> String {
        alloc::format!("{}/{POSITIONS}", self.config)
    }

    fn load_places(&mut self) {
        let text = fs::read_file(self.places_file().as_bytes()).unwrap_or_default();
        self.places = String::from(lossy(&text))
            .lines()
            .filter_map(|l| {
                let mut w = l.splitn(3, ' ');
                let (c, r) = (w.next()?.parse().ok()?, w.next()?.parse().ok()?);
                Some((String::from(w.next()?), (c, r)))
            })
            .collect();
    }

    fn save_places(&self) {
        if self.config.is_empty() {
            return;
        }
        let mut text = String::new();
        for (name, (c, r)) in &self.places {
            text.push_str(&alloc::format!("{c} {r} {name}\n"));
        }
        let _ = fs::write_file(self.places_file().as_bytes(), text.as_bytes(), 0o644);
    }

    /// Read the folder again if it changed: whether it did.
    pub fn refresh(&mut self) -> bool {
        let stamp =
            fs::stat(self.dir.as_bytes()).map_or(0, |s| s.mtime.wrapping_mul(1_000_000_007).wrapping_add(s.mtime_nsec));
        if stamp == self.stamp {
            return false;
        }
        self.stamp = stamp;
        let entries = fs::read_dir(self.dir.as_bytes()).unwrap_or_default();
        self.set(
            entries
                .iter()
                .filter(|e| !e.name.starts_with(b"."))
                .filter_map(|e| self.item(&String::from(lossy(&e.name))))
                .collect(),
        );
        slate_rt::eprintln!("strata: desktop: {} icons", self.items.len());
        true
    }

    /// Read the folder now (after a change made here).
    fn reread(&mut self) {
        self.stamp = 0;
        self.refresh();
    }

    /// The icon for `name` in the folder.
    fn item(&self, name: &str) -> Option<Item> {
        let path = alloc::format!("{}/{name}", self.dir);
        // Followed: a link on the desktop shows what it points at.
        let st = fs::stat(path.as_bytes()).ok()?;
        if st.mode & fs::S_IFMT == fs::S_IFDIR {
            return Some(Item { name: String::from(name), path, kind: Kind::Folder, icon: Icon::Folder });
        }
        if name.ends_with(".app") || name.ends_with(".desktop") {
            let text = fs::read_file(path.as_bytes()).ok().filter(|t| t.len() <= 64 * 1024)?;
            let text = String::from(lossy(&text));
            let app =
                if name.ends_with(".app") { launcher::parse_app(&text) } else { launcher::parse_desktop_entry(&text) };
            if let Some(app) = app {
                return Some(Item { name: app.name, path, kind: Kind::App(app.exec), icon: app.icon });
            }
        }
        let kind = Kind::File(fileicon::kind_of(name, st.mode & 0o111 != 0));
        Some(Item { name: String::from(name), icon: Icon::Document, path, kind })
    }

    /// New items: folders first, then by name. The selection, the
    /// cursor and a rename follow their files; a pending rename starts.
    pub fn set(&mut self, mut items: Vec<Item>) {
        items.sort_by(|a, b| {
            (a.kind != Kind::Folder)
                .cmp(&(b.kind != Kind::Folder))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        let path_of = |i: usize| self.items.get(i).map(|it| it.path.clone());
        let chosen: Vec<String> = self.selected.iter().filter_map(|&i| path_of(i)).collect();
        let cursor = self.cursor.and_then(path_of);
        let renaming = self.rename.take().and_then(|(i, e, why)| path_of(i).map(|p| (p, e, why)));
        let at = |p: &str| items.iter().position(|it| it.path == p);
        self.selected = chosen.iter().filter_map(|p| at(p)).collect();
        self.selected.sort_unstable();
        self.cursor = cursor.and_then(|p| at(&p));
        self.rename = renaming.and_then(|(p, e, why)| at(&p).map(|i| (i, e, why)));
        self.items = items;
        self.last_click = None;
        self.press = None;
        if let Some(name) = self.pending_rename.take() {
            match self.items.iter().position(|it| it.file_name() == name) {
                Some(i) => {
                    self.selected = alloc::vec![i];
                    self.cursor = Some(i);
                    self.start_rename(i);
                }
                None => self.pending_rename = Some(name),
            }
        }
    }

    /// The grid's columns and rows on `work`.
    fn grid(work: Area) -> (usize, usize) {
        let cols = floor((work.w - 2.0 * MARGIN) / CELL_W).max(1.0) as usize;
        let rows = floor((work.h - 2.0 * MARGIN) / CELL_H).max(1.0) as usize;
        (cols, rows)
    }

    fn cell_area(work: Area, (c, r): (usize, usize)) -> Area {
        Area::new(work.x + MARGIN + c as f32 * CELL_W, work.y + MARGIN + r as f32 * CELL_H, CELL_W, CELL_H)
    }

    /// The cell at (x, y), held to the grid.
    fn cell_at(work: Area, x: f32, y: f32) -> (usize, usize) {
        let (cols, rows) = Desk::grid(work);
        let c = floor((x - work.x - MARGIN) / CELL_W).max(0.0) as usize;
        let r = floor((y - work.y - MARGIN) / CELL_H).max(0.0) as usize;
        (c.min(cols - 1), r.min(rows - 1))
    }

    /// Each item's cell (column, row): where it was put if that is in the
    /// grid and free, else the next free one, down then across. The last
    /// cell is "more" when some don't fit.
    fn cells_of(&self, work: Area) -> (Vec<Option<(usize, usize)>>, usize) {
        let (cols, rows) = Desk::grid(work);
        let n = cols * rows;
        let mut taken = alloc::vec![false; n];
        let mut out = alloc::vec![None; self.items.len()];
        for (i, it) in self.items.iter().enumerate() {
            if let Some(&(c, r)) = self.places.get(it.file_name()) {
                let (c, r) = (usize::from(c), usize::from(r));
                if c < cols && r < rows && !taken[c * rows + r] {
                    taken[c * rows + r] = true;
                    out[i] = Some((c, r));
                }
            }
        }
        let mut next = 0;
        for slot in out.iter_mut().filter(|s| s.is_none()) {
            while next < n && taken[next] {
                next += 1;
            }
            if next == n {
                break;
            }
            taken[next] = true;
            *slot = Some((next / rows, next % rows));
        }
        let mut left = out.iter().filter(|s| s.is_none()).count();
        if left > 0 {
            let last = ((n - 1) / rows, (n - 1) % rows);
            if let Some(s) = out.iter_mut().find(|s| **s == Some(last)) {
                *s = None;
                left += 1;
            }
        }
        (out, left)
    }

    /// Where the icons are on `work`.
    pub fn layout(&self, work: Area) -> Layout {
        let (cells, left) = self.cells_of(work);
        let (cols, rows) = Desk::grid(work);
        Layout {
            cells: cells.iter().map(|c| c.map(|c| Desk::cell_area(work, c))).collect(),
            more: (left > 0).then(|| (Desk::cell_area(work, (cols - 1, rows - 1)), left)),
        }
    }

    /// The cells of the icons that fit `work`, in the items' order (None
    /// for those that don't).
    pub fn cells(&self, work: Area) -> Vec<Option<Area>> {
        self.layout(work).cells
    }

    /// The icon at (x, y).
    pub fn hit(&self, work: Area, x: f32, y: f32) -> Option<usize> {
        self.cells(work).iter().position(|a| a.is_some_and(|a| a.grow(-4.0).contains(x, y)))
    }

    fn hit_more(&self, work: Area, x: f32, y: f32) -> bool {
        self.layout(work).more.is_some_and(|(a, _)| a.grow(-4.0).contains(x, y))
    }

    fn is_folder(&self, i: usize) -> bool {
        self.items.get(i).is_some_and(|it| it.kind == Kind::Folder)
    }

    fn paths(&self, list: &[usize]) -> Vec<String> {
        list.iter().filter_map(|&i| self.items.get(i)).map(|it| it.path.clone()).collect()
    }

    /// The chosen icons, or the one the keys are on.
    fn chosen(&self) -> Vec<usize> {
        if self.selected.is_empty() { self.cursor.into_iter().collect() } else { self.selected.clone() }
    }

    /// Close the menu, and end a rename as Enter would.
    pub fn dismiss(&mut self) -> bool {
        let had = self.menu.take().is_some() || self.rename.is_some();
        if self.rename.is_some() {
            self.commit_rename();
            // A refused name isn't kept waiting for keys elsewhere.
            self.rename = None;
        }
        had
    }

    /// The left button down at (x, y) on the desktop at `now` (ms), with
    /// ctrl or shift held.
    pub fn press(&mut self, work: Area, x: f32, y: f32, ctrl: bool, shift: bool, now: i64) -> Out {
        if let Some(m) = self.menu.take() {
            return match m.area(self.screen).1.iter().position(|r| r.contains(x, y)) {
                Some(k) => self.act(work, m.items[k].1, (m.x, m.y)),
                None => Out::redraw(),
            };
        }
        if self.rename.is_some() {
            self.commit_rename();
            if self.rename.is_some() {
                return Out::redraw();
            }
        }
        if self.hit_more(work, x, y) {
            return Out::run(alloc::vec![String::from(FILES), self.dir.clone()]);
        }
        let Some(i) = self.hit(work, x, y) else {
            if !ctrl {
                self.selected.clear();
            }
            self.last_click = None;
            self.press = Some(Press::Band { x0: x, y0: y, x, y, before: self.selected.clone() });
            return Out::redraw();
        };
        let double = !ctrl && !shift && self.last_click.is_some_and(|(last, t)| last == i && now - t < DOUBLE_CLICK_MS);
        if double {
            self.last_click = None;
            self.selected = alloc::vec![i];
            return Out::run(self.open(i));
        }
        if ctrl {
            match self.selected.binary_search(&i) {
                Ok(k) => {
                    self.selected.remove(k);
                }
                Err(k) => self.selected.insert(k, i),
            }
        } else if shift {
            let from = self.cursor.filter(|&c| c < self.items.len()).unwrap_or(i);
            self.selected = (from.min(i)..=from.max(i)).collect();
        } else if self.selected.binary_search(&i).is_err() {
            self.selected = alloc::vec![i];
        }
        if !shift {
            self.cursor = Some(i);
        }
        self.last_click = Some((i, now));
        self.press = Some(Press::Icon { i, x0: x, y0: y, x, y, dragging: false, mods: ctrl || shift });
        Out::redraw()
    }

    /// The pointer moved to (x, y) with the button held: whether to draw.
    pub fn motion(&mut self, work: Area, x: f32, y: f32) -> bool {
        let Some(mut press) = self.press.take() else { return false };
        match &mut press {
            Press::Icon { i, x0, y0, x: px, y: py, dragging, .. } => {
                (*px, *py) = (x, y);
                if !*dragging && ((x - *x0).abs() >= DRAG_START || (y - *y0).abs() >= DRAG_START) {
                    *dragging = true;
                    if self.selected.binary_search(i).is_err() {
                        self.selected = alloc::vec![*i];
                    }
                }
                if *dragging {
                    let under = self.hit(work, x, y);
                    self.target = under.filter(|&t| self.is_folder(t) && self.selected.binary_search(&t).is_err());
                }
            }
            Press::Band { x0, y0, x: px, y: py, before } => {
                (*px, *py) = (x, y);
                let band = Area::new(x0.min(x), y0.min(y), (x - *x0).abs(), (y - *y0).abs());
                let mut sel = before.clone();
                for (i, c) in self.cells(work).iter().enumerate() {
                    if c.is_some_and(|c| crate::desktop::overlaps(&c.grow(-8.0), &band)) && !sel.contains(&i) {
                        sel.push(i);
                    }
                }
                sel.sort_unstable();
                self.selected = sel;
            }
        }
        self.press = Some(press);
        true
    }

    /// The button came up at (x, y); `over_window` when a window is there
    /// (the dragged icons are then dropped on it); `copy` with ctrl held
    /// (copied into a folder, or onto the desktop as new icons).
    pub fn release(&mut self, work: Area, x: f32, y: f32, over_window: bool, copy: bool) -> Out {
        let target = self.target.take();
        match self.press.take() {
            Some(Press::Icon { i, dragging: false, mods: false, .. }) => {
                // A plain click on one of several chosen: it alone, now.
                self.selected = alloc::vec![i];
                Out::redraw()
            }
            Some(Press::Icon { i, dragging: true, .. }) => {
                let paths = self.paths(&self.selected);
                if over_window {
                    slate_rt::eprintln!("strata: desktop: {} dropped on a window", paths.len());
                    return Out { redraw: true, run: Vec::new(), drop: Some(paths) };
                }
                if y < work.y {
                    return Out::redraw();
                }
                if let Some(t) = target {
                    let dir = self.items[t].path.clone();
                    let verb = if copy { "copied" } else { "moved" };
                    slate_rt::eprintln!("strata: desktop: {} {verb} into {}", paths.len(), self.items[t].name);
                    return Out::run(transfer(dir, paths, copy));
                }
                if copy {
                    // Copies beside the originals ("name (copy)"), in the
                    // free cells.
                    slate_rt::eprintln!("strata: desktop: {} copied", paths.len());
                    return Out::run(transfer(self.dir.clone(), paths, true));
                }
                self.move_icons(work, i, x, y);
                Out::redraw()
            }
            Some(_) => Out::redraw(),
            None => Out::default(),
        }
    }

    /// The selection moved so that icon `i` is in the cell at (x, y), the
    /// others keeping their places around it; one that would land on
    /// another icon or off the grid takes the nearest free cell. Every
    /// icon's place is kept from now on, so none shifts to make room.
    fn move_icons(&mut self, work: Area, i: usize, x: f32, y: f32) {
        let Some(new) = self.landing(work, i, x, y) else { return };
        for (k, c) in new.iter().enumerate() {
            if let Some((c, r)) = c {
                self.places.insert(String::from(self.items[k].file_name()), (*c as u16, *r as u16));
            }
        }
        self.save_places();
        let to = Desk::cell_at(work, x, y);
        slate_rt::eprintln!("strata: desktop: {} moved to column {}, row {}", self.selected.len(), to.0 + 1, to.1 + 1);
    }

    /// Every icon's cell once the selection is dropped with icon `i` at
    /// (x, y) (see [`Desk::move_icons`]).
    fn landing(&self, work: Area, i: usize, x: f32, y: f32) -> Option<Vec<Option<(usize, usize)>>> {
        let (cols, rows) = Desk::grid(work);
        let (cells, _) = self.cells_of(work);
        let from = cells.get(i).copied().flatten()?;
        let to = Desk::cell_at(work, x, y);
        let (dc, dr) = (to.0 as i64 - from.0 as i64, to.1 as i64 - from.1 as i64);
        let mut taken: Vec<(usize, usize)> =
            cells.iter().enumerate().filter(|(k, _)| !self.selected.contains(k)).filter_map(|(_, c)| *c).collect();
        let mut new = cells.clone();
        for &k in &self.selected {
            let Some((c, r)) = cells[k] else { continue };
            let want = (
                (c as i64 + dc).clamp(0, cols as i64 - 1) as usize,
                (r as i64 + dr).clamp(0, rows as i64 - 1) as usize,
            );
            let at = if taken.contains(&want) {
                let free = (0..cols * rows).map(|n| (n / rows, n % rows)).filter(|p| !taken.contains(p));
                free.min_by_key(|p| (p.0 as i64 - want.0 as i64).pow(2) + (p.1 as i64 - want.1 as i64).pow(2))
            } else {
                Some(want)
            };
            if let Some(at) = at {
                taken.push(at);
                new[k] = Some(at);
            }
        }
        Some(new)
    }

    /// An app's drag over the desktop at (x, y): the folder icon under it
    /// lights. Whether that changed.
    pub fn hover_drop(&mut self, work: Area, x: f32, y: f32) -> bool {
        let t = self.hit(work, x, y).filter(|&t| self.is_folder(t));
        let changed = t != self.target;
        self.target = t;
        changed
    }

    /// Files an app dragged out of its window, dropped on the desktop at
    /// (x, y): into the folder icon there, else onto the desktop, their
    /// icons from the cell under the pointer on (Files moves them, or
    /// with `copy`, copies them).
    pub fn drop_from_app(&mut self, work: Area, x: f32, y: f32, paths: &[String], copy: bool) -> Out {
        self.target = None;
        let dir = match self.hit(work, x, y).filter(|&t| self.is_folder(t)) {
            Some(t) => self.items[t].path.clone(),
            None => {
                let (cols, rows) = Desk::grid(work);
                let (cells, _) = self.cells_of(work);
                let mut taken: Vec<(usize, usize)> = cells.iter().filter_map(|c| *c).collect();
                let start = Desk::cell_at(work, x, y);
                let mut n = start.0 * rows + start.1;
                for p in paths {
                    let name = p.rsplit('/').next().unwrap_or(p);
                    while n < cols * rows && taken.contains(&(n / rows, n % rows)) {
                        n += 1;
                    }
                    if n == cols * rows {
                        break;
                    }
                    taken.push((n / rows, n % rows));
                    self.places.insert(String::from(name), ((n / rows) as u16, (n % rows) as u16));
                }
                self.save_places();
                self.dir.clone()
            }
        };
        let paths: Vec<String> =
            paths.iter().filter(|p| p.rsplit_once('/').map(|(d, _)| d) != Some(dir.as_str())).cloned().collect();
        if paths.is_empty() {
            return Out::redraw();
        }
        let verb = if copy { "copied" } else { "dropped" };
        slate_rt::eprintln!("strata: desktop: {} {verb} from a window into {dir}", paths.len());
        Out::run(transfer(dir, paths, copy))
    }

    /// The right button at (x, y): the menu for the icon there (chosen
    /// with the rest, or alone), or for the desktop.
    pub fn right_click(&mut self, work: Area, x: f32, y: f32) -> Out {
        self.dismiss();
        let items = match self.hit(work, x, y) {
            Some(i) => {
                if self.selected.binary_search(&i).is_err() {
                    self.selected = alloc::vec![i];
                }
                self.cursor = Some(i);
                let mut v = alloc::vec![("Open", Action::Open)];
                if self.selected.len() == 1 {
                    v.push(("Rename", Action::Rename));
                }
                v.push(("Move to Trash", Action::Trash));
                v
            }
            None => {
                self.selected.clear();
                let mut v = alloc::vec![
                    ("New Folder", Action::NewFolder),
                    ("Show the Desktop in Files", Action::ShowInFiles),
                    ("Change Wallpaper", Action::Wallpaper),
                ];
                // The last change on the desktop, to take back (last, so
                // the others keep their places).
                v.extend(crate::undo::last(&self.config).map(|op| (op.label(), Action::Undo)));
                v
            }
        };
        self.menu = Some(Menu { x, y, items, selected: 0 });
        Out::redraw()
    }

    /// Do `a`; (x, y) is where the menu was opened (a new folder goes
    /// there).
    fn act(&mut self, work: Area, a: Action, (x, y): (f32, f32)) -> Out {
        let chosen = self.chosen();
        match a {
            Action::Open => Out { redraw: true, run: chosen.iter().map(|&i| self.open(i)).collect(), drop: None },
            Action::Rename => {
                if let Some(&i) = chosen.first() {
                    self.start_rename(i);
                }
                Out::redraw()
            }
            Action::Trash if !chosen.is_empty() => {
                let paths = self.paths(&chosen);
                slate_rt::eprintln!("strata: desktop: {} to the trash", paths.len());
                self.selected.clear();
                let mut cmd = alloc::vec![String::from(FILES), String::from("--trash")];
                cmd.extend(paths);
                Out::run(cmd)
            }
            Action::Trash => Out::redraw(),
            Action::NewFolder => {
                let mut name = String::from("New Folder");
                let mut n = 2;
                while fs::lstat(alloc::format!("{}/{name}", self.dir).as_bytes()).is_ok() {
                    name = alloc::format!("New Folder {n}");
                    n += 1;
                }
                if let Err(e) = fs::mkdir(alloc::format!("{}/{name}", self.dir).as_bytes(), 0o755) {
                    slate_rt::eprintln!("strata: desktop: can't make a folder: {e:?}");
                    return Out::redraw();
                }
                slate_rt::eprintln!("strata: desktop: made {name}");
                crate::undo::push(&self.config, crate::undo::Op::MadeFolder(alloc::format!("{}/{name}", self.dir)));
                // In the cell the menu was opened on, if it is free.
                let at = Desk::cell_at(work, x, y);
                let (cells, _) = self.cells_of(work);
                if !cells.contains(&Some(at)) {
                    self.places.insert(name.clone(), (at.0 as u16, at.1 as u16));
                    self.save_places();
                }
                self.pending_rename = Some(name);
                self.reread();
                Out::redraw()
            }
            Action::ShowInFiles => Out::run(alloc::vec![String::from(FILES), self.dir.clone()]),
            Action::Wallpaper => Out::run(alloc::vec![String::from(SETTINGS)]),
            Action::Undo => {
                slate_rt::eprintln!("strata: desktop: undo");
                Out::run(alloc::vec![String::from(FILES), String::from("--undo")])
            }
        }
    }

    /// Start renaming icon `i`: a file's name with its extension left
    /// out of the selection, an app's own name.
    pub fn start_rename(&mut self, i: usize) {
        let Some(it) = self.items.get(i) else { return };
        let (text, stem) = match &it.kind {
            Kind::App(_) => (it.name.clone(), None),
            Kind::Folder => (String::from(it.file_name()), None),
            Kind::File(_) => {
                let name = it.file_name();
                let stem = name.rfind('.').filter(|&d| d > 0).map(|d| name[..d].chars().count());
                (String::from(name), stem)
            }
        };
        let mut e = LineEdit::new(&text);
        match stem {
            Some(n) => {
                e.place(0, false);
                e.place(n, true);
            }
            None => e.select_all(),
        }
        self.menu = None;
        self.rename = Some((i, e, None));
    }

    /// Take the name typed: the file renamed (an app entry's name line
    /// rewritten), or the reason it can't be, the field staying open.
    pub fn commit_rename(&mut self) {
        let Some((i, e, _)) = self.rename.take() else { return };
        let Some(it) = self.items.get(i).cloned() else { return };
        let new = e.text();
        if let Some(why) = bad_name(&new) {
            self.rename = Some((i, e, Some(String::from(why))));
            return;
        }
        if let Kind::App(_) = it.kind {
            if new != it.name {
                let text = fs::read_file(it.path.as_bytes()).map(|t| String::from(lossy(&t))).unwrap_or_default();
                let out = renamed_entry(&text, it.path.ends_with(".desktop"), &new);
                match fs::write_file(it.path.as_bytes(), out.as_bytes(), 0o644) {
                    Ok(()) => slate_rt::eprintln!("strata: desktop: {} renamed {new}", it.name),
                    Err(err) => slate_rt::eprintln!("strata: desktop: can't rename {}: {err:?}", it.name),
                }
                self.reread();
            }
            return;
        }
        let old = String::from(it.file_name());
        if new == old {
            return;
        }
        let to = alloc::format!("{}/{new}", self.dir);
        if fs::lstat(to.as_bytes()).is_ok() {
            self.rename = Some((i, e, Some(alloc::format!("There's already something called {new} here."))));
            return;
        }
        match fs::rename(it.path.as_bytes(), to.as_bytes()) {
            Ok(()) => {
                slate_rt::eprintln!("strata: desktop: {old} renamed {new}");
                crate::undo::push(&self.config, crate::undo::Op::Renamed(it.path.clone(), to.clone()));
                if let Some(at) = self.places.remove(&old) {
                    self.places.insert(new.clone(), at);
                    self.save_places();
                }
                // The selection follows the file to its new name.
                self.items[i].path = to;
                self.reread();
            }
            Err(err) => {
                let why = alloc::format!("Couldn't rename it: {err:?}");
                self.rename = Some((i, e, Some(why)));
            }
        }
    }

    /// A key while the desktop has the keyboard (no window focused):
    /// its evdev code, its character, and whether shift and ctrl are
    /// held.
    pub fn key(&mut self, work: Area, code: u16, ch: Option<char>, shift: bool, ctrl: bool) -> Out {
        if self.rename.is_some() {
            match code {
                KEY_ENTER | KEY_KPENTER => self.commit_rename(),
                KEY_ESC => self.rename = None,
                _ => return self.rename_key(code, ch, shift, ctrl),
            }
            return Out::redraw();
        }
        if let Some(m) = self.menu.as_mut() {
            match code {
                KEY_UP => m.selected = (m.selected + m.items.len() - 1) % m.items.len(),
                KEY_DOWN | KEY_TAB => m.selected = (m.selected + 1) % m.items.len(),
                KEY_ENTER | KEY_KPENTER | KEY_SPACE => {
                    let (a, at) = (m.items[m.selected].1, (m.x, m.y));
                    self.menu = None;
                    return self.act(work, a, at);
                }
                KEY_ESC => self.menu = None,
                _ => return Out::default(),
            }
            return Out::redraw();
        }
        let layout = self.layout(work);
        let first = (0..self.items.len()).find(|&i| layout.cells[i].is_some());
        match code {
            KEY_LEFT | KEY_RIGHT | KEY_UP | KEY_DOWN | KEY_HOME | KEY_END => {
                let next = match (self.cursor.filter(|&c| layout.cells.get(c).is_some_and(Option::is_some)), code) {
                    (_, KEY_HOME) | (None, _) => first,
                    (_, KEY_END) => (0..self.items.len()).rev().find(|&i| layout.cells[i].is_some()),
                    (Some(c), _) => Desk::neighbour(&layout, c, code).or(Some(c)),
                };
                let Some(n) = next else { return Out::default() };
                self.cursor = Some(n);
                if shift {
                    if let Err(k) = self.selected.binary_search(&n) {
                        self.selected.insert(k, n);
                    }
                } else if !ctrl {
                    self.selected = alloc::vec![n];
                }
                Out::redraw()
            }
            KEY_SPACE if ctrl => {
                if let Some(c) = self.cursor {
                    match self.selected.binary_search(&c) {
                        Ok(k) => {
                            self.selected.remove(k);
                        }
                        Err(k) => self.selected.insert(k, c),
                    }
                }
                Out::redraw()
            }
            KEY_ENTER | KEY_KPENTER => self.act(work, Action::Open, (0.0, 0.0)),
            KEY_F2 => self.act(work, Action::Rename, (0.0, 0.0)),
            KEY_DELETE => self.act(work, Action::Trash, (0.0, 0.0)),
            KEY_A if ctrl => {
                self.selected = (0..self.items.len()).collect();
                Out::redraw()
            }
            // By the character, so the layout's own z.
            _ if ctrl && matches!(ch, Some('z' | 'Z')) => self.act(work, Action::Undo, (0.0, 0.0)),
            KEY_ESC => {
                self.selected.clear();
                Out::redraw()
            }
            KEY_COMPOSE | KEY_F10 if code == KEY_COMPOSE || shift => {
                // The menu at the icon the keys are on, or the grid's corner.
                let at = self.cursor.and_then(|c| layout.cells.get(c).copied().flatten());
                let (x, y) =
                    at.map_or((work.x + MARGIN + 8.0, work.y + MARGIN + 8.0), |a| (a.x + a.w / 2.0, a.y + a.h / 2.0));
                if self.cursor.is_some() && self.selected.is_empty() {
                    self.selected = self.cursor.into_iter().collect();
                }
                let keep = self.selected.clone();
                let out = self.right_click(work, x, y);
                if at.is_some() {
                    self.selected = keep;
                }
                out
            }
            _ => Out::default(),
        }
    }

    /// A key while renaming: the editor's moves and edits, and typing.
    fn rename_key(&mut self, code: u16, ch: Option<char>, shift: bool, ctrl: bool) -> Out {
        let Some((_, e, why)) = self.rename.as_mut() else { return Out::default() };
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
        match (k, ch) {
            (Some(k), _) => {
                e.key(k, shift, ctrl);
            }
            (None, Some(c)) if !ctrl && !c.is_control() => {
                e.insert(c.encode_utf8(&mut [0; 4]));
            }
            _ => return Out::default(),
        }
        *why = None;
        Out::redraw()
    }

    /// The icon beside `c` in the direction of arrow `code`: the nearest
    /// whose cell is that way, straight lines first.
    fn neighbour(layout: &Layout, c: usize, code: u16) -> Option<usize> {
        let at = layout.cells[c]?;
        let mut best: Option<(f32, usize)> = None;
        for (j, a) in layout.cells.iter().enumerate() {
            let Some(a) = a.filter(|_| j != c) else { continue };
            let (dx, dy) = (a.x - at.x, a.y - at.y);
            let (ahead, aside) = match code {
                KEY_RIGHT => (dx, dy),
                KEY_LEFT => (-dx, dy),
                KEY_DOWN => (dy, dx),
                _ => (-dy, dx),
            };
            if ahead <= 0.0 {
                continue;
            }
            let score = ahead + 3.0 * aside.abs();
            if best.is_none_or(|(s, _)| score < s) {
                best = Some((score, j));
            }
        }
        best.map(|(_, j)| j)
    }

    /// What opens icon `i`.
    pub fn open(&self, i: usize) -> Open {
        let it = &self.items[i];
        let s = |t: &str| String::from(t);
        match &it.kind {
            Kind::Folder => alloc::vec![s(FILES), it.path.clone()],
            Kind::App(exec) => exec.split(' ').filter(|w| !w.is_empty()).map(String::from).collect(),
            Kind::File(_) => alloc::vec![s(FILES), s("--open"), it.path.clone()],
        }
    }

    /// Where the dragged icons would land, and how far the pointer has
    /// taken them: (the cells, dx, dy), while dragging over the desktop.
    pub fn dragged(&self, work: Area) -> Option<(Vec<Area>, f32, f32)> {
        let Some(Press::Icon { i, x0, y0, x, y, dragging: true, .. }) = &self.press else { return None };
        let new = self.landing(work, *i, *x, *y)?;
        let cells =
            self.selected.iter().filter_map(|&k| new.get(k).copied().flatten()).map(|c| Desk::cell_area(work, c));
        Some((cells.collect(), x - x0, y - y0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;

    fn scratch(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("slate-desk-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }

    /// A 400 x 800 screen below a 32 px bar: 3 columns of 7 rows.
    const WORK: Area = Area { x: 0.0, y: 32.0, w: 400.0, h: 768.0 };

    /// The middle of cell (c, r).
    fn at(c: usize, r: usize) -> (f32, f32) {
        let a = Desk::cell_area(WORK, (c, r));
        (a.x + a.w / 2.0, a.y + a.h / 2.0)
    }

    fn names(d: &Desk) -> Vec<&str> {
        d.items.iter().map(|i| i.name.as_str()).collect()
    }

    #[test]
    fn icons_and_clicks() {
        let home = scratch("icons");
        let d = Desk::new(&home);
        let dir = format!("{home}/Desktop");
        // The folder is made, with Files on it: it opens the home folder.
        assert_eq!(d.items.len(), 1);
        assert_eq!((d.items[0].name.as_str(), d.items[0].icon), ("Files", Icon::Folder));
        assert_eq!(d.open(0), [String::from("/bin/files")]);
        // Taken away, it stays away.
        std::fs::remove_file(format!("{dir}/Files.app")).unwrap();
        let mut d = Desk::new(&home);
        d.reread();
        assert!(d.items.is_empty());
        std::fs::create_dir(format!("{dir}/Projects")).unwrap();
        std::fs::write(format!("{dir}/notes.txt"), b"hi").unwrap();
        std::fs::write(format!("{dir}/beach.PNG"), b"").unwrap();
        std::fs::write(format!("{dir}/.hidden"), b"").unwrap();
        std::fs::write(format!("{dir}/calc.app"), b"name=Calculator\nexec=/bin/calculator\nicon=calculator\n").unwrap();
        // The directory's time may not have moved within the same tick.
        d.reread();
        assert_eq!(names(&d), ["Projects", "beach.PNG", "Calculator", "notes.txt"]);
        assert_eq!(d.items[1].kind, Kind::File(fileicon::Kind::Picture));
        assert_eq!(d.items[3].kind, Kind::File(fileicon::Kind::Text));
        assert!(!d.refresh(), "nothing changed");
        // One click selects; a second soon after opens.
        let click = |d: &mut Desk, i: usize, t: i64| {
            let (x, y) = at(0, i);
            let out = d.press(WORK, x, y, false, false, t);
            d.release(WORK, x, y, false, false);
            out.run
        };
        assert!(click(&mut d, 0, 1000).is_empty());
        assert_eq!(d.selected, [0]);
        assert_eq!(click(&mut d, 0, 1200), [alloc::vec![String::from("/bin/files"), format!("{dir}/Projects")]]);
        // Too slow, or another icon: only a selection.
        assert!(click(&mut d, 2, 2000).is_empty());
        assert!(click(&mut d, 2, 2500).is_empty());
        assert!(click(&mut d, 3, 2600).is_empty());
        assert_eq!(d.selected, [3]);
        assert_eq!(click(&mut d, 3, 2700)[0][..2], [String::from("/bin/files"), String::from("--open")]);
        assert_eq!(d.open(2), [String::from("/bin/calculator")]);
        // ctrl adds and takes away, shift takes a run.
        let (x, y) = at(0, 0);
        d.press(WORK, x, y, true, false, 4000);
        d.release(WORK, x, y, false, false);
        assert_eq!(d.selected, [0, 3]);
        let (x, y) = at(0, 2);
        d.press(WORK, x, y, false, true, 4100);
        d.release(WORK, x, y, false, false);
        assert_eq!(d.selected, [0, 1, 2]);
        // The empty desktop takes the selection away.
        let (x, y) = at(2, 6);
        d.press(WORK, x, y, false, false, 5000);
        d.release(WORK, x, y, false, false);
        assert!(d.selected.is_empty());
        // A box dragged over the wallpaper selects what it touches.
        let ((x0, y0), (x1, y1)) = (at(1, 0), at(0, 1));
        d.press(WORK, x0, y0, false, false, 6000);
        d.motion(WORK, x1, y1);
        d.release(WORK, x1, y1, false, false);
        assert_eq!(d.selected, [0, 1]);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn dragging_places_and_drops() {
        let home = scratch("drag");
        let dir = format!("{home}/Desktop");
        std::fs::create_dir_all(format!("{dir}/Projects")).unwrap();
        for n in ["a.txt", "b.txt", "c.txt"] {
            std::fs::write(format!("{dir}/{n}"), b"x").unwrap();
        }
        let mut d = Desk::new(&home);
        std::fs::remove_file(format!("{dir}/Files.app")).unwrap();
        d.reread();
        assert_eq!(names(&d), ["Projects", "a.txt", "b.txt", "c.txt"]);
        let drag = |d: &mut Desk, (x0, y0): (f32, f32), (x, y): (f32, f32), window: bool| {
            d.press(WORK, x0, y0, false, false, 0);
            d.motion(WORK, x0 + 10.0, y0);
            d.motion(WORK, x, y);
            d.release(WORK, x, y, window, false)
        };
        // a.txt to the third column: kept there, the others stay put.
        drag(&mut d, at(0, 1), at(2, 3), false);
        let cells = d.cells(WORK);
        assert_eq!(cells[1], Some(Desk::cell_area(WORK, (2, 3))));
        assert_eq!(cells[2], Some(Desk::cell_area(WORK, (0, 2))));
        let saved = std::fs::read_to_string(format!("{home}/.config/strata/desktop-positions")).unwrap();
        assert!(saved.contains("2 3 a.txt\n"), "{saved}");
        // Read again, the places hold.
        let d2 = Desk::new(&home);
        assert_eq!(d2.cells(WORK)[1], Some(Desk::cell_area(WORK, (2, 3))));
        // Onto another icon: the nearest free cell.
        drag(&mut d, at(0, 2), at(1, 3), false);
        assert_eq!(d.cells(WORK)[2], Some(Desk::cell_area(WORK, (1, 3))));
        drag(&mut d, at(1, 3), at(2, 3), false);
        let b = d.cells(WORK)[2].unwrap();
        assert_ne!(b, Desk::cell_area(WORK, (2, 3)));
        assert!((b.x - Desk::cell_area(WORK, (2, 3)).x).abs() <= CELL_W && (b.y - 32.0 - 12.0) / CELL_H >= 2.0);
        // Onto the folder: into it, through Files.
        let out = drag(&mut d, at(0, 3), at(0, 0), false);
        assert_eq!(
            out.run,
            [alloc::vec![
                String::from("/bin/files"),
                String::from("--move-to"),
                format!("{dir}/Projects"),
                format!("{dir}/c.txt")
            ]]
        );
        // With ctrl held, copies: into the folder, or beside the originals.
        // (Seconds apart, so two presses on one icon aren't a double click.)
        let copy = |d: &mut Desk, (x0, y0): (f32, f32), (x, y): (f32, f32), t: i64| {
            d.press(WORK, x0, y0, false, false, t);
            d.motion(WORK, x0 + 10.0, y0);
            d.motion(WORK, x, y);
            d.release(WORK, x, y, false, true)
        };
        let out = copy(&mut d, at(2, 3), at(0, 0), -10_000);
        assert_eq!(out.run[0][1..3], [String::from("--copy-to"), format!("{dir}/Projects")]);
        let out = copy(&mut d, at(2, 3), at(1, 6), -5_000);
        assert_eq!(out.run[0][1..], [String::from("--copy-to"), dir.clone(), format!("{dir}/a.txt")]);
        assert_eq!(d.cells(WORK)[1], Some(Desk::cell_area(WORK, (2, 3))), "the original stays put");
        // Onto a window: for its app.
        let out = drag(&mut d, at(2, 3), (200.0, 400.0), true);
        assert_eq!(out.drop, Some(alloc::vec![format!("{dir}/a.txt")]));
        // From an app onto the folder, and onto the desktop at a cell.
        assert!(d.hover_drop(WORK, at(0, 0).0, at(0, 0).1));
        assert_eq!(d.target, Some(0));
        let out = d.drop_from_app(WORK, at(0, 0).0, at(0, 0).1, &[String::from("/tmp/x.txt")], false);
        assert_eq!(out.run[0][2], format!("{dir}/Projects"));
        let out = d.drop_from_app(WORK, at(1, 5).0, at(1, 5).1, &[String::from("/tmp/y.txt")], false);
        assert_eq!(out.run[0][2..], [dir.clone(), String::from("/tmp/y.txt")]);
        let out = d.drop_from_app(WORK, at(1, 5).0, at(1, 5).1, &[String::from("/tmp/z.txt")], true);
        assert_eq!(out.run[0][1], "--copy-to");
        std::fs::write(format!("{dir}/y.txt"), b"y").unwrap();
        d.reread();
        let y = d.items.iter().position(|i| i.name == "y.txt").unwrap();
        assert_eq!(d.cells(WORK)[y], Some(Desk::cell_area(WORK, (1, 5))));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn menus_keys_and_renames() {
        let home = scratch("keys");
        let dir = format!("{home}/Desktop");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(format!("{dir}/notes.txt"), b"x").unwrap();
        let mut d = Desk::new(&home);
        assert_eq!(names(&d), ["Files", "notes.txt"]);
        // The keys: down to notes.txt, F2, a new name, Enter.
        d.key(WORK, KEY_DOWN, None, false, false);
        assert_eq!(d.cursor, Some(0));
        d.key(WORK, KEY_DOWN, None, false, false);
        assert_eq!((d.cursor, d.selected.as_slice()), (Some(1), &[1][..]));
        d.key(WORK, KEY_F2, None, false, false);
        let (_, e, _) = d.rename.as_ref().unwrap();
        assert_eq!(e.selected_text().as_deref(), Some("notes"));
        for c in "plans".chars() {
            d.key(WORK, 0, Some(c), false, false);
        }
        d.key(WORK, KEY_ENTER, None, false, false);
        assert!(d.rename.is_none());
        assert_eq!(names(&d), ["Files", "plans.txt"]);
        assert_eq!(d.selected, [1]);
        // A name that is taken is refused, the field kept.
        std::fs::write(format!("{dir}/taken.txt"), b"t").unwrap();
        d.reread();
        let i = d.items.iter().position(|i| i.name == "plans.txt").unwrap();
        d.start_rename(i);
        d.key(WORK, KEY_A, Some('a'), false, true);
        for c in "taken.txt".chars() {
            d.key(WORK, 0, Some(c), false, false);
        }
        d.key(WORK, KEY_ENTER, None, false, false);
        assert!(d.rename.as_ref().is_some_and(|r| r.2.is_some()));
        d.key(WORK, KEY_ESC, None, false, false);
        assert!(d.rename.is_none());
        // An app's rename is its entry's name.
        d.start_rename(0);
        d.key(WORK, KEY_A, Some('a'), false, true);
        for c in "My Files".chars() {
            d.key(WORK, 0, Some(c), false, false);
        }
        d.key(WORK, KEY_ENTER, None, false, false);
        assert_eq!(d.items[0].name, "My Files");
        assert!(std::fs::read_to_string(format!("{dir}/Files.app")).unwrap().contains("\nname=My Files\n"));
        // Delete: through Files' trash.
        d.key(WORK, KEY_A, Some('a'), false, true);
        let out = d.key(WORK, KEY_DELETE, None, false, false);
        assert_eq!(out.run[0][..2], [String::from("/bin/files"), String::from("--trash")]);
        assert_eq!(out.run[0].len(), 2 + 3);
        // The wallpaper's menu: a new folder, renamed at once; the rename
        // to take back is last.
        let (x, y) = at(2, 2);
        d.right_click(WORK, x, y);
        assert_eq!(d.menu.as_ref().unwrap().items[0], ("New Folder", Action::NewFolder));
        assert_eq!(d.menu.as_ref().unwrap().items[3], ("Undo Rename", Action::Undo));
        d.key(WORK, KEY_ENTER, None, false, false);
        let i = d.items.iter().position(|i| i.name == "New Folder").unwrap();
        assert_eq!(d.cells(WORK)[i], Some(Desk::cell_area(WORK, (2, 2))));
        assert_eq!(d.rename.as_ref().map(|r| r.0), Some(i));
        d.key(WORK, KEY_ENTER, None, false, false);
        // An icon's menu by its key: Open, Rename, Move to Trash.
        d.key(WORK, KEY_COMPOSE, None, false, false);
        let m = d.menu.as_ref().unwrap();
        assert_eq!(m.items.iter().map(|i| i.0).collect::<Vec<_>>(), ["Open", "Rename", "Move to Trash"]);
        d.key(WORK, KEY_ESC, None, false, false);
        assert!(d.menu.is_none());
        // The journal has the rename and the new folder; ctrl + z asks
        // Files to take the last back.
        let ops = crate::undo::parse(
            &std::fs::read_to_string(format!("{home}/.config/strata/{}", crate::undo::FILE)).unwrap(),
        );
        assert_eq!(
            ops,
            [
                crate::undo::Op::Renamed(format!("{dir}/notes.txt"), format!("{dir}/plans.txt")),
                crate::undo::Op::MadeFolder(format!("{dir}/New Folder")),
            ]
        );
        let out = d.key(WORK, 0, Some('z'), false, true);
        assert_eq!(out.run, [alloc::vec![String::from("/bin/files"), String::from("--undo")]]);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn cells_and_more() {
        let mut d = Desk::default();
        let item = |n: usize| Item {
            name: format!("{n:02}"),
            path: format!("/d/{n:02}"),
            kind: Kind::File(fileicon::Kind::Text),
            icon: Icon::Document,
        };
        d.set((0..40).map(item).collect());
        let l = d.layout(WORK);
        assert_eq!(l.cells[0], Some(Area::new(12.0, 44.0, CELL_W, CELL_H)));
        assert_eq!(l.cells[7].unwrap().x, 12.0 + CELL_W);
        assert_eq!(l.cells[7].unwrap().y, 44.0);
        // 21 cells: 20 icons and "20 more" in the last.
        assert_eq!(l.cells.iter().filter(|c| c.is_some()).count(), 20);
        assert_eq!(l.more, Some((Desk::cell_area(WORK, (2, 6)), 20)));
        assert_eq!(d.hit(WORK, 20.0, 50.0), Some(0));
        assert_eq!(d.hit(WORK, 20.0 + CELL_W, 50.0 + CELL_H), Some(8));
        assert_eq!(d.hit(WORK, 390.0, 50.0), None);
        let (x, y) = at(2, 6);
        let out = d.press(WORK, x, y, false, false, 0);
        assert_eq!(out.run, [alloc::vec![String::from("/bin/files"), String::new()]]);
    }

    #[test]
    fn entries_renamed() {
        assert_eq!(
            renamed_entry("# x\nname=Files\nexec=/bin/files\n", false, "Mine"),
            "# x\nname=Mine\nexec=/bin/files\n"
        );
        assert_eq!(
            renamed_entry("[Desktop Entry]\nType=Application\nName=Firefox\nName[de]=Firefox\n", true, "Web"),
            "[Desktop Entry]\nType=Application\nName=Web\nName[de]=Firefox\n"
        );
        assert_eq!(renamed_entry("[Desktop Entry]\nExec=x\n", true, "X"), "[Desktop Entry]\nName=X\nExec=x\n");
        assert_eq!(bad_name("a/b"), Some("A name can't have a / in it."));
        assert_eq!(bad_name(" "), Some("A name can't be empty."));
        assert_eq!(bad_name("ok.txt"), None);
    }
}
