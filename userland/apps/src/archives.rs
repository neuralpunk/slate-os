// SPDX-License-Identifier: MIT OR Apache-2.0

//! Archive Manager (ADR 0106), `archive-manager`:
//!
//! - `archive-manager ARCHIVE` looks into a zip, tar, tar.gz, cpio or
//!   gzip archive: up and down choose, Enter opens a folder, Backspace
//!   goes back up; `x` extracts what is chosen and `e` everything, into
//!   a new folder beside the archive.
//! - `archive-manager PATH...` (folders or files) makes an archive of
//!   them beside the first: Tab chooses zip, tar.gz or tar, the name can
//!   be edited, Enter makes it.
//!
//! What it reads, extracts and makes is [`crate::archive`].

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_display::input::{
    KEY_BACKSPACE, KEY_DELETE, KEY_DOWN, KEY_END, KEY_ENTER, KEY_ESC, KEY_HOME, KEY_KPENTER, KEY_LEFT, KEY_RIGHT,
    KEY_TAB, KEY_UP,
};
use slate_strata::fonts::Fonts;
use slate_strata_client::mods::{ALT, CTRL, LOGO, SHIFT};
use slate_ui::edit::{EditKey, LineEdit};
use slate_ui::graphite::Palette;
use slate_ui::icon::Icon;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;

use crate::archive::{Archive, Kind, free_name};
use crate::kit::{self, App, Effect, Hints};

const MAKE_KINDS: [Kind; 3] = [Kind::Zip, Kind::TarGz, Kind::Tar];

#[derive(Debug)]
pub enum Mode {
    /// Looking into an archive (its path), in a folder inside it.
    Browse { path: String, archive: Archive, dir: String, selected: usize, first: usize },
    /// Making an archive of these paths.
    Make { paths: Vec<String>, kind: usize, name: LineEdit },
    /// It couldn't be opened: why.
    Failed(String),
}

#[derive(Debug)]
pub struct Manager {
    pub mode: Mode,
    /// What the last action did.
    pub status: String,
    rows: Vec<Area>,
    make_button: Option<Area>,
    kind_chips: Vec<Area>,
}

/// Where a path's folder is.
fn folder_of(path: &str) -> &str {
    match path.trim_end_matches('/').rsplit_once('/') {
        Some(("", _)) => "/",
        Some((d, _)) => d,
        None => ".",
    }
}

fn base(path: &str) -> &str {
    path.trim_end_matches('/').rsplit('/').next().unwrap_or(path)
}

impl Manager {
    pub fn new(mode: Mode) -> Manager {
        Manager { mode, status: String::new(), rows: Vec::new(), make_button: None, kind_chips: Vec::new() }
    }

    /// Open `path` as an archive.
    pub fn open(path: &str) -> Manager {
        let mode = match slate_rt::fs::read_file(path.as_bytes()) {
            Ok(data) => match Archive::open(path, data) {
                Ok(archive) => {
                    Mode::Browse { path: path.to_string(), archive, dir: String::new(), selected: 0, first: 0 }
                }
                Err(e) => Mode::Failed(e),
            },
            Err(e) => Mode::Failed(alloc::format!("{path}: {e}")),
        };
        Manager::new(mode)
    }

    /// Make an archive of `paths`.
    pub fn make(paths: Vec<String>) -> Manager {
        let name = if paths.len() == 1 { base(&paths[0]).to_string() } else { String::from("archive") };
        Manager::new(Mode::Make { paths, kind: 0, name: LineEdit::new(&name).with_max(200) })
    }

    fn extract(&mut self, all: bool) -> Effect {
        let Mode::Browse { path, archive, dir, selected, .. } = &self.mode else { return Effect::None };
        let entries = archive.list(dir);
        let which: Vec<usize> = if all {
            Vec::new()
        } else {
            let Some((name, folder, _, _)) = entries.get(*selected) else { return Effect::None };
            let prefix = alloc::format!("{dir}{name}");
            archive
                .items
                .iter()
                .enumerate()
                .filter(|(_, it)| {
                    crate::archive::safe_path(&it.path)
                        .is_some_and(|p| if *folder { p.starts_with(&prefix) } else { p == prefix })
                })
                .map(|(i, _)| i)
                .collect()
        };
        if !all && which.is_empty() {
            return Effect::None;
        }
        self.status = match archive.extract(path, folder_of(path), &which) {
            Ok(r) => {
                crate::trace!("archive-manager: extracted {} files to {}", r.files, r.dest);
                let mut s = alloc::format!(
                    "Extracted {} file{} to {}.",
                    r.files,
                    if r.files == 1 { "" } else { "s" },
                    base(&r.dest)
                );
                if !r.skipped.is_empty() {
                    s.push_str(&alloc::format!(" Skipped {}: {}.", r.skipped.len(), r.skipped[0].1));
                }
                s
            }
            Err(e) => alloc::format!("Couldn't extract: {e}"),
        };
        Effect::Redraw
    }

    fn create(&mut self) -> Effect {
        let Mode::Make { paths, kind, name } = &self.mode else { return Effect::None };
        let k = MAKE_KINDS[*kind];
        let stem = name.text();
        let stem = stem.trim();
        if stem.is_empty() || stem.contains('/') {
            self.status = String::from("Give it a name (without a /).");
            return Effect::Redraw;
        }
        let Some(first) = paths.first() else { return Effect::None };
        let out = free_name(folder_of(first), stem, k.extension());
        self.status = match crate::archive::make(k, paths).and_then(|d| {
            slate_rt::fs::write_file(out.as_bytes(), &d, 0o644).map(|_| d.len()).map_err(|e| alloc::format!("{e}"))
        }) {
            Ok(n) => {
                crate::trace!("archive-manager: made {out} ({n} bytes)");
                alloc::format!("Made {} ({}).", base(&out), crate::help::size(n as u64))
            }
            Err(e) => alloc::format!("Couldn't make it: {e}"),
        };
        Effect::Redraw
    }
}

impl App for Manager {
    /// Files dropped on the window (ADR 0156's addendum): an archive
    /// opens; anything else is to be made into one (added to the one being
    /// made).
    fn dropped(&mut self, _x: f32, _y: f32, paths: &[String], _copy: bool) -> Effect {
        if let [p] = paths
            && crate::archive::is_archive(base(p))
        {
            crate::trace!("archives: {} dropped", base(p));
            *self = Manager::open(p);
            return Effect::Redraw;
        }
        if let Mode::Make { paths: making, .. } = &mut self.mode {
            for p in paths {
                if !making.contains(p) {
                    making.push(p.clone());
                }
            }
        } else if !paths.is_empty() {
            *self = Manager::make(paths.to_vec());
        }
        crate::trace!("archives: {} dropped to make an archive", paths.len());
        Effect::Redraw
    }

    fn draw(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area) {
        self.rows.clear();
        self.kind_chips.clear();
        self.make_button = None;
        let pad = 20.0;
        let (x, w) = (a.x + pad, a.w - 2.0 * pad);
        let mut y = a.y + 18.0;
        let title = p.style(&f.medium, 15.0, pal.chalk);
        let desc = p.style(&f.regular, 12.5, pal.muted);
        let name_s = p.style(&f.medium, 14.0, pal.text_1);
        let mono = p.style(&f.mono, 12.0, pal.text_3);
        let label = p.style(&f.mono, 11.0, pal.muted);
        match &mut self.mode {
            Mode::Failed(e) => {
                p.line(&title, x, y, 22.0, "Can't open this archive");
                p.line(&desc, x, y + 28.0, 18.0, e);
            }
            Mode::Browse { path, archive, dir, selected, first } => {
                p.icon(Icon::Archive, x, y + 2.0, 18.0, pal.text_3);
                p.line(&title, x + 28.0, y, 22.0, base(path));
                let summary = alloc::format!(
                    "{} · {} items · {}",
                    archive.kind.name(),
                    archive.items.len(),
                    crate::help::size(archive.total())
                );
                p.line(&desc, x + 28.0, y + 24.0, 18.0, &summary);
                y += 56.0;
                let crumb = if dir.is_empty() { String::from("/") } else { alloc::format!("/{dir}") };
                p.line(&label, x, y, 16.0, &crumb);
                y += 24.0;
                let entries = archive.list(dir);
                let row_h = 40.0;
                let room = ((a.y + a.h - 70.0 - y) / row_h).max(1.0) as usize;
                if *selected < *first {
                    *first = *selected;
                } else if *selected >= *first + room {
                    *first = *selected + 1 - room;
                }
                if entries.is_empty() {
                    p.line(&desc, x, y + 8.0, 20.0, "This folder is empty.");
                }
                for (i, (n, folder, size, item)) in entries.iter().enumerate().skip(*first).take(room) {
                    let r = Area::new(x - 10.0, y, w + 20.0, row_h - 4.0);
                    if i == *selected {
                        p.fill(r, 8.0, pal.raised);
                    }
                    p.icon(if *folder { Icon::Folder } else { Icon::Letter }, x, y + 9.0, 18.0, pal.text_3);
                    p.line(&name_s, x + 30.0, y + 8.0, 20.0, n.trim_end_matches('/'));
                    if !*folder {
                        let s = match item.map(|i| &archive.items[i].what) {
                            Some(crate::archive::What::Link(t)) => alloc::format!("-> {t}"),
                            _ => crate::help::size(*size),
                        };
                        let sw = p.measure(&mono, &s);
                        p.line(&mono, x + w - sw, y + 9.0, 18.0, &s);
                    }
                    self.rows.push(r);
                    y += row_h;
                }
                kit::hints(
                    p,
                    pal,
                    f,
                    a,
                    &[("enter", "open"), ("backspace", "up"), ("x", "extract"), ("e", "extract all")],
                );
            }
            Mode::Make { paths, kind, name } => {
                p.line(&title, x, y, 22.0, "Make an archive");
                let what = if paths.len() == 1 {
                    alloc::format!("of {}", base(&paths[0]))
                } else {
                    alloc::format!("of {} items", paths.len())
                };
                p.line(&desc, x, y + 26.0, 18.0, &what);
                y += 64.0;
                p.line(&label, x, y, 16.0, "name");
                y += 22.0;
                let field = Area::new(x, y, w, 40.0);
                p.fill(field, 8.0, pal.well);
                p.border(field, 8.0, 1.0, pal.field_focus);
                let mut typed = p.style(&f.regular, 14.0, pal.text_1);
                typed.ligatures = false;
                let text = name.text();
                let caret_x = {
                    let before: String = text.chars().take(name.caret()).collect();
                    p.measure(&typed, &before)
                };
                let end = p.line(&typed, x + 12.0, y + 10.0, 20.0, &text);
                let ext = MAKE_KINDS[*kind].extension();
                p.line(&desc, x + 14.0 + end, y + 11.0, 18.0, ext);
                p.fill(Area::new(x + 12.0 + caret_x, y + 10.0, 1.5, 20.0), 0.0, pal.chalk);
                y += 58.0;
                p.line(&label, x, y, 16.0, "kind");
                y += 22.0;
                let mut cx = x;
                for (i, k) in MAKE_KINDS.iter().enumerate() {
                    let s = p.style(&f.medium, 13.0, if i == *kind { pal.window } else { pal.text_2 });
                    let cw = p.measure(&s, k.name()) + 28.0;
                    let chip = Area::new(cx, y, cw, 32.0);
                    p.fill(chip, 8.0, if i == *kind { pal.chalk } else { pal.raised });
                    p.line(&s, cx + 14.0, y + 6.0, 20.0, k.name());
                    self.kind_chips.push(chip);
                    cx += cw + 8.0;
                }
                y += 56.0;
                let b = Area::new(x, y, 140.0, 40.0);
                kit::button(p, pal, f, b, "Make", true, false);
                self.make_button = Some(b);
                kit::hints(p, pal, f, a, &[("enter", "make"), ("tab", "kind")]);
            }
        }
        if !self.status.is_empty() {
            let s = p.style(&f.regular, 13.0, pal.text_2);
            let lines = slate_ui::text::wrap(&s, &self.status, w * p.scale);
            let mut sy = a.y + a.h - 50.0 - 20.0 * lines.len() as f32;
            for l in lines {
                p.line(&s, x, sy, 20.0, &l);
                sy += 20.0;
            }
        }
    }

    fn key(&mut self, code: u16, ch: Option<char>, mods: u8) -> Effect {
        let (shift, ctrl) = (mods & SHIFT != 0, mods & CTRL != 0);
        let shortcut = mods & (CTRL | ALT | LOGO) != 0;
        match &mut self.mode {
            Mode::Failed(_) => Effect::None,
            Mode::Browse { archive, dir, selected, .. } => {
                let n = archive.list(dir).len();
                match (code, ch.filter(|_| !shortcut)) {
                    (KEY_UP, _) => *selected = selected.saturating_sub(1),
                    (KEY_DOWN, _) => *selected = (*selected + 1).min(n.saturating_sub(1)),
                    (KEY_HOME, _) => *selected = 0,
                    (KEY_END, _) => *selected = n.saturating_sub(1),
                    (KEY_ENTER | KEY_KPENTER | KEY_RIGHT, _) => {
                        let entries = archive.list(dir);
                        match entries.get(*selected) {
                            Some((name, true, _, _)) => {
                                dir.push_str(name);
                                *selected = 0;
                            }
                            _ => return Effect::None,
                        }
                    }
                    (KEY_BACKSPACE | KEY_LEFT | KEY_ESC, _) => {
                        if dir.is_empty() {
                            return Effect::None;
                        }
                        let up = dir
                            .trim_end_matches('/')
                            .rsplit_once('/')
                            .map_or(String::new(), |(d, _)| alloc::format!("{d}/"));
                        let came_from = dir[up.len()..].to_string();
                        *dir = up;
                        *selected = archive.list(dir).iter().position(|e| e.0 == came_from).unwrap_or(0);
                    }
                    (_, Some('x')) => return self.extract(false),
                    (_, Some('e')) => return self.extract(true),
                    _ => return Effect::None,
                }
                Effect::Redraw
            }
            Mode::Make { kind, name, .. } => {
                match code {
                    KEY_ENTER | KEY_KPENTER => return self.create(),
                    KEY_TAB => {
                        *kind = (*kind + if shift { MAKE_KINDS.len() - 1 } else { 1 }) % MAKE_KINDS.len();
                        return Effect::Redraw;
                    }
                    _ => {}
                }
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
                let changed = match (edit, ch.filter(|c| !shortcut && !c.is_control() && *c != '/')) {
                    (Some(k), _) => name.key(k, shift, ctrl).moved,
                    (None, Some(c)) => name.insert(c.encode_utf8(&mut [0u8; 4])),
                    _ => false,
                };
                if changed { Effect::Redraw } else { Effect::None }
            }
        }
    }

    fn click(&mut self, x: f32, y: f32) -> Effect {
        if self.make_button.is_some_and(|b| b.contains(x, y)) {
            return self.create();
        }
        if let Some(i) = self.kind_chips.iter().position(|c| c.contains(x, y))
            && let Mode::Make { kind, .. } = &mut self.mode
        {
            *kind = i;
            return Effect::Redraw;
        }
        if let Some(i) = self.rows.iter().position(|r| r.contains(x, y))
            && let Mode::Browse { selected, first, .. } = &mut self.mode
        {
            let i = *first + i;
            if *selected == i {
                return self.key(KEY_ENTER, None, 0);
            }
            *selected = i;
            return Effect::Redraw;
        }
        Effect::None
    }
}

pub fn main() -> i32 {
    let args: Vec<String> = slate_rt::env::args().iter().skip(1).map(|a| String::from(slate_rt::lossy(a))).collect();
    let mut m = match args.as_slice() {
        [] => Manager::new(Mode::Failed(String::from(
            "Open an archive from Files, or give archive-manager an archive or the files to put in one.",
        ))),
        [one]
            if crate::archive::is_archive(one)
                && !slate_rt::fs::stat(one.as_bytes())
                    .is_ok_and(|s| s.mode & slate_rt::fs::S_IFMT == slate_rt::fs::S_IFDIR) =>
        {
            Manager::open(one)
        }
        _ => Manager::make(args.clone()),
    };
    let title = args.first().map(|a| base(a).to_string());
    kit::run("archive-manager", "archives", title.as_deref(), Hints { min: (420, 380), size: (560, 520) }, &mut m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browse_extract_and_make() {
        let s = std::env::temp_dir().join(alloc::format!("slate-archives-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&s);
        std::fs::create_dir_all(s.join("trip/day 1")).unwrap();
        std::fs::write(s.join("trip/day 1/notes.txt"), b"rain\n").unwrap();
        std::fs::write(s.join("trip/plan.txt"), b"go\n").unwrap();
        let sd = s.to_string_lossy().into_owned();
        // Make: a zip of the folder, named after it.
        let mut m = Manager::make(std::vec![alloc::format!("{sd}/trip")]);
        assert_eq!(m.key(KEY_ENTER, None, 0), Effect::Redraw);
        assert!(m.status.starts_with("Made trip.zip"), "{}", m.status);
        // Tab: tar.gz, and a new name.
        m.key(KEY_TAB, None, 0);
        for _ in 0..4 {
            m.key(KEY_BACKSPACE, None, 0);
        }
        for c in "holiday".chars() {
            m.key(0, Some(c), 0);
        }
        m.key(KEY_ENTER, None, 0);
        assert!(std::path::Path::new(&alloc::format!("{sd}/holiday.tar.gz")).exists(), "{}", m.status);
        // Dropped on the window: an archive opens; other files are to be
        // made into one, more dropped are added.
        let mut d = Manager::new(Mode::Failed(String::new()));
        d.dropped(0.0, 0.0, &[alloc::format!("{sd}/trip.zip")], false);
        assert!(matches!(d.mode, Mode::Browse { .. }));
        d.dropped(0.0, 0.0, &[alloc::format!("{sd}/trip/plan.txt")], false);
        d.dropped(0.0, 0.0, &[alloc::format!("{sd}/trip/day 1"), alloc::format!("{sd}/trip/plan.txt")], false);
        let Mode::Make { paths, .. } = &d.mode else { panic!("{:?}", d.mode) };
        assert_eq!(paths, &[alloc::format!("{sd}/trip/plan.txt"), alloc::format!("{sd}/trip/day 1")]);
        // Browse the zip: into "trip/", into "day 1/", back up.
        let mut b = Manager::open(&alloc::format!("{sd}/trip.zip"));
        b.key(KEY_ENTER, None, 0);
        if let Mode::Browse { dir, .. } = &b.mode {
            assert_eq!(dir, "trip/");
        }
        b.key(KEY_ENTER, None, 0);
        b.key(KEY_BACKSPACE, None, 0);
        if let Mode::Browse { dir, selected, .. } = &b.mode {
            assert_eq!((dir.as_str(), *selected), ("trip/", 0), "back on day 1");
        }
        // Extract the chosen folder only, then everything.
        b.key(0, Some('x'), 0);
        assert!(b.status.starts_with("Extracted 1 file to trip (2)"), "{}", b.status);
        assert_eq!(std::fs::read(s.join("trip (2)/trip/day 1/notes.txt")).unwrap(), b"rain\n");
        assert!(!s.join("trip (2)/trip/plan.txt").exists());
        b.key(0, Some('e'), 0);
        assert!(b.status.starts_with("Extracted 2 files to trip (3)"), "{}", b.status);
        let bad = Manager::open(&alloc::format!("{sd}/trip/plan.txt"));
        assert!(matches!(bad.mode, Mode::Failed(_)));
        std::fs::remove_dir_all(&s).unwrap();
    }
}
