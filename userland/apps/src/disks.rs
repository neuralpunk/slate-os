// SPDX-License-Identifier: MIT OR Apache-2.0

//! Disks (ADR 0112), `disks`: the computer's disks down a sidebar; the
//! chosen one as a map of its partitions and free space, and what the
//! chosen part holds: its file system, label and UUID, where it is
//! mounted, whether it is encrypted (and what the unlocked device holds),
//! and the SlateFS subvolumes of the running system.
//!
//! Changes go through the privilege broker's `disk=` action, behind the
//! approval dialog, and `slate-disk` makes them (userland/diskutil):
//!
//! - `n` (or New partition) on free space: its size, name and file system;
//! - `f` (Format) on a partition: a new FAT32 or SlateFS file system;
//! - Delete on a partition, `e` (Erase) on a disk: a new partition table;
//! - `m` (Mount) on a partition with SlateFS or ext4: mounted in
//!   `/run/media/USER`, and Unmount again (removable disks without the
//!   approval dialog); `r` (Rename) changes its name in the table.
//!
//! Each destructive one asks again in clay (Enter twice). Whatever is in
//! use is not offered: a mounted or unlocked partition, the system's disk
//! (`slate_diskutil::in_use` says why, and slate-disk checks again).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_diskutil::{ALIGN, Change, Format, free_regions, in_use};
use slate_display::input::{
    KEY_BACKSPACE, KEY_DELETE, KEY_DOWN, KEY_ENTER, KEY_ESC, KEY_KPENTER, KEY_LEFT, KEY_RIGHT, KEY_TAB, KEY_UP,
};
use slate_rt::subvol::Subvol;
use slate_strata::fonts::Fonts;
use slate_strata_client::mods::{ALT, CTRL, LOGO, SHIFT};
use slate_sysinfo::block::{Disk, Mapped, type_name};
use slate_sysinfo::load::Mount;
use slate_ui::edit::LineEdit;
use slate_ui::graphite::Palette;
use slate_ui::icon::Icon;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;

use crate::kit::{self, App, Effect, Hints, Job, Now};

const SIDEBAR_W: f32 = 240.0;
const MIB_SECTORS: u64 = ALIGN;

/// A piece of a disk's map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Segment {
    /// A partition: its index in the disk's list.
    Part(usize),
    /// Free space: first sector and sectors.
    Free(u64, u64),
    /// A disk without a partition table.
    Whole,
}

/// A disk's map, in order.
pub fn segments(d: &Disk) -> Vec<Segment> {
    if d.table.as_deref() != Some("gpt") && d.parts.is_empty() {
        return alloc::vec![Segment::Whole];
    }
    let mut out: Vec<(u64, Segment)> = d.parts.iter().enumerate().map(|(i, p)| (p.start, Segment::Part(i))).collect();
    if d.table.as_deref() == Some("gpt") {
        let used: Vec<(u64, u64)> = d.parts.iter().map(|p| (p.start, p.sectors)).collect();
        out.extend(free_regions(d.sectors, &used).into_iter().map(|(s, n)| (s, Segment::Free(s, n))));
    }
    out.sort_by_key(|(s, _)| *s);
    out.into_iter().map(|(_, s)| s).collect()
}

/// The form for a new partition or a new file system.
#[derive(Clone, Debug)]
pub struct Form {
    /// None: format the chosen partition; Some: a new partition in this
    /// free space (first sector, sectors).
    pub space: Option<(u64, u64)>,
    pub size: LineEdit,
    pub name: LineEdit,
    pub format: usize,
    /// 0 the size, 1 the name (or label), 2 the formats.
    pub focus: usize,
    pub error: Option<String>,
    /// Renaming the chosen partition (the name field only).
    pub rename: bool,
}

#[derive(Debug)]
pub struct Disks {
    pub disks: Vec<Disk>,
    pub mapped: Vec<Mapped>,
    pub mounts: Vec<Mount>,
    /// The running system's subvolumes (a SlateFS root).
    pub subvols: Vec<Subvol>,
    pub disk: usize,
    pub segment: usize,
    pub form: Option<Form>,
    /// A destructive change asked about: Enter again does it.
    pub confirm: Option<(Change, String)>,
    pub status: Option<(String, bool)>,
    job: Option<(Job, Change)>,
    side_hits: Vec<(Area, usize)>,
    map_hits: Vec<(Area, usize)>,
    button_hits: Vec<(Area, char)>,
    chip_hits: Vec<(Area, usize)>,
    field_hits: Vec<(Area, usize)>,
}

impl Disks {
    pub fn new(disks: Vec<Disk>, mapped: Vec<Mapped>, mounts: Vec<Mount>, subvols: Vec<Subvol>) -> Disks {
        let mut d = Disks {
            disks,
            mapped,
            mounts,
            subvols,
            disk: 0,
            segment: 0,
            form: None,
            confirm: None,
            status: None,
            job: None,
            side_hits: Vec::new(),
            map_hits: Vec::new(),
            button_hits: Vec::new(),
            chip_hits: Vec::new(),
            field_hits: Vec::new(),
        };
        // The first disk that isn't the system's, if there is one.
        d.disk = (0..d.disks.len()).find(|&i| !d.is_system(i)).unwrap_or(0);
        d
    }

    /// The computer's disks as /sys and /proc show them now.
    pub fn read() -> Disks {
        let (disks, mapped) = slate_sysinfo::block::read(&slate_sysinfo::block::RealSys);
        let mounts = slate_sysinfo::load::mounts(&slate_sysinfo::load::read("/proc/mounts"));
        Disks::new(disks, mapped, mounts, slate_rt::subvol::list().unwrap_or_default())
    }

    fn reload(&mut self) {
        let name = self.disks.get(self.disk).map(|d| d.name.clone());
        let fresh = Disks::read();
        self.disks = fresh.disks;
        self.mapped = fresh.mapped;
        self.mounts = fresh.mounts;
        self.subvols = fresh.subvols;
        self.disk = name.and_then(|n| self.disks.iter().position(|d| d.name == n)).unwrap_or(0);
        self.segment = self.segment.min(self.segs().len().saturating_sub(1));
    }

    fn is_system(&self, i: usize) -> bool {
        self.disks.get(i).is_some_and(|d| {
            in_use(&d.name, &self.disks, &self.mapped, &self.mounts)
                .is_some_and(|w| w.starts_with("This is the system"))
        })
    }

    fn segs(&self) -> Vec<Segment> {
        self.disks.get(self.disk).map(segments).unwrap_or_default()
    }

    fn chosen(&self) -> Option<Segment> {
        self.segs().get(self.segment).copied()
    }

    /// Say what the disks are (the scenario reads it).
    pub fn say(&self) {
        for (i, d) in self.disks.iter().enumerate() {
            let parts: Vec<String> = d
                .parts
                .iter()
                .map(|p| {
                    let holds = p.holds.as_ref().map_or("nothing known", |h| h.kind.as_str());
                    alloc::format!("{} {}", p.name, holds)
                })
                .collect();
            crate::trace!(
                "disks: {} {}{}, {}: {}",
                d.name,
                slate_sysinfo::size(d.sectors * 512),
                if self.is_system(i) { " (system)" } else { "" },
                d.table.as_deref().unwrap_or("no table"),
                if parts.is_empty() { String::from("no partitions") } else { parts.join(", ") }
            );
        }
    }

    /// Why the chosen segment (or `whole`: its disk) can't be changed.
    fn blocked(&self, whole: bool) -> Option<String> {
        let d = self.disks.get(self.disk)?;
        let target = match (whole, self.chosen()) {
            (false, Some(Segment::Part(i))) => d.parts[i].name.clone(),
            _ => d.name.clone(),
        };
        in_use(&target, &self.disks, &self.mapped, &self.mounts)
    }

    /// What `key` would do here: n, f, d, e (None: not offered).
    fn offered(&self, key: char) -> bool {
        match (key, self.chosen()) {
            // Unmounting what is mounted in /run/media; mounting what isn't
            // in use and can be.
            ('m', Some(Segment::Part(_))) if self.media_mount().is_some() => true,
            ('m', Some(Segment::Part(_))) => self.mountable() && self.blocked(false).is_none(),
            ('r', Some(Segment::Part(_))) => {
                self.disks.get(self.disk).is_some_and(|d| d.table.as_deref() == Some("gpt"))
                    && self.blocked(false).is_none()
            }
            ('n', Some(Segment::Free(..))) | ('f', Some(Segment::Part(_))) | ('d', Some(Segment::Part(_))) => {
                self.blocked(false).is_none()
            }
            ('e', Some(_)) => self.blocked(true).is_none(),
            _ => false,
        }
    }

    fn open_form(&mut self, new: bool) -> Effect {
        if !self.offered(if new { 'n' } else { 'f' }) {
            return Effect::None;
        }
        let space = match self.chosen() {
            Some(Segment::Free(s, n)) if new => Some((s, n)),
            _ => None,
        };
        let mib = space.map_or(0, |(_, n)| n / MIB_SECTORS);
        self.form = Some(Form {
            space,
            size: LineEdit::new(&mib.to_string()).with_max(9),
            name: LineEdit::new(if new { "Data" } else { "" }).with_max(36),
            format: 0,
            focus: if new { 0 } else { 1 },
            error: None,
            rename: false,
        });
        Effect::Redraw
    }

    /// The chosen partition's mount for this person (in /run/media), if
    /// it is mounted there.
    fn media_mount(&self) -> Option<String> {
        let d = self.disks.get(self.disk)?;
        let Some(Segment::Part(i)) = self.chosen() else { return None };
        let dev = alloc::format!("/dev/{}", d.parts[i].name);
        self.mounts
            .iter()
            .find(|m| m.source == dev && m.path.starts_with(&alloc::format!("{}/", slate_diskutil::MEDIA)))
            .map(|m| m.path.clone())
    }

    /// Whether the chosen partition holds something the kernel mounts.
    fn mountable(&self) -> bool {
        let Some(d) = self.disks.get(self.disk) else { return false };
        let Some(Segment::Part(i)) = self.chosen() else { return false };
        d.parts[i].holds.as_ref().is_some_and(|h| slate_diskutil::mountable(&h.fs))
    }

    /// Mount the chosen partition, or unmount it from /run/media.
    fn mount_or_unmount(&mut self) -> Effect {
        if !self.offered('m') {
            return Effect::None;
        }
        let (Some(d), Some(Segment::Part(i))) = (self.disks.get(self.disk), self.chosen()) else { return Effect::None };
        let part = d.parts[i].name.clone();
        let c = if self.media_mount().is_some() { Change::Unmount { part } } else { Change::Mount { part } };
        self.start(c);
        Effect::Redraw
    }

    fn open_rename(&mut self) -> Effect {
        if !self.offered('r') {
            return Effect::None;
        }
        let (Some(d), Some(Segment::Part(i))) = (self.disks.get(self.disk), self.chosen()) else { return Effect::None };
        let mut name = LineEdit::new(&d.parts[i].label).with_max(36);
        name.select_all();
        self.form =
            Some(Form { space: None, size: LineEdit::new(""), name, format: 0, focus: 1, error: None, rename: true });
        Effect::Redraw
    }

    /// The form's change, or what is wrong with it.
    pub fn form_change(&self) -> Result<Change, String> {
        let form = self.form.as_ref().ok_or("no form")?;
        let d = self.disks.get(self.disk).ok_or("no disk")?;
        let format = Format::ALL[form.format];
        let name = form.name.text().trim().to_string();
        if form.rename {
            let Some(Segment::Part(i)) = self.chosen() else { return Err("Choose a partition.".into()) };
            slate_diskutil::name_ok(&name)?;
            return Ok(Change::Name { part: d.parts[i].name.clone(), name });
        }
        match form.space {
            Some((start, sectors)) => {
                let size: u64 = form.size.text().trim().parse().map_err(|_| "The size is a number of MiB.")?;
                let max = sectors / MIB_SECTORS;
                if size == 0 || size > max {
                    return Err(alloc::format!("The size is 1 to {max} MiB."));
                }
                slate_diskutil::name_ok(&name)?;
                Ok(Change::Add { disk: d.name.clone(), start_mib: start / MIB_SECTORS, size_mib: size, format, name })
            }
            None => {
                let Some(Segment::Part(i)) = self.chosen() else { return Err("Choose a partition.".into()) };
                if format == Format::Empty {
                    return Err("Choose FAT32 or SlateFS.".into());
                }
                slate_diskutil::label_ok(format, &name)?;
                Ok(Change::Format { part: d.parts[i].name.clone(), format, label: format.label(&name) })
            }
        }
    }

    fn submit_form(&mut self) -> Effect {
        match self.form_change() {
            Ok(c @ Change::Format { .. }) => {
                let q = alloc::format!("Format {}? Everything on it is lost. Enter again to format.", c.target());
                self.form = None;
                self.confirm = Some((c, q));
            }
            Ok(c) => {
                self.form = None;
                self.start(c);
            }
            Err(e) => {
                if let Some(f) = &mut self.form {
                    f.error = Some(e);
                }
            }
        }
        Effect::Redraw
    }

    fn ask_delete(&mut self) -> Effect {
        if !self.offered('d') {
            return Effect::None;
        }
        let (Some(d), Some(Segment::Part(i))) = (self.disks.get(self.disk), self.chosen()) else { return Effect::None };
        let p = &d.parts[i];
        let c = Change::Delete { part: p.name.clone() };
        let q = alloc::format!("Delete {}? What is on it is lost. Enter again to delete.", p.name);
        self.confirm = Some((c, q));
        Effect::Redraw
    }

    fn ask_erase(&mut self) -> Effect {
        if !self.offered('e') {
            return Effect::None;
        }
        let Some(d) = self.disks.get(self.disk) else { return Effect::None };
        let what = if d.model.is_empty() { d.name.clone() } else { alloc::format!("{} ({})", d.model, d.name) };
        let q = alloc::format!("Erase {what}? Every partition on it is lost. Enter again to erase.");
        self.confirm = Some((Change::Table { disk: d.name.clone() }, q));
        Effect::Redraw
    }

    /// Ask the broker for `c`, away from the window.
    fn start(&mut self, c: Change) {
        let action = alloc::format!("disk={}", c.words());
        crate::trace!("disks: asking for {}", c.words());
        match Job::start(move || kit::broker(&action).map(|()| String::new())) {
            Ok(j) => {
                self.status = Some((String::from("Waiting for approval…"), false));
                self.job = Some((j, c));
            }
            Err(e) => self.status = Some((alloc::format!("Couldn't ask: {e}"), true)),
        }
    }

    /// A change's outcome.
    pub fn finished(&mut self, c: &Change, r: Result<String, String>) {
        self.status = Some(match r {
            Ok(_) => {
                crate::trace!("disks: done: {}", c.words());
                let said = match c {
                    Change::Table { disk } => alloc::format!("{disk} has a new, empty partition table."),
                    Change::Add { disk, size_mib, .. } => alloc::format!("A {size_mib} MiB partition is on {disk}."),
                    Change::Format { part, format, .. } => {
                        alloc::format!("{part} has a new {} file system.", format.name())
                    }
                    Change::Delete { part } => alloc::format!("{part} is deleted."),
                    Change::Name { part, name } => alloc::format!("{part} is named \"{name}\"."),
                    Change::Mount { part } => alloc::format!("{part} is mounted; Files shows it."),
                    Change::Unmount { part } => alloc::format!("{part} is unmounted: it can be removed."),
                    Change::PowerOff { disk } => alloc::format!("{disk} is powered off: it can be unplugged."),
                };
                (said, false)
            }
            Err(e) if e == "cancelled" => (String::from("Nothing was changed."), false),
            Err(e) => {
                crate::trace!("disks: failed: {}: {e}", c.words());
                (alloc::format!("Nothing was changed: {e}"), true)
            }
        });
    }

    fn form_key(&mut self, code: u16, ch: Option<char>, mods: u8) -> Effect {
        let Some(f) = &mut self.form else { return Effect::None };
        let fields: Vec<usize> = if f.space.is_some() {
            alloc::vec![0, 1, 2]
        } else if f.rename {
            alloc::vec![1]
        } else {
            alloc::vec![1, 2]
        };
        let at = fields.iter().position(|&x| x == f.focus).unwrap_or(0);
        match code {
            KEY_ESC => {
                self.form = None;
                return Effect::Redraw;
            }
            KEY_ENTER | KEY_KPENTER => return self.submit_form(),
            KEY_TAB => {
                let n = fields.len();
                f.focus = fields[if mods & SHIFT != 0 { (at + n - 1) % n } else { (at + 1) % n }];
                return Effect::Redraw;
            }
            KEY_LEFT | KEY_RIGHT if f.focus == 2 => {
                // A format for a new file system needs one: Nothing is
                // for new partitions only.
                let n = if f.space.is_some() { Format::ALL.len() } else { Format::ALL.len() - 1 };
                f.format = if code == KEY_LEFT { (f.format + n - 1) % n } else { (f.format + 1) % n };
                return Effect::Redraw;
            }
            _ => {}
        }
        let changed = match f.focus {
            0 => kit::edit_key(&mut f.size, code, ch, mods, |c| c.is_ascii_digit()),
            1 => kit::edit_key(&mut f.name, code, ch, mods, |c| c.is_ascii() && !c.is_ascii_control()),
            _ => false,
        };
        if changed {
            f.error = None;
            Effect::Redraw
        } else {
            Effect::None
        }
    }

    fn draw_sidebar(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area) {
        let side = Area::new(a.x, a.y, SIDEBAR_W, a.h);
        p.fill(side, 0.0, pal.header);
        p.fill(Area::new(side.x + side.w - 1.0, side.y, 1.0, side.h), 0.0, pal.divider);
        let label = p.style(&f.mono, 11.0, pal.muted);
        p.line(&label, side.x + 16.0, side.y + 16.0, 16.0, "disks");
        self.side_hits.clear();
        let mut y = side.y + 40.0;
        for i in 0..self.disks.len() {
            let d = &self.disks[i];
            let on = i == self.disk;
            let r = Area::new(side.x + 8.0, y, side.w - 16.0, 50.0);
            if on {
                p.fill(r, 8.0, pal.raised);
            }
            let ink = if on { pal.chalk } else { pal.text_2 };
            p.icon(Icon::Disk, r.x + 10.0, r.y + 14.0, 20.0, if on { pal.chalk } else { pal.text_3 });
            let name = if d.model.is_empty() { alloc::format!("Disk {}", d.name) } else { d.model.clone() };
            let ns = p.style(&f.medium, 13.0, ink);
            let name = kit::fit(p, &ns, &name, r.w - 50.0);
            p.line(&ns, r.x + 40.0, r.y + 6.0, 20.0, &name);
            let mut meta = alloc::format!("{} · {}", slate_sysinfo::size(d.sectors * 512), d.name);
            if self.is_system(i) {
                meta.push_str(" · system");
            } else if d.removable {
                meta.push_str(" · removable");
            }
            p.line(&label, r.x + 40.0, r.y + 27.0, 16.0, &meta);
            self.side_hits.push((r, i));
            y += 54.0;
        }
        if self.disks.is_empty() {
            let q = p.style(&f.regular, 13.0, pal.muted);
            p.line(&q, side.x + 16.0, y, 20.0, "No disks.");
        }
    }

    fn draw_map(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, d: &Disk, bar: Area) {
        self.map_hits.clear();
        let segs = segments(d);
        // Widths by size, each at least 44 pixels.
        let len = |s: &Segment| match s {
            Segment::Part(i) => d.parts[*i].sectors,
            Segment::Free(_, n) => *n,
            Segment::Whole => d.sectors,
        } as f32;
        let total: f32 = segs.iter().map(len).sum::<f32>().max(1.0);
        let min = 44.0;
        let spare = (bar.w - min * segs.len() as f32 - 4.0 * segs.len().saturating_sub(1) as f32).max(0.0);
        let mut x = bar.x;
        let small = p.style(&f.mono, 11.0, pal.text_3);
        for (i, s) in segs.iter().enumerate() {
            let w = min + spare * len(s) / total;
            let r = Area::new(x, bar.y, w, bar.h);
            let on = i == self.segment;
            let (text, fill) = match s {
                Segment::Part(k) => {
                    let pt = &d.parts[*k];
                    let what = pt.holds.as_ref().map_or("?", |h| h.kind.as_str());
                    (alloc::format!("{} · {}", pt.name, what), pal.raised)
                }
                Segment::Free(_, n) => (alloc::format!("free · {}", slate_sysinfo::size(n * 512)), pal.well),
                Segment::Whole => (
                    d.holds.as_ref().map_or_else(|| String::from("no partition table"), |h| h.kind.clone()),
                    pal.raised,
                ),
            };
            p.fill(r, 8.0, fill);
            if matches!(s, Segment::Free(..)) {
                p.border(r, 8.0, 1.0, pal.border);
            }
            if on {
                p.border(r.grow(2.0), 10.0, 2.0, pal.chalk);
            }
            let t = kit::fit(p, &small, &text, w - 16.0);
            p.line(&small, r.x + 8.0, r.y + (r.h - 16.0) / 2.0, 16.0, &t);
            self.map_hits.push((r, i));
            x += w + 4.0;
        }
    }

    /// Rows of (label, value) for the chosen segment.
    fn details(&self, d: &Disk) -> Vec<(String, String)> {
        let mut rows: Vec<(String, String)> = Vec::new();
        let mut row = |l: &str, v: String| {
            if !v.is_empty() {
                rows.push((l.to_string(), v));
            }
        };
        let mounted =
            |dev: &str| self.mounts.iter().find(|m| m.source == alloc::format!("/dev/{dev}")).map(|m| m.path.clone());
        match self.chosen() {
            Some(Segment::Part(i)) => {
                let pt = &d.parts[i];
                row("name", pt.label.clone());
                row("size", slate_sysinfo::size(pt.sectors * 512));
                row("device", alloc::format!("/dev/{}", pt.name));
                row("type", type_name(&pt.ptype).to_string());
                match &pt.holds {
                    Some(h) => {
                        row("contents", h.kind.clone());
                        row("label", h.label.clone());
                        row("uuid", h.uuid.clone());
                    }
                    None => row("contents", String::from("Unknown, or nothing")),
                }
                if let Some(m) = self.mapped.iter().find(|m| m.under == pt.name) {
                    let inside = m.holds.as_ref().map_or(String::new(), |h| {
                        if h.label.is_empty() {
                            alloc::format!(", holding {}", h.kind)
                        } else {
                            alloc::format!(", holding {} \"{}\"", h.kind, h.label)
                        }
                    });
                    row("unlocked", alloc::format!("as {}{inside}", m.name));
                    row("mounted at", mounted(&m.name).unwrap_or_default());
                } else {
                    row("mounted at", mounted(&pt.name).unwrap_or_default());
                }
            }
            Some(Segment::Free(s, n)) => {
                row("free space", slate_sysinfo::size(n * 512));
                row("from", alloc::format!("{} MiB", s / MIB_SECTORS));
            }
            Some(Segment::Whole) => {
                row("size", slate_sysinfo::size(d.sectors * 512));
                row("table", String::from("none"));
                if let Some(h) = &d.holds {
                    row("contents", h.kind.clone());
                    row("label", h.label.clone());
                }
                row("mounted at", mounted(&d.name).unwrap_or_default());
            }
            None => {}
        }
        rows
    }

    /// Whether the chosen partition holds the running system (directly
    /// or unlocked): its subvolumes are shown.
    fn holds_root(&self, d: &Disk) -> bool {
        let Some(Segment::Part(i)) = self.chosen() else { return false };
        let name = &d.parts[i].name;
        let dev = self.mapped.iter().find(|m| &m.under == name).map_or(name.clone(), |m| m.name.clone());
        self.mounts.iter().any(|m| m.source == alloc::format!("/dev/{dev}") && m.path == "/" && m.fs == "slatefs")
    }

    fn draw_form(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, x: f32, mut y: f32, w: f32) {
        let Some(form) = self.form.clone() else { return };
        self.field_hits.clear();
        self.chip_hits.clear();
        let title = p.style(&f.medium, 15.0, pal.chalk);
        let label = p.style(&f.mono, 11.0, pal.muted);
        let new = form.space.is_some();
        if form.rename {
            p.line(&title, x, y, 22.0, "Rename");
            y += 34.0;
            p.line(&label, x, y, 16.0, "name in the partition table");
            y += 20.0;
            let a = Area::new(x, y, (w - 20.0).min(360.0), 36.0);
            kit::field(p, pal, f, a, &form.name, true, "");
            self.field_hits.push((a, 1));
            y += 48.0;
            if let Some(e) = &form.error {
                let s = p.style(&f.regular, 13.0, pal.accents.clay.text);
                p.line(&s, x, y, 20.0, e);
            }
            return;
        }
        p.line(&title, x, y, 22.0, if new { "New partition" } else { "Format" });
        y += 34.0;
        if let Some((_, n)) = form.space {
            p.line(&label, x, y, 16.0, &alloc::format!("size, MiB (up to {})", n / MIB_SECTORS));
            y += 20.0;
            let a = Area::new(x, y, 160.0, 36.0);
            kit::field(p, pal, f, a, &form.size, form.focus == 0, "");
            self.field_hits.push((a, 0));
            y += 48.0;
        }
        p.line(&label, x, y, 16.0, if new { "name" } else { "label" });
        y += 20.0;
        let a = Area::new(x, y, (w - 20.0).min(360.0), 36.0);
        kit::field(p, pal, f, a, &form.name, form.focus == 1, if new { "" } else { "none" });
        self.field_hits.push((a, 1));
        y += 48.0;
        p.line(&label, x, y, 16.0, "file system");
        y += 20.0;
        let mut cx = x;
        let n = if new { Format::ALL.len() } else { Format::ALL.len() - 1 };
        for (i, fmt) in Format::ALL.iter().take(n).enumerate() {
            let on = i == form.format;
            let s = p.style(&f.medium, 13.0, if on { pal.window } else { pal.text_2 });
            let cw = p.measure(&s, fmt.name()) + 28.0;
            let chip = Area::new(cx, y, cw, 32.0);
            p.fill(chip, 8.0, if on { pal.chalk } else { pal.raised });
            if on && form.focus == 2 {
                p.border(chip.grow(3.0), 11.0, 2.0, pal.chalk);
            }
            p.line(&s, cx + 14.0, y + 6.0, 20.0, fmt.name());
            self.chip_hits.push((chip, i));
            cx += cw + 8.0;
        }
        y += 40.0;
        let note = p.style(&f.regular, 12.5, pal.muted);
        p.line(&note, x, y, 18.0, Format::ALL[form.format].purpose());
        y += 30.0;
        if let Some(e) = &form.error {
            let s = p.style(&f.regular, 13.0, pal.accents.clay.text);
            p.line(&s, x, y, 20.0, e);
        }
    }
}

impl App for Disks {
    fn draw(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area) {
        self.draw_sidebar(p, pal, f, a);
        self.button_hits.clear();
        let main = Area::new(a.x + SIDEBAR_W, a.y, a.w - SIDEBAR_W, a.h);
        let (x, w) = (main.x + 24.0, main.w - 48.0);
        let Some(d) = self.disks.get(self.disk).cloned() else {
            kit::hints(p, pal, f, a, &[]);
            return;
        };
        let title = p.style(&f.medium, 17.0, pal.chalk);
        let meta = p.style(&f.mono, 11.5, pal.text_4);
        let label = p.style(&f.mono, 11.0, pal.muted);
        let value = p.style(&f.regular, 13.5, pal.text_1);
        let name = if d.model.is_empty() { alloc::format!("Disk {}", d.name) } else { d.model.clone() };
        p.line(&title, x, main.y + 18.0, 24.0, &name);
        let table = match d.table.as_deref() {
            Some("gpt") => "GPT",
            Some("mbr") => "MBR",
            _ => "no partition table",
        };
        let line = alloc::format!(
            "/dev/{} · {} · {table}{}",
            d.name,
            slate_sysinfo::size(d.sectors * 512),
            if d.removable { " · removable" } else { "" }
        );
        p.line(&meta, x, main.y + 46.0, 16.0, &line);
        self.draw_map(p, pal, f, &d, Area::new(x, main.y + 76.0, w, 54.0));
        let mut y = main.y + 152.0;
        if self.form.is_some() {
            self.draw_form(p, pal, f, x, y, w);
        } else {
            for (l, v) in self.details(&d) {
                p.line(&label, x, y + 2.0, 16.0, &l);
                let v = kit::fit(p, &value, &v, w - 130.0);
                p.line(&value, x + 120.0, y, 20.0, &v);
                y += 26.0;
            }
            if self.holds_root(&d) && !self.subvols.is_empty() {
                y += 8.0;
                p.line(&label, x, y + 2.0, 16.0, "subvolumes");
                for s in &self.subvols {
                    let mut flags = Vec::new();
                    if s.has("mounted-here") {
                        flags.push("running");
                    }
                    if s.has("default") {
                        flags.push("starts next");
                    }
                    if s.has("fallback") {
                        flags.push("fallback");
                    }
                    if s.has("ro") {
                        flags.push("read-only");
                    }
                    let t = if flags.is_empty() {
                        s.name.clone()
                    } else {
                        alloc::format!("{} ({})", s.name, flags.join(", "))
                    };
                    p.line(&value, x + 120.0, y, 20.0, &t);
                    y += 24.0;
                }
            }
            // The actions, or why there are none.
            y += 14.0;
            let mut bx = x;
            let mount_label = if self.media_mount().is_some() { "Unmount" } else { "Mount" };
            let actions: [(char, &str); 6] = [
                ('m', mount_label),
                ('n', "New partition…"),
                ('r', "Rename…"),
                ('f', "Format…"),
                ('d', "Delete"),
                ('e', "Erase disk…"),
            ];
            let chosen = self.chosen();
            let mountable = self.mountable();
            let applies = |k: char| {
                matches!(
                    (k, chosen),
                    ('n', Some(Segment::Free(..))) | ('f' | 'd' | 'r', Some(Segment::Part(_))) | ('e', Some(_))
                ) || (k == 'm' && mountable)
            };
            for (k, l) in actions.into_iter().filter(|(k, _)| applies(*k)) {
                let s = p.style(&f.medium, 13.0, pal.text_1);
                let bw = p.measure(&s, l) + 32.0;
                let b = Area::new(bx, y, bw, 36.0);
                if self.offered(k) {
                    if matches!(k, 'd' | 'e') {
                        // Destructive: clay (STRATA_COLORS.md).
                        let c = pal.accents.clay;
                        p.fill(b, 8.0, c.tint);
                        p.border(b, 8.0, 1.0, c.border);
                        let cs = p.style(&f.medium, 13.0, c.text);
                        p.line(&cs, b.x + 16.0, b.y + 8.0, 20.0, l);
                    } else {
                        kit::button(p, pal, f, b, l, false, false);
                    }
                    self.button_hits.push((b, k));
                } else {
                    p.border(b, 8.0, 1.0, pal.border);
                    let ds = p.style(&f.medium, 13.0, pal.decor);
                    p.line(&ds, b.x + 16.0, b.y + 8.0, 20.0, l);
                }
                bx += bw + 10.0;
            }
            if let Some(why) =
                self.blocked(matches!(self.chosen(), Some(Segment::Free(..)) | None)).or_else(|| self.blocked(false))
            {
                let s = p.style(&f.regular, 13.0, pal.muted);
                p.line(&s, x, y + 46.0, 20.0, &why);
            }
        }
        // The question, or the outcome.
        let bottom = a.y + a.h - 70.0;
        if let Some((_, q)) = &self.confirm {
            let c = pal.accents.clay;
            let strip = Area::new(x - 10.0, bottom - 16.0, w + 20.0, 44.0);
            p.fill(strip, 8.0, c.tint);
            p.border(strip, 8.0, 1.0, c.border);
            let s = p.style(&f.regular, 13.5, pal.text_1);
            let q = kit::fit(p, &s, q, strip.w - 28.0);
            p.line(&s, strip.x + 14.0, strip.y + 12.0, 20.0, &q);
        } else if let Some((s, err)) = &self.status {
            let st = p.style(&f.regular, 13.0, if *err { pal.accents.clay.text } else { pal.text_2 });
            let s = kit::fit(p, &st, s, w);
            p.line(&st, x, bottom, 20.0, &s);
        }
        let hints: &[(&str, &str)] = if self.form.is_some() {
            &[("enter", "make it"), ("tab", "next"), ("←→", "file system"), ("esc", "cancel")]
        } else if self.confirm.is_some() {
            &[("enter", "yes, do it"), ("esc", "cancel")]
        } else {
            &[("↑↓", "disk"), ("←→", "part"), ("m", "mount"), ("n", "new"), ("f", "format"), ("del", "delete")]
        };
        kit::hints(p, pal, f, main, hints);
    }

    fn key(&mut self, code: u16, ch: Option<char>, mods: u8) -> Effect {
        if self.job.is_some() {
            return Effect::None;
        }
        if self.form.is_some() {
            return self.form_key(code, ch, mods);
        }
        if let Some((c, _)) = &self.confirm {
            return match code {
                KEY_ENTER | KEY_KPENTER => {
                    let c = c.clone();
                    self.confirm = None;
                    self.start(c);
                    Effect::Redraw
                }
                KEY_ESC | KEY_BACKSPACE => {
                    self.confirm = None;
                    Effect::Redraw
                }
                _ => Effect::None,
            };
        }
        let n = self.segs().len();
        let plain = ch.filter(|_| mods & (CTRL | ALT | LOGO) == 0);
        match (code, plain) {
            (KEY_UP, _) | (KEY_DOWN, _) => {
                let last = self.disks.len().saturating_sub(1);
                self.disk = if code == KEY_UP { self.disk.saturating_sub(1) } else { (self.disk + 1).min(last) };
                self.segment = 0;
                self.status = None;
                if let Some(d) = self.disks.get(self.disk) {
                    crate::trace!("disks: chose {}", d.name);
                }
            }
            (KEY_LEFT, _) => self.segment = self.segment.saturating_sub(1),
            (KEY_RIGHT, _) | (KEY_TAB, _) => self.segment = (self.segment + 1).min(n.saturating_sub(1)),
            (KEY_DELETE, _) | (_, Some('d')) => return self.ask_delete(),
            (_, Some('n')) => return self.open_form(true),
            (_, Some('f')) => return self.open_form(false),
            (_, Some('e')) => return self.ask_erase(),
            (_, Some('m')) => return self.mount_or_unmount(),
            (_, Some('r')) => return self.open_rename(),
            _ => return Effect::None,
        }
        Effect::Redraw
    }

    fn click(&mut self, x: f32, y: f32) -> Effect {
        if self.job.is_some() {
            return Effect::None;
        }
        if let Some((_, i)) = self.side_hits.iter().find(|(a, _)| a.contains(x, y)).copied() {
            self.disk = i;
            self.segment = 0;
            self.form = None;
            self.confirm = None;
            return Effect::Redraw;
        }
        if let Some(form) = &mut self.form {
            if let Some((_, i)) = self.chip_hits.iter().find(|(a, _)| a.contains(x, y)).copied() {
                form.format = i;
                form.focus = 2;
                return Effect::Redraw;
            }
            if let Some((_, i)) = self.field_hits.iter().find(|(a, _)| a.contains(x, y)).copied() {
                form.focus = i;
                return Effect::Redraw;
            }
            return Effect::None;
        }
        if let Some((_, i)) = self.map_hits.iter().find(|(a, _)| a.contains(x, y)).copied() {
            self.segment = i;
            self.confirm = None;
            return Effect::Redraw;
        }
        if let Some((_, k)) = self.button_hits.iter().find(|(a, _)| a.contains(x, y)).copied() {
            return match k {
                'n' => self.open_form(true),
                'f' => self.open_form(false),
                'd' => self.ask_delete(),
                'm' => self.mount_or_unmount(),
                'r' => self.open_rename(),
                _ => self.ask_erase(),
            };
        }
        Effect::None
    }

    fn tick(&mut self, _now: Now) -> bool {
        if let Some((j, c)) = &mut self.job
            && let Some(r) = j.poll()
        {
            let c = c.clone();
            self.job = None;
            let ok = r.is_ok();
            self.finished(&c, r);
            if ok {
                self.reload();
                self.say();
            }
            return true;
        }
        false
    }

    fn wake(&self, _now: Now) -> Option<i64> {
        self.job.as_ref().map(|_| kit::JOB_MS)
    }
}

pub fn main() -> i32 {
    let mut d = Disks::read();
    d.say();
    kit::run("disks", "disks", None, Hints { min: (720, 480), size: (940, 620) }, &mut d)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use slate_sysinfo::block::{Holds, Part};

    fn holds(fs: &str, kind: &str, label: &str) -> Option<Holds> {
        Some(Holds { fs: fs.into(), kind: kind.into(), label: label.into(), uuid: "1234-ABCD".into() })
    }

    pub fn sample() -> Disks {
        let part = |name: &str, n: u32, start: u64, sectors: u64, label: &str, h| Part {
            name: name.into(),
            number: n,
            start,
            sectors,
            label: label.into(),
            ptype: "0fc63daf-8483-4772-8e79-3d69d8477de4".into(),
            holds: h,
        };
        let system = Disk {
            name: "nvme0n1".into(),
            model: "WD_BLACK SN850X 500GB".into(),
            sectors: 976_773_168,
            table: Some("gpt".into()),
            parts: std::vec![
                Part {
                    ptype: "c12a7328-f81f-11d2-ba4b-00a0c93ec93b".into(),
                    ..part("nvme0n1p1", 1, 2048, 1_048_576, "slate-esp", holds("vfat", "FAT32", "SLATE-ESP"))
                },
                part(
                    "nvme0n1p2",
                    2,
                    1_050_624,
                    975_720_000,
                    "slate-root",
                    holds("slatecrypt", "Encrypted (SlateCrypt)", "")
                ),
            ],
            ..Disk::default()
        };
        let stick = Disk {
            name: "sda".into(),
            model: "DataTraveler 3.0".into(),
            sectors: 60_437_492,
            removable: true,
            table: Some("gpt".into()),
            parts: std::vec![part("sda1", 1, 2048, 20_971_520, "photos", holds("vfat", "FAT32", "PHOTOS"))],
            ..Disk::default()
        };
        let mapped = std::vec![Mapped {
            name: "dm-0".into(),
            under: "nvme0n1p2".into(),
            holds: holds("slatefs", "SlateFS", "slate-root")
        }];
        let mounts = std::vec![
            Mount { source: "/dev/dm-0".into(), path: "/".into(), fs: "slatefs".into() },
            Mount { source: "/dev/nvme0n1p1".into(), path: "/boot/efi".into(), fs: "vfat".into() },
        ];
        let subvols = std::vec![
            Subvol { id: 3, name: "system-3".into(), flags: std::vec!["default".into(), "mounted-here".into()] },
            Subvol { id: 2, name: "system-2".into(), flags: std::vec!["fallback".into()] },
            Subvol { id: 4, name: "home".into(), flags: Vec::new() },
        ];
        Disks::new(std::vec![system, stick], mapped, mounts, subvols)
    }

    #[test]
    fn mounting_and_renaming() {
        let mut d = sample();
        assert_eq!(d.disks[d.disk].name, "sda");
        // FAT32: the kernel can't mount it; rename is offered.
        assert!(!d.offered('m') && d.offered('r'));
        d.key(0, Some('r'), 0);
        assert!(d.form.as_ref().is_some_and(|f| f.rename));
        for _ in 0..6 {
            d.key(KEY_BACKSPACE, None, 0);
        }
        for c in "Trip".chars() {
            d.key(0, Some(c), 0);
        }
        assert_eq!(d.form_change(), Ok(Change::Name { part: "sda1".into(), name: "Trip".into() }));
        d.form = None;
        // SlateFS: Mount; once mounted in /run/media, Unmount.
        d.disks[1].parts[0].holds = holds("slatefs", "SlateFS", "Trip");
        assert!(d.offered('m'));
        d.mounts.push(Mount { source: "/dev/sda1".into(), path: "/run/media/ada/Trip".into(), fs: "slatefs".into() });
        assert!(d.offered('m') && !d.offered('r'), "mounted: unmount, not rename");
        assert_eq!(d.media_mount().as_deref(), Some("/run/media/ada/Trip"));
    }

    #[test]
    fn maps_and_what_is_offered() {
        let mut d = sample();
        assert_eq!(d.disk, 1, "the first disk that isn't the system's");
        assert!(d.is_system(0));
        assert_eq!(segments(&d.disks[1]).len(), 2, "a partition and the free space after it");
        // The partition: format and delete; the free space: new.
        assert!(d.offered('f') && d.offered('d') && !d.offered('n') && d.offered('e'));
        d.key(KEY_RIGHT, None, 0);
        assert!(matches!(d.chosen(), Some(Segment::Free(..))));
        assert!(d.offered('n'));
        // The system's disk offers nothing.
        d.key(KEY_UP, None, 0);
        assert_eq!(d.disk, 0);
        for k in ['n', 'f', 'd', 'e'] {
            assert!(!d.offered(k), "{k}");
        }
        assert_eq!(d.blocked(true).as_deref(), Some("This is the system's disk: Slate runs from it."));
        d.segment = 1;
        let rows = d.details(&d.disks[0].clone());
        assert!(
            rows.iter().any(|(l, v)| l == "unlocked" && v == "as dm-0, holding SlateFS \"slate-root\""),
            "{rows:?}"
        );
        assert!(rows.iter().any(|(l, v)| l == "mounted at" && v == "/"));
        assert!(d.holds_root(&d.disks[0].clone()));
    }

    #[test]
    fn forms_and_questions() {
        let mut d = sample();
        d.key(KEY_RIGHT, None, 0);
        d.key(0, Some('n'), 0);
        let f = d.form.as_ref().unwrap();
        let max = 60_437_492 / 2048 - 10_241 - 1;
        assert!(f.size.text().parse::<u64>().unwrap() >= max - 2, "{}", f.size.text());
        // Too big a size is refused, with words.
        for _ in 0..9 {
            d.key(KEY_BACKSPACE, None, 0);
        }
        for c in "999999".chars() {
            d.key(0, Some(c), 0);
        }
        d.key(KEY_ENTER, None, 0);
        assert!(d.form.as_ref().unwrap().error.as_deref().unwrap().starts_with("The size is 1 to"));
        for _ in 0..6 {
            d.key(KEY_BACKSPACE, None, 0);
        }
        for c in "x100".chars() {
            d.key(0, Some(c), 0);
        }
        d.key(KEY_TAB, None, 0);
        d.key(KEY_TAB, None, 0);
        d.key(KEY_RIGHT, None, 0);
        assert_eq!(
            d.form_change(),
            Ok(Change::Add {
                disk: "sda".into(),
                start_mib: 10_241,
                size_mib: 100,
                format: Format::SlateFs,
                name: "Data".into()
            })
        );
        d.key(KEY_ESC, None, 0);
        assert!(d.form.is_none());
        // Formatting asks again; Esc leaves it.
        d.key(KEY_LEFT, None, 0);
        d.key(0, Some('f'), 0);
        for c in "Holiday".chars() {
            d.key(0, Some(c), 0);
        }
        d.key(KEY_ENTER, None, 0);
        let (c, q) = d.confirm.clone().unwrap();
        assert_eq!(c, Change::Format { part: "sda1".into(), format: Format::Fat32, label: "HOLIDAY".into() });
        assert!(q.starts_with("Format sda1?"));
        d.key(KEY_ESC, None, 0);
        assert!(d.confirm.is_none());
        d.key(0, Some('e'), 0);
        assert_eq!(d.confirm.as_ref().unwrap().0, Change::Table { disk: "sda".into() });
        d.key(KEY_ESC, None, 0);
        d.finished(&Change::Delete { part: "sda1".into() }, Err("It is in use, at /x.".into()));
        assert_eq!(d.status, Some(("Nothing was changed: It is in use, at /x.".into(), true)));
    }
}
