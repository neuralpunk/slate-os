// SPDX-License-Identifier: MIT OR Apache-2.0

//! The System Monitor (ADR 0112), `system-monitor`, in three tabs:
//!
//! - **Processes:** every process, with its account, its share of the
//!   processors, its memory and its number; Linux programs carry the
//!   Linux tag (moss). Typing searches, a click on a column sorts by it,
//!   Delete asks to end the chosen process: End asks it to stop
//!   (SIGTERM), Kill stops it at once (SIGKILL). Another account's
//!   processes are ended through the privilege broker (`end=`), behind
//!   the approval dialog. ctrl + t shows them as a tree (children under
//!   their parents); ctrl + i, or a double click, shows one's details:
//!   its threads, its open files, what it has read and written, and its
//!   priority, which + and - change (the owner may lower it; raising it
//!   takes an administrator).
//! - **Resources:** the processors (the whole and each one), memory, the
//!   network and the disks, over the last two minutes.
//! - **File systems:** what is mounted, and how full each is.
//!
//! It samples /proc every two seconds ([`Sample::read`]); the figures are
//! the differences between two samples. What it reads is
//! `slate_sysinfo::procs` and `slate_sysinfo::load`.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_display::input::{
    KEY_DELETE, KEY_DOWN, KEY_END, KEY_ENTER, KEY_ESC, KEY_HOME, KEY_KPENTER, KEY_LEFT, KEY_PAGEDOWN, KEY_PAGEUP,
    KEY_RIGHT, KEY_TAB, KEY_UP,
};
use slate_strata::fonts::Fonts;
use slate_strata_client::mods::SHIFT;
use slate_sysinfo::load::{self, CpuTime, DiskCount, Memory, Mount, NetCount};
use slate_sysinfo::procs::{self, Proc};
use slate_ui::edit::LineEdit;
use slate_ui::graphite::Palette;
use slate_ui::icon::Icon;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;

use crate::kit::{self, App, Effect, Hints, Job, Now};

/// How often the monitor samples (ms), and how many samples its charts
/// keep (two minutes).
const SAMPLE_MS: i64 = 2000;
const HISTORY: usize = 60;
const ROW_H: f32 = 30.0;

const TABS: [&str; 3] = ["Processes", "Resources", "File systems"];

/// What /proc says at one moment.
#[derive(Clone, Debug, Default)]
pub struct Sample {
    pub procs: Vec<Proc>,
    /// The whole machine, then each processor.
    pub cpus: Vec<CpuTime>,
    pub memory: Memory,
    pub net: Vec<NetCount>,
    pub disks: Vec<DiskCount>,
    /// Mounted storage: the mount, its size and free space in bytes.
    pub mounts: Vec<(Mount, u64, u64)>,
}

impl Sample {
    pub fn read() -> Sample {
        let mounts = load::mounts(&load::read("/proc/mounts"))
            .into_iter()
            .filter(load::is_storage)
            .filter_map(|m| load::usage(&m.path).map(|(t, f)| (m, t, f)))
            .collect();
        Sample {
            procs: procs::read_all(),
            cpus: load::cpu_times(&load::read("/proc/stat")),
            memory: load::memory(&load::read("/proc/meminfo")),
            net: load::net_counts(&load::read("/proc/net/dev")),
            disks: load::disk_counts(&load::read("/proc/diskstats")),
            mounts,
        }
    }
}

/// A process as the table shows it.
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub pid: i32,
    pub name: String,
    pub user: String,
    pub uid: u32,
    /// Its share of the whole machine since the last sample, in percent.
    pub cpu: f32,
    /// Resident memory, KiB.
    pub memory: u64,
    pub linux: bool,
    pub cmdline: String,
    pub ppid: i32,
    /// Its nice value.
    pub nice: i32,
}

/// One process's details (ctrl + i), read when shown and at each sample.
#[derive(Clone, Debug, PartialEq)]
pub struct Details {
    pub pid: i32,
    pub threads: Vec<procs::Thread>,
    /// Its descriptors and what they name; None: another account's.
    pub files: Option<Vec<(u32, String)>>,
    pub io: Option<procs::Io>,
    pub nice: i32,
}

/// The most threads and files the details list.
const DETAIL_MAX: usize = 200;

impl Details {
    pub fn read(pid: i32) -> Details {
        Details {
            pid,
            threads: procs::threads(pid),
            files: procs::open_files(pid, DETAIL_MAX),
            io: procs::io(pid),
            nice: slate_rt::process::nice_of(pid).unwrap_or(0),
        }
    }
}

/// The processes in tree order: each after its parent, siblings in the
/// order `rows` gives; (index into `rows`, depth). A process whose parent
/// isn't listed is a root.
pub fn tree_order(rows: &[&Row]) -> Vec<(usize, usize)> {
    let pids: BTreeMap<i32, usize> = rows.iter().enumerate().map(|(i, r)| (r.pid, i)).collect();
    let mut children: BTreeMap<i32, Vec<usize>> = BTreeMap::new();
    let mut roots = Vec::new();
    for (i, r) in rows.iter().enumerate() {
        if r.ppid != r.pid && pids.contains_key(&r.ppid) {
            children.entry(r.ppid).or_default().push(i);
        } else {
            roots.push(i);
        }
    }
    let mut out = Vec::with_capacity(rows.len());
    let mut stack: Vec<(usize, usize)> = roots.into_iter().rev().map(|i| (i, 0)).collect();
    while let Some((i, depth)) = stack.pop() {
        out.push((i, depth));
        if let Some(c) = children.get(&rows[i].pid) {
            stack.extend(c.iter().rev().map(|&k| (k, depth + 1)));
        }
    }
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Col {
    Name,
    User,
    Cpu,
    Memory,
    Pid,
}

/// Asking before ending a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Confirm {
    pub pid: i32,
    pub name: String,
    /// 0 Cancel, 1 End, 2 Kill.
    pub focus: u8,
}

#[derive(Debug)]
pub struct Monitor {
    pub tab: usize,
    users: BTreeMap<u32, String>,
    me: u32,
    last: Option<(Sample, i64)>,
    pub rows: Vec<Row>,
    /// The whole machine's busy share (0 to 1), oldest first; each
    /// processor's now.
    pub cpu_history: Vec<f32>,
    pub cores: Vec<f32>,
    pub memory: Memory,
    pub memory_history: Vec<f32>,
    /// Received and sent, bytes a second.
    pub net_rate: (f64, f64),
    pub net_history: Vec<(f64, f64)>,
    /// Read and written, bytes a second.
    pub disk_rate: (f64, f64),
    pub disk_history: Vec<(f64, f64)>,
    pub mounts: Vec<(Mount, u64, u64)>,
    pub query: LineEdit,
    pub sort: Col,
    pub descending: bool,
    pub selected: Option<i32>,
    first: usize,
    shown: usize,
    pub confirm: Option<Confirm>,
    /// Children under their parents (ctrl + t).
    pub tree: bool,
    pub details: Option<Details>,
    /// What the last action did, and whether it failed.
    pub status: Option<(String, bool)>,
    job: Option<(Job, String)>,
    next_sample: i64,
    tab_hits: Vec<Area>,
    header_hits: Vec<(Area, Col)>,
    row_hits: Vec<(Area, i32)>,
    confirm_hits: Vec<(Area, u8)>,
}

impl Monitor {
    pub fn new(users: BTreeMap<u32, String>, me: u32) -> Monitor {
        Monitor {
            tab: 0,
            users,
            me,
            last: None,
            rows: Vec::new(),
            cpu_history: Vec::new(),
            cores: Vec::new(),
            memory: Memory::default(),
            memory_history: Vec::new(),
            net_rate: (0.0, 0.0),
            net_history: Vec::new(),
            disk_rate: (0.0, 0.0),
            disk_history: Vec::new(),
            mounts: Vec::new(),
            query: LineEdit::new("").with_max(64),
            sort: Col::Cpu,
            descending: true,
            selected: None,
            first: 0,
            shown: 10,
            confirm: None,
            tree: false,
            details: None,
            status: None,
            job: None,
            next_sample: 0,
            tab_hits: Vec::new(),
            header_hits: Vec::new(),
            row_hits: Vec::new(),
            confirm_hits: Vec::new(),
        }
    }

    /// Take sample `s`, made at monotonic `mono` ms: the rates are its
    /// differences from the last one.
    pub fn sample(&mut self, s: Sample, mono: i64) {
        let first = self.last.is_none();
        let (prev, dt) = match &self.last {
            Some((p, t)) => (Some(p), ((mono - t) as f64 / 1000.0).max(0.001)),
            None => (None, 1.0),
        };
        let machine = |s: &Sample| s.cpus.first().copied().unwrap_or_default();
        let total_ticks = prev.map_or(0, |p| machine(&s).total.saturating_sub(machine(p).total));
        let before: BTreeMap<i32, u64> =
            prev.map(|p| p.procs.iter().map(|q| (q.pid, q.ticks)).collect()).unwrap_or_default();
        self.rows = s
            .procs
            .iter()
            .map(|q| {
                let ticks = before.get(&q.pid).map_or(0, |b| q.ticks.saturating_sub(*b));
                let cpu = if total_ticks == 0 { 0.0 } else { (ticks as f32 / total_ticks as f32 * 100.0).min(100.0) };
                Row {
                    pid: q.pid,
                    name: q.name.clone(),
                    user: self.users.get(&q.uid).cloned().unwrap_or_else(|| q.uid.to_string()),
                    uid: q.uid,
                    cpu,
                    memory: q.rss,
                    linux: q.linux,
                    cmdline: q.cmdline.clone(),
                    ppid: q.ppid,
                    nice: q.nice,
                }
            })
            .collect();
        let push = |h: &mut Vec<f32>, v: f32| {
            h.push(v);
            if h.len() > HISTORY {
                h.remove(0);
            }
        };
        if let Some(p) = prev {
            push(&mut self.cpu_history, machine(&s).busy_since(&machine(p)));
            self.cores = s.cpus.iter().skip(1).zip(p.cpus.iter().skip(1)).map(|(n, b)| n.busy_since(b)).collect();
            let sum = |v: &[NetCount]| v.iter().fold((0u64, 0u64), |a, n| (a.0 + n.received, a.1 + n.sent));
            let (n1, n0) = (sum(&s.net), sum(&p.net));
            self.net_rate = (n1.0.saturating_sub(n0.0) as f64 / dt, n1.1.saturating_sub(n0.1) as f64 / dt);
            // Disks, not the devices mapped over them (their I/O is the
            // disks' too).
            let dsum = |v: &[DiskCount]| {
                v.iter()
                    .filter(|d| !d.name.starts_with("dm-"))
                    .fold((0u64, 0u64), |a, d| (a.0 + d.read, a.1 + d.written))
            };
            let (d1, d0) = (dsum(&s.disks), dsum(&p.disks));
            self.disk_rate =
                (d1.0.saturating_sub(d0.0) as f64 * 512.0 / dt, d1.1.saturating_sub(d0.1) as f64 * 512.0 / dt);
            for (h, v) in [(&mut self.net_history, self.net_rate), (&mut self.disk_history, self.disk_rate)] {
                h.push(v);
                if h.len() > HISTORY {
                    h.remove(0);
                }
            }
        } else {
            self.cores = alloc::vec![0.0; s.cpus.len().saturating_sub(1)];
        }
        self.memory = s.memory;
        let used = if s.memory.total == 0 { 0.0 } else { s.memory.used() as f32 / s.memory.total as f32 };
        push(&mut self.memory_history, used);
        self.mounts = s.mounts.clone();
        if first {
            crate::trace!(
                "system-monitor: {} processes, {} processors, {} of memory",
                self.rows.len(),
                self.cores.len(),
                slate_sysinfo::size(s.memory.total * 1024)
            );
        }
        self.last = Some((s, mono));
        if self.selected.is_none_or(|p| !self.visible().iter().any(|r| r.pid == p)) {
            self.selected = self.visible().first().map(|r| r.pid);
        }
    }

    /// The rows the search lets through, in the chosen order.
    pub fn visible(&self) -> Vec<&Row> {
        let q = self.query.text().to_lowercase();
        let mut v: Vec<&Row> = self
            .rows
            .iter()
            .filter(|r| {
                q.is_empty()
                    || r.name.to_lowercase().contains(&q)
                    || r.cmdline.to_lowercase().contains(&q)
                    || r.pid.to_string() == q
                    || r.user.to_lowercase() == q
            })
            .collect();
        v.sort_by(|a, b| {
            let o = match self.sort {
                Col::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                Col::User => a.user.cmp(&b.user),
                Col::Cpu => a.cpu.partial_cmp(&b.cpu).unwrap_or(core::cmp::Ordering::Equal),
                Col::Memory => a.memory.cmp(&b.memory),
                Col::Pid => a.pid.cmp(&b.pid),
            };
            let o = if self.descending { o.reverse() } else { o };
            o.then(a.pid.cmp(&b.pid))
        });
        // The tree, siblings in that order (not while searching: matches
        // are listed alone).
        if self.tree && q.is_empty() {
            return tree_order(&v).into_iter().map(|(i, _)| v[i]).collect();
        }
        v
    }

    /// Each visible row's depth in the tree (0 without it).
    fn depths(&self) -> BTreeMap<i32, usize> {
        if !self.tree || !self.query.is_empty() {
            return BTreeMap::new();
        }
        let v: Vec<&Row> = self.rows.iter().collect();
        tree_order(&v).into_iter().map(|(i, d)| (v[i].pid, d)).collect()
    }

    /// Show the chosen process's details.
    fn open_details(&mut self) -> Effect {
        let Some(r) = self.chosen() else { return Effect::None };
        let d = Details::read(r.pid);
        crate::trace!(
            "system-monitor: details of {} (pid {}): {} threads, {} open files, nice {}",
            r.name,
            r.pid,
            d.threads.len(),
            d.files.as_ref().map_or_else(|| String::from("unknown"), |f| f.len().to_string()),
            d.nice
        );
        self.details = Some(d);
        Effect::Redraw
    }

    /// Change the shown process's nice value by `by` (+ lowers its
    /// priority).
    pub fn renice(&mut self, by: i32) -> Effect {
        let Some(d) = &mut self.details else { return Effect::None };
        let to = (d.nice + by).clamp(-20, 19);
        if to == d.nice {
            return Effect::None;
        }
        self.status = Some(match slate_rt::process::set_nice(d.pid, to) {
            Ok(()) => {
                d.nice = to;
                crate::trace!("system-monitor: pid {} is now nice {to}", d.pid);
                (alloc::format!("Its priority is now {} (nice {to}).", priority_word(to)), false)
            }
            Err(slate_rt::Errno::EACCES) => (String::from("Raising a priority takes an administrator."), true),
            Err(slate_rt::Errno::EPERM) => (String::from("Only its owner can change its priority."), true),
            Err(e) => (alloc::format!("Couldn't change its priority: {e}"), true),
        });
        Effect::Redraw
    }

    fn chosen(&self) -> Option<&Row> {
        self.selected.and_then(|p| self.rows.iter().find(|r| r.pid == p))
    }

    fn say_chosen(&self) {
        if let Some(r) = self.chosen() {
            crate::trace!("system-monitor: chosen {} (pid {})", r.name, r.pid);
        }
    }

    fn sort_by(&mut self, c: Col) {
        if self.sort == c {
            self.descending = !self.descending;
        } else {
            self.sort = c;
            // Numbers from the largest, names from A.
            self.descending = matches!(c, Col::Cpu | Col::Memory);
        }
    }

    fn move_selection(&mut self, by: isize) -> Effect {
        let v = self.visible();
        if v.is_empty() {
            return Effect::None;
        }
        let at = self.selected.and_then(|p| v.iter().position(|r| r.pid == p)).unwrap_or(0) as isize;
        let to = (at + by).clamp(0, v.len() as isize - 1) as usize;
        self.selected = Some(v[to].pid);
        self.say_chosen();
        Effect::Redraw
    }

    fn ask_to_end(&mut self) -> Effect {
        let Some(r) = self.chosen() else { return Effect::None };
        self.confirm = Some(Confirm { pid: r.pid, name: r.name.clone(), focus: 1 });
        Effect::Redraw
    }

    /// End the process asked about: SIGTERM, or SIGKILL when `kill`.
    /// One's own directly; another account's through the broker.
    pub fn end(&mut self, kill: bool) -> Effect {
        let Some(c) = self.confirm.take() else { return Effect::None };
        let (sig, word) = if kill { (9, "KILL") } else { (15, "TERM") };
        let what = alloc::format!("{} (pid {})", c.name, c.pid);
        let theirs = self.rows.iter().find(|r| r.pid == c.pid).is_some_and(|r| r.uid != self.me) && self.me != 0;
        if theirs {
            let action = alloc::format!("end={} {word}", c.pid);
            match Job::start(move || kit::broker(&action).map(|()| String::new())) {
                Ok(j) => {
                    self.status = Some((alloc::format!("Asking to end {what}…"), false));
                    self.job = Some((j, what));
                }
                Err(e) => self.status = Some((alloc::format!("Couldn't end {what}: {e}"), true)),
            }
            return Effect::Redraw;
        }
        self.finished(
            &what,
            slate_rt::process::kill(c.pid, sig).map(|()| String::new()).map_err(|e| alloc::format!("{e}")),
        );
        Effect::Redraw
    }

    /// An ending's outcome.
    pub fn finished(&mut self, what: &str, r: Result<String, String>) {
        self.status = Some(match r {
            Ok(_) => {
                crate::trace!("system-monitor: ended {what}");
                (alloc::format!("Ended {what}."), false)
            }
            Err(e) if e == "cancelled" => (alloc::format!("{what} was left running."), false),
            Err(e) => (alloc::format!("Couldn't end {what}: {e}."), true),
        });
        // The next sample shows it gone.
        self.next_sample = 0;
    }

    fn resources_said(&self) {
        crate::trace!(
            "system-monitor: resources: {} processors at {:.0}%, memory {} of {}, network {} in, disks {} read",
            self.cores.len(),
            self.cpu_history.last().copied().unwrap_or(0.0) * 100.0,
            slate_sysinfo::size(self.memory.used() * 1024),
            slate_sysinfo::size(self.memory.total * 1024),
            kit::rate(self.net_rate.0),
            kit::rate(self.disk_rate.0)
        );
    }

    fn switch(&mut self, to: usize) -> Effect {
        self.tab = to % TABS.len();
        if self.tab == 1 {
            self.resources_said();
        } else if self.tab == 2 {
            crate::trace!("system-monitor: {} file systems", self.mounts.len());
        }
        Effect::Redraw
    }

    fn draw_processes(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, body: Area) {
        let label = p.style(&f.mono, 11.0, pal.muted);
        let field = Area::new(body.x + 20.0, body.y, 300.0_f32.min(body.w - 40.0), 34.0);
        kit::field(p, pal, f, Area::new(field.x, field.y, field.w, field.h), &self.query, true, "Search processes");
        let shown_rows = self.visible().len();
        let count = alloc::format!("{shown_rows} of {} processes", self.rows.len());
        let cw = p.measure(&label, &count);
        p.line(&label, body.x + body.w - 20.0 - cw, field.y + 9.0, 16.0, &count);
        let header = Area::new(body.x, field.y + field.h + 12.0, body.w, 26.0);
        p.fill(header, 0.0, pal.header);
        let right = body.x + body.w - 20.0;
        let cols = [
            ("name", Col::Name, body.x + 30.0),
            ("user", Col::User, right - 330.0),
            ("cpu", Col::Cpu, right - 210.0),
            ("memory", Col::Memory, right - 140.0),
            ("pid", Col::Pid, right - 50.0),
        ];
        self.header_hits.clear();
        for (l, c, cx) in cols {
            let t = if c == self.sort {
                alloc::format!("{l} {}", if self.descending { "v" } else { "^" })
            } else {
                l.to_string()
            };
            p.line(&label, cx, header.y + 5.0, 16.0, &t);
            self.header_hits.push((Area::new(cx - 6.0, header.y, 90.0, header.h), c));
        }
        let top = header.y + header.h + 4.0;
        let bottom = body.y + body.h - if self.confirm.is_some() { 58.0 } else { 0.0 };
        self.shown = ((bottom - top) / ROW_H).max(1.0) as usize;
        let rows: Vec<Row> = self.visible().into_iter().cloned().collect();
        let at = self.selected.and_then(|s| rows.iter().position(|r| r.pid == s)).unwrap_or(0);
        if at < self.first {
            self.first = at;
        } else if at >= self.first + self.shown {
            self.first = at + 1 - self.shown;
        }
        self.first = self.first.min(rows.len().saturating_sub(self.shown));
        self.row_hits.clear();
        let name_s = p.style(&f.regular, 13.5, pal.text_1);
        let num = p.style(&f.mono, 12.0, pal.text_3);
        let quiet = p.style(&f.regular, 14.0, pal.muted);
        if rows.is_empty() {
            let msg = if self.rows.is_empty() { "Reading the processes…" } else { "No process matches." };
            let w = p.measure(&quiet, msg);
            p.line(&quiet, body.x + (body.w - w) / 2.0, top + 40.0, 20.0, msg);
        }
        let moss = pal.accents.moss;
        let depths = self.depths();
        for (i, r) in rows.iter().enumerate().skip(self.first).take(self.shown) {
            let y = top + (i - self.first) as f32 * ROW_H;
            let a = Area::new(body.x + 10.0, y, body.w - 20.0, ROW_H - 2.0);
            let sel = self.selected == Some(r.pid);
            if sel {
                p.fill(a, 6.0, pal.list_selected);
            }
            let (ns, ms) = if sel {
                (p.style(&f.regular, 13.5, pal.window), p.style(&f.mono, 12.0, pal.window))
            } else {
                (name_s, num)
            };
            // In the tree, indented by depth, a mark before children.
            let depth = depths.get(&r.pid).copied().unwrap_or(0).min(12) as f32;
            let nx = body.x + 30.0 + 16.0 * depth;
            if depth > 0.0 {
                let mark = if sel { pal.window } else { pal.decor };
                p.fill(Area::new(nx - 11.0, y + 6.0, 1.0, 9.0), 0.0, mark);
                p.fill(Area::new(nx - 11.0, y + 14.0, 6.0, 1.0), 0.0, mark);
            }
            let name_w = right - 340.0 - nx - if r.linux { 50.0 } else { 0.0 };
            let shown = kit::fit(p, &ns, &r.name, name_w);
            let nw = p.line(&ns, nx, y + 4.0, 20.0, &shown) + (nx - body.x - 30.0);
            if r.linux {
                // The Linux domain's marker (STRATA_COLORS.md): a tag, in
                // words too.
                let tag = p.style(&f.mono, 10.5, moss.text);
                let tw = p.measure(&tag, "linux") + 12.0;
                let t = Area::new(body.x + 38.0 + nw, y + 6.0, tw, 17.0);
                p.fill(t, 4.0, moss.tint);
                p.border(t, 4.0, 1.0, moss.border);
                p.line(&tag, t.x + 6.0, t.y, t.h, "linux");
            }
            let user = kit::fit(p, &ms, &r.user, 100.0);
            p.line(&ms, right - 330.0, y + 5.0, 18.0, &user);
            let have_rates = !self.cpu_history.is_empty();
            let cpu = if have_rates { alloc::format!("{:.1}%", r.cpu) } else { String::from("–") };
            p.line(&ms, right - 210.0, y + 5.0, 18.0, &cpu);
            p.line(&ms, right - 140.0, y + 5.0, 18.0, &slate_sysinfo::size(r.memory * 1024));
            p.line(&ms, right - 50.0, y + 5.0, 18.0, &r.pid.to_string());
            self.row_hits.push((a, r.pid));
        }
        if let Some(c) = &self.confirm {
            let strip = Area::new(body.x + 10.0, body.y + body.h - 52.0, body.w - 20.0, 48.0);
            let clay = pal.accents.clay;
            p.fill(strip, 8.0, clay.tint);
            p.border(strip, 8.0, 1.0, clay.border);
            let text = p.style(&f.regular, 13.5, pal.text_1);
            let ask = alloc::format!("End {} ({})? Work it hasn't saved is lost.", c.name, c.pid);
            let ask = kit::fit(p, &text, &ask, strip.w - 300.0);
            p.line(&text, strip.x + 14.0, strip.y + 14.0, 20.0, &ask);
            self.confirm_hits.clear();
            let mut x = strip.x + strip.w - 10.0;
            for (k, l) in [(2u8, "Kill"), (1, "End"), (0, "Cancel")] {
                let w = if k == 0 { 84.0 } else { 70.0 };
                x -= w;
                let b = Area::new(x, strip.y + 8.0, w, 32.0);
                let lit = c.focus == k;
                if k == 2 {
                    p.fill(b, 7.0, clay.text);
                    let s = p.style(&f.medium, 13.0, pal.window);
                    let lw = p.measure(&s, l);
                    p.line(&s, b.x + (b.w - lw) / 2.0, b.y + 6.0, 20.0, l);
                    if lit {
                        p.border(b.grow(3.0), 10.0, 2.0, pal.chalk);
                    }
                } else {
                    kit::button(p, pal, f, b, l, k == 1, lit);
                }
                self.confirm_hits.push((b, k));
                x -= 8.0;
            }
        }
    }

    fn draw_resources(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, body: Area) {
        let gap = 14.0;
        let (x0, y0) = (body.x + 20.0, body.y);
        let w = (body.w - 40.0 - gap) / 2.0;
        let h = (body.h - gap) / 2.0;
        let title = p.style(&f.medium, 14.0, pal.chalk);
        let big = p.style(&f.medium, 22.0, pal.text_1);
        let note = p.style(&f.mono, 11.0, pal.muted);
        let panel = |p: &mut Painter<'_>, i: usize| -> Area {
            let a = Area::new(x0 + (i % 2) as f32 * (w + gap), y0 + (i / 2) as f32 * (h + gap), w, h);
            p.fill(a, 10.0, pal.raised);
            a
        };
        let chart_area =
            |a: Area, top: f32, bottom: f32| Area::new(a.x + 16.0, a.y + top, a.w - 32.0, a.h - top - bottom);
        let faint = pal.chart_fill;
        // Processors.
        let a = panel(p, 0);
        p.line(&title, a.x + 16.0, a.y + 12.0, 20.0, "Processors");
        let now = self.cpu_history.last().map_or(String::from("–"), |v| alloc::format!("{:.0}%", v * 100.0));
        let nw = p.measure(&big, &now);
        p.line(&big, a.x + a.w - 16.0 - nw, a.y + 8.0, 28.0, &now);
        let c = chart_area(a, 46.0, 56.0);
        p.fill(Area::new(c.x, c.y + c.h, c.w, 1.0), 0.0, pal.border);
        kit::chart(p, c, &self.cpu_history, HISTORY, pal.chart, faint);
        // Each processor: a bar.
        let n = self.cores.len().max(1);
        let bw = ((a.w - 32.0) / n as f32).min(24.0);
        for (i, v) in self.cores.iter().enumerate() {
            let bx = a.x + 16.0 + i as f32 * bw;
            let bar = Area::new(bx, a.y + a.h - 44.0, (bw - 2.0).max(1.0), 26.0);
            p.fill(bar, 2.0, pal.meter_track);
            let fill_h = (bar.h * v.clamp(0.0, 1.0)).max(1.0);
            p.fill(Area::new(bar.x, bar.y + bar.h - fill_h, bar.w, fill_h), 2.0, pal.meter);
        }
        p.line(&note, a.x + 16.0, a.y + a.h - 16.0, 14.0, &alloc::format!("{} processors", self.cores.len()));
        // Memory.
        let a = panel(p, 1);
        p.line(&title, a.x + 16.0, a.y + 12.0, 20.0, "Memory");
        let m = &self.memory;
        let pct = if m.total == 0 { 0.0 } else { m.used() as f32 / m.total as f32 * 100.0 };
        let now = alloc::format!("{pct:.0}%");
        let nw = p.measure(&big, &now);
        p.line(&big, a.x + a.w - 16.0 - nw, a.y + 8.0, 28.0, &now);
        let c = chart_area(a, 46.0, 40.0);
        p.fill(Area::new(c.x, c.y + c.h, c.w, 1.0), 0.0, pal.border);
        kit::chart(p, c, &self.memory_history, HISTORY, pal.chart, faint);
        let line = alloc::format!(
            "{} used of {} · {} cached",
            slate_sysinfo::size(m.used() * 1024),
            slate_sysinfo::size(m.total * 1024),
            slate_sysinfo::size((m.cached + m.buffers) * 1024)
        );
        p.line(&note, a.x + 16.0, a.y + a.h - 28.0, 14.0, &line);
        // The network and the disks: two lines, in and out.
        for (i, name, hist, now, words) in [
            (2, "Network", &self.net_history, self.net_rate, ("received", "sent")),
            (3, "Disks", &self.disk_history, self.disk_rate, ("read", "written")),
        ] {
            let a = panel(p, i);
            p.line(&title, a.x + 16.0, a.y + 12.0, 20.0, name);
            let c = chart_area(a, 46.0, 40.0);
            p.fill(Area::new(c.x, c.y + c.h, c.w, 1.0), 0.0, pal.border);
            let top = hist.iter().fold(64.0 * 1024.0f64, |m, v| m.max(v.0).max(v.1));
            let ins: Vec<f32> = hist.iter().map(|v| (v.0 / top) as f32).collect();
            let outs: Vec<f32> = hist.iter().map(|v| (v.1 / top) as f32).collect();
            kit::chart(p, c, &ins, HISTORY, pal.chart, faint);
            kit::chart(p, c, &outs, HISTORY, pal.muted, pal.muted.with_alpha(0));
            let scale = kit::rate(top);
            let sw = p.measure(&note, &scale);
            p.line(&note, a.x + a.w - 16.0 - sw, a.y + 16.0, 14.0, &scale);
            // A key: the line's colour and its words.
            let mut x = a.x + 16.0;
            for (ink, word, v) in [(pal.chart, words.0, now.0), (pal.muted, words.1, now.1)] {
                p.fill(Area::new(x, a.y + a.h - 22.0, 12.0, 2.0), 0.0, ink);
                x += 18.0;
                x += p.line(&note, x, a.y + a.h - 29.0, 14.0, &alloc::format!("{word} {}", kit::rate(v))) + 18.0;
            }
        }
    }

    fn draw_file_systems(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, body: Area) {
        let name_s = p.style(&f.medium, 14.0, pal.text_1);
        let meta = p.style(&f.mono, 11.5, pal.text_4);
        let quiet = p.style(&f.regular, 14.0, pal.muted);
        if self.mounts.is_empty() {
            p.line(&quiet, body.x + 20.0, body.y + 20.0, 20.0, "Nothing is mounted.");
        }
        let mut y = body.y;
        for (m, total, free) in &self.mounts {
            if y + 64.0 > body.y + body.h {
                break;
            }
            let a = Area::new(body.x + 20.0, y, body.w - 40.0, 58.0);
            p.fill(a, 8.0, pal.raised);
            p.icon(Icon::Disk, a.x + 14.0, a.y + 12.0, 18.0, pal.text_3);
            p.line(&name_s, a.x + 44.0, a.y + 9.0, 20.0, &m.path);
            let what = alloc::format!("{} · {}", m.source.trim_start_matches("/dev/"), m.fs);
            p.line(&meta, a.x + 44.0, a.y + 31.0, 16.0, &what);
            let used = total.saturating_sub(*free);
            let words = alloc::format!("{} free of {}", slate_sysinfo::size(*free), slate_sysinfo::size(*total));
            let ww = p.measure(&meta, &words);
            p.line(&meta, a.x + a.w - 14.0 - ww, a.y + 9.0, 16.0, &words);
            let bar = Area::new(a.x + a.w - 214.0, a.y + 34.0, 200.0, 8.0);
            p.fill(bar, 4.0, pal.meter_track);
            let share = if *total == 0 { 0.0 } else { used as f32 / *total as f32 };
            // Nearly full is a warning (ochre), said in words too.
            let ink = if share > 0.9 { pal.accents.ochre.text } else { pal.meter };
            p.fill(Area::new(bar.x, bar.y, (bar.w * share).max(4.0), bar.h), 4.0, ink);
            if share > 0.9 {
                let s = p.style(&f.mono, 11.0, pal.accents.ochre.text);
                let t = "nearly full";
                let tw = p.measure(&s, t);
                p.line(&s, bar.x - 12.0 - tw, a.y + 30.0, 16.0, t);
            }
            y += 66.0;
        }
    }
}

impl App for Monitor {
    fn draw(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area) {
        self.tab_hits = kit::tabs(p, pal, f, a.x + 16.0, a.y + 14.0, &TABS, self.tab);
        // A summary at the right of the tabs.
        let note = p.style(&f.mono, 11.0, pal.muted);
        let cpu = self.cpu_history.last().map_or(String::from("–"), |v| alloc::format!("{:.0}%", v * 100.0));
        let summary = alloc::format!(
            "cpu {cpu} · memory {} of {}",
            slate_sysinfo::size(self.memory.used() * 1024),
            slate_sysinfo::size(self.memory.total * 1024)
        );
        let sw = p.measure(&note, &summary);
        p.line(&note, a.x + a.w - 20.0 - sw, a.y + 21.0, 16.0, &summary);
        let status_h = if self.status.is_some() { 28.0 } else { 0.0 };
        let body = Area::new(a.x, a.y + 60.0, a.w, a.h - 60.0 - 44.0 - status_h);
        match self.tab {
            0 => self.draw_processes(p, pal, f, body),
            1 => self.draw_resources(p, pal, f, body),
            _ => self.draw_file_systems(p, pal, f, body),
        }
        if let (0, Some(d)) = (self.tab, &self.details) {
            let r = self.rows.iter().find(|r| r.pid == d.pid);
            draw_details(p, pal, f, a, body, d, r);
        }
        if let Some((s, err)) = &self.status {
            let ink = if *err { pal.accents.clay.text } else { pal.text_2 };
            let st = p.style(&f.regular, 13.0, ink);
            let s = kit::fit(p, &st, s, a.w - 40.0);
            p.line(&st, a.x + 20.0, a.y + a.h - 44.0 - status_h + 4.0, 20.0, &s);
        }
        let hints: &[(&str, &str)] = match (self.tab, &self.confirm) {
            (0, Some(_)) => &[("enter", "end"), ("tab", "choose"), ("esc", "cancel")],
            (0, None) if self.details.is_some() => &[],
            (0, None) => {
                &[("type", "search"), ("↑↓", "choose"), ("ctrl i", "details"), ("ctrl t", "tree"), ("del", "end")]
            }
            _ => &[("tab", "next tab")],
        };
        kit::hints(p, pal, f, a, hints);
    }

    fn key(&mut self, code: u16, ch: Option<char>, mods: u8) -> Effect {
        let shift = mods & SHIFT != 0;
        let ctrl = mods & slate_strata_client::mods::CTRL != 0;
        if self.details.is_some() {
            return match (code, ch) {
                (KEY_ESC | KEY_ENTER | KEY_KPENTER, _) => {
                    self.details = None;
                    Effect::Redraw
                }
                (_, Some('+')) => self.renice(1),
                (_, Some('-')) => self.renice(-1),
                _ => Effect::None,
            };
        }
        if self.tab == 0 && ctrl {
            match ch.map(|c| c.to_ascii_lowercase()) {
                Some('t') => {
                    self.tree = !self.tree;
                    crate::trace!("system-monitor: the tree {}", if self.tree { "shown" } else { "hidden" });
                    return Effect::Redraw;
                }
                Some('i') => return self.open_details(),
                _ => {}
            }
        }
        if let Some(c) = &mut self.confirm {
            match code {
                KEY_ESC => self.confirm = None,
                KEY_LEFT => c.focus = c.focus.saturating_sub(1),
                KEY_RIGHT => c.focus = (c.focus + 1).min(2),
                KEY_TAB if shift => c.focus = (c.focus + 2) % 3,
                KEY_TAB => c.focus = (c.focus + 1) % 3,
                KEY_ENTER | KEY_KPENTER => {
                    return match c.focus {
                        0 => {
                            self.confirm = None;
                            Effect::Redraw
                        }
                        k => self.end(k == 2),
                    };
                }
                _ => return Effect::None,
            }
            return Effect::Redraw;
        }
        match code {
            KEY_TAB => return self.switch(if shift { self.tab + TABS.len() - 1 } else { self.tab + 1 }),
            _ if self.tab != 0 => return Effect::None,
            KEY_UP => return self.move_selection(-1),
            KEY_DOWN => return self.move_selection(1),
            KEY_PAGEUP => return self.move_selection(-(self.shown as isize)),
            KEY_PAGEDOWN => return self.move_selection(self.shown as isize),
            KEY_HOME if self.query.is_empty() => return self.move_selection(isize::MIN / 2),
            KEY_END if self.query.is_empty() => return self.move_selection(isize::MAX / 2),
            KEY_DELETE => return self.ask_to_end(),
            KEY_ESC if !self.query.is_empty() => {
                self.query.clear();
                return Effect::Redraw;
            }
            KEY_ENTER | KEY_KPENTER => return self.ask_to_end(),
            _ => {}
        }
        if kit::edit_key(&mut self.query, code, ch, mods, |_| true) {
            self.selected = self.visible().first().map(|r| r.pid);
            self.first = 0;
            self.say_chosen();
            return Effect::Redraw;
        }
        Effect::None
    }

    fn click(&mut self, x: f32, y: f32) -> Effect {
        if let Some(i) = self.tab_hits.iter().position(|t| t.contains(x, y)) {
            return self.switch(i);
        }
        if self.tab != 0 {
            return Effect::None;
        }
        if self.confirm.is_some() {
            if let Some((_, k)) = self.confirm_hits.iter().find(|(a, _)| a.contains(x, y)).copied() {
                if k == 0 {
                    self.confirm = None;
                    return Effect::Redraw;
                }
                return self.end(k == 2);
            }
            return Effect::None;
        }
        if let Some((_, c)) = self.header_hits.iter().find(|(a, _)| a.contains(x, y)).copied() {
            self.sort_by(c);
            return Effect::Redraw;
        }
        if let Some((_, pid)) = self.row_hits.iter().find(|(a, _)| a.contains(x, y)).copied() {
            self.selected = Some(pid);
            self.say_chosen();
            return Effect::Redraw;
        }
        Effect::None
    }

    fn double_click(&mut self, x: f32, y: f32) -> Effect {
        let e = self.click(x, y);
        if self.tab == 0 && self.row_hits.iter().any(|(a, _)| a.contains(x, y)) {
            return self.open_details();
        }
        e
    }

    fn scroll(&mut self, lines: i32) -> Effect {
        if self.tab != 0 {
            return Effect::None;
        }
        let n = self.visible().len();
        self.first = (self.first as i64 + i64::from(lines)).clamp(0, n.saturating_sub(self.shown) as i64) as usize;
        Effect::Redraw
    }

    fn tick(&mut self, now: Now) -> bool {
        let mut changed = false;
        if let Some((j, what)) = &mut self.job
            && let Some(r) = j.poll()
        {
            let what = what.clone();
            self.job = None;
            self.finished(&what, r);
            changed = true;
        }
        if now.mono >= self.next_sample {
            self.sample(Sample::read(), now.mono);
            self.next_sample = now.mono + SAMPLE_MS;
            // The details follow (the process may have gone).
            if let Some(d) = &self.details {
                let pid = d.pid;
                self.details = self.rows.iter().any(|r| r.pid == pid).then(|| Details::read(pid));
            }
            changed = true;
        }
        changed
    }

    fn wake(&self, now: Now) -> Option<i64> {
        let sample = (self.next_sample - now.mono).max(0);
        Some(if self.job.is_some() { sample.min(kit::JOB_MS) } else { sample })
    }
}

/// A nice value in words.
fn priority_word(nice: i32) -> &'static str {
    match nice {
        i32::MIN..=-10 => "very high",
        -9..=-1 => "high",
        0 => "normal",
        1..=9 => "low",
        _ => "very low",
    }
}

/// The details of a process over the table.
fn draw_details(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    win: Area,
    body: Area,
    d: &Details,
    r: Option<&Row>,
) {
    p.fill(win, 0.0, pal.dim_dialog);
    let a = Area::new(body.x + 40.0, body.y + 6.0, body.w - 80.0, body.h - 12.0);
    p.fill(a, 12.0, pal.overlay);
    p.border(a, 12.0, 1.0, pal.border);
    let (x, w) = (a.x + 22.0, a.w - 44.0);
    let mut y = a.y + 18.0;
    let title = p.style(&f.medium, 16.0, pal.chalk);
    let label = p.style(&f.mono, 11.0, pal.muted);
    let value = p.style(&f.regular, 13.0, pal.text_1);
    let mono = p.style(&f.mono, 11.5, pal.text_2);
    let name = r.map_or_else(|| alloc::format!("pid {}", d.pid), |r| alloc::format!("{} · pid {}", r.name, r.pid));
    p.line(&title, x, y, 22.0, &kit::fit(p, &title, &name, w));
    y += 30.0;
    let size = |n: u64| slate_sysinfo::size(n);
    let io = d.io.map_or_else(
        || String::from("unknown"),
        |io| {
            alloc::format!(
                "read {} ({} from disk) · written {} ({} to disk)",
                size(io.rchar),
                size(io.read_bytes),
                size(io.wchar),
                size(io.write_bytes)
            )
        },
    );
    let rows = [
        ("command", r.map(|r| r.cmdline.clone()).unwrap_or_default()),
        ("priority", alloc::format!("{} (nice {}) · + lowers, - raises", priority_word(d.nice), d.nice)),
        ("input, output", io),
    ];
    for (l, v) in rows {
        p.line(&label, x, y + 2.0, 16.0, l);
        p.line(&value, x + 120.0, y, 20.0, &kit::fit(p, &value, &v, w - 120.0));
        y += 24.0;
    }
    y += 8.0;
    // Threads at the left, open files at the right.
    let half = (w - 20.0) / 2.0;
    let room = ((a.bottom() - 40.0 - y - 22.0) / 20.0).max(1.0) as usize;
    p.line(&label, x, y, 16.0, &alloc::format!("threads · {}", d.threads.len()));
    let files_label = match &d.files {
        Some(f) => alloc::format!("open files · {}", f.len()),
        None => String::from("open files · another account's"),
    };
    p.line(&label, x + half + 20.0, y, 16.0, &files_label);
    y += 22.0;
    for (k, t) in d.threads.iter().take(room).enumerate() {
        let line = alloc::format!("{:>7}  {}  {}", t.tid, t.state, t.name);
        p.line(&mono, x, y + 20.0 * k as f32, 18.0, &kit::fit(p, &mono, &line, half));
    }
    for (k, (fd, to)) in d.files.iter().flatten().take(room).enumerate() {
        let line = alloc::format!("{fd:>4}  {to}");
        p.line(&mono, x + half + 20.0, y + 20.0 * k as f32, 18.0, &kit::fit(p, &mono, &line, half));
    }
    kit::hints(p, pal, f, a, &[("+ -", "priority"), ("esc", "close")]);
}

pub fn main() -> i32 {
    let users = procs::user_names(&load::read("/etc/passwd"));
    let mut m = Monitor::new(users, slate_rt::process::getuid());
    kit::run("system-monitor", "monitor", None, Hints { min: (640, 460), size: (900, 620) }, &mut m)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    fn proc(pid: i32, name: &str, ticks: u64, rss: u64, uid: u32) -> Proc {
        Proc {
            pid,
            ppid: 1,
            name: name.into(),
            state: 'S',
            ticks,
            threads: 1,
            rss,
            uid,
            linux: name == "firefox",
            cmdline: name.into(),
            nice: 0,
        }
    }

    fn sample(cpu_busy: u64, procs: Vec<Proc>, rx: u64, read: u64) -> Sample {
        Sample {
            procs,
            cpus: std::vec![
                // 1000 ticks of idle time since the last sample, with the
                // busy ones.
                CpuTime { busy: cpu_busy, total: 1000 + 1000 * (cpu_busy / 400) + cpu_busy },
                CpuTime { busy: cpu_busy / 2, total: 500 + 500 * (cpu_busy / 400) + cpu_busy / 2 },
                CpuTime { busy: cpu_busy / 2, total: 500 + 500 * (cpu_busy / 400) + cpu_busy / 2 },
            ],
            memory: Memory { total: 4 << 20, available: 3 << 20, cached: 1 << 19, buffers: 0 },
            net: std::vec![NetCount { name: "eth0".into(), received: rx, sent: rx / 4 }],
            disks: std::vec![DiskCount { name: "vda".into(), read, written: 0 }],
            mounts: Vec::new(),
        }
    }

    pub fn monitor() -> Monitor {
        let users = BTreeMap::from([(0, String::from("root")), (1000, String::from("ada"))]);
        let mut m = Monitor::new(users, 1000);
        m.sample(
            sample(
                0,
                std::vec![
                    proc(1, "slinit", 10, 900, 0),
                    proc(40, "strata", 100, 60_000, 1000),
                    proc(77, "firefox", 50, 400_000, 1000)
                ],
                0,
                0,
            ),
            0,
        );
        m.sample(
            sample(
                400,
                std::vec![
                    proc(1, "slinit", 10, 900, 0),
                    proc(40, "strata", 200, 60_000, 1000),
                    proc(77, "firefox", 250, 400_000, 1000)
                ],
                2_000_000,
                4096,
            ),
            2000,
        );
        m
    }

    #[test]
    fn rates_and_order() {
        let m = monitor();
        // 400 of 1400 machine ticks: 29%; firefox had 200 of them.
        assert!((m.cpu_history[0] - 400.0 / 1400.0).abs() < 1e-3);
        let order: Vec<&str> = m.visible().iter().map(|r| r.name.as_str()).collect();
        assert_eq!(order, ["firefox", "strata", "slinit"]);
        assert!((m.rows[2].cpu - 200.0 / 14.0).abs() < 0.1, "{}", m.rows[2].cpu);
        assert!(m.rows[2].linux);
        assert_eq!(m.rows[0].user, "root");
        assert!((m.net_rate.0 - 1_000_000.0).abs() < 1.0, "bytes a second over two seconds");
        assert!((m.disk_rate.0 - 1024.0 * 1024.0).abs() < 1.0);
        assert_eq!(m.cores.len(), 2);
        assert_eq!(m.selected, Some(1), "the first sample's first row stays chosen");
    }

    #[test]
    fn tree_and_details() {
        let mut m = monitor();
        m.key(0, Some('t'), slate_strata_client::mods::CTRL);
        assert!(m.tree);
        let names: Vec<&str> = m.visible().iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["slinit", "firefox", "strata"], "children under init, by CPU");
        assert_eq!(m.depths().get(&77), Some(&1));
        // Searching lists the matches alone.
        m.key(0, Some('s'), 0);
        assert!(m.depths().is_empty());
        m.key(KEY_ESC, None, 0);
        // A real process's details: this test's own.
        let d = Details::read(std::process::id() as i32);
        assert!(!d.threads.is_empty() && d.files.as_ref().is_some_and(|f| !f.is_empty()) && d.io.is_some());
        // Lowering the priority of one's own process; Esc closes.
        let mut child = std::process::Command::new("sleep").arg("5").spawn().unwrap();
        let pid = child.id() as i32;
        m.details = Some(Details::read(pid));
        let before = m.details.as_ref().unwrap().nice;
        m.key(0, Some('+'), 0);
        assert_eq!(slate_rt::process::nice_of(pid), Ok((before + 1).min(19)));
        assert_eq!(m.details.as_ref().unwrap().nice, (before + 1).min(19));
        m.key(KEY_ESC, None, 0);
        assert!(m.details.is_none());
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn search_sort_and_asking() {
        let mut m = monitor();
        for c in "str".chars() {
            m.key(0, Some(c), 0);
        }
        assert_eq!(m.visible().len(), 1);
        assert_eq!(m.selected, Some(40));
        m.key(KEY_ESC, None, 0);
        assert_eq!(m.visible().len(), 3);
        m.sort_by(Col::Name);
        assert_eq!(m.visible()[0].name, "firefox");
        m.sort_by(Col::Name);
        assert_eq!(m.visible()[0].name, "strata");
        m.sort_by(Col::Pid);
        m.key(KEY_DOWN, None, 0);
        // Delete asks; Esc leaves it.
        m.selected = Some(1);
        m.key(KEY_DELETE, None, 0);
        assert_eq!(m.confirm.as_ref().map(|c| (c.pid, c.focus)), Some((1, 1)));
        m.key(KEY_RIGHT, None, 0);
        assert_eq!(m.confirm.as_ref().unwrap().focus, 2);
        m.key(KEY_ESC, None, 0);
        assert!(m.confirm.is_none());
        // Tab goes through the tabs.
        m.key(KEY_TAB, None, 0);
        assert_eq!(m.tab, 1);
        m.key(KEY_TAB, None, SHIFT);
        assert_eq!(m.tab, 0);
    }

    #[test]
    fn ending_ones_own() {
        let mut m = monitor();
        // A process of one's own that isn't there any more: the kernel says so.
        m.rows.push(Row {
            pid: 999_999,
            name: "gone".into(),
            user: "ada".into(),
            uid: 1000,
            cpu: 0.0,
            memory: 0,
            linux: false,
            cmdline: String::new(),
            ppid: 1,
            nice: 0,
        });
        m.selected = Some(999_999);
        m.key(KEY_DELETE, None, 0);
        m.key(KEY_ENTER, None, 0);
        let (s, err) = m.status.clone().unwrap();
        assert!(err && s.starts_with("Couldn't end gone (pid 999999)"), "{s}");
        m.finished("sleep (pid 5)", Ok(String::new()));
        assert_eq!(m.status, Some(("Ended sleep (pid 5).".into(), false)));
        m.finished("sleep (pid 5)", Err("cancelled".into()));
        assert_eq!(m.status, Some(("sleep (pid 5) was left running.".into(), false)));
    }
}
