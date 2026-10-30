// SPDX-License-Identifier: MIT OR Apache-2.0

//! top: the busiest processes, refreshed every `-d` seconds (3 by
//! default), with the fields, keys and options of top(1) (procps) that
//! fit Slate (ADRs 0055, 0152, 0163):
//! - four windows (field groups) of fields, each sorted by any of them,
//!   high to low unless `R` reverses it: `A` shows all four at once, `a`
//!   and `w` go to the next and previous, `g` chooses one; the `f` screen
//!   shows, hides and moves the current window's fields (Right picks one
//!   up, Up and Down move it, Left or Enter put it down);
//! - `o` and `O` filter the tasks (`[!]FIELD=TEXT`, `<` and `>`; `O`
//!   minds case), ctrl + o shows the filters and `=` clears them; `V`
//!   draws the process tree (forest view, threads under their process
//!   when `H` shows them); `E` and `e` scale the summary's and the tasks'
//!   memory (KiB to EiB); `<` and `>` sort by the field left or right of
//!   the sort field;
//! - each window's look: `x` highlights the sort column, `y` the running
//!   tasks (on at first), `b` makes those highlights reverse video rather
//!   than bold, `z` turns its colours on, and `Z`'s screen chooses them
//!   (summary, messages, column heads, tasks and highlights, each one of
//!   eight colours or none; red, red, yellow, none and red at first, as
//!   procps' top has them, observed);
//! - the arrows, PgUp, PgDn, Home and End scroll the current window's
//!   tasks and fields, `C` says where it is scrolled to;
//! - `H` (or `-H`) shows threads, `c` (or `-c`) command lines, `i` (or
//!   `-i`) hides idle tasks, `1` (or `-1`) each CPU;
//! - `W` writes the settings to `$XDG_CONFIG_HOME/slate/toprc` (Slate's
//!   own `key=value` lines, not procps' file), read at the start;
//! - `-b` writes plain frames for scripts, `-n N` stops after N frames,
//!   `-u USER` and `-p PID,...` show only those, `-o FIELD` sorts (`+` high
//!   to low, `-` low to high), `-O` lists the fields, `-s` is secure mode
//!   (no `k` or delay changes).

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{fs, io, lossy, print, println};

use crate::procs::{self, Ctx, Extra, HZ, Proc};
use crate::util::{error, parse_num};

/// A field top can show (top(1), "DESCRIPTIONS of Fields").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum F {
    Pid,
    Ppid,
    Uid,
    User,
    Tty,
    Pr,
    Ni,
    Nth,
    P,
    Virt,
    Res,
    Shr,
    Code,
    Data,
    Swap,
    S,
    Cpu,
    Mem,
    Time,
    TimePlus,
    Pgrp,
    Sid,
    Wchan,
    Command,
}

/// A field's name, width, alignment and description.
struct Spec {
    f: F,
    name: &'static str,
    width: usize,
    left: bool,
    about: &'static str,
}

/// The fields in their first order (the `f` screen's, until moved).
const FIELDS: [Spec; 24] = [
    Spec { f: F::Pid, name: "PID", width: 5, left: false, about: "Process Id" },
    Spec { f: F::Ppid, name: "PPID", width: 5, left: false, about: "Parent Process pid" },
    Spec { f: F::Uid, name: "UID", width: 5, left: false, about: "Effective User Id" },
    Spec { f: F::User, name: "USER", width: 8, left: true, about: "Effective User Name" },
    Spec { f: F::Tty, name: "TTY", width: 8, left: true, about: "Controlling Tty" },
    Spec { f: F::Pr, name: "PR", width: 4, left: false, about: "Priority" },
    Spec { f: F::Ni, name: "NI", width: 3, left: false, about: "Nice Value" },
    Spec { f: F::Nth, name: "nTH", width: 3, left: false, about: "Number of Threads" },
    Spec { f: F::P, name: "P", width: 2, left: false, about: "Last Used Cpu (SMP)" },
    Spec { f: F::Virt, name: "VIRT", width: 7, left: false, about: "Virtual Image (KiB)" },
    Spec { f: F::Res, name: "RES", width: 6, left: false, about: "Resident Size (KiB)" },
    Spec { f: F::Shr, name: "SHR", width: 6, left: false, about: "Shared Memory (KiB)" },
    Spec { f: F::Code, name: "CODE", width: 6, left: false, about: "Code Size (KiB)" },
    Spec { f: F::Data, name: "DATA", width: 7, left: false, about: "Data+Stack (KiB)" },
    Spec { f: F::Swap, name: "SWAP", width: 6, left: false, about: "Swapped Size (KiB)" },
    Spec { f: F::S, name: "S", width: 1, left: true, about: "Process Status" },
    Spec { f: F::Cpu, name: "%CPU", width: 5, left: false, about: "CPU Usage" },
    Spec { f: F::Mem, name: "%MEM", width: 5, left: false, about: "Memory Usage (RES)" },
    Spec { f: F::Time, name: "TIME", width: 6, left: false, about: "CPU Time" },
    Spec { f: F::TimePlus, name: "TIME+", width: 9, left: false, about: "CPU Time, hundredths" },
    Spec { f: F::Pgrp, name: "PGRP", width: 5, left: false, about: "Process Group Id" },
    Spec { f: F::Sid, name: "SID", width: 5, left: false, about: "Session Id" },
    Spec { f: F::Wchan, name: "WCHAN", width: 10, left: true, about: "Sleeping in Function" },
    Spec { f: F::Command, name: "COMMAND", width: 15, left: true, about: "Command Name/Line" },
];

/// The four windows' names, fields and sort fields (top(1)'s field
/// groups: Def, Job, Mem, Usr).
const WINDOWS: [(&str, &[F], F); 4] = [
    ("Def", &[F::Pid, F::User, F::Pr, F::Ni, F::Virt, F::Res, F::S, F::Cpu, F::Mem, F::TimePlus, F::Command], F::Cpu),
    ("Job", &[F::Pid, F::Ppid, F::Pgrp, F::Sid, F::Tty, F::TimePlus, F::Cpu, F::S, F::Command], F::Pid),
    ("Mem", &[F::Pid, F::Mem, F::Virt, F::Res, F::Shr, F::Code, F::Data, F::Swap, F::Command], F::Mem),
    ("Usr", &[F::Pid, F::Ppid, F::Uid, F::User, F::Tty, F::TimePlus, F::Cpu, F::S, F::Wchan, F::Command], F::User),
];

/// The memory units `E` and `e` step through.
const UNITS: [&str; 6] = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];

fn spec(f: F) -> &'static Spec {
    FIELDS.iter().find(|s| s.f == f).expect("every field has a spec")
}

/// A field by its name (any case).
pub fn field(name: &str) -> Option<F> {
    FIELDS.iter().find(|s| s.name.eq_ignore_ascii_case(name)).map(|s| s.f)
}

/// Whether a field needs [`Extra`] (statm, VmSwap, wchan).
fn needs_extra(f: F) -> bool {
    matches!(f, F::Shr | F::Code | F::Data | F::Swap | F::Wchan)
}

/// A task filter (`o`, `O`): `[!]FIELD=TEXT` keeps tasks whose field
/// holds TEXT, `<` and `>` those below or above it (as numbers when both
/// are); `!` keeps the others.
#[derive(Clone, Debug, PartialEq)]
pub struct Filter {
    pub f: F,
    pub op: u8,
    pub value: String,
    pub negate: bool,
    /// `O`: case matters.
    pub case: bool,
}

impl Filter {
    /// A filter as typed, or why not (top(1)'s messages).
    pub fn parse(text: &str, case: bool) -> Result<Filter, &'static str> {
        let (negate, rest) = match text.strip_prefix('!') {
            Some(r) => (true, r),
            None => (false, text),
        };
        let at = rest.find(['=', '<', '>']).ok_or("Unacceptable filter expression")?;
        let f = field(&rest[..at]).ok_or("Unrecognized field name")?;
        let value = String::from(&rest[at + 1..]);
        if value.is_empty() {
            return Err("Unacceptable filter expression");
        }
        Ok(Filter { f, op: rest.as_bytes()[at], value, negate, case })
    }

    fn keeps(&self, text: &str) -> bool {
        let text = text.trim();
        let hit = match self.op {
            b'=' if self.case => text.contains(self.value.as_str()),
            b'=' => text.to_lowercase().contains(&self.value.to_lowercase()),
            op => {
                let o = match (text.parse::<f64>(), self.value.parse::<f64>()) {
                    (Ok(a), Ok(b)) => a.partial_cmp(&b).unwrap_or(core::cmp::Ordering::Equal),
                    _ if self.case => text.cmp(self.value.as_str()),
                    _ => text.to_lowercase().cmp(&self.value.to_lowercase()),
                };
                if op == b'<' { o.is_lt() } else { o.is_gt() }
            }
        };
        hit != self.negate
    }

    fn text(&self) -> String {
        alloc::format!("{}{}{}{}", if self.negate { "!" } else { "" }, spec(self.f).name, self.op as char, self.value)
    }
}

/// A window: its fields (those shown, in order), every field in the `f`
/// screen's order, its sort and its filters.
#[derive(Clone, Debug, PartialEq)]
pub struct Win {
    pub name: &'static str,
    pub fields: Vec<F>,
    pub order: Vec<F>,
    pub sort: F,
    /// Low to high (`R`); top sorts high to low.
    pub reverse: bool,
    /// Not kept in the settings file (as top(1)'s).
    pub filters: Vec<Filter>,
    /// `z`: colours on.
    pub colour: bool,
    /// `Z`'s colours for [`Part`]s: 0 to 7 (black, red, green, yellow,
    /// blue, magenta, cyan, white) or -1 for none.
    pub colours: [i8; 5],
    /// `x`: the sort column highlighted; `y`: running tasks; `b`: those
    /// highlights in reverse video rather than bold.
    pub hi_column: bool,
    pub hi_running: bool,
    pub hi_reverse: bool,
    /// Scrolled to: the first task and the first field shown (not kept).
    pub first_task: usize,
    pub first_field: usize,
}

/// What `Z` colours.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    Summary,
    Messages,
    Heads,
    Tasks,
    Highlights,
}

/// The colours a window starts with (procps' top's, observed).
const COLOURS: [i8; 5] = [1, 1, 3, -1, 1];

/// The escape for colour `c` as text colour, nothing for none.
fn fg(c: i8) -> String {
    if (0..8).contains(&c) { alloc::format!("\x1b[3{c}m") } else { String::new() }
}

impl Win {
    fn new(n: usize) -> Win {
        let (name, fields, sort) = WINDOWS[n];
        let mut w = Win {
            name,
            fields: fields.to_vec(),
            order: Vec::new(),
            sort,
            reverse: false,
            filters: Vec::new(),
            colour: false,
            colours: COLOURS,
            hi_column: false,
            hi_running: true,
            hi_reverse: false,
            first_task: 0,
            first_field: 0,
        };
        w.order = order_for(&w.fields);
        w
    }

    /// The escape for part `p`: its colour when colours are on.
    fn colour_of(&self, p: Part) -> String {
        if self.colour { fg(self.colours[p as usize]) } else { String::new() }
    }

    /// The escape for highlighted text (`x`, `y`).
    fn highlight(&self) -> String {
        let mut e = self.colour_of(Part::Highlights);
        e.push_str(if self.hi_reverse { "\x1b[7m" } else { "\x1b[1m" });
        e
    }

    /// The fields shown after scrolling right (at least the last one).
    fn shown_fields(&self) -> &[F] {
        &self.fields[self.first_field.min(self.fields.len().saturating_sub(1))..]
    }

    /// `<` and `>`: sort by the shown field left (`left`) or right of the
    /// sort field, if it is shown and has one there.
    fn move_sort(&mut self, left: bool) {
        let Some(i) = self.fields.iter().position(|f| *f == self.sort) else { return };
        let to = if left { i.checked_sub(1) } else { Some(i + 1).filter(|&j| j < self.fields.len()) };
        if let Some(j) = to {
            self.sort = self.fields[j];
        }
    }

    /// The fields shown again from the order and a set of them.
    fn show(&mut self, shown: &[F]) {
        self.fields = self.order.iter().copied().filter(|f| shown.contains(f)).collect();
    }
}

/// Every field, in the table's order but for `shown`, which keep theirs
/// (a settings file with fields only).
fn order_for(shown: &[F]) -> Vec<F> {
    let mut rest = shown.iter();
    FIELDS.iter().map(|s| if shown.contains(&s.f) { *rest.next().unwrap_or(&s.f) } else { s.f }).collect()
}

/// What top shows and how: the command line's and the settings file's.
#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    pub wins: Vec<Win>,
    /// The current window.
    pub cur: usize,
    /// All four windows at once (`A`).
    pub alt: bool,
    pub delay: f64,
    pub per_cpu: bool,
    pub threads: bool,
    pub command_lines: bool,
    pub hide_idle: bool,
    /// The process tree (`V`).
    pub forest: bool,
    /// The summary's and the tasks' memory units (index in `UNITS`).
    pub scale_summary: usize,
    pub scale_tasks: usize,
    /// `-s`: no signals or delay changes (never kept).
    pub secure: bool,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            wins: (0..4).map(Win::new).collect(),
            cur: 0,
            alt: false,
            delay: 3.0,
            per_cpu: false,
            threads: false,
            command_lines: false,
            hide_idle: false,
            forest: false,
            scale_summary: 1,
            scale_tasks: 0,
            secure: false,
        }
    }
}

impl Settings {
    pub fn win(&self) -> &Win {
        &self.wins[self.cur]
    }

    pub fn win_mut(&mut self) -> &mut Win {
        &mut self.wins[self.cur]
    }

    /// The settings file: `key=value` lines, the first window's without a
    /// prefix and the others' after `w2.` to `w4.` (unknown keys and bad
    /// values are passed over, so an older top reads a newer file).
    pub fn parse(text: &str) -> Settings {
        let mut s = Settings::default();
        let names = |v: &str| -> Vec<F> { v.split(',').filter_map(|n| field(n.trim())).collect() };
        let mut orders: [Option<Vec<F>>; 4] = Default::default();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let Some((k, v)) = line.split_once('=') else { continue };
            let (k, v) = (k.trim(), v.trim());
            let yes = v == "1" || v == "yes";
            let (w, k) = match k.strip_prefix('w').and_then(|r| r.split_once('.')) {
                Some((n @ ("2" | "3" | "4"), k)) => (usize::from(n.as_bytes()[0] - b'1'), k),
                _ => (0, k),
            };
            let win = &mut s.wins[w];
            match k {
                "fields" => {
                    let f = names(v);
                    if !f.is_empty() {
                        win.fields = f;
                    }
                }
                "order" => orders[w] = Some(names(v)),
                "sort" => win.sort = field(v).unwrap_or(win.sort),
                "reverse" => win.reverse = yes,
                "delay" => s.delay = v.parse().ok().filter(|d: &f64| *d >= 0.0).unwrap_or(s.delay),
                "per_cpu" => s.per_cpu = yes,
                "threads" => s.threads = yes,
                "command_lines" => s.command_lines = yes,
                "hide_idle" => s.hide_idle = yes,
                "colour" => win.colour = yes,
                "colours" => {
                    let c: Vec<i8> = v.split(',').filter_map(|c| c.trim().parse().ok()).collect();
                    if let Ok(c) = <[i8; 5]>::try_from(c) {
                        win.colours = c.map(|c| if (0..8).contains(&c) { c } else { -1 });
                    }
                }
                "highlight_column" => win.hi_column = yes,
                "highlight_running" => win.hi_running = yes,
                "highlight_reverse" => win.hi_reverse = yes,
                "forest" => s.forest = yes,
                "alt" => s.alt = yes,
                "window" => s.cur = v.parse::<usize>().ok().filter(|n| (1..=4).contains(n)).map_or(s.cur, |n| n - 1),
                "scale_summary" => s.scale_summary = v.parse().ok().filter(|n| *n < UNITS.len()).unwrap_or(1),
                "scale_tasks" => s.scale_tasks = v.parse().ok().filter(|n| *n < UNITS.len()).unwrap_or(0),
                _ => {}
            }
        }
        for (w, order) in s.wins.iter_mut().zip(orders) {
            // A kept order (fields it lacks after it), else the table's.
            w.order = match order {
                Some(mut o) => {
                    o.dedup();
                    o.extend(FIELDS.iter().map(|s| s.f).filter(|f| !o.contains(f)).collect::<Vec<_>>());
                    o
                }
                None => order_for(&w.fields),
            };
            let shown = w.fields.clone();
            let listed = w.fields.clone();
            w.show(&shown);
            // Fields listed out of the order's sequence keep the listing's.
            if w.fields != listed {
                w.order = order_for(&listed);
                w.fields = listed;
            }
        }
        s
    }

    pub fn text(&self) -> String {
        let b = |v: bool| if v { 1 } else { 0 };
        let list = |fs: &[F]| fs.iter().map(|f| spec(*f).name).collect::<Vec<_>>().join(",");
        let mut out = String::from("# top's settings (written by W)\n");
        for (i, w) in self.wins.iter().enumerate() {
            let pre = if i == 0 { String::new() } else { alloc::format!("w{}.", i + 1) };
            out.push_str(&alloc::format!(
                "{pre}fields={}\n{pre}order={}\n{pre}sort={}\n{pre}reverse={}\n",
                list(&w.fields),
                list(&w.order),
                spec(w.sort).name,
                b(w.reverse)
            ));
            let colours: Vec<String> = w.colours.iter().map(|c| alloc::format!("{c}")).collect();
            out.push_str(&alloc::format!(
                "{pre}colour={}\n{pre}colours={}\n{pre}highlight_column={}\n{pre}highlight_running={}\n\
                 {pre}highlight_reverse={}\n",
                b(w.colour),
                colours.join(","),
                b(w.hi_column),
                b(w.hi_running),
                b(w.hi_reverse)
            ));
        }
        out.push_str(&alloc::format!(
            "delay={}\nper_cpu={}\nthreads={}\ncommand_lines={}\nhide_idle={}\nforest={}\nalt={}\n\
             window={}\nscale_summary={}\nscale_tasks={}\n",
            self.delay,
            b(self.per_cpu),
            b(self.threads),
            b(self.command_lines),
            b(self.hide_idle),
            b(self.forest),
            b(self.alt),
            self.cur + 1,
            self.scale_summary,
            self.scale_tasks
        ));
        out
    }
}

/// `$XDG_CONFIG_HOME/slate/toprc`, else `~/.config/slate/toprc`.
fn settings_path() -> Option<Vec<u8>> {
    let dir = match slate_rt::env::var(b"XDG_CONFIG_HOME").filter(|d| !d.is_empty()) {
        Some(d) => d,
        None => [slate_rt::env::var(b"HOME")?.as_slice(), b"/.config"].concat(),
    };
    Some([dir.as_slice(), b"/slate/toprc"].concat())
}

/// A task in a frame: the process (or thread), its share of a CPU, what
/// the memory fields read (when shown), and its depth in the forest view.
#[derive(Debug)]
pub struct Row<'a> {
    pub p: &'a Proc,
    pub cpu: f64,
    pub x: Option<Extra>,
    pub depth: usize,
}

impl<'a> Row<'a> {
    pub fn new(p: &'a Proc, cpu: f64) -> Row<'a> {
        Row { p, cpu, x: None, depth: 0 }
    }
}

fn mem_pct(p: &Proc, ctx: &Ctx) -> f64 {
    if ctx.mem_kb > 0 { (p.rss * ctx.page_kb) as f64 * 100.0 / ctx.mem_kb as f64 } else { 0.0 }
}

/// KiB in the tasks' unit (`e`): whole KiB, else one decimal and the
/// unit's letter (`m`, `g`, ...), as top(1) shows them.
fn scaled(kb: u64, unit: usize) -> String {
    if unit == 0 {
        return alloc::format!("{kb}");
    }
    let v = kb as f64 / (1u64 << (10 * unit)) as f64;
    alloc::format!("{v:.1}{}", ["", "m", "g", "t", "p", "e"][unit])
}

/// A field's text for a row.
fn cell(f: F, r: &Row<'_>, ctx: &Ctx, s: &Settings) -> String {
    let p = r.p;
    let t = p.utime + p.stime;
    let x = r.x.clone().unwrap_or_default();
    let kb = |kb: u64| scaled(kb, s.scale_tasks);
    match f {
        F::Pid => alloc::format!("{}", if s.threads { p.lwp } else { p.pid }),
        F::Ppid => alloc::format!("{}", p.ppid),
        F::Uid => alloc::format!("{}", p.uid),
        F::User => procs::user(p.uid),
        F::Tty => procs::tty_name(p.tty),
        F::Pr if p.prio < 0 => String::from("rt"),
        F::Pr => alloc::format!("{}", p.prio),
        F::Ni => alloc::format!("{}", p.nice),
        F::Nth => alloc::format!("{}", p.threads),
        F::P => alloc::format!("{}", p.cpu),
        F::Virt => kb(p.vsize / 1024),
        F::Res => kb(p.rss * ctx.page_kb),
        F::Shr => kb(x.shared * ctx.page_kb),
        F::Code => kb(x.text * ctx.page_kb),
        F::Data => kb(x.data * ctx.page_kb),
        F::Swap => kb(x.swap_kb),
        F::S => String::from(p.state as char),
        F::Cpu => alloc::format!("{:.1}", r.cpu),
        F::Mem => alloc::format!("{:.1}", mem_pct(p, ctx)),
        F::Time => alloc::format!("{}:{:02}", t / HZ / 60, t / HZ % 60),
        F::TimePlus => alloc::format!("{}:{:02}.{:02}", t / HZ / 60, t / HZ % 60, t % HZ),
        F::Pgrp => alloc::format!("{}", p.pgid),
        F::Sid => alloc::format!("{}", p.sid),
        F::Wchan if x.wchan.is_empty() || x.wchan == "0" => String::from("-"),
        F::Wchan => x.wchan,
        F::Command => {
            let name = if s.command_lines && !p.args.is_empty() {
                p.args.clone()
            } else if s.command_lines {
                alloc::format!("[{}]", p.comm)
            } else {
                p.comm.clone()
            };
            // The forest view's branches (top(1), `V`).
            if r.depth > 0 { alloc::format!("{}`- {name}", " ".repeat(4 * r.depth - 3)) } else { name }
        }
    }
}

/// Fields at their widths; the last one is not padded (and takes what
/// room is left), others are cut to their width.
fn cells(fields: &[F], text: impl Fn(F) -> String) -> Vec<String> {
    let mut out = Vec::new();
    for (i, &f) in fields.iter().enumerate() {
        let sp = spec(f);
        let v = text(f);
        if i + 1 == fields.len() && sp.left {
            out.push(v);
        } else {
            let v: String = v.chars().take(sp.width.max(sp.name.len())).collect();
            let w = sp.width.max(sp.name.len());
            out.push(if sp.left { alloc::format!("{v:<w$}") } else { alloc::format!("{v:>w$}") });
        }
    }
    out
}

/// Fields side by side.
fn join(fields: &[F], text: impl Fn(F) -> String) -> String {
    cells(fields, text).join(" ")
}

/// Pieces of text in their styles (escapes), cut to `width` characters
/// and ended with a reset; a style is written (after a reset) only where
/// it changes, and escapes don't count.
fn styled(pieces: &[(String, String)], width: usize) -> String {
    let mut out = String::new();
    let mut left = width;
    let mut current = "";
    for (style, text) in pieces {
        if left == 0 {
            break;
        }
        if style != current {
            out.push_str("\x1b[m");
            out.push_str(style);
            current = style;
        }
        let t: String = text.chars().take(left).collect();
        left -= t.chars().count();
        out.push_str(&t);
    }
    out.push_str("\x1b[m");
    out
}

/// A task's line on a terminal: in the tasks' colour, a running task
/// highlighted (`y`), the sort column too (`x`).
pub fn task_line(w: &Win, r: &Row<'_>, ctx: &Ctx, s: &Settings, width: usize) -> String {
    let fields = w.shown_fields();
    let base = if w.hi_running && r.p.state == b'R' { w.highlight() } else { w.colour_of(Part::Tasks) };
    let mut pieces = Vec::new();
    for (i, (f, c)) in fields.iter().zip(cells(fields, |f| cell(f, r, ctx, s))).enumerate() {
        if i > 0 {
            pieces.push((base.clone(), String::from(" ")));
        }
        let style = if w.hi_column && *f == w.sort { w.highlight() } else { base.clone() };
        pieces.push((style, c));
    }
    styled(&pieces, width)
}

pub fn header(fields: &[F]) -> String {
    join(fields, |f| String::from(spec(f).name))
}

pub fn line(fields: &[F], r: &Row<'_>, ctx: &Ctx, s: &Settings) -> String {
    join(fields, |f| cell(f, r, ctx, s))
}

/// Rows in window `w`'s order: high to low (low to high reversed), ties
/// by PID.
pub fn sort(rows: &mut [Row<'_>], w: &Win, s: &Settings, ctx: &Ctx) {
    use core::cmp::Ordering;
    let num = |a: f64, b: f64| a.partial_cmp(&b).unwrap_or(Ordering::Equal);
    let key = |a: &Row<'_>, b: &Row<'_>| -> Ordering {
        let (p, q) = (a.p, b.p);
        let (x, y) = (a.x.clone().unwrap_or_default(), b.x.clone().unwrap_or_default());
        match w.sort {
            F::Pid => p.lwp.cmp(&q.lwp),
            F::Ppid => p.ppid.cmp(&q.ppid),
            F::Uid => p.uid.cmp(&q.uid),
            F::User => procs::user(p.uid).cmp(&procs::user(q.uid)),
            F::Tty => p.tty.cmp(&q.tty),
            F::Pr => p.prio.cmp(&q.prio),
            F::Ni => p.nice.cmp(&q.nice),
            F::Nth => p.threads.cmp(&q.threads),
            F::P => p.cpu.cmp(&q.cpu),
            F::Virt => p.vsize.cmp(&q.vsize),
            F::Res | F::Mem => p.rss.cmp(&q.rss),
            F::Shr => x.shared.cmp(&y.shared),
            F::Code => x.text.cmp(&y.text),
            F::Data => x.data.cmp(&y.data),
            F::Swap => x.swap_kb.cmp(&y.swap_kb),
            F::S => p.state.cmp(&q.state),
            F::Cpu => num(a.cpu, b.cpu),
            F::Time | F::TimePlus => (p.utime + p.stime).cmp(&(q.utime + q.stime)),
            F::Pgrp => p.pgid.cmp(&q.pgid),
            F::Sid => p.sid.cmp(&q.sid),
            F::Wchan => x.wchan.cmp(&y.wchan),
            F::Command => cell(F::Command, a, ctx, s).cmp(&cell(F::Command, b, ctx, s)),
        }
    };
    rows.sort_by(|a, b| {
        let o = key(a, b);
        let o = if w.reverse { o } else { o.reverse() };
        o.then(a.p.lwp.cmp(&b.p.lwp))
    });
}

/// A task's place in the forest: its own ID and its parent's. A thread
/// other than a process's first is under that one, which is under the
/// parent process's (as procps' top shows them with `H`).
fn tree_ids(p: &Proc) -> (u32, u32) {
    (p.lwp, if p.lwp != p.pid { p.pid } else { p.ppid })
}

/// The forest view: each process under its parent (each thread under its
/// process), siblings in the sort's order, with its depth for the COMMAND
/// field's branches. Tasks whose parent isn't shown are roots.
pub fn forest(rows: Vec<Row<'_>>) -> Vec<Row<'_>> {
    let ids: Vec<u32> = rows.iter().map(|r| r.p.lwp).collect();
    let mut slots: Vec<Option<Row<'_>>> = rows.into_iter().map(Some).collect();
    let mut out = Vec::new();
    fn visit<'a>(i: usize, depth: usize, slots: &mut Vec<Option<Row<'a>>>, out: &mut Vec<Row<'a>>) {
        let Some(mut r) = slots[i].take() else { return };
        let id = r.p.lwp;
        r.depth = depth;
        out.push(r);
        for j in 0..slots.len() {
            if slots[j].as_ref().is_some_and(|c| tree_ids(c.p).1 == id && c.p.lwp != id) {
                visit(j, depth + 1, slots, out);
            }
        }
    }
    for i in 0..slots.len() {
        let root = slots[i].as_ref().is_some_and(|r| {
            let (id, parent) = tree_ids(r.p);
            parent == id || !ids.contains(&parent)
        });
        if root {
            visit(i, 0, &mut slots, &mut out);
        }
    }
    // Anything left (a loop): as it was.
    out.extend(slots.into_iter().flatten());
    out
}

/// The `f` screen: the current window's fields in their order, `*` before
/// those shown, the one under the cursor marked (and picked up, while it
/// is being moved).
pub fn fields_screen(s: &Settings, cursor: usize, moving: bool) -> String {
    let w = s.win();
    let mut out = alloc::format!(
        "Fields Management for window {}:{}, whose current sort field is {}\n   \
         Navigate with Up/Dn, Right selects for move then <Enter> or Left commits,\n   \
         'd' or <Space> toggles display, 's' sets sort.  Use 'q' or <Esc> to end!\n\n",
        s.cur + 1,
        w.name,
        spec(w.sort).name
    );
    for (i, f) in w.order.iter().enumerate() {
        let sp = spec(*f);
        let shown = if w.fields.contains(f) { '*' } else { ' ' };
        let line = alloc::format!("{shown} {:<7} = {}", sp.name, sp.about);
        if i == cursor {
            let mark = if moving { "\x1b[1;7m" } else { "\x1b[7m" };
            out.push_str(&alloc::format!("{mark}{line}\x1b[m\n"));
        } else {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

/// Show or hide field `f` in the current window, where the order has it.
pub fn toggle(s: &mut Settings, f: F) {
    let w = s.win_mut();
    let mut shown = w.fields.clone();
    if let Some(i) = shown.iter().position(|x| *x == f) {
        if shown.len() > 1 {
            shown.remove(i);
        }
    } else {
        shown.push(f);
    }
    w.show(&shown);
}

/// Move the field at `at` in the current window's order one place up
/// (`up`) or down; where it went.
pub fn move_field(s: &mut Settings, at: usize, up: bool) -> usize {
    let w = s.win_mut();
    let to = if up { at.saturating_sub(1) } else { (at + 1).min(w.order.len() - 1) };
    w.order.swap(at, to);
    let shown = w.fields.clone();
    w.show(&shown);
    to
}

const HELP: &str = "Help for Interactive Commands\n\n\
  P M T N   sort by %CPU, %MEM, TIME+ or PID\n\
  R         reverse the sort\n\
  f         choose, move and sort the fields\n\
  A         all four windows; a w next and previous; g choose one\n\
  o O       add a filter ([!]FIELD=TEXT, < or >; O minds case)\n\
  ^O        show the filters; = clears them\n\
  < >       sort by the field left or right of the sort field\n\
  V         the process tree (forest view)\n\
  E e       scale the summary's and the tasks' memory\n\
  x y       highlight the sort column, running tasks\n\
  b         highlights bold or reverse\n\
  z Z       colours on or off, choose them\n\
  arrows    scroll the tasks and fields (PgUp PgDn Home End)\n\
  C         where the window is scrolled to\n\
  H         threads on or off\n\
  c         command lines or names\n\
  i         idle tasks on or off\n\
  1         each CPU or all together\n\
  d         change the delay\n\
  k         end a process\n\
  W         write the settings file\n\
  space     refresh\n\
  q         quit\n\n\
Press any key to continue";

/// The keys in what one read gave: bytes, and `ESC [ X` or `ESC O X`
/// sequences as `X` with `esc` set (several keys can come at once).
pub fn keys(bytes: &[u8]) -> Vec<(u8, bool)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && matches!(bytes.get(i + 1), Some(b'[' | b'O')) {
            // Parameters, then the final byte.
            let mut j = i + 2;
            while j < bytes.len() && !(0x40..=0x7e).contains(&bytes[j]) {
                j += 1;
            }
            match bytes.get(j) {
                // `ESC [ 5 ~`: the number says which key (PgUp is 5).
                Some(b'~') => out.push((bytes.get(i + 2).copied().filter(u8::is_ascii_digit).unwrap_or(b'~'), true)),
                Some(&f) => out.push((f, true)),
                None => {}
            }
            i = j + 1;
            continue;
        }
        out.push((bytes[i], false));
        i += 1;
    }
    out
}

/// Ask for a line on the message row, in cooked mode.
fn prompt(question: &str, saved: Option<slate_rt::term::Termios>) -> String {
    if let Some(t) = saved {
        let _ = slate_rt::term::set(io::STDIN, &t, false);
    }
    print!("\x1b[6;1H\x1b[K{question}\x1b[?25h");
    io::flush_stdout();
    let mut r = io::Reader::new(io::STDIN);
    let line = r.line().ok().flatten().unwrap_or_default();
    print!("\x1b[?25l");
    if let Some(t) = saved {
        let _ = slate_rt::term::set(io::STDIN, &raw(t), false);
    }
    lossy(&line).trim().into()
}

fn raw(t: slate_rt::term::Termios) -> slate_rt::term::Termios {
    let mut raw = t;
    raw.lflag &= !(slate_rt::term::ICANON | slate_rt::term::ECHO);
    raw.cc[slate_rt::term::VMIN] = 1;
    raw.cc[slate_rt::term::VTIME] = 0;
    raw
}

/// The `f` screen while it is up: its cursor, and whether the field under
/// it is picked up to move.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FieldsScreen {
    pub cursor: usize,
    pub moving: bool,
}

/// `Z`'s screen while it is up: the window it colours, the part chosen,
/// and the colours and toggles until they are kept (Enter, `a`, `w`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ColourScreen {
    pub win: usize,
    pub part: Part,
    pub colours: [i8; 5],
    pub colour: bool,
    pub hi_reverse: bool,
}

impl ColourScreen {
    fn of(s: &Settings, win: usize) -> ColourScreen {
        let w = &s.wins[win];
        ColourScreen { win, part: Part::Tasks, colours: w.colours, colour: w.colour, hi_reverse: w.hi_reverse }
    }

    fn keep(&self, s: &mut Settings) {
        let w = &mut s.wins[self.win];
        (w.colours, w.colour, w.hi_reverse) = (self.colours, self.colour, self.hi_reverse);
    }
}

/// The screens and prompts the keys act on.
#[derive(Debug, Default)]
pub struct Ui {
    pub fields: Option<FieldsScreen>,
    pub colours: Option<ColourScreen>,
    pub help: bool,
    pub message: String,
    /// `C`: say where the window is scrolled to.
    pub coordinates: bool,
    /// The current window's tasks and rows for them in the last frame
    /// (for scrolling).
    pub tasks: usize,
    pub page: usize,
}

/// `Z`'s screen: a sample in the colours chosen, the parts and colours to
/// choose from, and the keys.
pub fn colour_screen(s: &Settings, c: &ColourScreen) -> String {
    let w = &s.wins[c.win];
    let name = alloc::format!("{}:{}", c.win + 1, w.name);
    let col = |p: Part| if c.colour { fg(c.colours[p as usize]) } else { String::new() };
    let hi = col(Part::Highlights) + if c.hi_reverse { "\x1b[7m" } else { "\x1b[1m" };
    let on = |v: bool| if v { "On" } else { "Off" };
    let parts =
        [(Part::Summary, 'S'), (Part::Messages, 'M'), (Part::Heads, 'H'), (Part::Tasks, 'T'), (Part::Highlights, 'X')];
    let letter = parts.iter().find(|p| p.0 == c.part).map_or('T', |p| p.1);
    let r = "\x1b[m";
    let mut out = alloc::format!("\x1b[1mHelp for color mapping{r} - \"Current Window\" = \x1b[7m {name} {r}\n\n");
    let summary = col(Part::Summary);
    out.push_str(&alloc::format!("   {summary}top - 12:00:00 up 1 day, load average: 0.10{r}\n"));
    out.push_str(&alloc::format!("   {summary}Tasks:  64 total,   2 running,  62 sleeping{r}\n"));
    let msg = col(Part::Messages);
    out.push_str(&alloc::format!("   {msg}\x1b[7m Nasty Message! {r}  -or-  {msg}\x1b[1mInput Prompt{r}\n"));
    let head = col(Part::Heads);
    out.push_str(&alloc::format!("   {head}\x1b[7m  PID USER      %CPU S COMMAND    {r}\n"));
    let task = col(Part::Tasks);
    out.push_str(&alloc::format!("   {task}17284 {hi}alex     {r}{task}  0.0 S chalk      {r}\n"));
    out.push_str(&alloc::format!("   {hi} 8601 alex       0.4 R top        {r}\n"));
    out.push_str(&alloc::format!("   {task}11005 {hi}alex     {r}{task}  0.0 S terminal   {r}\n"));
    out.push_str(&alloc::format!(
        "   available toggles: \x1b[1mz{r} =color/mono (\x1b[1m{}{r}), \x1b[1mb{r} =tasks bold/reverse (\x1b[1m{}{r})\n\n",
        on(c.colour),
        on(c.hi_reverse)
    ));
    out.push_str(&alloc::format!(
        "1) Select a \x1b[1mtarget{r} as an upper case letter, \x1b[1mcurrent target{r} is \x1b[7m {letter} {r}:\n\
         \x20  S = Summary Data,  M = Messages/Prompts,  H = Column Heads\n\
         \x20  T = Task Information,  X = Task x/y (col/row) Highlights\n\
         2) Select a \x1b[1mcolor{r} as a number (\x1b[1mnone{r} as @) or use the up/down arrow\n\
         \x20  keys to raise/lower the 8 colors value, \x1b[1mcurrent color{r} is \x1b[7m {} {r}:\n\
         \x20  0 = black,  1 = red,    2 = green,  3 = yellow,\n\
         \x20  4 = blue,   5 = magenta, 6 = cyan,  7 = white,  @ = none (-1)\n\n\
         3) Then use these keys when finished:\n\
         \x20  'q' or <Esc> to abort changes to window '\x1b[1m{name}{r}'\n\
         \x20  'a' or 'w' to commit & change another, <Enter> to commit and end\n",
        c.colours[c.part as usize]
    ));
    out
}

/// Window `w`'s rows: filtered, with what its fields need, sorted, and as
/// a tree in the forest view.
fn window_rows<'a>(tasks: &'a [Proc], cpu: &[f64], w: &Win, s: &Settings, ctx: &Ctx) -> Vec<Row<'a>> {
    let extra = w.fields.iter().chain(w.filters.iter().map(|f| &f.f)).any(|f| needs_extra(*f)) || needs_extra(w.sort);
    let mut rows: Vec<Row<'a>> = tasks
        .iter()
        .zip(cpu)
        .map(|(p, &c)| Row { x: extra.then(|| procs::extra(p.pid, p.lwp)), ..Row::new(p, c) })
        .filter(|r| !s.hide_idle || r.cpu > 0.0 || r.p.state == b'R')
        .filter(|r| w.filters.iter().all(|f| f.keeps(&cell(f.f, r, ctx, s))))
        .collect();
    sort(&mut rows, w, s, ctx);
    if s.forest { forest(rows) } else { rows }
}

pub fn top(args: &[Vec<u8>]) -> i32 {
    let mut s = settings_path()
        .and_then(|p| fs::read_file(&p).ok())
        .map_or_else(Settings::default, |t| Settings::parse(&lossy(&t)));
    let (mut batch, mut frames) = (false, None::<u64>);
    let (mut only_user, mut only_pids) = (None::<u32>, Vec::<u32>::new());
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        let val = |i: &mut usize| -> Option<Vec<u8>> {
            if a.len() > 2 {
                Some(a[2..].to_vec())
            } else {
                *i += 1;
                args.get(*i).cloned()
            }
        };
        match a.get(..2) {
            Some(b"-b") => batch = true,
            Some(b"-n") => frames = val(&mut i).and_then(|v| parse_num(&v)),
            Some(b"-d") => s.delay = val(&mut i).and_then(|v| lossy(&v).parse().ok()).unwrap_or(3.0),
            Some(b"-1") => s.per_cpu = !s.per_cpu,
            Some(b"-H") => s.threads = !s.threads,
            Some(b"-c") => s.command_lines = !s.command_lines,
            Some(b"-i") => s.hide_idle = !s.hide_idle,
            Some(b"-s") => s.secure = true,
            Some(b"-O") => {
                for sp in &FIELDS {
                    println!("{}", sp.name);
                }
                return 0;
            }
            Some(b"-u" | b"-U") => {
                let v = val(&mut i).unwrap_or_default();
                match parse_num(&v).or_else(|| crate::fileops::lookup_id(&v, b"/etc/passwd")) {
                    Some(id) => only_user = Some(id),
                    None => {
                        error(format_args!("Invalid user: {}", lossy(&v)));
                        return 1;
                    }
                }
            }
            Some(b"-p") => {
                let v = val(&mut i).unwrap_or_default();
                only_pids.extend(lossy(&v).split(',').filter_map(|p| p.trim().parse::<u32>().ok()));
            }
            Some(b"-o") => {
                let v = lossy(&val(&mut i).unwrap_or_default()).into_owned();
                let name = v.trim_start_matches(['+', '-']);
                match field(name).or_else(|| (name == "TIME").then_some(F::Time)) {
                    Some(f) => s.win_mut().sort = f,
                    None => {
                        error(format_args!("unknown sort field '{name}'"));
                        return 1;
                    }
                }
                // `+` high to low, `-` low to high (top(1), -o).
                if v.starts_with('-') {
                    s.win_mut().reverse = true;
                } else if v.starts_with('+') {
                    s.win_mut().reverse = false;
                }
            }
            _ => {
                error(format_args!("unknown option '{}'", lossy(a)));
                return 1;
            }
        }
        i += 1;
    }
    let interactive = !batch && slate_rt::term::isatty(io::STDIN) && slate_rt::term::isatty(io::STDOUT);
    let saved = if interactive { slate_rt::term::get(io::STDIN).ok() } else { None };
    if let Some(t) = saved {
        let _ = slate_rt::term::set(io::STDIN, &raw(t), false);
        io::out(b"\x1b[?1049h\x1b[?25l");
    }
    let mut prev: Vec<(u32, u64)> = Vec::new();
    let mut prev_cpu = procs::cpu_ticks();
    let mut prev_t = procs::uptime();
    let mut n = 0;
    let mut ui = Ui::default();
    loop {
        let ctx = Ctx::new();
        let wanted =
            |p: &Proc| only_user.is_none_or(|u| p.uid == u) && (only_pids.is_empty() || only_pids.contains(&p.pid));
        let procs: Vec<Proc> = procs::all().into_iter().filter(wanted).collect();
        let tasks: Vec<Proc> = if s.threads {
            procs
                .iter()
                .flat_map(|p| {
                    let ts = procs::threads_of(p.pid);
                    if ts.is_empty() { alloc::vec![p.clone()] } else { ts }
                })
                .collect()
        } else {
            procs.clone()
        };
        let cpu = procs::cpu_ticks();
        let dt = (ctx.now - prev_t).max(0.001);
        let at = |v: &Vec<(u64, u64)>, i: usize| v.get(i).copied().unwrap_or((0, 0));
        let busy = procs::busy_pct(at(&cpu, 0), at(&prev_cpu, 0));
        // CPU since the last frame (or over the task's life, first).
        let shares: Vec<f64> = tasks
            .iter()
            .map(|p| {
                let t = p.utime + p.stime;
                match prev.iter().find(|(id, _)| *id == p.lwp) {
                    Some(&(_, old)) => t.saturating_sub(old) as f64 / HZ as f64 * 100.0 / dt,
                    None => {
                        let age = (ctx.now - p.start as f64 / HZ as f64).max(0.001);
                        t as f64 / HZ as f64 * 100.0 / age
                    }
                }
            })
            .collect();
        let (height, width) = if interactive {
            slate_rt::term::size(io::STDOUT).map(|(r, c)| (usize::from(r), usize::from(c))).unwrap_or((24, 80))
        } else {
            (usize::MAX, 512)
        };
        // The summary and messages in the current window's colours.
        let cw = s.win();
        let (on, off) =
            if interactive && cw.colour { (cw.colour_of(Part::Summary), "\x1b[m") } else { (String::new(), "") };
        let msg_on = if interactive { cw.colour_of(Part::Messages) } else { String::new() };
        let mut frame = String::new();
        let up = ctx.now as u64;
        let tm = slate_rt::tz::localtime(slate_rt::time::unix());
        let la = procs::loadavg();
        let span = if up >= 86_400 {
            alloc::format!("{} days, {:2}:{:02}", up / 86_400, up / 3600 % 24, up / 60 % 60)
        } else {
            alloc::format!("{:2}:{:02}", up / 3600, up / 60 % 60)
        };
        frame.push_str(&alloc::format!(
            "{on}top - {:02}:{:02}:{:02} up {span}, load average: {}, {}, {}{off}\n",
            tm.hour,
            tm.min,
            tm.sec,
            la[0],
            la[1],
            la[2]
        ));
        let count = |st: u8| tasks.iter().filter(|p| p.state == st).count();
        frame.push_str(&alloc::format!(
            "{on}{}: {} total, {} running, {} sleeping, {} stopped, {} zombie{off}\n",
            if s.threads { "Threads" } else { "Tasks" },
            tasks.len(),
            count(b'R'),
            count(b'S') + count(b'D') + count(b'I'),
            count(b'T') + count(b't'),
            count(b'Z')
        ));
        if s.per_cpu && cpu.len() > 1 {
            for c in 1..cpu.len() {
                let b = procs::busy_pct(at(&cpu, c), at(&prev_cpu, c));
                frame.push_str(&alloc::format!("{on}%Cpu{:<3}: {b:5.1} busy, {:5.1} idle{off}\n", c - 1, 100.0 - b));
            }
        } else {
            frame.push_str(&alloc::format!("{on}%Cpu(s): {busy:5.1} busy, {:5.1} idle{off}\n", 100.0 - busy));
        }
        let m = procs::meminfo();
        let get = |k: &str| m.iter().find(|e| e.0 == k).map_or(0, |e| e.1);
        let unit = UNITS[s.scale_summary];
        let sum = |kb: u64| kb as f64 / (1u64 << (10 * s.scale_summary)) as f64;
        frame.push_str(&alloc::format!(
            "{on}{unit} Mem : {:8.1} total, {:8.1} free, {:8.1} available, {:8.1} buff/cache{off}\n",
            sum(get("MemTotal")),
            sum(get("MemFree")),
            sum(get("MemAvailable")),
            sum(get("Buffers") + get("Cached"))
        ));
        frame.push_str(&alloc::format!(
            "{on}{unit} Swap: {:8.1} total, {:8.1} free, {:8.1} used{off}\n",
            sum(get("SwapTotal")),
            sum(get("SwapFree")),
            sum(get("SwapTotal").saturating_sub(get("SwapFree")))
        ));
        if ui.message.is_empty() && ui.coordinates {
            ui.message = alloc::format!(
                "scroll coordinates: y = {}/{} (tasks), x = {}/{} (fields)",
                cw.first_task.min(ui.tasks.saturating_sub(1)) + 1,
                ui.tasks,
                cw.first_field.min(cw.fields.len() - 1) + 1,
                cw.fields.len()
            );
        }
        frame.push_str(&alloc::format!("{msg_on}{}{off}\n", ui.message));
        let summary_lines = frame.lines().count();
        let shown: Vec<usize> = if s.alt { (0..4).collect() } else { alloc::vec![s.cur] };
        // Each window: a title line when all four show, its header, rows.
        let titles = usize::from(s.alt);
        let per = height.saturating_sub(summary_lines) / shown.len();
        for &wi in &shown {
            let w = &s.wins[wi];
            if s.alt {
                let mark = if wi == s.cur { "*" } else { " " };
                frame.push_str(&alloc::format!("{mark}{}:{}\n", wi + 1, w.name));
            }
            let head = header(w.shown_fields());
            if interactive {
                let colour = w.colour_of(Part::Heads);
                frame.push_str(&alloc::format!(
                    "{colour}\x1b[7m{:<width$}\x1b[m\n",
                    head,
                    width = width.saturating_sub(1)
                ));
            } else {
                frame.push_str(&head);
                frame.push('\n');
            }
            let rows = window_rows(&tasks, &shares, w, &s, &ctx);
            let room = per.saturating_sub(1 + titles);
            if wi == s.cur {
                (ui.tasks, ui.page) = (rows.len(), room);
            }
            let first = w.first_task.min(rows.len().saturating_sub(1));
            for r in rows.iter().skip(first).take(room) {
                if interactive {
                    frame.push_str(&task_line(w, r, &ctx, &s, width.saturating_sub(1)));
                } else {
                    frame.push_str(&line(w.shown_fields(), r, &ctx, &s));
                }
                frame.push('\n');
            }
        }
        if let Some(f) = ui.fields {
            frame = fields_screen(&s, f.cursor, f.moving);
        } else if let Some(c) = &ui.colours {
            frame = colour_screen(&s, c);
        } else if ui.help {
            frame = alloc::format!("{HELP}\n");
        }
        if interactive {
            io::out(b"\x1b[H\x1b[J");
            io::out(frame.replace('\n', "\x1b[K\r\n").as_bytes());
        } else {
            io::out(frame.as_bytes());
            io::out(b"\n");
        }
        io::flush_stdout();
        prev = tasks.iter().map(|p| (p.lwp, p.utime + p.stime)).collect();
        prev_cpu = cpu;
        prev_t = ctx.now;
        n += 1;
        if frames.is_some_and(|f| n >= f) {
            break;
        }
        ui.message.clear();
        if !interactive {
            slate_rt::time::sleep_ns((s.delay * 1e9) as u64);
            continue;
        }
        // Wait for the delay or a key (screens wait for a key alone).
        let ms = if ui.fields.is_some() || ui.colours.is_some() || ui.help { -1 } else { (s.delay * 1000.0) as i32 };
        let mut fds = [io::PollFd { fd: io::STDIN, events: io::POLLIN, revents: 0 }];
        if io::poll(&mut fds, ms).unwrap_or(0) == 0 {
            continue;
        }
        let mut buf = [0u8; 64];
        let got = io::read(io::STDIN, &mut buf).unwrap_or(0);
        if got == 0 {
            break;
        }
        let mut quit = false;
        for (k, esc) in keys(&buf[..got]) {
            let ask = |q: &str| prompt(q, saved);
            if self::key(k, esc, &mut s, &mut ui, &ask) {
                quit = true;
                break;
            }
        }
        if quit {
            break;
        }
    }
    if let Some(t) = saved {
        io::out(b"\x1b[?25h\x1b[?1049l");
        io::flush_stdout();
        let _ = slate_rt::term::set(io::STDIN, &t, false);
    }
    0
}

/// One key typed: true to quit. `ask` reads a line for the prompts.
pub fn key(k: u8, esc: bool, s: &mut Settings, ui: &mut Ui, ask: &dyn Fn(&str) -> String) -> bool {
    if ui.help {
        ui.help = false;
        return false;
    }
    if let Some(FieldsScreen { cursor: c, moving }) = ui.fields {
        let last = s.win().order.len() - 1;
        let f = s.win().order[c];
        ui.fields = match (k, esc, moving) {
            // Picked up: Up and Down carry it, Left or Enter put it down.
            (b'A', true, true) | (b'k', false, true) => Some(FieldsScreen { cursor: move_field(s, c, true), moving }),
            (b'B', true, true) | (b'j', false, true) => Some(FieldsScreen { cursor: move_field(s, c, false), moving }),
            (b'D', true, true) | (b'\r' | b'\n', false, true) => Some(FieldsScreen { cursor: c, moving: false }),
            (b'C', true, false) => Some(FieldsScreen { cursor: c, moving: true }),
            (b'A', true, _) | (b'k', false, _) => Some(FieldsScreen { cursor: c.saturating_sub(1), moving }),
            (b'B', true, _) | (b'j', false, _) => Some(FieldsScreen { cursor: (c + 1).min(last), moving }),
            (b'd' | b' ', false, _) => {
                toggle(s, f);
                Some(FieldsScreen { cursor: c, moving })
            }
            (b's', false, _) => {
                s.win_mut().sort = f;
                Some(FieldsScreen { cursor: c, moving })
            }
            (b'q' | 0x1b | b'f' | b'\r' | b'\n', false, _) => None,
            _ => Some(FieldsScreen { cursor: c, moving }),
        };
        return false;
    }
    if let Some(mut c) = ui.colours {
        let n = &mut c.colours[c.part as usize];
        match (k, esc) {
            (b'S', false) => c.part = Part::Summary,
            (b'M', false) => c.part = Part::Messages,
            (b'H', false) => c.part = Part::Heads,
            (b'T', false) => c.part = Part::Tasks,
            (b'X', false) => c.part = Part::Highlights,
            (b'0'..=b'7', false) => *n = (k - b'0') as i8,
            (b'@', false) => *n = -1,
            (b'A', true) => *n = if *n >= 7 { -1 } else { *n + 1 },
            (b'B', true) => *n = if *n <= -1 { 7 } else { *n - 1 },
            (b'z', false) => c.colour = !c.colour,
            (b'b', false) => c.hi_reverse = !c.hi_reverse,
            (b'a' | b'w', false) => {
                c.keep(s);
                let next = if k == b'a' { (c.win + 1) % 4 } else { (c.win + 3) % 4 };
                c = ColourScreen::of(s, next);
            }
            (b'\r' | b'\n', false) => {
                c.keep(s);
                s.cur = c.win;
                ui.colours = None;
                return false;
            }
            (b'q' | 0x1b, false) => {
                s.cur = c.win;
                ui.colours = None;
                return false;
            }
            _ => {}
        }
        ui.colours = Some(c);
        return false;
    }
    if esc {
        // Scrolling the current window: a task, a page, a field, the ends.
        let (tasks, page) = (ui.tasks, ui.page.max(1));
        let w = s.win_mut();
        let last_task = tasks.saturating_sub(1);
        match k {
            b'A' => w.first_task = w.first_task.min(last_task).saturating_sub(1),
            b'B' => w.first_task = (w.first_task + 1).min(last_task),
            b'5' => w.first_task = w.first_task.min(last_task).saturating_sub(page),
            b'6' => w.first_task = (w.first_task + page).min(last_task),
            b'D' => w.first_field = w.first_field.min(w.fields.len() - 1).saturating_sub(1),
            b'C' => w.first_field = (w.first_field + 1).min(w.fields.len() - 1),
            b'H' | b'1' | b'7' => (w.first_task, w.first_field) = (0, 0),
            b'F' | b'4' | b'8' => w.first_task = tasks.saturating_sub(page),
            _ => {}
        }
        return false;
    }
    let refused = |ui: &mut Ui| ui.message = String::from("Unavailable in secure mode");
    match k {
        b'q' | 3 => return true,
        b'P' => s.win_mut().sort = F::Cpu,
        b'M' => s.win_mut().sort = F::Mem,
        b'T' => s.win_mut().sort = F::TimePlus,
        b'N' => s.win_mut().sort = F::Pid,
        b'R' => s.win_mut().reverse = !s.win().reverse,
        b'1' => s.per_cpu = !s.per_cpu,
        b'A' => s.alt = !s.alt,
        b'a' => s.cur = (s.cur + 1) % 4,
        b'w' => s.cur = (s.cur + 3) % 4,
        b'g' => {
            let a = ask("Choose field group (1 - 4): ");
            match a.parse::<usize>() {
                Ok(n) if (1..=4).contains(&n) => s.cur = n - 1,
                _ if a.is_empty() => {}
                _ => ui.message = String::from("Invalid field group"),
            }
        }
        b'V' => {
            s.forest = !s.forest;
            ui.message = String::from(if s.forest { "Forest mode On" } else { "Forest mode Off" });
        }
        b'E' => s.scale_summary = (s.scale_summary + 1) % UNITS.len(),
        b'e' => s.scale_tasks = (s.scale_tasks + 1) % (UNITS.len() - 1),
        b'z' => s.win_mut().colour = !s.win().colour,
        b'Z' => ui.colours = Some(ColourScreen::of(s, s.cur)),
        b'x' => s.win_mut().hi_column = !s.win().hi_column,
        b'y' => s.win_mut().hi_running = !s.win().hi_running,
        b'b' => s.win_mut().hi_reverse = !s.win().hi_reverse,
        b'<' | b'>' => s.win_mut().move_sort(k == b'<'),
        b'C' => ui.coordinates = !ui.coordinates,
        b'o' | b'O' => {
            let n = s.win().filters.len() + 1;
            let case = if k == b'O' { "" } else { "ignoring case" };
            let a = ask(&alloc::format!("add filter #{n} ({case}) as: [!]FLD?VAL "));
            if !a.is_empty() {
                match Filter::parse(&a, k == b'O') {
                    Ok(f) => s.win_mut().filters.push(f),
                    Err(why) => ui.message = String::from(why),
                }
            }
        }
        0x0f => {
            let f: Vec<String> = s.win().filters.iter().map(Filter::text).collect();
            ui.message = if f.is_empty() {
                String::from("No active filters")
            } else {
                alloc::format!("Active filters: {}", f.join(" "))
            };
        }
        b'=' => s.win_mut().filters.clear(),
        b'H' => {
            s.threads = !s.threads;
            ui.message = String::from(if s.threads { "Show threads On" } else { "Show threads Off" });
        }
        b'c' => s.command_lines = !s.command_lines,
        b'i' => s.hide_idle = !s.hide_idle,
        b'f' | b'F' => {
            let at = s.win().order.iter().position(|f| *f == s.win().sort).unwrap_or(0);
            ui.fields = Some(FieldsScreen { cursor: at, moving: false });
        }
        b'h' | b'?' => ui.help = true,
        b'd' | b's' if s.secure => refused(ui),
        b'd' | b's' => {
            let a = ask(&alloc::format!("Change delay from {:.1} to ", s.delay));
            match a.parse::<f64>() {
                Ok(d) if d >= 0.0 => s.delay = d,
                _ if a.is_empty() => {}
                _ => ui.message = String::from("Unacceptable floating point"),
            }
        }
        b'W' => {
            ui.message = match settings_path() {
                Some(p) => {
                    let _ = fs::mkdir(fs::dirname(fs::dirname(&p)), 0o755);
                    let _ = fs::mkdir(fs::dirname(&p), 0o755);
                    match fs::write_file(&p, s.text().as_bytes(), 0o644) {
                        Ok(()) => alloc::format!("Wrote configuration to '{}'", lossy(&p)),
                        Err(e) => alloc::format!("Failed to write configuration to '{}': {e}", lossy(&p)),
                    }
                }
                None => String::from("No HOME to write the configuration in"),
            };
        }
        b'k' if s.secure => refused(ui),
        b'k' => {
            let a = ask("PID to signal/kill: ");
            ui.message = match parse_num::<i32>(a.as_bytes()) {
                Some(pid) => match slate_rt::process::kill(pid, slate_rt::signal::SIGTERM) {
                    Ok(()) => alloc::format!("Sent SIGTERM to {pid}"),
                    Err(e) => alloc::format!("Failed to signal {pid}: {e}"),
                },
                None => String::new(),
            };
        }
        _ => {}
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Ctx {
        Ctx { now: 100.0, boot_time: 0, mem_kb: 1000, fg: None, page_kb: 4 }
    }

    #[test]
    fn fields_and_lines() {
        let s = Settings::default();
        assert_eq!(header(&s.win().fields), "  PID USER       PR  NI    VIRT    RES S  %CPU  %MEM     TIME+ COMMAND");
        let p = Proc {
            pid: 42,
            lwp: 42,
            uid: 0,
            prio: 20,
            vsize: 2048 * 1024,
            rss: 25,
            state: b'S',
            utime: 6123,
            comm: "chalk".into(),
            args: "chalk -l".into(),
            ..Default::default()
        };
        let r = Row::new(&p, 1.25);
        assert_eq!(
            line(&s.win().fields, &r, &ctx(), &s),
            "   42 root       20   0    2048    100 S   1.2  10.0   1:01.23 chalk"
        );
        let mut wide = Settings { command_lines: true, ..Settings::default() };
        wide.win_mut().fields = alloc::vec![F::Command, F::Pid];
        assert_eq!(header(&wide.win().fields), "COMMAND           PID");
        assert_eq!(line(&wide.win().fields, &r, &ctx(), &wide), "chalk -l           42");
        assert_eq!(field("%cpu"), Some(F::Cpu));
        assert_eq!(field("nth"), Some(F::Nth));
        // The memory fields, in KiB and scaled (`e`).
        let x = Extra { shared: 10, text: 5, data: 300, swap_kb: 0, wchan: String::from("poll") };
        let r = Row { x: Some(x), ..Row::new(&p, 0.0) };
        let mem = [F::Shr, F::Code, F::Data, F::Swap, F::Wchan];
        assert_eq!(line(&mem, &r, &ctx(), &s), "    40     20    1200      0 poll");
        let big = Settings { scale_tasks: 1, ..Settings::default() };
        assert_eq!(line(&[F::Data, F::Virt], &r, &ctx(), &big), "   1.2m    2.0m");
    }

    #[test]
    fn settings_round_trip_toggle_and_move() {
        let mut s = Settings { delay: 1.5, threads: true, forest: true, cur: 2, alt: true, ..Settings::default() };
        s.cur = 0;
        s.win_mut().sort = F::Mem;
        s.win_mut().reverse = true;
        toggle(&mut s, F::Nth);
        toggle(&mut s, F::Virt);
        assert_eq!(header(&s.win().fields), "  PID USER       PR  NI nTH    RES S  %CPU  %MEM     TIME+ COMMAND");
        // COMMAND moved up past the hidden WCHAN, SID, PGRP and TIME, and
        // past TIME+ and %MEM.
        let mut at = s.win().order.iter().position(|f| *f == F::Command).unwrap();
        for _ in 0..6 {
            at = move_field(&mut s, at, true);
        }
        assert_eq!(s.win().order[at], F::Command);
        let h = header(&s.win().fields);
        assert!(h.ends_with("%CPU COMMAND          %MEM     TIME+"), "{h}");
        s.cur = 3;
        toggle(&mut s, F::Wchan);
        assert_eq!(Settings::parse(&s.text()), s);
        // An older file: fields only; unknown keys and fields are passed over.
        let t = Settings::parse("fields=PID,BOGUS,COMMAND\nsort=NOPE\nfuture=1\ndelay=-2\nw3.sort=VIRT\n");
        assert_eq!((t.win().fields.clone(), t.win().sort, t.delay), (alloc::vec![F::Pid, F::Command], F::Cpu, 3.0));
        assert_eq!(t.wins[2].sort, F::Virt);
        let screen = fields_screen(&s, 0, false);
        assert!(screen.contains("window 4:Usr"));
        let s0 = Settings { cur: 0, ..s.clone() };
        let screen = fields_screen(&s0, 0, false);
        assert!(screen.contains("current sort field is %MEM"));
        assert!(screen.contains("* nTH     = Number of Threads") && screen.contains("  VIRT    = Virtual Image (KiB)"));
    }

    #[test]
    fn keys_in_one_read() {
        assert_eq!(keys(b"\x1b[A\x1b[Ax q"), [(b'A', true), (b'A', true), (b'x', false), (b' ', false), (b'q', false)]);
        assert_eq!(keys(b"\x1b[1;5B\x1bOA\x1b"), [(b'B', true), (b'A', true), (0x1b, false)]);
    }

    #[test]
    fn sorting_filters_and_forest() {
        let p = |pid, ppid, rss, t| Proc {
            pid,
            lwp: pid,
            ppid,
            rss,
            utime: t,
            comm: alloc::format!("p{pid}"),
            ..Default::default()
        };
        let ps = [p(1, 0, 5, 10), p(2, 1, 9, 30), p(3, 1, 9, 20), p(4, 2, 1, 5)];
        let mut rows: Vec<Row<'_>> = ps.iter().map(|p| Row::new(p, 0.0)).collect();
        let mut s = Settings::default();
        s.win_mut().sort = F::Res;
        let w = s.win().clone();
        sort(&mut rows, &w, &s, &ctx());
        assert_eq!(rows.iter().map(|r| r.p.pid).collect::<Vec<_>>(), [2, 3, 1, 4]);
        s.win_mut().reverse = true;
        s.win_mut().sort = F::TimePlus;
        let w = s.win().clone();
        sort(&mut rows, &w, &s, &ctx());
        assert_eq!(rows.iter().map(|r| r.p.pid).collect::<Vec<_>>(), [4, 1, 3, 2]);
        // The forest: children under their parents, in the sort's order.
        let tree = forest(rows);
        let shape: Vec<(u32, usize)> = tree.iter().map(|r| (r.p.pid, r.depth)).collect();
        assert_eq!(shape, [(1, 0), (3, 1), (2, 1), (4, 2)]);
        assert_eq!(cell(F::Command, &tree[3], &ctx(), &s), "     `- p4");
        // Filters: text (case or not), numbers, negated.
        let r = Row::new(&ps[1], 7.5);
        let keeps = |t: &str, case: bool| {
            Filter::parse(t, case).unwrap().keeps(&cell(Filter::parse(t, case).unwrap().f, &r, &ctx(), &s))
        };
        assert!(keeps("COMMAND=P2", false) && !keeps("COMMAND=P2", true));
        assert!(keeps("%CPU>5", false) && !keeps("%CPU<5", false) && keeps("!PID=3", false));
        assert_eq!(Filter::parse("BOGUS=1", false), Err("Unrecognized field name"));
        assert_eq!(Filter::parse("PID", false), Err("Unacceptable filter expression"));
    }

    #[test]
    fn keys_act() {
        let mut s = Settings::default();
        let mut ui = Ui::default();
        let none = |_: &str| String::new();
        for k in [b'A', b'a', b'V', b'E', b'e', b'z'] {
            key(k, false, &mut s, &mut ui, &none);
        }
        // `z` coloured the window current then (1), before `a` moved on.
        assert!(s.alt && s.forest && s.wins[1].colour && !s.wins[0].colour);
        assert_eq!((s.cur, s.scale_summary, s.scale_tasks), (1, 2, 1));
        key(b'w', false, &mut s, &mut ui, &none);
        key(b'g', false, &mut s, &mut ui, &|_| String::from("3"));
        assert_eq!(s.cur, 2);
        key(b'o', false, &mut s, &mut ui, &|_| String::from("USER=root"));
        key(0x0f, false, &mut s, &mut ui, &none);
        assert_eq!(ui.message, "Active filters: USER=root");
        key(b'=', false, &mut s, &mut ui, &none);
        assert!(s.win().filters.is_empty());
        // The fields screen: Right picks up, Down carries, Enter puts down.
        key(b'f', false, &mut s, &mut ui, &none);
        let start = ui.fields.unwrap().cursor;
        let picked = s.win().order[start];
        key(b'C', true, &mut s, &mut ui, &none);
        key(b'B', true, &mut s, &mut ui, &none);
        key(b'\r', false, &mut s, &mut ui, &none);
        assert_eq!(s.win().order[start + 1], picked);
        assert_eq!(ui.fields, Some(FieldsScreen { cursor: start + 1, moving: false }));
        key(b'q', false, &mut s, &mut ui, &none);
        // Secure mode refuses signals and delays.
        s.secure = true;
        key(b'k', false, &mut s, &mut ui, &|_| String::from("1"));
        assert_eq!(ui.message, "Unavailable in secure mode");
    }

    #[test]
    fn highlights_and_colours() {
        let mut s = Settings::default();
        let run = Proc { pid: 7, lwp: 7, state: b'R', comm: "top".into(), ..Default::default() };
        let idle = Proc { pid: 8, lwp: 8, state: b'S', comm: "chalk".into(), ..Default::default() };
        let w = s.win().clone();
        // At first: running tasks bold, nothing else.
        let l = task_line(&w, &Row::new(&run, 0.0), &ctx(), &s, 200);
        assert!(l.starts_with("\x1b[m\x1b[1m    7") && l.ends_with("\x1b[m"), "{l:?}");
        let l = task_line(&w, &Row::new(&idle, 0.0), &ctx(), &s, 200);
        assert!(!l.contains("\x1b[1m") && !l.contains("\x1b[7m"));
        // `x` the sort column, `b` in reverse, `z` in colour (red, the first highlights').
        let mut ui = Ui::default();
        let none = |_: &str| String::new();
        for k in [b'x', b'b', b'z'] {
            key(k, false, &mut s, &mut ui, &none);
        }
        let w = s.win().clone();
        let l = task_line(&w, &Row::new(&idle, 2.5), &ctx(), &s, 200);
        assert!(l.contains("\x1b[m\x1b[31m\x1b[7m  2.5"), "{l:?}");
        // Cut to the width, escapes not counted.
        let l = task_line(&w, &Row::new(&idle, 2.5), &ctx(), &s, 10);
        let mut plain = String::new();
        let mut in_escape = false;
        for c in l.chars() {
            match c {
                '\x1b' => in_escape = true,
                'm' if in_escape => in_escape = false,
                c if !in_escape => plain.push(c),
                _ => {}
            }
        }
        assert_eq!(plain, "    8 root");
        // `<` and `>` move the sort among the shown fields.
        key(b'<', false, &mut s, &mut ui, &none);
        assert_eq!(s.win().sort, F::S);
        key(b'>', false, &mut s, &mut ui, &none);
        key(b'>', false, &mut s, &mut ui, &none);
        assert_eq!(s.win().sort, F::Mem);
        // The settings keep each window's look.
        s.wins[2].colours = [2, -1, 4, 6, 5];
        assert_eq!(Settings::parse(&s.text()), s);
        assert!(Settings::parse("colours=9,1,2,3,4\n").wins[0].colours == [-1, 1, 2, 3, 4]);
    }

    #[test]
    fn colour_screen_keys() {
        let mut s = Settings::default();
        let mut ui = Ui::default();
        let none = |_: &str| String::new();
        key(b'Z', false, &mut s, &mut ui, &none);
        assert!(colour_screen(&s, &ui.colours.unwrap()).contains("\"Current Window\" = \x1b[7m 1:Def"));
        // Tasks green, the heads one up from yellow; `q` forgets them.
        for (k, esc) in [(b'2', false), (b'H', false), (b'A', true), (b'z', false), (b'q', false)] {
            key(k, esc, &mut s, &mut ui, &none);
        }
        assert_eq!((s.win().colours, s.win().colour, ui.colours), (COLOURS, false, None));
        // Again, kept with `a` for window 1, and window 2's with Enter.
        for (k, esc) in [(b'Z', false), (b'2', false), (b'z', false), (b'a', false), (b'@', false), (b'\r', false)] {
            key(k, esc, &mut s, &mut ui, &none);
        }
        assert_eq!((s.wins[0].colours[Part::Tasks as usize], s.wins[0].colour), (2, true));
        assert_eq!((s.wins[1].colours[Part::Tasks as usize], s.cur), (-1, 1));
    }

    #[test]
    fn scrolling() {
        let mut s = Settings::default();
        let mut ui = Ui { tasks: 50, page: 20, ..Ui::default() };
        let none = |_: &str| String::new();
        let press = |k: &[u8], s: &mut Settings, ui: &mut Ui| {
            for (k, esc) in keys(k) {
                key(k, esc, s, ui, &none);
            }
        };
        press(b"\x1b[B\x1b[B\x1b[6~", &mut s, &mut ui);
        assert_eq!(s.win().first_task, 22);
        press(b"\x1b[6~\x1b[6~", &mut s, &mut ui);
        assert_eq!(s.win().first_task, 49);
        press(b"\x1b[5~\x1bOA", &mut s, &mut ui);
        assert_eq!(s.win().first_task, 28);
        press(b"\x1b[C\x1b[C", &mut s, &mut ui);
        assert_eq!(s.win().shown_fields()[0], F::Pr);
        press(b"\x1b[4~", &mut s, &mut ui);
        assert_eq!((s.win().first_task, s.win().first_field), (30, 2));
        press(b"\x1b[H", &mut s, &mut ui);
        assert_eq!((s.win().first_task, s.win().first_field), (0, 0));
        assert_eq!(keys(b"\x1b[5~\x1b[1~\x1b[F"), [(b'5', true), (b'1', true), (b'F', true)]);
    }

    #[test]
    fn threads_in_the_forest() {
        // Process 1 with thread 5; process 2 (under 1) with threads 3 and 4.
        let t = |pid, lwp, ppid| Proc { pid, lwp, ppid, comm: alloc::format!("t{lwp}"), ..Default::default() };
        let ps = [t(1, 1, 0), t(1, 5, 0), t(2, 2, 1), t(2, 3, 1), t(2, 4, 1)];
        let rows: Vec<Row<'_>> = ps.iter().map(|p| Row::new(p, 0.0)).collect();
        let shape: Vec<(u32, usize)> = forest(rows).iter().map(|r| (r.p.lwp, r.depth)).collect();
        assert_eq!(shape, [(1, 0), (5, 1), (2, 1), (3, 2), (4, 2)]);
    }
}
