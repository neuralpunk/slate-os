// SPDX-License-Identifier: MIT OR Apache-2.0

//! ps (and top's reading, `top.rs`): processes as /proc shows them (proc(5): `/proc/PID/stat`,
//! `status`, `cmdline`; `/proc/stat`, `/proc/meminfo`, `/proc/uptime`,
//! `/proc/loadavg`). Times in /proc are in USER_HZ, 100 a second (the
//! auxiliary vector's AT_CLKTCK).

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{fs, io, lossy, println};

use crate::util::{error, parse_num};

pub const HZ: u64 = 100;

#[derive(Clone, Debug, Default)]
pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub sid: u32,
    pub tty: u32,
    /// The terminal's foreground process group.
    pub tpgid: u32,
    pub state: u8,
    pub comm: String,
    pub args: String,
    pub uid: u32,
    pub utime: u64,
    pub stime: u64,
    /// The CPU time of its children that it has waited for (proc(5)'s
    /// cutime and cstime).
    pub cutime: u64,
    pub cstime: u64,
    pub prio: i64,
    pub nice: i64,
    pub threads: u64,
    /// Start, in ticks after boot.
    pub start: u64,
    pub vsize: u64,
    /// Resident pages.
    pub rss: u64,
    pub cpu: u32,
    /// The thread's ID (the process's own for a process).
    pub lwp: u32,
    /// The depth in the process tree (`ps -H`, `ps f`).
    pub depth: usize,
    /// For each ancestor below the root, whether it has later siblings
    /// (`ps f` draws a `|` down past them).
    pub lines: Vec<bool>,
}

/// One process from /proc/PID, or None if it went away.
pub fn read(pid: u32) -> Option<Proc> {
    read_from(&alloc::format!("/proc/{pid}"), pid)
}

/// Process `pid`'s threads, from /proc/PID/task/TID (whose `stat`,
/// `comm` and `status` are the thread's own).
pub fn threads_of(pid: u32) -> Vec<Proc> {
    let mut tids: Vec<u32> = fs::read_dir(alloc::format!("/proc/{pid}/task").as_bytes())
        .unwrap_or_default()
        .iter()
        .filter_map(|e| parse_num(&e.name))
        .collect();
    tids.sort_unstable();
    tids.into_iter().filter_map(|t| read_from(&alloc::format!("/proc/{pid}/task/{t}"), pid)).collect()
}

/// A process or a thread from its directory `base`.
fn read_from(base: &str, pid: u32) -> Option<Proc> {
    let stat = fs::read_file(alloc::format!("{base}/stat").as_bytes()).ok()?;
    let open = stat.iter().position(|&c| c == b'(')?;
    let close = stat.iter().rposition(|&c| c == b')')?;
    let comm = lossy(&stat[open + 1..close]).into_owned();
    let lwp = parse_num(stat[..open].trim_ascii()).unwrap_or(pid);
    let f: Vec<&[u8]> = stat.get(close + 2..)?.split(|&c| c == b' ').collect();
    // Fields from proc(5), counted from 3 (state) as index 0.
    let n = |i: usize| f.get(i).and_then(|x| parse_num::<i64>(x)).unwrap_or(0);
    let cmd = fs::read_file(alloc::format!("{base}/cmdline").as_bytes()).unwrap_or_default();
    let mut args: Vec<u8> = cmd.iter().map(|&c| if c == 0 { b' ' } else { c }).collect();
    while args.last() == Some(&b' ') {
        args.pop();
    }
    let uid = fs::read_file(alloc::format!("{base}/status").as_bytes())
        .ok()
        .and_then(|s| {
            let line = s.split(|&c| c == b'\n').find(|l| l.starts_with(b"Uid:"))?;
            line[4..].split(|c| c.is_ascii_whitespace()).find(|w| !w.is_empty()).and_then(parse_num)
        })
        .unwrap_or_else(|| fs::stat(base.as_bytes()).map_or(0, |s| s.uid));
    Some(Proc {
        pid,
        ppid: n(1) as u32,
        pgid: n(2) as u32,
        sid: n(3) as u32,
        tty: n(4) as u32,
        tpgid: n(5) as u32,
        state: f.first().and_then(|s| s.first().copied()).unwrap_or(b'?'),
        comm,
        args: lossy(&args).into_owned(),
        uid,
        utime: n(11) as u64,
        stime: n(12) as u64,
        cutime: n(13).max(0) as u64,
        cstime: n(14).max(0) as u64,
        prio: n(15),
        nice: n(16),
        threads: n(17) as u64,
        start: n(19) as u64,
        vsize: n(20) as u64,
        rss: n(21).max(0) as u64,
        cpu: n(36) as u32,
        lwp,
        depth: 0,
        lines: Vec::new(),
    })
}

/// What top's memory fields and WCHAN need beyond `stat` (proc(5)):
/// statm's shared, text and data pages, status's VmSwap (KiB), and what
/// the task sleeps in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Extra {
    pub shared: u64,
    pub text: u64,
    pub data: u64,
    pub swap_kb: u64,
    pub wchan: String,
}

/// [`Extra`] for process `pid`, thread `lwp`.
pub fn extra(pid: u32, lwp: u32) -> Extra {
    let read = |name: &str| fs::read_file(alloc::format!("/proc/{pid}/{name}").as_bytes()).unwrap_or_default();
    let statm = read("statm");
    let m: Vec<u64> = lossy(&statm).split_whitespace().map(|v| v.parse().unwrap_or(0)).collect();
    let status = read("status");
    let swap_kb = status
        .split(|&c| c == b'\n')
        .find(|l| l.starts_with(b"VmSwap:"))
        .and_then(|l| l[7..].split(|c| c.is_ascii_whitespace()).find(|w| !w.is_empty()).and_then(parse_num))
        .unwrap_or(0);
    let wchan = fs::read_file(alloc::format!("/proc/{pid}/task/{lwp}/wchan").as_bytes())
        .or_else(|_| fs::read_file(alloc::format!("/proc/{pid}/wchan").as_bytes()))
        .map(|w| lossy(w.trim_ascii()).into_owned())
        .unwrap_or_default();
    let at = |i: usize| m.get(i).copied().unwrap_or(0);
    Extra { shared: at(2), text: at(3), data: at(5), swap_kb, wchan }
}

pub fn all() -> Vec<Proc> {
    let mut pids: Vec<u32> =
        fs::read_dir(b"/proc").unwrap_or_default().iter().filter_map(|e| parse_num(&e.name)).collect();
    pids.sort_unstable();
    pids.into_iter().filter_map(read).collect()
}

/// Seconds since boot, from /proc/uptime.
pub fn uptime() -> f64 {
    fs::read_file(b"/proc/uptime")
        .ok()
        .and_then(|d| lossy(&d).split_whitespace().next().and_then(|s| s.parse().ok()))
        .unwrap_or(0.0)
}

/// Total memory in KiB, from /proc/meminfo.
pub fn mem_total() -> u64 {
    meminfo().iter().find(|e| e.0 == "MemTotal").map_or(0, |e| e.1)
}

pub fn meminfo() -> Vec<(String, u64)> {
    let d = fs::read_file(b"/proc/meminfo").unwrap_or_default();
    d.split(|&c| c == b'\n')
        .filter_map(|l| {
            let colon = l.iter().position(|&c| c == b':')?;
            let v = l[colon + 1..].split(|&c| c == b' ').find(|x| !x.is_empty())?;
            Some((lossy(&l[..colon]).into_owned(), parse_num(v)?))
        })
        .collect()
}

/// The three load averages, from /proc/loadavg.
pub fn loadavg() -> [String; 3] {
    let d = fs::read_file(b"/proc/loadavg").unwrap_or_default();
    let s = lossy(&d).into_owned();
    let mut it = s.split_whitespace().map(String::from);
    [
        it.next().unwrap_or_else(|| "0.00".into()),
        it.next().unwrap_or_else(|| "0.00".into()),
        it.next().unwrap_or_else(|| "0.00".into()),
    ]
}

/// A terminal's name from its device number (devices.txt: 4 = tty, 136+
/// = pts).
pub fn tty_name(dev: u32) -> String {
    if dev == 0 {
        return String::from("?");
    }
    let (major, minor) = ((dev >> 8) & 0xfff, (dev & 0xff) | ((dev >> 12) & 0xfff00));
    match major {
        4 if minor < 64 => alloc::format!("tty{minor}"),
        4 => alloc::format!("ttyS{}", minor - 64),
        5 if minor == 1 => String::from("console"),
        136..=143 => alloc::format!("pts/{}", (major - 136) * 256 + minor),
        _ => alloc::format!("{major},{minor}"),
    }
}

pub fn user(uid: u32) -> String {
    crate::simple::user_name(uid).map_or_else(|| alloc::format!("{uid}"), |n| lossy(&n).into_owned())
}

/// `[[DD-]HH:]MM:SS`, as ps prints elapsed time.
fn etime(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    if d > 0 {
        alloc::format!("{d}-{h:02}:{m:02}:{s:02}")
    } else if h > 0 {
        alloc::format!("{h:02}:{m:02}:{s:02}")
    } else {
        alloc::format!("{m:02}:{s:02}")
    }
}

/// `[DD-]HH:MM:SS` of CPU time.
fn cputime(ticks: u64) -> String {
    let secs = ticks / HZ;
    let (d, h, m, s) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    if d > 0 { alloc::format!("{d}-{h:02}:{m:02}:{s:02}") } else { alloc::format!("{h:02}:{m:02}:{s:02}") }
}

/// BSD STAT: the state plus `<` (high priority), `N` (low), `s`
/// (session leader), `l` (threads), `+` (foreground group).
fn bsd_stat(p: &Proc, fg: Option<u32>) -> String {
    let mut s = String::new();
    s.push(p.state as char);
    if p.nice < 0 {
        s.push('<');
    } else if p.nice > 0 {
        s.push('N');
    }
    if p.sid == p.pid {
        s.push('s');
    }
    if p.threads > 1 {
        s.push('l');
    }
    if p.tty != 0 && fg == Some(p.pgid) {
        s.push('+');
    }
    s
}

/// A ps(1) output column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Col {
    Pid,
    Ppid,
    Pgid,
    Sid,
    Tty,
    Stat,
    State,
    Time,
    Etime,
    Cmd,
    Args,
    Comm,
    User,
    Uid,
    Cpu,
    Mem,
    Vsz,
    Rss,
    Start,
    Ni,
    Pri,
    Nlwp,
    Psr,
    C,
    Stime,
    Lwp,
}

impl Col {
    fn parse(s: &str) -> Option<Col> {
        Some(match s {
            "pid" => Col::Pid,
            "ppid" => Col::Ppid,
            "pgid" | "pgrp" => Col::Pgid,
            "sid" | "sess" => Col::Sid,
            "tty" | "tt" | "tname" => Col::Tty,
            "stat" => Col::Stat,
            "s" | "state" => Col::State,
            "time" | "cputime" => Col::Time,
            "etime" => Col::Etime,
            "cmd" | "args" | "command" => Col::Args,
            "comm" | "ucomm" | "ucmd" => Col::Comm,
            "user" | "uname" | "euser" | "ruser" => Col::User,
            "uid" | "euid" | "ruid" => Col::Uid,
            "%cpu" | "pcpu" => Col::Cpu,
            "%mem" | "pmem" => Col::Mem,
            "vsz" | "vsize" => Col::Vsz,
            "rss" | "rssize" | "rsz" => Col::Rss,
            "start" | "bsdstart" | "start_time" => Col::Start,
            "ni" | "nice" => Col::Ni,
            "pri" | "priority" => Col::Pri,
            "nlwp" | "thcount" => Col::Nlwp,
            "psr" => Col::Psr,
            "c" => Col::C,
            "stime" => Col::Stime,
            "lwp" | "tid" | "spid" => Col::Lwp,
            _ => return None,
        })
    }

    fn header(self) -> &'static str {
        match self {
            Col::Pid => "PID",
            Col::Ppid => "PPID",
            Col::Pgid => "PGID",
            Col::Sid => "SID",
            Col::Tty => "TTY",
            Col::Stat => "STAT",
            Col::State => "S",
            Col::Time => "TIME",
            Col::Etime => "ELAPSED",
            Col::Cmd => "CMD",
            Col::Args => "COMMAND",
            Col::Comm => "COMMAND",
            Col::User => "USER",
            Col::Uid => "UID",
            Col::Cpu => "%CPU",
            Col::Mem => "%MEM",
            Col::Vsz => "VSZ",
            Col::Rss => "RSS",
            Col::Start => "START",
            Col::Ni => "NI",
            Col::Pri => "PRI",
            Col::Nlwp => "NLWP",
            Col::Psr => "PSR",
            Col::C => "C",
            Col::Stime => "STIME",
            Col::Lwp => "LWP",
        }
    }

    /// Right-aligned numeric columns, and their minimum widths.
    fn right(self) -> bool {
        !matches!(
            self,
            Col::Tty | Col::Stat | Col::State | Col::Cmd | Col::Args | Col::Comm | Col::User | Col::Start | Col::Stime
        )
    }

    fn width(self) -> usize {
        match self {
            Col::Pid | Col::Ppid | Col::Pgid | Col::Sid | Col::Lwp => 5,
            Col::Tty => 8,
            Col::Stat => 4,
            Col::Time => 8,
            Col::Etime => 11,
            Col::User => 8,
            Col::Uid => 5,
            Col::Cpu | Col::Mem => 4,
            Col::Vsz => 6,
            Col::Rss => 5,
            Col::Start | Col::Stime => 5,
            Col::Ni | Col::Pri | Col::Psr => 3,
            Col::Nlwp => 4,
            _ => 1,
        }
    }
}

#[derive(Debug)]
pub struct Ctx {
    pub now: f64,
    pub boot_time: i64,
    pub mem_kb: u64,
    pub fg: Option<u32>,
    pub page_kb: u64,
}

impl Default for Ctx {
    fn default() -> Self {
        Self::new()
    }
}

impl Ctx {
    pub fn new() -> Ctx {
        let now = uptime();
        Ctx {
            now,
            boot_time: slate_rt::time::unix() - now as i64,
            mem_kb: mem_total(),
            fg: slate_rt::term::foreground(io::STDIN).ok().map(|g| g as u32),
            page_kb: 4,
        }
    }
}

fn value(c: Col, p: &Proc, ctx: &Ctx, comm_only: bool) -> String {
    let age = (ctx.now - p.start as f64 / HZ as f64).max(0.0);
    match c {
        Col::Pid => alloc::format!("{}", p.pid),
        Col::Ppid => alloc::format!("{}", p.ppid),
        Col::Pgid => alloc::format!("{}", p.pgid),
        Col::Sid => alloc::format!("{}", p.sid),
        Col::Tty => tty_name(p.tty),
        Col::Stat => bsd_stat(p, ctx.fg),
        Col::State => alloc::format!("{}", p.state as char),
        Col::Time => cputime(p.utime + p.stime),
        Col::Etime => etime(age as u64),
        Col::Cmd | Col::Args => {
            if p.args.is_empty() || comm_only {
                if comm_only { p.comm.clone() } else { alloc::format!("[{}]", p.comm) }
            } else {
                p.args.clone()
            }
        }
        Col::Comm => p.comm.clone(),
        Col::User => user(p.uid),
        Col::Uid => alloc::format!("{}", p.uid),
        Col::Cpu | Col::C => {
            // CPU time over the process's life, as ps reports it.
            let cpu = (p.utime + p.stime) as f64 / HZ as f64;
            let pct = if age > 0.0 { cpu * 100.0 / age } else { 0.0 };
            if c == Col::C { alloc::format!("{}", pct as u64) } else { alloc::format!("{:.1}", pct) }
        }
        Col::Mem => {
            let pct = if ctx.mem_kb > 0 { (p.rss * ctx.page_kb) as f64 * 100.0 / ctx.mem_kb as f64 } else { 0.0 };
            alloc::format!("{pct:.1}")
        }
        Col::Vsz => alloc::format!("{}", p.vsize / 1024),
        Col::Rss => alloc::format!("{}", p.rss * ctx.page_kb),
        Col::Start | Col::Stime => {
            let t = ctx.boot_time + (p.start / HZ) as i64;
            let tm = slate_rt::tz::localtime(t);
            let today = slate_rt::tz::localtime(slate_rt::time::unix());
            if (tm.year, tm.yearday) == (today.year, today.yearday) {
                alloc::format!("{:02}:{:02}", tm.hour, tm.min)
            } else if tm.year == today.year {
                alloc::format!("{}{:02}", slate_rt::time::MONTHS[tm.month as usize - 1], tm.day)
            } else {
                alloc::format!("{}", tm.year)
            }
        }
        Col::Ni => alloc::format!("{}", p.nice),
        Col::Pri => alloc::format!("{}", p.prio),
        Col::Nlwp => alloc::format!("{}", p.threads),
        Col::Psr => alloc::format!("{}", p.cpu),
        Col::Lwp => alloc::format!("{}", p.lwp),
    }
}

/// How a process tree is drawn: `ps -H` indents, `ps f` draws branches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Forest {
    Indent,
    Branches,
}

/// `procs` in tree order (each parent before its children, children by
/// PID; a process whose parent isn't listed is a root), with depths.
fn forest(procs: Vec<Proc>) -> Vec<Proc> {
    let pids: Vec<u32> = procs.iter().map(|p| p.pid).collect();
    let mut out = Vec::with_capacity(procs.len());
    // (index, depth, its ancestors' lines, whether siblings follow it)
    let mut stack: Vec<(usize, usize, Vec<bool>, bool)> = Vec::new();
    let mut roots: Vec<usize> =
        (0..procs.len()).filter(|&i| !pids.contains(&procs[i].ppid) || procs[i].ppid == procs[i].pid).collect();
    roots.sort_by_key(|&i| core::cmp::Reverse(procs[i].pid));
    stack.extend(roots.into_iter().map(|i| (i, 0, Vec::new(), false)));
    let mut seen = alloc::vec![false; procs.len()];
    while let Some((i, d, lines, more)) = stack.pop() {
        if core::mem::replace(&mut seen[i], true) {
            continue;
        }
        let mut p = procs[i].clone();
        p.depth = d;
        let pid = p.pid;
        let mut below = lines.clone();
        if d > 0 {
            below.push(more);
        }
        p.lines = lines;
        out.push(p);
        let mut kids: Vec<usize> = (0..procs.len()).filter(|&k| procs[k].ppid == pid && procs[k].pid != pid).collect();
        kids.sort_by_key(|&k| core::cmp::Reverse(procs[k].pid));
        // Reversed: the first kid pushed is the last, with none after it.
        stack.extend(kids.into_iter().enumerate().map(|(n, k)| (k, d + 1, below.clone(), n > 0)));
    }
    out
}

/// A command's text drawn at its place in the tree: `ps f` puts ` |  `
/// under an ancestor with more children to come, as procps' ps does.
fn in_tree(text: String, p: &Proc, how: Forest) -> String {
    match how {
        Forest::Indent => alloc::format!("{}{text}", "  ".repeat(p.depth)),
        Forest::Branches if p.depth > 0 => {
            let bars: String = p.lines.iter().map(|&l| if l { " |  " } else { "    " }).collect();
            alloc::format!("{bars} \\_ {text}")
        }
        Forest::Branches => text,
    }
}

/// A column: what it shows, its header, and a width `-o name:WIDTH` set.
type Column = (Col, String, Option<usize>);

/// Print a table: every column as wide as its widest value (the last one
/// unpadded), or as its set width (values cut to it).
fn table(cols: &[Column], rows: &[Vec<String>], headers: bool) {
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            r.iter().zip(cols).map(|(v, c)| c.2.map_or_else(|| v.clone(), |w| v.chars().take(w).collect())).collect()
        })
        .collect();
    let mut w: Vec<usize> = cols.iter().map(|(c, h, set)| set.unwrap_or_else(|| c.width().max(h.len()))).collect();
    for r in &rows {
        for (i, v) in r.iter().enumerate() {
            if cols[i].2.is_none() {
                w[i] = w[i].max(v.len());
            }
        }
    }
    let line = |vals: &[&str]| {
        let mut s = String::new();
        for (i, v) in vals.iter().enumerate() {
            let last = i + 1 == vals.len();
            if i > 0 {
                s.push(' ');
            }
            if cols[i].0.right() {
                s.extend(core::iter::repeat_n(' ', w[i].saturating_sub(v.len())));
                s.push_str(v);
            } else if last {
                s.push_str(v);
            } else {
                s.push_str(v);
                s.extend(core::iter::repeat_n(' ', w[i].saturating_sub(v.len())));
            }
        }
        println!("{}", s.trim_end());
    };
    if headers {
        let h: Vec<&str> = cols.iter().map(|(_, h, _)| h.as_str()).collect();
        line(&h);
    }
    for r in &rows {
        let v: Vec<&str> = r.iter().map(String::as_str).collect();
        line(&v);
    }
}

pub fn ps(args: &[Vec<u8>]) -> i32 {
    // BSD style when the first argument has no dash (`ps aux`), POSIX
    // style otherwise.
    let (mut all, mut bsd_x) = (false, false);
    let mut cols: Option<Vec<Column>> = None;
    let (mut full, mut long, mut user_fmt, mut headers, mut comm_only) = (false, false, false, true, false);
    let (mut pids, mut users, mut cmds) = (Vec::<u32>::new(), Vec::<u32>::new(), Vec::<String>::new());
    let mut ttys: Vec<String> = Vec::new();
    // -L (with an LWP column) or H: threads; -H or f: the tree.
    let (mut threads, mut lwp_col, mut tree) = (false, false, None::<Forest>);
    let mut sort: Vec<(Col, bool)> = Vec::new();
    let mut i = 1;
    let list =
        |v: &[u8]| -> Vec<String> { lossy(v).split([',', ' ']).filter(|s| !s.is_empty()).map(String::from).collect() };
    let add_cols = |spec: &[u8], cols: &mut Option<Vec<Column>>| -> Result<(), String> {
        for item in list(spec) {
            let (name, hdr) = match item.split_once('=') {
                Some((n, h)) => (n.to_ascii_lowercase(), Some(String::from(h))),
                None => (item.to_ascii_lowercase(), None),
            };
            // `name:WIDTH` sets the column's width.
            let (name, width) = match name.split_once(':') {
                Some((n, w)) => {
                    let w = w.parse::<usize>().map_err(|_| alloc::format!("bad width in \"{item}\""))?;
                    (String::from(n), Some(w))
                }
                None => (name, None),
            };
            let c =
                Col::parse(&name).ok_or_else(|| alloc::format!("unknown user-defined format specifier \"{name}\""))?;
            let h = hdr.unwrap_or_else(|| String::from(if name == "cmd" { "CMD" } else { c.header() }));
            cols.get_or_insert_default().push((c, h, width));
        }
        Ok(())
    };
    while i < args.len() {
        let a = lossy(&args[i]).into_owned();
        let take = |i: &mut usize| -> Option<Vec<u8>> {
            *i += 1;
            args.get(*i).cloned()
        };
        if let Some(long_opt) = a.strip_prefix("--") {
            let (k, v) = match long_opt.split_once('=') {
                Some((k, v)) => (k, Some(v.as_bytes().to_vec())),
                None => (long_opt, None),
            };
            match k {
                "no-headers" | "no-heading" => headers = false,
                "sort" => {
                    let Some(v) = v.or_else(|| take(&mut i)) else { return usage() };
                    for s in list(&v) {
                        let (desc, name) = match s.strip_prefix('-') {
                            Some(n) => (true, n),
                            None => (false, s.trim_start_matches('+')),
                        };
                        let Some(c) = Col::parse(&name.to_ascii_lowercase()) else {
                            error(format_args!("unknown sort specifier \"{name}\""));
                            return 1;
                        };
                        sort.push((c, desc));
                    }
                }
                "pid" => pids.extend(
                    list(&v.or_else(|| take(&mut i)).unwrap_or_default()).iter().filter_map(|s| s.parse::<u32>().ok()),
                ),
                "format" => {
                    if let Err(e) = add_cols(&v.or_else(|| take(&mut i)).unwrap_or_default(), &mut cols) {
                        error(e);
                        return 1;
                    }
                }
                _ => return usage(),
            }
        } else if let Some(opts) = a.strip_prefix('-') {
            let mut chars = opts.chars();
            while let Some(c) = chars.next() {
                let rest: String = chars.clone().collect();
                let value = |i: &mut usize| -> Option<Vec<u8>> {
                    if rest.is_empty() { take(i) } else { Some(rest.as_bytes().to_vec()) }
                };
                match c {
                    'e' | 'A' => all = true,
                    'f' => full = true,
                    'F' => full = true,
                    'l' => long = true,
                    'd' => all = true,
                    'H' => tree = Some(Forest::Indent),
                    'L' => (threads, lwp_col) = (true, true),
                    'w' => {}
                    't' => {
                        let Some(v) = value(&mut i) else { return usage() };
                        ttys.extend(list(&v).into_iter().map(|t| String::from(t.trim_start_matches("/dev/"))));
                        break;
                    }
                    'o' => {
                        let Some(v) = value(&mut i) else { return usage() };
                        if let Err(e) = add_cols(&v, &mut cols) {
                            error(e);
                            return 1;
                        }
                        break;
                    }
                    'p' | 'q' => {
                        let Some(v) = value(&mut i) else { return usage() };
                        pids.extend(list(&v).iter().filter_map(|s| s.parse::<u32>().ok()));
                        break;
                    }
                    'u' | 'U' => {
                        let Some(v) = value(&mut i) else { return usage() };
                        for u in list(&v) {
                            match u.parse().ok().or_else(|| crate::fileops::lookup_id(u.as_bytes(), b"/etc/passwd")) {
                                Some(id) => users.push(id),
                                None => {
                                    error(format_args!("user name does not exist: {u}"));
                                    return 1;
                                }
                            }
                        }
                        break;
                    }
                    'C' => {
                        let Some(v) = value(&mut i) else { return usage() };
                        cmds.extend(list(&v));
                        break;
                    }
                    _ => return usage(),
                }
            }
        } else {
            // BSD options.
            for c in a.chars() {
                match c {
                    'a' => all = true,
                    'x' => bsd_x = true,
                    'u' => user_fmt = true,
                    'c' => comm_only = true,
                    'f' => tree = Some(Forest::Branches),
                    'H' => threads = true,
                    'w' | 'e' | 'h' => {
                        if c == 'h' {
                            headers = false;
                        }
                    }
                    'l' => long = true,
                    _ => return usage(),
                }
            }
        }
        i += 1;
    }
    let bsd = args.get(1).is_some_and(|a| !a.starts_with(b"-"));
    let user_cols = cols.is_some();
    let mut cols: Vec<Column> = cols.unwrap_or_else(|| {
        let names: &[Col] = if bsd && user_fmt {
            &[
                Col::User,
                Col::Pid,
                Col::Cpu,
                Col::Mem,
                Col::Vsz,
                Col::Rss,
                Col::Tty,
                Col::Stat,
                Col::Start,
                Col::Time,
                Col::Args,
            ]
        } else if bsd && long {
            &[
                Col::Uid,
                Col::Pid,
                Col::Ppid,
                Col::Pri,
                Col::Ni,
                Col::Vsz,
                Col::Rss,
                Col::Stat,
                Col::Tty,
                Col::Time,
                Col::Args,
            ]
        } else if bsd {
            &[Col::Pid, Col::Tty, Col::Stat, Col::Time, Col::Args]
        } else if full {
            &[Col::User, Col::Pid, Col::Ppid, Col::C, Col::Stime, Col::Tty, Col::Time, Col::Cmd]
        } else if long {
            &[
                Col::State,
                Col::Uid,
                Col::Pid,
                Col::Ppid,
                Col::C,
                Col::Pri,
                Col::Ni,
                Col::Vsz,
                Col::Rss,
                Col::Tty,
                Col::Time,
                Col::Cmd,
            ]
        } else {
            &[Col::Pid, Col::Tty, Col::Time, Col::Cmd]
        };
        names
            .iter()
            .map(|&c| {
                let h = match (c, full) {
                    (Col::User, true) => "UID",
                    (Col::Cmd, _) if !bsd => "CMD",
                    _ => c.header(),
                };
                (c, String::from(h), None)
            })
            .collect()
    });
    // -L: the threads' IDs after the PIDs (with -f, their counts too).
    if lwp_col && !user_cols {
        let at = cols.iter().position(|c| c.0 == Col::Ppid).or_else(|| cols.iter().position(|c| c.0 == Col::Pid));
        let at = at.map_or(0, |i| i + 1);
        cols.insert(at, (Col::Lwp, String::from("LWP"), None));
        if full && let Some(c) = cols.iter().position(|c| c.0 == Col::C) {
            cols.insert(c + 1, (Col::Nlwp, String::from("NLWP"), None));
        }
    }
    let ctx = Ctx::new();
    let me = slate_rt::process::getuid();
    let my_tty = read(slate_rt::process::getpid() as u32).map_or(0, |p| p.tty);
    let filter = Filter { all, bsd, bsd_x, me, my_tty, pids: &pids, users: &users, cmds: &cmds, ttys: &ttys };
    let mut procs: Vec<Proc> = self::all().into_iter().filter(|p| filter.wants(p)).collect();
    for &(c, desc) in sort.iter().rev() {
        procs.sort_by(|a, b| {
            let o = compare(c, a, b, &ctx);
            if desc { o.reverse() } else { o }
        });
    }
    if tree.is_some() {
        procs = forest(procs);
    }
    if threads {
        procs = procs
            .into_iter()
            .flat_map(|p| {
                let (depth, lines) = (p.depth, p.lines.clone());
                let mut ts = threads_of(p.pid);
                if ts.is_empty() {
                    ts.push(p);
                }
                for t in &mut ts {
                    t.depth = depth;
                    t.lines = lines.clone();
                }
                ts
            })
            .collect();
    }
    let simple_cmd = !full && !bsd && !long;
    let rows: Vec<Vec<String>> = procs
        .iter()
        .map(|p| {
            cols.iter()
                .map(|(c, _, _)| {
                    let v = value(*c, p, &ctx, comm_only || (simple_cmd && *c == Col::Cmd));
                    match tree {
                        Some(how) if matches!(c, Col::Cmd | Col::Args | Col::Comm) => in_tree(v, p, how),
                        _ => v,
                    }
                })
                .collect()
        })
        .collect();
    table(&cols, &rows, headers);
    io::flush_stdout();
    if procs.is_empty() && (!pids.is_empty() || !cmds.is_empty() || !users.is_empty() || !ttys.is_empty()) {
        1
    } else {
        0
    }
}

/// Which processes ps lists.
struct Filter<'a> {
    all: bool,
    bsd: bool,
    bsd_x: bool,
    me: u32,
    my_tty: u32,
    pids: &'a [u32],
    users: &'a [u32],
    cmds: &'a [String],
    /// `-t`: terminals by name (`pts/0`, `ttyS0`).
    ttys: &'a [String],
}

impl Filter<'_> {
    fn wants(&self, p: &Proc) -> bool {
        if !self.pids.is_empty() || !self.users.is_empty() || !self.cmds.is_empty() || !self.ttys.is_empty() {
            return self.pids.contains(&p.pid)
                || self.users.contains(&p.uid)
                || self.cmds.contains(&p.comm)
                || self.ttys.contains(&tty_name(p.tty));
        }
        if self.bsd {
            // `a`: everyone's with a terminal; `x`: those without one too.
            return match (self.all, self.bsd_x) {
                (true, true) => true,
                (true, false) => p.tty != 0,
                (false, true) => p.uid == self.me,
                (false, false) => p.uid == self.me && p.tty != 0,
            };
        }
        // POSIX: everything with -e, else this user's on this terminal.
        self.all || (p.uid == self.me && p.tty == self.my_tty)
    }
}

fn compare(c: Col, a: &Proc, b: &Proc, ctx: &Ctx) -> core::cmp::Ordering {
    let num = |p: &Proc| -> f64 {
        match c {
            Col::Pid => f64::from(p.pid),
            Col::Ppid => f64::from(p.ppid),
            Col::Pgid => f64::from(p.pgid),
            Col::Sid => f64::from(p.sid),
            Col::Uid | Col::User => f64::from(p.uid),
            Col::Cpu | Col::C => {
                let age = (ctx.now - p.start as f64 / HZ as f64).max(0.001);
                (p.utime + p.stime) as f64 / age
            }
            Col::Mem | Col::Rss => p.rss as f64,
            Col::Vsz => p.vsize as f64,
            Col::Time => (p.utime + p.stime) as f64,
            Col::Start | Col::Stime | Col::Etime => p.start as f64,
            Col::Ni => p.nice as f64,
            Col::Pri => p.prio as f64,
            Col::Nlwp => p.threads as f64,
            Col::Psr => f64::from(p.cpu),
            _ => 0.0,
        }
    };
    match c {
        Col::Comm | Col::Cmd | Col::Args => a.comm.cmp(&b.comm),
        Col::Tty => a.tty.cmp(&b.tty),
        Col::Stat | Col::State => a.state.cmp(&b.state),
        _ => num(a).partial_cmp(&num(b)).unwrap_or(core::cmp::Ordering::Equal),
    }
}

fn usage() -> i32 {
    error("unsupported option (try: ps aux, ps -ef, ps -o pid,comm,%cpu,%mem)");
    1
}

/// CPU counters from /proc/stat: (busy, total) for all CPUs together,
/// then for each.
pub(crate) fn cpu_ticks() -> Vec<(u64, u64)> {
    let d = fs::read_file(b"/proc/stat").unwrap_or_default();
    d.split(|&c| c == b'\n')
        .take_while(|l| l.starts_with(b"cpu"))
        .map(|line| {
            let v: Vec<u64> = line.split(|&c| c == b' ').skip(1).filter_map(parse_num).collect();
            let total: u64 = v.iter().sum();
            let idle = v.get(3).copied().unwrap_or(0) + v.get(4).copied().unwrap_or(0);
            (total - idle, total)
        })
        .collect()
}

/// The share of time busy between two counts (busy, total), in percent.
pub(crate) fn busy_pct(now: (u64, u64), before: (u64, u64)) -> f64 {
    if now.1 > before.1 { now.0.saturating_sub(before.0) as f64 * 100.0 / (now.1 - before.1) as f64 } else { 0.0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(etime(59), "00:59");
        assert_eq!(etime(3661), "01:01:01");
        assert_eq!(etime(90_061), "1-01:01:01");
        assert_eq!(cputime(12_345), "00:02:03");
        assert_eq!(tty_name((4 << 8) | 64), "ttyS0");
        assert_eq!(tty_name((5 << 8) | 1), "console");
        assert_eq!(tty_name((136 << 8) | 3), "pts/3");
        assert_eq!(tty_name(0), "?");
        let p = Proc { pid: 7, sid: 7, nice: 5, threads: 2, state: b'S', ..Default::default() };
        assert_eq!(bsd_stat(&p, None), "SNsl");
        assert_eq!(Col::parse("%cpu"), Some(Col::Cpu));
        assert_eq!(Col::parse("lwp"), Some(Col::Lwp));
    }

    #[test]
    fn process_trees() {
        let p = |pid, ppid| Proc { pid, ppid, comm: alloc::format!("p{pid}"), ..Default::default() };
        // 1 has children 5 and 3; 3 has 9; 7's parent isn't listed.
        let tree = forest(alloc::vec![p(9, 3), p(5, 1), p(1, 0), p(3, 1), p(7, 42)]);
        let order: Vec<(u32, usize)> = tree.iter().map(|p| (p.pid, p.depth)).collect();
        assert_eq!(order, [(1, 0), (3, 1), (9, 2), (5, 1), (7, 0)]);
        let drawn: Vec<String> = tree.iter().map(|p| in_tree(p.comm.clone(), p, Forest::Branches)).collect();
        // 3 has a later sibling (5), so a line runs down past its child.
        assert_eq!(drawn, ["p1", " \\_ p3", " |   \\_ p9", " \\_ p5", "p7"]);
        assert_eq!(in_tree("sh".into(), &tree[2], Forest::Indent), "    sh");
        // 2 is the last child: no line under it.
        let tree = forest(alloc::vec![p(1, 0), p(2, 1), p(4, 2), p(6, 4), p(8, 2)]);
        let drawn: Vec<String> = tree.iter().map(|p| in_tree(p.comm.clone(), p, Forest::Branches)).collect();
        assert_eq!(drawn, ["p1", " \\_ p2", "     \\_ p4", "     |   \\_ p6", "     \\_ p8"]);
    }
}
