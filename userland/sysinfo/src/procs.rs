// SPDX-License-Identifier: MIT OR Apache-2.0

//! The processes (ADR 0112), for the System Monitor: /proc/PID/stat and
//! status in proc(5)'s formats, with Slate's `Domain:` line (ADR 0032).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// One process.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Proc {
    pub pid: i32,
    pub ppid: i32,
    /// Its command name (`comm`).
    pub name: String,
    /// R, S, D, Z, T...
    pub state: char,
    /// User and system time, in USER_HZ ticks.
    pub ticks: u64,
    pub threads: u32,
    /// Resident memory, in KiB.
    pub rss: u64,
    pub uid: u32,
    /// In the Linux domain (a Linux program).
    pub linux: bool,
    /// Its command line, arguments joined by spaces.
    pub cmdline: String,
    /// Its nice value (-20 to 19).
    pub nice: i32,
}

/// /proc/PID/stat: the name is in brackets and may hold spaces and
/// brackets itself, so the fields are counted from the last `)`.
pub fn parse_stat(text: &str, p: &mut Proc) -> Option<()> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    p.pid = text[..open].trim().parse().ok()?;
    p.name = String::from(&text[open + 1..close]);
    let f: Vec<&str> = text[close + 1..].split_whitespace().collect();
    // After the name: state(3) ppid(4) ... utime(14) stime(15) ...
    // num_threads(20) ... rss(24), numbered as proc(5) does.
    let n = |field: usize| f.get(field - 3).and_then(|v| v.parse::<u64>().ok());
    p.state = f.first()?.chars().next()?;
    p.ppid = n(4)? as i32;
    p.ticks = n(14)? + n(15)?;
    p.threads = n(20)? as u32;
    p.rss = n(24)? * 4;
    p.nice = f.get(19 - 3).and_then(|v| v.parse().ok()).unwrap_or(0);
    Some(())
}

/// A thread of a process: its ID, name, state and CPU time (ticks).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Thread {
    pub tid: i32,
    pub name: String,
    pub state: char,
    pub ticks: u64,
}

/// The threads of process `pid` (/proc/PID/task).
pub fn threads(pid: i32) -> Vec<Thread> {
    let dir = alloc::format!("/proc/{pid}/task");
    let mut out: Vec<Thread> = slate_rt::fs::read_dir(dir.as_bytes())
        .unwrap_or_default()
        .iter()
        .filter_map(|e| {
            let tid = core::str::from_utf8(&e.name).ok()?;
            let mut p = Proc::default();
            parse_stat(&crate::load::read(&alloc::format!("{dir}/{tid}/stat")), &mut p)?;
            Some(Thread { tid: p.pid, name: p.name, state: p.state, ticks: p.ticks })
        })
        .collect();
    out.sort_by_key(|t| t.tid);
    out
}

/// What process `pid` has open (/proc/PID/fd's links): its descriptor
/// and what it names, the first `max`; None when it can't be read (another
/// account's).
pub fn open_files(pid: i32, max: usize) -> Option<Vec<(u32, String)>> {
    let dir = alloc::format!("/proc/{pid}/fd");
    let es = slate_rt::fs::read_dir(dir.as_bytes()).ok()?;
    let mut out: Vec<(u32, String)> = es
        .iter()
        .filter_map(|e| {
            let fd: u32 = core::str::from_utf8(&e.name).ok()?.parse().ok()?;
            let to = slate_rt::fs::readlink(alloc::format!("{dir}/{fd}").as_bytes()).ok()?;
            Some((fd, String::from(slate_rt::lossy(&to))))
        })
        .collect();
    out.sort_by_key(|f| f.0);
    out.truncate(max);
    Some(out)
}

/// /proc/PID/io's counts: bytes read and written through calls, then
/// from and to storage.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Io {
    pub rchar: u64,
    pub wchar: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

pub fn parse_io(text: &str) -> Io {
    let mut io = Io::default();
    for l in text.lines() {
        let Some((k, v)) = l.split_once(':') else { continue };
        let v = v.trim().parse().unwrap_or(0);
        match k {
            "rchar" => io.rchar = v,
            "wchar" => io.wchar = v,
            "read_bytes" => io.read_bytes = v,
            "write_bytes" => io.write_bytes = v,
            _ => {}
        }
    }
    io
}

/// Process `pid`'s I/O, if it can be read.
pub fn io(pid: i32) -> Option<Io> {
    let t = slate_rt::fs::read_file(alloc::format!("/proc/{pid}/io").as_bytes()).ok()?;
    Some(parse_io(&slate_rt::lossy(&t)))
}

/// /proc/PID/status: the real UID and the domain.
pub fn parse_status(text: &str, p: &mut Proc) {
    for l in text.lines() {
        if let Some(v) = l.strip_prefix("Uid:") {
            p.uid = v.split_whitespace().next().and_then(|u| u.parse().ok()).unwrap_or(0);
        } else if let Some(v) = l.strip_prefix("Domain:") {
            p.linux = v.trim().eq_ignore_ascii_case("linux");
        }
    }
}

/// Every process /proc shows now.
pub fn read_all() -> Vec<Proc> {
    let Ok(entries) = slate_rt::fs::read_dir(b"/proc") else { return Vec::new() };
    let mut out = Vec::new();
    for e in entries {
        let Ok(name) = core::str::from_utf8(&e.name) else { continue };
        if name.is_empty() || !name.bytes().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let read = |f: &str| crate::load::read(&alloc::format!("/proc/{name}/{f}"));
        let mut p = Proc::default();
        if parse_stat(&read("stat"), &mut p).is_none() {
            continue;
        }
        parse_status(&read("status"), &mut p);
        let cmd = slate_rt::fs::read_file(alloc::format!("/proc/{name}/cmdline").as_bytes()).unwrap_or_default();
        p.cmdline = cmd
            .split(|&c| c == 0)
            .filter(|a| !a.is_empty())
            .map(|a| String::from(slate_rt::lossy(a)))
            .collect::<Vec<_>>()
            .join(" ");
        out.push(p);
    }
    out
}

/// The account names by UID, from /etc/passwd's text.
pub fn user_names(passwd: &str) -> BTreeMap<u32, String> {
    passwd
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            Some((f.get(2)?.parse().ok()?, String::from(*f.first()?)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_and_status() {
        let mut p = Proc::default();
        let stat =
            "312 (my (odd) prog) S 1 312 312 0 -1 0 0 0 0 0 150 50 0 0 20 0 3 0 1234 100000 256 18446744073709551615";
        parse_stat(stat, &mut p).unwrap();
        assert_eq!((p.pid, p.name.as_str(), p.state, p.ppid), (312, "my (odd) prog", 'S', 1));
        assert_eq!((p.ticks, p.threads, p.rss, p.nice), (200, 3, 1024, 0));
        let mut q = Proc::default();
        parse_stat("9 (n) S 1 9 9 0 -1 0 0 0 0 0 1 1 0 0 30 10 1 0 1 1 1 1", &mut q).unwrap();
        assert_eq!(q.nice, 10);
        let io = parse_io("rchar: 100\nwchar: 20\nsyscr: 3\nsyscw: 1\nread_bytes: 4096\nwrite_bytes: 0\n");
        assert_eq!((io.rchar, io.wchar, io.read_bytes, io.write_bytes), (100, 20, 4096, 0));
        parse_status("Name:\tx\nUid:\t1000\t1000\t1000\t1000\nDomain:\tlinux\n", &mut p);
        assert_eq!((p.uid, p.linux), (1000, true));
        assert!(parse_stat("garbage", &mut Proc::default()).is_none());
        let names = user_names("root:x:0:0::/root:/bin/sh\nada:x:1000:1000:Ada:/home/ada:/bin/sh\n");
        assert_eq!(names.get(&1000).map(String::as_str), Some("ada"));
    }
}
