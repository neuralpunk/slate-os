// SPDX-License-Identifier: MIT OR Apache-2.0

//! who, users, w, last and lastlog: the login records slate-rt keeps
//! (ADR 0057; utmp(5), lastlog(8)).

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::utmp::{self, Entry};
use slate_rt::{fs, io, lossy, println, time};

use crate::util::{Opt, Parser, bad_option, error, parse_num};

fn stamp(secs: i64, fmt: &str) -> String {
    crate::datetime::format(&slate_rt::tz::localtime(secs), 0, fmt)
}

/// How long the terminal `line` has been idle: `.` under a minute,
/// `HH:MM`, `old` over a day, `?` if it has no device.
fn idle(line: &[u8]) -> String {
    let Ok(st) = fs::stat(&[b"/dev/".as_slice(), line].concat()) else { return String::from("?") };
    let secs = (time::unix() - st.atime).max(0);
    if secs < 60 {
        String::from(".")
    } else if secs < 86_400 {
        alloc::format!("{:02}:{:02}", secs / 3600, secs / 60 % 60)
    } else {
        String::from("old")
    }
}

fn line_of(e: &Entry, show_idle: bool) -> String {
    let mut s = alloc::format!("{:<8} {:<12} {}", lossy(&e.user), lossy(&e.line), stamp(e.secs, "%Y-%m-%d %H:%M"));
    if show_idle {
        s.push_str(&alloc::format!(" {:>5} {:>10}", idle(&e.line), e.pid));
    }
    if !e.host.is_empty() {
        s.push_str(&alloc::format!(" ({})", lossy(&e.host)));
    }
    s
}

pub fn who(args: &[Vec<u8>]) -> i32 {
    let (mut heading, mut boot, mut count, mut runlevel, mut show_idle, mut me, mut all) =
        (false, false, false, false, false, false, false);
    let mut operands = Vec::new();
    let mut p = Parser::new(args, b"");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'H') => heading = true,
            Opt::Short(b'b') => boot = true,
            Opt::Short(b'q') => count = true,
            Opt::Short(b'r') => runlevel = true,
            Opt::Short(b'u') => show_idle = true,
            Opt::Short(b'm') => me = true,
            Opt::Short(b'a') => all = true,
            Opt::Short(b's' | b'T' | b'w') => {}
            Opt::Long(l) if l == "heading" => heading = true,
            Opt::Long(l) if l == "boot" => boot = true,
            Opt::Long(l) if l == "count" => count = true,
            Opt::Long(l) if l == "runlevel" => runlevel = true,
            Opt::Long(l) if l == "users" => show_idle = true,
            Opt::Long(l) if l == "all" => all = true,
            Opt::Operand(x) => operands.push(x),
            o => return bad_option(&o),
        }
    }
    // `who am i` and `who mom likes`: like -m.
    if operands.len() == 2 {
        me = true;
    }
    let file = match operands.as_slice() {
        [f] => f.clone(),
        _ => utmp::UTMP.to_vec(),
    };
    let records = utmp::read(&file);
    let users: Vec<&Entry> = records
        .iter()
        .filter(|r| {
            r.kind == utmp::USER_PROCESS && (r.pid <= 0 || fs::exists(alloc::format!("/proc/{}", r.pid).as_bytes()))
        })
        .collect();
    if count {
        let names: Vec<String> = users.iter().map(|u| String::from(lossy(&u.user))).collect();
        println!("{}", names.join(" "));
        println!("# users={}", names.len());
        return 0;
    }
    if heading {
        println!(
            "{}",
            if show_idle || all {
                "NAME     LINE         TIME             IDLE          PID COMMENT"
            } else {
                "NAME     LINE         TIME             COMMENT"
            }
        );
    }
    let only_default = !(boot || runlevel || all);
    if boot || all {
        for r in records.iter().filter(|r| r.kind == utmp::BOOT_TIME) {
            println!("         {:<12} {}", "system boot", stamp(r.secs, "%Y-%m-%d %H:%M"));
        }
    }
    if runlevel || all {
        for r in records.iter().filter(|r| r.kind == utmp::RUN_LVL) {
            let (level, prev) = ((r.pid % 256) as u8, (r.pid / 256) as u8);
            let mut s = alloc::format!("         run-level {}  {}", level as char, stamp(r.secs, "%Y-%m-%d %H:%M"));
            if prev.is_ascii_alphanumeric() {
                s.push_str(&alloc::format!(" last={}", prev as char));
            }
            println!("{s}");
        }
    }
    if only_default || all {
        let mine = me.then(utmp::tty_line).flatten();
        for u in users {
            if me && mine.as_ref() != Some(&u.line) {
                continue;
            }
            println!("{}", line_of(u, show_idle || all));
        }
    }
    io::flush_stdout();
    0
}

pub fn users(_: &[Vec<u8>]) -> i32 {
    let mut names: Vec<String> = utmp::current().iter().map(|u| String::from(lossy(&u.user))).collect();
    names.sort();
    println!("{}", names.join(" "));
    0
}

/// CPU seconds of the processes on `line`, and the foreground one's
/// command line (what `w` shows as WHAT).
fn tty_activity(line: &[u8]) -> (f64, f64, String) {
    let dev = fs::stat(&[b"/dev/".as_slice(), line].concat()).map_or(0, |s| s.rdev);
    activity(&crate::procs::all(), dev)
}

/// w(1)'s JCPU, PCPU and WHAT for terminal `dev`: JCPU the time of the
/// terminal's processes, with that of the children they have waited for
/// (so finished commands count too); PCPU the foreground process's own;
/// WHAT its command line. Seconds.
fn activity(procs: &[crate::procs::Proc], dev: u64) -> (f64, f64, String) {
    let mut total = 0u64;
    let (mut fg_time, mut what) = (0u64, String::from("-"));
    for p in procs {
        if dev == 0 || u64::from(p.tty) != dev {
            continue;
        }
        let t = p.utime + p.stime;
        total += t + p.cutime + p.cstime;
        let foreground = p.pgid == p.tpgid;
        if foreground {
            fg_time = t;
            what = if p.args.is_empty() { p.comm.clone() } else { p.args.clone() };
        }
    }
    (total as f64 / 100.0, fg_time as f64 / 100.0, what)
}

pub fn w(args: &[Vec<u8>]) -> i32 {
    let (mut header, mut short) = (true, false);
    let mut only: Option<Vec<u8>> = None;
    let mut p = Parser::new(args, b"");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'h') => header = false,
            Opt::Short(b's') => short = true,
            Opt::Short(b'u' | b'f' | b'i') => {}
            Opt::Long(l) if l == "no-header" => header = false,
            Opt::Long(l) if l == "short" => short = true,
            Opt::Operand(x) => only = Some(x),
            o => return bad_option(&o),
        }
    }
    let users: Vec<Entry> =
        utmp::current().into_iter().filter(|u| only.as_ref().is_none_or(|n| *n == u.user)).collect();
    if header {
        let up = crate::procs::uptime() as u64;
        let span = if up >= 86_400 {
            alloc::format!(
                "{} day{}, {:2}:{:02}",
                up / 86_400,
                if up / 86_400 == 1 { "" } else { "s" },
                up / 3600 % 24,
                up / 60 % 60
            )
        } else if up >= 3600 {
            alloc::format!("{:2}:{:02}", up / 3600, up / 60 % 60)
        } else {
            alloc::format!("{} min", up / 60)
        };
        let la = crate::procs::loadavg();
        let n = utmp::current().len();
        println!(
            " {} up {span},  {n} user{},  load average: {}, {}, {}",
            stamp(time::unix(), "%H:%M:%S"),
            if n == 1 { "" } else { "s" },
            la[0],
            la[1],
            la[2]
        );
        if short {
            println!("USER     TTY       FROM             IDLE WHAT");
        } else {
            println!("USER     TTY       FROM             LOGIN@   IDLE   JCPU   PCPU WHAT");
        }
    }
    let today = slate_rt::tz::localtime(time::unix());
    for u in &users {
        let (jcpu, pcpu, what) = tty_activity(&u.line);
        let host = if u.host.is_empty() { String::from("-") } else { String::from(lossy(&u.host)) };
        let name: String = lossy(&u.user).chars().take(8).collect();
        let tty: String = lossy(&u.line).chars().take(8).collect();
        let host: String = host.chars().take(16).collect();
        if short {
            println!("{name:<8} {tty:<9} {host:<16} {:>4} {what}", idle(&u.line));
            continue;
        }
        let lt = slate_rt::tz::localtime(u.secs);
        let login_at = if (lt.year, lt.yearday) == (today.year, today.yearday) {
            stamp(u.secs, "%H:%M")
        } else {
            stamp(u.secs, "%a%H")
        };
        println!("{name:<8} {tty:<9} {host:<16} {login_at:<8} {:>5} {jcpu:5.2}s {pcpu:5.2}s {what}", idle(&u.line));
    }
    io::flush_stdout();
    0
}

/// `(dd:hh:mm)` or `(hh:mm)` of a session's length.
fn span(secs: i64) -> String {
    let m = secs.max(0) / 60;
    if m >= 1440 {
        alloc::format!("({}+{:02}:{:02})", m / 1440, m / 60 % 24, m % 60)
    } else {
        alloc::format!("({:02}:{:02})", m / 60, m % 60)
    }
}

fn trunc(s: &[u8], w: usize) -> String {
    let t = lossy(s);
    if t.chars().count() > w {
        let mut v: String = t.chars().take(w - 1).collect();
        v.push('*');
        v
    } else {
        String::from(t)
    }
}

pub fn last(args: &[Vec<u8>]) -> i32 {
    let (mut max, mut extra) = (usize::MAX, false);
    let mut file = utmp::WTMP.to_vec();
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut p = Parser::new(args, b"nf");
    p.numeric = true;
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'n') => max = p.value().and_then(|v| parse_num(&v)).unwrap_or(usize::MAX),
            Opt::Short(b'f') => file = p.value().unwrap_or_default(),
            Opt::Short(b'x') => extra = true,
            Opt::Short(b'w' | b'F' | b'a' | b'R') => {}
            Opt::Long(l) if l.bytes().all(|b| b.is_ascii_digit()) => max = l.parse().unwrap_or(usize::MAX),
            Opt::Long(l) if l == "system" => extra = true,
            Opt::Operand(x) => names.push(x),
            o => return bad_option(&o),
        }
    }
    let records = utmp::read(&file);
    let release =
        fs::read_file(b"/proc/sys/kernel/osrelease").map(|r| String::from(lossy(&r).trim())).unwrap_or_default();
    // Newest first; each login ends at the next logout on its line (seen
    // earlier, walking backwards), or at the next boot.
    let mut out = Vec::new();
    let mut logouts: Vec<(Vec<u8>, i64)> = Vec::new();
    let mut boot_after: Option<i64> = None;
    let mut down_after: Option<i64> = None;
    let mut shown = 0;
    for r in records.iter().rev() {
        if shown >= max {
            break;
        }
        let wanted = |n: &[u8]| names.is_empty() || names.iter().any(|x| x == n || x == &r.line);
        match r.kind {
            utmp::USER_PROCESS => {
                let end = logouts.iter().position(|(l, _)| *l == r.line).map(|i| logouts.remove(i).1);
                let alive = fs::exists(alloc::format!("/proc/{}", r.pid).as_bytes()) && boot_after.is_none();
                let tail = match end {
                    Some(t) => alloc::format!(" - {}  {}", stamp(t, "%H:%M"), span(t - r.secs)),
                    None if alive => String::from("   still logged in"),
                    None => match down_after.or(boot_after) {
                        Some(t) if down_after.is_some() => alloc::format!(" - down   {}", span(t - r.secs)),
                        Some(t) => alloc::format!(" - crash  {}", span(t - r.secs)),
                        None => String::from("   gone - no logout"),
                    },
                };
                if wanted(&r.user) {
                    let host = if r.host.is_empty() { b"local".as_slice() } else { &r.host };
                    out.push(alloc::format!(
                        "{:<8} {:<12} {:<16} {}{tail}",
                        trunc(&r.user, 8),
                        trunc(&r.line, 12),
                        trunc(host, 16),
                        stamp(r.secs, "%a %b %e %H:%M")
                    ));
                    shown += 1;
                }
            }
            utmp::DEAD_PROCESS => logouts.push((r.line.clone(), r.secs)),
            utmp::BOOT_TIME => {
                if wanted(b"reboot") {
                    let tail = match boot_after {
                        Some(t) => alloc::format!(" - {}  {}", stamp(t, "%H:%M"), span(t - r.secs)),
                        None => String::from("   still running"),
                    };
                    out.push(alloc::format!(
                        "{:<8} {:<12} {:<16} {}{tail}",
                        "reboot",
                        "system boot",
                        trunc(release.as_bytes(), 16),
                        stamp(r.secs, "%a %b %e %H:%M")
                    ));
                    shown += 1;
                }
                // Logins before this boot ended with it.
                logouts.clear();
                boot_after = Some(r.secs);
                down_after = None;
            }
            utmp::RUN_LVL if r.user == b"shutdown" => {
                if extra && wanted(b"shutdown") {
                    out.push(alloc::format!(
                        "{:<8} {:<12} {:<16} {}",
                        "shutdown",
                        "system down",
                        trunc(release.as_bytes(), 16),
                        stamp(r.secs, "%a %b %e %H:%M")
                    ));
                    shown += 1;
                }
                down_after = Some(r.secs);
            }
            _ => {}
        }
    }
    for l in out {
        println!("{l}");
    }
    let begins = records.first().map_or_else(|| fs::stat(&file).map_or(0, |s| s.mtime), |r| r.secs);
    println!();
    println!("{} begins {}", lossy(fs::basename(&file)), stamp(begins, "%a %b %e %H:%M:%S %Y"));
    io::flush_stdout();
    0
}

pub fn lastlog(args: &[Vec<u8>]) -> i32 {
    let mut only: Option<Vec<u8>> = None;
    let mut p = Parser::new(args, b"u");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'u') => only = p.value(),
            Opt::Long(l) if l == "user" => only = p.value(),
            o => return bad_option(&o),
        }
    }
    let users = crate::simple::db_names(b"/etc/passwd");
    if let Some(n) = &only
        && !users.iter().any(|(u, id, _)| u == n || lossy(n).parse::<u32>().ok() == Some(*id))
    {
        error(format_args!("Unknown user or range: {}", lossy(n)));
        return 1;
    }
    println!("Username         Port     From                                       Latest");
    for (name, uid, _) in &users {
        if only.as_ref().is_some_and(|n| n != name && lossy(n).parse::<u32>().ok() != Some(*uid)) {
            continue;
        }
        match utmp::lastlog(*uid) {
            Some((t, line, host)) => println!(
                "{:<16} {:<8} {:<42} {}",
                lossy(name),
                lossy(&line),
                lossy(&host),
                stamp(t, "%a %b %e %H:%M:%S %z %Y")
            ),
            None => {
                println!("{:<16}                                                    **Never logged in**", lossy(name))
            }
        }
    }
    io::flush_stdout();
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_activity() {
        use crate::procs::Proc;
        // The shell (waited for 1.5 s of finished commands) and a
        // foreground job on tty 0x8801; another terminal's process.
        let shell = Proc {
            pid: 10,
            pgid: 10,
            tpgid: 20,
            tty: 0x8801,
            utime: 20,
            stime: 10,
            cutime: 100,
            cstime: 50,
            ..Default::default()
        };
        let job = Proc {
            pid: 20,
            pgid: 20,
            tpgid: 20,
            tty: 0x8801,
            utime: 300,
            stime: 25,
            args: "make -j8".into(),
            ..Default::default()
        };
        let other = Proc { pid: 30, pgid: 30, tpgid: 30, tty: 0x8802, utime: 999, ..Default::default() };
        let (j, p, what) = activity(&[shell, job, other], 0x8801);
        assert_eq!((j, p, what.as_str()), (5.05, 3.25, "make -j8"));
    }

    #[test]
    fn spans_and_truncation() {
        assert_eq!(span(59), "(00:00)");
        assert_eq!(span(3720), "(01:02)");
        assert_eq!(span(90_000), "(1+01:00)");
        assert_eq!(trunc(b"maintainer", 8), "maintai*");
        assert_eq!(trunc(b"root", 8), "root");
    }
}

/// wall [message]: write a message (or standard input) to every logged-in
/// terminal, under a "Broadcast message" header (wall(1)). Terminals that
/// cannot be written are skipped.
pub fn wall(args: &[Vec<u8>]) -> i32 {
    let mut text: Vec<u8> =
        if args.len() > 1 { args[1..].join(&b' ') } else { io::read_to_end(io::STDIN).unwrap_or_default() };
    while text.last() == Some(&b'\n') {
        text.pop();
    }
    let me = crate::simple::user_name(slate_rt::process::getuid()).unwrap_or_else(|| b"root".to_vec());
    let host = slate_rt::process::uname()[1].clone();
    let tty = utmp::tty_line().unwrap_or_else(|| b"somewhere".to_vec());
    let mut msg = alloc::format!(
        "\r\nBroadcast message from {}@{} ({}) ({}):\r\n\r\n",
        lossy(&me),
        lossy(&host),
        lossy(&tty),
        stamp(time::unix(), "%a %b %e %H:%M:%S %Y")
    )
    .into_bytes();
    for l in text.split(|&c| c == b'\n') {
        msg.extend_from_slice(l);
        msg.extend_from_slice(b"\r\n");
    }
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for e in utmp::current() {
        if seen.contains(&e.line) || e.line.is_empty() || e.line.contains(&b'.') {
            continue;
        }
        seen.push(e.line.clone());
        let path = [b"/dev/".as_slice(), &e.line].concat();
        if let Ok(fd) = fs::open(&path, fs::O_WRONLY | fs::O_NOCTTY | fs::O_NONBLOCK | fs::O_CLOEXEC, 0) {
            let _ = io::write_all(fd, &msg);
            let _ = io::close(fd);
        }
    }
    0
}
