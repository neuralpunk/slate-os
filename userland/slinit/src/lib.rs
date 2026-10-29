// SPDX-License-Identifier: MIT OR Apache-2.0

//! slinit, Slate's init (ADR 0020): SysV semantics (inittab, runlevels
//! 0–6 and S, sysinit/wait/once/respawn entries), init.d scripts started
//! and stopped in the order their LSB headers imply, supervision with
//! restart backoff (respawn entries, `X-Slate-Exec` services), a control
//! socket for telinit, shutdown, reboot, poweroff, halt and service, and a
//! clean shutdown. Services' output goes to their own logs in
//! /var/log/services, their processes carry the service's tag in the
//! kernel, and shutdowns can be scheduled and cancelled (ADR 0060).

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod config;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::logfile::{self, LogFile};
use slate_rt::{fs, io, lossy, net, process, signal, time};

use config::{Action, Entry, Service};

/// The control socket's abstract name.
const SOCKET: &[u8] = b"slinit";
const INITTAB: &[u8] = b"/etc/inittab";
const INIT_D: &[u8] = b"/etc/init.d";
const PATH: &[u8] = b"PATH=/sbin:/bin:/usr/sbin:/usr/bin";
const SERVICE_LOGS: &[u8] = b"/var/log/services";
/// A service log is renamed to NAME.log.1 past this size.
const LOG_LIMIT: u64 = 512 * 1024;
const NOLOGIN: &[u8] = b"/run/nologin";
/// Minutes before a scheduled shutdown when users are told again.
const MARKS: [i64; 3] = [600, 300, 60];

fn say(msg: impl core::fmt::Display) {
    io::flush_stdout();
    io::err(alloc::format!("slinit: {msg}\n").as_bytes());
}

fn now_secs() -> i64 {
    time::now(time::CLOCK_MONOTONIC).0
}

fn now_ms() -> i64 {
    let (s, ns) = time::now(time::CLOCK_MONOTONIC);
    s * 1000 + ns / 1_000_000
}

fn cmd_name(cmd: u32) -> &'static str {
    match cmd {
        process::RB_AUTOBOOT => "reboot",
        process::RB_HALT_SYSTEM => "halt",
        _ => "power-off",
    }
}

/// What users are told about a scheduled shutdown.
fn shutdown_text(cmd: u32, at: i64, message: &[u8]) -> Vec<u8> {
    let left = (at - now_secs()).max(0);
    let when = slate_rt::tz::stamp(time::unix() + left);
    let mut t = alloc::format!("The system will go down for {} at {when}", cmd_name(cmd)).into_bytes();
    if left >= 60 {
        t.extend_from_slice(alloc::format!(" (in {} minutes)", (left + 30) / 60).as_bytes());
    }
    t.push(b'!');
    if !message.is_empty() {
        t.push(b' ');
        t.extend_from_slice(message);
    }
    t.push(b'\n');
    t
}

/// What a child process is.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Owner {
    Entry(usize),
    Service(Vec<u8>),
    Other,
}

/// A supervised process: respawn bookkeeping.
#[derive(Clone, Debug, Default)]
struct Supervised {
    pid: i32,
    started: i64,
    /// Quick deaths in a row (the backoff exponent).
    failures: u32,
    /// When to start it again (monotonic seconds), if it is waiting.
    due: Option<i64>,
}

/// The read end of a pipe carrying a service's output.
struct OutPipe {
    fd: i32,
    service: Vec<u8>,
    /// A line not finished yet.
    partial: Vec<u8>,
    /// Also copied to `service`'s caller while its script runs.
    forward: Option<i32>,
}

/// A shutdown that will happen (`shutdown +M`, ADR 0060).
struct Scheduled {
    /// Monotonic seconds.
    at: i64,
    cmd: u32,
    message: Vec<u8>,
    /// Seconds-before marks not announced yet.
    marks: Vec<i64>,
    nologin: bool,
}

struct Init {
    entries: Vec<Entry>,
    level: u8,
    previous: u8,
    children: BTreeMap<i32, Owner>,
    /// Respawn entries by index.
    respawn: BTreeMap<usize, Supervised>,
    /// Services started in this runlevel (by name), and supervised ones.
    started: BTreeSet<Vec<u8>>,
    daemons: BTreeMap<Vec<u8>, Supervised>,
    listener: i32,
    stopping: bool,
    pipes: Vec<OutPipe>,
    logs: BTreeMap<Vec<u8>, LogFile>,
    /// The logs' file system is going away (runlevels 0 and 6).
    logs_closed: bool,
    scheduled: Option<Scheduled>,
    /// Seconds between TERM and KILL at shutdown (`shutdown -t`).
    grace: i64,
}

/// Split a command line for exec, or run it with /bin/sh when it uses
/// shell syntax.
fn argv_of(cmd: &[u8]) -> Vec<Vec<u8>> {
    if cmd.iter().any(|c| b"|&;<>()$`\\\"'*?[]#~=%{}".contains(c)) {
        return alloc::vec![b"/bin/sh".to_vec(), b"-c".to_vec(), cmd.to_vec()];
    }
    cmd.split(|c| c.is_ascii_whitespace()).filter(|w| !w.is_empty()).map(<[u8]>::to_vec).collect()
}

/// Start `argv` in a new session with default signal handling; output to
/// `out` if given.
fn spawn(argv: &[Vec<u8>], out: Option<i32>, extra_env: &[Vec<u8>]) -> Option<i32> {
    spawn_with(argv, out, extra_env, None)
}

/// `spawn`, and with `hold` the child first waits for a byte on that
/// descriptor (so init can tag it before it runs) and reads /dev/null.
fn spawn_with(argv: &[Vec<u8>], out: Option<i32>, extra_env: &[Vec<u8>], hold: Option<i32>) -> Option<i32> {
    if argv.is_empty() {
        return None;
    }
    let path = if argv[0].contains(&b'/') { argv[0].clone() } else { fs::join(b"/bin", &argv[0]) };
    io::flush_stdout();
    match process::fork() {
        Ok(0) => {
            let _ = process::setsid();
            for s in 1..32 {
                let _ = signal::set(s, signal::Disposition::Default);
            }
            let _ = signal::set_mask(0);
            if let Some(h) = hold {
                let mut b = [0u8; 1];
                let _ = io::read(h, &mut b);
                if let Ok(null) = fs::open(b"/dev/null", fs::O_RDWR, 0) {
                    let _ = process::dup2(null, 0);
                }
            }
            if let Some(fd) = out {
                let _ = process::dup2(fd, 1);
                let _ = process::dup2(fd, 2);
            }
            let mut env = alloc::vec![PATH.to_vec(), b"TERM=linux".to_vec()];
            env.extend_from_slice(extra_env);
            let e = process::execve(&path, argv, &env);
            say(alloc::format!("{}: {e}", lossy(&path)));
            process::exit_now(127);
        }
        Ok(pid) => Some(pid),
        Err(e) => {
            say(alloc::format!("fork: {e}"));
            None
        }
    }
}

fn services() -> Vec<Service> {
    let mut v = Vec::new();
    for e in fs::read_dir(INIT_D).unwrap_or_default() {
        if e.name.starts_with(b".") {
            continue;
        }
        let path = fs::join(INIT_D, &e.name);
        if !fs::stat(&path).is_ok_and(|s| s.is_file() && s.mode & 0o111 != 0) {
            continue;
        }
        if let Some(s) = fs::read_file(&path).ok().and_then(|t| config::parse_lsb(&e.name, &t)) {
            v.push(s);
        }
    }
    v
}

/// Respawn delay after `failures` quick deaths: 1, 2, 4 ... 60 seconds.
fn backoff(failures: u32) -> i64 {
    if failures == 0 { 0 } else { (1i64 << failures.min(6)).min(60) }
}

impl Init {
    fn load(&mut self) {
        let (entries, errors) = match fs::read_file(INITTAB) {
            Ok(t) => config::parse_inittab(&t),
            Err(e) => {
                say(alloc::format!("/etc/inittab: {e}; starting a shell on the console"));
                (
                    alloc::vec![Entry {
                        id: b"sh".to_vec(),
                        levels: Vec::new(),
                        action: Action::Respawn,
                        process: b"/bin/sh -l".to_vec(),
                    }],
                    Vec::new(),
                )
            }
        };
        for e in errors {
            say(e);
        }
        self.entries = entries;
    }

    /// Note a child's end (respawn bookkeeping). Only failures (a non-zero
    /// status or a signal) soon after starting count towards the backoff.
    fn child_exited(&mut self, pid: i32, status: i32) {
        let Some(owner) = self.children.remove(&pid) else { return };
        // A getty's login session ended (ADR 0057).
        if matches!(owner, Owner::Entry(_)) {
            slate_rt::utmp::logout(pid);
        }
        let t = now_secs();
        let sup = match &owner {
            Owner::Entry(i) => self.respawn.get_mut(i),
            Owner::Service(name) => self.daemons.get_mut(name),
            Owner::Other => None,
        };
        if let Some(s) = sup
            && s.pid == pid
        {
            s.pid = 0;
            if self.stopping {
                return;
            }
            // A daemon's main process ended: what it left behind goes.
            if let Owner::Service(name) = &owner {
                let _ = process::kill_service(name, signal::SIGTERM);
            }
            s.failures = if t - s.started < 10 && status != 0 { s.failures + 1 } else { 0 };
            s.due = Some(t + backoff(s.failures));
            if s.failures >= 3 {
                let name = match &owner {
                    Owner::Entry(i) => lossy(&self.entries[*i].id).into_owned(),
                    Owner::Service(n) => lossy(n).into_owned(),
                    Owner::Other => String::new(),
                };
                say(alloc::format!("{name} keeps exiting; waiting {}s", backoff(s.failures)));
            }
        }
    }

    fn reap(&mut self) {
        while let Ok((pid, st)) = process::wait(-1, process::WNOHANG) {
            if pid <= 0 {
                break;
            }
            self.child_exited(pid, st);
        }
    }

    /// Run `argv` and wait for it, reaping others meanwhile.
    fn run_wait(&mut self, argv: &[Vec<u8>], out: Option<i32>, env: &[Vec<u8>]) -> i32 {
        let Some(pid) = spawn(argv, out, env) else { return 127 };
        loop {
            match process::wait(-1, 0) {
                Ok((p, st)) if p == pid => return process::exit_code(st),
                Ok((p, s)) => self.child_exited(p, s),
                Err(_) => return 127,
            }
        }
    }

    /// Start whatever supervised processes are due.
    fn start_due(&mut self) {
        let t = now_secs();
        let due: Vec<usize> =
            self.respawn.iter().filter(|(_, s)| s.pid == 0 && s.due.is_some_and(|d| d <= t)).map(|(i, _)| *i).collect();
        for i in due {
            let argv = argv_of(&self.entries[i].process);
            if let Some(pid) = spawn(&argv, None, &[]) {
                self.children.insert(pid, Owner::Entry(i));
                let s = self.respawn.entry(i).or_default();
                (s.pid, s.started, s.due) = (pid, t, None);
            }
        }
        let due: Vec<Vec<u8>> = self
            .daemons
            .iter()
            .filter(|(_, s)| s.pid == 0 && s.due.is_some_and(|d| d <= t))
            .map(|(n, _)| n.clone())
            .collect();
        for name in due {
            let exec = services().into_iter().find(|s| s.name == name).and_then(|s| s.exec);
            let Some(exec) = exec else {
                self.daemons.remove(&name);
                continue;
            };
            let _ = process::kill_service(&name, signal::SIGKILL);
            if let Some((pid, _)) = self.spawn_service(&argv_of(&exec), &name, None) {
                self.children.insert(pid, Owner::Service(name.clone()));
                let s = self.daemons.entry(name).or_default();
                (s.pid, s.started, s.due) = (pid, t, None);
            }
        }
    }

    /// The next wake-up for backoff timers, in milliseconds.
    fn timeout(&self) -> i32 {
        let t = now_secs();
        let next = self.respawn.values().chain(self.daemons.values()).filter_map(|s| s.due).min();
        let ms = match next {
            Some(d) => ((d - t).max(0) * 1000 + 50).min(60_000) as i32,
            None => 5_000,
        };
        // A scheduled shutdown is checked every second.
        if self.scheduled.is_some() { ms.min(1000) } else { ms }
    }

    /// Start one process of service `name` with its output in the
    /// service's log (and copied to `forward`) → its pid and the pipe.
    fn spawn_service(&mut self, argv: &[Vec<u8>], name: &[u8], forward: Option<i32>) -> Option<(i32, i32)> {
        let (r, w) = process::pipe(fs::O_CLOEXEC).ok()?;
        let Ok((hr, hw)) = process::pipe(fs::O_CLOEXEC) else {
            let _ = io::close(r);
            let _ = io::close(w);
            return None;
        };
        let pid = spawn_with(argv, Some(w), &[], Some(hr));
        let _ = io::close(w);
        let _ = io::close(hr);
        if let Some(pid) = pid
            && let Err(e) = process::set_service(pid, name)
            && e != slate_rt::Errno::ENOSYS
        {
            say(alloc::format!("{}: cannot tag pid {pid}: {e}", lossy(name)));
        }
        // Released: it may run now.
        let _ = io::write_all(hw, b"x");
        let _ = io::close(hw);
        let Some(pid) = pid else {
            let _ = io::close(r);
            return None;
        };
        let _ = process::fcntl(r, process::F_SETFL, fs::O_NONBLOCK as usize);
        self.pipes.push(OutPipe { fd: r, service: name.to_vec(), partial: Vec::new(), forward });
        Some((pid, r))
    }

    /// Read what pipe `fd` holds; at its end, close it.
    fn read_pipe(&mut self, fd: i32) {
        let Some(i) = self.pipes.iter().position(|p| p.fd == fd) else { return };
        let mut buf = [0u8; 4096];
        let mut ended = false;
        loop {
            match io::read(fd, &mut buf) {
                Ok(0) => {
                    ended = true;
                    break;
                }
                Ok(n) => self.pipes[i].partial.extend_from_slice(&buf[..n]),
                Err(slate_rt::Errno::EAGAIN) => break,
                Err(slate_rt::Errno::EINTR) => continue,
                Err(_) => {
                    ended = true;
                    break;
                }
            }
        }
        let p = &mut self.pipes[i];
        let mut lines: Vec<Vec<u8>> = Vec::new();
        while let Some(nl) = p.partial.iter().position(|&c| c == b'\n') {
            let l: Vec<u8> = p.partial.drain(..=nl).collect();
            lines.push(l[..l.len() - 1].to_vec());
        }
        if ended && !p.partial.is_empty() {
            lines.push(core::mem::take(&mut p.partial));
        }
        let (service, forward) = (p.service.clone(), p.forward);
        if ended {
            let _ = io::close(fd);
            self.pipes.remove(i);
        }
        for l in lines {
            if let Some(f) = forward {
                let _ = io::write_all(f, &[l.as_slice(), b"\n"].concat());
            }
            self.log(&service, &l);
        }
    }

    /// Append a line to a service's log.
    fn log(&mut self, service: &[u8], text: &[u8]) {
        if self.logs_closed {
            return;
        }
        let log = self
            .logs
            .entry(service.to_vec())
            .or_insert_with(|| LogFile::new(&[SERVICE_LOGS, b"/", service, b".log"].concat(), LOG_LIMIT, 0o600));
        log.append(&logfile::line(text));
    }

    /// Wait up to `ms` for service output and take it in.
    fn poll_pipes(&mut self, ms: i32) {
        let mut fds: Vec<io::PollFd> =
            self.pipes.iter().map(|p| io::PollFd { fd: p.fd, events: io::POLLIN, revents: 0 }).collect();
        if fds.is_empty() {
            if ms > 0 {
                time::sleep_ns(ms as u64 * 1_000_000);
            }
            return;
        }
        if io::poll(&mut fds, ms).unwrap_or(0) == 0 {
            return;
        }
        for f in fds.iter().filter(|f| f.revents != 0) {
            self.read_pipe(f.fd);
        }
    }

    /// Run a service's init.d script with `action`, logging its output
    /// (copied to `out` while it runs) → its exit status.
    fn run_script(&mut self, s: &Service, action: &[u8], out: Option<i32>) -> i32 {
        let path = fs::join(INIT_D, &s.name);
        let Some((pid, pipe)) = self.spawn_service(&[path, action.to_vec()], &s.name, out) else { return 127 };
        let st = loop {
            match process::wait(-1, process::WNOHANG) {
                Ok((p, st)) if p == pid => break process::exit_code(st),
                Ok((p, st)) if p > 0 => {
                    self.child_exited(p, st);
                    continue;
                }
                Ok(_) => {}
                Err(_) => break 127,
            }
            self.poll_pipes(100);
        };
        // What it wrote last, then the caller is no longer copied (its
        // daemons may keep the pipe).
        self.read_pipe(pipe);
        if let Some(p) = self.pipes.iter_mut().find(|p| p.fd == pipe) {
            p.forward = None;
        }
        st
    }

    /// Stop every process left in service `name`: TERM, then KILL after
    /// `grace` seconds.
    fn kill_service_procs(&mut self, name: &[u8], grace: i64) {
        if process::kill_service(name, 0).unwrap_or(0) == 0 {
            return;
        }
        let _ = process::kill_service(name, signal::SIGTERM);
        let _ = process::kill_service(name, signal::SIGCONT);
        let end = now_ms() + grace * 1000;
        while now_ms() < end {
            self.reap();
            if process::kill_service(name, 0).unwrap_or(0) == 0 {
                return;
            }
            self.poll_pipes(20);
        }
        let _ = process::kill_service(name, signal::SIGKILL);
        for _ in 0..50 {
            self.reap();
            if process::kill_service(name, 0).unwrap_or(0) == 0 {
                return;
            }
            time::sleep_ns(20_000_000);
        }
    }

    /// The pids in service `name` (from /proc/PID/status).
    fn service_pids(name: &[u8]) -> Vec<i32> {
        let want = [b"Service:\t".as_slice(), name, b"\n"].concat();
        let mut pids: Vec<i32> = fs::read_dir(b"/proc")
            .unwrap_or_default()
            .iter()
            .filter_map(|e| core::str::from_utf8(&e.name).ok()?.parse::<i32>().ok())
            .filter(|pid| {
                fs::read_file(alloc::format!("/proc/{pid}/status").as_bytes()).is_ok_and(|s| {
                    s.windows(want.len()).any(|w| w == want.as_slice()) && !s.windows(9).any(|w| w == b"State:\tZ")
                })
            })
            .collect();
        pids.sort_unstable();
        pids
    }

    /// Close the logs before their file system goes.
    fn close_logs(&mut self) {
        for l in self.logs.values_mut() {
            l.close();
        }
        self.logs_closed = true;
    }

    /// Tell everyone logged in (wall).
    fn announce(&mut self, text: &str) {
        if let Some(pid) = spawn(&[b"/bin/wall".to_vec(), text.as_bytes().to_vec()], None, &[]) {
            self.children.insert(pid, Owner::Other);
        }
    }

    /// A scheduled shutdown: announcements, /run/nologin, and the
    /// shutdown itself when it is due.
    fn check_schedule(&mut self) {
        let Some(s) = &mut self.scheduled else { return };
        let left = s.at - now_secs();
        let mut say_now = None;
        while s.marks.first().is_some_and(|&m| m >= left) {
            let m = s.marks.remove(0);
            say_now = Some(m);
        }
        let nologin = left <= 300 && !s.nologin;
        if nologin {
            s.nologin = true;
        }
        let (cmd, at, message) = (s.cmd, s.at, s.message.clone());
        if left <= 0 {
            self.scheduled = None;
            self.shutdown(cmd);
        }
        if nologin {
            let _ = fs::write_file(NOLOGIN, &shutdown_text(cmd, at, &message), 0o644);
        }
        if say_now.is_some() {
            self.announce(&String::from_utf8_lossy(&shutdown_text(cmd, at, &message)));
        }
    }

    /// Stop a process: SIGHUP and SIGTERM (a login session's shell
    /// ignores TERM), then SIGKILL after `grace` seconds.
    fn terminate(&mut self, pid: i32, grace: i64) {
        let _ = process::kill(pid, signal::SIGHUP);
        let _ = process::kill(pid, signal::SIGTERM);
        let _ = process::kill(pid, signal::SIGCONT);
        let end = now_secs() + grace;
        loop {
            match process::wait(pid, process::WNOHANG) {
                Ok((p, _)) if p == pid => {
                    self.children.remove(&pid);
                    return;
                }
                Ok(_) => {}
                Err(_) => return,
            }
            if now_secs() >= end {
                let _ = process::kill(pid, signal::SIGKILL);
                let _ = process::wait(pid, 0);
                self.children.remove(&pid);
                return;
            }
            time::sleep_ns(20_000_000);
        }
    }

    fn service_action(&mut self, s: &Service, action: &[u8], out: Option<i32>) -> i32 {
        if s.exec.is_some() {
            return match action {
                b"start" => {
                    if self.daemons.get(&s.name).is_some_and(|d| d.pid > 0) {
                        return 0;
                    }
                    self.daemons.insert(s.name.clone(), Supervised { due: Some(0), ..Supervised::default() });
                    self.started.insert(s.name.clone());
                    self.start_due();
                    0
                }
                b"stop" => {
                    self.started.remove(&s.name);
                    if let Some(d) = self.daemons.remove(&s.name)
                        && d.pid > 0
                    {
                        self.terminate(d.pid, 5);
                    }
                    self.kill_service_procs(&s.name, 5);
                    0
                }
                b"restart" => {
                    self.service_action(s, b"stop", out);
                    self.service_action(s, b"start", out)
                }
                b"status" => {
                    let running = self.daemons.get(&s.name).is_some_and(|d| d.pid > 0);
                    if let Some(fd) = out {
                        let pids = Self::service_pids(&s.name);
                        let msg = if running {
                            let list: Vec<String> = pids.iter().map(|p| alloc::format!("{p}")).collect();
                            alloc::format!("{} is running (pids {})\n", lossy(&s.name), list.join(" "))
                        } else {
                            alloc::format!("{} is stopped\n", lossy(&s.name))
                        };
                        let _ = io::write_all(fd, msg.as_bytes());
                    }
                    if running { 0 } else { 3 }
                }
                _ => 2,
            };
        }
        let st = self.run_script(s, action, out);
        match action {
            b"start" if st == 0 => {
                self.started.insert(s.name.clone());
            }
            b"stop" => {
                self.started.remove(&s.name);
                self.kill_service_procs(&s.name, 5);
            }
            _ => {}
        }
        st
    }

    /// The rc step of a runlevel change: stop the services the new level
    /// stops, start those it starts, in LSB order.
    fn rc(&mut self, level: u8) {
        let all = services();
        let (stop_order, warnings) = config::order(&all, true);
        for w in warnings {
            say(w);
        }
        for i in stop_order {
            let s = &all[i];
            let stops = s.default_stop.contains(&level) || (level == b'S' && s.default_stop.contains(&b'1'));
            if stops && self.started.contains(&s.name) {
                self.service_action(&s.clone(), b"stop", None);
            }
        }
        if matches!(level, b'0' | b'6') {
            return;
        }
        let (start_order, _) = config::order(&all, false);
        for i in start_order {
            let s = &all[i];
            if s.default_start.contains(&level) && !self.started.contains(&s.name) {
                let st = self.service_action(&s.clone(), b"start", None);
                if st != 0 {
                    say(alloc::format!("{} failed to start (status {st})", lossy(&s.name)));
                }
            }
        }
    }

    /// Enter runlevel `level`.
    fn enter(&mut self, level: u8) {
        if level != self.level {
            self.previous = self.level;
        }
        self.level = level;
        slate_rt::utmp::run_level(level, self.previous);
        // Respawn entries not in the new level go away.
        let stale: Vec<usize> = self.respawn.keys().copied().filter(|&i| !self.entries[i].in_level(level)).collect();
        for i in stale {
            if let Some(s) = self.respawn.remove(&i)
                && s.pid > 0
            {
                self.terminate(s.pid, 3);
            }
        }
        self.rc(level);
        if matches!(level, b'0' | b'6') {
            self.close_logs();
        }
        for i in 0..self.entries.len() {
            let e = self.entries[i].clone();
            if !e.in_level(level) {
                continue;
            }
            match e.action {
                Action::Wait => {
                    self.run_wait(
                        &argv_of(&e.process),
                        None,
                        &[alloc::format!("RUNLEVEL={}", level as char).into_bytes()],
                    );
                }
                Action::Once => {
                    if let Some(pid) = spawn(&argv_of(&e.process), None, &[]) {
                        self.children.insert(pid, Owner::Other);
                    }
                }
                Action::Respawn => {
                    self.respawn.entry(i).or_insert(Supervised { due: Some(0), ..Supervised::default() });
                }
                _ => {}
            }
        }
        self.start_due();
    }

    /// Shut down: stop everything, then halt, power off or reboot.
    fn shutdown(&mut self, cmd: u32) -> ! {
        let level = if cmd == process::RB_AUTOBOOT { b'6' } else { b'0' };
        say(match cmd {
            process::RB_AUTOBOOT => "rebooting",
            process::RB_HALT_SYSTEM => "halting",
            _ => "powering off",
        });
        self.enter(level);
        self.stopping = true;
        for (_, s) in core::mem::take(&mut self.respawn) {
            if s.pid > 0 {
                let _ = process::kill(s.pid, signal::SIGTERM);
            }
        }
        let started: Vec<Vec<u8>> = self.started.iter().cloned().collect();
        let all = services();
        for name in started.into_iter().rev() {
            if let Some(s) = all.iter().find(|s| s.name == name) {
                self.service_action(&s.clone(), b"stop", None);
            }
        }
        // Everyone else: HUP (interactive shells ignore TERM) and TERM, up
        // to the grace time (three seconds unless `shutdown -t`), then KILL.
        let _ = process::kill(-1, signal::SIGHUP);
        let _ = process::kill(-1, signal::SIGTERM);
        let _ = process::kill(-1, signal::SIGCONT);
        let end = now_ms() + self.grace * 1000;
        while now_ms() < end {
            match process::wait(-1, process::WNOHANG) {
                Ok((p, _)) if p > 0 => continue,
                Ok(_) => {
                    time::sleep_ns(20_000_000);
                }
                Err(_) => break,
            }
        }
        let _ = process::kill(-1, signal::SIGKILL);
        while process::wait(-1, 0).is_ok() {}
        let _ = fs::unlink(NOLOGIN);
        fs::sync();
        let e = process::reboot(cmd);
        say(alloc::format!("reboot: {e}"));
        process::exit(1)
    }

    /// One control-socket request.
    fn request(&mut self, fd: i32) {
        let reply = |msg: &str| {
            let _ = io::write_all(fd, msg.as_bytes());
        };
        let line = {
            let mut buf = alloc::vec![0u8; 1024];
            let n = io::read(fd, &mut buf).unwrap_or(0);
            buf.truncate(n);
            buf
        };
        let line = line.strip_suffix(b"\n").unwrap_or(&line);
        let words: Vec<&[u8]> = line.split(|&c| c == b' ').filter(|w| !w.is_empty()).collect();
        let root = net::peer_cred(fd).is_ok_and(|(_, uid, _)| uid == 0);
        match words.as_slice() {
            [b"runlevel"] => reply(&alloc::format!("{} {}\n", self.previous as char, self.level as char)),
            [b"scheduled"] => match &self.scheduled {
                Some(s) => reply(&alloc::format!("{} in {}s\n", cmd_name(s.cmd), (s.at - now_secs()).max(0))),
                None => reply("no shutdown is scheduled\n"),
            },
            _ if !root => reply("error: must be root\n"),
            [b"level", l] if l.len() == 1 && matches!(l[0], b'0'..=b'6' | b'S' | b's' | b'q' | b'Q') => match l[0] {
                b'0' => {
                    reply("ok\n");
                    let _ = io::close(fd);
                    self.shutdown(process::RB_POWER_OFF);
                }
                b'6' => {
                    reply("ok\n");
                    let _ = io::close(fd);
                    self.shutdown(process::RB_AUTOBOOT);
                }
                b'q' | b'Q' => {
                    self.load();
                    reply("ok\n");
                }
                l => {
                    reply("ok\n");
                    self.enter(l.to_ascii_uppercase());
                }
            },
            [b"halt"] => {
                reply("ok\n");
                let _ = io::close(fd);
                self.shutdown(process::RB_HALT_SYSTEM);
            }
            [b"schedule", secs, cmd, grace, message @ ..] => {
                let num = |w: &[u8]| core::str::from_utf8(w).ok().and_then(|t| t.parse::<i64>().ok());
                let cmd = match *cmd {
                    b"r" => process::RB_AUTOBOOT,
                    b"h" => process::RB_HALT_SYSTEM,
                    _ => process::RB_POWER_OFF,
                };
                let (Some(secs), Some(grace)) = (num(secs), num(grace)) else {
                    reply("error: bad schedule\n");
                    return;
                };
                self.grace = grace.clamp(0, 600);
                let message = message.join(&b' ');
                if secs <= 0 {
                    reply("ok\n");
                    let _ = io::close(fd);
                    self.shutdown(cmd);
                }
                let at = now_secs() + secs;
                let marks = MARKS.iter().copied().filter(|&m| m < secs).collect();
                self.scheduled = Some(Scheduled { at, cmd, message: message.clone(), marks, nologin: false });
                reply("ok\n");
                self.announce(&String::from_utf8_lossy(&shutdown_text(cmd, at, &message)));
                self.check_schedule();
            }
            [b"cancel"] => match self.scheduled.take() {
                Some(_) => {
                    let _ = fs::unlink(NOLOGIN);
                    self.announce("The system shutdown has been cancelled.");
                    reply("ok\n");
                }
                None => reply("error: no shutdown is scheduled\n"),
            },
            [b"service", name, action] => {
                let Some(s) = services().into_iter().find(|s| s.name == *name) else {
                    reply(&alloc::format!("error: no service {}\n", lossy(name)));
                    return;
                };
                let st = self.service_action(&s, action, Some(fd));
                reply(&alloc::format!("status {st}\n"));
            }
            _ => reply("error: unknown request\n"),
        }
    }

    fn run(&mut self) -> ! {
        loop {
            let pending = signal::take();
            // Ctrl-Alt-Del runs the ctrlaltdel entries; the power button
            // (SIGPWR from the kernel, ADR 0029) the powerfail ones.
            for (sig, action) in [(signal::SIGINT, Action::Ctrlaltdel), (signal::SIGPWR, Action::Powerfail)] {
                if pending & (1 << sig) == 0 {
                    continue;
                }
                for e in self.entries.clone().iter().filter(|e| e.action == action) {
                    if let Some(pid) = spawn(&argv_of(&e.process), None, &[]) {
                        self.children.insert(pid, Owner::Other);
                    }
                }
            }
            self.reap();
            self.start_due();
            self.check_schedule();
            for l in self.logs.values_mut() {
                l.flush();
            }
            let mut fds = alloc::vec![io::PollFd { fd: self.listener, events: io::POLLIN, revents: 0 }];
            fds.extend(self.pipes.iter().map(|p| io::PollFd { fd: p.fd, events: io::POLLIN, revents: 0 }));
            let n = io::poll(&mut fds, self.timeout()).unwrap_or(0);
            if n == 0 {
                continue;
            }
            for f in fds[1..].iter().filter(|f| f.revents != 0) {
                self.read_pipe(f.fd);
            }
            if self.listener >= 0
                && fds[0].revents & io::POLLIN != 0
                && let Ok(c) = net::accept(self.listener)
            {
                self.request(c);
                let _ = io::close(c);
            }
        }
    }
}

/// pid 1.
fn init() -> i32 {
    let _ = signal::set(signal::SIGCHLD, signal::Disposition::CatchInterrupt);
    let _ = signal::set(signal::SIGINT, signal::Disposition::CatchInterrupt);
    let _ = signal::set(signal::SIGPWR, signal::Disposition::CatchInterrupt);
    for s in [signal::SIGTERM, signal::SIGHUP, signal::SIGTSTP, signal::SIGTTIN, signal::SIGTTOU, signal::SIGPIPE] {
        let _ = signal::set(s, signal::Disposition::Ignore);
    }
    let _ = fs::chdir(b"/");
    // Ctrl-Alt-Del comes to init as SIGINT (ADR 0060).
    let _ = process::set_ctrl_alt_del(false);
    let mut it = Init {
        entries: Vec::new(),
        level: b'N',
        previous: b'N',
        children: BTreeMap::new(),
        respawn: BTreeMap::new(),
        started: BTreeSet::new(),
        daemons: BTreeMap::new(),
        listener: -1,
        stopping: false,
        pipes: Vec::new(),
        logs: BTreeMap::new(),
        logs_closed: false,
        scheduled: None,
        grace: 3,
    };
    it.load();
    // The kernel command line may name the runlevel ("single", "S", 1-5).
    let mut level = config::default_level(&it.entries);
    if let Ok(cmdline) = fs::read_file(b"/proc/cmdline") {
        for w in cmdline.split(|c| c.is_ascii_whitespace()) {
            match w {
                b"single" | b"S" | b"s" | b"1" => level = b'S',
                [d @ b'2'..=b'5'] => level = *d,
                _ => {}
            }
        }
    }
    for e in it.entries.clone() {
        if e.action == Action::Sysinit {
            it.run_wait(&argv_of(&e.process), None, &[]);
        }
    }
    // The file systems are mounted: a boot record (ADR 0057).
    slate_rt::utmp::boot();
    for e in it.entries.clone() {
        match e.action {
            Action::Boot => {
                if let Some(pid) = spawn(&argv_of(&e.process), None, &[]) {
                    it.children.insert(pid, Owner::Other);
                }
            }
            Action::Bootwait => {
                it.run_wait(&argv_of(&e.process), None, &[]);
            }
            _ => {}
        }
    }
    it.listener = net::listen(SOCKET).unwrap_or_else(|e| {
        say(alloc::format!("control socket: {e}"));
        -1
    });
    it.enter(level);
    it.run()
}

// --- commands -------------------------------------------------------------------------

/// Send `req` to init; print its answer. The status: 0 on "ok".
fn ask(req: &[u8]) -> Result<i32, slate_rt::Errno> {
    let fd = net::connect(SOCKET)?;
    io::write_all(fd, &[req, b"\n"].concat())?;
    let answer = io::read_to_end(fd).unwrap_or_default();
    let _ = io::close(fd);
    let text = String::from_utf8_lossy(&answer);
    let mut status = 0;
    for l in text.lines() {
        if let Some(e) = l.strip_prefix("error: ") {
            io::err(alloc::format!("{}: {e}\n", slate_rt::prog_name()).as_bytes());
            status = 1;
        } else if let Some(s) = l.strip_prefix("status ") {
            status = s.parse().unwrap_or(1);
        } else if l != "ok" {
            io::out(l.as_bytes());
            io::out(b"\n");
        }
    }
    Ok(status)
}

fn usage(text: &str) -> i32 {
    io::err(alloc::format!("usage: {} {text}\n", slate_rt::prog_name()).as_bytes());
    2
}

/// reboot/poweroff/halt: through init, or at once with -f.
fn power(cmd: u32, args: &[Vec<u8>]) -> i32 {
    let force = args.iter().any(|a| a == b"-f" || a == b"--force");
    if !force {
        let req: &[u8] = match cmd {
            process::RB_AUTOBOOT => b"level 6",
            process::RB_HALT_SYSTEM => b"halt",
            _ => b"level 0",
        };
        match ask(req) {
            Ok(st) => return st,
            Err(e) => {
                io::err(alloc::format!("{}: cannot reach init ({e}); forcing\n", slate_rt::prog_name()).as_bytes())
            }
        }
    }
    fs::sync();
    let e = process::reboot(cmd);
    io::err(alloc::format!("{}: {e}\n", slate_rt::prog_name()).as_bytes());
    1
}

/// `shutdown [-r|-h|-P|-H] [-t SEC] [now|+MIN|HH:MM] [message]`,
/// `shutdown -c` and `shutdown --show` (ADR 0060): init keeps the
/// schedule.
fn shutdown_cmd(args: &[Vec<u8>]) -> i32 {
    const USAGE: &str = "[-r|-h|-P|-H] [-t SEC] [now|+MIN|HH:MM] [message] | -c | --show";
    let mut cmd = b'p';
    let mut when: Option<&[u8]> = None;
    let mut grace = 3i64;
    let mut msg = Vec::new();
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        match a.as_slice() {
            b"-r" | b"--reboot" => cmd = b'r',
            b"-h" | b"-P" | b"--poweroff" => cmd = b'p',
            b"-H" | b"--halt" => cmd = b'h',
            b"-c" => return ask(b"cancel").unwrap_or_else(unreachable_init),
            b"--show" => return ask(b"scheduled").unwrap_or_else(unreachable_init),
            b"-t" => {
                i += 1;
                match args.get(i).and_then(|t| core::str::from_utf8(t).ok()?.parse().ok()) {
                    Some(t) => grace = t,
                    None => return usage(USAGE),
                }
            }
            _ if a.starts_with(b"-") => return usage(USAGE),
            _ if when.is_none() => when = Some(a),
            _ => {
                if !msg.is_empty() {
                    msg.push(b' ');
                }
                msg.extend_from_slice(a);
            }
        }
        i += 1;
    }
    let delay: i64 = match when {
        None | Some(b"now") | Some(b"+0") => 0,
        Some(w) if w.starts_with(b"+") => {
            match core::str::from_utf8(&w[1..]).ok().and_then(|m| m.parse::<i64>().ok()) {
                Some(m) if m >= 0 => m * 60,
                _ => return usage(USAGE),
            }
        }
        Some(w) => {
            // HH:MM, local time, today or tomorrow.
            let t: Vec<i64> =
                w.split(|&c| c == b':').filter_map(|p| core::str::from_utf8(p).ok()?.parse().ok()).collect();
            if t.len() != 2 || !(0..24).contains(&t[0]) || !(0..60).contains(&t[1]) {
                return usage(USAGE);
            }
            let tm = slate_rt::tz::localtime(time::unix());
            let now = i64::from(tm.hour * 3600 + tm.min * 60 + tm.sec);
            let target = t[0] * 3600 + t[1] * 60;
            if target >= now { target - now } else { target + 86400 - now }
        }
    };
    let req = [alloc::format!("schedule {delay} {} {grace} ", cmd as char).as_bytes(), &msg].concat();
    match ask(&req) {
        Ok(0) if delay > 0 => {
            io::out(
                alloc::format!(
                    "Shutdown scheduled for {}; 'shutdown -c' cancels it.\n",
                    slate_rt::tz::stamp(time::unix() + delay)
                )
                .as_bytes(),
            );
            0
        }
        Ok(st) => st,
        Err(e) if delay == 0 => {
            io::err(alloc::format!("shutdown: cannot reach init ({e}); forcing\n").as_bytes());
            let rb = match cmd {
                b'r' => process::RB_AUTOBOOT,
                b'h' => process::RB_HALT_SYSTEM,
                _ => process::RB_POWER_OFF,
            };
            power(rb, &[b"-f".to_vec()])
        }
        Err(e) => unreachable_init(e),
    }
}

fn unreachable_init(e: slate_rt::Errno) -> i32 {
    io::err(alloc::format!("{}: cannot reach init: {e}\n", slate_rt::prog_name()).as_bytes());
    1
}

/// Every command slinit provides, by the name it runs as.
pub fn main() -> i32 {
    let args = slate_rt::env::args();
    let name = slate_rt::prog_name();
    if process::getpid() == 1 && (name == "init" || name == "slinit") {
        return init();
    }
    // `slinit --order LEVEL`: the start order of /etc/init.d (for tests).
    if args.get(1).map(Vec::as_slice) == Some(b"--order") {
        let level = args.get(2).and_then(|l| l.first().copied()).unwrap_or(b'3');
        let svcs = services();
        let (o, w) = config::order(&svcs, false);
        for w in w {
            io::err(alloc::format!("{w}\n").as_bytes());
        }
        for i in o.into_iter().filter(|&i| svcs[i].default_start.contains(&level)) {
            io::out(&svcs[i].name);
            io::out(b"\n");
        }
        return 0;
    }
    let rest = || args.get(1).map_or(&b""[..], |a| a.as_slice());
    match name.as_str() {
        "telinit" | "init" | "slinit" => {
            let l = rest();
            if l.len() != 1 {
                return usage("RUNLEVEL (0-6, S, Q)");
            }
            ask(&[b"level ".as_slice(), l].concat()).unwrap_or_else(|e| {
                io::err(alloc::format!("{name}: cannot reach init: {e}\n").as_bytes());
                1
            })
        }
        "runlevel" => ask(b"runlevel").unwrap_or_else(|_| {
            io::out(b"unknown\n");
            1
        }),
        "reboot" => power(process::RB_AUTOBOOT, args),
        "poweroff" => power(process::RB_POWER_OFF, args),
        "halt" => power(process::RB_HALT_SYSTEM, args),
        "shutdown" => shutdown_cmd(args),
        "service" => {
            // `service NAME log [-n N] [-f]`: the service's log, by logread.
            if args.get(2).is_some_and(|a| a == b"log") {
                let mut argv = alloc::vec![b"logread".to_vec(), b"-s".to_vec(), args[1].clone()];
                argv.extend_from_slice(&args[3..]);
                let e = process::execve(b"/bin/logread", &argv, slate_rt::env::vars());
                io::err(alloc::format!("service: /bin/logread: {e}\n").as_bytes());
                return 1;
            }
            if args.len() != 3 {
                return usage("NAME start|stop|restart|status|log");
            }
            ask(&[b"service ".as_slice(), &args[1], b" ", &args[2]].concat()).unwrap_or_else(|e| {
                io::err(alloc::format!("service: cannot reach init: {e}\n").as_bytes());
                1
            })
        }
        _ => usage("is init; as a command: telinit, runlevel, shutdown, reboot, poweroff, halt, service"),
    }
}
