// SPDX-License-Identifier: MIT OR Apache-2.0

//! Logging in (ADR 0012: ours): getty opens a terminal and asks for a
//! name, login checks the password against /etc/shadow (SHA-512 crypt) and
//! starts the user's shell, su switches users, passwd changes passwords.
//!
//! On the console of a system with the Strata desktop, getty starts the
//! graphical login screen instead, `strata-login`, as the unprivileged
//! `greeter` user (ADR 0038); it falls back to the text prompt when the
//! screen can't show itself.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod accounts;
pub mod broker;
pub mod db;
pub mod iolog;
pub mod sudo;
pub mod sudoreplay;

use alloc::string::String;
use alloc::vec::Vec;

use slate_coreutils::crypt;
use slate_rt::{eprintln, fs, io, lossy, process, term};

use db::User;

/// The text of /run/nologin (a shutdown is near, ADR 0060) or
/// /etc/nologin, when one exists: only root may log in.
pub fn nologin() -> Option<Vec<u8>> {
    [&b"/run/nologin"[..], b"/etc/nologin"]
        .into_iter()
        .find(|p| fs::exists(p))
        .map(|p| fs::read_file(p).unwrap_or_default())
}

fn prog() -> String {
    slate_rt::prog_name()
}

fn error(msg: impl core::fmt::Display) {
    io::flush_stdout();
    eprintln!("{}: {msg}", prog());
}

/// Read a line from the terminal on `fd`, with echo off when `secret`.
pub(crate) fn read_line(fd: i32, secret: bool) -> Option<Vec<u8>> {
    let saved = term::get(fd).ok();
    if secret && let Some(t) = saved {
        let mut q = t;
        q.lflag &= !term::ECHO;
        q.lflag |= term::ICANON;
        let _ = term::set(fd, &q, true);
    }
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    let ok = loop {
        match io::read(fd, &mut b) {
            Ok(1) if b[0] == b'\n' || b[0] == b'\r' => break true,
            Ok(1) => line.push(b[0]),
            _ => break !line.is_empty(),
        }
    };
    if secret {
        if let Some(t) = saved {
            let _ = term::set(fd, &t, true);
        }
        let _ = io::write_all(fd, b"\n");
    }
    ok.then_some(line)
}

pub(crate) fn prompt(fd: i32, text: &[u8]) {
    io::flush_stdout();
    let _ = io::write_all(fd, text);
}

fn hostname() -> Vec<u8> {
    let n = process::uname()[1].clone();
    if n.is_empty() { b"slate".to_vec() } else { n }
}

/// The environment of a login session.
fn login_env(u: &User, keep: bool) -> Vec<Vec<u8>> {
    let mut env: Vec<Vec<u8>> = if keep { slate_rt::env::vars().to_vec() } else { Vec::new() };
    let mut set = |k: &[u8], v: &[u8]| {
        env.retain(|e| !(e.starts_with(k) && e.get(k.len()) == Some(&b'=')));
        env.push([k, b"=", v].concat());
    };
    let path: &[u8] = if u.uid == 0 { b"/sbin:/bin:/usr/sbin:/usr/bin" } else { b"/bin:/usr/bin" };
    let term = slate_rt::env::var(b"TERM").unwrap_or_else(|| b"linux".to_vec());
    set(b"HOME", &u.home);
    set(b"USER", &u.name);
    set(b"LOGNAME", &u.name);
    set(b"SHELL", &shell_of(u));
    set(b"PATH", path);
    set(b"TERM", &term);
    env
}

fn shell_of(u: &User) -> Vec<u8> {
    if u.shell.is_empty() { b"/bin/sh".to_vec() } else { u.shell.clone() }
}

/// Become `u`: supplementary groups, group, then user.
fn become_user(u: &User) -> bool {
    let groups = db::groups_of(u);
    if let Err(e) =
        process::setgroups(&groups).and_then(|()| process::setgid(u.gid)).and_then(|()| process::setuid(u.uid))
    {
        error(alloc::format!("cannot change to user {}: {e}", lossy(&u.name)));
        return false;
    }
    true
}

/// Start `u`'s shell (a login shell when `login`; `-c cmd` if given).
fn exec_shell(u: &User, env: &[Vec<u8>], login: bool, cmd: Option<&[u8]>) -> i32 {
    let shell = shell_of(u);
    let base = fs::basename(&shell).to_vec();
    let argv0 = if login { [b"-".as_slice(), &base].concat() } else { base };
    let mut argv = alloc::vec![argv0];
    if let Some(c) = cmd {
        argv.push(b"-c".to_vec());
        argv.push(c.to_vec());
    }
    let e = process::execve(&shell, &argv, env);
    error(alloc::format!("{}: {e}", lossy(&shell)));
    126
}

/// A new password for an account whose old one expired, typed twice;
/// the disk's password follows when the old one opened it.
fn change_expired(u: &User, fd: i32) -> bool {
    for _ in 0..3 {
        prompt(fd, b"Current password: ");
        let cur = read_line(fd, true).unwrap_or_default();
        let hash = db::hash_of(u).unwrap_or_default();
        if !hash.is_empty() && !crypt::verify(&cur, &hash) {
            io::out(b"Authentication token manipulation error\n");
            return false;
        }
        prompt(fd, b"New password: ");
        let Some(p1) = read_line(fd, true) else { return false };
        prompt(fd, b"Retype new password: ");
        let p2 = read_line(fd, true).unwrap_or_default();
        if p1 != p2 || p1.is_empty() || p1 == cur {
            io::out(if p1 == cur && !p1.is_empty() {
                b"The password has not been changed.\n".as_slice()
            } else {
                b"Sorry, passwords do not match.\n".as_slice()
            });
            continue;
        }
        let Ok(h) = accounts::hash(&p1) else { return false };
        if db::set_hash(&u.name, &h).is_err() {
            io::out(b"passwd: cannot update /etc/shadow\n");
            return false;
        }
        if !cur.is_empty() {
            let _ = slate_crypt::follow_password_of(Some(u.uid), &cur, &p1);
        }
        io::out(b"passwd: password updated successfully\n");
        return true;
    }
    false
}

/// An account without a password logs in without one at the machine
/// (shadow(5)), but not from elsewhere (`login -h`, ADR 0119).
fn check_password(u: &User, fd: i32, remote: bool) -> bool {
    let Some(hash) = db::hash_of(u) else { return false };
    if hash.is_empty() && !remote {
        return true;
    }
    // From elsewhere the question is asked anyway, so the answer can't
    // tell which accounts have no password.
    prompt(fd, b"Password: ");
    let Some(pw) = read_line(fd, true) else { return false };
    !hash.is_empty() && crypt::verify(&pw, &hash)
}

// --- login --------------------------------------------------------------------

/// `login`, `getty` and `nologin` share a binary.
pub fn login_main() -> i32 {
    match prog().as_str() {
        "getty" | "agetty" => getty(),
        "nologin" => {
            io::out(b"This account is currently not available.\n");
            1
        }
        _ => login(),
    }
}

fn login() -> i32 {
    let args = slate_rt::env::args();
    let mut preauth = false;
    let mut keep_env = false;
    let mut name: Option<Vec<u8>> = None;
    let mut host = Vec::new();
    let mut i = 1;
    while let Some(a) = args.get(i) {
        match a.as_slice() {
            b"-f" => preauth = true,
            b"-p" => keep_env = true,
            b"-h" => {
                i += 1;
                host = args.get(i).cloned().unwrap_or_default();
            }
            b"--" => {}
            _ => name = Some(a.clone()),
        }
        i += 1;
    }
    if preauth && process::getuid() != 0 {
        error("-f is for root only");
        return 1;
    }
    let fd = 0;
    for attempt in 0..3 {
        let user_name = match name.take() {
            Some(n) => n,
            None => {
                prompt(fd, &[hostname().as_slice(), b" login: "].concat());
                match read_line(fd, false) {
                    Some(n) if !n.is_empty() => n,
                    Some(_) => continue,
                    None => return 1,
                }
            }
        };
        let user = db::user_by_name(&user_name);
        let ok = match &user {
            Some(u) => preauth || check_password(u, fd, !host.is_empty()),
            None => {
                // Ask for a password anyway, so names cannot be probed.
                prompt(fd, b"Password: ");
                let _ = read_line(fd, true);
                false
            }
        };
        if let (true, Some(u)) = (ok, user) {
            // Password ageing (shadow(5), ADR 0057).
            match accounts::ageing(&u.name) {
                accounts::Ageing::Refused(msg) => {
                    io::out(alloc::format!("{msg}\n").as_bytes());
                    return 1;
                }
                accounts::Ageing::MustChange => {
                    io::out(b"You are required to change your password immediately.\n");
                    if !change_expired(&u, fd) {
                        return 1;
                    }
                }
                accounts::Ageing::Warn(days) => {
                    io::out(
                        alloc::format!(
                            "Warning: your password will expire in {days} day{}.\n",
                            if days == 1 { "" } else { "s" }
                        )
                        .as_bytes(),
                    );
                }
                accounts::Ageing::Ok => {}
            }
            if u.uid != 0
                && let Some(msg) = nologin()
            {
                io::out(&msg);
                return 1;
            }
            return start_session(&u, keep_env, &[], &host);
        }
        slate_rt::time::sleep_ns(if attempt < 2 { 1_000_000_000 } else { 0 });
        io::out(b"\nLogin incorrect\n");
        io::flush_stdout();
        preauth = false;
    }
    1
}

/// The broker's half of a graphical login (ADR 0038): in a session of
/// its own with the console as its terminal, become `u` and start their
/// login shell, whose profile starts Strata.
/// `screen`: the login was typed on the login screen, so the session is
/// Strata alone (`SLATE_SESSION=strata`, which /etc/profile execs).
pub(crate) fn session_on_console(u: &User, screen: bool) -> i32 {
    let _ = process::setsid();
    if let Ok(fd) = fs::open(b"/dev/console", fs::O_RDWR, 0) {
        let _ = term::steal_controlling(fd);
        for t in 0..3 {
            let _ = process::dup2(fd, t);
        }
        if fd > 2 {
            let _ = io::close(fd);
        }
    }
    let _ = term::set_foreground(0, process::getpid());
    // The profile execs Strata for it: nothing is left when Strata ends
    // (ADR 0039).
    let extra: &[&[u8]] = if screen { &[b"SLATE_SESSION=strata"] } else { &[] };
    start_session(u, false, extra, b"")
}

/// The login shell for `u`, with `extra` environment entries; `host` is
/// where the login came from (`login -h`), if anywhere.
fn start_session(u: &User, keep_env: bool, extra: &[&[u8]], host: &[u8]) -> i32 {
    // Login records (ADR 0057): this process becomes the shell, so its
    // pid names the session; whoever reaps it writes the logout.
    let line = slate_rt::utmp::tty_line().unwrap_or_else(|| b"console".to_vec());
    let last = slate_rt::utmp::lastlog(u.uid);
    slate_rt::utmp::login(process::getpid(), &line, &u.name, u.uid, host);
    // The terminal belongs to the user now.
    if let Some(tty) = process::ttyname(0) {
        let tty_gid = slate_coreutils::simple::db_names(db::GROUP)
            .into_iter()
            .find(|(n, _, _)| n == b"tty")
            .map_or(u.gid, |(_, g, _)| g);
        let _ = fs::chown(&tty, u.uid, tty_gid);
        let _ = fs::chmod(&tty, 0o620);
    }
    if !become_user(u) {
        return 1;
    }
    if fs::chdir(&u.home).is_err() {
        io::out(b"No home directory, logging in with HOME=/\n");
        let _ = fs::chdir(b"/");
    }
    let mut u = u.clone();
    if !fs::exists(&u.home) {
        u.home = b"/".to_vec();
    }
    if let Some((t, l, h)) = last {
        let tm = slate_rt::tz::localtime(t);
        let mut when = String::new();
        slate_rt::time::format(&tm, "%a %b %e %H:%M:%S %Y", &mut when);
        let place =
            if h.is_empty() { alloc::format!("on {}", lossy(&l)) } else { alloc::format!("from {}", lossy(&h)) };
        io::out(alloc::format!("Last login: {when} {place}\n").as_bytes());
    }
    if let Ok(m) = fs::read_file(b"/etc/motd") {
        io::out(&m);
    }
    io::flush_stdout();
    let mut env = login_env(&u, keep_env);
    env.extend(extra.iter().map(|e| e.to_vec()));
    exec_shell(&u, &env, true, None)
}

// --- getty --------------------------------------------------------------------

/// The IPv4 address of the interface with the default route
/// (/proc/net/route, then SIOCGIFADDR on its name; netdevice(7)).
fn ipv4_address() -> Option<[u8; 4]> {
    const SIOCGIFADDR: u32 = 0x8915;
    let route = fs::read_file(b"/proc/net/route").ok()?;
    let iface = lossy(&route)
        .lines()
        .skip(1)
        .find(|l| l.split('\t').nth(1) == Some("00000000"))
        .and_then(|l| l.split('\t').next().map(String::from))?;
    let fd = slate_rt::net::udp_socket().ok()?;
    let mut ifr = [0u8; 40];
    let n = iface.len().min(15);
    ifr[..n].copy_from_slice(&iface.as_bytes()[..n]);
    let r = io::ioctl(fd, SIOCGIFADDR, ifr.as_mut_ptr() as usize);
    let _ = io::close(fd);
    r.ok()?;
    // struct ifreq: the name, then a sockaddr_in (family, port, address).
    Some([ifr[20], ifr[21], ifr[22], ifr[23]])
}

/// `/etc/issue` with its escapes (\n host, \l line, \s system, \r
/// release, \m machine, \4 IPv4 address, \\). For \4 it waits a few
/// seconds for DHCP after boot.
fn issue(line: &[u8]) -> Vec<u8> {
    let Ok(text) = fs::read_file(b"/etc/issue") else { return Vec::new() };
    let mut addr = None;
    if text.windows(2).any(|w| w == b"\\4") {
        for _ in 0..40 {
            addr = ipv4_address();
            if addr.is_some() {
                break;
            }
            slate_rt::time::sleep_ns(250_000_000);
        }
    }
    let un = process::uname();
    let mut out = Vec::new();
    let mut i = 0;
    while i < text.len() {
        if text[i] == b'\\' && i + 1 < text.len() {
            match text[i + 1] {
                b'n' => out.extend_from_slice(&hostname()),
                b'l' => out.extend_from_slice(line),
                b's' => out.extend_from_slice(&un[0]),
                b'r' => out.extend_from_slice(&un[2]),
                b'v' => out.extend_from_slice(&un[3]),
                b'm' => out.extend_from_slice(&un[4]),
                b'4' => match addr {
                    Some(a) => out.extend_from_slice(alloc::format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]).as_bytes()),
                    None => out.extend_from_slice(b"none yet (is a network cable plugged in?)"),
                },
                b'\\' => out.push(b'\\'),
                c => out.extend_from_slice(&[b'\\', c]),
            }
            i += 2;
        } else {
            out.push(text[i]);
            i += 1;
        }
    }
    out
}

/// The graphical login screen (ADR 0038).
const LOGIN_SCREEN: &[u8] = b"/bin/strata-login";
/// What the login screen exits with when it can't show itself (no
/// display, seat, fonts or user to log in): getty asks on the text console.
pub const NO_SCREEN: i32 = 3;

/// Whether getty on `line` starts the login screen: on the console of a
/// system with Strata (/etc/slate/session), the login screen and a
/// display, unless the kernel command line says `slate.login=text`.
pub fn wants_login_screen(line: &[u8], cmdline: &[u8], exists: &dyn Fn(&[u8]) -> bool) -> bool {
    line == b"console"
        && !cmdline.split(|c| c.is_ascii_whitespace()).any(|w| w == b"slate.login=text")
        && [b"/etc/slate/session".as_slice(), LOGIN_SCREEN, b"/dev/dri/card0"].iter().all(|p| exists(p))
}

/// Run the login screen as `greeter` and wait for it; its exit status.
fn login_screen(greeter: &User, env: &[Vec<u8>]) -> Option<i32> {
    match process::fork() {
        Ok(0) => {
            if !become_user(greeter) {
                process::exit_now(NO_SCREEN);
            }
            let _ = fs::chdir(b"/");
            let mut env = env.to_vec();
            env.push(b"HOME=/".to_vec());
            env.push([b"USER=".as_slice(), &greeter.name].concat());
            let e = process::execve(LOGIN_SCREEN, &[b"strata-login".to_vec()], &env);
            error(alloc::format!("{}: {e}", lossy(LOGIN_SCREEN)));
            process::exit_now(NO_SCREEN)
        }
        // A login screen that crashed counts as one that can't show itself.
        Ok(pid) => process::wait(pid, 0).ok().and_then(|(_, status)| process::exited(status)),
        Err(_) => None,
    }
}

/// The c_cflag speed bits for the first speed in `list` (`9600` or
/// `115200,38400,9600`).
pub fn first_speed(list: &[u8]) -> Option<u32> {
    let first = list.split(|&c| c == b',').next()?;
    let n: u32 = core::str::from_utf8(first).ok()?.parse().ok()?;
    slate_coreutils::stty::SPEEDS.iter().find(|(s, _)| *s == n && n != 0).map(|(_, b)| *b)
}

/// `getty [-n] [-l program] [--noclear] [baud] tty [term]` (agetty's
/// argument order is accepted too): the line is set to the speed given.
fn getty() -> i32 {
    let args = slate_rt::env::args();
    let mut tty: Option<Vec<u8>> = None;
    let mut program = b"/bin/login".to_vec();
    let mut term_name: Option<Vec<u8>> = None;
    let mut speed: Option<u32> = None;
    let mut ask = true;
    let mut i = 1;
    while let Some(a) = args.get(i) {
        match a.as_slice() {
            b"-n" | b"--skip-login" => ask = false,
            b"-l" | b"--login-program" => {
                i += 1;
                program = args.get(i).cloned().unwrap_or(program);
            }
            b"-L" | b"--local-line" | b"--noclear" | b"-8" | b"-i" | b"-N" => {}
            // The line's speed: the first of a list (agetty's
            // `115200,38400,9600`), before or after the line.
            _ if a.first().is_some_and(u8::is_ascii_digit) => match first_speed(a) {
                Some(s) => speed = Some(s),
                None => {
                    error(alloc::format!("bad speed: {}", lossy(a)));
                    return 1;
                }
            },
            _ if tty.is_none() => tty = Some(a.clone()),
            _ => term_name = Some(a.clone()),
        }
        i += 1;
    }
    let Some(tty) = tty else {
        error("usage: getty [-n] [-l program] [baud] tty [term]");
        return 1;
    };
    let path = if tty.starts_with(b"/") { tty.clone() } else { fs::join(b"/dev", &tty) };
    let line = fs::basename(&path).to_vec();
    // A session of our own with the terminal as controlling terminal.
    let _ = process::setsid();
    let fd = match fs::open(&path, fs::O_RDWR | fs::O_NOCTTY, 0) {
        Ok(fd) => fd,
        Err(e) => {
            error(alloc::format!("{}: {e}", lossy(&path)));
            slate_rt::time::sleep_ns(5_000_000_000);
            return 1;
        }
    };
    if term::set_controlling(fd).is_err() {
        let _ = term::steal_controlling(fd);
    }
    for t in 0..3 {
        let _ = process::dup2(fd, t);
    }
    if fd > 2 {
        let _ = io::close(fd);
    }
    let _ = fs::chown(&path, 0, 0);
    let _ = fs::chmod(&path, 0o600);
    // Sane modes: canonical input with echo and signals.
    if let Ok(mut t) = term::get(0) {
        t.lflag |= term::ICANON | term::ECHO | term::ECHOE | term::ECHOK | term::ISIG | term::IEXTEN;
        t.iflag |= term::ICRNL;
        t.oflag |= term::OPOST | term::ONLCR;
        if let Some(bits) = speed {
            t.cflag = (t.cflag & !slate_coreutils::stty::CBAUD) | bits;
        }
        let _ = term::set(0, &t, true);
    }
    let term_env = [b"TERM=".as_slice(), term_name.as_deref().unwrap_or(b"linux")].concat();
    let env = alloc::vec![term_env, b"PATH=/sbin:/bin:/usr/sbin:/usr/bin".to_vec()];
    // The graphical login screen, where Strata is installed (ADR 0038).
    let cmdline = fs::read_file(b"/proc/cmdline").unwrap_or_default();
    if wants_login_screen(&line, &cmdline, &|p| fs::exists(p))
        && let Some(g) = db::user_by_name(b"greeter")
    {
        match login_screen(&g, &env) {
            Some(NO_SCREEN) | None => {}
            Some(status) => return status,
        }
    }
    let _ = io::write_all(1, &issue(&line));
    let mut argv = alloc::vec![b"login".to_vec()];
    if ask {
        loop {
            prompt(1, &[hostname().as_slice(), b" login: "].concat());
            match read_line(0, false) {
                Some(n) if !n.is_empty() && !n.starts_with(b"-") => {
                    argv.push(b"--".to_vec());
                    argv.push(n);
                    break;
                }
                Some(_) => continue,
                None => return 1,
            }
        }
    }
    let e = process::execve(&program, &argv, &env);
    error(alloc::format!("{}: {e}", lossy(&program)));
    1
}

// --- su ---------------------------------------------------------------------------

pub fn su_main() -> i32 {
    let args = slate_rt::env::args();
    let mut login = false;
    let mut cmd: Option<Vec<u8>> = None;
    let mut shell: Option<Vec<u8>> = None;
    let mut name = b"root".to_vec();
    let mut i = 1;
    while let Some(a) = args.get(i) {
        match a.as_slice() {
            b"-" | b"-l" | b"--login" => login = true,
            b"-c" | b"--command" => {
                i += 1;
                cmd = args.get(i).cloned();
            }
            b"-s" | b"--shell" => {
                i += 1;
                shell = args.get(i).cloned();
            }
            b"-m" | b"-p" | b"--preserve-environment" => {}
            _ if a.starts_with(b"-") => {
                error(alloc::format!("invalid option -- '{}'", lossy(&a[1..])));
                return 1;
            }
            _ => name = a.clone(),
        }
        i += 1;
    }
    let Some(mut u) = db::user_by_name(&name) else {
        error(alloc::format!("user {} does not exist", lossy(&name)));
        return 1;
    };
    let root = process::getuid() == 0;
    if let Some(s) = shell
        && root
    {
        u.shell = s;
    }
    if root {
        if !become_user(&u) {
            return 1;
        }
    } else {
        // su is not set-user-ID (ADR 0032): the privilege broker checks the
        // password and changes this process's credentials.
        prompt(0, b"Password: ");
        let pw = read_line(0, true).unwrap_or_default();
        if let Err(e) = broker::request(&[b"su", &u.name, &pw]) {
            error(e);
            return 1;
        }
    }
    let env = if login {
        let _ = fs::chdir(&u.home);
        login_env(&u, false)
    } else {
        // Keep the environment; HOME and SHELL follow the user, and USER
        // and LOGNAME too unless becoming root (util-linux su).
        let mut env = slate_rt::env::vars().to_vec();
        let mut set = |k: &[u8], v: &[u8]| {
            env.retain(|e| !(e.starts_with(k) && e.get(k.len()) == Some(&b'=')));
            env.push([k, b"=", v].concat());
        };
        set(b"HOME", &u.home);
        set(b"SHELL", &shell_of(&u));
        if u.uid != 0 {
            set(b"USER", &u.name);
            set(b"LOGNAME", &u.name);
        }
        env
    };
    exec_shell(&u, &env, login, cmd.as_deref())
}

// --- newgrp ---------------------------------------------------------------------------

/// `newgrp [-] [GROUP]`: a shell with GROUP (without one, the login
/// group) as the real and effective group; `-` gives it a login
/// environment. The broker checks membership or the group's password
/// (gshadow(5), ADR 0119).
pub fn newgrp_main() -> i32 {
    let args = slate_rt::env::args();
    // `sg [-] [GROUP [[-c] COMMAND]]`: the command, run by /bin/sh with
    // the group, as newgrp's shell would be (sg(1)).
    let sg = args.first().is_some_and(|a| fs::basename(a) == b"sg");
    let mut login = false;
    let mut group: Option<Vec<u8>> = None;
    let mut command: Vec<Vec<u8>> = Vec::new();
    for a in args.iter().skip(1) {
        match a.as_slice() {
            _ if sg && group.is_some() => {
                if !(command.is_empty() && a == b"-c") {
                    command.push(a.clone());
                }
            }
            b"-" | b"-l" => login = true,
            _ if a.starts_with(b"-") => {
                error(alloc::format!("invalid option -- '{}'", lossy(&a[1..])));
                return 2;
            }
            _ if group.is_some() => {
                error("usage: newgrp [-] [GROUP]");
                return 2;
            }
            _ => group = Some(a.clone()),
        }
    }
    let Some(u) = db::user_by_uid(process::getuid()) else {
        error("you have no account");
        return 1;
    };
    let group = match group {
        Some(g) => g,
        None => match name_of_group(u.gid) {
            Some(g) => g,
            None => {
                error("your login group has no name");
                return 1;
            }
        },
    };
    let ask = |pw: &[u8]| broker::request(&[b"newgrp", &group, &[b"p", pw].concat()]);
    let r = match ask(b"") {
        Err(e) if e == "password required" => {
            prompt(0, b"Password: ");
            let pw = read_line(0, true).unwrap_or_default();
            ask(&pw)
        }
        r => r,
    };
    if let Err(e) = r {
        error(e);
        return 1;
    }
    let env = if login {
        let _ = fs::chdir(&u.home);
        login_env(&u, false)
    } else {
        slate_rt::env::vars().to_vec()
    };
    if !command.is_empty() {
        let cmd = command.join(&b' ');
        let e = process::execve(b"/bin/sh", &[b"sh".to_vec(), b"-c".to_vec(), cmd], &env);
        error(alloc::format!("/bin/sh: {e}"));
        return 126;
    }
    exec_shell(&u, &env, login, None)
}

/// The name of the group numbered `gid`.
fn name_of_group(gid: u32) -> Option<Vec<u8>> {
    let data = fs::read_file(db::GROUP).ok()?;
    data.split(|&c| c == b'\n').find_map(|l| {
        let f: Vec<&[u8]> = l.split(|&c| c == b':').collect();
        (f.len() >= 4 && core::str::from_utf8(f[2]).ok()?.parse::<u32>().ok()? == gid).then(|| f[0].to_vec())
    })
}

// --- slate-approve ------------------------------------------------------------------

/// `slate-approve ACTION`: ask for a system action (restart, poweroff,
/// rollback, timezone=ZONE, network=CARD SETTINGS..., desktop=add|remove,
/// compat=on|off, flatpak=install|remove|update ...) through the
/// broker; in a Strata session its approval dialog asks for the password
/// (ADR 0037).
pub fn approve_main() -> i32 {
    let args = slate_rt::env::args();
    let Some(name) = args.get(1).filter(|_| args.len() == 2) else {
        error(
            "usage: slate-approve restart|poweroff|rollback|timezone=ZONE|'network=CARD SETTINGS...'|desktop=add|desktop=remove|compat=on|compat=off|'flatpak=install APP...'|'flatpak=remove APP...'|flatpak=update",
        );
        return 2;
    };
    match broker::request(&[b"action", name]) {
        Ok(()) => 0,
        Err(e) => {
            error(e);
            1
        }
    }
}

// --- passwd -------------------------------------------------------------------------

pub fn passwd_main() -> i32 {
    let args = slate_rt::env::args();
    let mut action = b'c';
    let mut stdin = false;
    let mut all = false;
    let mut name: Option<Vec<u8>> = None;
    // Ageing (root): -n MIN, -x MAX, -w WARN, -i INACTIVE, as shadow(5)
    // fields 3, 4, 5 and 6.
    let mut ageing: Vec<(usize, Option<i64>)> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        let field = match a.as_slice() {
            b"-n" | b"--mindays" => Some(3),
            b"-x" | b"--maxdays" => Some(4),
            b"-w" | b"--warndays" => Some(5),
            b"-i" | b"--inactive" => Some(6),
            _ => None,
        };
        if let Some(f) = field {
            let Some(v) = args.get(i) else {
                error(alloc::format!("option '{}' requires an argument", lossy(a)));
                return 2;
            };
            i += 1;
            let n = core::str::from_utf8(v).ok().and_then(|s| s.parse::<i64>().ok());
            if n.is_none() {
                error(alloc::format!("invalid numeric argument '{}'", lossy(v)));
                return 3;
            }
            ageing.push((f, n.filter(|&x| x >= 0)));
            action = b'a';
            continue;
        }
        match a.as_slice() {
            b"-e" | b"--expire" => action = b'e',
            b"-d" | b"--delete" => action = b'd',
            b"-l" | b"--lock" => action = b'l',
            b"-u" | b"--unlock" => action = b'u',
            b"-S" | b"--status" => action = b'S',
            b"-a" | b"--all" => all = true,
            b"-Sa" | b"-aS" => (action, all) = (b'S', true),
            b"--stdin" => stdin = true,
            _ if a.starts_with(b"-") => {
                error(alloc::format!("unrecognized option '{}'", lossy(a)));
                return 1;
            }
            _ => name = Some(a.clone()),
        }
    }
    let uid = process::getuid();
    if action == b'S' && all {
        // Every account's status, root only (shadow(5) is root's).
        if uid != 0 {
            error("Permission denied.");
            return 1;
        }
        let d = match accounts::Db::open() {
            Ok(d) => d,
            Err(e) => {
                error(e);
                return 1;
            }
        };
        let mut out = String::new();
        for p in &d.passwd {
            out.push_str(&accounts::status_line(&p.0[0], d.shadow.iter().find(|s| s.name() == p.0[0].as_slice())));
            out.push('\n');
        }
        io::out(out.as_bytes());
        return 0;
    }
    let me = db::user_by_uid(uid);
    let target = match name {
        Some(n) => n,
        None => match &me {
            Some(u) => u.name.clone(),
            None => {
                error("you do not exist");
                return 1;
            }
        },
    };
    let Some(u) = db::user_by_name(&target) else {
        error(alloc::format!("user '{}' does not exist", lossy(&target)));
        return 1;
    };
    if uid != 0 && (u.uid != uid || action != b'c') {
        error("Permission denied.");
        return 1;
    }
    if uid != 0 {
        // Not set-user-ID (ADR 0032): the broker checks the current password
        // and writes the new one.
        let fd = 0;
        prompt(fd, b"Current password: ");
        let cur = read_line(fd, !stdin).unwrap_or_default();
        if !stdin {
            prompt(fd, b"New password: ");
        }
        let Some(p1) = read_line(fd, !stdin) else { return 1 };
        if !stdin {
            prompt(fd, b"Retype new password: ");
            if read_line(fd, true).unwrap_or_default() != p1 {
                error("Sorry, passwords do not match.");
                return 1;
            }
        }
        return match broker::request(&[b"passwd", &u.name, &cur, &p1]) {
            Ok(()) => {
                io::out(b"passwd: password updated successfully\n");
                0
            }
            Err(e) => {
                error(e);
                1
            }
        };
    }
    if matches!(action, b'e' | b'a') {
        let mut d = match accounts::Db::open() {
            Ok(d) => d,
            Err(e) => {
                error(e);
                return 1;
            }
        };
        let sp = d.shadow_of(&u.name);
        if action == b'e' {
            // Changed "on day 0": a new password at the next login.
            sp.set(2, Some(0));
        }
        for (f, v) in &ageing {
            sp.set(*f, *v);
        }
        return match d.save() {
            Ok(()) => {
                io::out(b"passwd: password expiry information changed.\n");
                0
            }
            Err(e) => {
                error(e);
                1
            }
        };
    }
    let hash = db::hash_of(&u).unwrap_or_default();
    // Root setting a password: the disk's slot for the account follows
    // (ADR 0058).
    let mut typed: Option<Vec<u8>> = None;
    let new = match action {
        b'S' => {
            let d = match accounts::Db::open() {
                Ok(d) => d,
                Err(e) => {
                    error(e);
                    return 1;
                }
            };
            let line = accounts::status_line(&u.name, d.shadow.iter().find(|s| s.name() == u.name.as_slice()));
            io::out(alloc::format!("{line}\n").as_bytes());
            return 0;
        }
        b'd' => Vec::new(),
        b'l' => {
            if hash.starts_with(b"!") {
                hash
            } else {
                [b"!".as_slice(), &hash].concat()
            }
        }
        b'u' => hash.strip_prefix(b"!").unwrap_or(&hash).to_vec(),
        _ => {
            let fd = 0;
            if uid != 0 && !hash.is_empty() {
                prompt(fd, b"Current password: ");
                let cur = read_line(fd, !stdin).unwrap_or_default();
                if !crypt::verify(&cur, &hash) {
                    slate_rt::time::sleep_ns(1_000_000_000);
                    error("Authentication token manipulation error");
                    return 1;
                }
            }
            if !stdin {
                prompt(fd, b"New password: ");
            }
            let Some(p1) = read_line(fd, !stdin) else { return 1 };
            if !stdin {
                prompt(fd, b"Retype new password: ");
                let p2 = read_line(fd, true).unwrap_or_default();
                if p1 != p2 {
                    error("Sorry, passwords do not match.");
                    return 1;
                }
            }
            let mut salt = [0u8; 12];
            if process::random(&mut salt).is_err() {
                error("no random numbers");
                return 1;
            }
            let h = match crypt::crypt(&p1, crypt::new_salt(&salt).as_bytes()) {
                Some(h) => h.into_bytes(),
                None => return 1,
            };
            typed = Some(p1);
            h
        }
    };
    match db::set_hash(&u.name, &new) {
        Ok(()) => {
            if let Some(p) = typed
                && let Err(e) = slate_crypt::reset_password(u.uid, &p)
            {
                error(alloc::format!("the disk's password did not change: {e}"));
            }
            if action == b'c' {
                io::out(b"passwd: password updated successfully\n");
            }
            0
        }
        Err(e) => {
            error(alloc::format!("cannot update /etc/shadow: {e}"));
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_screen_or_text() {
        let all = |_: &[u8]| true;
        assert!(wants_login_screen(b"console", b"root=PARTUUID=x quiet", &all));
        assert!(!wants_login_screen(b"console", b"root=x slate.login=text", &all));
        assert!(!wants_login_screen(b"ttyS1", b"", &all));
        let no_card = |p: &[u8]| p != b"/dev/dri/card0";
        assert!(!wants_login_screen(b"console", b"", &no_card));
        let no_desktop = |p: &[u8]| p != b"/etc/slate/session";
        assert!(!wants_login_screen(b"console", b"", &no_desktop));
    }

    #[test]
    fn getty_speeds() {
        assert_eq!(first_speed(b"9600"), Some(13));
        assert_eq!(first_speed(b"115200,38400,9600"), Some(0o10002));
        assert_eq!(first_speed(b"0"), None);
        assert_eq!(first_speed(b"12345"), None);
        assert_eq!(first_speed(b"fast"), None);
    }
}
