// SPDX-License-Identifier: MIT OR Apache-2.0

//! sudo: run one command as another user (root unless `-u`), with the
//! caller's own password, through the privilege broker (ADRs 0058, 0142,
//! 0159). Slate programs are never set-user-ID: the broker checks the
//! policy's `run` rules (which may name commands) and the password,
//! changes this process's credentials (as for su), and sudo then executes
//! exactly the command it asked for, with a clean environment (the
//! policy's `defaults` say what is kept), descriptors from 3 up closed,
//! and on a terminal a pseudo-terminal of its own between the command
//! and the person's terminal. When the policy asks for an I/O log, the
//! broker hands over its open files and sudo records into them. The
//! options are sudo(8)'s: -u, -g, -i, -s, -e (and the name sudoedit), -b,
//! -C, -D, -E (and --preserve-env=LIST), -H, -P, -T, -A, -n, -k, -K, -v,
//! -l, -S, -p, -h; -r and -t (SELinux) are refused.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::signal::{self, Disposition};
use slate_rt::{env, fs, io, lossy, process, term};

use crate::broker::{self, Defaults, Rule};
use crate::db;
use crate::iolog::{Recorder, Stream};

/// After a timeout's SIGTERM, how long before SIGKILL.
const KILL_AFTER_NS: u64 = 5_000_000_000;

fn fail(code: i32, msg: impl core::fmt::Display) -> i32 {
    slate_rt::eprintln!("sudo: {msg}");
    code
}

const USAGE: &str =
    "usage: sudo [-bnSAEHP] [-C num] [-D dir] [-T timeout] [-u user] [-g group] [-p prompt] command [args...]
       sudo [-nSA] [-u user] -i | -s [command]
       sudo -e [-nSA] [-u user] file...
       sudo -v | -k | -K | -l [-h host] [command]
       sudo -h | -V
";

fn usage() -> i32 {
    io::write_all(2, USAGE.as_bytes()).map_or(1, |()| 1)
}

/// What the command line asks for.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub user: Option<Vec<u8>>,
    pub group: Option<Vec<u8>>,
    pub login: bool,
    pub shell: bool,
    pub edit: bool,
    pub background: bool,
    pub keep_env: bool,
    /// `--preserve-env=LIST`: these variables only.
    pub keep_vars: Vec<Vec<u8>>,
    pub nonint: bool,
    pub stdin: bool,
    pub askpass: bool,
    pub validate: bool,
    pub forget: bool,
    pub remove: bool,
    pub list: bool,
    pub version: bool,
    pub help: bool,
    pub preserve_groups: bool,
    /// `-r`/`-t`: an SELinux role or type, which Slate has not.
    pub selinux: bool,
    /// `-C`: the first descriptor closed before the command runs.
    pub close_from: Option<i32>,
    pub chdir: Option<Vec<u8>>,
    pub host: Option<Vec<u8>>,
    /// `-T`, as written.
    pub timeout: Option<Vec<u8>>,
    pub prompt: Option<Vec<u8>>,
    pub command: Vec<Vec<u8>>,
}

/// Parse sudo's arguments (after the program's name); `None` is a usage
/// error.
pub fn parse(args: &[Vec<u8>]) -> Option<Options> {
    let mut o = Options::default();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == b"--" {
            i += 1;
            break;
        }
        if !a.starts_with(b"-") || a.len() < 2 {
            break;
        }
        if let Some(l) = a.strip_prefix(b"--") {
            let (k, v) = match l.iter().position(|&c| c == b'=') {
                Some(e) => (&l[..e], Some(l[e + 1..].to_vec())),
                None => (l, None),
            };
            if k == b"preserve-env" {
                match v {
                    Some(list) => {
                        o.keep_vars.extend(list.split(|&c| c == b',').filter(|n| !n.is_empty()).map(<[u8]>::to_vec))
                    }
                    None => o.keep_env = true,
                }
                i += 1;
                continue;
            }
            let mut value = || {
                v.clone().or_else(|| {
                    i += 1;
                    args.get(i).cloned()
                })
            };
            match k {
                b"user" => o.user = Some(value()?),
                b"group" => o.group = Some(value()?),
                b"close-from" => o.close_from = Some(number(&value()?)?),
                b"chdir" => o.chdir = Some(value()?),
                b"host" => o.host = Some(value()?),
                b"command-timeout" => o.timeout = Some(value()?),
                b"prompt" => o.prompt = Some(value()?),
                b"role" | b"type" => {
                    value()?;
                    o.selinux = true;
                }
                b"login" => o.login = true,
                b"shell" => o.shell = true,
                b"edit" => o.edit = true,
                b"background" => o.background = true,
                b"set-home" => {}
                b"preserve-groups" => o.preserve_groups = true,
                b"askpass" => o.askpass = true,
                b"non-interactive" => o.nonint = true,
                b"stdin" => o.stdin = true,
                b"validate" => o.validate = true,
                b"reset-timestamp" => o.forget = true,
                b"remove-timestamp" => o.remove = true,
                b"list" => o.list = true,
                b"version" => o.version = true,
                b"help" => o.help = true,
                _ => return None,
            }
            i += 1;
            continue;
        }
        let mut j = 1;
        while j < a.len() {
            let c = a[j];
            j += 1;
            // -h is help alone, a host with a word after it (sudo(8)).
            if c == b'h' {
                if j < a.len() {
                    o.host = Some(a[j..].to_vec());
                    j = a.len();
                } else if args.get(i + 1).is_some_and(|n| !n.starts_with(b"-")) {
                    i += 1;
                    o.host = Some(args[i].clone());
                } else {
                    o.help = true;
                }
                continue;
            }
            let mut value = || -> Option<Vec<u8>> {
                if j < a.len() {
                    let v = a[j..].to_vec();
                    j = a.len();
                    Some(v)
                } else {
                    i += 1;
                    args.get(i).cloned()
                }
            };
            match c {
                b'u' => o.user = Some(value()?),
                b'g' => o.group = Some(value()?),
                b'C' => o.close_from = Some(number(&value()?)?),
                b'D' => o.chdir = Some(value()?),
                b'T' => o.timeout = Some(value()?),
                b'p' => o.prompt = Some(value()?),
                b'r' | b't' => {
                    value()?;
                    o.selinux = true;
                }
                b'i' => o.login = true,
                b's' => o.shell = true,
                b'e' => o.edit = true,
                b'b' => o.background = true,
                b'E' => o.keep_env = true,
                b'H' => {}
                b'P' => o.preserve_groups = true,
                b'A' => o.askpass = true,
                b'n' => o.nonint = true,
                b'S' => o.stdin = true,
                b'v' => o.validate = true,
                b'k' => o.forget = true,
                b'K' => o.remove = true,
                b'l' => o.list = true,
                b'V' => o.version = true,
                _ => return None,
            }
        }
        i += 1;
    }
    o.command = args[i.min(args.len())..].to_vec();
    Some(o)
}

fn number(v: &[u8]) -> Option<i32> {
    core::str::from_utf8(v).ok()?.parse().ok()
}

/// A timeout as sudo(8) takes it: seconds, or numbers with `d`, `h`, `m`
/// and `s` (`90`, `5m`, `1h30m`). Zero is none.
pub fn parse_timeout(v: &[u8]) -> Option<u64> {
    let v = core::str::from_utf8(v).ok()?;
    if v.is_empty() {
        return None;
    }
    if let Ok(s) = v.parse::<u64>() {
        return Some(s);
    }
    let (mut total, mut n, mut digits) = (0u64, 0u64, false);
    for c in v.chars() {
        match c {
            '0'..='9' => {
                n = n.checked_mul(10)?.checked_add(u64::from(c.to_digit(10)?))?;
                digits = true;
            }
            'd' | 'D' | 'h' | 'H' | 'm' | 'M' | 's' | 'S' if digits => {
                let unit = match c.to_ascii_lowercase() {
                    'd' => 86400,
                    'h' => 3600,
                    'm' => 60,
                    _ => 1,
                };
                total = total.checked_add(n.checked_mul(unit)?)?;
                (n, digits) = (0, false);
            }
            _ => return None,
        }
    }
    (!digits).then_some(total)
}

/// `p` made absolute against `cwd`, without following links.
fn absolute(cwd: &[u8], p: &[u8]) -> Vec<u8> {
    if p.starts_with(b"/") { p.to_vec() } else { fs::join(cwd, p) }
}

/// The command's absolute path: as given if it has a slash (made
/// absolute), else the first executable file of that name in `path`
/// (the policy's `secure_path`).
fn resolve(path: &[u8], cwd: &[u8], c: &[u8], exists: &dyn Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
    if c.contains(&b'/') {
        return Some(absolute(cwd, c));
    }
    path.split(|&b| b == b':').filter(|d| !d.is_empty()).map(|d| fs::join(d, c)).find(|p| exists(p))
}

/// A command word for the broker: `a` and the word, or `h` and its hex
/// when it holds a newline (a field can't).
fn encode_word(w: &[u8]) -> Vec<u8> {
    if !w.contains(&b'\n') {
        return [b"a".as_slice(), w].concat();
    }
    let mut out = b"h".to_vec();
    for b in w {
        out.extend(format!("{b:02x}").bytes());
    }
    out
}

/// The broker's `run` request: the target, the password (`p` first),
/// the action, the command line for the log (newlines written `\n`), the
/// group (`g` first), the options (`o` first), and the command's words.
fn request_fields(
    target: &[u8],
    pw: &[u8],
    action: &[u8],
    text: &[u8],
    group: Option<&[u8]>,
    opts: &[u8],
    argv: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    let mut f = alloc::vec![
        b"run".to_vec(),
        target.to_vec(),
        [b"p".as_slice(), pw].concat(),
        action.to_vec(),
        crate::iolog::escape_newlines(text),
        [b"g".as_slice(), group.unwrap_or_default()].concat(),
        [b"o".as_slice(), opts].concat(),
    ];
    f.extend(argv.iter().map(|a| encode_word(a)));
    f
}

/// Whether a directory (its owner, group and mode) is writable by `uid`
/// with `groups`: sudoedit will not edit files in one, where the person
/// could swap the file for a link meanwhile.
fn writable_by((owner, group, mode): (u32, u32, u32), uid: u32, groups: &[u32]) -> bool {
    uid == 0
        || (owner == uid && mode & 0o200 != 0)
        || (groups.contains(&group) && mode & 0o020 != 0)
        || mode & 0o002 != 0
}

/// The editor's words: `SUDO_EDITOR`, `VISUAL` or `EDITOR` (the first
/// set), split at blanks, else the first of vi and etch that exists.
fn editor(var: &dyn Fn(&[u8]) -> Option<Vec<u8>>, exists: &dyn Fn(&[u8]) -> bool) -> Option<Vec<Vec<u8>>> {
    for name in [b"SUDO_EDITOR".as_slice(), b"VISUAL", b"EDITOR"] {
        if let Some(v) = var(name) {
            let words: Vec<Vec<u8>> =
                v.split(|c| c.is_ascii_whitespace()).filter(|w| !w.is_empty()).map(<[u8]>::to_vec).collect();
            if !words.is_empty() {
                return Some(words);
            }
        }
    }
    [b"/bin/vi".as_slice(), b"/bin/etch"].iter().find(|p| exists(p)).map(|p| alloc::vec![p.to_vec()])
}

/// Read a password: from standard input with -S, else from the terminal
/// with echo off.
fn password(prompt: &[u8], stdin: bool) -> Option<Vec<u8>> {
    if stdin {
        // A byte at a time: the next try reads the next line.
        let _ = io::write_all(2, prompt);
        let mut l = Vec::new();
        let mut b = [0u8; 1];
        loop {
            match io::read(io::STDIN, &mut b) {
                Ok(1) if b[0] == b'\n' => break,
                Ok(1) => l.push(b[0]),
                _ if l.is_empty() => return None,
                _ => break,
            }
        }
        let _ = io::write_all(2, b"\n");
        return Some(l);
    }
    let fd = fs::open(b"/dev/tty", fs::O_RDWR | fs::O_CLOEXEC, 0).ok()?;
    let _ = io::write_all(fd, prompt);
    let saved = term::get(fd).ok();
    if let Some(t) = saved {
        let mut q = t;
        q.lflag &= !term::ECHO;
        q.lflag |= term::ICANON;
        let _ = term::set(fd, &q, true);
    }
    let mut r = io::Reader::new(fd);
    let line = r.line().ok().flatten();
    if let Some(t) = saved {
        let _ = term::set(fd, &t, true);
    }
    let _ = io::write_all(fd, b"\n");
    let _ = io::close(fd);
    let l = line?;
    Some(l.strip_suffix(b"\n").unwrap_or(&l).to_vec())
}

/// -A: the password from the `SUDO_ASKPASS` program (run as the caller,
/// the prompt its argument), the first line it writes.
fn askpass(prompt: &[u8]) -> Result<Vec<u8>, String> {
    let Some(prog) = env::var(b"SUDO_ASKPASS").filter(|p| !p.is_empty()) else {
        return Err("no askpass program specified, try setting SUDO_ASKPASS".into());
    };
    let (r, w) = process::pipe(fs::O_CLOEXEC).map_err(|e| format!("unable to make a pipe: {e}"))?;
    let pid = match process::fork() {
        Ok(0) => {
            let _ = process::dup2(w, 1);
            let e = process::execve(&prog, &[prog.clone(), prompt.to_vec()], env::vars());
            slate_rt::eprintln!("sudo: unable to run {}: {e}", lossy(&prog));
            process::exit_now(1);
        }
        Ok(pid) => pid,
        Err(e) => return Err(format!("unable to fork: {e}")),
    };
    let _ = io::close(w);
    let out = io::read_to_end(r).unwrap_or_default();
    let _ = io::close(r);
    let st = process::wait(pid, 0).map_or(1, |(_, st)| st);
    if st != 0 {
        return Err("no password was given".into());
    }
    Ok(out.split(|&c| c == b'\n').next().unwrap_or_default().to_vec())
}

/// Close every descriptor from `from` up (sudo's closefrom).
fn close_from(from: i32) {
    let fds: Vec<i32> = fs::read_dir(b"/proc/self/fd")
        .map(|d| d.iter().filter_map(|e| core::str::from_utf8(&e.name).ok()?.parse().ok()).collect())
        .unwrap_or_default();
    for fd in fds.into_iter().filter(|&fd| fd >= from) {
        let _ = io::close(fd);
    }
}

/// The person who ran sudo, as they were before the broker changed this
/// process.
struct Caller {
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
    name: Vec<u8>,
}

impl Caller {
    fn in_group(&self, g: &[u8]) -> bool {
        db::group_id(g).is_some_and(|gid| gid == self.gid || self.groups.contains(&gid))
    }
}

/// The rule that lets `me` run `argv` as `to` (with `group`), as the
/// broker will find it.
fn rule_for<'a>(rules: &'a [Rule], me: &Caller, to: &[u8], group: Option<&[u8]>, argv: &[Vec<u8>]) -> Option<&'a Rule> {
    let target_groups = db::user_by_name(to).map(|u| db::groups_of(&u)).unwrap_or_default();
    let target_in = |g: &[u8]| db::group_id(g).is_some_and(|gid| target_groups.contains(&gid));
    let req = broker::RunRequest { to, group, argv };
    broker::run_allowed(rules, &me.name, &|g| me.in_group(g), &req, &target_in)
}

pub fn sudo_main() -> i32 {
    let args = env::args();
    let edit_name = args.first().is_some_and(|a| fs::basename(a) == b"sudoedit");
    let Some(mut o) = parse(args.get(1..).unwrap_or_default()) else { return usage() };
    o.edit |= edit_name;
    if o.help {
        io::out(USAGE.as_bytes());
        return 0;
    }
    if o.version {
        io::out(b"Slate sudo (through slate-brokerd)\n");
        return 0;
    }
    if o.selinux {
        return fail(1, "SELinux roles and types (-r, -t) are not supported: Slate has no SELinux");
    }
    if let Some(h) = &o.host {
        let me = process::uname()[1].clone();
        if !(h == &me || h == b"localhost" || h == b"127.0.0.1" || h == b"::1") {
            return fail(1, format!("{}: only this machine's commands can be run or listed", lossy(h)));
        }
    }
    if o.close_from.is_some_and(|n| n < 3) {
        return fail(1, "the argument to -C must be a number greater than or equal to 3");
    }
    if (o.edit && (o.login || o.shell || o.background)) || (o.login && o.shell) {
        return usage();
    }
    if o.forget || o.remove {
        let _ = broker::request(&[b"run-forget"]);
        if o.command.is_empty() && !o.validate {
            return 0;
        }
    }
    let policy = broker::read_policy();
    let d = &policy.defaults;
    let me = Caller {
        uid: process::getuid(),
        gid: process::getgid(),
        groups: process::getgroups(),
        name: db::user_by_uid(process::getuid())
            .map_or_else(|| format!("{}", process::getuid()).into_bytes(), |u| u.name),
    };
    let cwd = fs::getcwd().unwrap_or_else(|_| b"/".to_vec());
    let is_file = |p: &[u8]| fs::stat(p).is_ok_and(|s| s.is_file());
    if o.list {
        return list(&o, &policy, &me, &cwd);
    }
    if o.command.is_empty() && !o.login && !o.shell && !o.validate {
        return usage();
    }
    let timeout = match &o.timeout {
        Some(t) => match parse_timeout(t) {
            Some(s) if me.uid != 0 && !d.user_command_timeouts => {
                let _ = s;
                return fail(1, "sorry, you are not allowed to set a command timeout");
            }
            Some(s) => (s > 0).then_some(s),
            None => return fail(1, format!("invalid timeout: {}", lossy(t))),
        },
        None => None,
    };
    if let Some(dir) = &o.chdir
        && me.uid != 0
        && d.runcwd.as_deref().is_none_or(|r| r != b"*" && r != dir.as_slice())
    {
        return fail(1, "sorry, you are not allowed to set the directory (-D)");
    }
    // -g alone runs as the caller, with that group.
    let target = o.user.clone().unwrap_or_else(|| if o.group.is_some() { me.name.clone() } else { b"root".to_vec() });
    let Some(t) = db::user_by_name(&target) else {
        return fail(1, format!("unknown user {}", lossy(&target)));
    };
    let text: Vec<u8> = match () {
        _ if o.command.is_empty() => b"-".to_vec(),
        _ if o.edit => [b"sudoedit ".as_slice(), &o.command.join(&b' ')].concat(),
        _ => o.command.join(&b' '),
    };
    let sh = if t.shell.is_empty() { b"/bin/sh".to_vec() } else { t.shell.clone() };
    // The command, exactly as it will run: the broker checks this.
    let (action, argv): (&[u8], Vec<Vec<u8>>) = if o.validate && o.command.is_empty() {
        (b"validate", Vec::new())
    } else if o.edit {
        if o.command.is_empty() {
            return usage();
        }
        let mut v = alloc::vec![b"sudoedit".to_vec()];
        v.extend(o.command.iter().map(|f| absolute(&cwd, f)));
        (b"edit", v)
    } else if o.login || o.shell {
        let mut v = alloc::vec![sh.clone()];
        if !o.command.is_empty() {
            v.push(b"-c".to_vec());
            v.push(text.clone());
        }
        (b"exec", v)
    } else {
        let Some(path) = resolve(&d.secure_path, &cwd, &o.command[0], &is_file) else {
            return fail(1, format!("{}: command not found", lossy(&o.command[0])));
        };
        let mut v = alloc::vec![path];
        v.extend(o.command[1..].iter().cloned());
        (b"exec", v)
    };
    // Keeping the environment takes a rule for every command, its
    // setenv tag, or defaults setenv (sudoers(5)).
    if (o.keep_env || !o.keep_vars.is_empty()) && me.uid != 0 && !d.setenv {
        let rule = rule_for(&policy.rules, &me, &target, o.group.as_deref(), &argv);
        if !rule.is_some_and(|r| r.tags.setenv || r.commands.is_none()) {
            return fail(1, "sorry, you are not allowed to preserve the environment");
        }
    }
    let mut opts: Vec<Vec<u8>> = Vec::new();
    if o.preserve_groups {
        opts.push(b"P".to_vec());
    }
    if let Some((rows, cols)) = (0..3).find_map(term::size) {
        opts.push(format!("W{rows}x{cols}").into_bytes());
    }
    let opts = opts.join(&b' ');
    let (granted, log_fds) = match ask(&o, d, &me, &target, action, &text, &opts, &argv) {
        Ok(g) => g,
        Err(code) => return code,
    };
    let log = granted
        .split(|c| c.is_ascii_whitespace())
        .find_map(|w| w.strip_prefix(b"log="))
        .and_then(|what| Recorder::new(&log_fds, what));
    if log.is_none() {
        for fd in log_fds {
            let _ = io::close(fd);
        }
    }
    if action == b"validate" {
        return 0;
    }
    if o.edit {
        return sudoedit(&me, &d.secure_path, &argv[1..]);
    }
    // This process is `t` now: the environment, then the command.
    let envp = environment(&o, d, &me, &t, &text);
    let exec_argv: Vec<Vec<u8>> = if o.login || o.shell {
        if o.login {
            let _ = fs::chdir(&t.home);
        }
        let base = fs::basename(&sh).to_vec();
        let mut v = alloc::vec![if o.login { [b"-".as_slice(), &base].concat() } else { base }];
        v.extend(argv[1..].iter().cloned());
        v
    } else {
        o.command.clone()
    };
    if let Some(dir) = &o.chdir
        && let Err(e) = fs::chdir(dir)
    {
        return fail(1, format!("unable to change directory to {}: {e}", lossy(dir)));
    }
    let path = argv[0].clone();
    let from = o.close_from.unwrap_or(3);
    if o.background {
        if let Some(l) = &log {
            l.close();
        }
        match process::fork() {
            Ok(0) => {}
            Ok(_) => return 0,
            Err(e) => return fail(1, format!("unable to fork: {e}")),
        }
    } else if log.is_some() || timeout.is_some() || (d.use_pty && (0..3).any(term::isatty)) {
        return watch(Watch { path: &path, argv: &exec_argv, envp: &envp, from, use_pty: d.use_pty, log, timeout });
    }
    close_from(from);
    let e = process::execve(&path, &exec_argv, &envp);
    fail(1, format!("unable to execute {}: {e}", lossy(&path)))
}

/// Ask the broker, with the password if it wants one (`passwd_tries`
/// tries). The words after its `ok` and the descriptors it sent.
#[allow(clippy::too_many_arguments)]
fn ask(
    o: &Options,
    d: &Defaults,
    me: &Caller,
    target: &[u8],
    action: &[u8],
    text: &[u8],
    opts: &[u8],
    argv: &[Vec<u8>],
) -> Result<(Vec<u8>, Vec<i32>), i32> {
    let send = |pw: &[u8]| {
        let f = request_fields(target, pw, action, text, o.group.as_deref(), opts, argv);
        broker::request_fds(&f.iter().map(Vec::as_slice).collect::<Vec<_>>())
    };
    // First without a password: the broker may need none (a recent
    // authentication, or a nopassword rule).
    let mut r = send(b"");
    let mut tries = 0;
    while let Err(e) = &r {
        if e != "password required" || tries >= d.passwd_tries {
            break;
        }
        if o.nonint {
            return Err(fail(1, "a password is required"));
        }
        let p = o
            .prompt
            .as_deref()
            .map(|p| p.to_vec())
            .unwrap_or_else(|| [b"[sudo] password for ".as_slice(), &me.name, b": "].concat());
        let p = String::from(lossy(&p))
            .replace("%u", &String::from(lossy(&me.name)))
            .replace("%p", &String::from(lossy(&me.name)));
        let pw = if o.askpass {
            askpass(p.as_bytes()).map_err(|e| fail(1, e))?
        } else {
            match password(p.as_bytes(), o.stdin) {
                Some(pw) => pw,
                None => return Err(fail(1, "no password was given")),
            }
        };
        r = send(&pw);
        if r.as_ref().is_err_and(|e| e == "Authentication failure") {
            slate_rt::eprintln!("Sorry, try again.");
            r = Err(String::from("password required"));
        }
        tries += 1;
    }
    match r {
        Ok(g) => Ok(g),
        Err(e) if e == "password required" => {
            Err(fail(1, format!("{} incorrect password attempt{}", tries, if tries == 1 { "" } else { "s" })))
        }
        Err(e) => Err(fail(1, e)),
    }
}

/// sudo -l: what the policy lets this person run, or, with a command,
/// whether it may run (its full path printed if so).
fn list(o: &Options, policy: &broker::Policy, me: &Caller, cwd: &[u8]) -> i32 {
    let rules = &policy.rules;
    if let Some(c) = o.command.first() {
        let is_file = |p: &[u8]| fs::stat(p).is_ok_and(|s| s.is_file());
        let Some(path) = resolve(&policy.defaults.secure_path, cwd, c, &is_file) else {
            return fail(1, format!("{}: command not found", lossy(c)));
        };
        let mut argv = alloc::vec![path];
        argv.extend(o.command[1..].iter().cloned());
        let to = o.user.clone().unwrap_or_else(|| b"root".to_vec());
        if me.uid != 0 && rule_for(rules, me, &to, o.group.as_deref(), &argv).is_none() {
            return 1;
        }
        let mut line = argv.join(&b' ');
        line.push(b'\n');
        io::out(&line);
        return 0;
    }
    let mine = broker::run_rules_for(rules, &me.name, &|g| me.in_group(g));
    if mine.is_empty() && me.uid != 0 {
        return fail(1, format!("{} may not run commands with sudo", lossy(&me.name)));
    }
    let mut out = format!("User {} may run the following commands:\n", lossy(&me.name));
    if me.uid == 0 {
        out.push_str("    (ALL) ALL\n");
    }
    let who = |w: &[u8]| if w == b"*" { String::from("ALL") } else { String::from(lossy(w)) };
    for r in mine {
        let mut how = String::from(match r.auth {
            broker::Auth::None => " NOPASSWD:",
            broker::Auth::Own => "",
            broker::Auth::Target => " TARGETPW:",
        });
        for (on, tag) in [
            (r.tags.setenv, " SETENV:"),
            (r.tags.log_input == Some(true), " LOG_INPUT:"),
            (r.tags.log_output == Some(true), " LOG_OUTPUT:"),
        ] {
            if on {
                how.push_str(tag);
            }
        }
        let to: Vec<String> = r.to.iter().map(|t| who(t)).collect();
        let group = r.group.as_deref().map(|g| format!(" : {}", who(g))).unwrap_or_default();
        let what = r
            .commands
            .as_ref()
            .map_or_else(|| String::from("ALL"), |c| c.iter().map(|c| format!("{c}")).collect::<Vec<_>>().join(", "));
        out.push_str(&format!("    ({}{group}){how} {what}\n", to.join(", ")));
    }
    io::out(out.as_bytes());
    0
}

/// The command's environment: the policy's `env_keep` (all with -E or
/// `!env_reset`; the `--preserve-env` list too), the target's HOME, USER,
/// LOGNAME and SHELL, `secure_path` and SUDO_*.
fn environment(o: &Options, d: &Defaults, me: &Caller, t: &db::User, text: &[u8]) -> Vec<Vec<u8>> {
    let all = o.keep_env || !d.env_reset;
    let mut envp: Vec<Vec<u8>> = env::vars()
        .iter()
        .filter(|v| {
            let name = v.split(|&c| c == b'=').next().unwrap_or(v);
            if all { name != b"PATH" } else { d.keeps(v) || o.keep_vars.iter().any(|k| k.as_slice() == name) }
        })
        .cloned()
        .collect();
    let set = |envp: &mut Vec<Vec<u8>>, k: &[u8], v: &[u8]| {
        envp.retain(|e| !(e.starts_with(k) && e.get(k.len()) == Some(&b'=')));
        envp.push([k, b"=", v].concat());
    };
    set(&mut envp, b"HOME", &t.home);
    set(&mut envp, b"USER", &t.name);
    set(&mut envp, b"LOGNAME", &t.name);
    set(&mut envp, b"SHELL", &t.shell);
    set(&mut envp, b"PATH", &d.secure_path);
    set(&mut envp, b"SUDO_USER", &me.name);
    set(&mut envp, b"SUDO_UID", format!("{}", me.uid).as_bytes());
    set(&mut envp, b"SUDO_GID", format!("{}", me.gid).as_bytes());
    set(&mut envp, b"SUDO_COMMAND", text);
    envp
}

/// How the command runs with sudo watching it.
struct Watch<'a> {
    path: &'a [u8],
    argv: &'a [Vec<u8>],
    envp: &'a [Vec<u8>],
    from: i32,
    /// The standard descriptors that are terminals get a pseudo-terminal.
    use_pty: bool,
    log: Option<Recorder>,
    /// Seconds before the command is ended (`-T`).
    timeout: Option<u64>,
}

/// The `timing` stream of standard descriptor `fd`.
fn stream_of(fd: usize) -> Stream {
    [Stream::Stdin, Stream::Stdout, Stream::Stderr][fd]
}

/// Run the command and watch it. With `use_pty`, the standard
/// descriptors that were terminals become a pseudo-terminal of its own
/// (sudo's use_pty), and this process copies between it and the person's
/// terminal (raw while sudo is in the foreground), passing on the window
/// size; standard streams the I/O log records that aren't terminals go
/// through pipes this process copies. It passes on the signals it gets,
/// stops when the command stops, ends the command when its time is up,
/// and ends as it ends.
fn watch(w: Watch<'_>) -> i32 {
    let mut log = w.log;
    let ttys: Vec<i32> = if w.use_pty { (0..3).filter(|&fd| term::isatty(fd)).collect() } else { Vec::new() };
    let user_tty = ttys.first().copied();
    let saved = user_tty.and_then(|t| term::get(t).ok());
    let pty = match user_tty {
        Some(t) => match term::open_pty() {
            Ok((master, slave)) => {
                if let Some((rows, cols)) = term::size(t) {
                    let _ = term::set_size(master, rows, cols);
                }
                Some((master, slave))
            }
            Err(e) => return fail(1, format!("unable to allocate a pty: {e}")),
        },
        None => None,
    };
    // Recorded standard streams that aren't on the pty: a pipe each, as
    // (this process's end, the command's end).
    let mut pipes: [Option<(i32, i32)>; 3] = [None; 3];
    for (fd, slot) in pipes.iter_mut().enumerate() {
        if ttys.contains(&(fd as i32)) || !log.as_ref().is_some_and(|l| l.wants(stream_of(fd))) {
            continue;
        }
        let Ok((r, wr)) = process::pipe(fs::O_CLOEXEC) else { return fail(1, "unable to make a pipe") };
        *slot = Some(if fd == 0 { (wr, r) } else { (r, wr) });
    }
    let caught_signals =
        [signal::SIGCHLD, signal::SIGWINCH, signal::SIGINT, signal::SIGQUIT, signal::SIGTERM, signal::SIGHUP];
    for s in caught_signals {
        let _ = signal::set(s, Disposition::CatchInterrupt);
    }
    let child = match process::fork() {
        Ok(0) => {
            for s in caught_signals {
                let _ = signal::set(s, Disposition::Default);
            }
            if let Some((_, slave)) = &pty {
                let _ = process::setsid();
                let Ok(s) = fs::open(slave, fs::O_RDWR, 0) else { process::exit_now(1) };
                let _ = term::set_controlling(s);
                if let Some(t) = saved {
                    let _ = term::set(s, &t, false);
                }
                for &fd in &ttys {
                    let _ = process::dup2(s, fd);
                }
                if s > 2 {
                    let _ = io::close(s);
                }
            }
            for (fd, p) in pipes.iter().enumerate() {
                if let Some((_, theirs)) = p {
                    let _ = process::dup2(*theirs, fd as i32);
                }
            }
            if let Some(l) = &log {
                l.close();
            }
            close_from(w.from);
            let e = process::execve(w.path, w.argv, w.envp);
            slate_rt::eprintln!("sudo: unable to execute {}: {e}", lossy(w.path));
            process::exit_now(1);
        }
        Ok(pid) => pid,
        Err(e) => return fail(1, format!("unable to fork: {e}")),
    };
    for p in pipes.iter().flatten() {
        let _ = io::close(p.1);
    }
    // The command's standard input pipe is written without blocking: the
    // command may be busy writing what this process must read.
    if let Some((ours, _)) = pipes[0] {
        let _ = process::fcntl(ours, process::F_SETFL, fs::O_NONBLOCK as usize);
    }
    let mut master = pty.as_ref().map(|p| p.0);
    // On a pty, input is relayed only when standard input is the
    // terminal; otherwise the command has it as it was (or its pipe).
    let relay_in = ttys.contains(&0) || pipes[0].is_some();
    let foreground = || user_tty.is_some_and(|t| term::foreground(t).is_ok_and(|g| g == process::getpgrp()));
    let raw = |on: bool| {
        if let (Some(t), Some(fd)) = (saved, user_tty) {
            if on {
                let mut r = t;
                r.lflag &= !(term::ICANON | term::ECHO | term::ISIG | term::IEXTEN);
                r.iflag &= !(term::ICRNL | term::IXON);
                r.oflag &= !term::OPOST;
                r.cc[term::VMIN] = 1;
                r.cc[term::VTIME] = 0;
                let _ = term::set(fd, &r, false);
            } else {
                let _ = term::set(fd, &t, true);
            }
        }
    };
    if ttys.contains(&0) && foreground() {
        raw(true);
    }
    let deadline = w.timeout.map(|s| slate_rt::time::monotonic_ns().saturating_add(s.saturating_mul(1_000_000_000)));
    let mut killed_at: Option<u64> = None;
    let mut buf = alloc::vec![0u8; 4096];
    let mut stdin_open = relay_in;
    // Input read but not yet taken by the command's pipe.
    let mut pending: Vec<u8> = Vec::new();
    let mut status = None;
    let kill = |s: i32| {
        // The command leads its own group on a pty: end what it started too.
        let _ = process::kill(if pty.is_some() { -child } else { child }, s);
        if pty.is_some() {
            let _ = process::kill(child, s);
        }
    };
    loop {
        let in_pipe = pipes[0].map(|p| p.0);
        let mut fds = [
            io::PollFd { fd: master.unwrap_or(-1), events: io::POLLIN, revents: 0 },
            io::PollFd { fd: if stdin_open && pending.is_empty() { 0 } else { -1 }, events: io::POLLIN, revents: 0 },
            io::PollFd { fd: pipes[1].map_or(-1, |p| p.0), events: io::POLLIN, revents: 0 },
            io::PollFd { fd: pipes[2].map_or(-1, |p| p.0), events: io::POLLIN, revents: 0 },
            io::PollFd {
                fd: if pending.is_empty() { -1 } else { in_pipe.unwrap_or(-1) },
                events: io::POLLOUT,
                revents: 0,
            },
        ];
        // A signal between taking the caught ones and polling would wait
        // for the next event; the timeout bounds that.
        let ready = io::poll(&mut fds, if status.is_some() { 0 } else { 250 });
        let mut moved = false;
        let caught = signal::take();
        for s in [signal::SIGINT, signal::SIGQUIT, signal::SIGTERM, signal::SIGHUP] {
            if caught & (1 << s) != 0 {
                let _ = process::kill(child, s);
            }
        }
        if caught & (1 << signal::SIGWINCH) != 0
            && let (Some(m), Some(t)) = (master, user_tty)
            && let Some((rows, cols)) = term::size(t)
        {
            let _ = term::set_size(m, rows, cols);
            if let Some(l) = log.as_mut() {
                l.size(u32::from(rows), u32::from(cols));
            }
        }
        if let (Some(m), Some(t)) = (master, user_tty)
            && fds[0].revents & (io::POLLIN | io::POLLHUP | io::POLLERR) != 0
        {
            match io::read(m, &mut buf) {
                Ok(n) if n > 0 => {
                    let _ = io::write_all(t, &buf[..n]);
                    if let Some(l) = log.as_mut() {
                        l.data(Stream::TtyOut, &buf[..n]);
                    }
                    moved = true;
                }
                // The terminal's last holder is gone.
                _ if status.is_some() => master = None,
                _ => {}
            }
        }
        for fd in 1..3 {
            if let Some((ours, _)) = pipes[fd]
                && fds[fd + 1].revents & (io::POLLIN | io::POLLHUP | io::POLLERR) != 0
            {
                match io::read(ours, &mut buf) {
                    Ok(n) if n > 0 => {
                        let _ = io::write_all(fd as i32, &buf[..n]);
                        if let Some(l) = log.as_mut() {
                            l.data(stream_of(fd), &buf[..n]);
                        }
                        moved = true;
                    }
                    _ => {
                        let _ = io::close(ours);
                        pipes[fd] = None;
                    }
                }
            }
        }
        if fds[1].revents & (io::POLLIN | io::POLLHUP | io::POLLERR) != 0 {
            match io::read(0, &mut buf) {
                Ok(n) if n > 0 => {
                    if let Some(m) = master.filter(|_| ttys.contains(&0)) {
                        let _ = io::write_all(m, &buf[..n]);
                        if let Some(l) = log.as_mut() {
                            l.data(Stream::TtyIn, &buf[..n]);
                        }
                    } else {
                        if let Some(l) = log.as_mut() {
                            l.data(Stream::Stdin, &buf[..n]);
                        }
                        pending.extend_from_slice(&buf[..n]);
                    }
                    moved = true;
                }
                _ => stdin_open = false,
            }
        }
        if let Some(p) = in_pipe {
            if !pending.is_empty() && fds[4].revents & (io::POLLOUT | io::POLLERR | io::POLLHUP) != 0 {
                match io::write(p, &pending) {
                    Ok(n) => {
                        pending.drain(..n);
                        moved = true;
                    }
                    Err(slate_rt::errno::Errno::EAGAIN) => {}
                    // The command closed its input.
                    Err(_) => {
                        pending.clear();
                        stdin_open = false;
                    }
                }
            }
            if !stdin_open && pending.is_empty() {
                let _ = io::close(p);
                pipes[0] = None;
            }
        }
        if status.is_some() {
            // Drained: nothing more was ready.
            if !moved || ready.is_ok_and(|n| n == 0) {
                break;
            }
            continue;
        }
        if let Some(end) = deadline {
            let now = slate_rt::time::monotonic_ns();
            match killed_at {
                None if now >= end => {
                    slate_rt::eprintln!("sudo: command timed out");
                    kill(signal::SIGTERM);
                    killed_at = Some(now);
                }
                Some(at) if now.saturating_sub(at) >= KILL_AFTER_NS => {
                    kill(signal::SIGKILL);
                    killed_at = Some(u64::MAX / 2);
                }
                _ => {}
            }
        }
        if let Ok((pid, st)) = process::wait(child, process::WNOHANG | process::WUNTRACED)
            && pid == child
        {
            if process::stopped(st).is_some() {
                // The command stopped (^Z): stop too, and carry on after.
                if let Some(l) = log.as_mut() {
                    l.signal("SIGTSTP");
                }
                raw(false);
                let _ = signal::set(signal::SIGTSTP, Disposition::Default);
                let _ = process::kill(process::getpid(), signal::SIGSTOP);
                if ttys.contains(&0) && foreground() {
                    raw(true);
                }
                if let Some(l) = log.as_mut() {
                    l.signal("SIGCONT");
                }
                let _ = process::kill(child, signal::SIGCONT);
            } else {
                status = Some(st);
            }
        }
    }
    raw(false);
    if let Some(m) = pty.as_ref().map(|p| p.0) {
        let _ = io::close(m);
    }
    if let Some(l) = &log {
        l.close();
    }
    let st = status.unwrap_or(0);
    if let Some(sig) = process::signaled(st) {
        // End the way the command ended.
        let _ = signal::set(sig, Disposition::Default);
        let _ = process::kill(process::getpid(), sig);
    }
    process::exit_code(st)
}

/// A file sudoedit edits: its path, the caller's copy, and what it held
/// (`None`: it did not exist).
type Edited = (Vec<u8>, Vec<u8>, Option<Vec<u8>>);

/// sudoedit: copy each file (as the target, which this process is now)
/// into a temporary file the caller owns, run the caller's editor as the
/// caller on the copies, and write back the ones that changed.
fn sudoedit(me: &Caller, secure_path: &[u8], files: &[Vec<u8>]) -> i32 {
    let tmpdir: &[u8] = if fs::stat(b"/var/tmp").is_ok_and(|s| s.is_dir()) { b"/var/tmp" } else { b"/tmp" };
    let mut copies: Vec<Edited> = Vec::new();
    let cleanup = |copies: &[Edited]| {
        for (_, tmp, _) in copies {
            let _ = fs::unlink(tmp);
        }
    };
    for f in files {
        let dir = fs::dirname(f);
        if me.uid != 0 && fs::stat(dir).is_ok_and(|d| writable_by((d.uid, d.gid, d.mode), me.uid, &me.groups)) {
            cleanup(&copies);
            return fail(1, format!("{}: editing files in a writable directory is not permitted", lossy(f)));
        }
        let old = match fs::lstat(f) {
            Ok(st) if st.is_symlink() => {
                cleanup(&copies);
                return fail(1, format!("{}: editing symbolic links is not permitted", lossy(f)));
            }
            Ok(st) if !st.is_file() => {
                cleanup(&copies);
                return fail(1, format!("{}: not a regular file", lossy(f)));
            }
            Ok(_) => match fs::open(f, fs::O_RDONLY | fs::O_NOFOLLOW | fs::O_CLOEXEC, 0).and_then(|fd| {
                let d = io::read_to_end(fd);
                let _ = io::close(fd);
                d
            }) {
                Ok(d) => Some(d),
                Err(e) => {
                    cleanup(&copies);
                    return fail(1, format!("{}: {e}", lossy(f)));
                }
            },
            Err(_) => None,
        };
        let mut tmp = None;
        let mut why = slate_rt::errno::Errno::EEXIST;
        for _ in 0..16 {
            let mut r = [0u8; 8];
            let _ = process::random(&mut r);
            let tag: Vec<u8> =
                r.iter().map(|b| b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"[*b as usize % 52]).collect();
            let path = fs::join(tmpdir, &[fs::basename(f), b".", &tag].concat());
            match fs::open(&path, fs::O_WRONLY | fs::O_CREAT | fs::O_EXCL | fs::O_NOFOLLOW | fs::O_CLOEXEC, 0o600) {
                Ok(fd) => {
                    let w = io::write_all(fd, old.as_deref().unwrap_or_default());
                    let _ = io::close(fd);
                    match w.and_then(|()| fs::chown(&path, me.uid, me.gid)) {
                        Ok(()) => {
                            tmp = Some(path);
                            break;
                        }
                        Err(e) => why = e,
                    }
                    let _ = fs::unlink(&path);
                }
                Err(slate_rt::errno::Errno::EEXIST) => {}
                Err(e) => {
                    why = e;
                    break;
                }
            }
        }
        let Some(tmp) = tmp else {
            cleanup(&copies);
            return fail(1, format!("{}: unable to make a temporary copy: {why}", lossy(f)));
        };
        copies.push((f.clone(), tmp, old));
    }
    let var = |n: &[u8]| env::var(n).filter(|v| !v.is_empty());
    let Some(mut words) = editor(&var, &|p| fs::stat(p).is_ok_and(|s| s.is_file())) else {
        cleanup(&copies);
        return fail(1, "no editor found (set SUDO_EDITOR, VISUAL or EDITOR)");
    };
    let is_file = |p: &[u8]| fs::stat(p).is_ok_and(|s| s.is_file());
    let Some(path) = resolve(secure_path, b"/", &words[0], &is_file) else {
        cleanup(&copies);
        return fail(1, format!("{}: command not found", lossy(&words[0])));
    };
    words.extend(copies.iter().map(|(_, t, _)| t.clone()));
    let status = match process::fork() {
        Ok(0) => {
            // The editor runs as the caller, never as the target.
            let dropped = process::setgroups(&me.groups)
                .and_then(|()| process::setgid(me.gid))
                .and_then(|()| process::setuid(me.uid));
            if dropped.is_err() || process::getuid() != me.uid {
                process::exit_now(1);
            }
            let e = process::execve(&path, &words, env::vars());
            slate_rt::eprintln!("sudoedit: unable to run {}: {e}", lossy(&path));
            process::exit_now(1);
        }
        Ok(pid) => process::wait(pid, 0).map_or(1, |(_, st)| st),
        Err(e) => {
            cleanup(&copies);
            return fail(1, format!("unable to fork: {e}"));
        }
    };
    if status != 0 {
        cleanup(&copies);
        slate_rt::eprintln!("sudoedit: {} exited abnormally; nothing was changed", lossy(&path));
        return 1;
    }
    let mut code = 0;
    for (f, tmp, old) in &copies {
        // Read the copy back without following a link the caller made.
        let new = fs::open(tmp, fs::O_RDONLY | fs::O_NOFOLLOW | fs::O_CLOEXEC, 0).and_then(|fd| {
            let st = fs::fstat(fd);
            let d = st.and_then(|st| {
                if st.is_file() && st.uid == me.uid { io::read_to_end(fd) } else { Err(slate_rt::errno::Errno::EPERM) }
            });
            let _ = io::close(fd);
            d
        });
        let _ = fs::unlink(tmp);
        let new = match new {
            Ok(n) => n,
            Err(e) => {
                slate_rt::eprintln!("sudoedit: {}: {e}; not changed", lossy(f));
                code = 1;
                continue;
            }
        };
        if old.as_deref() == Some(&new[..]) || (old.is_none() && new.is_empty()) {
            slate_rt::eprintln!("sudoedit: {} unchanged", lossy(f));
            continue;
        }
        let w = fs::open(f, fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC | fs::O_NOFOLLOW | fs::O_CLOEXEC, 0o644).and_then(
            |fd| {
                let r = io::write_all(fd, &new);
                let _ = io::close(fd);
                r
            },
        );
        if let Err(e) = w {
            slate_rt::eprintln!("sudoedit: {}: {e}", lossy(f));
            code = 1;
        }
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<Vec<u8>> {
        s.iter().map(|a| a.as_bytes().to_vec()).collect()
    }

    #[test]
    fn options() {
        let o = parse(&args(&["-u", "bob", "-g", "audio", "-bC5", "id", "-u"])).unwrap();
        assert_eq!(o.user.as_deref(), Some(b"bob".as_slice()));
        assert_eq!(o.group.as_deref(), Some(b"audio".as_slice()));
        assert!(o.background && o.close_from == Some(5));
        assert_eq!(o.command, args(&["id", "-u"]));
        let o = parse(&args(&["--edit", "--close-from=7", "--group", "wheel", "/etc/motd"])).unwrap();
        assert!(o.edit && o.close_from == Some(7) && o.group.as_deref() == Some(b"wheel".as_slice()));
        assert_eq!(parse(&args(&["-x"])), None);
        assert_eq!(parse(&args(&["-C", "many", "id"])), None);
        assert_eq!(parse(&args(&["-u"])), None);
        assert_eq!(parse(&args(&["--", "-v"])).unwrap().command, args(&["-v"]));
        let o = parse(&args(&["-APD/tmp", "-T", "5m", "--preserve-env=A,B", "id"])).unwrap();
        assert!(o.askpass && o.preserve_groups && !o.keep_env);
        assert_eq!((o.chdir.as_deref(), o.timeout.as_deref()), (Some(b"/tmp".as_slice()), Some(b"5m".as_slice())));
        assert_eq!(o.keep_vars, args(&["A", "B"]));
        assert!(parse(&args(&["-h"])).unwrap().help);
        assert!(parse(&args(&["-h", "-l"])).unwrap().help);
        let o = parse(&args(&["-h", "box", "-l"])).unwrap();
        assert!(o.list && !o.help && o.host.as_deref() == Some(b"box".as_slice()));
        assert!(parse(&args(&["-r", "sysadm_r", "id"])).unwrap().selinux);
        assert!(parse(&args(&["--type=x", "id"])).unwrap().selinux);
    }

    #[test]
    fn timeouts() {
        assert_eq!(parse_timeout(b"90"), Some(90));
        assert_eq!(parse_timeout(b"5m"), Some(300));
        assert_eq!(parse_timeout(b"1h30m10s"), Some(5410));
        assert_eq!(parse_timeout(b"2d"), Some(172_800));
        assert_eq!(parse_timeout(b"0"), Some(0));
        assert_eq!(parse_timeout(b"5x"), None);
        assert_eq!(parse_timeout(b"m"), None);
        assert_eq!(parse_timeout(b"1h5"), None);
        assert_eq!(parse_timeout(b""), None);
    }

    #[test]
    fn commands_and_requests() {
        let exists = |p: &[u8]| p == b"/usr/bin/id" || p == b"/bin/ls";
        let path = b"/sbin:/bin:/usr/sbin:/usr/bin";
        assert_eq!(resolve(path, b"/home/a", b"id", &exists).as_deref(), Some(b"/usr/bin/id".as_slice()));
        assert_eq!(resolve(path, b"/home/a", b"./run.sh", &exists).as_deref(), Some(b"/home/a/./run.sh".as_slice()));
        assert_eq!(resolve(path, b"/", b"nothing", &exists), None);
        assert_eq!(resolve(b"/bin", b"/", b"id", &exists), None);
        let f = request_fields(
            b"root",
            b"pw",
            b"exec",
            b"id -u",
            Some(b"audio"),
            b"P W24x80",
            &args(&["/usr/bin/id", "", "-u"]),
        );
        assert_eq!(
            f,
            args(&["run", "root", "ppw", "exec", "id -u", "gaudio", "oP W24x80", "a/usr/bin/id", "a", "a-u"])
        );
        assert_eq!(request_fields(b"root", b"", b"validate", b"-", None, b"", &[])[5], b"g");
        // A word with a newline goes as hex; the log line shows it as \n.
        let f = request_fields(b"root", b"", b"exec", b"echo a\nb", None, b"", &args(&["/bin/echo", "a\nb"]));
        assert_eq!(f[4], b"echo a\\nb".to_vec());
        assert_eq!(f[8], b"h610a62".to_vec());
        assert_eq!(broker::decode_word(&f[8]), Some(b"a\nb".to_vec()));
    }

    #[test]
    fn edit_checks() {
        assert!(writable_by((1000, 0, 0o755), 1000, &[]));
        assert!(!writable_by((0, 0, 0o755), 1000, &[100]));
        assert!(writable_by((0, 100, 0o775), 1000, &[100]));
        assert!(writable_by((0, 0, 0o1777), 1000, &[]));
        let none = |_: &[u8]| None;
        let all = |_: &[u8]| true;
        assert_eq!(editor(&none, &|p| p == b"/bin/etch"), Some(args(&["/bin/etch"])));
        assert_eq!(editor(&none, &|_| false), None);
        let vars = |n: &[u8]| (n == b"EDITOR").then(|| b"nano -w".to_vec());
        assert_eq!(editor(&vars, &all), Some(args(&["nano", "-w"])));
    }
}
