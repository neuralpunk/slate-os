// SPDX-License-Identifier: MIT OR Apache-2.0

//! The privilege broker (ADR 0032). Slate programs are never set-user-ID
//! in the Slate domain, so `su` and `passwd` ask `slate-brokerd`, which
//! runs as root, checks the password and the policy, logs the decision,
//! and acts: for su it changes the asking process's credentials with the
//! kernel's `setids_of`; for passwd it writes the new hash.
//!
//! The protocol, over the abstract Unix socket `slate-broker`: the
//! request is newline-separated fields ending with an empty line
//! (`su`, target, password; or `passwd`, target, current password, new
//! password); the reply is one line, `ok` or `error: MESSAGE`. The broker
//! knows who asks from the socket's peer credentials.
//!
//! System approval (ADR 0037): `action`, NAME[, password] runs one of a
//! fixed set of system actions as root for a caller the policy lets become
//! root. With the password (Strata's own launcher, after its dialog) the
//! broker checks it at once. The account changes (`user=...`, ADR 0110)
//! carry the account's new password there instead, and are always
//! approved through the agent (or asked by root). Without, it asks the session's **approval
//! agent**: Strata registers with `agent` on a connection it keeps open,
//! and the broker accepts that only from `/bin/strata` in the Slate
//! domain. The broker sends the agent `ask`, action, requesting program,
//! its pid, the user, and an error from the last try (`-` for none); the
//! agent answers `password`, PASSWORD or `cancel`; `done` closes the
//! dialog. Three tries, then the request fails.
//!
//! Graphical login (ADR 0038): `login`, user, password[, `screen` or
//! `console`, how it was typed], accepted only from
//! the login screen (`/bin/strata-login` in the Slate domain, running as
//! the unprivileged `greeter`). With the right password the broker
//! answers `ok` and keeps the connection; when the login screen has let
//! go of the display it sends `start`, and a supervisor process starts
//! the user's login shell on the console in a session of its own (the
//! profile starts Strata), and sends `ended` when that ends. The login
//! screen, and the session's Strata (its power dialog, ADR 0110), may
//! also `action` restart or poweroff without a password, as anyone at the
//! machine's power button could. Accounts without a
//! password log in there too, as on the console. Any of Slate's own
//! programs (the Slate domain) may `action` `update=check`, which only
//! fetches the repositories' signed indexes (ADR 0112).
//!
//! The lock screen (ADR 0039): `check`, password answers whether it is the
//! caller's own password (a second's wait after a wrong one).
//!
//! Each request is answered in a child of its own (ADR 0039), so one
//! waiting on an approval dialog or a wrong password's delay holds up no
//! one else.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_coreutils::crypt;
use slate_rt::{fs, io, lossy, net, process, signal};

use crate::db;

/// The broker's socket (an abstract name).
pub const SOCKET: &[u8] = b"slate-broker";
pub const POLICY: &[u8] = b"/etc/slate/broker.conf";
const LOG: &[u8] = b"/var/log/slate-security.log";
/// Largest request accepted.
const MAX_REQUEST: usize = 4096;

/// Ask the broker; Ok on `ok`, Err with its message otherwise.
pub fn request(fields: &[&[u8]]) -> Result<(), String> {
    if fields.iter().any(|f| f.contains(&b'\n')) {
        return Err("a field contains a newline".into());
    }
    let fd = net::connect(SOCKET)
        .map_err(|e| format!("cannot reach the privilege broker, slate-brokerd ({e}); is it running?"))?;
    let mut msg = fields.join(&b'\n');
    msg.extend_from_slice(b"\n\n");
    let r = io::write_all(fd, &msg).map_err(|e| format!("talking to the privilege broker: {e}"));
    let reply = r.and_then(|()| io::read_to_end(fd).map_err(|e| format!("talking to the privilege broker: {e}")));
    let _ = io::close(fd);
    let reply = reply?;
    let line = reply.split(|&c| c == b'\n').next().unwrap_or(&[]);
    if line == b"ok" { Ok(()) } else { Err(String::from(lossy(line.strip_prefix(b"error: ").unwrap_or(line)))) }
}

/// Ask the broker for something it may answer with descriptors (sudo's
/// I/O log, ADR 0159): the words after `ok` and the descriptors.
pub fn request_fds(fields: &[&[u8]]) -> Result<(Vec<u8>, Vec<i32>), String> {
    if fields.iter().any(|f| f.contains(&b'\n')) {
        return Err("a field contains a newline".into());
    }
    let fd = net::connect(SOCKET)
        .map_err(|e| format!("cannot reach the privilege broker, slate-brokerd ({e}); is it running?"))?;
    let mut msg = fields.join(&b'\n');
    msg.extend_from_slice(b"\n\n");
    let talk = |e| format!("talking to the privilege broker: {e}");
    let mut reply = Vec::new();
    let mut fds = Vec::new();
    let r = io::write_all(fd, &msg).map_err(talk).and_then(|()| {
        let mut buf = [0u8; 512];
        loop {
            let (n, got) = net::recv_fds(fd, &mut buf).map_err(talk)?;
            fds.extend(got);
            if n == 0 {
                return Ok(());
            }
            reply.extend_from_slice(&buf[..n]);
        }
    });
    let _ = io::close(fd);
    let line = reply.split(|&c| c == b'\n').next().unwrap_or(&[]).to_vec();
    match (r, line.strip_prefix(b"ok")) {
        (Ok(()), Some(rest)) if rest.is_empty() || rest.starts_with(b" ") => Ok((rest.trim_ascii().to_vec(), fds)),
        (r, _) => {
            for fd in fds {
                let _ = io::close(fd);
            }
            r?;
            Err(String::from(lossy(line.strip_prefix(b"error: ").unwrap_or(&line))))
        }
    }
}

/// Which password a rule asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth {
    /// The target's (what su always asked).
    Target,
    /// The caller's own: administrators on a system without a root
    /// password (ADR 0035).
    Own,
    None,
}

/// A `run` line's tags (ADR 0159): whether the caller may keep their
/// environment, and I/O logging, which overrides the defaults.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tags {
    pub setenv: bool,
    pub log_input: Option<bool>,
    pub log_output: Option<bool>,
}

/// One policy line: `su FROM TO [nopassword | ownpassword]`, or `run`
/// with the same words for sudo (ADR 0058), tags, and maybe commands
/// (ADRs 0142, 0159); FROM is a list of user names, `%group`s and `*`, TO
/// of user names and `*` (either may be a `users` alias), for `run` maybe
/// with `:GROUP` (a group name or `*`) that `sudo -g` may choose.
#[derive(Debug, PartialEq, Eq)]
pub struct Rule {
    pub run: bool,
    pub from: Vec<Vec<u8>>,
    pub to: Vec<Vec<u8>>,
    pub group: Option<Vec<u8>>,
    pub auth: Auth,
    pub tags: Tags,
    /// The commands a `run` line allows; `None`, every command.
    pub commands: Option<Vec<Command>>,
}

/// A `run` rule's command, as sudoers(5) has them: an absolute path, or
/// a directory (ending in `/`) for the commands directly in it, or
/// `sudoedit` for files to edit; then the arguments, if listed, which
/// must be exactly those (`""` for none).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    pub path: Vec<u8>,
    pub args: Option<Vec<Vec<u8>>>,
}

impl Command {
    /// Whether this allows `argv` (its first word the command's absolute
    /// path, or `sudoedit` and the files' absolute paths).
    pub fn allows(&self, argv: &[Vec<u8>]) -> bool {
        let Some((path, args)) = argv.split_first() else { return false };
        let path_ok = match self.path.strip_suffix(b"/") {
            Some(_) => {
                path.strip_prefix(self.path.as_slice()).is_some_and(|rest| !rest.is_empty() && !rest.contains(&b'/'))
            }
            None => *path == self.path,
        };
        path_ok && self.args.as_ref().is_none_or(|a| a.as_slice() == args)
    }
}

impl core::fmt::Display for Command {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&lossy(&self.path))?;
        match &self.args {
            Some(a) if a.is_empty() => f.write_str(" \"\""),
            Some(a) => a.iter().try_for_each(|w| write!(f, " {}", lossy(w))),
            None => Ok(()),
        }
    }
}

/// The variables sudo keeps without `-E` (sudoers' `env_keep`): names,
/// or prefixes ending in `*`.
pub const ENV_KEEP: &[&[u8]] =
    &[b"TERM", b"COLORTERM", b"LANG", b"LC_*", b"TZ", b"DISPLAY", b"WAYLAND_DISPLAY", b"STRATA_*"];

/// The policy's `defaults` lines (ADR 0159), sudoers' Defaults by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Defaults {
    /// Start from a clean environment (`!env_reset`: keep it all but PATH).
    pub env_reset: bool,
    pub env_keep: Vec<Vec<u8>>,
    /// The PATH commands are found in and run with.
    pub secure_path: Vec<u8>,
    /// Anyone may keep their environment (`-E`).
    pub setenv: bool,
    /// How long a password is remembered, in seconds; `None`, for ever.
    pub timestamp_timeout: Option<i64>,
    pub passwd_tries: u32,
    pub log_input: bool,
    pub log_output: bool,
    /// Commands on a terminal get a pseudo-terminal of their own.
    pub use_pty: bool,
    /// Where `-D` may go: `*` anywhere; `None`, nowhere.
    pub runcwd: Option<Vec<u8>>,
    /// `-T` may set a command's timeout.
    pub user_command_timeouts: bool,
}

impl Default for Defaults {
    fn default() -> Defaults {
        Defaults {
            env_reset: true,
            env_keep: ENV_KEEP.iter().map(|v| v.to_vec()).collect(),
            secure_path: b"/sbin:/bin:/usr/sbin:/usr/bin".to_vec(),
            setenv: false,
            timestamp_timeout: Some(300),
            passwd_tries: 3,
            log_input: false,
            log_output: false,
            use_pty: true,
            runcwd: None,
            user_command_timeouts: false,
        }
    }
}

impl Defaults {
    /// Whether `env_keep` keeps the variable `var` (`NAME=value`).
    pub fn keeps(&self, var: &[u8]) -> bool {
        let name = var.split(|&c| c == b'=').next().unwrap_or(var);
        self.env_keep.iter().any(|k| match k.strip_suffix(b"*") {
            Some(prefix) => name.starts_with(prefix),
            None => name == k.as_slice(),
        })
    }

    /// Apply one setting (`name`, `!name`, `name=v`, `name+=v`,
    /// `name-=v`); false if it isn't one.
    fn set(&mut self, setting: &[u8]) -> bool {
        let s = setting.trim_ascii();
        if let Some(name) = s.strip_prefix(b"!") {
            return self.flag(name.trim_ascii(), false);
        }
        let Some(eq) = s.iter().position(|&c| c == b'=') else { return self.flag(s, true) };
        let (mut name, value) = (s[..eq].trim_ascii(), s[eq + 1..].trim_ascii());
        let value = value.strip_prefix(b"\"").and_then(|v| v.strip_suffix(b"\"")).unwrap_or(value);
        let op = match name.last() {
            Some(&c @ (b'+' | b'-')) => {
                name = name[..name.len() - 1].trim_ascii();
                c
            }
            _ => b'=',
        };
        let words = || value.split(|c| c.is_ascii_whitespace()).filter(|w| !w.is_empty()).map(<[u8]>::to_vec);
        match (name, op) {
            (b"env_keep", b'=') => self.env_keep = words().collect(),
            (b"env_keep", b'+') => self.env_keep.extend(words()),
            (b"env_keep", b'-') => {
                let gone: Vec<Vec<u8>> = words().collect();
                self.env_keep.retain(|k| !gone.contains(k));
            }
            (b"secure_path", b'=') if !value.is_empty() => self.secure_path = value.to_vec(),
            (b"runcwd", b'=') if !value.is_empty() => self.runcwd = Some(value.to_vec()),
            (b"timestamp_timeout", b'=') => match minutes(value) {
                Some(secs) => self.timestamp_timeout = (secs >= 0).then_some(secs),
                None => return false,
            },
            (b"passwd_tries", b'=') => match core::str::from_utf8(value).ok().and_then(|v| v.parse().ok()) {
                Some(n) if n > 0 => self.passwd_tries = n,
                _ => return false,
            },
            _ => return false,
        }
        true
    }

    fn flag(&mut self, name: &[u8], on: bool) -> bool {
        let slot = match name {
            b"env_reset" => &mut self.env_reset,
            b"setenv" => &mut self.setenv,
            b"log_input" => &mut self.log_input,
            b"log_output" => &mut self.log_output,
            b"use_pty" => &mut self.use_pty,
            b"user_command_timeouts" => &mut self.user_command_timeouts,
            b"runcwd" if !on => {
                self.runcwd = None;
                return true;
            }
            _ => return false,
        };
        *slot = on;
        true
    }
}

/// Minutes as sudoers writes `timestamp_timeout` (`5`, `2.5`, `-1`), in
/// seconds.
fn minutes(v: &[u8]) -> Option<i64> {
    let v = core::str::from_utf8(v).ok()?;
    let (neg, v) = match v.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, v),
    };
    let (whole, frac) = v.split_once('.').unwrap_or((v, ""));
    let whole: i64 = if whole.is_empty() { 0 } else { whole.parse().ok()? };
    let mut secs = whole.checked_mul(60)?;
    if !frac.is_empty() {
        if !frac.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let digits = &frac[..frac.len().min(6)];
        let f: i64 = digits.parse().ok()?;
        secs += f * 60 / 10i64.pow(digits.len() as u32);
    }
    Some(if neg { -secs.max(1) } else { secs })
}

/// The whole policy: its rules, in order, and its defaults.
#[derive(Debug, Default)]
pub struct Policy {
    pub rules: Vec<Rule>,
    pub defaults: Defaults,
}

/// Whether `w` names an alias: capitals, digits and `_`, starting with a
/// capital (sudoers(5)); `ALL` is a word of its own.
fn alias_name(w: &[u8]) -> bool {
    w.first().is_some_and(u8::is_ascii_uppercase)
        && w.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
        && w != b"ALL"
}

/// A line's words, with each comma a word of its own (`a,b` is `a` `,`
/// `b`).
fn words(line: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    for w in line.split(|c| c.is_ascii_whitespace()).filter(|w| !w.is_empty()) {
        let mut rest = w;
        while let Some(i) = rest.iter().position(|&c| c == b',') {
            if i > 0 {
                out.push(&rest[..i]);
            }
            out.push(&b","[..]);
            rest = &rest[i + 1..];
        }
        if !rest.is_empty() {
            out.push(rest);
        }
    }
    out
}

/// Split words at commas into items (an empty item is an error).
fn items<'a>(w: &[&'a [u8]]) -> Option<Vec<Vec<&'a [u8]>>> {
    let list: Vec<Vec<&[u8]>> = w.split(|x| *x == b",").map(<[&[u8]]>::to_vec).collect();
    (!list.iter().any(Vec::is_empty)).then_some(list)
}

/// The aliases defined so far: commands and users by name.
#[derive(Default)]
struct Aliases {
    commands: BTreeMap<Vec<u8>, Option<Vec<Command>>>,
    users: BTreeMap<Vec<u8>, Vec<Vec<u8>>>,
}

impl Aliases {
    /// A list of users, `%group`s and `*`, aliases expanded.
    fn users(&self, list: &[Vec<&[u8]>]) -> Option<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        for item in list {
            match item[..] {
                [w] if alias_name(w) => out.extend(self.users.get(w)?.iter().cloned()),
                [w] if w == b"ALL" => out.push(b"*".to_vec()),
                [w] => out.push(w.to_vec()),
                _ => return None,
            }
        }
        Some(out)
    }

    /// A list of commands, aliases expanded; `None` inside `Some` is
    /// every command (`ALL`, or an alias holding it).
    fn commands(&self, list: &[Vec<&[u8]>]) -> Option<Option<Vec<Command>>> {
        let mut out = Vec::new();
        for item in list {
            match item[..] {
                [w] if alias_name(w) => match self.commands.get(w)? {
                    Some(c) => out.extend(c.iter().cloned()),
                    None => return Some(None),
                },
                [b"ALL"] => return Some(None),
                [path, ref args @ ..] if path.starts_with(b"/") || path == b"sudoedit" => out.push(Command {
                    path: path.to_vec(),
                    args: match args {
                        [] => None,
                        [b"\"\""] => Some(Vec::new()),
                        a => Some(a.iter().map(|w| w.to_vec()).collect()),
                    },
                }),
                _ => return None,
            }
        }
        Some(Some(out))
    }
}

/// The policy's rules; without a file, anyone may become anyone whose
/// password they know (what su always allowed).
pub fn parse_policy(text: Option<&[u8]>) -> Vec<Rule> {
    read_policy_text(text).rules
}

/// The policy in /etc/slate/broker.conf.
pub fn read_policy() -> Policy {
    read_policy_text(fs::read_file(POLICY).ok().as_deref())
}

/// The policy in `text` (none: the default). Lines that don't parse are
/// ignored, as are settings `defaults` doesn't know.
pub fn read_policy_text(text: Option<&[u8]>) -> Policy {
    let Some(text) = text else {
        return Policy {
            rules: alloc::vec![Rule {
                run: false,
                from: alloc::vec![b"*".to_vec()],
                to: alloc::vec![b"*".to_vec()],
                group: None,
                auth: Auth::Target,
                tags: Tags::default(),
                commands: None,
            }],
            defaults: Defaults::default(),
        };
    };
    let mut policy = Policy::default();
    let mut aliases = Aliases::default();
    for line in text.split(|&c| c == b'\n') {
        let line = line.split(|&c| c == b'#').next().unwrap_or(&[]);
        let w = words(line);
        match w[..] {
            [b"defaults", ..] => {
                let rest = line.trim_ascii().strip_prefix(b"defaults").unwrap_or(&[]);
                for setting in split_settings(rest) {
                    let _ = policy.defaults.set(setting);
                }
            }
            [kind @ (b"commands" | b"users"), name, b"=", ref list @ ..] if alias_name(name) => {
                let Some(list) = items(list) else { continue };
                if kind == b"commands" {
                    if let Some(c) = aliases.commands(&list) {
                        aliases.commands.insert(name.to_vec(), c);
                    }
                } else if let Some(u) = aliases.users(&list) {
                    aliases.users.insert(name.to_vec(), u);
                }
            }
            _ => {
                if let Some(rule) = parse_rule(line, &aliases) {
                    policy.rules.push(rule);
                }
            }
        }
    }
    policy
}

/// A `defaults` line's settings: separated by commas outside quotes.
fn split_settings(s: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let (mut start, mut quoted) = (0, false);
    for (i, &c) in s.iter().enumerate() {
        match c {
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out.retain(|x| !x.trim_ascii().is_empty());
    out
}

/// A `su` or `run` line: FROM and TO are a word each (a list is
/// written without blanks, `ann,bob`); the rest is split at commas.
fn parse_rule(line: &[u8], aliases: &Aliases) -> Option<Rule> {
    let raw: Vec<&[u8]> = line.split(|c| c.is_ascii_whitespace()).filter(|w| !w.is_empty()).collect();
    let (run, from, to, rest) = match raw[..] {
        [b"su", from, to, ref rest @ ..] => (false, from, to, rest),
        [b"run", from, to, ref rest @ ..] => (true, from, to, rest),
        _ => return None,
    };
    let joined = rest.join(&b' ');
    let rest_words = words(&joined);
    let mut rest = rest_words.as_slice();
    let mut auth = Auth::Target;
    let mut tags = Tags::default();
    while let Some((word, more)) = rest.split_first() {
        match *word {
            b"nopassword" => auth = Auth::None,
            b"ownpassword" => auth = Auth::Own,
            b"setenv" if run => tags.setenv = true,
            b"log_input" if run => tags.log_input = Some(true),
            b"nolog_input" if run => tags.log_input = Some(false),
            b"log_output" if run => tags.log_output = Some(true),
            b"nolog_output" if run => tags.log_output = Some(false),
            _ => break,
        }
        rest = more;
    }
    let commands = match rest {
        [] => None,
        _ if run => aliases.commands(&items(rest)?)?,
        _ => return None,
    };
    let (to, group) = match to.iter().position(|&c| c == b':') {
        Some(i) if run && i + 1 < to.len() => (&to[..i], Some(to[i + 1..].to_vec())),
        Some(_) => return None,
        None => (to, None),
    };
    let list = |w: &[u8]| -> Option<Vec<Vec<u8>>> {
        let parts: Vec<Vec<&[u8]>> = w.split(|&c| c == b',').map(|x| alloc::vec![x]).collect();
        if parts.iter().any(|p| p[0].is_empty()) {
            return None;
        }
        aliases.users(&parts)
    };
    let from = list(from)?;
    let to = list(to)?;
    // A target is a user, or anyone: not a group.
    if to.iter().any(|t| t.starts_with(b"%")) {
        return None;
    }
    Some(Rule { run, from, to, group, auth, tags, commands })
}

fn from_matches(rule: &Rule, from: &[u8], in_group: &dyn Fn(&[u8]) -> bool) -> bool {
    rule.from.iter().any(|f| match f.strip_prefix(b"%") {
        Some(group) => in_group(group),
        None => f == b"*" || f == from,
    })
}

fn to_matches(rule: &Rule, to: &[u8]) -> bool {
    rule.to.iter().any(|t| t == b"*" || t == to)
}

/// Whether `from` (a member of the groups `in_group` accepts) may become
/// `to`, and with which password. The first matching rule decides.
pub fn su_allowed(rules: &[Rule], from: &[u8], in_group: &dyn Fn(&[u8]) -> bool, to: &[u8]) -> Option<Auth> {
    rules.iter().find(|r| !r.run && from_matches(r, from, in_group) && to_matches(r, to)).map(|r| r.auth)
}

/// What sudo asks for: the user to become, maybe a group (`-g`), and
/// the command (its absolute path first, or `sudoedit` and the files).
#[derive(Debug)]
pub struct RunRequest<'a> {
    pub to: &'a [u8],
    pub group: Option<&'a [u8]>,
    pub argv: &'a [Vec<u8>],
}

/// The rule that lets `from` run `req` with sudo: the first `run` line
/// whose FROM, TO, group and commands all match. A group with no `:GROUP`
/// in the rule must be one of the target's own (`target_in`).
pub fn run_allowed<'a>(
    rules: &'a [Rule],
    from: &[u8],
    in_group: &dyn Fn(&[u8]) -> bool,
    req: &RunRequest<'_>,
    target_in: &dyn Fn(&[u8]) -> bool,
) -> Option<&'a Rule> {
    rules.iter().find(|r| {
        r.run
            && from_matches(r, from, in_group)
            && to_matches(r, req.to)
            && req.group.is_none_or(|g| match &r.group {
                Some(rg) => rg == b"*" || rg == g,
                None => target_in(g),
            })
            && r.commands.as_ref().is_none_or(|c| c.iter().any(|c| c.allows(req.argv)))
    })
}

/// The `run` rules for `from`, as `sudo -l` lists them.
pub fn run_rules_for<'a>(rules: &'a [Rule], from: &[u8], in_group: &dyn Fn(&[u8]) -> bool) -> Vec<&'a Rule> {
    rules.iter().filter(|r| r.run && from_matches(r, from, in_group)).collect()
}

/// sudo's memory of a recent authentication (ADR 0058): a file per user
/// and terminal session in /run, its age the time since.
/// How long it lasts is the policy's `timestamp_timeout`.
const TIMESTAMPS: &[u8] = b"/run/slate-brokerd/ts";

fn timestamp_path(uid: u32, sid: i32) -> Vec<u8> {
    format!("/run/slate-brokerd/ts/{uid}.{sid}").into_bytes()
}

fn timestamp_fresh(uid: u32, sid: i32, timeout: Option<i64>) -> bool {
    sid > 0
        && fs::exists(format!("/proc/{sid}").as_bytes())
        && fs::stat(&timestamp_path(uid, sid)).is_ok_and(|s| {
            let age = slate_rt::time::unix() - s.mtime;
            age >= 0 && timeout.is_none_or(|t| age < t)
        })
}

fn touch_timestamp(uid: u32, sid: i32) {
    if sid <= 0 {
        return;
    }
    let _ = fs::mkdir(b"/run/slate-brokerd", 0o700);
    let _ = fs::mkdir(TIMESTAMPS, 0o700);
    let _ = fs::write_file(&timestamp_path(uid, sid), b"", 0o600);
    let _ = fs::set_times(&timestamp_path(uid, sid), None, None, true);
}

/// The session of process `pid` (proc(5) stat field 6).
fn session_of(pid: i32) -> i32 {
    let Ok(stat) = fs::read_file(format!("/proc/{pid}/stat").as_bytes()) else { return 0 };
    let Some(close) = stat.iter().rposition(|&c| c == b')') else { return 0 };
    let f: Vec<&[u8]> = stat[close + 2..].split(|&c| c == b' ').collect();
    f.get(3).and_then(|s| core::str::from_utf8(s).ok()?.parse().ok()).unwrap_or(0)
}

/// Whether `password` matches `user`'s; an empty hash matches only when
/// `empty_ok`: for logging in at the machine (the login and lock screens)
/// and checks of the caller's own account, never for becoming someone
/// else, which takes a `nopassword` line in the policy (ADR 0119).
fn password_ok(user: &db::User, password: &[u8], empty_ok: bool) -> bool {
    let hash = db::hash_of(user).unwrap_or_default();
    if hash.is_empty() { empty_ok } else { crypt::verify(password, &hash) }
}

/// Append a decision to the security log.
fn log(line: &str) {
    let tm = slate_rt::tz::localtime(slate_rt::time::unix());
    let mut stamp = String::new();
    slate_rt::time::format(&tm, "%Y-%m-%d %H:%M:%S", &mut stamp);
    let _ = fs::mkdir(b"/var/log", 0o755);
    use slate_rt::fs::{O_APPEND, O_CLOEXEC, O_CREAT, O_WRONLY};
    if let Ok(fd) = fs::open(LOG, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0o600) {
        let _ = io::write_all(fd, format!("{stamp} slate-brokerd: {line}\n").as_bytes());
        let _ = io::close(fd);
    }
}

fn name_of(uid: u32) -> Vec<u8> {
    db::user_by_uid(uid).map_or_else(|| format!("uid {uid}").into_bytes(), |u| u.name)
}

/// The system actions `action` can run, and their commands.
pub const ACTIONS: &[(&str, &[&str])] = &[
    ("restart", &["/bin/reboot"]),
    ("poweroff", &["/bin/poweroff"]),
    ("rollback", &["/bin/slate-update", "rollback"]),
    // `timezone=ZONE`: the broker writes /etc/slate/timezone itself.
    ("timezone", &[]),
    // `network=CARD SETTINGS...` (ADR 0054): one card's section of
    // /etc/slate/network, then netd restarts; `network=CARD default`
    // takes the card's section away (it follows `[*]` again).
    ("network", &[]),
    // `desktop=add` or `desktop=remove` (ADR 0102): Strata, the
    // `slate-desktop` package, from the system's own repository (ADR 0071).
    ("desktop", &[]),
    // `graphics=full` or `graphics=slate` (ADR 0173): AMD's firmware, the
    // `slate-firmware-gpu` package, from the system's own repository, or
    // taken away again; either way from the next start.
    ("graphics", &[]),
    // `user=CHANGE` (ADR 0110): an account added or removed, made an
    // administrator or not, or its password changed.
    ("user", &[]),
    // `compat=on` or `compat=off` (ADR 0110): Linux compatibility mode,
    // as slate-compat changes it.
    ("compat", &[]),
    // `disk=WORDS` (ADR 0112): a disk's partition table, a partition or a
    // file system, as Disks asks; slate-disk does it (slate_diskutil).
    ("disk", &[]),
    // `update=check` fetches the repositories' signed indexes, granted to
    // Slate's own programs without asking; `update=install` installs what
    // they offer as a new system (ADR 0112, the Software Updater).
    ("update", &[]),
    // `end=PID TERM|KILL` (ADR 0112): end another account's process, as
    // the System Monitor asks.
    ("end", &[]),
    // `browser=setup` (ADR 0115): what a web browser from Flathub needs,
    // as the Web Browser asks: Linux compatibility on, and the Linux
    // runtime with Flatpak.
    ("browser", &[]),
    // `flatpak=install [--from REMOTE] APP...`, `flatpak=remove APP...` or
    // `flatpak=update [APP...]` (ADR 0114's addendum): apps for everyone,
    // in the runtime's system installation, as slate-flatpak --system.
    ("flatpak", &[]),
    // `firewall=on`, `firewall=off`, `firewall=allow tcp|udp PORT` or
    // `firewall=deny tcp|udp PORT` (ADR 0134): as slate-firewall does it,
    // from Settings' Security page.
    ("firewall", &[]),
];

/// `firewall=`'s words, checked: what slate-firewall is to be given.
pub fn parse_firewall(words: &str) -> Result<Vec<&str>, String> {
    let w: Vec<&str> = words.split(' ').collect();
    match w.as_slice() {
        ["on" | "off"] => Ok(w),
        ["allow" | "deny", "tcp" | "udp", port] if port.parse::<u16>().is_ok_and(|p| p != 0) => Ok(w),
        _ => Err(format!("firewall={words}: on, off, or allow or deny, tcp or udp and a port")),
    }
}

/// The Linux runtime (ADR 0038) and what the browser needs in it.
const RUNTIME_NEEDS: &[&str] = &[
    "/var/lib/slate/linux/usr/bin/flatpak",
    "/var/lib/slate/linux/usr/bin/sway",
    "/var/lib/slate/linux/usr/bin/dbus-daemon",
];

/// `browser=setup`: each step only if it is missing.
fn browser_setup() -> Result<(), String> {
    let compat = fs::read_file(b"/proc/sys/slate/linux_compat").is_ok_and(|t| t.first() == Some(&b'1'));
    if !compat {
        run_saying(&["/bin/slate-compat", "on", "--yes"])?;
    }
    if !RUNTIME_NEEDS.iter().all(|p| fs::exists(p.as_bytes())) {
        run_saying(&["/bin/slate-linux", "setup", "flatpak"])?;
    }
    // Setup said it was done: what the browser needs must be there now,
    // or the next step fails with less to go on.
    for p in RUNTIME_NEEDS {
        if let Err(e) = fs::lstat(p.as_bytes()) {
            let said = format!("the Linux runtime was set up, but {p} isn't there ({e})");
            slate_rt::eprintln!("slate-brokerd: browser=setup: {said}");
            return Err(said);
        }
    }
    Ok(())
}

/// `flatpak=WORDS`: what slate-flatpak --system does for the broker
/// (it checks them again): install (from Flathub, or `--from` a remote
/// the system installation has), remove or update, of application IDs
/// (reverse DNS, as flatpak names them). Remotes are root's to add.
pub fn parse_flatpak(words: &str) -> Result<Vec<&str>, String> {
    let w: Vec<&str> = words.split(' ').collect();
    let id_ok = |id: &str| {
        let name = id.split("//").next().unwrap_or("");
        name.split('.').count() >= 3
            && name
                .split('.')
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            && id.chars().all(|c| c.is_ascii_graphic())
    };
    let ids = match w[..] {
        ["install", "--from", remote, ref ids @ ..] if !ids.is_empty() => {
            let ok = !remote.is_empty()
                && !remote.starts_with('-')
                && remote.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
            if !ok {
                return Err(format!("{remote}: not a remote's name"));
            }
            ids
        }
        ["install" | "remove", ref ids @ ..] if !ids.is_empty() => ids,
        ["update", ref ids @ ..] => ids,
        _ => return Err("flatpak=install [--from REMOTE] APP... | remove APP... | update [APP...]".into()),
    };
    if let Some(bad) = ids.iter().find(|i| !id_ok(i)) {
        return Err(format!("{bad}: not a Flatpak application ID"));
    }
    Ok(w)
}

/// `end=PID TERM|KILL`: the process and the signal (signal(7): SIGTERM
/// 15, SIGKILL 9).
pub fn parse_end(words: &str) -> Result<(i32, i32), String> {
    let (pid, sig) = words.split_once(' ').ok_or("end=PID TERM|KILL")?;
    let pid: i32 = pid.parse().map_err(|_| format!("{pid}: not a process number"))?;
    let sig = match sig {
        "TERM" => 15,
        "KILL" => 9,
        _ => return Err(format!("{sig}: TERM or KILL")),
    };
    if pid <= 1 {
        return Err("init can't be ended".into());
    }
    Ok((pid, sig))
}

/// An account change from Settings (ADR 0110).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UserChange {
    /// `add NAME admin|standard FULL NAME...`; the password comes apart.
    Add { name: String, admin: bool, full: String },
    /// `remove NAME`: the account and its home.
    Remove(String),
    /// `admin NAME` or `standard NAME`: in the wheel group or not.
    Admin(String, bool),
    /// `password NAME`; the password comes apart.
    Password(String),
    /// `name NAME FULL NAME...`: the account's full name (ADR 0110's
    /// second addendum).
    Name(String, String),
    /// `expire NAME`: a new password at the next login (chage -d 0).
    Expire(String),
    /// `unblock NAME`: a picture someone else left under the caller's
    /// own name in the faces folder taken away (the folder is sticky).
    Unblock(String),
}

impl UserChange {
    pub fn name(&self) -> &str {
        match self {
            UserChange::Add { name, .. } => name,
            UserChange::Remove(n)
            | UserChange::Admin(n, _)
            | UserChange::Password(n)
            | UserChange::Name(n, _)
            | UserChange::Expire(n)
            | UserChange::Unblock(n) => n,
        }
    }

    /// Whether it carries the account's new password.
    pub fn needs_password(&self) -> bool {
        matches!(self, UserChange::Add { .. } | UserChange::Password(_))
    }
}

/// A full name fit for passwd(5)'s comment field: no `:` (the field
/// separator), `,` (the GECOS subfields) or control characters.
fn valid_full_name(s: &str) -> bool {
    s.chars().count() <= 64 && !s.chars().any(|c| c == ':' || c == ',' || c.is_control())
}

/// Read a `user=` argument.
pub fn parse_user_change(words: &str) -> Result<UserChange, String> {
    let mut w = words.splitn(3, ' ');
    let (op, name, rest) = (w.next().unwrap_or(""), w.next().unwrap_or(""), w.next().unwrap_or(""));
    if !crate::accounts::valid_name(name.as_bytes()) {
        return Err(format!("{name:?} is not a valid user name"));
    }
    let name = String::from(name);
    let full = |s: &str| -> Result<String, String> {
        let s = s.trim();
        if valid_full_name(s) { Ok(String::from(s)) } else { Err(String::from("the full name can't hold : or ,")) }
    };
    match op {
        "add" => {
            let (kind, rest) = rest.split_once(' ').unwrap_or((rest, ""));
            let admin = match kind {
                "admin" => true,
                "standard" => false,
                _ => return Err("user=add: admin or standard".into()),
            };
            Ok(UserChange::Add { name, admin, full: full(rest)? })
        }
        "remove" if rest.is_empty() => Ok(UserChange::Remove(name)),
        "admin" | "standard" if rest.is_empty() => Ok(UserChange::Admin(name, op == "admin")),
        "password" if rest.is_empty() => Ok(UserChange::Password(name)),
        "name" => Ok(UserChange::Name(name, full(rest)?)),
        "expire" if rest.is_empty() => Ok(UserChange::Expire(name)),
        "unblock" if rest.is_empty() => Ok(UserChange::Unblock(name)),
        _ => Err(format!("user={words}: add, remove, admin, standard, password, name, expire or unblock")),
    }
}

/// Check an account change against the accounts there are, for `caller`:
/// only people's accounts (from UID_MIN) change, and nobody removes their
/// own account or administrator rights (another administrator must).
fn check_user_change(c: &UserChange, caller: &[u8]) -> Result<(), String> {
    let name = c.name();
    let user = db::user_by_name(name.as_bytes());
    let people = crate::accounts::Defs::load().uid_min;
    match (c, &user) {
        (UserChange::Add { .. }, Some(_)) => return Err(format!("{name} already has an account")),
        (UserChange::Add { .. }, None) => return Ok(()),
        (_, None) => return Err(format!("{name} has no account")),
        (_, Some(u)) if u.uid < people => return Err(format!("{name} is not a person's account")),
        _ => {}
    }
    if matches!(c, UserChange::Remove(_) | UserChange::Admin(_, false)) && name.as_bytes() == caller {
        return Err("another administrator must do that for your own account".into());
    }
    if matches!(c, UserChange::Unblock(_)) && name.as_bytes() != caller {
        return Err("only for your own picture".into());
    }
    Ok(())
}

/// Make an account change; `password` is the account's new one.
fn change_user(c: &UserChange, password: &[u8]) -> Result<(), String> {
    match c {
        UserChange::Add { name, admin, full } => {
            let mut cmd = alloc::vec!["/sbin/useradd", "-m", "-c", full.as_str()];
            if *admin {
                cmd.extend(["-G", "wheel"]);
            }
            cmd.push(name.as_str());
            run_action(&cmd)?;
            crate::accounts::set_password(name.as_bytes(), password)
        }
        UserChange::Remove(name) => run_action(&["/sbin/userdel", "-r", name]),
        UserChange::Admin(name, true) => run_action(&["/bin/gpasswd", "-a", name, "wheel"]),
        UserChange::Admin(name, false) => run_action(&["/bin/gpasswd", "-d", name, "wheel"]),
        UserChange::Password(name) => crate::accounts::set_password(name.as_bytes(), password),
        UserChange::Name(name, full) => run_action(&["/sbin/usermod", "-c", full, name]),
        UserChange::Expire(name) => run_action(&["/bin/chage", "-d", "0", name]),
        UserChange::Unblock(name) => unblock_face(name),
    }
}

/// Take away `NAME.png` in the faces folder if someone other than NAME
/// owns it (a picture under one's own name is one's own business).
fn unblock_face(name: &str) -> Result<(), String> {
    let Some(u) = db::user_by_name(name.as_bytes()) else { return Err(format!("{name} has no account")) };
    let mut path = FACES.to_vec();
    path.extend_from_slice(format!("/{name}.png").as_bytes());
    match fs::lstat(&path) {
        Ok(st) if st.uid != u.uid => fs::unlink(&path).map_err(|e| format!("{e}")),
        _ => Ok(()),
    }
}

const NETWORK: &[u8] = b"/etc/slate/network";

/// A `network=` argument: a card's settings as words, one space apart.
fn network_card(words: &str) -> Result<slate_netconf::Card, String> {
    let words: Vec<&str> = words.split(' ').collect();
    // `CARD default`: the name checked as a card's.
    if let [name, "default"] = words.as_slice() {
        if *name == "*" {
            return Err("every card has its settings already".into());
        }
        return slate_netconf::Card::from_words(&[name, "dhcp"]).map_err(|e| e.0);
    }
    slate_netconf::Card::from_words(&words).map_err(|e| e.0)
}

/// Change one card's section of /etc/slate/network, or take it away (the
/// rest of the file stays), then restart netd.
fn set_network(words: &str) -> Result<(), String> {
    let card = network_card(words)?;
    let old = fs::read_file(NETWORK).map(|t| String::from(lossy(&t))).unwrap_or_default();
    let text = if words.ends_with(" default") {
        slate_netconf::remove_card(&old, &card.name)
    } else {
        slate_netconf::set_card(&old, &card)
    };
    let mut tmp = NETWORK.to_vec();
    tmp.extend_from_slice(b".new");
    fs::write_file(&tmp, text.as_bytes(), 0o644).map_err(|e| format!("{e}"))?;
    fs::rename(&tmp, NETWORK).map_err(|e| format!("{e}"))?;
    run_action(&["/bin/service", "netd", "restart"])
}

/// Set the system's time zone to `zone`, a name in the zone table
/// (slate-rt's tz, ADR 0039); the file is replaced whole.
fn set_timezone(zone: &str) -> Result<(), String> {
    let mut tmp = slate_rt::tz::SETTING.to_vec();
    tmp.extend_from_slice(b".new");
    fs::write_file(&tmp, format!("{zone}\n").as_bytes(), 0o644).map_err(|e| format!("{e}"))?;
    fs::rename(&tmp, slate_rt::tz::SETTING).map_err(|e| format!("{e}"))
}

/// Whether `zone` is in the zone table.
fn known_zone(zone: &str) -> bool {
    fs::read_file(slate_rt::tz::ZONES).is_ok_and(|z| slate_rt::tz::lookup(&z, zone).is_some())
}

/// The session's approval agent.
#[derive(Debug)]
struct Agent {
    fd: i32,
}

/// SIGPIPE back to its default (the broker ignores it) in a child before
/// it runs a program or a session (an ignored signal stays ignored across execve(2)).
fn pipe_default() {
    let _ = signal::set(signal::SIGPIPE, signal::Disposition::Default);
}

/// A field of /proc/<pid>/status.
fn status_field(pid: i32, field: &str) -> Option<String> {
    let status = fs::read_file(format!("/proc/{pid}/status").as_bytes()).ok()?;
    let text = String::from(lossy(&status));
    text.lines().find_map(|l| l.strip_prefix(field).and_then(|r| r.strip_prefix(':')).map(|v| String::from(v.trim())))
}

/// A terminal window's login record (ADR 0143), as utempter does for
/// terminal programs elsewhere: `pts/N` must be the caller's, and `pid`
/// the caller's process on it. utmp and wtmp, not lastlog: no one
/// logged in.
fn record(f: &[&[u8]], uid: u32, caller: &[u8]) -> Result<(), String> {
    let pid_of = |p: &[u8]| core::str::from_utf8(p).ok().and_then(|s| s.parse::<i32>().ok()).filter(|&p| p > 0);
    match f {
        [b"login", line, pid] => {
            let pid = pid_of(pid).ok_or("bad request")?;
            let n = line.strip_prefix(b"pts/").filter(|n| !n.is_empty() && n.iter().all(u8::is_ascii_digit));
            n.ok_or("only a pseudo-terminal's record")?;
            let st = fs::stat(&[b"/dev/".as_slice(), line].concat()).map_err(|e| format!("{}: {e}", lossy(line)))?;
            if uid != 0 && st.uid != uid {
                return Err("not your terminal".into());
            }
            // The process: the caller's, on that terminal (proc(5)'s
            // stat field 7, tty_nr).
            let stat = fs::read_file(format!("/proc/{pid}/stat").as_bytes()).map_err(|_| "no such process")?;
            let after = stat.iter().rposition(|&c| c == b')').map_or(&stat[..], |i| &stat[i + 1..]);
            let tty: Option<u64> = after
                .split(|c| c.is_ascii_whitespace())
                .filter(|w| !w.is_empty())
                .nth(4)
                .and_then(|w| core::str::from_utf8(w).ok()?.parse().ok());
            let owner = status_field(pid, "Uid").and_then(|u| u.split_whitespace().next()?.parse::<u32>().ok());
            if tty != Some(st.rdev) || (uid != 0 && owner != Some(uid)) {
                return Err("not your process on that terminal".into());
            }
            let e = slate_rt::utmp::Entry::new(slate_rt::utmp::USER_PROCESS, pid, line, caller, b"strata");
            slate_rt::utmp::write_utmp(&e);
            slate_rt::utmp::append_wtmp(&e);
            Ok(())
        }
        [b"logout", pid] => {
            let pid = pid_of(pid).ok_or("bad request")?;
            let mine = slate_rt::utmp::read(slate_rt::utmp::UTMP)
                .iter()
                .any(|r| r.pid == pid && r.kind == slate_rt::utmp::USER_PROCESS && (uid == 0 || r.user == caller));
            if mine {
                slate_rt::utmp::logout(pid);
            }
            Ok(())
        }
        _ => Err("bad request".into()),
    }
}

/// Only the login screen, from the system tree and in the Slate domain,
/// may log people in.
fn may_be_greeter(pid: i32) -> bool {
    let exe = fs::readlink(format!("/proc/{pid}/exe").as_bytes()).unwrap_or_default();
    exe == b"/bin/strata-login" && status_field(pid, "Domain").as_deref() == Some("slate")
}

/// SIGHUP (signal(7)), for what is left of an ended session.
const SIGHUP: i32 = 1;

/// `login`: check `user`'s password for the login screen; on success
/// answer `ok` on `fd` and leave a supervisor to start the session.
fn login(f: &[&[u8]], fd: i32) -> Result<(), String> {
    // An expired password comes back with a new one (`n` first: never
    // empty), changed before the session starts.
    let (name, password, screen, new) = match f[..] {
        [_, name, password] => (name, password, true, None),
        [_, name, password, how @ (b"screen" | b"console")] => (name, password, how == b"screen", None),
        [_, name, password, how @ (b"screen" | b"console"), new] => {
            (name, password, how == b"screen", Some(new.strip_prefix(b"n").ok_or("bad request")?))
        }
        _ => return Err("bad request".into()),
    };
    let what = format!("login: {}", lossy(name));
    let user = db::user_by_name(name).filter(|u| password_ok(u, password, true));
    let Some(u) = user else {
        log(&format!("{what}: denied (wrong password)"));
        slate_rt::time::sleep_ns(1_000_000_000);
        return Err("Login incorrect".into());
    };
    match crate::accounts::ageing(&u.name) {
        crate::accounts::Ageing::Refused(msg) => {
            log(&format!("{what}: denied (account expired)"));
            return Err(msg.into());
        }
        crate::accounts::Ageing::MustChange => match new {
            None => {
                log(&format!("{what}: password expired, a new one asked for"));
                return Err(EXPIRED.into());
            }
            Some([]) => return Err("The new password is empty.".into()),
            Some(n) if n == password => return Err("The new password must differ from the old one.".into()),
            Some(n) => set_password(&format!("{what}: expired password"), &u, password, n, false)?,
        },
        _ => {}
    }
    if u.uid != 0 && crate::nologin().is_some() {
        log(&format!("{what}: denied (nologin)"));
        return Err("Logins are not allowed now.".into());
    }
    log(&format!("{what}: granted"));
    io::write_all(fd, b"ok\n").map_err(|e| format!("{e}"))?;
    match process::fork() {
        Ok(0) => {
            pipe_default();
            process::exit_now(supervise(fd, &u, &what, screen))
        }
        Ok(_) => Ok(()),
        Err(e) => Err(format!("{e}")),
    }
}

/// The supervisor of a graphical login: wait for `start`, run the session,
/// say `ended`.
fn supervise(fd: i32, u: &db::User, what: &str, screen: bool) -> i32 {
    if read_message(fd, 30_000).as_deref() != Some(b"start") {
        return 1;
    }
    let session = match process::fork() {
        Ok(0) => {
            pipe_default();
            process::exit_now(crate::session_on_console(u, screen))
        }
        Ok(pid) => pid,
        Err(_) => return 1,
    };
    let _ = process::wait(session, 0);
    slate_rt::utmp::logout(session);
    // The session's leftovers go with it.
    let _ = process::kill(-session, SIGHUP);
    log(&format!("{what}: session ended"));
    let _ = io::write_all(fd, b"ended\n");
    0
}

/// Only Strata, from the system tree and in the Slate domain, may be the
/// approval agent: it alone sees the passwords people type into it.
fn may_be_agent(pid: i32) -> bool {
    let exe = fs::readlink(format!("/proc/{pid}/exe").as_bytes()).unwrap_or_default();
    exe == b"/bin/strata" && status_field(pid, "Domain").as_deref() == Some("slate")
}

/// The Software Updater, from the system tree and in the Slate domain.
fn may_be_updater(pid: i32) -> bool {
    let exe = fs::readlink(format!("/proc/{pid}/exe").as_bytes()).unwrap_or_default();
    exe == b"/bin/software-updater" && status_field(pid, "Domain").as_deref() == Some("slate")
}

/// An installed update waits for a restart: the next boot starts another
/// system than the running one.
fn update_waiting() -> bool {
    use slate_rt::subvol;
    let Ok(list) = subvol::list() else { return false };
    match (subvol::running(&list), subvol::flagged(&list, "default")) {
        (Ok(running), Some(next)) => running != next,
        _ => false,
    }
}

/// Read a message (fields up to an empty line) within `timeout_ms`.
fn read_message(fd: i32, timeout_ms: i32) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    while !buf.ends_with(b"\n\n") {
        let mut p = [io::PollFd { fd, events: io::POLLIN, revents: 0 }];
        if io::poll(&mut p, timeout_ms).ok()? == 0 {
            return None;
        }
        let n = io::read(fd, &mut chunk).ok()?;
        if n == 0 || buf.len() + n > MAX_REQUEST {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    buf.truncate(buf.len() - 2);
    Some(buf)
}

/// Run an action's command as root and wait for it.
/// Full graphics on trial (ADR 0173; slate-update's `GRAPHICS_TRIAL`).
const GRAPHICS_TRIAL: &str = "/var/lib/slate/graphics-trial";

fn run_action(cmd: &[&str]) -> Result<(), String> {
    let argv: Vec<Vec<u8>> = cmd.iter().map(|a| a.as_bytes().to_vec()).collect();
    let env = [b"PATH=/bin:/sbin:/usr/bin:/usr/sbin".to_vec()];
    match process::fork() {
        Ok(0) => {
            pipe_default();
            let e = process::execve(&argv[0], &argv, &env);
            slate_rt::eprintln!("slate-brokerd: {}: {e}", cmd[0]);
            process::exit_now(127)
        }
        Ok(child) => match process::wait(child, 0) {
            Ok((_, 0)) => Ok(()),
            _ => Err(format!("{} failed", cmd.join(" "))),
        },
        Err(e) => Err(format!("{e}")),
    }
}

/// [`run_action`], with what went wrong in the command's own words: the
/// last line it wrote on stderr (Disks shows it).
fn run_saying(cmd: &[&str]) -> Result<(), String> {
    let argv: Vec<Vec<u8>> = cmd.iter().map(|a| a.as_bytes().to_vec()).collect();
    let env = [b"PATH=/bin:/sbin:/usr/bin:/usr/sbin".to_vec()];
    let (r, w) = process::pipe(fs::O_CLOEXEC).map_err(|e| format!("{e}"))?;
    match process::fork() {
        Ok(0) => {
            let _ = process::dup2(w, 2);
            pipe_default();
            let e = process::execve(&argv[0], &argv, &env);
            slate_rt::eprintln!("slate-brokerd: {}: {e}", cmd[0]);
            process::exit_now(127)
        }
        Ok(child) => {
            let _ = io::close(w);
            let said = io::read_to_end(r).unwrap_or_default();
            let _ = io::close(r);
            match process::wait(child, 0) {
                Ok((_, 0)) => Ok(()),
                _ => {
                    let text = String::from(lossy(&said));
                    let last = text.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("");
                    // "slate-disk: It is in use" says it without the name.
                    let last = last.split_once(": ").filter(|(p, _)| !p.contains(' ')).map_or(last, |(_, m)| m);
                    Err(if last.is_empty() { format!("{} failed", cmd.join(" ")) } else { String::from(last) })
                }
            }
        }
        Err(e) => {
            let _ = io::close(r);
            let _ = io::close(w);
            Err(format!("{e}"))
        }
    }
}

/// `action`: run a system action for `pid`/`uid`, with the password given
/// or asked through the agent.
fn action(f: &[&[u8]], pid: i32, uid: u32, agent: &mut Option<Agent>) -> Result<(), String> {
    let name = String::from(lossy(f.get(1).ok_or("bad request")?));
    // An action may carry an argument: `timezone=Europe/London`,
    // `network=eth0 dhcp`.
    let (base, arg) = name.split_once('=').map_or((name.as_str(), None), |(b, a)| (b, Some(a)));
    let cmd = ACTIONS.iter().find(|(n, _)| *n == base).map(|(_, c)| *c).ok_or("no such action")?;
    if matches!(
        base,
        "timezone"
            | "network"
            | "desktop"
            | "graphics"
            | "user"
            | "compat"
            | "disk"
            | "update"
            | "end"
            | "browser"
            | "flatpak"
            | "firewall"
    ) != arg.is_some()
    {
        return Err("bad request".into());
    }
    // An account change's third field is the account's new password; an
    // approval password is never sent with one (ADR 0110). An empty field
    // is no password.
    let (approval, secret) = match f.get(2).filter(|p| !p.is_empty()) {
        Some(p) if base == "user" => (None, Some(*p)),
        p => (p.copied(), None),
    };
    let caller = name_of(uid);
    let mut change = None;
    match (base, arg) {
        ("timezone", Some(zone)) if !known_zone(zone) => return Err(format!("unknown time zone {zone}")),
        ("desktop", Some(a)) if a != "add" && a != "remove" => return Err(format!("desktop={a}: add or remove")),
        ("graphics", Some(a)) if a != "full" && a != "slate" => return Err(format!("graphics={a}: full or slate")),
        ("compat", Some(a)) if a != "on" && a != "off" => return Err(format!("compat={a}: on or off")),
        ("update", Some(a)) if a != "check" && a != "install" => return Err(format!("update={a}: check or install")),
        ("browser", Some(a)) if a != "setup" => return Err(format!("browser={a}: setup")),
        ("disk", Some(words)) => {
            slate_diskutil::parse(words)?;
        }
        // `flatpak=setup` (ADR 0125): what Flathub's apps need, as
        // `browser=setup` makes it, for App Center.
        ("flatpak", Some("setup")) => {}
        ("flatpak", Some(words)) => {
            parse_flatpak(words)?;
        }
        ("end", Some(words)) => {
            let (target, _) = parse_end(words)?;
            if target == process::getpid() || !fs::exists(format!("/proc/{target}/stat").as_bytes()) {
                return Err(format!("there is no process {target} to end"));
            }
            // Kernel threads have no program.
            if fs::readlink(format!("/proc/{target}/exe").as_bytes()).is_err() {
                return Err(format!("process {target} is part of the kernel"));
            }
        }
        ("network", Some(words)) => {
            network_card(words)?;
        }
        ("firewall", Some(words)) => {
            parse_firewall(words)?;
        }
        ("user", Some(words)) => {
            let c = parse_user_change(words)?;
            if c.needs_password() != secret.is_some() {
                return Err("bad request".into());
            }
            check_user_change(&c, &caller)?;
            change = Some(c);
        }
        _ => {}
    }
    let perform = || match (base, arg) {
        ("timezone", Some(zone)) => set_timezone(zone),
        ("network", Some(words)) => set_network(words),
        // Strata comes with its apps (ADR 0104), and goes with them if
        // they are there (quarry refuses to leave them without it).
        ("desktop", Some("add")) => run_action(&["/bin/quarry", "install", "slate-desktop", "slate-apps"]),
        ("desktop", Some(_)) if fs::exists(b"/usr/lib/quarry/db/slate-apps") => {
            run_action(&["/bin/quarry", "remove", "slate-apps", "slate-desktop"])
        }
        ("desktop", Some(_)) => run_action(&["/bin/quarry", "remove", "slate-desktop"]),
        // Full graphics starts on trial (ADR 0173): the next start asks
        // whether to keep it (slate-graphics-trial), and goes back to
        // standard graphics without an answer.
        ("graphics", Some("full")) => run_saying(&["/bin/quarry", "install", "slate-firmware-gpu"]).and_then(|()| {
            let _ = fs::mkdir(b"/var/lib/slate", 0o755);
            fs::write_file(GRAPHICS_TRIAL.as_bytes(), b"full\n", 0o644).map_err(|e| format!("{GRAPHICS_TRIAL}: {e}"))
        }),
        ("graphics", Some(_)) => {
            let _ = fs::unlink(GRAPHICS_TRIAL.as_bytes());
            run_saying(&["/bin/quarry", "remove", "slate-firmware-gpu"])
        }
        ("compat", Some(a)) => run_action(&["/bin/slate-compat", a, "--yes"]),
        ("disk", Some(words)) => {
            // The person asking: their folder for a mount, their top
            // folder in a new SlateFS.
            let person = format!("{uid}");
            let mut cmd = alloc::vec!["/sbin/slate-disk", "--for", person.as_str()];
            cmd.extend(words.split(' '));
            run_saying(&cmd)
        }
        ("update", Some("check")) => run_saying(&["/bin/quarry", "update"]),
        ("update", Some(_)) => run_saying(&["/bin/quarry", "upgrade"]),
        ("browser", Some(_)) | ("flatpak", Some("setup")) => browser_setup(),
        ("flatpak", Some(words)) => match parse_flatpak(words) {
            Ok(w) => {
                let mut cmd = alloc::vec!["/bin/slate-flatpak", "--system"];
                cmd.extend(w);
                run_saying(&cmd)
            }
            Err(e) => Err(e),
        },
        ("end", Some(words)) => match parse_end(words) {
            Ok((target, sig)) => process::kill(target, sig).map_err(|e| format!("{e}")),
            Err(e) => Err(e),
        },
        ("firewall", Some(words)) => match parse_firewall(words) {
            Ok(w) => {
                let mut cmd = alloc::vec!["/bin/slate-firewall"];
                cmd.extend(w);
                run_saying(&cmd)
            }
            Err(e) => Err(e),
        },
        ("user", Some(_)) => match &change {
            Some(c) => change_user(c, secret.unwrap_or_default()),
            None => Err("bad request".into()),
        },
        _ => run_action(cmd),
    };
    // Restart and Power off from the login screen and from the session's
    // own Strata (its power dialog, ADR 0110).
    if matches!(name.as_str(), "restart" | "poweroff") {
        let from = if may_be_greeter(pid) {
            Some("the login screen")
        } else if may_be_agent(pid) {
            Some("the session's Strata")
        } else if name == "restart" && may_be_updater(pid) && update_waiting() {
            // Finishing an update the person has installed (ADR 0112).
            Some("the Software Updater, for an installed update")
        } else {
            None
        };
        if let Some(from) = from {
            log(&format!("action {name}: {from}: granted"));
            return perform();
        }
    }
    // Mounting and unmounting a removable disk (a USB stick) in the
    // person's own /run/media folder, and powering it off to unplug it:
    // Slate's own programs (Files, Disks) may, without asking, as anyone
    // at the machine could plug it in or pull it out.
    if let Some(words) = name.strip_prefix("disk=")
        && let Ok(c) = slate_diskutil::parse(words)
        && c.mounting()
        && status_field(pid, "Domain").as_deref() == Some("slate")
        && slate_diskutil::removable(c.target())
    {
        log(&format!("action {name}: {}: granted (removable)", lossy(&caller)));
        return perform();
    }
    // Clearing one's own picture's place of someone else's file takes no
    // approval: it only gives back what is one's own (ADR 0110).
    if let Some(UserChange::Unblock(n)) = &change
        && n.as_bytes() == caller
    {
        log(&format!("action {name}: {}: granted", lossy(&caller)));
        return perform();
    }
    // Fetching the signed indexes changes nothing installed: Slate's own
    // programs (the Software Updater) may, without asking.
    if name == "update=check" && status_field(pid, "Domain").as_deref() == Some("slate") {
        log(&format!("action {name}: {}: granted", lossy(&caller)));
        return perform();
    }
    let me = db::user_by_uid(uid);
    // The log never shows a password, so an account change shows its
    // words only.
    let what = format!("action {name}: {}", lossy(&caller));
    let rules = parse_policy(fs::read_file(POLICY).ok().as_deref());
    let my_groups = me.as_ref().map(db::groups_of).unwrap_or_default();
    let in_group = |g: &[u8]| db::group_id(g).is_some_and(|gid| my_groups.contains(&gid));
    let Some(auth) = su_allowed(&rules, &caller, &in_group, b"root") else {
        log(&format!("{what}: denied by policy"));
        return Err("not allowed by the policy".into());
    };
    let root = db::user_by_name(b"root");
    let check = |pw: &[u8]| match auth {
        Auth::None => true,
        Auth::Target => root.as_ref().is_some_and(|r| password_ok(r, pw, false)),
        Auth::Own => me.as_ref().is_some_and(|m| password_ok(m, pw, false)),
    };
    let granted = |what: &str| -> Result<(), String> {
        log(&format!("{what}: granted"));
        perform()
    };
    if uid == 0 || auth == Auth::None {
        return granted(&what);
    }
    if let Some(pw) = approval {
        if check(pw) {
            return granted(&what);
        }
        log(&format!("{what}: denied (wrong password)"));
        slate_rt::time::sleep_ns(1_000_000_000);
        return Err("Authentication failure".into());
    }
    // Ask the agent: who asks, for what, as whom; one request at a time.
    if agent.is_none() {
        return Err("no approval agent is running (use su)".into());
    }
    let Some(_turn) = Lock::take(AGENT_LOCK, 600_000) else { return Err("the approval agent is busy".into()) };
    let Some(a) = agent.as_ref() else { return Err("no approval agent is running (use su)".into()) };
    let comm = fs::read_file(format!("/proc/{pid}/comm").as_bytes())
        .map(|c| String::from(lossy(&c).trim()))
        .unwrap_or_default();
    let mut error = String::new();
    for _ in 0..3 {
        // No field may be empty: an empty line ends the message.
        let (who, err) = (if comm.is_empty() { "?" } else { &comm }, if error.is_empty() { "-" } else { &error });
        let ask = format!("ask\n{name}\n{who}\n{pid}\n{}\n{err}\n\n", lossy(&caller));
        let reply = io::write_all(a.fd, ask.as_bytes()).ok().and_then(|()| read_message(a.fd, 120_000));
        let Some(reply) = reply else {
            let _ = io::close(a.fd);
            *agent = None;
            return Err("the approval agent did not answer".into());
        };
        let r: Vec<&[u8]> = reply.split(|&c| c == b'\n').collect();
        match r[..] {
            [b"password", pw] if check(pw) => {
                let _ = io::write_all(a.fd, b"done\n\n");
                return granted(&format!("{what} (approved)"));
            }
            [b"password", _] => {
                log(&format!("{what}: denied (wrong password)"));
                slate_rt::time::sleep_ns(1_000_000_000);
                error = String::from("That password didn't work. Try again.");
            }
            _ => {
                let _ = io::write_all(a.fd, b"done\n\n");
                log(&format!("{what}: cancelled"));
                return Err("cancelled".into());
            }
        }
    }
    let _ = io::write_all(a.fd, b"done\n\n");
    Err("Authentication failure".into())
}

/// `newgrp`: make `group` the caller's group (real and effective), as
/// newgrp(1) does. Members (group(5) or gshadow(5)) need no password;
/// others need the group's password from gshadow(5), and without one are
/// refused. An empty `password` asks whether one is needed.
fn newgrp(group: &[u8], password: &[u8], pid: i32, uid: u32) -> Result<(), String> {
    let me = db::user_by_uid(uid).ok_or("you have no account")?;
    let what = format!("newgrp: {} -> {}", lossy(&me.name), lossy(group));
    let gid = db::group_id(group).ok_or_else(|| format!("group '{}' does not exist", lossy(group)))?;
    let mut groups = db::groups_of(&me);
    let shadow = db::gshadow_of(group);
    let member = groups.contains(&gid) || shadow.as_ref().is_some_and(|(_, m)| m.contains(&me.name));
    if !member && uid != 0 {
        let hash = shadow.map(|(h, _)| h).filter(|h| !h.is_empty() && h[0] != b'!' && h[0] != b'*');
        let Some(hash) = hash else {
            log(&format!("{what}: denied (not a member)"));
            return Err("Permission denied.".into());
        };
        if password.is_empty() {
            return Err("password required".into());
        }
        if !crypt::verify(password, &hash) {
            log(&format!("{what}: denied (wrong password)"));
            slate_rt::time::sleep_ns(1_000_000_000);
            return Err("Invalid password.".into());
        }
    }
    if !groups.contains(&gid) {
        groups.push(gid);
    }
    if let Err(e) = process::setids_of(pid, me.uid, gid, &groups) {
        log(&format!("{what}: failed ({e})"));
        return Err(format!("cannot change the credentials ({e}); newgrp works for Slate programs only"));
    }
    log(&format!("{what}: granted"));
    Ok(())
}

/// gpasswd by a group's administrator (gshadow(5)): `-a`/`-d` and `u`
/// with a user, `-r` or `-R`, or `password` and `p` with the new one.
/// Root may too; -M and -A stay root's own gpasswd.
fn gpasswd(op: &[u8], group: &[u8], arg: &[u8], uid: u32, caller: &[u8]) -> Result<(), String> {
    let what = format!("gpasswd {}: {} for {}", lossy(op), lossy(caller), lossy(group));
    if db::group_id(group).is_none() {
        return Err(format!("group '{}' does not exist", lossy(group)));
    }
    if uid != 0 && !db::group_admins(group).iter().any(|a| a == caller) {
        log(&format!("{what}: denied (not an administrator of the group)"));
        return Err("Permission denied.".into());
    }
    let user = arg.strip_prefix(b"u").unwrap_or_default();
    let group_s = String::from(lossy(group));
    let user_s = String::from(lossy(user));
    let r = match op {
        b"-a" | b"-d" => {
            if db::user_by_name(user).is_none() {
                return Err(format!("user '{user_s}' does not exist"));
            }
            run_saying(&["/bin/gpasswd", if op == b"-a" { "-a" } else { "-d" }, &user_s, &group_s])
        }
        b"-r" => run_saying(&["/bin/gpasswd", "-r", &group_s]),
        b"-R" => run_saying(&["/bin/gpasswd", "-R", &group_s]),
        b"password" => {
            let pw = arg.strip_prefix(b"p").unwrap_or(arg);
            if pw.is_empty() {
                return Err("no password given".into());
            }
            crate::accounts::set_group_hash(group, pw)
        }
        _ => return Err("bad request".into()),
    };
    match &r {
        Ok(()) => log(&format!("{what}: done")),
        Err(e) => log(&format!("{what}: failed ({e})")),
    }
    r
}

/// A command word sudo sent: `a` and the word, or `h` and its hex (a
/// word holding a newline, which can't be a field of its own).
pub fn decode_word(w: &[u8]) -> Option<Vec<u8>> {
    match w.split_first()? {
        (b'a', rest) => Some(rest.to_vec()),
        (b'h', hex) if hex.len() % 2 == 0 => {
            hex.chunks(2).map(|p| u8::from_str_radix(core::str::from_utf8(p).ok()?, 16).ok()).collect()
        }
        _ => None,
    }
}

/// The terminal process `pid` has on a standard descriptor, for the I/O
/// log.
fn tty_of(pid: i32) -> Vec<u8> {
    (0..3)
        .filter_map(|fd| fs::readlink(format!("/proc/{pid}/fd/{fd}").as_bytes()).ok())
        .find(|l| l.starts_with(b"/dev/") && l != b"/dev/null")
        .unwrap_or_else(|| b"unknown".to_vec())
}

/// sudo's request (ADRs 0058, 0142, 0159): `run`, the target, the
/// password (`p` first), the action, the command line for the log, the
/// group (`g` first), the options (`o` first, then words: `P` keeps the
/// caller's groups, `WROWSxCOLS` is the terminal's size), and the
/// command's words ([`decode_word`]). An empty field would end the
/// message, hence the prefixes. Granted with an I/O log, the answer's
/// words are `log=` and what is recorded (`i` input, `o` output), and
/// the log's open files go with it.
fn run(f: &[&[u8]], pid: i32, uid: u32, caller: &[u8]) -> Result<(Vec<u8>, Vec<i32>), String> {
    let [_, target, password, action, text, group, opts, ref argv @ ..] = f[..] else {
        return Err("bad request".into());
    };
    let password = password.strip_prefix(b"p").unwrap_or(password);
    let group = group.strip_prefix(b"g").filter(|g| !g.is_empty());
    let Some(opts) = opts.strip_prefix(b"o") else { return Err("bad request".into()) };
    let opts: Vec<&[u8]> = opts.split(|&c| c == b' ').filter(|o| !o.is_empty()).collect();
    let keep_groups = opts.contains(&&b"P"[..]);
    let size = opts
        .iter()
        .find_map(|o| o.strip_prefix(b"W"))
        .and_then(|s| {
            let (r, c) = core::str::from_utf8(s).ok()?.split_once('x')?;
            Some((r.parse().ok()?, c.parse().ok()?))
        })
        .unwrap_or((0, 0));
    let argv: Vec<Vec<u8>> = argv.iter().map(|a| decode_word(a)).collect::<Option<_>>().ok_or("bad request")?;
    let Some(u) = db::user_by_name(target) else { return Err("no such user".into()) };
    let gid = match group {
        Some(g) => Some(db::group_id(g).ok_or_else(|| format!("unknown group {}", lossy(g)))?),
        None => None,
    };
    let mut what = format!(
        "run: {} -> {}{}: {}",
        lossy(caller),
        lossy(target),
        group.map(|g| format!(":{}", lossy(g))).unwrap_or_default(),
        lossy(text)
    );
    let policy = read_policy();
    let rules = &policy.rules;
    let me = db::user_by_uid(uid);
    let my_groups = me.as_ref().map(db::groups_of).unwrap_or_default();
    let in_group = |g: &[u8]| db::group_id(g).is_some_and(|gid| my_groups.contains(&gid));
    let target_groups = db::groups_of(&u);
    let target_in = |g: &[u8]| db::group_id(g).is_some_and(|gid| gid == u.gid || target_groups.contains(&gid));
    let req = RunRequest { to: target, group, argv: &argv };
    let rule = if action == b"validate" {
        // -v: allowed anything at all as anyone.
        rules.iter().find(|r| r.run && from_matches(r, caller, &in_group))
    } else {
        run_allowed(rules, caller, &in_group, &req, &target_in)
    };
    let auth = if uid == 0 { Some(Auth::None) } else { rule.map(|r| r.auth) };
    let Some(auth) = auth else {
        log(&format!("{what}: denied by policy"));
        return Err(if argv.is_empty() || rules.iter().all(|r| !r.run || !from_matches(r, caller, &in_group)) {
            format!("{} is not allowed to run commands as {}", lossy(caller), lossy(target))
        } else {
            format!("{} is not allowed to run {} as {}", lossy(caller), lossy(text), lossy(target))
        });
    };
    // A rule naming a command holds only if the command is what runs:
    // sudo resolved it and executes exactly that (ADR 0142).
    if uid != 0
        && rule.is_some_and(|r| r.commands.is_some())
        && !(fs::readlink(format!("/proc/{pid}/exe").as_bytes()).unwrap_or_default() == b"/bin/sudo"
            && status_field(pid, "Domain").as_deref() == Some("slate"))
    {
        log(&format!("{what}: denied (not sudo)"));
        return Err("only sudo may ask for a command".into());
    }
    if let crate::accounts::Ageing::Refused(msg) = crate::accounts::ageing(caller) {
        log(&format!("{what}: denied (account expired)"));
        return Err(msg.into());
    }
    let sid = session_of(pid);
    if auth != Auth::None && !timestamp_fresh(uid, sid, policy.defaults.timestamp_timeout) {
        if password.is_empty() {
            return Err("password required".into());
        }
        let ok = match auth {
            Auth::Own => me.as_ref().is_some_and(|m| password_ok(m, password, false)),
            _ => password_ok(&u, password, false),
        };
        if !ok {
            log(&format!("{what}: denied (wrong password)"));
            slate_rt::time::sleep_ns(1_000_000_000);
            return Err("Authentication failure".into());
        }
    }
    touch_timestamp(uid, sid);
    if action == b"validate" {
        log(&format!("{what}: validated"));
        return Ok((Vec::new(), Vec::new()));
    }
    // -P: the groups the caller has now (newgrp's among them).
    let groups: Vec<u32> = if keep_groups {
        status_field(pid, "Groups")
            .map(|g| g.split_ascii_whitespace().filter_map(|n| n.parse().ok()).collect())
            .unwrap_or_default()
    } else {
        target_groups.clone()
    };
    let primary = gid.unwrap_or(u.gid);
    if let Err(e) = process::setids_of(pid, u.uid, primary, &groups) {
        log(&format!("{what}: failed ({e})"));
        return Err(format!("cannot change the credentials ({e}); sudo works for Slate programs only"));
    }
    // The I/O log (ADR 0159): the rule's tags, else the defaults.
    let log_in = rule.and_then(|r| r.tags.log_input).unwrap_or(policy.defaults.log_input);
    let log_out = rule.and_then(|r| r.tags.log_output).unwrap_or(policy.defaults.log_output);
    let mut answer = Vec::new();
    let mut fds = Vec::new();
    if action == b"exec" && (log_in || log_out) {
        let info = crate::iolog::Info {
            time: slate_rt::time::unix(),
            user: caller.to_vec(),
            runas_user: target.to_vec(),
            runas_group: db::group_name(primary).unwrap_or_else(|| format!("{primary}").into_bytes()),
            tty: tty_of(pid),
            rows: size.0,
            cols: size.1,
            cwd: fs::readlink(format!("/proc/{pid}/cwd").as_bytes()).unwrap_or_else(|_| b"/".to_vec()),
            command: text.to_vec(),
        };
        let (id, files) = crate::iolog::create(&info).inspect_err(|e| log(&format!("{what}: {e}")))?;
        answer = format!("log={}{}", if log_in { "i" } else { "" }, if log_out { "o" } else { "" }).into_bytes();
        fds = files;
        what.push_str(&format!(" (I/O log {id})"));
    }
    log(&format!("{what}: granted"));
    Ok((answer, fds))
}

/// Handle one request from `pid`/`uid`; the reply's text.
fn handle(req: &[u8], pid: i32, uid: u32) -> Result<(), String> {
    let f: Vec<&[u8]> = req.split(|&c| c == b'\n').collect();
    let caller = name_of(uid);
    match f[..] {
        [b"su", target, password] => {
            let Some(u) = db::user_by_name(target) else { return Err("no such user".into()) };
            let rules = parse_policy(fs::read_file(POLICY).ok().as_deref());
            let what = format!("su: {} -> {}", lossy(&caller), lossy(target));
            let me = db::user_by_uid(uid);
            let my_groups = me.as_ref().map(db::groups_of).unwrap_or_default();
            let in_group = |g: &[u8]| db::group_id(g).is_some_and(|gid| my_groups.contains(&gid));
            let Some(auth) = su_allowed(&rules, &caller, &in_group, target) else {
                log(&format!("{what}: denied by policy"));
                return Err("not allowed by the policy".into());
            };
            let ok = uid == 0
                || match auth {
                    Auth::None => true,
                    Auth::Target => password_ok(&u, password, false),
                    // Your own password must exist: a passwordless account
                    // does not make its holder an administrator.
                    Auth::Own => me.as_ref().is_some_and(|m| password_ok(m, password, false)),
                };
            if !ok {
                log(&format!("{what}: denied (wrong password)"));
                slate_rt::time::sleep_ns(1_000_000_000);
                return Err("Authentication failure".into());
            }
            if uid != 0 {
                match crate::accounts::ageing(&u.name) {
                    crate::accounts::Ageing::Refused(msg) => {
                        log(&format!("{what}: denied (account expired)"));
                        return Err(msg.into());
                    }
                    crate::accounts::Ageing::MustChange => {
                        log(&format!("{what}: denied (password expired)"));
                        return Err("the target's password has expired".into());
                    }
                    _ => {}
                }
            }
            let groups = db::groups_of(&u);
            if let Err(e) = process::setids_of(pid, u.uid, u.gid, &groups) {
                log(&format!("{what}: failed ({e})"));
                return Err(format!("cannot change the credentials ({e}); su works for Slate programs only"));
            }
            log(&format!("{what}: granted"));
            Ok(())
        }
        [b"record", ref rest @ ..] => record(rest, uid, &caller),
        [b"newgrp", group, password] => newgrp(group, password.strip_prefix(b"p").unwrap_or(password), pid, uid),
        [b"gpasswd", op, group, arg] => gpasswd(op, group, arg, uid, &caller),
        [b"run-forget"] => {
            let _ = fs::unlink(&timestamp_path(uid, session_of(pid)));
            Ok(())
        }
        [b"chsh", target, password, shell] => {
            let what = format!("chsh: {} for {}", lossy(&caller), lossy(target));
            let Some(u) = db::user_by_name(target) else { return Err("no such user".into()) };
            if uid != 0 && u.uid != uid {
                log(&format!("{what}: denied"));
                return Err("Permission denied.".into());
            }
            if uid != 0 && !password_ok(&u, password, true) {
                log(&format!("{what}: denied (wrong password)"));
                slate_rt::time::sleep_ns(1_000_000_000);
                return Err("Authentication failure".into());
            }
            if !crate::accounts::valid_shell(shell) {
                return Err(format!("{} is an invalid shell", lossy(shell)));
            }
            // set_shell takes the accounts' lock itself.
            crate::accounts::set_shell(&u.name, shell)?;
            log(&format!("{what}: changed to {}", lossy(shell)));
            Ok(())
        }
        [b"check", password] => {
            let Some(u) = db::user_by_uid(uid) else { return Err("no such user".into()) };
            if password_ok(&u, password, true) {
                return Ok(());
            }
            log(&format!("check: {}: wrong password", lossy(&caller)));
            slate_rt::time::sleep_ns(1_000_000_000);
            Err("Authentication failure".into())
        }
        [b"passwd", target, current, new] => {
            let Some(u) = db::user_by_name(target) else { return Err("no such user".into()) };
            let what = format!("passwd: {} for {}", lossy(&caller), lossy(target));
            if uid != 0 && u.uid != uid {
                log(&format!("{what}: denied"));
                return Err("Permission denied.".into());
            }
            let hash = db::hash_of(&u).unwrap_or_default();
            if uid != 0 && !hash.is_empty() && !crypt::verify(current, &hash) {
                log(&format!("{what}: denied (wrong password)"));
                slate_rt::time::sleep_ns(1_000_000_000);
                return Err("Authentication token manipulation error".into());
            }
            set_password(&what, &u, current, new, uid == 0)
        }
        _ => Err("bad request".into()),
    }
}

/// Set `u`'s password to `new` (the caller knew `current`, or is root),
/// and let the encrypted root's password follow it.
fn set_password(what: &str, u: &db::User, current: &[u8], new: &[u8], by_root: bool) -> Result<(), String> {
    let Some(_turn) = Lock::take(SHADOW_LOCK, 60_000) else { return Err("/etc/shadow is busy".into()) };
    let mut salt = [0u8; 12];
    process::random(&mut salt).map_err(|e| format!("random numbers: {e}"))?;
    let h = crypt::crypt(new, crypt::new_salt(&salt).as_bytes()).ok_or("hashing failed")?;
    db::set_hash(&u.name, h.as_bytes()).map_err(|e| format!("cannot update /etc/shadow: {e}"))?;
    log(&format!("{what}: changed"));
    // The encrypted root's password follows the account's (ADR
    // 0039): the slot the old password opens takes the new one,
    // and is marked as the account's (ADR 0058). Root resetting it
    // without the old one: the slot marked as the account's.
    let followed = if !current.is_empty() {
        slate_crypt::follow_password_of(Some(u.uid), current, new)
    } else if by_root {
        slate_crypt::reset_password(u.uid, new)
    } else {
        Ok(false)
    };
    match followed {
        Ok(true) => log(&format!("{what}: the disk's password changed too")),
        Ok(false) => {}
        Err(e) => log(&format!("{what}: the disk's password did not change ({e})")),
    }
    Ok(())
}

/// The login screen's answer when the password is right but has expired
/// (shadow(5)): it then asks for a new one and sends it with the old.
pub const EXPIRED: &str = "Your password has expired. Choose a new one.";

/// A connection whose request is still arriving.
struct Pending {
    fd: i32,
    buf: Vec<u8>,
    since: i64,
}

/// How many connections may be half-read at once.
const MAX_PENDING: usize = 64;
/// A child's exit status when the approval agent has gone.
const AGENT_GONE: i32 = 3;

fn now_ms() -> i64 {
    let (s, ns) = slate_rt::time::now(slate_rt::time::CLOCK_MONOTONIC);
    s * 1000 + ns / 1_000_000
}

/// A lock between the broker's children (ADR 0039): flock(2) on a file in
/// /run. It belongs to the open file, so the kernel lets go when the
/// holder exits, however it ends; dropping it closes the file.
#[derive(Debug)]
struct Lock(i32);

impl Lock {
    /// Wait (up to `timeout_ms`) for `path`.
    fn take(path: &'static [u8], timeout_ms: i64) -> Option<Lock> {
        use slate_rt::fs::{LOCK_EX, LOCK_NB, O_CLOEXEC, O_CREAT, O_RDWR};
        let _ = fs::mkdir(b"/run", 0o755);
        let fd = fs::open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600).ok()?;
        let deadline = now_ms() + timeout_ms;
        loop {
            if fs::flock(fd, LOCK_EX | LOCK_NB).is_ok() {
                return Some(Lock(fd));
            }
            if now_ms() >= deadline {
                let _ = io::close(fd);
                return None;
            }
            slate_rt::time::sleep_ns(50_000_000);
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = io::close(self.0);
    }
}

/// Only one request talks to the approval agent at a time.
const AGENT_LOCK: &[u8] = b"/run/slate-brokerd.agent";
/// /etc/shadow and the disk's key slots change one request at a time.
/// The same lock the account tools take (ADR 0057).
const SHADOW_LOCK: &[u8] = crate::accounts::LOCK;

/// Answer one complete request in a child of the broker; the child's exit
/// status.
fn serve(fd: i32, req: &[u8], agent: &mut Option<Agent>) -> i32 {
    let reply = match net::peer_cred(fd) {
        Ok((pid, _, _)) if req.starts_with(b"login\n") => {
            if !may_be_greeter(pid) {
                log(&format!("login refused: pid {pid}"));
                b"error: not allowed\n".to_vec()
            } else {
                let f: Vec<&[u8]> = req.split(|&c| c == b'\n').collect();
                match login(&f, fd) {
                    // The supervisor has the connection now.
                    Ok(()) => return 0,
                    Err(e) => format!("error: {e}\n").into_bytes(),
                }
            }
        }
        Ok((pid, uid, _)) if req.starts_with(b"action\n") => {
            let f: Vec<&[u8]> = req.split(|&c| c == b'\n').collect();
            match action(&f, pid, uid, agent) {
                Ok(()) => b"ok\n".to_vec(),
                Err(e) => {
                    let _ = io::write_all(fd, format!("error: {e}\n").as_bytes());
                    return if agent.is_none() { AGENT_GONE } else { 1 };
                }
            }
        }
        Ok((pid, uid, _)) if req.starts_with(b"run\n") => {
            let f: Vec<&[u8]> = req.split(|&c| c == b'\n').collect();
            match run(&f, pid, uid, &name_of(uid)) {
                Ok((words, fds)) => {
                    let mut reply = b"ok".to_vec();
                    if !words.is_empty() {
                        reply.push(b' ');
                        reply.extend_from_slice(&words);
                    }
                    reply.push(b'\n');
                    let sent = net::send_fds(fd, &reply, &fds);
                    for f in fds {
                        let _ = io::close(f);
                    }
                    return i32::from(sent.is_err());
                }
                Err(e) => format!("error: {e}\n").into_bytes(),
            }
        }
        Ok((pid, uid, _)) => match handle(req, pid, uid) {
            Ok(()) => b"ok\n".to_vec(),
            Err(e) => format!("error: {e}\n").into_bytes(),
        },
        Err(_) => b"error: bad request\n".to_vec(),
    };
    let _ = io::write_all(fd, &reply);
    0
}

/// The folder of people's pictures (Strata's `faces`, ADR 0110's second
/// addendum): sticky and open to all, as /tmp is, since homes are private
/// and the login screen must read them; readers believe only a file its
/// account owns.
const FACES: &[u8] = b"/var/lib/slate/faces";

fn make_faces_dir() {
    for d in [b"/var/lib".as_slice(), b"/var/lib/slate", FACES] {
        let _ = fs::mkdir(d, 0o755);
    }
    // Only if it is a real folder (not a link someone put there).
    if fs::lstat(FACES).is_ok_and(|s| s.mode & fs::S_IFMT == fs::S_IFDIR && s.uid == 0) {
        let _ = fs::chmod(FACES, 0o1777);
    }
}

/// slate-brokerd, for good: requests are read as they arrive, and each is
/// answered in a child of its own (ADR 0039), so an open approval dialog
/// or a slow password hash holds up no one else. The approval agent's
/// registration stays with the broker; the agent itself, /etc/shadow and
/// the disk's key slots are taken one child at a time ([`Lock`]).
pub fn brokerd_main() -> i32 {
    if process::geteuid() != 0 {
        slate_rt::eprintln!("slate-brokerd: must run as root");
        return 1;
    }
    let l = match net::listen(SOCKET) {
        Ok(fd) => fd,
        Err(e) => {
            slate_rt::eprintln!("slate-brokerd: listening on @{}: {e}", lossy(SOCKET));
            return 1;
        }
    };
    // A write to a client or an approval agent that has gone must fail
    // (EPIPE), not end the broker or a request's child unheard: a gone
    // agent is then forgotten (AGENT_GONE) and the caller told. Children
    // put it back before running anything ([`pipe_default`]).
    let _ = signal::set(signal::SIGPIPE, signal::Disposition::Ignore);
    make_faces_dir();
    log("started");
    // Locks left by a broker that died.
    for lock in [AGENT_LOCK, SHADOW_LOCK] {
        let _ = fs::unlink(lock);
    }
    let mut agent: Option<Agent> = None;
    // The agent's registrations, counted, and which children use which.
    let mut agent_gen = 0u32;
    let mut users: Vec<(i32, u32)> = Vec::new();
    let mut pending: Vec<Pending> = Vec::new();
    // A child writes a byte here as it finishes, so it is reaped at once
    // rather than at the next timeout; until `soon`, look again often (it
    // may not have exited yet when the byte arrives).
    let Ok((wake_r, wake_w)) = process::pipe(fs::O_CLOEXEC | fs::O_NONBLOCK) else {
        slate_rt::eprintln!("slate-brokerd: no pipe");
        return 1;
    };
    let mut soon = 0i64;
    loop {
        // Children that have answered (and supervisors of ended sessions).
        while let Ok((pid, status)) = process::wait(-1, process::WNOHANG) {
            if pid <= 0 {
                break;
            }
            let used = users.iter().position(|u| u.0 == pid).map(|i| users.swap_remove(i).1);
            if process::exited(status) == Some(AGENT_GONE) && used == Some(agent_gen) && agent.is_some() {
                log("approval agent: gone");
                if let Some(a) = agent.take() {
                    let _ = io::close(a.fd);
                }
            }
        }
        let mut fds: Vec<io::PollFd> = [l, wake_r]
            .into_iter()
            .chain(pending.iter().map(|p| p.fd))
            .map(|fd| io::PollFd { fd, events: io::POLLIN, revents: 0 })
            .collect();
        if io::poll(&mut fds, if now_ms() < soon { 5 } else { 1000 }).is_err() {
            continue;
        }
        if fds[1].revents != 0 {
            let mut b = [0u8; 64];
            while io::read(wake_r, &mut b).is_ok_and(|n| n > 0) {}
            soon = now_ms() + 200;
        }
        let now = now_ms();
        let mut complete: Vec<(i32, Vec<u8>)> = Vec::new();
        let mut closed: Vec<i32> = Vec::new();
        for (p, f) in pending.iter_mut().zip(&fds[2..]) {
            if f.revents == 0 {
                if now - p.since > 10_000 {
                    closed.push(p.fd);
                }
                continue;
            }
            let mut chunk = [0u8; 512];
            match io::read(p.fd, &mut chunk) {
                Ok(n) if n > 0 && p.buf.len() + n <= MAX_REQUEST => {
                    p.buf.extend_from_slice(&chunk[..n]);
                    if p.buf.ends_with(b"\n\n") {
                        let mut req = core::mem::take(&mut p.buf);
                        req.truncate(req.len() - 2);
                        complete.push((p.fd, req));
                    }
                }
                _ => closed.push(p.fd),
            }
        }
        for fd in &closed {
            let _ = io::close(*fd);
        }
        pending.retain(|p| !closed.contains(&p.fd) && !complete.iter().any(|c| c.0 == p.fd));
        if fds[0].revents != 0
            && let Ok(fd) = net::accept(l)
        {
            if pending.len() < MAX_PENDING {
                pending.push(Pending { fd, buf: Vec::new(), since: now });
            } else {
                let _ = io::close(fd);
            }
        }
        for (fd, req) in complete {
            if req == b"agent" {
                let pid = net::peer_cred(fd).map_or(0, |c| c.0);
                if may_be_agent(pid) {
                    // The agent's connection stays open.
                    if let Some(old) = agent.replace(Agent { fd }) {
                        let _ = io::close(old.fd);
                    }
                    agent_gen += 1;
                    log(&format!("approval agent: pid {pid}"));
                    let _ = io::write_all(fd, b"ok\n");
                } else {
                    log(&format!("approval agent refused: pid {pid}"));
                    let _ = io::write_all(fd, b"error: not allowed\n");
                    let _ = io::close(fd);
                }
                continue;
            }
            match process::fork() {
                Ok(0) => {
                    // Only this connection and the agent's.
                    let _ = io::close(l);
                    for p in &pending {
                        let _ = io::close(p.fd);
                    }
                    let status = serve(fd, &req, &mut agent);
                    let _ = io::write(wake_w, b"x");
                    process::exit_now(status)
                }
                Ok(child) => {
                    if req.starts_with(b"action\n") {
                        users.push((child, agent_gen));
                    }
                }
                Err(e) => {
                    let _ = io::write_all(fd, format!("error: {e}\n").as_bytes());
                }
            }
            let _ = io::close(fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_changes() {
        let add = |s| parse_user_change(s);
        assert_eq!(
            add("add ada admin Ada Lovelace"),
            Ok(UserChange::Add { name: "ada".into(), admin: true, full: "Ada Lovelace".into() })
        );
        assert_eq!(
            add("add bo standard"),
            Ok(UserChange::Add { name: "bo".into(), admin: false, full: String::new() })
        );
        assert_eq!(add("remove ada"), Ok(UserChange::Remove("ada".into())));
        assert_eq!(add("standard ada"), Ok(UserChange::Admin("ada".into(), false)));
        assert_eq!(add("password ada"), Ok(UserChange::Password("ada".into())));
        assert!(add("add ada root Ada").is_err());
        assert!(add("add Ada admin").is_err(), "names are lower case");
        assert!(add("add ada admin Ada:0:0").is_err());
        assert_eq!(add("name ada Ada King"), Ok(UserChange::Name("ada".into(), "Ada King".into())));
        assert!(add("name ada Ada, Countess").is_err());
        assert!(add("rename ada Ada King").is_err());
        assert!(add("remove ada now").is_err());
        assert!(add("delete ada").is_err());
        assert!(UserChange::Password("x".into()).needs_password());
        assert!(!UserChange::Remove("x".into()).needs_password());
    }

    #[test]
    fn ending_processes() {
        assert_eq!(parse_end("312 TERM"), Ok((312, 15)));
        assert_eq!(parse_end("312 KILL"), Ok((312, 9)));
        assert!(parse_end("1 KILL").is_err(), "not init");
        assert!(parse_end("312 HUP").is_err());
        assert!(parse_end("312").is_err());
        assert!(parse_end("x TERM").is_err());
    }

    #[test]
    fn flatpak_words() {
        assert_eq!(parse_flatpak("install org.mozilla.firefox"), Ok(alloc::vec!["install", "org.mozilla.firefox"]));
        assert!(parse_flatpak("install --from mine org.app.One org.app.Two//beta").is_ok());
        assert!(parse_flatpak("remove org.app.One").is_ok());
        assert!(parse_flatpak("update").is_ok());
        assert!(parse_flatpak("update org.app.One").is_ok());
        assert!(parse_flatpak("install").is_err(), "an app");
        assert!(parse_flatpak("install --from -x org.app.One").is_err(), "an option as a remote");
        assert!(parse_flatpak("install --user org.app.One").is_err());
        assert!(parse_flatpak("install org.app").is_err(), "three parts");
        assert!(parse_flatpak("remote-add x https://example.org/x.flatpakrepo").is_err(), "root's to add");
        assert!(parse_flatpak("rollback org.app.One").is_err());
        assert!(parse_flatpak("install org.app.One  org.app.Two").is_err(), "an empty word");
    }

    #[test]
    fn policy() {
        let none = |_: &[u8]| false;
        let wheel = |g: &[u8]| g == b"wheel";
        let default = parse_policy(None);
        assert_eq!(su_allowed(&default, b"tester", &none, b"root"), Some(Auth::Target));
        let rules = parse_policy(Some(
            b"# comment\nsu admin root nopassword\nsu %wheel root ownpassword\nsu * root\nsu alex *\n",
        ));
        assert_eq!(su_allowed(&rules, b"admin", &none, b"root"), Some(Auth::None));
        assert_eq!(su_allowed(&rules, b"ada", &wheel, b"root"), Some(Auth::Own));
        assert_eq!(su_allowed(&rules, b"tester", &none, b"root"), Some(Auth::Target));
        assert_eq!(su_allowed(&rules, b"alex", &none, b"tester"), Some(Auth::Target));
        assert_eq!(su_allowed(&rules, b"tester", &none, b"alex"), None);
        let run = parse_policy(Some(b"run %wheel * ownpassword\nrun ci root nopassword\nsu * *\n"));
        let cmd = |w: &[&str]| w.iter().map(|w| w.as_bytes().to_vec()).collect::<Vec<_>>();
        let id = cmd(&["/bin/id"]);
        let ask = |rules, from: &[u8], in_group: &dyn Fn(&[u8]) -> bool, to: &[u8], argv: &[Vec<u8>]| {
            run_allowed(rules, from, in_group, &RunRequest { to, group: None, argv }, &none).map(|r| r.auth)
        };
        assert_eq!(ask(&run, b"ada", &wheel, b"root", &id), Some(Auth::Own));
        assert_eq!(ask(&run, b"ci", &none, b"root", &id), Some(Auth::None));
        assert_eq!(ask(&run, b"tester", &none, b"root", &id), None);
        assert_eq!(su_allowed(&run, b"tester", &none, b"root"), Some(Auth::Target));
        let default = parse_policy(None);
        assert_eq!(ask(&default, b"tester", &none, b"root", &id), None);

        // Commands (ADR 0142): a path with any arguments, exact arguments,
        // none (""), a directory, sudoedit; groups after the target.
        let rules = parse_policy(Some(
            b"run ci root nopassword /usr/bin/slate-update status\n\
              run ci root /bin/id \"\"\n\
              run ci root /sbin/\n\
              run ci root sudoedit /etc/motd\n\
              run ci *:audio ownpassword /bin/ls\n\
              run ops * nopassword\n\
              su ci root /bin/id\n\
              run ci root:\n",
        ));
        assert_eq!(rules.len(), 6, "{rules:?}");
        assert_eq!(format!("{}", rules[0].commands.as_ref().unwrap()[0]), "/usr/bin/slate-update status");
        assert_eq!(format!("{}", rules[1].commands.as_ref().unwrap()[0]), "/bin/id \"\"");
        assert_eq!(ask(&rules, b"ci", &none, b"root", &cmd(&["/usr/bin/slate-update", "status"])), Some(Auth::None));
        assert_eq!(ask(&rules, b"ci", &none, b"root", &cmd(&["/usr/bin/slate-update", "commit"])), None);
        assert_eq!(ask(&rules, b"ci", &none, b"root", &cmd(&["/bin/id"])), Some(Auth::Target));
        assert_eq!(ask(&rules, b"ci", &none, b"root", &cmd(&["/bin/id", "-u"])), None);
        assert_eq!(ask(&rules, b"ci", &none, b"root", &cmd(&["/sbin/reboot", "-f"])), Some(Auth::Target));
        assert_eq!(ask(&rules, b"ci", &none, b"root", &cmd(&["/sbin/x/y"])), None);
        assert_eq!(ask(&rules, b"ci", &none, b"root", &cmd(&["sudoedit", "/etc/motd"])), Some(Auth::Target));
        assert_eq!(ask(&rules, b"ci", &none, b"root", &cmd(&["sudoedit", "/etc/shadow"])), None);
        assert_eq!(ask(&rules, b"ops", &none, b"root", &cmd(&["/bin/sh"])), Some(Auth::None));
        let audio = |g: &str| {
            let req = RunRequest { to: b"bob", group: Some(g.as_bytes()), argv: &cmd(&["/bin/ls"]) };
            run_allowed(&rules, b"ci", &none, &req, &|g| g == b"users").map(|r| r.auth)
        };
        assert_eq!(audio("audio"), Some(Auth::Own));
        assert_eq!(audio("video"), None);
        // ops's rule has no group: only the target's own groups.
        let ops = |g: &str| {
            let req = RunRequest { to: b"bob", group: Some(g.as_bytes()), argv: &cmd(&["/bin/ls"]) };
            run_allowed(&rules, b"ops", &none, &req, &|g| g == b"users").is_some()
        };
        assert!(ops("users") && !ops("wheel"));
    }

    #[test]
    fn policy_lists_aliases_and_tags() {
        let none = |_: &[u8]| false;
        let cmd = |w: &[&str]| w.iter().map(|w| w.as_bytes().to_vec()).collect::<Vec<_>>();
        let p = read_policy_text(Some(
            b"commands UPDATE = /usr/bin/slate-update status, /usr/bin/slate-update commit\n\
              commands ADMIN = UPDATE, /bin/true \"\"\n\
              users OPS = ci, %ops\n\
              users BAD = NOPE\n\
              run OPS root nopassword setenv log_output ADMIN, /bin/echo\n\
              run ann root,bob ownpassword nolog_input /bin/id,/bin/ls -l\n\
              run BAD root\n\
              run ci root UNKNOWN\n\
              run ci root /bin/a,,/bin/b\n\
              run ci %wheel /bin/id\n\
              run ann root ALL\n",
        ));
        assert_eq!(p.rules.len(), 3, "{:?}", p.rules);
        let r = &p.rules[0];
        assert_eq!(r.from, cmd(&["ci", "%ops"]));
        assert_eq!(r.tags, Tags { setenv: true, log_input: None, log_output: Some(true) });
        let shown: Vec<String> = r.commands.as_ref().unwrap().iter().map(|c| format!("{c}")).collect();
        assert_eq!(
            shown,
            ["/usr/bin/slate-update status", "/usr/bin/slate-update commit", "/bin/true \"\"", "/bin/echo"]
        );
        let ask = |from: &[u8], in_group: &dyn Fn(&[u8]) -> bool, to: &[u8], argv: &[Vec<u8>]| {
            run_allowed(&p.rules, from, in_group, &RunRequest { to, group: None, argv }, &none).map(|r| r.auth)
        };
        assert_eq!(ask(b"ci", &none, b"root", &cmd(&["/usr/bin/slate-update", "commit"])), Some(Auth::None));
        assert_eq!(ask(b"x", &|g| g == b"ops", b"root", &cmd(&["/bin/echo", "hi"])), Some(Auth::None));
        assert_eq!(ask(b"ci", &none, b"root", &cmd(&["/bin/true", "x"])), None);
        assert_eq!(ask(b"ann", &none, b"bob", &cmd(&["/bin/ls", "-l"])), Some(Auth::Own));
        assert_eq!(ask(b"ann", &none, b"bob", &cmd(&["/bin/ls"])), None);
        assert_eq!(p.rules[1].tags.log_input, Some(false));
        assert!(p.rules[2].commands.is_none(), "ALL is every command");
    }

    #[test]
    fn policy_defaults() {
        let p = read_policy_text(Some(
            b"defaults env_keep += \"EDITOR PAGER\", secure_path=/bin:/usr/bin\n\
              defaults !env_reset,log_output, timestamp_timeout=2.5\n\
              defaults env_keep -= TZ\n\
              defaults passwd_tries=5, runcwd=*, user_command_timeouts, nosuchthing\n\
              defaults !use_pty\n",
        ));
        let d = &p.defaults;
        assert!(d.keeps(b"EDITOR=vi") && d.keeps(b"LC_ALL=C") && !d.keeps(b"TZ=UTC") && !d.keeps(b"LD_PRELOAD=x"));
        assert_eq!(d.secure_path, b"/bin:/usr/bin".to_vec());
        assert!(!d.env_reset && d.log_output && !d.log_input && !d.use_pty && d.user_command_timeouts);
        assert_eq!(d.timestamp_timeout, Some(150));
        assert_eq!(d.passwd_tries, 5);
        assert_eq!(d.runcwd.as_deref(), Some(b"*".as_slice()));
        assert_eq!(minutes(b"0"), Some(0));
        assert_eq!(minutes(b"-1"), Some(-60));
        assert_eq!(minutes(b"x"), None);
        let never = read_policy_text(Some(b"defaults timestamp_timeout=-1\n"));
        assert_eq!(never.defaults.timestamp_timeout, None);
        assert_eq!(read_policy_text(None).defaults, Defaults::default());
    }

    #[test]
    fn command_words() {
        assert_eq!(decode_word(b"a/bin/id"), Some(b"/bin/id".to_vec()));
        assert_eq!(decode_word(b"a"), Some(Vec::new()));
        assert_eq!(decode_word(b"h610a62"), Some(b"a\nb".to_vec()));
        assert_eq!(decode_word(b"h6"), None);
        assert_eq!(decode_word(b"x"), None);
    }

    #[test]
    fn firewall_words() {
        assert_eq!(parse_firewall("allow tcp 8080"), Ok(alloc::vec!["allow", "tcp", "8080"]));
        assert!(parse_firewall("off").is_ok());
        assert!(parse_firewall("deny udp 0").is_err());
        assert!(parse_firewall("allow sctp 1").is_err());
        assert!(parse_firewall("flush").is_err());
        assert!(parse_firewall("allow tcp 1 2").is_err());
    }
}
