// SPDX-License-Identifier: MIT OR Apache-2.0

//! One connection after the key exchange: user authentication (RFC 4252)
//! and the connection protocol (RFC 4254): session channels with a
//! pseudo-terminal or pipes, `shell` and `exec`, window sizes, flow
//! control, and exit status; keepalives and server-started rekeys (ADR
//! 0061). Port forwarding, agent forwarding and X11 are refused.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use slate_rt::io::{POLLERR, POLLHUP, POLLIN, POLLOUT, PollFd};
use slate_rt::{eprintln, fs, io, lossy, process, signal, term};

use crate::auth::{self, Outcome, User};
use crate::config::{RootLogin, Settings};
use crate::crypto::{HostKey, HostSign};
use crate::transport::{self, Fd, Transport, err};
use crate::wire::{Reader, Writer};

// Message numbers (RFC 4250 §4.1).
pub const MSG_SERVICE_REQUEST: u8 = 5;
pub const MSG_SERVICE_ACCEPT: u8 = 6;
pub const MSG_USERAUTH_REQUEST: u8 = 50;
pub const MSG_USERAUTH_FAILURE: u8 = 51;
pub const MSG_USERAUTH_SUCCESS: u8 = 52;
pub const MSG_USERAUTH_BANNER: u8 = 53;
pub const MSG_USERAUTH_PK_OK: u8 = 60;
/// The password method's use of 60 (RFC 4252 §8).
pub const MSG_USERAUTH_PASSWD_CHANGEREQ: u8 = 60;
pub const MSG_GLOBAL_REQUEST: u8 = 80;
pub const MSG_REQUEST_FAILURE: u8 = 82;
pub const MSG_CHANNEL_OPEN: u8 = 90;
pub const MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub const MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
pub const MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
pub const MSG_CHANNEL_DATA: u8 = 94;
pub const MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
pub const MSG_CHANNEL_EOF: u8 = 96;
pub const MSG_CHANNEL_CLOSE: u8 = 97;
pub const MSG_CHANNEL_REQUEST: u8 = 98;
pub const MSG_CHANNEL_SUCCESS: u8 = 99;
pub const MSG_CHANNEL_FAILURE: u8 = 100;

const WINDOW: u32 = 2 * 1024 * 1024;
const MAX_PACKET: u32 = 32 * 1024;

/// How the server runs.
#[derive(Clone, Debug)]
pub struct Config {
    /// sshd_config.
    pub settings: Settings,
    /// Running as root: sessions take the user's IDs. Otherwise (a test
    /// on the host) only the server's own user can log in.
    pub root: bool,
    /// The client's address, for the login records.
    pub peer: String,
    /// The Banner file's text, read at start (the pre-authentication
    /// process cannot read files).
    pub banner_text: Option<Vec<u8>>,
    /// Where interactive logins are recorded.
    pub records: Records,
}

/// Where an interactive login's records (utmp and wtmp, ADR 0057) go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Records {
    /// Nowhere (a test on the host, the pre-authentication process).
    Off,
    /// Asked of the monitor, which writes them as root (the session
    /// process after authentication).
    Monitor,
}

fn record_login(cfg: &Config, pid: i32, line: &[u8]) {
    if cfg.records == Records::Monitor {
        crate::privsep::record_login(pid, line);
    }
}

fn record_logout(cfg: &Config, pid: i32) {
    if cfg.records == Records::Monitor {
        crate::privsep::record_logout(pid);
    }
}

/// A line for the service log and the system log's `auth` facility.
pub fn log(msg: &str) {
    eprintln!("sshd: {msg}");
    let _ = slate_rt::syslog::syslog(slate_rt::syslog::LOG_AUTH | slate_rt::syslog::LOG_INFO, b"sshd", msg.as_bytes());
}

/// The names of the groups `user` is in (/etc/group), for AllowGroups.
fn group_names(user: &User) -> Vec<String> {
    let text = fs::read_file(b"/etc/group").unwrap_or_default();
    lossy(&text)
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            let member = f.get(3).is_some_and(|m| m.split(',').any(|n| n == user.name));
            (f.len() >= 3 && (f[2].parse() == Ok(user.gid) || member)).then(|| String::from(f[0]))
        })
        .collect()
}

/// The group IDs a session of `name` (primary group `gid`) runs with:
/// the primary group, then every group in `group` (/etc/group's text,
/// group(5)) that lists the user as a member, as login gives them
/// (initgroups(3)). The reference PC's first account got only its own group over
/// SSH, so not wheel.
pub fn session_groups(group: &str, name: &str, gid: u32) -> Vec<u32> {
    let mut ids = alloc::vec![gid];
    for l in group.lines() {
        let f: Vec<&str> = l.split(':').collect();
        let Some(id) = f.get(2).and_then(|g| g.parse().ok()) else { continue };
        if f.get(3).is_some_and(|m| m.split(',').any(|n| n == name)) && !ids.contains(&id) {
            ids.push(id);
        }
    }
    ids
}

fn now_secs() -> i64 {
    slate_rt::time::now(slate_rt::time::CLOCK_MONOTONIC).0
}

#[derive(Debug, Default)]
struct Channel {
    ours: u32,
    theirs: u32,
    remote_window: u64,
    remote_max: usize,
    consumed: u32,
    pty: Option<(i32, Vec<u8>)>,
    term: Vec<u8>,
    size: (u16, u16),
    child: Option<i32>,
    stdin: Option<i32>,
    stdout: Option<i32>,
    stderr: Option<i32>,
    status: Option<i32>,
    close_sent: bool,
    /// The client's data the program hasn't taken yet: its stdin or pty
    /// is written without blocking, and the window opens as it takes it.
    inbox: Vec<u8>,
    /// The client sent EOF: close stdin once the inbox is written.
    eof: bool,
}

impl Channel {
    /// Where the client's data goes: the program's stdin or its pty.
    fn input_fd(&self) -> Option<i32> {
        self.stdin.or(self.pty.as_ref().map(|p| p.0))
    }

    fn close_fds(&mut self) {
        for fd in [self.stdin.take(), self.stdout.take(), self.stderr.take()].into_iter().flatten() {
            let _ = io::close(fd);
        }
        if let Some((m, _)) = self.pty.take() {
            let _ = io::close(m);
        }
    }
}

pub type T = Transport<Fd>;

/// Serve one accepted connection: with privilege separation when
/// running as root (ADR 0061: before authentication the client talks to
/// an unprivileged process, after it to one with the user's IDs), else (a
/// test on the host) in one process.
pub fn serve(fd: i32, peer: &str, host: &HostKey, cfg: &Config) -> transport::Result<()> {
    let (mut t, user) = if cfg.root {
        crate::privsep::preauth(fd, peer, host, cfg)?
    } else {
        let mut t = start(fd, cfg)?;
        t.key_exchange(host, None)?;
        let mut judge = Judge::new(cfg, peer);
        let session_id = t.session_id.unwrap_or_default();
        authenticate(&mut t, host, cfg, &mut |m| judge.decide(m, &session_id))?;
        let user = judge.user.take().ok_or_else(|| transport::Error("no user".into()))?;
        (t, user)
    };
    t.deadline = None;
    let cfg = Config {
        peer: String::from(peer.rsplit_once(':').map_or(peer, |(h, _)| h).trim_matches(['[', ']'])),
        ..cfg.clone()
    };
    if cfg.root {
        return crate::privsep::postauth(fd, &t, &user, host, &cfg);
    }
    connection(&mut t, host, &user, &cfg)
}

/// The version exchange, with sshd_config's key exchange methods and
/// LoginGraceTime.
pub fn start(fd: i32, cfg: &Config) -> transport::Result<T> {
    let mut random = [0u8; 32];
    let _ = process::random(&mut random);
    let mut t = Transport::start(Fd(fd), random)?;
    t.kex_methods = cfg.settings.kex.clone();
    if cfg.settings.login_grace > 0 {
        t.deadline = Some(now_secs() + i64::from(cfg.settings.login_grace));
    }
    Ok(t)
}

/// A message that may be a rekey: run it and read on.
fn recv(t: &mut T, host: &dyn HostSign) -> transport::Result<Vec<u8>> {
    loop {
        let m = t.recv()?;
        if m[0] == transport::MSG_KEXINIT {
            t.key_exchange(host, Some(m))?;
            continue;
        }
        return Ok(m);
    }
}

/// The answer to one USERAUTH_REQUEST.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Logged in.
    Success,
    /// The account may not log in now (ageing): disconnect with this.
    Refused(String),
    /// The key would do (PK_OK): algorithm and blob.
    KeyOk(Vec<u8>, Vec<u8>),
    /// Try again: the methods that may continue.
    Failure(Vec<u8>),
    /// MaxAuthTries reached.
    TooMany,
    /// The password was right but has expired: ask for a new one
    /// (PASSWD_CHANGEREQ, RFC 4252 §8) with this prompt.
    ChangeRequest(String),
}

/// The prompt that asks for a new password in place of an expired one.
pub const EXPIRED_PROMPT: &str = "Your password has expired. Choose a new one.";

impl Verdict {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        match self {
            Verdict::Success => w.byte(0),
            Verdict::Refused(why) => w.byte(1).string(why.as_bytes()),
            Verdict::KeyOk(a, b) => w.byte(2).string(a).string(b),
            Verdict::Failure(m) => w.byte(3).string(m),
            Verdict::TooMany => w.byte(4),
            Verdict::ChangeRequest(p) => w.byte(5).string(p.as_bytes()),
        };
        w.finish()
    }

    pub fn decode(b: &[u8]) -> Option<Verdict> {
        let mut r = Reader::new(b);
        Some(match r.byte().ok()? {
            0 => Verdict::Success,
            1 => Verdict::Refused(String::from(lossy(r.string().ok()?))),
            2 => Verdict::KeyOk(r.string().ok()?.to_vec(), r.string().ok()?.to_vec()),
            3 => Verdict::Failure(r.string().ok()?.to_vec()),
            4 => Verdict::TooMany,
            5 => Verdict::ChangeRequest(String::from(lossy(r.string().ok()?))),
            _ => return None,
        })
    }
}

/// The decisions about authentication, made with the privileges to read
/// /etc/shadow and users' keys: sshd_config's rules, the methods,
/// password ageing, MaxAuthTries and the slowdown after a wrong password.
#[derive(Debug)]
pub struct Judge<'a> {
    cfg: &'a Config,
    peer: String,
    failures: u32,
    /// Who logged in, once someone has.
    pub user: Option<User>,
}

impl<'a> Judge<'a> {
    pub fn new(cfg: &'a Config, peer: &str) -> Judge<'a> {
        Judge { cfg, peer: peer.into(), failures: 0, user: None }
    }

    fn methods(&self) -> Vec<u8> {
        let s = &self.cfg.settings;
        let m: Vec<&[u8]> =
            [(s.pubkey, &b"publickey"[..]), (s.password, b"password")].iter().filter(|m| m.0).map(|m| m.1).collect();
        m.join(&b',')
    }

    /// One USERAUTH_REQUEST (without its message number).
    pub fn decide(&mut self, msg: &[u8], session_id: &[u8]) -> Verdict {
        let (s, peer) = (&self.cfg.settings, self.peer.clone());
        if self.user.is_some() || self.failures >= s.max_auth_tries {
            return Verdict::TooMany;
        }
        let mut r = Reader::new(msg);
        let (Ok(name), Ok(_), Ok(method)) = (r.string(), r.string(), r.string()) else {
            return Verdict::Failure(self.methods());
        };
        let (name, method) = (String::from(lossy(name)), method.to_vec());
        let me = process::getuid();
        let root = self.cfg.root;
        let find = move |name: &str| auth::lookup(name).filter(|u| root || u.uid == me);
        let read = |p: &str| fs::read_file(p.as_bytes()).ok().map(|d| String::from(lossy(&d)));
        let enabled = self.methods();
        let allowed_method = enabled.split(|&c| c == b',').any(|m| m == method.as_slice());
        let refused = if !allowed_method {
            true
        } else if let Some(u) = find(&name) {
            let root_ok = u.uid != 0
                || match s.permit_root {
                    RootLogin::Yes => true,
                    RootLogin::ProhibitPassword => method == b"publickey",
                    RootLogin::ForcedCommandsOnly | RootLogin::No => false,
                };
            let allowed = crate::config::user_allowed(s, &u.name, &group_names(&u));
            if !allowed {
                log(&format!("{name} from {peer}: not allowed by AllowUsers/DenyUsers/AllowGroups/DenyGroups"));
            }
            !root_ok || !allowed
        } else {
            false
        };
        let outcome =
            if refused { Outcome::Failure } else { auth::decide(msg, session_id, &s.authorized_keys, &find, &read) };
        match outcome {
            Outcome::Success(mut u) => {
                // Password ageing (shadow(5), ADRs 0057, 0143): an expired
                // account gets no session; a password that must be changed
                // is asked for again (RFC 4252 §8), and after a key the
                // session changes it first.
                match slate_login::accounts::ageing(u.name.as_bytes()) {
                    _ if !self.cfg.root => {}
                    slate_login::accounts::Ageing::Refused(m) => {
                        log(&format!("{} from {peer} refused: {m}", u.name));
                        self.failures = s.max_auth_tries;
                        return Verdict::Refused(m.into());
                    }
                    slate_login::accounts::Ageing::MustChange if method == b"password" => {
                        log(&format!("{} from {peer}: the password has expired, a new one asked for", u.name));
                        return Verdict::ChangeRequest(String::from(EXPIRED_PROMPT));
                    }
                    slate_login::accounts::Ageing::MustChange => u.expired = true,
                    _ => {}
                }
                log(&format!("{} logged in from {peer} ({})", u.name, lossy(&method)));
                self.user = Some(u);
                Verdict::Success
            }
            Outcome::Change { user, old, new } => {
                // Only an expired password is changed here; the broker
                // changes it (and the disk's, ADR 0058) as for passwd.
                let expired = !self.cfg.root
                    || slate_login::accounts::ageing(user.name.as_bytes()) == slate_login::accounts::Ageing::MustChange;
                let changed = if !expired {
                    Err(String::from("the password has not expired"))
                } else if new == old {
                    Err(String::from("the new password is the old one"))
                } else if self.cfg.root {
                    slate_login::broker::request(&[b"passwd", user.name.as_bytes(), &old, &new])
                } else {
                    Err(String::from("not running as root"))
                };
                match changed {
                    Ok(()) => {
                        log(&format!("{} from {peer}: password changed; logged in", user.name));
                        self.user = Some(user);
                        Verdict::Success
                    }
                    Err(e) => {
                        log(&format!("{} from {peer}: password not changed ({e})", user.name));
                        self.failures += 1;
                        if self.failures >= s.max_auth_tries {
                            return Verdict::TooMany;
                        }
                        Verdict::Failure(self.methods())
                    }
                }
            }
            Outcome::KeyAcceptable { algorithm, blob } => Verdict::KeyOk(algorithm, blob),
            Outcome::Failure => {
                if method != b"none" {
                    self.failures += 1;
                }
                if method == b"password" {
                    log(&format!("failed password for {name} from {peer}"));
                    // Slow down guessing.
                    slate_rt::time::sleep_ns(1_000_000_000);
                }
                if self.failures >= s.max_auth_tries {
                    log(&format!("too many authentication failures for {name} from {peer}"));
                    return Verdict::TooMany;
                }
                Verdict::Failure(enabled)
            }
        }
    }
}

/// User authentication (RFC 4252) as `judge` decides each request.
pub fn authenticate(
    t: &mut T,
    host: &dyn HostSign,
    cfg: &Config,
    judge: &mut dyn FnMut(&[u8]) -> Verdict,
) -> transport::Result<()> {
    let m = recv(t, host)?;
    if m[0] != MSG_SERVICE_REQUEST || Reader::new(&m[1..]).string()? != b"ssh-userauth" {
        let _ = t.disconnect(transport::PROTOCOL_ERROR, "expected ssh-userauth");
        return err("the client did not ask for ssh-userauth");
    }
    t.send(&Writer::new(MSG_SERVICE_ACCEPT).string(b"ssh-userauth").finish())?;
    if let Some(text) = &cfg.banner_text {
        t.send(&Writer::new(MSG_USERAUTH_BANNER).string(text).string(b"").finish())?;
    }
    loop {
        let m = recv(t, host)?;
        if m[0] != MSG_USERAUTH_REQUEST {
            continue;
        }
        match judge(&m[1..]) {
            Verdict::Success => {
                t.send(&[MSG_USERAUTH_SUCCESS])?;
                return Ok(());
            }
            Verdict::Refused(why) => {
                let _ = t.disconnect(transport::NO_MORE_AUTH_METHODS, &why);
                return err(why);
            }
            Verdict::KeyOk(algorithm, blob) => {
                t.send(&Writer::new(MSG_USERAUTH_PK_OK).string(&algorithm).string(&blob).finish())?;
            }
            Verdict::ChangeRequest(prompt) => {
                t.send(&Writer::new(MSG_USERAUTH_PASSWD_CHANGEREQ).string(prompt.as_bytes()).string(b"").finish())?;
            }
            Verdict::Failure(methods) => {
                t.send(&Writer::new(MSG_USERAUTH_FAILURE).string(&methods).bool(false).finish())?;
            }
            Verdict::TooMany => {
                let _ = t.disconnect(transport::NO_MORE_AUTH_METHODS, "too many authentication failures");
                return err("too many authentication failures");
            }
        }
    }
}

fn signal_name(sig: i32) -> &'static [u8] {
    match sig {
        signal::SIGHUP => b"HUP",
        signal::SIGINT => b"INT",
        signal::SIGQUIT => b"QUIT",
        signal::SIGKILL => b"KILL",
        signal::SIGSEGV => b"SEGV",
        signal::SIGPIPE => b"PIPE",
        signal::SIGALRM => b"ALRM",
        signal::SIGTERM => b"TERM",
        signal::SIGABRT => b"ABRT",
        _ => b"USR1",
    }
}

/// What a session channel runs.
enum Program<'a> {
    /// The user's login shell.
    Login,
    /// `shell -c command` (exec, or a subsystem's program).
    Command(&'a [u8]),
    /// Our own sftp-server (`internal-sftp`).
    Sftp,
}

/// Start the session's program.
fn spawn(ch: &mut Channel, user: &User, program: Program<'_>, cfg: &Config) -> Result<(), String> {
    let mut pipes: Option<[(i32, i32); 3]> = None;
    if ch.pty.is_none() {
        let mk = || process::pipe(fs::O_CLOEXEC).map_err(|e| format!("pipe: {e}"));
        pipes = Some([mk()?, mk()?, mk()?]);
    }
    let shell = user.shell.clone();
    let base = shell.rsplit('/').next().unwrap_or("sh");
    // internal-sftp runs this very program as sftp-server.
    let self_exe = fs::readlink(b"/proc/self/exe").unwrap_or_else(|_| b"/bin/sshd".to_vec());
    // After a key with an expired password, the session changes the
    // password first, as OpenSSH does without PAM, and ends.
    let expired_script: &[u8] = if ch.pty.is_some() && matches!(program, Program::Login) {
        b"echo 'WARNING: Your password has expired.'; echo 'You must change your password now and log in again!'; exec passwd"
    } else {
        b"echo 'Your password has expired; log in with a terminal to change it.' >&2; exit 1"
    };
    let (path, argv): (Vec<u8>, Vec<Vec<u8>>) = match program {
        _ if user.expired => (b"/bin/sh".to_vec(), vec![b"sh".to_vec(), b"-c".to_vec(), expired_script.to_vec()]),
        Program::Command(c) => {
            (shell.clone().into_bytes(), vec![shell.clone().into_bytes(), b"-c".to_vec(), c.to_vec()])
        }
        Program::Login => (shell.clone().into_bytes(), vec![format!("-{base}").into_bytes()]),
        Program::Sftp => (self_exe, vec![b"sftp-server".to_vec()]),
    };
    let mut env = vec![
        format!("HOME={}", user.home).into_bytes(),
        format!("USER={}", user.name).into_bytes(),
        format!("LOGNAME={}", user.name).into_bytes(),
        format!("SHELL={shell}").into_bytes(),
        b"PATH=/bin:/sbin:/usr/bin:/usr/sbin".to_vec(),
    ];
    if ch.pty.is_some() {
        let term = if ch.term.is_empty() { b"xterm".to_vec() } else { ch.term.clone() };
        env.push([b"TERM=".as_slice(), &term].concat());
    }
    let groups = session_groups(&lossy(&fs::read_file(b"/etc/group").unwrap_or_default()), &user.name, user.gid);
    match process::fork() {
        Ok(0) => {
            let _ = process::setsid();
            if let Some((_, path)) = &ch.pty {
                let Ok(fd) = fs::open(path, fs::O_RDWR, 0) else { process::exit_now(126) };
                let _ = term::set_controlling(fd);
                let _ = term::set_size(fd, ch.size.0, ch.size.1);
                for n in 0..3 {
                    let _ = process::dup2(fd, n);
                }
            } else if let Some(p) = pipes {
                let _ = process::dup2(p[0].0, 0);
                let _ = process::dup2(p[1].1, 1);
                let _ = process::dup2(p[2].1, 2);
            }
            for s in 1..32 {
                let _ = signal::set(s, signal::Disposition::Default);
            }
            let _ = signal::set_mask(0);
            if cfg.root
                && (process::setgroups(&groups).is_err()
                    || process::setgid(user.gid).is_err()
                    || process::setuid(user.uid).is_err())
            {
                process::exit_now(126);
            }
            if fs::chdir(user.home.as_bytes()).is_err() {
                let _ = fs::chdir(b"/");
            }
            let e = process::execve(&path, &argv, &env);
            eprintln!("{}: {e}", lossy(&path));
            process::exit_now(127);
        }
        Ok(pid) => {
            ch.child = Some(pid);
            // An interactive login on a pty: the login records (ADR 0057).
            if matches!(program, Program::Login)
                && let Some((_, path)) = &ch.pty
            {
                let line = path.strip_prefix(b"/dev/").unwrap_or(path);
                record_login(cfg, pid, line);
            }
            if let Some(p) = pipes {
                let _ = io::close(p[0].0);
                let _ = io::close(p[1].1);
                let _ = io::close(p[2].1);
                ch.stdin = Some(p[0].1);
                nonblocking(p[0].1);
                ch.stdout = Some(p[1].0);
                ch.stderr = Some(p[2].0);
            } else if let Some((m, _)) = &ch.pty {
                ch.stdout = Some(*m);
                nonblocking(*m);
            }
            Ok(())
        }
        Err(e) => {
            if let Some(p) = pipes {
                for (a, b) in p {
                    let _ = io::close(a);
                    let _ = io::close(b);
                }
            }
            Err(format!("fork: {e}"))
        }
    }
}

fn channel_request(t: &mut T, ch: &mut Channel, msg: &[u8], user: &User, cfg: &Config) -> transport::Result<()> {
    let mut r = Reader::new(msg);
    let _ = r.u32()?;
    let kind = r.string()?.to_vec();
    let want = r.bool()?;
    let ok = match kind.as_slice() {
        b"pty-req" if ch.pty.is_none() && ch.child.is_none() => {
            ch.term = r.string()?.to_vec();
            let (cols, rows) = (r.u32()?, r.u32()?);
            ch.size = (rows.min(1000) as u16, cols.min(1000) as u16);
            match term::open_pty() {
                Ok((m, path)) => {
                    let _ = term::set_size(m, ch.size.0, ch.size.1);
                    ch.pty = Some((m, path));
                    true
                }
                Err(_) => false,
            }
        }
        b"window-change" => {
            let (cols, rows) = (r.u32()?, r.u32()?);
            ch.size = (rows.min(1000) as u16, cols.min(1000) as u16);
            if let Some((m, _)) = &ch.pty {
                let _ = term::set_size(*m, ch.size.0, ch.size.1);
            }
            true
        }
        b"env" => true,
        // The sftp subsystem (ADR 0061): ours, or the configured program.
        b"subsystem" if ch.child.is_none() => {
            let name = r.string()?;
            match (name, &cfg.settings.sftp) {
                (b"sftp", Some(prog)) => {
                    let program =
                        if prog == "internal-sftp" { Program::Sftp } else { Program::Command(prog.as_bytes()) };
                    match spawn(ch, user, program, cfg) {
                        Ok(()) => true,
                        Err(e) => {
                            eprintln!("sshd: {e}");
                            false
                        }
                    }
                }
                _ => false,
            }
        }
        b"shell" | b"exec" if ch.child.is_none() => {
            let cmd = if kind == b"exec" { Some(r.string()?.to_vec()) } else { None };
            // PrintMotd: /etc/motd before an interactive shell.
            if cmd.is_none()
                && ch.pty.is_some()
                && cfg.settings.print_motd
                && let Ok(motd) = fs::read_file(b"/etc/motd")
                && !motd.is_empty()
            {
                let text: Vec<u8> =
                    motd.iter().flat_map(|&c| if c == b'\n' { vec![b'\r', b'\n'] } else { vec![c] }).collect();
                let n = text.len().min(ch.remote_window as usize).min(ch.remote_max);
                t.send(&Writer::new(MSG_CHANNEL_DATA).u32(ch.theirs).string(&text[..n]).finish())?;
                ch.remote_window -= n as u64;
            }
            let program = match &cmd {
                Some(c) => Program::Command(c),
                None => Program::Login,
            };
            match spawn(ch, user, program, cfg) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("sshd: {e}");
                    false
                }
            }
        }
        _ => false,
    };
    if want {
        let code = if ok { MSG_CHANNEL_SUCCESS } else { MSG_CHANNEL_FAILURE };
        t.send(&Writer::new(code).u32(ch.theirs).finish())?;
    }
    Ok(())
}

/// Read what a channel's program wrote and pass it on, within the
/// client's window. Returns false at end of file.
fn nonblocking(fd: i32) {
    if let Ok(flags) = process::fcntl(fd, process::F_GETFL, 0) {
        let _ = process::fcntl(fd, process::F_SETFL, flags | fs::O_NONBLOCK as usize);
    }
}

/// Give the program what it will take of the inbox (a full pty or pipe
/// keeps the rest), and open the client's window by as much.
fn feed(t: &mut T, ch: &mut Channel) -> transport::Result<()> {
    let mut taken = 0;
    if let Some(fd) = ch.input_fd() {
        while taken < ch.inbox.len() {
            match io::write(fd, &ch.inbox[taken..]) {
                Ok(0) => break,
                Ok(n) => taken += n,
                Err(slate_rt::Errno::EAGAIN) => break,
                Err(slate_rt::Errno::EINTR) => {}
                // The program is gone: what it didn't take is dropped.
                Err(_) => {
                    taken = ch.inbox.len();
                    break;
                }
            }
        }
    } else {
        taken = ch.inbox.len();
    }
    ch.inbox.drain(..taken);
    ch.consumed += taken as u32;
    if ch.consumed >= WINDOW / 2 {
        t.send(&Writer::new(MSG_CHANNEL_WINDOW_ADJUST).u32(ch.theirs).u32(ch.consumed).finish())?;
        ch.consumed = 0;
    }
    if ch.inbox.is_empty()
        && ch.eof
        && let Some(fd) = ch.stdin.take()
    {
        let _ = io::close(fd);
    }
    Ok(())
}

fn forward(t: &mut T, ch: &mut Channel, fd: i32, ext: bool) -> transport::Result<bool> {
    let room = (ch.remote_window as usize).min(ch.remote_max).min(MAX_PACKET as usize);
    if room == 0 {
        return Ok(true);
    }
    let mut buf = vec![0u8; room];
    let n = match io::read(fd, &mut buf) {
        Err(slate_rt::Errno::EAGAIN | slate_rt::Errno::EINTR) => return Ok(true),
        Ok(0) | Err(_) => return Ok(false),
        Ok(n) => n,
    };
    let m = if ext {
        Writer::new(MSG_CHANNEL_EXTENDED_DATA).u32(ch.theirs).u32(1).string(&buf[..n]).finish()
    } else {
        Writer::new(MSG_CHANNEL_DATA).u32(ch.theirs).string(&buf[..n]).finish()
    };
    t.send(&m)?;
    ch.remote_window -= n as u64;
    Ok(true)
}

/// The child exited and its output is drained: report and close.
fn finish(t: &mut T, ch: &mut Channel) -> transport::Result<()> {
    if let Some(st) = ch.status {
        let m = match process::signaled(st) {
            Some(sig) => Writer::new(MSG_CHANNEL_REQUEST)
                .u32(ch.theirs)
                .string(b"exit-signal")
                .bool(false)
                .string(signal_name(sig))
                .bool(false)
                .string(b"")
                .string(b"")
                .finish(),
            None => Writer::new(MSG_CHANNEL_REQUEST)
                .u32(ch.theirs)
                .string(b"exit-status")
                .bool(false)
                .u32(process::exit_code(st) as u32)
                .finish(),
        };
        t.send(&Writer::new(MSG_CHANNEL_EOF).u32(ch.theirs).finish())?;
        t.send(&m)?;
    }
    t.send(&Writer::new(MSG_CHANNEL_CLOSE).u32(ch.theirs).finish())?;
    ch.close_sent = true;
    ch.close_fds();
    Ok(())
}

fn hang_up(chans: &mut [Channel], cfg: &Config) {
    for ch in chans.iter_mut() {
        if let Some(pid) = ch.child.take() {
            let _ = process::kill(-pid, signal::SIGHUP);
            let _ = process::kill(pid, signal::SIGHUP);
            let _ = process::wait(pid, 0);
            record_logout(cfg, pid);
        }
        ch.close_fds();
    }
}

pub(crate) fn connection(t: &mut T, host: &dyn HostSign, user: &User, cfg: &Config) -> transport::Result<()> {
    let mut chans: Vec<Channel> = Vec::new();
    let mut next_id = 0u32;
    let s = &cfg.settings;
    // ClientAliveInterval: when the client was last heard from, and the
    // keepalives it has not answered.
    let mut heard = now_secs();
    let mut unanswered = 0u32;
    let r = (|| -> transport::Result<()> {
        loop {
            if t.rekey_due(s.rekey_bytes, i64::from(s.rekey_secs)) {
                t.rekey(host)?;
            }
            if s.alive_interval > 0 && now_secs() - heard >= i64::from(s.alive_interval) {
                if unanswered >= s.alive_count {
                    log(&format!("{}: timeout, the client is not responding", cfg.peer));
                    let _ = t.disconnect(transport::BY_APPLICATION, "Timeout, your session not responding.");
                    return err("the client stopped answering keepalives");
                }
                t.send(&Writer::new(MSG_GLOBAL_REQUEST).string(b"keepalive@openssh.com").bool(true).finish())?;
                unanswered += 1;
                heard = now_secs();
            }
            // Wait for the client or a program's output.
            let mut fds = vec![PollFd { fd: t.stream.0, events: POLLIN, revents: 0 }];
            let mut owners = Vec::new();
            for (i, ch) in chans.iter().enumerate() {
                if ch.remote_window == 0 {
                    continue;
                }
                for (fd, ext) in [(ch.stdout, false), (ch.stderr, true)] {
                    if let Some(fd) = fd {
                        fds.push(PollFd { fd, events: POLLIN, revents: 0 });
                        owners.push((i, fd, ext));
                    }
                }
            }
            // Programs that haven't taken all the client's data yet.
            let mut feeding = Vec::new();
            for (i, ch) in chans.iter().enumerate() {
                if !ch.inbox.is_empty()
                    && let Some(fd) = ch.input_fd()
                {
                    feeding.push((i, fds.len()));
                    fds.push(PollFd { fd, events: POLLOUT, revents: 0 });
                }
            }
            let waiting = chans.iter().any(|c| c.child.is_some() && c.status.is_none());
            let mut timeout = if t.pending() {
                0
            } else if waiting {
                200
            } else {
                -1
            };
            // Wake for the next keepalive or timed rekey.
            for secs in [
                (s.alive_interval > 0).then(|| heard + i64::from(s.alive_interval) - now_secs()),
                (s.rekey_secs > 0).then(|| t.kex_time + i64::from(s.rekey_secs) - now_secs()),
            ]
            .into_iter()
            .flatten()
            {
                let ms = (secs.max(0) * 1000 + 10).min(i64::from(i32::MAX)) as i32;
                timeout = if timeout < 0 { ms } else { timeout.min(ms) };
            }
            match io::poll(&mut fds, timeout) {
                Ok(_) | Err(slate_rt::Errno::EINTR) => {}
                Err(e) => return err(format!("poll: {e}")),
            }
            if t.pending() || fds[0].revents & (POLLIN | POLLHUP) != 0 {
                let m = recv(t, host)?;
                heard = now_secs();
                unanswered = 0;
                handle(t, &mut chans, &mut next_id, &m, user, cfg)?;
            }
            for &(i, k) in &feeding {
                if fds[k].revents & (POLLOUT | POLLERR | POLLHUP) != 0 {
                    feed(t, &mut chans[i])?;
                }
            }
            for (k, &(i, fd, ext)) in owners.iter().enumerate() {
                if fds[k + 1].revents & (POLLIN | POLLHUP) == 0 || chans[i].close_sent {
                    continue;
                }
                if !forward(t, &mut chans[i], fd, ext)? {
                    let ch = &mut chans[i];
                    if ch.stdout == Some(fd) {
                        ch.stdout = None;
                    } else {
                        ch.stderr = None;
                    }
                    if ch.pty.as_ref().is_none_or(|(m, _)| *m != fd) {
                        let _ = io::close(fd);
                    }
                }
            }
            for ch in chans.iter_mut() {
                if let (Some(pid), None) = (ch.child, ch.status)
                    && let Ok((p, st)) = process::wait(pid, process::WNOHANG)
                    && p == pid
                {
                    ch.status = Some(st);
                    record_logout(cfg, pid);
                }
                // Done: the program exited and its output is all sent (a
                // pty's output: what is readable right now).
                if ch.status.is_some() && !ch.close_sent {
                    if let Some(m) = ch.stdout.filter(|_| ch.pty.is_some()) {
                        let mut p = [PollFd { fd: m, events: POLLIN, revents: 0 }];
                        while ch.remote_window > 0
                            && io::poll(&mut p, 0).is_ok_and(|n| n > 0)
                            && p[0].revents & POLLIN != 0
                            && forward(t, ch, m, false)?
                        {}
                        ch.stdout = None;
                    }
                    if ch.stdout.is_none() && ch.stderr.is_none() {
                        finish(t, ch)?;
                    }
                }
            }
        }
    })();
    hang_up(&mut chans, cfg);
    r
}

fn handle(
    t: &mut T,
    chans: &mut Vec<Channel>,
    next_id: &mut u32,
    m: &[u8],
    user: &User,
    cfg: &Config,
) -> transport::Result<()> {
    let mut r = Reader::new(&m[1..]);
    let find = |chans: &mut Vec<Channel>, id: u32| chans.iter().position(|c| c.ours == id);
    match m[0] {
        MSG_GLOBAL_REQUEST => {
            let _ = r.string()?;
            if r.bool()? {
                t.send(&[MSG_REQUEST_FAILURE])?;
            }
        }
        MSG_CHANNEL_OPEN => {
            let kind = r.string()?.to_vec();
            let (theirs, window, max) = (r.u32()?, r.u32()?, r.u32()?);
            if kind != b"session" || chans.len() >= 10 {
                let m = Writer::new(MSG_CHANNEL_OPEN_FAILURE)
                    .u32(theirs)
                    .u32(1)
                    .string(b"only session channels are supported")
                    .string(b"")
                    .finish();
                return t.send(&m);
            }
            let ours = *next_id;
            *next_id += 1;
            chans.push(Channel {
                ours,
                theirs,
                remote_window: u64::from(window),
                remote_max: (max as usize).max(1),
                size: (24, 80),
                ..Channel::default()
            });
            let m =
                Writer::new(MSG_CHANNEL_OPEN_CONFIRMATION).u32(theirs).u32(ours).u32(WINDOW).u32(MAX_PACKET).finish();
            t.send(&m)?;
        }
        MSG_CHANNEL_REQUEST => {
            let id = Reader::new(&m[1..]).u32()?;
            if let Some(i) = find(chans, id) {
                channel_request(t, &mut chans[i], &m[1..], user, cfg)?;
            }
        }
        MSG_CHANNEL_WINDOW_ADJUST => {
            let (id, n) = (r.u32()?, r.u32()?);
            if let Some(i) = find(chans, id) {
                chans[i].remote_window += u64::from(n);
            }
        }
        MSG_CHANNEL_DATA => {
            let id = r.u32()?;
            let data = r.string()?;
            if let Some(i) = find(chans, id) {
                let ch = &mut chans[i];
                ch.inbox.extend_from_slice(data);
                feed(t, ch)?;
            }
        }
        MSG_CHANNEL_EOF => {
            let id = r.u32()?;
            if let Some(i) = find(chans, id) {
                chans[i].eof = true;
                feed(t, &mut chans[i])?;
            }
        }
        MSG_CHANNEL_CLOSE => {
            let id = r.u32()?;
            if let Some(i) = find(chans, id) {
                let mut ch = chans.remove(i);
                if !ch.close_sent {
                    t.send(&Writer::new(MSG_CHANNEL_CLOSE).u32(ch.theirs).finish())?;
                }
                hang_up(core::slice::from_mut(&mut ch), cfg);
            }
        }
        transport::MSG_UNIMPLEMENTED
        | MSG_CHANNEL_SUCCESS
        | MSG_CHANNEL_FAILURE
        | MSG_CHANNEL_EXTENDED_DATA
        | MSG_USERAUTH_REQUEST => {}
        _ => {
            // RFC 4253 §11.4: UNIMPLEMENTED with the rejected sequence
            // number is optional; ignoring is allowed by most clients, so
            // the message is just dropped.
        }
    }
    Ok(())
}
