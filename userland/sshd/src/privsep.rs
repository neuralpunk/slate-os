// SPDX-License-Identifier: MIT OR Apache-2.0

//! Privilege separation before authentication (ADR 0061). For each
//! connection the root process starts sshd again as `sshd-preauth`, a
//! fresh program (so no host key in its memory) that confines itself to
//! the empty, root-owned /var/empty as the `sshd` user and handles
//! everything the client sends until it has logged in: version exchange,
//! key exchange, packets, and authentication requests. It asks the root
//! process ("the monitor"), over a pair of pipes, for what it cannot do
//! itself: a host-key signature, and a verdict on each authentication
//! request. The monitor takes the first signed exchange hash as the
//! session identifier, counts failures, and remembers who logged in; it
//! never takes the child's word for that. On success the child sends the
//! connection's state and exits.
//!
//! After authentication the monitor starts sshd again as `sshd-session`
//! with the user's IDs (and groups), and hands it the connection's state:
//! that process runs the session and the user's programs, so nothing the
//! client sends after logging in is handled with root's privileges. It
//! asks the monitor for host-key signatures (rekeys) and for the login
//! records, which only root may write; the monitor checks that a record
//! is for one of that process's children on a pseudo-terminal.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::io::{POLLHUP, POLLIN, PollFd};
use slate_rt::{eprintln, fs, io, lossy, process};

use crate::auth::User;
use crate::crypto::{HostKey, HostSign};
use crate::session::{self, Config, Judge, T, Verdict};
use crate::transport::{self, Fd, Transport, err};
use crate::wire::{Reader, Writer};

/// Where the child confines itself.
const EMPTY: &[u8] = b"/var/empty";
/// The child's descriptors: the connection, then the pipes from and to
/// the monitor.
const CONN: i32 = 3;
const FROM_MONITOR: i32 = 4;
const TO_MONITOR: i32 = 5;

// Messages between the two: u32 length, a type byte, then its data.
const CONFIG: u8 = b'C';
const SIGN: u8 = b'S';
const AUTH: u8 = b'A';
const STATE: u8 = b'T';
const LOGIN: u8 = b'L';
const LOGOUT: u8 = b'O';
/// The most signatures a child may ask for (the first key exchange and
/// a few rekeys before authentication).
const MAX_SIGNATURES: u32 = 4;

fn send_frame(fd: i32, kind: u8, data: &[u8]) -> transport::Result<()> {
    let mut f = ((data.len() + 1) as u32).to_be_bytes().to_vec();
    f.push(kind);
    f.extend_from_slice(data);
    io::write_all(fd, &f).map_err(|e| transport::Error(format!("monitor pipe: {e}")))
}

fn read_exact(fd: i32, n: usize) -> transport::Result<Vec<u8>> {
    let mut out = alloc::vec![0u8; n];
    let mut got = 0;
    while got < n {
        match io::read(fd, &mut out[got..]) {
            Ok(0) => return err("the other process closed its pipe"),
            Ok(k) => got += k,
            Err(slate_rt::Errno::EINTR) => {}
            Err(e) => return err(format!("monitor pipe: {e}")),
        }
    }
    Ok(out)
}

fn recv_frame(fd: i32) -> transport::Result<(u8, Vec<u8>)> {
    let len = u32::from_be_bytes(read_exact(fd, 4)?.try_into().unwrap()) as usize;
    if len == 0 || len > 1 << 20 {
        return err("a bad message on the monitor pipe");
    }
    let mut f = read_exact(fd, len)?;
    let kind = f.remove(0);
    Ok((kind, f))
}

/// The unprivileged account: `sshd`, else `nobody`.
fn unprivileged() -> (u32, u32) {
    crate::auth::lookup("sshd").or_else(|| crate::auth::lookup("nobody")).map_or((65534, 65534), |u| (u.uid, u.gid))
}

/// The monitor's side: start the child, answer it, and take over the
/// connection once someone has logged in.
pub fn preauth(fd: i32, peer: &str, host: &HostKey, cfg: &Config) -> transport::Result<(T, User)> {
    let pipe = || process::pipe(fs::O_CLOEXEC).map_err(|e| transport::Error(format!("pipe: {e}")));
    let (to_child_r, to_child_w) = pipe()?;
    let (from_child_r, from_child_w) = pipe()?;
    if !fs::exists(EMPTY) {
        let _ = fs::mkdir(EMPTY, 0o755);
    }
    let exe = fs::readlink(b"/proc/self/exe").unwrap_or_else(|_| b"/bin/sshd".to_vec());
    let pid = match process::fork() {
        Ok(0) => {
            // The child's descriptors in their places (first moved above
            // them, so none is overwritten); everything else is
            // close-on-exec.
            let up = |f: i32| process::fcntl(f, 0, 10).map(|n| n as i32);
            let (c, r, w) = (up(fd), up(to_child_r), up(from_child_w));
            if let (Ok(c), Ok(r), Ok(w)) = (c, r, w) {
                let _ = process::dup2(c, CONN);
                let _ = process::dup2(r, FROM_MONITOR);
                let _ = process::dup2(w, TO_MONITOR);
                let e = process::execve(&exe, &[b"sshd-preauth".to_vec()], &[]);
                eprintln!("sshd: {}: {e}", lossy(&exe));
            }
            process::exit_now(1);
        }
        Ok(pid) => pid,
        Err(e) => return err(format!("fork: {e}")),
    };
    let _ = io::close(to_child_r);
    let _ = io::close(from_child_w);
    let (ours_r, ours_w) = (from_child_r, to_child_w);
    let finish = |r: transport::Result<(T, User)>| {
        let _ = io::close(ours_r);
        let _ = io::close(ours_w);
        if r.is_err() {
            let _ = process::kill(pid, slate_rt::signal::SIGKILL);
        }
        let _ = process::wait(pid, 0);
        r
    };
    // What the child needs, as it can read no files.
    let (uid, gid) = unprivileged();
    let mut w = Writer::default();
    w.u32(uid).u32(gid).u32(cfg.settings.login_grace).string(&host.blob());
    w.string(cfg.banner_text.as_deref().unwrap_or_default()).bool(cfg.banner_text.is_some());
    w.u32(cfg.settings.kex.len() as u32);
    for k in &cfg.settings.kex {
        w.string(k);
    }
    if let Err(e) = send_frame(ours_w, CONFIG, &w.finish()) {
        return finish(Err(e));
    }
    let mut judge = Judge::new(cfg, peer);
    let mut session_id: Option<Vec<u8>> = None;
    let mut signatures = 0;
    // LoginGraceTime, with room for the child's own clock.
    let deadline = (cfg.settings.login_grace > 0).then(|| now_secs() + i64::from(cfg.settings.login_grace) + 10);
    let r = loop {
        if let Some(d) = deadline {
            let left = d - now_secs();
            let mut p = [PollFd { fd: ours_r, events: POLLIN, revents: 0 }];
            if left <= 0 || io::poll(&mut p, (left * 1000) as i32).unwrap_or(0) == 0 {
                if p[0].revents & (POLLIN | POLLHUP) == 0 && now_secs() >= d {
                    break err("the client did not log in in time");
                }
                continue;
            }
        }
        let (kind, data) = match recv_frame(ours_r) {
            Ok(f) => f,
            Err(_) => break err("the connection ended before authentication"),
        };
        match kind {
            SIGN => {
                signatures += 1;
                if data.len() != 32 || signatures > MAX_SIGNATURES {
                    break err("the pre-authentication process asked for a bad signature");
                }
                // The first exchange hash is the session identifier.
                session_id.get_or_insert_with(|| data.clone());
                if let Err(e) = send_frame(ours_w, SIGN, &host.sign(&data)) {
                    break Err(e);
                }
            }
            AUTH => {
                let Some(sid) = &session_id else { break err("authentication before key exchange") };
                let v = judge.decide(&data, sid);
                if let Err(e) = send_frame(ours_w, AUTH, &v.encode()) {
                    break Err(e);
                }
            }
            STATE => {
                let Some(user) = judge.user.take() else {
                    break err("the pre-authentication process sent its state with nobody logged in");
                };
                break Transport::import(Fd(fd), &data, cfg.settings.kex.clone()).map(|t| (t, user));
            }
            _ => break err("an unknown message from the pre-authentication process"),
        }
    };
    finish(r)
}

fn now_secs() -> i64 {
    slate_rt::time::now(slate_rt::time::CLOCK_MONOTONIC).0
}

/// Signatures by the monitor.
struct MonitorSigner {
    blob: Vec<u8>,
}

impl HostSign for MonitorSigner {
    fn blob(&self) -> Vec<u8> {
        self.blob.clone()
    }
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        if send_frame(TO_MONITOR, SIGN, data).is_err() {
            return Vec::new();
        }
        match recv_frame(FROM_MONITOR) {
            Ok((SIGN, sig)) => sig,
            _ => Vec::new(),
        }
    }
}

/// `sshd-preauth`: the child's side.
pub fn child_main() -> i32 {
    match child() {
        Ok(()) => 0,
        Err(e) => {
            session::log(&e.0);
            1
        }
    }
}

fn child() -> transport::Result<()> {
    let (kind, data) = recv_frame(FROM_MONITOR)?;
    if kind != CONFIG {
        return err("no configuration from the monitor");
    }
    let mut r = Reader::new(&data);
    let (uid, gid, grace) = (r.u32()?, r.u32()?, r.u32()?);
    let blob = r.string()?.to_vec();
    let banner = r.string()?.to_vec();
    let has_banner = r.bool()?;
    let mut kex = Vec::new();
    for _ in 0..r.u32()? {
        let name = r.string()?;
        if let Some(k) = crate::config::KEX_ALL.iter().find(|k| **k == name) {
            kex.push(*k);
        }
    }
    // Confined: no file system, no privileges, before reading anything
    // the client sent.
    let confined = fs::chroot(EMPTY)
        .and_then(|()| fs::chdir(b"/"))
        .and_then(|()| process::setgroups(&[gid]))
        .and_then(|()| process::setgid(gid))
        .and_then(|()| process::setuid(uid));
    if let Err(e) = confined {
        return err(format!("cannot drop privileges: {e}"));
    }
    if process::getuid() != uid || process::geteuid() != uid || fs::chdir(b"/etc").is_ok() {
        return err("privileges were not dropped");
    }
    let mut random = [0u8; 32];
    let _ = process::random(&mut random);
    let mut t = Transport::start(Fd(CONN), random)?;
    t.kex_methods = kex;
    if grace > 0 {
        t.deadline = Some(now_secs() + i64::from(grace));
    }
    let signer = MonitorSigner { blob };
    t.key_exchange(&signer, None)?;
    // Only what the client needs; nothing else of the configuration.
    let cfg = Config {
        settings: crate::config::Settings::default(),
        root: false,
        peer: String::new(),
        banner_text: has_banner.then_some(banner),
        records: session::Records::Off,
    };
    let mut judge = |m: &[u8]| -> Verdict {
        if send_frame(TO_MONITOR, AUTH, m).is_err() {
            return Verdict::TooMany;
        }
        match recv_frame(FROM_MONITOR) {
            Ok((AUTH, v)) => Verdict::decode(&v).unwrap_or(Verdict::TooMany),
            _ => Verdict::TooMany,
        }
    };
    session::authenticate(&mut t, &signer, &cfg, &mut judge)?;
    send_frame(TO_MONITOR, STATE, &t.export())
}

/// The parent of process `pid` (/proc/PID/status's PPid), if it exists.
fn parent_of(pid: i32) -> Option<i32> {
    let status = fs::read_file(format!("/proc/{pid}/status").as_bytes()).ok()?;
    lossy(&status).lines().find_map(|l| l.strip_prefix("PPid:")).and_then(|v| v.trim().parse().ok())
}

/// The monitor's side after authentication: start `sshd-session` with
/// the user's IDs, hand it the connection, and answer it until the
/// session ends.
pub fn postauth(fd: i32, t: &T, user: &User, host: &HostKey, cfg: &Config) -> transport::Result<()> {
    let pipe = || process::pipe(fs::O_CLOEXEC).map_err(|e| transport::Error(format!("pipe: {e}")));
    let (to_child_r, to_child_w) = pipe()?;
    let (from_child_r, from_child_w) = pipe()?;
    let exe = fs::readlink(b"/proc/self/exe").unwrap_or_else(|_| b"/bin/sshd".to_vec());
    let groups =
        session::session_groups(&lossy(&fs::read_file(b"/etc/group").unwrap_or_default()), &user.name, user.gid);
    let child = match process::fork() {
        Ok(0) => {
            let up = |f: i32| process::fcntl(f, 0, 10).map(|n| n as i32);
            let (c, r, w) = (up(fd), up(to_child_r), up(from_child_w));
            if let (Ok(c), Ok(r), Ok(w)) = (c, r, w) {
                let _ = process::dup2(c, CONN);
                let _ = process::dup2(r, FROM_MONITOR);
                let _ = process::dup2(w, TO_MONITOR);
                // The user's IDs before running anything.
                let dropped = process::setgroups(&groups)
                    .and_then(|()| process::setgid(user.gid))
                    .and_then(|()| process::setuid(user.uid));
                if dropped.is_ok() {
                    let e = process::execve(&exe, &[b"sshd-session".to_vec()], &[]);
                    eprintln!("sshd: {}: {e}", lossy(&exe));
                }
            }
            process::exit_now(1);
        }
        Ok(pid) => pid,
        Err(e) => return err(format!("fork: {e}")),
    };
    let _ = io::close(to_child_r);
    let _ = io::close(from_child_w);
    let (ours_r, ours_w) = (from_child_r, to_child_w);
    let s = &cfg.settings;
    let mut w = Writer::default();
    w.string(&t.export()).string(&host.blob());
    w.string(user.name.as_bytes()).u32(user.uid).u32(user.gid);
    w.string(user.home.as_bytes()).string(user.shell.as_bytes()).string(cfg.peer.as_bytes());
    w.u32(s.alive_interval).u32(s.alive_count).u64(s.rekey_bytes).u32(s.rekey_secs).bool(s.print_motd);
    w.bool(s.sftp.is_some()).string(s.sftp.as_deref().unwrap_or_default().as_bytes());
    w.u32(s.kex.len() as u32);
    for k in &s.kex {
        w.string(k);
    }
    w.bool(user.expired);
    let mut logged: Vec<i32> = Vec::new();
    let r = (|| -> transport::Result<()> {
        send_frame(ours_w, STATE, &w.finish())?;
        // Until the session process closes its pipe: the session is over.
        while let Ok((kind, data)) = recv_frame(ours_r) {
            let mut r = Reader::new(&data);
            match kind {
                SIGN if data.len() == 32 => send_frame(ours_w, SIGN, &host.sign(&data))?,
                LOGIN => {
                    let (pid, line) = (r.u32()? as i32, r.string()?);
                    let pty =
                        line.strip_prefix(b"pts/").is_some_and(|n| !n.is_empty() && n.iter().all(u8::is_ascii_digit));
                    if pty && parent_of(pid) == Some(child) && !logged.contains(&pid) {
                        slate_rt::utmp::login(pid, line, user.name.as_bytes(), user.uid, cfg.peer.as_bytes());
                        logged.push(pid);
                    }
                }
                LOGOUT => {
                    let pid = r.u32()? as i32;
                    if let Some(i) = logged.iter().position(|p| *p == pid) {
                        slate_rt::utmp::logout(logged.remove(i));
                    }
                }
                _ => return err("an unknown message from the session process"),
            }
        }
        Ok(())
    })();
    // Logins the session process didn't end (it was killed).
    for pid in logged {
        slate_rt::utmp::logout(pid);
    }
    let _ = io::close(ours_r);
    let _ = io::close(ours_w);
    if r.is_err() {
        let _ = process::kill(child, slate_rt::signal::SIGKILL);
    }
    let _ = process::wait(child, 0);
    r
}

/// Ask the monitor to record a login on a pseudo-terminal (from the
/// session process).
pub fn record_login(pid: i32, line: &[u8]) {
    let mut w = Writer::default();
    w.u32(pid as u32).string(line);
    let _ = send_frame(TO_MONITOR, LOGIN, &w.finish());
}

/// Ask the monitor to record the end of a login.
pub fn record_logout(pid: i32) {
    let mut w = Writer::default();
    w.u32(pid as u32);
    let _ = send_frame(TO_MONITOR, LOGOUT, &w.finish());
}

/// `sshd-session`: the session process's side.
pub fn session_main() -> i32 {
    match session_child() {
        Ok(()) => 0,
        Err(e) => {
            session::log(&e.0);
            1
        }
    }
}

fn session_child() -> transport::Result<()> {
    // The user's programs get none of these.
    for fd in [CONN, FROM_MONITOR, TO_MONITOR] {
        let _ = process::fcntl(fd, process::F_SETFD, process::FD_CLOEXEC);
    }
    let (kind, data) = recv_frame(FROM_MONITOR)?;
    if kind != STATE {
        return err("no session from the monitor");
    }
    let mut r = Reader::new(&data);
    let state = r.string()?.to_vec();
    let blob = r.string()?.to_vec();
    let name = String::from(lossy(r.string()?));
    let (uid, gid) = (r.u32()?, r.u32()?);
    let (home, shell, peer) =
        (String::from(lossy(r.string()?)), String::from(lossy(r.string()?)), String::from(lossy(r.string()?)));
    let mut settings = crate::config::Settings {
        alive_interval: r.u32()?,
        alive_count: r.u32()?,
        rekey_bytes: r.u64()?,
        rekey_secs: r.u32()?,
        print_motd: r.bool()?,
        ..Default::default()
    };
    let has_sftp = r.bool()?;
    let sftp = String::from(lossy(r.string()?));
    settings.sftp = has_sftp.then_some(sftp);
    let mut kex = Vec::new();
    for _ in 0..r.u32()? {
        let k = r.string()?;
        if let Some(k) = crate::config::KEX_ALL.iter().find(|x| **x == k) {
            kex.push(*k);
        }
    }
    let expired = r.bool()?;
    // The monitor gave this process the user's IDs before it started.
    if process::getuid() != uid || process::geteuid() != uid || process::getgid() != gid {
        return err("the session process does not have the user's IDs");
    }
    settings.kex = kex.clone();
    let mut t = Transport::import(Fd(CONN), &state, kex)?;
    let user = User { name, uid, gid, home, shell, expired };
    let cfg = Config { settings, root: false, peer, banner_text: None, records: session::Records::Monitor };
    session::connection(&mut t, &MonitorSigner { blob }, &user, &cfg)
}
