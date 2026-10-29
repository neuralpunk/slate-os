// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-sshd: Slate's own SSH server (ADR 0030), written from RFC 4251
//! (architecture), 4252 (authentication), 4253 (transport), 4254
//! (connection), 8709 (Ed25519 keys), 8731 (curve25519-sha256) and
//! OpenSSH's PROTOCOL.chacha20poly1305 and kex-strict description.
//!
//! `sshd [-tT] [-f CONFIG] [-p PORT] [-k HOSTKEY] [-a KEYS] [-1]` reads
//! /etc/ssh/sshd_config (ADR 0061; `-t` checks it, `-T` prints the
//! settings), listens (port 22), makes the Ed25519 host key on first
//! start (`/etc/ssh/ssh_host_ed25519_key`, its public half in `.pub` in
//! OpenSSH's format), and serves each connection in its own process.
//! `-p`, `-k` and `-a` override the file's `Port`, `HostKey` and
//! `AuthorizedKeysFile`; `-1` serves one connection without forking
//! (tests).

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

pub mod auth;
pub mod config;
pub mod crypto;
pub mod privsep;
pub mod session;
pub mod sftp;
pub mod transport;
pub mod wire;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::io::{POLLIN, PollFd};
use slate_rt::{eprintln, fs, io, lossy, net, process, signal};

const HOST_KEY: &str = "/etc/ssh/ssh_host_ed25519_key";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Load the host key, or make one (its seed in hex, mode 0600).
fn host_key(path: &str) -> Result<crypto::HostKey, String> {
    if let Ok(text) = fs::read_file(path.as_bytes()) {
        let seed = unhex(&lossy(&text)).ok_or_else(|| format!("{path}: not a host key"))?;
        return Ok(crypto::HostKey::from_seed(&seed));
    }
    let mut seed = [0u8; 32];
    process::random(&mut seed).map_err(|e| format!("random numbers: {e}"))?;
    if let Some((dir, _)) = path.rsplit_once('/')
        && !dir.is_empty()
    {
        let _ = fs::mkdir(dir.as_bytes(), 0o755);
    }
    fs::write_file(path.as_bytes(), format!("{}\n", hex(&seed)).as_bytes(), 0o600)
        .map_err(|e| format!("{path}: {e}"))?;
    let key = crypto::HostKey::from_seed(&seed);
    let host = String::from(lossy(&process::uname()[1]));
    let public = format!("ssh-ed25519 {} root@{host}\n", wire::base64(&key.blob(), true));
    let _ = fs::write_file(format!("{path}.pub").as_bytes(), public.as_bytes(), 0o644);
    Ok(key)
}

fn reap() {
    while let Ok((pid, _)) = process::wait(-1, process::WNOHANG) {
        if pid <= 0 {
            break;
        }
    }
}

pub fn main() -> i32 {
    match slate_rt::prog_name().as_str() {
        "sftp-server" => return sftp::main(),
        "sshd-preauth" => return privsep::child_main(),
        "sshd-session" => return privsep::session_main(),
        _ => {}
    }
    let args: Vec<String> = slate_rt::env::args().iter().skip(1).map(|a| String::from(lossy(a))).collect();
    let (mut ports, mut key_path, mut keys, mut once) = (Vec::new(), None, None, false);
    let (mut config_path, mut test, mut dump) = (String::from(config::PATH), false, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-p" => ports.push(it.next().and_then(|p| p.parse::<u16>().ok()).unwrap_or(0)),
            "-k" => key_path = it.next().cloned(),
            "-a" => keys = it.next().cloned(),
            "-f" => config_path = it.next().cloned().unwrap_or_default(),
            "-t" => test = true,
            "-T" => dump = true,
            "-1" => once = true,
            // Foreground and logging to standard error: always so.
            "-D" | "-e" => {}
            _ => {
                eprintln!("usage: sshd [-tTDe1] [-f CONFIG] [-p PORT] [-k HOSTKEY] [-a AUTHORIZED_KEYS]");
                return 2;
            }
        }
    }
    if ports.contains(&0) {
        eprintln!("sshd: bad port");
        return 2;
    }
    // The configuration: a missing default file means the defaults.
    let mut settings = match fs::read_file(config_path.as_bytes()) {
        Ok(text) => match config::parse(&lossy(&text)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("sshd: {config_path}: {e}");
                return 255;
            }
        },
        Err(slate_rt::Errno::ENOENT) if config_path == config::PATH => config::Settings::default(),
        Err(e) => {
            eprintln!("sshd: {config_path}: {e}");
            return 255;
        }
    };
    if settings.ports.is_empty() {
        settings.ports.push(22);
    }
    if settings.host_keys.is_empty() {
        settings.host_keys.push(HOST_KEY.into());
    }
    if !ports.is_empty() {
        settings.ports = ports;
    }
    if let Some(k) = key_path {
        settings.host_keys = alloc::vec![k];
    }
    if let Some(k) = keys {
        settings.authorized_keys = alloc::vec![k];
    }
    if dump {
        io::out(config::dump(&settings).as_bytes());
        return 0;
    }
    if test {
        return 0;
    }
    let host = match host_key(&settings.host_keys[0]) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("sshd: {e}");
            return 1;
        }
    };
    let banner_text = settings.banner.as_ref().and_then(|b| fs::read_file(b.as_bytes()).ok());
    let cfg = session::Config {
        settings: settings.clone(),
        root: process::getuid() == 0,
        peer: String::new(),
        banner_text,
        records: session::Records::Off,
    };
    let _ = signal::set(signal::SIGPIPE, signal::Disposition::Ignore);
    let mut listeners = Vec::new();
    for &port in &settings.ports {
        match net::tcp_listen(port, 16) {
            Ok(fd) => listeners.push(fd),
            Err(e) => {
                eprintln!("sshd: port {port}: {e}");
                return 1;
            }
        }
    }
    let ports: Vec<String> = settings.ports.iter().map(|p| format!("{p}")).collect();
    session::log(&format!("listening on port {}, host key {}", ports.join(" "), auth::fingerprint(&host.blob())));
    loop {
        let mut p: Vec<PollFd> = listeners.iter().map(|&fd| PollFd { fd, events: POLLIN, revents: 0 }).collect();
        let ready = io::poll(&mut p, 1000).unwrap_or(0);
        reap();
        if ready == 0 {
            continue;
        }
        for l in p.iter().filter(|l| l.revents & POLLIN != 0) {
            let Ok((conn, ip, peer_port)) = net::tcp_accept(l.fd) else { continue };
            let peer = format!("{}.{}.{}.{}:{peer_port}", ip[0], ip[1], ip[2], ip[3]);
            if once {
                let r = session::serve(conn, &peer, &host, &cfg);
                let _ = io::close(conn);
                if let Err(e) = r {
                    session::log(&format!("{peer}: {}", e.0));
                }
                return 0;
            }
            match process::fork() {
                Ok(0) => {
                    for &fd in &listeners {
                        let _ = io::close(fd);
                    }
                    if let Err(e) = session::serve(conn, &peer, &host, &cfg) {
                        session::log(&format!("{peer}: {}", e.0));
                    }
                    process::exit_now(0);
                }
                Ok(_) => {
                    let _ = io::close(conn);
                }
                Err(e) => {
                    eprintln!("sshd: fork: {e}");
                    let _ = io::close(conn);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
