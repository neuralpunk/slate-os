// SPDX-License-Identifier: MIT OR Apache-2.0

//! Slate's end of a box session's channel ([`crate::channel`]): a
//! process slate-box forks for each session, outside the box, as the
//! person. It makes the session's folder (`/tmp/slate-host.PID`, the
//! person's alone) with the key and the socket the session binds into the
//! box, answers the box's requests, asks slate-boxd for install receipts,
//! and logs every request, and every message it refuses, in the person's
//! log of the box (`~/.local/state/slate/boxes/NAME.log`).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{fs, io, net, process, signal};

use crate::channel::{self, Sealed};
use crate::proto;

/// A session's agent.
#[derive(Debug)]
pub struct Agent {
    pid: i32,
    /// The folder bound into the box at `/run/slate-host`.
    pub dir: String,
}

/// Append a line to the person's log of box `name`.
pub fn log(name: &str, line: &str) {
    let home = crate::native::home();
    let dir = format!("{home}/.local/state/slate/boxes");
    let mut at = String::new();
    for part in dir.split('/').filter(|p| !p.is_empty()) {
        at.push('/');
        at.push_str(part);
        let _ = fs::mkdir(at.as_bytes(), 0o700);
    }
    let path = format!("{dir}/{name}.log");
    if let Ok(fd) = fs::open(path.as_bytes(), fs::O_WRONLY | fs::O_CREAT | fs::O_APPEND | fs::O_CLOEXEC, 0o600) {
        let _ = io::write_all(fd, format!("{} {line}\n", slate_rt::time::unix()).as_bytes());
        let _ = io::close(fd);
    }
}

/// What the agent knows of its session.
#[derive(Clone, Debug)]
pub struct About {
    pub name: String,
    pub title: String,
    pub shared: Option<String>,
}

impl Agent {
    /// Start the agent of a session of box `about.name`.
    pub fn start(about: &About) -> Result<Agent, String> {
        let mut tag = [0u8; 8];
        process::random(&mut tag).map_err(|e| format!("random bytes: {e}"))?;
        let dir = format!("/tmp/slate-host.{}.{}", process::getpid(), slate_hash::hex(&tag));
        fs::mkdir(dir.as_bytes(), 0o700).map_err(|e| format!("{dir}: {e}"))?;
        let mut secret = [0u8; 32];
        process::random(&mut secret).map_err(|e| format!("random bytes: {e}"))?;
        fs::write_file(format!("{dir}/key").as_bytes(), &secret, 0o600).map_err(|e| format!("{dir}/key: {e}"))?;
        let l = net::listen_path(format!("{dir}/socket").as_bytes(), 8).map_err(|e| format!("{dir}/socket: {e}"))?;
        let _ = fs::chmod(format!("{dir}/socket").as_bytes(), 0o600);
        match process::fork() {
            Ok(0) => {
                let _ = signal::set(signal::SIGINT, signal::Disposition::Ignore);
                let _ = signal::set(signal::SIGQUIT, signal::Disposition::Ignore);
                serve(l, &secret, about, &dir)
            }
            Ok(pid) => {
                let _ = io::close(l);
                Ok(Agent { pid, dir })
            }
            Err(e) => Err(format!("starting the box's channel: {e}")),
        }
    }

    /// Whether the session made an install receipt.
    pub fn installed(&self) -> bool {
        fs::exists(format!("{}/installed", self.dir).as_bytes())
    }

    /// End the agent; its folder goes.
    pub fn stop(self) {
        let _ = process::kill(self.pid, signal::SIGTERM);
        let _ = process::wait(self.pid, 0);
        for f in ["key", "socket", "installed"] {
            let _ = fs::unlink(format!("{}/{f}", self.dir).as_bytes());
        }
        let _ = fs::rmdir(self.dir.as_bytes());
    }
}

fn serve(l: i32, secret: &[u8], about: &About, dir: &str) -> ! {
    loop {
        match net::accept(l) {
            Ok(c) => {
                connection(c, secret, about, dir);
                let _ = io::close(c);
            }
            Err(slate_rt::Errno::EINTR) => {}
            Err(_) => process::exit_now(0),
        }
    }
}

/// One connection: the nonces, then requests until it ends.
fn connection(fd: i32, secret: &[u8], about: &About, dir: &str) {
    let mut theirs = [0u8; 32];
    if channel::read_exact(fd, &mut theirs).is_err() {
        return;
    }
    let mut mine = [0u8; 32];
    if process::random(&mut mine).is_err() || io::write_all(fd, &mine).is_err() {
        return;
    }
    let mut s = Sealed::new(secret, &theirs, &mine, false);
    while let Ok(frame) = channel::read_frame(fd) {
        let Ok(msg) = s.open(&frame) else {
            log(
                &about.name,
                "refused a message that didn't open (forged, replayed, or another session's); connection closed",
            );
            slate_rt::eprintln!("slate-box: the box {} sent a message that didn't open; refused", about.name);
            return;
        };
        let msg = String::from(slate_rt::lossy(&msg));
        let answer = handle(&msg, about, dir);
        if io::write_all(fd, &s.seal(answer.as_bytes())).is_err() {
            return;
        }
    }
}

/// A request's answer.
fn handle(msg: &str, about: &About, dir: &str) -> String {
    let f: Vec<&str> = msg.split('\t').collect();
    match f.as_slice() {
        ["info"] => {
            log(&about.name, "info");
            format!(
                "ok\tbox {}\tdistro {}\tshared {}",
                about.name,
                about.title,
                about.shared.as_deref().unwrap_or("nothing")
            )
        }
        ["begin", label, command] => {
            log(&about.name, &format!("begin {label}: {command}"));
            match proto::ask(&["begin", &about.name, label, command], &mut |_| {}) {
                Ok(facts) => format!("ok\t{}", proto::fact(&facts, "receipt").unwrap_or("")),
                Err(e) => format!("error\t{e}"),
            }
        }
        ["end"] => match proto::ask(&["end", &about.name], &mut |_| {}) {
            Ok(facts) => {
                let r = proto::fact(&facts, "receipt").unwrap_or("");
                if !r.is_empty() {
                    log(&about.name, &format!("receipt {r}"));
                    // The session's slate-box looks at it afterwards.
                    let _ = fs::write_file(format!("{dir}/installed").as_bytes(), b"", 0o600);
                }
                format!("ok\t{r}")
            }
            Err(e) => format!("error\t{e}"),
        },
        _ => {
            log(&about.name, &format!("refused an unknown request: {:?}", msg.chars().take(60).collect::<String>()));
            String::from("error\tunknown request")
        }
    }
}
