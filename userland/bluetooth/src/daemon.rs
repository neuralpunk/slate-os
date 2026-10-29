// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-btd (ADR 0113), a slinit service: it opens /dev/hci0 when a
//! controller appears (and again after one is unplugged and plugged in),
//! runs the [`Host`] over it, keeps pairings in [`store`], and answers
//! Settings and slate-bt ([`proto`]). What it does goes to its service
//! log, a line each.

use alloc::string::String;
use alloc::vec::Vec;

use slate_hci::BdAddr;
use slate_rt::{Errno, eprintln, fs, io, net, process};

use crate::host::{Host, State};
use crate::{proto, store};

const DEVICE: &[u8] = b"/dev/hci0";
/// How often to look for a controller while there is none (ms).
const LOOK_MS: i64 = 2000;
/// Discoverable lasts this long after the last `visible on` (Settings
/// repeats it while its page is open).
const VISIBLE_MS: i64 = 15_000;

fn now_ms() -> i64 {
    (slate_rt::time::monotonic_ns() / 1_000_000) as i64
}

/// Whether the program at `pid` is Slate's own (the Slate domain).
fn slate_domain(pid: i32) -> bool {
    let status = fs::read_file(alloc::format!("/proc/{pid}/status").as_bytes()).unwrap_or_default();
    slate_rt::lossy(&status).lines().any(|l| l.strip_prefix("Domain:").is_some_and(|d| d.trim() == "slate"))
}

struct Daemon {
    host: Host,
    hci: Option<i32>,
    visible_until: Option<i64>,
}

impl Daemon {
    fn open_controller(&mut self) {
        let Ok(fd) = fs::open(DEVICE, fs::O_RDWR | fs::O_NONBLOCK | fs::O_CLOEXEC, 0) else { return };
        self.hci = Some(fd);
        eprintln!("slate-btd: controller hci0");
        if store::powered() {
            self.host.power_on();
        } else {
            self.host.state = State::Off;
        }
    }

    fn lose_controller(&mut self, why: &str) {
        if let Some(fd) = self.hci.take() {
            let _ = io::close(fd);
            eprintln!("slate-btd: controller gone ({why})");
        }
        self.host.lost();
    }

    /// Send what the host has to say, read what the controller said.
    fn pump(&mut self) {
        let Some(fd) = self.hci else { return };
        let mut buf = alloc::vec![0u8; 2048];
        loop {
            match io::read(fd, &mut buf) {
                Ok(0) => break,
                Ok(n) => self.host.event(&buf[..n]),
                Err(Errno::EAGAIN) => break,
                Err(e) => {
                    self.lose_controller(&alloc::format!("{e}"));
                    return;
                }
            }
        }
        while let Some(p) = self.host.next_command() {
            if let Err(e) = io::write_all(fd, &p) {
                self.lose_controller(&alloc::format!("{e}"));
                return;
            }
        }
        for n in core::mem::take(&mut self.host.notes) {
            eprintln!("slate-btd: {n}");
        }
        if self.host.dirty {
            self.host.dirty = false;
            if let Err(e) = store::save(&self.host.devices) {
                eprintln!("slate-btd: couldn't keep the pairings: {e}");
            }
        }
    }

    fn handle(&mut self, words: &str) -> Result<(), String> {
        let (cmd, rest) = words.split_once(' ').unwrap_or((words, ""));
        let addr = || {
            let a = rest.split(' ').next().unwrap_or("");
            BdAddr::parse(a).ok_or_else(|| alloc::format!("{a:?} is not a device address"))
        };
        match cmd {
            "status" => Ok(()),
            "power" => {
                let on = match rest {
                    "on" => true,
                    "off" => false,
                    _ => return Err("power on or off".into()),
                };
                store::set_powered(on)?;
                if on && self.hci.is_some() && self.host.state != State::On {
                    self.host.power_on();
                } else if !on {
                    self.host.power_off();
                }
                Ok(())
            }
            "name" if !rest.trim().is_empty() => {
                self.host.set_name(rest.trim());
                Ok(())
            }
            "visible" => {
                let on = rest == "on";
                self.visible_until = on.then(|| now_ms() + VISIBLE_MS);
                if self.host.visible != on {
                    self.host.set_visible(on);
                }
                Ok(())
            }
            "discover" => self.host.discover(),
            "pair" => self.host.pair(addr()?),
            "connect" => self.host.connect(addr()?),
            "remove" => self.host.remove(addr()?),
            "confirm" => {
                let yes = match rest.split(' ').nth(1) {
                    Some("yes") => true,
                    Some("no") => false,
                    _ => return Err("confirm ADDR yes or no".into()),
                };
                self.host.confirm(addr()?, yes)
            }
            _ => Err(alloc::format!(
                "{words:?}: status, power, name, visible, discover, pair, connect, confirm or remove"
            )),
        }
    }

    /// One client: its request, our answer.
    fn serve(&mut self, fd: i32) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        while !buf.contains(&b'\n') && buf.len() < 1024 {
            let mut p = [io::PollFd { fd, events: io::POLLIN, revents: 0 }];
            if io::poll(&mut p, 2000).unwrap_or(0) == 0 {
                return;
            }
            match io::read(fd, &mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let words = String::from(slate_rt::lossy(&buf).lines().next().unwrap_or("").trim());
        let allowed = net::peer_cred(fd).is_ok_and(|(pid, _, _)| slate_domain(pid));
        let r = if allowed { self.handle(&words) } else { Err("only Slate's own programs may use Bluetooth".into()) };
        if words != "status" && !words.starts_with("visible") {
            eprintln!(
                "slate-btd: asked: {words}{}",
                r.as_ref().err().map_or(String::new(), |e| alloc::format!(" ({e})"))
            );
        }
        self.pump();
        let reply = match r {
            Ok(()) => alloc::format!("ok\n{}\n", proto::snapshot(&self.host, self.hci.is_some())),
            Err(e) => alloc::format!("error: {e}\n{}\n", proto::snapshot(&self.host, self.hci.is_some())),
        };
        let _ = io::write_all(fd, reply.as_bytes());
    }
}

pub fn main() -> i32 {
    if process::geteuid() != 0 {
        eprintln!("slate-btd: must run as root");
        return 1;
    }
    let host_name = String::from(slate_rt::lossy(&process::uname()[1]));
    let paired = store::load();
    eprintln!("slate-btd: {} paired devices", paired.len());
    let listen = match net::listen(proto::SOCKET) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("slate-btd: {e}");
            return 1;
        }
    };
    let mut d = Daemon { host: Host::new(&host_name, paired), hci: None, visible_until: None };
    let mut look = 0;
    loop {
        if d.hci.is_none() && now_ms() >= look {
            d.open_controller();
            look = now_ms() + LOOK_MS;
        }
        if d.visible_until.is_some_and(|t| now_ms() > t) {
            d.visible_until = None;
            d.host.set_visible(false);
        }
        d.pump();
        let mut fds = alloc::vec![io::PollFd { fd: listen, events: io::POLLIN, revents: 0 }];
        if let Some(h) = d.hci {
            fds.push(io::PollFd { fd: h, events: io::POLLIN, revents: 0 });
        }
        let wait = if d.hci.is_none() { LOOK_MS as i32 } else { 1000 };
        if io::poll(&mut fds, wait).unwrap_or(0) == 0 {
            continue;
        }
        if fds.get(1).is_some_and(|f| f.revents & (io::POLLHUP | 8) != 0 && f.revents & io::POLLIN == 0) {
            d.lose_controller("hung up");
        }
        if fds[0].revents & io::POLLIN != 0
            && let Ok(c) = net::accept(listen)
        {
            d.serve(c);
            let _ = io::close(c);
        }
    }
}
