// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-btd (ADR 0113), a slinit service: it opens /dev/hci0 when a
//! controller appears (and again after one is unplugged and plugged in),
//! runs the [`Host`] over it, keeps pairings in [`store`], and answers
//! Settings and slate-bt ([`proto`]). LE HID devices become kernel input
//! devices through /dev/slate-hid, one open each (ADR 0176); a mouse in
//! pairing mode pairs by itself, whatever else is plugged in
//! (/etc/slate/bluetooth's `autopair=`: `always`, the default; `auto`,
//! only while no other pointer is here; `never`). What it does goes to
//! its service log, a line each.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use slate_hci::BdAddr;
use slate_rt::{Errno, eprintln, fs, io, net, process};

use crate::host::{Host, State};
use crate::le::HidEvent;
use crate::{proto, store};

const DEVICE: &[u8] = b"/dev/hci0";
/// How often to look for a controller while there is none (ms).
const LOOK_MS: i64 = 2000;
/// Discoverable lasts this long after the last `visible on` (Settings
/// repeats it while its page is open).
const VISIBLE_MS: i64 = 15_000;
/// How often to look whether a pointer is there (ms).
const POINTER_MS: i64 = 3000;
const HID_DEVICE: &[u8] = b"/dev/slate-hid";
/// Bus type Bluetooth (input.h's BUS_BLUETOOTH, as evdev reports it).
const BUS_BLUETOOTH: u16 = 0x05;

fn now_ms() -> i64 {
    (slate_rt::time::monotonic_ns() / 1_000_000) as i64
}

/// Whether the program at `pid` is Slate's own (the Slate domain).
fn slate_domain(pid: i32) -> bool {
    let status = fs::read_file(alloc::format!("/proc/{pid}/status").as_bytes()).unwrap_or_default();
    slate_rt::lossy(&status).lines().any(|l| l.strip_prefix("Domain:").is_some_and(|d| d.trim() == "slate"))
}

/// Whether any input device points (relative or absolute axes), from
/// /sys/class/input's capabilities (sysfs-class-input).
fn pointer_present() -> bool {
    let Ok(entries) = fs::read_dir(b"/sys/class/input") else { return false };
    entries.iter().any(|e| {
        let name = slate_rt::lossy(&e.name);
        if !name.starts_with("input") {
            return false;
        }
        ["rel", "abs"].iter().any(|k| {
            fs::read_file(alloc::format!("/sys/class/input/{name}/capabilities/{k}").as_bytes())
                .is_ok_and(|t| !matches!(slate_rt::lossy(&t).trim(), "" | "0"))
        })
    })
}

/// The administrator's `autopair=` in /etc/slate/bluetooth: Some(true)
/// always (the default, and without the file), Some(false) never, None
/// (`auto`) only while no other pointer is here. Always by default: a
/// keyboard often brings a mouse device of its own, which would count as
/// a pointer, and nobody should be left without a mouse (the owner,
/// 2026-10-29).
fn autopair_setting() -> Option<bool> {
    let text = fs::read_file(b"/etc/slate/bluetooth").unwrap_or_default();
    let word = String::from(slate_rt::lossy(&text))
        .lines()
        .find_map(|l| Some(String::from(l.trim().strip_prefix("autopair=")?.trim())));
    match word.as_deref() {
        Some("never") => Some(false),
        Some("auto") => None,
        _ => Some(true),
    }
}

struct Daemon {
    host: Host,
    hci: Option<i32>,
    visible_until: Option<i64>,
    /// Each LE HID device's /dev/slate-hid.
    hid: BTreeMap<BdAddr, i32>,
    pointer_checked: i64,
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
        self.apply_hid();
    }

    /// Make, feed and close the kernel's HID devices as the host says.
    fn apply_hid(&mut self) {
        for e in core::mem::take(&mut self.host.hid) {
            match e {
                HidEvent::Create { addr, name, device, pointer_only } => {
                    if let Some(fd) = self.hid.remove(&addr) {
                        let _ = io::close(fd);
                    }
                    let Ok(fd) = fs::open(HID_DEVICE, fs::O_RDWR | fs::O_NONBLOCK | fs::O_CLOEXEC, 0) else {
                        eprintln!("slate-btd: {addr}: no /dev/slate-hid");
                        continue;
                    };
                    let phys = alloc::format!("bt-{addr}");
                    let create = slate_hid::user::Create {
                        bus: BUS_BLUETOOTH,
                        vendor: device.vendor,
                        product: device.product,
                        version: device.version,
                        flags: if pointer_only { slate_hid::user::FLAG_POINTER_ONLY } else { 0 },
                        name: &name,
                        phys: &phys,
                        descriptor: &device.descriptor,
                    };
                    match io::write_all(fd, &create.encode()) {
                        Ok(()) => {
                            eprintln!(
                                "slate-btd: {name}: input device{}",
                                if pointer_only { " (pointer only)" } else { "" }
                            );
                            self.hid.insert(addr, fd);
                        }
                        Err(e) => {
                            eprintln!("slate-btd: {name}: the kernel refused it ({e})");
                            let _ = io::close(fd);
                        }
                    }
                }
                HidEvent::Input { addr, report } => {
                    if let Some(&fd) = self.hid.get(&addr) {
                        let _ = io::write_all(fd, &slate_hid::user::input(&report));
                    }
                }
                HidEvent::Close { addr } => {
                    if let Some(fd) = self.hid.remove(&addr) {
                        let _ = io::close(fd);
                        eprintln!("slate-btd: {addr}: input device gone");
                    }
                }
            }
        }
    }

    /// Output reports the kernel has for the HID devices (lights).
    fn read_hid(&mut self) {
        let fds: Vec<(BdAddr, i32)> = self.hid.iter().map(|(a, f)| (*a, *f)).collect();
        let mut buf = [0u8; 600];
        for (a, fd) in fds {
            while let Ok(n) = io::read(fd, &mut buf) {
                if n >= 2 && buf[0] == slate_hid::user::OUTPUT {
                    self.host.hid_output(a, buf[1], &buf[2..n]);
                } else {
                    break;
                }
            }
        }
    }

    /// Whether a mouse should pair by itself (the setting; for `auto`, no
    /// other pointer here).
    fn check_pointer(&mut self) {
        if now_ms() < self.pointer_checked + POINTER_MS {
            return;
        }
        self.pointer_checked = now_ms();
        let want = autopair_setting().unwrap_or_else(|| !pointer_present());
        if want != self.host.autopair {
            self.host.autopair = want;
            eprintln!(
                "slate-btd: {}",
                if want { "a mouse in pairing mode pairs by itself" } else { "mice pair when asked" }
            );
        }
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
        self.read_hid();
        while let Some(p) = self.host.next_command().or_else(|| self.host.next_acl()) {
            if let Err(e) = io::write_all(fd, &p) {
                self.lose_controller(&alloc::format!("{e}"));
                return;
            }
        }
        self.apply_hid();
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
    store::repair();
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
    let mut host = Host::new(&host_name, paired);
    host.irk = store::irk();
    let mut d = Daemon { host, hci: None, visible_until: None, hid: BTreeMap::new(), pointer_checked: i64::MIN / 2 };
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
        d.check_pointer();
        d.pump();
        let mut fds = alloc::vec![io::PollFd { fd: listen, events: io::POLLIN, revents: 0 }];
        if let Some(h) = d.hci {
            fds.push(io::PollFd { fd: h, events: io::POLLIN, revents: 0 });
        }
        fds.extend(d.hid.values().map(|&fd| io::PollFd { fd, events: io::POLLIN, revents: 0 }));
        let wait = if d.hci.is_none() { LOOK_MS as i32 } else { 1000 }.min(POINTER_MS as i32);
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
