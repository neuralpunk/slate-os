// SPDX-License-Identifier: MIT OR Apache-2.0

//! How Settings and slate-bt talk to slate-btd (ADR 0113): one request per
//! connection on the abstract socket `slate-btd`, a line of words; the
//! answer is `ok` or `error: WORDS`, then the state as lines ([`Snapshot`]),
//! then an empty line. Requests:
//!
//! - `status`;
//! - `power on|off`, `name NAME`, `visible on|off`;
//! - `discover`;
//! - `pair ADDR`, `connect ADDR`, `confirm ADDR yes|no`, `remove ADDR`.
//!
//! The daemon answers only programs in the Slate domain (ADR 0032).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_hci::{BdAddr, Kind};

use crate::host::{Host, Prompt, State};

pub const SOCKET: &[u8] = b"slate-btd";

/// A device as clients see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    pub addr: BdAddr,
    pub name: String,
    pub kind: Kind,
    pub paired: bool,
    pub connected: bool,
    pub nearby: bool,
}

/// The daemon's state, as clients see it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// `on`, `off`, `starting`, `none` (no controller) or `failed`.
    pub state: String,
    /// Why it failed.
    pub problem: String,
    pub addr: Option<BdAddr>,
    pub name: String,
    pub discovering: bool,
    pub visible: bool,
    pub devices: Vec<Seen>,
    pub prompt: Option<Prompt>,
    /// The device being paired or connected.
    pub busy: Option<BdAddr>,
    pub said: Option<(String, bool)>,
}

impl Snapshot {
    pub fn on(&self) -> bool {
        self.state == "on"
    }

    pub fn device(&self, a: BdAddr) -> Option<&Seen> {
        self.devices.iter().find(|d| d.addr == a)
    }
}

/// The state's lines.
pub fn snapshot(h: &Host, have_controller: bool) -> String {
    let mut s = String::new();
    let state = match (&h.state, have_controller) {
        (_, false) => String::from("none"),
        (State::On, _) => String::from("on"),
        (State::Off, _) => String::from("off"),
        (State::Starting, _) => String::from("starting"),
        (State::Failed(e), _) => alloc::format!("failed {e}"),
    };
    s += &alloc::format!("state {state}\n");
    if let Some(a) = h.addr {
        s += &alloc::format!("controller {a} {}\n", h.name);
    }
    s += &alloc::format!("discovering {}\nvisible {}\n", yes(h.discovering), yes(h.visible));
    for d in &h.devices {
        let how = match (d.connected.is_some(), d.paired()) {
            (true, _) => "connected",
            (false, true) => "paired",
            (false, false) => "found",
        };
        s += &alloc::format!(
            "device {} {how} {} {} {}\n",
            d.addr,
            if d.nearby { "near" } else { "away" },
            d.kind.word(),
            d.name.replace('\n', " ")
        );
    }
    match h.prompt {
        Some(Prompt::Confirm(a, v)) => s += &alloc::format!("prompt {a} confirm {v:06}\n"),
        Some(Prompt::Pair(a)) => s += &alloc::format!("prompt {a} pair\n"),
        Some(Prompt::Passkey(a, v)) => s += &alloc::format!("prompt {a} passkey {v:06}\n"),
        None => {}
    }
    if let Some(op) = h.op {
        s += &alloc::format!("busy {}\n", op.addr);
    }
    if let Some((t, bad)) = &h.said {
        s += &alloc::format!("said {} {}\n", if *bad { "bad" } else { "ok" }, t.replace('\n', " "));
    }
    s
}

fn yes(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

/// Read the state's lines.
pub fn parse_snapshot(text: &str) -> Snapshot {
    let mut s = Snapshot::default();
    for l in text.lines() {
        let (word, rest) = l.split_once(' ').unwrap_or((l, ""));
        match word {
            "state" => {
                let (st, why) = rest.split_once(' ').unwrap_or((rest, ""));
                s.state = st.to_string();
                s.problem = why.to_string();
            }
            "controller" => {
                let (a, name) = rest.split_once(' ').unwrap_or((rest, ""));
                s.addr = BdAddr::parse(a);
                s.name = name.to_string();
            }
            "discovering" => s.discovering = rest == "yes",
            "visible" => s.visible = rest == "yes",
            "device" => {
                let f: Vec<&str> = rest.splitn(5, ' ').collect();
                if let [a, how, near, kind, name] = f[..]
                    && let Some(addr) = BdAddr::parse(a)
                {
                    s.devices.push(Seen {
                        addr,
                        name: name.to_string(),
                        kind: Kind::from_word(kind),
                        paired: how != "found",
                        connected: how == "connected",
                        nearby: near == "near",
                    });
                }
            }
            "prompt" => {
                let f: Vec<&str> = rest.split(' ').collect();
                let a = f.first().and_then(|a| BdAddr::parse(a));
                let v = f.get(2).and_then(|v| v.parse().ok());
                s.prompt = match (a, f.get(1).copied(), v) {
                    (Some(a), Some("confirm"), Some(v)) => Some(Prompt::Confirm(a, v)),
                    (Some(a), Some("passkey"), Some(v)) => Some(Prompt::Passkey(a, v)),
                    (Some(a), Some("pair"), _) => Some(Prompt::Pair(a)),
                    _ => None,
                };
            }
            "busy" => s.busy = BdAddr::parse(rest),
            "said" => {
                let (how, t) = rest.split_once(' ').unwrap_or((rest, ""));
                s.said = Some((t.to_string(), how == "bad"));
            }
            _ => {}
        }
    }
    s
}

/// Ask slate-btd: its answer (Err with its words, or when it is not
/// running) and the state after.
pub fn request(words: &str) -> Result<Snapshot, String> {
    let fd = slate_rt::net::connect(SOCKET).map_err(|_| String::from("the Bluetooth service isn't running"))?;
    let mut m = words.replace('\n', " ").into_bytes();
    m.push(b'\n');
    let r = slate_rt::io::write_all(fd, &m).and_then(|()| slate_rt::io::read_to_end(fd));
    let _ = slate_rt::io::close(fd);
    let reply = String::from(slate_rt::lossy(&r.map_err(|e| alloc::format!("{e}"))?));
    let (first, rest) = reply.split_once('\n').unwrap_or((&reply, ""));
    match first.strip_prefix("error: ") {
        Some(e) => Err(e.to_string()),
        None if first == "ok" => Ok(parse_snapshot(rest)),
        None => Err(alloc::format!("the Bluetooth service said {first:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::Device;

    #[test]
    fn round_trip() {
        let a = BdAddr([0x5C, 0xF3, 0x70, 0x11, 0x22, 0x33]);
        let mut h = Host::new("desk", Vec::new());
        h.state = State::On;
        h.addr = Some(BdAddr([0, 0x1B, 0xDC, 0x0F, 0, 1]));
        h.visible = true;
        h.devices.push(Device {
            addr: a,
            name: "Ada's Phone".into(),
            kind: Kind::Phone,
            page_scan_mode: 1,
            clock_offset: 0,
            nearby: true,
            key: None,
            connected: None,
            le: None,
        });
        h.prompt = Some(Prompt::Confirm(a, 4_913));
        h.said = Some(("Couldn't reach it.".into(), true));
        let s = parse_snapshot(&snapshot(&h, true));
        assert!(s.on() && s.visible && !s.discovering);
        assert_eq!((s.name.as_str(), s.addr), ("desk", h.addr));
        assert_eq!(
            s.devices,
            [Seen {
                addr: a,
                name: "Ada's Phone".into(),
                kind: Kind::Phone,
                paired: false,
                connected: false,
                nearby: true
            }]
        );
        assert_eq!(s.prompt, Some(Prompt::Confirm(a, 4_913)));
        assert_eq!(s.said, Some(("Couldn't reach it.".into(), true)));
        assert_eq!(parse_snapshot(&snapshot(&h, false)).state, "none");
        h.state = State::Failed("it broke".into());
        let s = parse_snapshot(&snapshot(&h, true));
        assert_eq!((s.state.as_str(), s.problem.as_str()), ("failed", "it broke"));
    }
}
