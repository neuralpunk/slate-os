// SPDX-License-Identifier: MIT OR Apache-2.0

//! `ss [-t] [-u] [-l] [-a] [-n] [-H] [-p] [-e] [-4|-6] [state STATE]...
//! [exclude STATE]...` (ADR 0052): TCP and UDP sockets from
//! /proc/net/tcp, tcp6, udp and udp6 (proc_net(5)), laid out as users of
//! ss(8) expect. Without `-t` or `-u`, both; without `-l` or `-a`,
//! connected sockets only (`-l` listening and unconnected ones, `-a` all);
//! `state` and `exclude` choose by state instead (ss(8)'s names and
//! groups). `-p` names the processes holding each socket (from
//! /proc/PID/fd), `-e` adds its user and inode. Ports are always numbers
//! (`-n` is accepted).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_net::{IpAddr, Ipv4, Ipv6};
use slate_rt::{eprintln, println};

/// One socket line from a /proc/net file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sock {
    pub tcp: bool,
    pub local: (IpAddr, u16),
    pub remote: (IpAddr, u16),
    /// The state number (01 established ... 0A listen; UDP 07 unconnected).
    pub state: u8,
    pub tx_queue: u32,
    pub rx_queue: u32,
    /// The user of a process holding it, and its inode (0: none holds it).
    pub uid: u32,
    pub inode: u64,
}

fn hex_addr(s: &str) -> Option<(IpAddr, u16)> {
    let (a, p) = s.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    // 32-bit words in host (little-endian) order, as the kernel writes them.
    let words: Vec<u32> =
        (0..a.len() / 8).map(|i| u32::from_str_radix(a.get(i * 8..i * 8 + 8)?, 16).ok()).collect::<Option<_>>()?;
    let ip = match words.as_slice() {
        [w] => IpAddr::V4(Ipv4(w.to_le_bytes())),
        [a, b, c, d] => {
            let mut v = [0u8; 16];
            for (i, w) in [a, b, c, d].iter().enumerate() {
                v[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
            }
            IpAddr::V6(Ipv6(v))
        }
        _ => return None,
    };
    Some((ip, port))
}

/// The sockets in one /proc/net/{tcp,udp}[6] file.
pub fn parse(text: &str, tcp: bool) -> Vec<Sock> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (tx, rx) = f.get(4)?.split_once(':')?;
            Some(Sock {
                tcp,
                local: hex_addr(f.get(1)?)?,
                remote: hex_addr(f.get(2)?)?,
                state: u8::from_str_radix(f.get(3)?, 16).ok()?,
                tx_queue: u32::from_str_radix(tx, 16).ok()?,
                rx_queue: u32::from_str_radix(rx, 16).ok()?,
                uid: f.get(7).and_then(|v| v.parse().ok()).unwrap_or(0),
                inode: f.get(9).and_then(|v| v.parse().ok()).unwrap_or(0),
            })
        })
        .collect()
}

/// The state's name as ss(8) shows it.
pub fn state_name(s: &Sock) -> &'static str {
    match (s.tcp, s.state) {
        (false, 0x01) => "ESTAB",
        (false, _) => "UNCONN",
        (true, 0x01) => "ESTAB",
        (true, 0x02) => "SYN-SENT",
        (true, 0x03) => "SYN-RECV",
        (true, 0x04) => "FIN-WAIT-1",
        (true, 0x05) => "FIN-WAIT-2",
        (true, 0x06) => "TIME-WAIT",
        (true, 0x07) => "CLOSE",
        (true, 0x08) => "CLOSE-WAIT",
        (true, 0x09) => "LAST-ACK",
        (true, 0x0A) => "LISTEN",
        (true, 0x0B) => "CLOSING",
        _ => "UNKNOWN",
    }
}

/// The states (by number, bit n for state n) a name of ss(8)'s `state`
/// filter stands for: one state, or a group.
pub fn state_bits(name: &str) -> Option<u16> {
    let one = |n: u16| 1u16 << n;
    let all = (1..=0x0B).fold(0, |a, n| a | one(n));
    let connected = all & !one(0x0A) & !one(0x07);
    let bucket = one(0x03) | one(0x06);
    Some(match name {
        "established" => one(0x01),
        "syn-sent" => one(0x02),
        "syn-recv" => one(0x03),
        "fin-wait-1" => one(0x04),
        "fin-wait-2" => one(0x05),
        "time-wait" => one(0x06),
        "closed" => one(0x07),
        "close-wait" => one(0x08),
        "last-ack" => one(0x09),
        "listening" => one(0x0A),
        "closing" => one(0x0B),
        "all" => all,
        "connected" => connected,
        "synchronized" => connected & !one(0x02),
        "bucket" => bucket,
        "big" => all & !bucket,
        _ => return None,
    })
}

/// Listening (TCP) or unconnected (UDP).
pub fn listening(s: &Sock) -> bool {
    if s.tcp { s.state == 0x0A } else { s.state != 0x01 }
}

/// `ADDR:PORT`, `[ADDR6]:PORT`, `*` for a wildcard address or port; an
/// IPv4-mapped address shows as `[::ffff:a.b.c.d]`.
pub fn endpoint(e: &(IpAddr, u16), wildcard_port: bool) -> String {
    let port = if wildcard_port && e.1 == 0 { "*".into() } else { format!("{}", e.1) };
    match e.0 {
        IpAddr::V4(a) if a.is_unspecified() => format!("0.0.0.0:{port}"),
        IpAddr::V4(a) => format!("{a}:{port}"),
        IpAddr::V6(a) if a.is_unspecified() => format!("[::]:{port}"),
        IpAddr::V6(a) if a.0[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF] => {
            format!("[::ffff:{}]:{port}", Ipv4(a.0[12..].try_into().unwrap()))
        }
        IpAddr::V6(a) => format!("[{a}]:{port}"),
    }
}

/// Options.
#[derive(Clone, Copy, Debug, Default)]
pub struct Opts {
    pub tcp: bool,
    pub udp: bool,
    pub listening: bool,
    pub all: bool,
    pub v4: bool,
    pub v6: bool,
    pub no_header: bool,
    /// `-p`: a Process column.
    pub processes: bool,
    /// `-e`: the user and inode after each socket.
    pub extended: bool,
    /// `state`/`exclude`: the states shown (bit n for state n).
    pub states: Option<u16>,
}

/// The table for `socks` (right-aligned queues, left-aligned addresses);
/// `users` gives each inode's processes for `-p`
/// (`users:(("name",pid=N,fd=N),...)`).
pub fn table(socks: &[Sock], o: &Opts, users: &BTreeMap<u64, String>) -> Vec<String> {
    let both = o.tcp == o.udp;
    let shown = |s: &Sock| match o.states {
        Some(bits) => bits & (1 << s.state.min(15)) != 0,
        None => o.all || listening(s) == o.listening,
    };
    let picked: Vec<&Sock> = socks.iter().filter(|s| both || s.tcp == o.tcp).filter(|s| shown(s)).collect();
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut head = Vec::new();
    if both {
        head.push(String::from("Netid"));
    }
    for h in ["State", "Recv-Q", "Send-Q", "Local Address:Port", "Peer Address:Port"] {
        head.push(h.into());
    }
    if o.processes {
        head.push("Process".into());
    }
    for s in &picked {
        let mut r = Vec::new();
        if both {
            r.push(String::from(if s.tcp { "tcp" } else { "udp" }));
        }
        r.push(state_name(s).into());
        r.push(format!("{}", s.rx_queue));
        r.push(format!("{}", s.tx_queue));
        r.push(endpoint(&s.local, false));
        r.push(endpoint(&s.remote, true));
        if o.processes {
            r.push(users.get(&s.inode).filter(|_| s.inode != 0).cloned().unwrap_or_default());
        }
        if o.extended {
            let last = r.last_mut().expect("columns");
            last.push_str(&format!(" uid:{} ino:{}", s.uid, s.inode));
            *last = String::from(last.trim_start());
        }
        rows.push(r);
    }
    let cols = head.len();
    let width: Vec<usize> = (0..cols)
        .map(|c| rows.iter().map(|r| r[c].len()).chain(core::iter::once(head[c].len())).max().unwrap_or(0))
        .collect();
    let line = |r: &[String]| {
        let mut s = String::new();
        for (c, v) in r.iter().enumerate() {
            let w = width[c];
            let queue = head[c].ends_with("-Q");
            if queue {
                s.push_str(&format!("{v:>w$}"));
            } else if c + 1 == cols {
                s.push_str(v);
            } else {
                s.push_str(&format!("{v:<w$}"));
            }
            if c + 1 < cols {
                s.push(' ');
            }
        }
        String::from(s.trim_end())
    };
    let mut out = Vec::new();
    if !o.no_header {
        out.push(line(&head));
    }
    out.extend(rows.iter().map(|r| line(r)));
    out
}

/// Each socket inode's holders, from /proc/PID/fd links (`socket:[N]`),
/// as `-p` shows them.
pub fn socket_users() -> BTreeMap<u64, String> {
    let mut held: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for e in slate_rt::fs::read_dir(b"/proc").unwrap_or_default() {
        let Ok(pid) = core::str::from_utf8(&e.name).unwrap_or("").parse::<u32>() else { continue };
        let comm = slate_rt::fs::read_file(format!("/proc/{pid}/comm").as_bytes()).unwrap_or_default();
        let comm = String::from(String::from_utf8_lossy(&comm).trim());
        for f in slate_rt::fs::read_dir(format!("/proc/{pid}/fd").as_bytes()).unwrap_or_default() {
            let fd = String::from_utf8_lossy(&f.name);
            let Ok(link) = slate_rt::fs::readlink(format!("/proc/{pid}/fd/{fd}").as_bytes()) else { continue };
            let link = String::from_utf8_lossy(&link);
            if let Some(ino) = link.strip_prefix("socket:[").and_then(|l| l.strip_suffix(']')?.parse().ok()) {
                held.entry(ino).or_default().push(format!("(\"{comm}\",pid={pid},fd={fd})"));
            }
        }
    }
    held.into_iter().map(|(ino, v)| (ino, format!("users:({})", v.join(",")))).collect()
}

const USAGE: &str = "usage: ss [-t] [-u] [-l] [-a] [-n] [-H] [-p] [-e] [-4|-6] [state STATE]... [exclude STATE]...";

pub fn main() -> i32 {
    let mut o = Opts::default();
    let args: Vec<String> =
        slate_rt::env::args().iter().skip(1).map(|a| String::from(String::from_utf8_lossy(a))).collect();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if a == "state" || a == "exclude" {
            let Some(bits) = args.get(i).and_then(|n| state_bits(n)) else {
                eprintln!("ss: wrong state name: {}", args.get(i).map_or("", |s| s.as_str()));
                return 1;
            };
            i += 1;
            let all = state_bits("all").unwrap_or(0);
            o.states = Some(match (a.as_str(), o.states) {
                ("state", s) => s.unwrap_or(0) | bits,
                (_, s) => s.unwrap_or(all) & !bits,
            });
            continue;
        }
        let Some(flags) = a.strip_prefix('-').filter(|f| !f.is_empty() && !f.starts_with('-')) else {
            if a == "--help" {
                println!("{USAGE}");
                return 0;
            }
            eprintln!("ss: unknown argument '{a}'");
            return 1;
        };
        for f in flags.chars() {
            match f {
                't' => o.tcp = true,
                'u' => o.udp = true,
                'l' => o.listening = true,
                'a' => o.all = true,
                'n' => {}
                'H' => o.no_header = true,
                'p' => o.processes = true,
                'e' => o.extended = true,
                '4' => o.v4 = true,
                '6' => o.v6 = true,
                'h' => {
                    println!("{USAGE}");
                    return 0;
                }
                c => {
                    eprintln!("ss: invalid option -- '{c}'");
                    return 1;
                }
            }
        }
    }
    let (four, six) = (o.v4 || !o.v6, o.v6 || !o.v4);
    let mut socks = Vec::new();
    for (file, tcp, v6) in [("tcp", true, false), ("tcp6", true, true), ("udp", false, false), ("udp6", false, true)] {
        if (v6 && !six) || (!v6 && !four) {
            continue;
        }
        let path = format!("/proc/net/{file}");
        match slate_rt::fs::read_file(path.as_bytes()) {
            Ok(t) => socks.extend(parse(&String::from_utf8_lossy(&t), tcp)),
            Err(e) => {
                eprintln!("ss: {path}: {}", e.message());
                return 1;
            }
        }
    }
    let users = if o.processes { socket_users() } else { BTreeMap::new() };
    for l in table(&socks, &o, &users) {
        println!("{l}");
    }
    0
}
