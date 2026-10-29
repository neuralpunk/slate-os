// SPDX-License-Identifier: MIT OR Apache-2.0

//! `ip [-4|-6] OBJECT [COMMAND [ARGS]]` (ADR 0052): links, addresses,
//! routes and neighbours over route netlink, shown and changed the way
//! users of ip(8) expect.
//!
//! - `ip addr [show [dev] NAME]`, `ip addr add|del|replace ADDR[/LEN] dev
//!   NAME`
//! - `ip route [show]`, `ip route add|del|replace PREFIX|default [via
//!   ADDR] [dev NAME] [metric N] [src ADDR] [proto P] [scope link|host]`
//! - `ip link [show [dev] NAME]`, `ip link set [dev] NAME up|down|mtu N...`
//! - `ip neigh [show [dev NAME]]` (without the device on each line when
//!   one is named), `ip neigh add|del|replace ADDR [lladdr MAC] dev NAME`
//!
//! - `ip addr flush dev NAME`: every address of the device (of the family
//!   with `-4`/`-6`)
//! - `ip route get ADDR`: the route the main table picks (the longest
//!   prefix, then the lowest metric) and the source address with it
//! - `-br`/`-brief` and `-o`/`-oneline` for `addr` and `link`; `-s`/`-stats`
//!   adds `link`'s counters (from /proc/net/dev)
//!
//! Objects and commands may be shortened (`a`, `r`, `l`, `n`; `s`,
//! `del`). Exits 1 for a bad command line, 2 when the kernel refuses.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_net::{IpAddr, Ipv4, Ipv6, Mac};
use slate_rt::{eprintln, println};

use crate::rtnl::{self, Addr, Conn, Link, Message, Neigh, Route};

/// Which addresses to show or what a change is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Any,
    V4,
    V6,
}

impl Family {
    fn af(self) -> u8 {
        match self {
            Family::Any => rtnl::AF_UNSPEC,
            Family::V4 => rtnl::AF_INET,
            Family::V6 => rtnl::AF_INET6,
        }
    }
    fn takes(self, a: &IpAddr) -> bool {
        match self {
            Family::Any => true,
            Family::V4 => matches!(a, IpAddr::V4(_)),
            Family::V6 => matches!(a, IpAddr::V6(_)),
        }
    }
}

/// A command-line or kernel error, with what to print.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Usage(String),
    Kernel(String),
}

type Result<T> = core::result::Result<T, Error>;

fn usage<T>(s: impl Into<String>) -> Result<T> {
    Err(Error::Usage(s.into()))
}

fn kernel(e: slate_rt::Errno) -> Error {
    Error::Kernel(format!("RTNETLINK answers: {}", e.message()))
}

/// Whether `word` names `full`: a prefix of it at least `min` long.
fn is(word: &str, full: &str, min: usize) -> bool {
    word.len() >= min && full.starts_with(word)
}

fn flag_names(flags: u32) -> String {
    let mut v = Vec::new();
    if flags & rtnl::IFF_UP != 0 && flags & rtnl::IFF_RUNNING == 0 && flags & rtnl::IFF_LOOPBACK == 0 {
        v.push("NO-CARRIER");
    }
    for (bit, name) in [
        (rtnl::IFF_LOOPBACK, "LOOPBACK"),
        (rtnl::IFF_BROADCAST, "BROADCAST"),
        (rtnl::IFF_POINTOPOINT, "POINTOPOINT"),
        (rtnl::IFF_MULTICAST, "MULTICAST"),
        (rtnl::IFF_NOARP, "NOARP"),
        (rtnl::IFF_PROMISC, "PROMISC"),
        (rtnl::IFF_UP, "UP"),
        (rtnl::IFF_LOWER_UP, "LOWER_UP"),
    ] {
        if flags & bit != 0 {
            v.push(name);
        }
    }
    v.join(",")
}

/// A link's two lines.
pub fn link_lines(l: &Link) -> [String; 2] {
    let state = state_name(l);
    let first =
        format!("{}: {}: <{}> mtu {} state {} qlen {}", l.index, l.name, flag_names(l.flags), l.mtu, state, l.txqlen);
    let kind = if l.flags & rtnl::IFF_LOOPBACK != 0 { "loopback" } else { "ether" };
    let mac = l.mac.unwrap_or_default();
    let second = match l.broadcast {
        Some(b) => format!("    link/{kind} {mac:?} brd {b:?}"),
        None => format!("    link/{kind} {mac:?}"),
    };
    [first, second]
}

fn scope_name(s: u8) -> String {
    match s {
        rtnl::RT_SCOPE_UNIVERSE => "global".into(),
        200 => "site".into(),
        rtnl::RT_SCOPE_LINK => "link".into(),
        rtnl::RT_SCOPE_HOST => "host".into(),
        255 => "nowhere".into(),
        n => format!("{n}"),
    }
}

fn lifetime(s: Option<u32>) -> String {
    s.map_or_else(|| "forever".into(), |s| format!("{s}sec"))
}

/// An address's two lines.
pub fn addr_lines(a: &Addr, name: &str) -> [String; 2] {
    let mut s = match a.addr {
        IpAddr::V4(ip) => format!("    inet {ip}/{}", a.prefix_len),
        IpAddr::V6(ip) => format!("    inet6 {ip}/{}", a.prefix_len),
    };
    if let Some(b) = a.broadcast {
        s.push_str(&format!(" brd {b}"));
    }
    s.push_str(&format!(" scope {}", scope_name(a.scope)));
    if a.flags & rtnl::IFA_F_PERMANENT == 0 {
        s.push_str(" dynamic");
    }
    if a.flags & rtnl::IFA_F_TENTATIVE != 0 {
        s.push_str(" tentative");
    }
    if a.flags & rtnl::IFA_F_DEPRECATED != 0 {
        s.push_str(" deprecated");
    }
    if matches!(a.addr, IpAddr::V4(_)) {
        s.push(' ');
        s.push_str(if a.label.is_empty() { name } else { &a.label });
    }
    [s, format!("       valid_lft {} preferred_lft {}", lifetime(a.valid), lifetime(a.preferred))]
}

fn proto_name(p: u8) -> String {
    // Route origins (rtnetlink(7), "rtm_protocol"; 9 is router
    // advertisements, 16 DHCP, as ip(8) names them).
    match p {
        1 => "redirect".into(),
        2 => "kernel".into(),
        3 => "boot".into(),
        4 => "static".into(),
        9 => "ra".into(),
        16 => "dhcp".into(),
        n => format!("{n}"),
    }
}

fn proto_number(s: &str) -> Option<u8> {
    (1..=255).find(|p| proto_name(*p) == s).or_else(|| s.parse().ok())
}

/// A route's line (`names` maps link indexes to names).
pub fn route_line(r: &Route, names: &BTreeMap<u32, String>) -> String {
    let mut s = match (&r.dst, r.dst_len) {
        (_, 0) => "default".into(),
        (Some(d), 32) if r.family == rtnl::AF_INET => format!("{d}"),
        (Some(d), 128) if r.family == rtnl::AF_INET6 => format!("{d}"),
        (Some(d), n) => format!("{d}/{n}"),
        (None, n) => format!("?/{n}"),
    };
    if let Some(g) = &r.gateway {
        s.push_str(&format!(" via {g}"));
    }
    if let Some(i) = r.oif {
        match names.get(&i) {
            Some(n) => s.push_str(&format!(" dev {n}")),
            None => s.push_str(&format!(" dev if{i}")),
        }
    }
    if r.protocol != 0 {
        s.push_str(&format!(" proto {}", proto_name(r.protocol)));
    }
    if r.scope != rtnl::RT_SCOPE_UNIVERSE {
        s.push_str(&format!(" scope {}", scope_name(r.scope)));
    }
    if let Some(p) = &r.prefsrc {
        s.push_str(&format!(" src {p}"));
    }
    if let Some(m) = r.metric {
        s.push_str(&format!(" metric {m}"));
    }
    s
}

/// A neighbour's line (without the device when `name` is None: the list
/// is for one).
pub fn neigh_line(n: &Neigh, name: Option<&str>) -> String {
    let mut s = format!("{}", n.dst);
    if let Some(name) = name {
        s.push_str(&format!(" dev {name}"));
    }
    if let Some(m) = n.lladdr {
        s.push_str(&format!(" lladdr {m:?}"));
    }
    let state = match n.state {
        rtnl::NUD_INCOMPLETE => "INCOMPLETE",
        rtnl::NUD_REACHABLE => "REACHABLE",
        rtnl::NUD_STALE => "STALE",
        rtnl::NUD_DELAY => "DELAY",
        rtnl::NUD_PROBE => "PROBE",
        rtnl::NUD_FAILED => "FAILED",
        rtnl::NUD_NOARP => "NOARP",
        rtnl::NUD_PERMANENT => "PERMANENT",
        _ => "NONE",
    };
    s.push(' ');
    s.push_str(state);
    s
}

/// `ADDR` or `ADDR/LEN` (the length defaults to the whole address).
pub fn prefix(s: &str) -> Option<(IpAddr, u8)> {
    let (a, len) = match s.split_once('/') {
        Some((a, l)) => (a, Some(l.parse::<u8>().ok()?)),
        None => (s, None),
    };
    let a: IpAddr = match Ipv4::parse(a) {
        Some(v4) => v4.into(),
        None => Ipv6::parse(a)?.into(),
    };
    let max = if matches!(a, IpAddr::V4(_)) { 32 } else { 128 };
    let len = len.unwrap_or(max);
    (len <= max).then_some((a, len))
}

fn address(s: &str) -> Result<IpAddr> {
    match prefix(s) {
        Some((a, 32 | 128)) => Ok(a),
        _ => usage(format!("\"{s}\" is not a valid address")),
    }
}

/// `aa:bb:cc:dd:ee:ff`.
pub fn mac(s: &str) -> Option<Mac> {
    let mut m = [0u8; 6];
    let mut parts = s.split(':');
    for b in &mut m {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(Mac(m))
}

/// A link's operational state's name.
fn state_name(l: &Link) -> &'static str {
    // Operational states (RFC 2863, as rtnetlink numbers them).
    match l.operstate {
        1 => "NOTPRESENT",
        2 => "DOWN",
        3 => "LOWERLAYERDOWN",
        4 => "TESTING",
        5 => "DORMANT",
        6 => "UP",
        _ => "UNKNOWN",
    }
}

/// A link's `-br` line: name, state, MAC address and flags in columns.
pub fn brief_link(l: &Link) -> String {
    let mac = format!("{:?}", l.mac.unwrap_or_default());
    format!("{:<16} {:<14} {mac:<17} <{}>", l.name, state_name(l), flag_names(l.flags))
}

/// A link's `-br` line for `ip addr`: name, state, then its addresses.
pub fn brief_addrs(l: &Link, addrs: &[&Addr]) -> String {
    let list: Vec<String> = addrs.iter().map(|a| format!("{}/{}", a.addr, a.prefix_len)).collect();
    String::from(format!("{:<16} {:<14} {}", l.name, state_name(l), list.join(" ")).trim_end())
}

/// Two lines as `-o` joins them.
pub fn oneline(first: &str, second: &str) -> String {
    format!("{first}\\{second}")
}

/// `-s`'s lines for a link: (bytes, packets, errors, dropped) received and
/// sent, from /proc/net/dev.
pub fn stats_lines(rx: [u64; 4], tx: [u64; 4]) -> [String; 4] {
    let row = |v: [u64; 4]| format!("    {:>10} {:>7} {:>6} {:>7}", v[0], v[1], v[2], v[3]);
    [
        String::from("    RX:  bytes packets errors dropped"),
        row(rx),
        String::from("    TX:  bytes packets errors dropped"),
        row(tx),
    ]
}

/// The counters /proc/net/dev gives `name`: received and sent (bytes,
/// packets, errors, dropped).
pub fn dev_counters(text: &str, name: &str) -> Option<([u64; 4], [u64; 4])> {
    text.lines().find_map(|l| {
        let (n, rest) = l.split_once(':')?;
        if n.trim() != name {
            return None;
        }
        let v: Vec<u64> = rest.split_whitespace().filter_map(|w| w.parse().ok()).collect();
        Some(([*v.first()?, *v.get(1)?, *v.get(2)?, *v.get(3)?], [*v.get(8)?, *v.get(9)?, *v.get(10)?, *v.get(11)?]))
    })
}

fn octets(a: &IpAddr) -> &[u8] {
    match a {
        IpAddr::V4(a) => &a.0,
        IpAddr::V6(a) => &a.0,
    }
}

/// Whether `addr` is in `net`/`len`.
pub fn in_prefix(addr: &IpAddr, net: &IpAddr, len: u8) -> bool {
    let (a, n) = (octets(addr), octets(net));
    if a.len() != n.len() {
        return false;
    }
    let full = usize::from(len / 8);
    let rest = len % 8;
    a[..full.min(a.len())] == n[..full.min(n.len())]
        && (rest == 0 || full >= a.len() || (a[full] ^ n[full]) >> (8 - rest) == 0)
}

/// The route of `routes` (the main table's) `dst` takes: the longest
/// prefix, then the lowest metric; and the source address: the route's
/// own, or the first of its device's addresses of the family.
pub fn route_get<'a>(routes: &'a [Route], addrs: &[Addr], dst: &IpAddr) -> Option<(&'a Route, Option<IpAddr>)> {
    let route = routes
        .iter()
        .filter(|r| r.table == rtnl::RT_TABLE_MAIN)
        .filter(|r| match &r.dst {
            _ if r.dst_len == 0 => octets(dst).len() == if r.family == rtnl::AF_INET6 { 16 } else { 4 },
            Some(n) => in_prefix(dst, n, r.dst_len),
            None => false,
        })
        .max_by(|a, b| a.dst_len.cmp(&b.dst_len).then(b.metric.unwrap_or(0).cmp(&a.metric.unwrap_or(0))))?;
    let src = route.prefsrc.or_else(|| {
        addrs.iter().find(|a| Some(a.index) == route.oif && octets(&a.addr).len() == octets(dst).len()).map(|a| a.addr)
    });
    Some((route, src))
}

/// How things are shown (`-br`, `-o`, `-s`).
#[derive(Clone, Copy, Debug, Default)]
struct Show {
    brief: bool,
    oneline: bool,
    stats: bool,
}

struct Ip {
    family: Family,
    conn: Conn,
    links: Vec<Link>,
    show: Show,
}

impl Ip {
    fn names(&self) -> BTreeMap<u32, String> {
        self.links.iter().map(|l| (l.index, l.name.clone())).collect()
    }

    fn index(&self, name: &str) -> Result<u32> {
        match self.links.iter().find(|l| l.name == name) {
            Some(l) => Ok(l.index),
            None => usage(format!("Cannot find device \"{name}\"")),
        }
    }

    fn name(&self, index: u32) -> String {
        self.links.iter().find(|l| l.index == index).map_or_else(|| format!("if{index}"), |l| l.name.clone())
    }

    fn addresses(&mut self) -> Result<Vec<Addr>> {
        let msgs = self.conn.dump(rtnl::RTM_GETADDR, self.family.af()).map_err(kernel)?;
        Ok(msgs
            .into_iter()
            .filter_map(|m| match m {
                Message::Addr(a) if self.family.takes(&a.addr) => Some(a),
                _ => None,
            })
            .collect())
    }

    fn show_links(&mut self, dev: Option<&str>, with_addrs: bool) -> Result<()> {
        let only = dev.map(|d| self.index(d)).transpose()?;
        let addrs = if with_addrs { self.addresses()? } else { Vec::new() };
        let counters = if self.show.stats {
            String::from(String::from_utf8_lossy(&slate_rt::fs::read_file(b"/proc/net/dev").unwrap_or_default()))
        } else {
            String::new()
        };
        let show = self.show;
        for l in self.links.iter().filter(|l| only.is_none_or(|i| i == l.index)) {
            let mine: Vec<&Addr> = addrs.iter().filter(|a| a.index == l.index).collect();
            // With -4 or -6, links without such addresses are left out.
            if with_addrs && self.family != Family::Any && mine.is_empty() {
                continue;
            }
            if show.brief {
                println!("{}", if with_addrs { brief_addrs(l, &mine) } else { brief_link(l) });
                continue;
            }
            let [a, b] = link_lines(l);
            if show.oneline && with_addrs {
                // One line per address, after the link's index and name.
                for ad in mine {
                    let [x, y] = addr_lines(ad, &l.name);
                    println!("{}", oneline(&format!("{}: {}{x}", l.index, l.name), &y));
                }
                continue;
            }
            if show.oneline {
                println!("{}", oneline(&a, &b));
                continue;
            }
            println!("{a}");
            if !with_addrs || self.family == Family::Any {
                println!("{b}");
            }
            if show.stats
                && !with_addrs
                && let Some((rx, tx)) = dev_counters(&counters, &l.name)
            {
                for line in stats_lines(rx, tx) {
                    println!("{line}");
                }
            }
            for ad in mine {
                for line in addr_lines(ad, &l.name) {
                    println!("{line}");
                }
            }
        }
        Ok(())
    }

    fn addr(&mut self, args: &[&str]) -> Result<()> {
        let cmd = args.first().copied().unwrap_or("show");
        if is(cmd, "show", 1) || is(cmd, "list", 1) || cmd == "lst" {
            let dev = match args.get(1..).unwrap_or(&[]) {
                [] => None,
                ["dev", d] | [d] => Some(*d),
                _ => return usage("usage: ip addr show [dev] NAME"),
            };
            return self.show_links(dev, true);
        }
        if is(cmd, "flush", 1) {
            let dev = match args.get(1..).unwrap_or(&[]) {
                ["dev", d] | [d] => *d,
                _ => return usage("Flush requires arguments: ip addr flush dev NAME"),
            };
            let index = self.index(dev)?;
            for a in self.addresses()?.into_iter().filter(|a| a.index == index) {
                let seq = self.conn.next_seq();
                self.conn.change(&rtnl::address(seq, true, 0, index, a.addr, a.prefix_len)).map_err(kernel)?;
            }
            return Ok(());
        }
        let (del, flags) = if is(cmd, "add", 1) {
            (false, rtnl::NLM_F_CREATE | rtnl::NLM_F_EXCL)
        } else if is(cmd, "delete", 1) {
            (true, 0)
        } else if is(cmd, "replace", 3) || is(cmd, "change", 3) {
            (false, rtnl::NLM_F_CREATE | rtnl::NLM_F_REPLACE)
        } else {
            return usage(format!("Command \"{cmd}\" is unknown, try \"ip addr help\"."));
        };
        let (mut addr, mut dev) = (None, None);
        let mut it = args.get(1..).unwrap_or(&[]).iter();
        while let Some(&w) = it.next() {
            match w {
                "dev" => dev = it.next().copied(),
                "local" => addr = it.next().copied(),
                w if addr.is_none() => addr = Some(w),
                w => return usage(format!("Unknown argument \"{w}\"")),
            }
        }
        let Some((ip, len)) = addr.and_then(prefix) else { return usage("an address (ADDR/LEN) is needed") };
        let Some(dev) = dev else { return usage("Not enough information: \"dev\" argument is required.") };
        let index = self.index(dev)?;
        let seq = self.conn.next_seq();
        self.conn.change(&rtnl::address(seq, del, flags, index, ip, len)).map_err(kernel)
    }

    fn route(&mut self, args: &[&str]) -> Result<()> {
        let cmd = args.first().copied().unwrap_or("show");
        if is(cmd, "show", 1) || is(cmd, "list", 1) {
            let names = self.names();
            let fam = if self.family == Family::Any { Family::V4 } else { self.family };
            let msgs = self.conn.dump(rtnl::RTM_GETROUTE, fam.af()).map_err(kernel)?;
            for m in msgs {
                if let Message::Route(r) = m
                    && r.table == rtnl::RT_TABLE_MAIN
                    && r.family == fam.af()
                {
                    println!("{}", route_line(&r, &names));
                }
            }
            return Ok(());
        }
        if is(cmd, "get", 1) {
            let dst = match args.get(1..).unwrap_or(&[]) {
                ["to", d] | [d] => address(d)?,
                _ => return usage("usage: ip route get ADDR"),
            };
            let fam = if matches!(dst, IpAddr::V6(_)) { Family::V6 } else { Family::V4 };
            let routes: Vec<Route> = self
                .conn
                .dump(rtnl::RTM_GETROUTE, fam.af())
                .map_err(kernel)?
                .into_iter()
                .filter_map(|m| if let Message::Route(r) = m { Some(r) } else { None })
                .collect();
            let addrs = self.addresses()?;
            let Some((r, src)) = route_get(&routes, &addrs, &dst) else {
                return Err(Error::Kernel(String::from("RTNETLINK answers: Network is unreachable")));
            };
            let mut line = format!("{dst}");
            if let Some(g) = &r.gateway {
                line.push_str(&format!(" via {g}"));
            }
            if let Some(i) = r.oif {
                line.push_str(&format!(" dev {}", self.name(i)));
            }
            if let Some(s) = src {
                line.push_str(&format!(" src {s}"));
            }
            println!("{line} uid {}", slate_rt::process::getuid());
            println!("    cache");
            return Ok(());
        }
        let (del, flags) = if is(cmd, "add", 1) {
            (false, rtnl::NLM_F_CREATE | rtnl::NLM_F_EXCL)
        } else if is(cmd, "delete", 1) {
            (true, 0)
        } else if is(cmd, "replace", 3) || is(cmd, "change", 3) {
            (false, rtnl::NLM_F_CREATE | rtnl::NLM_F_REPLACE)
        } else {
            return usage(format!("Command \"{cmd}\" is unknown, try \"ip route help\"."));
        };
        let mut r = Route { protocol: rtnl::RTPROT_BOOT, ..Default::default() };
        let mut family = self.family;
        let mut dst = None;
        let mut it = args.get(1..).unwrap_or(&[]).iter();
        while let Some(&w) = it.next() {
            let mut value = || it.next().copied().ok_or_else(|| Error::Usage(format!("\"{w}\" needs a value")));
            match w {
                "via" => r.gateway = Some(address(value()?)?),
                "dev" | "oif" => r.oif = Some(self.index(value()?)?),
                "metric" | "priority" | "preference" => {
                    let v = value()?;
                    r.metric = Some(v.parse().map_err(|_| Error::Usage(format!("bad metric \"{v}\"")))?);
                }
                "src" => r.prefsrc = Some(address(value()?)?),
                "proto" | "protocol" => {
                    let v = value()?;
                    r.protocol = proto_number(v).ok_or_else(|| Error::Usage(format!("bad protocol \"{v}\"")))?;
                }
                "scope" => {
                    r.scope = match value()? {
                        "link" => rtnl::RT_SCOPE_LINK,
                        "host" => rtnl::RT_SCOPE_HOST,
                        "global" | "universe" => rtnl::RT_SCOPE_UNIVERSE,
                        v => return usage(format!("bad scope \"{v}\"")),
                    }
                }
                "to" => dst = Some(value()?),
                w if dst.is_none() => dst = Some(w),
                w => return usage(format!("Unknown argument \"{w}\"")),
            }
        }
        if let Some(g) = &r.gateway {
            family = if matches!(g, IpAddr::V6(_)) { Family::V6 } else { Family::V4 };
        }
        match dst {
            None => return usage("a destination (PREFIX or default) is needed"),
            Some("default" | "all" | "any") => {
                if family == Family::Any {
                    family = Family::V4;
                }
            }
            Some(d) => {
                let Some((a, len)) = prefix(d) else { return usage(format!("\"{d}\" is not a valid prefix")) };
                family = if matches!(a, IpAddr::V6(_)) { Family::V6 } else { Family::V4 };
                r.dst = Some(a);
                r.dst_len = len;
            }
        }
        if r.gateway.is_none() && r.dst.is_some() && r.scope == rtnl::RT_SCOPE_UNIVERSE && family == Family::V4 {
            r.scope = rtnl::RT_SCOPE_LINK;
        }
        r.family = family.af();
        if del {
            r.protocol = 0;
        }
        let seq = self.conn.next_seq();
        self.conn.change(&rtnl::route(seq, del, flags, &r)).map_err(kernel)
    }

    fn link(&mut self, args: &[&str]) -> Result<()> {
        let cmd = args.first().copied().unwrap_or("show");
        if is(cmd, "show", 1) || is(cmd, "list", 1) {
            let dev = match args.get(1..).unwrap_or(&[]) {
                [] => None,
                ["dev", d] | [d] => Some(*d),
                _ => return usage("usage: ip link show [dev] NAME"),
            };
            return self.show_links(dev, false);
        }
        if !is(cmd, "set", 1) {
            return usage(format!("Command \"{cmd}\" is unknown, try \"ip link help\"."));
        }
        let (mut dev, mut up, mut mtu) = (None, None, None);
        let mut it = args.get(1..).unwrap_or(&[]).iter();
        while let Some(&w) = it.next() {
            match w {
                "dev" => dev = it.next().copied(),
                "up" => up = Some(true),
                "down" => up = Some(false),
                "mtu" => {
                    let v = it.next().copied().unwrap_or("");
                    mtu = Some(v.parse::<u32>().map_err(|_| Error::Usage(format!("bad mtu \"{v}\"")))?);
                }
                w if dev.is_none() => dev = Some(w),
                w => return usage(format!("Unknown argument \"{w}\"")),
            }
        }
        let Some(dev) = dev else { return usage("Not enough information: \"dev\" argument is required.") };
        let index = self.index(dev)?;
        let seq = self.conn.next_seq();
        self.conn.change(&rtnl::set_link(seq, index, up, mtu)).map_err(kernel)
    }

    fn neigh(&mut self, args: &[&str]) -> Result<()> {
        let cmd = args.first().copied().unwrap_or("show");
        if is(cmd, "show", 1) || is(cmd, "list", 1) {
            let only = match args.get(1..).unwrap_or(&[]) {
                [] => None,
                ["dev", d] => Some(self.index(d)?),
                _ => return usage("usage: ip neigh show [dev NAME]"),
            };
            let msgs = self.conn.dump(rtnl::RTM_GETNEIGH, self.family.af()).map_err(kernel)?;
            for m in msgs {
                if let Message::Neigh(n) = m
                    && only.is_none_or(|i| i == n.index)
                    && self.family.takes(&n.dst)
                {
                    let name = self.name(n.index);
                    println!("{}", neigh_line(&n, only.is_none().then_some(name.as_str())));
                }
            }
            return Ok(());
        }
        let (del, flags) = if is(cmd, "add", 1) {
            (false, rtnl::NLM_F_CREATE | rtnl::NLM_F_EXCL)
        } else if is(cmd, "delete", 1) {
            (true, 0)
        } else if is(cmd, "replace", 3) || is(cmd, "change", 3) {
            (false, rtnl::NLM_F_CREATE | rtnl::NLM_F_REPLACE)
        } else {
            return usage(format!("Command \"{cmd}\" is unknown, try \"ip neigh help\"."));
        };
        let (mut ip, mut lladdr, mut dev) = (None, None, None);
        let mut it = args.get(1..).unwrap_or(&[]).iter();
        while let Some(&w) = it.next() {
            match w {
                "dev" => dev = it.next().copied(),
                "lladdr" => {
                    let v = it.next().copied().unwrap_or("");
                    lladdr = Some(mac(v).ok_or_else(|| Error::Usage(format!("\"{v}\" is not a valid lladdr")))?);
                }
                "nud" => {
                    // Entries set by hand are permanent.
                    it.next();
                }
                "to" => ip = it.next().copied(),
                w if ip.is_none() => ip = Some(w),
                w => return usage(format!("Unknown argument \"{w}\"")),
            }
        }
        let Some(ip) = ip else { return usage("an address is needed") };
        let ip = address(ip)?;
        let Some(dev) = dev else { return usage("Not enough information: \"dev\" argument is required.") };
        if !del && lladdr.is_none() {
            return usage("\"lladdr\" is needed");
        }
        let index = self.index(dev)?;
        let seq = self.conn.next_seq();
        self.conn.change(&rtnl::neighbour(seq, del, flags, index, ip, lladdr)).map_err(kernel)
    }
}

const USAGE: &str =
    "usage: ip [-4|-6] [-br] [-o] [-s] {addr|route|link|neigh} [show|add|del|replace|set|flush|get] ...";

/// Run `ip` with `args` (without the program name).
pub fn run(args: &[&str]) -> Result<()> {
    let mut family = Family::Any;
    let mut show = Show::default();
    let mut i = 0;
    while let Some(a) = args.get(i).filter(|a| a.starts_with('-')) {
        match *a {
            "-4" => family = Family::V4,
            "-br" | "-brief" => show.brief = true,
            "-o" | "-oneline" => show.oneline = true,
            "-s" | "-stats" | "-statistics" => show.stats = true,
            "-6" => family = Family::V6,
            "-f" | "-family" => {
                i += 1;
                family = match args.get(i).copied() {
                    Some("inet") => Family::V4,
                    Some("inet6") => Family::V6,
                    _ => return usage("-f wants inet or inet6"),
                };
            }
            "-h" | "-help" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            a => return usage(format!("Option \"{a}\" is unknown, try \"ip -help\".")),
        }
        i += 1;
    }
    let Some(&object) = args.get(i) else { return usage(USAGE) };
    if object == "help" {
        println!("{USAGE}");
        return Ok(());
    }
    let rest = &args[i + 1..];
    let mut conn = Conn::open().map_err(|e| Error::Kernel(format!("cannot open netlink socket: {}", e.message())))?;
    let links = conn
        .dump(rtnl::RTM_GETLINK, rtnl::AF_UNSPEC)
        .map_err(kernel)?
        .into_iter()
        .filter_map(|m| if let Message::Link(l) = m { Some(l) } else { None })
        .collect();
    let mut ip = Ip { family, conn, links, show };
    if is(object, "address", 1) {
        ip.addr(rest)
    } else if is(object, "route", 1) {
        ip.route(rest)
    } else if is(object, "link", 1) {
        ip.link(rest)
    } else if is(object, "neighbour", 1) || is(object, "neighbor", 1) {
        ip.neigh(rest)
    } else {
        usage(format!("Object \"{object}\" is unknown, try \"ip help\"."))
    }
}

pub fn main() -> i32 {
    let owned: Vec<String> = slate_rt::env::args().iter().skip(1).map(|a| String::from_utf8_lossy(a).into()).collect();
    let args: Vec<&str> = owned.iter().map(String::as_str).collect();
    match run(&args) {
        Ok(()) => 0,
        Err(Error::Usage(m)) => {
            eprintln!("{m}");
            1
        }
        Err(Error::Kernel(m)) => {
            eprintln!("{m}");
            2
        }
    }
}
