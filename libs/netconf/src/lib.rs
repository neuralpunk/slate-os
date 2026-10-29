// SPDX-License-Identifier: MIT OR Apache-2.0

//! `/etc/slate/network` (ADR 0048, ADR 0050, ADR 0052): a section per
//! card, `[NAME]`, and `[*]` for every card not named. Keys: `method`
//! (`dhcp`, the default; `static`; `off`), and for a static card `address
//! = ADDR/PREFIX` and `gateway = ADDR`. `dns = SERVER...` (spaces or
//! commas between) adds name servers to what DHCP and routers give, with
//! any method: `10.0.2.3`, `fec0::3`, or with a port, `10.0.2.2:5353`,
//! `[fec0::2]:5353`. IPv6 comes from routers by itself; `address6 =
//! ADDR/PREFIX` and `gateway6 = ADDR` add a fixed address and default
//! route. `#` starts a comment.
//!
//! netd reads it; the installer, `slate-network` and Settings change one
//! card's section at a time ([`set_card`], ADR 0054), leaving the rest of
//! the file as it was.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use slate_net::{IpAddr, Ipv4, Ipv6};

/// A name server: its address and port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Server {
    pub addr: IpAddr,
    pub port: u16,
}

impl Server {
    pub fn new(addr: impl Into<IpAddr>) -> Server {
        Server { addr: addr.into(), port: 53 }
    }

    /// `ADDR`, `ADDR:PORT` (IPv4), `[ADDR]:PORT` (IPv6).
    pub fn parse(s: &str) -> Option<Server> {
        if let Some(rest) = s.strip_prefix('[') {
            let (a, p) = rest.split_once(']')?;
            let port = match p.strip_prefix(':') {
                Some(p) => p.parse().ok().filter(|p| *p != 0)?,
                None if p.is_empty() => 53,
                None => return None,
            };
            return Some(Server { addr: Ipv6::parse(a)?.into(), port });
        }
        if let Some(a) = Ipv6::parse(s) {
            return Some(Server::new(a));
        }
        let (a, port) = match s.split_once(':') {
            Some((a, p)) => (a, p.parse().ok().filter(|p| *p != 0)?),
            None => (s, 53),
        };
        Some(Server { addr: Ipv4::parse(a)?.into(), port })
    }
}

impl fmt::Display for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.addr, self.port) {
            (a, 53) => write!(f, "{a}"),
            (IpAddr::V4(a), p) => write!(f, "{a}:{p}"),
            (IpAddr::V6(a), p) => write!(f, "[{a}]:{p}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Method {
    Dhcp,
    Static { addr: Ipv4, prefix_len: u8, gateway: Option<Ipv4> },
    Off,
}

/// A card's IPv6 settings beyond what routers give.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Six {
    pub address: Option<(Ipv6, u8)>,
    pub gateway: Option<Ipv6>,
}

/// A section: the card's method, its IPv6 settings, its name servers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Card {
    /// The card's name, or `*` for every card not named.
    pub name: String,
    pub method: Method,
    pub six: Six,
    pub dns: Vec<Server>,
}

/// The whole file: sections by card name (`*` for the rest).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Network {
    sections: Vec<Card>,
}

/// A line the file could not use, for the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    pub line: usize,
    pub what: String,
}

#[derive(Default)]
struct Section {
    name: String,
    method: Option<String>,
    address: Option<(Ipv4, u8)>,
    gateway: Option<Ipv4>,
    dns: Vec<Server>,
    six: Six,
    line: usize,
}

fn cidr6(s: &str) -> Option<(Ipv6, u8)> {
    let (a, p) = s.split_once('/')?;
    let p: u8 = p.parse().ok().filter(|p| (1..=128).contains(p))?;
    Some((Ipv6::parse(a)?, p))
}

fn cidr(s: &str) -> Option<(Ipv4, u8)> {
    let (a, p) = s.split_once('/')?;
    let p: u8 = p.parse().ok().filter(|p| (1..=32).contains(p))?;
    Some((Ipv4::parse(a)?, p))
}

impl Network {
    /// Parse the file. Lines it cannot use are reported and skipped; a
    /// section that ends up unusable (a static card without an address)
    /// is left out, so that card falls back to `[*]`.
    pub fn parse(text: &str) -> (Network, Vec<Problem>) {
        let mut problems = Vec::new();
        let mut sections: Vec<Section> = Vec::new();
        for (n, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut bad = |what: &str| problems.push(Problem { line: n + 1, what: what.into() });
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                let name = name.trim();
                if name.is_empty() || name.contains(char::is_whitespace) {
                    bad("bad section name");
                    continue;
                }
                sections.push(Section { name: name.into(), line: n + 1, ..Default::default() });
                continue;
            }
            let Some(sec) = sections.last_mut() else {
                bad("setting outside a section");
                continue;
            };
            let Some((key, value)) = line.split_once('=') else {
                bad("expected KEY = VALUE");
                continue;
            };
            let value = value.trim();
            match key.trim() {
                "method" => sec.method = Some(value.into()),
                "address" => match cidr(value) {
                    Some(a) => sec.address = Some(a),
                    None => bad("address must be ADDR/PREFIX"),
                },
                "gateway" => match Ipv4::parse(value) {
                    Some(g) => sec.gateway = Some(g),
                    None => bad("bad gateway address"),
                },
                "dns" => {
                    for d in value.split([' ', ',']).filter(|d| !d.is_empty()) {
                        match Server::parse(d) {
                            Some(server) => sec.dns.push(server),
                            None => bad("bad name server address"),
                        }
                    }
                }
                "address6" => match cidr6(value) {
                    Some(a) => sec.six.address = Some(a),
                    None => bad("address6 must be ADDR/PREFIX"),
                },
                "gateway6" => match Ipv6::parse(value) {
                    Some(g) => sec.six.gateway = Some(g),
                    None => bad("bad IPv6 gateway address"),
                },
                _ => bad("unknown setting"),
            }
        }
        let mut net = Network::default();
        for s in sections {
            let method = match s.method.as_deref().unwrap_or("dhcp") {
                "dhcp" => Method::Dhcp,
                "off" => Method::Off,
                "static" => match s.address {
                    Some((addr, prefix_len)) => Method::Static { addr, prefix_len, gateway: s.gateway },
                    None => {
                        problems.push(Problem { line: s.line, what: "a static card needs an address".into() });
                        continue;
                    }
                },
                _ => {
                    problems.push(Problem { line: s.line, what: "method must be dhcp, static or off".into() });
                    continue;
                }
            };
            net.sections.retain(|c| c.name != s.name);
            net.sections.push(Card { name: s.name, method, six: s.six, dns: s.dns });
        }
        (net, problems)
    }

    /// How to configure the card called `name`: its section, else `[*]`,
    /// else DHCP.
    fn card(&self, name: &str) -> Option<&Card> {
        let find = |n: &str| self.sections.iter().find(|c| c.name == n);
        find(name).or_else(|| find("*"))
    }

    pub fn method(&self, name: &str) -> Method {
        self.card(name).map_or(Method::Dhcp, |c| c.method.clone())
    }

    /// The card's IPv6 settings (its section's, else `[*]`'s).
    pub fn six(&self, name: &str) -> Six {
        self.card(name).map(|c| c.six.clone()).unwrap_or_default()
    }

    /// The name servers the file gives the card.
    pub fn dns(&self, name: &str) -> Vec<Server> {
        self.card(name).map(|c| c.dns.clone()).unwrap_or_default()
    }

    /// The sections, in the file's order (a name given twice: the last).
    pub fn cards(&self) -> &[Card] {
        &self.sections
    }
}

/// A fixed address given on the kernel's command line for one boot
/// (`slate.ip=ADDR/PREFIX[,GATEWAY[,DNS...]]`, ADR 0076): the card the
/// kernel gave it to (`slate.net=NAME`, else the first card with a link)
/// takes it instead of what the file says, as the kernel did before user
/// space took over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootOverride {
    /// `slate.net=`: the card it is for; `None`: the first with a link.
    pub card: Option<String>,
    pub method: Method,
    pub dns: Vec<Server>,
}

/// The override in a kernel command line, if it has a usable `slate.ip=`.
pub fn boot_override(cmdline: &str) -> Option<BootOverride> {
    let word = |key: &str| cmdline.split_ascii_whitespace().find_map(|w| w.strip_prefix(key));
    let v = word("slate.ip=")?;
    let mut fields = v.split(',');
    let (addr, prefix_len) = cidr(fields.next()?)?;
    let gateway = match fields.next() {
        Some(g) if !g.is_empty() => Some(Ipv4::parse(g)?),
        _ => None,
    };
    let dns = fields.map(|d| Ipv4::parse(d).map(Server::new)).collect::<Option<Vec<_>>>()?;
    Some(BootOverride {
        card: word("slate.net=").filter(|n| valid_name(n)).map(String::from),
        method: Method::Static { addr, prefix_len, gateway },
        dns,
    })
}

/// Whether `name` can name a section: a card's name or `*`.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 15 && !name.contains(|c: char| c.is_whitespace() || "[]#=/".contains(c))
}

/// What the words of a card's settings could not use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BadWords(pub String);

fn bad<T>(what: impl Into<String>) -> Result<T, BadWords> {
    Err(BadWords(what.into()))
}

impl Card {
    /// A card's settings from words, as `slate-network` takes them and the
    /// broker's `network=` action carries them: `CARD dhcp|off|static
    /// ADDR/PREFIX [gateway ADDR]`, then optionally `dns SERVER...`,
    /// `address6 ADDR/PREFIX` and `gateway6 ADDR`.
    pub fn from_words(words: &[&str]) -> Result<Card, BadWords> {
        let Some((&name, rest)) = words.split_first() else { return bad("which card?") };
        if !valid_name(name) {
            return bad(format!("\"{name}\" is not a card's name"));
        }
        let Some((&method, mut rest)) = rest.split_first() else { return bad("dhcp, static or off?") };
        let method = match method {
            "dhcp" => Method::Dhcp,
            "off" => Method::Off,
            "static" => {
                let Some((&a, r)) = rest.split_first() else { return bad("static needs ADDR/PREFIX") };
                let Some((addr, prefix_len)) = cidr(a) else { return bad(format!("\"{a}\" is not ADDR/PREFIX")) };
                rest = r;
                let mut gateway = None;
                if let [k, g, r @ ..] = rest
                    && (*k == "gateway" || *k == "via")
                {
                    gateway = Some(Ipv4::parse(g).ok_or_else(|| BadWords(format!("\"{g}\" is not an address")))?);
                    rest = r;
                }
                Method::Static { addr, prefix_len, gateway }
            }
            m => return bad(format!("\"{m}\": dhcp, static or off?")),
        };
        let mut card = Card { name: name.into(), method, six: Six::default(), dns: Vec::new() };
        let mut it = rest.iter().peekable();
        while let Some(&k) = it.next() {
            match k {
                "dns" => {
                    let mut any = false;
                    while let Some(&&v) = it.peek() {
                        if matches!(v, "dns" | "address6" | "gateway6") {
                            break;
                        }
                        it.next();
                        for d in v.split(',').filter(|d| !d.is_empty()) {
                            card.dns.push(
                                Server::parse(d).ok_or_else(|| BadWords(format!("\"{d}\" is not a name server")))?,
                            );
                            any = true;
                        }
                    }
                    if !any {
                        return bad("dns needs a name server");
                    }
                }
                "address6" => {
                    let v = it.next().copied().unwrap_or("");
                    card.six.address = Some(cidr6(v).ok_or_else(|| BadWords(format!("\"{v}\" is not ADDR/PREFIX")))?);
                }
                "gateway6" => {
                    let v = it.next().copied().unwrap_or("");
                    card.six.gateway =
                        Some(Ipv6::parse(v).ok_or_else(|| BadWords(format!("\"{v}\" is not an address")))?);
                }
                k => return bad(format!("\"{k}\" is not a setting")),
            }
        }
        Ok(card)
    }

    /// The words [`Card::from_words`] reads back.
    pub fn words(&self) -> Vec<String> {
        let mut w = alloc::vec![self.name.clone()];
        match &self.method {
            Method::Dhcp => w.push("dhcp".into()),
            Method::Off => w.push("off".into()),
            Method::Static { addr, prefix_len, gateway } => {
                w.push("static".into());
                w.push(format!("{addr}/{prefix_len}"));
                if let Some(g) = gateway {
                    w.push("gateway".into());
                    w.push(format!("{g}"));
                }
            }
        }
        if !self.dns.is_empty() {
            w.push("dns".into());
            w.extend(self.dns.iter().map(|d| format!("{d}")));
        }
        if let Some((a, p)) = self.six.address {
            w.push("address6".into());
            w.push(format!("{a}/{p}"));
        }
        if let Some(g) = self.six.gateway {
            w.push("gateway6".into());
            w.push(format!("{g}"));
        }
        w
    }

    /// The section as the file holds it.
    pub fn section(&self) -> String {
        let mut s = format!("[{}]\n", self.name);
        match &self.method {
            Method::Dhcp => s.push_str("method = dhcp\n"),
            Method::Off => s.push_str("method = off\n"),
            Method::Static { addr, prefix_len, gateway } => {
                s.push_str(&format!("method = static\naddress = {addr}/{prefix_len}\n"));
                if let Some(g) = gateway {
                    s.push_str(&format!("gateway = {g}\n"));
                }
            }
        }
        if !self.dns.is_empty() {
            let d: Vec<String> = self.dns.iter().map(|d| format!("{d}")).collect();
            s.push_str(&format!("dns = {}\n", d.join(" ")));
        }
        if let Some((a, p)) = self.six.address {
            s.push_str(&format!("address6 = {a}/{p}\n"));
        }
        if let Some(g) = self.six.gateway {
            s.push_str(&format!("gateway6 = {g}\n"));
        }
        s
    }
}

/// Problems with the fields of a fixed address, by field: short enough to
/// show under each.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FieldErrors {
    pub address: Option<&'static str>,
    pub gateway: Option<&'static str>,
    pub dns: Option<&'static str>,
}

/// A fixed address for the cards in `name` (`*` for every card) from what
/// a person typed (the installers and Settings, ADR 0054): `ADDR/PREFIX`,
/// an optional gateway, name servers with spaces or commas between.
pub fn fixed(name: &str, address: &str, gateway: &str, dns: &str) -> Result<Card, FieldErrors> {
    let mut e = FieldErrors::default();
    let address = address.trim();
    if cidr(address).is_none() {
        e.address = Some("Like 192.168.1.20/24.");
    }
    let gateway = gateway.trim();
    if !gateway.is_empty() && Ipv4::parse(gateway).is_none() {
        e.gateway = Some("Like 192.168.1.1, or empty.");
    }
    let servers: Vec<&str> = dns.split([' ', ',']).filter(|s| !s.is_empty()).collect();
    if servers.iter().any(|s| Server::parse(s).is_none()) {
        e.dns = Some("Like 9.9.9.9 1.1.1.1.");
    }
    if e != FieldErrors::default() {
        return Err(e);
    }
    let mut words = alloc::vec![name, "static", address];
    if !gateway.is_empty() {
        words.extend(["gateway", gateway]);
    }
    if !servers.is_empty() {
        words.push("dns");
        words.extend(servers);
    }
    Card::from_words(&words).map_err(|_| FieldErrors { address: Some("Like 192.168.1.20/24."), ..e })
}

/// `text` (the file) with `card`'s section in place of the one it had
/// (the first, if it had several), or added at the end. Other sections,
/// and all comments and blank lines, stay.
pub fn set_card(text: &str, card: &Card) -> String {
    let mut out = String::new();
    let mut inside = false;
    let mut placed = false;
    for line in text.lines() {
        let t = line.split('#').next().unwrap_or("").trim();
        if let Some(name) = t.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            inside = name.trim() == card.name;
            if inside && !placed {
                out.push_str(&card.section());
                placed = true;
            }
            if inside {
                continue;
            }
        }
        // The old section's settings go; comments and blank lines stay.
        if !inside || t.is_empty() {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !placed {
        if !out.is_empty() && !out.ends_with("\n\n") {
            out.push('\n');
        }
        out.push_str(&card.section());
    }
    out
}

/// `text` without the section of card `name` (which then follows `[*]`).
/// Other sections, comments and blank lines stay.
pub fn remove_card(text: &str, name: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for line in text.lines() {
        let t = line.split('#').next().unwrap_or("").trim();
        if let Some(n) = t.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            inside = n.trim() == name;
            if inside {
                continue;
            }
        }
        if !inside || t.is_empty() {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests;
