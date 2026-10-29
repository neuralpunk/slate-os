// SPDX-License-Identifier: MIT OR Apache-2.0

//! Name resolution for Slate's tools: a literal address (`10.0.2.2`,
//! `fec0::2`, `[fec0::2]`), then `/etc/hosts` (hosts(5)), then DNS (RFC
//! 1035; AAAA records, RFC 3596) through the name servers in
//! `/etc/resolv.conf` (resolv.conf(5): netd's cache, ADR 0052). Its own
//! crate so that slate-libc's getaddrinfo can use it without the HTTP and
//! TLS code (ADR 0075).

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_net::{IpAddr, Ipv4, Ipv6};
use slate_rt::{fs, io, net};

/// Which addresses a lookup wants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Any,
    V4,
    V6,
}

impl Family {
    fn wants(self, a: &IpAddr) -> bool {
        match self {
            Family::Any => true,
            Family::V4 => !a.is_v6(),
            Family::V6 => a.is_v6(),
        }
    }
}

/// A literal address: dotted IPv4, or IPv6 (bare or in brackets).
pub fn literal(host: &str) -> Option<IpAddr> {
    let h = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    Ipv4::parse(h).map(IpAddr::V4).or_else(|| Ipv6::parse(h).map(IpAddr::V6))
}

/// A server written `ADDR`, `ADDR:PORT` or `[ADDR]:PORT`: (address, port).
pub fn server(s: &str) -> Option<(IpAddr, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (a, p) = rest.split_once(']')?;
        let port = match p.strip_prefix(':') {
            Some(p) => p.parse().ok().filter(|p| *p != 0)?,
            None if p.is_empty() => 53,
            None => return None,
        };
        return Some((IpAddr::V6(Ipv6::parse(a)?), port));
    }
    if let Some(a) = Ipv6::parse(s) {
        return Some((IpAddr::V6(a), 53));
    }
    let (a, port) = match s.split_once(':') {
        Some((a, p)) => (a, p.parse().ok().filter(|p| *p != 0)?),
        None => (s, 53),
    };
    Some((IpAddr::V4(Ipv4::parse(a)?), port))
}

/// The addresses `/etc/hosts`'s text gives `host`.
pub fn from_hosts(text: &str, host: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut f = line.split('#').next().unwrap_or("").split_whitespace();
        let Some(ip) = f.next().and_then(literal) else { continue };
        if f.any(|n| n.eq_ignore_ascii_case(host)) && !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

/// The `nameserver` lines of a resolv.conf.
pub fn nameservers(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| l.split('#').next().unwrap_or("").trim().strip_prefix("nameserver"))
        .filter_map(|s| literal(s.trim()))
        .collect()
}

pub fn peer(a: IpAddr, port: u16) -> net::Peer {
    match a {
        IpAddr::V4(a) => net::Peer::V4(a.0, port),
        IpAddr::V6(a) => net::Peer::V6(a.0, port, 0),
    }
}

/// Why a name has no address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The servers say it does not exist.
    NoSuchHost,
    /// It exists but has no address of the kind asked for.
    NoAddress,
    /// No server answered.
    NoAnswer,
    BadName,
}

impl Error {
    pub fn describe(&self, host: &str) -> String {
        match self {
            Error::NoSuchHost => format!("{host}: no such host"),
            Error::NoAddress => format!("{host}: no address"),
            Error::NoAnswer => format!("{host}: no name server answered"),
            Error::BadName => format!("{host}: not a valid host name"),
        }
    }
}

/// Ask `server` for `name`'s records of `qtype` (A or AAAA).
pub fn query(server: net::Peer, name: &str, qtype: u16, timeout_ms: i32) -> Result<Vec<IpAddr>, Error> {
    let mut id = [0u8; 2];
    let _ = slate_rt::process::random(&mut id);
    let id = u16::from_ne_bytes(id);
    let q = slate_dns::query_type(id, name, qtype).map_err(|_| Error::BadName)?;
    let fd = net::socket_for(&server, 2, 0).map_err(|_| Error::NoAnswer)?;
    let r = (|| {
        net::send_to_peer(fd, &q, &server).map_err(|_| Error::NoAnswer)?;
        let mut buf = [0u8; 4096];
        loop {
            let mut p = [io::PollFd { fd, events: io::POLLIN, revents: 0 }];
            if io::poll(&mut p, timeout_ms).unwrap_or(0) == 0 {
                return Err(Error::NoAnswer);
            }
            let Ok((n, from)) = net::recv_from_peer(fd, &mut buf) else { return Err(Error::NoAnswer) };
            if from != Some(server) {
                continue;
            }
            let found = if qtype == slate_dns::TYPE_AAAA {
                slate_dns::answer6(&buf[..n], id, name).map(|v| v.into_iter().map(|a| IpAddr::V6(Ipv6(a))).collect())
            } else {
                slate_dns::answer(&buf[..n], id, name).map(|v| v.into_iter().map(|a| IpAddr::V4(Ipv4(a))).collect())
            };
            return match found {
                Ok(v) => Ok(v),
                Err(slate_dns::Error::Rcode(3)) => Err(Error::NoSuchHost),
                Err(slate_dns::Error::Rcode(_)) => Err(Error::NoAnswer),
                Err(_) => continue, // Not the answer to this query.
            };
        }
    })();
    let _ = io::close(fd);
    r
}

/// `host`'s addresses: a literal, /etc/hosts, or DNS through `servers`
/// (the resolv.conf ones when None), IPv4 first.
pub fn resolve_with(host: &str, family: Family, servers: Option<&[(IpAddr, u16)]>) -> Result<Vec<IpAddr>, Error> {
    if let Some(a) = literal(host) {
        return if family.wants(&a) { Ok(alloc::vec![a]) } else { Err(Error::NoAddress) };
    }
    if servers.is_none() {
        let hosts = fs::read_file(b"/etc/hosts").unwrap_or_default();
        let found: Vec<IpAddr> =
            from_hosts(&String::from_utf8_lossy(&hosts), host).into_iter().filter(|a| family.wants(a)).collect();
        if !found.is_empty() {
            return Ok(found);
        }
    }
    let conf: Vec<(IpAddr, u16)> = match servers {
        Some(s) => s.to_vec(),
        None => {
            let text = fs::read_file(b"/etc/resolv.conf").unwrap_or_default();
            nameservers(&String::from_utf8_lossy(&text)).into_iter().map(|a| (a, 53)).collect()
        }
    };
    if conf.is_empty() {
        return Err(Error::NoAnswer);
    }
    let mut kinds = Vec::new();
    if family != Family::V6 {
        kinds.push(slate_dns::TYPE_A);
    }
    if family != Family::V4 {
        kinds.push(slate_dns::TYPE_AAAA);
    }
    let mut out = Vec::new();
    let mut last = Error::NoAnswer;
    let mut answered = false;
    for qtype in kinds {
        for &(a, port) in &conf {
            match query(peer(a, port), host, qtype, 2000) {
                Ok(v) => {
                    answered = true;
                    out.extend(v);
                    break;
                }
                Err(Error::NoSuchHost) => return Err(Error::NoSuchHost),
                Err(e) => last = e,
            }
        }
    }
    match (out.is_empty(), answered) {
        (false, _) => Ok(out),
        (true, true) => Err(Error::NoAddress),
        (true, false) => Err(last),
    }
}

/// `host`'s addresses through the system's name servers.
pub fn resolve(host: &str, family: Family) -> Result<Vec<IpAddr>, Error> {
    resolve_with(host, family, None)
}
