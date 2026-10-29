// SPDX-License-Identifier: MIT OR Apache-2.0

//! netd's clock setting (ADR 0052 §3): an SNTP client (RFC 4330, the
//! client side of RFC 5905) for the servers in `/etc/slate/ntp`, one
//! `server NAME[:PORT]` (or `[ADDR6]:PORT`) per line, `pool.ntp.org` when
//! the file is missing; a file without servers turns it off. netd asks
//! when a card is configured and every 17 minutes after. An offset over
//! half a second steps the clock (clock_settime, which also sets the RTC);
//! smaller ones are slewed at 500 ppm (`clock_adjust`, ADR 0078), which
//! finishes before the next round. Either way the clock then counts as
//! synchronized.
//!
//! netd is the DNS cache itself, so a server's name is looked up by
//! asking the cards' name servers directly, without blocking: everything
//! here is a state machine driven by netd's poll loop.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_net::{IpAddr, Ipv4, Ipv6};
use slate_rt::{eprintln, io, net, time};

use crate::config::Server;

pub const DEFAULT_SERVER: &str = "pool.ntp.org";
const NTP_PORT: u16 = 123;
/// Seconds from 1900 (NTP's era 0) to 1970 (RFC 5905 §6).
const UNIX_OFFSET: u64 = 2_208_988_800;
const INTERVAL_MS: u64 = 17 * 60 * 1000;
const RETRY_MS: u64 = 60 * 1000;
const TRY_MS: u64 = 2000;
/// Offsets up to this are slewed, bigger ones stepped.
const STEP_NS: i64 = 500_000_000;

/// A configured server: a name or an address, and a port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub host: String,
    pub port: u16,
}

/// `/etc/slate/ntp`'s servers (None: the file is missing) and the lines
/// it could not use.
pub fn parse(text: Option<&str>) -> (Vec<Peer>, Vec<usize>) {
    let Some(text) = text else {
        return (alloc::vec![Peer { host: DEFAULT_SERVER.into(), port: NTP_PORT }], Vec::new());
    };
    let mut out = Vec::new();
    let mut bad = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut words = line.split_whitespace();
        match (words.next(), words.next(), words.next()) {
            (Some("server"), Some(s), None) => match peer(s) {
                Some(p) => out.push(p),
                None => bad.push(n + 1),
            },
            _ => bad.push(n + 1),
        }
    }
    (out, bad)
}

fn peer(s: &str) -> Option<Peer> {
    if let Some(rest) = s.strip_prefix('[') {
        let (a, p) = rest.split_once(']')?;
        Ipv6::parse(a)?;
        let port = match p.strip_prefix(':') {
            Some(p) => p.parse().ok().filter(|p| *p != 0)?,
            None if p.is_empty() => NTP_PORT,
            None => return None,
        };
        return Some(Peer { host: a.into(), port });
    }
    if Ipv6::parse(s).is_some() {
        return Some(Peer { host: s.into(), port: NTP_PORT });
    }
    let (h, port) = match s.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok().filter(|p| *p != 0)?),
        None => (s, NTP_PORT),
    };
    let ok = !h.is_empty() && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    ok.then(|| Peer { host: h.into(), port })
}

fn literal(host: &str) -> Option<IpAddr> {
    Ipv4::parse(host).map(IpAddr::V4).or_else(|| Ipv6::parse(host).map(IpAddr::V6))
}

/// Nanoseconds since 1970 as an NTP timestamp (seconds since 1900 and a
/// fraction of 2^-32 s; past 2036 the seconds wrap into era 1, RFC 4330
/// §3).
pub fn to_ntp(unix_ns: i64) -> u64 {
    let secs = (unix_ns.div_euclid(1_000_000_000) as u64).wrapping_add(UNIX_OFFSET) & 0xFFFF_FFFF;
    let frac = ((unix_ns.rem_euclid(1_000_000_000) as u64) << 32) / 1_000_000_000;
    (secs << 32) | frac
}

/// An NTP timestamp as nanoseconds since 1970: seconds with the top bit
/// clear are in era 1 (2036 to 2104), as RFC 4330 §3 suggests.
pub fn from_ntp(t: u64) -> i64 {
    let secs = t >> 32;
    let secs = if secs & 0x8000_0000 != 0 { secs } else { secs + (1 << 32) };
    let ns = ((t & 0xFFFF_FFFF) * 1_000_000_000) >> 32;
    (secs - UNIX_OFFSET) as i64 * 1_000_000_000 + ns as i64
}

/// A client request (RFC 4330 §4): leap indicator 0, version 4, mode 3;
/// the transmit timestamp, which the server sends back as originate.
pub fn request(transmit: u64) -> [u8; 48] {
    let mut p = [0u8; 48];
    p[0] = 0x23;
    p[40..48].copy_from_slice(&transmit.to_be_bytes());
    p
}

/// What a reply gave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// The clock's offset from the server's and the round trip, in ns.
    Time { offset: i64, delay: i64 },
    /// A kiss-o'-death (stratum 0): stop asking this server for a while.
    Kiss,
}

/// Check a server's reply to the request sent at `t1` (an NTP timestamp),
/// received at `t4_ns` (since 1970): mode 4, version 3 or 4, our
/// timestamp as originate, a server that is synchronized (RFC 4330 §5).
pub fn reply(p: &[u8], t1: u64, t4_ns: i64) -> Option<Reply> {
    if p.len() < 48 {
        return None;
    }
    let (li, vn, mode) = (p[0] >> 6, (p[0] >> 3) & 7, p[0] & 7);
    let ts = |at: usize| u64::from_be_bytes(p[at..at + 8].try_into().unwrap());
    if mode != 4 || !(3..=4).contains(&vn) || ts(24) != t1 {
        return None;
    }
    if p[1] == 0 {
        return Some(Reply::Kiss);
    }
    if li == 3 || p[1] > 15 || ts(40) == 0 {
        return None;
    }
    let (t1, t2, t3) = (from_ntp(t1), from_ntp(ts(32)), from_ntp(ts(40)));
    let offset = ((t2 - t1) + (t3 - t4_ns)) / 2;
    let delay = (t4_ns - t1) - (t3 - t2);
    Some(Reply::Time { offset, delay })
}

fn realtime_ns() -> i64 {
    let (s, ns) = time::now(time::CLOCK_REALTIME);
    s * 1_000_000_000 + ns
}

/// Where a round is.
#[derive(Debug)]
enum Step {
    /// Waiting for the next round (ms, monotonic).
    Idle { at: Option<u64> },
    /// Looking up server `server`'s name with name server `ns`.
    Lookup { server: usize, ns: usize, id: u16, six: bool, fd: i32, deadline: u64 },
    /// Asking address `addr` of server `server` (the rest wait in `more`).
    Ask { server: usize, addr: IpAddr, more: Vec<IpAddr>, fd: i32, t1: u64, deadline: u64 },
}

/// The SNTP client.
#[derive(Debug)]
pub struct Client {
    servers: Vec<Peer>,
    step: Step,
    seed: u16,
    /// For /run/netd/status.
    pub status: String,
}

impl Client {
    pub fn new(servers: Vec<Peer>, seed: u16) -> Client {
        let status = if servers.is_empty() { "ntp off".into() } else { "ntp waiting".into() };
        Client { servers, step: Step::Idle { at: None }, seed, status }
    }

    /// A card came up: start a round now. One already going starts over,
    /// since the new card may be the way to the servers.
    pub fn kick(&mut self, now: u64) {
        if !self.servers.is_empty() {
            self.close();
            self.step = Step::Idle { at: Some(now) };
        }
    }

    pub fn next(&self) -> Option<u64> {
        match &self.step {
            Step::Idle { at } => *at,
            Step::Lookup { deadline, .. } | Step::Ask { deadline, .. } => Some(*deadline),
        }
    }

    pub fn fd(&self) -> Option<i32> {
        match &self.step {
            Step::Idle { .. } => None,
            Step::Lookup { fd, .. } | Step::Ask { fd, .. } => Some(*fd),
        }
    }

    fn close(&mut self) {
        if let Some(fd) = self.fd() {
            let _ = io::close(fd);
        }
    }

    fn idle(&mut self, after: u64, now: u64) {
        self.close();
        self.step = Step::Idle { at: Some(now + after) };
    }

    /// Start on server `server` (or give up the round past the last).
    fn begin(&mut self, server: usize, dns: &[Server], now: u64) {
        self.close();
        let Some(p) = self.servers.get(server) else {
            self.status = "ntp failed (no server answered)".into();
            self.idle(RETRY_MS, now);
            return;
        };
        match literal(&p.host) {
            Some(a) => self.ask(server, a, Vec::new(), now),
            None => self.lookup(server, 0, false, dns, now),
        }
    }

    fn lookup(&mut self, server: usize, ns: usize, six: bool, dns: &[Server], now: u64) {
        self.close();
        let Some(s) = dns.get(ns) else {
            // No name server had IPv4 addresses: ask for IPv6 ones, then
            // try the next server.
            if !six {
                return self.lookup(server, 0, true, dns, now);
            }
            return self.begin(server + 1, dns, now);
        };
        self.seed = self.seed.wrapping_mul(25173).wrapping_add(13849);
        let id = self.seed;
        let qtype = if six { slate_dns::TYPE_AAAA } else { slate_dns::TYPE_A };
        let to = peer_of(s.addr, s.port);
        let sent = slate_dns::query_type(id, &self.servers[server].host, qtype)
            .ok()
            .and_then(|q| net::socket_for(&to, 2, 0).ok().map(|fd| (fd, q)))
            .map(|(fd, q)| (fd, net::send_to_peer(fd, &q, &to).is_ok()));
        match sent {
            Some((fd, true)) => {
                self.step = Step::Lookup { server, ns, id, six, fd, deadline: now + TRY_MS };
            }
            Some((fd, false)) => {
                let _ = io::close(fd);
                self.lookup(server, ns + 1, six, dns, now);
            }
            None => self.begin(server + 1, dns, now),
        }
    }

    fn ask(&mut self, server: usize, addr: IpAddr, more: Vec<IpAddr>, now: u64) {
        self.close();
        let to = peer_of(addr, self.servers[server].port);
        let Ok(fd) = net::socket_for(&to, 2, 0) else {
            self.step = Step::Ask { server, addr, more, fd: -1, t1: 0, deadline: now };
            return;
        };
        let t1 = to_ntp(realtime_ns());
        let _ = net::send_to_peer(fd, &request(t1), &to);
        self.step = Step::Ask { server, addr, more, fd, t1, deadline: now + TRY_MS };
    }

    /// Time passed: start a round, or move on from what did not answer.
    pub fn tick(&mut self, dns: &[Server], now: u64) {
        match core::mem::replace(&mut self.step, Step::Idle { at: None }) {
            Step::Idle { at: Some(t) } if now >= t => self.begin(0, dns, now),
            Step::Lookup { server, ns, six, fd, deadline, .. } if now >= deadline => {
                let _ = io::close(fd);
                self.lookup(server, ns + 1, six, dns, now);
            }
            Step::Ask { server, mut more, fd, deadline, .. } if now >= deadline => {
                if fd >= 0 {
                    let _ = io::close(fd);
                }
                if more.is_empty() {
                    self.begin(server + 1, dns, now);
                } else {
                    let a = more.remove(0);
                    self.ask(server, a, more, now);
                }
            }
            other => self.step = other,
        }
    }

    /// Something to read on [`Client::fd`].
    pub fn ready(&mut self, dns: &[Server], now: u64) {
        let mut buf = [0u8; 1500];
        let Some(fd) = self.fd() else { return };
        let Ok((n, _)) = net::recv_from_peer(fd, &mut buf) else { return };
        let t4 = realtime_ns();
        match &self.step {
            Step::Lookup { server, id, six, .. } => {
                let (server, id, six) = (*server, *id, *six);
                let name = self.servers[server].host.clone();
                let found: Result<Vec<IpAddr>, _> = if six {
                    slate_dns::answer6(&buf[..n], id, &name)
                        .map(|v| v.into_iter().map(|a| IpAddr::V6(Ipv6(a))).collect())
                } else {
                    slate_dns::answer(&buf[..n], id, &name)
                        .map(|v| v.into_iter().map(|a| IpAddr::V4(Ipv4(a))).collect())
                };
                let found = match found {
                    Ok(v) => v,
                    // "No such name" and the like: nothing here.
                    Err(slate_dns::Error::Rcode(_)) => Vec::new(),
                    // Not the answer to this query.
                    Err(_) => return,
                };
                match found.split_first() {
                    Some((a, rest)) => self.ask(server, *a, rest.to_vec(), now),
                    None if !six => self.lookup(server, 0, true, dns, now),
                    None => self.begin(server + 1, dns, now),
                }
            }
            Step::Ask { server, addr, t1, .. } => {
                let (server, addr) = (*server, *addr);
                match reply(&buf[..n], *t1, t4) {
                    Some(Reply::Time { offset, .. }) => {
                        let name = &self.servers[server].host;
                        let mut what = "";
                        if offset.abs() <= STEP_NS {
                            match time::adjust(offset, true) {
                                Ok(_) => what = " slewing",
                                Err(e) => eprintln!("netd: cannot slew the clock: {}", e.message()),
                            }
                        } else {
                            let now_ns = realtime_ns() + offset;
                            match time::set(
                                time::CLOCK_REALTIME,
                                now_ns.div_euclid(1_000_000_000),
                                now_ns.rem_euclid(1_000_000_000),
                            ) {
                                Ok(()) => {
                                    eprintln!("netd: clock stepped by {} from {name} ({addr})", seconds(offset));
                                    what = " stepped";
                                    let _ = time::adjust(0, true);
                                }
                                Err(e) => eprintln!("netd: cannot set the clock: {}", e.message()),
                            }
                        }
                        self.status = format!("ntp synced {name} {addr} offset {}{what}", seconds(offset));
                        self.idle(INTERVAL_MS, now);
                    }
                    Some(Reply::Kiss) => {
                        // Told to go away: the next server, this one later.
                        self.begin(server + 1, dns, now);
                    }
                    None => {}
                }
            }
            Step::Idle { .. } => {}
        }
    }
}

fn peer_of(a: IpAddr, port: u16) -> net::Peer {
    match a {
        IpAddr::V4(a) => net::Peer::V4(a.0, port),
        IpAddr::V6(a) => net::Peer::V6(a.0, port, 0),
    }
}

/// Nanoseconds as `+1.234s`.
pub fn seconds(ns: i64) -> String {
    let sign = if ns < 0 { '-' } else { '+' };
    let ms = ns.unsigned_abs() / 1_000_000;
    format!("{sign}{}.{:03}s", ms / 1000, ms % 1000)
}
