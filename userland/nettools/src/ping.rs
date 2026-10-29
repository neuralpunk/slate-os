// SPDX-License-Identifier: MIT OR Apache-2.0

//! `ping [-4|-6] [-c COUNT] [-i SECONDS] [-W SECONDS] [-w DEADLINE] [-s BYTES]
//! [-I INTERFACE|ADDRESS] [-q] HOST` (ADR 0052): ICMP or ICMPv6 echo
//! requests (RFC 792, RFC 4443) through ping sockets, so no privilege is
//! needed (icmp(7), ping_group_range). A line per reply, with its TTL or
//! hop limit, and a summary at the end (after COUNT requests, at the
//! DEADLINE in seconds, or on Ctrl-C), as users of ping(8) expect; `-I`
//! sends from an interface (SO_BINDTODEVICE) or an address; `ping6` is
//! `ping -6`. Exits 0 if a reply came, 1 if none did, 2 on other errors.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_net::IpAddr;
use slate_rt::{eprintln, io, net, println, signal, time};

use crate::resolve::{self, Family};

const ICMP_ECHO: u8 = 8;
const ICMP_ECHOREPLY: u8 = 0;
const ICMP6_ECHO_REQUEST: u8 = 128;
const ICMP6_ECHO_REPLY: u8 = 129;
const IPPROTO_ICMP: usize = 1;
const IPPROTO_ICMPV6: usize = 58;
const SOCK_DGRAM: usize = 2;

/// An echo request: type, code, checksum (the kernel's), identifier (the
/// socket's), sequence number, then `size` bytes of data.
pub fn request(v6: bool, seq: u16, size: usize) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + size);
    p.extend_from_slice(&[if v6 { ICMP6_ECHO_REQUEST } else { ICMP_ECHO }, 0, 0, 0, 0, 0]);
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend((0..size).map(|i| (i % 256) as u8));
    p
}

/// The sequence number of an echo reply.
pub fn reply_seq(v6: bool, p: &[u8]) -> Option<u16> {
    let want = if v6 { ICMP6_ECHO_REPLY } else { ICMP_ECHOREPLY };
    (p.len() >= 8 && p[0] == want).then(|| u16::from_be_bytes([p[6], p[7]]))
}

/// Milliseconds as ping(8) shows a round trip: three decimals under 1 ms,
/// two under 10, one under 100, none above.
pub fn ms(us: u64) -> String {
    let (whole, frac) = (us / 1000, us % 1000);
    match whole {
        0 => format!("0.{frac:03}"),
        1..=9 => format!("{whole}.{:02}", frac / 10),
        10..=99 => format!("{whole}.{}", frac / 100),
        _ => format!("{whole}"),
    }
}

fn ms3(us: u64) -> String {
    format!("{}.{:03}", us / 1000, us % 1000)
}

fn isqrt(n: u128) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x as u64
}

/// The summary lines: counts and loss, then the round trips (min, mean,
/// max and mean deviation) if any reply came.
pub fn summary(host: &str, sent: u32, rtts_us: &[u64], elapsed_ms: u64) -> Vec<String> {
    let got = rtts_us.len() as u32;
    let loss = ((sent - got.min(sent)) * 100).checked_div(sent).unwrap_or(0);
    let mut out = alloc::vec![
        format!("--- {host} ping statistics ---"),
        format!("{sent} packets transmitted, {got} received, {loss}% packet loss, time {elapsed_ms}ms"),
    ];
    if let (Some(min), Some(max)) = (rtts_us.iter().min(), rtts_us.iter().max()) {
        let n = u128::from(got);
        let sum: u128 = rtts_us.iter().map(|&r| u128::from(r)).sum();
        let sq: u128 = rtts_us.iter().map(|&r| u128::from(r) * u128::from(r)).sum();
        let mean = sum / n;
        let mdev = isqrt((sq / n).saturating_sub(mean * mean));
        out.push(format!("rtt min/avg/max/mdev = {}/{}/{}/{} ms", ms3(*min), ms3(mean as u64), ms3(*max), ms3(mdev)));
    }
    out
}

/// `1`, `0.5`, `.2`: seconds as microseconds.
pub fn seconds(s: &str) -> Option<u64> {
    let (w, f) = s.split_once('.').unwrap_or((s, ""));
    if (w.is_empty() && f.is_empty()) || f.len() > 6 || !f.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let whole: u64 = if w.is_empty() { 0 } else { w.parse().ok()? };
    let frac: u64 = if f.is_empty() { 0 } else { f.parse::<u64>().ok()? * 10u64.pow(6 - f.len() as u32) };
    whole.checked_mul(1_000_000)?.checked_add(frac)
}

fn now_us() -> u64 {
    let (s, ns) = time::now(time::CLOCK_MONOTONIC);
    s as u64 * 1_000_000 + ns as u64 / 1000
}

struct Opts {
    family: Family,
    count: Option<u32>,
    interval_us: u64,
    wait_us: u64,
    /// `-w`: when to stop, after the start.
    deadline_us: Option<u64>,
    /// `-I`: an interface's name or a source address.
    source: Option<String>,
    size: usize,
    quiet: bool,
    host: String,
}

const USAGE: &str = "usage: ping [-4|-6] [-c COUNT] [-i SECONDS] [-W SECONDS] [-w DEADLINE] [-s BYTES] [-I INTERFACE|ADDRESS] [-q] HOST";

/// A reply's line, as ping(8) prints it.
pub fn reply_line(n: usize, from: &str, seq: u16, ttl: Option<u8>, rtt_us: u64) -> String {
    let ttl = ttl.map(|t| format!(" ttl={t}")).unwrap_or_default();
    format!("{n} bytes from {from}: icmp_seq={seq}{ttl} time={} ms", ms(rtt_us))
}

fn options() -> Result<Opts, String> {
    let args: Vec<String> = slate_rt::env::args().iter().skip(1).map(|a| String::from_utf8_lossy(a).into()).collect();
    // Called as ping6: IPv6 (as ping(8) has it).
    let ping6 = slate_rt::env::args().first().is_some_and(|a| a.rsplit(|b| *b == b'/').next() == Some(b"ping6"));
    let mut o = Opts {
        family: if ping6 { Family::V6 } else { Family::Any },
        count: None,
        interval_us: 1_000_000,
        wait_us: 10_000_000,
        deadline_us: None,
        source: None,
        size: 56,
        quiet: false,
        host: String::new(),
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let mut value = |what: &str| {
            i += 1;
            args.get(i).cloned().ok_or_else(|| format!("ping: option requires an argument -- '{what}'"))
        };
        match a {
            "-4" => o.family = Family::V4,
            "-6" => o.family = Family::V6,
            "-q" => o.quiet = true,
            "-c" => {
                let v = value("c")?;
                o.count = Some(v.parse().ok().filter(|c| *c > 0).ok_or(format!("ping: bad count: {v}"))?);
            }
            "-i" => {
                let v = value("i")?;
                o.interval_us = seconds(&v).filter(|t| *t >= 2000).ok_or(format!("ping: bad interval: {v}"))?;
            }
            "-W" => {
                let v = value("W")?;
                o.wait_us = seconds(&v).ok_or(format!("ping: bad wait time: {v}"))?;
            }
            "-w" => {
                let v = value("w")?;
                o.deadline_us = Some(seconds(&v).ok_or(format!("ping: bad linger time: {v}"))?);
            }
            "-I" => o.source = Some(value("I")?),
            "-s" => {
                let v = value("s")?;
                o.size = v.parse().ok().filter(|s| *s <= 65507).ok_or(format!("ping: bad packet size: {v}"))?;
            }
            "-h" | "--help" => return Err(String::new()),
            a if a.starts_with('-') && a.len() > 1 => return Err(format!("ping: invalid option -- '{}'", &a[1..])),
            a if o.host.is_empty() => o.host = a.into(),
            _ => return Err(USAGE.into()),
        }
        i += 1;
    }
    if o.host.is_empty() {
        return Err(USAGE.into());
    }
    Ok(o)
}

pub fn main() -> i32 {
    let o = match options() {
        Ok(o) => o,
        Err(m) if m.is_empty() => {
            println!("{USAGE}");
            return 0;
        }
        Err(m) => {
            eprintln!("{m}");
            return 2;
        }
    };
    let target = match resolve::resolve(&o.host, o.family) {
        Ok(a) => a[0],
        Err(e) => {
            eprintln!("ping: {}", e.describe(&o.host));
            return 2;
        }
    };
    let v6 = matches!(target, IpAddr::V6(_));
    let peer = resolve::peer(target, 0);
    let fd = match net::socket_for(&peer, SOCK_DGRAM, if v6 { IPPROTO_ICMPV6 } else { IPPROTO_ICMP }) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("ping: socket: {}", e.message());
            return 2;
        }
    };
    // Each reply's TTL or hop limit (shown when it comes).
    let _ = net::want_ttl(fd, v6);
    if let Some(src) = &o.source {
        let bound = match resolve::literal(src) {
            Some(a) => net::bind_peer(fd, &resolve::peer(a, 0)),
            None => net::set_option(fd, net::SO_BINDTODEVICE, src.as_bytes()),
        };
        if let Err(e) = bound {
            eprintln!("ping: {src}: {}", e.message());
            return 2;
        }
    }
    let _ = signal::set(signal::SIGINT, signal::Disposition::CatchInterrupt);
    let header = if v6 { 40 } else { 20 };
    println!("PING {} ({target}) {}({}) bytes of data.", o.host, o.size, o.size + 8 + header);
    let start = now_us();
    let (mut sent, mut next_send) = (0u32, start);
    let mut out: BTreeMap<u16, u64> = BTreeMap::new();
    let mut rtts = Vec::new();
    let mut last_deadline = None;
    let mut buf = alloc::vec![0u8; o.size + 64];
    let deadline = o.deadline_us.map(|d| start + d);
    while !signal::pending(signal::SIGINT) {
        let now = now_us();
        if deadline.is_some_and(|d| now >= d)
            || o.count.is_some_and(|c| o.deadline_us.is_some() && rtts.len() as u32 >= c)
        {
            break;
        }
        let more = o.count.is_none_or(|c| sent < c);
        if more && now >= next_send {
            sent += 1;
            let seq = sent as u16;
            match net::send_to_peer(fd, &request(v6, seq, o.size), &peer) {
                Ok(_) => {
                    out.insert(seq, now);
                }
                Err(e) => eprintln!("ping: sendmsg: {}", e.message()),
            }
            next_send = now + o.interval_us;
            if o.count == Some(sent) {
                last_deadline = Some(now + o.wait_us);
            }
            continue;
        }
        if !more && (out.is_empty() || last_deadline.is_some_and(|d| now >= d)) {
            break;
        }
        let mut until = if more { next_send } else { last_deadline.unwrap_or(now) };
        if let Some(d) = deadline {
            until = until.min(d);
        }
        let wait_ms = until.saturating_sub(now).div_ceil(1000).min(i32::MAX as u64) as i32;
        let mut p = [io::PollFd { fd, events: io::POLLIN, revents: 0 }];
        if !matches!(io::poll(&mut p, wait_ms), Ok(n) if n > 0) {
            continue;
        }
        let Ok((n, from, ttl)) = net::recv_with_ttl(fd, &mut buf) else { continue };
        let Some(seq) = reply_seq(v6, &buf[..n]) else { continue };
        let Some(at) = out.remove(&seq) else { continue };
        let rtt = now_us().saturating_sub(at);
        rtts.push(rtt);
        if !o.quiet {
            let from = from.map_or_else(|| format!("{target}"), |p| format!("{}", peer_ip(&p)));
            println!("{}", reply_line(n, &from, seq, ttl, rtt));
        }
    }
    let _ = io::close(fd);
    println!();
    for l in summary(&o.host, sent, &rtts, (now_us() - start) / 1000) {
        println!("{l}");
    }
    if rtts.is_empty() { 1 } else { 0 }
}

fn peer_ip(p: &net::Peer) -> IpAddr {
    match *p {
        net::Peer::V4(a, _) => IpAddr::V4(slate_net::Ipv4(a)),
        net::Peer::V6(a, _, _) => IpAddr::V6(slate_net::Ipv6(a)),
    }
}
