// SPDX-License-Identifier: MIT OR Apache-2.0

//! netd (ADR 0048, ADR 0052, ADR 0012: ours), Slate's network daemon: it
//! configures every network card as `/etc/slate/network` says (DHCP by
//! default, or a fixed address), follows links as they come and go (a
//! cable, a USB adapter), and answers name lookups through a DNS cache on
//! 127.0.0.53 that `/run/resolv.conf` names, forwarding to the cards' name
//! servers. It sets the clock over NTP (`/etc/slate/ntp`).
//!
//! It talks to the kernel over route netlink: one socket for requests,
//! one that joined the link group for notifications. Each card on DHCP has
//! its own UDP socket bound to the card (SO_BINDTODEVICE), port 68. The
//! first change netd makes tells the kernel to stop its own boot-time
//! configuration (ADR 0048 §2).

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod dhcp;
pub mod dns;
pub mod nl;
pub mod ntp;

/// The settings file (ADR 0048), shared with the installer and Settings.
pub use slate_netconf as config;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_net::{Ipv4, Ipv6};
use slate_rt::{eprintln, fs, io, net, process, time};

use config::{BootOverride, Method, Network, Server, Six};

const CONFIG: &[u8] = b"/etc/slate/network";
const NTP_CONFIG: &[u8] = b"/etc/slate/ntp";
const RESOLV: &[u8] = b"/run/resolv.conf";
const RESOLV_TMP: &[u8] = b"/run/resolv.conf.netd";
const STATUS_DIR: &[u8] = b"/run/netd";
const STATUS: &[u8] = b"/run/netd/status";
const STATUS_TMP: &[u8] = b"/run/netd/status.new";
/// The time zone a DHCP server named (the installers' guess, ADR 0151).
const TIMEZONE: &[u8] = b"/run/netd/timezone";
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_SERVER_PORT: u16 = 67;
/// Default routes: this plus the card's index, so the first card wins.
const METRIC_BASE: u32 = 100;

/// `/run/resolv.conf` (resolv.conf(5)): netd's cache, or (if it could not
/// start) the name servers themselves, those on port 53 (the file has no
/// ports).
pub fn resolv_conf(dns: &[Server], cache: bool, domain: &str) -> String {
    let mut s = String::from("# Written by netd from the network's settings.\n");
    if !domain.is_empty() {
        s.push_str(&format!("search {domain}\n"));
    }
    if cache {
        let a = dns::ADDRESS;
        s.push_str(&format!("nameserver {}.{}.{}.{}\n", a[0], a[1], a[2], a[3]));
        return s;
    }
    let mut seen: Vec<slate_net::IpAddr> = Vec::new();
    for d in dns.iter().filter(|d| d.port == 53) {
        if !seen.contains(&d.addr) {
            seen.push(d.addr);
            s.push_str(&format!("nameserver {}\n", d.addr));
        }
    }
    s
}

/// A tz database name from DHCP option 101, if it looks like one: names
/// are letters, digits and `/_+-` (tz-link.html, "Names of timezones"),
/// with no empty or dot-dot part, so it is safe to read as a path.
pub fn zone_name(raw: &[u8]) -> Option<&str> {
    let name = core::str::from_utf8(raw).ok()?.trim_end_matches('\0');
    let ok = !name.is_empty()
        && name.len() < 64
        && name.bytes().all(|c| c.is_ascii_alphanumeric() || b"/_+-".contains(&c))
        && name.split('/').all(|p| !p.is_empty() && p != "..");
    ok.then_some(name)
}

/// A card's line in `/run/netd/status`: its name, `up` or `down` (a
/// link), how it is configured, and what it got:
/// `eth0 up dhcp 10.0.2.15/24 via 10.0.2.2 dns 10.0.2.3`.
#[allow(clippy::too_many_arguments)]
pub fn status_line(
    name: &str,
    link: bool,
    method: &Method,
    addr: Option<(Ipv4, u8)>,
    gateway: Option<Ipv4>,
    dns: &[Server],
    addrs6: &[(Ipv6, u8)],
) -> String {
    let how = match method {
        Method::Dhcp => "dhcp",
        Method::Static { .. } => "static",
        Method::Off => "off",
    };
    let mut s = format!("{name} {} {how}", if link { "up" } else { "down" });
    if let Some((a, p)) = addr {
        s.push_str(&format!(" {a}/{p}"));
        if let Some(g) = gateway {
            s.push_str(&format!(" via {g}"));
        }
    }
    for (a, p) in addrs6 {
        s.push_str(&format!(" inet6 {a}/{p}"));
    }
    if !dns.is_empty() {
        s.push_str(" dns");
        for d in dns {
            s.push_str(&format!(" {d}"));
        }
    }
    s.push('\n');
    s
}

/// Name servers in a router advertisement's RDNSS option (RFC 8106
/// §5.1: type 25, length, two reserved bytes, a lifetime in seconds, then
/// the addresses): (servers, lifetime). `ra` is the ICMPv6 message.
pub fn rdnss(ra: &[u8]) -> Option<(Vec<Ipv6>, u32)> {
    if ra.len() < 16 || ra[0] != 134 {
        return None;
    }
    let mut at = 16;
    while at + 8 <= ra.len() {
        let len = usize::from(ra[at + 1]) * 8;
        if len == 0 || at + len > ra.len() {
            return None;
        }
        if ra[at] == 25 && len >= 24 {
            let life = u32::from_be_bytes(ra[at + 4..at + 8].try_into().unwrap());
            let servers = ra[at + 8..at + len].as_chunks::<16>().0.iter().map(|c| Ipv6(*c)).collect();
            return Some((servers, life));
        }
        at += len;
    }
    None
}

/// A router solicitation (RFC 4861 §4.1) with the card's link-layer
/// address; the kernel fills in the checksum and sends it with hop limit
/// 255.
pub fn router_solicitation(mac: slate_net::Mac) -> [u8; 16] {
    let mut m = [133, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0];
    m[10..].copy_from_slice(&mac.0);
    m
}

/// The metric of a card's default route.
pub fn metric(index: u32) -> u32 {
    METRIC_BASE + index
}

/// One network card as netd sees it.
struct Card {
    link: nl::Link,
    method: Method,
    /// Configured (or being configured) for its current link.
    running: bool,
    /// The DHCP client and its socket.
    dhcp: Option<(i32, dhcp::Client)>,
    /// What netd put on the card.
    addr: Option<(Ipv4, u8)>,
    gateway: Option<Ipv4>,
    /// Name servers from DHCP.
    dns: Vec<Ipv4>,
    domain: String,
    six: Six,
    /// Name servers from the configuration file.
    dns_conf: Vec<Server>,
    /// The raw ICMPv6 socket router advertisements come in on.
    ra: Option<i32>,
    /// Name servers routers announce (RDNSS).
    dns6: Vec<Ipv6>,
    /// The card's IPv6 addresses (not link-local, checked), for the status.
    addrs6: Vec<(Ipv6, u8)>,
}

struct Daemon {
    /// Requests and their replies.
    ctl: i32,
    /// Link notifications.
    mon: i32,
    seq: u32,
    cards: Vec<Card>,
    net: Network,
    hostname: Vec<u8>,
    seed: u32,
    resolv: String,
    /// The DNS cache, if it could listen.
    cache: Option<dns::Resolver>,
    ntp: ntp::Client,
    /// `slate.ip=` from the kernel's command line, until a card takes it.
    boot: Option<BootOverride>,
}

fn now_ms() -> u64 {
    let (s, ns) = time::now(time::CLOCK_MONOTONIC);
    s as u64 * 1000 + ns as u64 / 1_000_000
}

impl Daemon {
    /// Send a request and wait for its acknowledgement: 0 or an errno.
    fn request(&mut self, make: impl FnOnce(u32) -> Vec<u8>) -> i32 {
        self.seq += 1;
        let seq = self.seq;
        if io::write(self.ctl, &make(seq)).is_err() {
            return -1;
        }
        let mut buf = alloc::vec![0u8; 16384];
        loop {
            let Ok(n) = io::read(self.ctl, &mut buf) else { return -1 };
            for m in nl::parse(&buf[..n]) {
                if let nl::Message::Ack(s, e) = m
                    && s == seq
                {
                    return e;
                }
            }
        }
    }

    /// Send a dump request; the messages until NLMSG_DONE.
    fn dump(&mut self, make: impl FnOnce(u32) -> Vec<u8>) -> Vec<nl::Message> {
        self.seq += 1;
        let seq = self.seq;
        let mut out = Vec::new();
        if io::write(self.ctl, &make(seq)).is_err() {
            return out;
        }
        let mut buf = alloc::vec![0u8; 65536];
        loop {
            let Ok(n) = io::read(self.ctl, &mut buf) else { return out };
            for m in nl::parse(&buf[..n]) {
                match m {
                    nl::Message::Done(s) if s == seq => return out,
                    nl::Message::Ack(s, _) if s == seq => return out,
                    m => out.push(m),
                }
            }
        }
    }

    fn card(&mut self, index: u32) -> Option<&mut Card> {
        self.cards.iter_mut().find(|c| c.link.index == index)
    }

    /// A link appeared or changed.
    fn link(&mut self, link: nl::Link, now: u64) {
        if link.flags & nl::IFF_LOOPBACK != 0 {
            return;
        }
        if self.card(link.index).is_none() {
            let method = self.net.method(&link.name);
            let six = self.net.six(&link.name);
            let dns_conf = self.net.dns(&link.name);
            eprintln!("netd: {} ({:?}): {}", link.name, link.mac, describe(&method));
            let index = link.index;
            self.cards.push(Card {
                link: link.clone(),
                method: method.clone(),
                running: false,
                dhcp: None,
                addr: None,
                gateway: None,
                dns: Vec::new(),
                domain: String::new(),
                six,
                dns_conf,
                ra: None,
                dns6: Vec::new(),
                addrs6: Vec::new(),
            });
            // Bringing the card up (even if it is) is also netd's first
            // change, which ends the kernel's own DHCP client on it (ADR
            // 0048 §2) before netd's starts.
            if method != Method::Off {
                let e = self.request(|s| nl::link_up(s, index));
                if e != 0 {
                    eprintln!("netd: {}: cannot bring it up (error {e})", link.name);
                }
            }
        }
        let c = self.card(link.index).unwrap();
        c.link = link.clone();
        let (running, off) = (c.running, c.method == Method::Off);
        if !off && link.has_link() && !running {
            self.start(link.index, now);
        } else if running && !link.has_link() {
            eprintln!("netd: {}: link down", link.name);
            self.stop(link.index);
        }
    }

    /// Configure a card whose link came up.
    fn start(&mut self, index: u32, now: u64) {
        self.flush(index);
        let Some(c) = self.card(index) else { return };
        c.running = true;
        let (name, mac, six) = (c.link.name.clone(), c.link.mac, c.six.clone());
        // The boot command line's `slate.ip=`, for this boot only (ADR
        // 0076): the card the kernel gave it to (`slate.net=`, else the
        // first with a link) keeps it instead of the file's settings.
        if self.boot.as_ref().is_some_and(|b| b.card.as_deref().is_none_or(|n| n == name)) {
            let b = self.boot.take().unwrap();
            eprintln!("netd: {name}: {} (slate.ip= on the boot command line)", describe(&b.method));
            if let Some(c) = self.card(index) {
                (c.method, c.dns_conf) = (b.method, b.dns);
            }
        }
        // IPv6: routers' advertisements for their name servers (asked for
        // now, in case they came before), a fixed address if set.
        if let Ok(fd) = net::icmp6_on_device(name.as_bytes(), &[134]) {
            let _ = net::send_to6(fd, &router_solicitation(mac), Ipv6::ALL_ROUTERS.0, 0);
            if let Some(c) = self.card(index) {
                c.ra = Some(fd);
            }
        }
        if let Some((a, p)) = six.address {
            let e = self.request(|s| nl::address6(s, true, index, a, p));
            if e != 0 {
                eprintln!("netd: {name}: cannot add {a}/{p} (error {e})");
            }
        }
        if let Some(g) = six.gateway {
            let e = self.request(|s| nl::default_route6(s, index, g, metric(index)));
            if e != 0 {
                eprintln!("netd: {name}: cannot route IPv6 through {g} (error {e})");
            }
        }
        let Some(c) = self.card(index) else { return };
        match c.method.clone() {
            Method::Static { addr, prefix_len, gateway } => {
                self.configure(index, addr, prefix_len, gateway, nl::RTPROT_STATIC);
            }
            Method::Dhcp => {
                let name = c.link.name.clone();
                let mac = c.link.mac;
                match net::udp_on_device(name.as_bytes(), DHCP_CLIENT_PORT) {
                    Ok(fd) => {
                        self.seed = self.seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                        let client = dhcp::Client::new(mac, &self.hostname, self.seed ^ index);
                        let c = self.card(index).unwrap();
                        c.dhcp = Some((fd, client));
                        self.tick(index, now);
                    }
                    Err(e) => eprintln!("netd: {name}: no DHCP socket ({e:?})"),
                }
            }
            Method::Off => {}
        }
        self.publish();
    }

    /// The card's link went down (or it went away): its configuration goes.
    fn stop(&mut self, index: u32) {
        let Some(c) = self.card(index) else { return };
        c.running = false;
        if let Some((fd, _)) = c.dhcp.take() {
            let _ = io::close(fd);
        }
        if let Some(fd) = c.ra.take() {
            let _ = io::close(fd);
        }
        c.dns.clear();
        c.dns6.clear();
        c.domain.clear();
        if let Some((a, p)) = c.six.address {
            self.request(|s| nl::address6(s, false, index, a, p));
        }
        self.deconfigure(index);
        self.publish();
    }

    /// Remove every address on the card (the kernel's boot-time one too).
    fn flush(&mut self, index: u32) {
        let addrs: Vec<(Ipv4, u8)> = self
            .dump(nl::get_addrs)
            .into_iter()
            .filter_map(|m| match m {
                nl::Message::Addr(i, ip, p) if i == index => Some((ip, p)),
                _ => None,
            })
            .collect();
        for (ip, p) in addrs {
            self.request(|s| nl::address(s, false, index, ip, p));
        }
    }

    fn configure(&mut self, index: u32, addr: Ipv4, prefix_len: u8, gateway: Option<Ipv4>, protocol: u8) {
        let e = self.request(|s| nl::address(s, true, index, addr, prefix_len));
        let name = self.card(index).map(|c| c.link.name.clone()).unwrap_or_default();
        if e != 0 {
            eprintln!("netd: {name}: cannot add {addr}/{prefix_len} (error {e})");
            return;
        }
        if let Some(c) = self.card(index) {
            c.addr = Some((addr, prefix_len));
            c.gateway = gateway;
        }
        if let Some(g) = gateway {
            let e = self.request(|s| nl::default_route(s, index, g, metric(index), addr, protocol));
            if e != 0 {
                eprintln!("netd: {name}: cannot route through {g} (error {e})");
            }
        }
        match gateway {
            Some(g) => eprintln!("netd: {name} is {addr}/{prefix_len} via {g}"),
            None => eprintln!("netd: {name} is {addr}/{prefix_len}"),
        }
        // A way out: time to set the clock.
        self.ntp.kick(now_ms());
    }

    fn deconfigure(&mut self, index: u32) {
        let Some(c) = self.card(index) else { return };
        c.gateway = None;
        if let Some((addr, p)) = c.addr.take() {
            // Its routes go with it.
            self.request(|s| nl::address(s, false, index, addr, p));
        }
    }

    /// Run a card's DHCP timers.
    fn tick(&mut self, index: u32, now: u64) {
        let Some((_, client)) = self.card(index).and_then(|c| c.dhcp.as_mut()) else { return };
        let actions = client.tick(now);
        self.act(index, actions);
    }

    fn act(&mut self, index: u32, actions: Vec<dhcp::Action>) {
        for a in actions {
            match a {
                dhcp::Action::Send { to, message } => {
                    if let Some((fd, _)) = self.card(index).and_then(|c| c.dhcp.as_ref()) {
                        let _ = net::send_to(*fd, &message, to.0, DHCP_SERVER_PORT);
                    }
                }
                dhcp::Action::Configure(lease) => {
                    let same = self.card(index).and_then(|c| c.addr) == Some((lease.addr, lease.prefix_len));
                    if let Some(c) = self.card(index) {
                        c.dns = lease.dns.clone();
                        c.domain = String::from_utf8_lossy(&lease.domain).into();
                    }
                    if let Some(zone) = zone_name(&lease.timezone) {
                        let _ = fs::mkdir(STATUS_DIR, 0o755);
                        let _ = fs::write_file(TIMEZONE, format!("{zone}\n").as_bytes(), 0o644);
                    }
                    if !same {
                        self.configure(index, lease.addr, lease.prefix_len, lease.router, nl::RTPROT_DHCP);
                    }
                    self.publish();
                }
                dhcp::Action::Deconfigure => {
                    if let Some(c) = self.card(index) {
                        c.dns.clear();
                        c.domain.clear();
                    }
                    self.deconfigure(index);
                    self.publish();
                }
            }
        }
    }

    /// Write `/run/resolv.conf` and `/run/netd/status`.
    fn publish(&mut self) {
        self.refresh6();
        self.write_resolv();
        let mut cards: Vec<&Card> = self.cards.iter().collect();
        cards.sort_by_key(|c| c.link.index);
        let text: String = cards
            .iter()
            .map(|c| status_line(&c.link.name, c.link.has_link(), &c.method, c.addr, c.gateway, &servers(c), &c.addrs6))
            .collect();
        let text = format!("{text}{}\n", self.ntp.status);
        let _ = fs::mkdir(STATUS_DIR, 0o755);
        if fs::write_file(STATUS_TMP, text.as_bytes(), 0o644).and_then(|_| fs::rename(STATUS_TMP, STATUS)).is_err() {
            eprintln!("netd: cannot write /run/netd/status");
        }
    }

    /// The cards' IPv6 addresses (for the status), from a dump.
    fn refresh6(&mut self) {
        let all = self.dump(nl::get_addrs6);
        for c in self.cards.iter_mut() {
            c.addrs6 = all
                .iter()
                .filter_map(|m| match m {
                    nl::Message::Addr6(i, a, p, f)
                        if *i == c.link.index && !a.is_link_local() && f & nl::IFA_F_TENTATIVE == 0 =>
                    {
                        Some((*a, *p))
                    }
                    _ => None,
                })
                .collect();
        }
    }

    /// Name servers of every configured card, in card order.
    fn upstreams(&self) -> Vec<Server> {
        let mut cards: Vec<&Card> = self.cards.iter().filter(|c| c.running).collect();
        cards.sort_by_key(|c| c.link.index);
        let mut out: Vec<Server> = Vec::new();
        for s in cards.iter().flat_map(|c| servers(c)) {
            if !out.contains(&s) {
                out.push(s);
            }
        }
        out
    }

    fn write_resolv(&mut self) {
        let mut cards: Vec<&Card> = self.cards.iter().filter(|c| c.running).collect();
        cards.sort_by_key(|c| c.link.index);
        let domain = String::from(cards.iter().map(|c| c.domain.as_str()).find(|d| !d.is_empty()).unwrap_or(""));
        let text = resolv_conf(&self.upstreams(), self.cache.is_some(), &domain);
        let boot_link = fs::lstat(RESOLV).is_ok_and(|s| s.is_symlink());
        // Nothing configured yet: the kernel's boot-time settings stay.
        if cards.is_empty() && boot_link {
            return;
        }
        if text == self.resolv && !boot_link {
            return;
        }
        // A new file renamed over the old one (or over the boot-time link
        // to the kernel's /proc/net/pnp), so readers never see half.
        if fs::write_file(RESOLV_TMP, text.as_bytes(), 0o644).and_then(|_| fs::rename(RESOLV_TMP, RESOLV)).is_ok() {
            self.resolv = text;
        } else {
            eprintln!("netd: cannot write /run/resolv.conf");
        }
    }

    fn run(&mut self) -> ! {
        let mut buf = alloc::vec![0u8; 65536];
        loop {
            let now = now_ms();
            let indices: Vec<u32> = self.cards.iter().filter(|c| c.dhcp.is_some()).map(|c| c.link.index).collect();
            for i in &indices {
                self.tick(*i, now);
            }
            let next = self.cards.iter().filter_map(|c| c.dhcp.as_ref().map(|(_, d)| d.next())).min();
            let next = [next, self.cache.as_ref().and_then(|c| c.next()), self.ntp.next()].into_iter().flatten().min();
            let timeout = next.map_or(-1, |t| t.saturating_sub(now_ms()).min(60_000) as i32);
            let mut fds = alloc::vec![io::PollFd { fd: self.mon, events: io::POLLIN, revents: 0 }];
            let socks: Vec<(u32, i32)> =
                self.cards.iter().filter_map(|c| c.dhcp.as_ref().map(|(fd, _)| (c.link.index, *fd))).collect();
            fds.extend(socks.iter().map(|&(_, fd)| io::PollFd { fd, events: io::POLLIN, revents: 0 }));
            let ras: Vec<(u32, i32)> = self.cards.iter().filter_map(|c| c.ra.map(|fd| (c.link.index, fd))).collect();
            fds.extend(ras.iter().map(|&(_, fd)| io::PollFd { fd, events: io::POLLIN, revents: 0 }));
            let cache_fds = self.cache.as_ref().map(|c| c.fds()).unwrap_or_default();
            fds.extend(cache_fds.iter().map(|&fd| io::PollFd { fd, events: io::POLLIN, revents: 0 }));
            let ntp_fd = self.ntp.fd();
            fds.extend(ntp_fd.map(|fd| io::PollFd { fd, events: io::POLLIN, revents: 0 }));
            if io::poll(&mut fds, timeout).is_err() {
                continue;
            }
            let now = now_ms();
            if fds[0].revents != 0 {
                // Notifications: as many as are waiting.
                while let Ok(n) = io::read(self.mon, &mut buf) {
                    for m in nl::parse(&buf[..n]) {
                        match m {
                            nl::Message::Link(l) => {
                                self.link(l, now);
                                self.publish();
                            }
                            nl::Message::LinkGone(i) => {
                                self.stop(i);
                                self.cards.retain(|c| c.link.index != i);
                                self.publish();
                            }
                            nl::Message::Addr6(..) | nl::Message::DelAddr6(..) => self.publish(),
                            _ => {}
                        }
                    }
                }
            }
            for (k, &(index, fd)) in socks.iter().enumerate() {
                if fds[k + 1].revents == 0 {
                    continue;
                }
                if let Ok((n, _, port)) = net::recv_from(fd, &mut buf)
                    && port == DHCP_SERVER_PORT
                    && let Some((_, client)) = self.card(index).and_then(|c| c.dhcp.as_mut())
                {
                    let actions = client.receive(&buf[..n], now);
                    self.act(index, actions);
                }
            }
            let base = 1 + socks.len();
            for (k, &(index, fd)) in ras.iter().enumerate() {
                if fds[base + k].revents == 0 {
                    continue;
                }
                if let Ok(n) = net::recv(fd, &mut buf)
                    && let Some((servers, life)) = rdnss(&buf[..n])
                    && let Some(c) = self.card(index)
                {
                    let servers = if life == 0 { Vec::new() } else { servers };
                    if c.dns6 != servers {
                        c.dns6 = servers;
                        self.publish();
                    }
                }
            }
            let base = base + ras.len();
            let upstreams = self.upstreams();
            if let Some(cache) = self.cache.as_mut() {
                for (k, &fd) in cache_fds.iter().enumerate() {
                    if fds[base + k].revents != 0 {
                        cache.ready(fd, &upstreams, now);
                    }
                }
                cache.tick(&upstreams, now_ms());
            }
            let before = self.ntp.status.clone();
            if ntp_fd.is_some() && fds[base + cache_fds.len()].revents != 0 {
                self.ntp.ready(&upstreams, now);
            }
            self.ntp.tick(&upstreams, now_ms());
            if self.ntp.status != before {
                self.publish();
            }
        }
    }
}

/// A card's name servers: the configuration file's, then DHCP's, then
/// routers' (RDNSS).
fn servers(c: &Card) -> Vec<Server> {
    let mut v = c.dns_conf.clone();
    v.extend(c.dns.iter().map(|d| Server::new(*d)));
    v.extend(c.dns6.iter().map(|d| Server::new(*d)));
    v
}

fn describe(m: &Method) -> String {
    match m {
        Method::Dhcp => "DHCP".into(),
        Method::Off => "left alone".into(),
        Method::Static { addr, prefix_len, gateway, .. } => match gateway {
            Some(g) => format!("{addr}/{prefix_len} via {g}"),
            None => format!("{addr}/{prefix_len}"),
        },
    }
}

pub fn main() -> i32 {
    if process::geteuid() != 0 {
        eprintln!("netd: must run as root");
        return 1;
    }
    let text = fs::read_file(CONFIG).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    let (net, problems) = Network::parse(&text);
    for p in problems {
        eprintln!("netd: /etc/slate/network line {}: {}", p.line, p.what);
    }
    let hostname = fs::read_file(b"/etc/hostname")
        .ok()
        .map(|h| String::from_utf8_lossy(&h).trim().as_bytes().to_vec())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| b"slate".to_vec());
    // Listen before looking, so that no link change falls in between.
    let (Ok(mon), Ok(ctl)) = (net::route_socket(nl::RTMGRP_LINK | nl::RTMGRP_IPV6_IFADDR), net::route_socket(0)) else {
        eprintln!("netd: no netlink");
        return 1;
    };
    let _ = process::fcntl(mon, 4, slate_rt::fs::O_NONBLOCK as usize); // F_SETFL (fcntl(2))
    let (s, ns) = time::now(time::CLOCK_REALTIME);
    let mut d = Daemon {
        ctl,
        mon,
        seq: 0,
        cards: Vec::new(),
        net,
        hostname,
        seed: (s as u32) ^ (ns as u32) ^ (process::getpid() as u32).rotate_left(16),
        resolv: String::new(),
        cache: dns::Resolver::start(ns as u16 ^ process::getpid() as u16),
        ntp: {
            let text = fs::read_file(NTP_CONFIG).ok().map(|b| String::from_utf8_lossy(&b).into_owned());
            let (servers, bad) = ntp::parse(text.as_deref());
            for line in bad {
                eprintln!("netd: /etc/slate/ntp line {line}: expected `server NAME[:PORT]`");
            }
            ntp::Client::new(servers, (ns as u16).rotate_left(5) ^ process::getpid() as u16)
        },
        boot: fs::read_file(b"/proc/cmdline").ok().and_then(|c| config::boot_override(&String::from_utf8_lossy(&c))),
    };
    if d.cache.is_none() {
        eprintln!("netd: 127.0.0.53:53 is taken: no DNS cache");
    }
    let now = now_ms();
    for m in d.dump(nl::get_links) {
        if let nl::Message::Link(l) = m {
            d.link(l, now);
        }
    }
    d.write_resolv();
    d.run()
}

#[cfg(test)]
mod tests;
