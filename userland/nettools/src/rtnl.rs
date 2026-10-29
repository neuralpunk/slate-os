// SPDX-License-Identifier: MIT OR Apache-2.0

//! Route netlink for `ip` (netlink(7), rtnetlink(7)): requests that dump
//! or change links, addresses, routes and neighbours, and the records
//! that come back.

use alloc::string::String;
use alloc::vec::Vec;

use slate_net::{IpAddr, Ipv4, Ipv6, Mac};
use slate_rt::{io, net};

// Message types and flags (netlink(7), rtnetlink(7)).
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_DELNEIGH: u16 = 29;
pub const RTM_GETNEIGH: u16 = 30;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
const NLM_F_DUMP: u16 = 0x300;

pub const AF_UNSPEC: u8 = 0;
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

// Link flags (netdevice(7)).
pub const IFF_UP: u32 = 0x1;
pub const IFF_BROADCAST: u32 = 0x2;
pub const IFF_LOOPBACK: u32 = 0x8;
pub const IFF_POINTOPOINT: u32 = 0x10;
pub const IFF_RUNNING: u32 = 0x40;
pub const IFF_NOARP: u32 = 0x80;
pub const IFF_PROMISC: u32 = 0x100;
pub const IFF_MULTICAST: u32 = 0x1000;
pub const IFF_LOWER_UP: u32 = 0x10000;

// Attributes (rtnetlink(7)).
const IFLA_ADDRESS: u16 = 1;
const IFLA_BROADCAST: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_TXQLEN: u16 = 13;
const IFLA_OPERSTATE: u16 = 16;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_BROADCAST: u16 = 4;
const IFA_CACHEINFO: u16 = 6;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RTA_TABLE: u16 = 15;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;

pub const IFA_F_DEPRECATED: u8 = 0x20;
pub const IFA_F_TENTATIVE: u8 = 0x40;
pub const IFA_F_PERMANENT: u8 = 0x80;

pub const RT_TABLE_MAIN: u8 = 254;
pub const RT_TABLE_LOCAL: u8 = 255;
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_LINK: u8 = 253;
pub const RT_SCOPE_HOST: u8 = 254;
pub const RTN_UNICAST: u8 = 1;
pub const RTPROT_BOOT: u8 = 3;
pub const RTPROT_STATIC: u8 = 4;

// Neighbour states (rtnetlink(7), "RTM_NEWNEIGH").
pub const NUD_INCOMPLETE: u16 = 0x01;
pub const NUD_REACHABLE: u16 = 0x02;
pub const NUD_STALE: u16 = 0x04;
pub const NUD_DELAY: u16 = 0x08;
pub const NUD_PROBE: u16 = 0x10;
pub const NUD_FAILED: u16 = 0x20;
pub const NUD_NOARP: u16 = 0x40;
pub const NUD_PERMANENT: u16 = 0x80;

/// A request being built: the header, the fixed part, attributes.
#[derive(Debug)]
pub struct Msg(Vec<u8>);

impl Msg {
    pub fn new(ty: u16, flags: u16, seq: u32) -> Msg {
        let mut b = Vec::with_capacity(64);
        b.extend_from_slice(&0u32.to_ne_bytes());
        b.extend_from_slice(&ty.to_ne_bytes());
        b.extend_from_slice(&(flags | NLM_F_REQUEST).to_ne_bytes());
        b.extend_from_slice(&seq.to_ne_bytes());
        b.extend_from_slice(&0u32.to_ne_bytes());
        Msg(b)
    }
    pub fn bytes(mut self, b: &[u8]) -> Msg {
        self.0.extend_from_slice(b);
        self
    }
    pub fn attr(mut self, ty: u16, data: &[u8]) -> Msg {
        self.0.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        self.0.extend_from_slice(&ty.to_ne_bytes());
        self.0.extend_from_slice(data);
        while self.0.len() % 4 != 0 {
            self.0.push(0);
        }
        self
    }
    pub fn done(mut self) -> Vec<u8> {
        let len = self.0.len() as u32;
        self.0[..4].copy_from_slice(&len.to_ne_bytes());
        self.0
    }
}

fn ip_bytes(a: &IpAddr) -> &[u8] {
    match a {
        IpAddr::V4(a) => &a.0,
        IpAddr::V6(a) => &a.0,
    }
}

fn family_of(a: &IpAddr) -> u8 {
    if matches!(a, IpAddr::V6(_)) { AF_INET6 } else { AF_INET }
}

/// A dump request: `ty` (RTM_GET*) for `family` (AF_UNSPEC for both).
pub fn dump(ty: u16, family: u8, seq: u32) -> Vec<u8> {
    let fixed: &[u8] = match ty {
        RTM_GETLINK => &[0; 16],
        RTM_GETROUTE => &[0; 12],
        RTM_GETNEIGH => &[0; 12],
        _ => &[0; 8],
    };
    let mut fixed = fixed.to_vec();
    fixed[0] = family;
    Msg::new(ty, NLM_F_DUMP, seq).bytes(&fixed).done()
}

/// Change link `index`: `up` (Some to set IFF_UP or clear it), `mtu`.
pub fn set_link(seq: u32, index: u32, up: Option<bool>, mtu: Option<u32>) -> Vec<u8> {
    // struct ifinfomsg: family, pad, type, index, flags, change.
    let (flags, change) = match up {
        Some(true) => (IFF_UP, IFF_UP),
        Some(false) => (0, IFF_UP),
        None => (0, 0),
    };
    let mut m = Msg::new(RTM_NEWLINK, NLM_F_ACK, seq)
        .bytes(&[0, 0, 0, 0])
        .bytes(&index.to_ne_bytes())
        .bytes(&flags.to_ne_bytes())
        .bytes(&change.to_ne_bytes());
    if let Some(mtu) = mtu {
        m = m.attr(IFLA_MTU, &mtu.to_ne_bytes());
    }
    m.done()
}

/// Add (`flags`: NLM_F_CREATE and EXCL or REPLACE) or remove (`del`) an
/// address.
pub fn address(seq: u32, del: bool, flags: u16, index: u32, addr: IpAddr, prefix_len: u8) -> Vec<u8> {
    let ty = if del { RTM_DELADDR } else { RTM_NEWADDR };
    let scope = match addr {
        IpAddr::V4(a) if a.0[0] == 127 => RT_SCOPE_HOST,
        IpAddr::V6(a) if a.is_loopback() => RT_SCOPE_HOST,
        IpAddr::V6(a) if a.is_link_local() => RT_SCOPE_LINK,
        _ => RT_SCOPE_UNIVERSE,
    };
    // struct ifaddrmsg: family, prefixlen, flags, scope, index.
    Msg::new(ty, flags | NLM_F_ACK, seq)
        .bytes(&[family_of(&addr), prefix_len, 0, scope])
        .bytes(&index.to_ne_bytes())
        .attr(IFA_LOCAL, ip_bytes(&addr))
        .attr(IFA_ADDRESS, ip_bytes(&addr))
        .done()
}

/// A route to add or remove.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Route {
    pub family: u8,
    pub dst: Option<IpAddr>,
    pub dst_len: u8,
    pub gateway: Option<IpAddr>,
    pub oif: Option<u32>,
    pub metric: Option<u32>,
    pub prefsrc: Option<IpAddr>,
    pub protocol: u8,
    pub scope: u8,
    pub table: u8,
    pub kind: u8,
}

/// RTM_NEWROUTE (with `flags`) or RTM_DELROUTE for `r`.
pub fn route(seq: u32, del: bool, flags: u16, r: &Route) -> Vec<u8> {
    let ty = if del { RTM_DELROUTE } else { RTM_NEWROUTE };
    // struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope,
    // type, flags.
    let mut m = Msg::new(ty, flags | NLM_F_ACK, seq)
        .bytes(&[r.family, r.dst_len, 0, 0, RT_TABLE_MAIN, r.protocol, r.scope, RTN_UNICAST])
        .bytes(&0u32.to_ne_bytes());
    if let Some(d) = &r.dst {
        m = m.attr(RTA_DST, ip_bytes(d));
    }
    if let Some(g) = &r.gateway {
        m = m.attr(RTA_GATEWAY, ip_bytes(g));
    }
    if let Some(i) = r.oif {
        m = m.attr(RTA_OIF, &i.to_ne_bytes());
    }
    if let Some(p) = r.metric {
        m = m.attr(RTA_PRIORITY, &p.to_ne_bytes());
    }
    if let Some(s) = &r.prefsrc {
        m = m.attr(RTA_PREFSRC, ip_bytes(s));
    }
    m.done()
}

/// Set (`flags`: NLM_F_CREATE with REPLACE or EXCL) or remove (`del`) a
/// neighbour entry.
pub fn neighbour(seq: u32, del: bool, flags: u16, index: u32, ip: IpAddr, mac: Option<Mac>) -> Vec<u8> {
    let ty = if del { RTM_DELNEIGH } else { RTM_NEWNEIGH };
    // struct ndmsg: family, pads, ifindex, state, flags, type.
    let mut m = Msg::new(ty, flags | NLM_F_ACK, seq)
        .bytes(&[family_of(&ip), 0, 0, 0])
        .bytes(&index.to_ne_bytes())
        .bytes(&NUD_PERMANENT.to_ne_bytes())
        .bytes(&[0, 0])
        .attr(NDA_DST, ip_bytes(&ip));
    if let Some(mac) = mac {
        m = m.attr(NDA_LLADDR, &mac.0);
    }
    m.done()
}

/// A link (RTM_NEWLINK).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Link {
    pub index: u32,
    pub hw_type: u16,
    pub flags: u32,
    pub name: String,
    pub mac: Option<Mac>,
    pub broadcast: Option<Mac>,
    pub mtu: u32,
    pub txqlen: u32,
    pub operstate: u8,
}

/// An address (RTM_NEWADDR), with its lifetimes left in seconds (None:
/// for ever).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Addr {
    pub index: u32,
    pub prefix_len: u8,
    pub flags: u8,
    pub scope: u8,
    pub addr: IpAddr,
    pub broadcast: Option<Ipv4>,
    pub label: String,
    pub preferred: Option<u32>,
    pub valid: Option<u32>,
}

/// A neighbour (RTM_NEWNEIGH).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neigh {
    pub index: u32,
    pub state: u16,
    pub dst: IpAddr,
    pub lladdr: Option<Mac>,
}

/// A message read back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Link(Link),
    Addr(Addr),
    Route(Route),
    Neigh(Neigh),
    /// NLMSG_ERROR: the error (0: an acknowledgement).
    Ack(i32),
    Done,
    Other,
}

fn attrs(b: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= b.len() {
        let len = usize::from(u16::from_ne_bytes([b[at], b[at + 1]]));
        let ty = u16::from_ne_bytes([b[at + 2], b[at + 3]]) & 0x3FFF;
        if len < 4 || at + len > b.len() {
            break;
        }
        out.push((ty, &b[at + 4..at + len]));
        at += len.next_multiple_of(4);
    }
    out
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4).map_or(0, |v| u32::from_ne_bytes(v.try_into().unwrap()))
}

fn ip(family: u8, v: &[u8]) -> Option<IpAddr> {
    match (family, v.len()) {
        (AF_INET, 4) => Some(IpAddr::V4(Ipv4(v.try_into().unwrap()))),
        (AF_INET6, 16) => Some(IpAddr::V6(Ipv6(v.try_into().unwrap()))),
        _ => None,
    }
}

fn mac(v: &[u8]) -> Option<Mac> {
    v.try_into().ok().map(Mac)
}

fn text(v: &[u8]) -> String {
    let end = v.iter().position(|&b| b == 0).unwrap_or(v.len());
    String::from_utf8_lossy(&v[..end]).into()
}

fn link(body: &[u8]) -> Message {
    let mut l = Link {
        hw_type: u16::from_ne_bytes([body[2], body[3]]),
        index: u32_at(body, 4),
        flags: u32_at(body, 8),
        ..Default::default()
    };
    for (t, v) in attrs(&body[16..]) {
        match t {
            IFLA_IFNAME => l.name = text(v),
            IFLA_ADDRESS => l.mac = mac(v),
            IFLA_BROADCAST => l.broadcast = mac(v),
            IFLA_MTU => l.mtu = u32_at(v, 0),
            IFLA_TXQLEN => l.txqlen = u32_at(v, 0),
            IFLA_OPERSTATE => l.operstate = v.first().copied().unwrap_or(0),
            _ => {}
        }
    }
    Message::Link(l)
}

fn addr(body: &[u8]) -> Message {
    let family = body[0];
    let list = attrs(&body[8..]);
    let find = |ty| list.iter().find(|(t, _)| *t == ty).and_then(|(_, v)| ip(family, v));
    let Some(a) = find(IFA_LOCAL).or_else(|| find(IFA_ADDRESS)) else { return Message::Other };
    let mut out = Addr {
        index: u32_at(body, 4),
        prefix_len: body[1],
        flags: body[2],
        scope: body[3],
        addr: a,
        broadcast: match find(IFA_BROADCAST) {
            Some(IpAddr::V4(b)) => Some(b),
            _ => None,
        },
        label: String::new(),
        preferred: None,
        valid: None,
    };
    for (t, v) in &list {
        match *t {
            IFA_LABEL => out.label = text(v),
            IFA_CACHEINFO if v.len() >= 8 => {
                let forever = |s: u32| (s != u32::MAX).then_some(s);
                out.preferred = forever(u32_at(v, 0));
                out.valid = forever(u32_at(v, 4));
            }
            _ => {}
        }
    }
    Message::Addr(out)
}

fn route_rec(body: &[u8]) -> Message {
    let family = body[0];
    let mut r = Route {
        family,
        dst_len: body[1],
        table: body[4],
        protocol: body[5],
        scope: body[6],
        kind: body[7],
        ..Default::default()
    };
    for (t, v) in attrs(&body[12..]) {
        match t {
            RTA_DST => r.dst = ip(family, v),
            RTA_GATEWAY => r.gateway = ip(family, v),
            RTA_OIF => r.oif = Some(u32_at(v, 0)),
            RTA_PRIORITY => r.metric = Some(u32_at(v, 0)),
            RTA_PREFSRC => r.prefsrc = ip(family, v),
            RTA_TABLE => r.table = u32_at(v, 0) as u8,
            _ => {}
        }
    }
    Message::Route(r)
}

fn neigh(body: &[u8]) -> Message {
    let family = body[0];
    let list = attrs(&body[12..]);
    let Some(dst) = list.iter().find(|(t, _)| *t == NDA_DST).and_then(|(_, v)| ip(family, v)) else {
        return Message::Other;
    };
    Message::Neigh(Neigh {
        index: u32_at(body, 4),
        state: u16::from_ne_bytes([body[8], body[9]]),
        dst,
        lladdr: list.iter().find(|(t, _)| *t == NDA_LLADDR).and_then(|(_, v)| mac(v)),
    })
}

/// The messages in one datagram.
pub fn parse(data: &[u8]) -> Vec<Message> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 16 <= data.len() {
        let len = u32_at(data, at) as usize;
        if len < 16 || at + len > data.len() {
            break;
        }
        let ty = u16::from_ne_bytes([data[at + 4], data[at + 5]]);
        let body = &data[at + 16..at + len];
        out.push(match ty {
            NLMSG_ERROR => Message::Ack(-(u32_at(body, 0) as i32)),
            NLMSG_DONE => Message::Done,
            RTM_NEWLINK if body.len() >= 16 => link(body),
            RTM_NEWADDR if body.len() >= 8 => addr(body),
            RTM_NEWROUTE if body.len() >= 12 => route_rec(body),
            RTM_NEWNEIGH if body.len() >= 12 => neigh(body),
            _ => Message::Other,
        });
        at += len.next_multiple_of(4);
    }
    out
}

/// A route netlink connection.
#[derive(Debug)]
pub struct Conn {
    fd: i32,
    seq: u32,
}

impl Drop for Conn {
    fn drop(&mut self) {
        let _ = io::close(self.fd);
    }
}

impl Conn {
    pub fn open() -> slate_rt::Result<Conn> {
        Ok(Conn { fd: net::route_socket(0)?, seq: 1 })
    }

    pub fn next_seq(&mut self) -> u32 {
        self.seq += 1;
        self.seq
    }

    fn read(&self, buf: &mut [u8]) -> slate_rt::Result<usize> {
        let mut p = [io::PollFd { fd: self.fd, events: io::POLLIN, revents: 0 }];
        if io::poll(&mut p, 5000)? == 0 {
            return Err(slate_rt::Errno::ETIMEDOUT);
        }
        net::recv(self.fd, buf)
    }

    /// Everything a dump request returns, up to NLMSG_DONE.
    pub fn dump(&mut self, ty: u16, family: u8) -> slate_rt::Result<Vec<Message>> {
        let seq = self.next_seq();
        io::write_all(self.fd, &dump(ty, family, seq))?;
        let mut out = Vec::new();
        let mut buf = alloc::vec![0u8; 64 * 1024];
        loop {
            let n = self.read(&mut buf)?;
            for m in parse(&buf[..n]) {
                match m {
                    Message::Done => return Ok(out),
                    Message::Ack(e) if e != 0 => return Err(slate_rt::Errno(e)),
                    m => out.push(m),
                }
            }
        }
    }

    /// Send a change and wait for its acknowledgement.
    pub fn change(&mut self, req: &[u8]) -> slate_rt::Result<()> {
        io::write_all(self.fd, req)?;
        let mut buf = alloc::vec![0u8; 8192];
        loop {
            let n = self.read(&mut buf)?;
            for m in parse(&buf[..n]) {
                if let Message::Ack(e) = m {
                    return if e == 0 { Ok(()) } else { Err(slate_rt::Errno(e)) };
                }
            }
        }
    }
}
