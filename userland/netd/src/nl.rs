// SPDX-License-Identifier: MIT OR Apache-2.0

//! The route netlink messages netd sends and reads (netlink(7),
//! rtnetlink(7)): requests to dump links and addresses, to add and remove
//! addresses and routes and to bring a link up, and the link, address and
//! error messages that come back.

use alloc::string::String;
use alloc::vec::Vec;

use slate_net::{Ipv4, Ipv6, Mac};

// Message types and flags (netlink(7), rtnetlink(7)).
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_DUMP: u16 = 0x300;
/// The link and IPv6 address multicast groups' masks (rtnetlink(7)
/// RTMGRP_LINK, RTMGRP_IPV6_IFADDR).
pub const RTMGRP_LINK: u32 = 0x1;
pub const RTMGRP_IPV6_IFADDR: u32 = 0x100;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
/// The address is still being checked for duplicates (IFA_F_TENTATIVE).
pub const IFA_F_TENTATIVE: u8 = 0x40;
const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RT_TABLE_MAIN: u8 = 254;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;
/// Who made a route (rtnetlink(7) `rtm_protocol`).
pub const RTPROT_STATIC: u8 = 4;
pub const RTPROT_DHCP: u8 = 16;

// Interface flags (netdevice(7)).
pub const IFF_UP: u32 = 0x1;
pub const IFF_LOOPBACK: u32 = 0x8;
pub const IFF_RUNNING: u32 = 0x40;
pub const IFF_LOWER_UP: u32 = 0x10000;

struct Msg(Vec<u8>);

impl Msg {
    fn new(ty: u16, flags: u16, seq: u32) -> Msg {
        let mut b = Vec::with_capacity(64);
        b.extend_from_slice(&0u32.to_ne_bytes());
        b.extend_from_slice(&ty.to_ne_bytes());
        b.extend_from_slice(&(flags | NLM_F_REQUEST).to_ne_bytes());
        b.extend_from_slice(&seq.to_ne_bytes());
        b.extend_from_slice(&0u32.to_ne_bytes());
        Msg(b)
    }
    fn bytes(mut self, b: &[u8]) -> Msg {
        self.0.extend_from_slice(b);
        self
    }
    fn attr(mut self, ty: u16, data: &[u8]) -> Msg {
        self.0.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        self.0.extend_from_slice(&ty.to_ne_bytes());
        self.0.extend_from_slice(data);
        while self.0.len() % 4 != 0 {
            self.0.push(0);
        }
        self
    }
    fn done(mut self) -> Vec<u8> {
        let len = self.0.len() as u32;
        self.0[..4].copy_from_slice(&len.to_ne_bytes());
        self.0
    }
}

/// Dump every link.
pub fn get_links(seq: u32) -> Vec<u8> {
    Msg::new(RTM_GETLINK, NLM_F_DUMP, seq).bytes(&[0; 16]).done()
}

/// Dump every IPv4 address.
pub fn get_addrs(seq: u32) -> Vec<u8> {
    Msg::new(RTM_GETADDR, NLM_F_DUMP, seq).bytes(&[AF_INET, 0, 0, 0]).bytes(&[0; 4]).done()
}

/// Bring link `index` up.
pub fn link_up(seq: u32, index: u32) -> Vec<u8> {
    // struct ifinfomsg: family, pad, type, index, flags, change.
    Msg::new(RTM_NEWLINK, NLM_F_ACK, seq)
        .bytes(&[0, 0, 0, 0])
        .bytes(&index.to_ne_bytes())
        .bytes(&IFF_UP.to_ne_bytes())
        .bytes(&IFF_UP.to_ne_bytes())
        .done()
}

/// Add (or, with `add` false, remove) an address on link `index`.
pub fn address(seq: u32, add: bool, index: u32, addr: Ipv4, prefix_len: u8) -> Vec<u8> {
    let (ty, flags) =
        if add { (RTM_NEWADDR, NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE) } else { (RTM_DELADDR, NLM_F_ACK) };
    // struct ifaddrmsg: family, prefixlen, flags, scope, index.
    Msg::new(ty, flags, seq)
        .bytes(&[AF_INET, prefix_len, 0, RT_SCOPE_UNIVERSE])
        .bytes(&index.to_ne_bytes())
        .attr(IFA_LOCAL, &addr.0)
        .attr(IFA_ADDRESS, &addr.0)
        .done()
}

/// Dump every IPv6 address.
pub fn get_addrs6(seq: u32) -> Vec<u8> {
    Msg::new(RTM_GETADDR, NLM_F_DUMP, seq).bytes(&[AF_INET6, 0, 0, 0]).bytes(&[0; 4]).done()
}

/// Add (or, with `add` false, remove) an IPv6 address on link `index`.
pub fn address6(seq: u32, add: bool, index: u32, addr: Ipv6, prefix_len: u8) -> Vec<u8> {
    let (ty, flags) = if add { (RTM_NEWADDR, NLM_F_ACK | NLM_F_CREATE) } else { (RTM_DELADDR, NLM_F_ACK) };
    Msg::new(ty, flags, seq)
        .bytes(&[AF_INET6, prefix_len, 0, RT_SCOPE_UNIVERSE])
        .bytes(&index.to_ne_bytes())
        .attr(IFA_LOCAL, &addr.0)
        .attr(IFA_ADDRESS, &addr.0)
        .done()
}

/// Add (or replace) the IPv6 default route through `gateway` on `index`.
pub fn default_route6(seq: u32, index: u32, gateway: Ipv6, metric: u32) -> Vec<u8> {
    Msg::new(RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, seq)
        .bytes(&[AF_INET6, 0, 0, 0, RT_TABLE_MAIN, RTPROT_STATIC, RT_SCOPE_UNIVERSE, RTN_UNICAST])
        .bytes(&0u32.to_ne_bytes())
        .attr(RTA_GATEWAY, &gateway.0)
        .attr(RTA_OIF, &index.to_ne_bytes())
        .attr(RTA_PRIORITY, &metric.to_ne_bytes())
        .done()
}

/// Add (or replace) the default route through `gateway` on link `index`.
pub fn default_route(seq: u32, index: u32, gateway: Ipv4, metric: u32, src: Ipv4, protocol: u8) -> Vec<u8> {
    // struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope,
    // type, flags.
    Msg::new(RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, seq)
        .bytes(&[AF_INET, 0, 0, 0, RT_TABLE_MAIN, protocol, RT_SCOPE_UNIVERSE, RTN_UNICAST])
        .bytes(&0u32.to_ne_bytes())
        .attr(RTA_DST, &Ipv4::UNSPECIFIED.0)
        .attr(RTA_GATEWAY, &gateway.0)
        .attr(RTA_OIF, &index.to_ne_bytes())
        .attr(RTA_PRIORITY, &metric.to_ne_bytes())
        .attr(RTA_PREFSRC, &src.0)
        .done()
}

/// A link as RTM_NEWLINK describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub index: u32,
    pub flags: u32,
    pub name: String,
    pub mac: Mac,
}

impl Link {
    /// Up with a carrier.
    pub fn has_link(&self) -> bool {
        self.flags & IFF_UP != 0 && self.flags & (IFF_RUNNING | IFF_LOWER_UP) != 0
    }
}

/// A message read back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Link(Link),
    LinkGone(u32),
    /// An IPv4 address: (link, address, prefix length).
    Addr(u32, Ipv4, u8),
    /// An IPv6 address: (link, address, prefix length, IFA_F_* flags).
    Addr6(u32, Ipv6, u8, u8),
    /// One went away (RTM_DELADDR).
    DelAddr6(u32, Ipv6),
    /// NLMSG_ERROR: the request's sequence number and the error (0: an
    /// acknowledgement).
    Ack(u32, i32),
    Done(u32),
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
        let seq = u32_at(data, at + 8);
        let body = &data[at + 16..at + len];
        out.push(match ty {
            NLMSG_ERROR => Message::Ack(u32_at(body, 12), -(u32_at(body, 0) as i32)),
            NLMSG_DONE => Message::Done(seq),
            RTM_NEWLINK if body.len() >= 16 => {
                let mut link =
                    Link { index: u32_at(body, 4), flags: u32_at(body, 8), name: String::new(), mac: Mac::default() };
                for (t, v) in attrs(&body[16..]) {
                    match t {
                        IFLA_IFNAME => {
                            let end = v.iter().position(|&b| b == 0).unwrap_or(v.len());
                            link.name = String::from_utf8_lossy(&v[..end]).into();
                        }
                        IFLA_ADDRESS if v.len() == 6 => link.mac = Mac(v.try_into().unwrap()),
                        _ => {}
                    }
                }
                Message::Link(link)
            }
            RTM_DELLINK if body.len() >= 8 => Message::LinkGone(u32_at(body, 4)),
            RTM_NEWADDR | RTM_DELADDR if body.len() >= 8 && body[0] == AF_INET6 => {
                let ip = attrs(&body[8..])
                    .into_iter()
                    .find(|(t, v)| *t == IFA_ADDRESS && v.len() == 16)
                    .map(|(_, v)| Ipv6(v.try_into().unwrap()));
                match (ip, ty) {
                    (Some(ip), RTM_NEWADDR) => Message::Addr6(u32_at(body, 4), ip, body[1], body[2]),
                    (Some(ip), _) => Message::DelAddr6(u32_at(body, 4), ip),
                    (None, _) => Message::Other,
                }
            }
            RTM_NEWADDR if body.len() >= 8 && body[0] == AF_INET => {
                let list = attrs(&body[8..]);
                let ip = list
                    .iter()
                    .find(|(t, v)| *t == IFA_LOCAL && v.len() == 4)
                    .or_else(|| list.iter().find(|(t, v)| *t == IFA_ADDRESS && v.len() == 4))
                    .map(|(_, v)| Ipv4((*v).try_into().unwrap()));
                match ip {
                    Some(ip) => Message::Addr(u32_at(body, 4), ip, body[1]),
                    None => Message::Other,
                }
            }
            _ => Message::Other,
        });
        at += len.next_multiple_of(4);
    }
    out
}
