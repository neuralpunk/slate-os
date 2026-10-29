// SPDX-License-Identifier: MIT OR Apache-2.0

//! Netlink route sockets (netlink(7), rtnetlink(7); ADR 0048, ADR 0049):
//! dumps and queries of links, IPv4 addresses, routes and neighbours (the
//! ARP table), changes to them (link state and MTU, addresses, routes,
//! neighbours set by hand), veth pairs, bridges and dummies made, moved
//! between namespaces, renamed, enslaved and deleted (ADR 0131), and
//! notifications of every change to the
//! sockets that joined the link, neighbour, IPv4 address and IPv4 route
//! multicast groups.

use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use slate_net::{
    AddrOrigin, AddrState, Change, If6Addr, IfAddr, IfInfo, IpAddr, Ipv4, Ipv6, LOOPBACK, Mac, Neighbour, Route, Route6,
};

use super::ioctl::{IFF_LOOPBACK, Iface, iface, interfaces_in};
use crate::abi::linux::errno::*;
use crate::fs::vfs::{Metadata, Result, S_IFSOCK};
use crate::fs::{File, O_NONBLOCK, O_RDWR, POLLIN, POLLOUT};
use crate::sched::wait::WaitResult;
use crate::sync::IrqSpinLock;

const NETLINK_ROUTE: u32 = 0;
/// nf_tables' family (netlink(7): NETLINK_NETFILTER; ADR 0129).
const NETLINK_NETFILTER: u32 = 12;
const AF_NETLINK: u16 = 16;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

// Message types and flags (netlink(7), rtnetlink(7)).
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
const RTM_SETLINK: u16 = 19;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;
const RTM_NEWNEIGH: u16 = 28;
const RTM_DELNEIGH: u16 = 29;
const RTM_GETNEIGH: u16 = 30;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_MULTI: u16 = 0x2;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_DUMP: u16 = 0x300;

// Multicast groups (rtnetlink(7): RTMGRP_* masks in `nl_groups`;
// NETLINK_ADD_MEMBERSHIP takes the group number, the mask's bit + 1).
const RTMGRP_LINK: u32 = 0x1;
const RTMGRP_NEIGH: u32 = 0x4;
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV4_ROUTE: u32 = 0x40;
const RTMGRP_IPV6_IFADDR: u32 = 0x100;
const RTMGRP_IPV6_ROUTE: u32 = 0x400;

const IFLA_ADDRESS: u16 = 1;
const IFLA_BROADCAST: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_TXQLEN: u16 = 13;
const IFLA_OPERSTATE: u16 = 16;
// Links of a kind, their bridge and namespace (linux/if_link.h and
// linux/veth.h, UAPI, ADR 0131).
const IFLA_LINK: u16 = 5;
const IFLA_MASTER: u16 = 10;
const IFLA_LINKINFO: u16 = 18;
const IFLA_NET_NS_PID: u16 = 19;
const IFLA_NET_NS_FD: u16 = 28;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;
// RFC 2863 operational states, as rtnetlink(7) reports them.
const IF_OPER_UNKNOWN: u8 = 0;
const IF_OPER_DOWN: u8 = 2;
const IF_OPER_UP: u8 = 6;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_BROADCAST: u16 = 4;
const IFA_CACHEINFO: u16 = 6;
const IFA_F_DEPRECATED: u8 = 0x20;
const IFA_F_TENTATIVE: u8 = 0x40;
const IFA_F_PERMANENT: u8 = 0x80;

// Neighbour attributes and states (rtnetlink(7) "struct ndmsg").
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const NUD_INCOMPLETE: u16 = 0x01;
const NUD_REACHABLE: u16 = 0x02;
const NUD_PERMANENT: u16 = 0x80;

const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RTA_TABLE: u16 = 15;
const RT_TABLE_UNSPEC: u8 = 0;
const RT_TABLE_MAIN: u8 = 254;
const RT_TABLE_LOCAL: u8 = 255;
const RTPROT_KERNEL: u8 = 2;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RT_SCOPE_HOST: u8 = 254;
const RTN_UNICAST: u8 = 1;
const RTN_LOCAL: u8 = 2;

/// Most messages waiting for one socket before notifications are dropped
/// (the reader then gets ENOBUFS once, netlink(7)).
const QUEUE: usize = 1024;

pub struct NetlinkSocket {
    pub protocol: u32,
    /// The network namespace it was created in: the one it shows and
    /// changes.
    ns: Arc<crate::proc::ns::NetNs>,
    port: AtomicU32,
    groups: AtomicU32,
    replies: IrqSpinLock<VecDeque<Vec<u8>>>,
    overrun: AtomicBool,
    flags: AtomicU32,
    pub rcvtimeo_ns: AtomicU64,
    /// SO_SNDTIMEO and the other options kept for getsockopt (ADR 0077).
    pub opts: crate::net::socket::SockOpts,
    /// NETLINK_CAP_ACK and NETLINK_EXT_ACK (netlink(7)): how errors come
    /// back (nf_tables' answers follow them).
    pub cap_ack: AtomicBool,
    pub ext_ack: AtomicBool,
}

/// Every open route socket, for notifications.
static SOCKETS: IrqSpinLock<Vec<Weak<NetlinkSocket>>> = IrqSpinLock::new(Vec::new());

fn live() -> Vec<Arc<NetlinkSocket>> {
    let mut all = SOCKETS.lock();
    all.retain(|w| w.strong_count() > 0);
    all.iter().filter_map(Weak::upgrade).collect()
}

/// A netlink message under construction.
struct Msg(Vec<u8>);

impl Msg {
    fn new(ty: u16, flags: u16, seq: u32, port: u32) -> Msg {
        let mut b = Vec::with_capacity(256);
        b.extend_from_slice(&0u32.to_ne_bytes());
        b.extend_from_slice(&ty.to_ne_bytes());
        b.extend_from_slice(&flags.to_ne_bytes());
        b.extend_from_slice(&seq.to_ne_bytes());
        b.extend_from_slice(&port.to_ne_bytes());
        Msg(b)
    }
    fn bytes(&mut self, b: &[u8]) -> &mut Msg {
        self.0.extend_from_slice(b);
        self
    }
    /// An attribute (`struct rtattr`), padded to 4 bytes.
    fn attr(&mut self, ty: u16, data: &[u8]) -> &mut Msg {
        self.0.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        self.0.extend_from_slice(&ty.to_ne_bytes());
        self.0.extend_from_slice(data);
        while self.0.len() % 4 != 0 {
            self.0.push(0);
        }
        self
    }
    fn finish(mut self) -> Vec<u8> {
        let len = self.0.len() as u32;
        self.0[..4].copy_from_slice(&len.to_ne_bytes());
        self.0
    }
}

fn cstr(s: &str) -> Vec<u8> {
    let mut v = Vec::from(s.as_bytes());
    v.push(0);
    v
}

fn link_msg(i: &Iface, ty: u16, flags: u16, seq: u32, port: u32) -> Vec<u8> {
    let mut m = Msg::new(ty, flags, seq, port);
    // struct ifinfomsg: family, pad, type, index, flags, change.
    m.bytes(&[0, 0]).bytes(&i.hw_type.to_ne_bytes()).bytes(&i.index.to_ne_bytes());
    m.bytes(&i.flags.to_ne_bytes()).bytes(&0u32.to_ne_bytes());
    m.attr(IFLA_IFNAME, &cstr(&i.name));
    m.attr(IFLA_MTU, &(i.mtu as u32).to_ne_bytes());
    m.attr(IFLA_TXQLEN, &1000u32.to_ne_bytes());
    let loopback = i.flags & IFF_LOOPBACK != 0;
    let oper = if loopback {
        IF_OPER_UNKNOWN
    } else if i.flags & 0x40 != 0 {
        IF_OPER_UP
    } else {
        IF_OPER_DOWN
    };
    m.attr(IFLA_OPERSTATE, &[oper]);
    m.attr(IFLA_ADDRESS, &i.mac.0);
    m.attr(IFLA_BROADCAST, &if loopback { [0; 6] } else { [0xFF; 6] });
    if i.master != 0 {
        m.attr(IFLA_MASTER, &i.master.to_ne_bytes());
    }
    if i.peer != 0 {
        m.attr(IFLA_LINK, &i.peer.to_ne_bytes());
    }
    if let Some(kind) = i.kind {
        let mut info = Msg(Vec::new());
        info.attr(IFLA_INFO_KIND, kind.as_bytes());
        m.attr(IFLA_LINKINFO, &info.0);
    }
    m.finish()
}

fn addr_msg(name: &str, index: u32, a: &IfAddr, ty: u16, flags: u16, seq: u32, port: u32) -> Vec<u8> {
    let loopback = index == LOOPBACK;
    let mut m = Msg::new(ty, flags, seq, port);
    // struct ifaddrmsg: family, prefixlen, flags, scope, index.
    m.bytes(&[AF_INET, a.prefix_len, IFA_F_PERMANENT, if loopback { RT_SCOPE_HOST } else { RT_SCOPE_UNIVERSE }]);
    m.bytes(&index.to_ne_bytes());
    m.attr(IFA_ADDRESS, &a.addr.0).attr(IFA_LOCAL, &a.addr.0);
    if !loopback && a.prefix_len < 31 {
        m.attr(IFA_BROADCAST, &a.broadcast().0);
    }
    m.attr(IFA_LABEL, &cstr(name));
    m.finish()
}

#[allow(clippy::too_many_arguments)]
fn route_msg(r: &Route, table: u8, scope: u8, kind: u8, ty: u16, flags: u16, seq: u32, port: u32) -> Vec<u8> {
    let mut m = Msg::new(ty, flags, seq, port);
    // struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope,
    // type, flags.
    m.bytes(&[AF_INET, r.prefix_len, 0, 0, table, r.protocol, scope, kind]).bytes(&0u32.to_ne_bytes());
    m.attr(RTA_TABLE, &u32::from(table).to_ne_bytes());
    if r.prefix_len > 0 {
        m.attr(RTA_DST, &r.dst.0);
    }
    if let Some(g) = r.gateway {
        m.attr(RTA_GATEWAY, &g.0);
    }
    if r.metric != 0 {
        m.attr(RTA_PRIORITY, &r.metric.to_ne_bytes());
    }
    if let Some(s) = r.src {
        m.attr(RTA_PREFSRC, &s.0);
    }
    m.attr(RTA_OIF, &r.iface.to_ne_bytes());
    m.finish()
}

/// A route of the main table as a message.
fn main_route_msg(r: &Route, ty: u16, flags: u16, seq: u32, port: u32) -> Vec<u8> {
    let scope = if r.gateway.is_none() { RT_SCOPE_LINK } else { RT_SCOPE_UNIVERSE };
    route_msg(r, RT_TABLE_MAIN, scope, RTN_UNICAST, ty, flags, seq, port)
}

/// The local table's entry for one of the host's addresses.
fn local_route_msg(index: u32, a: &IfAddr, seq: u32, port: u32) -> Vec<u8> {
    let r = Route {
        dst: a.addr,
        prefix_len: 32,
        gateway: None,
        iface: index,
        metric: 0,
        protocol: RTPROT_KERNEL,
        src: Some(a.addr),
    };
    route_msg(&r, RT_TABLE_LOCAL, RT_SCOPE_HOST, RTN_LOCAL, RTM_NEWROUTE, NLM_F_MULTI, seq, port)
}

fn neigh_msg(n: &Neighbour, ty: u16, flags: u16, seq: u32, port: u32) -> Vec<u8> {
    let mut m = Msg::new(ty, flags, seq, port);
    let state = if n.permanent {
        NUD_PERMANENT
    } else if n.mac.is_some() {
        NUD_REACHABLE
    } else {
        NUD_INCOMPLETE
    };
    // struct ndmsg: family, pad, pad (u16), ifindex, state, flags, type.
    let family = if n.ip.is_v6() { AF_INET6 } else { AF_INET };
    m.bytes(&[family, 0, 0, 0]).bytes(&(n.iface as i32).to_ne_bytes()).bytes(&state.to_ne_bytes());
    m.bytes(&[0, RTN_UNICAST]);
    match n.ip {
        IpAddr::V4(a) => m.attr(NDA_DST, &a.0),
        IpAddr::V6(a) => m.attr(NDA_DST, &a.0),
    };
    if let Some(mac) = n.mac {
        m.attr(NDA_LLADDR, &mac.0);
    }
    m.finish()
}

/// An IPv6 address: its state as flags, its scope, and IFA_CACHEINFO
/// (`struct ifa_cacheinfo`: preferred and valid lifetimes left, in
/// seconds, all ones for ever, then two timestamps).
fn addr6_msg(name: &str, index: u32, a: &If6Addr, ty: u16, flags: u16, seq: u32, port: u32) -> Vec<u8> {
    let mut f = match a.state {
        AddrState::Tentative => IFA_F_TENTATIVE,
        AddrState::Deprecated => IFA_F_DEPRECATED,
        AddrState::Preferred => 0,
    };
    if a.origin != AddrOrigin::Slaac {
        f |= IFA_F_PERMANENT;
    }
    let scope = if a.addr.is_loopback() {
        RT_SCOPE_HOST
    } else if a.addr.is_link_local() {
        RT_SCOPE_LINK
    } else {
        RT_SCOPE_UNIVERSE
    };
    let mut m = Msg::new(ty, flags, seq, port);
    m.bytes(&[AF_INET6, a.prefix_len, f, scope]).bytes(&index.to_ne_bytes());
    m.attr(IFA_ADDRESS, &a.addr.0);
    let now = crate::time::monotonic_ns() / 1_000_000;
    let left = |t: Option<u64>| t.map_or(u32::MAX, |t| (t.saturating_sub(now) / 1000) as u32);
    let mut ci = Vec::with_capacity(16);
    ci.extend_from_slice(&left(a.preferred_until).to_ne_bytes());
    ci.extend_from_slice(&left(a.valid_until).to_ne_bytes());
    ci.extend_from_slice(&[0; 8]);
    m.attr(IFA_CACHEINFO, &ci);
    let _ = name;
    m.finish()
}

/// An IPv6 route of the main table (`table`) or the local one.
fn route6_msg(r: &Route6, table: u8, kind: u8, ty: u16, flags: u16, seq: u32, port: u32) -> Vec<u8> {
    let mut m = Msg::new(ty, flags, seq, port);
    m.bytes(&[AF_INET6, r.prefix_len, 0, 0, table, r.protocol, RT_SCOPE_UNIVERSE, kind]).bytes(&0u32.to_ne_bytes());
    m.attr(RTA_TABLE, &u32::from(table).to_ne_bytes());
    if r.prefix_len > 0 {
        m.attr(RTA_DST, &r.dst.0);
    }
    if let Some(g) = r.gateway {
        m.attr(RTA_GATEWAY, &g.0);
    }
    m.attr(RTA_PRIORITY, &r.metric.to_ne_bytes());
    m.attr(RTA_OIF, &r.iface.to_ne_bytes());
    m.finish()
}

fn ip6_attr(list: &[(u16, &[u8])], ty: u16) -> Option<Ipv6> {
    attr(list, ty).filter(|v| v.len() >= 16).map(|v| Ipv6(v[..16].try_into().unwrap()))
}

fn done(seq: u32, port: u32) -> Vec<u8> {
    let mut m = Msg::new(NLMSG_DONE, NLM_F_MULTI, seq, port);
    m.bytes(&0i32.to_ne_bytes());
    m.finish()
}

/// NLMSG_ERROR: `error` (0 is an acknowledgement) and the request header.
fn error(errno: i32, req: &[u8], port: u32) -> Vec<u8> {
    let seq = u32::from_ne_bytes(req[8..12].try_into().unwrap());
    let mut m = Msg::new(NLMSG_ERROR, 0, seq, port);
    m.bytes(&(-errno).to_ne_bytes()).bytes(&req[..16]);
    m.finish()
}

/// The (type, payload) attributes in `b` (rtnetlink(7) attribute layout).
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

fn attr<'a>(list: &[(u16, &'a [u8])], ty: u16) -> Option<&'a [u8]> {
    list.iter().find(|(t, _)| *t == ty).map(|(_, v)| *v)
}

fn ip_attr(list: &[(u16, &[u8])], ty: u16) -> Option<Ipv4> {
    attr(list, ty).filter(|v| v.len() >= 4).map(|v| Ipv4(v[..4].try_into().unwrap()))
}

fn u32_attr(list: &[(u16, &[u8])], ty: u16) -> Option<u32> {
    attr(list, ty).filter(|v| v.len() >= 4).map(|v| u32::from_ne_bytes(v[..4].try_into().unwrap()))
}

fn name_attr<'a>(list: &[(u16, &'a [u8])]) -> Option<&'a str> {
    let v = attr(list, IFLA_IFNAME)?;
    let end = v.iter().position(|&b| b == 0).unwrap_or(v.len());
    core::str::from_utf8(&v[..end]).ok()
}

/// Announce configuration changes in namespace `ns` to the sockets that
/// joined the matching groups (the stack's changes, with the interface
/// as it was then for link changes).
pub fn announce(ns: u64, changes: &[(Change, Option<IfInfo>)]) {
    let listeners: Vec<Arc<NetlinkSocket>> =
        live().into_iter().filter(|s| s.ns.id == ns && s.groups.load(Ordering::Relaxed) != 0).collect();
    if listeners.is_empty() {
        return;
    }
    for (c, info) in changes {
        let (group, msg) = match *c {
            Change::Link(_) => {
                let Some(i) = info else { continue };
                (RTMGRP_LINK, link_msg(&iface(ns, i), RTM_NEWLINK, 0, 0, 0))
            }
            Change::LinkGone(index) => {
                let mut m = Msg::new(RTM_DELLINK, 0, 0, 0);
                m.bytes(&[0, 0, 1, 0]).bytes(&(index as i32).to_ne_bytes()).bytes(&[0; 8]);
                (RTMGRP_LINK, m.finish())
            }
            Change::NewAddr(index, a) | Change::DelAddr(index, a) => {
                let ty = if matches!(c, Change::NewAddr(..)) { RTM_NEWADDR } else { RTM_DELADDR };
                let name = super::name_of(ns, index).unwrap_or_default();
                (RTMGRP_IPV4_IFADDR, addr_msg(&name, index, &a, ty, 0, 0, 0))
            }
            Change::NewRoute(r) => (RTMGRP_IPV4_ROUTE, main_route_msg(&r, RTM_NEWROUTE, 0, 0, 0)),
            Change::DelRoute(r) => (RTMGRP_IPV4_ROUTE, main_route_msg(&r, RTM_DELROUTE, 0, 0, 0)),
            Change::NewNeigh(n) => (RTMGRP_NEIGH, neigh_msg(&n, RTM_NEWNEIGH, 0, 0, 0)),
            Change::DelNeigh(n) => (RTMGRP_NEIGH, neigh_msg(&n, RTM_DELNEIGH, 0, 0, 0)),
            Change::NewAddr6(index, a) | Change::DelAddr6(index, a) => {
                let ty = if matches!(c, Change::NewAddr6(..)) { RTM_NEWADDR } else { RTM_DELADDR };
                let name = super::name_of(ns, index).unwrap_or_default();
                (RTMGRP_IPV6_IFADDR, addr6_msg(&name, index, &a, ty, 0, 0, 0))
            }
            Change::NewRoute6(r) => {
                (RTMGRP_IPV6_ROUTE, route6_msg(&r, RT_TABLE_MAIN, RTN_UNICAST, RTM_NEWROUTE, 0, 0, 0))
            }
            Change::DelRoute6(r) => {
                (RTMGRP_IPV6_ROUTE, route6_msg(&r, RT_TABLE_MAIN, RTN_UNICAST, RTM_DELROUTE, 0, 0, 0))
            }
        };
        for s in &listeners {
            if s.groups.load(Ordering::Relaxed) & group != 0 {
                s.deliver(msg.clone());
            }
        }
    }
    crate::fs::poll_notify();
}

impl NetlinkSocket {
    pub fn new(protocol: u32, flags: u32) -> core::result::Result<Arc<NetlinkSocket>, Errno> {
        if protocol != NETLINK_ROUTE && protocol != NETLINK_NETFILTER {
            return Err(EPROTONOSUPPORT);
        }
        let port = crate::proc::current().map_or(0, |p| p.pid);
        let s = Arc::new(NetlinkSocket {
            protocol,
            ns: super::current_ns(),
            port: AtomicU32::new(port),
            groups: AtomicU32::new(0),
            replies: IrqSpinLock::new(VecDeque::new()),
            overrun: AtomicBool::new(false),
            flags: AtomicU32::new(O_RDWR | (flags & O_NONBLOCK)),
            rcvtimeo_ns: AtomicU64::new(0),
            opts: crate::net::socket::SockOpts::default(),
            cap_ack: AtomicBool::new(false),
            ext_ack: AtomicBool::new(false),
        });
        SOCKETS.lock().push(Arc::downgrade(&s));
        Ok(s)
    }

    /// `struct sockaddr_nl`: family, pad, port ID, groups.
    fn sockaddr(port: u32, groups: u32) -> Vec<u8> {
        let mut b = Vec::from(AF_NETLINK.to_ne_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&port.to_ne_bytes());
        b.extend_from_slice(&groups.to_ne_bytes());
        b
    }

    pub fn address(&self) -> Vec<u8> {
        Self::sockaddr(self.port.load(Ordering::Relaxed), self.groups.load(Ordering::Relaxed))
    }

    /// The kernel's address (port 0), the sender of every reply.
    pub fn kernel_address(&self) -> Vec<u8> {
        Self::sockaddr(0, 0)
    }

    pub fn bind(&self, raw: &[u8]) -> Result<()> {
        if raw.len() < 12 || u16::from_ne_bytes([raw[0], raw[1]]) != AF_NETLINK {
            return Err(EINVAL);
        }
        let port = u32::from_ne_bytes(raw[4..8].try_into().unwrap());
        if port != 0 {
            self.port.store(port, Ordering::Relaxed);
        }
        self.groups.store(u32::from_ne_bytes(raw[8..12].try_into().unwrap()), Ordering::Relaxed);
        Ok(())
    }

    /// NETLINK_ADD_MEMBERSHIP / NETLINK_DROP_MEMBERSHIP: group numbers
    /// from 1.
    pub fn membership(&self, group: u32, add: bool) -> Result<()> {
        if group == 0 || group > 32 {
            return Err(EINVAL);
        }
        let bit = 1 << (group - 1);
        if add {
            self.groups.fetch_or(bit, Ordering::Relaxed);
        } else {
            self.groups.fetch_and(!bit, Ordering::Relaxed);
        }
        Ok(())
    }

    /// nf_tables requests (ADR 0129): the namespace's ruleset answers.
    /// Reading or changing it needs CAP_NET_ADMIN over the namespace, as
    /// on Linux (observed: nft list ruleset is EPERM for others).
    fn send_nftables(&self, data: &[u8]) -> Result<usize> {
        let port = self.port.load(Ordering::Relaxed);
        if !crate::proc::cred::current().ns_capable(&self.ns.owner, crate::proc::cred::CAP_NET_ADMIN) {
            let mut at = 0;
            while at + 16 <= data.len() {
                let len = u32::from_ne_bytes(data[at..at + 4].try_into().unwrap()) as usize;
                if len < 16 || at + len > data.len() {
                    break;
                }
                let h = &data[at..at + 16];
                self.deliver(error(EPERM.0, h, port));
                at += len.next_multiple_of(4);
            }
            crate::fs::poll_notify();
            return Ok(data.len());
        }
        let (pid, comm) =
            crate::proc::current().map_or((0, alloc::vec::Vec::new()), |p| (p.pid, p.name.lock().as_bytes().to_vec()));
        let acks = slate_net::AckOpts {
            capped: self.cap_ack.load(Ordering::Relaxed),
            extended: self.ext_ack.load(Ordering::Relaxed),
        };
        let answers = super::with_stack_in(self.ns.id, |st| st.firewall.netlink_opts(data, port, pid, &comm, acks));
        for a in answers {
            self.deliver(a);
        }
        crate::fs::poll_notify();
        Ok(data.len())
    }

    /// Queue a notification (dropped, with ENOBUFS to come, when full).
    fn deliver(&self, m: Vec<u8>) {
        let mut q = self.replies.lock();
        if q.len() >= QUEUE {
            self.overrun.store(true, Ordering::Relaxed);
            return;
        }
        q.push_back(m);
    }

    /// Handle the requests in `data`; replies are queued for recv.
    pub fn send(&self, data: &[u8]) -> Result<usize> {
        if self.protocol == NETLINK_NETFILTER {
            return self.send_nftables(data);
        }
        let port = self.port.load(Ordering::Relaxed);
        let ns = self.ns.id;
        let mut at = 0;
        while at + 16 <= data.len() {
            let len = u32::from_ne_bytes(data[at..at + 4].try_into().unwrap()) as usize;
            if len < 16 || at + len > data.len() {
                return Err(EINVAL);
            }
            let req = &data[at..at + len];
            let ty = u16::from_ne_bytes([req[4], req[5]]);
            let flags = u16::from_ne_bytes([req[6], req[7]]);
            let seq = u32::from_ne_bytes(req[8..12].try_into().unwrap());
            let body = &req[16..];
            let mut reply: Vec<u8> = Vec::new();
            let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
            let family = body.first().copied().unwrap_or(0);
            match ty {
                _ if flags & NLM_F_REQUEST == 0 => {}
                RTM_GETLINK if dump => {
                    for i in interfaces_in(ns) {
                        reply.extend(link_msg(&i, RTM_NEWLINK, NLM_F_MULTI, seq, port));
                    }
                    reply.extend(done(seq, port));
                }
                RTM_GETLINK => {
                    let index = body.get(4..8).map_or(0, |b| i32::from_ne_bytes(b.try_into().unwrap()));
                    let name = name_attr(&attrs(body.get(16..).unwrap_or(&[]))).map(alloc::string::String::from);
                    match interfaces_in(ns)
                        .into_iter()
                        .find(|i| (index != 0 && i.index == index) || name.as_deref() == Some(i.name.as_str()))
                    {
                        Some(i) => reply.extend(link_msg(&i, RTM_NEWLINK, 0, seq, port)),
                        None => reply.extend(error(ENODEV.0, req, port)),
                    }
                }
                RTM_GETADDR if dump => {
                    for i in interfaces_in(ns) {
                        if family == 0 || family == AF_INET {
                            for a in &i.addrs {
                                reply.extend(addr_msg(&i.name, i.index as u32, a, RTM_NEWADDR, NLM_F_MULTI, seq, port));
                            }
                        }
                        if family == 0 || family == AF_INET6 {
                            for a in &i.addrs6 {
                                reply.extend(addr6_msg(
                                    &i.name,
                                    i.index as u32,
                                    a,
                                    RTM_NEWADDR,
                                    NLM_F_MULTI,
                                    seq,
                                    port,
                                ));
                            }
                        }
                    }
                    reply.extend(done(seq, port));
                }
                RTM_GETROUTE if dump => {
                    if family == 0 || family == AF_INET {
                        let routes = super::with_stack_in(ns, |st| st.routes().to_vec());
                        for r in &routes {
                            reply.extend(main_route_msg(r, RTM_NEWROUTE, NLM_F_MULTI, seq, port));
                        }
                        for i in interfaces_in(ns) {
                            for a in &i.addrs {
                                reply.extend(local_route_msg(i.index as u32, a, seq, port));
                            }
                        }
                    }
                    if family == 0 || family == AF_INET6 {
                        let routes = super::with_stack_in(ns, |st| st.routes6().to_vec());
                        for r in &routes {
                            reply.extend(route6_msg(
                                r,
                                RT_TABLE_MAIN,
                                RTN_UNICAST,
                                RTM_NEWROUTE,
                                NLM_F_MULTI,
                                seq,
                                port,
                            ));
                        }
                        for i in interfaces_in(ns) {
                            for a in i.addrs6.iter().filter(|a| a.state != AddrState::Tentative) {
                                let r = Route6 {
                                    dst: a.addr,
                                    prefix_len: 128,
                                    gateway: None,
                                    iface: i.index as u32,
                                    metric: 0,
                                    protocol: RTPROT_KERNEL,
                                    expires: None,
                                };
                                reply.extend(route6_msg(
                                    &r,
                                    RT_TABLE_LOCAL,
                                    RTN_LOCAL,
                                    RTM_NEWROUTE,
                                    NLM_F_MULTI,
                                    seq,
                                    port,
                                ));
                            }
                        }
                    }
                    // Local routes added for other addresses (kept, without
                    // effect).
                    let extra = self.ns.extra_local.lock().clone();
                    for (dst, prefix_len, iface, protocol) in extra {
                        match dst {
                            IpAddr::V4(dst) if family == 0 || family == AF_INET => {
                                let r = Route { dst, prefix_len, gateway: None, iface, metric: 0, protocol, src: None };
                                let m = route_msg(
                                    &r,
                                    RT_TABLE_LOCAL,
                                    RT_SCOPE_HOST,
                                    RTN_LOCAL,
                                    RTM_NEWROUTE,
                                    NLM_F_MULTI,
                                    seq,
                                    port,
                                );
                                reply.extend(m);
                            }
                            IpAddr::V6(dst) if family == 0 || family == AF_INET6 => {
                                let r = Route6 {
                                    dst,
                                    prefix_len,
                                    gateway: None,
                                    iface,
                                    metric: 0,
                                    protocol,
                                    expires: None,
                                };
                                reply.extend(route6_msg(
                                    &r,
                                    RT_TABLE_LOCAL,
                                    RTN_LOCAL,
                                    RTM_NEWROUTE,
                                    NLM_F_MULTI,
                                    seq,
                                    port,
                                ));
                            }
                            _ => {}
                        }
                    }
                    reply.extend(done(seq, port));
                }
                RTM_GETNEIGH if dump => {
                    for n in super::with_stack_in(ns, |st| st.neighbours()) {
                        let f = if n.ip.is_v6() { AF_INET6 } else { AF_INET };
                        if family == 0 || family == f {
                            reply.extend(neigh_msg(&n, RTM_NEWNEIGH, NLM_F_MULTI, seq, port));
                        }
                    }
                    reply.extend(done(seq, port));
                }
                RTM_NEWNEIGH | RTM_DELNEIGH => {
                    let e = match self.neighbour(ty, body) {
                        Ok(()) => 0,
                        Err(e) => e.0,
                    };
                    if e != 0 || flags & NLM_F_ACK != 0 {
                        reply.extend(error(e, req, port));
                    }
                }
                RTM_NEWLINK | RTM_SETLINK | RTM_DELLINK | RTM_NEWADDR | RTM_DELADDR | RTM_NEWROUTE | RTM_DELROUTE => {
                    let e = match self.change(ty, flags, body) {
                        Ok(()) => 0,
                        Err(e) => e.0,
                    };
                    // Errors always get an answer, success when asked.
                    if e != 0 || flags & NLM_F_ACK != 0 {
                        reply.extend(error(e, req, port));
                    }
                }
                _ => reply.extend(error(EOPNOTSUPP.0, req, port)),
            }
            if flags & NLM_F_ACK != 0 && matches!(ty, RTM_GETLINK | RTM_GETADDR | RTM_GETROUTE) && !dump {
                reply.extend(error(0, req, port));
            }
            if !reply.is_empty() {
                self.replies.lock().push_back(reply);
            }
            at += len.next_multiple_of(4);
        }
        crate::fs::poll_notify();
        Ok(data.len())
    }

    /// RTM_NEWNEIGH / RTM_DELNEIGH: set an ARP entry by hand or remove one
    /// (`ip neigh add|del`). Needs CAP_NET_ADMIN over the namespace.
    fn neighbour(&self, ty: u16, body: &[u8]) -> Result<()> {
        if !crate::proc::cred::current().ns_capable(&self.ns.owner, crate::proc::cred::CAP_NET_ADMIN) {
            return Err(EPERM);
        }
        // struct ndmsg: family, pads, ifindex, state, flags, type.
        let family = body.first().copied().unwrap_or(0);
        if !matches!(family, AF_INET | AF_INET6) || body.len() < 12 {
            return Err(EINVAL);
        }
        let index = u32::from_ne_bytes(body[4..8].try_into().unwrap());
        let list = attrs(&body[12..]);
        let ip: IpAddr = if family == AF_INET6 {
            ip6_attr(&list, NDA_DST).ok_or(EINVAL)?.into()
        } else {
            ip_attr(&list, NDA_DST).ok_or(EINVAL)?.into()
        };
        let r = if ty == RTM_DELNEIGH {
            super::with_stack_in(self.ns.id, |st| st.del_neighbour(index, ip))
        } else {
            let mac = attr(&list, NDA_LLADDR).filter(|v| v.len() == 6).ok_or(EINVAL)?;
            let mac = Mac(mac.try_into().unwrap());
            super::with_stack_in(self.ns.id, |st| st.add_neighbour(index, ip, mac))
        };
        r.map_err(|e| if e == slate_net::Error::NotFound { ENOENT } else { super::socket::errno(e) })
    }

    /// A request that changes the namespace's configuration
    /// (rtnetlink(7)): a link's state (IFF_UP) and MTU, addresses, routes.
    /// Needs CAP_NET_ADMIN over the namespace. In the initial namespace the
    /// kernel stops configuring cards itself from then on (ADR 0048).
    fn change(&self, ty: u16, flags: u16, body: &[u8]) -> Result<()> {
        if !crate::proc::cred::current().ns_capable(&self.ns.owner, crate::proc::cred::CAP_NET_ADMIN) {
            return Err(EPERM);
        }
        let ns = self.ns.id;
        let u32_at = |o: usize| body.get(o..o + 4).map_or(0, |b| u32::from_ne_bytes(b.try_into().unwrap()));
        let net = super::socket::errno;
        match ty {
            RTM_NEWLINK | RTM_SETLINK | RTM_DELLINK => {
                // struct ifinfomsg: family, pad, type, index, flags, change.
                let list = attrs(body.get(16..).unwrap_or(&[]));
                let found = match u32_at(4) {
                    0 => name_attr(&list).and_then(|n| super::index_of(ns, n)),
                    i => Some(super::with_stack_in(ns, |st| st.interface(i)).ok_or(ENODEV)?.index),
                };
                let index = match found {
                    Some(i) if ty == RTM_NEWLINK && flags & NLM_F_CREATE != 0 && flags & NLM_F_EXCL != 0 => {
                        let _ = i;
                        return Err(EEXIST);
                    }
                    Some(i) => i,
                    None if ty == RTM_NEWLINK && flags & NLM_F_CREATE != 0 => return self.create_link(body, &list),
                    None => return Err(ENODEV),
                };
                if ty == RTM_DELLINK {
                    let l = super::link::find(ns, index).ok_or(EOPNOTSUPP)?;
                    return super::link::delete(&l);
                }
                let mut ns = ns;
                let mut index = index;
                let link = super::link::find(ns, index);
                // Into another namespace first (named there as asked), then
                // the rest there.
                if let Some(target) = self.target_ns(&list)? {
                    let l = link.as_ref().ok_or(EINVAL)?;
                    super::link::move_to(l, target.id, name_attr(&list))?;
                    (ns, index) = l.place();
                } else if let (Some(l), Some(n)) = (&link, name_attr(&list))
                    && u32_at(4) != 0
                {
                    super::link::rename(l, n)?;
                }
                let info = super::with_stack_in(ns, |st| st.interface(index)).ok_or(ENODEV)?;
                let virt = link.as_ref().is_some_and(|l| !l.is_card());
                for (a, v) in &list {
                    match *a {
                        IFLA_MTU if v.len() >= 4 && index != LOOPBACK => {
                            let mtu = u32::from_ne_bytes(v[..4].try_into().unwrap()) as usize;
                            // A card's own frame size is the ceiling.
                            if !(68..=65535).contains(&mtu) || (!virt && mtu > info.mtu.max(1500)) {
                                return Err(EINVAL);
                            }
                            super::with_stack_in(ns, |st| st.set_link(index, info.mac, mtu)).map_err(net)?;
                        }
                        IFLA_ADDRESS if v.len() >= 6 && virt => {
                            super::link::set_mac(link.as_ref().unwrap(), Mac(v[..6].try_into().unwrap()))?;
                        }
                        IFLA_ADDRESS => return Err(EOPNOTSUPP),
                        IFLA_MASTER if v.len() >= 4 => {
                            let l = link.as_ref().ok_or(EINVAL)?;
                            super::link::set_master(l, u32::from_ne_bytes(v[..4].try_into().unwrap()))?;
                            super::announce_link(ns, index);
                        }
                        _ => {}
                    }
                }
                let (iff, change) = (u32_at(8), u32_at(12));
                // IFF_UP changes when `change` names it; a request without a
                // change mask (as for an MTU alone) may bring a link up but
                // never takes it down.
                let up = iff & super::ioctl::IFF_UP != 0;
                if change & super::ioctl::IFF_UP != 0 || (change == 0 && up) {
                    super::set_up(ns, index, up).map_err(net)?;
                }
                super::user_configured(ns);
                Ok(())
            }
            RTM_NEWADDR | RTM_DELADDR => {
                // struct ifaddrmsg: family, prefixlen, flags, scope, index.
                let (family, prefix, index) =
                    (body.first().copied().unwrap_or(0), body.get(1).copied().unwrap_or(0), u32_at(4));
                if family == AF_INET6 {
                    return self.change6(ty, flags, body);
                }
                if family != AF_INET || prefix > 32 {
                    return Err(EINVAL);
                }
                let list = attrs(body.get(8..).unwrap_or(&[]));
                let addr = ip_attr(&list, IFA_LOCAL).or_else(|| ip_attr(&list, IFA_ADDRESS)).ok_or(EINVAL)?;
                let a = IfAddr { addr, prefix_len: prefix };
                let r = super::with_stack_in(ns, |st| {
                    if ty == RTM_DELADDR {
                        return st.del_address(index, addr);
                    }
                    match st.add_address(index, a) {
                        // NLM_F_REPLACE (`ip addr replace`) takes the new prefix.
                        Err(slate_net::Error::Exists) if flags & NLM_F_REPLACE != 0 => {
                            st.del_address(index, addr)?;
                            st.add_address(index, a)
                        }
                        Err(slate_net::Error::Exists) if flags & NLM_F_EXCL == 0 => Ok(()),
                        r => r,
                    }
                });
                r.map_err(|e| if e == slate_net::Error::AddrNotAvailable { EADDRNOTAVAIL } else { net(e) })?;
                super::user_configured(ns);
                Ok(())
            }
            _ => {
                // RTM_NEWROUTE / RTM_DELROUTE: struct rtmsg (family, dst_len,
                // src_len, tos, table, protocol, scope, type, flags), then
                // attributes.
                let b = |i: usize| body.get(i).copied().unwrap_or(0);
                let (family, dst_len, table, protocol) = (b(0), b(1), b(4), b(5));
                if family == AF_INET6 {
                    return self.change6(ty, flags, body);
                }
                if family != AF_INET || dst_len > 32 {
                    return Err(EINVAL);
                }
                let list = attrs(body.get(12..).unwrap_or(&[]));
                let table = u32_attr(&list, RTA_TABLE).map_or(table, |t| t as u8);
                let dst = ip_attr(&list, RTA_DST).unwrap_or(Ipv4::UNSPECIFIED);
                if table == RT_TABLE_LOCAL {
                    let own = dst_len == 32 && interfaces_in(ns).iter().any(|i| i.addrs.iter().any(|a| a.addr == dst));
                    let oif = u32_attr(&list, RTA_OIF).unwrap_or(0);
                    return self.local_route(own, b(7), (dst.into(), dst_len, oif, protocol), ty, flags);
                }
                if !matches!(table, RT_TABLE_UNSPEC | RT_TABLE_MAIN) {
                    return Err(EOPNOTSUPP); // Only the main table (a GAP).
                }
                let gateway = ip_attr(&list, RTA_GATEWAY);
                let oif = u32_attr(&list, RTA_OIF);
                let metric = u32_attr(&list, RTA_PRIORITY);
                let src = ip_attr(&list, RTA_PREFSRC);
                super::with_stack_in(ns, |st| {
                    if ty == RTM_DELROUTE {
                        return st.del_route(dst, dst_len, oif, gateway, metric).map(|_| ());
                    }
                    // Without an interface, the one whose subnet has the gateway.
                    let iface = oif
                        .or_else(|| {
                            let g = gateway?;
                            st.interfaces().into_iter().find(|i| i.addrs.iter().any(|a| a.contains(g))).map(|i| i.index)
                        })
                        .ok_or(slate_net::Error::NetUnreachable)?;
                    let r =
                        Route { dst, prefix_len: dst_len, gateway, iface, metric: metric.unwrap_or(0), protocol, src };
                    match st.add_route(r) {
                        Err(slate_net::Error::Exists) if flags & NLM_F_REPLACE != 0 => {
                            st.del_route(dst, dst_len, None, None, Some(r.metric))?;
                            st.add_route(r)
                        }
                        other => other,
                    }
                })
                .map_err(net)?;
                super::user_configured(ns);
                Ok(())
            }
        }
    }

    /// The namespace IFLA_NET_NS_PID or IFLA_NET_NS_FD names (a process's,
    /// or a namespace file's), checking the caller may change it.
    fn target_ns(&self, list: &[(u16, &[u8])]) -> Result<Option<Arc<crate::proc::ns::NetNs>>> {
        let ns = if let Some(pid) = u32_attr(list, IFLA_NET_NS_PID) {
            crate::proc::find_in_caller_ns(pid).ok_or(ESRCH)?.namespaces().net
        } else if let Some(fd) = u32_attr(list, IFLA_NET_NS_FD) {
            let f = crate::proc::current().ok_or(ESRCH)?.files.lock().get(fd as i32)?;
            match f.namespace() {
                Some(crate::fs::NsRef::Net(n)) => n,
                _ => return Err(EINVAL),
            }
        } else {
            return Ok(None);
        };
        if !crate::proc::cred::current().ns_capable(&ns.owner, crate::proc::cred::CAP_NET_ADMIN) {
            return Err(EPERM);
        }
        Ok(Some(ns))
    }

    /// RTM_NEWLINK with NLM_F_CREATE for an interface that isn't there: a
    /// veth pair (its peer described in VETH_INFO_PEER, an ifinfomsg and
    /// attributes), a bridge or a dummy (`ip link add`). Other kinds are
    /// EOPNOTSUPP, as Linux answers for a kind it lacks.
    fn create_link(&self, body: &[u8], list: &[(u16, &[u8])]) -> Result<()> {
        let info = attrs(attr(list, IFLA_LINKINFO).ok_or(EOPNOTSUPP)?);
        let kind = attr(&info, IFLA_INFO_KIND).ok_or(EOPNOTSUPP)?;
        let kind = core::str::from_utf8(kind).map_err(|_| EINVAL)?.trim_end_matches('\0');
        let ns = self.target_ns(list)?.map_or(self.ns.id, |n| n.id);
        let up = body.get(8..12).is_some_and(|b| u32::from_ne_bytes(b.try_into().unwrap()) & super::ioctl::IFF_UP != 0);
        let mac = |l: &[(u16, &[u8])]| {
            attr(l, IFLA_ADDRESS).filter(|v| v.len() >= 6).map(|v| Mac(v[..6].try_into().unwrap()))
        };
        let mtu = u32_attr(list, IFLA_MTU).map_or(1500, |m| m as usize);
        if !(68..=65535).contains(&mtu) {
            return Err(EINVAL);
        }
        let name = |l: &[(u16, &[u8])], default: &'static str| name_attr(l).unwrap_or(default).replace('\0', "");
        let made = match kind {
            "veth" => {
                // The peer: in the requester's namespace unless it names one.
                let data = attrs(attr(&info, IFLA_INFO_DATA).unwrap_or(&[]));
                let (peer_body, peer) = match attr(&data, VETH_INFO_PEER) {
                    Some(p) if p.len() >= 16 => (&p[..16], attrs(&p[16..])),
                    _ => (&[0u8; 16][..], Vec::new()),
                };
                let peer_ns = self.target_ns(&peer)?.map_or(self.ns.id, |n| n.id);
                let peer_up = u32::from_ne_bytes(peer_body[8..12].try_into().unwrap()) & super::ioctl::IFF_UP != 0;
                let peer_mtu = u32_attr(&peer, IFLA_MTU).map_or(mtu, |m| m as usize);
                let (a, b) = super::link::create_veth(
                    (ns, &name(list, "veth%d"), mac(list), mtu, up),
                    (peer_ns, &name(&peer, "veth%d"), mac(&peer), peer_mtu, peer_up),
                )?;
                alloc::vec![a.place(), b.place()]
            }
            "bridge" | "dummy" => {
                let (k, default) = if kind == "bridge" {
                    (super::link::Kind::Bridge(IrqSpinLock::new(alloc::collections::BTreeMap::new())), "bridge%d")
                } else {
                    (super::link::Kind::Dummy, "dummy%d")
                };
                let l = super::link::create(
                    k,
                    ns,
                    &name(list, default),
                    mac(list).unwrap_or_else(super::link::random_mac),
                    mtu,
                    up,
                )?;
                alloc::vec![l.place()]
            }
            _ => return Err(EOPNOTSUPP),
        };
        // A port from the start (`ip link add ... master br0`).
        if let Some(m) = u32_attr(list, IFLA_MASTER)
            && let Some(l) = super::link::find(made[0].0, made[0].1)
        {
            super::link::set_master(&l, m)?;
            super::announce_link(made[0].0, made[0].1);
        }
        super::user_configured(ns);
        Ok(())
    }

    /// A request for a route of the local table (rtnetlink(7)). The kernel
    /// keeps one there for each of the namespace's own addresses (made and
    /// removed with the address), so adding one of those finds it there
    /// (EEXIST with NLM_F_EXCL, as for any route that exists). Local routes
    /// for other addresses are kept and listed but have no effect: pasta
    /// copies a namespace's routes, these included, into a container
    /// (docs/GAPS.md). Other kinds of route there are not supported.
    fn local_route(&self, own: bool, kind: u8, r: (IpAddr, u8, u32, u8), ty: u16, flags: u16) -> Result<()> {
        if kind != RTN_LOCAL || (own && ty == RTM_DELROUTE) {
            return Err(EOPNOTSUPP);
        }
        let mut extra = self.ns.extra_local.lock();
        let at = extra.iter().position(|e| (e.0, e.1, e.2) == (r.0, r.1, r.2));
        match (ty, at) {
            (RTM_DELROUTE, Some(i)) => {
                extra.remove(i);
                Ok(())
            }
            (RTM_DELROUTE, None) => Err(ESRCH),
            _ if own || at.is_some() => {
                if flags & NLM_F_EXCL != 0 {
                    Err(EEXIST)
                } else {
                    Ok(())
                }
            }
            _ if extra.len() >= 256 => Err(ENOBUFS),
            _ => {
                extra.push(r);
                Ok(())
            }
        }
    }

    /// An IPv6 address or route change (the request's checks are done).
    fn change6(&self, ty: u16, flags: u16, body: &[u8]) -> Result<()> {
        let ns = self.ns.id;
        let net = super::socket::errno;
        let u32_at = |o: usize| body.get(o..o + 4).map_or(0, |b| u32::from_ne_bytes(b.try_into().unwrap()));
        if ty == RTM_NEWADDR || ty == RTM_DELADDR {
            let (prefix, index) = (body.get(1).copied().unwrap_or(0), u32_at(4));
            if prefix > 128 {
                return Err(EINVAL);
            }
            let list = attrs(body.get(8..).unwrap_or(&[]));
            let addr = ip6_attr(&list, IFA_LOCAL).or_else(|| ip6_attr(&list, IFA_ADDRESS)).ok_or(EINVAL)?;
            super::with_stack_in(ns, |st| {
                if ty == RTM_DELADDR {
                    return st.del_address6(index, addr);
                }
                match st.add_address6(index, addr, prefix) {
                    Err(slate_net::Error::Exists) if flags & NLM_F_EXCL == 0 => Ok(()),
                    r => r,
                }
            })
            .map_err(|e| if e == slate_net::Error::AddrNotAvailable { EADDRNOTAVAIL } else { net(e) })?;
            super::user_configured(ns);
            return Ok(());
        }
        let b = |i: usize| body.get(i).copied().unwrap_or(0);
        let (dst_len, table, protocol) = (b(1), b(4), b(5));
        if dst_len > 128 {
            return Err(EINVAL);
        }
        let list = attrs(body.get(12..).unwrap_or(&[]));
        let table = u32_attr(&list, RTA_TABLE).map_or(table, |t| t as u8);
        let dst = ip6_attr(&list, RTA_DST).unwrap_or(Ipv6::UNSPECIFIED);
        if table == RT_TABLE_LOCAL {
            let own = dst_len == 128 && interfaces_in(ns).iter().any(|i| i.addrs6.iter().any(|a| a.addr == dst));
            let oif = u32_attr(&list, RTA_OIF).unwrap_or(0);
            return self.local_route(own, b(7), (dst.into(), dst_len, oif, protocol), ty, flags);
        }
        if !matches!(table, RT_TABLE_UNSPEC | RT_TABLE_MAIN) {
            return Err(EOPNOTSUPP);
        }
        let gateway = ip6_attr(&list, RTA_GATEWAY);
        let oif = u32_attr(&list, RTA_OIF);
        let metric = u32_attr(&list, RTA_PRIORITY);
        super::with_stack_in(ns, |st| {
            if ty == RTM_DELROUTE {
                return st.del_route6(dst, dst_len, oif, gateway, metric).map(|_| ());
            }
            // Without an interface, the one a route to the gateway leaves by
            // (a link-local gateway needs one named).
            let iface = oif
                .or_else(|| gateway.filter(|g| !g.is_link_local()).and_then(|g| st.lookup6(g, None)).map(|r| r.iface))
                .ok_or(slate_net::Error::NetUnreachable)?;
            // User routes default to 1024, as `ip -6 route` shows Linux's.
            let r = Route6 {
                dst,
                prefix_len: dst_len,
                gateway,
                iface,
                metric: metric.unwrap_or(1024),
                protocol,
                expires: None,
            };
            match st.add_route6(r) {
                Err(slate_net::Error::Exists) if flags & NLM_F_REPLACE != 0 => {
                    st.del_route6(dst, dst_len, Some(iface), None, Some(r.metric))?;
                    st.add_route6(r)
                }
                other => other,
            }
        })
        .map_err(net)?;
        super::user_configured(ns);
        Ok(())
    }

    /// One queued message (a reply or a notification): (bytes copied, its
    /// full length). Waits for one unless non-blocking.
    pub fn recv(&self, buf: &mut [u8], peek: bool, dontwait: bool) -> Result<(usize, usize)> {
        let timeout = self.rcvtimeo_ns.load(Ordering::Relaxed);
        let deadline = (timeout != 0).then(|| crate::time::monotonic_ns() + timeout);
        loop {
            let seen = crate::fs::poll_generation();
            {
                let mut q = self.replies.lock();
                if let Some(r) = if peek { q.front().cloned() } else { q.pop_front() } {
                    let n = buf.len().min(r.len());
                    buf[..n].copy_from_slice(&r[..n]);
                    return Ok((n, r.len()));
                }
            }
            if self.overrun.swap(false, Ordering::Relaxed) {
                return Err(ENOBUFS);
            }
            if dontwait || self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0 {
                return Err(EAGAIN);
            }
            match crate::fs::poll_wait(seen, deadline) {
                WaitResult::Interrupted => return Err(EINTR),
                WaitResult::TimedOut => return Err(EAGAIN),
                WaitResult::Ready => {}
            }
        }
    }
}

impl File for NetlinkSocket {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.recv(buf, false, false)?.0)
    }
    fn write(&self, buf: &[u8]) -> Result<usize> {
        self.send(buf)
    }
    fn stat(&self) -> Result<Metadata> {
        Ok(Metadata { mode: S_IFSOCK | 0o777, nlink: 1, ..Default::default() })
    }
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64> {
        super::ioctl::interface_ioctl(cmd, arg)
    }
    fn poll(&self) -> u16 {
        POLLOUT | if self.replies.lock().is_empty() && !self.overrun.load(Ordering::Relaxed) { 0 } else { POLLIN }
    }
    fn status_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }
    fn set_status_flags(&self, flags: u32) {
        let old = self.flags.load(Ordering::Relaxed);
        self.flags.store((old & !O_NONBLOCK) | (flags & O_NONBLOCK), Ordering::Relaxed);
    }
}
