// SPDX-License-Identifier: MIT OR Apache-2.0

//! IPv6 (RFC 8200, ADR 0050): each interface's addresses, from its
//! link-local one (an EUI-64 interface identifier, RFC 4291 appendix A)
//! and stateless autoconfiguration (RFC 4862: router solicitations,
//! prefixes from router advertisements, duplicate address detection with
//! one probe); neighbour discovery (RFC 4861: solicitations and
//! advertisements, a neighbour cache per interface, routers and on-link
//! prefixes as routes); ICMPv6 (RFC 4443); the IPv6 routing table;
//! sending (with fragmentation at the source, RFC 8200 §4.5), receiving
//! (extension headers skipped, fragments reassembled) and forwarding.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::{Change, Error, IfIndex, LOOPBACK, Result, Stack};
use crate::wire::*;

/// Who made a route: a router advertisement (rtnetlink(7) RTPROT_RA).
pub const PROTO_RA: u8 = 9;
/// Router solicitations: three, four seconds apart (RFC 4861 §10).
const RS_INTERVAL_MS: u64 = 4000;
const RS_MAX: u32 = 3;
/// RetransTimer (RFC 4861 §10): duplicate address detection waits this
/// long for an answer to its one probe, address resolution this long
/// between its three.
const RETRANS_MS: u64 = 1000;
const ND_TRIES: u32 = 3;
const ND_TTL_MS: u64 = 20 * 60 * 1000;
/// Metrics of routes from router advertisements: on-link prefixes, then
/// default routers (the values Linux shows, so tools sort them alike).
const PREFIX_METRIC: u32 = 256;
const ROUTER_METRIC: u32 = 1024;
/// ND messages travel one link: hop limit 255 (RFC 4861 §6.1, §7.1).
const ND_HOP_LIMIT: u8 = 255;
// ND option types (RFC 4861 §4.6).
const OPT_SOURCE_LLADDR: u8 = 1;
const OPT_TARGET_LLADDR: u8 = 2;
const OPT_PREFIX: u8 = 3;
const OPT_MTU: u8 = 5;
// Neighbour advertisement flags (RFC 4861 §4.4).
const NA_ROUTER: u8 = 0x80;
const NA_SOLICITED: u8 = 0x40;
const NA_OVERRIDE: u8 = 0x20;
// Prefix information flags (RFC 4861 §4.6.2).
const PREFIX_ON_LINK: u8 = 0x80;
const PREFIX_AUTONOMOUS: u8 = 0x40;
/// A lifetime of all ones is infinity (RFC 4861 §4.6.2).
const INFINITE: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrState {
    /// Being checked for duplicates: not used yet.
    Tentative,
    Preferred,
    /// Past its preferred lifetime: kept for what uses it, not chosen for
    /// new traffic.
    Deprecated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrOrigin {
    LinkLocal,
    /// Stateless autoconfiguration from a router's prefix.
    Slaac,
    /// Added by hand (netlink).
    Manual,
}

/// An IPv6 address on an interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct If6Addr {
    pub addr: Ipv6,
    pub prefix_len: u8,
    pub state: AddrState,
    pub origin: AddrOrigin,
    /// When (ms) it stops being preferred, and valid; None: never.
    pub preferred_until: Option<u64>,
    pub valid_until: Option<u64>,
}

/// An IPv6 route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route6 {
    pub dst: Ipv6,
    pub prefix_len: u8,
    pub gateway: Option<Ipv6>,
    pub iface: IfIndex,
    pub metric: u32,
    pub protocol: u8,
    /// When (ms) a route from a router advertisement lapses.
    pub expires: Option<u64>,
}

impl Route6 {
    pub fn covers(&self, ip: Ipv6) -> bool {
        ip.within(self.dst, self.prefix_len)
    }
}

/// An interface's IPv6 state.
#[derive(Debug, Default)]
pub(super) struct Iface6 {
    pub addrs: Vec<If6Addr>,
    /// Tentative addresses and when their probe went out.
    dad: BTreeMap<Ipv6, u64>,
    /// Link-layer addresses of neighbours, with their expiry (u64::MAX:
    /// set by hand).
    pub nd: BTreeMap<Ipv6, (Mac, u64)>,
    /// Addresses being resolved: (last solicitation, solicitations sent).
    pub resolving: BTreeMap<Ipv6, (u64, u32)>,
    pending: Vec<(Ipv6, Vec<u8>)>,
    /// Router solicitation: (next time, sent so far).
    rs: Option<(u64, u32)>,
    /// The link MTU a router announced.
    pub mtu: Option<usize>,
    pub hop_limit: u8,
    /// Stateless autoconfiguration (accept_ra).
    pub autoconf: bool,
}

/// One reassembly in progress (IPv6, RFC 8200 §4.5).
#[derive(Debug)]
pub(super) struct Reassembly6 {
    /// The packet's header and next header (from the first fragment).
    next: u8,
    pieces: BTreeMap<usize, Vec<u8>>,
    total: Option<usize>,
    bytes: usize,
    deadline: u64,
}

/// Fragments kept for reassembly: 60 s (RFC 8200 §4.5), at most this much.
const REASSEMBLY_MS: u64 = 60_000;
const REASSEMBLY_BYTES: usize = 256 * 1024;

impl Stack {
    pub(super) fn v6(&self, index: IfIndex) -> Option<&Iface6> {
        self.ifaces.get(&index).map(|i| &i.v6)
    }

    fn v6_mut(&mut self, index: IfIndex) -> Option<&mut Iface6> {
        self.ifaces.get_mut(&index).map(|i| &mut i.v6)
    }

    /// Give a new interface its IPv6 state: loopback ::1, a card its
    /// link-local address (tentative, probed) and router solicitations.
    pub(super) fn start_v6(&mut self, index: IfIndex) {
        let now = self.now;
        let Some(i) = self.ifaces.get_mut(&index) else { return };
        i.v6.hop_limit = DEFAULT_HOP_LIMIT;
        if index == LOOPBACK {
            let a = If6Addr {
                addr: Ipv6::LOCALHOST,
                prefix_len: 128,
                state: AddrState::Preferred,
                origin: AddrOrigin::Manual,
                preferred_until: None,
                valid_until: None,
            };
            i.v6.addrs.push(a);
            return;
        }
        i.v6.autoconf = true;
        if i.mac == Mac::default() {
            return;
        }
        let ll = Ipv6::link_local(i.mac);
        let _ = self.add_address6_with(index, ll, 64, AddrOrigin::LinkLocal, None, None);
        if let Some(v6) = self.v6_mut(index) {
            v6.rs = Some((now + RETRANS_MS, 0));
        }
    }

    /// The link came back: ask the routers again.
    pub(super) fn link_up_v6(&mut self, index: IfIndex) {
        let now = self.now;
        if let Some(v6) = self.v6_mut(index)
            && v6.autoconf
        {
            v6.rs = Some((now, 0));
        }
    }

    /// Every IPv6 address of an interface.
    pub fn addresses6(&self, index: IfIndex) -> Vec<If6Addr> {
        self.v6(index).map(|v| v.addrs.clone()).unwrap_or_default()
    }

    /// Stateless autoconfiguration on or off (accept_ra).
    pub fn set_autoconf6(&mut self, index: IfIndex, on: bool) -> Result<()> {
        let v6 = self.v6_mut(index).ok_or(Error::NoDevice)?;
        v6.autoconf = on;
        if !on {
            v6.rs = None;
        }
        Ok(())
    }

    /// Add an address by hand (it is probed for duplicates first).
    pub fn add_address6(&mut self, index: IfIndex, addr: Ipv6, prefix_len: u8) -> Result<()> {
        if addr.is_unspecified() || addr.is_multicast() || prefix_len > 128 {
            return Err(Error::InvalidInput);
        }
        self.add_address6_with(index, addr, prefix_len, AddrOrigin::Manual, None, None)
    }

    fn add_address6_with(
        &mut self,
        index: IfIndex,
        addr: Ipv6,
        prefix_len: u8,
        origin: AddrOrigin,
        preferred_until: Option<u64>,
        valid_until: Option<u64>,
    ) -> Result<()> {
        let now = self.now;
        let v6 = self.v6_mut(index).ok_or(Error::NoDevice)?;
        if v6.addrs.iter().any(|a| a.addr == addr) {
            return Err(Error::Exists);
        }
        let a = If6Addr { addr, prefix_len, state: AddrState::Tentative, origin, preferred_until, valid_until };
        v6.addrs.push(a);
        v6.dad.insert(addr, now);
        self.changes.push(Change::NewAddr6(index, a));
        self.send_dad(index, addr);
        // The subnet of an address added by hand is on the link.
        if origin == AddrOrigin::Manual && prefix_len < 128 && index != LOOPBACK {
            let r = Route6 {
                dst: addr.masked(prefix_len),
                prefix_len,
                gateway: None,
                iface: index,
                metric: PREFIX_METRIC,
                protocol: super::PROTO_KERNEL,
                expires: None,
            };
            let _ = self.add_route6(r);
        }
        self.events += 1;
        Ok(())
    }

    /// Remove an address (and, for one added by hand, its subnet route).
    pub fn del_address6(&mut self, index: IfIndex, addr: Ipv6) -> Result<()> {
        let v6 = self.v6_mut(index).ok_or(Error::NoDevice)?;
        let at = v6.addrs.iter().position(|a| a.addr == addr).ok_or(Error::AddrNotAvailable)?;
        let a = v6.addrs.remove(at);
        v6.dad.remove(&addr);
        self.changes.push(Change::DelAddr6(index, a));
        if a.origin == AddrOrigin::Manual {
            let net = addr.masked(a.prefix_len);
            let still = self.v6(index).is_some_and(|v| v.addrs.iter().any(|x| x.addr.within(net, a.prefix_len)));
            if !still {
                let _ = self.del_route6(net, a.prefix_len, Some(index), None, None);
            }
        }
        self.events += 1;
        Ok(())
    }

    pub fn add_route6(&mut self, r: Route6) -> Result<()> {
        if r.prefix_len > 128 {
            return Err(Error::InvalidInput);
        }
        self.iface(r.iface)?;
        if r.gateway.is_some_and(|g| g.is_multicast() || g.is_unspecified()) {
            return Err(Error::InvalidInput);
        }
        let r = Route6 { dst: r.dst.masked(r.prefix_len), ..r };
        if self
            .routes6
            .iter()
            .any(|x| x.dst == r.dst && x.prefix_len == r.prefix_len && x.metric == r.metric && x.iface == r.iface)
        {
            return Err(Error::Exists);
        }
        self.routes6.push(r);
        self.changes.push(Change::NewRoute6(r));
        self.events += 1;
        Ok(())
    }

    pub fn del_route6(
        &mut self,
        dst: Ipv6,
        prefix_len: u8,
        iface: Option<IfIndex>,
        gateway: Option<Ipv6>,
        metric: Option<u32>,
    ) -> Result<Route6> {
        let dst = dst.masked(prefix_len);
        let at = self
            .routes6
            .iter()
            .position(|r| {
                r.dst == dst
                    && r.prefix_len == prefix_len
                    && iface.is_none_or(|i| r.iface == i)
                    && gateway.is_none_or(|g| r.gateway == Some(g))
                    && metric.is_none_or(|m| r.metric == m)
            })
            .ok_or(Error::NotFound)?;
        let r = self.routes6.remove(at);
        self.changes.push(Change::DelRoute6(r));
        self.events += 1;
        Ok(r)
    }

    pub fn routes6(&self) -> &[Route6] {
        &self.routes6
    }

    /// The IPv6 route for `dst` over usable interfaces (only `dev` if given).
    pub fn lookup6(&self, dst: Ipv6, dev: Option<IfIndex>) -> Option<Route6> {
        self.routes6
            .iter()
            .filter(|r| r.covers(dst) && dev.is_none_or(|d| r.iface == d))
            .filter(|r| self.ifaces.get(&r.iface).is_some_and(|i| i.up && i.carrier))
            .max_by_key(|r| (r.prefix_len, core::cmp::Reverse(r.metric)))
            .copied()
    }

    pub fn forwarding6(&self) -> bool {
        self.forwarding6
    }
    pub fn set_forwarding6(&mut self, on: bool) {
        self.forwarding6 = on;
    }

    /// Whether `ip` is one of the host's usable IPv6 addresses (link-local
    /// ones count only on `on`, when given).
    pub(super) fn is_local6(&self, ip: Ipv6, on: Option<IfIndex>) -> bool {
        ip.is_loopback()
            || self.ifaces.iter().any(|(k, i)| {
                (!ip.is_link_local() || on.is_none_or(|o| o == *k))
                    && i.v6.addrs.iter().any(|a| a.addr == ip && a.state != AddrState::Tentative)
            })
    }

    /// Whether interface `index` takes packets to multicast address `ip`:
    /// all nodes, and the solicited-node groups of its addresses (tentative
    /// ones too, so duplicates are noticed).
    fn joined(&self, index: IfIndex, ip: Ipv6) -> bool {
        ip == Ipv6::ALL_NODES
            || self.v6(index).is_some_and(|v| v.addrs.iter().any(|a| a.addr.solicited_node() == ip))
            || (self.forwarding6 && ip == Ipv6::ALL_ROUTERS)
    }

    /// The interface for link-scope traffic without a scope: the bound
    /// one, else the only usable card.
    fn link_scope_iface(&self, dev: Option<IfIndex>) -> Result<IfIndex> {
        if let Some(d) = dev {
            return Ok(d);
        }
        let mut cards = self.ifaces.iter().filter(|(k, i)| **k != LOOPBACK && i.up && i.carrier);
        match (cards.next(), cards.next()) {
            (Some((k, _)), None) => Ok(*k),
            _ => Err(Error::InvalidInput),
        }
    }

    /// Where a packet to `dst` goes: (interface, next hop).
    pub(super) fn next_hop6(&self, dst: Ipv6, dev: Option<IfIndex>) -> Result<(IfIndex, Ipv6)> {
        if dst.is_link_scope() {
            return Ok((self.link_scope_iface(dev)?, dst));
        }
        let r = self.lookup6(dst, dev).ok_or(Error::NetUnreachable)?;
        Ok((r.iface, r.gateway.unwrap_or(dst)))
    }

    /// The source address for packets to `dst` (RFC 6724, simply: the
    /// destination itself if it is ours, the link-local address for
    /// link-scope destinations, else a preferred global one on the way out).
    pub(super) fn source_for6(&self, dst: Ipv6, dev: Option<IfIndex>) -> Ipv6 {
        if dst.is_loopback() {
            return Ipv6::LOCALHOST;
        }
        if self.is_local6(dst, dev) {
            return dst;
        }
        let Ok((out, _)) = self.next_hop6(dst, dev) else { return Ipv6::UNSPECIFIED };
        let Some(v6) = self.v6(out) else { return Ipv6::UNSPECIFIED };
        let usable = |a: &&If6Addr| a.state == AddrState::Preferred;
        let link = v6.addrs.iter().filter(usable).find(|a| a.addr.is_link_local()).map(|a| a.addr);
        if dst.is_link_scope() {
            return link.unwrap_or(Ipv6::UNSPECIFIED);
        }
        v6.addrs
            .iter()
            .filter(usable)
            .find(|a| !a.addr.is_link_local())
            .map(|a| a.addr)
            .or_else(|| {
                self.ifaces
                    .values()
                    .flat_map(|i| i.v6.addrs.iter())
                    .filter(usable)
                    .find(|a| !a.addr.is_link_local() && !a.addr.is_loopback())
                    .map(|a| a.addr)
            })
            .or(link)
            .unwrap_or(Ipv6::UNSPECIFIED)
    }

    /// The MTU of the way to `dst`.
    pub(super) fn path_mtu6(&self, dst: Ipv6) -> usize {
        let Ok((out, _)) = self.next_hop6(dst, None) else { return IPV6_MIN_MTU };
        let link = self.ifaces.get(&out).map_or(IPV6_MIN_MTU, |i| i.v6.mtu.unwrap_or(i.mtu).min(i.mtu));
        let learned = self.pmtu6.get(&dst).map_or(usize::MAX, |(m, _)| *m);
        link.min(learned).max(IPV6_MIN_MTU)
    }

    // --- output ----------------------------------------------------------------

    /// Send an IPv6 packet from `src` to `dst` (out of `dev` only, if given),
    /// fragmenting it at the source if it is too big.
    pub(super) fn send_ip6_dev(
        &mut self,
        src: Ipv6,
        dst: Ipv6,
        next: u8,
        payload: &[u8],
        dev: Option<IfIndex>,
    ) -> Result<()> {
        self.send_ip6_tc(src, dst, next, payload, dev, 0)
    }

    /// [`Self::send_ip6_dev`] with a traffic class (RFC 8200 §3: the eight
    /// bits after the version; IPV6_TCLASS).
    pub(super) fn send_ip6_tc(
        &mut self,
        src: Ipv6,
        dst: Ipv6,
        next: u8,
        payload: &[u8],
        dev: Option<IfIndex>,
        tclass: u8,
    ) -> Result<()> {
        let classed = |mut p: Vec<u8>| {
            p[0] = 0x60 | (tclass >> 4);
            p[1] = (p[1] & 0x0F) | (tclass << 4);
            p
        };
        if self.is_local6(dst, dev) || dst.is_loopback() {
            let mut p = classed(ipv6(src, dst, next, DEFAULT_HOP_LIMIT, payload));
            let mut conn = None;
            self.leaving(&mut p, super::LOOPBACK, &mut conn)?;
            self.looped.push_back((p, conn));
            return Ok(());
        }
        let (mut out, mut next_hop) = self.next_hop6(dst, dev)?;
        let hop = if next == PROTO_ICMPV6 && is_nd(payload) {
            ND_HOP_LIMIT
        } else {
            self.v6(out).map_or(DEFAULT_HOP_LIMIT, |v| v.hop_limit)
        };
        if payload.len() > u16::MAX as usize {
            return Err(Error::MessageTooLong);
        }
        // Neighbour discovery goes through the hooks too, as on Linux: a
        // ruleset that drops it cuts the link. NAT in output may give the
        // packet another destination, which is then its way; postrouting
        // may give it another source.
        let mut whole = ipv6(src, dst, next, hop, payload);
        let mut conn = None;
        self.output(&mut whole, out, &mut conn)?;
        let to = Ipv6(whole[24..40].try_into().unwrap());
        if to != dst {
            if self.is_local6(to, None) || to.is_loopback() {
                self.postrouting(&mut whole, super::LOOPBACK, &mut conn)?;
                self.looped.push_back((classed(whole), conn));
                return Ok(());
            }
            (out, next_hop) = self.next_hop6(to, None)?;
        }
        self.postrouting(&mut whole, out, &mut conn)?;
        let (src, dst) = (Ipv6(whole[8..24].try_into().unwrap()), to);
        let mtu = if dst.is_multicast() {
            self.ifaces.get(&out).map_or(IPV6_MIN_MTU, |i| i.v6.mtu.unwrap_or(i.mtu).min(i.mtu))
        } else {
            self.path_mtu6(dst)
        };
        let packets = if whole.len() <= mtu {
            alloc::vec![whole]
        } else {
            self.frag_id = self.frag_id.wrapping_add(1);
            fragment6(src, dst, next, hop, &whole[IP6_HEADER..], mtu, self.frag_id)
        };
        for p in packets {
            let p = if tclass != 0 { classed(p) } else { p };
            if dst.is_multicast() {
                let mac = self.ifaces.get(&out).map(|i| i.mac).unwrap_or_default();
                self.emit(out, ethernet(dst.multicast_mac(), mac, ETHERTYPE_IPV6, &p), None);
            } else {
                self.transmit6(out, next_hop, p);
            }
        }
        Ok(())
    }

    /// Send a packet to a neighbour, resolving its address first if need be.
    fn transmit6(&mut self, out: IfIndex, next_hop: Ipv6, packet: Vec<u8>) {
        let now = self.now;
        let Some(i) = self.ifaces.get_mut(&out) else { return };
        let mac = i.mac;
        match i.v6.nd.get(&next_hop) {
            Some(&(hw, _)) => self.emit(out, ethernet(hw, mac, ETHERTYPE_IPV6, &packet), None),
            None => {
                i.v6.pending.push((next_hop, packet));
                if let alloc::collections::btree_map::Entry::Vacant(e) = i.v6.resolving.entry(next_hop) {
                    e.insert((now, 1));
                    self.solicit(out, next_hop);
                }
            }
        }
    }

    /// A neighbour solicitation for `target` (RFC 4861 §7.2.2).
    fn solicit(&mut self, index: IfIndex, target: Ipv6) {
        let Some(mac) = self.mac(index) else { return };
        let src = self.source_for6(target, Some(index));
        let mut body = Vec::from(target.0);
        if !src.is_unspecified() {
            body.extend_from_slice(&[OPT_SOURCE_LLADDR, 1]);
            body.extend_from_slice(&mac.0);
        }
        let dst = target.solicited_node();
        let m = icmpv6(src, dst, ND_NEIGHBOR_SOLICIT, 0, [0; 4], &body);
        let p = ipv6(src, dst, PROTO_ICMPV6, ND_HOP_LIMIT, &m);
        self.emit(index, ethernet(dst.multicast_mac(), mac, ETHERTYPE_IPV6, &p), None);
    }

    /// Duplicate address detection's probe: a solicitation from the
    /// unspecified address (RFC 4862 §5.4.2).
    fn send_dad(&mut self, index: IfIndex, addr: Ipv6) {
        let Some(mac) = self.mac(index) else { return };
        if index == LOOPBACK {
            return;
        }
        let dst = addr.solicited_node();
        let m = icmpv6(Ipv6::UNSPECIFIED, dst, ND_NEIGHBOR_SOLICIT, 0, [0; 4], &addr.0);
        let p = ipv6(Ipv6::UNSPECIFIED, dst, PROTO_ICMPV6, ND_HOP_LIMIT, &m);
        self.emit(index, ethernet(dst.multicast_mac(), mac, ETHERTYPE_IPV6, &p), None);
    }

    fn send_rs(&mut self, index: IfIndex) {
        let Some(mac) = self.mac(index) else { return };
        let src = self.source_for6(Ipv6::ALL_ROUTERS, Some(index));
        let mut body = Vec::new();
        if !src.is_unspecified() {
            body.extend_from_slice(&[OPT_SOURCE_LLADDR, 1]);
            body.extend_from_slice(&mac.0);
        }
        let m = icmpv6(src, Ipv6::ALL_ROUTERS, ND_ROUTER_SOLICIT, 0, [0; 4], &body);
        let p = ipv6(src, Ipv6::ALL_ROUTERS, PROTO_ICMPV6, ND_HOP_LIMIT, &m);
        self.emit(index, ethernet(Ipv6::ALL_ROUTERS.multicast_mac(), mac, ETHERTYPE_IPV6, &p), None);
    }

    /// An ICMPv6 error about `packet` to its sender (RFC 4443 §2.4): never
    /// about an ICMPv6 error, nor about a multicast packet (except "packet
    /// too big"), quoting as much as fits in the minimum MTU.
    pub(super) fn icmp6_error(&mut self, h: &Ipv6Header, packet: &[u8], kind: u8, code: u8, rest: [u8; 4]) {
        let about_error = h.next == PROTO_ICMPV6 && packet.get(IP6_HEADER).is_some_and(|t| *t < 128);
        if about_error
            || h.src.is_unspecified()
            || h.src.is_multicast()
            || (h.dst.is_multicast() && kind != ICMP6_PACKET_TOO_BIG)
        {
            return;
        }
        let quoted = &packet[..packet.len().min(IPV6_MIN_MTU - IP6_HEADER - 8)];
        let src = self.source_for6(h.src, None);
        let m = icmpv6(src, h.src, kind, code, rest, quoted);
        let _ = self.send_ip6_dev(src, h.src, PROTO_ICMPV6, &m, None);
    }

    // --- input -----------------------------------------------------------------

    pub(super) fn receive_ip6(&mut self, index: IfIndex, b: &[u8], looped: bool, conn: super::filter::Conn) {
        let Some(h) = Ipv6Header::parse(b) else { return };
        let packet = &b[..IP6_HEADER + h.payload_len];
        if h.src.is_multicast() {
            return;
        }
        // Prerouting sees whole packets: a piece of one for this host waits
        // until it is put back together (forwarded pieces are judged each
        // on its own). It may give the packet a new destination (NAT).
        let piece_for_us = self.is_local6(h.dst, None) && has_fragment_header(packet);
        if !piece_for_us && self.filtering() {
            let (mut p, mut conn) = (packet.to_vec(), conn);
            if !self.arriving(super::filter::NF_INET_PRE_ROUTING, &mut p, index, None, &mut conn) {
                return;
            }
            return self.receive_ip6_routed(index, &p, looped, conn);
        }
        self.receive_ip6_routed(index, packet, looped, conn)
    }

    /// An IPv6 packet past prerouting: to this host, or forwarded.
    fn receive_ip6_routed(&mut self, index: IfIndex, packet: &[u8], looped: bool, mut conn: super::filter::Conn) {
        let Some(h) = Ipv6Header::parse(packet) else { return };
        let for_us = (looped && (h.dst.is_loopback() || self.is_local6(h.dst, None)))
            || (!h.dst.is_loopback() && !h.dst.is_multicast() && self.is_local6(h.dst, Some(index)))
            || (h.dst.is_multicast() && self.joined(index, h.dst))
            // A tentative address takes only duplicate address detection.
            || self.v6(index).is_some_and(|v| v.dad.contains_key(&h.dst));
        if !for_us {
            if self.forwarding6 && !looped && !h.dst.is_multicast() && !h.dst.is_link_local() && !h.src.is_link_local()
            {
                self.forward6(index, &h, packet, conn);
            }
            return;
        }
        // Extension headers: skipped, a fragment's reassembled first.
        let (mut next, mut at) = (h.next, IP6_HEADER);
        loop {
            match next {
                NEXT_HOP_BY_HOP | NEXT_DEST_OPTS | NEXT_ROUTING => {
                    if at + 8 > packet.len() {
                        return;
                    }
                    // A routing header with segments left is for a router.
                    if next == NEXT_ROUTING && packet[at + 3] != 0 {
                        return;
                    }
                    next = packet[at];
                    at += (usize::from(packet[at + 1]) + 1) * 8;
                }
                NEXT_FRAGMENT => {
                    if let Some(whole) = self.reassemble6(&h, packet, at) {
                        self.receive_ip6(index, &whole, looped, conn);
                    }
                    return;
                }
                _ => break,
            }
        }
        if at > packet.len() {
            return;
        }
        // Input may give it a new source (NAT).
        let owned;
        let (h, packet) = if self.filtering() {
            let mut p = packet.to_vec();
            if !self.arriving(super::filter::NF_INET_LOCAL_IN, &mut p, index, None, &mut conn) {
                return;
            }
            owned = p;
            match Ipv6Header::parse(&owned) {
                Some(h) => (h, &owned[..]),
                None => return,
            }
        } else {
            (h, packet)
        };
        let payload = &packet[at..];
        let (src, dst) = (IpAddr::V6(h.src), IpAddr::V6(h.dst));
        match next {
            PROTO_ICMPV6 => self.receive_icmp6(index, &h, packet, payload),
            PROTO_UDP => {
                if !self.receive_udp_ip(index, src, dst, payload, h.dst.is_multicast(), (h.tclass, h.hop_limit))
                    && !h.dst.is_multicast()
                    && parse_udp_ip(src, dst, payload).is_some()
                {
                    self.icmp6_error(&h, packet, ICMP6_DEST_UNREACHABLE, ICMP6_PORT_UNREACHABLE, [0; 4]);
                }
            }
            PROTO_TCP if !h.dst.is_multicast() => self.receive_tcp(index, src, dst, payload),
            _ => {}
        }
    }

    fn receive_icmp6(&mut self, index: IfIndex, h: &Ipv6Header, packet: &[u8], m: &[u8]) {
        if m.len() < 8 || !icmpv6_ok(h.src, h.dst, m) {
            return;
        }
        self.deliver_raw6(index, h, m);
        match m[0] {
            ICMP6_ECHO_REQUEST => {
                let src = if h.dst.is_multicast() { self.source_for6(h.src, Some(index)) } else { h.dst };
                let reply = icmpv6(src, h.src, ICMP6_ECHO_REPLY, 0, m[4..8].try_into().unwrap(), &m[8..]);
                let dev = h.src.is_link_scope().then_some(index);
                let _ = self.send_ip6_dev(src, h.src, PROTO_ICMPV6, &reply, dev);
            }
            ICMP6_ECHO_REPLY => self.deliver_echo_reply6(index, h, m),
            ND_NEIGHBOR_SOLICIT if h.hop_limit == ND_HOP_LIMIT => self.receive_ns(index, h, m),
            ND_NEIGHBOR_ADVERT if h.hop_limit == ND_HOP_LIMIT => self.receive_na(index, m),
            ND_ROUTER_ADVERT if h.hop_limit == ND_HOP_LIMIT && h.src.is_link_local() => self.receive_ra(index, h, m),
            ICMP6_PACKET_TOO_BIG if m.len() >= 8 + IP6_HEADER => {
                // Remember the smaller MTU for the quoted packet's destination.
                let mtu = (get32(m, 4) as usize).max(IPV6_MIN_MTU);
                if let Some(q) = Ipv6Header::parse_quoted(&m[8..]) {
                    self.pmtu6.insert(q.dst, (mtu, self.now + 10 * 60 * 1000));
                }
                self.tcp_error6(m, super::tcp::IcmpEffect::Mtu);
                self.udp_error6(h.src, m);
            }
            ICMP6_DEST_UNREACHABLE | ICMP6_TIME_EXCEEDED if m.len() >= 8 + IP6_HEADER => {
                // Unreachable is hopeless for an attempt (RFC 4443 §3.1,
                // RFC 5927 §4.1); time exceeded is soft.
                let e = super::icmp6_error_of(m[0], m[1]);
                let effect = if m[0] == ICMP6_DEST_UNREACHABLE {
                    super::tcp::IcmpEffect::Fatal(e)
                } else {
                    super::tcp::IcmpEffect::Soft(e)
                };
                self.tcp_error6(m, effect);
                self.udp_error6(h.src, m);
            }
            _ => {}
        }
        let _ = packet;
        self.events += 1;
    }

    /// An ICMPv6 error `m` about one of this host's TCP segments.
    fn tcp_error6(&mut self, m: &[u8], effect: super::tcp::IcmpEffect) {
        let Some(q) = Ipv6Header::parse_quoted(&m[8..]) else { return };
        let t = &m[8 + IP6_HEADER..];
        if q.next != PROTO_TCP || t.len() < 8 || !self.is_local6(q.src, None) {
            return;
        }
        let (local, remote) = ((q.src.into(), get16(t, 0)), (q.dst.into(), get16(t, 2)));
        self.tcp_icmp_error(local, remote, get32(t, 4), effect);
    }

    /// Neighbour options: (type, contents) pairs (RFC 4861 §4.6).
    fn nd_options(o: &[u8]) -> Vec<(u8, &[u8])> {
        let mut out = Vec::new();
        let mut at = 0;
        while at + 2 <= o.len() {
            let len = usize::from(o[at + 1]) * 8;
            if len == 0 || at + len > o.len() {
                break;
            }
            out.push((o[at], &o[at + 2..at + len]));
            at += len;
        }
        out
    }

    fn lladdr(opts: &[(u8, &[u8])], kind: u8) -> Option<Mac> {
        opts.iter().find(|(t, v)| *t == kind && v.len() >= 6).map(|(_, v)| Mac(v[..6].try_into().unwrap()))
    }

    fn learn6(&mut self, index: IfIndex, ip: Ipv6, mac: Mac) {
        let now = self.now;
        let Some(i) = self.ifaces.get_mut(&index) else { return };
        let old = i.v6.nd.get(&ip).copied();
        if old.is_some_and(|(_, e)| e == u64::MAX) {
            return;
        }
        i.v6.nd.insert(ip, (mac, now + ND_TTL_MS));
        i.v6.resolving.remove(&ip);
        let (ready, waiting): (Vec<_>, Vec<_>) =
            core::mem::take(&mut i.v6.pending).into_iter().partition(|(hop, _)| *hop == ip);
        i.v6.pending = waiting;
        let own = i.mac;
        if old.is_none_or(|(m, _)| m != mac) {
            self.changes.push(Change::NewNeigh(super::Neighbour {
                iface: index,
                ip: ip.into(),
                mac: Some(mac),
                permanent: false,
            }));
        }
        for (_, p) in ready {
            self.emit(index, ethernet(mac, own, ETHERTYPE_IPV6, &p), None);
        }
    }

    /// A tentative address turned out to be someone else's: give it up.
    fn duplicate(&mut self, index: IfIndex, addr: Ipv6) {
        let _ = self.del_address6(index, addr);
    }

    fn receive_ns(&mut self, index: IfIndex, h: &Ipv6Header, m: &[u8]) {
        if m.len() < 24 {
            return;
        }
        let target = Ipv6(m[8..24].try_into().unwrap());
        let opts = Self::nd_options(&m[24..]);
        let Some(a) = self.v6(index).and_then(|v| v.addrs.iter().find(|a| a.addr == target)).copied() else { return };
        if a.state == AddrState::Tentative {
            // Another node probes the same address (RFC 4862 §5.4.3).
            if h.src.is_unspecified() {
                self.duplicate(index, target);
            }
            return;
        }
        if !h.src.is_unspecified()
            && let Some(mac) = Self::lladdr(&opts, OPT_SOURCE_LLADDR)
        {
            self.learn6(index, h.src, mac);
        }
        let Some(own) = self.mac(index) else { return };
        let (dst, mut flags) = if h.src.is_unspecified() { (Ipv6::ALL_NODES, 0) } else { (h.src, NA_SOLICITED) };
        flags |= NA_OVERRIDE;
        if self.forwarding6 {
            flags |= NA_ROUTER;
        }
        let mut body = Vec::from(target.0);
        body.extend_from_slice(&[OPT_TARGET_LLADDR, 1]);
        body.extend_from_slice(&own.0);
        let na = icmpv6(target, dst, ND_NEIGHBOR_ADVERT, 0, [flags, 0, 0, 0], &body);
        let p = ipv6(target, dst, PROTO_ICMPV6, ND_HOP_LIMIT, &na);
        let hw = if dst.is_multicast() {
            Some(dst.multicast_mac())
        } else {
            self.v6(index).and_then(|v| v.nd.get(&dst)).map(|(m, _)| *m)
        };
        match hw {
            Some(hw) => self.emit(index, ethernet(hw, own, ETHERTYPE_IPV6, &p), None),
            None => self.transmit6(index, dst, p),
        }
    }

    fn receive_na(&mut self, index: IfIndex, m: &[u8]) {
        if m.len() < 24 {
            return;
        }
        let target = Ipv6(m[8..24].try_into().unwrap());
        if self.v6(index).is_some_and(|v| v.addrs.iter().any(|a| a.addr == target && a.state == AddrState::Tentative)) {
            self.duplicate(index, target);
            return;
        }
        let opts = Self::nd_options(&m[24..]);
        let known = self.v6(index).is_some_and(|v| v.nd.contains_key(&target) || v.resolving.contains_key(&target));
        if known && let Some(mac) = Self::lladdr(&opts, OPT_TARGET_LLADDR) {
            self.learn6(index, target, mac);
        }
    }

    /// A router advertisement (RFC 4861 §6.3.4, RFC 4862 §5.5.3): the
    /// router as a default route, on-link prefixes as routes, autonomous
    /// /64 prefixes as addresses, the link's MTU and hop limit.
    fn receive_ra(&mut self, index: IfIndex, h: &Ipv6Header, m: &[u8]) {
        if m.len() < 16 || !self.v6(index).is_some_and(|v| v.autoconf) {
            return;
        }
        let now = self.now;
        let hop_limit = m[4];
        let lifetime = get16(m, 6);
        let opts = Self::nd_options(&m[16..]);
        if let Some(mac) = Self::lladdr(&opts, OPT_SOURCE_LLADDR) {
            self.learn6(index, h.src, mac);
        }
        let link_mtu = self.mtu(index).unwrap_or(1500);
        if let Some(v6) = self.v6_mut(index) {
            v6.rs = None; // Heard a router: no more solicitations.
            if hop_limit != 0 {
                v6.hop_limit = hop_limit;
            }
        }
        let ms = |secs: u32| (secs != INFINITE).then(|| now + u64::from(secs) * 1000);
        for (kind, v) in &opts {
            match *kind {
                OPT_MTU if v.len() >= 6 => {
                    let mtu = get32(v, 2) as usize;
                    if (IPV6_MIN_MTU..=link_mtu).contains(&mtu)
                        && let Some(v6) = self.v6_mut(index)
                    {
                        v6.mtu = Some(mtu);
                    }
                }
                OPT_PREFIX if v.len() >= 30 => {
                    let (len, flags) = (v[0], v[1]);
                    let (valid, preferred) = (get32(v, 2), get32(v, 6));
                    let prefix = Ipv6(v[14..30].try_into().unwrap()).masked(len);
                    if prefix.is_link_local() || preferred > valid || len > 128 {
                        continue;
                    }
                    if flags & PREFIX_ON_LINK != 0 {
                        let _ = self.del_route6(prefix, len, Some(index), None, Some(PREFIX_METRIC));
                        if valid != 0 {
                            let _ = self.add_route6(Route6 {
                                dst: prefix,
                                prefix_len: len,
                                gateway: None,
                                iface: index,
                                metric: PREFIX_METRIC,
                                protocol: PROTO_RA,
                                expires: ms(valid),
                            });
                        }
                    }
                    if flags & PREFIX_AUTONOMOUS != 0 && len == 64 {
                        self.slaac(index, prefix, ms(preferred), ms(valid), valid == 0);
                    }
                }
                _ => {}
            }
        }
        // The router itself (lifetime 0: it is not a default router).
        let _ = self.del_route6(Ipv6::UNSPECIFIED, 0, Some(index), Some(h.src), None);
        if lifetime != 0 {
            let _ = self.add_route6(Route6 {
                dst: Ipv6::UNSPECIFIED,
                prefix_len: 0,
                gateway: Some(h.src),
                iface: index,
                metric: ROUTER_METRIC,
                protocol: PROTO_RA,
                expires: Some(now + u64::from(lifetime) * 1000),
            });
        }
    }

    /// An address from an autonomous prefix: new, or its lifetimes renewed.
    fn slaac(&mut self, index: IfIndex, prefix: Ipv6, preferred: Option<u64>, valid: Option<u64>, gone: bool) {
        let Some(mac) = self.mac(index) else { return };
        let addr = Ipv6::with_interface_id(prefix, Ipv6::eui64(mac));
        let now = self.now;
        let existing = self.v6_mut(index).and_then(|v| v.addrs.iter_mut().find(|a| a.addr == addr));
        match existing {
            Some(a) => {
                if gone {
                    // RFC 4862 §5.5.3 e) keeps at least two hours against
                    // spoofed advertisements; a zero lifetime ends it sooner
                    // than that only for addresses that would lapse anyway.
                    a.valid_until = Some(a.valid_until.unwrap_or(u64::MAX).min(now + 2 * 3600 * 1000));
                } else {
                    a.preferred_until = preferred;
                    a.valid_until = valid;
                    if a.state == AddrState::Deprecated {
                        a.state = AddrState::Preferred;
                    }
                }
            }
            None if !gone => {
                let _ = self.add_address6_with(index, addr, 64, AddrOrigin::Slaac, preferred, valid);
            }
            None => {}
        }
    }

    /// Run the IPv6 timers of one interface: duplicate address detection,
    /// router solicitations, address resolution, lifetimes.
    pub(super) fn timers6(&mut self, index: IfIndex, now: u64) -> Option<u64> {
        let mut next: Option<u64> = None;
        let mut soonest = |t: u64| next = Some(next.map_or(t, |n: u64| n.min(t)));
        let (done, rs_due, ask, expired, lapsed): Due6 = {
            let v6 = &mut self.ifaces.get_mut(&index)?.v6;
            let done: Vec<Ipv6> = v6.dad.iter().filter(|(_, t)| now >= *t + RETRANS_MS).map(|(a, _)| *a).collect();
            for t in v6.dad.values() {
                soonest(t + RETRANS_MS);
            }
            let tentative = !v6.dad.is_empty();
            let mut rs_due = false;
            if let Some((t, sent)) = v6.rs {
                if sent >= RS_MAX {
                    v6.rs = None;
                } else if now >= t && !tentative {
                    rs_due = true;
                    v6.rs = Some((now + RS_INTERVAL_MS, sent + 1));
                    soonest(now + RS_INTERVAL_MS);
                } else {
                    soonest(t.max(now + 1));
                }
            }
            let mut ask = Vec::new();
            let due: Vec<Ipv6> =
                v6.resolving.iter().filter(|(_, (t, _))| now >= t + RETRANS_MS).map(|(ip, _)| *ip).collect();
            for ip in due {
                let tries = v6.resolving[&ip].1;
                if tries >= ND_TRIES {
                    v6.resolving.remove(&ip);
                    v6.pending.retain(|(hop, _)| *hop != ip);
                } else {
                    v6.resolving.insert(ip, (now, tries + 1));
                    ask.push(ip);
                }
            }
            for (t, _) in v6.resolving.values() {
                soonest(t + RETRANS_MS);
            }
            let expired: Vec<(Ipv6, Mac)> =
                v6.nd.iter().filter(|(_, (_, e))| *e <= now).map(|(ip, (m, _))| (*ip, *m)).collect();
            for (ip, _) in &expired {
                v6.nd.remove(ip);
            }
            let mut lapsed = Vec::new();
            for a in v6.addrs.iter_mut() {
                if a.valid_until.is_some_and(|t| now >= t) {
                    lapsed.push(a.addr);
                } else if a.state == AddrState::Preferred && a.preferred_until.is_some_and(|t| now >= t) {
                    a.state = AddrState::Deprecated;
                }
                for t in [a.valid_until, a.preferred_until].into_iter().flatten() {
                    if t > now {
                        soonest(t);
                    }
                }
            }
            (done, rs_due, ask, expired, lapsed)
        };
        for a in done {
            if let Some(v6) = self.v6_mut(index) {
                v6.dad.remove(&a);
                if let Some(x) = v6.addrs.iter_mut().find(|x| x.addr == a) {
                    x.state = if x.preferred_until.is_some_and(|t| now >= t) {
                        AddrState::Deprecated
                    } else {
                        AddrState::Preferred
                    };
                    let x = *x;
                    self.changes.push(Change::NewAddr6(index, x));
                    self.events += 1;
                }
            }
        }
        if rs_due {
            self.send_rs(index);
        }
        for ip in ask {
            self.solicit(index, ip);
        }
        for (ip, mac) in expired {
            self.changes.push(Change::DelNeigh(super::Neighbour {
                iface: index,
                ip: ip.into(),
                mac: Some(mac),
                permanent: false,
            }));
        }
        for a in lapsed {
            let _ = self.del_address6(index, a);
        }
        next
    }

    /// Routes from router advertisements whose lifetime ended go.
    pub(super) fn expire_routes6(&mut self, now: u64) -> Option<u64> {
        let gone: Vec<Route6> = self.routes6.iter().filter(|r| r.expires.is_some_and(|t| now >= t)).copied().collect();
        self.routes6.retain(|r| !gone.contains(r));
        self.changes.extend(gone.into_iter().map(Change::DelRoute6));
        self.pmtu6.retain(|_, (_, t)| *t > now);
        self.pmtu4.retain(|_, (_, t)| *t > now);
        self.reassembly6.retain(|_, r| r.deadline > now);
        self.routes6.iter().filter_map(|r| r.expires).min()
    }

    // --- neighbours set by hand -------------------------------------------------

    pub(super) fn add_neighbour6(&mut self, index: IfIndex, ip: Ipv6, mac: Mac) -> Result<()> {
        if ip.is_unspecified() || ip.is_multicast() || index == LOOPBACK {
            return Err(Error::InvalidInput);
        }
        let i = self.iface_mut(index)?;
        i.v6.nd.insert(ip, (mac, u64::MAX));
        self.changes.push(Change::NewNeigh(super::Neighbour {
            iface: index,
            ip: ip.into(),
            mac: Some(mac),
            permanent: true,
        }));
        self.learn_flush6(index, ip, mac);
        self.events += 1;
        Ok(())
    }

    fn learn_flush6(&mut self, index: IfIndex, ip: Ipv6, mac: Mac) {
        let Some(i) = self.ifaces.get_mut(&index) else { return };
        i.v6.resolving.remove(&ip);
        let (ready, waiting): (Vec<_>, Vec<_>) =
            core::mem::take(&mut i.v6.pending).into_iter().partition(|(hop, _)| *hop == ip);
        i.v6.pending = waiting;
        let own = i.mac;
        for (_, p) in ready {
            self.emit(index, ethernet(mac, own, ETHERTYPE_IPV6, &p), None);
        }
    }

    pub(super) fn del_neighbour6(&mut self, index: IfIndex, ip: Ipv6) -> Result<()> {
        let i = self.iface_mut(index)?;
        let (mac, exp) = i.v6.nd.remove(&ip).ok_or(Error::NotFound)?;
        self.changes.push(Change::DelNeigh(super::Neighbour {
            iface: index,
            ip: ip.into(),
            mac: Some(mac),
            permanent: exp == u64::MAX,
        }));
        Ok(())
    }

    // --- forwarding and fragments ------------------------------------------------

    /// Forward a packet for another host (RFC 8200 §3, RFC 4443 errors).
    fn forward6(&mut self, from: IfIndex, h: &Ipv6Header, packet: &[u8], mut conn: super::filter::Conn) {
        if h.hop_limit <= 1 {
            self.icmp6_error(h, packet, ICMP6_TIME_EXCEEDED, 0, [0; 4]);
            return;
        }
        let Some(r) = self.lookup6(h.dst, None) else {
            self.icmp6_error(h, packet, ICMP6_DEST_UNREACHABLE, ICMP6_NO_ROUTE, [0; 4]);
            return;
        };
        // Postrouting may give it a new source (NAT); errors to the sender
        // quote it as it came.
        let mut p = packet.to_vec();
        if self.filtering()
            && (!self.arriving(super::filter::NF_INET_FORWARD, &mut p, from, Some(r.iface), &mut conn)
                || self.filter(super::filter::NF_INET_POST_ROUTING, &mut p, None, Some(r.iface), &mut conn)
                    != slate_nft::Outcome::Accept)
        {
            return;
        }
        let mtu = self.ifaces.get(&r.iface).map_or(IPV6_MIN_MTU, |i| i.v6.mtu.unwrap_or(i.mtu).min(i.mtu));
        if packet.len() > mtu {
            // Routers never fragment IPv6 (RFC 8200 §5).
            self.icmp6_error(h, packet, ICMP6_PACKET_TOO_BIG, 0, (mtu as u32).to_be_bytes());
            return;
        }
        p[7] -= 1;
        self.transmit6(r.iface, r.gateway.unwrap_or(h.dst), p);
    }

    /// Add a fragment (its header at `at`); the whole packet once every
    /// piece is in (RFC 8200 §4.5).
    fn reassemble6(&mut self, h: &Ipv6Header, packet: &[u8], at: usize) -> Option<Vec<u8>> {
        if at + 8 > packet.len() {
            return None;
        }
        let next = packet[at];
        let off_flags = get16(packet, at + 2);
        let offset = usize::from(off_flags & !7);
        let more = off_flags & 1 != 0;
        let id = get32(packet, at + 4);
        let data = &packet[at + 8..];
        if more && data.len() % 8 != 0 {
            return None;
        }
        let key = (h.src, h.dst, id);
        let pending: usize = self.reassembly6.values().map(|r| r.bytes).sum();
        if pending + data.len() > REASSEMBLY_BYTES && !self.reassembly6.contains_key(&key) {
            return None;
        }
        let now = self.now;
        let r = self.reassembly6.entry(key).or_insert_with(|| Reassembly6 {
            next,
            pieces: BTreeMap::new(),
            total: None,
            bytes: 0,
            deadline: now + REASSEMBLY_MS,
        });
        if offset == 0 {
            r.next = next;
        }
        if !more {
            r.total = Some(offset + data.len());
        }
        if r.pieces.insert(offset, data.to_vec()).is_none() {
            r.bytes += data.len();
        }
        let total = r.total?;
        let mut have = 0;
        for (o, d) in &r.pieces {
            if *o > have {
                return None; // A hole.
            }
            have = have.max(o + d.len());
        }
        if have < total || total > usize::from(u16::MAX) {
            return None;
        }
        let r = self.reassembly6.remove(&key)?;
        let mut payload = alloc::vec![0u8; total];
        for (o, d) in r.pieces {
            let end = (o + d.len()).min(total);
            payload[o..end].copy_from_slice(&d[..end - o]);
        }
        Some(ipv6(h.src, h.dst, r.next, h.hop_limit, &payload))
    }
}

/// What an interface's IPv6 timers found due: addresses done with
/// duplicate detection, whether to solicit routers, addresses to solicit
/// again, expired neighbours, lapsed addresses.
type Due6 = (Vec<Ipv6>, bool, Vec<Ipv6>, Vec<(Ipv6, Mac)>, Vec<Ipv6>);

/// Whether an ICMPv6 message is neighbour discovery (sent with hop limit 255).
fn is_nd(m: &[u8]) -> bool {
    matches!(m.first(), Some(&(ND_ROUTER_SOLICIT..=ND_NEIGHBOR_ADVERT)))
}

/// Split a packet into fragments that fit `mtu` (RFC 8200 §4.5): each
/// with a fragment header, data in multiples of eight bytes.
fn fragment6(src: Ipv6, dst: Ipv6, next: u8, hop: u8, payload: &[u8], mtu: usize, id: u32) -> Vec<Vec<u8>> {
    let room = (mtu - IP6_HEADER - 8) / 8 * 8;
    let mut out = Vec::new();
    let mut at = 0;
    while at < payload.len() {
        let end = (at + room).min(payload.len());
        let more = end < payload.len();
        let mut f = Vec::with_capacity(8 + end - at);
        f.extend_from_slice(&[next, 0]);
        f.extend_from_slice(&((at as u16) | u16::from(more)).to_be_bytes());
        f.extend_from_slice(&id.to_be_bytes());
        f.extend_from_slice(&payload[at..end]);
        out.push(ipv6(src, dst, NEXT_FRAGMENT, hop, &f));
        at = end;
    }
    out
}

impl Ipv6Header {
    /// A header quoted in an ICMPv6 error (its payload may be cut short).
    pub fn parse_quoted(b: &[u8]) -> Option<Ipv6Header> {
        if b.len() < IP6_HEADER || b[0] >> 4 != 6 {
            return None;
        }
        Some(Ipv6Header {
            payload_len: usize::from(get16(b, 4)),
            next: b[6],
            hop_limit: b[7],
            src: Ipv6(b[8..24].try_into().unwrap()),
            dst: Ipv6(b[24..40].try_into().unwrap()),
            tclass: (b[0] << 4) | (b[1] >> 4),
        })
    }
}

/// Whether an IPv6 packet carries a fragment header (past its other
/// extension headers).
fn has_fragment_header(p: &[u8]) -> bool {
    let (mut next, mut at) = (p.get(6).copied().unwrap_or(0), IP6_HEADER);
    loop {
        match next {
            NEXT_FRAGMENT => return true,
            NEXT_HOP_BY_HOP | NEXT_DEST_OPTS | NEXT_ROUTING => {
                let (Some(&n), Some(&len)) = (p.get(at), p.get(at + 1)) else { return false };
                next = n;
                at += (usize::from(len) + 1) * 8;
            }
            _ => return false,
        }
    }
}
