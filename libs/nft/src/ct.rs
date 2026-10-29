// SPDX-License-Identifier: MIT OR Apache-2.0

//! Connection tracking for `ct state` and NAT (nft(8); the states of
//! nf_conntrack_common.h, ADRs 0128 and 0132): flows by their addresses,
//! protocol and ports (an ICMP echo's identifier for both ports), each
//! direction seen. A flow's first packet is new, any packet once the other
//! side has answered established; an ICMP error about a known flow is
//! related; a TCP reset that belongs to nothing is invalid. Flows end
//! after their protocol's quiet time.
//!
//! Each flow knows what its replies look like: the first packet's tuple
//! reversed, until NAT changes it (a new source makes replies come back
//! to it, a new destination makes them come from it). Replies are found
//! by that tuple. A packet is tracked once, at the first hook it meets,
//! and carries what it was found to be (`Tracked`) through the others.

use alloc::collections::BTreeMap;

use crate::consts::*;
use crate::nat::{Endpoint, Rewrite};

/// What tracking says about a packet: its state bit (`ct state`) and
/// whether it goes the flow's reply way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtInfo {
    pub state: u32,
    pub reply: bool,
    /// NAT changed the connection's source, its destination (as
    /// iptables' conntrack match asks: SNAT, DNAT).
    pub snat: bool,
    pub dnat: bool,
}

/// A packet's connection, carried from hook to hook: what tracking said,
/// and which flow it belongs to (none if untracked or invalid).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tracked {
    pub info: CtInfo,
    key: Option<Tuple>,
    /// An ICMP error about the flow, quoting one of its packets.
    related: bool,
}

/// One direction of a flow: protocol, source, destination (addresses as
/// 16 bytes, IPv4 in the first four) and their ports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Tuple {
    v6: bool,
    proto: u8,
    src: [u8; 16],
    dst: [u8; 16],
    sport: u16,
    dport: u16,
}

impl Tuple {
    fn reversed(&self) -> Tuple {
        Tuple { src: self.dst, dst: self.src, sport: self.dport, dport: self.sport, ..*self }
    }
    /// With the echo reply marker taken off the protocol.
    fn plain(&self) -> Tuple {
        Tuple { proto: self.proto & 0x7F, ..*self }
    }
}

#[derive(Clone, Copy, Debug)]
struct Flow {
    /// The other side has answered.
    replied: bool,
    /// A FIN went each way, or a reset: the connection is closing.
    closing: bool,
    expires: u64,
    /// What its replies look like.
    reply: Tuple,
    /// Where source NAT took the source, and destination NAT the
    /// destination (none: left alone).
    snat: Option<Endpoint>,
    dnat: Option<Endpoint>,
    /// Whether each translation was decided (by the nat chains, for the
    /// first packet).
    src_done: bool,
    dst_done: bool,
}

/// Where NAT takes a flow's source or destination: an address, and a port
/// from `ports` (or the flow's own, if free).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub addr: [u8; 16],
    pub ports: Option<(u16, u16)>,
    /// Pick the port at random in the range rather than the first free.
    pub random: bool,
}

/// The most flows tracked at once; past it, new flows go untracked.
const MAX_FLOWS: usize = 65_536;

// How long a quiet flow lasts (milliseconds; Linux's defaults, observed in
// /proc/sys/net/netfilter on the host).
const TCP_ESTABLISHED_MS: u64 = 432_000_000;
const TCP_OPENING_MS: u64 = 120_000;
const TCP_CLOSING_MS: u64 = 10_000;
const UDP_MS: u64 = 30_000;
const UDP_REPLIED_MS: u64 = 120_000;
const ICMP_MS: u64 = 30_000;
const OTHER_MS: u64 = 600_000;

const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;

/// The connections of one network namespace.
#[derive(Clone, Debug, Default)]
pub struct Conntrack {
    /// Each flow under its original direction.
    flows: BTreeMap<Tuple, Flow>,
    /// Each flow's reply tuple, to the flow.
    replies: BTreeMap<Tuple, Tuple>,
}

/// An echo request's type and its reply's, per family.
fn echo_pair(v6: bool) -> (u8, u8) {
    if v6 { (128, 129) } else { (8, 0) }
}

/// Whether ICMP type `t` is an error (destination unreachable, packet too
/// big, time exceeded, parameter problem).
fn icmp_error(v6: bool, t: u8) -> bool {
    if v6 { t < 128 } else { matches!(t, 3 | 11 | 12) }
}

/// The addresses of an IP header (and where they are).
fn addresses(v6: bool, net: &[u8]) -> Option<([u8; 16], [u8; 16])> {
    let (mut s, mut d) = ([0u8; 16], [0u8; 16]);
    if v6 {
        s.copy_from_slice(net.get(8..24)?);
        d.copy_from_slice(net.get(24..40)?);
    } else {
        s[..4].copy_from_slice(net.get(12..16)?);
        d[..4].copy_from_slice(net.get(16..20)?);
    }
    Some((s, d))
}

/// A packet's tuple, and for an ICMP error the tuple of what it quotes.
fn tuple(v6: bool, net: &[u8], l4: Option<(u8, usize)>) -> Option<(Tuple, Option<Tuple>)> {
    let (proto, at) = l4?;
    let (src, dst) = addresses(v6, net)?;
    let t = net.get(at..)?;
    let port = |i: usize| t.get(i..i + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    let mut tu = Tuple { v6, proto, src, dst, sport: 0, dport: 0 };
    match proto {
        PROTO_TCP | PROTO_UDP => {
            (tu.sport, tu.dport) = (port(0)?, port(2)?);
        }
        PROTO_ICMP | PROTO_ICMPV6 => {
            let kind = *t.first()?;
            if icmp_error(v6, kind) {
                // The quoted packet: its own header, then 8 bytes at least.
                let inner = t.get(8..)?;
                let (ihl, iproto) =
                    if v6 { (40, *inner.get(6)?) } else { (usize::from(*inner.first()? & 0xF) * 4, *inner.get(9)?) };
                let quoted = tuple(v6, inner, Some((iproto, ihl))).map(|q| q.0);
                return Some((tu, quoted));
            }
            let (request, reply) = echo_pair(v6);
            if kind == request || kind == reply {
                // The identifier stands for both ports; a reply is the
                // request's reverse.
                let id = port(4)?;
                (tu.sport, tu.dport) = (id, id);
                tu.proto = if kind == reply { proto | 0x80 } else { proto };
            }
        }
        _ => {}
    }
    Some((tu, None))
}

/// How long a flow lasts quiet now.
fn quiet_time(proto: u8, f: &Flow) -> u64 {
    match proto & 0x7F {
        PROTO_TCP if f.closing => TCP_CLOSING_MS,
        PROTO_TCP if f.replied => TCP_ESTABLISHED_MS,
        PROTO_TCP => TCP_OPENING_MS,
        PROTO_UDP if f.replied => UDP_REPLIED_MS,
        PROTO_UDP => UDP_MS,
        PROTO_ICMP | PROTO_ICMPV6 => ICMP_MS,
        _ => OTHER_MS,
    }
}

impl Conntrack {
    /// A flow's key and whether `t` goes its reply way: replies of an
    /// echo are filed under the request's protocol.
    fn find(&self, t: &Tuple) -> Option<(Tuple, bool)> {
        let plain = t.plain();
        if t.proto & 0x80 == 0 && self.flows.contains_key(&plain) {
            return Some((plain, false));
        }
        self.replies.get(&plain).map(|k| (*k, true))
    }

    fn insert(&mut self, key: Tuple, f: Flow) {
        self.replies.insert(f.reply, key);
        self.flows.insert(key, f);
    }

    fn remove(&mut self, key: &Tuple) {
        if let Some(f) = self.flows.remove(key)
            && self.replies.get(&f.reply) == Some(key)
        {
            self.replies.remove(&f.reply);
        }
    }

    fn expire(&mut self, now: u64) {
        let gone: alloc::vec::Vec<Tuple> =
            self.flows.iter().filter(|(_, f)| f.expires <= now).map(|(k, _)| *k).collect();
        for k in gone {
            self.remove(&k);
        }
    }

    fn handle(info: CtInfo, key: Option<Tuple>, related: bool) -> Tracked {
        Tracked { info, key, related }
    }

    /// Track a packet as the first hook it meets sees it.
    pub fn track(&mut self, v6: bool, net: &[u8], l4: Option<(u8, usize)>, now: u64) -> Option<Tracked> {
        let (t, quoted) = tuple(v6, net, l4)?;
        if let Some(q) = quoted {
            return Some(self.related(&q, now));
        }
        let flags = (t.proto == PROTO_TCP).then(|| net.get(l4?.1 + 13).copied()).flatten().unwrap_or(0);
        let (rst, fin) = (flags & 0x04 != 0, flags & 0x01 != 0);
        if let Some((key, reply)) = self.find(&t) {
            let f = self.flows.get_mut(&key).unwrap();
            if f.expires <= now {
                self.remove(&key);
                return self.track(v6, net, l4, now);
            }
            f.replied |= reply;
            f.closing |= rst || fin;
            f.expires = now + quiet_time(t.proto, f);
            let state = if f.replied { NF_CT_STATE_ESTABLISHED } else { NF_CT_STATE_NEW };
            let (snat, dnat) = (f.snat.is_some(), f.dnat.is_some());
            return Some(Self::handle(CtInfo { state, reply, snat, dnat }, Some(key), false));
        }
        // A reset, or an echo reply, that belongs to no flow is invalid.
        if (t.proto == PROTO_TCP && rst) || t.proto & 0x80 != 0 {
            return Some(Self::handle(
                CtInfo { state: NF_CT_STATE_INVALID_BIT, reply: false, snat: false, dnat: false },
                None,
                false,
            ));
        }
        if self.flows.len() >= MAX_FLOWS {
            self.expire(now);
            if self.flows.len() >= MAX_FLOWS {
                return Some(Self::handle(
                    CtInfo { state: NF_CT_STATE_UNTRACKED_BIT, reply: false, snat: false, dnat: false },
                    None,
                    false,
                ));
            }
        }
        let mut f = Flow {
            replied: false,
            closing: rst || fin,
            expires: 0,
            reply: t.reversed(),
            snat: None,
            dnat: None,
            src_done: false,
            dst_done: false,
        };
        f.expires = now + quiet_time(t.proto, &f);
        // A tuple that is some other flow's reply already (NAT took its
        // place): this one's replies can't be told apart; it goes as it is.
        if self.replies.contains_key(&f.reply) {
            return Some(Self::handle(
                CtInfo { state: NF_CT_STATE_NEW, reply: false, snat: false, dnat: false },
                None,
                false,
            ));
        }
        self.insert(t, f);
        Some(Self::handle(CtInfo { state: NF_CT_STATE_NEW, reply: false, snat: false, dnat: false }, Some(t), false))
    }

    /// What tracking says without changing anything (a later hook of a
    /// packet that wasn't carried through).
    pub fn lookup(&self, v6: bool, net: &[u8], l4: Option<(u8, usize)>, now: u64) -> Option<CtInfo> {
        let (t, quoted) = tuple(v6, net, l4)?;
        if let Some(q) = quoted {
            let state = if self.quoted_flow(&q, now).is_some() { NF_CT_STATE_RELATED } else { NF_CT_STATE_INVALID_BIT };
            return Some(CtInfo { state, reply: false, snat: false, dnat: false });
        }
        match self.find(&t) {
            Some((k, reply)) if self.flows[&k].expires > now => {
                let state = if self.flows[&k].replied { NF_CT_STATE_ESTABLISHED } else { NF_CT_STATE_NEW };
                Some(CtInfo { state, reply, snat: false, dnat: false })
            }
            _ => Some(CtInfo { state: NF_CT_STATE_NEW, reply: false, snat: false, dnat: false }),
        }
    }

    /// The live flow a quoted packet belongs to, and whether the quoted
    /// packet went its reply way. The quote may show it before or after
    /// NAT changed it, so both its tuple and its reverse are looked for.
    fn quoted_flow(&self, q: &Tuple, now: u64) -> Option<(Tuple, bool)> {
        let live = |k: &Tuple| self.flows.get(k).is_some_and(|f| f.expires > now);
        if let Some((k, reply)) = self.find(q).filter(|(k, _)| live(k)) {
            return Some((k, reply));
        }
        // The reverse of a reply is the original as it went out, and the
        // reverse of an original is a reply as it came back.
        let r = q.reversed();
        if let Some(k) = self.replies.get(&r.plain()).filter(|k| live(k)) {
            return Some((*k, false));
        }
        self.flows.contains_key(&r.plain()).then_some((r.plain(), true)).filter(|(k, _)| live(k))
    }

    /// An ICMP error quoting `q`: related to its flow, if there is one,
    /// going the other way from the packet it quotes.
    fn related(&self, q: &Tuple, now: u64) -> Tracked {
        match self.quoted_flow(q, now) {
            Some((k, reply)) => Self::handle(
                CtInfo { state: NF_CT_STATE_RELATED, reply: !reply, snat: false, dnat: false },
                Some(k),
                true,
            ),
            None => Self::handle(
                CtInfo { state: NF_CT_STATE_INVALID_BIT, reply: false, snat: false, dnat: false },
                None,
                false,
            ),
        }
    }

    /// Whether the source (`src`) or destination translation of the
    /// packet's flow is still to be decided: only for a flow's first
    /// packet going the original way.
    pub fn undecided(&self, tr: &Tracked, src: bool) -> bool {
        if tr.info.reply || tr.related {
            return false;
        }
        tr.key.and_then(|k| self.flows.get(&k)).is_some_and(|f| if src { !f.src_done } else { !f.dst_done })
    }

    /// Decide the flow's source (`src`) or destination translation: to
    /// `to`, or none. The port is the flow's own when it is in the range
    /// and keeps the flow's replies apart from every other flow's, else
    /// the first (or a random) one in the range that does; without a
    /// range, the flow's own or one from the same band (below 1024 or
    /// not). False when no port is free: the packet is dropped, as Linux
    /// drops one whose translation would clash.
    pub fn bind(&mut self, tr: &Tracked, src: bool, to: Option<Target>, seed: u32) -> bool {
        let Some(key) = tr.key else { return true };
        let Some(mut f) = self.flows.get(&key).copied() else { return true };
        if src {
            f.src_done = true;
        } else {
            f.dst_done = true;
        }
        if let Some(to) = to {
            let mut reply = f.reply;
            let own = if src { key.sport } else { key.dport };
            if src {
                reply.dst = to.addr;
            } else {
                reply.src = to.addr;
            }
            let with = |mut r: Tuple, p: u16| {
                if src {
                    r.dport = p;
                } else {
                    r.sport = p;
                }
                r
            };
            let free = |p: u16| self.replies.get(&with(reply, p)).is_none_or(|k| *k == key);
            let has_ports = matches!(key.proto, PROTO_TCP | PROTO_UDP);
            let (lo, hi) = to.ports.unwrap_or(if own < 1024 { (1, 1023) } else { (1024, 65535) });
            // Its own port, when it may keep it.
            let keep = (own >= lo && own <= hi && !to.random) || to.ports.is_none();
            let port = if !has_ports || (keep && free(own)) {
                own
            } else {
                let span = u32::from(hi - lo) + 1;
                let start = if to.random { seed % span } else { 0 };
                match (0..span).map(|i| lo + ((start + i) % span) as u16).find(|p| free(*p)) {
                    Some(p) => p,
                    None => return false,
                }
            };
            reply = with(reply, port);
            if src {
                f.snat = Some((to.addr, port));
            } else {
                f.dnat = Some((to.addr, port));
            }
            if self.replies.get(&f.reply) == Some(&key) {
                self.replies.remove(&f.reply);
            }
            f.reply = reply;
            self.replies.insert(reply, key);
        }
        self.flows.insert(key, f);
        true
    }

    /// How NAT changes this packet at a hook that changes sources (`src`:
    /// postrouting, input) or destinations (prerouting, output): the
    /// original way, to the translation; the reply way, back from the
    /// other one.
    pub fn manip(&self, tr: &Tracked, src: bool) -> Option<Rewrite> {
        let key = tr.key?;
        let f = self.flows.get(&key)?;
        let back = |a: [u8; 16], p: u16| Some((a, p));
        match (src, tr.info.reply) {
            (true, false) => f.snat.map(|e| Rewrite { src: Some(e), dst: None }),
            (true, true) => f.dnat.and(back(key.dst, key.dport)).map(|e| Rewrite { src: Some(e), dst: None }),
            (false, false) => f.dnat.map(|e| Rewrite { src: None, dst: Some(e) }),
            (false, true) => f.snat.and(back(key.src, key.sport)).map(|e| Rewrite { src: None, dst: Some(e) }),
        }
    }

    /// Whether `tr` is an ICMP error about its flow.
    pub fn is_related(tr: &Tracked) -> bool {
        tr.related
    }

    /// A seed for random port choices: the flow's tuple, mixed.
    pub fn seed(tr: &Tracked) -> u32 {
        let Some(k) = tr.key else { return 0 };
        let mut h: u32 = 0x811C_9DC5;
        for b in
            k.src.iter().chain(k.dst.iter()).chain(k.sport.to_be_bytes().iter()).chain(k.dport.to_be_bytes().iter())
        {
            h = (h ^ u32::from(*b)).wrapping_mul(0x0100_0193);
        }
        h
    }

    /// Forget every flow (the ruleset that needed them went).
    pub fn clear(&mut self) {
        self.flows.clear();
        self.replies.clear();
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}
