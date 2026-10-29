// SPDX-License-Identifier: MIT OR Apache-2.0

//! The firewall's hooks (nf_tables, ADR 0129): every IPv4 and IPv6 packet
//! meets the namespace's ruleset where Linux's netfilter hooks are:
//! prerouting as it arrives (whole: fragments are put back together
//! first), input when it is for this host, forward when routed through,
//! output when this host makes it, postrouting as it leaves. An empty
//! ruleset costs one check.
//!
//! A packet is tracked at the first hook it meets and carries its
//! connection (`Conn`) through the others, looped-back packets too. NAT
//! (ADR 0132) may rewrite it at prerouting and output (its destination:
//! the caller routes it by the new one) and at postrouting and input (its
//! source).

use super::*;
use slate_nft::{Iface as Seen, Outcome, Packet, Reject};

/// A packet's connection, carried from hook to hook (none until a hook
/// tracks it, or when nothing is tracked).
pub(super) type Conn = Option<slate_nft::Tracked>;

pub(super) use slate_nft::consts::{
    NF_INET_FORWARD, NF_INET_LOCAL_IN, NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING, NF_INET_PRE_ROUTING,
};

/// ARPHRD types (musl `net/if_arp.h`): Ethernet and loopback.
const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;

/// Where a packet's transport header starts, past IPv6's extension
/// headers; none for a fragment after the first.
fn transport(net: &[u8]) -> Option<(u8, usize)> {
    if net.first()? >> 4 == 4 {
        let frag = u16::from_be_bytes([*net.get(6)?, *net.get(7)?]);
        return (frag & 0x1FFF == 0).then(|| (net[9], usize::from(net[0] & 0xF) * 4));
    }
    let (mut next, mut at) = (*net.get(6)?, IP6_HEADER);
    loop {
        match next {
            NEXT_HOP_BY_HOP | NEXT_DEST_OPTS | NEXT_ROUTING => {
                next = *net.get(at)?;
                at += (usize::from(*net.get(at + 1)?) + 1) * 8;
            }
            NEXT_FRAGMENT => {
                // The first piece has the transport header after it.
                let first = u16::from_be_bytes([*net.get(at + 2)?, *net.get(at + 3)?]) & !7 == 0;
                if !first {
                    return None;
                }
                next = *net.get(at)?;
                at += 8;
            }
            _ => return (at <= net.len()).then_some((next, at)),
        }
    }
}

/// How the rules see interface `i` named `n`.
fn seen(i: Option<IfIndex>, n: &Option<([u8; 15], usize)>) -> Option<Seen<'_>> {
    let (i, (bytes, len)) = (i?, n.as_ref()?);
    Some(Seen { index: i, name: &bytes[..*len], kind: if i == LOOPBACK { ARPHRD_LOOPBACK } else { ARPHRD_ETHER } })
}

impl Stack {
    /// Name an interface, as the rules match it (`iifname`, `oifname`).
    pub fn set_ifname(&mut self, index: IfIndex, name: &[u8]) -> Result<()> {
        self.iface_mut(index)?.name = name.iter().take(15).copied().collect();
        Ok(())
    }

    /// Whether any rules are loaded (the hooks have something to do).
    pub(super) fn filtering(&self) -> bool {
        !self.firewall.tables.is_empty()
    }

    /// This host's address for NAT to use at `hook`: the arriving
    /// interface's (redirect), or the one it sends from out of the leaving
    /// interface towards the packet's destination (masquerade).
    fn nat_address(&self, hook: u32, net: &[u8], iif: Option<IfIndex>, oif: Option<IfIndex>) -> Option<[u8; 16]> {
        let mut a = [0u8; 16];
        let v6 = net[0] >> 4 == 6;
        let (index, leaving) = match hook {
            NF_INET_PRE_ROUTING | NF_INET_LOCAL_IN => (iif?, false),
            _ => (oif?, true),
        };
        if v6 {
            let dst = Ipv6(net.get(24..40)?.try_into().ok()?);
            let src = if leaving {
                self.source_for6(dst, Some(index))
            } else {
                self.v6(index)?.addrs.iter().find(|x| !x.addr.is_link_local()).or(self.v6(index)?.addrs.first())?.addr
            };
            if src.is_unspecified() {
                return None;
            }
            a.copy_from_slice(&src.0);
        } else {
            let i = self.ifaces.get(&index)?;
            let src = if leaving { i.source_towards(ip_at(net, 16))? } else { i.addrs.first()?.addr };
            a[..4].copy_from_slice(&src.0);
        }
        Some(a)
    }

    /// The type of address `a` as xtables' addrtype match names it: this
    /// host's own (loopback's too), a broadcast, multicast, unspecified, or
    /// anyone's (unicast).
    fn address_type(&self, a: &[u8]) -> u16 {
        use slate_nft::compat::*;
        if a.len() == 16 {
            let ip = Ipv6(a.try_into().unwrap());
            return if ip.is_unspecified() {
                XT_ADDRTYPE_UNSPEC
            } else if ip.is_multicast() {
                XT_ADDRTYPE_MULTICAST
            } else if ip.is_loopback() || self.is_local6(ip, None) {
                XT_ADDRTYPE_LOCAL
            } else {
                XT_ADDRTYPE_UNICAST
            };
        }
        let ip = Ipv4(a.try_into().unwrap());
        if ip.is_unspecified() {
            XT_ADDRTYPE_UNSPEC
        } else if ip.is_loopback() || self.is_local(ip) {
            XT_ADDRTYPE_LOCAL
        } else if ip == Ipv4::BROADCAST || self.ifaces.keys().any(|i| self.is_broadcast_on(*i, ip)) {
            XT_ADDRTYPE_BROADCAST
        } else if ip.is_multicast() {
            XT_ADDRTYPE_MULTICAST
        } else {
            XT_ADDRTYPE_UNICAST
        }
    }

    /// Pass `net` (a whole IPv4 or IPv6 packet) through `hook`, having come
    /// in on `iif` or going out of `oif`, with its connection `conn`. NAT
    /// may rewrite it.
    pub(super) fn filter(
        &mut self,
        hook: u32,
        net: &mut [u8],
        iif: Option<IfIndex>,
        oif: Option<IfIndex>,
        conn: &mut Conn,
    ) -> Outcome {
        if !self.filtering() || net.is_empty() {
            return Outcome::Accept;
        }
        let name = |s: &Stack, i: IfIndex| -> ([u8; 15], usize) {
            let mut n = [0u8; 15];
            let src = s.ifaces.get(&i).map_or(&[][..], |f| f.name.as_slice());
            n[..src.len()].copy_from_slice(src);
            (n, src.len())
        };
        let (iname, oname) = (iif.map(|i| name(self, i)), oif.map(|i| name(self, i)));
        let ll = self.arriving_ll.filter(|_| matches!(hook, NF_INET_PRE_ROUTING | NF_INET_LOCAL_IN | NF_INET_FORWARD));
        let v6 = net[0] >> 4 == 6;
        let local = if self.firewall.has_nat(v6) { self.nat_address(hook, net, iif, oif) } else { None };
        let types = if self.firewall.uses_addrtype() {
            let (s, d) = if v6 { (8..24, 24..40) } else { (12..16, 16..20) };
            match (net.get(s), net.get(d)) {
                (Some(s), Some(d)) => (self.address_type(s), self.address_type(d)),
                _ => (0, 0),
            }
        } else {
            (0, 0)
        };
        // `process` looks at `net` itself (the packet may change on the way).
        let p = Packet {
            hook,
            v6,
            net: &[],
            l4: transport(net),
            ll: ll.as_ref().map(|l| &l[..]),
            iif: seen(iif, &iname),
            oif: seen(oif, &oname),
            pkttype: 0,
            owner: None,
            local,
            types,
        };
        let mut mark = 0;
        self.firewall.process(&mut self.conntrack, net, &p, conn, self.now, &mut mark)
    }

    /// Answer a packet a rule rejected, which came in on `from`: a TCP
    /// reset, or an ICMP (ICMPv6) destination unreachable with its code.
    pub(super) fn reject(&mut self, from: IfIndex, net: &[u8], r: Reject) {
        let v6 = net[0] >> 4 == 6;
        match r {
            Reject::TcpReset => {
                let Some((_, at)) = transport(net) else { return };
                let (src, dst): (IpAddr, IpAddr) = if v6 {
                    let Some(h) = Ipv6Header::parse(net) else { return };
                    (h.src.into(), h.dst.into())
                } else {
                    let Some(h) = Ipv4Header::parse(net) else { return };
                    (h.src.into(), h.dst.into())
                };
                self.reset_reply(src, dst, &net[at..]);
            }
            Reject::Unreachable(code) if v6 => {
                if let Some(h) = Ipv6Header::parse(net) {
                    self.icmp6_error(&h, net, ICMP6_DEST_UNREACHABLE, code, [0; 4]);
                }
            }
            Reject::Unreachable(code) => {
                if let Some(h) = Ipv4Header::parse(net) {
                    self.icmp_error(from, &h, net, ICMP_DEST_UNREACHABLE, code, [0; 4]);
                }
            }
        }
    }

    /// The firewall's verdict on a packet arriving at `hook` (prerouting,
    /// input, forward): whether it goes on. A reject is answered here.
    pub(super) fn arriving(
        &mut self,
        hook: u32,
        net: &mut [u8],
        iif: IfIndex,
        oif: Option<IfIndex>,
        conn: &mut Conn,
    ) -> bool {
        match self.filter(hook, net, Some(iif), oif, conn) {
            Outcome::Accept => true,
            Outcome::Drop => false,
            Outcome::Reject(r) => {
                self.reject(iif, net, r);
                false
            }
        }
    }

    /// The output hook for a packet this host sends out of `oif`: EPERM
    /// when a rule drops or rejects it, as Linux's sendmsg reports. NAT may
    /// give it a new destination, which the caller routes again.
    pub(super) fn output(&mut self, net: &mut [u8], oif: IfIndex, conn: &mut Conn) -> Result<()> {
        match self.filter(NF_INET_LOCAL_OUT, net, None, Some(oif), conn) {
            Outcome::Accept => Ok(()),
            _ => Err(Error::NotPermitted),
        }
    }

    /// The postrouting hook for a packet leaving by `oif` (EPERM as for
    /// output; NAT may give it a new source).
    pub(super) fn postrouting(&mut self, net: &mut [u8], oif: IfIndex, conn: &mut Conn) -> Result<()> {
        match self.filter(NF_INET_POST_ROUTING, net, None, Some(oif), conn) {
            Outcome::Accept => Ok(()),
            _ => Err(Error::NotPermitted),
        }
    }

    /// Both, for a packet whose way NAT doesn't change (looped back, or no
    /// NAT): output, then postrouting.
    pub(super) fn leaving(&mut self, net: &mut [u8], oif: IfIndex, conn: &mut Conn) -> Result<()> {
        self.output(net, oif, conn)?;
        self.postrouting(net, oif, conn)
    }
}
