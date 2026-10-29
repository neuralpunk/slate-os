// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rewriting packets for NAT (ADR 0132): a new source or destination
//! address and port, with the checksums that cover them brought up to
//! date by RFC 1624's incremental update (the IPv4 header's; TCP's, UDP's
//! and ICMPv6's, whose pseudo-headers hold the addresses). An ICMP error
//! about a translated flow has the packet it quotes translated back too,
//! and its own checksum made again.

/// An address (IPv4 in the first four bytes) and a port.
pub type Endpoint = ([u8; 16], u16);

/// What NAT changes in a packet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rewrite {
    pub src: Option<Endpoint>,
    pub dst: Option<Endpoint>,
}

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;

/// A checksum `c` over data in which `old` became `new` (RFC 1624, eqn.
/// 3: HC' = ~(~HC + ~m + m')), both of even length.
fn adjust(c: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut s = u32::from(!c);
    for w in old.chunks(2) {
        s += u32::from(!u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)]));
    }
    for w in new.chunks(2) {
        s += u32::from(u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)]));
    }
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    !(s as u16)
}

/// Adjust the checksum at `at` in `b` (if it is there) for `old` → `new`.
/// UDP's zero means "none" over IPv4 and stays; a sum that comes out zero
/// is sent as all ones (RFC 768).
fn fix(b: &mut [u8], at: usize, old: &[u8], new: &[u8], udp4: bool) {
    let Some(f) = b.get(at..at + 2) else { return };
    let c = u16::from_be_bytes([f[0], f[1]]);
    if udp4 && c == 0 {
        return;
    }
    let mut n = adjust(c, old, new);
    if udp4 && n == 0 {
        n = 0xFFFF;
    }
    b[at..at + 2].copy_from_slice(&n.to_be_bytes());
}

/// Where a transport header keeps its checksum, and whether the
/// addresses are in it (its pseudo-header).
fn l4_checksum(v6: bool, proto: u8) -> Option<(usize, bool)> {
    match proto {
        PROTO_TCP => Some((16, true)),
        PROTO_UDP => Some((6, true)),
        PROTO_ICMPV6 if v6 => Some((2, true)),
        _ => None,
    }
}

/// Rewrite the packet `net` (an IPv4 or IPv6 packet, its transport header
/// at `l4`'s offset), as far as it goes (a quoted packet may be cut short).
pub fn rewrite(net: &mut [u8], v6: bool, l4: Option<(u8, usize)>, rw: Rewrite) {
    let alen = if v6 { 16 } else { 4 };
    let (soff, doff) = if v6 { (8, 24) } else { (12, 16) };
    let udp4 = !v6 && l4.is_some_and(|l| l.0 == PROTO_UDP);
    for (end, off, poff) in [(rw.src, soff, 0), (rw.dst, doff, 2)] {
        let Some((addr, port)) = end else { continue };
        let Some(old) = net.get(off..off + alen).map(|o| o.to_vec()) else { continue };
        let new = &addr[..alen];
        if old != new {
            net[off..off + alen].copy_from_slice(new);
            if !v6 {
                fix(net, 10, &old, new, false);
            }
            if let Some((proto, at)) = l4
                && let Some((c, true)) = l4_checksum(v6, proto)
            {
                fix(net, at + c, &old, new, udp4);
            }
        }
        // Ports, for the protocols that have them.
        if let Some((proto @ (PROTO_TCP | PROTO_UDP), at)) = l4
            && let Some(o) = net.get(at + poff..at + poff + 2).map(|o| [o[0], o[1]])
        {
            let p = port.to_be_bytes();
            if o != p {
                net[at + poff..at + poff + 2].copy_from_slice(&p);
                let (c, _) = l4_checksum(v6, proto).unwrap();
                fix(net, at + c, &o, &p, udp4);
            }
        }
    }
}

/// The Internet checksum of `data` with `sum` added in.
fn checksum(data: &[u8], mut sum: u32) -> u16 {
    for w in data.chunks(2) {
        sum += u32::from(u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Rewrite an ICMP (ICMPv6) error about a translated flow: the error's own
/// addresses as `rw` says, the packet it quotes (which went the other
/// way) with source and destination swapped, then its checksum anew.
pub fn rewrite_related(net: &mut [u8], v6: bool, l4: Option<(u8, usize)>, rw: Rewrite) {
    let Some((_, at)) = l4 else { return };
    rewrite(net, v6, None, rw);
    let inner_at = at + 8;
    if let Some(inner) = net.get(inner_at..)
        && !inner.is_empty()
    {
        let (ihl, iproto) =
            if v6 { (40, inner.get(6).copied()) } else { (usize::from(inner[0] & 0xF) * 4, inner.get(9).copied()) };
        let il4 = iproto.map(|p| (p, ihl));
        let swapped = Rewrite { src: rw.dst, dst: rw.src };
        rewrite(&mut net[inner_at..], v6, il4, swapped);
    }
    // The error's checksum covers what it quotes (and, over IPv6, the
    // addresses).
    if net.len() < at + 4 {
        return;
    }
    net[at + 2..at + 4].fill(0);
    let sum = if v6 {
        let len = (net.len() - at) as u32;
        let mut s = 0u32;
        for w in net[8..40].chunks(2) {
            s += u32::from(u16::from_be_bytes([w[0], w[1]]));
        }
        s + (len >> 16) + (len & 0xFFFF) + u32::from(PROTO_ICMPV6)
    } else {
        0
    };
    let c = checksum(&net[at..], sum);
    net[at + 2..at + 4].copy_from_slice(&c.to_be_bytes());
}
