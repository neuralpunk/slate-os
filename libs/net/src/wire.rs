// SPDX-License-Identifier: MIT OR Apache-2.0

//! Packet formats: Ethernet II (IEEE 802.3), ARP (RFC 826), IPv4 (RFC 791),
//! ICMP (RFC 792), UDP (RFC 768), the Internet checksum (RFC 1071), and
//! IPv6 (RFC 8200) with its addresses (RFC 4291, RFC 5952) and ICMPv6
//! (RFC 4443).

use alloc::vec::Vec;
use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    pub const BROADCAST: Mac = Mac([0xFF; 6]);
}

impl fmt::Debug for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ipv4(pub [u8; 4]);

impl Ipv4 {
    pub const UNSPECIFIED: Ipv4 = Ipv4([0; 4]);
    pub const BROADCAST: Ipv4 = Ipv4([255; 4]);
    pub const LOCALHOST: Ipv4 = Ipv4([127, 0, 0, 1]);

    pub fn to_u32(self) -> u32 {
        u32::from_be_bytes(self.0)
    }
    pub fn from_u32(v: u32) -> Ipv4 {
        Ipv4(v.to_be_bytes())
    }
    pub fn is_loopback(self) -> bool {
        self.0[0] == 127
    }
    pub fn is_unspecified(self) -> bool {
        self == Ipv4::UNSPECIFIED
    }
    pub fn is_multicast(self) -> bool {
        self.0[0] & 0xF0 == 0xE0
    }
    /// Dotted decimal, `a.b.c.d`.
    pub fn parse(s: &str) -> Option<Ipv4> {
        let mut b = [0u8; 4];
        let mut parts = s.split('.');
        for o in b.iter_mut() {
            *o = parts.next()?.parse().ok()?;
        }
        parts.next().is_none().then_some(Ipv4(b))
    }
}

impl fmt::Debug for Ipv4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

impl fmt::Display for Ipv4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

pub fn get16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}
pub fn get32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
pub fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_be_bytes());
}
pub fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_be_bytes());
}
pub fn ip_at(b: &[u8], at: usize) -> Ipv4 {
    Ipv4([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Ones' complement sum of 16-bit words (RFC 1071), not yet folded.
pub fn sum(mut acc: u32, data: &[u8]) -> u32 {
    let (words, rest) = data.as_chunks::<2>();
    for w in words {
        acc += u32::from(u16::from_be_bytes(*w));
    }
    if let [last] = rest {
        acc += u32::from(*last) << 8;
    }
    acc
}

/// Fold and complement a sum into a checksum.
pub fn finish(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    !(acc as u16)
}

pub fn checksum(data: &[u8]) -> u16 {
    finish(sum(0, data))
}

/// Sum of the IPv4 pseudo-header for UDP and TCP checksums.
pub fn pseudo_sum(src: Ipv4, dst: Ipv4, proto: u8, len: usize) -> u32 {
    let mut acc = sum(0, &src.0);
    acc = sum(acc, &dst.0);
    acc + u32::from(proto) + len as u32
}

// Ethernet.
pub const ETH_HEADER: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;

pub fn ethernet(dst: Mac, src: Mac, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(ETH_HEADER + payload.len().max(46));
    f.extend_from_slice(&dst.0);
    f.extend_from_slice(&src.0);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    // Pad to the 60-byte minimum frame (without FCS).
    if f.len() < 60 {
        f.resize(60, 0);
    }
    f
}

// ARP for IPv4 over Ethernet.
pub const ARP_LEN: usize = 28;
pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arp {
    pub op: u16,
    pub sender_mac: Mac,
    pub sender_ip: Ipv4,
    pub target_mac: Mac,
    pub target_ip: Ipv4,
}

impl Arp {
    pub fn parse(b: &[u8]) -> Option<Arp> {
        if b.len() < ARP_LEN || get16(b, 0) != 1 || get16(b, 2) != ETHERTYPE_IPV4 || b[4] != 6 || b[5] != 4 {
            return None;
        }
        let mac = |at: usize| Mac(b[at..at + 6].try_into().unwrap());
        Some(Arp {
            op: get16(b, 6),
            sender_mac: mac(8),
            sender_ip: ip_at(b, 14),
            target_mac: mac(18),
            target_ip: ip_at(b, 24),
        })
    }
    pub fn build(&self) -> [u8; ARP_LEN] {
        let mut b = [0u8; ARP_LEN];
        put16(&mut b, 0, 1);
        put16(&mut b, 2, ETHERTYPE_IPV4);
        b[4] = 6;
        b[5] = 4;
        put16(&mut b, 6, self.op);
        b[8..14].copy_from_slice(&self.sender_mac.0);
        b[14..18].copy_from_slice(&self.sender_ip.0);
        b[18..24].copy_from_slice(&self.target_mac.0);
        b[24..28].copy_from_slice(&self.target_ip.0);
        b
    }
}

// IPv4.
pub const IP_HEADER: usize = 20;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const DEFAULT_TTL: u8 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Header {
    pub header_len: usize,
    pub total_len: usize,
    pub id: u16,
    /// More-fragments flag or a non-zero offset.
    pub fragmented: bool,
    pub ttl: u8,
    pub proto: u8,
    pub src: Ipv4,
    pub dst: Ipv4,
    /// The type-of-service byte (RFC 791; IP_RECVTOS reports it).
    pub tos: u8,
}

impl Ipv4Header {
    /// Parse and validate (version, lengths, header checksum).
    pub fn parse(b: &[u8]) -> Option<Ipv4Header> {
        if b.len() < IP_HEADER || b[0] >> 4 != 4 {
            return None;
        }
        let header_len = usize::from(b[0] & 0xF) * 4;
        let total_len = usize::from(get16(b, 2));
        if header_len < IP_HEADER || total_len < header_len || total_len > b.len() || checksum(&b[..header_len]) != 0 {
            return None;
        }
        let frag = get16(b, 6);
        Some(Ipv4Header {
            header_len,
            total_len,
            id: get16(b, 4),
            fragmented: frag & 0x2000 != 0 || frag & 0x1FFF != 0,
            ttl: b[8],
            proto: b[9],
            src: ip_at(b, 12),
            dst: ip_at(b, 16),
            tos: b[1],
        })
    }
}

impl Ipv4Header {
    /// Parse a header quoted in an ICMP error (truncated, checksum unchecked).
    pub fn parse_unchecked(b: &[u8]) -> Option<Ipv4Header> {
        if b.len() < IP_HEADER || b[0] >> 4 != 4 {
            return None;
        }
        let header_len = usize::from(b[0] & 0xF) * 4;
        if header_len < IP_HEADER || b.len() < header_len + 4 {
            return None;
        }
        Some(Ipv4Header {
            header_len,
            total_len: usize::from(get16(b, 2)),
            id: get16(b, 4),
            fragmented: false,
            ttl: b[8],
            proto: b[9],
            src: ip_at(b, 12),
            dst: ip_at(b, 16),
            tos: b[1],
        })
    }
}

/// An IPv4 packet (no options, Don't Fragment set).
pub fn ipv4(src: Ipv4, dst: Ipv4, proto: u8, id: u16, ttl: u8, payload: &[u8]) -> Vec<u8> {
    ipv4_tos(src, dst, proto, id, ttl, 0, payload)
}

/// An IPv4 packet with the type-of-service byte `tos` (RFC 791 §3.1; ip(7)
/// IP_TOS).
#[allow(clippy::too_many_arguments)]
pub fn ipv4_tos(src: Ipv4, dst: Ipv4, proto: u8, id: u16, ttl: u8, tos: u8, payload: &[u8]) -> Vec<u8> {
    ipv4_full(src, dst, proto, id, ttl, tos, &[], payload)
}

/// An IPv4 packet carrying the option field `options` (at most
/// `IP_OPTIONS_MAX` bytes, padded here to a multiple of four with
/// end-of-list bytes: RFC 791 §3.1).
#[allow(clippy::too_many_arguments)]
pub fn ipv4_full(
    src: Ipv4,
    dst: Ipv4,
    proto: u8,
    id: u16,
    ttl: u8,
    tos: u8,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let opts = options.len().min(IP_OPTIONS_MAX).next_multiple_of(4);
    let header = IP_HEADER + opts;
    let mut p = Vec::with_capacity(header + payload.len());
    p.extend_from_slice(&[0x40 | (header / 4) as u8, tos, 0, 0, 0, 0, 0x40, 0, ttl, proto, 0, 0]);
    put16(&mut p, 2, (header + payload.len()) as u16);
    put16(&mut p, 4, id);
    p.extend_from_slice(&src.0);
    p.extend_from_slice(&dst.0);
    p.extend_from_slice(&options[..options.len().min(IP_OPTIONS_MAX)]);
    p.resize(header, IPOPT_END);
    let c = checksum(&p);
    put16(&mut p, 10, c);
    p.extend_from_slice(payload);
    p
}

// IPv4 options (RFC 791 §3.1; Router Alert RFC 2113): a kind byte, then for
// all but the one-byte END and NOP a length counting the kind and itself.
// Record Route and the source routes carry a pointer (1-based, from the
// option's start) to the next address slot; Timestamp a pointer, then
// overflow (high nibble) and flags (low: 0 times only, 1 address and time,
// 3 times for the addresses given).
pub const IPOPT_END: u8 = 0;
pub const IPOPT_NOP: u8 = 1;
pub const IPOPT_RR: u8 = 7;
pub const IPOPT_TS: u8 = 68;
pub const IPOPT_LSRR: u8 = 131;
pub const IPOPT_SSRR: u8 = 137;
pub const IPOPT_RA: u8 = 148;
/// The most option bytes a header holds (a 60-byte header).
pub const IP_OPTIONS_MAX: usize = 40;

/// Where one option is in an option field, and its kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpOpt {
    pub kind: u8,
    pub at: usize,
    pub len: usize,
}

/// The options of an option field (the header's bytes after the first
/// 20). `Err(n)`: byte `n` of the field is wrong (Parameter Problem's
/// pointer is 20 + n, RFC 792).
pub fn ipv4_options(f: &[u8]) -> core::result::Result<Vec<IpOpt>, usize> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < f.len() {
        let kind = f[at];
        match kind {
            IPOPT_END => break,
            IPOPT_NOP => {
                at += 1;
                continue;
            }
            _ => {}
        }
        let len = usize::from(*f.get(at + 1).ok_or(at)?);
        if len < 2 || at + len > f.len() {
            return Err(at + 1);
        }
        let pointer = usize::from(f.get(at + 2).copied().unwrap_or(0));
        let bad = match kind {
            IPOPT_RR | IPOPT_LSRR | IPOPT_SSRR => len < 3 || pointer < 4 || pointer % 4 != 0,
            IPOPT_TS => len < 4 || pointer < 5 || !matches!(f[at + 3] & 0xF, 0 | 1 | 3),
            IPOPT_RA => len != 4,
            _ => false,
        };
        if bad {
            return Err(if kind == IPOPT_RA { at + 1 } else { at + 2 });
        }
        out.push(IpOpt { kind, at, len });
        at += len;
    }
    Ok(out)
}

/// Record `addr` in a Record Route option, if it has room.
pub fn record_route(opt: &mut [u8], addr: Ipv4) {
    let p = usize::from(opt[2]);
    if p + 3 <= opt.len() {
        opt[p - 1..p + 3].copy_from_slice(&addr.0);
        opt[2] += 4;
    }
}

/// Record a time (`ms` since midnight UT, or with the high bit set when
/// the clock isn't known: RFC 791) in a Timestamp option, with `addr` as
/// its flags ask; with no room left, count an overflow.
pub fn record_timestamp(opt: &mut [u8], addr: Ipv4, ms: u32) {
    let p = usize::from(opt[2]);
    let flags = opt[3] & 0xF;
    let slot = if flags == 0 { 4 } else { 8 };
    if p + slot - 1 > opt.len() {
        let overflow = (opt[3] >> 4).saturating_add(1).min(15);
        opt[3] = (overflow << 4) | flags;
        return;
    }
    match flags {
        0 => opt[p - 1..p + 3].copy_from_slice(&ms.to_be_bytes()),
        1 => {
            opt[p - 1..p + 3].copy_from_slice(&addr.0);
            opt[p + 3..p + 7].copy_from_slice(&ms.to_be_bytes());
        }
        // Prespecified: only when the next address named is ours.
        _ if opt[p - 1..p + 3] == addr.0 => opt[p + 3..p + 7].copy_from_slice(&ms.to_be_bytes()),
        _ => return,
    }
    opt[2] += slot as u8;
}

// ICMP.
pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_DEST_UNREACHABLE: u8 = 3;
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_PORT_UNREACHABLE: u8 = 3;
// Destination unreachable codes (RFC 792; 4 with the next hop's MTU, RFC
// 1191 §4) and time exceeded in transit (RFC 792).
pub const ICMP_NET_UNREACHABLE: u8 = 0;
pub const ICMP_FRAG_NEEDED: u8 = 4;
pub const ICMP_TIME_EXCEEDED: u8 = 11;
/// Destination unreachable's protocol unreachable, time exceeded's
/// reassembly timeout, and parameter problem with its pointer in the first
/// byte after the checksum (RFC 792).
pub const ICMP_PROTO_UNREACHABLE: u8 = 2;
pub const ICMP_REASSEMBLY_TIMEOUT: u8 = 1;
pub const ICMP_PARAMETER_PROBLEM: u8 = 12;

/// An ICMP message with its checksum filled in.
pub fn icmp(kind: u8, code: u8, rest: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(8 + payload.len());
    m.extend_from_slice(&[kind, code, 0, 0]);
    m.extend_from_slice(&rest);
    m.extend_from_slice(payload);
    let c = checksum(&m);
    put16(&mut m, 2, c);
    m
}

// UDP.
pub const UDP_HEADER: usize = 8;

pub fn udp(src: Ipv4, sport: u16, dst: Ipv4, dport: u16, payload: &[u8]) -> Vec<u8> {
    let len = UDP_HEADER + payload.len();
    let mut d = Vec::with_capacity(len);
    d.extend_from_slice(&sport.to_be_bytes());
    d.extend_from_slice(&dport.to_be_bytes());
    d.extend_from_slice(&(len as u16).to_be_bytes());
    d.extend_from_slice(&[0, 0]);
    d.extend_from_slice(payload);
    let mut c = finish(sum(pseudo_sum(src, dst, PROTO_UDP, len), &d));
    if c == 0 {
        c = 0xFFFF; // Zero means "no checksum" (RFC 768).
    }
    put16(&mut d, 6, c);
    d
}

/// Parse a UDP datagram: (source port, destination port, payload), after
/// checking its length and checksum.
pub fn parse_udp(src: Ipv4, dst: Ipv4, d: &[u8]) -> Option<(u16, u16, &[u8])> {
    if d.len() < UDP_HEADER {
        return None;
    }
    let len = usize::from(get16(d, 4));
    if len < UDP_HEADER || len > d.len() {
        return None;
    }
    if get16(d, 6) != 0 && finish(sum(pseudo_sum(src, dst, PROTO_UDP, len), &d[..len])) != 0 {
        return None;
    }
    Some((get16(d, 0), get16(d, 2), &d[UDP_HEADER..len]))
}

// --- IPv6 (RFC 8200), its addresses (RFC 4291), ICMPv6 (RFC 4443) --------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ipv6(pub [u8; 16]);

impl Ipv6 {
    pub const UNSPECIFIED: Ipv6 = Ipv6([0; 16]);
    pub const LOCALHOST: Ipv6 = Ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    /// ff02::1 and ff02::2 (RFC 4291 §2.7.1).
    pub const ALL_NODES: Ipv6 = Ipv6([0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    pub const ALL_ROUTERS: Ipv6 = Ipv6([0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    pub fn from_segments(s: [u16; 8]) -> Ipv6 {
        let mut b = [0u8; 16];
        for (i, v) in s.iter().enumerate() {
            b[2 * i..2 * i + 2].copy_from_slice(&v.to_be_bytes());
        }
        Ipv6(b)
    }
    pub fn segments(self) -> [u16; 8] {
        core::array::from_fn(|i| u16::from_be_bytes([self.0[2 * i], self.0[2 * i + 1]]))
    }
    pub fn is_unspecified(self) -> bool {
        self == Ipv6::UNSPECIFIED
    }
    pub fn is_loopback(self) -> bool {
        self == Ipv6::LOCALHOST
    }
    pub fn is_multicast(self) -> bool {
        self.0[0] == 0xff
    }
    /// fe80::/10.
    pub fn is_link_local(self) -> bool {
        self.0[0] == 0xfe && self.0[1] & 0xc0 == 0x80
    }
    /// Link-local scope for routing: link-local unicast, or multicast of
    /// interface- or link-local scope (RFC 4291 §2.7).
    pub fn is_link_scope(self) -> bool {
        self.is_link_local() || (self.is_multicast() && self.0[1] & 0x0f <= 2)
    }
    /// The solicited-node multicast address (RFC 4291 §2.7.1): ff02::1:ff
    /// and the address's last 24 bits.
    pub fn solicited_node(self) -> Ipv6 {
        let mut b = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 0];
        b[13..].copy_from_slice(&self.0[13..]);
        Ipv6(b)
    }
    /// The Ethernet address a multicast packet goes to (RFC 2464 §7).
    pub fn multicast_mac(self) -> Mac {
        Mac([0x33, 0x33, self.0[12], self.0[13], self.0[14], self.0[15]])
    }
    /// ::ffff:a.b.c.d, an IPv4 address on an IPv6 socket (RFC 4291 §2.5.5.2).
    pub fn mapped(v4: Ipv4) -> Ipv6 {
        let mut b = [0u8; 16];
        b[10] = 0xff;
        b[11] = 0xff;
        b[12..].copy_from_slice(&v4.0);
        Ipv6(b)
    }
    pub fn to_mapped_v4(self) -> Option<Ipv4> {
        (self.0[..10] == [0; 10] && self.0[10] == 0xff && self.0[11] == 0xff)
            .then(|| Ipv4([self.0[12], self.0[13], self.0[14], self.0[15]]))
    }
    /// An address from a /64 prefix and an interface identifier.
    pub fn with_interface_id(prefix: Ipv6, id: [u8; 8]) -> Ipv6 {
        let mut b = prefix.0;
        b[8..].copy_from_slice(&id);
        Ipv6(b)
    }
    /// The modified EUI-64 interface identifier of a MAC address (RFC 4291
    /// appendix A).
    pub fn eui64(mac: Mac) -> [u8; 8] {
        let m = mac.0;
        [m[0] ^ 0x02, m[1], m[2], 0xff, 0xfe, m[3], m[4], m[5]]
    }
    pub fn link_local(mac: Mac) -> Ipv6 {
        Ipv6::with_interface_id(Ipv6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), Ipv6::eui64(mac))
    }
    /// The first `prefix_len` bits, the rest zero.
    pub fn masked(self, prefix_len: u8) -> Ipv6 {
        let mut b = self.0;
        for (i, x) in b.iter_mut().enumerate() {
            let keep = (usize::from(prefix_len.min(128))).saturating_sub(i * 8).min(8);
            *x &= if keep == 0 { 0 } else { 0xffu8 << (8 - keep) };
        }
        Ipv6(b)
    }
    pub fn within(self, net: Ipv6, prefix_len: u8) -> bool {
        self.masked(prefix_len) == net.masked(prefix_len)
    }

    /// Parse the text forms of RFC 4291 §2.2: eight groups, `::` for a run
    /// of zero groups, an IPv4 address in the last 32 bits.
    pub fn parse(s: &str) -> Option<Ipv6> {
        let (head, tail) = match s.split_once("::") {
            Some((h, t)) => (h, Some(t)),
            None => (s, None),
        };
        fn groups(part: &str, allow_v4: bool) -> Option<Vec<u16>> {
            let mut out = Vec::new();
            if part.is_empty() {
                return Some(out);
            }
            let pieces: Vec<&str> = part.split(':').collect();
            for (i, g) in pieces.iter().enumerate() {
                if allow_v4 && i == pieces.len() - 1 && g.contains('.') {
                    let v4 = Ipv4::parse(g)?;
                    out.push(u16::from_be_bytes([v4.0[0], v4.0[1]]));
                    out.push(u16::from_be_bytes([v4.0[2], v4.0[3]]));
                } else {
                    if g.is_empty() || g.len() > 4 {
                        return None;
                    }
                    out.push(u16::from_str_radix(g, 16).ok()?);
                }
            }
            Some(out)
        }
        let h = groups(head, tail.is_none())?;
        let mut seg = [0u16; 8];
        match tail {
            None => {
                if h.len() != 8 {
                    return None;
                }
                seg.copy_from_slice(&h);
            }
            Some(t) => {
                if t.contains("::") {
                    return None;
                }
                let t = groups(t, true)?;
                if h.len() + t.len() > 7 {
                    return None;
                }
                seg[..h.len()].copy_from_slice(&h);
                seg[8 - t.len()..].copy_from_slice(&t);
            }
        }
        Some(Ipv6::from_segments(seg))
    }
}

impl fmt::Display for Ipv6 {
    /// RFC 5952 §4: lower case, no leading zeros, the longest run of two or
    /// more zero groups (the first if tied) as `::`; mapped IPv4 addresses
    /// in dotted form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(v4) = self.to_mapped_v4() {
            return write!(f, "::ffff:{v4}");
        }
        let s = self.segments();
        let (mut best, mut best_len, mut i) = (8, 0, 0);
        while i < 8 {
            if s[i] == 0 {
                let start = i;
                while i < 8 && s[i] == 0 {
                    i += 1;
                }
                if i - start > best_len && i - start >= 2 {
                    (best, best_len) = (start, i - start);
                }
            } else {
                i += 1;
            }
        }
        let mut i = 0;
        while i < 8 {
            if i == best {
                f.write_str("::")?;
                i += best_len;
                continue;
            }
            if i > 0 && i != best + best_len {
                f.write_str(":")?;
            }
            write!(f, "{:x}", s[i])?;
            i += 1;
        }
        Ok(())
    }
}

impl fmt::Debug for Ipv6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// An IPv4 or IPv6 address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IpAddr {
    V4(Ipv4),
    V6(Ipv6),
}

impl Default for IpAddr {
    fn default() -> IpAddr {
        IpAddr::V4(Ipv4::UNSPECIFIED)
    }
}

impl From<Ipv4> for IpAddr {
    fn from(a: Ipv4) -> IpAddr {
        IpAddr::V4(a)
    }
}
impl From<Ipv6> for IpAddr {
    fn from(a: Ipv6) -> IpAddr {
        IpAddr::V6(a)
    }
}

impl IpAddr {
    pub fn is_unspecified(self) -> bool {
        match self {
            IpAddr::V4(a) => a.is_unspecified(),
            IpAddr::V6(a) => a.is_unspecified(),
        }
    }
    pub fn is_loopback(self) -> bool {
        match self {
            IpAddr::V4(a) => a.is_loopback(),
            IpAddr::V6(a) => a.is_loopback(),
        }
    }
    pub fn is_multicast(self) -> bool {
        match self {
            IpAddr::V4(a) => a.is_multicast(),
            IpAddr::V6(a) => a.is_multicast(),
        }
    }
    pub fn v4(self) -> Option<Ipv4> {
        match self {
            IpAddr::V4(a) => Some(a),
            IpAddr::V6(_) => None,
        }
    }
    pub fn v6(self) -> Option<Ipv6> {
        match self {
            IpAddr::V6(a) => Some(a),
            IpAddr::V4(_) => None,
        }
    }
    pub fn is_v6(self) -> bool {
        matches!(self, IpAddr::V6(_))
    }
}

impl fmt::Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpAddr::V4(a) => fmt::Display::fmt(a, f),
            IpAddr::V6(a) => fmt::Display::fmt(a, f),
        }
    }
}

impl fmt::Debug for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const IP6_HEADER: usize = 40;
// Next header values (RFC 8200 §4; IANA protocol numbers).
pub const NEXT_HOP_BY_HOP: u8 = 0;
pub const NEXT_ROUTING: u8 = 43;
pub const NEXT_FRAGMENT: u8 = 44;
pub const NEXT_NONE: u8 = 59;
pub const NEXT_DEST_OPTS: u8 = 60;
pub const PROTO_ICMPV6: u8 = 58;
pub const DEFAULT_HOP_LIMIT: u8 = 64;
/// The smallest MTU every IPv6 link has (RFC 8200 §5).
pub const IPV6_MIN_MTU: usize = 1280;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6Header {
    pub payload_len: usize,
    pub next: u8,
    pub hop_limit: u8,
    pub src: Ipv6,
    pub dst: Ipv6,
    /// The traffic class (RFC 8200 §3; IPV6_RECVTCLASS reports it).
    pub tclass: u8,
}

impl Ipv6Header {
    pub fn parse(b: &[u8]) -> Option<Ipv6Header> {
        if b.len() < IP6_HEADER || b[0] >> 4 != 6 {
            return None;
        }
        let payload_len = usize::from(get16(b, 4));
        if IP6_HEADER + payload_len > b.len() {
            return None;
        }
        Some(Ipv6Header {
            payload_len,
            next: b[6],
            hop_limit: b[7],
            src: Ipv6(b[8..24].try_into().unwrap()),
            dst: Ipv6(b[24..40].try_into().unwrap()),
            tclass: (b[0] << 4) | (b[1] >> 4),
        })
    }
}

/// An IPv6 packet: version 6, no traffic class or flow label.
pub fn ipv6(src: Ipv6, dst: Ipv6, next: u8, hop_limit: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(IP6_HEADER + payload.len());
    p.extend_from_slice(&[0x60, 0, 0, 0]);
    p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    p.extend_from_slice(&[next, hop_limit]);
    p.extend_from_slice(&src.0);
    p.extend_from_slice(&dst.0);
    p.extend_from_slice(payload);
    p
}

/// Sum of the pseudo-header for checksums over IPv4 or IPv6 (RFC 768,
/// RFC 9293; RFC 8200 §8.1: addresses, length, next header).
pub fn pseudo_sum_ip(src: IpAddr, dst: IpAddr, proto: u8, len: usize) -> u32 {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => pseudo_sum(s, d, proto, len),
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut acc = sum(sum(0, &s.0), &d.0);
            acc += (len as u32 >> 16) + (len as u32 & 0xFFFF);
            acc + u32::from(proto)
        }
        // Mixed families never meet on the wire.
        _ => 0,
    }
}

// ICMPv6 message types (RFC 4443 §2.1, RFC 4861 §4).
pub const ICMP6_DEST_UNREACHABLE: u8 = 1;
pub const ICMP6_PACKET_TOO_BIG: u8 = 2;
pub const ICMP6_TIME_EXCEEDED: u8 = 3;
pub const ICMP6_ECHO_REQUEST: u8 = 128;
pub const ICMP6_ECHO_REPLY: u8 = 129;
pub const ND_ROUTER_SOLICIT: u8 = 133;
pub const ND_ROUTER_ADVERT: u8 = 134;
pub const ND_NEIGHBOR_SOLICIT: u8 = 135;
pub const ND_NEIGHBOR_ADVERT: u8 = 136;
// Destination unreachable codes (RFC 4443 §3.1).
pub const ICMP6_NO_ROUTE: u8 = 0;
pub const ICMP6_ADDR_UNREACHABLE: u8 = 3;
pub const ICMP6_PORT_UNREACHABLE: u8 = 4;

/// An ICMPv6 message with its checksum (over the pseudo-header).
pub fn icmpv6(src: Ipv6, dst: Ipv6, kind: u8, code: u8, rest: [u8; 4], body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(8 + body.len());
    m.extend_from_slice(&[kind, code, 0, 0]);
    m.extend_from_slice(&rest);
    m.extend_from_slice(body);
    let c = finish(sum(pseudo_sum_ip(src.into(), dst.into(), PROTO_ICMPV6, m.len()), &m));
    put16(&mut m, 2, c);
    m
}

/// Whether an ICMPv6 message's checksum is right.
pub fn icmpv6_ok(src: Ipv6, dst: Ipv6, m: &[u8]) -> bool {
    m.len() >= 4 && finish(sum(pseudo_sum_ip(src.into(), dst.into(), PROTO_ICMPV6, m.len()), m)) == 0
}

/// A UDP datagram over IPv4 or IPv6 (the checksum is mandatory over IPv6,
/// RFC 8200 §8.1).
pub fn udp_ip(src: IpAddr, sport: u16, dst: IpAddr, dport: u16, payload: &[u8]) -> Vec<u8> {
    let len = UDP_HEADER + payload.len();
    let mut d = Vec::with_capacity(len);
    d.extend_from_slice(&sport.to_be_bytes());
    d.extend_from_slice(&dport.to_be_bytes());
    d.extend_from_slice(&(len as u16).to_be_bytes());
    d.extend_from_slice(&[0, 0]);
    d.extend_from_slice(payload);
    let mut c = finish(sum(pseudo_sum_ip(src, dst, PROTO_UDP, len), &d));
    if c == 0 {
        c = 0xFFFF;
    }
    put16(&mut d, 6, c);
    d
}

/// Parse a UDP datagram over either family (a zero checksum is refused
/// over IPv6).
pub fn parse_udp_ip(src: IpAddr, dst: IpAddr, d: &[u8]) -> Option<(u16, u16, &[u8])> {
    if d.len() < UDP_HEADER {
        return None;
    }
    let len = usize::from(get16(d, 4));
    if len < UDP_HEADER || len > d.len() {
        return None;
    }
    let zero = get16(d, 6) == 0;
    if (zero && src.is_v6()) || (!zero && finish(sum(pseudo_sum_ip(src, dst, PROTO_UDP, len), &d[..len])) != 0) {
        return None;
    }
    Some((get16(d, 0), get16(d, 2), &d[UDP_HEADER..len]))
}

/// The TCP flags that only the last of a segmented send's frames keeps
/// (RFC 9293 §3.1: FIN ends the stream, PSH marks where data was pushed).
const TCP_FIN: u8 = 0x01;
const TCP_PSH: u8 = 0x08;

/// Split an Ethernet frame holding one large TCP segment over IPv4 into
/// frames of at most `mss` bytes of payload, as a card's TCP segmentation
/// offload would (ADR 0083): each with the headers copied, the IPv4 total
/// length and identification (one more each frame) and the TCP sequence
/// number adjusted, FIN and PSH only on the last, and both checksums
/// computed again. A frame that is not IPv4 TCP, or already fits, comes
/// back whole.
pub fn segment_tcp4(frame: &[u8], mss: usize) -> Vec<Vec<u8>> {
    let whole = || alloc::vec![frame.to_vec()];
    if mss == 0 || frame.len() < ETH_HEADER + IP_HEADER + 20 || get16(frame, 12) != ETHERTYPE_IPV4 {
        return whole();
    }
    let ip = ETH_HEADER;
    let ihl = usize::from(frame[ip] & 0xF) * 4;
    let total = usize::from(get16(frame, ip + 2));
    if frame[ip + 9] != PROTO_TCP || ihl < IP_HEADER || ip + total > frame.len() {
        return whole();
    }
    let tcp = ip + ihl;
    let thl = usize::from(frame.get(tcp + 12).copied().unwrap_or(0) >> 4) * 4;
    let data = tcp + thl;
    if thl < 20 || data > ip + total || ip + total - data <= mss {
        return whole();
    }
    let payload = &frame[data..ip + total];
    let (id, seq, flags) = (get16(frame, ip + 4), get32(frame, tcp + 4), frame[tcp + 13]);
    let src = Ipv4(frame[ip + 12..ip + 16].try_into().unwrap());
    let dst = Ipv4(frame[ip + 16..ip + 20].try_into().unwrap());
    let pieces = payload.len().div_ceil(mss);
    let mut out = alloc::vec::Vec::with_capacity(pieces);
    for (k, chunk) in payload.chunks(mss).enumerate() {
        let mut f = alloc::vec::Vec::with_capacity(data + chunk.len());
        f.extend_from_slice(&frame[..data]);
        f.extend_from_slice(chunk);
        put16(&mut f, ip + 2, (ihl + thl + chunk.len()) as u16);
        put16(&mut f, ip + 4, id.wrapping_add(k as u16));
        put16(&mut f, ip + 10, 0);
        let c = checksum(&f[ip..ip + ihl]);
        put16(&mut f, ip + 10, c);
        put32(&mut f, tcp + 4, seq.wrapping_add((k * mss) as u32));
        if k + 1 < pieces {
            f[tcp + 13] = flags & !(TCP_FIN | TCP_PSH);
        }
        put16(&mut f, tcp + 16, 0);
        let c = finish(sum(pseudo_sum(src, dst, PROTO_TCP, thl + chunk.len()), &f[tcp..]));
        put16(&mut f, tcp + 16, c);
        out.push(f);
    }
    out
}

/// The frames and bytes `segment_tcp4(frame, mss)` would make, without
/// making them (for counters).
pub fn segmented_size(frame: &[u8], mss: usize) -> (usize, usize) {
    let pieces = segment_tcp4_header(frame).map(|h| (h, frame.len().saturating_sub(h)));
    match pieces {
        Some((h, payload)) if mss > 0 && payload > mss => {
            let n = payload.div_ceil(mss);
            (n, payload + n * h)
        }
        _ => (1, frame.len()),
    }
}

/// The Ethernet, IPv4 and TCP headers' length of a TCP over IPv4 frame.
fn segment_tcp4_header(frame: &[u8]) -> Option<usize> {
    if frame.len() < ETH_HEADER + IP_HEADER + 20
        || get16(frame, 12) != ETHERTYPE_IPV4
        || frame[ETH_HEADER + 9] != PROTO_TCP
    {
        return None;
    }
    let ihl = usize::from(frame[ETH_HEADER] & 0xF) * 4;
    let thl = usize::from(*frame.get(ETH_HEADER + ihl + 12)? >> 4) * 4;
    Some(ETH_HEADER + ihl + thl)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_text_forms() {
        // RFC 5952 §4's rules, and RFC 4291 §2.2's forms.
        let cases = [
            ("2001:db8::1", "2001:db8::1"),
            ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
            ("::", "::"),
            ("::1", "::1"),
            ("fe80::5054:ff:fe12:3456", "fe80::5054:ff:fe12:3456"),
            ("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"),
            ("2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"),
            ("::ffff:10.0.2.15", "::ffff:10.0.2.15"),
            ("ff02::1:ff12:3456", "ff02::1:ff12:3456"),
        ];
        for (text, canonical) in cases {
            let a = Ipv6::parse(text).unwrap_or_else(|| panic!("{text}"));
            assert_eq!(alloc::format!("{a}"), canonical);
        }
        for bad in ["1::2::3", "12345::", ":1", "1:2:3:4:5:6:7:8:9", "g::1", "1.2.3.4"] {
            assert_eq!(Ipv6::parse(bad), None, "{bad}");
        }
        let mac = Mac([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        assert_eq!(Ipv6::link_local(mac), Ipv6::parse("fe80::5054:ff:fe12:3456").unwrap());
        assert_eq!(Ipv6::link_local(mac).solicited_node(), Ipv6::parse("ff02::1:ff12:3456").unwrap());
        assert_eq!(Ipv6::ALL_NODES.multicast_mac(), Mac([0x33, 0x33, 0, 0, 0, 1]));
        assert_eq!(Ipv6::parse("2001:db8:1:2:3::").unwrap().masked(64), Ipv6::parse("2001:db8:1:2::").unwrap());
        assert_eq!(Ipv6::parse("::ffff:1.2.3.4").unwrap().to_mapped_v4(), Some(Ipv4([1, 2, 3, 4])));
    }

    #[test]
    fn udp6_checksum() {
        let (a, b) = (IpAddr::V6(Ipv6::parse("fe80::1").unwrap()), IpAddr::V6(Ipv6::parse("fe80::2").unwrap()));
        let d = udp_ip(a, 5000, b, 53, b"query");
        assert_eq!(parse_udp_ip(a, b, &d), Some((5000, 53, &b"query"[..])));
        let mut zero = d.clone();
        zero[6..8].fill(0);
        assert_eq!(parse_udp_ip(a, b, &zero), None);
        let m = icmpv6(a.v6().unwrap(), b.v6().unwrap(), ICMP6_ECHO_REQUEST, 0, [0, 1, 0, 1], b"x");
        assert!(icmpv6_ok(a.v6().unwrap(), b.v6().unwrap(), &m));
    }

    #[test]
    fn rfc1071_example() {
        // The worked example in RFC 1071 §3: sum 0xddf2, checksum 0x220d.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&data), 0x220d);
    }

    #[test]
    fn ipv4_round_trip() {
        let p = ipv4(Ipv4([10, 0, 2, 15]), Ipv4([10, 0, 2, 2]), PROTO_UDP, 7, 64, b"hi");
        let h = Ipv4Header::parse(&p).unwrap();
        assert_eq!(
            (h.src, h.dst, h.proto, h.total_len, h.fragmented),
            (Ipv4([10, 0, 2, 15]), Ipv4([10, 0, 2, 2]), 17, 22, false)
        );
    }

    #[test]
    fn udp_checksum_verifies() {
        let (a, b) = (Ipv4([1, 2, 3, 4]), Ipv4([5, 6, 7, 8]));
        let d = udp(a, 1000, b, 53, b"query");
        assert_eq!(parse_udp(a, b, &d), Some((1000, 53, &b"query"[..])));
        let mut bad = d.clone();
        bad[9] ^= 1;
        assert_eq!(parse_udp(a, b, &bad), None);
    }
}
