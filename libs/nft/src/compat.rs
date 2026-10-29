// SPDX-License-Identifier: MIT OR Apache-2.0

//! xtables' matches and targets inside nf_tables (the `match` and
//! `target` expressions, ADR 0133): what iptables-nft can't say in
//! nf_tables' own expressions it sends as an xtables extension by name and
//! revision, with the extension's own structure. Slate has the ones
//! Docker's rules use, and a few as common: the matches addrtype,
//! conntrack, state, tcp and udp, and the NAT targets MASQUERADE, SNAT,
//! DNAT and REDIRECT. Programs ask which revision each has first
//! (NFNL_MSG_COMPAT_GET).
//!
//! Layouts from the UAPI headers ADR 0133 allows: xt_addrtype.h,
//! xt_conntrack.h, xt_state.h, xt_tcpudp.h, nf_nat.h, x_tables.h
//! (structures padded to XT_ALIGN, 8 bytes on x86-64).

use crate::consts::*;
use crate::expr::{EINVAL, ENOENT, EOPNOTSUPP};

/// NFTA_COMPAT_TYPE's values.
pub const MATCH: u32 = 0;
pub const TARGET: u32 = 1;

/// The extensions Slate has: name, type, newest revision.
const KNOWN: &[(&[u8], u32, u32)] = &[
    (b"addrtype", MATCH, 1),
    (b"conntrack", MATCH, 3),
    (b"state", MATCH, 0),
    (b"tcp", MATCH, 0),
    (b"udp", MATCH, 0),
    (b"MASQUERADE", TARGET, 0),
    (b"SNAT", TARGET, 2),
    (b"DNAT", TARGET, 2),
    (b"REDIRECT", TARGET, 0),
];

/// The newest revision of extension `name` of `kind` Slate has (what
/// NFNL_MSG_COMPAT_GET answers), or ENOENT, as Linux answers for one it
/// has no module for.
pub fn revision(name: &[u8], kind: u32) -> Result<u32, i32> {
    KNOWN.iter().find(|k| k.0 == name && k.1 == kind).map(|k| k.2).ok_or(ENOENT)
}

// xt_addrtype.h: flags and types.
const XT_ADDRTYPE_INVERT_SOURCE: u32 = 0x1;
const XT_ADDRTYPE_INVERT_DEST: u32 = 0x2;
/// The address types a packet's addresses have (XT_ADDRTYPE_*: 1 <<
/// rtnetlink's route type), as the stack sees them.
pub const XT_ADDRTYPE_UNSPEC: u16 = 1 << 0;
pub const XT_ADDRTYPE_UNICAST: u16 = 1 << 1;
pub const XT_ADDRTYPE_LOCAL: u16 = 1 << 2;
pub const XT_ADDRTYPE_BROADCAST: u16 = 1 << 3;
pub const XT_ADDRTYPE_MULTICAST: u16 = 1 << 5;

// xt_conntrack.h: what is matched, and the state bits (XT_CONNTRACK_STATE_*:
// 1 << (ctinfo % IP_CT_IS_REPLY + 1), with IP_CT_NUMBER 5).
const XT_CONNTRACK_STATE: u16 = 1 << 0;
const XT_CONNTRACK_PROTO: u16 = 1 << 1;
const XT_CONNTRACK_DIRECTION: u16 = 1 << 12;
const XT_CONNTRACK_STATE_ALIAS: u16 = 1 << 13;
const XT_CONNTRACK_STATE_SNAT: u16 = 1 << 6;
const XT_CONNTRACK_STATE_DNAT: u16 = 1 << 7;
const XT_CONNTRACK_STATE_UNTRACKED: u16 = 1 << 8;

// xt_tcpudp.h: inverse flags.
const XT_TCP_INV_SRCPT: u8 = 0x1;
const XT_TCP_INV_DSTPT: u8 = 0x2;
const XT_TCP_INV_FLAGS: u8 = 0x4;

/// An extension, as Slate runs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Xt {
    /// Address types wanted of the source and destination (0: any).
    AddrType { src: u16, dst: u16, invert_src: bool, invert_dst: bool },
    /// Connection tracking: the state (in the extension's bits), the
    /// transport protocol, the direction (original unless inverted).
    Conntrack { flags: u16, invert: u16, state: u16, proto: u16 },
    /// The older state match (xt_state's bits: untracked is 64 there).
    State { mask: u32 },
    /// TCP or UDP ports in ranges, and (TCP) flags.
    Ports { proto: u8, sport: (u16, u16), dport: (u16, u16), flags: Option<(u8, u8)>, inv: u8 },
    /// A NAT target.
    Nat { src: bool, how: NatHow, addr: Option<[u8; 16]>, ports: Option<(u16, u16)>, flags: u32 },
}

/// Which NAT target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatHow {
    Given,
    Masquerade,
    Redirect,
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([b[at], b[at + 1]])
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
}
fn be16_at(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

/// The structure's size padded to XT_ALIGN, which the info must be.
fn sized(info: &[u8], size: usize) -> Result<(), i32> {
    if info.len() == size.next_multiple_of(8) { Ok(()) } else { Err(EINVAL) }
}

/// A match by name and revision with its structure.
pub fn parse_match(name: &[u8], rev: u32, info: &[u8]) -> Result<Xt, i32> {
    match (name, rev) {
        // struct xt_addrtype_info_v1 (source, dest, flags); revision 0's
        // inversions are two words.
        (b"addrtype", 0 | 1) => {
            let (src, dst) = (u16_at(info.get(..4).ok_or(EINVAL)?, 0), u16_at(info, 2));
            let (inv_src, inv_dst) = if rev == 0 {
                sized(info, 12)?;
                (u32_at(info, 4) != 0, u32_at(info, 8) != 0)
            } else {
                sized(info, 8)?;
                let f = u32_at(info, 4);
                // Limiting to the interface's own addresses isn't done.
                if f & !(XT_ADDRTYPE_INVERT_SOURCE | XT_ADDRTYPE_INVERT_DEST) != 0 {
                    return Err(EOPNOTSUPP);
                }
                (f & XT_ADDRTYPE_INVERT_SOURCE != 0, f & XT_ADDRTYPE_INVERT_DEST != 0)
            };
            Ok(Xt::AddrType { src, dst, invert_src: inv_src, invert_dst: inv_dst })
        }
        // struct xt_conntrack_mtinfo1..3: eight addresses (128 bytes), the
        // expiry range, l4proto, four ports, the flags, the masks (a byte
        // each in revision 1), and four high ports in revision 3.
        (b"conntrack", 1..=3) => {
            sized(info, [152, 154, 162][rev as usize - 1])?;
            let (flags, invert) = (u16_at(info, 146), u16_at(info, 148));
            let state = if rev == 1 { u16::from(info[150]) } else { u16_at(info, 150) };
            // Only the state, protocol and direction are looked at.
            let known = XT_CONNTRACK_STATE | XT_CONNTRACK_PROTO | XT_CONNTRACK_DIRECTION | XT_CONNTRACK_STATE_ALIAS;
            if flags & !known != 0 {
                return Err(EOPNOTSUPP);
            }
            Ok(Xt::Conntrack { flags, invert, state, proto: u16_at(info, 136) })
        }
        (b"state", 0) => {
            sized(info, 4)?;
            Ok(Xt::State { mask: u32_at(info, 0) })
        }
        // struct xt_tcp: port ranges, option, flag mask and value, inversions.
        (b"tcp", 0) => {
            sized(info, 12)?;
            if info[8] != 0 {
                return Err(EOPNOTSUPP); // --tcp-option
            }
            let flags = (info[9] != 0).then_some((info[9], info[10]));
            Ok(Xt::Ports {
                proto: 6,
                sport: (u16_at(info, 0), u16_at(info, 2)),
                dport: (u16_at(info, 4), u16_at(info, 6)),
                flags,
                inv: info[11],
            })
        }
        (b"udp", 0) => {
            sized(info, 9)?;
            Ok(Xt::Ports {
                proto: 17,
                sport: (u16_at(info, 0), u16_at(info, 2)),
                dport: (u16_at(info, 4), u16_at(info, 6)),
                flags: None,
                inv: info[8],
            })
        }
        _ => Err(ENOENT),
    }
}

/// A target by name and revision with its structure, for a rule of
/// `family`.
pub fn parse_target(name: &[u8], rev: u32, info: &[u8], family: u8) -> Result<Xt, i32> {
    let (src, how) = match name {
        b"MASQUERADE" => (true, NatHow::Masquerade),
        b"SNAT" => (true, NatHow::Given),
        b"DNAT" => (false, NatHow::Given),
        b"REDIRECT" => (false, NatHow::Redirect),
        _ => return Err(ENOENT),
    };
    if revision(name, TARGET)? < rev {
        return Err(ENOENT);
    }
    let v6 = family == NFPROTO_IPV6;
    // Revision 0 is IPv4's nf_nat_ipv4_multi_range_compat (one range:
    // flags, two addresses, two ports), or IPv6's nf_nat_range; 1 is
    // nf_nat_range (flags, two 16-byte addresses, two ports), 2
    // nf_nat_range2 (and a base port, for offsets).
    let (flags, min_addr, min_port, max_port) = if rev == 0 && !v6 {
        sized(info, 24)?;
        if u32_at(info, 0) != 1 {
            return Err(EINVAL);
        }
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&info[8..12]);
        (u32_at(info, 4), a, be16_at(info, 16), be16_at(info, 18))
    } else {
        sized(info, if rev == 2 { 42 } else { 40 })?;
        let a: [u8; 16] = info[4..20].try_into().unwrap();
        (u32_at(info, 0), a, be16_at(info, 36), be16_at(info, 38))
    };
    if flags & !NF_NAT_RANGE_MASK != 0 {
        return Err(EINVAL);
    }
    let addr = (how == NatHow::Given && flags & NF_NAT_RANGE_MAP_IPS != 0).then_some(min_addr);
    let ports = (flags & NF_NAT_RANGE_PROTO_SPECIFIED != 0).then_some((min_port, max_port));
    Ok(Xt::Nat { src, how, addr, ports, flags })
}

impl Xt {
    /// The hooks a NAT target works at, as a bit per hook (0: not one).
    pub fn nat_hooks(&self) -> u32 {
        let bit = |h: u32| 1u32 << h;
        match self {
            Xt::Nat { how: NatHow::Masquerade, .. } => bit(NF_INET_POST_ROUTING),
            Xt::Nat { src: true, .. } => bit(NF_INET_POST_ROUTING) | bit(NF_INET_LOCAL_IN),
            Xt::Nat { .. } => bit(NF_INET_PRE_ROUTING) | bit(NF_INET_LOCAL_OUT),
            _ => 0,
        }
    }
}

/// What a match looks at in a packet.
#[derive(Debug)]
pub struct Seen<'a> {
    /// The connection state in nf_tables' bits, and whether it goes its
    /// connection's reply way; whether NAT changed its source or
    /// destination.
    pub ct: Option<(u32, bool, bool, bool)>,
    /// The transport protocol and header.
    pub l4: Option<(u8, &'a [u8])>,
    /// The address types of its source and destination.
    pub types: (u16, u16),
}

/// Whether a match matches.
pub fn matches(x: &Xt, s: &Seen<'_>) -> bool {
    match x {
        Xt::AddrType { src, dst, invert_src, invert_dst } => {
            let ok = |want: u16, has: u16, inv: bool| want == 0 || ((has & want != 0) != inv);
            ok(*src, s.types.0, *invert_src) && ok(*dst, s.types.1, *invert_dst)
        }
        Xt::Conntrack { flags, invert, state, proto } => {
            let inv = |f: u16| invert & f != 0;
            if flags & (XT_CONNTRACK_STATE | XT_CONNTRACK_STATE_ALIAS) != 0 {
                // nf_tables' bits are the extension's but for untracked,
                // and NAT has bits of its own here.
                let bits = match s.ct {
                    None => XT_CONNTRACK_STATE_UNTRACKED,
                    Some((b, _, snat, dnat)) => {
                        let mut x = if b & NF_CT_STATE_UNTRACKED_BIT != 0 {
                            XT_CONNTRACK_STATE_UNTRACKED
                        } else {
                            (b & 0xF) as u16
                        };
                        if snat {
                            x |= XT_CONNTRACK_STATE_SNAT;
                        }
                        if dnat {
                            x |= XT_CONNTRACK_STATE_DNAT;
                        }
                        x
                    }
                };
                if (bits & state != 0) == inv(XT_CONNTRACK_STATE) {
                    return false;
                }
            }
            if flags & XT_CONNTRACK_PROTO != 0
                && (s.l4.is_some_and(|l| u16::from(l.0) == *proto)) == inv(XT_CONNTRACK_PROTO)
            {
                return false;
            }
            if flags & XT_CONNTRACK_DIRECTION != 0 {
                let Some((_, reply, _, _)) = s.ct else { return false };
                if reply != inv(XT_CONNTRACK_DIRECTION) {
                    return false;
                }
            }
            true
        }
        Xt::State { mask } => {
            let bits = match s.ct {
                None => NF_CT_STATE_UNTRACKED_BIT,
                Some((b, ..)) => b,
            };
            bits & mask != 0
        }
        Xt::Ports { proto, sport, dport, flags, inv } => {
            let Some((p, h)) = s.l4 else { return false };
            if p != *proto || h.len() < 4 {
                return false;
            }
            let within = |v: u16, r: (u16, u16)| v >= r.0 && v <= r.1;
            let (sp, dp) = (be16_at(h, 0), be16_at(h, 2));
            if within(sp, *sport) == (inv & XT_TCP_INV_SRCPT != 0)
                || within(dp, *dport) == (inv & XT_TCP_INV_DSTPT != 0)
            {
                return false;
            }
            match flags {
                Some((mask, cmp)) => {
                    let f = h.get(13).copied().unwrap_or(0);
                    ((f & mask) == *cmp) != (inv & XT_TCP_INV_FLAGS != 0)
                }
                None => true,
            }
        }
        Xt::Nat { .. } => true,
    }
}

/// NFNL_MSG_COMPAT_GET: the answer for extension `name` of `kind`, or
/// the errno.
pub fn get(name: &[u8], kind: u32) -> Result<u32, i32> {
    revision(name, kind)
}

/// Whether a rule's expressions name an extension Slate keeps (for the
/// address types the stack works out only when asked).
pub fn uses_addrtype(x: &Xt) -> bool {
    matches!(x, Xt::AddrType { .. })
}
