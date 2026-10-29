// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rule expressions: parsed from nft's attributes (a name and a nest of
//! data, ADR 0128), and written back the way Linux's dumps have them
//! (observed on the host: its own attribute order, defaults filled in,
//! counters' live values).

use alloc::vec::Vec;

use crate::attr::{Attr, Attrs, Msg};
use crate::consts::*;

/// A verdict (enum nft_verdicts and NF_ACCEPT/NF_DROP): jumps and gotos
/// name their chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
    Continue,
    Break,
    Return,
    Jump(Vec<u8>),
    Goto(Vec<u8>),
}

impl Verdict {
    fn code(&self) -> i32 {
        match self {
            Verdict::Accept => NF_ACCEPT,
            Verdict::Drop => NF_DROP,
            Verdict::Continue => NFT_CONTINUE,
            Verdict::Break => NFT_BREAK,
            Verdict::Return => NFT_RETURN,
            Verdict::Jump(_) => NFT_JUMP,
            Verdict::Goto(_) => NFT_GOTO,
        }
    }

    /// From a NFTA_DATA_VERDICT nest; `chain_ids` names chains made in the
    /// same transaction by their NFTA_CHAIN_ID.
    pub fn parse(a: Attrs<'_>, chain_ids: &dyn Fn(u32) -> Option<Vec<u8>>) -> Result<Verdict, i32> {
        let code = a.get(NFTA_VERDICT_CODE).and_then(|c| c.i32()).ok_or(EINVAL)?;
        let target = || -> Result<Vec<u8>, i32> {
            if let Some(n) = a.get(NFTA_VERDICT_CHAIN).and_then(|c| c.str()) {
                return Ok(n.to_vec());
            }
            a.get(NFTA_VERDICT_CHAIN_ID).and_then(|c| c.u32()).and_then(chain_ids).ok_or(ENOENT)
        };
        Ok(match code {
            NF_ACCEPT => Verdict::Accept,
            NF_DROP => Verdict::Drop,
            NFT_CONTINUE => Verdict::Continue,
            NFT_BREAK => Verdict::Break,
            NFT_RETURN => Verdict::Return,
            NFT_JUMP => Verdict::Jump(target()?),
            NFT_GOTO => Verdict::Goto(target()?),
            _ => return Err(EINVAL),
        })
    }

    /// As a NFTA_DATA_VERDICT nest in `m` (inside an open data nest).
    pub fn dump(&self, m: &mut Msg) {
        m.nest(NFTA_DATA_VERDICT);
        m.u32(NFTA_VERDICT_CODE, self.code() as u32);
        if let Verdict::Jump(c) | Verdict::Goto(c) = self {
            m.str(NFTA_VERDICT_CHAIN, c);
        }
        m.end();
    }
}

/// An immediate's or a map's data: bytes, or a verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Data {
    Value(Vec<u8>),
    Verdict(Verdict),
}

impl Data {
    pub fn parse(a: Attr<'_>, chain_ids: &dyn Fn(u32) -> Option<Vec<u8>>) -> Result<Data, i32> {
        let n = a.nested();
        if let Some(v) = n.get(NFTA_DATA_VALUE) {
            if v.value.is_empty() || v.value.len() > 64 {
                return Err(EINVAL);
            }
            return Ok(Data::Value(v.value.to_vec()));
        }
        n.get(NFTA_DATA_VERDICT).map(|v| Verdict::parse(v.nested(), chain_ids).map(Data::Verdict)).ok_or(EINVAL)?
    }

    /// As an attribute `kind` holding the data nest.
    pub fn dump(&self, m: &mut Msg, kind: u16) {
        m.nest(kind);
        match self {
            Data::Value(v) => {
                m.attr(NFTA_DATA_VALUE, v);
            }
            Data::Verdict(v) => v.dump(m),
        }
        m.end();
    }
}

/// One expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    Immediate {
        dreg: u32,
        data: Data,
    },
    Cmp {
        sreg: u32,
        op: u32,
        data: Vec<u8>,
    },
    Range {
        sreg: u32,
        op: u32,
        from: Vec<u8>,
        to: Vec<u8>,
    },
    /// Mask and xor (op 0), or a shift by `shift` (ops 1, 2).
    Bitwise {
        sreg: u32,
        dreg: u32,
        len: u32,
        op: u32,
        mask: Vec<u8>,
        xor: Vec<u8>,
        shift: u32,
    },
    /// A set by name; `dreg` for a map's data; `inv` for "not in".
    Lookup {
        set: Vec<u8>,
        sreg: u32,
        dreg: Option<u32>,
        inv: bool,
    },
    Payload {
        dreg: u32,
        base: u32,
        offset: u32,
        len: u32,
    },
    Meta {
        key: u32,
        dreg: Option<u32>,
        sreg: Option<u32>,
    },
    Ct {
        key: u32,
        dreg: Option<u32>,
        dir: Option<u8>,
        sreg: Option<u32>,
    },
    Counter {
        bytes: u64,
        packets: u64,
    },
    Reject {
        kind: u32,
        code: u8,
    },
    /// snat or dnat (`kind`) to the address range in two registers and
    /// the port range in two more (ADR 0132).
    Nat {
        kind: u32,
        family: u32,
        addr: Option<(u32, u32)>,
        proto: Option<(u32, u32)>,
        flags: u32,
    },
    /// Source NAT to the outgoing interface's address.
    Masq {
        flags: u32,
        proto: Option<(u32, u32)>,
    },
    /// Destination NAT to this host (the incoming interface's address).
    Redir {
        flags: u32,
        proto: Option<(u32, u32)>,
    },
    /// An xtables match or target (`target`), by name and revision with
    /// its structure as given, and as Slate runs it (ADR 0133).
    Xt {
        target: bool,
        name: Vec<u8>,
        rev: u32,
        info: Vec<u8>,
        x: crate::compat::Xt,
    },
}

impl Expr {
    /// Whether this is a NAT statement (valid only in nat chains).
    pub fn is_nat(&self) -> bool {
        matches!(self, Expr::Nat { .. } | Expr::Masq { .. } | Expr::Redir { .. })
            || matches!(self, Expr::Xt { x, .. } if x.nat_hooks() != 0)
    }

    /// The hooks a NAT statement may run at (nft(8): snat at postrouting
    /// and input, dnat and redirect at prerouting and output, masquerade
    /// at postrouting), as a bit per hook.
    pub fn nat_hooks(&self) -> u32 {
        let bit = |h: u32| 1u32 << h;
        match self {
            Expr::Nat { kind: NFT_NAT_SNAT, .. } => bit(NF_INET_POST_ROUTING) | bit(NF_INET_LOCAL_IN),
            Expr::Nat { .. } | Expr::Redir { .. } => bit(NF_INET_PRE_ROUTING) | bit(NF_INET_LOCAL_OUT),
            Expr::Masq { .. } => bit(NF_INET_POST_ROUTING),
            Expr::Xt { x, .. } => x.nat_hooks(),
            _ => 0,
        }
    }
}

/// Errno values of nf_tables' answers (musl `errno.h`).
pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const E2BIG: i32 = 7;
pub const EBUSY: i32 = 16;
pub const EEXIST: i32 = 17;
pub const EINVAL: i32 = 22;
pub const ERANGE: i32 = 34;
pub const ELOOP: i32 = 40;
pub const EOPNOTSUPP: i32 = 95;
pub const EAFNOSUPPORT: i32 = 97;
pub const ERESTART: i32 = 85;

/// A register as a byte range of the 64 data bytes: NFT_REG_1 to 4 are
/// 16 bytes each, NFT_REG32_00 to 15 four each, overlapping them.
pub fn reg_offset(reg: u32, len: usize) -> Result<usize, i32> {
    let at = match reg {
        1..=4 => (reg as usize - 1) * 16,
        NFT_REG32_00..=NFT_REG32_15 => (reg - NFT_REG32_00) as usize * 4,
        _ => return Err(ERANGE),
    };
    if len == 0 || at + len > 64 {
        return Err(ERANGE);
    }
    Ok(at)
}

impl Expr {
    /// Parse one NFTA_LIST_ELEM of a rule's expressions. `set_ids` names
    /// sets made in the same transaction by their NFTA_SET_ID. `Err` is an
    /// errno; an expression Slate doesn't have is ENOENT, as Linux answers
    /// for one it lacks a module for (its name is in `unknown`).
    pub fn parse(
        e: Attrs<'_>,
        family: u8,
        set_ids: &dyn Fn(u32) -> Option<Vec<u8>>,
        chain_ids: &dyn Fn(u32) -> Option<Vec<u8>>,
        unknown: &mut Vec<u8>,
    ) -> Result<Expr, i32> {
        let name = e.get(NFTA_EXPR_NAME).and_then(|n| n.str()).ok_or(EINVAL)?;
        let d = e.get(NFTA_EXPR_DATA).map(|d| d.nested()).unwrap_or(Attrs(&[]));
        let u32_of = |k: u16| d.get(k).and_then(|a| a.u32());
        let need = |k: u16| u32_of(k).ok_or(EINVAL);
        let value = |k: u16| -> Result<Vec<u8>, i32> {
            match Data::parse(d.get(k).ok_or(EINVAL)?, chain_ids)? {
                Data::Value(v) => Ok(v),
                Data::Verdict(_) => Err(EINVAL),
            }
        };
        let e = match name {
            b"immediate" => {
                let dreg = need(NFTA_IMMEDIATE_DREG)?;
                let data = Data::parse(d.get(NFTA_IMMEDIATE_DATA).ok_or(EINVAL)?, chain_ids)?;
                match &data {
                    Data::Verdict(_) if dreg != NFT_REG_VERDICT => return Err(EINVAL),
                    Data::Value(v) => {
                        reg_offset(dreg, v.len())?;
                    }
                    _ => {}
                }
                Expr::Immediate { dreg, data }
            }
            b"cmp" => {
                let (sreg, op, data) = (need(NFTA_CMP_SREG)?, need(NFTA_CMP_OP)?, value(NFTA_CMP_DATA)?);
                if op > NFT_CMP_GTE {
                    return Err(EINVAL);
                }
                reg_offset(sreg, data.len())?;
                Expr::Cmp { sreg, op, data }
            }
            b"range" => {
                let (sreg, op) = (need(NFTA_RANGE_SREG)?, need(NFTA_RANGE_OP)?);
                let (from, to) = (value(NFTA_RANGE_FROM_DATA)?, value(NFTA_RANGE_TO_DATA)?);
                if op > 1 || from.len() != to.len() {
                    return Err(EINVAL);
                }
                reg_offset(sreg, from.len())?;
                Expr::Range { sreg, op, from, to }
            }
            b"bitwise" => {
                let (sreg, dreg, len) = (need(NFTA_BITWISE_SREG)?, need(NFTA_BITWISE_DREG)?, need(NFTA_BITWISE_LEN)?);
                let op = u32_of(NFTA_BITWISE_OP).unwrap_or(NFT_BITWISE_MASK_XOR);
                reg_offset(sreg, len as usize)?;
                reg_offset(dreg, len as usize)?;
                let (mut mask, mut xor, mut shift) = (Vec::new(), Vec::new(), 0);
                match op {
                    NFT_BITWISE_MASK_XOR => {
                        (mask, xor) = (value(NFTA_BITWISE_MASK)?, value(NFTA_BITWISE_XOR)?);
                        if mask.len() != len as usize || xor.len() != len as usize {
                            return Err(EINVAL);
                        }
                    }
                    NFT_BITWISE_LSHIFT | NFT_BITWISE_RSHIFT => {
                        let s = value(NFTA_BITWISE_DATA)?;
                        shift = u32::from_ne_bytes(s.get(..4).ok_or(EINVAL)?.try_into().unwrap());
                        if shift >= 32 || len % 4 != 0 {
                            return Err(EINVAL);
                        }
                    }
                    _ => return Err(EOPNOTSUPP),
                }
                Expr::Bitwise { sreg, dreg, len, op, mask, xor, shift }
            }
            b"lookup" => {
                let named = d.get(NFTA_LOOKUP_SET).and_then(|s| s.str()).map(|s| s.to_vec());
                let by_id = u32_of(NFTA_LOOKUP_SET_ID).and_then(set_ids);
                // A set made in this transaction is known by its id (its
                // name may still be the "__set%d" template).
                let set = by_id.or(named).ok_or(EINVAL)?;
                Expr::Lookup {
                    set,
                    sreg: need(NFTA_LOOKUP_SREG)?,
                    dreg: u32_of(NFTA_LOOKUP_DREG),
                    inv: u32_of(NFTA_LOOKUP_FLAGS).unwrap_or(0) & NFT_LOOKUP_F_INV != 0,
                }
            }
            b"payload" => {
                if d.get(NFTA_PAYLOAD_SREG).is_some() {
                    // Rewriting packets (payload set) isn't done.
                    return Err(EOPNOTSUPP);
                }
                let (dreg, base) = (need(NFTA_PAYLOAD_DREG)?, need(NFTA_PAYLOAD_BASE)?);
                let (offset, len) = (need(NFTA_PAYLOAD_OFFSET)?, need(NFTA_PAYLOAD_LEN)?);
                if base > NFT_PAYLOAD_TRANSPORT_HEADER {
                    return Err(EOPNOTSUPP);
                }
                reg_offset(dreg, len as usize)?;
                Expr::Payload { dreg, base, offset, len }
            }
            b"meta" => {
                let key = need(NFTA_META_KEY)?;
                let (dreg, sreg) = (u32_of(NFTA_META_DREG), u32_of(NFTA_META_SREG));
                if dreg.is_none() == sreg.is_none() {
                    return Err(EINVAL);
                }
                // What evaluation knows (the mark the only one set).
                let known = matches!(
                    key,
                    NFT_META_LEN
                        | NFT_META_PROTOCOL
                        | NFT_META_MARK
                        | NFT_META_IIF
                        | NFT_META_OIF
                        | NFT_META_IIFNAME
                        | NFT_META_OIFNAME
                        | NFT_META_IIFTYPE
                        | NFT_META_OIFTYPE
                        | NFT_META_SKUID
                        | NFT_META_SKGID
                        | NFT_META_NFPROTO
                        | NFT_META_L4PROTO
                        | NFT_META_PKTTYPE
                );
                if !known || (sreg.is_some() && key != NFT_META_MARK) {
                    return Err(EOPNOTSUPP);
                }
                Expr::Meta { key, dreg, sreg }
            }
            b"ct" => {
                let key = need(NFTA_CT_KEY)?;
                let (dreg, sreg) = (u32_of(NFTA_CT_DREG), u32_of(NFTA_CT_SREG));
                if dreg.is_none() == sreg.is_none() {
                    return Err(EINVAL);
                }
                // States and directions only; nothing is set.
                if sreg.is_some() || !matches!(key, NFT_CT_STATE | NFT_CT_DIRECTION) {
                    return Err(EOPNOTSUPP);
                }
                Expr::Ct { key, dreg, dir: d.get(NFTA_CT_DIRECTION).and_then(|a| a.u8()), sreg }
            }
            b"counter" => Expr::Counter {
                bytes: d.get(NFTA_COUNTER_BYTES).and_then(|a| a.u64()).unwrap_or(0),
                packets: d.get(NFTA_COUNTER_PACKETS).and_then(|a| a.u64()).unwrap_or(0),
            },
            b"nat" | b"masq" | b"redir" => {
                // A port range is two bytes in a register; an address four
                // or sixteen, by the family. The ends default to the start.
                let range = |lo: u16, hi: u16, len: usize| -> Result<Option<(u32, u32)>, i32> {
                    let Some(min) = u32_of(lo) else { return Ok(None) };
                    let max = u32_of(hi).unwrap_or(min);
                    reg_offset(min, len)?;
                    reg_offset(max, len)?;
                    Ok(Some((min, max)))
                };
                match name {
                    b"nat" => {
                        let (kind, family) = (need(NFTA_NAT_TYPE)?, need(NFTA_NAT_FAMILY)?);
                        if kind > NFT_NAT_DNAT {
                            return Err(EOPNOTSUPP);
                        }
                        let len = match family as u8 {
                            NFPROTO_IPV4 => 4,
                            NFPROTO_IPV6 => 16,
                            _ => return Err(EAFNOSUPPORT),
                        };
                        let addr = range(NFTA_NAT_REG_ADDR_MIN, NFTA_NAT_REG_ADDR_MAX, len)?;
                        let proto = range(NFTA_NAT_REG_PROTO_MIN, NFTA_NAT_REG_PROTO_MAX, 2)?;
                        let mut flags = u32_of(NFTA_NAT_FLAGS).unwrap_or(0);
                        if flags & !NF_NAT_RANGE_MASK != 0 {
                            return Err(EOPNOTSUPP);
                        }
                        // Linux notes what was given in the flags (observed:
                        // `dnat to 10.1.0.3` dumps flags 1).
                        if addr.is_some() {
                            flags |= NF_NAT_RANGE_MAP_IPS;
                        }
                        if proto.is_some() {
                            flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
                        }
                        Expr::Nat { kind, family, addr, proto, flags }
                    }
                    b"masq" => {
                        let proto = range(NFTA_MASQ_REG_PROTO_MIN, NFTA_MASQ_REG_PROTO_MAX, 2)?;
                        let mut flags = u32_of(NFTA_MASQ_FLAGS).unwrap_or(0);
                        if flags & !NF_NAT_RANGE_MASK != 0 {
                            return Err(EINVAL);
                        }
                        if proto.is_some() {
                            flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
                        }
                        Expr::Masq { flags, proto }
                    }
                    _ => {
                        let proto = range(NFTA_REDIR_REG_PROTO_MIN, NFTA_REDIR_REG_PROTO_MAX, 2)?;
                        let mut flags = u32_of(NFTA_REDIR_FLAGS).unwrap_or(0);
                        if flags & !NF_NAT_RANGE_MASK != 0 {
                            return Err(EINVAL);
                        }
                        if proto.is_some() {
                            flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
                        }
                        Expr::Redir { flags, proto }
                    }
                }
            }
            b"match" | b"target" => {
                let target = name == b"target";
                let xname = d.get(NFTA_MATCH_NAME).and_then(|a| a.str()).ok_or(EINVAL)?.to_vec();
                let rev = need(NFTA_MATCH_REV)?;
                let info = d.get(NFTA_MATCH_INFO).ok_or(EINVAL)?.value.to_vec();
                let x = if target {
                    crate::compat::parse_target(&xname, rev, &info, family)
                } else {
                    crate::compat::parse_match(&xname, rev, &info)
                };
                let x = x.inspect_err(|e| {
                    if *e == ENOENT {
                        unknown.clear();
                        unknown.extend_from_slice(&xname);
                    }
                })?;
                Expr::Xt { target, name: xname, rev, info, x }
            }
            b"reject" => {
                let kind = need(NFTA_REJECT_TYPE)?;
                if kind > NFT_REJECT_ICMPX_UNREACH {
                    return Err(EINVAL);
                }
                Expr::Reject { kind, code: d.get(NFTA_REJECT_ICMP_CODE).and_then(|a| a.u8()).unwrap_or(0) }
            }
            other => {
                unknown.clear();
                unknown.extend_from_slice(other);
                return Err(ENOENT);
            }
        };
        Ok(e)
    }

    /// Write this expression as a NFTA_LIST_ELEM into `m`.
    pub fn dump(&self, m: &mut Msg) {
        m.nest(NFTA_LIST_ELEM);
        let name: &[u8] = match self {
            Expr::Immediate { .. } => b"immediate",
            Expr::Cmp { .. } => b"cmp",
            Expr::Range { .. } => b"range",
            Expr::Bitwise { .. } => b"bitwise",
            Expr::Lookup { .. } => b"lookup",
            Expr::Payload { .. } => b"payload",
            Expr::Meta { .. } => b"meta",
            Expr::Ct { .. } => b"ct",
            Expr::Counter { .. } => b"counter",
            Expr::Reject { .. } => b"reject",
            Expr::Nat { .. } => b"nat",
            Expr::Masq { .. } => b"masq",
            Expr::Redir { .. } => b"redir",
            Expr::Xt { target: true, .. } => b"target",
            Expr::Xt { .. } => b"match",
        };
        m.str(NFTA_EXPR_NAME, name);
        m.nest(NFTA_EXPR_DATA);
        let value = |m: &mut Msg, kind: u16, v: &[u8]| {
            m.nest(kind);
            m.attr(NFTA_DATA_VALUE, v);
            m.end();
        };
        match self {
            Expr::Immediate { dreg, data } => {
                m.u32(NFTA_IMMEDIATE_DREG, *dreg);
                data.dump(m, NFTA_IMMEDIATE_DATA);
            }
            Expr::Cmp { sreg, op, data } => {
                m.u32(NFTA_CMP_SREG, *sreg).u32(NFTA_CMP_OP, *op);
                value(m, NFTA_CMP_DATA, data);
            }
            Expr::Range { sreg, op, from, to } => {
                m.u32(NFTA_RANGE_SREG, *sreg).u32(NFTA_RANGE_OP, *op);
                value(m, NFTA_RANGE_FROM_DATA, from);
                value(m, NFTA_RANGE_TO_DATA, to);
            }
            Expr::Bitwise { sreg, dreg, len, op, mask, xor, shift } => {
                m.u32(NFTA_BITWISE_SREG, *sreg).u32(NFTA_BITWISE_DREG, *dreg).u32(NFTA_BITWISE_LEN, *len);
                m.u32(NFTA_BITWISE_OP, *op);
                if *op == NFT_BITWISE_MASK_XOR {
                    value(m, NFTA_BITWISE_MASK, mask);
                    value(m, NFTA_BITWISE_XOR, xor);
                } else {
                    value(m, NFTA_BITWISE_DATA, &shift.to_ne_bytes());
                }
            }
            Expr::Lookup { set, sreg, dreg, inv } => {
                m.str(NFTA_LOOKUP_SET, set).u32(NFTA_LOOKUP_SREG, *sreg);
                if let Some(d) = dreg {
                    m.u32(NFTA_LOOKUP_DREG, *d);
                }
                m.u32(NFTA_LOOKUP_FLAGS, if *inv { NFT_LOOKUP_F_INV } else { 0 });
            }
            Expr::Payload { dreg, base, offset, len } => {
                m.u32(NFTA_PAYLOAD_DREG, *dreg).u32(NFTA_PAYLOAD_BASE, *base);
                m.u32(NFTA_PAYLOAD_OFFSET, *offset).u32(NFTA_PAYLOAD_LEN, *len);
            }
            Expr::Meta { key, dreg, sreg } => {
                m.u32(NFTA_META_KEY, *key);
                if let Some(r) = dreg {
                    m.u32(NFTA_META_DREG, *r);
                }
                if let Some(r) = sreg {
                    m.u32(NFTA_META_SREG, *r);
                }
            }
            Expr::Ct { key, dreg, dir, sreg } => {
                if let Some(r) = dreg {
                    m.u32(NFTA_CT_DREG, *r);
                }
                m.u32(NFTA_CT_KEY, *key);
                if let Some(d) = dir {
                    m.attr(NFTA_CT_DIRECTION, &[*d]);
                }
                if let Some(r) = sreg {
                    m.u32(NFTA_CT_SREG, *r);
                }
            }
            Expr::Counter { bytes, packets } => {
                m.u64(NFTA_COUNTER_BYTES, *bytes).u64(NFTA_COUNTER_PACKETS, *packets);
            }
            Expr::Reject { kind, code } => {
                m.u32(NFTA_REJECT_TYPE, *kind);
                if *kind != NFT_REJECT_TCP_RST {
                    m.attr(NFTA_REJECT_ICMP_CODE, &[*code]);
                }
            }
            // In attribute order, the ends always, flags when there are any
            // (observed in Linux's dumps).
            Expr::Nat { kind, family, addr, proto, flags } => {
                m.u32(NFTA_NAT_TYPE, *kind).u32(NFTA_NAT_FAMILY, *family);
                if let Some((lo, hi)) = addr {
                    m.u32(NFTA_NAT_REG_ADDR_MIN, *lo).u32(NFTA_NAT_REG_ADDR_MAX, *hi);
                }
                if let Some((lo, hi)) = proto {
                    m.u32(NFTA_NAT_REG_PROTO_MIN, *lo).u32(NFTA_NAT_REG_PROTO_MAX, *hi);
                }
                if *flags != 0 {
                    m.u32(NFTA_NAT_FLAGS, *flags);
                }
            }
            Expr::Masq { flags, proto } => {
                if *flags != 0 {
                    m.u32(NFTA_MASQ_FLAGS, *flags);
                }
                if let Some((lo, hi)) = proto {
                    m.u32(NFTA_MASQ_REG_PROTO_MIN, *lo).u32(NFTA_MASQ_REG_PROTO_MAX, *hi);
                }
            }
            Expr::Xt { name, rev, info, .. } => {
                m.str(NFTA_MATCH_NAME, name).u32(NFTA_MATCH_REV, *rev).attr(NFTA_MATCH_INFO, info);
            }
            Expr::Redir { flags, proto } => {
                if let Some((lo, hi)) = proto {
                    m.u32(NFTA_REDIR_REG_PROTO_MIN, *lo).u32(NFTA_REDIR_REG_PROTO_MAX, *hi);
                }
                if *flags != 0 {
                    m.u32(NFTA_REDIR_FLAGS, *flags);
                }
            }
        }
        m.end();
        m.end();
    }
}
