// SPDX-License-Identifier: MIT OR Apache-2.0

//! Running the ruleset on a packet (nft(8)'s semantics, ADR 0129): each
//! base chain on the packet's hook, lowest priority first, from tables of
//! the packet's family (inet takes both); within a chain, rules in order,
//! each a run of expressions over 64 bytes of registers until one fails to
//! match or a verdict ends it. Accept ends one base chain (the next still
//! runs); drop and reject end the packet; a chain without a verdict ends
//! in its policy.
//!
//! NAT (ADR 0132) happens at a point of its own in the hooks that have it:
//! at priority -100 in prerouting and output (destinations), 100 in
//! postrouting and input (sources). A flow's first packet runs the nat
//! chains of the hook there, which decide its translation (or that there
//! is none); every packet of the flow, either way, is then rewritten from
//! it, so the filter chains after that point see the translated packet.

use alloc::vec::Vec;

use crate::consts::*;
use crate::ct::{Conntrack, CtInfo, Target, Tracked};
use crate::expr::{Data, Expr, Verdict, reg_offset};
use crate::nat::{self, Rewrite};
use crate::ruleset::{Ruleset, Set};

/// An interface as the rules see it.
#[derive(Clone, Copy, Debug)]
pub struct Iface<'a> {
    pub index: u32,
    /// Its name (eth0), up to 15 bytes.
    pub name: &'a [u8],
    /// Its ARPHRD type: 1 for Ethernet, 772 for loopback.
    pub kind: u16,
}

/// A packet at a hook.
#[derive(Clone, Copy, Debug)]
pub struct Packet<'a> {
    /// NF_INET_PRE_ROUTING to NF_INET_POST_ROUTING.
    pub hook: u32,
    pub v6: bool,
    /// From the network header on.
    pub net: &'a [u8],
    /// The transport protocol and where its header starts in `net`; none
    /// for a fragment after the first.
    pub l4: Option<(u8, usize)>,
    /// The link-layer header, when there is one (arrivals).
    pub ll: Option<&'a [u8]>,
    pub iif: Option<Iface<'a>>,
    pub oif: Option<Iface<'a>>,
    /// Sent to this host, broadcast, multicast, other (PACKET_*).
    pub pkttype: u8,
    /// The sending socket's owner, for locally made packets.
    pub owner: Option<(u32, u32)>,
    /// This host's address on the interface it arrived on (prerouting) or
    /// leaves by (postrouting), for redirect and masquerade.
    pub local: Option<[u8; 16]>,
    /// The address types of its source and destination (XT_ADDRTYPE_*
    /// bits, for xtables' addrtype match), when a rule asks for them.
    pub types: (u16, u16),
}

/// How a reject answers: a TCP reset, or an ICMP or ICMPv6 unreachable
/// with this code (already the family's own).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    TcpReset,
    Unreachable(u8),
}

/// What happens to a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Accept,
    Drop,
    Reject(Reject),
}

/// The deepest jumps go (Linux: 16, observed as ELOOP when made).
const MAX_DEPTH: usize = 16;

/// A NAT statement as a rule ran it: which side, where to (addresses and
/// ports as the registers held them), and how.
#[derive(Clone, Copy, Debug)]
struct NatSpec {
    src: bool,
    addr: Option<[u8; 16]>,
    ports: Option<(u16, u16)>,
    flags: u32,
    how: How,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum How {
    Given,
    Masquerade,
    Redirect,
}

/// How a base chain ended.
enum End {
    Out(Outcome),
    Nat(NatSpec),
}

/// Where NAT happens in a hook, by priority (NF_IP_PRI_NAT_DST and
/// NF_IP_PRI_NAT_SRC in nft(8)'s table of priorities: dstnat, srcnat), and
/// whether it changes sources there.
fn nat_point(hook: u32) -> Option<(i32, bool)> {
    match hook {
        NF_INET_PRE_ROUTING | NF_INET_LOCAL_OUT => Some((-100, false)),
        NF_INET_POST_ROUTING | NF_INET_LOCAL_IN => Some((100, true)),
        _ => None,
    }
}

impl Ruleset {
    /// What the rules ask of the stack, worked out again only when the
    /// ruleset changed.
    fn features(&self) -> crate::ruleset::Features {
        let chains: usize = self.tables.iter().map(|t| t.chains.len()).sum();
        let rules: usize = self.tables.iter().flat_map(|t| t.chains.iter()).map(|c| c.rules.len()).sum();
        let key = (self.generation, self.tables.len() + chains, rules);
        if let Some((k, f)) = self.features.get()
            && k == key
        {
            return f;
        }
        let exprs = || {
            self.tables.iter().flat_map(|t| t.chains.iter()).flat_map(|c| c.rules.iter()).flat_map(|r| r.exprs.iter())
        };
        let is_nat = |c: &crate::ruleset::Chain| c.base.as_ref().is_some_and(|b| b.kind == b"nat");
        let nat = |family: u8| {
            self.tables
                .iter()
                .filter(|t| t.family == family || t.family == NFPROTO_INET)
                .any(|t| t.flags & NFT_TABLE_F_DORMANT == 0 && t.chains.iter().any(is_nat))
        };
        use crate::compat::Xt;
        let f = crate::ruleset::Features {
            ct: self.tables.iter().flat_map(|t| t.chains.iter()).any(is_nat)
                || exprs().any(|e| {
                    matches!(e, Expr::Ct { .. } | Expr::Xt { x: Xt::Conntrack { .. } | Xt::State { .. }, .. })
                }),
            nat4: nat(NFPROTO_IPV4),
            nat6: nat(NFPROTO_IPV6),
            addrtype: exprs().any(|e| matches!(e, Expr::Xt { x, .. } if crate::compat::uses_addrtype(x))),
        };
        self.features.set(Some((key, f)));
        f
    }

    /// Whether a rule anywhere asks for connection states (nf_tables' ct,
    /// xtables' conntrack and state), or a nat chain needs them.
    pub fn uses_ct(&self) -> bool {
        self.features().ct
    }

    /// Whether a rule asks for address types (xtables' addrtype match).
    pub fn uses_addrtype(&self) -> bool {
        self.features().addrtype
    }

    /// Whether a nat chain is there for packets of this family.
    pub fn has_nat(&self, v6: bool) -> bool {
        let f = self.features();
        if v6 { f.nat6 } else { f.nat4 }
    }

    /// The base chains of `kind` on `p`'s hook, by priority: (priority,
    /// table, chain).
    fn bases(&self, p: &Packet<'_>, kind: &[u8]) -> Vec<(i32, usize, usize)> {
        let family = if p.v6 { NFPROTO_IPV6 } else { NFPROTO_IPV4 };
        let mut bases = Vec::new();
        for (ti, t) in self.tables.iter().enumerate() {
            if !(t.family == family || t.family == NFPROTO_INET) || t.flags & NFT_TABLE_F_DORMANT != 0 {
                continue;
            }
            for (ci, c) in t.chains.iter().enumerate() {
                if let Some(b) = &c.base
                    && b.hook == p.hook
                    && b.kind == kind
                {
                    bases.push((b.priority, ti, ci));
                }
            }
        }
        bases.sort_by_key(|b| b.0);
        bases
    }

    /// Run hook `p.hook` on the packet in `net` (which `p` shows): the
    /// filter chains and, where the hook has one, the NAT point, in
    /// priority order. `tracked` is the packet's connection: tracked here
    /// if it isn't yet (the first hook it meets), then carried to its
    /// other hooks. NAT may rewrite `net`; what comes after sees it so.
    pub fn process(
        &mut self,
        ct: &mut Conntrack,
        net: &mut [u8],
        p: &Packet<'_>,
        tracked: &mut Option<Tracked>,
        now: u64,
        mark: &mut u32,
    ) -> Outcome {
        if tracked.is_none() && self.uses_ct() {
            *tracked = ct.track(p.v6, net, p.l4, now);
        }
        let info = tracked.map(|t| t.info);
        let mut steps: Vec<(i32, Option<(usize, usize)>)> =
            self.bases(p, b"filter").into_iter().map(|(pr, t, c)| (pr, Some((t, c)))).collect();
        if let Some((prio, _)) = nat_point(p.hook).filter(|_| self.has_nat(p.v6)) {
            // After the filter chains of the same priority.
            let at = steps.iter().position(|s| s.0 > prio).unwrap_or(steps.len());
            steps.insert(at, (prio, None));
        }
        for (_, step) in steps {
            let pk = Packet { net: &net[..], ..*p };
            match step {
                Some((ti, ci)) => match self.run_base(ti, ci, &pk, info, mark) {
                    End::Out(Outcome::Accept) | End::Nat(_) => {}
                    End::Out(o) => return o,
                },
                None => {
                    let Some(tr) = tracked.as_ref() else { continue };
                    let src = nat_point(p.hook).is_some_and(|n| n.1);
                    if ct.undecided(tr, src) {
                        let spec = match self.nat_chains(&pk, info, mark) {
                            Ok(s) => s,
                            Err(o) => return o,
                        };
                        let target = match spec {
                            Some(s) => match resolve(&s, &pk) {
                                Some(t) => Some(t),
                                // Masquerade with no address to take: dropped.
                                None => return Outcome::Drop,
                            },
                            None => None,
                        };
                        if !ct.bind(tr, src, target, Conntrack::seed(tr)) {
                            return Outcome::Drop;
                        }
                    }
                    if let Some(rw) = ct.manip(tr, src) {
                        apply(net, p, tr, rw);
                    }
                }
            }
        }
        Outcome::Accept
    }

    /// The nat chains of the packet's hook, in order, until one decides a
    /// translation: a NAT statement, or none when they all end without
    /// one. A drop or reject in them ends the packet.
    fn nat_chains(&mut self, p: &Packet<'_>, ct: Option<CtInfo>, mark: &mut u32) -> Result<Option<NatSpec>, Outcome> {
        for (_, ti, ci) in self.bases(p, b"nat") {
            match self.run_base(ti, ci, p, ct, mark) {
                End::Nat(s) => return Ok(Some(s)),
                End::Out(Outcome::Accept) => {}
                End::Out(o) => return Err(o),
            }
        }
        Ok(None)
    }

    /// Run the base chains of `p`'s hook; `ct` is the connection state the
    /// tracker gave (or none), `mark` the packet's mark, which rules may
    /// read and set.
    pub fn evaluate(&mut self, p: &Packet<'_>, ct: Option<CtInfo>, mark: &mut u32) -> Outcome {
        for (_, ti, ci) in self.bases(p, b"filter") {
            match self.run_base(ti, ci, p, ct, mark) {
                End::Out(Outcome::Accept) | End::Nat(_) => {}
                End::Out(o) => return o,
            }
        }
        Outcome::Accept
    }

    /// One base chain, with its jumps.
    fn run_base(&mut self, ti: usize, ci: usize, p: &Packet<'_>, ct: Option<CtInfo>, mark: &mut u32) -> End {
        let t = &mut self.tables[ti];
        let policy = t.chains[ci].base.as_ref().map_or(NF_ACCEPT, |b| b.policy);
        // Where to go back to after a jump: (chain, next rule).
        let mut stack: Vec<(usize, usize)> = Vec::new();
        let (mut chain, mut rule) = (ci, 0);
        loop {
            if rule >= t.chains[chain].rules.len() {
                match stack.pop() {
                    Some((c, r)) => {
                        (chain, rule) = (c, r);
                        continue;
                    }
                    None => return End::Out(if policy == NF_DROP { Outcome::Drop } else { Outcome::Accept }),
                }
            }
            let v = run_rule(&mut t.chains[chain].rules[rule].exprs, &t.sets, p, ct, mark);
            rule += 1;
            let target = |name: &[u8]| t.chains.iter().position(|c| c.name == name);
            match v {
                Step::Next => {}
                Step::Out(o) => return End::Out(o),
                Step::Nat(s) => return End::Nat(s),
                Step::Verdict(Verdict::Accept) => return End::Out(Outcome::Accept),
                Step::Verdict(Verdict::Drop) => return End::Out(Outcome::Drop),
                Step::Verdict(Verdict::Continue | Verdict::Break) => {}
                Step::Verdict(Verdict::Return) => match stack.pop() {
                    Some((c, r)) => (chain, rule) = (c, r),
                    None => return End::Out(if policy == NF_DROP { Outcome::Drop } else { Outcome::Accept }),
                },
                Step::Verdict(Verdict::Jump(n)) => {
                    let Some(c) = target(&n) else { continue };
                    if stack.len() >= MAX_DEPTH {
                        return End::Out(Outcome::Drop);
                    }
                    stack.push((chain, rule));
                    (chain, rule) = (c, 0);
                }
                Step::Verdict(Verdict::Goto(n)) => {
                    let Some(c) = target(&n) else { continue };
                    (chain, rule) = (c, 0);
                }
            }
        }
    }
}

/// How a rule ended: not matched (or matched with no verdict), a verdict,
/// a reject, or a NAT statement.
enum Step {
    Next,
    Verdict(Verdict),
    Out(Outcome),
    Nat(NatSpec),
}

/// Where a NAT statement takes the packet's flow: its address (the
/// interface's for masquerade, this host's for redirect: loopback in
/// output), the ports.
fn resolve(s: &NatSpec, p: &Packet<'_>) -> Option<Target> {
    let loopback = || {
        let mut a = [0u8; 16];
        if p.v6 {
            a[15] = 1;
        } else {
            a[..4].copy_from_slice(&[127, 0, 0, 1]);
        }
        a
    };
    let current = |at: usize| {
        let mut a = [0u8; 16];
        let len = if p.v6 { 16 } else { 4 };
        a[..len].copy_from_slice(p.net.get(at..at + len)?);
        Some(a)
    };
    let addr = match s.how {
        How::Masquerade => p.local?,
        How::Redirect if p.hook == NF_INET_LOCAL_OUT => loopback(),
        How::Redirect => p.local?,
        // Only ports given: the address stays.
        How::Given => match s.addr {
            Some(a) => a,
            None if s.src => current(if p.v6 { 8 } else { 12 })?,
            None => current(if p.v6 { 24 } else { 16 })?,
        },
    };
    let random = s.flags & (NF_NAT_RANGE_PROTO_RANDOM | NF_NAT_RANGE_PROTO_RANDOM_FULLY) != 0;
    Some(Target { addr, ports: s.ports, random })
}

/// Rewrite the packet as NAT says, an ICMP error with what it quotes.
fn apply(net: &mut [u8], p: &Packet<'_>, tr: &Tracked, rw: Rewrite) {
    if Conntrack::is_related(tr) {
        nat::rewrite_related(net, p.v6, p.l4, rw);
    } else {
        nat::rewrite(net, p.v6, p.l4, rw);
    }
}

fn run_rule(exprs: &mut [Expr], sets: &[Set], p: &Packet<'_>, ct: Option<CtInfo>, mark: &mut u32) -> Step {
    let mut regs = [0u8; 64];
    for e in exprs.iter_mut() {
        match eval(e, &mut regs, sets, p, ct, mark) {
            Ok(None) => {}
            Ok(Some(s)) => return s,
            // The expression didn't match (or had nothing to look at).
            Err(()) => return Step::Next,
        }
    }
    Step::Next
}

/// Write `v` to register `reg`.
fn store(regs: &mut [u8; 64], reg: u32, v: &[u8]) -> Result<(), ()> {
    let at = reg_offset(reg, v.len()).map_err(|_| ())?;
    regs[at..at + v.len()].copy_from_slice(v);
    Ok(())
}

/// A value of under four bytes is stored zero-extended to four, as Linux
/// stores a byte or a half-word.
fn store_word(regs: &mut [u8; 64], reg: u32, v: &[u8]) -> Result<(), ()> {
    let mut w = [0u8; 4];
    w[..v.len().min(4)].copy_from_slice(&v[..v.len().min(4)]);
    store(regs, reg, if v.len() < 4 { &w } else { v })
}

fn load(regs: &[u8; 64], reg: u32, len: usize) -> Result<&[u8], ()> {
    let at = reg_offset(reg, len).map_err(|_| ())?;
    Ok(&regs[at..at + len])
}

fn eval(
    e: &mut Expr,
    regs: &mut [u8; 64],
    sets: &[Set],
    p: &Packet<'_>,
    ct: Option<CtInfo>,
    mark: &mut u32,
) -> Result<Option<Step>, ()> {
    match e {
        Expr::Immediate { dreg, data } => match data {
            Data::Verdict(v) => return Ok(Some(Step::Verdict(v.clone()))),
            Data::Value(v) => store(regs, *dreg, v)?,
        },
        Expr::Cmp { sreg, op, data } => {
            let x = load(regs, *sreg, data.len())?;
            let ord = x.cmp(data.as_slice());
            let ok = match *op {
                NFT_CMP_EQ => ord.is_eq(),
                NFT_CMP_NEQ => ord.is_ne(),
                NFT_CMP_LT => ord.is_lt(),
                NFT_CMP_LTE => ord.is_le(),
                NFT_CMP_GT => ord.is_gt(),
                _ => ord.is_ge(),
            };
            if !ok {
                return Err(());
            }
        }
        Expr::Range { sreg, op, from, to } => {
            let x = load(regs, *sreg, from.len())?;
            let inside = x >= from.as_slice() && x <= to.as_slice();
            if inside != (*op == NFT_RANGE_EQ) {
                return Err(());
            }
        }
        Expr::Bitwise { sreg, dreg, len, op, mask, xor, shift } => {
            let x: Vec<u8> = load(regs, *sreg, *len as usize)?.to_vec();
            let y: Vec<u8> = match *op {
                NFT_BITWISE_MASK_XOR => {
                    x.iter().zip(mask.iter()).zip(xor.iter()).map(|((a, m), x)| (a & m) ^ x).collect()
                }
                // Shifts work on the register's 32-bit words (in host
                // order), carrying from word to word.
                _ => {
                    let words: Vec<u32> = x.chunks(4).map(|c| u32::from_ne_bytes(c.try_into().unwrap())).collect();
                    let mut out = alloc::vec![0u32; words.len()];
                    let s = *shift;
                    if *op == NFT_BITWISE_LSHIFT {
                        let mut carry = 0u32;
                        for i in (0..words.len()).rev() {
                            out[i] = (words[i] << s) | carry;
                            carry = if s == 0 { 0 } else { words[i] >> (32 - s) };
                        }
                    } else {
                        let mut carry = 0u32;
                        for i in 0..words.len() {
                            out[i] = (words[i] >> s) | carry;
                            carry = if s == 0 { 0 } else { words[i] << (32 - s) };
                        }
                    }
                    out.iter().flat_map(|w| w.to_ne_bytes()).collect()
                }
            };
            store(regs, *dreg, &y)?;
        }
        Expr::Lookup { set, sreg, dreg, inv } => {
            let s = sets.iter().find(|s| &s.name == set).ok_or(())?;
            let key = load(regs, *sreg, s.key_len as usize)?.to_vec();
            let found = lookup(s, &key);
            if found.is_some() == *inv {
                return Err(());
            }
            if let (Some(d), Some(e)) = (dreg, found) {
                match &e.data {
                    Some(Data::Verdict(v)) => return Ok(Some(Step::Verdict(v.clone()))),
                    Some(Data::Value(v)) => store(regs, *d, v)?,
                    None => return Err(()),
                }
            }
        }
        Expr::Payload { dreg, base, offset, len } => {
            let from: &[u8] = match *base {
                NFT_PAYLOAD_LL_HEADER => p.ll.ok_or(())?,
                NFT_PAYLOAD_NETWORK_HEADER => p.net,
                _ => {
                    let (_, at) = p.l4.ok_or(())?;
                    p.net.get(at..).ok_or(())?
                }
            };
            let v = from.get(*offset as usize..(*offset + *len) as usize).ok_or(())?;
            store(regs, *dreg, v)?;
        }
        Expr::Meta { key, dreg, sreg } => {
            if let Some(s) = sreg {
                // Only the mark may be set.
                *mark = u32::from_ne_bytes(load(regs, *s, 4)?.try_into().unwrap());
                return Ok(None);
            }
            let d = dreg.ok_or(())?;
            let name16 = |i: Option<Iface<'_>>| -> Result<[u8; 16], ()> {
                let mut n = [0u8; 16];
                let i = i.ok_or(())?;
                n[..i.name.len().min(15)].copy_from_slice(&i.name[..i.name.len().min(15)]);
                Ok(n)
            };
            match *key {
                NFT_META_LEN => store(regs, d, &(p.net.len() as u32).to_ne_bytes())?,
                NFT_META_PROTOCOL => store_word(regs, d, &(if p.v6 { 0x86DDu16 } else { 0x0800 }).to_be_bytes())?,
                NFT_META_MARK => store(regs, d, &mark.to_ne_bytes())?,
                NFT_META_IIF => store(regs, d, &p.iif.ok_or(())?.index.to_ne_bytes())?,
                NFT_META_OIF => store(regs, d, &p.oif.ok_or(())?.index.to_ne_bytes())?,
                NFT_META_IIFNAME => store(regs, d, &name16(p.iif)?)?,
                NFT_META_OIFNAME => store(regs, d, &name16(p.oif)?)?,
                NFT_META_IIFTYPE => store_word(regs, d, &p.iif.ok_or(())?.kind.to_ne_bytes())?,
                NFT_META_OIFTYPE => store_word(regs, d, &p.oif.ok_or(())?.kind.to_ne_bytes())?,
                NFT_META_SKUID => store(regs, d, &p.owner.ok_or(())?.0.to_ne_bytes())?,
                NFT_META_SKGID => store(regs, d, &p.owner.ok_or(())?.1.to_ne_bytes())?,
                NFT_META_NFPROTO => store_word(regs, d, &[if p.v6 { NFPROTO_IPV6 } else { NFPROTO_IPV4 }])?,
                NFT_META_L4PROTO => store_word(regs, d, &[p.l4.ok_or(())?.0])?,
                NFT_META_PKTTYPE => store_word(regs, d, &[p.pkttype])?,
                _ => return Err(()),
            }
        }
        Expr::Ct { key, dreg, sreg, .. } => {
            if sreg.is_some() {
                return Ok(None);
            }
            let d = dreg.ok_or(())?;
            match *key {
                NFT_CT_STATE => {
                    let bits = ct.map_or(NF_CT_STATE_UNTRACKED_BIT, |c| c.state);
                    store(regs, d, &bits.to_ne_bytes())?;
                }
                NFT_CT_DIRECTION => store_word(regs, d, &[ct.ok_or(())?.reply as u8])?,
                _ => return Err(()),
            }
        }
        Expr::Counter { bytes, packets } => {
            *packets += 1;
            *bytes += p.net.len() as u64;
        }
        Expr::Nat { kind, family, addr, proto, flags } => {
            let len = if *family as u8 == NFPROTO_IPV6 { 16 } else { 4 };
            let a = match addr {
                Some((lo, _)) => {
                    let mut a = [0u8; 16];
                    a[..len].copy_from_slice(load(regs, *lo, len)?);
                    Some(a)
                }
                None => None,
            };
            let ports = ports_of(regs, *proto)?;
            let src = *kind == NFT_NAT_SNAT;
            return Ok(Some(Step::Nat(NatSpec { src, addr: a, ports, flags: *flags, how: How::Given })));
        }
        Expr::Masq { flags, proto } => {
            let ports = ports_of(regs, *proto)?;
            return Ok(Some(Step::Nat(NatSpec { src: true, addr: None, ports, flags: *flags, how: How::Masquerade })));
        }
        Expr::Redir { flags, proto } => {
            let ports = ports_of(regs, *proto)?;
            return Ok(Some(Step::Nat(NatSpec { src: false, addr: None, ports, flags: *flags, how: How::Redirect })));
        }
        Expr::Xt { x: crate::compat::Xt::Nat { src, how, addr, ports, flags }, .. } => {
            let how = match how {
                crate::compat::NatHow::Given => How::Given,
                crate::compat::NatHow::Masquerade => How::Masquerade,
                crate::compat::NatHow::Redirect => How::Redirect,
            };
            let spec = NatSpec { src: *src, addr: *addr, ports: *ports, flags: *flags, how };
            return Ok(Some(Step::Nat(spec)));
        }
        Expr::Xt { x, .. } => {
            let seen = crate::compat::Seen {
                ct: ct.map(|c| (c.state, c.reply, c.snat, c.dnat)),
                l4: p.l4.and_then(|(proto, at)| Some((proto, p.net.get(at..)?))),
                types: p.types,
            };
            if !crate::compat::matches(x, &seen) {
                return Err(());
            }
        }
        Expr::Reject { kind, code } => {
            let r = match *kind {
                NFT_REJECT_TCP_RST if p.l4.is_some_and(|l| l.0 == 6) => Reject::TcpReset,
                NFT_REJECT_TCP_RST => return Err(()),
                NFT_REJECT_ICMP_UNREACH => Reject::Unreachable(*code),
                // ICMPX: one code for both families (enum
                // nft_reject_inet_code), translated to each's own.
                _ => Reject::Unreachable(match (*code, p.v6) {
                    (NFT_REJECT_ICMPX_NO_ROUTE, _) => 0,
                    (NFT_REJECT_ICMPX_PORT_UNREACH, false) => 3,
                    (NFT_REJECT_ICMPX_PORT_UNREACH, true) => 4,
                    (NFT_REJECT_ICMPX_HOST_UNREACH, false) => 1,
                    (NFT_REJECT_ICMPX_HOST_UNREACH, true) => 3,
                    (_, false) => 13,
                    (_, true) => 1,
                }),
            };
            return Ok(Some(Step::Out(Outcome::Reject(r))));
        }
    }
    Ok(None)
}

/// A port range from two registers (each port two bytes in network
/// order at the register's start).
fn ports_of(regs: &[u8; 64], r: Option<(u32, u32)>) -> Result<Option<(u16, u16)>, ()> {
    let Some((lo, hi)) = r else { return Ok(None) };
    let port = |reg: u32| load(regs, reg, 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    Ok(Some((port(lo)?, port(hi)?)))
}

/// The element of `s` that `key` falls in.
fn lookup<'s>(s: &'s Set, key: &[u8]) -> Option<&'s crate::ruleset::Elem> {
    if s.flags & NFT_SET_INTERVAL == 0 {
        return s.elems.iter().find(|e| e.flags & NFT_SET_ELEM_INTERVAL_END == 0 && e.key == key);
    }
    // Ranges given with their ends.
    if let Some(e) =
        s.elems.iter().find(|e| e.key_end.as_ref().is_some_and(|end| e.key.as_slice() <= key && key <= end.as_slice()))
    {
        return Some(e);
    }
    // Ranges as a start, and an end flagged one past their last key: the
    // closest element at or below the key decides (an end at the same key
    // as a start sorts first, so the start wins).
    s.elems
        .iter()
        .filter(|e| e.key.as_slice() <= key && e.key_end.is_none())
        .max_by(|a, b| {
            a.key.cmp(&b.key).then((b.flags & NFT_SET_ELEM_INTERVAL_END).cmp(&(a.flags & NFT_SET_ELEM_INTERVAL_END)))
        })
        .filter(|e| e.flags & NFT_SET_ELEM_INTERVAL_END == 0)
}

impl Ruleset {
    /// The connection state of `p`, from `ct` (tracking it at the first
    /// hook a packet meets: prerouting for arrivals, output for this
    /// host's own), when some rule asks for states.
    pub fn track(&self, ct: &mut Conntrack, p: &Packet<'_>, now: u64) -> Option<CtInfo> {
        if !self.uses_ct() {
            return None;
        }
        if matches!(p.hook, NF_INET_PRE_ROUTING | NF_INET_LOCAL_OUT) {
            ct.track(p.v6, p.net, p.l4, now).map(|t| t.info)
        } else {
            ct.lookup(p.v6, p.net, p.l4, now)
        }
    }
}
