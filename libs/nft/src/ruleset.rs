// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ruleset and what nfnetlink does to it (nft(8); the message layouts
//! of ADR 0128, matched to Linux's answers as observed on the host): tables
//! of chains, rules and sets, changed only by batches that apply whole or
//! not at all, and dumped back.

use alloc::vec::Vec;

use crate::attr::{Attrs, Header, Msg, ack, done, messages};
use crate::consts::*;
use crate::expr::*;

#[derive(Clone, Debug, Default)]
pub struct Table {
    pub family: u8,
    pub name: Vec<u8>,
    pub handle: u64,
    pub flags: u32,
    pub userdata: Option<Vec<u8>>,
    pub chains: Vec<Chain>,
    pub sets: Vec<Set>,
    /// The next handle for the table's chains, rules and sets (one
    /// counter, as Linux numbers them).
    pub next_handle: u64,
}

#[derive(Clone, Debug)]
pub struct Chain {
    pub name: Vec<u8>,
    pub handle: u64,
    pub base: Option<BaseChain>,
    pub rules: Vec<Rule>,
    pub userdata: Option<Vec<u8>>,
}

/// A chain on a hook: its number, priority, type ("filter", "nat",
/// "route") and policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseChain {
    pub hook: u32,
    pub priority: i32,
    pub kind: Vec<u8>,
    pub policy: i32,
    /// Made with NFTA_CHAIN_COUNTERS.
    pub counters: bool,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub handle: u64,
    pub exprs: Vec<Expr>,
    pub userdata: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct Set {
    pub name: Vec<u8>,
    pub handle: u64,
    pub flags: u32,
    pub key_type: u32,
    pub key_len: u32,
    pub data_type: Option<u32>,
    pub data_len: u32,
    pub policy: Option<u32>,
    pub desc_size: Option<u32>,
    pub userdata: Option<Vec<u8>>,
    pub elems: Vec<Elem>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Elem {
    pub key: Vec<u8>,
    pub key_end: Option<Vec<u8>>,
    pub flags: u32,
    pub data: Option<Data>,
    pub userdata: Option<Vec<u8>>,
}

/// Everything a network namespace's firewall holds.
#[derive(Clone, Debug)]
pub struct Ruleset {
    pub tables: Vec<Table>,
    /// The generation: one more for every batch committed.
    pub generation: u32,
    next_table_handle: u64,
    /// What the rules ask of the stack (connection tracking, NAT, address
    /// types), worked out once per ruleset rather than per packet: under
    /// the generation and the numbers of tables, chains and rules it was
    /// worked out for.
    pub(crate) features: core::cell::Cell<Option<(FeatureKey, Features)>>,
}

/// What [`Features`] were worked out for: the generation, the number of
/// tables and chains, the number of rules.
pub(crate) type FeatureKey = (u32, usize, usize);

/// What a ruleset asks of the stack.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Features {
    pub ct: bool,
    pub nat4: bool,
    pub nat6: bool,
    pub addrtype: bool,
}

impl Default for Ruleset {
    /// Empty, at generation 1 (a new namespace's, observed).
    fn default() -> Ruleset {
        Ruleset { tables: Vec::new(), generation: 1, next_table_handle: 0, features: core::cell::Cell::new(None) }
    }
}

/// A failure: its errno, and the request's attribute it is about (for
/// the extended acknowledgement's offset).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fail(pub i32, pub Option<u16>);

impl From<i32> for Fail {
    fn from(e: i32) -> Fail {
        Fail(e, None)
    }
}

/// What a socket asked of its acknowledgements (netlink(7)):
/// NETLINK_CAP_ACK leaves the request out of an error, NETLINK_EXT_ACK
/// adds attributes (the offending one's offset). Successes are always
/// just the request's header (observed, flagged NLM_F_CAPPED either way).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AckOpts {
    pub capped: bool,
    pub extended: bool,
}

/// An answer as a socket with options `o` gets it: errors made in the
/// extended form (the request whole, then attributes) cut to fit.
fn reshape(m: &mut Vec<u8>, o: AckOpts) {
    const NLM_F_CAPPED: u16 = 0x100;
    const NLM_F_ACK_TLVS: u16 = 0x200;
    if m.len() < 36 || u16::from_ne_bytes([m[4], m[5]]) != NLMSG_ERROR {
        return;
    }
    if i32::from_ne_bytes(m[16..20].try_into().unwrap()) == 0 {
        return;
    }
    let req_len = (u32::from_ne_bytes(m[20..24].try_into().unwrap()) as usize).min(m.len() - 20);
    let mut flags = u16::from_ne_bytes([m[6], m[7]]);
    let tlvs: Vec<u8> = if flags & NLM_F_ACK_TLVS != 0 && o.extended {
        m[(20 + req_len).next_multiple_of(4).min(m.len())..].to_vec()
    } else {
        flags &= !NLM_F_ACK_TLVS;
        Vec::new()
    };
    let keep = if o.capped {
        flags |= NLM_F_CAPPED;
        36
    } else {
        20 + req_len
    };
    m.truncate(keep);
    while m.len() % 4 != 0 {
        m.push(0);
    }
    m.extend_from_slice(&tlvs);
    let len = m.len() as u32;
    m[..4].copy_from_slice(&len.to_ne_bytes());
    m[6..8].copy_from_slice(&flags.to_ne_bytes());
}

/// `errno` about attribute `attr`.
fn about(errno: i32, attr: u16) -> Fail {
    Fail(errno, Some(attr))
}

/// What a batch adds to a message: objects made in the batch by their
/// numbers (NFTA_SET_ID, NFTA_CHAIN_ID, NFTA_RULE_ID), resolved as later
/// messages name them.
#[derive(Default)]
struct Ids {
    sets: Vec<(u32, Vec<u8>)>,
    chains: Vec<(u32, Vec<u8>)>,
    rules: Vec<(u32, u64)>,
}

fn str_attr(a: &Attrs<'_>, k: u16) -> Option<Vec<u8>> {
    a.get(k).and_then(|v| v.str()).map(|s| s.to_vec())
}

/// Whether `table_family` takes messages that name `family` (UNSPEC: all).
fn family_matches(family: u8, table_family: u8) -> bool {
    family == NFPROTO_UNSPEC || family == table_family
}

impl Ruleset {
    fn table_mut(&mut self, family: u8, a: &Attrs<'_>, name_attr: u16) -> Result<&mut Table, Fail> {
        let name = str_attr(a, name_attr).ok_or(EINVAL)?;
        self.tables.iter_mut().find(|t| t.family == family && t.name == name).ok_or(about(ENOENT, name_attr))
    }

    /// [`Ruleset::netlink`] for a socket with these acknowledgement options:
    /// errors come back as netlink(7) says each option shapes them.
    pub fn netlink_opts(&mut self, b: &[u8], port: u32, pid: u32, comm: &[u8], o: AckOpts) -> Vec<Vec<u8>> {
        let mut out = self.netlink(b, port, pid, comm);
        for m in &mut out {
            reshape(m, o);
        }
        out
    }

    /// Handle one datagram from a program (port `port`, process `pid` and
    /// `comm` for NEWGEN); the answers, each a whole message, errors as a
    /// socket with NETLINK_EXT_ACK gets them.
    pub fn netlink(&mut self, b: &[u8], port: u32, pid: u32, comm: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let msgs = messages(b);
        let mut i = 0;
        while i < msgs.len() {
            let (h, body) = msgs[i];
            if h.kind == NFNL_MSG_BATCH_BEGIN {
                let end = msgs[i + 1..].iter().position(|(h, _)| h.kind == NFNL_MSG_BATCH_END).map(|p| i + 1 + p);
                let Some(end) = end else {
                    out.push(ack(&h, body, EINVAL, port, None));
                    break;
                };
                self.batch(&h, body, &msgs[i + 1..end], (port, pid, comm), &mut out);
                i = end + 1;
                continue;
            }
            self.request(&h, body, port, pid, comm, &mut out);
            i += 1;
        }
        out
    }

    /// A batch: applied to a copy, which replaces the ruleset only if every
    /// message succeeded; the first failure is answered and ends it.
    fn batch(
        &mut self,
        begin: &Header,
        body: &[u8],
        msgs: &[(Header, &[u8])],
        (port, pid, comm): (u32, u32, &[u8]),
        out: &mut Vec<Vec<u8>>,
    ) {
        // nfgenmsg's res_id names the subsystem (big-endian).
        if body.len() < 4 || u16::from_be_bytes([body[2], body[3]]) != NFNL_SUBSYS_NFTABLES {
            out.push(ack(begin, body, EINVAL, port, None));
            return;
        }
        // A batch may require the generation it was made against.
        if let Some(g) = Attrs(&body[4..]).get(NFNL_BATCH_GENID).and_then(|a| a.u32())
            && g != self.generation
        {
            out.push(ack(begin, body, ERESTART, port, None));
            return;
        }
        // Nothing in it: nothing changes, not even the generation
        // (observed: `iptables -C` commits an empty batch).
        if msgs.is_empty() {
            return;
        }
        let mut work = self.clone();
        let mut ids = Ids::default();
        let mut acks = Vec::new();
        let mut echoes = Vec::new();
        for (h, body) in msgs {
            if body.len() < 4 || h.kind >> 8 != NFNL_SUBSYS_NFTABLES {
                out.push(ack(h, body, EINVAL, port, None));
                return;
            }
            let family = body[0];
            let a = Attrs(&body[4..]);
            if !a.well_formed() {
                out.push(ack(h, body, EINVAL, port, None));
                return;
            }
            match work.change(h, family, a, &mut ids) {
                Ok(echo) => {
                    if h.flags & NLM_F_ACK != 0 {
                        acks.push(ack(h, body, 0, port, None));
                    }
                    if h.flags & NLM_F_ECHO != 0
                        && let Some(e) = echo
                    {
                        echoes.push((e, h.seq));
                    }
                }
                Err(Fail(e, bad)) => {
                    out.push(ack(h, body, e, port, bad));
                    return;
                }
            }
        }
        work.drop_unused_anonymous_sets();
        work.generation = self.generation.wrapping_add(1);
        *self = work;
        let generation = self.generation;
        // What NLM_F_ECHO asked for, then the new generation (observed:
        // nft prints "# new generation N by process P (comm)").
        let last = echoes.last().map(|(_, seq)| *seq);
        for (e, seq) in echoes {
            out.push(self.echo(e, generation, seq, port));
        }
        if let Some(seq) = last {
            out.push(newgen(generation, seq, port, pid, comm));
        }
        out.extend(acks);
    }

    /// One change of a batch. Returns what NLM_F_ECHO sends back.
    fn change(&mut self, h: &Header, family: u8, a: Attrs<'_>, ids: &mut Ids) -> Result<Option<Echo>, Fail> {
        let msg = h.kind & 0xFF;
        let create = h.flags & NLM_F_CREATE != 0;
        let excl = h.flags & NLM_F_EXCL != 0;
        match msg {
            NFT_MSG_NEWTABLE => {
                let name = str_attr(&a, NFTA_TABLE_NAME).ok_or(EINVAL)?;
                let flags = a.get(NFTA_TABLE_FLAGS).and_then(|f| f.u32()).unwrap_or(0);
                if !matches!(family, NFPROTO_INET | NFPROTO_IPV4 | NFPROTO_IPV6 | 3 | 5 | 7) {
                    return Err(EOPNOTSUPP.into());
                }
                if let Some(t) = self.tables.iter_mut().find(|t| t.family == family && t.name == name) {
                    if excl {
                        return Err(about(EEXIST, NFTA_TABLE_NAME));
                    }
                    t.flags = flags;
                    return Ok(None);
                }
                self.next_table_handle += 1;
                let userdata = a.get(NFTA_TABLE_USERDATA).map(|u| u.value.to_vec());
                self.tables.push(Table {
                    family,
                    name: name.clone(),
                    handle: self.next_table_handle,
                    flags,
                    userdata,
                    chains: Vec::new(),
                    sets: Vec::new(),
                    next_handle: 0,
                });
                Ok(Some(Echo::Table(family, name)))
            }
            NFT_MSG_DELTABLE | NFT_MSG_DESTROYTABLE => {
                let name = str_attr(&a, NFTA_TABLE_NAME);
                let handle = a.get(NFTA_TABLE_HANDLE).and_then(|v| v.u64());
                if name.is_none() && handle.is_none() {
                    // No table named: every table of the family (nft flush
                    // ruleset).
                    self.tables.retain(|t| !family_matches(family, t.family));
                    return Ok(None);
                }
                let at = self
                    .tables
                    .iter()
                    .position(|t| t.family == family && (name.as_ref() == Some(&t.name) || handle == Some(t.handle)));
                match at {
                    Some(i) => {
                        self.tables.remove(i);
                    }
                    None if msg == NFT_MSG_DESTROYTABLE => {}
                    None => {
                        return Err(about(ENOENT, if name.is_some() { NFTA_TABLE_NAME } else { NFTA_TABLE_HANDLE }));
                    }
                }
                Ok(None)
            }
            NFT_MSG_NEWCHAIN => self.new_chain(family, &a, create, excl, ids),
            NFT_MSG_DELCHAIN | NFT_MSG_DESTROYCHAIN => {
                let t = self.table_mut(family, &a, NFTA_CHAIN_TABLE)?;
                let name = str_attr(&a, NFTA_CHAIN_NAME);
                let handle = a.get(NFTA_CHAIN_HANDLE).and_then(|v| v.u64());
                let Some(i) = t.chains.iter().position(|c| name.as_ref() == Some(&c.name) || handle == Some(c.handle))
                else {
                    return if msg == NFT_MSG_DESTROYCHAIN { Ok(None) } else { Err(about(ENOENT, NFTA_CHAIN_NAME)) };
                };
                let cname = t.chains[i].name.clone();
                let jumped_to = t.chains.iter().any(|c| c.rules.iter().any(|r| r.jumps_to(&cname)))
                    || t.sets
                        .iter()
                        .any(|s| s.elems.iter().any(|e| e.data.as_ref().is_some_and(|d| d.jumps_to(&cname))));
                // Its rules go with it; only jumps to it keep it (observed).
                if jumped_to {
                    return Err(about(EBUSY, NFTA_CHAIN_NAME));
                }
                t.chains.remove(i);
                Ok(None)
            }
            NFT_MSG_NEWRULE => self.new_rule(h, family, &a, ids),
            NFT_MSG_DELRULE | NFT_MSG_DESTROYRULE => {
                let t = self.table_mut(family, &a, NFTA_RULE_TABLE)?;
                let chain = str_attr(&a, NFTA_RULE_CHAIN);
                let handle = a.get(NFTA_RULE_HANDLE).and_then(|v| v.u64());
                match (chain, handle) {
                    (None, _) => t.chains.iter_mut().for_each(|c| c.rules.clear()),
                    (Some(c), None) => {
                        t.chains.iter_mut().find(|x| x.name == c).ok_or(about(ENOENT, NFTA_RULE_CHAIN))?.rules.clear()
                    }
                    (Some(c), Some(h)) => {
                        let c = t.chains.iter_mut().find(|x| x.name == c).ok_or(about(ENOENT, NFTA_RULE_CHAIN))?;
                        match c.rules.iter().position(|r| r.handle == h) {
                            Some(i) => {
                                c.rules.remove(i);
                            }
                            None if msg == NFT_MSG_DESTROYRULE => {}
                            None => return Err(about(ENOENT, NFTA_RULE_HANDLE)),
                        }
                    }
                }
                Ok(None)
            }
            NFT_MSG_NEWSET => self.new_set(family, &a, excl, ids),
            NFT_MSG_DELSET | NFT_MSG_DESTROYSET => {
                let t = self.table_mut(family, &a, NFTA_SET_TABLE)?;
                let name = str_attr(&a, NFTA_SET_NAME);
                let handle = a.get(NFTA_SET_HANDLE).and_then(|v| v.u64());
                let Some(i) = t.sets.iter().position(|s| name.as_ref() == Some(&s.name) || handle == Some(s.handle))
                else {
                    return if msg == NFT_MSG_DESTROYSET { Ok(None) } else { Err(about(ENOENT, NFTA_SET_NAME)) };
                };
                let sname = t.sets[i].name.clone();
                if t.chains.iter().any(|c| c.rules.iter().any(|r| r.looks_up(&sname))) {
                    return Err(about(EBUSY, NFTA_SET_NAME));
                }
                t.sets.remove(i);
                Ok(None)
            }
            NFT_MSG_NEWSETELEM | NFT_MSG_DELSETELEM | NFT_MSG_DESTROYSETELEM => {
                self.set_elems(family, &a, msg, excl, ids)?;
                Ok(None)
            }
            _ => Err(EOPNOTSUPP.into()),
        }
    }

    fn new_chain(
        &mut self,
        family: u8,
        a: &Attrs<'_>,
        create: bool,
        excl: bool,
        ids: &mut Ids,
    ) -> Result<Option<Echo>, Fail> {
        let t = self.table_mut(family, a, NFTA_CHAIN_TABLE)?;
        let tname = t.name.clone();
        let name = str_attr(a, NFTA_CHAIN_NAME);
        let handle = a.get(NFTA_CHAIN_HANDLE).and_then(|v| v.u64());
        let policy = a.get(NFTA_CHAIN_POLICY).and_then(|v| v.i32());
        if policy.is_some_and(|p| p != NF_ACCEPT && p != NF_DROP) {
            return Err(EINVAL.into());
        }
        let existing = t.chains.iter_mut().find(|c| name.as_ref() == Some(&c.name) || handle == Some(c.handle));
        if let Some(c) = existing {
            if excl && create {
                return Err(about(EEXIST, NFTA_CHAIN_NAME));
            }
            // An update: a base chain's policy may change.
            if let (Some(b), Some(p)) = (c.base.as_mut(), policy) {
                b.policy = p;
            } else if policy.is_some() {
                return Err(EOPNOTSUPP.into());
            }
            return Ok(None);
        }
        let name = name.ok_or(EINVAL)?;
        if name.len() >= 256 {
            return Err(ENAMETOOLONG.into());
        }
        let base = match a.get(NFTA_CHAIN_HOOK) {
            None => None,
            Some(h) => {
                let h = h.nested();
                let hook = h.get(NFTA_HOOK_HOOKNUM).and_then(|v| v.u32()).ok_or(EINVAL)?;
                let priority = h.get(NFTA_HOOK_PRIORITY).and_then(|v| v.i32()).ok_or(EINVAL)?;
                let kind = str_attr(a, NFTA_CHAIN_TYPE).unwrap_or_else(|| b"filter".to_vec());
                let ok_hook = match (family, kind.as_slice()) {
                    (NFPROTO_INET | NFPROTO_IPV4 | NFPROTO_IPV6, b"filter") => hook <= NF_INET_POST_ROUTING,
                    (NFPROTO_INET | NFPROTO_IPV4 | NFPROTO_IPV6, b"nat") => hook != NF_INET_FORWARD && hook <= 4,
                    (NFPROTO_IPV4 | NFPROTO_IPV6, b"route") => hook == NF_INET_LOCAL_OUT,
                    _ => false,
                };
                if !ok_hook {
                    return Err(EOPNOTSUPP.into());
                }
                // Made with counters (iptables-nft's are): they're dumped.
                let counters = a.get(NFTA_CHAIN_COUNTERS).is_some();
                Some(BaseChain { hook, priority, kind, policy: policy.unwrap_or(NF_ACCEPT), counters })
            }
        };
        t.next_handle += 1;
        let handle = t.next_handle;
        let userdata = a.get(NFTA_CHAIN_USERDATA).map(|u| u.value.to_vec());
        t.chains.push(Chain { name: name.clone(), handle, base, rules: Vec::new(), userdata });
        if let Some(id) = a.get(NFTA_CHAIN_ID).and_then(|v| v.u32()) {
            ids.chains.push((id, name.clone()));
        }
        Ok(Some(Echo::Chain(family, tname, name)))
    }

    fn new_rule(&mut self, h: &Header, family: u8, a: &Attrs<'_>, ids: &mut Ids) -> Result<Option<Echo>, Fail> {
        let set_ids = |id: u32| ids.sets.iter().find(|(i, _)| *i == id).map(|(_, n)| n.clone());
        let chain_ids = |id: u32| ids.chains.iter().find(|(i, _)| *i == id).map(|(_, n)| n.clone());
        let mut unknown = Vec::new();
        let mut exprs = Vec::new();
        if let Some(list) = a.get(NFTA_RULE_EXPRESSIONS) {
            // Each element's type is its place in nft's lists (observed:
            // 1, 2, 3...), so any type is an element.
            for e in list.nested().iter() {
                let e = Expr::parse(e.nested(), family, &set_ids, &chain_ids, &mut unknown);
                exprs.push(e.map_err(|e| about(e, NFTA_RULE_EXPRESSIONS))?);
            }
        }
        if exprs.len() > 128 {
            return Err(E2BIG.into());
        }
        let t = self.table_mut(family, a, NFTA_RULE_TABLE)?;
        let tname = t.name.clone();
        let chain = match str_attr(a, NFTA_RULE_CHAIN) {
            Some(c) => c,
            None => a.get(NFTA_RULE_CHAIN_ID).and_then(|v| v.u32()).and_then(chain_ids).ok_or(EINVAL)?,
        };
        // What the rule names must exist: sets, and chains it jumps to
        // (which must not be base chains).
        for e in &exprs {
            match e {
                Expr::Lookup { set, dreg, .. } => {
                    let s = t.sets.iter().find(|s| &s.name == set).ok_or(ENOENT)?;
                    if dreg.is_some() != (s.flags & NFT_SET_MAP != 0) {
                        return Err(EINVAL.into());
                    }
                }
                Expr::Immediate { data: Data::Verdict(Verdict::Jump(c) | Verdict::Goto(c)), .. } => {
                    let target = t.chains.iter().find(|x| &x.name == c).ok_or(ENOENT)?;
                    if target.base.is_some() || *c == chain {
                        return Err(ELOOP.into());
                    }
                }
                _ => {}
            }
        }
        let userdata = a.get(NFTA_RULE_USERDATA).map(|u| u.value.to_vec());
        let replace = h.flags & NLM_F_REPLACE != 0;
        let handle_attr = a.get(NFTA_RULE_HANDLE).and_then(|v| v.u64());
        let position = match a.get(NFTA_RULE_POSITION).and_then(|v| v.u64()) {
            Some(p) => Some(p),
            None => a
                .get(NFTA_RULE_POSITION_ID)
                .and_then(|v| v.u32())
                .map(|id| ids.rules.iter().find(|(i, _)| *i == id).map(|(_, h)| *h).ok_or(ENOENT))
                .transpose()?,
        };
        t.next_handle += 1;
        let handle = t.next_handle;
        let c = t.chains.iter_mut().find(|x| x.name == chain).ok_or(about(ENOENT, NFTA_RULE_CHAIN))?;
        // A NAT statement only in a nat chain, at a hook it works at (a
        // regular chain's rules are taken as they come).
        if let Some(b) = &c.base
            && exprs.iter().any(|e| e.is_nat() && (b.kind != b"nat" || e.nat_hooks() & (1 << b.hook) == 0))
        {
            return Err(EOPNOTSUPP.into());
        }
        let rule = Rule { handle, exprs, userdata };
        if replace {
            let h = handle_attr.ok_or(EINVAL)?;
            let i = c.rules.iter().position(|r| r.handle == h).ok_or(about(ENOENT, NFTA_RULE_HANDLE))?;
            c.rules[i] = rule;
        } else {
            let append = h.flags & NLM_F_APPEND != 0;
            let at = match position {
                Some(p) => {
                    let i = c.rules.iter().position(|r| r.handle == p).ok_or(about(ENOENT, NFTA_RULE_POSITION))?;
                    if append { i + 1 } else { i }
                }
                None if append => c.rules.len(),
                None => 0,
            };
            c.rules.insert(at, rule);
        }
        if let Some(id) = a.get(NFTA_RULE_ID).and_then(|v| v.u32()) {
            ids.rules.push((id, handle));
        }
        Ok(Some(Echo::Rule(family, tname, chain, handle)))
    }

    fn new_set(&mut self, family: u8, a: &Attrs<'_>, excl: bool, ids: &mut Ids) -> Result<Option<Echo>, Fail> {
        let t = self.table_mut(family, a, NFTA_SET_TABLE)?;
        let tname = t.name.clone();
        let mut name = str_attr(a, NFTA_SET_NAME).ok_or(EINVAL)?;
        let flags = a.get(NFTA_SET_FLAGS).and_then(|v| v.u32()).unwrap_or(0);
        if flags & NFT_SET_ANONYMOUS != 0 {
            // "__set%d": the lowest number free in the table.
            if let Some(stem) = name.strip_suffix(b"%d") {
                let stem = stem.to_vec();
                let n = (0u32..)
                    .find(|n| {
                        let mut c = stem.clone();
                        c.extend_from_slice(alloc::format!("{n}").as_bytes());
                        !t.sets.iter().any(|s| s.name == c)
                    })
                    .unwrap_or(0);
                name = stem;
                name.extend_from_slice(alloc::format!("{n}").as_bytes());
            }
        }
        if let Some(s) = t.sets.iter().find(|s| s.name == name) {
            if excl {
                return Err(about(EEXIST, NFTA_SET_NAME));
            }
            let _ = s;
            return Ok(None);
        }
        let key_len = a.get(NFTA_SET_KEY_LEN).and_then(|v| v.u32()).ok_or(EINVAL)?;
        if key_len == 0 || key_len > 64 {
            return Err(EINVAL.into());
        }
        let data_type = a.get(NFTA_SET_DATA_TYPE).and_then(|v| v.u32());
        if (flags & NFT_SET_MAP != 0) != data_type.is_some() {
            return Err(EINVAL.into());
        }
        // A verdict map's data is a verdict register's size (16).
        let data_len = match data_type {
            Some(NFT_DATA_VERDICT) => 16,
            Some(_) => a.get(NFTA_SET_DATA_LEN).and_then(|v| v.u32()).ok_or(EINVAL)?,
            None => 0,
        };
        t.next_handle += 1;
        let handle = t.next_handle;
        t.sets.push(Set {
            name: name.clone(),
            handle,
            flags,
            key_type: a.get(NFTA_SET_KEY_TYPE).and_then(|v| v.u32()).unwrap_or(0),
            key_len,
            data_type,
            data_len,
            policy: a.get(NFTA_SET_POLICY).and_then(|v| v.u32()),
            desc_size: a.get(NFTA_SET_DESC).and_then(|d| d.nested().get(1).and_then(|v| v.u32())),
            userdata: a.get(NFTA_SET_USERDATA).map(|u| u.value.to_vec()),
            elems: Vec::new(),
        });
        if let Some(id) = a.get(NFTA_SET_ID).and_then(|v| v.u32()) {
            ids.sets.push((id, name.clone()));
        }
        Ok(Some(Echo::Set(family, tname, name)))
    }

    fn set_elems(&mut self, family: u8, a: &Attrs<'_>, msg: u16, excl: bool, ids: &Ids) -> Result<(), Fail> {
        let chain_ids = |id: u32| ids.chains.iter().find(|(i, _)| *i == id).map(|(_, n)| n.clone());
        let t = self.table_mut(family, a, NFTA_SET_ELEM_LIST_TABLE)?;
        let name = match str_attr(a, NFTA_SET_ELEM_LIST_SET) {
            Some(n) if !n.ends_with(b"%d") => n,
            _ => {
                let id = a.get(NFTA_SET_ELEM_LIST_SET_ID).and_then(|v| v.u32()).ok_or(EINVAL)?;
                ids.sets.iter().find(|(i, _)| *i == id).map(|(_, n)| n.clone()).ok_or(ENOENT)?
            }
        };
        let chains: Vec<Vec<u8>> = t.chains.iter().map(|c| c.name.clone()).collect();
        let s = t.sets.iter_mut().find(|s| s.name == name).ok_or(about(ENOENT, NFTA_SET_ELEM_LIST_SET))?;
        let Some(list) = a.get(NFTA_SET_ELEM_LIST_ELEMENTS) else {
            // No elements named: delete them all (nft flush set).
            if msg != NFT_MSG_NEWSETELEM {
                s.elems.clear();
            }
            return Ok(());
        };
        for e in list.nested().iter() {
            let e = e.nested();
            let value = |k: u16| -> Result<Option<Vec<u8>>, i32> {
                match e.get(k) {
                    None => Ok(None),
                    Some(v) => match Data::parse(v, &chain_ids)? {
                        Data::Value(v) => Ok(Some(v)),
                        Data::Verdict(_) => Err(EINVAL),
                    },
                }
            };
            let key = value(NFTA_SET_ELEM_KEY)?.ok_or(EINVAL)?;
            if key.len() != s.key_len as usize {
                return Err(EINVAL.into());
            }
            let key_end = value(NFTA_SET_ELEM_KEY_END)?;
            let flags = e.get(NFTA_SET_ELEM_FLAGS).and_then(|v| v.u32()).unwrap_or(0);
            let at = s
                .elems
                .iter()
                .position(|x| x.key == key && x.flags & NFT_SET_ELEM_INTERVAL_END == flags & NFT_SET_ELEM_INTERVAL_END);
            if msg != NFT_MSG_NEWSETELEM {
                match at {
                    Some(i) => {
                        s.elems.remove(i);
                    }
                    None if msg == NFT_MSG_DESTROYSETELEM => {}
                    None => return Err(ENOENT.into()),
                }
                continue;
            }
            let data = match e.get(NFTA_SET_ELEM_DATA) {
                Some(d) if flags & NFT_SET_ELEM_INTERVAL_END == 0 => {
                    let d = Data::parse(d, &chain_ids)?;
                    if let Data::Verdict(Verdict::Jump(c) | Verdict::Goto(c)) = &d
                        && !chains.contains(c)
                    {
                        return Err(ENOENT.into());
                    }
                    Some(d)
                }
                None if s.flags & NFT_SET_MAP != 0 && flags & NFT_SET_ELEM_INTERVAL_END == 0 => {
                    return Err(EINVAL.into());
                }
                _ => None,
            };
            let elem =
                Elem { key, key_end, flags, data, userdata: e.get(NFTA_SET_ELEM_USERDATA).map(|u| u.value.to_vec()) };
            match at {
                Some(_) if excl => return Err(EEXIST.into()),
                Some(i) => s.elems[i] = elem,
                None => s.elems.push(elem),
            }
        }
        Ok(())
    }

    /// Anonymous sets go with the last rule that used them.
    fn drop_unused_anonymous_sets(&mut self) {
        for t in &mut self.tables {
            let used: Vec<Vec<u8>> = t
                .chains
                .iter()
                .flat_map(|c| c.rules.iter())
                .flat_map(|r| r.exprs.iter())
                .filter_map(|e| if let Expr::Lookup { set, .. } = e { Some(set.clone()) } else { None })
                .collect();
            t.sets.retain(|s| s.flags & NFT_SET_ANONYMOUS == 0 || used.contains(&s.name));
        }
    }

    // --- requests outside batches: gets and dumps ----------------------------

    fn request(&mut self, h: &Header, body: &[u8], port: u32, pid: u32, comm: &[u8], out: &mut Vec<Vec<u8>>) {
        if h.kind >> 8 == NFNL_SUBSYS_NFT_COMPAT && body.len() >= 4 {
            return self.compat_get(h, body, port, out);
        }
        if h.kind >> 8 != NFNL_SUBSYS_NFTABLES || body.len() < 4 {
            let e = if h.kind >> 8 == NFNL_SUBSYS_NFTABLES { EINVAL } else { EOPNOTSUPP };
            out.push(ack(h, body, e, port, None));
            return;
        }
        let family = body[0];
        let a = Attrs(&body[4..]);
        let dump = h.flags & NLM_F_DUMP == NLM_F_DUMP;
        let g = self.generation;
        let seq = h.seq;
        let flags = if dump { NLM_F_MULTI } else { 0 };
        let mut msgs: Vec<Vec<u8>> = Vec::new();
        let r: Result<(), Fail> = (|| {
            match h.kind & 0xFF {
                NFT_MSG_GETGEN => msgs.push(newgen(g, seq, port, pid, comm)),
                NFT_MSG_GETTABLE => {
                    let name = str_attr(&a, NFTA_TABLE_NAME);
                    let mut found = false;
                    for t in self.tables.iter().filter(|t| family_matches(family, t.family)) {
                        if name.as_ref().is_some_and(|n| *n != t.name) {
                            continue;
                        }
                        found = true;
                        msgs.push(dump_table(t, g, seq, port, flags));
                    }
                    if !dump && !found {
                        return Err(about(ENOENT, NFTA_TABLE_NAME));
                    }
                }
                NFT_MSG_GETCHAIN => {
                    let (tname, cname) = (str_attr(&a, NFTA_CHAIN_TABLE), str_attr(&a, NFTA_CHAIN_NAME));
                    let table_known =
                        self.tables.iter().any(|t| family_matches(family, t.family) && Some(&t.name) == tname.as_ref());
                    let mut found = false;
                    for t in self.tables.iter().filter(|t| family_matches(family, t.family)) {
                        if tname.as_ref().is_some_and(|n| *n != t.name) {
                            continue;
                        }
                        for c in &t.chains {
                            if cname.as_ref().is_some_and(|n| *n != c.name) {
                                continue;
                            }
                            found = true;
                            msgs.push(dump_chain(t, c, g, seq, port, flags));
                        }
                    }
                    if !dump && !found {
                        return Err(about(ENOENT, if table_known { NFTA_CHAIN_NAME } else { NFTA_CHAIN_TABLE }));
                    }
                }
                NFT_MSG_GETRULE => {
                    let (tname, cname) = (str_attr(&a, NFTA_RULE_TABLE), str_attr(&a, NFTA_RULE_CHAIN));
                    let handle = a.get(NFTA_RULE_HANDLE).and_then(|v| v.u64());
                    let mut found = false;
                    for t in self.tables.iter().filter(|t| family_matches(family, t.family)) {
                        if tname.as_ref().is_some_and(|n| *n != t.name) {
                            continue;
                        }
                        for c in &t.chains {
                            if cname.as_ref().is_some_and(|n| *n != c.name) {
                                continue;
                            }
                            for (i, r) in c.rules.iter().enumerate() {
                                if handle.is_some_and(|h| h != r.handle) {
                                    continue;
                                }
                                found = true;
                                let prev = i.checked_sub(1).map(|p| c.rules[p].handle);
                                msgs.push(dump_rule(t, c, r, prev, g, seq, port, flags | NLM_F_APPEND));
                            }
                        }
                    }
                    if !dump && !found {
                        return Err(ENOENT.into());
                    }
                }
                NFT_MSG_GETSET => {
                    let (tname, sname) = (str_attr(&a, NFTA_SET_TABLE), str_attr(&a, NFTA_SET_NAME));
                    let mut found = false;
                    for t in self.tables.iter().filter(|t| family_matches(family, t.family)) {
                        if tname.as_ref().is_some_and(|n| *n != t.name) {
                            continue;
                        }
                        for s in &t.sets {
                            if sname.as_ref().is_some_and(|n| *n != s.name) {
                                continue;
                            }
                            found = true;
                            msgs.push(dump_set(t, s, g, seq, port, flags));
                        }
                    }
                    if !dump && !found {
                        return Err(about(ENOENT, NFTA_SET_NAME));
                    }
                }
                NFT_MSG_GETSETELEM => {
                    let t = self
                        .tables
                        .iter()
                        .find(|t| {
                            t.family == family && Some(&t.name) == str_attr(&a, NFTA_SET_ELEM_LIST_TABLE).as_ref()
                        })
                        .ok_or(ENOENT)?;
                    let sname = str_attr(&a, NFTA_SET_ELEM_LIST_SET).ok_or(EINVAL)?;
                    let s = t.sets.iter().find(|s| s.name == sname).ok_or(ENOENT)?;
                    msgs.push(dump_elems(t, s, &s.elems_dump_order(), g, seq, port, flags));
                    // Linux ends the walk with an empty list (observed).
                    msgs.push(dump_elems(t, s, &[], g, seq, port, flags));
                }
                // Objects, flowtables: none.
                NFT_MSG_GETOBJ | NFT_MSG_GETFLOWTABLE | 21 | 25 | 33 => {
                    if !dump {
                        return Err(ENOENT.into());
                    }
                }
                _ => return Err(EOPNOTSUPP.into()),
            }
            Ok(())
        })();
        match r {
            Err(Fail(e, bad)) => out.push(ack(h, body, e, port, bad)),
            Ok(()) => {
                out.extend(msgs);
                if dump {
                    out.push(done(seq, port));
                } else if h.flags & NLM_F_ACK != 0 {
                    out.push(ack(h, body, 0, port, None));
                }
            }
        }
    }

    fn echo(&self, e: Echo, g: u32, seq: u32, port: u32) -> Vec<u8> {
        let find_table = |f: u8, n: &[u8]| self.tables.iter().find(|t| t.family == f && t.name == n);
        match e {
            Echo::Table(f, n) => dump_table(find_table(f, &n).unwrap(), g, seq, port, NLM_F_CREATE),
            Echo::Chain(f, t, c) => {
                let t = find_table(f, &t).unwrap();
                dump_chain(t, t.chains.iter().find(|x| x.name == c).unwrap(), g, seq, port, NLM_F_CREATE)
            }
            Echo::Rule(f, t, c, h) => {
                let t = find_table(f, &t).unwrap();
                let c = t.chains.iter().find(|x| x.name == c).unwrap();
                let i = c.rules.iter().position(|r| r.handle == h).unwrap();
                let prev = i.checked_sub(1).map(|p| c.rules[p].handle);
                dump_rule(t, c, &c.rules[i], prev, g, seq, port, NLM_F_CREATE | NLM_F_APPEND)
            }
            Echo::Set(f, t, s) => {
                let t = find_table(f, &t).unwrap();
                dump_set(t, t.sets.iter().find(|x| x.name == s).unwrap(), g, seq, port, NLM_F_CREATE)
            }
        }
    }
}

/// What an NLM_F_ECHO change sends back: the object made.
enum Echo {
    Table(u8, Vec<u8>),
    Chain(u8, Vec<u8>, Vec<u8>),
    Rule(u8, Vec<u8>, Vec<u8>, u64),
    Set(u8, Vec<u8>, Vec<u8>),
}

const ENAMETOOLONG: i32 = 36;

/// NEWGEN: generation `g`, and the process that asked.
fn newgen(g: u32, seq: u32, port: u32, pid: u32, comm: &[u8]) -> Vec<u8> {
    let mut m = Msg::new(nft(NFT_MSG_NEWGEN), 0, seq, port, NFPROTO_UNSPEC, g as u16);
    m.u32(NFTA_GEN_ID, g).u32(NFTA_GEN_PROC_PID, pid).str(NFTA_GEN_PROC_NAME, comm);
    m.finish()
}

impl Ruleset {
    /// NFNL_MSG_COMPAT_GET (ADR 0133): which revision of an xtables
    /// extension Slate has. The answer repeats the name, gives the
    /// revision and the type (observed: NLM_F_MULTI, the family echoed),
    /// then the acknowledgement asked for; ENOENT for one it hasn't.
    fn compat_get(&self, h: &Header, body: &[u8], port: u32, out: &mut Vec<Vec<u8>>) {
        let a = Attrs(&body[4..]);
        let name = str_attr(&a, NFTA_COMPAT_NAME);
        let kind = a.get(NFTA_COMPAT_TYPE).and_then(|v| v.u32());
        let (Some(name), Some(kind)) = (name, kind) else {
            out.push(ack(h, body, EINVAL, port, None));
            return;
        };
        if h.kind & 0xFF != NFNL_MSG_COMPAT_GET {
            out.push(ack(h, body, EOPNOTSUPP, port, None));
            return;
        }
        match crate::compat::get(&name, kind) {
            Ok(rev) => {
                let mut m = Msg::new(h.kind, NLM_F_MULTI, h.seq, port, body[0], 0);
                m.str(NFTA_COMPAT_NAME, &name).u32(NFTA_COMPAT_REV, rev).u32(NFTA_COMPAT_TYPE, kind);
                out.push(m.finish());
                if h.flags & NLM_F_ACK != 0 {
                    out.push(ack(h, body, 0, port, None));
                }
            }
            Err(e) => out.push(ack(h, body, e, port, None)),
        }
    }
}

/// An nf_tables message type.
fn nft(msg: u16) -> u16 {
    (NFNL_SUBSYS_NFTABLES << 8) | msg
}

impl Rule {
    fn jumps_to(&self, chain: &[u8]) -> bool {
        self.exprs.iter().any(|e| matches!(e, Expr::Immediate { data, .. } if data.jumps_to(chain)))
    }

    fn looks_up(&self, set: &[u8]) -> bool {
        self.exprs.iter().any(|e| matches!(e, Expr::Lookup { set: s, .. } if s == set))
    }
}

impl Data {
    fn jumps_to(&self, chain: &[u8]) -> bool {
        matches!(self, Data::Verdict(Verdict::Jump(c) | Verdict::Goto(c)) if c == chain)
    }
}

impl Set {
    /// The order Linux's dumps give (observed): interval sets by key,
    /// highest first; constant sets of small keys (two bytes at most)
    /// lowest first; others newest first.
    fn elems_dump_order(&self) -> Vec<Elem> {
        let mut e = self.elems.clone();
        if self.flags & NFT_SET_INTERVAL != 0 {
            e.sort_by(|a, b| b.key.cmp(&a.key).then(b.flags.cmp(&a.flags)));
        } else if self.key_len <= 2 && self.flags & NFT_SET_CONSTANT != 0 {
            e.sort_by(|a, b| a.key.cmp(&b.key));
        } else {
            e.reverse();
        }
        e
    }
}

// --- dumps, laid out as Linux's (observed) -----------------------------------

fn dump_table(t: &Table, g: u32, seq: u32, port: u32, flags: u16) -> Vec<u8> {
    let mut m = Msg::new(nft(NFT_MSG_NEWTABLE), flags, seq, port, t.family, g as u16);
    // Its chains and named sets (anonymous ones belong to their rules).
    let used = t.chains.len() + t.sets.iter().filter(|s| s.flags & NFT_SET_ANONYMOUS == 0).count();
    m.str(NFTA_TABLE_NAME, &t.name).u32(NFTA_TABLE_USE, used as u32);
    m.u64(NFTA_TABLE_HANDLE, t.handle).u32(NFTA_TABLE_FLAGS, t.flags);
    if let Some(u) = &t.userdata {
        m.attr(NFTA_TABLE_USERDATA, u);
    }
    m.finish()
}

fn dump_chain(t: &Table, c: &Chain, g: u32, seq: u32, port: u32, flags: u16) -> Vec<u8> {
    let mut m = Msg::new(nft(NFT_MSG_NEWCHAIN), flags, seq, port, t.family, g as u16);
    m.str(NFTA_CHAIN_TABLE, &t.name).str(NFTA_CHAIN_NAME, &c.name).u64(NFTA_CHAIN_HANDLE, c.handle);
    if let Some(b) = &c.base {
        m.nest(NFTA_CHAIN_HOOK).u32(NFTA_HOOK_HOOKNUM, b.hook).u32(NFTA_HOOK_PRIORITY, b.priority as u32).end();
        m.u32(NFTA_CHAIN_POLICY, b.policy as u32).str(NFTA_CHAIN_TYPE, &b.kind);
        if b.counters {
            // Packets, then bytes (observed); Slate counts no policy hits.
            m.nest(NFTA_CHAIN_COUNTERS).u64(NFTA_COUNTER_PACKETS, 0).u64(NFTA_COUNTER_BYTES, 0).end();
        }
        m.u32(NFTA_CHAIN_FLAGS, NFT_CHAIN_BASE);
    }
    // Its rules, and the jumps and gotos to it (rules' and maps').
    let jumps = t.chains.iter().flat_map(|x| x.rules.iter()).filter(|r| r.jumps_to(&c.name)).count()
        + t.sets
            .iter()
            .flat_map(|s| s.elems.iter())
            .filter(|e| e.data.as_ref().is_some_and(|d| d.jumps_to(&c.name)))
            .count();
    m.u32(NFTA_CHAIN_USE, (c.rules.len() + jumps) as u32);
    if let Some(u) = &c.userdata {
        m.attr(NFTA_CHAIN_USERDATA, u);
    }
    m.finish()
}

#[allow(clippy::too_many_arguments)]
fn dump_rule(t: &Table, c: &Chain, r: &Rule, prev: Option<u64>, g: u32, seq: u32, port: u32, flags: u16) -> Vec<u8> {
    let mut m = Msg::new(nft(NFT_MSG_NEWRULE), flags, seq, port, t.family, g as u16);
    m.str(NFTA_RULE_TABLE, &t.name).str(NFTA_RULE_CHAIN, &c.name).u64(NFTA_RULE_HANDLE, r.handle);
    if let Some(p) = prev {
        m.u64(NFTA_RULE_POSITION, p);
    }
    m.nest(NFTA_RULE_EXPRESSIONS);
    for e in &r.exprs {
        e.dump(&mut m);
    }
    m.end();
    if let Some(u) = &r.userdata {
        m.attr(NFTA_RULE_USERDATA, u);
    }
    m.finish()
}

fn dump_set(t: &Table, s: &Set, g: u32, seq: u32, port: u32, flags: u16) -> Vec<u8> {
    let mut m = Msg::new(nft(NFT_MSG_NEWSET), flags, seq, port, t.family, g as u16);
    m.str(NFTA_SET_TABLE, &t.name).str(NFTA_SET_NAME, &s.name).u64(NFTA_SET_HANDLE, s.handle);
    if s.flags != 0 {
        m.u32(NFTA_SET_FLAGS, s.flags);
    }
    m.u32(NFTA_SET_KEY_TYPE, s.key_type).u32(NFTA_SET_KEY_LEN, s.key_len);
    if let Some(d) = s.data_type {
        m.u32(NFTA_SET_DATA_TYPE, d).u32(NFTA_SET_DATA_LEN, s.data_len);
    }
    if let Some(p) = s.policy {
        m.u32(NFTA_SET_POLICY, p);
    }
    if let Some(u) = &s.userdata {
        m.attr(NFTA_SET_USERDATA, u);
    }
    m.nest(NFTA_SET_DESC);
    if let Some(n) = s.desc_size {
        m.u32(1, n);
    }
    m.end();
    // How many elements (intervals count once). Linux also names its
    // set backend here (NFTA_SET_TYPE), which means nothing elsewhere.
    m.u32(NFTA_SET_COUNT, s.elems.iter().filter(|e| e.flags & NFT_SET_ELEM_INTERVAL_END == 0).count() as u32);
    m.finish()
}

fn dump_elems(t: &Table, s: &Set, elems: &[Elem], g: u32, seq: u32, port: u32, flags: u16) -> Vec<u8> {
    let mut m = Msg::new(nft(NFT_MSG_NEWSETELEM), flags, seq, port, t.family, g as u16);
    m.str(NFTA_SET_ELEM_LIST_TABLE, &t.name).str(NFTA_SET_ELEM_LIST_SET, &s.name);
    m.nest(NFTA_SET_ELEM_LIST_ELEMENTS);
    for e in elems {
        m.nest(NFTA_LIST_ELEM);
        m.nest(NFTA_SET_ELEM_KEY).attr(NFTA_DATA_VALUE, &e.key).end();
        if let Some(k) = &e.key_end {
            m.nest(NFTA_SET_ELEM_KEY_END).attr(NFTA_DATA_VALUE, k).end();
        }
        if let Some(d) = &e.data {
            d.dump(&mut m, NFTA_SET_ELEM_DATA);
        }
        if e.flags != 0 {
            m.u32(NFTA_SET_ELEM_FLAGS, e.flags);
        }
        if let Some(u) = &e.userdata {
            m.attr(NFTA_SET_ELEM_USERDATA, u);
        }
        m.end();
    }
    m.end();
    m.finish()
}
