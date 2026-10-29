// SPDX-License-Identifier: MIT OR Apache-2.0

//! SlateOS's default-deny inbound firewall (ADR 0134), as nf_tables
//! batches: the kernel loads [`table`] into the initial network namespace
//! at boot, and `slate-firewall` changes which ports are open with
//! [`ports`]. It is an ordinary table, `inet slate`, that nft shows and
//! can change:
//!
//! ```text
//! table inet slate {
//!   set tcp { type inet_service; }
//!   set udp { type inet_service; }
//!   chain input {
//!     type filter hook input priority filter; policy drop;
//!     iif lo accept
//!     ct state established,related accept
//!     ct state invalid drop
//!     meta l4proto icmp icmp type echo-request accept
//!     meta l4proto ipv6-icmp accept
//!     udp sport 67 udp dport 68 accept
//!     udp sport 547 udp dport 546 accept
//!     tcp dport @tcp accept
//!     udp dport @udp accept
//!   }
//! }
//! ```
//!
//! ICMPv6 is let in whole (neighbour discovery and router advertisements
//! arrive unasked); ICMP errors come in as related. Forwarded packets
//! aren't this table's: containers' rules are their own.

use alloc::vec::Vec;

use crate::attr::{Attrs, Msg, messages};
use crate::consts::*;

/// The table's name.
pub const TABLE: &[u8] = b"slate";

/// The sets of open ports, by protocol.
pub fn set_name(tcp: bool) -> &'static [u8] {
    if tcp { b"tcp" } else { b"udp" }
}

/// inet_service, nft's type for ports (its type number, as nft sends it).
const INET_SERVICE: u32 = 13;
const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;
const ICMP_ECHO_REQUEST: u8 = 8;

fn nft(msg: u16) -> u16 {
    (NFNL_SUBSYS_NFTABLES << 8) | msg
}

/// A batch: its messages between BATCH_BEGIN and BATCH_END, each asking
/// for an acknowledgement.
struct Batch {
    out: Vec<u8>,
    seq: u32,
}

impl Batch {
    fn new() -> Batch {
        let mut b = Batch { out: Vec::new(), seq: 0 };
        b.marker(NFNL_MSG_BATCH_BEGIN);
        b
    }
    fn marker(&mut self, kind: u16) {
        self.seq += 1;
        let m = Msg::new(kind, NLM_F_REQUEST, self.seq, 0, NFPROTO_UNSPEC, NFNL_SUBSYS_NFTABLES);
        self.out.extend(m.finish());
    }
    fn msg(&mut self, kind: u16, flags: u16) -> Msg {
        self.seq += 1;
        Msg::new(nft(kind), NLM_F_REQUEST | NLM_F_ACK | flags, self.seq, 0, NFPROTO_INET, 0)
    }
    fn add(&mut self, m: Msg) {
        self.out.extend(m.finish());
    }
    fn finish(mut self) -> Vec<u8> {
        self.marker(NFNL_MSG_BATCH_END);
        self.out
    }
}

/// One expression of a rule.
fn expr(m: &mut Msg, name: &[u8], data: impl FnOnce(&mut Msg)) {
    m.nest(NFTA_LIST_ELEM).str(NFTA_EXPR_NAME, name).nest(NFTA_EXPR_DATA);
    data(m);
    m.end().end();
}

fn meta(m: &mut Msg, key: u32) {
    expr(m, b"meta", |m| {
        m.u32(NFTA_META_DREG, 1).u32(NFTA_META_KEY, key);
    });
}

fn cmp(m: &mut Msg, op: u32, v: &[u8]) {
    expr(m, b"cmp", |m| {
        m.u32(NFTA_CMP_SREG, 1).u32(NFTA_CMP_OP, op).nest(NFTA_CMP_DATA).attr(NFTA_DATA_VALUE, v).end();
    });
}

/// `len` bytes of the transport header at `offset`, to register 1.
fn transport(m: &mut Msg, offset: u32, len: u32) {
    expr(m, b"payload", |m| {
        m.u32(NFTA_PAYLOAD_DREG, 1).u32(NFTA_PAYLOAD_BASE, NFT_PAYLOAD_TRANSPORT_HEADER);
        m.u32(NFTA_PAYLOAD_OFFSET, offset).u32(NFTA_PAYLOAD_LEN, len);
    });
}

fn l4proto(m: &mut Msg, proto: u8) {
    meta(m, NFT_META_L4PROTO);
    cmp(m, NFT_CMP_EQ, &[proto]);
}

/// `ct state` has one of the bits in `mask`.
fn ct_state(m: &mut Msg, mask: u32) {
    expr(m, b"ct", |m| {
        m.u32(NFTA_CT_DREG, 1).u32(NFTA_CT_KEY, NFT_CT_STATE);
    });
    expr(m, b"bitwise", |m| {
        m.u32(NFTA_BITWISE_SREG, 1).u32(NFTA_BITWISE_DREG, 1).u32(NFTA_BITWISE_LEN, 4);
        m.nest(NFTA_BITWISE_MASK).attr(NFTA_DATA_VALUE, &mask.to_ne_bytes()).end();
        m.nest(NFTA_BITWISE_XOR).attr(NFTA_DATA_VALUE, &[0; 4]).end();
    });
    cmp(m, NFT_CMP_NEQ, &[0; 4]);
}

fn verdict(m: &mut Msg, code: i32) {
    expr(m, b"immediate", |m| {
        m.u32(NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
        m.nest(NFTA_IMMEDIATE_DATA).nest(NFTA_DATA_VERDICT).u32(NFTA_VERDICT_CODE, code as u32).end().end();
    });
}

/// A rule appended to the input chain, its expressions by `exprs`.
fn rule(b: &mut Batch, exprs: impl FnOnce(&mut Msg)) {
    let mut m = b.msg(NFT_MSG_NEWRULE, NLM_F_CREATE | NLM_F_APPEND);
    m.str(NFTA_RULE_TABLE, TABLE).str(NFTA_RULE_CHAIN, b"input").nest(NFTA_RULE_EXPRESSIONS);
    exprs(&mut m);
    m.end();
    b.add(m);
}

/// The batch that makes the table (empty sets: no port open).
pub fn table() -> Vec<u8> {
    let mut b = Batch::new();
    let mut m = b.msg(NFT_MSG_NEWTABLE, NLM_F_CREATE);
    m.str(NFTA_TABLE_NAME, TABLE);
    b.add(m);
    for (tcp, id) in [(true, 1), (false, 2)] {
        let mut m = b.msg(NFT_MSG_NEWSET, NLM_F_CREATE);
        m.str(NFTA_SET_TABLE, TABLE).str(NFTA_SET_NAME, set_name(tcp)).u32(NFTA_SET_FLAGS, 0);
        m.u32(NFTA_SET_KEY_TYPE, INET_SERVICE).u32(NFTA_SET_KEY_LEN, 2).u32(NFTA_SET_ID, id);
        b.add(m);
    }
    let mut m = b.msg(NFT_MSG_NEWCHAIN, NLM_F_CREATE);
    m.str(NFTA_CHAIN_TABLE, TABLE).str(NFTA_CHAIN_NAME, b"input");
    m.nest(NFTA_CHAIN_HOOK).u32(NFTA_HOOK_HOOKNUM, NF_INET_LOCAL_IN).u32(NFTA_HOOK_PRIORITY, 0).end();
    m.u32(NFTA_CHAIN_POLICY, NF_DROP as u32).str(NFTA_CHAIN_TYPE, b"filter");
    b.add(m);
    rule(&mut b, |m| {
        meta(m, NFT_META_IIF);
        cmp(m, NFT_CMP_EQ, &1u32.to_ne_bytes());
        verdict(m, NF_ACCEPT);
    });
    rule(&mut b, |m| {
        ct_state(m, NF_CT_STATE_ESTABLISHED | NF_CT_STATE_RELATED);
        verdict(m, NF_ACCEPT);
    });
    rule(&mut b, |m| {
        ct_state(m, NF_CT_STATE_INVALID_BIT);
        verdict(m, NF_DROP);
    });
    rule(&mut b, |m| {
        l4proto(m, PROTO_ICMP);
        transport(m, 0, 1);
        cmp(m, NFT_CMP_EQ, &[ICMP_ECHO_REQUEST]);
        verdict(m, NF_ACCEPT);
    });
    rule(&mut b, |m| {
        l4proto(m, PROTO_ICMPV6);
        verdict(m, NF_ACCEPT);
    });
    // DHCP's and DHCPv6's answers to this host's clients (RFC 2131 §4.1,
    // RFC 8415 §7.2): servers send them to ports nothing asked from.
    for (server, client) in [(67u16, 68u16), (547, 546)] {
        rule(&mut b, |m| {
            l4proto(m, PROTO_UDP);
            transport(m, 0, 2);
            cmp(m, NFT_CMP_EQ, &server.to_be_bytes());
            transport(m, 2, 2);
            cmp(m, NFT_CMP_EQ, &client.to_be_bytes());
            verdict(m, NF_ACCEPT);
        });
    }
    for (tcp, proto) in [(true, PROTO_TCP), (false, PROTO_UDP)] {
        rule(&mut b, |m| {
            l4proto(m, proto);
            transport(m, 2, 2);
            expr(m, b"lookup", |m| {
                m.str(NFTA_LOOKUP_SET, set_name(tcp)).u32(NFTA_LOOKUP_SREG, 1);
            });
            verdict(m, NF_ACCEPT);
        });
    }
    b.finish()
}

/// The batch that opens (`add`) or closes ports of one protocol. Opening
/// one that is open, or closing one that isn't, changes nothing (the
/// elements are added without NLM_F_EXCL; closing asks DESTROYSETELEM,
/// which doesn't mind).
pub fn ports(add: bool, tcp: bool, list: &[u16]) -> Vec<u8> {
    let mut b = Batch::new();
    let kind = if add { NFT_MSG_NEWSETELEM } else { NFT_MSG_DESTROYSETELEM };
    let mut m = b.msg(kind, if add { NLM_F_CREATE } else { 0 });
    m.str(NFTA_SET_ELEM_LIST_TABLE, TABLE).str(NFTA_SET_ELEM_LIST_SET, set_name(tcp));
    m.nest(NFTA_SET_ELEM_LIST_ELEMENTS);
    for p in list {
        m.nest(NFTA_LIST_ELEM).nest(NFTA_SET_ELEM_KEY).attr(NFTA_DATA_VALUE, &p.to_be_bytes()).end().end();
    }
    m.end();
    b.add(m);
    b.finish()
}

/// The batch that takes the table away (the firewall off).
pub fn remove() -> Vec<u8> {
    let mut b = Batch::new();
    let mut m = b.msg(NFT_MSG_DESTROYTABLE, 0);
    m.str(NFTA_TABLE_NAME, TABLE);
    b.add(m);
    b.finish()
}

/// A request for one set's elements (a dump).
pub fn list(tcp: bool) -> Vec<u8> {
    let mut m = Msg::new(nft(NFT_MSG_GETSETELEM), NLM_F_REQUEST | NLM_F_DUMP, 1, 0, NFPROTO_INET, 0);
    m.str(NFTA_SET_ELEM_LIST_TABLE, TABLE).str(NFTA_SET_ELEM_LIST_SET, set_name(tcp));
    m.finish()
}

/// The ports in a [`list`] answer, and whether the set was there (no:
/// the table isn't, so the firewall is off).
pub fn listed(answer: &[u8]) -> (Vec<u16>, bool) {
    let mut ports = Vec::new();
    let mut found = true;
    for (h, body) in messages(answer) {
        if h.kind == NLMSG_ERROR && body.len() >= 4 && i32::from_ne_bytes(body[..4].try_into().unwrap()) != 0 {
            found = false;
        }
        if h.kind != nft(NFT_MSG_NEWSETELEM) || body.len() < 4 {
            continue;
        }
        let Some(list) = Attrs(&body[4..]).get(NFTA_SET_ELEM_LIST_ELEMENTS) else { continue };
        for e in list.nested().iter() {
            let key = e.nested().get(NFTA_SET_ELEM_KEY).and_then(|k| k.nested().get(NFTA_DATA_VALUE));
            if let Some(v) = key.filter(|v| v.value.len() == 2) {
                ports.push(u16::from_be_bytes([v.value[0], v.value[1]]));
            }
        }
    }
    ports.sort_unstable();
    (ports, found)
}

/// The first error among a batch's acknowledgements (0: none).
pub fn first_error(answers: &[u8]) -> i32 {
    messages(answers)
        .iter()
        .filter(|(h, _)| h.kind == NLMSG_ERROR)
        .filter_map(|(_, b)| b.get(..4).map(|e| -i32::from_ne_bytes(e.try_into().unwrap())))
        .find(|e| *e != 0)
        .unwrap_or(0)
}
