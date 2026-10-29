// SPDX-License-Identifier: MIT OR Apache-2.0

//! Linux's own answers, replayed: `tests/fixtures/*.txt` are nft sessions
//! captured on the host in a network namespace of their own (ADR 0128;
//! `>` what nft sent, `<` what Linux answered, as hex). Every request goes
//! to a fresh ruleset; its answers must be Linux's, byte for byte.

use alloc::vec::Vec;

use crate::{AckOpts, Ruleset};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// The datagrams of a fixture: each request with what answered it.
fn exchanges(text: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for line in text.lines() {
        let (dir, h) = line.split_at(2);
        match dir {
            "> " => out.push((hex(h), Vec::new())),
            _ => {
                if let Some(last) = out.last_mut() {
                    last.1.extend_from_slice(&hex(h));
                }
            }
        }
    }
    out
}

/// The port an answer went to (the program's), from its first message.
fn port_of(answer: &[u8]) -> u32 {
    if answer.len() < 16 { 0 } else { u32::from_ne_bytes(answer[12..16].try_into().unwrap()) }
}

/// Linux's answers without what Slate leaves out: set dumps' backend name
/// (NFTA_SET_TYPE, Linux's own set implementation).
fn normalize(b: &[u8]) -> Vec<u8> {
    use crate::attr::{Attrs, messages};
    use crate::consts::*;
    let mut out = Vec::new();
    for (h, body) in messages(b) {
        let mut m = body.to_vec();
        if h.kind == (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSET && m.len() >= 4 {
            let mut kept = m[..4].to_vec();
            let attrs = Attrs(&body[4..]);
            let mut at = 4;
            for a in attrs.iter() {
                let len = 4 + a.value.len();
                if a.kind != NFTA_SET_TYPE {
                    kept.extend_from_slice(&body[at..at + len.next_multiple_of(4)]);
                }
                at += len.next_multiple_of(4);
            }
            m = kept;
        }
        out.extend_from_slice(&((16 + m.len()) as u32).to_ne_bytes());
        out.extend_from_slice(&h.kind.to_ne_bytes());
        out.extend_from_slice(&h.flags.to_ne_bytes());
        out.extend_from_slice(&h.seq.to_ne_bytes());
        out.extend_from_slice(&h.port.to_ne_bytes());
        out.extend_from_slice(&m);
    }
    out
}

fn replay(name: &str, text: &str) {
    replay_as(name, text, b"nft", AckOpts { capped: false, extended: true });
}

/// [`replay`] for a program called `comm` (it names itself in NEWGEN) on
/// a socket with acknowledgement options `o` (nft asks for extended
/// acknowledgements, iptables for none).
fn replay_as(name: &str, text: &str, comm: &[u8], o: AckOpts) {
    let mut r = Ruleset::default();
    // The program's port follows it from answer to answer; a request with
    // no answer keeps the last.
    let mut port = 0;
    for (n, (req, want)) in exchanges(text).into_iter().enumerate() {
        if !want.is_empty() {
            port = port_of(&want);
        }
        let got: Vec<u8> = r.netlink_opts(&req, port, port, comm, o).concat();
        let want = normalize(&want);
        assert!(
            got == want,
            "{name}: datagram {n} ({} bytes sent): answered\\n{}\\nLinux answered\\n{}",
            req.len(),
            hexs(&got),
            hexs(&want)
        );
    }
}

fn hexs(b: &[u8]) -> alloc::string::String {
    b.iter().map(|x| alloc::format!("{x:02x}")).collect()
}

#[test]
fn basic_session_as_linux() {
    replay("basic", include_str!("../tests/fixtures/basic.txt"));
}

#[test]
fn rich_session_as_linux() {
    replay("rich", include_str!("../tests/fixtures/rich.txt"));
}

#[test]
fn edits_as_linux() {
    replay("edits", include_str!("../tests/fixtures/edits.txt"));
}

// --- evaluation, on the rich session's ruleset -------------------------------

use crate::consts::*;
use crate::{Conntrack, Expr, Iface, Outcome, Packet, Reject};

/// The ruleset Linux made of `rich.txt`'s nft -f (the same requests).
fn rich() -> Ruleset {
    let mut r = Ruleset::default();
    for (req, want) in exchanges(include_str!("../tests/fixtures/rich.txt")) {
        let port = port_of(&want);
        r.netlink(&req, port, port, b"nft");
    }
    r
}

/// An IPv4 packet with a transport header of `proto` (TCP: ports and
/// flags; UDP: ports; ICMP: type and identifier in `dport`).
fn v4(src: [u8; 4], dst: [u8; 4], proto: u8, sport: u16, dport: u16, tcp_flags: u8) -> Vec<u8> {
    let mut p = alloc::vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, proto, 0, 0];
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    match proto {
        6 => {
            p.extend_from_slice(&sport.to_be_bytes());
            p.extend_from_slice(&dport.to_be_bytes());
            p.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, tcp_flags, 0xFF, 0xFF, 0, 0, 0, 0]);
        }
        17 => {
            p.extend_from_slice(&sport.to_be_bytes());
            p.extend_from_slice(&dport.to_be_bytes());
            p.extend_from_slice(&[0, 8, 0, 0]);
        }
        _ => {
            p.extend_from_slice(&[sport as u8, 0, 0, 0]);
            p.extend_from_slice(&dport.to_be_bytes());
            p.extend_from_slice(&[0, 1]);
        }
    }
    let len = p.len() as u16;
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p
}

const ETH0: Iface<'static> = Iface { index: 2, name: b"eth0", kind: 1 };
const LO: Iface<'static> = Iface { index: 1, name: b"lo", kind: 772 };

/// Run `p` through `hook` with tracking, as the stack does.
fn run(
    r: &mut Ruleset,
    ct: &mut Conntrack,
    hook: u32,
    net: &[u8],
    iif: Option<Iface<'_>>,
    oif: Option<Iface<'_>>,
) -> Outcome {
    let p = Packet {
        hook,
        v6: false,
        net,
        l4: Some((net[9], 20)),
        ll: None,
        iif,
        oif,
        pkttype: 0,
        owner: None,
        local: None,
        types: (0, 0),
    };
    let info = r.track(ct, &p, 0);
    let mut mark = 0;
    r.evaluate(&p, info, &mut mark)
}

#[test]
fn rich_ruleset_decides_like_nft() {
    let mut r = rich();
    let mut ct = Conntrack::default();
    let me = [10, 0, 0, 100];
    let mut input = |r: &mut Ruleset, src: [u8; 4], proto: u8, dport: u16| {
        let p = v4(src, me, proto, 40000, dport, 0x02);
        run(r, &mut ct, NF_INET_PRE_ROUTING, &p, Some(ETH0), None);
        run(r, &mut ct, NF_INET_LOCAL_IN, &p, Some(ETH0), None)
    };
    let other = [10, 0, 0, 9];
    // ssh only from the allowed set, counted.
    assert_eq!(input(&mut r, [10, 0, 0, 1], 6, 22), Outcome::Accept);
    assert_eq!(input(&mut r, other, 6, 22), Outcome::Drop);
    // The interval set: 8000-8080 and 9000; 8081 is past the range.
    assert_eq!(input(&mut r, other, 6, 8050), Outcome::Accept);
    assert_eq!(input(&mut r, other, 6, 8081), Outcome::Drop);
    assert_eq!(input(&mut r, other, 6, 9000), Outcome::Accept);
    // The verdict map, the jump to "extra" and its anonymous set.
    assert_eq!(input(&mut r, other, 6, 25), Outcome::Drop);
    assert_eq!(input(&mut r, other, 6, 110), Outcome::Accept);
    assert_eq!(input(&mut r, other, 6, 443), Outcome::Accept);
    // Rejects: a reset for telnet, port unreachable (ICMPX) for tftp.
    assert_eq!(input(&mut r, other, 6, 23), Outcome::Reject(Reject::TcpReset));
    assert_eq!(input(&mut r, other, 17, 69), Outcome::Reject(Reject::Unreachable(3)));
    assert_eq!(input(&mut r, other, 1, 0x0800), Outcome::Accept);
    let counted = r.tables[0].chains[0].rules[3].exprs.iter().find_map(|e| match e {
        Expr::Counter { packets, .. } => Some(*packets),
        _ => None,
    });
    assert_eq!(counted, Some(1));
    // Loopback: anything.
    let p = v4([127, 0, 0, 1], [127, 0, 0, 1], 6, 1, 4444, 0x02);
    assert_eq!(run(&mut r, &mut ct, NF_INET_LOCAL_IN, &p, Some(LO), None), Outcome::Accept);
}

#[test]
fn replies_to_own_connections_are_established() {
    let mut r = rich();
    let mut ct = Conntrack::default();
    let (me, them) = ([10, 0, 0, 100], [198, 51, 100, 50]);
    // Nothing allows port 5555 in; this host's connection out of it is
    // tracked, so the answer is established and accepted.
    let reply = v4(them, me, 6, 443, 5555, 0x12);
    assert_eq!(run(&mut r, &mut ct, NF_INET_LOCAL_IN, &reply, Some(ETH0), None), Outcome::Drop);
    let out = v4(me, them, 6, 5555, 443, 0x02);
    assert_eq!(run(&mut r, &mut ct, NF_INET_LOCAL_OUT, &out, None, Some(ETH0)), Outcome::Accept);
    run(&mut r, &mut ct, NF_INET_PRE_ROUTING, &reply, Some(ETH0), None);
    assert_eq!(run(&mut r, &mut ct, NF_INET_LOCAL_IN, &reply, Some(ETH0), None), Outcome::Accept);
    // An ICMP error about that connection is related, so accepted too.
    let mut err = v4([198, 51, 100, 1], me, 1, 3, 0, 0);
    err.truncate(20 + 8);
    err[21] = 1;
    err.extend_from_slice(&out[..28]);
    let len = err.len() as u16;
    err[2..4].copy_from_slice(&len.to_be_bytes());
    run(&mut r, &mut ct, NF_INET_PRE_ROUTING, &err, Some(ETH0), None);
    assert_eq!(run(&mut r, &mut ct, NF_INET_LOCAL_IN, &err, Some(ETH0), None), Outcome::Accept);
    // The ip table's output chain drops 192.0.2.0/24 out of eth0 only.
    let p = v4(me, [192, 0, 2, 7], 17, 1, 53, 0);
    assert_eq!(run(&mut r, &mut ct, NF_INET_LOCAL_OUT, &p, None, Some(ETH0)), Outcome::Drop);
    assert_eq!(run(&mut r, &mut ct, NF_INET_LOCAL_OUT, &p, None, Some(LO)), Outcome::Accept);
}

// --- NAT (ADR 0132), on the nat session's ruleset -----------------------------
//
// nat.txt is `nft -f` of this ruleset, then `nft list ruleset`:
//   table ip n {
//     chain pre { type nat hook prerouting priority dstnat; policy accept;
//       tcp dport 8080 dnat to 10.1.0.2:80
//       iifname "eth9" udp dport 5000-5010 dnat to 10.1.0.3 }
//     chain post { type nat hook postrouting priority srcnat; policy accept;
//       ip saddr 10.1.0.0/16 oifname != "br9" masquerade
//       ip saddr 10.2.0.0/16 snat to 192.0.2.1
//       ip saddr 10.3.0.0/16 meta l4proto tcp masquerade to :2000-3000 random
//       ip saddr 10.4.0.0/16 meta l4proto udp snat to 192.0.2.1-192.0.2.9:100-200 persistent }
//     chain out { type nat hook output priority dstnat; policy accept;
//       tcp dport 9090 redirect to :80
//       udp dport 53 redirect } }

#[test]
fn nat_session_as_linux() {
    replay("nat", include_str!("../tests/fixtures/nat.txt"));
}

/// The ruleset of `nat.txt`.
fn nat_rules() -> Ruleset {
    let mut r = Ruleset::default();
    for (req, want) in exchanges(include_str!("../tests/fixtures/nat.txt")) {
        let port = port_of(&want);
        r.netlink(&req, port, port, b"nft");
    }
    r
}

const BR9: Iface<'static> = Iface { index: 3, name: b"br9", kind: 1 };
const PUBLIC: [u8; 4] = [203, 0, 113, 1];

fn addr16(a: [u8; 4]) -> [u8; 16] {
    let mut x = [0u8; 16];
    x[..4].copy_from_slice(&a);
    x
}

/// The Internet checksum of `b` with `sum` added: 0 over data whose
/// checksum is right.
fn sum16(b: &[u8], mut sum: u32) -> u16 {
    for w in b.chunks(2) {
        sum += u32::from(u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// A packet with its checksums made (IPv4 header, and TCP or UDP over the
/// pseudo-header, or ICMP).
fn sealed(mut p: Vec<u8>) -> Vec<u8> {
    p[10..12].fill(0);
    let c = sum16(&p[..20], 0);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    let proto = p[9];
    let at = match proto {
        6 => 36,
        17 => 26,
        _ => 22,
    };
    p[at..at + 2].fill(0);
    let pseudo = if proto == 1 { 0 } else { pseudo(&p) };
    let c = sum16(&p[20..], pseudo);
    p[at..at + 2].copy_from_slice(&c.to_be_bytes());
    p
}

fn pseudo(p: &[u8]) -> u32 {
    let mut s = 0u32;
    for w in p[12..20].chunks(2) {
        s += u32::from(u16::from_be_bytes([w[0], w[1]]));
    }
    s + u32::from(p[9]) + (p.len() - 20) as u32
}

/// Whether every checksum of `p` checks.
fn sound(p: &[u8]) -> bool {
    let l4 = if p[9] == 1 { sum16(&p[20..], 0) } else { sum16(&p[20..], pseudo(p)) };
    sum16(&p[..20], 0) == 0 && l4 == 0
}

/// Run `net` through `hook` as the stack does, carrying its connection.
fn hop(
    r: &mut Ruleset,
    ct: &mut Conntrack,
    hook: u32,
    net: &mut [u8],
    io: (Option<Iface<'_>>, Option<Iface<'_>>),
    local: Option<[u8; 4]>,
    tracked: &mut Option<crate::Tracked>,
) -> Outcome {
    let copy = net.to_vec();
    let p = Packet {
        hook,
        v6: false,
        net: &copy,
        l4: Some((copy[9], 20)),
        ll: None,
        iif: io.0,
        oif: io.1,
        pkttype: 0,
        owner: None,
        local: local.map(addr16),
        types: (0, 0),
    };
    let mut mark = 0;
    r.process(ct, net, &p, tracked, 0, &mut mark)
}

/// A packet forwarded from `iif` to `oif`: prerouting, forward,
/// postrouting (the router's address on each side as `local`).
fn forward(r: &mut Ruleset, ct: &mut Conntrack, net: &mut [u8], iif: Iface<'_>, oif: Iface<'_>) -> Outcome {
    let side = |i: Iface<'_>| if i.index == ETH0.index { PUBLIC } else { [10, 1, 0, 1] };
    let mut t = None;
    for (hook, io, local) in [
        (NF_INET_PRE_ROUTING, (Some(iif), None), Some(side(iif))),
        (NF_INET_FORWARD, (Some(iif), Some(oif)), None),
        (NF_INET_POST_ROUTING, (None, Some(oif)), Some(side(oif))),
    ] {
        let o = hop(r, ct, hook, net, io, local, &mut t);
        if o != Outcome::Accept {
            return o;
        }
    }
    Outcome::Accept
}

#[test]
fn masquerade_and_its_replies() {
    let mut r = nat_rules();
    let mut ct = Conntrack::default();
    let (inside, dns) = ([10, 1, 0, 5], [8, 8, 8, 8]);
    // Out: the source becomes the outside address; the port stays.
    let mut p = sealed(v4(inside, dns, 17, 4000, 53, 0));
    assert_eq!(forward(&mut r, &mut ct, &mut p, BR9, ETH0), Outcome::Accept);
    assert_eq!((&p[12..16], &p[20..22]), (&PUBLIC[..], &4000u16.to_be_bytes()[..]));
    assert!(sound(&p), "checksums after masquerade");
    // The answer comes back to the inside host.
    let mut back = sealed(v4(dns, PUBLIC, 17, 53, 4000, 0));
    assert_eq!(forward(&mut r, &mut ct, &mut back, ETH0, BR9), Outcome::Accept);
    assert_eq!((&back[16..20], &back[22..24]), (&inside[..], &4000u16.to_be_bytes()[..]));
    assert!(sound(&back), "checksums of the reply");
    // A second inside host on the same port gets another one outside.
    let mut q = sealed(v4([10, 1, 0, 6], dns, 17, 4000, 53, 0));
    assert_eq!(forward(&mut r, &mut ct, &mut q, BR9, ETH0), Outcome::Accept);
    let port = u16::from_be_bytes([q[20], q[21]]);
    assert!(port != 4000 && port >= 1024, "port {port}");
    assert!(sound(&q));
    // Leaving by br9 itself: no masquerade.
    let mut lan = sealed(v4(inside, [10, 1, 0, 9], 17, 4001, 53, 0));
    assert_eq!(forward(&mut r, &mut ct, &mut lan, ETH0, BR9), Outcome::Accept);
    assert_eq!(&lan[12..16], &inside[..]);
    // An ICMP error about the first flow, from a router outside: to the
    // inside host, quoting the packet as it left there.
    let mut err = v4([192, 0, 2, 254], PUBLIC, 1, 3, 0, 0);
    err.truncate(28);
    err[20] = 3;
    err[21] = 4;
    err.extend_from_slice(&p[..28]);
    let len = err.len() as u16;
    err[2..4].copy_from_slice(&len.to_be_bytes());
    let mut err = sealed(err);
    assert_eq!(forward(&mut r, &mut ct, &mut err, ETH0, BR9), Outcome::Accept);
    assert_eq!(&err[16..20], &inside[..], "outer destination");
    assert_eq!((&err[40..44], &err[48..50]), (&inside[..], &4000u16.to_be_bytes()[..]), "quoted source");
    assert!(sum16(&err[..20], 0) == 0 && sum16(&err[20..], 0) == 0, "checksums of the error");
}

#[test]
fn dnat_and_its_replies() {
    let mut r = nat_rules();
    let mut ct = Conntrack::default();
    let (client, server) = ([198, 51, 100, 7], [10, 1, 0, 2]);
    let mut syn = sealed(v4(client, PUBLIC, 6, 5555, 8080, 0x02));
    assert_eq!(forward(&mut r, &mut ct, &mut syn, ETH0, BR9), Outcome::Accept);
    assert_eq!((&syn[16..20], &syn[22..24]), (&server[..], &80u16.to_be_bytes()[..]));
    assert!(sound(&syn));
    // The server's answer leaves from the address the client asked for
    // (and isn't masqueraded: only new flows meet the nat chains).
    let mut ack = sealed(v4(server, client, 6, 80, 5555, 0x12));
    assert_eq!(forward(&mut r, &mut ct, &mut ack, BR9, ETH0), Outcome::Accept);
    assert_eq!((&ack[12..16], &ack[20..22]), (&PUBLIC[..], &8080u16.to_be_bytes()[..]));
    assert!(sound(&ack));
    // A port the rules don't name is left alone.
    let mut other = sealed(v4(client, PUBLIC, 6, 5556, 8081, 0x02));
    forward(&mut r, &mut ct, &mut other, ETH0, BR9);
    assert_eq!(&other[16..20], &PUBLIC[..]);
}

#[test]
fn redirect_in_output() {
    let mut r = nat_rules();
    let mut ct = Conntrack::default();
    let me = [10, 0, 0, 100];
    let mut q = sealed(v4(me, [9, 9, 9, 9], 17, 3333, 53, 0));
    let mut t = None;
    assert_eq!(hop(&mut r, &mut ct, NF_INET_LOCAL_OUT, &mut q, (None, Some(ETH0)), None, &mut t), Outcome::Accept);
    assert_eq!((&q[16..20], &q[22..24]), (&[127, 0, 0, 1][..], &53u16.to_be_bytes()[..]));
    assert!(sound(&q));
    // The answer from the local server looks as if it came from 9.9.9.9.
    let mut a = sealed(v4([127, 0, 0, 1], me, 17, 53, 3333, 0));
    let mut t = None;
    hop(&mut r, &mut ct, NF_INET_LOCAL_OUT, &mut a, (None, Some(LO)), None, &mut t);
    hop(&mut r, &mut ct, NF_INET_POST_ROUTING, &mut a, (None, Some(LO)), None, &mut t);
    hop(&mut r, &mut ct, NF_INET_PRE_ROUTING, &mut a, (Some(LO), None), None, &mut t);
    hop(&mut r, &mut ct, NF_INET_LOCAL_IN, &mut a, (Some(LO), None), None, &mut t);
    assert_eq!((&a[12..16], &a[20..22]), (&[9, 9, 9, 9][..], &53u16.to_be_bytes()[..]));
    assert!(sound(&a));
}

#[test]
fn nat_statements_only_in_nat_chains() {
    // `masq` in a filter chain's rule is refused (EOPNOTSUPP), as Linux's
    // nft_masq_validate refuses it.
    let r = nat_rules();
    let f = r.tables[0].chains.iter().position(|c| c.name == b"pre").unwrap();
    let base = r.tables[0].chains[f].base.clone().unwrap();
    assert_eq!(&base.kind[..], b"nat");
    let masq = Expr::Masq { flags: 0, proto: None };
    assert!(masq.nat_hooks() & (1 << NF_INET_PRE_ROUTING) == 0);
}

// --- iptables-nft (ADR 0133) --------------------------------------------------
//
// docker.txt is iptables-nft 1.8.11 making Docker 28's default bridge
// rules (one program run per rule, each listing what it needs first),
// then `iptables -t nat -C`, `-t nat -L -n` and `-S`.

#[test]
fn iptables_session_as_linux() {
    replay_as("docker", include_str!("../tests/fixtures/docker.txt"), b"iptables", AckOpts::default());
}

/// The rules of `docker.txt`.
fn docker_rules() -> Ruleset {
    let mut r = Ruleset::default();
    for (req, want) in exchanges(include_str!("../tests/fixtures/docker.txt")) {
        let port = port_of(&want);
        r.netlink_opts(&req, port, port, b"iptables", AckOpts::default());
    }
    r
}

const DOCKER0: Iface<'static> = Iface { index: 3, name: b"docker0", kind: 1 };

/// A packet through a host with Docker's rules from `iif` to `oif`
/// (forwarded) or to the host (`oif` none), the host's address on each
/// side as NAT's `local`, its destination's type as the stack gives it.
fn through(r: &mut Ruleset, ct: &mut Conntrack, net: &mut [u8], iif: Iface<'_>, oif: Option<Iface<'_>>) -> Outcome {
    use crate::compat::{XT_ADDRTYPE_LOCAL, XT_ADDRTYPE_UNICAST};
    let side = |i: Iface<'_>| if i.index == ETH0.index { PUBLIC } else { [172, 17, 0, 1] };
    let mut t = None;
    let hooks: &[(u32, Option<Iface<'_>>, Option<Iface<'_>>)] = match oif {
        Some(o) => &[
            (NF_INET_PRE_ROUTING, Some(iif), None),
            (NF_INET_FORWARD, Some(iif), Some(o)),
            (NF_INET_POST_ROUTING, None, Some(o)),
        ],
        None => &[(NF_INET_PRE_ROUTING, Some(iif), None), (NF_INET_LOCAL_IN, Some(iif), None)],
    };
    for &(hook, i, o) in hooks {
        let copy = net.to_vec();
        let mine = |a: &[u8]| a == PUBLIC || a == [172, 17, 0, 1];
        let kind = |a: &[u8]| if mine(a) { XT_ADDRTYPE_LOCAL } else { XT_ADDRTYPE_UNICAST };
        let p = Packet {
            hook,
            v6: false,
            net: &copy,
            l4: Some((copy[9], 20)),
            ll: None,
            iif: i,
            oif: o,
            pkttype: 0,
            owner: None,
            local: i.or(o).map(|x| addr16(side(x))),
            types: (kind(&copy[12..16]), kind(&copy[16..20])),
        };
        let mut mark = 0;
        let out = r.process(ct, net, &p, &mut t, 0, &mut mark);
        if out != Outcome::Accept {
            return out;
        }
    }
    Outcome::Accept
}

#[test]
fn docker_rules_route_containers() {
    let mut r = docker_rules();
    let mut ct = Conntrack::default();
    let (box_ip, dns) = ([172, 17, 0, 2], [8, 8, 8, 8]);
    // Out of a container: masqueraded; the answer goes back in.
    let mut q = sealed(v4(box_ip, dns, 17, 5000, 53, 0));
    assert_eq!(through(&mut r, &mut ct, &mut q, DOCKER0, Some(ETH0)), Outcome::Accept);
    assert_eq!(&q[12..16], &PUBLIC[..]);
    assert!(sound(&q));
    let mut a = sealed(v4(dns, PUBLIC, 17, 53, 5000, 0));
    assert_eq!(through(&mut r, &mut ct, &mut a, ETH0, Some(DOCKER0)), Outcome::Accept);
    assert_eq!(&a[16..20], &box_ip[..]);
    // The published port: 8080 on the host is the container's 80, let
    // through by the DOCKER chain.
    let client = [198, 51, 100, 7];
    let mut syn = sealed(v4(client, PUBLIC, 6, 6000, 8080, 0x02));
    assert_eq!(through(&mut r, &mut ct, &mut syn, ETH0, Some(DOCKER0)), Outcome::Accept);
    assert_eq!((&syn[16..20], &syn[22..24]), (&box_ip[..], &80u16.to_be_bytes()[..]));
    // Anything else from outside to the container: dropped (the raw
    // table's guard first).
    let mut probe = sealed(v4(client, box_ip, 6, 6001, 22, 0x02));
    assert_eq!(through(&mut r, &mut ct, &mut probe, ETH0, Some(DOCKER0)), Outcome::Drop);
    // Between containers on the bridge: accepted (in by docker0).
    let mut peer = sealed(v4(box_ip, [172, 17, 0, 3], 6, 6002, 80, 0x02));
    assert_eq!(through(&mut r, &mut ct, &mut peer, DOCKER0, Some(DOCKER0)), Outcome::Accept);
    assert_eq!(&peer[12..16], &box_ip[..], "not masqueraded on the bridge");
}

#[test]
fn compat_revisions_and_unknown_extensions() {
    use crate::compat::{MATCH, TARGET, revision};
    assert_eq!(revision(b"conntrack", MATCH), Ok(3));
    assert_eq!(revision(b"DNAT", TARGET), Ok(2));
    assert_eq!(revision(b"DNAT", MATCH), Err(crate::expr::ENOENT));
    assert_eq!(revision(b"hashlimit", MATCH), Err(crate::expr::ENOENT));
}

// --- SlateOS's default inbound firewall (ADR 0134) ----------------------------

#[test]
fn default_inbound_firewall() {
    use crate::inbound;
    let mut r = Ruleset::default();
    let answers = r.netlink(&inbound::table(), 1, 1, b"kernel").concat();
    assert_eq!(inbound::first_error(&answers), 0, "the table loads");
    let mut ct = Conntrack::default();
    let (me, them) = ([10, 0, 0, 100], [198, 51, 100, 9]);
    let arrive = |r: &mut Ruleset, ct: &mut Conntrack, p: &[u8]| {
        run(r, ct, NF_INET_PRE_ROUTING, p, Some(ETH0), None);
        run(r, ct, NF_INET_LOCAL_IN, p, Some(ETH0), None)
    };
    // Nothing is open: a new connection in is dropped, an echo request
    // answered, DHCP's answer let in, loopback anything.
    assert_eq!(arrive(&mut r, &mut ct, &v4(them, me, 6, 40000, 22, 0x02)), Outcome::Drop);
    assert_eq!(arrive(&mut r, &mut ct, &v4(them, me, 17, 40000, 53, 0)), Outcome::Drop);
    assert_eq!(arrive(&mut r, &mut ct, &v4(them, me, 1, 8, 7, 0)), Outcome::Accept);
    assert_eq!(arrive(&mut r, &mut ct, &v4(them, me, 17, 67, 68, 0)), Outcome::Accept);
    let lo = v4([127, 0, 0, 1], [127, 0, 0, 1], 6, 1, 4444, 0x02);
    assert_eq!(run(&mut r, &mut ct, NF_INET_LOCAL_IN, &lo, Some(LO), None), Outcome::Accept);
    // This host's own connection out gets its answers.
    let out = v4(me, them, 6, 50000, 443, 0x02);
    run(&mut r, &mut ct, NF_INET_LOCAL_OUT, &out, None, Some(ETH0));
    assert_eq!(arrive(&mut r, &mut ct, &v4(them, me, 6, 443, 50000, 0x12)), Outcome::Accept);
    // Port 22 opened, and listed; closed again.
    let answers = r.netlink(&inbound::ports(true, true, &[22, 8080]), 1, 1, b"slate-firewall").concat();
    assert_eq!(inbound::first_error(&answers), 0);
    assert_eq!(arrive(&mut r, &mut ct, &v4(them, me, 6, 40001, 22, 0x02)), Outcome::Accept);
    let listed = r.netlink(&inbound::list(true), 1, 1, b"slate-firewall").concat();
    assert_eq!(inbound::listed(&listed), (alloc::vec![22, 8080], true));
    let answers = r.netlink(&inbound::ports(false, true, &[22, 9]), 1, 1, b"slate-firewall").concat();
    assert_eq!(inbound::first_error(&answers), 0, "closing a port that isn't open is no error");
    assert_eq!(arrive(&mut r, &mut ct, &v4(them, me, 6, 40002, 22, 0x02)), Outcome::Drop);
    // Off: everything comes in; the list says so.
    r.netlink(&inbound::remove(), 1, 1, b"slate-firewall");
    assert_eq!(arrive(&mut r, &mut ct, &v4(them, me, 6, 40003, 22, 0x02)), Outcome::Accept);
    let listed = r.netlink(&inbound::list(true), 1, 1, b"slate-firewall").concat();
    assert!(!inbound::listed(&listed).1);
}
