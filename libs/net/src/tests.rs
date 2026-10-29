// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stacks wired back to back on a simulated Ethernet segment.

use alloc::vec::Vec;

use crate::wire::*;
use crate::{
    Change, Config, ETH_P_ALL, Error, IfAddr, IfIndex, IpOptions, LinkAddr, Neighbour, OptionField, PACKET_HOST,
    PACKET_OUTGOING, PROTO_BOOT, PROTO_KERNEL, PROTO_STATIC, Route, Stack, TcpState, dhcp,
};

const A_MAC: Mac = Mac([2, 0, 0, 0, 0, 1]);
const B_MAC: Mac = Mac([2, 0, 0, 0, 0, 2]);
pub(crate) const A_IP: Ipv4 = Ipv4([10, 0, 0, 1]);
pub(crate) const B_IP: Ipv4 = Ipv4([10, 0, 0, 2]);

/// The card of a one-card test host.
const ETH: IfIndex = 2;

/// IPv6 kept out of the IPv4 tests: no router solicitations, and the
/// link-local address's probe drained.
pub(crate) fn quiet_v6(s: &mut Stack, index: IfIndex) {
    s.set_autoconf6(index, false).unwrap();
    s.take_tx();
}

/// Give a stack's card an IPv4 address on 10.0.0.0/24.
pub(crate) fn configure_v4(s: &mut Stack, ip: Ipv4) {
    let c = Config { addr: ip, prefix_len: 24, gateway: None, dns: Vec::new() };
    s.set_config(ETH, Some(c), PROTO_BOOT).unwrap();
}

/// A stack with one card and no address.
fn card(mac: Mac, seed: u32) -> Stack {
    let mut s = Stack::new(seed);
    s.add_interface(ETH, mac, 1500).unwrap();
    quiet_v6(&mut s, ETH);
    s
}

fn configured(mac: Mac, ip: Ipv4) -> Stack {
    let mut s = card(mac, ip.0[3].into());
    let c = Config { addr: ip, prefix_len: 24, gateway: Some(Ipv4([10, 0, 0, 254])), dns: Vec::new() };
    s.set_config(ETH, Some(c), PROTO_BOOT).unwrap();
    s
}

/// Move frames between the two stacks until both are quiet.
fn exchange(a: &mut Stack, b: &mut Stack, now: u64) {
    for _ in 0..20 {
        a.poll(now);
        b.poll(now);
        let (fa, fb) = (a.take_tx(), b.take_tx());
        if fa.is_empty() && fb.is_empty() {
            return;
        }
        fa.iter().for_each(|f| b.receive(ETH, &f.1, now));
        fb.iter().for_each(|f| a.receive(ETH, &f.1, now));
    }
}

/// The first IPv4 frame in `tx`.
fn first_ipv4(tx: &[(IfIndex, Vec<u8>)]) -> &[u8] {
    tx.iter().map(|f| f.1.as_slice()).find(|f| f[12..14] == [0x08, 0x00]).expect("an IPv4 frame")
}

#[test]
fn ip_options_on_datagrams() {
    let (mut a, mut b) = (configured(A_MAC, A_IP), configured(B_MAC, B_IP));
    let c = a.udp_open();
    let to = Some((B_IP.into(), 7));
    // IP_TOS: the byte after the version and header length (RFC 791 §3.1).
    a.set_ip_options(c, IpOptions { tos: 0x10, dont_fragment: false, ..IpOptions::default() }).unwrap();
    a.send_to(c, b"first", to).unwrap();
    exchange(&mut a, &mut b, 0);
    a.send_to(c, b"second", to).unwrap();
    a.poll(0);
    assert_eq!(first_ipv4(&a.take_tx())[14 + 1], 0x10);
    // IP_PMTUDISC_DO: too big for the card's 1500 bytes is EMSGSIZE, not
    // fragments; without it the datagram goes in pieces.
    a.set_ip_options(c, IpOptions { tos: 0, dont_fragment: true, ..IpOptions::default() }).unwrap();
    assert_eq!(a.send_to(c, &[0; 2000], to), Err(Error::MessageTooLong));
    assert!(a.send_to(c, &[0; 1400], to).is_ok());
    a.set_ip_options(c, IpOptions::default()).unwrap();
    assert!(a.send_to(c, &[0; 2000], to).is_ok());
}

/// udp(7): connect sets the local address to the route's source, and
/// disconnecting (AF_UNSPEC) gives the wildcard back.
#[test]
fn udp_connect_picks_the_source() {
    let mut a = configured(A_MAC, A_IP);
    let c = a.udp_open();
    a.connect(c, (Ipv4([192, 0, 2, 1]).into(), 53)).unwrap();
    let (src, port) = a.local(c).unwrap().unwrap();
    assert_eq!(src, A_IP.into());
    a.connect(c, (Ipv4::UNSPECIFIED.into(), 0)).unwrap();
    assert_eq!(a.local(c).unwrap(), Some((Ipv4::UNSPECIFIED.into(), port)));
    // Loopback goes from loopback.
    a.connect(c, (Ipv4([127, 0, 0, 1]).into(), 53)).unwrap();
    assert_eq!(a.local(c).unwrap().unwrap().0, Ipv4([127, 0, 0, 1]).into());
}

#[test]
fn dontroute_needs_a_direct_network() {
    // 192.0.2.1 (RFC 5737) is only reachable through the gateway.
    let mut a = configured(A_MAC, A_IP);
    let far = (Ipv4([192, 0, 2, 1]).into(), 7);
    let c = a.udp_open();
    a.set_dontroute(c, true).unwrap();
    assert_eq!(a.connect(c, far), Err(Error::NetUnreachable));
    assert_eq!(a.send_to(c, b"x", Some(far)), Err(Error::NetUnreachable));
    a.connect(c, (B_IP.into(), 7)).unwrap();
    a.set_dontroute(c, false).unwrap();
    a.connect(c, far).unwrap();
}

#[test]
fn arp_then_ping() {
    let (mut a, mut b) = (configured(A_MAC, A_IP), configured(B_MAC, B_IP));
    let p = a.icmp_open(false);
    let echo = icmp(ICMP_ECHO_REQUEST, 0, [0, 0, 0, 1], b"ping!");
    a.send_to(p, &echo, Some((B_IP.into(), 0))).unwrap();
    exchange(&mut a, &mut b, 0);
    let (reply, from) = a.recv_from(p).unwrap();
    assert_eq!(from.0, B_IP.into());
    assert_eq!(reply[0], ICMP_ECHO_REPLY);
    assert_eq!(&reply[8..], b"ping!");
    // The identifier is the ping socket's port.
    assert_eq!(get16(&reply, 4), a.local(p).unwrap().unwrap().1);
}

#[test]
fn raw_icmp_sees_whole_packets() {
    let (mut a, mut b) = (configured(A_MAC, A_IP), configured(B_MAC, B_IP));
    let r = a.icmp_open(true);
    a.send_to(r, &icmp(ICMP_ECHO_REQUEST, 0, [0x12, 0x34, 0, 7], b"raw"), Some((B_IP.into(), 0))).unwrap();
    exchange(&mut a, &mut b, 0);
    let (pkt, _) = a.recv_from(r).unwrap();
    let h = Ipv4Header::parse(&pkt).unwrap();
    assert_eq!((h.src, h.proto, pkt[h.header_len]), (B_IP, PROTO_ICMP, ICMP_ECHO_REPLY));
    assert_eq!(get16(&pkt, h.header_len + 4), 0x1234);
}

#[test]
fn udp_both_ways_and_port_unreachable() {
    let (mut a, mut b) = (configured(A_MAC, A_IP), configured(B_MAC, B_IP));
    let server = b.udp_open();
    b.bind(server, Ipv4::UNSPECIFIED, 7).unwrap();
    let dup = b.udp_open();
    assert_eq!(b.bind(dup, Ipv4::UNSPECIFIED, 7), Err(Error::AddrInUse));
    let client = a.udp_open();
    a.send_to(client, b"hello", Some((B_IP.into(), 7))).unwrap();
    exchange(&mut a, &mut b, 0);
    let (data, from) = b.recv_from(server).unwrap();
    assert_eq!((data.as_slice(), from.0), (&b"hello"[..], A_IP.into()));
    b.send_to(server, b"world", Some(from)).unwrap();
    exchange(&mut a, &mut b, 0);
    assert_eq!(a.recv_from(client).unwrap().0, b"world");
    assert_eq!(a.recv_from(client), Err(Error::WouldBlock));
    // A connected socket learns that nobody listens.
    let c2 = a.udp_open();
    a.connect(c2, (B_IP.into(), 9999)).unwrap();
    a.send_to(c2, b"anyone?", None).unwrap();
    exchange(&mut a, &mut b, 0);
    assert_eq!(a.recv_from(c2), Err(Error::ConnectionRefused));
}

#[test]
fn icmp_errors_queued_and_where_datagrams_arrived() {
    let (mut a, mut b) = (configured(A_MAC, A_IP), configured(B_MAC, B_IP));
    // IP_RECVERR (ip(7)): an unconnected socket hears of the error too,
    // and gets it queued with the payload and the datagram's destination.
    let tx = a.udp_open();
    a.set_recverr(tx, true).unwrap();
    a.send_to(tx, b"payload!", Some((B_IP.into(), 9))).unwrap();
    let quiet = a.udp_open();
    a.send_to(quiet, b"x", Some((B_IP.into(), 9))).unwrap();
    exchange(&mut a, &mut b, 0);
    assert!(a.errors_queued(tx) && !a.errors_queued(quiet));
    assert_eq!(a.take_error(tx), Ok(Some(Error::ConnectionRefused)));
    assert_eq!(a.take_error(quiet), Ok(None));
    let e = a.recv_error(tx, false).unwrap();
    assert_eq!(
        (e.error, e.origin, e.kind, e.code),
        (Error::ConnectionRefused, crate::ORIGIN_ICMP, ICMP_DEST_UNREACHABLE, ICMP_PORT_UNREACHABLE)
    );
    assert_eq!((e.offender, e.dest, e.payload.as_slice()), (B_IP.into(), (B_IP.into(), 9), &b"payload!"[..]));
    assert_eq!(a.recv_error(tx, false), Err(Error::WouldBlock));
    // Where a datagram arrived: its destination, the interface, the TOS.
    let rx = b.udp_open();
    b.bind(rx, Ipv4::UNSPECIFIED, 7).unwrap();
    let s = a.udp_open();
    a.set_ip_options(s, IpOptions { tos: 0x28, ..IpOptions::default() }).unwrap();
    a.send_to(s, b"meta", Some((B_IP.into(), 7))).unwrap();
    exchange(&mut a, &mut b, 0);
    let (d, _, meta) = b.recv_meta(rx).unwrap();
    assert_eq!((d.as_slice(), meta.to, meta.tos), (&b"meta"[..], Some(B_IP.into()), 0x28));
    assert_ne!(meta.ifindex, 0);
}

#[test]
fn udp_segments() {
    let (mut a, mut b) = (configured(A_MAC, A_IP), configured(B_MAC, B_IP));
    let rx = b.udp_open();
    b.bind(rx, Ipv4::UNSPECIFIED, 7).unwrap();
    let tx = a.udp_open();
    // 250 bytes in segments of 100: three datagrams, 100, 100 and 50.
    assert_eq!(a.send_segments(tx, &[7; 250], Some((B_IP.into(), 7)), 100), Ok(250));
    exchange(&mut a, &mut b, 0);
    let sizes: Vec<usize> = core::iter::from_fn(|| b.recv_meta(rx).ok().map(|d| d.0.len())).collect();
    assert_eq!(sizes, [100, 100, 50]);
    // At most 128 segments; each within the path's MTU (1500 here).
    assert_eq!(a.send_segments(tx, &[0; 12_900], Some((B_IP.into(), 7)), 100), Err(Error::InvalidInput));
    assert_eq!(a.send_segments(tx, &[0; 4000], Some((B_IP.into(), 7)), 1600), Err(Error::MessageTooLong));
    // Not longer than a segment: one datagram.
    assert_eq!(a.send_segments(tx, b"one", Some((B_IP.into(), 7)), 100), Ok(3));
    exchange(&mut a, &mut b, 0);
    assert_eq!(b.recv_meta(rx).unwrap().0, b"one");
}

#[test]
fn loopback_without_a_network() {
    let mut s = card(A_MAC, 1);
    let rx = s.udp_open();
    s.bind(rx, Ipv4::LOCALHOST, 5000).unwrap();
    let tx = s.udp_open();
    s.send_to(tx, b"local", Some((Ipv4::LOCALHOST.into(), 5000))).unwrap();
    s.poll(0);
    let (d, from) = s.recv_from(rx).unwrap();
    assert_eq!((d.as_slice(), from.0), (&b"local"[..], Ipv4::LOCALHOST.into()));
    assert!(s.take_tx().is_empty());
    // Off-link destinations need an address.
    assert_eq!(s.send_to(tx, b"x", Some((B_IP.into(), 1))), Err(Error::NetUnreachable));
}

#[test]
fn connect_without_a_route() {
    let mut s = Stack::new(1);
    let u = s.udp_open();
    assert_eq!(s.connect(u, (B_IP.into(), 53)), Err(Error::NetUnreachable));
    assert_eq!(s.connect(u, (Ipv4([127, 0, 0, 1]).into(), 53)), Ok(()));
    let mut c = configured(A_MAC, A_IP);
    let v = c.udp_open();
    assert_eq!(c.connect(v, (Ipv4([8, 8, 8, 8]).into(), 53)), Ok(()));
}

#[test]
fn arp_gives_up() {
    let mut a = configured(A_MAC, A_IP);
    let u = a.udp_open();
    a.send_to(u, b"x", Some((Ipv4([10, 0, 0, 77]).into(), 1))).unwrap();
    let mut requests = 0;
    for t in (0..10_000).step_by(100) {
        a.poll(t);
        requests += a.take_tx().iter().filter(|f| get16(&f.1, 12) == ETHERTYPE_ARP).count();
    }
    assert_eq!(requests, 3);
}

#[test]
fn dhcp_against_a_small_server() {
    let mut c = card(A_MAC, 99);
    c.start_dhcp(ETH, 0).unwrap();
    let server_ip = Ipv4([10, 0, 2, 2]);
    let offer_ip = Ipv4([10, 0, 2, 15]);
    let mut acked = false;
    for t in 0..10u64 {
        for (_, f) in c.take_tx() {
            // The "server": answer DISCOVER with OFFER and REQUEST with ACK.
            let h = Ipv4Header::parse(&f[ETH_HEADER..]).unwrap();
            let Some((_, 67, m)) = parse_udp(h.src, h.dst, &f[ETH_HEADER + h.header_len..]) else { continue };
            let (kind, xid, req) = dhcp::parse_client(m).unwrap();
            let reply_kind = match kind {
                dhcp::DISCOVER => dhcp::OFFER,
                dhcp::REQUEST => {
                    assert_eq!(req, Some(offer_ip));
                    acked = true;
                    dhcp::ACK
                }
                _ => continue,
            };
            let r = dhcp::server_message(reply_kind, xid, A_MAC, offer_ip, server_ip, server_ip, Ipv4([10, 0, 2, 3]));
            let d = udp(server_ip, 67, Ipv4::BROADCAST, 68, &r);
            let p = ipv4(server_ip, Ipv4::BROADCAST, PROTO_UDP, 1, 64, &d);
            c.receive(ETH, &ethernet(Mac::BROADCAST, B_MAC, ETHERTYPE_IPV4, &p), t * 100);
        }
        c.poll(t * 100);
    }
    assert!(acked && c.dhcp_bound(ETH));
    let cfg = c.config(ETH).unwrap();
    assert_eq!(
        (cfg.addr, cfg.prefix_len, cfg.gateway, cfg.dns.as_slice()),
        (offer_ip, 24, Some(server_ip), &[Ipv4([10, 0, 2, 3])][..])
    );
    assert_eq!(c.lease(ETH).unwrap().lease_secs, 86400);
}

#[test]
fn answers_arp_and_ping_for_others() {
    let (mut a, mut b) = (configured(A_MAC, A_IP), configured(B_MAC, B_IP));
    // B pings A through a raw socket; A answers with its own stack.
    let r = b.icmp_open(true);
    b.send_to(r, &icmp(ICMP_ECHO_REQUEST, 0, [0, 9, 0, 1], b"x"), Some((A_IP.into(), 0))).unwrap();
    exchange(&mut a, &mut b, 0);
    assert!(b.recv_from(r).is_ok());
    // A datagram bigger than the link goes in pieces, put back together at
    // the other end (RFC 791).
    let rx = a.udp_open();
    a.bind(rx, Ipv4::UNSPECIFIED, 1).unwrap();
    let big = b.udp_open();
    let data: alloc::vec::Vec<u8> = (0..4000u32).map(|i| i as u8).collect();
    assert_eq!(b.send_to(big, &data, Some((A_IP.into(), 1))), Ok(4000));
    let mut pieces = 0;
    for _ in 0..10 {
        a.poll(0);
        b.poll(0);
        let (fa, fb) = (a.take_tx(), b.take_tx());
        if fa.is_empty() && fb.is_empty() {
            break;
        }
        pieces += fb.iter().filter(|f| get16(&f.1, 12) == ETHERTYPE_IPV4).count();
        fa.iter().for_each(|f| b.receive(ETH, &f.1, 0));
        fb.iter().for_each(|f| a.receive(ETH, &f.1, 0));
    }
    assert_eq!(pieces, 3);
    assert_eq!(a.recv_from(rx).unwrap().0, data);
}

#[test]
fn static_config() {
    let c = Config::parse_static("192.168.1.203/24,192.168.1.1,8.8.8.8,9.9.9.9").unwrap();
    assert_eq!(c.addr, Ipv4([192, 168, 1, 203]));
    assert_eq!(c.prefix_len, 24);
    assert_eq!(c.gateway, Some(Ipv4([192, 168, 1, 1])));
    assert_eq!(c.dns, alloc::vec![Ipv4([8, 8, 8, 8]), Ipv4([9, 9, 9, 9])]);
    assert_eq!(Config::parse_static("10.0.0.2/8").unwrap().gateway, None);
    assert!(Config::parse_static("10.0.0.2").is_none());
    assert!(Config::parse_static("10.0.0.300/8").is_none());
    assert!(Config::parse_static("10.0.0.2/33").is_none());
}

// --- several interfaces (ADR 0048) -----------------------------------------

const H1: Mac = Mac([2, 0, 0, 0, 1, 1]);
const H2: Mac = Mac([2, 0, 0, 0, 1, 2]);

/// A host with two cards: 10.0.0.1/24 on 2 and 10.0.1.1/24 on 3.
fn two_cards() -> Stack {
    let mut h = Stack::new(7);
    h.add_interface(2, H1, 1500).unwrap();
    quiet_v6(&mut h, 2);
    h.add_interface(3, H2, 1500).unwrap();
    quiet_v6(&mut h, 3);
    h.add_address(2, IfAddr { addr: A_IP, prefix_len: 24 }).unwrap();
    h.add_address(3, IfAddr { addr: Ipv4([10, 0, 1, 1]), prefix_len: 24 }).unwrap();
    h
}

/// Move frames between `h` (two cards) and a peer on each card's segment.
fn exchange3(h: &mut Stack, p2: &mut Stack, p3: &mut Stack, now: u64) {
    for _ in 0..20 {
        h.poll(now);
        p2.poll(now);
        p3.poll(now);
        let (fh, f2, f3) = (h.take_tx(), p2.take_tx(), p3.take_tx());
        if fh.is_empty() && f2.is_empty() && f3.is_empty() {
            return;
        }
        for (i, f) in fh {
            if i == 2 {
                p2.receive(ETH, &f, now);
            } else {
                p3.receive(ETH, &f, now);
            }
        }
        f2.iter().for_each(|f| h.receive(2, &f.1, now));
        f3.iter().for_each(|f| h.receive(3, &f.1, now));
    }
}

fn peer(mac: Mac, ip: Ipv4, gateway: Ipv4) -> Stack {
    let mut s = card(mac, ip.0[3].into());
    s.set_config(ETH, Some(Config { addr: ip, prefix_len: 24, gateway: Some(gateway), dns: Vec::new() }), PROTO_BOOT)
        .unwrap();
    s
}

#[test]
fn routes_follow_subnets() {
    let mut h = two_cards();
    let (mut p2, mut p3) =
        (peer(B_MAC, B_IP, A_IP), peer(Mac([2, 0, 0, 0, 0, 3]), Ipv4([10, 0, 1, 2]), Ipv4([10, 0, 1, 1])));
    let u = h.udp_open();
    let (s2, s3) = (p2.udp_open(), p3.udp_open());
    p2.bind(s2, Ipv4::UNSPECIFIED, 9).unwrap();
    p3.bind(s3, Ipv4::UNSPECIFIED, 9).unwrap();
    h.send_to(u, b"to two", Some((B_IP.into(), 9))).unwrap();
    h.send_to(u, b"to three", Some((Ipv4([10, 0, 1, 2]).into(), 9))).unwrap();
    exchange3(&mut h, &mut p2, &mut p3, 0);
    let (d2, from2) = p2.recv_from(s2).unwrap();
    let (d3, from3) = p3.recv_from(s3).unwrap();
    assert_eq!((d2.as_slice(), from2.0), (&b"to two"[..], A_IP.into()));
    // Each leaves from the address on its own subnet.
    assert_eq!((d3.as_slice(), from3.0), (&b"to three"[..], Ipv4([10, 0, 1, 1]).into()));
    // The peer on card 3 reaches card 2's address too (the weak host model).
    let q = p3.udp_open();
    let r = h.udp_open();
    h.bind(r, A_IP, 7000).unwrap();
    p3.send_to(q, b"across", Some((A_IP.into(), 7000))).unwrap();
    exchange3(&mut h, &mut p2, &mut p3, 0);
    assert_eq!(h.recv_from(r).unwrap().0, b"across");
}

#[test]
fn default_route_by_metric_and_carrier() {
    let mut h = two_cards();
    let gw = |n: u8| Ipv4([10, 0, n, 254]);
    let route = |iface, metric, g| Route {
        dst: Ipv4::UNSPECIFIED,
        prefix_len: 0,
        gateway: Some(g),
        iface,
        metric,
        protocol: PROTO_STATIC,
        src: None,
    };
    h.add_route(route(2, 102, gw(0))).unwrap();
    h.add_route(route(3, 103, gw(1))).unwrap();
    assert_eq!(h.add_route(route(3, 103, gw(1))), Err(Error::Exists));
    // A gateway must be on one of the card's subnets.
    assert_eq!(h.add_route(route(3, 104, gw(0))), Err(Error::NetUnreachable));
    let far = Ipv4([93, 184, 216, 34]);
    assert_eq!(h.lookup(far, None).map(|r| r.iface), Some(2));
    h.set_carrier(2, false).unwrap();
    assert_eq!(h.lookup(far, None).map(|r| r.iface), Some(3));
    h.set_carrier(2, true).unwrap();
    h.set_up(2, false).unwrap();
    assert_eq!(h.lookup(far, None).map(|r| r.iface), Some(3));
    h.set_up(2, true).unwrap();
    // The ARP request for the gateway goes out of the chosen card.
    let u = h.udp_open();
    h.send_to(u, b"x", Some((far.into(), 53))).unwrap();
    let tx = h.take_tx();
    assert_eq!(tx.len(), 1);
    assert_eq!((tx[0].0, get16(&tx[0].1, 12)), (2, ETHERTYPE_ARP));
    assert_eq!(h.del_route(Ipv4::UNSPECIFIED, 0, Some(2), None, None).unwrap().metric, 102);
    assert_eq!(h.del_route(Ipv4::UNSPECIFIED, 0, Some(2), None, None), Err(Error::NotFound));
}

#[test]
fn address_changes_are_reported() {
    let mut h = Stack::new(1);
    h.add_interface(2, H1, 1500).unwrap();
    quiet_v6(&mut h, 2);
    h.take_changes();
    let a = IfAddr { addr: Ipv4([192, 168, 7, 9]), prefix_len: 24 };
    h.add_address(2, a).unwrap();
    assert_eq!(h.add_address(2, a), Err(Error::Exists));
    let subnet = Route {
        dst: Ipv4([192, 168, 7, 0]),
        prefix_len: 24,
        gateway: None,
        iface: 2,
        metric: 0,
        protocol: PROTO_KERNEL,
        src: Some(a.addr),
    };
    assert_eq!(h.take_changes(), alloc::vec![Change::NewAddr(2, a), Change::NewRoute(subnet)]);
    let default = Route {
        dst: Ipv4::UNSPECIFIED,
        prefix_len: 0,
        gateway: Some(Ipv4([192, 168, 7, 1])),
        metric: 5,
        src: None,
        ..subnet
    };
    h.add_route(default).unwrap();
    h.take_changes();
    // Removing the address takes its subnet route and the route through a
    // gateway only it reached.
    h.del_address(2, a.addr).unwrap();
    assert_eq!(
        h.take_changes(),
        alloc::vec![Change::DelAddr(2, a), Change::DelRoute(subnet), Change::DelRoute(default)]
    );
    assert!(h.routes().is_empty());
    assert_eq!(h.del_address(2, a.addr), Err(Error::AddrNotAvailable));
    assert_eq!(h.add_address(9, a), Err(Error::NoDevice));
    h.set_carrier(2, false).unwrap();
    h.set_carrier(2, false).unwrap();
    assert_eq!(h.take_changes(), alloc::vec![Change::Link(2)]);
}

#[test]
fn sockets_bound_to_a_card() {
    let mut h = Stack::new(3);
    h.add_interface(2, H1, 1500).unwrap();
    quiet_v6(&mut h, 2);
    h.add_interface(3, H2, 1500).unwrap();
    quiet_v6(&mut h, 3);
    // A DHCP client per card, as netd runs them: the same port, one per
    // card, before either has an address.
    let (c2, c3) = (h.udp_open(), h.udp_open());
    h.bind_device(c2, Some(2)).unwrap();
    h.bind_device(c3, Some(3)).unwrap();
    h.bind(c2, Ipv4::UNSPECIFIED, dhcp::CLIENT_PORT).unwrap();
    h.bind(c3, Ipv4::UNSPECIFIED, dhcp::CLIENT_PORT).unwrap();
    let any = h.udp_open();
    assert_eq!(h.bind(any, Ipv4::UNSPECIFIED, dhcp::CLIENT_PORT), Err(Error::AddrInUse));
    assert_eq!(h.bind_device(any, Some(9)), Err(Error::NoDevice));
    // The limited broadcast leaves through the socket's card, from 0.0.0.0.
    h.send_to(c3, b"discover", Some((Ipv4::BROADCAST.into(), dhcp::SERVER_PORT))).unwrap();
    let tx = h.take_tx();
    assert_eq!(tx.len(), 1);
    assert_eq!(tx[0].0, 3);
    let ip = Ipv4Header::parse(&tx[0].1[ETH_HEADER..]).unwrap();
    assert_eq!((ip.src, ip.dst), (Ipv4::UNSPECIFIED, Ipv4::BROADCAST));
    // A reply to the offered address reaches only card 3's socket.
    let server = Ipv4([10, 0, 1, 254]);
    let offered = Ipv4([10, 0, 1, 50]);
    let d = udp(server, dhcp::SERVER_PORT, offered, dhcp::CLIENT_PORT, b"offer");
    let p = ipv4(server, offered, PROTO_UDP, 1, 64, &d);
    h.receive(3, &ethernet(H2, B_MAC, ETHERTYPE_IPV4, &p), 0);
    assert_eq!(h.recv_from(c3).unwrap().0, b"offer");
    assert_eq!(h.recv_from(c2), Err(Error::WouldBlock));
    // Bound to a card with no route to the destination: unreachable.
    assert_eq!(h.send_to(c2, b"x", Some((Ipv4([8, 8, 8, 8]).into(), 53))), Err(Error::NetUnreachable));
}

#[test]
fn dhcp_on_the_second_card() {
    let mut c = Stack::new(5);
    c.add_interface(2, H1, 1500).unwrap();
    quiet_v6(&mut c, 2);
    c.add_interface(3, H2, 1500).unwrap();
    quiet_v6(&mut c, 3);
    c.start_dhcp(3, 0).unwrap();
    let server_ip = Ipv4([10, 0, 3, 2]);
    let offer_ip = Ipv4([10, 0, 3, 15]);
    for t in 0..10u64 {
        for (i, f) in c.take_tx() {
            assert_eq!(i, 3);
            let h = Ipv4Header::parse(&f[ETH_HEADER..]).unwrap();
            let Some((_, 67, m)) = parse_udp(h.src, h.dst, &f[ETH_HEADER + h.header_len..]) else { continue };
            let (kind, xid, _) = dhcp::parse_client(m).unwrap();
            let reply = if kind == dhcp::DISCOVER { dhcp::OFFER } else { dhcp::ACK };
            let r = dhcp::server_message(reply, xid, H2, offer_ip, server_ip, server_ip, Ipv4([10, 0, 3, 3]));
            let d = udp(server_ip, 67, Ipv4::BROADCAST, 68, &r);
            let p = ipv4(server_ip, Ipv4::BROADCAST, PROTO_UDP, 1, 64, &d);
            c.receive(3, &ethernet(Mac::BROADCAST, B_MAC, ETHERTYPE_IPV4, &p), t * 100);
        }
        c.poll(t * 100);
    }
    assert!(c.dhcp_bound(3) && !c.dhcp_bound(2));
    assert_eq!(c.addresses(3), alloc::vec![IfAddr { addr: offer_ip, prefix_len: 24 }]);
    assert!(c.addresses(2).is_empty());
    assert_eq!(c.lookup(Ipv4([1, 1, 1, 1]), None).map(|r| (r.iface, r.gateway)), Some((3, Some(server_ip))));
}

// --- the ARP table, forwarding, packet sockets (ADR 0049) --------------------

#[test]
fn arp_table_learned_and_set() {
    let (mut a, mut b) = (configured(A_MAC, A_IP), configured(B_MAC, B_IP));
    a.take_changes();
    let u = a.udp_open();
    a.send_to(u, b"x", Some((B_IP.into(), 9))).unwrap();
    // While resolving, the entry shows without an address.
    assert!(a.neighbours().contains(&Neighbour { iface: ETH, ip: B_IP.into(), mac: None, permanent: false }));
    exchange(&mut a, &mut b, 0);
    let learned = Neighbour { iface: ETH, ip: B_IP.into(), mac: Some(B_MAC), permanent: false };
    assert!(a.neighbours().contains(&learned));
    assert!(a.take_changes().contains(&Change::NewNeigh(learned)));
    // Set by hand: used at once (no ARP request), kept across link loss.
    let c = Ipv4([10, 0, 0, 9]);
    let c_mac = Mac([2, 0, 0, 0, 0, 9]);
    a.add_neighbour(ETH, c.into(), c_mac).unwrap();
    a.send_to(u, b"y", Some((c.into(), 9))).unwrap();
    let tx = a.take_tx();
    assert_eq!(tx.len(), 1);
    assert_eq!((get16(&tx[0].1, 12), &tx[0].1[0..6]), (ETHERTYPE_IPV4, &c_mac.0[..]));
    a.set_carrier(ETH, false).unwrap();
    a.set_carrier(ETH, true).unwrap();
    assert!(a.neighbours().contains(&Neighbour { iface: ETH, ip: c.into(), mac: Some(c_mac), permanent: true }));
    assert!(!a.neighbours().contains(&learned));
    a.del_neighbour(ETH, c.into()).unwrap();
    assert_eq!(a.del_neighbour(ETH, c.into()), Err(Error::NotFound));
    assert_eq!(a.add_neighbour(ETH, Ipv4::BROADCAST.into(), c_mac), Err(Error::InvalidInput));
}

/// A — R — B: A on 10.0.0.0/24 and B on 10.0.1.0/24, each with R as its
/// gateway; R forwards between its two cards.
fn routed() -> (Stack, Stack, Stack) {
    let mut r = two_cards();
    r.set_forwarding(true);
    let a = peer(B_MAC, B_IP, A_IP); // 10.0.0.2 via 10.0.0.1
    let b = peer(Mac([2, 0, 0, 0, 0, 3]), Ipv4([10, 0, 1, 2]), Ipv4([10, 0, 1, 1]));
    (r, a, b)
}

#[test]
fn forwarding_between_cards() {
    let (mut r, mut a, mut b) = routed();
    let far = Ipv4([10, 0, 1, 2]);
    let rx = b.udp_open();
    b.bind(rx, Ipv4::UNSPECIFIED, 7).unwrap();
    let raw = b.icmp_open(true);
    let tx = a.udp_open();
    a.send_to(tx, b"through", Some((far.into(), 7))).unwrap();
    exchange3(&mut r, &mut a, &mut b, 0);
    let (d, from) = b.recv_from(rx).unwrap();
    assert_eq!((d.as_slice(), from.0), (&b"through"[..], B_IP.into()));
    // And back: a ping from B to A answered through R.
    b.send_to(raw, &icmp(ICMP_ECHO_REQUEST, 0, [0, 1, 0, 1], b"p"), Some((B_IP.into(), 0))).unwrap();
    exchange3(&mut r, &mut a, &mut b, 0);
    let (pkt, _) = b.recv_from(raw).unwrap();
    let h = Ipv4Header::parse(&pkt).unwrap();
    assert_eq!((h.src, pkt[h.header_len], h.ttl), (B_IP, ICMP_ECHO_REPLY, DEFAULT_TTL - 1));
    // Forwarding off: nothing goes through.
    r.set_forwarding(false);
    a.send_to(tx, b"blocked", Some((far.into(), 7))).unwrap();
    exchange3(&mut r, &mut a, &mut b, 0);
    assert_eq!(b.recv_from(rx), Err(Error::WouldBlock));
}

#[test]
fn forwarding_errors() {
    let (mut r, mut a, mut b) = routed();
    let raw = a.icmp_open(true);
    let error_from_r = |a: &mut Stack| -> (u8, u8, [u8; 4]) {
        let (pkt, from) = a.recv_from(raw).unwrap();
        let h = Ipv4Header::parse(&pkt).unwrap();
        assert_eq!(from.0, A_IP.into());
        let m = &pkt[h.header_len..];
        (m[0], m[1], m[4..8].try_into().unwrap())
    };
    // TTL 1: time exceeded.
    let d = udp(B_IP, 5000, Ipv4([10, 0, 1, 2]), 7, b"old");
    let p = ipv4(B_IP, Ipv4([10, 0, 1, 2]), PROTO_UDP, 9, 1, &d);
    r.receive(2, &ethernet(H1, B_MAC, ETHERTYPE_IPV4, &p), 0);
    exchange3(&mut r, &mut a, &mut b, 0);
    assert_eq!(error_from_r(&mut a).0, ICMP_TIME_EXCEEDED);
    // No route: network unreachable.
    let u = a.udp_open();
    a.send_to(u, b"nowhere", Some((Ipv4([172, 16, 0, 1]).into(), 7))).unwrap();
    exchange3(&mut r, &mut a, &mut b, 0);
    let (kind, code, _) = error_from_r(&mut a);
    assert_eq!((kind, code), (ICMP_DEST_UNREACHABLE, ICMP_NET_UNREACHABLE));
    // Too big for the next link, Don't Fragment set: the MTU comes back.
    r.set_link(3, H2, 600).unwrap();
    a.send_to(u, &[0u8; 1000], Some((Ipv4([10, 0, 1, 2]).into(), 7))).unwrap();
    exchange3(&mut r, &mut a, &mut b, 0);
    let (kind, code, rest) = error_from_r(&mut a);
    assert_eq!((kind, code, u16::from_be_bytes([rest[2], rest[3]])), (ICMP_DEST_UNREACHABLE, ICMP_FRAG_NEEDED, 600));
}

#[test]
fn packet_sockets() {
    let (mut a, mut b) = (configured(A_MAC, A_IP), configured(B_MAC, B_IP));
    // A raw socket for every protocol sees frames both ways.
    let all = a.packet_open(ETH_P_ALL, false);
    // A cooked ARP socket on the card, as arping uses one.
    let arp = a.packet_open(0, true);
    a.packet_bind(arp, ETHERTYPE_ARP, Some(ETH)).unwrap();
    let req = Arp { op: ARP_REQUEST, sender_mac: A_MAC, sender_ip: A_IP, target_mac: Mac::default(), target_ip: B_IP };
    let to = LinkAddr { iface: ETH, protocol: ETHERTYPE_ARP, pkttype: 0, mac: Mac::BROADCAST };
    assert_eq!(a.packet_send(arp, &req.build(), Some(to)), Ok(ARP_LEN));
    exchange(&mut a, &mut b, 0);
    let (reply, from) = a.packet_recv(arp, false).unwrap();
    let r = Arp::parse(&reply).unwrap();
    assert_eq!((r.op, r.sender_ip, r.sender_mac), (ARP_REPLY, B_IP, B_MAC));
    assert_eq!((from.iface, from.protocol, from.pkttype, from.mac), (ETH, ETHERTYPE_ARP, PACKET_HOST, B_MAC));
    // The sender does not see its own frame; the ETH_P_ALL socket sees the
    // request going out and the reply coming in, whole.
    assert_eq!(a.packet_recv(arp, false), Err(Error::WouldBlock));
    let (out, o) = a.packet_recv(all, false).unwrap();
    // (Padded to Ethernet's 60-byte minimum.)
    assert_eq!((o.pkttype, get16(&out, 12), out.len()), (PACKET_OUTGOING, ETHERTYPE_ARP, 60));
    assert_eq!(a.packet_recv(all, false).unwrap().1.pkttype, PACKET_HOST);
    // A filter that keeps nothing.
    let none = alloc::vec![slate_bpf::SockFilter { code: 0x06, jt: 0, jf: 0, k: 0 }];
    a.packet_filter(all, Some(none)).unwrap();
    a.packet_send(arp, &req.build(), Some(to)).unwrap();
    exchange(&mut a, &mut b, 0);
    assert!(a.packet_recv(arp, false).is_ok());
    assert_eq!(a.packet_recv(all, false), Err(Error::WouldBlock));
    // Raw frames go out as given; a card is needed.
    let raw = a.packet_open(ETH_P_ALL, false);
    assert_eq!(a.packet_send(raw, &[0u8; 20], None), Err(Error::NoDevice));
    a.take_tx();
    let frame = ethernet(B_MAC, A_MAC, 0x88B5, b"local experimental ethertype");
    assert_eq!(a.packet_send(raw, &frame, Some(LinkAddr { iface: ETH, ..Default::default() })), Ok(frame.len()));
    assert_eq!(a.take_tx(), alloc::vec![(ETH, frame)]);
}

#[test]
fn raw_ip_sends_whole_packets() {
    let (mut a, mut b) = (configured(A_MAC, A_IP), configured(B_MAC, B_IP));
    let raw = a.raw_ip_open();
    let listen = a.icmp_open(true);
    // An echo request with the header written by hand: no source address,
    // no length, no checksum; the stack fills them in (raw(7)).
    let mut p = ipv4(Ipv4::UNSPECIFIED, B_IP, PROTO_ICMP, 0, 64, &icmp(ICMP_ECHO_REQUEST, 0, [0, 5, 0, 1], b"hand"));
    p[2..4].fill(0);
    p[10..12].fill(0);
    assert_eq!(a.send_to(raw, &p, Some((B_IP.into(), 0))), Ok(p.len()));
    exchange(&mut a, &mut b, 0);
    let (reply, from) = a.recv_from(listen).unwrap();
    let h = Ipv4Header::parse(&reply).unwrap();
    assert_eq!((from.0, h.dst, reply[h.header_len]), (B_IP.into(), A_IP, ICMP_ECHO_REPLY));
    // Send only: nothing is ever received on it.
    assert_eq!(a.recv_from(raw), Err(Error::WouldBlock));
    assert_eq!(a.send_to(raw, &[0x45, 0, 0], Some((B_IP.into(), 0))), Err(Error::InvalidInput));
}

/// A new namespace's loopback (ADR 0114): down and without addresses, as
/// Linux makes it; up, it has 127.0.0.1/8 and ::1, and adding them again
/// is refused as on Linux.
#[test]
fn a_new_namespace_loopback() {
    let mut s = Stack::new_namespace(1);
    let lo = s.interfaces()[0].clone();
    assert!(!lo.up && lo.addrs.is_empty() && lo.addrs6.is_empty());
    // bubblewrap's order: the address first, then up.
    assert_eq!(s.add_address(1, IfAddr { addr: Ipv4::LOCALHOST, prefix_len: 8 }), Ok(()));
    s.set_up(1, true).unwrap();
    let lo = s.interfaces()[0].clone();
    assert!(lo.up && lo.addrs.len() == 1 && lo.addrs6.len() == 1);
    assert_eq!(s.add_address(1, IfAddr { addr: Ipv4::LOCALHOST, prefix_len: 8 }), Err(Error::Exists));
    // Up straight away: the addresses come with it.
    let mut t = Stack::new_namespace(2);
    t.set_up(1, true).unwrap();
    assert_eq!(t.interfaces()[0].addrs, [IfAddr { addr: Ipv4::LOCALHOST, prefix_len: 8 }]);
    let u = t.udp_open();
    t.bind(u, Ipv4::LOCALHOST, 5000).unwrap();
}

/// A raw ICMP socket on `s` whose packets carry option field `opts`.
fn raw_with_options(s: &mut Stack, opts: &[u8]) -> crate::Handle {
    let r = s.icmp_open(true);
    s.set_ip_options(r, IpOptions { options: OptionField::new(opts).unwrap(), ..IpOptions::default() }).unwrap();
    r
}

/// A Record Route option with room for `slots` addresses (RFC 791).
fn rr(slots: usize) -> Vec<u8> {
    let mut o = alloc::vec![0u8; 3 + 4 * slots];
    (o[0], o[1], o[2]) = (IPOPT_RR, o.len() as u8, 4);
    o
}

/// The addresses a Record Route option at the start of `pkt`'s option
/// field holds.
fn recorded(pkt: &[u8]) -> Vec<Ipv4> {
    let o = &pkt[IP_HEADER..];
    assert_eq!(o[0], IPOPT_RR);
    (3..usize::from(o[2]) - 1).step_by(4).map(|i| Ipv4(o[i..i + 4].try_into().unwrap())).collect()
}

/// `ping -R`: the reply carries Record Route with the sender's address
/// and the replier's (RFC 1122 §3.2.2.6); through a router, its outgoing
/// address both ways too.
#[test]
fn record_route_comes_back() {
    let (mut a, mut b) = (configured(A_MAC, A_IP), configured(B_MAC, B_IP));
    let r = raw_with_options(&mut a, &rr(9));
    a.send_to(r, &icmp(ICMP_ECHO_REQUEST, 0, [0, 1, 0, 1], b"rr"), Some((B_IP.into(), 0))).unwrap();
    exchange(&mut a, &mut b, 0);
    let (pkt, _) = a.recv_from(r).unwrap();
    assert_eq!(pkt[IP_HEADER + 39 + 1], ICMP_ECHO_REPLY);
    assert_eq!(recorded(&pkt), [A_IP, B_IP]);

    let (mut rt, mut a, mut b) = routed();
    let far = Ipv4([10, 0, 1, 2]);
    let r = raw_with_options(&mut a, &rr(9));
    a.send_to(r, &icmp(ICMP_ECHO_REQUEST, 0, [0, 1, 0, 2], b"rr"), Some((far.into(), 0))).unwrap();
    exchange3(&mut rt, &mut a, &mut b, 0);
    let (pkt, _) = a.recv_from(r).unwrap();
    assert_eq!(recorded(&pkt), [B_IP, Ipv4([10, 0, 1, 1]), far, A_IP]);
}

/// Timestamp with addresses: the sender's and the replier's entries, the
/// time of day in milliseconds since midnight UT; with no room, the
/// overflow count goes up.
#[test]
fn timestamps_come_back() {
    let (mut a, mut b) = (configured(A_MAC, A_IP), configured(B_MAC, B_IP));
    let day = 86_400_000;
    (a.wall_ms, b.wall_ms) = (1000 * day + 1234, 1000 * day + 1250);
    let mut ts = alloc::vec![0u8; 4 + 8 * 2];
    (ts[0], ts[1], ts[2], ts[3]) = (IPOPT_TS, ts.len() as u8, 5, 1);
    ts.extend_from_slice(&[IPOPT_NOP; 3]);
    ts.extend_from_slice(&[IPOPT_TS, 4, 5, 0]);
    let r = raw_with_options(&mut a, &ts);
    a.send_to(r, &icmp(ICMP_ECHO_REQUEST, 0, [0, 1, 0, 1], b"ts"), Some((B_IP.into(), 0))).unwrap();
    exchange(&mut a, &mut b, 0);
    let (pkt, _) = a.recv_from(r).unwrap();
    let o = &pkt[IP_HEADER..];
    assert_eq!(o[2], 21);
    assert_eq!((&o[4..8], get32(o, 8)), (&A_IP.0[..], 1234));
    assert_eq!((&o[12..16], get32(o, 16)), (&B_IP.0[..], 1250));
    // The second, without room: both sides counted an overflow.
    assert_eq!(o[20..24], [IPOPT_TS, 4, 5, 0x20]);
}

/// An echo request to B with option field `opts`, from outside a socket.
fn echo_with_options(opts: &[u8]) -> Vec<u8> {
    let p = ipv4_full(A_IP, B_IP, PROTO_ICMP, 77, 64, 0, opts, &icmp(ICMP_ECHO_REQUEST, 0, [0, 9, 0, 1], b"x"));
    ethernet(B_MAC, A_MAC, ETHERTYPE_IPV4, &p)
}

#[test]
fn source_routes_and_bad_options() {
    let (mut a, mut b) = (configured(A_MAC, A_IP), configured(B_MAC, B_IP));
    let raw = a.icmp_open(true);
    exchange(&mut a, &mut b, 0);
    // A loose source route through B: dropped without a word.
    let mut lsrr = alloc::vec![IPOPT_LSRR, 7, 4];
    lsrr.extend_from_slice(&[10, 0, 0, 9]);
    b.receive(ETH, &echo_with_options(&lsrr), 0);
    exchange(&mut a, &mut b, 0);
    assert_eq!(a.recv_from(raw), Err(Error::WouldBlock));
    // Record Route with a pointer of 3: Parameter Problem, pointing at the
    // pointer (byte 22 of the header).
    b.receive(ETH, &echo_with_options(&[IPOPT_RR, 7, 3, 0, 0, 0, 0]), 0);
    exchange(&mut a, &mut b, 0);
    let (pkt, _) = a.recv_from(raw).unwrap();
    let h = Ipv4Header::parse(&pkt).unwrap();
    let m = &pkt[h.header_len..];
    assert_eq!((m[0], m[1], m[4]), (ICMP_PARAMETER_PROBLEM, 0, 22));
    // An option running past the header: pointed at its length.
    b.receive(ETH, &echo_with_options(&[IPOPT_NOP, IPOPT_RR, 40, 4]), 0);
    exchange(&mut a, &mut b, 0);
    let (pkt, _) = a.recv_from(raw).unwrap();
    assert_eq!(pkt[IP_HEADER + 4], 22);
}

#[test]
fn unknown_protocols_unreachable_at_a_rate() {
    let (mut a, mut b) = (configured(A_MAC, A_IP), configured(B_MAC, B_IP));
    let raw = a.icmp_open(true);
    exchange(&mut a, &mut b, 0);
    let p = ipv4(A_IP, B_IP, 99, 5, 64, b"what is this");
    for _ in 0..60 {
        b.receive(ETH, &ethernet(B_MAC, A_MAC, ETHERTYPE_IPV4, &p), 0);
    }
    exchange(&mut a, &mut b, 0);
    let mut errors = 0;
    while let Ok((pkt, _)) = a.recv_from(raw) {
        let m = &pkt[IP_HEADER..];
        assert_eq!((m[0], m[1], m[8 + 9]), (ICMP_DEST_UNREACHABLE, ICMP_PROTO_UNREACHABLE, 99));
        errors += 1;
    }
    // Fifty at once, then one every 20 ms.
    assert_eq!(errors, 50);
    b.receive(ETH, &ethernet(B_MAC, A_MAC, ETHERTYPE_IPV4, &p), 40);
    exchange(&mut a, &mut b, 40);
    assert!(a.recv_from(raw).is_ok());
}

/// Fragments: Record Route (not copied) in the first piece only; a
/// security-like copied option (kind 130) in every piece.
#[test]
fn fragments_copy_only_copied_options() {
    let (mut a, mut b) = (configured(A_MAC, A_IP), configured(B_MAC, B_IP));
    exchange(&mut a, &mut b, 0);
    let mut opts = rr(2);
    opts.extend_from_slice(&[130, 4, 0, 0]);
    let u = a.udp_open();
    // B's hardware address learned first, so the pieces go out at once.
    a.send_to(u, b"hello", Some((B_IP.into(), 9))).unwrap();
    exchange(&mut a, &mut b, 0);
    a.set_ip_options(u, IpOptions { options: OptionField::new(&opts).unwrap(), ..IpOptions::default() }).unwrap();
    a.send_to(u, &[7u8; 2000], Some((B_IP.into(), 9))).unwrap();
    a.poll(0);
    let frames: Vec<_> = a.take_tx().into_iter().filter(|f| f.1[12..14] == [8, 0]).collect();
    assert_eq!(frames.len(), 2);
    let (first, second) = (&frames[0].1[14..], &frames[1].1[14..]);
    assert_eq!((first[0] & 0xF, second[0] & 0xF), (5 + 4, 5 + 1));
    assert_eq!(second[IP_HEADER..IP_HEADER + 4], [130, 4, 0, 0]);
    assert!(Ipv4Header::parse(second).is_some());
}

/// Only the first piece came: after 30 s the sender hears time exceeded
/// in reassembly, quoting it.
#[test]
fn reassembly_times_out_with_an_error() {
    let (mut a, mut b) = (configured(A_MAC, A_IP), configured(B_MAC, B_IP));
    let raw = a.icmp_open(true);
    exchange(&mut a, &mut b, 0);
    let mut p = ipv4(A_IP, B_IP, PROTO_UDP, 31, 64, &udp(A_IP, 4000, B_IP, 9, &[1u8; 64]));
    put16(&mut p, 6, 0x2000);
    p[10..12].fill(0);
    let c = checksum(&p[..IP_HEADER]);
    put16(&mut p, 10, c);
    b.receive(ETH, &ethernet(B_MAC, A_MAC, ETHERTYPE_IPV4, &p), 0);
    exchange(&mut a, &mut b, 1000);
    assert_eq!(a.recv_from(raw), Err(Error::WouldBlock));
    exchange(&mut a, &mut b, 31_000);
    let (pkt, _) = a.recv_from(raw).unwrap();
    let m = &pkt[IP_HEADER..];
    assert_eq!((m[0], m[1], get16(m, 8 + 4)), (ICMP_TIME_EXCEEDED, ICMP_REASSEMBLY_TIMEOUT, 31));
}

/// An attempt to connect across the router to a network it has no route
/// to fails at once on its "network unreachable" (RFC 1122 §4.2.3.9), not
/// after two minutes of retries.
#[test]
fn tcp_attempt_ends_on_unreachable() {
    let (mut r, mut a, mut b) = routed();
    let c = a.tcp_open();
    a.tcp_connect(c, (Ipv4([172, 16, 0, 1]).into(), 80)).unwrap();
    exchange3(&mut r, &mut a, &mut b, 0);
    assert_eq!(a.tcp_take_error(c).unwrap(), Some(Error::NetUnreachable));
    assert_eq!(a.tcp_state(c).unwrap(), TcpState::Closed);
}

/// Across a 600-byte link a connection's full-size segments draw
/// "fragmentation needed" from the router: the sender learns the path's
/// MTU (RFC 1191), sends smaller segments and everything arrives.
#[test]
fn tcp_learns_the_path_mtu() {
    let (mut r, mut a, mut b) = routed();
    let far = Ipv4([10, 0, 1, 2]);
    r.set_link(3, H2, 600).unwrap();
    let l = b.tcp_open();
    b.tcp_bind(l, Ipv4::UNSPECIFIED, 7).unwrap();
    b.tcp_listen(l, 4).unwrap();
    let c = a.tcp_open();
    a.tcp_connect(c, (far.into(), 7)).unwrap();
    let mut now = 0;
    let mut s = None;
    while s.is_none() && now < 5000 {
        exchange3(&mut r, &mut a, &mut b, now);
        s = b.tcp_accept(l).ok();
        now += 10;
    }
    let s = s.expect("connected");
    let data: Vec<u8> = (0..40_000).map(|i| (i * 7 % 253) as u8).collect();
    let (mut sent, mut got, mut buf) = (0, Vec::new(), [0u8; 4096]);
    while got.len() < data.len() && now < 60_000 {
        if let Ok(n) = a.tcp_send(c, &data[sent..]) {
            sent += n;
        }
        exchange3(&mut r, &mut a, &mut b, now);
        while let Ok(n @ 1..) = b.tcp_recv(s, &mut buf, false) {
            got.extend_from_slice(&buf[..n]);
        }
        now += 10;
    }
    assert!(got == data, "{} of {} bytes arrived", got.len(), data.len());
    assert!(a.tcp_info(c).unwrap().mss <= 600 - IP_HEADER - 20);
}

/// On an established connection an ICMP error never ends it (RFC 5927
/// §4.1); one quoting a sequence number outside what is in flight is
/// ignored outright.
#[test]
fn tcp_established_keeps_on_icmp_errors() {
    let (mut a, mut b) = (configured(A_MAC, A_IP), configured(B_MAC, B_IP));
    let l = b.tcp_open();
    b.tcp_bind(l, Ipv4::UNSPECIFIED, 7).unwrap();
    b.tcp_listen(l, 4).unwrap();
    let c = a.tcp_open();
    a.tcp_connect(c, (B_IP.into(), 7)).unwrap();
    exchange(&mut a, &mut b, 0);
    assert!(b.tcp_accept(l).is_ok());
    // A segment in flight, caught before B sees it.
    a.tcp_send(c, b"in flight").unwrap();
    a.poll(0);
    let seg = first_ipv4(&a.take_tx())[14..].to_vec();
    let unreachable = |quoted: &[u8]| {
        let m = icmp(ICMP_DEST_UNREACHABLE, ICMP_PORT_UNREACHABLE, [0; 4], &quoted[..IP_HEADER + 8]);
        ethernet(A_MAC, B_MAC, ETHERTYPE_IPV4, &ipv4(B_IP, A_IP, PROTO_ICMP, 1, 64, &m))
    };
    let mut forged = seg.clone();
    put32(&mut forged, IP_HEADER + 4, get32(&seg, IP_HEADER + 4).wrapping_add(1 << 30));
    a.receive(ETH, &unreachable(&forged), 0);
    a.receive(ETH, &unreachable(&seg), 0);
    assert_eq!(a.tcp_state(c).unwrap(), TcpState::Established);
    assert_eq!(a.tcp_take_error(c).unwrap(), None);
}

// --- the firewall (nf_tables, ADR 0129) ---------------------------------------

mod firewall {
    use super::*;
    use slate_nft::consts::*;
    use slate_nft::{BaseChain, Chain, Data, Expr, Rule, Table, Verdict};

    fn rule(exprs: Vec<Expr>) -> Rule {
        Rule { handle: 0, exprs, userdata: None }
    }

    fn accept() -> Expr {
        Expr::Immediate { dreg: NFT_REG_VERDICT, data: Data::Verdict(Verdict::Accept) }
    }

    /// `tcp dport PORT` as nft compiles it.
    fn tcp_dport(port: u16) -> Vec<Expr> {
        alloc::vec![
            Expr::Meta { key: NFT_META_L4PROTO, dreg: Some(1), sreg: None },
            Expr::Cmp { sreg: 1, op: NFT_CMP_EQ, data: alloc::vec![6] },
            Expr::Payload { dreg: 1, base: NFT_PAYLOAD_TRANSPORT_HEADER, offset: 2, len: 2 },
            Expr::Cmp { sreg: 1, op: NFT_CMP_EQ, data: port.to_be_bytes().to_vec() },
        ]
    }

    /// `ct state established,related accept`.
    fn established() -> Rule {
        rule(alloc::vec![
            Expr::Ct { key: NFT_CT_STATE, dreg: Some(1), dir: None, sreg: None },
            Expr::Bitwise {
                sreg: 1,
                dreg: 1,
                len: 4,
                op: NFT_BITWISE_MASK_XOR,
                mask: (NF_CT_STATE_ESTABLISHED | NF_CT_STATE_RELATED).to_ne_bytes().to_vec(),
                xor: alloc::vec![0; 4],
                shift: 0,
            },
            Expr::Cmp { sreg: 1, op: NFT_CMP_NEQ, data: alloc::vec![0; 4] },
            accept(),
        ])
    }

    /// An inet table with one base chain on `hook`.
    fn chain(s: &mut Stack, hook: u32, policy: i32, rules: Vec<Rule>) {
        let base = BaseChain { hook, priority: 0, kind: b"filter".to_vec(), policy, counters: false };
        let c = Chain { name: b"c".to_vec(), handle: 1, base: Some(base), rules, userdata: None };
        let t =
            Table { family: NFPROTO_INET, name: b"t".to_vec(), handle: 1, chains: alloc::vec![c], ..Table::default() };
        s.firewall.tables.push(t);
    }

    /// Default drop in: only replies and ssh. B's own connection out gets
    /// its answers; A's datagram to B doesn't arrive; A reaches B's ssh.
    #[test]
    fn input_drops_all_but_replies_and_ssh() {
        let (mut a, mut b) = (configured(A_MAC, A_IP), configured(B_MAC, B_IP));
        let mut ssh = tcp_dport(22);
        ssh.push(accept());
        chain(&mut b, NF_INET_LOCAL_IN, NF_DROP, alloc::vec![established(), rule(ssh)]);
        // A datagram for a listening port: dropped.
        let rx = b.udp_open();
        b.bind(rx, Ipv4::UNSPECIFIED, 7).unwrap();
        let tx = a.udp_open();
        a.send_to(tx, b"knock", Some((B_IP.into(), 7))).unwrap();
        exchange(&mut a, &mut b, 0);
        assert_eq!(b.recv_from(rx), Err(Error::WouldBlock));
        // ssh: allowed in.
        let l = b.tcp_open();
        b.tcp_bind(l, Ipv4::UNSPECIFIED, 22).unwrap();
        b.tcp_listen(l, 4).unwrap();
        let c = a.tcp_open();
        a.tcp_connect(c, (B_IP.into(), 22)).unwrap();
        exchange(&mut a, &mut b, 0);
        assert_eq!(a.tcp_state(c).unwrap(), TcpState::Established);
        // B's own connection to A's port 80: its replies are established.
        let l = a.tcp_open();
        a.tcp_bind(l, Ipv4::UNSPECIFIED, 80).unwrap();
        a.tcp_listen(l, 4).unwrap();
        let out = b.tcp_open();
        b.tcp_connect(out, (A_IP.into(), 80)).unwrap();
        exchange(&mut a, &mut b, 0);
        assert_eq!(b.tcp_state(out).unwrap(), TcpState::Established);
    }

    /// A reject with a TCP reset: the connection is refused at once.
    #[test]
    fn reject_resets_connections() {
        let (mut a, mut b) = (configured(A_MAC, A_IP), configured(B_MAC, B_IP));
        let mut telnet = tcp_dport(23);
        telnet.push(Expr::Reject { kind: NFT_REJECT_TCP_RST, code: 0 });
        chain(&mut b, NF_INET_LOCAL_IN, NF_ACCEPT, alloc::vec![rule(telnet)]);
        let l = b.tcp_open();
        b.tcp_bind(l, Ipv4::UNSPECIFIED, 23).unwrap();
        b.tcp_listen(l, 4).unwrap();
        let c = a.tcp_open();
        a.tcp_connect(c, (B_IP.into(), 23)).unwrap();
        exchange(&mut a, &mut b, 0);
        assert_eq!(a.tcp_take_error(c).unwrap(), Some(Error::ConnectionRefused));
    }

    /// Output: a drop is EPERM to the sender (Linux's sendmsg).
    #[test]
    fn output_drop_is_eperm() {
        let mut a = configured(A_MAC, A_IP);
        chain(&mut a, NF_INET_LOCAL_OUT, NF_DROP, Vec::new());
        let u = a.udp_open();
        assert_eq!(a.send_to(u, b"no", Some((B_IP.into(), 9))), Err(Error::NotPermitted));
    }

    /// Forward: the router drops what its forward chain drops.
    #[test]
    fn forward_chain_blocks_routing() {
        let (mut r, mut a, mut b) = routed();
        let far = Ipv4([10, 0, 1, 2]);
        let rx = b.udp_open();
        b.bind(rx, Ipv4::UNSPECIFIED, 7).unwrap();
        let tx = a.udp_open();
        a.send_to(tx, b"through", Some((far.into(), 7))).unwrap();
        exchange3(&mut r, &mut a, &mut b, 0);
        assert!(b.recv_from(rx).is_ok());
        chain(&mut r, NF_INET_FORWARD, NF_DROP, Vec::new());
        a.send_to(tx, b"blocked", Some((far.into(), 7))).unwrap();
        exchange3(&mut r, &mut a, &mut b, 0);
        assert_eq!(b.recv_from(rx), Err(Error::WouldBlock));
    }

    /// A nat chain on `hook` at `priority` with these rules, in a table of
    /// its own.
    fn nat_chain(s: &mut Stack, name: &[u8], hook: u32, priority: i32, rules: Vec<Rule>) {
        let base = BaseChain { hook, priority, kind: b"nat".to_vec(), policy: NF_ACCEPT, counters: false };
        let c = Chain { name: b"n".to_vec(), handle: 1, base: Some(base), rules, userdata: None };
        let t =
            Table { family: NFPROTO_IPV4, name: name.to_vec(), handle: 1, chains: alloc::vec![c], ..Table::default() };
        s.firewall.tables.push(t);
    }

    /// NAT on the router (ADR 0132): what leaves by the far card is
    /// masqueraded, and TCP to the router's far address on port 8080 goes
    /// to A's port 80. A's datagram reaches B from the router's address and
    /// B's answer comes back to A; B's connection to the router lands at A,
    /// which sees B, and B sees the router's address answer.
    #[test]
    fn masquerade_and_dnat_through_the_router() {
        let (mut r, mut a, mut b) = routed();
        let (far, router_far) = (Ipv4([10, 0, 1, 2]), Ipv4([10, 0, 1, 1]));
        // `oif 3 masquerade`.
        nat_chain(
            &mut r,
            b"post",
            NF_INET_POST_ROUTING,
            100,
            alloc::vec![rule(alloc::vec![
                Expr::Meta { key: NFT_META_OIF, dreg: Some(1), sreg: None },
                Expr::Cmp { sreg: 1, op: NFT_CMP_EQ, data: 3u32.to_ne_bytes().to_vec() },
                Expr::Masq { flags: 0, proto: None },
            ])],
        );
        // `tcp dport 8080 dnat to 10.0.0.2:80`.
        let mut dnat = tcp_dport(8080);
        dnat.push(Expr::Immediate { dreg: 1, data: Data::Value(B_IP.0.to_vec()) });
        dnat.push(Expr::Immediate { dreg: 2, data: Data::Value(80u16.to_be_bytes().to_vec()) });
        dnat.push(Expr::Nat {
            kind: NFT_NAT_DNAT,
            family: u32::from(NFPROTO_IPV4),
            addr: Some((1, 1)),
            proto: Some((2, 2)),
            flags: NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED,
        });
        nat_chain(&mut r, b"pre", NF_INET_PRE_ROUTING, -100, alloc::vec![rule(dnat)]);

        let rx = b.udp_open();
        b.bind(rx, Ipv4::UNSPECIFIED, 7).unwrap();
        let tx = a.udp_open();
        a.bind(tx, Ipv4::UNSPECIFIED, 4000).unwrap();
        a.send_to(tx, b"out", Some((far.into(), 7))).unwrap();
        exchange3(&mut r, &mut a, &mut b, 0);
        let (d, from) = b.recv_from(rx).unwrap();
        assert_eq!((d.as_slice(), from.0), (&b"out"[..], router_far.into()));
        b.send_to(rx, b"back", Some(from)).unwrap();
        exchange3(&mut r, &mut a, &mut b, 0);
        let (d, from) = a.recv_from(tx).unwrap();
        assert_eq!((d.as_slice(), from), (&b"back"[..], (far.into(), 7)));

        let l = a.tcp_open();
        a.tcp_bind(l, Ipv4::UNSPECIFIED, 80).unwrap();
        a.tcp_listen(l, 4).unwrap();
        let c = b.tcp_open();
        b.tcp_connect(c, (router_far.into(), 8080)).unwrap();
        exchange3(&mut r, &mut a, &mut b, 0);
        assert_eq!(b.tcp_state(c).unwrap(), TcpState::Established);
        let s = a.tcp_accept(l).unwrap();
        assert_eq!(a.tcp_remote(s).unwrap().map(|e| e.0), Some(far.into()));
        assert_eq!(b.tcp_remote(c).unwrap(), Some((router_far.into(), 8080)));
        a.tcp_send(s, b"served").unwrap();
        exchange3(&mut r, &mut a, &mut b, 0);
        let mut buf = [0u8; 16];
        let n = b.tcp_recv(c, &mut buf, false).unwrap();
        assert_eq!(&buf[..n], b"served");
    }
}
