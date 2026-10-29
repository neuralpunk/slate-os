// SPDX-License-Identifier: MIT OR Apache-2.0

//! IPv6 between stacks on simulated links (ADR 0050).

use alloc::vec::Vec;

use crate::wire::*;
use crate::{AddrOrigin, AddrState, Error, IpAddr, Ipv6, Route6, Stack};

const A_MAC: Mac = Mac([2, 0, 0, 0, 6, 1]);
const B_MAC: Mac = Mac([2, 0, 0, 0, 6, 2]);
const ETH: u32 = 2;

fn ip(s: &str) -> Ipv6 {
    Ipv6::parse(s).unwrap()
}

fn host(mac: Mac, seed: u32) -> Stack {
    let mut s = Stack::new(seed);
    s.add_interface(ETH, mac, 1500).unwrap();
    s
}

/// Move frames between the stacks on one link, `ms` milliseconds at a time
/// for `steps` steps, starting at `*now`.
fn run(stacks: &mut [&mut Stack], now: &mut u64, ms: u64, steps: usize) {
    for _ in 0..steps {
        for _ in 0..30 {
            let mut frames = Vec::new();
            for (i, s) in stacks.iter_mut().enumerate() {
                s.poll(*now);
                frames.extend(s.take_tx().into_iter().map(|(_, f)| (i, f)));
            }
            if frames.is_empty() {
                break;
            }
            for (from, f) in frames {
                for (i, s) in stacks.iter_mut().enumerate() {
                    if i != from {
                        s.receive(ETH, &f, *now);
                    }
                }
            }
        }
        *now += ms;
    }
}

#[test]
fn link_local_after_dad() {
    let mut a = host(A_MAC, 1);
    let ll = Ipv6::link_local(A_MAC);
    assert_eq!(a.addresses6(ETH)[0].addr, ll);
    assert_eq!(a.addresses6(ETH)[0].state, AddrState::Tentative);
    // The probe: a neighbour solicitation from :: to the solicited-node group.
    let tx = a.take_tx();
    let probe = tx.iter().find(|(_, f)| get16(f, 12) == ETHERTYPE_IPV6).unwrap();
    let h = Ipv6Header::parse(&probe.1[ETH_HEADER..]).unwrap();
    assert_eq!((h.src, h.dst, h.hop_limit), (Ipv6::UNSPECIFIED, ll.solicited_node(), 255));
    assert_eq!(&probe.1[..6], &ll.solicited_node().multicast_mac().0);
    let mut now = 0;
    run(&mut [&mut a], &mut now, 500, 3);
    let a0 = a.addresses6(ETH)[0];
    assert_eq!((a0.state, a0.origin, a0.prefix_len), (AddrState::Preferred, AddrOrigin::LinkLocal, 64));
    // Then a router solicitation went out.
    // (Nobody answered; the host keeps its link-local address only.)
    assert_eq!(a.addresses6(ETH).len(), 1);
    assert_eq!(a.addresses6(1)[0].addr, Ipv6::LOCALHOST);
}

/// Two hosts on one link, link-local addresses ready.
fn pair() -> (Stack, Stack, u64) {
    let (mut a, mut b) = (host(A_MAC, 1), host(B_MAC, 2));
    let mut now = 0;
    run(&mut [&mut a, &mut b], &mut now, 500, 4);
    (a, b, now)
}

#[test]
fn ping_and_udp_over_link_local() {
    let (mut a, mut b, mut now) = pair();
    let (la, lb) = (Ipv6::link_local(A_MAC), Ipv6::link_local(B_MAC));
    let p = a.icmp6_open(false);
    a.bind_device(p, Some(ETH)).unwrap();
    let echo = [ICMP6_ECHO_REQUEST, 0, 0, 0, 0, 0, 0, 1, b'h', b'i'];
    a.send_to(p, &echo, Some((lb.into(), 0))).unwrap();
    run(&mut [&mut a, &mut b], &mut now, 10, 2);
    let (reply, from) = a.recv_from(p).unwrap();
    assert_eq!((reply[0], &reply[8..], from.0), (ICMP6_ECHO_REPLY, &b"hi"[..], IpAddr::V6(lb)));
    // The neighbours learned each other.
    assert!(a.neighbours().iter().any(|n| n.ip == IpAddr::V6(lb) && n.mac == Some(B_MAC)));
    // UDP: an AF_INET6 socket on B, a datagram from A's link-local address.
    let rx = b.udp_open();
    b.set_family(rx, true, false).unwrap();
    b.bind(rx, Ipv6::UNSPECIFIED, 5353).unwrap();
    let tx = a.udp_open();
    a.set_family(tx, true, false).unwrap();
    a.bind_device(tx, Some(ETH)).unwrap();
    a.send_to(tx, b"over v6", Some((lb.into(), 5353))).unwrap();
    run(&mut [&mut a, &mut b], &mut now, 10, 2);
    let (d, from) = b.recv_from(rx).unwrap();
    assert_eq!((d.as_slice(), from.0), (&b"over v6"[..], IpAddr::V6(la)));
    // Nobody on that port: "port unreachable" comes back.
    a.connect(tx, (lb.into(), 9)).unwrap();
    a.send_to(tx, b"?", None).unwrap();
    run(&mut [&mut a, &mut b], &mut now, 10, 2);
    assert_eq!(a.recv_from(tx), Err(Error::ConnectionRefused));
}

/// The pair with global addresses 2001:db8::a and ::b added by hand.
fn global_pair() -> (Stack, Stack, u64) {
    let (mut a, mut b, mut now) = pair();
    a.add_address6(ETH, ip("2001:db8::a"), 64).unwrap();
    b.add_address6(ETH, ip("2001:db8::b"), 64).unwrap();
    run(&mut [&mut a, &mut b], &mut now, 500, 4);
    (a, b, now)
}

#[test]
fn tcp_over_ipv6() {
    let (mut a, mut b, mut now) = global_pair();
    let l = b.tcp_open();
    b.tcp_set_family(l, true, false).unwrap();
    b.tcp_bind(l, Ipv6::UNSPECIFIED, 80).unwrap();
    b.tcp_listen(l, 4).unwrap();
    let c = a.tcp_open();
    a.tcp_set_family(c, true, false).unwrap();
    a.tcp_connect(c, (ip("2001:db8::b").into(), 80)).unwrap();
    run(&mut [&mut a, &mut b], &mut now, 10, 5);
    let s = b.tcp_accept(l).unwrap();
    assert_eq!(b.tcp_remote(s).unwrap().unwrap().0, IpAddr::V6(ip("2001:db8::a")));
    let data: Vec<u8> = (0..100_000u32).map(|i| (i * 7) as u8).collect();
    let mut sent = 0;
    let mut got = Vec::new();
    let mut buf = alloc::vec![0u8; 65536];
    for _ in 0..500 {
        if sent < data.len()
            && let Ok(n) = a.tcp_send(c, &data[sent..])
        {
            sent += n;
        }
        run(&mut [&mut a, &mut b], &mut now, 10, 1);
        while let Ok(n) = b.tcp_recv(s, &mut buf, false) {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        if got.len() == data.len() {
            break;
        }
    }
    assert!(got == data, "got {} of {} bytes", got.len(), data.len());
}

#[test]
fn dual_stack_sockets() {
    use crate::tests::{A_IP, B_IP, configure_v4};
    let (mut a, mut b, mut now) = global_pair();
    configure_v4(&mut a, A_IP);
    configure_v4(&mut b, B_IP);
    // An AF_INET6 socket on [::] takes IPv4 too, unless it is v6-only.
    let both = b.udp_open();
    b.set_family(both, true, false).unwrap();
    b.bind(both, Ipv6::UNSPECIFIED, 7000).unwrap();
    let only = b.udp_open();
    b.set_family(only, true, true).unwrap();
    // v6-only on the same port does not clash with a v4 socket...
    let v4 = b.udp_open();
    assert_eq!(b.bind(v4, crate::Ipv4::UNSPECIFIED, 7000), Err(Error::AddrInUse));
    b.bind(only, Ipv6::UNSPECIFIED, 7001).unwrap();
    b.bind(v4, crate::Ipv4::UNSPECIFIED, 7001).unwrap();
    let tx = a.udp_open();
    a.send_to(tx, b"v4 to dual", Some((B_IP.into(), 7000))).unwrap();
    a.send_to(tx, b"v4 to v4", Some((B_IP.into(), 7001))).unwrap();
    run(&mut [&mut a, &mut b], &mut now, 10, 3);
    let (d, from) = b.recv_from(both).unwrap();
    assert_eq!((d.as_slice(), from.0), (&b"v4 to dual"[..], IpAddr::V4(A_IP)));
    assert_eq!(b.recv_from(v4).unwrap().0, b"v4 to v4");
    assert_eq!(b.recv_from(only), Err(Error::WouldBlock));
    // TCP: a [::] listener accepts an IPv4 connection.
    let l = b.tcp_open();
    b.tcp_set_family(l, true, false).unwrap();
    b.tcp_bind(l, Ipv6::UNSPECIFIED, 22).unwrap();
    b.tcp_listen(l, 2).unwrap();
    let c = a.tcp_open();
    a.tcp_connect(c, (B_IP.into(), 22)).unwrap();
    run(&mut [&mut a, &mut b], &mut now, 10, 4);
    let s = b.tcp_accept(l).unwrap();
    assert_eq!(b.tcp_remote(s).unwrap().unwrap().0, IpAddr::V4(A_IP));
}

/// A router advertisement from `router` (link-local) with a prefix, the
/// router's link-layer address and an MTU (RFC 4861 §4.2, §4.6).
fn advert(router: Mac, prefix: Ipv6, lifetime: u16) -> Vec<u8> {
    let src = Ipv6::link_local(router);
    let mut body = Vec::new();
    body.extend_from_slice(&[0; 8]); // reachable time, retrans timer
    body.extend_from_slice(&[1, 1]);
    body.extend_from_slice(&router.0);
    body.extend_from_slice(&[5, 1, 0, 0]);
    body.extend_from_slice(&1400u32.to_be_bytes());
    body.extend_from_slice(&[3, 4, 64, 0xC0]);
    body.extend_from_slice(&86400u32.to_be_bytes());
    body.extend_from_slice(&14400u32.to_be_bytes());
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&prefix.0);
    let mut rest = [64, 0, 0, 0];
    rest[2..4].copy_from_slice(&lifetime.to_be_bytes());
    let m = icmpv6(src, Ipv6::ALL_NODES, ND_ROUTER_ADVERT, 0, rest, &body);
    let p = ipv6(src, Ipv6::ALL_NODES, PROTO_ICMPV6, 255, &m);
    ethernet(Ipv6::ALL_NODES.multicast_mac(), router, ETHERTYPE_IPV6, &p)
}

#[test]
fn slaac_from_a_router_advertisement() {
    let mut a = host(A_MAC, 1);
    let mut now = 0;
    run(&mut [&mut a], &mut now, 500, 3);
    // It asked: a router solicitation to all routers.
    let router = Mac([2, 0, 0, 0, 6, 0xee]);
    let prefix = ip("2001:db8:1::");
    a.receive(ETH, &advert(router, prefix, 1800), now);
    run(&mut [&mut a], &mut now, 500, 4);
    let slaac = Ipv6::with_interface_id(prefix, Ipv6::eui64(A_MAC));
    let got = a.addresses6(ETH).into_iter().find(|x| x.addr == slaac).unwrap();
    assert_eq!((got.state, got.origin), (AddrState::Preferred, AddrOrigin::Slaac));
    // The router is the default route; the prefix is on the link.
    let gw = Ipv6::link_local(router);
    let r = a.lookup6(ip("2001:db8:99::1"), None).unwrap();
    assert_eq!((r.gateway, r.metric, r.protocol), (Some(gw), 1024, crate::PROTO_RA));
    assert_eq!(a.lookup6(ip("2001:db8:1::77"), None).unwrap().gateway, None);
    // Packets to the world leave from the new address, to the router's MAC
    // (learned from the advertisement), sized by its MTU.
    let u = a.udp_open();
    a.set_family(u, true, false).unwrap();
    a.take_tx();
    a.send_to(u, &[0u8; 1500], Some((ip("2001:db8:99::1").into(), 53))).unwrap();
    let tx = a.take_tx();
    assert_eq!(tx.len(), 2, "two fragments for an MTU of 1400");
    let h = Ipv6Header::parse(&tx[0].1[ETH_HEADER..]).unwrap();
    assert_eq!((h.src, h.next, &tx[0].1[..6]), (slaac, NEXT_FRAGMENT, &router.0[..]));
    // A router lifetime of zero: no longer a default router.
    a.receive(ETH, &advert(router, prefix, 0), now);
    assert!(a.lookup6(ip("2001:db8:99::1"), None).is_none());
    // The route's own lifetime runs out too.
    a.receive(ETH, &advert(router, prefix, 30), now);
    run(&mut [&mut a], &mut now, 10_000, 4);
    assert!(a.lookup6(ip("2001:db8:99::1"), None).is_none());
}

#[test]
fn duplicate_address_detection() {
    let (mut a, mut b, mut now) = pair();
    b.add_address6(ETH, ip("2001:db8::5"), 64).unwrap();
    run(&mut [&mut a, &mut b], &mut now, 500, 4);
    // A wants the same address: B defends it, A gives it up.
    a.add_address6(ETH, ip("2001:db8::5"), 64).unwrap();
    run(&mut [&mut a, &mut b], &mut now, 500, 4);
    assert!(!a.addresses6(ETH).iter().any(|x| x.addr == ip("2001:db8::5")));
    assert!(b.addresses6(ETH).iter().any(|x| x.addr == ip("2001:db8::5") && x.state == AddrState::Preferred));
}

#[test]
fn fragments_reassembled() {
    let (mut a, mut b, mut now) = global_pair();
    let rx = b.udp_open();
    b.set_family(rx, true, false).unwrap();
    b.bind(rx, Ipv6::UNSPECIFIED, 9).unwrap();
    let tx = a.udp_open();
    a.set_family(tx, true, false).unwrap();
    let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    a.send_to(tx, &data, Some((ip("2001:db8::b").into(), 9))).unwrap();
    run(&mut [&mut a, &mut b], &mut now, 10, 3);
    assert_eq!(b.recv_from(rx).unwrap().0, data);
}

#[test]
fn forwarding_v6() {
    // A — R — B on two links; R forwards.
    let mut r = Stack::new(9);
    r.add_interface(2, Mac([2, 0, 0, 0, 7, 2]), 1500).unwrap();
    r.add_interface(3, Mac([2, 0, 0, 0, 7, 3]), 1500).unwrap();
    r.set_forwarding6(true);
    let (mut a, mut b) = (host(A_MAC, 1), host(B_MAC, 2));
    let mut now = 0;
    let step = |r: &mut Stack, a: &mut Stack, b: &mut Stack, now: &mut u64, ms: u64| {
        for _ in 0..30 {
            r.poll(*now);
            a.poll(*now);
            b.poll(*now);
            let (fr, fa, fb) = (r.take_tx(), a.take_tx(), b.take_tx());
            if fr.is_empty() && fa.is_empty() && fb.is_empty() {
                break;
            }
            for (i, f) in fr {
                if i == 2 { a.receive(ETH, &f, *now) } else { b.receive(ETH, &f, *now) }
            }
            fa.iter().for_each(|f| r.receive(2, &f.1, *now));
            fb.iter().for_each(|f| r.receive(3, &f.1, *now));
        }
        *now += ms;
    };
    for _ in 0..4 {
        step(&mut r, &mut a, &mut b, &mut now, 500);
    }
    r.add_address6(2, ip("2001:db8:a::1"), 64).unwrap();
    r.add_address6(3, ip("2001:db8:b::1"), 64).unwrap();
    a.add_address6(ETH, ip("2001:db8:a::2"), 64).unwrap();
    b.add_address6(ETH, ip("2001:db8:b::2"), 64).unwrap();
    let default = |gw: &str| Route6 {
        dst: Ipv6::UNSPECIFIED,
        prefix_len: 0,
        gateway: Some(ip(gw)),
        iface: ETH,
        metric: 1,
        protocol: crate::PROTO_STATIC,
        expires: None,
    };
    a.add_route6(default("2001:db8:a::1")).unwrap();
    b.add_route6(default("2001:db8:b::1")).unwrap();
    for _ in 0..4 {
        step(&mut r, &mut a, &mut b, &mut now, 500);
    }
    let rx = b.udp_open();
    b.set_family(rx, true, false).unwrap();
    b.bind(rx, Ipv6::UNSPECIFIED, 7).unwrap();
    let tx = a.udp_open();
    a.set_family(tx, true, false).unwrap();
    a.send_to(tx, b"routed", Some((ip("2001:db8:b::2").into(), 7))).unwrap();
    for _ in 0..3 {
        step(&mut r, &mut a, &mut b, &mut now, 10);
    }
    let (d, from) = b.recv_from(rx).unwrap();
    assert_eq!((d.as_slice(), from.0), (&b"routed"[..], IpAddr::V6(ip("2001:db8:a::2"))));
}

/// IPV6_TCLASS: the traffic class a socket sets goes out in its packets'
/// headers (RFC 8200 §3) and the receiver reads it; arrival times come
/// from the embedder's clock when it gives one.
#[test]
fn traffic_class_and_arrival() {
    let (mut a, mut b, mut now) = global_pair();
    let rx = b.udp_open();
    b.set_family(rx, true, false).unwrap();
    b.bind(rx, Ipv6::UNSPECIFIED, 5000).unwrap();
    let tx = a.udp_open();
    a.set_family(tx, true, false).unwrap();
    a.set_ip_options(tx, crate::IpOptions { tos: 0xB8, ..Default::default() }).unwrap();
    a.send_to(tx, b"classed", Some((ip("2001:db8::b").into(), 5000))).unwrap();
    b.clock_ns = 123_456_789;
    run(&mut [&mut a, &mut b], &mut now, 10, 2);
    let (d, _, meta) = b.recv_meta(rx).unwrap();
    assert_eq!((d.as_slice(), meta.tos, meta.at), (&b"classed"[..], 0xB8, 123_456_789));
}

/// udp(7): connect takes the source address the route would use, which
/// getsockname reports (getaddrinfo ranks a name's addresses by it, RFC
/// 6724); disconnecting gives the wildcard back.
#[test]
fn udp_connect_picks_the_source() {
    let (mut a, mut b, mut now) = pair();
    let default = Route6 {
        dst: Ipv6::UNSPECIFIED,
        prefix_len: 0,
        gateway: Some(Ipv6::link_local(B_MAC)),
        iface: ETH,
        metric: 1024,
        protocol: crate::PROTO_STATIC,
        expires: None,
    };
    a.add_route6(default).unwrap();
    let u = a.udp_open();
    a.set_family(u, true, false).unwrap();
    let far = (ip("2001:db8:1::1").into(), 53);
    // Only a link-local address: that one (its scope ranks the
    // destination below IPv4 ones).
    a.connect(u, far).unwrap();
    assert_eq!(a.local(u).unwrap().unwrap().0, IpAddr::V6(Ipv6::link_local(A_MAC)));
    // A site-local one (as QEMU's user network gives): that is the source.
    a.add_address6(ETH, ip("fec0::a"), 64).unwrap();
    run(&mut [&mut a, &mut b], &mut now, 500, 4);
    a.connect(u, far).unwrap();
    let (src, port) = a.local(u).unwrap().unwrap();
    assert_eq!(src, IpAddr::V6(ip("fec0::a")));
    assert_ne!(port, 0);
    // Disconnected (AF_UNSPEC): the wildcard again, on the same port.
    a.connect(u, (Ipv6::UNSPECIFIED.into(), 0)).unwrap();
    assert_eq!(a.local(u).unwrap(), Some((IpAddr::V6(Ipv6::UNSPECIFIED), port)));
    // Link-scope destinations go from the link-local address.
    a.connect(u, (Ipv6::link_local(B_MAC).into(), 53)).unwrap();
    assert_eq!(a.local(u).unwrap().unwrap().0, IpAddr::V6(Ipv6::link_local(A_MAC)));
    // Bound by hand, the address stays as bound.
    let v = a.udp_open();
    a.set_family(v, true, false).unwrap();
    a.bind(v, Ipv6::UNSPECIFIED, 4000).unwrap();
    let w = a.udp_open();
    a.set_family(w, true, false).unwrap();
    a.bind(w, ip("fec0::a"), 4001).unwrap();
    a.connect(w, (Ipv6::link_local(B_MAC).into(), 53)).unwrap();
    assert_eq!(a.local(w).unwrap().unwrap().0, IpAddr::V6(ip("fec0::a")));
}
