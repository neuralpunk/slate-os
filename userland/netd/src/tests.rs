// SPDX-License-Identifier: MIT OR Apache-2.0

use alloc::vec;

use slate_net::dhcp as msg;
use slate_net::{Ipv4, Ipv6, Mac};

use crate::config::{Method, Network, Server};
use crate::dhcp::{Action, Client};
use crate::{nl, rdnss, resolv_conf, router_solicitation, status_line, zone_name};

const MAC: Mac = Mac([2, 0, 0, 0, 0, 7]);
const SERVER: Ipv4 = Ipv4([10, 0, 2, 2]);
const OFFERED: Ipv4 = Ipv4([10, 0, 2, 15]);

#[test]
fn config_sections_and_defaults() {
    let text = "\
# Two cards.
[eth1]
method = static
address = 10.0.3.15/24
gateway = 10.0.3.2
dns = 10.0.3.3, 9.9.9.9

[usb0]
method = off
[*]
method = dhcp
";
    let (net, problems) = Network::parse(text);
    assert!(problems.is_empty(), "{problems:?}");
    assert_eq!(
        net.method("eth1"),
        Method::Static { addr: Ipv4([10, 0, 3, 15]), prefix_len: 24, gateway: Some(Ipv4([10, 0, 3, 2])) }
    );
    assert_eq!(net.dns("eth1"), vec![Server::new(Ipv4([10, 0, 3, 3])), Server::new(Ipv4([9, 9, 9, 9]))]);
    assert_eq!(net.method("usb0"), Method::Off);
    assert_eq!(net.method("eth0"), Method::Dhcp);
    // No file at all: DHCP everywhere.
    assert_eq!(Network::parse("").0.method("eth5"), Method::Dhcp);
}

#[test]
fn config_problems_are_reported() {
    let (net, problems) =
        Network::parse("method = dhcp\n[eth0]\nmethod = static\ngateway = 1.2.3\ncolor = blue\n[*]\nmethod = off\n");
    let lines: alloc::vec::Vec<usize> = problems.iter().map(|p| p.line).collect();
    // Outside a section, a bad gateway, an unknown key, and a static card
    // with no address (left out, so eth0 falls back to [*]).
    assert_eq!(lines, vec![1, 4, 5, 2]);
    assert_eq!(net.method("eth0"), Method::Off);
}

fn server_reply(kind: u8, xid: u32) -> alloc::vec::Vec<u8> {
    msg::server_message(kind, xid, MAC, OFFERED, SERVER, SERVER, Ipv4([10, 0, 2, 3]))
}

/// The client's last message: (type, transaction, requested address).
fn sent(actions: &[Action]) -> (Ipv4, u8, u32, Option<Ipv4>) {
    let Some(Action::Send { to, message }) = actions.iter().find(|a| matches!(a, Action::Send { .. })) else {
        panic!("nothing sent: {actions:?}")
    };
    let (kind, xid, req) = msg::parse_client(message).unwrap();
    (*to, kind, xid, req)
}

#[test]
fn dhcp_lease_renewal_and_expiry() {
    let mut c = Client::new(MAC, b"slate", 42);
    let (to, kind, xid, _) = sent(&c.tick(0));
    assert_eq!((to, kind), (Ipv4::BROADCAST, msg::DISCOVER));
    // No answer: DISCOVER again after the backoff, not before.
    assert!(c.tick(1000).is_empty());
    assert_eq!(sent(&c.tick(2000)).1, msg::DISCOVER);
    let a = c.receive(&server_reply(msg::OFFER, xid), 2100);
    let (_, kind, xid2, req) = sent(&a);
    assert_eq!((kind, xid2, req), (msg::REQUEST, xid, Some(OFFERED)));
    // A reply to another transaction is ignored.
    assert!(c.receive(&server_reply(msg::ACK, xid ^ 1), 2150).is_empty());
    let a = c.receive(&server_reply(msg::ACK, xid), 2200);
    let Some(Action::Configure(lease)) = a.first() else { panic!("{a:?}") };
    assert_eq!((lease.addr, lease.prefix_len, lease.router, lease.secs), (OFFERED, 24, Some(SERVER), 86_400));
    assert_eq!(lease.dns, vec![Ipv4([10, 0, 2, 3])]);
    // Renewing at T1 (12 h), to the server itself.
    let t1 = 2200 + 43_200_000;
    assert!(c.tick(t1 - 1).is_empty());
    let a = c.tick(t1);
    let (to, kind, rxid, req) = sent(&a);
    assert_eq!((to, kind, req), (SERVER, msg::REQUEST, None));
    let a = c.receive(&server_reply(msg::ACK, rxid), t1 + 10);
    assert!(matches!(a.as_slice(), [Action::Configure(_)]));
    // Nobody answers the next renewals: rebinding by broadcast after T2,
    // and the lease ends after its 24 h.
    let start = t1 + 10;
    let t2 = start + 86_400_000 * 7 / 8;
    let mut broadcast = false;
    let mut t = start;
    let mut gone = false;
    while t < start + 86_400_000 + 1000 {
        for a in c.tick(t) {
            match a {
                Action::Send { to, .. } if t >= t2 => broadcast |= to == Ipv4::BROADCAST,
                Action::Deconfigure => gone = true,
                _ => {}
            }
        }
        t += 30_000;
    }
    assert!(broadcast && gone);
    assert!(c.lease().is_none());
}

#[test]
fn dhcp_time_zone() {
    // RFC 4833's TCode: asked for, and carried into the lease.
    let mut c = Client::new(MAC, b"slate", 5);
    let a = c.tick(0);
    let Some(Action::Send { message, .. }) = a.first() else { panic!("{a:?}") };
    let params = message.windows(2).position(|w| w == [55, 6]).expect("parameter list");
    assert!(message[params + 2..params + 8].contains(&101));
    let (_, _, xid, _) = sent(&a);
    c.receive(&server_reply(msg::OFFER, xid), 10);
    let ack = msg::with_option(&server_reply(msg::ACK, xid), 101, b"Europe/Berlin");
    let a = c.receive(&ack, 20);
    let Some(Action::Configure(lease)) = a.first() else { panic!("{a:?}") };
    assert_eq!(zone_name(&lease.timezone), Some("Europe/Berlin"));
    // Only names that are safe as paths.
    assert_eq!(zone_name(b"America/Argentina/Buenos_Aires\0"), Some("America/Argentina/Buenos_Aires"));
    for bad in [&b""[..], b"../etc/passwd", b"Europe//Berlin", b"Europe/Berlin\n", b"/Europe"] {
        assert_eq!(zone_name(bad), None, "{bad:?}");
    }
}

#[test]
fn dhcp_nak_starts_over() {
    let mut c = Client::new(MAC, b"", 9);
    let (_, _, xid, _) = sent(&c.tick(0));
    c.receive(&server_reply(msg::OFFER, xid), 10);
    c.receive(&server_reply(msg::ACK, xid), 20);
    assert!(c.lease().is_some());
    let a = c.tick(43_200_020);
    let (_, _, rxid, _) = sent(&a);
    let a = c.receive(&server_reply(msg::NAK, rxid), 43_200_030);
    assert_eq!(a[0], Action::Deconfigure);
    assert_eq!(sent(&a).1, msg::DISCOVER);
}

#[test]
fn netlink_requests_and_replies() {
    let m = nl::address(7, true, 3, Ipv4([10, 0, 3, 15]), 24);
    // nlmsghdr: length, RTM_NEWADDR, request|ack|create|replace, seq 7.
    assert_eq!(u32::from_ne_bytes(m[0..4].try_into().unwrap()) as usize, m.len());
    assert_eq!(u16::from_ne_bytes([m[4], m[5]]), nl::RTM_NEWADDR);
    assert_eq!(u16::from_ne_bytes([m[6], m[7]]), 0x1 | 0x4 | 0x400 | 0x100);
    assert_eq!(&m[16..20], &[2, 24, 0, 0]);
    assert_eq!(u32::from_ne_bytes(m[20..24].try_into().unwrap()), 3);
    // An acknowledgement quotes the request's header.
    let mut ack = vec![0u8; 16];
    ack[0..4].copy_from_slice(&36u32.to_ne_bytes());
    ack[4..6].copy_from_slice(&nl::NLMSG_ERROR.to_ne_bytes());
    ack.extend_from_slice(&(-17i32).to_ne_bytes());
    ack.extend_from_slice(&m[..16]);
    assert_eq!(nl::parse(&ack), vec![nl::Message::Ack(7, 17)]);
    // A link with its name and address.
    let mut link = vec![0u8; 16];
    link[4..6].copy_from_slice(&nl::RTM_NEWLINK.to_ne_bytes());
    link.extend_from_slice(&[0, 0, 1, 0]);
    link.extend_from_slice(&2i32.to_ne_bytes());
    link.extend_from_slice(&(nl::IFF_UP | nl::IFF_RUNNING).to_ne_bytes());
    link.extend_from_slice(&0u32.to_ne_bytes());
    link.extend_from_slice(&[9, 0, 3, 0, b'e', b't', b'h', b'0', 0, 0, 0, 0]);
    link.extend_from_slice(&[10, 0, 1, 0, 2, 0, 0, 0, 0, 7, 0, 0]);
    let n = link.len() as u32;
    link[0..4].copy_from_slice(&n.to_ne_bytes());
    let parsed = nl::parse(&link);
    let [nl::Message::Link(l)] = parsed.as_slice() else { panic!("{parsed:?}") };
    assert_eq!((l.index, l.name.as_str(), l.mac), (2, "eth0", MAC));
    assert!(l.has_link());
}

#[test]
fn resolv_conf_lists_each_server_once() {
    let a = Server::new(Ipv4([10, 0, 2, 3]));
    let b = Server::new(Ipv4([9, 9, 9, 9]));
    let c = Server::new(Ipv6::parse("fec0::3").unwrap());
    let odd = Server::parse("10.0.2.2:5353").unwrap();
    // Without the cache: the servers themselves (the file has no ports).
    assert_eq!(
        resolv_conf(&[a, b, a, odd, c], false, "lan"),
        "# Written by netd from the network's settings.\nsearch lan\nnameserver 10.0.2.3\nnameserver 9.9.9.9\n\
         nameserver fec0::3\n"
    );
    // With it: only the cache.
    assert_eq!(resolv_conf(&[a], true, ""), "# Written by netd from the network's settings.\nnameserver 127.0.0.53\n");
}

#[test]
fn server_addresses() {
    let s = |t: &str| Server::parse(t).map(|s| alloc::format!("{s}"));
    assert_eq!(s("10.0.2.3").as_deref(), Some("10.0.2.3"));
    assert_eq!(s("10.0.2.2:5353").as_deref(), Some("10.0.2.2:5353"));
    assert_eq!(s("fec0::3").as_deref(), Some("fec0::3"));
    assert_eq!(s("[fec0::2]:5353").as_deref(), Some("[fec0::2]:5353"));
    assert_eq!(s("[fec0::2]").as_deref(), Some("fec0::2"));
    assert_eq!(s("[fec0::2]:0"), None);
    assert_eq!(s("10.0.2.2:x"), None);
    assert_eq!(s("example.com"), None);
}

#[test]
fn dns_cache() {
    use crate::dns::Cache;
    let q = slate_dns::query_type(5, "host.slate.test", slate_dns::TYPE_A).unwrap();
    let question = slate_dns::question(&q).unwrap();
    let reply = slate_dns::reply(&q, 0, &[(slate_dns::TYPE_A, &[10, 0, 2, 2], 30)]).unwrap();
    let mut c = Cache::default();
    c.put(&question, &reply, 1000);
    // Asked again with another ID: the kept answer, with that ID.
    let again = slate_dns::question(&slate_dns::query_type(77, "HOST.slate.test", slate_dns::TYPE_A).unwrap()).unwrap();
    let r = c.get(&again, 20_000).unwrap();
    assert_eq!(slate_dns::answer(&r, 77, "host.slate.test"), Ok(vec![[10, 0, 2, 2]]));
    // Gone after its TTL.
    assert!(c.get(&again, 31_001).is_none());
    // "No such name" is kept a minute; a server failure not at all.
    let nx = slate_dns::reply(&q, 3, &[]).unwrap();
    c.put(&question, &nx, 40_000);
    assert!(c.get(&question, 99_999).is_some() && c.get(&question, 100_000).is_none());
    let fail = slate_dns::reply(&q, 2, &[]).unwrap();
    let mut d = Cache::default();
    d.put(&question, &fail, 0);
    assert!(d.is_empty());
}

#[test]
fn status_lines() {
    let dns = [Server::new(Ipv4([10, 0, 2, 3]))];
    assert_eq!(
        status_line("eth0", true, &Method::Dhcp, Some((OFFERED, 24)), Some(SERVER), &dns, &[]),
        "eth0 up dhcp 10.0.2.15/24 via 10.0.2.2 dns 10.0.2.3\n"
    );
    assert_eq!(status_line("eth1", false, &Method::Off, None, None, &[], &[]), "eth1 down off\n");
    let six = [(Ipv6::parse("fec0::5054:ff:fe12:3456").unwrap(), 64)];
    let dns6 = [Server::new(Ipv6::parse("fec0::3").unwrap()), Server::parse("[fec0::2]:5353").unwrap()];
    assert_eq!(
        status_line("eth0", true, &Method::Dhcp, None, None, &dns6, &six),
        "eth0 up dhcp inet6 fec0::5054:ff:fe12:3456/64 dns fec0::3 [fec0::2]:5353\n"
    );
}

#[test]
fn ipv6_settings() {
    let (net, problems) =
        Network::parse("[eth1]\naddress6 = fec1::20/64\ngateway6 = fec1::2\ndns = 10.0.3.3 fec1::3\naddress6 = x\n");
    assert_eq!(problems.len(), 1);
    let six = net.six("eth1");
    assert_eq!(six.address, Some((Ipv6::parse("fec1::20").unwrap(), 64)));
    assert_eq!(six.gateway, Ipv6::parse("fec1::2"));
    assert_eq!(net.dns("eth1"), vec![Server::new(Ipv4([10, 0, 3, 3])), Server::new(Ipv6::parse("fec1::3").unwrap())]);
    assert_eq!(net.six("eth0"), Default::default());
}

#[test]
fn rdnss_from_an_advertisement() {
    // A router advertisement: the 16-byte header, a source link-layer
    // option, then RDNSS with two servers (RFC 8106 §5.1).
    let mut ra = vec![134, 0, 0, 0, 64, 0, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0];
    ra.extend_from_slice(&[1, 1, 2, 0, 0, 0, 0, 1]);
    ra.extend_from_slice(&[25, 5, 0, 0]);
    ra.extend_from_slice(&3600u32.to_be_bytes());
    ra.extend_from_slice(&Ipv6::parse("fec0::3").unwrap().0);
    ra.extend_from_slice(&Ipv6::parse("2001:db8::53").unwrap().0);
    let (servers, life) = rdnss(&ra).unwrap();
    assert_eq!(life, 3600);
    assert_eq!(servers, vec![Ipv6::parse("fec0::3").unwrap(), Ipv6::parse("2001:db8::53").unwrap()]);
    assert_eq!(rdnss(&ra[..24]), None);
    let rs = router_solicitation(MAC);
    assert_eq!((rs[0], rs[8], rs[9], &rs[10..]), (133, 1, 1, &MAC.0[..]));
}

#[test]
fn ntp_config() {
    use crate::ntp::{Peer, parse};
    let p = |h: &str, port| Peer { host: h.into(), port };
    assert_eq!(parse(None), (std::vec![p("pool.ntp.org", 123)], std::vec![]));
    let text = "# clocks\nserver time.example.org\nserver 10.0.2.2:12345\nserver [fec0::2]:124\nserver fec0::3\n\
                server bad_name!\nhost x\n";
    assert_eq!(
        parse(Some(text)),
        (
            std::vec![p("time.example.org", 123), p("10.0.2.2", 12345), p("fec0::2", 124), p("fec0::3", 123)],
            std::vec![6, 7]
        )
    );
    // A file without servers turns NTP off.
    assert_eq!(parse(Some("# none\n")), (std::vec![], std::vec![]));
}

#[test]
fn ntp_packets() {
    use crate::ntp::{Reply, from_ntp, reply, request, seconds, to_ntp};
    // 2026-10-21 00:00:00.25 UTC, and a time in NTP's era 1 (2040).
    for ns in [1_792_540_800_250_000_000i64, 2_208_988_800_000_000_000, 0] {
        assert!((from_ntp(to_ntp(ns)) - ns).abs() < 2, "{ns}");
    }
    assert_eq!(to_ntp(0) >> 32, 2_208_988_800);
    let t1 = to_ntp(1_000_000_000_000_000_000);
    let r = request(t1);
    assert_eq!((r[0], &r[40..48]), (0x23, &t1.to_be_bytes()[..]));
    // A server 10 s ahead, 20 ms away each way.
    let server = |stratum: u8, origin: u64| {
        let mut p = [0u8; 48];
        p[0] = 0x24; // version 4, mode 4
        p[1] = stratum;
        p[24..32].copy_from_slice(&origin.to_be_bytes());
        p[32..40].copy_from_slice(&to_ntp(1_000_000_010_020_000_000).to_be_bytes());
        p[40..48].copy_from_slice(&to_ntp(1_000_000_010_021_000_000).to_be_bytes());
        p
    };
    let got = reply(&server(2, t1), t1, 1_000_000_000_041_000_000);
    match got {
        Some(Reply::Time { offset, delay }) => {
            assert!((offset - 10_000_000_000).abs() < 10, "{offset}");
            assert!((delay - 40_000_000).abs() < 10, "{delay}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(reply(&server(0, t1), t1, 0), Some(Reply::Kiss));
    assert_eq!(reply(&server(2, t1 + 1), t1, 0), None); // not our request
    assert_eq!(reply(&server(16, t1), t1, 0), None); // unsynchronized
    assert_eq!(reply(&server(2, t1)[..40], t1, 0), None);
    assert_eq!((seconds(-1_234_567_890), seconds(5_000_000)), ("-1.234s".into(), "+0.005s".into()));
}
