// SPDX-License-Identifier: MIT OR Apache-2.0

use slate_net::{IpAddr, Ipv4, Ipv6};

use crate::resolve::{from_hosts, literal, nameservers, server};

#[test]
fn literals_and_servers() {
    assert_eq!(literal("10.0.2.2"), Some(IpAddr::V4(Ipv4([10, 0, 2, 2]))));
    assert_eq!(literal("[fec0::2]"), Ipv6::parse("fec0::2").map(IpAddr::V6));
    assert_eq!(literal("fec0::2"), Ipv6::parse("fec0::2").map(IpAddr::V6));
    assert_eq!(literal("example.com"), None);
    assert_eq!(server("10.0.2.2:5353"), Some((IpAddr::V4(Ipv4([10, 0, 2, 2])), 5353)));
    assert_eq!(server("[fec0::2]:5353"), Some((IpAddr::V6(Ipv6::parse("fec0::2").unwrap()), 5353)));
    assert_eq!(server("fec0::3"), Some((IpAddr::V6(Ipv6::parse("fec0::3").unwrap()), 53)));
    assert_eq!(server("x:1"), None);
}

#[test]
fn hosts_and_resolv_conf() {
    let hosts = "127.0.0.1 localhost\n::1 localhost ip6-localhost # loopback\n10.0.2.2 host.lan host\n";
    assert_eq!(from_hosts(hosts, "LOCALHOST"), std::vec![IpAddr::V4(Ipv4::LOCALHOST), IpAddr::V6(Ipv6::LOCALHOST)]);
    assert_eq!(from_hosts(hosts, "host"), std::vec![IpAddr::V4(Ipv4([10, 0, 2, 2]))]);
    assert!(from_hosts(hosts, "nope").is_empty());
    let conf = "# netd\nsearch lan\nnameserver 127.0.0.53\nnameserver fec0::3\nnameserver bogus\n";
    assert_eq!(
        nameservers(conf),
        std::vec![IpAddr::V4(Ipv4([127, 0, 0, 53])), IpAddr::V6(Ipv6::parse("fec0::3").unwrap())]
    );
}

#[test]
fn lookup_lines() {
    assert_eq!(crate::lookup::line("h", &IpAddr::V4(Ipv4([1, 2, 3, 4]))), "h has address 1.2.3.4");
    assert_eq!(crate::lookup::line("h", &IpAddr::V6(Ipv6::LOCALHOST)), "h has IPv6 address ::1");
}

#[test]
fn ip_lines() {
    use crate::ip::{addr_lines, link_lines, mac, neigh_line, prefix, route_line};
    use crate::rtnl::{self, Addr, Link, Neigh, Route};
    let eth = Link {
        index: 2,
        hw_type: 1,
        flags: rtnl::IFF_UP | rtnl::IFF_BROADCAST | rtnl::IFF_MULTICAST | rtnl::IFF_RUNNING | rtnl::IFF_LOWER_UP,
        name: "eth0".into(),
        mac: mac("52:54:00:12:34:56"),
        broadcast: Some(slate_net::Mac::BROADCAST),
        mtu: 1500,
        txqlen: 1000,
        operstate: 6,
    };
    assert_eq!(
        link_lines(&eth),
        [
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP qlen 1000".into(),
            std::string::String::from("    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff")
        ]
    );
    let down = Link { flags: rtnl::IFF_UP | rtnl::IFF_BROADCAST, operstate: 2, ..eth.clone() };
    assert!(link_lines(&down)[0].starts_with("2: eth0: <NO-CARRIER,BROADCAST,UP> mtu 1500 state DOWN"));
    let a = Addr {
        index: 2,
        prefix_len: 24,
        flags: rtnl::IFA_F_PERMANENT,
        scope: 0,
        addr: IpAddr::V4(Ipv4([10, 0, 2, 15])),
        broadcast: Some(Ipv4([10, 0, 2, 255])),
        label: "eth0".into(),
        preferred: None,
        valid: None,
    };
    assert_eq!(
        addr_lines(&a, "eth0"),
        [
            "    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0".into(),
            std::string::String::from("       valid_lft forever preferred_lft forever")
        ]
    );
    let a6 = Addr {
        prefix_len: 64,
        flags: 0,
        scope: rtnl::RT_SCOPE_UNIVERSE,
        addr: IpAddr::V6(Ipv6::parse("fec0::5054:ff:fe12:3456").unwrap()),
        broadcast: None,
        preferred: Some(14000),
        valid: Some(86000),
        ..a.clone()
    };
    assert_eq!(addr_lines(&a6, "eth0")[0], "    inet6 fec0::5054:ff:fe12:3456/64 scope global dynamic");
    assert_eq!(addr_lines(&a6, "eth0")[1], "       valid_lft 86000sec preferred_lft 14000sec");
    let names = [(2, std::string::String::from("eth0"))].into_iter().collect();
    let def = Route {
        family: rtnl::AF_INET,
        gateway: Some(IpAddr::V4(Ipv4([10, 0, 2, 2]))),
        oif: Some(2),
        metric: Some(100),
        prefsrc: Some(IpAddr::V4(Ipv4([10, 0, 2, 15]))),
        protocol: 16,
        table: rtnl::RT_TABLE_MAIN,
        ..Default::default()
    };
    assert_eq!(route_line(&def, &names), "default via 10.0.2.2 dev eth0 proto dhcp src 10.0.2.15 metric 100");
    let net = Route {
        dst: Some(IpAddr::V4(Ipv4([10, 0, 2, 0]))),
        dst_len: 24,
        gateway: None,
        metric: None,
        protocol: 2,
        scope: rtnl::RT_SCOPE_LINK,
        ..def.clone()
    };
    assert_eq!(route_line(&net, &names), "10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15");
    let n = Neigh {
        index: 2,
        state: rtnl::NUD_REACHABLE,
        dst: IpAddr::V4(Ipv4([10, 0, 2, 2])),
        lladdr: mac("52:55:0a:00:02:02"),
    };
    assert_eq!(neigh_line(&n, Some("eth0")), "10.0.2.2 dev eth0 lladdr 52:55:0a:00:02:02 REACHABLE");
    assert_eq!(neigh_line(&Neigh { state: rtnl::NUD_INCOMPLETE, lladdr: None, ..n }, None), "10.0.2.2 INCOMPLETE");
    assert_eq!(prefix("10.0.3.0/24"), Some((IpAddr::V4(Ipv4([10, 0, 3, 0])), 24)));
    assert_eq!(prefix("fec1::3"), Some((IpAddr::V6(Ipv6::parse("fec1::3").unwrap()), 128)));
    assert_eq!(prefix("10.0.3.0/33"), None);
    assert_eq!(mac("52:54:00:12:34"), None);
}

#[test]
fn ip_netlink_round_trip() {
    use crate::rtnl::{self, Message};
    // What the kernel sends back for a route dump is what `route` builds.
    let r = rtnl::Route {
        family: rtnl::AF_INET6,
        dst: Some(IpAddr::V6(Ipv6::parse("fec1::").unwrap())),
        dst_len: 64,
        gateway: Some(IpAddr::V6(Ipv6::parse("fe80::1").unwrap())),
        oif: Some(3),
        metric: Some(1024),
        prefsrc: None,
        protocol: rtnl::RTPROT_STATIC,
        scope: 0,
        table: rtnl::RT_TABLE_MAIN,
        kind: rtnl::RTN_UNICAST,
    };
    let mut msg = rtnl::route(7, false, rtnl::NLM_F_CREATE, &r);
    msg[4..6].copy_from_slice(&rtnl::RTM_NEWROUTE.to_ne_bytes());
    assert_eq!(rtnl::parse(&msg), std::vec![Message::Route(r)]);
    let n = rtnl::neighbour(
        8,
        false,
        rtnl::NLM_F_CREATE,
        2,
        IpAddr::V4(Ipv4([10, 0, 2, 9])),
        crate::ip::mac("02:00:00:00:00:09"),
    );
    match &rtnl::parse(&n)[..] {
        [Message::Neigh(x)] => {
            assert_eq!((x.index, x.state, x.lladdr), (2, rtnl::NUD_PERMANENT, crate::ip::mac("02:00:00:00:00:09")))
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn ss_table() {
    use crate::ss::{Opts, endpoint, parse, state_bits, table};
    let none = std::collections::BTreeMap::new();
    let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                  0: 00000000:0016 00000000:0000 0A 00000080:00000000 00:00000000 00000000     0        0 4242\n\
                  1: 0F02000A:0016 0202000A:C350 01 00000000:00000005 00:00000000 00000000     0        0 0\n";
    let tcp6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue\n\
                   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000\n\
                   1: 0000000000000000FFFF00000F02000A:1F90 0000000000000000FFFF00000202000A:D000 01 00000000:00000000\n";
    let udp = "  sl  local_address rem_address   st tx_queue rx_queue\n    0: 3500007F:0035 00000000:0000 07 00000000:00000000\n";
    let mut socks = parse(tcp, true);
    socks.extend(parse(tcp6, true));
    socks.extend(parse(udp, false));
    assert_eq!(socks.len(), 5);
    assert_eq!(endpoint(&socks[0].local, false), "0.0.0.0:22");
    assert_eq!(endpoint(&socks[0].remote, true), "0.0.0.0:*");
    assert_eq!(endpoint(&socks[1].remote, true), "10.0.2.2:50000");
    assert_eq!(endpoint(&socks[2].local, false), "[::1]:8080");
    assert_eq!(endpoint(&socks[3].local, false), "[::ffff:10.0.2.15]:8080");
    let listen = table(&socks, &Opts { tcp: true, listening: true, ..Default::default() }, &none);
    assert_eq!(
        listen,
        std::vec![
            "State  Recv-Q Send-Q Local Address:Port Peer Address:Port",
            "LISTEN      0    128 0.0.0.0:22         0.0.0.0:*",
            "LISTEN      0      0 [::1]:8080         [::]:*",
        ]
        .iter()
        .map(|s| std::string::String::from(*s))
        .collect::<std::vec::Vec<_>>()
    );
    let all = table(&socks, &Opts { all: true, no_header: true, ..Default::default() }, &none);
    assert_eq!(all.len(), 5);
    assert!(all[4].starts_with("udp   UNCONN"));
    assert!(all[1].starts_with("tcp   ESTAB"));
    // Without -l or -a, connected sockets only.
    assert_eq!(table(&socks, &Opts::default(), &none).len(), 3);
    // State filters, by name and group.
    let only = |names: &[&str]| Some(names.iter().fold(0, |b, n| b | state_bits(n).unwrap()));
    let estab = table(&socks, &Opts { states: only(&["established"]), no_header: true, ..Default::default() }, &none);
    assert_eq!(estab.len(), 2);
    let listening = table(&socks, &Opts { tcp: true, states: only(&["listening"]), ..Default::default() }, &none);
    assert_eq!(listening.len(), 3);
    assert_eq!(state_bits("connected").unwrap() & state_bits("listening").unwrap(), 0);
    assert!(state_bits("nonsense").is_none());
    // -p and -e: the holders and the user and inode.
    let mut users = std::collections::BTreeMap::new();
    users.insert(4242u64, std::string::String::from("users:((\"sshd\",pid=7,fd=3))"));
    let p = table(
        &socks[..1],
        &Opts { tcp: true, listening: true, processes: true, extended: true, ..Default::default() },
        &users,
    );
    assert!(p[0].ends_with("Process"), "{p:?}");
    assert!(p[1].ends_with("users:((\"sshd\",pid=7,fd=3)) uid:0 ino:4242"), "{p:?}");
}

#[test]
fn ping_parts() {
    use crate::ping::{ms, reply_line, reply_seq, request, seconds, summary};
    assert_eq!(reply_line(64, "10.0.2.2", 3, Some(64), 1234), "64 bytes from 10.0.2.2: icmp_seq=3 ttl=64 time=1.23 ms");
    assert_eq!(reply_line(64, "::1", 1, None, 50), "64 bytes from ::1: icmp_seq=1 time=0.050 ms");
    let r = request(false, 3, 4);
    assert_eq!(r, std::vec![8, 0, 0, 0, 0, 0, 0, 3, 0, 1, 2, 3]);
    assert_eq!(request(true, 1, 0)[0], 128);
    assert_eq!(reply_seq(false, &[0, 0, 0, 0, 0, 9, 0, 3]), Some(3));
    assert_eq!(reply_seq(true, &[129, 0, 0, 0, 0, 9, 1, 0]), Some(256));
    assert_eq!(reply_seq(false, &[8, 0, 0, 0, 0, 9, 0, 3]), None);
    assert_eq!(
        (ms(123), ms(4567), ms(45_678), ms(456_789)),
        ("0.123".into(), "4.56".into(), "45.6".into(), "456".into())
    );
    assert_eq!(
        (seconds("1"), seconds("0.2"), seconds(".5"), seconds("x"), seconds("1.0000001")),
        (Some(1_000_000), Some(200_000), Some(500_000), None, None)
    );
    assert_eq!(
        summary("h", 4, &[1000, 3000, 2000], 3004),
        std::vec![
            std::string::String::from("--- h ping statistics ---"),
            "4 packets transmitted, 3 received, 25% packet loss, time 3004ms".into(),
            "rtt min/avg/max/mdev = 1.000/2.000/3.000/0.816 ms".into(),
        ]
    );
    assert_eq!(summary("h", 2, &[], 1000).len(), 2);
}

#[test]
fn network_show() {
    let out = crate::netcfg::show(
        "# settings\n[*]\nmethod = dhcp\n[eth1]\nmethod = static\naddress = 10.0.3.20/24\ngateway = 10.0.3.2\n",
        "eth0 up dhcp 10.0.2.15/24 via 10.0.2.2 dns 10.0.2.3\nntp off\n",
    );
    assert_eq!(
        out,
        [
            "Settings (/etc/slate/network):",
            "  *     dhcp",
            "  eth1  static 10.0.3.20/24 gateway 10.0.3.2",
            "Now (/run/netd/status):",
            "  eth0 up dhcp 10.0.2.15/24 via 10.0.2.2 dns 10.0.2.3",
            "  ntp off",
        ]
        .map(std::string::String::from)
    );
    assert_eq!(crate::netcfg::show("", "")[1], "  (none: every card uses DHCP)");
}

#[test]
fn ip_route_get_and_forms() {
    use crate::ip::{brief_addrs, brief_link, dev_counters, in_prefix, oneline, route_get};
    use crate::rtnl::{self, Addr, Link, Route};
    use slate_net::{IpAddr, Ipv4};
    let v4 = |a: [u8; 4]| IpAddr::V4(Ipv4(a));
    assert!(in_prefix(&v4([10, 0, 2, 7]), &v4([10, 0, 2, 0]), 24));
    assert!(!in_prefix(&v4([10, 0, 3, 7]), &v4([10, 0, 2, 0]), 24));
    assert!(in_prefix(&v4([10, 0, 2, 129]), &v4([10, 0, 2, 128]), 25));
    assert!(!in_prefix(&v4([10, 0, 2, 127]), &v4([10, 0, 2, 128]), 25));
    let main = |dst: Option<IpAddr>, len: u8, gw: Option<IpAddr>, metric: Option<u32>| Route {
        family: rtnl::AF_INET,
        dst,
        dst_len: len,
        gateway: gw,
        oif: Some(2),
        metric,
        table: rtnl::RT_TABLE_MAIN,
        ..Default::default()
    };
    let routes = std::vec![
        main(None, 0, Some(v4([10, 0, 2, 2])), Some(100)),
        main(Some(v4([10, 0, 2, 0])), 24, None, Some(100)),
        main(Some(v4([10, 0, 2, 0])), 24, None, Some(50)),
    ];
    let addrs = std::vec![Addr {
        index: 2,
        prefix_len: 24,
        flags: 0,
        scope: 0,
        addr: v4([10, 0, 2, 15]),
        broadcast: None,
        label: std::string::String::new(),
        preferred: None,
        valid: None,
    }];
    let (r, src) = route_get(&routes, &addrs, &v4([10, 0, 2, 2])).unwrap();
    assert_eq!((r.dst_len, r.metric, src), (24, Some(50), Some(v4([10, 0, 2, 15]))));
    let (r, _) = route_get(&routes, &addrs, &v4([1, 1, 1, 1])).unwrap();
    assert_eq!(r.gateway, Some(v4([10, 0, 2, 2])));
    let lo = Link { index: 1, name: "lo".into(), flags: rtnl::IFF_LOOPBACK | 1, operstate: 0, ..Default::default() };
    assert!(
        brief_link(&lo).starts_with("lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP"),
        "{}",
        brief_link(&lo)
    );
    let a = &addrs[0];
    assert_eq!(brief_addrs(&lo, &[a]), "lo               UNKNOWN        10.0.2.15/24");
    assert_eq!(oneline("1: lo: <UP>", "    link/loopback"), "1: lo: <UP>\\    link/loopback");
    let dev = "Inter-|   Receive\n face |bytes\n  eth0:    1000      10    1    2    0     0          0         0     2000      20    3    4    0     0       0          0\n";
    assert_eq!(dev_counters(dev, "eth0"), Some(([1000, 10, 1, 2], [2000, 20, 3, 4])));
    assert_eq!(dev_counters(dev, "lo"), None);
}

#[test]
fn fetch_progress() {
    use crate::fetch::progress_line;
    assert_eq!(progress_line(512, Some(2048)), "fetch: 512 of 2048 bytes (25%)");
    assert_eq!(progress_line(512, None), "fetch: 512 bytes");
}

// --- slate-firewall (ADR 0134) --------------------------------------------------

#[test]
fn firewall_configuration() {
    use crate::firewall::{edit, parse};
    let text = "# Slate's firewall\nallow tcp 22   # sshd\n\nallow udp 5353\nallow tcp 22\n";
    assert_eq!(parse(text), Ok(alloc::vec![(true, 22), (false, 5353)]));
    assert!(parse("allow sctp 9\n").unwrap_err().contains("line 1"));
    assert!(parse("allow tcp 0\n").is_err());
    assert!(parse("open tcp 80\n").is_err());
    // Opening keeps the comments and adds what isn't there; closing drops
    // only the ports named.
    let opened = edit(text, true, true, &[22, 8080]);
    assert!(opened.starts_with("# Slate's firewall\nallow tcp 22   # sshd\n"));
    assert!(opened.ends_with("allow tcp 8080\n"));
    assert_eq!(opened.matches("allow tcp 8080").count(), 1);
    let closed = edit(&opened, false, true, &[22]);
    assert_eq!(parse(&closed), Ok(alloc::vec![(false, 5353), (true, 8080)]));
    assert!(closed.contains("# Slate's firewall"));
}
