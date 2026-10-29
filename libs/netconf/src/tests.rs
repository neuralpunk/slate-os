// SPDX-License-Identifier: MIT OR Apache-2.0

use alloc::string::String;
use alloc::vec::Vec;

use slate_net::{Ipv4, Ipv6};

use crate::{Card, FieldErrors, Method, Network, Server, Six, boot_override, fixed, remove_card, set_card};

fn card(words: &str) -> Card {
    Card::from_words(&words.split_whitespace().collect::<Vec<_>>()).unwrap()
}

#[test]
fn words_both_ways() {
    let c = card("eth0 static 192.168.1.20/24 gateway 192.168.1.1 dns 9.9.9.9,1.1.1.1 [fec0::2]:5353");
    assert_eq!(
        c,
        Card {
            name: "eth0".into(),
            method: Method::Static {
                addr: Ipv4([192, 168, 1, 20]),
                prefix_len: 24,
                gateway: Some(Ipv4([192, 168, 1, 1]))
            },
            six: Six::default(),
            dns: std::vec![
                Server::new(Ipv4([9, 9, 9, 9])),
                Server::new(Ipv4([1, 1, 1, 1])),
                Server::parse("[fec0::2]:5353").unwrap()
            ],
        }
    );
    assert_eq!(
        c.words().join(" "),
        "eth0 static 192.168.1.20/24 gateway 192.168.1.1 dns 9.9.9.9 1.1.1.1 [fec0::2]:5353"
    );
    let six = card("* dhcp address6 fec1::20/64 gateway6 fec1::2 dns fec1::3");
    assert_eq!(six.six.address, Some((Ipv6::parse("fec1::20").unwrap(), 64)));
    assert_eq!(card(&six.words().join(" ")), six);
    assert_eq!(card("eth1 off").method, Method::Off);
    for bad in [
        "",
        "eth0",
        "eth0 static",
        "eth0 static 10.0.0.1",
        "eth0 dhcp dns",
        "eth0 dhcp color blue",
        "a b dhcp",
        "e[0] dhcp",
    ] {
        assert!(Card::from_words(&bad.split_whitespace().collect::<Vec<_>>()).is_err(), "{bad:?}");
    }
}

#[test]
fn sections_written_and_read_back() {
    let c = card("eth1 static 10.0.3.20/24 gateway 10.0.3.2 dns 10.0.3.3 address6 fec1::20/64 gateway6 fec1::2");
    let (net, problems) = Network::parse(&c.section());
    assert!(problems.is_empty());
    assert_eq!(net.cards(), core::slice::from_ref(&c));
    assert_eq!(net.method("eth1"), c.method);
}

#[test]
fn one_section_changed() {
    let text = "# Network settings\n#   [eth0] ...\n[*]\nmethod = dhcp\n\n# The wired card\n[eth0]\nmethod = dhcp\n# old\ndns = 1.2.3.4\n[eth1]\nmethod = off\n";
    let new = set_card(text, &card("eth0 static 10.0.0.5/24 gateway 10.0.0.1"));
    assert_eq!(
        new,
        "# Network settings\n#   [eth0] ...\n[*]\nmethod = dhcp\n\n# The wired card\n[eth0]\nmethod = static\n\
         address = 10.0.0.5/24\ngateway = 10.0.0.1\n# old\n[eth1]\nmethod = off\n"
    );
    let (net, _) = Network::parse(&new);
    assert_eq!(net.dns("eth0"), std::vec![]);
    assert_eq!(net.method("eth1"), Method::Off);
    // A card without a section gets one at the end.
    let added = set_card("[*]\nmethod = dhcp\n", &card("wlan0 off"));
    assert_eq!(added, "[*]\nmethod = dhcp\n\n[wlan0]\nmethod = off\n");
    assert_eq!(set_card("", &card("eth0 dhcp")), String::from("[eth0]\nmethod = dhcp\n"));
}

#[test]
fn fields_of_a_fixed_address() {
    let c = fixed("*", " 192.168.1.20/24 ", "192.168.1.1", "9.9.9.9, 1.1.1.1").unwrap();
    assert_eq!(c.words().join(" "), "* static 192.168.1.20/24 gateway 192.168.1.1 dns 9.9.9.9 1.1.1.1");
    assert_eq!(fixed("eth0", "10.0.0.5/8", "", "").unwrap().words().join(" "), "eth0 static 10.0.0.5/8");
    let e = fixed("*", "192.168.1.20", "192.168.1", "x").unwrap_err();
    assert!(e.address.is_some() && e.gateway.is_some() && e.dns.is_some());
    assert_eq!(fixed("*", "10.0.0.1/24", "", "").map(|_| ()), Ok::<(), FieldErrors>(()));
}

#[test]
fn boot_override_from_the_command_line() {
    let o = boot_override("slate.live quiet slate.ip=192.168.1.201/24,192.168.1.1,8.8.8.8,9.9.9.9").unwrap();
    assert_eq!(o.card, None);
    assert_eq!(
        o.method,
        Method::Static { addr: Ipv4([192, 168, 1, 201]), prefix_len: 24, gateway: Some(Ipv4([192, 168, 1, 1])) }
    );
    assert_eq!(o.dns, alloc::vec![Server::new(Ipv4([8, 8, 8, 8])), Server::new(Ipv4([9, 9, 9, 9]))]);
    let named = boot_override("slate.net=eth1 slate.ip=10.0.0.5/8").unwrap();
    assert_eq!(named.card.as_deref(), Some("eth1"));
    assert_eq!(named.method, Method::Static { addr: Ipv4([10, 0, 0, 5]), prefix_len: 8, gateway: None });
    assert!(named.dns.is_empty());
    // Nothing, or nothing usable: the file decides.
    assert_eq!(boot_override("quiet slate.net=eth0"), None);
    assert_eq!(boot_override("slate.ip=192.168.1.201"), None);
    assert_eq!(boot_override("slate.ip=192.168.1.201/24,nope"), None);
}

#[test]
fn a_card_back_to_every_card() {
    let text =
        "# cards\n[*]\nmethod = dhcp\n\n[eth1]\nmethod = static\naddress = 10.0.0.2/24\n\n[eth2]\nmethod = off\n";
    let out = remove_card(text, "eth1");
    assert_eq!(out, "# cards\n[*]\nmethod = dhcp\n\n\n[eth2]\nmethod = off\n");
    let (net, problems) = Network::parse(&out);
    assert!(problems.is_empty());
    assert_eq!(net.cards().iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["*", "eth2"]);
    assert_eq!(remove_card(text, "eth9"), text);
}
