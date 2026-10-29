// SPDX-License-Identifier: MIT OR Apache-2.0

//! `lookup [-4|-6] [-s SERVER] NAME...`: a name's addresses, from DNS
//! (through netd's cache, or the server given: `ADDR`, `ADDR:PORT`,
//! `[ADDR]:PORT`), /etc/hosts, or the name itself if it is an address.
//! One line per address: `NAME has address A` or `NAME has IPv6 address
//! A`. Exits 1 if a name has none.

use alloc::string::String;
use alloc::vec::Vec;

use slate_net::IpAddr;
use slate_rt::{eprintln, println};

use crate::resolve::{self, Family};

/// The line for one address.
pub fn line(name: &str, a: &IpAddr) -> String {
    match a {
        IpAddr::V4(a) => alloc::format!("{name} has address {a}"),
        IpAddr::V6(a) => alloc::format!("{name} has IPv6 address {a}"),
    }
}

pub fn main() -> i32 {
    let args: Vec<String> = slate_rt::env::args().iter().skip(1).map(|a| String::from_utf8_lossy(a).into()).collect();
    let mut family = Family::Any;
    let mut server = None;
    let mut names = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-4" => family = Family::V4,
            "-6" => family = Family::V6,
            "-s" => {
                i += 1;
                match args.get(i).and_then(|s| resolve::server(s)) {
                    Some(s) => server = Some(s),
                    None => {
                        eprintln!("lookup: -s wants ADDR, ADDR:PORT or [ADDR]:PORT");
                        return 2;
                    }
                }
            }
            "-h" | "--help" => {
                println!("usage: lookup [-4|-6] [-s SERVER] NAME...");
                return 0;
            }
            n => names.push(String::from(n)),
        }
        i += 1;
    }
    if names.is_empty() {
        eprintln!("usage: lookup [-4|-6] [-s SERVER] NAME...");
        return 2;
    }
    let mut status = 0;
    for name in &names {
        let servers = server.map(|s| alloc::vec![s]);
        match resolve::resolve_with(name, family, servers.as_deref()) {
            Ok(addrs) => {
                for a in &addrs {
                    println!("{}", line(name, a));
                }
            }
            Err(e) => {
                eprintln!("lookup: {}", e.describe(name));
                status = 1;
            }
        }
    }
    status
}
