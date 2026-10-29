// SPDX-License-Identifier: MIT OR Apache-2.0

//! `slate-network [show]` and `slate-network CARD dhcp|off|static
//! ADDR/PREFIX [gateway ADDR] [dns SERVER...] [address6 ADDR/PREFIX]
//! [gateway6 ADDR]` (ADR 0054): the network settings from the command
//! line, the same ones the installer and Settings change. `show` lists
//! /etc/slate/network's sections and what netd has now. A change replaces
//! that card's section (`*` for every card not named) and restarts netd:
//! as root directly, otherwise through slate-brokerd's `network=` action,
//! which asks for approval.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_netconf::{Card, Network};
use slate_rt::{eprintln, fs, lossy, println, process};

const NETWORK: &[u8] = b"/etc/slate/network";
const STATUS: &[u8] = b"/run/netd/status";
const USAGE: &str = "usage: slate-network [show]\n       slate-network CARD dhcp|off|static ADDR/PREFIX [gateway ADDR] \
                     [dns SERVER...] [address6 ADDR/PREFIX] [gateway6 ADDR]";

/// What `show` prints: the settings, then netd's status.
pub fn show(settings: &str, status: &str) -> Vec<String> {
    let (net, _) = Network::parse(settings);
    let mut out = alloc::vec![String::from("Settings (/etc/slate/network):")];
    let width = net.cards().iter().map(|c| c.name.len()).max().unwrap_or(0);
    for c in net.cards() {
        let w = c.words();
        out.push(format!("  {:<width$}  {}", c.name, w[1..].join(" ")));
    }
    if net.cards().is_empty() {
        out.push("  (none: every card uses DHCP)".into());
    }
    out.push("Now (/run/netd/status):".into());
    let lines: Vec<&str> = status.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.is_empty() {
        out.push("  (netd is not running)".into());
    }
    out.extend(lines.iter().map(|l| format!("  {l}")));
    out
}

fn run(argv: &[&str]) -> Result<(), String> {
    let argv: Vec<Vec<u8>> = argv.iter().map(|a| a.as_bytes().to_vec()).collect();
    let env = [b"PATH=/bin:/sbin:/usr/bin:/usr/sbin".to_vec()];
    match process::fork() {
        Ok(0) => {
            let e = process::execve(&argv[0], &argv, &env);
            eprintln!("slate-network: {}: {e}", lossy(&argv[0]));
            process::exit_now(127)
        }
        Ok(child) => match process::wait(child, 0) {
            Ok((_, 0)) => Ok(()),
            _ => Err(format!("{} failed", lossy(&argv[0]))),
        },
        Err(e) => Err(format!("{e}")),
    }
}

fn change(card: &Card) -> Result<(), String> {
    let words = card.words().join(" ");
    if process::geteuid() != 0 {
        // Through the broker, which asks for approval (ADR 0054).
        return run(&["/bin/slate-approve", &format!("network={words}")]);
    }
    let old = fs::read_file(NETWORK).map(|t| String::from(lossy(&t))).unwrap_or_default();
    let text = slate_netconf::set_card(&old, card);
    let mut tmp = NETWORK.to_vec();
    tmp.extend_from_slice(b".new");
    fs::write_file(&tmp, text.as_bytes(), 0o644).map_err(|e| format!("/etc/slate/network: {e}"))?;
    fs::rename(&tmp, NETWORK).map_err(|e| format!("/etc/slate/network: {e}"))?;
    run(&["/bin/service", "netd", "restart"])
}

pub fn main() -> i32 {
    let owned: Vec<String> = slate_rt::env::args().iter().skip(1).map(|a| String::from(lossy(a))).collect();
    let args: Vec<&str> = owned.iter().map(String::as_str).collect();
    match args.as_slice() {
        [] | ["show"] => {
            let read = |p: &[u8]| fs::read_file(p).map(|t| String::from(lossy(&t))).unwrap_or_default();
            for l in show(&read(NETWORK), &read(STATUS)) {
                println!("{l}");
            }
            0
        }
        ["-h" | "--help" | "help"] => {
            println!("{USAGE}");
            0
        }
        words => {
            let words = if words[0] == "set" { &words[1..] } else { words };
            let card = match Card::from_words(words) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("slate-network: {}\n{USAGE}", e.0);
                    return 2;
                }
            };
            match change(&card) {
                Ok(()) => {
                    println!("slate-network: {}: {}", card.name, card.words()[1..].join(" "));
                    0
                }
                Err(e) => {
                    eprintln!("slate-network: {e}");
                    1
                }
            }
        }
    }
}
