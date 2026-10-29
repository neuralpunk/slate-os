// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-bt (ADR 0113): Bluetooth from the command line, through
//! slate-btd.
//!
//! ```text
//! slate-bt [status]            the controller and the devices
//! slate-bt power on|off
//! slate-bt name NAME           what others see this computer as
//! slate-bt scan                look for devices nearby (about ten seconds)
//! slate-bt pair ADDR           pair; numeric comparison asks here (y/n)
//! slate-bt connect ADDR        connect a paired device with its key
//! slate-bt confirm ADDR yes|no answer a pairing's question
//! slate-bt remove ADDR         forget a paired device
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{eprintln, print, println};

use crate::host::Prompt;
use crate::proto::{Snapshot, request};

const USAGE: &str = "usage: slate-bt [status | power on|off | name NAME | scan | pair ADDR | connect ADDR | confirm ADDR yes|no | remove ADDR]";

fn show(s: &Snapshot) {
    match s.state.as_str() {
        "none" => println!("no Bluetooth controller"),
        "failed" => println!("Bluetooth failed: {}", s.problem),
        st => match s.addr {
            Some(a) => println!("controller {a} \"{}\": {st}", s.name),
            None => println!("Bluetooth: {st}"),
        },
    }
    for d in &s.devices {
        let how = match (d.connected, d.paired) {
            (true, _) => "connected",
            (false, true) => "paired",
            _ => "nearby",
        };
        println!("{} {how:9} {:10} {}", d.addr, d.kind.word(), d.name);
    }
}

fn wait_ms(ms: u64) {
    slate_rt::time::sleep_ns(ms * 1_000_000);
}

/// Wait while `busy` holds, polling the state; the last state.
fn wait_while(busy: impl Fn(&Snapshot) -> bool, secs: u64) -> Result<Snapshot, String> {
    for _ in 0..secs * 4 {
        let s = request("status")?;
        if !busy(&s) {
            return Ok(s);
        }
        wait_ms(250);
    }
    request("status")
}

/// Ask on the terminal: y or n.
fn yes_or_no(question: &str) -> bool {
    print!("{question} [y/n] ");
    let mut b = [0u8; 16];
    let n = slate_rt::io::read(0, &mut b).unwrap_or(0);
    matches!(b[..n].first(), Some(b'y' | b'Y'))
}

fn pair(addr: &str) -> Result<(), String> {
    let s = request(&alloc::format!("pair {addr}"))?;
    let a = s.busy;
    let mut answered = false;
    for _ in 0..240 {
        let s = request("status")?;
        match s.prompt {
            Some(Prompt::Confirm(p, v)) if !answered => {
                answered = true;
                let yes = yes_or_no(&alloc::format!(
                    "Does {v:06} show on {}?",
                    s.device(p).map_or("the device", |d| &d.name)
                ));
                request(&alloc::format!("confirm {p} {}", if yes { "yes" } else { "no" }))?;
            }
            Some(Prompt::Pair(p)) if !answered => {
                answered = true;
                let yes = yes_or_no(&alloc::format!("Pair with {}?", s.device(p).map_or("the device", |d| &d.name)));
                request(&alloc::format!("confirm {p} {}", if yes { "yes" } else { "no" }))?;
            }
            Some(Prompt::Passkey(_, v)) if !answered => {
                answered = true;
                println!("Type {v:06} on the device, then Enter.");
            }
            _ => {}
        }
        if s.busy.is_none() || s.busy != a {
            return match s.said {
                Some((t, false)) => {
                    println!("{t}");
                    Ok(())
                }
                Some((t, true)) => Err(t),
                None => Ok(()),
            };
        }
        wait_ms(250);
    }
    Err("no answer in a minute".into())
}

fn run(args: &[String]) -> Result<(), String> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words[..] {
        [] | ["status"] => show(&request("status")?),
        ["power", on @ ("on" | "off")] => show(&request(&alloc::format!("power {on}"))?),
        ["name", ref name @ ..] if !name.is_empty() => show(&request(&alloc::format!("name {}", name.join(" ")))?),
        ["scan"] => {
            request("discover")?;
            wait_ms(300);
            show(&wait_while(|s| s.discovering, 30)?);
        }
        ["pair", a] => pair(a)?,
        ["connect", a] => {
            request(&alloc::format!("connect {a}"))?;
            let s = wait_while(|s| s.busy.is_some(), 30)?;
            match s.said {
                Some((t, true)) => return Err(t),
                Some((t, false)) => println!("{t}"),
                None => {}
            }
        }
        ["confirm", a, yn @ ("yes" | "no")] => show(&request(&alloc::format!("confirm {a} {yn}"))?),
        ["remove", a] => {
            let s = request(&alloc::format!("remove {a}"))?;
            if let Some((t, _)) = s.said {
                println!("{t}");
            }
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

pub fn main() -> i32 {
    let args: Vec<String> = slate_rt::env::args().iter().skip(1).map(|a| String::from(slate_rt::lossy(a))).collect();
    match run(&args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("slate-bt: {e}");
            1
        }
    }
}
