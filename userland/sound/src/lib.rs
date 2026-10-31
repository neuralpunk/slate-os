// SPDX-License-Identifier: MIT OR Apache-2.0

//! `slate-sound` (ADR 0184): the sound cards Slate found, and the
//! self-test Settings › Sound plays: a short, soft music-box phrase (a
//! falling G major arpeggio that settles on a chord), made here, played
//! straight through ALSA's kernel interface (`slate_alsa`'s numbers).
//!
//! ```text
//! slate-sound              the sound cards
//! slate-sound test [CARD]  play the test tune (card 0 if none is named)
//! slate-sound volume [-c CARD] [PERCENT|up|down|mute|unmute|toggle]
//!                          a card's playback volume (the first's): say it, or set it
//! ```
//!
//! Exit status: 0 played, 1 failed, 2 the card is in use, 3 no such card.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod mixer;
pub mod play;
pub mod tune;

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{eprintln, println};

/// A sound card, as /proc/asound/cards lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Card {
    pub index: u32,
    pub id: String,
    pub driver: String,
    pub name: String,
    pub longname: String,
}

/// Read /proc/asound/cards' text: ` 0 [Intel          ]: HDA-Intel - HDA
/// Intel`, then the long name on the next line.
pub fn parse_cards(text: &str) -> Vec<Card> {
    let mut out: Vec<Card> = Vec::new();
    for line in text.lines() {
        let t = line.trim_start();
        let head = t.split_once(' ').and_then(|(n, rest)| Some((n.parse::<u32>().ok()?, rest)));
        if let Some((index, rest)) = head
            && let Some(rest) = rest.trim_start().strip_prefix('[')
            && let Some((id, rest)) = rest.split_once(']')
        {
            let rest = rest.trim_start_matches(':').trim();
            let (driver, name) = rest.split_once(" - ").unwrap_or((rest, rest));
            out.push(Card {
                index,
                id: String::from(id.trim()),
                driver: String::from(driver.trim()),
                name: String::from(name.trim()),
                longname: String::new(),
            });
        } else if let Some(last) = out.last_mut()
            && last.longname.is_empty()
            && !t.is_empty()
        {
            last.longname = String::from(t);
        }
    }
    out
}

/// The cards there are now.
pub fn cards() -> Vec<Card> {
    let text = slate_rt::fs::read_file(b"/proc/asound/cards").unwrap_or_default();
    parse_cards(&String::from(slate_rt::lossy(&text)))
}

pub fn main() -> i32 {
    let args: Vec<String> = slate_rt::env::args().iter().skip(1).map(|a| String::from(slate_rt::lossy(a))).collect();
    match args.first().map(String::as_str) {
        None => {
            let cards = cards();
            if cards.is_empty() {
                println!("No sound cards.");
            }
            for c in cards {
                println!("{}: {} ({}, {})", c.index, c.name, c.id, c.longname);
            }
            0
        }
        Some("test") => {
            let index: u32 = match args.get(1).map(|a| a.parse()) {
                None => 0,
                Some(Ok(n)) => n,
                Some(Err(_)) => {
                    eprintln!("slate-sound: not a card number: {}", args[1]);
                    return 1;
                }
            };
            let Some(card) = cards().into_iter().find(|c| c.index == index) else {
                eprintln!("slate-sound: there is no sound card {index}");
                return 3;
            };
            match play::tune(index) {
                Ok(rate) => {
                    println!("slate-sound: played the test tune on card {index}, {} ({rate} Hz)", card.name);
                    0
                }
                Err(play::Failure::Busy) => {
                    eprintln!("slate-sound: card {index} is in use by another program");
                    2
                }
                Err(play::Failure::Other(e)) => {
                    eprintln!("slate-sound: card {index}: {e}");
                    1
                }
            }
        }
        Some("volume") => volume(&args[1..]),
        Some("--help" | "-h") => {
            println!("usage: slate-sound            the sound cards");
            println!("       slate-sound test [CARD] play the test tune");
            println!("       slate-sound volume [-c CARD] [PERCENT|up|down|mute|unmute|toggle]");
            0
        }
        Some(other) => {
            eprintln!("slate-sound: unknown command {other} (slate-sound --help)");
            1
        }
    }
}

/// What `volume` is asked: a level, a step, or the switch.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Change {
    Say,
    Level(f32),
    Step(f32),
    Mute(Option<bool>),
}

/// `volume`'s change: "40" (or "40%"), "up", "down", "mute", "unmute",
/// "toggle"; None for anything else.
pub fn parse_change(word: Option<&str>) -> Option<Change> {
    Some(match word {
        None => Change::Say,
        Some("up") => Change::Step(0.05),
        Some("down") => Change::Step(-0.05),
        Some("mute") => Change::Mute(Some(true)),
        Some("unmute") => Change::Mute(Some(false)),
        Some("toggle") => Change::Mute(None),
        Some(w) => Change::Level(w.trim_end_matches('%').parse::<u32>().ok().filter(|p| *p <= 100)? as f32 / 100.0),
    })
}

/// Make `change` to card `card`'s volume: what it is after.
pub fn change(card: u32, change: Change) -> Result<mixer::Volume, String> {
    match change {
        Change::Say => mixer::get(card),
        Change::Level(l) => mixer::set(card, Some(l), None),
        Change::Step(d) => {
            let v = mixer::get(card)?;
            // Up from muted unmutes where it was.
            let base = if v.muted && d > 0.0 { v.level.max(0.0) } else { v.level };
            mixer::set(card, Some((base + d).clamp(0.0, 1.0)), (d > 0.0).then_some(false))
        }
        Change::Mute(m) => {
            let v = mixer::get(card)?;
            mixer::set(card, None, Some(m.unwrap_or(!v.muted)))
        }
    }
}

/// `slate-sound volume [-c CARD] [CHANGE]`.
fn volume(args: &[String]) -> i32 {
    // `-c CARD` names a card; the first one otherwise.
    let (card, rest) = match args {
        [flag, n, rest @ ..] if flag == "-c" => match n.parse::<u32>() {
            Ok(n) => (Some(n), rest),
            Err(_) => {
                eprintln!("slate-sound: not a card number: {n}");
                return 1;
            }
        },
        _ => (None, args),
    };
    let Some(card) = card.or_else(mixer::default_card) else {
        eprintln!("slate-sound: there is no sound card");
        return 3;
    };
    let Some(c) = parse_change(rest.first().map(String::as_str)) else {
        eprintln!("slate-sound: volume: a percentage, up, down, mute, unmute or toggle");
        return 1;
    };
    match change(card, c) {
        Ok(v) => {
            println!("card {card}: {} ({}%)", mixer::words(&v), mixer::percent(v.level));
            0
        }
        Err(e) => {
            eprintln!("slate-sound: card {card}: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_changes() {
        assert_eq!(parse_change(None), Some(Change::Say));
        assert_eq!(parse_change(Some("40")), Some(Change::Level(0.4)));
        assert_eq!(parse_change(Some("40%")), Some(Change::Level(0.4)));
        assert_eq!(parse_change(Some("140")), None);
        assert_eq!(parse_change(Some("up")), Some(Change::Step(0.05)));
        assert_eq!(parse_change(Some("toggle")), Some(Change::Mute(None)));
        assert_eq!(parse_change(Some("loud")), None);
    }

    #[test]
    fn cards_are_read() {
        let text = " 0 [Intel          ]: HDA-Intel - HDA Intel\n                      HDA Intel at 0x81044000\n 2 [Audio          ]: USB-Audio - QEMU USB Audio\n                      QEMU QEMU USB Audio at usb-5, full speed\n";
        let c = parse_cards(text);
        assert_eq!(c.len(), 2);
        assert_eq!((c[0].index, c[0].id.as_str(), c[0].driver.as_str()), (0, "Intel", "HDA-Intel"));
        assert_eq!((c[0].name.as_str(), c[0].longname.as_str()), ("HDA Intel", "HDA Intel at 0x81044000"));
        assert_eq!((c[1].index, c[1].name.as_str()), (2, "QEMU USB Audio"));
        assert!(parse_cards("--- no soundcards ---\n").is_empty());
    }
}
