// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sound cards with ALSA's kernel interface (ADR 0184).
//!
//! A driver ([`hda`], USB audio) builds a [`Card`]: its PCM devices, each
//! with a playback and/or a capture [`pcm::Substream`] the driver runs
//! through [`pcm::PcmOps`], and its controls ([`control::Elem`]). The
//! core gives each card `/dev/snd/controlCn` and `/dev/snd/pcmCnDd[pc]`,
//! `/sys/class/sound` entries with uevents (laid out as on Linux,
//! observed on the host), and `/proc/asound`. alsa-lib, and PipeWire on
//! it, then work as on Linux. Numbers and layouts are `slate_alsa::abi`.

pub mod control;
pub mod hda;
pub mod pcm;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};

use slate_alsa::abi::{MINOR_CAPTURE, MINOR_PLAYBACK, MINORS_PER_CARD, SOUND_MAJOR, STREAM_CAPTURE, STREAM_PLAYBACK};

use crate::abi::linux::errno::*;
use crate::fs::vfs::{self, Result};
use crate::fs::{CharNode, File, SysEntry};
use crate::sync::IrqSpinLock;

/// Cards Slate takes (devices.txt's numbering leaves room for 8).
const MAX_CARDS: u32 = 8;

/// A PCM device of a card: its playback and capture streams.
pub struct Pcm {
    pub device: u32,
    /// alsa-lib's `id` and `name` (the codec's or the device's name).
    pub id: String,
    pub name: String,
    pub playback: Option<Arc<pcm::Substream>>,
    pub capture: Option<Arc<pcm::Substream>>,
}

impl Pcm {
    pub fn stream(&self, dir: u32) -> Option<&Arc<pcm::Substream>> {
        match dir {
            STREAM_PLAYBACK => self.playback.as_ref(),
            STREAM_CAPTURE => self.capture.as_ref(),
            _ => None,
        }
    }
}

/// A sound card.
pub struct Card {
    pub index: u32,
    /// Short id (`hw:CARD=id`), driver, names, as `snd_ctl_card_info`.
    pub id: String,
    pub driver: String,
    pub name: String,
    pub longname: String,
    pub mixername: String,
    pub components: String,
    /// The device it belongs to in /sys ("devices/pci0000:00/0000:00:04.0").
    pub parent: String,
    pub pcms: Vec<Pcm>,
    pub controls: Vec<Arc<control::Elem>>,
    pub(crate) clients: IrqSpinLock<Vec<alloc::sync::Weak<control::Client>>>,
    pub gone: AtomicBool,
}

/// What a driver fills in; [`register`] makes it a card.
pub struct NewCard {
    pub id: String,
    pub driver: String,
    pub name: String,
    pub longname: String,
    pub mixername: String,
    pub components: String,
    pub parent: String,
    pub pcms: Vec<Pcm>,
    pub controls: Vec<Arc<control::Elem>>,
}

static CARDS: IrqSpinLock<Vec<Arc<Card>>> = IrqSpinLock::new(Vec::new());

/// The card with number `index`, if it is there.
pub fn card(index: u32) -> Option<Arc<Card>> {
    CARDS.lock().iter().find(|c| c.index == index).cloned()
}

pub fn cards() -> Vec<Arc<Card>> {
    CARDS.lock().clone()
}

/// A short id no other card has: `base`, else `base_1`, `base_2`...
fn unique_id(base: &str, taken: &[Arc<Card>]) -> String {
    let mut base: String = base.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(15).collect();
    if base.is_empty() {
        base = "Card".into();
    }
    let mut id = base.clone();
    let mut n = 1;
    while taken.iter().any(|c| c.id == id) {
        id = format!("{}_{n}", &base[..base.len().min(12)]);
        n += 1;
    }
    id
}

/// Add a card: its /dev nodes, /sys entries and uevents. None if there
/// are already as many cards as numbers.
pub fn register(new: NewCard) -> Option<Arc<Card>> {
    let card = {
        let mut all = CARDS.lock();
        let index = (0..MAX_CARDS).find(|i| !all.iter().any(|c| c.index == *i))?;
        let id = unique_id(&new.id, &all);
        let card = Arc::new(Card {
            index,
            id,
            driver: new.driver,
            name: new.name,
            longname: new.longname,
            mixername: new.mixername,
            components: new.components,
            parent: new.parent,
            pcms: new.pcms,
            controls: new.controls,
            clients: IrqSpinLock::new(Vec::new()),
            gone: AtomicBool::new(false),
        });
        all.push(card.clone());
        card
    };
    for p in &card.pcms {
        for s in [&p.playback, &p.capture].into_iter().flatten() {
            s.attach(card.index);
        }
    }
    let streams: Vec<String> = card
        .pcms
        .iter()
        .flat_map(|p| {
            [(&p.playback, "playback"), (&p.capture, "capture")]
                .into_iter()
                .filter(|(s, _)| s.is_some())
                .map(move |(_, d)| format!("{} {d}", p.device))
        })
        .collect();
    crate::log_info!(
        "sound: card {} [{}]: {}; pcm {}; {} controls",
        card.index,
        card.id,
        card.longname,
        streams.join(", "),
        card.controls.len()
    );
    // The control device carries the card's own entries, so the card's
    // uevent comes first; then each PCM device.
    crate::fs::char_added(control_node(&card));
    for p in &card.pcms {
        for dir in [STREAM_PLAYBACK, STREAM_CAPTURE] {
            if p.stream(dir).is_some() {
                crate::fs::char_added(pcm_node(&card, p, dir));
            }
        }
    }
    Some(card)
}

/// A card went (a USB device unplugged): its streams are disconnected,
/// its nodes and /sys entries go.
pub fn unregister(card: &Arc<Card>) {
    card.gone.store(true, Ordering::Release);
    CARDS.lock().retain(|c| !Arc::ptr_eq(c, card));
    for p in &card.pcms {
        for dir in [STREAM_PLAYBACK, STREAM_CAPTURE] {
            if let Some(s) = p.stream(dir) {
                s.disconnect();
                crate::fs::char_removed(&format!("snd/{}", pcm_name(card.index, p.device, dir)));
            }
        }
    }
    control::disconnect(card);
    crate::fs::char_removed(&format!("snd/controlC{}", card.index));
    crate::log_info!("sound: card {} [{}] gone", card.index, card.id);
}

fn pcm_name(card: u32, device: u32, dir: u32) -> String {
    format!("pcmC{card}D{device}{}", if dir == STREAM_PLAYBACK { 'p' } else { 'c' })
}

fn pcm_minor(card: u32, device: u32, dir: u32) -> u32 {
    card * MINORS_PER_CARD + if dir == STREAM_PLAYBACK { MINOR_PLAYBACK } else { MINOR_CAPTURE } + device
}

/// The card's directory in /sys.
fn card_dir(card: &Card) -> String {
    format!("{}/sound/card{}", card.parent, card.index)
}

/// `../` back to /sys from `p`.
fn up(p: &str) -> String {
    "../".repeat(p.split('/').count())
}

/// /dev/snd/controlCn, with the card's own /sys entries (as on Linux:
/// `card0` under its device, `id`, `number`, a uevent without a device
/// number; `controlC0` in it).
fn control_node(card: &Card) -> CharNode {
    let dir = card_dir(card);
    let ctl = format!("{dir}/controlC{}", card.index);
    let minor = card.index * MINORS_PER_CARD;
    let sys = alloc::vec![
        SysEntry::Dir(dir.clone()),
        SysEntry::File(format!("{dir}/id"), format!("{}\n", card.id)),
        SysEntry::File(format!("{dir}/number"), format!("{}\n", card.index)),
        SysEntry::File(format!("{dir}/uevent"), String::new()),
        SysEntry::Link(format!("{dir}/subsystem"), format!("{}class/sound", up(&dir))),
        SysEntry::Link(format!("{dir}/device"), String::from("../..")),
        SysEntry::Link(format!("class/sound/card{}", card.index), format!("../../{dir}")),
        SysEntry::File(format!("{ctl}/dev"), format!("{SOUND_MAJOR}:{minor}\n")),
        SysEntry::File(
            format!("{ctl}/uevent"),
            format!("MAJOR={SOUND_MAJOR}\nMINOR={minor}\nDEVNAME=snd/controlC{}\n", card.index),
        ),
        SysEntry::Link(format!("{ctl}/subsystem"), format!("{}class/sound", up(&ctl))),
        SysEntry::Link(format!("{ctl}/device"), String::from("..")),
        SysEntry::Link(format!("class/sound/controlC{}", card.index), format!("../../{ctl}")),
        SysEntry::Link(format!("dev/char/{SOUND_MAJOR}:{minor}"), format!("../../{ctl}")),
        SysEntry::Dir(String::from("class/sound")),
    ];
    CharNode { dev: format!("snd/controlC{}", card.index), rdev: vfs::makedev(SOUND_MAJOR, minor), mode: 0o660, sys }
}

/// /dev/snd/pcmCnDd[pc] and its /sys entries.
fn pcm_node(card: &Card, p: &Pcm, dir: u32) -> CharNode {
    let name = pcm_name(card.index, p.device, dir);
    let path = format!("{}/{name}", card_dir(card));
    let minor = pcm_minor(card.index, p.device, dir);
    let sys = alloc::vec![
        SysEntry::File(format!("{path}/dev"), format!("{SOUND_MAJOR}:{minor}\n")),
        SysEntry::File(format!("{path}/pcm_class"), String::from("generic\n")),
        SysEntry::File(
            format!("{path}/uevent"),
            format!("MAJOR={SOUND_MAJOR}\nMINOR={minor}\nDEVNAME=snd/{name}\nDEVTYPE=pcm\n"),
        ),
        SysEntry::Link(format!("{path}/subsystem"), format!("{}class/sound", up(&path))),
        SysEntry::Link(format!("{path}/device"), String::from("..")),
        SysEntry::Link(format!("class/sound/{name}"), format!("../../{path}")),
        SysEntry::Link(format!("dev/char/{SOUND_MAJOR}:{minor}"), format!("../../{path}")),
    ];
    CharNode { dev: format!("snd/{name}"), rdev: vfs::makedev(SOUND_MAJOR, minor), mode: 0o660, sys }
}

/// Open /dev/snd's node `minor` (character major 116).
pub fn open(minor: u32, flags: u32) -> Result<Arc<dyn File>> {
    let card = card(minor / MINORS_PER_CARD).ok_or(ENODEV)?;
    let sub = minor % MINORS_PER_CARD;
    if sub == 0 {
        return control::open(card, flags);
    }
    let (dir, device) = match sub {
        s if (MINOR_PLAYBACK..MINOR_CAPTURE).contains(&s) => (STREAM_PLAYBACK, s - MINOR_PLAYBACK),
        s if s >= MINOR_CAPTURE => (STREAM_CAPTURE, s - MINOR_CAPTURE),
        _ => return Err(ENODEV),
    };
    let s = card.pcms.iter().find(|p| p.device == device).and_then(|p| p.stream(dir)).cloned().ok_or(ENODEV)?;
    pcm::open(s, flags)
}

/// What /proc/asound holds at `path` ("", "cards", "card0/pcm0p/info"):
/// a directory's entries (name, is it a directory) or a file's text.
pub enum ProcEntry {
    Dir(Vec<(String, bool)>),
    File(String),
}

/// /proc/asound, laid out as Linux's (observed on the host).
pub fn proc_entry(path: &str) -> Option<ProcEntry> {
    let cards = cards();
    let parts: Vec<&str> = if path.is_empty() { Vec::new() } else { path.split('/').collect() };
    match parts.as_slice() {
        [] => {
            let mut e: Vec<(String, bool)> =
                ["cards", "devices", "pcm", "version"].iter().map(|n| (String::from(*n), false)).collect();
            for c in &cards {
                e.push((format!("card{}", c.index), true));
                // Linux also has a link named after each card's id.
                e.push((c.id.clone(), true));
            }
            Some(ProcEntry::Dir(e))
        }
        ["version"] => Some(ProcEntry::File(String::from("Advanced Linux Sound Architecture Driver Version k7.2.\n"))),
        ["cards"] => {
            let mut s = String::new();
            for c in &cards {
                let _ = writeln!(s, "{:2} [{:<15}]: {} - {}", c.index, c.id, c.driver, c.name);
                let _ = writeln!(s, "{:22}{}", "", c.longname);
            }
            if cards.is_empty() {
                s.push_str("--- no soundcards ---\n");
            }
            Some(ProcEntry::File(s))
        }
        ["pcm"] => {
            let mut s = String::new();
            for c in &cards {
                for p in &c.pcms {
                    let _ = write!(s, "{:02}-{:02}: {} : {}", c.index, p.device, p.id, p.name);
                    if p.playback.is_some() {
                        s.push_str(" : playback 1");
                    }
                    if p.capture.is_some() {
                        s.push_str(" : capture 1");
                    }
                    s.push('\n');
                }
            }
            Some(ProcEntry::File(s))
        }
        ["devices"] => {
            let mut s = String::new();
            for c in &cards {
                for p in &c.pcms {
                    for (dir, what) in [(STREAM_PLAYBACK, "playback"), (STREAM_CAPTURE, "capture")] {
                        if p.stream(dir).is_some() {
                            let m = pcm_minor(c.index, p.device, dir);
                            let _ = writeln!(s, "{m:3}: [{:2}-{:2}]: digital audio {what}", c.index, p.device);
                        }
                    }
                }
                let _ = writeln!(s, "{:3}: [{:2}]   : control", c.index * MINORS_PER_CARD, c.index);
            }
            Some(ProcEntry::File(s))
        }
        [card_name, rest @ ..] => {
            let c = cards.iter().find(|c| format!("card{}", c.index) == *card_name || c.id == *card_name)?;
            card_proc(c, rest)
        }
    }
}

fn card_proc(c: &Card, rest: &[&str]) -> Option<ProcEntry> {
    let pcm_dirs = || {
        c.pcms.iter().flat_map(|p| {
            [(STREAM_PLAYBACK, 'p'), (STREAM_CAPTURE, 'c')]
                .into_iter()
                .filter(|(d, _)| p.stream(*d).is_some())
                .map(move |(d, ch)| (format!("pcm{}{ch}", p.device), p, d))
        })
    };
    match rest {
        [] => {
            let mut e = alloc::vec![(String::from("id"), false)];
            e.extend(pcm_dirs().map(|(n, ..)| (n, true)));
            Some(ProcEntry::Dir(e))
        }
        ["id"] => Some(ProcEntry::File(format!("{}\n", c.id))),
        [dir, more @ ..] => {
            let (_, p, d) = pcm_dirs().find(|(n, ..)| n == dir)?;
            let s = p.stream(d)?;
            match more {
                [] => Some(ProcEntry::Dir(alloc::vec![(String::from("info"), false), (String::from("sub0"), true)])),
                ["info"] | ["sub0", "info"] => Some(ProcEntry::File(s.proc_info(c, p))),
                ["sub0"] => Some(ProcEntry::Dir(
                    ["info", "status", "hw_params", "sw_params"].iter().map(|n| (String::from(*n), false)).collect(),
                )),
                ["sub0", "status"] => Some(ProcEntry::File(s.proc_status())),
                ["sub0", "hw_params"] => Some(ProcEntry::File(s.proc_hw_params())),
                ["sub0", "sw_params"] => Some(ProcEntry::File(s.proc_sw_params())),
                _ => None,
            }
        }
    }
}

/// Log an ioctl nobody handles, once per number (CLAUDE.md: never fail
/// silently).
pub(crate) fn unknown_ioctl(what: &str, cmd: u32) -> Result<u64> {
    static SEEN: IrqSpinLock<Vec<u32>> = IrqSpinLock::new(Vec::new());
    let mut seen = SEEN.lock();
    if !seen.contains(&cmd) {
        seen.push(cmd);
        crate::log_warn!("sound: {what} ioctl {cmd:#010x} ({}) is not supported", ioctl_name(cmd));
    }
    Err(ENOTTY)
}

fn ioctl_name(cmd: u32) -> String {
    let ty = ((cmd >> 8) & 0xff) as u8;
    format!("'{}' {:#04x}, {} bytes", ty as char, cmd & 0xff, (cmd >> 16) & 0x3fff)
}
