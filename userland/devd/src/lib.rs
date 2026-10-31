// SPDX-License-Identifier: MIT OR Apache-2.0

//! devd (ADR 0033, ADR 0012: ours): the device database that libudev
//! reads. libudev finds devices by walking sysfs, and reads what a device
//! manager learned about each one from `/run/udev/data/c<major>:<minor>`.
//! libinput takes only devices that have such an entry, and asks it what
//! kind of device each one is (`ID_INPUT_KEYBOARD`, `ID_INPUT_MOUSE`...).
//!
//! devd writes those entries: at start for the devices sysfs shows
//! (input event nodes and DRM cards), then as the kernel announces
//! devices on the uevent socket (netlink(7), group 1).
//!
//! The entry format is what the database files on a Linux host show
//! (observed, ADR 0003's difftest rule): `I:` the monotonic time the
//! device was set up, in microseconds; `E:KEY=value` properties; `G:` and
//! `Q:` tags; `V:1`. Tags are also empty files under
//! `/run/udev/tags/<tag>/`. The property names and meanings are libudev's
//! and libinput's documented ones.
//!
//! Re-announcing (ADR 0185): after recording a device the kernel
//! announced, devd tells libudev's monitors (WirePlumber, libinput) on
//! uevent group 2, as udevd does: a 40-byte header, then the properties.
//! The header's layout, observed from systemd-udevd on a Linux host (no
//! code read): `libudev\0`; the magic 0xfeedcafe, big-endian; the
//! header's size, the properties' offset and their length (native
//! order); MurmurHash2 (seed 0) of the subsystem and of the device type,
//! big-endian (0 without one); and a 64-bit bloom filter of the tags,
//! high word then low, big-endian, each tag setting the bits its hash
//! gives at bits 0, 6, 12 and 18 (six bits each). The properties: the
//! kernel's (DEVNAME as a /dev path), `USEC_INITIALIZED`, devd's own, and
//! `TAGS`/`CURRENT_TAGS`, each NUL-terminated. devd also keeps
//! `/run/udev/control`, a socket (0600, root's) as udevd's is on a Linux
//! host: libudev takes its presence to mean a device manager runs, and
//! without it gives no monitor any udev messages. devd takes no commands
//! on it (each connection is closed at once).
//!
//! Sound cards (ADR 0184): each card's entry (`+sound:cardN`, a device
//! without a node) says `SOUND_INITIALIZED=1` and its `ID_PATH`, which
//! PipeWire waits for before it opens a card; the card's nodes in
//! /dev/snd are tagged `seat` and given to the `seat` group (the people
//! who may use the desktop, ADR 0110), as udev's rules give them to the
//! seat's user on Linux.
//!
//! Block devices (`b<major>:<minor>`) get what the kernel found on them
//! (/sys/block's `slate_fs*`, ADR 0112) as udev's `ID_FS_TYPE`,
//! `ID_FS_LABEL`, `ID_FS_UUID` and `ID_FS_USAGE`, and their partition's
//! number and name. devd looks at /sys/block at start and after each
//! uevent (the kernel announces block devices since ADR 0185; a look a
//! minute catches anything else), and writes only the entries that
//! changed (ADR 0112's addendum).
//!
//! `devd monitor [SECONDS]` prints what the kernel announces, a line a
//! message (`KERNEL ACTION DEVPATH (SUBSYSTEM) DEVTYPE`), as `udevadm
//! monitor --kernel` does; anyone may run it.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{eprintln, fs, net, process};

// Event types, codes and properties: the numbers of `input-event-codes.h`
// (used as numeric facts only, ADR 0033).
const EV_KEY: u16 = 0x01;
const EV_REL: u16 = 0x02;
const EV_ABS: u16 = 0x03;
const EV_SW: u16 = 0x05;
const KEY_ESC: u16 = 1;
const KEY_ENTER: u16 = 28;
const KEY_A: u16 = 30;
const KEY_Z: u16 = 44;
const KEY_SPACE: u16 = 57;
const BTN_MISC: u16 = 0x100;
const BTN_LEFT: u16 = 0x110;
const BTN_JOYSTICK: u16 = 0x120;
const BTN_GAMEPAD: u16 = 0x130;
const BTN_TOOL_PEN: u16 = 0x140;
const BTN_TOOL_FINGER: u16 = 0x145;
const BTN_TOUCH: u16 = 0x14a;
const BTN_STYLUS: u16 = 0x14b;
/// KEY_OK: the first key code after the button range.
const KEY_OK: u16 = 0x160;
const KEY_MAX: u16 = 0x2ff;
const REL_X: u16 = 0x00;
const REL_Y: u16 = 0x01;
const ABS_X: u16 = 0x00;
const ABS_Y: u16 = 0x01;
const INPUT_PROP_ACCELEROMETER: u16 = 0x06;

/// Character device majors (devices.txt): input, DRM, sound.
const INPUT_MAJOR: u32 = 13;
const DRM_MAJOR: u32 = 226;
const SOUND_MAJOR: u32 = 116;
/// The kernel's multicast group on the uevent socket.
const KERNEL_GROUP: u32 = 1;

const RUN: &[u8] = b"/run/udev";
const DATA: &[u8] = b"/run/udev/data";
const TAGS: &[u8] = b"/run/udev/tags";

/// `KEY=value` pairs of a device's environment.
pub type Env = Vec<(String, String)>;

/// A sysfs capability bitmap: hexadecimal words, most significant first.
#[derive(Debug, Default)]
pub struct Bits(Vec<u64>);

impl Bits {
    pub fn parse(s: &str) -> Bits {
        let mut w: Vec<u64> = s.split_whitespace().map(|x| u64::from_str_radix(x, 16).unwrap_or(0)).collect();
        w.reverse();
        Bits(w)
    }

    pub fn has(&self, bit: u16) -> bool {
        self.0.get(usize::from(bit / 64)).is_some_and(|w| w & (1 << (bit % 64)) != 0)
    }

    fn any(&self, from: u16, to: u16) -> bool {
        (from..=to).any(|b| self.has(b))
    }
}

/// An input device's capabilities, from its sysfs directory.
#[derive(Debug, Default)]
pub struct InputCaps {
    pub ev: Bits,
    pub key: Bits,
    pub rel: Bits,
    pub abs: Bits,
    pub prop: Bits,
}

/// What kind of input device it is, as libudev's `ID_INPUT_*`
/// properties say.
pub fn input_properties(c: &InputCaps) -> Env {
    let mut kinds: Vec<&str> = Vec::new();
    if c.prop.has(INPUT_PROP_ACCELEROMETER) {
        kinds.push("ID_INPUT_ACCELEROMETER");
    } else {
        let keys = c.ev.has(EV_KEY);
        if keys && c.key.any(1, BTN_MISC - 1) || keys && c.key.any(KEY_OK, KEY_MAX) {
            kinds.push("ID_INPUT_KEY");
        }
        if keys && [KEY_ESC, KEY_ENTER, KEY_A, KEY_Z, KEY_SPACE].iter().all(|&k| c.key.has(k)) {
            kinds.push("ID_INPUT_KEYBOARD");
        }
        if c.ev.has(EV_REL) && c.rel.has(REL_X) && c.rel.has(REL_Y) && c.key.has(BTN_LEFT) {
            kinds.push("ID_INPUT_MOUSE");
        }
        if c.ev.has(EV_ABS) && c.abs.has(ABS_X) && c.abs.has(ABS_Y) {
            if c.key.has(BTN_TOOL_PEN) || c.key.has(BTN_STYLUS) {
                kinds.push("ID_INPUT_TABLET");
            } else if c.key.has(BTN_TOUCH) && c.key.has(BTN_TOOL_FINGER) {
                kinds.push("ID_INPUT_TOUCHPAD");
            } else if c.key.has(BTN_TOUCH) {
                kinds.push("ID_INPUT_TOUCHSCREEN");
            } else if c.key.has(BTN_LEFT) {
                // An absolute pointer with buttons (QEMU's tablet, KVM
                // switches): a mouse to libinput.
                kinds.push("ID_INPUT_MOUSE");
            } else if c.key.any(BTN_JOYSTICK, BTN_GAMEPAD + 0x0f) {
                kinds.push("ID_INPUT_JOYSTICK");
            }
        }
        if c.ev.has(EV_SW) {
            kinds.push("ID_INPUT_SWITCH");
        }
    }
    let mut props = alloc::vec![(String::from("ID_INPUT"), String::from("1"))];
    kinds.dedup();
    props.extend(kinds.into_iter().map(|k| (String::from(k), String::from("1"))));
    props
}

/// `KEY=value` lines (a sysfs uevent file).
pub fn parse_env(text: &str) -> Env {
    text.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (String::from(k), String::from(v))).collect()
}

fn get<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
    env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// A kernel uevent message: "ACTION@DEVPATH" and NUL-separated
/// `KEY=value` pairs. Returns (action, devpath, environment).
pub fn parse_message(msg: &[u8]) -> Option<(String, String, Env)> {
    let mut parts = msg.split(|&b| b == 0).filter(|p| !p.is_empty());
    let head = core::str::from_utf8(parts.next()?).ok()?;
    let (action, devpath) = head.split_once('@')?;
    let env = parts
        .filter_map(|p| core::str::from_utf8(p).ok())
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (String::from(k), String::from(v)))
        .collect();
    Some((String::from(action), String::from(devpath), env))
}

/// MurmurHash2 with seed 0 (Austin Appleby's published algorithm), as
/// libudev's monitor filters hash subsystems, device types and tags.
pub fn murmur2(data: &[u8]) -> u32 {
    const M: u32 = 0x5bd1_e995;
    let mut h = data.len() as u32;
    let (chunks, rest) = data.as_chunks::<4>();
    for c in chunks {
        let mut k = u32::from_le_bytes(*c);
        k = k.wrapping_mul(M);
        k ^= k >> 24;
        k = k.wrapping_mul(M);
        h = h.wrapping_mul(M) ^ k;
    }
    if !rest.is_empty() {
        for (i, &b) in rest.iter().enumerate() {
            h ^= u32::from(b) << (8 * i);
        }
        h = h.wrapping_mul(M);
    }
    h ^= h >> 13;
    h = h.wrapping_mul(M);
    h ^ (h >> 15)
}

/// The tags' bloom filter in udev's header.
pub fn tag_bloom(tags: &[&str]) -> u64 {
    tags.iter().fold(0u64, |b, t| {
        let h = murmur2(t.as_bytes());
        [0, 6, 12, 18].iter().fold(b, |b, sh| b | 1 << ((h >> sh) & 63))
    })
}

/// udevd's message for a device the kernel announced (`action`,
/// `devpath`, its environment `env`), with devd's `props` and `tags`.
pub fn udev_message(
    action: &str,
    devpath: &str,
    env: &[(String, String)],
    props: &[(String, String)],
    tags: &[&str],
    usec: u64,
) -> Vec<u8> {
    let mut body = Vec::new();
    let mut put = |k: &str, v: &str| {
        body.extend_from_slice(k.as_bytes());
        body.push(b'=');
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    };
    put("UDEV_DATABASE_VERSION", "1");
    put("ACTION", action);
    put("DEVPATH", devpath);
    for (k, v) in env.iter().filter(|(k, _)| !matches!(k.as_str(), "ACTION" | "DEVPATH")) {
        if k == "DEVNAME" && !v.starts_with('/') {
            put(k, &format!("/dev/{v}"));
        } else {
            put(k, v);
        }
    }
    put("USEC_INITIALIZED", &format!("{usec}"));
    for (k, v) in props.iter().filter(|(k, _)| get(env, k).is_none()) {
        put(k, v);
    }
    if !tags.is_empty() {
        let list = format!(":{}:", tags.join(":"));
        put("TAGS", &list);
        put("CURRENT_TAGS", &list);
    }
    let hash = |key: &str| get(env, key).map_or(0, |v| murmur2(v.as_bytes()));
    let bloom = tag_bloom(tags);
    let mut m = Vec::with_capacity(40 + body.len());
    m.extend_from_slice(b"libudev\0");
    m.extend_from_slice(&0xfeed_cafe_u32.to_be_bytes());
    m.extend_from_slice(&40u32.to_ne_bytes());
    m.extend_from_slice(&40u32.to_ne_bytes());
    m.extend_from_slice(&(body.len() as u32).to_ne_bytes());
    m.extend_from_slice(&hash("SUBSYSTEM").to_be_bytes());
    m.extend_from_slice(&hash("DEVTYPE").to_be_bytes());
    m.extend_from_slice(&((bloom >> 32) as u32).to_be_bytes());
    m.extend_from_slice(&(bloom as u32).to_be_bytes());
    m.extend_from_slice(&body);
    m
}

/// A database entry's text.
pub fn db_entry(props: &[(String, String)], tags: &[&str], usec: u64) -> String {
    let mut s = format!("I:{usec}\n");
    for (k, v) in props {
        s.push_str(&format!("E:{k}={v}\n"));
    }
    for t in tags {
        s.push_str(&format!("G:{t}\n"));
    }
    for t in tags {
        s.push_str(&format!("Q:{t}\n"));
    }
    s.push_str("V:1\n");
    s
}

/// A block device's properties: its uevent file's `DEVTYPE`, `PARTN` and
/// `PARTNAME`, and the file system the kernel found (`fs`, `label`,
/// `uuid` from /sys/block's `slate_fs*`), named as udev names them.
pub fn block_properties(uevent: &[(String, String)], fs: &str, label: &str, uuid: &str) -> Env {
    let mut out: Env = Vec::new();
    let mut put = |k: &str, v: &str| {
        if !v.is_empty() {
            out.push((String::from(k), String::from(v)));
        }
    };
    put("DEVTYPE", get(uevent, "DEVTYPE").unwrap_or(""));
    put("ID_PART_ENTRY_NUMBER", get(uevent, "PARTN").unwrap_or(""));
    put("ID_PART_ENTRY_NAME", get(uevent, "PARTNAME").unwrap_or(""));
    if !fs.is_empty() {
        put("ID_FS_TYPE", fs);
        put("ID_FS_USAGE", if fs == "slatecrypt" { "crypto" } else { "filesystem" });
        // udev's ID_FS_LABEL has spaces as `_`; ID_FS_LABEL_ENC keeps them
        // as `\x20`.
        put("ID_FS_LABEL", &label.replace(' ', "_"));
        put("ID_FS_LABEL_ENC", &label.replace(' ', "\\x20"));
        put("ID_FS_UUID", uuid);
    }
    out
}

/// What devd records for a device: (database name, properties, tags), or
/// None for devices it doesn't keep.
pub fn describe(
    subsystem: &str,
    env: &[(String, String)],
    caps: impl FnOnce() -> InputCaps,
) -> Option<(String, Env, Vec<&'static str>)> {
    let major: u32 = get(env, "MAJOR")?.parse().ok()?;
    let minor: u32 = get(env, "MINOR")?.parse().ok()?;
    let name = format!("c{major}:{minor}");
    match (subsystem, major) {
        ("input", INPUT_MAJOR) if get(env, "DEVNAME")?.starts_with("input/event") => {
            Some((name, input_properties(&caps()), alloc::vec!["seat"]))
        }
        ("drm", DRM_MAJOR) => Some((name, Vec::new(), alloc::vec!["seat", "master-of-seat"])),
        ("sound", SOUND_MAJOR) => Some((name, Vec::new(), alloc::vec!["seat"])),
        _ => None,
    }
}

/// A sound card's own entry (it has no node): its database name and
/// properties, from its sysfs path ("/sys/devices/pci0000:00/0000:00:04.0/
/// sound/card0"). udev's `ID_PATH` names the device the card is on.
pub fn sound_card(syspath: &str) -> Option<(String, Env)> {
    let (parent, card) = syspath.rsplit_once("/sound/")?;
    if !card.starts_with("card") || !card[4..].bytes().all(|b| b.is_ascii_digit()) || card.len() == 4 {
        return None;
    }
    let device = parent.rsplit('/').next()?;
    let id_path = if parent.contains("/usb") { format!("usb-{device}") } else { format!("pci-{device}") };
    let tag = id_path.replace([':', '.'], "_");
    let props = alloc::vec![
        (String::from("ID_PATH"), id_path),
        (String::from("ID_PATH_TAG"), tag),
        (String::from("SOUND_INITIALIZED"), String::from("1")),
    ];
    Some((format!("+sound:{card}"), props))
}

/// The `seat` group's ID, from /etc/group.
fn seat_gid() -> Option<u32> {
    let text = read_text(b"/etc/group");
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 3 && f[0] == "seat").then(|| f[2].parse().ok()).flatten()
    })
}

fn read_text(path: &[u8]) -> String {
    fs::read_file(path).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default()
}

/// The capabilities of the input device above event node `syspath`.
fn read_caps(syspath: &[u8]) -> InputCaps {
    let bits = |name: &str| Bits::parse(read_text(&fs::join(syspath, format!("device/{name}").as_bytes())).trim());
    InputCaps {
        ev: bits("capabilities/ev"),
        key: bits("capabilities/key"),
        rel: bits("capabilities/rel"),
        abs: bits("capabilities/abs"),
        prop: bits("properties"),
    }
}

fn monotonic_usec() -> u64 {
    // CLOCK_MONOTONIC (clock_gettime(2)).
    let (s, ns) = slate_rt::time::now(1);
    s as u64 * 1_000_000 + ns as u64 / 1000
}

/// Write an entry and its tags.
fn write_entry(name: &str, props: &[(String, String)], tags: &[&str]) {
    let text = db_entry(props, tags, monotonic_usec());
    let tmp = fs::join(DATA, format!(".{name}.tmp").as_bytes());
    let path = fs::join(DATA, name.as_bytes());
    if fs::write_file(&tmp, text.as_bytes(), 0o644).and_then(|_| fs::rename(&tmp, &path)).is_err() {
        eprintln!("devd: cannot write {}", name);
        return;
    }
    for t in tags {
        let dir = fs::join(TAGS, t.as_bytes());
        let _ = fs::mkdir(&dir, 0o755);
        let _ = fs::write_file(&fs::join(&dir, name.as_bytes()), b"", 0o644);
    }
}

/// Record the device at `syspath` (its uevent environment `env`); what
/// was recorded, for libudev's monitors: (properties, tags).
fn add(subsystem: &str, syspath: &[u8], env: &[(String, String)]) -> (Env, Vec<&'static str>) {
    if subsystem == "sound" && get(env, "MAJOR").is_none() {
        if let Some((name, props)) = sound_card(&String::from_utf8_lossy(syspath)) {
            write_entry(&name, &props, &["seat"]);
            return (props, alloc::vec!["seat"]);
        }
        return (Vec::new(), Vec::new());
    }
    // Block devices: what the kernel found on them (written by
    // `sync_block`).
    if subsystem == "block" {
        let f = |n: &[u8]| String::from(read_text(&fs::join(syspath, n)).trim());
        return (block_properties(env, &f(b"slate_fs"), &f(b"slate_fs_label"), &f(b"slate_fs_uuid")), Vec::new());
    }
    // Sound nodes belong to the seat group.
    if subsystem == "sound"
        && let Some(dev) = get(env, "DEVNAME")
    {
        let node = format!("/dev/{dev}");
        if let Some(gid) = seat_gid() {
            let _ = fs::chown(node.as_bytes(), 0, gid);
        }
        let _ = fs::chmod(node.as_bytes(), 0o660);
    }
    let Some((name, props, tags)) = describe(subsystem, env, || read_caps(syspath)) else {
        return (Vec::new(), Vec::new());
    };
    write_entry(&name, &props, &tags);
    (props, tags)
}

fn remove(syspath: &[u8], env: &[(String, String)]) {
    let name = match (get(env, "MAJOR"), get(env, "MINOR")) {
        (Some(major), Some(minor)) => format!("c{major}:{minor}"),
        _ => match sound_card(&String::from_utf8_lossy(syspath)) {
            Some((name, _)) => name,
            None => return,
        },
    };
    let _ = fs::unlink(&fs::join(DATA, name.as_bytes()));
    if let Ok(tags) = fs::read_dir(TAGS) {
        for t in tags {
            let _ = fs::unlink(&fs::join(&fs::join(TAGS, &t.name), name.as_bytes()));
        }
    }
}

/// The subsystem of the device at `syspath` (its `subsystem` link).
fn subsystem_of(syspath: &[u8]) -> String {
    let target = fs::readlink(&fs::join(syspath, b"subsystem")).unwrap_or_default();
    String::from_utf8_lossy(fs::basename(&target)).into_owned()
}

/// The block devices' entries as /sys/block shows them now: (database
/// name, text without its time).
fn block_entries() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut visit = |dir: &[u8]| {
        let env = parse_env(&read_text(&fs::join(dir, b"uevent")));
        let (Some(major), Some(minor)) = (get(&env, "MAJOR"), get(&env, "MINOR")) else { return };
        let f = |n: &[u8]| String::from(read_text(&fs::join(dir, n)).trim());
        let props = block_properties(&env, &f(b"slate_fs"), &f(b"slate_fs_label"), &f(b"slate_fs_uuid"));
        let text = db_entry(&props, &[], 0);
        out.push((format!("b{major}:{minor}"), text));
    };
    let Ok(disks) = fs::read_dir(b"/sys/block") else { return out };
    for d in disks.iter().filter(|e| !e.name.starts_with(b".")) {
        let dir = fs::join(b"/sys/block", &d.name);
        visit(&dir);
        for p in fs::read_dir(&dir).unwrap_or_default() {
            // A partition's directory has its own uevent with DEVTYPE.
            let pd = fs::join(&dir, &p.name);
            if p.name.starts_with(&d.name) && fs::exists(&fs::join(&pd, b"partition")) {
                visit(&pd);
            }
        }
    }
    out
}

/// Write the block devices' entries that changed since `known`, remove
/// the ones gone; `known` becomes what is there now.
fn sync_block(known: &mut Vec<(String, String)>) {
    let now = block_entries();
    for (name, text) in &now {
        if known.iter().any(|(n, t)| n == name && t == text) {
            continue;
        }
        let full = text.replacen("I:0\n", &format!("I:{}\n", monotonic_usec()), 1);
        let tmp = fs::join(DATA, format!(".{name}.tmp").as_bytes());
        let path = fs::join(DATA, name.as_bytes());
        if fs::write_file(&tmp, full.as_bytes(), 0o644).and_then(|_| fs::rename(&tmp, &path)).is_err() {
            eprintln!("devd: cannot write {name}");
        }
    }
    for (name, _) in known.iter() {
        if !now.iter().any(|(n, _)| n == name) {
            let _ = fs::unlink(&fs::join(DATA, name.as_bytes()));
        }
    }
    *known = now;
}

/// Record the devices sysfs already shows. Returns how many.
fn coldplug() -> usize {
    let mut n = 0;
    for class in ["input", "drm", "sound"] {
        let dir = format!("/sys/class/{class}");
        let Ok(entries) = fs::read_dir(dir.as_bytes()) else { continue };
        for e in entries.iter().filter(|e| !e.name.starts_with(b".")) {
            let syspath = fs::join(dir.as_bytes(), &e.name);
            let env = parse_env(&read_text(&fs::join(&syspath, b"uevent")));
            if get(&env, "MAJOR").is_some() {
                add(&subsystem_of(&syspath), &syspath, &env);
                n += 1;
            } else if class == "sound" {
                // A card: by its real path, as the uevent names it.
                // (/sys/class/sound/cardN leads to ../../devices/...).
                let target = fs::readlink(&syspath).unwrap_or_default();
                let real = match target.strip_prefix(b"../../") {
                    Some(rest) => fs::join(b"/sys", rest),
                    None => syspath,
                };
                add("sound", &real, &env);
                n += 1;
            }
        }
    }
    n
}

/// `devd monitor [SECONDS]`: print the kernel's uevents.
fn monitor(seconds: Option<u64>) -> i32 {
    let sock = match net::uevent_listen(1 << (KERNEL_GROUP - 1) | 2) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("devd: uevent socket: {e}");
            return 1;
        }
    };
    slate_rt::println!("monitor: listening");
    let _ = slate_rt::io::flush_stdout();
    let end = seconds.map(|s| slate_rt::time::monotonic_ns() / 1_000_000 + s * 1000);
    let mut buf = alloc::vec![0u8; 16 * 1024];
    loop {
        let wait = match end {
            Some(end) => {
                let now = slate_rt::time::monotonic_ns() / 1_000_000;
                if now >= end {
                    return 0;
                }
                (end - now).min(1000) as i32
            }
            None => 1000,
        };
        let mut fds = [slate_rt::io::PollFd { fd: sock, events: slate_rt::io::POLLIN, revents: 0 }];
        if slate_rt::io::poll(&mut fds, wait).unwrap_or(0) == 0 {
            continue;
        }
        let Ok((len, from)) = net::uevent_recv(sock, &mut buf) else { continue };
        let line = if from == 0 {
            parse_message(&buf[..len]).map(|(action, devpath, env)| monitor_line(true, &action, &devpath, &env))
        } else {
            parse_udev(&buf[..len]).map(|(env, ok)| {
                let line =
                    monitor_line(false, get(&env, "ACTION").unwrap_or("-"), get(&env, "DEVPATH").unwrap_or("-"), &env);
                if ok { line } else { format!("{line} (bad header)") }
            })
        };
        let Some(line) = line else { continue };
        slate_rt::println!("{line}");
        let _ = slate_rt::io::flush_stdout();
    }
}

/// A udev message's properties, and whether its header holds together
/// (magic, sizes, the subsystem's and device type's hashes).
pub fn parse_udev(m: &[u8]) -> Option<(Env, bool)> {
    if m.len() < 40 || &m[..8] != b"libudev\0" {
        return None;
    }
    let ne = |at: usize| u32::from_ne_bytes([m[at], m[at + 1], m[at + 2], m[at + 3]]);
    let be = |at: usize| u32::from_be_bytes([m[at], m[at + 1], m[at + 2], m[at + 3]]);
    let (off, len) = (ne(16) as usize, ne(20) as usize);
    let body = m.get(off..off.checked_add(len)?)?;
    let env: Env = body
        .split(|&b| b == 0)
        .filter_map(|p| core::str::from_utf8(p).ok()?.split_once('='))
        .map(|(k, v)| (String::from(k), String::from(v)))
        .collect();
    let hash = |key: &str| get(&env, key).map_or(0, |v| murmur2(v.as_bytes()));
    let ok = be(8) == 0xfeed_cafe && ne(12) == 40 && be(24) == hash("SUBSYSTEM") && be(28) == hash("DEVTYPE");
    Some((env, ok))
}

/// One `devd monitor` line.
pub fn monitor_line(kernel: bool, action: &str, devpath: &str, env: &[(String, String)]) -> String {
    format!(
        "{} {action} {devpath} ({}) {}",
        if kernel { "KERNEL" } else { "UDEV" },
        get(env, "SUBSYSTEM").unwrap_or("-"),
        get(env, "DEVTYPE").unwrap_or("-")
    )
}

pub fn main() -> i32 {
    let args = slate_rt::env::args();
    if args.get(1).map(|a| a.as_slice()) == Some(b"monitor") {
        let secs = args.get(2).and_then(|a| core::str::from_utf8(a).ok()).and_then(|a| a.parse().ok());
        return monitor(secs);
    }
    if process::geteuid() != 0 {
        eprintln!("devd: must run as root");
        return 1;
    }
    for d in [RUN, DATA, TAGS] {
        let _ = fs::mkdir(d, 0o755);
    }
    // Listen first, so that nothing that appears during the scan is
    // missed.
    let sock = match net::uevent_listen(1 << (KERNEL_GROUP - 1)) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("devd: uevent socket: {e}");
            return 1;
        }
    };
    // udevd's control socket: libudev's monitors look for it.
    let control = net::listen_path(b"/run/udev/control", 4).ok();
    let _ = fs::chmod(b"/run/udev/control", 0o600);
    let n = coldplug();
    let mut block = Vec::new();
    sync_block(&mut block);
    eprintln!("devd: {n} devices, {} block devices", block.len());
    let mut buf = alloc::vec![0u8; 16 * 1024];
    loop {
        // Block devices: looked at after each uevent, and once a minute.
        let mut fds = [
            slate_rt::io::PollFd { fd: sock, events: slate_rt::io::POLLIN, revents: 0 },
            slate_rt::io::PollFd { fd: control.unwrap_or(-1), events: slate_rt::io::POLLIN, revents: 0 },
        ];
        let ready = slate_rt::io::poll(&mut fds, 60_000).unwrap_or(0);
        if fds[1].revents != 0
            && let Some(c) = control
            && let Ok(conn) = net::accept(c)
        {
            let _ = slate_rt::io::close(conn);
        }
        if fds[0].revents == 0 {
            sync_block(&mut block);
            continue;
        }
        sync_block(&mut block);
        if ready == 0 {
            continue;
        }
        let Ok((len, from)) = net::uevent_recv(sock, &mut buf) else { continue };
        if from != 0 {
            continue; // Only the kernel announces devices here.
        }
        let Some((action, devpath, env)) = parse_message(&buf[..len]) else { continue };
        let syspath = format!("/sys{devpath}");
        let subsystem = get(&env, "SUBSYSTEM").unwrap_or_default();
        let (props, tags) = match action.as_str() {
            "add" | "change" => add(subsystem, syspath.as_bytes(), &env),
            "remove" => {
                remove(syspath.as_bytes(), &env);
                (Vec::new(), Vec::new())
            }
            _ => (Vec::new(), Vec::new()),
        };
        if subsystem == "block" {
            sync_block(&mut block);
        }
        // Then libudev's monitors hear of it (ADR 0185).
        let m = udev_message(&action, &devpath, &env, &props, &tags, monotonic_usec());
        if let Err(e) = net::uevent_send(sock, &m, 2) {
            eprintln!("devd: re-announcing {devpath}: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(ev: &str, key: &str, rel: &str, abs: &str) -> InputCaps {
        InputCaps {
            ev: Bits::parse(ev),
            key: Bits::parse(key),
            rel: Bits::parse(rel),
            abs: Bits::parse(abs),
            ..InputCaps::default()
        }
    }

    fn kinds(c: &InputCaps) -> Vec<String> {
        input_properties(c).into_iter().map(|(k, _)| k).collect()
    }

    #[test]
    fn udev_messages() {
        // Hashes and a bloom filter as systemd-udevd sent them on a Linux
        // host (2026-10-31: a loop device, `module`, `misc` and `bdi`).
        assert_eq!(murmur2(b"block"), 0xf003_1db7);
        assert_eq!(murmur2(b"disk"), 0x7bcb_c5ee);
        assert_eq!(murmur2(b"module"), 0x38e3_a30f);
        assert_eq!(murmur2(b"misc"), 0x4b1a_4e75);
        assert_eq!(murmur2(b"bdi"), 0x2a18_84a1);
        assert_eq!(tag_bloom(&["systemd"]), 0x0200_0400_1080_0000);
        let env = parse_env("SUBSYSTEM=block\nDEVNAME=sda\nDEVTYPE=disk\nMAJOR=8\nMINOR=0\n");
        let props = alloc::vec![(String::from("ID_FS_TYPE"), String::from("vfat"))];
        let m = udev_message("add", "/block/sda", &env, &props, &["systemd"], 77);
        assert_eq!(&m[..8], b"libudev\0");
        assert_eq!(m[8..12], [0xfe, 0xed, 0xca, 0xfe]);
        assert_eq!(m[24..32], [0xf0, 0x03, 0x1d, 0xb7, 0x7b, 0xcb, 0xc5, 0xee]);
        assert_eq!(m[32..40], [0x02, 0x00, 0x04, 0x00, 0x10, 0x80, 0x00, 0x00]);
        let (got, ok) = parse_udev(&m).unwrap();
        assert!(ok);
        assert_eq!(get(&got, "DEVNAME"), Some("/dev/sda"));
        assert_eq!(get(&got, "ACTION"), Some("add"));
        assert_eq!(get(&got, "ID_FS_TYPE"), Some("vfat"));
        assert_eq!(get(&got, "TAGS"), Some(":systemd:"));
        assert_eq!(get(&got, "USEC_INITIALIZED"), Some("77"));
        let body = &m[40..];
        assert!(body.starts_with(b"UDEV_DATABASE_VERSION=1\0ACTION=add\0DEVPATH=/block/sda\0SUBSYSTEM=block\0"));
        assert_eq!(u32::from_ne_bytes(m[20..24].try_into().unwrap()) as usize, body.len());
    }

    #[test]
    fn monitor_lines() {
        let (action, devpath, env) =
            parse_message(b"add@/block/sda\0ACTION=add\0DEVPATH=/block/sda\0SUBSYSTEM=block\0DEVTYPE=disk\0SEQNUM=4\0")
                .unwrap();
        assert_eq!(monitor_line(true, &action, &devpath, &env), "KERNEL add /block/sda (block) disk");
    }

    #[test]
    fn sound_devices() {
        let pcm = parse_env("MAJOR=116\nMINOR=16\nDEVNAME=snd/pcmC0D0p\nDEVTYPE=pcm\n");
        let (name, props, tags) = describe("sound", &pcm, InputCaps::default).unwrap();
        assert_eq!((name.as_str(), props.len(), tags), ("c116:16", 0, alloc::vec!["seat"]));
        let (name, props) = sound_card("/sys/devices/pci0000:00/0000:00:04.0/sound/card0").unwrap();
        assert_eq!(name, "+sound:card0");
        assert_eq!(
            db_entry(&props, &["seat"], 7),
            "I:7\nE:ID_PATH=pci-0000:00:04.0\nE:ID_PATH_TAG=pci-0000_00_04_0\nE:SOUND_INITIALIZED=1\nG:seat\nQ:seat\nV:1\n"
        );
        assert!(sound_card("/sys/devices/pci0000:00/0000:00:04.0/sound/card0/controlC0").is_none());
        assert!(sound_card("/sys/devices/pci0000:00/0000:00:04.0/sound/card").is_none());
    }

    #[test]
    fn bitmaps() {
        let b = Bits::parse("10000 0 1");
        assert!(b.has(0));
        assert!(!b.has(1));
        assert!(b.has(128 + 16));
        assert!(!b.has(1000));
    }

    #[test]
    fn keyboards_and_mice() {
        // A keyboard: EV_SYN, EV_KEY, EV_MSC, EV_LED, EV_REP; keys 1-127.
        let kbd = caps("120013", "0 ffffffffffffffff ffffffffffffffff", "0", "0");
        assert_eq!(kinds(&kbd), ["ID_INPUT", "ID_INPUT_KEY", "ID_INPUT_KEYBOARD"]);
        // A mouse: EV_KEY, EV_REL; BTN_LEFT..BTN_MIDDLE; REL_X, REL_Y, REL_WHEEL.
        let mouse = caps("7", "70000 0 0 0 0", "103", "0");
        assert_eq!(kinds(&mouse), ["ID_INPUT", "ID_INPUT_MOUSE"]);
        // QEMU's tablet: EV_KEY, EV_ABS; buttons; ABS_X, ABS_Y.
        let tablet = caps("b", "70000 0 0 0 0", "0", "3");
        assert_eq!(kinds(&tablet), ["ID_INPUT", "ID_INPUT_MOUSE"]);
        // A pen tablet.
        let pen = caps("b", "c01 0 0 0 0 0", "0", "3");
        assert_eq!(kinds(&pen), ["ID_INPUT", "ID_INPUT_TABLET"]);
    }

    #[test]
    fn messages_and_entries() {
        let m = b"add@/devices/virtual/input/input3/event3\0ACTION=add\0DEVPATH=/devices/virtual/input/input3/event3\0SUBSYSTEM=input\0MAJOR=13\0MINOR=67\0DEVNAME=input/event3\0SEQNUM=9\0";
        let (action, path, env) = parse_message(m).unwrap();
        assert_eq!((action.as_str(), path.as_str()), ("add", "/devices/virtual/input/input3/event3"));
        assert_eq!(get(&env, "SUBSYSTEM"), Some("input"));
        let (name, props, tags) = describe("input", &env, || caps("7", "70000 0 0 0 0", "3", "0")).unwrap();
        assert_eq!(name, "c13:67");
        assert_eq!(db_entry(&props, &tags, 42), "I:42\nE:ID_INPUT=1\nE:ID_INPUT_MOUSE=1\nG:seat\nQ:seat\nV:1\n");
        // A partition with a labelled SlateFS, and an encrypted one.
        let ue = parse_env("MAJOR=8\nMINOR=1\nDEVNAME=sda1\nDEVTYPE=partition\nPARTN=1\nPARTNAME=Trip\n");
        let p = block_properties(&ue, "slatefs", "My Trip", "1234");
        let keys: Vec<String> = p.iter().map(|(k, v)| format!("{k}={v}")).collect();
        assert_eq!(
            keys,
            [
                "DEVTYPE=partition",
                "ID_PART_ENTRY_NUMBER=1",
                "ID_PART_ENTRY_NAME=Trip",
                "ID_FS_TYPE=slatefs",
                "ID_FS_USAGE=filesystem",
                "ID_FS_LABEL=My_Trip",
                "ID_FS_LABEL_ENC=My\\x20Trip",
                "ID_FS_UUID=1234"
            ]
        );
        let c = block_properties(&ue, "slatecrypt", "", "");
        assert!(c.iter().any(|(k, v)| k == "ID_FS_USAGE" && v == "crypto"));
        assert_eq!(block_properties(&parse_env("DEVTYPE=disk\n"), "", "", "").len(), 1);
        // The input device itself (no node) is not kept.
        let parent = parse_env("PRODUCT=11/1/1/ab41\nNAME=\"kbd\"\n");
        assert!(describe("input", &parent, InputCaps::default).is_none());
        let drm = parse_env("MAJOR=226\nMINOR=0\nDEVNAME=dri/card0\nDEVTYPE=drm_minor\n");
        assert_eq!(describe("drm", &drm, InputCaps::default).unwrap().2, ["seat", "master-of-seat"]);
    }
}
