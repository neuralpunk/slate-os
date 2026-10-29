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
//! and libinput's documented ones. Re-announcing devices to libudev
//! monitors (netlink group 2) is not done yet (docs/GAPS.md).
//!
//! Block devices (`b<major>:<minor>`) get what the kernel found on them
//! (/sys/block's `slate_fs*`, ADR 0112) as udev's `ID_FS_TYPE`,
//! `ID_FS_LABEL`, `ID_FS_UUID` and `ID_FS_USAGE`, and their partition's
//! number and name. The kernel announces no block devices, so devd looks
//! at /sys/block at start, after each uevent and every few seconds, and
//! writes only the entries that changed (ADR 0112's addendum).

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

/// Character device majors (devices.txt): input, DRM.
const INPUT_MAJOR: u32 = 13;
const DRM_MAJOR: u32 = 226;
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
        _ => None,
    }
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

/// Record the device at `syspath` (its uevent environment `env`).
fn add(subsystem: &str, syspath: &[u8], env: &[(String, String)]) {
    let Some((name, props, tags)) = describe(subsystem, env, || read_caps(syspath)) else { return };
    let text = db_entry(&props, &tags, monotonic_usec());
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

fn remove(env: &[(String, String)]) {
    let (Some(major), Some(minor)) = (get(env, "MAJOR"), get(env, "MINOR")) else { return };
    let name = format!("c{major}:{minor}");
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
    for class in ["input", "drm"] {
        let dir = format!("/sys/class/{class}");
        let Ok(entries) = fs::read_dir(dir.as_bytes()) else { continue };
        for e in entries.iter().filter(|e| !e.name.starts_with(b".")) {
            let syspath = fs::join(dir.as_bytes(), &e.name);
            let env = parse_env(&read_text(&fs::join(&syspath, b"uevent")));
            if get(&env, "MAJOR").is_some() {
                add(&subsystem_of(&syspath), &syspath, &env);
                n += 1;
            }
        }
    }
    n
}

pub fn main() -> i32 {
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
    let n = coldplug();
    let mut block = Vec::new();
    sync_block(&mut block);
    eprintln!("devd: {n} devices, {} block devices", block.len());
    let mut buf = alloc::vec![0u8; 16 * 1024];
    loop {
        // Block devices aren't announced: looked at every few seconds,
        // and after anything that is.
        let mut fds = [slate_rt::io::PollFd { fd: sock, events: slate_rt::io::POLLIN, revents: 0 }];
        let ready = slate_rt::io::poll(&mut fds, 5000).unwrap_or(0);
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
        match action.as_str() {
            "add" | "change" => add(subsystem, syspath.as_bytes(), &env),
            "remove" => remove(&env),
            _ => {}
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
