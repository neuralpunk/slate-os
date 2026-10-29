// SPDX-License-Identifier: MIT OR Apache-2.0

//! `lspci [-n|-nn] [-k] [-D] [-mm] [-x[x[x]]] [-s [[dom:]bus:][slot][.func]]
//! [-d [vendor]:[device][:class]] [-i file]`: the PCI functions in
//! /sys/bus/pci/devices, one line each, laid out as pciutils' lspci lays
//! them out (observed with lspci 3.15 on the host, with and without a
//! name database): the slot, the class, the vendor and device, the
//! revision when it is not zero. Names come from a pci.ids file if one
//! is installed (`-i` names another); without one, numbers, as lspci
//! shows them then ("Class 0600: Device 1022:14b5").

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{eprintln, print, println};

use crate::ids::{Ids, load};

/// Where lspci looks for its names (the hwdata package's place, then the
/// older one).
const IDS: &[&[u8]] = &[b"/usr/share/hwdata/pci.ids", b"/usr/share/misc/pci.ids", b"/usr/share/pci.ids"];

/// One function, as /sys describes it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Function {
    pub domain: u16,
    pub bus: u8,
    pub slot: u8,
    pub func: u8,
    pub vendor: u16,
    pub device: u16,
    /// Class, subclass, programming interface.
    pub class: u32,
    pub revision: u8,
    pub subvendor: u16,
    pub subdevice: u16,
    pub driver: Option<String>,
}

/// What to show.
#[derive(Clone, Debug, Default)]
pub struct Opts {
    /// `-n` once: numbers only; twice: names and numbers.
    pub numeric: u8,
    pub kernel: bool,
    pub domain: bool,
    pub machine: bool,
    /// `-x` once: the first 64 bytes of configuration space; twice, 256;
    /// three times, all 4096 (as much as /sys lets the caller read).
    pub hex: u8,
}

/// `0000:00:1f.2` into its parts.
fn parse_name(n: &str) -> Option<(u16, u8, u8, u8)> {
    let (dom, rest) = n.split_once(':')?;
    let (bus, rest) = rest.split_once(':')?;
    let (slot, func) = rest.split_once('.')?;
    Some((
        u16::from_str_radix(dom, 16).ok()?,
        u8::from_str_radix(bus, 16).ok()?,
        u8::from_str_radix(slot, 16).ok()?,
        u8::from_str_radix(func, 16).ok()?,
    ))
}

fn hex_attr(dir: &str, name: &str) -> Option<u32> {
    let b = slate_rt::fs::read_file(format!("{dir}/{name}").as_bytes()).ok()?;
    let s = String::from_utf8_lossy(&b);
    u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok()
}

/// Every function in /sys/bus/pci/devices, in bus order.
pub fn functions() -> Vec<Function> {
    let base = "/sys/bus/pci/devices";
    let Ok(entries) = slate_rt::fs::read_dir(base.as_bytes()) else { return Vec::new() };
    let mut out: Vec<Function> = entries
        .iter()
        .filter_map(|e| {
            let name = String::from_utf8_lossy(&e.name).into_owned();
            let (domain, bus, slot, func) = parse_name(&name)?;
            let dir = format!("{base}/{name}");
            let driver = slate_rt::fs::readlink(format!("{dir}/driver").as_bytes())
                .ok()
                .map(|l| String::from_utf8_lossy(l.rsplit(|&c| c == b'/').next().unwrap_or(&[])).into_owned());
            Some(Function {
                domain,
                bus,
                slot,
                func,
                vendor: hex_attr(&dir, "vendor")? as u16,
                device: hex_attr(&dir, "device")? as u16,
                class: hex_attr(&dir, "class").unwrap_or(0),
                revision: hex_attr(&dir, "revision").unwrap_or(0) as u8,
                subvendor: hex_attr(&dir, "subsystem_vendor").unwrap_or(0) as u16,
                subdevice: hex_attr(&dir, "subsystem_device").unwrap_or(0) as u16,
                driver,
            })
        })
        .collect();
    out.sort_by_key(|f| (f.domain, f.bus, f.slot, f.func));
    out
}

fn slot(f: &Function, o: &Opts) -> String {
    let s = format!("{:02x}:{:02x}.{:x}", f.bus, f.slot, f.func);
    if o.domain { format!("{:04x}:{s}", f.domain) } else { s }
}

/// `CCSS`: class and subclass.
fn cc(f: &Function) -> String {
    format!("{:04x}", f.class >> 8)
}

fn class_name(f: &Function, ids: &Ids) -> Option<String> {
    ids.class((f.class >> 16) as u8, (f.class >> 8) as u8).map(String::from)
}

/// The subsystem's vendor and name as `-k` and `-mm` give them: the
/// subsystem's own name, else the device's when it is the device itself.
fn subsystem_names(f: &Function, ids: &Ids) -> (Option<String>, Option<String>) {
    let vendor = ids.vendor(f.subvendor).map(String::from);
    let name = ids.subsystem(f.vendor, f.device, f.subvendor, f.subdevice).map(String::from).or_else(|| {
        ((f.subvendor, f.subdevice) == (f.vendor, f.device))
            .then(|| ids.device(f.vendor, f.device).map(String::from))?
    });
    (vendor, name)
}

/// One function's line.
pub fn line(f: &Function, ids: &Ids, o: &Opts) -> String {
    if o.machine {
        return machine_line(f, ids, o);
    }
    let rev = if f.revision != 0 { format!(" (rev {:02x})", f.revision) } else { String::new() };
    if o.numeric == 1 {
        return format!("{} {}: {:04x}:{:04x}{rev}", slot(f, o), cc(f), f.vendor, f.device);
    }
    let both = o.numeric >= 2;
    let class = match class_name(f, ids) {
        Some(n) if both => format!("{n} [{}]", cc(f)),
        Some(n) => n,
        None if both => format!("Class [{}]", cc(f)),
        None => format!("Class {}", cc(f)),
    };
    let ids_num = format!("{:04x}:{:04x}", f.vendor, f.device);
    let what = match (ids.vendor(f.vendor), ids.device(f.vendor, f.device)) {
        (Some(v), Some(d)) if both => format!("{v} {d} [{ids_num}]"),
        (Some(v), Some(d)) => format!("{v} {d}"),
        (Some(v), None) if both => format!("{v} Device [{ids_num}]"),
        (Some(v), None) => format!("{v} Device {:04x}", f.device),
        (None, _) if both => format!("Device [{ids_num}]"),
        (None, _) => format!("Device {ids_num}"),
    };
    let mut s = format!("{} {class}: {what}{rev}", slot(f, o));
    if o.kernel {
        if f.subvendor != 0 || f.subdevice != 0 {
            let (v, n) = subsystem_names(f, ids);
            let n = n.unwrap_or_else(|| format!("Device {:04x}", f.subdevice));
            match v {
                Some(v) => s.push_str(&format!("\n\tSubsystem: {v} {n}")),
                None => s.push_str(&format!("\n\tSubsystem: Device {:04x}:{:04x}", f.subvendor, f.subdevice)),
            }
        }
        if let Some(d) = &f.driver {
            s.push_str(&format!("\n\tKernel driver in use: {d}"));
        }
    }
    s
}

/// `-mm`: slot, then quoted class, vendor, device, `-rXX` when the
/// revision is not zero, `-pXX`, quoted subsystem vendor and device
/// (empty when there is no subsystem).
fn machine_line(f: &Function, ids: &Ids, o: &Opts) -> String {
    let rev = if f.revision != 0 { format!(" -r{:02x}", f.revision) } else { String::new() };
    let prog = format!(" -p{:02x}", f.class & 0xFF);
    let has_sub = f.subvendor != 0 || f.subdevice != 0;
    let q = |s: String| format!("\"{s}\"");
    let (class, vendor, device, subv, subd) = if o.numeric == 1 {
        let (sv, sd) = if has_sub {
            (format!("{:04x}", f.subvendor), format!("{:04x}", f.subdevice))
        } else {
            (String::new(), String::new())
        };
        (cc(f), format!("{:04x}", f.vendor), format!("{:04x}", f.device), sv, sd)
    } else {
        // A known name, with its number in brackets for -nn; else the
        // word and the number ("Vendor 1022", "Vendor [1022]").
        let both = o.numeric >= 2;
        let named = |name: Option<String>, word: &str, num: String| match name {
            Some(n) if both => format!("{n} [{num}]"),
            Some(n) => n,
            None if both => format!("{word} [{num}]"),
            None => format!("{word} {num}"),
        };
        let class = named(class_name(f, ids), "Class", cc(f));
        let vendor = named(ids.vendor(f.vendor).map(String::from), "Vendor", format!("{:04x}", f.vendor));
        let device = named(ids.device(f.vendor, f.device).map(String::from), "Device", format!("{:04x}", f.device));
        let (subv, subd) = if has_sub {
            let (v, n) = subsystem_names(f, ids);
            (
                named(v, "Unknown vendor", format!("{:04x}", f.subvendor)),
                named(n, "Device", format!("{:04x}", f.subdevice)),
            )
        } else {
            (String::new(), String::new())
        };
        (class, vendor, device, subv, subd)
    };
    format!("{} {} {} {}{rev}{prog} {} {}", slot(f, o), q(class), q(vendor), q(device), q(subv), q(subd))
}

/// `-s [[domain:]bus:][slot][.func]`: empty parts (or `*`) match any.
pub fn slot_filter(spec: &str) -> Option<impl Fn(&Function) -> bool> {
    let (left, func) = match spec.split_once('.') {
        Some((l, f)) => (l, Some(f)),
        None => (spec, None),
    };
    let parts: Vec<&str> = left.split(':').collect();
    let (dom, bus, slot) = match parts.as_slice() {
        [s] => (None, None, Some(*s)),
        [b, s] => (None, Some(*b), Some(*s)),
        [d, b, s] => (Some(*d), Some(*b), Some(*s)),
        _ => return None,
    };
    let num = |p: Option<&str>| -> Option<Option<u32>> {
        match p {
            None | Some("") | Some("*") => Some(None),
            Some(x) => u32::from_str_radix(x, 16).ok().map(Some),
        }
    };
    let (d, b, s, f) = (num(dom)?, num(bus)?, num(slot)?, num(func)?);
    Some(move |x: &Function| {
        d.is_none_or(|v| v == u32::from(x.domain))
            && b.is_none_or(|v| v == u32::from(x.bus))
            && s.is_none_or(|v| v == u32::from(x.slot))
            && f.is_none_or(|v| v == u32::from(x.func))
    })
}

/// `-d [vendor]:[device][:class]`.
pub fn id_filter(spec: &str) -> Option<impl Fn(&Function) -> bool> {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() < 2 || parts.len() > 3 {
        return None;
    }
    let num = |p: &str| -> Option<Option<u32>> {
        if p.is_empty() || p == "*" { Some(None) } else { u32::from_str_radix(p, 16).ok().map(Some) }
    };
    let (v, d) = (num(parts[0])?, num(parts[1])?);
    let c = match parts.get(2) {
        Some(p) => num(p)?,
        None => None,
    };
    Some(move |x: &Function| {
        v.is_none_or(|v| v == u32::from(x.vendor))
            && d.is_none_or(|d| d == u32::from(x.device))
            && c.is_none_or(|c| c == x.class >> 8)
    })
}

pub fn main() -> i32 {
    let args: Vec<String> =
        slate_rt::env::args().iter().skip(1).map(|a| String::from_utf8_lossy(a).into_owned()).collect();
    let mut o = Opts::default();
    let (mut slot_spec, mut id_spec, mut ids_file) = (None, None, None);
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let Some(flags) = a.strip_prefix('-').filter(|f| !f.is_empty()) else {
            eprintln!("lspci: unexpected argument {a}");
            return 2;
        };
        for (k, c) in flags.char_indices() {
            match c {
                'n' => o.numeric += 1,
                'k' => o.kernel = true,
                'D' => o.domain = true,
                'm' => o.machine = true,
                'x' => o.hex += 1,
                's' | 'd' | 'i' => {
                    let value = if k + 1 < flags.len() {
                        String::from(&flags[k + 1..])
                    } else {
                        i += 1;
                        match args.get(i) {
                            Some(v) => v.clone(),
                            None => {
                                eprintln!("lspci: -{c} needs an argument");
                                return 2;
                            }
                        }
                    };
                    let spec = match c {
                        's' => &mut slot_spec,
                        'd' => &mut id_spec,
                        _ => &mut ids_file,
                    };
                    if spec.is_some() && c != 'i' {
                        eprintln!("Multiple -{c} options are given, only the last one has effect.");
                    }
                    *spec = Some(value);
                    break;
                }
                _ => {
                    eprintln!("lspci: -{c} is not supported");
                    return 2;
                }
            }
        }
        i += 1;
    }
    let ids = match &ids_file {
        Some(f) => load(&[f.as_bytes()]),
        None => load(IDS),
    };
    let mut list = functions();
    if let Some(s) = &slot_spec {
        let Some(keep) = slot_filter(s) else {
            eprintln!("lspci: -s: invalid slot number");
            return 2;
        };
        list.retain(|f| keep(f));
    }
    if let Some(s) = &id_spec {
        let Some(keep) = id_filter(s) else {
            eprintln!("lspci: -d: invalid ID");
            return 2;
        };
        list.retain(|f| keep(f));
    }
    for f in &list {
        println!("{}", line(f, &ids, &o));
        if o.hex > 0 {
            let want = match o.hex {
                1 => 64,
                2 => 256,
                _ => 4096,
            };
            let name = format!("{:04x}:{:02x}:{:02x}.{:x}", f.domain, f.bus, f.slot, f.func);
            let config =
                slate_rt::fs::read_file(format!("/sys/bus/pci/devices/{name}/config").as_bytes()).unwrap_or_default();
            print!("{}", hex_dump(&config[..config.len().min(want)]));
        }
    }
    0
}

/// `-x`: sixteen bytes a line, each line headed by its offset, then a
/// blank line.
pub fn hex_dump(config: &[u8]) -> String {
    let mut s = String::new();
    for (i, row) in config.chunks(16).enumerate() {
        s.push_str(&format!("{:02x}:", i * 16));
        for b in row {
            s.push_str(&format!(" {b:02x}"));
        }
        s.push('\n');
    }
    s.push('\n');
    s
}
