// SPDX-License-Identifier: MIT OR Apache-2.0

//! `lsusb [-t] [-s [[bus]:][devnum]] [-d [vendor]:[product]] [-i file]`:
//! the USB devices in /sys/bus/usb/devices, laid out as usbutils' lsusb
//! lays them out (observed with lsusb 019 on the host): one line per
//! device, `Bus 001 Device 002: ID 046d:0afe` and its names; `-t`, the
//! tree of hubs, ports and interfaces with their classes, drivers and
//! speeds. Names come from a usb.ids file if one is installed (`-i`
//! names another), else from the device's own strings (its manufacturer
//! and product), as lsusb falls back to them.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{eprintln, println};

use crate::ids::{Ids, load};

const IDS: &[&[u8]] = &[b"/usr/share/hwdata/usb.ids", b"/usr/share/misc/usb.ids", b"/usr/share/usb.ids"];

/// One interface of a device.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Interface {
    pub number: u8,
    pub class: u8,
    pub driver: Option<String>,
}

/// One device, as /sys describes it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Device {
    /// Its name in /sys: `usb1` for a root hub, `1-4.2` behind a hub.
    pub name: String,
    pub bus: u16,
    pub devnum: u16,
    pub vendor: u16,
    pub product: u16,
    /// The speed in Mbit/s as /sys gives it ("1.5", "12", "480", "5000").
    pub speed: String,
    /// rx_lanes: more than one shows as `/x2` after the speed in -t.
    pub lanes: u16,
    /// A hub's ports.
    pub maxchild: u16,
    pub manufacturer: Option<String>,
    pub product_name: Option<String>,
    /// A root hub's controller's driver (`xhci`).
    pub controller_driver: Option<String>,
    pub interfaces: Vec<Interface>,
}

impl Device {
    pub fn is_root(&self) -> bool {
        self.name.starts_with("usb")
    }

    /// Its ports from the root hub (`4.2` for `1-4.2`; empty for a root hub).
    pub fn ports(&self) -> Vec<u16> {
        match self.name.split_once('-') {
            Some((_, p)) => p.split('.').filter_map(|x| x.parse().ok()).collect(),
            None => Vec::new(),
        }
    }
}

fn text(path: &str) -> Option<String> {
    let b = slate_rt::fs::read_file(path.as_bytes()).ok()?;
    let s = String::from_utf8_lossy(&b).into_owned();
    Some(String::from(s.strip_suffix('\n').unwrap_or(&s)))
}

fn hex(path: &str) -> Option<u32> {
    u32::from_str_radix(text(path)?.trim(), 16).ok()
}

fn dec(path: &str) -> Option<u32> {
    text(path)?.trim().parse().ok()
}

fn link_name(path: &str) -> Option<String> {
    let l = slate_rt::fs::readlink(path.as_bytes()).ok()?;
    Some(String::from_utf8_lossy(l.rsplit(|&c| c == b'/').next().unwrap_or(&[])).into_owned())
}

/// Every device in /sys/bus/usb/devices, by bus and device number.
pub fn devices() -> Vec<Device> {
    let base = "/sys/bus/usb/devices";
    let Ok(entries) = slate_rt::fs::read_dir(base.as_bytes()) else { return Vec::new() };
    let names: Vec<String> = entries.iter().map(|e| String::from_utf8_lossy(&e.name).into_owned()).collect();
    let mut out: Vec<Device> = names
        .iter()
        .filter(|n| !n.contains(':') && !n.starts_with('.'))
        .filter_map(|n| {
            let dir = format!("{base}/{n}");
            let mut interfaces: Vec<Interface> = names
                .iter()
                .filter(|i| {
                    i.split_once(':').is_some_and(|(d, _)| {
                        d == n.as_str() || (n.starts_with("usb") && d == format!("{}-0", &n[3..]))
                    })
                })
                .filter_map(|i| {
                    let idir = format!("{base}/{i}");
                    Some(Interface {
                        number: hex(&format!("{idir}/bInterfaceNumber"))? as u8,
                        class: hex(&format!("{idir}/bInterfaceClass")).unwrap_or(0) as u8,
                        driver: link_name(&format!("{idir}/driver")),
                    })
                })
                .collect();
            interfaces.sort_by_key(|i| i.number);
            Some(Device {
                name: n.clone(),
                bus: dec(&format!("{dir}/busnum"))? as u16,
                devnum: dec(&format!("{dir}/devnum"))? as u16,
                vendor: hex(&format!("{dir}/idVendor"))? as u16,
                product: hex(&format!("{dir}/idProduct"))? as u16,
                speed: text(&format!("{dir}/speed")).unwrap_or_default(),
                lanes: dec(&format!("{dir}/rx_lanes")).unwrap_or(1) as u16,
                maxchild: dec(&format!("{dir}/maxchild")).unwrap_or(0) as u16,
                manufacturer: text(&format!("{dir}/manufacturer")),
                product_name: text(&format!("{dir}/product")),
                controller_driver: if n.starts_with("usb") { link_name(&format!("{dir}/../driver")) } else { None },
                interfaces,
            })
        })
        .collect();
    out.sort_by_key(|d| (d.bus, d.devnum));
    out
}

/// The default line: bus, device, IDs, vendor and product names (the
/// database's, else the device's strings).
pub fn line(d: &Device, ids: &Ids) -> String {
    let vendor = ids.vendor(d.vendor).map(String::from).or_else(|| d.manufacturer.clone()).unwrap_or_default();
    let product =
        ids.device(d.vendor, d.product).map(String::from).or_else(|| d.product_name.clone()).unwrap_or_default();
    format!("Bus {:03} Device {:03}: ID {:04x}:{:04x} {vendor} {product}", d.bus, d.devnum, d.vendor, d.product)
}

/// Interface class names as lsusb -t gives them (the USB-IF's base class
/// codes; the names lsusb prints, observed).
fn class_name(class: u8) -> &'static str {
    match class {
        0x01 => "Audio",
        0x02 => "Communications",
        0x03 => "Human Interface Device",
        0x05 => "Physical Interface Device",
        0x06 => "Imaging",
        0x07 => "Printer",
        0x08 => "Mass Storage",
        0x09 => "Hub",
        0x0a => "CDC Data",
        0x0b => "Chip/SmartCard",
        0x0d => "Content Security",
        0x0e => "Video",
        0x0f => "Personal Healthcare",
        0x10 => "Audio/Video",
        0x11 => "Billboard",
        0x12 => "Type-C Bridge",
        0xdc => "Diagnostic",
        0xe0 => "Wireless",
        0xef => "Miscellaneous Device",
        0xfe => "Application Specific Interface",
        0xff => "Vendor Specific Class",
        _ => "[unknown]",
    }
}

fn speed(d: &Device) -> String {
    if d.lanes > 1 { format!("{}M/x{}", d.speed, d.lanes) } else { format!("{}M", d.speed) }
}

/// `-t`: each root hub, then its devices' interfaces, hub by hub, port by
/// port, four spaces deeper for each tier.
pub fn tree(all: &[Device]) -> String {
    let mut s = String::new();
    for root in all.iter().filter(|d| d.is_root()) {
        s.push_str(&format!(
            "/:  Bus {:03}.Port 001: Dev {:03}, Class=root_hub, Driver={}/{}p, {}\n",
            root.bus,
            root.devnum,
            root.controller_driver.as_deref().unwrap_or("[none]"),
            root.maxchild,
            speed(root)
        ));
        children(all, root.bus, &[], 1, &mut s);
    }
    s
}

fn children(all: &[Device], bus: u16, parent: &[u16], depth: usize, s: &mut String) {
    let mut kids: Vec<&Device> = all
        .iter()
        .filter(|d| d.bus == bus && !d.is_root())
        .filter(|d| {
            let p = d.ports();
            p.len() == parent.len() + 1 && p.starts_with(parent)
        })
        .collect();
    kids.sort_by_key(|d| d.ports());
    for d in kids {
        let ports = d.ports();
        for i in &d.interfaces {
            let mut driver = String::from(i.driver.as_deref().unwrap_or("[none]"));
            if i.class == 9 {
                driver.push_str(&format!("/{}p", d.maxchild));
            }
            s.push_str(&format!(
                "{:width$}|__ Port {:03}: Dev {:03}, If {}, Class={}, Driver={driver}, {}\n",
                "",
                ports.last().copied().unwrap_or(0),
                d.devnum,
                i.number,
                class_name(i.class),
                speed(d),
                width = depth * 4
            ));
        }
        children(all, bus, &ports, depth + 1, s);
    }
}

/// `-s [[bus]:][devnum]`.
pub fn slot_filter(spec: &str) -> Option<impl Fn(&Device) -> bool> {
    let (bus, dev) = match spec.split_once(':') {
        Some((b, d)) => (b, d),
        None => ("", spec),
    };
    let num = |p: &str| -> Option<Option<u16>> { if p.is_empty() { Some(None) } else { p.parse().ok().map(Some) } };
    let (b, d) = (num(bus)?, num(dev)?);
    Some(move |x: &Device| b.is_none_or(|b| b == x.bus) && d.is_none_or(|d| d == x.devnum))
}

/// `-d [vendor]:[product]`.
pub fn id_filter(spec: &str) -> Option<impl Fn(&Device) -> bool> {
    let (v, p) = spec.split_once(':')?;
    let num = |p: &str| -> Option<Option<u16>> {
        if p.is_empty() { Some(None) } else { u16::from_str_radix(p, 16).ok().map(Some) }
    };
    let (v, p) = (num(v)?, num(p)?);
    Some(move |x: &Device| v.is_none_or(|v| v == x.vendor) && p.is_none_or(|p| p == x.product))
}

pub fn main() -> i32 {
    let args: Vec<String> =
        slate_rt::env::args().iter().skip(1).map(|a| String::from_utf8_lossy(a).into_owned()).collect();
    let (mut tree_view, mut slot_spec, mut id_spec, mut ids_file) = (false, None, None, None);
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let Some(flags) = a.strip_prefix('-').filter(|f| !f.is_empty()) else {
            eprintln!("lsusb: unexpected argument {a}");
            return 2;
        };
        for (k, c) in flags.char_indices() {
            match c {
                't' => tree_view = true,
                's' | 'd' | 'i' => {
                    let value = if k + 1 < flags.len() {
                        String::from(&flags[k + 1..])
                    } else {
                        i += 1;
                        match args.get(i) {
                            Some(v) => v.clone(),
                            None => {
                                eprintln!("lsusb: -{c} needs an argument");
                                return 2;
                            }
                        }
                    };
                    match c {
                        's' => slot_spec = Some(value),
                        'd' => id_spec = Some(value),
                        _ => ids_file = Some(value),
                    }
                    break;
                }
                _ => {
                    eprintln!("lsusb: -{c} is not supported");
                    return 2;
                }
            }
        }
        i += 1;
    }
    let all = devices();
    if tree_view {
        slate_rt::print!("{}", tree(&all));
        return 0;
    }
    let ids = match &ids_file {
        Some(f) => load(&[f.as_bytes()]),
        None => load(IDS),
    };
    let mut list = all;
    if let Some(s) = &slot_spec {
        let Some(keep) = slot_filter(s) else {
            eprintln!("lsusb: -s: invalid bus or device number");
            return 2;
        };
        list.retain(|d| keep(d));
    }
    if let Some(s) = &id_spec {
        let Some(keep) = id_filter(s) else {
            eprintln!("lsusb: -d: invalid vendor or product");
            return 2;
        };
        list.retain(|d| keep(d));
    }
    for d in &list {
        println!("{}", line(d, &ids));
    }
    // No match: status 1, as lsusb gives.
    if list.is_empty() && (slot_spec.is_some() || id_spec.is_some()) { 1 } else { 0 }
}
