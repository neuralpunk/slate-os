// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ID databases' format (pci.ids and usb.ids, as their headers
//! describe it): a vendor line `vvvv  name`, its devices indented by a tab
//! `\tdddd  name`, their subsystems by two `\t\tssss dddd  name`; and after
//! `C cc  name` lines, the classes' subclasses `\tss  name` and programming
//! interfaces `\t\tpp  name`. `#` starts a comment.

use alloc::collections::BTreeMap;
use alloc::string::String;

#[derive(Default, Debug)]
struct Vendor {
    name: String,
    devices: BTreeMap<u16, Device>,
}

#[derive(Default, Debug)]
struct Device {
    name: String,
    subsystems: BTreeMap<(u16, u16), String>,
}

#[derive(Default, Debug)]
struct Class {
    name: String,
    subclasses: BTreeMap<u8, String>,
}

/// A parsed database.
#[derive(Default, Debug)]
pub struct Ids {
    vendors: BTreeMap<u16, Vendor>,
    classes: BTreeMap<u8, Class>,
}

fn hex16(s: &str) -> Option<u16> {
    u16::from_str_radix(s.get(..4)?, 16).ok()
}

/// "id  name": the name after the ID and its two spaces.
fn name_after(s: &str, id_len: usize) -> Option<String> {
    Some(String::from(s.get(id_len..)?.trim_start()))
}

impl Ids {
    pub fn parse(text: &str) -> Ids {
        let mut ids = Ids::default();
        let (mut vendor, mut device, mut class): (Option<u16>, Option<u16>, Option<u8>) = (None, None, None);
        for line in text.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("C ") {
                vendor = None;
                class = u8::from_str_radix(rest.get(..2).unwrap_or(""), 16).ok();
                if let (Some(c), Some(n)) = (class, name_after(rest, 2)) {
                    ids.classes.insert(c, Class { name: n, subclasses: BTreeMap::new() });
                }
                continue;
            }
            if let Some(rest) = line.strip_prefix("\t\t") {
                if let (Some(v), Some(d)) = (vendor, device) {
                    let (Some(sv), Some(sd)) = (hex16(rest), rest.get(5..).and_then(hex16)) else { continue };
                    let Some(n) = name_after(rest, 9) else { continue };
                    if let Some(dev) = ids.vendors.get_mut(&v).and_then(|x| x.devices.get_mut(&d)) {
                        dev.subsystems.insert((sv, sd), n);
                    }
                }
                continue;
            }
            if let Some(rest) = line.strip_prefix('\t') {
                if let Some(v) = vendor {
                    device = hex16(rest);
                    if let (Some(d), Some(n)) = (device, name_after(rest, 4))
                        && let Some(x) = ids.vendors.get_mut(&v)
                    {
                        x.devices.insert(d, Device { name: n, subsystems: BTreeMap::new() });
                    }
                } else if let Some(c) = class
                    && let (Ok(s), Some(n)) = (u8::from_str_radix(rest.get(..2).unwrap_or(""), 16), name_after(rest, 2))
                    && let Some(x) = ids.classes.get_mut(&c)
                {
                    x.subclasses.insert(s, n);
                }
                continue;
            }
            // A vendor line (or another top-level section, which ends the
            // vendors and classes).
            class = None;
            device = None;
            vendor = hex16(line).filter(|_| line.as_bytes().get(4) == Some(&b' '));
            if let (Some(v), Some(n)) = (vendor, name_after(line, 4)) {
                ids.vendors.insert(v, Vendor { name: n, devices: BTreeMap::new() });
            }
        }
        ids
    }

    pub fn vendor(&self, v: u16) -> Option<&str> {
        self.vendors.get(&v).map(|x| x.name.as_str())
    }

    pub fn device(&self, v: u16, d: u16) -> Option<&str> {
        self.vendors.get(&v)?.devices.get(&d).map(|x| x.name.as_str())
    }

    pub fn subsystem(&self, v: u16, d: u16, sv: u16, sd: u16) -> Option<&str> {
        self.vendors.get(&v)?.devices.get(&d)?.subsystems.get(&(sv, sd)).map(String::as_str)
    }

    /// The subclass's name, else the class's.
    pub fn class(&self, c: u8, s: u8) -> Option<&str> {
        let class = self.classes.get(&c)?;
        Some(class.subclasses.get(&s).map_or(class.name.as_str(), String::as_str))
    }
}

/// The first of `paths` that reads, parsed; an empty database if none.
pub fn load(paths: &[&[u8]]) -> Ids {
    for p in paths {
        if let Ok(b) = slate_rt::fs::read_file(p) {
            return Ids::parse(&String::from_utf8_lossy(&b));
        }
    }
    Ids::default()
}
