// SPDX-License-Identifier: MIT OR Apache-2.0

//! What slate-btd keeps (ADR 0113), in /var/lib/slate/bluetooth (root's
//! alone, mode 0700): `settings` (whether Bluetooth is on) and a file per
//! paired device under `devices/`, named by its address, holding its
//! name, kind, link key and key type; an LE device's (ADR 0176) its
//! address type, long-term key, EDIV, Rand, whether Secure Connections
//! made it, its identity key and address, and whether it paired by itself.
//! /var survives system rollbacks (ADR 0027), so pairings do too; the
//! installers carry the live system's to the installed one.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_hci::{BdAddr, Kind};

use crate::host::{Device, LeInfo};

pub const DIR: &str = "/var/lib/slate/bluetooth";

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| alloc::format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// A paired device's file.
pub fn device_text(d: &Device) -> Option<String> {
    let head = alloc::format!("name={}\nkind={}\n", d.name.replace('\n', " "), d.kind.word());
    if let Some(LeInfo { addr_type, keys: Some(k), auto }) = &d.le {
        let mut t = head;
        t += &alloc::format!(
            "le={}\nltk={}\nediv={}\nrand={}\nsecure={}\nauto={}\n",
            if *addr_type == 1 { "random" } else { "public" },
            hex(&k.ltk),
            k.ediv,
            k.rand,
            u8::from(k.secure),
            u8::from(*auto)
        );
        if let Some(irk) = k.irk {
            t += &alloc::format!("irk={}\n", hex(&irk));
        }
        if let Some((kind, a)) = k.identity {
            t += &alloc::format!("identity={kind} {a}\n");
        }
        return Some(t);
    }
    let (key, kind) = d.key?;
    Some(alloc::format!("{head}key={}\ntype={kind}\n", hex(&key)))
}

/// A device from its file (`addr` is the file's name).
pub fn parse_device(addr: &str, text: &str) -> Option<Device> {
    let addr = BdAddr::parse(addr)?;
    let field = |k: &str| text.lines().find_map(|l| l.strip_prefix(k)?.strip_prefix('=')).map(str::to_string);
    if let Some(le) = field("le") {
        let keys = slate_hci::smp::Keys {
            ltk: unhex(&field("ltk")?)?,
            ediv: field("ediv")?.parse().ok()?,
            rand: field("rand")?.parse().ok()?,
            secure: field("secure").as_deref() == Some("1"),
            irk: field("irk").and_then(|h| unhex(&h)),
            identity: field("identity").and_then(|v| {
                let (k, a) = v.split_once(' ')?;
                Some((k.parse().ok()?, BdAddr::parse(a)?))
            }),
        };
        return Some(Device {
            addr,
            name: field("name").unwrap_or_default(),
            kind: Kind::from_word(&field("kind").unwrap_or_default()),
            page_scan_mode: 0,
            clock_offset: 0,
            nearby: false,
            key: None,
            connected: None,
            le: Some(LeInfo {
                addr_type: u8::from(le == "random"),
                keys: Some(keys),
                auto: field("auto").as_deref() == Some("1"),
            }),
        });
    }
    let key = unhex::<16>(&field("key")?)?;
    Some(Device {
        addr,
        name: field("name").unwrap_or_default(),
        kind: Kind::from_word(&field("kind").unwrap_or_default()),
        page_scan_mode: 1,
        clock_offset: 0,
        nearby: false,
        key: Some((key, field("type").and_then(|t| t.parse().ok()).unwrap_or(0))),
        connected: None,
        le: None,
    })
}

fn path(rel: &str) -> Vec<u8> {
    alloc::format!("{DIR}/{rel}").into_bytes()
}

/// The paired devices on the disk.
pub fn load() -> Vec<Device> {
    let Ok(entries) = slate_rt::fs::read_dir(&path("devices")) else { return Vec::new() };
    let mut out: Vec<Device> = entries
        .iter()
        .filter_map(|e| {
            let name = String::from(slate_rt::lossy(&e.name));
            let text = slate_rt::fs::read_file(&path(&alloc::format!("devices/{name}"))).ok()?;
            parse_device(&name, &slate_rt::lossy(&text))
        })
        .collect();
    out.sort_by_key(|d| d.addr);
    out
}

/// Write the paired devices: each one's file, and none for the others.
pub fn save(devices: &[Device]) -> Result<(), String> {
    for d in ["/var/lib/slate", DIR] {
        let _ = slate_rt::fs::mkdir(d.as_bytes(), 0o700);
    }
    let _ = slate_rt::fs::mkdir(&path("devices"), 0o700);
    let keep: Vec<String> = devices.iter().filter(|d| d.paired()).map(|d| d.addr.to_string()).collect();
    for d in devices {
        let Some(text) = device_text(d) else { continue };
        let (file, tmp) =
            (path(&alloc::format!("devices/{}", d.addr)), path(&alloc::format!("devices/.{}.new", d.addr)));
        slate_rt::fs::write_file(&tmp, text.as_bytes(), 0o600).map_err(|e| alloc::format!("{e}"))?;
        slate_rt::fs::rename(&tmp, &file).map_err(|e| alloc::format!("{e}"))?;
    }
    if let Ok(entries) = slate_rt::fs::read_dir(&path("devices")) {
        for e in entries {
            let name = String::from(slate_rt::lossy(&e.name));
            if !name.starts_with('.') && !keep.contains(&name) {
                let _ = slate_rt::fs::unlink(&path(&alloc::format!("devices/{name}")));
            }
        }
    }
    Ok(())
}

/// The identity resolving key this computer hands out when it pairs an
/// LE device: made once, kept.
pub fn irk() -> [u8; 16] {
    if let Ok(t) = slate_rt::fs::read_file(&path("irk"))
        && let Some(k) = unhex::<16>(slate_rt::lossy(&t).trim())
    {
        return k;
    }
    let mut k = [0u8; 16];
    let _ = slate_rt::process::random(&mut k);
    for d in ["/var/lib/slate", DIR] {
        let _ = slate_rt::fs::mkdir(d.as_bytes(), 0o700);
    }
    let _ = slate_rt::fs::write_file(&path("irk"), alloc::format!("{}\n", hex(&k)).as_bytes(), 0o600);
    k
}

/// Whether Bluetooth was left on (it is, unless turned off).
pub fn powered() -> bool {
    !slate_rt::fs::read_file(&path("settings"))
        .is_ok_and(|t| slate_rt::lossy(&t).lines().any(|l| l.trim() == "power=off"))
}

pub fn set_powered(on: bool) -> Result<(), String> {
    for d in ["/var/lib/slate", DIR] {
        let _ = slate_rt::fs::mkdir(d.as_bytes(), 0o700);
    }
    let text = if on { "power=on\n" } else { "power=off\n" };
    slate_rt::fs::write_file(&path("settings"), text.as_bytes(), 0o600).map(|_| ()).map_err(|e| alloc::format!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_files() {
        let d = Device {
            addr: BdAddr([0x5C, 0xF3, 0x70, 0x11, 0x22, 0x33]),
            name: "Ada's Phone".into(),
            kind: Kind::Phone,
            page_scan_mode: 1,
            clock_offset: 0x1234,
            nearby: true,
            key: Some(([0xAB; 16], 8)),
            connected: Some(11),
            le: None,
        };
        let text = device_text(&d).unwrap();
        assert_eq!(text, "name=Ada's Phone\nkind=phone\nkey=abababababababababababababababab\ntype=8\n");
        let back = parse_device("5C:F3:70:11:22:33", &text).unwrap();
        assert_eq!((back.addr, back.name.as_str(), back.kind, back.key), (d.addr, "Ada's Phone", Kind::Phone, d.key));
        assert!(!back.nearby && back.connected.is_none());
        assert!(parse_device("nonsense", &text).is_none());
        assert!(parse_device("5C:F3:70:11:22:33", "name=x\nkey=12\n").is_none());
        assert!(device_text(&Device { key: None, ..d.clone() }).is_none());
        // An LE device: its keys and identity, and that it paired by itself.
        let keys = slate_hci::smp::Keys {
            ltk: [0x11; 16],
            ediv: 513,
            rand: 77,
            secure: true,
            irk: Some([0x22; 16]),
            identity: Some((1, BdAddr([0xDA, 0xDB, 0, 0x8C, 0xD8, 0xE5]))),
        };
        let m = Device {
            addr: BdAddr([0xDA, 0xDB, 0, 0x8C, 0xD8, 0xE5]),
            name: "Logi M650 L B".into(),
            kind: Kind::Mouse,
            key: None,
            le: Some(LeInfo { addr_type: 1, keys: Some(keys), auto: true }),
            ..d
        };
        let text = device_text(&m).unwrap();
        let back = parse_device("DA:DB:00:8C:D8:E5", &text).unwrap();
        assert_eq!((&back.le, back.kind, back.name.as_str()), (&m.le, Kind::Mouse, "Logi M650 L B"));
        assert!(back.paired());
    }
}
