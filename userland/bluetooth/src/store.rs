// SPDX-License-Identifier: MIT OR Apache-2.0

//! What slate-btd keeps (ADR 0113), in /var/lib/slate/bluetooth (root's
//! alone, mode 0700): `settings` (whether Bluetooth is on) and a file per
//! paired device under `devices/`, named by its address, holding its
//! name, kind, link key and key type. /var survives system rollbacks
//! (ADR 0027), so pairings do too.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_hci::{BdAddr, Kind};

use crate::host::Device;

pub const DIR: &str = "/var/lib/slate/bluetooth";

/// A paired device's file.
pub fn device_text(d: &Device) -> Option<String> {
    let (key, kind) = d.key?;
    let hex: String = key.iter().map(|b| alloc::format!("{b:02x}")).collect();
    Some(alloc::format!("name={}\nkind={}\nkey={hex}\ntype={kind}\n", d.name.replace('\n', " "), d.kind.word()))
}

/// A device from its file (`addr` is the file's name).
pub fn parse_device(addr: &str, text: &str) -> Option<Device> {
    let addr = BdAddr::parse(addr)?;
    let field = |k: &str| text.lines().find_map(|l| l.strip_prefix(k)?.strip_prefix('=')).map(str::to_string);
    let hex = field("key")?;
    if hex.len() != 32 {
        return None;
    }
    let mut key = [0u8; 16];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(Device {
        addr,
        name: field("name").unwrap_or_default(),
        kind: Kind::from_word(&field("kind").unwrap_or_default()),
        page_scan_mode: 1,
        clock_offset: 0,
        nearby: false,
        key: Some((key, field("type").and_then(|t| t.parse().ok()).unwrap_or(0))),
        connected: None,
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
        };
        let text = device_text(&d).unwrap();
        assert_eq!(text, "name=Ada's Phone\nkind=phone\nkey=abababababababababababababababab\ntype=8\n");
        let back = parse_device("5C:F3:70:11:22:33", &text).unwrap();
        assert_eq!((back.addr, back.name.as_str(), back.kind, back.key), (d.addr, "Ada's Phone", Kind::Phone, d.key));
        assert!(!back.nearby && back.connected.is_none());
        assert!(parse_device("nonsense", &text).is_none());
        assert!(parse_device("5C:F3:70:11:22:33", "name=x\nkey=12\n").is_none());
        assert!(device_text(&Device { key: None, ..d }).is_none());
    }
}
