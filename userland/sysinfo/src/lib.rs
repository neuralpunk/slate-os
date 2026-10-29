// SPDX-License-Identifier: MIT OR Apache-2.0

//! What Slate's apps say about the computer (ADR 0110): Help's "About
//! this system", Settings' About, and the System Monitor read it here.
//! The graphics cards and displays come from /sys/class/drm.
//! The parsers are host-tested; the readers take /proc and /sys as the
//! kernel gives them (proc(5)'s formats). [`procs`] and [`load`] are what
//! the System Monitor shows, [`block`] what Disks shows (ADR 0112).

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub mod block;
pub mod load;
pub mod procs;

/// What About this system shows: (label, value).
pub fn about() -> Vec<(String, String)> {
    let read = |p: &str| slate_rt::fs::read_file(p.as_bytes()).ok().map(|b| String::from(slate_rt::lossy(&b)));
    let mut rows = Vec::new();
    let release = read("/usr/share/slate/release").map(|r| r.trim().to_string());
    rows.push(("release".to_string(), release.unwrap_or_else(|| "Slate".into())));
    let u = slate_rt::process::uname();
    let field = |b: &[u8]| String::from(slate_rt::lossy(b));
    // The Linux interface's release: Slate's programs are told Slate's own
    // (ADR 0153), so it comes from /proc/sys/slate/linux_release.
    let linux = read("/proc/sys/slate/linux_release").map_or_else(|| field(&u[2]), |r| r.trim().to_string());
    rows.push(("kernel".into(), kernel(read("/proc/version").as_deref().unwrap_or(""), &linux)));
    rows.push(("computer name".into(), field(&u[1])));
    if let Some(cpu) = read("/proc/cpuinfo") {
        rows.push(("processor".into(), processor(&cpu)));
    }
    if let Some(m) = read("/proc/meminfo").and_then(|m| memory(&m)) {
        rows.push(("memory".into(), m));
    }
    for (name, text) in disks() {
        rows.push((name, text));
    }
    rows.extend(graphics());
    if let Some(up) = read("/proc/uptime").and_then(|u| uptime(&u)) {
        rows.push(("up for".into(), up));
    }
    rows.push(("desktop".into(), "Strata".into()));
    rows
}

/// Slate's kernel and the Linux interface it offers, from /proc/version
/// ("Slate version 0.1.0 ..." as Slate's programs read it, "Linux version
/// 6.12.0-slate ... Slate 0.1.0" as Linux programs do) and the Linux
/// release: "Slate 0.1.0 (Linux 6.12 interface)".
pub fn kernel(version: &str, release: &str) -> String {
    let ours = match version.strip_prefix("Slate version ") {
        Some(rest) => rest.split_whitespace().next().map(|v| alloc::format!("Slate {v}")),
        None => version.find("Slate ").map(|i| version[i..].trim().to_string()),
    };
    let linux: Vec<&str> = release.split(['.', '-']).take(2).collect();
    match ours {
        Some(o) if linux.len() == 2 => alloc::format!("{o} (Linux {}.{} interface)", linux[0], linux[1]),
        Some(o) => o,
        None => alloc::format!("Linux {release}"),
    }
}

/// "AMD Ryzen 9 7950X × 32" from /proc/cpuinfo.
pub fn processor(cpuinfo: &str) -> String {
    let model = cpuinfo
        .lines()
        .find_map(|l| l.strip_prefix("model name").and_then(|r| r.split_once(':')).map(|(_, v)| v.trim()))
        .unwrap_or("unknown");
    let n = cpuinfo.lines().filter(|l| l.starts_with("processor")).count().max(1);
    let model = model.split_whitespace().collect::<Vec<_>>().join(" ");
    alloc::format!("{model} × {n}")
}

/// MemTotal from /proc/meminfo, in GiB (or MiB below one).
pub fn memory(meminfo: &str) -> Option<String> {
    let kb: u64 = meminfo.lines().find_map(|l| l.strip_prefix("MemTotal:"))?.split_whitespace().next()?.parse().ok()?;
    Some(size(kb * 1024))
}

/// A size in bytes, as people read it: "476.9 GiB".
pub fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 || v >= 100.0 {
        alloc::format!("{} {}", (v + 0.5) as u64, UNITS[u])
    } else {
        let tenths = (v * 10.0 + 0.5) as u64;
        alloc::format!("{}.{} {}", tenths / 10, tenths % 10, UNITS[u])
    }
}

/// "3 days, 4 hours" from /proc/uptime.
pub fn uptime(text: &str) -> Option<String> {
    let s = text.split_whitespace().next()?.split('.').next()?.parse::<u64>().ok()?;
    let (d, h, m) = (s / 86_400, (s / 3600) % 24, (s / 60) % 60);
    let unit = |n: u64, one: &str| if n == 1 { alloc::format!("1 {one}") } else { alloc::format!("{n} {one}s") };
    Some(match (d, h) {
        (0, 0) => unit(m, "minute"),
        (0, _) => alloc::format!("{}, {}", unit(h, "hour"), unit(m, "minute")),
        _ => alloc::format!("{}, {}", unit(d, "day"), unit(h, "hour")),
    })
}

/// The disks in /sys/block (not RAM disks, loops or mapped devices):
/// ("disk sda", "Samsung SSD 980 PRO, 931.5 GiB").
pub fn disks() -> Vec<(String, String)> {
    let Ok(entries) = slate_rt::fs::read_dir(b"/sys/block") else { return Vec::new() };
    let mut names: Vec<String> = entries.iter().map(|e| String::from(slate_rt::lossy(&e.name))).collect();
    names.sort();
    let read = |p: String| slate_rt::fs::read_file(p.as_bytes()).ok().map(|b| String::from(slate_rt::lossy(&b).trim()));
    names
        .into_iter()
        .filter(|n| !["ram", "loop", "dm-", "zram"].iter().any(|p| n.starts_with(p)))
        .filter_map(|n| {
            let sectors: u64 = read(alloc::format!("/sys/block/{n}/size"))?.parse().ok()?;
            if sectors == 0 {
                return None;
            }
            let model = read(alloc::format!("/sys/block/{n}/device/model")).filter(|m| !m.is_empty());
            let s = size(sectors * 512);
            Some((alloc::format!("disk {n}"), model.map_or_else(|| s.clone(), |m| alloc::format!("{m}, {s}"))))
        })
        .collect()
}

/// The graphics cards and the displays on them, from /sys/class/drm (the
/// cards, and each connector's `status`, `modes` and `edid`).
pub fn graphics() -> Vec<(String, String)> {
    let Ok(entries) = slate_rt::fs::read_dir(b"/sys/class/drm") else { return Vec::new() };
    let mut names: Vec<String> = entries.iter().map(|e| String::from(slate_rt::lossy(&e.name))).collect();
    names.sort();
    let text = |p: &str| slate_rt::fs::read_file(p.as_bytes()).ok().map(|b| String::from(slate_rt::lossy(&b).trim()));
    let link = |p: &str| slate_rt::fs::readlink(p.as_bytes()).ok().map(|b| String::from(slate_rt::lossy(&b)));
    let mut cards = Vec::new();
    let mut displays = Vec::new();
    for n in &names {
        let at = alloc::format!("/sys/class/drm/{n}");
        if n.starts_with("card") && !n.contains('-') {
            // card0 -> ../../devices/pci0000:00/0000:00:02.0/drm/card0
            let target = link(&at).unwrap_or_default();
            let parts: Vec<&str> = target.split('/').collect();
            let device = parts.iter().position(|p| *p == "drm").and_then(|i| i.checked_sub(1)).map(|i| parts[i]);
            let driver = link(&alloc::format!("{at}/device/driver"));
            let driver = driver.as_deref().and_then(|d| d.rsplit('/').next());
            let ids = text(&alloc::format!("{at}/device/vendor")).zip(text(&alloc::format!("{at}/device/device")));
            cards.push(card_text(device.unwrap_or(""), driver, ids.as_ref().map(|(v, d)| (v.as_str(), d.as_str()))));
        } else if n.starts_with("card") && text(&alloc::format!("{at}/status")).as_deref() == Some("connected") {
            let edid = slate_rt::fs::read_file(alloc::format!("{at}/edid").as_bytes()).unwrap_or_default();
            let modes = text(&alloc::format!("{at}/modes")).unwrap_or_default();
            displays.extend(display_text(&edid, &modes));
        }
    }
    let label = |what: &str, i: usize, all: usize| {
        if all > 1 { alloc::format!("{what} {}", i + 1) } else { what.to_string() }
    };
    let (nc, nd) = (cards.len(), displays.len());
    let mut rows: Vec<(String, String)> =
        cards.into_iter().enumerate().map(|(i, c)| (label("graphics", i, nc), c)).collect();
    rows.extend(displays.into_iter().enumerate().map(|(i, d)| (label("display", i, nd), d)));
    rows
}

/// A graphics card, from its device's name under /sys/devices, its
/// driver and its PCI vendor and device numbers: "virtio-gpu (PCI
/// 1af4:1050)", or "firmware framebuffer" for the one the firmware set up,
/// or for the AMD driver's (a DRM card only with AMD's firmware, full
/// graphics, ADR 0173) "AMD (PCI 1002:164e): Slate's driver with AMD's
/// firmware".
pub fn card_text(device: &str, driver: Option<&str>, ids: Option<(&str, &str)>) -> String {
    if device.starts_with("simple-framebuffer") || device.starts_with("efi-framebuffer") {
        return String::from("firmware framebuffer");
    }
    // Slate's AMD driver drives a card only with AMD's firmware (ADR 0173).
    if driver == Some("amd-display") {
        let ids =
            ids.map(|(v, d)| alloc::format!(" (PCI {}:{})", v.trim_start_matches("0x"), d.trim_start_matches("0x")));
        return alloc::format!("AMD{}: Slate's driver with AMD's firmware", ids.unwrap_or_default());
    }
    let name = driver.map_or_else(|| String::from("graphics card"), String::from);
    match ids {
        Some((v, d)) => alloc::format!("{name} (PCI {}:{})", v.trim_start_matches("0x"), d.trim_start_matches("0x")),
        None => name,
    }
}

/// A display, from its EDID's name and its preferred mode (the first of
/// `modes`): "QEMU Monitor, 1280 × 800". An EDID Slate made for an output
/// without one (vendor SLT) names nothing.
pub fn display_text(edid: &[u8], modes: &str) -> Option<String> {
    let mode = modes.lines().next().and_then(|m| m.split_once('x')).map(|(w, h)| alloc::format!("{w} × {h}"));
    let name = slate_edid::parse(edid)
        .filter(|e| &e.vendor != b"SLT")
        .map(|e| String::from(slate_rt::lossy(&e.name[..e.name_len.min(13)]).trim()))
        .filter(|n| !n.is_empty());
    match (name, mode) {
        (Some(n), Some(m)) => Some(alloc::format!("{n}, {m}")),
        (Some(n), None) => Some(n),
        (None, Some(m)) => Some(m),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graphics_lines() {
        assert_eq!(card_text("simple-framebuffer.0", None, None), "firmware framebuffer");
        assert_eq!(
            card_text("0000:00:02.0", Some("virtio-gpu"), Some(("0x1af4", "0x1050"))),
            "virtio-gpu (PCI 1af4:1050)"
        );
        assert_eq!(card_text("0000:00:02.0", None, None), "graphics card");
        // Medusa's iGPU with full graphics (ADR 0173).
        assert_eq!(
            card_text("0000:00:04.0", Some("amd-display"), Some(("0x1002", "0x164e"))),
            "AMD (PCI 1002:164e): Slate's driver with AMD's firmware"
        );
        let d = slate_edid::Display {
            vendor: *b"QEM",
            product: 1,
            serial: 1,
            year: 2026,
            name: "QEMU Monitor",
            size_mm: (0, 0),
            timing: slate_edid::Timing {
                clock_khz: 65_000,
                hactive: 1024,
                hsync_start: 1048,
                hsync_end: 1184,
                htotal: 1344,
                vactive: 768,
                vsync_start: 771,
                vsync_end: 777,
                vtotal: 806,
                hsync_positive: false,
                vsync_positive: false,
            },
        };
        let edid = slate_edid::build(&d);
        assert_eq!(display_text(&edid, "1280x800\n1024x768\n").as_deref(), Some("QEMU Monitor, 1280 × 800"));
        let made = slate_edid::build(&slate_edid::Display { vendor: *b"SLT", ..d });
        assert_eq!(display_text(&made, "1280x800\n").as_deref(), Some("1280 × 800"));
        assert_eq!(display_text(&[], ""), None);
    }

    #[test]
    fn hardware_lines() {
        let cpu = "processor\t: 0\nmodel name\t: AMD Ryzen 9 7950X  16-Core Processor\nprocessor\t: 1\n";
        assert_eq!(processor(cpu), "AMD Ryzen 9 7950X 16-Core Processor × 2");
        let v = "Linux version 6.12.0-slate (slate@slate) #1 SMP PREEMPT Slate 0.1.0\n";
        assert_eq!(kernel(v, "6.12.0-slate"), "Slate 0.1.0 (Linux 6.12 interface)");
        let v = "Slate version 0.1.0 (slate@slate) #1 SMP PREEMPT\n";
        assert_eq!(kernel(v, "6.12.0-slate"), "Slate 0.1.0 (Linux 6.12 interface)");
        assert_eq!(kernel("", "6.1.0"), "Linux 6.1.0");
        assert_eq!(memory("MemTotal:       131072000 kB\n").as_deref(), Some("125 GiB"));
        assert_eq!(memory("MemTotal: 4026532 kB\n").as_deref(), Some("3.8 GiB"));
        assert_eq!(size(500_107_862_016), "466 GiB");
        assert_eq!(size(512), "512 B");
        assert_eq!(uptime("200000.5 1.0").as_deref(), Some("2 days, 7 hours"));
        assert_eq!(uptime("3700.0 1").as_deref(), Some("1 hour, 1 minute"));
        assert_eq!(uptime("59 1").as_deref(), Some("0 minutes"));
    }
}
