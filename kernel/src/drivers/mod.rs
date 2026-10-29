// SPDX-License-Identifier: MIT OR Apache-2.0

//! Device drivers.

pub mod acpi_events;
pub mod ahci;
pub mod amd;
pub mod aml;
pub mod dma;
pub mod drm;
pub mod fbcon;
pub mod firmware;
pub mod ide;
pub mod igb;
pub mod input;
pub mod iommu;
pub mod nvme;
pub mod pci;
pub mod pci_sys;
pub mod ps2;
pub mod rtc;
pub mod rtl8139;
pub mod usb;
pub mod virtio;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::sync::IrqSpinLock;

/// When a PCI driver is started: virtio first (the boot framebuffer is a
/// card only if no GPU driver took it), then storage, network and USB.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stage {
    Virtio,
    Storage,
    Network,
    Usb,
}

/// How a PCI driver finds and starts its devices.
pub struct PciDriver {
    pub stage: Stage,
    pub matches: fn(&pci::Device) -> bool,
    pub probe: fn(Arc<pci::Device>) -> Option<()>,
    /// Stop using a device that is about to go (hot-plug): `None` for
    /// drivers whose devices cannot be removed yet.
    pub remove: Option<fn(&Arc<pci::Device>)>,
}

/// A driver Slate has (ADR 0081): its name for `slate.disable=` and
/// /proc/slate_drivers, what it drives, and for PCI drivers how they are
/// matched and started. The first matching driver takes a device.
pub struct Driver {
    pub name: &'static str,
    pub what: &'static str,
    pub pci: Option<PciDriver>,
}

const fn pci_driver(
    name: &'static str,
    what: &'static str,
    stage: Stage,
    matches: fn(&pci::Device) -> bool,
    probe: fn(Arc<pci::Device>) -> Option<()>,
) -> Driver {
    Driver { name, what, pci: Some(PciDriver { stage, matches, probe, remove: None }) }
}

/// A PCI driver that can let its devices go (hot-plug).
const fn removable(d: Driver, remove: fn(&Arc<pci::Device>)) -> Driver {
    match d.pci {
        Some(p) => Driver { pci: Some(PciDriver { remove: Some(remove), ..p }), ..d },
        None => d,
    }
}

/// Every driver. PCI class codes are from the PCI Code and ID Assignment
/// Specification (class 01h: 01h IDE, 06h/01h AHCI, 08h/02h NVMe; class
/// 0Ch/03h/30h xHCI).
pub const DRIVERS: &[Driver] = &[
    pci_driver(
        "virtio-blk",
        "virtio block devices",
        Stage::Virtio,
        |d| virtio::device_type(d) == Some(virtio::ID_BLOCK),
        virtio::blk::probe,
    ),
    pci_driver(
        "virtio-net",
        "virtio network cards",
        Stage::Virtio,
        |d| virtio::device_type(d) == Some(virtio::ID_NET),
        virtio::net::probe,
    ),
    pci_driver(
        "virtio-gpu",
        "virtio GPUs",
        Stage::Virtio,
        |d| virtio::device_type(d) == Some(virtio::ID_GPU),
        virtio::gpu::probe,
    ),
    pci_driver(
        "virtio-input",
        "virtio keyboards, mice and tablets",
        Stage::Virtio,
        |d| virtio::device_type(d) == Some(virtio::ID_INPUT),
        virtio::input::probe,
    ),
    pci_driver(
        "ahci",
        "AHCI SATA controllers",
        Stage::Storage,
        |d| (d.class, d.subclass, d.prog_if) == (0x01, 0x06, 0x01),
        ahci::probe,
    ),
    removable(
        pci_driver(
            "nvme",
            "NVMe controllers",
            Stage::Storage,
            |d| (d.class, d.subclass, d.prog_if) == (0x01, 0x08, 0x02),
            nvme::probe,
        ),
        nvme::remove,
    ),
    pci_driver("ide", "IDE (PATA) controllers", Stage::Storage, |d| (d.class, d.subclass) == (0x01, 0x01), ide::probe),
    pci_driver(
        "igb",
        "Intel gigabit network cards (igb family)",
        Stage::Network,
        |d| d.vendor == 0x8086 && igb::DEVICE_IDS.contains(&d.device),
        igb::probe,
    ),
    pci_driver(
        "rtl8139",
        "Realtek RTL8139 network cards",
        Stage::Network,
        |d| (d.vendor, d.device) == (rtl8139::VENDOR, rtl8139::DEVICE),
        rtl8139::probe,
    ),
    pci_driver(
        "amd-display",
        "AMD display engines (RDNA 2 integrated GPUs: found, not yet driven; ADR 0171)",
        Stage::Network,
        amd::matches,
        amd::probe,
    ),
    pci_driver(
        "xhci",
        "USB host controllers (xHCI)",
        Stage::Usb,
        |d| (d.class, d.subclass, d.prog_if) == (0x0C, 0x03, 0x30),
        usb::xhci::probe,
    ),
    Driver { name: "usb-hid", what: "USB keyboards, mice and tablets", pci: None },
    Driver { name: "usb-storage", what: "USB mass storage (Bulk-Only)", pci: None },
    Driver { name: "usb-uas", what: "USB Attached SCSI (else storage uses Bulk-Only)", pci: None },
    Driver { name: "usb-hub", what: "USB hubs", pci: None },
    Driver { name: "usb-ecm", what: "USB Ethernet adapters (CDC-ECM)", pci: None },
    Driver { name: "ps2", what: "PS/2 keyboards and mice (i8042)", pci: None },
];

/// The names `slate.disable=` gives (comma separated; the option may
/// appear more than once).
pub fn disabled_in(cmdline: &str) -> Vec<&str> {
    cmdline
        .split_ascii_whitespace()
        .filter_map(|w| w.strip_prefix("slate.disable="))
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .collect()
}

static DISABLED: slate_sync::Once<Vec<String>> = slate_sync::Once::new();

fn disabled() -> &'static [String] {
    DISABLED.call_once(|| {
        let names = disabled_in(crate::boot::info().cmdline);
        for n in &names {
            if DRIVERS.iter().any(|d| d.name == *n) {
                crate::log_info!("{n} disabled (slate.disable)");
            } else {
                crate::log_warn!("slate.disable names {n:?}, which is not a driver");
            }
        }
        names.into_iter().map(String::from).collect()
    })
}

/// Whether driver `name` may start.
pub fn enabled(name: &str) -> bool {
    !disabled().iter().any(|n| n == name)
}

/// What each driver did: (driver, device, outcome), for /proc/slate_drivers.
static BOUND: IrqSpinLock<Vec<(&'static str, String, &'static str)>> = IrqSpinLock::new(Vec::new());

/// Record that driver `name` took `device` (or skipped it, or failed).
pub fn record(name: &'static str, device: String, outcome: &'static str) {
    BOUND.lock().push((name, device, outcome));
}

/// The driver that has the PCI function at `a` now, if any.
pub fn bound_to(a: pci::Address) -> Option<&'static str> {
    let device = alloc::format!("{a:?}");
    let bound = BOUND.lock();
    let last = bound.iter().rev().find(|(_, d, _)| *d == device)?;
    (last.2 == "bound").then_some(last.0)
}

/// Start the PCI drivers of `stage` on the devices they match.
pub fn probe_pci(stage: Stage) {
    probe_devices(&pci::devices(), Some(stage));
}

/// Start drivers on `devices` (those of `stage`, or of any stage).
fn probe_devices(devices: &[Arc<pci::Device>], stage: Option<Stage>) {
    for d in devices {
        let Some((drv, pd)) = DRIVERS
            .iter()
            .filter_map(|drv| drv.pci.as_ref().map(|pd| (drv, pd)))
            .find(|(_, pd)| stage.is_none_or(|s| pd.stage == s) && (pd.matches)(d))
        else {
            continue;
        };
        let device = alloc::format!("{:?}", d.address);
        if !enabled(drv.name) {
            crate::log_info!("{} {device}: driver disabled; device left alone", drv.name);
            record(drv.name, device, "disabled");
        } else if (pd.probe)(d.clone()).is_some() {
            record(drv.name, device, "bound");
            pci_sys::bound(d.address, drv.name);
        } else {
            crate::log_warn!("{} {device}: initialization failed", drv.name);
            record(drv.name, device, "failed");
        }
    }
}

/// A device was plugged into slot `device` of bus `bus` (ACPI device
/// check): find its functions and start their drivers.
pub fn hot_add(bus: u8, device: u8) {
    let added = pci::hot_add(bus, device);
    probe_devices(&added, None);
}

/// The device in slot `device` of bus `bus` is to be ejected: stop its
/// drivers and take it off the bus. Returns false if a driver cannot let
/// go of it (it must then stay).
pub fn hot_remove(bus: u8, device: u8) -> bool {
    let devices: Vec<Arc<pci::Device>> =
        pci::devices().into_iter().filter(|d| d.address.bus == bus && d.address.device == device).collect();
    for d in &devices {
        let name = alloc::format!("{:?}", d.address);
        let bound =
            BOUND.lock().iter().rev().find(|(_, dev, outcome)| *dev == name && *outcome == "bound").map(|b| b.0);
        let Some(drv) = bound.and_then(|n| DRIVERS.iter().find(|d| d.name == n)) else { continue };
        match drv.pci.as_ref().and_then(|p| p.remove) {
            Some(remove) => {
                remove(d);
                record(drv.name, name, "removed");
            }
            None => {
                crate::log_warn!("{} {name}: the driver cannot let the device go; not ejected", drv.name);
                return false;
            }
        }
    }
    pci::remove_slot(bus, device);
    true
}

/// Probe the network cards Slate has drivers for (besides virtio).
pub fn init_network() {
    probe_pci(Stage::Network);
}

/// Probe the USB host controllers. Devices are set up by each
/// controller's own thread.
pub fn init_usb() {
    probe_pci(Stage::Usb);
}

/// Probe the PCI storage controllers.
pub fn init_storage() {
    probe_pci(Stage::Storage);
}

/// /proc/slate_drivers: each driver, on or off, what it drives, and the
/// devices it took, skipped or failed on.
pub fn proc_drivers(s: &mut String) {
    use core::fmt::Write;
    let bound = BOUND.lock().clone();
    for drv in DRIVERS {
        let state = if enabled(drv.name) { "on" } else { "off" };
        let _ = writeln!(s, "{:<14} {state:<4} {}", drv.name, drv.what);
        for (_, device, outcome) in bound.iter().filter(|(n, ..)| *n == drv.name) {
            let _ = writeln!(s, "{:<14} {:<4} {device} {outcome}", "", "");
        }
    }
}

pub const TESTS: &[crate::ktest::Test] = &[crate::ktest::Test { name: "drivers::registry", run: test_registry }];

/// The command line's list is read as written; names are unique; the
/// test machine's `slate.disable=rtl8139` (a card it does not have) is
/// off; drivers that took the test machine's disks say so.
fn test_registry() -> Result<(), &'static str> {
    if disabled_in("ro slate.disable=nvme, slate.disable=ahci,,ide quiet") != ["nvme", "ahci", "ide"] {
        return Err("slate.disable= read wrongly");
    }
    for (i, d) in DRIVERS.iter().enumerate() {
        if DRIVERS[..i].iter().any(|e| e.name == d.name) {
            return Err("two drivers share a name");
        }
    }
    if enabled("rtl8139") || !enabled("nvme") {
        return Err("the command line's slate.disable=rtl8139 was not applied");
    }
    let mut s = String::new();
    proc_drivers(&mut s);
    let line = |name: &str| s.lines().find(|l| l.starts_with(name)).unwrap_or("");
    if !line("rtl8139 ").contains(" off ") || !line("nvme ").contains(" on ") {
        return Err("/proc/slate_drivers shows the wrong states");
    }
    if !s.contains(" bound") {
        return Err("no driver took a device");
    }
    Ok(())
}
