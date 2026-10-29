// SPDX-License-Identifier: MIT OR Apache-2.0

//! PCI functions in /sys (M23 phase 7): each function's directory under
//! /sys/devices, below the bridge that leads to its bus (`pci0000:00` for
//! the host bridge's), with its identification, a `config` file that
//! reads its configuration space as it is now, and a `uevent` file; the
//! /sys/bus/pci/devices links, and the driver's link once one takes it.
//!
//! Laid out as Linux lays them out (observed on the host: paths, file
//! names, the hex formats), the attributes as the kernel's ABI
//! documentation (sysfs-bus-pci) describes them. A function's `irq` is
//! its interrupt line register; Slate's vectors have no Linux IRQ numbers.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::pci::{Address, Device};
use crate::fs::SysEntry;

/// The function's name in /sys (domain 0).
pub fn name(a: Address) -> String {
    format!("0000:{:02x}:{:02x}.{:x}", a.bus, a.device, a.function)
}

/// The function's directory, relative to /sys:
/// `devices/pci0000:00[/<bridge>...]/0000:bb:dd.f`.
pub fn path(a: Address) -> String {
    let mut at = a;
    let mut chain = alloc::vec![name(a)];
    for _ in 0..32 {
        if at.bus == 0 {
            break;
        }
        let Some(b) = super::pci::devices()
            .into_iter()
            .find(|d| d.read8(0x0E) & 0x7F == 1 && d.read8(0x19) == at.bus)
            .map(|d| d.address)
        else {
            break;
        };
        chain.push(name(b));
        at = b;
    }
    chain.reverse();
    format!("devices/pci0000:00/{}", chain.join("/"))
}

/// `../` once for each component of `p`: from inside `p` to /sys.
fn up(p: &str) -> String {
    "../".repeat(p.split('/').count())
}

fn key(a: Address) -> String {
    format!("pci-{}", name(a))
}

/// A function appeared (at boot or plugged in): its entries.
pub fn added(d: &Arc<Device>) {
    let a = d.address;
    let p = path(a);
    let bridge = d.read8(0x0E) & 0x7F == 1;
    // A bridge's header (type 1) has no subsystem IDs; it may give them in
    // a Subsystem ID capability (ID 0Dh: vendor at +4, device at +6; PCI
    // Bridge Architecture spec, the capability list).
    let (sv, sd) = if bridge {
        d.capability(0x0D).map_or((0, 0), |c| (d.read16(c + 4), d.read16(c + 6)))
    } else {
        (d.read16(0x2C), d.read16(0x2E))
    };
    let class = (u32::from(d.class) << 16) | (u32::from(d.subclass) << 8) | u32::from(d.prog_if);
    let modalias = format!(
        "pci:v{:08X}d{:08X}sv{sv:08X}sd{sd:08X}bc{:02X}sc{:02X}i{:02X}",
        d.vendor, d.device, d.class, d.subclass, d.prog_if
    );
    let f = |n: &str, t: String| SysEntry::File(format!("{p}/{n}"), t);
    let dev = d.clone();
    let config: crate::fs::tmpfs::Generator = Arc::new(move |out: &mut Vec<u8>| {
        out.reserve(dev.config_size());
        for off in (0..dev.config_size()).step_by(4) {
            out.extend_from_slice(&dev.read32(off).to_le_bytes());
        }
    });
    let (vendor, device, slot) = (d.vendor, d.device, name(a));
    let ma = modalias.clone();
    let uevent: crate::fs::tmpfs::Generator = Arc::new(move |out: &mut Vec<u8>| {
        let mut s = String::new();
        if let Some(drv) = crate::drivers::bound_to(a) {
            s.push_str(&format!("DRIVER={drv}\n"));
        }
        s.push_str(&format!(
            "PCI_CLASS={class:X}\nPCI_ID={vendor:04X}:{device:04X}\nPCI_SUBSYS_ID={sv:04X}:{sd:04X}\nPCI_SLOT_NAME={slot}\nMODALIAS={ma}\n"
        ));
        out.extend_from_slice(s.as_bytes());
    });
    let entries = alloc::vec![
        SysEntry::Dir(p.clone()),
        f("vendor", format!("0x{:04x}\n", d.vendor)),
        f("device", format!("0x{:04x}\n", d.device)),
        f("subsystem_vendor", format!("0x{sv:04x}\n")),
        f("subsystem_device", format!("0x{sd:04x}\n")),
        f("class", format!("0x{class:06x}\n")),
        f("revision", format!("0x{:02x}\n", d.revision)),
        f("irq", format!("{}\n", d.read8(0x3C))),
        f("enable", String::from("1\n")),
        f("numa_node", String::from("-1\n")),
        f("modalias", format!("{modalias}\n")),
        SysEntry::Generated(format!("{p}/config"), config),
        SysEntry::Generated(format!("{p}/uevent"), uevent),
        SysEntry::Link(format!("{p}/subsystem"), format!("{}bus/pci", up(&p))),
        SysEntry::Link(format!("bus/pci/devices/{}", name(a)), format!("../../../{p}")),
    ];
    crate::fs::sys_device_add(&key(a), entries);
}

/// Driver `driver` took the function: its `driver` link, and the
/// driver's link to it.
pub fn bound(a: Address, driver: &str) {
    let p = path(a);
    let entries = alloc::vec![
        SysEntry::Link(format!("{p}/driver"), format!("{}bus/pci/drivers/{driver}", up(&p))),
        SysEntry::Link(format!("bus/pci/drivers/{driver}/{}", name(a)), format!("../../../../{p}")),
    ];
    crate::fs::sys_device_extend(&key(a), entries);
}

/// The function went (ejected): its entries go.
pub fn removed(a: Address) {
    crate::fs::sys_device_remove(&key(a));
}
