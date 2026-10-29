// SPDX-License-Identifier: MIT OR Apache-2.0

//! USB devices in sysfs (ADR 0084), laid out as sysfs-bus-usb(5) and the
//! host's /sys show them. Each xHCI controller is two root hubs, `usbN`
//! for its USB 2 ports and `usbN+1` for its USB 3 ones, under the
//! controller's PCI directory. A device is `N-P` on root port P, `N-P.Q`
//! on port Q of the hub there, nested below its hub. Its interfaces are
//! `N-P:C.I` (configuration C, interface I).
//!
//! Attribute formats are those observed on the host:
//!
//! - `idVendor` `%04x`; `bNumInterfaces` `%2d`; `bMaxPower` `%dmA`;
//!   `version` `%2x.%02x`;
//! - `speed` in Mbit/s (`1.5`, `12`, `480`, `5000`, `10000`);
//! - the device's `descriptors`: its device descriptor, then the
//!   configuration as read;
//! - the `uevent` keys: `DEVTYPE`, `DRIVER`, `PRODUCT`, `TYPE`,
//!   `INTERFACE`, `MODALIAS`, `BUSNUM`, `DEVNUM`.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicU16, Ordering};

use crate::fs::SysEntry;
use crate::sync::IrqSpinLock;

/// Bus numbers, two per controller, in the order controllers start.
static NEXT_BUS: AtomicU16 = AtomicU16::new(1);

/// The drivers bound to interfaces, by the interface's sysfs path (for
/// the `uevent` files, which are made when read).
static BOUND: IrqSpinLock<Vec<(String, &'static str)>> = IrqSpinLock::new(Vec::new());

/// One root hub of a controller.
pub struct RootHub {
    pub bus: u16,
    /// The controller's ports this hub has, in order: its port 1 is the
    /// first of them.
    pub ports: Vec<u8>,
    /// The Supported Protocol capability's revision (BCD, `0x0310`).
    pub revision: u16,
    /// The fastest speed its ports list, in Mbit/s (0: none listed).
    pub mbps: u32,
    /// Device numbers in use (1 is the hub), and the one tried next.
    devnums: IrqSpinLock<(u128, u8)>,
}

/// A controller's place in sysfs.
pub struct Controller {
    pub pci_path: String,
    pub pci_name: String,
    /// The USB 2 hub, then the USB 3 one; a controller without ports of
    /// a kind has no hub for it (and takes no bus number for it), as on
    /// the host.
    pub hubs: Vec<RootHub>,
}

impl Controller {
    /// Root hubs for a controller whose ports have these protocols
    /// (index = port number: the revision, 0 for no port, and the fastest
    /// speed), with their sysfs entries.
    pub fn new(pci: crate::drivers::pci::Address, protocols: &[(u16, u32)], usb2: &[bool]) -> Controller {
        let hub = |want2: bool| {
            let ports: Vec<u8> = (1..protocols.len())
                .filter(|&p| protocols[p].0 != 0 && usb2.get(p).copied().unwrap_or(false) == want2)
                .map(|p| p as u8)
                .collect();
            if ports.is_empty() {
                return None;
            }
            let revision = ports.iter().map(|&p| protocols[usize::from(p)].0).max().unwrap_or(0);
            let mbps = ports.iter().map(|&p| protocols[usize::from(p)].1).max().unwrap_or(0);
            let bus = NEXT_BUS.fetch_add(1, Ordering::Relaxed);
            Some(RootHub { bus, ports, revision, mbps, devnums: IrqSpinLock::new((0b10, 2)) })
        };
        let c = Controller {
            pci_path: crate::drivers::pci_sys::path(pci),
            pci_name: crate::drivers::pci_sys::name(pci),
            hubs: [hub(true), hub(false)].into_iter().flatten().collect(),
        };
        for h in &c.hubs {
            root_hub_entries(&c, h);
        }
        c
    }

    /// The root hub and its port number for the controller's port `port`.
    fn locate(&self, port: u8) -> Option<(&RootHub, usize)> {
        self.hubs.iter().find_map(|h| h.ports.iter().position(|&p| p == port).map(|i| (h, i + 1)))
    }
}

/// `%2x.%02x` of a BCD version (bcdUSB).
fn version(bcd: u16) -> String {
    format!("{:2x}.{:02x}", bcd >> 8, bcd & 0xFF)
}

/// The speed in Mbit/s for a port speed ID (xHCI §7.2.1 default IDs).
fn speed(id: u32) -> &'static str {
    match id {
        super::xhci::SPEED_LOW => "1.5",
        super::xhci::SPEED_FULL => "12",
        super::xhci::SPEED_HIGH => "480",
        super::xhci::SPEED_SUPER => "5000",
        _ => "10000",
    }
}

/// Slate's version as BCD, for the root hubs' bcdDevice (as the host
/// gives its kernel's version there).
fn slate_bcd() -> u16 {
    let mut v = env!("CARGO_PKG_VERSION").split('.').map(|p| p.parse::<u16>().unwrap_or(0));
    let (major, minor) = (v.next().unwrap_or(0), v.next().unwrap_or(0));
    ((major / 10 % 10) << 12) | ((major % 10) << 8) | ((minor / 10 % 10) << 4) | (minor % 10)
}

fn file(p: &str, name: &str, text: String) -> SysEntry {
    SysEntry::File(format!("{p}/{name}"), text)
}

/// `../` back to /sys from `path`.
fn up(path: &str) -> String {
    "../".repeat(path.split('/').count())
}

fn key(c: &Controller, name: &str) -> String {
    format!("usb-{}-{name}", c.pci_name)
}

/// What a device and an interface have in common: the subsystem link and
/// the bus's link to it.
fn bus_links(p: &str, name: &str) -> [SysEntry; 2] {
    [
        SysEntry::Link(format!("{p}/subsystem"), format!("{}bus/usb", up(p))),
        SysEntry::Link(format!("bus/usb/devices/{name}"), format!("../../../{p}")),
    ]
}

/// The fields of a device every device directory shows.
struct Desc<'a> {
    /// The device descriptor (USB 2.0 §9.6.1).
    device: &'a [u8; 18],
    config: &'a slate_usb::Configuration,
    bus: u16,
    devnum: u8,
    devpath: String,
    speed: &'static str,
    /// rx_lanes and tx_lanes.
    lanes: u8,
    superspeed: bool,
    maxchild: Arc<AtomicU8>,
    strings: [Option<String>; 3],
}

fn device_entries(p: &str, name: &str, d: &Desc, out: &mut Vec<SysEntry>) {
    let dd = d.device;
    let w = |i: usize| u16::from_le_bytes([dd[i], dd[i + 1]]);
    let (vendor, product, bcd) = (w(8), w(10), w(12));
    out.push(SysEntry::Dir(String::from(p)));
    for (n, v) in [
        ("idVendor", format!("{vendor:04x}")),
        ("idProduct", format!("{product:04x}")),
        ("bcdDevice", format!("{bcd:04x}")),
        ("bDeviceClass", format!("{:02x}", dd[4])),
        ("bDeviceSubClass", format!("{:02x}", dd[5])),
        ("bDeviceProtocol", format!("{:02x}", dd[6])),
        ("bMaxPacketSize0", format!("{}", dd[7])),
        ("bNumConfigurations", format!("{}", dd[17])),
        ("bConfigurationValue", format!("{}", d.config.value)),
        ("bNumInterfaces", format!("{:2}", d.config.interfaces.iter().filter(|i| i.alt == 0).count())),
        ("bmAttributes", format!("{:02x}", d.config.attributes)),
        ("bMaxPower", format!("{}mA", u32::from(d.config.max_power) * if d.superspeed { 8 } else { 2 })),
        ("busnum", format!("{}", d.bus)),
        ("devnum", format!("{}", d.devnum)),
        ("devpath", d.devpath.clone()),
        ("speed", String::from(d.speed)),
        ("rx_lanes", format!("{}", d.lanes)),
        ("tx_lanes", format!("{}", d.lanes)),
        ("version", version(w(2))),
        ("removable", String::from("unknown")),
        ("authorized", String::from("1")),
    ] {
        out.push(file(p, n, v + "\n"));
    }
    // A hub's driver says how many ports it has after this is made.
    let maxchild = d.maxchild.clone();
    out.push(SysEntry::Generated(
        format!("{p}/maxchild"),
        Arc::new(move |o: &mut Vec<u8>| {
            o.extend_from_slice(format!("{}\n", maxchild.load(Ordering::Relaxed)).as_bytes())
        }),
    ));
    for (n, s) in ["manufacturer", "product", "serial"].iter().zip(&d.strings) {
        if let Some(s) = s {
            out.push(file(p, n, format!("{s}\n")));
        }
    }
    let mut raw = dd.to_vec();
    raw.extend_from_slice(&d.config.raw);
    out.push(SysEntry::Generated(
        format!("{p}/descriptors"),
        Arc::new(move |o: &mut Vec<u8>| o.extend_from_slice(&raw)),
    ));
    out.push(file(
        p,
        "uevent",
        format!(
            "DEVTYPE=usb_device\nDRIVER=usb\nPRODUCT={vendor:x}/{product:x}/{bcd:x}\nTYPE={}/{}/{}\nBUSNUM={:03}\nDEVNUM={:03}\n",
            dd[4], dd[5], dd[6], d.bus, d.devnum
        ),
    ));
    out.extend(bus_links(p, name));
    out.push(SysEntry::Link(format!("{p}/driver"), format!("{}bus/usb/drivers/usb", up(p))));
    out.push(SysEntry::Link(format!("bus/usb/drivers/usb/{name}"), format!("../../../../{p}")));
}

fn interface_entries(
    dir: &str,
    dev_name: &str,
    d: &Desc,
    i: &slate_usb::Interface,
    string: Option<String>,
    out: &mut Vec<SysEntry>,
) {
    let dd = d.device;
    let w = |k: usize| u16::from_le_bytes([dd[k], dd[k + 1]]);
    let (vendor, product, bcd) = (w(8), w(10), w(12));
    let name = format!("{dev_name}:{}.{}", d.config.value, i.number);
    let p = format!("{dir}/{name}");
    let modalias = format!(
        "usb:v{vendor:04X}p{product:04X}d{bcd:04X}dc{:02X}dsc{:02X}dp{:02X}ic{:02X}isc{:02X}ip{:02X}in{:02X}",
        dd[4], dd[5], dd[6], i.class, i.subclass, i.protocol, i.number
    );
    out.push(SysEntry::Dir(p.clone()));
    for (n, v) in [
        ("bInterfaceNumber", format!("{:02x}", i.number)),
        ("bAlternateSetting", format!("{:2}", i.alt)),
        ("bNumEndpoints", format!("{:02x}", i.num_endpoints)),
        ("bInterfaceClass", format!("{:02x}", i.class)),
        ("bInterfaceSubClass", format!("{:02x}", i.subclass)),
        ("bInterfaceProtocol", format!("{:02x}", i.protocol)),
        ("modalias", modalias.clone()),
        ("authorized", String::from("1")),
    ] {
        out.push(file(&p, n, v + "\n"));
    }
    if let Some(s) = string {
        out.push(file(&p, "interface", format!("{s}\n")));
    }
    let fixed = format!(
        "PRODUCT={vendor:x}/{product:x}/{bcd:x}\nTYPE={}/{}/{}\nINTERFACE={}/{}/{}\nMODALIAS={modalias}\n",
        dd[4], dd[5], dd[6], i.class, i.subclass, i.protocol
    );
    let at = p.clone();
    out.push(SysEntry::Generated(
        format!("{p}/uevent"),
        Arc::new(move |o: &mut Vec<u8>| {
            o.extend_from_slice(b"DEVTYPE=usb_interface\n");
            if let Some((_, drv)) = BOUND.lock().iter().find(|(k, _)| *k == at) {
                o.extend_from_slice(format!("DRIVER={drv}\n").as_bytes());
            }
            o.extend_from_slice(fixed.as_bytes());
        }),
    ));
    out.extend(bus_links(&p, &name));
}

/// The root hub's entries: a device with Slate's IDs (the Linux
/// Foundation's 1d6b, product 2 for USB 2 and 3 for USB 3, as root hubs
/// show on the host) and its one hub interface.
fn root_hub_entries(c: &Controller, h: &RootHub) {
    let name = format!("usb{}", h.bus);
    let p = format!("{}/{name}", c.pci_path);
    let usb3 = h.revision >= 0x0300;
    let bcd = slate_bcd();
    let mut device = [0u8; 18];
    device[0] = 18;
    device[1] = super::DESC_DEVICE;
    // bcdUSB: 2.00, or 3.00 or 3.10 (the newest a root hub shows on the
    // host, even on 3.2 controllers).
    let bcd_usb: u16 = if !usb3 {
        0x0200
    } else if h.revision >= 0x0310 {
        0x0310
    } else {
        0x0300
    };
    device[2..4].copy_from_slice(&bcd_usb.to_le_bytes());
    device[4] = 9;
    device[6] = if usb3 { 3 } else { 1 };
    device[7] = if usb3 { 9 } else { 64 };
    device[8..10].copy_from_slice(&0x1d6bu16.to_le_bytes());
    device[10..12].copy_from_slice(&(if usb3 { 3u16 } else { 2 }).to_le_bytes());
    device[12..14].copy_from_slice(&bcd.to_le_bytes());
    device[14..17].copy_from_slice(&[3, 2, 1]);
    device[17] = 1;
    // One configuration, self-powered, with a hub interface and its
    // status-change endpoint.
    let raw = alloc::vec![
        9, 2, 25, 0, 1, 1, 0, 0xE0, 0, // configuration
        9, 4, 0, 0, 1, 9, 0, 0, 0, // interface
        7, 5, 0x81, 3, 4, 0, 12, // endpoint
    ];
    let config = slate_usb::parse_configuration(&raw);
    let d = Desc {
        device: &device,
        config: &config,
        bus: h.bus,
        devnum: 1,
        devpath: String::from("0"),
        // The fastest speed the ports list, but at least the revision's
        // (3.1 is 10 Gbit/s: the reference PC's 15:00.3 lists only 5 in its speed
        // IDs and Fedora shows 10000); 20 Gbit/s is two lanes (USB 3.2
        // Gen 2x2, the only 20 Gbit/s mode).
        speed: match (usb3, h.mbps.max(if h.revision >= 0x0310 { 10000 } else { 5000 })) {
            (false, _) => "480",
            (true, 20000..) => "20000",
            (true, 10000..) => "10000",
            (true, _) => "5000",
        },
        lanes: if usb3 && h.mbps >= 20000 { 2 } else { 1 },
        superspeed: usb3,
        maxchild: Arc::new(AtomicU8::new(h.ports.len() as u8)),
        strings: [
            Some(format!("Slate {} xhci", env!("CARGO_PKG_VERSION"))),
            Some(String::from("xHCI Host Controller")),
            Some(c.pci_name.clone()),
        ],
    };
    let mut out = Vec::new();
    device_entries(&p, &name, &d, &mut out);
    let iface = &config.interfaces[0];
    let if_name = format!("{}-0", h.bus);
    interface_entries(&p, &if_name, &d, iface, None, &mut out);
    let if_path = format!("{p}/{if_name}:1.0");
    bind_entries(&if_path, &format!("{if_name}:1.0"), "usb-hub", &mut out);
    BOUND.lock().push((if_path, "usb-hub"));
    crate::fs::sys_device_add(&key(c, &name), out);
}

fn bind_entries(p: &str, name: &str, driver: &str, out: &mut Vec<SysEntry>) {
    out.push(SysEntry::Link(format!("{p}/driver"), format!("{}bus/usb/drivers/{driver}", up(p))));
    out.push(SysEntry::Link(format!("bus/usb/drivers/{driver}/{name}"), format!("../../../../{p}")));
}

/// A device at `port` (the controller's root port, then hub ports:
/// "3.2") was set up: its name (`1-3.2`) and directory.
pub fn place(c: &Controller, port: &str) -> Option<(u16, String, String)> {
    let mut parts = port.split('.');
    let root: u8 = parts.next()?.parse().ok()?;
    let (hub, rh_port) = c.locate(root)?;
    let rest: Vec<&str> = parts.collect();
    let mut name = format!("{}-{rh_port}", hub.bus);
    let mut path = format!("{}/usb{}/{name}", c.pci_path, hub.bus);
    for q in rest {
        name = format!("{name}.{q}");
        path = format!("{path}/{name}");
    }
    Some((hub.bus, name, path))
}

/// A free device number for the device at `port`, on its bus (2 to 127,
/// the next after the last given, as numbers are handed out on the host).
pub fn take_devnum(c: &Controller, port: &str) -> u8 {
    let Some((bus, _, _)) = place(c, port) else { return 0 };
    let Some(h) = c.hubs.iter().find(|h| h.bus == bus) else { return 0 };
    let mut st = h.devnums.lock();
    for k in 0..126u8 {
        let n = 2 + (st.1 - 2 + k) % 126;
        if st.0 & (1 << n) == 0 {
            st.0 |= 1 << n;
            st.1 = if n == 127 { 2 } else { n + 1 };
            return n;
        }
    }
    0
}

/// What `added` needs to know of a device.
pub struct Added<'a> {
    pub port: &'a str,
    pub devnum: u8,
    pub speed_id: u32,
    pub device: &'a [u8; 18],
    pub config: &'a slate_usb::Configuration,
    /// Manufacturer, product, serial.
    pub strings: [Option<String>; 3],
    /// Each interface's string (by interface number).
    pub interface_strings: Vec<(u8, String)>,
    pub maxchild: Arc<AtomicU8>,
}

/// A device was set up: its directory and its interfaces'.
pub fn added(c: &Controller, a: &Added) {
    let Some((bus, name, p)) = place(c, a.port) else { return };
    let devpath = String::from(name.split_once('-').map_or("", |x| x.1));
    let d = Desc {
        device: a.device,
        config: a.config,
        bus,
        devnum: a.devnum,
        devpath,
        speed: speed(a.speed_id),
        lanes: 1,
        superspeed: a.speed_id >= super::xhci::SPEED_SUPER,
        maxchild: a.maxchild.clone(),
        strings: a.strings.clone(),
    };
    let mut out = Vec::new();
    device_entries(&p, &name, &d, &mut out);
    for i in a.config.interfaces.iter().filter(|i| i.alt == 0) {
        let s = a.interface_strings.iter().find(|(n, _)| *n == i.number).map(|(_, s)| s.clone());
        interface_entries(&p, &name, &d, i, s, &mut out);
    }
    crate::fs::sys_device_add(&key(c, &name), out);
}

/// Driver `driver` took interface `number` of the device at `port`.
pub fn bound(c: &Controller, port: &str, config: u8, number: u8, driver: &'static str) {
    let Some((_, name, p)) = place(c, port) else { return };
    let if_name = format!("{name}:{config}.{number}");
    let if_path = format!("{p}/{if_name}");
    let mut out = Vec::new();
    bind_entries(&if_path, &if_name, driver, &mut out);
    BOUND.lock().push((if_path, driver));
    crate::fs::sys_device_extend(&key(c, &name), out);
}

/// The device at `port` went: its entries and its interfaces' drivers.
pub fn removed(c: &Controller, port: &str) {
    let Some((_, name, p)) = place(c, port) else { return };
    crate::fs::sys_device_remove(&key(c, &name));
    BOUND.lock().retain(|(k, _)| !(k.starts_with(&p) && k[p.len()..].starts_with('/')));
}

/// The device at `port` is no more: its number is free again.
pub fn free_devnum(c: &Controller, port: &str, devnum: u8) {
    let Some((bus, _, _)) = place(c, port) else { return };
    if let Some(h) = c.hubs.iter().find(|h| h.bus == bus)
        && devnum > 1
    {
        h.devnums.lock().0 &= !(1 << devnum);
    }
}
