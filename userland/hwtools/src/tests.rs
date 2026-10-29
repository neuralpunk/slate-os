// SPDX-License-Identifier: MIT OR Apache-2.0

//! The layouts lspci shows (observed with lspci 3.15 on the host), with a
//! small name database and with none.

use crate::ids::Ids;
use crate::lspci::{Function, Opts, id_filter, line, slot_filter};
use alloc::string::String;

const IDS: &str = "# a comment\n\
1022  Advanced Micro Devices, Inc. [AMD]\n\
\t14b5  Family 17h-19h PCIe Root Complex\n\
\t14ba  Family 17h-19h PCIe GPP Bridge\n\
\t\t1022 1453  A named subsystem\n\
8086  Intel Corporation\n\
C 06  Bridge\n\
\t00  Host bridge\n\
\t04  PCI bridge\n\
C 0c  Serial bus controller\n";

fn root_complex() -> Function {
    Function {
        vendor: 0x1022,
        device: 0x14b5,
        class: 0x060000,
        revision: 1,
        subvendor: 0x1022,
        subdevice: 0x14b5,
        ..Function::default()
    }
}

fn opts(numeric: u8) -> Opts {
    Opts { numeric, ..Opts::default() }
}

#[test]
fn names_numbers_and_neither() {
    let ids = Ids::parse(IDS);
    let none = Ids::default();
    let f = root_complex();
    assert_eq!(
        line(&f, &ids, &opts(0)),
        "00:00.0 Host bridge: Advanced Micro Devices, Inc. [AMD] Family 17h-19h PCIe Root Complex (rev 01)"
    );
    assert_eq!(line(&f, &ids, &opts(1)), "00:00.0 0600: 1022:14b5 (rev 01)");
    assert_eq!(
        line(&f, &ids, &opts(2)),
        "00:00.0 Host bridge [0600]: Advanced Micro Devices, Inc. [AMD] Family 17h-19h PCIe Root Complex [1022:14b5] (rev 01)"
    );
    assert_eq!(line(&f, &none, &opts(0)), "00:00.0 Class 0600: Device 1022:14b5 (rev 01)");
    assert_eq!(line(&f, &none, &opts(2)), "00:00.0 Class [0600]: Device [1022:14b5] (rev 01)");
    // A known vendor, an unknown device; no revision.
    let g = Function { device: 0x14b7, revision: 0, subvendor: 0, subdevice: 0, ..f.clone() };
    assert_eq!(line(&g, &ids, &opts(0)), "00:00.0 Host bridge: Advanced Micro Devices, Inc. [AMD] Device 14b7");
    assert_eq!(
        line(&g, &ids, &opts(2)),
        "00:00.0 Host bridge [0600]: Advanced Micro Devices, Inc. [AMD] Device [1022:14b7]"
    );
    // A class known, its subclass not: the class's name.
    let s = Function { class: 0x0c8000, ..g.clone() };
    assert!(line(&s, &ids, &opts(0)).starts_with("00:00.0 Serial bus controller: "));
}

#[test]
fn kernel_and_machine_formats() {
    let ids = Ids::parse(IDS);
    let none = Ids::default();
    let mut f = root_complex();
    f.driver = Some(String::from("pcieport"));
    let k = Opts { kernel: true, ..Opts::default() };
    assert_eq!(
        line(&f, &ids, &k),
        "00:00.0 Host bridge: Advanced Micro Devices, Inc. [AMD] Family 17h-19h PCIe Root Complex (rev 01)\n\
         \tSubsystem: Advanced Micro Devices, Inc. [AMD] Family 17h-19h PCIe Root Complex\n\
         \tKernel driver in use: pcieport"
    );
    let mm = Opts { machine: true, ..Opts::default() };
    let none_nn = Opts { machine: true, numeric: 2, ..Opts::default() };
    assert_eq!(
        line(&f, &none, &none_nn),
        "00:00.0 \"Class [0600]\" \"Vendor [1022]\" \"Device [14b5]\" -r01 -p00 \"Unknown vendor [1022]\" \"Device [14b5]\""
    );
    assert_eq!(
        line(&f, &ids, &mm),
        "00:00.0 \"Host bridge\" \"Advanced Micro Devices, Inc. [AMD]\" \"Family 17h-19h PCIe Root Complex\" -r01 -p00 \
         \"Advanced Micro Devices, Inc. [AMD]\" \"Family 17h-19h PCIe Root Complex\""
    );
    assert_eq!(
        line(&f, &none, &mm),
        "00:00.0 \"Class 0600\" \"Vendor 1022\" \"Device 14b5\" -r01 -p00 \"Unknown vendor 1022\" \"Device 14b5\""
    );
    let bridge = Function {
        bus: 0,
        slot: 2,
        func: 1,
        device: 0x14ba,
        class: 0x060400,
        revision: 0,
        subvendor: 0x1022,
        subdevice: 0x1453,
        ..f.clone()
    };
    assert_eq!(
        line(&bridge, &ids, &Opts { machine: true, numeric: 1, ..Opts::default() }),
        "00:02.1 \"0604\" \"1022\" \"14ba\" -p00 \"1022\" \"1453\""
    );
    let nosub = Function { subvendor: 0, subdevice: 0, ..f.clone() };
    assert!(line(&nosub, &ids, &mm).ends_with("-r01 -p00 \"\" \"\""));
    let d = Opts { domain: true, numeric: 1, ..Opts::default() };
    assert_eq!(line(&nosub, &ids, &d), "0000:00:00.0 0600: 1022:14b5 (rev 01)");
}

#[test]
fn filters() {
    let f = Function {
        bus: 0x34,
        slot: 0,
        func: 3,
        vendor: 0x1022,
        device: 0x161d,
        class: 0x0c0330,
        ..Function::default()
    };
    let s = |spec: &str| slot_filter(spec).map(|k| k(&f));
    assert_eq!(s("34:00.3"), Some(true));
    assert_eq!(s("34:"), Some(true));
    assert_eq!(s(".3"), Some(true));
    assert_eq!(s("00"), Some(true));
    assert_eq!(s("35:"), Some(false));
    assert_eq!(s("0000:34:00.4"), Some(false));
    assert_eq!(s("zz:"), None);
    let d = |spec: &str| id_filter(spec).map(|k| k(&f));
    assert_eq!(d("1022:"), Some(true));
    assert_eq!(d(":161d"), Some(true));
    assert_eq!(d("::0c03"), Some(true));
    assert_eq!(d("8086:"), Some(false));
    assert_eq!(d("1022"), None);
}

#[test]
fn config_dump() {
    let mut config = [0u8; 272];
    config[0] = 0x22;
    config[256] = 0x10;
    let d = crate::lspci::hex_dump(&config);
    assert!(d.starts_with("00: 22 00 "));
    assert!(d.contains("\nf0: 00"));
    assert!(d.ends_with("100: 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n\n"));
}

mod usb {
    use crate::ids::Ids;
    use crate::lsusb::{Device, Interface, id_filter, line, slot_filter, tree};
    use alloc::string::String;
    use alloc::vec;

    fn s(x: &str) -> Option<String> {
        Some(String::from(x))
    }

    fn iface(number: u8, class: u8, driver: &str) -> Interface {
        Interface { number, class, driver: s(driver) }
    }

    /// A root hub with a hub on port 1 and a keyboard behind it on port 4,
    /// as lsusb -t showed them on the host.
    fn sample() -> alloc::vec::Vec<Device> {
        vec![
            Device {
                name: String::from("usb5"),
                bus: 5,
                devnum: 1,
                vendor: 0x1d6b,
                product: 2,
                speed: String::from("480"),
                lanes: 1,
                maxchild: 1,
                controller_driver: s("xhci_hcd"),
                interfaces: vec![iface(0, 9, "hub")],
                ..Device::default()
            },
            Device {
                name: String::from("5-1"),
                bus: 5,
                devnum: 6,
                vendor: 0x2109,
                product: 0x2817,
                speed: String::from("480"),
                maxchild: 4,
                product_name: s("USB2.0 Hub             "),
                interfaces: vec![iface(0, 9, "hub")],
                ..Device::default()
            },
            Device {
                name: String::from("5-1.4"),
                bus: 5,
                devnum: 7,
                vendor: 0x24f0,
                product: 0x20a1,
                speed: String::from("12"),
                manufacturer: s("Das Keyboard"),
                product_name: s("Das Keyboard 6 Pro"),
                interfaces: vec![iface(0, 3, "usbhid"), Interface { number: 1, class: 3, driver: None }],
                ..Device::default()
            },
        ]
    }

    #[test]
    fn lines() {
        let ids = Ids::parse("1d6b  Linux Foundation\n\t0002  2.0 root hub\n2109  VIA Labs, Inc.\n");
        let d = sample();
        assert_eq!(line(&d[0], &ids), "Bus 005 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub");
        // The vendor's name from the database, the product's from the device.
        assert_eq!(line(&d[1], &ids), "Bus 005 Device 006: ID 2109:2817 VIA Labs, Inc. USB2.0 Hub             ");
        assert_eq!(line(&d[2], &Ids::default()), "Bus 005 Device 007: ID 24f0:20a1 Das Keyboard Das Keyboard 6 Pro");
    }

    #[test]
    fn the_tree() {
        assert_eq!(
            tree(&sample()),
            "/:  Bus 005.Port 001: Dev 001, Class=root_hub, Driver=xhci_hcd/1p, 480M\n\
             \x20   |__ Port 001: Dev 006, If 0, Class=Hub, Driver=hub/4p, 480M\n\
             \x20       |__ Port 004: Dev 007, If 0, Class=Human Interface Device, Driver=usbhid, 12M\n\
             \x20       |__ Port 004: Dev 007, If 1, Class=Human Interface Device, Driver=[none], 12M\n"
        );
        // A USB 3.2 Gen 2x2 root hub, as the reference PC's Fedora shows it.
        let gen2x2 = Device {
            name: String::from("usb2"),
            bus: 2,
            devnum: 1,
            speed: String::from("20000"),
            lanes: 2,
            maxchild: 5,
            controller_driver: s("xhci_hcd"),
            ..Device::default()
        };
        assert_eq!(tree(&[gen2x2]), "/:  Bus 002.Port 001: Dev 001, Class=root_hub, Driver=xhci_hcd/5p, 20000M/x2\n");
    }

    #[test]
    fn filters() {
        let d = &sample()[2];
        assert_eq!(slot_filter("5:7").map(|k| k(d)), Some(true));
        assert_eq!(slot_filter("7").map(|k| k(d)), Some(true));
        assert_eq!(slot_filter("5:").map(|k| k(d)), Some(true));
        assert_eq!(slot_filter("4:7").map(|k| k(d)), Some(false));
        assert_eq!(id_filter("24f0:").map(|k| k(d)), Some(true));
        assert_eq!(id_filter(":20a2").map(|k| k(d)), Some(false));
        assert!(id_filter("24f0").is_none());
    }
}
