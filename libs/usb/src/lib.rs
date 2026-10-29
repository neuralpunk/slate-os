// SPDX-License-Identifier: MIT OR Apache-2.0

//! USB descriptors and the Ethernet class (ADR 0046): parsing that needs
//! no hardware, so it is tested on the host.
//!
//! Sources: USB 2.0 specification chapter 9 (standard descriptors, §9.6);
//! USB Class Definitions for Communications Devices 1.2 (CDC: class codes
//! §4, functional descriptors §5.2.3); USB CDC Subclass Specification for
//! Ethernet Control Model Devices 1.2 (ECM: the Ethernet Networking
//! functional descriptor §5.4, requests §6.2, notifications §6.3).

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

/// Descriptor types (USB 2.0 table 9-5) and CDC's class-specific
/// interface descriptor (CDC table 12).
pub const DESC_STRING: u8 = 3;
pub const DESC_INTERFACE: u8 = 4;
pub const DESC_ENDPOINT: u8 = 5;
pub const DESC_CS_INTERFACE: u8 = 0x24;
/// A SuperSpeed endpoint companion (USB 3.2 §9.6.7).
pub const DESC_SS_COMPANION: u8 = 0x30;
/// UAS pipe IDs (UAS 1.0 table 6).
pub const PIPE_COMMAND: u8 = 1;
pub const PIPE_STATUS: u8 = 2;
pub const PIPE_DATA_IN: u8 = 3;
pub const PIPE_DATA_OUT: u8 = 4;
/// The HID descriptor (HID 1.11 §6.2.1), between an HID interface and its
/// endpoints, and the report descriptor type it lists.
pub const DESC_HID: u8 = 0x21;
pub const DESC_HID_REPORT: u8 = 0x22;

/// Endpoint transfer types (bmAttributes, USB 2.0 table 9-13).
pub const EP_BULK: u8 = 2;
pub const EP_INTERRUPT: u8 = 3;

/// An endpoint descriptor's fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// bEndpointAddress: number in bits 3:0, IN when bit 7 is set.
    pub address: u8,
    pub kind: u8,
    pub max_packet: u16,
    pub interval: u8,
    /// A SuperSpeed bulk endpoint's streams, as the exponent its
    /// companion descriptor gives (2^n streams; 0: none). USB 3.2 §9.6.7:
    /// bmAttributes bits 4:0.
    pub max_streams: u8,
    /// The UAS pipe it is (UAS 1.0 §5.3.3.1, the Pipe Usage descriptor
    /// after it: 1 command, 2 status, 3 data in, 4 data out; 0 none).
    pub pipe: u8,
}

impl Endpoint {
    pub fn is_in(&self) -> bool {
        self.address & 0x80 != 0
    }
}

/// An interface (one alternate setting) with its endpoints and the
/// class-specific descriptors that follow it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub number: u8,
    pub alt: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    /// bNumEndpoints as the descriptor gives it.
    pub num_endpoints: u8,
    /// iInterface: the index of its string descriptor (0: none).
    pub string: u8,
    pub endpoints: Vec<Endpoint>,
    /// Class-specific interface descriptors, whole (length and type
    /// included).
    pub extra: Vec<Vec<u8>>,
}

/// A configuration descriptor set (USB 2.0 §9.6.3-§9.6.6): every
/// interface and alternate setting, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Configuration {
    /// bConfigurationValue: what SET_CONFIGURATION takes.
    pub value: u8,
    /// bmAttributes (self-powered, remote wakeup) and bMaxPower (2 mA
    /// units, 8 mA at SuperSpeed: USB 3.2 §9.6.3).
    pub attributes: u8,
    pub max_power: u8,
    pub interfaces: Vec<Interface>,
    /// The descriptors as read.
    pub raw: Vec<u8>,
}

/// The endpoint parsed last.
fn last_endpoint(c: &mut Configuration) -> Option<&mut Endpoint> {
    c.interfaces.last_mut().and_then(|f| f.endpoints.last_mut())
}

/// Parse a configuration descriptor and what follows it. Malformed
/// trailing data is ignored.
pub fn parse_configuration(data: &[u8]) -> Configuration {
    let at = |i: usize| data.get(i).copied().unwrap_or(0);
    let mut c =
        Configuration { value: at(5), attributes: at(7), max_power: at(8), interfaces: Vec::new(), raw: data.to_vec() };
    let mut i = 0;
    // The descriptor before: an endpoint's companion and Pipe Usage
    // descriptors follow it.
    let mut after_endpoint = false;
    while i + 2 <= data.len() {
        let len = usize::from(data[i]);
        if len < 2 || i + len > data.len() {
            break;
        }
        let d = &data[i..i + len];
        if after_endpoint && d[1] == DESC_SS_COMPANION && len >= 6 {
            if let Some(e) = last_endpoint(&mut c)
                && e.kind == EP_BULK
            {
                e.max_streams = d[3] & 0x1F;
            }
            i += len;
            continue;
        }
        if after_endpoint && d[1] == DESC_CS_INTERFACE && len == 4 {
            if let Some(e) = last_endpoint(&mut c) {
                e.pipe = d[2];
            }
            i += len;
            continue;
        }
        after_endpoint = d[1] == DESC_ENDPOINT;
        match d[1] {
            DESC_INTERFACE if len >= 9 => c.interfaces.push(Interface {
                number: d[2],
                alt: d[3],
                class: d[5],
                subclass: d[6],
                protocol: d[7],
                num_endpoints: d[4],
                string: d[8],
                endpoints: Vec::new(),
                extra: Vec::new(),
            }),
            DESC_ENDPOINT if len >= 7 => {
                if let Some(iface) = c.interfaces.last_mut() {
                    iface.endpoints.push(Endpoint {
                        address: d[2],
                        kind: d[3] & 3,
                        max_packet: u16::from_le_bytes([d[4], d[5]]) & 0x7FF,
                        interval: d[6],
                        max_streams: 0,
                        pipe: 0,
                    });
                }
            }
            DESC_CS_INTERFACE | DESC_HID => {
                if let Some(iface) = c.interfaces.last_mut() {
                    iface.extra.push(d.to_vec());
                }
            }
            _ => {}
        }
        i += len;
    }
    c
}

/// The length of an HID interface's report descriptor, from its HID
/// descriptor (HID 1.11 §6.2.1: bNumDescriptors at 5, then a type and a
/// 16-bit length for each class descriptor): what GET_DESCRIPTOR asks for.
pub fn hid_report_length(iface: &Interface) -> Option<u16> {
    let d = iface.extra.iter().find(|d| d.len() >= 9 && d[1] == DESC_HID)?;
    let n = usize::from(d[5]);
    (0..n).find_map(|k| {
        let e = d.get(6 + 3 * k..9 + 3 * k)?;
        (e[0] == DESC_HID_REPORT).then(|| u16::from_le_bytes([e[1], e[2]]))
    })
}

/// A string descriptor's text (UTF-16LE after the two header bytes;
/// characters outside Latin-1 become '?').
pub fn string_text(desc: &[u8]) -> Vec<u8> {
    let len = usize::from(desc.first().copied().unwrap_or(0)).min(desc.len());
    if len < 2 || desc.get(1) != Some(&DESC_STRING) {
        return Vec::new();
    }
    desc[2..len]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| {
            let u = u16::from_le_bytes([c[0], c[1]]);
            if u < 0x100 { u as u8 } else { b'?' }
        })
        .collect()
}

/// A string descriptor's text as UTF-8 (USB 2.0 §9.6.7: UTF-16LE after
/// the two header bytes; unpaired surrogates become U+FFFD).
pub fn string_utf8(desc: &[u8]) -> alloc::string::String {
    let len = usize::from(desc.first().copied().unwrap_or(0)).min(desc.len());
    if len < 2 || desc.get(1) != Some(&DESC_STRING) {
        return alloc::string::String::new();
    }
    let units = desc[2..len].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c));
    char::decode_utf16(units).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)).collect()
}

pub mod ecm {
    //! The Ethernet Control Model (CDC ECM 1.2).

    use super::{Configuration, EP_BULK, EP_INTERRUPT, Endpoint};

    /// Communications Interface Class and the ECM subclass (CDC tables 3
    /// and 4), and the Data Interface Class (CDC table 6).
    pub const CLASS_COMM: u8 = 0x02;
    pub const SUBCLASS_ECM: u8 = 0x06;
    pub const CLASS_DATA: u8 = 0x0A;
    /// Functional descriptor subtypes (CDC table 13).
    const FD_UNION: u8 = 0x06;
    const FD_ETHERNET: u8 = 0x0F;

    /// SET_ETHERNET_PACKET_FILTER (ECM table 6) and its filter bits (ECM
    /// table 8).
    pub const SET_ETHERNET_PACKET_FILTER: u8 = 0x43;
    pub const FILTER_ALL_MULTICAST: u16 = 1 << 1;
    pub const FILTER_DIRECTED: u16 = 1 << 2;
    pub const FILTER_BROADCAST: u16 = 1 << 3;

    /// An ECM function found in a configuration.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Function {
        /// The communications (control) interface and the data interface.
        pub control: u8,
        pub data: u8,
        /// The data interface's alternate setting with the bulk endpoints
        /// (alternate 0 has none: selecting this one starts the traffic,
        /// ECM §3.3).
        pub data_alt: u8,
        /// The string descriptor index of the MAC address.
        pub mac_string: u8,
        /// The largest Ethernet frame, header included.
        pub max_segment: u16,
        pub notify: Option<Endpoint>,
        pub bulk_in: Endpoint,
        pub bulk_out: Endpoint,
    }

    /// The first ECM function in `c`.
    pub fn find(c: &Configuration) -> Option<Function> {
        let comm = c.interfaces.iter().find(|i| i.class == CLASS_COMM && i.subclass == SUBCLASS_ECM)?;
        let mut data_if = None;
        let (mut mac_string, mut max_segment) = (0, 1514);
        for d in &comm.extra {
            match d.get(2) {
                // Union: bControlInterface, bSubordinateInterface0 (CDC
                // §5.2.3.2).
                Some(&FD_UNION) if d.len() >= 5 => data_if = Some(d[4]),
                // Ethernet Networking (ECM §5.4): iMACAddress at 3,
                // wMaxSegmentSize at 8.
                Some(&FD_ETHERNET) if d.len() >= 13 => {
                    mac_string = d[3];
                    max_segment = u16::from_le_bytes([d[8], d[9]]);
                }
                _ => {}
            }
        }
        // Without a union descriptor, the data interface is the next one.
        let data_if = data_if.unwrap_or(comm.number + 1);
        let data = c.interfaces.iter().find(|i| {
            i.number == data_if
                && i.class == CLASS_DATA
                && i.endpoints.iter().any(|e| e.kind == EP_BULK && e.is_in())
                && i.endpoints.iter().any(|e| e.kind == EP_BULK && !e.is_in())
        })?;
        let notify = comm.endpoints.iter().copied().find(|e| e.kind == EP_INTERRUPT && e.is_in());
        Some(Function {
            control: comm.number,
            data: data.number,
            data_alt: data.alt,
            mac_string,
            max_segment: max_segment.max(1514),
            notify,
            bulk_in: *data.endpoints.iter().find(|e| e.kind == EP_BULK && e.is_in())?,
            bulk_out: *data.endpoints.iter().find(|e| e.kind == EP_BULK && !e.is_in())?,
        })
    }

    /// The MAC address in an iMACAddress string: twelve hex digits, most
    /// significant first (ECM §5.4).
    pub fn parse_mac(text: &[u8]) -> Option<[u8; 6]> {
        if text.len() != 12 {
            return None;
        }
        let hex = |c: u8| (c as char).to_digit(16).map(|v| v as u8);
        let mut mac = [0u8; 6];
        for (i, m) in mac.iter_mut().enumerate() {
            *m = hex(text[2 * i])? << 4 | hex(text[2 * i + 1])?;
        }
        Some(mac)
    }

    /// A notification on the interrupt endpoint (ECM §6.3).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Notification {
        /// NETWORK_CONNECTION: the link is up (true) or down.
        Connection(bool),
        /// CONNECTION_SPEED_CHANGE: downstream and upstream bits per second.
        Speed(u32, u32),
        Other(u8),
    }

    /// Parse a notification: an eight-byte header (bmRequestType,
    /// bNotificationCode, wValue, wIndex, wLength) and its data.
    pub fn parse_notification(b: &[u8]) -> Option<Notification> {
        if b.len() < 8 || b[0] != 0xA1 {
            return None;
        }
        let value = u16::from_le_bytes([b[2], b[3]]);
        Some(match b[1] {
            0x00 => Notification::Connection(value != 0),
            0x2A if b.len() >= 16 => Notification::Speed(
                u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
                u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
            ),
            code => Notification::Other(code),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn strings_and_configuration_fields() {
        // "Hé€" and an unpaired surrogate.
        let d = [10, DESC_STRING, b'H', 0, 0xE9, 0, 0xAC, 0x20, 0x00, 0xD8];
        assert_eq!(string_utf8(&d), "Hé€\u{FFFD}");
        assert_eq!(string_utf8(&[2, 2]), "");
        let c = parse_configuration(&[9, 2, 18, 0, 1, 3, 0, 0xA0, 50, 9, 4, 0, 0, 2, 3, 1, 1, 7]);
        assert_eq!((c.value, c.attributes, c.max_power, c.raw.len()), (3, 0xA0, 50, 18));
        assert_eq!((c.interfaces[0].num_endpoints, c.interfaces[0].string), (2, 7));
    }

    /// A configuration shaped like a USB 3 Ethernet adapter's CDC one: a
    /// communications interface with header, union and Ethernet
    /// descriptors and an interrupt endpoint, then a data interface whose
    /// alternate 0 is empty and alternate 1 has the bulk pair.
    fn ecm_config() -> Vec<u8> {
        let mut d = vec![9, 2, 0, 0, 2, 2, 0, 0xA0, 50];
        d.extend([9, 4, 0, 0, 1, 2, 6, 0, 5]); // comm interface
        d.extend([5, 0x24, 0, 0x10, 0x01]); // header
        d.extend([5, 0x24, 6, 0, 1]); // union: control 0, data 1
        d.extend([13, 0x24, 0x0F, 3, 0, 0, 0, 0, 0xEA, 0x05, 0, 0, 0]); // ethernet: MAC string 3, 1514
        d.extend([7, 5, 0x83, 3, 16, 0, 8]); // interrupt IN 3
        d.extend([9, 4, 1, 0, 0, 0x0A, 0, 0, 0]); // data alt 0
        d.extend([9, 4, 1, 1, 2, 0x0A, 0, 0, 0]); // data alt 1
        d.extend([7, 5, 0x81, 2, 0, 4, 0]); // bulk IN 1, 1024
        d.extend([7, 5, 0x02, 2, 0, 4, 0]); // bulk OUT 2
        let len = d.len() as u16;
        d[2..4].copy_from_slice(&len.to_le_bytes());
        d
    }

    #[test]
    fn parses_alternates_and_class_descriptors() {
        let c = parse_configuration(&ecm_config());
        assert_eq!(c.value, 2);
        assert_eq!(c.interfaces.len(), 3);
        assert_eq!(c.interfaces[0].extra.len(), 3);
        assert_eq!((c.interfaces[2].number, c.interfaces[2].alt), (1, 1));
        assert_eq!(c.interfaces[2].endpoints[0].max_packet, 1024);
    }

    #[test]
    fn finds_the_ecm_function() {
        let f = ecm::find(&parse_configuration(&ecm_config())).unwrap();
        assert_eq!((f.control, f.data, f.data_alt, f.mac_string, f.max_segment), (0, 1, 1, 3, 1514));
        assert_eq!(f.bulk_in.address, 0x81);
        assert_eq!(f.bulk_out.address, 0x02);
        assert_eq!(f.notify.map(|e| e.address), Some(0x83));
    }

    #[test]
    fn no_ecm_in_a_vendor_configuration() {
        let mut d = vec![9, 2, 0, 0, 1, 1, 0, 0xA0, 50];
        d.extend([9, 4, 0, 0, 2, 0xFF, 0xFF, 0, 0]);
        d.extend([7, 5, 0x81, 2, 0, 4, 0]);
        d.extend([7, 5, 0x02, 2, 0, 4, 0]);
        assert_eq!(ecm::find(&parse_configuration(&d)), None);
    }

    #[test]
    fn mac_strings() {
        let mut desc = vec![26, 3];
        for c in b"5254001234aB" {
            desc.extend([*c, 0]);
        }
        let text = string_text(&desc);
        assert_eq!(text, b"5254001234aB");
        assert_eq!(ecm::parse_mac(&text), Some([0x52, 0x54, 0x00, 0x12, 0x34, 0xAB]));
        assert_eq!(ecm::parse_mac(b"52540012"), None);
        assert_eq!(ecm::parse_mac(b"5254001234zz"), None);
    }

    #[test]
    fn notifications() {
        use ecm::Notification::*;
        assert_eq!(ecm::parse_notification(&[0xA1, 0, 1, 0, 0, 0, 0, 0]), Some(Connection(true)));
        assert_eq!(ecm::parse_notification(&[0xA1, 0, 0, 0, 0, 0, 0, 0]), Some(Connection(false)));
        let mut s = vec![0xA1, 0x2A, 0, 0, 0, 0, 8, 0];
        s.extend(1_000_000_000u32.to_le_bytes());
        s.extend(100_000_000u32.to_le_bytes());
        assert_eq!(ecm::parse_notification(&s), Some(Speed(1_000_000_000, 100_000_000)));
        assert_eq!(ecm::parse_notification(&[0x21, 0, 1, 0, 0, 0, 0, 0]), None);
    }

    /// The G900 mouse's configuration (046d:c081, as lsusb -v reads it on
    /// the reference PC): a boot mouse interface and a second HID interface whose
    /// report descriptor is 151 bytes.
    #[test]
    fn hid_descriptor_lengths() {
        let config = [
            9, 2, 59, 0, 2, 1, 0, 0xA0, 50, // configuration
            9, 4, 0, 0, 1, 3, 1, 2, 0, // interface 0: HID, boot, mouse
            9, 0x21, 0x11, 0x01, 0, 1, 0x22, 67, 0, // HID descriptor: 67 bytes
            7, 5, 0x81, 3, 8, 0, 1, // endpoint 1 IN, interrupt
            9, 4, 1, 0, 1, 3, 0, 0, 0, // interface 1: HID
            9, 0x21, 0x11, 0x01, 0, 1, 0x22, 151, 0, // HID descriptor: 151 bytes
            7, 5, 0x82, 3, 20, 0, 1, // endpoint 2 IN, interrupt
        ];
        let c = parse_configuration(&config);
        assert_eq!(c.interfaces.len(), 2);
        assert_eq!(hid_report_length(&c.interfaces[0]), Some(67));
        assert_eq!(hid_report_length(&c.interfaces[1]), Some(151));
        assert_eq!(c.interfaces[1].endpoints[0].max_packet, 20);
    }

    /// A UAS interface as UAS 1.0 lays it out (§5.3.3): alternate setting 0
    /// Bulk-Only, alternate setting 1 UAS with four bulk endpoints, each
    /// with a SuperSpeed companion (32 streams on the three that stream)
    /// and a Pipe Usage descriptor.
    #[test]
    fn uas_pipes_and_streams() {
        let mut config = alloc::vec![9, 2, 0, 0, 1, 1, 0, 0x80, 50];
        config.extend([9, 4, 0, 0, 2, 8, 6, 0x50, 0]);
        config.extend([7, 5, 0x81, 2, 0, 4, 0, 6, 0x30, 0, 0, 0, 0]);
        config.extend([7, 5, 0x02, 2, 0, 4, 0, 6, 0x30, 0, 0, 0, 0]);
        config.extend([9, 4, 0, 1, 4, 8, 6, 0x62, 0]);
        for (address, streams, pipe) in [(0x04u8, 0u8, 1u8), (0x83, 5, 2), (0x85, 5, 3), (0x06, 5, 4)] {
            config.extend([7, 5, address, 2, 0, 4, 0]);
            config.extend([6, 0x30, 0, streams, 0, 0]);
            config.extend([4, 0x24, pipe, 0]);
        }
        let c = parse_configuration(&config);
        assert_eq!(c.interfaces.len(), 2);
        let bot = &c.interfaces[0];
        assert_eq!((bot.alt, bot.protocol, bot.endpoints.len()), (0, 0x50, 2));
        let uas = &c.interfaces[1];
        assert_eq!((uas.alt, uas.protocol), (1, 0x62));
        let pipes: Vec<(u8, u8, u8)> = uas.endpoints.iter().map(|e| (e.address, e.max_streams, e.pipe)).collect();
        assert_eq!(pipes, [(0x04, 0, 1), (0x83, 5, 2), (0x85, 5, 3), (0x06, 5, 4)]);
        assert!(uas.extra.is_empty());
    }
}
