// SPDX-License-Identifier: MIT OR Apache-2.0

//! USB: the xHCI host controller driver and the class drivers on it (HID
//! keyboards and pointers, Bulk-Only mass storage, hubs, ADR 0029; CDC
//! Ethernet, ADR 0046; Bluetooth controllers, ADR 0113).
//!
//! Devices plug into the controller's root ports or into USB 2 hubs
//! (keyboards often have one built in). Descriptors and standard requests
//! follow the USB 2.0 specification, chapter 9; hubs chapter 11.

pub mod btusb;
pub mod ecm;
pub mod hid;
pub mod hub;
pub mod msc;
pub mod sys;
pub mod xhci;

use alloc::vec::Vec;

// Standard requests (USB 2.0 §9.4) and descriptor types (table 9-5).
pub const REQ_CLEAR_FEATURE: u8 = 0x01;
pub const REQ_GET_DESCRIPTOR: u8 = 0x06;
pub const REQ_SET_CONFIGURATION: u8 = 0x09;
pub const DESC_DEVICE: u8 = 1;
pub const DESC_CONFIGURATION: u8 = 2;
/// ENDPOINT_HALT feature selector (table 9-6).
pub const FEATURE_ENDPOINT_HALT: u16 = 0;

/// bmRequestType values: direction, type (standard/class), recipient.
pub const RT_DEVICE_IN: u8 = 0x80;
pub const RT_DEVICE_OUT: u8 = 0x00;
pub const RT_ENDPOINT_OUT: u8 = 0x02;
pub const RT_CLASS_INTERFACE_OUT: u8 = 0x21;

/// Transfer types in bmAttributes (table 9-13).
pub const EP_BULK: u8 = 2;
pub const EP_INTERRUPT: u8 = 3;

/// An endpoint descriptor's useful fields.
#[derive(Clone, Copy, Debug)]
pub struct EndpointDesc {
    /// bEndpointAddress: number in bits 3:0, IN when bit 7 is set.
    pub address: u8,
    pub kind: u8,
    pub max_packet: u16,
    pub interval: u8,
    /// SuperSpeed bulk streams offered: 2^n (0: none).
    pub max_streams: u8,
}

impl EndpointDesc {
    pub fn from(e: &slate_usb::Endpoint) -> EndpointDesc {
        EndpointDesc {
            address: e.address,
            kind: e.kind,
            max_packet: e.max_packet,
            interval: e.interval,
            max_streams: e.max_streams,
        }
    }

    pub fn is_in(&self) -> bool {
        self.address & 0x80 != 0
    }

    /// The xHCI device context index: 2 × number + direction (xHCI §4.5.1).
    pub fn dci(&self) -> u8 {
        (self.address & 0xF) * 2 + u8::from(self.is_in())
    }
}

/// An interface with its endpoints.
#[derive(Clone, Debug)]
pub struct InterfaceDesc {
    pub number: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub endpoints: Vec<EndpointDesc>,
    /// An HID interface's report descriptor length (its HID descriptor).
    pub report_len: Option<u16>,
}

/// The interfaces (first alternate settings only) of a parsed
/// configuration (`slate-usb`, USB 2.0 §9.6.3-§9.6.6).
pub fn first_alternates(c: &slate_usb::Configuration) -> Vec<InterfaceDesc> {
    c.interfaces.iter().filter(|i| i.alt == 0).map(interface).collect()
}

/// One interface (alternate setting) of a parsed configuration.
pub fn interface(i: &slate_usb::Interface) -> InterfaceDesc {
    InterfaceDesc {
        number: i.number,
        class: i.class,
        subclass: i.subclass,
        protocol: i.protocol,
        endpoints: i.endpoints.iter().map(EndpointDesc::from).collect(),
        report_len: slate_usb::hid_report_length(i),
    }
}

/// Whether Slate has a driver for an interface of this class, subclass
/// and protocol (choosing among a device's configurations).
pub fn supported(class: u8, subclass: u8, protocol: u8) -> bool {
    matches!(
        (class, subclass, protocol),
        (3, _, _)
            | (8, 6, 0x50 | 0x62)
            | (9, _, _)
            | (0xE0, 1, 1)
            | (slate_usb::ecm::CLASS_COMM, slate_usb::ecm::SUBCLASS_ECM, _)
    )
}
