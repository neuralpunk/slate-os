// SPDX-License-Identifier: MIT OR Apache-2.0

//! Slate's own hardware listing tools (ADR 0012: ours, written from the
//! outputs observed on the host, not from pciutils or usbutils): `lspci`
//! and `lsusb`, which read /sys, with the names of a pci.ids or usb.ids
//! file if one is installed (Slate ships none).

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod ids;
pub mod lspci;
pub mod lsusb;

#[cfg(test)]
mod tests;
