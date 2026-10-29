// SPDX-License-Identifier: MIT OR Apache-2.0

//! Slate's Bluetooth host (ADR 0113). The kernel drives the controller's
//! transport (USB, /dev/hci0); everything above it is here, in user space:
//!
//! - [`host`], the HCI host without I/O (host-tested against
//!   `slate_hci::sim`);
//! - [`store`], the pairings kept in /var/lib/slate/bluetooth;
//! - [`proto`], how Settings and slate-bt talk to the daemon;
//! - [`daemon`], slate-btd, a slinit service;
//! - [`cli`], slate-bt.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod cli;
pub mod daemon;
pub mod host;
pub mod proto;
pub mod store;
