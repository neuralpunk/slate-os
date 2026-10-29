// SPDX-License-Identifier: MIT OR Apache-2.0

//! `strata-wl` (ADR 0038): inside a Linux runtime, it shows what a
//! kiosk compositor (Sway, on wlroots' headless backend) draws in a
//! Strata window, and passes the window's keys and pointer back. To the
//! compositor it is a Wayland client: it sizes the output to the window
//! (wlr-output-management), copies frames as they change
//! (wlr-screencopy) and types and points with the virtual keyboard and
//! pointer protocols; it passes the clipboards both ways
//! (wlr-data-control) and shows the active window's title
//! (wlr-foreign-toplevel-management). To Strata it is an ordinary app, and Strata tags
//! its window "linux", since it runs in the Linux domain.
//!
//! The protocol work is ours, from the public protocol descriptions
//! (wayland.xml, wlr-screencopy-unstable-v1, wlr-output-management-
//! unstable-v1, wlr-virtual-pointer-unstable-v1, virtual-keyboard-
//! unstable-v1, wlr-data-control-unstable-v1, wlr-foreign-toplevel-
//! management-unstable-v1); SlateOS itself never speaks Wayland.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod app;
pub mod keymap;
pub mod pixels;
pub mod wire;
