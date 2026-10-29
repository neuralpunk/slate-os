// SPDX-License-Identifier: MIT OR Apache-2.0

//! `terminal`, Strata's terminal emulator (ADR 0037): a window of
//! Strata showing a pseudo-terminal running the user's shell, drawn in
//! graphite's terminal style (docs/design/WM_STYLE.md §7). The emulation is
//! `slate-term`'s, shared with the kernel's console.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod app;
pub mod keys;
pub mod menu;
pub mod mouse;
pub mod outbox;
pub mod render;
pub mod select;
