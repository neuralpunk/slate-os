// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-loader's core (ADR 0089): what the UEFI and BIOS loaders share.
//! It reads the menu file, lays out the kernel's ELF image, builds the
//! page tables, answers the Limine boot protocol's requests, starts the
//! other CPUs, draws the menu, and jumps to the kernel.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod boot;
pub mod config;
pub mod cpu;
pub mod handoff;
pub mod kernel;
pub mod memmap;
pub mod menu;
pub mod mode;
pub mod mp;
pub mod paging;
pub mod proto;
pub mod screen;
pub mod textmenu;
pub mod trial;

/// The loader's name and version, as the bootloader info response gives
/// them.
pub const NAME: &str = "Slate";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
