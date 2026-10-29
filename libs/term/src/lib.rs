// SPDX-License-Identifier: MIT OR Apache-2.0

//! Text console building blocks, independent of hardware: Slate's bitmap
//! font, a terminal emulator, and a PC keyboard decoder. The kernel's
//! framebuffer console and PS/2 driver use them; everything is unit-tested
//! on the host.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod font;
pub mod keyboard;
pub mod keymap;
mod layouts;
pub mod vt;
pub mod width;
mod width_table;
