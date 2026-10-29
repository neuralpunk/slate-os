// SPDX-License-Identifier: MIT OR Apache-2.0

//! `slate-unlock`, the boot's disk unlock screen (ADR 0038). With an
//! encrypted root, the kernel runs it from the `unlock` module before
//! init, as distributions run an initramfs to unlock LUKS. It asks for the
//! password on a graphite screen (and on the console, which also works
//! alone), derives each key slot's key with Argon2id here in user space,
//! and hands it to the kernel with the native call `unlock`; the kernel
//! opens the slot with it, which tells a wrong password.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod app;
pub mod screen;
