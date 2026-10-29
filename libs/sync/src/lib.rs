// SPDX-License-Identifier: MIT OR Apache-2.0

//! Synchronization primitives for the Slate kernel.
//!
//! Everything here is `no_std`, has no architecture dependencies and is unit
//! tested on the host. Interrupt-aware wrappers belong in the kernel, which
//! knows how to mask interrupts.

#![no_std]

#[cfg(test)]
extern crate std;

mod once;
mod spin;

pub use once::Once;
pub use spin::{SpinLock, SpinLockGuard};
