// SPDX-License-Identifier: MIT OR Apache-2.0

//! ALSA's kernel interface (ADR 0184): what alsa-lib, and through it
//! PipeWire and every ALSA program, expects of `/dev/snd`. [`abi`] has
//! the numbers and layouts, [`params`] the hardware parameter space and
//! its refinement, [`ptr`] the stream positions, [`tlv`] volume scales.
//! The kernel's sound core uses them; they are host-tested here.

#![no_std]

#[cfg(test)]
extern crate std;

pub mod abi;
pub mod params;
pub mod ptr;
pub mod tlv;
