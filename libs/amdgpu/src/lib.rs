// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading what an AMD GPU says about itself (ADR 0171, M32 phase 4),
//! for Slate's display driver, on the host first:
//!
//! - [`vfct`]: the ACPI VFCT table, where an integrated GPU's VBIOS image
//!   is (there is no ROM BAR);
//! - [`atom`]: the AtomBIOS image: its headers, the master data and
//!   command table lists, and the display object table (the connectors,
//!   their encoders, HPD pins and DDC lines);
//! - [`discovery`]: the IP discovery table: each hardware block's version
//!   and register bases;
//! - [`interp`]: an AtomBIOS interpreter, to run the VBIOS's command
//!   tables (the PHYs, the pixel clock);
//! - [`gfxhub`] and [`sdma`]: the GFX hub's context 0 and the copy
//!   engine; [`gcfw`]: GC's firmware for the PSP to load; [`cp`]: a
//!   compute queue and its packets; [`rdna2`]: Slate's own shaders
//!   (ADR 0172).
//!
//! Sources (docs/gpu/SOURCES.md; ADR 0157's addendum): AMD's headers as
//! they are in Linux v7.2.12, `drivers/gpu/drm/amd/include/atombios.h`,
//! `atomfirmware.h`, `discovery.h`, `soc15_hw_ip.h`, and
//! `drivers/gpu/drm/amd/amdgpu/ObjectID.h`; each fact names its file.
//! Checked against the reference PC's Raphael iGPU (its VBIOS and discovery table
//! in `target/gpu/refpc/`, never committed).

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod atom;
pub mod cp;
pub mod discovery;
pub mod dmub;
pub mod gcfw;
pub mod gfxhub;
pub mod i2c;
pub mod interp;
pub mod mode;
pub mod otg;
pub mod psp;
pub mod rdna2;
#[cfg(test)]
mod rdna2sim;
pub mod scanout;
pub mod sdma;
pub mod vfct;

/// Little-endian reads that fail softly on short data.
pub(crate) fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

pub(crate) fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}
