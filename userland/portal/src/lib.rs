// SPDX-License-Identifier: MIT OR Apache-2.0

//! `slate-portal` (M31 phase 4, ADR 0182): inside the Linux runtime, on
//! the session bus slate-linux-app starts for an app, it is the desktop
//! portal's Settings (`org.freedesktop.portal.Desktop`,
//! `/org/freedesktop/portal/desktop`, `org.freedesktop.portal.Settings`
//! version 2), so that GTK, libadwaita and Qt apps in Flatpak's sandbox
//! follow Strata's light or dark style, accent, contrast and fonts, and
//! change with them. Other portals' interfaces it doesn't have: asked
//! for them, it says so, and toolkits do without.
//!
//! The protocol work is Slate's own, from the D-Bus Specification and the
//! XDG Desktop Portal documentation; SlateOS itself never speaks D-Bus.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod service;
pub mod settings;
pub mod wire;
