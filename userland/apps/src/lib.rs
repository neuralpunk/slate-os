// SPDX-License-Identifier: MIT OR Apache-2.0

//! Slate's own apps for Strata (M28, ADR 0104), each a window drawn with
//! slate-ui in the graphite theme: the Calculator, the Clock, Help and
//! About this system, the Image Viewer, the Archive Manager, the Text
//! Editor, Files, Calendar and Contacts; and the system tools (ADR 0112):
//! the System Monitor, Disks and the Software Updater; the Web
//! Browser's first use (ADR 0115); and App Center (ADR 0125). [`kit`] is what they share.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod appcenter;
pub mod archive;
pub mod archives;
pub mod browser;
pub mod calc;
pub mod calendar;
pub mod clock;
pub mod contacts;
pub mod disks;
pub mod editor;
pub mod expr;
pub mod files;
pub mod fsops;
pub mod help;
pub mod kit;
pub mod syntax;
pub mod sysmon;
pub mod updater;
pub mod viewer;

#[cfg(test)]
mod scenes;
