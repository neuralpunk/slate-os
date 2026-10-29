// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strata (ADR 0037): Slate's own tiling window manager and display
//! server, in the graphite theme of docs/design/WM_STYLE.md: the fonts, the
//! tiling layout, the window manager's state, the drawing of every surface
//! (wallpaper, top bar, window frames, launcher, system approval dialog),
//! and the session on KMS and evdev that the `strata` program runs.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod agent;
pub mod alarms;
pub mod approval;
pub mod desk;
pub mod desktop;
pub mod displays;
pub mod draw;
pub mod faces;
pub mod fonts;
pub mod greeter;
pub mod keys;
pub mod launcher;
pub mod layout;
pub mod lock;
pub mod menu;
pub mod motion;
pub mod power;
pub mod server;
pub mod session;
pub mod settings;
pub mod settings_app;
pub mod stats;
pub mod undo;
pub mod watch;
pub mod wm;

#[cfg(test)]
mod scenes;
