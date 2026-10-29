// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-ui (ADR 0023, ADR 0034, ADR 0037): Slate's own small GUI toolkit.
//! It draws into ARGB8888 canvases and knows nothing of the platform: a
//! front end gives it pixels and events (the graphical installer and
//! Strata do so on KMS and evdev; host tests save PNG files).
//!
//! The target is soft-float, so geometry is f32 (through [`math`]) and the
//! per-pixel work (compositing, blurring) is integer arithmetic.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod anim;
pub mod canvas;
pub mod color;
pub mod edit;
pub mod fileicon;
pub mod font;
pub mod graphite;
pub mod icon;
pub mod logo;
pub mod math;
pub mod paint;
pub mod path;
pub mod png;
pub mod raster;
pub mod shadow;
pub mod stroke;
pub mod text;
pub mod theme;
pub mod themes;
pub mod ui;
pub mod wallpaper;

pub use canvas::{Canvas, Rect};
pub use color::Color;
pub use path::{Path, Transform};
