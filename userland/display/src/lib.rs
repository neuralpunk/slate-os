// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-display: what Slate's graphical programs need from the platform,
//! shared by the graphical installer (ADR 0034) and Strata (ADR 0037): the
//! screen through KMS ([`kms`]) and every input device through evdev, with
//! keyboard layouts and key repeat ([`input`]); for a program that is not
//! root, the devices come from seatd ([`seat`]); a card's 2D requests
//! ([`twod`]); whether full graphics is there ([`graphics`]).

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod graphics;
pub mod input;
pub mod kms;
pub mod seat;
pub mod twod;
