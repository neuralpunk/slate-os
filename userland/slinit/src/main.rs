// SPDX-License-Identifier: MIT OR Apache-2.0

//! The slinit binary; init and its commands live in the library.

#![no_std]
#![no_main]

slate_rt::program!(slate_slinit::main);
