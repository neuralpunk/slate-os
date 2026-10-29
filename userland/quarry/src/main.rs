// SPDX-License-Identifier: MIT OR Apache-2.0

//! The quarry binary; the package manager lives in the library.

#![no_std]
#![no_main]

slate_rt::program!(slate_quarry::main);
