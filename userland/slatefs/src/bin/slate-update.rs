// SPDX-License-Identifier: MIT OR Apache-2.0

//! The slate-update binary; the tool lives in the library.

#![no_std]
#![no_main]

slate_rt::program!(slate_slatefs::update::main);
