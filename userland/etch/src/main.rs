// SPDX-License-Identifier: MIT OR Apache-2.0

//! The etch binary; the editor lives in the library.

#![no_std]
#![no_main]

slate_rt::program!(slate_etch::main);
