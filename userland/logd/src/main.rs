// SPDX-License-Identifier: MIT OR Apache-2.0

//! The logd binary: the daemon, logread and logger live in the library.

#![no_std]
#![no_main]

slate_rt::program!(slate_logd::main);
