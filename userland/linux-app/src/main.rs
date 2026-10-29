// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_std]
#![no_main]

// A Linux program: it runs in the Linux domain, as what it starts does
// (ADR 0038).
slate_rt::linux_program!(slate_linux_app::main);
