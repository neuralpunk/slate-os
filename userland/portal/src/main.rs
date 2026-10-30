// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_std]
#![no_main]

// A Linux program: it runs inside the Linux runtime (ADR 0038).
slate_rt::linux_program!(slate_portal::service::main);
