// SPDX-License-Identifier: MIT OR Apache-2.0

//! Arguments and environment, as received at start-up.

use alloc::vec::Vec;

use crate::start::STARTUP;

static EMPTY: Vec<Vec<u8>> = Vec::new();

/// Command-line arguments, including the program name.
pub fn args() -> &'static [Vec<u8>] {
    STARTUP.get().map_or(&EMPTY, |s| &s.args)
}

/// `NAME=value` strings.
pub fn vars() -> &'static [Vec<u8>] {
    STARTUP.get().map_or(&EMPTY, |s| &s.env)
}

pub fn var(name: &[u8]) -> Option<Vec<u8>> {
    vars().iter().find_map(|v| v.strip_prefix(name).and_then(|r| r.strip_prefix(b"=")).map(<[u8]>::to_vec))
}
