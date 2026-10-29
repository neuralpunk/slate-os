// SPDX-License-Identifier: MIT OR Apache-2.0

//! HTTP for Slate's programs (ADR 0052, ADR 0069): name resolution
//! (`resolve`, re-exported from slate-resolve), and an HTTP/1.1 client that hands a body over as it
//! arrives (`http`). `fetch` and quarry use it.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod http;
pub use slate_resolve as resolve;

#[cfg(test)]
mod tests;
