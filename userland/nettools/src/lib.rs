// SPDX-License-Identifier: MIT OR Apache-2.0

//! Slate's own network tools (ADR 0052, ADR 0012: ours): `ip`, `ping`,
//! `lookup`, `fetch`, `ss`, `slate-network` and `slate-firewall` (ADR
//! 0134), with the name resolution they share.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod fetch;
pub mod firewall;
pub mod ip;
pub mod lookup;
pub mod netcfg;
pub mod ping;
/// Name resolution lives in slate-web, shared with quarry.
pub use slate_web::resolve;
pub mod rtnl;
pub mod ss;

#[cfg(test)]
mod tests;
