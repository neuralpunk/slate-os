// SPDX-License-Identifier: MIT OR Apache-2.0

//! nf_tables, Slate's firewall (ADRs 0128, 0129): rulesets as nft(8) and
//! other programs make them over nfnetlink, and (in the network stack)
//! their evaluation on each packet. No I/O and no clock of its own: the
//! kernel hands messages in and takes the answers, and is unit-tested on
//! the host against what Linux answered the same requests.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod attr;
pub mod compat;
pub mod consts;
pub mod ct;
pub mod eval;
pub mod expr;
pub mod inbound;
pub mod nat;
pub mod ruleset;

pub use ct::{Conntrack, CtInfo, Tracked};
pub use eval::{Iface, Outcome, Packet, Reject};
pub use expr::{Data, Expr, Verdict};
pub use nat::Rewrite;
pub use ruleset::{AckOpts, BaseChain, Chain, Elem, Rule, Ruleset, Set, Table};

#[cfg(test)]
mod tests;
