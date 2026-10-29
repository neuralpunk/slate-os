// SPDX-License-Identifier: MIT OR Apache-2.0

//! File capabilities (capabilities(7), "File capabilities"): the
//! `security.capability` extended attribute, applied at execve(2).
//!
//! The value is little-endian 32-bit words, as Linux was seen to write it
//! (getfattr on the host, ADR 0121): `magic_etc` (the revision in the top
//! byte, bit 0 the effective flag), then the permitted and inheritable
//! masks' low halves and, from revision 2, their high halves; revision 3
//! adds the user ID (a kernel ID) of the root of the user namespace that
//! set it ("Namespaced file capabilities").

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::cred::{CAP_FULL, Cred};
use super::ns::UserNs;
use crate::abi::linux::errno::{EINVAL, Errno};

pub const NAME: &str = "security.capability";

// VFS_CAP_REVISION_1..3 and VFS_CAP_FLAGS_EFFECTIVE (capabilities(7)
// names them; the values as observed).
const REVISION_MASK: u32 = 0xFF00_0000;
const REVISION_1: u32 = 0x0100_0000;
const REVISION_2: u32 = 0x0200_0000;
const REVISION_3: u32 = 0x0300_0000;
const EFFECTIVE: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileCaps {
    pub permitted: u64,
    pub inheritable: u64,
    pub effective: bool,
    /// The kernel user ID of the namespace root they belong to (0, the
    /// initial root, before revision 3).
    pub root: u32,
    /// Revision 3: `root` is part of the value.
    pub v3: bool,
}

fn words(v: &[u8]) -> Vec<u32> {
    v.as_chunks::<4>().0.iter().map(|b| u32::from_le_bytes(*b)).collect()
}

/// The capabilities a value holds; `None` if it is malformed.
pub fn parse(v: &[u8]) -> Option<FileCaps> {
    let w = words(v);
    let magic = *w.first()?;
    let effective = magic & EFFECTIVE != 0;
    let (lo, hi, root, v3) = match (magic & REVISION_MASK, v.len()) {
        (REVISION_1, 12) => ((w[1], w[2]), (0, 0), 0, false),
        (REVISION_2, 20) => ((w[1], w[2]), (w[3], w[4]), 0, false),
        (REVISION_3, 24) => ((w[1], w[2]), (w[3], w[4]), w[5], true),
        _ => return None,
    };
    let permitted = (u64::from(hi.0) << 32 | u64::from(lo.0)) & CAP_FULL;
    let inheritable = (u64::from(hi.1) << 32 | u64::from(lo.1)) & CAP_FULL;
    Some(FileCaps { permitted, inheritable, effective, root, v3 })
}

/// The value for `c`: revision 3 when it names a root, else revision 2.
pub fn encode(c: &FileCaps) -> Vec<u8> {
    let rev = if c.v3 { REVISION_3 } else { REVISION_2 };
    let mut w = alloc::vec![
        rev | u32::from(c.effective),
        c.permitted as u32,
        c.inheritable as u32,
        (c.permitted >> 32) as u32,
        (c.inheritable >> 32) as u32,
    ];
    if c.v3 {
        w.push(c.root);
    }
    w.iter().flat_map(|x| x.to_le_bytes()).collect()
}

/// The kernel user ID of `ns`'s root (its uid 0), if mapped.
fn root_of(ns: &Arc<UserNs>) -> Option<u32> {
    ns.uid_to_kernel(0)
}

/// A value as written by `cred`: checked (EINVAL if malformed), and from
/// inside a user namespace it names that namespace's root, so the
/// capabilities count only there and below (a revision 3 value's root is
/// given as the writer sees it).
pub fn on_write(v: &[u8], cred: &Cred) -> Result<Vec<u8>, Errno> {
    let mut c = parse(v).ok_or(EINVAL)?;
    if c.v3 {
        c.root = cred.uid_in(c.root)?;
    } else if cred.user_ns.parent.is_some() {
        c.root = root_of(&cred.user_ns).ok_or(EINVAL)?;
        c.v3 = true;
    }
    // A value for the initial root is stored as revision 2, as Linux does.
    if c.v3 && c.root == 0 {
        c.v3 = false;
    }
    Ok(encode(&c))
}

/// A stored value as `cred` reads it: one for its own namespace's root
/// reads as revision 2; another revision 3 value shows its root as the
/// reader sees it.
pub fn on_read(v: Vec<u8>, cred: &Cred) -> Vec<u8> {
    let Some(mut c) = parse(&v).filter(|c| c.v3) else { return v };
    if root_of(&cred.user_ns) == Some(c.root) {
        c.v3 = false;
    } else {
        c.root = cred.uid_out(c.root);
    }
    encode(&c)
}

/// Whether file capabilities set for root `root` count for a process in
/// `ns`: `root` is the root of `ns` or of one of its ancestors.
pub fn applies(root: u32, ns: &Arc<UserNs>) -> bool {
    let mut at = Some(ns.clone());
    while let Some(n) = at {
        if root_of(&n) == Some(root) {
            return true;
        }
        at = n.parent.clone();
    }
    false
}
