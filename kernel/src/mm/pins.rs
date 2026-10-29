// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pages a device holds (M32 phase 6, ADR 0172's addendum): a GPU's 2D
//! image of a process's memory writes the image's frames directly, so
//! those frames must stay the process's. A fork copies a pinned private
//! page for the child at once instead of sharing it copy-on-write (which
//! would hand the parent a new frame at its next write and leave the
//! device writing the child's).

use alloc::collections::BTreeMap;

use super::PhysAddr;
use crate::sync::IrqSpinLock;

static PINS: IrqSpinLock<BTreeMap<u64, u32>> = IrqSpinLock::new(BTreeMap::new());

/// `f` held by a device once more.
pub fn pin(f: PhysAddr) {
    *PINS.lock().entry(f.0).or_insert(0) += 1;
}

/// One device hold on `f` let go.
pub fn unpin(f: PhysAddr) {
    let mut p = PINS.lock();
    if let Some(n) = p.get_mut(&f.0) {
        *n -= 1;
        if *n == 0 {
            p.remove(&f.0);
        }
    }
}

/// Whether a device holds `f`.
pub fn is_pinned(f: PhysAddr) -> bool {
    PINS.lock().contains_key(&f.0)
}
