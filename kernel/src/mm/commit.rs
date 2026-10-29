// SPDX-License-Identifier: MIT OR Apache-2.0

//! The overcommit policy (proc(5): /proc/sys/vm/overcommit_memory and
//! overcommit_ratio; ADR 0123). Memory a mapping may need, but has not
//! touched yet, is "committed": private writable mappings (anonymous, a
//! private copy of a file, the heap, stacks). Slate has no swap, so what
//! can be promised is RAM.
//!
//! - 0 (the default): only an obvious overcommit is refused, a single
//!   request for more than all of RAM (not with MAP_NORESERVE);
//! - 1: nothing is refused (the out-of-memory killer acts at fault time);
//! - 2: what is committed in all may not pass the commit limit,
//!   `overcommit_ratio` percent of RAM.
//!
//! Refusals are ENOMEM, from mmap(2), brk(2), mremap(2), mprotect(2) and
//! fork(2).

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

pub static MODE: AtomicU8 = AtomicU8::new(0);
/// Percent of RAM mode 2 may commit (proc(5)'s default, 50).
pub static RATIO: AtomicU64 = AtomicU64::new(50);

fn pages(bytes: u64) -> u64 {
    bytes.div_ceil(super::PAGE_SIZE)
}

/// CommitLimit (/proc/meminfo), in pages.
pub fn limit_pages() -> u64 {
    super::frame::stats().usable_frames.saturating_mul(RATIO.load(Ordering::Relaxed)) / 100
}

/// Committed_AS (/proc/meminfo): what every address space has
/// committed, in pages (one lent to a vfork child is the child's alone).
pub fn committed_pages() -> u64 {
    crate::proc::all().iter().map(|p| p.aspace.lock().as_ref().map_or(0, |a| a.committed_bytes())).map(pages).sum()
}

/// Whether `bytes` more may be committed under the policy; `noreserve`
/// for MAP_NORESERVE, which only mode 2 counts.
pub fn enough(bytes: u64, noreserve: bool) -> bool {
    match MODE.load(Ordering::Relaxed) {
        1 => true,
        2 => committed_pages().saturating_add(pages(bytes)) <= limit_pages(),
        _ => noreserve || pages(bytes) <= super::frame::stats().usable_frames,
    }
}

/// Strict accounting (mode 2), where a fork's copy counts too.
pub fn strict() -> bool {
    MODE.load(Ordering::Relaxed) == 2
}
