// SPDX-License-Identifier: MIT OR Apache-2.0

//! A debugging aid: `slate.canary=MB` on the command line keeps that much
//! free memory filled with a pattern and checks it every 200 ms. Anything
//! that writes to memory it does not own (a device still writing a freed
//! DMA buffer, a use after free, a stack the kernel no longer owns) shows
//! up as a log line with the physical address and the words found there.
//!
//! `slate.quarantine` holds every freed frame back for two seconds, filled
//! with the pattern, and checks it before the allocator gets it back: a
//! write to a frame after it was freed is logged, and nothing reuses a
//! frame its old owner might still write.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::sync::IrqSpinLock;

use super::{PAGE_SIZE, PhysAddr, frame};
use crate::log_warn;

const WORDS: usize = PAGE_SIZE as usize / 8;

/// The pattern word at index `i` of frame `p`: unique per address, so data
/// moved from elsewhere is recognisable too.
fn pattern(p: PhysAddr, i: usize) -> u64 {
    (p.0 + 8 * i as u64) ^ 0x5a5a_c0de_0000_0000
}

fn fill(p: PhysAddr) {
    let w = p.to_virt() as *mut u64;
    for i in 0..WORDS {
        // SAFETY: `p` is a frame we allocated; it is in the direct map.
        unsafe { w.add(i).write_volatile(pattern(p, i)) };
    }
}

/// Check frame `p`; log what changed and refill it. Returns whether it
/// had changed.
fn check(p: PhysAddr) -> bool {
    let w = p.to_virt() as *const u64;
    let mut changed = 0;
    let mut first = None;
    for i in 0..WORDS {
        // SAFETY: As in `fill`.
        let v = unsafe { w.add(i).read_volatile() };
        if v != pattern(p, i) {
            changed += 1;
            first.get_or_insert(i);
        }
    }
    let Some(i) = first else { return false };
    let mut words = alloc::string::String::new();
    for j in i..(i + 8).min(WORDS) {
        // SAFETY: As in `fill`.
        let v = unsafe { w.add(j).read_volatile() };
        let _ = core::fmt::Write::write_fmt(&mut words, format_args!(" {v:#x}"));
    }
    log_warn!("canary: frame {:#x}: {changed} words changed, from +{:#x}:{words}", p.0, i * 8);
    fill(p);
    true
}

/// Start the checker if the command line asks for it.
pub fn start(cmdline: &str) {
    let Some(mb) = cmdline.split_ascii_whitespace().find_map(|w| w.strip_prefix("slate.canary=")) else { return };
    let Ok(mb) = mb.parse::<u64>() else { return };
    let mut frames = Vec::new();
    for _ in 0..mb * 1024 * 1024 / PAGE_SIZE {
        let Some(p) = frame::alloc(0) else { break };
        fill(p);
        frames.push(p);
    }
    log_warn!("canary: watching {} frames ({} MiB)", frames.len(), frames.len() as u64 * PAGE_SIZE / (1024 * 1024));
    crate::sched::spawn("canary", move || {
        loop {
            crate::time::sleep_ns(200_000_000);
            for &p in &frames {
                check(p);
            }
        }
    });
}

static QUARANTINE_ON: AtomicBool = AtomicBool::new(false);
/// Freed frames and when they were freed.
static QUARANTINED: IrqSpinLock<Option<VecDeque<(PhysAddr, u64)>>> = IrqSpinLock::new(None);
/// Most frames held back (512 MiB); beyond that, frees go straight through.
const QUARANTINE_MAX: usize = 131_072;
const QUARANTINE_NS: u64 = 2_000_000_000;

/// Take a frame being freed into quarantine; false if quarantine is off
/// or full (the caller frees it).
pub fn quarantine(p: PhysAddr) -> bool {
    if !QUARANTINE_ON.load(Ordering::Relaxed) {
        return false;
    }
    let mut g = QUARANTINED.lock();
    let Some(q) = g.as_mut() else { return false };
    if q.len() >= q.capacity() {
        return false;
    }
    fill(p);
    q.push_back((p, crate::time::monotonic_ns()));
    true
}

/// Start the quarantine if the command line asks for it.
pub fn start_quarantine(cmdline: &str) {
    if !cmdline.split_ascii_whitespace().any(|w| w == "slate.quarantine") {
        return;
    }
    *QUARANTINED.lock() = Some(VecDeque::with_capacity(QUARANTINE_MAX));
    QUARANTINE_ON.store(true, Ordering::Release);
    log_warn!("canary: freed frames are quarantined for 2 s");
    crate::sched::spawn("quarantine", || {
        loop {
            crate::time::sleep_ns(100_000_000);
            let now = crate::time::monotonic_ns();
            loop {
                let p = {
                    let mut g = QUARANTINED.lock();
                    let q = g.as_mut().unwrap();
                    match q.front() {
                        Some(&(p, at)) if now - at >= QUARANTINE_NS => {
                            q.pop_front();
                            p
                        }
                        _ => break,
                    }
                };
                check(p);
                frame::free_now(p, 0);
            }
        }
    });
}
