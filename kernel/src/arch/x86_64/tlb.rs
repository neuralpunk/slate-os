// SPDX-License-Identifier: MIT OR Apache-2.0

//! TLB shootdown: making other CPUs drop stale translations.
//!
//! When a multi-threaded process changes its page tables (unmap, protect,
//! copy-on-write), CPUs running its other threads may still hold the old
//! translations. Each CPU has two counters: requests made of it and
//! requests it has served. A sender bumps the other online CPUs' request
//! counters, sends an IPI and waits until each has served at least its
//! request. A CPU serves by noting its request count, flushing, and only
//! then publishing that count as served: a sender never goes on while the
//! CPU might still use an old translation (acknowledging before flushing
//! once let a copy-on-write split's old frame be read after the new one was
//! written). While waiting a sender serves requests aimed at itself, so two
//! CPUs shooting down at the same time, even with interrupts masked, cannot
//! deadlock. Callers must not hold spinlocks another CPU might be spinning
//! on with interrupts masked.

use core::sync::atomic::{AtomicU64, Ordering};

use super::{apic, cpu, irq, paging};
use crate::mm::PhysAddr;

const MAX_CPUS: usize = 64;

static REQUESTED: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static SERVED: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Serve the requests made of this CPU so far, if any. Every request gets a
/// full local flush: a CPU running another address space has nothing to
/// drop, and the flush (a CR3 reload) is cheap.
fn serve() {
    let me = super::cpu_id() as usize;
    let wanted = REQUESTED[me].load(Ordering::Acquire);
    if SERVED[me].load(Ordering::Relaxed) == wanted {
        return;
    }
    paging::flush_local();
    SERVED[me].fetch_max(wanted, Ordering::Release);
}

/// IPI handler.
pub fn interrupt() {
    serve();
}

/// Flush `root`'s translations on every CPU (this one included).
pub fn shootdown(_root: PhysAddr) {
    // Masked: the CPU flushed locally must be the one left out of the IPIs
    // (a migration in between would leave the new CPU's TLB stale).
    let _irq = cpu::InterruptGuard::new();
    paging::flush_local();
    let me = super::cpu_id() as usize;
    let cpus = crate::sched::cpu_count().min(MAX_CPUS);
    let mut tickets = [0u64; MAX_CPUS];
    for c in (0..cpus).filter(|&c| c != me) {
        tickets[c] = REQUESTED[c].fetch_add(1, Ordering::AcqRel) + 1;
        apic::send_ipi(crate::sched::apic_id_of(c), u32::from(irq::TLB_VECTOR) | (1 << 14));
    }
    for c in (0..cpus).filter(|&c| c != me) {
        while SERVED[c].load(Ordering::Acquire) < tickets[c] {
            serve();
            core::hint::spin_loop();
        }
    }
}

/// Requests made and served, per CPU (for fault diagnostics).
pub fn counters() -> alloc::vec::Vec<(u64, u64)> {
    let cpus = crate::sched::cpu_count().min(MAX_CPUS);
    (0..cpus).map(|c| (REQUESTED[c].load(Ordering::Acquire), SERVED[c].load(Ordering::Acquire))).collect()
}
