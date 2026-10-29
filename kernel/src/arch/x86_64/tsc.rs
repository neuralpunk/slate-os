// SPDX-License-Identifier: MIT OR Apache-2.0

//! The time-stamp counter as the kernel's clock source.

use super::cpu::cpuid;
use super::hpet;
use core::arch::x86_64::_rdtsc;

/// Whether the TSC runs at a constant rate in all power states
/// (CPUID 8000_0007h EDX bit 8, "invariant TSC").
pub fn invariant() -> bool {
    cpuid(0x8000_0000, 0).0 >= 0x8000_0007 && cpuid(0x8000_0007, 0).3 & (1 << 8) != 0
}

pub fn read() -> u64 {
    // SAFETY: RDTSC is always available on x86-64 and has no side effects.
    unsafe { _rdtsc() }
}

/// Measure the TSC frequency against the HPET over 50 ms.
pub fn calibrate() -> u64 {
    let (h0, t0) = (hpet::counter(), read());
    hpet::spin_ns(50_000_000);
    let (h1, t1) = (hpet::counter(), read());
    let ns = hpet::ticks_to_ns(h1 - h0);
    (u128::from(t1 - t0) * 1_000_000_000 / u128::from(ns)) as u64
}
