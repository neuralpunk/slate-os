// SPDX-License-Identifier: MIT OR Apache-2.0

//! The reference clock for calibration, and a fallback clock source: the
//! High Precision Event Timer (IA-PC HPET specification 1.0a, §2.3), or,
//! on machines without one, the ACPI power-management timer (ACPI 6.5
//! §4.8.3.3: a free-running 24- or 32-bit counter at 3.579545 MHz, read
//! from the FADT's PM_TMR_BLK port). The PM timer is extended to 64 bits
//! here, which holds as long as it is read at least once a wrap (4.7 s
//! for 24 bits); calibration reads it continuously.

use core::sync::atomic::{AtomicPtr, AtomicU16, AtomicU64, Ordering};

use super::port::Port32;

use crate::mm::{PhysAddr, vmap};

const GENERAL_CAPABILITIES: usize = 0x000;
const GENERAL_CONFIG: usize = 0x010;
const MAIN_COUNTER: usize = 0x0F0;
const ENABLE_CNF: u64 = 1;

static BASE: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static PERIOD_FS: AtomicU64 = AtomicU64::new(0);

/// The PM timer's port (0: the HPET is the reference), its counter's mask,
/// and the last 64-bit value read.
static PM_PORT: AtomicU16 = AtomicU16::new(0);
static PM_MASK: AtomicU64 = AtomicU64::new(0);
static PM_LAST: AtomicU64 = AtomicU64::new(0);
/// The PM timer's frequency (ACPI 6.5 §4.8.3.3).
const PM_HZ: u64 = 3_579_545;
/// Femtoseconds per PM timer tick.
const PM_PERIOD_FS: u64 = 1_000_000_000_000_000 / PM_HZ;

/// Use the ACPI PM timer at I/O port `port` (32 bits wide if `wide`).
pub fn init_pm(port: u16, wide: bool) {
    PM_MASK.store(if wide { 0xFFFF_FFFF } else { 0xFF_FFFF }, Ordering::Relaxed);
    PERIOD_FS.store(PM_PERIOD_FS, Ordering::Relaxed);
    PM_PORT.store(port, Ordering::Relaxed);
    PM_LAST.store(0, Ordering::Relaxed);
}

/// Whether the reference is the PM timer (it wraps; no clock source).
pub fn is_pm_timer() -> bool {
    PM_PORT.load(Ordering::Relaxed) != 0
}

fn pm_counter(port: u16) -> u64 {
    let mask = PM_MASK.load(Ordering::Relaxed);
    // SAFETY: PM_TMR_BLK, from the FADT, is the read-only PM timer port.
    let raw = u64::from(unsafe { Port32::new(port) }.read()) & mask;
    let last = PM_LAST.load(Ordering::Relaxed);
    let now = last + (raw.wrapping_sub(last & mask) & mask);
    PM_LAST.fetch_max(now, Ordering::Relaxed).max(now)
}

fn reg(offset: usize) -> *mut u64 {
    BASE.load(Ordering::Relaxed).wrapping_add(offset).cast()
}

/// Map and start the HPET at physical address `phys`.
pub fn init(phys: u64) {
    let base = vmap::map_mmio(PhysAddr(phys), 1024);
    BASE.store(base, Ordering::Relaxed);
    // SAFETY: `base` maps the HPET register block (1 KiB) uncached; the
    // registers are 64-bit and naturally aligned.
    unsafe {
        let caps = reg(GENERAL_CAPABILITIES).read_volatile();
        PERIOD_FS.store(caps >> 32, Ordering::Relaxed);
        let conf = reg(GENERAL_CONFIG).read_volatile();
        reg(GENERAL_CONFIG).write_volatile(conf | ENABLE_CNF);
    }
}

/// The main counter (the PM timer's, extended, without an HPET).
pub fn counter() -> u64 {
    let port = PM_PORT.load(Ordering::Relaxed);
    if port != 0 {
        return pm_counter(port);
    }
    // SAFETY: Only called after `init`; reading
    // the main counter has no side effects.
    unsafe { reg(MAIN_COUNTER).read_volatile() }
}

/// Counter frequency in Hz.
pub fn frequency() -> u64 {
    1_000_000_000_000_000 / PERIOD_FS.load(Ordering::Relaxed).max(1)
}

/// Busy-wait for `ns` nanoseconds by the HPET.
pub fn spin_ns(ns: u64) {
    let ticks = (u128::from(ns) * u128::from(frequency()) / 1_000_000_000) as u64;
    let start = counter();
    while counter().wrapping_sub(start) < ticks {
        core::hint::spin_loop();
    }
}

/// Nanoseconds between two counter readings.
pub fn ticks_to_ns(ticks: u64) -> u64 {
    (u128::from(ticks) * u128::from(PERIOD_FS.load(Ordering::Relaxed)) / 1_000_000) as u64
}
