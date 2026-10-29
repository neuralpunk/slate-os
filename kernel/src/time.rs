// SPDX-License-Identifier: MIT OR Apache-2.0

//! Kernel time: the monotonic clock, wall-clock time, the periodic tick and
//! sleeping. Wall-clock time is the monotonic clock plus an offset in
//! nanoseconds, which setting the time changes (clock_settime(2); the vDSO
//! reads the same offset). A correction moves the offset a little on each
//! of CPU 0's ticks: a frequency and a slew (adjtimex(2), ADR 0078).

use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use slate_sync::Once;

/// Frequency of the periodic timer interrupt.
pub const TICK_HZ: u32 = 1000;
pub const NS_PER_SEC: u64 = 1_000_000_000;

/// A free-running counter converted to nanoseconds with a fixed-point
/// multiplier: `ns = (count - base) * mult >> 32`.
#[derive(Debug)]
struct Clock {
    name: &'static str,
    read: fn() -> u64,
    base: u64,
    mult: u64,
}

static CLOCK: Once<Clock> = Once::new();
static TICKS: AtomicU64 = AtomicU64::new(0);
/// Wall-clock nanoseconds since the epoch at monotonic zero.
static REALTIME_OFFSET_NS: AtomicI64 = AtomicI64::new(0);

/// Install the clock source. `read` returns a counter running at `freq` Hz;
/// `boot_unix_secs` is the wall-clock time now, if known.
pub fn init(name: &'static str, read: fn() -> u64, freq: u64, boot_unix_secs: Option<i64>) {
    let mult = ((u128::from(NS_PER_SEC) << 32) / u128::from(freq)) as u64;
    CLOCK.call_once(|| Clock { name, read, base: read(), mult });
    let secs = boot_unix_secs.unwrap_or(0);
    REALTIME_OFFSET_NS.store(secs.saturating_mul(NS_PER_SEC as i64), Ordering::Relaxed);
}

/// The clock's counter value at monotonic zero and its 32.32 fixed-point
/// nanoseconds-per-count multiplier, for the vDSO.
pub fn clock_params() -> Option<(&'static str, u64, u64)> {
    CLOCK.get().map(|c| (c.name, c.base, c.mult))
}

/// Wall-clock nanoseconds at monotonic zero (for the vDSO).
pub fn realtime_offset_ns() -> i64 {
    REALTIME_OFFSET_NS.load(Ordering::Acquire)
}

/// Set the wall clock to `ns` nanoseconds since the epoch (clock_settime(2)):
/// the kernel's clock and the vDSO's move together, and a slew under way
/// stops. The hardware clock is the caller's to update.
pub fn set_realtime_ns(ns: i128) {
    let mut a = ADJUST.lock();
    a.slew_ns = 0;
    let offset = (ns - i128::from(monotonic_ns())).clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
    REALTIME_OFFSET_NS.store(offset, Ordering::Release);
    crate::mm::vdso::set_realtime_offset(offset);
}

/// Move the wall clock by `delta` nanoseconds (the vDSO too).
fn shift_realtime(delta: i64) {
    let offset = REALTIME_OFFSET_NS.fetch_add(delta, Ordering::AcqRel).wrapping_add(delta);
    crate::mm::vdso::set_realtime_offset(offset);
}

/// adjtimex(2)'s limits: the frequency in ppm with 16 fraction bits, the
/// tick (microseconds per 1/100 s) and the slew rate (ppm).
pub const MAX_FREQ: i64 = 500 << 16;
pub const TICK_MIN: i64 = 9000;
pub const TICK_MAX: i64 = 11000;
pub const TICK_NORMAL: i64 = 10000;
const SLEW_PPM: i128 = 500;
/// adjtimex(2) status: the clock is not synchronized.
pub const STA_UNSYNC: i32 = 0x40;

/// The wall clock's correction and adjtimex(2)'s other state (ADR 0078).
#[derive(Clone, Copy, Debug)]
pub struct Adjust {
    /// Frequency: parts per million with 16 fraction bits.
    pub freq: i64,
    /// Microseconds per 1/100 s; each away from 10000 is 100 ppm.
    pub tick: i64,
    /// Nanoseconds still to slew, at 500 ppm.
    pub slew_ns: i64,
    pub status: i32,
    pub maxerror: i64,
    pub esterror: i64,
    pub constant: i64,
    pub tai: i32,
    /// When the correction was last applied (monotonic ns), and the
    /// fraction of a nanosecond carried.
    last_ns: u64,
    carry: i128,
}

static ADJUST: crate::sync::IrqSpinLock<Adjust> = crate::sync::IrqSpinLock::new(Adjust {
    freq: 0,
    tick: TICK_NORMAL,
    slew_ns: 0,
    status: STA_UNSYNC,
    // adjtimex(2)'s "16 s" for an unknown error, in microseconds.
    maxerror: 16_000_000,
    esterror: 16_000_000,
    constant: 2,
    tai: 0,
    last_ns: 0,
    carry: 0,
});

/// The correction as it is now.
pub fn adjustment() -> Adjust {
    *ADJUST.lock()
}

/// Change the correction: `f` gets it, applied up to now, to change.
pub fn adjust(f: impl FnOnce(&mut Adjust)) -> Adjust {
    let mut a = ADJUST.lock();
    apply(&mut a);
    f(&mut a);
    *a
}

/// Apply the frequency and the slew for the time since the last call.
fn apply(a: &mut Adjust) {
    let now = monotonic_ns();
    let dt = i128::from(now.saturating_sub(a.last_ns));
    a.last_ns = now;
    if a.freq == 0 && a.tick == TICK_NORMAL && a.slew_ns == 0 {
        a.carry = 0;
        return;
    }
    // ppm << 16 of the frequency and the tick together.
    let rate = i128::from(a.freq) + i128::from(a.tick - TICK_NORMAL) * 100 * 65536;
    let den = 1_000_000i128 << 16;
    let num = dt * rate + a.carry;
    let mut delta = num / den;
    a.carry = num % den;
    let most = (dt * SLEW_PPM / 1_000_000) as i64;
    let slew = a.slew_ns.clamp(-most, most);
    a.slew_ns -= slew;
    delta += i128::from(slew);
    if delta != 0 {
        shift_realtime(delta as i64);
    }
}

pub fn clock_name() -> &'static str {
    CLOCK.get().map_or("none", |c| c.name)
}

/// Nanoseconds since the clock was installed (0 before that).
pub fn monotonic_ns() -> u64 {
    match CLOCK.get() {
        Some(c) => ((u128::from((c.read)().wrapping_sub(c.base)) * u128::from(c.mult)) >> 32) as u64,
        None => 0,
    }
}

/// Wall-clock time in nanoseconds since the UNIX epoch.
pub fn realtime_ns() -> i128 {
    i128::from(REALTIME_OFFSET_NS.load(Ordering::Acquire)) + i128::from(monotonic_ns())
}

/// Timer interrupts handled since boot.
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// Called by CPU 0's timer interrupt handler.
pub fn tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
    // Not this tick if someone is changing the correction.
    if let Some(mut a) = ADJUST.try_lock() {
        apply(&mut a);
    }
}

/// Sleep for at least `ns` nanoseconds. Interrupts must be enabled.
pub fn sleep_ns(ns: u64) {
    crate::sched::sleep_until(monotonic_ns() + ns);
}

// --- Kernel timers ------------------------------------------------------

type Callback = alloc::boxed::Box<dyn FnOnce() + Send>;

static TIMERS: crate::sync::IrqSpinLock<alloc::collections::BTreeMap<(u64, u64), Callback>> =
    crate::sync::IrqSpinLock::new(alloc::collections::BTreeMap::new());
static NEXT_TIMER: AtomicU64 = AtomicU64::new(1);

/// A pending timer: cancel it with [`cancel_timer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerId(u64, u64);

/// Run `f` from the timer interrupt once the monotonic clock reaches
/// `deadline_ns` (the timer is set for it, not rounded to the tick). `f`
/// runs with interrupts masked and must be short: wake threads, send
/// signals, notify pollers.
pub fn add_timer(deadline_ns: u64, f: impl FnOnce() + Send + 'static) -> TimerId {
    let id = NEXT_TIMER.fetch_add(1, Ordering::Relaxed);
    TIMERS.lock().insert((deadline_ns, id), alloc::boxed::Box::new(f));
    crate::arch::timer_deadline(deadline_ns);
    TimerId(deadline_ns, id)
}

/// The earliest pending kernel timer's deadline (u64::MAX: none).
pub fn earliest_timer() -> u64 {
    TIMERS.lock().first_key_value().map_or(u64::MAX, |(k, _)| k.0)
}

/// Cancel a timer; returns false if it already ran.
pub fn cancel_timer(t: TimerId) -> bool {
    TIMERS.lock().remove(&(t.0, t.1)).is_some()
}

/// Run due timers (from the timer interrupt).
pub(crate) fn run_timers() {
    let now = monotonic_ns();
    let due = {
        let mut t = TIMERS.lock();
        let later = t.split_off(&(now + 1, 0));
        core::mem::replace(&mut *t, later)
    };
    for (_, f) in due {
        f();
    }
}
