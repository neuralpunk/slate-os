// SPDX-License-Identifier: MIT OR Apache-2.0

//! clock_gettime(2), clock_settime(2), gettimeofday(2), settimeofday(2),
//! nanosleep(2), clock_nanosleep(2).

use super::errno::{EFAULT, EINVAL, EPERM};
use super::{Args, Result};
use crate::arch::uaccess::{read_user, write_user};
use crate::time::{self, NS_PER_SEC};

/// `struct timespec`.
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Timespec {
    sec: i64,
    nsec: i64,
}

/// `struct timeval`.
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Timeval {
    sec: i64,
    usec: i64,
}

// Clock IDs. Source: musl `time.h` (ADR 0009); see clock_gettime(2).
pub(crate) const CLOCK_REALTIME: u64 = 0;
pub(crate) const CLOCK_MONOTONIC: u64 = 1;
pub(crate) const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
const CLOCK_THREAD_CPUTIME_ID: u64 = 3;
const CLOCK_MONOTONIC_RAW: u64 = 4;
const CLOCK_REALTIME_COARSE: u64 = 5;
const CLOCK_MONOTONIC_COARSE: u64 = 6;
pub(crate) const CLOCK_BOOTTIME: u64 = 7;
const TIMER_ABSTIME: u64 = 1;

fn now(clock: u64) -> core::result::Result<i128, super::Errno> {
    Ok(match clock {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE => time::realtime_ns(),
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_MONOTONIC_COARSE | CLOCK_BOOTTIME => {
            i128::from(time::monotonic_ns())
        }
        CLOCK_PROCESS_CPUTIME_ID => {
            crate::sched::update_current_times();
            let (u, s) = crate::proc::current().ok_or(EINVAL)?.cpu.own();
            i128::from(u + s)
        }
        CLOCK_THREAD_CPUTIME_ID => {
            crate::sched::update_current_times();
            let (u, s) = crate::sched::current().cpu_ns();
            i128::from(u + s)
        }
        c if (c as i32) < 0 => cpu_clock(c as i32)?,
        _ => return Err(EINVAL),
    })
}

/// Another process's or thread's CPU-time clock (clock_getcpuclockid(3),
/// pthread_getcpuclockid(3)): the ID is (!id) * 8 + kind, where bit 2 of
/// kind means a thread and its low bits say which time (0: user and
/// system, 1: user only, 2: user and system, as the scheduler counts it).
/// Encoding observed on the host with musl.
fn cpu_clock(c: i32) -> core::result::Result<i128, super::Errno> {
    let (kind, id) = (c & 7, !(c >> 3));
    if kind & 3 == 3 || id <= 0 {
        return Err(EINVAL);
    }
    crate::sched::update_current_times();
    let ns = crate::proc::caller_pid_ns();
    let (u, s) = if kind & 4 != 0 {
        crate::proc::all()
            .into_iter()
            .find_map(|p| p.threads().into_iter().find(|t| p.tid_in(t.tid, &ns) == Some(id as u64)))
            .ok_or(EINVAL)?
            .cpu_ns()
    } else {
        crate::proc::find_in_caller_ns(id as u32).ok_or(EINVAL)?.cpu.own()
    };
    Ok(i128::from(if kind & 3 == 1 { u } else { u + s }))
}

fn split(ns: i128) -> Timespec {
    let s = i128::from(NS_PER_SEC);
    Timespec { sec: ns.div_euclid(s) as i64, nsec: ns.rem_euclid(s) as i64 }
}

pub fn clock_gettime(a: Args) -> Result {
    let ts = split(now(a.0[0])?);
    write_user(a.0[1], &ts).map_err(|_| EFAULT)?;
    Ok(0)
}

/// clock_getres(2): every clock Slate knows counts in nanoseconds; the
/// result pointer may be null.
pub fn clock_getres(a: Args) -> Result {
    now(a.0[0])?;
    if a.0[1] != 0 {
        write_user(a.0[1], &split(1)).map_err(|_| EFAULT)?;
    }
    Ok(0)
}

/// Set the wall clock (CAP_SYS_TIME): the kernel's, the vDSO's, and soon
/// after the hardware clock's.
pub(crate) fn set_realtime(ns: i128) -> Result {
    if !crate::proc::cred::current().capable(crate::proc::cred::CAP_SYS_TIME) {
        return Err(EPERM);
    }
    if ns < 0 {
        return Err(EINVAL);
    }
    time::set_realtime_ns(ns);
    crate::log_info!("the wall clock was set to {} s", ns / i128::from(NS_PER_SEC));
    crate::drivers::rtc::sync_from_system();
    Ok(0)
}

/// clock_settime(2): only CLOCK_REALTIME can be set.
pub fn clock_settime(a: Args) -> Result {
    if a.0[0] != CLOCK_REALTIME {
        return Err(EINVAL);
    }
    let ts: Timespec = read_user(a.0[1]).map_err(|_| EFAULT)?;
    if !(0..NS_PER_SEC as i64).contains(&ts.nsec) {
        return Err(EINVAL);
    }
    set_realtime(i128::from(ts.sec) * i128::from(NS_PER_SEC) + i128::from(ts.nsec))
}

/// settimeofday(2): the time zone argument is obsolete and ignored.
pub fn settimeofday(a: Args) -> Result {
    if a.0[0] == 0 {
        return Ok(0);
    }
    let tv: Timeval = read_user(a.0[0]).map_err(|_| EFAULT)?;
    if !(0..1_000_000).contains(&tv.usec) {
        return Err(EINVAL);
    }
    set_realtime(i128::from(tv.sec) * i128::from(NS_PER_SEC) + i128::from(tv.usec) * 1000)
}

pub fn gettimeofday(a: Args) -> Result {
    if a.0[0] != 0 {
        let ts = split(time::realtime_ns());
        write_user(a.0[0], &Timeval { sec: ts.sec, usec: ts.nsec / 1000 }).map_err(|_| EFAULT)?;
    }
    // The obsolete time zone (gettimeofday(2)): zero minutes west, no DST.
    if a.0[1] != 0 {
        write_user(a.0[1], &[0i32; 2]).map_err(|_| EFAULT)?;
    }
    Ok(0)
}

/// time(2): seconds since the epoch, also stored at `tloc` if not null.
pub fn time(a: Args) -> Result {
    let secs = split(time::realtime_ns()).sec;
    if a.0[0] != 0 {
        write_user(a.0[0], &secs).map_err(|_| EFAULT)?;
    }
    Ok(secs as u64)
}

/// getcpu(2): the CPU the caller is running on (one NUMA node).
pub fn getcpu(a: Args) -> Result {
    let cpu = crate::arch::cpu_id();
    if a.0[0] != 0 {
        write_user(a.0[0], &cpu).map_err(|_| EFAULT)?;
    }
    if a.0[1] != 0 {
        write_user(a.0[1], &0u32).map_err(|_| EFAULT)?;
    }
    Ok(0)
}

fn read_timespec(addr: u64) -> core::result::Result<i128, super::Errno> {
    let ts: Timespec = read_user(addr).map_err(|_| EFAULT)?;
    if ts.sec < 0 || !(0..NS_PER_SEC as i64).contains(&ts.nsec) {
        return Err(EINVAL);
    }
    Ok(i128::from(ts.sec) * i128::from(NS_PER_SEC) + i128::from(ts.nsec))
}

/// Sleep until the monotonic time `until`. If a signal interrupts it, the
/// remaining time goes to `rem` (if given) and the call either fails with
/// EINTR (a handler ran) or restarts transparently for the rest of the
/// time (a stop/continue, or an ignored signal), as on Linux.
fn sleep_monotonic(until: u64, rem: u64) -> Result {
    if crate::sched::sleep_until_interruptible(until) {
        let left = until.saturating_sub(time::monotonic_ns());
        if rem != 0 {
            let ts = split(i128::from(left));
            write_user(rem, &ts).map_err(|_| EFAULT)?;
        }
        crate::sched::current().set_restart_deadline(until);
        return Err(crate::proc::signal::ERESTARTNOHAND);
    }
    Ok(0)
}

fn sleep_until_clock(clock: u64, deadline: i128, rem: u64) -> Result {
    let delta = deadline - now(clock)?;
    if delta <= 0 {
        return Ok(0);
    }
    let until = time::monotonic_ns().saturating_add(delta.min(i128::from(u64::MAX)) as u64);
    sleep_monotonic(until, rem)
}

pub fn nanosleep(a: Args) -> Result {
    // A restarted call continues toward its original deadline.
    if let Some(until) = crate::sched::current().take_restart_deadline() {
        return sleep_monotonic(until, a.0[1]);
    }
    let d = read_timespec(a.0[0])?;
    sleep_until_clock(CLOCK_MONOTONIC, i128::from(time::monotonic_ns()) + d, a.0[1])
}

pub fn clock_nanosleep(a: Args) -> Result {
    let [clock, flags, req, rem, ..] = a.0;
    if let Some(until) = crate::sched::current().take_restart_deadline() {
        return sleep_monotonic(until, if flags & TIMER_ABSTIME != 0 { 0 } else { rem });
    }
    let d = read_timespec(req)?;
    let (deadline, rem) = if flags & TIMER_ABSTIME != 0 { (d, 0) } else { (now(clock)? + d, rem) };
    sleep_until_clock(clock, deadline, rem)
}

// adjtimex(2): `struct timex` (208 bytes; musl `sys/timex.h`, offsets
// measured with the host's compiler, ADR 0078), the mode bits, status bits
// and results.
const TIMEX_SIZE: usize = 208;
const TX_MODES: usize = 0;
const TX_OFFSET: usize = 8;
const TX_FREQ: usize = 16;
const TX_MAXERROR: usize = 24;
const TX_ESTERROR: usize = 32;
const TX_STATUS: usize = 40;
const TX_CONSTANT: usize = 48;
const TX_PRECISION: usize = 56;
const TX_TOLERANCE: usize = 64;
const TX_TIME: usize = 72;
const TX_TICK: usize = 88;
const TX_TAI: usize = 160;
const ADJ_OFFSET: u32 = 0x0001;
const ADJ_FREQUENCY: u32 = 0x0002;
const ADJ_MAXERROR: u32 = 0x0004;
const ADJ_ESTERROR: u32 = 0x0008;
const ADJ_STATUS: u32 = 0x0010;
const ADJ_TIMECONST: u32 = 0x0020;
const ADJ_TAI: u32 = 0x0080;
const ADJ_SETOFFSET: u32 = 0x0100;
const ADJ_MICRO: u32 = 0x1000;
const ADJ_NANO: u32 = 0x2000;
const ADJ_TICK: u32 = 0x4000;
/// adjtime(3)'s bit: with ADJ_OFFSET, the single shot (0x8001); with
/// 0x2000 too, reading what is left (0xa001).
const ADJ_ADJTIME: u32 = 0x8000;
const ADJ_OFFSET_SINGLESHOT: u32 = 0x8001;
const ADJ_OFFSET_SS_READ: u32 = 0xa001;
const ADJ_KNOWN: u32 = ADJ_OFFSET
    | ADJ_FREQUENCY
    | ADJ_MAXERROR
    | ADJ_ESTERROR
    | ADJ_STATUS
    | ADJ_TIMECONST
    | ADJ_TAI
    | ADJ_SETOFFSET
    | ADJ_MICRO
    | ADJ_NANO
    | ADJ_TICK;
const STA_INS: i32 = 0x0010;
const STA_DEL: i32 = 0x0020;
const STA_NANO: i32 = 0x2000;
/// The status bits a caller may set (STA_PLL to STA_FREQHOLD), and those
/// it may pass back as read (STA_PPSSIGNAL to STA_CLK).
const STA_WRITABLE: i32 = 0x00FF;
const STA_READ_ONLY: i32 = 0xFF00;
const TIME_OK: u64 = 0;
const TIME_ERROR: u64 = 5;
/// The most ADJ_OFFSET slews: half a second.
const MAX_PHASE_NS: i64 = 500_000_000;

/// adjtimex(2): clock_adjtime(CLOCK_REALTIME, buf).
pub fn adjtimex(a: Args) -> Result {
    adjust_clock(a.0[0])
}

/// clock_adjtime(2): the wall clock only.
pub fn clock_adjtime(a: Args) -> Result {
    match a.0[0] {
        CLOCK_REALTIME => adjust_clock(a.0[1]),
        _ => Err(EINVAL),
    }
}

fn adjust_clock(ptr: u64) -> Result {
    let mut tx = [0u8; TIMEX_SIZE];
    crate::arch::uaccess::copy_from_user(&mut tx, ptr).map_err(|_| EFAULT)?;
    let i64_at = |b: &[u8; TIMEX_SIZE], o: usize| i64::from_ne_bytes(b[o..o + 8].try_into().unwrap());
    let i32_at = |b: &[u8; TIMEX_SIZE], o: usize| i32::from_ne_bytes(b[o..o + 4].try_into().unwrap());
    let modes = u32::from_ne_bytes(tx[TX_MODES..TX_MODES + 4].try_into().unwrap());
    if modes != 0
        && modes != ADJ_OFFSET_SS_READ
        && !crate::proc::cred::current().capable(crate::proc::cred::CAP_SYS_TIME)
    {
        return Err(EPERM);
    }
    let nano = time::adjustment().status & STA_NANO != 0;
    // The units of `offset` and `time`'s second field: what the status
    // says, or what this call switches to.
    let nano = (nano || modes & ADJ_NANO != 0) && modes & ADJ_MICRO == 0;
    let unit = if nano { 1 } else { 1000 };
    let mut previous_slew = None;
    if modes & ADJ_ADJTIME != 0 {
        match modes {
            ADJ_OFFSET_SS_READ => {}
            ADJ_OFFSET_SINGLESHOT => {
                // adjtime(3): microseconds, whatever the status's units.
                let slew = i64_at(&tx, TX_OFFSET).saturating_mul(1000);
                previous_slew = Some(time::adjust(|a| a.slew_ns = slew).slew_ns);
            }
            _ => return Err(EINVAL),
        }
    } else if modes != 0 {
        if modes & !ADJ_KNOWN != 0 {
            return Err(EINVAL);
        }
        let status = i32_at(&tx, TX_STATUS);
        if modes & ADJ_STATUS != 0 && status & !(STA_WRITABLE | STA_READ_ONLY) != 0 {
            return Err(EINVAL);
        }
        let tick = i64_at(&tx, TX_TICK);
        if modes & ADJ_TICK != 0 && !(time::TICK_MIN..=time::TICK_MAX).contains(&tick) {
            return Err(EINVAL);
        }
        if modes & ADJ_SETOFFSET != 0 {
            // A step by a timeval (a timespec with ADJ_NANO).
            let (sec, frac) = (i64_at(&tx, TX_TIME), i64_at(&tx, TX_TIME + 8));
            let per = if modes & ADJ_NANO != 0 { NS_PER_SEC as i64 } else { 1_000_000 };
            if !(0..per).contains(&frac) {
                return Err(EINVAL);
            }
            let delta =
                i128::from(sec) * i128::from(NS_PER_SEC) + i128::from(frac) * i128::from(NS_PER_SEC as i64 / per);
            set_realtime(time::realtime_ns() + delta)?;
        }
        if modes & ADJ_STATUS != 0 && status & (STA_INS | STA_DEL) != 0 {
            crate::log_warn!("adjtimex: leap seconds are not applied (STA_INS/STA_DEL kept only)");
        }
        let (freq, maxerror, esterror, constant) =
            (i64_at(&tx, TX_FREQ), i64_at(&tx, TX_MAXERROR), i64_at(&tx, TX_ESTERROR), i64_at(&tx, TX_CONSTANT));
        let (offset, tai) = (i64_at(&tx, TX_OFFSET), i32_at(&tx, TX_TAI));
        time::adjust(|a| {
            if modes & ADJ_STATUS != 0 {
                a.status = (a.status & !STA_WRITABLE) | (status & STA_WRITABLE);
            }
            if nano {
                a.status |= STA_NANO;
            } else {
                a.status &= !STA_NANO;
            }
            if modes & ADJ_FREQUENCY != 0 {
                a.freq = freq.clamp(-time::MAX_FREQ, time::MAX_FREQ);
            }
            if modes & ADJ_TICK != 0 {
                a.tick = tick;
            }
            if modes & ADJ_MAXERROR != 0 {
                a.maxerror = maxerror;
            }
            if modes & ADJ_ESTERROR != 0 {
                a.esterror = esterror;
            }
            if modes & ADJ_TIMECONST != 0 {
                a.constant = constant;
            }
            if modes & ADJ_TAI != 0 {
                a.tai = tai;
            }
            if modes & ADJ_OFFSET != 0 {
                a.slew_ns = offset.saturating_mul(unit).clamp(-MAX_PHASE_NS, MAX_PHASE_NS);
            }
        });
    }
    // What the clock is now.
    let a = time::adjustment();
    let put = |b: &mut [u8; TIMEX_SIZE], o: usize, v: i64| b[o..o + 8].copy_from_slice(&v.to_ne_bytes());
    let mut out = tx;
    let slew = previous_slew.unwrap_or(a.slew_ns);
    // The single shot and its read always speak microseconds.
    let slew_unit = if modes & ADJ_ADJTIME != 0 { 1000 } else { unit };
    put(&mut out, TX_OFFSET, slew / slew_unit);
    put(&mut out, TX_FREQ, a.freq);
    put(&mut out, TX_MAXERROR, a.maxerror);
    put(&mut out, TX_ESTERROR, a.esterror);
    out[TX_STATUS..TX_STATUS + 4].copy_from_slice(&a.status.to_ne_bytes());
    put(&mut out, TX_CONSTANT, a.constant);
    put(&mut out, TX_PRECISION, 1);
    put(&mut out, TX_TOLERANCE, time::MAX_FREQ);
    let now = time::realtime_ns();
    put(&mut out, TX_TIME, now.div_euclid(i128::from(NS_PER_SEC)) as i64);
    let frac = now.rem_euclid(i128::from(NS_PER_SEC)) as i64;
    put(&mut out, TX_TIME + 8, if a.status & STA_NANO != 0 { frac } else { frac / 1000 });
    put(&mut out, TX_TICK, a.tick);
    out[TX_TAI..TX_TAI + 4].copy_from_slice(&a.tai.to_ne_bytes());
    crate::arch::uaccess::copy_to_user(ptr, &out).map_err(|_| EFAULT)?;
    Ok(if a.status & time::STA_UNSYNC != 0 { TIME_ERROR } else { TIME_OK })
}

/// The native `clock_adjust` (ADR 0078): slew by `delta_ns` (0: none),
/// marking the clock synchronized with `synced`; the slew still to come.
pub(crate) fn clock_adjust(delta_ns: i64, synced: bool) -> core::result::Result<i64, super::Errno> {
    if (delta_ns != 0 || synced) && !crate::proc::cred::current().capable(crate::proc::cred::CAP_SYS_TIME) {
        return Err(EPERM);
    }
    if delta_ns.unsigned_abs() > MAX_PHASE_NS as u64 {
        return Err(EINVAL);
    }
    Ok(time::adjust(|a| {
        if delta_ns != 0 {
            a.slew_ns = delta_ns;
        }
        if synced {
            a.status &= !time::STA_UNSYNC;
        }
    })
    .slew_ns)
}
