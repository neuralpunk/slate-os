// SPDX-License-Identifier: MIT OR Apache-2.0

//! Clocks, sleeping, and calendar dates (proleptic Gregorian; the
//! day-count conversion is the standard civil-from-days arithmetic). Local
//! time is [`crate::tz`]'s.

use crate::sys;

pub const CLOCK_REALTIME: u32 = 0;
pub const CLOCK_MONOTONIC: u32 = 1;
const _: () = assert!(CLOCK_REALTIME == slate_abi::clock::REALTIME && CLOCK_MONOTONIC == slate_abi::clock::MONOTONIC);

/// (seconds, nanoseconds) of `clock`.
pub fn now(clock: u32) -> (i64, i64) {
    let mut ts = [0i64; 2];
    // The native clock numbers for REALTIME and MONOTONIC are the same.
    let _ = crate::syscall!(sys::pick(sys::CLOCK_GETTIME, slate_abi::nr::CLOCK_GET), clock, ts.as_mut_ptr());
    (ts[0], ts[1])
}

/// Set `clock` (only `CLOCK_REALTIME`) to `secs`.`nsec`: clock_settime(2),
/// natively `clock_set`. Needs root (CAP_SYS_TIME).
pub fn set(clock: u32, secs: i64, nsec: i64) -> crate::Result<()> {
    let ts = [secs, nsec];
    crate::syscall!(sys::pick(sys::CLOCK_SETTIME, slate_abi::nr::CLOCK_SET), clock, ts.as_ptr()).map(|_| ())
}

/// Slew the wall clock by `delta_ns` (0: none; at most ±0.5 s), marking
/// it synchronized with `synced`; returns the slew still to come, in
/// nanoseconds. Needs root to change anything. Natively `clock_adjust`
/// (ADR 0078); on Linux, adjtimex(2)'s single shot (microseconds).
pub fn adjust(delta_ns: i64, synced: bool) -> crate::Result<i64> {
    if sys::native() {
        let flags = if synced { slate_abi::clock_adjust::SYNCED } else { 0 };
        let mut left = 0i64;
        crate::syscall!(slate_abi::nr::CLOCK_ADJUST as usize, delta_ns, flags, &mut left as *mut i64)?;
        return Ok(left);
    }
    // struct timex (adjtimex(2); 208 bytes): modes at 0, offset at 8,
    // status at 40.
    let mut tx = [0i64; 26];
    tx[0] = if delta_ns != 0 { 0x8001 } else { 0xa001 }; // ADJ_OFFSET_SINGLESHOT, ADJ_OFFSET_SS_READ
    tx[1] = delta_ns / 1000;
    crate::syscall!(sys::ADJTIMEX, tx.as_mut_ptr())?;
    let left = tx[1] * 1000;
    if synced {
        let mut st = [0i64; 26];
        crate::syscall!(sys::ADJTIMEX, st.as_mut_ptr())?;
        st[0] = 0x0010; // ADJ_STATUS: clear STA_UNSYNC (0x40)
        st[5] &= !0x40;
        crate::syscall!(sys::ADJTIMEX, st.as_mut_ptr())?;
    }
    Ok(left)
}

/// Nanoseconds on the monotonic clock.
pub fn monotonic_ns() -> u64 {
    let (s, ns) = now(CLOCK_MONOTONIC);
    (s as u64).saturating_mul(1_000_000_000).saturating_add(ns as u64)
}

/// Wall-clock seconds since the epoch.
pub fn unix() -> i64 {
    now(CLOCK_REALTIME).0
}

/// Sleep for `ns` nanoseconds (restarting after signals handled with
/// SA_RESTART semantics is up to the caller: this returns early on EINTR).
pub fn sleep_ns(ns: u64) -> bool {
    let req = [(ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as i64];
    crate::syscall!(sys::pick(sys::NANOSLEEP, slate_abi::nr::SLEEP), req.as_ptr(), 0).is_ok()
}

/// A broken-down time: UTC from [`gmtime`], local from [`crate::tz`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tm {
    pub year: i64,
    /// 1-12
    pub month: u32,
    /// 1-31
    pub day: u32,
    pub hour: u32,
    pub min: u32,
    pub sec: u32,
    /// 0 = Sunday
    pub weekday: u32,
    /// 0-365
    pub yearday: u32,
    /// Seconds east of UTC.
    pub offset: i32,
    /// The zone's abbreviation.
    pub zone: crate::tz::Abbrev,
}

fn days_to_civil(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Days since the epoch of a civil date.
pub fn civil_to_days(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

pub fn gmtime(t: i64) -> Tm {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400) as u32;
    let (year, month, day) = days_to_civil(days);
    let yearday = (days - civil_to_days(year, 1, 1)) as u32;
    Tm {
        year,
        month,
        day,
        hour: secs / 3600,
        min: secs / 60 % 60,
        sec: secs % 60,
        weekday: (days + 4).rem_euclid(7) as u32,
        yearday,
        offset: 0,
        zone: crate::tz::Abbrev::default(),
    }
}

pub fn timegm(tm: &Tm) -> i64 {
    civil_to_days(tm.year, tm.month, tm.day) * 86_400
        + i64::from(tm.hour) * 3600
        + i64::from(tm.min) * 60
        + i64::from(tm.sec)
}

pub const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
pub const FULL_DAYS: [&str; 7] = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
pub const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
pub const FULL_MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// strftime(3)-style formatting of the common conversions.
pub fn format(tm: &Tm, fmt: &str, out: &mut alloc::string::String) {
    use core::fmt::Write;
    let mut it = fmt.chars();
    while let Some(c) = it.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        let Some(f) = it.next() else {
            out.push('%');
            break;
        };
        let _ = match f {
            'Y' => write!(out, "{}", tm.year),
            'C' => write!(out, "{:02}", tm.year / 100),
            'y' => write!(out, "{:02}", tm.year % 100),
            'm' => write!(out, "{:02}", tm.month),
            'd' => write!(out, "{:02}", tm.day),
            'e' => write!(out, "{:2}", tm.day),
            'H' => write!(out, "{:02}", tm.hour),
            'I' => write!(out, "{:02}", if tm.hour % 12 == 0 { 12 } else { tm.hour % 12 }),
            'M' => write!(out, "{:02}", tm.min),
            'S' => write!(out, "{:02}", tm.sec),
            'p' => write!(out, "{}", if tm.hour < 12 { "AM" } else { "PM" }),
            'a' => write!(out, "{}", DAYS[tm.weekday as usize]),
            'A' => write!(out, "{}", FULL_DAYS[tm.weekday as usize]),
            'b' | 'h' => write!(out, "{}", MONTHS[tm.month as usize - 1]),
            'B' => write!(out, "{}", FULL_MONTHS[tm.month as usize - 1]),
            'j' => write!(out, "{:03}", tm.yearday + 1),
            'u' => write!(out, "{}", if tm.weekday == 0 { 7 } else { tm.weekday }),
            'w' => write!(out, "{}", tm.weekday),
            'Z' => write!(out, "{}", tm.zone.as_str()),
            'z' => {
                let m = tm.offset.unsigned_abs() / 60;
                write!(out, "{}{:02}{:02}", if tm.offset < 0 { '-' } else { '+' }, m / 60, m % 60)
            }
            's' => write!(out, "{}", timegm(tm) - i64::from(tm.offset)),
            'n' => writeln!(out),
            't' => write!(out, "\t"),
            'F' => write!(out, "{}-{:02}-{:02}", tm.year, tm.month, tm.day),
            'T' => write!(out, "{:02}:{:02}:{:02}", tm.hour, tm.min, tm.sec),
            'R' => write!(out, "{:02}:{:02}", tm.hour, tm.min),
            'D' => write!(out, "{:02}/{:02}/{:02}", tm.month, tm.day, tm.year % 100),
            'c' => write!(
                out,
                "{} {} {:2} {:02}:{:02}:{:02} {}",
                DAYS[tm.weekday as usize],
                MONTHS[tm.month as usize - 1],
                tm.day,
                tm.hour,
                tm.min,
                tm.sec,
                tm.year
            ),
            '%' => write!(out, "%"),
            other => write!(out, "%{other}"),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        // 2026-10-17T12:34:56Z, a Saturday.
        let t = 1_792_240_496;
        let tm = gmtime(t);
        assert_eq!((tm.year, tm.month, tm.day, tm.hour, tm.min, tm.sec, tm.weekday), (2026, 10, 17, 12, 34, 56, 6));
        assert_eq!(timegm(&tm), t);
        assert_eq!(gmtime(0).weekday, 4); // 1970-01-01 was a Thursday.
        assert_eq!(gmtime(-86_400).year, 1969);
    }
}
