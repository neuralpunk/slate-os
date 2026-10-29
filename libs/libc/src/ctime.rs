// SPDX-License-Identifier: MIT OR Apache-2.0

//! <time.h>'s calendar functions and <sys/time.h> (C11 7.27, POSIX;
//! ADR 0075): gmtime, localtime (slate-rt's zones, docs/GAPS.md), mktime,
//! timegm, strftime with every C11 conversion in the C locale, asctime,
//! ctime, difftime, clock and gettimeofday. The `_r` forms are
//! thread-safe; the others return a buffer per thread.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_long};

use slate_rt::sync::Mutex;
use slate_rt::time::{self as rtime, Tm};
use slate_rt::tz;

/// `struct tm`, with the common tm_gmtoff and tm_zone fields.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CTm {
    sec: c_int,
    min: c_int,
    hour: c_int,
    mday: c_int,
    mon: c_int,
    year: c_int,
    wday: c_int,
    yday: c_int,
    isdst: c_int,
    gmtoff: c_long,
    zone: *const c_char,
}

const EMPTY: CTm = CTm {
    sec: 0,
    min: 0,
    hour: 0,
    mday: 0,
    mon: 0,
    year: 0,
    wday: 0,
    yday: 0,
    isdst: 0,
    gmtoff: 0,
    zone: core::ptr::null(),
};

/// Zone abbreviations handed out as `tm_zone`, each kept for good (there
/// are only ever a few).
static ZONES: Mutex<Vec<Box<[u8]>>> = Mutex::new(Vec::new());

fn zone_ptr(name: &str) -> *const c_char {
    let mut z = ZONES.lock();
    if let Some(b) = z.iter().find(|b| &b[..b.len() - 1] == name.as_bytes()) {
        return b.as_ptr() as *const c_char;
    }
    let mut v = name.as_bytes().to_vec();
    v.push(0);
    let b: Box<[u8]> = v.into_boxed_slice();
    let p = b.as_ptr() as *const c_char;
    z.push(b);
    p
}

fn to_c(tm: &Tm, dst: bool) -> CTm {
    CTm {
        sec: tm.sec as c_int,
        min: tm.min as c_int,
        hour: tm.hour as c_int,
        mday: tm.day as c_int,
        mon: tm.month as c_int - 1,
        year: (tm.year - 1900) as c_int,
        wday: tm.weekday as c_int,
        yday: tm.yearday as c_int,
        isdst: c_int::from(dst),
        gmtoff: c_long::from(tm.offset),
        zone: zone_ptr(tm.zone.as_str()),
    }
}

/// The fields of `t` normalised (months past 11, days past the month's
/// end and so on carry over) as seconds counted like UTC.
fn fields_seconds(t: &CTm) -> i64 {
    let mon = i64::from(t.mon);
    let year = i64::from(t.year) + 1900 + mon.div_euclid(12);
    let month = mon.rem_euclid(12) as u32 + 1;
    let days = rtime::civil_to_days(year, month, 1) + i64::from(t.mday) - 1;
    days * 86_400 + i64::from(t.hour) * 3600 + i64::from(t.min) * 60 + i64::from(t.sec)
}

/// One `struct tm` per thread for the functions that return a pointer.
struct PerThread(UnsafeCell<CTm>);

#[thread_local]
static TM_BUF: PerThread = PerThread(UnsafeCell::new(EMPTY));

#[thread_local]
static ASC_BUF: UnsafeCell<[u8; 32]> = UnsafeCell::new([0; 32]);

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn gmtime_r(t: *const c_long, out: *mut CTm) -> *mut CTm {
    // SAFETY: C passes a time and room for the result.
    unsafe { *out = to_c(&rtime::gmtime(*t), false) };
    out
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn localtime_r(t: *const c_long, out: *mut CTm) -> *mut CTm {
    // SAFETY: As above.
    unsafe {
        let t = *t;
        *out = to_c(&tz::localtime(t), tz::is_summer(t));
    }
    out
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn gmtime(t: *const c_long) -> *mut CTm {
    // SAFETY: The calling thread's own buffer.
    unsafe { gmtime_r(t, TM_BUF.0.get()) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn localtime(t: *const c_long) -> *mut CTm {
    // SAFETY: As above.
    unsafe { localtime_r(t, TM_BUF.0.get()) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn timegm(tm: *mut CTm) -> c_long {
    // SAFETY: C passes a `struct tm`, normalised in place.
    unsafe {
        let t = fields_seconds(&*tm);
        *tm = to_c(&rtime::gmtime(t), false);
        t
    }
}

/// mktime: the fields as local time. The `tm_isdst` hint is not used: a
/// time repeated by a change of offset gets one of its two meanings
/// (docs/GAPS.md).
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn mktime(tm: *mut CTm) -> c_long {
    // SAFETY: C passes a `struct tm`, normalised in place.
    unsafe {
        let local = fields_seconds(&*tm);
        let t = tz::timelocal(&rtime::gmtime(local));
        *tm = to_c(&tz::localtime(t), tz::is_summer(t));
        t
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn difftime(a: c_long, b: c_long) -> f64 {
    (a - b) as f64
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn tzset() {
    tz::reload();
}

const DAYS: [&[u8]; 7] = [b"Sunday", b"Monday", b"Tuesday", b"Wednesday", b"Thursday", b"Friday", b"Saturday"];
const MONTHS: [&[u8]; 12] = [
    b"January",
    b"February",
    b"March",
    b"April",
    b"May",
    b"June",
    b"July",
    b"August",
    b"September",
    b"October",
    b"November",
    b"December",
];

fn day_name(t: &CTm) -> &'static [u8] {
    DAYS[t.wday.rem_euclid(7) as usize]
}

fn month_name(t: &CTm) -> &'static [u8] {
    MONTHS[t.mon.rem_euclid(12) as usize]
}

/// The ISO 8601 week-based year and week (%G, %V): weeks start on
/// Monday, and week 1 holds the year's first Thursday.
fn iso_week(t: &CTm) -> (i64, i64) {
    let year = i64::from(t.year) + 1900;
    let wday = i64::from((t.wday + 6) % 7); // Monday 0
    let yday = i64::from(t.yday);
    let week = (yday - wday + 10) / 7;
    let days_in = |y: i64| if rtime::is_leap(y) { 366 } else { 365 };
    if week < 1 {
        // The last week of the previous year: 52 or 53.
        let prev = year - 1;
        let pyday = yday + days_in(prev);
        return (prev, (pyday - wday + 10) / 7);
    }
    if week == 53 {
        // Week 53 only if the year ends on Thursday or later (in ISO terms).
        let dec31_wday = (wday + (days_in(year) - 1 - yday)) % 7;
        if dec31_wday < 3 {
            return (year + 1, 1);
        }
    }
    (year, week)
}

fn num(out: &mut Vec<u8>, v: i64, width: usize, pad: u8) {
    let s = alloc::format!("{}", v.unsigned_abs());
    if v < 0 {
        out.push(b'-');
    }
    for _ in s.len()..width {
        out.push(pad);
    }
    out.extend_from_slice(s.as_bytes());
}

/// strftime's conversions into `out`.
fn format(fmt: &[u8], t: &CTm, out: &mut Vec<u8>) {
    let mut i = 0;
    while i < fmt.len() {
        let c = fmt[i];
        i += 1;
        if c != b'%' {
            out.push(c);
            continue;
        }
        // The E and O modifiers change nothing in the C locale.
        if matches!(fmt.get(i), Some(b'E' | b'O')) {
            i += 1;
        }
        let Some(&f) = fmt.get(i) else {
            out.push(b'%');
            break;
        };
        i += 1;
        let year = i64::from(t.year) + 1900;
        let hour12 = if t.hour % 12 == 0 { 12 } else { t.hour % 12 };
        match f {
            b'a' => out.extend_from_slice(&day_name(t)[..3]),
            b'A' => out.extend_from_slice(day_name(t)),
            b'b' | b'h' => out.extend_from_slice(&month_name(t)[..3]),
            b'B' => out.extend_from_slice(month_name(t)),
            b'c' => format(b"%a %b %e %H:%M:%S %Y", t, out),
            b'C' => num(out, year.div_euclid(100), 2, b'0'),
            b'd' => num(out, i64::from(t.mday), 2, b'0'),
            b'D' => format(b"%m/%d/%y", t, out),
            b'e' => num(out, i64::from(t.mday), 2, b' '),
            b'F' => format(b"%Y-%m-%d", t, out),
            b'g' => num(out, iso_week(t).0.rem_euclid(100), 2, b'0'),
            b'G' => num(out, iso_week(t).0, 1, b'0'),
            b'H' => num(out, i64::from(t.hour), 2, b'0'),
            b'I' => num(out, i64::from(hour12), 2, b'0'),
            b'j' => num(out, i64::from(t.yday) + 1, 3, b'0'),
            b'm' => num(out, i64::from(t.mon) + 1, 2, b'0'),
            b'M' => num(out, i64::from(t.min), 2, b'0'),
            b'n' => out.push(b'\n'),
            b'p' => out.extend_from_slice(if t.hour < 12 { b"AM" } else { b"PM" }),
            b'r' => format(b"%I:%M:%S %p", t, out),
            b'R' => format(b"%H:%M", t, out),
            b's' => num(out, fields_seconds(t) - t.gmtoff, 1, b'0'),
            b'S' => num(out, i64::from(t.sec), 2, b'0'),
            b't' => out.push(b'\t'),
            b'T' => format(b"%H:%M:%S", t, out),
            b'u' => num(out, if t.wday == 0 { 7 } else { i64::from(t.wday) }, 1, b'0'),
            b'U' => num(out, (i64::from(t.yday) + 7 - i64::from(t.wday)) / 7, 2, b'0'),
            b'V' => num(out, iso_week(t).1, 2, b'0'),
            b'w' => num(out, i64::from(t.wday), 1, b'0'),
            b'W' => num(out, (i64::from(t.yday) + 7 - i64::from((t.wday + 6) % 7)) / 7, 2, b'0'),
            b'x' => format(b"%m/%d/%y", t, out),
            b'X' => format(b"%H:%M:%S", t, out),
            b'y' => num(out, year.rem_euclid(100), 2, b'0'),
            b'Y' => num(out, year, 1, b'0'),
            b'z' => {
                let off = t.gmtoff;
                out.push(if off < 0 { b'-' } else { b'+' });
                let m = off.unsigned_abs() / 60;
                num(out, (m / 60 * 100 + m % 60) as i64, 4, b'0');
            }
            b'Z' => {
                if !t.zone.is_null() {
                    // SAFETY: tm_zone is a NUL-terminated string when set.
                    out.extend_from_slice(unsafe { crate::cstr(t.zone) });
                }
            }
            b'%' => out.push(b'%'),
            other => {
                out.push(b'%');
                out.push(other);
            }
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strftime(s: *mut c_char, max: usize, fmt: *const c_char, tm: *const CTm) -> usize {
    let mut out = Vec::new();
    // SAFETY: C passes a format and a `struct tm`.
    unsafe { format(crate::cstr(fmt), &*tm, &mut out) };
    if out.len() >= max {
        return 0;
    }
    // SAFETY: `s` holds `max` bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(out.as_ptr(), s as *mut u8, out.len());
        *s.add(out.len()) = 0;
    }
    out.len()
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn asctime_r(tm: *const CTm, buf: *mut c_char) -> *mut c_char {
    let mut out = Vec::new();
    // SAFETY: C passes a `struct tm`.
    let t = unsafe { &*tm };
    format(b"%a %b %e %H:%M:%S ", t, &mut out);
    num(&mut out, i64::from(t.year) + 1900, 1, b'0');
    out.push(b'\n');
    out.truncate(25);
    // SAFETY: C passes 26 bytes, as asctime_r requires.
    unsafe {
        core::ptr::copy_nonoverlapping(out.as_ptr(), buf as *mut u8, out.len());
        *buf.add(out.len()) = 0;
    }
    buf
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn asctime(tm: *const CTm) -> *mut c_char {
    // SAFETY: The calling thread's own buffer of 32 bytes.
    unsafe { asctime_r(tm, ASC_BUF.get() as *mut c_char) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn ctime_r(t: *const c_long, buf: *mut c_char) -> *mut c_char {
    let mut tm = EMPTY;
    // SAFETY: Forwarded.
    unsafe {
        localtime_r(t, &mut tm);
        asctime_r(&tm, buf)
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn ctime(t: *const c_long) -> *mut c_char {
    // SAFETY: As for asctime.
    unsafe { ctime_r(t, ASC_BUF.get() as *mut c_char) }
}

/// clock(): the process's CPU time in CLOCKS_PER_SEC (a million) units.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn clock() -> c_long {
    match slate_rt::process::cpu_times() {
        Ok(t) => ((t[0] + t[1]) / 1000) as c_long,
        Err(_) => -1,
    }
}

/// gettimeofday(2): the wall clock as seconds and microseconds; the
/// obsolete zone argument is ignored.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn gettimeofday(tv: *mut [c_long; 2], _tz: *mut core::ffi::c_void) -> c_int {
    let (s, ns) = rtime::now(rtime::CLOCK_REALTIME);
    if !tv.is_null() {
        // SAFETY: C passes a `struct timeval`.
        unsafe { *tv = [s, ns / 1000] };
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::String;

    fn fmt(f: &str, t: &CTm) -> String {
        let mut out = Vec::new();
        format(f.as_bytes(), t, &mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn strftime_conversions() {
        // 2026-10-17T12:34:56Z, a Saturday.
        let mut t = EMPTY;
        // SAFETY: Local values.
        unsafe { gmtime_r(&1_792_240_496, &mut t) };
        assert_eq!(
            fmt("%Y-%m-%d %H:%M:%S %a %A %b %B %j %u %w", &t),
            "2026-10-17 12:34:56 Sat Saturday Oct October 290 6 6"
        );
        assert_eq!(
            fmt("%c|%x|%X|%r|%D|%e|%C|%y|%p|%I", &t),
            "Sat Oct 17 12:34:56 2026|10/17/26|12:34:56|12:34:56 PM|10/17/26|17|20|26|PM|12"
        );
        assert_eq!(fmt("%U %W %V %G %g %z %Z %s %%", &t), "41 41 42 2026 26 +0000 UTC 1792240496 %");
        let mut b = [0 as c_char; 32];
        // SAFETY: Room for the line.
        unsafe { asctime_r(&t, b.as_mut_ptr()) };
        // SAFETY: NUL-terminated by asctime_r.
        assert_eq!(unsafe { crate::cstr(b.as_ptr()) }, b"Sat Oct 17 12:34:56 2026\n");
        // ISO weeks at the year's edges: 2021-01-01 is in 2020's week 53,
        // 2024-12-30 in 2025's week 1.
        // SAFETY: Local values.
        unsafe { gmtime_r(&1_609_459_200, &mut t) };
        assert_eq!(fmt("%G-W%V", &t), "2020-W53");
        // SAFETY: Local values.
        unsafe { gmtime_r(&1_735_516_800, &mut t) };
        assert_eq!(fmt("%G-W%V", &t), "2025-W01");
    }

    #[test]
    fn normalising() {
        // 2026-14-35 25:61:61 is 2027-03-08 02:02:01.
        let mut t = CTm { year: 126, mon: 13, mday: 35, hour: 25, min: 61, sec: 61, ..EMPTY };
        // SAFETY: A local struct.
        let s = unsafe { timegm(&mut t) };
        assert_eq!((t.year, t.mon, t.mday, t.hour, t.min, t.sec), (127, 2, 8, 2, 2, 1));
        assert_eq!(s, rtime::civil_to_days(2027, 3, 8) * 86_400 + 2 * 3600 + 2 * 60 + 1);
        let mut out = [0 as c_char; 8];
        // SAFETY: Room for 8 bytes.
        assert_eq!(unsafe { strftime(out.as_mut_ptr(), 8, c"%Y-%m-%d".as_ptr(), &t) }, 0);
    }
}
