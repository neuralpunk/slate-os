// SPDX-License-Identifier: MIT OR Apache-2.0

//! The PC's battery-backed real-time clock: the CMOS RTC, compatible with
//! the Motorola MC146818 (its data sheet describes the registers used
//! here). The kernel provides register access ([`Cmos`]); this crate knows
//! the formats (BCD or binary, 12- or 24-hour), the update cycle, and the
//! calendar arithmetic between dates and Unix time. The clock holds UTC.
//!
//! Registers: seconds 0x00, minutes 0x02, hours 0x04, day of month 0x07,
//! month 0x08, year (two digits) 0x09, status A 0x0A (bit 7: update in
//! progress), status B 0x0B (bit 7: SET, updates held; bit 2: binary
//! rather than BCD; bit 1: 24-hour). The century lives in the register
//! the ACPI FADT's CENTURY field names, if any.

#![no_std]

/// Register access, one byte at a time.
pub trait Cmos {
    fn read(&mut self, reg: u8) -> u8;
    fn write(&mut self, reg: u8, value: u8);
}

pub const SECONDS: u8 = 0x00;
pub const MINUTES: u8 = 0x02;
pub const HOURS: u8 = 0x04;
pub const DAY: u8 = 0x07;
pub const MONTH: u8 = 0x08;
pub const YEAR: u8 = 0x09;
pub const STATUS_A: u8 = 0x0A;
pub const STATUS_B: u8 = 0x0B;

/// Status A: the clock is updating; its time registers are not stable.
pub const A_UPDATE_IN_PROGRESS: u8 = 0x80;
/// Status B: updates are held while the time is written.
pub const B_SET: u8 = 0x80;
/// Status B: values are binary, not BCD.
pub const B_BINARY: u8 = 0x04;
/// Status B: hours count 0-23, not 1-12 with bit 7 for PM.
pub const B_24_HOUR: u8 = 0x02;
/// The PM bit of the hours register in 12-hour mode.
const PM: u8 = 0x80;

/// A UTC date and time to the second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateTime {
    pub year: i64,
    /// 1-12
    pub month: u8,
    /// 1-31
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`, public domain).
pub fn days_from_civil(y: i64, m: u8, d: u8) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date `days` after 1970-01-01 (Hinnant's `civil_from_days`).
pub fn civil_from_days(days: i64) -> (i64, u8, u8) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    let y = yoe + era * 400;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

impl DateTime {
    pub fn to_unix(&self) -> i64 {
        days_from_civil(self.year, self.month, self.day) * 86_400
            + i64::from(self.hour) * 3600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
    }

    pub fn from_unix(t: i64) -> DateTime {
        let (year, month, day) = civil_from_days(t.div_euclid(86_400));
        let s = t.rem_euclid(86_400);
        DateTime { year, month, day, hour: (s / 3600) as u8, minute: (s / 60 % 60) as u8, second: (s % 60) as u8 }
    }

    fn valid(&self) -> bool {
        let days_in_month = match self.month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if (self.year % 4 == 0 && self.year % 100 != 0) || self.year % 400 == 0 => 29,
            2 => 28,
            _ => return false,
        };
        (1..=days_in_month).contains(&self.day) && self.hour < 24 && self.minute < 60 && self.second < 60
    }
}

fn from_bcd(v: u8) -> Option<u8> {
    let (hi, lo) = (v >> 4, v & 0xF);
    (hi < 10 && lo < 10).then_some(hi * 10 + lo)
}

fn to_bcd(v: u8) -> u8 {
    ((v / 10) << 4) | (v % 10)
}

/// The raw time registers, read in one go.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Raw([u8; 7]);

fn read_raw(c: &mut impl Cmos, century: Option<u8>) -> Raw {
    Raw([
        c.read(SECONDS),
        c.read(MINUTES),
        c.read(HOURS),
        c.read(DAY),
        c.read(MONTH),
        c.read(YEAR),
        century.map_or(0, |r| c.read(r)),
    ])
}

/// Wait (a bounded number of polls) for no update to be in progress.
fn settle(c: &mut impl Cmos) -> bool {
    (0..1_000_000).any(|_| c.read(STATUS_A) & A_UPDATE_IN_PROGRESS == 0)
}

/// Read the clock. `century`: the century register, from the FADT. Reads
/// until two passes outside an update agree; `None` if the clock never
/// settles or holds an impossible time.
pub fn read(c: &mut impl Cmos, century: Option<u8>) -> Option<DateTime> {
    let mut last = None;
    for _ in 0..8 {
        if !settle(c) {
            return None;
        }
        let r = read_raw(c, century);
        if last == Some(r) {
            return decode(r, c.read(STATUS_B), century.is_some());
        }
        last = Some(r);
    }
    None
}

fn decode(Raw(r): Raw, status_b: u8, has_century: bool) -> Option<DateTime> {
    let binary = status_b & B_BINARY != 0;
    let conv = |v: u8| if binary { Some(v) } else { from_bcd(v) };
    let mut hour = conv(r[2] & !PM)?;
    if status_b & B_24_HOUR == 0 {
        // 12-hour mode: 12 AM is midnight, 12 PM noon.
        hour %= 12;
        if r[2] & PM != 0 {
            hour += 12;
        }
    }
    let yy = i64::from(conv(r[5])?);
    // Without a century register, assume 2000-2099.
    let year = if has_century { i64::from(conv(r[6])?) * 100 + yy } else { 2000 + yy };
    let t = DateTime { year, month: conv(r[4])?, day: conv(r[3])?, hour, minute: conv(r[1])?, second: conv(r[0])? };
    t.valid().then_some(t)
}

/// Set the clock to `t`, in the format the clock uses, with updates held
/// while the registers change. Years outside the century register's reach
/// (or 2000-2099 without one) are refused.
pub fn write(c: &mut impl Cmos, century: Option<u8>, t: &DateTime) -> bool {
    let fits = if century.is_some() { (0..10_000).contains(&t.year) } else { (2000..2100).contains(&t.year) };
    if !t.valid() || !fits {
        return false;
    }
    let b = c.read(STATUS_B);
    let binary = b & B_BINARY != 0;
    let conv = |v: u8| if binary { v } else { to_bcd(v) };
    let hour = if b & B_24_HOUR != 0 {
        conv(t.hour)
    } else {
        let h12 = if t.hour % 12 == 0 { 12 } else { t.hour % 12 };
        conv(h12) | if t.hour >= 12 { PM } else { 0 }
    };
    c.write(STATUS_B, b | B_SET);
    c.write(SECONDS, conv(t.second));
    c.write(MINUTES, conv(t.minute));
    c.write(HOURS, hour);
    c.write(DAY, conv(t.day));
    c.write(MONTH, conv(t.month));
    c.write(YEAR, conv((t.year % 100) as u8));
    if let Some(r) = century {
        c.write(r, conv((t.year / 100) as u8));
    }
    c.write(STATUS_B, b & !B_SET);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clock that reports an update in progress for its first `busy`
    /// status reads.
    struct Fake {
        regs: [u8; 128],
        busy: u32,
    }

    impl Cmos for Fake {
        fn read(&mut self, reg: u8) -> u8 {
            if reg == STATUS_A && self.busy > 0 {
                self.busy -= 1;
                return A_UPDATE_IN_PROGRESS;
            }
            self.regs[usize::from(reg)]
        }
        fn write(&mut self, reg: u8, value: u8) {
            self.regs[usize::from(reg)] = value;
        }
    }

    fn fake(status_b: u8) -> Fake {
        let mut regs = [0; 128];
        regs[usize::from(STATUS_B)] = status_b;
        Fake { regs, busy: 3 }
    }

    #[test]
    fn unix_round_trips() {
        for (t, unix) in [
            (DateTime { year: 2026, month: 10, day: 20, hour: 12, minute: 34, second: 56 }, 1_792_499_696),
            (DateTime { year: 2000, month: 2, day: 29, hour: 23, minute: 59, second: 59 }, 951_868_799),
            (DateTime { year: 1999, month: 12, day: 31, hour: 0, minute: 0, second: 0 }, 946_598_400),
            (DateTime { year: 2099, month: 12, day: 31, hour: 23, minute: 59, second: 59 }, 4_102_444_799),
            (DateTime { year: 2038, month: 1, day: 19, hour: 3, minute: 14, second: 8 }, 2_147_483_648),
        ] {
            assert_eq!(t.to_unix(), unix);
            assert_eq!(DateTime::from_unix(unix), t);
        }
    }

    #[test]
    fn every_format_round_trips() {
        let times = [
            DateTime { year: 2026, month: 10, day: 20, hour: 0, minute: 5, second: 9 },
            DateTime { year: 2026, month: 10, day: 20, hour: 12, minute: 0, second: 0 },
            DateTime { year: 2031, month: 2, day: 28, hour: 23, minute: 59, second: 58 },
        ];
        for b in [0, B_BINARY, B_24_HOUR, B_BINARY | B_24_HOUR] {
            for century in [None, Some(0x32)] {
                for t in &times {
                    let mut c = fake(b);
                    assert!(write(&mut c, century, t));
                    assert_eq!(c.regs[usize::from(STATUS_B)], b, "SET is cleared again");
                    assert_eq!(read(&mut c, century), Some(*t), "status B {b:#x}, century {century:?}");
                }
            }
        }
    }

    #[test]
    fn decodes_bcd_12_hour() {
        let mut c = fake(0);
        // 11:45:30 PM on 2026-10-20, century 20.
        for (r, v) in [(SECONDS, 0x30), (MINUTES, 0x45), (HOURS, 0x80 | 0x11), (DAY, 0x20), (MONTH, 0x10), (YEAR, 0x26)]
        {
            c.regs[usize::from(r)] = v;
        }
        c.regs[0x32] = 0x20;
        let t = read(&mut c, Some(0x32)).unwrap();
        assert_eq!((t.year, t.month, t.day, t.hour, t.minute, t.second), (2026, 10, 20, 23, 45, 30));
        // 12 AM is midnight.
        c.regs[usize::from(HOURS)] = 0x12;
        assert_eq!(read(&mut c, Some(0x32)).unwrap().hour, 0);
    }

    #[test]
    fn refuses_nonsense() {
        let mut c = fake(B_24_HOUR);
        c.regs[usize::from(MONTH)] = 0x13;
        c.regs[usize::from(DAY)] = 0x01;
        assert_eq!(read(&mut c, None), None);
        c.regs[usize::from(MONTH)] = 0x02;
        c.regs[usize::from(DAY)] = 0x30;
        assert_eq!(read(&mut c, None), None);
        let t = DateTime { year: 2150, month: 1, day: 1, hour: 0, minute: 0, second: 0 };
        assert!(!write(&mut c, None, &t));
        assert!(write(&mut c, Some(0x32), &t));
    }
}
