// SPDX-License-Identifier: MIT OR Apache-2.0

//! Days of the proleptic Gregorian calendar (RFC 5545 §3.3.4's dates):
//! a date, the days since 1970-01-01, and the weekday.

/// A date (year, month 1-12, day 1-31), always a real one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date {
    pub year: i32,
    pub month: u8,
    pub day: u8,
}

pub fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

pub fn month_days(y: i32, m: u8) -> u8 {
    match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

impl Date {
    pub fn new(year: i32, month: u8, day: u8) -> Option<Date> {
        ((1..=12).contains(&month) && day >= 1 && day <= month_days(year, month) && (1..=9999).contains(&year))
            .then_some(Date { year, month, day })
    }

    /// Days since 1970-01-01.
    pub fn days(&self) -> i64 {
        let (y, m, d) = (i64::from(self.year), i64::from(self.month), i64::from(self.day));
        let y = if m <= 2 { y - 1 } else { y };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let mp = (m + 9) % 12;
        let doy = (153 * mp + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    /// `YYYYMMDD`.
    pub fn compact(&self) -> alloc::string::String {
        alloc::format!("{:04}{:02}{:02}", self.year, self.month, self.day)
    }

    /// The first of its month.
    pub fn first_of_month(&self) -> Date {
        Date { day: 1, ..*self }
    }

    /// `n` months on (or back), the day kept where the month has it, else
    /// its last day.
    pub fn add_months(&self, n: i32) -> Date {
        let m0 = self.year * 12 + i32::from(self.month) - 1 + n;
        let (y, m) = (m0.div_euclid(12), (m0.rem_euclid(12) + 1) as u8);
        Date { year: y, month: m, day: self.day.min(month_days(y, m)) }
    }
}

/// The date `days` after 1970-01-01.
pub fn days_to_date(days: i64) -> Date {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    let y = yoe + era * 400 + i64::from(m <= 2);
    Date { year: y as i32, month: m, day: d }
}

/// 0 Sunday to 6 Saturday.
pub fn weekday(d: Date) -> u8 {
    // 1970-01-01 was a Thursday.
    (d.days() + 4).rem_euclid(7) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_and_weekdays() {
        let d = Date::new(2026, 10, 24).unwrap();
        assert_eq!(days_to_date(d.days()), d);
        assert_eq!(weekday(d), 6, "a Saturday");
        assert_eq!(Date::new(2026, 2, 29), None);
        assert_eq!(Date::new(2024, 2, 29).unwrap().add_months(12), Date::new(2025, 2, 28).unwrap());
        assert_eq!(Date::new(2026, 1, 31).unwrap().add_months(-2), Date::new(2025, 11, 30).unwrap());
        assert_eq!(days_to_date(0), Date::new(1970, 1, 1).unwrap());
        assert_eq!(d.compact(), "20261024");
    }
}
