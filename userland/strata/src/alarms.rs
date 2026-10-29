// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Clock's alarms (ADR 0104 and its addendum), shared with Strata,
//! which opens the Clock to ring one when the Clock isn't running. They
//! are `alarm=` lines in `~/.config/strata/clock`:
//!
//! ```text
//! alarm=07:30 on                 every day
//! alarm=07:30 on mon tue thu     on those days
//! alarm=09:00 off sat sun
//! alarm=06:15 on once            the next time it comes, then off
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::time::Tm;

/// The days an alarm rings on: bit N is weekday N (0 = Sunday); none is
/// once.
pub const EVERY_DAY: u8 = 0x7F;
pub const WEEKDAYS: u8 = 0x3E;
pub const WEEKENDS: u8 = 0x41;
pub const ONCE: u8 = 0;

/// The days' names in the file, Sunday first (as `Tm::weekday`).
const NAMES: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
const SHOWN: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Alarm {
    pub hour: u8,
    pub min: u8,
    pub on: bool,
    pub days: u8,
}

impl Alarm {
    /// "07:30" (on, every day).
    pub fn at(s: &str) -> Option<Alarm> {
        let (h, m) = s.split_once(':')?;
        let (hour, min) = (h.parse::<u8>().ok()?, m.parse::<u8>().ok()?);
        (hour < 24 && min < 60 && h.len() <= 2 && m.len() == 2).then_some(Alarm {
            hour,
            min,
            on: true,
            days: EVERY_DAY,
        })
    }

    /// An `alarm=` line's value.
    pub fn parse(value: &str) -> Option<Alarm> {
        let mut words = value.split_whitespace();
        let mut a = Alarm::at(words.next()?)?;
        let mut days = None::<u8>;
        for w in words {
            match w {
                "on" => a.on = true,
                "off" => a.on = false,
                "once" => days = Some(ONCE),
                "weekdays" => days = Some(days.unwrap_or(0) | WEEKDAYS),
                "weekends" => days = Some(days.unwrap_or(0) | WEEKENDS),
                d => {
                    if let Some(i) = NAMES.iter().position(|n| *n == d) {
                        days = Some(days.unwrap_or(0) | 1 << i);
                    }
                }
            }
        }
        a.days = days.unwrap_or(EVERY_DAY);
        Some(a)
    }

    /// As [`Alarm::parse`] reads it.
    pub fn render(&self) -> String {
        let mut s = alloc::format!("{:02}:{:02} {}", self.hour, self.min, if self.on { "on" } else { "off" });
        match self.days {
            EVERY_DAY => {}
            ONCE => s.push_str(" once"),
            d => {
                for (i, n) in NAMES.iter().enumerate() {
                    if d & 1 << i != 0 {
                        s.push(' ');
                        s.push_str(n);
                    }
                }
            }
        }
        s
    }

    /// Whether it rings at `t`'s minute.
    pub fn rings(&self, t: &Tm) -> bool {
        self.on
            && u32::from(self.hour) == t.hour
            && u32::from(self.min) == t.min
            && (self.days == ONCE || self.days & 1 << (t.weekday % 7) != 0)
    }

    /// The days, as the Clock shows them under the time.
    pub fn days_text(&self) -> String {
        match self.days {
            EVERY_DAY => String::from("every day"),
            WEEKDAYS => String::from("weekdays"),
            WEEKENDS => String::from("weekends"),
            ONCE => String::from("once"),
            d => {
                // Monday first, as people read a week.
                let shown: Vec<&str> =
                    [1, 2, 3, 4, 5, 6, 0].iter().filter(|&&i| d & 1 << i != 0).map(|&i| SHOWN[i]).collect();
                shown.join(" ")
            }
        }
    }

    /// The next set of days `d` gives: every day, weekdays, weekends,
    /// once.
    pub fn next_days(&mut self) {
        self.days = match self.days {
            EVERY_DAY => WEEKDAYS,
            WEEKDAYS => WEEKENDS,
            WEEKENDS => ONCE,
            _ => EVERY_DAY,
        };
    }

    /// A day switched (0 = Sunday); no days left is once.
    pub fn toggle_day(&mut self, day: u32) {
        self.days ^= 1 << (day % 7);
    }
}

/// The alarms in the Clock's file.
pub fn read(text: &str) -> Vec<Alarm> {
    text.lines().filter_map(|l| l.strip_prefix("alarm=")).filter_map(Alarm::parse).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tm(weekday: u32, hour: u32, min: u32) -> Tm {
        let mut t = slate_rt::time::gmtime(0);
        (t.weekday, t.hour, t.min) = (weekday, hour, min);
        t
    }

    #[test]
    fn lines_and_days() {
        let a = Alarm::parse("07:30 on").unwrap();
        assert_eq!(a, Alarm { hour: 7, min: 30, on: true, days: EVERY_DAY });
        assert_eq!(a.render(), "07:30 on");
        let b = Alarm::parse("09:05 off mon wed fri").unwrap();
        assert_eq!((b.on, b.days, b.render()), (false, 0x2A, String::from("09:05 off mon wed fri")));
        assert_eq!(b.days_text(), "Mon Wed Fri");
        assert_eq!(Alarm::parse("06:00 on weekdays").unwrap().days_text(), "weekdays");
        assert_eq!(Alarm::parse("06:00 on sat sun").unwrap().days_text(), "weekends");
        let once = Alarm::parse("06:00 on once").unwrap();
        assert_eq!((once.days, once.render()), (ONCE, String::from("06:00 on once")));
        assert_eq!(Alarm::parse("25:00 on"), None);
        assert_eq!(read("zone=Asia/Tokyo\nalarm=07:30 on\nalarm=bad\nalarm=08:00 off\n").len(), 2);
        // d goes round; a day switched on and off.
        let mut c = a;
        for want in [WEEKDAYS, WEEKENDS, ONCE, EVERY_DAY] {
            c.next_days();
            assert_eq!(c.days, want);
        }
        c.toggle_day(0);
        assert_eq!(c.days_text(), "Mon Tue Wed Thu Fri Sat");
    }

    #[test]
    fn ringing() {
        let weekdays = Alarm { days: WEEKDAYS, ..Alarm::at("07:30").unwrap() };
        assert!(weekdays.rings(&tm(1, 7, 30)));
        assert!(!weekdays.rings(&tm(0, 7, 30)));
        assert!(!weekdays.rings(&tm(1, 7, 31)));
        let once = Alarm { days: ONCE, ..weekdays };
        assert!(once.rings(&tm(0, 7, 30)));
        assert!(!Alarm { on: false, ..once }.rings(&tm(0, 7, 30)));
    }
}
