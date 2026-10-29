// SPDX-License-Identifier: MIT OR Apache-2.0

//! iCalendar events (RFC 5545): VEVENTs read from and written to a
//! VCALENDAR, with what calendars put in them most: UID, SUMMARY,
//! DESCRIPTION, LOCATION, DTSTART and DTEND (or DURATION), as dates
//! (all day) or times (UTC, in a named zone, or floating), and simple
//! recurrence (RRULE: FREQ, INTERVAL, COUNT, UNTIL, and BYDAY for weekly
//! rules; EXDATE). Other properties and components are kept as they
//! were, so a calendar read and written again loses nothing it had.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::date::{Date, days_to_date, weekday};
use crate::line::{self, Component, Prop};

/// A moment as the file has it (§3.3.4 DATE, §3.3.5 DATE-TIME).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum When {
    /// A whole day.
    Day(Date),
    /// A time: the date, the seconds into it, and its zone: `None`
    /// floating (whatever zone the reader is in), `Some("UTC")`, or a
    /// zone name (TZID).
    At(Date, u32, Option<String>),
}

impl When {
    pub fn date(&self) -> Date {
        match self {
            When::Day(d) | When::At(d, ..) => *d,
        }
    }

    pub fn is_day(&self) -> bool {
        matches!(self, When::Day(_))
    }

    fn parse(p: &Prop) -> Option<When> {
        let v = p.value.trim();
        let date = |s: &str| -> Option<Date> {
            if s.len() != 8 || !s.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Date::new(s[..4].parse().ok()?, s[4..6].parse().ok()?, s[6..8].parse().ok()?)
        };
        match v.split_once('T') {
            None => date(v).map(When::Day),
            Some((d, t)) => {
                let (t, utc) = match t.strip_suffix('Z') {
                    Some(t) => (t, true),
                    None => (t, false),
                };
                if t.len() < 4 || !t.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                let h: u32 = t[..2].parse().ok()?;
                let m: u32 = t[2..4].parse().ok()?;
                let s: u32 = t.get(4..6).map_or(Some(0), |x| x.parse().ok())?;
                if h > 23 || m > 59 || s > 60 {
                    return None;
                }
                let zone = if utc { Some(String::from("UTC")) } else { p.get("TZID").and_then(|z| z.first()).cloned() };
                Some(When::At(date(d)?, h * 3600 + m * 60 + s.min(59), zone))
            }
        }
    }

    fn to_prop(&self, name: &str) -> Prop {
        match self {
            When::Day(d) => Prop::new(name, &d.compact()).param("VALUE", "DATE"),
            When::At(d, secs, zone) => {
                let t = alloc::format!("{}T{:02}{:02}{:02}", d.compact(), secs / 3600, secs / 60 % 60, secs % 60);
                match zone.as_deref() {
                    Some("UTC") => Prop::new(name, &alloc::format!("{t}Z")),
                    Some(z) => Prop::new(name, &t).param("TZID", z),
                    None => Prop::new(name, &t),
                }
            }
        }
    }
}

/// §3.3.6: a duration, in seconds (weeks, days, hours, minutes, seconds;
/// a negative one is refused).
pub fn duration(s: &str) -> Option<i64> {
    let s = s.trim().strip_prefix('+').unwrap_or(s.trim());
    let s = s.strip_prefix('P')?;
    let (mut total, mut num, mut in_time) = (0i64, String::new(), false);
    for c in s.chars() {
        match c {
            'T' => in_time = true,
            '0'..='9' => num.push(c),
            _ => {
                let n: i64 = num.parse().ok()?;
                num.clear();
                total += n * match (c, in_time) {
                    ('W', _) => 7 * 86_400,
                    ('D', _) => 86_400,
                    ('H', true) => 3600,
                    ('M', true) => 60,
                    ('S', true) => 1,
                    _ => return None,
                };
            }
        }
    }
    num.is_empty().then_some(total)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freq {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

/// §3.3.10: the parts of a rule this reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repeat {
    pub freq: Freq,
    pub interval: u32,
    pub count: Option<u32>,
    /// The last day an occurrence may start on.
    pub until: Option<Date>,
    /// For weekly rules: the weekdays (0 Sunday).
    pub days: Vec<u8>,
}

const DAY_NAMES: [&str; 7] = ["SU", "MO", "TU", "WE", "TH", "FR", "SA"];

impl Repeat {
    pub fn parse(v: &str) -> Option<Repeat> {
        let mut r = Repeat { freq: Freq::Daily, interval: 1, count: None, until: None, days: Vec::new() };
        let mut freq = None;
        for part in v.split(';') {
            let (k, val) = part.split_once('=')?;
            match k.to_ascii_uppercase().as_str() {
                "FREQ" => {
                    freq = Some(match val.to_ascii_uppercase().as_str() {
                        "DAILY" => Freq::Daily,
                        "WEEKLY" => Freq::Weekly,
                        "MONTHLY" => Freq::Monthly,
                        "YEARLY" => Freq::Yearly,
                        // Hourly and finer, and others: not read.
                        _ => return None,
                    })
                }
                "INTERVAL" => r.interval = val.parse::<u32>().ok()?.max(1),
                "COUNT" => r.count = Some(val.parse().ok()?),
                "UNTIL" => r.until = When::parse(&Prop::new("UNTIL", val)).map(|w| w.date()),
                "BYDAY" => {
                    for d in val.split(',') {
                        // An ordinal (2MO) is a monthly rule's: not read.
                        let name = d.trim_start_matches(['+', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']);
                        if name.len() != d.len() {
                            return None;
                        }
                        r.days.push(DAY_NAMES.iter().position(|n| n.eq_ignore_ascii_case(name))? as u8);
                    }
                }
                "WKST" => {}
                // BYMONTHDAY, BYSETPOS and the rest: a rule this doesn't
                // understand isn't guessed at.
                _ => return None,
            }
        }
        r.freq = freq?;
        Some(r)
    }

    pub fn render(&self) -> String {
        let f = match self.freq {
            Freq::Daily => "DAILY",
            Freq::Weekly => "WEEKLY",
            Freq::Monthly => "MONTHLY",
            Freq::Yearly => "YEARLY",
        };
        let mut s = alloc::format!("FREQ={f}");
        if self.interval > 1 {
            s.push_str(&alloc::format!(";INTERVAL={}", self.interval));
        }
        if let Some(c) = self.count {
            s.push_str(&alloc::format!(";COUNT={c}"));
        }
        if let Some(u) = self.until {
            s.push_str(&alloc::format!(";UNTIL={}", u.compact()));
        }
        if !self.days.is_empty() {
            let names: Vec<&str> = self.days.iter().map(|&d| DAY_NAMES[usize::from(d % 7)]).collect();
            s.push_str(&alloc::format!(";BYDAY={}", names.join(",")));
        }
        s
    }

    /// The days occurrences start on from `start`, up to `to` (and at most
    /// `limit` of them).
    pub fn days_from(&self, start: Date, to: Date, limit: usize) -> Vec<Date> {
        let mut out = Vec::new();
        let mut n = 0u32;
        let ok = |d: Date, n: u32| self.count.is_none_or(|c| n < c) && self.until.is_none_or(|u| d <= u);
        let step = i64::from(self.interval.max(1));
        match self.freq {
            Freq::Daily => {
                let mut d = start.days();
                while d <= to.days() && out.len() < limit {
                    let day = days_to_date(d);
                    if !ok(day, n) {
                        break;
                    }
                    out.push(day);
                    n += 1;
                    d += step;
                }
            }
            Freq::Weekly => {
                let days = if self.days.is_empty() { alloc::vec![weekday(start)] } else { self.days.clone() };
                // The weeks counted from the start's week (Sunday first).
                let week0 = start.days() - i64::from(weekday(start));
                let mut w = 0i64;
                'weeks: while week0 + w * 7 <= to.days() && out.len() < limit {
                    let mut ds: Vec<u8> = days.clone();
                    ds.sort_unstable();
                    for wd in ds {
                        let d = week0 + w * 7 + i64::from(wd);
                        if d < start.days() {
                            continue;
                        }
                        let day = days_to_date(d);
                        if d > to.days() || !ok(day, n) {
                            break 'weeks;
                        }
                        out.push(day);
                        n += 1;
                    }
                    w += step;
                }
            }
            Freq::Monthly | Freq::Yearly => {
                let months = if self.freq == Freq::Monthly { step } else { step * 12 };
                let mut k = 0i64;
                while out.len() < limit {
                    let m0 = i64::from(start.month) - 1 + k * months;
                    let (y, m) = (i64::from(start.year) + m0.div_euclid(12), m0.rem_euclid(12) as u8 + 1);
                    k += 1;
                    // The 31st in a month without one: that month is
                    // skipped (§3.3.10: invalid dates are ignored).
                    let Some(day) = Date::new(y as i32, m, start.day) else {
                        if y > i64::from(to.year) {
                            break;
                        }
                        continue;
                    };
                    if day > to || !ok(day, n) {
                        break;
                    }
                    out.push(day);
                    n += 1;
                }
            }
        }
        out
    }
}

/// An event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub uid: String,
    pub summary: String,
    pub description: String,
    pub location: String,
    pub start: When,
    /// The end, exclusive (an all-day event on one day ends the next).
    pub end: When,
    pub repeat: Option<Repeat>,
    /// Days left out of the repetition.
    pub except: Vec<Date>,
    /// Properties this doesn't read, kept as they were.
    pub other: Vec<Prop>,
    pub children: Vec<Component>,
}

impl Event {
    /// The event in a VEVENT, if it has a start.
    pub fn from_component(c: &Component) -> Option<Event> {
        let start = When::parse(c.prop("DTSTART")?)?;
        let end = match (c.prop("DTEND").and_then(When::parse), c.prop("DURATION").and_then(|p| duration(&p.value))) {
            (Some(e), _) => e,
            (None, Some(secs)) => add_seconds(&start, secs),
            // §3.6.1: a date lasts a day; a time, no time at all.
            (None, None) => match &start {
                When::Day(d) => When::Day(days_to_date(d.days() + 1)),
                w => w.clone(),
            },
        };
        let read = ["UID", "SUMMARY", "DESCRIPTION", "LOCATION", "DTSTART", "DTEND", "DURATION", "RRULE", "EXDATE"];
        let repeat = c.prop("RRULE").and_then(|p| Repeat::parse(&p.value));
        // A rule this can't follow is kept as written rather than lost.
        let mut other: Vec<Prop> = c.props.iter().filter(|p| !read.contains(&p.name.as_str())).cloned().collect();
        if repeat.is_none()
            && let Some(p) = c.prop("RRULE")
        {
            other.push(p.clone());
        }
        let except = c
            .all("EXDATE")
            .flat_map(|p| {
                p.value
                    .split(',')
                    .filter_map(|v| When::parse(&Prop { value: v.to_string(), ..p.clone() }))
                    .map(|w| w.date())
                    .collect::<Vec<_>>()
            })
            .collect();
        Some(Event {
            uid: c.text("UID").unwrap_or_default(),
            summary: c.text("SUMMARY").unwrap_or_default(),
            description: c.text("DESCRIPTION").unwrap_or_default(),
            location: c.text("LOCATION").unwrap_or_default(),
            start,
            end,
            repeat,
            except,
            other,
            children: c.children.clone(),
        })
    }

    pub fn to_component(&self, stamp: &str) -> Component {
        let mut c = Component::new("VEVENT");
        c.push(Prop::new("UID", &line::escape(&self.uid)));
        // §3.6.1: DTSTAMP is required; the event's own, else now.
        match self.other.iter().find(|p| p.name == "DTSTAMP") {
            Some(p) => c.push(p.clone()),
            None => c.push(Prop::new("DTSTAMP", stamp)),
        }
        c.push(self.start.to_prop("DTSTART"));
        c.push(self.end.to_prop("DTEND"));
        c.push(Prop::new("SUMMARY", &line::escape(&self.summary)));
        if !self.location.is_empty() {
            c.push(Prop::new("LOCATION", &line::escape(&self.location)));
        }
        if !self.description.is_empty() {
            c.push(Prop::new("DESCRIPTION", &line::escape(&self.description)));
        }
        if let Some(r) = &self.repeat {
            c.push(Prop::new("RRULE", &r.render()));
        }
        if !self.except.is_empty() {
            let v: Vec<String> = self.except.iter().map(Date::compact).collect();
            c.push(Prop::new("EXDATE", &v.join(",")).param("VALUE", "DATE"));
        }
        c.props.extend(self.other.iter().filter(|p| p.name != "DTSTAMP").cloned());
        c.children = self.children.clone();
        c
    }

    /// The days the event starts on between `from` and `to` (by its
    /// start's own date), repetitions included, exceptions left out.
    pub fn days(&self, from: Date, to: Date) -> Vec<Date> {
        let start = self.start.date();
        let all = match &self.repeat {
            None => alloc::vec![start],
            Some(r) => r.days_from(start, to, 10_000),
        };
        all.into_iter().filter(|d| *d >= from && *d <= to && !self.except.contains(d)).collect()
    }
}

fn add_seconds(w: &When, secs: i64) -> When {
    match w {
        When::Day(d) => When::Day(days_to_date(d.days() + secs.div_euclid(86_400))),
        When::At(d, t, z) => {
            let total = i64::from(*t) + secs;
            When::At(days_to_date(d.days() + total.div_euclid(86_400)), total.rem_euclid(86_400) as u32, z.clone())
        }
    }
}

/// A calendar: its name (X-WR-CALNAME, which most programs write), its
/// events, and what else it holds (time zone definitions, to-dos...).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Calendar {
    pub name: String,
    pub events: Vec<Event>,
    pub other: Vec<Component>,
    pub props: Vec<Prop>,
}

impl Calendar {
    /// Every VCALENDAR in `text`, merged into one.
    pub fn parse(text: &str) -> Calendar {
        let mut cal = Calendar::default();
        for top in line::parse(text).into_iter().filter(|c| c.name == "VCALENDAR") {
            if cal.name.is_empty() {
                cal.name = top.text("X-WR-CALNAME").unwrap_or_default();
            }
            for p in &top.props {
                if !matches!(p.name.as_str(), "VERSION" | "PRODID" | "X-WR-CALNAME") && !cal.props.contains(p) {
                    cal.props.push(p.clone());
                }
            }
            for c in top.children {
                match Event::from_component(&c).filter(|_| c.name == "VEVENT") {
                    Some(e) => cal.events.push(e),
                    None => cal.other.push(c),
                }
            }
        }
        cal
    }

    /// The calendar as a file; `stamp` is now in UTC (`20261024T120000Z`)
    /// for events without a DTSTAMP.
    pub fn render(&self, stamp: &str) -> String {
        let mut top = Component::new("VCALENDAR");
        top.push(Prop::new("VERSION", "2.0"));
        top.push(Prop::new("PRODID", "-//Slate//Calendar 1//EN"));
        if !self.name.is_empty() {
            top.push(Prop::new("X-WR-CALNAME", &line::escape(&self.name)));
        }
        top.props.extend(self.props.iter().cloned());
        top.children = self.other.clone();
        top.children.extend(self.events.iter().map(|e| e.to_component(stamp)));
        let mut out = String::new();
        line::write(&mut out, &top);
        out
    }

    /// Add `other`'s events, an event with a UID already here replacing
    /// it; how many were new and how many replaced.
    pub fn merge(&mut self, other: Calendar) -> (usize, usize) {
        let (mut new, mut replaced) = (0, 0);
        for e in other.events {
            match self.events.iter_mut().find(|x| !e.uid.is_empty() && x.uid == e.uid) {
                Some(x) => {
                    *x = e;
                    replaced += 1;
                }
                None => {
                    self.events.push(e);
                    new += 1;
                }
            }
        }
        for c in other.other {
            if !self.other.contains(&c) {
                self.other.push(c);
            }
        }
        (new, replaced)
    }
}

/// A new UID: a time, a counter and a host-free suffix (§3.8.4.7 asks
/// only that it be unique).
pub fn new_uid(now: i64, n: u32) -> String {
    alloc::format!("{now:x}-{n:x}@slate")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Example//EN\r\nX-WR-CALNAME:Work\r\nBEGIN:VTIMEZONE\r\nTZID:Europe/Paris\r\nEND:VTIMEZONE\r\nBEGIN:VEVENT\r\nUID:standup@example\r\nDTSTAMP:20261001T080000Z\r\nDTSTART;TZID=Europe/Paris:20261005T093000\r\nDURATION:PT15M\r\nRRULE:FREQ=WEEKLY;BYDAY=MO,WE,FR;COUNT=6\r\nEXDATE;TZID=Europe/Paris:20261007T093000\r\nSUMMARY:Stand-up\r\nX-UNKNOWN;P=1:kept\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT5M\r\nEND:VALARM\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:trip@example\r\nDTSTART;VALUE=DATE:20261030\r\nDTEND;VALUE=DATE:20261102\r\nSUMMARY:Trip to Lyon\\, by train\r\nEND:VEVENT\r\nBEGIN:VTODO\r\nUID:x\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";

    fn d(y: i32, m: u8, day: u8) -> Date {
        Date::new(y, m, day).unwrap()
    }

    #[test]
    fn reading_events() {
        let c = Calendar::parse(SAMPLE);
        assert_eq!(c.name, "Work");
        assert_eq!(c.events.len(), 2);
        assert_eq!(c.other.len(), 2, "the time zone and the to-do are kept");
        let s = &c.events[0];
        assert_eq!(s.start, When::At(d(2026, 10, 5), 9 * 3600 + 1800, Some("Europe/Paris".into())));
        assert_eq!(s.end, When::At(d(2026, 10, 5), 9 * 3600 + 45 * 60, Some("Europe/Paris".into())));
        // Mon 5, (Wed 7 left out), Fri 9, Mon 12, Wed 14, Fri 16: six by
        // count, the exception among them.
        assert_eq!(
            s.days(d(2026, 10, 1), d(2026, 10, 31)),
            [d(2026, 10, 5), d(2026, 10, 9), d(2026, 10, 12), d(2026, 10, 14), d(2026, 10, 16)]
        );
        assert_eq!(s.children.len(), 1, "the alarm is kept");
        let t = &c.events[1];
        assert_eq!((t.summary.as_str(), t.start.is_day()), ("Trip to Lyon, by train", true));
        assert_eq!(t.end, When::Day(d(2026, 11, 2)));
    }

    #[test]
    fn writing_keeps_everything() {
        let c = Calendar::parse(SAMPLE);
        let text = c.render("20261024T120000Z");
        let again = Calendar::parse(&text);
        // The same, but for the DTSTAMP §3.6.1 requires, added where it
        // was missing; writing again changes nothing more.
        assert_eq!(again.events[0], c.events[0]);
        assert_eq!(again.events[1].other, [Prop::new("DTSTAMP", "20261024T120000Z")]);
        assert_eq!((&again.other, &again.name), (&c.other, &c.name));
        assert_eq!(again.render("20991231T000000Z"), text);
        assert!(text.contains("X-UNKNOWN;P=1:kept") && text.contains("BEGIN:VALARM"));
        assert!(text.contains("SUMMARY:Trip to Lyon\\, by train"));
    }

    #[test]
    fn rules() {
        let monthly = Repeat::parse("FREQ=MONTHLY;UNTIL=20270501").unwrap();
        let days = monthly.days_from(d(2027, 1, 31), d(2027, 12, 31), 100);
        assert_eq!(days, [d(2027, 1, 31), d(2027, 3, 31)], "February and April have no 31st");
        let yearly = Repeat::parse("FREQ=YEARLY;INTERVAL=2;COUNT=3").unwrap();
        assert_eq!(
            yearly.days_from(d(2024, 2, 29), d(2040, 1, 1), 100),
            [d(2024, 2, 29), d(2028, 2, 29), d(2032, 2, 29)]
        );
        let daily = Repeat::parse("FREQ=DAILY;INTERVAL=3").unwrap();
        assert_eq!(daily.days_from(d(2026, 10, 30), d(2026, 11, 5), 100).len(), 3);
        assert_eq!(Repeat::parse("FREQ=MONTHLY;BYDAY=2MO"), None);
        assert_eq!(Repeat::parse("FREQ=HOURLY"), None);
        assert_eq!(
            Repeat::parse("FREQ=WEEKLY;BYDAY=TU,TH;INTERVAL=2").unwrap().render(),
            "FREQ=WEEKLY;INTERVAL=2;BYDAY=TU,TH"
        );
        assert_eq!(duration("P1W2DT3H4M5S"), Some(9 * 86_400 + 3 * 3600 + 4 * 60 + 5));
        assert_eq!(duration("-PT1H"), None);
    }

    #[test]
    fn merging() {
        let mut a = Calendar::parse(SAMPLE);
        let mut b = Calendar::parse(SAMPLE);
        b.events[1].summary = "Trip, moved".into();
        b.events.push(Event { uid: "new@x".into(), ..b.events[0].clone() });
        assert_eq!(a.merge(b), (1, 2));
        assert_eq!(a.events[1].summary, "Trip, moved");
        assert_eq!(a.events.len(), 3);
    }
}
