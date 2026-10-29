// SPDX-License-Identifier: MIT OR Apache-2.0

//! Time zones (ADRs 0039, 0141): POSIX TZ rules (IEEE Std 1003.1-2024,
//! Base Definitions §8.3, "TZ"), and zone names like `Europe/London`
//! looked up in `/usr/share/slate/zones`, a table of each zone's history
//! and current rule taken from tzdata (public domain; the format is in
//! `tools/xtask/src/zones.rs`, which makes it). A zone's history is the
//! local time types and transitions of RFC 8536 §3.2: times before its
//! last transition take the type in force then, later ones the rule.
//!
//! The zone is, in order: `TZ` (a rule, a zone name, or `:name`), the
//! zone named in `/etc/slate/timezone`, the rule at the end of
//! `/etc/localtime` (a TZif file, RFC 8536 §3.3, as other systems have),
//! and otherwise UTC.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use slate_sync::SpinLock;

use crate::time::{Tm, civil_to_days, gmtime, timegm};

/// The table of zone names and rules: lines `Area/City RULE`.
pub const ZONES: &[u8] = b"/usr/share/slate/zones";
/// The system's zone: a zone name on its first line.
pub const SETTING: &[u8] = b"/etc/slate/timezone";

/// A zone abbreviation ("UTC", "BST", "+0530"), kept inline so that
/// [`Tm`] stays `Copy`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Abbrev {
    len: u8,
    bytes: [u8; 15],
}

impl Abbrev {
    /// The first 15 bytes of `s`, cut at a character boundary.
    pub fn new(s: &str) -> Abbrev {
        let mut n = s.len().min(15);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        let mut bytes = [0; 15];
        bytes[..n].copy_from_slice(&s.as_bytes()[..n]);
        Abbrev { len: n as u8, bytes }
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("")
    }
}

impl Default for Abbrev {
    fn default() -> Abbrev {
        Abbrev::new("UTC")
    }
}

impl core::fmt::Debug for Abbrev {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.as_str())
    }
}

/// The day of a change of offset (§8.3's `date`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Day {
    /// `Jn`: 1 to 365, February 29 never counted.
    Julian(u32),
    /// `n`: 0 to 365, February 29 counted in leap years.
    Zero(u32),
    /// `Mm.w.d`: day `d` (0 = Sunday) of week `w` (5 = the last) of month `m`.
    Month { m: u32, w: u32, d: u32 },
}

impl Day {
    /// Days since the epoch of this day in `year`.
    fn in_year(self, year: i64) -> i64 {
        let jan1 = civil_to_days(year, 1, 1);
        match self {
            Day::Julian(n) => jan1 + i64::from(n) - 1 + i64::from(crate::time::is_leap(year) && n >= 60),
            Day::Zero(n) => jan1 + i64::from(n),
            Day::Month { m, w, d } => {
                let first = civil_to_days(year, m, 1);
                let next = if m == 12 { civil_to_days(year + 1, 1, 1) } else { civil_to_days(year, m + 1, 1) };
                let weekday = (first + 4).rem_euclid(7);
                let mut day = first + (i64::from(d) - weekday).rem_euclid(7) + 7 * (i64::from(w) - 1);
                while day >= next {
                    day -= 7;
                }
                day
            }
        }
    }
}

/// A change of offset: the day, and the local time of day (seconds; may
/// be negative or past 24 hours).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Change {
    day: Day,
    time: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Dst {
    name: Abbrev,
    /// Seconds east of UTC.
    offset: i32,
    start: Change,
    end: Change,
}

/// A zone's past (RFC 8536 §3.2): its local time types and the times it
/// changed from one to another.
#[derive(Debug, PartialEq, Eq)]
struct History {
    /// Seconds east of UTC, summer time, abbreviation; the first is in
    /// force before the first change.
    types: Vec<(i32, bool, Abbrev)>,
    /// When (seconds since the epoch, ascending) and to which type.
    changes: Vec<(i64, u8)>,
}

impl History {
    /// The table's form: `ABBR=OFFSET[d],...` and the changes, each a
    /// base-36 distance from the one before (from the epoch for the
    /// first, `-` before it if negative) and a type letter (`A` the first).
    fn parse(types: &str, changes: &str) -> Option<History> {
        let types = types
            .split(',')
            .map(|t| {
                let (abbr, off) = t.split_once('=')?;
                let (off, dst) = match off.strip_suffix('d') {
                    Some(o) => (o, true),
                    None => (off, false),
                };
                Some((off.parse().ok()?, dst, Abbrev::new(abbr)))
            })
            .collect::<Option<Vec<_>>>()?;
        let mut list: Vec<(i64, u8)> = Vec::new();
        let (mut neg, mut n, mut prev) = (false, 0i64, 0i64);
        for c in changes.bytes() {
            match c {
                b'-' if n == 0 && list.is_empty() => neg = true,
                b'0'..=b'9' | b'a'..=b'z' => {
                    let d = if c.is_ascii_digit() { c - b'0' } else { c - b'a' + 10 };
                    n = n.checked_mul(36)?.checked_add(i64::from(d))?;
                }
                b'A'..=b'Z' if usize::from(c - b'A') < types.len() => {
                    let at = prev.checked_add(if neg { -n } else { n })?;
                    if !list.is_empty() && at <= prev {
                        return None;
                    }
                    list.push((at, c - b'A'));
                    (prev, neg, n) = (at, false, 0);
                }
                _ => return None,
            }
        }
        (!types.is_empty() && !list.is_empty() && n == 0 && !neg).then_some(History { types, changes: list })
    }

    /// The type in force at `t`, if `t` is before the last change.
    fn at(&self, t: i64) -> Option<(i32, Abbrev, bool)> {
        if t >= self.changes.last()?.0 {
            return None;
        }
        let i = self.changes.partition_point(|&(c, _)| c <= t);
        let ty = if i == 0 { 0 } else { usize::from(self.changes[i - 1].1) };
        let (off, dst, name) = *self.types.get(ty)?;
        Some((off, name, dst))
    }
}

/// A zone: its history, if known, then its rule (a standard time and,
/// maybe, a summer time).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    name: Abbrev,
    /// Seconds east of UTC (TZ strings count west).
    offset: i32,
    dst: Option<Dst>,
    history: Option<Arc<History>>,
}

impl Default for Rule {
    fn default() -> Rule {
        Rule::UTC
    }
}

impl Rule {
    pub const UTC: Rule =
        Rule { name: Abbrev { len: 3, bytes: *b"UTC\0\0\0\0\0\0\0\0\0\0\0\0" }, offset: 0, dst: None, history: None };

    /// Parse a POSIX TZ rule: `std offset [dst [offset] [,start[/time],end[/time]]]`.
    pub fn parse(s: &str) -> Option<Rule> {
        let mut p = Cursor { s: s.as_bytes(), at: 0 };
        let name = p.name()?;
        let offset = -p.time(24)?;
        if p.done() {
            return Some(Rule { name, offset, dst: None, history: None });
        }
        let dst_name = p.name()?;
        let dst_offset = if matches!(p.peek(), Some(b'0'..=b'9' | b'+' | b'-')) { -p.time(24)? } else { offset + 3600 };
        // Without dates the rule is implementation-defined; like other
        // systems, take the United States' (second Sunday of March to the
        // first of November).
        let (start, end) = if p.done() {
            (
                Change { day: Day::Month { m: 3, w: 2, d: 0 }, time: 7200 },
                Change { day: Day::Month { m: 11, w: 1, d: 0 }, time: 7200 },
            )
        } else {
            p.eat(b',')?;
            let start = p.change()?;
            p.eat(b',')?;
            (start, p.change()?)
        };
        p.done().then_some(Rule {
            name,
            offset,
            dst: Some(Dst { name: dst_name, offset: dst_offset, start, end }),
            history: None,
        })
    }

    /// A zone from its line in the table, after the name: the rule, then
    /// maybe the history's types and changes.
    pub fn from_table(line: &str) -> Option<Rule> {
        let mut f = line.split_ascii_whitespace();
        let mut rule = Rule::parse(f.next()?)?;
        if let Some(types) = f.next() {
            rule.history = Some(Arc::new(History::parse(types, f.next().unwrap_or(""))?));
        }
        Some(rule)
    }

    /// The offset (seconds east), abbreviation and whether it is summer
    /// time at `t` (seconds since the epoch).
    pub fn at(&self, t: i64) -> (i32, Abbrev, bool) {
        if let Some(past) = self.history.as_ref().and_then(|h| h.at(t)) {
            return past;
        }
        let Some(d) = &self.dst else { return (self.offset, self.name, false) };
        let year = gmtime(t + i64::from(self.offset)).year;
        // The start is in standard time, the end in summer time.
        let start = d.start.day.in_year(year) * 86_400 + i64::from(d.start.time) - i64::from(self.offset);
        let end = d.end.day.in_year(year) * 86_400 + i64::from(d.end.time) - i64::from(d.offset);
        let summer = if start < end { start <= t && t < end } else { !(end <= t && t < start) };
        if summer { (d.offset, d.name, true) } else { (self.offset, self.name, false) }
    }

    /// `t` as a local time in this zone.
    pub fn localtime(&self, t: i64) -> Tm {
        let (offset, zone, _) = self.at(t);
        Tm { offset, zone, ..gmtime(t + i64::from(offset)) }
    }

    /// The seconds since the epoch of a local time in this zone (mktime).
    /// A time skipped or repeated by a change of offset gets one of the
    /// offsets either side.
    pub fn timelocal(&self, tm: &Tm) -> i64 {
        let local = timegm(tm);
        let first = local - i64::from(self.at(local - i64::from(self.offset)).0);
        local - i64::from(self.at(first).0)
    }

    /// The zone named `name`: a rule, a name in the table (`zones`, the
    /// table's text), or an absolute path to a TZif file. `:` before it
    /// is allowed.
    pub fn resolve(name: &str, zones: Option<&[u8]>) -> Option<Rule> {
        let name = name.trim();
        let name = name.strip_prefix(':').unwrap_or(name);
        if let Some(r) = Rule::parse(name) {
            return Some(r);
        }
        if let Some(line) = zones.and_then(|z| lookup(z, name)) {
            return Rule::from_table(&line);
        }
        if name.starts_with('/') {
            return tzif(&crate::fs::read_file(name.as_bytes()).ok()?);
        }
        None
    }

    /// The zone `name` names: a rule, a name in the table, an absolute
    /// path to a TZif file, or a name in the system's tz database (the
    /// host's).
    pub fn named(name: &str) -> Option<Rule> {
        let zones = crate::fs::read_file(ZONES).ok();
        Rule::resolve(name, zones.as_deref()).or_else(|| {
            let n = name.trim().trim_start_matches(':');
            let path = alloc::format!("/usr/share/zoneinfo/{n}");
            (!n.contains("..")).then(|| tzif(&crate::fs::read_file(path.as_bytes()).ok()?)).flatten()
        })
    }

    /// The local zone, as the module documentation says.
    pub fn local() -> Rule {
        let named = |name: &[u8]| Rule::named(&crate::lossy(name)).unwrap_or(Rule::UTC);
        if let Some(tz) = crate::env::var(b"TZ") {
            return named(&tz);
        }
        if let Ok(s) = crate::fs::read_file(SETTING) {
            let line = s.split(|&c| c == b'\n').next().unwrap_or(&[]);
            if !line.is_empty() {
                return named(line);
            }
        }
        crate::fs::read_file(b"/etc/localtime").ok().and_then(|d| tzif(&d)).unwrap_or(Rule::UTC)
    }
}

/// Zone `name`'s line in table `zones`, after the name.
pub fn lookup(zones: &[u8], name: &str) -> Option<String> {
    zones.split(|&c| c == b'\n').find_map(|line| {
        let line = core::str::from_utf8(line).ok()?;
        let (n, rule) = line.split_once(' ')?;
        (n == name && !line.starts_with('#')).then(|| String::from(rule.trim()))
    })
}

/// The zone names in table `zones`, in its order.
pub fn names(zones: &[u8]) -> Vec<String> {
    zones
        .split(|&c| c == b'\n')
        .filter(|l| !l.is_empty() && !l.starts_with(b"#"))
        .filter_map(|l| core::str::from_utf8(l).ok()?.split(' ').next().map(String::from))
        .collect()
}

fn be32(d: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_be_bytes(d.get(at..at + 4)?.try_into().ok()?) as usize)
}

/// The zone in a TZif file (RFC 8536): the version 2 data block's types
/// and transitions (§3.2; leap seconds are ignored), and the rule in the
/// footer (§3.3: version 2 and later end with it between newlines). A
/// file without transitions is just its rule.
fn tzif(data: &[u8]) -> Option<Rule> {
    if !data.starts_with(b"TZif") || !matches!(data.get(4), Some(b'2'..=b'9')) || !data.ends_with(b"\n") {
        return None;
    }
    let body = &data[..data.len() - 1];
    let nl = body.iter().rposition(|&c| c == b'\n')?;
    let mut rule = Rule::parse(core::str::from_utf8(&body[nl + 1..]).ok()?)?;
    // §3.1: six counts after "TZif", the version and 15 unused bytes;
    // the version 1 block (32-bit times) comes first and is skipped.
    let counts = |at: usize| -> Option<[usize; 6]> {
        (data.get(at..at + 4)? == b"TZif").then_some(())?;
        let mut c = [0; 6];
        for (i, n) in c.iter_mut().enumerate() {
            *n = be32(data, at + 20 + 4 * i)?;
        }
        Some(c)
    };
    let [isut, isstd, leap, time, typ, chars] = counts(0)?;
    let v2 = 44 + time * 5 + typ * 6 + chars + leap * 8 + isstd + isut;
    let [_, _, _, time, typ, chars] = counts(v2)?;
    if time == 0 || typ == 0 {
        return Some(rule);
    }
    let at = v2 + 44;
    let mut changes = Vec::with_capacity(time);
    for i in 0..time {
        let t = i64::from_be_bytes(data.get(at + 8 * i..at + 8 * i + 8)?.try_into().ok()?);
        let ty = *data.get(at + 8 * time + i)?;
        if usize::from(ty) >= typ || changes.last().is_some_and(|&(p, _)| p >= t) {
            return None;
        }
        changes.push((t, ty));
    }
    let tt = at + 9 * time;
    let abbrevs = data.get(tt + 6 * typ..tt + 6 * typ + chars)?;
    let mut types = Vec::with_capacity(typ);
    for i in 0..typ {
        let e = data.get(tt + 6 * i..tt + 6 * i + 6)?;
        let off = i32::from_be_bytes(e[..4].try_into().ok()?);
        let name = abbrevs.get(usize::from(e[5])..)?;
        let name = &name[..name.iter().position(|&c| c == 0)?];
        types.push((off, e[4] != 0, Abbrev::new(core::str::from_utf8(name).ok()?)));
    }
    rule.history = Some(Arc::new(History { types, changes }));
    Some(rule)
}

struct Cursor<'a> {
    s: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.at).copied()
    }

    fn done(&self) -> bool {
        self.at == self.s.len()
    }

    fn eat(&mut self, c: u8) -> Option<()> {
        (self.peek() == Some(c)).then(|| self.at += 1)
    }

    /// A zone abbreviation: three or more letters, or `<...>` of letters,
    /// digits, `+` and `-`.
    fn name(&mut self) -> Option<Abbrev> {
        let start = self.at;
        if self.eat(b'<').is_some() {
            while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || c == b'+' || c == b'-') {
                self.at += 1;
            }
            let name = &self.s[start + 1..self.at];
            self.eat(b'>')?;
            return (name.len() >= 3).then(|| Abbrev::new(core::str::from_utf8(name).unwrap_or("")));
        }
        while matches!(self.peek(), Some(c) if c.is_ascii_alphabetic()) {
            self.at += 1;
        }
        let name = &self.s[start..self.at];
        (name.len() >= 3).then(|| Abbrev::new(core::str::from_utf8(name).unwrap_or("")))
    }

    fn number(&mut self) -> Option<u32> {
        let start = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        if self.at == start || self.at - start > 3 {
            return None;
        }
        core::str::from_utf8(&self.s[start..self.at]).ok()?.parse().ok()
    }

    /// `[+|-]hh[:mm[:ss]]` in seconds, hours at most `max_hours`.
    fn time(&mut self, max_hours: u32) -> Option<i32> {
        let sign = match self.peek() {
            Some(b'-') => {
                self.at += 1;
                -1
            }
            Some(b'+') => {
                self.at += 1;
                1
            }
            _ => 1,
        };
        let h = self.number()?;
        let mut secs = h * 3600;
        if self.eat(b':').is_some() {
            secs += self.number().filter(|&m| m < 60)? * 60;
            if self.eat(b':').is_some() {
                secs += self.number().filter(|&s| s < 60)?;
            }
        }
        (h <= max_hours).then_some(sign * secs as i32)
    }

    /// `date[/time]`; the time is 02:00 when left out.
    fn change(&mut self) -> Option<Change> {
        let day = match self.peek()? {
            b'J' => {
                self.at += 1;
                Day::Julian(self.number().filter(|n| (1..=365).contains(n))?)
            }
            b'M' => {
                self.at += 1;
                let m = self.number().filter(|n| (1..=12).contains(n))?;
                self.eat(b'.')?;
                let w = self.number().filter(|n| (1..=5).contains(n))?;
                self.eat(b'.')?;
                let d = self.number().filter(|&n| n <= 6)?;
                Day::Month { m, w, d }
            }
            _ => Day::Zero(self.number().filter(|&n| n <= 365)?),
        };
        // POSIX.1-2024 allows -167 to 167 hours.
        let time = if self.eat(b'/').is_some() { self.time(167)? } else { 7200 };
        Some(Change { day, time })
    }
}

/// The process's zone, worked out once.
static LOCAL: SpinLock<Option<Rule>> = SpinLock::new(None);

fn local_rule() -> Rule {
    let mut l = LOCAL.lock();
    l.get_or_insert_with(Rule::local).clone()
}

/// `t` in the local zone.
pub fn localtime(t: i64) -> Tm {
    local_rule().localtime(t)
}

/// Whether `t` falls in the local zone's summer time.
pub fn is_summer(t: i64) -> bool {
    local_rule().at(t).2
}

/// `t` as an RFC 3339 local time with its offset, to the second:
/// `2026-10-22T14:03:01+02:00` (the logs' timestamps, ADR 0060).
pub fn stamp(t: i64) -> alloc::string::String {
    let tm = localtime(t);
    let off = tm.offset.unsigned_abs();
    alloc::format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{}{:02}:{:02}",
        tm.year,
        tm.month,
        tm.day,
        tm.hour,
        tm.min,
        tm.sec,
        if tm.offset < 0 { '-' } else { '+' },
        off / 3600,
        off / 60 % 60
    )
}

/// The seconds since the epoch of local time `tm`.
pub fn timelocal(tm: &Tm) -> i64 {
    local_rule().timelocal(tm)
}

/// Work the local zone out again (after `/etc/slate/timezone` changed).
pub fn reload() {
    *LOCAL.lock() = Some(Rule::local());
}

/// Use `tz` as `TZ` from now on (a shell's own assignment); None goes
/// back to the system's zone.
pub fn set_tz(tz: Option<&[u8]>) {
    let rule = match tz {
        Some(tz) => {
            let name = crate::lossy(tz);
            let zones = crate::fs::read_file(ZONES).ok();
            Rule::resolve(&name, zones.as_deref()).unwrap_or(Rule::UTC)
        }
        None => Rule::local(),
    };
    *LOCAL.lock() = Some(rule);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(rule: &str, y: i64, mo: u32, d: u32, h: u32, mi: u32) -> (i32, String, bool) {
        let r = Rule::parse(rule).unwrap();
        let t = civil_to_days(y, mo, d) * 86_400 + i64::from(h) * 3600 + i64::from(mi) * 60;
        let (o, n, s) = r.at(t);
        (o, String::from(n.as_str()), s)
    }

    #[test]
    fn parses() {
        assert_eq!(Rule::parse("UTC0"), Some(Rule::UTC));
        let r = Rule::parse("<+0530>-5:30").unwrap();
        assert_eq!((r.name.as_str(), r.offset, r.dst), ("+0530", 19_800, None));
        let r = Rule::parse("AEST-10AEDT,M10.1.0,M4.1.0/3").unwrap();
        let d = r.dst.unwrap();
        assert_eq!((r.offset, d.offset, d.end.time), (36_000, 39_600, 10_800));
        let r = Rule::parse("<-02>2<-01>,M3.5.0/-1,M10.5.0/0").unwrap();
        assert_eq!(r.dst.unwrap().start.time, -3600);
        assert_eq!(Rule::parse("<-04>4<-03>,M9.1.6/24,M4.1.6/24").unwrap().dst.unwrap().end.time, 86_400);
        assert_eq!(Rule::parse("EST5EDT,J60/2,300").unwrap().dst.unwrap().end.day, Day::Zero(300));
        for bad in ["", "UTC", "AB1", "EST5EDT,M3", "EST5EDT,M13.1.0,M1.1.0", "EST5x", "<+05", "EST99"] {
            assert_eq!(Rule::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn london() {
        // Summer time from 01:00 UTC on the last Sunday in March to 01:00
        // UTC on the last Sunday in October; in 2026 the 29th and the 25th.
        let r = "GMT0BST,M3.5.0/1,M10.5.0";
        assert_eq!(at(r, 2026, 1, 15, 12, 0), (0, "GMT".into(), false));
        assert_eq!(at(r, 2026, 3, 29, 0, 59), (0, "GMT".into(), false));
        assert_eq!(at(r, 2026, 3, 29, 1, 0), (3600, "BST".into(), true));
        assert_eq!(at(r, 2026, 10, 25, 0, 59), (3600, "BST".into(), true));
        assert_eq!(at(r, 2026, 10, 25, 1, 0), (0, "GMT".into(), false));
    }

    #[test]
    fn new_york_and_sydney() {
        // 2026: summer time from March 8 07:00 UTC to November 1 06:00 UTC.
        let r = "EST5EDT,M3.2.0,M11.1.0";
        assert_eq!(at(r, 2026, 3, 8, 6, 59).0, -18_000);
        assert_eq!(at(r, 2026, 3, 8, 7, 0).0, -14_400);
        assert_eq!(at(r, 2026, 11, 1, 5, 59).0, -14_400);
        assert_eq!(at(r, 2026, 11, 1, 6, 0).0, -18_000);
        // The southern hemisphere: summer across the new year. Ends April 5
        // 2026 at 03:00 AEDT (16:00 UTC the day before), starts October 4
        // at 02:00 AEST (16:00 UTC the day before).
        let r = "AEST-10AEDT,M10.1.0,M4.1.0/3";
        assert_eq!(at(r, 2026, 1, 1, 0, 0).0, 39_600);
        assert_eq!(at(r, 2026, 4, 4, 15, 59).0, 39_600);
        assert_eq!(at(r, 2026, 4, 4, 16, 0).0, 36_000);
        assert_eq!(at(r, 2026, 10, 3, 15, 59).0, 36_000);
        assert_eq!(at(r, 2026, 10, 3, 16, 0).0, 39_600);
        // A half-hour summer time (Lord Howe Island).
        assert_eq!(at("<+1030>-10:30<+11>-11,M10.1.0,M4.1.0", 2026, 1, 1, 0, 0), (39_600, "+11".into(), true));
    }

    #[test]
    fn local_and_back() {
        let r = Rule::parse("GMT0BST,M3.5.0/1,M10.5.0").unwrap();
        // 2026-07-01 12:00 UTC is 13:00 BST.
        let t = civil_to_days(2026, 7, 1) * 86_400 + 12 * 3600;
        let tm = r.localtime(t);
        assert_eq!((tm.hour, tm.offset, tm.zone.as_str()), (13, 3600, "BST"));
        assert_eq!(r.timelocal(&tm), t);
        let mut s = String::new();
        crate::time::format(&tm, "%H:%M %Z %z %s", &mut s);
        assert_eq!(s, alloc::format!("13:00 BST +0100 {t}"));
        let r = Rule::parse("<-0930>9:30").unwrap();
        let mut s = String::new();
        crate::time::format(&r.localtime(0), "%z %Z", &mut s);
        assert_eq!(s, "-0930 -0930");
    }

    #[test]
    fn table() {
        let zones = b"# comment\nEurope/London GMT0BST,M3.5.0/1,M10.5.0\nUTC UTC0\n";
        assert_eq!(names(zones), ["Europe/London", "UTC"]);
        assert_eq!(lookup(zones, "UTC").as_deref(), Some("UTC0"));
        assert_eq!(Rule::resolve(":UTC", Some(zones)), Some(Rule::UTC));
        assert_eq!(Rule::resolve("Europe/London", Some(zones)).unwrap().name.as_str(), "GMT");
        assert_eq!(Rule::resolve("Mars/Olympus", Some(zones)), None);
        assert_eq!(tzif(&tzif_file(&[], &[], "IST-5:30")).unwrap().offset, 19_800);
        assert_eq!(tzif(b"TZif\0junk\nIST-5:30\n"), None);
    }

    /// A TZif version 2 file (RFC 8536 §3) with an empty version 1 block.
    fn tzif_file(types: &[(i32, bool, &str)], changes: &[(i64, u8)], rule: &str) -> Vec<u8> {
        let header = |time: usize, typ: usize, chars: usize| {
            let mut h = b"TZif2".to_vec();
            h.extend_from_slice(&[0; 15]);
            for n in [0, 0, 0, time, typ, chars] {
                h.extend_from_slice(&(n as u32).to_be_bytes());
            }
            h
        };
        // Version 1: one type, one byte of names.
        let mut f = header(0, 1, 1);
        f.extend_from_slice(&[0; 7]);
        let mut chars = Vec::new();
        let mut entries = Vec::new();
        for &(off, dst, name) in types {
            entries.extend_from_slice(&off.to_be_bytes());
            entries.extend_from_slice(&[u8::from(dst), chars.len() as u8]);
            chars.extend_from_slice(name.as_bytes());
            chars.push(0);
        }
        f.extend(header(changes.len(), types.len(), chars.len()));
        for &(t, _) in changes {
            f.extend_from_slice(&t.to_be_bytes());
        }
        f.extend(changes.iter().map(|&(_, ty)| ty));
        f.extend(entries);
        f.extend(chars);
        f.extend_from_slice(alloc::format!("\n{rule}\n").as_bytes());
        f
    }

    #[test]
    fn history() {
        // Before the first change the first type; between changes the one
        // changed to; from the last change on, the rule.
        let line = "GMT0BST,M3.5.0/1,M10.5.0 LMT=-75,GMT=0,BST=3600d,BDST=7200d -100B64C1aD";
        let r = Rule::from_table(line).unwrap();
        let h = r.history.as_ref().unwrap();
        assert_eq!(h.changes, [(-1296, 1), (-1296 + 220, 2), (-1296 + 220 + 46, 3)]);
        let name = |t| String::from(r.at(t).1.as_str());
        assert_eq!((r.at(-1297).0, name(-1297)), (-75, "LMT".into()));
        assert_eq!((r.at(-1296).0, name(-1296)), (0, "GMT".into()));
        assert_eq!(r.at(-1077).1.as_str(), "GMT");
        assert_eq!(r.at(-1076), (3600, Abbrev::new("BST"), true));
        assert_eq!(r.at(-1031).0, 3600);
        // From the last change on, the rule: December, so GMT.
        assert_eq!(r.at(-1030), (0, Abbrev::new("GMT"), false));
        for bad in ["UTC0 X=1", "UTC0 A=0 1B", "UTC0 A=0 -1A1A0A", "UTC0 A=0 1", "UTC0 A=x 1A"] {
            assert_eq!(Rule::from_table(bad), None, "{bad}");
        }
        // The same from a TZif file.
        let f = tzif_file(
            &[(-75, false, "LMT"), (0, false, "GMT"), (3600, true, "BST"), (7200, true, "BDST")],
            &[(-1296, 1), (-1076, 2), (-1030, 3)],
            "GMT0BST,M3.5.0/1,M10.5.0",
        );
        assert_eq!(tzif(&f), Some(r));
    }

    #[test]
    fn london_1970() {
        // From 1968 to 1971 Britain kept summer time all year as "BST"
        // (British Standard Time); today's rule would say GMT in January.
        let zones = include_bytes!("../../../rootfs/usr/share/slate/zones");
        let r = Rule::resolve("Europe/London", Some(zones)).unwrap();
        let jan70 = civil_to_days(1970, 1, 15) * 86_400;
        assert_eq!((r.at(jan70).0, r.at(jan70).1.as_str()), (3600, "BST"));
        let tm = r.localtime(jan70);
        assert_eq!((tm.hour, r.timelocal(&tm)), (1, jan70));
        // India's 1942-45 war time, and Kolkata's local mean time.
        let r = Rule::resolve("Asia/Kolkata", Some(zones)).unwrap();
        assert_eq!(r.at(civil_to_days(1943, 6, 1) * 86_400).0, 23_400);
        assert_eq!(r.at(civil_to_days(1850, 6, 1) * 86_400).0, 21_208);
    }

    #[test]
    fn shipped_history() {
        // Each zone of the table agrees with the host's TZif file (when the
        // host has the same tzdata) at and either side of every transition
        // through 2037, the last the TZif files list: so the table's
        // history is right and its rules take over where its list stops.
        let zones = include_bytes!("../../../rootfs/usr/share/slate/zones");
        let text = core::str::from_utf8(zones).unwrap();
        let version = text.split("From tzdata ").nth(1).and_then(|s| s.split(' ').next()).unwrap();
        let Ok(host) = std::fs::read_to_string("/usr/share/zoneinfo/tzdata.zi") else { return };
        if host.lines().next() != Some(&*alloc::format!("# version {version}")) {
            std::eprintln!("shipped_history: the host's tzdata is not {version}; skipped");
            return;
        }
        for n in names(zones) {
            let ours = Rule::resolve(&n, Some(zones)).unwrap();
            let theirs = tzif(&std::fs::read(alloc::format!("/usr/share/zoneinfo/{n}")).unwrap()).unwrap();
            let Some(h) = &theirs.history else {
                assert_eq!(ours.at(0), theirs.at(0), "{n}");
                continue;
            };
            for &(t, _) in &h.changes {
                for t in [t - 1, t, t + 1] {
                    assert_eq!(ours.at(t), theirs.at(t), "{n} at {t}");
                }
            }
        }
    }

    #[test]
    fn shipped_table() {
        // Every rule in the image's table parses, and a local time goes
        // back to the same instant away from changes of offset.
        let zones = include_bytes!("../../../rootfs/usr/share/slate/zones");
        let names = names(zones);
        assert!(names.len() > 300 && names.iter().any(|n| n == "UTC"));
        for n in &names {
            let line = lookup(zones, n).unwrap();
            let r = Rule::from_table(&line).unwrap_or_else(|| panic!("{n}: {line}"));
            for (y, m) in [(1890, 1), (1944, 7), (1970, 1), (1999, 7), (2027, 1), (2050, 7)] {
                let noon = civil_to_days(y, m, 20) * 86_400 + 12 * 3600;
                assert_eq!(r.timelocal(&r.localtime(noon)), noon, "{n} {y}");
            }
        }
    }
}
