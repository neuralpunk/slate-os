// SPDX-License-Identifier: MIT OR Apache-2.0

//! Dates as `date -d`, `touch -d` and friends read them, and date(1)'s
//! output formats. The input language follows the "Date input formats"
//! chapter of the GNU coreutils manual: calendar dates (ISO 8601, `m/d/y`,
//! `22 Oct 2026`, `Oct 22, 2026`), times of day (with `am`/`pm`, seconds,
//! fractions and a zone correction), time zones (UTC, the US zones the
//! manual lists, military letters, `+hh:mm`), days of the week (with
//! `next`/`last`/ordinals), relative items (`3 days ago`, `next month`,
//! `-2 hours`, `tomorrow`), pure numbers and `@SECONDS`. Anything else is
//! an error, never a guess.

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::time::{self, Tm};

/// A moment: seconds since the epoch and nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instant {
    pub secs: i64,
    pub nsec: u32,
}

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Num(i64, usize, i32),
    Word(String),
    Sym(char),
    /// `+N` or `-N` (a signed number written with its sign).
    Signed(i64, usize),
    /// Fraction of a second, in nanoseconds.
    Frac(u32),
}

fn lex(s: &str) -> Option<Vec<Tok>> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() || c == b',' {
            i += 1;
            continue;
        }
        if c == b'(' {
            // A comment, as the manual allows.
            let mut depth = 0;
            while i < b.len() {
                if b[i] == b'(' {
                    depth += 1;
                } else if b[i] == b')' {
                    depth -= 1;
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                i += 1;
            }
            continue;
        }
        if c.is_ascii_digit() || ((c == b'+' || c == b'-') && b.get(i + 1).is_some_and(u8::is_ascii_digit)) {
            let signed = !c.is_ascii_digit();
            let start = if signed { i + 1 } else { i };
            let mut j = start;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            let digits = &s[start..j];
            let n: i64 = digits.parse().ok()?;
            if signed {
                // A sign right after a time is a zone correction; the
                // parser decides. Keep the sign.
                out.push(Tok::Signed(if c == b'-' { -n } else { n }, digits.len()));
            } else {
                out.push(Tok::Num(n, digits.len(), 0));
            }
            i = j;
            if i < b.len() && (b[i] == b'.' || b[i] == b',') && b.get(i + 1).is_some_and(u8::is_ascii_digit) {
                // Fractional seconds (only meaningful after hh:mm:ss or @).
                let mut k = i + 1;
                let mut ns: u64 = 0;
                let mut places = 0;
                while k < b.len() && b[k].is_ascii_digit() {
                    if places < 9 {
                        ns = ns * 10 + u64::from(b[k] - b'0');
                        places += 1;
                    }
                    k += 1;
                }
                while places < 9 {
                    ns *= 10;
                    places += 1;
                }
                out.push(Tok::Frac(ns as u32));
                i = k;
            }
            continue;
        }
        if c.is_ascii_alphabetic() {
            let mut j = i;
            while j < b.len() && (b[j].is_ascii_alphabetic() || b[j] == b'.') {
                j += 1;
            }
            out.push(Tok::Word(s[i..j].trim_end_matches('.').to_ascii_lowercase()));
            i = j;
            continue;
        }
        if matches!(c, b':' | b'/' | b'-' | b'+' | b'@' | b'T') {
            out.push(Tok::Sym(c as char));
            i += 1;
            continue;
        }
        return None;
    }
    Some(out)
}

fn month(w: &str) -> Option<u32> {
    let names = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    let full = time::FULL_MONTHS;
    for (i, n) in names.iter().enumerate() {
        if w == *n || w == full[i].to_ascii_lowercase() || (i == 8 && w == "sept") {
            return Some(i as u32 + 1);
        }
    }
    None
}

fn weekday(w: &str) -> Option<u32> {
    let names = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
    for (i, n) in names.iter().enumerate() {
        let full = time::FULL_DAYS[i].to_ascii_lowercase();
        if w == *n
            || w == full
            || (i == 2 && w == "tues")
            || (i == 3 && w == "wednes")
            || (i == 4 && (w == "thur" || w == "thurs"))
        {
            return Some(i as u32);
        }
    }
    None
}

/// Seconds east of UTC for a zone name the manual lists.
fn zone(w: &str) -> Option<i32> {
    let h = |n: i32| Some(n * 3600);
    match w {
        "utc" | "gmt" | "ut" | "z" | "zulu" => h(0),
        "edt" => h(-4),
        "est" | "cdt" => h(-5),
        "cst" | "mdt" => h(-6),
        "mst" | "pdt" => h(-7),
        "pst" => h(-8),
        "akst" => h(-9),
        "akdt" => h(-8),
        "hst" => h(-10),
        "wet" => h(0),
        "west" | "cet" | "bst" => h(1),
        "cest" | "eet" => h(2),
        "eest" | "msk" => h(3),
        "ist" => Some(19800),
        "jst" | "kst" => h(9),
        "aest" => h(10),
        "aedt" => h(11),
        "nzst" => h(12),
        "nzdt" => h(13),
        _ if w.len() == 1 && w != "j" => {
            // Military zones: A-I = +1..+9, K-M = +10..+12, N-Y = -1..-12.
            let c = w.as_bytes()[0];
            match c {
                b'a'..=b'i' => h(i32::from(c - b'a') + 1),
                b'k'..=b'm' => h(i32::from(c - b'k') + 10),
                b'n'..=b'y' => h(-(i32::from(c - b'n') + 1)),
                _ => None,
            }
        }
        _ => None,
    }
}

fn ordinal(w: &str) -> Option<i64> {
    Some(match w {
        "last" => -1,
        "this" => 0,
        "next" | "first" => 1,
        "third" => 3,
        "fourth" => 4,
        "fifth" => 5,
        "sixth" => 6,
        "seventh" => 7,
        "eighth" => 8,
        "ninth" => 9,
        "tenth" => 10,
        "eleventh" => 11,
        "twelfth" => 12,
        _ => return None,
    })
}

/// The unit of a relative item: which of years, months, days, hours,
/// minutes and seconds it counts, and how many of them it is.
fn unit(w: &str) -> Option<(usize, i64)> {
    let w = w.strip_suffix('s').filter(|r| !r.is_empty() && *r != "mon").unwrap_or(w);
    Some(match w {
        "year" => (0, 1),
        "month" => (1, 1),
        "fortnight" => (2, 14),
        "week" => (2, 7),
        "day" => (2, 1),
        "hour" => (3, 1),
        "minute" | "min" => (4, 1),
        "second" | "sec" => (5, 1),
        _ => return None,
    })
}

#[derive(Default, Debug, Clone, PartialEq)]
struct Parsed {
    date: Option<(i64, u32, u32)>,
    time: Option<(u32, u32, u32, u32)>,
    zone: Option<i32>,
    weekday: Option<(i64, u32)>,
    /// `this` was said before the day of the week.
    this_said: bool,
    /// Relative years, months, days, hours, minutes and seconds.
    rel: [i64; 6],
    /// The last relative item, for `ago`.
    last_rel: [i64; 6],
    epoch: Option<Instant>,
}

/// The zone a date is read in.
enum InZone {
    Utc,
    Local,
    Rule(slate_rt::tz::Rule),
}

impl InZone {
    fn tm(&self, t: i64) -> Tm {
        match self {
            InZone::Utc => time::gmtime(t),
            InZone::Local => slate_rt::tz::localtime(t),
            InZone::Rule(r) => r.localtime(t),
        }
    }

    fn time_of(&self, tm: &Tm) -> i64 {
        match self {
            InZone::Utc => time::timegm(tm),
            InZone::Local => slate_rt::tz::timelocal(tm),
            InZone::Rule(r) => r.timelocal(tm),
        }
    }
}

/// Parse `s` relative to `now`; `utc` reads times as UTC rather than local.
pub fn parse(s: &str, now: Instant, utc: bool) -> Option<Instant> {
    parse_traced(s, now, utc).0
}

/// What `date --debug` says about a parse: how the input's zone was
/// chosen, for the output's lines too.
#[derive(Debug)]
pub struct Traced {
    /// GNU's lines, each without the program's name.
    pub lines: Vec<String>,
    /// The zone named by `TZ="..."` at the start of the string.
    pub zone_in_string: Option<(String, slate_rt::tz::Rule)>,
}

/// [`parse`], and the steps `date --debug` shows (as GNU's date was seen
/// to print them). A string may start with `TZ="ZONE"`: it is then read
/// in that zone.
pub fn parse_traced(s: &str, now: Instant, utc: bool) -> (Option<Instant>, Traced) {
    let mut traced = Traced { lines: Vec::new(), zone_in_string: None };
    let mut rest = s.trim_start();
    let mut zone = if utc { InZone::Utc } else { InZone::Local };
    let mut desc = if utc {
        String::from("TZ=\"UTC0\" environment value or -u")
    } else {
        match slate_rt::env::var(b"TZ") {
            Some(tz) => alloc::format!("TZ=\"{}\" environment value", slate_rt::lossy(&tz)),
            None => String::from("system default"),
        }
    };
    if let Some(r) = rest.strip_prefix("TZ=\"")
        && let Some(end) = r.find('"')
    {
        let name = &r[..end];
        // A zone unknown here is UTC, as TZ's is.
        let rule = slate_rt::tz::Rule::named(name).unwrap_or(slate_rt::tz::Rule::UTC);
        desc = alloc::format!("TZ=\"{name}\" in date string");
        traced.zone_in_string = Some((String::from(name), rule.clone()));
        zone = InZone::Rule(rule);
        rest = &r[end + 1..];
    }
    let r = parse_in(rest, now, &zone, &desc, &mut traced.lines);
    (r, traced)
}

fn parse_in(s: &str, now: Instant, inzone: &InZone, desc: &str, trace: &mut Vec<String>) -> Option<Instant> {
    let toks = lex(s)?;
    let mut p = Parsed::default();
    let mut i = 0;
    let get = |i: usize| toks.get(i);
    let this_year = inzone.tm(now.secs).year;
    while i < toks.len() {
        let before = p.clone();
        'item: {
            match &toks[i] {
                Tok::Sym('@') => {
                    let (secs, neg) = match get(i + 1)? {
                        Tok::Num(n, _, _) => (*n, false),
                        Tok::Signed(n, _) => (n.abs(), *n < 0),
                        _ => return None,
                    };
                    let nsec = match get(i + 2) {
                        Some(Tok::Frac(f)) => {
                            i += 1;
                            *f
                        }
                        _ => 0,
                    };
                    p.epoch = Some(if neg && nsec > 0 {
                        Instant { secs: -secs - 1, nsec: 1_000_000_000 - nsec }
                    } else {
                        Instant { secs: if neg { -secs } else { secs }, nsec }
                    });
                    i += 2;
                }
                Tok::Num(n, len, _) => {
                    let n = *n;
                    let len = *len;
                    // ISO 8601 date: YYYY-MM-DD.
                    if let (Some(Tok::Signed(m, 2 | 1)), Some(Tok::Signed(d, 2 | 1))) = (get(i + 1), get(i + 2))
                        && *m < 0
                        && *d < 0
                    {
                        p.date = Some((n, (-m) as u32, (-d) as u32));
                        i += 3;
                        if let Some(Tok::Word(w)) = get(i)
                            && w.starts_with('t')
                            && w.len() == 1
                        {
                            i += 1;
                        }
                        break 'item;
                    }
                    // m/d[/y], or y/m/d with a four-digit year.
                    if let (Some(Tok::Sym('/')), Some(Tok::Num(d, _, _))) = (get(i + 1), get(i + 2)) {
                        let d = *d;
                        i += 3;
                        let third = match (get(i), get(i + 1)) {
                            (Some(Tok::Sym('/')), Some(Tok::Num(z, zl, _))) => {
                                i += 2;
                                Some((*z, *zl))
                            }
                            _ => None,
                        };
                        p.date = Some(match third {
                            Some((z, _)) if len >= 4 => (n, d as u32, z as u32),
                            Some((z, zl)) => (year(z, zl), n as u32, d as u32),
                            None => (i64::MIN, n as u32, d as u32),
                        });
                        break 'item;
                    }
                    // hh:mm[:ss[.frac]] [am|pm] [zone correction]
                    if let (Some(Tok::Sym(':')), Some(Tok::Num(mm, _, _))) = (get(i + 1), get(i + 2)) {
                        let (mut h, m) = (n as u32, *mm as u32);
                        let (mut sec, mut ns) = (0u32, 0u32);
                        i += 3;
                        if let (Some(Tok::Sym(':')), Some(Tok::Num(ss, _, _))) = (get(i), get(i + 1)) {
                            sec = *ss as u32;
                            i += 2;
                            if let Some(Tok::Frac(f)) = get(i) {
                                ns = *f;
                                i += 1;
                            }
                        }
                        if let Some(Tok::Word(w)) = get(i)
                            && let Some(nh) = meridian(w, h)
                        {
                            h = nh?;
                            i += 1;
                        }
                        // A signed number straight after the time is a zone.
                        if let Some(Tok::Signed(z, zl)) = get(i) {
                            let (mut zh, mut zm) = if *zl <= 2 { (z.abs(), 0) } else { (z.abs() / 100, z.abs() % 100) };
                            i += 1;
                            if let (Some(Tok::Sym(':')), Some(Tok::Num(m2, _, _))) = (get(i), get(i + 1))
                                && *zl <= 2
                            {
                                zm = *m2;
                                i += 2;
                            }
                            if zh > 24 || zm > 59 {
                                return None;
                            }
                            zh = zh * 3600 + zm * 60;
                            p.zone = Some(if *z < 0 { -(zh as i32) } else { zh as i32 });
                        }
                        if p.time.is_some() {
                            return None;
                        }
                        p.time = Some((h, m, sec, ns));
                        break 'item;
                    }
                    // N am/pm
                    if let Some(Tok::Word(w)) = get(i + 1)
                        && let Some(h) = meridian(w, n as u32)
                    {
                        p.time = Some((h?, 0, 0, 0));
                        i += 2;
                        break 'item;
                    }
                    // N unit [ago], N weekday
                    if let Some(Tok::Word(w)) = get(i + 1) {
                        if let Some(u) = unit(w) {
                            add_rel(&mut p, n, u);
                            i += 2;
                            ago_after(&toks, &mut i, &mut p);
                            break 'item;
                        }
                        if let Some(wd) = weekday(w) {
                            p.weekday = Some((n, wd));
                            i += 2;
                            break 'item;
                        }
                        // 22 Oct [2026]
                        if let Some(m) = month(w) {
                            i += 2;
                            let mut y = i64::MIN;
                            if let Some(Tok::Num(yy, yl, _)) = get(i)
                                && !matches!(get(i + 1), Some(Tok::Sym(':')))
                            {
                                y = year(*yy, *yl);
                                i += 1;
                            } else if let Some(Tok::Signed(yy, yl)) = get(i) {
                                // 22-Oct-2026
                                y = year(yy.abs(), *yl);
                                i += 1;
                            }
                            p.date = Some((y, m, n as u32));
                            break 'item;
                        }
                    }
                    // 22-Oct-2026
                    if let (Some(Tok::Sym('-')), Some(Tok::Word(w))) = (get(i + 1), get(i + 2))
                        && let Some(m) = month(w)
                    {
                        i += 3;
                        let mut y = i64::MIN;
                        if let Some(Tok::Signed(yy, yl)) = get(i) {
                            y = year(yy.abs(), *yl);
                            i += 1;
                        }
                        p.date = Some((y, m, n as u32));
                        break 'item;
                    }
                    // Pure numbers, as the manual reads them: yyyymmdd when no
                    // date came before, hhmm when no time did, else the year
                    // when both did and no relative item.
                    i += 1;
                    let rel = p.rel != [0; 6];
                    if len > 4 && p.date.is_none() {
                        p.date = Some((n / 10_000, (n / 100 % 100) as u32, (n % 100) as u32));
                    } else if len <= 4 && p.time.is_none() {
                        let (h, m) = if len <= 2 { (n, 0) } else { (n / 100, n % 100) };
                        p.time = Some((h as u32, m as u32, 0, 0));
                    } else if p.date.is_some() && p.time.is_some() && !rel {
                        let d = p.date.as_mut()?;
                        d.0 = year(n, len);
                    } else {
                        return None;
                    }
                }
                Tok::Signed(n, _) => {
                    let n = *n;
                    if let Some(Tok::Word(w)) = get(i + 1)
                        && let Some(u) = unit(w)
                    {
                        add_rel(&mut p, n, u);
                        i += 2;
                        ago_after(&toks, &mut i, &mut p);
                        break 'item;
                    }
                    // A zone correction on its own (`+0200`, `-05:00`).
                    p.zone = Some(((n.abs() / 100 * 3600 + n.abs() % 100 * 60) * n.signum()) as i32);
                    i += 1;
                }
                Tok::Word(w) => {
                    let w = w.clone();
                    i += 1;
                    match w.as_str() {
                        "now" => {}
                        "today" => {}
                        "tomorrow" => add_rel(&mut p, 1, (2, 1)),
                        "yesterday" => add_rel(&mut p, -1, (2, 1)),
                        "ago" => {
                            // Turns the item before it around.
                            ago(&mut p);
                        }
                        "t" => {}
                        _ => {
                            if let Some(o) = ordinal(&w) {
                                match get(i) {
                                    Some(Tok::Word(next)) if unit(next).is_some() => {
                                        add_rel(&mut p, o, unit(next)?);
                                        i += 1;
                                        ago_after(&toks, &mut i, &mut p);
                                    }
                                    Some(Tok::Word(next)) if weekday(next).is_some() => {
                                        p.weekday = Some((o, weekday(next)?));
                                        p.this_said = w == "this";
                                        i += 1;
                                    }
                                    _ => return None,
                                }
                            } else if let Some(m) = month(&w) {
                                // Oct 22[, 2026]
                                let Some(Tok::Num(d, _, _)) = get(i) else {
                                    p.date = Some((i64::MIN, m, 1));
                                    break 'item;
                                };
                                let d = *d as u32;
                                i += 1;
                                let mut y = i64::MIN;
                                if let Some(Tok::Num(yy, yl, _)) = get(i)
                                    && !matches!(get(i + 1), Some(Tok::Sym(':')))
                                {
                                    y = year(*yy, *yl);
                                    i += 1;
                                } else if let Some(Tok::Signed(yy, yl)) = get(i) {
                                    y = year(yy.abs(), *yl);
                                    i += 1;
                                }
                                p.date = Some((y, m, d));
                            } else if let Some(wd) = weekday(&w) {
                                if p.weekday.is_none() {
                                    p.weekday = Some((0, wd));
                                }
                            } else if let Some(u) = unit(&w) {
                                add_rel(&mut p, 1, u);
                                ago_after(&toks, &mut i, &mut p);
                            } else {
                                // A zone, as in `UTC+3` or `CET DST`.
                                let mut z = zone(&w)?;
                                if let Some(Tok::Signed(off, ol)) = get(i) {
                                    let off = *off;
                                    let secs = if *ol <= 2 {
                                        off.abs() * 3600
                                    } else {
                                        off.abs() / 100 * 3600 + off.abs() % 100 * 60
                                    };
                                    z += (secs * off.signum()) as i32;
                                    i += 1;
                                }
                                p.zone = Some(z);
                                if let Some(Tok::Word(dst)) = get(i)
                                    && dst == "dst"
                                {
                                    p.zone = Some(z + 3600);
                                    i += 1;
                                }
                            }
                        }
                    }
                }
                Tok::Sym('T') => i += 1,
                _ => return None,
            }
        }
        say_item(&before, &p, this_year, trace);
    }
    resolve(&p, now, inzone, desc, trace)
}

fn year(y: i64, len: usize) -> i64 {
    if len <= 2 { if y < 69 { 2000 + y } else { 1900 + y } } else { y }
}

/// `am`/`pm` after an hour: Some(Some(24-hour)) when it is one, Some(None)
/// for a bad hour.
fn meridian(w: &str, h: u32) -> Option<Option<u32>> {
    let pm = match w {
        "am" | "a.m" => false,
        "pm" | "p.m" => true,
        _ => return None,
    };
    if !(1..=12).contains(&h) {
        return Some(None);
    }
    Some(Some(match (h, pm) {
        (12, false) => 0,
        (12, true) => 12,
        (h, true) => h + 12,
        (h, false) => h,
    }))
}

fn add_rel(p: &mut Parsed, n: i64, (index, times): (usize, i64)) {
    let mut item = [0; 6];
    item[index] = n * times;
    for (r, d) in p.rel.iter_mut().zip(item) {
        *r += d;
    }
    p.last_rel = item;
}

/// `ago`: the relative item before it, turned around.
fn ago(p: &mut Parsed) {
    for (r, l) in p.rel.iter_mut().zip(p.last_rel.iter_mut()) {
        *r -= 2 * *l;
        *l = -*l;
    }
}

/// An `ago` straight after a relative item is part of it.
fn ago_after(toks: &[Tok], i: &mut usize, p: &mut Parsed) {
    if matches!(toks.get(*i), Some(Tok::Word(w)) if w == "ago") {
        ago(p);
        *i += 1;
    }
}

fn days_in(y: i64, m: u32) -> u32 {
    match m {
        2 if time::is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// `(Y-M-D) 2026-10-01`, as `date --debug` writes dates.
fn ymd(y: i64, m: u32, d: u32) -> String {
    alloc::format!("(Y-M-D) {y:04}-{m:02}-{d:02}")
}

/// `+02`, `-05`, `+05:30`: an offset east of UTC.
pub fn offset_text(z: i32) -> String {
    let a = z.unsigned_abs();
    let sign = if z < 0 { '-' } else { '+' };
    if a % 3600 == 0 {
        alloc::format!("{sign}{:02}", a / 3600)
    } else {
        alloc::format!("{sign}{:02}:{:02}", a / 3600, a / 60 % 60)
    }
}

/// The relative items so far, as `date --debug` lists them.
fn rel_text(rel: &[i64; 6]) -> String {
    let names = ["year(s)", "month(s)", "day(s)", "hour(s)", "minutes", "seconds"];
    let parts: Vec<String> =
        rel.iter().zip(names).filter(|(n, _)| **n != 0).map(|(n, name)| alloc::format!("{n:+} {name}")).collect();
    parts.join(" ")
}

/// A day of the week with its ordinal, as `date --debug` names it.
fn day_text(n: i64, wd: u32, this_said: bool) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const ORD: [&str; 14] = [
        "last",
        "this",
        "next/first",
        "(SECOND)",
        "third",
        "fourth",
        "fifth",
        "sixth",
        "seventh",
        "eighth",
        "ninth",
        "tenth",
        "eleventh",
        "twelfth",
    ];
    let day = DAYS[wd as usize % 7];
    match n {
        0 if !this_said => String::from(day),
        -1..=12 => alloc::format!("{} {day}", ORD[(n + 1) as usize]),
        n => alloc::format!("{n} {day}"),
    }
}

/// What the last item added, as `date --debug` says it.
fn say_item(before: &Parsed, p: &Parsed, this_year: i64, trace: &mut Vec<String>) {
    if p.epoch != before.epoch
        && let Some(e) = p.epoch
    {
        trace.push(alloc::format!("parsed number of seconds part: number of seconds: {}", e.secs));
    }
    if p.date != before.date
        && let Some((y, m, d)) = p.date
    {
        trace.push(alloc::format!("parsed date part: {}", ymd(if y == i64::MIN { this_year } else { y }, m, d)));
    }
    if p.weekday != before.weekday
        && let Some((n, wd)) = p.weekday
    {
        trace.push(alloc::format!("parsed day part: {} (day ordinal={n} number={wd})", day_text(n, wd, p.this_said)));
    }
    let zone_changed = p.zone != before.zone;
    if p.time != before.time
        && let Some((h, m, sec, ns)) = p.time
    {
        let mut l = alloc::format!("parsed time part: {h:02}:{m:02}:{sec:02}");
        if ns != 0 {
            l.push_str(&alloc::format!(".{ns:09}"));
        }
        if zone_changed && let Some(z) = p.zone {
            l.push_str(&alloc::format!(" UTC{}", offset_text(z)));
        }
        trace.push(l);
    } else if zone_changed && let Some(z) = p.zone {
        trace.push(alloc::format!("parsed zone part: UTC{}", offset_text(z)));
    }
    if p.rel != before.rel {
        trace.push(alloc::format!("parsed relative part: {}", rel_text(&p.rel)));
    }
}

/// The parsed items as a moment, step by step as GNU's date takes them
/// (its `--debug` lines into `trace`): the start (the date and time
/// given, or today and now, or midnight), the day of the week, then the
/// years, months and days, then the hours, minutes and seconds.
fn resolve(p: &Parsed, now: Instant, zone: &InZone, desc: &str, trace: &mut Vec<String>) -> Option<Instant> {
    let fixed = p.zone;
    let in_tm = |t: i64| match fixed {
        Some(z) => {
            let mut x = time::gmtime(t + i64::from(z));
            x.offset = z;
            x
        }
        None => zone.tm(t),
    };
    trace.push(alloc::format!(
        "input timezone: {}",
        match (p.epoch, fixed) {
            (Some(_), _) => String::from("'@timespec' - always UTC"),
            (None, Some(z)) => alloc::format!("parsed date/time string ({})", offset_text(z)),
            _ => String::from(desc),
        }
    ));
    // `@SECONDS` stands alone (GNU's date refuses it with anything else).
    if let Some(e) = p.epoch {
        let alone = p.date.is_none() && p.time.is_none() && p.weekday.is_none() && p.rel == [0; 6] && fixed.is_none();
        return alone.then_some(e);
    }
    let mut tm = in_tm(p.epoch.map_or(now.secs, |e| e.secs));
    let mut nsec = p.epoch.map_or(now.nsec, |e| e.nsec);
    if let Some((y, m, d)) = p.date {
        if y != i64::MIN {
            tm.year = y;
        }
        if !(1..=12).contains(&m) || d == 0 || d > days_in(tm.year, m) {
            return None;
        }
        tm.month = m;
        tm.day = d;
    }
    let hms = |tm: &Tm| alloc::format!("{:02}:{:02}:{:02}", tm.hour, tm.min, tm.sec);
    match p.time {
        Some((h, m, sec, ns)) => {
            if h > 23 || m > 59 || sec > 60 {
                return None;
            }
            (tm.hour, tm.min, tm.sec) = (h, m, sec);
            nsec = ns;
            trace.push(alloc::format!("using specified time as starting value: '{}'", hms(&tm)));
        }
        None if p.date.is_some() || p.weekday.is_some() => {
            (tm.hour, tm.min, tm.sec) = (0, 0, 0);
            nsec = 0;
            trace.push(String::from("warning: using midnight as starting time: 00:00:00"));
        }
        None => trace.push(alloc::format!("using current time as starting value: '{}'", hms(&tm))),
    }
    if p.date.is_none() && p.weekday.is_none() {
        trace.push(alloc::format!("using current date as starting value: '{}'", ymd(tm.year, tm.month, tm.day)));
    }
    let tz_suffix = fixed.map(|z| alloc::format!(" TZ={}", offset_text(z))).unwrap_or_default();
    let stamp = |tm: &Tm, tz: &str| alloc::format!("{} {}{tz}", ymd(tm.year, tm.month, tm.day), hms(tm));
    let set_days = |tm: &mut Tm, days: i64| {
        let d = time::gmtime(days * 86_400);
        (tm.year, tm.month, tm.day) = (d.year, d.month, d.day);
    };
    let mut days = time::civil_to_days(tm.year, tm.month, 1) + i64::from(tm.day) - 1;
    // With a date given, a day of the week is ignored (GNU's date warns).
    let weekday = match (p.weekday, p.date) {
        (Some((n, wd)), Some(_)) => {
            trace.push(alloc::format!(
                "warning: day ({}) ignored when explicit dates are given",
                day_text(n, wd, p.this_said)
            ));
            None
        }
        (w, _) => w,
    };
    if let Some((n, wd)) = weekday {
        // A day by itself is today or the next such day; `N day` is the
        // Nth one after today, `last day` the one before.
        let cur = (days + 4).rem_euclid(7);
        let wd = i64::from(wd);
        days += match n {
            0 => (wd - cur).rem_euclid(7),
            n if n > 0 => (wd - cur - 1).rem_euclid(7) + 1 + 7 * (n - 1),
            n => -((cur - wd - 1).rem_euclid(7) + 1) + 7 * (n + 1),
        };
        set_days(&mut tm, days);
        trace.push(alloc::format!("new start date: '{}' is '{}'", day_text(n, wd as u32, p.this_said), stamp(&tm, "")));
    }
    trace.push(alloc::format!("starting date/time: '{}'", stamp(&tm, &tz_suffix)));
    // Years and months move the calendar date; days, the day count.
    let [ry, rm, rd, rh, rmin, rs] = p.rel;
    if (ry != 0 || rm != 0) && tm.day != 15 {
        trace.push(String::from(
            "warning: when adding relative months/years, it is recommended to specify the 15th of the months",
        ));
    }
    if rd != 0 && (tm.hour, tm.min, tm.sec) != (12, 0, 0) {
        trace.push(String::from("warning: when adding relative days, it is recommended to specify noon"));
    }
    if ry != 0 || rm != 0 || rd != 0 {
        let total = tm.year * 12 + i64::from(tm.month) - 1 + ry * 12 + rm;
        let (y, m, d) = (total.div_euclid(12), (total.rem_euclid(12) + 1) as u32, tm.day);
        let shifted = d > days_in(y, m);
        let month_days = time::civil_to_days(y, m, 1) + i64::from(d) - 1;
        set_days(&mut tm, month_days + rd);
        trace.push(alloc::format!("after date adjustment ({ry:+} years, {rm:+} months, {rd:+} days),"));
        trace.push(alloc::format!("    new date/time = '{}'", stamp(&tm, "")));
        if shifted {
            let n = time::gmtime(month_days * 86_400);
            trace.push(String::from("warning: month/year adjustment resulted in shifted dates:"));
            trace.push(alloc::format!("     adjusted Y M D: {y:04} {m:02} {d:02}"));
            trace.push(alloc::format!("   normalized Y M D: {:04} {:02} {:02}", n.year, n.month, n.day));
        }
    }
    let secs_of_day = i64::from(tm.hour) * 3600 + i64::from(tm.min) * 60 + i64::from(tm.sec);
    let local = (time::civil_to_days(tm.year, tm.month, 1) + i64::from(tm.day) - 1) * 86_400 + secs_of_day;
    let t = match fixed {
        Some(z) => local - i64::from(z),
        None => zone.time_of(&time::gmtime(local)),
    };
    trace.push(alloc::format!("'{}' = {t} epoch-seconds", stamp(&tm, &tz_suffix)));
    let shift = rh * 3600 + rmin * 60 + rs;
    if rh != 0 || rmin != 0 || rs != 0 {
        trace.push(alloc::format!("after time adjustment ({rh:+} hours, {rmin:+} minutes, {rs:+} seconds, +0 ns),"));
        trace.push(alloc::format!("    new time = {} epoch-seconds", t + shift));
    }
    Some(Instant { secs: t + shift, nsec })
}

/// date(1)'s `+FORMAT`: strftime's conversions plus GNU's `%N`, `%:z`,
/// `%P`, `%k`, `%l`, `%q`, `%s`, the flags `-_0^#` and field widths.
pub fn format(tm: &Tm, nsec: u32, fmt: &str) -> String {
    use core::fmt::Write;
    let mut out = String::new();
    let c: Vec<char> = fmt.chars().collect();
    let mut i = 0;
    while i < c.len() {
        if c[i] != '%' {
            out.push(c[i]);
            i += 1;
            continue;
        }
        let start = i;
        i += 1;
        let mut flag = None;
        while i < c.len() && matches!(c[i], '-' | '_' | '0' | '^' | '#') {
            flag = Some(c[i]);
            i += 1;
        }
        let mut width = None::<usize>;
        let ws = i;
        while i < c.len() && c[i].is_ascii_digit() {
            i += 1;
        }
        if i > ws {
            width = c[ws..i].iter().collect::<String>().parse().ok();
        }
        let mut colons = 0;
        while i < c.len() && c[i] == ':' {
            colons += 1;
            i += 1;
        }
        while i < c.len() && matches!(c[i], 'E' | 'O') {
            i += 1;
        }
        let Some(&conv) = c.get(i) else {
            out.extend(&c[start..]);
            break;
        };
        i += 1;
        // (text, is number, default pad char, default width)
        let wd = tm.weekday as usize;
        let h12 = if tm.hour % 12 == 0 { 12 } else { tm.hour % 12 };
        let off = tm.offset;
        let zone_num = |colons: usize| -> String {
            let a = off.unsigned_abs();
            let sign = if off < 0 { '-' } else { '+' };
            let (h, m, s) = (a / 3600, a / 60 % 60, a % 60);
            match colons {
                0 => alloc::format!("{sign}{h:02}{m:02}"),
                1 => alloc::format!("{sign}{h:02}:{m:02}"),
                2 => alloc::format!("{sign}{h:02}:{m:02}:{s:02}"),
                _ if s != 0 => alloc::format!("{sign}{h:02}:{m:02}:{s:02}"),
                _ if m != 0 => alloc::format!("{sign}{h:02}:{m:02}"),
                _ => alloc::format!("{sign}{h:02}"),
            }
        };
        let iso = iso_week(tm);
        let (text, numeric, pad, w): (String, bool, char, usize) = match conv {
            'a' => (String::from(time::DAYS[wd]), false, ' ', 0),
            'A' => (String::from(time::FULL_DAYS[wd]), false, ' ', 0),
            'b' | 'h' => (String::from(time::MONTHS[tm.month as usize - 1]), false, ' ', 0),
            'B' => (String::from(time::FULL_MONTHS[tm.month as usize - 1]), false, ' ', 0),
            'c' => (format(tm, nsec, "%a %b %e %H:%M:%S %Y"), false, ' ', 0),
            'C' => (alloc::format!("{}", tm.year.div_euclid(100)), true, '0', 2),
            'd' => (alloc::format!("{}", tm.day), true, '0', 2),
            'D' => (format(tm, nsec, "%m/%d/%y"), false, ' ', 0),
            'e' => (alloc::format!("{}", tm.day), true, ' ', 2),
            'F' => (format(tm, nsec, "%Y-%m-%d"), false, ' ', 0),
            'g' => (alloc::format!("{}", iso.0.rem_euclid(100)), true, '0', 2),
            'G' => (alloc::format!("{}", iso.0), true, '0', 4),
            'H' => (alloc::format!("{}", tm.hour), true, '0', 2),
            'I' => (alloc::format!("{h12}"), true, '0', 2),
            'j' => (alloc::format!("{}", tm.yearday + 1), true, '0', 3),
            'k' => (alloc::format!("{}", tm.hour), true, ' ', 2),
            'l' => (alloc::format!("{h12}"), true, ' ', 2),
            'm' => (alloc::format!("{}", tm.month), true, '0', 2),
            'M' => (alloc::format!("{}", tm.min), true, '0', 2),
            'n' => (String::from("\n"), false, ' ', 0),
            'N' => {
                let mut s = alloc::format!("{nsec:09}");
                if let Some(w) = width {
                    s.truncate(w.min(9));
                    while s.len() < w {
                        s.push('0');
                    }
                }
                out.push_str(&s);
                continue;
            }
            'p' => (String::from(if tm.hour < 12 { "AM" } else { "PM" }), false, ' ', 0),
            'P' => (String::from(if tm.hour < 12 { "am" } else { "pm" }), false, ' ', 0),
            'q' => (alloc::format!("{}", (tm.month - 1) / 3 + 1), true, '0', 1),
            'r' => (format(tm, nsec, "%I:%M:%S %p"), false, ' ', 0),
            'R' => (format(tm, nsec, "%H:%M"), false, ' ', 0),
            's' => (alloc::format!("{}", time::timegm(tm) - i64::from(off)), true, '0', 1),
            'S' => (alloc::format!("{}", tm.sec), true, '0', 2),
            't' => (String::from("\t"), false, ' ', 0),
            'T' => (format(tm, nsec, "%H:%M:%S"), false, ' ', 0),
            'u' => (alloc::format!("{}", if wd == 0 { 7 } else { wd }), true, '0', 1),
            'U' => (alloc::format!("{}", (tm.yearday as usize + 7 - wd) / 7), true, '0', 2),
            'V' => (alloc::format!("{}", iso.1), true, '0', 2),
            'w' => (alloc::format!("{wd}"), true, '0', 1),
            'W' => (alloc::format!("{}", (tm.yearday as usize + 7 - (wd + 6) % 7) / 7), true, '0', 2),
            'x' => (format(tm, nsec, "%m/%d/%y"), false, ' ', 0),
            'X' => (format(tm, nsec, "%H:%M:%S"), false, ' ', 0),
            'y' => (alloc::format!("{}", tm.year.rem_euclid(100)), true, '0', 2),
            'Y' => (alloc::format!("{}", tm.year), true, '0', 4),
            'z' => (zone_num(colons), false, ' ', 0),
            'Z' => (String::from(tm.zone.as_str()), false, ' ', 0),
            '%' => (String::from("%"), false, ' ', 0),
            other => {
                // Unknown: printed as written.
                out.extend(&c[start..i - 1]);
                out.push(other);
                continue;
            }
        };
        let mut text = text;
        match flag {
            Some('^') => text = text.to_ascii_uppercase(),
            Some('#') => {
                text = if text.chars().any(|ch| ch.is_ascii_lowercase()) {
                    text.to_ascii_uppercase()
                } else {
                    text.to_ascii_lowercase()
                }
            }
            _ => {}
        }
        let (pad, w) = match flag {
            Some('-') => (' ', 0),
            Some('_') => (' ', width.unwrap_or(w)),
            Some('0') => ('0', width.unwrap_or(w)),
            _ => (pad, width.unwrap_or(w)),
        };
        let w = if numeric || width.is_some() { w } else { 0 };
        if text.len() < w {
            let n = w - text.len();
            if pad == '0' && text.starts_with('-') {
                out.push('-');
                out.extend(core::iter::repeat_n('0', n));
                out.push_str(&text[1..]);
            } else {
                out.extend(core::iter::repeat_n(pad, n));
                out.push_str(&text);
            }
        } else {
            let _ = write!(out, "{text}");
        }
    }
    out
}

/// ISO 8601 week-numbering year and week.
fn iso_week(tm: &Tm) -> (i64, u32) {
    let wd = (tm.weekday + 6) % 7; // Monday = 0
    let yday = i64::from(tm.yearday);
    let mut week = (yday - i64::from(wd) + 10) / 7;
    let mut year = tm.year;
    if week < 1 {
        year -= 1;
        let prev_days = if time::is_leap(year) { 366 } else { 365 };
        week = (yday + prev_days - i64::from(wd) + 10) / 7;
    } else {
        let days = if time::is_leap(year) { 366 } else { 365 };
        if week == 53 && yday - i64::from(wd) + 3 >= days {
            year += 1;
            week = 1;
        }
    }
    (year, week as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> Option<i64> {
        // Thursday 2026-10-22 15:30:45 UTC.
        parse(s, Instant { secs: 1_792_683_045, nsec: 5 }, true).map(|i| i.secs)
    }

    fn day(y: i64, m: u32, d: u32, h: i64, mi: i64, s: i64) -> i64 {
        time::civil_to_days(y, m, d) * 86_400 + h * 3600 + mi * 60 + s
    }

    #[test]
    fn absolute_forms() {
        assert_eq!(at("2020-01-02"), Some(day(2020, 1, 2, 0, 0, 0)));
        assert_eq!(at("2020-01-02 03:04:05"), Some(day(2020, 1, 2, 3, 4, 5)));
        assert_eq!(at("2020-01-02T03:04:05Z"), Some(day(2020, 1, 2, 3, 4, 5)));
        assert_eq!(at("2020-01-02T03:04:05+02:00"), Some(day(2020, 1, 2, 1, 4, 5)));
        assert_eq!(at("1/2/2020"), Some(day(2020, 1, 2, 0, 0, 0)));
        assert_eq!(at("2 Jan 2020"), Some(day(2020, 1, 2, 0, 0, 0)));
        assert_eq!(at("Jan 2, 2020 3pm"), Some(day(2020, 1, 2, 15, 0, 0)));
        assert_eq!(at("Thu, 02 Jan 2020 10:00:00 +0000"), Some(day(2020, 1, 2, 10, 0, 0)));
        assert_eq!(at("02-jan-2020"), Some(day(2020, 1, 2, 0, 0, 0)));
        assert_eq!(at("20200102"), Some(day(2020, 1, 2, 0, 0, 0)));
        assert_eq!(at("@86400"), Some(86_400));
        assert_eq!(at("@-1"), Some(-1));
        assert_eq!(at("12:00"), Some(day(2026, 10, 22, 12, 0, 0)));
        assert_eq!(at("oct 22 10:00 2026"), Some(day(2026, 10, 22, 10, 0, 0)));
        assert_eq!(at("2026"), Some(day(2026, 10, 22, 20, 26, 0)));
        assert_eq!(at("2020/01/02"), Some(day(2020, 1, 2, 0, 0, 0)));
        assert_eq!(at("10/22/26"), Some(day(2026, 10, 22, 0, 0, 0)));
        assert_eq!(at("12am"), Some(day(2026, 10, 22, 0, 0, 0)));
        assert_eq!(at("2020-01-02 10:00 EST"), Some(day(2020, 1, 2, 15, 0, 0)));
        assert_eq!(at("2020-01-02 10:00 UTC+3"), Some(day(2020, 1, 2, 7, 0, 0)));
        assert_eq!(at("2020-01-02 24:00"), None);
        assert_eq!(at("2020-02-30"), None);
        assert_eq!(at("bogus"), None);
    }

    #[test]
    fn relative_forms() {
        let now = 1_792_683_045;
        assert_eq!(at("now"), Some(now));
        assert_eq!(at("tomorrow"), Some(now + 86_400));
        assert_eq!(at("3 days ago"), Some(now - 3 * 86_400));
        assert_eq!(at("-2 hours"), Some(now - 7200));
        assert_eq!(at("2020-01-31 +1 month"), Some(day(2020, 3, 2, 0, 0, 0)));
        assert_eq!(at("2020-01-02 next week"), Some(day(2020, 1, 9, 0, 0, 0)));
        assert_eq!(at("monday"), Some(day(2026, 10, 26, 0, 0, 0)));
        assert_eq!(at("thursday"), Some(day(2026, 10, 22, 0, 0, 0)));
        assert_eq!(at("last thursday"), Some(day(2026, 10, 15, 0, 0, 0)));
        assert_eq!(at("next thursday"), Some(day(2026, 10, 29, 0, 0, 0)));
        assert_eq!(at("next monday"), Some(day(2026, 10, 26, 0, 0, 0)));
        assert_eq!(at("2 monday"), Some(day(2026, 11, 2, 0, 0, 0)));
        assert_eq!(at("third thursday"), Some(day(2026, 11, 12, 0, 0, 0)));
        assert_eq!(at("last monday"), Some(day(2026, 10, 19, 0, 0, 0)));
        assert_eq!(at("2020-01-02 +3 days 2 hours ago"), Some(day(2020, 1, 4, 22, 0, 0)));
    }

    #[test]
    fn formats() {
        let tm = time::gmtime(day(2020, 1, 2, 3, 4, 5));
        assert_eq!(
            format(&tm, 123_456_789, "%F %T.%N %3N %:z %s"),
            "2020-01-02 03:04:05.123456789 123 +00:00 1577934245"
        );
        assert_eq!(
            format(&tm, 0, "%-d %_m %^a %e %k %l %P %q %j %U %W %V %G"),
            "2  1 THU  2  3  3 am 1 002 00 00 01 2020"
        );
        assert_eq!(format(&tm, 0, "%10Y|%-H|%_5S"), "0000002020|3|    5");
    }
}
