// SPDX-License-Identifier: MIT OR Apache-2.0

//! Calendar (ADR 0109), `calendar [FILE.ics]`: local calendars kept as
//! iCalendar files (`~/.local/share/slate/calendars/NAME.ics`, read and
//! written by `libs/pim`), a month at a time, or as an agenda.
//!
//! - The month: the arrows move the chosen day, Page Up and Down the
//!   month, `t` goes to today; the chosen day's events are beside it.
//!   Enter goes into them (up and down, Enter edits, Delete deletes,
//!   Esc back); `n` makes a new one on the chosen day.
//! - Tab switches to the agenda (the next eight weeks) and back.
//! - An event's form: Tab and shift + Tab move between its fields, left
//!   and right change its choices (all day, repeat, calendar), ctrl + s
//!   or Enter saves, Esc leaves it.
//! - Opening a `.ics` file imports it, into the calendar it names (an
//!   event already there, by its UID, is replaced); ctrl + e exports every
//!   calendar to ~/Documents.
//!
//! Each calendar has a colour from STRATA_COLORS.md, always shown with
//! its name. Events made in other zones show in local time.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_display::input::{
    KEY_BACKSPACE, KEY_DELETE, KEY_DOWN, KEY_END, KEY_ENTER, KEY_ESC, KEY_HOME, KEY_KPENTER, KEY_LEFT, KEY_PAGEDOWN,
    KEY_PAGEUP, KEY_RIGHT, KEY_SPACE, KEY_TAB, KEY_UP,
};
use slate_pim::date::{Date, days_to_date, month_days, weekday};
use slate_pim::ical::{Calendar, Event, Freq, Repeat, When};
use slate_strata::fonts::Fonts;
use slate_strata_client::mods::{ALT, CTRL, LOGO, SHIFT};
use slate_ui::edit::{EditKey, LineEdit};
use slate_ui::graphite::{Accent, Palette};
use slate_ui::paint::Painter;
use slate_ui::ui::Area;

use crate::kit::{self, App, Effect, Hints, Now};

const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MONTHS: [&str; 12] = [
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
/// The days the agenda looks ahead.
const AGENDA_DAYS: i64 = 56;

/// The accents calendars take, in order (clay means errors, so never).
fn accent(pal: &Palette, i: usize) -> Accent {
    let a = &pal.accents;
    [a.heather, a.steel, a.sage, a.ochre, a.moss][i % 5]
}

/// An event on a day, in local time: (calendar, event index, start and
/// end seconds into the day or None for all day).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shown {
    pub cal: usize,
    pub event: usize,
    pub time: Option<(u32, u32)>,
    pub title: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    Month,
    Agenda,
}

/// The fields of the event form, in order.
const FIELDS: [&str; 9] = ["title", "date", "all day", "starts", "ends", "repeat", "calendar", "where", "notes"];
const REPEATS: [&str; 5] = ["never", "every day", "every week", "every month", "every year"];

#[derive(Clone, Debug)]
pub struct Form {
    /// The event edited: (calendar, index), or None for a new one.
    pub editing: Option<(usize, usize)>,
    pub field: usize,
    pub title: LineEdit,
    pub date: LineEdit,
    pub all_day: bool,
    pub starts: LineEdit,
    pub ends: LineEdit,
    pub repeat: usize,
    pub cal: usize,
    pub place: LineEdit,
    pub notes: LineEdit,
    pub error: String,
}

pub struct Cal {
    pub dir: String,
    pub calendars: Vec<(String, Calendar)>,
    pub today: Date,
    pub day: Date,
    pub view: View,
    /// Into the chosen day's events (the index), or not.
    pub in_day: Option<usize>,
    pub form: Option<Form>,
    pub status: String,
    zones: Option<Vec<u8>>,
    local: slate_rt::tz::Rule,
    cells: Vec<(Area, Date)>,
    confirm_delete: bool,
    uid_n: u32,
}

impl core::fmt::Debug for Cal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Cal({} calendars, {:?})", self.calendars.len(), self.day)
    }
}

fn secs_text(s: u32) -> String {
    alloc::format!("{:02}:{:02}", s / 3600, s / 60 % 60)
}

/// "9:30", "0930", "9" as seconds into the day.
fn parse_time(t: &str) -> Option<u32> {
    let t = t.trim();
    let (h, m) = match t.split_once(':') {
        Some((h, m)) => (h.parse::<u32>().ok()?, m.parse::<u32>().ok()?),
        None if t.len() == 4 => (t[..2].parse().ok()?, t[2..].parse().ok()?),
        None => (t.parse().ok()?, 0),
    };
    (h < 24 && m < 60).then_some(h * 3600 + m * 60)
}

/// "2026-10-24" as a date.
fn parse_date(t: &str) -> Option<Date> {
    let mut it = t.trim().split('-');
    let (y, m, d) = (it.next()?.parse().ok()?, it.next()?.parse().ok()?, it.next()?.parse().ok()?);
    if it.next().is_some() {
        return None;
    }
    Date::new(y, m, d)
}

fn date_text(d: Date) -> String {
    alloc::format!("{:04}-{:02}-{:02}", d.year, d.month, d.day)
}

/// Monday 0 to Sunday 6.
fn iso_weekday(d: Date) -> usize {
    (usize::from(weekday(d)) + 6) % 7
}

impl Cal {
    pub fn new(dir: &str, today: Date, zones: Option<Vec<u8>>, local: slate_rt::tz::Rule) -> Cal {
        let mut c = Cal {
            dir: dir.to_string(),
            calendars: Vec::new(),
            today,
            day: today,
            view: View::Month,
            in_day: None,
            form: None,
            status: String::new(),
            zones,
            local,
            cells: Vec::new(),
            confirm_delete: false,
            uid_n: 0,
        };
        c.load();
        c
    }

    /// Read the calendars in the folder (a Personal one if there are none).
    pub fn load(&mut self) {
        let mut names: Vec<String> = slate_rt::fs::read_dir(self.dir.as_bytes())
            .map(|es| {
                es.iter().map(|e| String::from(slate_rt::lossy(&e.name))).filter(|n| n.ends_with(".ics")).collect()
            })
            .unwrap_or_default();
        names.sort();
        self.calendars = names
            .iter()
            .filter_map(|n| {
                let text = slate_rt::fs::read_file(alloc::format!("{}/{n}", self.dir).as_bytes()).ok()?;
                let mut c = Calendar::parse(&slate_rt::lossy(&text));
                let name = n.trim_end_matches(".ics").to_string();
                if c.name.is_empty() {
                    c.name = name.clone();
                }
                Some((name, c))
            })
            .collect();
        if self.calendars.is_empty() {
            self.calendars
                .push((String::from("Personal"), Calendar { name: "Personal".into(), ..Calendar::default() }));
        }
    }

    fn save(&mut self, i: usize) {
        let dir = self.dir.clone();
        let mut at = String::new();
        for c in dir.split('/').filter(|c| !c.is_empty()) {
            at.push('/');
            at.push_str(c);
            let _ = slate_rt::fs::mkdir(at.as_bytes(), 0o700);
        }
        let (name, cal) = &self.calendars[i];
        let path = alloc::format!("{dir}/{name}.ics");
        let tmp = alloc::format!("{path}.new");
        let text = cal.render(&utc_stamp(slate_rt::time::unix()));
        let r = slate_rt::fs::write_file(tmp.as_bytes(), text.as_bytes(), 0o600)
            .and_then(|_| slate_rt::fs::rename(tmp.as_bytes(), path.as_bytes()));
        if let Err(e) = r {
            self.status = alloc::format!("Couldn't save {name}: {e}");
        }
    }

    /// A moment of an event (on `date`, at `secs`, in `zone`) in local
    /// time: its date and seconds into it.
    fn local(&self, date: Date, secs: u32, zone: &Option<String>) -> (Date, u32) {
        let rule = match zone.as_deref() {
            None => return (date, secs),
            Some("UTC") => slate_rt::tz::Rule::UTC,
            Some(z) => match slate_rt::tz::Rule::resolve(z, self.zones.as_deref()) {
                Some(r) => r,
                // A zone this system doesn't know: as written.
                None => return (date, secs),
            },
        };
        let tm = slate_rt::time::Tm {
            year: i64::from(date.year),
            month: u32::from(date.month),
            day: u32::from(date.day),
            hour: secs / 3600,
            min: secs / 60 % 60,
            sec: secs % 60,
            ..Default::default()
        };
        let t = rule.timelocal(&tm);
        let l = self.local.localtime(t);
        let d = Date::new(l.year as i32, l.month as u8, l.day as u8).unwrap_or(date);
        (d, l.hour * 3600 + l.min * 60 + l.sec)
    }

    /// The events on `day`, in local time, all-day ones first, then by
    /// time.
    pub fn on(&self, day: Date) -> Vec<Shown> {
        let mut out = Vec::new();
        for (ci, (_, cal)) in self.calendars.iter().enumerate() {
            for (ei, e) in cal.events.iter().enumerate() {
                match &e.start {
                    When::Day(_) => {
                        let len = (e.end.date().days() - e.start.date().days()).max(1);
                        // An all-day event covers its days.
                        let starts = e.days(days_to_date(day.days() - len + 1), day);
                        if !starts.is_empty() {
                            out.push(Shown { cal: ci, event: ei, time: None, title: e.summary.clone() });
                        }
                    }
                    When::At(_, secs, zone) => {
                        // Occurrences a day either side may land on this day
                        // once in local time.
                        let near = e.days(days_to_date(day.days() - 1), days_to_date(day.days() + 1));
                        for d in near {
                            let (ld, ls) = self.local(d, *secs, zone);
                            if ld == day {
                                let len = match (&e.start, &e.end) {
                                    (When::At(a, s1, _), When::At(b, s2, _)) => {
                                        (b.days() - a.days()) * 86_400 + i64::from(*s2) - i64::from(*s1)
                                    }
                                    _ => 0,
                                };
                                let end = (i64::from(ls) + len.max(0)).min(86_400) as u32;
                                out.push(Shown { cal: ci, event: ei, time: Some((ls, end)), title: e.summary.clone() });
                            }
                        }
                    }
                }
            }
        }
        out.sort_by_key(|s| (s.time.map_or(-1, |t| i64::from(t.0)), s.title.to_lowercase()));
        out
    }

    /// Import a calendar file's events.
    pub fn import(&mut self, name: &str, text: &str) -> String {
        let incoming = Calendar::parse(text);
        if incoming.events.is_empty() {
            return alloc::format!("{name} has no events Slate can read.");
        }
        let target = if incoming.name.is_empty() {
            name.rsplit('/').next().unwrap_or(name).trim_end_matches(".ics").to_string()
        } else {
            incoming.name.clone()
        };
        let target = target.replace('/', "-");
        let i = match self.calendars.iter().position(|(n, _)| *n == target) {
            Some(i) => i,
            None => {
                self.calendars.push((target.clone(), Calendar { name: target.clone(), ..Calendar::default() }));
                self.calendars.len() - 1
            }
        };
        let n = incoming.events.len();
        let (new, replaced) = self.calendars[i].1.merge(incoming);
        self.save(i);
        crate::trace!("calendar: imported {n} events into {target}");
        let mut s = alloc::format!("Imported {new} new event{} into {target}", if new == 1 { "" } else { "s" });
        if replaced > 0 {
            s.push_str(&alloc::format!(", {replaced} updated"));
        }
        s.push('.');
        if let Some(first) =
            self.calendars[i].1.events.iter().map(|e| e.start.date()).filter(|d| *d >= self.today).min()
        {
            self.day = first;
        }
        s
    }

    /// Every calendar written to `dir`.
    pub fn export(&mut self, dir: &str) -> String {
        let stamp = utc_stamp(slate_rt::time::unix());
        let mut done = Vec::new();
        for (name, cal) in &self.calendars {
            let path = alloc::format!("{dir}/{name}.ics");
            if slate_rt::fs::write_file(path.as_bytes(), cal.render(&stamp).as_bytes(), 0o644).is_ok() {
                done.push(name.clone());
            }
        }
        crate::trace!("calendar: exported {}", done.join(", "));
        alloc::format!("Exported {} to {}.", done.join(", "), dir.rsplit('/').next().unwrap_or(dir))
    }

    fn new_form(&self, editing: Option<(usize, usize)>) -> Form {
        let e = editing.map(|(c, i)| &self.calendars[c].1.events[i]);
        let (all_day, s, end) = match e.map(|e| (&e.start, &e.end)) {
            Some((When::At(_, a, _), When::At(_, b, _))) => (false, *a, *b),
            Some(_) => (true, 9 * 3600, 10 * 3600),
            None => (false, 9 * 3600, 10 * 3600),
        };
        let repeat = match e.and_then(|e| e.repeat.as_ref()).map(|r| r.freq) {
            None => 0,
            Some(Freq::Daily) => 1,
            Some(Freq::Weekly) => 2,
            Some(Freq::Monthly) => 3,
            Some(Freq::Yearly) => 4,
        };
        let date = e.map_or(self.day, |e| e.start.date());
        Form {
            editing,
            field: 0,
            title: LineEdit::new(e.map_or("", |e| e.summary.as_str())).with_max(200),
            date: LineEdit::new(&date_text(date)).with_max(10),
            all_day,
            starts: LineEdit::new(&secs_text(s)).with_max(5),
            ends: LineEdit::new(&secs_text(end)).with_max(5),
            repeat,
            cal: editing.map_or(0, |(c, _)| c),
            place: LineEdit::new(e.map_or("", |e| e.location.as_str())).with_max(200),
            notes: LineEdit::new(e.map_or("", |e| e.description.as_str())).with_max(2000),
            error: String::new(),
        }
    }

    /// Save the form's event; false (with its error) if it doesn't hold
    /// together.
    fn save_form(&mut self) -> bool {
        let Some(f) = self.form.as_mut() else { return false };
        let title = f.title.text().trim().to_string();
        let Some(date) = parse_date(&f.date.text()) else {
            f.error = String::from("The date is year-month-day, as 2026-10-24.");
            f.field = 1;
            return false;
        };
        let (start, end) = if f.all_day {
            (When::Day(date), When::Day(days_to_date(date.days() + 1)))
        } else {
            let (Some(a), Some(b)) = (parse_time(&f.starts.text()), parse_time(&f.ends.text())) else {
                f.error = String::from("Times are hours and minutes, as 09:30.");
                f.field = 3;
                return false;
            };
            // An end before the start is the next day's.
            let end_day = if b <= a { days_to_date(date.days() + 1) } else { date };
            (When::At(date, a, None), When::At(end_day, b, None))
        };
        let repeat = match f.repeat {
            0 => None,
            k => Some(Repeat {
                freq: [Freq::Daily, Freq::Weekly, Freq::Monthly, Freq::Yearly][k - 1],
                interval: 1,
                count: None,
                until: None,
                days: Vec::new(),
            }),
        };
        let (place, notes, cal, editing) = (f.place.text(), f.notes.text(), f.cal, f.editing);
        let title = if title.is_empty() { String::from("New event") } else { title };
        match editing {
            Some((c, i)) => {
                let mut e = self.calendars[c].1.events.remove(i);
                e.summary = title.clone();
                e.start = start;
                e.end = end;
                // The same kind of repeat keeps the rule's details
                // (weekdays, a count, an end); another replaces it.
                if repeat.as_ref().map(|r| r.freq) != e.repeat.as_ref().map(|r| r.freq) {
                    e.repeat = repeat;
                }
                e.location = place;
                e.description = notes;
                self.calendars[cal].1.events.push(e);
                self.save(c);
                if cal != c {
                    self.save(cal);
                }
            }
            None => {
                self.uid_n += 1;
                let e = Event {
                    uid: slate_pim::ical::new_uid(slate_rt::time::unix(), self.uid_n),
                    summary: title.clone(),
                    description: notes,
                    location: place,
                    start,
                    end,
                    repeat,
                    except: Vec::new(),
                    other: Vec::new(),
                    children: Vec::new(),
                };
                self.calendars[cal].1.events.push(e);
                self.save(cal);
            }
        }
        crate::trace!("calendar: saved \"{title}\" on {}", date_text(date));
        self.day = date;
        self.form = None;
        self.status = alloc::format!("Saved {title}.");
        true
    }

    fn form_key(&mut self, code: u16, ch: Option<char>, mods: u8) -> Effect {
        let (shift, ctrl) = (mods & SHIFT != 0, mods & CTRL != 0);
        let ncal = self.calendars.len();
        let Some(f) = self.form.as_mut() else { return Effect::None };
        match (code, ch.map(|c| c.to_ascii_lowercase())) {
            (KEY_ESC, _) => {
                self.form = None;
                return Effect::Redraw;
            }
            (_, Some('s')) if ctrl => {
                self.save_form();
                return Effect::Redraw;
            }
            (KEY_ENTER | KEY_KPENTER, _) => {
                self.save_form();
                return Effect::Redraw;
            }
            (KEY_TAB | KEY_DOWN, _) | (KEY_UP, _) => {
                let back = shift || code == KEY_UP;
                let n = FIELDS.len();
                loop {
                    f.field = if back { (f.field + n - 1) % n } else { (f.field + 1) % n };
                    // The times are skipped for an all-day event.
                    if !(f.all_day && (f.field == 3 || f.field == 4)) {
                        break;
                    }
                }
                return Effect::Redraw;
            }
            _ => {}
        }
        // The choice fields.
        let step = match code {
            KEY_LEFT => Some(false),
            KEY_RIGHT | KEY_SPACE => Some(true),
            _ => None,
        };
        match (f.field, step) {
            (2, Some(_)) => f.all_day = !f.all_day,
            (5, Some(fwd)) => f.repeat = if fwd { (f.repeat + 1) % 5 } else { (f.repeat + 4) % 5 },
            (6, Some(fwd)) => f.cal = if fwd { (f.cal + 1) % ncal } else { (f.cal + ncal - 1) % ncal },
            (2 | 5 | 6, None) => return Effect::None,
            _ => {
                let field = match f.field {
                    0 => &mut f.title,
                    1 => &mut f.date,
                    3 => &mut f.starts,
                    4 => &mut f.ends,
                    7 => &mut f.place,
                    _ => &mut f.notes,
                };
                if !edit(field, code, ch, mods) {
                    return Effect::None;
                }
                f.error.clear();
            }
        }
        Effect::Redraw
    }
}

/// A text field's keys; whether anything changed.
pub fn edit(f: &mut LineEdit, code: u16, ch: Option<char>, mods: u8) -> bool {
    let (shift, ctrl) = (mods & SHIFT != 0, mods & CTRL != 0);
    let k = match (code, ch.map(|c| c.to_ascii_lowercase())) {
        (KEY_LEFT, _) => Some(EditKey::Left),
        (KEY_RIGHT, _) => Some(EditKey::Right),
        (KEY_HOME, _) => Some(EditKey::Home),
        (KEY_END, _) => Some(EditKey::End),
        (KEY_BACKSPACE, _) => Some(EditKey::Backspace),
        (KEY_DELETE, _) => Some(EditKey::Delete),
        (_, Some('a')) if ctrl => Some(EditKey::SelectAll),
        _ => None,
    };
    let shortcut = mods & (CTRL | ALT | LOGO) != 0;
    match (k, ch.filter(|c| !shortcut && !c.is_control())) {
        (Some(k), _) => f.key(k, shift, ctrl).moved,
        (None, Some(c)) => f.insert(c.encode_utf8(&mut [0u8; 4])),
        _ => false,
    }
}

/// `t` (seconds since the epoch) as an iCalendar UTC stamp.
pub fn utc_stamp(t: i64) -> String {
    let tm = slate_rt::time::gmtime(t);
    alloc::format!("{:04}{:02}{:02}T{:02}{:02}{:02}Z", tm.year, tm.month, tm.day, tm.hour, tm.min, tm.sec)
}

/// Draw a text field with its caret (and selection), for forms.
pub fn field(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area, e: &LineEdit, focused: bool) {
    p.fill(a, 6.0, pal.well);
    p.border(a, 6.0, 1.0, if focused { pal.field_focus } else { pal.border });
    let mut s = p.style(&f.regular, 13.5, pal.text_1);
    s.ligatures = false;
    let text = e.text();
    let clip = p.clip(a);
    if focused && let Some((s0, s1)) = e.selection() {
        let a0: String = text.chars().take(s0).collect();
        let a1: String = text.chars().take(s1).collect();
        let (x0, x1) = (p.measure(&s, &a0), p.measure(&s, &a1));
        p.fill(Area::new(a.x + 10.0 + x0, a.y + 5.0, x1 - x0, a.h - 10.0), 0.0, pal.raised);
    }
    p.line(&s, a.x + 10.0, a.y + (a.h - 20.0) / 2.0, 20.0, &text);
    if focused {
        let before: String = text.chars().take(e.caret()).collect();
        let cx = p.measure(&s, &before);
        p.fill(Area::new(a.x + 10.0 + cx, a.y + (a.h - 18.0) / 2.0, 1.5, 18.0), 0.0, pal.chalk);
    }
    p.unclip(clip);
}

/// A choice shown as a field: `< value >`.
fn choice(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area, value: &str, focused: bool, dot: Option<Accent>) {
    p.fill(a, 6.0, pal.well);
    p.border(a, 6.0, 1.0, if focused { pal.field_focus } else { pal.border });
    let mut x = a.x + 10.0;
    if let Some(acc) = dot {
        p.fill(Area::new(x, a.y + a.h / 2.0 - 4.0, 8.0, 8.0), 4.0, acc.text);
        x += 16.0;
    }
    let s = p.style(&f.regular, 13.5, pal.text_1);
    p.line(&s, x, a.y + (a.h - 20.0) / 2.0, 20.0, value);
    if focused {
        let hint = p.style(&f.mono, 11.0, pal.muted);
        let w = p.measure(&hint, "left / right");
        p.line(&hint, a.x + a.w - 10.0 - w, a.y + (a.h - 18.0) / 2.0, 18.0, "left / right");
    }
}

impl App for Cal {
    fn draw(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area) {
        self.cells.clear();
        let title = p.style(&f.semibold, 20.0, pal.chalk);
        let label = p.style(&f.mono, 11.0, pal.muted);
        let small = p.style(&f.regular, 12.0, pal.text_2);
        let name_s = p.style(&f.medium, 13.5, pal.text_1);
        let mono = p.style(&f.mono, 12.0, pal.text_3);
        let pad = 20.0;
        if let Some(form) = &self.form {
            let x = a.x + pad;
            let w = (a.w - 2.0 * pad).min(560.0);
            let head = if form.editing.is_some() { "Change the event" } else { "A new event" };
            p.line(&title, x, a.y + 16.0, 28.0, head);
            let mut y = a.y + 60.0;
            for (i, name) in FIELDS.iter().enumerate() {
                if form.all_day && (i == 3 || i == 4) {
                    continue;
                }
                p.line(&label, x, y + 9.0, 18.0, name);
                let fa = Area::new(x + 90.0, y, w - 90.0, 34.0);
                let on = form.field == i;
                match i {
                    0 => field(p, pal, f, fa, &form.title, on),
                    1 => field(p, pal, f, fa, &form.date, on),
                    2 => choice(p, pal, f, fa, if form.all_day { "yes" } else { "no" }, on, None),
                    3 => field(p, pal, f, fa, &form.starts, on),
                    4 => field(p, pal, f, fa, &form.ends, on),
                    5 => choice(p, pal, f, fa, REPEATS[form.repeat], on, None),
                    6 => {
                        let (n, _) = &self.calendars[form.cal];
                        choice(p, pal, f, fa, n, on, Some(accent(pal, form.cal)));
                    }
                    7 => field(p, pal, f, fa, &form.place, on),
                    _ => field(p, pal, f, fa, &form.notes, on),
                }
                y += 42.0;
            }
            if !form.error.is_empty() {
                // An error, in clay with its words (STRATA_COLORS.md).
                let c = pal.accents.clay;
                let r = Area::new(x, y + 4.0, w, 36.0);
                p.fill(r, 8.0, c.tint);
                p.border(r, 8.0, 1.0, c.border);
                let e = p.style(&f.medium, 13.0, c.text);
                p.line(&e, r.x + 12.0, r.y + 8.0, 20.0, &form.error);
            }
            kit::hints(p, pal, f, a, &[("tab", "next field"), ("enter", "save"), ("esc", "cancel")]);
            return;
        }
        // The header: the month (or Agenda), and the view.
        let x = a.x + pad;
        let head = match self.view {
            View::Month => alloc::format!("{} {}", MONTHS[usize::from(self.day.month) - 1], self.day.year),
            View::Agenda => String::from("Coming up"),
        };
        p.line(&title, x, a.y + 14.0, 28.0, &head);
        // The calendars, each with its colour and name.
        let mut lx = a.x + a.w - pad;
        for (i, (n, _)) in self.calendars.iter().enumerate().rev() {
            let w = p.measure(&small, n);
            lx -= w;
            p.line(&small, lx, a.y + 20.0, 18.0, n);
            lx -= 14.0;
            p.fill(Area::new(lx, a.y + 25.0, 8.0, 8.0), 4.0, accent(pal, i).text);
            lx -= 16.0;
        }
        let top = a.y + 58.0;
        let bottom = a.y + a.h - 40.0;
        match self.view {
            View::Month => {
                let panel_w = (a.w * 0.32).clamp(220.0, 320.0);
                let gw = a.w - 2.0 * pad - panel_w - 16.0;
                let cw = gw / 7.0;
                for (i, d) in WEEKDAYS.iter().enumerate() {
                    p.line(&label, x + i as f32 * cw + 6.0, top, 16.0, d);
                }
                let first = self.day.first_of_month();
                let lead = iso_weekday(first) as i64;
                let start = first.days() - lead;
                let rows = (lead + i64::from(month_days(first.year, first.month))).div_euclid(7) + 1;
                let rows = rows.clamp(5, 6);
                let ch = (bottom - top - 22.0) / rows as f32;
                for r in 0..rows {
                    for c in 0..7 {
                        let d = days_to_date(start + r * 7 + c);
                        let cell = Area::new(x + c as f32 * cw, top + 22.0 + r as f32 * ch, cw - 4.0, ch - 4.0);
                        let this_month = d.month == self.day.month;
                        let chosen = d == self.day;
                        p.fill(
                            cell,
                            6.0,
                            if chosen {
                                pal.raised
                            } else if this_month {
                                pal.well
                            } else {
                                pal.window
                            },
                        );
                        if chosen {
                            p.border(cell, 6.0, 1.5, pal.chalk);
                        }
                        let num = d.day.to_string();
                        if d == self.today {
                            // Today: the number inverted, as a selection.
                            let nw = p.measure(&name_s, &num) + 12.0;
                            let r2 = Area::new(cell.x + 4.0, cell.y + 4.0, nw.max(22.0), 20.0);
                            p.fill(r2, 10.0, pal.chalk);
                            let s = p.style(&f.medium, 12.5, pal.window);
                            p.line(&s, r2.x + (r2.w - p.measure(&s, &num)) / 2.0, r2.y, 20.0, &num);
                        } else {
                            let s = p.style(&f.medium, 12.5, if this_month { pal.text_1 } else { pal.decor });
                            p.line(&s, cell.x + 8.0, cell.y + 4.0, 20.0, &num);
                        }
                        let events = self.on(d);
                        let room = ((cell.h - 28.0) / 18.0).max(0.0) as usize;
                        let show = if events.len() > room { room.saturating_sub(1) } else { events.len() };
                        let chip = p.style(&f.regular, 11.5, pal.text_1);
                        for (k, ev) in events.iter().take(show).enumerate() {
                            let acc = accent(pal, ev.cal);
                            let r2 = Area::new(cell.x + 4.0, cell.y + 26.0 + k as f32 * 18.0, cell.w - 8.0, 16.0);
                            p.fill(r2, 4.0, acc.tint);
                            p.fill(Area::new(r2.x, r2.y, 3.0, r2.h), 1.5, acc.text);
                            let t = kit::fit(p, &chip, &ev.title, r2.w - 10.0);
                            p.line(&chip, r2.x + 7.0, r2.y - 1.0, 18.0, &t);
                        }
                        if events.len() > show {
                            let more = alloc::format!("+{} more", events.len() - show);
                            p.line(&label, cell.x + 8.0, cell.y + 26.0 + show as f32 * 18.0, 16.0, &more);
                        }
                        self.cells.push((cell, d));
                    }
                }
                // The chosen day's events.
                let px = x + gw + 16.0;
                let panel = Area::new(px, top, panel_w, bottom - top);
                p.fill(panel, 10.0, pal.well);
                let dname = alloc::format!(
                    "{} {} {}",
                    ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
                        [usize::from(weekday(self.day))],
                    self.day.day,
                    MONTHS[usize::from(self.day.month) - 1]
                );
                let dh = p.style(&f.medium, 15.0, pal.chalk);
                p.line(&dh, px + 14.0, top + 12.0, 22.0, &dname);
                let events = self.on(self.day);
                let mut y = top + 46.0;
                if events.is_empty() {
                    p.line(&small, px + 14.0, y, 18.0, "Nothing on. Press N to add something.");
                }
                for (k, ev) in events.iter().enumerate() {
                    let r = Area::new(px + 6.0, y - 4.0, panel_w - 12.0, 50.0);
                    if self.in_day == Some(k) {
                        p.fill(r, 8.0, pal.raised);
                        p.border(r, 8.0, 1.0, pal.chalk);
                    }
                    let acc = accent(pal, ev.cal);
                    p.fill(Area::new(px + 14.0, y + 2.0, 3.0, 36.0), 1.5, acc.text);
                    let when = ev.time.map_or(String::from("all day"), |(s, e)| {
                        alloc::format!("{} – {}", secs_text(s), secs_text(e))
                    });
                    p.line(&mono, px + 24.0, y, 18.0, &when);
                    let t = kit::fit(p, &name_s, &ev.title, panel_w - 40.0);
                    p.line(&name_s, px + 24.0, y + 18.0, 20.0, &t);
                    let cname = &self.calendars[ev.cal].0;
                    let cs = p.style(&f.mono, 11.0, acc.text);
                    let cw2 = p.measure(&cs, cname);
                    p.line(&cs, px + panel_w - 14.0 - cw2, y, 18.0, cname);
                    y += 54.0;
                }
                if self.confirm_delete {
                    let c = pal.accents.clay;
                    let r = Area::new(px + 6.0, bottom - 46.0, panel_w - 12.0, 40.0);
                    p.fill(r, 8.0, c.tint);
                    p.border(r, 8.0, 1.0, c.border);
                    let s = p.style(&f.medium, 12.5, c.text);
                    p.line(&s, r.x + 10.0, r.y + 10.0, 20.0, "Delete it? Press Delete again.");
                }
            }
            View::Agenda => {
                let mut y = top;
                let today = self.today;
                let mut any = false;
                for k in 0..AGENDA_DAYS {
                    let d = days_to_date(today.days() + k);
                    let events = self.on(d);
                    if events.is_empty() {
                        continue;
                    }
                    any = true;
                    if y > bottom - 40.0 {
                        break;
                    }
                    let when = if k == 0 {
                        String::from("today")
                    } else if k == 1 {
                        String::from("tomorrow")
                    } else {
                        alloc::format!(
                            "{} {} {}",
                            WEEKDAYS[iso_weekday(d)],
                            d.day,
                            &MONTHS[usize::from(d.month) - 1][..3]
                        )
                    };
                    p.line(&label, x, y + 4.0, 16.0, &when);
                    y += 22.0;
                    for ev in events {
                        if y > bottom - 22.0 {
                            break;
                        }
                        let acc = accent(pal, ev.cal);
                        p.fill(Area::new(x, y + 3.0, 3.0, 16.0), 1.5, acc.text);
                        let t = ev.time.map_or(String::from("all day"), |(s, _)| secs_text(s));
                        p.line(&mono, x + 12.0, y + 1.0, 20.0, &t);
                        p.line(&name_s, x + 80.0, y, 22.0, &ev.title);
                        let cname = &self.calendars[ev.cal].0;
                        let cs = p.style(&f.mono, 11.0, acc.text);
                        let cw2 = p.measure(&cs, cname);
                        p.line(&cs, a.x + a.w - pad - cw2, y + 2.0, 18.0, cname);
                        y += 26.0;
                    }
                    y += 8.0;
                }
                if !any {
                    p.line(&small, x, top + 8.0, 18.0, "Nothing in the next eight weeks.");
                }
            }
        }
        if !self.status.is_empty() {
            let s = p.style(&f.regular, 12.5, pal.text_3);
            p.line(&s, x, a.y + a.h - 58.0, 18.0, &self.status);
        }
        let hint: &[(&str, &str)] = match (self.view, self.in_day.is_some()) {
            (View::Month, false) => {
                &[("arrows", "day"), ("pgup pgdn", "month"), ("n", "new"), ("enter", "events"), ("tab", "agenda")]
            }
            (View::Month, true) => &[("enter", "change"), ("del", "delete"), ("esc", "back")],
            _ => &[("tab", "month"), ("n", "new"), ("ctrl e", "export")],
        };
        kit::hints(p, pal, f, a, hint);
    }

    fn key(&mut self, code: u16, ch: Option<char>, mods: u8) -> Effect {
        if self.form.is_some() {
            return self.form_key(code, ch, mods);
        }
        let ctrl = mods & CTRL != 0;
        let letter = ch.map(|c| c.to_ascii_lowercase());
        self.status.clear();
        if let Some(k) = self.in_day {
            let events = self.on(self.day);
            match code {
                KEY_UP => self.in_day = Some(k.saturating_sub(1)),
                KEY_DOWN => self.in_day = Some((k + 1).min(events.len().saturating_sub(1))),
                KEY_ESC | KEY_LEFT => {
                    self.in_day = None;
                    self.confirm_delete = false;
                }
                KEY_ENTER | KEY_KPENTER => {
                    if let Some(ev) = events.get(k) {
                        self.form = Some(self.new_form(Some((ev.cal, ev.event))));
                    }
                }
                KEY_DELETE | KEY_BACKSPACE => {
                    let Some(ev) = events.get(k) else { return Effect::None };
                    if !self.confirm_delete {
                        self.confirm_delete = true;
                        return Effect::Redraw;
                    }
                    self.confirm_delete = false;
                    let e = self.calendars[ev.cal].1.events.remove(ev.event);
                    self.save(ev.cal);
                    crate::trace!("calendar: deleted \"{}\"", e.summary);
                    self.status = alloc::format!("Deleted {}.", e.summary);
                    let n = self.on(self.day).len();
                    self.in_day = if n == 0 { None } else { Some(k.min(n - 1)) };
                }
                _ => return Effect::None,
            }
            return Effect::Redraw;
        }
        let move_days = |c: &mut Cal, n: i64| {
            c.day = days_to_date(c.day.days() + n);
        };
        match (code, letter) {
            (_, Some('e')) if ctrl => {
                let home = slate_rt::env::var(b"HOME").map(|h| String::from(slate_rt::lossy(&h))).unwrap_or_default();
                let docs = alloc::format!("{home}/Documents");
                let _ = slate_rt::fs::mkdir(docs.as_bytes(), 0o755);
                self.status = self.export(&docs);
            }
            (KEY_TAB, _) => self.view = if self.view == View::Month { View::Agenda } else { View::Month },
            (_, Some('n')) => self.form = Some(self.new_form(None)),
            (_, Some('t')) => self.day = self.today,
            (KEY_LEFT, _) => move_days(self, -1),
            (KEY_RIGHT, _) => move_days(self, 1),
            (KEY_UP, _) => move_days(self, -7),
            (KEY_DOWN, _) => move_days(self, 7),
            (KEY_PAGEUP, _) => self.day = self.day.add_months(-1),
            (KEY_PAGEDOWN, _) => self.day = self.day.add_months(1),
            (KEY_ENTER | KEY_KPENTER, _) => {
                if self.on(self.day).is_empty() {
                    self.form = Some(self.new_form(None));
                } else {
                    self.in_day = Some(0);
                }
            }
            _ => return Effect::None,
        }
        Effect::Redraw
    }

    fn click(&mut self, x: f32, y: f32) -> Effect {
        if self.form.is_some() {
            return Effect::None;
        }
        if let Some(&(_, d)) = self.cells.iter().find(|(r, _)| r.contains(x, y)) {
            self.day = d;
            self.in_day = None;
            return Effect::Redraw;
        }
        Effect::None
    }

    fn double_click(&mut self, x: f32, y: f32) -> Effect {
        self.click(x, y);
        if self.form.is_none() && self.cells.iter().any(|(r, _)| r.contains(x, y)) {
            self.form = Some(self.new_form(None));
            return Effect::Redraw;
        }
        Effect::None
    }

    fn paste(&mut self, text: &str) -> Effect {
        if let Some(f) = self.form.as_mut() {
            let field = match f.field {
                0 => &mut f.title,
                7 => &mut f.place,
                8 => &mut f.notes,
                _ => return Effect::None,
            };
            field.insert(text.lines().next().unwrap_or(""));
            return Effect::Redraw;
        }
        Effect::None
    }

    fn tick(&mut self, now: Now) -> bool {
        // Midnight moves today.
        let l = self.local.localtime(now.wall.div_euclid(1000));
        match Date::new(l.year as i32, l.month as u8, l.day as u8) {
            Some(d) if d != self.today && now.wall > 0 => {
                if self.day == self.today {
                    self.day = d;
                }
                self.today = d;
                true
            }
            _ => false,
        }
    }

    fn wake(&self, now: Now) -> Option<i64> {
        Some(60_000 - now.wall.rem_euclid(60_000))
    }
}

pub fn main() -> i32 {
    let home = slate_rt::env::var(b"HOME").map(|h| String::from(slate_rt::lossy(&h))).unwrap_or_else(|| "/".into());
    let dir = alloc::format!("{home}/.local/share/slate/calendars");
    let local = slate_rt::tz::Rule::local();
    let l = local.localtime(slate_rt::time::unix());
    let today = Date::new(l.year as i32, l.month as u8, l.day as u8).unwrap_or(Date { year: 2026, month: 1, day: 1 });
    let zones = slate_rt::fs::read_file(slate_rt::tz::ZONES).ok();
    let mut c = Cal::new(&dir, today, zones, local);
    if let Some(path) = slate_rt::env::args().get(1).map(|a| String::from(slate_rt::lossy(a))) {
        c.status = match slate_rt::fs::read_file(path.as_bytes()) {
            Ok(t) => c.import(&path, &slate_rt::lossy(&t)),
            Err(e) => alloc::format!("{path}: {e}"),
        };
    }
    kit::run("calendar", "calendar", None, Hints { min: (640, 460), size: (980, 680) }, &mut c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u8, day: u8) -> Date {
        Date::new(y, m, day).unwrap()
    }

    fn scratch(tag: &str) -> String {
        let p = std::env::temp_dir().join(alloc::format!("slate-cal-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p.to_string_lossy().into_owned()
    }

    fn zones() -> Vec<u8> {
        b"Europe/Paris CET-1CEST,M3.5.0,M10.5.0/3\nAmerica/New_York EST5EDT,M3.2.0,M11.1.0\n".to_vec()
    }

    fn typed(c: &mut Cal, s: &str) {
        for ch in s.chars() {
            match ch {
                '\t' => c.key(KEY_TAB, None, 0),
                '\n' => c.key(KEY_ENTER, None, 0),
                ch => c.key(0, Some(ch), 0),
            };
        }
    }

    const IMPORT: &str = "BEGIN:VCALENDAR\r\nX-WR-CALNAME:Work\r\nBEGIN:VEVENT\r\nUID:a@x\r\nDTSTART:20261026T080000Z\r\nDTEND:20261026T090000Z\r\nSUMMARY:Review\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:b@x\r\nDTSTART;TZID=America/New_York:20261026T230000\r\nDURATION:PT1H\r\nSUMMARY:Late call\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:c@x\r\nDTSTART;VALUE=DATE:20261030\r\nDTEND;VALUE=DATE:20261101\r\nSUMMARY:Away\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    #[test]
    fn import_zones_and_days() {
        let dir = scratch("import");
        let paris = slate_rt::tz::Rule::resolve("Europe/Paris", Some(&zones())).unwrap();
        let mut c = Cal::new(&dir, d(2026, 10, 24), Some(zones()), paris);
        assert_eq!(c.import("work.ics", IMPORT), "Imported 3 new events into Work.");
        assert_eq!(c.day, d(2026, 10, 26), "on to the first event to come");
        // 08:00 UTC is 09:00 in Paris (winter time from 25 October).
        let mon = c.on(d(2026, 10, 26));
        assert_eq!(mon.len(), 1);
        assert_eq!((mon[0].title.as_str(), mon[0].time), ("Review", Some((9 * 3600, 10 * 3600))));
        // 23:00 in New York on the 26th (summer time there until 1
        // November: 03:00 UTC) is 04:00 in Paris on the 27th.
        let tue = c.on(d(2026, 10, 27));
        assert_eq!((tue[0].title.as_str(), tue[0].time), ("Late call", Some((4 * 3600, 5 * 3600))));
        // Two whole days.
        assert_eq!(c.on(d(2026, 10, 31))[0].title, "Away");
        assert!(c.on(d(2026, 11, 1)).is_empty());
        // Saved, and read again from the folder.
        let again = Cal::new(&dir, d(2026, 10, 24), Some(zones()), slate_rt::tz::Rule::UTC);
        assert!(again.calendars.iter().any(|(n, cal)| n == "Work" && cal.events.len() == 3));
        // Imported again: replaced, not doubled.
        assert_eq!(c.import("work.ics", IMPORT), "Imported 0 new events into Work, 3 updated.");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_new_event_from_the_keyboard() {
        let dir = scratch("form");
        let mut c = Cal::new(&dir, d(2026, 10, 24), None, slate_rt::tz::Rule::UTC);
        c.key(KEY_RIGHT, None, 0);
        typed(&mut c, "n");
        // Title, date (kept), all day (no), starts, ends, repeat weekly.
        typed(&mut c, "Piano\t\t\t");
        for _ in 0..5 {
            c.key(KEY_BACKSPACE, None, 0);
        }
        typed(&mut c, "18:30\t");
        for _ in 0..5 {
            c.key(KEY_BACKSPACE, None, 0);
        }
        typed(&mut c, "19:15\t");
        c.key(KEY_RIGHT, None, 0);
        c.key(KEY_RIGHT, None, 0);
        typed(&mut c, "\n");
        assert!(c.form.is_none(), "{}", c.status);
        let sun = c.on(d(2026, 10, 25));
        assert_eq!((sun[0].title.as_str(), sun[0].time), ("Piano", Some((18 * 3600 + 1800, 19 * 3600 + 900))));
        assert_eq!(c.on(d(2026, 11, 1)).len(), 1, "every week");
        // Into the day, change it, and delete it (twice).
        c.key(KEY_ENTER, None, 0);
        assert_eq!(c.in_day, Some(0));
        c.key(KEY_DELETE, None, 0);
        assert_eq!(c.on(d(2026, 10, 25)).len(), 1, "asked first");
        c.key(KEY_DELETE, None, 0);
        assert!(c.on(d(2026, 10, 25)).is_empty() && c.in_day.is_none());
        // A bad time says so.
        typed(&mut c, "n\t\t\t");
        c.key(KEY_BACKSPACE, None, 0);
        typed(&mut c, "x\n");
        assert!(c.form.as_ref().is_some_and(|f| f.field == 3 && !f.error.is_empty()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn times_dates_and_export() {
        assert_eq!(
            (parse_time("9:30"), parse_time("0930"), parse_time("9"), parse_time("24:00")),
            (Some(34_200), Some(34_200), Some(32_400), None)
        );
        assert_eq!(parse_date("2026-02-29"), None);
        assert_eq!(utc_stamp(1_792_879_170), "20261024T215930Z");
        let dir = scratch("export");
        let mut c = Cal::new(&dir, d(2026, 10, 24), Some(zones()), slate_rt::tz::Rule::UTC);
        c.import("work.ics", IMPORT);
        std::fs::create_dir_all(format!("{dir}/out")).unwrap();
        assert!(c.export(&format!("{dir}/out")).starts_with("Exported"));
        let text = std::fs::read_to_string(format!("{dir}/out/Work.ics")).unwrap();
        assert_eq!(Calendar::parse(&text).events.len(), 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    use std::format;
}
