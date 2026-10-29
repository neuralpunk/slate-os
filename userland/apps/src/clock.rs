// SPDX-License-Identifier: MIT OR Apache-2.0

//! Clock (ADR 0104): four pages, Tab between them.
//!
//! - **World:** the time here, and in the places added (`a` adds one by
//!   name, as Settings' time zone list finds it; Delete removes).
//! - **Alarms:** times of day that ring (`a` and four digits add one;
//!   space switches the chosen one on or off; `d` goes through every
//!   day, weekdays, weekends and once, and 1 to 7 switch Monday to
//!   Sunday; Delete removes). An alarm rings in the Clock's window:
//!   Enter stops it, `s` snoozes it ten minutes. With the Clock closed,
//!   Strata opens it to ring (`clock --ring HH:MM`).
//! - **Timer:** digits set it as a microwave's do (`130` is 1:30), Enter
//!   starts and pauses it, `r` resets it; it rings when it reaches zero.
//! - **Stopwatch:** Enter starts and stops it, `l` takes a lap, `r`
//!   resets it.
//!
//! The places and the alarms are kept in `~/.config/strata/clock`
//! (the alarms' lines: `slate_strata::alarms`). Alarms ring without
//! sound (GAPS.md).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_display::input::{
    KEY_BACKSPACE, KEY_DELETE, KEY_DOWN, KEY_ENTER, KEY_ESC, KEY_KPENTER, KEY_SPACE, KEY_TAB, KEY_UP,
};
use slate_rt::time::Tm;
use slate_rt::tz::Rule;
pub use slate_strata::alarms::Alarm;
use slate_strata::fonts::Fonts;
use slate_strata_client::mods::{ALT, CTRL, LOGO, SHIFT};
use slate_ui::graphite::Palette;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;

use crate::kit::{self, App, Effect, Hints, Now};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    World,
    Alarms,
    Timer,
    Stopwatch,
}

const PAGES: [Page; 4] = [Page::World, Page::Alarms, Page::Timer, Page::Stopwatch];
const LABELS: [&str; 4] = ["world", "alarms", "timer", "stopwatch"];

/// How long a snooze is (ms).
const SNOOZE_MS: i64 = 10 * 60 * 1000;
/// The most places and alarms kept.
const MAX_ITEMS: usize = 50;

/// What is ringing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ring {
    Alarm(u8, u8),
    Timer,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Timer {
    /// The digits typed, as a microwave's (hhmmss, right-aligned).
    pub digits: String,
    /// The length set (ms) once started.
    pub total: i64,
    /// What was left when last paused or started (ms).
    pub left: i64,
    /// When it last started (monotonic ms), while running.
    pub since: Option<i64>,
}

impl Timer {
    /// The length the digits say (ms).
    fn typed(&self) -> i64 {
        let d: Vec<i64> = self.digits.chars().filter_map(|c| c.to_digit(10)).map(i64::from).collect();
        let mut six = [0i64; 6];
        for (i, v) in d.iter().rev().take(6).enumerate() {
            six[5 - i] = *v;
        }
        let (h, m, s) = (six[0] * 10 + six[1], six[2] * 10 + six[3], six[4] * 10 + six[5]);
        (h * 3600 + m * 60 + s) * 1000
    }

    pub fn remaining(&self, mono: i64) -> i64 {
        match self.since {
            Some(t) => (self.left - (mono - t)).max(0),
            None if self.total > 0 => self.left,
            None => self.typed(),
        }
    }

    fn running(&self) -> bool {
        self.since.is_some()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stopwatch {
    /// Time counted before the last start (ms).
    pub counted: i64,
    pub since: Option<i64>,
    /// The laps' total times (ms), first first.
    pub laps: Vec<i64>,
}

impl Stopwatch {
    pub fn elapsed(&self, mono: i64) -> i64 {
        self.counted + self.since.map_or(0, |t| mono - t)
    }
}

#[derive(Debug)]
pub struct Clock {
    pub page: Page,
    names: Vec<String>,
    zones: Option<Vec<u8>>,
    /// The local zone, and its name.
    local: Rule,
    pub local_name: String,
    /// The places added, by zone name.
    pub world: Vec<String>,
    pub selected: usize,
    /// Searching for a place: what is typed, and the match chosen.
    pub adding: Option<(String, usize)>,
    pub alarms: Vec<Alarm>,
    pub alarm_selected: usize,
    /// A new alarm's digits, while one is being typed.
    pub new_alarm: Option<String>,
    pub ringing: Option<Ring>,
    /// A snoozed alarm rings again then (wall ms).
    snooze: Option<(i64, Ring)>,
    pub timer: Timer,
    pub stopwatch: Stopwatch,
    /// The minute last checked for alarms (wall minutes since the epoch).
    checked: i64,
    pub now: Now,
    tabs: Vec<Area>,
    /// The rows shown: the item each is, and where.
    rows: Vec<(usize, Area)>,
    buttons: Vec<(Area, u16, Option<char>)>,
    /// Whether to write the places and alarms out.
    pub dirty: bool,
}

impl Clock {
    pub fn new(local: Rule, local_name: &str, zones: Option<Vec<u8>>) -> Clock {
        let names = zones.as_deref().map(slate_rt::tz::names).unwrap_or_default();
        Clock {
            page: Page::World,
            names,
            zones,
            local,
            local_name: String::from(local_name),
            world: Vec::new(),
            selected: 0,
            adding: None,
            alarms: Vec::new(),
            alarm_selected: 0,
            new_alarm: None,
            ringing: None,
            snooze: None,
            timer: Timer::default(),
            stopwatch: Stopwatch::default(),
            checked: i64::MIN,
            now: Now::default(),
            tabs: Vec::new(),
            rows: Vec::new(),
            buttons: Vec::new(),
            dirty: false,
        }
    }

    /// The places and alarms as the file keeps them.
    pub fn render(&self) -> String {
        let mut s = String::new();
        for z in &self.world {
            s.push_str(&alloc::format!("zone={z}\n"));
        }
        for a in &self.alarms {
            s.push_str(&alloc::format!("alarm={}\n", a.render()));
        }
        s
    }

    pub fn parse(&mut self, text: &str) {
        for line in text.lines() {
            match line.split_once('=') {
                Some(("zone", z)) if self.world.len() < MAX_ITEMS => self.world.push(String::from(z.trim())),
                Some(("alarm", a)) if self.alarms.len() < MAX_ITEMS => {
                    if let Some(al) = Alarm::parse(a) {
                        self.alarms.push(al);
                    }
                }
                _ => {}
            }
        }
    }

    fn rule(&self, zone: &str) -> Rule {
        Rule::resolve(zone, self.zones.as_deref()).unwrap_or(Rule::UTC)
    }

    pub fn local_time(&self) -> Tm {
        self.local.localtime(self.now.wall.div_euclid(1000))
    }

    fn matches(&self, q: &str) -> Vec<&str> {
        slate_strata::settings_app::matches(&self.names, q)
    }

    fn page_index(&self) -> usize {
        PAGES.iter().position(|p| *p == self.page).unwrap_or(0)
    }

    /// Alarm `i` rings; one set for once is switched off.
    pub fn ring_alarm(&mut self, i: usize) {
        let al = &mut self.alarms[i];
        self.ringing = Some(Ring::Alarm(al.hour, al.min));
        crate::trace!("clock: the alarm at {:02}:{:02} rang", al.hour, al.min);
        if al.days == slate_strata::alarms::ONCE {
            al.on = false;
            self.dirty = true;
        }
    }

    fn ring_stop(&mut self) -> Effect {
        self.ringing = None;
        Effect::Redraw
    }

    fn key_world(&mut self, code: u16, ch: Option<char>) -> Effect {
        if let Some((q, sel)) = &mut self.adding {
            match code {
                KEY_ESC => self.adding = None,
                KEY_UP => *sel = sel.saturating_sub(1),
                KEY_DOWN => *sel += 1,
                KEY_BACKSPACE => {
                    q.pop();
                    *sel = 0;
                }
                KEY_ENTER | KEY_KPENTER => {
                    let (q, sel) = (q.clone(), *sel);
                    let found: Vec<String> = self.matches(&q).into_iter().map(String::from).collect();
                    if let Some(z) = found.get(sel.min(found.len().saturating_sub(1))) {
                        if !self.world.contains(z) && self.world.len() < MAX_ITEMS {
                            self.world.push(z.clone());
                            self.selected = self.world.len() - 1;
                            self.dirty = true;
                        }
                        self.adding = None;
                    }
                }
                _ => match ch.filter(|c| !c.is_control()) {
                    Some(c) => {
                        q.push(c);
                        *sel = 0;
                    }
                    None => return Effect::None,
                },
            }
            if let Some((q, sel)) = &self.adding {
                let n = self.matches(q).len();
                let sel = (*sel).min(n.saturating_sub(1));
                self.adding = Some((q.clone(), sel));
            }
            return Effect::Redraw;
        }
        match (code, ch) {
            (_, Some('a' | '+')) => self.adding = Some((String::new(), 0)),
            (KEY_UP, _) => self.selected = self.selected.saturating_sub(1),
            (KEY_DOWN, _) => self.selected = (self.selected + 1).min(self.world.len().saturating_sub(1)),
            (KEY_DELETE | KEY_BACKSPACE, _) if self.selected < self.world.len() => {
                self.world.remove(self.selected);
                self.selected = self.selected.min(self.world.len().saturating_sub(1));
                self.dirty = true;
            }
            _ => return Effect::None,
        }
        Effect::Redraw
    }

    fn key_alarms(&mut self, code: u16, ch: Option<char>) -> Effect {
        if let Some(d) = &mut self.new_alarm {
            match (code, ch) {
                (KEY_ESC, _) => self.new_alarm = None,
                (KEY_BACKSPACE, _) => {
                    d.pop();
                }
                (KEY_ENTER | KEY_KPENTER, _) => {
                    let t = alloc::format!("{:0>4}", d);
                    match Alarm::at(&alloc::format!("{}:{}", &t[..2], &t[2..])) {
                        Some(a) if self.alarms.len() < MAX_ITEMS => {
                            self.alarms.push(a);
                            self.alarms.sort_by_key(|a| (a.hour, a.min));
                            self.alarm_selected = self.alarms.iter().position(|x| *x == a).unwrap_or(0);
                            self.new_alarm = None;
                            self.dirty = true;
                        }
                        _ => return Effect::None,
                    }
                }
                (_, Some(c)) if c.is_ascii_digit() && d.len() < 4 => d.push(c),
                _ => return Effect::None,
            }
            return Effect::Redraw;
        }
        match (code, ch) {
            (_, Some('a' | '+')) => self.new_alarm = Some(String::new()),
            (KEY_UP, _) => self.alarm_selected = self.alarm_selected.saturating_sub(1),
            (KEY_DOWN, _) => self.alarm_selected = (self.alarm_selected + 1).min(self.alarms.len().saturating_sub(1)),
            (KEY_SPACE | KEY_ENTER | KEY_KPENTER, _) if self.alarm_selected < self.alarms.len() => {
                let a = &mut self.alarms[self.alarm_selected];
                a.on = !a.on;
                self.dirty = true;
            }
            (_, Some('d')) if self.alarm_selected < self.alarms.len() => {
                self.alarms[self.alarm_selected].next_days();
                self.dirty = true;
            }
            // 1 is Monday, 7 Sunday (weekday 0).
            (_, Some(c @ '1'..='7')) if self.alarm_selected < self.alarms.len() => {
                self.alarms[self.alarm_selected].toggle_day(c as u32 - '0' as u32);
                self.dirty = true;
            }
            (KEY_DELETE | KEY_BACKSPACE, _) if self.alarm_selected < self.alarms.len() => {
                self.alarms.remove(self.alarm_selected);
                self.alarm_selected = self.alarm_selected.min(self.alarms.len().saturating_sub(1));
                self.dirty = true;
            }
            _ => return Effect::None,
        }
        Effect::Redraw
    }

    fn key_timer(&mut self, code: u16, ch: Option<char>) -> Effect {
        let mono = self.now.mono;
        let t = &mut self.timer;
        match (code, ch) {
            (KEY_ENTER | KEY_KPENTER | KEY_SPACE, _) => match t.since {
                Some(s) => {
                    t.left = (t.left - (mono - s)).max(0);
                    t.since = None;
                }
                None => {
                    if t.total == 0 {
                        t.total = t.typed();
                        t.left = t.total;
                    }
                    if t.left > 0 {
                        t.since = Some(mono);
                    }
                }
            },
            (_, Some('r')) => *t = Timer::default(),
            (KEY_BACKSPACE, _) if t.total == 0 => {
                t.digits.pop();
            }
            (_, Some(c)) if c.is_ascii_digit() && t.total == 0 && t.digits.len() < 6 => {
                if !(t.digits.is_empty() && c == '0') {
                    t.digits.push(c);
                }
            }
            _ => return Effect::None,
        }
        Effect::Redraw
    }

    fn key_stopwatch(&mut self, code: u16, ch: Option<char>) -> Effect {
        let mono = self.now.mono;
        let s = &mut self.stopwatch;
        match (code, ch) {
            (KEY_ENTER | KEY_KPENTER | KEY_SPACE, _) => match s.since {
                Some(t) => {
                    s.counted += mono - t;
                    s.since = None;
                }
                None => s.since = Some(mono),
            },
            (_, Some('l')) if s.since.is_some() => {
                let e = s.elapsed(mono);
                s.laps.push(e);
            }
            (_, Some('r')) if s.since.is_none() => *s = Stopwatch::default(),
            _ => return Effect::None,
        }
        Effect::Redraw
    }
}

/// A place's name from its zone: the last part, with spaces.
pub fn place(zone: &str) -> String {
    zone.rsplit('/').next().unwrap_or(zone).replace('_', " ")
}

/// ms as `h:mm:ss` or `mm:ss`, and with tenths if asked.
pub fn duration(ms: i64, tenths: bool) -> String {
    let ms = ms.max(0);
    let s = ms / 1000;
    let (h, m, sec) = (s / 3600, (s / 60) % 60, s % 60);
    let mut out = if h > 0 { alloc::format!("{h}:{m:02}:{sec:02}") } else { alloc::format!("{m:02}:{sec:02}") };
    if tenths {
        out.push_str(&alloc::format!(".{}", (ms % 1000) / 100));
    }
    out
}

/// The difference between two zones' offsets, as "+5:30 h" or "same time".
pub fn offset_text(theirs: i32, ours: i32) -> String {
    let d = theirs - ours;
    if d == 0 {
        return String::from("same time");
    }
    let sign = if d > 0 { '+' } else { '−' };
    let (h, m) = (d.abs() / 3600, (d.abs() % 3600) / 60);
    if m == 0 { alloc::format!("{sign}{h} h") } else { alloc::format!("{sign}{h}:{m:02} h") }
}

/// Whether a zone's date is yesterday, today or tomorrow here.
fn day_word(theirs: &Tm, ours: &Tm) -> &'static str {
    let days = |t: &Tm| slate_rt::time::civil_to_days(t.year, t.month, t.day);
    match days(theirs) - days(ours) {
        0 => "today",
        1 => "tomorrow",
        -1 => "yesterday",
        _ => "",
    }
}

impl App for Clock {
    fn draw(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area) {
        self.rows.clear();
        self.buttons.clear();
        let pad = 20.0;
        let x = a.x + pad;
        let w = a.w - 2.0 * pad;
        self.tabs = kit::tabs(p, pal, f, x - 4.0, a.y + 12.0, &LABELS, self.page_index());
        let mut y = a.y + 60.0;
        if let Some(r) = self.ringing {
            let card = Area::new(x, y, w, 64.0);
            p.fill(card, 10.0, pal.chalk);
            let title = p.style(&f.semibold, 16.0, pal.window);
            let what = match r {
                Ring::Alarm(h, m) => alloc::format!("Alarm · {h:02}:{m:02}"),
                Ring::Timer => String::from("Time's up"),
            };
            p.line(&title, x + 18.0, y + 10.0, 22.0, &what);
            let sub = p.style(&f.regular, 12.5, pal.window);
            let words = if matches!(r, Ring::Alarm(..)) { "enter to stop · s to snooze" } else { "enter to stop" };
            p.line(&sub, x + 18.0, y + 34.0, 18.0, words);
            y += 80.0;
        }
        let big = p.style(&f.mono_medium, 52.0, pal.chalk);
        let name = p.style(&f.medium, 14.0, pal.text_1);
        let desc = p.style(&f.regular, 12.5, pal.muted);
        let mono = p.style(&f.mono, 13.0, pal.text_3);
        let label = p.style(&f.mono, 11.0, pal.muted);
        let ghost = p.style(&f.regular, 13.5, pal.muted);
        let local = self.local_time();
        match self.page {
            Page::World => {
                let hm = alloc::format!("{:02}:{:02}", local.hour, local.min);
                let end = p.line(&big, x, y, 64.0, &hm);
                let secs = p.style(&f.mono, 20.0, pal.text_3);
                p.line(&secs, x + end + 6.0, y + 26.0, 30.0, &alloc::format!("{:02}", local.sec));
                y += 66.0;
                let date = alloc::format!(
                    "{} {} {} · {}",
                    slate_rt::time::FULL_DAYS[local.weekday as usize % 7],
                    local.day,
                    slate_rt::time::FULL_MONTHS[(local.month as usize).saturating_sub(1) % 12],
                    place(&self.local_name)
                );
                p.line(&desc, x, y, 18.0, &date);
                y += 34.0;
                if let Some((q, sel)) = &self.adding {
                    let field = Area::new(x, y, w, 40.0);
                    p.fill(field, 8.0, pal.well);
                    p.border(field, 8.0, 1.0, pal.field_focus);
                    let typed = p.style(&f.regular, 14.0, pal.text_1);
                    if q.is_empty() {
                        p.line(&ghost, x + 14.0, y + 10.0, 20.0, "Type a city or region");
                    } else {
                        let e = p.line(&typed, x + 14.0, y + 10.0, 20.0, q);
                        p.fill(Area::new(x + 15.0 + e, y + 10.0, 1.5, 20.0), 0.0, pal.chalk);
                    }
                    y += 50.0;
                    let room = ((a.y + a.h - 50.0 - y) / 30.0).max(1.0) as usize;
                    let found = self.matches(q);
                    let first = sel.saturating_sub(room.saturating_sub(1));
                    for (i, z) in found.iter().enumerate().skip(first).take(room) {
                        let r = Area::new(x - 8.0, y, w + 16.0, 28.0);
                        if i == *sel {
                            p.fill(r, 6.0, pal.raised);
                        }
                        p.line(&name, x, y + 4.0, 20.0, z);
                        y += 30.0;
                    }
                    if found.is_empty() {
                        p.line(&ghost, x, y + 4.0, 20.0, "No place by that name");
                    }
                } else {
                    p.line(&label, x, y, 16.0, "places");
                    y += 24.0;
                    if self.world.is_empty() {
                        p.line(&ghost, x, y + 6.0, 20.0, "Press A to add a place.");
                    }
                    let ours = self.local.at(self.now.wall.div_euclid(1000)).0;
                    let room = ((a.y + a.h - 50.0 - y) / 56.0).max(1.0) as usize;
                    let first = self.selected.saturating_sub(room - 1);
                    for (i, z) in self.world.iter().enumerate().skip(first).take(room) {
                        let r = Area::new(x - 10.0, y, w + 20.0, 52.0);
                        if i == self.selected {
                            p.fill(r, 8.0, pal.raised);
                        }
                        let rule = self.rule(z);
                        let t = self.now.wall.div_euclid(1000);
                        let tm = rule.localtime(t);
                        p.line(&name, x, y + 7.0, 20.0, &place(z));
                        let day = day_word(&tm, &local);
                        let off = offset_text(rule.at(t).0, ours);
                        let sub = if day.is_empty() || day == "today" { off } else { alloc::format!("{off}, {day}") };
                        p.line(&desc, x, y + 28.0, 18.0, &sub);
                        let time = alloc::format!("{:02}:{:02}", tm.hour, tm.min);
                        let tstyle = p.style(&f.mono_medium, 20.0, pal.text_1);
                        let tw = p.measure(&tstyle, &time);
                        p.line(&tstyle, x + w - tw, y + 12.0, 28.0, &time);
                        self.rows.push((i, r));
                        y += 56.0;
                    }
                }
                let hint: &[(&str, &str)] = if self.adding.is_some() {
                    &[("enter", "add"), ("esc", "cancel")]
                } else {
                    &[("a", "add a place"), ("del", "remove"), ("tab", "alarms")]
                };
                kit::hints(p, pal, f, a, hint);
            }
            Page::Alarms => {
                if let Some(d) = &self.new_alarm {
                    let t = alloc::format!("{:-<4}", alloc::format!("{:0>w$}", d, w = d.len()));
                    let shown = alloc::format!("{}:{}", &t[..2], &t[2..]);
                    p.line(&label, x, y, 16.0, "new alarm");
                    y += 22.0;
                    let field = Area::new(x, y, w, 76.0);
                    p.fill(field, 10.0, pal.well);
                    p.border(field, 10.0, 1.0, pal.field_focus);
                    p.line(&big, x + 18.0, y + 6.0, 64.0, &shown);
                    y += 90.0;
                    p.line(&desc, x, y, 18.0, "Type the hour and the minutes, as 0730.");
                } else {
                    p.line(&label, x, y, 16.0, "alarms");
                    y += 24.0;
                    if self.alarms.is_empty() {
                        p.line(&ghost, x, y + 6.0, 20.0, "No alarms. Press A to add one.");
                    }
                    let room = ((a.y + a.h - 50.0 - y) / 60.0).max(1.0) as usize;
                    let first = self.alarm_selected.saturating_sub(room - 1);
                    for (i, al) in self.alarms.iter().enumerate().skip(first).take(room) {
                        let r = Area::new(x - 10.0, y, w + 20.0, 56.0);
                        if i == self.alarm_selected {
                            p.fill(r, 8.0, pal.raised);
                        }
                        let t = p.style(&f.mono_medium, 26.0, if al.on { pal.chalk } else { pal.text_4 });
                        let tw = p.line(&t, x, y + 10.0, 36.0, &alloc::format!("{:02}:{:02}", al.hour, al.min));
                        p.line(&desc, x + tw + 16.0, y + 19.0, 18.0, &al.days_text());
                        switch(p, pal, x + w - 36.0, y + 19.0, al.on);
                        self.rows.push((i, r));
                        y += 60.0;
                    }
                }
                let hint: &[(&str, &str)] = if self.new_alarm.is_some() {
                    &[("enter", "save"), ("esc", "cancel")]
                } else {
                    &[("a", "add"), ("space", "on/off"), ("d", "days"), ("del", "remove")]
                };
                kit::hints(p, pal, f, a, hint);
            }
            Page::Timer => {
                let left = self.timer.remaining(self.now.mono);
                let total = if self.timer.total > 0 { self.timer.total } else { left };
                let cx = x + w / 2.0;
                let r = ((a.h - 260.0).min(w) / 2.0).clamp(60.0, 120.0);
                let cy = y + r + 10.0;
                ring(p, cx, cy, r, 1.0, pal.raised);
                if total > 0 && self.timer.total > 0 {
                    ring(p, cx, cy, r, left as f32 / total as f32, pal.chalk);
                }
                let text = duration(left.div_euclid(1000) * 1000 + if left % 1000 > 0 { 1000 } else { 0 }, false);
                let tw = p.measure(&big, &text);
                p.line(&big, cx - tw / 2.0, cy - 32.0, 64.0, &text);
                let state = match (self.timer.running(), self.timer.total > 0) {
                    (true, _) => "running",
                    (false, true) => "paused",
                    _ if self.timer.digits.is_empty() => "type the time",
                    _ => "ready",
                };
                let sw = p.measure(&mono, state);
                p.line(&mono, cx - sw / 2.0, cy + 34.0, 18.0, state);
                y = cy + r + 22.0;
                let bw = 120.0;
                let start = Area::new(cx - bw - 6.0, y, bw, 40.0);
                let reset = Area::new(cx + 6.0, y, bw, 40.0);
                kit::button(p, pal, f, start, if self.timer.running() { "Pause" } else { "Start" }, true, false);
                kit::button(p, pal, f, reset, "Reset", false, false);
                self.buttons.push((start, KEY_ENTER, None));
                self.buttons.push((reset, 0, Some('r')));
                kit::hints(p, pal, f, a, &[("0-9", "set"), ("enter", "start/pause"), ("r", "reset")]);
            }
            Page::Stopwatch => {
                let e = self.stopwatch.elapsed(self.now.mono);
                let text = duration(e, true);
                let tw = p.measure(&big, &text);
                let cx = x + w / 2.0;
                p.line(&big, cx - tw / 2.0, y + 10.0, 64.0, &text);
                y += 96.0;
                let bw = 120.0;
                let running = self.stopwatch.since.is_some();
                let start = Area::new(cx - bw - 6.0, y, bw, 40.0);
                let other = Area::new(cx + 6.0, y, bw, 40.0);
                kit::button(p, pal, f, start, if running { "Stop" } else { "Start" }, true, false);
                kit::button(p, pal, f, other, if running { "Lap" } else { "Reset" }, false, false);
                self.buttons.push((start, KEY_ENTER, None));
                self.buttons.push((other, 0, Some(if running { 'l' } else { 'r' })));
                y += 60.0;
                let room = ((a.y + a.h - 50.0 - y) / 26.0).max(0.0) as usize;
                for (i, total) in self.stopwatch.laps.iter().enumerate().rev().take(room) {
                    let prev = if i == 0 { 0 } else { self.stopwatch.laps[i - 1] };
                    p.line(&desc, x, y + 3.0, 20.0, &alloc::format!("lap {}", i + 1));
                    let lap = duration(total - prev, true);
                    let lw = p.measure(&mono, &lap);
                    p.line(&mono, cx - lw / 2.0, y + 3.0, 20.0, &lap);
                    let all = duration(*total, true);
                    let aw = p.measure(&mono, &all);
                    p.line(&mono, x + w - aw, y + 3.0, 20.0, &all);
                    y += 26.0;
                }
                kit::hints(p, pal, f, a, &[("enter", "start/stop"), ("l", "lap"), ("r", "reset")]);
            }
        }
    }

    fn key(&mut self, code: u16, ch: Option<char>, mods: u8) -> Effect {
        if mods & (CTRL | ALT | LOGO) != 0 {
            return Effect::None;
        }
        let ch = ch.map(|c| c.to_ascii_lowercase());
        if let Some(r) = self.ringing {
            return match (code, ch) {
                (KEY_ENTER | KEY_KPENTER | KEY_ESC | KEY_SPACE, _) => self.ring_stop(),
                (_, Some('s')) if matches!(r, Ring::Alarm(..)) => {
                    self.snooze = Some((self.now.wall + SNOOZE_MS, r));
                    self.ring_stop()
                }
                _ => Effect::None,
            };
        }
        let editing = self.adding.is_some() || self.new_alarm.is_some();
        if code == KEY_TAB && !editing {
            let i = self.page_index();
            let next = if mods & SHIFT != 0 { (i + 3) % 4 } else { (i + 1) % 4 };
            self.page = PAGES[next];
            return Effect::Redraw;
        }
        match self.page {
            Page::World => self.key_world(code, ch),
            Page::Alarms => self.key_alarms(code, ch),
            Page::Timer => self.key_timer(code, ch),
            Page::Stopwatch => self.key_stopwatch(code, ch),
        }
    }

    fn click(&mut self, x: f32, y: f32) -> Effect {
        if let Some(i) = self.tabs.iter().position(|a| a.contains(x, y)) {
            self.page = PAGES[i];
            self.adding = None;
            self.new_alarm = None;
            return Effect::Redraw;
        }
        if let Some(&(_, code, ch)) = self.buttons.iter().find(|(a, ..)| a.contains(x, y)) {
            return self.key(code, ch, 0);
        }
        if let Some(&(i, r)) = self.rows.iter().find(|(_, a)| a.contains(x, y)) {
            match self.page {
                Page::World => self.selected = i,
                Page::Alarms => {
                    // A click on the switch flips it.
                    if self.alarm_selected == i || x > r.x + r.w - 60.0 {
                        self.alarms[i].on = !self.alarms[i].on;
                        self.dirty = true;
                    }
                    self.alarm_selected = i;
                }
                _ => {}
            }
            return Effect::Redraw;
        }
        Effect::None
    }

    fn tick(&mut self, now: Now) -> bool {
        self.now = now;
        let mut changed = false;
        if self.dirty {
            self.dirty = false;
            if let Err(e) = kit::save_config("clock", &self.render()) {
                slate_rt::eprintln!("clock: saving the places and alarms: {e}");
            }
        }
        // The timer reaching zero.
        if self.timer.running() && self.timer.remaining(now.mono) == 0 {
            self.timer = Timer::default();
            self.ringing = Some(Ring::Timer);
            crate::trace!("clock: the timer rang");
            changed = true;
        }
        // Alarms, once a minute (the first look only notes the minute).
        let minute = now.wall.div_euclid(60_000);
        if minute != self.checked {
            let first = self.checked == i64::MIN;
            self.checked = minute;
            let t = self.local_time();
            if !first && let Some(i) = self.alarms.iter().position(|a| a.rings(&t)) {
                self.ring_alarm(i);
                changed = true;
            }
        }
        if let Some((when, r)) = self.snooze
            && now.wall >= when
        {
            self.snooze = None;
            self.ringing = Some(r);
            changed = true;
        }
        changed
    }

    fn wake(&self, now: Now) -> Option<i64> {
        let to_second = 1000 - now.wall.rem_euclid(1000);
        let mut w = match self.page {
            Page::World => Some(to_second),
            Page::Stopwatch if self.stopwatch.since.is_some() => Some(100),
            Page::Timer if self.timer.running() => Some((self.timer.remaining(now.mono) % 1000).clamp(1, 250)),
            _ => None,
        };
        // Alarms, snoozes and a running timer are watched on every page.
        let to_minute = 60_000 - now.wall.rem_euclid(60_000);
        if self.alarms.iter().any(|a| a.on) || self.snooze.is_some() {
            w = Some(w.map_or(to_minute, |x| x.min(to_minute)));
        }
        if self.timer.running() {
            let left = self.timer.remaining(now.mono).max(1);
            w = Some(w.map_or(left, |x| x.min(left)));
        }
        w
    }
}

/// A ring of `fraction` of a circle, clockwise from the top.
fn ring(p: &mut Painter<'_>, cx: f32, cy: f32, r: f32, fraction: f32, c: slate_ui::Color) {
    let n = (slate_ui::math::ceil(96.0 * fraction) as usize).max(1);
    let pts: Vec<(f32, f32)> = (0..=n)
        .map(|i| {
            let a = core::f32::consts::TAU * fraction * i as f32 / n as f32;
            (cx + r * slate_math::sin_(f64::from(a)) as f32, cy - r * slate_math::cos_(f64::from(a)) as f32)
        })
        .collect();
    p.polyline(&pts, 6.0, c);
}

/// An on/off switch, as Settings draws it.
fn switch(p: &mut Painter<'_>, pal: &Palette, x: f32, y: f32, on: bool) {
    let track = Area::new(x, y, 36.0, 20.0);
    p.fill(track, 10.0, if on { pal.chalk } else { pal.raised });
    let knob = Area::new(if on { x + 18.0 } else { x + 2.0 }, y + 2.0, 16.0, 16.0);
    p.fill(knob, 8.0, if on { pal.window } else { pal.text_4 });
}

pub fn main() -> i32 {
    let zones = slate_rt::fs::read_file(slate_rt::tz::ZONES).ok();
    let name = slate_rt::fs::read_file(slate_rt::tz::SETTING)
        .ok()
        .map(|s| String::from(slate_rt::lossy(&s).lines().next().unwrap_or("UTC").trim()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "UTC".to_string());
    let mut c = Clock::new(Rule::local(), &name, zones);
    if let Some(text) = kit::load_config("clock") {
        c.parse(&text);
    }
    // Strata opens the Clock to ring an alarm when it isn't running.
    let args = slate_rt::env::args();
    if args.get(1).is_some_and(|a| a == b"--ring")
        && let Some(at) = args.get(2).and_then(|a| Alarm::at(&slate_rt::lossy(a)))
    {
        c.page = Page::Alarms;
        match c.alarms.iter().position(|a| (a.hour, a.min) == (at.hour, at.min) && a.on) {
            Some(i) => {
                c.alarm_selected = i;
                c.ring_alarm(i);
            }
            None => c.ringing = Some(Ring::Alarm(at.hour, at.min)),
        }
    }
    kit::run("clock", "clock", None, Hints { min: (360, 420), size: (420, 560) }, &mut c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zones() -> Vec<u8> {
        b"Europe/Paris CET-1CEST,M3.5.0,M10.5.0/3\nAsia/Kolkata IST-5:30\nAmerica/New_York EST5EDT,M3.2.0,M11.1.0\n"
            .to_vec()
    }

    fn clock() -> Clock {
        let mut c = Clock::new(Rule::UTC, "UTC", Some(zones()));
        // Saturday 24 October 2026, 21:59:30 UTC.
        c.tick(Now { wall: 1_792_879_170_000, mono: 1_000 });
        c
    }

    fn keys(c: &mut Clock, s: &str) {
        for ch in s.chars() {
            match ch {
                '\n' => c.key(KEY_ENTER, None, 0),
                '\t' => c.key(KEY_TAB, None, 0),
                _ => c.key(0, Some(ch), 0),
            };
        }
    }

    #[test]
    fn places() {
        let mut c = clock();
        keys(&mut c, "akolk\n");
        keys(&mut c, "anew york\n");
        assert_eq!(c.world, ["Asia/Kolkata", "America/New_York"]);
        let t = c.now.wall / 1000;
        let k = c.rule("Asia/Kolkata");
        assert_eq!(offset_text(k.at(t).0, 0), "+5:30 h");
        assert_eq!(day_word(&k.localtime(t), &c.local_time()), "tomorrow");
        assert_eq!(offset_text(c.rule("America/New_York").at(t).0, 0), "−4 h");
        c.key(KEY_DELETE, None, 0);
        assert_eq!(c.world, ["Asia/Kolkata"]);
        assert!(c.dirty);
        assert_eq!(place("America/New_York"), "New York");
        // Kept and read back.
        let mut d = clock();
        c.alarms.push(Alarm { on: false, ..Alarm::at("07:30").unwrap() });
        c.alarms.push(Alarm { days: slate_strata::alarms::WEEKDAYS, ..Alarm::at("06:45").unwrap() });
        d.parse(&c.render());
        assert_eq!((d.world, d.alarms), (c.world.clone(), c.alarms.clone()));
    }

    #[test]
    fn alarms_ring_and_snooze() {
        let mut c = clock();
        keys(&mut c, "\ta2200\n");
        assert_eq!(c.alarms, [Alarm::at("22:00").unwrap()]);
        keys(&mut c, "a99\n");
        assert_eq!(c.new_alarm.as_deref(), Some("99"), "09:9 is no time");
        c.key(KEY_ESC, None, 0);
        // 22:00:00 comes.
        assert!(c.tick(Now { wall: 1_792_879_200_000, mono: 31_000 }));
        assert_eq!(c.ringing, Some(Ring::Alarm(22, 0)));
        keys(&mut c, "s");
        assert_eq!(c.ringing, None);
        assert!(!c.tick(Now { wall: 1_792_879_500_000, mono: 331_000 }));
        assert!(c.tick(Now { wall: 1_792_879_800_000, mono: 631_000 }));
        assert_eq!(c.ringing, Some(Ring::Alarm(22, 0)));
        c.key(KEY_ENTER, None, 0);
        assert_eq!(c.ringing, None);
        // Off, it stays quiet the next day.
        c.key(KEY_SPACE, None, 0);
        assert!(!c.alarms[0].on);
        assert!(!c.tick(Now { wall: 1_792_879_200_000 + 86_400_000, mono: 87_000_000 }));
    }

    #[test]
    fn alarm_days() {
        // Saturday 24 October 2026, 21:59:30 UTC.
        let mut c = clock();
        keys(
            &mut c, "	a2200
d",
        );
        assert_eq!(c.alarms[0].days_text(), "weekdays");
        assert!(!c.tick(Now { wall: 1_792_879_200_000, mono: 31_000 }), "not on a Saturday");
        // Saturday switched on (6), then Monday off (1).
        keys(&mut c, "61");
        assert_eq!(c.alarms[0].days_text(), "Tue Wed Thu Fri Sat");
        assert!(c.render().contains("alarm=22:00 on tue wed thu fri sat"));
        // Once (from chosen days: every day, weekdays, weekends, once):
        // it rings, and then it is off.
        keys(&mut c, "dddd");
        let mut d = clock();
        d.parse(&c.render());
        d.page = Page::Alarms;
        assert_eq!(d.alarms[0].days_text(), "once");
        assert!(d.tick(Now { wall: 1_792_879_200_000, mono: 31_000 }));
        assert_eq!((d.ringing, d.alarms[0].on, d.dirty), (Some(Ring::Alarm(22, 0)), false, true));
    }

    #[test]
    fn timer_and_stopwatch() {
        let mut c = clock();
        keys(&mut c, "\t\t0130");
        assert_eq!(c.timer.remaining(1_000), 90_000);
        c.key(KEY_ENTER, None, 0);
        c.tick(Now { wall: c.now.wall + 30_000, mono: 31_000 });
        assert_eq!(c.timer.remaining(31_000), 60_000);
        c.key(KEY_ENTER, None, 0);
        assert_eq!(c.timer.remaining(50_000), 60_000, "paused");
        c.tick(Now { wall: c.now.wall + 1000, mono: 50_000 });
        c.key(KEY_ENTER, None, 0);
        assert!(c.tick(Now { wall: c.now.wall + 60_000, mono: 110_000 }));
        assert_eq!(c.ringing, Some(Ring::Timer));
        c.key(KEY_ENTER, None, 0);
        // The stopwatch.
        keys(&mut c, "\t");
        assert_eq!(c.page, Page::Stopwatch);
        c.tick(Now { wall: c.now.wall, mono: 200_000 });
        c.key(KEY_ENTER, None, 0);
        c.tick(Now { wall: c.now.wall, mono: 212_340 });
        keys(&mut c, "l");
        c.tick(Now { wall: c.now.wall, mono: 215_000 });
        c.key(KEY_ENTER, None, 0);
        assert_eq!((c.stopwatch.laps.clone(), c.stopwatch.elapsed(999_999)), (std::vec![12_340], 15_000));
        assert_eq!(duration(12_340, true), "00:12.3");
        assert_eq!(duration(3_723_000, false), "1:02:03");
        keys(&mut c, "r");
        assert_eq!(c.stopwatch, Stopwatch::default());
    }
}
