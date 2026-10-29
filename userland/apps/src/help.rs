// SPDX-License-Identifier: MIT OR Apache-2.0

//! Help and About this system (ADR 0104), `slate-help`: two pages, Tab
//! between them.
//!
//! - **About this system:** Slate's release, the kernel, the computer's
//!   name, its processor, memory and disks, and how long it has been up,
//!   from /usr/share/slate/release, uname, /proc and /sys/block. ctrl + c
//!   copies it all as text, for a bug report.
//! - **Guides:** the user guides in /usr/share/doc/slate/guides (Markdown,
//!   each titled by its first heading). Typing searches them (titles and
//!   text); Enter opens one, at the first match with the matches marked;
//!   the arrows, Page Up and Down, Home, End and the wheel scroll it; Tab
//!   goes from link to link, Enter or a click follows one; Esc goes back.
//!
//! Guides are read as a part of Markdown: headings, paragraphs, lists,
//! code blocks, rules and tables, with `code` and **bold** shown as their
//! text and [links](url) in the links' colour. A link to another guide
//! (`installing.md`) opens it; a web address is copied, to paste in the
//! browser (Slate's apps can't open one there yet, GAPS.md).

use alloc::string::String;
use alloc::vec::Vec;

use slate_display::input::{
    KEY_BACKSPACE, KEY_DOWN, KEY_END, KEY_ENTER, KEY_ESC, KEY_HOME, KEY_KPENTER, KEY_PAGEDOWN, KEY_PAGEUP, KEY_TAB,
    KEY_UP,
};
use slate_strata::fonts::Fonts;
use slate_strata_client::mods::{CTRL, SHIFT};
use slate_ui::graphite::Palette;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;

use crate::kit::{self, App, Effect, Hints};

pub const GUIDES: &str = "/usr/share/doc/slate/guides";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Guide {
    pub title: String,
    /// Its file's name, which links to it use.
    pub file: String,
    pub text: String,
}

impl Guide {
    pub fn new(text: &str, file: &str) -> Guide {
        let title = text
            .lines()
            .find_map(|l| l.strip_prefix("# "))
            .map(|t| inline(t.trim()))
            .unwrap_or_else(|| file.trim_end_matches(".md").replace('-', " "));
        Guide { title, file: String::from(file), text: String::from(text) }
    }

    /// Whether the title or the text holds `q` (any case).
    pub fn holds(&self, q: &str) -> bool {
        let q = q.to_lowercase();
        self.title.to_lowercase().contains(&q) || self.text.to_lowercase().contains(&q)
    }
}

/// A part of a guide.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Block {
    Heading(u8, String),
    Para(String),
    /// A list item, and how deep it is (0 at the margin).
    Item(usize, String),
    Code(Vec<String>),
    Rule,
    /// A table's rows, the header first.
    Table(Vec<Vec<String>>),
}

/// Markdown's inline marks taken out: `code`, **bold**, *emphasis*,
/// [text](link) (as its text).
pub fn inline(s: &str) -> String {
    let mut out = String::new();
    let c: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            '`' | '*' => i += 1,
            '_' if c.get(i + 1) == Some(&'_') => i += 2,
            '[' => {
                // [text](link): the text.
                let close = c[i..].iter().position(|&x| x == ']').map(|p| p + i);
                match close {
                    Some(j) if c.get(j + 1) == Some(&'(') => {
                        let end = c[j..].iter().position(|&x| x == ')').map_or(c.len(), |p| p + j);
                        out.extend(&c[i + 1..j]);
                        i = end + 1;
                    }
                    _ => {
                        out.push('[');
                        i += 1;
                    }
                }
            }
            ch => {
                out.push(ch);
                i += 1;
            }
        }
    }
    out
}

/// The links in a guide's text, in order: (text, where to).
pub fn links(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut in_code = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            in_code = !in_code;
            continue;
        }
        if in_code {
            continue;
        }
        let mut rest = line;
        while let Some(open) = rest.find('[') {
            let after = &rest[open + 1..];
            let Some(close) = after.find("](") else { break };
            let Some(end) = after[close + 2..].find(')') else { break };
            out.push((inline(&after[..close]), String::from(&after[close + 2..close + 2 + end])));
            rest = &after[close + 2 + end + 1..];
        }
    }
    out
}

/// A table row's cells (`| a | b |`); None for the line under the header
/// (`|---|:---:|`).
fn cells(t: &str) -> Option<Vec<String>> {
    let inner = t.trim().trim_start_matches('|').trim_end_matches('|');
    if inner.chars().all(|c| matches!(c, '-' | ':' | '|' | ' ')) {
        return None;
    }
    Some(inner.split('|').map(|c| inline(c.trim())).collect())
}

/// A guide's text as blocks.
pub fn blocks(text: &str) -> Vec<Block> {
    let mut out = Vec::new();
    let mut para = String::new();
    let mut code: Option<Vec<String>> = None;
    let flush = |para: &mut String, out: &mut Vec<Block>| {
        if !para.is_empty() {
            out.push(Block::Para(inline(para)));
            para.clear();
        }
    };
    for line in text.lines() {
        if let Some(lines) = &mut code {
            if line.trim_start().starts_with("```") {
                out.push(Block::Code(code.take().unwrap_or_default()));
            } else {
                lines.push(line.replace('\t', "    "));
            }
            continue;
        }
        let t = line.trim();
        if t.starts_with('|') {
            flush(&mut para, &mut out);
            match (out.last_mut(), cells(t)) {
                (Some(Block::Table(rows)), Some(r)) => rows.push(r),
                (Some(Block::Table(_)), None) => {}
                (_, Some(r)) => out.push(Block::Table(alloc::vec![r])),
                (_, None) => {}
            }
            continue;
        }
        if t.starts_with("```") {
            flush(&mut para, &mut out);
            code = Some(Vec::new());
        } else if t.is_empty() {
            flush(&mut para, &mut out);
        } else if let Some(h) = t.strip_prefix('#') {
            flush(&mut para, &mut out);
            let level = 1 + h.chars().take_while(|&c| c == '#').count() as u8;
            out.push(Block::Heading(level, inline(h.trim_start_matches('#').trim())));
        } else if t == "---" || t == "***" {
            flush(&mut para, &mut out);
            out.push(Block::Rule);
        } else if let Some(item) = t.strip_prefix("- ").or_else(|| t.strip_prefix("* ")).or_else(|| numbered(t)) {
            flush(&mut para, &mut out);
            let depth = (line.len() - line.trim_start().len()) / 2;
            out.push(Block::Item(depth, inline(item)));
        } else if let Some(Block::Item(_, text)) = out.last_mut().filter(|_| para.is_empty() && line.starts_with("  "))
        {
            // A list item's text going on to the next line.
            text.push(' ');
            text.push_str(&inline(t));
        } else {
            if !para.is_empty() {
                para.push(' ');
            }
            para.push_str(t);
        }
    }
    flush(&mut para, &mut out);
    if let Some(lines) = code {
        out.push(Block::Code(lines));
    }
    out
}

/// "3. text" as "text" (numbered list items read as bullets).
fn numbered(t: &str) -> Option<&str> {
    let digits = t.chars().take_while(char::is_ascii_digit).count();
    (digits > 0).then(|| t[digits..].strip_prefix(". ")).flatten()
}

pub use slate_sysinfo::{about, kernel, memory, processor, size, uptime};

/// The guides in `dir`, by title.
pub fn guides(dir: &str) -> Vec<Guide> {
    let Ok(entries) = slate_rt::fs::read_dir(dir.as_bytes()) else { return Vec::new() };
    let mut out: Vec<Guide> = entries
        .iter()
        .map(|e| String::from(slate_rt::lossy(&e.name)))
        .filter(|n| n.ends_with(".md"))
        .filter_map(|n| {
            let text = slate_rt::fs::read_file(alloc::format!("{dir}/{n}").as_bytes()).ok()?;
            Some(Guide::new(&slate_rt::lossy(&text), &n))
        })
        .collect();
    out.sort_by(|a, b| a.title.cmp(&b.title));
    out
}

/// What a guide's text shows apart: its links (the one chosen, the
/// places they were drawn) and a search's matches.
struct Marks<'a> {
    links: &'a [(String, String)],
    /// The next link to look for, and the rest of one that went on to the
    /// next line.
    next: usize,
    rest: Option<(usize, String)>,
    focus: Option<usize>,
    find: Option<String>,
    hits: Vec<(Area, usize)>,
    /// Where each link was drawn (from the guide's top).
    at: Vec<f32>,
    /// Where the first match was drawn.
    first_match: Option<f32>,
}

#[derive(Debug, Default)]
pub struct Help {
    /// 0: About this system, 1: Guides.
    pub page: usize,
    pub about: Vec<(String, String)>,
    pub guides: Vec<Guide>,
    pub selected: usize,
    /// The guide open, and how far down it is scrolled (logical px).
    pub reading: Option<(usize, f32)>,
    /// How far a guide can scroll (from the last frame), and a page.
    max_scroll: f32,
    page_h: f32,
    tabs: Vec<Area>,
    /// The guides' rows: the guide each is, and where.
    rows: Vec<(usize, Area)>,
    back: Option<Area>,
    /// What is typed to search the guides.
    pub query: Option<String>,
    /// The words marked in the guide open (the search's), and whether to
    /// scroll to the first.
    find: Option<(String, bool)>,
    /// The link chosen in the guide open.
    pub link: Option<usize>,
    /// Where the links were drawn (and, from the guide's top, each one).
    link_hits: Vec<(Area, usize)>,
    link_at: Vec<f32>,
    /// The guides read before the one open, for Esc to go back to.
    trail: Vec<(usize, f32)>,
    /// A word in the hints' place (a web address copied).
    pub notice: Option<&'static str>,
    /// Drawn scrolled to a search's first match: draw again from there.
    again: bool,
}

impl Help {
    pub fn about_text(&self) -> String {
        self.about.iter().map(|(k, v)| alloc::format!("{k}: {v}\n")).collect()
    }

    fn scroll_by(&mut self, dy: f32) -> Effect {
        let max = self.max_scroll;
        match &mut self.reading {
            Some((_, s)) => {
                let new = (*s + dy).clamp(0.0, max);
                if new == *s {
                    return Effect::None;
                }
                *s = new;
                Effect::Redraw
            }
            None => Effect::None,
        }
    }

    /// The guides shown on the guides page: those the search finds.
    pub fn shown(&self) -> Vec<usize> {
        (0..self.guides.len()).filter(|&i| self.query.as_ref().is_none_or(|q| self.guides[i].holds(q))).collect()
    }

    /// Open guide `g` (from a link: after the one open).
    fn open(&mut self, g: usize, from_link: bool) {
        if from_link && let Some(r) = self.reading {
            self.trail.push(r);
        }
        crate::trace!("slate-help: reading \"{}\"", self.guides[g].title);
        self.reading = Some((g, 0.0));
        self.link = None;
        self.max_scroll = f32::MAX;
    }

    /// Follow link `i` of the guide open.
    fn follow(&mut self, i: usize) -> Effect {
        let Some((g, _)) = self.reading else { return Effect::None };
        let Some((_, to)) = links(&self.guides[g].text).get(i).cloned() else { return Effect::None };
        let file = to.split('#').next().unwrap_or("").rsplit('/').next().unwrap_or("");
        if let Some(t) = self.guides.iter().position(|x| !file.is_empty() && x.file.eq_ignore_ascii_case(file)) {
            self.find = None;
            self.open(t, true);
            return Effect::Redraw;
        }
        if to.starts_with("http://") || to.starts_with("https://") {
            crate::trace!("slate-help: copied {to}");
            self.notice = Some("Link copied: paste it in the browser.");
            return Effect::Copy(to);
        }
        Effect::None
    }

    /// Back from a guide: to the one a link came from, else the list.
    fn back(&mut self) -> Effect {
        self.reading = self.trail.pop();
        self.link = None;
        self.max_scroll = f32::MAX;
        Effect::Redraw
    }

    fn draw_guide(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area, g: usize, scroll: f32) {
        let pad = 28.0;
        let x = a.x + pad;
        let w = (a.w - 2.0 * pad).min(720.0);
        let top = a.y + 56.0;
        let bottom = a.y + a.h - 40.0;
        let back = Area::new(a.x + 16.0, a.y + 14.0, 28.0, 28.0);
        p.icon(slate_ui::icon::Icon::ChevronLeft, back.x + 6.0, back.y + 6.0, 16.0, pal.text_3);
        self.back = Some(back);
        let title = p.style(&f.medium, 14.0, pal.chalk);
        p.line(&title, a.x + 50.0, a.y + 18.0, 20.0, &self.guides[g].title);
        let clip = p.clip(Area::new(a.x, top, a.w, bottom - top));
        let mut y = top + 8.0 - scroll;
        let all = links(&self.guides[g].text);
        let mut m = Marks {
            links: &all,
            next: 0,
            rest: None,
            focus: self.link,
            find: self.find.as_ref().map(|(q, _)| q.to_lowercase()),
            hits: Vec::new(),
            at: alloc::vec![0.0; all.len()],
            first_match: None,
        };
        let origin = top + 8.0 - scroll;
        for b in blocks(&self.guides[g].text) {
            match b {
                Block::Heading(level, t) => {
                    let (face, size, before) = match level {
                        1 => (&f.semibold, 22.0, 4.0),
                        2 => (&f.semibold, 17.0, 18.0),
                        _ => (&f.medium, 15.0, 12.0),
                    };
                    y += before;
                    let s = p.style(face, size, pal.chalk);
                    for l in slate_ui::text::wrap(&s, &t, w * p.scale) {
                        marked(p, pal, &s, &mut m, x, y - origin, origin, size * 1.35, &l);
                        y += size * 1.35;
                    }
                    y += 6.0;
                }
                Block::Para(t) => {
                    let s = p.style(&f.regular, 14.0, pal.text_2);
                    for l in slate_ui::text::wrap(&s, &t, w * p.scale) {
                        marked(p, pal, &s, &mut m, x, y - origin, origin, 21.0, &l);
                        y += 21.0;
                    }
                    y += 10.0;
                }
                Block::Item(depth, t) => {
                    let s = p.style(&f.regular, 14.0, pal.text_2);
                    let ix = x + 18.0 + depth as f32 * 18.0;
                    p.fill(Area::new(ix - 11.0, y + 9.0, 4.0, 4.0), 2.0, pal.muted);
                    for l in slate_ui::text::wrap(&s, &t, (w - (ix - x)) * p.scale) {
                        marked(p, pal, &s, &mut m, ix, y - origin, origin, 21.0, &l);
                        y += 21.0;
                    }
                    y += 4.0;
                }
                Block::Code(lines) => {
                    let s = p.style(&f.mono, 12.5, pal.text_1);
                    let h = lines.len() as f32 * 19.0 + 20.0;
                    p.fill(Area::new(x, y, w, h), 8.0, pal.well);
                    let mut ly = y + 10.0;
                    for l in &lines {
                        p.line(&s, x + 14.0, ly, 19.0, l);
                        ly += 19.0;
                    }
                    y += h + 12.0;
                }
                Block::Rule => {
                    p.fill(Area::new(x, y + 8.0, w, 1.0), 0.0, pal.divider);
                    y += 20.0;
                }
                Block::Table(rows) => {
                    y = table(p, pal, f, &mut m, &rows, x, y, w, origin) + 12.0;
                }
            }
        }
        p.unclip(clip);
        let height = y + scroll - top;
        self.page_h = bottom - top;
        self.max_scroll = (height - self.page_h + 16.0).max(0.0);
        self.link_hits = m.hits;
        self.link_at = m.at;
        // Opened by a search: at its first match (redrawn from there).
        if let Some((_, scroll_to)) = &mut self.find
            && core::mem::take(scroll_to)
            && let (Some(at), Some((_, s))) = (m.first_match, &mut self.reading)
        {
            *s = (at - 40.0).clamp(0.0, self.max_scroll);
            self.again = true;
        }
        match self.notice {
            Some(n) => {
                let s = p.style(&f.regular, 12.5, pal.muted);
                p.line(&s, a.x + 20.0, a.y + a.h - 30.0, 18.0, n);
            }
            None => kit::hints(
                p,
                pal,
                f,
                a,
                &[("up down", "scroll"), ("tab", "links"), ("enter", "follow"), ("esc", "back")],
            ),
        }
    }
}

impl App for Help {
    fn draw(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area) {
        self.rows.clear();
        self.back = None;
        if let Some((g, s)) = self.reading
            && g < self.guides.len()
        {
            self.draw_guide(p, pal, f, a, g, s);
            return;
        }
        let pad = 24.0;
        let x = a.x + pad;
        let w = a.w - 2.0 * pad;
        self.tabs = kit::tabs(p, pal, f, x - 4.0, a.y + 12.0, &["about this system", "guides"], self.page);
        let mut y = a.y + 64.0;
        let label = p.style(&f.mono, 11.5, pal.muted);
        // Model names are text as written: no "×" for the X in "7950X".
        let mut value = p.style(&f.regular, 14.0, pal.text_1);
        value.ligatures = false;
        if self.page == 0 {
            p.logo(x, y, 40.0, pal.chalk);
            let big = p.style(&f.semibold, 22.0, pal.chalk);
            let release = self.about.first().map_or("Slate", |r| r.1.as_str());
            p.line(&big, x + 56.0, y + 2.0, 26.0, release);
            let sub = p.style(&f.regular, 13.0, pal.muted);
            p.line(&sub, x + 56.0, y + 28.0, 18.0, "A clean, fast system of its own.");
            y += 70.0;
            for (k, v) in self.about.iter().skip(1) {
                p.line(&label, x, y + 2.0, 18.0, k);
                let vx = x + 130.0;
                for (i, l) in slate_ui::text::wrap(&value, v, (w - 130.0) * p.scale).iter().enumerate() {
                    p.line(&value, vx, y + i as f32 * 20.0, 20.0, l);
                    if i > 0 {
                        y += 20.0;
                    }
                }
                y += 30.0;
            }
            kit::hints(p, pal, f, a, &[("tab", "guides"), ("ctrl c", "copy")]);
        } else {
            let ghost = p.style(&f.regular, 14.0, pal.muted);
            // The search: a field once something is typed.
            let field = Area::new(x, y, w, 36.0);
            p.fill(field, 8.0, pal.well);
            match &self.query {
                Some(q) => {
                    p.border(field, 8.0, 1.0, pal.field_focus);
                    let typed = p.style(&f.regular, 14.0, pal.text_1);
                    let e = p.line(&typed, x + 12.0, y + 8.0, 20.0, q);
                    p.fill(Area::new(x + 13.0 + e, y + 8.0, 1.5, 20.0), 0.0, pal.chalk);
                }
                None => {
                    p.line(&ghost, x + 12.0, y + 8.0, 20.0, "Type to search the guides");
                }
            }
            y += 50.0;
            let shown = self.shown();
            if self.guides.is_empty() {
                p.line(&ghost, x, y, 20.0, "No guides are installed.");
            } else if shown.is_empty() {
                p.line(&ghost, x, y, 20.0, "No guide says that.");
            }
            let name = p.style(&f.medium, 15.0, pal.text_1);
            for (row, &i) in shown.iter().enumerate() {
                let g = &self.guides[i];
                let r = Area::new(x - 10.0, y, w + 20.0, 44.0);
                if row == self.selected {
                    p.fill(r, 8.0, pal.raised);
                }
                p.icon(slate_ui::icon::Icon::Letter, x, y + 12.0, 18.0, pal.text_3);
                p.line(&name, x + 30.0, y + 11.0, 22.0, &g.title);
                self.rows.push((row, r));
                y += 48.0;
            }
            let hint: &[(&str, &str)] = if self.query.is_some() {
                &[("enter", "read"), ("esc", "clear")]
            } else {
                &[("enter", "read"), ("type", "search"), ("tab", "about")]
            };
            kit::hints(p, pal, f, a, hint);
        }
    }

    fn key(&mut self, code: u16, ch: Option<char>, mods: u8) -> Effect {
        if mods & CTRL != 0 {
            return match ch.map(|c| c.to_ascii_lowercase()) {
                Some('c') if self.page == 0 && self.reading.is_none() => Effect::Copy(self.about_text()),
                _ => Effect::None,
            };
        }
        if self.reading.is_some() {
            let page = (self.page_h - 40.0).max(40.0);
            self.notice = None;
            return match code {
                KEY_ESC | KEY_BACKSPACE => self.back(),
                KEY_TAB => {
                    let n = self.link_at.len();
                    if n == 0 {
                        return Effect::None;
                    }
                    let back = mods & SHIFT != 0;
                    let i = match self.link {
                        None if back => n - 1,
                        None => 0,
                        Some(i) if back => (i + n - 1) % n,
                        Some(i) => (i + 1) % n,
                    };
                    self.link = Some(i);
                    // Scrolled to, if it is out of sight.
                    if let Some((_, s)) = &mut self.reading {
                        let at = self.link_at[i];
                        if at < *s || at > *s + self.page_h - 40.0 {
                            *s = (at - self.page_h / 3.0).clamp(0.0, self.max_scroll);
                        }
                    }
                    Effect::Redraw
                }
                KEY_ENTER | KEY_KPENTER => self.link.map_or(Effect::None, |i| self.follow(i)),
                KEY_UP => self.scroll_by(-40.0),
                KEY_DOWN => self.scroll_by(40.0),
                KEY_PAGEUP => self.scroll_by(-page),
                KEY_PAGEDOWN | slate_display::input::KEY_SPACE => self.scroll_by(page),
                KEY_HOME => self.scroll_by(-f32::MAX / 2.0),
                KEY_END => self.scroll_by(f32::MAX / 2.0),
                _ => Effect::None,
            };
        }
        let shown = self.shown();
        match code {
            KEY_TAB => self.page = 1 - self.page,
            KEY_UP if self.page == 1 => self.selected = self.selected.saturating_sub(1),
            KEY_DOWN if self.page == 1 => self.selected = (self.selected + 1).min(shown.len().saturating_sub(1)),
            KEY_ENTER | KEY_KPENTER if self.page == 1 && self.selected < shown.len() => {
                self.find = self.query.clone().map(|q| (q, true));
                self.trail.clear();
                self.open(shown[self.selected], false);
            }
            KEY_ESC if self.page == 1 && self.query.is_some() => self.query = None,
            KEY_BACKSPACE if self.page == 1 && self.query.is_some() => {
                if let Some(q) = &mut self.query {
                    q.pop();
                    if q.is_empty() {
                        self.query = None;
                    }
                }
                self.selected = 0;
            }
            _ => match ch.filter(|c| !c.is_control() && self.page == 1) {
                Some(c) if self.query.as_ref().is_none_or(|q| q.chars().count() < 64) => {
                    self.query.get_or_insert_with(String::new).push(c);
                    self.selected = 0;
                    crate::trace!(
                        "slate-help: searching for \"{}\": {} found",
                        self.query.as_deref().unwrap_or(""),
                        self.shown().len()
                    );
                }
                _ => return Effect::None,
            },
        }
        Effect::Redraw
    }

    fn click(&mut self, x: f32, y: f32) -> Effect {
        if self.back.is_some_and(|b| b.contains(x, y)) {
            return self.back();
        }
        if self.reading.is_some() {
            return match self.link_hits.iter().find(|(a, _)| a.contains(x, y)) {
                Some(&(_, i)) => {
                    self.link = Some(i);
                    self.follow(i)
                }
                None => Effect::None,
            };
        }
        if let Some(i) = self.tabs.iter().position(|a| a.contains(x, y)) {
            self.page = i;
            return Effect::Redraw;
        }
        if let Some(&(i, _)) = self.rows.iter().find(|(_, a)| a.contains(x, y)) {
            if self.selected == i {
                return self.key(KEY_ENTER, None, 0);
            }
            self.selected = i;
            return Effect::Redraw;
        }
        Effect::None
    }

    fn scroll(&mut self, lines: i32) -> Effect {
        self.scroll_by(lines as f32 * 40.0)
    }

    fn tick(&mut self, _now: kit::Now) -> bool {
        core::mem::take(&mut self.again)
    }

    fn wake(&self, _now: kit::Now) -> Option<i64> {
        self.again.then_some(0)
    }
}

/// One line of a guide's text, with its links in the links' colour (the
/// chosen one underlined, ADR STRATA_COLORS' links) and a search's
/// matches on a tint. `y` is from the guide's top, `origin` where that is
/// now.
#[allow(clippy::too_many_arguments)]
fn marked(
    p: &mut Painter<'_>,
    pal: &Palette,
    s: &slate_ui::text::Style<'_, '_>,
    m: &mut Marks<'_>,
    x: f32,
    y: f32,
    origin: f32,
    h: f32,
    line: &str,
) {
    // The pieces: (start, end, link) over the line's bytes.
    let mut pieces: Vec<(usize, usize, Option<usize>)> = Vec::new();
    let mut from = 0;
    // A link that went on from the line before.
    if let Some((i, rest)) = m.rest.take() {
        let r = rest.trim_start();
        let n = line.len().min(r.len());
        let take = (0..=n).rev().find(|&k| line.is_char_boundary(k) && r.starts_with(&line[..k])).unwrap_or(0);
        if take > 0 {
            pieces.push((0, take, Some(i)));
            from = take;
        }
        if take < r.len() && take == line.len() {
            m.rest = Some((i, String::from(&r[take..])));
        }
    }
    while m.rest.is_none() && m.next < m.links.len() {
        let text = m.links[m.next].0.as_str();
        if text.is_empty() {
            m.next += 1;
            continue;
        }
        if let Some(k) = line[from..].find(text) {
            pieces.push((from + k, from + k + text.len(), Some(m.next)));
            m.at[m.next] = y;
            from += k + text.len();
            m.next += 1;
            continue;
        }
        // Its start at the line's end: the rest comes on the next line.
        let tail = (1..text.len())
            .rev()
            .find(|&k| text.is_char_boundary(k) && line[from..].ends_with(&text[..k]) && text[k..].starts_with(' '));
        if let Some(k) = tail {
            pieces.push((line.len() - k, line.len(), Some(m.next)));
            m.at[m.next] = y;
            m.rest = Some((m.next, String::from(&text[k..])));
            m.next += 1;
        }
        break;
    }
    let link_style = slate_ui::text::Style { color: pal.accents.steel.text, ..*s };
    let mut cx = x;
    let mut at = 0;
    let draw = |p: &mut Painter<'_>, cx: &mut f32, part: &str, link: Option<usize>, m: &mut Marks<'_>| {
        if part.is_empty() {
            return;
        }
        let pw = p.measure(s, part);
        // A search's matches, on a tint.
        if let Some(q) = m.find.as_deref().filter(|q| !q.is_empty()) {
            let low = part.to_lowercase();
            let mut k = 0;
            while let Some(i) = low[k..].find(q) {
                let (a, b) = (k + i, k + i + q.len());
                if part.is_char_boundary(a) && part.is_char_boundary(b) {
                    let mx = *cx + p.measure(s, &part[..a]);
                    p.fill(
                        Area::new(mx - 1.0, origin + y + 1.0, p.measure(s, &part[a..b]) + 2.0, h - 2.0),
                        3.0,
                        pal.raised,
                    );
                    m.first_match.get_or_insert(y);
                }
                k = b;
            }
        }
        match link {
            Some(i) => {
                p.line(&link_style, *cx, origin + y, h, part);
                if m.focus == Some(i) {
                    p.fill(Area::new(*cx, origin + y + h - 3.0, pw, 1.0), 0.0, pal.accents.steel.text);
                }
                m.hits.push((Area::new(*cx, origin + y, pw, h), i));
            }
            None => {
                p.line(s, *cx, origin + y, h, part);
            }
        }
        *cx += pw;
    };
    for (a, b, link) in pieces {
        draw(p, &mut cx, &line[at..a], None, m);
        draw(p, &mut cx, &line[a..b], link, m);
        at = b;
    }
    draw(p, &mut cx, &line[at..], None, m);
}

/// A table: the header on a raised row, the cells wrapped in columns as
/// wide as they need, shared out when they don't fit. Returns the y below.
#[allow(clippy::too_many_arguments)]
fn table(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    m: &mut Marks<'_>,
    rows: &[Vec<String>],
    x: f32,
    mut y: f32,
    w: f32,
    origin: f32,
) -> f32 {
    let pad = 10.0;
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    if cols == 0 {
        return y;
    }
    let head = p.style(&f.medium, 13.5, pal.chalk);
    let body = p.style(&f.regular, 13.5, pal.text_2);
    let mut natural = alloc::vec![0.0f32; cols];
    for (r, row) in rows.iter().enumerate() {
        let s = if r == 0 { &head } else { &body };
        for (c, cell) in row.iter().enumerate() {
            natural[c] = natural[c].max(p.measure(s, cell) + 2.0 * pad);
        }
    }
    let total: f32 = natural.iter().sum();
    let widths: Vec<f32> = if total <= w {
        natural
    } else {
        // Each column its share, the narrow ones whole.
        let fair = w / cols as f32;
        let narrow: f32 = natural.iter().filter(|&&n| n <= fair).sum();
        let wide: f32 = natural.iter().filter(|&&n| n > fair).sum();
        natural.iter().map(|&n| if n <= fair { n } else { (w - narrow) * n / wide }).collect()
    };
    let tw: f32 = widths.iter().sum();
    let line_h = 19.0;
    for (r, row) in rows.iter().enumerate() {
        let s = if r == 0 { &head } else { &body };
        let wrapped: Vec<Vec<String>> = (0..cols)
            .map(|c| {
                let cell = row.get(c).map_or("", String::as_str);
                slate_ui::text::wrap(s, cell, (widths[c] - 2.0 * pad).max(20.0) * p.scale)
            })
            .collect();
        let lines = wrapped.iter().map(Vec::len).max().unwrap_or(1).max(1);
        let rh = lines as f32 * line_h + 12.0;
        if r == 0 {
            p.fill(Area::new(x, y, tw, rh), 6.0, pal.raised);
        } else {
            p.fill(Area::new(x, y, tw, 1.0), 0.0, pal.divider);
        }
        let mut cx = x;
        for (c, cell) in wrapped.iter().enumerate() {
            for (k, l) in cell.iter().enumerate() {
                marked(p, pal, s, m, cx + pad, y + 6.0 + k as f32 * line_h - origin, origin, line_h, l);
            }
            cx += widths[c];
        }
        y += rh;
    }
    y
}

pub fn main() -> i32 {
    let mut h = Help { about: about(), guides: guides(GUIDES), ..Help::default() };
    for (k, v) in &h.about {
        crate::trace!("slate-help: {k}: {v}");
    }
    kit::run("slate-help", "help", None, Hints { min: (420, 420), size: (600, 600) }, &mut h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown() {
        let text = "# Getting started\n\nSlate is **small**.\nIt is `fast`, see [the guide](x.md).\n\n## Keys\n\n- super + space\n  opens the launcher\n  - nested\n1. first\n\n```sh\ncargo xtask run\n```\n---\n";
        assert_eq!(
            blocks(text),
            [
                Block::Heading(1, "Getting started".into()),
                Block::Para("Slate is small. It is fast, see the guide.".into()),
                Block::Heading(2, "Keys".into()),
                Block::Item(0, "super + space opens the launcher".into()),
                Block::Item(1, "nested".into()),
                Block::Item(0, "first".into()),
                Block::Code(std::vec!["cargo xtask run".into()]),
                Block::Rule,
            ]
        );
        assert_eq!(Guide::new(text, "getting-started.md").title, "Getting started");
        let t = "| Keys | What |\n|---|:--:|\n| super + q | close `it` |\n| a |\n\nAfter.\n";
        assert_eq!(
            blocks(t),
            [
                Block::Table(std::vec![
                    std::vec!["Keys".into(), "What".into()],
                    std::vec!["super + q".into(), "close it".into()],
                    std::vec!["a".into()],
                ]),
                Block::Para("After.".into()),
            ]
        );
        assert_eq!(
            links("See [the guide](installing.md#disks) and [Slate](https://example.org).\n```\n[no](x)\n```\n"),
            [
                (String::from("the guide"), String::from("installing.md#disks")),
                (String::from("Slate"), String::from("https://example.org"))
            ]
        );
        assert_eq!(Guide::new("no heading", "using-quarry.md").title, "using quarry");
    }

    #[test]
    fn keys() {
        let guide = |t: &str| Guide::new(&alloc::format!("# {t}\n\nText."), "x.md");
        let mut h = Help { guides: std::vec![guide("Installing Slate"), guide("Getting started")], ..Help::default() };
        h.about = std::vec![("release".into(), "Slate 0.1.0".into()), ("memory".into(), "4 GiB".into())];
        assert_eq!(h.key(0, Some('c'), CTRL), Effect::Copy("release: Slate 0.1.0\nmemory: 4 GiB\n".into()));
        h.key(KEY_TAB, None, 0);
        h.key(KEY_DOWN, None, 0);
        h.key(KEY_ENTER, None, 0);
        assert_eq!(h.reading, Some((1, 0.0)));
        (h.max_scroll, h.page_h) = (100.0, 500.0);
        h.key(KEY_PAGEDOWN, None, 0);
        assert_eq!(h.reading, Some((1, 100.0)));
        h.key(KEY_HOME, None, 0);
        assert_eq!(h.reading, Some((1, 0.0)));
        h.key(KEY_ESC, None, 0);
        assert_eq!(h.reading, None);
    }

    #[test]
    fn search_and_links() {
        let a = Guide::new(
            "# Getting started\n\nRead [installing](installing.md) or [the web](https://example.org).",
            "getting-started.md",
        );
        let b = Guide::new("# Installing Slate\n\nThe disks are erased.", "installing.md");
        let mut h = Help { page: 1, guides: std::vec![a, b], ..Help::default() };
        // Typing searches the text too.
        for c in "DISKS".chars() {
            h.key(0, Some(c), 0);
        }
        assert_eq!((h.query.as_deref(), h.shown()), (Some("DISKS"), std::vec![1]));
        h.key(KEY_ENTER, None, 0);
        assert_eq!(h.reading.map(|r| r.0), Some(1));
        assert_eq!(h.find.as_ref().map(|f| f.0.as_str()), Some("DISKS"));
        h.key(KEY_ESC, None, 0);
        h.key(KEY_ESC, None, 0);
        assert_eq!((h.reading, h.query.as_deref()), (None, None));
        // Links: Tab chooses, Enter follows; Esc comes back to the guide
        // the link was in.
        h.key(KEY_ENTER, None, 0);
        assert_eq!(h.reading.map(|r| r.0), Some(0));
        h.link_at = std::vec![0.0, 0.0];
        h.key(KEY_TAB, None, 0);
        assert_eq!(h.link, Some(0));
        h.key(KEY_ENTER, None, 0);
        assert_eq!(h.reading.map(|r| r.0), Some(1));
        h.key(KEY_ESC, None, 0);
        assert_eq!(h.reading.map(|r| r.0), Some(0));
        h.link_at = std::vec![0.0, 0.0];
        h.key(KEY_TAB, None, SHIFT);
        assert_eq!(h.link, Some(1));
        assert_eq!(h.key(KEY_ENTER, None, 0), Effect::Copy("https://example.org".into()));
        assert!(h.notice.is_some());
    }
}
