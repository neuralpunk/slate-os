// SPDX-License-Identifier: MIT OR Apache-2.0

//! Contacts (ADR 0109), `contacts [FILE.vcf]`: an address book kept as
//! vCards (`~/.local/share/slate/contacts/contacts.vcf`, read and written
//! by `libs/pim`).
//!
//! - Typing searches names, organisations, e-mail addresses and phone
//!   numbers; up and down choose; the chosen card shows beside the list.
//! - Enter edits it, `ctrl + n` makes a new one, Delete deletes it
//!   (pressed twice); in the form, Tab moves between the fields, Enter or
//!   ctrl + s saves, Esc leaves it.
//! - Opening a `.vcf` file imports its cards (one already here, by its
//!   UID, is replaced); ctrl + e exports them all to ~/Documents.
//!
//! The form edits a card's first phone number, e-mail address and postal
//! address and the rest of what people use most; anything else the card
//! holds is kept as it was.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_display::input::{KEY_DELETE, KEY_DOWN, KEY_END, KEY_ENTER, KEY_ESC, KEY_HOME, KEY_KPENTER, KEY_TAB, KEY_UP};
use slate_pim::vcard::{self, Address, Contact, Typed};
use slate_strata::fonts::Fonts;
use slate_strata_client::mods::{ALT, CTRL, LOGO, SHIFT};
use slate_ui::edit::LineEdit;
use slate_ui::graphite::Palette;
use slate_ui::icon::Icon;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;

use crate::kit::{self, App, Effect, Hints};

/// The form's fields, in order.
const FIELDS: [&str; 10] =
    ["name", "phone", "e-mail", "street", "town", "postcode", "country", "organisation", "birthday", "notes"];

#[derive(Clone, Debug)]
pub struct Form {
    /// The card edited (an index), or None for a new one.
    pub editing: Option<usize>,
    pub field: usize,
    pub values: Vec<LineEdit>,
    pub error: String,
}

#[derive(Debug)]
pub struct Book {
    pub path: String,
    pub cards: Vec<Contact>,
    pub query: LineEdit,
    /// The cards shown (indices into `cards`), sorted.
    pub shown: Vec<usize>,
    pub selected: usize,
    first: usize,
    pub form: Option<Form>,
    pub status: String,
    confirm_delete: bool,
    rows: Vec<Area>,
    uid_n: u32,
}

impl Book {
    pub fn new(path: &str) -> Book {
        let cards =
            slate_rt::fs::read_file(path.as_bytes()).map(|t| vcard::parse(&slate_rt::lossy(&t))).unwrap_or_default();
        let mut b = Book {
            path: path.to_string(),
            cards,
            query: LineEdit::new("").with_max(100),
            shown: Vec::new(),
            selected: 0,
            first: 0,
            form: None,
            status: String::new(),
            confirm_delete: false,
            rows: Vec::new(),
            uid_n: 0,
        };
        b.filter();
        b
    }

    pub fn filter(&mut self) {
        let q = self.query.text();
        let chosen = self.shown.get(self.selected).copied();
        let mut v: Vec<usize> = (0..self.cards.len()).filter(|&i| self.cards[i].matches(q.trim())).collect();
        v.sort_by_key(|&i| self.cards[i].sort_key());
        self.selected = chosen.and_then(|c| v.iter().position(|&i| i == c)).unwrap_or(0);
        self.shown = v;
    }

    pub fn chosen(&self) -> Option<&Contact> {
        self.shown.get(self.selected).map(|&i| &self.cards[i])
    }

    fn save(&mut self) {
        let dir = self.path.rsplit_once('/').map_or(String::new(), |(d, _)| d.to_string());
        let mut at = String::new();
        for c in dir.split('/').filter(|c| !c.is_empty()) {
            at.push('/');
            at.push_str(c);
            let _ = slate_rt::fs::mkdir(at.as_bytes(), 0o700);
        }
        let tmp = alloc::format!("{}.new", self.path);
        let text = vcard::render(&self.cards);
        let r = slate_rt::fs::write_file(tmp.as_bytes(), text.as_bytes(), 0o600)
            .and_then(|_| slate_rt::fs::rename(tmp.as_bytes(), self.path.as_bytes()));
        if let Err(e) = r {
            self.status = alloc::format!("Couldn't save the contacts: {e}");
        }
    }

    pub fn import(&mut self, name: &str, text: &str) -> String {
        let incoming = vcard::parse(text);
        if incoming.is_empty() {
            return alloc::format!("{} has no cards Slate can read.", name.rsplit('/').next().unwrap_or(name));
        }
        let n = incoming.len();
        let (new, replaced) = vcard::merge(&mut self.cards, incoming);
        self.save();
        self.filter();
        crate::trace!("contacts: imported {n} cards");
        let mut s = alloc::format!("Imported {new} new contact{}", if new == 1 { "" } else { "s" });
        if replaced > 0 {
            s.push_str(&alloc::format!(", {replaced} updated"));
        }
        s.push('.');
        s
    }

    pub fn export(&mut self, dir: &str) -> String {
        let path = alloc::format!("{dir}/contacts.vcf");
        match slate_rt::fs::write_file(path.as_bytes(), vcard::render(&self.cards).as_bytes(), 0o644) {
            Ok(()) => {
                crate::trace!("contacts: exported {} cards", self.cards.len());
                alloc::format!("Exported {} contacts to {}.", self.cards.len(), "Documents/contacts.vcf")
            }
            Err(e) => alloc::format!("Couldn't export: {e}"),
        }
    }

    fn open_form(&mut self, editing: Option<usize>) {
        let c = editing.map(|i| self.cards[i].clone()).unwrap_or_default();
        let adr = c.addresses.first().map(|a| a.value.clone()).unwrap_or_default();
        let vals = [
            c.name.clone(),
            c.phones.first().map(|p| p.value.clone()).unwrap_or_default(),
            c.emails.first().map(|p| p.value.clone()).unwrap_or_default(),
            adr.street,
            adr.locality,
            adr.code,
            adr.country,
            c.org.clone(),
            birthday_text(&c.birthday),
            c.note.clone(),
        ];
        let values = vals.iter().map(|v| LineEdit::new(v).with_max(500)).collect();
        self.form = Some(Form { editing, field: 0, values, error: String::new() });
    }

    fn save_form(&mut self) -> bool {
        let Some(f) = self.form.as_mut() else { return false };
        let v: Vec<String> = f.values.iter().map(|e| e.text().trim().to_string()).collect();
        if v[0].is_empty() {
            f.error = String::from("A contact needs a name.");
            f.field = 0;
            return false;
        }
        let birthday = match parse_birthday(&v[8]) {
            Some(b) => b,
            None => {
                f.error = String::from("A birthday is year-month-day, as 1815-12-10.");
                f.field = 8;
                return false;
            }
        };
        let editing = f.editing;
        let mut c = editing.map(|i| self.cards[i].clone()).unwrap_or_default();
        if c.uid.is_empty() {
            self.uid_n += 1;
            c.uid = slate_pim::ical::new_uid(slate_rt::time::unix(), self.uid_n);
        }
        // A new name: the structured one follows it (given names, then the
        // family name last).
        if c.name != v[0] {
            let words: Vec<&str> = v[0].split_whitespace().collect();
            c.parts = Default::default();
            if let Some((last, rest)) = words.split_last() {
                c.parts[0] = last.to_string();
                c.parts[1] = rest.join(" ");
            }
        }
        c.name = v[0].clone();
        let set_first = |list: &mut Vec<Typed<String>>, value: &str| match (list.first_mut(), value.is_empty()) {
            (Some(_), true) => {
                list.remove(0);
            }
            (Some(x), false) => x.value = value.to_string(),
            (None, false) => list.push(Typed { kinds: Vec::new(), value: value.to_string() }),
            (None, true) => {}
        };
        set_first(&mut c.phones, &v[1]);
        set_first(&mut c.emails, &v[2]);
        let adr_given = v[3..7].iter().any(|s| !s.is_empty());
        match (c.addresses.first_mut(), adr_given) {
            (Some(a), true) => {
                a.value.street = v[3].clone();
                a.value.locality = v[4].clone();
                a.value.code = v[5].clone();
                a.value.country = v[6].clone();
            }
            (Some(_), false) => {
                c.addresses.remove(0);
            }
            (None, true) => c.addresses.push(Typed {
                kinds: Vec::new(),
                value: Address {
                    street: v[3].clone(),
                    locality: v[4].clone(),
                    code: v[5].clone(),
                    country: v[6].clone(),
                    ..Address::default()
                },
            }),
            (None, false) => {}
        }
        c.org = v[7].clone();
        c.birthday = birthday;
        c.note = v[9].clone();
        let name = c.name.clone();
        let at = match editing {
            Some(i) => {
                self.cards[i] = c;
                i
            }
            None => {
                self.cards.push(c);
                self.cards.len() - 1
            }
        };
        self.save();
        self.form = None;
        self.query.clear();
        self.filter();
        self.selected = self.shown.iter().position(|&i| i == at).unwrap_or(0);
        crate::trace!("contacts: saved {name}");
        self.status = alloc::format!("Saved {name}.");
        true
    }
}

/// A BDAY value (RFC 6350 §6.2.5: `19801210`, `1980-12-10`, `--1210`) as
/// `1980-12-10` (or `12-10` without a year).
fn birthday_text(b: &str) -> String {
    let d: String = b.chars().filter(char::is_ascii_digit).collect();
    match (b.starts_with("--"), d.len()) {
        (true, 4) => alloc::format!("{}-{}", &d[..2], &d[2..]),
        (false, 8) => alloc::format!("{}-{}-{}", &d[..4], &d[4..6], &d[6..]),
        _ => b.to_string(),
    }
}

/// What is typed as a BDAY value (`19801210`, or `--1210` without a
/// year); None if it isn't a date; empty for none.
fn parse_birthday(t: &str) -> Option<String> {
    if t.is_empty() {
        return Some(String::new());
    }
    let parts: Vec<&str> = t.split('-').collect();
    match parts.as_slice() {
        [y, m, d] => {
            let date = slate_pim::date::Date::new(y.parse().ok()?, m.parse().ok()?, d.parse().ok()?)?;
            Some(date.compact())
        }
        [m, d] => {
            let (m, d): (u8, u8) = (m.parse().ok()?, d.parse().ok()?);
            slate_pim::date::Date::new(2000, m, d)?;
            Some(alloc::format!("--{m:02}{d:02}"))
        }
        _ => None,
    }
}

/// A person's initials, for the card's badge.
fn initials(name: &str) -> String {
    let words: Vec<&str> = name.split_whitespace().collect();
    let first = |w: &str| w.chars().next().map(|c| c.to_uppercase().collect::<String>()).unwrap_or_default();
    match words.as_slice() {
        [] => String::from("?"),
        [one] => first(one),
        [a, .., z] => alloc::format!("{}{}", first(a), first(z)),
    }
}

impl App for Book {
    fn draw(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area) {
        self.rows.clear();
        let label = p.style(&f.mono, 11.0, pal.muted);
        let title = p.style(&f.semibold, 20.0, pal.chalk);
        let pad = 20.0;
        if let Some(form) = &self.form {
            let x = a.x + pad;
            let w = (a.w - 2.0 * pad).min(560.0);
            p.line(
                &title,
                x,
                a.y + 16.0,
                28.0,
                if form.editing.is_some() { "Change the contact" } else { "A new contact" },
            );
            let mut y = a.y + 60.0;
            for (i, name) in FIELDS.iter().enumerate() {
                p.line(&label, x, y + 9.0, 18.0, name);
                crate::calendar::field(
                    p,
                    pal,
                    f,
                    Area::new(x + 110.0, y, w - 110.0, 34.0),
                    &form.values[i],
                    form.field == i,
                );
                y += 40.0;
            }
            if !form.error.is_empty() {
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
        // The list, with its search field.
        let list_w = (a.w * 0.38).clamp(240.0, 340.0);
        let side = Area::new(a.x, a.y, list_w, a.h);
        p.fill(side, 0.0, pal.header);
        p.fill(Area::new(side.x + side.w - 1.0, side.y, 1.0, side.h), 0.0, pal.divider);
        let fa = Area::new(side.x + 12.0, a.y + 12.0, side.w - 24.0, 34.0);
        p.fill(fa, 8.0, pal.well);
        p.border(fa, 8.0, 1.0, if self.query.is_empty() { pal.border } else { pal.field_focus });
        p.icon(Icon::Search, fa.x + 10.0, fa.y + 9.0, 16.0, pal.muted);
        let q = self.query.text();
        if q.is_empty() {
            let ghost = p.style(&f.regular, 13.0, pal.muted);
            p.line(&ghost, fa.x + 34.0, fa.y + 7.0, 20.0, "Search");
        } else {
            let s = p.style(&f.regular, 13.0, pal.text_1);
            let end = p.line(&s, fa.x + 34.0, fa.y + 7.0, 20.0, &q);
            p.fill(Area::new(fa.x + 35.0 + end, fa.y + 8.0, 1.5, 18.0), 0.0, pal.chalk);
        }
        let row_h = 44.0;
        let top = a.y + 56.0;
        let room = ((a.y + a.h - 36.0 - top) / row_h).max(1.0) as usize;
        if self.selected < self.first {
            self.first = self.selected;
        } else if self.selected >= self.first + room {
            self.first = self.selected + 1 - room;
        }
        let name_s = p.style(&f.medium, 13.5, pal.text_1);
        let sub = p.style(&f.regular, 12.0, pal.muted);
        if self.shown.is_empty() {
            let msg =
                if self.cards.is_empty() { "No contacts yet. ctrl + n adds one." } else { "No one by that name." };
            p.line(&sub, side.x + 16.0, top + 8.0, 18.0, msg);
        }
        for (k, &ci) in self.shown.iter().enumerate().skip(self.first).take(room) {
            let c = &self.cards[ci];
            let y = top + (k - self.first) as f32 * row_h;
            let r = Area::new(side.x + 8.0, y, side.w - 16.0, row_h - 4.0);
            let sel = k == self.selected;
            if sel {
                p.fill(r, 8.0, pal.list_selected);
            }
            let ns = if sel { p.style(&f.medium, 13.5, pal.window) } else { name_s };
            let ss = if sel { p.style(&f.regular, 12.0, pal.window) } else { sub };
            p.line(&ns, r.x + 12.0, r.y + 3.0, 20.0, &kit::fit(p, &ns, &c.name, r.w - 24.0));
            let detail = if !c.org.is_empty() {
                c.org.clone()
            } else {
                c.emails.first().or(c.phones.first()).map(|x| x.value.clone()).unwrap_or_default()
            };
            p.line(&ss, r.x + 12.0, r.y + 21.0, 18.0, &kit::fit(p, &ss, &detail, r.w - 24.0));
            self.rows.push(r);
        }
        let count = alloc::format!("{} contacts", self.cards.len());
        p.line(&label, side.x + 16.0, a.y + a.h - 30.0, 18.0, &count);
        // The chosen card.
        let x = a.x + list_w + 28.0;
        let w = a.w - list_w - 56.0;
        if let Some(c) = self.chosen().cloned() {
            let mut y = a.y + 28.0;
            // The initials: a quiet personal accent (heather), with the name.
            let h = pal.accents.heather;
            let badge = Area::new(x, y, 56.0, 56.0);
            p.fill(badge, 28.0, h.tint);
            p.border(badge, 28.0, 1.0, h.border);
            let ini = initials(&c.name);
            let is = p.style(&f.semibold, 20.0, h.text);
            let iw = p.measure(&is, &ini);
            p.line(&is, badge.x + (56.0 - iw) / 2.0, badge.y + 14.0, 28.0, &ini);
            p.line(&title, x + 72.0, y + 4.0, 28.0, &kit::fit(p, &title, &c.name, w - 80.0));
            let orgs = [c.title.as_str(), c.org.as_str()]
                .iter()
                .filter(|s| !s.is_empty())
                .copied()
                .collect::<Vec<_>>()
                .join(", ");
            if !orgs.is_empty() {
                p.line(&sub, x + 72.0, y + 32.0, 18.0, &orgs);
            }
            y += 84.0;
            let value = p.style(&f.regular, 14.0, pal.text_1);
            let row = |p: &mut Painter<'_>, y: &mut f32, k: &str, v: &str, kind: &str| {
                let kk = if kind.is_empty() { k.to_string() } else { alloc::format!("{k} · {kind}") };
                p.line(&label, x, *y + 2.0, 18.0, &kk);
                for (i, l) in slate_ui::text::wrap(&value, v, (w - 130.0) * p.scale).iter().enumerate() {
                    p.line(&value, x + 130.0, *y + i as f32 * 20.0, 20.0, l);
                    if i > 0 {
                        *y += 20.0;
                    }
                }
                *y += 32.0;
            };
            for t in &c.phones {
                row(p, &mut y, "phone", &t.value, &vcard::kind_word(&t.kinds));
            }
            for t in &c.emails {
                row(p, &mut y, "e-mail", &t.value, &vcard::kind_word(&t.kinds));
            }
            for t in &c.addresses {
                row(p, &mut y, "address", &t.value.one_line(), &vcard::kind_word(&t.kinds));
            }
            if !c.birthday.is_empty() {
                row(p, &mut y, "birthday", &birthday_text(&c.birthday), "");
            }
            if !c.note.is_empty() {
                row(p, &mut y, "notes", &c.note, "");
            }
            if self.confirm_delete {
                let cl = pal.accents.clay;
                let r = Area::new(x, a.y + a.h - 92.0, w, 40.0);
                p.fill(r, 8.0, cl.tint);
                p.border(r, 8.0, 1.0, cl.border);
                let s = p.style(&f.medium, 13.0, cl.text);
                p.line(&s, r.x + 12.0, r.y + 10.0, 20.0, &alloc::format!("Delete {}? Press Delete again.", c.name));
            }
        }
        if !self.status.is_empty() {
            let s = p.style(&f.regular, 12.5, pal.text_3);
            p.line(&s, x, a.y + a.h - 46.0, 18.0, &self.status);
        }
        let hint_area = Area::new(x - 20.0, a.y, w, a.h);
        kit::hints(
            p,
            pal,
            f,
            hint_area,
            &[("enter", "edit"), ("ctrl n", "new"), ("del", "delete"), ("ctrl e", "export")],
        );
    }

    fn key(&mut self, code: u16, ch: Option<char>, mods: u8) -> Effect {
        let (shift, ctrl) = (mods & SHIFT != 0, mods & CTRL != 0);
        let letter = ch.map(|c| c.to_ascii_lowercase());
        if let Some(f) = self.form.as_mut() {
            match (code, letter) {
                (KEY_ESC, _) => self.form = None,
                (_, Some('s')) if ctrl => {
                    self.save_form();
                }
                (KEY_ENTER | KEY_KPENTER, _) => {
                    self.save_form();
                }
                (KEY_TAB | KEY_DOWN, _) | (KEY_UP, _) => {
                    let back = shift || code == KEY_UP;
                    let n = FIELDS.len();
                    f.field = if back { (f.field + n - 1) % n } else { (f.field + 1) % n };
                }
                _ => {
                    let fi = f.field;
                    if !crate::calendar::edit(&mut f.values[fi], code, ch, mods) {
                        return Effect::None;
                    }
                    f.error.clear();
                }
            }
            return Effect::Redraw;
        }
        self.status.clear();
        let n = self.shown.len();
        match (code, letter) {
            (_, Some('n')) if ctrl => self.open_form(None),
            (_, Some('e')) if ctrl => {
                let home = slate_rt::env::var(b"HOME").map(|h| String::from(slate_rt::lossy(&h))).unwrap_or_default();
                let docs = alloc::format!("{home}/Documents");
                let _ = slate_rt::fs::mkdir(docs.as_bytes(), 0o755);
                self.status = self.export(&docs);
            }
            (KEY_UP, _) => self.selected = self.selected.saturating_sub(1),
            (KEY_DOWN, _) => self.selected = (self.selected + 1).min(n.saturating_sub(1)),
            (KEY_HOME, _) if self.query.is_empty() => self.selected = 0,
            (KEY_END, _) if self.query.is_empty() => self.selected = n.saturating_sub(1),
            (KEY_ENTER | KEY_KPENTER, _) => {
                if let Some(&i) = self.shown.get(self.selected) {
                    self.open_form(Some(i));
                }
            }
            (KEY_DELETE, _) => {
                let Some(&i) = self.shown.get(self.selected) else { return Effect::None };
                if !self.confirm_delete {
                    self.confirm_delete = true;
                    return Effect::Redraw;
                }
                self.confirm_delete = false;
                let c = self.cards.remove(i);
                self.save();
                self.filter();
                self.selected = self.selected.min(self.shown.len().saturating_sub(1));
                crate::trace!("contacts: deleted {}", c.name);
                self.status = alloc::format!("Deleted {}.", c.name);
            }
            (KEY_ESC, _) if !self.query.is_empty() => {
                self.query.clear();
                self.filter();
            }
            _ => {
                // Everything else goes to the search.
                if mods & (CTRL | ALT | LOGO) != 0 || !crate::calendar::edit(&mut self.query, code, ch, mods) {
                    return Effect::None;
                }
                self.filter();
                self.selected = 0;
            }
        }
        if code != KEY_DELETE {
            self.confirm_delete = false;
        }
        Effect::Redraw
    }

    fn click(&mut self, x: f32, y: f32) -> Effect {
        if self.form.is_some() {
            return Effect::None;
        }
        match self.rows.iter().position(|r| r.contains(x, y)) {
            Some(k) => {
                self.selected = self.first + k;
                self.confirm_delete = false;
                Effect::Redraw
            }
            None => Effect::None,
        }
    }

    fn double_click(&mut self, x: f32, y: f32) -> Effect {
        if self.click(x, y) == Effect::Redraw
            && let Some(&i) = self.shown.get(self.selected)
        {
            self.open_form(Some(i));
        }
        Effect::Redraw
    }

    fn paste(&mut self, text: &str) -> Effect {
        let line = text.lines().next().unwrap_or("");
        match self.form.as_mut() {
            Some(f) => {
                let i = f.field;
                f.values[i].insert(line);
            }
            None => {
                self.query.insert(line);
                self.filter();
            }
        }
        Effect::Redraw
    }
}

pub fn main() -> i32 {
    let home = slate_rt::env::var(b"HOME").map(|h| String::from(slate_rt::lossy(&h))).unwrap_or_else(|| "/".into());
    let mut b = Book::new(&alloc::format!("{home}/.local/share/slate/contacts/contacts.vcf"));
    if let Some(path) = slate_rt::env::args().get(1).map(|a| String::from(slate_rt::lossy(a))) {
        b.status = match slate_rt::fs::read_file(path.as_bytes()) {
            Ok(t) => b.import(&path, &slate_rt::lossy(&t)),
            Err(e) => alloc::format!("{path}: {e}"),
        };
    }
    kit::run("contacts", "contacts", None, Hints { min: (560, 420), size: (860, 600) }, &mut b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> String {
        let p = std::env::temp_dir().join(alloc::format!("slate-contacts-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        alloc::format!("{}/contacts.vcf", p.to_string_lossy())
    }

    fn typed(b: &mut Book, s: &str) {
        for c in s.chars() {
            match c {
                '\t' => b.key(KEY_TAB, None, 0),
                '\n' => b.key(KEY_ENTER, None, 0),
                c => b.key(0, Some(c), 0),
            };
        }
    }

    const CARDS: &str = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:ada\r\nFN:Ada Lovelace\r\nN:Lovelace;Ada;;;\r\nTEL;TYPE=CELL:+44 20 7946 0958\r\nEMAIL:ada@example.org\r\nORG:Analytical Engines\r\nX-KEPT:yes\r\nEND:VCARD\r\nBEGIN:VCARD\r\nVERSION:4.0\r\nUID:grace\r\nFN:Grace Hopper\r\nN:Hopper;Grace;;;\r\nEMAIL;TYPE=work:grace@example.com\r\nEND:VCARD\r\n";

    #[test]
    fn import_search_and_edit() {
        let path = scratch("one");
        let mut b = Book::new(&path);
        assert_eq!(b.import("people.vcf", CARDS), "Imported 2 new contacts.");
        let names: Vec<&str> = b.shown.iter().map(|&i| b.cards[i].name.as_str()).collect();
        assert_eq!(names, ["Grace Hopper", "Ada Lovelace"], "by family name");
        typed(&mut b, "love");
        assert_eq!(b.chosen().unwrap().name, "Ada Lovelace");
        // Edit: a new phone number, kept; the unknown property too.
        b.key(KEY_ENTER, None, 0);
        b.key(KEY_TAB, None, 0);
        b.key(0, Some('a'), CTRL);
        typed(&mut b, "+44 1234\n");
        assert!(b.form.is_none(), "{}", b.status);
        let again = Book::new(&path);
        let ada = again.cards.iter().find(|c| c.uid == "ada").unwrap();
        assert_eq!(ada.phones[0].value, "+44 1234");
        assert_eq!(ada.phones[0].kinds, ["cell"]);
        assert!(ada.other.iter().any(|p| p.name == "X-KEPT"));
        // Imported again: replaced, not doubled.
        assert_eq!(b.import("people.vcf", CARDS), "Imported 0 new contacts, 2 updated.");
        std::fs::remove_dir_all(path.rsplit_once('/').unwrap().0).unwrap();
    }

    #[test]
    fn new_contacts_and_deleting() {
        let path = scratch("two");
        let mut b = Book::new(&path);
        b.key(0, Some('n'), CTRL);
        b.key(KEY_ENTER, None, 0);
        assert!(b.form.as_ref().is_some_and(|f| !f.error.is_empty()), "a name is needed");
        typed(&mut b, "Katherine Johnson\t\tkj@example.org\t\t\t\t\tNASA\t1918-8-26\n");
        let c = b.chosen().unwrap().clone();
        assert_eq!(
            (c.parts[0].as_str(), c.parts[1].as_str(), c.org.as_str(), c.birthday.as_str()),
            ("Johnson", "Katherine", "NASA", "19180826")
        );
        assert_eq!(c.emails[0].value, "kj@example.org");
        assert!(!c.uid.is_empty());
        b.key(KEY_DELETE, None, 0);
        assert_eq!(b.cards.len(), 1, "asked first");
        b.key(KEY_DELETE, None, 0);
        assert!(b.cards.is_empty());
        assert_eq!((birthday_text("--1210"), birthday_text("18151210")), ("12-10".into(), "1815-12-10".into()));
        assert_eq!((parse_birthday("12-10"), parse_birthday("2026-02-30")), (Some("--1210".into()), None));
        assert_eq!((initials("Ada King Lovelace"), initials("Cher")), ("AL".into(), "C".into()));
        std::fs::remove_dir_all(path.rsplit_once('/').unwrap().0).ok();
    }
}
