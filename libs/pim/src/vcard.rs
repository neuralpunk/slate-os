// SPDX-License-Identifier: MIT OR Apache-2.0

//! vCards (RFC 6350, version 4.0; versions 3.0 and 2.1 read the same
//! way where they agree): FN, N, TEL, EMAIL, ADR, ORG, TITLE, BDAY, NOTE
//! and UID, with their TYPEs. Everything else is kept as it was, so a
//! card read and written again loses nothing. Cards are written as 4.0.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::line::{self, Component, Prop};

/// A postal address (§6.3.1's seven parts; the first two are rarely
/// used and kept).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Address {
    pub po_box: String,
    pub extended: String,
    pub street: String,
    pub locality: String,
    pub region: String,
    pub code: String,
    pub country: String,
}

impl Address {
    /// The address on one line, its parts that are there.
    pub fn one_line(&self) -> String {
        [&self.street, &self.extended, &self.po_box, &self.locality, &self.region, &self.code, &self.country]
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.replace('\n', ", "))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// A value with its kinds (`home`, `work`, `cell`...).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Typed<T> {
    pub kinds: Vec<String>,
    pub value: T,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Contact {
    pub uid: String,
    /// The name as shown (FN).
    pub name: String,
    /// N: family, given, additional, prefixes, suffixes.
    pub parts: [String; 5],
    pub phones: Vec<Typed<String>>,
    pub emails: Vec<Typed<String>>,
    pub addresses: Vec<Typed<Address>>,
    pub org: String,
    pub title: String,
    /// BDAY as written (`19801210`, `1980-12-10`, `--1210`).
    pub birthday: String,
    pub note: String,
    pub other: Vec<Prop>,
}

/// The kinds worth keeping from TYPE: `pref` and `voice` are noise to a
/// person.
fn kinds(p: &Prop) -> Vec<String> {
    p.types().into_iter().filter(|t| !matches!(t.as_str(), "pref" | "voice" | "internet" | "x400")).collect()
}

impl Contact {
    pub fn from_component(c: &Component) -> Contact {
        let mut k = Contact { uid: c.text("UID").unwrap_or_default(), ..Contact::default() };
        let n = c.prop("N").map(|p| line::split(&p.value, ';')).unwrap_or_default();
        for (i, v) in n.into_iter().take(5).enumerate() {
            k.parts[i] = v;
        }
        k.name = c.text("FN").unwrap_or_default();
        if k.name.is_empty() {
            // §6.2.1 makes FN required; a card without one is named from N.
            let p = &k.parts;
            k.name = [&p[3], &p[1], &p[2], &p[0], &p[4]]
                .iter()
                .filter(|s| !s.is_empty())
                .cloned()
                .cloned()
                .collect::<Vec<_>>()
                .join(" ");
        }
        for p in &c.props {
            match p.name.as_str() {
                // tel: URIs (4.0) lose their scheme for showing.
                "TEL" => k.phones.push(Typed {
                    kinds: kinds(p),
                    value: line::unescape(p.value.strip_prefix("tel:").unwrap_or(&p.value)),
                }),
                "EMAIL" => k.emails.push(Typed { kinds: kinds(p), value: line::unescape(&p.value) }),
                "ADR" => {
                    let a = line::split(&p.value, ';');
                    let part = |i: usize| a.get(i).cloned().unwrap_or_default();
                    k.addresses.push(Typed {
                        kinds: kinds(p),
                        value: Address {
                            po_box: part(0),
                            extended: part(1),
                            street: part(2),
                            locality: part(3),
                            region: part(4),
                            code: part(5),
                            country: part(6),
                        },
                    });
                }
                "ORG" => {
                    k.org =
                        line::split(&p.value, ';').into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(", ")
                }
                "TITLE" => k.title = line::unescape(&p.value),
                "BDAY" => k.birthday = p.value.clone(),
                "NOTE" => k.note = line::unescape(&p.value),
                "UID" | "FN" | "N" | "VERSION" => {}
                _ => k.other.push(p.clone()),
            }
        }
        k
    }

    pub fn to_component(&self) -> Component {
        let mut c = Component::new("VCARD");
        c.push(Prop::new("VERSION", "4.0"));
        if !self.uid.is_empty() {
            c.push(Prop::new("UID", &line::escape(&self.uid)));
        }
        c.push(Prop::new("FN", &line::escape(&self.name)));
        if self.parts.iter().any(|s| !s.is_empty()) {
            let n: Vec<String> = self.parts.iter().map(|s| line::escape(s)).collect();
            c.push(Prop::new("N", &n.join(";")));
        }
        let typed = |name: &str, kinds: &[String], value: &str| {
            let mut p = Prop::new(name, value);
            if !kinds.is_empty() {
                p = p.param("TYPE", &kinds.join(","));
            }
            p
        };
        for t in &self.phones {
            c.push(typed("TEL", &t.kinds, &line::escape(&t.value)));
        }
        for t in &self.emails {
            c.push(typed("EMAIL", &t.kinds, &line::escape(&t.value)));
        }
        for t in &self.addresses {
            let a = &t.value;
            let v: Vec<String> = [&a.po_box, &a.extended, &a.street, &a.locality, &a.region, &a.code, &a.country]
                .iter()
                .map(|s| line::escape(s))
                .collect();
            c.push(typed("ADR", &t.kinds, &v.join(";")));
        }
        if !self.org.is_empty() {
            c.push(Prop::new("ORG", &line::escape(&self.org)));
        }
        if !self.title.is_empty() {
            c.push(Prop::new("TITLE", &line::escape(&self.title)));
        }
        if !self.birthday.is_empty() {
            c.push(Prop::new("BDAY", &self.birthday));
        }
        if !self.note.is_empty() {
            c.push(Prop::new("NOTE", &line::escape(&self.note)));
        }
        c.props.extend(self.other.iter().cloned());
        c
    }

    /// The name to sort by: family name, then given, else the shown name.
    pub fn sort_key(&self) -> String {
        let key = if self.parts[0].is_empty() {
            self.name.clone()
        } else {
            alloc::format!("{} {}", self.parts[0], self.parts[1])
        };
        key.to_lowercase()
    }

    /// Whether any of its words starts with what is typed (case ignored).
    pub fn matches(&self, query: &str) -> bool {
        let q = query.to_lowercase();
        if q.is_empty() {
            return true;
        }
        let hay = [self.name.as_str(), self.org.as_str()]
            .into_iter()
            .chain(self.emails.iter().map(|e| e.value.as_str()))
            .map(str::to_lowercase)
            .collect::<Vec<_>>();
        hay.iter().any(|h| h.split(|c: char| !c.is_alphanumeric()).any(|w| w.starts_with(&q)) || h.starts_with(&q))
            || self.phones.iter().any(|p| {
                let digits: String = p.value.chars().filter(char::is_ascii_digit).collect();
                !q.is_empty()
                    && q.chars().all(|c| c.is_ascii_digit() || c == '+')
                    && digits.contains(q.trim_start_matches('+'))
            })
    }
}

/// Every card in `text`.
pub fn parse(text: &str) -> Vec<Contact> {
    line::parse(text).iter().filter(|c| c.name == "VCARD").map(Contact::from_component).collect()
}

pub fn render(cards: &[Contact]) -> String {
    let mut out = String::new();
    for c in cards {
        line::write(&mut out, &c.to_component());
    }
    out
}

/// Add `new` cards to `cards`, one with a UID already there replacing
/// it; (new, replaced).
pub fn merge(cards: &mut Vec<Contact>, new: Vec<Contact>) -> (usize, usize) {
    let (mut n, mut r) = (0, 0);
    for c in new {
        match cards.iter_mut().find(|x| !c.uid.is_empty() && x.uid == c.uid) {
            Some(x) => {
                *x = c;
                r += 1;
            }
            None => {
                cards.push(c);
                n += 1;
            }
        }
    }
    (n, r)
}

pub fn kind_word(kinds: &[String]) -> String {
    kinds.first().map_or_else(String::new, |k| k.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CARDS: &str = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:urn:uuid:ada\r\nFN:Ada Lovelace\r\nN:Lovelace;Ada;;Countess;\r\nTEL;TYPE=cell,voice;VALUE=uri:tel:+44-20-7946-0958\r\nEMAIL;TYPE=work:ada@example.org\r\nADR;TYPE=home:;;12 St James\\'s Square;London;;SW1Y 4JH;United Kingdom\r\nORG:Analytical Engines;Notes\r\nBDAY:18151210\r\nNOTE:Wrote the first program\\, on paper.\r\nX-SOCIAL;TYPE=x:@ada\r\nEND:VCARD\r\nBEGIN:VCARD\r\nVERSION:3.0\r\nN:Hopper;Grace;;Rear Admiral;\r\nTEL;TYPE=WORK;TYPE=VOICE:+1 555 0100\r\nitem1.EMAIL;TYPE=INTERNET:grace@example.com\r\nEND:VCARD\r\n";

    #[test]
    fn reading_cards() {
        let cs = parse(CARDS);
        assert_eq!(cs.len(), 2);
        let a = &cs[0];
        assert_eq!(
            (a.name.as_str(), a.parts[0].as_str(), a.parts[3].as_str()),
            ("Ada Lovelace", "Lovelace", "Countess")
        );
        assert_eq!(a.phones[0], Typed { kinds: std::vec!["cell".into()], value: "+44-20-7946-0958".into() });
        assert_eq!(a.addresses[0].value.one_line(), "12 St James's Square, London, SW1Y 4JH, United Kingdom");
        assert_eq!((a.org.as_str(), a.birthday.as_str()), ("Analytical Engines, Notes", "18151210"));
        assert_eq!(a.note, "Wrote the first program, on paper.");
        let g = &cs[1];
        assert_eq!(g.name, "Rear Admiral Grace Hopper", "named from N without FN");
        assert_eq!(g.phones[0].kinds, ["work"]);
        assert_eq!(g.emails[0].value, "grace@example.com");
        assert!(a.matches("love") && a.matches("ANALYT") && a.matches("7946") && !a.matches("grace"));
        assert!(g.sort_key() < a.sort_key());
    }

    #[test]
    fn writing_and_merging() {
        let cs = parse(CARDS);
        let text = render(&cs);
        assert!(text.contains("VERSION:4.0") && text.contains("X-SOCIAL;TYPE=x:@ada"));
        let back = parse(&text);
        assert_eq!(back[0].phones, cs[0].phones);
        assert_eq!(back[0].addresses, cs[0].addresses);
        assert_eq!(back[0].note, cs[0].note);
        let mut all = cs.clone();
        let mut ada = cs[0].clone();
        ada.title = "Mathematician".into();
        assert_eq!(merge(&mut all, std::vec![ada, Contact { name: "New".into(), ..Contact::default() }]), (1, 1));
        assert_eq!((all.len(), all[0].title.as_str()), (3, "Mathematician"));
    }
}
