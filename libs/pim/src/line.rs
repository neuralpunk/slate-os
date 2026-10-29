// SPDX-License-Identifier: MIT OR Apache-2.0

//! Content lines, as iCalendar (RFC 5545 §3.1) and vCard (RFC 6350 §3.2)
//! share them: lines folded at 75 octets (a line break and a space or a
//! tab joins them again), `NAME;PARAM=VALUE,VALUE:value`, names in any
//! case, parameter values quoted when they hold `:`, `;` or `,`, and
//! components between `BEGIN:` and `END:`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// A property: its name (upper case), its parameters (names upper case),
/// and its value as written (escapes not undone).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Prop {
    pub name: String,
    pub params: Vec<(String, Vec<String>)>,
    pub value: String,
}

impl Prop {
    pub fn new(name: &str, value: &str) -> Prop {
        Prop { name: name.to_ascii_uppercase(), params: Vec::new(), value: value.to_string() }
    }

    /// A parameter; `value` may be a list ("work,voice").
    pub fn param(mut self, name: &str, value: &str) -> Prop {
        self.params.push((name.to_ascii_uppercase(), value.split(',').map(|v| v.to_string()).collect()));
        self
    }

    /// A parameter's values.
    pub fn get(&self, name: &str) -> Option<&[String]> {
        self.params.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_slice())
    }

    /// The values of every TYPE parameter, lower case (vCard writes
    /// `TYPE=home,cell` or `TYPE=HOME;TYPE=CELL`).
    pub fn types(&self) -> Vec<String> {
        self.params
            .iter()
            .filter(|(n, _)| n == "TYPE")
            .flat_map(|(_, v)| v.iter().flat_map(|x| x.split(',')).map(str::to_ascii_lowercase))
            .collect()
    }
}

/// A component: its name (VCALENDAR, VEVENT, VCARD...), its properties,
/// and the components inside it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Component {
    pub name: String,
    pub props: Vec<Prop>,
    pub children: Vec<Component>,
}

impl Component {
    pub fn new(name: &str) -> Component {
        Component { name: name.to_ascii_uppercase(), ..Component::default() }
    }

    pub fn prop(&self, name: &str) -> Option<&Prop> {
        self.props.iter().find(|p| p.name.eq_ignore_ascii_case(name))
    }

    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Prop> + 'a {
        self.props.iter().filter(move |p| p.name.eq_ignore_ascii_case(name))
    }

    /// A text property's value with its escapes undone.
    pub fn text(&self, name: &str) -> Option<String> {
        self.prop(name).map(|p| unescape(&p.value))
    }

    pub fn push(&mut self, p: Prop) {
        self.props.push(p);
    }
}

/// Undo the text escapes (RFC 5545 §3.3.11, RFC 6350 §3.4): `\\`, `\;`,
/// `\,`, and `\n` or `\N` for a line break.
pub fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n' | 'N') => out.push('\n'),
            Some(c) => out.push(c),
            None => out.push('\\'),
        }
    }
    out
}

/// Escape text for a value (and `;` too, which structured values use
/// to separate their parts).
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            c => out.push(c),
        }
    }
    out
}

/// Split a structured value at unescaped `sep` (`;` for N and ADR), each
/// part unescaped.
pub fn split(value: &str, sep: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut esc = false;
    for c in value.chars() {
        if esc {
            cur.push('\\');
            cur.push(c);
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else if c == sep {
            parts.push(unescape(&core::mem::take(&mut cur)));
        } else {
            cur.push(c);
        }
    }
    parts.push(unescape(&cur));
    parts
}

/// Unfold the text into logical lines.
fn unfold(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if (raw.starts_with(' ') || raw.starts_with('\t')) && !lines.is_empty() {
            if let Some(last) = lines.last_mut() {
                last.push_str(&raw[1..]);
            }
        } else if !raw.is_empty() {
            lines.push(raw.to_string());
        }
    }
    lines
}

/// One logical line as a property.
pub fn parse_line(line: &str) -> Option<Prop> {
    // The name and parameters end at the first ':' outside quotes.
    let mut quoted = false;
    let mut colon = None;
    for (i, c) in line.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ':' if !quoted => {
                colon = Some(i);
                break;
            }
            _ => {}
        }
    }
    let colon = colon?;
    let (head, value) = (&line[..colon], &line[colon + 1..]);
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in head.chars() {
        match c {
            '"' => quoted = !quoted,
            ';' if !quoted => parts.push(core::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    parts.push(cur);
    let mut it = parts.into_iter();
    let name = it.next()?.trim().to_ascii_uppercase();
    // A group prefix (vCard's `item1.TEL`) is dropped.
    let name = name.rsplit('.').next().unwrap_or(&name).to_string();
    if name.is_empty() {
        return None;
    }
    let params = it
        .map(|p| {
            // A bare value (vCard 2.1's `TEL;HOME:`) is a TYPE.
            let (n, v) = p.split_once('=').unwrap_or(("TYPE", &p));
            (n.trim().to_ascii_uppercase(), v.split(',').map(|x| x.to_string()).collect())
        })
        .collect();
    Some(Prop { name, params, value: value.to_string() })
}

/// The components in `text` (properties outside any component are
/// dropped). Unclosed components are closed at the end.
pub fn parse(text: &str) -> Vec<Component> {
    let mut stack: Vec<Component> = Vec::new();
    let mut top = Vec::new();
    for line in unfold(text) {
        let Some(p) = parse_line(&line) else { continue };
        match p.name.as_str() {
            "BEGIN" => stack.push(Component::new(p.value.trim())),
            "END" => {
                if let Some(c) = stack.pop() {
                    match stack.last_mut() {
                        Some(parent) => parent.children.push(c),
                        None => top.push(c),
                    }
                }
            }
            _ => {
                if let Some(c) = stack.last_mut() {
                    c.props.push(p);
                }
            }
        }
    }
    while let Some(c) = stack.pop() {
        match stack.last_mut() {
            Some(parent) => parent.children.push(c),
            None => top.push(c),
        }
    }
    top
}

/// Write a property, folded at 75 octets without splitting a character.
fn write_prop(out: &mut String, p: &Prop) {
    let mut line = p.name.clone();
    for (n, vs) in &p.params {
        line.push(';');
        line.push_str(n);
        line.push('=');
        let joined: Vec<String> = vs
            .iter()
            .map(|v| if v.contains([':', ';', ',']) { alloc::format!("\"{v}\"") } else { v.clone() })
            .collect();
        line.push_str(&joined.join(","));
    }
    line.push(':');
    line.push_str(&p.value);
    let mut width = 0;
    for c in line.chars() {
        let n = c.len_utf8();
        if width + n > 75 {
            out.push_str("\r\n ");
            width = 1;
        }
        out.push(c);
        width += n;
    }
    out.push_str("\r\n");
}

/// Write a component and its children.
pub fn write(out: &mut String, c: &Component) {
    write_prop(out, &Prop::new("BEGIN", &c.name));
    for p in &c.props {
        write_prop(out, p);
    }
    for child in &c.children {
        write(out, child);
    }
    write_prop(out, &Prop::new("END", &c.name));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_params_and_folding() {
        let text = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Lunch\\, then\r\n  a walk\\nby the river\r\nX-ALT;LANGUAGE=en;ALTREP=\"cid:a;b\":v\r\nitem1.TEL;TYPE=home,cell:+44\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let cs = parse(text);
        assert_eq!(cs.len(), 1);
        let ev = &cs[0].children[0];
        assert_eq!(ev.name, "VEVENT");
        assert_eq!(ev.text("summary").as_deref(), Some("Lunch, then a walk\nby the river"));
        let alt = ev.prop("X-ALT").unwrap();
        assert_eq!(alt.get("altrep"), Some(&["cid:a;b".to_string()][..]));
        let tel = ev.prop("TEL").unwrap();
        assert_eq!(tel.types(), ["home", "cell"]);
        assert_eq!(split("Lovelace;Ada;;Hon.\\;x;", ';'), ["Lovelace", "Ada", "", "Hon.;x", ""]);
    }

    #[test]
    fn writing_folds_and_round_trips() {
        let mut c = Component::new("VCARD");
        let long = "ü".repeat(60);
        c.push(Prop::new("NOTE", &escape(&long)));
        c.push(Prop::new("TEL", "+1 555").param("TYPE", "work,voice"));
        let mut out = String::new();
        write(&mut out, &c);
        assert!(out.lines().all(|l| l.trim_end_matches('\r').len() <= 75));
        let back = parse(&out);
        assert_eq!(back[0].text("NOTE").as_deref(), Some(long.as_str()));
        assert_eq!(back[0].prop("TEL").unwrap().types(), ["work", "voice"]);
        assert_eq!(unescape(&escape("a;b,c\\d\ne")), "a;b,c\\d\ne");
    }
}
