// SPDX-License-Identifier: MIT OR Apache-2.0

//! A small XML reader (W3C XML 1.0's syntax, the parts AppStream data
//! uses): start and end tags with attributes, empty-element tags, text,
//! the five predefined entities and character references, CDATA
//! sections; declarations, processing instructions, comments and
//! DOCTYPEs are skipped. No namespaces or DTDs. It reads leniently:
//! what it can't make sense of ends the document.

use alloc::string::String;
use alloc::vec::Vec;

/// One piece of a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// A start tag (or an empty-element tag, `empty`), with its
    /// attributes unescaped.
    Start {
        name: &'a str,
        attrs: Vec<(&'a str, String)>,
        empty: bool,
    },
    End(&'a str),
    /// Text between tags, unescaped (whitespace as written).
    Text(String),
}

/// The text with its entities and character references replaced
/// (unknown ones are kept as written).
pub fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return String::from(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let Some(end) = rest.find(';').filter(|&e| e <= 12) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let name = &rest[1..end];
        let c = match name {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => name
                .strip_prefix("#x")
                .or_else(|| name.strip_prefix("#X"))
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| name.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32),
        };
        match c {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Reads events from a document, in order.
#[derive(Debug)]
pub struct Reader<'a> {
    s: &'a str,
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(s: &'a str) -> Reader<'a> {
        Reader { s, pos: 0 }
    }

    /// The attributes in a tag's text after its name.
    fn attrs(text: &'a str) -> Vec<(&'a str, String)> {
        let mut out = Vec::new();
        let mut rest = text.trim_start();
        while let Some(eq) = rest.find('=') {
            let name = rest[..eq].trim();
            let after = rest[eq + 1..].trim_start();
            let Some(q) = after.chars().next().filter(|c| *c == '"' || *c == '\'') else { break };
            let Some(close) = after[1..].find(q) else { break };
            out.push((name, unescape(&after[1..1 + close])));
            rest = after[close + 2..].trim_start();
        }
        out
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = Event<'a>;

    fn next(&mut self) -> Option<Event<'a>> {
        'next: loop {
            let rest = &self.s[self.pos..];
            if rest.is_empty() {
                return None;
            }
            if !rest.starts_with('<') {
                let end = rest.find('<').unwrap_or(rest.len());
                self.pos += end;
                return Some(Event::Text(unescape(&rest[..end])));
            }
            // What isn't a tag: skipped (or CDATA's text).
            for (open, close) in [("<?", "?>"), ("<!--", "-->"), ("<![CDATA[", "]]>")] {
                if let Some(body) = rest.strip_prefix(open) {
                    let end = body.find(close)?;
                    self.pos += open.len() + end + close.len();
                    if open == "<![CDATA[" {
                        return Some(Event::Text(String::from(&body[..end])));
                    }
                    continue 'next;
                }
            }
            if rest.starts_with("<!") {
                // A DOCTYPE (without an internal subset of tags).
                let end = rest.find('>')?;
                self.pos += end + 1;
                continue;
            }
            let end = rest.find('>')?;
            let tag = &rest[1..end];
            self.pos += end + 1;
            if let Some(name) = tag.strip_prefix('/') {
                return Some(Event::End(name.trim()));
            }
            let (tag, empty) = match tag.strip_suffix('/') {
                Some(t) => (t, true),
                None => (tag, false),
            };
            let name_end = tag.find(|c: char| c.is_whitespace()).unwrap_or(tag.len());
            let name = &tag[..name_end];
            if name.is_empty() {
                return None;
            }
            return Some(Event::Start { name, attrs: Reader::attrs(&tag[name_end..]), empty });
        }
    }
}

/// Runs of whitespace as one space, trimmed (how AppStream text reads).
pub fn collapse(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for w in s.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(w);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn events() {
        let doc = "<?xml version=\"1.0\"?>\n<!-- hi --><a x='1 &amp; 2' y=\"&#x41;\"><b/>t&lt;u<![CDATA[<raw>]]></a>";
        let ev: Vec<Event<'_>> = Reader::new(doc).collect();
        assert_eq!(
            ev,
            vec![
                Event::Text("\n".into()),
                Event::Start { name: "a", attrs: vec![("x", "1 & 2".into()), ("y", "A".into())], empty: false },
                Event::Start { name: "b", attrs: vec![], empty: true },
                Event::Text("t<u".into()),
                Event::Text("<raw>".into()),
                Event::End("a"),
            ]
        );
        assert_eq!(unescape("a &bogus; &#233; &"), "a &bogus; é &");
        assert_eq!(collapse("  two\n   words "), "two words");
        // A broken document just ends.
        assert_eq!(Reader::new("<a").count(), 0);
    }
}
