// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tags (`-t`, `:t`; ADR 0149): a ctags file's lines are `NAME<TAB>FILE<TAB>ADDRESS`,
//! the address a line number or a pattern (`/^text$/` or `?...?`, with
//! `;"` and extension fields after it), as ctags(1) writes them.

use alloc::vec::Vec;

/// Where a tag points.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    /// A 1-based line number.
    Line(usize),
    /// The text of a line: anchored at its start and end when the
    /// pattern said so (ctags patterns are otherwise literal).
    Text { text: Vec<u8>, start: bool, end: bool },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tag {
    pub file: Vec<u8>,
    pub address: Address,
}

/// Every entry for `name` in tags file text `data`, in order.
pub fn find(data: &[u8], name: &[u8]) -> Vec<Tag> {
    let mut out = Vec::new();
    for line in data.split(|&c| c == b'\n') {
        let mut f = line.splitn(3, |&c| c == b'\t');
        let (Some(n), Some(file), Some(addr)) = (f.next(), f.next(), f.next()) else { continue };
        if n != name {
            continue;
        }
        if let Some(address) = address(addr) {
            out.push(Tag { file: file.to_vec(), address });
        }
    }
    out
}

fn address(a: &[u8]) -> Option<Address> {
    // The address ends where `;"` begins the extension fields.
    let a = match a.windows(2).position(|w| w == b";\"") {
        Some(i) => &a[..i],
        None => a,
    };
    let a = a.trim_ascii_end();
    if !a.is_empty() && a.iter().all(u8::is_ascii_digit) {
        return core::str::from_utf8(a).ok()?.parse().ok().map(Address::Line);
    }
    let delim = *a.first()?;
    if delim != b'/' && delim != b'?' {
        return None;
    }
    let body = a.get(1..)?.strip_suffix(&[delim]).unwrap_or(&a[1..]);
    let (start, body) = match body.strip_prefix(b"^") {
        Some(b) => (true, b),
        None => (false, body),
    };
    let (end, body) = match body.strip_suffix(b"$") {
        Some(b) if !b.ends_with(b"\\") => (true, b),
        _ => (false, body),
    };
    // `\/` (or `\?`) and `\\` stand for themselves.
    let mut text = Vec::new();
    let mut i = 0;
    while i < body.len() {
        if body[i] == b'\\' && i + 1 < body.len() {
            text.push(body[i + 1]);
            i += 2;
        } else {
            text.push(body[i]);
            i += 1;
        }
    }
    Some(Address::Text { text, start, end })
}

impl Address {
    /// Whether line `l` is the one this points at (for patterns).
    pub fn matches(&self, l: &[u8]) -> bool {
        match self {
            Address::Line(_) => false,
            Address::Text { text, start: true, end: true } => l == text.as_slice(),
            Address::Text { text, start: true, end: false } => l.starts_with(text),
            Address::Text { text, start: false, end: true } => l.ends_with(text),
            Address::Text { text, .. } => l.windows(text.len().max(1)).any(|w| w == text.as_slice()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctags_lines() {
        let data = b"!_TAG_FILE_FORMAT\t2\t/extended format/\nmain\tsrc/main.c\t/^int main(void)$/;\"\tf\n\
                     main\tother.c\t42;\"\tf\nhelper\tsrc/a\\/b.c\t?^static int helper\\/x(?\n";
        let t = find(data, b"main");
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].file, b"src/main.c");
        assert!(t[0].address.matches(b"int main(void)"));
        assert!(!t[0].address.matches(b" int main(void)"));
        assert_eq!(t[1].address, Address::Line(42));
        let h = find(data, b"helper");
        assert!(h[0].address.matches(b"static int helper/x(int a)"));
        assert!(find(data, b"nothing").is_empty());
    }
}
