// SPDX-License-Identifier: MIT OR Apache-2.0

//! OSC 8 hyperlinks (less(1), ^O^N and the rest; ADR 0164): `ESC ] 8 ;
//! params ; URI ST` starts a link, the same with an empty URI ends it,
//! ST being `ESC \` or BEL. The text between is the link's.

use alloc::string::String;
use alloc::vec::Vec;

/// A link in a line: the byte range from its opening sequence to its
/// closing one (or the line's end), its URI and its `id=` parameter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub start: usize,
    pub end: usize,
    pub uri: String,
    pub id: Option<String>,
}

/// The OSC sequence at `i` (which starts `ESC ]`): its body and the
/// index after its terminator.
pub fn osc_at(line: &[u8], i: usize) -> Option<(&[u8], usize)> {
    let body = i + 2;
    let mut j = body;
    while j < line.len() {
        match line[j] {
            0x07 => return Some((&line[body..j], j + 1)),
            0x1b if line.get(j + 1) == Some(&b'\\') => return Some((&line[body..j], j + 2)),
            _ => j += 1,
        }
    }
    None
}

/// The links in `line`, in order.
pub fn links(line: &[u8]) -> Vec<Link> {
    let mut out: Vec<Link> = Vec::new();
    let mut open: Option<Link> = None;
    let mut i = 0;
    while i + 1 < line.len() {
        if line[i] == 0x1b && line[i + 1] == b']' {
            let Some((body, next)) = osc_at(line, i) else { break };
            if let Some(rest) = body.strip_prefix(b"8;") {
                let (params, uri) = match rest.iter().position(|&c| c == b';') {
                    Some(p) => (&rest[..p], &rest[p + 1..]),
                    None => (&rest[..0], rest),
                };
                if let Some(mut l) = open.take() {
                    l.end = i;
                    out.push(l);
                }
                if !uri.is_empty() {
                    let id = params
                        .split(|&c| c == b':')
                        .find_map(|p| p.strip_prefix(b"id="))
                        .map(|v| String::from_utf8_lossy(v).into_owned());
                    open = Some(Link { start: i, end: line.len(), uri: String::from_utf8_lossy(uri).into_owned(), id });
                }
            }
            i = next;
            continue;
        }
        i += 1;
    }
    out.extend(open);
    out
}

/// The handler variable's scheme part (less(1), ^O^O): before the first
/// colon, in lower case, or `NONE`.
pub fn scheme(uri: &str) -> String {
    match uri.split_once(':') {
        Some((s, _)) => s.to_ascii_lowercase(),
        None => String::from("NONE"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn found() {
        let line =
            b"see \x1b]8;id=a;https://x.org/\x1b\\the site\x1b]8;;\x1b\\ and \x1b]8;;man:ls(1)\x07ls\x1b]8;;\x07.";
        let l = links(line);
        assert_eq!(l.len(), 2);
        assert_eq!((l[0].uri.as_str(), l[0].id.as_deref()), ("https://x.org/", Some("a")));
        assert_eq!(&line[l[0].start..l[0].start + 4], b"\x1b]8;");
        assert!(line[l[0].start..l[0].end].ends_with(b"the site"));
        assert_eq!((l[1].uri.as_str(), l[1].id.as_deref()), ("man:ls(1)", None));
        assert_eq!((scheme(&l[0].uri), scheme("#top")), (String::from("https"), String::from("NONE")));
        // One left open runs to the line's end.
        let open_line = b"\x1b]8;;file:///etc\x1b\\etc";
        assert_eq!(links(open_line)[0].end, open_line.len());
    }
}
