// SPDX-License-Identifier: MIT OR Apache-2.0

//! The history file (less(1), LESSHISTFILE; ADR 0164): search patterns
//! and shell commands kept between runs, in the format less was seen to
//! write: a `.less-history-file:` line, then sections (`.search`,
//! `.shell`) of lines each starting with `"`. Sections Slate's less
//! doesn't use (`.mark`) are kept as they were.

use alloc::vec::Vec;

/// The history: searches, shell commands, and other sections' lines.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct History {
    pub search: Vec<Vec<u8>>,
    pub shell: Vec<Vec<u8>>,
    pub other: Vec<Vec<u8>>,
}

const HEADER: &[u8] = b".less-history-file:";

/// The most lines kept of each kind (LESSHISTSIZE's default).
pub const SIZE: usize = 100;

impl History {
    pub fn parse(text: &[u8]) -> History {
        let mut h = History::default();
        let mut section: Option<u8> = None;
        for line in text.split(|&c| c == b'\n') {
            match line {
                HEADER | b"" => {}
                b".search" => section = Some(b's'),
                b".shell" => section = Some(b'!'),
                l if l.starts_with(b".") => {
                    section = Some(b'o');
                    h.other.push(l.to_vec());
                }
                l => match (section, l.strip_prefix(b"\"")) {
                    (Some(b's'), Some(v)) => h.search.push(v.to_vec()),
                    (Some(b'!'), Some(v)) => h.shell.push(v.to_vec()),
                    (Some(b'o'), _) => h.other.push(l.to_vec()),
                    _ => {}
                },
            }
        }
        h
    }

    pub fn text(&self, size: usize) -> Vec<u8> {
        let mut out = [HEADER, b"\n"].concat();
        for (name, list) in [(&b".search"[..], &self.search), (b".shell", &self.shell)] {
            out.extend_from_slice(name);
            out.push(b'\n');
            for l in &list[list.len().saturating_sub(size)..] {
                out.push(b'"');
                out.extend_from_slice(l);
                out.push(b'\n');
            }
        }
        for l in &self.other {
            out.extend_from_slice(l);
            out.push(b'\n');
        }
        out
    }

    /// Add a line to a list: the newest last, an earlier copy dropped.
    pub fn add(list: &mut Vec<Vec<u8>>, line: &[u8]) {
        if line.is_empty() {
            return;
        }
        list.retain(|l| l != line);
        list.push(line.to_vec());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let text = b".less-history-file:\n.search\n\"printk\n\"XSS\n.shell\n\"ls -l\n.mark\nm a 1 2 /x\n";
        let mut h = History::parse(text);
        assert_eq!(h.search, [b"printk".to_vec(), b"XSS".to_vec()]);
        assert_eq!(h.shell, [b"ls -l".to_vec()]);
        assert_eq!(h.text(SIZE), text, "unknown sections kept");
        History::add(&mut h.search, b"printk");
        assert_eq!(h.search, [b"XSS".to_vec(), b"printk".to_vec()]);
        assert!(History::parse(&h.text(1)).search == [b"printk".to_vec()], "only the newest kept");
    }
}
