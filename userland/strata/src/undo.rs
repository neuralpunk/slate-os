// SPDX-License-Identifier: MIT OR Apache-2.0

//! What ctrl + z undoes: Files' window keeps its own list; the desktop's
//! changes (moves, copies and trashing through `files`, renames and new
//! folders by Strata) go to a journal in `~/.config/strata/desktop-undo`
//! that `files --undo` takes the last one from (ADR 0156's addendum).
//!
//! The journal is a line per change, newest last: a word, then its paths,
//! separated by tabs, with `\`, tab and newline written `\\`, `\t` and
//! `\n`. Only the last [`KEEP`] are kept.

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::fs;

/// A change that can be undone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// Moved to the trash: (where from, where it is in the trash).
    Trashed(Vec<(String, String)>),
    Renamed(String, String),
    /// Moved: (from, to).
    Moved(Vec<(String, String)>),
    /// Copies made (removed on undo).
    Copied(Vec<String>),
    MadeFolder(String),
}

/// The journal's file, in `~/.config/strata`.
pub const FILE: &str = "desktop-undo";
/// How many changes the journal keeps.
pub const KEEP: usize = 20;

impl Op {
    /// What undoing it does, for a menu ("Undo Move to Trash").
    pub fn label(&self) -> &'static str {
        match self {
            Op::Trashed(_) => "Undo Move to Trash",
            Op::Renamed(..) => "Undo Rename",
            Op::Moved(_) => "Undo Move",
            Op::Copied(_) => "Undo Copy",
            Op::MadeFolder(_) => "Undo New Folder",
        }
    }

    /// The journal's line for it (no newline).
    pub fn encode(&self) -> String {
        let (word, fields): (&str, Vec<&str>) = match self {
            Op::Trashed(v) => ("trashed", v.iter().flat_map(|(a, b)| [a.as_str(), b.as_str()]).collect()),
            Op::Renamed(a, b) => ("renamed", alloc::vec![a.as_str(), b.as_str()]),
            Op::Moved(v) => ("moved", v.iter().flat_map(|(a, b)| [a.as_str(), b.as_str()]).collect()),
            Op::Copied(v) => ("copied", v.iter().map(String::as_str).collect()),
            Op::MadeFolder(p) => ("made-folder", alloc::vec![p.as_str()]),
        };
        let mut out = String::from(word);
        for f in fields {
            out.push('\t');
            for c in f.chars() {
                match c {
                    '\\' => out.push_str("\\\\"),
                    '\t' => out.push_str("\\t"),
                    '\n' => out.push_str("\\n"),
                    c => out.push(c),
                }
            }
        }
        out
    }

    /// A journal line back, if it is one.
    pub fn decode(line: &str) -> Option<Op> {
        let mut parts = line.split('\t');
        let word = parts.next()?;
        let fields: Vec<String> = parts.map(unescape).collect();
        let pairs = |f: Vec<String>| -> Option<Vec<(String, String)>> {
            if f.is_empty() || f.len() % 2 != 0 {
                return None;
            }
            Some(f.chunks(2).map(|c| (c[0].clone(), c[1].clone())).collect())
        };
        Some(match word {
            "trashed" => Op::Trashed(pairs(fields)?),
            "moved" => Op::Moved(pairs(fields)?),
            "renamed" if fields.len() == 2 => Op::Renamed(fields[0].clone(), fields[1].clone()),
            "copied" if !fields.is_empty() => Op::Copied(fields),
            "made-folder" if fields.len() == 1 => Op::MadeFolder(fields[0].clone()),
            _ => return None,
        })
    }
}

fn unescape(f: &str) -> String {
    let mut out = String::new();
    let mut it = f.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some(c) => out.push(c),
            None => out.push('\\'),
        }
    }
    out
}

/// The journal's changes, oldest first (lines that aren't one are
/// skipped).
pub fn parse(text: &str) -> Vec<Op> {
    text.lines().filter_map(Op::decode).collect()
}

/// The journal for `ops`, the last [`KEEP`] of them.
pub fn render(ops: &[Op]) -> String {
    let from = ops.len().saturating_sub(KEEP);
    let mut out = String::new();
    for op in &ops[from..] {
        out.push_str(&op.encode());
        out.push('\n');
    }
    out
}

fn path(config: &str) -> String {
    alloc::format!("{config}/{FILE}")
}

fn read(config: &str) -> Vec<Op> {
    fs::read_file(path(config).as_bytes()).map(|t| parse(&slate_rt::lossy(&t))).unwrap_or_default()
}

fn write(config: &str, ops: &[Op]) {
    // `~/.config` may not be there yet.
    if let Some((parent, _)) = config.rsplit_once('/') {
        let _ = fs::mkdir(parent.as_bytes(), 0o755);
    }
    let _ = fs::mkdir(config.as_bytes(), 0o755);
    if let Err(e) = fs::write_file(path(config).as_bytes(), render(ops).as_bytes(), 0o600) {
        slate_rt::eprintln!("strata: the desktop's undo list: {e:?}");
    }
}

/// Add a change to the journal in `config` (`~/.config/strata`).
pub fn push(config: &str, op: Op) {
    let mut ops = read(config);
    ops.push(op);
    write(config, &ops);
}

/// The last change in the journal, taken off it.
pub fn pop(config: &str) -> Option<Op> {
    let mut ops = read(config);
    let op = ops.pop()?;
    write(config, &ops);
    Some(op)
}

/// The last change in the journal, left there.
pub fn last(config: &str) -> Option<Op> {
    read(config).pop()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn lines_round_trip() {
        let ops = alloc::vec![
            Op::Trashed(alloc::vec![("/h/Desktop/a b".to_string(), "/h/.local/share/Trash/files/a b".to_string())]),
            Op::Renamed("/h/Desktop/x\ty".to_string(), "/h/Desktop/new\\name\n".to_string()),
            Op::Moved(alloc::vec![("/a".to_string(), "/b".to_string()), ("/c".to_string(), "/d".to_string())]),
            Op::Copied(alloc::vec!["/h/Desktop/a (copy)".to_string()]),
            Op::MadeFolder("/h/Desktop/New Folder".to_string()),
        ];
        let text = render(&ops);
        assert_eq!(text.lines().count(), 5, "one line each, tabs and newlines escaped");
        assert_eq!(parse(&text), ops);
        assert_eq!(parse("junk\nmoved\t/odd\nrenamed\t/one\n"), alloc::vec![], "half a change is no change");
    }

    #[test]
    fn keeps_the_last_ones() {
        let ops: Vec<Op> = (0..KEEP + 5).map(|i| Op::MadeFolder(alloc::format!("/f{i}"))).collect();
        let kept = parse(&render(&ops));
        assert_eq!(kept.len(), KEEP);
        assert_eq!(kept[0], Op::MadeFolder("/f5".to_string()));
    }
}
