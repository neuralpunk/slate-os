// SPDX-License-Identifier: MIT OR Apache-2.0

//! Three-way merges of `/etc` (ADR 0087): what one system changed since
//! two systems parted, carried into the other.
//!
//! [`merge`] compares a base (the tree both had), ours (the target) and
//! theirs (the source of the changes), path by path. The account
//! databases merge record by record, other text line by line as diff3
//! does (Khanna, Kunal and Pierce, "A Formal Investigation of Diff3",
//! 2007), and what cannot be merged keeps ours, with theirs saved beside
//! it. [`archive`] and [`unarchive`] keep a base as a cpio archive.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// One path's version: what it is, its permission bits and owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    File { data: Vec<u8>, mode: u32, uid: u32, gid: u32 },
    Link { target: String, uid: u32, gid: u32 },
    Dir { mode: u32, uid: u32, gid: u32 },
}

/// A tree by path, relative to its root (`passwd`, `ssh/sshd_config`).
pub type Tree = BTreeMap<String, Node>;

/// A change to make to the target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Put(String, Node),
    Remove(String),
}

/// What a merge decided: the changes for the target (directories put
/// before what is in them, removed after), and the paths that conflicted
/// (each with `theirs` saved as `PATH.slate-merge` when it exists).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub changes: Vec<Change>,
    pub conflicts: Vec<String>,
    /// Files both sides changed that merged cleanly.
    pub merged: Vec<String>,
}

/// The suffix for `theirs` beside a conflicted file.
pub const CONFLICT_SUFFIX: &str = ".slate-merge";

/// Files of colon-separated records keyed by their first field (passwd(5),
/// group(5), shadow(5), gshadow(5), subuid(5)).
const KEYED: &[&str] = &["passwd", "group", "shadow", "gshadow", "subuid", "subgid"];

/// Text files longer than this many lines are not merged line by line
/// (the comparison is quadratic): both changing one is a conflict.
const MAX_LINES: usize = 20_000;

/// Carry what `theirs` changed since `base` into `ours`.
pub fn merge(base: &Tree, ours: &Tree, theirs: &Tree) -> Outcome {
    let mut out = Outcome::default();
    let paths: BTreeSet<&String> = base.keys().chain(ours.keys()).chain(theirs.keys()).collect();
    let mut removes = Vec::new();
    for p in paths {
        let (b, o, t) = (base.get(p), ours.get(p), theirs.get(p));
        if t == b || o == t {
            continue;
        }
        if o == b {
            match t {
                Some(n) => out.changes.push(Change::Put(p.clone(), n.clone())),
                None => removes.push(p.clone()),
            }
            continue;
        }
        // Both changed it, differently.
        match (b, o, t) {
            (_, Some(o @ Node::File { .. }), Some(t @ Node::File { .. })) => {
                let empty = Node::File { data: Vec::new(), mode: 0, uid: 0, gid: 0 };
                let b = match b {
                    Some(f @ Node::File { .. }) => f,
                    _ => &empty,
                };
                match merge_file(p, b, o, t) {
                    Some(n) => {
                        if Some(&n) != Some(o) {
                            out.changes.push(Change::Put(p.clone(), n));
                        }
                        out.merged.push(p.clone());
                    }
                    None => conflict(&mut out, p, Some(t)),
                }
            }
            _ => conflict(&mut out, p, t),
        }
    }
    // Deepest first, so a directory goes after what was in it.
    removes.sort_by_key(|p| core::cmp::Reverse(p.matches('/').count()));
    out.changes.extend(removes.into_iter().map(Change::Remove));
    out
}

fn conflict(out: &mut Outcome, path: &str, theirs: Option<&Node>) {
    out.conflicts.push(String::from(path));
    if let Some(t @ (Node::File { .. } | Node::Link { .. })) = theirs {
        out.changes.push(Change::Put(format!("{path}{CONFLICT_SUFFIX}"), t.clone()));
    }
}

/// Two changed versions of a file, merged: the contents as the text
/// merges say, the mode and owner as the attributes do. None for a
/// conflict.
fn merge_file(path: &str, b: &Node, o: &Node, t: &Node) -> Option<Node> {
    let (
        Node::File { data: bd, mode: bm, uid: bu, gid: bg },
        Node::File { data: od, mode: om, uid: ou, gid: og },
        Node::File { data: td, mode: tm, uid: tu, gid: tg },
    ) = (b, o, t)
    else {
        return None;
    };
    let pick = |b: u32, o: u32, t: u32| {
        if t == b {
            Some(o)
        } else if o == b || o == t {
            Some(t)
        } else {
            None
        }
    };
    let (mode, uid, gid) = (pick(*bm, *om, *tm)?, pick(*bu, *ou, *tu)?, pick(*bg, *og, *tg)?);
    let data = if od == td || td == bd {
        od.clone()
    } else if od == bd {
        td.clone()
    } else {
        let (b, o, t) = (text(bd)?, text(od)?, text(td)?);
        let name = path.rsplit('/').next().unwrap_or(path);
        let merged = if !path.contains('/') && KEYED.contains(&name) { keyed(&b, &o, &t) } else { lines3(&b, &o, &t)? };
        merged.into_bytes()
    };
    Some(Node::File { data, mode, uid, gid })
}

/// A file as text, if it is (UTF-8 without NULs).
fn text(d: &[u8]) -> Option<String> {
    if d.contains(&0) {
        return None;
    }
    core::str::from_utf8(d).ok().map(String::from)
}

/// The lines of a text, each with its newline (the last may lack one).
fn split_lines(s: &str) -> Vec<&str> {
    s.split_inclusive('\n').collect()
}

/// A record's key: its first colon-separated field; None for comments and
/// blank lines.
fn key(line: &str) -> Option<&str> {
    let l = line.trim_end_matches('\n');
    if l.is_empty() || l.starts_with('#') {
        return None;
    }
    Some(l.split(':').next().unwrap_or(l))
}

/// A keyed database merged record by record: ours' lines in their order,
/// changed or removed as theirs did; records theirs added at the end, in
/// theirs' order. A record both changed takes theirs.
fn keyed(b: &str, o: &str, t: &str) -> String {
    let by_key = |s: &str| -> BTreeMap<String, String> {
        split_lines(s).into_iter().filter_map(|l| Some((String::from(key(l)?), String::from(l)))).collect()
    };
    let (bk, ok, tk) = (by_key(b), by_key(o), by_key(t));
    let mut out = String::new();
    for line in split_lines(o) {
        let Some(k) = key(line) else {
            out += line;
            continue;
        };
        let (bl, tl) = (bk.get(k), tk.get(k));
        let line = if tl == bl {
            Some(String::from(line))
        } else {
            // theirs changed it (or removed it): take theirs.
            tl.cloned()
        };
        if let Some(l) = line {
            out += &l;
            if !l.ends_with('\n') {
                out.push('\n');
            }
        }
    }
    for line in split_lines(t) {
        if let Some(k) = key(line)
            && !ok.contains_key(k)
            && !bk.contains_key(k)
        {
            out += line;
            if !line.ends_with('\n') {
                out.push('\n');
            }
        }
    }
    out
}

/// The longest common subsequence of `a` and `b` as matched index pairs,
/// in order (dynamic programming; inputs are capped at `MAX_LINES`).
fn lcs(a: &[&str], b: &[&str]) -> Vec<(usize, usize)> {
    let (n, m) = (a.len(), b.len());
    let mut t = alloc::vec![0u32; (n + 1) * (m + 1)];
    let at = |i: usize, j: usize| i * (m + 1) + j;
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            t[at(i, j)] = if a[i] == b[j] { t[at(i + 1, j + 1)] + 1 } else { t[at(i + 1, j)].max(t[at(i, j + 1)]) };
        }
    }
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    while i < n && j < m {
        if a[i] == b[j] {
            out.push((i, j));
            i += 1;
            j += 1;
        } else if t[at(i + 1, j)] >= t[at(i, j + 1)] {
            i += 1;
        } else {
            j += 1;
        }
    }
    out
}

/// A three-way merge of text by lines (diff3's: the base split into runs
/// both sides keep unchanged and the chunks between; a chunk only one
/// side changed takes that side). None if both changed a chunk
/// differently.
fn lines3(b: &str, o: &str, t: &str) -> Option<String> {
    let (bl, ol, tl) = (split_lines(b), split_lines(o), split_lines(t));
    if bl.len().max(ol.len()).max(tl.len()) > MAX_LINES {
        return None;
    }
    let mo: BTreeMap<usize, usize> = lcs(&bl, &ol).into_iter().collect();
    let mt: BTreeMap<usize, usize> = lcs(&bl, &tl).into_iter().collect();
    let mut out = String::new();
    let (mut bi, mut oi, mut ti) = (0usize, 0usize, 0usize);
    loop {
        // The next base line both sides keep, after a chunk.
        let next = (bi..bl.len()).find(|i| mo.contains_key(i) && mt.contains_key(i));
        let (bend, oend, tend) = match next {
            Some(i) => (i, mo[&i], mt[&i]),
            None => (bl.len(), ol.len(), tl.len()),
        };
        let (bc, oc, tc) = (&bl[bi..bend], &ol[oi..oend], &tl[ti..tend]);
        let chunk: &[&str] = if oc == bc {
            tc
        } else if tc == bc || oc == tc {
            oc
        } else {
            return None;
        };
        for l in chunk {
            out += l;
        }
        match next {
            Some(i) => {
                out += bl[i];
                (bi, oi, ti) = (i + 1, oend + 1, tend + 1);
            }
            None => return Some(out),
        }
    }
}

/// A tree as a cpio (newc) archive whose first member, `.parent`, names
/// the system it came from: the base of a system (ADR 0087).
pub fn archive(parent: &str, tree: &Tree) -> Vec<u8> {
    let mut w = slate_cpio::Writer::new();
    w.file(".parent", 0o644, parent.as_bytes());
    for (path, n) in tree {
        match n {
            Node::File { data, mode, uid, gid } => {
                w.owned(path, slate_cpio::S_IFREG | (mode & 0o7777), *uid, *gid, data)
            }
            Node::Link { target, uid, gid } => {
                w.owned(path, slate_cpio::S_IFLNK | 0o777, *uid, *gid, target.as_bytes())
            }
            Node::Dir { mode, uid, gid } => w.owned(path, slate_cpio::S_IFDIR | (mode & 0o7777), *uid, *gid, &[]),
        }
    }
    w.finish()
}

/// A base back from [`archive`]: the system it came from and the tree.
pub fn unarchive(data: &[u8]) -> Option<(String, Tree)> {
    let mut parent = None;
    let mut tree = Tree::new();
    for e in slate_cpio::entries(data) {
        let e = e.ok()?;
        if e.name == ".parent" {
            parent = Some(String::from(core::str::from_utf8(e.data).ok()?));
            continue;
        }
        let perm = e.mode & 0o7777;
        let node = match e.mode & slate_cpio::S_IFMT {
            slate_cpio::S_IFREG => Node::File { data: e.data.to_vec(), mode: perm, uid: e.uid, gid: e.gid },
            slate_cpio::S_IFLNK => {
                Node::Link { target: String::from(core::str::from_utf8(e.data).ok()?), uid: e.uid, gid: e.gid }
            }
            slate_cpio::S_IFDIR => Node::Dir { mode: perm, uid: e.uid, gid: e.gid },
            _ => continue,
        };
        tree.insert(String::from(e.name), node);
    }
    Some((parent?, tree))
}

#[cfg(test)]
mod tests;
