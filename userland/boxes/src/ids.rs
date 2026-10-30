// SPDX-License-Identifier: MIT OR Apache-2.0

//! IDs of a box's own (ADR 0183). Each box and each base has a number k,
//! and with it the 65536 user and group IDs from [`FIRST`] + k * 65536.
//! In a box, IDs 0 to 65535 are that range, except [`PERSON`], which is
//! the person who owns the box; in a base, all of them are the range.
//!
//! slate-boxd keeps the numbers it gave out in `.state/numbers`, a line
//! each: `k kind owner name` (`base 0 arch`, `box 1000 dev`).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::fs;

/// The first ID of number 0's range.
pub const FIRST: u32 = 0x4000_0000;
/// IDs in a range.
pub const SIZE: u32 = 0x1_0000;
/// The person's ID inside their boxes (user and group).
pub const PERSON: u32 = 1000;
/// The highest number: ranges stay below 2^32 - 1 (Linux's -1).
pub const MAX_NUMBER: u32 = (u32::MAX - FIRST) / SIZE - 1;

/// Where number `k`'s range starts.
pub fn first_of(k: u32) -> u32 {
    FIRST + k * SIZE
}

/// A uid_map or gid_map (user_namespaces(7)) for number `k`'s range, with
/// `person` (their ID outside) as [`PERSON`] when given.
pub fn map(k: u32, person: Option<u32>) -> String {
    let r = first_of(k);
    match person {
        None => format!("0 {r} {SIZE}\n"),
        Some(p) => format!("0 {r} {PERSON}\n{PERSON} {p} 1\n{} {} {}\n", PERSON + 1, r + PERSON + 1, SIZE - PERSON - 1),
    }
}

/// An ID moved from range `from` to range `to` (IDs outside `from` stay).
pub fn moved(id: u32, from: u32, to: u32) -> u32 {
    if (first_of(from)..first_of(from) + SIZE).contains(&id) { id - first_of(from) + first_of(to) } else { id }
}

/// An ID given as it is on disk (`from_zero`: plain 0..65535, as a
/// tarball unpacked by root has them) moved into range `to`.
pub fn into_range(id: u32, to: u32) -> u32 {
    if id < SIZE { first_of(to) + id } else { id }
}

/// Move every file's owner and group under `root` (not crossing into
/// other file systems) with `f`; set-user-ID and set-group-ID bits are
/// kept (chown(2) clears them). How many changed.
pub fn shift_tree(root: &str, f: &dyn Fn(u32) -> u32) -> Result<u64, String> {
    let top = fs::lstat(root.as_bytes()).map_err(|e| format!("{root}: {e}"))?;
    let mut count = 0;
    let mut stack = alloc::vec![String::from(root)];
    while let Some(path) = stack.pop() {
        let st = fs::lstat(path.as_bytes()).map_err(|e| format!("{path}: {e}"))?;
        if st.dev != top.dev {
            continue;
        }
        let (uid, gid) = (f(st.uid), f(st.gid));
        if (uid, gid) != (st.uid, st.gid) {
            fs::lchown(path.as_bytes(), uid, gid).map_err(|e| format!("{path}: {e}"))?;
            if !st.is_symlink() && st.mode & 0o6000 != 0 {
                fs::chmod(path.as_bytes(), st.mode & 0o7777).map_err(|e| format!("{path}: {e}"))?;
            }
            count += 1;
        }
        if st.is_dir() {
            for e in fs::read_dir(path.as_bytes()).map_err(|e| format!("{path}: {e}"))? {
                stack.push(format!("{}/{}", path.trim_end_matches('/'), slate_rt::lossy(&e.name)));
            }
        }
    }
    Ok(count)
}

/// A number given out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Number {
    pub k: u32,
    /// `base` or `box`.
    pub kind: String,
    pub owner: u32,
    pub name: String,
}

/// The numbers given out.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Numbers(pub Vec<Number>);

impl Numbers {
    pub fn parse(text: &str) -> Numbers {
        Numbers(
            text.lines()
                .filter_map(|l| {
                    let mut w = l.split_whitespace();
                    let k = w.next()?.parse().ok()?;
                    let kind = String::from(w.next()?);
                    let owner = w.next()?.parse().ok()?;
                    let name = String::from(w.next()?);
                    Some(Number { k, kind, owner, name })
                })
                .collect(),
        )
    }

    pub fn text(&self) -> String {
        self.0.iter().map(|n| format!("{} {} {} {}\n", n.k, n.kind, n.owner, n.name)).collect()
    }

    pub fn find(&self, kind: &str, owner: u32, name: &str) -> Option<&Number> {
        self.0.iter().find(|n| n.kind == kind && n.owner == owner && n.name == name)
    }

    /// Give out the lowest free number.
    pub fn give(&mut self, kind: &str, owner: u32, name: &str) -> Result<u32, String> {
        let k = (0..=MAX_NUMBER).find(|k| !self.0.iter().any(|n| n.k == *k)).ok_or("no ID range is left")?;
        self.0.push(Number { k, kind: String::from(kind), owner, name: String::from(name) });
        self.0.sort_by_key(|n| n.k);
        Ok(k)
    }

    pub fn take_back(&mut self, kind: &str, owner: u32, name: &str) {
        self.0.retain(|n| !(n.kind == kind && n.owner == owner && n.name == name));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps() {
        assert_eq!(map(0, None), "0 1073741824 65536\n");
        assert_eq!(map(2, Some(1000)), "0 1073872896 1000\n1000 1000 1\n1001 1073873897 64535\n");
        assert_eq!(map(1, Some(1234)), "0 1073807360 1000\n1000 1234 1\n1001 1073808361 64535\n");
        // The last range fits.
        assert!(first_of(MAX_NUMBER) as u64 + SIZE as u64 <= u32::MAX as u64);
        assert_eq!(moved(first_of(3) + 7, 3, 5), first_of(5) + 7);
        assert_eq!(moved(1000, 3, 5), 1000);
        assert_eq!(into_range(0, 4), first_of(4));
        assert_eq!(into_range(first_of(4) + 2, 9), first_of(4) + 2);
    }

    #[test]
    fn numbers() {
        let mut n = Numbers::parse("0 base 0 arch\n2 box 1000 dev\n");
        assert_eq!(n.give("box", 1000, "two").unwrap(), 1);
        assert_eq!(n.give("box", 1001, "dev").unwrap(), 3);
        assert_eq!(n.find("box", 1000, "two").unwrap().k, 1);
        n.take_back("box", 1000, "dev");
        assert_eq!(n.text(), "0 base 0 arch\n1 box 1000 two\n3 box 1001 dev\n");
        assert_eq!(Numbers::parse(&n.text()), n);
    }
}
