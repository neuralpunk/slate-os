// SPDX-License-Identifier: MIT OR Apache-2.0

//! Install receipts (ADR 0183's phase 4), slate-boxd's side.
//!
//! Before a command runs as a box's root, slate-boxd keeps the box as it
//! is: a read-only snapshot, `box.UID.NAME.rN`. Afterwards it compares the
//! box with it, file by file (type, mode, owners, size, times and a link's
//! target; [`EXCLUDE`]'s folders and files left out: homes, caches, logs,
//! indexes rebuilt by tools), and keeps what changed as receipt N:
//! `.state/receipts/UID.NAME/N`, a header and a line per path, `A` added,
//! `M` changed, `D` removed.
//!
//! Undoing a receipt removes what it added and puts back, from its
//! snapshot, what it changed or removed; it refuses when a later receipt
//! touched one of the same paths. Rolling back to a receipt puts the whole
//! box back to its snapshot, dropping it and every later one.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::fs;

/// What a receipt doesn't record (inside the box): homes, what is made
/// fresh each session, caches and logs, and indexes tools rebuild after an
/// undo (`ldconfig`, `install-info`).
pub const EXCLUDE: &[&str] = &[
    "/home",
    "/root",
    "/tmp",
    "/run",
    "/proc",
    "/dev",
    "/sys",
    "/var/tmp",
    "/var/cache",
    "/var/log",
    "/var/lib/pacman/sync",
    "/etc/pacman.d/gnupg",
    "/etc/ld.so.cache",
    "/usr/share/info/dir",
];

/// What a file is, as a receipt compares it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sig {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: i64,
    pub mtime: (i64, i64),
    pub ctime: (i64, i64),
    pub link: Option<Vec<u8>>,
}

/// Whether `path` (inside the box) is left out.
pub fn excluded(path: &str) -> bool {
    EXCLUDE.iter().any(|e| path == *e || path.starts_with(&format!("{e}/")))
}

/// Every path under `root` (as the box sees it) with what it is.
pub fn scan(root: &str) -> Result<BTreeMap<String, Sig>, String> {
    let root = root.trim_end_matches('/');
    let top = fs::lstat(root.as_bytes()).map_err(|e| format!("{root}: {e}"))?;
    let mut out = BTreeMap::new();
    let mut stack = alloc::vec![String::new()];
    while let Some(rel) = stack.pop() {
        let full = format!("{root}{rel}");
        let Ok(st) = fs::lstat(full.as_bytes()) else { continue };
        if st.dev != top.dev {
            continue;
        }
        let link = st.is_symlink().then(|| fs::readlink(full.as_bytes()).unwrap_or_default());
        if !rel.is_empty() {
            out.insert(
                rel.clone(),
                Sig {
                    mode: st.mode,
                    uid: st.uid,
                    gid: st.gid,
                    size: if st.is_dir() { 0 } else { st.size },
                    mtime: if st.is_dir() { (0, 0) } else { (st.mtime, st.mtime_nsec) },
                    ctime: if st.is_dir() { (0, 0) } else { (st.ctime, st.ctime_nsec) },
                    link,
                },
            );
        }
        if st.is_dir() {
            for e in fs::read_dir(full.as_bytes()).unwrap_or_default() {
                let child = format!("{rel}/{}", slate_rt::lossy(&e.name));
                if !excluded(&child) {
                    stack.push(child);
                }
            }
        }
    }
    Ok(out)
}

/// What changed from `before` to `after`: (`A`, `M` or `D`, path), sorted
/// by path.
pub fn diff(before: &BTreeMap<String, Sig>, after: &BTreeMap<String, Sig>) -> Vec<(char, String)> {
    let mut out = Vec::new();
    for (p, s) in after {
        match before.get(p) {
            None => out.push(('A', p.clone())),
            Some(b) if b != s => out.push(('M', p.clone())),
            _ => {}
        }
    }
    for p in before.keys().filter(|p| !after.contains_key(*p)) {
        out.push(('D', p.clone()));
    }
    out.sort_by(|a, b| a.1.cmp(&b.1));
    out
}

/// A receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub n: u32,
    pub label: String,
    pub when: u64,
    pub command: String,
    pub entries: Vec<(char, String)>,
}

impl Receipt {
    pub fn text(&self) -> String {
        let mut s = format!("label {}\nwhen {}\ncommand {}\n", self.label, self.when, self.command);
        for (k, p) in &self.entries {
            s.push_str(&format!("{k} {p}\n"));
        }
        s
    }

    pub fn parse(n: u32, text: &str) -> Receipt {
        let mut r = Receipt { n, label: String::new(), when: 0, command: String::new(), entries: Vec::new() };
        for l in text.lines() {
            match l.split_once(' ') {
                Some(("label", v)) => r.label = String::from(v),
                Some(("when", v)) => r.when = v.parse().unwrap_or(0),
                Some(("command", v)) => r.command = String::from(v),
                Some((k, p)) if k.len() == 1 && "AMD".contains(k) => {
                    r.entries.push((k.chars().next().unwrap(), String::from(p)))
                }
                _ => {}
            }
        }
        r
    }
}

/// The paths receipt `n` shares with a later one (which would be undone
/// out from under it).
pub fn conflicts(receipts: &[Receipt], n: u32) -> Vec<String> {
    let Some(mine) = receipts.iter().find(|r| r.n == n) else { return Vec::new() };
    let later: Vec<&str> =
        receipts.iter().filter(|r| r.n > n).flat_map(|r| r.entries.iter().map(|(_, p)| p.as_str())).collect();
    mine.entries.iter().filter(|(_, p)| later.contains(&p.as_str())).map(|(_, p)| p.clone()).collect()
}

/// A receipt's label for a command: pacman's packages (`pacman: cmake`),
/// else the project's folder (`hello-2.12.3`), else the program.
pub fn label_for(argv: &[String], cwd: &str) -> String {
    let prog = argv.first().map(|a| String::from(a.rsplit('/').next().unwrap_or(a))).unwrap_or_default();
    if prog == "pacman" {
        let pkgs: Vec<&str> = argv[1..].iter().map(String::as_str).filter(|a| !a.starts_with('-')).collect();
        return if pkgs.is_empty() { String::from("pacman") } else { format!("pacman: {}", pkgs.join(" ")) };
    }
    let folder = cwd.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    let generic = ["", "root", "tmp"].contains(&folder) || cwd.trim_end_matches('/').matches('/').count() < 2;
    if generic { prog } else { String::from(folder) }
}

/// `label`, or `label (2)` and on when the receipts have it already.
pub fn unique_label(receipts: &[Receipt], label: &str) -> String {
    let taken = |l: &str| receipts.iter().any(|r| r.label == l);
    if !taken(label) {
        return String::from(label);
    }
    (2..).map(|i| format!("{label} ({i})")).find(|l| !taken(l)).unwrap()
}

/// Which receipt `which` names: its number, or its label.
pub fn find<'a>(receipts: &'a [Receipt], which: &str) -> Option<&'a Receipt> {
    if let Ok(n) = which.parse::<u32>() {
        return receipts.iter().find(|r| r.n == n);
    }
    receipts.iter().rev().find(|r| r.label == which)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn sig(size: i64) -> Sig {
        Sig { mode: 0o100644, uid: 0, gid: 0, size, mtime: (1, 0), ctime: (1, 0), link: None }
    }

    #[test]
    fn diffs() {
        let mut a = BTreeMap::new();
        a.insert("/usr/bin/x".to_string(), sig(1));
        a.insert("/etc/hosts".to_string(), sig(2));
        let mut b = a.clone();
        b.insert("/usr/local/bin/hello".to_string(), sig(3));
        b.get_mut("/etc/hosts").unwrap().size = 4;
        b.remove("/usr/bin/x");
        assert_eq!(
            diff(&a, &b),
            [('M', "/etc/hosts".into()), ('D', "/usr/bin/x".into()), ('A', "/usr/local/bin/hello".into())]
        );
        assert!(excluded("/home/ada/x") && excluded("/etc/ld.so.cache") && !excluded("/etc/hosts"));
        assert!(!excluded("/homework"));
    }

    #[test]
    fn receipts() {
        let r = Receipt {
            n: 3,
            label: "hello-2.12.3".into(),
            when: 1790000000,
            command: "make install".into(),
            entries: alloc::vec![('A', "/usr/local/bin/hello".into()), ('M', "/etc/a b".into())],
        };
        assert_eq!(Receipt::parse(3, &r.text()), r);
        let later = Receipt { n: 4, entries: alloc::vec![('M', "/usr/local/bin/hello".into())], ..r.clone() };
        let rs = [r.clone(), later];
        assert_eq!(conflicts(&rs, 3), ["/usr/local/bin/hello"]);
        assert!(conflicts(&rs, 4).is_empty());
        assert_eq!(find(&rs, "3").unwrap().n, 3);
        assert_eq!(find(&rs, "hello-2.12.3").unwrap().n, 4);
        assert_eq!(unique_label(&rs, "hello-2.12.3"), "hello-2.12.3 (2)");
        assert_eq!(unique_label(&rs, "nano"), "nano");
    }

    #[test]
    fn labels() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            label_for(&a(&["pacman", "-S", "--noconfirm", "cmake", "ninja"]), "/home/ada"),
            "pacman: cmake ninja"
        );
        assert_eq!(label_for(&a(&["make", "install"]), "/home/ada/src/hello-2.12.3"), "hello-2.12.3");
        assert_eq!(label_for(&a(&["/usr/bin/sh", "-c", "x"]), "/"), "sh");
        assert_eq!(label_for(&a(&["make"]), "/root"), "make");
    }
}
