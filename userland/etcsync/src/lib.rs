// SPDX-License-Identifier: MIT OR Apache-2.0

//! `/etc` across updates and rollbacks on a running system (ADR 0087):
//! the base each new system starts from, kept in `/var`, and the
//! three-way merge of one system's `/etc` changes into another's
//! (`slate_etcmerge`).

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_etcmerge::{Change, Node, Outcome, Tree};
use slate_rt::{fs, lossy};

/// Where the bases are: one file per system, named after it.
pub const BASES: &str = "/var/lib/slate-update/bases";

fn base_path(system: &str) -> String {
    format!("{BASES}/{system}")
}

/// The tree under `root` (`/etc`, or a mounted system's `/run/x/etc`).
pub fn read_tree(root: &str) -> Result<Tree, String> {
    let mut tree = Tree::new();
    walk(root, "", &mut tree)?;
    Ok(tree)
}

fn walk(root: &str, rel: &str, tree: &mut Tree) -> Result<(), String> {
    let dir = if rel.is_empty() { String::from(root) } else { format!("{root}/{rel}") };
    let mut names: Vec<String> = fs::read_dir(dir.as_bytes())
        .map_err(|e| format!("{dir}: {e}"))?
        .into_iter()
        .map(|e| String::from(lossy(&e.name)))
        .filter(|n| n != "." && n != "..")
        .collect();
    names.sort();
    for name in names {
        let path = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
        let full = format!("{root}/{path}");
        let st = fs::lstat(full.as_bytes()).map_err(|e| format!("{full}: {e}"))?;
        let (perm, uid, gid) = (st.mode & 0o7777, st.uid, st.gid);
        if st.is_dir() {
            tree.insert(path.clone(), Node::Dir { mode: perm, uid, gid });
            walk(root, &path, tree)?;
        } else if st.is_symlink() {
            let target = fs::readlink(full.as_bytes()).map_err(|e| format!("{full}: {e}"))?;
            tree.insert(path, Node::Link { target: String::from(lossy(&target)), uid, gid });
        } else if st.is_file() {
            let data = fs::read_file(full.as_bytes()).map_err(|e| format!("{full}: {e}"))?;
            tree.insert(path, Node::File { data, mode: perm, uid, gid });
        }
        // Devices, sockets and pipes in /etc are left alone.
    }
    Ok(())
}

/// Record `system`'s base: the tree at `etc` (an `/etc`) as it is now,
/// `system` being made from `parent` (ADR 0087).
pub fn save_base(system: &str, parent: &str, etc: &str) -> Result<(), String> {
    let tree = read_tree(etc)?;
    let mut at = String::new();
    for part in BASES.split('/').filter(|p| !p.is_empty()) {
        at = format!("{at}/{part}");
        let _ = fs::mkdir(at.as_bytes(), 0o700);
    }
    let path = base_path(system);
    let tmp = format!("{path}.new");
    fs::write_file(tmp.as_bytes(), &slate_etcmerge::archive(parent, &tree), 0o600)
        .and_then(|()| fs::rename(tmp.as_bytes(), path.as_bytes()))
        .map_err(|e| format!("{path}: {e}"))
}

/// `system`'s base: the system it was made from and its `/etc` then.
pub fn base(system: &str) -> Option<(String, Tree)> {
    slate_etcmerge::unarchive(&fs::read_file(base_path(system).as_bytes()).ok()?)
}

/// Delete `system`'s base (an update given up).
pub fn drop_base(system: &str) {
    let _ = fs::unlink(base_path(system).as_bytes());
}

/// Delete the bases of systems not in `keep`.
pub fn prune_bases(keep: &[String]) {
    for e in fs::read_dir(BASES.as_bytes()).unwrap_or_default() {
        let name = String::from(lossy(&e.name));
        if name != "." && name != ".." && !keep.contains(&name) {
            let _ = fs::unlink(base_path(&name).as_bytes());
        }
    }
}

/// Make `changes` under `root`: files go in whole (written beside, then
/// renamed over), with their mode and owner.
pub fn apply(root: &str, changes: &[Change]) -> Result<(), String> {
    for c in changes {
        match c {
            Change::Put(path, node) => put(&format!("{root}/{path}"), node)?,
            Change::Remove(path) => {
                let full = format!("{root}/{path}");
                let is_dir = fs::lstat(full.as_bytes()).is_ok_and(|s| s.is_dir());
                let r = if is_dir { fs::rmdir(full.as_bytes()) } else { fs::unlink(full.as_bytes()) };
                // Already gone is fine; a directory with something left in
                // it (the target's own) stays.
                if let Err(e) = r
                    && fs::exists(full.as_bytes())
                    && !is_dir
                {
                    return Err(format!("{full}: {e}"));
                }
            }
        }
    }
    Ok(())
}

fn put(full: &str, node: &Node) -> Result<(), String> {
    let err = |e: slate_rt::Errno| format!("{full}: {e}");
    match node {
        Node::Dir { mode, uid, gid } => {
            if !fs::lstat(full.as_bytes()).is_ok_and(|s| s.is_dir()) {
                let _ = fs::unlink(full.as_bytes());
                fs::mkdir(full.as_bytes(), *mode).map_err(err)?;
            }
            fs::chown(full.as_bytes(), *uid, *gid).map_err(err)?;
            fs::chmod(full.as_bytes(), *mode).map_err(err)
        }
        Node::File { data, mode, uid, gid } => {
            let tmp = format!("{full}.slate-new");
            fs::write_file(tmp.as_bytes(), data, 0o600).map_err(err)?;
            fs::chown(tmp.as_bytes(), *uid, *gid).map_err(err)?;
            fs::chmod(tmp.as_bytes(), *mode).map_err(err)?;
            fs::rename(tmp.as_bytes(), full.as_bytes()).map_err(err)
        }
        Node::Link { target, uid, gid } => {
            let tmp = format!("{full}.slate-new");
            let _ = fs::unlink(tmp.as_bytes());
            fs::symlink(target.as_bytes(), tmp.as_bytes()).map_err(err)?;
            fs::lchown(tmp.as_bytes(), *uid, *gid).map_err(err)?;
            fs::rename(tmp.as_bytes(), full.as_bytes()).map_err(err)
        }
    }
}

/// Carry what `source_etc` changed since `system`'s base into
/// `target_etc`, if that base came from `expect_parent` (None: any).
/// Returns what was merged, or None when there is no fitting base.
pub fn carry(
    base_of: &str,
    expect_parent: Option<&str>,
    source_etc: &str,
    target_etc: &str,
) -> Result<Option<Outcome>, String> {
    let Some((parent, base)) = base(base_of) else { return Ok(None) };
    if expect_parent.is_some_and(|p| p != parent) {
        return Ok(None);
    }
    let (ours, theirs) = (read_tree(target_etc)?, read_tree(source_etc)?);
    let outcome = slate_etcmerge::merge(&base, &ours, &theirs);
    apply(target_etc, &outcome.changes)?;
    Ok(Some(outcome))
}

/// A line about a merge, for the user.
pub fn describe(o: &Outcome) -> String {
    let puts = o
        .changes
        .iter()
        .filter(|c| matches!(c, Change::Put(p, _) if !p.ends_with(slate_etcmerge::CONFLICT_SUFFIX)))
        .count();
    let removes = o.changes.iter().filter(|c| matches!(c, Change::Remove(_))).count();
    let mut s = format!("/etc: {puts} changed, {removes} removed");
    if !o.merged.is_empty() {
        s += &format!(", merged {}", o.merged.join(" "));
    }
    if !o.conflicts.is_empty() {
        s += &format!(
            "; conflicts in {} (the other side's version is beside each as NAME{})",
            o.conflicts.join(" "),
            slate_etcmerge::CONFLICT_SUFFIX
        );
    }
    s
}
