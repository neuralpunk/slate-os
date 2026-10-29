// SPDX-License-Identifier: MIT OR Apache-2.0

//! The dentry cache's upkeep: misses (negative entries) and the shrinker.
//!
//! A directory's dentry caches its children as they are looked up and, on
//! file systems that ask for it ([`Inode::cache_misses`]), the names it
//! doesn't have. Both are trimmed when the cache grows past a limit set by
//! the memory there is, when the page cache could not free what reclaim
//! asked of it, and by `/proc/sys/vm/drop_caches`: a clock sweep over the
//! tree drops what nothing has found since it last passed. Only leaves go
//! (no cached children or misses, nothing mounted on them, held by nobody
//! but the cache), and only where the file system keeps an inode's
//! identity without its dentry ([`Inode::dentry_reclaimable`]); a dropped
//! name is looked up again when it is next wanted.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::ops::Bound;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::{ALIASES, Dentry, Inode, LIVE_DENTRIES, MOUNTS, Result};
use crate::abi::linux::errno::*;

/// Misses cached (negative entries), for the shrinker and /proc/slate_sched.
pub static MISSES: AtomicU64 = AtomicU64::new(0);
/// Set when the page cache couldn't free what reclaim asked for: the next
/// tick halves the cache.
static PRESSURE: AtomicBool = AtomicBool::new(false);
/// Dentries left after a sweep that couldn't free what it wanted (most are
/// in use): the next sweep waits until the cache has grown past this by an
/// eighth of the limit, rather than walking the tree every second for
/// nothing.
static SETTLED: AtomicU64 = AtomicU64::new(0);

/// Names looked at under one directory's lock (it masks interrupts).
const BATCH: usize = 256;

/// A directory's misses: names it doesn't have, each with its clock bit.
#[derive(Default)]
pub struct Misses {
    names: BTreeMap<String, bool>,
    /// Bumped whenever a name is added to the directory, so a lookup that
    /// raced with the add doesn't record the name as missing.
    generation: u64,
}

impl Misses {
    /// ENOENT if `name` is a cached miss; otherwise the generation that a
    /// miss the following lookup finds is noted at.
    pub(super) fn check(&mut self, name: &str) -> Result<u64> {
        match self.names.get_mut(name) {
            Some(used) => {
                *used = true;
                Err(ENOENT)
            }
            None => Ok(self.generation),
        }
    }

    /// Whether `name` is a cached miss.
    pub(super) fn has(&mut self, name: &str) -> bool {
        self.check(name).is_err()
    }

    /// Record `name` as missing, unless a name was added since `generation`.
    pub(super) fn note(&mut self, name: &str, generation: u64) {
        if self.generation == generation && self.names.insert(String::from(name), true).is_none() {
            MISSES.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn len(&self) -> usize {
        self.names.len()
    }

    fn added(&mut self, name: &str) {
        self.generation += 1;
        if self.names.remove(name).is_some() {
            MISSES.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// A dentry with `n` misses went away.
pub(super) fn dropped_misses(n: usize) {
    if n > 0 {
        MISSES.fetch_sub(n as u64, Ordering::Relaxed);
    }
}

/// A file system added `name` to the directory `dir` (a create, mkdir,
/// symlink, link or a rename's new name): every dentry of `dir` forgets it
/// as a miss. File systems whose directories cache misses call it for every
/// name they add, with no lock of theirs held.
pub fn name_added(dir: &dyn Inode, name: &str) {
    let key = core::ptr::from_ref(dir).cast::<()>() as usize;
    let all: Vec<Arc<Dentry>> =
        ALIASES.lock().get(&key).map(|v| v.iter().filter_map(Weak::upgrade).collect()).unwrap_or_default();
    for d in &all {
        d.missing.lock().added(name);
    }
    // Dropped only now, with no lock held (dropping a dentry takes ALIASES).
    drop(all);
}

/// How many dentries the cache keeps before the shrinker trims it: about
/// 1/64 of memory at some 512 bytes for a dentry and the inode it holds,
/// and never fewer than 16 384. Misses get a quarter of that.
fn limit() -> u64 {
    let bytes = crate::mm::frame::stats().usable_frames * crate::mm::PAGE_SIZE;
    (bytes / 64 / 512).max(16384)
}

/// The page cache couldn't free what reclaim asked for. Only sets a flag:
/// reclaim runs where dentries can't be dropped.
pub fn pressure() {
    PRESSURE.store(true, Ordering::Relaxed);
}

/// Keep the cache within its limit (the flusher calls it every second):
/// past the limit, trim to 7/8 of it; under memory pressure, halve it.
pub fn tick() {
    let limit = limit();
    let live = LIVE_DENTRIES.load(Ordering::Relaxed);
    let misses = MISSES.load(Ordering::Relaxed);
    let pressed = PRESSURE.swap(false, Ordering::Relaxed);
    let (keep, keep_misses) = if pressed {
        (live / 2, misses / 2)
    } else if live > limit.max(SETTLED.load(Ordering::Relaxed) + limit / 8) || misses > limit / 4 {
        (limit * 7 / 8, limit / 4 * 7 / 8)
    } else {
        return;
    };
    let want = live.saturating_sub(keep);
    let (freed, _) = shrink(&roots(), want, misses.saturating_sub(keep_misses), false);
    let left = LIVE_DENTRIES.load(Ordering::Relaxed);
    SETTLED.store(if freed < want { left } else { 0 }, Ordering::Relaxed);
}

/// Drop every cached name nothing uses, and every miss
/// (`/proc/sys/vm/drop_caches` 2). Returns the dentries and misses dropped.
pub fn drop_all() -> (u64, u64) {
    let r = shrink(&roots(), u64::MAX, u64::MAX, true);
    SETTLED.store(0, Ordering::Relaxed);
    r
}

/// The roots of every mount in every namespace, once each.
fn roots() -> Vec<Arc<Dentry>> {
    let mut r: Vec<Arc<Dentry>> = MOUNTS.lock().iter().map(|m| m.root.clone()).collect();
    r.sort_by_key(|d| Arc::as_ptr(d) as usize);
    r.dedup_by(|a, b| Arc::ptr_eq(a, b));
    r
}

/// Drop up to `want` idle dentries and `want_misses` misses below `roots`;
/// unless `force`, what was found since the last pass gets a second chance.
/// Returns what was dropped.
fn shrink(roots: &[Arc<Dentry>], want: u64, want_misses: u64, force: bool) -> (u64, u64) {
    let (mut freed, mut freed_misses) = (0, 0);
    // Two passes: the first may only clear the bits of names used since.
    for _ in 0..2 {
        let mut dirs: Vec<Arc<Dentry>> = roots.to_vec();
        while let Some(d) = dirs.pop() {
            if freed >= want && freed_misses >= want_misses {
                return (freed, freed_misses);
            }
            freed_misses += d.trim_misses(want_misses - freed_misses, force);
            freed += d.trim_children(want - freed, force, &mut dirs);
        }
        if force {
            break;
        }
    }
    (freed, freed_misses)
}

impl Dentry {
    /// Drop up to `want` of this directory's misses.
    fn trim_misses(&self, want: u64, force: bool) -> u64 {
        if want == 0 {
            return 0;
        }
        let mut m = self.missing.lock();
        let before = m.names.len();
        let mut left = want;
        m.names.retain(|_, used| {
            if left == 0 {
                return true;
            }
            if *used && !force {
                *used = false;
                return true;
            }
            left -= 1;
            false
        });
        let n = (before - m.names.len()) as u64;
        MISSES.fetch_sub(n, Ordering::Relaxed);
        n
    }

    /// Drop up to `want` idle leaves cached in this directory, and push its
    /// children with cached children or misses of their own onto `dirs`.
    fn trim_children(&self, want: u64, force: bool, dirs: &mut Vec<Arc<Dentry>>) -> u64 {
        let mut freed = 0;
        let mut after: Option<String> = None;
        loop {
            let mut gone: Vec<Arc<Dentry>> = Vec::new();
            let mut seen = 0;
            {
                let mut kids = self.children.lock();
                let start = after.take();
                let range = match &start {
                    Some(a) => kids.range::<str, _>((Bound::Excluded(a.as_str()), Bound::Unbounded)),
                    None => kids.range::<str, _>(..),
                };
                let mut names: Vec<String> = Vec::new();
                for (name, c) in range.take(BATCH) {
                    seen += 1;
                    after = Some(name.clone());
                    if !c.children.lock().is_empty() || c.missing.lock().len() > 0 {
                        dirs.push(c.clone());
                        continue;
                    }
                    // Nobody else holds it: the count can only grow through
                    // this map, whose lock is held (or through ALIASES, whose
                    // users only clear misses).
                    let idle = Arc::strong_count(c) == 1 && c.inode.dentry_reclaimable() && c.mounted.lock().is_empty();
                    if !idle || freed + names.len() as u64 >= want {
                        continue;
                    }
                    if c.referenced.swap(false, Ordering::Relaxed) && !force {
                        continue;
                    }
                    names.push(name.clone());
                }
                for n in names {
                    gone.extend(kids.remove(&n));
                }
            }
            freed += gone.len() as u64;
            // Dropped with no lock held (dropping a dentry takes ALIASES).
            drop(gone);
            if seen < BATCH {
                return freed;
            }
        }
    }
}

// --- Tests ---------------------------------------------------------------

use super::{Metadata, S_IFDIR, S_IFREG};
use crate::sync::IrqSpinLock;

/// A directory of a file system that keeps its files' inodes (as tmpfs
/// does) but lets the cache drop their dentries and cache misses (as ext4
/// and SlateFS do); it counts the lookups that reach it.
struct TestDir {
    files: IrqSpinLock<BTreeMap<String, Arc<dyn Inode>>>,
    lookups: AtomicU64,
}

struct TestFile;

impl Inode for TestFile {
    fn metadata(&self) -> Metadata {
        Metadata { mode: S_IFREG | 0o644, nlink: 1, ..Metadata::default() }
    }
    fn dentry_reclaimable(&self) -> bool {
        true
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl Inode for TestDir {
    fn metadata(&self) -> Metadata {
        Metadata { mode: S_IFDIR | 0o755, nlink: 2, ..Metadata::default() }
    }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        self.lookups.fetch_add(1, Ordering::Relaxed);
        self.files.lock().get(name).cloned().ok_or(ENOENT)
    }
    fn create(&self, name: &str, _mode: u32, _rdev: u64) -> Result<Arc<dyn Inode>> {
        let f: Arc<dyn Inode> = Arc::new(TestFile);
        self.files.lock().insert(String::from(name), f.clone());
        name_added(self, name);
        Ok(f)
    }
    fn dentry_reclaimable(&self) -> bool {
        true
    }
    fn cache_misses(&self) -> bool {
        true
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

fn test_tree() -> (Arc<TestDir>, Arc<Dentry>) {
    let dir = Arc::new(TestDir { files: IrqSpinLock::new(BTreeMap::new()), lookups: AtomicU64::new(0) });
    let root = Dentry::new("/", dir.clone(), None, None);
    (dir, root)
}

fn check(ok: bool, what: &'static str) -> core::result::Result<(), &'static str> {
    if ok { Ok(()) } else { Err(what) }
}

/// Idle names are dropped after a second chance and looked up again;
/// names in use and mount points stay.
fn test_shrink() -> core::result::Result<(), &'static str> {
    let (dir, root) = test_tree();
    for n in ["a", "b", "m"] {
        dir.create(n, S_IFREG, 0).map_err(|_| "create")?;
    }
    let a = root.child("a").map_err(|_| "lookup a")?;
    let a_inode = a.inode.clone();
    drop(a);
    let held = root.child("b").map_err(|_| "lookup b")?;
    let m = root.child("m").map_err(|_| "lookup m")?;
    m.mounted.lock().insert(u64::MAX, root.clone());
    drop(m);
    let before = dir.lookups.load(Ordering::Relaxed);
    root.child("a").map_err(|_| "cached a")?;
    check(dir.lookups.load(Ordering::Relaxed) == before, "a cached name went to the file system")?;
    let roots = [root.clone()];
    let (freed, _) = shrink(&roots, u64::MAX, 0, false);
    check(freed == 1, "the sweep didn't drop exactly the idle name")?;
    check(!root.children.lock().contains_key("a"), "the idle name stayed")?;
    check(root.children.lock().contains_key("b"), "a name in use was dropped")?;
    check(root.children.lock().contains_key("m"), "a mount point was dropped")?;
    let again = root.child("a").map_err(|_| "lookup a again")?;
    check(dir.lookups.load(Ordering::Relaxed) == before + 1, "a dropped name wasn't looked up again")?;
    check(Arc::ptr_eq(&again.inode, &a_inode), "the name came back with another inode")?;
    drop((again, held));
    // A name just found survives one sweep (its clock bit), not two.
    check(shrink(&roots, u64::MAX, 0, false).0 == 2, "the second sweep didn't drop a and b")?;
    let m = root.children.lock().get("m").cloned().ok_or("the mount point went")?;
    m.mounted.lock().clear();
    drop(m);
    check(shrink(&roots, u64::MAX, 0, true).0 == 1, "a forced sweep didn't drop the last name")?;
    check(root.children.lock().is_empty(), "names were left after a forced sweep")
}

/// Misses are cached, forgotten when the name is added, and trimmed.
fn test_misses() -> core::result::Result<(), &'static str> {
    let (dir, root) = test_tree();
    check(root.child("x").err() == Some(ENOENT), "x was found")?;
    let n = dir.lookups.load(Ordering::Relaxed);
    check(root.child("x").err() == Some(ENOENT), "x was found the second time")?;
    check(dir.lookups.load(Ordering::Relaxed) == n, "a cached miss went to the file system")?;
    check(root.cached_child("x").err() == Some(ENOENT), "RESOLVE_CACHED didn't see the miss")?;
    check(root.cached_child("y").err() == Some(EAGAIN), "RESOLVE_CACHED knew an unknown name")?;
    dir.create("x", S_IFREG, 0).map_err(|_| "create x")?;
    check(root.child("x").is_ok(), "x wasn't found once made")?;
    // A miss found while the name was being added isn't recorded.
    let generation = root.missing.lock().check("z").map_err(|_| "z cached")?;
    name_added(&*dir, "z");
    root.missing.lock().note("z", generation);
    check(!root.missing.lock().has("z"), "a stale miss was recorded")?;
    check(root.child("w").err() == Some(ENOENT), "w was found")?;
    check(root.missing.lock().len() == 1, "the miss for w wasn't cached")?;
    let total = MISSES.load(Ordering::Relaxed);
    check(shrink(core::slice::from_ref(&root), 0, u64::MAX, false).1 == 1, "the sweep didn't drop the miss")?;
    check(root.missing.lock().len() == 0, "the miss stayed")?;
    check(MISSES.load(Ordering::Relaxed) == total - 1, "the miss count is off")
}

/// relatime, noatime, nodiratime and strictatime decide whether a read
/// updates the access time (ADR 0162).
fn test_atime_rules() -> core::result::Result<(), &'static str> {
    use super::{
        FileType, MNT_NOATIME, MNT_NODIRATIME, MNT_RDONLY, MNT_RELATIME, MNT_STRICTATIME, Metadata, Timespec,
        atime_default, atime_due,
    };
    let t = |sec: i64| Timespec { sec, nsec: 0 };
    let now = t(1_000_000);
    let file =
        |a: i64, m: i64| Metadata { mode: 0o100644, atime: t(a), mtime: t(m), ctime: t(m), ..Default::default() };
    let check = |ok: bool, what: &'static str| if ok { Ok(()) } else { Err(what) };
    check(atime_due(&file(500, 600), MNT_RELATIME, now), "relatime: older than the change")?;
    check(!atime_due(&file(999_000, 600), MNT_RELATIME, now), "relatime: newer, within the day")?;
    check(atime_due(&file(900_000, 600), MNT_RELATIME, now), "relatime: newer, a day old")?;
    check(!atime_due(&file(500, 600), MNT_NOATIME, now), "noatime")?;
    check(!atime_due(&file(500, 600), MNT_RDONLY, now), "read-only")?;
    check(atime_due(&file(999_999, 600), MNT_STRICTATIME, now), "strictatime")?;
    check(!atime_due(&file(1_000_000, 600), MNT_STRICTATIME, now), "strictatime: already now")?;
    let dir = Metadata { mode: 0o040755, ..file(500, 600) };
    check(dir.file_type() == FileType::Directory, "a directory")?;
    check(!atime_due(&dir, MNT_RELATIME | MNT_NODIRATIME, now), "nodiratime")?;
    check(atime_due(&file(500, 600), MNT_NODIRATIME, now), "nodiratime: files still")?;
    check(atime_default(0) == MNT_RELATIME, "relatime by default")?;
    check(atime_default(MNT_NOATIME | MNT_RELATIME) == MNT_NOATIME, "noatime wins")
}

pub const TESTS: &[crate::ktest::Test] = &[
    crate::ktest::Test { name: "fs::dcache_shrink", run: test_shrink },
    crate::ktest::Test { name: "fs::dcache_misses", run: test_misses },
    crate::ktest::Test { name: "fs::atime_rules", run: test_atime_rules },
];
