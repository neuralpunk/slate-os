// SPDX-License-Identifier: MIT OR Apache-2.0

//! Advisory file locks (M19, ADR 0043): flock(2) locks, POSIX record locks
//! (fcntl(2) F_SETLK) and open file description locks (F_OFD_SETLK), with
//! the semantics their man pages give:
//! - flock locks belong to an open file description: dup(2) and fork(2)
//!   share them, and they go when its last descriptor closes;
//! - POSIX locks belong to a process: never inherited by fork, and all of
//!   a process's locks on a file go when it closes *any* descriptor of it,
//!   or exits;
//! - OFD locks are byte ranges like POSIX locks but belong to an open file
//!   description like flock locks.
//!
//! flock locks never conflict with record locks; POSIX and OFD locks
//! conflict with each other. Locks are keyed by the file's inode, and only
//! files with a name (a dentry) take them: on pipes and sockets every lock
//! succeeds and holds nothing.
//!
//! Locks of an open file description that is gone, or of a process that
//! has exited, are stale: they are dropped when met. Regular files drop
//! theirs as their open file description goes ([`ofd_dropped`]); waiters
//! also look again every [`RECHECK_NS`], for other kinds of files. A
//! blocked F_SETLKW that would wait in a cycle of POSIX lock owners fails
//! with EDEADLK.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::fmt::Write;

use super::File;
use super::vfs::{Inode, Result};
use crate::abi::linux::errno::*;
use crate::sched::wait::{WaitQueue, WaitResult};
use crate::sync::IrqSpinLock;

/// How often a waiter looks again without being woken.
const RECHECK_NS: u64 = 200_000_000;

/// Who holds a lock.
#[derive(Clone)]
enum Owner {
    /// A process (POSIX locks), by pid.
    Process(u32),
    /// An open file description (flock and OFD locks).
    Ofd(usize, Weak<dyn File>),
}

impl Owner {
    fn same(&self, other: &Owner) -> bool {
        match (self, other) {
            (Owner::Process(a), Owner::Process(b)) => a == b,
            (Owner::Ofd(a, _), Owner::Ofd(b, _)) => a == b,
            _ => false,
        }
    }

    fn alive(&self) -> bool {
        match self {
            Owner::Process(pid) => crate::proc::get(*pid).is_some_and(|p| !p.is_zombie()),
            Owner::Ofd(_, w) => w.strong_count() > 0,
        }
    }

    /// The pid F_GETLK reports: the holder's as the caller sees it (0
    /// outside its namespace), or -1 for OFD locks.
    fn pid(&self) -> i32 {
        match self {
            Owner::Process(pid) => crate::proc::pid_in_caller_ns(*pid).unwrap_or(0) as i32,
            Owner::Ofd(..) => -1,
        }
    }
}

/// A byte-range lock on `[start, end)`; `end` u64::MAX reaches past any
/// end of file.
#[derive(Clone)]
struct Range {
    start: u64,
    end: u64,
    write: bool,
    owner: Owner,
}

impl Range {
    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start < end && start < self.end
    }
}

#[derive(Clone)]
struct Flock {
    exclusive: bool,
    owner: Owner,
}

struct FileLocks {
    inode: Weak<dyn Inode>,
    flocks: Vec<Flock>,
    ranges: Vec<Range>,
}

impl FileLocks {
    fn prune(&mut self) {
        self.flocks.retain(|f| f.owner.alive());
        self.ranges.retain(|r| r.owner.alive());
    }

    fn is_empty(&self) -> bool {
        self.flocks.is_empty() && self.ranges.is_empty()
    }

    /// The first lock of another owner that conflicts with `owner` taking
    /// `[start, end)` for reading or writing.
    /// The conflicting lock that starts first (F_GETLK reports that one).
    fn conflict(&self, owner: &Owner, start: u64, end: u64, write: bool) -> Option<&Range> {
        self.ranges
            .iter()
            .filter(|r| !r.owner.same(owner) && r.overlaps(start, end) && (write || r.write))
            .min_by_key(|r| r.start)
    }

    /// Give `owner` lock type `kind` (None: unlocked) over `[start, end)`,
    /// splitting its locks around the range and merging neighbours of the
    /// same type.
    fn set(&mut self, owner: &Owner, start: u64, end: u64, kind: Option<bool>) {
        let mut kept = Vec::with_capacity(self.ranges.len() + 2);
        for r in self.ranges.drain(..) {
            if !r.owner.same(owner) || !r.overlaps(start, end) {
                kept.push(r);
                continue;
            }
            if r.start < start {
                kept.push(Range { end: start, ..r.clone() });
            }
            if r.end > end {
                kept.push(Range { start: end, ..r });
            }
        }
        self.ranges = kept;
        let Some(write) = kind else { return };
        let (mut s, mut e) = (start, end);
        // Join this owner's touching locks of the same type.
        self.ranges.retain(|r| {
            let joins = r.owner.same(owner) && r.write == write && r.start <= e && s <= r.end;
            if joins {
                s = s.min(r.start);
                e = e.max(r.end);
            }
            !joins
        });
        self.ranges.push(Range { start: s, end: e, write, owner: owner.clone() });
    }
}

/// Locks by inode address (checked against the weak reference, as an
/// address can be reused once an inode is gone).
static LOCKS: IrqSpinLock<BTreeMap<usize, FileLocks>> = IrqSpinLock::new(BTreeMap::new());
/// POSIX lock owners blocked in F_SETLKW: what each waits for (for
/// deadlock detection).
static WAITING: IrqSpinLock<BTreeMap<u32, (usize, u64, u64, bool)>> = IrqSpinLock::new(BTreeMap::new());
static WAIT: WaitQueue = WaitQueue::new();

/// The inode `f` locks apply to, if it takes locks.
fn target(f: &Arc<dyn File>) -> Option<Arc<dyn Inode>> {
    f.dentry().map(|d| d.inode.clone())
}

fn key(inode: &Arc<dyn Inode>) -> usize {
    Arc::as_ptr(inode).cast::<u8>() as usize
}

/// Run `f` on the locks of `inode` (pruned of stale ones).
fn with_locks<R>(inode: &Arc<dyn Inode>, f: impl FnOnce(&mut FileLocks) -> R) -> R {
    let mut all = LOCKS.lock();
    let k = key(inode);
    let entry = all.entry(k).or_insert_with(|| FileLocks {
        inode: Arc::downgrade(inode),
        flocks: Vec::new(),
        ranges: Vec::new(),
    });
    if !entry.inode.upgrade().is_some_and(|i| Arc::ptr_eq(&i, inode)) {
        *entry = FileLocks { inode: Arc::downgrade(inode), flocks: Vec::new(), ranges: Vec::new() };
    }
    entry.prune();
    let r = f(entry);
    if entry.is_empty() {
        all.remove(&k);
    }
    r
}

fn ofd_owner(f: &Arc<dyn File>) -> Owner {
    Owner::Ofd(Arc::as_ptr(f).cast::<u8>() as usize, Arc::downgrade(f))
}

fn current_pid() -> u32 {
    crate::proc::current().map_or(0, |p| p.pid)
}

/// Wait (interruptibly) until `attempt` gives a result.
fn wait_for<R>(mut attempt: impl FnMut() -> Option<Result<R>>) -> Result<R> {
    loop {
        let mut out = None;
        let deadline = crate::time::monotonic_ns() + RECHECK_NS;
        let r = WAIT.wait_until_deadline(
            || {
                out = attempt();
                out.is_some()
            },
            deadline,
        );
        if let Some(r) = out {
            return r;
        }
        if r == WaitResult::Interrupted {
            return Err(EINTR);
        }
    }
}

// --- flock(2) -------------------------------------------------------------

// flock(2) operations. Source: musl `sys/file.h` (ADR 0009).
pub const LOCK_SH: u32 = 1;
pub const LOCK_EX: u32 = 2;
pub const LOCK_NB: u32 = 4;
pub const LOCK_UN: u32 = 8;

/// flock(2) on open file `f`.
pub fn flock(f: &Arc<dyn File>, op: u32) -> Result<()> {
    let Some(inode) = target(f) else { return Ok(()) };
    let owner = ofd_owner(f);
    let exclusive = match op & !LOCK_NB {
        LOCK_SH => false,
        LOCK_EX => true,
        LOCK_UN => {
            with_locks(&inode, |l| l.flocks.retain(|x| !x.owner.same(&owner)));
            WAIT.wake_all();
            return Ok(());
        }
        _ => return Err(EINVAL),
    };
    // A conversion drops the old lock first (not atomically, as flock(2)
    // allows), so others waiting may get in between.
    let had = with_locks(&inode, |l| {
        let before = l.flocks.len();
        l.flocks.retain(|x| !x.owner.same(&owner));
        before != l.flocks.len()
    });
    if had {
        WAIT.wake_all();
    }
    let attempt = || {
        with_locks(&inode, |l| {
            let busy = l.flocks.iter().any(|x| !x.owner.same(&owner) && (exclusive || x.exclusive));
            if busy {
                return None;
            }
            l.flocks.push(Flock { exclusive, owner: owner.clone() });
            Some(Ok(()))
        })
    };
    if op & LOCK_NB != 0 {
        return attempt().unwrap_or(Err(EAGAIN));
    }
    wait_for(attempt)
}

// --- record locks ---------------------------------------------------------

// Lock types (struct flock l_type). Source: musl `bits/fcntl.h`.
pub const F_RDLCK: i16 = 0;
pub const F_WRLCK: i16 = 1;
pub const F_UNLCK: i16 = 2;

/// struct flock (fcntl(2)): l_type, l_whence (i16), l_start, l_len (i64),
/// l_pid (i32), padded to 32 bytes. Source: musl `fcntl.h`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct FlockArg {
    pub l_type: i16,
    pub l_whence: i16,
    pub l_start: i64,
    pub l_len: i64,
    pub l_pid: i32,
    pub pad: i32,
}

/// Which record lock family a call uses.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Posix,
    Ofd,
}

/// The byte range `[start, end)` an F_*LK argument names (whence relative
/// to the file's offset or end, negative lengths reaching back).
fn range_of(f: &Arc<dyn File>, a: &FlockArg) -> Result<(u64, u64)> {
    const SEEK_SET: i16 = 0;
    const SEEK_CUR: i16 = 1;
    const SEEK_END: i16 = 2;
    let base: i64 = match a.l_whence {
        SEEK_SET => 0,
        SEEK_CUR => f.seek(0, SEEK_CUR as u32)? as i64,
        SEEK_END => f.dentry().ok_or(EINVAL)?.metadata().size as i64,
        _ => return Err(EINVAL),
    };
    let start = base.checked_add(a.l_start).ok_or(EOVERFLOW)?;
    let (start, end) = match a.l_len {
        0 => (start, i64::MAX),
        n if n > 0 => (start, start.checked_add(n).ok_or(EOVERFLOW)?),
        n => (start.checked_add(n).ok_or(EINVAL)?, start),
    };
    if start < 0 {
        return Err(EINVAL);
    }
    let end = if end == i64::MAX { u64::MAX } else { end as u64 };
    Ok((start as u64, end))
}

fn owner_for(f: &Arc<dyn File>, family: Family) -> Owner {
    match family {
        Family::Posix => Owner::Process(current_pid()),
        Family::Ofd => ofd_owner(f),
    }
}

/// F_GETLK / F_OFD_GETLK: the first lock that would block `a`, written
/// back into it, or l_type F_UNLCK.
pub fn getlk(f: &Arc<dyn File>, family: Family, a: &mut FlockArg) -> Result<()> {
    if family == Family::Ofd && a.l_pid != 0 {
        return Err(EINVAL);
    }
    let write = match a.l_type {
        F_RDLCK => false,
        F_WRLCK => true,
        _ => return Err(EINVAL),
    };
    let (start, end) = range_of(f, a)?;
    let Some(inode) = target(f) else {
        a.l_type = F_UNLCK;
        return Ok(());
    };
    let owner = owner_for(f, family);
    let found = with_locks(&inode, |l| l.conflict(&owner, start, end, write).cloned());
    match found {
        None => a.l_type = F_UNLCK,
        Some(r) => {
            a.l_type = if r.write { F_WRLCK } else { F_RDLCK };
            a.l_whence = 0;
            a.l_start = r.start as i64;
            a.l_len = if r.end == u64::MAX { 0 } else { (r.end - r.start) as i64 };
            a.l_pid = r.owner.pid();
        }
    }
    Ok(())
}

/// F_SETLK / F_SETLKW and the OFD forms. `readable`/`writable`: the open
/// file's access mode (a read lock needs reading, a write lock writing).
pub fn setlk(
    f: &Arc<dyn File>,
    family: Family,
    a: &FlockArg,
    wait: bool,
    readable: bool,
    writable: bool,
) -> Result<()> {
    if family == Family::Ofd && a.l_pid != 0 {
        return Err(EINVAL);
    }
    let kind = match a.l_type {
        F_RDLCK if !readable => return Err(EBADF),
        F_WRLCK if !writable => return Err(EBADF),
        F_RDLCK => Some(false),
        F_WRLCK => Some(true),
        F_UNLCK => None,
        _ => return Err(EINVAL),
    };
    let (start, end) = range_of(f, a)?;
    let Some(inode) = target(f) else { return Ok(()) };
    let owner = owner_for(f, family);
    let Some(write) = kind else {
        with_locks(&inode, |l| l.set(&owner, start, end, None));
        WAIT.wake_all();
        return Ok(());
    };
    let k = key(&inode);
    // Ok(true): taken; Ok(false): blocked; Err: give up (EDEADLK).
    let attempt = |deadlock_check: bool| -> Result<bool> {
        let blocker = with_locks(&inode, |l| {
            let blocker = l.conflict(&owner, start, end, write).map(|r| r.owner.clone());
            if blocker.is_none() {
                l.set(&owner, start, end, Some(write));
            }
            blocker
        });
        match (blocker, &owner) {
            (None, _) => Ok(true),
            (Some(Owner::Process(them)), Owner::Process(me)) if deadlock_check && waits_on(them, *me) => Err(EDEADLK),
            (Some(_), _) => Ok(false),
        }
    };
    // Lowering or keeping one's own lock never blocks; neither does a free range.
    if attempt(false)? {
        WAIT.wake_all(); // A write lock turned into a read lock lets readers in.
        return Ok(());
    }
    if !wait {
        return Err(EAGAIN);
    }
    if let Owner::Process(me) = owner {
        WAITING.lock().insert(me, (k, start, end, write));
    }
    let r = wait_for(|| match attempt(true) {
        Ok(true) => Some(Ok(())),
        Ok(false) => None,
        Err(e) => Some(Err(e)),
    });
    if let Owner::Process(me) = owner {
        WAITING.lock().remove(&me);
    }
    r
}

/// Whether POSIX owner `from` waits, directly or through other waiters, on
/// a lock `to` holds.
fn waits_on(from: u32, to: u32) -> bool {
    let waiting = WAITING.lock().clone();
    let all = LOCKS.lock();
    let mut seen = Vec::new();
    let mut frontier = alloc::vec![from];
    while let Some(p) = frontier.pop() {
        if p == to {
            return true;
        }
        if seen.contains(&p) {
            continue;
        }
        seen.push(p);
        let Some(&(k, start, end, write)) = waiting.get(&p) else { continue };
        let Some(l) = all.get(&k) else { continue };
        for r in l.ranges.iter().filter(|r| r.overlaps(start, end) && (write || r.write)) {
            if let Owner::Process(holder) = r.owner
                && holder != p
            {
                frontier.push(holder);
            }
        }
    }
    false
}

/// A process closed a descriptor of `f`: its POSIX locks on the file go.
pub fn fd_closed(f: &Arc<dyn File>) {
    let Some(inode) = target(f) else { return };
    let me = Owner::Process(current_pid());
    let removed = {
        let mut all = LOCKS.lock();
        let k = key(&inode);
        let Some(l) = all.get_mut(&k) else { return };
        let before = l.ranges.len();
        l.ranges.retain(|r| !r.owner.same(&me));
        let removed = before != l.ranges.len();
        if l.is_empty() {
            all.remove(&k);
        }
        removed
    };
    if removed {
        WAIT.wake_all();
    }
}

/// An open file description at address `ofd` is gone: its flock and OFD
/// locks go.
pub fn ofd_dropped(ofd: usize) {
    let mut removed = false;
    {
        let mut all = LOCKS.lock();
        for l in all.values_mut() {
            let before = l.flocks.len() + l.ranges.len();
            l.flocks.retain(|x| !matches!(x.owner, Owner::Ofd(a, _) if a == ofd));
            l.ranges.retain(|x| !matches!(x.owner, Owner::Ofd(a, _) if a == ofd));
            removed |= before != l.flocks.len() + l.ranges.len();
        }
        all.retain(|_, l| !l.is_empty());
    }
    if removed {
        WAIT.wake_all();
    }
}

/// /proc/locks (proc(5)): one line per lock.
pub fn proc_locks(out: &mut String) {
    let all = LOCKS.lock();
    let mut n = 0;
    for l in all.values() {
        let Some(inode) = l.inode.upgrade() else { continue };
        let m = inode.metadata();
        let id = alloc::format!("{:02x}:{:02x}:{}", super::vfs::major(m.dev), super::vfs::minor(m.dev), m.ino);
        for f in l.flocks.iter().filter(|f| f.owner.alive()) {
            n += 1;
            let kind = if f.exclusive { "WRITE" } else { "READ " };
            let _ = writeln!(out, "{n}: FLOCK  ADVISORY  {kind} {} {id} 0 EOF", f.owner.pid());
        }
        for r in l.ranges.iter().filter(|r| r.owner.alive()) {
            n += 1;
            let family = if matches!(r.owner, Owner::Ofd(..)) { "OFDLCK" } else { "POSIX " };
            let kind = if r.write { "WRITE" } else { "READ " };
            let end = if r.end == u64::MAX { String::from("EOF") } else { alloc::format!("{}", r.end - 1) };
            let _ = writeln!(out, "{n}: {family} ADVISORY  {kind} {} {id} {} {end}", r.owner.pid(), r.start);
        }
    }
}
