// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fast user-space mutexes (futex(2)).
//!
//! Waiters are kept per futex word. A futex in a private mapping is
//! identified by its address space and virtual address, whether or not the
//! caller says FUTEX_PRIVATE_FLAG; only one in a shared mapping (MAP_SHARED,
//! where processes really share the page) by the physical address of the
//! word, so those processes find each other. Keying a private mapping's
//! word by its physical page would lose wakeups: a write after fork moves
//! the word to a fresh copy-on-write page, away from its waiters. The value check and the enqueue happen under the table lock, and
//! wakers take the same lock, so a wakeup between the check and the sleep
//! cannot be lost.
//!
//! Priority-inheritance futexes (ADR 0045) keep their own table: the word
//! holds the owner's thread ID, FUTEX_WAITERS and FUTEX_OWNER_DIED (the
//! policy futex(2) describes). Waiters lend their rank to the owner, along
//! the chain of owners blocked on further PI futexes; unlocking hands the
//! lock straight to the highest-ranked waiter. A thread that exits while
//! owning a PI futex hands it on with FUTEX_OWNER_DIED, and its robust
//! list (set_robust_list(2)) is walked: each lock it still holds gets
//! FUTEX_OWNER_DIED and one waiter is woken.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::Process;
use crate::abi::linux::errno::{EAGAIN, EDEADLK, EFAULT, EINTR, EINVAL, ENOSYS, EPERM, ESRCH, ETIMEDOUT, Errno};
use crate::arch::cpu::InterruptGuard;
use crate::arch::uaccess::{cmpxchg_user_u32, read_user, update_user_u32};
use crate::sched::{self, Thread};
use crate::sync::IrqSpinLock;

// futex(2) operations and flags. Values from musl's internal `futex.h`
// (ADR 0009); WAIT = 0 and PRIVATE = 128 also observed in musl's `__wait`.
pub const FUTEX_WAIT: u32 = 0;
pub const FUTEX_WAKE: u32 = 1;
pub const FUTEX_REQUEUE: u32 = 3;
pub const FUTEX_CMP_REQUEUE: u32 = 4;
pub const FUTEX_WAKE_OP: u32 = 5;
pub const FUTEX_LOCK_PI: u32 = 6;
pub const FUTEX_UNLOCK_PI: u32 = 7;
pub const FUTEX_TRYLOCK_PI: u32 = 8;
pub const FUTEX_LOCK_PI2: u32 = 13;
pub const FUTEX_WAIT_BITSET: u32 = 9;
pub const FUTEX_WAKE_BITSET: u32 = 10;
pub const FUTEX_PRIVATE_FLAG: u32 = 128;
pub const FUTEX_CLOCK_REALTIME: u32 = 256;
pub const FUTEX_BITSET_MATCH_ANY: u32 = u32::MAX;
// The PI futex word (futex(2) "Priority-inheritance futexes"); bit values
// from musl's internal `futex.h` and its pthread mutexes (ADR 0009).
pub const FUTEX_WAITERS: u32 = 0x8000_0000;
pub const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
pub const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
/// Entries of a robust list walked at most, so a corrupt (circular) list
/// cannot hold an exiting thread forever.
const ROBUST_LIST_LIMIT: usize = 2048;

/// Identifies a futex word.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    /// (process, virtual address)
    Private(usize, u64),
    /// Physical address.
    Shared(u64),
}

struct Waiter {
    thread: Arc<Thread>,
    bitset: u32,
    woken: Arc<AtomicBool>,
}

static TABLE: IrqSpinLock<BTreeMap<Key, Vec<Waiter>>> = IrqSpinLock::new(BTreeMap::new());

fn key(p: &Arc<Process>, uaddr: u64, private: bool) -> Result<Key, Errno> {
    if uaddr % 4 != 0 {
        return Err(EINVAL);
    }
    let shared_mapping = !private && p.aspace.lock().as_ref().and_then(|a| a.find(uaddr)).is_some_and(|v| v.shared);
    if !shared_mapping {
        return Ok(Key::Private(Arc::as_ptr(p) as usize, uaddr));
    }
    // Make sure the page is present, then key by physical address.
    read_user::<u32>(uaddr).map_err(|_| EFAULT)?;
    let phys = p.aspace.lock().as_ref().and_then(|a| a.translate(uaddr)).ok_or(EFAULT)?;
    Ok(Key::Shared(phys.0))
}

/// FUTEX_WAIT: sleep if `*uaddr == val`, until woken (by a matching
/// bitset), until `deadline_ns` (monotonic), or until a signal.
pub fn wait(
    p: &Arc<Process>,
    uaddr: u64,
    val: u32,
    bitset: u32,
    private: bool,
    deadline_ns: Option<u64>,
) -> Result<u64, Errno> {
    if bitset == 0 {
        return Err(EINVAL);
    }
    let k = key(p, uaddr, private)?;
    let me = sched::current();
    let woken = Arc::new(AtomicBool::new(false));
    {
        let _irq = InterruptGuard::new();
        {
            let mut table = TABLE.lock();
            // Reading under the table lock closes the race with wakers.
            let cur: u32 = read_user(uaddr).map_err(|_| EFAULT)?;
            if cur != val {
                return Err(EAGAIN);
            }
            if crate::proc::signal::pending_for_current() {
                return Err(EINTR);
            }
            me.block_prepare();
            table.entry(k).or_default().push(Waiter { thread: me.clone(), bitset, woken: woken.clone() });
        }
        if let Some(d) = deadline_ns {
            sched::add_sleeper(d, me.clone());
        }
        sched::schedule();
    }
    if let Some(d) = deadline_ns {
        sched::remove_sleeper(d, &me);
    }
    if woken.load(Ordering::Acquire) {
        return Ok(0);
    }
    // Not woken by FUTEX_WAKE: leave the queue and say why.
    remove(k, &me);
    if woken.load(Ordering::Acquire) {
        return Ok(0); // Woken while we were leaving.
    }
    if deadline_ns.is_some_and(|d| crate::time::monotonic_ns() >= d) {
        return Err(ETIMEDOUT);
    }
    if crate::proc::signal::pending_for_current() {
        return Err(EINTR);
    }
    Ok(0) // A spurious wakeup is allowed by futex(2).
}

/// Take `me` off every queue (it may have been requeued elsewhere).
fn remove(_k: Key, me: &Arc<Thread>) {
    TABLE.lock().retain(|_, q| {
        q.retain(|w| !Arc::ptr_eq(&w.thread, me));
        !q.is_empty()
    });
}

fn wake_key(k: Key, n: u32, bitset: u32) -> u64 {
    let woken: Vec<Arc<Thread>> = {
        let mut table = TABLE.lock();
        let Some(q) = table.get_mut(&k) else { return 0 };
        let mut out = Vec::new();
        q.retain(|w| {
            if (out.len() as u32) < n && w.bitset & bitset != 0 {
                w.woken.store(true, Ordering::Release);
                out.push(w.thread.clone());
                false
            } else {
                true
            }
        });
        if q.is_empty() {
            table.remove(&k);
        }
        out
    };
    for t in &woken {
        sched::wake(t);
    }
    woken.len() as u64
}

/// FUTEX_WAKE: wake up to `n` waiters whose bitset matches.
pub fn wake(p: &Arc<Process>, uaddr: u64, n: u32, bitset: u32, private: bool) -> Result<u64, Errno> {
    if bitset == 0 {
        return Err(EINVAL);
    }
    let k = key(p, uaddr, private)?;
    Ok(wake_key(k, n, bitset))
}

/// Wake waiters of a futex word (thread exit's CLONE_CHILD_CLEARTID),
/// however they keyed it.
pub fn wake_address(p: &Arc<Process>, uaddr: u64, n: u32) {
    let _ = wake(p, uaddr, n, FUTEX_BITSET_MATCH_ANY, true);
    if p.aspace.lock().as_ref().and_then(|a| a.find(uaddr)).is_some_and(|v| v.shared) {
        let _ = wake(p, uaddr, n, FUTEX_BITSET_MATCH_ANY, false);
    }
}

/// FUTEX_REQUEUE / FUTEX_CMP_REQUEUE: wake `n` waiters on `uaddr` and move
/// up to `n2` of the rest to `uaddr2` (CMP: only if `*uaddr == val`).
pub fn requeue(
    p: &Arc<Process>,
    uaddr: u64,
    n: u32,
    n2: u32,
    uaddr2: u64,
    cmp: Option<u32>,
    private: bool,
) -> Result<u64, Errno> {
    let (k1, k2) = (key(p, uaddr, private)?, key(p, uaddr2, private)?);
    let (woken, moved): (Vec<Arc<Thread>>, u64) = {
        let mut table = TABLE.lock();
        if let Some(v) = cmp {
            let cur: u32 = read_user(uaddr).map_err(|_| EFAULT)?;
            if cur != v {
                return Err(EAGAIN);
            }
        }
        let mut q = table.remove(&k1).unwrap_or_default();
        let wake_n = (n as usize).min(q.len());
        let rest = q.split_off(wake_n);
        let woken: Vec<_> = q
            .into_iter()
            .map(|w| {
                w.woken.store(true, Ordering::Release);
                w.thread
            })
            .collect();
        let move_n = (n2 as usize).min(rest.len());
        let mut rest = rest;
        let stay = rest.split_off(move_n);
        let moved = rest.len() as u64;
        table.entry(k2).or_default().extend(rest);
        if !stay.is_empty() {
            table.insert(k1, stay);
        }
        (woken, moved)
    };
    for t in &woken {
        sched::wake(t);
    }
    Ok(woken.len() as u64 + moved)
}

/// FUTEX_WAKE_OP: change the word at `uaddr2` atomically as `op` says, wake
/// up to `n` waiters on `uaddr`, and, if the old value of `uaddr2` passes
/// `op`'s comparison, up to `n2` on `uaddr2` (futex(2) gives the encoding:
/// operation, comparison and two 12-bit arguments).
pub fn wake_op(
    p: &Arc<Process>,
    uaddr: u64,
    n: u32,
    n2: u32,
    uaddr2: u64,
    op: u32,
    private: bool,
) -> Result<u64, Errno> {
    let (kind, cmp) = (op >> 28 & 0xf, op >> 24 & 0xf);
    // The arguments are 12-bit signed numbers.
    let sext = |v: u32| ((v << 20) as i32 >> 20) as u32;
    let (mut oparg, cmparg) = (sext(op >> 12 & 0xfff), sext(op & 0xfff));
    if kind & 8 != 0 {
        if oparg > 31 {
            return Err(EINVAL);
        }
        oparg = 1 << oparg;
    }
    let f: fn(u32, u32) -> u32 = match kind & 7 {
        0 => |_, a| a,
        1 => |v, a| v.wrapping_add(a),
        2 => |v, a| v | a,
        3 => |v, a| v & !a,
        4 => |v, a| v ^ a,
        _ => return Err(ENOSYS),
    };
    let (k1, k2) = (key(p, uaddr, private)?, key(p, uaddr2, private)?);
    let old = update_user_u32(uaddr2, |v| f(v, oparg)).map_err(|_| EFAULT)? as i32;
    let c = cmparg as i32;
    let pass = match cmp {
        0 => old == c,
        1 => old != c,
        2 => old < c,
        3 => old <= c,
        4 => old > c,
        5 => old >= c,
        _ => return Err(ENOSYS),
    };
    let mut woken = wake_key(k1, n, FUTEX_BITSET_MATCH_ANY);
    if pass {
        woken += wake_key(k2, n2, FUTEX_BITSET_MATCH_ANY);
    }
    Ok(woken)
}

// --- Priority inheritance ------------------------------------------------

struct PiWaiter {
    thread: Arc<Thread>,
    /// Its thread ID as the futex word holds it (in its PID namespace).
    tid: u32,
    granted: Arc<AtomicBool>,
}

#[derive(Default)]
struct PiFutex {
    /// The owner as the kernel knows it (set when the first waiter came).
    owner: Option<Arc<Thread>>,
    waiters: Vec<PiWaiter>,
}

#[derive(Default)]
struct PiTable {
    futexes: BTreeMap<Key, PiFutex>,
    /// The PI futex each blocked thread waits on.
    blocked: BTreeMap<sched::Tid, Key>,
}

static PI: IrqSpinLock<PiTable> = IrqSpinLock::new(PiTable { futexes: BTreeMap::new(), blocked: BTreeMap::new() });

/// The calling thread's ID as user space sees it (gettid(2)).
fn my_tid(p: &Process) -> u32 {
    let t = sched::current();
    p.tid_in(t.tid, &p.pid_ns()).unwrap_or(t.tid) as u32
}

/// The thread with ID `tid` as `p`'s PID namespace sees it.
fn thread_by_tid(p: &Arc<Process>, tid: u32) -> Option<Arc<Thread>> {
    let ns = p.pid_ns();
    let find = |q: &Arc<Process>| q.threads().into_iter().find(|t| q.tid_in(t.tid, &ns) == Some(u64::from(tid)));
    find(p).or_else(|| super::all().iter().find_map(find))
}

impl PiTable {
    /// The rank `t` borrows: the best effective rank among the waiters of
    /// the PI futexes it owns.
    fn boost_of(&self, t: &Arc<Thread>) -> u32 {
        self.futexes
            .values()
            .filter(|f| f.owner.as_ref().is_some_and(|o| Arc::ptr_eq(o, t)))
            .flat_map(|f| f.waiters.iter().map(|w| w.thread.effective_rank()))
            .max()
            .unwrap_or(0)
    }

    /// Recompute `t`'s boost, and its lock owner's in turn while the chain
    /// of blocked owners goes on (futex(2): "inheritance must be
    /// transitive").
    fn refresh(&self, t: &Arc<Thread>) {
        let mut at = t.clone();
        for _ in 0..32 {
            sched::set_boost(&at, self.boost_of(&at));
            let Some(owner) = self.blocked.get(&at.tid).and_then(|k| self.futexes.get(k)).and_then(|f| f.owner.clone())
            else {
                break;
            };
            at = owner;
        }
    }

    /// Whether `owner`, or the owner it waits for and so on, is `me`
    /// (taking the lock would deadlock).
    fn would_deadlock(&self, owner: &Arc<Thread>, me: &Arc<Thread>) -> bool {
        let mut at = owner.clone();
        for _ in 0..64 {
            if Arc::ptr_eq(&at, me) {
                return true;
            }
            let Some(next) = self.blocked.get(&at.tid).and_then(|k| self.futexes.get(k)).and_then(|f| f.owner.clone())
            else {
                return false;
            };
            at = next;
        }
        true
    }
}

/// The waiter to hand a PI futex to: the best rank, first come among equals.
fn top_waiter(f: &PiFutex) -> Option<usize> {
    f.waiters
        .iter()
        .enumerate()
        .max_by_key(|(i, w)| (w.thread.effective_rank(), core::cmp::Reverse(*i)))
        .map(|(i, _)| i)
}

/// FUTEX_LOCK_PI, FUTEX_LOCK_PI2 and FUTEX_TRYLOCK_PI (`try_only`): take
/// the PI futex at `uaddr`, waiting (until `deadline_ns`, monotonic) while
/// another thread owns it.
pub fn lock_pi(
    p: &Arc<Process>,
    uaddr: u64,
    private: bool,
    deadline_ns: Option<u64>,
    try_only: bool,
) -> Result<u64, Errno> {
    let k = key(p, uaddr, private)?;
    let me = sched::current();
    let tid = my_tid(p);
    // Fault the word in, writable, before taking locks.
    update_user_u32(uaddr, |v| v).map_err(|_| EFAULT)?;
    loop {
        let granted = Arc::new(AtomicBool::new(false));
        {
            let _irq = InterruptGuard::new();
            let mut pi = PI.lock();
            let val = cmpxchg_user_u32(uaddr, 0, tid).map_err(|_| EFAULT)?;
            if val == 0 {
                return Ok(0);
            }
            let owner_tid = val & FUTEX_TID_MASK;
            if owner_tid == tid {
                return Err(EDEADLK);
            }
            let waiting = pi.futexes.get(&k).is_some_and(|f| !f.waiters.is_empty());
            if owner_tid == 0 {
                // No owner, only stale state (FUTEX_OWNER_DIED): take it,
                // keeping the flag for user space to see.
                let new = tid | (val & FUTEX_OWNER_DIED) | if waiting { FUTEX_WAITERS } else { 0 };
                if cmpxchg_user_u32(uaddr, val, new).map_err(|_| EFAULT)? == val {
                    if let Some(f) = pi.futexes.get_mut(&k) {
                        f.owner = Some(me.clone());
                    }
                    return Ok(0);
                }
                continue;
            }
            if try_only {
                return Err(EAGAIN);
            }
            let owner = thread_by_tid(p, owner_tid).ok_or(ESRCH)?;
            if pi.would_deadlock(&owner, &me) {
                return Err(EDEADLK);
            }
            if val & FUTEX_WAITERS == 0 && cmpxchg_user_u32(uaddr, val, val | FUTEX_WAITERS).map_err(|_| EFAULT)? != val
            {
                continue;
            }
            if crate::proc::signal::pending_for_current() {
                return Err(EINTR);
            }
            let f = pi.futexes.entry(k).or_default();
            f.owner = Some(owner.clone());
            f.waiters.push(PiWaiter { thread: me.clone(), tid, granted: granted.clone() });
            pi.blocked.insert(me.tid, k);
            me.block_prepare();
            pi.refresh(&owner);
            drop(pi);
            if let Some(d) = deadline_ns {
                sched::add_sleeper(d, me.clone());
            }
            sched::schedule();
        }
        if let Some(d) = deadline_ns {
            sched::remove_sleeper(d, &me);
        }
        let _irq = InterruptGuard::new();
        let mut pi = PI.lock();
        if granted.load(Ordering::Acquire) {
            return Ok(0);
        }
        // Not handed the lock: leave the queue, give back the boost.
        pi.blocked.remove(&me.tid);
        let owner = pi.futexes.get_mut(&k).and_then(|f| {
            f.waiters.retain(|w| !Arc::ptr_eq(&w.thread, &me));
            f.owner.clone()
        });
        if let Some(o) = owner {
            pi.refresh(&o);
        }
        if pi.futexes.get(&k).is_some_and(|f| f.waiters.is_empty()) {
            pi.futexes.remove(&k);
        }
        drop(pi);
        if deadline_ns.is_some_and(|d| crate::time::monotonic_ns() >= d) {
            return Err(ETIMEDOUT);
        }
        if crate::proc::signal::pending_for_current() {
            return Err(EINTR);
        }
    }
}

/// Hand PI futex `k` (word at `uaddr`, holding `val`) from its owner to its
/// top waiter, with `extra` bits (FUTEX_OWNER_DIED when the owner died).
/// Returns false if the word changed under us. Called with the table
/// locked.
fn hand_off(pi: &mut PiTable, k: Key, uaddr: u64, val: u32, extra: u32) -> Result<bool, Errno> {
    let Some(f) = pi.futexes.get_mut(&k) else {
        return Ok(word_cmpxchg(k, uaddr, val, extra)? == val);
    };
    let Some(i) = top_waiter(f) else {
        let ok = word_cmpxchg(k, uaddr, val, extra)? == val;
        if ok {
            pi.futexes.remove(&k);
        }
        return Ok(ok);
    };
    let more = f.waiters.len() > 1;
    let new = f.waiters[i].tid | extra | if more { FUTEX_WAITERS } else { 0 };
    if word_cmpxchg(k, uaddr, val, new)? != val {
        return Ok(false);
    }
    let w = f.waiters.remove(i);
    let old_owner = f.owner.replace(w.thread.clone());
    w.granted.store(true, Ordering::Release);
    pi.blocked.remove(&w.thread.tid);
    if f.waiters.is_empty() {
        pi.futexes.remove(&k);
    }
    if let Some(o) = old_owner {
        pi.refresh(&o);
    }
    pi.refresh(&w.thread);
    sched::wake(&w.thread);
    Ok(true)
}

/// Compare and swap a futex word: through the caller's address space for
/// a private futex, through the direct map for a shared one (so an
/// exiting owner in another process can still hand it on).
fn word_cmpxchg(k: Key, uaddr: u64, old: u32, new: u32) -> Result<u32, Errno> {
    match k {
        Key::Private(..) => cmpxchg_user_u32(uaddr, old, new).map_err(|_| EFAULT),
        Key::Shared(phys) => {
            // SAFETY: `phys` is the physical address of an aligned futex
            // word in a page mapped shared by a live process (its waiters
            // keep the mapping); the direct map covers all RAM.
            let word = unsafe { &*(crate::mm::PhysAddr(phys).to_virt() as *const core::sync::atomic::AtomicU32) };
            Ok(match word.compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(v) | Err(v) => v,
            })
        }
    }
}

/// FUTEX_UNLOCK_PI: release a PI futex the caller owns, to its top waiter
/// if there is one (EPERM if the caller doesn't own it).
pub fn unlock_pi(p: &Arc<Process>, uaddr: u64, private: bool) -> Result<u64, Errno> {
    let k = key(p, uaddr, private)?;
    let tid = my_tid(p);
    update_user_u32(uaddr, |v| v).map_err(|_| EFAULT)?;
    loop {
        let _irq = InterruptGuard::new();
        let mut pi = PI.lock();
        let val: u32 = read_user(uaddr).map_err(|_| EFAULT)?;
        if val & FUTEX_TID_MASK != tid {
            return Err(EPERM);
        }
        if hand_off(&mut pi, k, uaddr, val, 0)? {
            pi.refresh(&sched::current());
            return Ok(0);
        }
    }
}

/// A thread's scheduling parameters changed: the owner of the PI futex it
/// waits on (and so on) borrows a different rank now.
pub fn priority_changed(t: &Arc<Thread>) {
    let _irq = InterruptGuard::new();
    let pi = PI.lock();
    let owner = pi.blocked.get(&t.tid).and_then(|k| pi.futexes.get(k)).and_then(|f| f.owner.clone());
    if let Some(o) = owner {
        pi.refresh(&o);
    }
}

/// The current thread is exiting: hand on the PI futexes it owns (with
/// FUTEX_OWNER_DIED), then walk its robust list.
pub fn exit_thread(p: &Arc<Process>) {
    let me = sched::current();
    {
        let _irq = InterruptGuard::new();
        let mut pi = PI.lock();
        let owned: Vec<Key> = pi
            .futexes
            .iter()
            .filter(|(_, f)| f.owner.as_ref().is_some_and(|o| Arc::ptr_eq(o, &me)))
            .map(|(k, _)| *k)
            .collect();
        for k in owned {
            // Only private futexes name their address; a shared one is
            // reached through its frame.
            let uaddr = match k {
                Key::Private(_, a) => a,
                Key::Shared(_) => 0,
            };
            for _ in 0..16 {
                let Ok(val) = (match k {
                    Key::Private(..) => read_user::<u32>(uaddr).map_err(|_| EFAULT),
                    Key::Shared(_) => word_cmpxchg(k, 0, 0, 0),
                }) else {
                    break;
                };
                if hand_off(&mut pi, k, uaddr, val, FUTEX_OWNER_DIED).unwrap_or(true) {
                    break;
                }
            }
        }
        pi.blocked.remove(&me.tid);
    }
    walk_robust_list(p, &me);
}

/// Walk the exiting thread's robust list (get_robust_list(2): a head of
/// three words, the first entry, the offset from an entry to its futex
/// word, and an entry being added or removed; entries link to the next
/// with their first word, and the list ends back at the head). Every
/// lock the thread still holds gets FUTEX_OWNER_DIED, and one waiter is
/// woken to find it.
fn walk_robust_list(p: &Arc<Process>, me: &Arc<Thread>) {
    let head = me.robust_list.swap(0, Ordering::Relaxed);
    if head == 0 {
        return;
    }
    let Ok([first, offset, pending]) = read_user::<[u64; 3]>(head) else { return };
    let tid = my_tid(p);
    let release =
        |entry: u64| {
            // The low bit marks a PI futex; the address is the rest.
            let word = (entry & !1).wrapping_add(offset);
            let Ok(old) = update_user_u32(word, |v| {
                if v & FUTEX_TID_MASK == tid { (v & FUTEX_WAITERS) | FUTEX_OWNER_DIED } else { v }
            }) else {
                return;
            };
            if old & FUTEX_TID_MASK == tid {
                wake_address(p, word, 1);
            }
        };
    let mut entry = first;
    let mut seen = 0;
    while entry != head && entry != 0 && seen < ROBUST_LIST_LIMIT {
        let Ok(next) = read_user::<u64>(entry & !1) else { break };
        if entry != pending {
            release(entry);
        }
        entry = next;
        seen += 1;
    }
    if pending != 0 {
        release(pending);
    }
}
