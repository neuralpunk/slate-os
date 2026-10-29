// SPDX-License-Identifier: MIT OR Apache-2.0

//! The out-of-memory killer (ADR 0045).
//!
//! When a page fault finds no memory, or its cgroup at `memory.max`, the
//! faulting thread gives back clean page-cache pages if that can help,
//! and otherwise kills the process with the highest badness score in the
//! scope that ran out (every process, or the cgroup's). The score is the
//! share of the allowed memory the process holds, in thousandths, plus
//! its `oom_score_adj` (proc_pid_oom_score_adj(5)); -1000 exempts it, as
//! does being init. Then the faulting thread reaps the victim, dropping
//! its private pages itself (ADR 0123), and the fault is retried; when
//! there was nothing to reap it waits for the victim to go. While a
//! victim is dying nobody else is chosen, unless it takes too long.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use super::{Process, signal};
use crate::mm::memcg::MemCg;

/// How long a victim may take to die before another may be chosen.
const VICTIM_GRACE_NS: u64 = 5_000_000_000;
/// How long a fault waits for a victim to go before trying again.
const WAIT_NS: u64 = 1_000_000_000;

/// Processes killed since boot (/proc/vmstat `oom_kill`).
pub static KILLS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The memory the scope allows, in pages.
fn allowed(scope: Option<&MemCg>) -> u64 {
    match scope {
        Some(m) if m.max() != crate::mm::memcg::UNLIMITED => m.max(),
        _ => crate::mm::frame::stats().usable_frames,
    }
    .max(1)
}

fn in_scope(p: &Process, scope: Option<&'static MemCg>) -> bool {
    match scope {
        None => true,
        Some(s) => p.cgroup().memcg().is_some_and(|m| m.is_under(s)),
    }
}

/// The badness score of `p` (0 to 1000 and beyond; /proc/<pid>/oom_score):
/// its resident pages as thousandths of what `scope` allows, plus
/// oom_score_adj. 0 for processes that may not be killed.
pub fn score(p: &Process, scope: Option<&'static MemCg>) -> u64 {
    let adj = i64::from(p.oom_score_adj.load(Ordering::Relaxed));
    if adj <= -1000 || p.pid == 1 || p.is_zombie() {
        return 0;
    }
    let rss = p.aspace.lock().as_ref().map_or(0, |a| a.resident_pages());
    if rss == 0 {
        return 0;
    }
    let points = (rss * 1000 / allowed(scope)) as i64 + adj;
    points.max(1) as u64
}

/// A victim chosen earlier that is still dying (within its grace time).
fn dying_victim(scope: Option<&'static MemCg>) -> Option<Arc<Process>> {
    let now = crate::time::monotonic_ns();
    super::all().into_iter().find(|p| {
        let at = p.oom_killed_at.load(Ordering::Relaxed);
        at != 0 && !p.is_zombie() && now.saturating_sub(at) < VICTIM_GRACE_NS && in_scope(p, scope)
    })
}

/// Wait until `victim` has exited (or a while has passed, or the caller
/// is dying itself).
fn wait_for(victim: &Arc<Process>, me: &Arc<Process>) {
    let until = crate::time::monotonic_ns() + WAIT_NS;
    while !victim.is_zombie() && victim.aspace.lock().is_some() && crate::time::monotonic_ns() < until {
        if Arc::ptr_eq(victim, me) || me.exiting().is_some() {
            return;
        }
        crate::sched::sleep_until(crate::time::monotonic_ns() + 2_000_000);
    }
}

/// A page fault of `me` found no memory. Free some, killing a process if
/// it must. Returns false if nothing could be done (no process may be
/// killed): the fault then fails.
pub fn out_of_memory(me: &Arc<Process>) -> bool {
    let scope = me.cgroup().memcg().and_then(|m| m.at_limit());
    if let Some(m) = scope {
        m.events_oom.fetch_add(1, Ordering::Relaxed);
    } else if crate::mm::frame::reclaim(64) > 0 {
        // Clean page-cache pages went back: try again. (Cgroups are not
        // charged for the page cache, so this would not help them.)
        return true;
    }
    if let Some(v) = dying_victim(scope) {
        wait_for(&v, me);
        return true;
    }
    let victim = super::all()
        .into_iter()
        .filter(|p| in_scope(p, scope) && p.aspace.lock().is_some())
        .map(|p| (score(&p, scope), p))
        .filter(|(s, _)| *s > 0)
        .max_by_key(|(s, p)| (*s, p.pid));
    let Some((points, v)) = victim else {
        crate::log_error!("out of memory: no process may be killed");
        return false;
    };
    let rss = v.aspace.lock().as_ref().map_or(0, |a| a.resident_pages());
    crate::log_warn!(
        "out of memory{}: killed pid {} ({}), score {points}, {} KiB resident",
        scope.map_or(alloc::string::String::new(), |_| alloc::format!(" in cgroup {}", me.cgroup().path())),
        v.pid,
        *v.name.lock(),
        rss * 4
    );
    v.oom_killed_at.store(crate::time::monotonic_ns().max(1), Ordering::Relaxed);
    KILLS.fetch_add(1, Ordering::Relaxed);
    // The kill counts in the victim's cgroup and its ancestors, up to the
    // scope.
    let mut at = v.cgroup().memcg();
    while let Some(c) = at {
        c.events_oom_kill.fetch_add(1, Ordering::Relaxed);
        if scope.is_some_and(|s| core::ptr::eq(c, s)) {
            break;
        }
        at = c.parent();
    }
    signal::send_to_process(&v, signal::SIGKILL);
    if reap(&v, me) == 0 {
        wait_for(&v, me);
    }
    true
}

/// The reaper (ADR 0123): drop a killed victim's private pages now
/// rather than when it gets to run and exit. Not the caller's own, nor an
/// address space lent by a vfork parent, which shares it. Returns the
/// pages freed.
fn reap(victim: &Arc<Process>, me: &Arc<Process>) -> u64 {
    if Arc::ptr_eq(victim, me) || victim.aspace_lender.lock().is_some() {
        return 0;
    }
    let pages = victim.aspace.lock().as_mut().map_or(0, |a| a.reap());
    if pages > 0 {
        // No CPU may keep using the victim's old translations.
        super::finish_vm_change(victim);
        crate::log_info!("oom reaper: freed {} KiB of pid {} ({})", pages * 4, victim.pid, *victim.name.lock());
    }
    pages
}
