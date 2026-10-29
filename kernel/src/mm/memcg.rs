// SPDX-License-Identifier: MIT OR Apache-2.0

//! Memory accounting for cgroups (ADR 0045).
//!
//! Every anonymous page a process faults in (fresh zeroed pages, private
//! copies of file pages and copy-on-write copies) is charged to the
//! process's cgroup and each of its ancestors, and uncharged when the
//! frame is freed: the frame allocator remembers which counter each user
//! frame was charged to. A charge that would take a cgroup past its
//! `memory.max` fails, and the fault path runs the out-of-memory killer
//! within that cgroup (`proc/oom.rs`).
//!
//! Counters live in a fixed table of slots and are never freed: frames
//! name them by slot number. A removed cgroup's slot is reused once
//! nothing is charged to it any more.

use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU16, AtomicU64, Ordering};

use alloc::boxed::Box;

/// Slots for counters; slot 0 means "not charged".
const SLOTS: usize = 4096;
static TABLE: [AtomicPtr<MemCg>; SLOTS] = [const { AtomicPtr::new(core::ptr::null_mut()) }; SLOTS];
static ALLOC_LOCK: crate::sync::IrqSpinLock<()> = crate::sync::IrqSpinLock::new(());

/// No limit.
pub const UNLIMITED: u64 = u64::MAX;

/// One cgroup's memory counters, in pages.
#[derive(Debug)]
pub struct MemCg {
    pub id: u16,
    /// The parent's slot (0 for the root).
    parent: AtomicU16,
    pages: AtomicU64,
    peak: AtomicU64,
    /// memory.max and memory.high in pages ([`UNLIMITED`]: none).
    max: AtomicU64,
    high: AtomicU64,
    /// memory.events: times usage went over memory.high, charges refused
    /// at memory.max, out-of-memory situations, and processes killed.
    pub events_high: AtomicU64,
    pub events_max: AtomicU64,
    pub events_oom: AtomicU64,
    pub events_oom_kill: AtomicU64,
    /// The cgroup still exists (its slot is not reusable).
    live: AtomicBool,
}

impl MemCg {
    fn init(&self, parent: u16) {
        self.parent.store(parent, Ordering::Relaxed);
        for c in [&self.pages, &self.peak, &self.events_high, &self.events_max, &self.events_oom, &self.events_oom_kill]
        {
            c.store(0, Ordering::Relaxed);
        }
        self.max.store(UNLIMITED, Ordering::Relaxed);
        self.high.store(UNLIMITED, Ordering::Relaxed);
        self.live.store(true, Ordering::Release);
    }

    pub fn parent(&self) -> Option<&'static MemCg> {
        get(self.parent.load(Ordering::Relaxed))
    }

    /// Pages charged here (this cgroup and below).
    pub fn pages(&self) -> u64 {
        self.pages.load(Ordering::Relaxed)
    }

    pub fn peak(&self) -> u64 {
        self.peak.load(Ordering::Relaxed)
    }

    pub fn max(&self) -> u64 {
        self.max.load(Ordering::Relaxed)
    }

    pub fn set_max(&self, pages: u64) {
        self.max.store(pages, Ordering::Relaxed);
    }

    pub fn set_high(&self, pages: u64) {
        self.high.store(pages, Ordering::Relaxed);
    }

    /// Whether `self` is `other` or below it.
    pub fn is_under(&'static self, other: &MemCg) -> bool {
        let mut at = Some(self);
        while let Some(m) = at {
            if core::ptr::eq(m, other) {
                return true;
            }
            at = m.parent();
        }
        false
    }

    /// Charge one page here and to every ancestor. Fails, charging
    /// nothing, at the first that would go past its memory.max; that one
    /// is returned.
    pub fn try_charge(&'static self) -> Result<(), &'static MemCg> {
        let mut at = Some(self);
        while let Some(m) = at {
            let now = m.pages.fetch_add(1, Ordering::Relaxed) + 1;
            if now > m.max.load(Ordering::Relaxed) {
                m.pages.fetch_sub(1, Ordering::Relaxed);
                m.events_max.fetch_add(1, Ordering::Relaxed);
                let mut undo = Some(self);
                while let Some(u) = undo.filter(|u| !core::ptr::eq(*u, m)) {
                    u.pages.fetch_sub(1, Ordering::Relaxed);
                    undo = u.parent();
                }
                return Err(m);
            }
            if now > m.high.load(Ordering::Relaxed) {
                m.events_high.fetch_add(1, Ordering::Relaxed);
            }
            m.peak.fetch_max(now, Ordering::Relaxed);
            at = m.parent();
        }
        Ok(())
    }

    /// The first cgroup from here up that is at its memory.max.
    pub fn at_limit(&'static self) -> Option<&'static MemCg> {
        let mut at = Some(self);
        while let Some(m) = at {
            if m.pages() >= m.max() {
                return Some(m);
            }
            at = m.parent();
        }
        None
    }

    /// The cgroup was removed: its slot may be reused once nothing is
    /// charged to it.
    pub fn release(&self) {
        self.live.store(false, Ordering::Release);
    }
}

/// The counter in slot `id`.
pub fn get(id: u16) -> Option<&'static MemCg> {
    if id == 0 {
        return None;
    }
    let p = TABLE.get(usize::from(id))?.load(Ordering::Acquire);
    // SAFETY: Slots hold leaked boxes that are never freed.
    (!p.is_null()).then(|| unsafe { &*p })
}

/// New counters for a cgroup below `parent`. With every slot taken, the
/// cgroup's pages go uncharged (logged once).
pub fn new(parent: Option<&'static MemCg>) -> Option<&'static MemCg> {
    let parent_id = parent.map_or(0, |p| p.id);
    let _g = ALLOC_LOCK.lock();
    for (i, slot) in TABLE.iter().enumerate().skip(1) {
        let p = slot.load(Ordering::Acquire);
        if p.is_null() {
            let m: &'static MemCg = Box::leak(Box::new(MemCg {
                id: i as u16,
                parent: AtomicU16::new(0),
                pages: AtomicU64::new(0),
                peak: AtomicU64::new(0),
                max: AtomicU64::new(UNLIMITED),
                high: AtomicU64::new(UNLIMITED),
                events_high: AtomicU64::new(0),
                events_max: AtomicU64::new(0),
                events_oom: AtomicU64::new(0),
                events_oom_kill: AtomicU64::new(0),
                live: AtomicBool::new(false),
            }));
            m.init(parent_id);
            slot.store(core::ptr::from_ref(m).cast_mut(), Ordering::Release);
            return Some(m);
        }
        // SAFETY: As in `get`.
        let m = unsafe { &*p };
        if !m.live.load(Ordering::Acquire) && m.pages() == 0 {
            m.init(parent_id);
            return Some(m);
        }
    }
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !WARNED.swap(true, Ordering::Relaxed) {
        crate::log_warn!("memcg: all {SLOTS} slots in use; new cgroups' memory is not accounted");
    }
    None
}

/// Uncharge one page from counter `id` and its ancestors (a charged frame
/// was freed).
pub fn uncharge(id: u16) {
    let mut at = get(id);
    while let Some(m) = at {
        m.pages.fetch_sub(1, Ordering::Relaxed);
        at = m.parent();
    }
}

/// The counters pages faulted in by the current process are charged to.
pub fn current() -> Option<&'static MemCg> {
    if !crate::sched::started() {
        return None; // Early boot (the vDSO's pages): nothing to charge.
    }
    crate::proc::current().and_then(|p| p.cgroup().memcg())
}
