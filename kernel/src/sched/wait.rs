// SPDX-License-Identifier: MIT OR Apache-2.0

//! Blocking primitives: wait queues and a sleeping mutex.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::fmt;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use super::{Thread, current, schedule, started, wake};
use crate::arch::cpu::InterruptGuard;
use crate::sync::IrqSpinLock;

/// How a wait ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitResult {
    Ready,
    Interrupted,
    TimedOut,
}

/// Threads waiting for a condition.
#[derive(Debug)]
pub struct WaitQueue {
    waiters: IrqSpinLock<VecDeque<Arc<Thread>>>,
}

impl WaitQueue {
    pub const fn new() -> WaitQueue {
        WaitQueue { waiters: IrqSpinLock::new(VecDeque::new()) }
    }

    /// Block until `cond` returns true. `cond` is evaluated with the queue
    /// locked, so a waker that changes the condition and then calls `wake_*`
    /// cannot be missed.
    pub fn wait_until(&self, cond: impl FnMut() -> bool) {
        self.wait_inner(cond, false, None);
    }

    /// Like [`WaitQueue::wait_until`], but give up when a signal is pending
    /// for the current thread. Returns true if interrupted.
    pub fn wait_until_interruptible(&self, cond: impl FnMut() -> bool) -> bool {
        self.wait_inner(cond, true, None) == WaitResult::Interrupted
    }

    /// Interruptible wait with a deadline on the monotonic clock.
    pub fn wait_until_deadline(&self, cond: impl FnMut() -> bool, deadline_ns: u64) -> WaitResult {
        self.wait_inner(cond, true, Some(deadline_ns))
    }

    /// Uninterruptible wait with a deadline (device I/O, where a signal
    /// must not abandon a transfer in flight). Returns false on timeout.
    pub fn wait_until_timeout(&self, cond: impl FnMut() -> bool, deadline_ns: u64) -> bool {
        self.wait_inner(cond, false, Some(deadline_ns)) == WaitResult::Ready
    }

    fn wait_inner(&self, mut cond: impl FnMut() -> bool, interruptible: bool, deadline: Option<u64>) -> WaitResult {
        loop {
            let _irq = InterruptGuard::new();
            let me = {
                let mut w = self.waiters.lock();
                if cond() {
                    return WaitResult::Ready;
                }
                if interruptible && crate::proc::signal::pending_for_current() {
                    return WaitResult::Interrupted;
                }
                if deadline.is_some_and(|d| crate::time::monotonic_ns() >= d) {
                    return WaitResult::TimedOut;
                }
                if !started() {
                    drop(w);
                    drop(_irq);
                    core::hint::spin_loop();
                    continue;
                }
                let t = current();
                t.block_prepare();
                w.push_back(t.clone());
                t
            };
            if let Some(d) = deadline {
                super::add_sleeper(d, me.clone());
            }
            schedule();
            // Woken by someone else (a timeout, a signal, a spurious wakeup):
            // leave the queue so a later wake_one is not wasted on us.
            self.waiters.lock().retain(|t| !Arc::ptr_eq(t, &me));
            if let Some(d) = deadline {
                super::remove_sleeper(d, &me);
            }
        }
    }

    /// Wake one waiter. Returns whether one was woken.
    pub fn wake_one(&self) -> bool {
        loop {
            let Some(t) = self.waiters.lock().pop_front() else { return false };
            if wake(&t) {
                return true;
            }
        }
    }

    /// Wake every waiter.
    pub fn wake_all(&self) {
        let all: VecDeque<_> = core::mem::take(&mut *self.waiters.lock());
        for t in all {
            wake(&t);
        }
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// A mutual-exclusion lock that blocks (sleeps) instead of spinning. Use it
/// for long critical sections; never take it in interrupt handlers.
pub struct Mutex<T> {
    locked: AtomicBool,
    waiters: WaitQueue,
    value: UnsafeCell<T>,
}

// SAFETY: The lock hands out access to `T` to one holder at a time.
unsafe impl<T: Send> Sync for Mutex<T> {}
// SAFETY: Moving the mutex moves the `T` it owns.
unsafe impl<T: Send> Send for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Mutex<T> {
        Mutex { locked: AtomicBool::new(false), waiters: WaitQueue::new(), value: UnsafeCell::new(value) }
    }

    fn try_acquire(&self) -> bool {
        self.locked.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        if !self.try_acquire() {
            self.waiters.wait_until(|| self.try_acquire());
        }
        MutexGuard { m: self }
    }
}

impl<T> fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mutex").field("locked", &self.locked.load(Ordering::Relaxed)).finish_non_exhaustive()
    }
}

pub struct MutexGuard<'a, T> {
    m: &'a Mutex<T>,
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: The guard proves the lock is held.
        unsafe { &*self.m.value.get() }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: The guard proves the lock is held, and `&mut self` is unique.
        unsafe { &mut *self.m.value.get() }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.m.locked.store(false, Ordering::Release);
        self.m.waiters.wake_one();
    }
}

impl<T> fmt::Debug for MutexGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MutexGuard")
    }
}
