// SPDX-License-Identifier: MIT OR Apache-2.0

//! A test-and-test-and-set spinlock.
//!
//! This is the bootstrap lock: good enough for early boot and short critical
//! sections. A fair (ticket or queued) lock replaces it for contended paths
//! once the scheduler exists (milestone M4).

use core::cell::UnsafeCell;
use core::fmt;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

/// A mutual-exclusion spinlock protecting a `T`.
pub struct SpinLock<T: ?Sized> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: The lock hands out access to `T` to one holder at a time, so sharing
// the lock between threads only requires that `T` itself can be sent.
unsafe impl<T: ?Sized + Send> Sync for SpinLock<T> {}
// SAFETY: Moving the lock moves the `T` it owns.
unsafe impl<T: ?Sized + Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(value: T) -> Self {
        SpinLock { locked: AtomicBool::new(false), value: UnsafeCell::new(value) }
    }

    pub fn into_inner(self) -> T {
        self.value.into_inner()
    }
}

impl<T: ?Sized> SpinLock<T> {
    /// Acquire the lock, spinning until it is free.
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        loop {
            if let Some(guard) = self.try_lock() {
                return guard;
            }
            // Spin on a plain load to keep the cache line shared while we wait.
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
    }

    /// Acquire the lock if it is free right now.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| SpinLockGuard { lock: self })
    }

    /// Whether some holder currently has the lock. Only useful as a hint, for
    /// example to avoid deadlocking a panic handler on a lock its caller held.
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }

    /// Release the lock without a guard.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that no guard for this lock is alive (for
    /// example: the only holder was the code that just panicked on this CPU).
    pub unsafe fn force_unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.value.get_mut()
    }
}

impl<T: ?Sized> fmt::Debug for SpinLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpinLock").field("locked", &self.is_locked()).finish_non_exhaustive()
    }
}

/// Proof of holding a [`SpinLock`]; releases it when dropped.
pub struct SpinLockGuard<'a, T: ?Sized> {
    lock: &'a SpinLock<T>,
}

impl<T: ?Sized> Deref for SpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: The guard exists only while `locked` is held by us, so no
        // other reference to the value exists.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T: ?Sized> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: As in `deref`; `&mut self` makes this access unique.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T: ?Sized> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for SpinLockGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::SpinLock;
    use std::sync::Arc;
    use std::thread;
    use std::vec::Vec;

    #[test]
    fn try_lock_excludes() {
        let l = SpinLock::new(1);
        let g = l.lock();
        assert!(l.try_lock().is_none());
        drop(g);
        assert_eq!(*l.try_lock().unwrap(), 1);
    }

    #[test]
    fn counts_under_contention() {
        const THREADS: usize = 8;
        const ITERS: usize = 20_000;
        let l = Arc::new(SpinLock::new(0usize));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let l = Arc::clone(&l);
                thread::spawn(move || {
                    for _ in 0..ITERS {
                        *l.lock() += 1;
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(*l.lock(), THREADS * ITERS);
    }
}
