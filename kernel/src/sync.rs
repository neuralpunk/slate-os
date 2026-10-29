// SPDX-License-Identifier: MIT OR Apache-2.0

//! Kernel locking on top of `slate-sync`.

use core::panic::Location;
use core::sync::atomic::{AtomicPtr, Ordering};

use slate_sync::{SpinLock, SpinLockGuard};

use crate::arch::cpu::InterruptGuard;

/// Spins after which a lock is considered deadlocked (seconds of waiting
/// with interrupts masked).
const DEADLOCK_SPINS: u64 = 200_000_000;

/// A spinlock that masks interrupts on this CPU while held, so an interrupt
/// handler that takes the same lock cannot deadlock against the code it
/// interrupted.
#[derive(Debug)]
pub struct IrqSpinLock<T> {
    inner: SpinLock<T>,
    /// Where it was last taken (a deadlock's report names the holder).
    taken_at: AtomicPtr<Location<'static>>,
}

/// Holds the lock and keeps interrupts masked. Fields drop in declaration
/// order: the lock is released before interrupts are restored.
#[derive(Debug)]
pub struct IrqSpinLockGuard<'a, T> {
    guard: SpinLockGuard<'a, T>,
    _irq: InterruptGuard,
}

impl<T> IrqSpinLock<T> {
    pub const fn new(value: T) -> Self {
        IrqSpinLock { inner: SpinLock::new(value), taken_at: AtomicPtr::new(core::ptr::null_mut()) }
    }

    /// Take the lock. Spinning far longer than any masked critical section
    /// can last means a deadlock (often the same CPU taking a lock it
    /// already holds): panic and name the caller rather than hang silently.
    #[track_caller]
    pub fn lock(&self) -> IrqSpinLockGuard<'_, T> {
        let irq = InterruptGuard::new();
        let mut spins: u64 = 0;
        loop {
            if let Some(guard) = self.inner.try_lock() {
                self.taken_at.store(Location::caller() as *const _ as *mut _, Ordering::Relaxed);
                return IrqSpinLockGuard { guard, _irq: irq };
            }
            while self.inner.is_locked() {
                core::hint::spin_loop();
                spins += 1;
                if spins == DEADLOCK_SPINS {
                    // SAFETY: Only `&'static Location`s are stored.
                    // (No allocation here: the allocator's lock may be the
                    // one held.)
                    match unsafe { self.taken_at.load(Ordering::Relaxed).as_ref() } {
                        Some(holder) => panic!(
                            "IrqSpinLock deadlock: lock at {} still held after {spins} spins (taken at {holder})",
                            Location::caller()
                        ),
                        None => panic!(
                            "IrqSpinLock deadlock: lock at {} still held after {spins} spins",
                            Location::caller()
                        ),
                    }
                }
            }
        }
    }

    /// Take the lock if it is free.
    #[track_caller]
    pub fn try_lock(&self) -> Option<IrqSpinLockGuard<'_, T>> {
        let irq = InterruptGuard::new();
        let guard = self.inner.try_lock()?;
        self.taken_at.store(Location::caller() as *const _ as *mut _, Ordering::Relaxed);
        Some(IrqSpinLockGuard { guard, _irq: irq })
    }

    pub fn is_locked(&self) -> bool {
        self.inner.is_locked()
    }

    /// # Safety
    ///
    /// See [`SpinLock::force_unlock`].
    pub unsafe fn force_unlock(&self) {
        // SAFETY: Forwarded to the caller.
        unsafe { self.inner.force_unlock() }
    }
}

impl<T> core::ops::Deref for IrqSpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T> core::ops::DerefMut for IrqSpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}
