// SPDX-License-Identifier: MIT OR Apache-2.0

//! Locks for threads (ADR 0073): a futex word under a mutex and a
//! condition variable. Uncontended, they are one atomic operation; a
//! waiter sleeps in the kernel (native `futex_wait`/`futex_wake`, or
//! futex(2) on Linux) instead of spinning.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

use crate::{Errno, Result, sys};

/// futex(2) on Linux: FUTEX_WAIT, FUTEX_WAKE and FUTEX_PRIVATE_FLAG
/// (musl's internal `futex.h`, ADR 0009).
const LINUX_WAIT: usize = 128;
const LINUX_WAIT_SHARED: usize = 0;
const LINUX_WAKE: usize = 129;

/// Sleep while `word` holds `expected`, for at most `timeout_ns`. Ok on a
/// wakeup (or a spurious return); EAGAIN when the word differs,
/// ETIMEDOUT, EINTR.
pub fn futex_wait(word: &AtomicU32, expected: u32, timeout_ns: Option<u64>) -> Result<()> {
    wait(word, expected, timeout_ns, LINUX_WAIT)
}

/// [`futex_wait`] for a thread-ID word the kernel clears at a thread's
/// end. Linux wakes those without FUTEX_PRIVATE_FLAG, and a private
/// waiter does not see that wakeup (observed on the host; ADR 0073), so
/// this waits shared there.
pub(crate) fn futex_wait_tid(word: &AtomicU32, expected: u32) -> Result<()> {
    wait(word, expected, None, LINUX_WAIT_SHARED)
}

fn wait(word: &AtomicU32, expected: u32, timeout_ns: Option<u64>, linux_op: usize) -> Result<()> {
    let ts = timeout_ns.map(|ns| [(ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as i64]);
    let tp = ts.as_ref().map_or(0, |t| t.as_ptr() as usize);
    let w = word.as_ptr() as usize;
    if sys::native() {
        crate::syscall!(slate_abi::nr::FUTEX_WAIT as usize, w, expected, tp).map(|_| ())
    } else {
        crate::syscall!(sys::FUTEX, w, linux_op, expected, tp).map(|_| ())
    }
}

/// Wake up to `n` threads sleeping on `word`; returns how many woke.
pub fn futex_wake(word: &AtomicU32, n: u32) -> usize {
    let w = word.as_ptr() as usize;
    let r = if sys::native() {
        crate::syscall!(slate_abi::nr::FUTEX_WAKE as usize, w, n)
    } else {
        crate::syscall!(sys::FUTEX, w, LINUX_WAKE, n.min(i32::MAX as u32))
    };
    r.unwrap_or(0)
}

/// A mutex without data: 0 unlocked, 1 locked, 2 locked with sleepers
/// (the classic three-state futex lock). slate-libc's pthread mutexes
/// are these.
#[derive(Debug, Default)]
pub struct RawMutex(AtomicU32);

impl RawMutex {
    pub const fn new() -> RawMutex {
        RawMutex(AtomicU32::new(0))
    }

    pub fn try_lock(&self) -> bool {
        self.0.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    pub fn lock(&self) {
        if self.try_lock() {
            return;
        }
        // Mark it contended; whoever unlocks wakes one sleeper.
        while self.0.swap(2, Ordering::Acquire) != 0 {
            let _ = futex_wait(&self.0, 2, None);
        }
    }

    /// Lock, giving up after `timeout_ns` (ETIMEDOUT).
    pub fn lock_timeout(&self, timeout_ns: u64) -> Result<()> {
        if self.try_lock() {
            return Ok(());
        }
        let until = crate::time::monotonic_ns().saturating_add(timeout_ns);
        while self.0.swap(2, Ordering::Acquire) != 0 {
            let left = until.saturating_sub(crate::time::monotonic_ns());
            if left == 0 {
                return Err(Errno::ETIMEDOUT);
            }
            let _ = futex_wait(&self.0, 2, Some(left));
        }
        Ok(())
    }

    /// # Safety
    ///
    /// The calling thread must hold the lock.
    pub unsafe fn unlock(&self) {
        if self.0.swap(0, Ordering::Release) == 2 {
            futex_wake(&self.0, 1);
        }
    }

    pub fn is_locked(&self) -> bool {
        self.0.load(Ordering::Relaxed) != 0
    }
}

/// A mutual-exclusion lock protecting a `T`.
#[derive(Default)]
pub struct Mutex<T: ?Sized> {
    raw: RawMutex,
    value: UnsafeCell<T>,
}

// SAFETY: The lock hands out access to `T` to one holder at a time.
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}
// SAFETY: Moving the lock moves the `T` it owns.
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Mutex<T> {
        Mutex { raw: RawMutex::new(), value: UnsafeCell::new(value) }
    }
}

impl<T: ?Sized> Mutex<T> {
    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.raw.lock();
        MutexGuard { lock: self }
    }

    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        self.raw.try_lock().then_some(MutexGuard { lock: self })
    }
}

impl<T: ?Sized> core::fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mutex").field("locked", &self.raw.is_locked()).finish_non_exhaustive()
    }
}

/// Access to a [`Mutex`]'s value; unlocks when dropped.
pub struct MutexGuard<'a, T: ?Sized> {
    lock: &'a Mutex<T>,
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: The guard holds the lock.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: The guard holds the lock, and `&mut self` is unique.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: The guard holds the lock.
        unsafe { self.lock.raw.unlock() }
    }
}

impl<T: ?Sized> core::fmt::Debug for MutexGuard<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MutexGuard")
    }
}

/// A condition variable: a counter that every notification bumps, so a
/// waiter that unlocked before a notification still sees it.
#[derive(Debug, Default)]
pub struct Condvar(AtomicU32);

impl Condvar {
    pub const fn new() -> Condvar {
        Condvar(AtomicU32::new(0))
    }

    /// Unlock `m`, sleep until notified (or spuriously), lock it again.
    ///
    /// # Safety
    ///
    /// The calling thread must hold `m`.
    pub unsafe fn wait_raw(&self, m: &RawMutex, timeout_ns: Option<u64>) -> Result<()> {
        let seq = self.0.load(Ordering::Relaxed);
        // SAFETY: Forwarded from the caller.
        unsafe { m.unlock() };
        let r = futex_wait(&self.0, seq, timeout_ns);
        // Relock as contended: other waiters may be asleep on `m`.
        while m.0.swap(2, Ordering::Acquire) != 0 {
            let _ = futex_wait(&m.0, 2, None);
        }
        match r {
            Err(Errno::ETIMEDOUT) => Err(Errno::ETIMEDOUT),
            _ => Ok(()),
        }
    }

    pub fn wait<'a, T: ?Sized>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
        let lock = guard.lock;
        core::mem::forget(guard);
        // SAFETY: The guard held the lock; a new guard takes it over.
        let _ = unsafe { self.wait_raw(&lock.raw, None) };
        MutexGuard { lock }
    }

    /// As [`wait`](Self::wait), at most `timeout_ns`; the flag says
    /// whether it timed out.
    pub fn wait_timeout<'a, T: ?Sized>(&self, guard: MutexGuard<'a, T>, timeout_ns: u64) -> (MutexGuard<'a, T>, bool) {
        let lock = guard.lock;
        core::mem::forget(guard);
        // SAFETY: As in `wait`.
        let r = unsafe { self.wait_raw(&lock.raw, Some(timeout_ns)) };
        (MutexGuard { lock }, r.is_err())
    }

    pub fn notify_one(&self) {
        self.0.fetch_add(1, Ordering::Release);
        futex_wake(&self.0, 1);
    }

    pub fn notify_all(&self) {
        self.0.fetch_add(1, Ordering::Release);
        futex_wake(&self.0, u32::MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn mutex_counts_across_threads() {
        // Host threads (std's) contend on the futex lock.
        let m = Arc::new(Mutex::new(0u64));
        let hs: std::vec::Vec<_> = (0..4)
            .map(|_| {
                let m = m.clone();
                std::thread::spawn(move || {
                    for _ in 0..20_000 {
                        *m.lock() += 1;
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(*m.lock(), 80_000);
    }

    #[test]
    fn condvar_hands_over() {
        let pair = Arc::new((Mutex::new(false), Condvar::new()));
        let p2 = pair.clone();
        let h = std::thread::spawn(move || {
            let (m, c) = &*p2;
            *m.lock() = true;
            c.notify_one();
        });
        let (m, c) = &*pair;
        let mut g = m.lock();
        while !*g {
            g = c.wait(g);
        }
        drop(g);
        h.join().unwrap();
        let (g, timed_out) = c.wait_timeout(m.lock(), 1_000_000);
        assert!(timed_out && *g);
    }
}
