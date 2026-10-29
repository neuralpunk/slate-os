// SPDX-License-Identifier: MIT OR Apache-2.0

//! One-time initialization of a value in a `static`.

use core::cell::UnsafeCell;
use core::fmt;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};

const EMPTY: u8 = 0;
const RUNNING: u8 = 1;
const READY: u8 = 2;

/// A cell written exactly once, then shared read-only.
///
/// Unlike `std::sync::OnceLock` it never blocks on a scheduler: a second
/// caller racing the initializer spins until the value is ready.
pub struct Once<T> {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: The value is written once, before `state` becomes READY with
// release ordering, and only read after observing READY with acquire
// ordering; afterwards it is only shared immutably.
unsafe impl<T: Send + Sync> Sync for Once<T> {}
// SAFETY: Moving the cell moves the `T` it may own.
unsafe impl<T: Send> Send for Once<T> {}

impl<T> Once<T> {
    pub const fn new() -> Self {
        Once { state: AtomicU8::new(EMPTY), value: UnsafeCell::new(MaybeUninit::uninit()) }
    }

    /// Initialize with `f` if nobody has yet, and return the value.
    ///
    /// If `f` panics the cell stays in the running state forever and other
    /// callers spin; in the kernel a panic halts anyway.
    pub fn call_once(&self, f: impl FnOnce() -> T) -> &T {
        match self.state.compare_exchange(EMPTY, RUNNING, Ordering::Acquire, Ordering::Acquire) {
            Ok(_) => {
                // SAFETY: Winning the EMPTY -> RUNNING exchange makes this the
                // only writer, and no reader looks before READY.
                unsafe { (*self.value.get()).write(f()) };
                self.state.store(READY, Ordering::Release);
            }
            Err(_) => {
                while self.state.load(Ordering::Acquire) != READY {
                    core::hint::spin_loop();
                }
            }
        }
        // SAFETY: The state is READY, so the value is initialized and never
        // written again.
        unsafe { (*self.value.get()).assume_init_ref() }
    }

    /// The value, if initialization has finished.
    pub fn get(&self) -> Option<&T> {
        if self.state.load(Ordering::Acquire) == READY {
            // SAFETY: As in `call_once`.
            Some(unsafe { (*self.value.get()).assume_init_ref() })
        } else {
            None
        }
    }
}

impl<T> Default for Once<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for Once<T> {
    fn drop(&mut self) {
        if *self.state.get_mut() == READY {
            // SAFETY: READY means initialized, and `&mut self` means no
            // outstanding references.
            unsafe { self.value.get_mut().assume_init_drop() };
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for Once<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get() {
            Some(v) => f.debug_tuple("Once").field(v).finish(),
            None => f.write_str("Once(<uninit>)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Once;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::vec::Vec;

    #[test]
    fn initializes_once() {
        let o = Once::new();
        assert!(o.get().is_none());
        assert_eq!(*o.call_once(|| 5), 5);
        assert_eq!(*o.call_once(|| 6), 5);
        assert_eq!(o.get(), Some(&5));
    }

    #[test]
    fn racing_initializers_run_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let o = Arc::new(Once::new());
        let hs: Vec<_> = (0..8)
            .map(|i| {
                let (o, calls) = (Arc::clone(&o), Arc::clone(&calls));
                thread::spawn(move || {
                    *o.call_once(|| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        i
                    })
                })
            })
            .collect();
        let seen: Vec<_> = hs.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(seen.iter().all(|&v| v == seen[0]));
    }

    #[test]
    fn drops_value() {
        let rc = Arc::new(());
        {
            let o = Once::new();
            o.call_once(|| Arc::clone(&rc));
            assert_eq!(Arc::strong_count(&rc), 2);
        }
        assert_eq!(Arc::strong_count(&rc), 1);
    }
}
