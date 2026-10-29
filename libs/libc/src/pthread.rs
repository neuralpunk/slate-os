// SPDX-License-Identifier: MIT OR Apache-2.0

//! <pthread.h> and <sched.h> (POSIX threads, from the POSIX.1-2017
//! descriptions) on slate-rt's threads and futex locks (ADR 0073):
//! threads with join and detach, mutexes (normal, recursive, error
//! checking), condition variables on either clock, read-write locks,
//! once, and thread-specific data. Functions return an error number
//! rather than setting `errno`, as POSIX says.
//!
//! Not here (docs/GAPS.md): cancellation, pthread_kill and
//! pthread_sigmask, barriers and spin locks, scheduling attributes,
//! process-shared and robust mutexes.

use alloc::sync::Arc;
use core::cell::Cell;
use core::ffi::{c_int, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering};

use slate_rt::sync::{Condvar, Mutex, RawMutex, futex_wait, futex_wake};
use slate_rt::thread::{self, JoinHandle};
use slate_rt::{Errno, time};

/// A thread as `pthread_t` points to it.
struct Thread {
    handle: Mutex<Option<JoinHandle<()>>>,
    result: AtomicPtr<c_void>,
}

static MAIN: Thread = Thread { handle: Mutex::new(None), result: AtomicPtr::new(null_mut()) };

#[thread_local]
static SELF: Cell<*const Thread> = Cell::new(core::ptr::null());

/// The calling thread's ID, cached (slate-libc's fork clears it).
#[thread_local]
static TID: Cell<u32> = Cell::new(0);

fn my_tid() -> u32 {
    if TID.get() == 0 {
        TID.set(thread::current_id());
    }
    TID.get()
}

/// After fork, the child's one thread has a new ID.
pub(crate) fn after_fork() {
    TID.set(0);
}

pub type PthreadT = usize;

/// `pthread_attr_t`: the stack size and the detach state.
#[repr(C)]
pub struct Attr {
    stack: usize,
    detached: c_int,
    _reserved: [c_int; 13],
}

pub const PTHREAD_CREATE_JOINABLE: c_int = 0;
pub const PTHREAD_CREATE_DETACHED: c_int = 1;

/// The thread's end: its result, then its thread-specific data's
/// destructors.
fn finish(t: *const Thread, value: *mut c_void) {
    // SAFETY: `t` is the calling thread's own record, alive while it runs.
    unsafe { (*t).result.store(value, Ordering::Release) };
    run_destructors();
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_create(
    out: *mut PthreadT,
    attr: *const Attr,
    start: extern "C" fn(*mut c_void) -> *mut c_void,
    arg: *mut c_void,
) -> c_int {
    // SAFETY: C passes null or an initialised attribute object.
    let (stack, detached) = match unsafe { attr.as_ref() } {
        Some(a) => (if a.stack == 0 { thread::DEFAULT_STACK } else { a.stack }, a.detached == PTHREAD_CREATE_DETACHED),
        None => (thread::DEFAULT_STACK, false),
    };
    let t = Arc::new(Thread { handle: Mutex::new(None), result: AtomicPtr::new(null_mut()) });
    let mine = t.clone();
    let arg = arg as usize;
    let r = thread::spawn_with(stack, move || {
        SELF.set(Arc::as_ptr(&mine));
        let v = start(arg as *mut c_void);
        finish(Arc::as_ptr(&mine), v);
    });
    let h = match r {
        Ok(h) => h,
        Err(_) => return Errno::EAGAIN.0,
    };
    let id = Arc::as_ptr(&t) as PthreadT;
    if detached {
        drop(h);
    } else {
        *t.handle.lock() = Some(h);
        // The creator's reference, given back by join or detach.
        let _ = Arc::into_raw(t.clone());
    }
    // SAFETY: C passes room for a `pthread_t`.
    unsafe { *out = id };
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_join(t: PthreadT, out: *mut *mut c_void) -> c_int {
    if t == pthread_self() {
        return Errno::EDEADLK.0;
    }
    if t == &MAIN as *const Thread as PthreadT {
        return Errno::EINVAL.0;
    }
    // SAFETY: A joinable `pthread_t` holds the creator's reference.
    let th = unsafe { &*(t as *const Thread) };
    let Some(h) = th.handle.lock().take() else { return Errno::EINVAL.0 };
    let _ = h.finish();
    if !out.is_null() {
        // SAFETY: C passes room for the result.
        unsafe { *out = th.result.load(Ordering::Acquire) };
    }
    // SAFETY: The reference `pthread_create` kept for the joiner.
    drop(unsafe { Arc::from_raw(t as *const Thread) });
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_detach(t: PthreadT) -> c_int {
    if t == &MAIN as *const Thread as PthreadT {
        return Errno::EINVAL.0;
    }
    // SAFETY: As in `pthread_join`.
    let th = unsafe { &*(t as *const Thread) };
    let Some(h) = th.handle.lock().take() else { return Errno::EINVAL.0 };
    drop(h);
    // SAFETY: As in `pthread_join`.
    drop(unsafe { Arc::from_raw(t as *const Thread) });
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn pthread_self() -> PthreadT {
    let me = SELF.get();
    if me.is_null() { &MAIN as *const Thread as PthreadT } else { me as PthreadT }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn pthread_equal(a: PthreadT, b: PthreadT) -> c_int {
    c_int::from(a == b)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn pthread_exit(value: *mut c_void) -> ! {
    finish(pthread_self() as *const Thread, value);
    crate::stdio::flush_all();
    thread::exit(0)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn sched_yield() -> c_int {
    // No yield call: a zero sleep passes through the scheduler.
    let _ = time::sleep_ns(0);
    0
}

// --- attributes ---------------------------------------------------------------

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_init(a: *mut Attr) -> c_int {
    // SAFETY: C passes room for the attribute object.
    unsafe { a.write(Attr { stack: thread::DEFAULT_STACK, detached: 0, _reserved: [0; 13] }) };
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn pthread_attr_destroy(_a: *mut Attr) -> c_int {
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setstacksize(a: *mut Attr, size: usize) -> c_int {
    if size < PTHREAD_STACK_MIN {
        return Errno::EINVAL.0;
    }
    // SAFETY: An initialised attribute object.
    unsafe { (*a).stack = size };
    0
}

/// The smallest stack a thread may ask for (also in <limits.h>).
pub const PTHREAD_STACK_MIN: usize = 16384;

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getstacksize(a: *const Attr, size: *mut usize) -> c_int {
    // SAFETY: An initialised attribute object and room for the answer.
    unsafe { *size = (*a).stack };
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setdetachstate(a: *mut Attr, state: c_int) -> c_int {
    if state != PTHREAD_CREATE_JOINABLE && state != PTHREAD_CREATE_DETACHED {
        return Errno::EINVAL.0;
    }
    // SAFETY: An initialised attribute object.
    unsafe { (*a).detached = state };
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getdetachstate(a: *const Attr, state: *mut c_int) -> c_int {
    // SAFETY: As above.
    unsafe { *state = (*a).detached };
    0
}

// --- mutexes ------------------------------------------------------------------

pub const PTHREAD_MUTEX_NORMAL: c_int = 0;
pub const PTHREAD_MUTEX_RECURSIVE: c_int = 1;
pub const PTHREAD_MUTEX_ERRORCHECK: c_int = 2;

/// `pthread_mutex_t`: all zeros is a default (normal) mutex.
#[repr(C)]
pub struct PMutex {
    lock: RawMutex,
    kind: c_int,
    owner: AtomicU32,
    count: u32,
    _reserved: [u64; 3],
}

/// `pthread_mutexattr_t`.
#[repr(C)]
pub struct MutexAttr {
    kind: c_int,
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_init(a: *mut MutexAttr) -> c_int {
    // SAFETY: C passes room for the object.
    unsafe { (*a).kind = PTHREAD_MUTEX_NORMAL };
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn pthread_mutexattr_destroy(_a: *mut MutexAttr) -> c_int {
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_settype(a: *mut MutexAttr, kind: c_int) -> c_int {
    if !(PTHREAD_MUTEX_NORMAL..=PTHREAD_MUTEX_ERRORCHECK).contains(&kind) {
        return Errno::EINVAL.0;
    }
    // SAFETY: An initialised object.
    unsafe { (*a).kind = kind };
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_gettype(a: *const MutexAttr, kind: *mut c_int) -> c_int {
    // SAFETY: As above.
    unsafe { *kind = (*a).kind };
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_init(m: *mut PMutex, a: *const MutexAttr) -> c_int {
    // SAFETY: C passes room for the mutex and null or an attribute object.
    unsafe {
        let kind = a.as_ref().map_or(PTHREAD_MUTEX_NORMAL, |a| a.kind);
        m.write(PMutex { lock: RawMutex::new(), kind, owner: AtomicU32::new(0), count: 0, _reserved: [0; 3] });
    }
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_destroy(m: *mut PMutex) -> c_int {
    // SAFETY: An initialised mutex.
    if unsafe { (*m).lock.is_locked() } { Errno::EBUSY.0 } else { 0 }
}

/// Lock `m`; `wait` says how: block, give up at once, or give up at a
/// deadline (nanoseconds left).
unsafe fn mutex_lock(m: *mut PMutex, wait: Option<Option<u64>>) -> c_int {
    // SAFETY: C passes an initialised mutex; only its owner touches
    // `count`.
    let m = unsafe { &mut *m };
    if m.kind != PTHREAD_MUTEX_NORMAL && m.owner.load(Ordering::Relaxed) == my_tid() {
        if m.kind == PTHREAD_MUTEX_ERRORCHECK {
            return Errno::EDEADLK.0;
        }
        m.count += 1;
        return 0;
    }
    match wait {
        Some(None) => m.lock.lock(),
        Some(Some(ns)) => {
            if m.lock.lock_timeout(ns).is_err() {
                return Errno::ETIMEDOUT.0;
            }
        }
        None => {
            if !m.lock.try_lock() {
                return Errno::EBUSY.0;
            }
        }
    }
    if m.kind != PTHREAD_MUTEX_NORMAL {
        m.owner.store(my_tid(), Ordering::Relaxed);
        m.count = 1;
    }
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_lock(m: *mut PMutex) -> c_int {
    // SAFETY: Forwarded.
    unsafe { mutex_lock(m, Some(None)) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_trylock(m: *mut PMutex) -> c_int {
    // SAFETY: Forwarded.
    unsafe { mutex_lock(m, None) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_timedlock(m: *mut PMutex, at: *const Timespec) -> c_int {
    // SAFETY: C passes an absolute CLOCK_REALTIME time.
    match unsafe { left_until(at, time::CLOCK_REALTIME) } {
        // SAFETY: Forwarded.
        Ok(ns) => unsafe { mutex_lock(m, Some(Some(ns))) },
        Err(e) => e,
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_unlock(m: *mut PMutex) -> c_int {
    // SAFETY: An initialised mutex.
    let m = unsafe { &mut *m };
    if m.kind != PTHREAD_MUTEX_NORMAL {
        if m.owner.load(Ordering::Relaxed) != my_tid() {
            return Errno::EPERM.0;
        }
        m.count -= 1;
        if m.count > 0 {
            return 0;
        }
        m.owner.store(0, Ordering::Relaxed);
    }
    // SAFETY: The caller holds it (the normal kind takes C's word).
    unsafe { m.lock.unlock() };
    0
}

// --- condition variables ------------------------------------------------------

#[repr(C)]
pub struct Timespec {
    sec: i64,
    nsec: i64,
}

/// Nanoseconds from now until `at` on `clock` (0 if past); EINVAL for a
/// malformed time.
unsafe fn left_until(at: *const Timespec, clock: u32) -> Result<u64, c_int> {
    // SAFETY: C passes a timespec.
    let at = unsafe { &*at };
    if !(0..1_000_000_000).contains(&at.nsec) {
        return Err(Errno::EINVAL.0);
    }
    let (s, ns) = time::now(clock);
    let left = (i128::from(at.sec) - i128::from(s)) * 1_000_000_000 + i128::from(at.nsec - ns);
    Ok(left.clamp(0, i128::from(u64::MAX)) as u64)
}

/// `pthread_cond_t`: all zeros is a condition variable on CLOCK_REALTIME.
#[repr(C)]
pub struct PCond {
    cv: Condvar,
    clock: c_int,
    _reserved: [u64; 5],
}

/// `pthread_condattr_t`.
#[repr(C)]
pub struct CondAttr {
    clock: c_int,
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_init(a: *mut CondAttr) -> c_int {
    // SAFETY: C passes room for the object.
    unsafe { (*a).clock = time::CLOCK_REALTIME as c_int };
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn pthread_condattr_destroy(_a: *mut CondAttr) -> c_int {
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_setclock(a: *mut CondAttr, clock: c_int) -> c_int {
    if clock != time::CLOCK_REALTIME as c_int && clock != time::CLOCK_MONOTONIC as c_int {
        return Errno::EINVAL.0;
    }
    // SAFETY: An initialised object.
    unsafe { (*a).clock = clock };
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_getclock(a: *const CondAttr, clock: *mut c_int) -> c_int {
    // SAFETY: As above.
    unsafe { *clock = (*a).clock };
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_init(c: *mut PCond, a: *const CondAttr) -> c_int {
    // SAFETY: C passes room for the object and null or an attribute object.
    unsafe {
        let clock = a.as_ref().map_or(time::CLOCK_REALTIME as c_int, |a| a.clock);
        c.write(PCond { cv: Condvar::new(), clock, _reserved: [0; 5] });
    }
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn pthread_cond_destroy(_c: *mut PCond) -> c_int {
    0
}

/// Wait on `c` with `m` held, at most `timeout` nanoseconds.
unsafe fn cond_wait(c: *mut PCond, m: *mut PMutex, timeout: Option<u64>) -> c_int {
    // SAFETY: C passes initialised objects, and holds `m`.
    let (c, m) = unsafe { (&*c, &mut *m) };
    let (owner, count) = (m.owner.load(Ordering::Relaxed), m.count);
    if m.kind != PTHREAD_MUTEX_NORMAL {
        if owner != my_tid() {
            return Errno::EPERM.0;
        }
        m.owner.store(0, Ordering::Relaxed);
    }
    // SAFETY: The caller holds the lock.
    let r = unsafe { c.cv.wait_raw(&m.lock, timeout) };
    if m.kind != PTHREAD_MUTEX_NORMAL {
        m.owner.store(owner, Ordering::Relaxed);
        m.count = count;
    }
    if r.is_err() { Errno::ETIMEDOUT.0 } else { 0 }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_wait(c: *mut PCond, m: *mut PMutex) -> c_int {
    // SAFETY: Forwarded.
    unsafe { cond_wait(c, m, None) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_timedwait(c: *mut PCond, m: *mut PMutex, at: *const Timespec) -> c_int {
    // SAFETY: `at` is absolute on the variable's clock.
    match unsafe { left_until(at, (*c).clock as u32) } {
        // A deadline already past still releases and retakes the lock.
        // SAFETY: Forwarded.
        Ok(ns) => unsafe { cond_wait(c, m, Some(ns.max(1))) },
        Err(e) => e,
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_signal(c: *mut PCond) -> c_int {
    // SAFETY: An initialised object.
    unsafe { (*c).cv.notify_one() };
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_broadcast(c: *mut PCond) -> c_int {
    // SAFETY: An initialised object.
    unsafe { (*c).cv.notify_all() };
    0
}

// --- read-write locks ---------------------------------------------------------

/// `pthread_rwlock_t`: all zeros is an unlocked lock. Readers share it
/// while no writer holds it; waiting writers do not hold back new
/// readers.
#[repr(C)]
pub struct RwLock {
    lock: RawMutex,
    cv: Condvar,
    readers: u32,
    writer: u32,
    _reserved: [u64; 4],
}

/// Take `l` for reading or writing; `block` false fails with EBUSY.
unsafe fn rw_take(l: *mut RwLock, write: bool, block: bool) -> c_int {
    // SAFETY: C passes an initialised lock; its fields change under `lock`.
    let l = unsafe { &mut *l };
    l.lock.lock();
    loop {
        let free = if write { l.writer == 0 && l.readers == 0 } else { l.writer == 0 };
        if free {
            break;
        }
        if !block {
            // SAFETY: Held above.
            unsafe { l.lock.unlock() };
            return Errno::EBUSY.0;
        }
        // SAFETY: Held above.
        let _ = unsafe { l.cv.wait_raw(&l.lock, None) };
    }
    if write {
        l.writer = my_tid();
    } else {
        l.readers += 1;
    }
    // SAFETY: Held above.
    unsafe { l.lock.unlock() };
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_init(l: *mut RwLock, _attr: *const c_void) -> c_int {
    // SAFETY: C passes room for the lock.
    unsafe { l.write(RwLock { lock: RawMutex::new(), cv: Condvar::new(), readers: 0, writer: 0, _reserved: [0; 4] }) };
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn pthread_rwlock_destroy(_l: *mut RwLock) -> c_int {
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_rdlock(l: *mut RwLock) -> c_int {
    // SAFETY: Forwarded.
    unsafe { rw_take(l, false, true) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_tryrdlock(l: *mut RwLock) -> c_int {
    // SAFETY: Forwarded.
    unsafe { rw_take(l, false, false) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_wrlock(l: *mut RwLock) -> c_int {
    // SAFETY: Forwarded.
    unsafe { rw_take(l, true, true) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_trywrlock(l: *mut RwLock) -> c_int {
    // SAFETY: Forwarded.
    unsafe { rw_take(l, true, false) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_unlock(l: *mut RwLock) -> c_int {
    // SAFETY: As in `rw_take`.
    let l = unsafe { &mut *l };
    l.lock.lock();
    if l.writer != 0 {
        l.writer = 0;
    } else if l.readers > 0 {
        l.readers -= 1;
    } else {
        // SAFETY: Held above.
        unsafe { l.lock.unlock() };
        return Errno::EPERM.0;
    }
    // SAFETY: Held above.
    unsafe { l.lock.unlock() };
    l.cv.notify_all();
    0
}

// --- once ---------------------------------------------------------------------

/// `pthread_once_t`: 0 not yet, 1 running, 2 done.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_once(once: *mut c_int, f: extern "C" fn()) -> c_int {
    // SAFETY: An int-aligned `pthread_once_t`, only touched atomically.
    let w = unsafe { AtomicU32::from_ptr(once as *mut u32) };
    loop {
        match w.compare_exchange(0, 1, Ordering::Acquire, Ordering::Acquire) {
            Ok(_) => {
                f();
                w.store(2, Ordering::Release);
                futex_wake(w, u32::MAX);
                return 0;
            }
            Err(2) => return 0,
            Err(v) => {
                let _ = futex_wait(w, v, None);
            }
        }
    }
}

// --- thread-specific data -----------------------------------------------------

pub const PTHREAD_KEYS_MAX: usize = 128;
/// Rounds of destructors at a thread's end (POSIX's minimum is 4).
const DESTRUCTOR_ROUNDS: usize = 4;

/// Each key's destructor plus one (0: the key is free; 1: no destructor).
static KEYS: [AtomicUsize; PTHREAD_KEYS_MAX] = [const { AtomicUsize::new(0) }; PTHREAD_KEYS_MAX];

#[thread_local]
static VALUES: [Cell<*mut c_void>; PTHREAD_KEYS_MAX] = [const { Cell::new(null_mut()) }; PTHREAD_KEYS_MAX];

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_key_create(key: *mut u32, dtor: Option<extern "C" fn(*mut c_void)>) -> c_int {
    let d = dtor.map_or(1, |f| f as usize);
    for (i, k) in KEYS.iter().enumerate() {
        if k.compare_exchange(0, d, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            // SAFETY: C passes room for the key.
            unsafe { *key = i as u32 };
            return 0;
        }
    }
    Errno::EAGAIN.0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn pthread_key_delete(key: u32) -> c_int {
    match KEYS.get(key as usize) {
        Some(k) if k.swap(0, Ordering::AcqRel) != 0 => 0,
        _ => Errno::EINVAL.0,
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn pthread_getspecific(key: u32) -> *mut c_void {
    VALUES.get(key as usize).map_or(null_mut(), |v| v.get())
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn pthread_setspecific(key: u32, value: *const c_void) -> c_int {
    match (KEYS.get(key as usize), VALUES.get(key as usize)) {
        (Some(k), Some(v)) if k.load(Ordering::Acquire) != 0 => {
            v.set(value as *mut c_void);
            0
        }
        _ => Errno::EINVAL.0,
    }
}

/// Call each key's destructor on the thread's non-null values, again
/// while destructors set new ones (up to the round limit).
fn run_destructors() {
    for _ in 0..DESTRUCTOR_ROUNDS {
        let mut ran = false;
        for (k, v) in KEYS.iter().zip(VALUES.iter()) {
            let d = k.load(Ordering::Acquire);
            let value = v.get();
            if d > 1 && !value.is_null() {
                v.set(null_mut());
                // SAFETY: `d` is the function pointer pthread_key_create stored.
                let f: extern "C" fn(*mut c_void) = unsafe { core::mem::transmute(d) };
                f(value);
                ran = true;
            }
        }
        if !ran {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutex_kinds() {
        let mut a = MutexAttr { kind: 0 };
        let mut m = core::mem::MaybeUninit::<PMutex>::uninit();
        // SAFETY: Plain test objects.
        unsafe {
            pthread_mutexattr_init(&mut a);
            assert_eq!(pthread_mutexattr_settype(&mut a, PTHREAD_MUTEX_RECURSIVE), 0);
            pthread_mutex_init(m.as_mut_ptr(), &a);
            let m = m.as_mut_ptr();
            assert_eq!(pthread_mutex_lock(m), 0);
            assert_eq!(pthread_mutex_lock(m), 0);
            assert_eq!(pthread_mutex_unlock(m), 0);
            assert_eq!(pthread_mutex_trylock(m), 0);
            assert_eq!(pthread_mutex_unlock(m), 0);
            assert_eq!(pthread_mutex_unlock(m), 0);
            assert_eq!(pthread_mutex_unlock(m), Errno::EPERM.0);
            (*m).kind = PTHREAD_MUTEX_ERRORCHECK;
            assert_eq!(pthread_mutex_lock(m), 0);
            assert_eq!(pthread_mutex_lock(m), Errno::EDEADLK.0);
            assert_eq!(pthread_mutex_unlock(m), 0);
        }
    }

    #[test]
    fn cond_times_out() {
        let mut c = core::mem::MaybeUninit::<PCond>::uninit();
        let mut m = core::mem::MaybeUninit::<PMutex>::uninit();
        // SAFETY: Plain test objects.
        unsafe {
            pthread_cond_init(c.as_mut_ptr(), core::ptr::null());
            pthread_mutex_init(m.as_mut_ptr(), core::ptr::null());
            let (s, ns) = time::now(time::CLOCK_REALTIME);
            let at = Timespec { sec: s, nsec: ns };
            pthread_mutex_lock(m.as_mut_ptr());
            assert_eq!(pthread_cond_timedwait(c.as_mut_ptr(), m.as_mut_ptr(), &at), Errno::ETIMEDOUT.0);
            assert_eq!(pthread_mutex_unlock(m.as_mut_ptr()), 0);
        }
    }

    #[test]
    fn keys_and_once() {
        let mut k = 0;
        // SAFETY: Plain test objects.
        unsafe {
            assert_eq!(pthread_key_create(&mut k, None), 0);
        }
        assert!(pthread_getspecific(k).is_null());
        assert_eq!(pthread_setspecific(k, 7usize as *const c_void), 0);
        assert_eq!(pthread_getspecific(k) as usize, 7);
        assert_eq!(pthread_key_delete(k), 0);
        assert_eq!(pthread_setspecific(k, null_mut()), Errno::EINVAL.0);
        static RUNS: AtomicU32 = AtomicU32::new(0);
        extern "C" fn once_fn() {
            RUNS.fetch_add(1, Ordering::Relaxed);
        }
        let mut o: c_int = 0;
        // SAFETY: A plain once object.
        unsafe {
            pthread_once(&mut o, once_fn);
            pthread_once(&mut o, once_fn);
        }
        assert_eq!(RUNS.load(Ordering::Relaxed), 1);
    }
}
