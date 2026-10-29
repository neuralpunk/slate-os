// SPDX-License-Identifier: MIT OR Apache-2.0

//! Event files: eventfd(2), timerfd_create(2), signalfd(2) and epoll(7).
//!
//! All of them report readiness through `File::poll`, and wake waiters
//! through the global poll notification (`poll_notify`), so they combine
//! freely with poll(2), select(2) and each other.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::vfs::{Metadata, Result};
use super::{File, O_NONBLOCK, POLLERR, POLLHUP, POLLIN, POLLOUT, poll_generation, poll_notify, poll_wait};
use crate::abi::linux::errno::{EAGAIN, EINTR, EINVAL};
use crate::proc::signal::{self, ERESTARTSYS};
use crate::sched::wait::WaitResult;
use crate::sync::IrqSpinLock;
use crate::time::{self, TimerId};

/// Block until `ready()` holds, re-checking on every poll notification.
fn block_until(nonblock: bool, mut ready: impl FnMut() -> bool) -> Result<()> {
    loop {
        let seen = poll_generation();
        if ready() {
            return Ok(());
        }
        if nonblock {
            return Err(EAGAIN);
        }
        if poll_wait(seen, None) == WaitResult::Interrupted {
            return Err(ERESTARTSYS);
        }
    }
}

fn anon_stat(ino: u64) -> Result<Metadata> {
    Ok(Metadata { mode: 0o600, nlink: 1, ino, dev: 0xFFFE, ..Default::default() })
}

// --- eventfd ---------------------------------------------------------------

pub const EFD_SEMAPHORE: u32 = 1;
const EVENTFD_MAX: u64 = u64::MAX - 1;

/// eventfd(2): a 64-bit counter.
#[derive(Debug)]
pub struct EventFd {
    events: AtomicU64,
    count: IrqSpinLock<u64>,
    semaphore: bool,
    flags: AtomicU32,
}

impl EventFd {
    pub fn new(initval: u32, flags: u32) -> EventFd {
        EventFd {
            events: AtomicU64::new(1),
            count: IrqSpinLock::new(u64::from(initval)),
            semaphore: flags & EFD_SEMAPHORE != 0,
            flags: AtomicU32::new(flags & O_NONBLOCK | super::O_RDWR),
        }
    }

    fn nonblock(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0
    }
}

impl File for EventFd {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < 8 {
            return Err(EINVAL);
        }
        let mut value = 0;
        block_until(self.nonblock(), || {
            let mut c = self.count.lock();
            if *c == 0 {
                return false;
            }
            value = if self.semaphore { 1 } else { *c };
            *c -= value;
            true
        })?;
        self.events.fetch_add(1, Ordering::Relaxed);
        poll_notify();
        buf[..8].copy_from_slice(&value.to_ne_bytes());
        Ok(8)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        let v = u64::from_ne_bytes(buf.get(..8).ok_or(EINVAL)?.try_into().unwrap());
        if v == u64::MAX {
            return Err(EINVAL);
        }
        block_until(self.nonblock(), || {
            let mut c = self.count.lock();
            if EVENTFD_MAX - *c < v {
                return false;
            }
            *c += v;
            true
        })?;
        self.events.fetch_add(1, Ordering::Relaxed);
        poll_notify();
        Ok(8)
    }

    fn poll(&self) -> u16 {
        let c = *self.count.lock();
        let mut r = 0;
        if c > 0 {
            r |= POLLIN;
        }
        if c < EVENTFD_MAX {
            r |= POLLOUT;
        }
        r
    }

    fn event_count(&self) -> u64 {
        self.events.load(Ordering::Relaxed)
    }

    fn stat(&self) -> Result<Metadata> {
        anon_stat(1)
    }

    fn status_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }

    fn set_status_flags(&self, flags: u32) {
        self.flags.store(super::O_RDWR | (flags & O_NONBLOCK), Ordering::Relaxed);
    }
}

// --- timerfd ---------------------------------------------------------------

pub const TFD_TIMER_ABSTIME: u32 = 1;
const CLOCK_REALTIME: u32 = 0;

#[derive(Debug, Default)]
struct TimerState {
    /// Next expiry on the monotonic clock (None: disarmed).
    next: Option<u64>,
    interval: u64,
    /// Expirations not yet read.
    expirations: u64,
    pending: Option<TimerId>,
    generation: u64,
}

/// timerfd_create(2): a timer read as a count of expirations.
#[derive(Debug)]
pub struct TimerFd {
    clock: u32,
    state: IrqSpinLock<TimerState>,
    flags: AtomicU32,
}

static TIMERFD_INO: AtomicU64 = AtomicU64::new(1);

impl TimerFd {
    pub fn new(clock: u32, flags: u32) -> Arc<TimerFd> {
        Arc::new(TimerFd {
            clock,
            state: IrqSpinLock::new(TimerState::default()),
            flags: AtomicU32::new(flags & O_NONBLOCK),
        })
    }

    /// Fold elapsed expirations into the count.
    fn update(st: &mut TimerState) {
        let now = time::monotonic_ns();
        if let Some(next) = st.next
            && now >= next
        {
            match (now - next).checked_div(st.interval) {
                None => {
                    st.expirations += 1;
                    st.next = None;
                }
                Some(periods) => {
                    let n = periods + 1;
                    st.expirations += n;
                    st.next = Some(next + n * st.interval);
                }
            }
        }
    }

    /// Arm (or with `value == 0`, disarm) the timer: first expiry after
    /// `value` ns (or at `value` on its clock if `absolute`), then every
    /// `interval` ns. Returns the previous (remaining, interval).
    pub fn set(self: &Arc<Self>, value: u64, interval: u64, absolute: bool) -> (u64, u64) {
        let old = self.get();
        let mut st = self.state.lock();
        if let Some(t) = st.pending.take() {
            time::cancel_timer(t);
        }
        st.generation += 1;
        st.expirations = 0;
        st.interval = interval;
        st.next = if value == 0 {
            None
        } else {
            let now = time::monotonic_ns();
            Some(if absolute {
                if self.clock == CLOCK_REALTIME {
                    let rt = time::realtime_ns().max(0) as u64;
                    now.saturating_add(value.saturating_sub(rt))
                } else {
                    value
                }
            } else {
                now.saturating_add(value)
            })
        };
        if let Some(next) = st.next {
            st.pending = Some(Self::arm(Arc::downgrade(self), next, st.generation));
        }
        old
    }

    /// Schedule a wakeup at `at` for readers and pollers.
    fn arm(me: Weak<TimerFd>, at: u64, generation: u64) -> TimerId {
        time::add_timer(at, move || {
            let Some(t) = me.upgrade() else { return };
            let mut st = t.state.lock();
            if st.generation != generation {
                return;
            }
            Self::update(&mut st);
            st.pending = st.next.map(|n| Self::arm(Arc::downgrade(&t), n, generation));
            drop(st);
            poll_notify();
        })
    }

    /// (time to next expiry, interval) in ns.
    pub fn get(&self) -> (u64, u64) {
        let mut st = self.state.lock();
        Self::update(&mut st);
        let remaining = st.next.map_or(0, |n| n.saturating_sub(time::monotonic_ns()).max(1));
        (remaining, st.interval)
    }
}

impl File for TimerFd {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < 8 {
            return Err(EINVAL);
        }
        let mut n = 0;
        let nonblock = self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0;
        block_until(nonblock, || {
            let mut st = self.state.lock();
            Self::update(&mut st);
            n = core::mem::take(&mut st.expirations);
            n > 0
        })?;
        buf[..8].copy_from_slice(&n.to_ne_bytes());
        Ok(8)
    }

    fn poll(&self) -> u16 {
        let mut st = self.state.lock();
        Self::update(&mut st);
        if st.expirations > 0 { POLLIN } else { 0 }
    }

    fn stat(&self) -> Result<Metadata> {
        anon_stat(TIMERFD_INO.load(Ordering::Relaxed))
    }

    fn status_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }

    fn set_status_flags(&self, flags: u32) {
        self.flags.store(flags & O_NONBLOCK, Ordering::Relaxed);
    }
}

impl Drop for TimerFd {
    fn drop(&mut self) {
        if let Some(t) = self.state.lock().pending.take() {
            time::cancel_timer(t);
        }
    }
}

// --- signalfd --------------------------------------------------------------

/// `struct signalfd_siginfo` (signalfd(2)): 128 bytes.
#[derive(Clone, Copy)]
#[repr(C)]
struct SignalfdSiginfo {
    signo: u32,
    errno: i32,
    code: i32,
    pid: u32,
    uid: u32,
    fd: i32,
    tid: u32,
    band: u32,
    overrun: u32,
    trapno: u32,
    status: i32,
    int: i32,
    ptr: u64,
    utime: u64,
    stime: u64,
    addr: u64,
    rest: [u8; 48],
}

const _: () = assert!(size_of::<SignalfdSiginfo>() == 128);

/// signalfd(2): read pending signals from `mask` instead of handling them.
#[derive(Debug)]
pub struct SignalFd {
    pub mask: AtomicU64,
    flags: AtomicU32,
}

impl SignalFd {
    pub fn new(mask: u64, flags: u32) -> SignalFd {
        SignalFd { mask: AtomicU64::new(mask), flags: AtomicU32::new(flags & O_NONBLOCK) }
    }

    /// Take one pending signal in the mask (thread-directed first), with
    /// its sender.
    fn take(&self) -> Option<(u32, signal::Info)> {
        let p = crate::proc::current()?;
        let t = crate::sched::current();
        let mask = self.mask.load(Ordering::Relaxed);
        signal::take_thread_signal(&t, mask).or_else(|| signal::take_process_signal(&p, mask))
    }

    fn pending(&self) -> bool {
        let Some(p) = crate::proc::current() else { return false };
        let t = crate::sched::current();
        (t.pending_signals() | p.signals.pending()) & self.mask.load(Ordering::Relaxed) != 0
    }
}

impl File for SignalFd {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < 128 {
            return Err(EINVAL);
        }
        let nonblock = self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0;
        let mut n = 0;
        while n + 128 <= buf.len() {
            let (sig, sent) = if n == 0 {
                let mut got = None;
                block_until(nonblock, || {
                    got = self.take();
                    got.is_some()
                })?;
                got.unwrap()
            } else {
                match self.take() {
                    Some(s) => s,
                    None => break,
                }
            };
            let info = SignalfdSiginfo {
                signo: sig,
                errno: 0,
                code: sent.code,
                pid: sent.pid,
                uid: sent.uid,
                fd: 0,
                tid: 0,
                band: 0,
                overrun: 0,
                trapno: 0,
                status: 0,
                int: sent.value as i32,
                ptr: sent.value,
                utime: 0,
                stime: 0,
                addr: 0,
                rest: [0; 48],
            };
            // SAFETY: `SignalfdSiginfo` is plain data of 128 bytes.
            let bytes = unsafe { core::slice::from_raw_parts((&raw const info).cast::<u8>(), 128) };
            buf[n..n + 128].copy_from_slice(bytes);
            n += 128;
        }
        Ok(n)
    }

    fn poll(&self) -> u16 {
        if self.pending() { POLLIN } else { 0 }
    }

    fn stat(&self) -> Result<Metadata> {
        anon_stat(3)
    }

    fn status_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }

    fn set_status_flags(&self, flags: u32) {
        self.flags.store(flags & O_NONBLOCK, Ordering::Relaxed);
    }
}

// --- epoll -----------------------------------------------------------------

pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;
pub const EPOLLONESHOT: u32 = 1 << 30;
pub const EPOLLET: u32 = 1 << 31;
pub const EPOLL_CTL_ADD: u32 = 1;
pub const EPOLL_CTL_DEL: u32 = 2;
pub const EPOLL_CTL_MOD: u32 = 3;

struct Interest {
    fd: i32,
    file: Weak<dyn File>,
    events: u32,
    data: u64,
    /// Readiness and event count last reported (edge-triggered mode).
    last: u32,
    last_count: u64,
    /// EPOLLONESHOT fired: disabled until EPOLL_CTL_MOD.
    disabled: bool,
}

/// An epoll instance (epoll(7)).
pub struct Epoll {
    interests: IrqSpinLock<Vec<Interest>>,
}

impl core::fmt::Debug for Epoll {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Epoll").finish_non_exhaustive()
    }
}

/// One ready event for epoll_wait.
#[derive(Clone, Copy, Debug)]
pub struct Ready {
    pub events: u32,
    pub data: u64,
}

fn same_file(a: &Weak<dyn File>, b: &Arc<dyn File>) -> bool {
    a.upgrade().is_some_and(|x| Arc::ptr_eq(&x, b))
}

impl Epoll {
    pub fn new() -> Epoll {
        Epoll { interests: IrqSpinLock::new(Vec::new()) }
    }

    pub fn ctl(&self, op: u32, fd: i32, file: &Arc<dyn File>, events: u32, data: u64) -> Result<()> {
        let mut list = self.interests.lock();
        list.retain(|i| i.file.strong_count() > 0);
        let pos = list.iter().position(|i| i.fd == fd && same_file(&i.file, file));
        match (op, pos) {
            (EPOLL_CTL_ADD, None) => list.push(Interest {
                fd,
                file: Arc::downgrade(file),
                events,
                data,
                last: 0,
                last_count: 0,
                disabled: false,
            }),
            (EPOLL_CTL_ADD, Some(_)) => return Err(crate::abi::linux::errno::EEXIST),
            (EPOLL_CTL_MOD, Some(i)) => {
                list[i].events = events;
                list[i].data = data;
                list[i].last = 0;
                list[i].last_count = 0;
                list[i].disabled = false;
            }
            (EPOLL_CTL_DEL, Some(i)) => {
                list.remove(i);
            }
            (EPOLL_CTL_MOD | EPOLL_CTL_DEL, None) => return Err(crate::abi::linux::errno::ENOENT),
            _ => return Err(EINVAL),
        }
        drop(list);
        poll_notify();
        Ok(())
    }

    /// Collect up to `max` ready events, applying edge-triggered and
    /// one-shot rules.
    fn collect(&self, max: usize) -> Vec<Ready> {
        let mut out = Vec::new();
        let mut list = self.interests.lock();
        list.retain(|i| i.file.strong_count() > 0);
        for i in list.iter_mut() {
            if out.len() >= max {
                break;
            }
            let Some(f) = i.file.upgrade() else { continue };
            let wanted = i.events | EPOLLERR | EPOLLHUP;
            let now = u32::from(f.poll()) & wanted;
            if i.disabled || now == 0 {
                i.last = 0;
                continue;
            }
            // Edge-triggered: report again only after a new readiness event
            // (or, for files without an event count, a new readiness bit).
            let count = f.event_count();
            let edge = if count != 0 { count != i.last_count } else { now & !i.last != 0 };
            if i.events & EPOLLET != 0 && !edge {
                continue;
            }
            i.last = now;
            i.last_count = count;
            out.push(Ready { events: now, data: i.data });
            if i.events & EPOLLONESHOT != 0 {
                i.disabled = true;
            }
        }
        out
    }

    /// epoll_wait: block until something is ready, a signal arrives, or
    /// `deadline_ns` passes.
    pub fn wait(&self, max: usize, deadline_ns: Option<u64>) -> Result<Vec<Ready>> {
        loop {
            let seen = poll_generation();
            let r = self.collect(max);
            if !r.is_empty() || deadline_ns.is_some_and(|d| time::monotonic_ns() >= d) {
                return Ok(r);
            }
            match poll_wait(seen, deadline_ns) {
                WaitResult::Interrupted => return Err(EINTR),
                WaitResult::TimedOut | WaitResult::Ready => {}
            }
        }
    }
}

impl Default for Epoll {
    fn default() -> Self {
        Self::new()
    }
}

impl File for Epoll {
    fn poll(&self) -> u16 {
        // Readable if any interest is ready (nested epoll, poll on epoll).
        let list = self.interests.lock();
        let ready = list.iter().any(|i| {
            !i.disabled && i.file.upgrade().is_some_and(|f| u32::from(f.poll()) & (i.events | EPOLLERR | EPOLLHUP) != 0)
        });
        if ready { POLLIN } else { 0 }
    }

    fn stat(&self) -> Result<Metadata> {
        anon_stat(4)
    }
}

// Silence unused warnings for documented readiness bits.
const _: u16 = POLLERR | POLLHUP;
