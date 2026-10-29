// SPDX-License-Identifier: MIT OR Apache-2.0

//! An I/O scheduler for devices that run one command at a time (ADR
//! 0080): virtio-blk, IDE, USB mass storage, SATA disks without native
//! command queuing. While the device is busy, reads and writes wait, and
//! the next one served is the waiting request at or after the sector the
//! last one ended on, else the lowest (C-LOOK: one sweep upwards, then
//! back to the start), not the one that came first: a disk with heads
//! moves less. Devices that queue commands themselves (NVMe, NCQ) order
//! their own queues and are not wrapped.
//!
//! I/O priorities (ioprio_set(2)) come first: a waiting request of the
//! real-time class goes before any best-effort one, and idle-class
//! requests only when nothing else waits; within a class, the sweep. A
//! thread without a priority is best-effort. Levels within a class are
//! not weighed (GAPS.md).
//!
//! Flushes, discards and the rest go straight to the device, whose driver
//! runs them one at a time anyway; only reads and writes are reordered,
//! and only among requests waiting at the same moment, which no caller
//! can have ordered (each waits for its own).

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use super::{BlockDevice, IoError};
use crate::sched::wait::WaitQueue;
use crate::sync::IrqSpinLock;

/// No request has been let through.
const NONE: u64 = u64::MAX;

struct State {
    busy: bool,
    /// Where the last request ended.
    head: u64,
    next_seq: u64,
    /// Waiting requests: (class rank, first sector, arrival number).
    waiting: BTreeSet<(u8, u64, u64)>,
}

pub struct Elevator {
    inner: Arc<dyn BlockDevice>,
    state: IrqSpinLock<State>,
    /// The arrival number of the waiting request let through.
    granted: AtomicU64,
    waiters: WaitQueue,
}

impl Elevator {
    pub fn new(inner: Arc<dyn BlockDevice>) -> Elevator {
        Elevator {
            inner,
            state: IrqSpinLock::new(State { busy: false, head: 0, next_seq: 0, waiting: BTreeSet::new() }),
            granted: AtomicU64::new(NONE),
            waiters: WaitQueue::new(),
        }
    }

    /// Run `f` on the device as the request for sectors `sector` to `end`,
    /// when its turn comes.
    fn run<T>(&self, sector: u64, end: u64, f: impl FnOnce(&dyn BlockDevice) -> T) -> T {
        let rank = rank(crate::sched::current().ioprio.load(Ordering::Relaxed));
        if !crate::sched::can_block() {
            return f(&*self.inner);
        }
        let seq = {
            let mut st = self.state.lock();
            if st.busy {
                let seq = st.next_seq;
                st.next_seq += 1;
                st.waiting.insert((rank, sector, seq));
                Some(seq)
            } else {
                st.busy = true;
                None
            }
        };
        if let Some(seq) = seq {
            self.waiters.wait_until(|| self.granted.load(Ordering::Acquire) == seq);
        }
        let r = f(&*self.inner);
        self.finish(end);
        r
    }

    /// The request ending at `end` is done: let the next one through, of
    /// the highest class waiting, the first at or after `end`, else its
    /// lowest.
    fn finish(&self, end: u64) {
        let mut st = self.state.lock();
        st.head = end;
        let next = st.waiting.iter().next().map(|&(r, _, _)| r).and_then(|r| {
            st.waiting
                .range((r, end, 0)..(r + 1, 0, 0))
                .next()
                .or_else(|| st.waiting.range((r, 0, 0)..).next())
                .copied()
        });
        match next {
            Some(k) => {
                st.waiting.remove(&k);
                self.granted.store(k.2, Ordering::Release);
                drop(st);
                self.waiters.wake_all();
            }
            None => st.busy = false,
        }
    }
}

/// ioprio_set(2)'s classes (the value's bits 13 and up): RT 1, BE 2, IDLE
/// 3; none (0) is best-effort. Their order: real-time first.
fn rank(ioprio: u32) -> u8 {
    match ioprio >> 13 {
        1 => 0,
        3 => 2,
        _ => 1,
    }
}

impl BlockDevice for Elevator {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn sectors(&self) -> u64 {
        self.inner.sectors()
    }
    fn read_only(&self) -> bool {
        self.inner.read_only()
    }
    fn read(&self, sector: u64, buf: &mut [u8]) -> Result<(), IoError> {
        let end = sector + (buf.len() / 512) as u64;
        self.run(sector, end, |d| d.read(sector, buf))
    }
    fn write(&self, sector: u64, buf: &[u8]) -> Result<(), IoError> {
        let end = sector + (buf.len() / 512) as u64;
        self.run(sector, end, |d| d.write(sector, buf))
    }
    fn flush(&self) -> Result<(), IoError> {
        self.inner.flush()
    }
    fn model(&self) -> String {
        self.inner.model()
    }
    fn removable(&self) -> bool {
        self.inner.removable()
    }
    fn can_discard(&self) -> bool {
        self.inner.can_discard()
    }
    fn shutdown(&self) {
        self.inner.shutdown()
    }
    fn discard(&self, sector: u64, count: u64) -> Result<(), IoError> {
        self.inner.discard(sector, count)
    }
    fn queue_depth(&self) -> usize {
        1
    }
    fn detach(&self) {
        self.inner.detach()
    }
}

pub const TESTS: &[crate::ktest::Test] = &[
    crate::ktest::Test { name: "block::elevator_order", run: test_order },
    crate::ktest::Test { name: "block::elevator_priorities", run: test_priorities },
];

/// A slow device that records the order of the reads it serves.
struct Recorder {
    order: IrqSpinLock<alloc::vec::Vec<u64>>,
}

impl BlockDevice for Recorder {
    fn name(&self) -> &str {
        "recorder"
    }
    fn sectors(&self) -> u64 {
        1 << 20
    }
    fn read_only(&self) -> bool {
        true
    }
    fn read(&self, sector: u64, _buf: &mut [u8]) -> Result<(), IoError> {
        self.order.lock().push(sector);
        // Long enough for the other requests to queue behind the first.
        crate::time::sleep_ns(if sector == 1000 { 100_000_000 } else { 1_000_000 });
        Ok(())
    }
    fn write(&self, _sector: u64, _buf: &[u8]) -> Result<(), IoError> {
        Err(IoError)
    }
    fn flush(&self) -> Result<(), IoError> {
        Ok(())
    }
}

/// One read holds the device (sector 1000); five more arrive meanwhile
/// (500, 3000, 1500, 200, 2500) and are served in one upward sweep from
/// where the first ended, then from the lowest: 1500, 2500, 3000, 200, 500.
fn test_order() -> Result<(), &'static str> {
    let rec = Arc::new(Recorder { order: IrqSpinLock::new(alloc::vec::Vec::new()) });
    let el = Arc::new(Elevator::new(rec.clone()));
    let done = Arc::new(AtomicU64::new(0));
    let start = |sector: u64| {
        let (el, done) = (el.clone(), done.clone());
        crate::sched::spawn("elevator-test", move || {
            let mut b = [0u8; 512];
            let _ = el.read(sector, &mut b);
            done.fetch_add(1, Ordering::Release);
        });
    };
    start(1000);
    crate::time::sleep_ns(20_000_000);
    for s in [500, 3000, 1500, 200, 2500] {
        start(s);
        crate::time::sleep_ns(2_000_000);
    }
    if !super::super::drivers::dma::wait_for(5000, || done.load(Ordering::Acquire) == 6) {
        return Err("the requests did not finish");
    }
    if rec.order.lock()[..] != [1000, 1500, 2500, 3000, 200, 500] {
        return Err("not served in C-LOOK order");
    }
    Ok(())
}

/// One read holds the device; an idle-class, a best-effort and a
/// real-time read arrive meanwhile, in that order and at sectors that
/// would sweep the other way: real-time first, then best-effort, idle
/// last.
fn test_priorities() -> Result<(), &'static str> {
    let rec = Arc::new(Recorder { order: IrqSpinLock::new(alloc::vec::Vec::new()) });
    let el = Arc::new(Elevator::new(rec.clone()));
    let done = Arc::new(AtomicU64::new(0));
    let start = |sector: u64, ioprio: u32| {
        let (el, done) = (el.clone(), done.clone());
        crate::sched::spawn("elevator-test", move || {
            crate::sched::current().ioprio.store(ioprio, Ordering::Relaxed);
            let mut b = [0u8; 512];
            let _ = el.read(sector, &mut b);
            done.fetch_add(1, Ordering::Release);
        });
    };
    start(1000, 0);
    crate::time::sleep_ns(20_000_000);
    for (s, prio) in [(1100, 3 << 13), (1200, 2 << 13 | 4), (3000, 1 << 13)] {
        start(s, prio);
        crate::time::sleep_ns(2_000_000);
    }
    if !super::super::drivers::dma::wait_for(5000, || done.load(Ordering::Acquire) == 4) {
        return Err("the requests did not finish");
    }
    if rec.order.lock()[..] != [1000, 3000, 1200, 1100] {
        return Err("not served by class");
    }
    Ok(())
}
