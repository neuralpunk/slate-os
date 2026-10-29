// SPDX-License-Identifier: MIT OR Apache-2.0

//! I/O counts for /proc/diskstats (ADR 0112): a disk's are counted
//! between its I/O scheduler and the block cache, so they are what the
//! device itself was asked to do; a mapped device's are what was asked of
//! it. The System Monitor turns them into read and write rates.

use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use super::{BlockDevice, IoError, SECTOR};

/// What one device has done since it appeared.
#[derive(Debug, Default)]
pub struct Stats {
    pub reads: AtomicU64,
    pub read_sectors: AtomicU64,
    pub read_ns: AtomicU64,
    pub writes: AtomicU64,
    pub written_sectors: AtomicU64,
    pub write_ns: AtomicU64,
    pub discards: AtomicU64,
    pub discarded_sectors: AtomicU64,
    pub flushes: AtomicU64,
    pub in_flight: AtomicU64,
}

impl Stats {
    /// The line proc(5) describes: major, minor, name, then reads
    /// (completed, merged, sectors, ms), writes (the same), I/Os in
    /// progress, ms doing I/O, weighted ms, discards (completed, merged,
    /// sectors, ms) and flushes (completed, ms). Merges are not done and
    /// count 0; the time doing I/O is the reads' and writes' time.
    pub fn line(&self, major: u32, minor: u32, name: &str) -> String {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let (rms, wms) = (g(&self.read_ns) / 1_000_000, g(&self.write_ns) / 1_000_000);
        alloc::format!(
            "{major:4} {minor:7} {name} {} 0 {} {rms} {} 0 {} {wms} {} {} {} {} 0 {} 0 {} 0\n",
            g(&self.reads),
            g(&self.read_sectors),
            g(&self.writes),
            g(&self.written_sectors),
            g(&self.in_flight),
            rms + wms,
            rms + wms,
            g(&self.discards),
            g(&self.discarded_sectors),
            g(&self.flushes),
        )
    }
}

/// A device whose I/O is counted in `stats`.
pub struct Counted {
    inner: Arc<dyn BlockDevice>,
    pub stats: Arc<Stats>,
    /// Charge the sectors to the thread asking (getrusage(2)'s inblock and
    /// oublock): disks only, so I/O through a mapped device on a disk is
    /// charged once.
    charge: bool,
}

impl Counted {
    /// A disk's counts.
    pub fn new(inner: Arc<dyn BlockDevice>) -> Counted {
        Counted { inner, stats: Arc::new(Stats::default()), charge: true }
    }

    /// A mapped device's (its disk charges the threads).
    pub fn mapped(inner: Arc<dyn BlockDevice>) -> Counted {
        Counted { charge: false, ..Counted::new(inner) }
    }

    fn charge_thread(&self, which: fn(&crate::proc::Counts) -> &AtomicU64, bytes: usize) {
        if self.charge && crate::sched::started() {
            crate::sched::current().count(which, (bytes / SECTOR) as u64);
        }
    }

    fn timed<T>(&self, count: &AtomicU64, ns: &AtomicU64, f: impl FnOnce() -> T) -> T {
        self.stats.in_flight.fetch_add(1, Ordering::Relaxed);
        let start = crate::time::monotonic_ns();
        let r = f();
        ns.fetch_add(crate::time::monotonic_ns().saturating_sub(start), Ordering::Relaxed);
        count.fetch_add(1, Ordering::Relaxed);
        self.stats.in_flight.fetch_sub(1, Ordering::Relaxed);
        r
    }
}

impl BlockDevice for Counted {
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
        self.stats.read_sectors.fetch_add((buf.len() / SECTOR) as u64, Ordering::Relaxed);
        self.charge_thread(|c| &c.inblock, buf.len());
        self.timed(&self.stats.reads, &self.stats.read_ns, || self.inner.read(sector, buf))
    }
    fn write(&self, sector: u64, buf: &[u8]) -> Result<(), IoError> {
        self.stats.written_sectors.fetch_add((buf.len() / SECTOR) as u64, Ordering::Relaxed);
        self.charge_thread(|c| &c.oublock, buf.len());
        self.timed(&self.stats.writes, &self.stats.write_ns, || self.inner.write(sector, buf))
    }
    fn flush(&self) -> Result<(), IoError> {
        self.stats.flushes.fetch_add(1, Ordering::Relaxed);
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
        self.stats.discards.fetch_add(1, Ordering::Relaxed);
        self.stats.discarded_sectors.fetch_add(count, Ordering::Relaxed);
        self.inner.discard(sector, count)
    }
    fn queue_depth(&self) -> usize {
        self.inner.queue_depth()
    }
    fn detach(&self) {
        self.inner.detach()
    }
}
