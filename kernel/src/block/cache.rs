// SPDX-License-Identifier: MIT OR Apache-2.0

//! The block cache (ADR 0080): recently read 4 KiB blocks of each disk,
//! for the small reads that file systems make of their metadata and that
//! programs make of /dev. File data has the page cache
//! (`fs/pagecache.rs`), so reads longer than `SMALL` go straight to the
//! disk and are not cached twice.
//!
//! The cache writes through: a write reaches the disk first, then the
//! cached copies of what it covered are patched, so a flush means what it
//! meant without the cache. A read that misses reads the whole blocks
//! around it and keeps them, unless a write to the disk started or ended
//! while it read (`started` and `ended`), which might have left it with
//! older data than the disk's. Discards drop the blocks they touch.
//!
//! Every cache together keeps at most `capacity()` bytes, dropping the
//! least recently used blocks of the one that grows; the page cache's
//! reclaim also shrinks them when memory runs low. /proc/meminfo shows
//! the total as Buffers, as Linux does for its block device cache.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::{BlockDevice, IoError};
use crate::sync::IrqSpinLock;

/// Cached blocks: 4 KiB, 8 sectors.
const BLOCK: usize = 4096;
const SECTORS: u64 = (BLOCK / 512) as u64;
/// Reads up to this long are cached.
const SMALL: usize = 16 * 1024;

#[derive(Default)]
struct Blocks {
    /// Block number → (data, last use).
    map: BTreeMap<u64, (Box<[u8; BLOCK]>, u64)>,
    /// Last use → block number, oldest first.
    lru: BTreeMap<u64, u64>,
    clock: u64,
}

impl Blocks {
    fn touch(&mut self, block: u64) {
        self.clock += 1;
        let now = self.clock;
        if let Some(e) = self.map.get_mut(&block) {
            self.lru.remove(&e.1);
            e.1 = now;
            self.lru.insert(now, block);
        }
    }

    fn insert(&mut self, block: u64, data: Box<[u8; BLOCK]>) -> bool {
        self.clock += 1;
        let now = self.clock;
        let new = match self.map.insert(block, (data, now)) {
            Some((_, old)) => {
                self.lru.remove(&old);
                false
            }
            None => true,
        };
        self.lru.insert(now, block);
        new
    }

    fn remove(&mut self, block: u64) -> bool {
        match self.map.remove(&block) {
            Some((_, stamp)) => {
                self.lru.remove(&stamp);
                true
            }
            None => false,
        }
    }

    /// Drop the least recently used block.
    fn evict(&mut self) -> bool {
        match self.lru.pop_first() {
            Some((_, block)) => {
                self.map.remove(&block);
                true
            }
            None => false,
        }
    }
}

/// A disk's cache.
struct Inner {
    blocks: IrqSpinLock<Blocks>,
    /// Writes started and ended: a read that saw both unchanged around it
    /// read what the disk holds.
    started: AtomicU64,
    ended: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
}

/// Bytes cached, in every cache.
static BYTES: AtomicUsize = AtomicUsize::new(0);
static CACHES: IrqSpinLock<Vec<Weak<Inner>>> = IrqSpinLock::new(Vec::new());

/// The most every cache together keeps: a 64th of memory, between 4 and
/// 64 MiB.
fn capacity() -> usize {
    let total = (crate::mm::frame::stats().usable_frames * crate::mm::PAGE_SIZE) as usize;
    (total / 64).clamp(4 << 20, 64 << 20)
}

/// Bytes cached, for /proc/meminfo's Buffers.
pub fn bytes() -> usize {
    BYTES.load(Ordering::Relaxed)
}

/// Give back about `pages` pages, least recently used blocks first, from
/// every cache in turn. Returns how many were freed.
pub fn shrink(pages: usize) -> usize {
    let caches: Vec<Arc<Inner>> = CACHES.lock().iter().filter_map(Weak::upgrade).collect();
    let mut freed = 0;
    while freed < pages {
        let mut any = false;
        for c in &caches {
            if c.blocks.lock().evict() {
                BYTES.fetch_sub(BLOCK, Ordering::Relaxed);
                freed += BLOCK / crate::mm::PAGE_SIZE as usize;
                any = true;
            }
        }
        if !any {
            break;
        }
    }
    freed
}

pub struct Cached {
    inner: Arc<dyn BlockDevice>,
    cache: Arc<Inner>,
    /// Unplugged: nothing reaches the device any more.
    gone: core::sync::atomic::AtomicBool,
}

impl Cached {
    pub fn new(inner: Arc<dyn BlockDevice>) -> Cached {
        let cache = Arc::new(Inner {
            blocks: IrqSpinLock::new(Blocks::default()),
            started: AtomicU64::new(0),
            ended: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        });
        CACHES.lock().push(Arc::downgrade(&cache));
        Cached { inner, cache, gone: core::sync::atomic::AtomicBool::new(false) }
    }

    /// Hits and misses so far.
    pub fn stats(&self) -> (u64, u64) {
        (self.cache.hits.load(Ordering::Relaxed), self.cache.misses.load(Ordering::Relaxed))
    }

    /// The blocks `sector..sector + n` lie in.
    fn blocks_of(sector: u64, n: u64) -> core::ops::Range<u64> {
        sector / SECTORS..(sector + n).div_ceil(SECTORS)
    }

    /// Copy cached bytes of sectors `sector..` into `buf` if every block
    /// is there.
    fn lookup(&self, sector: u64, buf: &mut [u8]) -> bool {
        let range = Self::blocks_of(sector, (buf.len() / 512) as u64);
        let mut b = self.cache.blocks.lock();
        if !range.clone().all(|k| b.map.contains_key(&k)) {
            return false;
        }
        let start = sector as usize * 512;
        for k in range {
            let data = &b.map[&k].0;
            let at = k as usize * BLOCK;
            let (from, to) = (start.max(at), (start + buf.len()).min(at + BLOCK));
            buf[from - start..to - start].copy_from_slice(&data[from - at..to - at]);
            b.touch(k);
        }
        true
    }

    fn keep(&self, first: u64, data: &[u8]) {
        let mut added = 0;
        {
            let mut b = self.cache.blocks.lock();
            for (i, chunk) in data.as_chunks::<BLOCK>().0.iter().enumerate() {
                let mut block = Box::new([0u8; BLOCK]);
                block.copy_from_slice(chunk);
                if b.insert(first + i as u64, block) {
                    added += 1;
                }
            }
        }
        if BYTES.fetch_add(added * BLOCK, Ordering::Relaxed) + added * BLOCK > capacity() {
            let mut b = self.cache.blocks.lock();
            while BYTES.load(Ordering::Relaxed) > capacity() && b.evict() {
                BYTES.fetch_sub(BLOCK, Ordering::Relaxed);
            }
        }
    }

    /// Patch what a write covered into the cached blocks.
    fn patch(&self, sector: u64, data: &[u8]) {
        let start = sector as usize * 512;
        let mut b = self.cache.blocks.lock();
        for k in Self::blocks_of(sector, (data.len() / 512) as u64) {
            if let Some((block, _)) = b.map.get_mut(&k) {
                let at = k as usize * BLOCK;
                let (from, to) = (start.max(at), (start + data.len()).min(at + BLOCK));
                block[from - at..to - at].copy_from_slice(&data[from - start..to - start]);
            }
        }
    }

    fn forget(&self, sector: u64, count: u64) {
        let mut b = self.cache.blocks.lock();
        let mut dropped = 0;
        for k in Self::blocks_of(sector, count) {
            if b.remove(k) {
                dropped += 1;
            }
        }
        BYTES.fetch_sub(dropped * BLOCK, Ordering::Relaxed);
    }
}

impl Drop for Cached {
    fn drop(&mut self) {
        let n = self.cache.blocks.lock().map.len();
        BYTES.fetch_sub(n * BLOCK, Ordering::Relaxed);
    }
}

impl BlockDevice for Cached {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn read_uncached(&self, sector: u64, buf: &mut [u8]) -> Result<(), IoError> {
        if self.gone.load(Ordering::Acquire) {
            return Err(IoError);
        }
        // The cache writes through, so the disk is never behind it.
        self.inner.read(sector, buf)
    }
    fn sectors(&self) -> u64 {
        self.inner.sectors()
    }
    fn read_only(&self) -> bool {
        self.inner.read_only()
    }
    fn read(&self, sector: u64, buf: &mut [u8]) -> Result<(), IoError> {
        if self.gone.load(Ordering::Acquire) {
            return Err(IoError);
        }
        if buf.len() > SMALL || buf.is_empty() {
            return self.inner.read(sector, buf);
        }
        if self.lookup(sector, buf) {
            self.cache.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        self.cache.misses.fetch_add(1, Ordering::Relaxed);
        let blocks = Self::blocks_of(sector, (buf.len() / 512) as u64);
        let first = blocks.start * SECTORS;
        let len = (blocks.end - blocks.start) as usize * BLOCK;
        if first + (len / 512) as u64 > self.inner.sectors() {
            // The disk's last blocks are not whole: not cached.
            return self.inner.read(sector, buf);
        }
        let (s0, e0) = (self.cache.started.load(Ordering::Acquire), self.cache.ended.load(Ordering::Acquire));
        let mut whole = alloc::vec![0u8; len];
        self.inner.read(first, &mut whole)?;
        let off = ((sector - first) * 512) as usize;
        buf.copy_from_slice(&whole[off..off + buf.len()]);
        let quiet = self.cache.started.load(Ordering::Acquire) == s0 && self.cache.ended.load(Ordering::Acquire) == e0;
        if quiet && s0 == e0 {
            self.keep(blocks.start, &whole);
        }
        Ok(())
    }
    fn write(&self, sector: u64, buf: &[u8]) -> Result<(), IoError> {
        if self.gone.load(Ordering::Acquire) {
            return Err(IoError);
        }
        self.cache.started.fetch_add(1, Ordering::AcqRel);
        let r = self.inner.write(sector, buf);
        match r {
            Ok(()) => self.patch(sector, buf),
            // What reached the disk is unknown: drop those blocks.
            Err(_) => self.forget(sector, (buf.len() / 512) as u64),
        }
        self.cache.ended.fetch_add(1, Ordering::AcqRel);
        r
    }
    fn flush(&self) -> Result<(), IoError> {
        if self.gone.load(Ordering::Acquire) {
            return Err(IoError);
        }
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
        self.cache.started.fetch_add(1, Ordering::AcqRel);
        let r = self.inner.discard(sector, count);
        self.forget(sector, count);
        self.cache.ended.fetch_add(1, Ordering::AcqRel);
        r
    }
    fn queue_depth(&self) -> usize {
        self.inner.queue_depth()
    }
    fn detach(&self) {
        self.gone.store(true, Ordering::Release);
        let n = {
            let mut b = self.cache.blocks.lock();
            let n = b.map.len();
            *b = Blocks::default();
            n
        };
        BYTES.fetch_sub(n * BLOCK, Ordering::Relaxed);
        self.inner.detach();
    }
    fn power_off(&self) -> Option<core::result::Result<(), IoError>> {
        // What the cache holds goes to the disk first.
        if let Err(e) = self.flush() {
            return Some(Err(e));
        }
        self.inner.power_off()
    }
}

pub const TESTS: &[crate::ktest::Test] = &[crate::ktest::Test { name: "block::cache", run: test_cache }];

/// A disk in memory that counts its reads.
struct Counted {
    data: IrqSpinLock<Vec<u8>>,
    reads: AtomicUsize,
}

impl BlockDevice for Counted {
    fn name(&self) -> &str {
        "counted"
    }
    fn sectors(&self) -> u64 {
        (self.data.lock().len() / 512) as u64
    }
    fn read_only(&self) -> bool {
        false
    }
    fn read(&self, sector: u64, buf: &mut [u8]) -> Result<(), IoError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let at = sector as usize * 512;
        buf.copy_from_slice(&self.data.lock()[at..at + buf.len()]);
        Ok(())
    }
    fn write(&self, sector: u64, buf: &[u8]) -> Result<(), IoError> {
        let at = sector as usize * 512;
        self.data.lock()[at..at + buf.len()].copy_from_slice(buf);
        Ok(())
    }
    fn flush(&self) -> Result<(), IoError> {
        Ok(())
    }
    fn can_discard(&self) -> bool {
        true
    }
    fn discard(&self, _sector: u64, _count: u64) -> Result<(), IoError> {
        Ok(())
    }
}

/// A small read misses once and hits after; a write through the cache
/// is seen without reading the disk; a long read is not cached; a
/// discard drops the blocks it touches; the disk's ragged end is read
/// but not cached.
fn test_cache() -> Result<(), &'static str> {
    let disk = Arc::new(Counted {
        data: IrqSpinLock::new((0..(64 * 1024 + 512)).map(|i| (i % 251) as u8).collect()),
        reads: AtomicUsize::new(0),
    });
    let c = Cached::new(disk.clone());
    let reads = || disk.reads.load(Ordering::Relaxed);
    let mut b = [0u8; 1024];
    c.read(9, &mut b).map_err(|_| "read")?;
    c.read(9, &mut b).map_err(|_| "read")?;
    if reads() != 1 || c.stats() != (1, 1) || b[0] != ((9 * 512) % 251) as u8 {
        return Err("a small read was not cached");
    }
    c.write(10, &[7u8; 512]).map_err(|_| "write")?;
    c.read(9, &mut b).map_err(|_| "read")?;
    if reads() != 1 || b[512..] != [7u8; 512] {
        return Err("the write did not reach the cached block");
    }
    let mut long = alloc::vec![0u8; 32 * 1024];
    c.read(0, &mut long).map_err(|_| "read")?;
    c.read(0, &mut long).map_err(|_| "read")?;
    if reads() != 3 || long[10 * 512] != 7 {
        return Err("a long read was cached, or missed the write");
    }
    c.discard(8, 8).map_err(|_| "discard")?;
    c.read(9, &mut b).map_err(|_| "read")?;
    if reads() != 4 {
        return Err("a discard left its block cached");
    }
    let mut tail = [0u8; 512];
    c.read(128, &mut tail).map_err(|_| "read")?;
    c.read(128, &mut tail).map_err(|_| "read")?;
    if reads() != 6 {
        return Err("the disk's ragged end was cached");
    }
    Ok(())
}
