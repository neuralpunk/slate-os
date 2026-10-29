// SPDX-License-Identifier: MIT OR Apache-2.0

//! The page cache: file data in memory, written back to the disk later.
//!
//! Files of the disk file systems (ext4, SlateFS) each own a [`PageCache`]
//! and implement [`Cached`] with their file system's own operations.
//! Reads fill the cache (with some read-ahead) and writes go into it, so
//! write(2) returns before the data reaches the disk. Dirty pages are
//! written back by the flusher thread once they have waited
//! [`EXPIRE_SECS`], at once when too much memory is dirty, and on
//! fsync(2), sync(2), msync(2), unmount and power-off. A failed write-back
//! is reported by the file's next fsync (like Linux, the pages count as
//! written: the data stays in memory but is not retried).
//!
//! Shared mappings (mmap(2) `MAP_SHARED`) map the cached pages themselves,
//! writable ones too. Such pages are mapped read-only until written; the
//! write fault marks the page dirty ([`mmap_written`]). Write-back marks a
//! page clean first, then makes its mappings read-only again (in every
//! process, with a TLB shootdown), and only then copies it out: a write
//! after the copy faults and dirties the page again.
//!
//! While writes are only in the cache, the file's size and modification
//! time are kept here too ([`PageCache::overlay`] puts them into stat).
//! The file systems stamp the time of the write-back on the file, so
//! write-back puts the time of the write back afterwards.
//!
//! When space runs short (less than twice the dirty data free), writes go
//! straight through to the file system instead, so `ENOSPC` reaches the
//! writer rather than a later write-back.
//!
//! Memory: clean pages no mapping uses are dropped (a clock sweep over
//! every cache) when the cache passes half of memory, when free memory
//! runs low, and when a user page cannot be allocated
//! (`frame::set_reclaim`).
//!
//! Files without a cache of their own (overlayfs, procfs) keep the older
//! write-through cache for shared read-only mappings, at the end.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::vfs::{Inode, Metadata, Result, Timespec};
use crate::abi::linux::errno::*;
use crate::log_warn;
use crate::mm::frame::{self, UserPage};
use crate::mm::{PAGE_SIZE, PhysAddr};
use crate::sched::wait::Mutex;
use crate::sync::IrqSpinLock;

/// Dirty data is written back once it has waited this long.
pub const EXPIRE_SECS: u64 = 5;
/// How often the flusher looks.
const FLUSH_INTERVAL_NS: u64 = 1_000_000_000;
/// Pages read at once on a miss (read-ahead).
const READ_AHEAD: u64 = 32;
/// Pages written back in one file system call.
const WRITE_RUN: usize = 64;
/// Space kept free beyond twice the dirty data before writes go through.
const SPACE_MARGIN: u64 = 8 << 20;

const PAGE: usize = PAGE_SIZE as usize;

/// A file with a page cache: the file system's own operations underneath.
pub trait Cached: Send + Sync {
    fn cache(&self) -> &PageCache;
    fn read_raw(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;
    fn write_raw(&self, offset: u64, buf: &[u8]) -> Result<usize>;
    fn truncate_raw(&self, size: u64) -> Result<()>;
    /// The size on the disk.
    fn size_raw(&self) -> Result<u64>;
    fn set_mtime_raw(&self, mtime: Timespec) -> Result<()>;
    /// Whether the file system can write this file later (it may refuse
    /// some files: ext4's block-mapped ones).
    fn check_write(&self) -> Result<()>;
    /// Free space on the file system, in bytes.
    fn free_bytes(&self) -> u64;
}

struct Page {
    frame: UserPage,
    dirty: bool,
    /// Used since the clock sweep last passed (reclaim keeps it a round).
    used: bool,
}

#[derive(Default)]
struct State {
    pages: BTreeMap<u64, Page>,
    dirty: usize,
    /// The file's size, once known: writes may have grown it past the
    /// size on the disk.
    size: Option<u64>,
    /// The modification time of writes not yet written back.
    mtime: Option<Timespec>,
    /// Bumped when pages are dropped or the file shrinks: a page read from
    /// the disk meanwhile may be stale and is not inserted.
    generation: u64,
    /// A write-back failed: reported by the next fsync.
    error: Option<Errno>,
    /// The file system accepted writes to this file.
    writable: bool,
    /// Listed in `CACHES` (for reclaim).
    listed: bool,
}

/// One file's cached pages.
pub struct PageCache {
    owner: Weak<dyn Cached>,
    state: IrqSpinLock<State>,
    /// Held across write-back, truncation and writes that go straight
    /// through, which must not overlap (an older copy written last would
    /// win).
    writeback: Mutex<()>,
}

/// A file with dirty pages. The strong reference keeps it until its data
/// is written.
struct Dirty {
    file: Arc<dyn Cached>,
    /// When it became dirty (monotonic nanoseconds).
    since: u64,
}

/// Files with dirty pages, by cache address.
static DIRTY: IrqSpinLock<BTreeMap<usize, Dirty>> = IrqSpinLock::new(BTreeMap::new());
/// Every cache holding pages, for reclaim.
static CACHES: IrqSpinLock<BTreeMap<usize, Weak<dyn Cached>>> = IrqSpinLock::new(BTreeMap::new());
/// Where the clock sweep goes on.
static SWEEP: AtomicUsize = AtomicUsize::new(0);
static PAGES: AtomicUsize = AtomicUsize::new(0);
static DIRTY_PAGES: AtomicUsize = AtomicUsize::new(0);
static FLUSHER: AtomicBool = AtomicBool::new(false);

/// Cached and dirty pages (/proc/meminfo).
pub fn counts() -> (usize, usize) {
    (PAGES.load(Ordering::Relaxed), DIRTY_PAGES.load(Ordering::Relaxed))
}

fn usable_pages() -> usize {
    frame::stats().usable_frames as usize
}

/// Start the flusher and register reclaim (once; from a context that may
/// sleep, when a disk file system is mounted). The flusher also keeps the
/// dentry cache within its limit.
pub fn start() {
    if FLUSHER.swap(true, Ordering::AcqRel) {
        return;
    }
    frame::set_reclaim(reclaim);
    crate::sched::spawn("flusher", || {
        loop {
            crate::time::sleep_ns(FLUSH_INTERVAL_NS);
            super::vfs::dcache::tick();
            let now = crate::time::monotonic_ns();
            let all = DIRTY_PAGES.load(Ordering::Relaxed) > usable_pages() / 16;
            let due: Vec<Arc<dyn Cached>> = DIRTY
                .lock()
                .values()
                .filter(|d| all || now.saturating_sub(d.since) >= EXPIRE_SECS * 1_000_000_000)
                .map(|d| d.file.clone())
                .collect();
            for f in due {
                let _ = write_back(&*f);
            }
        }
    });
}

impl PageCache {
    /// The cache of `owner` (made with `Arc::new_cyclic`).
    pub fn new(owner: Weak<dyn Cached>) -> PageCache {
        PageCache { owner, state: IrqSpinLock::new(State::default()), writeback: Mutex::new(()) }
    }

    fn id(&self) -> usize {
        self.owner.as_ptr().cast::<u8>() as usize
    }

    /// The file's size (read from the disk the first time).
    fn size(&self, file: &dyn Cached) -> Result<u64> {
        if let Some(s) = self.state.lock().size {
            return Ok(s);
        }
        let disk = file.size_raw()?;
        Ok(*self.state.lock().size.get_or_insert(disk))
    }

    /// Put the size and modification time of writes not yet on the disk
    /// into `m`.
    pub fn overlay(&self, m: &mut Metadata) {
        let st = self.state.lock();
        if let Some(s) = st.size {
            m.size = s;
        }
        if let Some(t) = st.mtime {
            m.mtime = t;
            m.ctime = t;
        }
        // Pages not yet written back have no blocks on the disk yet: count
        // the size rather than claim holes that may not be there.
        if st.dirty > 0 {
            m.blocks = None;
        }
    }

    /// Read pages `[first, first + count)` from the disk (zeros past its
    /// end) and insert those still missing, unless pages were dropped
    /// meanwhile. May sleep.
    fn fill(&self, file: &dyn Cached, first: u64, count: u64) -> Result<()> {
        let generation = self.state.lock().generation;
        let mut buf = alloc::vec![0u8; count as usize * PAGE];
        let mut done = 0;
        while done < buf.len() {
            match file.read_raw(first * PAGE_SIZE + done as u64, &mut buf[done..])? {
                0 => break,
                n => done += n,
            }
        }
        let mut fresh = Vec::new();
        for i in 0..count as usize {
            let page = UserPage::new().ok_or(ENOMEM)?;
            page.write(0, &buf[i * PAGE..(i + 1) * PAGE]);
            fresh.push(page);
        }
        self.insert(first, fresh, generation);
        Ok(())
    }

    /// Insert pages from `first` that are still missing, if nothing was
    /// dropped since `generation`.
    fn insert(&self, first: u64, fresh: Vec<UserPage>, generation: u64) {
        let mut added = 0;
        {
            let mut st = self.state.lock();
            if st.generation != generation {
                return;
            }
            for (i, frame) in fresh.into_iter().enumerate() {
                if let alloc::collections::btree_map::Entry::Vacant(e) = st.pages.entry(first + i as u64) {
                    e.insert(Page { frame, dirty: false, used: true });
                    added += 1;
                }
            }
            if added > 0 && !st.listed {
                st.listed = true;
                CACHES.lock().insert(self.id(), self.owner.clone());
            }
        }
        PAGES.fetch_add(added, Ordering::Relaxed);
    }

    /// Run `f` on page `index`, read in first if missing (`fill`; a page
    /// that will be overwritten whole or lies past the end starts as
    /// zeros). `ahead`: pages worth reading at once on a miss.
    fn with_page<R>(
        &self,
        file: &dyn Cached,
        index: u64,
        fill: bool,
        ahead: u64,
        mut f: impl FnMut(&mut State, u64) -> R,
    ) -> Result<R> {
        loop {
            {
                let mut st = self.state.lock();
                if let Some(p) = st.pages.get_mut(&index) {
                    p.used = true;
                    let r = f(&mut st, index);
                    drop(st);
                    // Only now, after the page was used: reclaim could
                    // otherwise drop it before every use.
                    let free = frame::stats().free_frames as usize;
                    if PAGES.load(Ordering::Relaxed) > usable_pages() / 2 || free < usable_pages() / 32 {
                        reclaim(256);
                    }
                    return Ok(r);
                }
            }
            if fill {
                // Read ahead only over pages that are missing, inside the file.
                let size = self.size(file)?;
                let last = size.div_ceil(PAGE_SIZE).max(index + 1);
                let st = self.state.lock();
                let mut count = 1;
                while count < ahead && index + count < last && !st.pages.contains_key(&(index + count)) {
                    count += 1;
                }
                drop(st);
                self.fill(file, index, count)?;
            } else {
                let generation = self.state.lock().generation;
                self.insert(index, alloc::vec![UserPage::new().ok_or(ENOMEM)?], generation);
            }
        }
    }
}

impl State {
    /// Mark page `index` dirty (it must be cached), listing the file in
    /// `DIRTY` with its first dirty page.
    fn dirty(&mut self, index: u64, owner: &Weak<dyn Cached>, id: usize) {
        let Some(p) = self.pages.get_mut(&index) else { return };
        if p.dirty {
            return;
        }
        p.dirty = true;
        self.dirty += 1;
        DIRTY_PAGES.fetch_add(1, Ordering::Relaxed);
        if self.dirty == 1
            && let Some(file) = owner.upgrade()
        {
            DIRTY.lock().entry(id).or_insert(Dirty { file, since: crate::time::monotonic_ns() });
        }
    }

    /// Drop the pages from `index` on (truncation).
    fn drop_from(&mut self, index: u64) -> Vec<UserPage> {
        let gone = self.pages.split_off(&index);
        let dirty = gone.values().filter(|p| p.dirty).count();
        self.dirty -= dirty;
        DIRTY_PAGES.fetch_sub(dirty, Ordering::Relaxed);
        PAGES.fetch_sub(gone.len(), Ordering::Relaxed);
        self.generation += 1;
        gone.into_values().map(|p| p.frame).collect()
    }
}

impl Drop for PageCache {
    fn drop(&mut self) {
        let st = self.state.lock();
        PAGES.fetch_sub(st.pages.len(), Ordering::Relaxed);
        DIRTY_PAGES.fetch_sub(st.dirty, Ordering::Relaxed);
        if st.listed {
            CACHES.lock().remove(&self.id());
        }
    }
}

/// read(2) through the cache.
pub fn read(file: &dyn Cached, offset: u64, buf: &mut [u8]) -> Result<usize> {
    let c = file.cache();
    let size = c.size(file)?;
    if offset >= size {
        return Ok(0);
    }
    let n = (size - offset).min(buf.len() as u64) as usize;
    let mut done = 0;
    while done < n {
        let pos = offset + done as u64;
        let (index, within) = (pos / PAGE_SIZE, (pos % PAGE_SIZE) as usize);
        let take = (PAGE - within).min(n - done);
        let ahead = (n - done).div_ceil(PAGE) as u64 + READ_AHEAD / 4;
        let out = &mut buf[done..done + take];
        c.with_page(file, index, true, ahead.min(READ_AHEAD), |st, i| {
            if let Some(p) = st.pages.get(&i) {
                p.frame.read(within, out);
            }
        })?;
        done += take;
    }
    Ok(n)
}

/// write(2) into the cache (straight through when space is short).
pub fn write(file: &dyn Cached, offset: u64, data: &[u8]) -> Result<usize> {
    let c = file.cache();
    if !c.state.lock().writable {
        file.check_write()?;
        c.state.lock().writable = true;
    }
    let end = offset.checked_add(data.len() as u64).ok_or(EFBIG)?;
    if data.is_empty() {
        return Ok(0);
    }
    let pages = end.div_ceil(PAGE_SIZE) - offset / PAGE_SIZE;
    let dirty = DIRTY_PAGES.load(Ordering::Relaxed) as u64;
    if file.free_bytes() < 2 * (dirty + pages) * PAGE_SIZE + SPACE_MARGIN {
        return write_through(file, offset, data);
    }
    let size = c.size(file)?;
    let (owner, id) = (&c.owner, c.id());
    let mut done = 0;
    while done < data.len() {
        let pos = offset + done as u64;
        let (index, within) = (pos / PAGE_SIZE, (pos % PAGE_SIZE) as usize);
        let take = (PAGE - within).min(data.len() - done);
        let whole = take == PAGE || index * PAGE_SIZE >= size;
        let chunk = &data[done..done + take];
        c.with_page(file, index, !whole, 1, |st, i| {
            if let Some(p) = st.pages.get(&i) {
                p.frame.write(within, chunk);
            }
            st.dirty(i, owner, id);
        })?;
        done += take;
    }
    {
        let mut st = c.state.lock();
        st.size = Some(st.size.unwrap_or(size).max(end));
        st.mtime = Some(Timespec::now());
    }
    // Too much dirty memory: the writer waits for its own data.
    if DIRTY_PAGES.load(Ordering::Relaxed) > usable_pages() / 8 {
        write_back(file)?;
    }
    Ok(data.len())
}

/// A write that goes to the file system at once, keeping cached pages up
/// to date.
fn write_through(file: &dyn Cached, offset: u64, data: &[u8]) -> Result<usize> {
    let c = file.cache();
    let _wb = c.writeback.lock();
    let n = file.write_raw(offset, data)?;
    let end = offset + n as u64;
    let mut st = c.state.lock();
    for (&index, p) in st.pages.range(offset / PAGE_SIZE..end.div_ceil(PAGE_SIZE)) {
        let start = (index * PAGE_SIZE).max(offset);
        let stop = ((index + 1) * PAGE_SIZE).min(end);
        p.frame.write((start - index * PAGE_SIZE) as usize, &data[(start - offset) as usize..(stop - offset) as usize]);
    }
    if let Some(s) = st.size.as_mut() {
        *s = (*s).max(end);
    }
    if st.mtime.is_some() {
        st.mtime = Some(Timespec::now());
    }
    Ok(n)
}

/// truncate(2): the file system changes size at once; cached pages past
/// the end go, and the rest of the last page reads as zeros.
pub fn truncate(file: &dyn Cached, size: u64) -> Result<()> {
    let c = file.cache();
    let _wb = c.writeback.lock();
    file.truncate_raw(size)?;
    let gone = {
        let mut st = c.state.lock();
        let gone = st.drop_from(size.div_ceil(PAGE_SIZE));
        if size % PAGE_SIZE != 0
            && let Some(p) = st.pages.get(&(size / PAGE_SIZE))
        {
            p.frame.zero_from((size % PAGE_SIZE) as usize);
        }
        st.size = Some(size);
        if st.mtime.is_some() {
            st.mtime = Some(Timespec::now());
        }
        gone
    };
    drop(gone);
    Ok(())
}

/// The cached page at `offset` with a reference taken for a shared
/// mapping. May sleep.
pub fn shared_page(file: &dyn Cached, offset: u64) -> Result<PhysAddr> {
    file.cache()
        .with_page(file, offset / PAGE_SIZE, true, 1, |st, i| st.pages.get(&i).map(|p| p.frame.share()))?
        .ok_or(EIO)
}

/// A shared mapping is about to write the page at `offset` (from the page
/// fault handler, with the address space's lock held).
pub fn mmap_written(file: &dyn Cached, offset: u64) {
    let c = file.cache();
    let mut st = c.state.lock();
    st.dirty(offset / PAGE_SIZE, &c.owner, c.id());
    st.mtime = Some(Timespec::now());
}

/// Write `file`'s dirty pages to its file system (not yet durable: the
/// file system's sync does that). Returns, and clears, an error a
/// write-back of this file met since the last call.
pub fn write_back(file: &dyn Cached) -> Result<()> {
    let c = file.cache();
    let _wb = c.writeback.lock();
    let size = c.size(file)?;
    // Mark the pages clean and take a reference to each, which keeps
    // reclaim away until they are written.
    let (pages, mapped, mtime) = {
        let mut st = c.state.lock();
        let mut pages = Vec::new();
        let mut mapped = BTreeSet::new();
        for (&i, p) in st.pages.iter_mut().filter(|(_, p)| p.dirty) {
            p.dirty = false;
            if p.frame.shared() {
                mapped.insert(i);
            }
            pages.push((i, p.frame.clone()));
        }
        st.dirty -= pages.len();
        DIRTY_PAGES.fetch_sub(pages.len(), Ordering::Relaxed);
        (pages, mapped, st.mtime)
    };
    if !mapped.is_empty() {
        write_protect(c.id(), &mapped);
    }
    let mut result = Ok(());
    if !pages.is_empty() {
        let mut run_start = 0;
        while run_start < pages.len() {
            let first = pages[run_start].0;
            let mut n = 1;
            while run_start + n < pages.len() && n < WRITE_RUN && pages[run_start + n].0 == first + n as u64 {
                n += 1;
            }
            let offset = first * PAGE_SIZE;
            let len = (size.saturating_sub(offset)).min(n as u64 * PAGE_SIZE) as usize;
            if len > 0 {
                let mut buf = alloc::vec![0u8; len];
                for (k, chunk) in buf.chunks_mut(PAGE).enumerate() {
                    pages[run_start + k].1.read(0, chunk);
                }
                if let Err(e) = write_all(file, offset, &buf) {
                    result = Err(e);
                }
            }
            run_start += n;
        }
        if let Some(t) = mtime
            && let Err(e) = file.set_mtime_raw(t)
        {
            result = Err(e);
        }
    }
    let mut st = c.state.lock();
    if st.mtime == mtime && result.is_ok() {
        st.mtime = None;
    }
    if let Err(e) = result
        && st.error.replace(e).is_none()
    {
        log_warn!("page cache: write-back failed: {e:?}");
    }
    let unlisted = if st.dirty == 0 { DIRTY.lock().remove(&c.id()) } else { None };
    let error = st.error.take();
    drop(st);
    drop(unlisted);
    drop(pages);
    error.map_or(Ok(()), Err)
}

fn write_all(file: &dyn Cached, offset: u64, buf: &[u8]) -> Result<()> {
    let mut done = 0;
    while done < buf.len() {
        match file.write_raw(offset + done as u64, &buf[done..])? {
            0 => return Err(ENOSPC),
            n => done += n,
        }
    }
    Ok(())
}

/// Make the pages `pages` of the file at address `file` read-only in every
/// process's shared mappings, then flush stale translations everywhere.
fn write_protect(file: usize, pages: &BTreeSet<u64>) {
    let mut changed = false;
    for p in crate::proc::all() {
        if let Some(a) = p.aspace.lock().as_mut() {
            changed |= a.write_protect_file(file, pages);
        }
    }
    if changed {
        crate::arch::tlb_shootdown(PhysAddr(0));
    }
}

/// Write back every file with dirty pages (sync(2), unmount, power-off).
/// Drop the clean, unmapped pages of `file` covering bytes `[offset,
/// offset + len)` (O_DIRECT, ADR 0145).
pub fn drop_range(file: &dyn Cached, offset: u64, len: u64) {
    let (first, last) = (offset / PAGE_SIZE, (offset + len).div_ceil(PAGE_SIZE));
    let mut gone = Vec::new();
    {
        let mut st = file.cache().state.lock();
        let keys: Vec<u64> =
            st.pages.range(first..last).filter(|(_, p)| !p.dirty && !p.frame.shared()).map(|(&k, _)| k).collect();
        if !keys.is_empty() {
            st.generation += 1;
        }
        for k in keys {
            if let Some(p) = st.pages.remove(&k) {
                gone.push(p.frame);
            }
        }
    }
    PAGES.fetch_sub(gone.len(), Ordering::Relaxed);
    // The frames go with no lock held.
    drop(gone);
}

pub fn write_back_all() {
    let all: Vec<Arc<dyn Cached>> = DIRTY.lock().values().map(|d| d.file.clone()).collect();
    for f in all {
        let _ = write_back(&*f);
    }
}

/// Drop at least `want` clean pages no mapping uses, if there are that
/// many: a clock sweep over the caches, which skips pages used since it
/// last passed (clearing the mark). Takes no lock it would wait for, so it
/// is safe wherever user pages are allocated. Returns the pages dropped.
pub fn reclaim(want: usize) -> usize {
    let freed = sweep(want);
    // And the dentry cache, by the flusher (dropping dentries takes locks
    // reclaim mustn't wait for).
    if freed < want {
        super::vfs::dcache::pressure();
    }
    freed
}

/// Drop every clean page no mapping uses (`/proc/sys/vm/drop_caches` 1).
pub fn drop_clean() -> usize {
    sweep(usize::MAX)
}

/// [`reclaim`]'s sweep, the block cache last.
fn sweep(want: usize) -> usize {
    let mut freed = 0;
    let mut held: Vec<Arc<dyn Cached>> = Vec::new();
    let mut gone: Vec<UserPage> = Vec::new();
    // Two rounds: the first may only clear marks of pages used since.
    for _ in 0..2 {
        let Some(caches) = CACHES.try_lock() else { break };
        let start = SWEEP.load(Ordering::Relaxed);
        let order: Vec<(usize, Weak<dyn Cached>)> =
            caches.range(start..).chain(caches.range(..start)).map(|(&k, w)| (k, w.clone())).collect();
        drop(caches);
        for (key, w) in order {
            let Some(file) = w.upgrade() else { continue };
            if let Some(mut st) = file.cache().state.try_lock() {
                let mut drop_keys = Vec::new();
                for (&i, p) in st.pages.iter_mut() {
                    if p.dirty || p.frame.shared() {
                        continue;
                    }
                    if p.used {
                        p.used = false;
                    } else {
                        drop_keys.push(i);
                        if freed + drop_keys.len() >= want {
                            break;
                        }
                    }
                }
                if !drop_keys.is_empty() {
                    st.generation += 1;
                }
                for i in drop_keys {
                    if let Some(p) = st.pages.remove(&i) {
                        gone.push(p.frame);
                        freed += 1;
                    }
                }
            }
            held.push(file);
            if freed >= want {
                SWEEP.store(key, Ordering::Relaxed);
                break;
            }
        }
        if freed >= want {
            break;
        }
    }
    PAGES.fetch_sub(freed, Ordering::Relaxed);
    // Frames and files go only now, with no lock held.
    drop(gone);
    drop(held);
    // Then the block cache's least recently used blocks (ADR 0080).
    if freed < want {
        freed += crate::block::cache::shrink(want - freed);
    }
    freed
}

// --- Files without a cache of their own ---------------------------------
//
// Shared read-only mappings of files that have no pages of their own to
// map (overlayfs, procfs): pages are read in on the first fault and kept
// while mapped; every write and truncate through an open file updates the
// cached pages it covers. Writable shared mappings of such files are
// refused.

struct Mapped {
    inode: Weak<dyn Inode>,
    pages: BTreeMap<u64, UserPage>,
}

/// Mapped pages by inode address (checked against the weak reference, as
/// an address can be reused once an inode is gone).
static MAPPED: IrqSpinLock<BTreeMap<usize, Mapped>> = IrqSpinLock::new(BTreeMap::new());

fn key(inode: &Arc<dyn Inode>) -> usize {
    Arc::as_ptr(inode).cast::<u8>() as usize
}

/// The page at `offset` of `inode` (read in if need be), with a reference
/// taken for a mapping. May sleep: call with no spinlock held.
pub fn mapped_page(inode: &Arc<dyn Inode>, offset: u64) -> Result<PhysAddr> {
    let index = offset / PAGE_SIZE;
    if let Some(p) = lookup(inode, index) {
        return Ok(p);
    }
    let page = UserPage::new().ok_or(ENOMEM)?;
    let mut buf = alloc::vec![0u8; PAGE];
    let mut done = 0;
    while done < buf.len() {
        match inode.read_at(index * PAGE_SIZE + done as u64, &mut buf[done..])? {
            0 => break,
            n => done += n,
        }
    }
    page.write(0, &buf);
    let mut cache = MAPPED.lock();
    let entry =
        cache.entry(key(inode)).or_insert_with(|| Mapped { inode: Arc::downgrade(inode), pages: BTreeMap::new() });
    if !entry.inode.upgrade().is_some_and(|i| Arc::ptr_eq(&i, inode)) {
        *entry = Mapped { inode: Arc::downgrade(inode), pages: BTreeMap::new() };
    }
    // Someone else may have read it meanwhile: theirs wins.
    let p = entry.pages.entry(index).or_insert(page);
    Ok(p.share())
}

fn lookup(inode: &Arc<dyn Inode>, index: u64) -> Option<PhysAddr> {
    let cache = MAPPED.lock();
    let c = cache.get(&key(inode))?;
    if !c.inode.upgrade().is_some_and(|i| Arc::ptr_eq(&i, inode)) {
        return None;
    }
    c.pages.get(&index).map(UserPage::share)
}

/// `data` was written at `offset` of `inode`: update the mapped pages.
/// Pages no mapping uses any more are dropped on the way.
pub fn wrote(inode: &Arc<dyn Inode>, offset: u64, data: &[u8]) {
    let mut cache = MAPPED.lock();
    let Some(c) = cache.get_mut(&key(inode)) else { return };
    c.pages.retain(|_, p| p.shared());
    let end = offset + data.len() as u64;
    for (&index, page) in c.pages.range(offset / PAGE_SIZE..end.div_ceil(PAGE_SIZE)) {
        let start = (index * PAGE_SIZE).max(offset);
        let stop = ((index + 1) * PAGE_SIZE).min(end);
        page.write((start - index * PAGE_SIZE) as usize, &data[(start - offset) as usize..(stop - offset) as usize]);
    }
    if c.pages.is_empty() {
        cache.remove(&key(inode));
    }
}

/// `inode` was truncated to `size`: mapped data past it reads as zeros.
pub fn truncated(inode: &Arc<dyn Inode>, size: u64) {
    let mut cache = MAPPED.lock();
    let Some(c) = cache.get_mut(&key(inode)) else { return };
    for (&index, page) in c.pages.range(size / PAGE_SIZE..) {
        let from = size.saturating_sub(index * PAGE_SIZE) as usize;
        page.zero_from(from.min(PAGE));
    }
}
