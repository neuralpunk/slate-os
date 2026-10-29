// SPDX-License-Identifier: MIT OR Apache-2.0

//! The physical frame allocator: a buddy allocator over all usable RAM.

use slate_buddy::{Buddy, Link, LinkStore};

use super::{PAGE_SIZE, PhysAddr};
use crate::arch::boot::{Region, RegionKind};
use crate::sync::IrqSpinLock;

pub use slate_buddy::MAX_ORDER;

/// Keeps buddy free-list links in the free frames themselves, through the
/// direct map.
#[derive(Debug)]
struct DirectMapLinks;

impl LinkStore for DirectMapLinks {
    fn read(&self, frame: u64) -> Link {
        // SAFETY: The buddy allocator only reads links of frames it wrote,
        // which are free frames it owns, mapped in the direct map.
        unsafe { PhysAddr::from_frame(frame).to_virt().cast::<Link>().read() }
    }

    fn write(&mut self, frame: u64, link: Link) {
        // SAFETY: The buddy allocator only writes links into free frames it
        // owns; nobody else touches them while they are free.
        unsafe { PhysAddr::from_frame(frame).to_virt().cast::<Link>().write(link) }
    }
}

static FRAMES: IrqSpinLock<Option<Buddy<'static, DirectMapLinks>>> = IrqSpinLock::new(None);
/// Reference counts of user-mapped frames (shared after fork, until a
/// copy-on-write fault splits them), indexed by frame number.
static REFCOUNTS: slate_sync::Once<&'static [core::sync::atomic::AtomicU32]> = slate_sync::Once::new();
/// The memory-cgroup counter each user frame is charged to (0: none;
/// `memcg.rs`), indexed by frame number.
static OWNERS: slate_sync::Once<&'static [core::sync::atomic::AtomicU16]> = slate_sync::Once::new();
static USABLE_FRAMES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Frame allocator statistics.
#[derive(Clone, Copy, Debug)]
pub struct Stats {
    pub free_frames: u64,
    pub usable_frames: u64,
}

pub fn stats() -> Stats {
    let free = FRAMES.lock().as_ref().map_or(0, |b| b.free_frames());
    Stats { free_frames: free, usable_frames: USABLE_FRAMES.load(core::sync::atomic::Ordering::Relaxed) }
}

/// Free block counts per order (for tests).
pub fn free_blocks() -> [usize; MAX_ORDER + 1] {
    FRAMES.lock().as_ref().map_or([0; MAX_ORDER + 1], |b| b.free_blocks())
}

/// Hand every usable region to the allocator. The per-frame metadata
/// (seven bytes per frame up to the highest usable address) is carved out
/// of the first usable region large enough to hold it.
pub fn init(map: impl Iterator<Item = Region> + Clone) {
    let usable = || map.clone().filter(|r| r.kind == RegionKind::Usable);
    let limit = usable().map(|r| (r.base + r.len) / PAGE_SIZE).max().expect("no usable memory");
    // One byte of buddy metadata, a four-byte reference count (a page
    // every process maps, like the vDSO's, outgrows 16 bits at 65 536
    // processes) and a two-byte memory-cgroup slot per frame.
    let meta_bytes = (limit * 7 + 8).div_ceil(PAGE_SIZE) * PAGE_SIZE;
    let meta_region = usable().find(|r| r.len >= meta_bytes + PAGE_SIZE).expect("no region fits frame metadata");
    // Keep frame 0 out of circulation so physical address 0 never looks valid.
    let meta_base = meta_region.base.max(PAGE_SIZE);

    // SAFETY: `meta_base..meta_base + meta_bytes` is usable RAM that nothing
    // else owns (it is excluded from the allocator below), mapped by the
    // bootloader's direct map, and lives forever.
    let meta = unsafe { core::slice::from_raw_parts_mut(PhysAddr(meta_base).to_virt(), meta_bytes as usize) };
    let (meta, refs) = meta.split_at_mut(limit as usize);
    let mut buddy = Buddy::new(DirectMapLinks, meta);
    refs.fill(0);
    // SAFETY: `refs` is at least `6 * limit + 8` zeroed bytes: room for
    // `limit` four-byte counters once aligned to four (it starts `limit`
    // bytes into a page-aligned region), then `limit` two-byte ones, which
    // the four-byte array's end leaves aligned. They live forever.
    let (refs, owners) = unsafe {
        let p = refs.as_mut_ptr();
        let aligned = p.add(p.align_offset(4)).cast::<core::sync::atomic::AtomicU32>();
        (
            core::slice::from_raw_parts(aligned, limit as usize),
            core::slice::from_raw_parts(
                aligned.add(limit as usize).cast::<core::sync::atomic::AtomicU16>(),
                limit as usize,
            ),
        )
    };
    REFCOUNTS.call_once(|| refs);
    OWNERS.call_once(|| owners);

    let mut total = 0;
    for r in usable() {
        let mut start = r.base.div_ceil(PAGE_SIZE).max(1);
        let mut end = (r.base + r.len) / PAGE_SIZE;
        if r.base == meta_region.base {
            start = (meta_base + meta_bytes) / PAGE_SIZE;
        }
        end = end.max(start);
        buddy.add_range(start, end - start);
        total += end - start;
    }
    USABLE_FRAMES.store(total, core::sync::atomic::Ordering::Relaxed);
    *FRAMES.lock() = Some(buddy);
}

/// Hand a physical range that the kernel no longer needs to the allocator.
pub fn add_region(base: u64, len: u64) {
    let start = base.div_ceil(PAGE_SIZE).max(1);
    let end = ((base + len) / PAGE_SIZE).max(start);
    if let Some(b) = FRAMES.lock().as_mut() {
        b.add_range(start, end - start);
    }
    USABLE_FRAMES.fetch_add(end - start, core::sync::atomic::Ordering::Relaxed);
}

/// Allocate 2^order contiguous, naturally aligned frames.
pub fn alloc(order: usize) -> Option<PhysAddr> {
    FRAMES.lock().as_mut()?.alloc(order).map(PhysAddr::from_frame)
}

/// Allocate 2^order contiguous, naturally aligned frames below physical
/// address `limit`.
pub fn alloc_below(order: usize, limit: u64) -> Option<PhysAddr> {
    FRAMES.lock().as_mut()?.alloc_below(order, limit / PAGE_SIZE).map(PhysAddr::from_frame)
}

/// Allocate one frame and fill it with zeros.
pub fn alloc_zeroed() -> Option<PhysAddr> {
    let p = alloc(0)?;
    // SAFETY: The frame was just allocated and is mapped in the direct map.
    unsafe { core::ptr::write_bytes(p.to_virt(), 0, PAGE_SIZE as usize) };
    Some(p)
}

/// Free frames from [`alloc`] with the same order.
///
/// # Panics
///
/// On a double free or a misaligned or out-of-range address: these are
/// kernel bugs, and continuing would corrupt memory.
pub fn free(p: PhysAddr, order: usize) {
    if order == 0 && super::canary::quarantine(p) {
        return;
    }
    free_now(p, order);
}

/// Free frames now (the quarantine's way back to the allocator).
pub(super) fn free_now(p: PhysAddr, order: usize) {
    let mut g = FRAMES.lock();
    let b = g.as_mut().expect("frame allocator not initialized");
    if let Err(e) = b.free(p.frame(), order) {
        drop(g);
        panic!("bad frame free of {:#x} (order {order}): {e:?}", p.0);
    }
}

fn refcount(p: PhysAddr) -> &'static core::sync::atomic::AtomicU32 {
    &REFCOUNTS.get().expect("frame allocator not initialized")[p.frame() as usize]
}

/// Frees memory others hold but can give back (the page cache's clean
/// pages): asked for at least `frames` frames, returns how many it freed.
/// It must not take locks that callers of [`alloc_user_page`] may hold.
static RECLAIM: slate_sync::Once<fn(usize) -> usize> = slate_sync::Once::new();

/// Register the function [`alloc_user_page`] calls when memory runs out.
pub fn set_reclaim(f: fn(usize) -> usize) {
    RECLAIM.call_once(|| f);
}

/// Allocate a zeroed frame for a user mapping, with reference count 1,
/// charged to the current process's memory cgroup (`memcg.rs`). When
/// memory runs out, reclaimable memory is given back first. Fails when
/// memory or the cgroup's allowance has run out.
pub fn alloc_user_page() -> Option<PhysAddr> {
    let cg = super::memcg::current();
    if let Some(m) = cg {
        m.try_charge().ok()?;
    }
    let p = alloc_user_page_uncharged();
    match (p, cg) {
        (Some(p), Some(m)) => owner(p).store(m.id, core::sync::atomic::Ordering::Relaxed),
        (None, Some(m)) => super::memcg::uncharge(m.id),
        _ => {}
    }
    p
}

/// [`alloc_user_page`] charged to no cgroup: pages that belong to files
/// (tmpfs, the page cache) rather than to a process.
pub fn alloc_user_page_uncharged() -> Option<PhysAddr> {
    let p = match alloc_above_reserve() {
        Some(p) => p,
        None => {
            let reclaim = RECLAIM.get()?;
            if reclaim(64) == 0 {
                return None;
            }
            alloc_above_reserve()?
        }
    };
    // SAFETY: The frame was just allocated and is mapped in the direct map.
    unsafe { core::ptr::write_bytes(p.to_virt(), 0, PAGE_SIZE as usize) };
    refcount(p).store(1, core::sync::atomic::Ordering::Relaxed);
    Some(p)
}

/// Frames user pages leave to the kernel (ADR 0047): 1/128 of memory,
/// between 4 and 32 MiB. User allocations fail first, so the
/// out-of-memory killer frees memory before the kernel's own allocations
/// (which cannot wait for it) run short.
fn reserve() -> u64 {
    (USABLE_FRAMES.load(core::sync::atomic::Ordering::Relaxed) / 128).clamp(1024, 8192)
}

/// One frame, unless that would dip into the kernel's reserve.
fn alloc_above_reserve() -> Option<PhysAddr> {
    let mut g = FRAMES.lock();
    let b = g.as_mut()?;
    if b.free_frames() <= reserve() {
        return None;
    }
    b.alloc(0).map(PhysAddr::from_frame)
}

/// Give back clean page-cache pages: at least `frames` were asked for;
/// returns how many were freed.
pub fn reclaim(frames: usize) -> usize {
    RECLAIM.get().map_or(0, |f| f(frames))
}

fn owner(p: PhysAddr) -> &'static core::sync::atomic::AtomicU16 {
    &OWNERS.get().expect("frame allocator not initialized")[p.frame() as usize]
}

/// Another mapping now shares user frame `p`.
pub fn get_user_page(p: PhysAddr) {
    let old = refcount(p).fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    assert!(old > 0 && old < u32::MAX, "bad user page refcount {old} for {:#x}", p.0);
}

/// Drop one mapping of user frame `p`; frees it with the last one.
pub fn put_user_page(p: PhysAddr) {
    let old = refcount(p).fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
    assert!(old > 0, "user page {:#x} freed twice", p.0);
    if old == 1 {
        let cg = owner(p).swap(0, core::sync::atomic::Ordering::Relaxed);
        if cg != 0 {
            super::memcg::uncharge(cg);
        }
        free(p, 0);
    }
}

/// How many mappings share user frame `p`.
pub fn user_page_refs(p: PhysAddr) -> u32 {
    refcount(p).load(core::sync::atomic::Ordering::Acquire)
}

/// One reference to a user frame, released when dropped: file pages that
/// mappings may share (tmpfs). Accesses copy through the direct map, so
/// user space writing the same page concurrently only races on the data.
#[derive(Debug)]
pub struct UserPage(PhysAddr);

impl UserPage {
    /// A zeroed page (charged to no cgroup: it belongs to a file).
    pub fn new() -> Option<UserPage> {
        alloc_user_page_uncharged().map(UserPage)
    }

    /// Take another reference for a mapping (released with
    /// [`put_user_page`] when it is unmapped).
    pub fn share(&self) -> PhysAddr {
        get_user_page(self.0);
        self.0
    }

    pub fn read(&self, off: usize, buf: &mut [u8]) {
        assert!(off + buf.len() <= PAGE_SIZE as usize);
        // SAFETY: The frame is ours (we hold a reference) and in the direct
        // map; the range is inside it.
        unsafe { core::ptr::copy_nonoverlapping(self.0.to_virt().add(off), buf.as_mut_ptr(), buf.len()) };
    }

    pub fn write(&self, off: usize, buf: &[u8]) {
        assert!(off + buf.len() <= PAGE_SIZE as usize);
        // SAFETY: As in `read`.
        unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), self.0.to_virt().add(off), buf.len()) };
    }

    /// Whether a mapping still uses the page besides this reference.
    pub fn shared(&self) -> bool {
        user_page_refs(self.0) > 1
    }

    /// Zero the page from `off` to its end.
    pub fn zero_from(&self, off: usize) {
        assert!(off <= PAGE_SIZE as usize);
        // SAFETY: As in `read`.
        unsafe { core::ptr::write_bytes(self.0.to_virt().add(off), 0, PAGE_SIZE as usize - off) };
    }
}

impl Clone for UserPage {
    /// Another reference to the same frame.
    fn clone(&self) -> UserPage {
        get_user_page(self.0);
        UserPage(self.0)
    }
}

impl Drop for UserPage {
    fn drop(&mut self) {
        put_user_page(self.0);
    }
}
