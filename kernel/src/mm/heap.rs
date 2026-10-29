// SPDX-License-Identifier: MIT OR Apache-2.0

//! The kernel heap (`alloc` support).
//!
//! Requests up to 2 KiB come from slab caches (one per size class, see
//! `slate-slab`); larger ones get whole buddy blocks from the frame
//! allocator, addressed through the direct map. The largest single
//! allocation is therefore one buddy block (4 MiB) until a virtually
//! contiguous allocator exists.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{self, NonNull};

use slate_slab::{CLASSES, Cache, PageSource, class_for, slab_order};

use super::{PAGE_SIZE, frame, virt_to_phys_direct};
use crate::sync::IrqSpinLock;

/// Slabs and large blocks come straight from the buddy allocator.
#[derive(Debug)]
struct FramePages;

// SAFETY: Buddy blocks of order `n` are 2^n frames, aligned to their size,
// and exclusively owned until freed; the direct map preserves alignment
// because its offset is 1 GiB aligned.
unsafe impl PageSource for FramePages {
    fn alloc_pages(&self, order: usize) -> Option<NonNull<u8>> {
        let p = frame::alloc(order).and_then(|p| NonNull::new(p.to_virt()))?;
        PAGES.fetch_add(1 << order, core::sync::atomic::Ordering::Relaxed);
        Some(p)
    }

    unsafe fn free_pages(&self, p: NonNull<u8>, order: usize) {
        PAGES.fetch_sub(1 << order, core::sync::atomic::Ordering::Relaxed);
        frame::free(virt_to_phys_direct(p.as_ptr()), order);
    }
}

/// Frames the heap holds (slabs and large blocks).
static PAGES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Frames the kernel heap holds now (/proc/meminfo `Slab:`).
pub fn pages() -> u64 {
    PAGES.load(core::sync::atomic::Ordering::Relaxed)
}

const fn cache(i: usize) -> IrqSpinLock<Cache> {
    IrqSpinLock::new(Cache::new(CLASSES[i], slab_order(CLASSES[i])))
}

static CACHES: [IrqSpinLock<Cache>; CLASSES.len()] =
    [cache(0), cache(1), cache(2), cache(3), cache(4), cache(5), cache(6), cache(7)];

/// Buddy order for a large allocation.
fn large_order(layout: Layout) -> Option<usize> {
    let bytes = layout.size().max(layout.align()) as u64;
    let pages = bytes.div_ceil(PAGE_SIZE).next_power_of_two();
    let order = pages.trailing_zeros() as usize;
    (order <= frame::MAX_ORDER).then_some(order)
}

#[derive(Debug)]
struct KernelHeap;

// SAFETY: Each allocation is a distinct slab object or buddy block of at
// least `layout.size()` bytes, aligned to at least `layout.align()` (slab
// objects are aligned to their class size, which is >= align; buddy blocks to
// their size). `dealloc` routes by the same layout back to the same source.
unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match class_for(layout) {
            Some(c) => CACHES[c].lock().alloc(&FramePages).map_or(ptr::null_mut(), |p| p.as_ptr()),
            None => large_order(layout).and_then(|o| FramePages.alloc_pages(o)).map_or(ptr::null_mut(), |p| p.as_ptr()),
        }
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        // SAFETY: `GlobalAlloc` guarantees `p` came from `alloc` with this
        // layout, so it is non-null.
        let p = unsafe { NonNull::new_unchecked(p) };
        match class_for(layout) {
            // SAFETY: `p` came from this class's cache.
            Some(c) => unsafe { CACHES[c].lock().free(p, &FramePages) },
            // SAFETY: `p` is a buddy block of this order.
            None => unsafe { FramePages.free_pages(p, large_order(layout).expect("bad large dealloc")) },
        }
    }
}

#[global_allocator]
static HEAP: KernelHeap = KernelHeap;

/// Objects in use per slab size class, as (size, objects).
pub fn class_stats() -> [(usize, usize); CLASSES.len()] {
    core::array::from_fn(|i| (CLASSES[i], CACHES[i].lock().stats().objects_in_use))
}

/// Objects in use and slabs held, summed over all slab caches.
pub fn slab_stats() -> slate_slab::Stats {
    let mut total = slate_slab::Stats::default();
    for c in &CACHES {
        let s = c.lock().stats();
        total.slabs += s.slabs;
        total.objects_in_use += s.objects_in_use;
    }
    total
}
