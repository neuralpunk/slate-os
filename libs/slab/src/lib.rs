// SPDX-License-Identifier: MIT OR Apache-2.0

//! Slab caches for small, fixed-size objects.
//!
//! A [`Cache`] serves objects of one size class out of slabs: naturally
//! aligned blocks of 2^order pages from a [`PageSource`]. Each slab keeps its
//! header at its end, so objects start at the slab base and stay aligned to
//! the class size, and the header of any object is found by masking its
//! address. Slabs with free objects sit on a partial list; full slabs are not
//! tracked; one empty slab is cached per class and further empty slabs go
//! back to the page source.
//!
//! Caches are not synchronized; the kernel puts each behind a lock.

#![no_std]

#[cfg(test)]
extern crate std;

use core::alloc::Layout;
use core::ptr::{self, NonNull};

pub const PAGE_SIZE: usize = 4096;

/// Object sizes served by slab caches. Larger requests go to the page
/// allocator directly.
pub const CLASSES: [usize; 8] = [16, 32, 64, 128, 256, 512, 1024, 2048];

/// Index into [`CLASSES`] for a layout, or `None` if it is too large.
pub fn class_for(layout: Layout) -> Option<usize> {
    let need = layout.size().max(layout.align());
    CLASSES.iter().position(|&c| c >= need)
}

/// Slab order (log2 of pages per slab) for a class size: big enough to hold
/// at least seven objects.
pub const fn slab_order(size: usize) -> usize {
    if size <= 512 {
        0
    } else if size <= 1024 {
        1
    } else {
        2
    }
}

/// Where slabs come from.
///
/// # Safety
///
/// `alloc` must return blocks of `PAGE_SIZE << order` bytes, aligned to that
/// size, exclusively owned by the caller until passed back to `free`.
pub unsafe trait PageSource {
    fn alloc_pages(&self, order: usize) -> Option<NonNull<u8>>;
    /// # Safety
    ///
    /// `p` must come from `alloc_pages(order)` and not be used afterwards.
    unsafe fn free_pages(&self, p: NonNull<u8>, order: usize);
}

#[repr(C)]
struct FreeObject {
    next: *mut FreeObject,
}

#[repr(C)]
struct SlabHeader {
    next: *mut SlabHeader,
    prev: *mut SlabHeader,
    free: *mut FreeObject,
    in_use: u32,
}

/// Statistics for one cache.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub slabs: usize,
    pub objects_in_use: usize,
}

/// A cache of objects of one size.
#[derive(Debug)]
pub struct Cache {
    size: usize,
    order: usize,
    partial: *mut SlabHeader,
    empty: *mut SlabHeader,
    stats: Stats,
}

// SAFETY: A cache exclusively owns its slabs; moving it between threads moves
// that ownership.
unsafe impl Send for Cache {}

impl Cache {
    pub const fn new(size: usize, order: usize) -> Cache {
        Cache {
            size,
            order,
            partial: ptr::null_mut(),
            empty: ptr::null_mut(),
            stats: Stats { slabs: 0, objects_in_use: 0 },
        }
    }

    pub fn object_size(&self) -> usize {
        self.size
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    fn slab_bytes(&self) -> usize {
        PAGE_SIZE << self.order
    }

    fn capacity(&self) -> usize {
        (self.slab_bytes() - size_of::<SlabHeader>()) / self.size
    }

    fn header_of(&self, p: *mut u8) -> *mut SlabHeader {
        let base = (p as usize) & !(self.slab_bytes() - 1);
        (base + self.slab_bytes() - size_of::<SlabHeader>()) as *mut SlabHeader
    }

    fn base_of(&self, h: *mut SlabHeader) -> *mut u8 {
        (h as usize + size_of::<SlabHeader>() - self.slab_bytes()) as *mut u8
    }

    /// Allocate one object, or `None` if the page source is exhausted.
    pub fn alloc(&mut self, src: &impl PageSource) -> Option<NonNull<u8>> {
        if self.partial.is_null() {
            let slab = if self.empty.is_null() { self.new_slab(src)? } else { core::mem::take(&mut self.empty) };
            // SAFETY: `slab` is a valid header of a slab this cache owns and is
            // on no list.
            unsafe { self.push_partial(slab) };
        }
        let s = self.partial;
        // SAFETY: Slabs on the partial list are valid and have a free object.
        unsafe {
            let obj = (*s).free;
            (*s).free = (*obj).next;
            (*s).in_use += 1;
            if (*s).free.is_null() {
                self.unlink_partial(s);
            }
            self.stats.objects_in_use += 1;
            Some(NonNull::new_unchecked(obj.cast()))
        }
    }

    /// Return an object to the cache.
    ///
    /// # Safety
    ///
    /// `p` must come from `alloc` on this cache with the same `src`, and must
    /// not be used afterwards.
    pub unsafe fn free(&mut self, p: NonNull<u8>, src: &impl PageSource) {
        let s = self.header_of(p.as_ptr());
        // SAFETY: `p` lies in a slab of this cache, so `s` is its header.
        unsafe {
            let was_full = (*s).free.is_null();
            let obj = p.as_ptr().cast::<FreeObject>();
            (*obj).next = (*s).free;
            (*s).free = obj;
            (*s).in_use -= 1;
            self.stats.objects_in_use -= 1;
            if was_full {
                self.push_partial(s);
            }
            if (*s).in_use == 0 {
                self.unlink_partial(s);
                if self.empty.is_null() {
                    self.empty = s;
                } else {
                    self.stats.slabs -= 1;
                    let base = NonNull::new_unchecked(self.base_of(s));
                    src.free_pages(base, self.order);
                }
            }
        }
    }

    fn new_slab(&mut self, src: &impl PageSource) -> Option<*mut SlabHeader> {
        let base = src.alloc_pages(self.order)?.as_ptr();
        let h = self.header_of(base);
        let mut free: *mut FreeObject = ptr::null_mut();
        // SAFETY: The page source handed us `slab_bytes` exclusive bytes; the
        // objects and the header at the end lie within them without overlap.
        unsafe {
            for i in (0..self.capacity()).rev() {
                let obj = base.add(i * self.size).cast::<FreeObject>();
                (*obj).next = free;
                free = obj;
            }
            h.write(SlabHeader { next: ptr::null_mut(), prev: ptr::null_mut(), free, in_use: 0 });
        }
        self.stats.slabs += 1;
        Some(h)
    }

    /// # Safety
    ///
    /// `s` must be a valid slab header of this cache that is on no list.
    unsafe fn push_partial(&mut self, s: *mut SlabHeader) {
        // SAFETY: Per the contract, and list members are valid headers.
        unsafe {
            (*s).prev = ptr::null_mut();
            (*s).next = self.partial;
            if !self.partial.is_null() {
                (*self.partial).prev = s;
            }
        }
        self.partial = s;
    }

    /// # Safety
    ///
    /// `s` must be on this cache's partial list.
    unsafe fn unlink_partial(&mut self, s: *mut SlabHeader) {
        // SAFETY: Per the contract, `s` and its neighbours are valid headers.
        unsafe {
            if (*s).prev.is_null() {
                self.partial = (*s).next;
            } else {
                (*(*s).prev).next = (*s).next;
            }
            if !(*s).next.is_null() {
                (*(*s).next).prev = (*s).prev;
            }
            (*s).next = ptr::null_mut();
            (*s).prev = ptr::null_mut();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{alloc, dealloc};
    use std::cell::Cell;
    use std::vec::Vec;

    #[derive(Default)]
    struct StdPages {
        live: Cell<isize>,
    }

    // SAFETY: Blocks come from the global allocator with the required size
    // and alignment.
    unsafe impl PageSource for StdPages {
        fn alloc_pages(&self, order: usize) -> Option<NonNull<u8>> {
            let l = Layout::from_size_align(PAGE_SIZE << order, PAGE_SIZE << order).unwrap();
            self.live.set(self.live.get() + 1);
            // SAFETY: The layout has a non-zero size.
            NonNull::new(unsafe { alloc(l) })
        }
        unsafe fn free_pages(&self, p: NonNull<u8>, order: usize) {
            let l = Layout::from_size_align(PAGE_SIZE << order, PAGE_SIZE << order).unwrap();
            self.live.set(self.live.get() - 1);
            // SAFETY: `p` came from `alloc` with this layout.
            unsafe { dealloc(p.as_ptr(), l) };
        }
    }

    #[test]
    fn class_selection() {
        assert_eq!(class_for(Layout::from_size_align(1, 1).unwrap()), Some(0));
        assert_eq!(class_for(Layout::from_size_align(17, 8).unwrap()), Some(1));
        assert_eq!(class_for(Layout::from_size_align(8, 256).unwrap()), Some(4));
        assert_eq!(class_for(Layout::from_size_align(2049, 8).unwrap()), None);
    }

    #[test]
    fn objects_are_aligned_distinct_and_recycled() {
        let src = StdPages::default();
        for &size in &CLASSES {
            let mut c = Cache::new(size, slab_order(size));
            let objs: Vec<_> = (0..100).map(|_| c.alloc(&src).unwrap()).collect();
            for o in &objs {
                assert_eq!(o.as_ptr() as usize % size, 0, "size {size} misaligned");
            }
            let mut addrs: Vec<usize> = objs.iter().map(|o| o.as_ptr() as usize).collect();
            addrs.sort();
            addrs.dedup();
            assert_eq!(addrs.len(), 100);
            for o in objs {
                // SAFETY: Allocated above from this cache.
                unsafe { c.free(o, &src) };
            }
            assert_eq!(c.stats().objects_in_use, 0);
            assert_eq!(c.stats().slabs, 1, "only the cached empty slab should remain");
        }
    }

    #[test]
    fn random_stress_with_patterns() {
        let src = StdPages::default();
        let mut caches: Vec<Cache> = CLASSES.iter().map(|&s| Cache::new(s, slab_order(s))).collect();
        let mut live: Vec<(usize, NonNull<u8>, u8)> = Vec::new();
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        for i in 0..200_000u32 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            if live.is_empty() || x % 5 < 3 {
                let class = (x >> 8) as usize % CLASSES.len();
                let p = caches[class].alloc(&src).unwrap();
                let tag = i as u8;
                // SAFETY: `p` points at an object of `CLASSES[class]` bytes.
                unsafe { ptr::write_bytes(p.as_ptr(), tag, CLASSES[class]) };
                live.push((class, p, tag));
            } else {
                let (class, p, tag) = live.swap_remove((x >> 16) as usize % live.len());
                // SAFETY: Each live object was filled with its tag and is
                // exclusively ours.
                let bytes = unsafe { core::slice::from_raw_parts(p.as_ptr(), CLASSES[class]) };
                assert!(bytes.iter().all(|&b| b == tag), "object of class {class} was overwritten");
                // SAFETY: Allocated from this cache.
                unsafe { caches[class].free(p, &src) };
            }
        }
        for (class, p, _) in live {
            // SAFETY: Allocated from this cache.
            unsafe { caches[class].free(p, &src) };
        }
        let slabs: usize = caches.iter().map(|c| c.stats().slabs).sum();
        assert!(slabs <= CLASSES.len());
        assert_eq!(src.live.get() as usize, slabs);
    }
}
