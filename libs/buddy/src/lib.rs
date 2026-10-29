// SPDX-License-Identifier: MIT OR Apache-2.0

//! A binary buddy allocator over page frame numbers.
//!
//! Free blocks of 2^order frames sit on one doubly linked list per order.
//! The list links live inside the free frames themselves (reached through a
//! [`LinkStore`]), so the only per-frame metadata is one byte: whether the
//! frame heads a free block, and of which order. That keeps the overhead at
//! one byte per 4 KiB frame.
//!
//! The allocator is not synchronized; the kernel wraps it in a lock.

#![no_std]

#[cfg(test)]
extern crate std;

/// Largest block order: 2^10 frames, 4 MiB with 4 KiB frames.
pub const MAX_ORDER: usize = 10;
const ORDERS: usize = MAX_ORDER + 1;

/// Marks a frame that heads a free block; the low bits hold the order.
const FREE_HEAD: u8 = 0x80;
const NIL: u64 = u64::MAX;

/// Free-list links stored in the first bytes of a free block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link {
    pub next: u64,
    pub prev: u64,
}

/// Storage for the links of free blocks, keyed by frame number.
///
/// The allocator only calls `read` on frames it previously passed to `write`,
/// and only while they are free; the kernel implements this with plain memory
/// accesses through the direct map.
pub trait LinkStore {
    fn read(&self, frame: u64) -> Link;
    fn write(&mut self, frame: u64, link: Link);
}

/// Errors from [`Buddy::free`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreeError {
    OutOfRange,
    Misaligned,
    BadOrder,
    AlreadyFree,
}

#[derive(Debug)]
pub struct Buddy<'m, S: LinkStore> {
    store: S,
    /// One byte per frame, frame numbers `0..meta.len()`.
    meta: &'m mut [u8],
    heads: [u64; ORDERS],
    counts: [usize; ORDERS],
    free_frames: u64,
}

impl<'m, S: LinkStore> Buddy<'m, S> {
    /// An allocator managing frames `0..meta.len()`, all initially unavailable.
    pub fn new(store: S, meta: &'m mut [u8]) -> Self {
        meta.fill(0);
        Buddy { store, meta, heads: [NIL; ORDERS], counts: [0; ORDERS], free_frames: 0 }
    }

    /// Number of free frames.
    pub fn free_frames(&self) -> u64 {
        self.free_frames
    }

    /// Number of free blocks of each order.
    pub fn free_blocks(&self) -> [usize; ORDERS] {
        self.counts
    }

    /// Number of frames covered (`meta.len()`).
    pub fn frame_limit(&self) -> u64 {
        self.meta.len() as u64
    }

    /// Make `count` frames starting at `start` available. The range must not
    /// overlap frames already free or handed out.
    pub fn add_range(&mut self, start: u64, count: u64) {
        let end = (start + count).min(self.frame_limit());
        let mut f = start;
        while f < end {
            let mut order = MAX_ORDER;
            while order > 0 && (f & ((1 << order) - 1) != 0 || f + (1 << order) > end) {
                order -= 1;
            }
            self.release(f, order);
            f += 1 << order;
        }
    }

    /// Allocate an aligned block of 2^order frames; returns its first frame.
    pub fn alloc(&mut self, order: usize) -> Option<u64> {
        if order > MAX_ORDER {
            return None;
        }
        let mut o = (order..ORDERS).find(|&o| self.heads[o] != NIL)?;
        let frame = self.heads[o];
        self.unlink(frame, o);
        // Split, returning the upper halves to their lists.
        while o > order {
            o -= 1;
            self.push(frame + (1 << o), o);
        }
        self.free_frames -= 1 << order;
        Some(frame)
    }

    /// Allocate an aligned block of 2^order frames that ends at or below
    /// frame `limit` (for devices that address memory with fewer bits).
    /// Walks the free lists, so it is slower than [`Buddy::alloc`].
    pub fn alloc_below(&mut self, order: usize, limit: u64) -> Option<u64> {
        if order > MAX_ORDER {
            return None;
        }
        for o in order..ORDERS {
            let mut f = self.heads[o];
            while f != NIL {
                if f + (1 << order) <= limit {
                    self.unlink(f, o);
                    let mut oo = o;
                    while oo > order {
                        oo -= 1;
                        self.push(f + (1 << oo), oo);
                    }
                    self.free_frames -= 1 << order;
                    return Some(f);
                }
                f = self.store.read(f).next;
            }
        }
        None
    }

    /// Return a block from [`Buddy::alloc`] with the same order.
    pub fn free(&mut self, frame: u64, order: usize) -> Result<(), FreeError> {
        if order > MAX_ORDER {
            return Err(FreeError::BadOrder);
        }
        if frame + (1 << order) > self.frame_limit() {
            return Err(FreeError::OutOfRange);
        }
        if frame & ((1 << order) - 1) != 0 {
            return Err(FreeError::Misaligned);
        }
        if self.meta[frame as usize] & FREE_HEAD != 0 {
            return Err(FreeError::AlreadyFree);
        }
        self.release(frame, order);
        Ok(())
    }

    /// Put a block back, merging with free buddies.
    fn release(&mut self, mut frame: u64, mut order: usize) {
        self.free_frames += 1 << order;
        while order < MAX_ORDER {
            let buddy = frame ^ (1 << order);
            if buddy + (1 << order) > self.frame_limit() || self.meta[buddy as usize] != FREE_HEAD | order as u8 {
                break;
            }
            self.unlink(buddy, order);
            frame = frame.min(buddy);
            order += 1;
        }
        self.push(frame, order);
    }

    fn push(&mut self, frame: u64, order: usize) {
        let head = self.heads[order];
        if head != NIL {
            let mut l = self.store.read(head);
            l.prev = frame;
            self.store.write(head, l);
        }
        self.store.write(frame, Link { next: head, prev: NIL });
        self.heads[order] = frame;
        self.meta[frame as usize] = FREE_HEAD | order as u8;
        self.counts[order] += 1;
    }

    fn unlink(&mut self, frame: u64, order: usize) {
        let l = self.store.read(frame);
        if l.prev == NIL {
            self.heads[order] = l.next;
        } else {
            let mut p = self.store.read(l.prev);
            p.next = l.next;
            self.store.write(l.prev, p);
        }
        if l.next != NIL {
            let mut n = self.store.read(l.next);
            n.prev = l.prev;
            self.store.write(l.next, n);
        }
        self.meta[frame as usize] = 0;
        self.counts[order] -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::vec;
    use std::vec::Vec;

    #[derive(Default)]
    struct MapStore(HashMap<u64, Link>);

    impl LinkStore for MapStore {
        fn read(&self, frame: u64) -> Link {
            *self.0.get(&frame).expect("read of a frame that was never linked")
        }
        fn write(&mut self, frame: u64, link: Link) {
            self.0.insert(frame, link);
        }
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn add_range_builds_maximal_blocks() {
        let mut meta = vec![0u8; 4096];
        let mut b = Buddy::new(MapStore::default(), &mut meta);
        b.add_range(0, 4096);
        assert_eq!(b.free_frames(), 4096);
        assert_eq!(b.free_blocks()[MAX_ORDER], 4);
        // An unaligned range splits into aligned pieces.
        let mut meta = vec![0u8; 64];
        let mut b = Buddy::new(MapStore::default(), &mut meta);
        b.add_range(3, 13); // 3, 4..8, 8..16
        assert_eq!(b.free_frames(), 13);
        assert_eq!(b.free_blocks()[0..4], [1, 0, 1, 1]);
    }

    #[test]
    fn alloc_below_a_limit() {
        let mut meta = vec![0u8; 4096];
        let mut b = Buddy::new(MapStore::default(), &mut meta);
        b.add_range(2048, 2048);
        assert_eq!(b.alloc_below(2, 2048), None);
        b.add_range(0, 2048);
        // Plain allocation takes the most recently freed block (high);
        // alloc_below finds a low one, split to size.
        let f = b.alloc_below(2, 1024).unwrap();
        assert!(f + 4 <= 1024 && f % 4 == 0);
        assert_eq!(b.free_frames(), 4096 - 4);
        b.free(f, 2).unwrap();
        assert_eq!(b.free_frames(), 4096);
        assert_eq!(b.free_blocks()[MAX_ORDER], 4, "everything merged back");
    }

    #[test]
    fn alloc_is_aligned_and_exhausts() {
        let mut meta = vec![0u8; 1024];
        let mut b = Buddy::new(MapStore::default(), &mut meta);
        b.add_range(0, 1024);
        let mut got = Vec::new();
        while let Some(f) = b.alloc(3) {
            assert_eq!(f % 8, 0);
            got.push(f);
        }
        assert_eq!(got.len(), 128);
        assert_eq!(b.free_frames(), 0);
        got.sort();
        got.dedup();
        assert_eq!(got.len(), 128, "blocks handed out twice");
        for f in got {
            b.free(f, 3).unwrap();
        }
        assert_eq!(b.free_frames(), 1024);
        assert_eq!(b.free_blocks()[MAX_ORDER], 1, "freed blocks did not coalesce");
    }

    #[test]
    fn rejects_bad_frees() {
        let mut meta = vec![0u8; 64];
        let mut b = Buddy::new(MapStore::default(), &mut meta);
        b.add_range(0, 64);
        let f = b.alloc(2).unwrap();
        assert_eq!(b.free(f + 1, 2), Err(FreeError::Misaligned));
        assert_eq!(b.free(64, 0), Err(FreeError::OutOfRange));
        b.free(f, 2).unwrap();
        assert_eq!(b.free(0, 6), Err(FreeError::AlreadyFree));
    }

    #[test]
    fn random_stress_restores_state() {
        const FRAMES: u64 = 1 << 14;
        let mut meta = vec![0u8; FRAMES as usize];
        let mut b = Buddy::new(MapStore::default(), &mut meta);
        // Leave holes so blocks cannot all merge.
        b.add_range(1, FRAMES / 2 - 1);
        b.add_range(FRAMES / 2 + 7, FRAMES / 2 - 7);
        let initial_free = b.free_frames();
        let initial_blocks = b.free_blocks();

        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut live: Vec<(u64, usize)> = Vec::new();
        let mut owner = vec![false; FRAMES as usize];
        for _ in 0..50_000 {
            if live.is_empty() || !rng.next().is_multiple_of(3) {
                let order = (rng.next() % 6) as usize;
                if let Some(f) = b.alloc(order) {
                    for i in f..f + (1 << order) {
                        assert!(!owner[i as usize], "frame {i} allocated twice");
                        owner[i as usize] = true;
                    }
                    live.push((f, order));
                }
            } else {
                let (f, order) = live.swap_remove((rng.next() % live.len() as u64) as usize);
                for i in f..f + (1 << order) {
                    owner[i as usize] = false;
                }
                b.free(f, order).unwrap();
            }
        }
        for (f, order) in live.drain(..) {
            b.free(f, order).unwrap();
        }
        assert_eq!(b.free_frames(), initial_free);
        assert_eq!(b.free_blocks(), initial_blocks);
    }
}
