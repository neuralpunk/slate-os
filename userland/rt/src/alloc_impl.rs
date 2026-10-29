// SPDX-License-Identifier: MIT OR Apache-2.0

//! The memory allocator, hardened (ADR 0094). Every Slate program uses it,
//! through Rust's allocation and through slate-libc's `malloc`.
//!
//! - Size classes of 16 to 2048 bytes live in 64 KiB slabs, one class per
//!   slab, 64 KiB-aligned. Nothing about the heap is kept next to the
//!   blocks: each slab's bitmap of used blocks, and the table that finds
//!   a slab from a pointer, are in mappings of their own. A write past a
//!   block or into a freed one cannot redirect the allocator.
//! - A block is picked at random among the slab's free ones, so where the
//!   next block lands cannot be predicted from the last.
//! - Freeing checks the pointer: one the allocator did not hand out, one
//!   freed twice, or one freed with the wrong size stops the program
//!   with a message (SIGABRT). Freed blocks are cleared.
//! - Larger blocks get their own mapping between two unmapped guard
//!   pages, placed at its end, so running off a block faults at once.
//! - A program that frees and allocates large blocks all the time (a
//!   desktop drawing frames) may keep some of the freed mappings for
//!   reuse ([`keep_freed`], ADR 0094's addendum): mapping, faulting in and
//!   unmapping them again (with every CPU's TLB) cost more than clearing
//!   them. A kept block is cleared when freed and keeps its guards; only
//!   a write to it after the free goes unnoticed.
//! - Every block handed out is zero (new mappings are, and freed blocks
//!   are cleared), so `alloc_zeroed` writes nothing.
//!
//! One lock covers it all (threads sleep on it, ADR 0073).

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::sync::Mutex;
use crate::sys;

const CLASSES: usize = 8; // 16, 32, ..., 2048
const SLAB: usize = 64 * 1024;
const PAGE: usize = 4096;
/// Bitmap words per slab: enough for 16-byte blocks.
const WORDS: usize = SLAB / 16 / 64;
const NONE: u32 = u32::MAX;
/// The most freed large mappings kept, and the largest kept.
const KEPT_MAX: usize = 16;
const KEPT_BLOCK_MAX: usize = 32 << 20;

/// How many bytes of freed large mappings the program keeps for reuse.
static KEEP: AtomicUsize = AtomicUsize::new(0);

/// Keep up to `bytes` of freed large blocks' mappings for reuse (0, the
/// default, unmaps each at once). For programs that draw frames: Strata
/// and its apps.
pub fn keep_freed(bytes: usize) {
    KEEP.store(bytes, Ordering::Relaxed);
}

fn class_of(size: usize) -> Option<usize> {
    let size = size.max(16).next_power_of_two();
    let c = size.trailing_zeros() as usize - 4;
    (c < CLASSES).then_some(c)
}

fn block_of(class: usize) -> usize {
    16 << class
}

/// Blocks in a slab of `class`.
fn blocks(class: usize) -> usize {
    SLAB / block_of(class)
}

fn map(len: usize) -> *mut u8 {
    map_prot(len, 3)
}

/// Anonymous private memory with `prot`: PROT_READ|PROT_WRITE is 3 and
/// PROT_NONE 0 in both interfaces; MAP_PRIVATE|MAP_ANONYMOUS (musl
/// sys/mman.h; slate-abi's map flags natively).
fn map_prot(len: usize, prot: usize) -> *mut u8 {
    let flags = if sys::native() { slate_abi::map::PRIVATE | slate_abi::map::ANONYMOUS } else { 0x22 };
    match crate::syscall!(sys::pick(sys::MMAP, slate_abi::nr::MAP), 0, len, prot, flags, usize::MAX, 0) {
        Ok(p) => p as *mut u8,
        Err(_) => null_mut(),
    }
}

fn unmap(p: *mut u8, len: usize) {
    let _ = crate::syscall!(sys::pick(sys::MUNMAP, slate_abi::nr::UNMAP), p, len);
}

/// Make `[p, p + len)` readable and writable.
fn open_up(p: *mut u8, len: usize) -> bool {
    crate::syscall!(sys::pick(sys::MPROTECT, slate_abi::nr::PROTECT), p, len, 3).is_ok()
}

/// What a bad free was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Not a block the allocator handed out (or not its start).
    Unknown,
    /// A block that is already free.
    DoubleFree,
    /// Freed with a size of another class than it was allocated with.
    WrongSize,
}

impl Fault {
    fn message(self) -> &'static [u8] {
        match self {
            Fault::Unknown => b": heap corruption: freeing memory the allocator did not hand out\n",
            Fault::DoubleFree => b": heap corruption: freeing a block twice\n",
            Fault::WrongSize => b": heap corruption: freeing a block with the wrong size\n",
        }
    }
}

/// A slab's own record, kept away from its blocks.
#[derive(Clone, Copy)]
struct Slab {
    base: usize,
    class: u8,
    used: u16,
    /// The partial list of its class (slabs with a free block).
    prev: u32,
    next: u32,
    bits: [u64; WORDS],
}

/// The table from addresses to blocks: a slab's base, or a large block's
/// pointer (with its mapping).
#[derive(Clone, Copy)]
struct Entry {
    /// 0 empty, 1 removed.
    key: usize,
    /// A slab's index, or a large block's mapping.
    start: usize,
    /// 0 for a slab; a large block's mapping's length.
    len: usize,
}

const EMPTY: usize = 0;
const REMOVED: usize = 1;

struct State {
    seed: u64,
    slabs: *mut Slab,
    slab_cap: usize,
    slab_len: usize,
    /// Records of unmapped slabs, through `next`.
    free_records: u32,
    partial: [u32; CLASSES],
    /// Empty slabs kept per class (one is; more are unmapped).
    spare: [u8; CLASSES],
    table: *mut Entry,
    table_cap: usize,
    table_used: usize,
    /// Freed large mappings kept (start, length), oldest first.
    kept: [(usize, usize); KEPT_MAX],
    kept_n: usize,
    kept_bytes: usize,
    /// This allocator's own limit, over [`KEEP`] (tests).
    keep: Option<usize>,
}

// SAFETY: The pointers are the allocator's own mappings, reached only with
// the lock held.
unsafe impl Send for State {}

impl State {
    const fn new() -> State {
        State {
            seed: 0,
            slabs: null_mut(),
            slab_cap: 0,
            slab_len: 0,
            free_records: NONE,
            partial: [NONE; CLASSES],
            spare: [0; CLASSES],
            table: null_mut(),
            table_cap: 0,
            table_used: 0,
            kept: [(0, 0); KEPT_MAX],
            kept_n: 0,
            kept_bytes: 0,
            keep: None,
        }
    }

    fn random(&mut self) -> u64 {
        if self.seed == 0 {
            let mut b = [0u8; 8];
            let _ = crate::process::random(&mut b);
            self.seed = u64::from_le_bytes(b) | 1;
        }
        // xorshift64* (Vigna, "An experimental exploration of Marsaglia's
        // xorshift generators").
        self.seed ^= self.seed >> 12;
        self.seed ^= self.seed << 25;
        self.seed ^= self.seed >> 27;
        self.seed.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn slab(&mut self, i: u32) -> &mut Slab {
        // SAFETY: Indexes in use are below `slab_len`, inside the records'
        // mapping.
        unsafe { &mut *self.slabs.add(i as usize) }
    }

    // --- the table -----------------------------------------------------

    fn slot(&self, key: usize) -> usize {
        (key >> 12).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> (64 - self.table_cap.trailing_zeros())
    }

    fn entry(&self, i: usize) -> Entry {
        // SAFETY: `i` is masked to the table's capacity.
        unsafe { *self.table.add(i) }
    }

    fn set_entry(&mut self, i: usize, e: Entry) {
        // SAFETY: As in `entry`.
        unsafe { *self.table.add(i) = e }
    }

    fn find(&self, key: usize) -> Option<usize> {
        if self.table_cap == 0 {
            return None;
        }
        let mut i = self.slot(key);
        loop {
            match self.entry(i).key {
                EMPTY => return None,
                k if k == key => return Some(i),
                _ => i = (i + 1) & (self.table_cap - 1),
            }
        }
    }

    fn insert(&mut self, e: Entry) -> bool {
        if (self.table_used + 1) * 2 > self.table_cap && !self.grow_table() {
            return false;
        }
        let mut i = self.slot(e.key);
        while self.entry(i).key > REMOVED {
            i = (i + 1) & (self.table_cap - 1);
        }
        if self.entry(i).key == EMPTY {
            self.table_used += 1;
        }
        self.set_entry(i, e);
        true
    }

    fn remove(&mut self, i: usize) {
        self.set_entry(i, Entry { key: REMOVED, start: 0, len: 0 });
    }

    /// Rebuild the table twice as large (removed entries go).
    fn grow_table(&mut self) -> bool {
        let cap = (self.table_cap * 2).max(256);
        let bytes = (cap * size_of::<Entry>()).next_multiple_of(PAGE);
        let new = map(bytes) as *mut Entry;
        if new.is_null() {
            return false;
        }
        let (old, old_cap) = (self.table, self.table_cap);
        (self.table, self.table_cap, self.table_used) = (new, cap, 0);
        for i in 0..old_cap {
            // SAFETY: The old table's entries, below its capacity.
            let e = unsafe { *old.add(i) };
            if e.key > REMOVED {
                let mut j = self.slot(e.key);
                while self.entry(j).key != EMPTY {
                    j = (j + 1) & (cap - 1);
                }
                self.set_entry(j, e);
                self.table_used += 1;
            }
        }
        if !old.is_null() {
            unmap(old as *mut u8, (old_cap * size_of::<Entry>()).next_multiple_of(PAGE));
        }
        true
    }

    // --- slabs ---------------------------------------------------------

    fn new_record(&mut self) -> Option<u32> {
        if self.free_records != NONE {
            let i = self.free_records;
            self.free_records = self.slab(i).next;
            return Some(i);
        }
        if self.slab_len == self.slab_cap {
            let cap = (self.slab_cap * 2).max(64);
            let new = map((cap * size_of::<Slab>()).next_multiple_of(PAGE)) as *mut Slab;
            if new.is_null() {
                return None;
            }
            if !self.slabs.is_null() {
                // SAFETY: Both mappings hold at least `slab_len` records.
                unsafe { core::ptr::copy_nonoverlapping(self.slabs, new, self.slab_len) };
                unmap(self.slabs as *mut u8, (self.slab_cap * size_of::<Slab>()).next_multiple_of(PAGE));
            }
            (self.slabs, self.slab_cap) = (new, cap);
        }
        self.slab_len += 1;
        Some(self.slab_len as u32 - 1)
    }

    /// A fresh slab of `class`, at the head of its partial list.
    fn new_slab(&mut self, class: usize) -> Option<u32> {
        // A 64 KiB-aligned 64 KiB: map twice that and trim.
        let raw = map(2 * SLAB);
        if raw.is_null() {
            return None;
        }
        let base = (raw as usize).next_multiple_of(SLAB);
        let head = base - raw as usize;
        if head > 0 {
            unmap(raw, head);
        }
        if SLAB - head > 0 {
            unmap((base + SLAB) as *mut u8, SLAB - head);
        }
        let Some(i) = self.new_record() else {
            unmap(base as *mut u8, SLAB);
            return None;
        };
        let head_of_list = self.partial[class];
        *self.slab(i) = Slab { base, class: class as u8, used: 0, prev: NONE, next: head_of_list, bits: [0; WORDS] };
        if head_of_list != NONE {
            self.slab(head_of_list).prev = i;
        }
        self.partial[class] = i;
        if !self.insert(Entry { key: base, start: i as usize, len: 0 }) {
            self.unlink(i);
            self.drop_slab(i);
            return None;
        }
        self.spare[class] += 1;
        Some(i)
    }

    fn unlink(&mut self, i: u32) {
        let (prev, next, class) = { (self.slab(i).prev, self.slab(i).next, self.slab(i).class as usize) };
        if prev == NONE {
            self.partial[class] = next;
        } else {
            self.slab(prev).next = next;
        }
        if next != NONE {
            self.slab(next).prev = prev;
        }
        let s = self.slab(i);
        (s.prev, s.next) = (NONE, NONE);
    }

    fn push_partial(&mut self, i: u32) {
        let class = self.slab(i).class as usize;
        let head = self.partial[class];
        let s = self.slab(i);
        (s.prev, s.next) = (NONE, head);
        if head != NONE {
            self.slab(head).prev = i;
        }
        self.partial[class] = i;
    }

    /// Unmap a slab that is off every list and free its record.
    fn drop_slab(&mut self, i: u32) {
        let base = self.slab(i).base;
        unmap(base as *mut u8, SLAB);
        if let Some(e) = self.find(base) {
            self.remove(e);
        }
        let head = self.free_records;
        self.slab(i).next = head;
        self.free_records = i;
    }

    fn alloc_small(&mut self, class: usize) -> *mut u8 {
        let i = match self.partial[class] {
            NONE => match self.new_slab(class) {
                Some(i) => i,
                None => return null_mut(),
            },
            i => i,
        };
        let n = blocks(class);
        let words = n.div_ceil(64);
        let r = self.random();
        let s = self.slab(i);
        // A random free block: from a random word on, the first with one,
        // and in it the first free bit from a random place.
        let start = (r as usize) % words;
        let mut slot = None;
        for k in 0..words {
            let w = (start + k) % words;
            let valid = if (w + 1) * 64 <= n { u64::MAX } else { (1u64 << (n - w * 64)) - 1 };
            let free = !s.bits[w] & valid;
            if free != 0 {
                let rot = ((r >> 32) % 64) as u32;
                let bit = (free.rotate_right(rot).trailing_zeros() + rot) % 64;
                slot = Some(w * 64 + bit as usize);
                break;
            }
        }
        let Some(slot) = slot else { return null_mut() };
        s.bits[slot / 64] |= 1 << (slot % 64);
        s.used += 1;
        let (used, base) = (s.used as usize, s.base);
        if used == 1 {
            self.spare[class] -= 1;
        }
        if used == n {
            self.unlink(i);
        }
        (base + slot * block_of(class)) as *mut u8
    }

    /// Free `p`, checking it against what the caller says it was
    /// (`expect`: None from C's free, which does not say; else its class,
    /// None for a large block).
    fn free_small(&mut self, i: u32, p: usize, expect: Option<Option<usize>>) -> Result<(), Fault> {
        let s = self.slab(i);
        let c = s.class as usize;
        if expect.is_some_and(|k| k != Some(c)) {
            return Err(Fault::WrongSize);
        }
        let block = block_of(c);
        let off = p - s.base;
        if off % block != 0 {
            return Err(Fault::Unknown);
        }
        let slot = off / block;
        if s.bits[slot / 64] & (1 << (slot % 64)) == 0 {
            return Err(Fault::DoubleFree);
        }
        // SAFETY: A used block of this slab, `block` bytes long.
        unsafe { core::ptr::write_bytes(p as *mut u8, 0, block) };
        s.bits[slot / 64] &= !(1 << (slot % 64));
        s.used -= 1;
        let used = s.used as usize;
        if used + 1 == blocks(c) {
            self.push_partial(i);
        }
        if used == 0 {
            if self.spare[c] >= 1 {
                self.unlink(i);
                self.drop_slab(i);
            } else {
                self.spare[c] += 1;
            }
        }
        Ok(())
    }

    // --- large blocks --------------------------------------------------

    fn alloc_large(&mut self, size: usize, align: usize) -> *mut u8 {
        let pages = size.next_multiple_of(PAGE);
        let need = pages + 2 * PAGE;
        let (start, len) = match self.take_kept(need) {
            Some(m) => m,
            None => {
                // All of it inaccessible, then the middle opened: guards
                // below and above, and the block ends where the upper one
                // starts.
                let start = map_prot(need, 0);
                if start.is_null() {
                    return null_mut();
                }
                if !open_up((start as usize + PAGE) as *mut u8, pages) {
                    unmap(start, need);
                    return null_mut();
                }
                (start as usize, need)
            }
        };
        let end = start + len;
        let p = (end - PAGE - size) & !(align - 1);
        if !self.insert(Entry { key: p, start, len }) {
            unmap(start as *mut u8, len);
            return null_mut();
        }
        p as *mut u8
    }

    /// Free any block, checking it (`expect` as for `free_small`).
    fn free(&mut self, p: usize, expect: Option<Option<usize>>) -> Result<(), Fault> {
        if let Some(e) = self.find(p & !(SLAB - 1))
            && self.entry(e).len == 0
        {
            let i = self.entry(e).start as u32;
            return self.free_small(i, p, expect);
        }
        let e = self.find(p).ok_or(Fault::Unknown)?;
        if expect.is_some_and(|k| k.is_some()) {
            return Err(Fault::WrongSize);
        }
        let Entry { start, len, .. } = self.entry(e);
        self.remove(e);
        self.keep_or_unmap(start, len);
        Ok(())
    }

    /// The best kept mapping for a block needing `len` bytes with its
    /// guards: one at most a quarter larger (a larger one would hold
    /// pages for nothing).
    fn take_kept(&mut self, len: usize) -> Option<(usize, usize)> {
        let i = (0..self.kept_n)
            .filter(|&i| self.kept[i].1 >= len && self.kept[i].1 <= len + len / 4)
            .min_by_key(|&i| self.kept[i].1)?;
        let m = self.kept[i];
        self.kept.copy_within(i + 1..self.kept_n, i);
        self.kept_n -= 1;
        self.kept_bytes -= m.1;
        Some(m)
    }

    /// A freed large block's mapping: cleared and kept for reuse when the
    /// program keeps some (oldest dropped to make room), else unmapped.
    fn keep_or_unmap(&mut self, start: usize, len: usize) {
        let keep = self.keep.unwrap_or_else(|| KEEP.load(Ordering::Relaxed));
        if len > keep || len > KEPT_BLOCK_MAX {
            unmap(start as *mut u8, len);
            return;
        }
        // SAFETY: The opened middle of the block's own mapping, between its
        // guards; the block has just been freed.
        unsafe { core::ptr::write_bytes((start + PAGE) as *mut u8, 0, len - 2 * PAGE) };
        while self.kept_n > 0 && (self.kept_n == KEPT_MAX || self.kept_bytes + len > keep) {
            let (s, l) = self.kept[0];
            self.kept.copy_within(1..self.kept_n, 0);
            self.kept_n -= 1;
            self.kept_bytes -= l;
            unmap(s as *mut u8, l);
        }
        self.kept[self.kept_n] = (start, len);
        self.kept_n += 1;
        self.kept_bytes += len;
    }

    /// The bytes usable at `p`.
    fn usable(&self, p: usize) -> Option<usize> {
        if let Some(e) = self.find(p & !(SLAB - 1))
            && self.entry(e).len == 0
        {
            // SAFETY: The entry's slab record is in use.
            let class = unsafe { (*self.slabs.add(self.entry(e).start)).class };
            return Some(block_of(class as usize));
        }
        let e = self.entry(self.find(p)?);
        Some(e.start + e.len - PAGE - p)
    }
}

/// Stop the program over a bad free: a message, then SIGABRT. Nothing
/// here allocates.
fn fatal(f: Fault) -> ! {
    let _ = crate::io::write(2, b"slate-rt");
    let _ = crate::io::write(2, f.message());
    let _ = crate::signal::set(crate::signal::SIGABRT, crate::signal::Disposition::Default);
    let _ = crate::process::kill(crate::process::getpid(), crate::signal::SIGABRT);
    crate::process::exit_now(134)
}

#[derive(Debug)]
pub struct Allocator {
    state: Mutex<State>,
}

impl core::fmt::Debug for State {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "State({} slabs)", self.slab_len)
    }
}

impl Allocator {
    pub const fn new() -> Allocator {
        Allocator { state: Mutex::new(State::new()) }
    }

    /// An allocator keeping up to `bytes` of freed large blocks, whatever
    /// [`keep_freed`] says.
    pub fn keeping(bytes: usize) -> Allocator {
        let a = Allocator::new();
        a.state.lock().keep = Some(bytes);
        a
    }

    /// Free `p` (allocated with `layout`; None from C's `free`), or report
    /// what is wrong with it.
    pub fn release(&self, p: *mut u8, layout: Option<Layout>) -> Result<(), Fault> {
        let expect = layout.map(|l| class_of(l.size().max(l.align())));
        self.state.lock().free(p as usize, expect)
    }

    /// The bytes usable at `p` (`malloc_usable_size`); None for a pointer
    /// it did not hand out.
    pub fn usable_size(&self, p: *mut u8) -> Option<usize> {
        self.state.lock().usable(p as usize)
    }

    /// Free `p` with no size, stopping the program if it is bad.
    ///
    /// # Safety
    ///
    /// None needed for memory safety: a bad pointer is caught. Only the
    /// block must not be used after.
    pub unsafe fn free_unsized(&self, p: *mut u8) {
        if let Err(f) = self.release(p, None) {
            fatal(f)
        }
    }
}

impl Default for Allocator {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: Blocks are handed out once and only reused after `dealloc`; the
// state is protected by the lock; frees are checked.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size().max(layout.align());
        if layout.align() > PAGE {
            return null_mut();
        }
        let mut s = self.state.lock();
        match class_of(size) {
            Some(c) => s.alloc_small(c),
            None => s.alloc_large(layout.size(), layout.align()),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Err(f) = self.release(ptr, Some(layout)) {
            fatal(f)
        }
    }

    /// Every block is handed out zero: nothing to write.
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: As `alloc`'s.
        unsafe { self.alloc(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let old = layout.size().max(layout.align());
        // Same class: keep the block.
        if let (Some(a), Some(b)) = (class_of(old), class_of(new_size.max(layout.align())))
            && a == b
        {
            return ptr;
        }
        // SAFETY: Allocate, copy the smaller size, free the old block.
        unsafe {
            let new = self.alloc(Layout::from_size_align_unchecked(new_size, layout.align()));
            if !new.is_null() {
                core::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
            new
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn l(size: usize, align: usize) -> Layout {
        Layout::from_size_align(size, align).unwrap()
    }

    #[test]
    fn blocks_are_distinct_aligned_and_cleared() {
        let a = Allocator::new();
        let mut live = alloc::vec::Vec::new();
        for i in 0..5000usize {
            let size = [1, 16, 24, 100, 700, 2048, 3000, 70_000][i % 8];
            let align = [1, 8, 16, 64][i % 4];
            // SAFETY: Non-zero sizes.
            let p = unsafe { a.alloc(l(size, align)) };
            assert!(!p.is_null() && p as usize % align == 0);
            // SAFETY: `size` bytes are ours.
            unsafe {
                assert!((0..size).all(|k| *p.add(k) == 0), "not cleared");
                core::ptr::write_bytes(p, 0xA5, size);
            }
            live.push((p, size, align));
        }
        let mut addrs: alloc::vec::Vec<usize> = live.iter().map(|x| x.0 as usize).collect();
        addrs.sort_unstable();
        addrs.dedup();
        assert_eq!(addrs.len(), live.len());
        for (p, size, align) in live {
            // SAFETY: Allocated above with this layout.
            unsafe { a.dealloc(p, l(size, align)) };
        }
    }

    #[test]
    fn bad_frees_are_caught() {
        let a = Allocator::new();
        // SAFETY: Non-zero sizes.
        let (small, large) = unsafe { (a.alloc(l(40, 8)), a.alloc(l(10_000, 8))) };
        assert_eq!(a.release(small.wrapping_add(8), None), Err(Fault::Unknown));
        assert_eq!(a.release(small, Some(l(200, 8))), Err(Fault::WrongSize));
        assert_eq!(a.release(small, Some(l(40, 8))), Ok(()));
        assert_eq!(a.release(small, None), Err(Fault::DoubleFree));
        assert_eq!(a.usable_size(large), Some(10_000));
        assert_eq!(a.release(large.wrapping_add(16), None), Err(Fault::Unknown));
        assert_eq!(a.release(large, None), Ok(()));
        assert_eq!(a.release(large, None), Err(Fault::Unknown));
        let mut x = 0u8;
        assert_eq!(a.release(&mut x, None), Err(Fault::Unknown));
    }

    #[test]
    fn placement_is_random() {
        // Two allocators place their first blocks differently (16 bytes in
        // 4096 slots: the same offset by chance once in 4096).
        let (a, b) = (Allocator::new(), Allocator::new());
        let mut same = 0;
        for _ in 0..8 {
            // SAFETY: Non-zero sizes.
            let (p, q) = unsafe { (a.alloc(l(16, 16)), b.alloc(l(16, 16))) };
            same += usize::from(p as usize % SLAB == q as usize % SLAB);
        }
        assert!(same < 4);
    }

    #[test]
    fn empty_slabs_go_back() {
        let a = Allocator::new();
        let mut ps = alloc::vec::Vec::new();
        for _ in 0..3 * blocks(7) {
            // SAFETY: Non-zero size.
            ps.push(unsafe { a.alloc(l(2048, 16)) });
        }
        for p in ps {
            // SAFETY: Allocated above with this layout.
            unsafe { a.dealloc(p, l(2048, 16)) };
        }
        let s = a.state.lock();
        // One empty slab is kept; the others' records are free.
        let mut free = 0;
        let mut i = s.free_records;
        while i != NONE {
            free += 1;
            // SAFETY: A free record's link.
            i = unsafe { (*s.slabs.add(i as usize)).next };
        }
        assert_eq!(free, 2);
    }

    #[test]
    fn freed_large_blocks_are_kept_cleared() {
        let a = Allocator::keeping(1 << 20);
        // SAFETY: Non-zero sizes; each block is used within its size, and
        // freed with the layout it was allocated with.
        unsafe {
            let p = a.alloc(l(100_000, 8));
            core::ptr::write_bytes(p, 0x5A, 100_000);
            a.dealloc(p, l(100_000, 8));
            assert_eq!(a.state.lock().kept_n, 1);
            // The same size again: the same mapping, cleared, at its guard.
            let q = a.alloc_zeroed(l(100_000, 8));
            assert_eq!(q, p);
            assert!((0..100_000).all(|k| *q.add(k) == 0));
            a.dealloc(q, l(100_000, 8));
            // A little smaller fits it too (a quarter at most), ending at
            // the guard; much smaller doesn't.
            let r = a.alloc(l(90_000, 8));
            assert_eq!(r as usize + 90_000, p as usize + 100_000);
            assert_eq!(a.state.lock().kept_n, 0);
            a.dealloc(r, l(90_000, 8));
            let t = a.alloc(l(10_000, 8));
            assert_eq!(a.state.lock().kept_n, 1);
            a.dealloc(t, l(10_000, 8));
            // Past the limit, the oldest go.
            let big: alloc::vec::Vec<*mut u8> = (0..20).map(|_| a.alloc(l(200_000, 8))).collect();
            for b in big {
                a.dealloc(b, l(200_000, 8));
            }
            let s = a.state.lock();
            assert!(s.kept_bytes <= 1 << 20 && s.kept_n <= KEPT_MAX && s.kept_n >= 4);
        }
        // Without keeping, nothing is.
        let b = Allocator::keeping(0);
        // SAFETY: As above.
        unsafe {
            let p = b.alloc(l(100_000, 8));
            b.dealloc(p, l(100_000, 8));
        }
        assert_eq!(b.state.lock().kept_n, 0);
    }

    #[test]
    fn large_blocks_end_at_a_guard() {
        let a = Allocator::new();
        // SAFETY: Non-zero size.
        let p = unsafe { a.alloc(l(5000, 8)) };
        let end = p as usize + 5000;
        assert_eq!(end % PAGE, 0, "the block does not end at the guard page");
        // SAFETY: Allocated above.
        unsafe { a.dealloc(p, l(5000, 8)) };
    }
}
