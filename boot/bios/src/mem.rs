// SPDX-License-Identifier: MIT OR Apache-2.0

//! The loader's memory on BIOS (ADR 0089): the largest usable range of the
//! memory map between 1 MiB and 4 GiB (inside the boot tables' one-to-one
//! map). The loader's data and its heap grow up from the bottom, the
//! kernel and the modules down from the top, and pages below 1 MiB come
//! from 0x70000 to 0x80000. Nothing is freed.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use slate_loader::boot::{Kind, Memory};
use slate_loader::memmap::Region;
use slate_loader::paging::PAGE;
use slate_loader::proto::memtype;

static LOW_START: AtomicU64 = AtomicU64::new(0);
static LOW: AtomicU64 = AtomicU64::new(0);
static HIGH: AtomicU64 = AtomicU64::new(0);
static HIGH_END: AtomicU64 = AtomicU64::new(0);
static UNDER_1M: AtomicU64 = AtomicU64::new(0x7_0000);
const UNDER_1M_END: u64 = 0x8_0000;
/// The heap's allocations go to the kernel's memory (a module read
/// straight into its place).
static FOR_KERNEL: AtomicBool = AtomicBool::new(false);

/// Take the largest usable range between 1 MiB and 4 GiB.
pub fn init(map: &[Region]) -> Result<(), &'static str> {
    let best = map
        .iter()
        .filter(|r| r.kind == memtype::USABLE)
        .filter_map(|r| {
            let start = r.base.max(0x10_0000).next_multiple_of(PAGE);
            let end = (r.base + r.len).min(1 << 32) / PAGE * PAGE;
            (end > start).then_some((start, end))
        })
        .max_by_key(|(s, e)| e - s)
        .ok_or("no usable memory above 1 MiB")?;
    LOW_START.store(best.0, Ordering::Relaxed);
    LOW.store(best.0, Ordering::Relaxed);
    HIGH.store(best.1, Ordering::Relaxed);
    HIGH_END.store(best.1, Ordering::Relaxed);
    Ok(())
}

fn take(kind: Kind, len: u64, align: u64) -> Option<u64> {
    let (low, high) = (LOW.load(Ordering::Relaxed), HIGH.load(Ordering::Relaxed));
    let at = match kind {
        Kind::Loader => low.next_multiple_of(align),
        Kind::Kernel => high.checked_sub(len)? / align * align,
    };
    let (new_low, new_high) = match kind {
        Kind::Loader => (at + len, high),
        Kind::Kernel => (low, at),
    };
    if new_low > new_high {
        return None;
    }
    LOW.store(new_low, Ordering::Relaxed);
    HIGH.store(new_high, Ordering::Relaxed);
    Some(at)
}

/// What the loader has taken, as the kernel's map should say: its low
/// memory (code, tables, buffers, the trampoline) and its data are
/// bootloader-reclaimable; the kernel and modules are theirs.
pub fn used() -> Vec<Region> {
    let reclaim = memtype::BOOTLOADER_RECLAIMABLE;
    let (ls, l) = (LOW_START.load(Ordering::Relaxed), LOW.load(Ordering::Relaxed));
    let (h, he) = (HIGH.load(Ordering::Relaxed), HIGH_END.load(Ordering::Relaxed));
    alloc::vec![
        Region { base: 0x500, len: 0x9_0000 - 0x500, kind: reclaim },
        Region { base: ls, len: l.next_multiple_of(PAGE) - ls, kind: reclaim },
        Region { base: h, len: he - h, kind: memtype::EXECUTABLE_AND_MODULES },
    ]
}

/// Heap allocations in the kernel's memory while `f` runs.
pub fn for_kernel<R>(f: impl FnOnce() -> R) -> R {
    FOR_KERNEL.store(true, Ordering::Relaxed);
    let r = f();
    FOR_KERNEL.store(false, Ordering::Relaxed);
    r
}

#[derive(Debug)]
pub struct Pool;

impl Memory for Pool {
    fn pages(&mut self, kind: Kind, bytes: u64, below: Option<u64>) -> Result<u64, String> {
        let len = bytes.max(1).next_multiple_of(PAGE);
        let at = if below.is_some_and(|b| b < 0x10_0000) {
            let at = UNDER_1M.load(Ordering::Relaxed);
            (at + len <= UNDER_1M_END).then(|| {
                UNDER_1M.store(at + len, Ordering::Relaxed);
                at
            })
        } else {
            take(kind, len, PAGE)
        };
        let at = at.ok_or_else(|| alloc::format!("out of memory ({bytes} bytes)"))?;
        // SAFETY: Memory just taken from the loader's range, one to one.
        unsafe { core::ptr::write_bytes(at as *mut u8, 0, len as usize) };
        Ok(at)
    }
}

struct Heap;

// SAFETY: Allocations come from the loader's range, aligned, and never
// overlap (the cursors only move apart from each other's taken memory).
unsafe impl core::alloc::GlobalAlloc for Heap {
    unsafe fn alloc(&self, l: core::alloc::Layout) -> *mut u8 {
        let kind = if FOR_KERNEL.load(Ordering::Relaxed) { Kind::Kernel } else { Kind::Loader };
        take(kind, l.size().max(1) as u64, l.align().max(16) as u64).map_or(core::ptr::null_mut(), |a| a as *mut u8)
    }
    unsafe fn dealloc(&self, _: *mut u8, _: core::alloc::Layout) {}
}

#[global_allocator]
static HEAP: Heap = Heap;
