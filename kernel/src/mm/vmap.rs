// SPDX-License-Identifier: MIT OR Apache-2.0

//! Kernel virtual mappings outside the direct map: stacks with guard pages,
//! device memory, and scratch memory larger than the heap's largest block.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::{PAGE_SIZE, PhysAddr, frame};
use crate::arch::paging::{MapFlags, PageSize, kernel_mapper};
use crate::sync::IrqSpinLock;

const STACK_REGION: u64 = 0xFFFF_C000_0000_0000;
const STACK_REGION_SIZE: u64 = 1 << 40;
/// Each stack slot: an unmapped guard area below the stack itself.
const STACK_SLOT: u64 = 64 * 1024;
/// Usable size of every kernel stack.
pub const STACK_SIZE: u64 = 32 * 1024;

const MMIO_REGION: u64 = 0xFFFF_C100_0000_0000;
const MMIO_REGION_SIZE: u64 = 1 << 40;

const SCRATCH_REGION: u64 = 0xFFFF_C200_0000_0000;
const SCRATCH_REGION_SIZE: u64 = 1 << 40;

#[derive(Debug)]
struct Slots {
    next: u64,
    /// Stacks freed and still mapped, for the reaper to unmap.
    dropped: Vec<u64>,
    /// Unmapped slots, oldest first: reused only after [`SLOT_QUARANTINE`]
    /// others, so a stale pointer into a dead thread's stack faults
    /// rather than reach a new thread's.
    free: VecDeque<u64>,
}

static STACK_SLOTS: IrqSpinLock<Slots> =
    IrqSpinLock::new(Slots { next: 0, dropped: Vec::new(), free: VecDeque::new() });
/// Unmapped slots kept before one is reused.
const SLOT_QUARANTINE: usize = 1024;
/// How often the reaper unmaps freed stacks.
const REAP_INTERVAL_NS: u64 = 20_000_000;
static REAPER: AtomicBool = AtomicBool::new(false);
static MMIO_NEXT: AtomicU64 = AtomicU64::new(MMIO_REGION);
static SCRATCH_NEXT: AtomicU64 = AtomicU64::new(SCRATCH_REGION);

/// Virtually contiguous scratch memory of separate frames (the key
/// derivation's 32 MiB at boot, ADR 0036). Mapped non-global, so a page
/// table reload drops it from the TLB; dropping it clears the memory,
/// unmaps it, shoots down every CPU's translations and frees the frames.
/// Its virtual addresses are never reused.
#[derive(Debug)]
pub struct Scratch {
    virt: u64,
    frames: Vec<PhysAddr>,
}

impl Scratch {
    /// `bytes` (rounded up to pages) of zeroed memory, or None when the
    /// frames run out.
    pub fn new(bytes: usize) -> Option<Scratch> {
        let pages = (bytes as u64).div_ceil(PAGE_SIZE);
        let virt = SCRATCH_NEXT.fetch_add(pages * PAGE_SIZE, Ordering::Relaxed);
        if virt + pages * PAGE_SIZE > SCRATCH_REGION + SCRATCH_REGION_SIZE {
            return None;
        }
        let mut s = Scratch { virt, frames: Vec::with_capacity(pages as usize) };
        let flags = MapFlags { global: false, ..MapFlags::KERNEL_DATA };
        // Every frame in `frames` is mapped, so a failure part way through
        // undoes cleanly through drop.
        for i in 0..pages {
            let f = frame::alloc_zeroed()?;
            if kernel_mapper().map(virt + i * PAGE_SIZE, f, PageSize::Size4K, flags).is_err() {
                frame::free(f, 0);
                return None;
            }
            s.frames.push(f);
        }
        Some(s)
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `frames.len()` pages are mapped read-write at `virt`, for
        // this object alone, until drop; `&mut self` makes this the only
        // reference.
        unsafe { core::slice::from_raw_parts_mut(self.virt as *mut u8, self.frames.len() * PAGE_SIZE as usize) }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // It may have held key material.
        self.as_mut_slice().fill(0);
        {
            let mut m = kernel_mapper();
            for i in 0..self.frames.len() as u64 {
                m.unmap(self.virt + i * PAGE_SIZE);
            }
        }
        crate::arch::tlb_shootdown(crate::arch::paging::kernel_root());
        for f in self.frames.drain(..) {
            frame::free(f, 0);
        }
    }
}

/// A kernel stack of [`STACK_SIZE`] bytes with an unmapped guard below it:
/// overflowing it faults instead of corrupting memory.
///
/// A stack is dropped wherever its thread's last reference goes, often
/// with locks held, where a TLB shootdown could deadlock. So a dropped
/// stack stays mapped until the reaper thread unmaps the dropped stacks
/// together, shoots down once and frees their frames (M25). Stacks are
/// mapped non-global: the shootdown's page table reload must drop them
/// from every CPU's TLB, or a CPU could reach a reused slot through the
/// old frame.
#[derive(Debug)]
pub struct KernelStack {
    slot: u64,
}

impl KernelStack {
    /// Allocate and map a new stack.
    pub fn new() -> Option<KernelStack> {
        let slot = {
            let mut s = STACK_SLOTS.lock();
            if s.free.len() > SLOT_QUARANTINE {
                s.free.pop_front().unwrap()
            } else if (s.next + 1) * STACK_SLOT <= STACK_REGION_SIZE {
                s.next += 1;
                s.next - 1
            } else {
                s.free.pop_front()?
            }
        };
        let stack = KernelStack { slot };
        let mut m = kernel_mapper();
        let flags = MapFlags { global: false, ..MapFlags::KERNEL_DATA };
        for v in (stack.bottom()..stack.top()).step_by(PAGE_SIZE as usize) {
            // Running out of memory here is fatal for now.
            let f = frame::alloc(0).expect("out of memory while mapping a kernel stack");
            m.map(v, f, PageSize::Size4K, flags).expect("kernel stack slot already mapped");
        }
        Some(stack)
    }

    /// Lowest usable address; the page below it is the guard.
    pub fn bottom(&self) -> u64 {
        self.top() - STACK_SIZE
    }

    /// Initial stack pointer (stacks grow down).
    pub fn top(&self) -> u64 {
        STACK_REGION + (self.slot + 1) * STACK_SLOT
    }

    /// Give up ownership: the stack stays mapped forever.
    pub fn leak(self) -> u64 {
        let top = self.top();
        core::mem::forget(self);
        top
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        STACK_SLOTS.lock().dropped.push(self.slot);
    }
}

/// Start the thread that unmaps dropped kernel stacks (once, with the
/// scheduler running).
pub fn start_stack_reaper() {
    if REAPER.swap(true, Ordering::AcqRel) {
        return;
    }
    crate::sched::spawn("stack-reaper", || {
        loop {
            crate::time::sleep_ns(REAP_INTERVAL_NS);
            reap_stacks();
        }
    });
}

/// Unmap the dropped stacks, flush every CPU's translations of them and
/// free their frames. From a thread that holds no locks.
pub fn reap_stacks() {
    let dropped = core::mem::take(&mut STACK_SLOTS.lock().dropped);
    if dropped.is_empty() {
        return;
    }
    let mut frames = Vec::with_capacity(dropped.len() * (STACK_SIZE / PAGE_SIZE) as usize);
    {
        let mut m = kernel_mapper();
        for &slot in &dropped {
            let top = STACK_REGION + (slot + 1) * STACK_SLOT;
            for v in (top - STACK_SIZE..top).step_by(PAGE_SIZE as usize) {
                frames.extend(m.unmap(v).map(|(f, _)| f));
            }
        }
    }
    // No CPU may still reach a frame through an old translation once it
    // is free.
    crate::arch::tlb_shootdown(crate::arch::paging::kernel_root());
    for f in frames {
        frame::free(f, 0);
    }
    STACK_SLOTS.lock().free.extend(dropped);
}

/// Whether `addr` is in a kernel stack slot (for tests).
pub fn in_stack_region(addr: u64) -> bool {
    (STACK_REGION..STACK_REGION + STACK_REGION_SIZE).contains(&addr)
}

/// Map `frames` (ordinary memory) contiguously, cached, and return the
/// virtual address of the first. Mappings are permanent (a console
/// framebuffer a GPU driver allocates).
pub fn map_ram(frames: &[PhysAddr]) -> *mut u8 {
    let len = frames.len() as u64 * PAGE_SIZE;
    let virt = MMIO_NEXT.fetch_add(len, Ordering::Relaxed);
    assert!(virt + len <= MMIO_REGION + MMIO_REGION_SIZE, "MMIO region exhausted");
    let mut m = kernel_mapper();
    for (i, f) in frames.iter().enumerate() {
        m.map(virt + i as u64 * PAGE_SIZE, *f, PageSize::Size4K, MapFlags::KERNEL_DATA)
            .expect("vmap slot already mapped");
    }
    virt as *mut u8
}

/// Map `len` bytes of device memory at `phys` uncached and return its
/// virtual address. Mappings are permanent.
pub fn map_mmio(phys: PhysAddr, len: u64) -> *mut u8 {
    map_device(phys, len, MapFlags::KERNEL_MMIO)
}

/// [`map_mmio`] write-combining: for framebuffers, written in long runs
/// and never read back.
pub fn map_wc(phys: PhysAddr, len: u64) -> *mut u8 {
    map_device(phys, len, MapFlags { cache: crate::arch::paging::CacheMode::WriteCombining, ..MapFlags::KERNEL_MMIO })
}

fn map_device(phys: PhysAddr, len: u64, flags: MapFlags) -> *mut u8 {
    let offset = phys.0 % PAGE_SIZE;
    let base = phys.0 - offset;
    let pages = (offset + len).div_ceil(PAGE_SIZE);
    let virt = MMIO_NEXT.fetch_add(pages * PAGE_SIZE, Ordering::Relaxed);
    assert!(virt + pages * PAGE_SIZE <= MMIO_REGION + MMIO_REGION_SIZE, "MMIO region exhausted");
    let mut m = kernel_mapper();
    for i in 0..pages {
        m.map(virt + i * PAGE_SIZE, PhysAddr(base + i * PAGE_SIZE), PageSize::Size4K, flags)
            .expect("MMIO slot already mapped");
    }
    (virt + offset) as *mut u8
}
