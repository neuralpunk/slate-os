// SPDX-License-Identifier: MIT OR Apache-2.0

//! Helpers shared by the bus-mastering drivers: physically contiguous DMA
//! memory, memory-mapped registers, buffer-to-physical translation and
//! bounded register polling.

use crate::mm::PhysAddr;
use crate::mm::frame;

const PAGE: usize = 4096;

/// 2^order zeroed, physically contiguous, naturally aligned pages that a
/// device reads or writes, freed on drop.
pub struct Dma {
    phys: PhysAddr,
    order: usize,
}

// SAFETY: The pages are owned by this value; sharing it only shares the
// addresses, and every access is a volatile access or happens under the
// owning driver's lock.
unsafe impl Send for Dma {}
// SAFETY: As above.
unsafe impl Sync for Dma {}

impl Dma {
    /// At least `bytes` bytes (one page minimum).
    pub fn new(bytes: usize) -> Option<Dma> {
        let pages = bytes.div_ceil(PAGE).max(1);
        let order = pages.next_power_of_two().trailing_zeros() as usize;
        let phys = frame::alloc(order)?;
        // SAFETY: Freshly allocated frames, mapped in the direct map.
        unsafe { core::ptr::write_bytes(phys.to_virt(), 0, PAGE << order) };
        Some(Dma { phys, order })
    }

    /// At least `bytes` bytes below 4 GiB, for devices that address memory
    /// with 32 bits.
    pub fn new_below_4g(bytes: usize) -> Option<Dma> {
        let pages = bytes.div_ceil(PAGE).max(1);
        let order = pages.next_power_of_two().trailing_zeros() as usize;
        let phys = frame::alloc_below(order, 1 << 32)?;
        // SAFETY: Freshly allocated frames, mapped in the direct map.
        unsafe { core::ptr::write_bytes(phys.to_virt(), 0, PAGE << order) };
        Some(Dma { phys, order })
    }

    pub fn phys(&self) -> u64 {
        self.phys.0
    }

    pub fn len(&self) -> usize {
        PAGE << self.order
    }

    pub fn ptr(&self) -> *mut u8 {
        self.phys.to_virt()
    }

    /// Volatile read of a `T` at byte offset `off`.
    pub fn read<T: Copy>(&self, off: usize) -> T {
        assert!(off + size_of::<T>() <= self.len());
        // SAFETY: In bounds (checked above); devices write these bytes, so the
        // read is volatile. Callers use naturally aligned offsets.
        unsafe { self.ptr().add(off).cast::<T>().read_volatile() }
    }

    /// Volatile write of a `T` at byte offset `off`.
    pub fn write<T: Copy>(&self, off: usize, v: T) {
        assert!(off + size_of::<T>() <= self.len());
        // SAFETY: As in `read`.
        unsafe { self.ptr().add(off).cast::<T>().write_volatile(v) }
    }

    /// Copy bytes out of the buffer.
    pub fn copy_out(&self, off: usize, out: &mut [u8]) {
        assert!(off + out.len() <= self.len());
        // SAFETY: In bounds; the device is done with these bytes.
        unsafe { core::ptr::copy_nonoverlapping(self.ptr().add(off), out.as_mut_ptr(), out.len()) }
    }

    /// Copy bytes into the buffer.
    pub fn copy_in(&self, off: usize, data: &[u8]) {
        assert!(off + data.len() <= self.len());
        // SAFETY: In bounds; the device is not using these bytes yet.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr().add(off), data.len()) }
    }

    pub fn zero_range(&self, off: usize, len: usize) {
        assert!(off + len <= self.len());
        // SAFETY: In bounds; the device is not using these bytes.
        unsafe { core::ptr::write_bytes(self.ptr().add(off), 0, len) }
    }
}

impl Drop for Dma {
    fn drop(&mut self) {
        frame::free(self.phys, self.order);
    }
}

/// A device's memory-mapped register window.
#[derive(Clone, Copy)]
pub struct Mmio(pub *mut u8);

// SAFETY: The window stays mapped for the kernel's life; each access is a
// single volatile access that the device handles atomically.
unsafe impl Send for Mmio {}
// SAFETY: As above.
unsafe impl Sync for Mmio {}

impl Mmio {
    pub fn read32(&self, off: usize) -> u32 {
        // SAFETY: Register offsets come from the device's specification and
        // lie inside the mapped BAR.
        unsafe { self.0.add(off).cast::<u32>().read_volatile() }
    }

    pub fn write32(&self, off: usize, v: u32) {
        // SAFETY: As in `read32`.
        unsafe { self.0.add(off).cast::<u32>().write_volatile(v) }
    }

    pub fn read16(&self, off: usize) -> u16 {
        // SAFETY: As in `read32`; the register is 16 bits wide.
        unsafe { self.0.add(off).cast::<u16>().read_volatile() }
    }

    pub fn write16(&self, off: usize, v: u16) {
        // SAFETY: As in `read32`.
        unsafe { self.0.add(off).cast::<u16>().write_volatile(v) }
    }

    pub fn read8(&self, off: usize) -> u8 {
        // SAFETY: As in `read32`; the register is 8 bits wide.
        unsafe { self.0.add(off).read_volatile() }
    }

    pub fn write8(&self, off: usize, v: u8) {
        // SAFETY: As in `read32`.
        unsafe { self.0.add(off).write_volatile(v) }
    }

    /// A 64-bit register as two 32-bit accesses, low half first (which
    /// every device here accepts).
    pub fn read64(&self, off: usize) -> u64 {
        u64::from(self.read32(off)) | (u64::from(self.read32(off + 4)) << 32)
    }

    pub fn write64(&self, off: usize, v: u64) {
        self.write32(off, v as u32);
        self.write32(off + 4, (v >> 32) as u32);
    }
}

/// Poll `cond` until it holds or `timeout_ms` passes. Sleeps between polls
/// when the scheduler can block, so slow hardware does not stall a CPU.
pub fn wait_for(timeout_ms: u64, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = crate::time::monotonic_ns() + timeout_ms * 1_000_000;
    loop {
        if cond() {
            return true;
        }
        if crate::time::monotonic_ns() >= deadline {
            return cond();
        }
        if crate::sched::can_block() {
            crate::time::sleep_ns(200_000);
        } else {
            core::hint::spin_loop();
        }
    }
}

/// Wait `ms` milliseconds.
pub fn delay_ms(ms: u64) {
    wait_for(ms, || false);
}

/// The physical pages of a kernel buffer, for a device to reach it
/// directly: the address of its first byte, then of each following page.
/// `None` if its start is not a multiple of `align` or any of it is not
/// mapped in the kernel's own address space (a user address, say).
pub fn kernel_pages(ptr: *const u8, len: usize, align: u64) -> Option<alloc::vec::Vec<u64>> {
    const PAGE: u64 = 4096;
    let start = ptr as u64;
    if start % align != 0 {
        return None;
    }
    let mut pages = alloc::vec![crate::mm::virt_to_phys(start)?.0];
    let mut page = (start & !(PAGE - 1)) + PAGE;
    while page < start + len as u64 {
        pages.push(crate::mm::virt_to_phys(page)?.0);
        page += PAGE;
    }
    Some(pages)
}
