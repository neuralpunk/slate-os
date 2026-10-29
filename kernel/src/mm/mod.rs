// SPDX-License-Identifier: MIT OR Apache-2.0

//! Memory management: physical frames, the kernel address space, the heap
//! and kernel virtual mappings.
//!
//! Kernel virtual layout (x86-64, 4-level paging):
//!
//! | Range | Use |
//! |---|---|
//! | `0x0000_0000_0000_0000..0x0000_8000_0000_0000` | user space (M5) |
//! | `0xffff_8000_0000_0000..` (64 TiB) | direct map of physical memory (HHDM) |
//! | `0xffff_c000_0000_0000..` (1 TiB) | kernel stacks, with guard pages |
//! | `0xffff_c100_0000_0000..` (1 TiB) | device (MMIO) mappings |
//! | `0xffff_ffff_8000_0000..` (2 GiB) | kernel image |

pub mod aspace;
pub mod canary;
pub mod commit;
pub mod frame;
pub mod heap;
pub mod memcg;
pub mod pins;
pub mod tests;
pub mod vdso;
pub mod vmap;

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::{boot, paging};
use crate::log_info;

pub const PAGE_SIZE: u64 = 4096;

/// A physical address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhysAddr(pub u64);

impl PhysAddr {
    /// The address's location in the direct map.
    pub fn to_virt(self) -> *mut u8 {
        (self.0 + hhdm_offset()) as *mut u8
    }

    pub fn frame(self) -> u64 {
        self.0 / PAGE_SIZE
    }

    pub fn from_frame(frame: u64) -> PhysAddr {
        PhysAddr(frame * PAGE_SIZE)
    }
}

static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Base of the direct map of physical memory.
pub fn hhdm_offset() -> u64 {
    HHDM_OFFSET.load(Ordering::Relaxed)
}

/// Translate a direct-map address back to physical.
pub fn virt_to_phys_direct(v: *const u8) -> PhysAddr {
    PhysAddr(v as u64 - hhdm_offset())
}

/// Physical address of kernel virtual address `v` (direct map, kernel image,
/// heap or vmap area), if mapped.
pub fn virt_to_phys(v: u64) -> Option<PhysAddr> {
    paging::kernel_mapper().translate(v)
}

/// Set up physical memory, switch to the kernel's own page tables, and make
/// the heap and kernel virtual mappings available.
pub fn init(hhdm: u64) {
    HHDM_OFFSET.store(hhdm, Ordering::Relaxed);
    frame::init(boot::memory_map());
    paging::init_kernel_space(boot::memory_map(), boot::kernel_address());
    let s = frame::stats();
    log_info!(
        "memory: {} MiB free of {} MiB usable; kernel page tables active ({})",
        s.free_frames * PAGE_SIZE / (1 << 20),
        s.usable_frames * PAGE_SIZE / (1 << 20),
        paging::features(),
    );
}

/// Free the memory the bootloader used for its own data. Every CPU must be
/// off bootloader stacks and page tables, and boot information must have
/// been copied (`boot::snapshot`).
pub fn reclaim_bootloader_memory() {
    let regions: alloc::vec::Vec<_> =
        boot::memory_map().filter(|r| r.kind == boot::RegionKind::BootloaderReclaimable).collect();
    // The kernel's own file stays on the live system (`boot::kernel_file`).
    let kept = boot::kernel_file().map_or((0, 0), |f| {
        let start = (f.as_ptr() as u64).wrapping_sub(boot::info().hhdm_offset);
        (start & !(PAGE_SIZE - 1), (start + f.len() as u64).next_multiple_of(PAGE_SIZE))
    });
    boot::mark_reclaimed();
    let mut bytes = 0;
    for r in regions {
        let end = r.base + r.len;
        for (from, to) in [(r.base, end.min(kept.0)), (r.base.max(kept.1), end)] {
            if from < to {
                frame::add_region(from, to - from);
                bytes += to - from;
            }
        }
    }
    log_info!("reclaimed {} KiB of bootloader memory", bytes / 1024);
}
