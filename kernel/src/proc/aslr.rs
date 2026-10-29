// SPDX-License-Identifier: MIT OR Apache-2.0

//! Address space layout randomization (ADR 0092): where exec puts a
//! program, its stack, its break, its mappings and the vDSO.
//!
//! Each is moved by a random number of pages (and the stack pointer by a
//! random multiple of 16 bytes within its page). The ranges never overlap:
//!
//! | what | from | bits (pages) |
//! |---|---|---|
//! | position-independent program | `0x5555_0000_0000` up | 30 |
//! | the break, after the program | up | 18 |
//! | mappings (and the dynamic loader) | `0x7F00_0000_0000` down | 30 |
//! | the vDSO | `0x7F00_1000_0000` up | 26 |
//! | the main stack's top | `0x7FFF_FFFF_F000` down | 27 (+ 8 within the page) |
//!
//! `/proc/sys/kernel/randomize_va_space` (proc(5)): 0 turns it off, 1
//! leaves the break unmoved, 2 (the default) moves everything.
//! `personality(ADDR_NO_RANDOMIZE)` (personality(2)) turns it off for a
//! process and the programs it runs, as debuggers ask; a set-user-ID
//! exec clears that flag. `norandmaps` on the command line starts with 0
//! (the kernel's documented parameter).

use core::sync::atomic::{AtomicU8, Ordering};

use crate::mm::PAGE_SIZE;

pub const PIE_BITS: u32 = 30;
pub const BRK_BITS: u32 = 18;
pub const MMAP_BITS: u32 = 30;
pub const VDSO_BITS: u32 = 26;
pub const STACK_BITS: u32 = 27;

/// Without randomization, position-independent programs load here (where
/// Linux puts them, which debuggers' users expect).
pub const PIE_FIXED: u64 = 0x5555_5555_4000;
const PIE_LOW: u64 = 0x5555_0000_0000;
/// The vDSO's window, above the mapping area and below the lowest main
/// stack (`STACK_BITS` below the top, then its largest reservation, 1 GiB).
const VDSO_LOW: u64 = 0x7F00_1000_0000;
const _: () = assert!(VDSO_LOW > crate::mm::aspace::MMAP_TOP);
const _: () = assert!(
    VDSO_LOW + (PAGE_SIZE << VDSO_BITS) + (2 << 20)
        < crate::mm::aspace::STACK_TOP - (PAGE_SIZE << STACK_BITS) - (1 << 30)
);
const _: () = assert!(PIE_LOW + (PAGE_SIZE << PIE_BITS) + (PAGE_SIZE << BRK_BITS) < 0x6000_0000_0000);
const _: () = assert!(crate::mm::aspace::MMAP_TOP - (PAGE_SIZE << MMAP_BITS) > 0x7000_0000_0000);

/// personality(2)'s ADDR_NO_RANDOMIZE (`sys/personality.h`, musl).
pub const ADDR_NO_RANDOMIZE: u32 = 0x0040000;

static LEVEL: AtomicU8 = AtomicU8::new(2);

pub fn configure(cmdline: &str) {
    if cmdline.split_ascii_whitespace().any(|w| w == "norandmaps") {
        LEVEL.store(0, Ordering::Relaxed);
        crate::log_warn!("aslr: off (norandmaps)");
    }
}

/// `randomize_va_space`.
pub fn level() -> u8 {
    LEVEL.load(Ordering::Relaxed)
}

pub fn set_level(v: u8) {
    LEVEL.store(v.min(2), Ordering::Relaxed);
}

/// How an exec lays out the new program.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    /// Moves the program, the mappings, the vDSO and the stack.
    pub maps: bool,
    /// Moves the break too.
    pub brk: bool,
}

impl Layout {
    /// For a process with personality `persona`.
    pub fn for_persona(persona: u32) -> Layout {
        let level = if persona & ADDR_NO_RANDOMIZE != 0 { 0 } else { level() };
        Layout { maps: level >= 1, brk: level >= 2 }
    }

    /// A random number of pages below 2^`bits`, in bytes; 0 when off.
    fn pages(on: bool, bits: u32) -> u64 {
        if !on {
            return 0;
        }
        let mut b = [0u8; 8];
        crate::random::fill(&mut b);
        (u64::from_le_bytes(b) & ((1 << bits) - 1)) * PAGE_SIZE
    }

    pub fn pie_base(self) -> u64 {
        if self.maps { PIE_LOW + Self::pages(true, PIE_BITS) } else { PIE_FIXED }
    }

    pub fn brk_gap(self) -> u64 {
        Self::pages(self.brk, BRK_BITS)
    }

    pub fn mmap_top(self) -> u64 {
        crate::mm::aspace::MMAP_TOP - Self::pages(self.maps, MMAP_BITS)
    }

    pub fn vvar(self) -> u64 {
        if self.maps { VDSO_LOW + Self::pages(true, VDSO_BITS) } else { crate::mm::vdso::VVAR_ADDR }
    }

    pub fn stack_top(self) -> u64 {
        crate::mm::aspace::STACK_TOP - Self::pages(self.maps, STACK_BITS)
    }

    /// How far below the stack's top the first byte goes: a multiple of 16
    /// within a page.
    pub fn stack_offset(self) -> u64 {
        Self::pages(self.maps, 8) / PAGE_SIZE * 16
    }
}
