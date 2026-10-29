// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-CPU data reached through the GS segment base.
//!
//! While in the kernel, `IA32_GS_BASE` points at this CPU's [`PerCpu`];
//! entry code from user mode runs `swapgs` to get there (and back on exit).
//! The first field is a pointer to the block itself, so `gs:[0]` yields a
//! normal reference.

use alloc::boxed::Box;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

use slate_sync::Once;

use super::cpu::{MSR_GS_BASE, MSR_KERNEL_GS_BASE, wrmsr};
use super::gdt::CpuTables;

/// This CPU's private data. Grows as subsystems need per-CPU state.
#[derive(Debug)]
#[repr(C)]
pub struct PerCpu {
    /// Address of this structure; must stay the first field (read via `gs:[0]`).
    self_ptr: AtomicPtr<PerCpu>,
    /// Kernel-assigned CPU number, dense from 0 (the bootstrap CPU).
    pub id: u32,
    /// Local APIC ID, filled in by APIC setup.
    pub apic_id: AtomicU32,
    /// This CPU's GDT and TSS.
    pub tables: &'static CpuTables,
    /// Kernel stack top of the running thread, loaded by the `syscall` entry.
    pub kernel_rsp: AtomicU64,
    /// Scratch slot for the user stack pointer during `syscall` entry.
    pub user_rsp: AtomicU64,
    /// When this CPU's next timer tick is due, and when its local APIC
    /// timer is set to fire (monotonic ns; the timer runs one-shot).
    pub next_tick: AtomicU64,
    pub timer_armed: AtomicU64,
}

/// Offsets used by assembly (`gs:[offset]`).
pub const KERNEL_RSP_OFFSET: usize = core::mem::offset_of!(PerCpu, kernel_rsp);
pub const USER_RSP_OFFSET: usize = core::mem::offset_of!(PerCpu, user_rsp);

static BSP: Once<PerCpu> = Once::new();

/// Install the per-CPU block for CPU `id` (0 = bootstrap CPU, which uses a
/// static block because the heap does not exist yet). Must run after the GDT
/// is loaded, because loading a GS selector clears the GS base.
pub fn init(id: u32, tables: &'static CpuTables) {
    let make = || PerCpu {
        self_ptr: AtomicPtr::new(core::ptr::null_mut()),
        id,
        apic_id: AtomicU32::new(0),
        tables,
        kernel_rsp: AtomicU64::new(0),
        user_rsp: AtomicU64::new(0),
        next_tick: AtomicU64::new(0),
        timer_armed: AtomicU64::new(u64::MAX),
    };
    let pc: &'static PerCpu = if id == 0 { BSP.call_once(make) } else { Box::leak(Box::new(make())) };
    let addr = core::ptr::from_ref(pc).cast_mut();
    // The block is 'static and never moves, so its address is stable.
    pc.self_ptr.store(addr, Ordering::Relaxed);
    // SAFETY: GS base and kernel GS base exist on every x86-64 CPU. The new
    // GS base points at a live, 'static per-CPU block. Kernel GS base holds
    // the user value (none yet) for `swapgs`.
    unsafe {
        wrmsr(MSR_GS_BASE, addr as u64);
        wrmsr(MSR_KERNEL_GS_BASE, 0);
    }
}

/// This CPU's per-CPU block.
pub fn current() -> &'static PerCpu {
    let p: *const PerCpu;
    // SAFETY: In kernel mode GS base points at a 'static `PerCpu` whose first
    // field is its own address (see `init`).
    unsafe { core::arch::asm!("mov {}, gs:[0]", out(reg) p, options(nostack, readonly, preserves_flags)) };
    // SAFETY: `p` is the address of a live 'static `PerCpu`.
    unsafe { &*p }
}

/// Record this CPU's local APIC ID.
pub fn set_apic_id(id: u32) {
    current().apic_id.store(id, Ordering::Relaxed);
}
