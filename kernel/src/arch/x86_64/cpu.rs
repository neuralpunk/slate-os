// SPDX-License-Identifier: MIT OR Apache-2.0

//! Control registers, MSRs and the interrupt flag (Intel SDM vol. 3A ch. 2;
//! MSR numbers from vol. 4).

use core::arch::asm;

pub const MSR_GS_BASE: u32 = 0xC000_0101;
pub const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;

const RFLAGS_IF: u64 = 1 << 9;

/// Read CR2, the faulting linear address of the last page fault.
pub fn cr2() -> u64 {
    let v: u64;
    // SAFETY: Reading CR2 has no side effects.
    unsafe { asm!("mov {}, cr2", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Read a model-specific register.
///
/// # Safety
///
/// `msr` must exist on this CPU, or the read raises #GP.
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: The caller guarantees the MSR exists.
    unsafe { asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
    (u64::from(hi) << 32) | u64::from(lo)
}

/// Write a model-specific register.
///
/// # Safety
///
/// `msr` must exist, and the new value must not break memory safety (for
/// example by moving the GS base out from under per-CPU data).
pub unsafe fn wrmsr(msr: u32, value: u64) {
    // SAFETY: The caller guarantees the write is sound.
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") value as u32, in("edx") (value >> 32) as u32,
             options(nomem, nostack, preserves_flags));
    }
}

/// Execute CPUID; returns (eax, ebx, ecx, edx).
pub fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let r = core::arch::x86_64::__cpuid_count(leaf, subleaf);
    (r.eax, r.ebx, r.ecx, r.edx)
}

pub fn read_cr0() -> u64 {
    let v: u64;
    // SAFETY: Reading CR0 has no side effects.
    unsafe { asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// # Safety
///
/// The new value must keep paging and protected mode on and must not make
/// memory the kernel relies on inaccessible.
pub unsafe fn write_cr0(v: u64) {
    // SAFETY: The caller guarantees the value is sound.
    unsafe { asm!("mov cr0, {}", in(reg) v, options(nostack, preserves_flags)) };
}

pub fn read_cr3() -> u64 {
    let v: u64;
    // SAFETY: Reading CR3 has no side effects.
    unsafe { asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

pub fn read_cr4() -> u64 {
    let v: u64;
    // SAFETY: Reading CR4 has no side effects.
    unsafe { asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// # Safety
///
/// The new value must keep long mode paging (PAE) on and enable only
/// features the CPU supports and the kernel is prepared for.
pub unsafe fn write_cr4(v: u64) {
    // SAFETY: The caller guarantees the value is sound.
    unsafe { asm!("mov cr4, {}", in(reg) v, options(nostack, preserves_flags)) };
}

pub fn rflags() -> u64 {
    let v: u64;
    // SAFETY: Reading RFLAGS has no side effects.
    unsafe { asm!("pushfq", "pop {}", out(reg) v, options(nomem, preserves_flags)) };
    v
}

pub fn interrupts_enabled() -> bool {
    rflags() & RFLAGS_IF != 0
}

/// Unmask interrupts on this CPU.
///
/// # Safety
///
/// The caller must hold no interrupt-masking lock (an interrupt handler or
/// a preempting thread could then try to take it).
pub unsafe fn enable_interrupts() {
    // SAFETY: The caller guarantees no masked-interrupt invariant is live.
    unsafe { asm!("sti", options(nomem, nostack)) };
}

/// Mask interrupts on this CPU.
pub fn disable_interrupts() {
    // SAFETY: Masking interrupts cannot break memory safety.
    unsafe { asm!("cli", options(nomem, nostack)) };
}

/// Masks maskable interrupts on this CPU while alive, then restores the
/// previous state. Nests correctly.
#[derive(Debug)]
pub struct InterruptGuard {
    were_enabled: bool,
}

impl InterruptGuard {
    pub fn new() -> InterruptGuard {
        let were_enabled = interrupts_enabled();
        // SAFETY: Masking interrupts cannot break memory safety.
        unsafe { asm!("cli", options(nomem, nostack)) };
        InterruptGuard { were_enabled }
    }
}

impl Drop for InterruptGuard {
    fn drop(&mut self) {
        if self.were_enabled {
            // SAFETY: Interrupts were enabled when the guard was made, so
            // re-enabling restores a state the caller already allowed.
            unsafe { asm!("sti", options(nomem, nostack)) };
        }
    }
}

/// Execute `int3`, raising a breakpoint exception (#BP).
pub fn breakpoint() {
    // SAFETY: The #BP handler returns to the next instruction.
    unsafe { asm!("int3", options(nomem, nostack)) };
}
