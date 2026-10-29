// SPDX-License-Identifier: MIT OR Apache-2.0

//! x86-64 support.

pub mod apic;
pub mod backtrace;
pub mod boot;
pub mod context;
pub mod cpu;
pub mod efi;
mod extable;
pub mod fpu;
pub mod gdt;
pub mod hpet;
mod idt;
pub mod irq;
pub mod paging;
pub mod percpu;
mod pic;
pub mod port;
pub mod power;
pub mod probe;
pub mod qemu;
pub mod serial;
pub mod smp;
pub mod syscall;
pub mod tests;
mod tlb;
pub mod trap;
pub mod tsc;
pub mod uaccess;

use core::arch::asm;
use core::sync::atomic::Ordering;

/// The ELF entry point named in the linker script. Limine jumps here in long
/// mode with a valid stack, interrupts disabled and the higher half mapped.
#[unsafe(no_mangle)]
extern "C" fn kernel_entry() -> ! {
    boot::check_revision();
    crate::kernel_main()
}

/// Bring up the bootstrap CPU's descriptor tables: GDT and TSS (with IST
/// stacks), per-CPU data through GS, and the IDT. Interrupts stay masked.
pub fn init_bsp() {
    gdt::init_bsp();
    percpu::init(0, &gdt::BSP_TABLES);
    idt::load();
}

/// This CPU's kernel CPU number.
pub fn cpu_id() -> u32 {
    percpu::current().id
}

/// Set the stack the CPU switches to when an interrupt or system call
/// arrives from user mode (TSS.RSP0).
pub fn set_kernel_stack(top: u64) {
    if top != 0 {
        let pc = percpu::current();
        pc.tables.set_rsp0(top);
        pc.kernel_rsp.store(top, core::sync::atomic::Ordering::Relaxed);
    }
}

/// TLB shootdown requests made and served, per CPU.
pub fn tlb_counters() -> alloc::vec::Vec<(u64, u64)> {
    tlb::counters()
}

/// Flush stale translations of page-table root `root` on all CPUs.
pub fn tlb_shootdown(root: crate::mm::PhysAddr) {
    tlb::shootdown(root);
}

/// Interrupt the CPU with `apic_id` so it reschedules.
pub fn send_reschedule_ipi(apic_id: u32) {
    // Fixed delivery, level assert (SDM vol. 3A §11.6.1, figure 11-12).
    apic::send_ipi(apic_id, u32::from(irq::RESCHED_VECTOR) | (1 << 14));
}

/// Time between timer ticks.
const TICK_NS: u64 = crate::time::NS_PER_SEC / crate::time::TICK_HZ as u64;

/// The local APIC timer runs one-shot (ADR 0045): it fires at the next
/// tick, or earlier for a kernel timer or sleeper due before it, so those
/// are not rounded up to the tick.
fn timer_interrupt() {
    let pc = percpu::current();
    let now = crate::time::monotonic_ns();
    let tick = pc.next_tick.load(Ordering::Relaxed);
    if now >= tick {
        if cpu_id() == 0 {
            crate::time::tick();
        }
        crate::sched::tick();
        // Ticks that were missed (a vCPU not running) are skipped.
        let next = if tick + TICK_NS > now { tick + TICK_NS } else { now + TICK_NS };
        pc.next_tick.store(next, Ordering::Relaxed);
    } else {
        crate::sched::run_due(now);
    }
    arm_next(pc, now >= tick && cpu_id() != 0);
}

/// Set this CPU's timer for its next tick, or for the earliest kernel
/// timer or sleeper if that comes first (`tick_only`: the tick alone; CPU
/// 0 and a CPU that took an early event watch the others).
fn arm_next(pc: &percpu::PerCpu, tick_only: bool) {
    let tick = pc.next_tick.load(Ordering::Relaxed);
    let at = if tick_only { tick } else { tick.min(crate::sched::earliest_deadline()) };
    pc.timer_armed.store(at, Ordering::Relaxed);
    apic::arm_timer(at.saturating_sub(crate::time::monotonic_ns()));
}

/// Start this CPU's tick.
fn start_tick() {
    let pc = percpu::current();
    pc.next_tick.store(crate::time::monotonic_ns() + TICK_NS, Ordering::Relaxed);
    apic::start_timer();
    arm_next(pc, true);
}

/// Something is due at `deadline_ns` (a kernel timer, a sleeper): if this
/// CPU's timer is set later, bring it forward.
pub fn timer_deadline(deadline_ns: u64) {
    let _irq = cpu::InterruptGuard::new();
    let pc = percpu::current();
    if deadline_ns < pc.timer_armed.load(Ordering::Relaxed) && pc.next_tick.load(Ordering::Relaxed) != 0 {
        pc.timer_armed.store(deadline_ns, Ordering::Relaxed);
        apic::arm_timer(deadline_ns.saturating_sub(crate::time::monotonic_ns()));
    }
}

/// Second-stage bring-up once memory management works: move the IST
/// stacks to guarded kernel stacks.
pub fn init_bsp_late() {
    paging::init_pat();
    fpu::init_cpu();
    syscall::init_cpu();
    for slot in 1..=gdt::IST_COUNT as u8 {
        let stack = crate::mm::vmap::KernelStack::new().expect("out of memory for IST stacks");
        gdt::BSP_TABLES.set_ist(slot, stack.leak());
    }
}

/// The wall-clock time now: the CMOS RTC's (the freshest), else what the
/// bootloader read at boot.
fn wall_clock_now() -> Option<i64> {
    crate::drivers::rtc::read_unix().or_else(boot::boot_time_unix)
}

/// Bring up interrupt delivery and time on the bootstrap CPU: mask the
/// 8259s, enable the local APIC and the I/O APICs, start the HPET, calibrate
/// the TSC and the APIC timer, install the clock, start the tick, and enable
/// interrupts.
pub fn init_interrupts_and_time() {
    let info = crate::acpi::info();
    if info.has_8259 {
        pic::disable();
    }
    apic::init_local();
    percpu::set_apic_id(apic::id());
    apic::init_io();
    // The reference clock: the HPET, else the ACPI PM timer (some
    // machines and VMs have no HPET).
    match (info.hpet, info.fadt.filter(|f| f.pm_timer != 0)) {
        (Some(h), _) => hpet::init(h.address),
        (None, Some(f)) => hpet::init_pm(f.pm_timer as u16, f.flags & slate_acpi::fadt::TMR_VAL_EXT != 0),
        (None, None) => panic!("no HPET and no ACPI PM timer: nothing to calibrate the clocks with"),
    }
    let tsc_hz = tsc::calibrate();
    if tsc::invariant() {
        crate::time::init("tsc", tsc::read, tsc_hz, wall_clock_now());
    } else if hpet::is_pm_timer() {
        // The PM timer wraps too often to be the clock (GAPS).
        crate::log_warn!("the TSC is not invariant and there is no HPET: using the TSC as the clock anyway");
        crate::time::init("tsc", tsc::read, tsc_hz, wall_clock_now());
    } else {
        crate::time::init("hpet", hpet::counter, hpet::frequency(), wall_clock_now());
    }
    apic::calibrate_timer();
    irq::register(irq::TIMER_VECTOR, timer_interrupt);
    irq::register(irq::RESCHED_VECTOR, crate::sched::request_resched);
    irq::register(irq::TLB_VECTOR, tlb::interrupt);
    start_tick();
    crate::log_info!(
        "interrupts: {} APIC id {}, TSC {}.{:03} MHz{}, clock {}, tick {} Hz",
        if apic::x2apic() { "x2APIC" } else { "xAPIC" },
        apic::id(),
        tsc_hz / 1_000_000,
        tsc_hz / 1000 % 1000,
        if tsc::invariant() { " (invariant)" } else { "" },
        crate::time::clock_name(),
        crate::time::TICK_HZ,
    );
    // SAFETY: Every vector has a handler stub and the APIC is configured;
    // taking interrupts from here on is intended.
    unsafe { asm!("sti", options(nomem, nostack)) };
}

/// Halt until the next interrupt, with interrupts enabled.
pub fn wait_for_interrupt() {
    // SAFETY: `sti; hlt` enables interrupts and halts; the interrupt shadow
    // of `sti` guarantees no wakeup is lost between the two.
    unsafe { asm!("sti", "hlt", options(nomem, nostack)) };
}

/// Like [`switch_stack`], passing `arg` to `f`.
pub fn switch_stack_with(top: u64, f: extern "C" fn(u64) -> !, arg: u64) -> ! {
    // SAFETY: As for `switch_stack`.
    unsafe {
        asm!("mov rsp, {top}", "xor ebp, ebp", "call {f}", "ud2", top = in(reg) top, f = in(reg) f, in("rdi") arg,
             options(noreturn))
    }
}

/// Switch to the stack whose top is `top` and call `f` there. The current
/// stack is abandoned.
pub fn switch_stack(top: u64, f: extern "C" fn() -> !) -> ! {
    // SAFETY: `top` is the top of a mapped kernel stack nobody else uses;
    // `f` never returns, so nothing ever runs on the old stack frames again.
    // RBP is cleared so backtraces end at `f`.
    unsafe {
        asm!("mov rsp, {top}", "xor ebp, ebp", "call {f}", "ud2", top = in(reg) top, f = in(reg) f, options(noreturn))
    }
}

/// Number of entries in the exception table (for diagnostics and tests).
pub fn extable_len() -> usize {
    extable::len()
}

/// Disable interrupts and halt this CPU for good.
pub fn halt_forever() -> ! {
    loop {
        // SAFETY: `cli; hlt` only stops this CPU; it touches no memory.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}
