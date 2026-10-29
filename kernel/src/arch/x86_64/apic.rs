// SPDX-License-Identifier: MIT OR Apache-2.0

//! Local APIC and I/O APIC (Intel SDM vol. 3A ch. 11; Intel 82093AA I/O APIC
//! datasheet).
//!
//! The local APIC runs in x2APIC mode (MSR access) when the CPU supports it,
//! and in xAPIC mode (MMIO) otherwise.

use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

use super::cpu::{cpuid, rdmsr, wrmsr};
use super::{hpet, irq};
use crate::acpi;
use crate::mm::{PhysAddr, vmap};
use crate::sync::IrqSpinLock;

const MSR_APIC_BASE: u32 = 0x1B;
const APIC_BASE_ENABLE: u64 = 1 << 11;
const APIC_BASE_X2APIC: u64 = 1 << 10;

// Register offsets in the xAPIC MMIO page; the x2APIC MSR is 0x800 + offset / 16.
const REG_ID: u32 = 0x020;
const REG_TPR: u32 = 0x080;
const REG_EOI: u32 = 0x0B0;
const REG_SVR: u32 = 0x0F0;
const REG_ICR_LOW: u32 = 0x300;
const REG_ICR_HIGH: u32 = 0x310;
const REG_LVT_TIMER: u32 = 0x320;
const REG_LVT_LINT0: u32 = 0x350;
const REG_LVT_LINT1: u32 = 0x360;
const REG_LVT_ERROR: u32 = 0x370;
const REG_TIMER_INITIAL: u32 = 0x380;
const REG_TIMER_CURRENT: u32 = 0x390;
const REG_TIMER_DIVIDE: u32 = 0x3E0;

const SVR_ENABLE: u32 = 1 << 8;
const LVT_MASKED: u32 = 1 << 16;
const LVT_DELIVERY_NMI: u32 = 0b100 << 8;
const LVT_ACTIVE_LOW: u32 = 1 << 13;
const LVT_LEVEL: u32 = 1 << 15;
const TIMER_DIVIDE_16: u32 = 0b0011;

static X2APIC: AtomicBool = AtomicBool::new(false);
static XAPIC_BASE: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
/// Local APIC timer ticks per millisecond at divide-by-16.
static TIMER_TICKS_PER_MS: AtomicU32 = AtomicU32::new(0);

fn read(reg: u32) -> u32 {
    if X2APIC.load(Ordering::Relaxed) {
        // SAFETY: In x2APIC mode every register below 0x400 exists as an MSR.
        unsafe { rdmsr(0x800 + reg / 16) as u32 }
    } else {
        // SAFETY: The xAPIC page is mapped uncached; registers are 32-bit
        // aligned.
        unsafe { XAPIC_BASE.load(Ordering::Relaxed).add(reg as usize).cast::<u32>().read_volatile() }
    }
}

fn write(reg: u32, v: u32) {
    if X2APIC.load(Ordering::Relaxed) {
        // SAFETY: As in `read`; writes to APIC registers only affect
        // interrupt delivery.
        unsafe { wrmsr(0x800 + reg / 16, u64::from(v)) }
    } else {
        // SAFETY: As in `read`.
        unsafe { XAPIC_BASE.load(Ordering::Relaxed).add(reg as usize).cast::<u32>().write_volatile(v) }
    }
}

/// This CPU's local APIC ID.
pub fn id() -> u32 {
    let v = read(REG_ID);
    if X2APIC.load(Ordering::Relaxed) { v } else { v >> 24 }
}

pub fn x2apic() -> bool {
    X2APIC.load(Ordering::Relaxed)
}

/// Signal end of interrupt.
pub fn eoi() {
    write(REG_EOI, 0);
}

/// Enable this CPU's local APIC: spurious vector, NMI pin from the MADT,
/// everything else masked. Called on every CPU.
pub fn init_local() {
    let x2 = cpuid(1, 0).2 & (1 << 21) != 0;
    // SAFETY: IA32_APIC_BASE exists on every x86-64 CPU; enabling the APIC
    // (and x2APIC mode when supported) only changes how it is accessed.
    let base = unsafe { rdmsr(MSR_APIC_BASE) };
    let mut new = base | APIC_BASE_ENABLE;
    if x2 {
        new |= APIC_BASE_X2APIC;
    }
    // SAFETY: As above.
    unsafe { wrmsr(MSR_APIC_BASE, new) };
    X2APIC.store(x2, Ordering::Relaxed);
    if !x2 && XAPIC_BASE.load(Ordering::Relaxed).is_null() {
        let phys = acpi::info().local_apic_address;
        XAPIC_BASE.store(vmap::map_mmio(PhysAddr(phys), 4096), Ordering::Relaxed);
    }

    write(REG_TPR, 0);
    write(REG_LVT_TIMER, LVT_MASKED);
    write(REG_LVT_ERROR, LVT_MASKED);
    write(REG_LVT_LINT0, LVT_MASKED);
    write(REG_LVT_LINT1, LVT_MASKED);
    if let Some((lint, flags)) = acpi::info().nmi_lint {
        let mut lvt = LVT_DELIVERY_NMI;
        if flags & slate_acpi::madt::POLARITY_MASK == slate_acpi::madt::POLARITY_ACTIVE_LOW {
            lvt |= LVT_ACTIVE_LOW;
        }
        write(if lint == 0 { REG_LVT_LINT0 } else { REG_LVT_LINT1 }, lvt);
    }
    write(REG_SVR, SVR_ENABLE | u32::from(irq::SPURIOUS_VECTOR));
}

/// Measure the local APIC timer against the HPET (once, on the bootstrap CPU).
pub fn calibrate_timer() {
    write(REG_TIMER_DIVIDE, TIMER_DIVIDE_16);
    write(REG_LVT_TIMER, LVT_MASKED);
    write(REG_TIMER_INITIAL, u32::MAX);
    hpet::spin_ns(10_000_000);
    let elapsed = u32::MAX - read(REG_TIMER_CURRENT);
    write(REG_TIMER_INITIAL, 0);
    TIMER_TICKS_PER_MS.store(elapsed / 10, Ordering::Relaxed);
}

/// Put this CPU's timer in one-shot mode (SDM vol. 3A §11.5.4: the LVT
/// timer mode bits 0) on the timer vector; [`arm_timer`] starts it.
pub fn start_timer() {
    write(REG_TIMER_DIVIDE, TIMER_DIVIDE_16);
    write(REG_LVT_TIMER, u32::from(irq::TIMER_VECTOR));
}

/// Make this CPU's timer interrupt once, `ns` from now (writing the
/// initial count restarts the count-down).
pub fn arm_timer(ns: u64) {
    let per_ms = u128::from(TIMER_TICKS_PER_MS.load(Ordering::Relaxed));
    let count = (u128::from(ns) * per_ms / 1_000_000).clamp(1, u128::from(u32::MAX)) as u32;
    write(REG_TIMER_INITIAL, count);
}

/// Send an IPI. `icr_low` holds vector and delivery mode bits (SDM vol. 3A
/// §11.6.1).
pub fn send_ipi(dest_apic_id: u32, icr_low: u32) {
    if X2APIC.load(Ordering::Relaxed) {
        // SAFETY: The x2APIC ICR is MSR 0x830; writing it sends an IPI.
        unsafe { wrmsr(0x830, (u64::from(dest_apic_id) << 32) | u64::from(icr_low)) };
    } else {
        write(REG_ICR_HIGH, dest_apic_id << 24);
        write(REG_ICR_LOW, icr_low);
        while read(REG_ICR_LOW) & (1 << 12) != 0 {
            core::hint::spin_loop(); // delivery status: send pending
        }
    }
}

// --- I/O APIC ------------------------------------------------------------

const IOREGSEL: usize = 0x00;
const IOWIN: usize = 0x10;
const IOAPICVER: u32 = 0x01;
const IOREDTBL: u32 = 0x10;

#[derive(Debug)]
struct IoApic {
    base: *mut u8,
    gsi_base: u32,
    entries: u32,
}

// SAFETY: The register window is only used under the `IO_APICS` lock.
unsafe impl Send for IoApic {}

impl IoApic {
    fn read(&self, reg: u32) -> u32 {
        // SAFETY: `base` maps the I/O APIC's register window uncached; the
        // select/window protocol is serialized by the lock around `self`.
        unsafe {
            self.base.add(IOREGSEL).cast::<u32>().write_volatile(reg);
            self.base.add(IOWIN).cast::<u32>().read_volatile()
        }
    }

    fn write(&self, reg: u32, v: u32) {
        // SAFETY: As in `read`.
        unsafe {
            self.base.add(IOREGSEL).cast::<u32>().write_volatile(reg);
            self.base.add(IOWIN).cast::<u32>().write_volatile(v);
        }
    }
}

static IO_APICS: IrqSpinLock<alloc::vec::Vec<IoApic>> = IrqSpinLock::new(alloc::vec::Vec::new());

/// Map every I/O APIC and mask all its inputs.
pub fn init_io() {
    let mut list = IO_APICS.lock();
    for a in &acpi::info().io_apics {
        let base = vmap::map_mmio(PhysAddr(a.address), 0x20);
        let mut io = IoApic { base, gsi_base: a.gsi_base, entries: 0 };
        io.entries = ((io.read(IOAPICVER) >> 16) & 0xFF) + 1;
        for i in 0..io.entries {
            io.write(IOREDTBL + 2 * i, LVT_MASKED);
            io.write(IOREDTBL + 2 * i + 1, 0);
        }
        list.push(io);
    }
}

/// Route GSI `gsi` to `vector` on the CPU with `dest_apic_id`, with the
/// trigger mode and polarity the firmware gave (legacy PCI interrupts
/// through `_PRT`, ADR 0079: level-triggered). Returns false when no I/O
/// APIC has that input.
pub fn route_gsi(gsi: u32, vector: u8, dest_apic_id: u32, level: bool, active_low: bool) -> bool {
    let mut low = u32::from(vector);
    if active_low {
        low |= LVT_ACTIVE_LOW;
    }
    if level {
        low |= LVT_LEVEL;
    }
    let list = IO_APICS.lock();
    let Some(io) = list.iter().find(|io| (io.gsi_base..io.gsi_base + io.entries).contains(&gsi)) else {
        return false;
    };
    let i = gsi - io.gsi_base;
    io.write(IOREDTBL + 2 * i + 1, dest_apic_id << 24);
    io.write(IOREDTBL + 2 * i, low);
    true
}

/// Route ISA IRQ `irq` to `vector` on the CPU with `dest_apic_id`, applying
/// the MADT's interrupt source overrides. ISA defaults: edge, active high.
pub fn route_isa_irq(irq: u8, vector: u8, dest_apic_id: u32) {
    let (mut gsi, mut flags) = (u32::from(irq), 0u16);
    if let Some(o) = acpi::info().overrides.iter().find(|o| o.source == irq) {
        gsi = o.gsi;
        flags = o.flags;
    }
    let mut low = u32::from(vector);
    if flags & slate_acpi::madt::POLARITY_MASK == slate_acpi::madt::POLARITY_ACTIVE_LOW {
        low |= LVT_ACTIVE_LOW;
    }
    if flags & slate_acpi::madt::TRIGGER_MASK == slate_acpi::madt::TRIGGER_LEVEL {
        low |= LVT_LEVEL;
    }
    let list = IO_APICS.lock();
    let Some(io) = list.iter().find(|io| (io.gsi_base..io.gsi_base + io.entries).contains(&gsi)) else {
        crate::log_warn!("no I/O APIC handles GSI {gsi} (ISA IRQ {irq})");
        return;
    };
    let i = gsi - io.gsi_base;
    io.write(IOREDTBL + 2 * i + 1, dest_apic_id << 24);
    io.write(IOREDTBL + 2 * i, low);
}
