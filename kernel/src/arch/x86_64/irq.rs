// SPDX-License-Identifier: MIT OR Apache-2.0

//! Interrupt vector assignment and dispatch for external interrupts.
//!
//! | Vectors | Use |
//! |---|---|
//! | 0x20-0x2F | ISA IRQs 0-15 through the I/O APIC |
//! | 0x30-0xEE | device interrupts (MSI/MSI-X), allocated on demand |
//! | 0xEF | local APIC timer |
//! | 0xF0 | reschedule IPI |
//! | 0xF1 | TLB shootdown IPI |
//! | 0xF2-0xFE | reserved for more IPIs |
//! | 0xFF | spurious |

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use core::fmt::Write;
use core::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};

use slate_sync::Once;

use super::apic;

pub const ISA_BASE: u8 = 0x20;
pub const TIMER_VECTOR: u8 = 0xEF;
pub const RESCHED_VECTOR: u8 = 0xF0;
pub const TLB_VECTOR: u8 = 0xF1;
pub const SPURIOUS_VECTOR: u8 = 0xFF;

/// Handlers by vector, stored as `fn()` addresses (0 = none).
static HANDLERS: [AtomicUsize; 256] = [const { AtomicUsize::new(0) }; 256];

/// A device interrupt handler.
pub type DeviceHandler = Box<dyn Fn() + Send + Sync>;

const DEVICE_FIRST: u8 = 0x30;
const DEVICE_LAST: u8 = 0xEE;
static NEXT_DEVICE_VECTOR: AtomicU8 = AtomicU8::new(DEVICE_FIRST);
static DEVICE_HANDLERS: [Once<DeviceHandler>; 256] = [const { Once::new() }; 256];

/// What each vector in use is, for /proc/interrupts: how it is delivered
/// and the devices on it.
static NAMES: crate::sync::IrqSpinLock<BTreeMap<u8, (String, String)>> = crate::sync::IrqSpinLock::new(BTreeMap::new());
/// Interrupts taken, by CPU and vector (`cpu * 256 + vector`), from
/// `init_counts` on.
static COUNTS: Once<Box<[AtomicU64]>> = Once::new();

/// Start counting interrupts (once the CPUs are known).
pub fn init_counts() {
    let n = crate::sched::cpu_count() * 256;
    COUNTS.call_once(|| (0..n).map(|_| AtomicU64::new(0)).collect());
}

/// Record how `vector` is delivered ("PCI-MSI-X 00:02.0") and for what.
pub fn describe(vector: u8, kind: &str, name: &str) {
    NAMES.lock().insert(vector, (kind.into(), name.into()));
}

/// Record how `vector` is delivered, keeping its devices' names.
pub fn set_kind(vector: u8, kind: &str) {
    NAMES.lock().entry(vector).or_default().0 = kind.into();
}

/// Allocate a vector for a device interrupt and install `handler` for it
/// (`name` is the device, for /proc/interrupts). Returns `None` when the
/// device range is used up.
pub fn alloc_vector(name: &str, handler: DeviceHandler) -> Option<u8> {
    let v = NEXT_DEVICE_VECTOR.fetch_add(1, Ordering::Relaxed);
    if !(DEVICE_FIRST..=DEVICE_LAST).contains(&v) {
        NEXT_DEVICE_VECTOR.store(DEVICE_LAST + 1, Ordering::Relaxed);
        return None;
    }
    DEVICE_HANDLERS[v as usize].call_once(|| handler);
    describe(v, "", name);
    Some(v)
}

/// Handlers sharing one GSI's vector (level-triggered legacy PCI
/// interrupts share lines): every handler runs on each interrupt, and each
/// checks and clears its own device.
type Sharers = alloc::sync::Arc<crate::sync::IrqSpinLock<alloc::vec::Vec<DeviceHandler>>>;
static SHARED: crate::sync::IrqSpinLock<alloc::vec::Vec<(u32, u8, Sharers)>> =
    crate::sync::IrqSpinLock::new(alloc::vec::Vec::new());

/// Add `handler` (for device `name`) to GSI `gsi`'s vector: the vector,
/// and whether it is new (the caller then routes the GSI to it).
pub fn share_gsi(gsi: u32, name: &str, handler: DeviceHandler) -> Option<(u8, bool)> {
    let mut shared = SHARED.lock();
    if let Some((_, v, list)) = shared.iter().find(|(g, ..)| *g == gsi) {
        list.lock().push(handler);
        if let Some((_, names)) = NAMES.lock().get_mut(v) {
            names.push_str(", ");
            names.push_str(name);
        }
        return Some((*v, false));
    }
    let list: Sharers = alloc::sync::Arc::new(crate::sync::IrqSpinLock::new(alloc::vec![handler]));
    let l = list.clone();
    let v = alloc_vector(
        name,
        Box::new(move || {
            for h in l.lock().iter() {
                h();
            }
        }),
    )?;
    describe(v, &alloc::format!("IO-APIC {gsi}-level"), name);
    shared.push((gsi, v, list));
    Some((v, true))
}

/// The (address, data) pair a device writes to raise `vector` on the CPU
/// with local APIC ID `dest`: fixed delivery, edge triggered, physical
/// destination (SDM vol. 3A §11.11). IDs above 255 need interrupt
/// remapping, which Slate does not use, so `dest` must fit in 8 bits.
pub fn msi_message(vector: u8, dest: u32) -> (u64, u32) {
    assert!(dest < 256, "MSI destination APIC ID {dest} needs interrupt remapping");
    (0xFEE0_0000 | (u64::from(dest) << 12), u32::from(vector))
}

static NEXT_TARGET: AtomicUsize = AtomicUsize::new(0);

/// The APIC ID the next device interrupt is sent to: the CPUs in turn,
/// from the second (the bootstrap CPU has the ISA interrupts), skipping
/// any whose ID an MSI cannot name without interrupt remapping (above
/// 255) or that is not online.
pub fn device_irq_target() -> u32 {
    let n = crate::sched::cpu_count();
    for _ in 0..n {
        let k = NEXT_TARGET.fetch_add(1, Ordering::Relaxed);
        let cpu = if n > 1 { 1 + k % (n - 1) } else { 0 };
        let id = crate::sched::apic_id_of(cpu);
        if id < 256 && crate::sched::cpu_online(cpu) {
            return id;
        }
    }
    crate::sched::apic_id_of(0)
}

/// Install `handler` for `vector`. Handlers run with interrupts masked.
pub fn register(vector: u8, handler: fn()) {
    HANDLERS[vector as usize].store(handler as usize, Ordering::Release);
}

/// Install `handler` for ISA IRQ `irq` (device `name`) and route it to
/// the bootstrap CPU.
pub fn register_isa(irq: u8, name: &str, handler: fn()) {
    let vector = ISA_BASE + irq;
    register(vector, handler);
    describe(vector, &alloc::format!("IO-APIC {irq}"), name);
    apic::route_isa_irq(irq, vector, apic::id());
}

/// Called from the trap path for vectors 32..=255.
pub fn dispatch(vector: u8) {
    if let Some(c) = COUNTS.get()
        && let Some(n) = c.get(super::cpu_id() as usize * 256 + usize::from(vector))
    {
        n.fetch_add(1, Ordering::Relaxed);
    }
    if vector == SPURIOUS_VECTOR {
        return; // No EOI for spurious interrupts (SDM vol. 3A §11.9).
    }
    let h = HANDLERS[vector as usize].load(Ordering::Acquire);
    if h != 0 {
        // SAFETY: Only `register` stores into the table, always a valid `fn()`.
        let f: fn() = unsafe { core::mem::transmute::<usize, fn()>(h) };
        f();
    } else if let Some(f) = DEVICE_HANDLERS[vector as usize].get() {
        f();
    } else {
        crate::log_warn!("interrupt on vector {vector:#x} with no handler");
    }
    apic::eoi();
}

/// /proc/interrupts (proc(5)): a column per CPU, a row per vector in use
/// with its delivery and devices, then the local APIC's own interrupts.
/// Laid out as observed on Linux; rows are numbered by vector, Slate
/// having no IRQ numbers of its own.
pub fn proc_interrupts(s: &mut String) {
    let cpus = crate::sched::cpu_count();
    let count = |cpu: usize, v: u8| {
        COUNTS.get().and_then(|c| c.get(cpu * 256 + usize::from(v))).map_or(0, |n| n.load(Ordering::Relaxed))
    };
    s.push_str("     ");
    for c in 0..cpus {
        let _ = write!(s, " {:>10}", alloc::format!("CPU{c}"));
    }
    s.push('\n');
    let row = |s: &mut String, label: &str, v: u8, what: &str| {
        let _ = write!(s, "{label:>4}:");
        for c in 0..cpus {
            let _ = write!(s, " {:10}", count(c, v));
        }
        let _ = writeln!(s, "   {what}");
    };
    let names = NAMES.lock().clone();
    for (v, (kind, name)) in &names {
        row(s, &alloc::format!("{v}"), *v, &alloc::format!("{kind:<20} {name}"));
    }
    row(s, "LOC", TIMER_VECTOR, "Local timer interrupts");
    row(s, "RES", RESCHED_VECTOR, "Rescheduling interrupts");
    row(s, "TLB", TLB_VECTOR, "TLB shootdowns");
    row(s, "SPU", SPURIOUS_VECTOR, "Spurious interrupts");
}
