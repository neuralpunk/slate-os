// SPDX-License-Identifier: MIT OR Apache-2.0

//! Interrupt Descriptor Table (SDM vol. 3A §6.14.1, figure 6-8).
//!
//! One IDT is shared by all CPUs. Every vector points at its entry stub in
//! `trap`; all are interrupt gates, so interrupts stay masked until the
//! handler re-enables them.

use core::arch::asm;
use core::mem::size_of;

use slate_sync::Once;

use super::gdt::{IST_DOUBLE_FAULT, IST_MACHINE_CHECK, IST_NMI, KERNEL_CS};
use super::trap::{self, vector};

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct Gate {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    _reserved: u32,
}

const _: () = assert!(size_of::<Gate>() == 16);

/// Present, 64-bit interrupt gate (type 0xE).
const INTERRUPT_GATE: u8 = 0x8E;
/// Descriptor privilege level 3: `int n` from user mode may use the gate.
const DPL3: u8 = 3 << 5;

impl Gate {
    fn new(handler: u64, ist: u8, dpl3: bool) -> Gate {
        Gate {
            offset_low: handler as u16,
            selector: KERNEL_CS,
            ist,
            type_attr: INTERRUPT_GATE | if dpl3 { DPL3 } else { 0 },
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            _reserved: 0,
        }
    }
}

#[repr(C, align(16))]
struct Idt([Gate; 256]);

#[repr(C, packed(2))]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

static IDT: Once<Idt> = Once::new();

fn build() -> Idt {
    let mut idt = Idt([Gate::default(); 256]);
    for (v, gate) in idt.0.iter_mut().enumerate() {
        let v = v as u64;
        let ist = match v {
            vector::DOUBLE_FAULT => IST_DOUBLE_FAULT,
            vector::NMI => IST_NMI,
            vector::MACHINE_CHECK => IST_MACHINE_CHECK,
            _ => 0,
        };
        // `int3` and `into` must work from user mode (debuggers rely on #BP).
        let dpl3 = matches!(v, vector::BREAKPOINT | vector::OVERFLOW);
        *gate = Gate::new(trap::stub_address(v as u8), ist, dpl3);
    }
    idt
}

/// Build the IDT (once) and load it on this CPU.
pub fn load() {
    assert_eq!(trap::stubs_size(), 256 * trap::STUB_SIZE, "trap stub table has the wrong layout");
    let idt = IDT.call_once(build);
    let ptr = DescriptorTablePointer { limit: (size_of::<Idt>() - 1) as u16, base: idt as *const Idt as u64 };
    // SAFETY: The IDT is 'static and every gate points at a valid entry stub
    // in the kernel code segment.
    unsafe { asm!("lidt [{}]", in(reg) &ptr, options(readonly, nostack, preserves_flags)) };
}
