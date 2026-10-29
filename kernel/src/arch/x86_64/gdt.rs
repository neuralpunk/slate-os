// SPDX-License-Identifier: MIT OR Apache-2.0

//! Global Descriptor Table and Task State Segment.
//!
//! Descriptor formats: Intel SDM vol. 3A §3.4.5 (segment descriptors),
//! §8.2.3 (64-bit TSS descriptor), §8.7 (64-bit TSS layout).
//!
//! Selector layout (see docs/adr/0005-gdt-layout.md). User selectors match the
//! values Linux programs observe (`cs` = 0x33, `ss` = 0x2b in signal frames
//! and ptrace), and the order is the one `syscall`/`sysret` require:
//!
//! | Index | Selector | Descriptor |
//! |---|---|---|
//! | 0 | 0x00 | null |
//! | 1 | 0x08 | kernel code, 64-bit |
//! | 2 | 0x10 | kernel data |
//! | 3 | 0x18 | null (unused) |
//! | 4 | 0x23 | user code, 32-bit (compat mode) |
//! | 5 | 0x2b | user data |
//! | 6 | 0x33 | user code, 64-bit |
//! | 7–8 | 0x38 | TSS (16-byte system descriptor) |

use core::arch::asm;
use core::cell::UnsafeCell;
use core::mem::size_of;

pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
// User selectors are loaded by the return-to-user path (M5).
#[allow(dead_code)]
pub const USER32_CS: u16 = 0x20 | 3;
#[allow(dead_code)]
pub const USER_DS: u16 = 0x28 | 3;
#[allow(dead_code)]
pub const USER_CS: u16 = 0x30 | 3;
pub const TSS_SEL: u16 = 0x38;

/// Interrupt Stack Table slots (1-based, as encoded in IDT entries).
pub const IST_DOUBLE_FAULT: u8 = 1;
pub const IST_NMI: u8 = 2;
pub const IST_MACHINE_CHECK: u8 = 3;
pub const IST_COUNT: usize = 3;

const IST_STACK_SIZE: usize = 16 * 1024;

// Flat 64-bit segment descriptors (SDM vol. 3A §3.4.5, §5.2.1): base 0,
// limit 0xFFFFF with G=1. Access byte: P | DPL | S | type; flags: G | L or D/B.
const KERNEL_CODE64: u64 = 0x00AF_9B00_0000_FFFF; // P DPL0 code exec/read accessed, L=1
const KERNEL_DATA: u64 = 0x00CF_9300_0000_FFFF; // P DPL0 data read/write accessed
const USER_CODE32: u64 = 0x00CF_FB00_0000_FFFF; // P DPL3 code, D=1
const USER_DATA: u64 = 0x00CF_F300_0000_FFFF; // P DPL3 data
const USER_CODE64: u64 = 0x00AF_FB00_0000_FFFF; // P DPL3 code, L=1

/// The 64-bit TSS (SDM vol. 3A §8.7, figure 8-11).
#[derive(Debug)]
#[repr(C, packed(4))]
pub struct Tss {
    _reserved0: u32,
    /// Stack pointers loaded on a privilege change to ring 0..2.
    pub rsp: [u64; 3],
    _reserved1: u64,
    /// Interrupt Stack Table: IST1..IST7.
    pub ist: [u64; 7],
    _reserved2: u64,
    _reserved3: u16,
    /// Offset of the I/O permission bitmap; past the limit means "none".
    pub iomap_base: u16,
}

const _: () = assert!(size_of::<Tss>() == 104);

#[repr(C, align(16))]
struct Gdt([u64; 9]);

#[repr(C, packed(2))]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

/// A stack for an IST slot. Written only by the CPU while handling the
/// exception it serves.
#[repr(C, align(16))]
struct IstStack(UnsafeCell<[u8; IST_STACK_SIZE]>);

// SAFETY: The memory is only ever used as a stack by the CPU that owns the
// TSS pointing at it; Rust code never forms references into it.
unsafe impl Sync for IstStack {}

impl IstStack {
    const fn new() -> IstStack {
        IstStack(UnsafeCell::new([0; IST_STACK_SIZE]))
    }

    fn top(&self) -> u64 {
        self.0.get() as u64 + IST_STACK_SIZE as u64
    }
}

/// One CPU's GDT and TSS. They must live forever at a fixed address once
/// loaded, so they are statics (bootstrap CPU) or leaked boxes (others).
#[derive(Debug)]
pub struct CpuTables {
    gdt: UnsafeCell<Gdt>,
    tss: UnsafeCell<Tss>,
}

// SAFETY: Only the CPU that loaded the tables modifies its TSS (through
// `set_ist`/`set_rsp0`), and the CPU itself reads it; the GDT is written once
// before it is loaded.
unsafe impl Sync for CpuTables {}

impl CpuTables {
    pub const fn new() -> CpuTables {
        CpuTables {
            gdt: UnsafeCell::new(Gdt([0; 9])),
            tss: UnsafeCell::new(Tss {
                _reserved0: 0,
                rsp: [0; 3],
                _reserved1: 0,
                ist: [0; 7],
                _reserved2: 0,
                _reserved3: 0,
                iomap_base: size_of::<Tss>() as u16,
            }),
        }
    }

    /// Point IST slot `slot` (1-based) at a new stack top.
    pub fn set_ist(&self, slot: u8, top: u64) {
        // SAFETY: Called only on the owning CPU, which reads the TSS only on
        // interrupt delivery; a single aligned 8-byte store is atomic with
        // respect to that.
        unsafe { (&raw mut (*self.tss.get()).ist[slot as usize - 1]).write_unaligned(top) };
    }

    /// Set the stack loaded on entry to ring 0 from user mode.
    pub fn set_rsp0(&self, top: u64) {
        // SAFETY: As in `set_ist`.
        unsafe { (&raw mut (*self.tss.get()).rsp[0]).write_unaligned(top) };
    }

    /// Fill in the GDT and TSS, then load them on this CPU: reload every
    /// segment register and the task register.
    ///
    /// `ist_tops` gives the initial IST1..IST3 stacks.
    pub fn load(&'static self, ist_tops: [u64; IST_COUNT]) {
        for (i, top) in ist_tops.into_iter().enumerate() {
            self.set_ist(i as u8 + 1, top);
        }
        let [tss_lo, tss_hi] = tss_descriptor(self.tss.get());
        // SAFETY: The GDT is not loaded yet (or loaded on no CPU), so nothing
        // reads it while it is written.
        unsafe {
            *self.gdt.get() =
                Gdt([0, KERNEL_CODE64, KERNEL_DATA, 0, USER_CODE32, USER_DATA, USER_CODE64, tss_lo, tss_hi])
        };
        let ptr = DescriptorTablePointer { limit: (size_of::<Gdt>() - 1) as u16, base: self.gdt.get() as u64 };
        // SAFETY: The GDT is 'static and its code/data descriptors match the
        // segments currently in use (flat 64-bit), so reloading them keeps
        // execution and memory accesses unchanged. CS is reloaded with a far
        // return. FS/GS selectors become null; the GS base is set up afterwards
        // by `percpu`. The TSS descriptor points at a 'static TSS.
        unsafe {
            asm!(
                "lgdt [{ptr}]",
                "push {cs}",
                "lea {tmp}, [rip + 2f]",
                "push {tmp}",
                "retfq",
                "2:",
                "mov ds, {ds:x}",
                "mov es, {ds:x}",
                "mov ss, {ds:x}",
                "mov fs, {null:x}",
                "mov gs, {null:x}",
                "ltr {tss:x}",
                ptr = in(reg) &ptr,
                cs = in(reg) u64::from(KERNEL_CS),
                ds = in(reg) KERNEL_DS,
                null = in(reg) 0u16,
                tss = in(reg) TSS_SEL,
                tmp = out(reg) _,
            );
        }
    }
}

impl Default for CpuTables {
    fn default() -> Self {
        Self::new()
    }
}

// Bootstrap CPU tables. Its first IST stacks are static (no guard pages)
// because exceptions must work before memory management exists;
// `arch::init_bsp_late` replaces them with guarded stacks.
static BSP_IST_STACKS: [IstStack; IST_COUNT] = [IstStack::new(), IstStack::new(), IstStack::new()];
pub static BSP_TABLES: CpuTables = CpuTables::new();

fn tss_descriptor(tss: *const Tss) -> [u64; 2] {
    let base = tss as u64;
    let limit = (size_of::<Tss>() - 1) as u64;
    let low = (limit & 0xFFFF)
        | ((base & 0xFF_FFFF) << 16)
        | (0x89 << 40) // P=1, DPL=0, type 9 = available 64-bit TSS
        | (((limit >> 16) & 0xF) << 48)
        | (((base >> 24) & 0xFF) << 56);
    [low, base >> 32]
}

/// Load the bootstrap CPU's GDT and TSS.
pub fn init_bsp() {
    BSP_TABLES.load([BSP_IST_STACKS[0].top(), BSP_IST_STACKS[1].top(), BSP_IST_STACKS[2].top()]);
}
