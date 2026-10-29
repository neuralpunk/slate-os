// SPDX-License-Identifier: MIT OR Apache-2.0

//! Trap entry: the low-level path from an exception or interrupt into Rust.
//!
//! Every vector has a 16-byte stub at `trap_stubs + 16 * vector`. A stub
//! pushes a zero error code when the CPU does not push one (SDM vol. 3A
//! §6.13, table 6-1 lists the vectors that do), pushes the vector number and
//! jumps to `trap_common`, which saves the general-purpose registers, swaps
//! GS when the trap came from user mode, and calls [`trap_dispatch`] with a
//! [`TrapFrame`].

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use super::{cpu, extable};
use crate::log_debug;

core::arch::global_asm!(
    r#"
    .section .text.trap_entry, "ax"
    .global trap_stubs
    .global trap_stubs_end
    .balign 16
trap_stubs:
    .set vec, 0
    .rept 256
        .balign 16
        .if (vec == 8) || (vec == 10) || (vec == 11) || (vec == 12) || (vec == 13) || (vec == 14) || (vec == 17) || (vec == 21) || (vec == 29) || (vec == 30)
        .else
            push 0
        .endif
        push vec
        jmp trap_common
        .set vec, vec + 1
    .endr
    .balign 16
trap_stubs_end:

trap_common:
    // Stack: vector, error code, then the CPU's frame (rip, cs, ...).
    test qword ptr [rsp + 24], 3
    jz .Lentry_from_kernel
    swapgs
.Lentry_from_kernel:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rdi, rsp
    cld
    call trap_dispatch
    .global slate_trap_return
slate_trap_return:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    test qword ptr [rsp + 24], 3
    jz .Lexit_to_kernel
    swapgs
.Lexit_to_kernel:
    add rsp, 16
    iretq
"#
);

unsafe extern "C" {
    static trap_stubs: u8;
    static trap_stubs_end: u8;
}

/// Size of each entry stub.
pub const STUB_SIZE: u64 = 16;

/// Address of the entry stub for `vector`.
pub fn stub_address(vector: u8) -> u64 {
    (&raw const trap_stubs) as u64 + u64::from(vector) * STUB_SIZE
}

/// Total size of the stub table, for a layout self-check.
pub fn stubs_size() -> u64 {
    (&raw const trap_stubs_end) as u64 - (&raw const trap_stubs) as u64
}

/// Register state saved on trap entry, lowest address first.
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct TrapFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error_code: u64,
    // Pushed by the CPU (SDM vol. 3A §6.14.1, figure 6-9).
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

const _: () = assert!(core::mem::size_of::<TrapFrame>() == 22 * 8);

impl TrapFrame {
    pub fn is_from_user(&self) -> bool {
        self.cs & 3 == 3
    }
}

impl fmt::Display for TrapFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  rip {:#018x}  cs {:#06x}  rflags {:#010x}", self.rip, self.cs, self.rflags)?;
        writeln!(f, "  rsp {:#018x}  ss {:#06x}  error {:#x}", self.rsp, self.ss, self.error_code)?;
        let regs = [
            ("rax", self.rax),
            ("rbx", self.rbx),
            ("rcx", self.rcx),
            ("rdx", self.rdx),
            ("rsi", self.rsi),
            ("rdi", self.rdi),
            ("rbp", self.rbp),
            (" r8", self.r8),
            (" r9", self.r9),
            ("r10", self.r10),
            ("r11", self.r11),
            ("r12", self.r12),
            ("r13", self.r13),
            ("r14", self.r14),
            ("r15", self.r15),
        ];
        for (i, (name, v)) in regs.iter().enumerate() {
            write!(f, "  {name} {v:#018x}")?;
            if i % 3 == 2 {
                writeln!(f)?;
            }
        }
        Ok(())
    }
}

/// Architectural exception vectors (SDM vol. 3A §6.3.1, table 6-1).
#[allow(dead_code)] // A reference table; not every vector has special handling yet.
pub mod vector {
    pub const DIVIDE_ERROR: u64 = 0;
    pub const DEBUG: u64 = 1;
    pub const NMI: u64 = 2;
    pub const BREAKPOINT: u64 = 3;
    pub const OVERFLOW: u64 = 4;
    pub const INVALID_OPCODE: u64 = 6;
    pub const DOUBLE_FAULT: u64 = 8;
    pub const STACK_FAULT: u64 = 12;
    pub const GENERAL_PROTECTION: u64 = 13;
    pub const PAGE_FAULT: u64 = 14;
    pub const MACHINE_CHECK: u64 = 18;
    /// First vector available for external interrupts.
    pub const FIRST_EXTERNAL: u64 = 32;
}

fn exception_name(v: u64) -> &'static str {
    const NAMES: [&str; 32] = [
        "divide error (#DE)",
        "debug (#DB)",
        "non-maskable interrupt",
        "breakpoint (#BP)",
        "overflow (#OF)",
        "BOUND range exceeded (#BR)",
        "invalid opcode (#UD)",
        "device not available (#NM)",
        "double fault (#DF)",
        "coprocessor segment overrun",
        "invalid TSS (#TS)",
        "segment not present (#NP)",
        "stack-segment fault (#SS)",
        "general protection (#GP)",
        "page fault (#PF)",
        "reserved (15)",
        "x87 floating-point error (#MF)",
        "alignment check (#AC)",
        "machine check (#MC)",
        "SIMD floating-point (#XM)",
        "virtualization (#VE)",
        "control protection (#CP)",
        "reserved (22)",
        "reserved (23)",
        "reserved (24)",
        "reserved (25)",
        "reserved (26)",
        "reserved (27)",
        "hypervisor injection (#HV)",
        "VMM communication (#VC)",
        "security (#SX)",
        "reserved (31)",
    ];
    NAMES.get(v as usize).copied().unwrap_or("external interrupt")
}

/// Exceptions a kernel instruction listed in the exception table may raise
/// and recover from (see `extable`).
fn recoverable(v: u64) -> bool {
    matches!(
        v,
        vector::DIVIDE_ERROR
            | vector::INVALID_OPCODE
            | vector::STACK_FAULT
            | vector::GENERAL_PROTECTION
            | vector::PAGE_FAULT
    )
}

static BREAKPOINTS: AtomicU64 = AtomicU64::new(0);

/// Number of breakpoint exceptions handled since boot.
pub fn breakpoint_count() -> u64 {
    BREAKPOINTS.load(Ordering::Relaxed)
}

/// CPU-time accounting around a trap from user mode: entering charges the
/// user time so far, leaving (on every return path) the kernel time.
struct UserEntry(bool);

impl UserEntry {
    fn new(from_user: bool) -> UserEntry {
        if from_user {
            crate::sched::enter_from_user();
        }
        UserEntry(from_user)
    }
}

impl Drop for UserEntry {
    fn drop(&mut self) {
        if self.0 {
            crate::sched::return_to_user();
        }
    }
}

/// Called from `trap_common` with interrupts disabled (all IDT entries are
/// interrupt gates) on the kernel stack, or on an IST stack for #DF, NMI
/// and #MC.
#[unsafe(no_mangle)]
extern "C" fn trap_dispatch(frame: &mut TrapFrame) {
    if super::paging::smap_enabled() {
        // RFLAGS.AC survives exception delivery; a fault inside a user copy
        // must not leave user memory open to the handler. `iretq` restores
        // the interrupted context's AC.
        // SAFETY: `clac` only re-arms SMAP.
        unsafe { core::arch::asm!("clac", options(nomem, nostack)) };
    }
    // CPU time: the user's until here, the kernel's until the return.
    let _user = UserEntry::new(frame.is_from_user());
    let v = frame.vector;
    if v == vector::BREAKPOINT && !frame.is_from_user() {
        BREAKPOINTS.fetch_add(1, Ordering::Relaxed);
        log_debug!("breakpoint at {:#x}", frame.rip - 1);
        return;
    }
    if v == vector::PAGE_FAULT && cpu::cr2() < super::uaccess::USER_END {
        let (addr, e) = (cpu::cr2(), frame.error_code);
        // Demand paging, for user code and for kernel accesses to user
        // memory. Paging in may sleep on I/O, so interrupts come back on
        // if the faulting code had them on (it then holds no spinlock).
        let irqs = frame.rflags & (1 << 9) != 0;
        if irqs {
            // SAFETY: Interrupts were on where the fault happened, so no
            // interrupt-masking lock was held there, and none is held here.
            unsafe { cpu::enable_interrupts() };
        }
        let fixed = crate::proc::handle_page_fault(addr, e & 2 != 0, e & 0x10 != 0, frame.is_from_user());
        if irqs {
            cpu::disable_interrupts();
        }
        if fixed {
            // A fault the out-of-memory killer resolved by killing this
            // process: SIGKILL is pending.
            if frame.is_from_user() {
                crate::proc::signal::deliver(frame, false);
            }
            return;
        }
    }
    if v < vector::FIRST_EXTERNAL && frame.is_from_user() && !matches!(v, vector::NMI | vector::MACHINE_CHECK) {
        // A fault in user code becomes a signal (SIGSEGV, SIGILL, ...),
        // delivered before returning to user mode.
        let addr = if v == vector::PAGE_FAULT { cpu::cr2() } else { 0 };
        crate::proc::user_exception(v, frame.error_code, frame.rip, frame.rsp, addr);
        crate::proc::log_fault_registers(&[
            ("rax", frame.rax),
            ("rbx", frame.rbx),
            ("rcx", frame.rcx),
            ("rdx", frame.rdx),
            ("rsi", frame.rsi),
            ("rdi", frame.rdi),
            ("rbp", frame.rbp),
            ("r8", frame.r8),
            ("r12", frame.r12),
            ("r13", frame.r13),
        ]);
        crate::proc::signal::deliver(frame, false);
        return;
    }
    if v < vector::FIRST_EXTERNAL {
        if !frame.is_from_user()
            && recoverable(v)
            && let Some(fixup) = extable::fixup_for(frame.rip)
        {
            let addr = if v == vector::PAGE_FAULT { cpu::cr2() } else { 0 };
            extable::apply(frame, fixup, addr);
            return;
        }
        fatal(frame);
    }
    if v == u64::from(super::irq::TIMER_VECTOR) {
        crate::proc::profile::sample(frame.rip, frame.is_from_user());
    }
    super::irq::dispatch(v as u8);
    // Preempt only if the interrupted code ran with interrupts enabled: then
    // it holds no interrupt-masking lock.
    if frame.rflags & (1 << 9) != 0 {
        crate::sched::preempt_point();
    }
    if frame.is_from_user() {
        crate::proc::signal::deliver(frame, false);
    }
}

fn fatal(frame: &TrapFrame) -> ! {
    let v = frame.vector;
    let mode = if frame.is_from_user() { "user" } else { "kernel" };
    if v == vector::PAGE_FAULT {
        let e = frame.error_code;
        // Error code bits: SDM vol. 3A §4.7, figure 4-12.
        let access = if e & 0x10 != 0 {
            "instruction fetch from"
        } else if e & 2 != 0 {
            "write to"
        } else {
            "read of"
        };
        let cause = if e & 1 != 0 { "protection violation" } else { "page not present" };
        panic!(
            "{} in {mode} mode at {:#x}: {access} {:#x} ({cause})\n{frame}",
            exception_name(v),
            frame.rip,
            cpu::cr2(),
        );
    }
    if v == vector::INVALID_OPCODE && !frame.is_from_user() && is_kcfi_trap(frame.rip) {
        panic!(
            "control-flow integrity check failed at {:#x}: an indirect call to a function of another type (KCFI)\n{frame}",
            frame.rip
        );
    }
    panic!("{} in {mode} mode at {:#x}\n{frame}", exception_name(v), frame.rip);
}

unsafe extern "C" {
    // The linker script's bounds of `.kcfi_traps` (ADR 0096).
    static __kcfi_traps_start: i32;
    static __kcfi_traps_end: i32;
}

/// Whether `rip` is one of KCFI's traps: LLVM lists each as a 32-bit
/// offset from its entry in `.kcfi_traps`.
fn is_kcfi_trap(rip: u64) -> bool {
    let (start, end) = (&raw const __kcfi_traps_start, &raw const __kcfi_traps_end);
    // SAFETY: The linker script puts only the 32-bit entries between the
    // two symbols, in read-only data.
    let entries = unsafe { core::slice::from_raw_parts(start, end.offset_from_unsigned(start)) };
    entries.iter().any(|e| (e as *const i32 as u64).wrapping_add(*e as i64 as u64) == rip)
}
