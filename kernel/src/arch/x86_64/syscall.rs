// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `syscall` instruction entry and the first entry into user mode.
//!
//! `syscall` (Intel SDM vol. 2B, SYSCALL) loads CS/SS from IA32_STAR, saves
//! the user RIP in RCX and RFLAGS in R11, masks RFLAGS with IA32_FMASK and
//! jumps to IA32_LSTAR, without switching stacks. The entry stub switches to
//! the thread's kernel stack (from the per-CPU block), builds the same
//! [`TrapFrame`] interrupts use, and returns through the common `iretq`
//! path, so system calls and interrupts share one exit.

use core::arch::{asm, global_asm};

use super::cpu::{rdmsr, wrmsr};
use super::gdt::{KERNEL_CS, USER_CS, USER_DS};
use super::percpu::{KERNEL_RSP_OFFSET, USER_RSP_OFFSET};
use super::trap::TrapFrame;

const MSR_EFER: u32 = 0xC000_0080;
const EFER_SCE: u64 = 1;
const MSR_STAR: u32 = 0xC000_0081;
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_FMASK: u32 = 0xC000_0084;
/// RFLAGS bits cleared on entry: TF, IF, DF, IOPL, NT, AC.
const FMASK: u64 = 0x4_7700;

/// Pseudo vector number marking a system call frame.
pub const SYSCALL_VECTOR: u64 = 0x100;

global_asm!(
    r#"
    .section .text.syscall_entry, "ax"
    .global slate_syscall_entry
slate_syscall_entry:
    swapgs
    mov gs:[{user_rsp}], rsp
    mov rsp, gs:[{kernel_rsp}]
    push {user_ds}
    push qword ptr gs:[{user_rsp}]
    push r11
    push {user_cs}
    push rcx
    push 0
    push {vector}
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
    call slate_syscall_dispatch
    jmp slate_trap_return
"#,
    user_rsp = const USER_RSP_OFFSET,
    kernel_rsp = const KERNEL_RSP_OFFSET,
    user_ds = const USER_DS as u64,
    user_cs = const USER_CS as u64,
    vector = const SYSCALL_VECTOR,
);

unsafe extern "C" {
    fn slate_syscall_entry();
}

/// Program the `syscall` MSRs on this CPU.
pub fn init_cpu() {
    // SYSRET loads CS = STAR[63:48] + 16 and SS = STAR[63:48] + 8; SYSCALL
    // loads CS = STAR[47:32] and SS = STAR[47:32] + 8 (see gdt.rs).
    let star = ((u64::from(USER_CS) - 16) & !3) << 48 | u64::from(KERNEL_CS) << 32;
    // SAFETY: These MSRs exist on every x86-64 CPU; the entry point is the
    // stub above, and the GDT matches the selectors.
    unsafe {
        wrmsr(MSR_STAR, star);
        wrmsr(MSR_LSTAR, slate_syscall_entry as *const () as u64);
        wrmsr(MSR_FMASK, FMASK);
        wrmsr(MSR_EFER, rdmsr(MSR_EFER) | EFER_SCE);
    }
}

#[unsafe(no_mangle)]
extern "C" fn slate_syscall_dispatch(frame: &mut TrapFrame) {
    crate::sched::enter_from_user();
    // SAFETY: The frame is saved; system calls run with interrupts enabled.
    unsafe { asm!("sti", options(nomem, nostack)) };
    // Keep the number for restarting interrupted calls (the error-code slot
    // is unused for system calls).
    frame.error_code = frame.rax;
    crate::abi::syscall(frame);
    crate::sched::preempt_point();
    crate::proc::signal::deliver(frame, true);
    // SAFETY: The shared exit path (`swapgs; iretq`) must not be interrupted.
    unsafe { asm!("cli", options(nomem, nostack)) };
    crate::sched::return_to_user();
}

/// Return to user mode with the registers in `frame` (a fork child's first
/// return). Never returns.
pub fn return_to_user(frame: &TrapFrame) -> ! {
    // Build the frame below everything live on this stack (the caller's
    // frames, and `frame` itself, may sit near the top), then let the
    // common trap exit pop it. Interrupts stay masked from before the
    // frame is written: one taken in between would push its own frame (and
    // a context switch's) right over it, below the stack pointer.
    // SAFETY: Masking interrupts; `iretq` restores the user's flags.
    unsafe { asm!("cli", options(nomem, nostack)) };
    crate::sched::return_to_user();
    let rsp: u64;
    // SAFETY: Reading RSP has no side effects.
    unsafe { asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)) };
    let at = (rsp - size_of::<TrapFrame>() as u64 - 256) & !15;
    // SAFETY: `at` lies below the current stack pointer, in this thread's
    // mapped kernel stack (which has far more than a page left here), so the
    // write clobbers nothing in use. The trap return path pops the
    // `TrapFrame` from `at`, swaps GS (it is a user frame) and `iretq`s.
    unsafe {
        core::ptr::write(at as *mut TrapFrame, frame.clone());
        asm!("mov rsp, {}", "jmp slate_trap_return", in(reg) at, options(noreturn))
    }
}

/// Make `frame` (a system call's) return into a new program image: at
/// `rip` with stack `rsp`, every general-purpose register cleared so
/// nothing of the old image or the kernel leaks. The call then returns
/// through the normal exit path, so the kernel stack unwinds (execve).
pub fn begin_image(frame: &mut TrapFrame, rip: u64, rsp: u64) {
    let (vector, error_code) = (frame.vector, frame.error_code);
    *frame = TrapFrame {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rbp: 0,
        rdi: 0,
        rsi: 0,
        rdx: 0,
        rcx: 0,
        rbx: 0,
        rax: 0,
        vector,
        error_code,
        rip,
        cs: u64::from(USER_CS),
        rflags: 0x202,
        rsp,
        ss: u64::from(USER_DS),
    };
}

/// Leave the kernel for user mode at `rip` with stack `rsp`, never to
/// return on this kernel stack. All general-purpose registers are cleared
/// so nothing from the kernel leaks.
pub fn enter_user(rip: u64, rsp: u64) -> ! {
    let frame = [rip, u64::from(USER_CS), 0x202, rsp, u64::from(USER_DS)];
    // SAFETY: Masking interrupts until `iretq` (which the asm below does
    // anyway); the accounting needs them masked.
    unsafe { asm!("cli", options(nomem, nostack)) };
    crate::sched::return_to_user();
    // SAFETY: `iretq` from this frame switches to ring 3 at `rip`/`rsp` with
    // interrupts enabled; `swapgs` installs the user GS base (kernel GS base
    // goes back into the MSR for the next entry).
    unsafe {
        asm!(
            "cli",
            "mov rsp, {f}",
            "swapgs",
            "xor eax, eax", "xor ebx, ebx", "xor ecx, ecx", "xor edx, edx",
            "xor esi, esi", "xor edi, edi", "xor ebp, ebp",
            "xor r8d, r8d", "xor r9d, r9d", "xor r10d, r10d", "xor r11d, r11d",
            "xor r12d, r12d", "xor r13d, r13d", "xor r14d, r14d", "xor r15d, r15d",
            "iretq",
            f = in(reg) frame.as_ptr(),
            options(noreturn),
        )
    }
}
