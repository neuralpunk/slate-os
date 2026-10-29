// SPDX-License-Identifier: MIT OR Apache-2.0

//! Kernel context switching.
//!
//! A suspended thread's kernel stack holds its callee-saved registers
//! (System V AMD64 ABI §3.2.1: rbx, rbp, r12-r15) and a return address; the
//! thread's saved stack pointer points at them. Caller-saved registers are
//! already saved by the compiler around the call to `switch_context`.

core::arch::global_asm!(
    r#"
    .section .text.context, "ax"
    .global slate_switch_context
slate_switch_context:
    // rdi = where to store the old stack pointer, rsi = new stack pointer.
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [rdi], rsp
    mov rsp, rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

    .global slate_thread_trampoline
slate_thread_trampoline:
    // First return of a new thread. The stack pointer is 16-byte aligned
    // here; r12 carries the argument for the Rust entry function.
    mov rdi, r12
    xor ebp, ebp
    call slate_thread_entry
    ud2
"#
);

unsafe extern "C" {
    fn slate_switch_context(old_rsp: *mut u64, new_rsp: u64);
    fn slate_thread_trampoline();
}

/// Save the current context into `*old_rsp` and resume the context saved at
/// `new_rsp`. Returns when something switches back to the saved context.
///
/// # Safety
///
/// `new_rsp` must be a stack pointer saved by this function or prepared by
/// [`prepare_stack`], on a stack that stays alive and is not in use by any
/// other CPU; `old_rsp` must stay valid until this context is resumed.
pub unsafe fn switch_context(old_rsp: *mut u64, new_rsp: u64) {
    // SAFETY: Forwarded to the caller.
    unsafe { slate_switch_context(old_rsp, new_rsp) }
}

/// Lay out a new thread's stack so that switching to the returned stack
/// pointer calls `slate_thread_entry(arg)`.
///
/// # Safety
///
/// `top` must be the 16-byte aligned top of a mapped stack with at least
/// 64 bytes free, owned by the new thread.
pub unsafe fn prepare_stack(top: u64, arg: u64) -> u64 {
    let frame = [0u64, 0, 0, arg, 0, 0, slate_thread_trampoline as *const () as u64]; // r15 r14 r13 r12 rbx rbp ret
    let rsp = top - (frame.len() as u64) * 8;
    // SAFETY: The caller guarantees the stack is mapped and ours.
    unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), rsp as *mut u64, frame.len()) };
    rsp
}

/// Architectural user-mode state of a thread that lives outside the trap
/// frame: segment bases and the FPU/SIMD registers.
#[derive(Debug)]
pub struct UserState {
    fs_base: u64,
    gs_base: u64,
    fpu: super::fpu::FpuState,
}

/// Per-thread architecture state, touched only by the CPU running the
/// thread (or switching it in or out).
#[derive(Debug, Default)]
pub struct ArchThread(core::cell::UnsafeCell<Option<UserState>>);

// SAFETY: Accessed only by the CPU that owns the thread at that moment; the
// scheduler's `on_cpu` protocol makes that exclusive.
unsafe impl Sync for ArchThread {}

const MSR_FS_BASE: u32 = 0xC000_0100;
const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;

impl ArchThread {
    /// Give the (current) thread fresh user state: zero segment bases and
    /// the reset FPU state, loaded into the CPU.
    pub fn init_user(&self) {
        let u = UserState { fs_base: 0, gs_base: 0, fpu: super::fpu::FpuState::new() };
        // Masked: a switch between loading the registers and recording the
        // state would neither save nor restore them, and the thread would
        // return to user mode with another thread's FS base.
        let _irq = super::cpu::InterruptGuard::new();
        u.fpu.restore();
        // SAFETY: Called by the thread itself; see the `Sync` impl.
        unsafe {
            super::cpu::wrmsr(MSR_FS_BASE, 0);
            super::cpu::wrmsr(MSR_KERNEL_GS_BASE, 0);
            *self.0.get() = Some(u);
        }
    }

    /// Save user state when switching away from this thread.
    pub fn switch_out(&self) {
        // SAFETY: See the `Sync` impl. While in the kernel, IA32_KERNEL_GS_BASE
        // holds the user GS base (swapped on entry).
        unsafe {
            if let Some(u) = &mut *self.0.get() {
                u.fs_base = super::cpu::rdmsr(MSR_FS_BASE);
                u.gs_base = super::cpu::rdmsr(MSR_KERNEL_GS_BASE);
                u.fpu.save();
            }
        }
    }

    /// Restore user state when switching to this thread.
    pub fn switch_in(&self) {
        // SAFETY: See the `Sync` impl.
        unsafe {
            if let Some(u) = &*self.0.get() {
                super::cpu::wrmsr(MSR_FS_BASE, u.fs_base);
                super::cpu::wrmsr(MSR_KERNEL_GS_BASE, u.gs_base);
                u.fpu.restore();
            }
        }
    }
}

/// A snapshot of a user thread's architectural state, for fork(2).
#[derive(Debug)]
pub struct ForkState {
    fs_base: u64,
    gs_base: u64,
    fpu: super::fpu::FpuState,
}

impl ForkState {
    /// Give the new thread a different FS base (CLONE_SETTLS).
    pub fn set_fs_base(&mut self, v: u64) {
        self.fs_base = v;
    }
}

impl ArchThread {
    /// Capture the running (current) thread's user state.
    pub fn fork_state(&self) -> ForkState {
        let fpu = super::fpu::FpuState::new();
        fpu.save();
        // SAFETY: Reading FS base and kernel GS base (the user GS base while
        // in the kernel) has no side effects.
        unsafe {
            ForkState { fs_base: super::cpu::rdmsr(MSR_FS_BASE), gs_base: super::cpu::rdmsr(MSR_KERNEL_GS_BASE), fpu }
        }
    }

    /// Become a user thread with `state` (the current thread, in a fork
    /// child), loading it into the CPU.
    pub fn adopt(&self, state: ForkState) {
        // Masked, as in `init_user`.
        let _irq = super::cpu::InterruptGuard::new();
        state.fpu.restore();
        // SAFETY: Called by the thread itself; see the `Sync` impl.
        unsafe {
            super::cpu::wrmsr(MSR_FS_BASE, state.fs_base);
            super::cpu::wrmsr(MSR_KERNEL_GS_BASE, state.gs_base);
            *self.0.get() = Some(UserState { fs_base: state.fs_base, gs_base: state.gs_base, fpu: state.fpu });
        }
    }

    /// The current FPU registers as bytes, for a signal frame.
    pub fn save_fpu_for_signal(&self) -> alloc::vec::Vec<u8> {
        let tmp = super::fpu::FpuState::new();
        tmp.save();
        tmp.bytes().to_vec()
    }

    /// Load FPU registers from a signal frame (validated; see
    /// `FpuState::load_bytes`).
    pub fn restore_fpu_from_signal(&self, bytes: &[u8]) {
        let tmp = super::fpu::FpuState::new();
        tmp.load_bytes(bytes);
        tmp.restore();
    }
}

/// Set the running thread's FS base (`arch_prctl(ARCH_SET_FS)`).
pub fn set_fs_base(v: u64) {
    // SAFETY: FS base only affects user-mode FS-relative accesses (the
    // kernel does not use FS).
    unsafe { super::cpu::wrmsr(MSR_FS_BASE, v) };
}

/// Set the running thread's user GS base: while in the kernel it is in
/// IA32_KERNEL_GS_BASE, which `swapgs` makes GS again on the way out.
pub fn set_user_gs_base(v: u64) {
    // SAFETY: IA32_KERNEL_GS_BASE holds the user's GS base while in the
    // kernel (the kernel's per-CPU base is in IA32_GS_BASE); it is saved
    // and restored with the thread on a switch.
    unsafe { super::cpu::wrmsr(MSR_KERNEL_GS_BASE, v) };
}

pub fn fs_base() -> u64 {
    // SAFETY: Reading FS base has no side effects.
    unsafe { super::cpu::rdmsr(MSR_FS_BASE) }
}
