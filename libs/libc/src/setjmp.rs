// SPDX-License-Identifier: MIT OR Apache-2.0

//! <setjmp.h> (C11 7.13, POSIX sigsetjmp; ADR 0075). A `jmp_buf` holds
//! what the x86-64 psABI (§3.2.1) says a called function must preserve:
//! rbx, rbp, r12 to r15 and the stack pointer, plus the return address.
//! setjmp saves them as its caller will see them after it returns;
//! longjmp puts them back and "returns" from setjmp again with a nonzero
//! value. sigsetjmp also keeps the signal mask when asked, and siglongjmp
//! restores it.

use core::ffi::c_int;

/// `jmp_buf` and `sigjmp_buf` (one type; C sees an array of one).
#[repr(C)]
pub struct JmpBuf {
    /// rbx, rbp, r12, r13, r14, r15, rsp, rip.
    regs: [u64; 8],
    /// Whether `mask` was saved (sigsetjmp).
    saved: u64,
    mask: u64,
}

#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".globl setjmp",
    ".globl _setjmp",
    ".globl sigsetjmp",
    ".globl longjmp",
    ".globl _longjmp",
    ".type setjmp, @function",
    ".type _setjmp, @function",
    ".type sigsetjmp, @function",
    ".type longjmp, @function",
    ".type _longjmp, @function",
    "setjmp:",
    "_setjmp:",
    "    mov qword ptr [rdi], rbx",
    "    mov qword ptr [rdi + 8], rbp",
    "    mov qword ptr [rdi + 16], r12",
    "    mov qword ptr [rdi + 24], r13",
    "    mov qword ptr [rdi + 32], r14",
    "    mov qword ptr [rdi + 40], r15",
    // The caller's stack pointer after the return, and where it returns.
    "    lea rdx, [rsp + 8]",
    "    mov qword ptr [rdi + 48], rdx",
    "    mov rdx, qword ptr [rsp]",
    "    mov qword ptr [rdi + 56], rdx",
    "    mov qword ptr [rdi + 64], 0",
    "    xor eax, eax",
    "    ret",
    // sigsetjmp(env, savemask): the same, then the mask in Rust, which
    // returns 0 straight to sigsetjmp's caller.
    "sigsetjmp:",
    "    mov qword ptr [rdi], rbx",
    "    mov qword ptr [rdi + 8], rbp",
    "    mov qword ptr [rdi + 16], r12",
    "    mov qword ptr [rdi + 24], r13",
    "    mov qword ptr [rdi + 32], r14",
    "    mov qword ptr [rdi + 40], r15",
    "    lea rdx, [rsp + 8]",
    "    mov qword ptr [rdi + 48], rdx",
    "    mov rdx, qword ptr [rsp]",
    "    mov qword ptr [rdi + 56], rdx",
    "    jmp {save}",
    // longjmp(env, val): val, or 1 for 0.
    "longjmp:",
    "_longjmp:",
    "    mov eax, esi",
    "    test eax, eax",
    "    jnz .Lslate_longjmp_go",
    "    inc eax",
    ".Lslate_longjmp_go:",
    "    mov rbx, qword ptr [rdi]",
    "    mov rbp, qword ptr [rdi + 8]",
    "    mov r12, qword ptr [rdi + 16]",
    "    mov r13, qword ptr [rdi + 24]",
    "    mov r14, qword ptr [rdi + 32]",
    "    mov r15, qword ptr [rdi + 40]",
    "    mov rsp, qword ptr [rdi + 48]",
    "    jmp qword ptr [rdi + 56]",
    save = sym sigsetjmp_save,
);

/// The rest of sigsetjmp: remember the mask if asked; 0 for its caller.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
extern "C" fn sigsetjmp_save(env: *mut JmpBuf, savemask: c_int) -> c_int {
    // SAFETY: sigsetjmp passes the caller's buffer.
    let env = unsafe { &mut *env };
    env.saved = 0;
    if savemask != 0
        && let Ok(m) = slate_rt::signal::block(0)
    {
        env.mask = m;
        env.saved = 1;
    }
    0
}

#[cfg(target_os = "none")]
unsafe extern "C" {
    fn longjmp(env: *mut JmpBuf, val: c_int) -> !;
}

/// siglongjmp: the saved mask back, then longjmp.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn siglongjmp(env: *mut JmpBuf, val: c_int) -> ! {
    // SAFETY: C passes a buffer filled by sigsetjmp.
    unsafe {
        if (*env).saved != 0 {
            let _ = slate_rt::signal::set_mask((*env).mask);
        }
        longjmp(env, val)
    }
}
