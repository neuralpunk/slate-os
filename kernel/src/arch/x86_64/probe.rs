// SPDX-License-Identifier: MIT OR Apache-2.0

//! Memory and instruction probes that report faults instead of panicking,
//! built on the exception table (`extable`).

use core::arch::asm;

/// A fault caught by a probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    pub vector: u64,
    pub error_code: u64,
    /// Faulting linear address for page faults, else 0.
    pub address: u64,
}

/// Turn the register convention of `extable` into a `Result`.
fn result<T>(faulted: u64, value: T, regs: (u64, u64, u64)) -> Result<T, Fault> {
    let (vector, error_code, address) = regs;
    if faulted == 0 { Ok(value) } else { Err(Fault { vector, error_code, address }) }
}

/// Read one byte at `addr`, or report the fault.
pub fn read_u8(addr: u64) -> Result<u8, Fault> {
    let (faulted, rax, rcx, rsi): (u64, u64, u64, u64);
    // SAFETY: The read either succeeds without side effects (the kernel does
    // not probe MMIO with read side effects) or faults and resumes at label 3
    // through the exception table, which sets r11/rax/rcx/rsi.
    unsafe {
        asm!(
            "2: movzx eax, byte ptr [{addr}]",
            "3:",
            ".pushsection .slate_extable, \"a\"",
            ".balign 4",
            ".long 2b - ., 3b - .",
            ".popsection",
            addr = in(reg) addr,
            inout("r11") 0u64 => faulted,
            out("rax") rax,
            out("rcx") rcx,
            out("rsi") rsi,
            options(nostack, readonly),
        );
    }
    result(faulted, rax as u8, (rax, rcx, rsi))
}

/// Read an aligned 64-bit word at `addr`, or report the fault.
pub fn read_u64(addr: u64) -> Result<u64, Fault> {
    let (faulted, rax, rcx, rsi): (u64, u64, u64, u64);
    // SAFETY: As for `read_u8`.
    unsafe {
        asm!(
            "2: mov rax, qword ptr [{addr}]",
            "3:",
            ".pushsection .slate_extable, \"a\"",
            ".balign 4",
            ".long 2b - ., 3b - .",
            ".popsection",
            addr = in(reg) addr,
            inout("r11") 0u64 => faulted,
            out("rax") rax,
            out("rcx") rcx,
            out("rsi") rsi,
            options(nostack, readonly),
        );
    }
    result(faulted, rax, (rax, rcx, rsi))
}

/// Execute `ud2` and report the resulting #UD (always an `Err`). Used to test
/// the exception path.
pub fn invalid_opcode() -> Result<(), Fault> {
    let (faulted, rax, rcx, rsi): (u64, u64, u64, u64);
    // SAFETY: `ud2` always raises #UD, which resumes at label 3 through the
    // exception table.
    unsafe {
        asm!(
            "2: ud2",
            "3:",
            ".pushsection .slate_extable, \"a\"",
            ".balign 4",
            ".long 2b - ., 3b - .",
            ".popsection",
            inout("r11") 0u64 => faulted,
            out("rax") rax,
            out("rcx") rcx,
            out("rsi") rsi,
            options(nomem, nostack),
        );
    }
    result(faulted, (), (rax, rcx, rsi))
}

/// Unsigned 64-bit division with the hardware `div`, reporting #DE for a
/// zero divisor instead of panicking. Used to test the exception path.
pub fn divide(dividend: u64, divisor: u64) -> Result<u64, Fault> {
    let (faulted, rax, rcx, rsi): (u64, u64, u64, u64);
    // SAFETY: `div` either succeeds or raises #DE, which resumes at label 3
    // through the exception table.
    unsafe {
        asm!(
            "2: div {d}",
            "3:",
            ".pushsection .slate_extable, \"a\"",
            ".balign 4",
            ".long 2b - ., 3b - .",
            ".popsection",
            d = in(reg) divisor,
            inout("r11") 0u64 => faulted,
            inout("rax") dividend => rax,
            inout("rdx") 0u64 => _,
            out("rcx") rcx,
            out("rsi") rsi,
            options(nomem, nostack),
        );
    }
    result(faulted, rax, (rax, rcx, rsi))
}

/// Write one byte at `addr`, or report the fault.
///
/// # Safety
///
/// If the write succeeds it modifies memory at `addr`: the caller must own
/// that byte (or be deliberately testing a mapping that must reject it).
pub unsafe fn write_u8(addr: u64, value: u8) -> Result<(), Fault> {
    let (faulted, rax, rcx, rsi): (u64, u64, u64, u64);
    // SAFETY: The caller vouches for the write; a fault resumes at label 3
    // through the exception table.
    unsafe {
        asm!(
            "2: mov byte ptr [{addr}], {v}",
            "3:",
            ".pushsection .slate_extable, \"a\"",
            ".balign 4",
            ".long 2b - ., 3b - .",
            ".popsection",
            addr = in(reg) addr,
            v = in(reg_byte) value,
            inout("r11") 0u64 => faulted,
            out("rax") rax,
            out("rcx") rcx,
            out("rsi") rsi,
            options(nostack),
        );
    }
    result(faulted, (), (rax, rcx, rsi))
}
