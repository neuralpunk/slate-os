// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exception table: kernel instructions that are allowed to fault.
//!
//! An instruction that may fault on purpose (probing an address, and later
//! copying from user memory) records `(instruction, fixup)` in the
//! `.slate_extable` section, each as a 32-bit offset from the field itself
//! (`.long 2b - ., 3b - .`): the table needs no relocation wherever the
//! kernel is loaded (KASLR, ADR 0095). When it faults, the trap handler resumes at
//! `fixup` instead of panicking, with these registers set:
//!
//! | Register | Value |
//! |---|---|
//! | `r11` | 1 (it is 0 on the non-faulting path) |
//! | `rax` | exception vector |
//! | `rcx` | error code |
//! | `rsi` | faulting address for #PF, else 0 |

use super::trap::TrapFrame;

#[repr(C)]
struct Entry {
    insn: i32,
    fixup: i32,
}

impl Entry {
    fn at(field: &i32) -> u64 {
        (field as *const i32 as u64).wrapping_add(*field as i64 as u64)
    }

    fn insn(&self) -> u64 {
        Self::at(&self.insn)
    }

    fn fixup(&self) -> u64 {
        Self::at(&self.fixup)
    }
}

unsafe extern "C" {
    // Defined by the linker script around the `.slate_extable` input sections.
    static __extable_start: Entry;
    static __extable_end: Entry;
}

fn entries() -> &'static [Entry] {
    let start = &raw const __extable_start;
    let end = &raw const __extable_end;
    // SAFETY: The linker script places only `Entry` records (two `.long`s,
    // 4-byte aligned) between the two symbols, and the section is read-only.
    unsafe { core::slice::from_raw_parts(start, end.offset_from_unsigned(start)) }
}

/// The fixup address for a faulting instruction, if it has one.
pub fn fixup_for(rip: u64) -> Option<u64> {
    entries().iter().find(|e| e.insn() == rip).map(Entry::fixup)
}

/// Redirect `frame` to `fixup`, reporting the fault in registers.
pub fn apply(frame: &mut TrapFrame, fixup: u64, fault_addr: u64) {
    frame.rip = fixup;
    frame.r11 = 1;
    frame.rax = frame.vector;
    frame.rcx = frame.error_code;
    frame.rsi = fault_addr;
}

/// Number of registered entries.
pub fn len() -> usize {
    entries().len()
}
