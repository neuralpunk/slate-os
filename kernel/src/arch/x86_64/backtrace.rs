// SPDX-License-Identifier: MIT OR Apache-2.0

//! Frame-pointer stack walking (the kernel is built with frame pointers
//! forced on; see docs/adr/0002).

use core::arch::asm;

use super::probe;

const MAX_FRAMES: usize = 32;
const HIGHER_HALF: u64 = 0xFFFF_8000_0000_0000;

/// Call `f` with each return address on the current stack, innermost first.
/// Reads go through `probe`, so a corrupt chain ends the walk instead of
/// faulting.
pub fn walk(mut f: impl FnMut(u64)) {
    let mut rbp: u64;
    // SAFETY: Reading RBP has no side effects.
    unsafe { asm!("mov {}, rbp", out(reg) rbp, options(nomem, nostack, preserves_flags)) };
    for _ in 0..MAX_FRAMES {
        if rbp < HIGHER_HALF || !rbp.is_multiple_of(8) {
            break;
        }
        let (Ok(next), Ok(ret)) = (probe::read_u64(rbp), probe::read_u64(rbp + 8)) else { break };
        if ret == 0 {
            break;
        }
        f(ret);
        if next <= rbp {
            break; // Stacks grow down, so callers' frames are at higher addresses.
        }
        rbp = next;
    }
}
