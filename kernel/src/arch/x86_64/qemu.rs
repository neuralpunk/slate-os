// SPDX-License-Identifier: MIT OR Apache-2.0

//! Leaving QEMU through its `isa-debug-exit` device.
//!
//! `cargo xtask` starts QEMU with `-device isa-debug-exit,iobase=0xf4,iosize=0x04`.
//! Writing `v` to the port makes QEMU exit with status `(v << 1) | 1`.

use super::port::Port32;

pub const DEBUG_EXIT_PORT: u16 = 0xf4;

/// Values written to the exit port. Success leaves QEMU with status 33 and
/// failure with 35; the host harness maps those back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ExitCode {
    Success = 0x10,
    Failure = 0x11,
}

/// Exit QEMU, or halt if the exit device is absent (for example on real
/// hardware, where port 0xf4 is unused).
pub fn exit(code: ExitCode) -> ! {
    // SAFETY: Port 0xf4 is the QEMU debug-exit device or unused; writing it
    // has no effect on memory.
    let port = unsafe { Port32::new(DEBUG_EXIT_PORT) };
    port.write(code as u32);
    super::halt_forever();
}
