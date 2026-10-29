// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-rt: the runtime under Slate's own programs (ADR 0018). No libc:
//! programs make system calls directly: Slate's native ones on Slate
//! (ADR 0031) and Linux ones on Linux, chosen at start-up, so one binary
//! runs on both. A program crate provides `fn main() -> i32` and invokes
//! [`program!`] in its binary to get `_start`, a panic handler and the
//! allocator; libraries use only the safe wrappers here.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

#[doc(hidden)]
pub mod alloc_impl;
pub mod env;
pub mod errno;
pub mod fs;
pub mod io;
pub mod logfile;
pub mod mem;
pub mod net;
pub mod process;
pub mod signal;
#[doc(hidden)]
pub mod start;
pub mod subvol;
pub mod sync;
pub mod sys;
pub mod syslog;
pub mod term;
pub mod thread;
pub mod time;
pub mod tz;
pub mod utmp;

pub use errno::{Errno, Result};
pub(crate) use sys::syscall;

/// Report a panic and exit with status 101.
#[doc(hidden)]
pub fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    eprintln!("{}: internal error: {}", prog_name(), info.message());
    process::exit_now(101)
}

/// The program's name (argv\[0\]'s last component), for messages.
pub fn prog_name() -> alloc::string::String {
    let a = env::args().first().map_or(&b"?"[..], |a| a.as_slice());
    alloc::string::String::from_utf8_lossy(fs::basename(a)).into_owned()
}

/// Lossy UTF-8 for messages.
pub fn lossy(b: &[u8]) -> alloc::borrow::Cow<'_, str> {
    alloc::string::String::from_utf8_lossy(b)
}
