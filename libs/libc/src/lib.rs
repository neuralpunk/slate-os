// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-libc (ADR 0031): a C library written in Rust, for C programs
//! built for Slate with `slate-cc`. It sits on slate-rt, so its programs
//! make Slate's native system calls (and Linux ones when run on Linux).
//! The headers are in `include/`; the C interfaces follow the C11
//! standard and POSIX, written from those documents.
//!
//! The C symbols are exported only when building for Slate
//! (`target_os = "none"`); on the host the same functions are ordinary
//! Rust functions, so their unit tests run without displacing the host's
//! own C library.
//!
//! It covers stdio (printf and scanf with floating point), string,
//! stdlib, ctype, errno, <math.h> (ADR 0074), POSIX threads (ADR 0073),
//! the unistd file and process calls, directories, wait, signals with
//! sigaction, setjmp, sockets, termios and the calendar functions
//! (ADR 0075).

#![no_std]
// errno and thread-specific data are ELF thread-locals (ADR 0073).
#![feature(thread_local)]
// The C interface is unsafe by nature: every pointer comes from C. Its
// types (FILE, DIR, ...) are opaque handles with nothing to debug-print.
#![allow(clippy::missing_safety_doc, missing_debug_implementations)]

extern crate alloc;
#[cfg(not(target_os = "none"))]
extern crate std;

pub mod ctime;
pub mod ctype;
pub mod float;
pub mod format;
pub mod math;
pub mod pthread;
pub mod scanf;
pub mod setjmp;
pub mod signals;
pub mod socket;
pub mod stdio;
pub mod stdlib;
pub mod string;
pub mod termios;
pub mod unistd;

use core::cell::Cell;
use core::ffi::{c_char, c_int};

/// The C `errno`, one per thread.
#[thread_local]
static ERRNO: Cell<c_int> = Cell::new(0);

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn __errno_location() -> *mut c_int {
    ERRNO.as_ptr()
}

pub(crate) fn set_errno(e: slate_rt::Errno) {
    ERRNO.set(e.0);
}

pub(crate) fn errno() -> c_int {
    ERRNO.get()
}

/// A result as C wants it: the value, or -1 with `errno` set.
pub(crate) fn ret<T: TryInto<c_int>>(r: slate_rt::Result<T>) -> c_int {
    match r {
        Ok(v) => v.try_into().unwrap_or(c_int::MAX),
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

/// The bytes of a C string, without its NUL.
///
/// # Safety
///
/// `p` must point to a NUL-terminated string that outlives `'a`.
pub(crate) unsafe fn cstr<'a>(p: *const c_char) -> &'a [u8] {
    // SAFETY: The caller guarantees a NUL-terminated string.
    unsafe { core::slice::from_raw_parts(p as *const u8, string::strlen(p)) }
}

/// The NUL-terminated strings of a NULL-terminated C array.
///
/// # Safety
///
/// `v` must be null or a NULL-terminated array of C strings.
pub(crate) unsafe fn cstr_array(v: *const *const c_char) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
    let mut out = alloc::vec::Vec::new();
    if v.is_null() {
        return out;
    }
    let mut i = 0;
    // SAFETY: The caller guarantees the array ends with NULL.
    unsafe {
        while !(*v.add(i)).is_null() {
            out.push(cstr(*v.add(i)).to_vec());
            i += 1;
        }
    }
    out
}

/// Start-up (Slate only): `_start` hands the initial stack to slate-rt,
/// which works out the interface, sets up its own state and calls
/// [`start_c`]; that calls the C `main` with the original argv and envp.
/// The note asks for the native interface (ADR 0031).
#[cfg(target_os = "none")]
mod start {
    use core::ffi::{c_char, c_int};
    use core::sync::atomic::{AtomicUsize, Ordering};

    core::arch::global_asm!(
        ".pushsection .note.slate,\"a\",@note",
        ".balign 4",
        ".long 6",
        ".long 4",
        ".long 1",
        ".asciz \"Slate\"",
        ".balign 4",
        ".long 1",
        ".popsection",
    );

    static STACK: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" {
        fn main(argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char) -> c_int;
    }

    #[unsafe(no_mangle)]
    #[unsafe(naked)]
    unsafe extern "C" fn _start() -> ! {
        slate_rt::start_asm!(entry)
    }

    extern "C" fn entry(sp: *const usize) -> ! {
        STACK.store(sp as usize, Ordering::Relaxed);
        // SAFETY: `_start` passes the initial stack pointer.
        unsafe { slate_rt::start::run(sp, start_c) }
    }

    fn start_c() -> i32 {
        let sp = STACK.load(Ordering::Relaxed) as *const usize;
        // SAFETY: The initial stack holds argc, then argv's pointers and
        // NULL, then envp's pointers.
        unsafe {
            let argc = *sp;
            let argv = sp.add(1) as *mut *mut c_char;
            let envp = argv.add(argc + 1);
            crate::stdlib::init_environ(envp);
            let code = main(argc as c_int, argv, envp);
            crate::stdlib::exit(code)
        }
    }

    /// Also `malloc`'s (ADR 0094): `free` asks it for the block's size.
    #[global_allocator]
    pub(crate) static ALLOCATOR: slate_rt::alloc_impl::Allocator = slate_rt::alloc_impl::Allocator::new();

    #[panic_handler]
    fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
        slate_rt::eprintln!("slate-libc: internal error: {}", info.message());
        slate_rt::process::exit_now(134)
    }
}

/// A static buffer that C functions return pointers into (strerror,
/// readdir's entry): valid until the next call, as C allows.
pub(crate) struct StaticBuf<const N: usize>(core::cell::UnsafeCell<[u8; N]>);

// SAFETY: The buffer only ever holds bytes; C callers accept that the
// contents change on the next call, from any thread (POSIX does not ask
// strerror or readdir to be thread-safe).
unsafe impl<const N: usize> Sync for StaticBuf<N> {}

impl<const N: usize> StaticBuf<N> {
    pub(crate) const fn new() -> Self {
        StaticBuf(core::cell::UnsafeCell::new([0; N]))
    }

    pub(crate) fn as_ptr(&self) -> *mut u8 {
        self.0.get() as *mut u8
    }

    /// Store `s` NUL-terminated (truncated to fit) and return it.
    pub(crate) fn set(&self, s: &[u8]) -> *mut c_char {
        let n = s.len().min(N - 1);
        // SAFETY: In bounds; see the Sync note.
        unsafe {
            core::ptr::copy_nonoverlapping(s.as_ptr(), self.as_ptr(), n);
            *self.as_ptr().add(n) = 0;
        }
        self.as_ptr() as *mut c_char
    }
}
