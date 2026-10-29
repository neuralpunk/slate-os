// SPDX-License-Identifier: MIT OR Apache-2.0

//! The vDSO (vdso(7)): a small shared object the kernel maps into every
//! process, so `clock_gettime`, `gettimeofday` and `time` can read the clock
//! without a system call.
//!
//! The kernel maps a read-only data page ("vvar") directly below the vDSO.
//! When it says the TSC is usable, the time is computed from RDTSC with the
//! kernel's own conversion; otherwise every call falls back to the real
//! system call.

#![no_std]

use core::arch::asm;

/// Layout shared with the kernel (kernel/src/mm/vdso.rs).
#[repr(C)]
struct Vvar {
    magic: u64,
    /// 1: the TSC is the clock source; 0: use system calls.
    mode: u64,
    tsc_base: u64,
    /// Nanoseconds per TSC tick, 32.32 fixed point.
    mult: u64,
    /// Wall-clock nanoseconds since the epoch at monotonic time zero. The
    /// kernel changes it when the time is set: read it whole, atomically.
    realtime_offset_ns: i64,
}

const MAGIC: u64 = 0x534C_4154_4556_4452; // "SLATEVDR"

#[derive(Debug)]
#[repr(C)]
pub struct Timespec {
    sec: i64,
    nsec: i64,
}

#[derive(Debug)]
#[repr(C)]
pub struct Timeval {
    sec: i64,
    usec: i64,
}

// System call numbers (musl `bits/syscall.h`).
const SYS_GETTIMEOFDAY: u64 = 96;
const SYS_TIME: u64 = 201;
const SYS_CLOCK_GETTIME: u64 = 228;
const SYS_GETCPU: u64 = 309;

fn vvar() -> &'static Vvar {
    let base: usize;
    // SAFETY: `__ehdr_start` is the vDSO's first byte (linker-defined); the
    // kernel maps the vvar page right below it.
    unsafe { asm!("lea {}, [rip + __ehdr_start]", out(reg) base, options(nomem, nostack, preserves_flags)) };
    // SAFETY: The page is mapped read-only for the process's whole life.
    unsafe { &*((base - 4096) as *const Vvar) }
}

fn syscall2(nr: u64, a: u64, b: u64) -> i64 {
    let r: i64;
    // SAFETY: A plain system call; the kernel validates the arguments.
    unsafe {
        asm!("syscall", inlateout("rax") nr as i64 => r, in("rdi") a, in("rsi") b, lateout("rcx") _, lateout("r11") _, options(nostack))
    };
    r
}

fn syscall3(nr: u64, a: u64, b: u64, c: u64) -> i64 {
    let r: i64;
    // SAFETY: As above.
    unsafe {
        asm!("syscall", inlateout("rax") nr as i64 => r, in("rdi") a, in("rsi") b, in("rdx") c, lateout("rcx") _, lateout("r11") _, options(nostack))
    };
    r
}

/// Nanoseconds of the monotonic clock, if the TSC can be used.
fn monotonic_ns() -> Option<u64> {
    let v = vvar();
    if v.magic != MAGIC || v.mode != 1 {
        return None;
    }
    let (lo, hi): (u32, u32);
    // SAFETY: RDTSC has no side effects.
    unsafe { asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
    let tsc = (u64::from(hi) << 32) | u64::from(lo);
    Some(((u128::from(tsc.wrapping_sub(v.tsc_base)) * u128::from(v.mult)) >> 32) as u64)
}

/// (seconds, nanoseconds) of the monotonic clock.
fn monotonic() -> Option<(i64, i64)> {
    monotonic_ns().map(|ns| ((ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as i64))
}

/// (seconds, nanoseconds) of the wall clock.
fn realtime() -> Option<(i64, i64)> {
    let mono = monotonic_ns()?;
    let offset: i64;
    // SAFETY: One aligned 8-byte load from the mapped (read-only) vvar
    // page: a single MOV, atomic on x86-64, so an update the kernel makes
    // meanwhile is seen whole.
    unsafe {
        asm!("mov {}, qword ptr [{}]", out(reg) offset, in(reg) &raw const vvar().realtime_offset_ns,
             options(nostack, preserves_flags, readonly))
    };
    // 64-bit arithmetic only: 128-bit division would call a compiler
    // helper the vDSO cannot link (and i64 nanoseconds last until 2262).
    let ns = offset.wrapping_add(mono as i64);
    Some((ns.div_euclid(1_000_000_000), ns.rem_euclid(1_000_000_000)))
}

/// # Safety
///
/// `ts` must be a valid pointer to a `struct timespec` (or the call falls
/// back to the kernel, which checks it).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn slate_vdso_clock_gettime(clock: i32, ts: *mut Timespec) -> i64 {
    // CLOCK_REALTIME(_COARSE) 0/5; MONOTONIC(_RAW/_COARSE) 1/4/6; BOOTTIME 7.
    let t = match clock {
        0 | 5 => realtime(),
        1 | 4 | 6 | 7 => monotonic(),
        _ => None,
    };
    match t {
        Some((sec, nsec)) if !ts.is_null() => {
            // SAFETY: The caller passes a valid timespec pointer.
            unsafe { ts.write(Timespec { sec, nsec }) };
            0
        }
        _ => syscall2(SYS_CLOCK_GETTIME, clock as u64, ts as u64),
    }
}

/// # Safety
///
/// As for `slate_vdso_clock_gettime`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn slate_vdso_gettimeofday(tv: *mut Timeval, tz: *mut u64) -> i64 {
    match realtime() {
        Some((sec, nsec)) if tz.is_null() => {
            if !tv.is_null() {
                // SAFETY: The caller passes a valid timeval pointer.
                unsafe { tv.write(Timeval { sec, usec: nsec / 1000 }) };
            }
            0
        }
        _ => syscall2(SYS_GETTIMEOFDAY, tv as u64, tz as u64),
    }
}

/// # Safety
///
/// `t` must be null or a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn slate_vdso_time(t: *mut i64) -> i64 {
    match realtime() {
        Some((sec, _)) => {
            if !t.is_null() {
                // SAFETY: The caller passes a valid pointer.
                unsafe { t.write(sec) };
            }
            sec
        }
        None => syscall2(SYS_TIME, t as u64, 0),
    }
}

/// # Safety
///
/// Pointers must be null or valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn slate_vdso_getcpu(cpu: *mut u32, node: *mut u32, _cache: u64) -> i64 {
    syscall3(SYS_GETCPU, cpu as u64, node as u64, 0)
}

// The exported names (vdso(7)), with and without the `__vdso_` prefix. They
// are aliases so that only the version script decides their visibility:
// rustc exports `#[no_mangle]` functions itself, without a version.
core::arch::global_asm!(
    ".globl __vdso_clock_gettime",
    ".set __vdso_clock_gettime, slate_vdso_clock_gettime",
    ".globl __vdso_gettimeofday",
    ".set __vdso_gettimeofday, slate_vdso_gettimeofday",
    ".globl __vdso_time",
    ".set __vdso_time, slate_vdso_time",
    ".globl __vdso_getcpu",
    ".set __vdso_getcpu, slate_vdso_getcpu",
    ".globl clock_gettime",
    ".set clock_gettime, slate_vdso_clock_gettime",
    ".globl gettimeofday",
    ".set gettimeofday, slate_vdso_gettimeofday",
    ".globl time",
    ".set time, slate_vdso_time",
    ".globl getcpu",
    ".set getcpu, slate_vdso_getcpu",
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
