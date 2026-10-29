// SPDX-License-Identifier: MIT OR Apache-2.0

//! Kernel panic handling.

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::{arch, console, ktest};

static PANICKING: AtomicBool = AtomicBool::new(false);

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    // Mask interrupts for good: nothing should run after a panic.
    core::mem::forget(arch::cpu::InterruptGuard::new());

    if PANICKING.swap(true, Ordering::Relaxed) {
        // Panicked while panicking (for example a fault in the backtrace
        // walk); print the bare minimum and stop.
        console::panic_print(format_args!("\nKERNEL PANIC (nested): {info}\n"));
        stop();
    }

    console::panic_print(format_args!("\nKERNEL PANIC: {}\n", info.message()));
    if let Some(loc) = info.location() {
        console::panic_print(format_args!("  at {}:{}:{}\n", loc.file(), loc.line(), loc.column()));
    }
    // Link addresses (KASLR moved the kernel, ADR 0095), so the file's
    // symbols name them as they are.
    let slide = arch::paging::kernel_slide();
    console::panic_print(format_args!("kernel slide {slide:#x}\n"));
    console::panic_print(format_args!("backtrace (link addresses; resolve with `addr2line -e <kernel>`):\n"));
    arch::backtrace::walk(|ret| console::panic_print(format_args!("  {:#018x}\n", ret.wrapping_sub(slide))));
    stop();
}

fn stop() -> ! {
    if ktest::active() {
        console::panic_print(format_args!("SLATE-TEST: FAIL panic\n"));
        arch::qemu::exit(arch::qemu::ExitCode::Failure);
    }
    arch::halt_forever();
}
