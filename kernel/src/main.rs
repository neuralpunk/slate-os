// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Slate kernel.

#![no_std]
#![no_main]
// `#[sanitize(kcfi = "off")]` on calls into firmware (ADR 0096).
#![feature(sanitize)]

extern crate alloc;

mod abi;
mod acpi;
mod arch;
mod block;
mod console;
mod drivers;
mod fs;
mod ktest;
mod log;
mod mm;
mod net;
mod panic;
mod proc;
mod random;
mod sched;
mod sync;
mod time;

use arch::boot;

/// Kernel version, reported on the serial console at entry.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// First Rust code to run, called by the architecture entry point once the
/// CPU is in a state where Rust code is sound to run.
fn kernel_main() -> ! {
    console::init();
    kprintln!("Slate kernel {VERSION} entered");

    let info = boot::info();
    log::configure(info.cmdline);
    proc::domain::configure(info.cmdline);
    ktest::activate_if_requested(info.cmdline);
    arch::init_bsp();
    log_info!(
        "boot: {} {}, base revision {}, kernel {}, hhdm {:#x}, cmdline {:?}",
        info.bootloader_name,
        info.bootloader_version,
        info.base_revision,
        info.kernel_path,
        info.hhdm_offset,
        info.cmdline
    );
    mm::init(info.hhdm_offset);
    // The trace filter is a list of names: it needs the heap.
    abi::linux::trace::configure(info.cmdline);
    arch::init_bsp_late();
    if let Some(fb) = boot::framebuffer() {
        drivers::fbcon::init(fb);
    }

    let stack = mm::vmap::KernelStack::new().expect("out of memory for the boot stack");
    arch::switch_stack(stack.leak(), kernel_main_on_own_stack);
}

/// Continues boot on a kernel-allocated stack with a guard page; the
/// bootloader's stack is abandoned (and reclaimable later).
extern "C" fn kernel_main_on_own_stack() -> ! {
    acpi::init(boot::rsdp().expect("no ACPI RSDP; ACPI is required"));
    arch::init_interrupts_and_time();
    mm::vdso::init();
    console::init_input();
    if !drivers::enabled("ps2") {
        log_info!("ps2: driver disabled");
    } else if !drivers::ps2::init() {
        log_info!("no PS/2 controller; keyboard input only on the serial port");
    }
    boot::snapshot();
    // UEFI runtime services (ADR 0088), unless `slate.efi=off`.
    if let Some(e) = boot::efi_runtime()
        && !boot::info().cmdline.split_ascii_whitespace().any(|w| w == "slate.efi=off")
    {
        arch::efi::init(&e.memmap, e.desc_size, e.table);
    }
    sched::init(&arch::smp::cpu_apic_ids());
    arch::irq::init_counts();
    arch::smp::start_aps();
    mm::reclaim_bootloader_memory();
    mm::vmap::start_stack_reaper();
    proc::aslr::configure(boot::info().cmdline);
    mm::canary::start_quarantine(boot::info().cmdline);
    drivers::pci::init();
    drivers::iommu::init(boot::info().cmdline);
    arch::power::enter_acpi_mode();
    drivers::aml::init();
    net::init();
    drivers::virtio::init();
    // The firmware framebuffer is a card unless a GPU driver took it.
    if let Some(fb) = drivers::fbcon::framebuffer() {
        drivers::drm::bootfb::register(fb);
    }
    drivers::init_storage();
    drivers::init_network();
    drivers::init_usb();
    arch::power::init_power_button();
    drivers::acpi_events::init();
    mm::canary::start(boot::info().cmdline);

    // Bootloader memory is gone: only the snapshot is valid now.
    let info = boot::info();
    fs::init_root(info.cmdline);
    drivers::firmware::root_ready();

    if info.cmdline.split_ascii_whitespace().any(|w| w == "test") {
        ktest::run_all(info.cmdline);
    }
    run_init(info.cmdline);
}

/// Start the first user process and wait for it; when it exits, power off.
fn run_init(cmdline: &str) -> ! {
    let path = cmdline.split_ascii_whitespace().find_map(|w| w.strip_prefix("init=")).unwrap_or("/init");
    let env: [&[u8]; 4] = [b"HOME=/root", b"PATH=/bin:/sbin:/usr/bin:/usr/sbin", b"TERM=xterm", b"SHELL=/bin/sh"];
    match proc::spawn(path, &[path.as_bytes()], &env) {
        Ok(init) => {
            // pid 1 leads session 1 with the console as its terminal.
            fs::tty::console().set_controlling(init.pid, init.pid);
            init.set_ctty(Some(fs::tty::console().clone()));
            let status = init.wait();
            log_info!("init exited (status {status:#x})");
        }
        Err(e) => log_error!("cannot start {path}: {e:?}"),
    }
    fs::shutdown();
    // A system on trial that loses init gets another boot, which counts
    // down to the fallback (ADR 0027).
    if fs::slatefs::BOOT_PENDING.load(core::sync::atomic::Ordering::Acquire) {
        log_warn!("the system being tried failed before it was confirmed; rebooting");
        arch::power::reboot();
    }
    log_info!("powering off");
    arch::power::power_off();
    arch::halt_forever();
}
