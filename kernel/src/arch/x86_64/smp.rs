// SPDX-License-Identifier: MIT OR Apache-2.0

//! Starting the application processors.
//!
//! Limine parks every AP and starts it at a function of our choosing (Limine
//! protocol, "MP feature"). Each AP then switches to the kernel page tables
//! and its own stack, loads its own GDT/TSS, the shared IDT and its per-CPU
//! block, enables its local APIC and timer, and becomes an idle thread.

use alloc::boxed::Box;
use alloc::vec::Vec;

use limine::mp::MpInfo;

use super::gdt::{CpuTables, IST_COUNT};
use super::{apic, boot, idt, paging, percpu};
use crate::mm::vmap::KernelStack;
use crate::{log_info, log_warn, sched, time};

/// Everything an AP needs, handed over through Limine's `extra_argument`.
#[derive(Debug)]
struct ApStart {
    id: u32,
    stack_top: u64,
    ist_tops: [u64; IST_COUNT],
}

fn stack() -> u64 {
    KernelStack::new().expect("out of memory for AP stacks").leak()
}

/// The APIC IDs of all CPUs, bootstrap CPU first; this order defines the
/// kernel's CPU numbers.
pub fn cpu_apic_ids() -> Vec<u32> {
    let mut ids = alloc::vec![apic::id()];
    if let Some((bsp, cpus)) = boot::mp_cpus() {
        ids.extend(cpus.iter().map(|c| c.lapic_id).filter(|&id| id != bsp));
    }
    ids
}

/// Start every AP the bootloader reported and wait (up to a second) until
/// they are all online. Call after `sched::init`.
pub fn start_aps() {
    let Some((bsp, cpus)) = boot::mp_cpus() else { return };
    let ids = cpu_apic_ids();
    for info in cpus.iter().filter(|c| c.lapic_id != bsp) {
        let id = ids.iter().position(|&a| a == info.lapic_id).unwrap() as u32;
        let start = Box::leak(Box::new(ApStart { id, stack_top: stack(), ist_tops: [stack(), stack(), stack()] }));
        info.bootstrap(ap_entry, start as *const ApStart as u64);
    }
    let deadline = time::monotonic_ns() + time::NS_PER_SEC;
    while sched::online_cpus() < ids.len() && time::monotonic_ns() < deadline {
        core::hint::spin_loop();
    }
    if sched::online_cpus() < ids.len() {
        log_warn!("only {} of {} CPUs came online", sched::online_cpus(), ids.len());
    } else {
        log_info!("SMP: {} CPUs online", ids.len());
    }
}

/// AP entry from Limine: on the bootloader's page tables and stack.
unsafe extern "C" fn ap_entry(info: &MpInfo) -> ! {
    let start = info.extra_argument();
    paging::init_ap();
    // SAFETY: `start` is the leaked `ApStart` written by `start_aps`.
    let top = unsafe { (*(start as *const ApStart)).stack_top };
    super::switch_stack_with(top, ap_main, start)
}

extern "C" fn ap_main(start: u64) -> ! {
    // SAFETY: As in `ap_entry`; the record is leaked and never freed.
    let start = unsafe { &*(start as *const ApStart) };
    let tables: &'static CpuTables = Box::leak(Box::new(CpuTables::new()));
    tables.load(start.ist_tops);
    percpu::init(start.id, tables);
    idt::load();
    super::paging::init_pat();
    super::fpu::init_cpu();
    super::syscall::init_cpu();
    apic::init_local();
    percpu::set_apic_id(apic::id());
    super::start_tick();
    sched::ap_online()
}
