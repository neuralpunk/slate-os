// SPDX-License-Identifier: MIT OR Apache-2.0

//! Power off and reset, and the power button.

use slate_acpi::GenericAddress;

use super::port::{Port8, Port16};
use crate::acpi;

const SLP_EN: u16 = 1 << 13;
/// PM1 control: SCI_EN, the system is in ACPI mode (ACPI 6.5 §4.8.3.2.1).
const SCI_EN: u16 = 1 << 0;
/// PM1 status and enable: the fixed power button (§4.8.3.1, tables 4.11
/// and 4.13).
const PWRBTN: u16 = 1 << 8;
/// Linux's signal number for SIGPWR (signal(7)).
const SIGPWR: u32 = 30;

fn pm1_regs(f: &slate_acpi::fadt::Fadt) -> impl Iterator<Item = (u16, u16)> {
    let half = u16::from(f.pm1_event_len / 2);
    [f.pm1a_event, f.pm1b_event].into_iter().filter(|&b| b != 0).map(move |b| (b as u16, b as u16 + half))
}

/// Put the system in ACPI mode (ACPI 6.5 §4.8.2.2.1.1: SCI_EN, through
/// the SMI command port if the firmware is not there yet) with every
/// fixed and general-purpose event off and its status cleared. Before
/// AML runs: the firmware's `_INI` methods expect ACPI mode.
pub fn enter_acpi_mode() {
    let Some(f) = acpi::info().fadt else { return };
    if f.pm1a_event == 0 || f.pm1_event_len < 4 || f.pm1a_control == 0 {
        return;
    }
    // SAFETY: These are the ACPI fixed-hardware and GPE register blocks the
    // FADT names; only ACPI event state changes.
    unsafe {
        let cnt = Port16::new(f.pm1a_control as u16);
        if cnt.read() & SCI_EN == 0 && f.smi_command != 0 && f.acpi_enable != 0 {
            Port8::new(f.smi_command as u16).write(f.acpi_enable);
            for _ in 0..1000 {
                if cnt.read() & SCI_EN != 0 {
                    break;
                }
                crate::drivers::dma::delay_ms(1);
            }
        }
        for (block, len) in [(f.gpe0_block, f.gpe0_len), (f.gpe1_block, f.gpe1_len)] {
            if block == 0 {
                continue;
            }
            for i in 0..u16::from(len / 2) {
                Port8::new(block as u16 + u16::from(len / 2) + i).write(0);
                Port8::new(block as u16 + i).write(0xFF);
            }
        }
        for (status, enable) in pm1_regs(&f) {
            Port16::new(enable).write(0);
            Port16::new(status).write(0xFFFF);
        }
    }
}

/// Route the SCI and turn on the fixed power button (§4.8.2.2.1.1),
/// unless the button is a control-method device, whose presses come as
/// Notify from AML (`drivers::acpi_events`, which also turns on the
/// general-purpose events). A press asks init for a clean power-off
/// (SIGPWR, its `powerfail` entries).
pub fn init_power_button() {
    let Some(f) = acpi::info().fadt else { return };
    if f.pm1a_event == 0 || f.pm1_event_len < 4 || f.pm1a_control == 0 {
        return;
    }
    let fixed = f.flags & slate_acpi::fadt::PWR_BUTTON == 0;
    if fixed {
        for (_, enable) in pm1_regs(&f) {
            // SAFETY: The PM1 enable register the FADT names.
            unsafe { Port16::new(enable).write(PWRBTN) };
        }
    }
    crate::arch::irq::register_isa(f.sci_interrupt as u8, "acpi", sci);
    if fixed {
        crate::log_info!("power button: enabled (SCI on IRQ {})", f.sci_interrupt);
    } else {
        crate::log_info!("power button: a control-method device (SCI on IRQ {})", f.sci_interrupt);
    }
}

fn sci() {
    let Some(f) = acpi::info().fadt else { return };
    let mut pressed = false;
    for (status, _) in pm1_regs(&f) {
        // SAFETY: The PM1 status register; writing 1 clears a bit.
        unsafe {
            let p = Port16::new(status);
            let st = p.read();
            if st & PWRBTN != 0 {
                pressed = true;
            }
            p.write(st);
        }
    }
    crate::drivers::acpi_events::sci();
    if pressed {
        power_button_pressed();
    }
}

/// The power button was pressed (the fixed one, or a control-method
/// button's Notify): shut down cleanly.
pub fn power_button_pressed() {
    crate::log_warn!("power button pressed: shutting down");
    shut_down();
}

/// Ask init for a clean power-off (SIGPWR).
pub fn shut_down() {
    if let Some(init) = crate::proc::get(1) {
        crate::proc::signal::send_to_process(&init, SIGPWR);
    }
}

/// Whether Ctrl-Alt-Del restarts at once (reboot(2)'s CAD_ON, the
/// default) or sends init SIGINT (CAD_OFF, which init asks for).
static CAD_RESTARTS: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(true);

/// Linux's signal number for SIGINT (signal(7)).
const SIGINT: u32 = 2;

pub fn set_ctrl_alt_del(restart: bool) {
    CAD_RESTARTS.store(restart, core::sync::atomic::Ordering::Relaxed);
}

/// Ctrl-Alt-Del on any keyboard (ADR 0060): restart without syncing, as
/// reboot(2) describes, or tell init.
pub fn ctrl_alt_del() {
    if CAD_RESTARTS.load(core::sync::atomic::Ordering::Relaxed) {
        crate::log_warn!("Ctrl-Alt-Del: restarting");
        reboot();
    }
    crate::log_info!("Ctrl-Alt-Del: telling init");
    if let Some(init) = crate::proc::get(1) {
        crate::proc::signal::send_to_process(&init, SIGINT);
    }
}

/// Enter ACPI S5 (soft off) using the FADT's PM1 control blocks and the
/// `\_S5` sleep types (ACPI 6.5 §4.8.3.2.1, §7.4.2). Returns if that is not
/// possible.
pub fn power_off() {
    let info = acpi::info();
    // The firmware's \_PTS first, and its \_S5 (ADR 0079); the pattern
    // found in the DSDT when AML could not give one.
    crate::drivers::aml::prepare_to_sleep(5);
    let s5 = crate::drivers::aml::s5().or(info.s5);
    let (Some(f), Some((typ_a, typ_b))) = (info.fadt, s5) else { return };
    let _irq = super::cpu::InterruptGuard::new();
    // SAFETY: PM1a/PM1b control blocks are the ACPI fixed hardware ports the
    // FADT names; writing SLP_TYP|SLP_EN powers the machine off.
    unsafe {
        Port16::new(f.pm1a_control as u16).write((u16::from(typ_a) << 10) | SLP_EN);
        if f.pm1b_control != 0 {
            Port16::new(f.pm1b_control as u16).write((u16::from(typ_b) << 10) | SLP_EN);
        }
    }
}

/// Reset the machine: the FADT reset register, then the 8042 keyboard
/// controller's reset line. Halts if neither works.
pub fn reboot() -> ! {
    let _irq = super::cpu::InterruptGuard::new();
    if let Some(f) = acpi::info().fadt
        && let Some(r) = f.reset_register
        && r.space == GenericAddress::SPACE_IO
    {
        // SAFETY: The FADT names this port as the reset register.
        unsafe { Port8::new(r.address as u16).write(f.reset_value) };
    }
    // SAFETY: Pulsing the 8042 reset line (command 0xFE) resets the CPU.
    unsafe { Port8::new(0x64).write(0xFE) };
    super::halt_forever();
}
