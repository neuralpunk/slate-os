// SPDX-License-Identifier: MIT OR Apache-2.0

//! In-kernel tests for the x86-64 exception and descriptor-table code.

use super::trap::vector;
use super::{apic, backtrace, cpu, hpet, percpu, probe, trap};
use crate::ktest::{Test, ensure};
use crate::{acpi, time};

/// A canonical lower-half address Limine never maps (it maps no lower-half
/// memory for the kernel at base revision 6).
const UNMAPPED: u64 = 0x0000_7FFF_0000_0040;
/// A non-canonical address: any access raises #GP, not #PF.
const NON_CANONICAL: u64 = 0x8000_0000_0000_0000;

/// Deliberate crashes for `ktest.crash=<name>`; the host harness checks the
/// panic message (see `tools/xtask/src/qemu.rs`).
pub const CRASHES: &[(&str, fn() -> !)] = &[
    ("page_fault", crash_page_fault),
    ("double_fault", crash_double_fault),
    ("stack_overflow", crash_stack_overflow),
    ("power_off", crash_power_off),
    ("reboot", crash_reboot),
    ("cfi", crash_cfi),
];

/// An indirect call through a pointer of another type than its target's:
/// KCFI's check before the call must stop it (ADR 0096).
fn crash_cfi() -> ! {
    fn takes_u64(x: u64) -> u64 {
        x.wrapping_add(1)
    }
    // SAFETY: Deliberately wrong, to be caught before the call: both are
    // function pointers of the same size.
    let wrong: fn(u32, u32) -> u32 = unsafe { core::mem::transmute(takes_u64 as fn(u64) -> u64) };
    core::hint::black_box(wrong)(1, 2);
    panic!("an indirect call of the wrong type was not caught");
}

/// ACPI soft-off must turn the machine off (QEMU exits with status 0).
fn crash_power_off() -> ! {
    super::power::power_off();
    panic!("ACPI power-off returned");
}

/// Reset must reboot the machine (QEMU runs with -no-reboot and exits).
fn crash_reboot() -> ! {
    super::power::reboot();
}

/// Unbounded recursion must hit the boot stack's guard page; the #PF cannot
/// be delivered on the overflowed stack, so it becomes a #DF on IST1.
fn crash_stack_overflow() -> ! {
    #[allow(unconditional_recursion)]
    fn recurse(depth: u64) -> u64 {
        let pad = core::hint::black_box([depth; 64]);
        recurse(depth + 1) + pad[3]
    }
    let n = recurse(0);
    panic!("recursion returned {n}");
}

/// An unrecoverable kernel page fault must panic with a precise report.
fn crash_page_fault() -> ! {
    // SAFETY: Not safe at all, on purpose: the read faults, and the fault
    // handler panics because the instruction has no exception-table entry.
    let v = unsafe { core::ptr::read_volatile(UNMAPPED as *const u8) };
    panic!("read of unmapped memory returned {v}");
}

/// A fault while the CPU cannot push an exception frame must escalate to a
/// double fault, handled on its IST stack.
fn crash_double_fault() -> ! {
    // SAFETY: Deliberately breaks the stack: `int3` cannot push its frame to
    // an unmapped stack, the resulting #PF cannot either, and the CPU raises
    // #DF, which switches to IST1 and panics.
    unsafe { core::arch::asm!("mov rsp, {}", "int3", in(reg) UNMAPPED, options(noreturn)) }
}

pub const TESTS: &[Test] = &[
    Test { name: "x86_64::ctrl_alt_del_keys", run: ctrl_alt_del_keys },
    Test { name: "x86_64::kernel_log_from", run: kernel_log_from },
    Test { name: "x86_64::percpu_via_gs", run: percpu_via_gs },
    Test { name: "x86_64::kaslr", run: kaslr },
    Test { name: "x86_64::serial_framing", run: serial_framing },
    Test { name: "x86_64::pat_write_combining", run: super::paging::pat_self_check },
    Test { name: "x86_64::breakpoint", run: breakpoint },
    Test { name: "x86_64::page_fault", run: page_fault },
    Test { name: "x86_64::general_protection", run: general_protection },
    Test { name: "x86_64::invalid_opcode", run: invalid_opcode },
    Test { name: "x86_64::divide_error", run: divide_error },
    Test { name: "x86_64::backtrace", run: backtrace_walks },
    Test { name: "x86_64::acpi_tables", run: acpi_tables },
    Test { name: "x86_64::irq_targets_spread", run: irq_targets_spread },
    Test { name: "x86_64::proc_interrupts", run: proc_interrupts },
    Test { name: "time::tick_rate", run: tick_rate },
    Test { name: "time::sleep_accuracy", run: sleep_accuracy },
    Test { name: "time::clock_matches_hpet", run: clock_matches_hpet },
    Test { name: "time::monotonic", run: monotonic },
    Test { name: "time::realtime", run: realtime },
    Test { name: "time::rtc_matches_wall_clock", run: rtc_matches },
    Test { name: "time::set_wall_clock_and_rtc", run: set_wall_clock },
    Test { name: "fbcon::draws_glyphs", run: fbcon_draws },
    Test { name: "fbcon::splash_layout", run: splash_layout },
];

/// The boot splash's line (ADR 0186): under the mark, on the screen, its
/// moving part within the track, sweeping across and back.
fn splash_layout() -> Result<(), &'static str> {
    use crate::drivers::fbcon::{splash_segment, splash_track};
    for (w, h, size) in [(1280, 800, 96), (3840, 2160, 192), (640, 480, 96)] {
        let (x, y, tw, th) = splash_track(w, h, size);
        ensure(x + tw <= w && y + th <= h, "the track leaves the screen")?;
        ensure(y > h * 2 / 5 + size / 2, "the track isn't under the mark")?;
        for n in 0..200 {
            let (start, len) = splash_segment(tw, n);
            ensure(start + len <= tw && len > 0, "the moving part leaves the track")?;
        }
        ensure(splash_segment(tw, 0).0 == 0 && splash_segment(tw, 40).0 == tw - tw / 4, "it doesn't sweep across")?;
    }
    // A test boot isn't quiet: no splash in the way of the console.
    ensure(!crate::drivers::fbcon::splash_showing(), "a splash on a test boot")?;
    // Shown for a moment: graphite in the corner, the mark's chalk in the
    // middle of its slab, the track under it; then the console again.
    use crate::drivers::fbcon;
    let Some(fb) = fbcon::framebuffer() else { return Ok(()) };
    let (w, h) = (fb.width, fb.height);
    fbcon::splash_start("quiet");
    let corner = fbcon::pixel_rgb(2, 2);
    let size = if h >= 1400 { 192 } else { 96 };
    // The slab's top face, a third of the way down the mark.
    let slab = fbcon::pixel_rgb(w / 2, h * 2 / 5 - size / 2 + size * 9 / 32);
    let (tx, ty, _, _) = splash_track(w, h, size);
    let track = fbcon::pixel_rgb(tx + 2, ty);
    fbcon::splash_end("the test");
    ensure(!fbcon::splash_showing(), "the splash didn't end")?;
    ensure(corner == Some((0x12, 0x12, 0x11)), "the splash's background isn't graphite")?;
    ensure(slab.is_some_and(|(r, _, _)| r > 0xC0), "no mark in the middle")?;
    ensure(track.is_some_and(|(r, _, _)| r > 0x20 && r < 0xA0), "no track under the mark")
}

/// The framebuffer console draws Slate's font in the right colors.
fn fbcon_draws() -> Result<(), &'static str> {
    use crate::drivers::fbcon;
    let Some(fg) = fbcon::color(9) else { return Ok(()) }; // No screen: nothing to check.
    let bg = fbcon::color(0).unwrap();
    // Home, clear, bright red "A", reset.
    fbcon::show(b"\x1b[H\x1b[2J\x1b[1;31mA\x1b[0m");
    // Row 7 of 'A' is a full bar in columns 0-6; column 7 is spacing.
    for x in 0..7 {
        ensure(fbcon::pixel(x, 7) == Some(fg), "glyph pixel not in the foreground color")?;
    }
    ensure(fbcon::pixel(7, 7) == Some(bg), "spacing column not background")?;
    ensure(fbcon::pixel(3, 0) == Some(bg), "row 0 not background")?;
    // A wide character (ADR 0166): its box spans both cells, the top edge
    // from x 1 to 14 and the right side at x 14.
    fbcon::show("\x1b[H\x1b[2J\x1b[1;31m中\x1b[0m".as_bytes());
    ensure(fbcon::pixel(1, 1) == Some(fg) && fbcon::pixel(14, 1) == Some(fg), "no wide box top edge")?;
    ensure(fbcon::pixel(14, 8) == Some(fg) && fbcon::pixel(15, 8) == Some(bg), "no wide box right side")?;
    fbcon::show(b"\x1b[2J\x1b[H");
    Ok(())
}

fn acpi_tables() -> Result<(), &'static str> {
    let info = acpi::info();
    ensure(!info.cpus.is_empty(), "MADT lists no CPUs")?;
    ensure(!info.io_apics.is_empty(), "MADT lists no I/O APIC")?;
    ensure(info.cpus.iter().any(|c| c.apic_id == apic::id()), "bootstrap CPU's APIC ID is not in the MADT")?;
    ensure(percpu::current().apic_id.load(core::sync::atomic::Ordering::Relaxed) == apic::id(), "per-CPU APIC ID")?;
    ensure(info.fadt.is_some() && info.s5.is_some(), "FADT or \\_S5 missing")
}

/// Elapsed HPET time in ns while running `f`.
fn hpet_time(f: impl FnOnce()) -> u64 {
    let h0 = hpet::counter();
    f();
    hpet::ticks_to_ns(hpet::counter() - h0)
}

fn tick_rate() -> Result<(), &'static str> {
    let t0 = time::ticks();
    let ns = hpet_time(|| hpet::spin_ns(200_000_000));
    let ticks = time::ticks() - t0;
    let expected = ns * u64::from(time::TICK_HZ) / time::NS_PER_SEC;
    // Within 5%: timer interrupts are not lost under KVM, but a busy host can
    // delay vCPUs (the timing tests assume a reasonably idle host).
    ensure(ticks.abs_diff(expected) * 20 <= expected, "timer tick rate is off by more than 5%")
}

fn sleep_accuracy() -> Result<(), &'static str> {
    for ms in [1u64, 10, 50] {
        let ns = hpet_time(|| time::sleep_ns(ms * 1_000_000));
        ensure(ns >= ms * 1_000_000, "slept too short")?;
        ensure(ns <= ms * 1_000_000 + 5_000_000, "slept more than 5 ms too long")?;
    }
    Ok(())
}

fn clock_matches_hpet() -> Result<(), &'static str> {
    let c0 = time::monotonic_ns();
    let h = hpet_time(|| hpet::spin_ns(100_000_000));
    let c = time::monotonic_ns() - c0;
    // 0.1% of 100 ms is 100 us; allow for the reads not being simultaneous.
    ensure(c.abs_diff(h) < 100_000, "monotonic clock drifts from the HPET by more than 0.1%")
}

fn monotonic() -> Result<(), &'static str> {
    let mut last = time::monotonic_ns();
    for _ in 0..100_000 {
        let now = time::monotonic_ns();
        ensure(now >= last, "monotonic clock went backwards")?;
        last = now;
    }
    Ok(())
}

fn realtime() -> Result<(), &'static str> {
    // 2020-01-01T00:00:00Z.
    ensure(time::realtime_ns() > 1_577_836_800 * i128::from(time::NS_PER_SEC), "wall clock is before 2020")
}

/// The CMOS RTC gave the wall clock at boot: they still agree.
fn rtc_matches() -> Result<(), &'static str> {
    let rtc = crate::drivers::rtc::read_unix().ok_or("no CMOS RTC reading")?;
    let wall = (time::realtime_ns() / i128::from(time::NS_PER_SEC)) as i64;
    ensure(rtc.abs_diff(wall) <= 2, "the RTC and the wall clock disagree")
}

/// Setting the wall clock moves it (and the vDSO's offset); the RTC takes
/// a time and gives it back; both are put back afterwards.
fn set_wall_clock() -> Result<(), &'static str> {
    let ns = i128::from(time::NS_PER_SEC);
    let before = time::realtime_ns();
    let start = time::monotonic_ns();
    let target = before + 1_000_000 * ns;
    time::set_realtime_ns(target);
    let moved = time::realtime_ns();
    let offset = time::realtime_offset_ns();
    let rtc_ok = crate::drivers::rtc::write_unix((target / ns) as i64)
        && crate::drivers::rtc::read().is_some_and(|t| t.to_unix().abs_diff((target / ns) as i64) <= 1);
    // Put everything back: the time that passed included.
    let restored = before + i128::from(time::monotonic_ns() - start);
    time::set_realtime_ns(restored);
    crate::drivers::rtc::write_unix((restored / ns) as i64);
    ensure((moved - target).abs() < ns, "the wall clock did not move")?;
    ensure(i128::from(offset) + i128::from(time::monotonic_ns()) > target, "the offset did not follow")?;
    ensure(rtc_ok, "the RTC did not keep the time written")?;
    ensure((time::realtime_ns() - restored).abs() < ns, "the wall clock was not put back")
}

fn percpu_via_gs() -> Result<(), &'static str> {
    // SAFETY: GS base exists on every x86-64 CPU; reading it has no effect.
    let gs = unsafe { cpu::rdmsr(cpu::MSR_GS_BASE) };
    let pc = percpu::current();
    ensure(gs == pc as *const _ as u64, "gs:[0] does not point at the per-CPU block")?;
    ensure(pc.id == 0, "bootstrap CPU should have id 0")
}

fn breakpoint() -> Result<(), &'static str> {
    let before = trap::breakpoint_count();
    cpu::breakpoint();
    cpu::breakpoint();
    ensure(trap::breakpoint_count() == before + 2, "breakpoint handler did not run exactly twice")
}

fn page_fault() -> Result<(), &'static str> {
    let f = probe::read_u8(UNMAPPED).err().ok_or("read of an unmapped page succeeded")?;
    ensure(f.vector == vector::PAGE_FAULT, "expected #PF")?;
    ensure(f.address == UNMAPPED, "CR2 does not hold the faulting address")?;
    // Error code (SDM vol. 3A figure 4-12): P=0 (not present), W/R=0 (read),
    // U/S=0 (supervisor).
    ensure(f.error_code & 0b111 == 0, "unexpected #PF error code")?;
    // The kernel keeps running normally afterwards.
    let x = 0x5Au8;
    ensure(probe::read_u8(&x as *const u8 as u64) == Ok(0x5A), "probe of mapped memory failed")
}

fn general_protection() -> Result<(), &'static str> {
    let f = probe::read_u64(NON_CANONICAL).err().ok_or("non-canonical read succeeded")?;
    ensure(f.vector == vector::GENERAL_PROTECTION, "expected #GP")?;
    ensure(f.error_code == 0, "#GP for a non-canonical address has error code 0")
}

fn invalid_opcode() -> Result<(), &'static str> {
    let f = probe::invalid_opcode().err().ok_or("ud2 did not fault")?;
    ensure(f.vector == vector::INVALID_OPCODE, "expected #UD")
}

fn divide_error() -> Result<(), &'static str> {
    ensure(probe::divide(10, 3) == Ok(3), "10 / 3 should be 3")?;
    let f = probe::divide(1, core::hint::black_box(0)).err().ok_or("division by zero did not fault")?;
    ensure(f.vector == vector::DIVIDE_ERROR, "expected #DE")
}

fn backtrace_walks() -> Result<(), &'static str> {
    let mut frames = 0;
    backtrace::walk(|ret| {
        if ret >= 0xFFFF_FFFF_8000_0000 {
            frames += 1;
        }
    });
    ensure(frames >= 2, "expected at least two kernel frames")?;
    ensure(super::extable_len() >= 5, "exception table is missing probe entries")
}

/// Ctrl-Alt-Del needs Delete pressed with a Ctrl and an Alt held, either
/// side (ADR 0060).
fn ctrl_alt_del_keys() -> Result<(), &'static str> {
    use crate::drivers::input::is_ctrl_alt_del;
    let with = |held: &[u16]| {
        let mut k = [0u64; 12];
        for &c in held {
            k[usize::from(c / 64)] |= 1 << (c % 64);
        }
        k
    };
    let cases: [(&[u16], u16, bool); 6] = [
        (&[29, 56], 111, true),
        (&[97, 100], 111, true),
        (&[29, 100], 111, true),
        (&[29], 111, false),
        (&[56], 111, false),
        (&[29, 56], 14, false),
    ];
    for (held, code, want) in cases {
        if is_ctrl_alt_del(&with(held), code) != want {
            return Err("wrong Ctrl-Alt-Del decision");
        }
    }
    Ok(())
}

/// The kernel log read from a position: whole lines, and the position
/// moves past them.
fn kernel_log_from() -> Result<(), &'static str> {
    let (_, end) = crate::log::read_from(usize::MAX, 1 << 20);
    crate::log_info!("kernel_log_from marker");
    let (text, next) = crate::log::read_from(end, 1 << 20);
    let s = core::str::from_utf8(&text).map_err(|_| "not text")?;
    if !s.contains("kernel_log_from marker") || !s.ends_with('\n') || next != end + text.len() {
        return Err("the new line was not read");
    }
    let (again, same) = crate::log::read_from(next, 1 << 20);
    if !again.is_empty() || same != next {
        return Err("read past the end");
    }
    // A position older than the ring starts at its first whole line.
    let (old, _) = crate::log::read_from(0, 64);
    if old.last().is_some_and(|&b| b != b'\n') {
        return Err("a partial line");
    }
    Ok(())
}

/// Device interrupts go to the CPUs in turn, never the bootstrap CPU when
/// there are others.
fn irq_targets_spread() -> Result<(), &'static str> {
    let n = crate::sched::cpu_count();
    let bsp = crate::sched::apic_id_of(0);
    let mut seen = alloc::vec::Vec::new();
    for _ in 0..n {
        let t = super::irq::device_irq_target();
        if n > 1 && t == bsp {
            return Err("a device interrupt went to the bootstrap CPU");
        }
        if !seen.contains(&t) {
            seen.push(t);
        }
    }
    if seen.len() != n.saturating_sub(1).max(1) {
        return Err("the targets did not go round the CPUs");
    }
    Ok(())
}

/// /proc/interrupts: a column per CPU, the devices' rows, and the local
/// timer counted on every CPU.
fn proc_interrupts() -> Result<(), &'static str> {
    let mut s = alloc::string::String::new();
    super::irq::proc_interrupts(&mut s);
    let n = crate::sched::cpu_count();
    let header = s.lines().next().ok_or("empty")?;
    if header.split_whitespace().count() != n || !header.ends_with(&alloc::format!("CPU{}", n - 1)) {
        return Err("wrong header");
    }
    let loc = s.lines().find(|l| l.trim_start().starts_with("LOC:")).ok_or("no LOC row")?;
    let counts: alloc::vec::Vec<u64> = loc.split_whitespace().skip(1).take(n).filter_map(|c| c.parse().ok()).collect();
    if counts.len() != n || counts.contains(&0) {
        return Err("a CPU took no timer interrupts");
    }
    if !s.contains("serial") {
        return Err("no serial row");
    }
    Ok(())
}

/// Where the bootloader put the kernel (KASLR, ADR 0095): a page inside the
/// first gigabyte of the top 2 GiB, with pointers stored in data moved
/// along. The slide is printed for xtask, which checks that boots differ.
fn kaslr() -> Result<(), &'static str> {
    static TARGET: u8 = 0;
    static POINTER: &u8 = &TARGET;
    let slide = super::paging::kernel_slide();
    crate::kprintln!("kaslr: slide {slide:#x}");
    let base = 0xffff_ffff_8000_0000u64.wrapping_add(slide);
    ensure(slide % 4096 == 0, "the kernel is not page-aligned")?;
    ensure((0xffff_ffff_8000_0000..0xffff_ffff_c000_0000).contains(&base), "the kernel is outside its range")?;
    ensure(core::ptr::eq(core::hint::black_box(POINTER), &TARGET), "a stored pointer was not relocated")
}

/// termios' framing as the UART's line control register has it.
fn serial_framing() -> Result<(), &'static str> {
    use super::serial::Framing;
    let lcr = |bits, two_stop, parity| Framing { bits, two_stop, parity }.lcr();
    if lcr(8, false, None) != 0x03 {
        return Err("8N1");
    }
    if lcr(7, false, Some(false)) != 0x1A {
        return Err("7E1");
    }
    if lcr(8, true, Some(true)) != 0x0F {
        return Err("8O2");
    }
    if lcr(5, false, None) != 0x00 {
        return Err("5N1");
    }
    Ok(())
}
