// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-loader for BIOS (ADR 0089). The boot sector loads it from the BIOS
//! boot partition (or the gap before the first partition) to 0x8000; it
//! enters long mode, reads the menu, the kernel and its modules from the
//! EFI System Partition through the BIOS's disk calls, and boots the entry
//! with the core the UEFI loader shares.

#![no_std]
#![no_main]

extern crate alloc;

mod bios;
mod disk;
mod mem;
mod menu;
mod rm;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use slate_loader::boot::{self as core_boot, File, Kind, Memory};
use slate_loader::memmap::{self, Region};
use slate_loader::proto::{self, memtype};
use slate_loader::{config, cpu};

/// A graphics mode is set: the BIOS's teletype must not draw over it.
static GRAPHICS: AtomicBool = AtomicBool::new(false);

/// COM1, for the line each step writes (QEMU's tests read it).
fn serial(s: &str) {
    for b in s.bytes() {
        // SAFETY: Port I/O on COM1's data and line status registers; on a
        // machine without it, the writes go nowhere.
        unsafe {
            for _ in 0..10_000 {
                let status: u8;
                core::arch::asm!("in al, dx", out("al") status, in("dx") 0x3fdu16, options(nomem, nostack));
                if status & 0x20 != 0 {
                    break;
                }
            }
            core::arch::asm!("out dx, al", in("dx") 0x3f8u16, in("al") b, options(nomem, nostack));
        }
    }
}

/// A line on the screen (the BIOS's teletype, in text mode) and the serial
/// port.
pub fn print(s: &str) {
    serial(s);
    if !GRAPHICS.load(Ordering::Relaxed) {
        for b in s.bytes() {
            rm::int(0x10, rm::Regs { eax: 0x0e00 | u32::from(b), ebx: 7, ..Default::default() });
        }
    }
}

fn halt() -> ! {
    loop {
        // SAFETY: Halting stops this CPU.
        unsafe { core::arch::asm!("cli", "hlt") };
    }
}

/// The stack the loader moves to once it has memory.
const STACK: u64 = 256 << 10;

core::arch::global_asm!(
    // slate_bios_switch(top, f, arg): f(arg) on the stack ending at top.
    ".globl slate_bios_switch",
    "slate_bios_switch:",
    "    mov %rdi, %rsp",
    "    and $-16, %rsp",
    "    mov %rdx, %rdi",
    "    call *%rsi",
    "    ud2",
    options(att_syntax)
);

unsafe extern "sysv64" {
    fn slate_bios_switch(top: u64, f: extern "sysv64" fn(u64) -> !, arg: u64) -> !;
}

/// What the loader knows when it moves to its large stack.
struct Start {
    drive: u8,
    e820: Vec<Region>,
}

#[unsafe(no_mangle)]
extern "sysv64" fn slate_bios_main(drive: u32) -> ! {
    // The memory map without the heap: the heap is made from it.
    let (map, n) = bios::memory_map();
    let r = mem::init(&map[..n]).map_err(String::from).and_then(|()| {
        let stack = mem::Pool.pages(Kind::Loader, STACK, None)?;
        Ok((stack, alloc::boxed::Box::new(Start { drive: drive as u8, e820: map[..n].to_vec() })))
    });
    match r {
        // SAFETY: The stack is loader memory just taken, one to one; `on`
        // gets the box back from the pointer.
        Ok((stack, start)) => unsafe {
            slate_bios_switch(stack + STACK, on, alloc::boxed::Box::into_raw(start) as u64)
        },
        Err(e) => fail(e),
    }
}

extern "sysv64" fn on(start: u64) -> ! {
    // SAFETY: The box `slate_bios_main` made.
    let start = unsafe { alloc::boxed::Box::from_raw(start as *mut Start) };
    match run(start.drive, start.e820) {
        Ok(never) => match never {},
        Err(e) => fail(e),
    }
}

fn fail(e: String) -> ! {
    if GRAPHICS.swap(false, Ordering::Relaxed) {
        bios::text_mode();
    }
    print(&format!("slate-loader: {e}\r\n"));
    halt()
}

enum Never {}

fn run(drive: u8, e820: Vec<Region>) -> Result<Never, String> {
    let start = disk::esp(drive)?;
    let mut fs =
        slate_fat::edit::Fs::open(disk::Part { drive, start }).map_err(|e| format!("boot partition: {e:?}"))?;
    let (path, text) = config::FILES
        .iter()
        .find_map(|p| fs.read(p).ok().map(|d| (*p, d)))
        .ok_or("no menu file (boot/limine/limine.conf or boot/limine.conf)")?;
    let text = core::str::from_utf8(&text).map_err(|_| format!("{path}: not text"))?;
    let menu = config::parse(text).map_err(|e| format!("{path}, line {}: {}", e.line, e.what))?;
    // Other systems' EFI loaders are for the UEFI loader (ADR 0116).
    let mut menu = menu.without_efi().ok_or_else(|| format!("{path}: nothing a BIOS can start"))?;
    // A one-shot choice (ADR 0116), cleared as it is taken.
    if menu.apply_next(fs.read(slate_esp::NEXT).ok().as_deref())
        && let Err(e) = fs.write(slate_esp::NEXT, b"")
    {
        print(&format!("slate-loader: {}: {e:?}\r\n", slate_esp::NEXT));
    }
    // The loader's count of a trial boot (`slate_loader::trial`).
    let default = menu.default;
    let tries = fs.read(slate_esp::TRIES).ok();
    if let Some(t) = slate_loader::trial::apply(&mut menu, tries.as_deref())
        && let Err(e) = fs.write(slate_esp::TRIES, t.as_bytes())
    {
        print(&format!("slate-loader: {}: {e:?}\r\n", slate_esp::TRIES));
    }
    if menu.default != default {
        print("slate-loader: the new system did not start; starting the previous one\r\n");
    }

    // The screen the kernel gets, and the menu's if it has one.
    let mode = bios::choose(&bios::modes(), bios::preferred()).filter(bios::set_mode);
    GRAPHICS.store(mode.is_some(), Ordering::Relaxed);
    let choice = menu::choose(&menu, mode.as_ref());
    let mut entry = menu.entries[choice.entry].clone();
    entry.cmdline = choice.cmdline;
    serial(&format!("slate-loader: booting {} ({})\r\n", entry.title, entry.kernel));

    let mut pool = mem::Pool;
    let mut load = |path: &str, kind: Kind| -> Result<File, String> {
        let len = fs.size(path).map_err(|e| format!("{path}: {e:?}"))?;
        let phys = pool.pages(kind, len, None)?;
        // SAFETY: Pages just taken, `len` bytes.
        let buf = unsafe { core::slice::from_raw_parts_mut(phys as *mut u8, len as usize) };
        // The file system's own buffers go to the kernel's memory too.
        mem::for_kernel(|| fs.read_into(path, buf)).map_err(|e| format!("{path}: {e:?}"))?;
        Ok(File { phys, len })
    };
    let kfile = load(&entry.kernel, Kind::Loader)?;
    let modules: Vec<(File, &config::Module)> =
        entry.modules.iter().map(|m| load(&m.path, Kind::Kernel).map(|f| (f, m))).collect::<Result<_, _>>()?;
    let (plan, image) = core_boot::load_kernel(&mut pool, &entry, &kfile)?;

    let framebuffer = mode.as_ref().map(|m| proto::Framebuffer {
        address: m.base,
        width: u64::from(m.width),
        height: u64::from(m.height),
        pitch: u64::from(m.pitch),
        bpp: 32,
        memory_model: proto::MEMORY_MODEL_RGB,
        red_mask_size: m.masks[0].0,
        red_mask_shift: m.masks[0].1,
        green_mask_size: m.masks[1].0,
        green_mask_shift: m.masks[1].1,
        blue_mask_size: m.masks[2].0,
        blue_mask_shift: m.masks[2].1,
        ..Default::default()
    });
    let map_now = |fb: Option<&proto::Framebuffer>| {
        let mut r: Vec<Region> = e820.clone();
        r.extend(mem::used());
        if let Some(f) = fb {
            r.push(Region { base: f.address, len: f.pitch * f.height, kind: memtype::FRAMEBUFFER });
        }
        memmap::normalize(&r)
    };
    let machine = core_boot::Machine {
        firmware: proto::FIRMWARE_X86_BIOS,
        rsdp: rsdp(),
        efi_system_table: None,
        date: date(),
        framebuffer,
        tsc_per_us: tsc_per_us(),
        map: map_now(framebuffer.as_ref()),
        map_capacity: e820.len() * 2 + 64,
    };
    let prepared = core_boot::prepare(&mut pool, &entry, &kfile, &plan, image, &modules, &machine)?;
    let last = map_now(framebuffer.as_ref());
    // SAFETY: There are no boot services to end; the loader runs one to one
    // on the boot tables, its code and data in the direct map.
    unsafe { prepared.finish(&last) }
}

/// The RSDP (ACPI 6.5 §5.2.5.1): on a 16-byte boundary in the first KiB of
/// the EBDA, or in 0xE0000 to 0xFFFFF.
fn rsdp() -> Option<u64> {
    // SAFETY: The BIOS data area's EBDA segment, a 16-bit word.
    let ebda = usize::from(unsafe { core::ptr::read_volatile(0x40e as *const u16) }) << 4;
    let areas = [(ebda, ebda + 1024), (0xe0000, 0x100000)];
    areas
        .iter()
        .filter(|(s, _)| *s != 0)
        .find_map(|&(s, e)| {
            (s..e).step_by(16).find(|&a| {
                // SAFETY: Firmware memory below 1 MiB, one to one.
                let b = unsafe { core::slice::from_raw_parts(a as *const u8, slate_acpi_len(a, e)) };
                b.starts_with(b"RSD PTR ") && slate_acpi::parse_rsdp(b).is_ok()
            })
        })
        .map(|a| a as u64)
}

/// Bytes an RSDP at `a` may take before `end`.
fn slate_acpi_len(a: usize, end: usize) -> usize {
    (end - a).min(slate_acpi::RSDP_MAX_LEN)
}

/// The CMOS clock (libs/rtc), as UNIX time.
fn date() -> Option<i64> {
    struct Ports;
    impl slate_rtc::Cmos for Ports {
        fn read(&mut self, reg: u8) -> u8 {
            let v: u8;
            // SAFETY: The CMOS index and data ports (0x70, 0x71).
            unsafe {
                core::arch::asm!("out 0x70, al", in("al") reg, options(nomem, nostack));
                core::arch::asm!("in al, 0x71", out("al") v, options(nomem, nostack));
            }
            v
        }
        fn write(&mut self, reg: u8, value: u8) {
            // SAFETY: As in `read`.
            unsafe {
                core::arch::asm!("out 0x70, al", in("al") reg, options(nomem, nostack));
                core::arch::asm!("out 0x71, al", in("al") value, options(nomem, nostack));
            }
        }
    }
    slate_rtc::read(&mut Ports, None).map(|d| d.to_unix())
}

/// Calibrate the time-stamp counter against the BIOS's wait.
fn tsc_per_us() -> u64 {
    let t = cpu::rdtsc();
    bios::wait_us(10_000);
    ((cpu::rdtsc() - t) / 10_000).max(1)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    serial(&format!("slate-loader: {info}\r\n"));
    halt()
}
