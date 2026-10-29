// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-loader for UEFI (ADR 0089): `EFI/BOOT/BOOTX64.EFI` (or
//! `EFI/slate/BOOTX64.EFI` on a partition shared with another system, ADR
//! 0116). It reads the menu file from its own partition, lets the user
//! choose (or boots the default), loads the kernel and its modules,
//! answers the kernel's Limine-protocol requests, leaves boot services,
//! starts the other CPUs and jumps to the kernel; or it starts another
//! system's EFI loader.

#![no_std]
#![no_main]

extern crate alloc;

mod console;
mod efi;
mod files;
mod menu;
mod screentest;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};

use efi::{BootServices, Handle, Status, SystemTable, memory};
use slate_loader::boot::{self as core_boot, Kind, Memory};
use slate_loader::memmap::{self, Region};
use slate_loader::paging::PAGE;
use slate_loader::proto::{self, memtype};
use slate_loader::{config, cpu};

static SYSTEM_TABLE: AtomicPtr<SystemTable> = AtomicPtr::new(core::ptr::null_mut());
/// Boot services are over: no more firmware calls but the runtime ones.
static EXITED: AtomicBool = AtomicBool::new(false);

fn st() -> &'static SystemTable {
    // SAFETY: Set once at entry to the firmware's system table, which
    // stays valid.
    unsafe { &*SYSTEM_TABLE.load(Ordering::Relaxed) }
}

fn bs() -> &'static BootServices {
    assert!(!EXITED.load(Ordering::Relaxed), "boot services used after they ended");
    // SAFETY: The table's boot services pointer is valid until
    // ExitBootServices, which `EXITED` guards.
    unsafe { &*st().boot_services }
}

/// The heap: pool memory while boot services last, then a block set aside
/// before they end (nothing is freed after that).
struct Heap;

static LATE: AtomicU64 = AtomicU64::new(0);
static LATE_END: AtomicU64 = AtomicU64::new(0);

// SAFETY: Allocation goes to the firmware's pool (8-byte aligned; larger
// alignments over-allocate and keep the pool pointer before the block), or
// after boot services to a bump allocator over memory the loader owns.
unsafe impl core::alloc::GlobalAlloc for Heap {
    unsafe fn alloc(&self, l: core::alloc::Layout) -> *mut u8 {
        if EXITED.load(Ordering::Relaxed) {
            let at = LATE.load(Ordering::Relaxed).next_multiple_of(l.align() as u64);
            if at + l.size() as u64 > LATE_END.load(Ordering::Relaxed) {
                return core::ptr::null_mut();
            }
            LATE.store(at + l.size() as u64, Ordering::Relaxed);
            return at as *mut u8;
        }
        let extra = if l.align() > 8 { l.align() } else { 0 };
        let mut p: *mut u8 = core::ptr::null_mut();
        if efi::is_error((bs().allocate_pool)(memory::LOADER_DATA, l.size() + extra, &mut p)) {
            return core::ptr::null_mut();
        }
        if extra == 0 {
            return p;
        }
        let a = (p as usize + 8).next_multiple_of(l.align());
        // SAFETY: `a - 8` is inside the over-allocated block.
        unsafe { *((a - 8) as *mut *mut u8) = p };
        a as *mut u8
    }

    unsafe fn dealloc(&self, p: *mut u8, l: core::alloc::Layout) {
        // Nothing is freed once boot services are over.
        if EXITED.load(Ordering::Relaxed) {
            return;
        }
        let pool = if l.align() > 8 {
            // SAFETY: `alloc` stored the pool pointer there.
            unsafe { *((p as usize - 8) as *const *mut u8) }
        } else {
            p
        };
        (bs().free_pool)(pool);
    }
}

#[global_allocator]
static HEAP: Heap = Heap;

const LATE_SIZE: u64 = 4 << 20;

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    if !EXITED.load(Ordering::Relaxed) {
        console::print(&format!("slate-loader: {info}\r\n"));
        (bs().stall)(10_000_000);
    }
    loop {
        // SAFETY: Halting with interrupts off stops this CPU.
        unsafe { core::arch::asm!("cli", "hlt") };
    }
}

#[unsafe(no_mangle)]
extern "efiapi" fn efi_main(image: Handle, st: *mut SystemTable) -> Status {
    SYSTEM_TABLE.store(st, Ordering::Relaxed);
    match run(image) {
        Ok(never) => match never {},
        Err(e) => {
            console::print(&format!("slate-loader: {e}\r\n"));
            // Time to read it; then the firmware tries what comes next.
            (bs().stall)(10_000_000);
            efi::INVALID_PARAMETER
        }
    }
}

enum Never {}

fn run(image: Handle) -> Result<Never, String> {
    // No firmware watchdog while the menu waits (§7.5.1).
    (bs().set_watchdog_timer)(0, 0, 0, core::ptr::null());
    let loaded: *mut efi::LoadedImage = protocol(image, &efi::LOADED_IMAGE)?;
    // SAFETY: The firmware's loaded image protocol for this image.
    let device = unsafe { (*loaded).device_handle };
    let volume = files::Volume::open(protocol(device, &efi::SIMPLE_FILE_SYSTEM)?)?;
    let (path, text) = config::FILES
        .iter()
        .find_map(|p| volume.read(p).ok().map(|d| (*p, d)))
        .ok_or("no menu file (boot/limine/limine.conf or boot/limine.conf)")?;
    let text = core::str::from_utf8(&text).map_err(|_| format!("{path}: not text"))?;
    let mut menu = config::parse(text).map_err(|e| format!("{path}, line {}: {}", e.line, e.what))?;
    // A one-shot choice (ADR 0116), blanked as it is taken (the loader
    // only overwrites).
    let next = volume.read(slate_esp::NEXT).ok();
    if menu.apply_next(next.as_deref())
        && let Err(e) = volume.overwrite(slate_esp::NEXT, &alloc::vec![b' '; next.map_or(0, |n| n.len())])
    {
        console::print(&format!("slate-loader: {e}\r\n"));
    }
    count_trial(&mut menu, |p| volume.read(p).ok(), |p, d| volume.overwrite(p, d));
    let mut log = String::new();
    let test = volume.read("slate-screen-test").is_ok();
    let mut gop = graphics(menu.resolution, test, &mut log);
    // What the screen is, for a machine where it shows wrongly: kept in
    // `slate-loader.log` on the boot volume when that file is there (the
    // loader only overwrites files).
    if volume.overwrite(LOG, &log.as_bytes()[..log.len().min(LOG_MAX)]).is_ok() {
        console::print("slate-loader: wrote slate-loader.log\r\n");
    }
    let choice = menu::choose(&menu, gop.as_mut());
    let mut entry = menu.entries[choice.entry].clone();
    entry.cmdline = choice.cmdline;
    console::print(&format!("slate-loader: booting {} ({})\r\n", entry.title, entry.kernel));
    if entry.efi {
        return chainload(image, device, &entry);
    }
    boot(image, &volume, &entry, gop)
}

/// Start another system's EFI loader (ADR 0116): read it from its
/// partition, and load it with the device path that names it there, so
/// it finds its own files (LoadImage and StartImage, §7.4).
fn chainload(image: Handle, own: Handle, entry: &config::Entry) -> Result<Never, String> {
    let device = match entry.volume {
        config::Volume::Boot => own,
        config::Volume::Guid(g) => {
            partition(&g).ok_or_else(|| format!("{}: its partition is not there", entry.title))?
        }
    };
    let data = files::Volume::open(protocol(device, &efi::SIMPLE_FILE_SYSTEM)?)?.read(&entry.kernel)?;
    let mut path = device_path(device).ok_or("the partition has no device path")?;
    let name = files::name(&entry.kernel);
    path.extend([efi::path::MEDIA, efi::path::FILE]);
    path.extend(((4 + 2 * name.len()) as u16).to_le_bytes());
    path.extend(name.iter().flat_map(|u| u.to_le_bytes()));
    path.extend([efi::path::END, efi::path::END_ENTIRE, 4, 0]);
    let mut child: Handle = core::ptr::null_mut();
    let s = (bs().load_image)(false, image, path.as_ptr(), data.as_ptr(), data.len(), &mut child);
    if efi::is_error(s) {
        return Err(format!("{}: the firmware would not load it (status {s:#x})", entry.kernel));
    }
    let (mut size, mut exit) = (0usize, core::ptr::null_mut());
    let s = (bs().start_image)(child, &mut size, &mut exit);
    Err(format!("{} stopped (status {s:#x})", entry.title))
}

/// A handle's device path, without its end node.
fn device_path(handle: Handle) -> Option<Vec<u8>> {
    let p: *const u8 = protocol(handle, &efi::DEVICE_PATH).ok()?;
    let mut out = Vec::new();
    loop {
        // SAFETY: The firmware's device path: nodes of at least four bytes,
        // each giving its length, up to an end node (bounded below).
        let (kind, len) = unsafe {
            let at = p.add(out.len());
            (*at, usize::from(u16::from_le_bytes([*at.add(2), *at.add(3)])))
        };
        if kind == efi::path::END {
            return Some(out);
        }
        if len < 4 || out.len() + len > 4096 {
            return None;
        }
        // SAFETY: The node is `len` bytes, as it says.
        out.extend_from_slice(unsafe { core::slice::from_raw_parts(p.add(out.len()), len) });
    }
}

/// The file system on the partition with GPT unique GUID `guid`: its hard
/// drive node carries it as the signature (§10.3.5.1).
fn partition(guid: &[u8; 16]) -> Option<Handle> {
    let (mut count, mut handles) = (0usize, core::ptr::null_mut());
    let s = (bs().locate_handle_buffer)(
        efi::BY_PROTOCOL,
        &efi::SIMPLE_FILE_SYSTEM,
        core::ptr::null_mut(),
        &mut count,
        &mut handles,
    );
    if efi::is_error(s) || handles.is_null() {
        return None;
    }
    // SAFETY: The firmware's array of `count` handles, freed below.
    let list: Vec<Handle> = unsafe { core::slice::from_raw_parts(handles, count) }.to_vec();
    (bs().free_pool)(handles.cast());
    list.into_iter().find(|&h| {
        let Some(p) = device_path(h) else { return false };
        let mut at = 0;
        while at + 4 <= p.len() {
            let len = usize::from(u16::from_le_bytes([p[at + 2], p[at + 3]]));
            let n = &p[at..(at + len).min(p.len())];
            if n[0] == efi::path::MEDIA
                && n[1] == efi::path::HARD_DRIVE
                && n.len() >= 42
                && n[41] == efi::path::SIGNATURE_GUID
                && n[24..40] == guid[..]
            {
                return true;
            }
            at += len.max(4);
        }
        false
    })
}

/// The loader's count of a trial boot (`slate_loader::trial`): one boot
/// fewer, or the previous system once none is left.
fn count_trial(
    menu: &mut config::Menu,
    read: impl FnOnce(&str) -> Option<Vec<u8>>,
    write: impl FnOnce(&str, &[u8]) -> Result<(), String>,
) {
    let tries = read(slate_esp::TRIES);
    let default = menu.default;
    if let Some(text) = slate_loader::trial::apply(menu, tries.as_deref())
        && let Err(e) = write(slate_esp::TRIES, text.as_bytes())
    {
        console::print(&format!("slate-loader: {e}\r\n"));
    }
    if menu.default != default {
        console::print("slate-loader: the new system did not start; starting the previous one\r\n");
    }
}

/// A protocol on a handle (HandleProtocol, §7.3.7).
fn protocol<T>(handle: Handle, guid: &efi::Guid) -> Result<*mut T, String> {
    let mut p: *mut c_void = core::ptr::null_mut();
    let s = (bs().handle_protocol)(handle, guid, &mut p);
    if efi::is_error(s) || p.is_null() {
        return Err(format!("no protocol {:08x} on the boot device (status {s:#x})", guid.0));
    }
    Ok(p.cast())
}

/// The screen, if the firmware has one (LocateProtocol, §7.3.16).
#[derive(Debug)]
pub struct Screen {
    pub base: u64,
    pub size: u64,
    pub width: u32,
    pub height: u32,
    /// Pixels per scan line.
    pub stride: u32,
    pub format: u32,
    pub masks: [u32; 3],
    /// The firmware's protocol, and the mode the loader chose.
    pub gop: *mut efi::GraphicsOutput,
    pub mode: u32,
}

impl Screen {
    /// The mode's facts as the firmware now gives them.
    fn read(gop: *mut efi::GraphicsOutput) -> Screen {
        // SAFETY: The firmware's graphics output protocol, its current mode
        // and that mode's information.
        let (m, i) = unsafe {
            let m = &*(*gop).mode;
            (m, &*m.info)
        };
        Screen {
            base: m.frame_buffer_base,
            size: m.frame_buffer_size as u64,
            width: i.horizontal_resolution,
            height: i.vertical_resolution,
            stride: i.pixels_per_scan_line,
            format: i.pixel_format,
            masks: [i.red_mask, i.green_mask, i.blue_mask],
            gop,
            mode: m.mode,
        }
    }

    /// Put the chosen mode back if something changed it. The reference PC's NVIDIA
    /// firmware switches to its text console's mode (1024 x 768) when the
    /// console is cleared, while the loader would go on drawing, and the
    /// kernel would take over, in the mode chosen: a wrapped, sheared
    /// picture (ADR 0111). So this runs before every menu frame and once
    /// more after the last console output. Whether it had to.
    pub fn keep(&mut self) -> bool {
        // SAFETY: The firmware's graphics output protocol and its mode.
        let (now, set) = unsafe { ((*(*self.gop).mode).mode, (*self.gop).set_mode) };
        if now == self.mode || efi::is_error(set(self.gop, self.mode)) {
            return false;
        }
        *self = Screen::read(self.gop);
        true
    }
}

/// The screen's log on the boot volume, and the most of it written.
const LOG: &str = "slate-loader.log";
const LOG_MAX: usize = 60 * 1024;

fn graphics(wanted: Option<(u32, u32)>, test: bool, log: &mut String) -> Option<Screen> {
    let mut p: *mut c_void = core::ptr::null_mut();
    if efi::is_error((bs().locate_protocol)(&efi::GRAPHICS_OUTPUT, core::ptr::null_mut(), &mut p)) || p.is_null() {
        return None;
    }
    let first = best_mode(p.cast(), wanted, log);
    if test {
        // SAFETY: The firmware's graphics output protocol.
        let chosen = unsafe { (*(*(p as *const efi::GraphicsOutput)).mode).mode };
        let mut modes = alloc::vec![first, chosen];
        modes.dedup();
        screentest::run(p.cast(), &modes);
        // Back to the chosen mode.
        // SAFETY: As above.
        let set = unsafe { (*(p as *const efi::GraphicsOutput)).set_mode };
        set(p.cast(), chosen);
    }
    // SAFETY: The firmware's graphics output protocol, its current mode
    // and that mode's information.
    let (m, i) = unsafe {
        let g = &*(p as *const efi::GraphicsOutput);
        let m = &*g.mode;
        (m, &*m.info)
    };
    log.push_str(&format!(
        "now: mode {} of {}, {}x{}, {} pixels a line, format {} (masks {:#x} {:#x} {:#x}), base {:#x}, size {:#x}\n",
        m.mode,
        m.max_mode,
        i.horizontal_resolution,
        i.vertical_resolution,
        i.pixels_per_scan_line,
        i.pixel_format,
        i.red_mask,
        i.green_mask,
        i.blue_mask,
        m.frame_buffer_base,
        m.frame_buffer_size
    ));
    if !usable(i) || m.frame_buffer_base == 0 {
        return None;
    }
    Some(Screen::read(p.cast()))
}

/// Whether a mode's pixels are 32-bit ones the loader and the kernel can
/// draw (§12.9, EFI_GRAPHICS_PIXEL_FORMAT).
fn usable(i: &efi::ModeInformation) -> bool {
    matches!(i.pixel_format, efi::PIXEL_RGB | efi::PIXEL_BGR | efi::PIXEL_BITMASK)
}

/// The display's EDID, from the first graphics handle that has one
/// (LocateHandleBuffer, §7.3.15): its resolution.
fn display_resolution(log: &mut String) -> Option<(u32, u32)> {
    let (mut n, mut handles): (usize, *mut efi::Handle) = (0, core::ptr::null_mut());
    let s = (bs().locate_handle_buffer)(
        efi::BY_PROTOCOL,
        &efi::GRAPHICS_OUTPUT,
        core::ptr::null_mut(),
        &mut n,
        &mut handles,
    );
    if efi::is_error(s) || handles.is_null() {
        return None;
    }
    // SAFETY: The firmware's buffer of `n` handles.
    let list = unsafe { core::slice::from_raw_parts(handles, n) };
    log.push_str(&format!("graphics handles: {n}\n"));
    let found = list.iter().find_map(|&h| {
        [&efi::EDID_ACTIVE, &efi::EDID_DISCOVERED].iter().find_map(|guid| {
            let e: *mut efi::Edid = protocol(h, guid).ok()?;
            // SAFETY: The firmware's EDID protocol: `size_of_edid` bytes
            // at `edid`.
            let bytes = unsafe {
                let e = &*e;
                if e.edid.is_null() || e.size_of_edid < 128 {
                    return None;
                }
                core::slice::from_raw_parts(e.edid, e.size_of_edid as usize)
            };
            log.push_str(&format!("EDID {:08x}, {} bytes:", guid.0, bytes.len()));
            for b in &bytes[..128] {
                log.push_str(&format!(" {b:02x}"));
            }
            log.push('\n');
            slate_loader::mode::native(bytes)
        })
    });
    (bs().free_pool)(handles.cast());
    found
}

/// Set the screen to the display's own resolution (or the menu file's
/// `interface_resolution`), or the best the firmware offers that fits
/// (ADR 0111): firmware often leaves a low mode, which the kernel's
/// firmware framebuffer would keep. Returns the mode it was in.
fn best_mode(g: *mut efi::GraphicsOutput, wanted: Option<(u32, u32)>, log: &mut String) -> u32 {
    // SAFETY: The firmware's graphics output protocol and its mode.
    let (query, set, max, current) = unsafe {
        let p = &*g;
        (p.query_mode, p.set_mode, (*p.mode).max_mode, (*p.mode).mode)
    };
    let mut modes = Vec::new();
    let mut now = None;
    for number in 0..max {
        let (mut size, mut info): (usize, *mut efi::ModeInformation) = (0, core::ptr::null_mut());
        if efi::is_error(query(g, number, &mut size, &mut info)) || info.is_null() {
            continue;
        }
        // SAFETY: The mode's information, which the firmware allocated.
        let i = unsafe { &*info };
        let m = slate_loader::mode::Mode {
            number,
            width: i.horizontal_resolution,
            height: i.vertical_resolution,
            usable: usable(i),
        };
        log.push_str(&format!(
            "mode {number}: {}x{}, {} pixels a line, format {}{}\n",
            i.horizontal_resolution,
            i.vertical_resolution,
            i.pixels_per_scan_line,
            i.pixel_format,
            if number == current { " (set at boot)" } else { "" }
        ));
        (bs().free_pool)(info.cast());
        if number == current {
            now = Some(m);
        }
        modes.push(m);
    }
    let edid = display_resolution(log);
    let display = wanted.or(edid);
    let from_edid = edid.map_or_else(|| String::from("no EDID"), |(w, h)| format!("{w}x{h} by its EDID"));
    let shown = match wanted {
        Some((w, h)) => format!("{w}x{h} from the menu file; {from_edid}"),
        None => from_edid,
    };
    let size = |m: Option<&slate_loader::mode::Mode>| {
        m.map_or_else(|| String::from("?"), |m| format!("{}x{}", m.width, m.height))
    };
    let line = match slate_loader::mode::choose(&modes, now, display) {
        Some(number) => {
            let s = set(g, number);
            let to = size(modes.iter().find(|m| m.number == number));
            if efi::is_error(s) { format!("{to} refused (status {s:#x})") } else { format!("set to {to}") }
        }
        None => format!("kept at {}", size(now.as_ref())),
    };
    let line = format!("slate-loader: screen {line} (display: {shown})");
    log.push_str(&line);
    log.push('\n');
    console::print(&format!("{line}\r\n"));
    current
}

/// Pages of a memory type (AllocatePages, §7.2.1), below `max` if given.
fn pages(kind: u32, bytes: u64, max: Option<u64>) -> Result<u64, String> {
    let n = bytes.div_ceil(PAGE) as usize;
    let mut at = max.unwrap_or(0);
    let how = if max.is_some() { efi::ALLOCATE_MAX_ADDRESS } else { efi::ALLOCATE_ANY_PAGES };
    // Everything is the firmware's loader data: the reference PC's firmware does not
    // get through ExitBootServices with the memory types left to loaders
    // (0x80000000 and up) in its map (ADR 0089). The kernel's own ranges
    // are remembered here instead.
    let s = (bs().allocate_pages)(how, memory::LOADER_DATA, n, &mut at);
    if efi::is_error(s) {
        return Err(format!("out of memory ({bytes} bytes, status {s:#x})"));
    }
    if kind == memory::SLATE_KERNEL {
        let i = KERNEL_RANGES_LEN.fetch_add(1, Ordering::Relaxed);
        let slot = KERNEL_RANGES.get(i).ok_or("too many kernel and module files")?;
        slot[0].store(at, Ordering::Relaxed);
        slot[1].store(n as u64 * PAGE, Ordering::Relaxed);
    }
    // SAFETY: The firmware just gave these pages, identity mapped.
    unsafe { core::ptr::write_bytes(at as *mut u8, 0, n * PAGE as usize) };
    Ok(at)
}

/// The kernel's and the modules' memory: (base, length) each.
static KERNEL_RANGES: [[AtomicU64; 2]; 64] = [const { [AtomicU64::new(0), AtomicU64::new(0)] }; 64];
static KERNEL_RANGES_LEN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// The firmware's memory map: the descriptors, the map key and the
/// descriptor size and version (GetMemoryMap, §7.2.3).
fn memory_map(buf: &mut [u8]) -> Result<(usize, usize, usize, u32), Status> {
    let (mut size, mut key, mut desc, mut ver) = (buf.len(), 0usize, 0usize, 0u32);
    let s = (bs().get_memory_map)(&mut size, buf.as_mut_ptr(), &mut key, &mut desc, &mut ver);
    if efi::is_error(s) {
        return Err(s);
    }
    Ok((size, key, desc, ver))
}

/// What a firmware memory type is to the kernel (ADR 0089).
fn kind_of(t: u32) -> u64 {
    match t {
        memory::CONVENTIONAL | memory::BOOT_SERVICES_CODE | memory::BOOT_SERVICES_DATA => memtype::USABLE,
        memory::LOADER_CODE | memory::LOADER_DATA => memtype::BOOTLOADER_RECLAIMABLE,
        memory::ACPI_RECLAIM => memtype::ACPI_RECLAIMABLE,
        memory::ACPI_NVS => memtype::ACPI_NVS,
        memory::UNUSABLE => memtype::BAD_MEMORY,
        _ => memtype::RESERVED,
    }
}

fn regions(map: &[u8], desc: usize, screen: Option<&Screen>) -> Vec<Region> {
    let mut r: Vec<Region> = map
        .chunks_exact(desc)
        .map(efi::descriptor)
        .map(|(t, base, pages)| Region { base, len: pages * PAGE, kind: kind_of(t) })
        .collect();
    if let Some(s) = screen {
        r.push(Region { base: s.base, len: s.size, kind: memtype::FRAMEBUFFER });
    }
    let n = KERNEL_RANGES_LEN.load(Ordering::Relaxed).min(KERNEL_RANGES.len());
    r.extend(KERNEL_RANGES[..n].iter().map(|k| Region {
        base: k[0].load(Ordering::Relaxed),
        len: k[1].load(Ordering::Relaxed),
        kind: memtype::EXECUTABLE_AND_MODULES,
    }));
    r
}

/// Days from 1970-01-01 to a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The firmware clock as UNIX time (GetTime, §8.3.1); its zone, when it
/// says one, is minutes from UTC.
fn now() -> Option<i64> {
    let mut t = efi::Time::default();
    // SAFETY: The runtime services table stays valid.
    let rt = unsafe { &*st().runtime_services };
    if efi::is_error((rt.get_time)(&mut t, core::ptr::null_mut())) {
        return None;
    }
    let days = days_from_civil(i64::from(t.year), i64::from(t.month), i64::from(t.day));
    let mut s = days * 86_400 + i64::from(t.hour) * 3600 + i64::from(t.minute) * 60 + i64::from(t.second);
    if t.time_zone != efi::UNSPECIFIED_TIMEZONE {
        s -= i64::from(t.time_zone) * 60;
    }
    Some(s)
}

/// The RSDP's physical address, from the configuration tables (§4.6).
fn rsdp() -> Option<u64> {
    let st = st();
    // SAFETY: The firmware's configuration table array.
    let tables = unsafe { core::slice::from_raw_parts(st.configuration_table, st.number_of_table_entries) };
    [efi::ACPI_20, efi::ACPI_10].iter().find_map(|g| tables.iter().find(|t| t.guid == *g)).map(|t| t.table as u64)
}

/// Calibrate the time-stamp counter against the firmware's Stall.
fn tsc_per_us() -> u64 {
    let t = cpu::rdtsc();
    (bs().stall)(2000);
    ((cpu::rdtsc() - t) / 2000).max(1)
}

/// Memory for the loader's core: pages of the loader's own types.
struct UefiMemory;

impl Memory for UefiMemory {
    fn pages(&mut self, kind: Kind, bytes: u64, below: Option<u64>) -> Result<u64, String> {
        let t = match kind {
            Kind::Loader => memory::SLATE_LOADER,
            Kind::Kernel => memory::SLATE_KERNEL,
        };
        pages(t, bytes, below)
    }
}

fn boot(image: Handle, volume: &files::Volume, entry: &config::Entry, screen: Option<Screen>) -> Result<Never, String> {
    let mem = &mut UefiMemory;
    // The console's last words are written: the screen as chosen, for the
    // kernel.
    let mut screen = screen;
    if let Some(s) = screen.as_mut() {
        s.keep();
    }
    // The kernel, its file kept for the executable file response.
    let kfile = volume.read_to(&entry.kernel, memory::SLATE_LOADER)?;
    let (plan, kimage) = core_boot::load_kernel(mem, entry, &kfile)?;
    let modules: Vec<(core_boot::File, &config::Module)> = entry
        .modules
        .iter()
        .map(|m| volume.read_to(&m.path, memory::SLATE_KERNEL).map(|f| (f, m)))
        .collect::<Result<_, _>>()?;
    let mut map_buf = alloc::vec![0u8; 64 << 10];
    let (size, _, desc, _) = memory_map(&mut map_buf).map_err(|s| format!("memory map: {s:#x}"))?;
    let machine = core_boot::Machine {
        firmware: proto::FIRMWARE_EFI64,
        rsdp: rsdp(),
        efi_system_table: Some(SYSTEM_TABLE.load(Ordering::Relaxed) as u64),
        date: now(),
        framebuffer: screen.as_ref().map(framebuffer),
        tsc_per_us: tsc_per_us(),
        map: memmap::normalize(&regions(&map_buf[..size], desc, screen.as_ref())),
        // One entry per descriptor, and some to spare.
        map_capacity: map_buf.len() / desc.max(1) + 64,
    };
    let mut prepared = core_boot::prepare(mem, entry, &kfile, &plan, kimage, &modules, &machine)?;
    let late = pages(memory::SLATE_LOADER, LATE_SIZE, None)?;
    LATE.store(late, Ordering::Relaxed);
    LATE_END.store(late + LATE_SIZE, Ordering::Relaxed);
    let efi_map = pages(memory::SLATE_LOADER, map_buf.len() as u64, None)?;
    // SAFETY: Loader pages, `map_buf.len()` bytes.
    let efi_map_buf = unsafe { core::slice::from_raw_parts_mut(efi_map as *mut u8, map_buf.len()) };

    // The end of boot services (§7.4.6): the last map, then exit; a
    // changed map key means another try.
    let mut last = None;
    for _ in 0..4 {
        let (size, key, desc, ver) = memory_map(efi_map_buf).map_err(|s| format!("memory map: {s:#x}"))?;
        if (bs().exit_boot_services)(image, key) == efi::SUCCESS {
            // No interrupts from here on: the firmware's handlers are still
            // in its IDT, and the services they would call are gone (UEFI
            // runs with them on, and not every firmware stops its timer).
            // SAFETY: Masking interrupts changes nothing else.
            unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
            last = Some((size, desc, ver));
            break;
        }
    }
    let Some((size, desc, ver)) = last else { return Err("ExitBootServices failed".into()) };
    EXITED.store(true, Ordering::Relaxed);

    // From here on only the loader's own memory.
    prepared.answer_efi_memmap(efi_map, size, desc, ver);
    let final_map = memmap::normalize(&regions(&efi_map_buf[..size], desc, screen.as_ref()));
    // SAFETY: Boot services are over; UEFI runs the loader one to one, and
    // its code and data are loader memory, in the direct map.
    unsafe { prepared.finish(&final_map) }
}

/// The framebuffer response for the firmware's screen.
fn framebuffer(s: &Screen) -> proto::Framebuffer {
    let mask = |m: u32| (m.count_ones() as u8, m.trailing_zeros() as u8);
    let (r, g, b) = match s.format {
        efi::PIXEL_RGB => ((8, 0), (8, 8), (8, 16)),
        efi::PIXEL_BGR => ((8, 16), (8, 8), (8, 0)),
        _ => (mask(s.masks[0]), mask(s.masks[1]), mask(s.masks[2])),
    };
    proto::Framebuffer {
        address: s.base,
        width: u64::from(s.width),
        height: u64::from(s.height),
        pitch: u64::from(s.stride) * 4,
        bpp: 32,
        memory_model: proto::MEMORY_MODEL_RGB,
        red_mask_size: r.0,
        red_mask_shift: r.1,
        green_mask_size: g.0,
        green_mask_shift: g.1,
        blue_mask_size: b.0,
        blue_mask_shift: b.1,
        ..Default::default()
    }
}
