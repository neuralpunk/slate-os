// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Limine boot protocol: requests the kernel makes and what it gets back.
//!
//! Protocol reference: the Limine boot protocol specification (PROTOCOL.md in
//! the Limine repository). The request structures come from the `limine` crate.

use limine::BaseRevision;
use limine::request::{
    BootloaderInfoRequest, DateAtBootRequest, EfiMemmapRequest, EfiRequest, ExecutableAddressRequest,
    ExecutableCmdlineRequest, ExecutableFileRequest, FirmwareTypeRequest, FramebufferRequest, HhdmRequest,
    MemmapRequest, ModulesRequest, MpRequest, RsdpRequest,
};
use limine::{RequestsEndMarker, RequestsStartMarker};

#[used]
#[unsafe(link_section = ".limine_requests_start")]
static REQUESTS_START: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static BASE_REVISION: BaseRevision = BaseRevision::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static BOOTLOADER_INFO: BootloaderInfoRequest = BootloaderInfoRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static CMDLINE: ExecutableCmdlineRequest = ExecutableCmdlineRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static EXECUTABLE_FILE: ExecutableFileRequest = ExecutableFileRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static HHDM: HhdmRequest = HhdmRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static MEMMAP: MemmapRequest = MemmapRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static EXECUTABLE_ADDRESS: ExecutableAddressRequest = ExecutableAddressRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static RSDP: RsdpRequest = RsdpRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static DATE_AT_BOOT: DateAtBootRequest = DateAtBootRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static MP: MpRequest = MpRequest::new(limine::mp::MP_FLAG_X2APIC);

#[used]
#[unsafe(link_section = ".limine_requests")]
static MODULES: ModulesRequest = ModulesRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static FRAMEBUFFER: FramebufferRequest = FramebufferRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static FIRMWARE: FirmwareTypeRequest = FirmwareTypeRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static EFI_SYSTEM_TABLE: EfiRequest = EfiRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static EFI_MEMMAP: EfiMemmapRequest = EfiMemmapRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests_end")]
static REQUESTS_END: RequestsEndMarker = RequestsEndMarker::new();

/// Stop if the bootloader does not speak the protocol revision we were built
/// for. Nothing is printed: the console is not up yet, and a mismatched
/// bootloader may not have set things up the way the kernel expects.
pub fn check_revision() {
    if !BASE_REVISION.is_supported() {
        super::halt_forever();
    }
}

/// What the bootloader told us, in kernel terms.
#[derive(Debug, Clone, Copy)]
pub struct BootInfo {
    pub bootloader_name: &'static str,
    pub bootloader_version: &'static str,
    pub base_revision: u64,
    pub cmdline: &'static str,
    /// The file the kernel was loaded from (`/boot/slate/system-2/kernel`).
    pub kernel_path: &'static str,
    /// Virtual address where all physical memory is mapped.
    pub hhdm_offset: u64,
}

static SNAPSHOT: slate_sync::Once<BootInfo> = slate_sync::Once::new();
static MODULE_LIST: slate_sync::Once<alloc::vec::Vec<Module>> = slate_sync::Once::new();

/// A file the bootloader loaded next to the kernel. Its contents stay in
/// memory (kernel-and-modules memory is never reclaimed).
#[derive(Debug, Clone, Copy)]
pub struct Module {
    /// The module's command line from the boot configuration (its name).
    pub name: &'static str,
    pub data: &'static [u8],
}

static KERNEL_FILE: slate_sync::Once<&'static [u8]> = slate_sync::Once::new();

/// The file the kernel was loaded from, kept on the live system
/// (`slate.live` on the command line) for the installer, which copies
/// it to the disk, so the install media need not carry it twice. Its
/// pages are left out when bootloader memory is reclaimed. Available
/// after [`snapshot`].
pub fn kernel_file() -> Option<&'static [u8]> {
    KERNEL_FILE.get().copied()
}

/// Modules loaded by the bootloader. Available after [`snapshot`].
pub fn modules() -> &'static [Module] {
    MODULE_LIST.get().map_or(&[], |m| m.as_slice())
}
static RECLAIMED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn check_live() {
    assert!(!RECLAIMED.load(core::sync::atomic::Ordering::Relaxed), "bootloader data used after it was reclaimed");
}

/// Copy everything kept from the bootloader's responses into kernel memory,
/// so bootloader-reclaimable memory can be freed. Needs the heap.
pub fn snapshot() {
    let live = info();
    let efi = FIRMWARE.response().is_some_and(|r| {
        matches!(r.firmware_type, limine::firmware::FIRMWARE_TYPE_EFI32 | limine::firmware::FIRMWARE_TYPE_EFI64)
    });
    EFI.store(efi, core::sync::atomic::Ordering::Relaxed);
    if efi && let (Some(m), Some(table)) = (EFI_MEMMAP.response(), runtime_table()) {
        EFI_RUNTIME.call_once(|| EfiRuntime { memmap: m.memmap().to_vec(), desc_size: m.desc_size as usize, table });
    }
    SNAPSHOT.call_once(|| BootInfo {
        bootloader_name: alloc::string::String::from(live.bootloader_name).leak(),
        bootloader_version: alloc::string::String::from(live.bootloader_version).leak(),
        base_revision: live.base_revision,
        cmdline: alloc::string::String::from(live.cmdline).leak(),
        kernel_path: alloc::string::String::from(live.kernel_path).leak(),
        hhdm_offset: live.hhdm_offset,
    });
    if live.cmdline.split_ascii_whitespace().any(|w| w == "slate.live")
        && let Some(r) = EXECUTABLE_FILE.response()
    {
        let f = r.executable_file();
        // SAFETY: The file is in the direct map; its pages are kept out of
        // the reclaim (`mm::reclaim_bootloader_memory`), so they stay ours
        // and are never written.
        KERNEL_FILE.call_once(|| unsafe { core::slice::from_raw_parts(f.data().as_ptr(), f.data().len()) });
    }
    MODULE_LIST.call_once(|| {
        let files = MODULES.response().map_or(&[][..], |r| r.modules());
        files
            .iter()
            .map(|f| {
                // SAFETY: Module contents live in executable-and-modules
                // memory, which stays mapped and is never reclaimed.
                let data: &'static [u8] = unsafe { core::slice::from_raw_parts(f.data().as_ptr(), f.data().len()) };
                Module { name: alloc::string::String::from(f.cmdline()).leak(), data }
            })
            .collect()
    });
}

static EFI: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// What the runtime services need, kept from the boot (ADR 0088): the
/// EFI memory map, its descriptor size, and the runtime services table's
/// physical address.
pub struct EfiRuntime {
    pub memmap: alloc::vec::Vec<u8>,
    pub desc_size: usize,
    pub table: u64,
}

static EFI_RUNTIME: slate_sync::Once<EfiRuntime> = slate_sync::Once::new();

/// The EFI runtime information kept at [`snapshot`], on UEFI boots.
pub fn efi_runtime() -> Option<&'static EfiRuntime> {
    EFI_RUNTIME.get()
}

/// The system table's RuntimeServices pointer (UEFI 2.10 §4.3.1: after
/// the 24-byte header, FirmwareVendor, FirmwareRevision and three
/// handle/protocol pairs). The table address is virtual for Limine's
/// base revisions past 4, and the system table carries the "IBI SYST"
/// signature.
fn runtime_table() -> Option<u64> {
    let st = EFI_SYSTEM_TABLE.response()?.address as *const u64;
    if st.is_null() {
        return None;
    }
    // The table is firmware memory the direct map may leave out.
    super::paging::ensure_direct_mapped((st as u64).wrapping_sub(info().hhdm_offset), 96);
    // SAFETY: Limine gives the system table's address in the higher-half
    // direct map, mapped just above; bootloader memory is still valid
    // during `snapshot`, and these are two 8-byte reads inside the table's
    // first 96 bytes.
    let (sig, rt) = unsafe { (core::ptr::read_volatile(st), core::ptr::read_volatile(st.add(11))) };
    (sig == 0x5453_5953_2049_4249 && rt != 0).then_some(rt)
}

/// The machine booted through UEFI firmware (known after [`snapshot`]).
pub fn efi_booted() -> bool {
    EFI.load(core::sync::atomic::Ordering::Relaxed)
}

/// From now on, bootloader responses must not be touched.
pub fn mark_reclaimed() {
    assert!(SNAPSHOT.get().is_some(), "reclaiming bootloader memory without a snapshot");
    RECLAIMED.store(true, core::sync::atomic::Ordering::Relaxed);
}

/// The CPUs the bootloader found: the bootstrap CPU's APIC ID and all CPUs.
pub fn mp_cpus() -> Option<(u32, &'static [&'static limine::mp::MpInfo])> {
    check_live();
    MP.response().map(|r| (r.bsp_lapic_id, r.cpus()))
}

pub fn info() -> BootInfo {
    if let Some(s) = SNAPSHOT.get() {
        return *s;
    }
    let (bootloader_name, bootloader_version) =
        BOOTLOADER_INFO.response().map_or(("unknown", "?"), |r| (r.name(), r.version()));
    BootInfo {
        bootloader_name,
        bootloader_version,
        base_revision: BASE_REVISION.actual_revision().unwrap_or(BaseRevision::MAX_SUPPORTED),
        cmdline: CMDLINE.response().map_or("", |r| r.cmdline()),
        kernel_path: EXECUTABLE_FILE.response().map_or("", |r| r.executable_file().path()),
        hhdm_offset: HHDM.response().map_or(0, |r| r.offset),
    }
}

/// Kinds of physical memory, in kernel terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionKind {
    Usable,
    /// Holds bootloader data (page tables, responses, its stack) until the
    /// kernel no longer needs it; usable afterwards.
    BootloaderReclaimable,
    /// The kernel image and boot modules.
    KernelAndModules,
    AcpiReclaimable,
    AcpiNvs,
    Framebuffer,
    Reserved,
    Bad,
}

/// A physical memory range.
#[derive(Clone, Copy, Debug)]
pub struct Region {
    pub base: u64,
    pub len: u64,
    pub kind: RegionKind,
}

/// The physical memory map.
pub fn memory_map() -> impl Iterator<Item = Region> + Clone {
    use limine::memmap::*;
    check_live();
    let entries = MEMMAP.response().map_or(&[][..], |r| r.entries());
    entries.iter().map(|e| Region {
        base: e.base,
        len: e.length,
        kind: match e.type_ {
            MEMMAP_USABLE => RegionKind::Usable,
            MEMMAP_BOOTLOADER_RECLAIMABLE => RegionKind::BootloaderReclaimable,
            MEMMAP_EXECUTABLE_AND_MODULES => RegionKind::KernelAndModules,
            MEMMAP_ACPI_RECLAIMABLE => RegionKind::AcpiReclaimable,
            MEMMAP_ACPI_NVS => RegionKind::AcpiNvs,
            MEMMAP_FRAMEBUFFER => RegionKind::Framebuffer,
            MEMMAP_BAD_MEMORY => RegionKind::Bad,
            _ => RegionKind::Reserved,
        },
    })
}

/// Physical and virtual base of the loaded kernel image.
pub fn kernel_address() -> (u64, u64) {
    check_live();
    let r = EXECUTABLE_ADDRESS.response().expect("bootloader did not report the kernel address");
    (r.physical_base, r.virtual_base)
}

/// Virtual address of the ACPI RSDP (base revision 6 reports a direct-map
/// address), if the firmware has ACPI.
pub fn rsdp() -> Option<u64> {
    check_live();
    RSDP.response().map(|r| r.address as u64).filter(|&a| a != 0)
}

/// Wall-clock time at boot, in seconds since the UNIX epoch.
pub fn boot_time_unix() -> Option<i64> {
    check_live();
    DATE_AT_BOOT.response().map(|r| r.timestamp)
}

/// A linear framebuffer set up by the bootloader.
#[derive(Debug, Clone, Copy)]
pub struct Framebuffer {
    /// Direct-map address of the first pixel.
    pub addr: u64,
    pub width: usize,
    pub height: usize,
    /// Bytes per scanline.
    pub pitch: usize,
    pub bpp: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

/// The first framebuffer, if the bootloader set one up. Valid until
/// bootloader memory is reclaimed (the pixels themselves stay mapped).
pub fn framebuffer() -> Option<Framebuffer> {
    check_live();
    let r = FRAMEBUFFER.response()?;
    let f = r.framebuffers().first()?;
    Some(Framebuffer {
        addr: f.address() as u64,
        width: f.width as usize,
        height: f.height as usize,
        pitch: f.pitch as usize,
        bpp: f.bpp,
        red_shift: f.red_mask_shift,
        green_shift: f.green_mask_shift,
        blue_shift: f.blue_mask_shift,
    })
}
