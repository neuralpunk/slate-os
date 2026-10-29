// SPDX-License-Identifier: MIT OR Apache-2.0

//! Booting an entry, the part the UEFI and BIOS loaders share (ADR 0089).
//! The front loads the files and says what the machine has; [`prepare`]
//! lays out the kernel, builds the page tables, starts the other CPUs'
//! trampoline and answers the kernel's requests; once the firmware is
//! done with (ExitBootServices on UEFI), [`Prepared::finish`] writes the
//! final memory map, starts the other CPUs and jumps.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::config::{Entry, Module};
use crate::handoff::{Arena, Jump, Requests};
use crate::memmap;
use crate::mp;
use crate::paging::{self, Flags, Frames, PAGE, Tables};
use crate::proto::{self, HHDM, MemmapEntry, id};
use crate::{cpu, kernel};

/// What memory is for, which decides its type in the kernel's map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The loader's data the kernel gets: bootloader-reclaimable.
    Loader,
    /// The kernel's image and the modules.
    Kernel,
}

/// Where the loader gets memory: whole zeroed pages, reachable one to
/// one, out of what the map called usable when the direct map was built.
pub trait Memory {
    fn pages(&mut self, kind: Kind, bytes: u64, below: Option<u64>) -> Result<u64, String>;
}

/// A file in memory: its physical address and length.
#[derive(Clone, Copy, Debug)]
pub struct File {
    pub phys: u64,
    pub len: u64,
}

impl File {
    pub fn bytes(&self) -> &'static [u8] {
        // SAFETY: Files are loaded into memory the loader owns and never
        // frees, reachable one to one.
        unsafe { core::slice::from_raw_parts(self.phys as *const u8, self.len as usize) }
    }
}

/// What the front found out about the machine.
#[derive(Clone, Debug)]
pub struct Machine {
    pub firmware: u64,
    /// The RSDP's physical address.
    pub rsdp: Option<u64>,
    /// The EFI system table's physical address.
    pub efi_system_table: Option<u64>,
    pub date: Option<i64>,
    /// The framebuffer response, its address physical.
    pub framebuffer: Option<proto::Framebuffer>,
    pub tsc_per_us: u64,
    /// The memory map as it is now (for the direct map).
    pub map: Vec<MemmapEntry>,
    /// How many entries the final map may have.
    pub map_capacity: usize,
}

const STACK: u64 = 64 << 10;
const AP_STACK: u64 = 16 << 10;

struct LoaderFrames<'a> {
    mem: &'a mut dyn Memory,
    below: Option<u64>,
}

impl Frames for LoaderFrames<'_> {
    fn alloc(&mut self) -> Option<u64> {
        self.mem.pages(Kind::Loader, PAGE, self.below).ok()
    }
    fn table(&mut self, phys: u64) -> &mut [u64; 512] {
        // SAFETY: Frames are loader pages, reachable one to one.
        unsafe { &mut *(phys as *mut [u64; 512]) }
    }
}

/// Everything ready for the jump but what only the end of the firmware's
/// services gives.
#[derive(Debug)]
pub struct Prepared {
    requests: Requests,
    arena: Arena,
    tables: Tables,
    identity: Tables,
    trampoline: mp::Trampoline,
    cpus: Vec<mp::Cpu>,
    infos: Vec<u64>,
    stacks: u64,
    x2apic: bool,
    bsp: u32,
    tsc_per_us: u64,
    stack_top: u64,
    entry_point: u64,
    entries_at: u64,
    pointers_at: u64,
    capacity: usize,
    jump_at: u64,
}

/// The kernel's image from its file, in memory of its own.
pub fn load_kernel(mem: &mut dyn Memory, entry: &Entry, file: &File) -> Result<(kernel::Plan, u64), String> {
    // A position-independent kernel goes at a random place (KASLR, ADR
    // 0095) unless the entry says otherwise.
    let random = entry.randomized().then(cpu::random_u64);
    let plan = kernel::plan(file.bytes(), random).map_err(|e| format!("{}: {e}", entry.kernel))?;
    let image = mem.pages(Kind::Kernel, plan.size, None)?;
    // SAFETY: The pages just given, `plan.size` bytes.
    let bytes = unsafe { core::slice::from_raw_parts_mut(image as *mut u8, plan.size as usize) };
    kernel::load(file.bytes(), &plan, bytes).map_err(|e| format!("{}: {e}", entry.kernel))?;
    Ok((plan, image))
}

/// Get everything ready for `entry`: the kernel loaded at `image` as
/// `plan` says, its file and the modules' in memory.
pub fn prepare(
    mem: &mut dyn Memory,
    entry: &Entry,
    kernel_file: &File,
    plan: &kernel::Plan,
    image: u64,
    modules: &[(File, &Module)],
    m: &Machine,
) -> Result<Prepared, String> {
    if cpu::cr4() & cpu::CR4_LA57 != 0 {
        return Err("the firmware runs with 5-level paging, which the loader does not build".into());
    }
    // SAFETY: The image the front loaded.
    let requests = unsafe { Requests::find(image, plan.size) };
    requests
        .base_revision()
        .map_err(|r| format!("the kernel wants base revision {r}; the loader speaks {}", proto::REVISION))?;
    let cpus_listed = m.rsdp.and_then(|r| acpi_table(r, b"APIC")).map(mp::cpus).unwrap_or_default();

    // The tables: the direct map over the memory there is (everything
    // allocated from here on comes out of usable memory, which it covers),
    // and the kernel's image.
    let pt = |e: paging::Error| format!("page tables: {e:?}");
    let mut f = LoaderFrames { mem, below: None };
    let mut tables = Tables::new(&mut f, cpu::gigabyte_pages()).map_err(pt)?;
    for e in &m.map {
        if memmap::in_direct_map(e.kind) {
            tables.map(&mut f, HHDM + e.base, e.base, e.length, Flags::RWX).map_err(pt)?;
        }
    }
    for s in &plan.segments {
        tables.map(&mut f, s.virt, image + s.offset, s.len, s.flags).map_err(pt)?;
    }
    // The trampoline loads the one-to-one tables in 32-bit code.
    f.below = Some(0xffff_f000);
    let identity = tables.with_identity(&mut f).map_err(pt)?;
    let mem = f.mem;

    // The other CPUs' way in, and what the kernel finds them by.
    let x2apic = requests.data(id::MP).is_some_and(|flags| flags & proto::MP_X2APIC != 0) && cpu::has_x2apic();
    let page = mem.pages(Kind::Loader, PAGE, Some(0x9_ffff))?;
    // SAFETY: A page below 1 MiB just given; the identity tables' root is
    // below 4 GiB.
    let trampoline = unsafe { mp::Trampoline::install(page, identity.root, tables.root, x2apic) };
    let bsp = cpu::apic_id();
    let mut cpus = cpus_listed;
    if !cpus.iter().any(|c| c.apic_id == bsp) {
        cpus.insert(0, mp::Cpu { uid: 0, apic_id: bsp });
    }
    let stacks = mem.pages(Kind::Loader, AP_STACK * cpus.len() as u64, None)?;

    // Responses.
    let capacity = m.map_capacity;
    let arena_len = (256 << 10) + cpus.len() as u64 * 64 + capacity as u64 * 32;
    // SAFETY: Loader pages, reachable one to one and in the direct map.
    let mut a = unsafe { Arena::new(mem.pages(Kind::Loader, arena_len, None)?, arena_len) };
    let oom = || String::from("out of room for the responses");
    let name = a.str(crate::NAME).ok_or_else(oom)?;
    let version = a.str(crate::VERSION).ok_or_else(oom)?;
    requests.answer(id::BOOTLOADER_INFO, a.array(&[0u64, name, version]).ok_or_else(oom)?);
    let cmdline = a.str(&entry.cmdline).ok_or_else(oom)?;
    requests.answer(id::EXECUTABLE_CMDLINE, a.array(&[0u64, cmdline]).ok_or_else(oom)?);
    requests.answer(id::FIRMWARE_TYPE, a.array(&[0u64, m.firmware]).ok_or_else(oom)?);
    requests.answer(id::HHDM, a.array(&[0u64, HHDM]).ok_or_else(oom)?);
    requests.answer(id::EXECUTABLE_ADDRESS, a.array(&[0u64, image, plan.virt_base]).ok_or_else(oom)?);
    let file_of = |a: &mut Arena, l: &File, path: &str, cmdline: &str| -> Option<u64> {
        // The path on its partition, as Limine gives it.
        let (path, cmdline) = (a.str(&format!("/{path}"))?, a.str(cmdline)?);
        a.put(proto::File { address: HHDM + l.phys, size: l.len, path, cmdline, ..Default::default() })
    };
    let kfile = file_of(&mut a, kernel_file, &entry.kernel, &entry.cmdline).ok_or_else(oom)?;
    requests.answer(id::EXECUTABLE_FILE, a.array(&[0u64, kfile]).ok_or_else(oom)?);
    let mods: Vec<u64> = modules
        .iter()
        .map(|(l, md)| file_of(&mut a, l, &md.path, &md.cmdline))
        .collect::<Option<_>>()
        .ok_or_else(oom)?;
    let mod_list = if mods.is_empty() { 0 } else { a.array(&mods).ok_or_else(oom)? };
    requests.answer(id::MODULES, a.array(&[0u64, mods.len() as u64, mod_list]).ok_or_else(oom)?);
    if let Some(r) = m.rsdp {
        requests.answer(id::RSDP, a.array(&[0u64, HHDM + r]).ok_or_else(oom)?);
    }
    if let Some(st) = m.efi_system_table {
        requests.answer(id::EFI, a.array(&[0u64, HHDM + st]).ok_or_else(oom)?);
    }
    if let Some(d) = m.date {
        requests.answer(id::DATE_AT_BOOT, a.array(&[0u64, d as u64]).ok_or_else(oom)?);
    }
    if let Some(fb) = m.framebuffer {
        let fbp = a.put(proto::Framebuffer { address: HHDM + fb.address, ..fb }).ok_or_else(oom)?;
        let list = a.array(&[fbp]).ok_or_else(oom)?;
        requests.answer(id::FRAMEBUFFER, a.array(&[0u64, 1, list]).ok_or_else(oom)?);
    }
    let stack_size = requests.data(id::STACK_SIZE).map_or(STACK, |s| s.max(STACK)).next_multiple_of(PAGE);
    let stack = mem.pages(Kind::Loader, stack_size, None)?;
    let entry_point = requests.data(id::ENTRY_POINT).filter(|&e| e != 0).unwrap_or(plan.entry);
    // MP: the CPUs' info structures now, the response once they run.
    let infos: Vec<u64> = cpus.iter().map(|c| a.put(mp::info(c))).collect::<Option<_>>().ok_or_else(oom)?;
    let entries_at = a.take((capacity * 24) as u64, 8).ok_or_else(oom)?;
    let pointers_at = a.take((capacity * 8) as u64, 8).ok_or_else(oom)?;
    let jump_at = a.take(core::mem::size_of::<Jump>() as u64, 16).ok_or_else(oom)?;
    Ok(Prepared {
        requests,
        arena: a,
        tables,
        identity,
        trampoline,
        cpus,
        infos,
        stacks,
        x2apic,
        bsp,
        tsc_per_us: m.tsc_per_us,
        stack_top: HHDM + stack + stack_size,
        entry_point,
        entries_at,
        pointers_at,
        capacity,
        jump_at,
    })
}

impl Prepared {
    /// The EFI memory map response: the firmware's last map, in loader
    /// memory (`phys`, `size` bytes of `desc`-byte descriptors).
    pub fn answer_efi_memmap(&mut self, phys: u64, size: usize, desc: usize, version: u32) {
        let r = self.arena.array(&[0u64, HHDM + phys, size as u64, desc as u64, u64::from(version)]).unwrap_or(0);
        self.requests.answer(id::EFI_MEMMAP, r);
    }

    /// Write the final memory map, start the other CPUs and enter the
    /// kernel. Allocates nothing from the front's memory.
    ///
    /// # Safety
    /// The firmware must be done with (no more boot services); the loader
    /// runs one to one, its code and data in the direct map.
    pub unsafe fn finish(mut self, final_map: &[MemmapEntry]) -> ! {
        let n = final_map.len().min(self.capacity);
        for (i, e) in final_map.iter().take(n).enumerate() {
            let at = self.entries_at + (i * 24) as u64;
            // SAFETY: The room taken in the arena for `capacity` entries.
            unsafe {
                core::ptr::write(at as *mut MemmapEntry, *e);
                core::ptr::write((self.pointers_at + (i * 8) as u64) as *mut u64, HHDM + at);
            }
        }
        let r = self.arena.array(&[0u64, n as u64, HHDM + self.pointers_at]).unwrap_or(0);
        self.requests.answer(id::MEMMAP, r);
        if self.requests.wants(id::MP) {
            if self.x2apic {
                // SAFETY: CPUID said x2APIC is there.
                unsafe { mp::enable_x2apic() };
            }
            let starts: Vec<(u32, u64, u64)> = self
                .cpus
                .iter()
                .zip(&self.infos)
                .enumerate()
                .map(|(i, (c, &info))| (c.apic_id, info, HHDM + self.stacks + AP_STACK * (i as u64 + 1)))
                .collect();
            // SAFETY: The caller says the firmware is done with; the APIC
            // is in x2APIC mode, or its registers are mapped one to one by
            // the tables loaded now.
            let started = unsafe { self.trampoline.start(&starts, self.bsp, self.x2apic, self.tsc_per_us) };
            let running: Vec<u64> = self.infos.iter().zip(&started).filter(|(_, s)| **s).map(|(i, _)| *i).collect();
            let list = self.arena.array(&running).unwrap_or(0);
            let flags = if self.x2apic { proto::MP_X2APIC } else { 0 };
            let word = flags | u64::from(self.bsp) << 32;
            let r = self.arena.array(&[0u64, word, running.len() as u64, list]).unwrap_or(0);
            self.requests.answer(id::MP, r);
        }
        let j = Jump {
            identity_cr3: self.identity.root,
            kernel_cr3: self.tables.root,
            hhdm: HHDM,
            entry: self.entry_point,
            stack: self.stack_top,
            gdtr: self.trampoline.gdtr64(),
        };
        // SAFETY: Room taken in the arena for it; the caller's conditions
        // are the jump's.
        unsafe {
            core::ptr::write(self.jump_at as *mut Jump, j);
            crate::handoff::jump(&*(self.jump_at as *const Jump))
        }
    }
}

/// An ACPI table by signature, through the RSDP (ACPI 6.5 §5.2.5, §5.2.7).
pub fn acpi_table(rsdp: u64, sig: &[u8; 4]) -> Option<&'static [u8]> {
    // SAFETY: ACPI tables are firmware memory, reachable one to one while
    // the loader runs; each is read within the length its header gives.
    let bytes = |at: u64, len: usize| unsafe { core::slice::from_raw_parts(at as *const u8, len) };
    let r = slate_acpi::parse_rsdp(bytes(rsdp, slate_acpi::RSDP_MAX_LEN)).ok()?;
    let (root, xsdt) = match r.xsdt {
        Some(x) => (x, true),
        None => (u64::from(r.rsdt), false),
    };
    let table = |at: u64| {
        let h = slate_acpi::parse_header(bytes(at, slate_acpi::HEADER_LEN)).ok()?;
        slate_acpi::validate(bytes(at, h.length as usize), None).ok()
    };
    let root = table(root)?;
    slate_acpi::root_entries(root, xsdt).filter_map(table).find(|t| t.get(..4) == Some(&sig[..]))
}
