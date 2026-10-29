// SPDX-License-Identifier: MIT OR Apache-2.0

//! 4-level paging (Intel SDM vol. 3A §4.5, tables 4-14 to 4-20).

use alloc::vec::Vec;
use core::arch::asm;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::boot::{Region, RegionKind};
use super::cpu;
use crate::mm::{PAGE_SIZE, PhysAddr, frame, hhdm_offset};
use crate::sync::{IrqSpinLock, IrqSpinLockGuard};

// Page-table entry bits (SDM vol. 3A tables 4-14..4-20).
const P: u64 = 1 << 0;
const RW: u64 = 1 << 1;
const US: u64 = 1 << 2;
const PWT: u64 = 1 << 3;
const PCD: u64 = 1 << 4;
const PS: u64 = 1 << 7;
const PAT_4K: u64 = 1 << 7;
const PAT_LARGE: u64 = 1 << 12;
const G: u64 = 1 << 8;
const NX: u64 = 1 << 63;
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

const CR0_WP: u64 = 1 << 16;
const CR4_PGE: u64 = 1 << 7;
const CR4_SMEP: u64 = 1 << 20;
const CR4_SMAP: u64 = 1 << 21;
const MSR_EFER: u32 = 0xC000_0080;
const MSR_PAT: u32 = 0x277;
const EFER_NXE: u64 = 1 << 11;

/// Supported page sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageSize {
    Size4K,
    Size2M,
    Size1G,
}

impl PageSize {
    pub const fn bytes(self) -> u64 {
        match self {
            PageSize::Size4K => 4096,
            PageSize::Size2M => 2 << 20,
            PageSize::Size1G => 1 << 30,
        }
    }

    /// Page-table level holding the leaf entry: 1 = PT, 2 = PD, 3 = PDPT.
    const fn level(self) -> usize {
        match self {
            PageSize::Size4K => 1,
            PageSize::Size2M => 2,
            PageSize::Size1G => 3,
        }
    }
}

/// Memory type of a mapping, through Slate's PAT ([`init_pat`]): PCD|PWT
/// selects UC, the PAT bit alone WC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheMode {
    WriteBack,
    Uncached,
    /// Write-combining: stores are gathered into bursts, nothing is
    /// cached (framebuffers).
    WriteCombining,
}

/// Slate's PAT, by entry (SDM vol. 3A §12.12.2, table 12-10 encodings):
/// the power-on layout (WB, WT, UC-, UC, WB, WT, UC-, UC) with entry 4 (the
/// PAT bit alone) write-combining instead.
const PAT_LAYOUT: u64 = 0x0007_0401_0007_0406;

/// This CPU has Slate's PAT, and write-combining mappings select its WC
/// entry (for the kernel tests).
pub fn pat_self_check() -> Result<(), &'static str> {
    // SAFETY: IA32_PAT exists on every x86-64 CPU.
    if unsafe { cpu::rdmsr(MSR_PAT) } != PAT_LAYOUT {
        return Err("this CPU's PAT is not Slate's");
    }
    let wc = MapFlags { cache: CacheMode::WriteCombining, ..MapFlags::KERNEL_MMIO };
    let (small, large) = (wc.leaf_bits(PageSize::Size4K), wc.leaf_bits(PageSize::Size2M));
    // Entry 4: PAT set, PCD and PWT clear; byte 4 of the layout is WC (1).
    if small & (PAT_4K | PCD | PWT) != PAT_4K || large & (PAT_LARGE | PCD | PWT) != PAT_LARGE {
        return Err("write-combining mappings do not select PAT entry 4");
    }
    if PAT_LAYOUT >> 32 & 0xFF != 1 {
        return Err("PAT entry 4 is not write-combining");
    }
    Ok(())
}

/// Load Slate's PAT on this CPU (every CPU, early). Entry 4 is the only
/// one that changes, and nothing maps through it before this, so no
/// cached translation or line has the old type (SDM vol. 3A §12.12.4).
pub fn init_pat() {
    // SAFETY: IA32_PAT exists on every x86-64 CPU; see above.
    unsafe { cpu::wrmsr(MSR_PAT, PAT_LAYOUT) };
}

/// Architecture-neutral mapping permissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapFlags {
    pub write: bool,
    pub exec: bool,
    pub user: bool,
    pub global: bool,
    pub cache: CacheMode,
}

impl MapFlags {
    /// Kernel read/write data, never executable.
    pub const KERNEL_DATA: MapFlags =
        MapFlags { write: true, exec: false, user: false, global: true, cache: CacheMode::WriteBack };
    pub const KERNEL_RODATA: MapFlags = MapFlags { write: false, ..MapFlags::KERNEL_DATA };
    pub const KERNEL_CODE: MapFlags = MapFlags { write: false, exec: true, ..MapFlags::KERNEL_DATA };
    pub const KERNEL_MMIO: MapFlags = MapFlags { cache: CacheMode::Uncached, ..MapFlags::KERNEL_DATA };

    fn leaf_bits(self, size: PageSize) -> u64 {
        let mut e = P;
        if self.write {
            e |= RW;
        }
        if self.user {
            e |= US;
        }
        if self.global {
            e |= G;
        }
        if !self.exec && nx_enabled() {
            e |= NX;
        }
        match self.cache {
            CacheMode::WriteBack => {}
            CacheMode::Uncached => e |= PCD | PWT,
            // The PAT bit: bit 7 in a 4 KiB entry, bit 12 in a large one.
            CacheMode::WriteCombining if size == PageSize::Size4K => e |= PAT_4K,
            CacheMode::WriteCombining => e |= PAT_LARGE,
        }
        if size != PageSize::Size4K {
            e |= PS;
        }
        e
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    AlreadyMapped,
    OutOfMemory,
    Misaligned,
    /// A larger page already covers the address.
    HugePageInTheWay,
}

/// A hierarchy of page tables rooted at a PML4.
#[derive(Debug)]
pub struct Mapper {
    root: PhysAddr,
    /// 4 KiB pages mapped in the lower half (a process's resident set),
    /// and the most there have been at once.
    resident: u64,
    peak: u64,
}

/// Where the lower (user) half ends.
const USER_END: u64 = 1 << 47;

fn table(p: PhysAddr) -> *mut [u64; 512] {
    p.to_virt().cast()
}

fn index(virt: u64, level: usize) -> usize {
    ((virt >> (12 + 9 * (level - 1))) & 0x1FF) as usize
}

/// Drop this CPU's translation of the page at `virt`.
pub fn invalidate_page(virt: u64) {
    invlpg(virt);
}

fn invlpg(virt: u64) {
    // SAFETY: Invalidating a TLB entry has no memory-safety effect.
    unsafe { asm!("invlpg [{}]", in(reg) virt, options(nostack, preserves_flags)) };
}

impl Mapper {
    /// A mapper over an existing PML4.
    ///
    /// # Safety
    ///
    /// `root` must be a page-table root whose tables all live in frames
    /// owned by this hierarchy, and nothing else may modify it concurrently.
    pub unsafe fn from_root(root: PhysAddr) -> Mapper {
        Mapper { root, resident: 0, peak: 0 }
    }

    /// Walk to the table at `level` covering `virt`, creating intermediate
    /// tables as needed.
    fn walk(&mut self, virt: u64, level: usize, user: bool) -> Result<*mut [u64; 512], MapError> {
        let mut t = table(self.root);
        for l in (level + 1..=4).rev() {
            // SAFETY: `t` is a page table of this hierarchy, mapped in the
            // direct map, and `&mut self` gives exclusive access.
            let e = unsafe { &mut (*t)[index(virt, l)] };
            if *e & P == 0 {
                let f = frame::alloc_zeroed().ok_or(MapError::OutOfMemory)?;
                *e = f.0 | P | RW | if user { US } else { 0 };
            } else if *e & PS != 0 {
                return Err(MapError::HugePageInTheWay);
            } else if user {
                *e |= US;
            }
            t = table(PhysAddr(*e & ADDR_MASK));
        }
        Ok(t)
    }

    /// Map one page.
    pub fn map(&mut self, virt: u64, phys: PhysAddr, size: PageSize, flags: MapFlags) -> Result<(), MapError> {
        if virt % size.bytes() != 0 || phys.0 % size.bytes() != 0 {
            return Err(MapError::Misaligned);
        }
        let t = self.walk(virt, size.level(), flags.user)?;
        // SAFETY: `t` is a table of this hierarchy (see `walk`).
        let e = unsafe { &mut (*t)[index(virt, size.level())] };
        if *e & P != 0 {
            return Err(MapError::AlreadyMapped);
        }
        *e = phys.0 | flags.leaf_bits(size);
        if size == PageSize::Size4K && virt < USER_END {
            self.resident += 1;
            self.peak = self.peak.max(self.resident);
        }
        Ok(())
    }

    /// Map `len` bytes, using the largest pages alignment allows.
    pub fn map_range(&mut self, virt: u64, phys: PhysAddr, len: u64, flags: MapFlags) -> Result<(), MapError> {
        let mut off = 0;
        while off < len {
            let (v, p, left) = (virt + off, phys.0 + off, len - off);
            let size = [PageSize::Size1G, PageSize::Size2M, PageSize::Size4K]
                .into_iter()
                .find(|s| {
                    (*s != PageSize::Size1G || huge_1g_supported())
                        && v % s.bytes() == 0
                        && p % s.bytes() == 0
                        && left >= s.bytes()
                })
                .ok_or(MapError::Misaligned)?;
            self.map(v, PhysAddr(p), size, flags)?;
            off += size.bytes();
        }
        Ok(())
    }

    /// A new address space: empty lower half, kernel upper half shared with
    /// every other address space.
    pub fn new_user() -> Option<Mapper> {
        let root = frame::alloc_zeroed()?;
        let kernel = table(kernel_root());
        // SAFETY: Both are PML4s in the direct map; the kernel's upper-half
        // entries never change after boot (all PDPTs exist up front).
        unsafe { (&mut *table(root))[256..].copy_from_slice(&(&*kernel)[256..]) };
        Some(Mapper { root, resident: 0, peak: 0 })
    }

    pub fn root(&self) -> PhysAddr {
        self.root
    }

    /// Change the permissions of the 4 KiB page mapping `virt`.
    pub fn protect(&mut self, virt: u64, flags: MapFlags) -> bool {
        let Some((t, 1)) = self.leaf(virt) else { return false };
        // SAFETY: `leaf` returned a page table of this hierarchy.
        let e = unsafe { &mut (*t)[index(virt, 1)] };
        *e = (*e & ADDR_MASK) | flags.leaf_bits(PageSize::Size4K);
        invlpg(virt);
        true
    }

    /// The mapping flags of the 4 KiB page at `virt` (to move it elsewhere).
    pub fn leaf_flags(&self, virt: u64) -> Option<MapFlags> {
        let (t, 1) = self.leaf(virt)? else { return None };
        // SAFETY: `leaf` returned a page table of this hierarchy.
        let e = unsafe { (*t)[index(virt, 1)] };
        Some(MapFlags {
            write: e & RW != 0,
            exec: e & NX == 0,
            user: e & US != 0,
            global: e & G != 0,
            cache: if e & PCD != 0 {
                CacheMode::Uncached
            } else if e & PAT_4K != 0 {
                CacheMode::WriteCombining
            } else {
                CacheMode::WriteBack
            },
        })
    }

    /// The memory type the mapping of `virt` gets from the PAT: its entry's
    /// PAT, PCD and PWT bits pick one of the IA32_PAT MSR's eight types
    /// (SDM vol. 3A §12.12.3, table 12-11; the PAT bit is bit 7 in a 4 KiB
    /// entry, bit 12 in a large page's).
    pub fn memory_type(&self, virt: u64) -> Option<&'static str> {
        let (t, level) = self.leaf(virt)?;
        // SAFETY: `leaf` returned a page table of this hierarchy.
        let e = unsafe { (*t)[index(virt, level)] };
        let pat = if level == 1 { e >> 7 & 1 } else { e >> 12 & 1 };
        let i = (pat << 2) | (e >> 4 & 1) << 1 | (e >> 3 & 1);
        // SAFETY: IA32_PAT (0x277) exists on every x86-64 CPU.
        let msr = unsafe { cpu::rdmsr(MSR_PAT) };
        // SDM vol. 3A table 12-10: the PAT's memory type encodings.
        Some(match msr >> (i * 8) & 7 {
            0 => "UC",
            1 => "WC",
            4 => "WT",
            5 => "WP",
            6 => "WB",
            7 => "UC-",
            _ => "reserved",
        })
    }

    /// The physical page and writability of the 4 KiB mapping at `virt`.
    pub fn lookup(&self, virt: u64) -> Option<(PhysAddr, bool)> {
        let (t, level) = self.leaf(virt)?;
        if level != 1 {
            return None;
        }
        // SAFETY: `leaf` returned a page table of this hierarchy.
        let e = unsafe { (*t)[index(virt, 1)] };
        Some((PhysAddr(e & ADDR_MASK), e & RW != 0))
    }

    /// Every present 4 KiB user page in `[start, end)`: (virtual address,
    /// frame, writable).
    pub fn user_pages(&self, start: u64, end: u64) -> Vec<(u64, PhysAddr, bool)> {
        let mut out = Vec::new();
        self.each_user_page(start, end, &mut |va, f, w| out.push((va, f, w)));
        out
    }

    /// How many 4 KiB user pages are present in `[start, end)`, without
    /// allocating (the out-of-memory killer counts with it).
    pub fn count_user_pages(&self, start: u64, end: u64) -> u64 {
        let mut n = 0;
        self.each_user_page(start, end, &mut |_, _, _| n += 1);
        n
    }

    fn each_user_page(&self, start: u64, end: u64, f: &mut dyn FnMut(u64, PhysAddr, bool)) {
        fn walk(t: PhysAddr, level: usize, base: u64, range: (u64, u64), out: &mut dyn FnMut(u64, PhysAddr, bool)) {
            let span = 1u64 << (12 + 9 * (level - 1));
            for i in 0..512 {
                let va = base | ((i as u64) << (12 + 9 * (level - 1)));
                if va + span <= range.0 || va >= range.1 {
                    continue;
                }
                // SAFETY: `t` is a page table of this hierarchy.
                let e = unsafe { (*table(t))[i] };
                if e & P == 0 {
                    continue;
                }
                if level == 1 {
                    out(va, PhysAddr(e & ADDR_MASK), e & RW != 0);
                } else {
                    walk(PhysAddr(e & ADDR_MASK), level - 1, va, range, out);
                }
            }
        }
        walk(self.root, 4, 0, (start, end.min(1 << 47)), f);
    }

    /// Clear the whole root table, kernel half included, before it is
    /// freed (debug builds): a CPU wrongly still running on it then faults
    /// at once instead of walking memory that is being reused.
    pub fn poison_root(&mut self) {
        // SAFETY: The root is this hierarchy's PML4, in the direct map, and
        // no CPU has it loaded (the caller waited).
        unsafe { (*table(self.root)).fill(0) };
    }

    /// Tear down the lower (user) half: call `leaf` for every mapped 4 KiB
    /// page, then free the page tables themselves.
    pub fn free_user_half(&mut self, mut leaf: impl FnMut(u64, PhysAddr)) {
        fn walk(t: PhysAddr, level: usize, base: u64, leaf: &mut dyn FnMut(u64, PhysAddr)) {
            for i in 0..512 {
                // SAFETY: `t` is a page table of this hierarchy.
                let e = unsafe { (*table(t))[i] };
                if e & P == 0 {
                    continue;
                }
                let va = base | ((i as u64) << (12 + 9 * (level - 1)));
                let next = PhysAddr(e & ADDR_MASK);
                if level == 1 {
                    leaf(va, next);
                } else {
                    debug_assert!(e & PS == 0, "huge pages in user space are not supported yet");
                    walk(next, level - 1, va, leaf);
                    frame::free(next, 0);
                }
            }
        }
        for i in 0..256 {
            // SAFETY: `root` is our PML4.
            let e = unsafe { (*table(self.root))[i] };
            if e & P != 0 {
                walk(PhysAddr(e & ADDR_MASK), 3, (i as u64) << 39, &mut leaf);
                frame::free(PhysAddr(e & ADDR_MASK), 0);
                // SAFETY: As above.
                unsafe { (*table(self.root))[i] = 0 };
            }
        }
        self.resident = 0;
    }

    /// Remove the mapping of the page containing `virt`, returning what it
    /// mapped. The caller handles TLB invalidation on other CPUs.
    pub fn unmap(&mut self, virt: u64) -> Option<(PhysAddr, PageSize)> {
        let (t, level) = self.leaf(virt)?;
        // SAFETY: `leaf` returned a table of this hierarchy.
        let e = unsafe { &mut (*t)[index(virt, level)] };
        let size = [PageSize::Size4K, PageSize::Size2M, PageSize::Size1G][level - 1];
        let phys = PhysAddr(*e & ADDR_MASK & !(size.bytes() - 1));
        *e = 0;
        invlpg(virt);
        if size == PageSize::Size4K && virt < USER_END {
            self.resident -= 1;
        }
        Some((phys, size))
    }

    /// 4 KiB pages mapped in the lower half now ([`Mapper::count_user_pages`]
    /// over all of it, kept as pages come and go).
    pub fn resident(&self) -> u64 {
        self.resident
    }

    /// The most lower-half pages mapped at once (getrusage(2)'s maxrss).
    pub fn peak(&self) -> u64 {
        self.peak
    }

    /// The physical address `virt` maps to, if any.
    pub fn translate(&self, virt: u64) -> Option<PhysAddr> {
        let (t, level) = self.leaf(virt)?;
        // SAFETY: `leaf` returned a table of this hierarchy.
        let e = unsafe { (*t)[index(virt, level)] };
        let size = [PageSize::Size4K, PageSize::Size2M, PageSize::Size1G][level - 1].bytes();
        Some(PhysAddr((e & ADDR_MASK & !(size - 1)) + virt % size))
    }

    /// The table and level holding the present leaf entry for `virt`.
    fn leaf(&self, virt: u64) -> Option<(*mut [u64; 512], usize)> {
        let mut t = table(self.root);
        for level in (1..=4).rev() {
            // SAFETY: `t` is a table of this hierarchy, mapped in the direct map.
            let e = unsafe { (*t)[index(virt, level)] };
            if e & P == 0 {
                return None;
            }
            if level == 1 || e & PS != 0 {
                return Some((t, level));
            }
            t = table(PhysAddr(e & ADDR_MASK));
        }
        None
    }
}

static NX_ENABLED: AtomicBool = AtomicBool::new(false);
static HUGE_1G: AtomicBool = AtomicBool::new(false);
static SMEP: AtomicBool = AtomicBool::new(false);
static SMAP: AtomicBool = AtomicBool::new(false);
static KERNEL_ROOT: AtomicU64 = AtomicU64::new(0);
static KERNEL_MAPPER: IrqSpinLock<Option<Mapper>> = IrqSpinLock::new(None);

fn nx_enabled() -> bool {
    NX_ENABLED.load(Ordering::Relaxed)
}

fn huge_1g_supported() -> bool {
    HUGE_1G.load(Ordering::Relaxed)
}

/// Exclusive access to the kernel's page tables. Only the upper half may be
/// changed through it; all address spaces share those tables.
pub fn kernel_mapper() -> impl core::ops::DerefMut<Target = Mapper> {
    struct G(IrqSpinLockGuard<'static, Option<Mapper>>);
    impl core::ops::Deref for G {
        type Target = Mapper;
        fn deref(&self) -> &Mapper {
            self.0.as_ref().expect("kernel page tables not set up")
        }
    }
    impl core::ops::DerefMut for G {
        fn deref_mut(&mut self) -> &mut Mapper {
            self.0.as_mut().expect("kernel page tables not set up")
        }
    }
    G(KERNEL_MAPPER.lock())
}

/// Make sure `phys..phys + len` is mapped in the direct map (write-back,
/// read-only). Firmware tables can sit in regions the memory map calls
/// reserved, which the direct map leaves out.
pub fn ensure_direct_mapped(phys: u64, len: u64) {
    let mut m = kernel_mapper();
    let start = phys & !(PAGE_SIZE - 1);
    for p in (start..phys + len).step_by(PAGE_SIZE as usize) {
        let v = hhdm_offset() + p;
        if m.translate(v).is_none() {
            m.map(v, PhysAddr(p), PageSize::Size4K, MapFlags::KERNEL_RODATA).expect("direct map conflict");
        }
    }
}

/// Flush this CPU's non-global TLB entries (all user mappings).
pub fn flush_local() {
    // SAFETY: Reloading CR3 with its current value only flushes the TLB.
    unsafe { asm!("mov {0}, cr3", "mov cr3, {0}", out(reg) _, options(nostack, preserves_flags)) };
}

/// Load page-table root `root` on this CPU if it is not already active.
/// Skipping the reload (and so the TLB flush) is only safe because a root
/// is never freed while a CPU has it loaded (sched::wait_root_unused):
/// otherwise a new process given the same frame would run on the old
/// one's cached translations. Use `sched::switch_root`, which records it.
pub fn switch_root(root: PhysAddr) {
    if cpu::read_cr3() & ADDR_MASK != root.0 {
        // SAFETY: Every root shares the kernel upper half, so the kernel's
        // code, data and stacks stay mapped across the switch.
        unsafe { asm!("mov cr3, {}", in(reg) root.0, options(nostack, preserves_flags)) };
    }
}

/// Physical address of the kernel PML4.
pub fn kernel_root() -> PhysAddr {
    PhysAddr(KERNEL_ROOT.load(Ordering::Relaxed))
}

/// Paging features in use, for the boot log.
#[derive(Debug)]
pub struct Features;

impl fmt::Display for Features {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flags = [
            ("NX", nx_enabled()),
            ("SMEP", SMEP.load(Ordering::Relaxed)),
            ("SMAP", SMAP.load(Ordering::Relaxed)),
            ("1G pages", huge_1g_supported()),
        ];
        let mut first = true;
        for (name, on) in flags {
            if on {
                write!(f, "{}{name}", if first { "" } else { ", " })?;
                first = false;
            }
        }
        Ok(())
    }
}

pub fn features() -> Features {
    Features
}

pub fn smap_enabled() -> bool {
    SMAP.load(Ordering::Relaxed)
}

unsafe extern "C" {
    static __kernel_start: u8;
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __kernel_end: u8;
}

fn sym(s: *const u8) -> u64 {
    s as u64
}

/// The address the kernel is linked at (linker-x86_64.ld).
const LINK_BASE: u64 = 0xffff_ffff_8000_0000;

/// How far the bootloader moved the kernel from its link address (KASLR,
/// ADR 0095); 0 where it was not moved.
pub fn kernel_slide() -> u64 {
    sym(&raw const __kernel_start).wrapping_sub(LINK_BASE)
}

/// Load `root` and turn on the protection features this CPU supports:
/// CR0.WP makes read-only mappings binding in ring 0; PGE, SMEP and SMAP
/// only add protection.
///
/// # Safety
///
/// `root` must map all code and data the CPU is using.
unsafe fn activate(root: PhysAddr, cpuid7_ebx: u32) {
    // SAFETY: Per the contract, switching CR3 keeps everything in use mapped;
    // the CR0/CR4/EFER bits only add checks the kernel is built to pass.
    unsafe {
        if nx_enabled() {
            cpu::wrmsr(MSR_EFER, cpu::rdmsr(MSR_EFER) | EFER_NXE);
        }
        cpu::write_cr0(cpu::read_cr0() | CR0_WP);
        asm!("mov cr3, {}", in(reg) root.0, options(nostack, preserves_flags));
        let mut cr4 = cpu::read_cr4() | CR4_PGE;
        if cpuid7_ebx & (1 << 7) != 0 {
            cr4 |= CR4_SMEP;
            SMEP.store(true, Ordering::Relaxed);
        }
        if cpuid7_ebx & (1 << 20) != 0 {
            cr4 |= CR4_SMAP;
            SMAP.store(true, Ordering::Relaxed);
        }
        cpu::write_cr4(cr4);
    }
}

/// Switch an application processor from the bootloader's page tables to the
/// kernel's, with the same protection features as the bootstrap CPU.
pub fn init_ap() {
    // SAFETY: The kernel page tables map everything an AP uses during
    // startup: the kernel image and the direct map (where its bootloader
    // stack lives).
    unsafe { activate(kernel_root(), cpu::cpuid(7, 0).1) };
}

/// Build the kernel address space (direct map of all RAM-like regions plus
/// the kernel image with per-segment permissions), switch to it, and turn on
/// global pages, SMEP and SMAP where the CPU has them.
pub fn init_kernel_space(map: impl Iterator<Item = Region>, (kphys, kvirt): (u64, u64)) {
    let ebx7 = cpu::cpuid(7, 0).1;
    let ext = cpu::cpuid(0x8000_0001, 0);
    let has_nx = ext.3 & (1 << 20) != 0;
    HUGE_1G.store(ext.3 & (1 << 26) != 0, Ordering::Relaxed);

    if has_nx {
        // SAFETY: EFER exists on every x86-64 CPU; setting NXE only makes
        // the NX bit meaningful.
        unsafe { cpu::wrmsr(MSR_EFER, cpu::rdmsr(MSR_EFER) | EFER_NXE) };
        NX_ENABLED.store(true, Ordering::Relaxed);
    }

    let root = frame::alloc_zeroed().expect("out of memory for the kernel PML4");
    // SAFETY: `root` is a fresh, zeroed frame that only this code uses.
    let mut m = unsafe { Mapper::from_root(root) };

    // Pre-create every upper-half PDPT so the kernel half can be shared by
    // copying the top 256 PML4 entries into each user address space.
    for i in 256..512 {
        let pdpt = frame::alloc_zeroed().expect("out of memory for kernel page tables");
        // SAFETY: `root` is our PML4, mapped in the direct map.
        unsafe { (*table(root))[i] = pdpt.0 | P | RW };
    }

    // Direct map: merge adjacent mappable regions for larger pages.
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let mut regions: Vec<Region> =
        map.filter(|r| !matches!(r.kind, RegionKind::Reserved | RegionKind::Bad) && r.len > 0).collect();
    regions.sort_by_key(|r| r.base);
    for r in regions {
        let (base, end) = (r.base & !(PAGE_SIZE - 1), (r.base + r.len).div_ceil(PAGE_SIZE) * PAGE_SIZE);
        match ranges.last_mut() {
            Some(last) if last.1 >= base => last.1 = last.1.max(end),
            _ => ranges.push((base, end)),
        }
    }
    for (base, end) in ranges {
        m.map_range(hhdm_offset() + base, PhysAddr(base), end - base, MapFlags::KERNEL_DATA)
            .expect("mapping the direct map failed");
    }

    // Kernel image, segment by segment (W^X).
    let to_phys = |v: u64| PhysAddr(v - kvirt + kphys);
    let segments = [
        (sym(&raw const __kernel_start), sym(&raw const __text_start), MapFlags::KERNEL_RODATA),
        (sym(&raw const __text_start), sym(&raw const __text_end), MapFlags::KERNEL_CODE),
        (sym(&raw const __rodata_start), sym(&raw const __rodata_end), MapFlags::KERNEL_RODATA),
        (sym(&raw const __data_start), sym(&raw const __kernel_end), MapFlags::KERNEL_DATA),
    ];
    for (start, end, flags) in segments {
        let end = end.div_ceil(PAGE_SIZE) * PAGE_SIZE;
        for v in (start..end).step_by(PAGE_SIZE as usize) {
            m.map(v, to_phys(v), PageSize::Size4K, flags).expect("mapping the kernel image failed");
        }
    }

    // SAFETY: The new tables map everything the kernel can be using right
    // now: its image (same virtual addresses), its stack and all bootloader
    // data (in the direct map at the same offset).
    unsafe { activate(root, ebx7) };
    KERNEL_ROOT.store(root.0, Ordering::Relaxed);
    *KERNEL_MAPPER.lock() = Some(m);
}
