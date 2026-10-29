// SPDX-License-Identifier: MIT OR Apache-2.0

//! AMD I/O virtualization (AMD-Vi): DMA remapping for the devices that ask.
//!
//! Source: AMD I/O Virtualization Technology (IOMMU) Specification 48882,
//! Rev 3.11 (April 2026): the Device Table and its entries (§2.2.2, Table
//! 7), host I/O page tables (§2.2.3, Tables 15 to 18), starting the IOMMU
//! (§2.3), the command buffer with COMPLETION_WAIT, INVALIDATE_DEVTAB_ENTRY,
//! INVALIDATE_IOMMU_PAGES and INVALIDATE_IOMMU_ALL (§2.4), the event log and
//! IO_PAGE_FAULT (§2.5, §2.5.3), the capability block and MMIO registers
//! (§3.2, §3.4) and the IVRS table (§5.2, parsed by `slate_acpi::ivrs`).
//!
//! A device whose driver asks (`domain_for`) gets a domain of its own: a
//! four-level page table where a page is present only while the driver has
//! mapped it, at its own physical address (I/O virtual addresses equal
//! physical ones, so drivers keep handing devices physical addresses). Any
//! other access is target aborted and logged. Every other device's Device
//! Table entry stays invalid, which passes its DMA and interrupts through
//! untranslated (Table 8, Table 9), as without an IOMMU (ADR 0127).

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, AtomicU64, Ordering};

use slate_acpi::ivrs;
use slate_sync::Once;

use super::dma::{Dma, Mmio, wait_for};
use super::pci::{self, Address};
use crate::mm::PhysAddr;
use crate::sync::IrqSpinLock;
use crate::{log_info, log_warn};

// MMIO registers (§3.4).
const DEVICE_TABLE: usize = 0x0000;
const COMMAND_BASE: usize = 0x0008;
const EVENT_BASE: usize = 0x0010;
const CONTROL: usize = 0x0018;
const EXCLUSION_BASE: usize = 0x0020;
const EXCLUSION_LIMIT: usize = 0x0028;
const FEATURES: usize = 0x0030;
const COMMAND_HEAD: usize = 0x2000;
const COMMAND_TAIL: usize = 0x2008;
const EVENT_HEAD: usize = 0x2010;
const EVENT_TAIL: usize = 0x2018;
const STATUS: usize = 0x2020;
/// The registers used, rounded to the 16 KiB every IOMMU has (§2.3).
const MMIO_LEN: u64 = 0x4000;

// The Control register (MMIO 0018h).
const CTRL_IOMMU_EN: u64 = 1 << 0;
const CTRL_EVENT_LOG_EN: u64 = 1 << 2;
const CTRL_CMD_BUF_EN: u64 = 1 << 12;
/// The bits IVHD flags recommend (Table 92), by flag bit: HtTunEn (bit 1),
/// PassPW (8), ResPassPW (9), Isoc (11), Coherent (10).
const CTRL_FROM_FLAGS: [(u8, u64); 5] = [(0, 1 << 1), (1, 1 << 8), (2, 1 << 9), (3, 1 << 11), (5, 1 << 10)];

// The Status register (MMIO 2020h).
const STATUS_EVENT_OVERFLOW: u64 = 1 << 0;
const STATUS_EVENT_LOG_RUN: u64 = 1 << 3;
const STATUS_CMD_BUF_RUN: u64 = 1 << 4;

/// Extended Feature Register (MMIO 0030h) bit 6: INVALIDATE_IOMMU_ALL.
const FEATURE_INVALIDATE_ALL: u64 = 1 << 6;
/// Capability header (Capability Offset 00h) bits: NpCache (26) and
/// EFRSup (27).
const CAP_NP_CACHE: u32 = 1 << 26;

// Commands (§2.4): the opcode in bits 31:28 of the second dword.
const CMD_COMPLETION_WAIT: u32 = 0x1;
const CMD_INVALIDATE_DEVTAB_ENTRY: u32 = 0x2;
const CMD_INVALIDATE_IOMMU_PAGES: u32 = 0x3;
const CMD_INVALIDATE_IOMMU_ALL: u32 = 0x8;
/// The command buffer and event log: 256 entries of 16 bytes, the
/// smallest (length code 1000b).
const RING_ENTRIES: usize = 256;
const RING_LEN_CODE: u64 = 8 << 56;

/// An event log entry's code (bits 31:28 of its second dword): IO_PAGE_FAULT.
const EVENT_IO_PAGE_FAULT: u32 = 0x2;

// I/O page table entries (Tables 17 and 18).
const PTE_PRESENT: u64 = 1 << 0;
const PTE_IR: u64 = 1 << 61;
const PTE_IW: u64 = 1 << 62;
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
/// Translation levels; DTE Mode 4 covers 48 bits of address.
const LEVELS: u64 = 4;

// Device Table entry, first quadword (Table 7): V, TV, Mode (bits 11:9), the
// page table root (51:12), IR and IW. The second quadword holds DomainID.
const DTE_V: u64 = 1 << 0;
const DTE_TV: u64 = 1 << 1;
const DTE_BYTES: usize = 32;
const DEVICE_IDS: usize = 1 << 16;

const PAGE: u64 = 4096;
/// How long a COMPLETION_WAIT may take.
const WAIT_MS: u64 = 100;
/// Faults logged one by one per IOMMU; later ones are only counted.
const FAULTS_LOGGED: u64 = 32;

/// One IOMMU.
pub struct Unit {
    info: ivrs::Iommu,
    regs: Mmio,
    device_table: Dma,
    commands: IrqSpinLock<Ring>,
    events: IrqSpinLock<Ring>,
    /// Where COMPLETION_WAIT stores its sequence number.
    wait_word: Dma,
    /// A page table with nothing in it, for closed domains.
    empty: Dma,
    sequence: AtomicU64,
    /// Not-present entries are cached: a map needs an invalidation too.
    np_cache: bool,
    invalidate_all: bool,
    next_domain: AtomicU16,
    /// Sources (DeviceIDs) that have a domain.
    taken: IrqSpinLock<Vec<u16>>,
    faults: AtomicU64,
}

/// The command buffer or the event log: its memory and our index into it.
struct Ring {
    mem: Dma,
    index: usize,
}

/// One device's address space.
pub struct Domain {
    unit: &'static Unit,
    id: u16,
    source: u16,
    root: Dma,
    state: IrqSpinLock<State>,
}

struct State {
    /// The page tables below the root, kept until the domain goes.
    tables: Vec<Dma>,
    /// How many mappings each mapped page has.
    pages: BTreeMap<u64, u32>,
}

static UNITS: Once<Vec<Unit>> = Once::new();

impl Unit {
    fn read(&self, off: usize) -> u64 {
        self.regs.read64(off)
    }

    fn write(&self, off: usize, v: u64) {
        self.regs.write64(off, v);
    }

    /// Queue commands (each four dwords), then wait for the IOMMU to finish
    /// them (COMPLETION_WAIT with a store). Returns whether it did in time.
    fn run(&self, commands: &[[u32; 4]]) -> bool {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let addr = self.wait_word.phys();
        let wait = [
            (addr as u32 & !7) | 1,
            (CMD_COMPLETION_WAIT << 28) | ((addr >> 32) as u32 & 0xF_FFFF),
            seq as u32,
            (seq >> 32) as u32,
        ];
        let mut ring = self.commands.lock();
        for c in commands.iter().chain(core::iter::once(&wait)) {
            // Room: the IOMMU's head must not be the entry after ours.
            let next = (ring.index + 1) % RING_ENTRIES;
            if !spin_for(|| (self.read(COMMAND_HEAD) as usize >> 4) % RING_ENTRIES != next) {
                log_warn!("iommu: the command buffer stays full");
                return false;
            }
            for (i, d) in c.iter().enumerate() {
                ring.mem.write::<u32>(ring.index * 16 + i * 4, *d);
            }
            ring.index = next;
        }
        core::sync::atomic::fence(Ordering::SeqCst);
        self.write(COMMAND_TAIL, (ring.index as u64) << 4);
        drop(ring);
        let done = spin_for(|| self.wait_word.read::<u64>(0) >= seq);
        if !done {
            log_warn!("iommu: a command did not complete (status {:#x})", self.read(STATUS));
        }
        done
    }

    /// Invalidate pages [first, first + 2^k pages) of a domain, `first`
    /// aligned to its size (§2.4.3: S=1 sizes the range by the first zero
    /// bit of the address from bit 12). Directories stay cached (PDE=0):
    /// a domain's tables are never freed or changed, only its leaves.
    fn invalidate_command(domain: u16, first: u64, k: u32) -> [u32; 4] {
        let (addr, s) = if k == 0 { (first, 0) } else { (first | (((1u64 << (k - 1)) - 1) << 12), 1) };
        [0, (CMD_INVALIDATE_IOMMU_PAGES << 28) | u32::from(domain), (addr as u32 & !0xFFF) | s, (addr >> 32) as u32]
    }

    /// The smallest aligned power-of-two block of pages holding [start, end).
    fn covering(start: u64, end: u64) -> (u64, u32) {
        let mut k = 0;
        loop {
            let size = PAGE << k;
            let first = start & !(size - 1);
            if first + size >= end || k >= 52 {
                return (first, k);
            }
            k += 1;
        }
    }

    /// Write a device's Device Table entry and make the IOMMU reread it.
    fn set_entry(&self, source: u16, q0: u64, q1: u64) {
        let at = usize::from(source) * DTE_BYTES;
        // The domain first, the valid bits last (§2.2.2.2).
        self.device_table.write::<u64>(at + 8, q1);
        self.device_table.write::<u64>(at + 16, 0);
        self.device_table.write::<u64>(at + 24, 0);
        core::sync::atomic::fence(Ordering::SeqCst);
        self.device_table.write::<u64>(at, q0);
        self.run(&[[u32::from(source), CMD_INVALIDATE_DEVTAB_ENTRY << 28, 0, 0]]);
    }

    /// Log the event log's new entries (from the poller, or the tests).
    fn drain(&self) {
        let mut ring = self.events.lock();
        let tail = (self.read(EVENT_TAIL) as usize >> 4) % RING_ENTRIES;
        while ring.index != tail {
            let at = ring.index * 16;
            let e: [u32; 4] = core::array::from_fn(|i| ring.mem.read::<u32>(at + i * 4));
            if e[1] >> 28 == EVENT_IO_PAGE_FAULT {
                let n = self.faults.fetch_add(1, Ordering::Relaxed);
                if n < FAULTS_LOGGED {
                    let id = e[0] as u16;
                    let what = if e[1] & (1 << 21) != 0 { "write" } else { "read" };
                    let addr = u64::from(e[2]) | (u64::from(e[3]) << 32);
                    log_warn!(
                        "iommu: {:?} refused: {what} at {addr:#x} (domain {}{})",
                        address_of(id),
                        e[1] & 0xFFFF,
                        if e[1] & (1 << 20) == 0 { ", not mapped" } else { ", not allowed" }
                    );
                }
            } else {
                log_warn!("iommu: event {:#x}: {:08x} {:08x} {:08x} {:08x}", e[1] >> 28, e[0], e[1], e[2], e[3]);
            }
            ring.mem.zero_range(at, 16);
            ring.index = (ring.index + 1) % RING_ENTRIES;
        }
        self.write(EVENT_HEAD, (ring.index as u64) << 4);
        if self.read(STATUS) & STATUS_EVENT_OVERFLOW != 0 {
            // §2.5.1: stop the log, clear the overflow, start it empty.
            log_warn!("iommu: the event log overflowed");
            self.write(CONTROL, self.read(CONTROL) & !CTRL_EVENT_LOG_EN);
            wait_for(WAIT_MS, || self.read(STATUS) & STATUS_EVENT_LOG_RUN == 0);
            self.write(STATUS, STATUS_EVENT_OVERFLOW);
            self.write(EVENT_HEAD, 0);
            self.write(EVENT_TAIL, 0);
            ring.index = 0;
            self.write(CONTROL, self.read(CONTROL) | CTRL_EVENT_LOG_EN);
        }
    }
}

/// Wait up to `WAIT_MS` for `cond`, spinning: commands take microseconds,
/// far less than a sleep (`wait_for` sleeps 200 µs between looks), and a
/// request's unmap waits for one.
fn spin_for(mut cond: impl FnMut() -> bool) -> bool {
    let deadline = crate::time::monotonic_ns() + WAIT_MS * 1_000_000;
    while !cond() {
        if crate::time::monotonic_ns() >= deadline {
            return cond();
        }
        core::hint::spin_loop();
    }
    true
}

/// The PCI address of DeviceID `id` (bus, device, function: Figure 5).
fn address_of(id: u16) -> Address {
    Address { bus: (id >> 8) as u8, device: ((id >> 3) & 0x1F) as u8, function: (id & 7) as u8 }
}

fn device_id(a: Address) -> u16 {
    (u16::from(a.bus) << 8) | (u16::from(a.device) << 3) | u16::from(a.function)
}

/// Find the IOMMUs and start them, every Device Table entry invalid.
/// `slate.iommu=off` on the command line leaves them alone.
pub fn init(cmdline: &str) {
    let off = cmdline.split_ascii_whitespace().any(|w| w == "slate.iommu=off");
    let Some(table) = crate::acpi::info().tables.iter().find(|t| &t.signature == b"IVRS") else { return };
    if off {
        log_info!("iommu: left off (slate.iommu=off)");
        return;
    }
    let units: Vec<Unit> = ivrs::parse(table.bytes).into_iter().filter_map(start).collect();
    if !units.is_empty() {
        UNITS.call_once(|| units);
        crate::sched::spawn("iommu-events", || {
            loop {
                poll();
                crate::time::sleep_ns(250_000_000);
            }
        });
    }
}

fn start(info: ivrs::Iommu) -> Option<Unit> {
    if info.segment != 0 {
        log_warn!("iommu at {:#x}: PCI segment {} is not supported", info.base, info.segment);
        return None;
    }
    let cap = pci::config_read(address_of(info.device_id), info.capability, 4);
    let unit = Unit {
        regs: Mmio(crate::mm::vmap::map_mmio(PhysAddr(info.base), MMIO_LEN)),
        device_table: Dma::new(DEVICE_IDS * DTE_BYTES)?,
        commands: IrqSpinLock::new(Ring { mem: Dma::new(RING_ENTRIES * 16)?, index: 0 }),
        events: IrqSpinLock::new(Ring { mem: Dma::new(RING_ENTRIES * 16)?, index: 0 }),
        wait_word: Dma::new(8)?,
        empty: Dma::new(PAGE as usize)?,
        sequence: AtomicU64::new(0),
        np_cache: cap & CAP_NP_CACHE != 0,
        invalidate_all: false,
        next_domain: AtomicU16::new(1),
        taken: IrqSpinLock::new(Vec::new()),
        faults: AtomicU64::new(0),
        info,
    };
    // Stop it if the firmware left it running (§2.4: the command buffer
    // must be stopped before its registers change).
    let ctrl = unit.read(CONTROL);
    if ctrl & CTRL_IOMMU_EN != 0 {
        unit.write(CONTROL, ctrl & !(CTRL_IOMMU_EN | CTRL_CMD_BUF_EN | CTRL_EVENT_LOG_EN));
        wait_for(WAIT_MS, || unit.read(STATUS) & (STATUS_CMD_BUF_RUN | STATUS_EVENT_LOG_RUN) == 0);
    }
    let unit = Unit { invalidate_all: unit.read(FEATURES) & FEATURE_INVALIDATE_ALL != 0, ..unit };
    // Size: (n + 1) × 4 KiB, all 64 Ki entries.
    unit.write(DEVICE_TABLE, unit.device_table.phys() | 0x1FF);
    unit.write(COMMAND_BASE, unit.commands.lock().mem.phys() | RING_LEN_CODE);
    unit.write(EVENT_BASE, unit.events.lock().mem.phys() | RING_LEN_CODE);
    for r in [COMMAND_HEAD, COMMAND_TAIL, EVENT_HEAD, EVENT_TAIL, EXCLUSION_BASE, EXCLUSION_LIMIT] {
        unit.write(r, 0);
    }
    unit.write(STATUS, STATUS_EVENT_OVERFLOW);
    let mut ctrl = CTRL_IOMMU_EN | CTRL_EVENT_LOG_EN | CTRL_CMD_BUF_EN;
    for (flag, bit) in CTRL_FROM_FLAGS {
        if unit.info.flags & (1 << flag) != 0 {
            ctrl |= bit;
        }
    }
    unit.write(CONTROL, ctrl);
    // Whatever the IOMMU cached from the firmware's tables goes.
    let ok = if unit.invalidate_all {
        unit.run(&[[0, CMD_INVALIDATE_IOMMU_ALL << 28, 0, 0]])
    } else {
        let all: Vec<[u32; 4]> = pci::devices()
            .iter()
            .map(|d| [u32::from(unit.info.source_of(device_id(d.address))), CMD_INVALIDATE_DEVTAB_ENTRY << 28, 0, 0])
            .collect();
        all.chunks(RING_ENTRIES / 2).all(|c| unit.run(c))
    };
    if !ok {
        log_warn!("iommu at {:#x}: does not complete commands; left off", unit.info.base);
        unit.write(CONTROL, 0);
        return None;
    }
    log_info!(
        "iommu: AMD-Vi at {:#x} ({:?}), {} device ranges{}",
        unit.info.base,
        address_of(unit.info.device_id),
        unit.info.devices.len() + unit.info.aliases.len(),
        if unit.np_cache { ", caches not-present entries" } else { "" }
    );
    Some(unit)
}

/// Read every IOMMU's event log.
pub fn poll() {
    for u in UNITS.get().into_iter().flatten() {
        u.drain();
    }
}

/// How many DMA accesses the IOMMUs refused.
pub fn faults() -> u64 {
    UNITS.get().into_iter().flatten().map(|u| u.faults.load(Ordering::Relaxed)).sum()
}

/// A domain of its own for `dev`, where it reaches only what is mapped
/// (and the memory the firmware's IVMD blocks reserve for it). `None` when
/// no IOMMU translates it, or its DeviceID already has one.
pub fn domain_for(dev: &pci::Device) -> Option<Arc<Domain>> {
    let id = device_id(dev.address);
    let unit = UNITS.get()?.iter().find(|u| u.info.covers(id))?;
    let source = unit.info.source_of(id);
    {
        let mut taken = unit.taken.lock();
        if taken.contains(&source) {
            log_warn!("iommu: {:?} shares DeviceID {source:#x} with a device that has a domain", dev.address);
            return None;
        }
        taken.push(source);
    }
    let domain = Arc::new(Domain {
        unit,
        id: unit.next_domain.fetch_add(1, Ordering::Relaxed),
        source,
        root: Dma::new(PAGE as usize)?,
        state: IrqSpinLock::new(State { tables: Vec::new(), pages: BTreeMap::new() }),
    });
    for m in unit.info.memory.iter().filter(|m| (m.first..=m.last).contains(&source)) {
        // Unity ranges, and exclusion ranges (which the IOMMU would pass
        // through), stay reachable at their own addresses.
        if m.flags & 0b1001 != 0 {
            domain.map(m.start, m.len as usize);
        }
    }
    let q0 = DTE_V | DTE_TV | (LEVELS << 9) | (domain.root.phys() & ADDR_MASK) | PTE_IR | PTE_IW;
    unit.set_entry(source, q0, u64::from(domain.id));
    log_info!("iommu: {:?} is in domain {} (DeviceID {source:#x})", dev.address, domain.id);
    Some(domain)
}

impl Domain {
    /// Let the device read and write the pages of [phys, phys + len).
    pub fn map(&self, phys: u64, len: usize) {
        self.map_pages(pages_of(phys, len));
    }

    /// `map` for the pages holding each of `addrs` (a request's pages).
    pub fn map_pages(&self, addrs: impl IntoIterator<Item = u64>) {
        let mut st = self.state.lock();
        let mut fresh: Option<(u64, u64)> = None;
        for page in addrs.into_iter().map(|a| a & !(PAGE - 1)) {
            let n = st.pages.entry(page).or_insert(0);
            *n += 1;
            if *n == 1 {
                self.set(&mut st, page, page | PTE_IR | PTE_IW | PTE_PRESENT);
                fresh = Some(fresh.map_or((page, page + PAGE), |(a, b)| (a.min(page), b.max(page + PAGE))));
            }
        }
        drop(st);
        if let Some((first, end)) = fresh.filter(|_| self.unit.np_cache) {
            self.invalidate(first, end);
        }
    }

    /// Take back what one `map_pages` of the same addresses gave: the
    /// entries cleared, then one invalidation covering them and one wait,
    /// however many pages. Once this returns, the device can no longer
    /// reach pages nothing else mapped.
    pub fn unmap_pages(&self, addrs: impl IntoIterator<Item = u64>) {
        let mut st = self.state.lock();
        let mut gone: Option<(u64, u64)> = None;
        for page in addrs.into_iter().map(|a| a & !(PAGE - 1)) {
            match st.pages.get_mut(&page) {
                Some(n) if *n > 1 => *n -= 1,
                Some(_) => {
                    st.pages.remove(&page);
                    self.set(&mut st, page, 0);
                    gone = Some(gone.map_or((page, page + PAGE), |(a, b)| (a.min(page), b.max(page + PAGE))));
                }
                None => {}
            }
        }
        drop(st);
        if let Some((first, end)) = gone {
            self.invalidate(first, end);
        }
    }

    /// Whether `phys`'s page is mapped (for the tests).
    pub fn is_mapped(&self, phys: u64) -> bool {
        self.state.lock().pages.contains_key(&(phys & !(PAGE - 1)))
    }

    fn invalidate(&self, first: u64, end: u64) {
        let (base, k) = Unit::covering(first, end);
        self.unit.run(&[Unit::invalidate_command(self.id, base, k)]);
    }

    /// Set the level-1 entry for `page`, making the tables above it.
    fn set(&self, st: &mut State, page: u64, entry: u64) {
        let mut table_phys = self.root.phys();
        for level in (2..=LEVELS).rev() {
            let index = ((page >> (12 + 9 * (level - 1))) & 0x1FF) as usize;
            let table = phys_table(table_phys);
            let e = table.read(index);
            table_phys = if e & PTE_PRESENT != 0 {
                e & ADDR_MASK
            } else {
                if entry == 0 {
                    // Nothing below to clear.
                    return;
                }
                let Some(next) = Dma::new(PAGE as usize) else {
                    log_warn!("iommu: no memory for a page table");
                    return;
                };
                let p = next.phys();
                // A directory: the next level's table, all of it allowed
                // (the leaf decides).
                table.write(index, p | ((level - 1) << 9) | PTE_IR | PTE_IW | PTE_PRESENT);
                st.tables.push(next);
                p
            };
        }
        phys_table(table_phys).write(((page >> 12) & 0x1FF) as usize, entry);
    }

    /// Block the device entirely (before its memory is freed, as when it
    /// is unplugged); the domain can be dropped after this.
    pub fn close(&self) {
        // V and TV, no permissions, an empty table: every access aborted.
        // (Mode 0 with no permissions would do on hardware; QEMU's model
        // passes Mode 0 through whatever the permissions.)
        let q0 = DTE_V | DTE_TV | (LEVELS << 9) | self.unit.empty.phys();
        self.unit.set_entry(self.source, q0, u64::from(self.id));
        // The whole address space (S=1 with every address bit set).
        self.unit.run(&[Unit::invalidate_command(self.id, 0x7FFF_FFFF_FFFF_F000 & !0xFFF, 52)]);
        self.unit.taken.lock().retain(|s| *s != self.source);
    }
}

/// The page addresses of [phys, phys + len).
fn pages_of(phys: u64, len: usize) -> impl Iterator<Item = u64> {
    let (first, end) = (phys & !(PAGE - 1), (phys + len.max(1) as u64).next_multiple_of(PAGE));
    (first..end).step_by(PAGE as usize)
}

/// A page table by its physical address, through the direct map.
struct PhysTable(*mut u64);

fn phys_table(phys: u64) -> PhysTable {
    PhysTable(PhysAddr(phys).to_virt().cast())
}

impl PhysTable {
    fn read(&self, i: usize) -> u64 {
        // SAFETY: `self.0` is a page table page the domain owns, mapped in
        // the direct map; `i` < 512.
        unsafe { self.0.add(i).read_volatile() }
    }

    fn write(&self, i: usize, v: u64) {
        // SAFETY: As above.
        unsafe { self.0.add(i).write_volatile(v) }
    }
}
