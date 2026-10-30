// SPDX-License-Identifier: MIT OR Apache-2.0

//! PCI and PCI Express: configuration space through ECAM (the ACPI MCFG
//! table), or on machines without one (plain PCI chipsets, such as
//! QEMU's i440fx that libvirt and GNOME Boxes use) through configuration
//! mechanism #1 (I/O ports 0xCF8 and 0xCFC, its first 256 bytes); device
//! enumeration, BARs, capabilities, MSI and MSI-X.
//!
//! Sources: PCI Local Bus Specification 3.0 (configuration mechanism #1,
//! §3.2.2.3.2; configuration header, §6.1;
//! capabilities list, §6.7; MSI, §6.8.1; MSI-X, §6.8.2), PCI Express Base Specification
//! (enhanced configuration access, §7.2.2), PCI Firmware Specification 3.2
//! (MCFG), PCI-to-PCI Bridge Architecture Specification 1.2 (the memory
//! and prefetchable memory windows of a bridge, §3.2.5.8-§3.2.5.10).
//! Firmware has already assigned bus numbers and BAR addresses; Slate
//! keeps them. A function plugged in later (`hot_add`) gets its memory
//! BARs from the window of the bridge above it.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use slate_sync::Once;

use crate::arch::port::Port32;
use crate::mm::PhysAddr;
use crate::mm::vmap::map_mmio;
use crate::sync::IrqSpinLock;
use crate::{log_info, log_warn};

// Configuration header offsets (type 0 and 1).
const VENDOR_ID: usize = 0x00;
const DEVICE_ID: usize = 0x02;
const COMMAND: usize = 0x04;
const STATUS: usize = 0x06;
const REVISION: usize = 0x08;
const HEADER_TYPE: usize = 0x0E;
const BAR0: usize = 0x10;
const SECONDARY_BUS: usize = 0x19;
/// A bridge's memory window (bits 31:20 of base and limit in bits 15:4)
/// and prefetchable memory window (the same, with upper 32 bits at 0x28
/// and 0x2C when bits 3:0 read 1).
const MEMORY_BASE: usize = 0x20;
const MEMORY_LIMIT: usize = 0x22;
const PREF_BASE: usize = 0x24;
const PREF_LIMIT: usize = 0x26;
const PREF_BASE_UPPER: usize = 0x28;
const PREF_LIMIT_UPPER: usize = 0x2C;
const CAPABILITIES_PTR: usize = 0x34;

const COMMAND_IO: u16 = 1 << 0;
const COMMAND_MEMORY: u16 = 1 << 1;
const COMMAND_BUS_MASTER: u16 = 1 << 2;
const COMMAND_INTX_DISABLE: u16 = 1 << 10;
const STATUS_CAPABILITIES: u16 = 1 << 4;

/// Power management (PCI Bus Power Management Interface Specification
/// 1.2, §3.2): PMCSR at +4, its power state in bits 1:0 (§3.2.4).
const CAP_PM: u8 = 0x01;
const PMCSR_STATE: u16 = 0b11;
pub const CAP_MSI: u8 = 0x05;
pub const CAP_VENDOR: u8 = 0x09;
pub const CAP_MSIX: u8 = 0x11;

/// Bus, device, function.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}:{:02x}.{}", self.bus, self.device, self.function)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bar {
    Memory { address: u64, size: u64, prefetchable: bool },
    Io { port: u16, size: u32 },
}

/// How a function's configuration space is reached.
#[derive(Clone, Copy)]
enum Config {
    /// Its 4 KiB, mapped uncached (ECAM).
    Mapped(*mut u8),
    /// Configuration mechanism #1: 256 bytes through I/O ports.
    Ports,
}

/// CONFIG_ADDRESS and CONFIG_DATA (§3.2.2.3.2), used in turn, so under a
/// lock.
const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;
static PORTS: IrqSpinLock<()> = IrqSpinLock::new(());

/// Read the dword at `off` (below 256, aligned) of function `a` through
/// the ports.
fn port_read(a: Address, off: usize) -> u32 {
    let _g = PORTS.lock();
    // SAFETY: CONFIG_ADDRESS and CONFIG_DATA select and move configuration
    // dwords; the address names one function's register.
    unsafe {
        Port32::new(CONFIG_ADDRESS).write(port_address(a, off));
        Port32::new(CONFIG_DATA).read()
    }
}

fn port_write(a: Address, off: usize, v: u32) {
    let _g = PORTS.lock();
    // SAFETY: As for `port_read`; configuration writes only affect this
    // function.
    unsafe {
        Port32::new(CONFIG_ADDRESS).write(port_address(a, off));
        Port32::new(CONFIG_DATA).write(v);
    }
}

/// The enable bit, bus, device, function and dword register (§3.2.2.3.2).
fn port_address(a: Address, off: usize) -> u32 {
    0x8000_0000
        | (u32::from(a.bus) << 16)
        | (u32::from(a.device) << 11)
        | (u32::from(a.function) << 8)
        | (off as u32 & 0xFC)
}

/// One PCI function.
pub struct Device {
    pub address: Address,
    config: Config,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
    pub bars: [Option<Bar>; 6],
    /// Virtual addresses of memory BARs mapped so far.
    mapped: IrqSpinLock<[usize; 6]>,
}

// SAFETY: `config` points at device registers mapped for the kernel's whole
// life (or names I/O ports); accesses are volatile and individually atomic
// for the device.
unsafe impl Send for Device {}
// SAFETY: As above.
unsafe impl Sync for Device {}

impl fmt::Debug for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} {:04x}:{:04x} class {:02x}.{:02x}.{:02x}",
            self.address, self.vendor, self.device, self.class, self.subclass, self.prog_if
        )
    }
}

impl Device {
    /// The configuration space's size: 4096 bytes through ECAM, 256 through
    /// the ports.
    pub fn config_size(&self) -> usize {
        match self.config {
            Config::Mapped(_) => 4096,
            Config::Ports => 256,
        }
    }

    /// Through the ports, offsets from 256 read as all ones and writes
    /// there go nowhere (there is no extended configuration space).
    pub fn read8(&self, off: usize) -> u8 {
        assert!(off < 4096);
        match self.config {
            // SAFETY: Inside this function's mapped configuration space.
            Config::Mapped(c) => unsafe { c.add(off).read_volatile() },
            Config::Ports if off < 256 => (port_read(self.address, off) >> (8 * (off % 4))) as u8,
            Config::Ports => 0xFF,
        }
    }

    pub fn read16(&self, off: usize) -> u16 {
        assert!(off < 4095 && off % 2 == 0);
        match self.config {
            // SAFETY: As above, naturally aligned.
            Config::Mapped(c) => unsafe { c.add(off).cast::<u16>().read_volatile() },
            Config::Ports if off < 256 => (port_read(self.address, off) >> (8 * (off % 4))) as u16,
            Config::Ports => 0xFFFF,
        }
    }

    pub fn read32(&self, off: usize) -> u32 {
        assert!(off < 4093 && off % 4 == 0);
        match self.config {
            // SAFETY: As above.
            Config::Mapped(c) => unsafe { c.add(off).cast::<u32>().read_volatile() },
            Config::Ports if off < 256 => port_read(self.address, off),
            Config::Ports => u32::MAX,
        }
    }

    pub fn write16(&self, off: usize, v: u16) {
        assert!(off < 4095 && off % 2 == 0);
        match self.config {
            // SAFETY: As above; configuration writes only affect this function.
            Config::Mapped(c) => unsafe { c.add(off).cast::<u16>().write_volatile(v) },
            Config::Ports if off < 256 => {
                // The ports move whole dwords: keep the other half. The
                // status register's write-one-to-clear bits are written as
                // read; Slate only writes the command register this way.
                let shift = 8 * (off % 4);
                let old = port_read(self.address, off & !3);
                let new = (old & !(0xFFFF << shift)) | (u32::from(v) << shift);
                port_write(self.address, off & !3, new);
            }
            Config::Ports => {}
        }
    }

    pub fn write32(&self, off: usize, v: u32) {
        assert!(off < 4093 && off % 4 == 0);
        match self.config {
            // SAFETY: As above.
            Config::Mapped(c) => unsafe { c.add(off).cast::<u32>().write_volatile(v) },
            Config::Ports if off < 256 => port_write(self.address, off, v),
            Config::Ports => {}
        }
    }

    /// The capabilities list as (ID, offset) pairs.
    pub fn capabilities(&self) -> Vec<(u8, usize)> {
        let mut caps = Vec::new();
        if self.read16(STATUS) & STATUS_CAPABILITIES == 0 {
            return caps;
        }
        let mut off = usize::from(self.read8(CAPABILITIES_PTR) & 0xFC);
        // The list lives in the first 256 bytes; 48 entries is the most that fit.
        while off >= 0x40 && caps.len() < 48 {
            caps.push((self.read8(off), off));
            off = usize::from(self.read8(off + 1) & 0xFC);
        }
        caps
    }

    /// The configuration-space offset of capability `id`.
    pub fn capability(&self, id: u8) -> Option<usize> {
        self.capabilities().into_iter().find(|&(i, _)| i == id).map(|(_, off)| off)
    }

    /// Turn on memory decoding and bus mastering (DMA), and turn off INTx
    /// (Slate uses MSI-X or MSI). A function another system left in a
    /// low-power state is brought back to D0 first: in D3hot its registers
    /// read as all ones.
    pub fn enable(&self) {
        self.wake();
        self.enable_bridges_above();
        let cmd = self.read16(COMMAND);
        self.write16(COMMAND, cmd | COMMAND_MEMORY | COMMAND_IO | COMMAND_BUS_MASTER | COMMAND_INTX_DISABLE);
    }

    /// Turn on memory decoding and bus mastering in every bridge between
    /// the function and the root complex. A bridge whose Bus Master Enable
    /// is clear refuses the memory requests it gets from below (PCI Express
    /// Base Specification 4.0, §7.5.1.1.3; PCI-to-PCI Bridge Architecture
    /// Specification 1.2, §3.2.5.3): the function's DMA and its MSI writes.
    /// Firmware sets it only for ports it used itself (a boot drive, the
    /// USB controllers), so a network card it never booted from had none.
    fn enable_bridges_above(&self) {
        let all = devices();
        let mut bus = self.address.bus;
        // Each step goes up a bus; 256 bounds a malformed topology.
        for _ in 0..256 {
            if bus == 0 {
                break;
            }
            let Some(bridge) = all.iter().find(|d| d.read8(HEADER_TYPE) & 0x7F == 1 && d.read8(SECONDARY_BUS) == bus)
            else {
                break;
            };
            let cmd = bridge.read16(COMMAND);
            if cmd & (COMMAND_MEMORY | COMMAND_BUS_MASTER) != COMMAND_MEMORY | COMMAND_BUS_MASTER {
                bridge.write16(COMMAND, cmd | COMMAND_MEMORY | COMMAND_BUS_MASTER);
                log_info!("{:?}: bus mastering turned on for {:?} below it", bridge.address, self.address);
            }
            bus = bridge.address.bus;
        }
    }

    /// Put the function in D0 if it is in D1, D2 or D3hot. Leaving D3hot
    /// may reset it (PMCSR's No_Soft_Reset clear, §3.2.4), which clears
    /// its BARs: they are written back. D3hot to D0 takes up to 10 ms
    /// (§5.6.1, table 5-6).
    fn wake(&self) {
        let Some(pm) = self.capability(CAP_PM) else { return };
        let pmcsr = self.read16(pm + 4);
        let state = pmcsr & PMCSR_STATE;
        if state == 0 {
            return;
        }
        // A bridge (header type 1) has two BARs, a device six.
        let count = if self.read8(HEADER_TYPE) & 0x7F == 0 { 6 } else { 2 };
        let bars: [u32; 6] = core::array::from_fn(|i| self.read32(BAR0 + 4 * i));
        self.write16(pm + 4, pmcsr & !PMCSR_STATE);
        super::dma::delay_ms(10);
        for (i, &b) in bars.iter().enumerate().take(count) {
            if self.read32(BAR0 + 4 * i) != b {
                self.write32(BAR0 + 4 * i, b);
            }
        }
        log_info!("{:?}: woken from D{state} to D{}", self.address, self.read16(pm + 4) & PMCSR_STATE);
    }

    /// Map memory BAR `i` and return its virtual address.
    pub fn map_bar(&self, i: usize) -> Option<*mut u8> {
        let Some(Bar::Memory { address, size, .. }) = self.bars.get(i).copied().flatten() else { return None };
        let mut mapped = self.mapped.lock();
        if mapped[i] == 0 {
            mapped[i] = map_mmio(PhysAddr(address), size) as usize;
        }
        Some(mapped[i] as *mut u8)
    }

    /// Turn MSI-X and MSI off (before the function goes away).
    pub fn disable_interrupts(&self) {
        if let Some(cap) = self.capability(CAP_MSIX) {
            self.write16(cap + 2, self.read16(cap + 2) & !(1 << 15));
        }
        if let Some(cap) = self.capability(CAP_MSI) {
            self.write16(cap + 2, self.read16(cap + 2) & !1);
        }
    }

    /// The number of entries in the function's MSI-X table, if it has one.
    pub fn msix_size(&self) -> Option<usize> {
        let cap = self.capability(CAP_MSIX)?;
        Some(usize::from(self.read16(cap + 2) & 0x7FF) + 1)
    }

    /// Set up MSI-X with one table entry per element of `vectors` (entry
    /// `i` raises `vectors[i]` on `dest`), and enable it.
    pub fn enable_msix(&self, vectors: &[u8], dest: u32) -> Option<()> {
        let entries: Vec<(u8, u32)> = vectors.iter().map(|&v| (v, dest)).collect();
        self.enable_msix_each(&entries)
    }

    /// Set up MSI-X with one table entry per element of `entries` (entry
    /// `i` raises vector `entries[i].0` on the CPU with APIC ID
    /// `entries[i].1`), and enable it.
    pub fn enable_msix_each(&self, entries: &[(u8, u32)]) -> Option<()> {
        let cap = self.capabilities().into_iter().find(|&(id, _)| id == CAP_MSIX)?.1;
        let control = self.read16(cap + 2);
        let table_size = usize::from(control & 0x7FF) + 1;
        if entries.len() > table_size {
            return None;
        }
        let table = self.read32(cap + 4);
        let base = self.map_bar((table & 7) as usize)?;
        // SAFETY: The table lies inside the BAR (the device says so).
        let table = unsafe { base.add((table & !7) as usize) }.cast::<u32>();
        // Mask the whole function while programming the entries.
        self.write16(cap + 2, control | (1 << 15) | (1 << 14));
        for (i, &(v, dest)) in entries.iter().enumerate() {
            let (addr, data) = crate::arch::irq::msi_message(v, dest);
            // SAFETY: Entry `i` < table size; each entry is four dwords.
            unsafe {
                let e = table.add(i * 4);
                e.write_volatile(addr as u32);
                e.add(1).write_volatile((addr >> 32) as u32);
                e.add(2).write_volatile(data);
                e.add(3).write_volatile(0); // Unmasked.
            }
        }
        self.write16(cap + 2, (control | (1 << 15)) & !(1 << 14));
        for &(v, _) in entries {
            crate::arch::irq::set_kind(v, &alloc::format!("PCI-MSI-X {:?}", self.address));
        }
        Some(())
    }

    /// Set up plain MSI with a single message raising `vector` on `dest`
    /// (§6.8.1.3: message control, address, optional upper address, data).
    pub fn enable_msi(&self, vector: u8, dest: u32) -> Option<()> {
        let cap = self.capability(CAP_MSI)?;
        let control = self.read16(cap + 2);
        let (addr, data) = crate::arch::irq::msi_message(vector, dest);
        self.write32(cap + 4, addr as u32);
        let data_off = if control & (1 << 7) != 0 {
            self.write32(cap + 8, (addr >> 32) as u32);
            cap + 12
        } else {
            cap + 8
        };
        self.write16(data_off, data as u16);
        // One message (Multiple Message Enable = 0), enabled.
        self.write16(cap + 2, (control & !(7 << 4)) | 1);
        crate::arch::irq::set_kind(vector, &alloc::format!("PCI-MSI {:?}", self.address));
        Some(())
    }

    /// The function's legacy interrupt (INTx), through the firmware's
    /// `_PRT` (ADR 0079): level-triggered and possibly shared, so `handler`
    /// must check and clear its own device's interrupt. Returns the GSI, or
    /// `None` (no pin, no route, or no vector).
    pub fn enable_intx(&self, name: &str, handler: crate::arch::irq::DeviceHandler) -> Option<u32> {
        let pin = self.read8(0x3D);
        if !(1..=4).contains(&pin) {
            return None;
        }
        let g = crate::drivers::aml::pci_gsi(self.address, pin - 1)?;
        let (vector, new) = crate::arch::irq::share_gsi(g.gsi, name, handler)?;
        let dest = crate::arch::irq::device_irq_target();
        if new && !crate::arch::apic::route_gsi(g.gsi, vector, dest, g.level, g.active_low) {
            return None;
        }
        // The command register's Interrupt Disable bit (bit 10) off.
        let cmd = self.read16(0x04);
        self.write16(0x04, cmd & !(1 << 10));
        Some(g.gsi)
    }

    /// One interrupt for the whole function: MSI-X entry 0, else MSI.
    /// Returns how it is delivered, or `None` (the driver then polls).
    pub fn enable_interrupt(&self, name: &str, handler: crate::arch::irq::DeviceHandler) -> Option<&'static str> {
        let dest = crate::arch::irq::device_irq_target();
        let has_msix = self.capability(CAP_MSIX).is_some();
        let has_msi = self.capability(CAP_MSI).is_some();
        if !has_msix && !has_msi {
            return None;
        }
        let v = crate::arch::irq::alloc_vector(name, handler)?;
        if has_msix && self.enable_msix(&[v], dest).is_some() {
            return Some("MSI-X");
        }
        self.enable_msi(v, dest).map(|_| "MSI")
    }
}

/// The 1 MiB configuration region of each bus, mapped on first use.
struct Ecam {
    base: u64,
    start_bus: u8,
    end_bus: u8,
    buses: BTreeMap<u8, usize>,
}

impl Ecam {
    fn function(&mut self, a: Address) -> *mut u8 {
        let bus = *self
            .buses
            .entry(a.bus)
            .or_insert_with(|| map_mmio(PhysAddr(self.base + (u64::from(a.bus) << 20)), 1 << 20) as usize);
        (bus + ((usize::from(a.device) << 15) | (usize::from(a.function) << 12))) as *mut u8
    }
}

static DEVICES: IrqSpinLock<Vec<Arc<Device>>> = IrqSpinLock::new(Vec::new());
/// Segment 0's ECAM, kept for configuration accesses to any function
/// (AML's PCI_Config regions, ADR 0079).
static ECAM: Once<IrqSpinLock<Ecam>> = Once::new();

// SAFETY: The mapped buses are device registers mapped for the kernel's
// whole life; the map itself is only used under the lock.
unsafe impl Send for Ecam {}

/// Read `width` bits (8, 16 or 32) at `off` of function `a`: through ECAM
/// when there is one, else the ports (below 256; above, all ones).
pub fn config_read(a: Address, off: u16, width: u8) -> u32 {
    let aligned = usize::from(off & !3);
    let dword = match ECAM.get() {
        Some(e) => {
            let f = e.lock().function(a);
            // SAFETY: `f` is the function's 4 KiB of ECAM, mapped uncached;
            // `aligned` is a dword offset below 4096.
            unsafe { core::ptr::read_volatile(f.add(aligned & 0xFFC) as *const u32) }
        }
        None if off < 256 => port_read(a, aligned),
        None => u32::MAX,
    };
    let shift = u32::from(off & 3) * 8;
    match width {
        8 => (dword >> shift) & 0xFF,
        16 => (dword >> shift) & 0xFFFF,
        _ => dword,
    }
}

/// Write `width` bits at `off` of function `a`.
pub fn config_write(a: Address, off: u16, width: u8, v: u32) {
    match ECAM.get() {
        Some(e) => {
            let f = e.lock().function(a);
            let off = usize::from(off) & 0xFFF;
            // SAFETY: As for `config_read`; ECAM takes byte, word and dword
            // writes at their own offsets (PCI Express base spec §7.2.2).
            unsafe {
                match width {
                    8 => core::ptr::write_volatile(f.add(off), v as u8),
                    16 => core::ptr::write_volatile(f.add(off & !1) as *mut u16, v as u16),
                    _ => core::ptr::write_volatile(f.add(off & !3) as *mut u32, v),
                }
            }
        }
        None if off < 256 => {
            let aligned = usize::from(off & !3);
            let shift = u32::from(off & 3) * 8;
            let merged = match width {
                8 => (port_read(a, aligned) & !(0xFF << shift)) | ((v & 0xFF) << shift),
                16 => (port_read(a, aligned) & !(0xFFFF << shift)) | ((v & 0xFFFF) << shift),
                _ => v,
            };
            port_write(a, aligned, merged);
        }
        None => {}
    }
}

/// Every PCI function present: those found at boot, and those plugged in
/// since.
pub fn devices() -> Vec<Arc<Device>> {
    DEVICES.lock().clone()
}

/// Enumerate segment 0 from its MCFG region, or through the configuration
/// ports when there is no MCFG.
pub fn init() {
    let mut found = Vec::new();
    let mut seen = [false; 256];
    match crate::acpi::info().mcfg.iter().find(|e| e.segment == 0) {
        Some(region) => {
            let mut ecam = Ecam {
                base: region.base,
                start_bus: region.start_bus,
                end_bus: region.end_bus,
                buses: BTreeMap::new(),
            };
            let start = region.start_bus;
            scan_bus(&mut Access::Ecam(&mut ecam), start, &mut found, &mut seen);
            ECAM.call_once(|| IrqSpinLock::new(ecam));
        }
        None if port_read(Address { bus: 0, device: 0, function: 0 }, 0) & 0xFFFF != 0xFFFF => {
            log_info!("no MCFG table: reading PCI configuration through I/O ports");
            scan_bus(&mut Access::Ports, 0, &mut found, &mut seen);
        }
        None => log_warn!("no MCFG table and no PCI host bridge on the configuration ports; no PCI devices"),
    }
    for d in &found {
        log_info!("{d:?}");
    }
    *DEVICES.lock() = found.clone();
    for d in &found {
        super::pci_sys::added(d);
    }
}

/// A bridge window's first and last address; `None` when it is closed
/// (limit below base).
type Window = Option<(u64, u64)>;

/// A bridge's windows: memory, then prefetchable memory.
fn windows(b: &Device) -> (Window, Window) {
    let mem_base = u64::from(b.read16(MEMORY_BASE) & 0xFFF0) << 16;
    let mem_limit = (u64::from(b.read16(MEMORY_LIMIT) & 0xFFF0) << 16) | 0xF_FFFF;
    let wide = b.read16(PREF_BASE) & 0xF == 1;
    let upper = |off| if wide { u64::from(b.read32(off)) << 32 } else { 0 };
    let pref_base = (u64::from(b.read16(PREF_BASE) & 0xFFF0) << 16) | upper(PREF_BASE_UPPER);
    let pref_limit = (u64::from(b.read16(PREF_LIMIT) & 0xFFF0) << 16) | 0xF_FFFF | upper(PREF_LIMIT_UPPER);
    let open = |base: u64, limit: u64| (limit > base).then_some((base, limit));
    (open(mem_base, mem_limit), open(pref_base, pref_limit))
}

/// Give function `d`'s memory BARs addresses in `bridge`'s windows
/// (prefetchable BARs in the prefetchable window when it has one, 32-bit
/// BARs below 4 GiB), avoiding what the other functions on its bus use.
/// I/O BARs are left unassigned. Returns whether every memory BAR got one.
fn assign_bars(d: &Device, bridge: &Device, others: &[Arc<Device>]) -> bool {
    let (mem, pref) = windows(bridge);
    let mut used: Vec<(u64, u64)> = others
        .iter()
        .flat_map(|o| o.bars.iter().flatten())
        .filter_map(|b| match *b {
            Bar::Memory { address, size, .. } => Some((address, address + size)),
            Bar::Io { .. } => None,
        })
        .collect();
    let cmd = d.read16(COMMAND);
    d.write16(COMMAND, cmd & !(COMMAND_IO | COMMAND_MEMORY));
    let mut ok = true;
    let mut i = 0;
    while i < 6 {
        let off = BAR0 + 4 * i;
        let orig = d.read32(off);
        if orig & 1 == 1 {
            i += 1;
            continue;
        }
        let is64 = (orig >> 1) & 3 == 2 && i < 5;
        let prefetchable = orig & 8 != 0;
        d.write32(off, u32::MAX);
        let lo = d.read32(off) & !0xF;
        let hi = if is64 {
            d.write32(off + 4, u32::MAX);
            d.read32(off + 4)
        } else {
            u32::MAX
        };
        let mask = u64::from(lo) | (u64::from(hi) << 32);
        if lo == 0 {
            // Not implemented.
            d.write32(off, orig);
            i += if is64 { 2 } else { 1 };
            continue;
        }
        let size = (!mask).wrapping_add(1);
        let window = match (prefetchable, pref, mem) {
            (true, Some(p), _) if is64 || p.1 < 1 << 32 => Some(p),
            (_, _, m) => m,
        };
        let place = window.and_then(|(first, last)| {
            let mut at = first.next_multiple_of(size);
            while at + size - 1 <= last {
                match used.iter().find(|&&(s, e)| at < e && s < at + size) {
                    Some(&(_, e)) => at = e.next_multiple_of(size),
                    None => return Some(at),
                }
            }
            None
        });
        match place {
            Some(at) if is64 || at + size <= 1 << 32 => {
                d.write32(off, at as u32);
                if is64 {
                    d.write32(off + 4, (at >> 32) as u32);
                }
                used.push((at, at + size));
            }
            _ => {
                log_warn!("{:?}: no room for BAR {i} ({size} bytes) behind {:?}", d.address, bridge.address);
                d.write32(off, 0);
                ok = false;
            }
        }
        i += if is64 { 2 } else { 1 };
    }
    d.write16(COMMAND, cmd);
    ok
}

fn config_of(a: Address) -> Config {
    match ECAM.get() {
        Some(e) => Config::Mapped(e.lock().function(a)),
        None => Config::Ports,
    }
}

/// Functions plugged into slot `device` of bus `bus` (after an ACPI
/// device check, say): read, given BARs in the window of the bridge above,
/// and added to the list. Returns them.
pub fn hot_add(bus: u8, device: u8) -> Vec<Arc<Device>> {
    let present = devices();
    let Some(bridge) =
        present.iter().find(|d| d.read8(HEADER_TYPE) & 0x7F == 1 && d.read8(SECONDARY_BUS) == bus).cloned()
    else {
        log_warn!("PCI {bus:02x}:{device:02x}: no bridge leads to this bus; not added");
        return Vec::new();
    };
    let mut added = Vec::new();
    for function in 0..8 {
        let address = Address { bus, device, function };
        if present.iter().any(|d| d.address == address) {
            continue;
        }
        let first = probe(address, config_of(address));
        if first.vendor == 0xFFFF {
            if function == 0 {
                break;
            }
            continue;
        }
        let single = function == 0 && first.read8(HEADER_TYPE) & 0x80 == 0;
        if first.read8(HEADER_TYPE) & 0x7F != 0 {
            log_warn!("{first:?}: a bridge plugged in; not supported");
        } else if assign_bars(&first, &bridge, &present) {
            // Read again, with the addresses it now has.
            let d = Arc::new(probe(address, config_of(address)));
            log_info!("{d:?}: plugged in");
            DEVICES.lock().push(d.clone());
            super::pci_sys::added(&d);
            added.push(d);
        }
        if single {
            break;
        }
    }
    added
}

/// Take the functions of slot `device` on bus `bus` out of the list (they
/// were stopped first): bus mastering and decoding off. Returns them.
pub fn remove_slot(bus: u8, device: u8) -> Vec<Arc<Device>> {
    let gone: Vec<Arc<Device>> = {
        let mut list = DEVICES.lock();
        let (gone, kept) = list.drain(..).partition(|d| d.address.bus == bus && d.address.device == device);
        *list = kept;
        gone
    };
    for d in &gone {
        d.write16(COMMAND, d.read16(COMMAND) & !(COMMAND_BUS_MASTER | COMMAND_MEMORY | COMMAND_IO));
        super::pci_sys::removed(d.address);
        log_info!("{d:?}: removed");
    }
    gone
}

/// How the scan reaches configuration space.
enum Access<'a> {
    Ecam(&'a mut Ecam),
    Ports,
}

impl Access<'_> {
    fn covers(&self, bus: u8) -> bool {
        match self {
            Access::Ecam(e) => (e.start_bus..=e.end_bus).contains(&bus),
            Access::Ports => true,
        }
    }

    fn config(&mut self, a: Address) -> Config {
        match self {
            Access::Ecam(e) => Config::Mapped(e.function(a)),
            Access::Ports => Config::Ports,
        }
    }
}

fn scan_bus(access: &mut Access<'_>, bus: u8, out: &mut Vec<Arc<Device>>, seen: &mut [bool; 256]) {
    if !access.covers(bus) || core::mem::replace(&mut seen[usize::from(bus)], true) {
        return;
    }
    for device in 0..32 {
        for function in 0..8 {
            let address = Address { bus, device, function };
            let config = access.config(address);
            let d = probe(address, config);
            if d.vendor == 0xFFFF {
                if function == 0 {
                    break; // No device here.
                }
                continue;
            }
            let header = d.read8(HEADER_TYPE);
            let bridge_bus = (header & 0x7F == 1).then(|| d.read8(SECONDARY_BUS));
            out.push(Arc::new(d));
            if let Some(b) = bridge_bus {
                scan_bus(access, b, out, seen);
            }
            if function == 0 && header & 0x80 == 0 {
                break; // Single-function device.
            }
        }
    }
}

/// Read a function's header (and size its BARs, if a function is there).
fn probe(address: Address, config: Config) -> Device {
    let mut d = Device {
        address,
        config,
        vendor: 0,
        device: 0,
        class: 0,
        subclass: 0,
        prog_if: 0,
        revision: 0,
        bars: [None; 6],
        mapped: IrqSpinLock::new([0; 6]),
    };
    d.vendor = d.read16(VENDOR_ID);
    if d.vendor == 0xFFFF {
        return d;
    }
    d.device = d.read16(DEVICE_ID);
    let class = d.read32(REVISION);
    d.revision = class as u8;
    d.prog_if = (class >> 8) as u8;
    d.subclass = (class >> 16) as u8;
    d.class = (class >> 24) as u8;
    if d.read8(HEADER_TYPE) & 0x7F == 0 {
        d.bars = size_bars(&d, 6);
    } else if d.read8(HEADER_TYPE) & 0x7F == 1 {
        let two = size_bars(&d, 2);
        d.bars[..2].copy_from_slice(&two[..2]);
    }
    d
}

/// Decode and size the BARs (§6.2.5.1): write all ones, read back the size
/// mask, restore. Decoding is off meanwhile so the probe values never
/// claim addresses.
fn size_bars(d: &Device, count: usize) -> [Option<Bar>; 6] {
    let mut bars = [None; 6];
    let cmd = d.read16(COMMAND);
    d.write16(COMMAND, cmd & !(COMMAND_IO | COMMAND_MEMORY));
    let mut i = 0;
    while i < count {
        let off = BAR0 + 4 * i;
        let orig = d.read32(off);
        d.write32(off, u32::MAX);
        let mask = d.read32(off);
        d.write32(off, orig);
        if orig & 1 == 1 {
            let size = !(mask & !3) as u16 as u32 + 1;
            if mask != 0 && orig & !3 != 0 {
                bars[i] = Some(Bar::Io { port: (orig & !3) as u16, size });
            }
            i += 1;
            continue;
        }
        let is64 = (orig >> 1) & 3 == 2;
        let prefetchable = orig & 8 != 0;
        let (address, size_mask) = if is64 && i + 1 < count {
            let hi_off = off + 4;
            let orig_hi = d.read32(hi_off);
            d.write32(hi_off, u32::MAX);
            let mask_hi = d.read32(hi_off);
            d.write32(hi_off, orig_hi);
            (u64::from(orig & !0xF) | (u64::from(orig_hi) << 32), u64::from(mask & !0xF) | (u64::from(mask_hi) << 32))
        } else {
            (u64::from(orig & !0xF), u64::from(mask & !0xF) | 0xFFFF_FFFF_0000_0000)
        };
        if size_mask != 0 && address != 0 {
            bars[i] = Some(Bar::Memory { address, size: (!size_mask).wrapping_add(1), prefetchable });
        }
        i += if is64 { 2 } else { 1 };
    }
    d.write16(COMMAND, cmd);
    bars
}
