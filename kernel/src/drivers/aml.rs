// SPDX-License-Identifier: MIT OR Apache-2.0

//! The firmware's AML in the kernel (ADR 0079): the DSDT and SSDTs loaded
//! into `slate-aml` at boot, with a host that reaches system memory
//! (RAM through the direct map, anything else mapped uncached), I/O ports
//! and PCI configuration space. The interpreter sits behind a sleeping
//! mutex: AML may Sleep, and nothing calls it from interrupt context.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use slate_aml::{Address, Error, Host, Interpreter, Value};
use slate_sync::Once;

use crate::arch::port::{Port8, Port16, Port32};
use crate::mm::PhysAddr;
use crate::sched::wait::Mutex;
use crate::{log_debug, log_info, log_warn};

const PAGE: u64 = 4096;

/// What AML reaches the machine through.
pub struct KernelHost {
    /// Pages of device memory mapped so far (physical page to virtual).
    mapped: BTreeMap<u64, usize>,
}

impl KernelHost {
    fn new() -> KernelHost {
        KernelHost { mapped: BTreeMap::new() }
    }

    /// A pointer to `width` bits at physical `addr`, within one page.
    fn pointer(&mut self, addr: u64, width: u8) -> Result<*mut u8, Error> {
        let bytes = u64::from(width / 8);
        if addr % bytes != 0 || addr / PAGE != (addr + bytes - 1) / PAGE {
            return Err(Error::Host("unaligned memory access"));
        }
        let page = addr & !(PAGE - 1);
        let ram = crate::acpi::info().ram.iter().any(|&(b, l)| (b..b + l).contains(&addr));
        if ram {
            crate::arch::paging::ensure_direct_mapped(page, PAGE);
            return Ok(PhysAddr(addr).to_virt());
        }
        let v = *self.mapped.entry(page).or_insert_with(|| crate::mm::vmap::map_mmio(PhysAddr(page), PAGE) as usize);
        Ok((v + (addr - page) as usize) as *mut u8)
    }
}

impl Host for KernelHost {
    fn read(&mut self, at: Address, width: u8) -> Result<u64, Error> {
        Ok(match at {
            Address::Memory(a) => {
                let p = self.pointer(a, width)?;
                // SAFETY: `p` maps `width` bits at the physical address the
                // firmware's AML names, aligned and within one page.
                unsafe {
                    match width {
                        8 => u64::from(core::ptr::read_volatile(p)),
                        16 => u64::from(core::ptr::read_volatile(p as *const u16)),
                        32 => u64::from(core::ptr::read_volatile(p as *const u32)),
                        _ => core::ptr::read_volatile(p as *const u64),
                    }
                }
            }
            // SAFETY: The I/O port the firmware's AML names (its own
            // chipset registers).
            Address::Io(port) => unsafe {
                match width {
                    8 => u64::from(Port8::new(port).read()),
                    16 => u64::from(Port16::new(port).read()),
                    32 => u64::from(Port32::new(port).read()),
                    _ => u64::from(Port32::new(port).read()) | (u64::from(Port32::new(port + 4).read()) << 32),
                }
            },
            Address::Pci { segment: 0, bus, device, function, offset } => {
                let a = super::pci::Address { bus, device, function };
                match width {
                    64 => {
                        u64::from(super::pci::config_read(a, offset, 32))
                            | (u64::from(super::pci::config_read(a, offset + 4, 32)) << 32)
                    }
                    w => u64::from(super::pci::config_read(a, offset, w)),
                }
            }
            Address::Pci { .. } => return Err(Error::Host("PCI segment other than 0")),
            Address::Other(..) => return Err(Error::Host("address space not handled")),
        })
    }

    fn write(&mut self, at: Address, width: u8, value: u64) -> Result<(), Error> {
        match at {
            Address::Memory(a) => {
                let p = self.pointer(a, width)?;
                // SAFETY: As for `read`.
                unsafe {
                    match width {
                        8 => core::ptr::write_volatile(p, value as u8),
                        16 => core::ptr::write_volatile(p as *mut u16, value as u16),
                        32 => core::ptr::write_volatile(p as *mut u32, value as u32),
                        _ => core::ptr::write_volatile(p as *mut u64, value),
                    }
                }
            }
            // SAFETY: As for `read`.
            Address::Io(port) => unsafe {
                match width {
                    8 => Port8::new(port).write(value as u8),
                    16 => Port16::new(port).write(value as u16),
                    32 => Port32::new(port).write(value as u32),
                    _ => {
                        Port32::new(port).write(value as u32);
                        Port32::new(port + 4).write((value >> 32) as u32);
                    }
                }
            },
            Address::Pci { segment: 0, bus, device, function, offset } => {
                let a = super::pci::Address { bus, device, function };
                match width {
                    64 => {
                        super::pci::config_write(a, offset, 32, value as u32);
                        super::pci::config_write(a, offset + 4, 32, (value >> 32) as u32);
                    }
                    w => super::pci::config_write(a, offset, w, value as u32),
                }
            }
            Address::Pci { .. } => return Err(Error::Host("PCI segment other than 0")),
            Address::Other(..) => return Err(Error::Host("address space not handled")),
        }
        Ok(())
    }

    fn stall(&mut self, us: u64) {
        // Stall is a busy wait of at most 100 us (§19.6.129).
        let end = crate::time::monotonic_ns() + us.min(100) * 1000;
        while crate::time::monotonic_ns() < end {
            core::hint::spin_loop();
        }
    }

    fn sleep(&mut self, ms: u64) {
        crate::time::sleep_ns(ms.saturating_mul(1_000_000));
    }

    fn timer(&mut self) -> u64 {
        crate::time::monotonic_ns() / 100
    }

    fn notify(&mut self, path: &str, value: u64) {
        super::acpi_events::notified(path, value);
    }

    fn debug(&mut self, text: &str) {
        log_debug!("AML debug: {text}");
    }

    fn find_table(&mut self, sig: &[u8], oem: &[u8], table: &[u8]) -> Option<(u64, u64)> {
        let pad = |b: &[u8], n: usize| {
            let mut v: Vec<u8> = b.iter().copied().take_while(|&c| c != 0).collect();
            v.resize(n, b' ');
            v
        };
        let (sig, oem, table) = (pad(sig, 4), pad(oem, 6), pad(table, 8));
        let trim = |b: &[u8]| -> Vec<u8> { b.iter().map(|&c| if c == 0 { b' ' } else { c }).collect() };
        crate::acpi::info()
            .tables
            .iter()
            .find(|t| t.signature[..] == sig[..] && trim(&t.oem) == oem && trim(&t.oem_table) == table)
            .map(|t| (t.phys, t.bytes.len() as u64))
    }
}

/// The interpreter, which holds `Rc`s (AML's shared buffers and packages)
/// and so is not `Send` by itself.
struct Shared(Interpreter<KernelHost>);

// SAFETY: The interpreter is only reached under `AML`'s mutex, and `with`
// lets only `Send` results out, so none of its `Rc`s is ever touched by
// two threads at once or outlives the lock on another thread.
unsafe impl Send for Shared {}

static AML: Once<Mutex<Shared>> = Once::new();

/// Load the DSDT and the SSDTs (in the root table's order), tell the
/// firmware Slate uses the APIC (`\_PIC(1)`, ACPI 6.5 §5.8.1), and run the
/// devices' initialization (`_INI`, `_REG`). Needs PCI (for PCI_Config
/// regions) and the scheduler (AML may Sleep).
pub fn init() {
    let started = crate::time::monotonic_ns();
    let mut aml = Interpreter::new(KernelHost::new());
    let info = crate::acpi::info();
    let dsdt = info.tables.iter().filter(|t| &t.signature == b"DSDT");
    let ssdts = info.tables.iter().filter(|t| &t.signature == b"SSDT");
    let mut loaded = 0;
    for t in dsdt.chain(ssdts) {
        match aml.load(t.bytes) {
            Ok(()) => loaded += 1,
            Err(e) => log_warn!("AML: {}: {e:?}", String::from_utf8_lossy(&t.oem_table)),
        }
    }
    if loaded == 0 {
        return;
    }
    if aml.find("\\_PIC").is_some()
        && let Err(e) = aml.evaluate("\\_PIC", alloc::vec![Value::Integer(1)])
    {
        log_warn!("AML: \\_PIC(1): {e:?}");
    }
    let ini = aml.initialize();
    let ms = (crate::time::monotonic_ns() - started) / 1_000_000;
    log_info!(
        "AML: {} objects from {loaded} tables, {ini} _INI methods, {} problems, {ms} ms",
        aml.len(),
        aml.problems().len()
    );
    for p in aml.problems().iter().take(8) {
        log_warn!("AML: table {} at {:#x} in {}: {:?}", p.table, p.offset, p.scope, p.error);
    }
    AML.call_once(|| Mutex::new(Shared(aml)));
}

/// Whether the tables were loaded.
pub fn available() -> bool {
    AML.get().is_some()
}

/// Run `f` with the interpreter, if there is one. Only `Send` results
/// leave it (no AML value does).
pub fn with<T: Send>(f: impl FnOnce(&mut Interpreter<KernelHost>) -> T) -> Option<T> {
    let mut g = AML.get()?.lock();
    Some(f(&mut g.0))
}

/// `\_S5`'s sleep types (SLP_TYPa, SLP_TYPb; §7.4.2).
pub fn s5() -> Option<(u8, u8)> {
    with(|aml| {
        let Ok(Value::Package(p)) = aml.evaluate("\\_S5", Vec::new()) else { return None };
        let p = p.borrow();
        let a = p.first()?.as_int()?;
        let b = p.get(1).and_then(Value::as_int).unwrap_or(a);
        Some((a as u8, b as u8))
    })
    .flatten()
}

/// `\_PTS(state)` (§7.4.1), before entering a sleep state (5: soft off).
pub fn prepare_to_sleep(state: u64) {
    with(|aml| {
        if aml.find("\\_PTS").is_some()
            && let Err(e) = aml.evaluate("\\_PTS", alloc::vec![Value::Integer(state)])
        {
            log_warn!("AML: \\_PTS({state}): {e:?}");
        }
    });
}

pub const TESTS: &[crate::ktest::Test] = &[
    crate::ktest::Test { name: "acpi::aml_loaded", run: test_loaded },
    crate::ktest::Test { name: "acpi::aml_s5_and_prt", run: test_s5_and_prt },
];

/// QEMU's tables load without a problem and hold the host bridge.
fn test_loaded() -> Result<(), &'static str> {
    use crate::ktest::ensure;
    ensure(available(), "the AML tables were not loaded")?;
    let (objects, problems, bridge) =
        with(|a| (a.len(), a.problems().len(), a.find("\\_SB.PCI0").is_some())).ok_or("no interpreter")?;
    ensure(objects > 50, "too few AML objects")?;
    ensure(problems == 0, "AML problems while loading")?;
    ensure(bridge, "no \\_SB.PCI0")
}

/// `\_S5` from AML agrees with the old pattern match, and the host
/// bridge's `_PRT` gives routing entries (APIC mode, after `\_PIC(1)`).
fn test_s5_and_prt() -> Result<(), &'static str> {
    use crate::ktest::ensure;
    ensure(s5().is_some() && s5() == crate::acpi::info().s5, "\\_S5 differs from the DSDT's pattern")?;
    let entries = with(|a| match a.evaluate("\\_SB.PCI0._PRT", Vec::new()) {
        Ok(Value::Package(p)) => p.borrow().len(),
        _ => 0,
    })
    .ok_or("no interpreter")?;
    ensure(entries >= 4, "\\_SB.PCI0._PRT gave no routing entries")
}

// --- Legacy PCI interrupts (§6.2.13, _PRT) -----------------------------------

/// Where a legacy PCI interrupt arrives, and how it is signalled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gsi {
    pub gsi: u32,
    pub level: bool,
    pub active_low: bool,
}

/// The GSI that INTx pin `pin` (0: INTA) of the function at `a` raises:
/// the `_PRT` of its bus (the host bridge's, or a bridge's), else the
/// bridge's swizzle up to one that has a `_PRT` (PCI-to-PCI Bridge
/// Architecture 1.2 §9.1: pin + device, modulo 4).
pub fn pci_gsi(a: super::pci::Address, pin: u8) -> Option<Gsi> {
    with(|aml| route(aml, a.bus, a.device, pin, 0)).flatten()
}

fn route(aml: &mut Interpreter<KernelHost>, bus: u8, device: u8, pin: u8, depth: u32) -> Option<Gsi> {
    if depth > 8 {
        return None;
    }
    if let Some(node) = bus_node(aml, bus, depth)
        && aml.child(node, "_PRT").is_some()
    {
        return prt_entry(aml, node, device, pin);
    }
    let bridge = bridge_to(bus)?;
    route(aml, bridge.bus, bridge.device, (pin + device) % 4, depth + 1)
}

// --- PCI hot-plug (§5.6.6 Notify, §6.1.1 _ADR, §6.3.3 _EJx) --------------

/// The PCI bus and slot an ACPI device object stands for (its `_ADR`, on
/// the bus below its parent), for a hot-plug Notify.
pub fn pci_slot(path: &str) -> Option<(u8, u8)> {
    with(|aml| {
        let node = aml.find(path)?;
        let adr = int(aml, node, "_ADR")?;
        let bus = bus_below(aml, aml.parent(node)?, 0)?;
        Some((bus, (adr >> 16) as u8))
    })
    .flatten()
}

/// The PCI bus below an ACPI object: a host bridge's `_BBN` (0 without
/// one), or the secondary bus of the bridge whose `_ADR` it has.
fn bus_below(aml: &mut Interpreter<KernelHost>, node: slate_aml::NodeId, depth: u32) -> Option<u8> {
    if depth > 8 {
        return None;
    }
    if host_bridge(aml, node) {
        return Some(int(aml, node, "_BBN").unwrap_or(0) as u8);
    }
    let adr = int(aml, node, "_ADR")?;
    let bus = bus_below(aml, aml.parent(node)?, depth + 1)?;
    let a = super::pci::Address { bus, device: (adr >> 16) as u8, function: (adr & 0xFFFF) as u8 };
    (super::pci::config_read(a, 0x0E, 8) & 0x7F == 1).then(|| super::pci::config_read(a, 0x19, 8) as u8)
}

/// `_EJ0(1)` on the object at `path` (§6.3.3): the firmware takes the
/// device out. Returns whether it ran.
pub fn eject(path: &str) -> bool {
    with(|aml| {
        let node = aml.find(path)?;
        aml.evaluate_child(node, "_EJ0", alloc::vec![Value::Integer(1)]).ok().flatten().map(|_| ())
    })
    .flatten()
    .is_some()
}

/// The address of the PCI bridge whose secondary bus is `bus`.
fn bridge_to(bus: u8) -> Option<super::pci::Address> {
    super::pci::devices().iter().find(|d| d.read8(0x0E) & 0x7F == 1 && d.read8(0x19) == bus).map(|d| d.address)
}

/// The AML device of PCI bus `bus`: the host bridge (PNP0A03/PNP0A08) with
/// that `_BBN`, else the device under the upstream bus's node whose `_ADR`
/// is the bridge's.
fn bus_node(aml: &mut Interpreter<KernelHost>, bus: u8, depth: u32) -> Option<slate_aml::NodeId> {
    if depth > 8 {
        return None;
    }
    match bridge_to(bus) {
        None => {
            let sb = aml.find("\\_SB_")?;
            let roots: Vec<_> = aml.children(sb).into_iter().filter(|&d| host_bridge(aml, d)).collect();
            roots.into_iter().find(|&d| int(aml, d, "_BBN").unwrap_or(0) == u64::from(bus))
        }
        Some(b) => {
            let parent = bus_node(aml, b.bus, depth + 1)?;
            let adr = (u64::from(b.device) << 16) | u64::from(b.function);
            aml.children(parent).into_iter().find(|&d| int(aml, d, "_ADR") == Some(adr))
        }
    }
}

fn int(aml: &mut Interpreter<KernelHost>, node: slate_aml::NodeId, name: &str) -> Option<u64> {
    aml.evaluate_child(node, name, Vec::new()).ok().flatten()?.as_int()
}

fn host_bridge(aml: &mut Interpreter<KernelHost>, node: slate_aml::NodeId) -> bool {
    slate_aml::events::has_id(aml, node, b"PNP0A03") || slate_aml::events::has_id(aml, node, b"PNP0A08")
}

/// The `_PRT` entry for `device` and `pin` under `node`: a GSI itself
/// (source 0), or an interrupt link device's.
fn prt_entry(aml: &mut Interpreter<KernelHost>, node: slate_aml::NodeId, device: u8, pin: u8) -> Option<Gsi> {
    let Ok(Some(Value::Package(prt))) = aml.evaluate_child(node, "_PRT", Vec::new()) else { return None };
    let entries = prt.borrow().clone();
    for e in entries {
        let Value::Package(e) = e else { continue };
        let e = e.borrow().clone();
        let (Some(addr), Some(p)) = (e.first().and_then(Value::as_int), e.get(1).and_then(Value::as_int)) else {
            continue;
        };
        if (addr >> 16) & 0xFFFF != u64::from(device) || p != u64::from(pin) {
            continue;
        }
        let index = e.get(3).and_then(Value::as_int).unwrap_or(0);
        return match e.get(2) {
            Some(Value::Integer(0)) | None => Some(Gsi { gsi: index as u32, level: true, active_low: true }),
            Some(Value::Node(link)) => link_gsi(aml, *link, index as usize),
            Some(Value::String(s)) => {
                let path = alloc::string::String::from_utf8_lossy(&s.borrow()).into_owned();
                let link = aml.find(&path)?;
                link_gsi(aml, link, index as usize)
            }
            _ => None,
        };
    }
    None
}

/// An interrupt link device's (PNP0C0F) current interrupt: `_CRS`, or, if
/// it has none set, the first of `_PRS` set with `_SRS` (§6.2.16).
fn link_gsi(aml: &mut Interpreter<KernelHost>, link: slate_aml::NodeId, index: usize) -> Option<Gsi> {
    let current = |aml: &mut Interpreter<KernelHost>| match aml.evaluate_child(link, "_CRS", Vec::new()) {
        Ok(Some(Value::Buffer(b))) => slate_aml::resource::interrupts(&b.borrow())
            .into_iter()
            .map(|i| Gsi { gsi: i.number, level: i.level, active_low: i.active_low })
            .collect(),
        _ => Vec::new(),
    };
    let mut irqs = current(aml);
    if irqs.iter().all(|g| g.gsi == 0) {
        if let Ok(Some(Value::Buffer(b))) = aml.evaluate_child(link, "_PRS", Vec::new()) {
            let first = slate_aml::resource::first_interrupt(&b.borrow());
            if let Some(mut d) = first {
                d.extend_from_slice(&[0x79, 0]);
                let _ = aml.evaluate_child(link, "_SRS", alloc::vec![Value::buffer(d)]);
            }
        }
        irqs = current(aml);
    }
    irqs.get(index).or(irqs.first()).copied().filter(|g| g.gsi != 0)
}
