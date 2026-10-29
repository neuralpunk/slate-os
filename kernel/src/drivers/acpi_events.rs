// SPDX-License-Identifier: MIT OR Apache-2.0

//! The firmware's events (ADR 0079): general-purpose events run their
//! `\_GPE` methods, Notify reaches the buttons and the thermal zones, and
//! the thermal zones' temperatures are read (ACPI 6.5 §5.6.4, §5.6.6,
//! chapter 11).
//!
//! The SCI's handler only masks the events that fired and wakes the
//! `acpi` thread, which runs their methods: AML takes the interpreter's
//! mutex and may sleep, which an interrupt handler must not.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use slate_aml::events;
use slate_aml::{NodeId, Value};

use crate::arch::port::Port8;
use crate::sched::wait::WaitQueue;
use crate::sync::IrqSpinLock;
use crate::{log_debug, log_error, log_info, log_warn};

/// A GPE register block: `bytes` status bytes at `port`, then as many
/// enable bytes; its first event is number `base` (the FADT's GPE0 and
/// GPE1 blocks, chapter 4).
#[derive(Clone, Copy)]
struct Block {
    port: u16,
    bytes: u16,
    base: u8,
}

fn blocks() -> impl Iterator<Item = Block> {
    let f = crate::acpi::info().fadt;
    let pairs = f.map_or([(0, 0, 0); 2], |f| [(f.gpe0_block, f.gpe0_len, 0), (f.gpe1_block, f.gpe1_len, f.gpe1_base)]);
    pairs.into_iter().filter(|&(port, len, _)| port != 0 && port <= 0xFFFF && len >= 2).map(|(port, len, base)| Block {
        port: port as u16,
        bytes: u16::from(len / 2),
        base,
    })
}

/// Event `n`'s status port, enable port and bit.
fn locate(n: u8) -> Option<(u16, u16, u8)> {
    blocks().find_map(|b| {
        let i = n.checked_sub(b.base)?;
        let byte = u16::from(i / 8);
        (byte < b.bytes).then(|| (b.port + byte, b.port + b.bytes + byte, 1 << (i % 8)))
    })
}

/// Read-modify-write of the enable registers, from the SCI and the thread.
static REGS: IrqSpinLock<()> = IrqSpinLock::new(());
/// Events that fired and wait for their method, one bit each.
static FIRED: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static WORK: AtomicBool = AtomicBool::new(false);
static WORKER: WaitQueue = WaitQueue::new();
static STARTED: AtomicBool = AtomicBool::new(false);
/// The events turned on (for the test).
static ENABLED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
/// Notify(object, value) calls the interpreter made, for the thread.
static NOTIFIED: IrqSpinLock<Vec<(String, u64)>> = IrqSpinLock::new(Vec::new());

fn wake() {
    WORK.store(true, Ordering::Release);
    WORKER.wake_all();
}

fn set_enabled(n: u8, on: bool) {
    let Some((_, enable, bit)) = locate(n) else { return };
    let _g = REGS.lock();
    // SAFETY: A GPE enable register of a block the FADT names; only this
    // event's bit changes.
    unsafe {
        let p = Port8::new(enable);
        let v = p.read();
        p.write(if on { v | bit } else { v & !bit });
    }
}

fn clear_status(n: u8) {
    let Some((status, _, bit)) = locate(n) else { return };
    // SAFETY: A GPE status register; writing a 1 clears that bit only.
    unsafe { Port8::new(status).write(bit) };
}

/// From the SCI: mask the enabled events that fired and leave them to
/// the thread. Returns whether there were any.
pub fn sci() -> bool {
    if !STARTED.load(Ordering::Acquire) {
        return false;
    }
    let mut any = false;
    let _g = REGS.lock();
    for b in blocks() {
        for i in 0..b.bytes {
            // SAFETY: The status and enable registers of a GPE block the
            // FADT names; fired events are only masked here.
            let fired = unsafe {
                let en = Port8::new(b.port + b.bytes + i);
                let v = en.read();
                let fired = Port8::new(b.port + i).read() & v;
                if fired != 0 {
                    en.write(v & !fired);
                }
                fired
            };
            for bit in (0..8).filter(|k| fired & (1 << k) != 0) {
                let n = usize::from(b.base) + usize::from(i) * 8 + bit;
                if n < 256 {
                    FIRED[n / 64].fetch_or(1 << (n % 64), Ordering::AcqRel);
                }
            }
            any |= fired != 0;
        }
    }
    if any {
        wake();
    }
    any
}

/// A Notify the interpreter made (`KernelHost::notify`).
pub fn notified(path: &str, value: u64) {
    NOTIFIED.lock().push((path.into(), value));
    wake();
}

struct Gpe {
    handler: events::GpeHandler,
    path: String,
    /// Runs in the current second, to catch an event that never clears.
    runs: u32,
    second: u64,
}

/// More runs than this in a second and an event is left off: its method
/// does not clear its source (a level event Slate cannot service yet).
const STORM: u32 = 200;

struct Zone {
    node: NodeId,
    path: String,
    index: usize,
    critical: Option<i64>,
    hot: Option<i64>,
    period_ms: u64,
    next_ms: u64,
    shut_down: bool,
}

/// Thermal zones without `_TZP` are read this often (ms).
const DEFAULT_PERIOD_MS: u64 = 10_000;

fn now_ms() -> u64 {
    crate::time::monotonic_ns() / 1_000_000
}

/// Turn on the events that have a handler and are not wake events, find
/// the thermal zones and start the `acpi` thread. After the SCI is set up
/// (`arch::power::init_power_button`).
pub fn init() {
    if !crate::drivers::aml::available() {
        return;
    }
    let found = crate::drivers::aml::with(|aml| {
        let wake = events::wake_gpes(aml);
        let handlers: Vec<(events::GpeHandler, String)> =
            events::gpe_handlers(aml).into_iter().map(|h| (h, aml.path(h.method))).collect();
        let zones: Vec<(NodeId, String)> = events::thermal_zones(aml).into_iter().map(|z| (z, aml.path(z))).collect();
        (wake, handlers, zones)
    });
    let Some((wake, handlers, zones)) = found else { return };
    let mut gpes = Vec::new();
    let mut names = String::new();
    for (h, path) in handlers {
        if wake.contains(&h.number) || locate(h.number).is_none() {
            continue;
        }
        names.push_str(if names.is_empty() { "" } else { " " });
        names.push_str(path.rsplit('.').next().unwrap_or(""));
        gpes.push(Gpe { handler: h, path, runs: 0, second: 0 });
    }
    let mut zones: Vec<Zone> = zones
        .into_iter()
        .enumerate()
        .map(|(index, (node, path))| Zone {
            node,
            path,
            index,
            critical: None,
            hot: None,
            period_ms: DEFAULT_PERIOD_MS,
            next_ms: 0,
            shut_down: false,
        })
        .collect();
    for z in &mut zones {
        trips(z);
    }
    log_info!(
        "ACPI events: {} GPE handlers ({}), {} wake events left off, {} thermal zones",
        gpes.len(),
        if names.is_empty() { "none" } else { &names },
        wake.len(),
        zones.len()
    );
    ENABLED.store(gpes.len(), Ordering::Relaxed);
    STARTED.store(true, Ordering::Release);
    for g in &gpes {
        clear_status(g.handler.number);
        set_enabled(g.handler.number, true);
    }
    crate::sched::spawn("acpi", move || worker(gpes, zones));
}

fn worker(mut gpes: Vec<Gpe>, mut zones: Vec<Zone>) {
    loop {
        WORK.store(false, Ordering::Release);
        for (k, word) in FIRED.iter().enumerate() {
            let mut bits = word.swap(0, Ordering::AcqRel);
            while bits != 0 {
                let n = (k * 64 + bits.trailing_zeros() as usize) as u8;
                bits &= bits - 1;
                if let Some(g) = gpes.iter_mut().find(|g| g.handler.number == n) {
                    run(g);
                }
            }
        }
        let notes = core::mem::take(&mut *NOTIFIED.lock());
        for (path, value) in notes {
            notification(&path, value, &mut zones);
        }
        let now = now_ms();
        for z in zones.iter_mut().filter(|z| z.next_ms <= now) {
            z.next_ms = now + z.period_ms;
            temperature(z);
        }
        match zones.iter().map(|z| z.next_ms).min() {
            Some(next) => {
                let deadline = next.saturating_mul(1_000_000);
                WORKER.wait_until_deadline(|| WORK.load(Ordering::Acquire), deadline);
            }
            None => WORKER.wait_until(|| WORK.load(Ordering::Acquire)),
        }
    }
}

/// Run an event's method (§5.6.4.1: an edge event's status is cleared
/// before its `_Exx` runs, a level event's after its `_Lxx`), then turn
/// it back on unless the method failed or it keeps firing.
fn run(g: &mut Gpe) {
    let n = g.handler.number;
    if g.handler.edge {
        clear_status(n);
    }
    let method = g.handler.method;
    let r = crate::drivers::aml::with(|aml| aml.evaluate_node(method, Vec::new()).map(|_| ()));
    if !g.handler.edge {
        clear_status(n);
    }
    if let Some(Err(e)) = r {
        log_warn!("ACPI: {}: {e:?}; event {n:#04x} left off", g.path);
        return;
    }
    let second = now_ms() / 1000;
    if second != g.second {
        g.second = second;
        g.runs = 0;
    }
    g.runs += 1;
    if g.runs > STORM {
        log_warn!("ACPI: {} ran {} times in a second; event {n:#04x} left off", g.path, g.runs);
        return;
    }
    set_enabled(n, true);
}

#[derive(Clone, Copy, Debug)]
enum Button {
    Power,
    Sleep,
    Lid(Option<bool>),
}

/// What a Notify means (§5.6.6: 0x80 on a button device is a press, on a
/// thermal zone a temperature change; 0x81 on a zone, new trip points).
fn notification(path: &str, value: u64, zones: &mut [Zone]) {
    if let Some(z) = zones.iter_mut().find(|z| z.path == path) {
        if value == 0x81 {
            trips(z);
        }
        temperature(z);
        return;
    }
    // PCI hot-plug (§5.6.6): a device check (or bus check) on a slot's
    // object, or an eject request.
    if matches!(value, 0 | 1 | 3)
        && let Some((bus, slot)) = crate::drivers::aml::pci_slot(path)
    {
        if value == 3 {
            log_info!("ACPI: {path}: eject request (PCI {bus:02x}:{slot:02x})");
            if crate::drivers::hot_remove(bus, slot) && !crate::drivers::aml::eject(path) {
                log_warn!("ACPI: {path}._EJ0 failed");
            }
        } else {
            log_info!("ACPI: {path}: {} check (PCI {bus:02x}:{slot:02x})", ["bus", "device"][value as usize]);
            crate::drivers::hot_add(bus, slot);
        }
        return;
    }
    let button = crate::drivers::aml::with(|aml| {
        let dev = aml.find(path)?;
        if events::has_id(aml, dev, b"PNP0C0C") {
            Some(Button::Power)
        } else if events::has_id(aml, dev, b"PNP0C0E") {
            Some(Button::Sleep)
        } else if events::has_id(aml, dev, b"PNP0C0D") {
            let lid = aml.evaluate_child(dev, "_LID", Vec::new()).ok().flatten().and_then(|v| v.as_int());
            Some(Button::Lid(lid.map(|v| v != 0)))
        } else {
            None
        }
    })
    .flatten();
    match (button, value) {
        (Some(Button::Power), 0x80) => crate::arch::power::power_button_pressed(),
        (Some(Button::Sleep), 0x80) => log_info!("sleep button pressed: no sleep states yet (M29)"),
        (Some(Button::Lid(open)), 0x80) => {
            log_info!("lid {}", open.map_or("changed", |o| if o { "opened" } else { "closed" }))
        }
        // Bus and device checks (§5.6.6): something was plugged in or
        // taken out under that object.
        (_, 0 | 1) => {
            log_info!("ACPI: {path}: {} check; hot-plug is not handled yet", ["bus", "device"][value as usize])
        }
        _ => log_debug!("ACPI: Notify({path}, {value:#x})"),
    }
}

fn int(aml: &mut slate_aml::Interpreter<crate::drivers::aml::KernelHost>, node: NodeId, name: &str) -> Option<u64> {
    aml.evaluate_child(node, name, Vec::new()).ok().flatten().as_ref().and_then(Value::as_int)
}

/// A zone's critical and hot temperatures and polling period (`_CRT`,
/// `_HOT`, `_TZP` in tenths of a second; chapter 11).
fn trips(z: &mut Zone) {
    let node = z.node;
    let Some((crt, hot, tzp)) =
        crate::drivers::aml::with(|aml| (int(aml, node, "_CRT"), int(aml, node, "_HOT"), int(aml, node, "_TZP")))
    else {
        return;
    };
    z.critical = crt.filter(|&t| t > 2732).map(events::millicelsius);
    z.hot = hot.filter(|&t| t > 2732).map(events::millicelsius);
    z.period_ms = match tzp {
        Some(t) if t > 0 => (t * 100).max(1000),
        _ => DEFAULT_PERIOD_MS,
    };
}

/// Read a zone's `_TMP` into /sys/class/thermal (thermal zones' `temp`,
/// in thousandths of a degree Celsius, as sysfs-class-thermal in the Linux
/// ABI documentation gives it); at its critical temperature, shut down
/// (chapter 11: the OS must).
fn temperature(z: &mut Zone) {
    let node = z.node;
    let t = crate::drivers::aml::with(|aml| {
        aml.evaluate_child(node, "_TMP", Vec::new()).map(|v| v.and_then(|v| v.as_int()))
    });
    let t = match t {
        Some(Ok(Some(t))) => events::millicelsius(t),
        Some(Err(e)) => {
            log_warn!("ACPI: {}._TMP: {e:?}; not read again", z.path);
            z.period_ms = u64::MAX / 2;
            z.next_ms = u64::MAX / 2;
            return;
        }
        _ => return,
    };
    // Every entry on every reading: /sys is mounted after the zones are
    // found.
    let dir = alloc::format!("class/thermal/thermal_zone{}", z.index);
    crate::fs::sysfs_put(&alloc::format!("{dir}/type"), "acpitz\n");
    // Numbered as Linux shows them (observed on the reference PC): critical, then hot.
    let trips = [("critical", z.critical), ("hot", z.hot)];
    for (k, (kind, c)) in trips.iter().filter_map(|(k, c)| Some((k, (*c)?))).enumerate() {
        crate::fs::sysfs_put(&alloc::format!("{dir}/trip_point_{k}_type"), &alloc::format!("{kind}\n"));
        crate::fs::sysfs_put(&alloc::format!("{dir}/trip_point_{k}_temp"), &alloc::format!("{c}\n"));
    }
    crate::fs::sysfs_put(&alloc::format!("{dir}/temp"), &alloc::format!("{t}\n"));
    if let Some(c) = z.critical
        && t >= c
        && !z.shut_down
    {
        z.shut_down = true;
        log_error!("thermal zone {}: {} °C, critical at {} °C: shutting down", z.path, t / 1000, c / 1000);
        crate::arch::power::shut_down();
    }
}

pub const TESTS: &[crate::ktest::Test] = &[crate::ktest::Test { name: "acpi::events_started", run: test_started }];

/// QEMU's tables have edge events for PCI and CPU hot-plug (`_E01`,
/// `_E02`): they are on, with the thread running; the NIC scenario plugs
/// a CPU in.
fn test_started() -> Result<(), &'static str> {
    if !crate::drivers::aml::available() {
        return Err("no AML");
    }
    if !STARTED.load(Ordering::Acquire) {
        return Err("the acpi thread did not start");
    }
    let Some((_, enable, bit)) = locate(2) else { return Err("no GPE block") };
    // SAFETY: Reading a GPE enable register changes nothing.
    let on = unsafe { Port8::new(enable).read() } & bit != 0;
    if ENABLED.load(Ordering::Relaxed) == 0 || !on {
        return Err("event 2 (_E02) is not enabled");
    }
    Ok(())
}
