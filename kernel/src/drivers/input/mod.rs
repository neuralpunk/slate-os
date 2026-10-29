// SPDX-License-Identifier: MIT OR Apache-2.0

//! Input devices as evdev (ADR 0033): each keyboard, mouse or tablet is a
//! `/dev/input/eventN` whose reads give `struct input_event`s and whose
//! `EVIOCG*` queries describe it, as libevdev and libinput expect.
//!
//! Sources (ADR 0033): key codes from xkeyboard-config 2.43's
//! `keycodes/evdev` (MIT; each entry is the evdev code plus 8); event
//! types and codes, ioctl numbers and the `input_event`, `input_id` and
//! `input_absinfo` layouts from the UAPI `linux/input.h` and
//! `input-event-codes.h`, used only as a table of numbers; behaviour from
//! the kernel's input documentation (input.rst, event-codes.rst).

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::abi::linux::errno::*;
use crate::arch::uaccess::{copy_to_user, read_user, write_user};
use crate::fs::vfs::{self, Metadata, Result};
use crate::fs::{CharNode, File, O_NONBLOCK, POLLERR, POLLHUP, POLLIN, SysEntry};

pub mod hid;
pub mod user;
use crate::sched::wait::WaitQueue;
use crate::sync::IrqSpinLock;

/// Input character devices (devices.txt: major 13, event devices from
/// minor 64).
pub const INPUT_MAJOR: u32 = 13;
const EVENT_MINOR_BASE: u32 = 64;

// Event types and codes (input-event-codes.h).
pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;
pub const EV_LED: u16 = 0x11;
pub const EV_REP: u16 = 0x14;
pub const LED_NUML: u16 = 0x00;
pub const LED_CAPSL: u16 = 0x01;
pub const LED_SCROLLL: u16 = 0x02;
/// The first button code: repeat is for keys below it.
const BTN_MISC: u16 = 0x100;
const EV_MAX: u16 = 0x1f;
pub const SYN_REPORT: u16 = 0;
const SYN_DROPPED: u16 = 3;
pub const BTN_LEFT: u16 = 0x110;
pub const BTN_RIGHT: u16 = 0x111;
pub const BTN_MIDDLE: u16 = 0x112;
pub const BTN_SIDE: u16 = 0x113;
pub const BTN_EXTRA: u16 = 0x114;
const KEY_MAX: u16 = 0x2ff;
pub const REL_X: u16 = 0x00;
pub const REL_Y: u16 = 0x01;
pub const REL_HWHEEL: u16 = 0x06;
pub const REL_WHEEL: u16 = 0x08;
pub const ABS_X: u16 = 0x00;
pub const ABS_Y: u16 = 0x01;
const REL_MAX: u16 = 0x0f;
const ABS_MAX: u16 = 0x3f;
const LED_MAX: u16 = 0x0f;
pub const INPUT_PROP_POINTER: u32 = 0x00;
// Bus types (input.h).
pub const BUS_USB: u16 = 0x03;
pub const BUS_BLUETOOTH: u16 = 0x05;
pub const BUS_I8042: u16 = 0x11;
/// EV_VERSION (input.h).
const EV_VERSION: i32 = 0x010001;
/// Clocks for EVIOCSCLOCKID (clock_gettime(2) ids).
const CLOCK_REALTIME: u32 = 0;
const CLOCK_MONOTONIC: u32 = 1;
const CLOCK_BOOTTIME: u32 = 7;

/// Events a reader may have queued before the oldest are dropped.
const QUEUE_MAX: usize = 1024;

/// The evdev key code for a PC scan code set 1 make code (`extended` for
/// the 0xE0 prefix), or 0. Set 1's single-byte codes are the evdev codes
/// themselves (xkeyboard-config: <ESC> = 9 is code 1, scan code 01h; <FK12>
/// = 96 is code 88, scan code 58h); the extended keys have codes of their
/// own.
pub fn set1_to_evdev(code: u8, extended: bool) -> u16 {
    if !extended {
        return if (0x01..=0x58).contains(&code) { u16::from(code) } else { 0 };
    }
    match code {
        0x1C => 96,  // <KPEN> 104
        0x1D => 97,  // <RCTL> 105
        0x35 => 98,  // <KPDV> 106
        0x37 => 99,  // <PRSC> 107
        0x38 => 100, // <RALT> 108
        0x47 => 102, // <HOME> 110
        0x48 => 103, // <UP> 111
        0x49 => 104, // <PGUP> 112
        0x4B => 105, // <LEFT> 113
        0x4D => 106, // <RGHT> 114
        0x4F => 107, // <END> 115
        0x50 => 108, // <DOWN> 116
        0x51 => 109, // <PGDN> 117
        0x52 => 110, // <INS> 118
        0x53 => 111, // <DELE> 119
        0x5B => 125, // <LWIN> 133
        0x5C => 126, // <RWIN> 134
        0x5D => 127, // <COMP> 135
        _ => 0,
    }
}

/// Every key code a PC keyboard can send through [`set1_to_evdev`].
pub fn keyboard_keys() -> Vec<u16> {
    let mut v: Vec<u16> = (1..=0x58).collect();
    v.extend([96, 97, 98, 99, 100, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 125, 126, 127]);
    v
}

/// An absolute axis's range (`struct input_absinfo`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AbsInfo {
    pub value: i32,
    pub minimum: i32,
    pub maximum: i32,
    pub fuzz: i32,
    pub flat: i32,
    pub resolution: i32,
}

/// What a device can report.
#[derive(Clone, Debug, Default)]
pub struct Caps {
    pub keys: Vec<u16>,
    pub rel: Vec<u16>,
    pub abs: Vec<(u16, AbsInfo)>,
    pub leds: Vec<u16>,
    pub props: u32,
    /// The kernel repeats held keys (EV_REP); the device's own repeats are
    /// dropped.
    pub rep: bool,
}

/// A device as a driver describes it.
#[derive(Clone, Debug, Default)]
pub struct Info {
    pub name: String,
    pub phys: String,
    pub bustype: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
    pub caps: Caps,
}

impl Info {
    /// The event types the capabilities imply.
    fn types(&self) -> Vec<u16> {
        let mut t = alloc::vec![EV_SYN];
        if !self.caps.keys.is_empty() {
            t.push(EV_KEY);
        }
        if !self.caps.rel.is_empty() {
            t.push(EV_REL);
        }
        if !self.caps.abs.is_empty() {
            t.push(EV_ABS);
        }
        if !self.caps.leds.is_empty() {
            t.push(EV_LED);
        }
        if self.caps.rep {
            t.push(EV_REP);
        }
        t
    }

    fn is_keyboard(&self) -> bool {
        self.caps.keys.contains(&30) // KEY_A
    }
}

/// A bitmap of `codes` up to `max`, as bytes (little-endian bit order).
fn bitmap(codes: &[u16], max: u16) -> Vec<u8> {
    let mut b = alloc::vec![0u8; usize::from(max) / 8 + 1];
    for &c in codes.iter().filter(|&&c| c <= max) {
        b[usize::from(c / 8)] |= 1 << (c % 8);
    }
    b
}

/// A bitmap in sysfs form: 64-bit words in hex, most significant first,
/// without leading zero words.
fn sysfs_bitmap(codes: &[u16], max: u16) -> String {
    let words = usize::from(max) / 64 + 1;
    let mut w = alloc::vec![0u64; words];
    for &c in codes.iter().filter(|&&c| c <= max) {
        w[usize::from(c / 64)] |= 1 << (c % 64);
    }
    let top = w.iter().rposition(|&x| x != 0).unwrap_or(0);
    let parts: Vec<String> = w[..=top].iter().rev().map(|x| format!("{x:x}")).collect();
    parts.join(" ")
}

/// Lights a keyboard's LEDs: the bits of LED_* codes that are on.
pub type LedHandler = alloc::boxed::Box<dyn Fn(u16) + Send + Sync>;

/// Repeat's delay and period, in milliseconds (EVIOCGREP's defaults).
const REPEAT_DEFAULT: [u32; 2] = [250, 33];

struct DevState {
    keys: [u64; 12],
    /// LEDs on, as bits of LED_* codes.
    leds: u16,
    /// Repeat's delay and period in milliseconds.
    rep: [u32; 2],
    /// The key repeating, and the press that started it.
    repeating: Option<(u16, u64)>,
    /// Events since the last SYN_REPORT, delivered together.
    frame: Vec<(u16, u16, i32)>,
    clients: Vec<Weak<Client>>,
    grab: Option<u64>,
}

/// One input device.
pub struct Device {
    pub index: usize,
    info: Info,
    state: IrqSpinLock<DevState>,
    leds_out: IrqSpinLock<Option<Arc<LedHandler>>>,
}

// Keys of Ctrl-Alt-Del (input-event-codes.h).
const KEY_LEFTCTRL: u16 = 29;
const KEY_LEFTALT: u16 = 56;
const KEY_RIGHTCTRL: u16 = 97;
const KEY_RIGHTALT: u16 = 100;
const KEY_DELETE: u16 = 111;

/// Whether pressing `code` with `keys` held is Ctrl-Alt-Del.
pub fn is_ctrl_alt_del(keys: &[u64; 12], code: u16) -> bool {
    let held = |k: u16| keys[usize::from(k / 64)] & (1 << (k % 64)) != 0;
    code == KEY_DELETE && (held(KEY_LEFTCTRL) || held(KEY_RIGHTCTRL)) && (held(KEY_LEFTALT) || held(KEY_RIGHTALT))
}

/// Presses so far, to tell a repeat timer whether its press still holds.
static PRESSES: AtomicU64 = AtomicU64::new(0);

static DEVICES: IrqSpinLock<Vec<Arc<Device>>> = IrqSpinLock::new(Vec::new());
static NEXT_INDEX: AtomicUsize = AtomicUsize::new(0);

/// Add a device; it appears as /dev/input/eventN.
pub fn register(info: Info) -> Arc<Device> {
    let index = NEXT_INDEX.fetch_add(1, Ordering::Relaxed);
    crate::log_info!("input: event{index}: {}", info.name);
    let dev = Arc::new(Device {
        index,
        info,
        state: IrqSpinLock::new(DevState {
            keys: [0; 12],
            leds: 0,
            rep: REPEAT_DEFAULT,
            repeating: None,
            frame: Vec::new(),
            clients: Vec::new(),
            grab: None,
        }),
        leds_out: IrqSpinLock::new(None),
    });
    DEVICES.lock().push(dev.clone());
    crate::fs::char_added(sysfs_node(&dev));
    dev
}

/// A device went (unplugged, or its Bluetooth link closed): its /dev node
/// and sysfs entries go, uevent listeners hear `remove`, and its readers
/// get ENODEV, as after EVIOCREVOKE.
pub fn unregister(dev: &Arc<Device>) {
    {
        let mut all = DEVICES.lock();
        let Some(i) = all.iter().position(|d| Arc::ptr_eq(d, dev)) else { return };
        all.remove(i);
    }
    crate::log_info!("input: event{}: {} gone", dev.index, dev.info.name);
    let clients: Vec<Arc<Client>> = dev.state.lock().clients.iter().filter_map(Weak::upgrade).collect();
    for c in clients {
        c.revoked.store(true, Ordering::Release);
        c.wait.wake_all();
    }
    crate::fs::poll_notify();
    crate::fs::char_removed(&format!("input/event{}", dev.index));
}

/// Whether event device `index` is still there.
pub fn exists(index: usize) -> bool {
    DEVICES.lock().iter().any(|d| d.index == index)
}

/// A reader of `dev` for the in-kernel tests: what it was sent, taken.
pub struct TestClient(Arc<Client>);

impl TestClient {
    /// The events delivered so far as (type, code, value), emptied.
    pub fn taken(&self) -> Vec<(u16, u16, i32)> {
        let mut q = self.0.queue.lock();
        q.drain(..)
            .map(|e| {
                let t = u16::from_le_bytes([e[16], e[17]]);
                let c = u16::from_le_bytes([e[18], e[19]]);
                (t, c, i32::from_le_bytes([e[20], e[21], e[22], e[23]]))
            })
            .collect()
    }
}

pub fn test_client(dev: &Arc<Device>) -> TestClient {
    let c = Arc::new(Client {
        id: NEXT_CLIENT.fetch_add(1, Ordering::Relaxed),
        dev: dev.clone(),
        queue: IrqSpinLock::new(VecDeque::new()),
        wait: WaitQueue::new(),
        count: AtomicU64::new(0),
        clock: AtomicU32::new(CLOCK_REALTIME),
        flags: AtomicU32::new(0),
        revoked: AtomicBool::new(false),
    });
    dev.state.lock().clients.push(Arc::downgrade(&c));
    TestClient(c)
}

/// The device's /dev node and sysfs entries (sysfs-class-input in the
/// Linux ABI documentation describes them).
fn sysfs_node(dev: &Device) -> CharNode {
    let i = &dev.info;
    let (n, minor) = (dev.index, EVENT_MINOR_BASE + dev.index as u32);
    let input = format!("devices/virtual/input/input{n}");
    let event = format!("{input}/event{n}");
    let keys = sysfs_bitmap(&i.caps.keys, KEY_MAX);
    let rel = sysfs_bitmap(&i.caps.rel, REL_MAX);
    let abs_codes: Vec<u16> = i.caps.abs.iter().map(|a| a.0).collect();
    let abs = sysfs_bitmap(&abs_codes, ABS_MAX);
    let ev = sysfs_bitmap(&i.types(), EV_MAX);
    let led = sysfs_bitmap(&i.caps.leds, LED_MAX);
    let prop = format!("{:x}", i.caps.props);
    let product = format!("{:x}/{:x}/{:x}/{:x}", i.bustype, i.vendor, i.product, i.version);
    let mut sys = alloc::vec![
        SysEntry::File(format!("{input}/name"), format!("{}\n", i.name)),
        SysEntry::File(format!("{input}/phys"), format!("{}\n", i.phys)),
        SysEntry::File(format!("{input}/uniq"), String::from("\n")),
        SysEntry::File(format!("{input}/properties"), format!("{prop}\n")),
        SysEntry::File(format!("{input}/id/bustype"), format!("{:04x}\n", i.bustype)),
        SysEntry::File(format!("{input}/id/vendor"), format!("{:04x}\n", i.vendor)),
        SysEntry::File(format!("{input}/id/product"), format!("{:04x}\n", i.product)),
        SysEntry::File(format!("{input}/id/version"), format!("{:04x}\n", i.version)),
        SysEntry::File(format!("{input}/capabilities/ev"), format!("{ev}\n")),
        SysEntry::File(format!("{input}/capabilities/key"), format!("{keys}\n")),
        SysEntry::File(format!("{input}/capabilities/rel"), format!("{rel}\n")),
        SysEntry::File(format!("{input}/capabilities/abs"), format!("{abs}\n")),
        SysEntry::File(format!("{input}/capabilities/led"), format!("{led}\n")),
        SysEntry::File(format!("{input}/capabilities/msc"), String::from("0\n")),
        SysEntry::File(format!("{input}/capabilities/sw"), String::from("0\n")),
        SysEntry::File(format!("{input}/capabilities/ff"), String::from("0\n")),
        SysEntry::File(format!("{input}/capabilities/snd"), String::from("0\n")),
        SysEntry::File(
            format!("{input}/uevent"),
            format!(
                "PRODUCT={product}\nNAME=\"{}\"\nPHYS=\"{}\"\nPROP={prop}\nEV={ev}\nKEY={keys}\nREL={rel}\nABS={abs}\n",
                i.name, i.phys
            ),
        ),
        SysEntry::Link(format!("{input}/subsystem"), String::from("../../../../class/input")),
        SysEntry::File(format!("{event}/dev"), format!("{INPUT_MAJOR}:{minor}\n")),
        SysEntry::File(
            format!("{event}/uevent"),
            format!("MAJOR={INPUT_MAJOR}\nMINOR={minor}\nDEVNAME=input/event{n}\n"),
        ),
        SysEntry::Link(format!("{event}/subsystem"), String::from("../../../../../class/input")),
        SysEntry::Link(format!("{event}/device"), String::from("..")),
        SysEntry::Link(format!("class/input/input{n}"), format!("../../{input}")),
        SysEntry::Link(format!("class/input/event{n}"), format!("../../{event}")),
        SysEntry::Link(format!("dev/char/{INPUT_MAJOR}:{minor}"), format!("../../{event}")),
    ];
    sys.push(SysEntry::Dir(String::from("class/input")));
    CharNode { dev: format!("input/event{n}"), rdev: vfs::makedev(INPUT_MAJOR, minor), mode: 0o660, sys }
}

impl Device {
    /// Report one event; EV_SYN/SYN_REPORT delivers what came before it.
    pub fn emit(&self, ty: u16, code: u16, value: i32) {
        let mut st = self.state.lock();
        let mut value = value;
        if ty == EV_KEY && code <= KEY_MAX {
            let (w, b) = (usize::from(code / 64), code % 64);
            let down = st.keys[w] & (1 << b) != 0;
            let rep = self.info.caps.rep && code < BTN_MISC;
            match value {
                0 => st.keys[w] &= !(1 << b),
                // With EV_REP the kernel's timer repeats; the device's own
                // repeats go.
                _ if down && rep && value != 2 => return,
                _ if down => value = 2, // A press while down is a repeat.
                _ => st.keys[w] |= 1 << b,
            }
            if value == 0 && !down {
                return;
            }
            if rep && value == 1 {
                let press = PRESSES.fetch_add(1, Ordering::Relaxed) + 1;
                st.repeating = Some((code, press));
                arm_repeat(self.index, code, press, st.rep[0]);
            } else if value == 0 && st.repeating.is_some_and(|r| r.0 == code) {
                st.repeating = None;
            }
        }
        st.frame.push((ty, code, value));
        if ty == EV_SYN && code == SYN_REPORT {
            let frame = core::mem::take(&mut st.frame);
            st.clients.retain(|c| c.strong_count() > 0);
            let grab = st.grab;
            let clients: Vec<Arc<Client>> =
                st.clients.iter().filter_map(Weak::upgrade).filter(|c| grab.is_none_or(|g| g == c.id)).collect();
            drop(st);
            for c in clients {
                c.deliver(&frame);
            }
        }
    }

    pub fn sync(&self) {
        self.emit(EV_SYN, SYN_REPORT, 0);
    }

    /// The handler that lights this keyboard's LEDs.
    pub fn set_led_handler(&self, h: LedHandler) {
        *self.leds_out.lock() = Some(Arc::new(h));
    }

    /// Turn LED `code` on or off, and light it; reported as an EV_LED event.
    pub fn set_led(&self, code: u16, on: bool) {
        let leds = {
            let mut st = self.state.lock();
            let leds = if on { st.leds | 1 << code } else { st.leds & !(1 << code) };
            if leds == st.leds {
                return;
            }
            st.leds = leds;
            leds
        };
        self.emit(EV_LED, code, i32::from(on));
        self.sync();
        let h = self.leds_out.lock().clone();
        if let Some(h) = h {
            h(leds);
        }
    }

    pub fn key(&self, code: u16, down: bool) {
        if code != 0 {
            self.emit(EV_KEY, code, i32::from(down));
            if down && is_ctrl_alt_del(&self.state.lock().keys, code) {
                crate::arch::power::ctrl_alt_del();
            }
        }
    }

    fn grabbed(&self) -> bool {
        self.state.lock().grab.is_some()
    }
}

/// The console's keyboard layout: `slate.keyboard=` on the command line,
/// or what /proc/sys/slate/keyboard was given (ADR 0039).
static LAYOUT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(u8::MAX);

pub fn layout() -> slate_term::keymap::Layout {
    use slate_term::keymap::Layout;
    match Layout::from_code(LAYOUT.load(Ordering::Relaxed)) {
        Some(l) => l,
        None => {
            let l = crate::arch::boot::info()
                .cmdline
                .split_ascii_whitespace()
                .find_map(|w| w.strip_prefix("slate.keyboard="))
                .and_then(Layout::by_name)
                .unwrap_or_default();
            LAYOUT.store(l.code(), Ordering::Relaxed);
            l
        }
    }
}

pub fn set_layout(l: slate_term::keymap::Layout) {
    LAYOUT.store(l.code(), Ordering::Relaxed);
    crate::log_info!("input: console keyboard layout {}", l.name());
}

/// Repeat `code` on device `index` after `ms`, while press `press` holds.
fn arm_repeat(index: usize, code: u16, press: u64, ms: u32) {
    if ms == 0 {
        return;
    }
    crate::time::add_timer(crate::time::monotonic_ns() + u64::from(ms) * 1_000_000, move || {
        let Some(dev) = DEVICES.lock().iter().find(|d| d.index == index).cloned() else { return };
        let period = {
            let st = dev.state.lock();
            if st.repeating != Some((code, press)) {
                return;
            }
            st.rep[1]
        };
        dev.emit(EV_KEY, code, 2);
        dev.sync();
        arm_repeat(index, code, press, period);
    });
}

/// The console's Caps Lock changed: the keyboards' lights follow, unless
/// a compositor has the keyboards (it lights them itself).
pub fn console_caps_lock(on: bool) {
    if !console_input() {
        return;
    }
    let keyboards: Vec<Arc<Device>> = DEVICES.lock().iter().filter(|d| d.info.is_keyboard()).cloned().collect();
    for k in keyboards {
        k.set_led(LED_CAPSL, on);
    }
}

/// Whether keyboards should also type on the console: not while a
/// process grabs a keyboard, nor while a DRM master owns the screen
/// (a compositor reads them then).
pub fn console_input() -> bool {
    if crate::drivers::fbcon::suspended() {
        return false;
    }
    !DEVICES.lock().iter().any(|d| d.info.is_keyboard() && d.grabbed())
}

static NEXT_CLIENT: AtomicU64 = AtomicU64::new(1);

/// One open event device.
struct Client {
    id: u64,
    dev: Arc<Device>,
    queue: IrqSpinLock<VecDeque<[u8; 24]>>,
    wait: WaitQueue,
    count: AtomicU64,
    clock: AtomicU32,
    flags: AtomicU32,
    revoked: AtomicBool,
}

impl Client {
    fn deliver(&self, frame: &[(u16, u16, i32)]) {
        if self.revoked.load(Ordering::Acquire) {
            return;
        }
        let ns = match self.clock.load(Ordering::Relaxed) {
            CLOCK_MONOTONIC | CLOCK_BOOTTIME => crate::time::monotonic_ns() as i128,
            _ => crate::time::realtime_ns(),
        };
        let (sec, usec) = ((ns / 1_000_000_000) as i64, ((ns % 1_000_000_000) / 1000) as i64);
        let ev = |ty: u16, code: u16, value: i32| {
            let mut e = [0u8; 24];
            e[0..8].copy_from_slice(&sec.to_le_bytes());
            e[8..16].copy_from_slice(&usec.to_le_bytes());
            e[16..18].copy_from_slice(&ty.to_le_bytes());
            e[18..20].copy_from_slice(&code.to_le_bytes());
            e[20..24].copy_from_slice(&value.to_le_bytes());
            e
        };
        {
            let mut q = self.queue.lock();
            if q.len() + frame.len() > QUEUE_MAX {
                // The reader fell behind: drop what it has and say so
                // (SYN_DROPPED, input.rst).
                q.clear();
                q.push_back(ev(EV_SYN, SYN_DROPPED, 0));
            }
            for &(t, c, v) in frame {
                q.push_back(ev(t, c, v));
            }
        }
        self.count.fetch_add(1, Ordering::Release);
        self.wait.wake_all();
        crate::fs::poll_notify();
    }
}

/// Open event device `minor`.
pub fn open(minor: u32, flags: u32) -> Result<Arc<dyn File>> {
    let index = minor.checked_sub(EVENT_MINOR_BASE).ok_or(ENXIO)? as usize;
    let dev = DEVICES.lock().iter().find(|d| d.index == index).cloned().ok_or(ENXIO)?;
    let c = Arc::new(Client {
        id: NEXT_CLIENT.fetch_add(1, Ordering::Relaxed),
        dev: dev.clone(),
        queue: IrqSpinLock::new(VecDeque::new()),
        wait: WaitQueue::new(),
        count: AtomicU64::new(0),
        clock: AtomicU32::new(CLOCK_REALTIME),
        flags: AtomicU32::new(flags),
        revoked: AtomicBool::new(false),
    });
    dev.state.lock().clients.push(Arc::downgrade(&c));
    Ok(Arc::new(EvdevFile(c)))
}

struct EvdevFile(Arc<Client>);

impl Drop for EvdevFile {
    fn drop(&mut self) {
        let mut st = self.0.dev.state.lock();
        if st.grab == Some(self.0.id) {
            st.grab = None;
        }
    }
}

/// Copy `data` into a user buffer of `size` bytes; returns bytes copied.
fn put(arg: u64, size: usize, data: &[u8]) -> Result<u64> {
    let n = data.len().min(size);
    copy_to_user(arg, &data[..n]).map_err(|_| EFAULT)?;
    Ok(n as u64)
}

/// A string for EVIOCGNAME and friends: NUL-terminated, cut to fit.
fn put_str(arg: u64, size: usize, s: &str) -> Result<u64> {
    if size == 0 {
        return Ok(0);
    }
    let mut b: Vec<u8> = s.as_bytes().iter().copied().take(size - 1).collect();
    b.push(0);
    put(arg, size, &b)
}

impl File for EvdevFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let c = &self.0;
        if buf.len() < 24 {
            return Err(EINVAL);
        }
        loop {
            if c.revoked.load(Ordering::Acquire) {
                return Err(ENODEV);
            }
            {
                let mut q = c.queue.lock();
                if !q.is_empty() {
                    let mut n = 0;
                    while n + 24 <= buf.len() {
                        let Some(e) = q.pop_front() else { break };
                        buf[n..n + 24].copy_from_slice(&e);
                        n += 24;
                    }
                    return Ok(n);
                }
            }
            if c.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0 {
                return Err(EAGAIN);
            }
            if c.wait.wait_until_interruptible(|| !c.queue.lock().is_empty() || c.revoked.load(Ordering::Acquire)) {
                return Err(EINTR);
            }
        }
    }

    /// Events written to the device: EV_LED lights a keyboard's LEDs, EV_REP
    /// sets repeat (input.rst, "Output events"); others are ignored.
    fn write(&self, buf: &[u8]) -> Result<usize> {
        let c = &self.0;
        if c.revoked.load(Ordering::Acquire) {
            return Err(ENODEV);
        }
        if buf.len() < 24 {
            return Err(EINVAL);
        }
        let n = buf.len() / 24 * 24;
        for e in buf[..n].as_chunks::<24>().0 {
            let ty = u16::from_le_bytes([e[16], e[17]]);
            let code = u16::from_le_bytes([e[18], e[19]]);
            let value = i32::from_le_bytes([e[20], e[21], e[22], e[23]]);
            match ty {
                EV_LED if c.dev.info.caps.leds.contains(&code) => c.dev.set_led(code, value != 0),
                EV_REP if code <= 1 && value >= 0 => c.dev.state.lock().rep[usize::from(code)] = value as u32,
                _ => {}
            }
        }
        Ok(n)
    }

    fn poll(&self) -> u16 {
        if self.0.revoked.load(Ordering::Acquire) {
            return POLLERR | POLLHUP;
        }
        if self.0.queue.lock().is_empty() { 0 } else { POLLIN }
    }

    fn event_count(&self) -> u64 {
        self.0.count.load(Ordering::Acquire)
    }

    fn status_flags(&self) -> u32 {
        self.0.flags.load(Ordering::Relaxed)
    }

    fn set_status_flags(&self, flags: u32) {
        let keep = self.0.flags.load(Ordering::Relaxed) & !O_NONBLOCK;
        self.0.flags.store(keep | (flags & O_NONBLOCK), Ordering::Relaxed);
    }

    fn stat(&self) -> Result<Metadata> {
        let rdev = vfs::makedev(INPUT_MAJOR, EVENT_MINOR_BASE + self.0.dev.index as u32);
        Ok(Metadata { mode: vfs::S_IFCHR | 0o660, rdev, nlink: 1, ..Metadata::default() })
    }

    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64> {
        let c = &self.0;
        let info = &c.dev.info;
        if (cmd >> 8) & 0xff != u32::from(b'E') {
            return Err(ENOTTY);
        }
        // A revoked descriptor answers nothing more (libevdev's
        // documentation of EVIOCREVOKE).
        if c.revoked.load(Ordering::Acquire) {
            return Err(ENODEV);
        }
        let (nr, size, write) = (cmd & 0xff, ((cmd >> 16) & 0x3fff) as usize, cmd >> 30 == 1);
        match nr {
            0x01 => write_user(arg, &EV_VERSION).map(|_| 0).map_err(|_| EFAULT),
            0x02 => {
                let id = [info.bustype, info.vendor, info.product, info.version];
                write_user(arg, &id).map(|_| 0).map_err(|_| EFAULT)
            }
            // EVIOCGREP and EVIOCSREP: repeat's delay and period (ms).
            0x03 if !write => {
                let r = c.dev.state.lock().rep;
                write_user(arg, &r).map(|_| 0).map_err(|_| EFAULT)
            }
            0x03 => {
                let r: [u32; 2] = read_user(arg).map_err(|_| EFAULT)?;
                c.dev.state.lock().rep = r;
                Ok(0)
            }
            0x06 => put_str(arg, size, &info.name),
            0x07 => put_str(arg, size, &info.phys),
            0x08 => put_str(arg, size, ""),
            0x09 => put(arg, size, &info.caps.props.to_le_bytes()),
            0x18 => {
                let keys = c.dev.state.lock().keys;
                let bytes: Vec<u8> = keys.iter().flat_map(|w| w.to_le_bytes()).collect();
                put(arg, size, &bytes)
            }
            // EVIOCGLED: the lights on.
            0x19 => {
                let leds = c.dev.state.lock().leds;
                put(arg, size, &leds.to_le_bytes())
            }
            0x1a..=0x1b => put(arg, size, &[0u8; 16]),
            0x20..=0x3f => {
                let ev = (nr - 0x20) as u16;
                let abs: Vec<u16> = info.caps.abs.iter().map(|a| a.0).collect();
                let bits = match ev {
                    0 => bitmap(&info.types(), EV_MAX),
                    EV_KEY => bitmap(&info.caps.keys, KEY_MAX),
                    EV_REL => bitmap(&info.caps.rel, REL_MAX),
                    EV_ABS => bitmap(&abs, ABS_MAX),
                    EV_LED => bitmap(&info.caps.leds, LED_MAX),
                    EV_REP if info.caps.rep => alloc::vec![0b11],
                    _ => alloc::vec![0u8; 8],
                };
                put(arg, size, &bits)
            }
            0x40..=0x7f => {
                let axis = (nr - 0x40) as u16;
                let a = info.caps.abs.iter().find(|a| a.0 == axis).ok_or(EINVAL)?;
                write_user(arg, &a.1).map(|_| 0).map_err(|_| EFAULT)
            }
            0xc0..=0xff => Ok(0),
            // EVIOCGEFFECTS: no force feedback.
            0x84 => write_user(arg, &0i32).map(|_| 0).map_err(|_| EFAULT),
            // EVIOCGRAB takes its argument by value.
            0x90 => {
                let mut st = c.dev.state.lock();
                match (arg, st.grab) {
                    (0, Some(g)) if g == c.id => {
                        st.grab = None;
                        Ok(0)
                    }
                    (0, _) => Err(EINVAL),
                    (_, Some(_)) => Err(EBUSY),
                    (_, None) => {
                        st.grab = Some(c.id);
                        Ok(0)
                    }
                }
            }
            // EVIOCREVOKE: this descriptor is done for good.
            0x91 => {
                c.revoked.store(true, Ordering::Release);
                c.wait.wake_all();
                crate::fs::poll_notify();
                Ok(0)
            }
            0xa0 => {
                let id: i32 = read_user(arg).map_err(|_| EFAULT)?;
                match id as u32 {
                    CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME => {
                        c.clock.store(id as u32, Ordering::Relaxed);
                        Ok(0)
                    }
                    _ => Err(EINVAL),
                }
            }
            _ => Err(EINVAL),
        }
    }
}
