// SPDX-License-Identifier: MIT OR Apache-2.0

//! USB keyboards, mice and other HID devices, for the console and as evdev
//! devices (ADR 0033).
//!
//! Sources: Device Class Definition for HID 1.11 (SET_PROTOCOL and
//! SET_IDLE, §7.2; the boot keyboard report, appendix B.1), HID Usage
//! Tables 1.4 (keyboard page 07h), and Microsoft's "USB HID to PS/2 Scan
//! Code Translation Table", which maps each usage to the scan code set 1
//! code that `slate_term::keyboard` already decodes for the PS/2 keyboard.
//!
//! Reports are compared with the previous one: new keys are pressed,
//! missing keys released. USB keyboards do not repeat by themselves, so a
//! key held for 500 ms repeats every 33 ms, as a PS/2 keyboard would (on
//! the console only: compositors repeat keys themselves). The boot mouse
//! report (appendix B.2) is buttons, then X and Y movement, with many mice
//! adding a wheel byte.
//!
//! Keyboards and other HID devices use the report protocol: their report
//! descriptor (§6.2.2, parsed by `slate_hid`, asked for with the length
//! the HID descriptor gives, §6.2.1 and §7.1.1) says where the keys, X, Y,
//! the buttons and the wheels are. Each report is the set of usages it
//! holds down, compared with that report's last: keyboard keys go to the
//! console and evdev, consumer controls (media keys, HID Usage Tables 1.4
//! §15) and system controls (power, sleep, wake; §4.5) to evdev only.
//! Pointers, absolute (the tablets virtual machines offer) or relative,
//! become evdev devices (ADR 0039). A boot keyboard whose descriptor
//! cannot be read falls back to the boot protocol.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use slate_term::keyboard::Keyboard;

use super::xhci::{CC_SHORT_PACKET, CC_SUCCESS, Endpoint, UsbDevice};
use super::{EP_INTERRUPT, InterfaceDesc, REQ_GET_DESCRIPTOR, RT_CLASS_INTERFACE_OUT};
use crate::drivers::dma::Dma;
use crate::drivers::input::{self, BTN_EXTRA, BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, BTN_SIDE, BUS_USB, Caps, Info};
use crate::sync::IrqSpinLock;
use crate::{log_info, log_warn};

const SET_REPORT: u8 = 0x09;
const SET_IDLE: u8 = 0x0A;
/// SET_REPORT's value for output report 0 (report type 2, HID 1.11 §7.2.2).
const OUTPUT_REPORT: u16 = 0x0200;
/// GET_DESCRIPTOR of the interface (standard request, recipient interface,
/// device to host) for its report descriptor (type 22h, HID 1.11 §7.1.1).
const RT_INTERFACE_IN: u8 = 0x81;
const DESC_REPORT: u16 = 0x22;
const SET_PROTOCOL: u8 = 0x0B;
const BOOT_PROTOCOL: u16 = 0;
const REPORT_PROTOCOL: u16 = 1;
/// When the HID descriptor gives no report descriptor length.
const REPORT_DESCRIPTOR_MAX: usize = 1024;

const REPEAT_DELAY_NS: u64 = 500_000_000;
const REPEAT_RATE_NS: u64 = 33_000_000;

/// Scan code set 1 make codes for usages 04h-65h (0xE0xx: extended).
const USAGE_TO_SET1: [u16; 0x62] = [
    0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18, 0x19, // a-p
    0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C, // q-z
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, // 1-0
    0x1C, 0x01, 0x0E, 0x0F, 0x39, 0x0C, 0x0D, 0x1A, 0x1B, 0x2B, 0x2B, 0x27, 0x28, 0x29, 0x33, 0x34,
    0x35, // Enter../
    0x3A, // Caps Lock
    0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x57, 0x58, // F1-F12
    0xE037, 0x46, 0, // Print Screen, Scroll Lock, Pause (not mapped)
    0xE052, 0xE047, 0xE049, 0xE053, 0xE04F, 0xE051, // Insert, Home, Page Up, Delete, End, Page Down
    0xE04D, 0xE04B, 0xE050, 0xE048, // Right, Left, Down, Up
    0x45, 0xE035, 0x37, 0x4A, 0x4E, 0xE01C, // Num Lock, keypad / * - + Enter
    0x4F, 0x50, 0x51, 0x4B, 0x4C, 0x4D, 0x47, 0x48, 0x49, 0x52, 0x53, // keypad 1-9, 0, .
    0x56, 0xE05D, // non-US \, Application
];

/// Modifier bits 0-7 of the report's first byte: left Ctrl, Shift, Alt,
/// GUI, then the right ones.
const MODIFIER_SET1: [u16; 8] = [0x1D, 0x2A, 0x38, 0xE05B, 0xE01D, 0x36, 0xE038, 0xE05C];

fn set1(usage: u8) -> u16 {
    match usage {
        0x04..=0x65 => USAGE_TO_SET1[usize::from(usage - 4)],
        _ => 0,
    }
}

/// What a usage held down does: a scan code set 1 make code for the
/// console (and evdev through it), or an evdev key only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Key {
    Console(u16),
    Evdev(u16),
}

/// Consumer controls (HID Usage Tables 1.4 §15) and the evdev keys they
/// are (codes from xkeyboard-config's keycodes/evdev, less 8; ADR 0033).
const CONSUMER_KEYS: &[(u16, u16)] = &[
    (0xE2, 113),  // Mute: KEY_MUTE
    (0xEA, 114),  // Volume Decrement: KEY_VOLUMEDOWN
    (0xE9, 115),  // Volume Increment: KEY_VOLUMEUP
    (0xCD, 164),  // Play/Pause: KEY_PLAYPAUSE
    (0xB5, 163),  // Scan Next Track: KEY_NEXTSONG
    (0xB6, 165),  // Scan Previous Track: KEY_PREVIOUSSONG
    (0xB7, 166),  // Stop: KEY_STOPCD
    (0xB8, 161),  // Eject: KEY_EJECTCD
    (0x18A, 155), // AL Email Reader: KEY_MAIL
    (0x192, 140), // AL Calculator: KEY_CALC
    (0x221, 217), // AC Search: KEY_SEARCH
    (0x223, 172), // AC Home: KEY_HOMEPAGE
    (0x224, 158), // AC Back: KEY_BACK
    (0x225, 159), // AC Forward: KEY_FORWARD
    (0x227, 173), // AC Refresh: KEY_REFRESH
    (0x6F, 225),  // Display Brightness Increment: KEY_BRIGHTNESSUP
    (0x70, 224),  // Display Brightness Decrement: KEY_BRIGHTNESSDOWN
];

/// System controls (Generic Desktop page, §4.5): Power Down, Sleep and
/// Wake Up as KEY_POWER, KEY_SLEEP and KEY_WAKEUP. They are keys only:
/// what to do is the desktop's choice, as with a keyboard's power key.
const SYSTEM_KEYS: &[(u16, u16)] = &[(0x81, 116), (0x82, 142), (0x83, 143)];

fn key_of(u: u32) -> Option<Key> {
    let (page, id) = ((u >> 16) as u16, u as u16);
    let table = |t: &[(u16, u16)]| t.iter().find(|e| e.0 == id).map(|e| Key::Evdev(e.1));
    match page {
        slate_hid::PAGE_KEYBOARD => match id {
            0xE0..=0xE7 => Some(Key::Console(MODIFIER_SET1[usize::from(id - 0xE0)])),
            0x04..=0x65 => Some(set1(id as u8)).filter(|&c| c != 0).map(Key::Console),
            _ => None,
        },
        slate_hid::PAGE_CONSUMER => table(CONSUMER_KEYS),
        slate_hid::PAGE_GENERIC_DESKTOP => table(SYSTEM_KEYS),
        _ => None,
    }
}

/// The evdev keys a keyboard can send: the keyboard's, the consumer and
/// system controls'.
fn all_keys() -> Vec<u16> {
    let mut v = input::keyboard_keys();
    v.extend(CONSUMER_KEYS.iter().chain(SYSTEM_KEYS).map(|e| e.1));
    v
}

/// What the keyboards share: the console's decoder, Caps Lock as the
/// lights last showed it, and the key that repeats (with a generation that
/// cancels old timers).
struct State {
    decoder: Keyboard,
    caps: bool,
    held: Option<u16>,
    generation: u64,
}

static STATE: IrqSpinLock<Option<State>> = IrqSpinLock::new(None);

/// Feed a make (or break, with `release`) code to the decoder and the
/// console, and to `kbd`'s evdev device: the keyboard it came from (none
/// for the console's own repeats).
fn press(st: &mut State, code: u16, release: bool, kbd: Option<&input::Device>) {
    if let Some(k) = kbd {
        evdev_key(k, input::set1_to_evdev(code as u8, code > 0xFF), !release);
    }
    let mut bytes = Vec::new();
    st.decoder.set_layout(input::layout());
    if code > 0xFF {
        bytes.extend(st.decoder.scancode(0xE0));
    }
    bytes.extend(st.decoder.scancode((code as u8) | if release { 0x80 } else { 0 }));
    if st.decoder.caps_lock() != st.caps {
        st.caps = st.decoder.caps_lock();
        input::console_caps_lock(st.caps);
    }
    if input::console_input()
        && let Some(tty) = crate::fs::tty::console_if_ready()
    {
        for b in bytes {
            tty.receive(b);
        }
    }
}

/// A key on keyboard `kbd`'s evdev device only: a key on one keyboard is
/// not a key on the others (the reference PC's G900 mouse has a keyboard interface,
/// and each key typed on the Das Keyboard came twice).
fn evdev_key(kbd: &input::Device, key: u16, down: bool) {
    kbd.key(key, down);
    kbd.sync();
}

/// A keyboard's keys went from `last` to `now` (sorted usages): releases
/// first, then presses; the newest console key repeats.
fn keys_changed(kbd: &input::Device, last: &[u32], now: &[u32]) {
    let mut guard = STATE.lock();
    let st = guard.get_or_insert_with(|| State { decoder: Keyboard::new(), caps: false, held: None, generation: 0 });
    for &u in last.iter().filter(|u| now.binary_search(u).is_err()) {
        match key_of(u) {
            Some(Key::Console(code)) => {
                press(st, code, true, Some(kbd));
                if st.held == Some(code) {
                    st.held = None;
                }
            }
            Some(Key::Evdev(k)) => evdev_key(kbd, k, false),
            None => {}
        }
    }
    let mut newest = None;
    for &u in now.iter().filter(|u| last.binary_search(u).is_err()) {
        match key_of(u) {
            Some(Key::Console(code)) => {
                press(st, code, false, Some(kbd));
                // Modifiers do not repeat.
                if u as u16 & 0xFFF8 != 0xE0 {
                    newest = Some(code);
                }
            }
            Some(Key::Evdev(k)) => evdev_key(kbd, k, true),
            None => {}
        }
    }
    if let Some(code) = newest {
        st.held = Some(code);
        st.generation += 1;
        arm_repeat(st.generation, REPEAT_DELAY_NS);
    }
}

/// The usages a boot keyboard report (appendix B.1) holds down, sorted;
/// `None` for the phantom state (every key slot 01h, a rollover error).
fn boot_usages(r: &[u8; 8]) -> Option<Vec<u32>> {
    if r[2..].iter().all(|&k| k == 1) {
        return None;
    }
    let key = |id: u16| slate_hid::usage(slate_hid::PAGE_KEYBOARD, id);
    let mut v: Vec<u32> = (0..8).filter(|b| r[0] & (1 << b) != 0).map(|b| key(0xE0 + b)).collect();
    v.extend(r[2..].iter().filter(|&&k| k > 3).map(|&k| key(u16::from(k))));
    v.sort_unstable();
    v.dedup();
    Some(v)
}

fn arm_repeat(generation: u64, after: u64) {
    crate::time::add_timer(crate::time::monotonic_ns() + after, move || {
        let mut guard = STATE.lock();
        let Some(st) = guard.as_mut() else { return };
        if st.generation != generation {
            return;
        }
        if let Some(code) = st.held {
            press(st, code, false, None);
            arm_repeat(generation, REPEAT_RATE_NS);
        }
    });
}

/// A keyboard's evdev device, with its lights sent by a thread (a control
/// transfer waits): `send` turns evdev's LED bits (Num, Caps, Scroll Lock
/// in bits 0-2) into the output report it SET_REPORTs.
fn keyboard_device(
    dev: &Arc<UsbDevice>,
    iface: &InterfaceDesc,
    (vendor, product): (u16, u16),
    leds: bool,
    send: impl Fn(u8) -> (u16, Vec<u8>) + Send + 'static,
) -> Arc<input::Device> {
    let keyboard = input::register(Info {
        name: "USB Keyboard".into(),
        phys: alloc::format!("usb-{}/input{}", dev.port, iface.number),
        bustype: BUS_USB,
        vendor,
        product,
        version: 0x0111,
        caps: Caps {
            keys: all_keys(),
            leds: if leds { alloc::vec![0, 1, 2] } else { Vec::new() },
            rep: true,
            ..Caps::default()
        },
    });
    if leds {
        let wanted = Arc::new(core::sync::atomic::AtomicU32::new(0));
        let wake = Arc::new(crate::sched::wait::WaitQueue::new());
        let (w, q) = (wanted.clone(), wake.clone());
        keyboard.set_led_handler(alloc::boxed::Box::new(move |leds| {
            w.store(u32::from(leds), Ordering::Release);
            q.wake_all();
        }));
        let (d, number) = (dev.clone(), u16::from(iface.number));
        crate::sched::spawn("usb-kbd-leds", move || {
            let (mut sent, mut first) = (0, true);
            loop {
                wake.wait_until(|| wanted.load(Ordering::Acquire) != sent || d.gone.load(Ordering::Acquire));
                if d.gone.load(Ordering::Acquire) {
                    return;
                }
                sent = wanted.load(Ordering::Acquire);
                let (value, mut report) = send(sent as u8);
                if d.control(RT_CLASS_INTERFACE_OUT, SET_REPORT, value, number, &mut report).is_err() {
                    log_warn!("USB keyboard on port {}: setting its lights failed", d.port);
                } else if core::mem::take(&mut first) {
                    log_info!("USB keyboard on port {}: lights set ({sent:#x})", d.port);
                }
            }
        });
    }
    keyboard
}

/// Set up a boot keyboard: through its report descriptor (the report
/// protocol), or if that cannot be read, the boot protocol.
pub fn start(dev: &Arc<UsbDevice>, iface: &InterfaceDesc, ids: (u16, u16)) {
    if !start_report(dev, iface, ids) {
        start_boot(dev, iface, ids);
    }
}

/// A boot keyboard in the boot protocol: its interrupt-IN endpoint, no
/// idle reports, and a report always queued. The lights are the boot
/// output report (appendix B.1: Num, Caps and Scroll Lock in bits 0-2, as
/// evdev numbers them).
fn start_boot(dev: &Arc<UsbDevice>, iface: &InterfaceDesc, ids: (u16, u16)) {
    let kbd = keyboard_device(dev, iface, ids, true, |leds| (OUTPUT_REPORT, alloc::vec![leds]));
    let Some(ep) = iface.endpoints.iter().find(|e| e.kind == EP_INTERRUPT && e.is_in()).copied() else { return };
    let Some(eps) = dev.configure(&[ep]) else { return };
    let index = u16::from(iface.number);
    if dev.control(RT_CLASS_INTERFACE_OUT, SET_PROTOCOL, BOOT_PROTOCOL, index, &mut []).is_err() {
        log_warn!("USB keyboard: SET_PROTOCOL failed");
    }
    // Some keyboards stall SET_IDLE; that is harmless.
    let _ = dev.control(RT_CLASS_INTERFACE_OUT, SET_IDLE, 0, index, &mut []);
    let Some(buf) = Dma::new(64) else { return };
    let endpoint: Arc<Endpoint> = eps[0].clone();
    let (d, e) = (dev.clone(), endpoint.clone());
    let len = usize::from(ep.max_packet).clamp(8, 64);
    let phys = buf.phys();
    let buf = Arc::new(buf);
    let last = IrqSpinLock::new(Vec::new());
    dev.hc.set_pipe(
        dev.slot,
        endpoint.dci,
        alloc::boxed::Box::new(move |code, _residual| {
            if d.gone.load(Ordering::Acquire) {
                return;
            }
            if code != CC_SUCCESS && code != CC_SHORT_PACKET {
                // Gone or broken: stop asking (the port change follows).
                log_warn!("USB keyboard on port {}: transfer error {code}", d.port);
                return;
            }
            let mut r = [0u8; 8];
            buf.copy_out(0, &mut r);
            if let Some(now) = boot_usages(&r) {
                let mut last = last.lock();
                keys_changed(&kbd, &last, &now);
                *last = now;
            }
            d.queue(&e, phys, len);
        }),
    );
    dev.queue(&endpoint, phys, len);
    log_info!("USB port {}: keyboard (boot protocol)", dev.port);
}

/// Set up a boot mouse: the boot protocol and a report always queued; its
/// reports go to its evdev device.
pub fn start_mouse(dev: &Arc<UsbDevice>, iface: &InterfaceDesc, (vendor, product): (u16, u16)) {
    let Some(ep) = iface.endpoints.iter().find(|e| e.kind == EP_INTERRUPT && e.is_in()).copied() else { return };
    let Some(eps) = dev.configure(&[ep]) else { return };
    let index = u16::from(iface.number);
    if dev.control(RT_CLASS_INTERFACE_OUT, SET_PROTOCOL, BOOT_PROTOCOL, index, &mut []).is_err() {
        log_warn!("USB mouse: SET_PROTOCOL failed");
    }
    let _ = dev.control(RT_CLASS_INTERFACE_OUT, SET_IDLE, 0, index, &mut []);
    let mouse = input::register(Info {
        name: "USB Mouse".into(),
        phys: alloc::format!("usb-{}/input{}", dev.port, iface.number),
        bustype: BUS_USB,
        vendor,
        product,
        version: 0x0111,
        caps: Caps {
            keys: alloc::vec![BTN_LEFT, BTN_RIGHT, BTN_MIDDLE, BTN_SIDE, BTN_EXTRA],
            rel: alloc::vec![input::REL_X, input::REL_Y, input::REL_WHEEL],
            props: 1 << input::INPUT_PROP_POINTER,
            ..Caps::default()
        },
    });
    let Some(buf) = Dma::new(64) else { return };
    let endpoint: Arc<Endpoint> = eps[0].clone();
    let (d, e) = (dev.clone(), endpoint.clone());
    let len = usize::from(ep.max_packet).clamp(3, 64);
    let phys = buf.phys();
    let buf = Arc::new(buf);
    let buttons = Arc::new(core::sync::atomic::AtomicU8::new(0));
    dev.hc.set_pipe(
        dev.slot,
        endpoint.dci,
        alloc::boxed::Box::new(move |code, residual| {
            if d.gone.load(Ordering::Acquire) {
                return;
            }
            if code != CC_SUCCESS && code != CC_SHORT_PACKET {
                log_warn!("USB mouse on port {}: transfer error {code}", d.port);
                return;
            }
            let got = len.saturating_sub(residual as usize);
            let mut r = [0u8; 8];
            buf.copy_out(0, &mut r);
            let old = buttons.swap(r[0], Ordering::Relaxed);
            for (bit, b) in [(1, BTN_LEFT), (2, BTN_RIGHT), (4, BTN_MIDDLE), (8, BTN_SIDE), (16, BTN_EXTRA)] {
                if (old ^ r[0]) & bit != 0 {
                    mouse.key(b, r[0] & bit != 0);
                }
            }
            // X and Y are signed counts, Y positive down (as evdev's); the
            // wheel is positive away from the user (up, as evdev's).
            let (dx, dy) = (i32::from(r[1] as i8), i32::from(r[2] as i8));
            if dx != 0 {
                mouse.emit(input::EV_REL, input::REL_X, dx);
            }
            if dy != 0 {
                mouse.emit(input::EV_REL, input::REL_Y, dy);
            }
            if got >= 4 && r[3] != 0 {
                mouse.emit(input::EV_REL, input::REL_WHEEL, i32::from(r[3] as i8));
            }
            mouse.sync();
            d.queue(&e, phys, len);
        }),
    );
    dev.queue(&endpoint, phys, len);
    log_info!("USB port {}: mouse", dev.port);
}

/// What a report value becomes.
#[derive(Clone, Copy, Debug)]
enum Action {
    Button(u16),
    Abs(u16),
    Rel(u16),
}

/// The LED page (HID Usage Tables §11): Num Lock, Caps Lock, Scroll Lock
/// are usages 1-3, evdev's LEDs 0-2.
const LED_USAGES: [u16; 3] = [1, 2, 3];

/// The output report that shows evdev's LED bits `leds`, if the
/// descriptor has one with lights: SET_REPORT's value (output, its ID)
/// and the report (its ID byte first when there are IDs).
fn led_report(desc: &slate_hid::Descriptor, leds: u8) -> Option<(u16, Vec<u8>)> {
    let led = |i: usize| slate_hid::usage(slate_hid::PAGE_LED, LED_USAGES[i]);
    let fields: Vec<&slate_hid::Field> = desc
        .fields
        .iter()
        .filter(|f| f.kind == slate_hid::Kind::Output && f.is_variable())
        .filter(|f| (0..f.count).any(|i| (0..3).any(|l| f.usage_of(i) == Some(led(l)))))
        .collect();
    let id = fields.first()?.report_id;
    let skip = usize::from(desc.report_ids);
    let mut report = alloc::vec![0u8; skip + desc.report_len(slate_hid::Kind::Output, id)];
    if desc.report_ids {
        report[0] = id;
    }
    for f in fields.iter().filter(|f| f.report_id == id) {
        for i in 0..f.count {
            if let Some(l) = (0..3).find(|&l| f.usage_of(i) == Some(led(l)))
                && leds & (1 << l) != 0
            {
                let bit = (f.offset + i * f.size) as usize;
                report[skip + bit / 8] |= 1 << (bit % 8);
            }
        }
    }
    Some((OUTPUT_REPORT | u16::from(id), report))
}

/// Whether input usage `u` is a key Slate turns into evdev.
fn is_key(u: u32) -> bool {
    key_of(u).is_some()
}

/// Set up a report-protocol HID device from its report descriptor: keys
/// (keyboard, consumer and system controls) become a keyboard, X and Y a
/// pointer; a device may be both. Returns false if the descriptor could
/// not be read (a boot keyboard then uses the boot protocol).
pub fn start_report(dev: &Arc<UsbDevice>, iface: &InterfaceDesc, (vendor, product): (u16, u16)) -> bool {
    use slate_hid::{GD_WHEEL, GD_X, GD_Y, PAGE_BUTTON, PAGE_CONSUMER, PAGE_GENERIC_DESKTOP, usage};
    let Some(ep) = iface.endpoints.iter().find(|e| e.kind == EP_INTERRUPT && e.is_in()).copied() else {
        return false;
    };
    let index = u16::from(iface.number);
    let want = iface.report_len.map_or(REPORT_DESCRIPTOR_MAX, usize::from).clamp(1, 4096);
    let mut raw = alloc::vec![0u8; want];
    let desc = match dev.control(RT_INTERFACE_IN, REQ_GET_DESCRIPTOR, DESC_REPORT << 8, index, &mut raw) {
        Ok(n) => slate_hid::parse(&raw[..n.min(raw.len())]),
        Err(code) => {
            log_warn!("USB port {}: HID interface {index}: no report descriptor (completion {code})", dev.port);
            return false;
        }
    };
    let desc = match desc {
        Ok(d) => d,
        Err(e) => {
            log_warn!("USB port {}: HID interface {index}: bad report descriptor ({e:?})", dev.port);
            return false;
        }
    };
    let desc = Arc::new(desc);
    let gd = |u| usage(PAGE_GENERIC_DESKTOP, u);
    let keys = desc
        .fields
        .iter()
        .filter(|f| f.kind == slate_hid::Kind::Input && !f.is_constant())
        .any(|f| f.usages.iter().any(|&u| is_key(u)));
    let pointer_axes = desc.find_input(gd(GD_X)).zip(desc.find_input(gd(GD_Y)));
    if !keys && pointer_axes.is_none() {
        log_info!(
            "USB port {}: HID interface {index} ({:x?}): no keys and no pointer; not supported",
            dev.port,
            desc.applications
        );
        // Handled: no boot protocol to fall back to for what it is.
        return true;
    }
    let Some(eps) = dev.configure(&[ep]) else { return true };
    if iface.subclass == 1 {
        // A boot interface: make sure it reports as its descriptor says
        // (HID 1.11 §7.2.6).
        let _ = dev.control(RT_CLASS_INTERFACE_OUT, SET_PROTOCOL, REPORT_PROTOCOL, index, &mut []);
    }
    // Reports only when something changes.
    let _ = dev.control(RT_CLASS_INTERFACE_OUT, SET_IDLE, 0, index, &mut []);

    let keyboard = keys.then(|| {
        let d = desc.clone();
        let leds = led_report(&desc, 0).is_some();
        keyboard_device(dev, iface, (vendor, product), leds, move |l| {
            led_report(&d, l).unwrap_or((OUTPUT_REPORT, alloc::vec![l]))
        })
    });

    let mut map: Vec<(usize, u32, Action)> = Vec::new();
    let mut name = "USB Mouse";
    let pointer = pointer_axes.map(|((x, xi), (y, yi))| {
        let absolute = !x.is_relative();
        let field = |f: &slate_hid::Field| desc.fields.iter().position(|g| core::ptr::eq(g, f)).unwrap_or(0);
        let mut caps = Caps { props: 1 << input::INPUT_PROP_POINTER, ..Caps::default() };
        if absolute {
            for (f, i, code) in [(x, xi, input::ABS_X), (y, yi, input::ABS_Y)] {
                let info =
                    input::AbsInfo { minimum: f.logical_min, maximum: f.logical_max, ..input::AbsInfo::default() };
                caps.abs.push((code, info));
                map.push((field(f), i, Action::Abs(code)));
            }
        } else {
            for (f, i, code) in [(x, xi, input::REL_X), (y, yi, input::REL_Y)] {
                caps.rel.push(code);
                map.push((field(f), i, Action::Rel(code)));
            }
        }
        for (u, code) in
            [(gd(GD_WHEEL), input::REL_WHEEL), (usage(PAGE_CONSUMER, slate_hid::CONSUMER_AC_PAN), input::REL_HWHEEL)]
        {
            if let Some((f, i)) = desc.find_input(u) {
                caps.rel.push(code);
                map.push((field(f), i, Action::Rel(code)));
            }
        }
        for (b, code) in [(1, BTN_LEFT), (2, BTN_RIGHT), (3, BTN_MIDDLE), (4, BTN_SIDE), (5, BTN_EXTRA)] {
            if let Some((f, i)) = desc.find_input(usage(PAGE_BUTTON, b)) {
                caps.keys.push(code);
                map.push((field(f), i, Action::Button(code)));
            }
        }
        name = if absolute { "USB Tablet" } else { "USB Mouse" };
        input::register(Info {
            name: name.into(),
            phys: alloc::format!("usb-{}/input{}", dev.port, iface.number),
            bustype: BUS_USB,
            vendor,
            product,
            version: 0x0111,
            caps,
        })
    });

    let Some(buf) = Dma::new(64) else { return true };
    let endpoint: Arc<Endpoint> = eps[0].clone();
    let (d, e) = (dev.clone(), endpoint.clone());
    let len = usize::from(ep.max_packet).clamp(1, 64);
    let phys = buf.phys();
    let buf = Arc::new(buf);
    // Per report ID: the keys it held, and the pointer buttons.
    let state = IrqSpinLock::new((alloc::collections::BTreeMap::<u8, Vec<u32>>::new(), 0u32));
    let fields = desc.fields.len();
    let has_keyboard = keyboard.is_some();
    let kbd = keyboard.clone();
    let rd = desc.clone();
    dev.hc.set_pipe(
        dev.slot,
        endpoint.dci,
        alloc::boxed::Box::new(move |code, residual| {
            if d.gone.load(Ordering::Acquire) {
                return;
            }
            if code != CC_SUCCESS && code != CC_SHORT_PACKET {
                log_warn!("USB HID device on port {}: transfer error {code}", d.port);
                return;
            }
            let got = len.saturating_sub(residual as usize);
            let mut r = [0u8; 64];
            buf.copy_out(0, &mut r[..len]);
            let (id, data) = if rd.report_ids { (r[0], &r[1..got.max(1)]) } else { (0, &r[..got]) };
            let mut st = state.lock();
            if let Some(kbd) = &kbd
                && let Some(now) = rd.pressed(id, data)
            {
                let now: Vec<u32> = now.into_iter().filter(|&u| is_key(u)).collect();
                let last = st.0.entry(id).or_default();
                if *last != now {
                    keys_changed(kbd, last, &now);
                    *last = now;
                }
            }
            if let Some(pointer) = &pointer {
                let mut any = false;
                for (bit, &(fi, i, action)) in map.iter().enumerate() {
                    let f = &rd.fields[fi];
                    if f.report_id != id {
                        continue;
                    }
                    let Some(v) = f.value(data, i) else { continue };
                    any = true;
                    match action {
                        Action::Abs(c) => pointer.emit(input::EV_ABS, c, v),
                        Action::Rel(c) if v != 0 => pointer.emit(input::EV_REL, c, v),
                        Action::Rel(_) => {}
                        Action::Button(c) => {
                            // Buttons are reported in every report; evdev
                            // hears changes only.
                            let (was, is) = (st.1 & (1 << bit) != 0, v != 0);
                            if was != is {
                                st.1 ^= 1 << bit;
                                pointer.key(c, is);
                            }
                        }
                    }
                }
                if any {
                    pointer.sync();
                }
            }
            drop(st);
            d.queue(&e, phys, len);
        }),
    );
    dev.queue(&endpoint, phys, len);
    if has_keyboard {
        log_info!("USB port {}: keyboard", dev.port);
    }
    if pointer_axes.is_some() {
        log_info!("USB port {}: {} ({fields} report fields)", dev.port, name.trim_start_matches("USB ").to_lowercase());
    }
    true
}

pub const TESTS: &[crate::ktest::Test] = &[crate::ktest::Test { name: "usb::hid_keys", run: test_keys }];

/// Usages become the right keys: letters and modifiers for the console,
/// media and system controls for evdev; a boot report's phantom state is
/// ignored.
fn test_keys() -> Result<(), &'static str> {
    use slate_hid::{PAGE_CONSUMER, PAGE_GENERIC_DESKTOP, PAGE_KEYBOARD, usage};
    let cases = [
        (usage(PAGE_KEYBOARD, 0x04), Some(Key::Console(0x1E))),
        (usage(PAGE_KEYBOARD, 0xE1), Some(Key::Console(0x2A))),
        (usage(PAGE_KEYBOARD, 0x52), Some(Key::Console(0xE048))),
        (usage(PAGE_KEYBOARD, 0x01), None),
        (usage(PAGE_CONSUMER, 0xE9), Some(Key::Evdev(115))),
        (usage(PAGE_CONSUMER, 0xCD), Some(Key::Evdev(164))),
        (usage(PAGE_GENERIC_DESKTOP, 0x81), Some(Key::Evdev(116))),
        (usage(PAGE_GENERIC_DESKTOP, 0x30), None),
    ];
    if cases.iter().any(|&(u, k)| key_of(u) != k) {
        return Err("a usage became the wrong key");
    }
    if boot_usages(&[0, 0, 1, 1, 1, 1, 1, 1]).is_some() {
        return Err("the phantom state was not ignored");
    }
    let shift_a = boot_usages(&[0x02, 0, 0x04, 0, 0, 0, 0, 0]);
    if shift_a != Some(alloc::vec![usage(PAGE_KEYBOARD, 0x04), usage(PAGE_KEYBOARD, 0xE1)]) {
        return Err("a boot report read wrongly");
    }
    if !all_keys().contains(&115) || !all_keys().contains(&30) {
        return Err("the keyboard does not offer its keys");
    }
    Ok(())
}
