// SPDX-License-Identifier: MIT OR Apache-2.0

//! HID devices whatever carries them (USB, Bluetooth through
//! /dev/slate-hid): what their report descriptors say becomes evdev
//! devices, and each report becomes events (ADR 0033, ADR 0039, ADR 0176).
//!
//! Sources: Device Class Definition for HID 1.11 (the boot keyboard
//! report, appendix B.1), HID Usage Tables 1.4 (keyboard page 07h), and
//! Microsoft's "USB HID to PS/2 Scan Code Translation Table", which maps
//! each usage to the scan code set 1 code that `slate_term::keyboard`
//! already decodes for the PS/2 keyboard.
//!
//! Reports are compared with the previous one: new keys are pressed,
//! missing keys released. HID keyboards do not repeat by themselves, so a
//! key held for 500 ms repeats every 33 ms, as a PS/2 keyboard would (on
//! the console only: compositors repeat keys themselves).
//!
//! A report descriptor (parsed by `slate_hid`) says where the keys, X, Y,
//! the buttons and the wheels are. Each report is the set of usages it
//! holds down, compared with that report's last: keyboard keys go to the
//! console and evdev, consumer controls (media keys, HID Usage Tables 1.4
//! §15) and system controls (power, sleep, wake; §4.5) to evdev only.
//! Pointers, absolute (the tablets virtual machines offer) or relative,
//! become evdev devices (ADR 0039).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use slate_term::keyboard::Keyboard;

use super::{self as input, BTN_EXTRA, BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, BTN_SIDE, Caps, Info};
use crate::sync::IrqSpinLock;

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
/// descriptor has one with lights: its ID and the report (its ID byte
/// first when there are IDs).
fn led_report(desc: &slate_hid::Descriptor, leds: u8) -> Option<(u8, Vec<u8>)> {
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
    Some((id, report))
}

/// Whether input usage `u` is a key Slate turns into evdev.
fn is_key(u: u32) -> bool {
    key_of(u).is_some()
}

/// Who a HID device is, for its evdev devices: `name` is what their names
/// start with ("USB" for USB's, the device's own name for Bluetooth's).
#[derive(Clone, Debug)]
pub struct Ident {
    pub name: String,
    pub phys: String,
    pub bustype: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
}

impl Ident {
    fn info(&self, what: &str, caps: Caps) -> Info {
        Info {
            name: alloc::format!("{} {what}", self.name),
            phys: self.phys.clone(),
            bustype: self.bustype,
            vendor: self.vendor,
            product: self.product,
            version: self.version,
            caps,
        }
    }
}

/// A keyboard's evdev device, its lights in its capabilities when `leds`
/// (the transport lights them: `Device::set_led_handler`).
pub fn keyboard_device(id: &Ident, leds: bool) -> Arc<input::Device> {
    input::register(id.info(
        "Keyboard",
        Caps {
            keys: all_keys(),
            leds: if leds { alloc::vec![0, 1, 2] } else { Vec::new() },
            rep: true,
            ..Caps::default()
        },
    ))
}

/// A keyboard reporting boot reports (appendix B.1) changed keys: `last`
/// is what its previous report held.
pub fn boot_keys(kbd: &input::Device, last: &mut Vec<u32>, r: &[u8; 8]) {
    if let Some(now) = boot_usages(r) {
        keys_changed(kbd, last, &now);
        *last = now;
    }
}

/// A HID device in the report protocol: its evdev devices (a keyboard, a
/// pointer, or both) and what each report field becomes.
pub struct Reports {
    pub desc: Arc<slate_hid::Descriptor>,
    pub keyboard: Option<Arc<input::Device>>,
    pub pointer: Option<Arc<input::Device>>,
    /// "mouse" or "tablet", for messages.
    pub pointer_kind: &'static str,
    map: Vec<(usize, u32, Action)>,
    /// Per report ID: the keys it held; and the pointer's buttons down.
    state: IrqSpinLock<(BTreeMap<u8, Vec<u32>>, u32)>,
}

impl Reports {
    /// The evdev devices for `desc`; None when it has neither keys nor a
    /// pointer (nothing Slate supports).
    pub fn new(desc: Arc<slate_hid::Descriptor>, id: &Ident) -> Option<Reports> {
        Reports::with(desc, id, false)
    }

    /// [`Reports::new`], with no keyboard when `pointer_only` (a device
    /// nobody chose may point but not type).
    pub fn with(desc: Arc<slate_hid::Descriptor>, id: &Ident, pointer_only: bool) -> Option<Reports> {
        use slate_hid::{GD_WHEEL, GD_X, GD_Y, PAGE_BUTTON, PAGE_CONSUMER, PAGE_GENERIC_DESKTOP, usage};
        let gd = |u| usage(PAGE_GENERIC_DESKTOP, u);
        let keys = !pointer_only
            && desc
                .fields
                .iter()
                .filter(|f| f.kind == slate_hid::Kind::Input && !f.is_constant())
                .any(|f| f.usages.iter().any(|&u| is_key(u)));
        let pointer_axes = desc.find_input(gd(GD_X)).zip(desc.find_input(gd(GD_Y)));
        if !keys && pointer_axes.is_none() {
            return None;
        }
        let keyboard = keys.then(|| keyboard_device(id, led_report(&desc, 0).is_some()));
        let mut map: Vec<(usize, u32, Action)> = Vec::new();
        let mut pointer_kind = "mouse";
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
            for (u, code) in [
                (gd(GD_WHEEL), input::REL_WHEEL),
                (usage(PAGE_CONSUMER, slate_hid::CONSUMER_AC_PAN), input::REL_HWHEEL),
            ] {
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
            pointer_kind = if absolute { "tablet" } else { "mouse" };
            input::register(id.info(if absolute { "Tablet" } else { "Mouse" }, caps))
        });
        Some(Reports { desc, keyboard, pointer, pointer_kind, map, state: IrqSpinLock::new((BTreeMap::new(), 0)) })
    }

    /// One input report (its ID byte first when the descriptor names IDs).
    pub fn report(&self, raw: &[u8]) {
        let rd = &self.desc;
        let (id, data) = if rd.report_ids {
            match raw.split_first() {
                Some((&id, rest)) => (id, rest),
                None => return,
            }
        } else {
            (0, raw)
        };
        let mut st = self.state.lock();
        if let Some(kbd) = &self.keyboard
            && let Some(now) = rd.pressed(id, data)
        {
            let now: Vec<u32> = now.into_iter().filter(|&u| is_key(u)).collect();
            let last = st.0.entry(id).or_default();
            if *last != now {
                keys_changed(kbd, last, &now);
                *last = now;
            }
        }
        if let Some(pointer) = &self.pointer {
            let mut any = false;
            for (bit, &(fi, i, action)) in self.map.iter().enumerate() {
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
    }

    /// The output report that shows evdev's LED bits `leds`: its ID (0
    /// without IDs) and the report, its ID byte first when there are IDs.
    pub fn led_report(&self, leds: u8) -> Option<(u8, Vec<u8>)> {
        led_report(&self.desc, leds)
    }

    /// [`Reports::led_report`] for descriptor `desc`.
    pub fn led_report_of(desc: &slate_hid::Descriptor, leds: u8) -> Option<(u8, Vec<u8>)> {
        led_report(desc, leds)
    }

    /// Its evdev devices.
    pub fn devices(&self) -> Vec<Arc<input::Device>> {
        self.keyboard.iter().chain(self.pointer.iter()).cloned().collect()
    }

    /// The device went: so do its evdev devices.
    pub fn unregister(&self) {
        for d in self.devices() {
            input::unregister(&d);
        }
    }
}

pub const TESTS: &[crate::ktest::Test] = &[
    crate::ktest::Test { name: "input::hid_keys", run: test_keys },
    crate::ktest::Test { name: "input::hid_reports", run: test_reports },
];

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

/// A mouse's report descriptor (HID 1.11 appendix E.10's, with a wheel)
/// becomes a pointer whose reports become events, and it goes again.
fn test_reports() -> Result<(), &'static str> {
    const MOUSE: [u8; 52] = [
        0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x09, 0x01, 0xA1, 0x00, 0x05, 0x09, 0x19, 0x01, 0x29, 0x03, 0x15, 0x00,
        0x25, 0x01, 0x95, 0x03, 0x75, 0x01, 0x81, 0x02, 0x95, 0x01, 0x75, 0x05, 0x81, 0x01, 0x05, 0x01, 0x09, 0x30,
        0x09, 0x31, 0x09, 0x38, 0x15, 0x81, 0x25, 0x7F, 0x75, 0x08, 0x95, 0x03, 0x81, 0x06, 0xC0, 0xC0,
    ];
    let desc = Arc::new(slate_hid::parse(&MOUSE).map_err(|_| "the descriptor didn't parse")?);
    let id = Ident {
        name: String::from("Test HID"),
        phys: String::from("test"),
        bustype: input::BUS_BLUETOOTH,
        vendor: 1,
        product: 2,
        version: 1,
    };
    let r = Reports::new(desc, &id).ok_or("no devices")?;
    let p = r.pointer.clone().ok_or("no pointer")?;
    if r.keyboard.is_some() || r.pointer_kind != "mouse" {
        return Err("the wrong devices");
    }
    let c = input::test_client(&p);
    r.report(&[0x01, 5, 0xFD, 1]);
    let got = c.taken();
    // Axes first, then the buttons that changed, as the map has them.
    let want = [
        (input::EV_REL, input::REL_X, 5),
        (input::EV_REL, input::REL_Y, -3),
        (input::EV_REL, input::REL_WHEEL, 1),
        (input::EV_KEY, BTN_LEFT, 1),
        (input::EV_SYN, 0, 0),
    ];
    if got != want {
        return Err("the report became the wrong events");
    }
    r.unregister();
    if input::exists(p.index) {
        return Err("the pointer stayed");
    }
    Ok(())
}
