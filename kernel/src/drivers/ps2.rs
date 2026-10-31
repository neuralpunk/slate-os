// SPDX-License-Identifier: MIT OR Apache-2.0

//! PS/2 keyboard and mouse on the i8042 controller (ports 0x60/0x64, ISA
//! IRQs 1 and 12).
//!
//! The controller protocol (status bits, configuration byte, the 0x20/0x60
//! read/write-configuration, 0xA7/0xA8 and 0xAD/0xAE disable/enable-port
//! and 0xD4 write-to-mouse commands) and the mouse protocol (0xF6 defaults,
//! 0xF3 sample rate, 0xF2 identify, 0xF4 enable reporting, the 3-byte
//! packet and the IntelliMouse 200/100/80 sample-rate sequence that
//! enables a fourth, wheel byte) follow the IBM PC/AT technical reference
//! as documented on the OSDev wiki. Translation stays on, so the keyboard
//! delivers scancode set 1, which `slate_term::keyboard` decodes for the
//! console. Both also report to evdev (ADR 0033).

use alloc::sync::Arc;

use slate_term::keyboard::Keyboard;

use crate::arch::port::Port8;
use crate::drivers::input::{self, BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, BUS_I8042, Caps, Info, REL_WHEEL, REL_X, REL_Y};
use crate::sync::IrqSpinLock;

const DATA: u16 = 0x60;
const STATUS: u16 = 0x64;
const COMMAND: u16 = 0x64;

const OUTPUT_FULL: u8 = 1 << 0;
const INPUT_FULL: u8 = 1 << 1;
const AUX_DATA: u8 = 1 << 5;

const CMD_READ_CONFIG: u8 = 0x20;
const CMD_WRITE_CONFIG: u8 = 0x60;
const CMD_DISABLE_PORT2: u8 = 0xA7;
const CMD_ENABLE_PORT2: u8 = 0xA8;
const CMD_DISABLE_PORT1: u8 = 0xAD;
const CMD_ENABLE_PORT1: u8 = 0xAE;
const CMD_WRITE_PORT2: u8 = 0xD4;

const CONFIG_IRQ1: u8 = 1 << 0;
const CONFIG_IRQ12: u8 = 1 << 1;
const CONFIG_PORT2_CLOCK_OFF: u8 = 1 << 5;
const CONFIG_TRANSLATE: u8 = 1 << 6;

const KEYBOARD_IRQ: u8 = 1;
const MOUSE_IRQ: u8 = 12;

// Mouse commands and replies.
const MOUSE_DEFAULTS: u8 = 0xF6;
const MOUSE_SAMPLE_RATE: u8 = 0xF3;
const MOUSE_IDENTIFY: u8 = 0xF2;
const MOUSE_ENABLE: u8 = 0xF4;
const ACK: u8 = 0xFA;
/// The IntelliMouse identity: packets carry a wheel byte.
const ID_WHEEL: u8 = 3;

static KEYBOARD: IrqSpinLock<Keyboard> = IrqSpinLock::new(Keyboard::new_const());
/// Caps Lock as the keyboard's light last showed it.
static CAPS: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// The LED mask to send once the keyboard acknowledges Set LEDs; NO_MASK
/// when none is waiting.
static LED_MASK: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(NO_MASK);
const NO_MASK: u16 = 0xFFFF;
/// The keyboard's Set LEDs command, and its "resend" reply.
const SET_LEDS: u8 = 0xED;
const RESEND: u8 = 0xFE;

struct Evdev {
    keyboard: Arc<input::Device>,
    mouse: Option<Arc<input::Device>>,
    /// The keyboard's 0xE0 prefix is pending.
    extended: bool,
    packet: [u8; 4],
    len: usize,
    packet_len: usize,
    buttons: u8,
}

static EVDEV: IrqSpinLock<Option<Evdev>> = IrqSpinLock::new(None);

fn port(p: u16) -> Port8 {
    // SAFETY: 0x60 and 0x64 are the i8042 data and status/command ports;
    // accessing them only affects the keyboard controller.
    unsafe { Port8::new(p) }
}

fn wait_input_clear() -> bool {
    (0..100_000).any(|_| port(STATUS).read() & INPUT_FULL == 0)
}

fn wait_output_full() -> bool {
    (0..100_000).any(|_| port(STATUS).read() & OUTPUT_FULL != 0)
}

fn command(c: u8) -> bool {
    if !wait_input_clear() {
        return false;
    }
    port(COMMAND).write(c);
    true
}

/// A byte from the mouse, by polling (setup runs before interrupts).
fn mouse_read() -> Option<u8> {
    for _ in 0..200_000 {
        let s = port(STATUS).read();
        if s & OUTPUT_FULL != 0 {
            let b = port(DATA).read();
            if s & AUX_DATA != 0 {
                return Some(b);
            }
        }
    }
    None
}

/// Send `b` to the mouse and wait for its acknowledgement.
fn mouse_send(b: u8) -> bool {
    command(CMD_WRITE_PORT2) && wait_input_clear() && {
        port(DATA).write(b);
        mouse_read() == Some(ACK)
    }
}

/// Set up the mouse; returns its packet length (3, or 4 with a wheel).
fn mouse_init() -> Option<usize> {
    if !command(CMD_ENABLE_PORT2) || !mouse_send(MOUSE_DEFAULTS) {
        return None;
    }
    for rate in [200, 100, 80] {
        if !mouse_send(MOUSE_SAMPLE_RATE) || !mouse_send(rate) {
            return None;
        }
    }
    let id = if mouse_send(MOUSE_IDENTIFY) { mouse_read()? } else { 0 };
    if !mouse_send(MOUSE_ENABLE) {
        return None;
    }
    Some(if id == ID_WHEEL { 4 } else { 3 })
}

/// Probe and set up the controller, keyboard and mouse. Returns false if
/// there is no i8042.
pub fn init() -> bool {
    if port(STATUS).read() == 0xFF {
        return false; // Floating bus: no controller.
    }
    if !command(CMD_DISABLE_PORT1) || !command(CMD_DISABLE_PORT2) {
        return false;
    }
    while port(STATUS).read() & OUTPUT_FULL != 0 {
        port(DATA).read();
    }
    if !command(CMD_READ_CONFIG) || !wait_output_full() {
        return false;
    }
    let mut config = port(DATA).read();
    // Interrupts off while the mouse is set up by polling.
    config &= !(CONFIG_IRQ1 | CONFIG_IRQ12 | CONFIG_PORT2_CLOCK_OFF);
    config |= CONFIG_TRANSLATE;
    if !command(CMD_WRITE_CONFIG) || !wait_input_clear() {
        return false;
    }
    port(DATA).write(config);
    let mouse = mouse_init();
    config |= CONFIG_IRQ1;
    match mouse {
        Some(_) => config |= CONFIG_IRQ12,
        None => {
            command(CMD_DISABLE_PORT2);
            config |= CONFIG_PORT2_CLOCK_OFF;
        }
    }
    if !command(CMD_WRITE_CONFIG) || !wait_input_clear() {
        return false;
    }
    port(DATA).write(config);

    let keyboard = input::register(Info {
        name: "AT Translated Set 2 keyboard".into(),
        phys: "isa0060/serio0/input0".into(),
        bustype: BUS_I8042,
        vendor: 1,
        product: 1,
        version: 0xab41,
        caps: Caps { keys: input::keyboard_keys(), leds: alloc::vec![0, 1, 2], rep: true, ..Caps::default() },
    });
    // The lights: Set LEDs (EDh), then the mask once the keyboard
    // acknowledges (`keyboard_byte`). The mask has Scroll, Num and Caps
    // Lock in bits 0-2.
    keyboard.set_led_handler(alloc::boxed::Box::new(|leds| {
        let bit = |code: u16, to: u8| -> u8 { if leds & (1 << code) != 0 { 1 << to } else { 0 } };
        let mask = bit(input::LED_SCROLLL, 0) | bit(input::LED_NUML, 1) | bit(input::LED_CAPSL, 2);
        LED_MASK.store(u16::from(mask), core::sync::atomic::Ordering::Release);
        if wait_input_clear() {
            port(DATA).write(SET_LEDS);
        }
    }));
    let mouse_dev = mouse.map(|len| {
        crate::log_info!("ps2: mouse{}", if len == 4 { " with a wheel" } else { "" });
        let mut rel = alloc::vec![REL_X, REL_Y];
        if len == 4 {
            rel.push(REL_WHEEL);
        }
        input::register(Info {
            name: if len == 4 { "ImPS/2 Generic Wheel Mouse".into() } else { "PS/2 Generic Mouse".into() },
            phys: "isa0060/serio1/input0".into(),
            bustype: BUS_I8042,
            vendor: 2,
            product: if len == 4 { 3 } else { 1 },
            version: 0,
            caps: Caps {
                keys: alloc::vec![BTN_LEFT, BTN_RIGHT, BTN_MIDDLE],
                rel,
                props: 1 << input::INPUT_PROP_POINTER,
                ..Caps::default()
            },
        })
    });
    *EVDEV.lock() = Some(Evdev {
        keyboard,
        mouse: mouse_dev,
        extended: false,
        packet: [0; 4],
        len: 0,
        packet_len: mouse.unwrap_or(3),
        buttons: 0,
    });
    if !command(CMD_ENABLE_PORT1) {
        return false;
    }
    crate::arch::irq::register_isa(KEYBOARD_IRQ, "i8042", interrupt);
    if mouse.is_some() {
        crate::arch::irq::register_isa(MOUSE_IRQ, "i8042", interrupt);
    }
    true
}

/// One byte from the keyboard: to evdev, and to the console unless a
/// compositor has the keyboard.
fn keyboard_byte(ev: &mut Evdev, code: u8) {
    // Replies to Set LEDs are not keys: after its acknowledgement, the
    // mask.
    if code == ACK || code == RESEND {
        let mask = LED_MASK.swap(NO_MASK, core::sync::atomic::Ordering::AcqRel);
        if code == ACK && mask != NO_MASK && wait_input_clear() {
            port(DATA).write(mask as u8);
        }
        return;
    }
    let mut ext = false;
    if code == 0xE0 {
        ev.extended = true;
    } else {
        let extended = core::mem::take(&mut ev.extended);
        ext = extended;
        let key = input::set1_to_evdev(code & 0x7F, extended);
        if key != 0 {
            ev.keyboard.key(key, code & 0x80 == 0);
            ev.keyboard.sync();
        }
    }
    let (bytes, caps) = {
        let mut k = KEYBOARD.lock();
        k.set_layout(crate::drivers::input::layout());
        (k.scancode(code), k.caps_lock())
    };
    if CAPS.swap(caps, core::sync::atomic::Ordering::Relaxed) != caps {
        input::console_caps_lock(caps);
    }
    // To the virtual console in front, unless the key switches VTs (ADR
    // 0185).
    let console = input::console_input();
    if code != 0xE0 && !crate::fs::vt::key(code, ext, console) && console {
        crate::fs::vt::type_bytes(&bytes);
    }
}

/// One byte from the mouse: assemble packets and report them.
fn mouse_byte(ev: &mut Evdev, b: u8) {
    // The first byte always has bit 3 set: resynchronise on it.
    if ev.len == 0 && b & 0x08 == 0 {
        return;
    }
    ev.packet[ev.len] = b;
    ev.len += 1;
    if ev.len < ev.packet_len {
        return;
    }
    ev.len = 0;
    let Some(m) = ev.mouse.clone() else { return };
    let p = ev.packet;
    let buttons = p[0] & 7;
    for (bit, code) in [(1, BTN_LEFT), (2, BTN_RIGHT), (4, BTN_MIDDLE)] {
        if (buttons ^ ev.buttons) & bit != 0 {
            m.key(code, buttons & bit != 0);
        }
    }
    ev.buttons = buttons;
    // Overflowed movement is meaningless (bits 6 and 7).
    if p[0] & 0xC0 == 0 {
        let dx = i32::from(p[1]) - if p[0] & 0x10 != 0 { 256 } else { 0 };
        let dy = i32::from(p[2]) - if p[0] & 0x20 != 0 { 256 } else { 0 };
        if dx != 0 {
            m.emit(input::EV_REL, REL_X, dx);
        }
        // PS/2 counts up as positive; evdev counts down.
        if dy != 0 {
            m.emit(input::EV_REL, REL_Y, -dy);
        }
    }
    if ev.packet_len == 4 {
        // A signed 4-bit wheel count, positive towards the user (down);
        // evdev's REL_WHEEL is positive up.
        let z = i32::from((p[3] & 0x0F) as i8) - if p[3] & 0x08 != 0 { 16 } else { 0 };
        if z != 0 {
            m.emit(input::EV_REL, REL_WHEEL, -z);
        }
    }
    m.sync();
}

fn interrupt() {
    while port(STATUS).read() & OUTPUT_FULL != 0 {
        let status = port(STATUS).read();
        let code = port(DATA).read();
        let mut g = EVDEV.lock();
        let Some(ev) = g.as_mut() else { continue };
        if status & AUX_DATA != 0 {
            mouse_byte(ev, code);
        } else {
            keyboard_byte(ev, code);
        }
    }
}
