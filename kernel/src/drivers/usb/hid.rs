// SPDX-License-Identifier: MIT OR Apache-2.0

//! USB keyboards, mice and other HID devices (ADR 0033): the USB side.
//! What their reports mean is `input::hid`'s.
//!
//! Sources: Device Class Definition for HID 1.11 (SET_PROTOCOL and
//! SET_IDLE, §7.2; SET_REPORT, §7.2.2; the report descriptor, asked for
//! with the length the HID descriptor gives, §6.2.1 and §7.1.1; the boot
//! keyboard and mouse reports, appendix B). Keyboards and other HID
//! devices use the report protocol; a boot keyboard whose descriptor
//! cannot be read falls back to the boot protocol, and boot mice use it.
//! Their evdev devices go when the device is unplugged.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::xhci::{CC_SHORT_PACKET, CC_SUCCESS, Endpoint, UsbDevice};
use super::{EP_INTERRUPT, InterfaceDesc, REQ_GET_DESCRIPTOR, RT_CLASS_INTERFACE_OUT};
use crate::drivers::dma::Dma;
use crate::drivers::input::hid::{self, Ident, Reports};
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

/// The evdev devices of USB devices, so an unplugged one's go too.
static DEVICES: IrqSpinLock<Vec<(Weak<UsbDevice>, Arc<input::Device>)>> = IrqSpinLock::new(Vec::new());

fn keep(dev: &Arc<UsbDevice>, d: &Arc<input::Device>) {
    DEVICES.lock().push((Arc::downgrade(dev), d.clone()));
}

/// USB device `dev` was unplugged: its evdev devices go.
pub fn detached(dev: &Arc<UsbDevice>) {
    let gone: Vec<Arc<input::Device>> = {
        let mut all = DEVICES.lock();
        let (gone, kept): (Vec<_>, Vec<_>) =
            all.drain(..).partition(|(d, _)| d.upgrade().is_none_or(|d| Arc::ptr_eq(&d, dev)));
        *all = kept;
        gone.into_iter().map(|(_, i)| i).collect()
    };
    for d in gone {
        input::unregister(&d);
    }
}

fn ident(dev: &UsbDevice, iface: &InterfaceDesc, (vendor, product): (u16, u16)) -> Ident {
    Ident {
        name: alloc::string::String::from("USB"),
        phys: alloc::format!("usb-{}/input{}", dev.port, iface.number),
        bustype: BUS_USB,
        vendor,
        product,
        version: 0x0111,
    }
}

/// Light keyboard `kbd`'s LEDs from a thread (a control transfer waits):
/// `send` turns evdev's LED bits (Num, Caps, Scroll Lock in bits 0-2) into
/// the output report it SET_REPORTs.
fn usb_leds(
    kbd: &Arc<input::Device>,
    dev: &Arc<UsbDevice>,
    iface: &InterfaceDesc,
    send: impl Fn(u8) -> (u16, Vec<u8>) + Send + 'static,
) {
    let wanted = Arc::new(core::sync::atomic::AtomicU32::new(0));
    let wake = Arc::new(crate::sched::wait::WaitQueue::new());
    let (w, q) = (wanted.clone(), wake.clone());
    kbd.set_led_handler(alloc::boxed::Box::new(move |leds| {
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
    let kbd = hid::keyboard_device(&ident(dev, iface, ids), true);
    keep(dev, &kbd);
    usb_leds(&kbd, dev, iface, |leds| (OUTPUT_REPORT, alloc::vec![leds]));
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
            hid::boot_keys(&kbd, &mut last.lock(), &r);
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
    keep(dev, &mouse);
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

/// Set up a report-protocol HID device from its report descriptor: keys
/// (keyboard, consumer and system controls) become a keyboard, X and Y a
/// pointer; a device may be both. Returns false if the descriptor could
/// not be read (a boot keyboard then uses the boot protocol).
pub fn start_report(dev: &Arc<UsbDevice>, iface: &InterfaceDesc, ids: (u16, u16)) -> bool {
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
        Ok(d) => Arc::new(d),
        Err(e) => {
            log_warn!("USB port {}: HID interface {index}: bad report descriptor ({e:?})", dev.port);
            return false;
        }
    };
    let Some(eps) = dev.configure(&[ep]) else { return true };
    let Some(reports) = Reports::new(desc.clone(), &ident(dev, iface, ids)) else {
        log_info!(
            "USB port {}: HID interface {index} ({:x?}): no keys and no pointer; not supported",
            dev.port,
            desc.applications
        );
        // Handled: no boot protocol to fall back to for what it is.
        return true;
    };
    if iface.subclass == 1 {
        // A boot interface: make sure it reports as its descriptor says
        // (HID 1.11 §7.2.6).
        let _ = dev.control(RT_CLASS_INTERFACE_OUT, SET_PROTOCOL, REPORT_PROTOCOL, index, &mut []);
    }
    // Reports only when something changes.
    let _ = dev.control(RT_CLASS_INTERFACE_OUT, SET_IDLE, 0, index, &mut []);
    for d in reports.devices() {
        keep(dev, &d);
    }
    if let Some(kbd) = &reports.keyboard {
        let d = desc.clone();
        usb_leds(kbd, dev, iface, move |l| {
            let r = Reports::led_report_of(&d, l);
            r.map_or((OUTPUT_REPORT, alloc::vec![l]), |(id, rep)| (OUTPUT_REPORT | u16::from(id), rep))
        });
    }
    let (has_keyboard, has_pointer) = (reports.keyboard.is_some(), reports.pointer.is_some());
    let (fields, kind) = (desc.fields.len(), reports.pointer_kind);

    let Some(buf) = Dma::new(64) else { return true };
    let endpoint: Arc<Endpoint> = eps[0].clone();
    let (d, e) = (dev.clone(), endpoint.clone());
    let len = usize::from(ep.max_packet).clamp(1, 64);
    let phys = buf.phys();
    let buf = Arc::new(buf);
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
            reports.report(&r[..got]);
            d.queue(&e, phys, len);
        }),
    );
    dev.queue(&endpoint, phys, len);
    if has_keyboard {
        log_info!("USB port {}: keyboard", dev.port);
    }
    if has_pointer {
        log_info!("USB port {}: {kind} ({fields} report fields)", dev.port);
    }
    true
}
