// SPDX-License-Identifier: MIT OR Apache-2.0

//! virtio-input (VIRTIO 1.2 §5.8): keyboards, mice and tablets whose
//! events already are evdev events. The device describes itself through
//! its configuration space (name, IDs, the bits of each event type, the
//! ranges of absolute axes) and fills the event queue with
//! `virtio_input_event`s, which go straight to its evdev device (ADR 0033).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{Transport, Virtqueue, segments};
use crate::drivers::input::{self, AbsInfo, Caps, EV_ABS, EV_KEY, EV_LED, EV_REL, Info};
use crate::drivers::pci::Device;
use crate::log_info;
use crate::sync::IrqSpinLock;

// Configuration selectors (§5.8.4).
const CFG_ID_NAME: u8 = 0x01;
const CFG_ID_DEVIDS: u8 = 0x03;
const CFG_PROP_BITS: u8 = 0x10;
const CFG_EV_BITS: u8 = 0x11;
const CFG_ABS_INFO: u8 = 0x12;
// Layout of struct virtio_input_config: select, subsel, size, 5 reserved
// bytes, then the 128-byte union.
const OFF_SELECT: usize = 0;
const OFF_SUBSEL: usize = 1;
const OFF_SIZE: usize = 2;
const OFF_DATA: usize = 8;

const EVENT_BUFFERS: usize = 64;

/// The configuration bytes for (`select`, `subsel`).
fn config(t: &Transport, select: u8, subsel: u8) -> Vec<u8> {
    t.config_w8(OFF_SELECT, select);
    t.config_w8(OFF_SUBSEL, subsel);
    let size = usize::from(t.config_r8(OFF_SIZE)).min(128);
    (0..size).map(|i| t.config_r8(OFF_DATA + i)).collect()
}

/// The codes set in a bitmap.
fn codes(bits: &[u8]) -> Vec<u16> {
    (0..bits.len() * 8).filter(|&i| bits[i / 8] & (1 << (i % 8)) != 0).map(|i| i as u16).collect()
}

struct VirtioInput {
    _transport: Transport,
    queue: Virtqueue,
    bufs: IrqSpinLock<BTreeMap<u16, Box<[u8; 8]>>>,
    dev: Arc<input::Device>,
}

impl VirtioInput {
    fn post(&self, buf: Box<[u8; 8]>) {
        let mut segs = Vec::new();
        segments(buf.as_ptr(), 8, true, &mut segs);
        if let Some(h) = self.queue.post(&segs) {
            self.bufs.lock().insert(h, buf);
        }
    }

    /// Deliver what the device wrote and give the buffers back.
    fn interrupt(&self) {
        let used = self.queue.take_used();
        let done: Vec<Box<[u8; 8]>> = {
            let mut bufs = self.bufs.lock();
            used.into_iter().filter_map(|(h, _)| bufs.remove(&h)).collect()
        };
        for b in done {
            // virtio_input_event: le16 type, le16 code, le32 value.
            let ty = u16::from_le_bytes([b[0], b[1]]);
            let code = u16::from_le_bytes([b[2], b[3]]);
            let value = i32::from_le_bytes([b[4], b[5], b[6], b[7]]);
            self.dev.emit(ty, code, value);
            self.post(b);
        }
        self.queue.kick();
    }
}

/// Bring up one virtio-input device as an evdev device.
pub fn probe(pci: Arc<Device>) -> Option<()> {
    let transport = Transport::new(pci)?;
    transport.init(0)?;
    let name = String::from_utf8_lossy(&config(&transport, CFG_ID_NAME, 0)).into_owned();
    let ids = config(&transport, CFG_ID_DEVIDS, 0);
    let id = |i: usize| ids.get(i * 2..i * 2 + 2).map_or(0, |b| u16::from_le_bytes([b[0], b[1]]));
    let props = config(&transport, CFG_PROP_BITS, 0);
    let mut caps = Caps {
        keys: codes(&config(&transport, CFG_EV_BITS, EV_KEY as u8)),
        rel: codes(&config(&transport, CFG_EV_BITS, EV_REL as u8)),
        leds: codes(&config(&transport, CFG_EV_BITS, EV_LED as u8)),
        props: props.first().map_or(0, |&p| u32::from(p)),
        ..Caps::default()
    };
    for axis in codes(&config(&transport, CFG_EV_BITS, EV_ABS as u8)) {
        // virtio_input_absinfo: min, max, fuzz, flat, res (le32 each).
        let a = config(&transport, CFG_ABS_INFO, axis as u8);
        let f = |i: usize| a.get(i * 4..i * 4 + 4).map_or(0, |b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]));
        caps.abs
            .push((axis, AbsInfo { value: 0, minimum: f(0), maximum: f(1), fuzz: f(2), flat: f(3), resolution: f(4) }));
    }
    let dev = input::register(Info {
        name: if name.is_empty() { "virtio input".into() } else { name },
        phys: alloc::format!("virtio{:?}/input0", transport.pci.address),
        bustype: id(0),
        vendor: id(1),
        product: id(2),
        version: id(3),
        caps,
    });

    let slot: Arc<slate_sync::Once<Arc<VirtioInput>>> = Arc::new(slate_sync::Once::new());
    let irq_slot = slot.clone();
    let vector = crate::arch::irq::alloc_vector(
        "virtio-input",
        Box::new(move || {
            if let Some(d) = irq_slot.get() {
                d.interrupt();
            }
        }),
    );
    let msix = vector.and_then(|v| transport.pci.enable_msix(&[v], crate::arch::irq::device_irq_target()));
    transport.no_config_interrupt();
    let queue = transport.setup_queue(0, EVENT_BUFFERS as u16, msix.map(|_| 0))?;
    queue.set_interrupts(msix.is_some());
    transport.driver_ok();
    if msix.is_none() {
        log_info!("virtio-input: no MSI-X; events will not arrive");
    }
    let d = Arc::new(VirtioInput { _transport: transport, queue, bufs: IrqSpinLock::new(BTreeMap::new()), dev });
    for _ in 0..EVENT_BUFFERS {
        d.post(Box::new([0u8; 8]));
    }
    d.queue.kick();
    slot.call_once(|| d.clone());
    Some(())
}
