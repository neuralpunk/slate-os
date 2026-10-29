// SPDX-License-Identifier: MIT OR Apache-2.0

//! virtio-net (VIRTIO 1.2 §5.1): one receive and one transmit queue, no
//! offloads. Every frame is preceded by the 12-byte `virtio_net_hdr`
//! (VERSION_1 layout), all zero on transmit.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use slate_net::Mac;
use slate_sync::Once;

use super::{Transport, Virtqueue, segments};
use crate::drivers::pci::Device;
use crate::log_info;
use crate::net::NetDevice;
use crate::sync::IrqSpinLock;

// Feature bits (§5.1.3).
const F_MAC: u64 = 1 << 5;

const HDR: usize = 12;
const RX_BUFFER: usize = 2048;
const RX_BUFFERS: u16 = 64;

pub struct VirtioNet {
    name: String,
    mac: Mac,
    _transport: Transport,
    rx: Virtqueue,
    tx: Virtqueue,
    /// Posted receive buffers by descriptor head.
    rx_bufs: IrqSpinLock<BTreeMap<u16, Box<[u8]>>>,
    /// Frames being transmitted, freed when the device is done.
    tx_bufs: IrqSpinLock<BTreeMap<u16, Box<[u8]>>>,
}

impl VirtioNet {
    fn post_rx(&self, buf: Box<[u8]>) {
        let mut segs = Vec::new();
        segments(buf.as_ptr(), buf.len(), true, &mut segs);
        if let Some(h) = self.rx.post(&segs) {
            self.rx_bufs.lock().insert(h, buf);
        }
    }

    fn reclaim_tx(&self) {
        for (h, _) in self.tx.take_used() {
            self.tx_bufs.lock().remove(&h);
        }
    }
}

impl NetDevice for VirtioNet {
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> Mac {
        self.mac
    }
    fn mtu(&self) -> usize {
        1500
    }

    fn send(&self, frame: &[u8]) {
        self.reclaim_tx();
        let mut buf = vec![0u8; HDR + frame.len()].into_boxed_slice();
        buf[HDR..].copy_from_slice(frame);
        let mut segs = Vec::new();
        segments(buf.as_ptr(), buf.len(), false, &mut segs);
        // A full transmit queue drops the frame, as a real NIC would.
        if let Some(h) = self.tx.post(&segs) {
            self.tx_bufs.lock().insert(h, buf);
            self.tx.kick();
        }
    }

    fn receive(&self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        let used = self.rx.take_used();
        if used.is_empty() {
            return frames;
        }
        // Take every finished buffer before re-posting any: a re-posted
        // buffer may get the descriptor number of one not yet handled.
        let done: Vec<(Box<[u8]>, usize)> = {
            let mut bufs = self.rx_bufs.lock();
            used.into_iter().filter_map(|(h, len)| bufs.remove(&h).map(|b| (b, len as usize))).collect()
        };
        for (buf, len) in done {
            let len = len.min(buf.len());
            if len > HDR {
                frames.push(buf[HDR..len].to_vec());
            }
            self.post_rx(buf);
        }
        self.rx.kick();
        frames
    }
}

pub fn probe(pci: Arc<Device>) -> Option<()> {
    let transport = Transport::new(pci)?;
    let features = transport.init(F_MAC)?;
    let mac = if features & F_MAC != 0 {
        let (lo, hi) = transport.config(|r| (r(0), r(4)));
        let b = [lo.to_le_bytes(), hi.to_le_bytes()].concat();
        Mac(b[..6].try_into().unwrap())
    } else {
        Mac([0x02, 0x53, 0x4C, 0x41, 0x54, 0x45]) // Locally administered.
    };
    let slot: Arc<Once<()>> = Arc::new(Once::new());
    let irq_slot = slot.clone();
    let vector = crate::arch::irq::alloc_vector(
        "virtio-net",
        Box::new(move || {
            if irq_slot.get().is_some() {
                crate::net::wake();
            }
        }),
    );
    let msix = vector.and_then(|v| transport.pci.enable_msix(&[v], crate::arch::irq::device_irq_target()));
    transport.no_config_interrupt();
    let entry = msix.map(|_| 0);
    let rx = transport.setup_queue(0, 128, entry)?;
    let tx = transport.setup_queue(1, 128, entry)?;
    rx.set_interrupts(msix.is_some());
    tx.set_interrupts(msix.is_some());
    transport.driver_ok();
    let name = crate::net::next_name();
    log_info!(
        "virtio-net {:?}: {name}, MAC {:?}, {}",
        transport.pci.address,
        mac,
        if msix.is_some() { "MSI-X" } else { "polled" }
    );
    let dev = Arc::new(VirtioNet {
        name,
        mac,
        _transport: transport,
        rx,
        tx,
        rx_bufs: IrqSpinLock::new(BTreeMap::new()),
        tx_bufs: IrqSpinLock::new(BTreeMap::new()),
    });
    for _ in 0..RX_BUFFERS {
        dev.post_rx(vec![0u8; RX_BUFFER].into_boxed_slice());
    }
    dev.rx.kick();
    slot.call_once(|| ());
    crate::net::register(dev, msix.is_some());
    Some(())
}
