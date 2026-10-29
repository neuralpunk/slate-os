// SPDX-License-Identifier: MIT OR Apache-2.0

//! USB Ethernet: the CDC Ethernet Control Model (ADR 0046).
//!
//! Sources: USB CDC 1.2 and the ECM 1.2 subclass specification (see
//! `libs/usb`); SET_INTERFACE from USB 2.0 §9.4.10. The adapter's MAC
//! address comes from its iMACAddress string. Selecting the data
//! interface's alternate setting with the bulk endpoints starts the
//! traffic (ECM §3.3); SET_ETHERNET_PACKET_FILTER asks for unicast,
//! broadcast and multicast frames. Frames go as they are over the bulk
//! endpoints, each ended by a short packet (a zero-length one after a
//! frame that fills its last packet, ECM §3.3.1). The interrupt endpoint
//! reports the link (NETWORK_CONNECTION).
//!
//! Received frames land in a ring of buffers kept queued on the bulk IN
//! endpoint; completions arrive in order, so each takes the oldest
//! buffer. Frames to send are copied into a ring of buffers and queued
//! on the bulk OUT endpoint; a full ring drops the frame.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use slate_net::Mac;
use slate_usb::ecm;

use super::xhci::{CC_SHORT_PACKET, CC_SUCCESS, Endpoint, UsbDevice};
use super::{EndpointDesc, REQ_GET_DESCRIPTOR, RT_CLASS_INTERFACE_OUT, RT_DEVICE_IN};
use crate::drivers::dma::Dma;
use crate::sync::IrqSpinLock;
use crate::{log_info, log_warn};

/// SET_INTERFACE (USB 2.0 table 9-4), to an interface.
const REQ_SET_INTERFACE: u8 = 0x0B;
const RT_INTERFACE_OUT: u8 = 0x01;
/// US English, for string descriptors (USB LANGID table).
const LANG_EN_US: u16 = 0x0409;
const BUF: usize = 2048;
const RX_BUFFERS: usize = 16;
const TX_BUFFERS: usize = 16;
/// Frames held for the network thread at most.
const RX_QUEUE: usize = 256;

struct Rx {
    /// Buffers queued on the endpoint, oldest first.
    pending: VecDeque<Dma>,
    frames: VecDeque<Vec<u8>>,
}

struct Tx {
    /// Buffers queued on the endpoint, oldest first, with whether a
    /// zero-length packet follows (it completes separately).
    pending: VecDeque<(Dma, bool)>,
    free: Vec<Dma>,
}

pub struct EcmNet {
    name: String,
    mac: Mac,
    dev: Arc<UsbDevice>,
    bulk_in: Arc<Endpoint>,
    bulk_out: Arc<Endpoint>,
    out_max_packet: usize,
    link: AtomicBool,
    /// The downstream speed last reported (bits/s), so it is logged only
    /// when it changes: some adapters (the RTL8153, a TP-Link UE300) send
    /// a speed notification on every interrupt-endpoint poll.
    speed: AtomicU64,
    rx: IrqSpinLock<Rx>,
    tx: IrqSpinLock<Tx>,
}

impl crate::net::NetDevice for EcmNet {
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
        if frame.len() > BUF || self.dev.gone.load(Ordering::Acquire) {
            return;
        }
        let mut tx = self.tx.lock();
        let Some(buf) = tx.free.pop() else { return };
        buf.copy_in(0, frame);
        let zlp = frame.len() % self.out_max_packet == 0;
        self.dev.queue(&self.bulk_out, buf.phys(), frame.len());
        if zlp {
            self.dev.queue(&self.bulk_out, buf.phys(), 0);
        }
        tx.pending.push_back((buf, zlp));
    }

    fn receive(&self) -> Vec<Vec<u8>> {
        self.rx.lock().frames.drain(..).collect()
    }

    fn link_up(&self) -> bool {
        self.link.load(Ordering::Relaxed) && !self.dev.gone.load(Ordering::Acquire)
    }
}

/// A string descriptor's text.
fn string(dev: &UsbDevice, index: u8) -> Option<Vec<u8>> {
    let mut buf = [0u8; 255];
    let value = (u16::from(slate_usb::DESC_STRING) << 8) | u16::from(index);
    let n = dev.control(RT_DEVICE_IN, REQ_GET_DESCRIPTOR, value, LANG_EN_US, &mut buf).ok()?;
    Some(slate_usb::string_text(&buf[..n]))
}

fn desc(e: &slate_usb::Endpoint) -> EndpointDesc {
    EndpointDesc::from(e)
}

/// Start the ECM function `f` of `dev` (its configuration is set).
pub fn start(dev: &Arc<UsbDevice>, f: &ecm::Function) {
    let mac = match f.mac_string {
        0 => None,
        i => string(dev, i).and_then(|t| ecm::parse_mac(&t)),
    };
    let mac = mac.map(Mac).unwrap_or_else(|| {
        log_warn!("USB Ethernet on port {}: no MAC address string; using a random one", dev.port);
        crate::net::link::random_mac()
    });
    let mut eps = alloc::vec![desc(&f.bulk_in), desc(&f.bulk_out)];
    eps.extend(f.notify.as_ref().map(desc));
    let Some(rings) = dev.configure(&eps) else { return };
    let (bulk_in, bulk_out) = (rings[0].clone(), rings[1].clone());
    if dev.control(RT_INTERFACE_OUT, REQ_SET_INTERFACE, u16::from(f.data_alt), u16::from(f.data), &mut []).is_err() {
        log_warn!("USB Ethernet on port {}: SET_INTERFACE failed", dev.port);
        return;
    }
    let filter = ecm::FILTER_DIRECTED | ecm::FILTER_BROADCAST | ecm::FILTER_ALL_MULTICAST;
    if dev
        .control(RT_CLASS_INTERFACE_OUT, ecm::SET_ETHERNET_PACKET_FILTER, filter, u16::from(f.control), &mut [])
        .is_err()
    {
        // Optional for some devices; frames for us still come.
        log_warn!("USB Ethernet on port {}: SET_ETHERNET_PACKET_FILTER failed", dev.port);
    }
    let mut free = Vec::new();
    for _ in 0..TX_BUFFERS {
        let Some(b) = Dma::new(BUF) else { return };
        free.push(b);
    }
    let net = Arc::new(EcmNet {
        name: crate::net::next_name(),
        mac,
        dev: dev.clone(),
        bulk_in: bulk_in.clone(),
        bulk_out: bulk_out.clone(),
        out_max_packet: usize::from(f.bulk_out.max_packet.max(8)),
        // Until a notification says otherwise (not every device sends one).
        link: AtomicBool::new(true),
        speed: AtomicU64::new(0),
        rx: IrqSpinLock::new(Rx { pending: VecDeque::new(), frames: VecDeque::new() }),
        tx: IrqSpinLock::new(Tx { pending: VecDeque::new(), free }),
    });
    dev.bound(f.control, "usb-ecm");
    dev.bound(f.data, "usb-ecm");

    // Received frames.
    let n = net.clone();
    dev.hc.set_pipe(
        dev.slot,
        bulk_in.dci,
        alloc::boxed::Box::new(move |code, residual| {
            if n.dev.gone.load(Ordering::Acquire) {
                return;
            }
            let mut rx = n.rx.lock();
            let Some(buf) = rx.pending.pop_front() else { return };
            if code == CC_SUCCESS || code == CC_SHORT_PACKET {
                let len = BUF - (residual as usize).min(BUF);
                if len >= 14 && rx.frames.len() < RX_QUEUE {
                    let mut frame = alloc::vec![0u8; len];
                    buf.copy_out(0, &mut frame);
                    rx.frames.push_back(frame);
                }
            } else {
                log_warn!("USB Ethernet on port {}: receive error {code}", n.dev.port);
            }
            n.dev.queue(&n.bulk_in, buf.phys(), BUF);
            rx.pending.push_back(buf);
            drop(rx);
            crate::net::wake();
        }),
    );
    // Sent frames: their buffers come back.
    let n = net.clone();
    let zlp_seen = AtomicBool::new(false);
    dev.hc.set_pipe(
        dev.slot,
        bulk_out.dci,
        alloc::boxed::Box::new(move |_code, _residual| {
            let mut tx = n.tx.lock();
            let Some((_, zlp)) = tx.pending.front() else { return };
            // A frame with a zero-length packet after it completes twice.
            if *zlp && !zlp_seen.swap(true, Ordering::Relaxed) {
                return;
            }
            zlp_seen.store(false, Ordering::Relaxed);
            if let Some((buf, _)) = tx.pending.pop_front() {
                tx.free.push(buf);
            }
        }),
    );
    // The link.
    if let (Some(ep), Some(ring)) = (f.notify, rings.get(2).cloned())
        && let Some(buf) = Dma::new(64)
    {
        let n = net.clone();
        let len = usize::from(ep.max_packet).clamp(8, 64);
        let phys = buf.phys();
        let r = ring.clone();
        dev.hc.set_pipe(
            dev.slot,
            ring.dci,
            alloc::boxed::Box::new(move |code, residual| {
                if n.dev.gone.load(Ordering::Acquire) {
                    return;
                }
                if code == CC_SUCCESS || code == CC_SHORT_PACKET {
                    let got = len - (residual as usize).min(len);
                    let mut b = [0u8; 64];
                    buf.copy_out(0, &mut b[..got]);
                    match ecm::parse_notification(&b[..got]) {
                        Some(ecm::Notification::Connection(up)) => {
                            if n.link.swap(up, Ordering::Relaxed) != up {
                                log_info!("{}: link {}", n.name, if up { "up" } else { "down" });
                            }
                            crate::net::links_changed();
                        }
                        Some(ecm::Notification::Speed(down, _))
                            if n.speed.swap(u64::from(down), Ordering::Relaxed) != u64::from(down) =>
                        {
                            log_info!("{}: {} Mbit/s", n.name, down / 1_000_000);
                        }
                        _ => {}
                    }
                }
                n.dev.queue(&r, phys, len);
            }),
        );
        dev.queue(&ring, phys, len);
    }
    {
        let mut rx = net.rx.lock();
        for _ in 0..RX_BUFFERS {
            let Some(b) = Dma::new(BUF) else { break };
            dev.queue(&bulk_in, b.phys(), BUF);
            rx.pending.push_back(b);
        }
    }
    let m = mac.0;
    log_info!(
        "USB port {}: Ethernet {} ({:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
        dev.port,
        net.name,
        m[0],
        m[1],
        m[2],
        m[3],
        m[4],
        m[5]
    );
    crate::net::register(net, dev.interrupts());
}
