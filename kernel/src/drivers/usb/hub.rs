// SPDX-License-Identifier: MIT OR Apache-2.0

//! USB 2.0 hubs, such as the one built into many keyboards.
//!
//! Source: USB 2.0 specification chapter 11 (the hub descriptor §11.23.2.1,
//! hub class requests §11.24.2, port status and change bits §11.24.2.7,
//! port reset §11.5.1.5), with the xHCI 1.2 rules for devices behind hubs
//! (route strings and transaction translators, §4.3.3 and §6.2.2).
//!
//! A hub says which ports changed through its status-change endpoint
//! (§11.12.1, §11.12.4: a bitmap, bit 0 the hub, bit N port N), which
//! wakes the controller's enumeration thread to look at those ports; a
//! hub without one is polled twice a second. Every change bit a port
//! reports is cleared, or the hub would report it again. Hubs may sit
//! behind hubs, up to the five tiers USB allows. USB 3 hubs on SuperSpeed
//! ports are not driven (their USB 2 half is; ADR 0082).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::xhci::{self, CC_SHORT_PACKET, CC_SUCCESS, Position, SPEED_FULL, SPEED_HIGH, SPEED_LOW, UsbDevice, Xhci};
use super::{EP_INTERRUPT, InterfaceDesc};
use crate::drivers::dma::{Dma, delay_ms, wait_for};
use crate::sched::wait::Mutex;
use crate::{log_info, log_warn};

// Class requests (§11.24.2) and their bmRequestType values.
const RT_HUB_IN: u8 = 0xA0;
const RT_PORT_IN: u8 = 0xA3;
const RT_PORT_OUT: u8 = 0x23;
const GET_STATUS: u8 = 0;
const CLEAR_FEATURE: u8 = 1;
const SET_FEATURE: u8 = 3;
const GET_DESCRIPTOR: u8 = 6;
const DESC_HUB: u16 = 0x29;

// Port features (table 11-17).
const PORT_RESET: u16 = 4;
const PORT_POWER: u16 = 8;
const C_PORT_CONNECTION: u16 = 16;
const C_PORT_ENABLE: u16 = 17;
const C_PORT_RESET: u16 = 20;
/// Hub features (table 11-17): the hub's own change bits.
const C_HUB_LOCAL_POWER: u16 = 0;
const C_HUB_OVER_CURRENT: u16 = 1;
const RT_HUB_OUT: u8 = 0x20;

// wPortStatus and wPortChange bits (tables 11-21, 11-22).
const STATUS_CONNECTION: u16 = 1 << 0;
const STATUS_ENABLE: u16 = 1 << 1;
const STATUS_LOW_SPEED: u16 = 1 << 9;
const STATUS_HIGH_SPEED: u16 = 1 << 10;
const CHANGE_RESET: u16 = 1 << 4;

const MAX_DEPTH: u8 = 5;

/// A hub and what is plugged into it.
pub struct Hub {
    pub dev: Arc<UsbDevice>,
    ports: u8,
    children: Mutex<BTreeMap<u8, Arc<UsbDevice>>>,
    /// Hubs plugged into this one, so their devices go when it goes.
    sub_hubs: Mutex<Vec<Arc<Hub>>>,
    /// Ports (bit N) and the hub itself (bit 0) that reported a change and
    /// have not been looked at.
    pending: AtomicU32,
    /// Changes come through the status-change endpoint.
    endpoint: AtomicBool,
}

impl Hub {
    fn port_status(&self, port: u8) -> Option<(u16, u16)> {
        let mut st = [0u8; 4];
        self.dev.control(RT_PORT_IN, GET_STATUS, 0, u16::from(port), &mut st).ok()?;
        Some((u16::from_le_bytes([st[0], st[1]]), u16::from_le_bytes([st[2], st[3]])))
    }

    fn port_feature(&self, set: bool, feature: u16, port: u8) -> bool {
        let req = if set { SET_FEATURE } else { CLEAR_FEATURE };
        self.dev.control(RT_PORT_OUT, req, feature, u16::from(port), &mut []).is_ok()
    }

    /// Reset a newly connected port (§11.5.1.5) and return the device's
    /// speed, or `None` if the port did not come up enabled.
    fn reset(&self, port: u8) -> Option<u32> {
        if !self.port_feature(true, PORT_RESET, port) {
            return None;
        }
        let mut status = 0;
        let done = wait_for(500, || match self.port_status(port) {
            Some((s, c)) => {
                status = s;
                c & CHANGE_RESET != 0
            }
            None => false,
        });
        self.port_feature(false, C_PORT_RESET, port);
        self.port_feature(false, C_PORT_ENABLE, port);
        if !done || status & STATUS_ENABLE == 0 {
            return None;
        }
        // Reset recovery (§7.1.7.5).
        delay_ms(10);
        Some(if status & STATUS_LOW_SPEED != 0 {
            SPEED_LOW
        } else if status & STATUS_HIGH_SPEED != 0 {
            SPEED_HIGH
        } else {
            SPEED_FULL
        })
    }

    /// Whether the hub reports its changes (else it is polled).
    pub fn reports_changes(&self) -> bool {
        self.endpoint.load(Ordering::Acquire)
    }

    /// Look at the ports that reported a change (every port when the hub
    /// is polled): set up new devices, forget removed ones. Returns hubs
    /// found behind this one.
    pub fn poll(&self, hc: &Arc<Xhci>) -> Vec<Arc<Hub>> {
        let mut found = Vec::new();
        let all = ((1u32 << (u32::from(self.ports) + 1)) - 1) & !1;
        let changed = if self.reports_changes() { self.pending.swap(0, Ordering::AcqRel) } else { all | 1 };
        if changed & 1 != 0 {
            // The hub's own changes (§11.24.2.6): acknowledged.
            self.dev.control(RT_HUB_OUT, CLEAR_FEATURE, C_HUB_LOCAL_POWER, 0, &mut []).ok();
            self.dev.control(RT_HUB_OUT, CLEAR_FEATURE, C_HUB_OVER_CURRENT, 0, &mut []).ok();
        }
        for port in (1..=self.ports).filter(|p| changed & (1 << p) != 0) {
            if self.dev.gone.load(Ordering::Acquire) {
                break;
            }
            let Some((status, change)) = self.port_status(port) else { continue };
            // Every change bit (wPortChange bits 0-4, cleared by features
            // C_PORT_CONNECTION to C_PORT_RESET), or the hub reports the
            // port again.
            for bit in 0..5 {
                if change & (1 << bit) != 0 {
                    self.port_feature(false, C_PORT_CONNECTION + bit, port);
                }
            }
            let connected = status & STATUS_CONNECTION != 0;
            let known = self.children.lock().contains_key(&port);
            if connected && !known {
                // Debounce (§7.1.7.3), then reset.
                delay_ms(100);
                let Some(speed) = self.reset(port) else {
                    log_warn!("USB port {}.{port}: did not come up after a reset", self.dev.port);
                    continue;
                };
                let me = self.dev.pos;
                // Low- and full-speed devices behind a high-speed hub go
                // through that hub's transaction translator; deeper ones
                // keep the one above.
                let tt = if speed != SPEED_HIGH && self.dev.speed == SPEED_HIGH {
                    Some((self.dev.slot, port))
                } else {
                    me.tt
                };
                let pos = Position {
                    root_port: me.root_port,
                    route: me.route | (u32::from(port.min(15)) << (4 * u32::from(me.depth))),
                    depth: me.depth + 1,
                    tt,
                };
                match xhci::setup(hc, pos, speed, format!("{}.{port}", self.dev.port)) {
                    Some((d, hub)) => {
                        self.children.lock().insert(port, d);
                        if let Some(h) = hub {
                            self.sub_hubs.lock().push(h.clone());
                            found.push(h);
                        }
                    }
                    None => log_warn!("USB port {}.{port}: device not set up", self.dev.port),
                }
            } else if !connected
                && known
                && let Some(d) = self.children.lock().remove(&port)
            {
                xhci::detach(&d);
            }
        }
        found
    }

    /// The hub is gone: so is everything behind it.
    pub fn detach_all(&self) {
        for (_, d) in core::mem::take(&mut *self.children.lock()) {
            xhci::detach(&d);
        }
        for h in core::mem::take(&mut *self.sub_hubs.lock()) {
            h.detach_all();
        }
    }
}

/// Set up a hub: its descriptor, the controller's view of it, power on
/// every port, and listen on its status-change endpoint. `protocol` is
/// the device descriptor's bDeviceProtocol.
pub fn start(dev: &Arc<UsbDevice>, protocol: u8, iface: &InterfaceDesc) -> Option<Arc<Hub>> {
    if dev.speed != SPEED_HIGH && dev.speed != SPEED_FULL {
        log_info!("USB port {}: SuperSpeed hubs are not supported (their USB 2 side is)", dev.port);
        return None;
    }
    if dev.pos.depth >= MAX_DEPTH {
        log_warn!("USB port {}: hubs nested too deep", dev.port);
        return None;
    }
    let mut d = [0u8; 9];
    let got = dev.control(RT_HUB_IN, GET_DESCRIPTOR, DESC_HUB << 8, 0, &mut d).ok()?;
    if got < 7 {
        return None;
    }
    let ports = d[2].min(15);
    let characteristics = u16::from_le_bytes([d[3], d[4]]);
    // Think time (bits 6:5) matters for high-speed hubs' translators.
    let ttt = if dev.speed == SPEED_HIGH { u32::from((characteristics >> 5) & 3) } else { 0 };
    let power_good_ms = u64::from(d[5]) * 2;
    let _ = protocol; // Single TT: the hub's default interface setting.
    if !dev.configure_hub(ports, ttt) {
        log_warn!("USB port {}: the controller did not accept the hub", dev.port);
        return None;
    }
    dev.maxchild.store(ports, core::sync::atomic::Ordering::Relaxed);
    let hub = Arc::new(Hub {
        dev: dev.clone(),
        ports,
        children: Mutex::new(BTreeMap::new()),
        sub_hubs: Mutex::new(Vec::new()),
        // Every port, at first.
        pending: AtomicU32::new(((1u32 << (u32::from(ports) + 1)) - 1) & !1),
        endpoint: AtomicBool::new(false),
    });
    for p in 1..=ports {
        hub.port_feature(true, PORT_POWER, p);
    }
    delay_ms(power_good_ms.max(20) + 100);
    let listening = listen(&hub, iface);
    log_info!(
        "USB port {}: hub with {ports} ports{}",
        dev.port,
        if listening { "" } else { " (polled: no status-change endpoint)" }
    );
    Some(hub)
}

/// Queue a read on the hub's status-change endpoint (an interrupt IN
/// endpoint, §11.12.1); each answer marks the ports it names and wakes
/// the enumeration thread. Returns whether the hub has one.
fn listen(hub: &Arc<Hub>, iface: &InterfaceDesc) -> bool {
    let Some(ep) = iface.endpoints.iter().find(|e| e.kind == EP_INTERRUPT && e.is_in()).copied() else {
        return false;
    };
    let Some(eps) = hub.dev.configure(&[ep]) else { return false };
    let Some(buf) = Dma::new(64) else { return false };
    let endpoint = eps[0].clone();
    // One bit per port and one for the hub, rounded up to bytes.
    let len = (usize::from(hub.ports) + 1).div_ceil(8).clamp(1, usize::from(ep.max_packet).max(1));
    let phys = buf.phys();
    let (h, e) = (hub.clone(), endpoint.clone());
    hub.dev.hc.set_pipe(
        hub.dev.slot,
        endpoint.dci,
        alloc::boxed::Box::new(move |code, residual| {
            if h.dev.gone.load(Ordering::Acquire) {
                return;
            }
            if code != CC_SUCCESS && code != CC_SHORT_PACKET {
                log_warn!("USB hub on port {}: status-change transfer error {code}; polled from now on", h.dev.port);
                h.endpoint.store(false, Ordering::Release);
                return;
            }
            let got = len.saturating_sub(residual as usize).min(4);
            let mut b = [0u8; 4];
            buf.copy_out(0, &mut b[..got]);
            h.pending.fetch_or(u32::from_le_bytes(b), Ordering::AcqRel);
            h.dev.hc.port_change.store(true, Ordering::Release);
            h.dev.hc.enum_waiters.wake_all();
            h.dev.queue(&e, phys, len);
        }),
    );
    hub.endpoint.store(true, Ordering::Release);
    hub.dev.queue(&endpoint, phys, len);
    true
}
