// SPDX-License-Identifier: MIT OR Apache-2.0

//! The host's Low Energy side (ADR 0176), without I/O like the rest of
//! [`Host`]:
//!
//! - **Finding:** while discovering, the controller scans (actively, for
//!   names in scan responses) beside the inquiry; advertisements become
//!   devices, their kind from their appearance.
//! - **Pairing:** LE Create Connection, then SMP as the initiator (Just
//!   Works: Secure Connections when the device offers it, else legacy),
//!   the link encrypted with the key it gives; the keys are kept. The
//!   link stays up: a paired HID device is used at once.
//! - **A mouse by itself** ([`Host::autopair`], on unless the
//!   administrator says otherwise): the controller scans, and a mouse or
//!   tablet advertising in pairing mode is paired without anyone asking,
//!   whatever else is plugged in, so nobody is left without a mouse. Such
//!   a device gets a pointer only: never keys (a stranger's "mouse" can't
//!   type); paired again from Settings, it gets all it has.
//! - **Reconnecting:** while a bonded device isn't connected, the
//!   controller scans; when one advertises, it is connected and the link
//!   encrypted with its key (a device's Security Request asks the same).
//!   A device that forgot this computer fails encryption: it is let go,
//!   its bond kept until the person removes it.
//! - **On the link:** L2CAP's LE channels ([`slate_hci::l2cap`]): SMP, ATT
//!   with an HID host over GATT ([`slate_hci::hogp`]) once encrypted, and
//!   the signalling channel's parameter updates (accepted and applied).
//!   HID devices become [`HidEvent`]s, which the daemon turns into
//!   /dev/slate-hid devices.
//! - **Flow control:** data goes no faster than the controller's LE
//!   buffers free (Number Of Completed Packets, Vol 4, Part E, §4.1.1).

use alloc::string::String;
use alloc::vec::Vec;

use slate_hci::hogp::{self, HidDevice};
use slate_hci::le::{self, LeEvent};
use slate_hci::{BdAddr, Kind, att, l2cap, smp};

use crate::host::{Device, Host, LeInfo, Op, Purpose, State};

/// An LE connection.
#[derive(Debug)]
pub struct Link {
    pub handle: u16,
    pub addr: BdAddr,
    pub(crate) smp: Option<smp::Initiator>,
    pub(crate) hid: Option<hogp::Client>,
    pub encrypted: bool,
    pub(crate) encrypting: bool,
}

/// What the daemon does with /dev/slate-hid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HidEvent {
    /// Make device `addr`'s HID device (a pointer only, when nobody
    /// chose it).
    Create { addr: BdAddr, name: String, device: HidDevice, pointer_only: bool },
    /// One of its input reports.
    Input { addr: BdAddr, report: Vec<u8> },
    /// It went.
    Close { addr: BdAddr },
}

/// The kind of device an LE appearance names (Assigned Numbers §2.6:
/// category in the upper ten bits).
pub fn kind_of(appearance: u16) -> Kind {
    match (appearance >> 6, appearance & 0x3F) {
        (0x01, _) => Kind::Phone,
        (0x02, _) => Kind::Computer,
        (0x0F, 1) => Kind::Keyboard,
        (0x0F, 2) => Kind::Mouse,
        (0x0F, 3 | 4) => Kind::Gamepad,
        (0x25, _) => Kind::Headphones,
        _ => Kind::Other,
    }
}

impl Host {
    fn link(&mut self, handle: u16) -> Option<&mut Link> {
        self.links.iter_mut().find(|l| l.handle == handle)
    }

    /// The next LE data packet to send, while the controller has room.
    pub fn next_acl(&mut self) -> Option<Vec<u8>> {
        if self.le_credits == 0 {
            return None;
        }
        let p = self.acl_out.pop_front()?;
        if let Some((h, _, _)) = l2cap::parse_acl(&p) {
            *self.in_flight.entry(h).or_default() += 1;
        }
        self.le_credits -= 1;
        Some(p)
    }

    fn le_send(&mut self, handle: u16, cid: u16, payload: &[u8]) {
        let max = self.le_len.max(23);
        self.acl_out.extend(l2cap::acl_packets(handle, cid, payload, max, false));
    }

    /// LE Read Buffer Size's answer: LE works; its own buffers, or the
    /// BR/EDR ones shared (a length of 0, §7.8.2).
    pub(crate) fn le_buffer(&mut self, status: u8, ret: &[u8]) {
        if status != 0 || ret.len() < 4 {
            self.notes.push("no Low Energy".into());
            return;
        }
        self.le_ok = true;
        let (len, n) = (usize::from(u16::from_le_bytes([ret[1], ret[2]])), u16::from(ret[3]));
        (self.le_len, self.le_credits) = if len == 0 { (self.acl_len, self.acl_packets) } else { (len, n) };
    }

    /// Everything LE ends (power off, the controller gone).
    pub(crate) fn le_reset(&mut self) {
        for l in core::mem::take(&mut self.links) {
            self.hid.push(HidEvent::Close { addr: l.addr });
        }
        self.acl_out.clear();
        self.in_flight.clear();
        self.scanning = false;
        self.le_connecting = None;
    }

    /// Whether the controller should be scanning: discovering, or a bonded
    /// device isn't connected (and no connection is being made).
    fn le_wants_scan(&self) -> bool {
        if !self.le_ok || self.state != State::On || self.le_connecting.is_some() {
            return false;
        }
        self.discovering || self.autopair || self.devices.iter().any(|d| self.reconnectable(d))
    }

    /// Whether an advertisement is a mouse or tablet in pairing mode (LE
    /// Limited or General Discoverable, Supplement Part A §1.3; a mouse's or
    /// digitizer's appearance, or no appearance and the HID service).
    fn pairing_pointer(adv: &le::Advert) -> bool {
        let discoverable = le::ad_field(&adv.data, 0x01).and_then(|f| f.first()).is_some_and(|f| f & 0x03 != 0);
        let hid = [0x02, 0x03]
            .iter()
            .filter_map(|&k| le::ad_field(&adv.data, k))
            .any(|list| list.chunks(2).any(|u| u.len() == 2 && u16::from_le_bytes([u[0], u[1]]) == att::SERVICE_HID));
        let pointer = match adv.appearance() {
            Some(a) => a == le::APPEARANCE_MOUSE || a == 0x03C5,
            None => hid,
        };
        adv.connectable() && discoverable && pointer
    }

    /// A bonded LE device to connect when it advertises.
    fn reconnectable(&self, d: &Device) -> bool {
        d.le.as_ref().is_some_and(|l| l.keys.is_some()) && d.connected.is_none() && !self.refused.contains(&d.addr)
    }

    pub(crate) fn le_update_scan(&mut self) {
        let want = self.le_wants_scan();
        if want != self.scanning {
            self.scanning = want;
            // Ahead of anything queued: a connection waits for it.
            self.queue_front(le::cmd::set_scan_enable(want));
        }
    }

    /// Connect to `a` (stopping the scan first: some controllers don't
    /// scan and connect at once).
    fn le_connect(&mut self, a: BdAddr) {
        let Some(kind) = self.devices.iter().find(|d| d.addr == a).and_then(|d| d.le.as_ref()).map(|l| l.addr_type)
        else {
            return;
        };
        if self.le_connecting.is_some() || self.links.iter().any(|l| l.addr == a) {
            return;
        }
        self.le_connecting = Some(a);
        if self.scanning {
            self.scanning = false;
            self.send(le::cmd::set_scan_enable(false));
        }
        self.send(le::cmd::create_connection(kind, a));
    }

    /// Pair or connect LE device `a` (the person asked).
    pub(crate) fn le_begin(&mut self, a: BdAddr, purpose: Purpose) -> Result<(), String> {
        if !self.le_ok {
            return Err("this controller doesn't do Low Energy".into());
        }
        self.refused.retain(|r| *r != a);
        // The person chose it (or this is the pairing nobody asked for).
        if self.auto_pairing != Some(a) {
            self.auto_pairing = None;
        }
        if let Some(l) = self.links.iter().find(|l| l.addr == a) {
            // Already connected: pairing goes ahead on the link.
            let handle = l.handle;
            if purpose == Purpose::Connect {
                return Err(alloc::format!("{} is connected", self.name_of(a)));
            }
            self.op = Some(Op { addr: a, purpose, handle: Some(handle), remote_io: None });
            self.said = None;
            self.le_start_pairing(handle, a);
            return Ok(());
        }
        if self.discovering {
            self.send(slate_hci::cmd::inquiry_cancel());
            self.discovering = false;
        }
        self.op = Some(Op { addr: a, purpose, handle: None, remote_io: None });
        self.said = None;
        self.le_connect(a);
        Ok(())
    }

    fn le_start_pairing(&mut self, handle: u16, a: BdAddr) {
        let kind = self.devices.iter().find(|d| d.addr == a).and_then(|d| d.le.as_ref()).map_or(1, |l| l.addr_type);
        let own = self.addr.unwrap_or_default();
        let id = smp::Identity { irk: self.irk, addr_type: le::ADDR_PUBLIC, addr: own };
        let (init, first) = smp::Initiator::start((le::ADDR_PUBLIC, own), (kind, a), id);
        if let Some(l) = self.link(handle) {
            l.smp = Some(init);
        }
        self.le_send(handle, smp::CID, &first);
        self.notes.push(alloc::format!("pairing {a} (LE)"));
    }

    /// Encrypt link `handle` with the bond's key.
    fn le_encrypt_bonded(&mut self, handle: u16, a: BdAddr) {
        let keys = self.devices.iter().find(|d| d.addr == a).and_then(|d| d.le.as_ref()).and_then(|l| l.keys.clone());
        let Some(k) = keys else { return };
        let Some(l) = self.link(handle) else { return };
        if l.encrypted || l.encrypting || l.smp.is_some() {
            return;
        }
        l.encrypting = true;
        self.send(le::cmd::start_encryption(handle, k.rand, k.ediv, &k.ltk));
    }

    pub(crate) fn le_status(&mut self, opcode: u16, status: u8) {
        match opcode {
            le::OP_LE_CREATE_CONNECTION => {
                let Some(a) = self.le_connecting.take() else { return };
                if self.op.is_some_and(|o| o.addr == a) {
                    let n = self.name_of(a);
                    self.finish(false, alloc::format!("Couldn't reach {n}: {}.", Self::error_words(status)));
                }
            }
            le::OP_LE_START_ENCRYPTION => {
                for l in &mut self.links {
                    l.encrypting = false;
                }
            }
            _ => {}
        }
    }

    pub(crate) fn le_event(&mut self, e: LeEvent) {
        match e {
            LeEvent::Adverts(list) => {
                for adv in list {
                    self.le_advert(adv);
                }
            }
            LeEvent::ConnectionComplete { status, handle, addr, .. } => {
                let ours = self.le_connecting == Some(addr);
                if ours {
                    self.le_connecting = None;
                }
                if status != 0 {
                    if self.op.is_some_and(|o| o.addr == addr) {
                        let n = self.name_of(addr);
                        self.finish(false, alloc::format!("Couldn't reach {n}: {}.", Self::error_words(status)));
                    }
                    return;
                }
                let known = self.devices.iter().any(|d| d.addr == addr && d.le.is_some());
                if !known {
                    // Nobody asked for it.
                    self.send(slate_hci::cmd::disconnect(handle, slate_hci::ERR_REMOTE_USER_TERMINATED));
                    return;
                }
                if let Some(d) = self.device(addr) {
                    d.connected = Some(handle);
                    d.nearby = true;
                }
                self.links.push(Link { handle, addr, smp: None, hid: None, encrypted: false, encrypting: false });
                self.in_flight.insert(handle, 0);
                self.notes.push(alloc::format!("LE connected {addr}"));
                let pairing = self.op.is_some_and(|o| o.addr == addr && o.purpose == Purpose::Pair);
                if let Some(op) = self.op.as_mut().filter(|o| o.addr == addr) {
                    op.handle = Some(handle);
                }
                if pairing {
                    self.le_start_pairing(handle, addr);
                } else {
                    self.le_encrypt_bonded(handle, addr);
                }
            }
            LeEvent::ConnectionUpdate { status: 0, handle, interval, latency, timeout } => {
                self.notes.push(alloc::format!(
                    "LE {handle:#x}: interval {} us, latency {latency}, timeout {} ms",
                    u32::from(interval) * 1250,
                    u32::from(timeout) * 10
                ));
            }
            LeEvent::ConnectionUpdate { .. } | LeEvent::LtkRequest { .. } | LeEvent::Other(_) => {}
        }
    }

    fn le_advert(&mut self, adv: le::Advert) {
        let name = adv.name();
        let kind = adv.appearance().map(kind_of);
        let discovering = self.discovering;
        if discovering && !self.seen_has(adv.addr) {
            self.seen_push(adv.addr);
        }
        match self.device(adv.addr) {
            Some(d) => {
                if let Some(n) = name {
                    d.name = n;
                }
                if let Some(k) = kind {
                    d.kind = k;
                }
                d.nearby = true;
                if let Some(l) = d.le.as_mut() {
                    l.addr_type = adv.addr_type;
                } else {
                    d.le = Some(LeInfo { addr_type: adv.addr_type, keys: None, auto: false });
                }
            }
            None if discovering && adv.connectable() => {
                self.devices.push(Device {
                    addr: adv.addr,
                    name: name.unwrap_or_default(),
                    kind: kind.unwrap_or(Kind::Other),
                    page_scan_mode: 0,
                    clock_offset: 0,
                    nearby: true,
                    key: None,
                    connected: None,
                    le: Some(LeInfo { addr_type: adv.addr_type, keys: None, auto: false }),
                });
                self.notes.push(alloc::format!("found {} (LE)", self.name_of(adv.addr)));
            }
            None => {}
        }
        // A bonded device back in range: connect.
        let bonded = self.devices.iter().any(|d| d.addr == adv.addr && self.reconnectable(d));
        if bonded && adv.connectable() && self.op.is_none() {
            self.notes.push(alloc::format!("reconnecting {}", adv.addr));
            self.le_connect(adv.addr);
            return;
        }
        // A mouse in pairing mode pairs by itself.
        let new = !self.devices.iter().any(|d| d.addr == adv.addr && d.paired());
        if self.autopair
            && new
            && self.op.is_none()
            && self.le_connecting.is_none()
            && !self.auto_tried.contains(&adv.addr)
            && Self::pairing_pointer(&adv)
        {
            if !self.devices.iter().any(|d| d.addr == adv.addr) {
                self.devices.push(Device {
                    addr: adv.addr,
                    name: adv.name().unwrap_or_default(),
                    kind: adv.appearance().map_or(Kind::Mouse, kind_of),
                    page_scan_mode: 0,
                    clock_offset: 0,
                    nearby: true,
                    key: None,
                    connected: None,
                    le: Some(LeInfo { addr_type: adv.addr_type, keys: None, auto: false }),
                });
            }
            self.auto_tried.push(adv.addr);
            self.auto_pairing = Some(adv.addr);
            self.notes.push(alloc::format!("pairing {} by itself", self.name_of(adv.addr)));
            if self.le_begin(adv.addr, Purpose::Pair).is_err() {
                self.auto_pairing = None;
            }
        }
    }

    pub(crate) fn le_encryption(&mut self, status: u8, handle: u16, on: bool) {
        let Some(l) = self.link(handle) else { return };
        l.encrypting = false;
        let addr = l.addr;
        if status != 0 || !on {
            let n = self.name_of(addr);
            let why = Self::error_words(status);
            self.notes.push(alloc::format!("LE {addr}: encryption failed ({status:#04x})"));
            if !self.refused.contains(&addr) {
                self.refused.push(addr);
            }
            if self.op.is_some_and(|o| o.addr == addr) {
                self.finish(false, alloc::format!("{n}: {why}."));
            } else {
                self.said = Some((alloc::format!("{n} doesn't know this computer any more: pair it again."), true));
            }
            self.send(slate_hci::cmd::disconnect(handle, slate_hci::ERR_AUTHENTICATION_FAILURE));
            return;
        }
        let first = !l.encrypted;
        l.encrypted = true;
        // Pairing goes on (the keys are handed out now).
        let steps = l.smp.as_mut().map(|s| s.encrypted()).unwrap_or_default();
        self.le_smp_steps(handle, steps);
        if first {
            self.notes.push(alloc::format!("LE {addr}: encrypted"));
            if self.op.is_some_and(|o| o.addr == addr && o.purpose == Purpose::Connect) {
                let n = self.name_of(addr);
                self.finish(true, alloc::format!("Connected to {n}."));
            }
            self.le_start_hid(handle);
        }
    }

    /// The HID host over GATT, on an encrypted link.
    fn le_start_hid(&mut self, handle: u16) {
        let Some(l) = self.link(handle) else { return };
        if l.hid.is_some() {
            return;
        }
        let (c, first) = hogp::Client::start();
        l.hid = Some(c);
        self.le_send(handle, att::CID, &first);
    }

    fn le_smp_steps(&mut self, handle: u16, steps: Vec<smp::Step>) {
        let Some(addr) = self.links.iter().find(|l| l.handle == handle).map(|l| l.addr) else { return };
        for s in steps {
            match s {
                smp::Step::Send(p) => self.le_send(handle, smp::CID, &p),
                smp::Step::Encrypt { ltk, ediv, rand } => {
                    if let Some(l) = self.link(handle) {
                        l.encrypting = true;
                    }
                    self.send(le::cmd::start_encryption(handle, rand, ediv, &ltk));
                }
                smp::Step::Done(keys) => {
                    if let Some(l) = self.link(handle) {
                        l.smp = None;
                    }
                    let secure = keys.secure;
                    let auto = self.auto_pairing.take() == Some(addr);
                    if let Some(d) = self.device(addr) {
                        let l = d.le.get_or_insert_with(LeInfo::default);
                        l.keys = Some(keys);
                        l.auto = auto;
                    }
                    self.dirty = true;
                    self.notes.push(alloc::format!(
                        "paired {addr} (LE, {})",
                        if secure { "Secure Connections" } else { "legacy" }
                    ));
                    if self.op.is_some_and(|o| o.addr == addr) {
                        let n = self.name_of(addr);
                        self.finish(true, alloc::format!("Paired with {n}."));
                    }
                    // Paired by the person over a device that paired by
                    // itself: its HID device again, with all it has.
                    let ready = self.links.iter().find(|l| l.handle == handle).and_then(|l| l.hid.as_ref()?.device());
                    if let (false, Some(device)) = (auto, ready.cloned()) {
                        let name = device.name.clone().unwrap_or_else(|| self.name_of(addr));
                        self.hid.push(HidEvent::Create { addr, name, device, pointer_only: false });
                    }
                }
                smp::Step::Failed(reason) => {
                    if let Some(l) = self.link(handle) {
                        l.smp = None;
                    }
                    self.notes.push(alloc::format!("LE pairing {addr} failed ({reason:#04x})"));
                    if self.op.is_some_and(|o| o.addr == addr) {
                        let n = self.name_of(addr);
                        let why = match reason {
                            smp::ERR_PAIRING_NOT_SUPPORTED => "it doesn't allow pairing now",
                            smp::ERR_ENCRYPTION_KEY_SIZE => "its keys are too short",
                            _ => "the pairing was refused",
                        };
                        self.finish(false, alloc::format!("{n} wasn't paired: {why}."));
                    }
                    self.send(slate_hci::cmd::disconnect(handle, slate_hci::ERR_AUTHENTICATION_FAILURE));
                }
            }
        }
    }

    /// LE data from the controller, framed.
    pub(crate) fn le_acl(&mut self, packet: &[u8]) {
        let Some((handle, cid, payload)) = self.reassembler.take(packet) else { return };
        let rng = self.rng;
        let Some(l) = self.link(handle) else { return };
        let addr = l.addr;
        match cid {
            smp::CID if payload.first() == Some(&smp::SECURITY_REQUEST) => {
                // The device asks for security: its bond's key, if any
                // (pairing is this computer's to start).
                if l.smp.is_none() && !l.encrypted {
                    self.le_encrypt_bonded(handle, addr);
                }
            }
            smp::CID => {
                let mut r = |b: &mut [u8]| rng(b);
                let steps = match l.smp.as_mut() {
                    Some(s) => s.received(&payload, &mut r),
                    // Pairing the device starts isn't taken (§3.5.5).
                    None => {
                        alloc::vec![smp::Step::Send(alloc::vec![smp::PAIRING_FAILED, smp::ERR_PAIRING_NOT_SUPPORTED])]
                    }
                };
                self.le_smp_steps(handle, steps);
            }
            att::CID => {
                let outs = match l.hid.as_mut() {
                    Some(c) => c.received(&payload),
                    // Requests to Slate's (empty) server are refused.
                    None if payload.first().is_some_and(|&op| op & 1 == 0 && op & 0x40 == 0) => {
                        alloc::vec![hogp::Out::Send(att::error(payload[0], 0, att::ERR_REQUEST_NOT_SUPPORTED))]
                    }
                    None => Vec::new(),
                };
                for o in outs {
                    match o {
                        hogp::Out::Send(p) => self.le_send(handle, att::CID, &p),
                        hogp::Out::Ready(device) => {
                            let name = device.name.clone().unwrap_or_else(|| self.name_of(addr));
                            let pointer_only = self
                                .devices
                                .iter()
                                .find(|d| d.addr == addr)
                                .and_then(|d| d.le.as_ref())
                                .is_none_or(|l| l.auto);
                            self.notes.push(alloc::format!(
                                "{addr}: HID device ready ({} report map bytes, {} inputs)",
                                device.descriptor.len(),
                                device.inputs.len()
                            ));
                            self.hid.push(HidEvent::Create { addr, name, device, pointer_only });
                        }
                        hogp::Out::Report(report) => self.hid.push(HidEvent::Input { addr, report }),
                        hogp::Out::Failed(why) => self.notes.push(alloc::format!("{addr}: not used: {why}")),
                    }
                }
            }
            l2cap::CID_LE_SIGNALLING => match l2cap::signal(&payload) {
                l2cap::Signal::ParamUpdate { min, max, latency, timeout, reply } => {
                    self.le_send(handle, l2cap::CID_LE_SIGNALLING, &reply);
                    self.send(le::cmd::connection_update(handle, min, max, latency, timeout));
                }
                l2cap::Signal::Other(Some(reply)) => self.le_send(handle, l2cap::CID_LE_SIGNALLING, &reply),
                l2cap::Signal::Other(None) => {}
            },
            _ => {}
        }
    }

    /// Number Of Completed Packets: room again in the controller.
    pub(crate) fn le_completed(&mut self, list: &[(u16, u16)]) {
        for &(h, n) in list {
            if let Some(f) = self.in_flight.get_mut(&h) {
                let n = n.min(*f);
                *f -= n;
                self.le_credits += n;
            }
        }
    }

    /// Connection `handle` closed: if it was LE, its link and HID device
    /// go, and its unsent data; its packets in the controller are freed.
    pub(crate) fn le_disconnected(&mut self, handle: u16, reason: u8) {
        let Some(i) = self.links.iter().position(|l| l.handle == handle) else { return };
        let l = self.links.remove(i);
        self.reassembler.forget(handle);
        self.le_credits += self.in_flight.remove(&handle).unwrap_or(0);
        self.acl_out.retain(|p| l2cap::parse_acl(p).is_none_or(|(h, _, _)| h != handle));
        if l.hid.as_ref().is_some_and(|c| c.ready()) {
            self.hid.push(HidEvent::Close { addr: l.addr });
        }
        self.notes.push(alloc::format!("LE disconnected {} ({reason:#04x})", l.addr));
        if self.op.is_some_and(|o| o.addr == l.addr) {
            let n = self.name_of(l.addr);
            self.finish(false, alloc::format!("{n} went away."));
        }
    }

    /// An output report from the kernel (a keyboard's lights) for device
    /// `a`.
    pub fn hid_output(&mut self, a: BdAddr, id: u8, report: &[u8]) {
        let Some(l) = self.links.iter().find(|l| l.addr == a) else { return };
        let Some(p) = l.hid.as_ref().and_then(|c| c.output(id, report)) else { return };
        let handle = l.handle;
        self.le_send(handle, att::CID, &p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::tests::settle;
    use slate_hci::sim::Controller;
    use slate_hci::sim_le::nearby_le;

    fn rng(b: &mut [u8]) {
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8).wrapping_mul(29).wrapping_add(11);
        }
    }

    fn started() -> (Host, Controller) {
        let mut c = Controller::new(BdAddr([0x00, 0x1B, 0xDC, 0x0F, 0x00, 0x01]), Vec::new());
        c.le = nearby_le();
        let mut h = Host::new("desk", Vec::new());
        h.rng = rng;
        h.power_on();
        settle(&mut h, &mut c);
        (h, c)
    }

    /// Found by scanning, paired, its HID device made and fed; out of
    /// range and back, reconnected with the bond; removed.
    #[test]
    fn a_mouse_found_paired_used_and_back() {
        let (mut h, mut c) = started();
        assert!(h.le_ok && h.state == State::On);
        let mouse = c.le[0].addr;
        h.discover().unwrap();
        settle(&mut h, &mut c);
        let d = h.devices.iter().find(|d| d.addr == mouse).expect("found");
        assert_eq!((d.name.as_str(), d.kind), ("Slate Mouse", Kind::Mouse));
        assert!(!h.scanning, "discovery over: no bonded device, no scanning");

        h.pair(mouse).unwrap();
        settle(&mut h, &mut c);
        assert_eq!(h.said, Some((String::from("Paired with Slate Mouse."), false)));
        let d = h.devices.iter().find(|d| d.addr == mouse).unwrap();
        assert!(d.paired() && d.connected.is_some() && h.dirty);
        assert!(d.le.as_ref().unwrap().keys.as_ref().unwrap().secure);
        let Some(HidEvent::Create { name, device, pointer_only, .. }) = h.hid.first().cloned() else {
            panic!("{:?}", h.hid)
        };
        assert_eq!((name.as_str(), device.descriptor.len()), ("Slate Mouse", hogp::MOUSE_REPORT_MAP.len()));
        assert!(!pointer_only, "chosen by the person: all of it");
        h.hid.clear();
        assert!(c.mouse_input(mouse, 1, 3, -4, 0));
        settle(&mut h, &mut c);
        assert_eq!(h.hid, [HidEvent::Input { addr: mouse, report: alloc::vec![1, 1, 3, 0xFC, 0] }]);
        h.hid.clear();

        // Out of range: its HID device goes, and the controller scans for it.
        c.le_drop(mouse);
        settle(&mut h, &mut c);
        assert_eq!(h.hid, [HidEvent::Close { addr: mouse }]);
        assert!(h.scanning);
        h.hid.clear();
        c.le_advertise(mouse, true);
        settle(&mut h, &mut c);
        assert!(c.le[0].encrypted(), "reconnected and encrypted with the bond");
        assert!(matches!(h.hid.first(), Some(HidEvent::Create { .. })));
        assert!(!h.scanning);

        // Removed: the link closes and the key goes.
        h.remove(mouse).unwrap();
        settle(&mut h, &mut c);
        assert!(!h.devices.iter().any(|d| d.addr == mouse && d.paired()));
        assert!(h.links.is_empty());
    }

    /// A device that forgot this computer: encryption fails, it is let go.
    #[test]
    fn a_mouse_that_forgot() {
        let (mut h, mut c) = started();
        let mouse = c.le[0].addr;
        h.discover().unwrap();
        settle(&mut h, &mut c);
        h.pair(mouse).unwrap();
        settle(&mut h, &mut c);
        c.le_drop(mouse);
        c.le[0].bond = None;
        settle(&mut h, &mut c);
        c.le_advertise(mouse, true);
        settle(&mut h, &mut c);
        assert!(h.links.is_empty() && !c.le[0].connected());
        assert!(h.notes.iter().any(|n| n.contains("encryption failed")), "{:?}", h.notes);
        assert!(h.devices.iter().any(|d| d.addr == mouse && d.paired()), "the bond is kept");
    }

    /// The mouse in pairing mode pairs by itself, pointer only, once.
    #[test]
    fn a_mouse_by_itself() {
        let (mut h, mut c) = started();
        let mouse = c.le[0].addr;
        h.autopair = true;
        settle(&mut h, &mut c);
        let d = h.devices.iter().find(|d| d.addr == mouse).expect("paired by itself");
        assert!(d.paired() && d.le.as_ref().unwrap().auto);
        assert!(matches!(h.hid.first(), Some(HidEvent::Create { pointer_only: true, .. })), "{:?}", h.hid);
        // Paired again by the person: all of it, at once.
        h.hid.clear();
        h.pair(mouse).unwrap();
        settle(&mut h, &mut c);
        assert!(!h.devices.iter().find(|d| d.addr == mouse).unwrap().le.as_ref().unwrap().auto);
        assert!(matches!(h.hid.first(), Some(HidEvent::Create { pointer_only: false, .. })), "{:?}", h.hid);
        // A keyboard in pairing mode is never taken.
        let adv = |appearance: u16| le::Advert {
            kind: le::ADV_IND,
            addr_type: 1,
            addr: BdAddr([0xC1; 6]),
            data: le::advertising_data("Keys", appearance, &[att::SERVICE_HID]),
            rssi: -40,
        };
        assert!(!Host::pairing_pointer(&adv(le::APPEARANCE_KEYBOARD)));
        assert!(Host::pairing_pointer(&adv(le::APPEARANCE_MOUSE)));
        // Not in pairing mode (no discoverable flag): not taken.
        let mut quiet = adv(le::APPEARANCE_MOUSE);
        quiet.data[2] = 0x04;
        assert!(!Host::pairing_pointer(&quiet));
    }

    #[test]
    fn appearances() {
        assert_eq!(kind_of(0x03C2), Kind::Mouse);
        assert_eq!(kind_of(0x03C1), Kind::Keyboard);
        assert_eq!(kind_of(0x03C4), Kind::Gamepad);
        assert_eq!(kind_of(0x0040), Kind::Phone);
        assert_eq!(kind_of(0x0000), Kind::Other);
    }
}
