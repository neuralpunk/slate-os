// SPDX-License-Identifier: MIT OR Apache-2.0

//! The simulated controller's Low Energy side (ADR 0176): devices that
//! advertise, take a connection from the host as the central, answer on
//! the link's fixed channels as a device would (SMP as the responder, Just
//! Works; ATT from their GATT database), and keep their bond for the next
//! connection. A mouse among them reports movement as notifications once
//! the host has turned them on. As the BR/EDR side, it has no radio and
//! no timing: what a device says comes at once.

use alloc::string::String;
use alloc::vec::Vec;

use super::sim::Controller;
use super::*;
use crate::le::{self, Advert};
use crate::{att, hogp, l2cap, smp};

/// The LE data a packet holds at most, both ways (LE Read Buffer Size's
/// answer: the smallest, 27 octets, so frames come in fragments), and how
/// many the controller takes at once.
pub const LE_ACL_LEN: usize = 27;
pub const LE_ACL_PACKETS: u8 = 8;

/// LE connection handles start here (the BR/EDR ones are below).
const LE_FIRST_HANDLE: u16 = 0x40;

/// An LE device in range.
#[derive(Debug)]
pub struct LeRemote {
    pub addr: BdAddr,
    pub addr_type: u8,
    pub name: String,
    /// Whether it offers LE Secure Connections (else legacy pairing).
    pub sc: bool,
    /// Whether it advertises, connectable (pairing mode, or bonded and
    /// waiting for its host).
    pub advertising: bool,
    pub server: att::Server,
    /// Its input report's value handle (the mouse's).
    pub input: u16,
    /// The keys it keeps from pairing with the host.
    pub bond: Option<smp::Keys>,
    conn: Option<LeConn>,
}

#[derive(Debug)]
struct LeConn {
    handle: u16,
    responder: Option<smp::Responder>,
    encrypted: bool,
}

impl LeRemote {
    /// A mouse: HID over GATT with a three-button wheel mouse's reports.
    pub fn mouse(addr: BdAddr, name: &str, sc: bool) -> LeRemote {
        let (server, input) = hogp::mouse_server(name, 0x046D, 0xB032);
        LeRemote {
            addr,
            addr_type: le::ADDR_RANDOM,
            name: String::from(name),
            sc,
            advertising: true,
            server,
            input,
            bond: None,
            conn: None,
        }
    }

    pub fn connected(&self) -> bool {
        self.conn.is_some()
    }

    pub fn encrypted(&self) -> bool {
        self.conn.as_ref().is_some_and(|c| c.encrypted)
    }

    fn advert(&self) -> Advert {
        Advert {
            kind: le::ADV_IND,
            addr_type: self.addr_type,
            addr: self.addr,
            data: le::advertising_data(&self.name, le::APPEARANCE_MOUSE, &[att::SERVICE_HID]),
            rssi: -52,
        }
    }
}

/// A mouse in range for tests: static random address, Secure Connections.
pub fn nearby_le() -> Vec<LeRemote> {
    alloc::vec![LeRemote::mouse(BdAddr([0xDA, 0xDB, 0x00, 0x8C, 0xD8, 0xE5]), "Slate Mouse", true)]
}

impl Controller {
    fn le_conn_of(&mut self, handle: u16) -> Option<&mut LeRemote> {
        self.le.iter_mut().find(|r| r.conn.as_ref().is_some_and(|c| c.handle == handle))
    }

    /// ACL data for the host on `handle`, in fragments.
    fn le_send(&mut self, handle: u16, cid: u16, payload: &[u8]) {
        for p in l2cap::acl_packets(handle, cid, payload, LE_ACL_LEN, true) {
            self.push(p);
        }
    }

    /// Randomness for the devices' pairing (deterministic, for tests).
    fn le_random(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            self.seed = self.seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            *x = (self.seed >> 33) as u8;
        }
    }

    fn le_connect(&mut self, i: usize) {
        let handle = LE_FIRST_HANDLE + self.next_le_handle;
        self.next_le_handle += 1;
        let r = &mut self.le[i];
        r.advertising = false;
        r.conn = Some(LeConn { handle, responder: None, encrypted: false });
        r.server.mtu = att::DEFAULT_MTU;
        // Notifications are off on a new connection unless bonded
        // (Vol 3, Part G, §3.3.3.3: a bonded client's CCCDs are kept).
        let bonded = r.bond.is_some();
        if !bonded && let Some(a) = r.server.attrs.get_mut(usize::from(r.input)) {
            a.value = alloc::vec![0, 0];
        }
        let (addr_type, addr) = (r.addr_type, r.addr);
        self.log.push(alloc::format!("LE connected {addr}"));
        self.push(le::event::connection_complete(0, handle, addr_type, addr));
        // As mice do: ask for a shorter interval, and (bonded) for
        // security, so the host encrypts with the bond's key.
        self.le_send(handle, l2cap::CID_LE_SIGNALLING, &l2cap::param_update_request(1, 6, 9, 44, 216));
        if bonded {
            self.le_send(handle, smp::CID, &[smp::SECURITY_REQUEST, smp::AUTH_BONDING | smp::AUTH_SC]);
        }
    }

    /// An LE command; false when it isn't one.
    pub(crate) fn le_command(&mut self, op: u16, p: &[u8]) -> bool {
        match op {
            le::OP_WRITE_LE_HOST_SUPPORT | le::OP_LE_SET_EVENT_MASK | le::OP_LE_SET_SCAN_PARAMETERS => {
                self.complete(op, &[0])
            }
            le::OP_LE_READ_BUFFER_SIZE => self.complete(op, &[0, LE_ACL_LEN as u8, 0, LE_ACL_PACKETS]),
            le::OP_LE_SET_SCAN_ENABLE => {
                self.le_scan = p.first() == Some(&1);
                self.complete(op, &[0]);
                if self.le_scan {
                    let adverts: Vec<Advert> = self.le.iter().filter(|r| r.advertising).map(|r| r.advert()).collect();
                    for a in adverts {
                        self.push(le::event::advertising_report(&a));
                    }
                }
            }
            le::OP_LE_CREATE_CONNECTION => {
                self.status(op, 0);
                let kind = p.get(5).copied().unwrap_or(0);
                let addr = p.get(6..).and_then(BdAddr::from_wire).unwrap_or_default();
                self.le_initiating = Some((kind, addr));
                self.le_try_connect();
            }
            le::OP_LE_CREATE_CONNECTION_CANCEL => {
                self.complete(op, &[0]);
                if let Some((kind, addr)) = self.le_initiating.take() {
                    self.push(le::event::connection_complete(ERR_UNKNOWN_CONNECTION, 0, kind, addr));
                }
            }
            le::OP_LE_CONNECTION_UPDATE => {
                self.status(op, 0);
                let w = |i: usize| u16::from_le_bytes([p[i], p[i + 1]]);
                if p.len() >= 10 {
                    self.push(le::event::connection_update(w(0), w(4), w(6), w(8)));
                }
            }
            le::OP_LE_START_ENCRYPTION => {
                self.status(op, 0);
                let handle = u16::from_le_bytes([p[0], p[1]]);
                let rand = u64::from_le_bytes(p.get(2..10).and_then(|b| b.try_into().ok()).unwrap_or_default());
                let ediv = u16::from_le_bytes([p[10], p[11]]);
                let ltk: [u8; 16] = p.get(12..28).and_then(|b| b.try_into().ok()).unwrap_or_default();
                self.le_encrypt(handle, ltk, ediv, rand);
            }
            OP_DISCONNECT => {
                let handle = u16::from_le_bytes([p[0], p[1]]);
                let Some(r) = self.le_conn_of(handle) else { return false };
                r.conn = None;
                // A bonded device waits for its host again.
                r.advertising = true;
                let addr = r.addr;
                self.log.push(alloc::format!("LE disconnected {addr}"));
                self.status(op, 0);
                let mut e = alloc::vec![0];
                e.extend_from_slice(&handle.to_le_bytes());
                e.push(ERR_LOCAL_HOST_TERMINATED);
                self.ev(EV_DISCONNECTION_COMPLETE, &e);
            }
            _ => return false,
        }
        true
    }

    /// Connect the host's pending LE connection if its device advertises.
    fn le_try_connect(&mut self) {
        let Some((_, addr)) = self.le_initiating else { return };
        if let Some(i) = self.le.iter().position(|r| r.addr == addr && r.advertising && r.conn.is_none()) {
            self.le_initiating = None;
            self.le_connect(i);
        }
    }

    fn le_encrypt(&mut self, handle: u16, ltk: [u8; 16], ediv: u16, rand: u64) {
        let mut rng_seed = [0u8; 64];
        self.le_random(&mut rng_seed);
        let Some(r) = self.le_conn_of(handle) else {
            self.push(le::event::encryption_change(ERR_UNKNOWN_CONNECTION, handle, false));
            return;
        };
        let pairing = r.conn.as_ref().and_then(|c| c.responder.as_ref()).and_then(|s| s.expected_key());
        let ok = match pairing {
            Some(k) => k == ltk && ediv == 0 && rand == 0,
            None => r.bond.as_ref().is_some_and(|b| b.ltk == ltk && b.ediv == ediv && b.rand == rand),
        };
        let addr = r.addr;
        if !ok {
            self.log.push(alloc::format!("LE {addr}: wrong key"));
            // PIN or Key Missing (Vol 1, Part F).
            self.push(le::event::encryption_change(ERR_PIN_OR_KEY_MISSING, handle, false));
            return;
        }
        if let Some(c) = r.conn.as_mut() {
            c.encrypted = true;
        }
        self.log.push(alloc::format!("LE {addr}: encrypted"));
        self.push(le::event::encryption_change(0, handle, true));
        // During pairing: the device hands out its keys now.
        let mut pos = 0;
        let mut rng = |b: &mut [u8]| {
            for x in b.iter_mut() {
                *x = rng_seed[pos % 64] ^ (pos as u8);
                pos += 1;
            }
        };
        let steps = self
            .le_conn_of(handle)
            .and_then(|r| r.conn.as_mut())
            .and_then(|c| c.responder.as_mut())
            .map(|s| s.encrypted(&mut rng))
            .unwrap_or_default();
        self.le_steps(handle, steps);
    }

    fn le_steps(&mut self, handle: u16, steps: Vec<smp::Step>) {
        for s in steps {
            match s {
                smp::Step::Send(p) => self.le_send(handle, smp::CID, &p),
                smp::Step::Done(keys) => {
                    if let Some(r) = self.le_conn_of(handle) {
                        r.bond = Some(keys);
                        let a = r.addr;
                        self.log.push(alloc::format!("LE paired {a}"));
                    }
                }
                smp::Step::Failed(reason) => self.log.push(alloc::format!("LE pairing failed ({reason})")),
                smp::Step::Encrypt { .. } => {}
            }
        }
    }

    /// ACL data from the host, framed.
    pub fn acl(&mut self, packet: &[u8]) {
        if let Some((h, _, _)) = l2cap::parse_acl(packet) {
            // The controller has sent it on and freed its buffer.
            self.push(le::event::completed_packets(h, 1));
        }
        let Some((handle, cid, payload)) = self.le_reassembler.take(packet) else { return };
        let our = (le::ADDR_PUBLIC, self.addr);
        let mut seed = [0u8; 64];
        self.le_random(&mut seed);
        let mut pos = 0;
        let mut rng = |b: &mut [u8]| {
            for x in b.iter_mut() {
                *x = seed[pos % 64].wrapping_add(pos as u8);
                pos += 1;
            }
        };
        let Some(r) = self.le_conn_of(handle) else { return };
        match cid {
            att::CID => {
                let encrypted = r.encrypted();
                let (rsp, _) = r.server.serve(&payload, encrypted);
                if let Some(rsp) = rsp {
                    self.le_send(handle, att::CID, &rsp);
                }
            }
            smp::CID => {
                let (own, sc) = ((r.addr_type, r.addr), r.sc);
                let Some(c) = r.conn.as_mut() else { return };
                if payload.first() == Some(&smp::PAIRING_REQUEST) {
                    let id = smp::Identity { irk: [0x5A; 16], addr_type: own.0, addr: own.1 };
                    c.responder = Some(smp::Responder::new(own, our, sc, id));
                }
                let steps = c.responder.as_mut().map(|s| s.received(&payload, &mut rng)).unwrap_or_default();
                self.le_steps(handle, steps);
            }
            // The host's answers on the signalling channel need nothing.
            _ => {}
        }
    }

    /// Mouse `addr` moved (buttons held, X, Y, wheel): a notification when
    /// it is connected, encrypted and its host turned them on. Whether one
    /// was sent.
    pub fn mouse_input(&mut self, addr: BdAddr, buttons: u8, dx: i8, dy: i8, wheel: i8) -> bool {
        let Some(r) = self.le.iter().find(|r| r.addr == addr) else { return false };
        let Some(c) = &r.conn else { return false };
        let on = r.server.get(r.input + 1).is_some_and(|a| a.value.first() == Some(&1));
        if !c.encrypted || !on {
            return false;
        }
        let (handle, input) = (c.handle, r.input);
        self.le_send(handle, att::CID, &att::notification(input, &[buttons, dx as u8, dy as u8, wheel as u8]));
        true
    }

    /// Device `addr` starts (or stops) advertising, as a mouse switched
    /// on does; a connection the host is waiting to make is made.
    pub fn le_advertise(&mut self, addr: BdAddr, on: bool) {
        let Some(r) = self.le.iter_mut().find(|r| r.addr == addr) else { return };
        r.advertising = on && r.conn.is_none();
        if r.advertising {
            let a = r.advert();
            if self.le_scan {
                self.push(le::event::advertising_report(&a));
            }
            self.le_try_connect();
        }
    }

    /// The host reset the controller: every LE link is gone (Vol 4, Part
    /// E, §7.3.2), and their devices advertise again.
    pub(crate) fn le_reset(&mut self) {
        self.le_scan = false;
        self.le_initiating = None;
        self.le_reassembler = l2cap::Reassembler::default();
        for r in &mut self.le {
            if r.conn.take().is_some() {
                r.advertising = true;
            }
        }
    }

    /// Device `addr` goes out of range: its link drops (supervision
    /// timeout).
    pub fn le_drop(&mut self, addr: BdAddr) {
        let Some(r) = self.le.iter_mut().find(|r| r.addr == addr) else { return };
        let Some(c) = r.conn.take() else { return };
        r.advertising = false;
        self.le_reassembler.forget(c.handle);
        let mut e = alloc::vec![0];
        e.extend_from_slice(&c.handle.to_le_bytes());
        e.push(le::ERR_CONNECTION_TIMEOUT);
        self.ev(EV_DISCONNECTION_COMPLETE, &e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The host's side driven by hand: scan, connect, pair (Secure
    /// Connections), read the HID service, move the mouse; then connect
    /// again with the bond.
    #[test]
    fn pair_and_report() {
        let host = BdAddr([0x00, 0x1B, 0xDC, 0x0F, 0x00, 0x01]);
        let mut c = Controller::new(host, Vec::new());
        c.le = nearby_le();
        let mouse = c.le[0].addr;
        c.command(&le::cmd::set_scan_enable(true));
        let evs: Vec<Event> = c.take_events().iter().filter_map(|e| parse_event(e)).collect();
        assert!(evs.iter().any(|e| matches!(e, Event::Le(le::LeEvent::Adverts(v)) if v[0].addr == mouse)));
        c.command(&le::cmd::create_connection(le::ADDR_RANDOM, mouse));
        let mut handle = 0;
        let mut reasm = l2cap::Reassembler::default();
        let frames = |c: &mut Controller, reasm: &mut l2cap::Reassembler, handle: &mut u16| {
            let mut out = Vec::new();
            for p in c.take_events() {
                if p[0] == H4_ACL {
                    if let Some(f) = reasm.take(&p) {
                        out.push(f);
                    }
                } else if let Some(Event::Le(le::LeEvent::ConnectionComplete { handle: h, .. })) = parse_event(&p) {
                    *handle = h;
                }
            }
            out
        };
        let f = frames(&mut c, &mut reasm, &mut handle);
        assert!(handle >= LE_FIRST_HANDLE);
        assert!(
            f.iter().any(|(_, cid, p)| *cid == l2cap::CID_LE_SIGNALLING && p[0] == l2cap::SIG_PARAM_UPDATE_REQUEST)
        );
        // Pairing.
        let id = smp::Identity { irk: [1; 16], addr_type: 0, addr: host };
        let (mut init, first) = smp::Initiator::start((0, host), (1, mouse), id);
        let mut rng = |b: &mut [u8]| b.iter_mut().enumerate().for_each(|(i, x)| *x = i as u8 * 7 + 3);
        let mut to_dev = alloc::vec![first];
        let mut keys = None;
        for _ in 0..20 {
            for p in core::mem::take(&mut to_dev) {
                for a in l2cap::acl_packets(handle, smp::CID, &p, 27, false) {
                    c.acl(&a);
                }
            }
            for (_, cid, p) in frames(&mut c, &mut reasm, &mut handle) {
                if cid != smp::CID {
                    continue;
                }
                for s in init.received(&p, &mut rng) {
                    match s {
                        smp::Step::Send(p) => to_dev.push(p),
                        smp::Step::Encrypt { ltk, ediv, rand } => {
                            c.command(&le::cmd::start_encryption(handle, rand, ediv, &ltk));
                            for s in init.encrypted() {
                                match s {
                                    smp::Step::Send(p) => to_dev.push(p),
                                    smp::Step::Done(k) => keys = Some(k),
                                    _ => {}
                                }
                            }
                        }
                        smp::Step::Done(k) => keys = Some(k),
                        s => panic!("{s:?}"),
                    }
                }
            }
            if keys.is_some() && to_dev.is_empty() {
                break;
            }
        }
        let keys = keys.expect("paired");
        assert!(keys.secure && c.le[0].encrypted());
        assert_eq!(keys.identity, Some((1, mouse)));
        // GATT: the HID host until ready.
        let (mut hid, first) = hogp::Client::start();
        let mut pdu = Some(first);
        let mut ready = None;
        while let Some(p) = pdu.take() {
            for a in l2cap::acl_packets(handle, att::CID, &p, 27, false) {
                c.acl(&a);
            }
            for (_, cid, p) in frames(&mut c, &mut reasm, &mut handle) {
                if cid == att::CID {
                    for o in hid.received(&p) {
                        match o {
                            hogp::Out::Send(p) => pdu = Some(p),
                            hogp::Out::Ready(d) => ready = Some(d),
                            o => panic!("{o:?}"),
                        }
                    }
                }
            }
        }
        assert_eq!(ready.expect("ready").name.as_deref(), Some("Slate Mouse"));
        assert!(c.mouse_input(mouse, 1, 4, -2, 0));
        let f = frames(&mut c, &mut reasm, &mut handle);
        assert_eq!(hid.received(&f[0].2), [hogp::Out::Report(alloc::vec![1, 1, 4, 0xFE, 0])]);
        // Out of range, back: connected again, and the bond's key works.
        c.le_drop(mouse);
        c.take_events();
        c.command(&le::cmd::create_connection(le::ADDR_RANDOM, mouse));
        assert!(frames(&mut c, &mut reasm, &mut handle).is_empty(), "not advertising: nothing yet");
        c.le_advertise(mouse, true);
        let f = frames(&mut c, &mut reasm, &mut handle);
        assert!(f.iter().any(|(_, cid, p)| *cid == smp::CID && p[0] == smp::SECURITY_REQUEST));
        c.command(&le::cmd::start_encryption(handle, keys.rand, keys.ediv, &keys.ltk));
        assert!(c.le[0].encrypted());
        // Notifications stayed on with the bond.
        assert!(c.mouse_input(mouse, 0, 1, 1, 0));
        // A wrong key is refused.
        c.le_drop(mouse);
        c.le_advertise(mouse, true);
        c.command(&le::cmd::create_connection(le::ADDR_RANDOM, mouse));
        c.take_events();
        c.command(&le::cmd::start_encryption(handle + 1, 0, 0, &[0; 16]));
        let evs: Vec<Event> = c.take_events().iter().filter_map(|e| parse_event(e)).collect();
        assert!(evs.contains(&Event::EncryptionChange {
            status: ERR_PIN_OR_KEY_MISSING,
            handle: handle + 1,
            on: false
        }));
    }
}
