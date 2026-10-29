// SPDX-License-Identifier: MIT OR Apache-2.0

//! A simulated BR/EDR controller with devices nearby (ADR 0113), for
//! tests: the Bluetooth daemon's host tests feed it the daemon's commands,
//! and xtask's stand-in USB adapter in the `bluetooth` scenario wraps it.
//! It answers as the Core Specification (Vol 4, Part E) has a controller
//! answer:
//!
//! - inquiry: Command Status, an Extended Inquiry Result for each device
//!   in range (with its name), Inquiry Complete;
//! - Create_Connection: Connection Complete (Page Timeout for a device not
//!   in range);
//! - Authentication_Requested: Link Key Request; with a key the device
//!   still has, Authentication Complete; without one, Secure Simple
//!   Pairing (Vol 2, Part H; Vol 3, Part C, §5.2.2.6): IO capabilities
//!   both ways, then numeric comparison or Just Works (User Confirmation
//!   Request), or passkey entry with the keyboard typing the passkey this
//!   computer shows (User Passkey Notification), then Simple Pairing
//!   Complete, Link Key Notification and Authentication Complete;
//! - Disconnect, Remote_Name_Request, and the setup commands.
//!
//! It holds no radio and no timing: events come at once. With the `smp`
//! feature it has LE devices too ([`crate::sim_le`]: a mouse that pairs and
//! reports), and carries their ACL data.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use super::*;

/// A device in range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Remote {
    pub addr: BdAddr,
    pub name: String,
    pub class: u32,
    /// Its IO capability (`IO_*`).
    pub io: u8,
    /// The six digits it shows for numeric comparison, or the passkey it
    /// types.
    pub number: u32,
    /// Whether it agrees to pair (its user says yes, types the passkey).
    pub accepts: bool,
    /// The link key it keeps from an earlier pairing.
    pub key: Option<[u8; 16]>,
    /// Whether it answers inquiries (it is discoverable).
    pub discoverable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Idle,
    /// Link Key Request sent.
    KeyAsked,
    /// IO Capability Request sent.
    IoAsked,
    /// User Confirmation Request sent.
    Confirming,
}

#[derive(Clone, Debug)]
struct Conn {
    handle: u16,
    addr: BdAddr,
    stage: Stage,
    /// The host's IO capability, once it said.
    host_io: u8,
}

/// The controller.
#[derive(Debug)]
pub struct Controller {
    pub addr: BdAddr,
    /// What the host wrote with Write_Local_Name.
    pub name: String,
    /// Write_Scan_Enable's bits.
    pub scan: u8,
    pub simple_pairing: bool,
    pub remotes: Vec<Remote>,
    conns: Vec<Conn>,
    next_handle: u16,
    out: VecDeque<Vec<u8>>,
    /// What happened, in words (the scenario logs it).
    pub log: Vec<String>,
    /// LE devices in range (ADR 0176), whether the host scans, the
    /// connection it is making, the next LE handle, randomness for
    /// pairing, and the host's ACL data put back together.
    #[cfg(feature = "smp")]
    pub le: Vec<crate::sim_le::LeRemote>,
    #[cfg(feature = "smp")]
    pub(crate) le_scan: bool,
    #[cfg(feature = "smp")]
    pub(crate) le_initiating: Option<(u8, BdAddr)>,
    #[cfg(feature = "smp")]
    pub(crate) next_le_handle: u16,
    #[cfg(feature = "smp")]
    pub(crate) seed: u64,
    #[cfg(feature = "smp")]
    pub(crate) le_reassembler: crate::l2cap::Reassembler,
}

impl Controller {
    pub fn new(addr: BdAddr, remotes: Vec<Remote>) -> Controller {
        Controller {
            addr,
            name: String::new(),
            scan: 0,
            simple_pairing: false,
            remotes,
            conns: Vec::new(),
            next_handle: 0x0B,
            out: VecDeque::new(),
            log: Vec::new(),
            #[cfg(feature = "smp")]
            le: Vec::new(),
            #[cfg(feature = "smp")]
            le_scan: false,
            #[cfg(feature = "smp")]
            le_initiating: None,
            #[cfg(feature = "smp")]
            next_le_handle: 0,
            #[cfg(feature = "smp")]
            seed: 0x5EED,
            #[cfg(feature = "smp")]
            le_reassembler: crate::l2cap::Reassembler::default(),
        }
    }

    /// The events waiting for the host, framed, oldest first.
    pub fn take_events(&mut self) -> Vec<Vec<u8>> {
        self.out.drain(..).collect()
    }

    pub(crate) fn ev(&mut self, code: u8, params: &[u8]) {
        self.out.push_back(event(code, params));
    }

    /// A packet for the host (an event or ACL data), framed.
    #[cfg(feature = "smp")]
    pub(crate) fn push(&mut self, packet: Vec<u8>) {
        self.out.push_back(packet);
    }

    pub(crate) fn complete(&mut self, opcode: u16, ret: &[u8]) {
        let mut p = alloc::vec![1, opcode as u8, (opcode >> 8) as u8];
        p.extend_from_slice(ret);
        self.ev(EV_COMMAND_COMPLETE, &p);
    }

    pub(crate) fn status(&mut self, opcode: u16, status: u8) {
        self.ev(EV_COMMAND_STATUS, &[status, 1, opcode as u8, (opcode >> 8) as u8]);
    }

    fn with_addr(&mut self, code: u8, a: BdAddr, rest: &[u8]) {
        let mut p = a.wire().to_vec();
        p.extend_from_slice(rest);
        self.ev(code, &p);
    }

    fn remote(&self, a: BdAddr) -> Option<&Remote> {
        self.remotes.iter().find(|r| r.addr == a)
    }

    fn conn_of(&mut self, a: BdAddr) -> Option<&mut Conn> {
        self.conns.iter_mut().find(|c| c.addr == a)
    }

    /// The link key both ends derive (a fixed function of the two
    /// addresses here; a real controller's comes from the pairing).
    pub fn key_for(&self, remote: BdAddr) -> [u8; 16] {
        let mut k = [0u8; 16];
        for (i, b) in k.iter_mut().enumerate() {
            *b = self.addr.0[i % 6].wrapping_mul(31) ^ remote.0[(i + 3) % 6].wrapping_add(i as u8 * 17);
        }
        k
    }

    fn auth_done(&mut self, a: BdAddr, status: u8) {
        let handle = self.conn_of(a).map(|c| {
            c.stage = Stage::Idle;
            c.handle
        });
        if let Some(h) = handle {
            let mut p = alloc::vec![status];
            p.extend_from_slice(&h.to_le_bytes());
            self.ev(EV_AUTHENTICATION_COMPLETE, &p);
        }
    }

    /// Simple pairing ended: `ok` or not.
    fn pairing_done(&mut self, a: BdAddr, ok: bool) {
        if ok {
            self.ev(EV_SIMPLE_PAIRING_COMPLETE, &[[0u8].as_slice(), &a.wire()].concat());
            let key = self.key_for(a);
            if let Some(r) = self.remotes.iter_mut().find(|r| r.addr == a) {
                r.key = Some(key);
            }
            // Authenticated combination key, P-256 (type 0x08) or, without
            // MITM protection (Just Works), unauthenticated (0x07).
            let just_works = self.remote(a).is_some_and(|r| r.io == IO_NO_INPUT_NO_OUTPUT);
            let mut p = key.to_vec();
            p.push(if just_works { 0x07 } else { 0x08 });
            self.with_addr(EV_LINK_KEY_NOTIFICATION, a, &p);
            self.log.push(alloc::format!("paired {a}"));
            self.auth_done(a, 0);
        } else {
            self.ev(EV_SIMPLE_PAIRING_COMPLETE, &[[ERR_AUTHENTICATION_FAILURE].as_slice(), &a.wire()].concat());
            self.log.push(alloc::format!("pairing with {a} failed"));
            self.auth_done(a, ERR_AUTHENTICATION_FAILURE);
        }
    }

    /// A command from the host, framed.
    pub fn command(&mut self, packet: &[u8]) {
        let Some((op, p)) = parse_command(packet) else { return };
        #[cfg(feature = "smp")]
        if self.le_command(op, p) {
            return;
        }
        let addr = BdAddr::from_wire(p).unwrap_or_default();
        match op {
            OP_RESET => {
                self.conns.clear();
                #[cfg(feature = "smp")]
                self.le_reset();
                self.scan = 0;
                self.complete(op, &[0]);
            }
            OP_READ_BD_ADDR => {
                let mut r = alloc::vec![0];
                r.extend_from_slice(&self.addr.wire());
                self.complete(op, &r);
            }
            // Core 5.4 (version 13); manufacturer 0xFFFF is kept for tests
            // (Assigned Numbers, Company Identifiers).
            OP_READ_LOCAL_VERSION => self.complete(op, &[0, 13, 0, 0, 13, 0xFF, 0xFF, 0, 0]),
            OP_READ_BUFFER_SIZE => self.complete(op, &[0, 0xFD, 0x03, 0x40, 0x08, 0x00, 0x00, 0x00]),
            OP_WRITE_LOCAL_NAME => {
                self.name =
                    String::from(String::from_utf8_lossy(&p[..p.iter().position(|&c| c == 0).unwrap_or(p.len())]));
                self.complete(op, &[0]);
            }
            OP_WRITE_SCAN_ENABLE => {
                self.scan = p.first().copied().unwrap_or(0);
                self.complete(op, &[0]);
            }
            OP_WRITE_SIMPLE_PAIRING_MODE => {
                self.simple_pairing = p.first() == Some(&1);
                self.complete(op, &[0]);
            }
            OP_SET_EVENT_MASK | OP_WRITE_CLASS_OF_DEVICE | OP_WRITE_INQUIRY_MODE => self.complete(op, &[0]),
            OP_INQUIRY => {
                self.status(op, 0);
                let found: Vec<Remote> = self.remotes.iter().filter(|r| r.discoverable).cloned().collect();
                for r in found {
                    let mut e = alloc::vec![1];
                    e.extend_from_slice(&r.addr.wire());
                    // Page scan mode R1, reserved, the class, a clock
                    // offset, -48 dBm.
                    e.extend_from_slice(&[1, 0]);
                    e.extend_from_slice(&r.class.to_le_bytes()[..3]);
                    e.extend_from_slice(&[0x34, 0x12, (-48i8) as u8]);
                    let mut eir = alloc::vec![0u8; 240];
                    let n = r.name.len().min(237);
                    eir[0] = n as u8 + 1;
                    eir[1] = 0x09;
                    eir[2..2 + n].copy_from_slice(&r.name.as_bytes()[..n]);
                    e.extend_from_slice(&eir);
                    self.ev(EV_EXTENDED_INQUIRY_RESULT, &e);
                }
                self.ev(EV_INQUIRY_COMPLETE, &[0]);
            }
            OP_INQUIRY_CANCEL => self.complete(op, &[0]),
            OP_REMOTE_NAME_REQUEST => {
                self.status(op, 0);
                let mut name = [0u8; 248];
                let status = match self.remote(addr) {
                    Some(r) => {
                        let n = r.name.len().min(247);
                        name[..n].copy_from_slice(&r.name.as_bytes()[..n]);
                        0
                    }
                    None => ERR_PAGE_TIMEOUT,
                };
                let mut e = alloc::vec![status];
                e.extend_from_slice(&addr.wire());
                e.extend_from_slice(&name);
                self.ev(EV_REMOTE_NAME_COMPLETE, &e);
            }
            OP_CREATE_CONNECTION => {
                self.status(op, 0);
                let mut e = alloc::vec![];
                if self.remote(addr).is_some() && self.conn_of(addr).is_none() {
                    let handle = self.next_handle;
                    self.next_handle += 1;
                    self.conns.push(Conn { handle, addr, stage: Stage::Idle, host_io: IO_DISPLAY_YES_NO });
                    self.log.push(alloc::format!("connected {addr}"));
                    e.push(0);
                    e.extend_from_slice(&handle.to_le_bytes());
                } else {
                    e.push(ERR_PAGE_TIMEOUT);
                    e.extend_from_slice(&[0, 0]);
                }
                e.extend_from_slice(&addr.wire());
                // ACL, not encrypted.
                e.extend_from_slice(&[1, 0]);
                self.ev(EV_CONNECTION_COMPLETE, &e);
            }
            OP_DISCONNECT => {
                let handle = u16::from_le_bytes([p[0], p[1]]);
                match self.conns.iter().position(|c| c.handle == handle) {
                    Some(i) => {
                        let c = self.conns.remove(i);
                        self.log.push(alloc::format!("disconnected {}", c.addr));
                        self.status(op, 0);
                        let mut e = alloc::vec![0];
                        e.extend_from_slice(&handle.to_le_bytes());
                        e.push(ERR_LOCAL_HOST_TERMINATED);
                        self.ev(EV_DISCONNECTION_COMPLETE, &e);
                    }
                    None => self.status(op, ERR_UNKNOWN_CONNECTION),
                }
            }
            OP_AUTHENTICATION_REQUESTED => {
                let handle = u16::from_le_bytes([p[0], p[1]]);
                let Some(c) = self.conns.iter_mut().find(|c| c.handle == handle) else {
                    self.status(op, ERR_UNKNOWN_CONNECTION);
                    return;
                };
                c.stage = Stage::KeyAsked;
                let a = c.addr;
                self.status(op, 0);
                self.with_addr(EV_LINK_KEY_REQUEST, a, &[]);
            }
            OP_LINK_KEY_REPLY => {
                let mut r = alloc::vec![0];
                r.extend_from_slice(&addr.wire());
                self.complete(op, &r);
                let theirs = self.remote(addr).and_then(|r| r.key);
                let ok = theirs.is_some() && theirs.as_ref().map(|k| &k[..]) == p.get(6..22);
                self.log.push(alloc::format!("{} key for {addr}", if ok { "right" } else { "wrong" }));
                self.auth_done(addr, if ok { 0 } else { ERR_PIN_OR_KEY_MISSING });
            }
            OP_LINK_KEY_NEGATIVE_REPLY => {
                let mut r = alloc::vec![0];
                r.extend_from_slice(&addr.wire());
                self.complete(op, &r);
                if !self.simple_pairing {
                    // Legacy pairing: a PIN, which Slate refuses.
                    self.with_addr(EV_PIN_CODE_REQUEST, addr, &[]);
                    return;
                }
                if let Some(c) = self.conn_of(addr) {
                    c.stage = Stage::IoAsked;
                }
                self.with_addr(EV_IO_CAPABILITY_REQUEST, addr, &[]);
            }
            OP_PIN_CODE_NEGATIVE_REPLY => {
                let mut r = alloc::vec![0];
                r.extend_from_slice(&addr.wire());
                self.complete(op, &r);
                self.auth_done(addr, ERR_PIN_OR_KEY_MISSING);
            }
            OP_IO_CAPABILITY_REPLY | OP_IO_CAPABILITY_NEGATIVE_REPLY => {
                let mut r = alloc::vec![0];
                r.extend_from_slice(&addr.wire());
                self.complete(op, &r);
                if op == OP_IO_CAPABILITY_NEGATIVE_REPLY {
                    self.pairing_done(addr, false);
                    return;
                }
                let host_io = p.get(6).copied().unwrap_or(IO_NO_INPUT_NO_OUTPUT);
                let Some(remote) = self.remote(addr).cloned() else { return };
                if let Some(c) = self.conn_of(addr) {
                    c.host_io = host_io;
                    c.stage = Stage::Confirming;
                }
                self.with_addr(EV_IO_CAPABILITY_RESPONSE, addr, &[remote.io, 0, AUTH_MITM_GENERAL_BONDING]);
                // The association model (Vol 3, Part C, table 5.7).
                if remote.io == IO_KEYBOARD_ONLY && matches!(host_io, IO_DISPLAY_ONLY | IO_DISPLAY_YES_NO) {
                    // This computer shows the passkey; the keyboard types
                    // it (here at once).
                    self.with_addr(EV_USER_PASSKEY_NOTIFICATION, addr, &remote.number.to_le_bytes());
                    self.log.push(alloc::format!("{addr} typed the passkey {:06}", remote.number));
                    self.pairing_done(addr, remote.accepts);
                } else {
                    self.with_addr(EV_USER_CONFIRMATION_REQUEST, addr, &remote.number.to_le_bytes());
                }
            }
            OP_USER_CONFIRMATION_REPLY | OP_USER_CONFIRMATION_NEGATIVE_REPLY => {
                let mut r = alloc::vec![0];
                r.extend_from_slice(&addr.wire());
                self.complete(op, &r);
                let accepts = self.remote(addr).is_some_and(|r| r.accepts);
                self.pairing_done(addr, op == OP_USER_CONFIRMATION_REPLY && accepts);
            }
            _ => self.complete(op, &[0x01]),
        }
    }
}

/// Two devices for tests: a phone that compares numbers and a keyboard
/// that types a passkey.
pub fn nearby() -> Vec<Remote> {
    alloc::vec![
        Remote {
            addr: BdAddr([0x5C, 0xF3, 0x70, 0x11, 0x22, 0x33]),
            name: String::from("Ada's Phone"),
            class: 0x5A_020C,
            io: IO_DISPLAY_YES_NO,
            number: 482_913,
            accepts: true,
            key: None,
            discoverable: true,
        },
        Remote {
            addr: BdAddr([0x00, 0x1F, 0x20, 0x44, 0x55, 0x66]),
            name: String::from("Slate Keyboard"),
            class: 0x00_0540,
            io: IO_KEYBOARD_ONLY,
            number: 7_351,
            accepts: true,
            key: None,
            discoverable: true,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(c: &mut Controller) -> Vec<Event> {
        c.take_events().iter().filter_map(|e| parse_event(e)).collect()
    }

    #[test]
    fn inquiry_and_numeric_comparison() {
        let mut c = Controller::new(BdAddr([0x00, 0x1B, 0xDC, 0x0F, 0x00, 0x01]), nearby());
        c.command(&cmd::write_simple_pairing_mode(true));
        c.command(&cmd::inquiry(4));
        let e = events(&mut c);
        assert!(matches!(e[1], Event::Status { opcode: OP_INQUIRY, status: 0 }));
        let names: Vec<String> =
            e.iter().filter_map(|e| if let Event::Found(f) = e { f[0].name.clone() } else { None }).collect();
        assert_eq!(names, ["Ada's Phone", "Slate Keyboard"]);
        assert_eq!(e.last(), Some(&Event::InquiryComplete { status: 0 }));
        let phone = c.remotes[0].addr;
        c.command(&cmd::create_connection(phone, 1, 0x1234));
        let Some(Event::ConnectionComplete { status: 0, handle, .. }) = events(&mut c).pop() else { panic!() };
        c.command(&cmd::authentication_requested(handle));
        assert_eq!(events(&mut c).pop(), Some(Event::LinkKeyRequest(phone)));
        c.command(&cmd::link_key_negative_reply(phone));
        assert_eq!(events(&mut c).pop(), Some(Event::IoCapabilityRequest(phone)));
        c.command(&cmd::io_capability_reply(phone, IO_DISPLAY_YES_NO, AUTH_MITM_GENERAL_BONDING));
        assert_eq!(events(&mut c).pop(), Some(Event::UserConfirmation { addr: phone, value: 482_913 }));
        c.command(&cmd::user_confirmation_reply(phone, true));
        let e = events(&mut c);
        assert!(e.contains(&Event::SimplePairingComplete { status: 0, addr: phone }));
        let key = c.key_for(phone);
        assert!(e.contains(&Event::LinkKey { addr: phone, key, kind: 0x08 }));
        assert_eq!(e.last(), Some(&Event::AuthenticationComplete { status: 0, handle }));
        // Again, with the key: no questions.
        c.command(&cmd::disconnect(handle, ERR_REMOTE_USER_TERMINATED));
        c.command(&cmd::create_connection(phone, 1, 0));
        let Some(Event::ConnectionComplete { handle, .. }) = events(&mut c).pop() else { panic!() };
        c.command(&cmd::authentication_requested(handle));
        c.command(&cmd::link_key_reply(phone, &key));
        assert_eq!(events(&mut c).pop(), Some(Event::AuthenticationComplete { status: 0, handle }));
    }

    #[test]
    fn passkey_and_refusals() {
        let mut c = Controller::new(BdAddr([1; 6]), nearby());
        c.command(&cmd::write_simple_pairing_mode(true));
        let kb = c.remotes[1].addr;
        c.command(&cmd::create_connection(kb, 1, 0));
        let Some(Event::ConnectionComplete { handle, .. }) = events(&mut c).pop() else { panic!() };
        c.command(&cmd::authentication_requested(handle));
        c.command(&cmd::link_key_negative_reply(kb));
        c.command(&cmd::io_capability_reply(kb, IO_DISPLAY_YES_NO, AUTH_MITM_GENERAL_BONDING));
        let e = events(&mut c);
        assert!(e.contains(&Event::PasskeyNotification { addr: kb, passkey: 7_351 }));
        assert_eq!(e.last(), Some(&Event::AuthenticationComplete { status: 0, handle }));
        // The phone, said no to.
        let phone = c.remotes[0].addr;
        c.command(&cmd::create_connection(phone, 1, 0));
        let Some(Event::ConnectionComplete { handle, .. }) = events(&mut c).pop() else { panic!() };
        c.command(&cmd::authentication_requested(handle));
        c.command(&cmd::link_key_negative_reply(phone));
        c.command(&cmd::io_capability_reply(phone, IO_DISPLAY_YES_NO, AUTH_MITM_GENERAL_BONDING));
        c.command(&cmd::user_confirmation_reply(phone, false));
        assert_eq!(
            events(&mut c).pop(),
            Some(Event::AuthenticationComplete { status: ERR_AUTHENTICATION_FAILURE, handle })
        );
        // A device out of range.
        c.command(&cmd::create_connection(BdAddr([9; 6]), 1, 0));
        assert!(matches!(events(&mut c).pop(), Some(Event::ConnectionComplete { status: ERR_PAGE_TIMEOUT, .. })));
        // A wrong key.
        c.command(&cmd::disconnect(handle, ERR_REMOTE_USER_TERMINATED));
        c.command(&cmd::create_connection(kb, 1, 0));
        let _ = events(&mut c);
        let handle = c.conns.last().unwrap().handle;
        c.command(&cmd::authentication_requested(handle));
        c.command(&cmd::link_key_reply(kb, &[0; 16]));
        assert_eq!(
            events(&mut c).pop(),
            Some(Event::AuthenticationComplete { status: ERR_PIN_OR_KEY_MISSING, handle })
        );
    }
}
