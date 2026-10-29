// SPDX-License-Identifier: MIT OR Apache-2.0

//! A USB Bluetooth adapter for QEMU (ADR 0113). QEMU has no Bluetooth
//! device any more, so the `bluetooth` scenario gives the guest one
//! through `usb-redir`: QEMU connects to this program's socket and speaks
//! the USB redirection protocol (usbredir's
//! docs/usb-redirection-protocol.md, version 0.7) as the usb-guest; this
//! is the usb-host, playing a primary controller (class 0xE0/0x01/0x01,
//! Bluetooth Core 5.4, Vol 4, Part B) whose HCI is `slate_hci::sim`, with
//! a phone and a keyboard nearby, and an LE mouse (ADR 0176) whose data
//! goes over the bulk endpoints and which the scenario moves
//! ([`Adapter::mouse`]).
//!
//! The packet type numbers are the order of the document's list (hello 0,
//! device_connect 1, ..., data packets from 100), as QEMU sends them.
//! The capabilities offered are those QEMU's xHCI needs: the device
//! version in device_connect, max packet sizes in ep_info, 64-bit ids and
//! 32-bit bulk lengths.

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use slate_hci::BdAddr;
use slate_hci::sim::{Controller, nearby};
use slate_hci::sim_le::nearby_le;

use crate::Result;

// Packet types (the protocol's enum order).
const HELLO: u32 = 0;
const DEVICE_CONNECT: u32 = 1;
const RESET: u32 = 3;
const INTERFACE_INFO: u32 = 4;
const EP_INFO: u32 = 5;
const SET_CONFIGURATION: u32 = 6;
const GET_CONFIGURATION: u32 = 7;
const CONFIGURATION_STATUS: u32 = 8;
const SET_ALT_SETTING: u32 = 9;
const GET_ALT_SETTING: u32 = 10;
const ALT_SETTING_STATUS: u32 = 11;
const START_INTERRUPT_RECEIVING: u32 = 15;
const STOP_INTERRUPT_RECEIVING: u32 = 16;
const INTERRUPT_RECEIVING_STATUS: u32 = 17;
const CANCEL_DATA_PACKET: u32 = 21;
const CONTROL_PACKET: u32 = 100;
const BULK_PACKET: u32 = 101;
const INTERRUPT_PACKET: u32 = 103;
// Statuses.
const SUCCESS: u8 = 0;
const CANCELLED: u8 = 1;
const STALL: u8 = 4;
/// Capabilities: connect_device_version (1), ep_info_max_packet_size (4),
/// 64bits_ids (5), 32bits_bulk_length (6).
const CAPS: u32 = (1 << 1) | (1 << 4) | (1 << 5) | (1 << 6);
/// The adapter's own address in the scenario.
pub const ADDRESS: BdAddr = BdAddr([0xC0, 0xFF, 0xEE, 0x00, 0x00, 0x01]);
/// The event endpoint's packet size (Vol 4, Part B, §2.1.1: 16).
const EVENT_PACKET: usize = 16;

/// What the scenario asks of the simulated LE mouse.
#[derive(Clone, Copy, Debug)]
enum Act {
    Move {
        buttons: u8,
        dx: i8,
        dy: i8,
    },
    /// Out of range (its link drops), or back (it advertises).
    Away,
    Back,
}

/// The adapter, listening for QEMU.
pub struct Adapter {
    pub port: u16,
    log: Arc<Mutex<Vec<String>>>,
    acts: Arc<Mutex<Vec<Act>>>,
}

impl Adapter {
    pub fn start() -> Result<Adapter> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("Bluetooth adapter: {e}"))?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let log = Arc::new(Mutex::new(Vec::new()));
        let acts = Arc::new(Mutex::new(Vec::new()));
        let (l, a) = (log.clone(), acts.clone());
        std::thread::spawn(move || {
            // QEMU connects again after a device_del and device_add.
            for s in listener.incoming().flatten() {
                let r = serve(s, &l, &a);
                l.lock().unwrap().push(format!("connection ended: {}", r.err().unwrap_or_else(|| "closed".into())));
            }
        });
        Ok(Adapter { port, log, acts })
    }

    /// The LE mouse moves (buttons held, X, Y).
    pub fn mouse(&self, buttons: u8, dx: i8, dy: i8) {
        self.acts.lock().unwrap().push(Act::Move { buttons, dx, dy });
    }

    /// The LE mouse goes out of range (or is switched off), or comes back
    /// (switched on: it advertises, in pairing mode while unpaired).
    pub fn mouse_away(&self, away: bool) {
        self.acts.lock().unwrap().push(if away { Act::Away } else { Act::Back });
    }

    /// What happened, in words.
    pub fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

fn device_descriptor() -> Vec<u8> {
    // USB 2.0, class E0/01/01, 64-byte ep0, a test VID:PID (pid.codes'
    // 1209:0001), version 1.00, manufacturer 1, product 2, one
    // configuration.
    vec![18, 1, 0x00, 0x02, 0xE0, 1, 1, 64, 0x09, 0x12, 0x01, 0x00, 0x00, 0x01, 1, 2, 0, 1]
}

fn config_descriptor() -> Vec<u8> {
    let body = [
        // Interface 0: three endpoints, the controller.
        9,
        4,
        0,
        0,
        3,
        0xE0,
        1,
        1,
        0, //
        7,
        5,
        0x81,
        3,
        EVENT_PACKET as u8,
        0,
        1, // events, interrupt IN
        7,
        5,
        0x82,
        2,
        0x00,
        0x02,
        0, // ACL in, bulk 512
        7,
        5,
        0x02,
        2,
        0x00,
        0x02,
        0, // ACL out, bulk 512
    ];
    let total = (9 + body.len()) as u16;
    let mut d = vec![9, 2, total as u8, (total >> 8) as u8, 1, 1, 0, 0x80, 50];
    d.extend_from_slice(&body);
    d
}

fn string_descriptor(index: u8) -> Vec<u8> {
    let text = match index {
        0 => return vec![4, 3, 0x09, 0x04],
        1 => "Slate",
        2 => "Bluetooth test adapter",
        _ => return Vec::new(),
    };
    let mut d = vec![0, 3];
    for c in text.encode_utf16() {
        d.extend_from_slice(&c.to_le_bytes());
    }
    d[0] = d.len() as u8;
    d
}

struct Link {
    s: TcpStream,
    /// After both hellos: 64-bit ids.
    wide: bool,
}

impl Link {
    fn send(&mut self, kind: u32, id: u64, body: &[u8]) -> Result {
        let mut p = kind.to_le_bytes().to_vec();
        p.extend_from_slice(&(body.len() as u32).to_le_bytes());
        if self.wide {
            p.extend_from_slice(&id.to_le_bytes());
        } else {
            p.extend_from_slice(&(id as u32).to_le_bytes());
        }
        p.extend_from_slice(body);
        self.s.write_all(&p).map_err(|e| e.to_string())
    }

    /// A packet, or None when nothing came in a while.
    fn recv(&mut self) -> Result<Option<(u32, u64, Vec<u8>)>> {
        let mut head = [0u8; 16];
        let n = if self.wide { 16 } else { 12 };
        match self.s.read_exact(&mut head[..1]) {
            Ok(()) => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => return Ok(None),
            Err(e) => return Err(e.to_string()),
        }
        // The rest of a packet that has begun: wait for it.
        let poll = self.s.read_timeout().map_err(|e| e.to_string())?;
        self.s.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
        let r = self.rest(&mut head, n);
        self.s.set_read_timeout(poll).map_err(|e| e.to_string())?;
        r
    }

    fn rest(&mut self, head: &mut [u8; 16], n: usize) -> Result<Option<(u32, u64, Vec<u8>)>> {
        self.s.read_exact(&mut head[1..n]).map_err(|e| e.to_string())?;
        let kind = u32::from_le_bytes(head[0..4].try_into().unwrap());
        let len = u32::from_le_bytes(head[4..8].try_into().unwrap()) as usize;
        let id = if self.wide {
            u64::from_le_bytes(head[8..16].try_into().unwrap())
        } else {
            u64::from(u32::from_le_bytes(head[8..12].try_into().unwrap()))
        };
        let mut body = vec![0u8; len];
        self.s.read_exact(&mut body).map_err(|e| e.to_string())?;
        Ok(Some((kind, id, body)))
    }

    /// The endpoints, then the interface (the protocol wants them before
    /// device_connect and configuration or alt setting statuses).
    fn describe(&mut self) -> Result {
        let mut types = [255u8; 32];
        let (mut interval, iface) = ([0u8; 32], [0u8; 32]);
        let mut mps = [0u16; 32];
        // Out endpoints 0-15, then in endpoints 0-15.
        for (i, t, m) in [(0, 0, 64), (16, 0, 64), (2, 2, 512), (17, 3, EVENT_PACKET as u16), (18, 2, 512)] {
            types[i] = t;
            mps[i] = m;
        }
        interval[17] = 1;
        let mut ep = types.to_vec();
        ep.extend_from_slice(&interval);
        ep.extend_from_slice(&iface);
        for m in mps {
            ep.extend_from_slice(&m.to_le_bytes());
        }
        self.send(EP_INFO, 0, &ep)?;
        let mut ii = 1u32.to_le_bytes().to_vec();
        for first in [0u8, 0xE0, 1, 1] {
            let mut a = [0u8; 32];
            a[0] = first;
            ii.extend_from_slice(&a);
        }
        self.send(INTERFACE_INFO, 0, &ii)
    }
}

fn serve(s: TcpStream, log: &Arc<Mutex<Vec<String>>>, acts: &Arc<Mutex<Vec<Act>>>) -> Result {
    let say = |m: String| log.lock().unwrap().push(m);
    let mut link = Link { s, wide: false };
    let mut hello = b"slate xtask bluetooth adapter".to_vec();
    hello.resize(64, 0);
    hello.extend_from_slice(&CAPS.to_le_bytes());
    link.send(HELLO, 0, &hello)?;
    let (kind, _, body) = loop {
        if let Some(p) = link.recv()? {
            break p;
        }
    };
    if kind != HELLO || body.len() < 68 {
        return Err(format!("expected a hello, got packet type {kind}"));
    }
    let theirs = u32::from_le_bytes(body[64..68].try_into().unwrap());
    if theirs & CAPS != CAPS {
        return Err(format!("QEMU lacks capabilities ({theirs:#x})"));
    }
    link.wide = true;
    say("QEMU connected".into());
    link.describe()?;
    // High speed, class E0/01/01, the IDs, version 1.00.
    let mut dc = vec![2, 0xE0, 1, 1];
    dc.extend_from_slice(&[0x09, 0x12, 0x01, 0x00, 0x00, 0x01]);
    link.send(DEVICE_CONNECT, 0, &dc)?;
    link.s.set_read_timeout(Some(Duration::from_millis(20))).map_err(|e| e.to_string())?;
    let mut hci = Controller::new(ADDRESS, nearby());
    hci.le = nearby_le();
    // Switched off until the scenario switches it on, in pairing mode.
    hci.le[0].advertising = false;
    let mouse = hci.le[0].addr;
    let mut receiving = false;
    let mut events: VecDeque<Vec<u8>> = VecDeque::new();
    // ACL data for the host, a packet per bulk IN transfer.
    let mut acl: VecDeque<Vec<u8>> = VecDeque::new();
    let mut interrupt_id = 0u64;
    let mut bulk_in: Vec<u64> = Vec::new();
    let mut logged = 0;
    loop {
        if let Some((kind, id, body)) = link.recv()? {
            match kind {
                RESET => {
                    receiving = false;
                    events.clear();
                    acl.clear();
                }
                SET_CONFIGURATION => {
                    link.describe()?;
                    link.send(CONFIGURATION_STATUS, id, &[SUCCESS, body.first().copied().unwrap_or(1)])?;
                }
                GET_CONFIGURATION => link.send(CONFIGURATION_STATUS, id, &[SUCCESS, 1])?,
                SET_ALT_SETTING => {
                    link.describe()?;
                    link.send(ALT_SETTING_STATUS, id, &[SUCCESS, body[0], body[1]])?;
                }
                GET_ALT_SETTING => link.send(ALT_SETTING_STATUS, id, &[SUCCESS, body[0], 0])?,
                START_INTERRUPT_RECEIVING => {
                    receiving = true;
                    link.send(INTERRUPT_RECEIVING_STATUS, id, &[SUCCESS, body[0]])?;
                }
                STOP_INTERRUPT_RECEIVING => {
                    receiving = false;
                    link.send(INTERRUPT_RECEIVING_STATUS, id, &[SUCCESS, body[0]])?;
                }
                CANCEL_DATA_PACKET => {
                    if let Some(i) = bulk_in.iter().position(|b| *b == id) {
                        bulk_in.remove(i);
                        link.send(BULK_PACKET, id, &[0x82, CANCELLED, 0, 0, 0, 0, 0, 0, 0, 0])?;
                    }
                }
                CONTROL_PACKET if body.len() >= 10 => {
                    // endpoint, request, requesttype, status, value,
                    // index, length; OUT data follows.
                    let (req, rt) = (body[1], body[2]);
                    let value = u16::from_le_bytes([body[4], body[5]]);
                    let len = usize::from(u16::from_le_bytes([body[8], body[9]]));
                    let mut head = body[..10].to_vec();
                    if rt & 0x80 != 0 {
                        let data = match (rt, req, (value >> 8) as u8) {
                            (0x80, 6, 1) => device_descriptor(),
                            (0x80, 6, 2) => config_descriptor(),
                            (0x80, 6, 3) => string_descriptor(value as u8),
                            // GET_STATUS: bus powered, nothing set.
                            (0x80, 0, _) => vec![0, 0],
                            _ => Vec::new(),
                        };
                        let data = &data[..data.len().min(len)];
                        head[3] = if data.is_empty() { STALL } else { SUCCESS };
                        head[8..10].copy_from_slice(&(data.len() as u16).to_le_bytes());
                        let mut p = head;
                        p.extend_from_slice(data);
                        link.send(CONTROL_PACKET, id, &p)?;
                    } else {
                        if rt == 0x20 && req == 0 {
                            // An HCI command.
                            let mut packet = vec![slate_hci::H4_COMMAND];
                            packet.extend_from_slice(&body[10..]);
                            hci.command(&packet);
                        }
                        head[3] = SUCCESS;
                        link.send(CONTROL_PACKET, id, &head)?;
                    }
                }
                BULK_PACKET if !body.is_empty() => {
                    if body[0] & 0x80 != 0 {
                        // ACL data in: answered as data comes.
                        bulk_in.push(id);
                    } else {
                        // ACL data out: endpoint, status, length, stream,
                        // length's high half, then the data.
                        if body.len() > 10 {
                            let mut packet = vec![slate_hci::H4_ACL];
                            packet.extend_from_slice(&body[10..]);
                            hci.acl(&packet);
                        }
                        let mut head = body[..10.min(body.len())].to_vec();
                        head[1] = SUCCESS;
                        link.send(BULK_PACKET, id, &head)?;
                    }
                }
                _ => {}
            }
        }
        for act in std::mem::take(&mut *acts.lock().unwrap()) {
            match act {
                Act::Move { buttons, dx, dy } => {
                    if !hci.mouse_input(mouse, buttons, dx, dy, 0) {
                        say("mouse moved, unheard".into());
                    }
                }
                Act::Away => hci.le_drop(mouse),
                Act::Back => hci.le_advertise(mouse, true),
            }
        }
        for p in hci.take_events() {
            if p.first() == Some(&slate_hci::H4_ACL) {
                acl.push_back(p[1..].to_vec());
            } else {
                events.push_back(p);
            }
        }
        while !bulk_in.is_empty() && !acl.is_empty() {
            let (id, data) = (bulk_in.remove(0), acl.pop_front().unwrap_or_default());
            let mut p = vec![0x82, SUCCESS];
            p.extend_from_slice(&(data.len() as u16).to_le_bytes());
            p.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            p.extend_from_slice(&data);
            link.send(BULK_PACKET, id, &p)?;
        }
        // Events go up the interrupt endpoint, a packet's size at a time.
        while receiving && let Some(e) = events.pop_front() {
            for chunk in e[1..].chunks(EVENT_PACKET) {
                let mut p = vec![0x81, SUCCESS];
                p.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
                p.extend_from_slice(chunk);
                link.send(INTERRUPT_PACKET, interrupt_id, &p)?;
                interrupt_id += 1;
            }
        }
        if hci.log.len() > logged {
            for l in &hci.log[logged..] {
                say(l.clone());
            }
            logged = hci.log.len();
        }
    }
}
