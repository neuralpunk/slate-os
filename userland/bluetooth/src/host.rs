// SPDX-License-Identifier: MIT OR Apache-2.0

//! The host's side of a BR/EDR controller (ADR 0113): what Slate asks of
//! it and what it does with the answers, without I/O. The daemon feeds it
//! events ([`Host::event`]) and sends the commands it hands out
//! ([`Host::next_command`]), one at a time: each waits for its Command
//! Complete or Command Status (Vol 4, Part E, §4.4).
//!
//! - **Starting:** Reset, then the controller's address, version and
//!   buffers, the event mask, Secure Simple Pairing on, extended inquiry
//!   results, the class of device (a desktop computer), the name, and
//!   connectable (page scan) for paired devices; discoverable too while
//!   someone looks ([`Host::set_visible`]).
//! - **Discovering:** a General Inquiry of about ten seconds; names come
//!   in extended inquiry results, else from Remote Name Request.
//! - **Pairing:** Create Connection, Authentication Requested, then Secure
//!   Simple Pairing with this computer as DisplayYesNo, asking for MITM
//!   protection and general bonding: numeric comparison and Just Works
//!   are a [`Prompt`] the person answers ([`Host::confirm`]); passkey
//!   entry shows the passkey to type on the device. The link key the
//!   controller gives is kept; the connection is closed after (no
//!   profiles are driven yet).
//! - **Connecting:** a paired device's stored key answers Link Key
//!   Request; a device that forgot this computer fails authentication.
//! - Legacy PIN pairing is refused (PIN Code Request Negative Reply).
//! - **Low Energy** ([`crate::le`], ADR 0176): found by scanning beside
//!   the inquiry, paired with SMP, reconnected when a bonded device
//!   advertises, and HID devices driven over GATT.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_hci::{BdAddr, Event, Kind, cmd};

/// A device the host knows: found nearby, paired, or both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub addr: BdAddr,
    pub name: String,
    pub kind: Kind,
    /// From the last inquiry: page scan mode and clock offset.
    pub page_scan_mode: u8,
    pub clock_offset: u16,
    /// Seen by the last discovery.
    pub nearby: bool,
    /// The link key, once paired, and its type.
    pub key: Option<([u8; 16], u8)>,
    pub connected: Option<u16>,
    /// An LE device's own (ADR 0176).
    pub le: Option<LeInfo>,
}

/// What an LE device has of its own: its address type (0 public, 1
/// random) and the keys pairing left.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LeInfo {
    pub addr_type: u8,
    pub keys: Option<slate_hci::smp::Keys>,
    /// Paired without anyone choosing it (no pointer was there): it may
    /// point but not type.
    pub auto: bool,
}

impl Device {
    pub fn paired(&self) -> bool {
        self.key.is_some() || self.le.as_ref().is_some_and(|l| l.keys.is_some())
    }

    /// Its name, or its address while it has none.
    pub fn shown(&self) -> String {
        if self.name.is_empty() { self.addr.to_string() } else { self.name.clone() }
    }
}

/// A question for the person.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prompt {
    /// Numeric comparison: the six digits both show; yes or no.
    Confirm(BdAddr, u32),
    /// Just Works: pair, yes or no (the device shows nothing).
    Pair(BdAddr),
    /// Passkey entry: type these digits on the device.
    Passkey(BdAddr, u32),
}

impl Prompt {
    pub fn addr(&self) -> BdAddr {
        match self {
            Prompt::Confirm(a, _) | Prompt::Pair(a) | Prompt::Passkey(a, _) => *a,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Pair,
    Connect,
}

/// The pairing or connecting under way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Op {
    pub addr: BdAddr,
    pub purpose: Purpose,
    pub handle: Option<u16>,
    /// The remote's IO capability, once it said.
    pub remote_io: Option<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Off,
    Starting,
    On,
    Failed(String),
}

#[derive(Debug)]
pub struct Host {
    pub state: State,
    pub addr: Option<BdAddr>,
    pub name: String,
    pub visible: bool,
    pub discovering: bool,
    pub devices: Vec<Device>,
    pub op: Option<Op>,
    pub prompt: Option<Prompt>,
    /// What the last operation came to, and whether it failed.
    pub said: Option<(String, bool)>,
    /// The paired devices changed: write them out.
    pub dirty: bool,
    queue: VecDeque<Vec<u8>>,
    awaiting: Option<u16>,
    /// Names to ask for after an inquiry.
    names: Vec<BdAddr>,
    /// What the inquiry under way has seen (the list keeps the last
    /// one's until it ends).
    seen: Vec<BdAddr>,
    /// Things worth a log line, taken by the daemon.
    pub notes: Vec<String>,
    // --- Low Energy (crate::le) ---
    /// The controller does LE, its LE data packets' size, how many more it
    /// takes now and how many each link has in it.
    pub le_ok: bool,
    pub(crate) le_len: usize,
    pub(crate) le_credits: u16,
    pub(crate) in_flight: BTreeMap<u16, u16>,
    /// The BR/EDR buffer, which LE shares when it has none of its own.
    pub(crate) acl_len: usize,
    pub(crate) acl_packets: u16,
    pub(crate) acl_out: VecDeque<Vec<u8>>,
    pub(crate) links: Vec<crate::le::Link>,
    pub(crate) reassembler: slate_hci::l2cap::Reassembler,
    /// Whether the controller scans, and the device being connected to.
    pub(crate) scanning: bool,
    pub(crate) le_connecting: Option<BdAddr>,
    /// Bonded devices that refused their key (they forgot this computer):
    /// not reconnected until the person pairs or connects them again.
    pub(crate) refused: Vec<BdAddr>,
    /// A mouse in pairing mode is paired by itself (the daemon says, from
    /// the setting). Those tried, and the pairing under way that nobody
    /// asked for.
    pub autopair: bool,
    pub(crate) auto_tried: Vec<BdAddr>,
    pub(crate) auto_pairing: Option<BdAddr>,
    /// HID devices made, fed and closed, for the daemon to apply.
    pub hid: Vec<crate::le::HidEvent>,
    /// Randomness for pairing, and the identity key this computer hands
    /// out.
    pub rng: fn(&mut [u8]),
    pub irk: [u8; 16],
}

impl Host {
    pub fn new(name: &str, paired: Vec<Device>) -> Host {
        Host {
            state: State::Off,
            addr: None,
            name: name.to_string(),
            visible: false,
            discovering: false,
            devices: paired,
            op: None,
            prompt: None,
            said: None,
            dirty: false,
            queue: VecDeque::new(),
            awaiting: None,
            names: Vec::new(),
            seen: Vec::new(),
            notes: Vec::new(),
            le_ok: false,
            le_len: 0,
            le_credits: 0,
            in_flight: BTreeMap::new(),
            acl_len: 0,
            acl_packets: 0,
            acl_out: VecDeque::new(),
            links: Vec::new(),
            reassembler: slate_hci::l2cap::Reassembler::default(),
            scanning: false,
            le_connecting: None,
            refused: Vec::new(),
            autopair: false,
            auto_tried: Vec::new(),
            auto_pairing: None,
            hid: Vec::new(),
            rng: |b| {
                let _ = slate_rt::process::random(b);
            },
            irk: [0; 16],
        }
    }

    pub(crate) fn send(&mut self, packet: Vec<u8>) {
        self.queue.push_back(packet);
    }

    /// A command to send before those queued.
    pub(crate) fn queue_front(&mut self, packet: Vec<u8>) {
        self.queue.push_front(packet);
    }

    pub(crate) fn seen_has(&self, a: BdAddr) -> bool {
        self.seen.contains(&a)
    }

    pub(crate) fn seen_push(&mut self, a: BdAddr) {
        self.seen.push(a);
    }

    /// The next command to send, if the last one was answered.
    pub fn next_command(&mut self) -> Option<Vec<u8>> {
        if self.awaiting.is_some() {
            return None;
        }
        self.le_update_scan();
        let p = self.queue.pop_front()?;
        self.awaiting = slate_hci::parse_command(&p).map(|(op, _)| op);
        Some(p)
    }

    fn scan_mode(&self) -> Vec<u8> {
        cmd::write_scan_enable(self.visible, true)
    }

    /// Start the controller (just found, or turned on).
    pub fn power_on(&mut self) {
        self.state = State::Starting;
        self.queue.clear();
        self.awaiting = None;
        for p in [
            cmd::reset(),
            cmd::read_bd_addr(),
            cmd::read_local_version(),
            cmd::read_buffer_size(),
            cmd::set_event_mask(),
            slate_hci::le::cmd::write_le_host_support(),
            slate_hci::le::cmd::set_event_mask(),
            slate_hci::le::cmd::read_buffer_size(),
            slate_hci::le::cmd::set_scan_parameters(true),
            cmd::write_simple_pairing_mode(true),
            cmd::write_inquiry_mode_extended(),
            cmd::write_class_of_device(slate_hci::CLASS_DESKTOP),
            cmd::write_local_name(&self.name.clone()),
            self.scan_mode(),
        ] {
            self.send(p);
        }
    }

    /// Turn the radio off: connections close, nothing scans.
    pub fn power_off(&mut self) {
        self.le_reset();
        let handles: Vec<u16> = self.devices.iter().filter_map(|d| d.connected).collect();
        for h in handles {
            self.send(cmd::disconnect(h, slate_hci::ERR_REMOTE_USER_TERMINATED));
        }
        self.send(cmd::write_scan_enable(false, false));
        self.discovering = false;
        self.op = None;
        self.prompt = None;
        self.state = State::Off;
        self.notes.push("off".into());
    }

    /// The controller went away.
    pub fn lost(&mut self) {
        self.le_reset();
        self.queue.clear();
        self.awaiting = None;
        self.discovering = false;
        self.op = None;
        self.prompt = None;
        self.addr = None;
        for d in &mut self.devices {
            d.connected = None;
        }
    }

    pub(crate) fn ready(&self) -> Result<(), String> {
        match &self.state {
            State::On => Ok(()),
            State::Off => Err("Bluetooth is off".into()),
            State::Starting => Err("Bluetooth is starting".into()),
            State::Failed(e) => Err(e.clone()),
        }
    }

    pub fn set_name(&mut self, name: &str) {
        self.name = name.chars().take(64).collect();
        if self.state == State::On {
            self.send(cmd::write_local_name(&self.name.clone()));
        }
    }

    /// Others may find this computer (while Settings' page is open).
    pub fn set_visible(&mut self, on: bool) {
        self.visible = on;
        if self.state == State::On {
            let p = self.scan_mode();
            self.send(p);
        }
    }

    /// Look for devices nearby, for about ten seconds.
    pub fn discover(&mut self) -> Result<(), String> {
        self.ready()?;
        if self.discovering {
            return Ok(());
        }
        self.seen.clear();
        self.discovering = true;
        self.send(cmd::inquiry(8));
        Ok(())
    }

    pub(crate) fn device(&mut self, a: BdAddr) -> Option<&mut Device> {
        self.devices.iter_mut().find(|d| d.addr == a)
    }

    pub(crate) fn name_of(&self, a: BdAddr) -> String {
        self.devices.iter().find(|d| d.addr == a).map_or_else(|| a.to_string(), Device::shown)
    }

    fn begin(&mut self, a: BdAddr, purpose: Purpose) -> Result<(), String> {
        self.ready()?;
        if self.op.is_some() {
            return Err("Wait for the one under way to finish".into());
        }
        let d = self.devices.iter().find(|d| d.addr == a).ok_or("No such device nearby")?;
        if purpose == Purpose::Connect && !d.paired() {
            return Err(alloc::format!("{} isn't paired", d.shown()));
        }
        if d.le.is_some() {
            return self.le_begin(a, purpose);
        }
        let (mode, clock) = (d.page_scan_mode, d.clock_offset);
        if self.discovering {
            self.send(cmd::inquiry_cancel());
            self.discovering = false;
        }
        self.op = Some(Op { addr: a, purpose, handle: None, remote_io: None });
        self.said = None;
        self.send(cmd::create_connection(a, mode, clock));
        Ok(())
    }

    pub fn pair(&mut self, a: BdAddr) -> Result<(), String> {
        self.begin(a, Purpose::Pair)
    }

    pub fn connect(&mut self, a: BdAddr) -> Result<(), String> {
        self.begin(a, Purpose::Connect)
    }

    /// The person's answer to the prompt for `a`.
    pub fn confirm(&mut self, a: BdAddr, yes: bool) -> Result<(), String> {
        match self.prompt {
            Some(Prompt::Confirm(p, _) | Prompt::Pair(p)) if p == a => {
                self.prompt = None;
                self.send(cmd::user_confirmation_reply(a, yes));
                Ok(())
            }
            _ => Err("Nothing to confirm for that device".into()),
        }
    }

    /// Forget a paired device: its key goes, and its connection.
    pub fn remove(&mut self, a: BdAddr) -> Result<(), String> {
        let d = self.device(a).ok_or("No such device")?;
        if !d.paired() {
            return Err("It isn't paired".into());
        }
        d.key = None;
        if let Some(l) = d.le.as_mut() {
            l.keys = None;
        }
        let handle = d.connected;
        let name = d.shown();
        if let Some(h) = handle {
            self.send(cmd::disconnect(h, slate_hci::ERR_REMOTE_USER_TERMINATED));
        }
        self.devices.retain(|d| d.paired() || d.nearby);
        self.dirty = true;
        self.notes.push(alloc::format!("removed {a}"));
        self.said = Some((alloc::format!("{name} is forgotten."), false));
        Ok(())
    }

    pub(crate) fn finish(&mut self, ok: bool, text: String) {
        if let Some(op) = self.op.take() {
            let pairing = op.purpose == Purpose::Pair;
            let le = self.links.iter().any(|l| l.addr == op.addr);
            // BR/EDR pairing holds a connection for nothing else: close it
            // (an LE device's link stays: its profiles run on it).
            if let (true, false, Some(h)) = (pairing, le, op.handle) {
                self.send(cmd::disconnect(h, slate_hci::ERR_REMOTE_USER_TERMINATED));
            }
            self.notes.push(alloc::format!(
                "{} {}: {}",
                if pairing { "pairing" } else { "connecting" },
                op.addr,
                if ok { "done" } else { "failed" }
            ));
        }
        self.prompt = None;
        self.said = Some((text, !ok));
    }

    pub(crate) fn error_words(status: u8) -> &'static str {
        match status {
            slate_hci::ERR_PAGE_TIMEOUT => "it didn't answer",
            slate_hci::ERR_AUTHENTICATION_FAILURE => "the pairing was refused",
            slate_hci::ERR_PIN_OR_KEY_MISSING => "it doesn't know this computer any more",
            slate_hci::ERR_PAIRING_NOT_ALLOWED => "it doesn't allow pairing now",
            _ => "it failed",
        }
    }

    /// An event (or LE data) from the controller, framed.
    pub fn event(&mut self, packet: &[u8]) {
        if packet.first() == Some(&slate_hci::H4_ACL) {
            self.le_acl(packet);
            return;
        }
        let Some(e) = slate_hci::parse_event(packet) else { return };
        match e {
            Event::Complete { opcode, ret } => {
                if self.awaiting == Some(opcode) {
                    self.awaiting = None;
                }
                let status = ret.first().copied().unwrap_or(0);
                match opcode {
                    slate_hci::OP_READ_BD_ADDR if status == 0 => self.addr = BdAddr::from_wire(&ret[1..]),
                    slate_hci::OP_READ_BUFFER_SIZE if status == 0 && ret.len() >= 8 => {
                        self.acl_len = usize::from(u16::from_le_bytes([ret[1], ret[2]]));
                        self.acl_packets = u16::from_le_bytes([ret[4], ret[5]]);
                    }
                    slate_hci::le::OP_LE_READ_BUFFER_SIZE => self.le_buffer(status, &ret),
                    slate_hci::OP_RESET if status != 0 => {
                        self.state = State::Failed(alloc::format!("the controller didn't reset ({status:#04x})"));
                        self.queue.clear();
                    }
                    _ => {}
                }
                if self.state == State::Starting && self.queue.is_empty() && self.awaiting.is_none() {
                    self.state = State::On;
                    let a = self.addr.map(|a| a.to_string()).unwrap_or_default();
                    self.notes.push(alloc::format!("on: {a}"));
                }
            }
            Event::Status { opcode, status } => {
                if self.awaiting == Some(opcode) {
                    self.awaiting = None;
                }
                if status != 0 {
                    match opcode {
                        slate_hci::OP_INQUIRY => self.discovering = false,
                        slate_hci::OP_CREATE_CONNECTION | slate_hci::OP_AUTHENTICATION_REQUESTED => {
                            let n = self.op.map(|o| self.name_of(o.addr)).unwrap_or_default();
                            self.finish(false, alloc::format!("Couldn't reach {n}: {}.", Self::error_words(status)));
                        }
                        _ => self.le_status(opcode, status),
                    }
                }
            }
            Event::Found(list) => {
                for f in list {
                    if !self.seen.contains(&f.addr) {
                        self.seen.push(f.addr);
                    }
                    let kind = Kind::of(f.class);
                    match self.device(f.addr) {
                        Some(d) => {
                            d.nearby = true;
                            d.page_scan_mode = f.page_scan_mode;
                            d.clock_offset = f.clock_offset;
                            if let Some(n) = f.name {
                                d.name = n;
                            }
                            d.kind = kind;
                        }
                        None => {
                            if f.name.is_none() {
                                self.names.push(f.addr);
                            }
                            self.devices.push(Device {
                                addr: f.addr,
                                name: f.name.unwrap_or_default(),
                                kind,
                                page_scan_mode: f.page_scan_mode,
                                clock_offset: f.clock_offset,
                                nearby: true,
                                key: None,
                                connected: None,
                                le: None,
                            });
                            self.notes.push(alloc::format!("found {}", self.name_of(f.addr)));
                        }
                    }
                }
            }
            Event::InquiryComplete { .. } => {
                self.discovering = false;
                let seen = core::mem::take(&mut self.seen);
                for d in &mut self.devices {
                    d.nearby = seen.contains(&d.addr);
                }
                self.devices.retain(|d| d.nearby || d.paired());
                let nearby = self.devices.iter().filter(|d| d.nearby).count();
                self.notes.push(alloc::format!("discovery done: {nearby} nearby"));
                for a in core::mem::take(&mut self.names) {
                    let (m, c) = self
                        .devices
                        .iter()
                        .find(|d| d.addr == a)
                        .map_or((1, 0), |d| (d.page_scan_mode, d.clock_offset));
                    self.send(cmd::remote_name_request(a, m, c));
                }
            }
            Event::RemoteName { status: 0, addr, name } => {
                if let Some(d) = self.device(addr) {
                    d.name = name;
                }
            }
            Event::RemoteName { .. } => {}
            Event::ConnectionComplete { status, handle, addr } => {
                let ours = self.op.is_some_and(|o| o.addr == addr);
                if status != 0 {
                    if ours {
                        let n = self.name_of(addr);
                        self.finish(false, alloc::format!("Couldn't reach {n}: {}.", Self::error_words(status)));
                    }
                    return;
                }
                if let Some(d) = self.device(addr) {
                    d.connected = Some(handle);
                }
                if let Some(op) = self.op.as_mut().filter(|o| o.addr == addr) {
                    op.handle = Some(handle);
                    self.send(cmd::authentication_requested(handle));
                }
            }
            Event::ConnectionRequest { addr, .. } => {
                // Paired devices may come to us; others are refused (this
                // computer starts every pairing).
                let known = self.devices.iter().any(|d| d.addr == addr && d.paired());
                self.send(if known { cmd::accept_connection(addr) } else { cmd::reject_connection(addr) });
            }
            Event::Disconnected { handle, reason, .. } => {
                self.le_disconnected(handle, reason);
                for d in &mut self.devices {
                    if d.connected == Some(handle) {
                        d.connected = None;
                    }
                }
            }
            Event::LinkKeyRequest(addr) => {
                let key = self.devices.iter().find(|d| d.addr == addr).and_then(|d| d.key);
                self.send(match key {
                    Some((k, _)) => cmd::link_key_reply(addr, &k),
                    None => cmd::link_key_negative_reply(addr),
                });
            }
            Event::PinCodeRequest(addr) => {
                self.send(cmd::pin_code_negative_reply(addr));
                let n = self.name_of(addr);
                self.finish(false, alloc::format!("{n} only pairs with a PIN, which Slate doesn't do yet."));
            }
            Event::IoCapabilityRequest(addr) => {
                let ours = self.op.is_some_and(|o| o.addr == addr && o.purpose == Purpose::Pair);
                self.send(if ours {
                    cmd::io_capability_reply(addr, slate_hci::IO_DISPLAY_YES_NO, slate_hci::AUTH_MITM_GENERAL_BONDING)
                } else {
                    // Pairing this computer didn't ask for.
                    slate_hci::command(
                        slate_hci::OP_IO_CAPABILITY_NEGATIVE_REPLY,
                        &[&addr.wire()[..], &[0x18]].concat(),
                    )
                });
            }
            Event::IoCapabilityResponse { addr, io, .. } => {
                if let Some(op) = self.op.as_mut().filter(|o| o.addr == addr) {
                    op.remote_io = Some(io);
                }
            }
            Event::UserConfirmation { addr, value } => {
                let just_works = self.op.and_then(|o| o.remote_io) == Some(slate_hci::IO_NO_INPUT_NO_OUTPUT);
                self.prompt = Some(if just_works { Prompt::Pair(addr) } else { Prompt::Confirm(addr, value) });
                self.notes.push(alloc::format!("confirm {addr} {value:06}"));
            }
            Event::PasskeyNotification { addr, passkey } => {
                self.prompt = Some(Prompt::Passkey(addr, passkey));
                self.notes.push(alloc::format!("passkey {addr} {passkey:06}"));
            }
            Event::SimplePairingComplete { status, addr } if status != 0 => {
                let n = self.name_of(addr);
                self.finish(false, alloc::format!("{n} wasn't paired: {}.", Self::error_words(status)));
            }
            Event::SimplePairingComplete { .. } => self.prompt = None,
            Event::LinkKey { addr, key, kind } => {
                if let Some(d) = self.device(addr) {
                    d.key = Some((key, kind));
                    self.dirty = true;
                }
            }
            Event::AuthenticationComplete { status, handle } => {
                let Some(op) = self.op.filter(|o| o.handle == Some(handle)) else { return };
                let n = self.name_of(op.addr);
                match (status, op.purpose) {
                    (0, Purpose::Pair) => self.finish(true, alloc::format!("Paired with {n}.")),
                    (0, Purpose::Connect) => self.finish(true, alloc::format!("Connected to {n}.")),
                    (s, purpose) => {
                        self.finish(false, alloc::format!("{n}: {}.", Self::error_words(s)));
                        // Connecting failed: close the link.
                        if purpose == Purpose::Connect {
                            self.send(cmd::disconnect(handle, slate_hci::ERR_AUTHENTICATION_FAILURE));
                        }
                    }
                }
            }
            Event::HardwareError(code) => {
                self.state = State::Failed(alloc::format!("the controller reported a hardware error ({code:#04x})"));
                self.lost();
            }
            Event::EncryptionChange { status, handle, on } => self.le_encryption(status, handle, on),
            Event::Completed(list) => self.le_completed(&list),
            Event::Le(e) => self.le_event(e),
            Event::Other(_) => {}
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use slate_hci::sim::{Controller, nearby};

    /// Run `h` against `c` until neither has anything more to say.
    pub(crate) fn settle(h: &mut Host, c: &mut Controller) {
        for _ in 0..1000 {
            let mut moved = false;
            while let Some(p) = h.next_command() {
                c.command(&p);
                moved = true;
            }
            while let Some(p) = h.next_acl() {
                c.acl(&p);
                moved = true;
            }
            for e in c.take_events() {
                h.event(&e);
                moved = true;
            }
            if !moved {
                return;
            }
        }
        panic!("no end");
    }

    fn started() -> (Host, Controller) {
        let mut c = Controller::new(BdAddr([0x00, 0x1B, 0xDC, 0x0F, 0x00, 0x01]), nearby());
        let mut h = Host::new("desk", Vec::new());
        h.power_on();
        settle(&mut h, &mut c);
        (h, c)
    }

    #[test]
    fn starting_and_discovering() {
        let (mut h, mut c) = started();
        assert_eq!(h.state, State::On);
        assert_eq!(h.addr, Some(c.addr));
        assert_eq!((c.name.as_str(), c.scan, c.simple_pairing), ("desk", 2, true));
        h.set_visible(true);
        h.discover().unwrap();
        settle(&mut h, &mut c);
        assert_eq!(c.scan, 3);
        assert!(!h.discovering);
        let found: Vec<(&str, Kind)> = h.devices.iter().map(|d| (d.name.as_str(), d.kind)).collect();
        assert_eq!(found, [("Ada's Phone", Kind::Phone), ("Slate Keyboard", Kind::Keyboard)]);
        // The phone goes out of sight: the next discovery drops it, and
        // keeps the list as it was while looking.
        c.remotes[0].discoverable = false;
        h.discover().unwrap();
        assert_eq!(h.devices.len(), 2, "unchanged while looking");
        settle(&mut h, &mut c);
        assert_eq!(h.devices.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(), ["Slate Keyboard"]);
    }

    #[test]
    fn pairing_by_numbers_then_connecting_with_the_key() {
        let (mut h, mut c) = started();
        h.discover().unwrap();
        settle(&mut h, &mut c);
        let phone = c.remotes[0].addr;
        h.pair(phone).unwrap();
        settle(&mut h, &mut c);
        assert_eq!(h.prompt, Some(Prompt::Confirm(phone, 482_913)));
        assert!(h.pair(phone).is_err(), "one at a time");
        h.confirm(phone, true).unwrap();
        settle(&mut h, &mut c);
        assert_eq!(h.said, Some(("Paired with Ada's Phone.".into(), false)));
        assert!(h.dirty && h.devices[0].paired() && h.op.is_none());
        assert_eq!(h.devices[0].connected, None, "closed after pairing");
        assert_eq!(c.remotes[0].key, h.devices[0].key.map(|k| k.0));
        // With the key: connected without questions.
        h.connect(phone).unwrap();
        settle(&mut h, &mut c);
        assert_eq!(h.said, Some(("Connected to Ada's Phone.".into(), false)));
        assert!(h.devices[0].connected.is_some());
        assert!(c.log.iter().any(|l| l.starts_with("right key")));
        // Forgotten: the key goes, the link closes.
        h.remove(phone).unwrap();
        settle(&mut h, &mut c);
        assert!(!h.devices[0].paired() && h.devices[0].connected.is_none());
    }

    #[test]
    fn passkeys_refusals_and_forgetting_devices() {
        let (mut h, mut c) = started();
        h.discover().unwrap();
        settle(&mut h, &mut c);
        let (phone, kb) = (c.remotes[0].addr, c.remotes[1].addr);
        h.pair(kb).unwrap();
        settle(&mut h, &mut c);
        assert_eq!(h.said, Some(("Paired with Slate Keyboard.".into(), false)));
        assert!(h.notes.iter().any(|n| n == "passkey 00:1F:20:44:55:66 007351"));
        // Saying no.
        h.pair(phone).unwrap();
        settle(&mut h, &mut c);
        h.confirm(phone, false).unwrap();
        settle(&mut h, &mut c);
        assert_eq!(h.said, Some(("Ada's Phone wasn't paired: the pairing was refused.".into(), true)));
        assert!(!h.devices[0].paired());
        // The keyboard forgets this computer: connecting fails and says so.
        c.remotes[1].key = None;
        h.connect(kb).unwrap();
        settle(&mut h, &mut c);
        assert_eq!(h.said, Some(("Slate Keyboard: it doesn't know this computer any more.".into(), true)));
        // Out of range.
        c.remotes.remove(0);
        h.pair(phone).unwrap();
        settle(&mut h, &mut c);
        assert_eq!(h.said, Some(("Couldn't reach Ada's Phone: it didn't answer.".into(), true)));
        // Off: nothing goes.
        h.power_off();
        assert!(h.discover().is_err());
    }
}
