// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Bluetooth Host Controller Interface (ADR 0113), from the Bluetooth
//! Core Specification 5.4, Volume 4: the packets the host and a BR/EDR
//! controller exchange, the commands Slate sends, the events it reads,
//! addresses and classes of device. [`sim`] is a controller with devices
//! nearby, for tests: the daemon's host tests and the QEMU scenario's
//! stand-in USB adapter both use it.
//!
//! Packets travel framed as on the UART transport (Vol 4, Part A, §2): a
//! type byte ([`H4_COMMAND`], [`H4_ACL`], [`H4_EVENT`]) and the packet.
//! /dev/hci0 reads and writes them so.

#![no_std]

extern crate alloc;

pub mod att;
pub mod hogp;
pub mod l2cap;
pub mod le;
pub mod mtk;
pub mod sim;
#[cfg(feature = "smp")]
pub mod sim_le;
#[cfg(feature = "smp")]
pub mod smp;

use alloc::string::String;
use alloc::vec::Vec;

/// UART transport packet types (Vol 4, Part A, §2).
pub const H4_COMMAND: u8 = 0x01;
pub const H4_ACL: u8 = 0x02;
pub const H4_EVENT: u8 = 0x04;

/// A device address (BD_ADDR), as written: the most significant byte
/// first. On the wire it goes least significant first (Vol 4, Part E,
/// §5.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BdAddr(pub [u8; 6]);

impl BdAddr {
    /// From its wire order.
    pub fn from_wire(b: &[u8]) -> Option<BdAddr> {
        let w: [u8; 6] = b.get(..6)?.try_into().ok()?;
        Some(BdAddr([w[5], w[4], w[3], w[2], w[1], w[0]]))
    }

    pub fn wire(&self) -> [u8; 6] {
        let a = self.0;
        [a[5], a[4], a[3], a[2], a[1], a[0]]
    }

    /// `00:1A:7D:DA:71:13`.
    pub fn parse(s: &str) -> Option<BdAddr> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return None;
        }
        let mut a = [0u8; 6];
        for (i, p) in parts.iter().enumerate() {
            if p.len() != 2 {
                return None;
            }
            a[i] = u8::from_str_radix(p, 16).ok()?;
        }
        Some(BdAddr(a))
    }
}

impl core::fmt::Display for BdAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let a = self.0;
        write!(f, "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", a[0], a[1], a[2], a[3], a[4], a[5])
    }
}

// Opcodes: OGF << 10 | OCF (Vol 4, Part E, §7). Link Control (OGF 1).
pub const OP_INQUIRY: u16 = 0x0401;
pub const OP_INQUIRY_CANCEL: u16 = 0x0402;
pub const OP_CREATE_CONNECTION: u16 = 0x0405;
pub const OP_DISCONNECT: u16 = 0x0406;
pub const OP_ACCEPT_CONNECTION: u16 = 0x0409;
pub const OP_REJECT_CONNECTION: u16 = 0x040A;
pub const OP_LINK_KEY_REPLY: u16 = 0x040B;
pub const OP_LINK_KEY_NEGATIVE_REPLY: u16 = 0x040C;
pub const OP_PIN_CODE_NEGATIVE_REPLY: u16 = 0x040E;
pub const OP_AUTHENTICATION_REQUESTED: u16 = 0x0411;
pub const OP_REMOTE_NAME_REQUEST: u16 = 0x0419;
pub const OP_IO_CAPABILITY_REPLY: u16 = 0x042B;
pub const OP_USER_CONFIRMATION_REPLY: u16 = 0x042C;
pub const OP_USER_CONFIRMATION_NEGATIVE_REPLY: u16 = 0x042D;
pub const OP_IO_CAPABILITY_NEGATIVE_REPLY: u16 = 0x0434;
// Controller and Baseband (OGF 3).
pub const OP_SET_EVENT_MASK: u16 = 0x0C01;
pub const OP_RESET: u16 = 0x0C03;
pub const OP_WRITE_LOCAL_NAME: u16 = 0x0C13;
pub const OP_WRITE_SCAN_ENABLE: u16 = 0x0C1A;
pub const OP_WRITE_CLASS_OF_DEVICE: u16 = 0x0C24;
pub const OP_WRITE_INQUIRY_MODE: u16 = 0x0C45;
pub const OP_WRITE_SIMPLE_PAIRING_MODE: u16 = 0x0C56;
// Informational (OGF 4).
pub const OP_READ_LOCAL_VERSION: u16 = 0x1001;
pub const OP_READ_BUFFER_SIZE: u16 = 0x1005;
pub const OP_READ_BD_ADDR: u16 = 0x1009;

// Event codes (Vol 4, Part E, §7.7).
pub const EV_INQUIRY_COMPLETE: u8 = 0x01;
pub const EV_INQUIRY_RESULT: u8 = 0x02;
pub const EV_CONNECTION_COMPLETE: u8 = 0x03;
pub const EV_CONNECTION_REQUEST: u8 = 0x04;
pub const EV_DISCONNECTION_COMPLETE: u8 = 0x05;
pub const EV_AUTHENTICATION_COMPLETE: u8 = 0x06;
pub const EV_REMOTE_NAME_COMPLETE: u8 = 0x07;
pub const EV_COMMAND_COMPLETE: u8 = 0x0E;
pub const EV_COMMAND_STATUS: u8 = 0x0F;
pub const EV_HARDWARE_ERROR: u8 = 0x10;
pub const EV_PIN_CODE_REQUEST: u8 = 0x16;
pub const EV_LINK_KEY_REQUEST: u8 = 0x17;
pub const EV_LINK_KEY_NOTIFICATION: u8 = 0x18;
pub const EV_INQUIRY_RESULT_RSSI: u8 = 0x22;
pub const EV_EXTENDED_INQUIRY_RESULT: u8 = 0x2F;
pub const EV_IO_CAPABILITY_REQUEST: u8 = 0x31;
pub const EV_IO_CAPABILITY_RESPONSE: u8 = 0x32;
pub const EV_USER_CONFIRMATION_REQUEST: u8 = 0x33;
pub const EV_SIMPLE_PAIRING_COMPLETE: u8 = 0x36;
pub const EV_USER_PASSKEY_NOTIFICATION: u8 = 0x3B;

/// Error codes (Vol 1, Part F): those Slate names.
pub const ERR_UNKNOWN_CONNECTION: u8 = 0x02;
pub const ERR_PAGE_TIMEOUT: u8 = 0x04;
pub const ERR_AUTHENTICATION_FAILURE: u8 = 0x05;
pub const ERR_PIN_OR_KEY_MISSING: u8 = 0x06;
pub const ERR_REMOTE_USER_TERMINATED: u8 = 0x13;
pub const ERR_LOCAL_HOST_TERMINATED: u8 = 0x16;
pub const ERR_PAIRING_NOT_ALLOWED: u8 = 0x18;

/// IO capabilities (Vol 4, Part E, §7.1.29).
pub const IO_DISPLAY_ONLY: u8 = 0;
pub const IO_DISPLAY_YES_NO: u8 = 1;
pub const IO_KEYBOARD_ONLY: u8 = 2;
pub const IO_NO_INPUT_NO_OUTPUT: u8 = 3;
/// Authentication requirements: MITM protection, general bonding.
pub const AUTH_MITM_GENERAL_BONDING: u8 = 0x05;

/// The General Inquiry Access Code (Assigned Numbers, Baseband).
pub const GIAC: [u8; 3] = [0x33, 0x8B, 0x9E];
/// ACL packet types for Create_Connection: DM1, DH1, DM3, DH3, DM5, DH5.
pub const PACKET_TYPES: u16 = 0xCC18;

/// A command packet (Vol 4, Part E, §5.4.1), framed for /dev/hci0.
pub fn command(opcode: u16, params: &[u8]) -> Vec<u8> {
    let mut p = alloc::vec![H4_COMMAND, opcode as u8, (opcode >> 8) as u8, params.len() as u8];
    p.extend_from_slice(params);
    p
}

/// A command's opcode and parameters, from a framed packet.
pub fn parse_command(p: &[u8]) -> Option<(u16, &[u8])> {
    if p.len() < 4 || p[0] != H4_COMMAND {
        return None;
    }
    let n = usize::from(p[3]);
    Some((u16::from_le_bytes([p[1], p[2]]), p.get(4..4 + n)?))
}

/// An event packet, framed.
pub fn event(code: u8, params: &[u8]) -> Vec<u8> {
    let mut p = alloc::vec![H4_EVENT, code, params.len() as u8];
    p.extend_from_slice(params);
    p
}

/// Commands Slate sends, each framed.
pub mod cmd {
    use super::*;

    pub fn reset() -> Vec<u8> {
        command(OP_RESET, &[])
    }
    pub fn read_bd_addr() -> Vec<u8> {
        command(OP_READ_BD_ADDR, &[])
    }
    pub fn read_local_version() -> Vec<u8> {
        command(OP_READ_LOCAL_VERSION, &[])
    }
    pub fn read_buffer_size() -> Vec<u8> {
        command(OP_READ_BUFFER_SIZE, &[])
    }
    /// Every event up to bit 61, LE Meta (§7.3.1; the rest are reserved).
    pub fn set_event_mask() -> Vec<u8> {
        command(OP_SET_EVENT_MASK, &0x3FFF_FFFF_FFFF_FFFFu64.to_le_bytes())
    }
    pub fn write_simple_pairing_mode(on: bool) -> Vec<u8> {
        command(OP_WRITE_SIMPLE_PAIRING_MODE, &[u8::from(on)])
    }
    /// 2: Inquiry Result with RSSI or Extended Inquiry Result.
    pub fn write_inquiry_mode_extended() -> Vec<u8> {
        command(OP_WRITE_INQUIRY_MODE, &[2])
    }
    pub fn write_class_of_device(cod: u32) -> Vec<u8> {
        command(OP_WRITE_CLASS_OF_DEVICE, &cod.to_le_bytes()[..3])
    }
    /// The name, UTF-8, NUL-padded to 248 bytes.
    pub fn write_local_name(name: &str) -> Vec<u8> {
        let mut b = [0u8; 248];
        let n = name.len().min(247);
        b[..n].copy_from_slice(&name.as_bytes()[..n]);
        command(OP_WRITE_LOCAL_NAME, &b)
    }
    /// Bit 0: discoverable (inquiry scan); bit 1: connectable (page scan).
    pub fn write_scan_enable(discoverable: bool, connectable: bool) -> Vec<u8> {
        command(OP_WRITE_SCAN_ENABLE, &[u8::from(discoverable) | (u8::from(connectable) << 1)])
    }
    /// Look for devices for `units` × 1.28 s.
    pub fn inquiry(units: u8) -> Vec<u8> {
        command(OP_INQUIRY, &[GIAC[0], GIAC[1], GIAC[2], units, 0])
    }
    pub fn inquiry_cancel() -> Vec<u8> {
        command(OP_INQUIRY_CANCEL, &[])
    }
    pub fn remote_name_request(a: BdAddr, page_scan_mode: u8, clock_offset: u16) -> Vec<u8> {
        let mut p = a.wire().to_vec();
        p.extend_from_slice(&[page_scan_mode, 0]);
        p.extend_from_slice(&clock_offset.to_le_bytes());
        command(OP_REMOTE_NAME_REQUEST, &p)
    }
    pub fn create_connection(a: BdAddr, page_scan_mode: u8, clock_offset: u16) -> Vec<u8> {
        let mut p = a.wire().to_vec();
        p.extend_from_slice(&PACKET_TYPES.to_le_bytes());
        p.extend_from_slice(&[page_scan_mode, 0]);
        p.extend_from_slice(&clock_offset.to_le_bytes());
        // Allow the remote to switch roles.
        p.push(1);
        command(OP_CREATE_CONNECTION, &p)
    }
    pub fn disconnect(handle: u16, reason: u8) -> Vec<u8> {
        let mut p = handle.to_le_bytes().to_vec();
        p.push(reason);
        command(OP_DISCONNECT, &p)
    }
    pub fn authentication_requested(handle: u16) -> Vec<u8> {
        command(OP_AUTHENTICATION_REQUESTED, &handle.to_le_bytes())
    }
    pub fn link_key_reply(a: BdAddr, key: &[u8; 16]) -> Vec<u8> {
        let mut p = a.wire().to_vec();
        p.extend_from_slice(key);
        command(OP_LINK_KEY_REPLY, &p)
    }
    pub fn link_key_negative_reply(a: BdAddr) -> Vec<u8> {
        command(OP_LINK_KEY_NEGATIVE_REPLY, &a.wire())
    }
    pub fn pin_code_negative_reply(a: BdAddr) -> Vec<u8> {
        command(OP_PIN_CODE_NEGATIVE_REPLY, &a.wire())
    }
    pub fn io_capability_reply(a: BdAddr, io: u8, auth: u8) -> Vec<u8> {
        let mut p = a.wire().to_vec();
        // No out-of-band data.
        p.extend_from_slice(&[io, 0, auth]);
        command(OP_IO_CAPABILITY_REPLY, &p)
    }
    pub fn user_confirmation_reply(a: BdAddr, yes: bool) -> Vec<u8> {
        let op = if yes { OP_USER_CONFIRMATION_REPLY } else { OP_USER_CONFIRMATION_NEGATIVE_REPLY };
        command(op, &a.wire())
    }
    pub fn accept_connection(a: BdAddr) -> Vec<u8> {
        let mut p = a.wire().to_vec();
        // Stay the peripheral.
        p.push(1);
        command(OP_ACCEPT_CONNECTION, &p)
    }
    pub fn reject_connection(a: BdAddr) -> Vec<u8> {
        let mut p = a.wire().to_vec();
        // "Connection rejected due to security reasons".
        p.push(0x0E);
        command(OP_REJECT_CONNECTION, &p)
    }
}

/// A device found by an inquiry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub addr: BdAddr,
    pub page_scan_mode: u8,
    pub class: u32,
    pub clock_offset: u16,
    pub rssi: Option<i8>,
    /// The name in its extended inquiry response, if it sent one.
    pub name: Option<String>,
}

/// The events Slate reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Command Complete: the opcode and its return parameters (status
    /// first, for most).
    Complete {
        opcode: u16,
        ret: Vec<u8>,
    },
    /// Command Status: the command started (status 0) or not.
    Status {
        opcode: u16,
        status: u8,
    },
    InquiryComplete {
        status: u8,
    },
    Found(Vec<Found>),
    ConnectionComplete {
        status: u8,
        handle: u16,
        addr: BdAddr,
    },
    ConnectionRequest {
        addr: BdAddr,
        class: u32,
    },
    Disconnected {
        status: u8,
        handle: u16,
        reason: u8,
    },
    AuthenticationComplete {
        status: u8,
        handle: u16,
    },
    RemoteName {
        status: u8,
        addr: BdAddr,
        name: String,
    },
    PinCodeRequest(BdAddr),
    LinkKeyRequest(BdAddr),
    LinkKey {
        addr: BdAddr,
        key: [u8; 16],
        kind: u8,
    },
    IoCapabilityRequest(BdAddr),
    IoCapabilityResponse {
        addr: BdAddr,
        io: u8,
        auth: u8,
    },
    UserConfirmation {
        addr: BdAddr,
        value: u32,
    },
    PasskeyNotification {
        addr: BdAddr,
        passkey: u32,
    },
    SimplePairingComplete {
        status: u8,
        addr: BdAddr,
    },
    HardwareError(u8),
    /// Encryption Change (§7.7.8), or a key refresh (on: true).
    EncryptionChange {
        status: u8,
        handle: u16,
        on: bool,
    },
    /// Number Of Completed Packets: (handle, packets) the controller has
    /// sent and freed (§7.7.19).
    Completed(Vec<(u16, u16)>),
    /// An LE Meta event (§7.7.65).
    Le(le::LeEvent),
    Other(u8),
}

pub(crate) fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn cod_at(b: &[u8], at: usize) -> Option<u32> {
    let c = b.get(at..at + 3)?;
    Some(u32::from(c[0]) | (u32::from(c[1]) << 8) | (u32::from(c[2]) << 16))
}

/// A NUL-terminated (or full) UTF-8 name field.
fn name_field(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from(String::from_utf8_lossy(&b[..end]))
}

/// The name in extended inquiry response data (Core Specification
/// Supplement, Part A, §1.2: complete 0x09, else shortened 0x08).
pub fn eir_name(eir: &[u8]) -> Option<String> {
    let mut i = 0;
    let mut short = None;
    while i < eir.len() {
        let len = usize::from(eir[i]);
        if len == 0 || i + 1 + len > eir.len() {
            break;
        }
        let (kind, data) = (eir[i + 1], &eir[i + 2..i + 1 + len]);
        match kind {
            0x09 => return Some(name_field(data)),
            0x08 => short = Some(name_field(data)),
            _ => {}
        }
        i += 1 + len;
    }
    short
}

/// Read a framed event packet.
pub fn parse_event(p: &[u8]) -> Option<Event> {
    if p.len() < 3 || p[0] != H4_EVENT {
        return None;
    }
    let (code, n) = (p[1], usize::from(p[2]));
    let b = p.get(3..3 + n)?;
    let addr = |at: usize| BdAddr::from_wire(b.get(at..)?);
    Some(match code {
        EV_COMMAND_COMPLETE => Event::Complete { opcode: u16_at(b, 1)?, ret: b.get(3..)?.to_vec() },
        EV_COMMAND_STATUS => Event::Status { opcode: u16_at(b, 2)?, status: b[0] },
        EV_INQUIRY_COMPLETE => Event::InquiryComplete { status: *b.first()? },
        EV_INQUIRY_RESULT | EV_INQUIRY_RESULT_RSSI => {
            // Parameters in arrays, one per field (§7.7.2, §7.7.33).
            let k = usize::from(*b.first()?);
            let rssi = code == EV_INQUIRY_RESULT_RSSI;
            let (psrm, cod) = (1 + 6 * k, 1 + 6 * k + k * if rssi { 2 } else { 3 });
            let clock = cod + 3 * k;
            let mut v = Vec::new();
            for i in 0..k {
                v.push(Found {
                    addr: addr(1 + 6 * i)?,
                    page_scan_mode: *b.get(psrm + i)?,
                    class: cod_at(b, cod + 3 * i)?,
                    clock_offset: u16_at(b, clock + 2 * i)?,
                    rssi: if rssi { Some(*b.get(clock + 2 * k + i)? as i8) } else { None },
                    name: None,
                });
            }
            Event::Found(v)
        }
        EV_EXTENDED_INQUIRY_RESULT => Event::Found(alloc::vec![Found {
            addr: addr(1)?,
            page_scan_mode: *b.get(7)?,
            class: cod_at(b, 9)?,
            clock_offset: u16_at(b, 12)?,
            rssi: Some(*b.get(14)? as i8),
            name: eir_name(b.get(15..)?),
        }]),
        EV_CONNECTION_COMPLETE => {
            Event::ConnectionComplete { status: b[0], handle: u16_at(b, 1)? & 0x0FFF, addr: addr(3)? }
        }
        EV_CONNECTION_REQUEST => Event::ConnectionRequest { addr: addr(0)?, class: cod_at(b, 6)? },
        EV_DISCONNECTION_COMPLETE => {
            Event::Disconnected { status: b[0], handle: u16_at(b, 1)? & 0x0FFF, reason: *b.get(3)? }
        }
        EV_AUTHENTICATION_COMPLETE => Event::AuthenticationComplete { status: b[0], handle: u16_at(b, 1)? & 0x0FFF },
        EV_REMOTE_NAME_COMPLETE => Event::RemoteName { status: b[0], addr: addr(1)?, name: name_field(b.get(7..)?) },
        EV_PIN_CODE_REQUEST => Event::PinCodeRequest(addr(0)?),
        EV_LINK_KEY_REQUEST => Event::LinkKeyRequest(addr(0)?),
        EV_LINK_KEY_NOTIFICATION => {
            Event::LinkKey { addr: addr(0)?, key: b.get(6..22)?.try_into().ok()?, kind: *b.get(22)? }
        }
        EV_IO_CAPABILITY_REQUEST => Event::IoCapabilityRequest(addr(0)?),
        EV_IO_CAPABILITY_RESPONSE => Event::IoCapabilityResponse { addr: addr(0)?, io: *b.get(6)?, auth: *b.get(8)? },
        EV_USER_CONFIRMATION_REQUEST => Event::UserConfirmation { addr: addr(0)?, value: u32_at(b, 6)? },
        EV_USER_PASSKEY_NOTIFICATION => Event::PasskeyNotification { addr: addr(0)?, passkey: u32_at(b, 6)? },
        EV_SIMPLE_PAIRING_COMPLETE => Event::SimplePairingComplete { status: b[0], addr: addr(1)? },
        EV_HARDWARE_ERROR => Event::HardwareError(*b.first()?),
        le::EV_ENCRYPTION_CHANGE => {
            Event::EncryptionChange { status: b[0], handle: u16_at(b, 1)? & 0x0FFF, on: *b.get(3)? != 0 }
        }
        le::EV_ENCRYPTION_KEY_REFRESH => {
            Event::EncryptionChange { status: b[0], handle: u16_at(b, 1)? & 0x0FFF, on: true }
        }
        le::EV_NUMBER_OF_COMPLETED_PACKETS => {
            let n = usize::from(*b.first()?);
            Event::Completed(
                (0..n).map(|i| Some((u16_at(b, 1 + 4 * i)? & 0x0FFF, u16_at(b, 3 + 4 * i)?))).collect::<Option<_>>()?,
            )
        }
        le::EV_LE_META => Event::Le(le::parse_meta(b)?),
        c => Event::Other(c),
    })
}

/// What a device is, from its class of device's major and minor classes
/// (Assigned Numbers, Baseband: Class of Device).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Computer,
    Phone,
    Headphones,
    Speaker,
    Keyboard,
    Mouse,
    Gamepad,
    Other,
}

impl Kind {
    pub fn of(class: u32) -> Kind {
        let (major, minor) = ((class >> 8) & 0x1F, (class >> 2) & 0x3F);
        match major {
            1 => Kind::Computer,
            2 => Kind::Phone,
            // Audio/video: headset, hands-free, headphones; loudspeaker.
            4 => match minor {
                5 => Kind::Speaker,
                _ => Kind::Headphones,
            },
            // Peripherals: bits 7-6 keyboard / pointing; bits 5-2
            // joystick, gamepad.
            5 => match (minor >> 4, minor & 0xF) {
                (_, 1 | 2) => Kind::Gamepad,
                (1 | 3, _) => Kind::Keyboard,
                (2, _) => Kind::Mouse,
                _ => Kind::Other,
            },
            _ => Kind::Other,
        }
    }

    pub fn word(self) -> &'static str {
        match self {
            Kind::Computer => "computer",
            Kind::Phone => "phone",
            Kind::Headphones => "headphones",
            Kind::Speaker => "speaker",
            Kind::Keyboard => "keyboard",
            Kind::Mouse => "mouse",
            Kind::Gamepad => "gamepad",
            Kind::Other => "device",
        }
    }

    pub fn from_word(w: &str) -> Kind {
        [Kind::Computer, Kind::Phone, Kind::Headphones, Kind::Speaker, Kind::Keyboard, Kind::Mouse, Kind::Gamepad]
            .into_iter()
            .find(|k| k.word() == w)
            .unwrap_or(Kind::Other)
    }
}

/// Slate's own class of device: a desktop computer (major 1, minor 1).
pub const CLASS_DESKTOP: u32 = 0x00_0104;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        let a = BdAddr::parse("00:1A:7D:DA:71:13").unwrap();
        assert_eq!(a.wire(), [0x13, 0x71, 0xDA, 0x7D, 0x1A, 0x00]);
        assert_eq!(BdAddr::from_wire(&a.wire()), Some(a));
        assert_eq!(alloc::format!("{a}"), "00:1A:7D:DA:71:13");
        assert_eq!(BdAddr::parse("00:1A:7D"), None);
        assert_eq!(BdAddr::parse("00:1A:7D:DA:71:1G"), None);
    }

    #[test]
    fn commands_and_events() {
        assert_eq!(cmd::reset(), [1, 0x03, 0x0C, 0]);
        assert_eq!(cmd::inquiry(8), [1, 0x01, 0x04, 5, 0x33, 0x8B, 0x9E, 8, 0]);
        let a = BdAddr([1, 2, 3, 4, 5, 6]);
        let cc = cmd::create_connection(a, 1, 0x1234);
        let (op, p) = parse_command(&cc).unwrap();
        assert_eq!((op, p.len(), &p[..6]), (OP_CREATE_CONNECTION, 13, &a.wire()[..]));
        // Command Complete for Read_BD_ADDR.
        let mut ret = alloc::vec![1, 0x09, 0x10, 0];
        ret.extend_from_slice(&a.wire());
        let e = parse_event(&event(EV_COMMAND_COMPLETE, &ret)).unwrap();
        assert_eq!(e, Event::Complete { opcode: OP_READ_BD_ADDR, ret: [&[0u8][..], &a.wire()].concat() });
        // An extended inquiry result with a name.
        let mut ext = alloc::vec![1];
        ext.extend_from_slice(&a.wire());
        ext.extend_from_slice(&[1, 0, 0x0C, 0x02, 0x5A, 0x34, 0x12, 0xC8]);
        let mut eir = alloc::vec![0u8; 240];
        eir[..7].copy_from_slice(&[6, 0x09, b'P', b'h', b'o', b'n', b'e']);
        ext.extend_from_slice(&eir);
        let Event::Found(f) = parse_event(&event(EV_EXTENDED_INQUIRY_RESULT, &ext)).unwrap() else { panic!() };
        assert_eq!(
            (f[0].addr, f[0].name.as_deref(), f[0].clock_offset, f[0].rssi),
            (a, Some("Phone"), 0x1234, Some(-56))
        );
        assert_eq!(Kind::of(f[0].class), Kind::Phone);
        // Two plain inquiry results, in arrays.
        let b = BdAddr([9, 9, 9, 9, 9, 9]);
        let mut r = alloc::vec![2];
        r.extend_from_slice(&a.wire());
        r.extend_from_slice(&b.wire());
        r.extend_from_slice(&[1, 2, 0, 0, 0, 0, 0x40, 0x05, 0x00, 0x80, 0x05, 0x00, 0x11, 0x00, 0x22, 0x00]);
        let Event::Found(f) = parse_event(&event(EV_INQUIRY_RESULT, &r)).unwrap() else { panic!() };
        assert_eq!((f[1].addr, f[1].page_scan_mode, f[1].clock_offset), (b, 2, 0x22));
        assert_eq!((Kind::of(f[0].class), Kind::of(f[1].class)), (Kind::Keyboard, Kind::Mouse));
        let mut uc = BdAddr([1; 6]).wire().to_vec();
        uc.extend_from_slice(&123_456u32.to_le_bytes());
        assert_eq!(
            parse_event(&event(EV_USER_CONFIRMATION_REQUEST, &uc)),
            Some(Event::UserConfirmation { addr: BdAddr([1; 6]), value: 123_456 })
        );
        assert_eq!(parse_event(&[4, 0x0E, 9, 1]), None, "too short");
    }
}
