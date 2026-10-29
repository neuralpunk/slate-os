// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bluetooth Low Energy's commands and events (Core 5.4, Vol 4, Part E,
//! §7.8 and §7.7.65), the legacy advertising ones every LE controller
//! takes (ADR 0176): scanning, connecting as the central, encrypting, and
//! the parameters a connection runs with.

use alloc::string::String;
use alloc::vec::Vec;

use super::*;

// LE Controller commands (OGF 8).
pub const OP_LE_SET_EVENT_MASK: u16 = 0x2001;
pub const OP_LE_READ_BUFFER_SIZE: u16 = 0x2002;
pub const OP_LE_SET_SCAN_PARAMETERS: u16 = 0x200B;
pub const OP_LE_SET_SCAN_ENABLE: u16 = 0x200C;
pub const OP_LE_CREATE_CONNECTION: u16 = 0x200D;
pub const OP_LE_CREATE_CONNECTION_CANCEL: u16 = 0x200E;
pub const OP_LE_CONNECTION_UPDATE: u16 = 0x2013;
pub const OP_LE_START_ENCRYPTION: u16 = 0x2019;
// Controller and Baseband: LE on in a dual-mode controller (§7.3.79).
pub const OP_WRITE_LE_HOST_SUPPORT: u16 = 0x0C6D;

// Events.
pub const EV_ENCRYPTION_CHANGE: u8 = 0x08;
pub const EV_NUMBER_OF_COMPLETED_PACKETS: u8 = 0x13;
pub const EV_ENCRYPTION_KEY_REFRESH: u8 = 0x30;
pub const EV_LE_META: u8 = 0x3E;
// LE Meta subevents (§7.7.65).
pub const LE_CONNECTION_COMPLETE: u8 = 0x01;
pub const LE_ADVERTISING_REPORT: u8 = 0x02;
pub const LE_CONNECTION_UPDATE_COMPLETE: u8 = 0x03;
pub const LE_LTK_REQUEST: u8 = 0x05;

/// Advertising report event types (§7.7.65.2): connectable undirected,
/// connectable directed, scannable, non-connectable, scan response.
pub const ADV_IND: u8 = 0x00;
pub const ADV_DIRECT_IND: u8 = 0x01;
pub const ADV_SCAN_IND: u8 = 0x02;
pub const ADV_NONCONN_IND: u8 = 0x03;
pub const SCAN_RSP: u8 = 0x04;

/// Address types (§7.8.12): public, random.
pub const ADDR_PUBLIC: u8 = 0;
pub const ADDR_RANDOM: u8 = 1;

/// Error: the connection timed out, or the device didn't answer the
/// connection (Vol 1, Part F: 0x08, 0x3E).
pub const ERR_CONNECTION_TIMEOUT: u8 = 0x08;
pub const ERR_CONNECTION_FAILED_TO_ESTABLISH: u8 = 0x3E;

/// Appearance values (Assigned Numbers §2.6): HID keyboard and mouse.
pub const APPEARANCE_KEYBOARD: u16 = 0x03C1;
pub const APPEARANCE_MOUSE: u16 = 0x03C2;

/// The connection parameters Slate asks for (units of 1.25 ms, 10 ms):
/// 7.5 to 30 ms, no latency, 2 s supervision timeout. A device may ask
/// for others ([`crate::l2cap`]'s parameter update).
pub const INTERVAL_MIN: u16 = 0x0006;
pub const INTERVAL_MAX: u16 = 0x0018;
pub const SUPERVISION_TIMEOUT: u16 = 0x00C8;

pub mod cmd {
    use super::*;

    /// LE support on (dual-mode controllers keep it off until the host
    /// says, §7.3.79).
    pub fn write_le_host_support() -> Vec<u8> {
        command(OP_WRITE_LE_HOST_SUPPORT, &[1, 0])
    }
    /// The LE events Slate reads: Connection Complete, Advertising Report,
    /// Connection Update Complete, Long Term Key Request (§7.8.1).
    pub fn set_event_mask() -> Vec<u8> {
        command(OP_LE_SET_EVENT_MASK, &0x0000_0000_0000_001Fu64.to_le_bytes())
    }
    pub fn read_buffer_size() -> Vec<u8> {
        command(OP_LE_READ_BUFFER_SIZE, &[])
    }
    /// Active scanning (scan requests, for names in scan responses) every
    /// 60 ms for 30 ms, from the public address, everything accepted.
    pub fn set_scan_parameters(active: bool) -> Vec<u8> {
        command(OP_LE_SET_SCAN_PARAMETERS, &[u8::from(active), 0x60, 0x00, 0x30, 0x00, ADDR_PUBLIC, 0])
    }
    /// Scanning on or off, duplicates filtered.
    pub fn set_scan_enable(on: bool) -> Vec<u8> {
        command(OP_LE_SET_SCAN_ENABLE, &[u8::from(on), 1])
    }
    /// Connect to `addr` (of address type `kind`) as the central.
    pub fn create_connection(kind: u8, addr: BdAddr) -> Vec<u8> {
        let mut p = alloc::vec![0x60, 0x00, 0x30, 0x00, 0, kind & 1];
        p.extend_from_slice(&addr.wire());
        p.push(ADDR_PUBLIC);
        for v in [INTERVAL_MIN, INTERVAL_MAX, 0, SUPERVISION_TIMEOUT, 0, 0] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        command(OP_LE_CREATE_CONNECTION, &p)
    }
    pub fn create_connection_cancel() -> Vec<u8> {
        command(OP_LE_CREATE_CONNECTION_CANCEL, &[])
    }
    /// New parameters for a connection (what the device asked, §7.8.18).
    pub fn connection_update(handle: u16, min: u16, max: u16, latency: u16, timeout: u16) -> Vec<u8> {
        let mut p = Vec::with_capacity(14);
        for v in [handle, min, max, latency, timeout, 0, 0] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        command(OP_LE_CONNECTION_UPDATE, &p)
    }
    /// Encrypt connection `handle` with `ltk` (least significant octet
    /// first) and its Rand and EDIV (§7.8.24).
    pub fn start_encryption(handle: u16, rand: u64, ediv: u16, ltk: &[u8; 16]) -> Vec<u8> {
        let mut p = handle.to_le_bytes().to_vec();
        p.extend_from_slice(&rand.to_le_bytes());
        p.extend_from_slice(&ediv.to_le_bytes());
        p.extend_from_slice(ltk);
        command(OP_LE_START_ENCRYPTION, &p)
    }
}

/// An advertisement heard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advert {
    pub kind: u8,
    pub addr_type: u8,
    pub addr: BdAddr,
    pub data: Vec<u8>,
    pub rssi: i8,
}

impl Advert {
    /// Whether a connection can be made to it.
    pub fn connectable(&self) -> bool {
        matches!(self.kind, ADV_IND | ADV_DIRECT_IND)
    }
    pub fn name(&self) -> Option<String> {
        eir_name(&self.data)
    }
    /// Its appearance (Core Specification Supplement, Part A, §1.12).
    pub fn appearance(&self) -> Option<u16> {
        ad_field(&self.data, 0x19).and_then(|d| Some(u16::from_le_bytes(d.get(..2)?.try_into().ok()?)))
    }
}

/// The data of advertising data structure `kind` (Supplement, Part A).
pub fn ad_field(data: &[u8], kind: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i < data.len() {
        let len = usize::from(data[i]);
        if len == 0 || i + 1 + len > data.len() {
            return None;
        }
        if data[i + 1] == kind {
            return Some(&data[i + 2..i + 1 + len]);
        }
        i += 1 + len;
    }
    None
}

/// Advertising data: flags (LE General Discoverable, no BR/EDR), the
/// appearance, the 16-bit service UUIDs and the complete name.
pub fn advertising_data(name: &str, appearance: u16, services: &[u16]) -> Vec<u8> {
    let mut d = alloc::vec![2, 0x01, 0x06, 3, 0x19];
    d.extend_from_slice(&appearance.to_le_bytes());
    if !services.is_empty() {
        d.push(1 + 2 * services.len() as u8);
        d.push(0x03);
        for s in services {
            d.extend_from_slice(&s.to_le_bytes());
        }
    }
    let n = name.len().min(31 - d.len() - 2);
    d.push(1 + n as u8);
    d.push(0x09);
    d.extend_from_slice(&name.as_bytes()[..n]);
    d
}

/// The LE events Slate reads (inside [`Event::Le`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeEvent {
    ConnectionComplete { status: u8, handle: u16, role: u8, addr_type: u8, addr: BdAddr, interval: u16 },
    Adverts(Vec<Advert>),
    ConnectionUpdate { status: u8, handle: u16, interval: u16, latency: u16, timeout: u16 },
    LtkRequest { handle: u16, rand: u64, ediv: u16 },
    Other(u8),
}

/// An LE Meta event's parameters.
pub fn parse_meta(b: &[u8]) -> Option<LeEvent> {
    let (&sub, p) = b.split_first()?;
    Some(match sub {
        LE_CONNECTION_COMPLETE => LeEvent::ConnectionComplete {
            status: *p.first()?,
            handle: u16_at(p, 1)? & 0x0FFF,
            role: *p.get(3)?,
            addr_type: *p.get(4)?,
            addr: BdAddr::from_wire(p.get(5..11)?)?,
            interval: u16_at(p, 11)?,
        },
        LE_ADVERTISING_REPORT => {
            // Each report in turn (§7.7.65.2; controllers send one or a few).
            let n = usize::from(*p.first()?);
            let mut at = 1;
            let mut v = Vec::new();
            for _ in 0..n {
                let len = usize::from(*p.get(at + 8)?);
                v.push(Advert {
                    kind: *p.get(at)?,
                    addr_type: *p.get(at + 1)?,
                    addr: BdAddr::from_wire(p.get(at + 2..at + 8)?)?,
                    data: p.get(at + 9..at + 9 + len)?.to_vec(),
                    rssi: *p.get(at + 9 + len)? as i8,
                });
                at += 10 + len;
            }
            LeEvent::Adverts(v)
        }
        LE_CONNECTION_UPDATE_COMPLETE => LeEvent::ConnectionUpdate {
            status: *p.first()?,
            handle: u16_at(p, 1)? & 0x0FFF,
            interval: u16_at(p, 3)?,
            latency: u16_at(p, 5)?,
            timeout: u16_at(p, 7)?,
        },
        LE_LTK_REQUEST => LeEvent::LtkRequest {
            handle: u16_at(p, 0)? & 0x0FFF,
            rand: u64::from_le_bytes(p.get(2..10)?.try_into().ok()?),
            ediv: u16_at(p, 10)?,
        },
        s => LeEvent::Other(s),
    })
}

/// The LE events as a controller sends them (the simulator).
pub mod event {
    use super::*;

    pub fn connection_complete(status: u8, handle: u16, addr_type: u8, addr: BdAddr) -> Vec<u8> {
        let mut p = alloc::vec![LE_CONNECTION_COMPLETE, status];
        p.extend_from_slice(&handle.to_le_bytes());
        // Central; the peer; 30 ms, no latency, 2 s; clock accuracy.
        p.extend_from_slice(&[0, addr_type]);
        p.extend_from_slice(&addr.wire());
        for v in [INTERVAL_MAX, 0, SUPERVISION_TIMEOUT] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        p.push(0);
        super::super::event(EV_LE_META, &p)
    }
    pub fn advertising_report(a: &Advert) -> Vec<u8> {
        let mut p = alloc::vec![LE_ADVERTISING_REPORT, 1, a.kind, a.addr_type];
        p.extend_from_slice(&a.addr.wire());
        p.push(a.data.len() as u8);
        p.extend_from_slice(&a.data);
        p.push(a.rssi as u8);
        super::super::event(EV_LE_META, &p)
    }
    pub fn connection_update(handle: u16, interval: u16, latency: u16, timeout: u16) -> Vec<u8> {
        let mut p = alloc::vec![LE_CONNECTION_UPDATE_COMPLETE, 0];
        for v in [handle, interval, latency, timeout] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        super::super::event(EV_LE_META, &p)
    }
    pub fn encryption_change(status: u8, handle: u16, on: bool) -> Vec<u8> {
        let mut p = alloc::vec![status];
        p.extend_from_slice(&handle.to_le_bytes());
        p.push(u8::from(on));
        super::super::event(EV_ENCRYPTION_CHANGE, &p)
    }
    pub fn completed_packets(handle: u16, n: u16) -> Vec<u8> {
        let mut p = alloc::vec![1];
        p.extend_from_slice(&handle.to_le_bytes());
        p.extend_from_slice(&n.to_le_bytes());
        super::super::event(EV_NUMBER_OF_COMPLETED_PACKETS, &p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adverts_and_events() {
        let a = BdAddr([0xDA, 0xDB, 0, 0x8C, 0xD8, 0xE5]);
        let data = advertising_data("Logi M650 L B", APPEARANCE_MOUSE, &[0x1812]);
        assert!(data.len() <= 31);
        let adv = Advert { kind: ADV_IND, addr_type: ADDR_RANDOM, addr: a, data, rssi: -60 };
        let Some(Event::Le(LeEvent::Adverts(v))) = parse_event(&event::advertising_report(&adv)) else { panic!() };
        assert_eq!(v, core::slice::from_ref(&adv));
        assert_eq!((v[0].name().as_deref(), v[0].appearance()), (Some("Logi M650 L B"), Some(APPEARANCE_MOUSE)));
        assert!(v[0].connectable());
        let cc = parse_event(&event::connection_complete(0, 0x40, ADDR_RANDOM, a));
        assert_eq!(
            cc,
            Some(Event::Le(LeEvent::ConnectionComplete {
                status: 0,
                handle: 0x40,
                role: 0,
                addr_type: 1,
                addr: a,
                interval: INTERVAL_MAX
            }))
        );
        assert_eq!(
            parse_event(&event::encryption_change(0, 0x40, true)),
            Some(Event::EncryptionChange { status: 0, handle: 0x40, on: true })
        );
        assert_eq!(parse_event(&event::completed_packets(0x40, 2)), Some(Event::Completed(alloc::vec![(0x40, 2)])));
        let c = cmd::create_connection(ADDR_RANDOM, a);
        let (op, p) = parse_command(&c).unwrap();
        assert_eq!((op, p.len(), p[5], &p[6..12]), (OP_LE_CREATE_CONNECTION, 25, 1, &a.wire()[..]));
        let c = cmd::start_encryption(0x40, 7, 9, &[3; 16]);
        let (op, p) = parse_command(&c).unwrap();
        assert_eq!((op, p.len(), p[10]), (OP_LE_START_ENCRYPTION, 28, 9));
    }
}
