// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Attribute Protocol and what GATT builds on it (Core 5.4, Vol 3,
//! Part F and Part G), as far as an HID host needs (ADR 0176): Slate's
//! requests and the responses it reads, and a small attribute server for
//! the simulated devices. Every value is little-endian (Part F, §3.2.9).

use alloc::vec::Vec;

/// ATT's fixed channel on LE links (Vol 3, Part A, §2.1).
pub const CID: u16 = 0x0004;
/// The MTU every LE link starts with, and the one Slate offers (Part F,
/// §3.2.8).
pub const DEFAULT_MTU: u16 = 23;
pub const OUR_MTU: u16 = 185;

// Opcodes (Part F, §3.4.8).
pub const ERROR_RSP: u8 = 0x01;
pub const EXCHANGE_MTU_REQ: u8 = 0x02;
pub const EXCHANGE_MTU_RSP: u8 = 0x03;
pub const FIND_INFORMATION_REQ: u8 = 0x04;
pub const FIND_INFORMATION_RSP: u8 = 0x05;
pub const READ_BY_TYPE_REQ: u8 = 0x08;
pub const READ_BY_TYPE_RSP: u8 = 0x09;
pub const READ_REQ: u8 = 0x0A;
pub const READ_RSP: u8 = 0x0B;
pub const READ_BLOB_REQ: u8 = 0x0C;
pub const READ_BLOB_RSP: u8 = 0x0D;
pub const READ_BY_GROUP_TYPE_REQ: u8 = 0x10;
pub const READ_BY_GROUP_TYPE_RSP: u8 = 0x11;
pub const WRITE_REQ: u8 = 0x12;
pub const WRITE_RSP: u8 = 0x13;
pub const WRITE_CMD: u8 = 0x52;
pub const HANDLE_VALUE_NTF: u8 = 0x1B;
pub const HANDLE_VALUE_IND: u8 = 0x1D;
pub const HANDLE_VALUE_CFM: u8 = 0x1E;

// Error codes (Part F, §3.4.1.1).
pub const ERR_INVALID_HANDLE: u8 = 0x01;
pub const ERR_READ_NOT_PERMITTED: u8 = 0x02;
pub const ERR_WRITE_NOT_PERMITTED: u8 = 0x03;
pub const ERR_INSUFFICIENT_AUTHENTICATION: u8 = 0x05;
pub const ERR_REQUEST_NOT_SUPPORTED: u8 = 0x06;
pub const ERR_INVALID_OFFSET: u8 = 0x07;
pub const ERR_ATTRIBUTE_NOT_FOUND: u8 = 0x0A;
pub const ERR_INSUFFICIENT_ENCRYPTION: u8 = 0x0F;

// GATT's attribute types (Assigned Numbers §3.5, §3.7, §3.8).
pub const PRIMARY_SERVICE: u16 = 0x2800;
pub const CHARACTERISTIC: u16 = 0x2803;
pub const CCCD: u16 = 0x2902;
pub const REPORT_REFERENCE: u16 = 0x2908;
pub const SERVICE_GAP: u16 = 0x1800;
pub const SERVICE_DEVICE_INFORMATION: u16 = 0x180A;
pub const SERVICE_BATTERY: u16 = 0x180F;
pub const SERVICE_HID: u16 = 0x1812;
pub const DEVICE_NAME: u16 = 0x2A00;
pub const BATTERY_LEVEL: u16 = 0x2A19;
pub const PNP_ID: u16 = 0x2A50;
pub const HID_INFORMATION: u16 = 0x2A4A;
pub const REPORT_MAP: u16 = 0x2A4B;
pub const HID_CONTROL_POINT: u16 = 0x2A4C;
pub const REPORT: u16 = 0x2A4D;
pub const PROTOCOL_MODE: u16 = 0x2A4E;

/// Characteristic properties (Part G, §3.3.1.1).
pub const PROP_READ: u8 = 0x02;
pub const PROP_WRITE_NO_RSP: u8 = 0x04;
pub const PROP_WRITE: u8 = 0x08;
pub const PROP_NOTIFY: u8 = 0x10;
pub const PROP_INDICATE: u8 = 0x20;

/// The Bluetooth Base UUID's last 12 octets, as sent (Vol 3, Part B,
/// §2.5.1): a 16-bit UUID is these with the value at octets 12 and 13.
const BASE: [u8; 12] = [0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00];

/// An attribute type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Uuid {
    U16(u16),
    /// As sent (least significant octet first).
    U128([u8; 16]),
}

impl Uuid {
    /// From 2 or 16 octets; a 128-bit one on the base is its 16-bit self.
    pub fn from_wire(b: &[u8]) -> Option<Uuid> {
        match b.len() {
            2 => Some(Uuid::U16(u16::from_le_bytes([b[0], b[1]]))),
            16 if b[..12] == BASE && b[14..] == [0, 0] => Some(Uuid::U16(u16::from_le_bytes([b[12], b[13]]))),
            16 => Some(Uuid::U128(b.try_into().ok()?)),
            _ => None,
        }
    }
    pub fn wire(&self) -> Vec<u8> {
        match self {
            Uuid::U16(v) => v.to_le_bytes().to_vec(),
            Uuid::U128(b) => b.to_vec(),
        }
    }
    pub fn is(&self, v: u16) -> bool {
        *self == Uuid::U16(v)
    }
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

// --- Requests (the client's) ---------------------------------------------

pub fn exchange_mtu(mtu: u16) -> Vec<u8> {
    let mut p = alloc::vec![EXCHANGE_MTU_REQ];
    p.extend_from_slice(&mtu.to_le_bytes());
    p
}

fn range(op: u8, start: u16, end: u16, uuid: Option<u16>) -> Vec<u8> {
    let mut p = alloc::vec![op];
    p.extend_from_slice(&start.to_le_bytes());
    p.extend_from_slice(&end.to_le_bytes());
    if let Some(u) = uuid {
        p.extend_from_slice(&u.to_le_bytes());
    }
    p
}

pub fn read_by_group_type(start: u16, end: u16, kind: u16) -> Vec<u8> {
    range(READ_BY_GROUP_TYPE_REQ, start, end, Some(kind))
}
pub fn read_by_type(start: u16, end: u16, kind: u16) -> Vec<u8> {
    range(READ_BY_TYPE_REQ, start, end, Some(kind))
}
pub fn find_information(start: u16, end: u16) -> Vec<u8> {
    range(FIND_INFORMATION_REQ, start, end, None)
}
pub fn read(handle: u16) -> Vec<u8> {
    let mut p = alloc::vec![READ_REQ];
    p.extend_from_slice(&handle.to_le_bytes());
    p
}
pub fn read_blob(handle: u16, offset: u16) -> Vec<u8> {
    let mut p = alloc::vec![READ_BLOB_REQ];
    p.extend_from_slice(&handle.to_le_bytes());
    p.extend_from_slice(&offset.to_le_bytes());
    p
}
pub fn write(handle: u16, value: &[u8]) -> Vec<u8> {
    let mut p = alloc::vec![WRITE_REQ];
    p.extend_from_slice(&handle.to_le_bytes());
    p.extend_from_slice(value);
    p
}
pub fn notification(handle: u16, value: &[u8]) -> Vec<u8> {
    let mut p = alloc::vec![HANDLE_VALUE_NTF];
    p.extend_from_slice(&handle.to_le_bytes());
    p.extend_from_slice(value);
    p
}
pub fn error(req: u8, handle: u16, code: u8) -> Vec<u8> {
    let mut p = alloc::vec![ERROR_RSP, req];
    p.extend_from_slice(&handle.to_le_bytes());
    p.push(code);
    p
}

// --- Responses (read by the client) ----------------------------------------------

/// An Error Response's request opcode, handle and code.
pub fn parse_error(p: &[u8]) -> Option<(u8, u16, u8)> {
    (p.first() == Some(&ERROR_RSP)).then_some(())?;
    Some((*p.get(1)?, u16_at(p, 2)?, *p.get(4)?))
}

/// A Read By Group Type Response: (start, end, service UUID) each.
pub fn parse_groups(p: &[u8]) -> Option<Vec<(u16, u16, Uuid)>> {
    let len = usize::from(*p.get(1)?);
    if p.first() != Some(&READ_BY_GROUP_TYPE_RSP) || len < 6 {
        return None;
    }
    p[2..].chunks(len).map(|c| Some((u16_at(c, 0)?, u16_at(c, 2)?, Uuid::from_wire(c.get(4..len)?)?))).collect()
}

/// A Read By Type Response: (handle, value) each.
pub fn parse_by_type(p: &[u8]) -> Option<Vec<(u16, Vec<u8>)>> {
    let len = usize::from(*p.get(1)?);
    if p.first() != Some(&READ_BY_TYPE_RSP) || len < 2 {
        return None;
    }
    p[2..].chunks(len).map(|c| Some((u16_at(c, 0)?, c.get(2..len)?.to_vec()))).collect()
}

/// A Find Information Response: (handle, type) each.
pub fn parse_information(p: &[u8]) -> Option<Vec<(u16, Uuid)>> {
    let size = match p.get(1)? {
        1 => 2,
        2 => 16,
        _ => return None,
    };
    if p.first() != Some(&FIND_INFORMATION_RSP) {
        return None;
    }
    p[2..].chunks(2 + size).map(|c| Some((u16_at(c, 0)?, Uuid::from_wire(c.get(2..2 + size)?)?))).collect()
}

/// A characteristic declaration's value: properties, value handle, type.
pub fn parse_characteristic(v: &[u8]) -> Option<(u8, u16, Uuid)> {
    Some((*v.first()?, u16_at(v, 1)?, Uuid::from_wire(v.get(3..)?)?))
}

// --- A server (the simulated devices') -------------------------------------------------

/// An attribute: its handle, type, value and what may be done with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribute {
    pub handle: u16,
    pub kind: Uuid,
    pub value: Vec<u8>,
    pub writable: bool,
    /// Reading or writing it needs an encrypted link.
    pub encrypted: bool,
}

/// An attribute database, built service by service.
#[derive(Clone, Debug, Default)]
pub struct Server {
    pub attrs: Vec<Attribute>,
    /// The MTU agreed, and the largest it takes.
    pub mtu: u16,
    pub max_mtu: u16,
}

impl Server {
    pub fn new() -> Server {
        Server { attrs: Vec::new(), mtu: DEFAULT_MTU, max_mtu: OUR_MTU }
    }

    fn add(&mut self, kind: Uuid, value: Vec<u8>, writable: bool, encrypted: bool) -> u16 {
        let handle = self.attrs.len() as u16 + 1;
        self.attrs.push(Attribute { handle, kind, value, writable, encrypted });
        handle
    }

    pub fn service(&mut self, uuid: u16) -> u16 {
        self.add(Uuid::U16(PRIMARY_SERVICE), uuid.to_le_bytes().to_vec(), false, false)
    }

    /// A characteristic: its declaration, its value (the handle returned),
    /// and a CCCD when it notifies.
    pub fn characteristic(&mut self, uuid: u16, props: u8, value: &[u8], encrypted: bool) -> u16 {
        let decl = self.attrs.len() as u16 + 1;
        let mut d = alloc::vec![props];
        d.extend_from_slice(&(decl + 1).to_le_bytes());
        d.extend_from_slice(&uuid.to_le_bytes());
        self.add(Uuid::U16(CHARACTERISTIC), d, false, false);
        let h = self.add(Uuid::U16(uuid), value.to_vec(), props & (PROP_WRITE | PROP_WRITE_NO_RSP) != 0, encrypted);
        if props & (PROP_NOTIFY | PROP_INDICATE) != 0 {
            self.add(Uuid::U16(CCCD), alloc::vec![0, 0], true, encrypted);
        }
        h
    }

    pub fn descriptor(&mut self, uuid: u16, value: &[u8], encrypted: bool) -> u16 {
        self.add(Uuid::U16(uuid), value.to_vec(), false, encrypted)
    }

    pub fn get(&self, handle: u16) -> Option<&Attribute> {
        self.attrs.get(usize::from(handle).checked_sub(1)?)
    }

    /// The end of the service starting at `start`.
    fn group_end(&self, start: u16) -> u16 {
        self.attrs
            .iter()
            .find(|a| a.handle > start && a.kind.is(PRIMARY_SERVICE))
            .map_or(self.attrs.len() as u16, |a| a.handle - 1)
    }

    /// Answer request `req` on a link encrypted or not: the response, and
    /// the attribute written if one was.
    pub fn serve(&mut self, req: &[u8], encrypted: bool) -> (Option<Vec<u8>>, Option<u16>) {
        let Some(&op) = req.first() else { return (None, None) };
        let max = usize::from(self.mtu);
        let in_range = |s: u16, e: u16| s != 0 && s <= e;
        let rsp = match op {
            EXCHANGE_MTU_REQ => {
                let client = u16_at(req, 1).unwrap_or(DEFAULT_MTU);
                self.mtu = client.clamp(DEFAULT_MTU, self.max_mtu.max(DEFAULT_MTU));
                let mut p = alloc::vec![EXCHANGE_MTU_RSP];
                p.extend_from_slice(&self.max_mtu.to_le_bytes());
                p
            }
            READ_BY_GROUP_TYPE_REQ | READ_BY_TYPE_REQ | FIND_INFORMATION_REQ => {
                let (Some(s), Some(e)) = (u16_at(req, 1), u16_at(req, 3)) else {
                    return (Some(error(op, 0, ERR_INVALID_HANDLE)), None);
                };
                if !in_range(s, e) {
                    return (Some(error(op, s, ERR_INVALID_HANDLE)), None);
                }
                let kind = req.get(5..).and_then(Uuid::from_wire);
                let found = self.attrs.iter().filter(|a| a.handle >= s && a.handle <= e);
                let mut out: Vec<u8> = Vec::new();
                let mut each = 0usize;
                for a in found {
                    let entry = match op {
                        READ_BY_GROUP_TYPE_REQ if Some(a.kind) == kind => {
                            let mut v = a.handle.to_le_bytes().to_vec();
                            v.extend_from_slice(&self.group_end(a.handle).to_le_bytes());
                            v.extend_from_slice(&a.value);
                            v
                        }
                        READ_BY_TYPE_REQ if Some(a.kind) == kind => {
                            if a.encrypted && !encrypted {
                                return (Some(error(op, a.handle, ERR_INSUFFICIENT_ENCRYPTION)), None);
                            }
                            let mut v = a.handle.to_le_bytes().to_vec();
                            v.extend_from_slice(&a.value[..a.value.len().min(max - 4)]);
                            v
                        }
                        FIND_INFORMATION_REQ => {
                            let mut v = a.handle.to_le_bytes().to_vec();
                            v.extend_from_slice(&a.kind.wire());
                            v
                        }
                        _ => continue,
                    };
                    // One size per response, as many as fit.
                    if each == 0 {
                        each = entry.len();
                    } else if entry.len() != each {
                        break;
                    }
                    if 2 + out.len() + each > max {
                        break;
                    }
                    out.extend_from_slice(&entry);
                }
                if out.is_empty() {
                    return (Some(error(op, s, ERR_ATTRIBUTE_NOT_FOUND)), None);
                }
                let header = match op {
                    READ_BY_GROUP_TYPE_REQ => [READ_BY_GROUP_TYPE_RSP, each as u8],
                    READ_BY_TYPE_REQ => [READ_BY_TYPE_RSP, each as u8],
                    _ => [FIND_INFORMATION_RSP, if each == 4 { 1 } else { 2 }],
                };
                [&header[..], &out].concat()
            }
            READ_REQ | READ_BLOB_REQ => {
                let h = u16_at(req, 1).unwrap_or(0);
                let offset = if op == READ_BLOB_REQ { usize::from(u16_at(req, 3).unwrap_or(0)) } else { 0 };
                let Some(a) = self.get(h) else { return (Some(error(op, h, ERR_INVALID_HANDLE)), None) };
                if a.encrypted && !encrypted {
                    return (Some(error(op, h, ERR_INSUFFICIENT_ENCRYPTION)), None);
                }
                if offset > a.value.len() {
                    return (Some(error(op, h, ERR_INVALID_OFFSET)), None);
                }
                let part = &a.value[offset..];
                let mut p = alloc::vec![if op == READ_REQ { READ_RSP } else { READ_BLOB_RSP }];
                p.extend_from_slice(&part[..part.len().min(max - 1)]);
                p
            }
            WRITE_REQ | WRITE_CMD => {
                let h = u16_at(req, 1).unwrap_or(0);
                let value = req.get(3..).unwrap_or_default().to_vec();
                let reply = |code: u8| if op == WRITE_REQ { Some(error(op, h, code)) } else { None };
                let Some(a) = self.attrs.get_mut(usize::from(h).wrapping_sub(1)) else {
                    return (reply(ERR_INVALID_HANDLE), None);
                };
                if !a.writable {
                    return (reply(ERR_WRITE_NOT_PERMITTED), None);
                }
                if a.encrypted && !encrypted {
                    return (reply(ERR_INSUFFICIENT_ENCRYPTION), None);
                }
                a.value = value;
                return ((op == WRITE_REQ).then(|| alloc::vec![WRITE_RSP]), Some(h));
            }
            HANDLE_VALUE_CFM => return (None, None),
            // Commands get nothing back; requests are refused.
            op if op & 0x40 != 0 => return (None, None),
            op => error(op, 0, ERR_REQUEST_NOT_SUPPORTED),
        };
        (Some(rsp), None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_and_a_server() {
        let mut s = Server::new();
        s.service(SERVICE_GAP);
        let name = s.characteristic(DEVICE_NAME, PROP_READ, b"Mouse", false);
        s.service(SERVICE_HID);
        let map = s.characteristic(REPORT_MAP, PROP_READ, &[0x55; 40], true);
        let report = s.characteristic(REPORT, PROP_READ | PROP_NOTIFY, &[0, 0, 0], true);
        s.descriptor(REPORT_REFERENCE, &[1, 1], true);
        // The services, grouped.
        let (r, _) = s.serve(&read_by_group_type(1, 0xFFFF, PRIMARY_SERVICE), false);
        let groups = parse_groups(&r.unwrap()).unwrap();
        assert_eq!(groups, [(1, 3, Uuid::U16(SERVICE_GAP)), (4, 10, Uuid::U16(SERVICE_HID))]);
        // Its characteristics.
        let (r, _) = s.serve(&read_by_type(4, 10, CHARACTERISTIC), false);
        let chars = parse_by_type(&r.unwrap()).unwrap();
        let decls: Vec<_> = chars.iter().map(|(_, v)| parse_characteristic(v).unwrap()).collect();
        assert_eq!(decls[0], (PROP_READ, map, Uuid::U16(REPORT_MAP)));
        assert_eq!(decls[1], (PROP_READ | PROP_NOTIFY, report, Uuid::U16(REPORT)));
        // The report's descriptors: its CCCD and reference.
        let (r, _) = s.serve(&find_information(report + 1, 10), false);
        let info = parse_information(&r.unwrap()).unwrap();
        assert_eq!(info, [(report + 1, Uuid::U16(CCCD)), (report + 2, Uuid::U16(REPORT_REFERENCE))]);
        // Reading: the name freely, the map only encrypted, in pieces.
        assert_eq!(s.serve(&read(name), false).0.unwrap(), b"\x0bMouse");
        assert_eq!(
            parse_error(&s.serve(&read(map), false).0.unwrap()),
            Some((READ_REQ, map, ERR_INSUFFICIENT_ENCRYPTION))
        );
        assert_eq!(s.serve(&read(map), true).0.unwrap().len(), 23);
        assert_eq!(s.serve(&read_blob(map, 22), true).0.unwrap().len(), 19);
        // Notifications on.
        let (r, w) = s.serve(&write(report + 1, &[1, 0]), true);
        assert_eq!((r.unwrap(), w), (alloc::vec![WRITE_RSP], Some(report + 1)));
        // Past the end: not found.
        let (r, _) = s.serve(&read_by_group_type(11, 0xFFFF, PRIMARY_SERVICE), false);
        assert_eq!(parse_error(&r.unwrap()), Some((READ_BY_GROUP_TYPE_REQ, 11, ERR_ATTRIBUTE_NOT_FOUND)));
        // A 128-bit UUID on the base is its 16-bit self.
        let mut long = BASE.to_vec();
        long.extend_from_slice(&[0x12, 0x18, 0, 0]);
        assert_eq!(Uuid::from_wire(&long), Some(Uuid::U16(SERVICE_HID)));
    }
}
