// SPDX-License-Identifier: MIT OR Apache-2.0

//! /dev/slate-hid's messages (ADR 0176): HID devices whose transport is in
//! user space (Bluetooth's, through slate-btd). Slate's own interface;
//! every number is little-endian.
//!
//! Each open of /dev/slate-hid is one device. Its writes are one message
//! each:
//! - [`CREATE`] first, once: bus, vendor, product, version, flags, then
//!   the name, the physical path and the report descriptor, each as a
//!   16-bit length and the bytes. The kernel makes the evdev devices the
//!   descriptor describes (a keyboard, a pointer); with
//!   [`FLAG_POINTER_ONLY`], only the pointer (a device paired without
//!   anyone choosing it: it may not type).
//! - [`INPUT`]: one input report, its ID byte first when the descriptor
//!   names IDs.
//!
//! Its reads are [`OUTPUT`] messages: an output report the device should
//! get (a keyboard's lights), its ID, then the report as for [`INPUT`].
//! Closing it removes the evdev devices.

use alloc::vec::Vec;

pub const CREATE: u8 = 1;
pub const INPUT: u8 = 2;
pub const OUTPUT: u8 = 3;

/// [`Create::flags`]: make no keyboard, whatever the descriptor says.
pub const FLAG_POINTER_ONLY: u16 = 1;

/// The longest name and path, descriptor and report taken.
pub const MAX_NAME: usize = 128;
pub const MAX_DESCRIPTOR: usize = 4096;
pub const MAX_REPORT: usize = 512;

/// A [`CREATE`] message's contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Create<'a> {
    pub bus: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
    pub flags: u16,
    pub name: &'a str,
    pub phys: &'a str,
    pub descriptor: &'a [u8],
}

fn put(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u16).to_le_bytes());
    out.extend_from_slice(b);
}

impl<'a> Create<'a> {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = alloc::vec![CREATE];
        for v in [self.bus, self.vendor, self.product, self.version, self.flags] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        put(&mut out, self.name.as_bytes());
        put(&mut out, self.phys.as_bytes());
        put(&mut out, self.descriptor);
        out
    }

    /// A [`CREATE`] message read back; None if malformed or too long.
    pub fn decode(b: &'a [u8]) -> Option<Create<'a>> {
        let (&kind, mut rest) = b.split_first()?;
        if kind != CREATE || rest.len() < 10 {
            return None;
        }
        let word = |b: &[u8], i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
        let (bus, vendor, product, version, flags) =
            (word(rest, 0), word(rest, 2), word(rest, 4), word(rest, 6), word(rest, 8));
        rest = &rest[10..];
        let mut take = |max: usize| -> Option<&'a [u8]> {
            if rest.len() < 2 {
                return None;
            }
            let n = usize::from(word(rest, 0));
            let field = rest.get(2..2 + n).filter(|_| n <= max)?;
            rest = &rest[2 + n..];
            Some(field)
        };
        let name = core::str::from_utf8(take(MAX_NAME)?).ok()?;
        let phys = core::str::from_utf8(take(MAX_NAME)?).ok()?;
        let descriptor = take(MAX_DESCRIPTOR)?;
        rest.is_empty().then_some(Create { bus, vendor, product, version, flags, name, phys, descriptor })
    }
}

/// An [`INPUT`] message for `report`.
pub fn input(report: &[u8]) -> Vec<u8> {
    let mut out = alloc::vec![INPUT];
    out.extend_from_slice(report);
    out
}

/// An [`OUTPUT`] message: report `id`'s `report`.
pub fn output(id: u8, report: &[u8]) -> Vec<u8> {
    let mut out = alloc::vec![OUTPUT, id];
    out.extend_from_slice(report);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages() {
        let c = Create {
            bus: 5,
            vendor: 0x046D,
            product: 0xB032,
            version: 0x13,
            flags: FLAG_POINTER_ONLY,
            name: "Logi M650 L B",
            phys: "bt-11:22:33:44:55:66",
            descriptor: &[0x05, 0x01, 0x09, 0x02],
        };
        let b = c.encode();
        assert_eq!(Create::decode(&b), Some(c.clone()));
        // Cut short, or with something after: refused.
        assert_eq!(Create::decode(&b[..b.len() - 1]), None);
        let mut more = b.clone();
        more.push(0);
        assert_eq!(Create::decode(&more), None);
        assert_eq!(input(&[1, 2]), [INPUT, 1, 2]);
        assert_eq!(output(1, &[1, 2]), [OUTPUT, 1, 1, 2]);
    }
}
