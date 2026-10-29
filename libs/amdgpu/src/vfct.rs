// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ACPI VFCT table (atombios.h, `UEFI_ACPI_VFCT` and
//! `VFCT_IMAGE_HEADER`): after the 36-byte ACPI header, a UUID, then at
//! 34h the offset of the first VBIOS image. Each image is a header (the
//! PCI bus, device and function, vendor and device IDs, subsystem IDs,
//! a revision, the image's length; 28 bytes) and the image itself, one
//! after another.

use crate::{u16_at, u32_at};

/// An image's header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Image<'a> {
    pub bus: u32,
    pub device: u32,
    pub function: u32,
    pub vendor: u16,
    pub device_id: u16,
    pub image: &'a [u8],
}

const VBIOS_OFFSET: usize = 0x34;
const HEADER: usize = 28;

/// The VBIOS images in a VFCT table.
pub fn images(t: &[u8]) -> impl Iterator<Item = Image<'_>> {
    let ok = t.len() >= 36 && &t[..4] == b"VFCT";
    let mut at = if ok { u32_at(t, VBIOS_OFFSET).map(|o| o as usize) } else { None };
    core::iter::from_fn(move || {
        let a = at?;
        let len = u32_at(t, a + 24)? as usize;
        let image = t.get(a + HEADER..(a + HEADER).checked_add(len)?)?;
        let i = Image {
            bus: u32_at(t, a)?,
            device: u32_at(t, a + 4)?,
            function: u32_at(t, a + 8)?,
            vendor: u16_at(t, a + 12)?,
            device_id: u16_at(t, a + 14)?,
            image,
        };
        at = Some(a + HEADER + len);
        Some(i)
    })
}

/// The VBIOS for the PCI function at `bus:device.function` with these IDs.
pub fn vbios(t: &[u8], bus: u32, device: u32, function: u32, vendor: u16, device_id: u16) -> Option<&[u8]> {
    images(t)
        .find(|i| (i.bus, i.device, i.function, i.vendor, i.device_id) == (bus, device, function, vendor, device_id))
        .map(|i| i.image)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// An image to put in a table: its PCI address, its IDs, its bytes.
    type Entry<'a> = ((u32, u32, u32), (u16, u16), &'a [u8]);

    fn table(images: &[Entry<'_>]) -> Vec<u8> {
        let mut t = std::vec![0u8; 0x4C];
        t[..4].copy_from_slice(b"VFCT");
        t[VBIOS_OFFSET..VBIOS_OFFSET + 4].copy_from_slice(&0x4Cu32.to_le_bytes());
        for &((bus, dev, func), (vendor, device), image) in images {
            for v in [bus, dev, func] {
                t.extend_from_slice(&v.to_le_bytes());
            }
            t.extend_from_slice(&vendor.to_le_bytes());
            t.extend_from_slice(&device.to_le_bytes());
            t.extend_from_slice(&[0; 8]);
            t.extend_from_slice(&(image.len() as u32).to_le_bytes());
            t.extend_from_slice(image);
        }
        t
    }

    #[test]
    fn the_image_for_a_device() {
        let t = table(&[((1, 0, 0), (0x10DE, 0x2216), b"nvidia"), ((0x15, 0, 0), (0x1002, 0x164E), b"raphael")]);
        assert_eq!(images(&t).count(), 2);
        assert_eq!(vbios(&t, 0x15, 0, 0, 0x1002, 0x164E), Some(&b"raphael"[..]));
        assert_eq!(vbios(&t, 0x15, 0, 1, 0x1002, 0x164E), None);
        assert_eq!(images(b"ABCD").count(), 0);
    }

    #[test]
    fn refpc_vfct() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/gpu/refpc/VFCT.bin");
        let Ok(t) = std::fs::read(path) else { return };
        let v = vbios(&t, 0x15, 0, 0, 0x1002, 0x164E).expect("Raphael's VBIOS");
        assert_eq!(&v[..2], &[0x55, 0xAA]);
        assert!(crate::atom::Rom::new(v).is_some());
    }
}
