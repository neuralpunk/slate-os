// SPDX-License-Identifier: MIT OR Apache-2.0

//! The AtomBIOS image (atomfirmware.h): a PCI option ROM (55h AAh) whose
//! word at 48h points to the ROM header (`atom_rom_header_v2_2`, "ATOM" at
//! its offset 4), which gives the master command table list (at 1Eh) and
//! the master data table list (at 20h). Each table starts with
//! `atom_common_table_header`: its size, format and content revisions.
//!
//! The display object table (`display_object_info_table_v1_4` and
//! `_v1_5`, the master data list's 23rd entry, `displayobjectinfo`) lists
//! the display paths: a connector, the encoder nearest it, a device tag,
//! and records (`atom_common_record_header` and the records after it)
//! starting at an offset from the table's own start: the DDC line
//! (`atom_i2c_record`), the HPD pin (`atom_hpd_int_record`), ending with
//! FFh. Object IDs (ObjectID.h): bits 14:12 the type (2 encoder, 3
//! connector), 10:8 the enum (the instance, from 1), 7:0 the ID.

use crate::{u16_at, u32_at};

/// The master data list's entries used here (atomfirmware.h,
/// `atom_master_list_of_data_tables_v2_1`, in order from 0).
pub const DATA_FIRMWARE_INFO: usize = 4;
pub const DATA_GPIO_PIN_LUT: usize = 12;
pub const DATA_DISPLAY_OBJECT_INFO: usize = 22;
pub const DATA_DCE_INFO: usize = 27;
pub const DATA_INTEGRATED_SYSTEM_INFO: usize = 30;

/// Object types (ObjectID.h, GRAPH_OBJECT_TYPE_*).
pub const TYPE_ENCODER: u8 = 2;
pub const TYPE_CONNECTOR: u8 = 3;

/// Record types (atomfirmware.h, `atom_object_record_type_id`).
const RECORD_I2C: u8 = 1;
const RECORD_HPD: u8 = 2;
const RECORD_END: u8 = 0xFF;

/// An AtomBIOS image.
#[derive(Clone, Copy, Debug)]
pub struct Rom<'a> {
    pub image: &'a [u8],
    header: usize,
}

/// An object ID's parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Object {
    pub kind: u8,
    /// The instance, from 1.
    pub instance: u8,
    pub id: u8,
}

impl Object {
    pub fn from(v: u16) -> Object {
        Object { kind: ((v >> 12) & 7) as u8, instance: ((v >> 8) & 7) as u8, id: v as u8 }
    }
}

/// A connector's kind (ObjectID.h, CONNECTOR_OBJECT_ID_*).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Connector {
    DviD,
    Hdmi,
    DisplayPort,
    Edp,
    UsbC,
    Other(u8),
}

impl Connector {
    fn from(id: u8) -> Connector {
        match id {
            0x03 | 0x04 => Connector::DviD,
            0x0C => Connector::Hdmi,
            0x13 => Connector::DisplayPort,
            0x14 => Connector::Edp,
            0x17 => Connector::UsbC,
            o => Connector::Other(o),
        }
    }
}

/// An encoder's PHY, as a letter's number (A = 0): ObjectID.h's internal
/// UNIPHY (1Eh), UNIPHY1 (20h), UNIPHY2 (21h) and UNIPHY3 (25h), two
/// links each (the enum: 1 is the first).
pub fn transmitter(encoder: Object) -> Option<u8> {
    let pair = match encoder.id {
        0x1E => 0,
        0x20 => 1,
        0x21 => 2,
        0x25 => 3,
        _ => return None,
    };
    (1..=2).contains(&encoder.instance).then(|| pair * 2 + encoder.instance - 1)
}

/// A display path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Path {
    pub connector: Object,
    pub kind: Connector,
    pub encoder: Object,
    pub device_tag: u16,
    /// The HPD pin (`atom_hpd_int_record`'s pin_id).
    pub hpd: Option<u8>,
    /// The DDC line (`atom_i2c_record`'s i2c_id: bit 7 a hardware engine,
    /// bits 6:4 the engine, 3:0 the line; atomfirmware.h I2C_HW_*).
    pub ddc: Option<u8>,
}

impl<'a> Rom<'a> {
    /// The image, if it is an AtomBIOS one.
    pub fn new(image: &'a [u8]) -> Option<Rom<'a>> {
        if image.get(..2)? != [0x55, 0xAA] {
            return None;
        }
        let header = usize::from(u16_at(image, 0x48)?);
        (image.get(header + 4..header + 8)? == b"ATOM").then_some(Rom { image, header })
    }

    fn table_list(&self, at: usize) -> Option<(usize, usize)> {
        let list = usize::from(u16_at(self.image, self.header + at)?);
        let size = usize::from(u16_at(self.image, list)?);
        Some((list, size))
    }

    /// A master data table's offset in the image (0: none).
    pub fn data_table(&self, index: usize) -> Option<usize> {
        let (list, size) = self.table_list(0x20)?;
        let at = list + 4 + 2 * index;
        (at + 2 <= list + size).then(|| u16_at(self.image, at)).flatten().map(usize::from).filter(|&o| o != 0)
    }

    /// A master command table's offset in the image (0: none).
    pub fn command_table(&self, index: usize) -> Option<usize> {
        let (list, size) = self.table_list(0x1E)?;
        let at = list + 4 + 2 * index;
        (at + 2 <= list + size).then(|| u16_at(self.image, at)).flatten().map(usize::from).filter(|&o| o != 0)
    }

    /// A table's format and content revisions.
    pub fn revision(&self, at: usize) -> Option<(u8, u8)> {
        Some((*self.image.get(at + 2)?, *self.image.get(at + 3)?))
    }

    /// The display paths with a connector (display_object_info_table v1.4
    /// and v1.5: a 16-byte path each, after an 8-byte head).
    pub fn display_paths(&self) -> impl Iterator<Item = Path> + '_ {
        let table = self.data_table(DATA_DISPLAY_OBJECT_INFO).filter(|&t| {
            let r = self.revision(t);
            r == Some((1, 4)) || r == Some((1, 5))
        });
        let n = table.and_then(|t| self.image.get(t + 6).copied()).unwrap_or(0);
        (0..usize::from(n)).filter_map(move |i| {
            let t = table?;
            let p = t + 8 + 16 * i;
            let connector = Object::from(u16_at(self.image, p)?);
            if connector.kind != TYPE_CONNECTOR {
                return None;
            }
            let mut path = Path {
                connector,
                kind: Connector::from(connector.id),
                encoder: Object::from(u16_at(self.image, p + 4)?),
                device_tag: u16_at(self.image, p + 12)?,
                hpd: None,
                ddc: None,
            };
            let mut r = t + usize::from(u16_at(self.image, p + 2)?);
            // At most a few dozen records; a broken table ends early.
            for _ in 0..32 {
                let (kind, size) = (*self.image.get(r)?, usize::from(*self.image.get(r + 1)?));
                if kind == RECORD_END || size < 2 {
                    break;
                }
                match kind {
                    RECORD_I2C => path.ddc = self.image.get(r + 2).copied(),
                    RECORD_HPD => path.hpd = self.image.get(r + 2).copied(),
                    _ => {}
                }
                r += size;
            }
            Some(path)
        })
    }

    /// The image's name strings (the part number and the build), for the
    /// log: the first printable runs of the ROM's first kilobyte.
    pub fn build(&self) -> Option<&'a str> {
        // The ROM header's bootup message offset (10h) points at the
        // VBIOS's own message.
        let at = usize::from(u16_at(self.image, self.header + 0x10)?);
        let rest = self.image.get(at..)?;
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len()).min(120);
        core::str::from_utf8(&rest[..end]).ok().map(str::trim)
    }

    /// The firmware info table's revision and the bootup display engine
    /// clock, if a v4.x dce_info table is there (in 10 kHz).
    pub fn bootup_dispclk_10khz(&self) -> Option<u32> {
        let t = self.data_table(DATA_DCE_INFO)?;
        match self.revision(t)? {
            (4, _) => u32_at(self.image, t + 8),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// A small AtomBIOS image: the ROM signature, the ROM header at 80h,
    /// a data table list with the display object table, two paths (HDMI on
    /// UNIPHY A, DisplayPort on UNIPHY1 B) and their records.
    fn image() -> Vec<u8> {
        let mut d = std::vec![0u8; 0x400];
        d[0..2].copy_from_slice(&[0x55, 0xAA]);
        d[0x48..0x4A].copy_from_slice(&0x80u16.to_le_bytes());
        d[0x84..0x88].copy_from_slice(b"ATOM");
        d[0x80 + 0x10..0x80 + 0x12].copy_from_slice(&0x300u16.to_le_bytes());
        d[0x300..0x310].copy_from_slice(b"Test VBIOS 1.0\0\0");
        d[0x80 + 0x20..0x80 + 0x22].copy_from_slice(&0x100u16.to_le_bytes());
        // The data list: 31 entries; the display objects at 200h.
        let size = 4 + 2 * 31u16;
        d[0x100..0x102].copy_from_slice(&size.to_le_bytes());
        d[0x102] = 2;
        d[0x103] = 1;
        let e = 0x104 + 2 * DATA_DISPLAY_OBJECT_INFO;
        d[e..e + 2].copy_from_slice(&0x200u16.to_le_bytes());
        // The display object table v1.4: three paths (the middle one
        // empty), records from 40h on.
        d[0x202] = 1;
        d[0x203] = 4;
        d[0x206] = 3;
        let path = |d: &mut Vec<u8>, i: usize, conn: u16, rec: u16, enc: u16, tag: u16| {
            let p = 0x208 + 16 * i;
            d[p..p + 2].copy_from_slice(&conn.to_le_bytes());
            d[p + 2..p + 4].copy_from_slice(&rec.to_le_bytes());
            d[p + 4..p + 6].copy_from_slice(&enc.to_le_bytes());
            d[p + 12..p + 14].copy_from_slice(&tag.to_le_bytes());
        };
        path(&mut d, 0, 0x310C, 0x40, 0x211E, 0x400);
        path(&mut d, 1, 0, 0x50, 0x221E, 0);
        path(&mut d, 2, 0x3113, 0x50, 0x2220, 0x8);
        d[0x240..0x249].copy_from_slice(&[1, 4, 0x90, 0, 2, 4, 1, 0, 0xFF]);
        d[0x250..0x259].copy_from_slice(&[1, 4, 0x92, 0, 2, 4, 3, 0, 0xFF]);
        d
    }

    #[test]
    fn paths_and_records() {
        let d = image();
        let rom = Rom::new(&d).unwrap();
        assert_eq!(rom.build(), Some("Test VBIOS 1.0"));
        assert_eq!(rom.data_table(DATA_DISPLAY_OBJECT_INFO), Some(0x200));
        assert_eq!(rom.data_table(DATA_DCE_INFO), None);
        let paths: Vec<Path> = rom.display_paths().collect();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].kind, Connector::Hdmi);
        assert_eq!((paths[0].hpd, paths[0].ddc, transmitter(paths[0].encoder)), (Some(1), Some(0x90), Some(0)));
        assert_eq!(paths[1].kind, Connector::DisplayPort);
        assert_eq!((paths[1].hpd, paths[1].ddc, transmitter(paths[1].encoder)), (Some(3), Some(0x92), Some(3)));
        // Not a ROM, or not AtomBIOS.
        assert!(Rom::new(&d[1..]).is_none());
        let mut bad = d.clone();
        bad[0x84] = b'X';
        assert!(Rom::new(&bad).is_none());
        assert_eq!(Object::from(0x340C), Object { kind: 3, instance: 4, id: 0x0C });
    }

    /// The reference PC's own VBIOS, when target/gpu/refpc holds it (never
    /// committed: it is AMD's).
    #[test]
    fn refpc_vbios() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/gpu/refpc/vbios.rom");
        let Ok(d) = std::fs::read(path) else { return };
        let rom = Rom::new(&d).unwrap();
        let paths: Vec<Path> = rom.display_paths().collect();
        for p in &paths {
            std::println!("{p:?} transmitter {:?}", transmitter(p.encoder));
        }
        // An HDMI connector on UNIPHY A and three DisplayPort ones, as
        // Fedora's amdgpu lists HDMI-A-1 and DP-1 to DP-3.
        assert_eq!(paths.iter().filter(|p| p.kind == Connector::Hdmi).count(), 1);
        assert_eq!(paths.iter().filter(|p| p.kind == Connector::DisplayPort).count(), 3);
        let hdmi = paths.iter().find(|p| p.kind == Connector::Hdmi).unwrap();
        assert_eq!((transmitter(hdmi.encoder), hdmi.hpd), (Some(0), Some(1)));
        std::println!("dispclk at boot: {:?} x 10 kHz; {:?}", rom.bootup_dispclk_10khz(), rom.build());
    }
}
