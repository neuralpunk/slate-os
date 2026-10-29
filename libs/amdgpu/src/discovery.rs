// SPDX-License-Identifier: MIT OR Apache-2.0

//! The IP discovery table (discovery.h): where each hardware block of the
//! GPU is and which version it is. The driver reads it from the top of
//! the GPU's memory: 64 KiB below the size RCC_CONFIG_MEMSIZE gives (in
//! MiB), 10 KiB long (amdgpu_discovery.h, DISCOVERY_TMR_OFFSET and
//! DISCOVERY_TMR_SIZE).
//!
//! - `binary_header`: the signature 28211407h, the version, a checksum
//!   (the 16-bit byte sum of the binary after the checksum field), the
//!   size, and a list of tables (offset, checksum, size); the IP
//!   discovery table is the first.
//! - `ip_discovery_header`: "IPDS", the version, the size, the dies (up to
//!   16: an ID and the offset of its `die_header`); version 4 can use
//!   64-bit base addresses (the flag after the dies).
//! - `die_header`: the die's ID and its number of IPs, followed by `ip`
//!   (`ip_v3`, `ip_v4`) entries: the hardware ID (soc15_hw_ip.h), the
//!   instance, the number of base addresses, the major, minor and
//!   revision numbers, a harvest or sub-revision byte, then the bases
//!   (register offsets in 32-bit words, one per register segment).

use crate::{u16_at, u32_at};

/// Hardware IDs (soc15_hw_ip.h, *_HWID).
pub const MP1: u16 = 1;
pub const SMUIO: u16 = 4;
pub const GC: u16 = 11;
pub const MMHUB: u16 = 34;
pub const OSSSYS: u16 = 40;
pub const HDP: u16 = 41;
pub const NBIF: u16 = 108;
pub const DMU: u16 = 271;
pub const MP0: u16 = 255;

const BINARY_SIGNATURE: u32 = 0x2821_1407;
/// DISCOVERY_TABLE_SIGNATURE: "IPDS" read as a little-endian word.
const TABLE_SIGNATURE: u32 = 0x5344_5049;

/// Where the table is: `memsize_mib` from RCC_CONFIG_MEMSIZE.
pub fn offset(memsize_mib: u32) -> u64 {
    (u64::from(memsize_mib) << 20) - (64 << 10)
}

/// How much to read.
pub const SIZE: usize = 10 << 10;

/// An IP block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ip {
    pub hw_id: u16,
    pub instance: u8,
    pub version: (u8, u8, u8),
    /// Register segment bases (32-bit words), the first `bases` of them.
    pub base: [u64; 8],
    pub bases: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Signature,
    Checksum,
    Short,
}

/// A checked discovery binary.
#[derive(Clone, Copy, Debug)]
pub struct Table<'a> {
    b: &'a [u8],
    ip: usize,
}

fn byte_sum(b: &[u8]) -> u16 {
    b.iter().fold(0u16, |a, &v| a.wrapping_add(u16::from(v)))
}

impl<'a> Table<'a> {
    pub fn new(b: &'a [u8]) -> Result<Table<'a>, Error> {
        if u32_at(b, 0) != Some(BINARY_SIGNATURE) {
            return Err(Error::Signature);
        }
        let (sum, size) = (u16_at(b, 8).ok_or(Error::Short)?, usize::from(u16_at(b, 10).ok_or(Error::Short)?));
        let rest = b.get(10..size).ok_or(Error::Short)?;
        if byte_sum(rest) != sum {
            return Err(Error::Checksum);
        }
        // The first table (version 1's list starts at 12, version 2's at
        // 16, after its count).
        let list = if u16_at(b, 4) == Some(2) { 16 } else { 12 };
        let ip = usize::from(u16_at(b, list).ok_or(Error::Short)?);
        if u32_at(b, ip) != Some(TABLE_SIGNATURE) {
            return Err(Error::Signature);
        }
        Ok(Table { b, ip })
    }

    /// The IP discovery table's version.
    pub fn version(&self) -> u16 {
        u16_at(self.b, self.ip + 4).unwrap_or(0)
    }

    /// Every IP block of every die.
    pub fn ips(&self) -> impl Iterator<Item = Ip> + '_ {
        let b = self.b;
        let dies = usize::from(u16_at(b, self.ip + 12).unwrap_or(0)).min(16);
        // After 16 die entries: version 4's flags (bit 0: 64-bit bases).
        let wide = self.version() == 4 && b.get(self.ip + 14 + 16 * 4).is_some_and(|f| f & 1 != 0);
        (0..dies).flat_map(move |d| {
            let die = u16_at(b, self.ip + 14 + 4 * d + 2).map_or(0, usize::from);
            let n = u16_at(b, die + 2).unwrap_or(0);
            let mut at = die + 4;
            (0..n).map_while(move |_| {
                let k = usize::from(*b.get(at + 3)?);
                let mut ip = Ip {
                    hw_id: u16_at(b, at)?,
                    instance: *b.get(at + 2)?,
                    version: (*b.get(at + 4)?, *b.get(at + 5)?, *b.get(at + 6)?),
                    base: [0; 8],
                    bases: k.min(8),
                };
                let step = if wide { 8 } else { 4 };
                for i in 0..ip.bases {
                    let p = at + 8 + step * i;
                    ip.base[i] = if wide {
                        u64::from(u32_at(b, p)?) | (u64::from(u32_at(b, p + 4)?) << 32)
                    } else {
                        u64::from(u32_at(b, p)?)
                    };
                }
                at += 8 + step * k;
                Some(ip)
            })
        })
    }

    /// The first instance of `hw_id`.
    pub fn find(&self, hw_id: u16) -> Option<Ip> {
        self.ips().find(|i| i.hw_id == hw_id && i.instance == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// A version 1 binary with one die: DMU 3.1.5 (two bases) and MP1.
    fn binary() -> Vec<u8> {
        let mut b = std::vec![0u8; 0x200];
        b[0..4].copy_from_slice(&BINARY_SIGNATURE.to_le_bytes());
        b[4..6].copy_from_slice(&1u16.to_le_bytes());
        b[10..12].copy_from_slice(&0x200u16.to_le_bytes());
        b[12..14].copy_from_slice(&0x40u16.to_le_bytes());
        b[0x40..0x44].copy_from_slice(&TABLE_SIGNATURE.to_le_bytes());
        b[0x44..0x46].copy_from_slice(&3u16.to_le_bytes());
        b[0x4C..0x4E].copy_from_slice(&1u16.to_le_bytes());
        b[0x50..0x52].copy_from_slice(&0x100u16.to_le_bytes());
        b[0x102..0x104].copy_from_slice(&2u16.to_le_bytes());
        let mut ip = Vec::new();
        ip.extend_from_slice(&DMU.to_le_bytes());
        ip.extend_from_slice(&[0, 2, 3, 1, 5, 0]);
        ip.extend_from_slice(&0x12u32.to_le_bytes());
        ip.extend_from_slice(&0xC0u32.to_le_bytes());
        ip.extend_from_slice(&MP1.to_le_bytes());
        ip.extend_from_slice(&[0, 1, 13, 0, 5, 0]);
        ip.extend_from_slice(&0x16000u32.to_le_bytes());
        b[0x104..0x104 + ip.len()].copy_from_slice(&ip);
        let sum = byte_sum(&b[10..0x200]);
        b[8..10].copy_from_slice(&sum.to_le_bytes());
        b
    }

    #[test]
    fn blocks_and_bases() {
        let b = binary();
        let t = Table::new(&b).unwrap();
        let ips: Vec<Ip> = t.ips().collect();
        assert_eq!(ips.len(), 2);
        let dmu = t.find(DMU).unwrap();
        assert_eq!((dmu.version, dmu.bases, dmu.base[0], dmu.base[1]), ((3, 1, 5), 2, 0x12, 0xC0));
        assert_eq!(t.find(MP1).unwrap().version, (13, 0, 5));
        assert!(t.find(GC).is_none());
        let mut bad = b.clone();
        bad[0x150] ^= 1;
        assert_eq!(Table::new(&bad).err(), Some(Error::Checksum));
        assert_eq!(Table::new(&b[4..]).err(), Some(Error::Signature));
        assert_eq!(offset(512), (512 << 20) - (64 << 10));
    }

    /// The reference PC's own table, when target/gpu/refpc holds it.
    #[test]
    fn refpc_discovery() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/gpu/refpc/discovery.bin");
        let Ok(b) = std::fs::read(path) else { return };
        let t = Table::new(&b).unwrap();
        // As amdgpu reported it under Fedora: DCN 3.1.5, GC 10.3.6, MP1
        // 13.0.5.
        assert_eq!(t.find(DMU).unwrap().version, (3, 1, 5));
        assert_eq!(t.find(GC).unwrap().version, (10, 3, 6));
        assert_eq!(t.find(MP1).unwrap().version, (13, 0, 5));
        std::println!(
            "table v{}; DMU bases {:x?}",
            t.version(),
            &t.find(DMU).unwrap().base[..t.find(DMU).unwrap().bases]
        );
    }
}
