// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parsing of ACPI static tables from byte slices.
//!
//! Layouts follow the ACPI Specification 6.5: RSDP (§5.2.5.3), system
//! description table header (§5.2.6), XSDT/RSDT (§5.2.7, §5.2.8), FADT
//! (§5.2.9), MADT (§5.2.12) and the generic address structure (§5.2.3.2).
//! The HPET table follows the IA-PC HPET specification 1.0a, §3.2.4; MCFG
//! follows the PCI Firmware Specification 3.2, §4.1.2; IVRS the AMD I/O
//! Virtualization Technology (IOMMU) Specification 48882, §5.2.
//!
//! The crate never touches memory itself: the kernel maps tables and hands
//! in slices, so all parsing is unit-tested on the host.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

/// Errors from parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BadSignature,
    BadChecksum,
    Truncated,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// ACPI checksums: all bytes sum to zero modulo 256.
pub fn checksum_ok(b: &[u8]) -> bool {
    b.iter().fold(0u8, |a, &x| a.wrapping_add(x)) == 0
}

/// Root System Description Pointer (§5.2.5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rsdp {
    pub revision: u8,
    pub rsdt: u32,
    /// Present from revision 2.
    pub xsdt: Option<u64>,
}

/// Bytes needed to parse an RSDP of any revision.
pub const RSDP_MAX_LEN: usize = 36;

pub fn parse_rsdp(b: &[u8]) -> Result<Rsdp, Error> {
    if b.get(0..8) != Some(b"RSD PTR ") {
        return Err(Error::BadSignature);
    }
    if !checksum_ok(b.get(..20).ok_or(Error::Truncated)?) {
        return Err(Error::BadChecksum);
    }
    let revision = b[15];
    let rsdt = u32_at(b, 16).ok_or(Error::Truncated)?;
    let xsdt = if revision >= 2 {
        let len = u32_at(b, 20).ok_or(Error::Truncated)? as usize;
        if !checksum_ok(b.get(..len).ok_or(Error::Truncated)?) {
            return Err(Error::BadChecksum);
        }
        Some(u64_at(b, 24).ok_or(Error::Truncated)?)
    } else {
        None
    };
    Ok(Rsdp { revision, rsdt, xsdt })
}

/// Size of the common table header (§5.2.6).
pub const HEADER_LEN: usize = 36;

/// The common header of every system description table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
}

pub fn parse_header(b: &[u8]) -> Result<Header, Error> {
    if b.len() < HEADER_LEN {
        return Err(Error::Truncated);
    }
    Ok(Header { signature: [b[0], b[1], b[2], b[3]], length: u32_at(b, 4).unwrap(), revision: b[8] })
}

/// Validate a complete table: length and checksum, optionally signature.
pub fn validate<'a>(b: &'a [u8], signature: Option<&[u8; 4]>) -> Result<&'a [u8], Error> {
    let h = parse_header(b)?;
    if signature.is_some_and(|s| *s != h.signature) {
        return Err(Error::BadSignature);
    }
    let t = b.get(..h.length as usize).ok_or(Error::Truncated)?;
    if !checksum_ok(t) {
        return Err(Error::BadChecksum);
    }
    Ok(t)
}

/// Physical addresses of the tables listed in an XSDT (8-byte entries) or
/// RSDT (4-byte entries).
pub fn root_entries(table: &[u8], xsdt: bool) -> impl Iterator<Item = u64> + '_ {
    let width = if xsdt { 8 } else { 4 };
    table.get(HEADER_LEN..).unwrap_or(&[]).chunks_exact(width).map(move |c| {
        if xsdt {
            u64::from_le_bytes(c.try_into().unwrap())
        } else {
            u64::from(u32::from_le_bytes(c.try_into().unwrap()))
        }
    })
}

/// Generic Address Structure (§5.2.3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenericAddress {
    /// 0 = system memory, 1 = system I/O.
    pub space: u8,
    pub bit_width: u8,
    pub bit_offset: u8,
    pub access_size: u8,
    pub address: u64,
}

impl GenericAddress {
    pub const SPACE_MEMORY: u8 = 0;
    pub const SPACE_IO: u8 = 1;

    fn parse(b: &[u8], at: usize) -> Option<GenericAddress> {
        let s = b.get(at..at + 12)?;
        Some(GenericAddress {
            space: s[0],
            bit_width: s[1],
            bit_offset: s[2],
            access_size: s[3],
            address: u64_at(s, 4)?,
        })
    }
}

pub mod madt {
    //! Multiple APIC Description Table (§5.2.12).

    use super::{HEADER_LEN, u16_at, u32_at, u64_at};

    /// Flags bit: the system also has dual 8259 PICs (§5.2.12, table 5.20).
    pub const PCAT_COMPAT: u32 = 1;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Entry {
        /// Processor Local APIC (type 0).
        LocalApic {
            processor_uid: u8,
            apic_id: u8,
            flags: u32,
        },
        /// I/O APIC (type 1).
        IoApic {
            id: u8,
            address: u32,
            gsi_base: u32,
        },
        /// Interrupt Source Override (type 2): ISA `source` arrives on `gsi`.
        SourceOverride {
            bus: u8,
            source: u8,
            gsi: u32,
            flags: u16,
        },
        /// Local APIC NMI (type 4).
        LocalApicNmi {
            processor_uid: u8,
            flags: u16,
            lint: u8,
        },
        /// Local APIC Address Override (type 5).
        LocalApicAddressOverride {
            address: u64,
        },
        /// Processor Local x2APIC (type 9).
        LocalX2Apic {
            x2apic_id: u32,
            flags: u32,
            processor_uid: u32,
        },
        Other {
            kind: u8,
        },
    }

    /// Local APIC flags (§5.2.12.2, table 5.23).
    pub const LAPIC_ENABLED: u32 = 1;
    pub const LAPIC_ONLINE_CAPABLE: u32 = 2;

    /// MPS INTI flags (§5.2.12.5, table 5.26): polarity and trigger mode.
    pub const POLARITY_MASK: u16 = 0b11;
    pub const POLARITY_ACTIVE_LOW: u16 = 0b11;
    pub const TRIGGER_MASK: u16 = 0b1100;
    pub const TRIGGER_LEVEL: u16 = 0b1100;

    #[derive(Clone, Copy, Debug)]
    pub struct Madt<'a> {
        pub local_apic_address: u32,
        pub flags: u32,
        entries: &'a [u8],
    }

    pub fn parse(table: &[u8]) -> Option<Madt<'_>> {
        Some(Madt {
            local_apic_address: u32_at(table, HEADER_LEN)?,
            flags: u32_at(table, HEADER_LEN + 4)?,
            entries: table.get(HEADER_LEN + 8..)?,
        })
    }

    impl<'a> Madt<'a> {
        pub fn entries(&self) -> impl Iterator<Item = Entry> + 'a {
            let mut rest = self.entries;
            core::iter::from_fn(move || {
                let (&kind, &len) = (rest.first()?, rest.get(1)?);
                let len = len as usize;
                if len < 2 || len > rest.len() {
                    return None;
                }
                let e = &rest[..len];
                rest = &rest[len..];
                let entry = match kind {
                    0 if len >= 8 => Entry::LocalApic { processor_uid: e[2], apic_id: e[3], flags: u32_at(e, 4)? },
                    1 if len >= 12 => Entry::IoApic { id: e[2], address: u32_at(e, 4)?, gsi_base: u32_at(e, 8)? },
                    2 if len >= 10 => {
                        Entry::SourceOverride { bus: e[2], source: e[3], gsi: u32_at(e, 4)?, flags: u16_at(e, 8)? }
                    }
                    4 if len >= 6 => Entry::LocalApicNmi { processor_uid: e[2], flags: u16_at(e, 3)?, lint: e[5] },
                    5 if len >= 12 => Entry::LocalApicAddressOverride { address: u64_at(e, 4)? },
                    9 if len >= 16 => Entry::LocalX2Apic {
                        x2apic_id: u32_at(e, 4)?,
                        flags: u32_at(e, 8)?,
                        processor_uid: u32_at(e, 12)?,
                    },
                    _ => Entry::Other { kind },
                };
                Some(entry)
            })
        }
    }
}

pub mod hpet {
    //! HPET description table (IA-PC HPET specification 1.0a, §3.2.4).

    use super::{GenericAddress, HEADER_LEN};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Hpet {
        pub base: GenericAddress,
        pub number: u8,
    }

    pub fn parse(table: &[u8]) -> Option<Hpet> {
        Some(Hpet { base: GenericAddress::parse(table, HEADER_LEN + 4)?, number: *table.get(HEADER_LEN + 16)? })
    }
}

pub mod mcfg {
    //! PCI Express memory-mapped configuration space base addresses
    //! (PCI Firmware Specification 3.2, §4.1.2): after the header and 8
    //! reserved bytes, 16-byte entries of base address (u64), segment group
    //! (u16), start bus (u8), end bus (u8) and 4 reserved bytes.

    use super::{HEADER_LEN, u16_at, u64_at};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Entry {
        /// Physical address of bus 0's configuration space (even when
        /// `start_bus` is not 0).
        pub base: u64,
        pub segment: u16,
        pub start_bus: u8,
        pub end_bus: u8,
    }

    pub fn entries(table: &[u8]) -> impl Iterator<Item = Entry> + '_ {
        table.get(HEADER_LEN + 8..).unwrap_or(&[]).as_chunks::<16>().0.iter().filter_map(|e| {
            Some(Entry { base: u64_at(e, 0)?, segment: u16_at(e, 8)?, start_bus: e[10], end_bus: e[11] })
        })
    }
}

pub mod ivrs {
    //! I/O Virtualization Reporting Structure (AMD I/O Virtualization
    //! Technology (IOMMU) Specification 48882, Rev 3.11, §5.2): after the
    //! 48-byte header, I/O Virtualization Hardware Definition blocks (one per
    //! IOMMU, types 10h, 11h and 40h: Table 89) with their device entries
    //! (Tables 103 to 110), and Memory Definition blocks (types 20h to 22h:
    //! Tables 111 to 113) for the IOMMU before them.

    use alloc::vec::Vec;

    use super::{u16_at, u64_at};

    /// Where the definition blocks start (Table 85).
    const BLOCKS: usize = 48;

    /// One IOMMU.
    #[derive(Clone, Debug, PartialEq, Eq, Default)]
    pub struct Iommu {
        /// Its own PCI DeviceID (bus << 8 | device << 3 | function) and the
        /// offset of its capability block in its configuration space.
        pub device_id: u16,
        pub capability: u16,
        /// Its registers' physical address.
        pub base: u64,
        pub segment: u16,
        /// The IVHD flags (Table 92: Coherent is bit 5).
        pub flags: u8,
        /// The DeviceIDs it translates, as inclusive ranges.
        pub devices: Vec<(u16, u16)>,
        /// Devices that use another DeviceID as their source (alias
        /// entries): (first, last, the DeviceID used).
        pub aliases: Vec<(u16, u16, u16)>,
        /// Memory the firmware needs left reachable (IVMD blocks).
        pub memory: Vec<Memory>,
    }

    /// An IVMD block (Table 112): which devices it is for, and the range.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Memory {
        /// Inclusive DeviceID range; all devices for type 20h.
        pub first: u16,
        pub last: u16,
        pub start: u64,
        pub len: u64,
        /// Table 113: bit 0 unity (mapped at its own address), 1 IR, 2 IW,
        /// 3 exclusion range.
        pub flags: u8,
    }

    impl Iommu {
        /// Whether it translates `id`.
        pub fn covers(&self, id: u16) -> bool {
            self.devices.iter().any(|&(a, b)| (a..=b).contains(&id))
                || self.aliases.iter().any(|&(a, b, _)| (a..=b).contains(&id))
        }

        /// The DeviceID requests from device `id` carry.
        pub fn source_of(&self, id: u16) -> u16 {
            self.aliases.iter().find(|&&(a, b, _)| (a..=b).contains(&id)).map_or(id, |&(_, _, s)| s)
        }
    }

    /// The IOMMUs an IVRS table describes. Type 11h and 40h blocks are
    /// preferred over a type 10h block for the same IOMMU (§5.2: firmware
    /// gives both, the newer superseding).
    pub fn parse(table: &[u8]) -> Vec<Iommu> {
        let mut out: Vec<(u8, Iommu)> = Vec::new();
        let mut at = BLOCKS;
        while let (Some(&kind), Some(len)) = (table.get(at), u16_at(table, at + 2)) {
            let len = usize::from(len);
            let Some(block) = table.get(at..at + len).filter(|_| len >= 8) else { break };
            match kind {
                0x10 | 0x11 | 0x40 => {
                    if let Some(i) = hardware(block, if kind == 0x10 { 24 } else { 40 }) {
                        // Another block for the same IOMMU: keep the newer type.
                        match out.iter_mut().find(|(_, o)| o.base == i.base) {
                            Some((k, o)) if *k == 0x10 && kind != 0x10 => {
                                let memory = core::mem::take(&mut o.memory);
                                *o = Iommu { memory, ..i };
                                *k = kind;
                            }
                            Some(_) => {}
                            None => out.push((kind, i)),
                        }
                    }
                }
                0x20..=0x22 => {
                    if let (Some(m), Some((_, last))) = (memory(block), out.last_mut()) {
                        last.memory.push(m);
                    }
                }
                _ => {}
            }
            at += len;
        }
        out.into_iter().map(|(_, i)| i).collect()
    }

    /// An IVHD block whose device entries start at `entries`.
    fn hardware(b: &[u8], entries: usize) -> Option<Iommu> {
        let mut i = Iommu {
            flags: b[1],
            device_id: u16_at(b, 4)?,
            capability: u16_at(b, 6)?,
            base: u64_at(b, 8)?,
            segment: u16_at(b, 16)?,
            ..Iommu::default()
        };
        let mut at = entries;
        // A start of range waiting for its end, and the alias it uses.
        let mut start: Option<(u16, Option<u16>)> = None;
        while let Some(&kind) = b.get(at) {
            let id = u16_at(b, at + 1).unwrap_or(0);
            let len = match kind {
                0x00..=0x3F => 4,
                0x40..=0x7F => 8,
                // Variable length (Table 110): its length is at offset 21,
                // the UID after the 22 bytes before it.
                _ => 22 + usize::from(*b.get(at + 21)?),
            };
            match kind {
                // All (Table 105).
                0x01 => i.devices.push((0, 0xFFFF)),
                // Select, and Extended select (Table 107).
                0x02 | 0x46 => i.devices.push((id, id)),
                // Start of range, and Extended start of range.
                0x03 | 0x47 => start = Some((id, None)),
                // Alias select: device `id` uses DevIDb (bytes 5-6).
                0x42 => i.aliases.push((id, id, u16_at(b, at + 5)?)),
                // Alias start of range.
                0x43 => start = Some((id, Some(u16_at(b, at + 5)?))),
                // End of range.
                0x04 => match start.take() {
                    Some((first, None)) => i.devices.push((first, id)),
                    Some((first, Some(alias))) => i.aliases.push((first, id, alias)),
                    None => {}
                },
                // ACPI HID devices (F0h): their DeviceID is translated too.
                0xF0 => i.devices.push((id, id)),
                _ => {}
            }
            at += len;
        }
        Some(i)
    }

    fn memory(b: &[u8]) -> Option<Memory> {
        let id = u16_at(b, 4)?;
        let (first, last) = match b[0] {
            0x20 => (0, 0xFFFF),
            0x21 => (id, id),
            _ => (id, u16_at(b, 6)?),
        };
        Some(Memory { first, last, start: u64_at(b, 16)?, len: u64_at(b, 24)?, flags: b[1] })
    }

    /// For tests: the bytes of an IVRS table with these blocks.
    #[cfg(test)]
    pub fn table(blocks: &[&[u8]]) -> Vec<u8> {
        let mut t = alloc::vec![0u8; BLOCKS];
        t[..4].copy_from_slice(b"IVRS");
        for b in blocks {
            t.extend_from_slice(b);
        }
        let len = t.len() as u32;
        t[4..8].copy_from_slice(&len.to_le_bytes());
        t
    }
}

pub mod fadt {
    //! Fixed ACPI Description Table (§5.2.9, table 5.9).

    use super::{GenericAddress, u16_at, u32_at, u64_at};

    /// FADT flag: the power button is a control-method device (in AML),
    /// not the fixed-hardware button.
    pub const PWR_BUTTON: u32 = 1 << 4;
    /// FADT flag TMR_VAL_EXT: the PM timer counts in 32 bits, not 24
    /// (ACPI 6.5 §5.2.9, the FADT's fixed feature flags).
    pub const TMR_VAL_EXT: u32 = 1 << 8;
    /// FADT flag: the reset register is supported.
    pub const RESET_REG_SUP: u32 = 1 << 10;
    /// IA-PC boot architecture flag: there is no CMOS RTC (ACPI 6.5
    /// §5.2.9.3, table 5.11, bit 5).
    pub const BOOT_ARCH_NO_CMOS_RTC: u16 = 1 << 5;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Fadt {
        pub dsdt: u64,
        pub sci_interrupt: u16,
        pub smi_command: u32,
        pub acpi_enable: u8,
        pub pm1a_event: u32,
        pub pm1b_event: u32,
        pub pm1a_control: u32,
        pub pm1b_control: u32,
        pub pm_timer: u32,
        /// Bytes in each PM1 event block (status, then enable).
        pub pm1_event_len: u8,
        pub gpe0_block: u32,
        pub gpe1_block: u32,
        pub gpe0_len: u8,
        pub gpe1_len: u8,
        /// The number of GPE1's first event.
        pub gpe1_base: u8,
        pub century: u8,
        /// IA-PC boot architecture flags (`BOOT_ARCH_*`).
        pub iapc_boot_arch: u16,
        pub flags: u32,
        pub reset_register: Option<GenericAddress>,
        pub reset_value: u8,
    }

    pub fn parse(t: &[u8]) -> Option<Fadt> {
        let x_dsdt = u64_at(t, 140).filter(|&a| a != 0);
        let flags = u32_at(t, 112).unwrap_or(0);
        Some(Fadt {
            dsdt: x_dsdt.unwrap_or(u64::from(u32_at(t, 40)?)),
            sci_interrupt: u16_at(t, 46)?,
            smi_command: u32_at(t, 48)?,
            acpi_enable: *t.get(52)?,
            pm1a_event: u32_at(t, 56)?,
            pm1b_event: u32_at(t, 60)?,
            pm1a_control: u32_at(t, 64)?,
            pm1b_control: u32_at(t, 68)?,
            pm_timer: u32_at(t, 76)?,
            pm1_event_len: t.get(88).copied().unwrap_or(0),
            gpe0_block: u32_at(t, 80).unwrap_or(0),
            gpe1_block: u32_at(t, 84).unwrap_or(0),
            gpe0_len: t.get(92).copied().unwrap_or(0),
            gpe1_len: t.get(93).copied().unwrap_or(0),
            gpe1_base: t.get(94).copied().unwrap_or(0),
            century: t.get(108).copied().unwrap_or(0),
            iapc_boot_arch: u16_at(t, 109).unwrap_or(0),
            flags,
            reset_register: if flags & RESET_REG_SUP != 0 { GenericAddress::parse(t, 116) } else { None },
            reset_value: t.get(128).copied().unwrap_or(0),
        })
    }
}

/// Find the sleep type values of the `\_S5` (soft off) object in a DSDT.
///
/// This is not an AML interpreter: it looks for the common encoding
/// `NameOp "_S5_" PackageOp PkgLength NumElements <SLP_TYPa> <SLP_TYPb> ...`
/// (ACPI 6.5 §20.2.5.4 and §20.2.3 for the integer encodings), which is what
/// firmware emits in practice. A full interpreter can replace it later.
pub fn find_s5(dsdt: &[u8]) -> Option<(u8, u8)> {
    let body = dsdt.get(HEADER_LEN..)?;
    let at = body.windows(4).position(|w| w == b"_S5_")?;
    // NameOp, optionally followed by the root prefix '\'.
    let named = at >= 1 && (body[at - 1] == 0x08 || (at >= 2 && body[at - 1] == b'\\' && body[at - 2] == 0x08));
    if !named {
        return None;
    }
    let mut p = at + 4;
    if *body.get(p)? != 0x12 {
        return None; // PackageOp
    }
    p += 1;
    p += 1 + (body.get(p)? >> 6) as usize; // PkgLength: lead byte bits 7:6 = extra bytes
    p += 1; // NumElements
    let mut int = || -> Option<u8> {
        let op = *body.get(p)?;
        p += 1;
        match op {
            0x0A => {
                // BytePrefix
                let v = *body.get(p)?;
                p += 1;
                Some(v)
            }
            0x00 => Some(0), // ZeroOp
            0x01 => Some(1), // OneOp
            v if v < 0x0A => Some(v),
            _ => None,
        }
    };
    let a = int()?;
    let b = int().unwrap_or(0);
    Some((a, b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn fix_checksum(t: &mut [u8], at: usize) {
        t[at] = 0;
        let sum = t.iter().fold(0u8, |a, &x| a.wrapping_add(x));
        t[at] = 0u8.wrapping_sub(sum);
    }

    fn table(sig: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(sig);
        t.extend_from_slice(&((HEADER_LEN + body.len()) as u32).to_le_bytes());
        t.push(1);
        t.push(0);
        t.extend_from_slice(&[0; 26]);
        t.extend_from_slice(body);
        fix_checksum(&mut t, 9);
        t
    }

    #[test]
    fn mcfg_entries() {
        let mut body = std::vec![0u8; 8];
        body.extend_from_slice(&0xB000_0000u64.to_le_bytes());
        body.extend_from_slice(&[0, 0, 0, 0xFF, 0, 0, 0, 0]);
        let t = table(b"MCFG", &body);
        let e: Vec<_> = mcfg::entries(&t).collect();
        assert_eq!(e, [mcfg::Entry { base: 0xB000_0000, segment: 0, start_bus: 0, end_bus: 0xFF }]);
    }

    #[test]
    fn rsdp_v2() {
        let mut r = Vec::new();
        r.extend_from_slice(b"RSD PTR ");
        r.push(0);
        r.extend_from_slice(b"SLATE ");
        r.push(2);
        r.extend_from_slice(&0x1234u32.to_le_bytes());
        r.extend_from_slice(&36u32.to_le_bytes());
        r.extend_from_slice(&0xABCD_0000u64.to_le_bytes());
        r.extend_from_slice(&[0; 4]);
        fix_checksum(&mut r[..20], 8);
        fix_checksum(&mut r, 32);
        let p = parse_rsdp(&r).unwrap();
        assert_eq!(p, Rsdp { revision: 2, rsdt: 0x1234, xsdt: Some(0xABCD_0000) });
        r[16] ^= 1;
        assert_eq!(parse_rsdp(&r), Err(Error::BadChecksum));
    }

    #[test]
    fn xsdt_and_validation() {
        let mut body = Vec::new();
        body.extend_from_slice(&0x1000u64.to_le_bytes());
        body.extend_from_slice(&0x2000u64.to_le_bytes());
        let t = table(b"XSDT", &body);
        assert!(validate(&t, Some(b"XSDT")).is_ok());
        assert_eq!(validate(&t, Some(b"RSDT")), Err(Error::BadSignature));
        assert_eq!(root_entries(&t, true).collect::<Vec<_>>(), [0x1000, 0x2000]);
        let mut bad = t.clone();
        bad[40] ^= 0xFF;
        assert_eq!(validate(&bad, None), Err(Error::BadChecksum));
    }

    #[test]
    fn madt_entries() {
        let mut body = Vec::new();
        body.extend_from_slice(&0xFEE0_0000u32.to_le_bytes());
        body.extend_from_slice(&madt::PCAT_COMPAT.to_le_bytes());
        body.extend_from_slice(&[0, 8, 0, 0, 1, 0, 0, 0]); // LAPIC uid 0 id 0 enabled
        body.extend_from_slice(&[0, 8, 1, 1, 1, 0, 0, 0]);
        body.extend_from_slice(&[1, 12, 0, 0, 0x00, 0x00, 0xC0, 0xFE, 0, 0, 0, 0]); // IOAPIC at 0xFEC00000
        body.extend_from_slice(&[2, 10, 0, 0, 2, 0, 0, 0, 0, 0]); // ISA IRQ0 -> GSI2
        body.extend_from_slice(&[4, 6, 0xFF, 0, 0, 1]); // NMI on LINT1
        let t = table(b"APIC", &body);
        let m = madt::parse(&t).unwrap();
        assert_eq!(m.local_apic_address, 0xFEE0_0000);
        let e: Vec<_> = m.entries().collect();
        assert_eq!(e.len(), 5);
        assert_eq!(e[1], madt::Entry::LocalApic { processor_uid: 1, apic_id: 1, flags: 1 });
        assert_eq!(e[2], madt::Entry::IoApic { id: 0, address: 0xFEC0_0000, gsi_base: 0 });
        assert_eq!(e[3], madt::Entry::SourceOverride { bus: 0, source: 0, gsi: 2, flags: 0 });
        assert_eq!(e[4], madt::Entry::LocalApicNmi { processor_uid: 0xFF, flags: 0, lint: 1 });
    }

    #[test]
    fn s5_package() {
        // Name(\_S5, Package(4) { 0x05, Zero, Zero, Zero }) after some filler.
        let mut body = std::vec![0x10, 0x20, 0x30];
        body.extend_from_slice(&[0x08, b'\\', b'_', b'S', b'5', b'_', 0x12, 0x08, 0x04, 0x0A, 0x05, 0x00, 0x00, 0x00]);
        let t = table(b"DSDT", &body);
        assert_eq!(find_s5(&t), Some((5, 0)));
        let t = table(b"DSDT", &[0x08, b'_', b'S', b'5', b'_', 0x12, 0x06, 0x04, 0x07, 0x07, 0x00, 0x00]);
        assert_eq!(find_s5(&t), Some((7, 7)));
        assert_eq!(find_s5(&table(b"DSDT", b"nothing here")), None);
    }

    #[test]
    fn fadt_fields() {
        let mut t = std::vec![0u8; 276];
        t[..4].copy_from_slice(b"FACP");
        t[4..8].copy_from_slice(&276u32.to_le_bytes());
        t[40..44].copy_from_slice(&0x1111u32.to_le_bytes());
        t[64..68].copy_from_slice(&0x604u32.to_le_bytes());
        t[112..116].copy_from_slice(&fadt::RESET_REG_SUP.to_le_bytes());
        t[116] = 1; // I/O space
        t[120..128].copy_from_slice(&0xCF9u64.to_le_bytes());
        t[128] = 6;
        t[140..148].copy_from_slice(&0x2222u64.to_le_bytes());
        let f = fadt::parse(&t).unwrap();
        assert_eq!(f.dsdt, 0x2222, "X_DSDT takes precedence");
        assert_eq!(f.pm1a_control, 0x604);
        assert_eq!(f.reset_register.unwrap().address, 0xCF9);
        assert_eq!(f.reset_value, 6);
    }
    #[test]
    fn ivrs_blocks_and_entries() {
        use super::ivrs;
        // A type 10h IVHD: select 00:02.0, a range 01:00.0-01:1f.7, devices
        // 03:00.0-03:00.7 using 02:00.0's DeviceID, an ACPI device.
        let mut h10 = std::vec![0x10, 0x20, 0, 0, 0x02, 0x00, 0x40, 0x00];
        h10.extend_from_slice(&0xfeb8_0000u64.to_le_bytes());
        h10.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        h10.extend_from_slice(&[0x02, 0x10, 0x00, 0]);
        h10.extend_from_slice(&[0x03, 0x00, 0x01, 0, 0x04, 0xff, 0x01, 0]);
        h10.extend_from_slice(&[0x43, 0x00, 0x03, 0, 0, 0x00, 0x02, 0, 0x04, 0x07, 0x03, 0]);
        let mut acpi_dev = std::vec![0xF0, 0xa0, 0x00, 0];
        acpi_dev.extend_from_slice(&[0; 16]);
        acpi_dev.extend_from_slice(&[2, 4]);
        acpi_dev.extend_from_slice(b"FUR0");
        h10.extend_from_slice(&acpi_dev);
        let len = h10.len() as u16;
        h10[2..4].copy_from_slice(&len.to_le_bytes());
        // An IVMD for 00:02.0: 1 MiB at 0x1000_0000, unity, read and write.
        let mut md = std::vec![0x21, 0b0111, 32, 0, 0x10, 0x00, 0, 0];
        md.extend_from_slice(&[0; 8]);
        md.extend_from_slice(&0x1000_0000u64.to_le_bytes());
        md.extend_from_slice(&(1u64 << 20).to_le_bytes());
        // A type 11h block for the same IOMMU, which wins: one "all" entry.
        let mut h11 = std::vec![0x11, 0x20, 44, 0, 0x02, 0x00, 0x40, 0x00];
        h11.extend_from_slice(&0xfeb8_0000u64.to_le_bytes());
        h11.extend_from_slice(&[0; 24]);
        h11.extend_from_slice(&[0x01, 0, 0, 0]);
        let t = ivrs::table(&[&h10, &md, &h11]);
        let units = ivrs::parse(&t);
        assert_eq!(units.len(), 1);
        let u = &units[0];
        assert_eq!((u.base, u.device_id, u.capability, u.flags), (0xfeb8_0000, 0x0002, 0x40, 0x20));
        assert_eq!(u.devices, std::vec![(0, 0xFFFF)]);
        // The memory block followed the first block; it stays.
        assert_eq!(u.memory.len(), 1);
        assert_eq!((u.memory[0].first, u.memory[0].last, u.memory[0].start), (0x10, 0x10, 0x1000_0000));

        // Without the type 11h block: the entries themselves.
        let units = ivrs::parse(&ivrs::table(&[&h10]));
        let u = &units[0];
        assert_eq!(u.devices, std::vec![(0x10, 0x10), (0x100, 0x1ff), (0xa0, 0xa0)]);
        assert_eq!(u.aliases, std::vec![(0x300, 0x307, 0x200)]);
        assert!(u.covers(0x150) && u.covers(0x305) && !u.covers(0x400));
        assert_eq!(u.source_of(0x305), 0x200);
        assert_eq!(u.source_of(0x150), 0x150);
        // A truncated table stops parsing without panicking.
        assert!(ivrs::parse(&t[..60]).len() <= 1);
    }
}
