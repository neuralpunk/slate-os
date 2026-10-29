// SPDX-License-Identifier: MIT OR Apache-2.0

//! GUID Partition Table (GPT) encoding and parsing.
//!
//! Written from the UEFI Specification 2.10, section 5 ("GUID Partition
//! Table (GPT) Disk Layout"): the protective MBR (5.2.3), the GPT header
//! (5.3.2, table 5.5) and the partition entry (5.3.3, table 5.6).
//!
//! The crate is `no_std` and allocation-free so the kernel can use the parser
//! to discover partitions; the host image builder uses the encoder. The
//! `alloc` feature adds what needs a heap ([`free_regions`]).

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(test)]
extern crate std;

mod crc32;

pub use crc32::crc32;

/// Logical block size this crate works with. 4Kn disks are not handled yet.
pub const BLOCK_SIZE: usize = 512;
/// Number of partition entries we write (the spec minimum array size is 16 KiB).
pub const ENTRY_COUNT: u32 = 128;
/// Size of one partition entry in bytes (UEFI 2.10 table 5.5, `SizeOfPartitionEntry`).
pub const ENTRY_SIZE: u32 = 128;
/// Blocks used by the partition entry array.
pub const ENTRY_ARRAY_BLOCKS: u64 = (ENTRY_COUNT as u64 * ENTRY_SIZE as u64) / BLOCK_SIZE as u64;
/// Header signature "EFI PART" (UEFI 2.10 table 5.5).
pub const SIGNATURE: [u8; 8] = *b"EFI PART";
/// GPT revision 1.0 (UEFI 2.10 table 5.5).
pub const REVISION: u32 = 0x0001_0000;
/// Size of the header structure in bytes (UEFI 2.10 table 5.5).
pub const HEADER_SIZE: u32 = 92;

/// A GUID in its in-memory form (RFC 4122 fields; UEFI stores the first three
/// fields little-endian, see UEFI 2.10 appendix A).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

/// The registry format, lower case (`c12a7328-f81f-11d2-ba4b-00a0c93ec93b`),
/// as `PARTUUID=` names it.
impl core::fmt::Display for Guid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let d = self.data4;
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.data1, self.data2, self.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
        )
    }
}

impl Guid {
    /// The all-zero GUID; marks an unused partition entry.
    pub const NIL: Guid = Guid { data1: 0, data2: 0, data3: 0, data4: [0; 8] };

    /// EFI System Partition type GUID (UEFI 2.10 table 5.7).
    pub const EFI_SYSTEM: Guid = Guid {
        data1: 0xC12A_7328,
        data2: 0xF81F,
        data3: 0x11D2,
        data4: [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B],
    };

    /// BIOS boot partition type GUID ("Hah!IdontNeedEFI"), the GPT convention
    /// for a raw partition holding a BIOS bootloader's later stages.
    pub const BIOS_BOOT: Guid = Guid {
        data1: 0x2168_6148,
        data2: 0x6449,
        data3: 0x6E6F,
        data4: [0x74, 0x4E, 0x65, 0x65, 0x64, 0x45, 0x46, 0x49],
    };

    /// Linux file system data (also used for ext4 by other systems).
    pub const LINUX_FILESYSTEM: Guid = Guid {
        data1: 0x0FC6_3DAF,
        data2: 0x8483,
        data3: 0x4772,
        data4: [0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4],
    };

    /// Basic data, the type of FAT and NTFS partitions other systems read
    /// (Microsoft's PARTITION_BASIC_DATA_GUID, in its documentation of
    /// PARTITION_INFORMATION_GPT).
    pub const BASIC_DATA: Guid = Guid {
        data1: 0xEBD0_A0A2,
        data2: 0xB9E5,
        data3: 0x4433,
        data4: [0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7],
    };

    /// Encode to the 16-byte mixed-endian on-disk form.
    pub fn to_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&self.data1.to_le_bytes());
        out[4..6].copy_from_slice(&self.data2.to_le_bytes());
        out[6..8].copy_from_slice(&self.data3.to_le_bytes());
        out[8..16].copy_from_slice(&self.data4);
        out
    }

    /// Decode from the 16-byte on-disk form.
    pub fn from_bytes(b: &[u8; 16]) -> Guid {
        Guid {
            data1: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            data2: u16::from_le_bytes([b[4], b[5]]),
            data3: u16::from_le_bytes([b[6], b[7]]),
            data4: [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
        }
    }

    /// Build a version-4-shaped GUID from 16 arbitrary bytes (for example a
    /// hash), so images can be reproducible without a random source.
    pub fn from_seed(seed: [u8; 16]) -> Guid {
        let mut b = seed;
        b[7] = (b[7] & 0x0F) | 0x40; // version 4 (data3 high nibble, little-endian)
        b[8] = (b[8] & 0x3F) | 0x80; // RFC 4122 variant
        Guid::from_bytes(&b)
    }
}

/// A partition to place on the disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Partition<'a> {
    pub type_guid: Guid,
    pub unique_guid: Guid,
    pub first_lba: u64,
    /// Inclusive, as in the on-disk format.
    pub last_lba: u64,
    pub attributes: u64,
    /// The name, written as UTF-16LE: up to 36 code units, no NUL.
    pub name: &'a str,
}

/// Errors from encoding or parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    DiskTooSmall,
    TooManyPartitions,
    PartitionOutOfRange,
    PartitionsOverlap,
    BadName,
    BadSignature,
    BadHeaderCrc,
    BadEntryCrc,
    UnsupportedLayout,
    BufferTooSmall,
}

/// Disk geometry derived from its size in blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub total_blocks: u64,
    pub first_usable: u64,
    pub last_usable: u64,
}

impl Layout {
    pub fn for_disk(total_blocks: u64) -> Result<Layout, Error> {
        // MBR + header + array, and at the end: array + backup header.
        let overhead = 2 + 2 * ENTRY_ARRAY_BLOCKS + 1;
        if total_blocks <= overhead {
            return Err(Error::DiskTooSmall);
        }
        Ok(Layout {
            total_blocks,
            first_usable: 2 + ENTRY_ARRAY_BLOCKS,
            last_usable: total_blocks - 2 - ENTRY_ARRAY_BLOCKS,
        })
    }

    fn last_lba(&self) -> u64 {
        self.total_blocks - 1
    }
}

/// The free spaces of a disk `total_blocks` long whose partitions are
/// `parts` (first block, blocks), between the first and last usable
/// blocks: (first block, blocks), each starting and ending on a multiple
/// of `align` blocks and at least `align` long.
#[cfg(feature = "alloc")]
pub fn free_regions(total_blocks: u64, parts: &[(u64, u64)], align: u64) -> alloc::vec::Vec<(u64, u64)> {
    let Ok(layout) = Layout::for_disk(total_blocks) else { return alloc::vec::Vec::new() };
    let mut used: alloc::vec::Vec<(u64, u64)> = parts.iter().map(|&(s, n)| (s, s + n)).collect();
    used.sort();
    let mut out = alloc::vec::Vec::new();
    let mut at = layout.first_usable;
    let end = layout.last_usable + 1;
    for (s, e) in used.into_iter().chain(core::iter::once((end, end))) {
        let first = at.div_ceil(align) * align;
        let last = s.min(end) / align * align;
        if last > first {
            out.push((first, last - first));
        }
        at = at.max(e);
    }
    out
}

/// The metadata regions of a GPT disk, ready to be written at the given block
/// offsets. Produced by [`encode`].
#[derive(Debug)]
pub struct Encoded {
    /// Block 0.
    pub protective_mbr: [u8; BLOCK_SIZE],
    /// Block 1.
    pub primary_header: [u8; BLOCK_SIZE],
    /// Written at block 2 and at [`Encoded::backup_entries_lba`].
    pub entries: [u8; (ENTRY_COUNT * ENTRY_SIZE) as usize],
    /// Written at the last block.
    pub backup_header: [u8; BLOCK_SIZE],
    pub backup_entries_lba: u64,
    pub backup_header_lba: u64,
}

/// Encode a complete GPT for a disk of `total_blocks` blocks.
pub fn encode(total_blocks: u64, disk_guid: Guid, parts: &[Partition<'_>]) -> Result<Encoded, Error> {
    encode_with(total_blocks, disk_guid, parts.len(), |i| (i as u32, parts[i]))
}

/// [`encode`] with each partition in a slot of its own (its number - 1),
/// so a table changed in place keeps the others' numbers.
pub fn encode_slots(total_blocks: u64, disk_guid: Guid, parts: &[(u32, Partition<'_>)]) -> Result<Encoded, Error> {
    encode_with(total_blocks, disk_guid, parts.len(), |i| parts[i])
}

fn encode_with<'a>(
    total_blocks: u64,
    disk_guid: Guid,
    n: usize,
    part: impl Fn(usize) -> (u32, Partition<'a>),
) -> Result<Encoded, Error> {
    let layout = Layout::for_disk(total_blocks)?;
    if n > ENTRY_COUNT as usize || (0..n).any(|i| part(i).0 >= ENTRY_COUNT) {
        return Err(Error::TooManyPartitions);
    }
    for i in 0..n {
        let (slot, p) = part(i);
        if p.first_lba < layout.first_usable || p.last_lba > layout.last_usable || p.first_lba > p.last_lba {
            return Err(Error::PartitionOutOfRange);
        }
        for j in 0..i {
            let (other, q) = part(j);
            if p.first_lba <= q.last_lba && q.first_lba <= p.last_lba {
                return Err(Error::PartitionsOverlap);
            }
            if other == slot {
                return Err(Error::TooManyPartitions);
            }
        }
    }

    let mut entries = [0u8; (ENTRY_COUNT * ENTRY_SIZE) as usize];
    for i in 0..n {
        let (slot, p) = part(i);
        let i = slot as usize;
        let e = &mut entries[i * ENTRY_SIZE as usize..(i + 1) * ENTRY_SIZE as usize];
        e[0..16].copy_from_slice(&p.type_guid.to_bytes());
        e[16..32].copy_from_slice(&p.unique_guid.to_bytes());
        e[32..40].copy_from_slice(&p.first_lba.to_le_bytes());
        e[40..48].copy_from_slice(&p.last_lba.to_le_bytes());
        e[48..56].copy_from_slice(&p.attributes.to_le_bytes());
        if p.name.encode_utf16().count() > 36 || p.name.contains('\0') {
            return Err(Error::BadName);
        }
        for (j, u) in p.name.encode_utf16().enumerate() {
            e[56 + 2 * j..58 + 2 * j].copy_from_slice(&u.to_le_bytes());
        }
    }
    let entries_crc = crc32(&entries);

    let last = layout.last_lba();
    let backup_entries_lba = last - ENTRY_ARRAY_BLOCKS;
    let primary_header = header(&layout, disk_guid, 1, last, 2, entries_crc);
    let backup_header = header(&layout, disk_guid, last, 1, backup_entries_lba, entries_crc);

    Ok(Encoded {
        protective_mbr: protective_mbr(total_blocks),
        primary_header,
        entries,
        backup_header,
        backup_entries_lba,
        backup_header_lba: last,
    })
}

/// Protective MBR (UEFI 2.10 section 5.2.3, table 5.4).
fn protective_mbr(total_blocks: u64) -> [u8; BLOCK_SIZE] {
    let mut mbr = [0u8; BLOCK_SIZE];
    let rec = &mut mbr[446..462];
    rec[0] = 0x00; // BootIndicator
    rec[1..4].copy_from_slice(&[0x00, 0x02, 0x00]); // StartingCHS
    rec[4] = 0xEE; // OSType: GPT protective
    rec[5..8].copy_from_slice(&[0xFF, 0xFF, 0xFF]); // EndingCHS
    rec[8..12].copy_from_slice(&1u32.to_le_bytes()); // StartingLBA
    let size = u32::try_from(total_blocks - 1).unwrap_or(u32::MAX);
    rec[12..16].copy_from_slice(&size.to_le_bytes()); // SizeInLBA
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    mbr
}

/// GPT header (UEFI 2.10 table 5.5).
fn header(
    layout: &Layout,
    disk_guid: Guid,
    my_lba: u64,
    alt_lba: u64,
    entries_lba: u64,
    entries_crc: u32,
) -> [u8; BLOCK_SIZE] {
    let mut h = [0u8; BLOCK_SIZE];
    h[0..8].copy_from_slice(&SIGNATURE);
    h[8..12].copy_from_slice(&REVISION.to_le_bytes());
    h[12..16].copy_from_slice(&HEADER_SIZE.to_le_bytes());
    // 16..20 HeaderCRC32 (filled below), 20..24 Reserved.
    h[24..32].copy_from_slice(&my_lba.to_le_bytes());
    h[32..40].copy_from_slice(&alt_lba.to_le_bytes());
    h[40..48].copy_from_slice(&layout.first_usable.to_le_bytes());
    h[48..56].copy_from_slice(&layout.last_usable.to_le_bytes());
    h[56..72].copy_from_slice(&disk_guid.to_bytes());
    h[72..80].copy_from_slice(&entries_lba.to_le_bytes());
    h[80..84].copy_from_slice(&ENTRY_COUNT.to_le_bytes());
    h[84..88].copy_from_slice(&ENTRY_SIZE.to_le_bytes());
    h[88..92].copy_from_slice(&entries_crc.to_le_bytes());
    let crc = crc32(&h[..HEADER_SIZE as usize]);
    h[16..20].copy_from_slice(&crc.to_le_bytes());
    h
}

/// A validated GPT header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub my_lba: u64,
    pub alternate_lba: u64,
    pub first_usable: u64,
    pub last_usable: u64,
    pub disk_guid: Guid,
    pub entries_lba: u64,
    pub entry_count: u32,
    pub entry_size: u32,
    pub entries_crc: u32,
}

fn le_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn le_u64(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}

fn guid_at(b: &[u8], at: usize) -> Guid {
    let mut g = [0u8; 16];
    g.copy_from_slice(&b[at..at + 16]);
    Guid::from_bytes(&g)
}

/// Parse and validate a header block (signature and header CRC).
pub fn parse_header(block: &[u8]) -> Result<Header, Error> {
    if block.len() < BLOCK_SIZE {
        return Err(Error::BufferTooSmall);
    }
    if block[0..8] != SIGNATURE {
        return Err(Error::BadSignature);
    }
    let size = le_u32(block, 12) as usize;
    if !(HEADER_SIZE as usize..=BLOCK_SIZE).contains(&size) {
        return Err(Error::UnsupportedLayout);
    }
    let mut copy = [0u8; BLOCK_SIZE];
    copy[..size].copy_from_slice(&block[..size]);
    copy[16..20].fill(0);
    if crc32(&copy[..size]) != le_u32(block, 16) {
        return Err(Error::BadHeaderCrc);
    }
    let h = Header {
        my_lba: le_u64(block, 24),
        alternate_lba: le_u64(block, 32),
        first_usable: le_u64(block, 40),
        last_usable: le_u64(block, 48),
        disk_guid: guid_at(block, 56),
        entries_lba: le_u64(block, 72),
        entry_count: le_u32(block, 80),
        entry_size: le_u32(block, 84),
        entries_crc: le_u32(block, 88),
    };
    if h.entry_size < 128 || !h.entry_size.is_power_of_two() {
        return Err(Error::UnsupportedLayout);
    }
    Ok(h)
}

/// A partition entry as read from disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Slot in the entry array (partition number - 1).
    pub index: u32,
    pub type_guid: Guid,
    pub unique_guid: Guid,
    pub first_lba: u64,
    pub last_lba: u64,
    pub attributes: u64,
    /// Raw UTF-16LE name.
    pub name_utf16: [u16; 36],
}

/// Iterate the used entries of a partition entry array, after checking its CRC
/// against the header.
pub fn parse_entries<'a>(header: &Header, array: &'a [u8]) -> Result<impl Iterator<Item = Entry> + 'a, Error> {
    let len = header.entry_count as usize * header.entry_size as usize;
    if array.len() < len {
        return Err(Error::BufferTooSmall);
    }
    if crc32(&array[..len]) != header.entries_crc {
        return Err(Error::BadEntryCrc);
    }
    let size = header.entry_size as usize;
    Ok(array[..len].chunks_exact(size).enumerate().filter_map(|(index, e)| {
        let type_guid = guid_at(e, 0);
        if type_guid == Guid::NIL {
            return None;
        }
        let mut name_utf16 = [0u16; 36];
        for (i, n) in name_utf16.iter_mut().enumerate() {
            *n = u16::from_le_bytes([e[56 + 2 * i], e[57 + 2 * i]]);
        }
        Some(Entry {
            index: index as u32,
            type_guid,
            unique_guid: guid_at(e, 16),
            first_lba: le_u64(e, 32),
            last_lba: le_u64(e, 40),
            attributes: le_u64(e, 48),
            name_utf16,
        })
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: Guid = Guid { data1: 1, data2: 2, data3: 3, data4: [4; 8] };

    #[test]
    fn guid_round_trip_and_esp_bytes() {
        // On-disk bytes of the ESP type GUID (UEFI 2.10 appendix A encoding).
        let b = Guid::EFI_SYSTEM.to_bytes();
        assert_eq!(&b[..4], &[0x28, 0x73, 0x2A, 0xC1]);
        assert_eq!(Guid::from_bytes(&b), Guid::EFI_SYSTEM);
    }

    #[test]
    fn seeded_guid_is_v4() {
        let g = Guid::from_seed([0xFF; 16]);
        assert_eq!(g.data3 >> 12, 4);
        assert_eq!(g.data4[0] >> 6, 0b10);
    }

    #[test]
    fn layout_bounds() {
        let l = Layout::for_disk(2048).unwrap();
        assert_eq!(l.first_usable, 34);
        assert_eq!(l.last_usable, 2048 - 34);
        assert_eq!(Layout::for_disk(67), Err(Error::DiskTooSmall));
    }

    #[test]
    fn encode_then_parse() {
        let total = 64 * 2048;
        let parts = [Partition {
            type_guid: Guid::EFI_SYSTEM,
            unique_guid: SEED,
            first_lba: 2048,
            last_lba: total - 2048,
            attributes: 0,
            name: "EFI system",
        }];
        let enc = encode(total, SEED, &parts).unwrap();
        assert_eq!(&enc.protective_mbr[510..], &[0x55, 0xAA]);
        assert_eq!(enc.protective_mbr[450], 0xEE);

        let primary = parse_header(&enc.primary_header).unwrap();
        let backup = parse_header(&enc.backup_header).unwrap();
        assert_eq!(primary.my_lba, 1);
        assert_eq!(primary.alternate_lba, total - 1);
        assert_eq!(backup.my_lba, total - 1);
        assert_eq!(backup.entries_lba, total - 33);

        let entries: std::vec::Vec<_> = parse_entries(&primary, &enc.entries).unwrap().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].first_lba, 2048);
        assert_eq!(entries[0].type_guid, Guid::EFI_SYSTEM);
        assert_eq!(entries[0].name_utf16[0], u16::from(b'E'));
    }

    /// Names are UTF-16 (another system's, written back as they were).
    #[test]
    fn names_beyond_ascii() {
        let p = |name| Partition {
            type_guid: Guid::BASIC_DATA,
            unique_guid: SEED,
            first_lba: 2048,
            last_lba: 4095,
            attributes: 0,
            name,
        };
        let enc = encode(8192, SEED, &[p("Partição básica de dados")]).unwrap();
        let h = parse_header(&enc.primary_header).unwrap();
        let e = parse_entries(&h, &enc.entries).unwrap().next().unwrap();
        let name: std::string::String =
            char::decode_utf16(e.name_utf16.iter().copied().take_while(|&u| u != 0)).map(|c| c.unwrap()).collect();
        assert_eq!(name, "Partição básica de dados");
        assert_eq!(encode(8192, SEED, &[p("a\0b")]).unwrap_err(), Error::BadName);
        let (long, longest) = ("x".repeat(37), "x".repeat(36));
        assert_eq!(encode(8192, SEED, &[p(&long)]).unwrap_err(), Error::BadName);
        assert!(encode(8192, SEED, &[p(&longest)]).is_ok());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn free_space_between_partitions() {
        // On whole MiB, at least one.
        let s = 202_752;
        assert_eq!(free_regions(s, &[], 2048), [(2048, 97 * 2048)]);
        let parts = [(2048, 20 * 2048 - 2048), (40 * 2048, 10 * 2048)];
        assert_eq!(free_regions(s, &parts, 2048), [(20 * 2048, 20 * 2048), (50 * 2048, 48 * 2048)]);
    }

    #[test]
    fn rejects_overlap_and_corruption() {
        let p = |a, b| Partition {
            type_guid: Guid::EFI_SYSTEM,
            unique_guid: SEED,
            first_lba: a,
            last_lba: b,
            attributes: 0,
            name: "",
        };
        assert_eq!(encode(4096, SEED, &[p(100, 200), p(200, 300)]).unwrap_err(), Error::PartitionsOverlap);
        assert_eq!(encode(4096, SEED, &[p(10, 20)]).unwrap_err(), Error::PartitionOutOfRange);

        let mut enc = encode(4096, SEED, &[p(100, 200)]).unwrap();
        enc.primary_header[40] ^= 1;
        assert_eq!(parse_header(&enc.primary_header), Err(Error::BadHeaderCrc));
        let h = parse_header(&enc.backup_header).unwrap();
        enc.entries[0] ^= 1;
        assert!(matches!(parse_entries(&h, &enc.entries), Err(Error::BadEntryCrc)));
    }
}
