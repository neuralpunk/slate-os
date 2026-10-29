// SPDX-License-Identifier: MIT OR Apache-2.0

//! The boot disk's EFI System Partition, through the BIOS's extended disk
//! reads: a GPT's partition of the EFI system type (UEFI 2.10 §5.3), or
//! an MBR's partition of type EFh (the USB image).

use alloc::format;
use alloc::string::String;

use slate_fat::Error;
use slate_fat::SECTOR;
use slate_fat::edit::Disk;

use crate::bios;
use crate::rm::DISK_BUFFER;

/// A partition of the boot drive, read by sector from its start.
#[derive(Debug)]
pub struct Part {
    pub drive: u8,
    pub start: u64,
}

/// At most this many sectors a call (32 KiB): some BIOSes take no more
/// than 127.
const CHUNK: usize = 64;
const _: () = assert!(CHUNK * SECTOR <= crate::rm::DISK_BUFFER_LEN);

fn read(drive: u8, lba: u64, buf: &mut [u8]) -> Result<(), ()> {
    for (i, chunk) in buf.chunks_mut(CHUNK * SECTOR).enumerate() {
        let n = chunk.len().div_ceil(SECTOR);
        bios::read_sectors(drive, lba + (i * CHUNK) as u64, n as u16)?;
        // SAFETY: The disk buffer holds what the BIOS just read.
        let from = unsafe { core::slice::from_raw_parts(DISK_BUFFER as *const u8, chunk.len()) };
        chunk.copy_from_slice(from);
    }
    Ok(())
}

impl Disk for Part {
    fn read(&mut self, sector: u64, buf: &mut [u8; SECTOR]) -> Result<(), Error> {
        read(self.drive, self.start + sector, buf).map_err(|_| Error::Io)
    }
    /// The loader's count of a trial boot and the one-shot choice
    /// (emptied) are all it writes.
    fn write(&mut self, sector: u64, data: &[u8; SECTOR]) -> Result<(), Error> {
        // SAFETY: The disk buffer, which the next call reads out.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), DISK_BUFFER as *mut u8, SECTOR) };
        bios::write_sectors(self.drive, self.start + sector, 1).map_err(|_| Error::Io)
    }
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn read_run(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), Error> {
        read(self.drive, self.start + sector, buf).map_err(|_| Error::Io)
    }
}

/// The EFI System Partition's first sector on `drive`.
pub fn esp(drive: u8) -> Result<u64, String> {
    if !bios::extended_disk(drive) {
        return Err(format!("drive {drive:#x} has no extended disk reads"));
    }
    let io = |_| String::from("cannot read the boot disk");
    let mut s0 = [0u8; SECTOR];
    read(drive, 0, &mut s0).map_err(io)?;
    match slate_mbr::parse(&s0, u64::MAX) {
        slate_mbr::Table::Gpt => {
            let mut h = [0u8; SECTOR];
            read(drive, 1, &mut h).map_err(io)?;
            let h = slate_gpt::parse_header(&h).map_err(|e| format!("GPT: {e:?}"))?;
            let len = h.entry_count as usize * h.entry_size as usize;
            if len > 64 << 10 {
                return Err("GPT entry array too large".into());
            }
            let mut a = alloc::vec![0u8; len.next_multiple_of(SECTOR)];
            read(drive, h.entries_lba, &mut a).map_err(io)?;
            let mut entries = slate_gpt::parse_entries(&h, &a).map_err(|e| format!("GPT: {e:?}"))?;
            entries
                .find(|e| e.type_guid == slate_gpt::Guid::EFI_SYSTEM)
                .map(|e| e.first_lba)
                .ok_or_else(|| "the boot disk has no EFI System Partition".into())
        }
        slate_mbr::Table::Mbr { primary, .. } => primary
            .iter()
            .find(|p| p.kind == 0xef)
            .map(|p| p.start)
            .ok_or_else(|| "the boot disk has no EFI System Partition".into()),
        slate_mbr::Table::None => Err("the boot disk has no partition table".into()),
    }
}
