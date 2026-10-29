// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parallel ATA (IDE) disks on PCI IDE controllers, by programmed I/O.
//!
//! Sources: the PCI IDE Controller Specification 1.0 (the programming
//! interface byte, compatibility and native-PCI modes and their ports,
//! §2), ATA/ATAPI-6 (the command and control block registers §7, the
//! status bits §7.15, software reset §9.2, the PIO data-in and data-out
//! protocols §9.5-§9.6, the signatures of packet devices §9.12) and
//! ATA8-ACS (IDENTIFY DEVICE data words, READ SECTOR(S) (EXT), WRITE
//! SECTOR(S) (EXT), FLUSH CACHE (EXT)).
//!
//! Interrupts stay off (nIEN): every command polls the status register.
//! The two drives of a channel share its registers, so a channel runs one
//! command at a time. Packet (ATAPI) devices, such as CD drives, are
//! skipped.

use alloc::string::String;
use alloc::sync::Arc;

use super::dma::wait_for;
use super::pci::{Bar, Device};
use crate::arch::port::{Port8, Port16};
use crate::block::{self, BlockDevice, Family, IoError};
use crate::sched::wait::Mutex;
use crate::{log_info, log_warn};

// Command block registers (offsets from the command block's base).
const DATA: u16 = 0;
const ERROR: u16 = 1;
const COUNT: u16 = 2;
const LBA_LOW: u16 = 3;
const LBA_MID: u16 = 4;
const LBA_HIGH: u16 = 5;
const DEVICE: u16 = 6;
const STATUS: u16 = 7;
const COMMAND: u16 = 7;

// Status bits.
const BSY: u8 = 0x80;
const DF: u8 = 0x20;
const DRQ: u8 = 0x08;
const ERR: u8 = 0x01;

// Device control register bits.
const NIEN: u8 = 0x02;
const SRST: u8 = 0x04;

// Commands (ATA8-ACS).
const IDENTIFY: u8 = 0xEC;
const READ_SECTORS: u8 = 0x20;
const READ_SECTORS_EXT: u8 = 0x24;
const WRITE_SECTORS: u8 = 0x30;
const WRITE_SECTORS_EXT: u8 = 0x34;
const FLUSH_CACHE: u8 = 0xE7;
const FLUSH_CACHE_EXT: u8 = 0xEA;
/// STANDBY IMMEDIATE: spin down, heads parked, before the power goes.
const STANDBY_IMMEDIATE: u8 = 0xE0;

/// Sectors per command: 256 is the most a 28-bit command moves, and keeps
/// 48-bit ones short too.
const CHUNK: u64 = 256;
/// How long a command may keep the drive busy.
const TIMEOUT_MS: u64 = 10_000;

/// How long to spin on the status before sleeping between polls: a drive
/// is busy for microseconds between sectors, and a sleep lasts a whole
/// scheduler tick.
const SPIN_NS: u64 = 2_000_000;

/// Poll `cond`, spinning for [`SPIN_NS`], then as [`wait_for`] does.
fn spin_then_wait(timeout_ms: u64, mut cond: impl FnMut() -> bool) -> bool {
    let until = crate::time::monotonic_ns() + SPIN_NS;
    while crate::time::monotonic_ns() < until {
        if cond() {
            return true;
        }
        core::hint::spin_loop();
    }
    wait_for(timeout_ms, cond)
}

/// One IDE channel: its command block and its control register.
struct Channel {
    cmd: u16,
    ctrl: u16,
    lock: Mutex<()>,
}

impl Channel {
    fn reg(&self, off: u16) -> Port8 {
        // SAFETY: The command block's eight ports belong to this channel's
        // controller; reading and writing them drives the disk, not DMA.
        unsafe { Port8::new(self.cmd + off) }
    }

    fn data(&self) -> Port16 {
        // SAFETY: As in `reg`: the data port of this channel.
        unsafe { Port16::new(self.cmd + DATA) }
    }

    fn control(&self) -> Port8 {
        // SAFETY: The alternate status / device control port of this
        // channel; it has no side effects on read.
        unsafe { Port8::new(self.ctrl) }
    }

    /// The status, without acknowledging anything (alternate status).
    fn alt_status(&self) -> u8 {
        self.control().read()
    }

    /// Select a drive, then give it the 400 ns the standard asks for
    /// (four reads of the alternate status).
    fn select(&self, dev: u8) {
        self.reg(DEVICE).write(dev);
        for _ in 0..4 {
            self.alt_status();
        }
    }

    fn wait_not_busy(&self, ms: u64) -> bool {
        spin_then_wait(ms, || self.alt_status() & BSY == 0)
    }

    /// Wait for the drive to want data (or fail).
    fn wait_drq(&self) -> Result<(), IoError> {
        if !spin_then_wait(TIMEOUT_MS, || {
            let s = self.alt_status();
            s & BSY == 0 && s & (DRQ | ERR | DF) != 0
        }) {
            return Err(IoError);
        }
        let s = self.reg(STATUS).read();
        if s & (ERR | DF) != 0 || s & DRQ == 0 {
            return Err(IoError);
        }
        Ok(())
    }

    /// Soft reset of both drives, interrupts off.
    fn reset(&self) {
        self.control().write(NIEN | SRST);
        super::dma::delay_ms(1);
        self.control().write(NIEN);
        super::dma::delay_ms(2);
        self.wait_not_busy(2000);
    }
}

/// An ATA disk on a channel.
struct IdeDisk {
    name: String,
    model: String,
    channel: Arc<Channel>,
    /// Bit 4 of the device register: 0 the first drive, 1 the second.
    slave: u8,
    lba48: bool,
    sectors: u64,
}

impl IdeDisk {
    /// Issue a read or write command for `count` (1..=256) sectors at
    /// `lba`.
    fn issue(&self, cmd28: u8, cmd48: u8, lba: u64, count: u64) -> Result<(), IoError> {
        let c = &self.channel;
        if !c.wait_not_busy(TIMEOUT_MS) {
            return Err(IoError);
        }
        if self.lba48 {
            c.select(0x40 | self.slave << 4);
            // High bytes first, then low (the registers are two deep).
            c.reg(COUNT).write((count >> 8) as u8);
            c.reg(LBA_LOW).write((lba >> 24) as u8);
            c.reg(LBA_MID).write((lba >> 32) as u8);
            c.reg(LBA_HIGH).write((lba >> 40) as u8);
            c.reg(COUNT).write(count as u8);
            c.reg(LBA_LOW).write(lba as u8);
            c.reg(LBA_MID).write((lba >> 8) as u8);
            c.reg(LBA_HIGH).write((lba >> 16) as u8);
            c.reg(COMMAND).write(cmd48);
        } else {
            c.select(0xE0 | self.slave << 4 | ((lba >> 24) as u8 & 0x0F));
            // A count of 0 means 256.
            c.reg(COUNT).write(count as u8);
            c.reg(LBA_LOW).write(lba as u8);
            c.reg(LBA_MID).write((lba >> 8) as u8);
            c.reg(LBA_HIGH).write((lba >> 16) as u8);
            c.reg(COMMAND).write(cmd28);
        }
        Ok(())
    }

    fn check(&self, sector: u64, len: usize) -> Result<u64, IoError> {
        if len % 512 != 0 {
            return Err(IoError);
        }
        let n = (len / 512) as u64;
        if sector.checked_add(n).is_none_or(|end| end > self.sectors) || (!self.lba48 && sector + n > 1 << 28) {
            return Err(IoError);
        }
        Ok(n)
    }
}

impl BlockDevice for IdeDisk {
    fn name(&self) -> &str {
        &self.name
    }
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read_only(&self) -> bool {
        false
    }
    fn read(&self, sector: u64, buf: &mut [u8]) -> Result<(), IoError> {
        let total = self.check(sector, buf.len())?;
        let c = &self.channel;
        let _g = c.lock.lock();
        let mut done = 0;
        while done < total {
            let n = (total - done).min(CHUNK);
            self.issue(READ_SECTORS, READ_SECTORS_EXT, sector + done, n)?;
            for s in 0..n {
                c.wait_drq()?;
                let at = ((done + s) * 512) as usize;
                c.data().read_words(&mut buf[at..at + 512]);
            }
            done += n;
        }
        Ok(())
    }
    fn write(&self, sector: u64, buf: &[u8]) -> Result<(), IoError> {
        let total = self.check(sector, buf.len())?;
        let c = &self.channel;
        let _g = c.lock.lock();
        let mut done = 0;
        while done < total {
            let n = (total - done).min(CHUNK);
            self.issue(WRITE_SECTORS, WRITE_SECTORS_EXT, sector + done, n)?;
            for s in 0..n {
                c.wait_drq()?;
                let at = ((done + s) * 512) as usize;
                c.data().write_words(&buf[at..at + 512]);
            }
            // The last sector is written once the drive is no longer busy.
            if !c.wait_not_busy(TIMEOUT_MS) || c.reg(STATUS).read() & (ERR | DF) != 0 {
                return Err(IoError);
            }
            done += n;
        }
        Ok(())
    }
    fn flush(&self) -> Result<(), IoError> {
        let c = &self.channel;
        let _g = c.lock.lock();
        if !c.wait_not_busy(TIMEOUT_MS) {
            return Err(IoError);
        }
        c.select(0xE0 | self.slave << 4);
        c.reg(COMMAND).write(if self.lba48 { FLUSH_CACHE_EXT } else { FLUSH_CACHE });
        if !c.wait_not_busy(30_000) || c.reg(STATUS).read() & (ERR | DF) != 0 {
            return Err(IoError);
        }
        Ok(())
    }
    fn shutdown(&self) {
        let c = &self.channel;
        let _g = c.lock.lock();
        if c.wait_not_busy(TIMEOUT_MS) {
            c.select(0xE0 | self.slave << 4);
            c.reg(COMMAND).write(STANDBY_IMMEDIATE);
            let _ = c.wait_not_busy(30_000);
        }
    }
    fn model(&self) -> String {
        self.model.clone()
    }
}

fn word(id: &[u8], w: usize) -> u16 {
    u16::from_le_bytes([id[2 * w], id[2 * w + 1]])
}

fn ata_string(id: &[u8], first_word: usize, words: usize) -> String {
    let mut s = String::new();
    for w in first_word..first_word + words {
        for b in [id[2 * w + 1], id[2 * w]] {
            s.push(if b.is_ascii_graphic() || b == b' ' { b as char } else { ' ' });
        }
    }
    String::from(s.trim())
}

/// IDENTIFY DEVICE on drive `slave` of `c`: its 256 words, or None when
/// there is no ATA drive (nothing, or a packet device).
fn identify(c: &Channel, slave: u8) -> Option<[u8; 512]> {
    c.select(0xA0 | slave << 4);
    // No drive: the bus floats high, or the status stays 0.
    if c.alt_status() == 0xFF {
        return None;
    }
    c.reg(COUNT).write(0);
    c.reg(LBA_LOW).write(0);
    c.reg(LBA_MID).write(0);
    c.reg(LBA_HIGH).write(0);
    c.reg(COMMAND).write(IDENTIFY);
    if c.alt_status() == 0 || !c.wait_not_busy(1000) {
        return None;
    }
    // A packet device (or a SATA bridge) answers with its signature in the
    // LBA mid and high registers and aborts IDENTIFY DEVICE.
    if c.reg(LBA_MID).read() != 0 || c.reg(LBA_HIGH).read() != 0 {
        return None;
    }
    if !wait_for(1000, || c.alt_status() & (DRQ | ERR) != 0) || c.reg(STATUS).read() & ERR != 0 {
        let _ = c.reg(ERROR).read();
        return None;
    }
    let mut id = [0u8; 512];
    c.data().read_words(&mut id);
    Some(id)
}

/// The command block and control register of channel `n` (0 primary, 1
/// secondary): the fixed ports in compatibility mode, else BARs 0-1 or
/// 2-3 (the control register is the third byte of its BAR).
fn channel_ports(pci: &Device, n: usize) -> Option<(u16, u16)> {
    let native = pci.prog_if & (1 << (2 * n)) != 0;
    if !native {
        return Some(if n == 0 { (0x1F0, 0x3F6) } else { (0x170, 0x376) });
    }
    let io = |i: usize| match pci.bars.get(i).copied().flatten() {
        Some(Bar::Io { port, .. }) => Some(port),
        _ => None,
    };
    Some((io(2 * n)?, io(2 * n + 1)? + 2))
}

/// Probe a PCI IDE controller (class 01h, subclass 01h): both channels,
/// both drives.
pub fn probe(pci: Arc<Device>) -> Option<()> {
    pci.enable();
    let mut found = 0;
    for n in 0..2 {
        let Some((cmd, ctrl)) = channel_ports(&pci, n) else {
            log_warn!("IDE {:?}: channel {n} has no I/O ports", pci.address);
            continue;
        };
        let channel = Arc::new(Channel { cmd, ctrl, lock: Mutex::new(()) });
        if channel.alt_status() == 0xFF {
            continue; // Nothing on this channel.
        }
        channel.reset();
        for slave in 0..2 {
            let Some(id) = identify(&channel, slave) else { continue };
            // Word 49 bit 9: LBA; word 83 bit 10: 48-bit addressing (words
            // 100-103 its count, else 60-61 the 28-bit count).
            if word(&id, 49) & (1 << 9) == 0 {
                log_warn!("IDE {:?}: a drive without LBA; not supported", pci.address);
                continue;
            }
            let lba48 = word(&id, 83) & (1 << 10) != 0;
            let sectors = if lba48 {
                (0..4).fold(0u64, |acc, i| acc | (u64::from(word(&id, 100 + i)) << (16 * i)))
            } else {
                u64::from(word(&id, 60)) | (u64::from(word(&id, 61)) << 16)
            };
            let disk = IdeDisk {
                name: block::next_name(Family::Scsi),
                model: ata_string(&id, 27, 20),
                channel: channel.clone(),
                slave,
                lba48,
                sectors,
            };
            log_info!(
                "IDE {:?} channel {n} drive {slave}: /dev/{}, \"{}\", {} MiB{}",
                pci.address,
                disk.name,
                disk.model,
                sectors / 2048,
                if lba48 { "" } else { " (28-bit)" }
            );
            block::register_disk(Arc::new(disk), Family::Scsi);
            found += 1;
        }
    }
    if found == 0 {
        log_info!("IDE {:?}: no ATA disks", pci.address);
    }
    Some(())
}
