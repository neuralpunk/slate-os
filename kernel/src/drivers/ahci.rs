// SPDX-License-Identifier: MIT OR Apache-2.0

//! AHCI SATA host controllers and the ATA disks on them.
//!
//! Sources: Serial ATA AHCI 1.3.1 (registers §3, command list and tables
//! §4.2, native command queuing §5.6.4 and §8, initialization §10.1,
//! BIOS/OS handoff §10.6, error recovery §6.2.2) and ATA8-ACS (IDENTIFY
//! DEVICE data words, READ/WRITE DMA EXT, READ/WRITE FPDMA QUEUED, FLUSH
//! CACHE EXT), with the Register Host-to-Device FIS from the Serial ATA
//! specification (§10.5.5).
//!
//! Where the controller and the disk both do native command queuing,
//! reads and writes are queued: each takes a command slot (as many as
//! both allow, up to 32), is issued through PxSACT and PxCI, and is done
//! when the device clears its PxSACT bit. Every other command (IDENTIFY,
//! FLUSH, TRIM, STANDBY) runs alone in slot 0 once the queue has drained,
//! as do reads and writes on disks without queuing. An error restarts the
//! port, which aborts every queued command; each is then tried once more
//! on its own, so only the one that failed reports it.
//!
//! Data moves straight between the disk and the caller's buffer, one PRD
//! entry per physically contiguous run; buffers at odd addresses or not
//! mapped by the kernel go through the port's bounce buffer. Completion
//! comes by MSI where the controller has it, else by polling.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use slate_sync::Once;

use super::dma::{Dma, Mmio, delay_ms, wait_for};
use super::pci::Device;
use crate::block::{self, BlockDevice, Family, IoError};
use crate::sched::wait::{Mutex, WaitQueue};
use crate::{log_info, log_warn};

// Generic host control (§3.1).
const CAP: usize = 0x00;
const GHC: usize = 0x04;
const IS: usize = 0x08;
const PI: usize = 0x0C;
const VS: usize = 0x10;
const CAP2: usize = 0x24;
const BOHC: usize = 0x28;

const CAP_S64A: u32 = 1 << 31;
/// CAP.SNCQ: the controller does native command queuing (§3.1.1).
const CAP_SNCQ: u32 = 1 << 30;
const CAP_SSS: u32 = 1 << 27;
const GHC_IE: u32 = 1 << 1;
const GHC_AE: u32 = 1 << 31;
const CAP2_BOH: u32 = 1 << 0;
const BOHC_BOS: u32 = 1 << 0;
const BOHC_OOS: u32 = 1 << 1;
const BOHC_BB: u32 = 1 << 4;

// Port registers (§3.3), at 0x100 + 0x80 * port.
const PX_CLB: usize = 0x00;
const PX_FB: usize = 0x08;
const PX_IS: usize = 0x10;
const PX_IE: usize = 0x14;
const PX_CMD: usize = 0x18;
const PX_TFD: usize = 0x20;
const PX_SIG: usize = 0x24;
const PX_SSTS: usize = 0x28;
const PX_SCTL: usize = 0x2C;
const PX_SERR: usize = 0x30;
/// PxSACT: a queued command's tag is set here before it is issued, and
/// the device clears it when the command completes (§3.3.13).
const PX_SACT: usize = 0x34;
const PX_CI: usize = 0x38;

const CMD_ST: u32 = 1 << 0;
const CMD_SUD: u32 = 1 << 1;
const CMD_POD: u32 = 1 << 2;
const CMD_FRE: u32 = 1 << 4;
const CMD_FR: u32 = 1 << 14;
const CMD_CR: u32 = 1 << 15;

const TFD_ERR: u32 = 1 << 0;
const TFD_DRQ: u32 = 1 << 3;
const TFD_BSY: u32 = 1 << 7;

/// PxIS error bits: task file error, host bus fatal/data error, interface
/// fatal error, overflow (§3.3.5).
const IS_ERRORS: u32 = (1 << 30) | (1 << 29) | (1 << 28) | (1 << 27) | (1 << 24);
/// Interrupts a port raises: D2H register FIS, PIO setup, DMA setup, set
/// device bits (queued completions), descriptor processed, and the errors.
const IE_MASK: u32 = 0x1F | IS_ERRORS;

/// PxSIG of an ATA disk (§3.3.9; ATAPI devices are skipped).
const SIG_ATA: u32 = 0x0000_0101;

// ATA commands (ATA8-ACS §7).
const ATA_IDENTIFY: u8 = 0xEC;
const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA_EXT: u8 = 0x35;
/// READ and WRITE FPDMA QUEUED (ATA8-ACS §7.27, §7.68): the sector count
/// in the features registers, the tag in bits 7:3 of the count.
const ATA_READ_FPDMA_QUEUED: u8 = 0x60;
const ATA_WRITE_FPDMA_QUEUED: u8 = 0x61;
const ATA_FLUSH_CACHE_EXT: u8 = 0xEA;
/// STANDBY IMMEDIATE (ATA8-ACS §7.53): spin down, heads parked, before
/// the power goes.
const ATA_STANDBY_IMMEDIATE: u8 = 0xE0;
/// DATA SET MANAGEMENT with the TRIM bit (ATA8-ACS §7.10): one 512-byte
/// block of 64 ranges (48-bit LBA, 16-bit count), sent by DMA.
const ATA_DSM: u8 = 0x06;
const DSM_TRIM: u16 = 1;

const FIS_REG_H2D: u8 = 0x27;

/// The most one command moves, and the bounce buffer's size.
const BOUNCE: usize = 256 * 1024;
const COMMAND_TIMEOUT_MS: u64 = 10_000;
/// A command table: the command FIS area (0x80 bytes), then PRD entries
/// of 16 bytes (§4.2.3).
const TABLE: usize = 4096;
const MAX_PRDS: usize = (TABLE - 0x80) / 16;
/// The most one PRD entry covers (DBC is 22 bits, §4.2.3.3).
const PRD_MAX: u64 = 4 << 20;

/// What the interrupt handler shares with a port's waiters.
struct PortEvents {
    status: AtomicU32,
    waiters: WaitQueue,
}

/// The controller-wide part.
struct Hba {
    regs: Mmio,
    ports: [Once<Arc<PortEvents>>; 32],
    interrupts: bool,
    /// CAP.SNCQ and CAP.NCS + 1.
    ncq: bool,
    slots: usize,
}

impl Hba {
    fn port(&self, p: usize) -> Mmio {
        // SAFETY: Port register blocks lie inside ABAR for implemented ports.
        Mmio(unsafe { self.regs.0.add(0x100 + 0x80 * p) })
    }

    fn interrupt(&self) {
        let is = self.regs.read32(IS);
        for p in 0..32 {
            if is & (1 << p) == 0 {
                continue;
            }
            let regs = self.port(p);
            let pis = regs.read32(PX_IS);
            regs.write32(PX_IS, pis);
            if let Some(ev) = self.ports[p].get() {
                ev.status.fetch_or(pis, Ordering::AcqRel);
                ev.waiters.wake_all();
            }
        }
        self.regs.write32(IS, is);
    }
}

/// Memory a port's commands use: the command list and received-FIS area
/// (one page: list at 0, FIS at 0x400), a command table per slot.
struct PortMem {
    list: Dma,
    tables: Vec<Dma>,
}

pub struct AhciDisk {
    name: String,
    model: String,
    hba: Arc<Hba>,
    index: usize,
    events: Arc<PortEvents>,
    mem: PortMem,
    bounce: Mutex<Dma>,
    sectors: u64,
    /// The disk takes TRIM (IDENTIFY word 169 bit 0).
    trim: bool,
    /// Queued reads and writes, in this many slots (1: not queued).
    queued: bool,
    slots: usize,
    /// Taken slots, one bit each.
    busy: AtomicU32,
    /// A command that runs alone is waiting for the queue to drain: no
    /// new queued commands until it is done.
    draining: AtomicBool,
    /// Commands that run alone, and recoveries, one at a time.
    alone: Mutex<()>,
    /// How many times the port was restarted after an error.
    epoch: AtomicU32,
    in_flight: AtomicUsize,
    most_in_flight: AtomicUsize,
}

/// An ATA command's registers: the command, its features, the LBA and the
/// sector count.
#[derive(Clone, Copy, Debug)]
struct Ata {
    cmd: u8,
    features: u16,
    lba: u64,
    count: u16,
}

impl Ata {
    const fn new(cmd: u8, lba: u64, count: u16) -> Ata {
        Ata { cmd, features: 0, lba, count }
    }
}

/// Where a command's data is: physically contiguous runs (address,
/// bytes).
type Runs = Vec<(u64, usize)>;

/// The runs of a kernel buffer, or `None` if it is at an odd address
/// (§4.2.3.3: DBA bit 0 is reserved) or not all mapped by the kernel.
fn buffer_runs(ptr: *const u8, len: usize) -> Option<Runs> {
    let pages = super::dma::kernel_pages(ptr, len, 2)?;
    let mut runs: Runs = Vec::new();
    let mut left = len;
    for (i, p) in pages.iter().enumerate() {
        let first = if i == 0 { 4096 - (ptr as usize % 4096) } else { 4096 };
        let n = first.min(left);
        match runs.last_mut() {
            Some((a, l)) if *a + *l as u64 == *p && ((*l + n) as u64) <= PRD_MAX => *l += n,
            _ => runs.push((*p, n)),
        }
        left -= n;
    }
    (runs.len() <= MAX_PRDS).then_some(runs)
}

impl AhciDisk {
    fn regs(&self) -> Mmio {
        self.hba.port(self.index)
    }

    /// Write slot `slot`'s command FIS, PRD table and header.
    fn prepare(&self, slot: usize, ata: Ata, runs: &[(u64, usize)], write: bool) {
        let Ata { cmd, features, lba, count } = ata;
        let table = &self.mem.tables[slot];
        // Command FIS (Register H2D, §10.5.5 of SATA).
        table.zero_range(0, 0x80);
        let fis = [
            FIS_REG_H2D,
            0x80, // Command, not control.
            cmd,
            features as u8,
            lba as u8,
            (lba >> 8) as u8,
            (lba >> 16) as u8,
            if cmd == ATA_IDENTIFY { 0 } else { 0x40 }, // LBA mode.
            (lba >> 24) as u8,
            (lba >> 32) as u8,
            (lba >> 40) as u8,
            (features >> 8) as u8,
            count as u8,
            (count >> 8) as u8,
            0,
            0,
        ];
        table.copy_in(0, &fis);
        for (i, &(addr, len)) in runs.iter().enumerate() {
            // A PRD entry: data base, byte count - 1 (§4.2.3.3).
            table.write::<u64>(0x80 + 16 * i, addr);
            table.write::<u32>(0x88 + 16 * i, 0);
            table.write::<u32>(0x8C + 16 * i, (len as u32 - 1) & 0x3F_FFFF);
        }
        // Command header (§4.2.2): FIS length 5 dwords, write flag, PRD count.
        let flags = 5 | if write { 1 << 6 } else { 0 } | ((runs.len() as u32) << 16);
        let h = slot * 32;
        self.mem.list.write::<u32>(h, flags);
        self.mem.list.write::<u32>(h + 4, 0);
        self.mem.list.write::<u64>(h + 8, table.phys());
    }

    fn failed(&self) -> bool {
        let pending = if self.hba.interrupts { 0 } else { self.regs().read32(PX_IS) };
        (self.events.status.load(Ordering::Acquire) | pending) & IS_ERRORS != 0
    }

    /// Wait for `done`, by interrupt or by polling.
    fn wait(&self, done: impl FnMut() -> bool) -> bool {
        if self.hba.interrupts && crate::sched::can_block() {
            let deadline = crate::time::monotonic_ns() + COMMAND_TIMEOUT_MS * 1_000_000;
            self.events.waiters.wait_until_timeout(done, deadline)
        } else {
            wait_for(COMMAND_TIMEOUT_MS, done)
        }
    }

    fn release(&self, slot: usize) {
        self.busy.fetch_and(!(1 << slot), Ordering::AcqRel);
        self.events.waiters.wake_all();
    }

    /// Run one command alone in slot 0 once nothing else is in flight, and
    /// wait for it.
    fn command(&self, ata: Ata, runs: &[(u64, usize)], write: bool) -> Result<(), IoError> {
        let _alone = self.alone.lock();
        self.draining.store(true, Ordering::SeqCst);
        let r = self.command_alone(ata, runs, write);
        self.draining.store(false, Ordering::SeqCst);
        self.events.waiters.wake_all();
        r
    }

    fn command_alone(&self, ata: Ata, runs: &[(u64, usize)], write: bool) -> Result<(), IoError> {
        // Slot 0, once nothing is in flight: queued commands check
        // `draining` again after taking a slot, so none starts after this.
        let take = || self.busy.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst).is_ok();
        if !self.wait(take) {
            log_warn!("{}: queued commands do not finish", self.name);
            self.recover();
            self.busy.store(1, Ordering::SeqCst);
        }
        let regs = self.regs();
        if !wait_for(COMMAND_TIMEOUT_MS, || regs.read32(PX_TFD) & (TFD_BSY | TFD_DRQ) == 0) {
            log_warn!("{}: device stays busy (TFD {:#x})", self.name, regs.read32(PX_TFD));
            self.recover();
            self.release(0);
            return Err(IoError);
        }
        self.prepare(0, ata, runs, write);
        self.events.status.store(0, Ordering::Release);
        if !self.hba.interrupts {
            regs.write32(PX_IS, u32::MAX);
        }
        core::sync::atomic::fence(Ordering::SeqCst);
        regs.write32(PX_CI, 1);
        let finished = self.wait(|| regs.read32(PX_CI) & 1 == 0 || self.failed());
        let tfd = regs.read32(PX_TFD);
        let r = if !finished || self.failed() || tfd & TFD_ERR != 0 {
            log_warn!(
                "{}: command {:#x} at {} failed (IS {:#x}, TFD {tfd:#x}{})",
                self.name,
                ata.cmd,
                ata.lba,
                self.events.status.load(Ordering::Acquire) | regs.read32(PX_IS),
                if finished { "" } else { ", timed out" }
            );
            self.recover();
            Err(IoError)
        } else {
            Ok(())
        };
        self.release(0);
        r
    }

    /// A queued read or write (§5.6.4): a free slot as its tag, PxSACT,
    /// then PxCI; done when the device clears the tag in PxSACT. After an
    /// error (this command's or another's, which aborts all of them), it
    /// is tried once more alone.
    fn queued(&self, lba: u64, sectors: u16, runs: &[(u64, usize)], write: bool) -> Result<(), IoError> {
        let slot = loop {
            if !self.draining.load(Ordering::SeqCst) {
                let busy = self.busy.load(Ordering::SeqCst);
                let free = (0..self.slots).find(|s| busy & (1 << s) == 0);
                if let Some(s) = free
                    && self.busy.compare_exchange(busy, busy | (1 << s), Ordering::SeqCst, Ordering::Relaxed).is_ok()
                {
                    // A command that runs alone may have started waiting
                    // for the queue meanwhile: let it go first.
                    if !self.draining.load(Ordering::SeqCst) {
                        break s;
                    }
                    self.release(s);
                }
                if free.is_some() && !self.draining.load(Ordering::SeqCst) {
                    continue;
                }
            }
            let ready = || {
                !self.draining.load(Ordering::Acquire)
                    && self.busy.load(Ordering::Acquire).count_ones() < self.slots as u32
            };
            if crate::sched::can_block() {
                self.events.waiters.wait_until(ready);
            } else {
                core::hint::spin_loop();
            }
        };
        let bit = 1u32 << slot;
        let cmd = if write { ATA_WRITE_FPDMA_QUEUED } else { ATA_READ_FPDMA_QUEUED };
        // The count goes in the features registers, the tag in count 7:3.
        self.prepare(slot, Ata { cmd, features: sectors, lba, count: (slot as u16) << 3 }, runs, write);
        let epoch = self.epoch.load(Ordering::Acquire);
        let regs = self.regs();
        core::sync::atomic::fence(Ordering::SeqCst);
        regs.write32(PX_SACT, bit);
        regs.write32(PX_CI, bit);
        let now = self.in_flight.fetch_add(1, Ordering::AcqRel) + 1;
        self.most_in_flight.fetch_max(now, Ordering::Relaxed);
        let done = || {
            (regs.read32(PX_SACT) | regs.read32(PX_CI)) & bit == 0
                || self.failed()
                || self.epoch.load(Ordering::Acquire) != epoch
        };
        let finished = self.wait(done);
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
        // Done if the device cleared the tag before any restart (a restart
        // moves `epoch` before it clears the registers).
        let cleared = (regs.read32(PX_SACT) | regs.read32(PX_CI)) & bit == 0;
        let completed = cleared && self.epoch.load(Ordering::Acquire) == epoch;
        if completed {
            self.release(slot);
            return Ok(());
        }
        // Restart the port once for everyone in flight, then try again alone.
        {
            let _alone = self.alone.lock();
            if self.epoch.load(Ordering::Acquire) == epoch {
                log_warn!(
                    "{}: queued {} at {lba} {} (IS {:#x}, TFD {:#x}); restarting the port",
                    self.name,
                    if write { "write" } else { "read" },
                    if finished { "failed" } else { "timed out" },
                    self.events.status.load(Ordering::Acquire) | regs.read32(PX_IS),
                    regs.read32(PX_TFD)
                );
                self.recover();
            }
        }
        self.release(slot);
        let cmd = if write { ATA_WRITE_DMA_EXT } else { ATA_READ_DMA_EXT };
        self.command(Ata::new(cmd, lba, sectors), runs, write)
    }

    /// Restart the port after an error (§6.2.2.1): stop it (which clears
    /// PxCI and PxSACT, aborting what was in flight), clear the error
    /// state, start it again.
    fn recover(&self) {
        // First, so no waiter takes an aborted command for a finished one.
        self.epoch.fetch_add(1, Ordering::SeqCst);
        let regs = self.regs();
        stop_port(regs);
        regs.write32(PX_SERR, u32::MAX);
        regs.write32(PX_IS, u32::MAX);
        self.events.status.store(0, Ordering::Release);
        start_port(regs);
        self.events.waiters.wake_all();
    }

    /// Read or write `sectors` sectors at `lba` from or to `runs`.
    fn rw(&self, lba: u64, sectors: u16, runs: &[(u64, usize)], write: bool) -> Result<(), IoError> {
        if self.queued {
            self.queued(lba, sectors, runs, write)
        } else {
            let cmd = if write { ATA_WRITE_DMA_EXT } else { ATA_READ_DMA_EXT };
            self.command(Ata::new(cmd, lba, sectors), runs, write)
        }
    }

    fn transfer(&self, sector: u64, buf: *mut u8, len: usize, write: bool) -> Result<(), IoError> {
        if len % 512 != 0 || sector + (len / 512) as u64 > self.sectors {
            return Err(IoError);
        }
        let mut done = 0;
        while done < len {
            let n = (len - done).min(BOUNCE);
            let lba = sector + (done / 512) as u64;
            let count = (n / 512) as u16;
            // SAFETY: `done + n <= len`, inside the caller's buffer.
            let p = unsafe { buf.add(done) };
            if let Some(runs) = buffer_runs(p, n) {
                self.rw(lba, count, &runs, write)?;
            } else {
                let b = self.bounce.lock();
                let runs = [(b.phys(), n)];
                if write {
                    // SAFETY: As above; the caller's buffer holds `len` bytes.
                    b.copy_in(0, unsafe { core::slice::from_raw_parts(p, n) });
                    self.rw(lba, count, &runs, true)?;
                } else {
                    self.rw(lba, count, &runs, false)?;
                    // SAFETY: As above.
                    b.copy_out(0, unsafe { core::slice::from_raw_parts_mut(p, n) });
                }
            }
            done += n;
        }
        Ok(())
    }
}

impl BlockDevice for AhciDisk {
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
        self.transfer(sector, buf.as_mut_ptr(), buf.len(), false)
    }
    fn write(&self, sector: u64, buf: &[u8]) -> Result<(), IoError> {
        self.transfer(sector, buf.as_ptr().cast_mut(), buf.len(), true)
    }
    fn flush(&self) -> Result<(), IoError> {
        self.command(Ata::new(ATA_FLUSH_CACHE_EXT, 0, 0), &[], false)
    }
    fn shutdown(&self) {
        if self.command(Ata::new(ATA_STANDBY_IMMEDIATE, 0, 0), &[], false).is_err() {
            log_warn!("{}: STANDBY IMMEDIATE failed", self.name);
        }
    }
    fn model(&self) -> String {
        self.model.clone()
    }
    fn can_discard(&self) -> bool {
        self.trim
    }
    fn queue_depth(&self) -> usize {
        self.slots
    }
    fn discard(&self, sector: u64, count: u64) -> Result<(), IoError> {
        if !self.trim || sector.checked_add(count).is_none_or(|end| end > self.sectors) {
            return Err(IoError);
        }
        let b = self.bounce.lock();
        let (mut lba, end) = (sector, sector + count);
        while lba < end {
            // Up to 64 ranges of up to 65535 sectors per command.
            let mut block = [0u8; 512];
            for e in block.as_chunks_mut::<8>().0.iter_mut() {
                if lba >= end {
                    break;
                }
                let n = (end - lba).min(0xFFFF);
                *e = (lba | (n << 48)).to_le_bytes();
                lba += n;
            }
            b.copy_in(0, &block);
            self.command(Ata { cmd: ATA_DSM, features: DSM_TRIM, lba: 0, count: 1 }, &[(b.phys(), 512)], true)?;
        }
        Ok(())
    }
}

/// Clear ST and FRE and wait for the engines to stop (§10.1.2).
fn stop_port(regs: Mmio) {
    let cmd = regs.read32(PX_CMD);
    if cmd & (CMD_ST | CMD_CR) != 0 {
        regs.write32(PX_CMD, cmd & !CMD_ST);
        wait_for(500, || regs.read32(PX_CMD) & CMD_CR == 0);
    }
    let cmd = regs.read32(PX_CMD);
    if cmd & (CMD_FRE | CMD_FR) != 0 {
        regs.write32(PX_CMD, cmd & !CMD_FRE);
        wait_for(500, || regs.read32(PX_CMD) & CMD_FR == 0);
    }
}

fn start_port(regs: Mmio) {
    regs.write32(PX_CMD, regs.read32(PX_CMD) | CMD_FRE);
    wait_for(1000, || regs.read32(PX_TFD) & (TFD_BSY | TFD_DRQ) == 0);
    regs.write32(PX_CMD, regs.read32(PX_CMD) | CMD_ST);
}

/// Take the controller from the firmware (§10.6).
fn bios_handoff(regs: Mmio) {
    if regs.read32(CAP2) & CAP2_BOH == 0 {
        return;
    }
    regs.write32(BOHC, regs.read32(BOHC) | BOHC_OOS);
    if !wait_for(25, || regs.read32(BOHC) & BOHC_BOS == 0) {
        log_warn!("AHCI: firmware keeps the controller; taking it anyway");
    }
    delay_ms(25);
    if regs.read32(BOHC) & BOHC_BB != 0 {
        wait_for(2000, || regs.read32(BOHC) & BOHC_BB == 0);
    }
}

/// ATA string from IDENTIFY words (two characters per word, high byte
/// first), trimmed.
fn ata_string(id: &[u8], first_word: usize, words: usize) -> String {
    let mut s = String::new();
    for w in first_word..first_word + words {
        for b in [id[2 * w + 1], id[2 * w]] {
            s.push(if b.is_ascii_graphic() || b == b' ' { b as char } else { ' ' });
        }
    }
    String::from(s.trim())
}

fn word(id: &[u8], w: usize) -> u16 {
    u16::from_le_bytes([id[2 * w], id[2 * w + 1]])
}

/// Every disk found, for the tests.
static DISKS: crate::sync::IrqSpinLock<Vec<Arc<AhciDisk>>> = crate::sync::IrqSpinLock::new(Vec::new());

pub fn probe(pci: Arc<Device>) -> Option<()> {
    pci.enable();
    let regs = Mmio(pci.map_bar(5)?);
    regs.write32(GHC, regs.read32(GHC) | GHC_AE);
    bios_handoff(regs);
    regs.write32(GHC, regs.read32(GHC) | GHC_AE);
    let cap = regs.read32(CAP);
    if cap & CAP_S64A == 0 {
        log_warn!("AHCI {:?}: no 64-bit DMA; not supported", pci.address);
        return None;
    }
    let pi = regs.read32(PI);
    let vs = regs.read32(VS);
    // CAP.NCS (bits 12:8): command slots, zero based.
    let slots = (((cap >> 8) & 0x1F) + 1) as usize;

    let slot: Arc<Once<Arc<Hba>>> = Arc::new(Once::new());
    let irq_slot = slot.clone();
    let mode = pci.enable_interrupt(
        "ahci",
        Box::new(move || {
            if let Some(h) = irq_slot.get() {
                h.interrupt();
            }
        }),
    );
    let hba = Arc::new(Hba {
        regs,
        ports: [const { Once::new() }; 32],
        interrupts: mode.is_some(),
        ncq: cap & CAP_SNCQ != 0,
        slots,
    });
    slot.call_once(|| hba.clone());
    log_info!(
        "AHCI {:?}: version {}.{}, ports {pi:#x}, {slots} slots{}, {}",
        pci.address,
        vs >> 16,
        (vs >> 8) & 0xFF,
        if hba.ncq { ", NCQ" } else { "" },
        mode.unwrap_or("polled")
    );

    let mut disks = Vec::new();
    for p in (0..32).filter(|p| pi & (1 << p) != 0) {
        if let Some(d) = init_port(&hba, p, cap) {
            disks.push(d);
        }
    }
    if hba.interrupts {
        regs.write32(IS, u32::MAX);
        regs.write32(GHC, regs.read32(GHC) | GHC_IE);
    }
    for d in disks {
        if let Some(disk) = identify(d) {
            DISKS.lock().push(disk.clone());
            block::register_disk(disk, Family::Scsi);
        }
    }
    Some(())
}

/// A port with a disk on it, started, before IDENTIFY.
struct Started {
    hba: Arc<Hba>,
    index: usize,
    events: Arc<PortEvents>,
    mem: PortMem,
    bounce: Dma,
}

fn init_port(hba: &Arc<Hba>, p: usize, cap: u32) -> Option<Started> {
    let regs = hba.port(p);
    stop_port(regs);
    // Spin up and power on where the controller staggers them (§10.10.1).
    if cap & CAP_SSS != 0 {
        regs.write32(PX_CMD, regs.read32(PX_CMD) | CMD_SUD | CMD_POD);
    }
    // Device present with the link up: DET = 3 (§3.3.10). An empty port
    // shows DET = 0 at once; a link still being negotiated shows 1.
    let det = || regs.read32(PX_SSTS) & 0xF;
    if !wait_for(50, || det() != 0) || !wait_for(1000, || det() == 3) {
        return None;
    }
    let mut tables = Vec::with_capacity(hba.slots);
    for _ in 0..hba.slots {
        tables.push(Dma::new(TABLE)?);
    }
    let mem = PortMem { list: Dma::new(4096)?, tables };
    let bounce = Dma::new(BOUNCE)?;
    regs.write64(PX_CLB, mem.list.phys());
    regs.write64(PX_FB, mem.list.phys() + 0x400);
    regs.write32(PX_SERR, u32::MAX);
    regs.write32(PX_IS, u32::MAX);
    // Receive FISes from now on: the device's first D2H register FIS
    // carries the signature (§3.3.9).
    regs.write32(PX_CMD, regs.read32(PX_CMD) | CMD_FRE);
    let ready = || regs.read32(PX_TFD) & (TFD_BSY | TFD_DRQ) == 0 && regs.read32(PX_SIG) != u32::MAX;
    if !wait_for(5000, ready) {
        // No signature yet: a COMRESET makes the device send it again
        // (§10.4.2: PxSCTL.DET = 1 for at least 1 ms, then 0).
        regs.write32(PX_SCTL, (regs.read32(PX_SCTL) & !0xF) | 1);
        delay_ms(2);
        regs.write32(PX_SCTL, regs.read32(PX_SCTL) & !0xF);
        wait_for(1000, || det() == 3);
        regs.write32(PX_SERR, u32::MAX);
        wait_for(5000, ready);
    }
    regs.write32(PX_SERR, u32::MAX);
    let sig = regs.read32(PX_SIG);
    if sig != SIG_ATA {
        log_info!("AHCI port {p}: device signature {sig:#x} (not a disk); skipped");
        abandon(regs, (mem, bounce));
        return None;
    }
    let events = Arc::new(PortEvents { status: AtomicU32::new(0), waiters: WaitQueue::new() });
    hba.ports[p].call_once(|| events.clone());
    regs.write32(PX_IE, if hba.interrupts { IE_MASK } else { 0 });
    start_port(regs);
    Some(Started { hba: hba.clone(), index: p, events, mem, bounce })
}

/// Stop a port that had our memory and keep that memory forever: a
/// device that was given an address may still write there.
fn abandon<T>(regs: Mmio, mem: T) {
    stop_port(regs);
    core::mem::forget(mem);
}

fn identify(s: Started) -> Option<Arc<AhciDisk>> {
    let regs = s.hba.port(s.index);
    let disk = AhciDisk {
        name: block::next_name(Family::Scsi),
        model: String::new(),
        hba: s.hba,
        index: s.index,
        events: s.events,
        mem: s.mem,
        bounce: Mutex::new(s.bounce),
        sectors: 0,
        trim: false,
        queued: false,
        slots: 1,
        busy: AtomicU32::new(0),
        draining: AtomicBool::new(false),
        alone: Mutex::new(()),
        epoch: AtomicU32::new(0),
        in_flight: AtomicUsize::new(0),
        most_in_flight: AtomicUsize::new(0),
    };
    match check_identity(&disk) {
        Some(found) => {
            let queued = disk.hba.ncq && found.depth > 1;
            let slots = if queued { found.depth.min(disk.hba.slots) } else { 1 };
            log_info!(
                "AHCI port {}: /dev/{}, \"{}\", {} MiB{}{}",
                disk.index,
                disk.name,
                found.model,
                found.sectors / 2048,
                if found.trim { ", TRIM" } else { "" },
                if queued { alloc::format!(", NCQ depth {slots}") } else { String::new() }
            );
            Some(Arc::new(AhciDisk {
                model: found.model,
                sectors: found.sectors,
                trim: found.trim,
                queued,
                slots,
                ..disk
            }))
        }
        None => {
            // As in `abandon`: the port had this disk's memory.
            abandon(regs, disk);
            None
        }
    }
}

/// What IDENTIFY DEVICE says about a disk.
struct Identity {
    sectors: u64,
    model: String,
    trim: bool,
    /// Queue depth for native command queuing (1: none).
    depth: usize,
}

fn check_identity(disk: &AhciDisk) -> Option<Identity> {
    let mut id = [0u8; 512];
    {
        let b = disk.bounce.lock();
        disk.command(Ata::new(ATA_IDENTIFY, 0, 0), &[(b.phys(), 512)], false).ok()?;
        b.copy_out(0, &mut id);
    }
    // Words 83 bit 10: 48-bit addressing; 100-103 its sector count.
    // Word 106 bit 12: logical sectors longer than 256 words (words
    // 117-118).
    if word(&id, 83) & (1 << 10) == 0 {
        log_warn!("{}: no 48-bit addressing; not supported", disk.name);
        return None;
    }
    let sectors = (0..4).fold(0u64, |acc, i| acc | (u64::from(word(&id, 100 + i)) << (16 * i)));
    let w106 = word(&id, 106);
    if w106 & 0xC000 == 0x4000 && w106 & (1 << 12) != 0 {
        let words = u32::from(word(&id, 117)) | (u32::from(word(&id, 118)) << 16);
        if words != 256 {
            log_warn!("{}: {}-byte logical sectors are not supported", disk.name, words * 2);
            return None;
        }
    }
    // Word 76 bit 8: native command queuing; word 75 bits 4:0 the queue
    // depth less one.
    let depth = if word(&id, 76) & (1 << 8) != 0 { usize::from(word(&id, 75) & 0x1F) + 1 } else { 1 };
    // Word 169 bit 0: DATA SET MANAGEMENT's TRIM.
    Some(Identity { sectors, model: ata_string(&id, 27, 20), trim: word(&id, 169) & 1 != 0, depth })
}

pub const TESTS: &[crate::ktest::Test] = &[
    crate::ktest::Test { name: "ahci::parallel_io", run: test_parallel },
    crate::ktest::Test { name: "ahci::recovers", run: test_recovers },
];

/// The test machine's AHCI disk fails one read at 24 MiB (QEMU's
/// blkdebug, `AHCI_BAD_SECTOR` in xtask): eight threads read around it at
/// once, every read still succeeds (the failed one and those the restart
/// aborted are tried again alone), and the port was restarted.
fn test_recovers() -> Result<(), &'static str> {
    const BAD: u64 = (24 << 20) / 512;
    let Some(disk) = DISKS.lock().first().cloned() else { return Err("no AHCI disk") };
    let before = disk.epoch.load(Ordering::Acquire);
    let failures = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(AtomicUsize::new(0));
    for t in 0..8u64 {
        let (disk, failures, finished) = (disk.clone(), failures.clone(), finished.clone());
        crate::sched::spawn("ahci-test", move || {
            let mut b = alloc::vec![0u8; 64 * 1024];
            if disk.read(BAD - 4 * 128 + t * 128, &mut b).is_err() {
                failures.fetch_add(1, Ordering::Relaxed);
            }
            finished.fetch_add(1, Ordering::Release);
        });
    }
    if !wait_for(60_000, || finished.load(Ordering::Acquire) == 8) {
        return Err("the readers did not finish");
    }
    if failures.load(Ordering::Relaxed) != 0 {
        return Err("a read failed for good");
    }
    if disk.epoch.load(Ordering::Acquire) == before {
        return Err("no error came, or the port was not restarted");
    }
    Ok(())
}

/// Eight threads write their own stretch of the first AHCI disk at once
/// (16 MiB on, past what tests/user/disks.c uses), half of them through
/// the bounce buffer, then read it all back at once: the data matches,
/// and with NCQ more than one command was in flight.
fn test_parallel() -> Result<(), &'static str> {
    let Some(disk) = DISKS.lock().first().cloned() else { return Err("no AHCI disk") };
    const THREADS: usize = 8;
    const SPAN: usize = 128 * 1024;
    const BASE: u64 = (16 << 20) / 512;
    if disk.sectors < BASE + (THREADS * SPAN / 512) as u64 {
        return Err("the disk is too small");
    }
    let pattern = |t: usize, i: usize| (i * 7 + t * 31 + 3) as u8;
    let failures = Arc::new(AtomicUsize::new(0));
    disk.most_in_flight.store(0, Ordering::Relaxed);
    for write in [true, false] {
        let finished = Arc::new(AtomicUsize::new(0));
        for t in 0..THREADS {
            let (disk, failures, finished) = (disk.clone(), failures.clone(), finished.clone());
            crate::sched::spawn("ahci-test", move || {
                let mut b = alloc::vec![0u8; SPAN + 1];
                // Odd threads use an odd address: the bounce buffer.
                let at = t % 2;
                let sector = BASE + (t * SPAN / 512) as u64;
                let ok = if write {
                    for (i, x) in b[at..at + SPAN].iter_mut().enumerate() {
                        *x = pattern(t, i);
                    }
                    disk.write(sector, &b[at..at + SPAN]).is_ok()
                } else {
                    disk.read(sector, &mut b[at..at + SPAN]).is_ok()
                        && b[at..at + SPAN].iter().enumerate().all(|(i, &x)| x == pattern(t, i))
                };
                if !ok {
                    failures.fetch_add(1, Ordering::Relaxed);
                }
                finished.fetch_add(1, Ordering::Release);
            });
        }
        if !wait_for(30_000, || finished.load(Ordering::Acquire) == THREADS) {
            return Err("the threads did not finish");
        }
    }
    if failures.load(Ordering::Relaxed) != 0 {
        return Err("a parallel write or read went wrong");
    }
    if disk.queued && disk.most_in_flight.load(Ordering::Relaxed) < 2 {
        return Err("NCQ, but never more than one command in flight");
    }
    Ok(())
}
