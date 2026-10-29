// SPDX-License-Identifier: MIT OR Apache-2.0

//! USB mass storage: SCSI commands over Bulk-Only Transport or USB
//! Attached SCSI (UAS, ADR 0082).
//!
//! Sources: USB Mass Storage Class Bulk-Only Transport 1.0 (the Command
//! Block Wrapper and Command Status Wrapper, §5; error handling, §6.6);
//! USB Attached SCSI 1.0 (the interface's alternate setting and pipes,
//! §5.3; the USB 3 stream protocol and the USB 2 protocol with Read Ready
//! and Write Ready, §5.4) with the information units of T10 UAS-2 (Command
//! IU, Sense IU, Response IU, Read Ready and Write Ready IUs, §6.2); SCSI
//! Primary Commands SPC-4 (INQUIRY, TEST UNIT READY, REQUEST SENSE, fixed
//! sense data) and SCSI Block Commands SBC-3 (READ CAPACITY (10)/(16),
//! READ (10)/(16), WRITE (10)/(16), SYNCHRONIZE CACHE (10)).
//!
//! A device whose mass storage interface has a UAS alternate setting
//! (protocol 62h) uses it, unless `slate.disable=usb-uas`: on SuperSpeed
//! every command's status and data go on the streams its tag names, which
//! are queued before the command is sent; at high speed the device asks
//! for the data (Read Ready, Write Ready) on the status pipe. Others use
//! Bulk-Only. One command at a time either way, data through a 64 KiB
//! bounce buffer (aligned to 64 KiB, so each transfer is one TRB that
//! crosses no 64 KiB boundary, as xHCI §4.11.7.1 requires).

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use super::xhci::{CC_STALL, Endpoint, SPEED_SUPER, TRANSFER_TIMEOUT_MS, UsbDevice};
use super::{EP_BULK, EndpointDesc, InterfaceDesc};
use crate::block::{self, BlockDevice, Family, IoError};
use crate::drivers::dma::{Dma, delay_ms};
use crate::sched::wait::Mutex;
use crate::{log_info, log_warn};

const CBW_SIGNATURE: u32 = 0x4342_5355;
const CSW_SIGNATURE: u32 = 0x5342_5355;
const BOUNCE: usize = 64 * 1024;

const TEST_UNIT_READY: u8 = 0x00;
const REQUEST_SENSE: u8 = 0x03;
const INQUIRY: u8 = 0x12;
const READ_CAPACITY_10: u8 = 0x25;
const READ_10: u8 = 0x28;
const WRITE_10: u8 = 0x2A;
const SYNCHRONIZE_CACHE_10: u8 = 0x35;
const START_STOP_UNIT: u8 = 0x1B;
/// START STOP UNIT's byte 4: LOEJ with START clear, stop and eject
/// (SBC-3 §5.25).
const STOP_AND_EJECT: u8 = 0x02;
const READ_16: u8 = 0x88;
const WRITE_16: u8 = 0x8A;
const SERVICE_ACTION_IN_16: u8 = 0x9E;
const READ_CAPACITY_16: u8 = 0x10;

/// UAS information unit IDs (UAS-2 §6.2.1, table 11).
const IU_COMMAND: u8 = 0x01;
const IU_SENSE: u8 = 0x03;
const IU_RESPONSE: u8 = 0x04;
const IU_READ_READY: u8 = 0x06;
const IU_WRITE_READY: u8 = 0x07;
/// The tag (and stream) commands use: one at a time.
const UAS_TAG: u16 = 1;
/// Streams asked for on each streaming pipe.
const UAS_STREAMS: u16 = 4;
/// Where IUs go in `Io::wrap`: the command at 0, status at 64.
const IU_STATUS: usize = 64;
const IU_STATUS_LEN: usize = 96;

struct Io {
    /// CBW (or Command IU) at 0, CSW (or the status pipe's IU) at 64.
    wrap: Dma,
    bounce: Dma,
    tag: u32,
    /// The sense key and ASC of UAS's last Sense IU.
    sense: (u8, u8),
}

/// How commands reach the device.
enum Transport {
    /// Bulk-Only: one pipe each way.
    Bot { bulk_in: Arc<Endpoint>, bulk_out: Arc<Endpoint>, in_addr: u8, out_addr: u8 },
    /// UAS: command, status, data-in and data-out pipes; `streams` on
    /// SuperSpeed.
    Uas {
        command: Arc<Endpoint>,
        status: Arc<Endpoint>,
        data_in: Arc<Endpoint>,
        data_out: Arc<Endpoint>,
        streams: bool,
    },
}

pub struct UsbDisk {
    name: String,
    model: String,
    dev: Arc<UsbDevice>,
    transport: Transport,
    io: Mutex<Io>,
    /// Logical block size (512 or 4096...).
    block: usize,
    blocks: u64,
    removable: bool,
}

enum Data<'a> {
    None,
    In(&'a mut [u8]),
    Out(&'a [u8]),
}

impl UsbDisk {
    fn bulk(&self, ep: &Endpoint, address: u8, phys: u64, len: usize) -> Result<usize, u8> {
        let r = self.dev.transfer(ep, phys, len);
        if r == Err(CC_STALL) {
            self.dev.clear_halt(ep, address);
        }
        r
    }

    /// One command; returns the bytes moved.
    fn command(&self, io: &mut Io, cdb: &[u8], data: Data<'_>) -> Result<usize, IoError> {
        if self.dev.gone.load(Ordering::Acquire) {
            return Err(IoError);
        }
        match &self.transport {
            Transport::Bot { bulk_in, bulk_out, in_addr, out_addr } => {
                self.bot_command(io, (bulk_in, *in_addr), (bulk_out, *out_addr), cdb, data)
            }
            Transport::Uas { command, status, data_in, data_out, streams } => {
                self.uas_command(io, [command, status, data_in, data_out], *streams, cdb, data)
            }
        }
    }

    /// A UAS command (UAS 1.0 §5.4, UAS-2 §6.2): the Command IU, the data,
    /// and the Sense IU that ends it. On SuperSpeed the status and data
    /// transfers are queued on the tag's stream first; at high speed the
    /// device asks for the data with Read Ready or Write Ready.
    fn uas_command(
        &self,
        io: &mut Io,
        [cmd_pipe, status_pipe, data_in, data_out]: [&Arc<Endpoint>; 4],
        streams: bool,
        cdb: &[u8],
        data: Data<'_>,
    ) -> Result<usize, IoError> {
        let tag = UAS_TAG;
        // Command IU (UAS-2 §6.2.2): ID, tag (big-endian), simple task
        // attribute, no additional CDB bytes, LUN 0, the CDB in 16 bytes.
        let mut iu = [0u8; 32];
        iu[0] = IU_COMMAND;
        iu[2..4].copy_from_slice(&tag.to_be_bytes());
        iu[16..16 + cdb.len()].copy_from_slice(cdb);
        io.wrap.copy_in(0, &iu);
        let (len, dir_in) = match &data {
            Data::None => (0, false),
            Data::In(b) => (b.len(), true),
            Data::Out(b) => (b.len(), false),
        };
        if let Data::Out(b) = &data {
            io.bounce.copy_in(0, b);
        }
        let data_pipe = if dir_in { data_in } else { data_out };
        let status_phys = io.wrap.phys() + IU_STATUS as u64;
        let fail = |what: &str| {
            log_warn!("{}: UAS command {:#x}: {what}", self.name, cdb[0]);
            IoError
        };
        let mut moved = 0;
        if streams {
            let st = self.dev.submit(status_pipe, tag, status_phys, IU_STATUS_LEN);
            let dt = (len > 0).then(|| self.dev.submit(data_pipe, tag, io.bounce.phys(), len));
            let ct = self.dev.submit(cmd_pipe, 0, io.wrap.phys(), iu.len());
            self.dev.finish(ct, iu.len(), TRANSFER_TIMEOUT_MS).map_err(|_| fail("command pipe"))?;
            self.dev.finish(st, IU_STATUS_LEN, TRANSFER_TIMEOUT_MS).map_err(|_| fail("no status"))?;
            if let Some(dt) = dt {
                moved = self.dev.finish(dt, len, TRANSFER_TIMEOUT_MS).map_err(|_| fail("data"))?;
            }
        } else {
            let ct = self.dev.submit(cmd_pipe, 0, io.wrap.phys(), iu.len());
            self.dev.finish(ct, iu.len(), TRANSFER_TIMEOUT_MS).map_err(|_| fail("command pipe"))?;
            loop {
                let st = self.dev.submit(status_pipe, 0, status_phys, IU_STATUS_LEN);
                self.dev.finish(st, IU_STATUS_LEN, TRANSFER_TIMEOUT_MS).map_err(|_| fail("no status"))?;
                match io.wrap.read::<u8>(IU_STATUS) {
                    IU_READ_READY | IU_WRITE_READY if len > 0 => {
                        let dt = self.dev.submit(data_pipe, 0, io.bounce.phys(), len);
                        moved = self.dev.finish(dt, len, TRANSFER_TIMEOUT_MS).map_err(|_| fail("data"))?;
                    }
                    _ => break,
                }
            }
        }
        // The Sense IU (UAS-2 §6.2.3): status at 6, sense data length at
        // 14 (big-endian), the sense data from 16.
        let mut st = [0u8; IU_STATUS_LEN];
        io.wrap.copy_out(IU_STATUS, &mut st);
        match st[0] {
            IU_SENSE => {}
            IU_RESPONSE => return Err(fail(&alloc::format!("response code {:#x}", st[7]))),
            other => return Err(fail(&alloc::format!("unexpected IU {other:#x}"))),
        }
        if u16::from_be_bytes([st[2], st[3]]) != tag {
            return Err(fail("the status is for another tag"));
        }
        if st[6] != 0 {
            // Fixed format sense data (SPC-4 §4.5.3): key in byte 2, ASC
            // in byte 12.
            io.sense = (st[16 + 2] & 0xF, st[16 + 12]);
            return Err(IoError);
        }
        if dir_in && let Data::In(b) = data {
            io.bounce.copy_out(0, &mut b[..moved]);
        }
        Ok(moved)
    }

    /// One Bulk-Only command: CBW, data stage, CSW (BOT §5).
    fn bot_command(
        &self,
        io: &mut Io,
        (bulk_in, in_addr): (&Arc<Endpoint>, u8),
        (bulk_out, out_addr): (&Arc<Endpoint>, u8),
        cdb: &[u8],
        data: Data<'_>,
    ) -> Result<usize, IoError> {
        let (len, dir_in) = match &data {
            Data::None => (0, false),
            Data::In(b) => (b.len(), true),
            Data::Out(b) => (b.len(), false),
        };
        io.tag = io.tag.wrapping_add(1);
        let mut cbw = [0u8; 31];
        cbw[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
        cbw[4..8].copy_from_slice(&io.tag.to_le_bytes());
        cbw[8..12].copy_from_slice(&(len as u32).to_le_bytes());
        cbw[12] = if dir_in { 0x80 } else { 0 };
        cbw[14] = cdb.len() as u8;
        cbw[15..15 + cdb.len()].copy_from_slice(cdb);
        io.wrap.copy_in(0, &cbw);
        if self.bulk(bulk_out, out_addr, io.wrap.phys(), 31).is_err() {
            self.reset_recovery();
            return Err(IoError);
        }
        let mut moved = 0;
        match data {
            Data::None => {}
            Data::In(b) => {
                if let Ok(n) = self.bulk(bulk_in, in_addr, io.bounce.phys(), b.len()) {
                    io.bounce.copy_out(0, &mut b[..n]);
                    moved = n;
                }
            }
            Data::Out(b) => {
                io.bounce.copy_in(0, b);
                if let Ok(n) = self.bulk(bulk_out, out_addr, io.bounce.phys(), b.len()) {
                    moved = n;
                }
            }
        }
        // The status, once more after a stall (BOT §6.7.2).
        let csw = io.wrap.phys() + 64;
        let got = match self.bulk(bulk_in, in_addr, csw, 13) {
            Err(CC_STALL) => self.bulk(bulk_in, in_addr, csw, 13),
            r => r,
        };
        let mut status = [0u8; 13];
        io.wrap.copy_out(64, &mut status);
        let sig = u32::from_le_bytes(status[0..4].try_into().unwrap());
        let tag = u32::from_le_bytes(status[4..8].try_into().unwrap());
        if got != Ok(13) || sig != CSW_SIGNATURE || tag != io.tag || status[12] == 2 {
            log_warn!("{}: no valid status for command {:#x}", self.name, cdb[0]);
            self.reset_recovery();
            return Err(IoError);
        }
        if status[12] != 0 {
            return Err(IoError);
        }
        Ok(moved)
    }

    /// Bulk-Only Mass Storage Reset, then clear both halts (BOT §5.3.4).
    fn reset_recovery(&self) {
        const BOMS_RESET: u8 = 0xFF;
        let Transport::Bot { bulk_in, bulk_out, in_addr, out_addr } = &self.transport else { return };
        let _ = self.dev.control(super::RT_CLASS_INTERFACE_OUT, BOMS_RESET, 0, 0, &mut []);
        self.dev.clear_halt(bulk_in, *in_addr);
        self.dev.clear_halt(bulk_out, *out_addr);
    }

    /// The sense key and ASC of the last failed command: UAS sent them in
    /// its Sense IU; Bulk-Only asks with REQUEST SENSE.
    fn sense(&self, io: &mut Io) -> (u8, u8) {
        if matches!(self.transport, Transport::Uas { .. }) {
            return core::mem::take(&mut io.sense);
        }
        let mut s = [0u8; 18];
        match self.command(io, &[REQUEST_SENSE, 0, 0, 0, 18, 0], Data::In(&mut s)) {
            Ok(_) => (s[2] & 0xF, s[12]),
            Err(_) => (0xFF, 0),
        }
    }

    fn rw(&self, lba: u64, count: usize, data: Data<'_>) -> Result<usize, IoError> {
        let write = matches!(data, Data::Out(_));
        let mut io = self.io.lock();
        let mut cdb = [0u8; 16];
        let cdb: &[u8] = if lba + count as u64 <= u64::from(u32::MAX) {
            cdb[0] = if write { WRITE_10 } else { READ_10 };
            cdb[2..6].copy_from_slice(&(lba as u32).to_be_bytes());
            cdb[7..9].copy_from_slice(&(count as u16).to_be_bytes());
            &cdb[..10]
        } else {
            cdb[0] = if write { WRITE_16 } else { READ_16 };
            cdb[2..10].copy_from_slice(&lba.to_be_bytes());
            cdb[10..14].copy_from_slice(&(count as u32).to_be_bytes());
            &cdb[..16]
        };
        let r = self.command(&mut io, cdb, data);
        if r.is_err() {
            let (key, asc) = self.sense(&mut io);
            log_warn!(
                "{}: {} at {lba} failed (sense key {key:#x}, ASC {asc:#x})",
                self.name,
                if write { "write" } else { "read" }
            );
        }
        r
    }

    /// Byte-granular transfer in whole logical blocks; partly covered
    /// blocks are read first when writing.
    fn transfer(&self, pos: u64, buf: *mut u8, len: usize, write: bool) -> Result<(), IoError> {
        let blk = self.block as u64;
        if len % 512 != 0 || (pos + len as u64).div_ceil(blk) > self.blocks {
            return Err(IoError);
        }
        let chunk = (BOUNCE as u64 / blk).max(1);
        let end = pos + len as u64;
        let mut tmp = alloc::vec![0u8; BOUNCE];
        let mut lba = pos / blk;
        while lba * blk < end {
            let n = chunk.min(end.div_ceil(blk) - lba);
            let (cstart, cend) = (lba * blk, (lba + n) * blk);
            let (from, to) = (pos.max(cstart), end.min(cend));
            let at = (from - cstart) as usize;
            let bytes = (to - from) as usize;
            let total = (n * blk) as usize;
            // SAFETY: `from - pos + bytes <= len`: inside the caller's buffer.
            let user = unsafe { buf.add((from - pos) as usize) };
            if write {
                if from != cstart || to != cend {
                    self.rw(lba, n as usize, Data::In(&mut tmp[..total]))?;
                }
                // SAFETY: As above.
                tmp[at..at + bytes].copy_from_slice(unsafe { core::slice::from_raw_parts(user, bytes) });
                self.rw(lba, n as usize, Data::Out(&tmp[..total]))?;
            } else {
                if self.rw(lba, n as usize, Data::In(&mut tmp[..total]))? != total {
                    return Err(IoError);
                }
                // SAFETY: As above.
                unsafe { core::slice::from_raw_parts_mut(user, bytes) }.copy_from_slice(&tmp[at..at + bytes]);
            }
            lba += n;
        }
        Ok(())
    }
}

impl BlockDevice for UsbDisk {
    fn name(&self) -> &str {
        &self.name
    }
    fn sectors(&self) -> u64 {
        self.blocks * (self.block as u64 / 512)
    }
    fn read_only(&self) -> bool {
        false
    }
    fn read(&self, sector: u64, buf: &mut [u8]) -> Result<(), IoError> {
        self.transfer(sector * 512, buf.as_mut_ptr(), buf.len(), false)
    }
    fn write(&self, sector: u64, buf: &[u8]) -> Result<(), IoError> {
        self.transfer(sector * 512, buf.as_ptr().cast_mut(), buf.len(), true)
    }
    fn flush(&self) -> Result<(), IoError> {
        let mut io = self.io.lock();
        // Devices without a cache may refuse; that is not a failure.
        let _ = self.command(&mut io, &[SYNCHRONIZE_CACHE_10, 0, 0, 0, 0, 0, 0, 0, 0, 0], Data::None);
        Ok(())
    }
    fn model(&self) -> String {
        self.model.clone()
    }
    fn removable(&self) -> bool {
        self.removable
    }
    fn power_off(&self) -> Option<Result<(), IoError>> {
        {
            let mut io = self.io.lock();
            // Devices without a cache, or a medium to eject, may refuse
            // either; neither stops the device from going.
            let _ = self.command(&mut io, &[SYNCHRONIZE_CACHE_10, 0, 0, 0, 0, 0, 0, 0, 0, 0], Data::None);
            let _ = self.command(&mut io, &[START_STOP_UNIT, 0, 0, 0, STOP_AND_EJECT, 0], Data::None);
        }
        log_info!("USB port {}: {} powered off", self.dev.port, self.name);
        Some(if super::xhci::request_removal(&self.dev, 5000) { Ok(()) } else { Err(IoError) })
    }
}

fn ascii(b: &[u8]) -> String {
    String::from(String::from_utf8_lossy(b).trim())
}

/// The UAS alternate setting of interface `number` (protocol 62h, UAS
/// 1.0 §5.3), with its four pipes in order: command, status, data in,
/// data out.
fn uas_setting(config: &slate_usb::Configuration, number: u8) -> Option<(u8, [EndpointDesc; 4])> {
    let alt = config.interfaces.iter().find(|i| i.number == number && i.class == 8 && i.protocol == 0x62)?;
    let pipe = |id: u8| alt.endpoints.iter().find(|e| e.pipe == id).map(EndpointDesc::from);
    let pipes = [
        pipe(slate_usb::PIPE_COMMAND)?,
        pipe(slate_usb::PIPE_STATUS)?,
        pipe(slate_usb::PIPE_DATA_IN)?,
        pipe(slate_usb::PIPE_DATA_OUT)?,
    ];
    Some((alt.alt, pipes))
}

/// SET_INTERFACE (USB 2.0 §9.4.10): standard, interface recipient.
const RT_INTERFACE_OUT: u8 = 0x01;
const REQ_SET_INTERFACE: u8 = 0x0B;

/// Choose how to talk to the device: UAS when it offers it (and the
/// controller gives a SuperSpeed device its streams), else Bulk-Only.
fn transport(dev: &Arc<UsbDevice>, iface: &InterfaceDesc, config: &slate_usb::Configuration) -> Option<Transport> {
    if crate::drivers::enabled("usb-uas")
        && let Some((alt, pipes)) = uas_setting(config, iface.number)
    {
        let streams = dev.speed >= SPEED_SUPER;
        let set = dev.control(RT_INTERFACE_OUT, REQ_SET_INTERFACE, u16::from(alt), u16::from(iface.number), &mut []);
        let rings = set.ok().and_then(|_| dev.configure_streams(&pipes, if streams { UAS_STREAMS } else { 0 }));
        match rings {
            Some(r) if !streams || r[1..].iter().all(|e| !e.streams.is_empty()) => {
                log_info!("USB port {}: UAS{}", dev.port, if streams { " with streams" } else { "" });
                return Some(Transport::Uas {
                    command: r[0].clone(),
                    status: r[1].clone(),
                    data_in: r[2].clone(),
                    data_out: r[3].clone(),
                    streams,
                });
            }
            _ => {
                log_warn!("USB port {}: UAS could not be set up; using Bulk-Only", dev.port);
                let _ = dev.control(RT_INTERFACE_OUT, REQ_SET_INTERFACE, 0, u16::from(iface.number), &mut []);
            }
        }
    }
    if iface.protocol != 0x50 {
        let pipes: alloc::vec::Vec<(u8, u8, u8)> = config
            .interfaces
            .iter()
            .filter(|i| i.number == iface.number)
            .flat_map(|i| i.endpoints.iter().map(move |e| (i.alt, e.address, e.pipe)))
            .collect();
        log_warn!(
            "USB port {}: mass storage protocol {:#x} without a usable UAS setting (alt, endpoint, pipe: {pipes:x?}); not supported",
            dev.port,
            iface.protocol
        );
        return None;
    }
    let find = |inward: bool| iface.endpoints.iter().find(|e| e.kind == EP_BULK && e.is_in() == inward).copied();
    let (Some(i), Some(o)) = (find(true), find(false)) else { return None };
    let eps: [EndpointDesc; 2] = [i, o];
    let rings = dev.configure(&eps)?;
    Some(Transport::Bot {
        bulk_in: rings[0].clone(),
        bulk_out: rings[1].clone(),
        in_addr: i.address,
        out_addr: o.address,
    })
}

/// Set up a SCSI device on LUN 0 (UAS or Bulk-Only) and register it as a
/// disk.
pub fn start(dev: &Arc<UsbDevice>, iface: &InterfaceDesc, config: &slate_usb::Configuration) {
    let Some(transport) = transport(dev, iface, config) else { return };
    let (Some(wrap), Some(bounce)) = (Dma::new(4096), Dma::new(BOUNCE)) else { return };
    let mut disk = UsbDisk {
        // Named when it is registered (block::register_named).
        name: format!("usb-{}", dev.port),
        model: String::new(),
        dev: dev.clone(),
        transport,
        io: Mutex::new(Io { wrap, bounce, tag: 0, sense: (0, 0) }),
        block: 512,
        blocks: 0,
        removable: true,
    };
    let mut inq = [0u8; 36];
    {
        let mut io = disk.io.lock();
        if disk.command(&mut io, &[INQUIRY, 0, 0, 0, 36, 0], Data::In(&mut inq)).is_err() {
            log_warn!("USB port {}: storage does not answer INQUIRY", dev.port);
            return;
        }
        // A device that is still spinning up says "not ready" for a while.
        let mut ready = false;
        for _ in 0..50 {
            if disk.command(&mut io, &[TEST_UNIT_READY, 0, 0, 0, 0, 0], Data::None).is_ok() {
                ready = true;
                break;
            }
            let _ = disk.sense(&mut io);
            delay_ms(100);
        }
        if !ready {
            log_warn!("USB port {}: storage never became ready", dev.port);
            return;
        }
        let mut cap = [0u8; 8];
        if disk.command(&mut io, &[READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0], Data::In(&mut cap)).is_err() {
            return;
        }
        let last = u32::from_be_bytes(cap[0..4].try_into().unwrap());
        disk.block = u32::from_be_bytes(cap[4..8].try_into().unwrap()) as usize;
        disk.blocks = u64::from(last) + 1;
        if last == u32::MAX {
            let mut cap16 = [0u8; 32];
            let mut cdb = [0u8; 16];
            cdb[0] = SERVICE_ACTION_IN_16;
            cdb[1] = READ_CAPACITY_16;
            cdb[13] = 32;
            if disk.command(&mut io, &cdb, Data::In(&mut cap16)).is_err() {
                return;
            }
            disk.blocks = u64::from_be_bytes(cap16[0..8].try_into().unwrap()) + 1;
            disk.block = u32::from_be_bytes(cap16[8..12].try_into().unwrap()) as usize;
        }
    }
    if !disk.block.is_power_of_two() || !(512..=BOUNCE / 2).contains(&disk.block) {
        log_warn!("USB port {}: {}-byte blocks are not supported", dev.port, disk.block);
        return;
    }
    disk.removable = inq[1] & 0x80 != 0;
    disk.model = format!("{} {}", ascii(&inq[8..16]), ascii(&inq[16..32])).trim().into();
    let (model, mib, removable) = (disk.model.clone(), (disk.blocks * disk.block as u64) >> 20, disk.removable);
    let driver = if matches!(disk.transport, Transport::Uas { .. }) { "usb-uas" } else { "usb-storage" };
    let mut name = String::new();
    block::register_named(Family::Scsi, |n| {
        name = n.clone();
        disk.name = n;
        Arc::new(disk)
    });
    log_info!(
        "USB port {}: /dev/{name}, \"{model}\", {mib} MiB{}",
        dev.port,
        if removable { ", removable" } else { "" }
    );
    DISKS.lock().push((Arc::downgrade(dev), name));
    dev.bound(iface.number, driver);
}

/// Disks of USB devices, by device, so an unplugged one's go too.
static DISKS: crate::sync::IrqSpinLock<alloc::vec::Vec<(alloc::sync::Weak<UsbDevice>, String)>> =
    crate::sync::IrqSpinLock::new(alloc::vec::Vec::new());

/// USB device `dev` was unplugged: its disks leave /dev and /sys (I/O on
/// them already fails, `UsbDevice::gone`).
pub fn detached(dev: &Arc<UsbDevice>) {
    let names: alloc::vec::Vec<String> = {
        let mut disks = DISKS.lock();
        let (gone, kept): (alloc::vec::Vec<_>, alloc::vec::Vec<_>) =
            disks.drain(..).partition(|(d, _)| d.upgrade().is_none_or(|d| Arc::ptr_eq(&d, dev)));
        *disks = kept;
        gone.into_iter().map(|(_, n)| n).collect()
    };
    for n in names {
        block::unregister_disk(&n);
    }
}
