// SPDX-License-Identifier: MIT OR Apache-2.0

//! virtio-blk (VIRTIO 1.2 §5.2): one request queue, reads, writes, cache
//! flushes and discards in 512-byte sectors.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{Segment, Transport, Virtqueue, segments};
use crate::block::{self, BlockDevice, IoError};
use crate::drivers::pci::Device;
use crate::log_info;

// Feature bits (§5.2.3).
const F_SIZE_MAX: u64 = 1 << 1;
const F_SEG_MAX: u64 = 1 << 2;
const F_RO: u64 = 1 << 5;
const F_BLK_SIZE: u64 = 1 << 6;
const F_FLUSH: u64 = 1 << 9;
const F_DISCARD: u64 = 1 << 13;

// Request types and status values (§5.2.6).
const T_IN: u32 = 0;
const T_OUT: u32 = 1;
const T_FLUSH: u32 = 4;
const T_DISCARD: u32 = 11;
const S_OK: u8 = 0;

/// Largest request Slate sends, in bytes.
const MAX_REQUEST: usize = 128 * 1024;

pub struct VirtioBlk {
    name: String,
    /// Owns the register windows the queue notifies through.
    _transport: Transport,
    queue: Virtqueue,
    sectors: u64,
    read_only: bool,
    flush: bool,
    /// Most data segments per request.
    seg_max: usize,
    /// Most sectors one discard request covers (0: no discards).
    max_discard: u64,
}

/// One range of a discard request (`struct virtio_blk_discard_write_zeroes`,
/// §5.2.6).
#[repr(C)]
struct DiscardRange {
    sector: u64,
    sectors: u32,
    flags: u32,
}

#[repr(C)]
struct Header {
    kind: u32,
    reserved: u32,
    sector: u64,
}

impl VirtioBlk {
    fn request(&self, kind: u32, sector: u64, data: Option<(*const u8, usize)>) -> Result<(), IoError> {
        // The header and status byte live on the heap (direct map), so
        // their physical addresses are contiguous.
        let header = Box::new(Header { kind, reserved: 0, sector });
        let mut status = Box::new(0xFFu8);
        let mut segs = Vec::with_capacity(4);
        segs.push(Segment {
            phys: crate::mm::virt_to_phys(&*header as *const Header as u64).ok_or(IoError)?,
            len: 16,
            device_writes: false,
        });
        if let Some((p, len)) = data {
            segments(p, len, kind == T_IN, &mut segs);
            if segs.len() - 1 > self.seg_max {
                return Err(IoError);
            }
        }
        segs.push(Segment {
            phys: crate::mm::virt_to_phys(&mut *status as *mut u8 as u64).ok_or(IoError)?,
            len: 1,
            device_writes: true,
        });
        self.queue.submit_and_wait(&segs);
        // SAFETY: The device wrote the status byte before returning the chain.
        let st = unsafe { core::ptr::read_volatile(&*status) };
        if st == S_OK { Ok(()) } else { Err(IoError) }
    }

    fn transfer(&self, sector: u64, buf: *const u8, len: usize, write: bool) -> Result<(), IoError> {
        if len % 512 != 0 || sector + (len / 512) as u64 > self.sectors {
            return Err(IoError);
        }
        if write && self.read_only {
            return Err(IoError);
        }
        // Each page of the buffer can be its own segment.
        let chunk = MAX_REQUEST.min(self.seg_max.saturating_sub(1).max(1) * 4096);
        let mut done = 0;
        while done < len {
            let n = (len - done).min(chunk);
            // SAFETY: `done + n <= len`, inside the caller's buffer.
            let p = unsafe { buf.add(done) };
            self.request(if write { T_OUT } else { T_IN }, sector + (done / 512) as u64, Some((p, n)))?;
            done += n;
        }
        Ok(())
    }
}

impl BlockDevice for VirtioBlk {
    fn name(&self) -> &str {
        &self.name
    }
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read_only(&self) -> bool {
        self.read_only
    }
    fn read(&self, sector: u64, buf: &mut [u8]) -> Result<(), IoError> {
        self.transfer(sector, buf.as_mut_ptr(), buf.len(), false)
    }
    fn write(&self, sector: u64, buf: &[u8]) -> Result<(), IoError> {
        self.transfer(sector, buf.as_ptr(), buf.len(), true)
    }
    fn flush(&self) -> Result<(), IoError> {
        if self.flush { self.request(T_FLUSH, 0, None) } else { Ok(()) }
    }
    fn can_discard(&self) -> bool {
        self.max_discard > 0 && !self.read_only
    }
    fn discard(&self, sector: u64, count: u64) -> Result<(), IoError> {
        if !self.can_discard() || sector.checked_add(count).is_none_or(|end| end > self.sectors) {
            return Err(IoError);
        }
        let mut done = 0;
        while done < count {
            let n = (count - done).min(self.max_discard);
            let range = Box::new(DiscardRange { sector: sector + done, sectors: n as u32, flags: 0 });
            let p = &*range as *const DiscardRange as *const u8;
            self.request(T_DISCARD, 0, Some((p, core::mem::size_of::<DiscardRange>())))?;
            done += n;
        }
        Ok(())
    }
}

/// Bring up one virtio-blk device and register it as a disk.
pub fn probe(pci: Arc<Device>) -> Option<()> {
    let transport = Transport::new(pci)?;
    let features = transport.init(F_SIZE_MAX | F_SEG_MAX | F_RO | F_BLK_SIZE | F_FLUSH | F_DISCARD)?;
    // The configuration (§5.2.4): capacity at 0, seg_max at 12,
    // max_discard_sectors at 36.
    let (sectors, seg_max, max_discard) =
        transport.config(|r| (u64::from(r(0)) | (u64::from(r(4)) << 32), r(12), r(36)));
    let max_discard =
        if features & F_DISCARD != 0 { u64::from(max_discard.max(1)).min(u64::from(u32::MAX)) } else { 0 };
    let seg_max = if features & F_SEG_MAX != 0 { (seg_max as usize).max(1) } else { 1 };

    // One MSI-X vector for the request queue; polling if that fails.
    let slot: Arc<slate_sync::Once<Arc<VirtioBlk>>> = Arc::new(slate_sync::Once::new());
    let irq_slot = slot.clone();
    let vector = crate::arch::irq::alloc_vector(
        "virtio-blk",
        Box::new(move || {
            if let Some(d) = irq_slot.get() {
                d.queue.interrupt();
            }
        }),
    );
    let msix = vector.and_then(|v| transport.pci.enable_msix(&[v], crate::arch::irq::device_irq_target()));
    transport.no_config_interrupt();
    let queue = transport.setup_queue(0, 128, msix.map(|_| 0))?;
    queue.set_interrupts(msix.is_some());
    transport.driver_ok();

    let name = block::next_name(block::Family::Virtio);
    log_info!(
        "virtio-blk {:?}: /dev/{name}, {} MiB{}{}, {} segments per request, {}",
        transport.pci.address,
        sectors / 2048,
        if features & F_RO != 0 { " read-only" } else { "" },
        if max_discard > 0 { ", discards" } else { "" },
        seg_max,
        if msix.is_some() { "MSI-X" } else { "polled" }
    );
    let dev = Arc::new(VirtioBlk {
        name,
        _transport: transport,
        queue,
        sectors,
        read_only: features & F_RO != 0,
        flush: features & F_FLUSH != 0,
        seg_max: seg_max.min(64),
        max_discard,
    });
    slot.call_once(|| dev.clone());
    block::register_disk(dev, block::Family::Virtio);
    Some(())
}
