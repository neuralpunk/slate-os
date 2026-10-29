// SPDX-License-Identifier: MIT OR Apache-2.0

//! Virtio devices over PCI (OASIS VIRTIO 1.2): the modern PCI transport
//! (§4.1) and split virtqueues (§2.7). Only the version 1 interface is
//! used; legacy-only devices are ignored.

pub mod blk;
pub mod gpu;
pub mod input;
pub mod net;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};

use super::pci::{CAP_VENDOR, Device};
use crate::log_warn;
use crate::mm::{PhysAddr, frame};
use crate::sched::wait::WaitQueue;
use crate::sync::IrqSpinLock;

pub const VENDOR: u16 = 0x1AF4;
/// Device types (§5).
pub const ID_NET: u16 = 1;
pub const ID_BLOCK: u16 = 2;
/// GPU device (§5.7).
pub const ID_GPU: u16 = 16;
/// Input device (§5.8).
pub const ID_INPUT: u16 = 18;

/// Feature bits (§6).
pub const F_VERSION_1: u64 = 1 << 32;

// Device status bits (§2.1).
const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_FAILED: u8 = 128;

// PCI capability types (§4.1.4).
const CFG_COMMON: u8 = 1;
const CFG_NOTIFY: u8 = 2;
const CFG_ISR: u8 = 3;
const CFG_DEVICE: u8 = 4;

// Common configuration layout (§4.1.4.3).
const DEVICE_FEATURE_SELECT: usize = 0x00;
const DEVICE_FEATURE: usize = 0x04;
const DRIVER_FEATURE_SELECT: usize = 0x08;
const DRIVER_FEATURE: usize = 0x0C;
const CONFIG_MSIX_VECTOR: usize = 0x10;
const DEVICE_STATUS: usize = 0x14;
const CONFIG_GENERATION: usize = 0x15;
const QUEUE_SELECT: usize = 0x16;
const QUEUE_SIZE: usize = 0x18;
const QUEUE_MSIX_VECTOR: usize = 0x1A;
const QUEUE_ENABLE: usize = 0x1C;
const QUEUE_NOTIFY_OFF: usize = 0x1E;
const QUEUE_DESC: usize = 0x20;
const QUEUE_DRIVER: usize = 0x28;
const QUEUE_DEVICE: usize = 0x30;
const NO_VECTOR: u16 = 0xFFFF;

/// The device type of a virtio PCI function (§4.1.2): modern IDs are
/// 0x1040 + type; transitional ones map through the subsystem ID, which for
/// the devices Slate drives equals the type.
pub fn device_type(d: &Device) -> Option<u16> {
    if d.vendor != VENDOR {
        return None;
    }
    match d.device {
        0x1040..=0x107F => Some(d.device - 0x1040),
        0x1000..=0x103F => Some(d.read16(0x2E)),
        _ => None,
    }
}

/// A register window inside a BAR.
#[derive(Clone, Copy)]
struct Window(*mut u8);

impl Window {
    fn at(self, off: usize) -> *mut u8 {
        // SAFETY: Callers stay inside the window the capability describes.
        unsafe { self.0.add(off) }
    }
    fn r8(self, off: usize) -> u8 {
        // SAFETY: Device register inside a mapped BAR.
        unsafe { self.at(off).read_volatile() }
    }
    fn w8(self, off: usize, v: u8) {
        // SAFETY: As above.
        unsafe { self.at(off).write_volatile(v) }
    }
    fn r16(self, off: usize) -> u16 {
        // SAFETY: As above.
        unsafe { self.at(off).cast::<u16>().read_volatile() }
    }
    fn w16(self, off: usize, v: u16) {
        // SAFETY: As above.
        unsafe { self.at(off).cast::<u16>().write_volatile(v) }
    }
    fn r32(self, off: usize) -> u32 {
        // SAFETY: As above.
        unsafe { self.at(off).cast::<u32>().read_volatile() }
    }
    fn w32(self, off: usize, v: u32) {
        // SAFETY: As above.
        unsafe { self.at(off).cast::<u32>().write_volatile(v) }
    }
    fn w64(self, off: usize, v: u64) {
        // 64-bit fields are written as two 32-bit halves (§4.1.3.1).
        self.w32(off, v as u32);
        self.w32(off + 4, (v >> 32) as u32);
    }
}

/// The modern PCI transport of one device.
pub struct Transport {
    pub pci: Arc<Device>,
    common: Window,
    notify: Window,
    notify_multiplier: u32,
    device_cfg: Window,
}

// SAFETY: The windows point at device registers mapped for the kernel's
// whole life; register accesses are volatile.
unsafe impl Send for Transport {}
// SAFETY: As above.
unsafe impl Sync for Transport {}

impl Transport {
    /// Find the transport's register windows (§4.1.4).
    pub fn new(pci: Arc<Device>) -> Option<Transport> {
        let (mut common, mut notify, mut device_cfg, mut mult) = (None, None, None, 0);
        for (_, off) in pci.capabilities().into_iter().filter(|&(id, _)| id == CAP_VENDOR) {
            let kind = pci.read8(off + 3);
            let bar = usize::from(pci.read8(off + 4));
            let offset = pci.read32(off + 8) as usize;
            let Some(base) = pci.map_bar(bar) else { continue };
            // SAFETY: The capability places the window inside the BAR.
            let w = Window(unsafe { base.add(offset) });
            match kind {
                CFG_COMMON if common.is_none() => common = Some(w),
                CFG_NOTIFY if notify.is_none() => {
                    notify = Some(w);
                    mult = pci.read32(off + 16);
                }
                CFG_DEVICE if device_cfg.is_none() => device_cfg = Some(w),
                CFG_ISR => {}
                _ => {}
            }
        }
        pci.enable();
        Some(Transport { pci, common: common?, notify: notify?, notify_multiplier: mult, device_cfg: device_cfg? })
    }

    fn set_status(&self, bits: u8) {
        let s = self.common.r8(DEVICE_STATUS);
        self.common.w8(DEVICE_STATUS, s | bits);
    }

    /// Reset the device and negotiate features (§3.1.1): the result is the
    /// subset of `wanted` the device offers, which must include VERSION_1.
    pub fn init(&self, wanted: u64) -> Option<u64> {
        self.common.w8(DEVICE_STATUS, 0);
        while self.common.r8(DEVICE_STATUS) != 0 {
            core::hint::spin_loop();
        }
        self.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER);
        let mut offered = 0u64;
        for half in 0..2 {
            self.common.w32(DEVICE_FEATURE_SELECT, half);
            offered |= u64::from(self.common.r32(DEVICE_FEATURE)) << (32 * half);
        }
        let accepted = offered & (wanted | F_VERSION_1);
        if accepted & F_VERSION_1 == 0 {
            self.set_status(STATUS_FAILED);
            return None;
        }
        for half in 0..2 {
            self.common.w32(DRIVER_FEATURE_SELECT, half);
            self.common.w32(DRIVER_FEATURE, (accepted >> (32 * half)) as u32);
        }
        self.set_status(STATUS_FEATURES_OK);
        if self.common.r8(DEVICE_STATUS) & STATUS_FEATURES_OK == 0 {
            self.set_status(STATUS_FAILED);
            return None;
        }
        Some(accepted)
    }

    /// Finish initialization: the device may now use its queues.
    pub fn driver_ok(&self) {
        self.set_status(STATUS_DRIVER_OK);
    }

    /// Read device-specific configuration, retrying if the device changed it
    /// meanwhile (§2.5.1).
    pub fn config<T>(&self, f: impl Fn(&dyn Fn(usize) -> u32) -> T) -> T {
        loop {
            let before = self.common.r8(CONFIG_GENERATION);
            let cfg = self.device_cfg;
            let v = f(&|off| cfg.r32(off));
            if self.common.r8(CONFIG_GENERATION) == before {
                return v;
            }
        }
    }

    /// Byte access to device-specific configuration (virtio-input selects
    /// what it shows by writing two bytes).
    pub fn config_r8(&self, off: usize) -> u8 {
        self.device_cfg.r8(off)
    }
    pub fn config_w8(&self, off: usize, v: u8) {
        self.device_cfg.w8(off, v);
    }

    /// Set up queue `index` with at most `max_size` entries, interrupting
    /// through MSI-X table entry `msix_entry` if given.
    pub fn setup_queue(&self, index: u16, max_size: u16, msix_entry: Option<u16>) -> Option<Virtqueue> {
        self.common.w16(QUEUE_SELECT, index);
        let device_max = self.common.r16(QUEUE_SIZE);
        if device_max == 0 {
            return None;
        }
        // Sizes need not be powers of two in split queues, but keep them so.
        let mut size = device_max.min(max_size).min(256);
        while !size.is_power_of_two() {
            size &= size - 1;
        }
        let q = Virtqueue::alloc(size)?;
        self.common.w16(QUEUE_SIZE, size);
        self.common.w64(QUEUE_DESC, q.desc_phys.0);
        self.common.w64(QUEUE_DRIVER, q.avail_phys.0);
        self.common.w64(QUEUE_DEVICE, q.used_phys.0);
        self.common.w16(QUEUE_MSIX_VECTOR, msix_entry.unwrap_or(NO_VECTOR));
        if msix_entry.is_some() && self.common.r16(QUEUE_MSIX_VECTOR) == NO_VECTOR {
            log_warn!("virtio {:?}: queue {index} rejected its MSI-X vector", self.pci.address);
        }
        let notify_off = usize::from(self.common.r16(QUEUE_NOTIFY_OFF));
        let notify = self.notify.at(notify_off * self.notify_multiplier as usize);
        self.common.w16(QUEUE_ENABLE, 1);
        Some(Virtqueue { notify, index, ..q })
    }

    /// No interrupt for configuration changes.
    pub fn no_config_interrupt(&self) {
        self.common.w16(CONFIG_MSIX_VECTOR, NO_VECTOR);
    }

    /// Configuration changes interrupt through MSI-X table entry `entry`
    /// (§4.1.5.1.2); false if the device refused it.
    pub fn config_interrupt(&self, entry: u16) -> bool {
        self.common.w16(CONFIG_MSIX_VECTOR, entry);
        self.common.r16(CONFIG_MSIX_VECTOR) == entry
    }

    /// Write a 32-bit field of the device-specific configuration.
    pub fn config_w32(&self, off: usize, v: u32) {
        self.device_cfg.w32(off, v);
    }
}

// Descriptor flags (§2.7.5).
const DESC_NEXT: u16 = 1;
const DESC_WRITE: u16 = 2;

/// One buffer of a request: physical address, length, and whether the
/// device writes it.
#[derive(Clone, Copy, Debug)]
pub struct Segment {
    pub phys: PhysAddr,
    pub len: u32,
    pub device_writes: bool,
}

struct QueueState {
    free: Vec<u16>,
    /// Requests the device has finished: head descriptor → bytes written.
    /// In the order the device finished them (network frames must not be
    /// reordered).
    done: VecDeque<(u16, u32)>,
    last_used: u16,
    avail_idx: u16,
}

/// A split virtqueue: descriptor table, available ring and used ring, each
/// in its own zeroed page (§2.7: alignments 16, 2 and 4).
pub struct Virtqueue {
    size: u16,
    index: u16,
    desc_phys: PhysAddr,
    avail_phys: PhysAddr,
    used_phys: PhysAddr,
    notify: *mut u8,
    state: IrqSpinLock<QueueState>,
    waiters: WaitQueue,
    /// Interrupts are delivered (otherwise waiters poll). A waiter checks
    /// the used ring before it sleeps, so turning this on while requests
    /// are under way loses no completion.
    interrupts: core::sync::atomic::AtomicBool,
}

// SAFETY: The rings live in frames owned by the queue; all access to the
// shared parts goes through `state`'s lock or is a single volatile access.
unsafe impl Send for Virtqueue {}
// SAFETY: As above.
unsafe impl Sync for Virtqueue {}

impl Virtqueue {
    fn alloc(size: u16) -> Option<Virtqueue> {
        let page = || frame::alloc_zeroed();
        let (desc_phys, avail_phys, used_phys) = (page()?, page()?, page()?);
        Some(Virtqueue {
            size,
            index: 0,
            desc_phys,
            avail_phys,
            used_phys,
            notify: core::ptr::null_mut(),
            state: IrqSpinLock::new(QueueState {
                free: (0..size).rev().collect(),
                done: VecDeque::new(),
                last_used: 0,
                avail_idx: 0,
            }),
            waiters: WaitQueue::new(),
            interrupts: core::sync::atomic::AtomicBool::new(false),
        })
    }

    pub fn set_interrupts(&self, on: bool) {
        self.interrupts.store(on, core::sync::atomic::Ordering::Release);
    }

    fn desc(&self, i: u16) -> *mut u8 {
        // SAFETY: `i` < size, and the table holds `size` 16-byte descriptors.
        unsafe { self.desc_phys.to_virt().add(usize::from(i) * 16) }
    }

    fn avail(&self) -> *mut u16 {
        self.avail_phys.to_virt().cast()
    }

    fn used(&self) -> *mut u8 {
        self.used_phys.to_virt()
    }

    /// Move finished requests from the used ring into `done`.
    fn reap(&self, st: &mut QueueState) {
        // SAFETY: The used ring's `idx` field is written by the device.
        let used_idx = unsafe { self.used().add(2).cast::<u16>().read_volatile() };
        fence(Ordering::Acquire);
        while st.last_used != used_idx {
            let slot = usize::from(st.last_used % self.size);
            // SAFETY: Used ring entries are 8 bytes after the 4-byte header.
            let (id, len) = unsafe {
                let e = self.used().add(4 + slot * 8).cast::<u32>();
                (e.read_volatile(), e.add(1).read_volatile())
            };
            st.done.push_back((id as u16, len));
            st.last_used = st.last_used.wrapping_add(1);
        }
    }

    /// Called from the device's interrupt handler.
    pub fn interrupt(&self) {
        {
            let mut st = self.state.lock();
            self.reap(&mut st);
        }
        self.waiters.wake_all();
    }

    /// Submit a request made of `segs` and wait until the device has
    /// finished it; returns the number of bytes the device wrote.
    pub fn submit_and_wait(&self, segs: &[Segment]) -> u32 {
        assert!(!segs.is_empty() && segs.len() <= usize::from(self.size));
        let head = loop {
            let mut got = None;
            self.waiters.wait_until(|| {
                let mut st = self.state.lock();
                if st.free.len() >= segs.len() {
                    got = Some(self.push(&mut st, segs));
                    true
                } else {
                    self.reap(&mut st);
                    false
                }
            });
            if let Some(h) = got {
                break h;
            }
        };
        // SAFETY: Writing the queue index to its notify address (§4.1.4.4).
        unsafe { self.notify.cast::<u16>().write_volatile(self.index) };
        let mut len = 0;
        let mut finished = || {
            let mut st = self.state.lock();
            self.reap(&mut st);
            let found = st.done.iter().position(|&(h, _)| h == head).map(|i| st.done.remove(i).unwrap().1);
            match found {
                Some(l) => {
                    len = l;
                    self.release(&mut st, head);
                    true
                }
                None => false,
            }
        };
        if self.interrupts.load(core::sync::atomic::Ordering::Acquire) && crate::sched::can_block() {
            self.waiters.wait_until(finished);
        } else {
            while !finished() {
                core::hint::spin_loop();
            }
        }
        // Freed descriptors may let another submitter proceed.
        self.waiters.wake_all();
        len
    }

    /// Post a chain without waiting for it (queues whose completions are
    /// collected with [`Virtqueue::take_used`]). `None` when the queue is
    /// full. The device is not notified until [`Virtqueue::kick`].
    pub fn post(&self, segs: &[Segment]) -> Option<u16> {
        let mut st = self.state.lock();
        if st.free.len() < segs.len() {
            self.reap(&mut st);
            return None;
        }
        Some(self.push(&mut st, segs))
    }

    /// Notify the device of newly posted chains.
    pub fn kick(&self) {
        // SAFETY: Writing the queue index to its notify address (§4.1.4.4).
        unsafe { self.notify.cast::<u16>().write_volatile(self.index) };
    }

    /// Chains the device has finished, as (head, bytes written), with their
    /// descriptors freed.
    pub fn take_used(&self) -> Vec<(u16, u32)> {
        let mut st = self.state.lock();
        self.reap(&mut st);
        let done: Vec<(u16, u32)> = core::mem::take(&mut st.done).into();
        for &(h, _) in &done {
            self.release(&mut st, h);
        }
        done
    }

    /// Fill a descriptor chain and publish it in the available ring.
    fn push(&self, st: &mut QueueState, segs: &[Segment]) -> u16 {
        let ids: Vec<u16> = (0..segs.len()).map(|_| st.free.pop().unwrap()).collect();
        for (i, s) in segs.iter().enumerate() {
            let mut flags = if s.device_writes { DESC_WRITE } else { 0 };
            let next = ids.get(i + 1).copied().unwrap_or(0);
            if i + 1 < segs.len() {
                flags |= DESC_NEXT;
            }
            // SAFETY: Descriptor `ids[i]` is free and ours until released.
            unsafe {
                let d = self.desc(ids[i]);
                d.cast::<u64>().write_volatile(s.phys.0);
                d.add(8).cast::<u32>().write_volatile(s.len);
                d.add(12).cast::<u16>().write_volatile(flags);
                d.add(14).cast::<u16>().write_volatile(next);
            }
        }
        let slot = usize::from(st.avail_idx % self.size);
        // SAFETY: Available ring: flags, idx, then `size` entries.
        unsafe { self.avail().add(2 + slot).write_volatile(ids[0]) };
        fence(Ordering::Release);
        st.avail_idx = st.avail_idx.wrapping_add(1);
        // SAFETY: As above.
        unsafe { self.avail().add(1).write_volatile(st.avail_idx) };
        fence(Ordering::SeqCst);
        ids[0]
    }

    /// Return a finished chain's descriptors to the free list.
    fn release(&self, st: &mut QueueState, head: u16) {
        let mut i = head;
        loop {
            st.free.push(i);
            // SAFETY: `i` is a descriptor of the chain the device returned.
            let (flags, next) = unsafe {
                let d = self.desc(i);
                (d.add(12).cast::<u16>().read_volatile(), d.add(14).cast::<u16>().read_volatile())
            };
            if flags & DESC_NEXT == 0 {
                break;
            }
            i = next;
        }
    }
}

/// Split a kernel buffer into physically contiguous segments.
pub fn segments(buf: *const u8, len: usize, device_writes: bool, out: &mut Vec<Segment>) {
    let mut addr = buf as u64;
    let end = addr + len as u64;
    while addr < end {
        let page_end = (addr | 0xFFF) + 1;
        let n = (end.min(page_end) - addr) as u32;
        let phys = crate::mm::virt_to_phys(addr).expect("DMA buffer not mapped");
        match out.last_mut() {
            Some(s) if s.device_writes == device_writes && s.phys.0 + u64::from(s.len) == phys.0 => s.len += n,
            _ => out.push(Segment { phys, len: n, device_writes }),
        }
        addr += u64::from(n);
    }
}

/// Probe every virtio PCI function Slate has a driver for.
pub fn init() {
    super::probe_pci(super::Stage::Virtio);
}
