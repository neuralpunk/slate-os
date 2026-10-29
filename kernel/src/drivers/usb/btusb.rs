// SPDX-License-Identifier: MIT OR Apache-2.0

//! USB Bluetooth controllers (ADR 0113): the HCI transport of the
//! Bluetooth Core Specification 5.4, Vol 4, Part B. A primary controller
//! is interface class 0xE0, subclass 0x01, protocol 0x01; it takes HCI
//! commands on the control endpoint (class request 0x00 to the device),
//! gives events on its interrupt IN endpoint and carries ACL data on its
//! bulk endpoints. (SCO, on the isochronous interface, is not driven.)
//!
//! The controller appears as /dev/hci0 (misc major 10, minor 240 on: the
//! local-use range of devices.txt), for Slate's Bluetooth daemon, which
//! holds the host stack. One program opens it at a time. Packets go both
//! ways framed as on the UART transport (Vol 4, Part A): a type byte, 0x01
//! command or 0x02 ACL written, 0x04 event or 0x02 ACL read, then the
//! packet. A read returns one whole packet. Events and ACL packets that
//! span several USB packets are put back together by their own length
//! fields.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::xhci::{CC_SHORT_PACKET, CC_SUCCESS, Endpoint, UsbDevice};
use super::{EP_BULK, EP_INTERRUPT, EndpointDesc, InterfaceDesc};
use crate::abi::linux::errno::*;
use crate::drivers::dma::Dma;
use crate::fs::vfs::{self, Metadata, Result};
use crate::fs::{CharNode, File, O_NONBLOCK, POLLERR, POLLHUP, POLLIN, POLLOUT, SysEntry};
use crate::sched::wait::WaitQueue;
use crate::sync::IrqSpinLock;
use crate::{log_info, log_warn};

/// /dev/hciN: misc major, minors from 240 (devices.txt's local use).
pub const HCI_MINOR_BASE: u32 = 240;
const MAX_CONTROLLERS: u32 = 8;
/// UART transport packet types (Vol 4, Part A, §2).
const H4_COMMAND: u8 = 0x01;
const H4_ACL: u8 = 0x02;
const H4_EVENT: u8 = 0x04;
/// HCI commands to a USB controller: a class request to the device, 0x00
/// (Vol 4, Part B, §2.2).
const RT_CLASS_DEVICE_OUT: u8 = 0x20;
/// Bulk IN buffers kept queued, and their size.
const ACL_BUFFERS: usize = 4;
const ACL_BUF: usize = 1024;
/// Packets held for the reader at most; older ones are dropped.
const QUEUE_MAX: usize = 512;

struct Rx {
    queue: VecDeque<Vec<u8>>,
    /// An event or ACL packet still arriving.
    event: Vec<u8>,
    acl: Vec<u8>,
    /// Bulk IN buffers queued, oldest first.
    acl_pending: VecDeque<Dma>,
}

pub struct Hci {
    index: u32,
    dev: Arc<UsbDevice>,
    bulk_out: Arc<Endpoint>,
    out_buf: crate::sched::wait::Mutex<Dma>,
    rx: IrqSpinLock<Rx>,
    wait: WaitQueue,
    count: AtomicU64,
    open: AtomicBool,
    flags: AtomicU32,
}

static CONTROLLERS: IrqSpinLock<Vec<Arc<Hci>>> = IrqSpinLock::new(Vec::new());

impl Hci {
    fn gone(&self) -> bool {
        self.dev.gone.load(Ordering::Acquire)
    }

    fn deliver(&self, packet: Vec<u8>) {
        {
            let mut rx = self.rx.lock();
            if rx.queue.len() >= QUEUE_MAX {
                rx.queue.pop_front();
            }
            rx.queue.push_back(packet);
        }
        self.count.fetch_add(1, Ordering::Release);
        self.wait.wake_all();
        crate::fs::poll_notify();
    }

    /// Bytes from the interrupt endpoint: whole events out of them (an
    /// event is its code, its parameters' length, the parameters).
    fn event_bytes(&self, b: &[u8]) {
        let mut done = Vec::new();
        {
            let mut rx = self.rx.lock();
            rx.event.extend_from_slice(b);
            while rx.event.len() >= 2 && rx.event.len() >= 2 + usize::from(rx.event[1]) {
                let n = 2 + usize::from(rx.event[1]);
                let mut p = alloc::vec![H4_EVENT];
                p.extend(rx.event.drain(..n));
                done.push(p);
            }
        }
        for p in done {
            self.deliver(p);
        }
    }

    /// Bytes from the bulk IN endpoint: whole ACL packets (a handle and
    /// flags, a length, the data; Vol 4, Part E, §5.4.2).
    fn acl_bytes(&self, b: &[u8]) {
        let mut done = Vec::new();
        {
            let mut rx = self.rx.lock();
            rx.acl.extend_from_slice(b);
            while rx.acl.len() >= 4 {
                let n = 4 + usize::from(u16::from_le_bytes([rx.acl[2], rx.acl[3]]));
                if rx.acl.len() < n {
                    break;
                }
                let mut p = alloc::vec![H4_ACL];
                p.extend(rx.acl.drain(..n));
                done.push(p);
            }
        }
        for p in done {
            self.deliver(p);
        }
    }
}

/// Start the Bluetooth controller on interface `iface` of `dev`.
pub fn start(dev: &Arc<UsbDevice>, iface: &InterfaceDesc) {
    let find = |kind: u8, input: bool| iface.endpoints.iter().find(|e| e.kind == kind && e.is_in() == input).copied();
    let (Some(intr), Some(bin), Some(bout)) = (find(EP_INTERRUPT, true), find(EP_BULK, true), find(EP_BULK, false))
    else {
        log_warn!("USB port {}: Bluetooth interface {} lacks its endpoints", dev.port, iface.number);
        return;
    };
    let eps: [EndpointDesc; 3] = [intr, bin, bout];
    let Some(rings) = dev.configure(&eps) else { return };
    let (intr_ep, bin_ep, bout_ep) = (rings[0].clone(), rings[1].clone(), rings[2].clone());
    let index = {
        let all = CONTROLLERS.lock();
        (0..MAX_CONTROLLERS).find(|i| !all.iter().any(|c| c.index == *i && !c.gone()))
    };
    let (Some(index), Some(out_buf)) = (index, Dma::new(ACL_BUF + 4)) else { return };
    let hci = Arc::new(Hci {
        index,
        dev: dev.clone(),
        bulk_out: bout_ep,
        out_buf: crate::sched::wait::Mutex::new(out_buf),
        rx: IrqSpinLock::new(Rx {
            queue: VecDeque::new(),
            event: Vec::new(),
            acl: Vec::new(),
            acl_pending: VecDeque::new(),
        }),
        wait: WaitQueue::new(),
        count: AtomicU64::new(0),
        open: AtomicBool::new(false),
        flags: AtomicU32::new(0),
    });
    // Events: one USB packet at a time, put back together.
    let len = usize::from(intr.max_packet).clamp(8, 64);
    let Some(ebuf) = Dma::new(64) else { return };
    let phys = ebuf.phys();
    let h = hci.clone();
    let r = intr_ep.clone();
    dev.hc.set_pipe(
        dev.slot,
        intr_ep.dci,
        alloc::boxed::Box::new(move |code, residual| {
            if h.gone() {
                return;
            }
            if code == CC_SUCCESS || code == CC_SHORT_PACKET {
                let got = len - (residual as usize).min(len);
                let mut b = [0u8; 64];
                ebuf.copy_out(0, &mut b[..got]);
                h.event_bytes(&b[..got]);
            } else {
                log_warn!("hci{}: event endpoint error {code}", h.index);
            }
            h.dev.queue(&r, phys, len);
        }),
    );
    dev.queue(&intr_ep, phys, len);
    // ACL data in.
    let h = hci.clone();
    let r = bin_ep.clone();
    dev.hc.set_pipe(
        dev.slot,
        bin_ep.dci,
        alloc::boxed::Box::new(move |code, residual| {
            if h.gone() {
                return;
            }
            let Some(buf) = h.rx.lock().acl_pending.pop_front() else { return };
            if code == CC_SUCCESS || code == CC_SHORT_PACKET {
                let got = ACL_BUF - (residual as usize).min(ACL_BUF);
                let mut b = alloc::vec![0u8; got];
                buf.copy_out(0, &mut b);
                h.acl_bytes(&b);
            }
            h.dev.queue(&r, buf.phys(), ACL_BUF);
            h.rx.lock().acl_pending.push_back(buf);
        }),
    );
    for _ in 0..ACL_BUFFERS {
        let Some(b) = Dma::new(ACL_BUF) else { break };
        dev.queue(&bin_ep, b.phys(), ACL_BUF);
        hci.rx.lock().acl_pending.push_back(b);
    }
    dev.bound(iface.number, "btusb");
    CONTROLLERS.lock().push(hci.clone());
    log_info!("USB port {}: Bluetooth controller hci{index}", dev.port);
    crate::fs::char_added(node(index));
}

fn node(index: u32) -> CharNode {
    let minor = HCI_MINOR_BASE + index;
    let major = crate::fs::devices::MISC_MAJOR;
    let dir = alloc::format!("devices/virtual/bluetooth/hci{index}");
    CharNode {
        dev: alloc::format!("hci{index}"),
        rdev: vfs::makedev(major, minor),
        // The Bluetooth daemon's alone.
        mode: 0o600,
        sys: alloc::vec![
            SysEntry::File(alloc::format!("{dir}/dev"), alloc::format!("{major}:{minor}\n")),
            SysEntry::File(
                alloc::format!("{dir}/uevent"),
                alloc::format!("MAJOR={major}\nMINOR={minor}\nDEVNAME=hci{index}\n")
            ),
            SysEntry::Link(alloc::format!("class/bluetooth/hci{index}"), alloc::format!("../../{dir}")),
        ],
    }
}

/// The USB device went: its controllers' readers get ENODEV, and their
/// /dev nodes go.
pub fn detached(dev: &Arc<UsbDevice>) {
    let gone: Vec<Arc<Hci>> = {
        let mut all = CONTROLLERS.lock();
        let (gone, kept) = all.drain(..).partition(|c| Arc::ptr_eq(&c.dev, dev));
        *all = kept;
        gone
    };
    for h in gone {
        log_info!("hci{}: removed", h.index);
        h.wait.wake_all();
        crate::fs::poll_notify();
        crate::fs::char_removed(&alloc::format!("hci{}", h.index));
    }
}

/// Open /dev/hci(minor - 240).
pub fn open(minor: u32, flags: u32) -> Result<Arc<dyn File>> {
    let index = minor.checked_sub(HCI_MINOR_BASE).ok_or(ENXIO)?;
    let h = CONTROLLERS.lock().iter().find(|c| c.index == index && !c.gone()).cloned().ok_or(ENXIO)?;
    if h.open.swap(true, Ordering::AcqRel) {
        return Err(EBUSY);
    }
    // What came before this opener is not theirs.
    h.rx.lock().queue.clear();
    h.flags.store(flags, Ordering::Relaxed);
    Ok(Arc::new(HciFile(h)))
}

struct HciFile(Arc<Hci>);

impl Drop for HciFile {
    fn drop(&mut self) {
        self.0.open.store(false, Ordering::Release);
    }
}

impl File for HciFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let h = &self.0;
        loop {
            if h.gone() {
                return Err(ENODEV);
            }
            {
                let mut rx = h.rx.lock();
                if let Some(p) = rx.queue.front() {
                    if p.len() > buf.len() {
                        return Err(EINVAL);
                    }
                    let p = rx.queue.pop_front().unwrap_or_default();
                    buf[..p.len()].copy_from_slice(&p);
                    return Ok(p.len());
                }
            }
            if h.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0 {
                return Err(EAGAIN);
            }
            if h.wait.wait_until_interruptible(|| !h.rx.lock().queue.is_empty() || h.gone()) {
                return Err(EINTR);
            }
        }
    }

    /// One framed packet: a command (to the control endpoint) or ACL data
    /// (to the bulk OUT endpoint).
    fn write(&self, buf: &[u8]) -> Result<usize> {
        let h = &self.0;
        if h.gone() {
            return Err(ENODEV);
        }
        match buf.first() {
            Some(&H4_COMMAND) if buf.len() >= 4 && buf.len() == 4 + usize::from(buf[3]) => {
                let mut cmd = buf[1..].to_vec();
                h.dev.control(RT_CLASS_DEVICE_OUT, 0, 0, 0, &mut cmd).map_err(|_| EIO)?;
            }
            Some(&H4_ACL) if buf.len() >= 5 && buf.len() - 1 <= ACL_BUF + 4 => {
                let out = h.out_buf.lock();
                out.copy_in(0, &buf[1..]);
                h.dev.transfer(&h.bulk_out, out.phys(), buf.len() - 1).map_err(|_| EIO)?;
            }
            _ => return Err(EINVAL),
        }
        Ok(buf.len())
    }

    fn poll(&self) -> u16 {
        if self.0.gone() {
            return POLLERR | POLLHUP;
        }
        if self.0.rx.lock().queue.is_empty() { POLLOUT } else { POLLIN | POLLOUT }
    }

    fn event_count(&self) -> u64 {
        self.0.count.load(Ordering::Acquire)
    }

    fn status_flags(&self) -> u32 {
        self.0.flags.load(Ordering::Relaxed)
    }

    fn set_status_flags(&self, flags: u32) {
        let keep = self.0.flags.load(Ordering::Relaxed) & !O_NONBLOCK;
        self.0.flags.store(keep | (flags & O_NONBLOCK), Ordering::Relaxed);
    }

    fn stat(&self) -> Result<Metadata> {
        let rdev = vfs::makedev(crate::fs::devices::MISC_MAJOR, HCI_MINOR_BASE + self.0.index);
        Ok(Metadata { mode: vfs::S_IFCHR | 0o600, rdev, nlink: 1, ..Metadata::default() })
    }
}
