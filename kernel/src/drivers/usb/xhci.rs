// SPDX-License-Identifier: MIT OR Apache-2.0

//! xHCI USB host controllers.
//!
//! Source: eXtensible Host Controller Interface for Universal Serial Bus
//! (xHCI) Revision 1.2: capability, operational, runtime and doorbell
//! registers (§5), TRB rings and the event ring (§4.9-§4.11, §6.4), device
//! and input contexts (§6.2), device slot setup (§4.3), USB legacy support
//! and supported protocol capabilities (§7.1-§7.2), and initialization
//! (§4.2).
//!
//! Events are handled in the interrupt handler (or by a polling thread
//! when the controller has no MSI): command and transfer completions are
//! recorded for the waiting thread, interrupt pipes (keyboards) call their
//! handler, and port changes wake the enumeration thread, which sets up
//! new devices and starts their class drivers.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use slate_sync::Once;

use super::*;
use crate::drivers::dma::{Dma, Mmio, delay_ms, wait_for};
use crate::drivers::pci::Device;
use crate::sched::wait::{Mutex, WaitQueue};
use crate::sync::IrqSpinLock;
use crate::{log_info, log_warn};

// Capability registers (§5.3).
const CAPLENGTH: usize = 0x00;
const HCSPARAMS1: usize = 0x04;
const HCSPARAMS2: usize = 0x08;
const HCCPARAMS1: usize = 0x10;
const DBOFF: usize = 0x14;
const RTSOFF: usize = 0x18;

// Operational registers (§5.4).
const USBCMD: usize = 0x00;
const USBSTS: usize = 0x04;
const CRCR: usize = 0x18;
const DCBAAP: usize = 0x30;
const CONFIG: usize = 0x38;
const PORTSC: usize = 0x400;

const CMD_RUN: u32 = 1 << 0;
const CMD_HCRST: u32 = 1 << 1;
const CMD_INTE: u32 = 1 << 2;
const STS_HCH: u32 = 1 << 0;
const STS_EINT: u32 = 1 << 3;
const STS_CNR: u32 = 1 << 11;

// PORTSC bits (§5.4.8).
const PORT_CCS: u32 = 1 << 0;
const PORT_PED: u32 = 1 << 1;
const PORT_PR: u32 = 1 << 4;
const PORT_PP: u32 = 1 << 9;
const PORT_PRC: u32 = 1 << 21;
const PORT_WPR: u32 = 1 << 31;
/// Write-1-to-clear change bits (CSC..CEC), and PED (writing 1 disables).
const PORT_RW1C: u32 = 0x7F << 17;
const PORT_PRESERVE_MASK: u32 = !(PORT_RW1C | PORT_PED);

// Interrupter 0 (§5.5.2), from the runtime base.
const IMAN: usize = 0x20;
const IMOD: usize = 0x24;
const ERSTSZ: usize = 0x28;
const ERSTBA: usize = 0x30;
const ERDP: usize = 0x38;
const IMAN_IP: u32 = 1 << 0;
const IMAN_IE: u32 = 1 << 1;
const ERDP_EHB: u64 = 1 << 3;

// Extended capabilities (§7).
const XCAP_LEGACY: u32 = 1;
const XCAP_PROTOCOL: u32 = 2;
const LEGACY_BIOS_OWNED: u32 = 1 << 16;
const LEGACY_OS_OWNED: u32 = 1 << 24;

// TRB types (§6.4.6).
const TRB_NORMAL: u32 = 1;
const TRB_SETUP: u32 = 2;
const TRB_DATA: u32 = 3;
const TRB_STATUS: u32 = 4;
/// An isochronous TRB (§6.4.1.3).
const TRB_ISOCH: u32 = 5;
const TRB_LINK: u32 = 6;
const TRB_ENABLE_SLOT: u32 = 9;
const TRB_DISABLE_SLOT: u32 = 10;
const TRB_ADDRESS_DEVICE: u32 = 11;
const TRB_CONFIGURE_ENDPOINT: u32 = 12;
const TRB_EVALUATE_CONTEXT: u32 = 13;
const TRB_RESET_ENDPOINT: u32 = 14;
const TRB_SET_DEQUEUE: u32 = 16;
const EVT_TRANSFER: u32 = 32;
const EVT_COMMAND: u32 = 33;
const EVT_PORT: u32 = 34;

const TRB_CYCLE: u32 = 1 << 0;
const TRB_TOGGLE: u32 = 1 << 1;
const TRB_ISP: u32 = 1 << 2;
const TRB_IOC: u32 = 1 << 5;
const TRB_IDT: u32 = 1 << 6;
const TRB_DIR_IN: u32 = 1 << 16;
/// An isochronous TD's Start Isoch ASAP: the next free service interval.
const TRB_SIA: u32 = 1 << 31;

// Completion codes (§6.4.5).
pub const CC_SUCCESS: u8 = 1;
pub const CC_STALL: u8 = 6;
pub const CC_SHORT_PACKET: u8 = 13;

// Endpoint types in endpoint contexts (§6.2.3, table 6-9).
const EPT_ISOCH_OUT: u32 = 1;
const EPT_ISOCH_IN: u32 = 5;
const EPT_CONTROL: u32 = 4;
const EPT_BULK_OUT: u32 = 2;
const EPT_INTERRUPT_OUT: u32 = 3;
const EPT_BULK_IN: u32 = 6;
const EPT_INTERRUPT_IN: u32 = 7;

/// Port speeds in PORTSC and slot contexts (§7.2.1 default IDs).
pub const SPEED_FULL: u32 = 1;
pub const SPEED_LOW: u32 = 2;
pub const SPEED_HIGH: u32 = 3;
/// SuperSpeed (and 5, SuperSpeedPlus).
pub const SPEED_SUPER: u32 = 4;

const RING_TRBS: usize = 256;
const COMMAND_TIMEOUT_MS: u64 = 5000;
pub const TRANSFER_TIMEOUT_MS: u64 = 10_000;

/// A producer ring of TRBs (command or transfer ring) in one page, with a
/// Link TRB back to the start in the last slot.
pub struct Ring {
    dma: Dma,
    idx: usize,
    cycle: bool,
}

impl Ring {
    fn new() -> Option<Ring> {
        Some(Ring { dma: Dma::new(RING_TRBS * 16)?, idx: 0, cycle: true })
    }

    fn phys(&self) -> u64 {
        self.dma.phys()
    }

    /// Wrap to the start now with a Link TRB (toggle cycle).
    fn link(&mut self) {
        let off = self.idx * 16;
        self.dma.write::<u64>(off, self.dma.phys());
        self.dma.write::<u32>(off + 8, 0);
        core::sync::atomic::fence(Ordering::SeqCst);
        self.dma.write::<u32>(off + 12, (TRB_LINK << 10) | TRB_TOGGLE | u32::from(self.cycle));
        self.idx = 0;
        self.cycle = !self.cycle;
    }

    /// Make sure `n` TRBs fit before the end, so a TD never straddles the
    /// link.
    fn room(&mut self, n: usize) {
        if self.idx + n > RING_TRBS - 1 {
            self.link();
        }
    }

    /// Write one TRB; returns its physical address.
    fn push(&mut self, t: [u32; 4]) -> u64 {
        if self.idx >= RING_TRBS - 1 {
            self.link();
        }
        let off = self.idx * 16;
        self.dma.write::<u32>(off, t[0]);
        self.dma.write::<u32>(off + 4, t[1]);
        self.dma.write::<u32>(off + 8, t[2]);
        core::sync::atomic::fence(Ordering::SeqCst);
        self.dma.write::<u32>(off + 12, (t[3] & !TRB_CYCLE) | u32::from(self.cycle));
        self.idx += 1;
        self.dma.phys() + off as u64
    }

    /// Where the next TRB goes, with the cycle state (for Set TR Dequeue).
    fn enqueue_pointer(&self) -> u64 {
        (self.dma.phys() + (self.idx * 16) as u64) | u64::from(self.cycle)
    }
}

/// A finished command or transfer.
#[derive(Clone, Copy, Debug)]
pub struct Completion {
    pub code: u8,
    pub slot: u8,
    /// Bytes not transferred (transfer events).
    pub residual: u32,
}

/// Where a device sits (xHCI §4.3.3, §6.2.2): its root hub port, the
/// route string through hubs (4 bits per tier), and, for a low- or
/// full-speed device behind a high-speed hub, the transaction translator
/// (that hub's slot and port).
#[derive(Clone, Copy, Debug, Default)]
pub struct Position {
    pub root_port: u8,
    pub route: u32,
    pub depth: u8,
    pub tt: Option<(u8, u8)>,
}

struct EventRing {
    dma: Dma,
    idx: usize,
    cycle: bool,
}

/// A handler for an interrupt-IN pipe's completions (code, residual).
pub type PipeHandler = Box<dyn Fn(u8, u32) + Send + Sync>;

pub struct Xhci {
    op: Mmio,
    rt: Mmio,
    db: Mmio,
    /// Bytes per context: 32, or 64 with HCCPARAMS1.CSZ.
    pub ctx_size: usize,
    /// HCCPARAMS1.MaxPSASize: primary stream arrays of up to 2^(n+1)
    /// entries (0: no streams; §5.3.6).
    max_psa: u8,
    max_ports: u8,
    /// Ports whose protocol is USB 2 (they need a reset to be enabled).
    usb2: [bool; 256],
    /// Its root hubs in sysfs.
    pub sys: super::sys::Controller,
    dcbaa: Dma,
    cmd: IrqSpinLock<Ring>,
    events: IrqSpinLock<EventRing>,
    done: IrqSpinLock<BTreeMap<u64, Completion>>,
    waiters: WaitQueue,
    pipes: IrqSpinLock<BTreeMap<(u8, u8), Arc<PipeHandler>>>,
    interrupts: bool,
    pub port_change: AtomicBool,
    pub enum_waiters: WaitQueue,
    _scratchpad: Vec<Dma>,
}

impl Xhci {
    fn portsc(&self, port: u8) -> usize {
        PORTSC + 0x10 * (usize::from(port) - 1)
    }

    /// Handle every pending event (interrupt handler or polling thread).
    pub fn process_events(&self) {
        let mut pipe_events = Vec::new();
        {
            let mut ev = self.events.lock();
            let start = ev.idx;
            loop {
                let off = ev.idx * 16;
                let d3 = ev.dma.read::<u32>(off + 12);
                if (d3 & TRB_CYCLE != 0) != ev.cycle {
                    break;
                }
                let ptr = ev.dma.read::<u64>(off);
                let d2 = ev.dma.read::<u32>(off + 8);
                let code = (d2 >> 24) as u8;
                let slot = (d3 >> 24) as u8;
                match (d3 >> 10) & 0x3F {
                    EVT_COMMAND => {
                        self.done.lock().insert(ptr, Completion { code, slot, residual: 0 });
                    }
                    EVT_TRANSFER => {
                        let ep = ((d3 >> 16) & 0x1F) as u8;
                        let c = Completion { code, slot, residual: d2 & 0xFF_FFFF };
                        match self.pipes.lock().get(&(slot, ep)) {
                            Some(h) => pipe_events.push((h.clone(), c)),
                            None => {
                                self.done.lock().insert(ptr, c);
                            }
                        }
                    }
                    EVT_PORT => {
                        self.port_change.store(true, Ordering::Release);
                        self.enum_waiters.wake_all();
                    }
                    _ => {}
                }
                ev.idx += 1;
                if ev.idx == RING_TRBS {
                    ev.idx = 0;
                    ev.cycle = !ev.cycle;
                }
            }
            if ev.idx != start {
                self.rt.write64(ERDP, (ev.dma.phys() + (ev.idx * 16) as u64) | ERDP_EHB);
            }
        }
        for (h, c) in pipe_events {
            h(c.code, c.residual);
        }
        self.waiters.wake_all();
    }

    fn interrupt(&self) {
        self.rt.write32(IMAN, self.rt.read32(IMAN) | IMAN_IP);
        self.op.write32(USBSTS, STS_EINT);
        self.process_events();
    }

    /// Wait until `cond` holds (completions arrive by interrupt, or are
    /// polled for); false after `timeout_ms`.
    fn wait_until(&self, mut cond: impl FnMut() -> bool, timeout_ms: u64) -> bool {
        if self.interrupts && crate::sched::can_block() {
            let deadline = crate::time::monotonic_ns() + timeout_ms * 1_000_000;
            self.waiters.wait_until_timeout(cond, deadline)
        } else {
            wait_for(timeout_ms, || {
                self.process_events();
                cond()
            })
        }
    }

    /// Wait for the completion of the TRB at `ptr`.
    pub fn wait(&self, ptr: u64, timeout_ms: u64) -> Option<Completion> {
        let ready = || self.done.lock().contains_key(&ptr);
        let ok = if self.interrupts && crate::sched::can_block() {
            let deadline = crate::time::monotonic_ns() + timeout_ms * 1_000_000;
            self.waiters.wait_until_timeout(ready, deadline)
        } else {
            wait_for(timeout_ms, || {
                self.process_events();
                ready()
            })
        };
        if !ok {
            return None;
        }
        self.done.lock().remove(&ptr)
    }

    /// Run a command (§4.6) and wait for its completion event.
    fn command(&self, trb: [u32; 4]) -> Option<Completion> {
        let ptr = self.cmd.lock().push(trb);
        self.db.write32(0, 0);
        let c = self.wait(ptr, COMMAND_TIMEOUT_MS);
        if c.is_none() {
            log_warn!("xHCI: command {} timed out", (trb[3] >> 10) & 0x3F);
        }
        c
    }

    pub fn ring_doorbell(&self, slot: u8, target: u8) {
        self.db.write32(4 * usize::from(slot), u32::from(target));
    }

    /// A doorbell for stream `stream` of endpoint `dci` (§5.6: DB Stream
    /// ID in bits 31:16).
    fn ring_stream(&self, slot: u8, dci: u8, stream: u16) {
        self.db.write32(4 * usize::from(slot), u32::from(dci) | (u32::from(stream) << 16));
    }

    /// Route completions of `slot`'s endpoint `dci` to `handler`.
    pub fn set_pipe(&self, slot: u8, dci: u8, handler: PipeHandler) {
        self.pipes.lock().insert((slot, dci), Arc::new(handler));
    }

    fn drop_pipes(&self, slot: u8) {
        self.pipes.lock().retain(|k, _| k.0 != slot);
    }
}

/// An endpoint's transfer ring, and its streams' rings when it has
/// streams (stream ID n is `streams[n - 1]`).
pub struct Endpoint {
    pub dci: u8,
    pub ring: IrqSpinLock<Ring>,
    pub streams: Vec<IrqSpinLock<Ring>>,
    /// The stream context array the controller reads.
    _stream_array: Option<Dma>,
}

/// A device in a slot.
pub struct UsbDevice {
    pub hc: Arc<Xhci>,
    pub slot: u8,
    /// Where it is, for messages: the root port, then hub ports ("3.2").
    pub port: String,
    pub pos: Position,
    pub speed: u32,
    /// Its device number on its bus (sysfs `devnum`).
    pub devnum: u8,
    /// The configuration set (bConfigurationValue).
    pub config_value: AtomicU8,
    /// A hub's ports (sysfs `maxchild`), once its driver knows them.
    pub maxchild: Arc<AtomicU8>,
    out_ctx: Dma,
    ep0: Endpoint,
    /// Bounce buffer for control transfers.
    ctrl_buf: Mutex<Dma>,
    pub gone: AtomicBool,
    /// Its removal was asked for (a disk powered off, ADR 0108's second
    /// addendum): the enumeration thread forgets it and disables its port.
    pub removal: AtomicBool,
}

impl Drop for UsbDevice {
    fn drop(&mut self) {
        super::sys::free_devnum(&self.hc.sys, &self.port, self.devnum);
    }
}

impl UsbDevice {
    /// Driver `driver` took interface `number` (its sysfs links).
    pub fn bound(&self, number: u8, driver: &'static str) {
        super::sys::bound(&self.hc.sys, &self.port, self.config_value.load(Ordering::Relaxed), number, driver);
    }

    /// String descriptor `index` in language `lang` (USB 2.0 §9.6.7).
    pub fn string(&self, index: u8, lang: u16) -> Option<String> {
        if index == 0 {
            return None;
        }
        let mut buf = [0u8; 255];
        let value = (u16::from(slate_usb::DESC_STRING) << 8) | u16::from(index);
        let n = self.control(RT_DEVICE_IN, REQ_GET_DESCRIPTOR, value, lang, &mut buf).ok()?;
        Some(slate_usb::string_utf8(&buf[..n]))
    }

    /// A control transfer on endpoint 0 (§4.11.2.2: Setup, optional Data,
    /// Status). IN data lands in `data`; OUT data comes from it.
    pub fn control(&self, rt: u8, req: u8, value: u16, index: u16, data: &mut [u8]) -> Result<usize, u8> {
        let len = data.len();
        let buf = self.ctrl_buf.lock();
        if len > buf.len() {
            return Err(0);
        }
        let dir_in = rt & 0x80 != 0;
        if !dir_in && len > 0 {
            buf.copy_in(0, data);
        }
        let (setup_ptr, data_ptr, status_ptr) = {
            let mut ring = self.ep0.ring.lock();
            ring.room(3);
            let trt = if len == 0 {
                0
            } else if dir_in {
                3
            } else {
                2
            };
            let setup_ptr = ring.push([
                u32::from(rt) | (u32::from(req) << 8) | (u32::from(value) << 16),
                u32::from(index) | ((len as u32) << 16),
                8,
                (TRB_SETUP << 10) | TRB_IDT | (trt << 16),
            ]);
            let data_ptr = (len > 0).then(|| {
                let p = buf.phys();
                ring.push([
                    p as u32,
                    (p >> 32) as u32,
                    len as u32,
                    (TRB_DATA << 10) | TRB_ISP | if dir_in { TRB_DIR_IN } else { 0 },
                ])
            });
            let status_dir = if len > 0 && dir_in { 0 } else { TRB_DIR_IN };
            let status_ptr = ring.push([0, 0, 0, (TRB_STATUS << 10) | TRB_IOC | status_dir]);
            (setup_ptr, data_ptr, status_ptr)
        };
        self.hc.ring_doorbell(self.slot, 1);
        // Done when the status stage completes, or when an earlier stage
        // fails (a stall in the setup or data stage leaves the rest unrun;
        // the controller reports it on the TRB where it stopped).
        let failed = |c: &Completion| c.code != CC_SUCCESS && c.code != CC_SHORT_PACKET;
        let settled = || {
            let done = self.hc.done.lock();
            done.contains_key(&status_ptr)
                || [Some(setup_ptr), data_ptr].into_iter().flatten().any(|p| done.get(&p).is_some_and(failed))
        };
        let finished = self.hc.wait_until(settled, TRANSFER_TIMEOUT_MS);
        let (setup, status, data_event) = {
            let mut done = self.hc.done.lock();
            (done.remove(&setup_ptr), done.remove(&status_ptr), data_ptr.and_then(|p| done.remove(&p)))
        };
        let code = match (setup, status, data_event) {
            (Some(s), _, _) if failed(&s) => s.code,
            (_, _, Some(d)) if failed(&d) => d.code,
            (_, Some(s), _) => s.code,
            _ => 0,
        };
        if !finished || code != CC_SUCCESS {
            // A stall (or any error) halts endpoint 0 in the controller
            // (§4.10.2.1): nothing more goes through until it is reset.
            self.reset_control();
            return Err(code);
        }
        let short = data_event;
        let got = len - short.map_or(0, |s| s.residual as usize).min(len);
        if dir_in && got > 0 {
            buf.copy_out(0, &mut data[..got]);
        }
        Ok(got)
    }

    /// One Normal TRB on endpoint `ep` (§4.11.2.1) moving `len` bytes at
    /// physical `buf`; returns the bytes moved, or the completion code.
    pub fn transfer(&self, ep: &Endpoint, buf: u64, len: usize) -> Result<usize, u8> {
        let ptr =
            ep.ring.lock().push([buf as u32, (buf >> 32) as u32, len as u32, (TRB_NORMAL << 10) | TRB_IOC | TRB_ISP]);
        self.hc.ring_doorbell(self.slot, ep.dci);
        let c = self.hc.wait(ptr, TRANSFER_TIMEOUT_MS).ok_or(0u8)?;
        match c.code {
            CC_SUCCESS | CC_SHORT_PACKET => Ok(len - (c.residual as usize).min(len)),
            code => Err(code),
        }
    }

    /// Queue a Normal TRB on stream `stream` of `ep` (0: the endpoint's
    /// own ring) moving `len` bytes at `buf`, without waiting; returns
    /// what `finish` waits for.
    pub fn submit(&self, ep: &Endpoint, stream: u16, buf: u64, len: usize) -> u64 {
        let trb = [buf as u32, (buf >> 32) as u32, len as u32, (TRB_NORMAL << 10) | TRB_IOC | TRB_ISP];
        match stream.checked_sub(1).and_then(|i| ep.streams.get(usize::from(i))) {
            Some(ring) => {
                let ptr = ring.lock().push(trb);
                self.hc.ring_stream(self.slot, ep.dci, stream);
                ptr
            }
            None => {
                let ptr = ep.ring.lock().push(trb);
                self.hc.ring_doorbell(self.slot, ep.dci);
                ptr
            }
        }
    }

    /// Wait for a transfer `submit` queued (`len` bytes asked for): the
    /// bytes moved, or the completion code (0: it never completed).
    pub fn finish(&self, ptr: u64, len: usize, timeout_ms: u64) -> Result<usize, u8> {
        let c = self.hc.wait(ptr, timeout_ms).ok_or(0u8)?;
        match c.code {
            CC_SUCCESS | CC_SHORT_PACKET => Ok(len - (c.residual as usize).min(len)),
            code => Err(code),
        }
    }

    /// Queue a Normal TRB without waiting (interrupt pipes).
    pub fn queue(&self, ep: &Endpoint, buf: u64, len: usize) {
        ep.ring.lock().push([buf as u32, (buf >> 32) as u32, len as u32, (TRB_NORMAL << 10) | TRB_IOC | TRB_ISP]);
        self.hc.ring_doorbell(self.slot, ep.dci);
    }

    /// Queue one isochronous TD of `len` bytes at `buf` (§4.11.2.5), in
    /// the next service interval free after those queued (SIA), with an
    /// interrupt on its completion.
    pub fn queue_isoch(&self, ep: &Endpoint, buf: u64, len: usize) {
        let trb = [buf as u32, (buf >> 32) as u32, len as u32, (TRB_ISOCH << 10) | TRB_SIA | TRB_IOC | TRB_ISP];
        ep.ring.lock().push(trb);
        self.hc.ring_doorbell(self.slot, ep.dci);
    }

    /// GET_DESCRIPTOR into `buf`.
    pub fn descriptor(&self, kind: u8, buf: &mut [u8]) -> Result<usize, u8> {
        self.control(RT_DEVICE_IN, REQ_GET_DESCRIPTOR, u16::from(kind) << 8, 0, buf)
    }

    /// Configuration `index` with everything that follows it (USB 2.0
    /// §9.4.3: the header first, for the total length).
    pub fn configuration(&self, index: u8) -> Option<slate_usb::Configuration> {
        let value = (u16::from(DESC_CONFIGURATION) << 8) | u16::from(index);
        let mut head = [0u8; 9];
        self.control(RT_DEVICE_IN, REQ_GET_DESCRIPTOR, value, 0, &mut head).ok()?;
        let total = usize::from(u16::from_le_bytes([head[2], head[3]])).clamp(9, 4096);
        let mut data = alloc::vec![0u8; total];
        let got = self.control(RT_DEVICE_IN, REQ_GET_DESCRIPTOR, value, 0, &mut data).ok()?;
        Some(slate_usb::parse_configuration(&data[..got]))
    }

    /// Whether the controller interrupts (else its events are polled).
    pub fn interrupts(&self) -> bool {
        self.hc.interrupts
    }

    /// Configure endpoints (Configure Endpoint command, §4.6.6) and return
    /// their rings, in the order given.
    pub fn configure(&self, eps: &[EndpointDesc]) -> Option<Vec<Arc<Endpoint>>> {
        self.configure_streams(eps, 0)
    }

    /// As `configure`, with up to `streams` streams on each SuperSpeed bulk
    /// endpoint that offers them (§4.12: a linear primary stream array,
    /// one ring per stream).
    pub fn configure_streams(&self, eps: &[EndpointDesc], streams: u16) -> Option<Vec<Arc<Endpoint>>> {
        let cs = self.hc.ctx_size;
        let input = Dma::new(cs * 33)?;
        let max_dci = eps.iter().map(|e| e.dci()).max().unwrap_or(1);
        let mut add = 1u32;
        let mut out = Vec::new();
        for e in eps {
            let ring = Ring::new()?;
            let dci = e.dci();
            add |= 1 << dci;
            let ctx = (usize::from(dci) + 1) * cs;
            let interval = match (e.kind, self.speed) {
                (EP_INTERRUPT, SPEED_FULL | SPEED_LOW) => {
                    // bInterval frames of 1 ms, as 2^n × 125 µs.
                    (31 - (u32::from(e.interval.max(1)) * 8).leading_zeros()).clamp(3, 10)
                }
                (EP_INTERRUPT, _) => u32::from(e.interval.clamp(1, 16)) - 1,
                // Isochronous: 2^(bInterval - 1) frames (full speed, 8
                // microframes each) or microframes (USB 2.0 §9.6.6).
                (EP_ISOCH, SPEED_FULL) => u32::from(e.interval.clamp(1, 16)) - 1 + 3,
                (EP_ISOCH, _) => u32::from(e.interval.clamp(1, 16)) - 1,
                _ => 0,
            };
            let kind = match (e.kind, e.is_in()) {
                (EP_INTERRUPT, true) => EPT_INTERRUPT_IN,
                (EP_INTERRUPT, false) => EPT_INTERRUPT_OUT,
                (EP_ISOCH, true) => EPT_ISOCH_IN,
                (EP_ISOCH, false) => EPT_ISOCH_OUT,
                (_, true) => EPT_BULK_IN,
                (_, false) => EPT_BULK_OUT,
            };
            let mps = u32::from(e.max_packet);
            // Streams: as many as asked for, the endpoint offers and the
            // controller's array takes, in an array of a power of two
            // entries (entry 0 is reserved). MaxPStreams is log2 of the
            // entries less one; LSA (bit 15) says the array is linear.
            let want = if e.kind == EP_BULK && self.hc.max_psa > 0 && e.max_streams > 0 { streams } else { 0 };
            let n = u32::from(want).min(1 << e.max_streams.min(16)).min((1 << (u32::from(self.hc.max_psa) + 1)) - 1);
            let mut stream_rings = Vec::new();
            let mut array = None;
            if n > 0 {
                let entries = (n + 1).next_power_of_two().max(2);
                let a = Dma::new(entries as usize * 16)?;
                for k in 1..=n {
                    let r = Ring::new()?;
                    // Stream context (§6.2.4.1): the ring, SCT 1 (a primary
                    // transfer ring, bits 3:1), DCS 1.
                    a.write::<u64>(k as usize * 16, r.phys() | (1 << 1) | 1);
                    stream_rings.push(IrqSpinLock::new(r));
                }
                let max_p = entries.trailing_zeros() - 1;
                input.write::<u32>(ctx, (interval << 16) | (max_p << 10) | (1 << 15));
                input.write::<u64>(ctx + 8, a.phys());
                array = Some(a);
            } else {
                input.write::<u32>(ctx, interval << 16);
                input.write::<u64>(ctx + 8, ring.phys() | 1);
            }
            // Error count 3, but 0 for isochronous endpoints (§6.2.3.2:
            // they are never retried).
            let cerr = if e.kind == EP_ISOCH { 0 } else { 3 };
            input.write::<u32>(ctx + 4, (cerr << 1) | (kind << 3) | (mps << 16));
            let avg = match e.kind {
                EP_INTERRUPT => 8,
                EP_ISOCH => mps,
                _ => 1024,
            };
            let esit = if matches!(e.kind, EP_INTERRUPT | EP_ISOCH) { mps } else { 0 };
            input.write::<u32>(ctx + 16, avg | (esit << 16));
            out.push(Arc::new(Endpoint {
                dci,
                ring: IrqSpinLock::new(ring),
                streams: stream_rings,
                _stream_array: array,
            }));
        }
        // Input control context: add the slot and the endpoints; the slot
        // context comes from the output context with more entries.
        input.write::<u32>(4, add);
        for dw in 0..4 {
            input.write::<u32>(cs + 4 * dw, self.out_ctx.read::<u32>(4 * dw));
        }
        let d0 = input.read::<u32>(cs);
        input.write::<u32>(cs, (d0 & !(0x1F << 27)) | (u32::from(max_dci) << 27));
        let p = input.phys();
        let c = self.hc.command([
            p as u32,
            (p >> 32) as u32,
            0,
            (TRB_CONFIGURE_ENDPOINT << 10) | (u32::from(self.slot) << 24),
        ])?;
        if c.code != CC_SUCCESS {
            log_warn!("USB slot {}: Configure Endpoint failed ({})", self.slot, c.code);
            return None;
        }
        Some(out)
    }

    /// Tell the controller this device is a hub with `ports` ports and
    /// think time `ttt` (slot context Hub, Number of Ports and TTT fields,
    /// set with Configure Endpoint; xHCI §4.5.2, §6.2.2).
    pub fn configure_hub(&self, ports: u8, ttt: u32) -> bool {
        let cs = self.hc.ctx_size;
        let Some(input) = Dma::new(cs * 33) else { return false };
        input.write::<u32>(4, 1);
        for dw in 0..4 {
            input.write::<u32>(cs + 4 * dw, self.out_ctx.read::<u32>(4 * dw));
        }
        input.write::<u32>(cs, input.read::<u32>(cs) | (1 << 26));
        let d1 = input.read::<u32>(cs + 4) & 0x00FF_FFFF;
        input.write::<u32>(cs + 4, d1 | (u32::from(ports) << 24));
        let d2 = input.read::<u32>(cs + 8) & !(3 << 16);
        input.write::<u32>(cs + 8, d2 | ((ttt & 3) << 16));
        // The slot state and device address (dword 3) are the
        // controller's; leave them zero in the input.
        input.write::<u32>(cs + 12, 0);
        let p = input.phys();
        let c = self.hc.command([
            p as u32,
            (p >> 32) as u32,
            0,
            (TRB_CONFIGURE_ENDPOINT << 10) | (u32::from(self.slot) << 24),
        ]);
        matches!(c, Some(c) if c.code == CC_SUCCESS)
    }

    /// Clear a halted (stalled) endpoint: Reset Endpoint, move the
    /// dequeue pointer past the failed TD, CLEAR_FEATURE(ENDPOINT_HALT)
    /// (§4.6.8, §4.6.10, USB 2.0 §9.4.1).
    /// After a failed control transfer: Reset Endpoint on endpoint 0, and
    /// its dequeue pointer past what was queued (§4.6.8, §4.6.10). The
    /// device clears a control endpoint's stall itself at the next setup
    /// (USB 2.0 §8.5.3.4).
    fn reset_control(&self) {
        let target = (1u32 << 16) | (u32::from(self.slot) << 24);
        let _ = self.hc.command([0, 0, 0, (TRB_RESET_ENDPOINT << 10) | target]);
        let deq = self.ep0.ring.lock().enqueue_pointer();
        let _ = self.hc.command([deq as u32, (deq >> 32) as u32, 0, (TRB_SET_DEQUEUE << 10) | target]);
    }

    pub fn clear_halt(&self, ep: &Endpoint, address: u8) {
        let target = (u32::from(ep.dci) << 16) | (u32::from(self.slot) << 24);
        let _ = self.hc.command([0, 0, 0, (TRB_RESET_ENDPOINT << 10) | target]);
        let deq = ep.ring.lock().enqueue_pointer();
        let _ = self.hc.command([deq as u32, (deq >> 32) as u32, 0, (TRB_SET_DEQUEUE << 10) | target]);
        let _ = self.control(RT_ENDPOINT_OUT, REQ_CLEAR_FEATURE, FEATURE_ENDPOINT_HALT, u16::from(address), &mut []);
    }
}

/// Take the controller from firmware (§4.22.1, §7.1): set the OS-owned
/// semaphore, wait for the BIOS one to clear, and turn off SMIs.
fn bios_handoff(cap: Mmio, xecp: usize) {
    let mut off = xecp;
    for _ in 0..64 {
        if off == 0 {
            return;
        }
        let v = cap.read32(off);
        if v & 0xFF == XCAP_LEGACY {
            cap.write32(off, v | LEGACY_OS_OWNED);
            if !wait_for(1000, || cap.read32(off) & LEGACY_BIOS_OWNED == 0) {
                log_warn!("xHCI: firmware keeps the controller; taking it anyway");
                cap.write32(off, cap.read32(off) & !LEGACY_BIOS_OWNED);
            }
            // USBLEGCTLSTS: SMI enables off, status bits cleared.
            cap.write32(off + 4, 0xE000_0000);
            return;
        }
        let next = ((v >> 8) & 0xFF) as usize;
        off = if next == 0 { 0 } else { off + 4 * next };
    }
}

/// Each port's protocol: its revision, BCD (`0x0200`, `0x0310`; 0 for no
/// port), and the fastest speed it lists in Mbit/s (0: none listed). From
/// the Supported Protocol capabilities (§7.2.2.1: the major revision in
/// bits 31:24 and the minor in 23:16 of the first word; the ports covered
/// and the count of Protocol Speed ID words in the third; those words from
/// the fifth on, each a mantissa in bits 31:16 and an exponent in 5:4,
/// 0 for bit/s to 3 for Gbit/s).
fn port_protocols(cap: Mmio, xecp: usize) -> [(u16, u32); 256] {
    let mut revs = [(0u16, 0u32); 256];
    let mut off = xecp;
    for _ in 0..64 {
        if off == 0 {
            break;
        }
        let v = cap.read32(off);
        if v & 0xFF == XCAP_PROTOCOL {
            let ports = cap.read32(off + 8);
            let (first, count) = ((ports & 0xFF) as usize, ((ports >> 8) & 0xFF) as usize);
            let fastest = (0..(ports >> 28) as usize)
                .map(|i| {
                    let psi = cap.read32(off + 0x10 + 4 * i);
                    let mantissa = u64::from(psi >> 16);
                    mantissa * [1, 1_000, 1_000_000, 1_000_000_000][((psi >> 4) & 3) as usize] / 1_000_000
                })
                .max()
                .unwrap_or(0) as u32;
            for slot in revs.iter_mut().take((first + count).min(256)).skip(first) {
                *slot = ((v >> 16) as u16, fastest);
            }
        }
        let next = ((v >> 8) & 0xFF) as usize;
        off = if next == 0 { 0 } else { off + 4 * next };
    }
    revs
}

pub fn probe(pci: Arc<Device>) -> Option<()> {
    pci.enable();
    let cap = Mmio(pci.map_bar(0)?);
    let caplen = (cap.read32(CAPLENGTH) & 0xFF) as usize;
    // SAFETY: The operational, runtime and doorbell registers lie inside
    // BAR 0 at the offsets the capability registers give.
    let (op, rt, db) = unsafe {
        (
            Mmio(cap.0.add(caplen)),
            Mmio(cap.0.add((cap.read32(RTSOFF) & !0x1F) as usize)),
            Mmio(cap.0.add((cap.read32(DBOFF) & !3) as usize)),
        )
    };
    let hcs1 = cap.read32(HCSPARAMS1);
    let hcs2 = cap.read32(HCSPARAMS2);
    let hcc1 = cap.read32(HCCPARAMS1);
    if hcc1 & 1 == 0 {
        log_warn!("xHCI {:?}: no 64-bit addressing; not supported", pci.address);
        return None;
    }
    let max_slots = (hcs1 & 0xFF) as u8;
    let max_ports = (hcs1 >> 24) as u8;
    let xecp = ((hcc1 >> 16) as usize) * 4;
    bios_handoff(cap, xecp);

    // Stop, then reset (§4.2).
    if op.read32(USBSTS) & STS_HCH == 0 {
        op.write32(USBCMD, op.read32(USBCMD) & !CMD_RUN);
        wait_for(100, || op.read32(USBSTS) & STS_HCH != 0);
    }
    op.write32(USBCMD, CMD_HCRST);
    delay_ms(1);
    if !wait_for(1000, || op.read32(USBCMD) & CMD_HCRST == 0 && op.read32(USBSTS) & STS_CNR == 0) {
        log_warn!("xHCI {:?}: reset does not finish", pci.address);
        return None;
    }

    let ctx_size = if hcc1 & (1 << 2) != 0 { 64 } else { 32 };
    op.write32(CONFIG, u32::from(max_slots));
    let dcbaa = Dma::new((usize::from(max_slots) + 1) * 8)?;
    // Scratchpad buffers the controller asked for (§4.20).
    let scratch_count = (((hcs2 >> 21) & 0x1F) << 5 | (hcs2 >> 27)) as usize;
    let mut scratchpad = Vec::new();
    if scratch_count > 0 {
        let array = Dma::new(scratch_count * 8)?;
        for i in 0..scratch_count {
            let page = Dma::new(4096)?;
            array.write::<u64>(i * 8, page.phys());
            scratchpad.push(page);
        }
        dcbaa.write::<u64>(0, array.phys());
        scratchpad.push(array);
    }
    op.write64(DCBAAP, dcbaa.phys());
    let cmd = Ring::new()?;
    op.write64(CRCR, cmd.phys() | 1);

    // One event ring segment for interrupter 0.
    let events = Dma::new(RING_TRBS * 16)?;
    let erst = Dma::new(64)?;
    erst.write::<u64>(0, events.phys());
    erst.write::<u32>(8, RING_TRBS as u32);
    rt.write32(ERSTSZ, 1);
    rt.write64(ERDP, events.phys());
    rt.write64(ERSTBA, erst.phys());
    scratchpad.push(erst);

    let protocols = port_protocols(cap, xecp);
    let usb2 = protocols.map(|(r, _)| r >> 8 == 2);
    let slot: Arc<Once<Arc<Xhci>>> = Arc::new(Once::new());
    let irq_slot = slot.clone();
    let mode = pci.enable_interrupt(
        "xhci",
        Box::new(move || {
            if let Some(h) = irq_slot.get() {
                h.interrupt();
            }
        }),
    );
    let hc = Arc::new(Xhci {
        op,
        rt,
        db,
        ctx_size,
        max_psa: ((hcc1 >> 12) & 0xF) as u8,
        max_ports,
        usb2,
        sys: super::sys::Controller::new(pci.address, &protocols[..=usize::from(max_ports)], &usb2),
        dcbaa,
        cmd: IrqSpinLock::new(cmd),
        events: IrqSpinLock::new(EventRing { dma: events, idx: 0, cycle: true }),
        done: IrqSpinLock::new(BTreeMap::new()),
        waiters: WaitQueue::new(),
        pipes: IrqSpinLock::new(BTreeMap::new()),
        interrupts: mode.is_some(),
        port_change: AtomicBool::new(true),
        enum_waiters: WaitQueue::new(),
        _scratchpad: scratchpad,
    });
    slot.call_once(|| hc.clone());
    // Interrupt moderation 250 µs; interrupts on.
    rt.write32(IMOD, 1000);
    rt.write32(IMAN, IMAN_IE | IMAN_IP);
    op.write32(USBCMD, CMD_RUN | if hc.interrupts { CMD_INTE } else { 0 });
    if !wait_for(100, || op.read32(USBSTS) & STS_HCH == 0) {
        log_warn!("xHCI {:?}: does not start", pci.address);
        return None;
    }
    // Power every port (when the controller switches port power).
    for p in 1..=max_ports {
        let r = hc.portsc(p);
        let v = op.read32(r);
        if v & PORT_PP == 0 {
            op.write32(r, (v & PORT_PRESERVE_MASK) | PORT_PP);
        }
    }
    log_info!(
        "xHCI {:?}: {max_slots} slots, {max_ports} ports, {}-byte contexts, {}",
        pci.address,
        ctx_size,
        mode.unwrap_or("polled")
    );
    if !hc.interrupts {
        let poll = hc.clone();
        crate::sched::spawn("xhci-poll", move || {
            loop {
                poll.process_events();
                crate::time::sleep_ns(5_000_000);
            }
        });
    }
    let e = hc.clone();
    crate::sched::spawn("usb", move || enumerate(e));
    Some(())
}

/// The enumeration thread: attach devices on connected ports, forget them
/// when they go, whenever a port changes.
fn enumerate(hc: Arc<Xhci>) {
    let mut attached: BTreeMap<u8, Arc<UsbDevice>> = BTreeMap::new();
    let mut hubs: Vec<Arc<super::hub::Hub>> = Vec::new();
    // Ports whose device was removed on request: left alone until it is
    // unplugged.
    let mut parked: alloc::collections::BTreeSet<u8> = alloc::collections::BTreeSet::new();
    // Give devices on ports powered just now time to connect (USB 2.0
    // §7.1.7.3: 100 ms debounce).
    delay_ms(100);
    loop {
        hc.port_change.store(false, Ordering::Release);
        // Devices whose removal was asked for: forgotten, and their port
        // disabled (xHCI 1.2 §4.19.1.2: writing 1 to PED disables a port;
        // the device stays connected but gets no traffic).
        let asked: Vec<u8> =
            attached.iter().filter(|(_, d)| d.removal.load(Ordering::Acquire)).map(|(p, _)| *p).collect();
        for p in asked {
            if let Some(d) = attached.remove(&p) {
                detach(&d);
                let r = hc.portsc(p);
                let v = hc.op.read32(r);
                hc.op.write32(r, (v & PORT_PRESERVE_MASK) | PORT_PED);
                parked.insert(p);
                log_info!("USB port {p}: disabled; unplug the device to use the port again");
            }
        }
        for p in 1..=hc.max_ports {
            let r = hc.portsc(p);
            let v = hc.op.read32(r);
            // Acknowledge the change bits.
            if v & PORT_RW1C != 0 {
                hc.op.write32(r, (v & PORT_PRESERVE_MASK) | (v & PORT_RW1C));
            }
            let connected = v & PORT_CCS != 0;
            if !connected {
                parked.remove(&p);
            }
            match (connected, attached.contains_key(&p)) {
                (true, false) if parked.contains(&p) => {}
                (true, false) => {
                    delay_ms(100);
                    match attach(&hc, p) {
                        Some((d, hub)) => {
                            attached.insert(p, d);
                            hubs.extend(hub);
                        }
                        None => log_warn!("USB port {p}: device not set up"),
                    }
                }
                (false, true) => {
                    if let Some(d) = attached.remove(&p) {
                        detach(&d);
                    }
                }
                _ => {}
            }
        }
        // Hubs: forget those that went away (and what hung off them), and
        // look at the ports of the others.
        let mut i = 0;
        while i < hubs.len() {
            if hubs[i].dev.gone.load(Ordering::Acquire) {
                hubs.remove(i).detach_all();
                continue;
            }
            let found = hubs[i].poll(&hc);
            hubs.extend(found);
            i += 1;
        }
        if hubs.iter().all(|h| h.reports_changes()) {
            // Hubs say when a port changes (their status-change endpoint).
            hc.enum_waiters.wait_until(|| hc.port_change.load(Ordering::Acquire));
        } else {
            // A hub without one is polled.
            let deadline = crate::time::monotonic_ns() + 500_000_000;
            hc.enum_waiters.wait_until_timeout(|| hc.port_change.load(Ordering::Acquire), deadline);
        }
    }
}

/// Ask for `d` to be removed as if unplugged (its port disabled), and
/// wait for it: whether it went within `timeout_ms`.
pub fn request_removal(d: &Arc<UsbDevice>, timeout_ms: u64) -> bool {
    d.removal.store(true, Ordering::Release);
    d.hc.port_change.store(true, Ordering::Release);
    d.hc.enum_waiters.wake_all();
    wait_for(timeout_ms, || d.gone.load(Ordering::Acquire))
}

pub fn detach(d: &Arc<UsbDevice>) {
    log_info!("USB port {}: device removed", d.port);
    d.gone.store(true, Ordering::Release);
    // A network card that was on this device loses its link at once.
    crate::net::links_changed();
    super::sys::removed(&d.hc.sys, &d.port);
    super::msc::detached(d);
    super::btusb::detached(d);
    super::hid::detached(d);
    super::audio::detached(d);
    d.hc.drop_pipes(d.slot);
    let _ = d.hc.command([0, 0, 0, (TRB_DISABLE_SLOT << 10) | (u32::from(d.slot) << 24)]);
    d.hc.dcbaa.write::<u64>(usize::from(d.slot) * 8, 0);
}

/// The USB scenario's check that a stalled control transfer leaves
/// endpoint 0 usable (`usb.stall_test` on the command line): ask for an
/// interface descriptor with GET_DESCRIPTOR, which every device must
/// stall (USB 2.0 §9.4.3: only device, configuration and string
/// descriptors are asked for so), then for the device descriptor at once.
fn stall_test(dev: &UsbDevice) {
    const DESC_INTERFACE: u8 = 4;
    let started = crate::time::monotonic_ns();
    let refused = dev.descriptor(DESC_INTERFACE, &mut [0u8; 9]);
    let mut d = [0u8; 18];
    let after = dev.descriptor(DESC_DEVICE, &mut d);
    let ms = (crate::time::monotonic_ns() - started) / 1_000_000;
    log_info!(
        "USB port {}: stall test: interface descriptor {}, then the device descriptor {} ({ms} ms)",
        dev.port,
        match refused {
            Ok(_) => "read",
            Err(CC_STALL) => "stalled",
            Err(_) => "failed",
        },
        if after == Ok(18) { "read" } else { "not read" }
    );
}

/// idVendor and idProduct from a device descriptor (USB 2.0 §9.6.1).
fn ids(desc: &[u8]) -> (u16, u16) {
    let w = |i: usize| desc.get(i..i + 2).map_or(0, |b| u16::from_le_bytes([b[0], b[1]]));
    (w(8), w(10))
}

/// The class driver a hub device got, with the device.
pub type Attached = (Arc<UsbDevice>, Option<Arc<super::hub::Hub>>);

/// Reset and enable a root port, then set up the device on it.
fn attach(hc: &Arc<Xhci>, port: u8) -> Option<Attached> {
    let r = hc.portsc(port);
    if hc.usb2[usize::from(port)] {
        let v = hc.op.read32(r);
        hc.op.write32(r, (v & PORT_PRESERVE_MASK) | PORT_PR);
        if !wait_for(500, || hc.op.read32(r) & PORT_PRC != 0) {
            return None;
        }
        let v = hc.op.read32(r);
        hc.op.write32(r, (v & PORT_PRESERVE_MASK) | PORT_PRC);
        // Reset recovery (USB 2.0 §7.1.7.5: 10 ms).
        delay_ms(10);
    } else if !wait_for(1000, || hc.op.read32(r) & PORT_PED != 0) {
        // A USB 3 link that did not train: a warm reset.
        let v = hc.op.read32(r);
        hc.op.write32(r, (v & PORT_PRESERVE_MASK) | PORT_WPR);
        wait_for(1000, || hc.op.read32(r) & PORT_PED != 0);
    }
    let v = hc.op.read32(r);
    if v & PORT_PED == 0 {
        return None;
    }
    let speed = (v >> 10) & 0xF;
    let pos = Position { root_port: port, route: 0, depth: 0, tt: None };
    setup(hc, pos, speed, alloc::format!("{port}"))
}

/// Address the device at `pos` (its port already reset and enabled), read
/// its descriptors, set its configuration and start the class drivers it
/// has.
pub fn setup(hc: &Arc<Xhci>, pos: Position, speed: u32, port: String) -> Option<Attached> {
    let c = hc.command([0, 0, 0, TRB_ENABLE_SLOT << 10])?;
    if c.code != CC_SUCCESS {
        return None;
    }
    let slot = c.slot;
    let cs = hc.ctx_size;
    let out_ctx = Dma::new(cs * 32)?;
    hc.dcbaa.write::<u64>(usize::from(slot) * 8, out_ctx.phys());
    let ep0_ring = Ring::new()?;
    let mps0: u32 = match speed {
        SPEED_LOW | SPEED_FULL => 8,
        SPEED_HIGH => 64,
        _ => 512,
    };
    // Input context: add the slot and endpoint 0 (§4.3.3).
    let input = Dma::new(cs * 33)?;
    input.write::<u32>(4, 0b11);
    input.write::<u32>(cs, (1 << 27) | (speed << 20) | (pos.route & 0xF_FFFF));
    input.write::<u32>(cs + 4, u32::from(pos.root_port) << 16);
    if let Some((hub_slot, hub_port)) = pos.tt {
        input.write::<u32>(cs + 8, u32::from(hub_slot) | (u32::from(hub_port) << 8));
    }
    input.write::<u32>(2 * cs + 4, (3 << 1) | (EPT_CONTROL << 3) | (mps0 << 16));
    input.write::<u64>(2 * cs + 8, ep0_ring.phys() | 1);
    input.write::<u32>(2 * cs + 16, 8);
    let p = input.phys();
    let c = hc.command([p as u32, (p >> 32) as u32, 0, (TRB_ADDRESS_DEVICE << 10) | (u32::from(slot) << 24)])?;
    if c.code != CC_SUCCESS {
        log_warn!("USB port {port}: Address Device failed ({})", c.code);
        let _ = hc.command([0, 0, 0, (TRB_DISABLE_SLOT << 10) | (u32::from(slot) << 24)]);
        return None;
    }
    let devnum = super::sys::take_devnum(&hc.sys, &port);
    let dev = Arc::new(UsbDevice {
        hc: hc.clone(),
        slot,
        port: port.clone(),
        pos,
        speed,
        devnum,
        config_value: AtomicU8::new(0),
        maxchild: Arc::new(AtomicU8::new(0)),
        out_ctx,
        ep0: Endpoint { dci: 1, ring: IrqSpinLock::new(ep0_ring), streams: Vec::new(), _stream_array: None },
        ctrl_buf: Mutex::new(Dma::new(4096)?),
        gone: AtomicBool::new(false),
        removal: AtomicBool::new(false),
    });

    // The first 8 bytes of the device descriptor give endpoint 0's real
    // packet size; full-speed devices may need it changed (§4.6.7).
    let mut desc = [0u8; 18];
    dev.descriptor(DESC_DEVICE, &mut desc[..8]).ok()?;
    if speed == SPEED_FULL && u32::from(desc[7]) != mps0 && desc[7] != 0 {
        input.zero_range(0, cs * 3);
        input.write::<u32>(4, 0b10);
        input.write::<u32>(2 * cs + 4, (3 << 1) | (EPT_CONTROL << 3) | (u32::from(desc[7]) << 16));
        let _ = hc.command([p as u32, (p >> 32) as u32, 0, (TRB_EVALUATE_CONTEXT << 10) | (u32::from(slot) << 24)]);
    }
    dev.descriptor(DESC_DEVICE, &mut desc).ok()?;
    if crate::boot::info().cmdline.split_ascii_whitespace().any(|w| w == "usb.stall_test") {
        stall_test(&dev);
    }
    let (vendor, product) = (u16::from_le_bytes([desc[8], desc[9]]), u16::from_le_bytes([desc[10], desc[11]]));
    // A device may offer several configurations (a USB Ethernet adapter
    // its vendor one first and the CDC one second): take the first with
    // an interface Slate drives, else the first.
    let configs: Vec<slate_usb::Configuration> = (0..desc[17].max(1)).filter_map(|i| dev.configuration(i)).collect();
    let usable =
        |c: &&slate_usb::Configuration| c.interfaces.iter().any(|i| supported(i.class, i.subclass, i.protocol));
    let config = configs.iter().find(usable).or(configs.first())?.clone();
    if configs.len() > 1 {
        log_info!("USB port {port}: {} configurations; using {}", configs.len(), config.value);
    }
    let interfaces = first_alternates(&config);
    dev.control(RT_DEVICE_OUT, REQ_SET_CONFIGURATION, u16::from(config.value), 0, &mut []).ok()?;
    dev.config_value.store(config.value, Ordering::Relaxed);
    // Its strings in its first language (string descriptor 0 lists them),
    // and its place in sysfs.
    let mut langs = [0u8; 4];
    let lang = match dev.descriptor(slate_usb::DESC_STRING, &mut langs) {
        Ok(4) => u16::from_le_bytes([langs[2], langs[3]]),
        _ => 0x0409,
    };
    let strings = [desc[14], desc[15], desc[16]].map(|i| dev.string(i, lang));
    let interface_strings = config
        .interfaces
        .iter()
        .filter(|i| i.alt == 0)
        .filter_map(|i| Some((i.number, dev.string(i.string, lang)?)))
        .collect();
    super::sys::added(
        &hc.sys,
        &super::sys::Added {
            port: &port,
            devnum,
            speed_id: speed,
            device: &desc,
            config: &config,
            strings: strings.clone(),
            interface_strings,
            maxchild: dev.maxchild.clone(),
        },
    );
    log_info!(
        "USB port {port}: {vendor:04x}:{product:04x}, slot {slot}, {}",
        match speed {
            SPEED_LOW => "low speed",
            SPEED_FULL => "full speed",
            SPEED_HIGH => "high speed",
            _ => "SuperSpeed",
        }
    );
    let mut hub = None;
    for iface in &interfaces {
        let driver = match iface.class {
            3 => "usb-hid",
            8 => "usb-storage",
            9 => "usb-hub",
            0xE0 => "btusb",
            _ => "",
        };
        if !driver.is_empty() && !crate::drivers::enabled(driver) {
            log_info!("USB port {}: interface {} left alone ({driver} disabled)", dev.port, iface.number);
            continue;
        }
        match (iface.class, iface.subclass, iface.protocol) {
            // HID, boot interface subclass, keyboard (HID 1.11 §4.2-§4.3).
            (3, 1, 1) => {
                super::hid::start(&dev, iface, ids(&desc));
                dev.bound(iface.number, "usb-hid");
            }
            // HID, boot interface subclass, mouse.
            (3, 1, 2) => {
                super::hid::start_mouse(&dev, iface, ids(&desc));
                dev.bound(iface.number, "usb-hid");
            }
            // Other HID devices (tablets, mice outside the boot subclass):
            // their report descriptor says what their reports hold.
            (3, _, _) => {
                if super::hid::start_report(&dev, iface, ids(&desc)) {
                    dev.bound(iface.number, "usb-hid");
                }
            }
            // A Bluetooth primary controller (Core 5.4, Vol 4, Part B).
            (0xE0, 1, 1) => super::btusb::start(&dev, iface, ids(&desc)),
            // Audio: the control interface leads to the whole function
            // (Audio Class 1.0, ADR 0184).
            (1, 1, _) if crate::drivers::enabled("usb-audio") => {
                let place = super::sys::place(&hc.sys, &port);
                let (sys_name, sys_path) = place.map(|(_, n, p)| (n, p)).unwrap_or_default();
                let names = super::audio::Names {
                    maker: strings[0].as_deref(),
                    product: strings[1].as_deref(),
                    sys_path: &sys_path,
                    sys_name: &sys_name,
                };
                if super::audio::start(&dev, &config, &names) {
                    dev.bound(iface.number, "snd-usb-audio");
                }
            }
            // Mass storage, SCSI transparent command set, Bulk-Only.
            (8, 6, 0x50 | 0x62) => super::msc::start(&dev, iface, &config),
            // A hub (USB 2.0 §11.23.1).
            (9, _, _) if hub.is_none() => {
                hub = super::hub::start(&dev, desc[6], iface);
                if hub.is_some() {
                    dev.bound(iface.number, "usb-hub");
                }
            }
            _ => {}
        }
    }
    // A CDC Ethernet function spans two interfaces (and an alternate
    // setting).
    if let Some(f) = slate_usb::ecm::find(&config)
        && crate::drivers::enabled("usb-ecm")
    {
        super::ecm::start(&dev, &f);
    }
    Some((dev, hub))
}
