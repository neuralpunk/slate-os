// SPDX-License-Identifier: MIT OR Apache-2.0

//! Realtek RTL8139 Fast Ethernet controllers (QEMU's `-device rtl8139`,
//! the default card of libvirt and GNOME Boxes for unknown systems).
//!
//! Sources: the Realtek RTL8139D(L) datasheet (register map §5: IDR,
//! TSD0-3 and TSAD0-3, RBSTART, CR, CAPR, IMR and ISR, TCR, RCR, CONFIG1,
//! MSR; the receive buffer and its packet headers §6.1; transmission
//! through four descriptors §6.2) and the RTL8139 programming guide's
//! initialization order.
//!
//! Reception goes into one 8 KiB ring (WRAP set, so a packet never splits
//! at its end); transmission round-robins four 2 KiB buffers. The card
//! addresses memory with 32 bits, so both live below 4 GiB. QEMU's has no
//! MSI: its legacy interrupt is routed through the firmware's `_PRT` (ADR
//! 0079), and without a route the network thread polls.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use slate_net::Mac;

use super::dma::{Dma, wait_for};
use super::pci::{Bar, Device};
use crate::arch::port::{Port8, Port16, Port32};
use crate::net::NetDevice;
use crate::sync::IrqSpinLock;
use crate::{log_info, log_warn};

/// PCI vendor and device (the datasheet's PCI configuration space).
pub const VENDOR: u16 = 0x10EC;
pub const DEVICE: u16 = 0x8139;

// Registers (offsets in the I/O BAR).
const IDR0: u16 = 0x00;
const TSD0: u16 = 0x10;
const TSAD0: u16 = 0x20;
const RBSTART: u16 = 0x30;
const CR: u16 = 0x37;
const CAPR: u16 = 0x38;
const IMR: u16 = 0x3C;
/// IMR: receive OK and error, transmit OK and error, receive buffer
/// overflow, link change, receive FIFO overflow (datasheet §5, IMR bits
/// 0 to 6).
const IMR_VALUE: u16 = 0x007F;
const ISR: u16 = 0x3E;
const TCR: u16 = 0x40;
const RCR: u16 = 0x44;
/// MAR0-7: the multicast hash filter; all ones takes every multicast
/// frame (IPv6 neighbour discovery needs its groups).
const MAR0: u16 = 0x08;
const CONFIG1: u16 = 0x52;
const MSR: u16 = 0x58;

const CR_RST: u8 = 0x10;
const CR_RE: u8 = 0x08;
const CR_TE: u8 = 0x04;
const CR_BUFE: u8 = 0x01;
/// TSD: the card is done with the buffer; the frame went out.
const TSD_OWN: u32 = 1 << 13;
/// RCR: accept broadcast, multicast and our own address; WRAP; unlimited
/// DMA bursts; an 8 KiB + 16 byte ring; no receive FIFO threshold.
const RCR_VALUE: u32 = 0x08 | 0x04 | 0x02 | 0x80 | (7 << 8) | (7 << 13);
/// TCR: the standard interframe gap, 2 KiB DMA bursts.
const TCR_VALUE: u32 = (3 << 24) | (7 << 8);
/// MSR: link down when set.
const MSR_LINKB: u8 = 0x04;
/// The receive status's "received OK".
const RX_ROK: u16 = 0x0001;

const RX_RING: usize = 8192;
/// The ring, the 16 bytes the card may write past it, and room for a whole
/// frame past its end (WRAP).
const RX_BYTES: usize = RX_RING + 16 + 1536;
const TX_SLOTS: usize = 4;
const TX_BUF: usize = 2048;

struct Rx {
    /// Where the next packet's header is in the ring.
    offset: usize,
}

struct Tx {
    next: usize,
    /// Slots handed to the card and not yet seen done.
    busy: [bool; TX_SLOTS],
}

pub struct Rtl8139 {
    name: String,
    mac: Mac,
    io: u16,
    rx_buf: Dma,
    tx_bufs: Dma,
    rx: IrqSpinLock<Rx>,
    tx: IrqSpinLock<Tx>,
}

impl Rtl8139 {
    fn r8(&self, off: u16) -> Port8 {
        // SAFETY: Ports inside this card's I/O BAR; the card's DMA targets
        // are only ever buffers this driver owns.
        unsafe { Port8::new(self.io + off) }
    }
    fn r16(&self, off: u16) -> Port16 {
        // SAFETY: As in `r8`.
        unsafe { Port16::new(self.io + off) }
    }
    fn r32(&self, off: u16) -> Port32 {
        // SAFETY: As in `r8`.
        unsafe { Port32::new(self.io + off) }
    }

    /// Restart reception after a bad packet header (the programming
    /// guide's recovery: receiver off and on, the ring from its start).
    fn reset_rx(&self, rx: &mut Rx) {
        self.r8(CR).write(CR_TE);
        self.r32(RBSTART).write(self.rx_buf.phys() as u32);
        self.r32(RCR).write(RCR_VALUE);
        self.r8(CR).write(CR_RE | CR_TE);
        rx.offset = 0;
    }
}

impl NetDevice for Rtl8139 {
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> Mac {
        self.mac
    }
    fn mtu(&self) -> usize {
        1500
    }

    fn send(&self, frame: &[u8]) {
        if frame.len() > 1514 {
            return;
        }
        let mut tx = self.tx.lock();
        let t = tx.next;
        let tsd = TSD0 + 4 * t as u16;
        if tx.busy[t] {
            if self.r32(tsd).read() & TSD_OWN == 0 {
                return; // All four in flight: drop.
            }
            tx.busy[t] = false;
        }
        // Short frames are padded to the 60-byte minimum.
        let len = frame.len().max(60);
        self.tx_bufs.copy_in(t * TX_BUF, frame);
        if frame.len() < len {
            self.tx_bufs.copy_in(t * TX_BUF + frame.len(), &[0u8; 60][..len - frame.len()]);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.r32(TSAD0 + 4 * t as u16).write((self.tx_bufs.phys() + (t * TX_BUF) as u64) as u32);
        // Writing the size with OWN clear starts the transmission.
        self.r32(tsd).write(len as u32);
        tx.busy[t] = true;
        tx.next = (t + 1) % TX_SLOTS;
    }

    fn receive(&self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        let mut rx = self.rx.lock();
        // Acknowledge whatever the card flagged (write 1 to clear).
        let isr = self.r16(ISR).read();
        if isr != 0 {
            self.r16(ISR).write(isr);
        }
        while self.r8(CR).read() & CR_BUFE == 0 && frames.len() < 64 {
            let o = rx.offset;
            let status: u16 = self.rx_buf.read(o);
            let len = usize::from(self.rx_buf.read::<u16>(o + 2));
            // The length counts the 4-byte CRC.
            if status & RX_ROK == 0 || !(64..=1522).contains(&len) {
                log_warn!("{}: bad receive header {status:#06x}, length {len}; restarting reception", self.name);
                self.reset_rx(&mut rx);
                break;
            }
            let mut f = alloc::vec![0u8; len - 4];
            self.rx_buf.copy_out(o + 4, &mut f);
            frames.push(f);
            rx.offset = (o + 4 + len + 3) & !3;
            if rx.offset >= RX_RING {
                rx.offset -= RX_RING;
            }
            // CAPR trails the read offset by 16 (the datasheet's quirk).
            self.r16(CAPR).write((rx.offset as u16).wrapping_sub(16));
        }
        frames
    }

    fn link_up(&self) -> bool {
        self.r8(MSR).read() & MSR_LINKB == 0
    }
}

pub fn probe(pci: Arc<Device>) -> Option<()> {
    pci.enable();
    let Some(Bar::Io { port: io, .. }) = pci.bars[0] else {
        log_warn!("rtl8139 {:?}: no I/O BAR", pci.address);
        return None;
    };
    let rx_buf = Dma::new_below_4g(RX_BYTES)?;
    let tx_bufs = Dma::new_below_4g(TX_SLOTS * TX_BUF)?;
    let mut mac = [0u8; 6];
    let dev = Rtl8139 {
        name: crate::net::next_name(),
        mac: Mac(mac),
        io,
        rx_buf,
        tx_bufs,
        rx: IrqSpinLock::new(Rx { offset: 0 }),
        tx: IrqSpinLock::new(Tx { next: 0, busy: [false; TX_SLOTS] }),
    };
    // Power on (CONFIG1 LWAKE/LWPTN), then a software reset.
    dev.r8(CONFIG1).write(0);
    dev.r8(CR).write(CR_RST);
    if !wait_for(100, || dev.r8(CR).read() & CR_RST == 0) {
        log_warn!("rtl8139 {:?}: did not come out of reset", pci.address);
        return None;
    }
    for (i, b) in mac.iter_mut().enumerate() {
        *b = dev.r8(IDR0 + i as u16).read();
    }
    let dev = Rtl8139 { mac: Mac(mac), ..dev };
    dev.r32(RBSTART).write(dev.rx_buf.phys() as u32);
    dev.r16(IMR).write(0);
    dev.r8(CR).write(CR_RE | CR_TE);
    dev.r32(RCR).write(RCR_VALUE);
    dev.r32(MAR0).write(u32::MAX);
    dev.r32(MAR0 + 4).write(u32::MAX);
    dev.r32(TCR).write(TCR_VALUE);
    // The interrupt (level-triggered, maybe shared): the card's own status
    // says whether it was this card; writing it back clears it and lowers
    // the line.
    let isr_port = io + ISR;
    let gsi = pci.enable_intx(
        "rtl8139",
        alloc::boxed::Box::new(move || {
            // SAFETY: ISR in the card's I/O BAR, which only this driver uses.
            let isr = unsafe { Port16::new(isr_port) };
            let v = isr.read();
            if v != 0 {
                isr.write(v);
                crate::net::wake();
            }
        }),
    );
    if gsi.is_some() {
        dev.r16(IMR).write(IMR_VALUE);
    }
    let how = gsi.map_or(String::from("polled"), |g| alloc::format!("INTx on GSI {g}"));
    log_info!(
        "rtl8139 {:?}: {}, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, link {}, {how}",
        pci.address,
        dev.name,
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5],
        if dev.link_up() { "up" } else { "down" }
    );
    crate::net::register(Arc::new(dev), gsi.is_some());
    Some(())
}
