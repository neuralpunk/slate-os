// SPDX-License-Identifier: MIT OR Apache-2.0

//! Intel gigabit Ethernet controllers of the igb family: the I211 (the
//! reference PC's six ports), the I210, and the 82576 that QEMU emulates
//! (`-device igb`).
//!
//! Sources: the Intel 82576EB Gigabit Ethernet Controller Datasheet and the
//! Intel Ethernet Controller I210/I211 Datasheet (register maps; device
//! reset §4.3; receive and transmit initialization §4.5.9-§4.5.10;
//! advanced one-buffer receive descriptors §7.1.5 and legacy transmit
//! descriptors §7.2.2; interrupt causes and
//! MSI-X allocation §7.3; MDIO access through MDIC §8.2) and IEEE 802.3
//! clause 22 for the PHY's control register.
//!
//! One receive and one transmit queue, copying
//! frames through fixed DMA buffers. The internal copper PHY negotiates
//! the link by itself; the driver powers it up and reports link state.
//!
//! TCP segmentation offload (ADR 0083; 82576 datasheet rev. 2.7 §7.2.2.2,
//! §7.2.2.3, §7.2.4): a large TCP segment over IPv4 goes out as an
//! advanced context descriptor (MACLEN, IPLEN, TUCMD IPv4 and TCP, L4LEN,
//! MSS) and a chain of advanced data descriptors (TSE, TXSM and IXSM,
//! PAYLEN the TCP payload) over consecutive buffers; its IPv4 checksum is
//! zeroed and its TCP checksum set to the partial pseudo-header sum
//! without the length (§7.2.4.5, table 7-37), and the card does the rest.
//! Descriptors are given back as the head register (TDH) passes them:
//! context descriptors are not written back.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use slate_net::Mac;
use slate_sync::Once;

use super::dma::{Dma, Mmio, delay_ms, wait_for};
use super::pci::{CAP_MSI, CAP_MSIX, Device};
use crate::net::NetDevice;
use crate::sync::IrqSpinLock;
use crate::{log_info, log_warn};

/// PCI device IDs (vendor 8086h) from the datasheets.
pub const DEVICE_IDS: &[u16] = &[
    0x10C9, 0x10E6, 0x10E7, 0x10E8, 0x150A, 0x150D, 0x1518, 0x1526, // 82576
    0x1533, 0x1536, 0x1537, 0x1538, 0x157B, 0x157C, // I210
    0x1539, // I211
];

// Registers.
const CTRL: usize = 0x0000;
const STATUS: usize = 0x0008;
const EEC: usize = 0x0010;
const EERD: usize = 0x0014;
const CTRL_EXT: usize = 0x0018;
const MDIC: usize = 0x0020;
const RCTL: usize = 0x0100;
const TCTL: usize = 0x0400;
// The interrupt cause and mask registers at their alias offsets (I210
// datasheet §8.1.3 table 8-6 and §8.1.3.1: ICR 0x1500/alias 0x00C0, IMS
// 0x1508/0x00D0, IMC 0x150C/0x00D8; the 82576 has the same aliases).
// QEMU's model implements only the aliases.
const ICR: usize = 0x00C0;
const IMS: usize = 0x00D0;
const IMC: usize = 0x00D8;
const GPIE: usize = 0x1514;
const EIMS: usize = 0x1524;
const EIMC: usize = 0x1528;
const EIAC: usize = 0x152C;
const EIAM: usize = 0x1530;
const EICR: usize = 0x1580;
const IVAR0: usize = 0x1700;
const IVAR_MISC: usize = 0x1740;
const MTA: usize = 0x5200;
const RAL0: usize = 0x5400;
const RAH0: usize = 0x5404;
const RDBAL0: usize = 0xC000;
const RDLEN0: usize = 0xC008;
const SRRCTL0: usize = 0xC00C;
const RDH0: usize = 0xC010;
const RDT0: usize = 0xC018;
const RXDCTL0: usize = 0xC028;
const TDBAL0: usize = 0xE000;
const TDLEN0: usize = 0xE008;
const TDH0: usize = 0xE010;
const TDT0: usize = 0xE018;
const TXDCTL0: usize = 0xE028;

const CTRL_SLU: u32 = 1 << 6;
const CTRL_RST: u32 = 1 << 26;
const STATUS_LU: u32 = 1 << 1;
const EEC_AUTO_RD: u32 = 1 << 9;
const CTRL_EXT_DRV_LOAD: u32 = 1 << 28;
const RAH_AV: u32 = 1 << 31;

const RCTL_EN: u32 = 1 << 1;
const RCTL_BAM: u32 = 1 << 15;
/// Multicast promiscuous: every multicast frame (no filter table yet; IPv6
/// neighbour discovery needs its groups).
const RCTL_MPE: u32 = 1 << 4;
const RCTL_SECRC: u32 = 1 << 26;
/// One 2 KiB buffer per packet, advanced one-buffer descriptors, drop
/// when full.
const SRRCTL_2K_ADV_DROP: u32 = 2 | (1 << 25) | (1 << 31);
const QUEUE_ENABLE: u32 = 1 << 25;
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;
const TCTL_CT: u32 = 0x0F << 4;
const TCTL_COLD: u32 = 0x3F << 12;

// Interrupt causes (ICR/IMS).
const INT_TXDW: u32 = 1 << 0;
const INT_LSC: u32 = 1 << 2;
const INT_RXDMT0: u32 = 1 << 4;
const INT_RXO: u32 = 1 << 6;
const INT_RXT0: u32 = 1 << 7;
const INT_CAUSES: u32 = INT_TXDW | INT_LSC | INT_RXDMT0 | INT_RXO | INT_RXT0;

// Advanced receive write-back (§7.1.5.2): extended status and errors in
// the third dword, length in the fourth.
const RX_DD: u32 = 1 << 0;
const RX_EOP: u32 = 1 << 1;
const RX_ERRORS: u32 = 0xFFF0_0000;
// Legacy transmit descriptor bits.

// MDIC (§8.2.4): data, register, PHY address, opcode, ready, error.
const MDIC_OP_WRITE: u32 = 1 << 26;
const MDIC_OP_READ: u32 = 2 << 26;
const MDIC_READY: u32 = 1 << 28;
const MDIC_ERROR: u32 = 1 << 30;
const PHY_ADDR: u32 = 1;
/// IEEE 802.3 clause 22 control register: power down, autonegotiation
/// enable and restart.
const PHY_CONTROL: u32 = 0;
const BMCR_POWER_DOWN: u16 = 1 << 11;
const BMCR_ANENABLE: u16 = 1 << 12;
const BMCR_ANRESTART: u16 = 1 << 9;

const RING: usize = 256;
const BUF: usize = 2048;

// Advanced transmit descriptors (§7.2.2.2, §7.2.2.3): types, the data
// descriptor's command and options, and the context's TUCMD.
const DTYP_CONTEXT: u64 = 0b0010;
const DTYP_DATA: u64 = 0b0011;
const DCMD_EOP: u64 = 1 << 0;
const DCMD_IFCS: u64 = 1 << 1;
const DCMD_RS: u64 = 1 << 3;
const DCMD_DEXT: u64 = 1 << 5;
const DCMD_TSE: u64 = 1 << 7;
const POPTS_IXSM: u64 = 1 << 0;
const POPTS_TXSM: u64 = 1 << 1;
const TUCMD_IPV4: u64 = 1 << 1;
const TUCMD_L4T_TCP: u64 = 1 << 2;
/// The context descriptor's DEXT (qword 1, bit 29).
const CONTEXT_DEXT: u64 = 1 << 29;
/// The largest TCP payload a large send carries: what fits an IPv4 total
/// length with the largest headers.
const TSO_MAX: usize = 64_000;

struct Rx {
    next: usize,
}

struct Tx {
    tail: usize,
    clean: usize,
    in_flight: usize,
}

pub struct Igb {
    name: String,
    mac: Mac,
    regs: Mmio,
    rx_ring: Dma,
    rx_bufs: Dma,
    tx_ring: Dma,
    tx_bufs: Dma,
    rx: IrqSpinLock<Rx>,
    tx: IrqSpinLock<Tx>,
}

impl Igb {
    fn interrupt(&self) {
        // Reading the cause registers acknowledges them: queue events
        // arrive in EICR, the others (link) in ICR.
        self.regs.read32(EICR);
        self.regs.read32(ICR);
        crate::net::wake();
    }

    /// Give back any transmit slots the device has finished with.
    /// Give back the descriptors the card is done with: those before its
    /// head (TDH, §8.12.11), which also passes context descriptors.
    fn reclaim(&self, tx: &mut Tx) {
        let head = (self.regs.read32(TDH0) as usize) % RING;
        while tx.in_flight > 0 && tx.clean != head {
            tx.clean = (tx.clean + 1) % RING;
            tx.in_flight -= 1;
        }
    }
}

impl NetDevice for Igb {
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
        if frame.len() > BUF {
            return;
        }
        let mut tx = self.tx.lock();
        self.reclaim(&mut tx);
        // Keep one slot free so a full ring is never mistaken for empty.
        if tx.in_flight >= RING - 1 {
            return;
        }
        let t = tx.tail;
        self.tx_bufs.copy_in(t * BUF, frame);
        let d = t * 16;
        // An advanced data descriptor (table 7-32) without TSE: every frame
        // says itself whether it is segmented, so no large send's context
        // carries over to the frames after it.
        let len = frame.len() as u64;
        let dcmd = DCMD_DEXT | DCMD_IFCS | DCMD_EOP | DCMD_RS;
        self.tx_ring.write::<u64>(d, self.tx_bufs.phys() + (t * BUF) as u64);
        self.tx_ring.write::<u64>(d + 8, len | (DTYP_DATA << 20) | (dcmd << 24) | (len << 46));
        tx.tail = (t + 1) % RING;
        tx.in_flight += 1;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.regs.write32(TDT0, tx.tail as u32);
    }

    fn tso(&self) -> usize {
        TSO_MAX
    }

    fn send_large(&self, frame: &[u8], mss: u16) -> bool {
        // Ethernet II, IPv4 and TCP, as the stack makes them.
        let ip = 14;
        if frame.len() < ip + 40 || frame[12..14] != [0x08, 0x00] || frame[ip + 9] != 6 {
            return false;
        }
        let ihl = usize::from(frame[ip] & 0xF) * 4;
        let tcp = ip + ihl;
        let thl = usize::from(frame[tcp + 12] >> 4) * 4;
        let header = tcp + thl;
        if frame.len() <= header || mss == 0 {
            return false;
        }
        let payload = frame.len() - header;
        let buffers = frame.len().div_ceil(BUF);
        let mut tx = self.tx.lock();
        self.reclaim(&mut tx);
        // The context descriptor and the data descriptors, and one slot
        // kept free so a full ring is never mistaken for empty.
        if tx.in_flight + 1 + buffers > RING - 1 {
            return true; // Dropped, as a full ring drops single frames.
        }
        // The header as §7.2.4.5 wants it: IPv4 checksum zero, TCP checksum
        // the partial pseudo-header sum (addresses and protocol, no
        // length), not complemented.
        let mut first = [0u8; BUF];
        let head_len = frame.len().min(BUF);
        first[..head_len].copy_from_slice(&frame[..head_len]);
        first[ip + 10] = 0;
        first[ip + 11] = 0;
        let mut acc: u32 = 6;
        for k in (ip + 12..ip + 20).step_by(2) {
            acc += u32::from(u16::from_be_bytes([frame[k], frame[k + 1]]));
        }
        while acc > 0xFFFF {
            acc = (acc & 0xFFFF) + (acc >> 16);
        }
        first[tcp + 16..tcp + 18].copy_from_slice(&(acc as u16).to_be_bytes());
        // Context descriptor (table 7-29).
        let c = tx.tail;
        let lens = (ihl as u64) | (14u64 << 9);
        let tucmd = TUCMD_IPV4 | TUCMD_L4T_TCP;
        let ctx = (tucmd << 9) | (DTYP_CONTEXT << 20) | CONTEXT_DEXT | ((thl as u64) << 40) | (u64::from(mss) << 48);
        self.tx_ring.write::<u64>(c * 16, lens);
        self.tx_ring.write::<u64>(c * 16 + 8, ctx);
        let mut slot = (c + 1) % RING;
        // Data descriptors (table 7-32), one per buffer.
        for b in 0..buffers {
            let (from, to) = (b * BUF, ((b + 1) * BUF).min(frame.len()));
            if b == 0 {
                self.tx_bufs.copy_in(slot * BUF, &first[..to]);
            } else {
                self.tx_bufs.copy_in(slot * BUF, &frame[from..to]);
            }
            let last = b + 1 == buffers;
            let mut dcmd = DCMD_DEXT | DCMD_IFCS;
            if b == 0 {
                dcmd |= DCMD_TSE;
            }
            if last {
                dcmd |= DCMD_EOP | DCMD_RS;
            }
            let mut q1 = ((to - from) as u64) | (DTYP_DATA << 20) | (dcmd << 24);
            if b == 0 {
                q1 |= ((POPTS_TXSM | POPTS_IXSM) << 40) | ((payload as u64) << 46);
            }
            self.tx_ring.write::<u64>(slot * 16, self.tx_bufs.phys() + (slot * BUF) as u64);
            self.tx_ring.write::<u64>(slot * 16 + 8, q1);
            slot = (slot + 1) % RING;
        }
        tx.tail = slot;
        tx.in_flight += 1 + buffers;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.regs.write32(TDT0, tx.tail as u32);
        true
    }

    fn receive(&self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        let mut rx = self.rx.lock();
        let mut last = None;
        for _ in 0..RING {
            let d = rx.next * 16;
            let status = self.rx_ring.read::<u32>(d + 8);
            if status & RX_DD == 0 {
                break;
            }
            let len = usize::from(self.rx_ring.read::<u16>(d + 12));
            if status & RX_EOP != 0 && status & RX_ERRORS == 0 && len <= BUF {
                let mut f = alloc::vec![0u8; len];
                self.rx_bufs.copy_out(rx.next * BUF, &mut f);
                frames.push(f);
            }
            // Hand the descriptor back to the device (read format: packet
            // buffer address, no header buffer).
            self.rx_ring.write::<u64>(d, self.rx_bufs.phys() + (rx.next * BUF) as u64);
            self.rx_ring.write::<u64>(d + 8, 0);
            last = Some(rx.next);
            rx.next = (rx.next + 1) % RING;
        }
        if let Some(i) = last {
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            self.regs.write32(RDT0, i as u32);
        }
        frames
    }

    fn link_up(&self) -> bool {
        self.regs.read32(STATUS) & STATUS_LU != 0
    }
}

fn mdic(regs: Mmio, op: u32, reg: u32, data: u16) -> Option<u16> {
    regs.write32(MDIC, op | (PHY_ADDR << 21) | (reg << 16) | u32::from(data));
    let mut v = 0;
    if !wait_for(10, || {
        v = regs.read32(MDIC);
        v & MDIC_READY != 0
    }) || v & MDIC_ERROR != 0
    {
        return None;
    }
    Some(v as u16)
}

/// The station address: what the hardware loaded into receive address 0
/// from its NVM, else the NVM's first three words through EERD (§3.3).
fn read_mac(regs: Mmio) -> Option<Mac> {
    let (lo, hi) = (regs.read32(RAL0), regs.read32(RAH0));
    let mut b = [lo as u8, (lo >> 8) as u8, (lo >> 16) as u8, (lo >> 24) as u8, hi as u8, (hi >> 8) as u8];
    if b == [0; 6] || b == [0xFF; 6] {
        for w in 0..3u32 {
            regs.write32(EERD, (w << 2) | 1);
            let mut v = 0;
            if !wait_for(10, || {
                v = regs.read32(EERD);
                v & 2 != 0
            }) {
                return None;
            }
            b[2 * w as usize] = (v >> 16) as u8;
            b[2 * w as usize + 1] = (v >> 24) as u8;
        }
    }
    (b != [0; 6] && b != [0xFF; 6] && b[0] & 1 == 0).then_some(Mac(b))
}

pub fn probe(pci: Arc<Device>) -> Option<()> {
    pci.enable();
    let regs = Mmio(pci.map_bar(0)?);

    // Mask everything, reset, mask again (§4.3.1).
    regs.write32(IMC, u32::MAX);
    regs.write32(EIMC, u32::MAX);
    regs.write32(CTRL, regs.read32(CTRL) | CTRL_RST);
    delay_ms(2);
    if !wait_for(100, || regs.read32(CTRL) & CTRL_RST == 0) {
        log_warn!("igb {:?}: reset does not finish", pci.address);
        return None;
    }
    wait_for(50, || regs.read32(EEC) & EEC_AUTO_RD != 0);
    regs.write32(IMC, u32::MAX);
    regs.write32(EIMC, u32::MAX);
    regs.read32(ICR);

    let Some(mac) = read_mac(regs) else {
        log_warn!("igb {:?}: no station address", pci.address);
        return None;
    };
    // Receive address 0 is our unicast filter (valid bit set).
    let b = mac.0;
    regs.write32(RAL0, u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    regs.write32(RAH0, u32::from(b[4]) | (u32::from(b[5]) << 8) | RAH_AV);
    regs.write32(CTRL_EXT, regs.read32(CTRL_EXT) | CTRL_EXT_DRV_LOAD);

    // Link: the MAC follows what the PHY negotiates; make sure the PHY is
    // powered and negotiating (an earlier system may have powered it down).
    regs.write32(CTRL, regs.read32(CTRL) | CTRL_SLU);
    if let Some(bmcr) = mdic(regs, MDIC_OP_READ, PHY_CONTROL, 0)
        && bmcr != 0xFFFF
    {
        // After the reset, negotiate from scratch.
        let want = (bmcr & !BMCR_POWER_DOWN) | BMCR_ANENABLE | BMCR_ANRESTART;
        let _ = mdic(regs, MDIC_OP_WRITE, PHY_CONTROL, want);
    }

    let rx_ring = Dma::new(RING * 16)?;
    let tx_ring = Dma::new(RING * 16)?;
    let rx_bufs = Dma::new(RING * BUF)?;
    let tx_bufs = Dma::new(RING * BUF)?;
    for i in 0..RING {
        rx_ring.write::<u64>(i * 16, rx_bufs.phys() + (i * BUF) as u64);
    }
    for i in 0..128 {
        regs.write32(MTA + 4 * i, 0);
    }

    // Receive (§4.5.9): ring, buffer size, enable the queue, then the
    // tail, then the receiver.
    regs.write64(RDBAL0, rx_ring.phys());
    regs.write32(RDLEN0, (RING * 16) as u32);
    regs.write32(SRRCTL0, SRRCTL_2K_ADV_DROP);
    regs.write32(RDH0, 0);
    regs.write32(RDT0, 0);
    regs.write32(RXDCTL0, regs.read32(RXDCTL0) | QUEUE_ENABLE);
    wait_for(10, || regs.read32(RXDCTL0) & QUEUE_ENABLE != 0);
    regs.write32(RDT0, (RING - 1) as u32);
    regs.write32(RCTL, RCTL_EN | RCTL_BAM | RCTL_MPE | RCTL_SECRC);

    // Transmit (§4.5.10): write back each descriptor (WTHRESH 1).
    regs.write64(TDBAL0, tx_ring.phys());
    regs.write32(TDLEN0, (RING * 16) as u32);
    regs.write32(TDH0, 0);
    regs.write32(TDT0, 0);
    regs.write32(TXDCTL0, QUEUE_ENABLE | 8 | (1 << 8) | (1 << 16));
    wait_for(10, || regs.read32(TXDCTL0) & QUEUE_ENABLE != 0);
    regs.write32(TCTL, TCTL_EN | TCTL_PSP | TCTL_CT | TCTL_COLD);

    let name = crate::net::next_name();
    let slot: Arc<Once<Arc<Igb>>> = Arc::new(Once::new());
    let irq_slot = slot.clone();
    let handler = Box::new(move || {
        if let Some(d) = irq_slot.get() {
            d.interrupt();
        }
    });
    // Plain MSI where the function has it (one message, ICR causes);
    // otherwise MSI-X with every cause on entry 0 (§7.3.1).
    let dest = crate::arch::irq::device_irq_target();
    let mut mode = None;
    if pci.capability(CAP_MSI).is_some() || pci.capability(CAP_MSIX).is_some() {
        let v = crate::arch::irq::alloc_vector("igb", handler)?;
        if pci.capability(CAP_MSI).is_some() && pci.enable_msi(v, dest).is_some() {
            mode = Some("MSI");
        } else if pci.enable_msix(&[v], dest).is_some() {
            mode = Some("MSI-X");
        }
    }
    let msix = mode == Some("MSI-X");
    let dev = Arc::new(Igb {
        name,
        mac,
        regs,
        rx_ring,
        rx_bufs,
        tx_ring,
        tx_bufs,
        rx: IrqSpinLock::new(Rx { next: 0 }),
        tx: IrqSpinLock::new(Tx { tail: 0, clean: 0, in_flight: 0 }),
    });
    slot.call_once(|| dev.clone());
    if msix {
        // Multiple-MSI-X mode, auto-clear: queue 0's receive and transmit
        // causes and the other causes (link) all on vector 0.
        regs.write32(GPIE, (1 << 4) | (1 << 30) | (1 << 31));
        regs.write32(IVAR0, 0x8080);
        regs.write32(IVAR_MISC, 0x8000);
        regs.write32(EIAC, 1);
        regs.write32(EIAM, 1);
        regs.write32(EIMS, 1);
        regs.write32(IMS, INT_LSC);
    } else if mode.is_some() {
        // MSI (I210 datasheet §7.3.2.1): queue 0's receive and transmit
        // events go to EICR bit 0 through IVAR, the other causes to ICR
        // (summed in EICR bit 31). The 82576 (QEMU's model) also raises
        // queue events in ICR, so both are enabled.
        regs.write32(IVAR0, 0x8080);
        regs.write32(EIMS, 1 | (1 << 31));
        regs.write32(IMS, INT_CAUSES);
    }
    log_info!("igb {:?} ({:04x}): {}, MAC {mac:?}, {}", pci.address, pci.device, dev.name, mode.unwrap_or("polled"));
    crate::net::register(dev, mode.is_some());
    Some(())
}
