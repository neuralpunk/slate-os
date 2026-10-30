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
//!
//! Intel's 2.5 GbE I225 and I226 (`Family::I225`; ADR 0178) are the I210's
//! model with a few differences, learnt from Linux v7.2.12's igc driver
//! (`drivers/net/ethernet/intel/igc/`, read as documentation, its
//! datasheet being Intel's under NDA): the device IDs (igc_hw.h); the
//! interrupt registers only at 0x1500 on and EERD at 0x12014
//! (igc_regs.h); the internal PHY at MDIO address 0 (`phy.addr` is never
//! set, igc_phy.c), reached under the SW/FW semaphore (SWSM's SMBI then
//! SWESMBI, then SW_FW_SYNC's PHY0 bit; igc_i225.c,
//! `igc_acquire_swfw_sync_i225`, igc_base.c `igc_acquire_phy_base`);
//! PCIe mastering stopped before the reset (igc_mac.c,
//! `igc_disable_pcie_master`; igc_base.c `igc_reset_hw_base`), and
//! after it only the NVM's auto read awaited, not RST clearing (the
//! same); the
//! forced speed and duplex cleared with SLU (igc_base.c,
//! `igc_setup_copper_link_base`); queue causes in ICR under plain MSI
//! (igc_main.c, `igc_irq_enable`), with queue 0 still given vector 0 in
//! IVAR0 (`igc_up` and `igc_request_irq` call `igc_assign_vector` for
//! MSI too; without it only the link interrupts), and interrupts held
//! to about 20 000 a second (EITR, igc_regs.h; `IGC_20K_ITR`, igc.h);
//! queue 0 stopped before its rings are
//! given (it may come out of reset enabled: igc_main.c, `igc_setup_rctl`,
//! `igc_setup_tctl`), SRRCTL's other bits kept (`igc_configure_rx_ring`)
//! and only RXE taken as a receive error (`igc_clean_rx_irq`'s
//! `igc_test_staterr`). No segmentation offload on them yet.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

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

/// The I225 and I226 (vendor 8086h), from igc_hw.h; not the blank-NVM IDs
/// (0x15FD, 0x125F), which have no station address.
pub const I225_IDS: &[u16] = &[
    0x15F2, 0x15F3, 0x15F8, 0x15F7, 0x3100, 0x3101, 0x0D9F, 0x5502, // I225 (and I220-V)
    0x3102, 0x5503, 0x125B, 0x125C, 0x125D, 0x125E, // I226 (and I221-V)
];

/// Which model of the family a card follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    /// The 82576, I210 and I211.
    Igb,
    /// The I225 and I226 (ADR 0178).
    I225,
}

impl Family {
    fn name(self) -> &'static str {
        match self {
            Family::Igb => "igb",
            Family::I225 => "igc",
        }
    }
    fn icr(self) -> usize {
        match self {
            Family::Igb => ICR,
            Family::I225 => I225_ICR,
        }
    }
    fn ims(self) -> usize {
        match self {
            Family::Igb => IMS,
            Family::I225 => I225_IMS,
        }
    }
    fn imc(self) -> usize {
        match self {
            Family::Igb => IMC,
            Family::I225 => I225_IMC,
        }
    }
    fn eerd(self) -> usize {
        match self {
            Family::Igb => EERD,
            Family::I225 => I225_EERD,
        }
    }
    fn phy_addr(self) -> u32 {
        match self {
            Family::Igb => PHY_ADDR,
            Family::I225 => 0,
        }
    }
}

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
// The I225's (igc_regs.h): ICR, IMS and IMC without the low aliases, EERD
// moved, and the semaphores.
const I225_ICR: usize = 0x1500;
const I225_IMS: usize = 0x1508;
const I225_IMC: usize = 0x150C;
const I225_EERD: usize = 0x12014;
const SWSM: usize = 0x5B50;
const SW_FW_SYNC: usize = 0x5B5C;
const IVAR0: usize = 0x1700;
/// Queue vector 0's interrupt throttle (igc_regs.h, `IGC_EITR(0)`; the
/// I210's is at the same offset).
const EITR0: usize = 0x1680;
/// The interval igc gives for about 20 000 interrupts a second (igc.h,
/// `IGC_20K_ITR`), with the counter left alone (igc_defines.h,
/// `IGC_EITR_CNT_IGNR`).
const EITR_20K: u32 = 196 | (1 << 31);
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
// Statistics (I210 datasheet §8.19; the I225's are at the same offsets,
// igc_regs.h), cleared by reading.
const CRCERRS: usize = 0x4000;
const RXERRC: usize = 0x400C;
const MPC: usize = 0x4010;
const GPRC: usize = 0x4074;
const GPTC: usize = 0x4080;
const RNBC: usize = 0x40A0;
const TPR: usize = 0x40D0;
const TPT: usize = 0x40D4;
const TDBAL0: usize = 0xE000;
const TDLEN0: usize = 0xE008;
const TDH0: usize = 0xE010;
const TDT0: usize = 0xE018;
const TXDCTL0: usize = 0xE028;

const CTRL_GIO_MASTER_DISABLE: u32 = 1 << 2;
const CTRL_SLU: u32 = 1 << 6;
const CTRL_FRCSPD: u32 = 1 << 11;
const CTRL_FRCDPX: u32 = 1 << 12;
const STATUS_GIO_MASTER_ENABLE: u32 = 1 << 19;
// igc_defines.h: SWSM's software and firmware semaphore bits, SW_FW_SYNC's
// PHY 0 bit (firmware's is 16 higher).
const SWSM_SMBI: u32 = 1 << 0;
const SWSM_SWESMBI: u32 = 1 << 1;
const SWFW_PHY0: u32 = 1 << 1;
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
const SRRCTL_2K_ADV: u32 = 2 | (1 << 25);
const SRRCTL_2K_ADV_DROP: u32 = SRRCTL_2K_ADV | (1 << 31);
/// SRRCTL's packet size, header size and descriptor type fields
/// (igc_base.h), and the 256-byte header size igc gives (igc.h).
const SRRCTL_FIELDS: u32 = 0x7F | (0x3F << 8) | (7 << 25);
const SRRCTL_HDR_256: u32 = 4 << 8;
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
/// The I225's only receive error (igc_defines.h, `IGC_RXDEXT_STATERR_RXE`):
/// its other high bits are checksum results, not reasons to drop.
const RX_ERRORS_I225: u32 = 1 << 31;
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

/// When the I225 next reports its counters, and how many reports are left;
/// the interrupts and frames when the link was last checked.
struct Report {
    next_ms: u64,
    left: u32,
    irqs: u32,
    frames: u32,
}

pub struct Igb {
    family: Family,
    name: String,
    mac: Mac,
    regs: Mmio,
    rx_ring: Dma,
    rx_bufs: Dma,
    tx_ring: Dma,
    tx_bufs: Dma,
    rx: IrqSpinLock<Rx>,
    tx: IrqSpinLock<Tx>,
    report: IrqSpinLock<Report>,
    /// Registered with interrupts (MSI or MSI-X), and whether they have
    /// been found not to come.
    interrupts: bool,
    polled: AtomicBool,
    /// Interrupts taken and frames received, for the checks.
    irqs: AtomicU32,
    frames: AtomicU32,
}

impl Igb {
    fn interrupt(&self) {
        self.irqs.fetch_add(1, Ordering::Relaxed);
        // Reading the cause registers acknowledges them: queue events
        // arrive in EICR, the others (link) in ICR.
        self.regs.read32(EICR);
        self.regs.read32(self.family.icr());
        crate::net::wake();
    }

    /// The I225's hardware counters in the kernel log (`dmesg`), every
    /// 10 s for the first minute: it can only be tried on real hardware
    /// (ADR 0178), and they tell whether frames reach the card and the
    /// wire. The statistics count since the line before.
    fn report(&self) {
        let now = crate::time::monotonic_ns() / 1_000_000;
        {
            let mut r = self.report.lock();
            if r.left == 0 || now < r.next_ms {
                return;
            }
            r.left -= 1;
            r.next_ms = now + 10_000;
        }
        let g = |o| self.regs.read32(o);
        log_info!(
            "{}: rx {} good {} missed {} no-buffer {} crc {} errors {}; tx {} good {}; \
             RDH {} RDT {} TDH {} TDT {}; RXDCTL {:#x} TXDCTL {:#x} RCTL {:#x} TCTL {:#x} STATUS {:#x}; \
             interrupts {} frames {} (since start)",
            self.name,
            g(TPR),
            g(GPRC),
            g(MPC),
            g(RNBC),
            g(CRCERRS),
            g(RXERRC),
            g(TPT),
            g(GPTC),
            g(RDH0),
            g(RDT0),
            g(TDH0),
            g(TDT0),
            g(RXDCTL0),
            g(TXDCTL0),
            g(RCTL),
            g(TCTL),
            g(STATUS),
            self.irqs.load(Ordering::Relaxed),
            self.frames.load(Ordering::Relaxed)
        );
    }

    /// Frames arrived since the last link check but no interrupt did:
    /// they wait for the network thread's timers (half a second at most,
    /// and slow with it), so the card is polled from now on.
    fn check_interrupts(&self) {
        if !self.interrupts || self.polled.load(Ordering::Relaxed) {
            return;
        }
        let (irqs, frames) = (self.irqs.load(Ordering::Relaxed), self.frames.load(Ordering::Relaxed));
        let quiet = {
            let mut r = self.report.lock();
            let quiet = irqs == r.irqs && frames.wrapping_sub(r.frames) >= 8;
            (r.irqs, r.frames) = (irqs, frames);
            quiet
        };
        if quiet {
            self.polled.store(true, Ordering::Relaxed);
            log_warn!("{}: frames arrive but no interrupts ({irqs} so far); polling the card", self.name);
            crate::net::poll_cards();
        }
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
        if self.family == Family::Igb { TSO_MAX } else { 0 }
    }

    fn send_large(&self, frame: &[u8], mss: u16) -> bool {
        if self.family != Family::Igb {
            return false;
        }
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
        let errors = if self.family == Family::I225 { RX_ERRORS_I225 } else { RX_ERRORS };
        for _ in 0..RING {
            let d = rx.next * 16;
            let status = self.rx_ring.read::<u32>(d + 8);
            if status & RX_DD == 0 {
                break;
            }
            let len = usize::from(self.rx_ring.read::<u16>(d + 12));
            if status & RX_EOP != 0 && status & errors == 0 && len <= BUF {
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
        self.frames.fetch_add(frames.len() as u32, Ordering::Relaxed);
        frames
    }

    fn link_up(&self) -> bool {
        if self.family == Family::I225 {
            self.report();
        }
        self.check_interrupts();
        self.regs.read32(STATUS) & STATUS_LU != 0
    }
}

fn mdic(regs: Mmio, family: Family, op: u32, reg: u32, data: u16) -> Option<u16> {
    // The I225's PHY is shared with its firmware: hold the semaphore.
    if family == Family::I225 && !swfw_acquire(regs) {
        return None;
    }
    regs.write32(MDIC, op | (family.phy_addr() << 21) | (reg << 16) | u32::from(data));
    // igc gives the I225's PHY up to about 96 ms (igc_phy.c, 50 µs
    // polls); the I210's answers far sooner.
    let mut v = 0;
    let done = wait_for(100, || {
        v = regs.read32(MDIC);
        v & MDIC_READY != 0
    });
    if family == Family::I225 {
        swfw_release(regs);
    }
    (done && v & MDIC_ERROR == 0).then_some(v as u16)
}

/// The I225's hardware semaphore: SWSM's SMBI free, then SWESMBI latched
/// (igc_i225.c, `igc_get_hw_semaphore_i225`).
fn hw_semaphore(regs: Mmio) -> bool {
    if !wait_for(50, || regs.read32(SWSM) & SWSM_SMBI == 0) {
        return false;
    }
    let got = wait_for(50, || {
        regs.write32(SWSM, regs.read32(SWSM) | SWSM_SWESMBI);
        regs.read32(SWSM) & SWSM_SWESMBI != 0
    });
    if !got {
        hw_semaphore_put(regs);
    }
    got
}

fn hw_semaphore_put(regs: Mmio) {
    regs.write32(SWSM, regs.read32(SWSM) & !(SWSM_SMBI | SWSM_SWESMBI));
}

/// The PHY for software: SW_FW_SYNC's PHY 0 bit, once neither software nor
/// firmware holds it (igc_i225.c, `igc_acquire_swfw_sync_i225`).
fn swfw_acquire(regs: Mmio) -> bool {
    for _ in 0..200 {
        if !hw_semaphore(regs) {
            return false;
        }
        let sync = regs.read32(SW_FW_SYNC);
        if sync & (SWFW_PHY0 | (SWFW_PHY0 << 16)) == 0 {
            regs.write32(SW_FW_SYNC, sync | SWFW_PHY0);
            hw_semaphore_put(regs);
            return true;
        }
        hw_semaphore_put(regs);
        delay_ms(5);
    }
    false
}

fn swfw_release(regs: Mmio) {
    if hw_semaphore(regs) {
        regs.write32(SW_FW_SYNC, regs.read32(SW_FW_SYNC) & !SWFW_PHY0);
        hw_semaphore_put(regs);
    }
}

/// The station address: what the hardware loaded into receive address 0
/// from its NVM, else the NVM's first three words through EERD (§3.3).
fn read_mac(regs: Mmio, family: Family) -> Option<Mac> {
    let (lo, hi) = (regs.read32(RAL0), regs.read32(RAH0));
    let mut b = [lo as u8, (lo >> 8) as u8, (lo >> 16) as u8, (lo >> 24) as u8, hi as u8, (hi >> 8) as u8];
    if b == [0; 6] || b == [0xFF; 6] {
        for w in 0..3u32 {
            regs.write32(family.eerd(), (w << 2) | 1);
            let mut v = 0;
            if !wait_for(10, || {
                v = regs.read32(family.eerd());
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
    probe_family(pci, Family::Igb)
}

/// An I225 or I226 (ADR 0178).
pub fn probe_i225(pci: Arc<Device>) -> Option<()> {
    probe_family(pci, Family::I225)
}

fn probe_family(pci: Arc<Device>, family: Family) -> Option<()> {
    pci.enable();
    let fname = family.name();
    let Some(bar) = pci.map_bar(0) else {
        log_warn!("{fname} {:?}: no memory BAR 0", pci.address);
        return None;
    };
    let regs = Mmio(bar);
    if regs.read32(STATUS) == u32::MAX {
        log_warn!("{fname} {:?}: its registers read as all ones (powered down or gone)", pci.address);
        return None;
    }

    // Mask everything, reset, mask again (§4.3.1). The I225 first stops
    // its DMA (the firmware may have used the card) and its receiver and
    // transmitter.
    regs.write32(family.imc(), u32::MAX);
    regs.write32(EIMC, u32::MAX);
    if family == Family::I225 {
        regs.write32(CTRL, regs.read32(CTRL) | CTRL_GIO_MASTER_DISABLE);
        if !wait_for(30, || regs.read32(STATUS) & STATUS_GIO_MASTER_ENABLE == 0) {
            log_warn!("{fname} {:?}: DMA still pending before the reset", pci.address);
        }
        regs.write32(RCTL, 0);
        regs.write32(TCTL, TCTL_PSP);
        delay_ms(10);
    }
    regs.write32(CTRL, regs.read32(CTRL) | CTRL_RST);
    delay_ms(2);
    if !wait_for(100, || regs.read32(CTRL) & CTRL_RST == 0) {
        let (ctrl, status) = (regs.read32(CTRL), regs.read32(STATUS));
        // igc never waits for RST to clear, only for the NVM's auto read
        // (igc_base.c, `igc_reset_hw_base`): the I225 goes on.
        log_warn!("{fname} {:?}: reset does not finish (CTRL {ctrl:#x} STATUS {status:#x})", pci.address);
        if family == Family::Igb || ctrl == u32::MAX {
            return None;
        }
    }
    if !wait_for(50, || regs.read32(EEC) & EEC_AUTO_RD != 0) {
        log_warn!("{fname} {:?}: the NVM's auto read is not done (EEC {:#x})", pci.address, regs.read32(EEC));
    }
    regs.write32(family.imc(), u32::MAX);
    regs.write32(EIMC, u32::MAX);
    regs.read32(family.icr());

    let Some(mac) = read_mac(regs, family) else {
        log_warn!(
            "{fname} {:?}: no station address (RAL0 {:#x} RAH0 {:#x} EEC {:#x} STATUS {:#x})",
            pci.address,
            regs.read32(RAL0),
            regs.read32(RAH0),
            regs.read32(EEC),
            regs.read32(STATUS)
        );
        return None;
    };
    // Receive address 0 is our unicast filter (valid bit set).
    let b = mac.0;
    regs.write32(RAL0, u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    regs.write32(RAH0, u32::from(b[4]) | (u32::from(b[5]) << 8) | RAH_AV);
    regs.write32(CTRL_EXT, regs.read32(CTRL_EXT) | CTRL_EXT_DRV_LOAD);

    // Link: the MAC follows what the PHY negotiates; make sure the PHY is
    // powered and negotiating (an earlier system may have powered it down).
    let mut ctrl = regs.read32(CTRL) | CTRL_SLU;
    if family == Family::I225 {
        ctrl &= !(CTRL_FRCSPD | CTRL_FRCDPX);
    }
    regs.write32(CTRL, ctrl);
    match mdic(regs, family, MDIC_OP_READ, PHY_CONTROL, 0) {
        Some(bmcr) if bmcr != 0xFFFF => {
            // After the reset, negotiate from scratch.
            let want = (bmcr & !BMCR_POWER_DOWN) | BMCR_ANENABLE | BMCR_ANRESTART;
            let _ = mdic(regs, family, MDIC_OP_WRITE, PHY_CONTROL, want);
        }
        _ => log_warn!("{fname} {:?}: its PHY doesn't answer; the link is left as it is", pci.address),
    }

    let (Some(rx_ring), Some(tx_ring), Some(rx_bufs), Some(tx_bufs)) =
        (Dma::new(RING * 16), Dma::new(RING * 16), Dma::new(RING * BUF), Dma::new(RING * BUF))
    else {
        log_warn!("{fname} {:?}: no memory for its rings", pci.address);
        return None;
    };
    for i in 0..RING {
        rx_ring.write::<u64>(i * 16, rx_bufs.phys() + (i * BUF) as u64);
    }
    for i in 0..128 {
        regs.write32(MTA + 4 * i, 0);
    }
    // The I225's queue 0 may be running already: stop it before it gets
    // its rings.
    if family == Family::I225 {
        regs.write32(RXDCTL0, 0);
        regs.write32(TXDCTL0, 0);
        if !wait_for(10, || (regs.read32(RXDCTL0) | regs.read32(TXDCTL0)) & QUEUE_ENABLE == 0) {
            log_warn!("{fname} {:?}: queue 0 does not stop", pci.address);
        }
    }

    // Receive (§4.5.9): ring, buffer size, enable the queue, then the
    // tail, then the receiver.
    regs.write64(RDBAL0, rx_ring.phys());
    regs.write32(RDLEN0, (RING * 16) as u32);
    // igc sets no drop bit and keeps SRRCTL's other bits: the I225 gets
    // the sizes and the type.
    let srrctl = match family {
        Family::I225 => (regs.read32(SRRCTL0) & !SRRCTL_FIELDS) | SRRCTL_2K_ADV | SRRCTL_HDR_256,
        Family::Igb => SRRCTL_2K_ADV_DROP,
    };
    regs.write32(SRRCTL0, srrctl);
    regs.write32(RDH0, 0);
    regs.write32(RDT0, 0);
    // The I225's queue was cleared above: prefetch and host thresholds as
    // igc's (igc.h), each descriptor written back as it completes.
    let rxdctl = match family {
        Family::I225 => 8 | (8 << 8) | (1 << 16),
        Family::Igb => regs.read32(RXDCTL0),
    };
    regs.write32(RXDCTL0, rxdctl | QUEUE_ENABLE);
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
        let Some(v) = crate::arch::irq::alloc_vector(fname, handler) else {
            log_warn!("{fname} {:?}: no interrupt vector", pci.address);
            return None;
        };
        if pci.capability(CAP_MSI).is_some() && pci.enable_msi(v, dest).is_some() {
            mode = Some("MSI");
        } else if pci.enable_msix(&[v], dest).is_some() {
            mode = Some("MSI-X");
        }
    }
    let msix = mode == Some("MSI-X");
    let dev = Arc::new(Igb {
        family,
        name,
        mac,
        regs,
        rx_ring,
        rx_bufs,
        tx_ring,
        tx_bufs,
        rx: IrqSpinLock::new(Rx { next: 0 }),
        tx: IrqSpinLock::new(Tx { tail: 0, clean: 0, in_flight: 0 }),
        report: IrqSpinLock::new(Report { next_ms: 0, left: 6, irqs: 0, frames: 0 }),
        interrupts: mode.is_some(),
        polled: AtomicBool::new(false),
        irqs: AtomicU32::new(0),
        frames: AtomicU32::new(0),
    });
    // Start the statistics from here.
    for r in [CRCERRS, RXERRC, MPC, GPRC, GPTC, RNBC, TPR, TPT] {
        regs.read32(r);
    }
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
        regs.write32(family.ims(), INT_LSC);
    } else if mode.is_some() && family == Family::I225 {
        // MSI on the I225: every cause in ICR, queue 0's receive and
        // transmit still on vector 0 through IVAR0, or they never raise
        // one (igc_main.c, `igc_assign_vector` from `igc_up`); pending
        // causes cleared, then the mask (`igc_irq_enable`).
        regs.write32(IVAR0, 0x8080);
        regs.write32(EITR0, EITR_20K);
        regs.read32(I225_ICR);
        regs.write32(I225_IMS, INT_CAUSES);
    } else if mode.is_some() {
        // MSI (I210 datasheet §7.3.2.1): queue 0's receive and transmit
        // events go to EICR bit 0 through IVAR, the other causes to ICR
        // (summed in EICR bit 31). The 82576 (QEMU's model) also raises
        // queue events in ICR, so both are enabled.
        regs.write32(IVAR0, 0x8080);
        regs.write32(EIMS, 1 | (1 << 31));
        regs.write32(IMS, INT_CAUSES);
    }
    log_info!(
        "{fname} {:?} ({:04x}): {}, MAC {mac:?}, {}",
        pci.address,
        pci.device,
        dev.name,
        mode.unwrap_or("polled")
    );
    crate::net::register(dev, mode.is_some());
    Some(())
}
