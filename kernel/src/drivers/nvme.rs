// SPDX-License-Identifier: MIT OR Apache-2.0

//! NVMe controllers and their namespaces.
//!
//! Source: NVM Express Base Specification 2.0 (controller registers §3.1,
//! queues and entries §4.1-§4.6, initialization §3.5.1, Identify §5.17 with
//! its controller and namespace data structures, Create I/O Completion and
//! Submission Queue §5.4-§5.5, and Set Features with its Number of Queues
//! feature)
//! and the NVM Command Set Specification 1.0 (Read, Write, Flush; the LBA
//! formats of Identify Namespace).
//!
//! One admin queue pair and an I/O queue pair per CPU (as many as the
//! controller gives, up to `MAX_IO_QUEUES`), each queue's completions on an
//! MSI-X vector of its own where there are enough, spread over the CPUs.
//! Every queue has `SLOTS` commands in flight at most, told apart by their
//! command identifier, which is the slot's index. Data moves straight
//! between the caller's buffer and the drive through PRP lists (§4.3);
//! requests that do not cover whole logical blocks, or buffers that cannot
//! be translated, go through a bounce buffer.
//!
//! A command that does not complete in time resets the controller (§3.7.2:
//! clearing CC.EN stops it and its DMA, and the queues are made again);
//! the commands the reset caught are submitted again, as are those that
//! failed without the Do Not Retry bit (§4.6.1.2). The controller is given
//! up on, and disabled, only after resets in a row that let nothing
//! complete.
//!
//! Behind an IOMMU the controller has a domain of its own: it reaches its
//! queues, lists and buffers, and a request's pages only while the request
//! runs (`iommu::Domain`, ADR 0127).
//!
//! Namespaces come and go while the controller runs: an Asynchronous Event
//! Request (§5.2) stays outstanding on the admin queue, and a Namespace
//! Attribute Changed notice reads the Changed Namespace List log (§5.16.1.5)
//! and adds, removes or replaces the disks it names.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use slate_sync::Once;

use super::dma::{Dma, Mmio, delay_ms, wait_for};
use super::iommu::Domain;
use super::pci::Device;
use crate::block::{self, BlockDevice, Family, IoError};
use crate::sched::wait::{Mutex, WaitQueue};
use crate::sync::IrqSpinLock;
use crate::{log_info, log_warn};

// Controller registers (§3.1).
const CAP: usize = 0x00;
const VS: usize = 0x08;
const INTMS: usize = 0x0C;
const CC: usize = 0x14;
const CSTS: usize = 0x1C;
const AQA: usize = 0x24;
const ASQ: usize = 0x28;
const ACQ: usize = 0x30;
const DOORBELLS: usize = 0x1000;

const CC_EN: u32 = 1 << 0;
/// CC.SHN, shutdown notification (NVMe base specification, "Controller
/// Shutdown"): 01b normal; CSTS.SHST reads 10b once it is done.
const CC_SHN_MASK: u32 = 3 << 14;
const CC_SHN_NORMAL: u32 = 1 << 14;
const CSTS_SHST_MASK: u32 = 3 << 2;
const CSTS_SHST_DONE: u32 = 2 << 2;
/// I/O submission and completion queue entry sizes: 2^6 and 2^4 bytes.
const CC_IOSQES_IOCQES: u32 = (6 << 16) | (4 << 20);
const CSTS_RDY: u32 = 1 << 0;
const CSTS_CFS: u32 = 1 << 1;

// Admin commands (§5).
const ADMIN_GET_LOG_PAGE: u8 = 0x02;
const ADMIN_CREATE_SQ: u8 = 0x01;
const ADMIN_CREATE_CQ: u8 = 0x05;
const ADMIN_IDENTIFY: u8 = 0x06;
const ADMIN_SET_FEATURES: u8 = 0x09;
const ADMIN_ASYNC_EVENT: u8 = 0x0C;
const ADMIN_NS_ATTACHMENT: u8 = 0x15;
/// Set Features: Asynchronous Event Configuration (§5.27.1.7), and its
/// Namespace Attribute Notices bit.
const FEATURE_ASYNC_EVENTS: u32 = 0x0B;
const NOTICE_NAMESPACES: u32 = 1 << 8;
/// An asynchronous event's completion dword 0 (§5.2.1): the Notice type,
/// and its Namespace Attribute Changed information.
const EVENT_NOTICE: u32 = 2;
const EVENT_NAMESPACE_CHANGED: u32 = 0;
/// The Changed Namespace List log (§5.16.1.5): up to 1024 identifiers, or
/// 0xFFFFFFFF first when more changed.
const LOG_CHANGED_NAMESPACES: u32 = 0x04;
const CNS_NAMESPACE: u32 = 0x00;
const CNS_CONTROLLER: u32 = 0x01;
const CNS_ACTIVE_NAMESPACES: u32 = 0x02;
/// Set Features: the Number of Queues feature identifier.
const FEATURE_QUEUES: u32 = 0x07;

// NVM commands (NVM Command Set §3).
const NVM_FLUSH: u8 = 0x00;
const NVM_WRITE: u8 = 0x01;
const NVM_READ: u8 = 0x02;
/// Dataset Management (NVMe 1.4 §6.7), and its Attribute - Deallocate bit
/// in dword 11.
const NVM_DSM: u8 = 0x09;
const DSM_DEALLOCATE: u32 = 1 << 2;
/// Read and Write dword 12 (NVM Command Set §3.2.4, §3.2.6): Protection
/// Information Action, so the controller makes the protection information
/// on writes and checks nothing on reads (PRCHK, bits 28:26, left 0).
const PRACT: u32 = 1 << 29;
/// The size of protection information with a 16-bit guard (NVM Command
/// Set §5.2.1): with PRACT, metadata of exactly this size is not moved.
const PI_BYTES: usize = 8;

const QUEUE_ENTRIES: u16 = 64;
/// Commands in flight per queue: fewer than the entries, so a submission
/// queue never fills.
const SLOTS: usize = 32;
const MAX_IO_QUEUES: usize = 32;
/// The largest transfer per command, and the bounce buffer's size.
const BOUNCE: usize = 256 * 1024;
const PAGE: usize = 4096;
const COMMAND_TIMEOUT_MS: u64 = 10_000;
/// A namespace the controller has as a disk.
#[derive(Clone)]
struct Known {
    nsid: u32,
    name: String,
    /// Its size and LBA format, to see whether a change changed them.
    blocks: u64,
    format: u32,
}

/// A status no completion carries: the command never completed.
const NO_STATUS: u16 = 0xFFFF;
/// Nor this one: a controller reset caught the command, which can be
/// submitted again.
const RESET_STATUS: u16 = 0xFFFE;
/// The status field's Do Not Retry bit (§4.6.1, Completion Queue Entry
/// dword 3 bit 31, so bit 14 once the phase tag is shifted out).
const STATUS_DNR: u16 = 1 << 14;
/// How often a command is submitted again after a reset or a failure that
/// may be retried.
const RETRIES: u32 = 3;
/// Resets in a row, with no command completing between them, before the
/// controller is given up on.
const MAX_RESETS: u32 = 3;

/// A command slot: its PRP list page, and what its completion said.
struct Slot {
    busy: AtomicBool,
    done: AtomicBool,
    dw0: AtomicU32,
    status: AtomicU32,
    list: Dma,
}

/// A submission/completion queue pair with `SLOTS` commands in flight.
struct Queue {
    id: u16,
    sq: Dma,
    cq: Dma,
    /// The submission queue's tail.
    tail: IrqSpinLock<u16>,
    /// The completion queue's head and the phase tag expected there.
    head: IrqSpinLock<(u16, bool)>,
    slots: Vec<Slot>,
    /// Completions and freed slots.
    waiters: WaitQueue,
}

impl Queue {
    fn new(id: u16, domain: Option<&Domain>) -> Option<Queue> {
        let mut slots = Vec::with_capacity(SLOTS);
        for _ in 0..SLOTS {
            slots.push(Slot {
                busy: AtomicBool::new(false),
                done: AtomicBool::new(false),
                dw0: AtomicU32::new(0),
                status: AtomicU32::new(0),
                list: device_dma(domain, PAGE)?,
            });
        }
        Some(Queue {
            id,
            sq: device_dma(domain, usize::from(QUEUE_ENTRIES) * 64)?,
            cq: device_dma(domain, usize::from(QUEUE_ENTRIES) * 16)?,
            tail: IrqSpinLock::new(0),
            head: IrqSpinLock::new((0, true)),
            slots,
            waiters: WaitQueue::new(),
        })
    }

    fn busy_slots(&self) -> usize {
        self.slots.iter().filter(|s| s.busy.load(Ordering::Acquire)).count()
    }

    /// Empty the queue after the controller stopped (a reset): both rings
    /// back to their start, and every command in flight completed with
    /// `RESET_STATUS`. Returns how many there were.
    fn clear(&self) -> usize {
        {
            let mut tail = self.tail.lock();
            *tail = 0;
            self.sq.zero_range(0, self.sq.len());
        }
        // The head's lock keeps `reap` out while the slots are marked.
        let mut head = self.head.lock();
        *head = (0, true);
        self.cq.zero_range(0, self.cq.len());
        let mut caught = 0;
        for s in &self.slots {
            if s.busy.load(Ordering::Acquire) && !s.done.load(Ordering::Acquire) {
                s.status.store(u32::from(RESET_STATUS), Ordering::Relaxed);
                s.done.store(true, Ordering::Release);
                caught += 1;
            }
        }
        drop(head);
        self.waiters.wake_all();
        caught
    }

    /// Give slot `cid` back.
    fn release(&self, cid: usize) {
        self.slots[cid].busy.store(false, Ordering::Release);
        self.waiters.wake_all();
    }
}

struct Controller {
    regs: Mmio,
    stride: usize,
    admin: Queue,
    io: Once<Vec<Queue>>,
    /// Completions arrive by interrupt (else they are polled for), and on
    /// how many vectors.
    interrupts: AtomicBool,
    vectors: AtomicUsize,
    /// How long the controller may take to become ready or stop (CAP.TO).
    ready_ms: u64,
    /// How long a command may take (lowered by the tests).
    timeout_ms: AtomicU64,
    /// A reset is under way: new commands wait for it on `gate`.
    resetting: AtomicBool,
    gate: WaitQueue,
    /// One reset at a time.
    reset_lock: Mutex<()>,
    /// Counts resets, so a command knows whether one caught it already.
    generation: AtomicU32,
    /// Resets in all, and in a row with nothing completing in between;
    /// commands resets caught.
    resets: AtomicU32,
    caught: AtomicUsize,
    failed_resets: AtomicU32,
    /// For the tests: the next I/O command is lost on its way to the
    /// controller, so it times out.
    lose_next: AtomicBool,
    /// Largest transfer, in bytes (set from Identify Controller).
    max_transfer: AtomicUsize,
    /// Dataset Management works (Identify Controller's ONCS, bit 2).
    dsm: AtomicBool,
    /// For transfers that cannot go straight to the caller's buffer, for
    /// Identify and for deallocation ranges.
    bounce: Mutex<Dma>,
    /// `nvmeN`, for messages.
    index: u32,
    /// How long a shutdown may take (Identify Controller's RTD3E).
    shutdown_ms: AtomicUsize,
    /// Shut down or failed: no more commands.
    down: AtomicBool,
    in_flight: AtomicUsize,
    /// The most commands that were in flight at once (for the tests).
    most_in_flight: AtomicUsize,
    /// Its PCI function, its IOMMU domain, and the disks its namespaces
    /// became.
    pci: Arc<Device>,
    domain: Option<Arc<Domain>>,
    namespaces: IrqSpinLock<Vec<Known>>,
    /// Identify Controller's model and controller identifier (CNTLID).
    model: Once<String>,
    cntlid: AtomicU32,
    /// Asynchronous Event Requests outstanding (0 or 1): admin slots that
    /// stay taken; and how many scans namespace changes have made.
    events: AtomicUsize,
    scans: AtomicU32,
}

/// Where a command's data is: the physical address of its first byte,
/// then of each following page.
type Pages = Vec<u64>;

/// A command to submit: its opcode, namespace, data pages, metadata
/// buffer (MPTR, §4.2: 0 for none) and command dwords 10 to 15. A
/// `patient` one has no time limit (an Asynchronous Event Request).
#[derive(Clone, Copy)]
struct Command<'a> {
    opcode: u8,
    nsid: u32,
    pages: &'a [u64],
    meta: u64,
    cdw: [u32; 6],
    patient: bool,
}

impl Controller {
    fn doorbell(&self, index: usize) -> usize {
        DOORBELLS + index * self.stride
    }

    /// The I/O queue for this CPU.
    fn io_queue(&self) -> Option<&Queue> {
        let qs = self.io.get()?;
        qs.get(crate::arch::cpu_id() as usize % qs.len())
    }

    /// Take the completions waiting on `q` (§4.6: an entry is new when its
    /// phase tag matches), record them in their slots and move the head.
    /// Returns whether there were any.
    fn reap(&self, q: &Queue) -> bool {
        let mut h = q.head.lock();
        let mut any = false;
        loop {
            let off = usize::from(h.0) * 16;
            let dw3 = q.cq.read::<u32>(off + 12);
            if (dw3 >> 16) & 1 != u32::from(h.1) {
                break;
            }
            let dw0 = q.cq.read::<u32>(off);
            if let Some(s) = q.slots.get((dw3 & 0xFFFF) as usize) {
                s.dw0.store(dw0, Ordering::Relaxed);
                s.status.store(dw3 >> 17, Ordering::Relaxed);
                s.done.store(true, Ordering::Release);
            }
            h.0 = (h.0 + 1) % QUEUE_ENTRIES;
            if h.0 == 0 {
                h.1 = !h.1;
            }
            any = true;
        }
        if any {
            self.regs.write32(self.doorbell(2 * usize::from(q.id) + 1), u32::from(h.0));
        }
        any
    }

    /// A free slot of `q`, waiting for one if all are taken.
    fn claim(&self, q: &Queue) -> usize {
        loop {
            for (i, s) in q.slots.iter().enumerate() {
                if s.busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                    return i;
                }
            }
            if crate::sched::can_block() {
                q.waiters.wait_until(|| q.busy_slots() < SLOTS);
            } else {
                self.reap(q);
                core::hint::spin_loop();
            }
        }
    }

    /// Submit a command on `q` and wait for its completion, again if a
    /// reset caught it or it failed in a way that may be retried. Returns
    /// dword 0 of the completion, or its status.
    fn submit(&self, q: &Queue, opcode: u8, nsid: u32, pages: &[u64], cdw: [u32; 6]) -> Result<u32, u16> {
        self.submit_command(q, Command { opcode, nsid, pages, meta: 0, cdw, patient: false })
    }

    /// `submit`, for a whole `Command`.
    fn submit_command(&self, q: &Queue, c: Command<'_>) -> Result<u32, u16> {
        let opcode = c.opcode;
        let mut tries = 0;
        loop {
            let r = self.attempt(q, c, false);
            let again = match r {
                Err(RESET_STATUS) => true,
                // Only I/O commands: an admin command that failed (creating
                // a queue, say) is the caller's to judge.
                Err(status) => q.id != 0 && status != NO_STATUS && status & STATUS_DNR == 0,
                Ok(_) => false,
            };
            if !again || tries == RETRIES || self.down.load(Ordering::Acquire) {
                return if r == Err(RESET_STATUS) { Err(NO_STATUS) } else { r };
            }
            tries += 1;
            if r != Err(RESET_STATUS) {
                log_warn!(
                    "nvme{}: command {opcode:#x} failed (status {:#x}); trying again",
                    self.index,
                    r.unwrap_err()
                );
            }
        }
    }

    /// Submit a command once and wait for it. A reset's own commands pass
    /// `in_reset`; others wait while a reset is under way. A command that
    /// times out resets the controller, and comes back with `RESET_STATUS`.
    fn attempt(&self, q: &Queue, c: Command<'_>, in_reset: bool) -> Result<u32, u16> {
        let Command { opcode, nsid, pages, meta, cdw, patient } = c;
        let (cid, generation) = loop {
            if self.down.load(Ordering::Acquire) {
                return Err(NO_STATUS);
            }
            if !in_reset {
                self.wait_reset();
            }
            let cid = self.claim(q);
            let s = &q.slots[cid];
            s.done.store(false, Ordering::Release);
            // PRP1 and PRP2 (§4.3): the second page itself, or a list of all
            // the pages after the first.
            let (prp1, prp2) = match pages {
                [] => (0, 0),
                [a] => (*a, 0),
                [a, b] => (*a, *b),
                [a, rest @ ..] => {
                    for (i, p) in rest.iter().enumerate() {
                        s.list.write::<u64>(i * 8, *p);
                    }
                    (*a, s.list.phys())
                }
            };
            let mut tail = q.tail.lock();
            if !in_reset && self.resetting.load(Ordering::Acquire) {
                // The reset began after the wait above: start over after it.
                drop(tail);
                q.release(cid);
                continue;
            }
            let generation = self.generation.load(Ordering::Acquire);
            if q.id != 0 && self.lose_next.swap(false, Ordering::AcqRel) {
                // The test's lost command: never written, never rung.
                break (cid, generation);
            }
            let off = usize::from(*tail) * 64;
            q.sq.zero_range(off, 64);
            q.sq.write::<u32>(off, u32::from(opcode) | ((cid as u32) << 16));
            q.sq.write::<u32>(off + 4, nsid);
            q.sq.write::<u64>(off + 16, meta);
            q.sq.write::<u64>(off + 24, prp1);
            q.sq.write::<u64>(off + 32, prp2);
            for (i, v) in cdw.iter().enumerate() {
                q.sq.write::<u32>(off + 40 + 4 * i, *v);
            }
            *tail = (*tail + 1) % QUEUE_ENTRIES;
            core::sync::atomic::fence(Ordering::SeqCst);
            self.regs.write32(self.doorbell(2 * usize::from(q.id)), u32::from(*tail));
            break (cid, generation);
        };
        let s = &q.slots[cid];
        let now = self.in_flight.fetch_add(1, Ordering::AcqRel) + 1;
        self.most_in_flight.fetch_max(now, Ordering::Relaxed);
        let timeout_ms = self.timeout_ms.load(Ordering::Relaxed);
        let done = if patient {
            q.waiters.wait_until(|| s.done.load(Ordering::Acquire) || self.down.load(Ordering::Acquire));
            s.done.load(Ordering::Acquire)
        } else if self.interrupts.load(Ordering::Acquire) && crate::sched::can_block() {
            let deadline = crate::time::monotonic_ns() + timeout_ms * 1_000_000;
            q.waiters.wait_until_timeout(|| s.done.load(Ordering::Acquire), deadline)
        } else {
            wait_for(timeout_ms, || {
                self.reap(q);
                s.done.load(Ordering::Acquire)
            })
        };
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
        if !done && patient {
            // The controller was stopped (shut down or failed). The request
            // has no buffer for it to write, so its slot can go.
            q.release(cid);
            return Err(NO_STATUS);
        }
        if !done {
            let why = format!("command {opcode:#x} on queue {} timed out", q.id);
            if in_reset {
                self.fail(&format!("{why} during a reset"));
            } else {
                self.recover(generation, &why);
            }
            if !s.done.load(Ordering::Acquire) {
                // The slot stays taken: the controller is stopped, so it can
                // no longer write into the buffer the caller gets back.
                return Err(NO_STATUS);
            }
        }
        let status = s.status.load(Ordering::Relaxed) as u16;
        let dw0 = s.dw0.load(Ordering::Relaxed);
        q.release(cid);
        if status != RESET_STATUS {
            self.failed_resets.store(0, Ordering::Relaxed);
        }
        if status != 0 { Err(status) } else { Ok(dw0) }
    }

    /// Wait while a reset is under way.
    fn wait_reset(&self) {
        if crate::sched::can_block() {
            self.gate.wait_until(|| !self.resetting.load(Ordering::Acquire));
        } else {
            while self.resetting.load(Ordering::Acquire) {
                core::hint::spin_loop();
            }
        }
    }

    /// A command submitted at reset `generation` timed out: reset the
    /// controller, unless another reset since then caught the command.
    fn recover(&self, generation: u32, why: &str) {
        let _one = self.reset_lock.lock();
        if self.generation.load(Ordering::Acquire) == generation && !self.down.load(Ordering::Acquire) {
            self.reset(why);
        }
    }

    /// Reset the controller (§3.7.2, a Controller Reset by CC.EN): stop it,
    /// complete everything in flight with `RESET_STATUS`, and bring it up
    /// with the same queues again. Called with `reset_lock` held. Returns
    /// whether the controller is back.
    fn reset(&self, why: &str) -> bool {
        self.resets.fetch_add(1, Ordering::Relaxed);
        if self.failed_resets.fetch_add(1, Ordering::AcqRel) + 1 > MAX_RESETS {
            self.fail(&format!("{why}, after {MAX_RESETS} resets in a row"));
            return false;
        }
        log_warn!("nvme{}: {why} (CSTS {:#x}); resetting the controller", self.index, self.regs.read32(CSTS));
        self.resetting.store(true, Ordering::SeqCst);
        self.regs.write32(CC, self.regs.read32(CC) & !CC_EN);
        if !wait_for(self.ready_ms, || self.regs.read32(CSTS) & CSTS_RDY == 0) {
            // Still running, so still able to DMA: the slots stay taken.
            self.fail("the controller does not stop for a reset");
            self.resetting.store(false, Ordering::SeqCst);
            self.gate.wake_all();
            return false;
        }
        self.generation.fetch_add(1, Ordering::AcqRel);
        let queues = core::iter::once(&self.admin).chain(self.io.get().into_iter().flatten());
        for q in queues {
            self.caught.fetch_add(q.clear(), Ordering::Relaxed);
        }
        let ios = self.io.get().map_or(&[][..], Vec::as_slice);
        let started = self.start();
        if started && !self.interrupts.load(Ordering::Acquire) {
            // A reset unmasks them (INTMS reads 0 again).
            self.regs.write32(INTMS, u32::MAX);
        }
        let ok = started && self.set_queue_count(ios.len()) >= ios.len() && self.create_io_queues(ios) == ios.len();
        self.resetting.store(false, Ordering::SeqCst);
        self.gate.wake_all();
        if ok {
            log_info!("nvme{}: reset done", self.index);
        } else {
            self.fail("the controller did not come back from a reset");
        }
        ok
    }

    /// Point the controller at the admin queue and enable it (§3.5.1).
    /// Returns whether it became ready.
    fn start(&self) -> bool {
        let entries = u32::from(QUEUE_ENTRIES - 1);
        self.regs.write32(AQA, entries | (entries << 16));
        self.regs.write64(ASQ, self.admin.sq.phys());
        self.regs.write64(ACQ, self.admin.cq.phys());
        // NVM command set, 4 KiB pages, round robin.
        self.regs.write32(CC, CC_IOSQES_IOCQES | CC_EN);
        wait_for(self.ready_ms, || self.regs.read32(CSTS) & (CSTS_RDY | CSTS_CFS) != 0)
            && self.regs.read32(CSTS) & CSTS_CFS == 0
    }

    /// Ask for `want` I/O queue pairs (Set Features, Number of Queues; the
    /// counts are zero based). Returns how many the controller gives.
    fn set_queue_count(&self, want: usize) -> usize {
        let want = want.max(1) as u32;
        let resetting = self.resetting.load(Ordering::Acquire);
        let cdw = [FEATURE_QUEUES, ((want - 1) << 16) | (want - 1), 0, 0, 0, 0];
        self.attempt(
            &self.admin,
            Command { opcode: ADMIN_SET_FEATURES, nsid: 0, pages: &[], meta: 0, cdw, patient: false },
            resetting,
        )
        .map(|dw0| ((dw0 & 0xFFFF).min(dw0 >> 16) + 1) as usize)
        .unwrap_or(1)
    }

    /// Create the I/O queue pairs `qs` on the controller: completion queue
    /// k on vector (k - 1) mod the vectors, then submission queue k feeding
    /// it (§5.4, §5.5). Returns how many it made, in order.
    fn create_io_queues(&self, qs: &[Queue]) -> usize {
        let resetting = self.resetting.load(Ordering::Acquire);
        let vectors = self.vectors.load(Ordering::Relaxed).max(1) as u32;
        let qsize = u32::from(QUEUE_ENTRIES - 1) << 16;
        let ien = if self.interrupts.load(Ordering::Acquire) { 1 << 1 } else { 0 };
        for (made, q) in qs.iter().enumerate() {
            let k = u32::from(q.id);
            let cq = [qsize | k, (((k - 1) % vectors) << 16) | ien | 1, 0, 0, 0, 0];
            let sq = [qsize | k, (k << 16) | 1, 0, 0, 0, 0];
            let admin = |opcode, page, cdw| {
                let c = Command { opcode, nsid: 0, pages: &[page], meta: 0, cdw, patient: false };
                self.attempt(&self.admin, c, resetting)
            };
            let r = admin(ADMIN_CREATE_CQ, q.cq.phys(), cq).and_then(|_| admin(ADMIN_CREATE_SQ, q.sq.phys(), sq));
            if let Err(s) = r {
                log_warn!("nvme{}: creating I/O queue {k} failed ({s:#x})", self.index);
                return made;
            }
        }
        qs.len()
    }

    /// Stop using the controller: disable it, so it does no more DMA.
    fn fail(&self, why: &str) {
        if !self.down.swap(true, Ordering::AcqRel) {
            log_warn!("nvme{}: {why} (CSTS {:#x}); controller disabled", self.index, self.regs.read32(CSTS));
            self.regs.write32(CC, self.regs.read32(CC) & !CC_EN);
            self.admin.waiters.wake_all();
        }
    }

    fn identify(&self, cns: u32, nsid: u32, out: &mut [u8; 4096]) -> Result<(), u16> {
        let b = self.bounce.lock();
        self.submit(&self.admin, ADMIN_IDENTIFY, nsid, &[b.phys()], [cns, 0, 0, 0, 0, 0])?;
        b.copy_out(0, out);
        Ok(())
    }

    /// Reap the queues this vector serves, and wake their waiters.
    fn interrupt(&self, vector: usize, vectors: usize) {
        if vector == 0 && self.reap(&self.admin) {
            self.admin.waiters.wake_all();
        }
        if let Some(qs) = self.io.get() {
            for (k, q) in qs.iter().enumerate() {
                if k % vectors == vector && self.reap(q) {
                    q.waiters.wake_all();
                }
            }
        }
    }
}

/// DMA memory the controller keeps for its life: mapped in its domain, if
/// it has one (never unmapped: closing the domain blocks it all).
fn device_dma(domain: Option<&Domain>, bytes: usize) -> Option<Dma> {
    let d = Dma::new(bytes)?;
    if let Some(dom) = domain {
        dom.map(d.phys(), d.len());
    }
    Some(d)
}

/// A request's pages, reachable by the controller while this lives.
struct Lent<'a> {
    domain: Option<&'a Domain>,
    pages: &'a [u64],
}

impl<'a> Lent<'a> {
    fn new(domain: Option<&'a Domain>, pages: &'a [u64]) -> Lent<'a> {
        if let Some(d) = domain {
            d.map_pages(pages.iter().copied());
        }
        Lent { domain, pages }
    }
}

impl Drop for Lent<'_> {
    fn drop(&mut self) {
        if let Some(d) = self.domain {
            d.unmap_pages(self.pages.iter().copied());
        }
    }
}

/// The pages of the first `len` bytes of a contiguous DMA buffer.
fn dma_pages(d: &Dma, len: usize) -> Pages {
    (0..len.div_ceil(PAGE).max(1)).map(|i| d.phys() + (i * PAGE) as u64).collect()
}

/// Where a namespace keeps each block's metadata (Identify Namespace's
/// LBA format MS and FLBAS bit 4; NVM Command Set §5.3).
#[derive(Clone, Copy, PartialEq, Debug)]
enum Metadata {
    None,
    /// Only protection information, which the controller makes and strips
    /// (PRACT): nothing travels with the data.
    Stripped,
    /// After each block's data, in the same buffer ("extended LBA").
    Extended(usize),
    /// In a buffer of its own (MPTR), this many bytes per block.
    Separate(usize),
}

pub struct Namespace {
    name: String,
    model: String,
    ctrl: Arc<Controller>,
    nsid: u32,
    /// Logical block size, a power of two ≥ 512 (data only).
    block: usize,
    blocks: u64,
    meta: Metadata,
    /// The protection information type (DPS bits 2:0; 0 for none).
    pi: u8,
    /// For `Metadata::Separate`: one command's metadata at a time. Writes
    /// give zeros (the controller fills in protection information); reads
    /// drop it.
    meta_page: Option<Mutex<Dma>>,
}

impl Namespace {
    fn io(&self, opcode: u8, lba: u64, count: usize, pages: &[u64]) -> Result<(), IoError> {
        let guard = match self.meta {
            Metadata::Separate(ms) => self.meta_page.as_ref().map(|m| (m.lock(), ms)),
            _ => None,
        };
        let meta = guard.as_ref().map_or(0, |(m, ms)| {
            if opcode == NVM_WRITE {
                m.zero_range(0, count * ms);
            }
            m.phys()
        });
        let q = self.ctrl.io_queue().ok_or(IoError)?;
        let mut cdw12 = (count - 1) as u32;
        // Types 1 and 2 check the reference tag against the block's
        // address (its low 32 bits, the Initial Logical Block Reference
        // Tag in dword 14).
        let mut ilbrt = 0;
        if self.pi != 0 {
            cdw12 |= PRACT;
            if self.pi != 3 {
                ilbrt = lba as u32;
            }
        }
        let cdw = [lba as u32, (lba >> 32) as u32, cdw12, 0, ilbrt, 0];
        let c = Command { opcode, nsid: self.nsid, pages, meta, cdw, patient: false };
        self.ctrl.submit_command(q, c).map(|_| ()).map_err(|status| {
            log_warn!("{}: {} of {count} blocks at {lba} failed (status {status:#x})", self.name, opcode_name(opcode));
            IoError
        })
    }

    /// Deallocate the logical blocks wholly inside sectors `sector` to
    /// `sector + count`, one range per command.
    fn deallocate(&self, sector: u64, count: u64) -> Result<(), IoError> {
        let blk = self.block as u64;
        let first = (sector * 512).div_ceil(blk);
        let end = ((sector + count) * 512 / blk).min(self.blocks);
        let q = self.ctrl.io_queue().ok_or(IoError)?;
        let b = self.ctrl.bounce.lock();
        let mut lba = first;
        while lba < end {
            let n = (end - lba).min(u64::from(u32::MAX));
            // One range (§6.7.1, figure 365): context attributes, length in
            // blocks, starting block.
            let mut range = [0u8; 16];
            range[4..8].copy_from_slice(&(n as u32).to_le_bytes());
            range[8..16].copy_from_slice(&lba.to_le_bytes());
            b.copy_in(0, &range);
            self.ctrl.submit(q, NVM_DSM, self.nsid, &[b.phys()], [0, DSM_DEALLOCATE, 0, 0, 0, 0]).map_err(
                |status| {
                    log_warn!("{}: deallocating {n} blocks at {lba} failed (status {status:#x})", self.name);
                    IoError
                },
            )?;
            lba += n;
        }
        Ok(())
    }

    /// Move `len` bytes at byte offset `pos`, in chunks of whole logical
    /// blocks: straight to and from `buf` when the chunk covers whole
    /// blocks of it, else through the bounce buffer (partly covered blocks
    /// are read first when writing).
    fn transfer(&self, pos: u64, buf: *mut u8, len: usize, write: bool) -> Result<(), IoError> {
        let blk = self.block as u64;
        if len % 512 != 0 || (pos + len as u64).div_ceil(blk) > self.blocks {
            return Err(IoError);
        }
        if let Metadata::Extended(ms) = self.meta {
            return self.transfer_extended(pos, buf, len, write, ms);
        }
        let op = if write { NVM_WRITE } else { NVM_READ };
        let mut chunk = (self.ctrl.max_transfer.load(Ordering::Relaxed) as u64 / blk).max(1);
        if let Metadata::Separate(ms) = self.meta {
            // One command's metadata fits the namespace's page.
            chunk = chunk.min((PAGE / ms) as u64).max(1);
        }
        let end = pos + len as u64;
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
            let whole = from == cstart && to == cend;
            // §4.3: data pointers must be dword aligned.
            if let Some(pages) = super::dma::kernel_pages(user, bytes, 4).filter(|_| whole) {
                let _lent = Lent::new(self.ctrl.domain.as_deref(), &pages);
                self.io(op, lba, n as usize, &pages)?;
            } else {
                let b = self.ctrl.bounce.lock();
                let pages = dma_pages(&b, total);
                if write {
                    if !whole {
                        self.io(NVM_READ, lba, n as usize, &pages)?;
                    }
                    // SAFETY: As above.
                    b.copy_in(at, unsafe { core::slice::from_raw_parts(user, bytes) });
                    self.io(NVM_WRITE, lba, n as usize, &pages)?;
                } else {
                    self.io(NVM_READ, lba, n as usize, &pages)?;
                    // SAFETY: As above.
                    b.copy_out(at, unsafe { core::slice::from_raw_parts_mut(user, bytes) });
                }
            }
            lba += n;
        }
        Ok(())
    }
}

impl Namespace {
    /// `transfer` for a namespace whose metadata follows each block's data:
    /// always through the bounce buffer, where block i's data is at
    /// i × (block + `ms`). Metadata read is kept for writes of partial
    /// chunks; whole chunks are written with zeros there.
    fn transfer_extended(&self, pos: u64, buf: *mut u8, len: usize, write: bool, ms: usize) -> Result<(), IoError> {
        let blk = self.block as u64;
        let stride = self.block + ms;
        let chunk = (self.ctrl.max_transfer.load(Ordering::Relaxed) / stride).max(1) as u64;
        let end = pos + len as u64;
        let mut lba = pos / blk;
        while lba * blk < end {
            let n = chunk.min(end.div_ceil(blk) - lba);
            let (cstart, cend) = (lba * blk, (lba + n) * blk);
            let (from, to) = (pos.max(cstart), end.min(cend));
            let b = self.ctrl.bounce.lock();
            let pages = dma_pages(&b, n as usize * stride);
            // Each block's part of [from, to): where it is in the bounce
            // buffer, where in the caller's buffer, and how long.
            let parts = (0..n).filter_map(|i| {
                let (bs, be) = (cstart + i * blk, cstart + (i + 1) * blk);
                let (lo, hi) = (from.max(bs), to.min(be));
                (lo < hi).then(|| (i as usize * stride + (lo - bs) as usize, (lo - pos) as usize, (hi - lo) as usize))
            });
            if write {
                if from == cstart && to == cend {
                    b.zero_range(0, n as usize * stride);
                } else {
                    self.io(NVM_READ, lba, n as usize, &pages)?;
                }
                for (at, off, len) in parts {
                    // SAFETY: `off + len <= len` of the caller's buffer.
                    b.copy_in(at, unsafe { core::slice::from_raw_parts(buf.add(off), len) });
                }
                self.io(NVM_WRITE, lba, n as usize, &pages)?;
            } else {
                self.io(NVM_READ, lba, n as usize, &pages)?;
                for (at, off, len) in parts {
                    // SAFETY: As above.
                    b.copy_out(at, unsafe { core::slice::from_raw_parts_mut(buf.add(off), len) });
                }
            }
            lba += n;
        }
        Ok(())
    }
}

impl Controller {
    /// Tell the controller the power is going (once): stop new commands,
    /// let those in flight finish, then request a normal shutdown and wait
    /// for it.
    fn shutdown(&self) {
        if self.down.swap(true, Ordering::AcqRel) {
            return;
        }
        // The Asynchronous Event Request is never answered: it does not count.
        self.admin.waiters.wake_all();
        let queues = core::iter::once(&self.admin).chain(self.io.get().into_iter().flatten());
        let busy: Vec<&Queue> = queues.collect();
        let idle = |q: &&Queue| q.busy_slots() <= if q.id == 0 { self.events.load(Ordering::Acquire) } else { 0 };
        if !wait_for(COMMAND_TIMEOUT_MS, || busy.iter().all(idle)) {
            log_warn!("nvme{}: commands still in flight at shutdown", self.index);
        }
        let cc = self.regs.read32(CC);
        self.regs.write32(CC, (cc & !CC_SHN_MASK) | CC_SHN_NORMAL);
        let ms = self.shutdown_ms.load(Ordering::Relaxed) as u64;
        if wait_for(ms, || self.regs.read32(CSTS) & CSTS_SHST_MASK == CSTS_SHST_DONE) {
            log_info!("nvme{}: shut down", self.index);
        } else {
            log_warn!("nvme{}: shutdown not finished after {ms} ms", self.index);
        }
    }
}

fn opcode_name(op: u8) -> &'static str {
    match op {
        NVM_READ => "read",
        NVM_WRITE => "write",
        _ => "flush",
    }
}

impl BlockDevice for Namespace {
    fn name(&self) -> &str {
        &self.name
    }
    fn can_discard(&self) -> bool {
        self.ctrl.dsm.load(Ordering::Relaxed)
    }
    fn discard(&self, sector: u64, count: u64) -> Result<(), IoError> {
        if !self.can_discard() || sector.checked_add(count).is_none_or(|end| end > self.sectors()) {
            return Err(IoError);
        }
        self.deallocate(sector, count)
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
        let q = self.ctrl.io_queue().ok_or(IoError)?;
        self.ctrl.submit(q, NVM_FLUSH, self.nsid, &[], [0; 6]).map(|_| ()).map_err(|_| IoError)
    }
    fn model(&self) -> String {
        self.model.clone()
    }
    fn shutdown(&self) {
        self.ctrl.shutdown();
    }
    fn queue_depth(&self) -> usize {
        SLOTS * self.ctrl.io.get().map_or(1, Vec::len)
    }
}

/// Every controller, for the tests.
static ALL: IrqSpinLock<Vec<Arc<Controller>>> = IrqSpinLock::new(Vec::new());

/// Turn on completion interrupts: an MSI-X vector per I/O queue where the
/// table has enough entries (each on the next CPU, the admin queue sharing
/// the first), else one vector for all. Returns how they are delivered
/// and how many vectors there are.
fn interrupts(pci: &Device, slot: &Arc<Once<Arc<Controller>>>, queues: usize) -> Option<(&'static str, usize)> {
    let handler = |vector: usize, vectors: usize| -> crate::arch::irq::DeviceHandler {
        let slot = slot.clone();
        Box::new(move || {
            if let Some(c) = slot.get() {
                c.interrupt(vector, vectors);
            }
        })
    };
    if let Some(size) = pci.msix_size() {
        let vectors = queues.min(size).max(1);
        let mut entries = Vec::new();
        for v in 0..vectors {
            let vector = crate::arch::irq::alloc_vector("nvme", handler(v, vectors))?;
            entries.push((vector, crate::arch::irq::device_irq_target()));
        }
        if pci.enable_msix_each(&entries).is_some() {
            return Some(("MSI-X", vectors));
        }
    }
    pci.enable_interrupt("nvme", handler(0, 1)).map(|m| (m, 1))
}

pub fn probe(pci: Arc<Device>) -> Option<()> {
    let domain = super::iommu::domain_for(&pci);
    let r = start(pci, domain.clone());
    if r.is_none()
        && let Some(d) = domain
    {
        // Whatever was mapped for it is freed now: block the device first.
        d.close();
    }
    r
}

fn start(pci: Arc<Device>, domain: Option<Arc<Domain>>) -> Option<()> {
    pci.enable();
    let regs = Mmio(pci.map_bar(0)?);
    let cap = regs.read64(CAP);
    let timeout_ms = ((cap >> 24) & 0xFF).max(1) * 500;
    let stride = 4usize << ((cap >> 32) & 0xF);
    if (cap >> 37) & 1 == 0 {
        log_warn!("NVMe {:?}: no NVM command set", pci.address);
        return None;
    }
    let max_entries = ((cap & 0xFFFF) + 1) as u16;
    if max_entries < QUEUE_ENTRIES {
        log_warn!("NVMe {:?}: queues of at most {max_entries} entries", pci.address);
        return None;
    }

    // Reset (§3.5.1): disable, wait for not ready.
    if regs.read32(CC) & CC_EN != 0 {
        regs.write32(CC, regs.read32(CC) & !CC_EN);
    }
    if !wait_for(timeout_ms, || regs.read32(CSTS) & CSTS_RDY == 0) {
        log_warn!("NVMe {:?}: controller does not stop", pci.address);
        return None;
    }
    // The lowest number no controller has (one unplugged frees its own),
    // as Linux numbers them.
    let index = {
        let all = ALL.lock();
        (0..).find(|n| !all.iter().any(|c| c.index == *n)).unwrap_or(0)
    };
    let ctrl = Arc::new(Controller {
        regs,
        stride,
        admin: Queue::new(0, domain.as_deref())?,
        io: Once::new(),
        interrupts: AtomicBool::new(false),
        vectors: AtomicUsize::new(1),
        ready_ms: timeout_ms,
        timeout_ms: AtomicU64::new(COMMAND_TIMEOUT_MS),
        resetting: AtomicBool::new(false),
        gate: WaitQueue::new(),
        reset_lock: Mutex::new(()),
        generation: AtomicU32::new(0),
        resets: AtomicU32::new(0),
        caught: AtomicUsize::new(0),
        failed_resets: AtomicU32::new(0),
        lose_next: AtomicBool::new(false),
        max_transfer: AtomicUsize::new(BOUNCE),
        dsm: AtomicBool::new(false),
        bounce: Mutex::new(device_dma(domain.as_deref(), BOUNCE)?),
        index,
        shutdown_ms: AtomicUsize::new(5000),
        down: AtomicBool::new(false),
        in_flight: AtomicUsize::new(0),
        most_in_flight: AtomicUsize::new(0),
        pci: pci.clone(),
        domain,
        namespaces: IrqSpinLock::new(Vec::new()),
        model: Once::new(),
        cntlid: AtomicU32::new(0),
        events: AtomicUsize::new(0),
        scans: AtomicU32::new(0),
    });
    // The admin queue is polled until the interrupts are set up.
    if !ctrl.start() {
        log_warn!("NVMe {:?}: controller does not become ready (CSTS {:#x})", pci.address, ctrl.regs.read32(CSTS));
        return None;
    }
    let slot: Arc<Once<Arc<Controller>>> = Arc::new(Once::new());
    slot.call_once(|| ctrl.clone());

    let mut id = Box::new([0u8; 4096]);
    if let Err(s) = ctrl.identify(CNS_CONTROLLER, 0, &mut id) {
        log_warn!("NVMe {:?}: Identify Controller failed ({s:#x})", pci.address);
        return None;
    }
    let model = String::from(String::from_utf8_lossy(&id[24..64]).trim());
    ctrl.model.call_once(|| model.clone());
    // CNTLID (bytes 78-79); OAES (bytes 92-95) bit 8: namespace notices.
    ctrl.cntlid.store(u32::from(u16::from_le_bytes([id[78], id[79]])), Ordering::Relaxed);
    let notices = id[93] & 1 != 0;
    // MDTS (byte 77): a power of two of the minimum page size, 0 = no limit.
    let mdts = id[77];
    let max_transfer = if mdts == 0 { BOUNCE } else { (PAGE << mdts.min(16)).min(BOUNCE) };
    ctrl.max_transfer.store(max_transfer, Ordering::Relaxed);
    // ONCS (bytes 520-521), bit 2: Dataset Management, so deallocation.
    ctrl.dsm.store(id[520] & (1 << 2) != 0, Ordering::Relaxed);
    // RTD3E (bytes 88-91): the time a shutdown can take, in microseconds
    // (0: not reported). Wait at least 5 s, at most 60 s.
    let rtd3e = u32::from_le_bytes(id[88..92].try_into().unwrap());
    ctrl.shutdown_ms.store((rtd3e as usize / 1000).clamp(5000, 60_000), Ordering::Relaxed);

    // How many I/O queues: one per CPU, as far as the controller goes.
    let want = crate::sched::cpu_count().clamp(1, MAX_IO_QUEUES);
    let nqueues = want.min(ctrl.set_queue_count(want)).max(1);

    let mode = interrupts(&pci, &slot, nqueues);
    if mode.is_none() {
        ctrl.regs.write32(INTMS, u32::MAX);
    }
    ctrl.vectors.store(mode.map_or(1, |m| m.1), Ordering::Relaxed);
    ctrl.interrupts.store(mode.is_some(), Ordering::Release);

    let mut queues = Vec::with_capacity(nqueues);
    for k in 1..=nqueues as u16 {
        queues.push(Queue::new(k, ctrl.domain.as_deref())?);
    }
    queues.truncate(ctrl.create_io_queues(&queues));
    if queues.is_empty() {
        log_warn!("NVMe {:?}: no I/O queues", pci.address);
        return None;
    }
    let made = queues.len();
    ctrl.io.call_once(|| queues);
    ALL.lock().push(ctrl.clone());

    let vs = ctrl.regs.read32(VS);
    log_info!(
        "NVMe {:?}: \"{model}\", version {}.{}, {made} I/O queues, {}",
        pci.address,
        vs >> 16,
        (vs >> 8) & 0xFF,
        mode.map_or_else(|| String::from("polled"), |(m, n)| format!("{m} ({n} vectors)"))
    );
    ctrl.scan(None)?;
    if notices && mode.is_some() {
        let c = ctrl.clone();
        crate::sched::spawn(&format!("nvme{index}-events"), move || c.events());
    }
    Some(())
}

impl Controller {
    /// Make disks of the active namespaces not yet known, and remove those
    /// no longer active. Namespaces in `changed` (None: all) that are still
    /// active are replaced if their size or format changed.
    fn scan(self: &Arc<Self>, changed: Option<&[u32]>) -> Option<()> {
        let mut id = Box::new([0u8; 4096]);
        self.identify(CNS_ACTIVE_NAMESPACES, 0, &mut id).ok()?;
        let active: Vec<u32> =
            id.chunks(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).take_while(|&n| n != 0).collect();
        let known = self.namespaces.lock().clone();
        for k in &known {
            let gone = !active.contains(&k.nsid);
            let looked = changed.is_none_or(|c| c.contains(&k.nsid));
            let stale = !gone
                && looked
                && self.identify(CNS_NAMESPACE, k.nsid, &mut id).is_ok()
                && namespace_shape(&id) != (k.blocks, k.format);
            if gone || stale {
                log_info!("nvme{}: namespace {} {}", self.index, k.nsid, if gone { "removed" } else { "changed" });
                self.namespaces.lock().retain(|n| n.nsid != k.nsid);
                block::unregister_disk(&k.name);
            }
        }
        for nsid in active {
            if !self.namespaces.lock().iter().any(|k| k.nsid == nsid)
                && self.identify(CNS_NAMESPACE, nsid, &mut id).is_ok()
            {
                self.add_namespace(nsid, &id);
            }
        }
        Some(())
    }

    /// Make a disk of namespace `nsid`, `id` its Identify Namespace data.
    fn add_namespace(self: &Arc<Self>, nsid: u32, id: &[u8; 4096]) {
        let index = self.index;
        let (blocks, lbaf) = namespace_shape(id);
        if blocks == 0 {
            return;
        }
        let lbads = (lbaf >> 16) & 0xFF;
        let ms = (lbaf & 0xFFFF) as usize;
        // DPS (byte 29), bits 2:0: the protection information type.
        let pi = id[29] & 7;
        let meta = match ms {
            0 => Metadata::None,
            PI_BYTES if pi != 0 => Metadata::Stripped,
            // FLBAS bit 4: metadata at the end of each block's data.
            _ if id[26] & (1 << 4) != 0 => Metadata::Extended(ms),
            _ => Metadata::Separate(ms),
        };
        if !(9..=16).contains(&lbads) || matches!(meta, Metadata::Separate(m) | Metadata::Extended(m) if m > PAGE) {
            log_warn!("nvme{index}n{nsid}: unsupported LBA format {lbaf:#x}");
            return;
        }
        let meta_page = match meta {
            Metadata::Separate(_) => match device_dma(self.domain.as_deref(), PAGE) {
                Some(d) => Some(Mutex::new(d)),
                None => return,
            },
            _ => None,
        };
        let name = format!("nvme{index}n{nsid}");
        let block = 1usize << lbads;
        let how = match meta {
            Metadata::None => String::new(),
            Metadata::Stripped => format!(", protection information type {pi}"),
            Metadata::Extended(ms) => format!(", {ms} bytes of metadata after each (protection type {pi})"),
            Metadata::Separate(ms) => format!(", {ms} bytes of metadata apart (protection type {pi})"),
        };
        log_info!("NVMe: /dev/{name}, {} MiB, {block}-byte blocks{how}", (blocks * block as u64) >> 20);
        self.namespaces.lock().push(Known { nsid, name: name.clone(), blocks, format: lbaf });
        let ns = Arc::new(Namespace {
            name,
            model: self.model.get().cloned().unwrap_or_default(),
            ctrl: self.clone(),
            nsid,
            block,
            blocks,
            meta,
            pi,
            meta_page,
        });
        block::register_disk(ns, Family::Nvme);
    }

    /// The events thread: keep an Asynchronous Event Request outstanding
    /// and act on what it reports, until the controller stops. A reset
    /// forgets the configuration and the request, so both are made again.
    fn events(self: Arc<Self>) {
        let enable = [FEATURE_ASYNC_EVENTS, NOTICE_NAMESPACES, 0, 0, 0, 0];
        'configure: while !self.down.load(Ordering::Acquire) {
            if let Err(s) = self.submit(&self.admin, ADMIN_SET_FEATURES, 0, &[], enable) {
                log_warn!("nvme{}: namespace notices could not be turned on ({s:#x})", self.index);
                return;
            }
            loop {
                let c = Command { opcode: ADMIN_ASYNC_EVENT, nsid: 0, pages: &[], meta: 0, cdw: [0; 6], patient: true };
                self.events.fetch_add(1, Ordering::AcqRel);
                let r = self.attempt(&self.admin, c, false);
                self.events.fetch_sub(1, Ordering::AcqRel);
                match r {
                    Ok(dw0) => self.event(dw0),
                    Err(RESET_STATUS) => continue 'configure,
                    Err(s) => {
                        if !self.down.load(Ordering::Acquire) {
                            log_warn!("nvme{}: asynchronous events stopped ({s:#x})", self.index);
                        }
                        return;
                    }
                }
            }
        }
    }

    /// One asynchronous event (§5.2.1): its log page is read, which lets
    /// the controller report that kind again; a namespace change rescans.
    fn event(self: &Arc<Self>, dw0: u32) {
        let (kind, info, log) = (dw0 & 7, (dw0 >> 8) & 0xFF, (dw0 >> 16) & 0xFF);
        let mut page = Box::new([0u8; 4096]);
        if self.log_page(log, &mut page).is_err() {
            log_warn!("nvme{}: reading log page {log:#x} after event {dw0:#x} failed", self.index);
        }
        if kind == EVENT_NOTICE && info == EVENT_NAMESPACE_CHANGED && log == LOG_CHANGED_NAMESPACES {
            let list: Vec<u32> =
                page.chunks(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).take_while(|&n| n != 0).collect();
            let changed = if list.first() == Some(&u32::MAX) { None } else { Some(&list[..]) };
            self.scan(changed);
            self.scans.fetch_add(1, Ordering::Release);
        } else {
            log_warn!("nvme{}: asynchronous event {dw0:#x}", self.index);
        }
    }

    /// Get Log Page (§5.16): the first 4 KiB of log `lid`, clearing the
    /// event that named it (RAE left 0).
    fn log_page(&self, lid: u32, out: &mut [u8; 4096]) -> Result<(), u16> {
        let b = self.bounce.lock();
        // NUMDL (bits 31:16): dwords to read, zero based.
        let cdw10 = lid | ((4096 / 4 - 1) << 16);
        self.submit(&self.admin, ADMIN_GET_LOG_PAGE, 0, &[b.phys()], [cdw10, 0, 0, 0, 0, 0])?;
        b.copy_out(0, out);
        Ok(())
    }

    /// Attach namespace `nsid` to this controller, or detach it (Namespace
    /// Attachment, §5.22, with a Controller List of this one).
    fn attach(&self, nsid: u32, attach: bool) -> Result<(), u16> {
        let b = self.bounce.lock();
        b.zero_range(0, PAGE);
        let cntlid = self.cntlid.load(Ordering::Relaxed) as u16;
        b.copy_in(0, &[1, 0]);
        b.copy_in(2, &cntlid.to_le_bytes());
        let sel = if attach { 0 } else { 1 };
        self.submit(&self.admin, ADMIN_NS_ATTACHMENT, nsid, &[b.phys()], [sel, 0, 0, 0, 0, 0]).map(|_| ())
    }
}

/// A namespace's size in blocks (NSZE) and its LBA format, from its
/// Identify Namespace data. FLBAS (byte 26): the format index in bits
/// 3:0, with bits 6:5 above them.
fn namespace_shape(id: &[u8; 4096]) -> (u64, u32) {
    let blocks = u64::from_le_bytes(id[0..8].try_into().unwrap());
    let fmt = usize::from(id[26] & 0xF) | (usize::from((id[26] >> 5) & 3) << 4);
    (blocks, u32::from_le_bytes(id[128 + 4 * fmt..132 + 4 * fmt].try_into().unwrap()))
}

/// The controller at `pci` is about to be ejected (hot-plug): its disks
/// go first, so nothing new reaches it, then it is shut down normally and
/// its interrupts turned off.
pub fn remove(pci: &Arc<Device>) {
    let ctrl = {
        let mut all = ALL.lock();
        let Some(i) = all.iter().position(|c| c.pci.address == pci.address) else { return };
        all.remove(i)
    };
    let namespaces = core::mem::take(&mut *ctrl.namespaces.lock());
    for k in &namespaces {
        block::unregister_disk(&k.name);
    }
    ctrl.shutdown();
    pci.disable_interrupts();
    if let Some(d) = &ctrl.domain {
        d.close();
    }
}

pub const TESTS: &[crate::ktest::Test] = &[
    crate::ktest::Test { name: "nvme::parallel_reads", run: test_parallel },
    crate::ktest::Test { name: "nvme::reset_recovers", run: test_reset },
    crate::ktest::Test { name: "nvme::metadata", run: test_metadata },
    crate::ktest::Test { name: "nvme::namespaces", run: test_namespaces },
    crate::ktest::Test { name: "nvme::iommu", run: test_iommu },
];

/// Behind the test machine's IOMMU: a read aimed at a page the controller
/// was never given leaves the page as it was and is logged as a refused
/// access; after ordinary reads, none of their pages stay mapped.
fn test_iommu() -> Result<(), &'static str> {
    let Some(ctrl) = ALL.lock().iter().find(|c| c.index == 0).cloned() else { return Err("no nvme0") };
    let Some(domain) = ctrl.domain.clone() else { return Err("nvme0 has no IOMMU domain") };
    let page = Dma::new(PAGE).ok_or("no memory")?;
    page.copy_in(0, &[0xA5; PAGE]);
    let faults = super::iommu::faults();
    let q = ctrl.io_queue().ok_or("no I/O queue")?;
    // Hardware fails such a command (a data transfer error); QEMU's NVMe
    // completes it with success all the same: the page and the log tell.
    let _ = ctrl.submit(q, NVM_READ, 1, &[page.phys()], [0, 0, 7, 0, 0, 0]);
    let mut after = [0u8; PAGE];
    page.copy_out(0, &mut after);
    if after.iter().any(|&b| b != 0xA5) {
        return Err("the controller wrote into a page not mapped");
    }
    if !wait_for(2000, || {
        super::iommu::poll();
        super::iommu::faults() > faults
    }) {
        return Err("the refused access was not logged");
    }
    let Some((dev, _)) = block::find("nvme0n1") else { return Err("no nvme0n1") };
    let mut b = alloc::vec![0u8; 64 * 1024];
    dev.read(0, &mut b).map_err(|_| "a read failed")?;
    let pages = super::dma::kernel_pages(b.as_ptr(), b.len(), 1).ok_or("no pages")?;
    if pages.iter().any(|p| domain.is_mapped(*p)) {
        return Err("a request's pages stayed mapped");
    }
    Ok(())
}

/// Namespace 4 of the second controller starts detached: attaching it
/// makes /dev/nvme1n4 appear through the controller's notice, data written
/// there survives a detach (the disk goes) and an attach (it comes back).
fn test_namespaces() -> Result<(), &'static str> {
    let Some(ctrl) = ALL.lock().iter().find(|c| c.index == 1).cloned() else { return Err("no nvme1") };
    let appears = |there: bool| wait_for(5000, || block::find("nvme1n4").is_some() == there);
    if !appears(false) {
        return Err("nvme1n4 is there before it was attached");
    }
    ctrl.attach(4, true).map_err(|_| "attaching failed")?;
    if !appears(true) {
        return Err("an attached namespace did not become a disk");
    }
    let (dev, _) = block::find("nvme1n4").ok_or("nvme1n4 went")?;
    let data: Vec<u8> = (0..8192).map(|i| (i * 5 + 2) as u8).collect();
    dev.write(16, &data).map_err(|_| "writing nvme1n4 failed")?;
    drop(dev);
    ctrl.attach(4, false).map_err(|_| "detaching failed")?;
    if !appears(false) {
        return Err("a detached namespace stayed a disk");
    }
    ctrl.attach(4, true).map_err(|_| "attaching again failed")?;
    if !appears(true) {
        return Err("a namespace attached again did not come back");
    }
    let (dev, _) = block::find("nvme1n4").ok_or("nvme1n4 went")?;
    let mut back = alloc::vec![0u8; 8192];
    dev.read(16, &mut back).map_err(|_| "reading nvme1n4 failed")?;
    if back != data {
        return Err("nvme1n4 lost its data across a detach");
    }
    if !wait_for(5000, || ctrl.scans.load(Ordering::Acquire) >= 3) {
        return Err("the changes did not come as notices");
    }
    Ok(())
}

/// The namespaces with metadata on the test machine's second controller
/// (xtask's `NVME_META_NAMESPACES`), their block sizes and metadata bytes
/// per block, each 4 MiB on the host.
const META_DISKS: &[(&str, usize, usize)] = &[("nvme1n1", 512, 16), ("nvme1n2", 4096, 16), ("nvme1n3", 512, 8)];

/// Each layout of metadata (after each block, apart, stripped protection
/// information) holds what was written: a long write starting inside a
/// block and spanning commands, a short one from an odd address over it,
/// read back whole and at an odd address. Sizes count data only.
fn test_metadata() -> Result<(), &'static str> {
    const SECTORS: usize = 2000;
    for &(name, block, ms) in META_DISKS {
        let Some((dev, _)) = block::find(name) else { return Err("a namespace with metadata is missing") };
        let blocks = (4 << 20) / (block + ms);
        if dev.sectors() != (blocks * block / 512) as u64 {
            return Err("a namespace with metadata has the wrong size");
        }
        let mut model = alloc::vec![0u8; SECTORS * 512];
        dev.write(0, &model).map_err(|_| "clearing failed")?;
        let long: Vec<u8> = (0..1200 * 512).map(|i| (i * 7 + 3) as u8).collect();
        dev.write(3, &long).map_err(|_| "the long write failed")?;
        model[3 * 512..1203 * 512].copy_from_slice(&long);
        let mut short = alloc::vec![0u8; 7 * 512 + 1];
        for (i, b) in short.iter_mut().enumerate() {
            *b = (i * 13 + 1) as u8;
        }
        dev.write(1100, &short[1..]).map_err(|_| "the short write failed")?;
        model[1100 * 512..1107 * 512].copy_from_slice(&short[1..]);
        let mut back = alloc::vec![0u8; SECTORS * 512 + 1];
        dev.read(0, &mut back[..SECTORS * 512]).map_err(|_| "reading back failed")?;
        if back[..SECTORS * 512] != model[..] {
            return Err("a namespace with metadata read back other data");
        }
        dev.read(0, &mut back[1..]).map_err(|_| "reading back at an odd address failed")?;
        if back[1..] != model[..] {
            return Err("a namespace with metadata read back other data at an odd address");
        }
    }
    Ok(())
}

/// A command lost on its way to the controller times out, the controller
/// is reset and the command comes back with the right data; then resets
/// made while eight threads read lose none of their reads.
fn test_reset() -> Result<(), &'static str> {
    let Some((dev, _)) = block::find("nvme0n1") else { return Err("no nvme0n1") };
    let Some(ctrl) = ALL.lock().first().cloned() else { return Err("no controller") };
    const SPAN: usize = 64 * 1024;
    let mut expected = alloc::vec![0u8; SPAN];
    dev.read(0, &mut expected).map_err(|_| "a read failed")?;
    let resets = ctrl.resets.load(Ordering::Relaxed);
    ctrl.timeout_ms.store(300, Ordering::Relaxed);
    ctrl.lose_next.store(true, Ordering::Release);
    let mut b = alloc::vec![0u8; SPAN];
    let r = dev.read(0, &mut b);
    // Another thread's command may have been the lost one: wait for its reset.
    let reset = wait_for(5000, || ctrl.resets.load(Ordering::Relaxed) > resets);
    ctrl.timeout_ms.store(COMMAND_TIMEOUT_MS, Ordering::Relaxed);
    if r.is_err() || b != expected {
        return Err("the read after the lost command failed");
    }
    if !reset || ctrl.down.load(Ordering::Acquire) {
        return Err("the lost command did not reset the controller");
    }

    const THREADS: usize = 8;
    let finished = Arc::new(AtomicUsize::new(0));
    let failures = Arc::new(AtomicUsize::new(0));
    let expected = Arc::new(expected);
    for _ in 0..THREADS {
        let (dev, expected, failures, finished) = (dev.clone(), expected.clone(), failures.clone(), finished.clone());
        crate::sched::spawn("nvme-test", move || {
            let mut b = alloc::vec![0u8; SPAN];
            for _ in 0..100 {
                if dev.read(0, &mut b).is_err() || b[..] != expected[..] {
                    failures.fetch_add(1, Ordering::Relaxed);
                }
            }
            finished.fetch_add(1, Ordering::Release);
        });
    }
    let caught = ctrl.caught.load(Ordering::Relaxed);
    for _ in 0..3 {
        delay_ms(5);
        let _one = ctrl.reset_lock.lock();
        if !ctrl.reset("a test resets it") {
            return Err("a reset failed");
        }
    }
    if !wait_for(30_000, || finished.load(Ordering::Acquire) == THREADS) {
        return Err("the readers did not finish");
    }
    if failures.load(Ordering::Relaxed) != 0 {
        return Err("a read across a reset failed or differed");
    }
    if ctrl.caught.load(Ordering::Relaxed) == caught {
        return Err("no reset caught a read in flight");
    }
    if ctrl.failed_resets.load(Ordering::Relaxed) != 0 || ctrl.down.load(Ordering::Acquire) {
        return Err("the controller did not recover");
    }
    Ok(())
}

/// Eight threads read the first NVMe disk at once, each its own stretch
/// several times, through buffers on the heap (straight DMA) and at an odd
/// address (the bounce buffer): every read matches one made alone, and
/// more than one command was in flight at a time.
fn test_parallel() -> Result<(), &'static str> {
    let Some((dev, _)) = block::find("nvme0n1") else { return Err("no nvme0n1") };
    let Some(ctrl) = ALL.lock().first().cloned() else { return Err("no controller") };
    const THREADS: usize = 8;
    const SPAN: usize = 64 * 1024;
    let mut expected = Vec::new();
    for t in 0..THREADS {
        let mut b = alloc::vec![0u8; SPAN];
        dev.read((t * SPAN / 512) as u64, &mut b).map_err(|_| "a single read failed")?;
        expected.push(b);
    }
    let expected = Arc::new(expected);
    let failures = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(AtomicUsize::new(0));
    ctrl.most_in_flight.store(0, Ordering::Relaxed);
    for t in 0..THREADS {
        let (dev, expected, failures, finished) = (dev.clone(), expected.clone(), failures.clone(), finished.clone());
        crate::sched::spawn("nvme-test", move || {
            let mut b = alloc::vec![0u8; SPAN + 1];
            for round in 0..16 {
                // Odd rounds read at an odd address: through the bounce buffer.
                let at = round % 2;
                let ok = dev.read((t * SPAN / 512) as u64, &mut b[at..at + SPAN]).is_ok()
                    && b[at..at + SPAN] == expected[t][..];
                if !ok {
                    failures.fetch_add(1, Ordering::Relaxed);
                }
            }
            finished.fetch_add(1, Ordering::Release);
        });
    }
    if !wait_for(30_000, || finished.load(Ordering::Acquire) == THREADS) {
        return Err("the readers did not finish");
    }
    if failures.load(Ordering::Relaxed) != 0 {
        return Err("a parallel read differed");
    }
    if ctrl.io.get().map_or(0, Vec::len) > 1 && ctrl.most_in_flight.load(Ordering::Relaxed) < 2 {
        return Err("never more than one command in flight");
    }
    Ok(())
}
