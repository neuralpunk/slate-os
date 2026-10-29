// SPDX-License-Identifier: MIT OR Apache-2.0

//! Restartable sequences, rseq(2) (ADR 0115). glibc registers an area per
//! thread and reads the CPU from it; a critical section that is preempted,
//! moved or interrupted by a signal starts over at its abort handler.
//!
//! The man page (librseq's rseq.2) gives the structures and errors; the
//! rest was observed on Linux (ADR 0115):
//! - `struct rseq`: u32 cpu_id_start, u32 cpu_id, u64 rseq_cs, u32 flags,
//!   u32 node_id, u32 mm_cid: the features end at 28 bytes, which
//!   AT_RSEQ_FEATURE_SIZE says, with AT_RSEQ_ALIGN 32 (the auxiliary
//!   vector's types 27 and 28, observed on Linux). The area is 32 bytes,
//!   or larger and 32-byte aligned. node_id is 0 (one memory node);
//!   mm_cid, a concurrency ID unique among the process's running threads
//!   and below the number of possible CPUs, is the CPU's number (not
//!   packed towards 0). Linux 7.2's features past mm_cid (its feature
//!   size is 33) aren't offered.
//! - Registering writes the current CPU into cpu_id_start and cpu_id; the
//!   same registration again is EBUSY, one with another signature EPERM,
//!   any other difference EINVAL; an unaligned area or another size
//!   EINVAL, an unmapped one EFAULT.
//! - Unregistering (RSEQ_FLAG_UNREGISTER, 1) needs the same area (else
//!   EINVAL) and signature (else EPERM), and writes cpu_id -1 and
//!   cpu_id_start 0. With nothing registered it is EINVAL.
//! - `struct rseq_cs`: u32 version, u32 flags, u64 start_ip, u64
//!   post_commit_offset, u64 abort_ip. After a switch away or before a
//!   signal, an instruction pointer in [start_ip, start_ip +
//!   post_commit_offset) moves to abort_ip, whose four bytes before must
//!   be the signature (else SIGSEGV); rseq_cs is cleared either way.
//! - fork keeps the registration; new threads and execve start without.

use core::sync::atomic::Ordering;

use crate::abi::linux::errno::*;
use crate::arch::trap::TrapFrame;
use crate::arch::uaccess::{read_user, write_user};
use crate::sched;

/// The area's least size, and its alignment (the man page's first
/// version, and AT_RSEQ_ALIGN).
const AREA: u64 = 32;
/// Where the features end (AT_RSEQ_FEATURE_SIZE): after mm_cid.
pub const FEATURE_SIZE: u64 = 28;
const NODE_ID_AT: u64 = 20;
const MM_CID_AT: u64 = 24;
const RSEQ_FLAG_UNREGISTER: u64 = 1;
/// cpu_id when no area is registered (the man page: user space starts it
/// at -1).
const CPU_ID_UNINITIALIZED: u32 = u32::MAX;

/// A thread's registration: the area and the signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registration {
    pub area: u64,
    pub len: u64,
    pub sig: u32,
}

/// rseq(2).
pub fn rseq(area: u64, len: u64, flags: u64, sig: u32) -> Result<u64, Errno> {
    let t = sched::current();
    let mut reg = t.rseq.lock();
    match flags {
        RSEQ_FLAG_UNREGISTER => {
            let r = (*reg).ok_or(EINVAL)?;
            if r.area != area || len != r.len {
                return Err(EINVAL);
            }
            if r.sig != sig {
                return Err(EPERM);
            }
            *reg = None;
            drop(reg);
            // (A failed write leaves the thread unregistered all the same.)
            let _ = write_user(area + 4, &CPU_ID_UNINITIALIZED);
            let _ = write_user(area, &0u32);
            Ok(0)
        }
        0 => {
            if let Some(r) = *reg {
                return Err(if r.area == area && len == r.len && r.sig == sig {
                    EBUSY
                } else if r.area == area && len == r.len {
                    EPERM
                } else {
                    EINVAL
                });
            }
            if len < AREA || area % AREA != 0 {
                return Err(EINVAL);
            }
            drop(reg);
            write_ids(area).map_err(|_| EFAULT)?;
            *t.rseq.lock() = Some(Registration { area, len, sig });
            t.rseq_seen.store(t.switched_out.load(Ordering::Relaxed), Ordering::Relaxed);
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

/// Before returning to user mode with `frame` (no lock held: this writes
/// user memory): after a switch away, or with a signal about to be
/// delivered, bring the area up to date and abort an interrupted critical
/// section. A broken area or section is SIGSEGV.
pub fn before_user(frame: &mut TrapFrame, signal: bool) {
    let t = sched::current();
    // Most returns: no switch since the last, and no signal (two loads).
    let n = t.switched_out.load(Ordering::Relaxed);
    if !signal && t.rseq_seen.load(Ordering::Relaxed) == n {
        return;
    }
    t.rseq_seen.store(n, Ordering::Relaxed);
    let Some(reg) = *t.rseq.lock() else { return };
    if fix(frame, reg).is_err() {
        crate::proc::signal::force_signal(crate::proc::signal::SIGSEGV, crate::proc::signal::SEGV_ACCERR, reg.area);
    }
}

/// The CPU, node and concurrency ID into the area.
fn write_ids(area: u64) -> Result<(), ()> {
    let cpu = crate::arch::cpu_id();
    write_user(area, &cpu).map_err(|_| ())?;
    write_user(area + 4, &cpu).map_err(|_| ())?;
    write_user(area + NODE_ID_AT, &0u32).map_err(|_| ())?;
    write_user(area + MM_CID_AT, &cpu).map_err(|_| ())
}

fn fix(frame: &mut TrapFrame, reg: Registration) -> Result<(), ()> {
    write_ids(reg.area)?;
    let cs: u64 = read_user(reg.area + 8).map_err(|_| ())?;
    if cs == 0 {
        return Ok(());
    }
    let start: u64 = read_user(cs + 8).map_err(|_| ())?;
    let offset: u64 = read_user(cs + 16).map_err(|_| ())?;
    let abort: u64 = read_user(cs + 24).map_err(|_| ())?;
    write_user(reg.area + 8, &0u64).map_err(|_| ())?;
    let end = start.checked_add(offset).ok_or(())?;
    if frame.rip < start || frame.rip >= end {
        return Ok(());
    }
    // The abort handler lies outside the section, after the signature.
    if (start..end).contains(&abort) || abort < 4 {
        return Err(());
    }
    let found: u32 = read_user(abort - 4).map_err(|_| ())?;
    if found != reg.sig {
        return Err(());
    }
    frame.rip = abort;
    Ok(())
}
