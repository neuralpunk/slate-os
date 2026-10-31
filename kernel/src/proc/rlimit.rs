// SPDX-License-Identifier: MIT OR Apache-2.0

//! Resource limits (getrlimit(2), ADR 0045).
//!
//! Each process has a soft and a hard limit per resource, inherited on
//! fork and kept across execve. Enforced: RLIMIT_CPU (SIGXCPU each second
//! past the soft limit, SIGKILL at the hard one), RLIMIT_FSIZE (SIGXFSZ
//! and EFBIG), RLIMIT_DATA (brk), RLIMIT_STACK (the stack reserved at
//! exec), RLIMIT_AS (brk, mmap, mremap), RLIMIT_NPROC (fork and clone),
//! RLIMIT_NOFILE (new descriptors), RLIMIT_NICE and RLIMIT_RTPRIO (raising
//! priorities), RLIMIT_RTTIME (a real-time thread's CPU time since it last
//! blocked: SIGXCPU past the soft limit and each second after, SIGKILL at
//! the hard one; ADR 0184). RLIMIT_CORE is kept: Slate writes no core
//! dumps. The rest are kept and reported only.

use core::sync::atomic::Ordering;

use super::Process;

// Resource numbers. Source: musl `sys/resource.h` (ADR 0009).
pub const RLIMIT_CPU: usize = 0;
pub const RLIMIT_FSIZE: usize = 1;
pub const RLIMIT_DATA: usize = 2;
pub const RLIMIT_STACK: usize = 3;
pub const RLIMIT_CORE: usize = 4;
#[allow(dead_code)] // Kept and reported only.
pub const RLIMIT_RSS: usize = 5;
pub const RLIMIT_NPROC: usize = 6;
pub const RLIMIT_NOFILE: usize = 7;
pub const RLIMIT_MEMLOCK: usize = 8;
pub const RLIMIT_AS: usize = 9;
#[allow(dead_code)] // Kept and reported only.
pub const RLIMIT_LOCKS: usize = 10;
pub const RLIMIT_SIGPENDING: usize = 11;
pub const RLIMIT_MSGQUEUE: usize = 12;
pub const RLIMIT_NICE: usize = 13;
pub const RLIMIT_RTPRIO: usize = 14;
pub const RLIMIT_RTTIME: usize = 15;
pub const RLIM_NLIMITS: usize = 16;
pub const RLIM_INFINITY: u64 = !0;

/// The ceiling root may raise the hard RLIMIT_NOFILE to
/// (/proc/sys/fs/nr_open).
pub const NR_OPEN: u64 = 1 << 20;

/// One resource's limits (`struct rlimit`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Rlimit {
    pub cur: u64,
    pub max: u64,
}

/// A process's limits.
#[derive(Clone, Debug)]
pub struct Limits(pub [Rlimit; RLIM_NLIMITS]);

const fn both(v: u64) -> Rlimit {
    Rlimit { cur: v, max: v }
}

impl Limits {
    /// What the first process starts with (Linux's defaults: no core
    /// files, 1024 descriptors of at most 4096, an 8 MiB stack).
    pub fn defaults() -> Limits {
        let tasks = (crate::mm::frame::stats().usable_frames / 64).max(512);
        let mut l = [both(RLIM_INFINITY); RLIM_NLIMITS];
        l[RLIMIT_STACK] = Rlimit { cur: 8 << 20, max: RLIM_INFINITY };
        l[RLIMIT_CORE] = Rlimit { cur: 0, max: RLIM_INFINITY };
        l[RLIMIT_NPROC] = both(tasks);
        l[RLIMIT_SIGPENDING] = both(tasks);
        l[RLIMIT_NOFILE] = Rlimit { cur: 1024, max: 4096 };
        l[RLIMIT_MEMLOCK] = both(8 << 20);
        l[RLIMIT_MSGQUEUE] = both(819_200);
        l[RLIMIT_NICE] = both(0);
        l[RLIMIT_RTPRIO] = both(0);
        Limits(l)
    }

    pub fn get(&self, r: usize) -> Rlimit {
        self.0[r]
    }
}

/// Resource names and units for /proc/<pid>/limits (proc(5)).
pub const NAMES: [(&str, &str); RLIM_NLIMITS] = [
    ("Max cpu time", "seconds"),
    ("Max file size", "bytes"),
    ("Max data size", "bytes"),
    ("Max stack size", "bytes"),
    ("Max core file size", "bytes"),
    ("Max resident set", "bytes"),
    ("Max processes", "processes"),
    ("Max open files", "files"),
    ("Max locked memory", "bytes"),
    ("Max address space", "bytes"),
    ("Max file locks", "locks"),
    ("Max pending signals", "signals"),
    ("Max msgqueue size", "bytes"),
    ("Max nice priority", ""),
    ("Max realtime priority", ""),
    ("Max realtime timeout", "us"),
];

impl Process {
    /// One of the process's limits.
    pub fn rlimit(&self, r: usize) -> Rlimit {
        self.limits.lock().get(r)
    }

    /// Set a limit (the caller checked it), and what depends on it.
    pub fn set_rlimit(&self, r: usize, l: Rlimit) {
        self.limits.lock().0[r] = l;
        match r {
            RLIMIT_NOFILE => self.files.lock().set_limit(l.cur.min(NR_OPEN) as usize),
            RLIMIT_CPU => {
                let ns = |s: u64| s.saturating_mul(crate::time::NS_PER_SEC);
                self.cpu_limit_ns[0].store(ns(l.cur), Ordering::Relaxed);
                self.cpu_limit_ns[1].store(ns(l.max), Ordering::Relaxed);
            }
            // In microseconds (getrlimit(2)).
            RLIMIT_RTTIME => {
                let ns = |us: u64| us.saturating_mul(1000);
                self.rt_limit_ns[0].store(ns(l.cur), Ordering::Relaxed);
                self.rt_limit_ns[1].store(ns(l.max), Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// Whether `bytes` more of address space stay within RLIMIT_AS (and,
    /// for the heap, RLIMIT_DATA).
    pub fn may_grow(&self, bytes: u64, data: bool) -> bool {
        let as_limit = self.rlimit(RLIMIT_AS).cur;
        let data_limit = if data { self.rlimit(RLIMIT_DATA).cur } else { RLIM_INFINITY };
        if as_limit == RLIM_INFINITY && data_limit == RLIM_INFINITY {
            return true;
        }
        let a = self.aspace.lock();
        let Some(a) = a.as_ref() else { return true };
        let total = a.mapped_bytes().saturating_add(bytes);
        let heap = a.brk.saturating_sub(a.brk_start).saturating_add(bytes);
        total <= as_limit && (!data || heap <= data_limit)
    }
}

/// RLIMIT_CPU, from the timer tick: SIGXCPU once a second past the soft
/// limit, SIGKILL at the hard one (getrlimit(2)).
pub fn check_cpu_limit(p: &alloc::sync::Arc<Process>) {
    let soft = p.cpu_limit_ns[0].load(Ordering::Relaxed);
    if soft == u64::MAX {
        return;
    }
    let (u, s) = p.cpu.own();
    let used = u + s;
    if used >= p.cpu_limit_ns[1].load(Ordering::Relaxed) {
        super::signal::send_to_process(p, super::signal::SIGKILL);
    } else if used >= soft {
        let second = used / crate::time::NS_PER_SEC;
        if p.cpu_limit_signalled.swap(second + 1, Ordering::Relaxed) != second + 1 {
            super::signal::send_to_process(p, super::signal::SIGXCPU);
        }
    }
}

/// RLIMIT_RTTIME, from the timer tick, for a real-time thread that has run
/// `ran_ns` of CPU time since it last blocked (getrlimit(2)): SIGXCPU when
/// it passes the soft limit and once a second after that, SIGKILL at the
/// hard limit. `signalled` is the thread's count of SIGXCPUs sent.
pub fn check_rt_limit(p: &alloc::sync::Arc<Process>, ran_ns: u64, signalled: &core::sync::atomic::AtomicU64) {
    let soft = p.rt_limit_ns[0].load(Ordering::Relaxed);
    if ran_ns < soft {
        return;
    }
    if ran_ns >= p.rt_limit_ns[1].load(Ordering::Relaxed) {
        crate::log_warn!("pid {}: a real-time thread ran past RLIMIT_RTTIME's hard limit; killed", p.pid);
        super::signal::send_to_process(p, super::signal::SIGKILL);
        return;
    }
    // The first at the soft limit, then one for each further second.
    let due = 1 + (ran_ns - soft) / crate::time::NS_PER_SEC;
    if signalled.load(Ordering::Relaxed) < due {
        signalled.store(due, Ordering::Relaxed);
        super::signal::send_to_process(p, super::signal::SIGXCPU);
    }
}

/// RLIMIT_FSIZE for a write or truncation that would make a file `end`
/// bytes long: how far it may go. Past the limit, the process gets
/// SIGXFSZ and the call fails with EFBIG (getrlimit(2)); a write that
/// starts below it is cut short.
pub fn file_size_limit(start: u64, end: u64) -> Result<u64, crate::abi::linux::errno::Errno> {
    let Some(p) = super::current() else { return Ok(end) };
    let limit = p.rlimit(RLIMIT_FSIZE).cur;
    if end <= limit {
        return Ok(end);
    }
    if start >= limit {
        super::signal::send_to_process(&p, super::signal::SIGXFSZ);
        return Err(crate::abi::linux::errno::EFBIG);
    }
    Ok(limit)
}
