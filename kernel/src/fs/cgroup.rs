// SPDX-License-Identifier: MIT OR Apache-2.0

//! cgroup v2 (cgroups(7), ADR 0028): a hierarchy of control groups as a
//! file system. Directories are cgroups; every process is in exactly one,
//! inherited on fork, and moves when its PID is written to `cgroup.procs`.
//! Controllers (ADR 0045): `pids` (enforced at fork), `memory` (anonymous
//! memory charged per cgroup, `memory.max` enforced by refusing charges
//! and the out-of-memory killer), `cpu` (`cpu.max` enforced by holding a
//! cgroup's threads back until its next period; `cpu.weight` accepted
//! only) and `io` (accepted only).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::File;
use super::vfs::*;
use crate::abi::linux::errno::*;
use crate::proc::{self, Pid};
use crate::sync::IrqSpinLock;

/// CGROUP2_SUPER_MAGIC (statfs(2)).
const CGROUP2_MAGIC: i64 = 0x6367_7270;
const CGROUP_DEV: u64 = 0xF2;
const CONTROLLERS: &[&str] = &["cpu", "io", "memory", "pids"];

#[derive(Debug, Default)]
struct State {
    children: BTreeMap<String, Arc<Cgroup>>,
    subtree_control: BTreeSet<&'static str>,
    pids_max: Option<u64>,
    /// memory.max and memory.high as written, in bytes (the counters hold
    /// them in pages).
    memory_max: Option<u64>,
    memory_high: Option<u64>,
    cpu_weight: u64,
    frozen: bool,
    /// Device-controller BPF programs attached here.
    device_progs: Vec<Arc<crate::abi::linux::bpf::BpfProg>>,
}

#[derive(Debug)]
pub struct Cgroup {
    name: String,
    parent: Option<Weak<Cgroup>>,
    ino: u64,
    state: IrqSpinLock<State>,
    /// Memory counters (none once every slot is taken; `mm/memcg.rs`).
    mem: Option<&'static crate::mm::memcg::MemCg>,
    cpu: CpuBandwidth,
}

/// The cpu controller: CPU time used, and `cpu.max`, a quota of run time
/// per period. Once the cgroup (with its descendants) has used its quota,
/// its threads are parked until the next period begins.
#[derive(Debug)]
struct CpuBandwidth {
    /// Nanoseconds of CPU time used here and below, in all, in user mode
    /// and in the kernel.
    usage: AtomicU64,
    user: AtomicU64,
    system: AtomicU64,
    /// Quota per period in nanoseconds (u64::MAX: none), and the period.
    quota: AtomicU64,
    period: AtomicU64,
    /// Run time used in this period.
    used: AtomicU64,
    throttled: AtomicBool,
    /// When throttling began (monotonic ns).
    throttled_since: AtomicU64,
    nr_periods: AtomicU64,
    nr_throttled: AtomicU64,
    throttled_ns: AtomicU64,
    /// Threads held back until the next period.
    parked: IrqSpinLock<Vec<Arc<crate::sched::Thread>>>,
    /// A period timer is pending.
    timer: AtomicBool,
}

/// cpu.max's default period: 100 ms.
const DEFAULT_PERIOD_NS: u64 = 100_000_000;

impl CpuBandwidth {
    fn new() -> CpuBandwidth {
        CpuBandwidth {
            usage: AtomicU64::new(0),
            user: AtomicU64::new(0),
            system: AtomicU64::new(0),
            quota: AtomicU64::new(u64::MAX),
            period: AtomicU64::new(DEFAULT_PERIOD_NS),
            used: AtomicU64::new(0),
            throttled: AtomicBool::new(false),
            throttled_since: AtomicU64::new(0),
            nr_periods: AtomicU64::new(0),
            nr_throttled: AtomicU64::new(0),
            throttled_ns: AtomicU64::new(0),
            parked: IrqSpinLock::new(Vec::new()),
            timer: AtomicBool::new(false),
        }
    }

    /// Stop throttling and give back the parked threads.
    fn unthrottle(&self) -> Vec<Arc<crate::sched::Thread>> {
        let mut parked = self.parked.lock();
        if self.throttled.swap(false, Ordering::Relaxed) {
            let since = self.throttled_since.load(Ordering::Relaxed);
            self.throttled_ns.fetch_add(crate::time::monotonic_ns().saturating_sub(since), Ordering::Relaxed);
        }
        core::mem::take(&mut *parked)
    }
}

/// Charge CPU time a thread of `cg` used (from the scheduler). Returns
/// true if `cg` or an ancestor has now used its quota: the thread must
/// stop.
pub fn charge_cpu(cg: &Arc<Cgroup>, user_ns: u64, system_ns: u64) -> bool {
    let mut stop = false;
    let mut at = Some(cg.clone());
    while let Some(c) = at {
        let b = &c.cpu;
        b.usage.fetch_add(user_ns + system_ns, Ordering::Relaxed);
        b.user.fetch_add(user_ns, Ordering::Relaxed);
        b.system.fetch_add(system_ns, Ordering::Relaxed);
        let quota = b.quota.load(Ordering::Relaxed);
        if quota != u64::MAX {
            let used = b.used.fetch_add(user_ns + system_ns, Ordering::Relaxed) + user_ns + system_ns;
            if used >= quota {
                let _g = b.parked.lock();
                if !b.throttled.swap(true, Ordering::Relaxed) {
                    b.nr_throttled.fetch_add(1, Ordering::Relaxed);
                    b.throttled_since.store(crate::time::monotonic_ns(), Ordering::Relaxed);
                }
                stop = true;
            }
        }
        at = c.parent();
    }
    stop
}

/// If `cg` or an ancestor is throttled, park `t` there until its next
/// period (from the scheduler, which then runs something else).
pub fn park_if_throttled(cg: &Arc<Cgroup>, t: &Arc<crate::sched::Thread>) -> bool {
    let mut at = Some(cg.clone());
    while let Some(c) = at {
        if c.cpu.throttled.load(Ordering::Relaxed) {
            let mut parked = c.cpu.parked.lock();
            if c.cpu.throttled.load(Ordering::Relaxed) {
                parked.push(t.clone());
                return true;
            }
        }
        at = c.parent();
    }
    false
}

/// A cpu.max period ended: start a new one. Run time beyond the quota is
/// carried over, so the quota holds on average.
fn cpu_period(cg: Arc<Cgroup>) {
    let b = &cg.cpu;
    let quota = b.quota.load(Ordering::Relaxed);
    b.nr_periods.fetch_add(1, Ordering::Relaxed);
    let used = b.used.load(Ordering::Relaxed);
    b.used.store(used.saturating_sub(quota), Ordering::Relaxed);
    let threads = if quota == u64::MAX || used.saturating_sub(quota) < quota { b.unthrottle() } else { Vec::new() };
    for t in threads {
        crate::sched::unpark(t);
    }
    if quota == u64::MAX {
        b.timer.store(false, Ordering::Relaxed);
        return;
    }
    let at = crate::time::monotonic_ns() + b.period.load(Ordering::Relaxed);
    crate::time::add_timer(at, move || cpu_period(cg));
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        if let Some(m) = self.mem {
            m.release();
        }
    }
}

static NEXT_INO: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(16);
static ROOT: slate_sync::Once<Arc<Cgroup>> = slate_sync::Once::new();

/// The root cgroup.
pub fn root() -> Arc<Cgroup> {
    ROOT.call_once(|| {
        Arc::new(Cgroup {
            name: String::new(),
            parent: None,
            ino: 1,
            state: IrqSpinLock::new(State { cpu_weight: 100, ..Default::default() }),
            mem: crate::mm::memcg::new(None),
            cpu: CpuBandwidth::new(),
        })
    })
    .clone()
}

// bpf_cgroup_dev_ctx values (bpf(2), BPF_PROG_TYPE_CGROUP_DEVICE).
pub const DEV_BLOCK: u32 = 1;
pub const DEV_CHAR: u32 = 2;
pub const ACC_MKNOD: u32 = 1;
pub const ACC_READ: u32 = 2;
pub const ACC_WRITE: u32 = 4;

/// The device controller: may the calling process use device `kind`
/// `major:minor` with `access` (ACC_* bits)? Every device program of its
/// cgroup and their ancestors must return non-zero; a program that fails
/// denies.
pub fn device_allowed(kind: u32, major: u32, minor: u32, access: u32) -> bool {
    let Some(p) = proc::current() else { return true };
    let mut ctx = [0u8; 12];
    ctx[..4].copy_from_slice(&(kind | (access << 16)).to_le_bytes());
    ctx[4..8].copy_from_slice(&major.to_le_bytes());
    ctx[8..].copy_from_slice(&minor.to_le_bytes());
    let mut at = Some(p.cgroup());
    while let Some(cg) = at {
        let progs = cg.state.lock().device_progs.clone();
        for prog in progs {
            if !slate_bpf::run_ebpf(&prog.insns, &ctx).is_ok_and(|r| r != 0) {
                return false;
            }
        }
        at = cg.parent();
    }
    true
}

/// The cgroup a cgroup2 directory inode stands for.
pub fn of_inode(i: &Arc<dyn Inode>) -> Option<Arc<Cgroup>> {
    i.as_any().downcast_ref::<CgInode>().filter(|c| c.file.is_none()).map(|c| c.cg.clone())
}

impl Cgroup {
    /// Attach a device program (BPF_F_ALLOW_MULTI semantics: programs add
    /// up; attaching one already there is EEXIST).
    pub fn attach_device_prog(&self, p: Arc<crate::abi::linux::bpf::BpfProg>) -> Result<()> {
        let mut st = self.state.lock();
        if st.device_progs.iter().any(|x| x.id == p.id) {
            return Err(EEXIST);
        }
        st.device_progs.push(p);
        Ok(())
    }

    /// Detach program `id` (or all, with `None`); ENOENT if not attached.
    pub fn detach_device_prog(&self, id: Option<u32>) -> Result<()> {
        let mut st = self.state.lock();
        let before = st.device_progs.len();
        st.device_progs.retain(|x| id.is_some_and(|i| x.id != i));
        if st.device_progs.len() == before { Err(ENOENT) } else { Ok(()) }
    }

    pub fn device_prog_ids(&self) -> Vec<u32> {
        self.state.lock().device_progs.iter().map(|p| p.id).collect()
    }

    fn parent(&self) -> Option<Arc<Cgroup>> {
        self.parent.as_ref().and_then(Weak::upgrade)
    }

    /// The memory counters its processes' pages are charged to.
    pub fn memcg(&self) -> Option<&'static crate::mm::memcg::MemCg> {
        self.mem
    }

    /// Set cpu.max: `quota` nanoseconds of run time per `period` (`None`:
    /// no limit).
    fn set_cpu_max(self: &Arc<Self>, quota: Option<u64>, period: u64) {
        let b = &self.cpu;
        b.period.store(period, Ordering::Relaxed);
        b.quota.store(quota.unwrap_or(u64::MAX), Ordering::Relaxed);
        if quota.is_none() {
            for t in b.unthrottle() {
                crate::sched::unpark(t);
            }
        } else if !b.timer.swap(true, Ordering::Relaxed) {
            b.used.store(0, Ordering::Relaxed);
            let cg = self.clone();
            crate::time::add_timer(crate::time::monotonic_ns() + period, move || cpu_period(cg));
        }
    }

    /// The path from the root (`/` for the root itself).
    pub fn path(&self) -> String {
        let mut parts = Vec::new();
        let mut c = Some(self.name.clone());
        let mut at = self.parent();
        while let Some(n) = c {
            if !n.is_empty() {
                parts.push(n);
            }
            c = at.as_ref().map(|p| p.name.clone());
            at = at.and_then(|p| p.parent());
        }
        parts.reverse();
        format!("/{}", parts.join("/"))
    }

    fn is_under(self: &Arc<Self>, ancestor: &Arc<Cgroup>) -> bool {
        let mut c = Some(self.clone());
        while let Some(x) = c {
            if Arc::ptr_eq(&x, ancestor) {
                return true;
            }
            c = x.parent();
        }
        false
    }

    /// Processes directly in this cgroup (host PIDs).
    fn members(self: &Arc<Self>) -> Vec<Pid> {
        proc::all().iter().filter(|p| !p.is_zombie() && Arc::ptr_eq(&p.cgroup(), self)).map(|p| p.pid).collect()
    }

    /// Processes in this cgroup and below.
    fn subtree_count(self: &Arc<Self>) -> u64 {
        proc::all().iter().filter(|p| !p.is_zombie() && p.cgroup().is_under(self)).count() as u64
    }

    /// Controllers available here: all at the root, else those the parent
    /// enabled for its children.
    fn controllers(&self) -> Vec<&'static str> {
        match self.parent() {
            None => CONTROLLERS.to_vec(),
            Some(p) => p.state.lock().subtree_control.iter().copied().collect(),
        }
    }
}

/// A memory size as cgroup files take it: bytes, with an optional K, M,
/// G or T suffix, or "max" (`None`).
fn memory_size(t: &str) -> Result<Option<u64>> {
    if t == "max" {
        return Ok(None);
    }
    let (num, shift) = match t.as_bytes().last() {
        Some(b'k' | b'K') => (&t[..t.len() - 1], 10),
        Some(b'm' | b'M') => (&t[..t.len() - 1], 20),
        Some(b'g' | b'G') => (&t[..t.len() - 1], 30),
        Some(b't' | b'T') => (&t[..t.len() - 1], 40),
        _ => (t, 0),
    };
    let n: u64 = num.parse().map_err(|_| EINVAL)?;
    n.checked_mul(1 << shift).map(Some).ok_or(EINVAL)
}

/// May a process be added to `cg`? `pids.max` on it and every ancestor.
pub fn may_fork(cg: &Arc<Cgroup>) -> bool {
    let mut c = Some(cg.clone());
    while let Some(x) = c {
        if let Some(max) = x.state.lock().pids_max
            && x.subtree_count() >= max
        {
            return false;
        }
        c = x.parent();
    }
    true
}

/// /proc/<pid>/cgroup: the v2 line.
pub fn proc_line(p: &proc::Process) -> String {
    // Relative to the reader's cgroup namespace root (cgroup_namespaces(7)).
    let ns_root = proc::current().map_or_else(root, |me| me.namespaces().cgroup.root.clone());
    let (path, base) = (p.cgroup().path(), ns_root.path());
    let shown = if base == "/" {
        path
    } else if path == base {
        "/".into()
    } else if let Some(rest) = path.strip_prefix(&base).filter(|r| r.starts_with('/')) {
        rest.into()
    } else {
        // Outside the namespace root: shown relative to it.
        let ups = base.matches('/').count();
        format!("{}{}", "/..".repeat(ups), path)
    };
    format!("0::{shown}\n")
}

/// A new cgroup2 file system: rooted at the mounter's cgroup namespace
/// root (cgroup_namespaces(7)).
pub fn new() -> Arc<dyn Inode> {
    let cg = proc::current().map_or_else(root, |me| me.namespaces().cgroup.root.clone());
    Arc::new(CgInode { cg, file: None })
}

const ROOT_FILES: &[&str] = &["cgroup.controllers", "cgroup.procs", "cgroup.subtree_control", "cgroup.threads"];
const FILES: &[&str] = &[
    "cgroup.controllers",
    "cgroup.events",
    "cgroup.freeze",
    "cgroup.kill",
    "cgroup.max.depth",
    "cgroup.max.descendants",
    "cgroup.procs",
    "cgroup.stat",
    "cgroup.subtree_control",
    "cgroup.threads",
    "cgroup.type",
    "cpu.max",
    "cpu.stat",
    "cpu.weight",
    "io.max",
    "io.stat",
    "memory.current",
    "memory.events",
    "memory.high",
    "memory.low",
    "memory.max",
    "memory.min",
    "memory.peak",
    "memory.stat",
    "memory.swap.current",
    "memory.swap.max",
    "pids.current",
    "pids.events",
    "pids.max",
    "pids.peak",
];

struct CgInode {
    cg: Arc<Cgroup>,
    file: Option<&'static str>,
}

impl CgInode {
    fn files(&self) -> &'static [&'static str] {
        if self.cg.parent.is_none() { ROOT_FILES } else { FILES }
    }

    fn generate(&self, name: &str) -> Result<String> {
        let cg = &self.cg;
        let st = || cg.state.lock();
        let opt = |v: Option<u64>| v.map_or_else(|| "max".to_string(), |n| n.to_string());
        let mut s = String::new();
        match name {
            "cgroup.controllers" => s = cg.controllers().join(" "),
            "cgroup.subtree_control" => s = st().subtree_control.iter().copied().collect::<Vec<_>>().join(" "),
            "cgroup.procs" | "cgroup.threads" => {
                for p in cg.members() {
                    let _ = writeln!(s, "{}", proc::pid_in_caller_ns(p).unwrap_or(0));
                }
                return Ok(s);
            }
            "cgroup.type" => s = "domain".into(),
            "cgroup.events" => {
                s = format!("populated {}\nfrozen {}", u8::from(cg.subtree_count() > 0), u8::from(st().frozen))
            }
            "cgroup.freeze" => s = u8::from(st().frozen).to_string(),
            "cgroup.max.depth" | "cgroup.max.descendants" => s = "max".into(),
            "cgroup.stat" => s = format!("nr_descendants {}\nnr_dying_descendants 0", st().children.len()),
            "cpu.max" => {
                let b = &cg.cpu;
                let quota = b.quota.load(Ordering::Relaxed);
                let q = if quota == u64::MAX { "max".to_string() } else { (quota / 1000).to_string() };
                s = format!("{q} {}", b.period.load(Ordering::Relaxed) / 1000);
            }
            "cpu.weight" => s = st().cpu_weight.to_string(),
            "cpu.stat" => {
                let b = &cg.cpu;
                let us = |a: &AtomicU64| a.load(Ordering::Relaxed) / 1000;
                s = format!("usage_usec {}\nuser_usec {}\nsystem_usec {}", us(&b.usage), us(&b.user), us(&b.system));
                if cg.parent.is_some() {
                    let _ = write!(
                        s,
                        "\nnr_periods {}\nnr_throttled {}\nthrottled_usec {}",
                        b.nr_periods.load(Ordering::Relaxed),
                        b.nr_throttled.load(Ordering::Relaxed),
                        us(&b.throttled_ns)
                    );
                }
            }
            "io.max" | "io.stat" => return Ok(String::new()),
            "memory.current" => s = (cg.mem.map_or(0, |m| m.pages()) * 4096).to_string(),
            "memory.peak" => s = (cg.mem.map_or(0, |m| m.peak()) * 4096).to_string(),
            "memory.max" => s = opt(st().memory_max),
            "memory.high" => s = opt(st().memory_high),
            "memory.low" | "memory.min" | "memory.swap.current" => s = "0".into(),
            "memory.swap.max" => s = "max".into(),
            "memory.events" => {
                let ev =
                    |f: fn(&crate::mm::memcg::MemCg) -> &AtomicU64| cg.mem.map_or(0, |m| f(m).load(Ordering::Relaxed));
                s = format!(
                    "low 0\nhigh {}\nmax {}\noom {}\noom_kill {}",
                    ev(|m| &m.events_high),
                    ev(|m| &m.events_max),
                    ev(|m| &m.events_oom),
                    ev(|m| &m.events_oom_kill)
                );
            }
            // Only anonymous memory is charged (GAPS).
            "memory.stat" => s = format!("anon {}\nfile 0", cg.mem.map_or(0, |m| m.pages()) * 4096),
            "pids.current" | "pids.peak" => s = cg.subtree_count().to_string(),
            "pids.max" => s = opt(st().pids_max),
            "pids.events" => s = "max 0".into(),
            _ => return Err(ENOENT),
        }
        s.push('\n');
        Ok(s)
    }

    fn write(&self, name: &str, text: &str) -> Result<()> {
        let cg = &self.cg;
        let t = text.trim();
        let limit = |v: &str| -> Result<Option<u64>> {
            if v == "max" { Ok(None) } else { v.parse().map(Some).map_err(|_| EINVAL) }
        };
        match name {
            "cgroup.procs" | "cgroup.threads" => {
                let pid: Pid = t.parse().map_err(|_| EINVAL)?;
                let p =
                    if pid == 0 { proc::current().ok_or(ESRCH)? } else { proc::find_in_caller_ns(pid).ok_or(ESRCH)? };
                if !may_fork(cg) && !Arc::ptr_eq(&p.cgroup(), cg) {
                    return Err(EAGAIN);
                }
                p.set_cgroup(cg.clone());
            }
            "cgroup.subtree_control" => {
                let avail = cg.controllers();
                let mut st = cg.state.lock();
                for w in t.split_whitespace() {
                    let (on, c) = match w.as_bytes()[0] {
                        b'+' => (true, &w[1..]),
                        b'-' => (false, &w[1..]),
                        _ => return Err(EINVAL),
                    };
                    let c = *avail.iter().find(|a| **a == c).ok_or(ENOENT)?;
                    if on {
                        st.subtree_control.insert(c);
                    } else {
                        st.subtree_control.remove(c);
                    }
                }
            }
            "cgroup.freeze" => cg.state.lock().frozen = t == "1",
            "cgroup.kill" if t == "1" => {
                for p in proc::all().iter().filter(|p| p.cgroup().is_under(cg)) {
                    proc::signal::send_to_process(p, proc::signal::SIGKILL);
                }
            }
            "cpu.max" => {
                // "$MAX $PERIOD" in microseconds, or just "$MAX" (cgroups(7)).
                let mut w = t.split_whitespace();
                let quota = limit(w.next().ok_or(EINVAL)?)?;
                let period = match w.next() {
                    Some(p) => p.parse::<u64>().map_err(|_| EINVAL)?,
                    None => cg.cpu.period.load(Ordering::Relaxed) / 1000,
                };
                if w.next().is_some()
                    || !(1000..=1_000_000).contains(&period)
                    || quota.is_some_and(|q| !(1000..=u64::MAX / 1000).contains(&q))
                {
                    return Err(EINVAL);
                }
                cg.set_cpu_max(quota.map(|q| q * 1000), period * 1000);
            }
            "cpu.weight" => {
                let w: u64 = t.parse().map_err(|_| EINVAL)?;
                if !(1..=10000).contains(&w) {
                    return Err(EINVAL);
                }
                cg.state.lock().cpu_weight = w;
                crate::log::accepted_without_effect("cgroup cpu.weight (kept, not applied)");
            }
            "memory.max" | "memory.high" => {
                let bytes = memory_size(t)?;
                let pages = bytes.map_or(crate::mm::memcg::UNLIMITED, |b| b / 4096);
                if let Some(m) = cg.mem {
                    if name == "memory.max" { m.set_max(pages) } else { m.set_high(pages) }
                }
                let mut st = cg.state.lock();
                if name == "memory.max" {
                    st.memory_max = bytes
                } else {
                    st.memory_high = bytes
                }
                if name == "memory.high" {
                    crate::log::accepted_without_effect("cgroup memory.high (counted, not throttled)");
                }
            }
            "pids.max" => cg.state.lock().pids_max = limit(t)?,
            "io.max"
            | "memory.low"
            | "memory.min"
            | "memory.swap.max"
            | "cgroup.max.depth"
            | "cgroup.max.descendants"
            | "cgroup.type" => crate::log::accepted_without_effect(
                "cgroup io.max, memory.low/min/swap.max, cgroup.max.* or cgroup.type",
            ),
            _ => return Err(EINVAL),
        }
        Ok(())
    }
}

impl Inode for CgInode {
    fn metadata(&self) -> Metadata {
        let now = Timespec::now();
        let (ino, mode) = match self.file {
            None => (self.cg.ino << 8, S_IFDIR | 0o755),
            Some(f) => {
                let h = f.bytes().fold(7u64, |h, b| h.wrapping_mul(31).wrapping_add(u64::from(b))) & 0xff;
                let ro = f.ends_with(".current")
                    || f.ends_with(".stat")
                    || f.ends_with(".events")
                    || f == "cgroup.controllers";
                ((self.cg.ino << 8) | h, S_IFREG | if ro { 0o444 } else { 0o644 })
            }
        };
        Metadata { dev: CGROUP_DEV, ino, mode, nlink: 1, atime: now, mtime: now, ctime: now, ..Default::default() }
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        if self.file.is_some() {
            return Err(ENOTDIR);
        }
        if let Some(c) = self.cg.state.lock().children.get(name) {
            return Ok(Arc::new(CgInode { cg: c.clone(), file: None }));
        }
        let f = self.files().iter().find(|f| **f == name).ok_or(ENOENT)?;
        Ok(Arc::new(CgInode { cg: self.cg.clone(), file: Some(f) }))
    }

    fn readdir(&self) -> Result<Vec<DirEntry>> {
        if self.file.is_some() {
            return Err(ENOTDIR);
        }
        let mut out = Vec::new();
        for (i, f) in self.files().iter().enumerate() {
            out.push(DirEntry {
                name: (*f).into(),
                ino: (self.cg.ino << 8) | i as u64,
                kind: FileType::Regular,
                pos: i as u64,
            });
        }
        for (i, (n, c)) in self.cg.state.lock().children.iter().enumerate() {
            out.push(DirEntry { name: n.clone(), ino: c.ino << 8, kind: FileType::Directory, pos: 1000 + i as u64 });
        }
        Ok(out)
    }

    fn mkdir(&self, name: &str, _mode: u32) -> Result<Arc<dyn Inode>> {
        if self.file.is_some() {
            return Err(ENOTDIR);
        }
        if name.contains('/') || name.starts_with('.') || FILES.contains(&name) {
            return Err(EINVAL);
        }
        let mut st = self.cg.state.lock();
        if st.children.contains_key(name) {
            return Err(EEXIST);
        }
        let c = Arc::new(Cgroup {
            name: name.into(),
            parent: Some(Arc::downgrade(&self.cg)),
            ino: NEXT_INO.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
            state: IrqSpinLock::new(State { cpu_weight: 100, ..Default::default() }),
            mem: crate::mm::memcg::new(self.cg.mem),
            cpu: CpuBandwidth::new(),
        });
        st.children.insert(name.into(), c.clone());
        Ok(Arc::new(CgInode { cg: c, file: None }))
    }

    fn rmdir(&self, name: &str) -> Result<()> {
        let c = self.cg.state.lock().children.get(name).cloned().ok_or(ENOENT)?;
        if !c.state.lock().children.is_empty() || c.subtree_count() > 0 {
            return Err(EBUSY);
        }
        self.cg.state.lock().children.remove(name);
        // Its period timer stops, and threads it held back (of processes
        // that moved away) run again.
        c.set_cpu_max(None, DEFAULT_PERIOD_NS);
        Ok(())
    }

    fn statfs(&self) -> Option<StatFs> {
        Some(StatFs {
            magic: CGROUP2_MAGIC,
            block_size: 4096,
            blocks: 0,
            free_blocks: 0,
            files: 0,
            free_files: 0,
            read_only: false,
        })
    }

    fn open_special(self: Arc<Self>, flags: u32) -> Option<Result<Arc<dyn File>>> {
        let f = self.file?;
        Some(self.generate(f).map(|text| {
            let file: Arc<dyn File> = Arc::new(CgFile {
                inode: self.clone(),
                data: IrqSpinLock::new(text.into_bytes()),
                offset: IrqSpinLock::new(0),
                flags,
            });
            file
        }))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// An open cgroup file: contents generated at open and again whenever it
/// is read from the start after a seek (so polling a file such as
/// cgroup.freeze or cgroup.events sees changes); writes applied at once.
struct CgFile {
    inode: Arc<CgInode>,
    data: IrqSpinLock<Vec<u8>>,
    offset: IrqSpinLock<usize>,
    flags: u32,
}

impl CgFile {
    fn refresh(&self) {
        if let Some(f) = self.inode.file
            && let Ok(text) = self.inode.generate(f)
        {
            *self.data.lock() = text.into_bytes();
        }
    }

    fn copy_out(&self, start: usize, buf: &mut [u8]) -> usize {
        let data = self.data.lock();
        let start = start.min(data.len());
        let n = buf.len().min(data.len() - start);
        buf[..n].copy_from_slice(&data[start..start + n]);
        n
    }
}

impl File for CgFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut off = self.offset.lock();
        let n = self.copy_out(*off, buf);
        *off += n;
        Ok(n)
    }
    fn pread(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset == 0 {
            self.refresh();
        }
        Ok(self.copy_out(offset as usize, buf))
    }
    fn seek(&self, offset: i64, whence: u32) -> Result<u64> {
        let mut off = self.offset.lock();
        let len = self.data.lock().len() as i64;
        let base = match whence {
            super::SEEK_SET => 0,
            super::SEEK_CUR => *off as i64,
            super::SEEK_END => len,
            _ => return Err(EINVAL),
        };
        let n = base.checked_add(offset).filter(|n| *n >= 0).ok_or(EINVAL)?;
        *off = n as usize;
        drop(off);
        if n == 0 {
            self.refresh();
        }
        Ok(n as u64)
    }
    fn write(&self, buf: &[u8]) -> Result<usize> {
        let text = core::str::from_utf8(buf).map_err(|_| EINVAL)?;
        self.inode.write(self.inode.file.unwrap_or(""), text)?;
        Ok(buf.len())
    }
    fn stat(&self) -> Result<Metadata> {
        Ok(self.inode.metadata())
    }
    fn status_flags(&self) -> u32 {
        self.flags
    }
}
