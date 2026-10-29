// SPDX-License-Identifier: MIT OR Apache-2.0

//! A sampling profiler (ADR 0062), controlled through
//! `/proc/slate_profile` by root. Writing names, as for
//! `/proc/slate_strace` (`NAME`, `PREFIX*`, `pid:N`, comma-separated), or
//! `all` (every CPU, kernel threads and idle included) starts a new
//! profile; writing an empty line stops it and keeps what it found. On
//! each timer interrupt (at least `TICK_HZ` times a second on every CPU)
//! the instruction pointer the interrupt stopped is recorded if the
//! running process matches, with whether it was user or kernel code.
//!
//! Reading gives a header, `# samples N dropped N running yes|no`, a
//! `# pid PID NAME EXE BIAS` line for each process sampled (BIAS, in
//! hexadecimal, is where a position-independent program was loaded:
//! subtract it from its user addresses, ADR 0092), a `# kernel SLIDE`
//! line (where KASLR put the kernel, ADR 0095: subtract it from kernel
//! addresses), then the samples
//! counted by place, most first: `COUNT PID u|k ADDRESS` (hexadecimal).
//! `cargo xtask bench` turns the addresses into function names on the
//! host.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::ktest::{Test, ensure};
use crate::sync::IrqSpinLock;

/// The most samples one profile keeps (16 bytes each).
const MAX_SAMPLES: usize = 1 << 17;

#[derive(Clone, Copy, Debug)]
struct Sample {
    pid: u32,
    user: bool,
    rip: u64,
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static FILTER: IrqSpinLock<Vec<String>> = IrqSpinLock::new(Vec::new());
static SAMPLES: IrqSpinLock<Vec<Sample>> = IrqSpinLock::new(Vec::new());

/// Start a new profile of `spec`, or stop the running one (empty).
pub fn set(spec: &str) {
    let list: Vec<String> = spec.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect();
    ENABLED.store(false, Ordering::Release);
    if list.is_empty() {
        return;
    }
    // The buffer is made here, never in the interrupt.
    let mut fresh = Vec::new();
    fresh.reserve_exact(MAX_SAMPLES);
    *SAMPLES.lock() = fresh;
    DROPPED.store(0, Ordering::Relaxed);
    *FILTER.lock() = list;
    ENABLED.store(true, Ordering::Release);
}

/// Called from the timer interrupt with the interrupted `rip`.
pub fn sample(rip: u64, user: bool) {
    if !ENABLED.load(Ordering::Acquire) {
        return;
    }
    let p = super::current();
    let (pid, wanted) = {
        let filter = FILTER.lock();
        match &p {
            _ if filter.iter().any(|f| f == "all") => (p.as_ref().map_or(0, |p| p.pid), true),
            None => (0, false),
            Some(p) => {
                let name = p.name.lock();
                let hit = filter.iter().any(|f| {
                    *f == *name
                        || f.strip_suffix('*').is_some_and(|pre| name.starts_with(pre))
                        || f.strip_prefix("pid:").and_then(|n| n.parse().ok()) == Some(p.pid)
                });
                (p.pid, hit)
            }
        }
    };
    if !wanted {
        return;
    }
    let mut samples = SAMPLES.lock();
    if samples.len() < samples.capacity() {
        samples.push(Sample { pid, user, rip });
    } else {
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

/// The text of `/proc/slate_profile`.
pub fn report() -> String {
    let samples: Vec<Sample> = SAMPLES.lock().clone();
    let mut counts: BTreeMap<(u32, bool, u64), u64> = BTreeMap::new();
    for s in &samples {
        *counts.entry((s.pid, s.user, s.rip)).or_default() += 1;
    }
    let mut out = String::new();
    let running = if ENABLED.load(Ordering::Acquire) { "yes" } else { "no" };
    let _ = writeln!(out, "# samples {} dropped {} running {running}", samples.len(), DROPPED.load(Ordering::Relaxed));
    let _ = writeln!(out, "# kernel {:x}", crate::arch::paging::kernel_slide());
    let mut pids: Vec<u32> = counts.keys().map(|k| k.0).collect();
    pids.dedup();
    for pid in pids {
        let (name, exe, bias) = match super::get(pid) {
            Some(p) => {
                let exe = p.exe.lock().clone().map_or_else(|| String::from("-"), |d| d.path_from(None));
                (p.name.lock().clone(), exe, p.exe_bias.load(Ordering::Relaxed))
            }
            None if pid == 0 => (String::from("kernel"), String::from("-"), 0),
            None => (String::from("?"), String::from("-"), 0),
        };
        let _ = writeln!(out, "# pid {pid} {name} {exe} {bias:x}");
    }
    let mut by_count: Vec<_> = counts.into_iter().collect();
    by_count.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    for ((pid, user, rip), n) in by_count {
        let _ = writeln!(out, "{n} {pid} {} {rip:x}", if user { 'u' } else { 'k' });
    }
    out
}

pub const TESTS: &[Test] = &[Test { name: "proc::profile", run: profile_test }];

/// A profile of everything while this thread spins finds kernel samples,
/// and stops when told.
fn profile_test() -> Result<(), &'static str> {
    set("all");
    let until = crate::time::monotonic_ns() + 30_000_000;
    while crate::time::monotonic_ns() < until {
        core::hint::spin_loop();
    }
    set("");
    let r = report();
    let taken = SAMPLES.lock().len();
    ensure(taken >= 10, "fewer than 10 samples in 30 ms on every CPU")?;
    ensure(r.starts_with(&alloc::format!("# samples {taken} dropped 0 running no\n")), "a bad header")?;
    ensure(r.lines().any(|l| l.split(' ').nth(2) == Some("k")), "no kernel samples")?;
    // Stopped: no more samples.
    let until = crate::time::monotonic_ns() + 5_000_000;
    while crate::time::monotonic_ns() < until {
        core::hint::spin_loop();
    }
    ensure(SAMPLES.lock().len() == taken, "samples after the profile stopped")?;
    // A name that matches nothing samples nothing.
    set("no-such-program");
    let until = crate::time::monotonic_ns() + 5_000_000;
    while crate::time::monotonic_ns() < until {
        core::hint::spin_loop();
    }
    set("");
    ensure(SAMPLES.lock().is_empty(), "samples of a process that does not run")?;
    *SAMPLES.lock() = Vec::new();
    Ok(())
}
