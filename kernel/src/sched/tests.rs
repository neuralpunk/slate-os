// SPDX-License-Identifier: MIT OR Apache-2.0

//! In-kernel tests for threads, the scheduler and locks.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::wait::{Mutex, WaitQueue};
use super::{cpu_count, online_cpus, spawn, spawn_on, yield_now};
use crate::arch;
use crate::ktest::{Rng, Test, ensure};
use crate::sync::IrqSpinLock;
use crate::time;

pub const TESTS: &[Test] = &[
    Test { name: "sched::all_cpus_online", run: all_cpus_online },
    Test { name: "sched::pinned_threads", run: pinned_threads },
    Test { name: "sched::threads_spread_to_all_cpus", run: threads_spread },
    Test { name: "sched::preemption", run: preemption },
    Test { name: "sched::spinlock_stress", run: spinlock_stress },
    Test { name: "sched::mutex_stress", run: mutex_stress },
    Test { name: "sched::sleep_wakeups", run: sleep_wakeups },
    Test { name: "sched::wait_queue_handoff", run: wait_queue_handoff },
    Test { name: "sched::spawn_join_churn", run: spawn_join_churn },
    Test { name: "sched::policy_tables", run: policy_tables },
    Test { name: "sched::cpu_time_measured", run: cpu_time_measured },
    Test { name: "sched::nice_shares_cpu", run: nice_shares_cpu },
    Test { name: "sched::realtime_runs_first", run: realtime_runs_first },
    Test { name: "time::sleep_below_tick", run: sleep_below_tick },
];

fn policy_tables() -> Result<(), &'static str> {
    super::policy::self_check()
}

/// Spin on CPU `cpu` until `stop`, as a kernel thread.
fn spinner(cpu: u32, stop: &Arc<AtomicBool>) -> Arc<super::Thread> {
    let stop = stop.clone();
    spawn_on("spinner", Some(cpu), move || {
        while !stop.load(Ordering::Relaxed) {
            core::hint::spin_loop();
        }
    })
}

/// The last CPU (the tests run on CPU 0; keep the others for spinners).
fn far_cpu(back: usize) -> u32 {
    (cpu_count().saturating_sub(1 + back)).max(1) as u32
}

fn cpu_ns(t: &super::Thread) -> u64 {
    let (u, s) = t.cpu_ns();
    u + s
}

fn cpu_time_measured() -> Result<(), &'static str> {
    // A thread that sleeps 30 ms and then spins 20 ms: its CPU time is the
    // spinning only, measured, not counted in whole ticks.
    let t = spawn_on("timed", Some(far_cpu(0)), || {
        time::sleep_ns(30_000_000);
        let until = time::monotonic_ns() + 20_000_000;
        while time::monotonic_ns() < until {
            core::hint::spin_loop();
        }
    });
    t.join();
    let ns = cpu_ns(&t);
    ensure(ns >= 19_000_000, "spinning 20 ms counted less than 19 ms of CPU time")?;
    ensure(ns <= 26_000_000, "sleeping was counted as CPU time")
}

fn nice_shares_cpu() -> Result<(), &'static str> {
    // Two spinners on one CPU at nice 0 and nice 5: weights 1024 and 335,
    // so about 3 to 1.
    let stop = Arc::new(AtomicBool::new(false));
    let cpu = far_cpu(1);
    let a = spinner(cpu, &stop);
    let b = spinner(cpu, &stop);
    super::set_params(&b, super::policy::SCHED_OTHER, 0, 5, false);
    time::sleep_ns(400_000_000);
    stop.store(true, Ordering::Relaxed);
    a.join();
    b.join();
    let (ta, tb) = (cpu_ns(&a), cpu_ns(&b).max(1));
    let ratio_x10 = ta * 10 / tb;
    ensure(ratio_x10 >= 20, "nice 5 got more than half of nice 0's CPU time")?;
    ensure(ratio_x10 <= 50, "nice 5 got less than a fifth of nice 0's CPU time")
}

fn realtime_runs_first() -> Result<(), &'static str> {
    // A SCHED_FIFO thread spinning for 50 ms on a CPU leaves nothing for a
    // normal thread there.
    let stop = Arc::new(AtomicBool::new(false));
    let cpu = far_cpu(0);
    let normal = spinner(cpu, &stop);
    time::sleep_ns(20_000_000);
    let before = cpu_ns(&normal);
    let rt = spawn_on("fifo", Some(cpu), || {
        let until = time::monotonic_ns() + 50_000_000;
        while time::monotonic_ns() < until {
            core::hint::spin_loop();
        }
    });
    super::set_params(&rt, super::policy::SCHED_FIFO, 10, 0, false);
    rt.join();
    let during = cpu_ns(&normal) - before;
    stop.store(true, Ordering::Relaxed);
    normal.join();
    // Until the boost reached it the FIFO thread was a normal one: allow
    // a few slices.
    ensure(during < 25_000_000, "a normal thread ran while a real-time thread wanted the CPU")
}

fn sleep_below_tick() -> Result<(), &'static str> {
    // The timer is set for the deadline itself: 300 us takes well under a
    // 1 ms tick (the best of five, for a busy host).
    let best = (0..5)
        .map(|_| {
            let t0 = time::monotonic_ns();
            time::sleep_ns(300_000);
            time::monotonic_ns() - t0
        })
        .min()
        .unwrap_or(u64::MAX);
    ensure(best >= 300_000, "slept too short")?;
    ensure(best < 900_000, "a 300 us sleep took most of a tick")
}

fn all_cpus_online() -> Result<(), &'static str> {
    ensure(cpu_count() > 1, "only one CPU found (the harness runs -smp 4)")?;
    ensure(online_cpus() == cpu_count(), "not every CPU came online")
}

fn pinned_threads() -> Result<(), &'static str> {
    let seen: Arc<Vec<AtomicU64>> = Arc::new((0..cpu_count()).map(|_| AtomicU64::new(u64::MAX)).collect());
    let ts: Vec<_> = (0..cpu_count() as u32)
        .map(|c| {
            let seen = seen.clone();
            spawn_on("pinned", Some(c), move || seen[c as usize].store(u64::from(arch::cpu_id()), Ordering::SeqCst))
        })
        .collect();
    for t in ts {
        t.join();
    }
    ensure(seen.iter().enumerate().all(|(i, s)| s.load(Ordering::SeqCst) == i as u64), "a pinned thread ran elsewhere")
}

fn threads_spread() -> Result<(), &'static str> {
    let mask = Arc::new(AtomicU64::new(0));
    let ts: Vec<_> = (0..cpu_count() * 4)
        .map(|_| {
            let mask = mask.clone();
            spawn("spinner", move || {
                let end = time::monotonic_ns() + 20_000_000;
                while time::monotonic_ns() < end {
                    mask.fetch_or(1 << arch::cpu_id(), Ordering::Relaxed);
                    core::hint::spin_loop();
                }
            })
        })
        .collect();
    for t in ts {
        t.join();
    }
    let all = (1u64 << cpu_count()) - 1;
    ensure(mask.load(Ordering::Relaxed) == all, "threads did not run on every CPU")
}

fn preemption() -> Result<(), &'static str> {
    // A thread that never yields, pinned to our CPU: we only get the CPU back
    // (and wake from sleep) if the timer preempts it.
    let stop = Arc::new(AtomicBool::new(false));
    let spins = Arc::new(AtomicU64::new(0));
    let me = arch::cpu_id();
    let t = {
        let (stop, spins) = (stop.clone(), spins.clone());
        spawn_on("hog", Some(me), move || {
            while !stop.load(Ordering::Relaxed) {
                spins.fetch_add(1, Ordering::Relaxed);
            }
        })
    };
    time::sleep_ns(50_000_000);
    stop.store(true, Ordering::Relaxed);
    t.join();
    ensure(spins.load(Ordering::Relaxed) > 0, "the hog thread never ran")
}

fn spinlock_stress() -> Result<(), &'static str> {
    const ITERS: u64 = 50_000;
    let lock = Arc::new(IrqSpinLock::new((0u64, 0u64)));
    let n = cpu_count() * 2;
    let ts: Vec<_> = (0..n)
        .map(|_| {
            let lock = lock.clone();
            spawn("spin-stress", move || {
                for _ in 0..ITERS {
                    let mut g = lock.lock();
                    // A torn update would make the two halves disagree.
                    g.0 += 1;
                    core::hint::spin_loop();
                    g.1 += 1;
                }
            })
        })
        .collect();
    for t in ts {
        t.join();
    }
    let g = lock.lock();
    ensure(g.0 == n as u64 * ITERS && g.1 == g.0, "spinlock lost or tore updates")
}

fn mutex_stress() -> Result<(), &'static str> {
    const ITERS: u64 = 5_000;
    let m = Arc::new(Mutex::new(Vec::<u64>::new()));
    let n = cpu_count() * 3;
    let ts: Vec<_> = (0..n as u64)
        .map(|id| {
            let m = m.clone();
            spawn("mutex-stress", move || {
                for i in 0..ITERS {
                    let mut v = m.lock();
                    v.push(id * ITERS + i);
                    if i % 64 == 0 {
                        yield_now(); // Hold the mutex across a reschedule.
                    }
                }
            })
        })
        .collect();
    for t in ts {
        t.join();
    }
    let mut v = core::mem::take(&mut *m.lock());
    v.sort_unstable();
    ensure(v.len() as u64 == n as u64 * ITERS, "mutex lost updates")?;
    ensure(v.iter().enumerate().all(|(i, &x)| x == i as u64), "mutex duplicated or corrupted updates")
}

fn sleep_wakeups() -> Result<(), &'static str> {
    let late = Arc::new(AtomicU64::new(0));
    let early = Arc::new(AtomicBool::new(false));
    let mut rng = Rng::new(42);
    let ts: Vec<_> = (0..50)
        .map(|_| {
            let ms = 1 + rng.next() % 20;
            let (late, early) = (late.clone(), early.clone());
            spawn("sleeper", move || {
                let start = time::monotonic_ns();
                time::sleep_ns(ms * 1_000_000);
                let took = time::monotonic_ns() - start;
                if took < ms * 1_000_000 {
                    early.store(true, Ordering::Relaxed);
                }
                late.fetch_max(took - ms * 1_000_000.min(took), Ordering::Relaxed);
            })
        })
        .collect();
    for t in ts {
        t.join();
    }
    ensure(!early.load(Ordering::Relaxed), "a sleeper woke early")?;
    ensure(late.load(Ordering::Relaxed) < 10_000_000, "a sleeper woke more than 10 ms late")
}

fn wait_queue_handoff() -> Result<(), &'static str> {
    // Ping-pong a token between two threads on different CPUs.
    const ROUNDS: u64 = 2_000;
    let state = Arc::new((AtomicU64::new(0), WaitQueue::new()));
    let other = cpu_count().min(2) as u32 - 1;
    let t = {
        let state = state.clone();
        spawn_on("pong", Some(other), move || {
            for r in 0..ROUNDS {
                state.1.wait_until(|| state.0.load(Ordering::Acquire) == 2 * r + 1);
                state.0.store(2 * r + 2, Ordering::Release);
                state.1.wake_all();
            }
        })
    };
    for r in 0..ROUNDS {
        state.0.store(2 * r + 1, Ordering::Release);
        state.1.wake_all();
        state.1.wait_until(|| state.0.load(Ordering::Acquire) == 2 * r + 2);
    }
    t.join();
    ensure(state.0.load(Ordering::Relaxed) == 2 * ROUNDS, "handoff lost a round")
}

fn spawn_join_churn() -> Result<(), &'static str> {
    let count = Arc::new(AtomicU64::new(0));
    for _ in 0..20 {
        let ts: Vec<_> = (0..50)
            .map(|_| {
                let count = count.clone();
                spawn("churn", move || {
                    count.fetch_add(1, Ordering::Relaxed);
                })
            })
            .collect();
        for t in ts {
            t.join();
        }
    }
    ensure(count.load(Ordering::Relaxed) == 1000, "not every thread ran exactly once")
}
