// SPDX-License-Identifier: MIT OR Apache-2.0

//! Threads and the scheduler.
//!
//! Every CPU has a run queue (ADR 0045): real-time threads first, by
//! priority, then normal threads by virtual run time, their run time
//! weighted by nice value, so each gets a share of the CPU that its weight
//! says. The timer tick asks for a reschedule when a slice is used up, and
//! the switch happens on the way out of the interrupt. New threads go to
//! the least-loaded CPU; idle CPUs steal work from busy ones.
//!
//! CPU time is measured with the clock at every entry to and exit from
//! the kernel and at every switch, not sampled by the tick.
//!
//! Locking protocol (see docs/adr/0008-scheduler.md):
//! - A thread's state changes under its `sched_lock`.
//! - `on_cpu` is true from the moment a CPU picks a thread until that CPU
//!   has finished switching away from it; nobody else may resume it before
//!   then, so a CPU that picks such a thread waits for the flag to clear.
//! - Blocking happens with interrupts masked: mark the thread blocked,
//!   register it where a waker will find it, then call [`schedule`].

pub mod policy;
pub mod tests;
mod thread;
pub mod wait;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use slate_sync::Once;
pub use thread::{ALTSTACK_DISABLED, Fault, State, Thread, Tid, UserEntry, alloc_id, next_id, rewind_ids};

use crate::arch::{self, cpu::InterruptGuard};
use crate::sync::IrqSpinLock;
use crate::time;

use policy::Class;

/// Timer ticks a normal thread runs before it is preempted (10 ms at 1000
/// Hz).
const TIME_SLICE_TICKS: u32 = 10;
/// A woken thread is placed at most this much virtual run time before the
/// queue's minimum: it was not competing while it slept, but must not
/// make up for all of that time at once.
const WAKE_CREDIT_NS: u64 = 5_000_000;

/// A CPU's runnable threads in the order they run: real-time threads by
/// priority (first in, first out within one), then normal threads by
/// virtual run time. Keys are (class, order, sequence).
#[derive(Debug)]
struct RunQueue {
    tree: BTreeMap<(u8, u64, u64), Arc<Thread>>,
    /// Sequence numbers: counting down for threads put back at the head of
    /// their priority, up for the tail.
    head: u64,
    tail: u64,
}

impl RunQueue {
    const fn new() -> RunQueue {
        RunQueue { tree: BTreeMap::new(), head: 1 << 62, tail: 1 << 62 }
    }

    fn insert(&mut self, t: Arc<Thread>, at_head: bool) {
        let key = match t.class() {
            Class::RealTime { priority, .. } => {
                let seq = if at_head {
                    self.head -= 1;
                    self.head
                } else {
                    self.tail += 1;
                    self.tail
                };
                (0, u64::from(u8::MAX - priority), seq)
            }
            Class::Fair { .. } => {
                self.tail += 1;
                (1, t.vruntime.load(Ordering::Relaxed), self.tail)
            }
        };
        self.tree.insert(key, t);
    }

    /// Remove and return the first thread `ok` accepts.
    fn take_first(&mut self, ok: impl Fn(&Arc<Thread>) -> bool) -> Option<Arc<Thread>> {
        let key = *self.tree.iter().find(|(_, t)| ok(t))?.0;
        self.tree.remove(&key)
    }

    /// Remove `t`; false if it is not here.
    fn remove(&mut self, t: &Arc<Thread>) -> bool {
        let key = self.tree.iter().find(|(_, x)| Arc::ptr_eq(x, t)).map(|(k, _)| *k);
        key.is_some_and(|k| self.tree.remove(&k).is_some())
    }

    fn len(&self) -> usize {
        self.tree.len()
    }
}

/// Where [`enqueue`] puts a thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Place {
    /// A new thread: at the queue's minimum virtual run time.
    New,
    /// A woken thread: at most [`WAKE_CREDIT_NS`] before the minimum.
    Wake,
    /// A thread that was running: where its run time puts it.
    Tail,
}

/// Per-CPU scheduler state.
#[derive(Debug)]
pub struct CpuSched {
    pub apic_id: u32,
    queue: IrqSpinLock<RunQueue>,
    queued: AtomicUsize,
    /// The smallest virtual run time of this CPU's normal threads (it
    /// only grows): threads moving between CPUs keep their place relative
    /// to it.
    min_vruntime: AtomicU64,
    current: IrqSpinLock<Option<Arc<Thread>>>,
    idle: Once<Arc<Thread>>,
    /// The thread this CPU just switched away from, until the switch is done.
    prev: IrqSpinLock<Option<Arc<Thread>>>,
    need_resched: AtomicBool,
    /// The running thread called sched_yield(2).
    yielding: AtomicBool,
    slice_left: AtomicU32,
    online: AtomicBool,
    /// When this CPU's time was last charged to someone (monotonic ns).
    acct_mark: AtomicU64,
    /// Time spent in user mode, in the kernel, and idle (/proc/stat).
    pub times: CpuTimes,
    /// What runs here, for placing real-time threads (ADR 0184): 0 the
    /// idle thread, 1 a normal thread, a real-time thread's rank (101 to
    /// 199) with its boost.
    running_rank: AtomicU32,
    /// The page-table root this CPU has loaded (0 before the first
    /// switch). Page tables are freed only when no CPU has them loaded
    /// ([`wait_root_unused`]).
    active_root: AtomicU64,
}

/// Where a CPU's time went, in nanoseconds.
#[derive(Debug, Default)]
pub struct CpuTimes {
    pub user: AtomicU64,
    pub system: AtomicU64,
    pub idle: AtomicU64,
}

static CPUS: Once<Vec<CpuSched>> = Once::new();
static STARTED: AtomicBool = AtomicBool::new(false);
static SLEEPERS: IrqSpinLock<BTreeMap<(u64, Tid), Arc<Thread>>> = IrqSpinLock::new(BTreeMap::new());

fn cpus() -> &'static [CpuSched] {
    CPUS.get().expect("scheduler not initialized")
}

/// This CPU's scheduler state. Use it with interrupts masked (or from the
/// idle thread, which never moves): otherwise the thread may migrate and
/// the reference would name another CPU.
fn this_cpu() -> &'static CpuSched {
    &cpus()[arch::cpu_id() as usize]
}

/// The page-table root to run `p`'s threads on (the kernel's for kernel
/// threads and processes without an address space).
fn root_of(p: Option<&crate::proc::Process>) -> u64 {
    match p.map_or(0, |p| p.root()) {
        0 => arch::paging::kernel_root().0,
        r => r,
    }
}

/// Load page-table root `root` on this CPU (exec, process exit).
pub fn switch_root(root: crate::mm::PhysAddr) {
    let _irq = InterruptGuard::new();
    this_cpu().active_root.store(root.0, Ordering::SeqCst);
    arch::paging::switch_root(root);
}

/// Times a teardown had to wait for another CPU to leave the page tables
/// it was about to free (/proc/slate_sched).
static ROOT_WAITS: AtomicU64 = AtomicU64::new(0);

pub fn root_waits() -> u64 {
    ROOT_WAITS.load(Ordering::Relaxed)
}

/// Wait until no CPU has page-table root `root` loaded, before its tables
/// are freed. The caller has already stopped publishing `root` (the
/// process's root points elsewhere), so CPUs still on it are threads of
/// the process on their way out: they switch away at their next
/// schedule. Without this, such a CPU runs on freed page tables (an
/// intermittent panic in `cargo xtask accept`, 2026-10-18).
pub fn wait_root_unused(root: u64) {
    let Some(cpus) = CPUS.get() else { return };
    let me = arch::cpu_id() as usize;
    let mut waited = false;
    for (i, c) in cpus.iter().enumerate() {
        if i == me {
            continue;
        }
        let mut spins = 0u64;
        while c.active_root.load(Ordering::SeqCst) == root {
            waited = true;
            spins += 1;
            if spins == 1 << 28 {
                crate::log_warn!("cpu {i} still on page-table root {root:#x} being freed");
            }
            core::hint::spin_loop();
        }
    }
    if waited {
        ROOT_WAITS.fetch_add(1, Ordering::Relaxed);
    }
}

/// APIC ID of kernel CPU number `cpu`.
pub fn apic_id_of(cpu: usize) -> u32 {
    cpus()[cpu].apic_id
}

/// Number of CPUs known to the scheduler.
pub fn cpu_count() -> usize {
    CPUS.get().map_or(1, |c| c.len())
}

/// Whether kernel CPU `cpu` is online.
pub fn cpu_online(cpu: usize) -> bool {
    CPUS.get().and_then(|c| c.get(cpu)).is_some_and(|c| c.online.load(Ordering::Acquire))
}

/// Number of CPUs that are online.
pub fn online_cpus() -> usize {
    CPUS.get().map_or(1, |c| c.iter().filter(|c| c.online.load(Ordering::Acquire)).count())
}

/// Whether threads exist yet (before this, "blocking" means spinning).
pub fn started() -> bool {
    STARTED.load(Ordering::Acquire)
}

/// The current context may sleep: the scheduler runs and interrupts are
/// enabled (no spinlock held, not in an interrupt handler).
pub fn can_block() -> bool {
    started() && crate::arch::cpu::interrupts_enabled()
}

/// Create the scheduler for CPUs with the given APIC IDs (index = CPU id),
/// and turn the code running now on CPU 0 into its first thread.
pub fn init(apic_ids: &[u32]) {
    CPUS.call_once(|| {
        apic_ids
            .iter()
            .map(|&apic_id| CpuSched {
                apic_id,
                queue: IrqSpinLock::new(RunQueue::new()),
                queued: AtomicUsize::new(0),
                min_vruntime: AtomicU64::new(0),
                current: IrqSpinLock::new(None),
                idle: Once::new(),
                prev: IrqSpinLock::new(None),
                need_resched: AtomicBool::new(false),
                yielding: AtomicBool::new(false),
                slice_left: AtomicU32::new(TIME_SLICE_TICKS),
                online: AtomicBool::new(false),
                acct_mark: AtomicU64::new(0),
                active_root: AtomicU64::new(0),
                times: CpuTimes::default(),
                running_rank: AtomicU32::new(0),
            })
            .collect()
    });
    let cpu = &cpus()[0];
    let boot = Thread::new_current("kmain", Some(0));
    *cpu.current.lock() = Some(boot);
    cpu.idle.call_once(|| Thread::new_idle(0));
    cpu.acct_mark.store(time::monotonic_ns(), Ordering::Relaxed);
    cpu.online.store(true, Ordering::Release);
    STARTED.store(true, Ordering::Release);
}

/// Called on an application processor once it can take interrupts: its
/// current context becomes the CPU's idle thread, which never returns.
pub fn ap_online() -> ! {
    let id = arch::cpu_id();
    let cpu = this_cpu();
    let idle = cpu.idle.call_once(|| Thread::new_current("idle", Some(id)));
    *cpu.current.lock() = Some(idle.clone());
    cpu.acct_mark.store(time::monotonic_ns(), Ordering::Relaxed);
    cpu.online.store(true, Ordering::Release);
    idle_loop()
}

/// The idle thread's body: run whatever is runnable, else halt.
pub(crate) fn idle_loop() -> ! {
    loop {
        let irq = InterruptGuard::new();
        let work = this_cpu().queued.load(Ordering::Relaxed) > 0 || steal_candidate().is_some();
        if work {
            drop(irq);
            schedule();
        } else {
            // `wait_for_interrupt` re-enables interrupts atomically with the
            // halt; forget the guard so it does not re-enable them first.
            core::mem::forget(irq);
            arch::wait_for_interrupt();
        }
    }
}

/// The running thread.
pub fn current() -> Arc<Thread> {
    // Masked, so the thread cannot move to another CPU between finding
    // "this CPU" and reading its current thread.
    let _irq = InterruptGuard::new();
    this_cpu().current.lock().clone().expect("no current thread")
}

/// Start a kernel thread running `f`.
pub fn spawn(name: &str, f: impl FnOnce() + Send + 'static) -> Arc<Thread> {
    spawn_on(name, None, f)
}

/// Start a kernel thread, optionally pinned to one CPU.
pub fn spawn_on(name: &str, pinned: Option<u32>, f: impl FnOnce() + Send + 'static) -> Arc<Thread> {
    start(Thread::new(
        name,
        pinned,
        alloc::boxed::Box::new(move || {
            f();
            None
        }),
        None,
        None,
    ))
}

/// Start a thread of a user process; `f` runs in the kernel and says how
/// the thread enters user mode.
pub fn spawn_user(
    name: &str,
    process: Arc<crate::proc::Process>,
    tid: Tid,
    f: impl FnOnce() -> UserEntry + Send + 'static,
) -> Arc<Thread> {
    let t = Thread::new(name, None, alloc::boxed::Box::new(move || Some(f())), Some(process), Some(tid));
    // A user thread's scheduling parameters come from the thread that
    // made it (fork(2), clone(2)).
    let me = current();
    if me.process.is_some() {
        t.inherit_sched(&me);
    }
    start(t)
}

fn start(t: Arc<Thread>) -> Arc<Thread> {
    let target = match t.pinned {
        Some(c) => c as usize,
        None => least_loaded_cpu_for(&t),
    };
    enqueue(&cpus()[target], t.clone(), Place::New);
    t
}

/// Whether `t` may run on CPU `cpu` (its pinning and affinity).
fn allowed(t: &Thread, cpu: usize) -> bool {
    t.pinned.is_none_or(|p| p as usize == cpu) && (cpu >= 64 || t.affinity.load(Ordering::Relaxed) >> cpu & 1 == 1)
}

/// The online CPU with the shortest queue that `t` may run on; ties go to
/// the current CPU.
fn least_loaded_cpu_for(t: &Thread) -> usize {
    let me = arch::cpu_id() as usize;
    let cs = cpus();
    (0..cs.len())
        .filter(|&i| cs[i].online.load(Ordering::Acquire) && allowed(t, i))
        .min_by_key(|&i| (cs[i].queued.load(Ordering::Relaxed), i != me))
        .unwrap_or(me)
}

/// sched_setaffinity(2): the CPUs `t` may run on. A running thread that
/// may no longer stay where it is moves at its next scheduling point.
pub fn set_affinity(t: &Arc<Thread>, mask: u64) {
    t.affinity.store(mask, Ordering::Relaxed);
    if Arc::ptr_eq(t, &current()) && !allowed(t, arch::cpu_id() as usize) {
        this_cpu().need_resched.store(true, Ordering::Relaxed);
    }
}

/// The CPUs online, one bit each (for affinity masks).
pub fn online_mask() -> u64 {
    let cs = cpus();
    (0..cs.len().min(64)).filter(|&i| cs[i].online.load(Ordering::Acquire)).fold(0, |m, i| m | 1 << i)
}

fn index_of(cpu: &CpuSched) -> usize {
    cpus().iter().position(|c| core::ptr::eq(c, cpu)).unwrap()
}

/// Put `t` on `cpu`'s run queue, its virtual run time moved there from
/// the CPU it last ran on.
fn enqueue(cpu: &'static CpuSched, t: Arc<Thread>, place: Place) {
    // Masked: "is this our CPU?" below must stay true until the IPI decision.
    let _irq = InterruptGuard::new();
    let idx = index_of(cpu);
    let from = t.cpu.swap(idx as u32, Ordering::Relaxed) as usize;
    let min = cpu.min_vruntime.load(Ordering::Relaxed);
    let mut v = t.vruntime.load(Ordering::Relaxed);
    if from != idx {
        v = v.saturating_sub(cpus()[from].min_vruntime.load(Ordering::Relaxed)).saturating_add(min);
    }
    v = match place {
        Place::New => min,
        Place::Wake => v.max(min.saturating_sub(WAKE_CREDIT_NS)),
        Place::Tail => v,
    };
    t.vruntime.store(v, Ordering::Relaxed);
    {
        let mut q = cpu.queue.lock();
        q.insert(t, false);
        cpu.queued.store(q.len(), Ordering::Relaxed);
    }
    if !core::ptr::eq(cpu, this_cpu()) {
        arch::send_reschedule_ipi(cpu.apic_id);
    }
}

/// A thread's class changed (its policy, nice value or boost): move it in
/// its run queue, and let its CPU choose again what runs.
pub fn reprioritize(t: &Arc<Thread>) {
    let _irq = InterruptGuard::new();
    let cpu = &cpus()[t.cpu.load(Ordering::Relaxed) as usize];
    {
        let mut q = cpu.queue.lock();
        if q.remove(t) {
            q.insert(t.clone(), false);
        }
    }
    if core::ptr::eq(cpu, this_cpu()) {
        cpu.need_resched.store(true, Ordering::Relaxed);
    } else {
        arch::send_reschedule_ipi(cpu.apic_id);
    }
}

/// Set a thread's policy, real-time priority and nice value (sched(7)).
/// The caller has checked them and the caller's right to.
pub fn set_params(t: &Arc<Thread>, policy: u8, rt_priority: u8, nice: i8, reset_on_fork: bool) {
    if t.policy.swap(policy, Ordering::Relaxed) != policy {
        t.rt_restart();
    }
    t.rt_priority.store(rt_priority, Ordering::Relaxed);
    t.nice.store(nice.clamp(-20, 19), Ordering::Relaxed);
    t.reset_on_fork.store(reset_on_fork, Ordering::Relaxed);
    reprioritize(t);
}

/// Set the rank `t` borrows from threads waiting on priority-inheritance
/// futexes it owns (0: none).
pub fn set_boost(t: &Arc<Thread>, rank: u32) {
    if t.pi_boost.swap(rank, Ordering::Relaxed) != rank {
        reprioritize(t);
    }
}

/// Make a blocked thread runnable. Returns false if it was not blocked.
pub fn wake(t: &Arc<Thread>) -> bool {
    let _irq = InterruptGuard::new();
    {
        let _g = t.sched_lock.lock();
        if t.state() != State::Blocked {
            return false;
        }
        t.set_state(State::Runnable);
    }
    let last = t.cpu.load(Ordering::Relaxed) as usize;
    let target = match t.pinned {
        Some(c) => c as usize,
        None => {
            let usual = if allowed(t, last) { last } else { least_loaded_cpu_for(t) };
            // A real-time thread goes where it runs at once (ADR 0184).
            match t.class() {
                Class::RealTime { priority, .. } => {
                    rt_target(t, 100 + u32::from(priority), Some(usual)).unwrap_or(usual)
                }
                Class::Fair { .. } => usual,
            }
        }
    };
    let cpu = &cpus()[target];
    enqueue(cpu, t.clone(), Place::Wake);
    // Run woken threads promptly: they are usually waiting on I/O or time
    // and run briefly (remote CPUs get the IPI from `enqueue`).
    if core::ptr::eq(cpu, this_cpu()) {
        cpu.need_resched.store(true, Ordering::Relaxed);
    }
    true
}

/// What a CPU's `running_rank` says for `t` running there.
fn running_rank_of(t: &Thread) -> u32 {
    match t.class() {
        Class::RealTime { priority, .. } => 100 + u32::from(priority),
        Class::Fair { .. } => 1,
    }
}

/// Where a real-time thread of rank `rank` runs at once: `prefer` if what
/// runs there ranks lower, else the online CPU it may use whose running
/// thread ranks lowest (idle first, then normal threads, then lower
/// real-time ones; ties to the shorter queue). None if every CPU runs
/// something at least as high. Linux's real-time scheduler is said to
/// push and pull its threads between CPUs the same way (sched(7)
/// describes only the per-CPU rules; this placement is Slate's own).
fn rt_target(t: &Thread, rank: u32, prefer: Option<usize>) -> Option<usize> {
    let cs = cpus();
    let usable = |i: usize| cs[i].online.load(Ordering::Acquire) && allowed(t, i);
    let below = |i: usize| cs[i].running_rank.load(Ordering::Relaxed) < rank;
    if let Some(p) = prefer
        && usable(p)
        && below(p)
    {
        return Some(p);
    }
    (0..cs.len())
        .filter(|&i| usable(i) && below(i))
        .min_by_key(|&i| (cs[i].running_rank.load(Ordering::Relaxed), cs[i].queued.load(Ordering::Relaxed)))
}

/// A thread in another CPU's queue that this CPU may take.
fn steal_candidate() -> Option<usize> {
    let me = arch::cpu_id() as usize;
    let cs = cpus();
    (0..cs.len())
        .filter(|&i| i != me)
        .max_by_key(|&i| cs[i].queued.load(Ordering::Relaxed))
        .filter(|&i| cs[i].queued.load(Ordering::Relaxed) > 0)
}

fn steal() -> Option<Arc<Thread>> {
    let victim = &cpus()[steal_candidate()?];
    let me = arch::cpu_id() as usize;
    let t = {
        let mut q = victim.queue.lock();
        let t = q.take_first(|t| t.pinned.is_none() && allowed(t, me) && !t.on_cpu.load(Ordering::Acquire));
        victim.queued.store(q.len(), Ordering::Relaxed);
        t
    }?;
    // Its virtual run time moves from the victim's queue to ours.
    let v = t
        .vruntime
        .load(Ordering::Relaxed)
        .saturating_sub(victim.min_vruntime.load(Ordering::Relaxed))
        .saturating_add(this_cpu().min_vruntime.load(Ordering::Relaxed));
    t.vruntime.store(v, Ordering::Relaxed);
    t.cpu.store(me as u32, Ordering::Relaxed);
    Some(t)
}

/// The next thread to run here: the first in the queue (other than
/// `skip`, if there is another), else one stolen from another CPU.
/// Threads whose cgroup used up its CPU quota are parked on the way.
fn pick_next(cpu: &'static CpuSched, skip: Option<&Arc<Thread>>) -> Option<Arc<Thread>> {
    loop {
        let local = {
            let mut q = cpu.queue.lock();
            let t = match skip {
                Some(s) => q.take_first(|t| !Arc::ptr_eq(t, s)).or_else(|| q.take_first(|_| true)),
                None => q.take_first(|_| true),
            };
            cpu.queued.store(q.len(), Ordering::Relaxed);
            t
        };
        let t = local.or_else(steal)?;
        if let Some(p) = &t.process
            && crate::fs::cgroup::park_if_throttled(&p.cgroup(), &t)
        {
            continue;
        }
        if let Class::Fair { .. } = t.class() {
            cpu.min_vruntime.fetch_max(t.vruntime.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        return Some(t);
    }
}

/// Put back a thread a cgroup's CPU quota held (its new period began).
pub fn unpark(t: Arc<Thread>) {
    let target = match t.pinned {
        Some(c) => c as usize,
        None if allowed(&t, t.cpu.load(Ordering::Relaxed) as usize) => t.cpu.load(Ordering::Relaxed) as usize,
        None => least_loaded_cpu_for(&t),
    };
    enqueue(&cpus()[target], t, Place::Tail);
}

/// Bring `t`'s virtual run time and its cgroup's CPU usage up to date with
/// the CPU time it used since the last call.
fn update_curr(cpu: &CpuSched, t: &Thread) {
    let (u, s) = t.cpu_ns();
    let du = u.saturating_sub(t.charged_user.swap(u, Ordering::Relaxed));
    let ds = s.saturating_sub(t.charged_system.swap(s, Ordering::Relaxed));
    if du + ds == 0 {
        return;
    }
    if let Class::Fair { weight } = t.class() {
        t.vruntime.fetch_add((du + ds) * policy::NICE_0_WEIGHT / weight, Ordering::Relaxed);
    }
    if let Some(p) = &t.process
        && crate::fs::cgroup::charge_cpu(&p.cgroup(), du, ds)
    {
        cpu.need_resched.store(true, Ordering::Relaxed);
    }
}

/// Charge the time since this CPU's last accounting point to whatever ran:
/// as user time if it was in user mode, else as kernel time.
fn account(cpu: &CpuSched, user: bool) {
    let now = time::monotonic_ns();
    let ns = now.saturating_sub(cpu.acct_mark.swap(now, Ordering::Relaxed));
    let cur = cpu.current.lock();
    let Some(t) = cur.as_ref() else { return };
    if cpu.idle.get().is_some_and(|i| Arc::ptr_eq(i, t)) {
        cpu.times.idle.fetch_add(ns, Ordering::Relaxed);
        return;
    }
    let bucket = if user { &cpu.times.user } else { &cpu.times.system };
    bucket.fetch_add(ns, Ordering::Relaxed);
    t.charge(user, ns);
}

/// Entering the kernel from user mode (a system call, an interrupt, an
/// exception): the time since the last accounting point was user time.
/// Interrupts are masked.
pub fn enter_from_user() {
    if started() {
        account(this_cpu(), true);
    }
}

/// Returning to user mode: the time since the last accounting point was
/// kernel time. Interrupts are masked.
pub fn return_to_user() {
    if started() {
        account(this_cpu(), false);
    }
}

/// Bring the current thread's CPU time up to now (for CPU-time clocks).
pub fn update_current_times() {
    if started() {
        let _irq = InterruptGuard::new();
        account(this_cpu(), false);
    }
}

/// Give up the CPU: switch to the next runnable thread, if any. The current
/// thread is requeued unless it is blocked or dead.
pub fn schedule() {
    let _irq = InterruptGuard::new();
    let cpu = this_cpu();
    cpu.need_resched.store(false, Ordering::Relaxed);
    let yielding = cpu.yielding.swap(false, Ordering::Relaxed);
    let expired = cpu.slice_left.load(Ordering::Relaxed) <= 1;
    let prev = cpu.current.lock().clone().expect("no current thread");
    let idle = cpu.idle.get().expect("no idle thread").clone();
    let prev_idle = Arc::ptr_eq(&prev, &idle);
    account(cpu, false);
    if !prev_idle {
        update_curr(cpu, &prev);
    }

    let still_runnable = {
        let _g = prev.sched_lock.lock();
        prev.state() == State::Running
    };
    let here = arch::cpu_id() as usize;
    if still_runnable && !prev_idle {
        {
            let _g = prev.sched_lock.lock();
            prev.set_state(State::Runnable);
        }
        if allowed(&prev, here) {
            // A real-time thread that was preempted keeps its place at the
            // head of its priority; one that yields or used up its slice
            // goes to the tail (sched(7)). Others compete by run time.
            let head = matches!(prev.class(), Class::RealTime { .. }) && !yielding && !expired;
            let mut q = cpu.queue.lock();
            q.insert(prev.clone(), head);
            cpu.queued.store(q.len(), Ordering::Relaxed);
        } else {
            // Its affinity no longer includes this CPU: it moves.
            enqueue(&cpus()[least_loaded_cpu_for(&prev)], prev.clone(), Place::Tail);
        }
    }
    if !still_runnable && !prev_idle {
        prev.rt_restart();
    }
    let next = pick_next(cpu, if yielding { Some(&prev) } else { None }).unwrap_or_else(|| idle.clone());
    let next_rank = if Arc::ptr_eq(&next, &idle) { 0 } else { running_rank_of(&next) };
    cpu.running_rank.store(next_rank, Ordering::Relaxed);
    // A real-time thread something higher preempted moves to a CPU where
    // it runs at once, if there is one (ADR 0184).
    if still_runnable
        && !prev_idle
        && !yielding
        && !Arc::ptr_eq(&next, &prev)
        && prev.pinned.is_none()
        && let Class::RealTime { priority, .. } = prev.class()
        && let Some(other) = rt_target(&prev, 100 + u32::from(priority), None)
        && other != here
    {
        let moved = {
            let mut q = cpu.queue.lock();
            let moved = q.remove(&prev);
            cpu.queued.store(q.len(), Ordering::Relaxed);
            moved
        };
        if moved {
            enqueue(&cpus()[other], prev.clone(), Place::Tail);
        }
    }
    let slice = match next.class() {
        Class::RealTime { rr: true, .. } => policy::RR_SLICE_TICKS,
        Class::RealTime { rr: false, .. } => u32::MAX,
        Class::Fair { .. } => TIME_SLICE_TICKS,
    };
    cpu.slice_left.store(slice, Ordering::Relaxed);
    if Arc::ptr_eq(&next, &prev) {
        prev.set_state(State::Running);
        return;
    }

    // A thread that was just woken may still be switching out on another CPU.
    while next.on_cpu.swap(true, Ordering::Acquire) {
        core::hint::spin_loop();
    }
    next.set_state(State::Running);
    next.cpu.store(arch::cpu_id(), Ordering::Relaxed);
    arch::set_kernel_stack(next.kernel_stack_top());
    prev.arch.switch_out();
    prev.switched_out.fetch_add(1, Ordering::Relaxed);
    // Leaving the CPU while still able to run is preemption (or a yield);
    // blocking is voluntary (getrusage(2)).
    if !prev_idle {
        prev.count(if still_runnable { |c| &c.nivcsw } else { |c| &c.nvcsw }, 1);
    }
    next.arch.switch_in();
    // Announce the root before loading it, then check it is still the
    // process's: a teardown publishes the new root first and then waits
    // for CPUs still announcing the old one (wait_root_unused), so one of
    // the two always sees the other.
    let root = loop {
        let r = root_of(next.process.as_deref());
        cpu.active_root.store(r, Ordering::SeqCst);
        if root_of(next.process.as_deref()) == r {
            break r;
        }
    };
    arch::paging::switch_root(crate::mm::PhysAddr(root));
    *cpu.current.lock() = Some(next.clone());
    *cpu.prev.lock() = Some(prev.clone());

    let old_rsp = prev.saved_rsp_ptr();
    let new_rsp = next.saved_rsp();
    drop(next);
    drop(prev);
    drop(idle);
    // SAFETY: `new_rsp` was saved by a previous switch away from `next`, or
    // prepared for it by `Thread::new`; `on_cpu` guarantees no other CPU is
    // running on that stack. `old_rsp` points into `prev`, which `cpu.prev`
    // keeps alive until `finish_switch` runs on the other side.
    unsafe { arch::context::switch_context(old_rsp, new_rsp) };
    finish_switch();
}

/// Completes a switch on the incoming side: the previous thread is now
/// fully off this CPU.
fn finish_switch() {
    let prev = this_cpu().prev.lock().take();
    if let Some(p) = prev {
        p.on_cpu.store(false, Ordering::Release);
        // If `p` is dead and this was the last reference, its stack is freed here.
    }
}

/// Entry point of every new thread, reached through the arch trampoline.
#[unsafe(no_mangle)]
extern "C" fn slate_thread_entry(arg: u64) -> ! {
    finish_switch();
    // SAFETY: `arg` is the address of the thread's `Arc<Thread>` inner
    // value, kept alive by the reference in `current`.
    let t = unsafe { &*(arg as *const Thread) };
    let f = t.take_entry().expect("thread started twice");
    // SAFETY: Enabling interrupts is the normal state for a running thread.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
    // The entry is consumed (and freed) before the jump to user mode.
    match f() {
        Some(UserEntry::Return(frame)) => crate::arch::syscall::return_to_user(&frame),
        Some(UserEntry::Start { rip, rsp }) => crate::arch::syscall::enter_user(rip, rsp),
        None => exit(),
    }
}

/// Yield the CPU to another runnable thread (sched_yield(2)).
pub fn yield_now() {
    {
        let _irq = InterruptGuard::new();
        this_cpu().yielding.store(true, Ordering::Relaxed);
    }
    schedule();
}

/// End the current thread.
pub fn exit() -> ! {
    let _irq = InterruptGuard::new();
    let t = current();
    {
        let _g = t.sched_lock.lock();
        t.set_state(State::Dead);
    }
    t.exited.wake_all();
    drop(t);
    schedule();
    unreachable!("a dead thread was resumed");
}

/// Block the current thread until `deadline_ns` on the monotonic clock.
pub fn sleep_until(deadline_ns: u64) {
    if !started() {
        while time::monotonic_ns() < deadline_ns {
            arch::wait_for_interrupt();
        }
        return;
    }
    while time::monotonic_ns() < deadline_ns {
        let _irq = InterruptGuard::new();
        let t = current();
        t.block_prepare();
        add_sleeper(deadline_ns, t);
        schedule();
    }
}

pub(crate) fn add_sleeper(deadline_ns: u64, t: Arc<Thread>) {
    SLEEPERS.lock().insert((deadline_ns, t.tid), t);
    arch::timer_deadline(deadline_ns);
}

/// The earliest deadline of a sleeper or a kernel timer (u64::MAX: none).
pub fn earliest_deadline() -> u64 {
    let s = SLEEPERS.lock().first_key_value().map_or(u64::MAX, |(k, _)| k.0);
    s.min(time::earliest_timer())
}

/// Wake the sleepers and run the kernel timers due by `now` (from the
/// timer interrupt).
pub fn run_due(now: u64) {
    if !started() {
        return;
    }
    let due: Vec<Arc<Thread>> = {
        let mut s = SLEEPERS.lock();
        let later = s.split_off(&(now + 1, 0));
        core::mem::replace(&mut *s, later).into_values().collect()
    };
    for t in due {
        wake(&t);
    }
    time::run_timers();
}

pub(crate) fn remove_sleeper(deadline_ns: u64, t: &Arc<Thread>) {
    SLEEPERS.lock().remove(&(deadline_ns, t.tid));
}

/// Sleep until `deadline_ns`, or until a signal is pending. Returns true if
/// interrupted.
pub fn sleep_until_interruptible(deadline_ns: u64) -> bool {
    while time::monotonic_ns() < deadline_ns {
        if crate::proc::signal::pending_for_current() {
            return true;
        }
        let _irq = InterruptGuard::new();
        let t = current();
        t.block_prepare();
        add_sleeper(deadline_ns, t.clone());
        schedule();
        SLEEPERS.lock().remove(&(deadline_ns, t.tid));
    }
    false
}

/// Timer tick, on every CPU: charge the running thread's time, account
/// the time slice and, on CPU 0, wake sleepers whose deadline passed and
/// update the load average.
pub fn tick() {
    if !started() {
        return;
    }
    if arch::cpu_id() == 0 {
        let now = time::monotonic_ns();
        run_due(now);
        update_load_average(now);
    }
    let cpu = this_cpu();
    // An interrupt from user mode charged the user time on entry: what is
    // left since then is the kernel's.
    account(cpu, false);
    let cur = cpu.current.lock().clone();
    if let Some(t) = cur.filter(|t| !cpu.idle.get().is_some_and(|i| Arc::ptr_eq(i, t))) {
        update_curr(cpu, &t);
        if let Some(p) = &t.process {
            crate::proc::check_cpu_limit(p);
            if matches!(t.policy.load(Ordering::Relaxed), policy::SCHED_FIFO | policy::SCHED_RR) {
                crate::proc::rlimit::check_rt_limit(p, t.rt_ran_ns(), &t.rt_signalled);
            }
        }
    }
    if cpu.slice_left.fetch_sub(1, Ordering::Relaxed) <= 1 {
        cpu.need_resched.store(true, Ordering::Relaxed);
    }
}

// The load average (proc(5) /proc/loadavg): every 5 seconds, the number of
// runnable threads is folded into three exponentially decaying averages
// over 1, 5 and 15 minutes, in fixed point with 11 fraction bits. The
// decay factors are e^(-5/60), e^(-5/300) and e^(-5/900), times 2048.
const LOAD_SHIFT: u32 = 11;
const LOAD_ONE: u64 = 1 << LOAD_SHIFT;
const LOAD_DECAY: [u64; 3] = [1884, 2014, 2037];
const LOAD_INTERVAL_NS: u64 = 5_000_000_000;
static LOADS: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
static LOAD_NEXT: AtomicU64 = AtomicU64::new(LOAD_INTERVAL_NS);

fn update_load_average(now: u64) {
    let next = LOAD_NEXT.load(Ordering::Relaxed);
    if now < next {
        return;
    }
    LOAD_NEXT
        .store(next.max(now) + LOAD_INTERVAL_NS - (now - next.min(now)).min(LOAD_INTERVAL_NS - 1), Ordering::Relaxed);
    let n = runnable_threads() as u64 * LOAD_ONE;
    for (l, e) in LOADS.iter().zip(LOAD_DECAY) {
        let old = l.load(Ordering::Relaxed);
        l.store((old * e + n * (LOAD_ONE - e) + LOAD_ONE / 2) >> LOAD_SHIFT, Ordering::Relaxed);
    }
}

/// The 1, 5 and 15 minute load averages, in fixed point with
/// [`LOAD_FRACTION_BITS`] fraction bits.
pub fn load_average() -> [u64; 3] {
    LOADS.each_ref().map(|l| l.load(Ordering::Relaxed))
}

/// Fraction bits of [`load_average`]'s numbers.
pub const LOAD_FRACTION_BITS: u32 = LOAD_SHIFT;

/// Threads running or waiting to run, on all CPUs.
pub fn runnable_threads() -> usize {
    let Some(cs) = CPUS.get() else { return 0 };
    cs.iter()
        .map(|c| {
            let running = c.current.lock().as_ref().is_some_and(|t| !c.idle.get().is_some_and(|i| Arc::ptr_eq(i, t)));
            c.queued.load(Ordering::Relaxed) + usize::from(running)
        })
        .sum()
}

/// The scheduler's view, for debugging (/proc/slate_sched): each CPU's
/// current thread and run queue, then every user thread's state.
pub fn dump(s: &mut alloc::string::String) {
    use core::fmt::Write;
    for (i, c) in cpus().iter().enumerate() {
        let cur = c.current.lock().as_ref().map(|t| t.tid);
        let queue: Vec<Tid> = c.queue.lock().tree.values().map(|t| t.tid).collect();
        let _ = writeln!(
            s,
            "cpu{i}: current {cur:?} queued {} {queue:?} need_resched {}",
            c.queued.load(Ordering::Relaxed),
            c.need_resched.load(Ordering::Relaxed)
        );
    }
    let _ = writeln!(s, "page-table teardowns that waited for a CPU: {}", root_waits());
    let _ = writeln!(s, "heap objects by size: {:?}", crate::mm::heap::class_stats());
    let _ = writeln!(s, "cached dentries: {:?}", crate::fs::vfs::root().census(6));
    let _ = writeln!(
        s,
        "objects alive: {} threads, {} processes ({} in the table), {} dentries, {} cached misses",
        thread::LIVE.load(Ordering::Relaxed),
        crate::proc::LIVE.load(Ordering::Relaxed),
        crate::proc::all().len(),
        crate::fs::vfs::LIVE_DENTRIES.load(Ordering::Relaxed),
        crate::fs::vfs::dcache::MISSES.load(Ordering::Relaxed)
    );
    for p in crate::proc::all() {
        for t in p.threads() {
            let _ = writeln!(
                s,
                "pid {} tid {} {:?} on_cpu {} cpu {}{}{}",
                p.pid,
                t.tid,
                t.state(),
                t.on_cpu.load(Ordering::Relaxed),
                t.cpu.load(Ordering::Relaxed),
                if p.abi() == crate::proc::Abi::Native { " native" } else { "" },
                match t.syscall.load(Ordering::Relaxed) {
                    0 => alloc::string::String::new(),
                    n => alloc::format!(
                        " in {}({:#x})",
                        if p.abi() == crate::proc::Abi::Native {
                            slate_abi::nr::name(n - 1)
                        } else {
                            crate::abi::linux::nr::name(n - 1)
                        }
                        .unwrap_or("?"),
                        t.syscall_arg.load(Ordering::Relaxed)
                    ),
                }
            );
        }
    }
}

/// Where CPU `cpu`'s time went (/proc/stat).
pub fn cpu_times(cpu: usize) -> &'static CpuTimes {
    &cpus()[cpu].times
}

/// Ask this CPU to reschedule at the next opportunity (from an IPI).
pub fn request_resched() {
    if started() {
        this_cpu().need_resched.store(true, Ordering::Relaxed);
    }
}

/// Called on the way out of an interrupt whose interrupted context had
/// interrupts enabled (so it held no interrupt-masking lock).
pub fn preempt_point() {
    if started() && this_cpu().need_resched.load(Ordering::Relaxed) {
        schedule();
    }
}
