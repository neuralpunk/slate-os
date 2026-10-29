// SPDX-License-Identifier: MIT OR Apache-2.0

//! The thread object.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI8, AtomicU8, AtomicU32, AtomicU64, Ordering};

use super::wait::WaitQueue;
use crate::arch;
use crate::mm::vmap::KernelStack;
use crate::sync::IrqSpinLock;

/// `SS_DISABLE` (sigaltstack(2)): the flags of a thread without an
/// alternate signal stack.
pub const ALTSTACK_DISABLED: u32 = 2;

pub type Tid = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    Runnable = 0,
    Running = 1,
    Blocked = 2,
    Dead = 3,
}

/// What a new thread runs. A user thread's entry returns how it enters
/// user mode; the jump happens after the entry (and its box) is gone,
/// because the jump never returns and would leave them allocated.
pub(super) type Entry = Box<dyn FnOnce() -> Option<UserEntry> + Send>;

/// How a new user thread enters user mode.
#[derive(Debug)]
pub enum UserEntry {
    /// Return from a system call with these registers (fork, clone).
    Return(crate::arch::trap::TrapFrame),
    /// Start a program at `rip` with stack `rsp` (the first process).
    Start { rip: u64, rsp: u64 },
}

/// A signal the kernel raised for a thread (a fault, a seccomp trap) and
/// what its siginfo says: si_code, the first union word (si_addr), the
/// second (for SIGSYS: si_syscall and si_arch) and si_errno.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    pub sig: u32,
    pub code: i32,
    pub addr: u64,
    pub extra: u64,
    pub errno: i32,
}

/// A kernel thread (and, from M5, the kernel side of a user thread).
pub struct Thread {
    pub tid: Tid,
    pub name: String,
    pub(super) pinned: Option<u32>,
    /// The CPUs it may run on (sched_setaffinity(2)), one bit each.
    pub affinity: AtomicU64,
    state: AtomicU8,
    pub(super) sched_lock: IrqSpinLock<()>,
    /// Set while a CPU is running on (or switching away from) this thread.
    pub(super) on_cpu: AtomicBool,
    /// CPU whose queue the thread is on, or where it last ran.
    pub(super) cpu: AtomicU32,
    /// Saved stack pointer while switched out.
    rsp: UnsafeCell<u64>,
    stack: Option<KernelStack>,
    entry: IrqSpinLock<Option<Entry>>,
    /// Woken when the thread exits.
    pub(super) exited: WaitQueue,
    /// The process this thread belongs to (user threads only).
    pub process: Option<Arc<crate::proc::Process>>,
    /// Architecture-specific user state (segment bases, FPU registers).
    pub arch: arch::context::ArchThread,
    /// Blocked signals (bit n-1 = signal n).
    sig_mask: AtomicU64,
    /// Signals directed at this thread (faults, tgkill).
    sig_pending: AtomicU64,
    /// What those sent by a process carry for siginfo (tgkill(2),
    /// rt_tgsigqueueinfo(2)), by signal.
    pub sig_info: IrqSpinLock<alloc::vec::Vec<(u32, crate::proc::signal::Info)>>,
    /// Mask to restore after the next signal delivery (rt_sigsuspend).
    saved_mask: IrqSpinLock<Option<u64>>,
    /// Deadline of an interrupted sleep that will be restarted (0 = none).
    restart_deadline: AtomicU64,
    /// Alternate signal stack (sigaltstack(2)): (base, size, flags).
    pub altstack: IrqSpinLock<(u64, u64, u32)>,
    /// A user thread's own name (PR_SET_NAME from a thread other than the
    /// main one); the main thread's name is its process's.
    pub comm: IrqSpinLock<Option<String>>,
    /// Details of the last fault turned into a signal: (signal, si_code,
    /// address), for that signal's siginfo.
    /// A signal the kernel raised for this thread, with its siginfo.
    pub fault: IrqSpinLock<Option<Fault>>,
    /// User address to clear and futex-wake when the thread exits
    /// (set_tid_address(2), CLONE_CHILD_CLEARTID).
    pub clear_child_tid: AtomicU64,
    /// set_robust_list(2): the head of the thread's robust futex list.
    pub robust_list: AtomicU64,
    /// rseq(2)'s registration (ADR 0115).
    pub rseq: IrqSpinLock<Option<crate::proc::rseq::Registration>>,
    /// Times this thread was switched away from a CPU, and that count when
    /// its rseq area was last brought up to date.
    pub switched_out: AtomicU64,
    pub rseq_seen: AtomicU64,
    /// ioprio_set(2)'s value (class << 13 | level), kept and read back:
    /// Slate's block layer has no I/O priorities (ADR 0115).
    pub ioprio: AtomicU32,
    /// The system call in progress, plus one (0: none), for
    /// /proc/slate_sched.
    pub syscall: AtomicU64,
    /// Its first argument.
    pub syscall_arg: AtomicU64,
    /// Namespaces of this thread when they differ from its process's (a
    /// thread of a multi-threaded process called unshare or setns:
    /// namespaces are per thread, ADR 0028).
    pub ns: crate::sync::IrqSpinLock<Option<crate::proc::ns::Namespaces>>,
    /// Credentials of this thread when they differ from its process's:
    /// each thread has its own (credentials(7)), and setuid(2) and the
    /// others change only the caller's (C libraries make every thread
    /// call them). For the length of an access(2) check, the ones it
    /// checks with.
    pub cred: crate::sync::IrqSpinLock<Option<alloc::sync::Arc<crate::proc::cred::Cred>>>,
    /// Root and working directory of this thread after unshare(CLONE_FS)
    /// in a multi-threaded process (as namespaces, per thread on Linux).
    pub fs: crate::sync::IrqSpinLock<Option<crate::proc::ThreadFs>>,
    /// Another thread asked this one to exit (exit_group, execve).
    pub exit_requested: AtomicBool,
    /// CPU time this thread used in user mode and in the kernel, in
    /// nanoseconds, measured at every switch between the two (ADR 0045).
    pub user_ns: AtomicU64,
    pub system_ns: AtomicU64,
    /// Faults, block I/O and context switches (getrusage(2)).
    pub counts: crate::proc::Counts,
    /// The part of `user_ns` and `system_ns` already charged to the
    /// virtual run time and the cgroup.
    pub(super) charged_user: AtomicU64,
    pub(super) charged_system: AtomicU64,
    /// Scheduling policy, real-time priority and nice value (sched(7)).
    pub(super) policy: AtomicU8,
    pub(super) rt_priority: AtomicU8,
    pub(super) nice: AtomicI8,
    /// SCHED_RESET_ON_FORK: children start with the normal policy.
    pub(super) reset_on_fork: AtomicBool,
    /// The rank lent by threads waiting on priority-inheritance futexes
    /// this thread owns (0: none; see `policy.rs`).
    pub(super) pi_boost: AtomicU32,
    /// Run time weighted by nice: the order of normal threads in a run
    /// queue, relative to the queue's `min_vruntime`.
    pub(super) vruntime: AtomicU64,
}

// SAFETY: `rsp` is only accessed by the CPU switching this thread in or
// out, which the `on_cpu` protocol makes exclusive; everything else is
// atomic or locked.
unsafe impl Sync for Thread {}
// SAFETY: As above.
unsafe impl Send for Thread {}

impl core::fmt::Debug for Thread {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Thread")
            .field("tid", &self.tid)
            .field("name", &self.name)
            .field("state", &self.state())
            .finish()
    }
}

static NEXT_TID: AtomicU64 = AtomicU64::new(1);
/// Thread objects alive (not yet dropped), for /proc/slate_sched.
pub static LIVE: AtomicU64 = AtomicU64::new(0);

impl Drop for Thread {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::Relaxed);
    }
}
/// Kernel threads are numbered separately, far above user IDs, so the
/// first user process is pid 1 (init) whatever the kernel started before.
static NEXT_KERNEL_TID: AtomicU64 = AtomicU64::new(1 << 32);

/// Allocate a user thread ID. Process IDs come from the same space: a
/// process's pid is its first thread's tid, as on Linux.
pub fn alloc_id() -> Tid {
    NEXT_TID.fetch_add(1, Ordering::Relaxed)
}

/// The id [`alloc_id`] gives next.
pub fn next_id() -> Tid {
    NEXT_TID.load(Ordering::Relaxed)
}

/// Give ids from `to` again. Only for the boot's unlock stage (ADR 0038):
/// its one process has gone, and init must still be pid 1.
pub fn rewind_ids(to: Tid) {
    NEXT_TID.store(to, Ordering::Relaxed);
}

impl Thread {
    /// Charge `ns` of CPU time to this thread and its process.
    pub(super) fn charge(&self, user: bool, ns: u64) {
        let mine = if user { &self.user_ns } else { &self.system_ns };
        mine.fetch_add(ns, Ordering::Relaxed);
        if let Some(p) = &self.process {
            let theirs = if user { &p.cpu.user } else { &p.cpu.system };
            theirs.fetch_add(ns, Ordering::Relaxed);
        }
    }

    /// Count `n` events of one kind (`which` picks the counter) for this
    /// thread and its process.
    pub fn count(&self, which: fn(&crate::proc::Counts) -> &AtomicU64, n: u64) {
        which(&self.counts).fetch_add(n, Ordering::Relaxed);
        if let Some(p) = &self.process {
            which(&p.cpu.counts).fetch_add(n, Ordering::Relaxed);
        }
    }

    /// The CPU it runs on or last ran on.
    pub fn last_cpu(&self) -> u32 {
        self.cpu.load(Ordering::Relaxed)
    }

    /// (user, system) CPU time in nanoseconds.
    pub fn cpu_ns(&self) -> (u64, u64) {
        (self.user_ns.load(Ordering::Relaxed), self.system_ns.load(Ordering::Relaxed))
    }

    /// How the thread runs now: its policy, priority, nice value and boost.
    pub fn class(&self) -> super::policy::Class {
        super::policy::class(
            self.policy.load(Ordering::Relaxed),
            self.rt_priority.load(Ordering::Relaxed),
            self.nice.load(Ordering::Relaxed),
            self.pi_boost.load(Ordering::Relaxed),
        )
    }

    /// Its own rank, without a boost.
    pub fn rank(&self) -> u32 {
        super::policy::rank(
            self.policy.load(Ordering::Relaxed),
            self.rt_priority.load(Ordering::Relaxed),
            self.nice.load(Ordering::Relaxed),
        )
    }

    /// Its rank with a boost: what it lends to a lock owner.
    pub fn effective_rank(&self) -> u32 {
        self.rank().max(self.pi_boost.load(Ordering::Relaxed))
    }

    /// (policy, real-time priority, nice value, reset on fork).
    pub fn sched_params(&self) -> (u8, u8, i8, bool) {
        (
            self.policy.load(Ordering::Relaxed),
            self.rt_priority.load(Ordering::Relaxed),
            self.nice.load(Ordering::Relaxed),
            self.reset_on_fork.load(Ordering::Relaxed),
        )
    }

    /// Take the creator's scheduling parameters (fork(2), clone(2); with
    /// SCHED_RESET_ON_FORK the normal policy and a nice value of at least
    /// 0, sched(7)).
    pub fn inherit_sched(&self, from: &Thread) {
        let (policy, prio, nice, reset) = from.sched_params();
        let (policy, prio, nice) = match policy {
            _ if !reset => (policy, prio, nice),
            super::policy::SCHED_FIFO | super::policy::SCHED_RR => (super::policy::SCHED_OTHER, 0, nice.max(0)),
            _ => (policy, 0, nice.max(0)),
        };
        self.policy.store(policy, Ordering::Relaxed);
        self.rt_priority.store(prio, Ordering::Relaxed);
        self.nice.store(nice, Ordering::Relaxed);
        // "The reset-on-fork flag is disabled in children created by
        // fork(2)" (sched(7)).
        self.reset_on_fork.store(false, Ordering::Relaxed);
    }

    fn alloc(
        name: &str,
        pinned: Option<u32>,
        state: State,
        stack: Option<KernelStack>,
        entry: Option<Entry>,
        process: Option<Arc<crate::proc::Process>>,
        tid: Option<Tid>,
    ) -> Thread {
        LIVE.fetch_add(1, Ordering::Relaxed);
        Thread {
            tid: tid.unwrap_or_else(|| NEXT_KERNEL_TID.fetch_add(1, Ordering::Relaxed)),
            name: String::from(name),
            pinned,
            affinity: AtomicU64::new(u64::MAX),
            state: AtomicU8::new(state as u8),
            sched_lock: IrqSpinLock::new(()),
            on_cpu: AtomicBool::new(state == State::Running),
            cpu: AtomicU32::new(pinned.unwrap_or(arch::cpu_id())),
            rsp: UnsafeCell::new(0),
            stack,
            entry: IrqSpinLock::new(entry),
            exited: WaitQueue::new(),
            process,
            arch: arch::context::ArchThread::default(),
            sig_mask: AtomicU64::new(0),
            sig_pending: AtomicU64::new(0),
            sig_info: IrqSpinLock::new(alloc::vec::Vec::new()),
            saved_mask: IrqSpinLock::new(None),
            restart_deadline: AtomicU64::new(0),
            altstack: IrqSpinLock::new((0, 0, ALTSTACK_DISABLED)),
            comm: IrqSpinLock::new(None),
            fault: IrqSpinLock::new(None),
            clear_child_tid: AtomicU64::new(0),
            robust_list: AtomicU64::new(0),
            rseq: IrqSpinLock::new(None),
            switched_out: AtomicU64::new(0),
            rseq_seen: AtomicU64::new(0),
            ioprio: AtomicU32::new(0),
            syscall: AtomicU64::new(0),
            syscall_arg: AtomicU64::new(0),
            ns: crate::sync::IrqSpinLock::new(None),
            cred: crate::sync::IrqSpinLock::new(None),
            fs: crate::sync::IrqSpinLock::new(None),
            exit_requested: AtomicBool::new(false),
            user_ns: AtomicU64::new(0),
            counts: crate::proc::Counts::default(),
            system_ns: AtomicU64::new(0),
            charged_user: AtomicU64::new(0),
            charged_system: AtomicU64::new(0),
            policy: AtomicU8::new(super::policy::SCHED_OTHER),
            rt_priority: AtomicU8::new(0),
            nice: AtomicI8::new(0),
            reset_on_fork: AtomicBool::new(false),
            pi_boost: AtomicU32::new(0),
            vruntime: AtomicU64::new(0),
        }
    }

    /// A new thread that will run `f` on its own kernel stack.
    pub(super) fn new(
        name: &str,
        pinned: Option<u32>,
        f: Entry,
        process: Option<Arc<crate::proc::Process>>,
        tid: Option<Tid>,
    ) -> Arc<Thread> {
        let stack = KernelStack::new().expect("out of memory for a kernel stack");
        let top = stack.top();
        let t = Arc::new(Thread::alloc(name, pinned, State::Runnable, Some(stack), Some(f), process, tid));
        // SAFETY: The stack is fresh and owned by `t`; the trampoline gets a
        // pointer to the thread, which stays alive while it runs.
        let rsp = unsafe { arch::context::prepare_stack(top, Arc::as_ptr(&t) as u64) };
        // SAFETY: Nobody else can see `t` yet.
        unsafe { *t.rsp.get() = rsp };
        t
    }

    /// Wrap the context running right now (on a stack it already has).
    pub(super) fn new_current(name: &str, pinned: Option<u32>) -> Arc<Thread> {
        Arc::new(Thread::alloc(name, pinned, State::Running, None, None, None, None))
    }

    /// The idle thread of a CPU that has not run yet (the bootstrap CPU,
    /// whose boot context becomes an ordinary thread).
    pub(super) fn new_idle(cpu: u32) -> Arc<Thread> {
        Thread::new("idle", Some(cpu), Box::new(|| super::idle_loop()), None, None)
    }

    pub fn state(&self) -> State {
        match self.state.load(Ordering::Acquire) {
            0 => State::Runnable,
            1 => State::Running,
            2 => State::Blocked,
            _ => State::Dead,
        }
    }

    pub(super) fn set_state(&self, s: State) {
        self.state.store(s as u8, Ordering::Release);
    }

    /// Mark the current thread as about to block. Must be called with
    /// interrupts masked, before registering with a waker.
    pub(crate) fn block_prepare(&self) {
        let _g = self.sched_lock.lock();
        self.set_state(State::Blocked);
    }

    pub(super) fn saved_rsp_ptr(&self) -> *mut u64 {
        self.rsp.get()
    }

    pub(super) fn saved_rsp(&self) -> u64 {
        // SAFETY: Only read by the CPU about to switch to this thread, after
        // the `on_cpu` handshake.
        unsafe { *self.rsp.get() }
    }

    pub(super) fn kernel_stack_top(&self) -> u64 {
        self.stack.as_ref().map_or(0, |s| s.top())
    }

    pub(super) fn take_entry(&self) -> Option<Entry> {
        self.entry.lock().take()
    }

    pub fn signal_mask(&self) -> u64 {
        self.sig_mask.load(Ordering::Acquire)
    }

    pub fn set_signal_mask(&self, m: u64) {
        self.sig_mask.store(m, Ordering::Release);
    }

    pub fn pending_signals(&self) -> u64 {
        self.sig_pending.load(Ordering::Acquire)
    }

    pub fn add_pending_signal(&self, bits: u64) {
        self.sig_pending.fetch_or(bits, Ordering::AcqRel);
    }

    pub fn take_pending_signal(&self, bits: u64) {
        self.sig_pending.fetch_and(!bits, Ordering::AcqRel);
    }

    /// Remember `mask` as the mask a signal frame should restore.
    pub fn save_mask_for_delivery(&self, mask: u64) {
        *self.saved_mask.lock() = Some(mask);
    }

    pub fn take_saved_mask(&self) -> Option<u64> {
        self.saved_mask.lock().take()
    }

    /// Remember where an interrupted sleep was going to end, so its
    /// transparent restart sleeps only the remaining time.
    pub fn set_restart_deadline(&self, ns: u64) {
        self.restart_deadline.store(ns, Ordering::Relaxed);
    }

    pub fn take_restart_deadline(&self) -> Option<u64> {
        Some(self.restart_deadline.swap(0, Ordering::Relaxed)).filter(|&d| d != 0)
    }

    /// Wait until the thread has exited.
    pub fn join(&self) {
        self.exited.wait_until(|| self.state() == State::Dead);
    }
}
