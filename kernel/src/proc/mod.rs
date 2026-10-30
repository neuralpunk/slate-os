// SPDX-License-Identifier: MIT OR Apache-2.0

//! Processes: an address space, open files, a working directory, signal
//! state, and (until M8) exactly one thread.
//!
//! Every process except those the kernel starts directly has a parent. A
//! process that exits becomes a zombie until its parent collects it with
//! wait4(2); children of an exiting process move to init (pid 1).

pub mod apps;
pub mod aslr;
pub mod cred;
pub mod domain;
pub mod exec;
pub mod fcaps;
pub mod futex;
pub mod ns;
pub mod oom;
pub mod profile;
pub mod rlimit;
pub mod rseq;
pub mod seccomp;
pub mod sign;
pub mod signal;
pub mod tests;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};

pub use rlimit::check_cpu_limit;

use crate::abi::linux::errno::*;
use crate::arch::trap::TrapFrame;
use crate::arch::{paging, syscall};
use crate::fs::FdTable;
use crate::fs::vfs::{self, Dentry};
use crate::log_warn;
use crate::mm::aspace::AddressSpace;
use crate::sched::{self, wait::WaitQueue};
use crate::sync::IrqSpinLock;

pub type Pid = u32;

pub struct Process {
    pub pid: Pid,
    /// The parent, or none for processes the kernel started directly.
    parent: IrqSpinLock<Weak<Process>>,
    pub pgid: AtomicU32,
    pub sid: AtomicU32,
    pub name: IrqSpinLock<String>,
    /// NUL-separated argv, for /proc/<pid>/cmdline.
    pub cmdline: IrqSpinLock<Vec<u8>>,
    /// The running program (/proc/<pid>/exe); `None` before the first exec.
    pub exe: IrqSpinLock<Option<Arc<Dentry>>>,
    /// `None` once the process has exited.
    pub aspace: IrqSpinLock<Option<AddressSpace>>,
    /// Page-table root of `aspace`, readable without the lock (the scheduler
    /// needs it on every switch).
    root: AtomicU64,
    pub files: IrqSpinLock<FdTable>,
    /// Working and root directory (chroot(2)) and umask, shared with the
    /// processes made with clone(CLONE_FS); see `cwd()`/`root_dir()`/`umask()`.
    fs: IrqSpinLock<Arc<SharedFs>>,
    /// PR_SET_PDEATHSIG: the signal sent when the parent exits (0: none).
    pub pdeath_signal: AtomicU32,
    /// PR_SET_CHILD_SUBREAPER: orphaned descendants come here instead of
    /// to the namespace's init.
    pub subreaper: core::sync::atomic::AtomicBool,
    /// PR_SET_DUMPABLE.
    pub dumpable: core::sync::atomic::AtomicBool,
    /// The system-call interface its program uses (set at exec, inherited
    /// on fork; ADR 0031).
    abi: core::sync::atomic::AtomicU8,
    /// Slate or Linux domain (set at exec, inherited on fork; ADR 0032).
    domain: core::sync::atomic::AtomicU8,
    /// The system grant (ADR 0090): it may change the system image.
    grant: AtomicBool,
    /// personality(2)'s persona: PER_LINUX and its flags (ADR 0092).
    pub persona: AtomicU32,
    /// The JIT permission (ADR 0093): a program signed JIT, in the Slate
    /// domain.
    jit: AtomicBool,
    /// Per-app permissions (ADR 0130): `apps::CONFINED` and what a
    /// confined process may do; 0 unconfined.
    app: AtomicU32,
    /// May write the encrypted root's key slots (ADR 0130): a program
    /// signed KEYSLOTS, run as root.
    keyslots: AtomicBool,
    /// The running program's load bias (ADR 0092), for the profiler.
    pub exe_bias: AtomicU64,
    /// The service it belongs to (set by init, inherited on fork, kept
    /// across exec; ADR 0060).
    pub service: IrqSpinLock<Option<Arc<str>>>,
    /// The Linux box it runs in (ADR 0183): set once by `box_tag`,
    /// inherited on fork, kept across exec.
    pub box_tag: IrqSpinLock<Option<Arc<str>>>,
    /// How many of its refusals have been logged (a box's process; ADR
    /// 0183's phase 5).
    pub box_refusals: core::sync::atomic::AtomicU32,
    /// seccomp mode and filters.
    pub seccomp: IrqSpinLock<seccomp::Seccomp>,
    /// clone(CLONE_VFORK | CLONE_FILES): the parent, blocked until this
    /// child execs or exits, gets the descriptor table back then, as if
    /// they had shared it all along.
    files_back: IrqSpinLock<Option<Weak<Process>>>,
    /// vfork(2): the parent whose address space this child borrows (CLONE_VM
    /// with the parent blocked); it goes back at exec or exit.
    aspace_lender: IrqSpinLock<Option<Weak<Process>>>,
    /// Credentials (proc/cred.rs).
    cred: IrqSpinLock<Arc<cred::Cred>>,
    pub signals: signal::ProcessSignals,
    children: IrqSpinLock<Vec<Arc<Process>>>,
    /// Woken when a child changes state (exits).
    child_event: WaitQueue,
    /// Linux wait status (wait(2)): set once, at exit.
    status: IrqSpinLock<Option<i32>>,
    exited: WaitQueue,
    /// Woken when a vfork child execs or exits.
    vfork_done: WaitQueue,
    vfork_released: core::sync::atomic::AtomicBool,
    /// Monotonic time of creation, for /proc.
    pub start_ns: u64,
    /// CPU time used (nanoseconds), by this process and by its reaped
    /// children.
    pub cpu: CpuTimes,
    /// Resource limits (`rlimit.rs`).
    limits: IrqSpinLock<rlimit::Limits>,
    /// RLIMIT_CPU's soft and hard limits in nanoseconds, for the tick.
    cpu_limit_ns: [AtomicU64; 2],
    /// One more than the CPU second SIGXCPU was last sent for.
    cpu_limit_signalled: AtomicU64,
    /// /proc/<pid>/oom_score_adj (-1000 to 1000; proc(5)).
    pub oom_score_adj: AtomicI32,
    /// When the out-of-memory killer chose this process (monotonic ns; 0:
    /// never).
    pub oom_killed_at: AtomicU64,
    /// The process's threads (the first is the main thread, tid == pid).
    threads: IrqSpinLock<Vec<Weak<sched::Thread>>>,
    /// Set by exit_group(2) or a fatal signal: the status every thread
    /// leaves with; the last thread out finishes the process.
    group_exit: IrqSpinLock<Option<i32>>,
    /// Controlling terminal (credentials(7)).
    ctty: IrqSpinLock<Option<Arc<crate::fs::tty::Tty>>>,
    /// Job control: stopped by a signal, and the state change not yet
    /// reported to the parent by wait4(2).
    job: IrqSpinLock<JobState>,
    /// Woken when a stopped process is continued (or killed).
    continued: WaitQueue,
    /// ITIMER_REAL (alarm(2), setitimer(2)).
    real_timer: IrqSpinLock<RealTimer>,
    /// The cgroup the process belongs to (cgroups(7)).
    cgroup: IrqSpinLock<Arc<crate::fs::cgroup::Cgroup>>,
    /// The namespaces it is in (ADR 0028).
    ns: IrqSpinLock<ns::Namespaces>,
    /// Its PID in its PID namespace and in each ancestor, outermost first
    /// (the first is `pid`, the host PID).
    pids: IrqSpinLock<NsPids>,
    /// Thread IDs of its other threads in each PID namespace below the
    /// initial one (empty for processes in the initial namespace).
    thread_ids: IrqSpinLock<Vec<(u64, NsPids)>>,
}

#[derive(Debug, Default)]
struct RealTimer {
    deadline: Option<u64>,
    interval: u64,
    pending: Option<crate::time::TimerId>,
    generation: u64,
}

#[derive(Debug, Default)]
struct JobState {
    stopped: bool,
    /// Wait status to report for WUNTRACED/WCONTINUED.
    report: Option<i32>,
}

impl core::fmt::Debug for Process {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Process").field("pid", &self.pid).field("name", &*self.name.lock()).finish()
    }
}

/// A process's system-call interface (ADR 0031).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Abi {
    Linux = 0,
    /// Slate's native interface (programs with the `Slate` ELF note).
    Native = 1,
}

/// Process objects alive (not yet dropped), for /proc/slate_sched.
pub static LIVE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

impl Drop for Process {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Every process that has not been reaped, by pid.
static TABLE: IrqSpinLock<BTreeMap<Pid, Arc<Process>>> = IrqSpinLock::new(BTreeMap::new());

/// Wait status for a normal exit with `code` (wait(2), WEXITSTATUS).
pub fn wait_status_exited(code: i32) -> i32 {
    (code & 0xFF) << 8
}

/// Wait status for death by signal `sig` (WTERMSIG).
pub fn wait_status_signaled(sig: i32) -> i32 {
    sig & 0x7F
}

impl Process {
    pub fn abi(&self) -> Abi {
        if self.abi.load(Ordering::Relaxed) == Abi::Native as u8 { Abi::Native } else { Abi::Linux }
    }

    fn set_abi(&self, abi: Abi) {
        self.abi.store(abi as u8, Ordering::Relaxed);
    }

    pub fn domain(&self) -> domain::Domain {
        if self.domain.load(Ordering::Relaxed) == domain::Domain::Slate as u8 {
            domain::Domain::Slate
        } else {
            domain::Domain::Linux
        }
    }

    fn set_domain(&self, d: domain::Domain) {
        self.domain.store(d as u8, Ordering::Relaxed);
    }

    /// Whether it holds the system grant (ADR 0090).
    pub fn has_grant(&self) -> bool {
        self.grant.load(Ordering::Relaxed)
    }

    /// Whether it may generate code (ADR 0093).
    pub fn has_jit(&self) -> bool {
        self.jit.load(Ordering::Relaxed)
    }

    /// Its per-app permissions (ADR 0130).
    pub fn app(&self) -> u32 {
        self.app.load(Ordering::Relaxed)
    }

    /// Whether it may write the encrypted root's key slots.
    pub fn has_keyslots(&self) -> bool {
        self.keyslots.load(Ordering::Relaxed)
    }

    fn new(
        name: String,
        parent: Weak<Process>,
        aspace: AddressSpace,
        files: FdTable,
        cwd: Arc<Dentry>,
        root_dir: Arc<Dentry>,
    ) -> Arc<Process> {
        let pid = sched::alloc_id() as Pid;
        LIVE.fetch_add(1, Ordering::Relaxed);
        let p = Arc::new(Process {
            pid,
            parent: IrqSpinLock::new(parent),
            pgid: AtomicU32::new(pid),
            sid: AtomicU32::new(pid),
            name: IrqSpinLock::new(name),
            cmdline: IrqSpinLock::new(Vec::new()),
            exe: IrqSpinLock::new(None),
            root: AtomicU64::new(aspace.root().0),
            aspace: IrqSpinLock::new(Some(aspace)),
            files: IrqSpinLock::new(files),
            fs: IrqSpinLock::new(Arc::new(SharedFs {
                root: IrqSpinLock::new(root_dir),
                cwd: IrqSpinLock::new(cwd),
                umask: AtomicU32::new(0o022),
            })),
            pdeath_signal: AtomicU32::new(0),
            subreaper: core::sync::atomic::AtomicBool::new(false),
            dumpable: core::sync::atomic::AtomicBool::new(true),
            abi: core::sync::atomic::AtomicU8::new(Abi::Linux as u8),
            domain: core::sync::atomic::AtomicU8::new(domain::Domain::Linux as u8),
            grant: AtomicBool::new(false),
            persona: AtomicU32::new(0),
            exe_bias: AtomicU64::new(0),
            jit: AtomicBool::new(false),
            app: AtomicU32::new(0),
            keyslots: AtomicBool::new(false),
            service: IrqSpinLock::new(None),
            box_tag: IrqSpinLock::new(None),
            box_refusals: core::sync::atomic::AtomicU32::new(0),
            seccomp: IrqSpinLock::new(seccomp::Seccomp::default()),
            files_back: IrqSpinLock::new(None),
            aspace_lender: IrqSpinLock::new(None),
            cred: IrqSpinLock::new(Arc::new(cred::Cred::root())),
            signals: signal::ProcessSignals::new(),
            children: IrqSpinLock::new(Vec::new()),
            child_event: WaitQueue::new(),
            status: IrqSpinLock::new(None),
            exited: WaitQueue::new(),
            vfork_done: WaitQueue::new(),
            vfork_released: core::sync::atomic::AtomicBool::new(false),
            start_ns: crate::time::monotonic_ns(),
            cpu: CpuTimes::default(),
            limits: IrqSpinLock::new(rlimit::Limits::defaults()),
            cpu_limit_ns: [AtomicU64::new(u64::MAX), AtomicU64::new(u64::MAX)],
            cpu_limit_signalled: AtomicU64::new(0),
            oom_score_adj: AtomicI32::new(0),
            oom_killed_at: AtomicU64::new(0),
            threads: IrqSpinLock::new(Vec::new()),
            group_exit: IrqSpinLock::new(None),
            ctty: IrqSpinLock::new(None),
            job: IrqSpinLock::new(JobState::default()),
            continued: WaitQueue::new(),
            real_timer: IrqSpinLock::new(RealTimer::default()),
            cgroup: IrqSpinLock::new(crate::fs::cgroup::root()),
            ns: IrqSpinLock::new(ns::initial()),
            pids: IrqSpinLock::new(alloc::vec![(ns::initial().pid_for_children, pid)]),
            thread_ids: IrqSpinLock::new(Vec::new()),
        });
        TABLE.lock().insert(pid, p.clone());
        p
    }

    /// The credentials (a snapshot; changes replace it): the calling
    /// thread's when it is one of ours (they may be its own), else the
    /// process's, which are its main thread's.
    pub fn cred(&self) -> Arc<cred::Cred> {
        if let Some(t) = self.own_current_thread()
            && let Some(c) = t.cred.lock().clone()
        {
            return c;
        }
        self.cred.lock().clone()
    }

    /// Change the calling thread's credentials, as setuid(2) and the
    /// others do (credentials(7)): when the main thread changes, the
    /// process's change and the other threads keep what they had. Called
    /// from outside the process (the kernel, the privilege broker), it
    /// changes every thread's ([`Process::set_cred_all`]).
    pub fn set_cred(&self, c: cred::Cred) {
        let Some(me) = self.own_current_thread() else { return self.set_cred_all(c) };
        self.ids_changed(&self.cred(), &c);
        let c = Arc::new(c);
        let mut base = self.cred.lock();
        if me.tid != u64::from(self.pid) {
            *me.cred.lock() = (*c != **base).then_some(c);
            return;
        }
        for t in self.threads().iter().filter(|t| t.tid != me.tid) {
            let mut own = t.cred.lock();
            match &*own {
                None => *own = Some(base.clone()),
                Some(o) if **o == *c => *own = None,
                Some(_) => {}
            }
        }
        *me.cred.lock() = None;
        *base = c;
    }

    /// Change every thread's credentials (execve(2), Slate's native
    /// `setids`, the privilege broker).
    pub fn set_cred_all(&self, c: cred::Cred) {
        self.ids_changed(&self.cred.lock().clone(), &c);
        let mut base = self.cred.lock();
        for t in self.threads() {
            *t.cred.lock() = None;
        }
        *base = Arc::new(c);
    }

    /// A change of the effective or file-system IDs makes the process not
    /// dumpable (prctl(2) PR_SET_DUMPABLE: /proc/sys/fs/suid_dumpable is
    /// 0): its /proc files are then private to CAP_SYS_PTRACE.
    fn ids_changed(&self, old: &cred::Cred, new: &cred::Cred) {
        if (old.euid, old.egid, old.fsuid, old.fsgid) != (new.euid, new.egid, new.fsuid, new.fsgid) {
            self.dumpable.store(false, Ordering::Relaxed);
        }
    }

    /// Run `f` with the calling thread checking access as `c` (access(2)
    /// checks with the real IDs, also for the directories it searches).
    pub fn with_cred<R>(&self, c: cred::Cred, f: impl FnOnce() -> R) -> R {
        let Some(me) = self.own_current_thread() else { return f() };
        let saved = me.cred.lock().replace(Arc::new(c));
        let r = f();
        *me.cred.lock() = saved;
        r
    }

    /// Physical address of the page-table root, for the scheduler.
    pub fn root(&self) -> u64 {
        self.root.load(Ordering::Acquire)
    }

    pub fn ppid(&self) -> Pid {
        self.parent.lock().upgrade().map_or(0, |p| p.pid)
    }

    pub fn parent(&self) -> Option<Arc<Process>> {
        self.parent.lock().upgrade()
    }

    pub fn is_zombie(&self) -> bool {
        self.status.lock().is_some()
    }

    pub fn ctty(&self) -> Option<Arc<crate::fs::tty::Tty>> {
        self.ctty.lock().clone()
    }

    pub fn set_ctty(&self, t: Option<Arc<crate::fs::tty::Tty>>) {
        *self.ctty.lock() = t;
    }

    pub fn is_stopped(&self) -> bool {
        self.job.lock().stopped
    }

    /// The calling thread, if it belongs to this process.
    fn own_current_thread(&self) -> Option<Arc<sched::Thread>> {
        let t = sched::current();
        t.process.as_ref().is_some_and(|p| core::ptr::eq(Arc::as_ptr(p), self)).then_some(t)
    }

    /// The working directory: the calling thread's own after
    /// unshare(CLONE_FS), else the process's.
    pub fn cwd(&self) -> Arc<Dentry> {
        if let Some(t) = self.own_current_thread()
            && let Some(f) = t.fs.lock().as_ref()
        {
            return f.cwd.clone();
        }
        let fs = self.fs.lock().clone();
        fs.cwd.lock().clone()
    }

    pub fn root_dir(&self) -> Arc<Dentry> {
        if let Some(t) = self.own_current_thread()
            && let Some(f) = t.fs.lock().as_ref()
        {
            return f.root.clone();
        }
        let fs = self.fs.lock().clone();
        fs.root.lock().clone()
    }

    pub fn set_cwd(&self, d: Arc<Dentry>) {
        if let Some(t) = self.own_current_thread()
            && let Some(f) = t.fs.lock().as_mut()
        {
            f.cwd = d;
            return;
        }
        let fs = self.fs.lock().clone();
        *fs.cwd.lock() = d;
    }

    /// The file mode creation mask (umask(2)): the calling thread's own
    /// after unshare(CLONE_FS), else the one shared with clone(CLONE_FS).
    pub fn umask(&self) -> u32 {
        if let Some(t) = self.own_current_thread()
            && let Some(f) = t.fs.lock().as_ref()
        {
            return f.umask;
        }
        self.fs.lock().clone().umask.load(Ordering::Relaxed)
    }

    /// Set the mask; returns the one before.
    pub fn set_umask(&self, mask: u32) -> u32 {
        if let Some(t) = self.own_current_thread()
            && let Some(f) = t.fs.lock().as_mut()
        {
            return core::mem::replace(&mut f.umask, mask);
        }
        self.fs.lock().clone().umask.swap(mask, Ordering::Relaxed)
    }

    pub fn set_root_dir(&self, d: Arc<Dentry>) {
        if let Some(t) = self.own_current_thread()
            && let Some(f) = t.fs.lock().as_mut()
        {
            f.root = d;
            return;
        }
        let fs = self.fs.lock().clone();
        *fs.root.lock() = d;
    }

    /// unshare(CLONE_FS): the calling thread gets its own root and working
    /// directory, if it is one of several threads; a process sharing them
    /// with others (clone(CLONE_FS)) gets its own copy.
    pub fn unshare_fs(&self) {
        let shared = self.fs.lock().clone();
        if let Some(t) = self.own_current_thread()
            && self.threads().len() > 1
        {
            let mut f = t.fs.lock();
            if f.is_none() {
                *f = Some(ThreadFs {
                    root: shared.root.lock().clone(),
                    cwd: shared.cwd.lock().clone(),
                    umask: shared.umask.load(Ordering::Relaxed),
                });
            }
            return;
        }
        // Two references: ours, and `shared` here.
        if Arc::strong_count(&shared) > 2 {
            let own = SharedFs {
                root: IrqSpinLock::new(shared.root.lock().clone()),
                cwd: IrqSpinLock::new(shared.cwd.lock().clone()),
                umask: AtomicU32::new(shared.umask.load(Ordering::Relaxed)),
            };
            *self.fs.lock() = Arc::new(own);
        }
    }

    /// Share `other`'s root and working directory (clone(CLONE_FS)).
    fn share_fs_with(&self, other: &Process) {
        let fs = other.fs.lock().clone();
        *self.fs.lock() = fs;
    }

    /// Its namespaces: the calling thread's own, when called from a thread
    /// of this process that has them; otherwise the process's (its main
    /// thread's, as /proc/<pid>/ns shows).
    pub fn namespaces(&self) -> ns::Namespaces {
        if let Some(t) = self.own_current_thread()
            && let Some(n) = t.ns.lock().clone()
        {
            return n;
        }
        self.ns.lock().clone()
    }

    /// Thread `tid`'s namespaces.
    pub fn thread_namespaces(&self, tid: u64) -> ns::Namespaces {
        self.threads()
            .iter()
            .find(|t| t.tid == tid)
            .and_then(|t| t.ns.lock().clone())
            .unwrap_or_else(|| self.ns.lock().clone())
    }

    /// The id of its mount namespace (cheap: path lookup asks often).
    pub fn mnt_ns_id(&self) -> u64 {
        if let Some(t) = self.own_current_thread()
            && let Some(n) = t.ns.lock().as_ref()
        {
            return n.mnt.id;
        }
        self.ns.lock().mnt.id
    }

    /// Change the namespaces: of the calling thread only, when it is one of
    /// several threads (unshare(2) and setns(2) act on the caller); of the
    /// whole process otherwise.
    pub fn set_namespaces(&self, n: ns::Namespaces) {
        if let Some(t) = self.own_current_thread()
            && self.threads().len() > 1
        {
            *t.ns.lock() = Some(n);
            return;
        }
        if let Some(t) = self.own_current_thread() {
            *t.ns.lock() = None;
        }
        *self.ns.lock() = n;
    }

    /// execve leaves one thread: its namespaces, root and working
    /// directory become the process's.
    fn adopt_thread_namespaces(&self) {
        let Some(t) = self.own_current_thread() else { return };
        if let Some(n) = t.ns.lock().take() {
            *self.ns.lock() = n;
        }
        if let Some(f) = t.fs.lock().take() {
            let fs = self.fs.lock().clone();
            *fs.root.lock() = f.root;
            *fs.cwd.lock() = f.cwd;
            fs.umask.store(f.umask, Ordering::Relaxed);
        }
    }

    /// The PID namespace the process is in.
    pub fn pid_ns(&self) -> Arc<ns::PidNs> {
        self.pids.lock().last().map(|(n, _)| n.clone()).expect("a process without a PID")
    }

    /// Its PID as seen from PID namespace `n` (None outside it).
    pub fn pid_in(&self, n: &Arc<ns::PidNs>) -> Option<Pid> {
        self.pids.lock().iter().find(|(x, _)| Arc::ptr_eq(x, n)).map(|(_, p)| *p)
    }

    /// Thread `tid` (a host thread ID) of this process as PID namespace
    /// `n` sees it.
    pub fn tid_in(&self, tid: u64, n: &Arc<ns::PidNs>) -> Option<u64> {
        if n.level == 0 {
            return Some(tid);
        }
        if tid == u64::from(self.pid) {
            return self.pid_in(n).map(u64::from);
        }
        let ids = self.thread_ids.lock();
        let (_, local) = ids.iter().find(|(t, _)| *t == tid)?;
        local.iter().find(|(x, _)| Arc::ptr_eq(x, n)).map(|(_, l)| u64::from(*l))
    }

    pub fn cgroup(&self) -> Arc<crate::fs::cgroup::Cgroup> {
        self.cgroup.lock().clone()
    }

    pub fn set_cgroup(&self, cg: Arc<crate::fs::cgroup::Cgroup>) {
        *self.cgroup.lock() = cg;
    }

    /// The process's live threads.
    pub fn threads(&self) -> Vec<Arc<sched::Thread>> {
        self.threads.lock().iter().filter_map(Weak::upgrade).collect()
    }

    /// What the process itself used (RUSAGE_SELF): its CPU time, the
    /// largest resident set of this and earlier images, and its counts.
    pub fn usage(&self) -> Usage {
        let (user, system) = self.cpu.own();
        let now = self.aspace.lock().as_ref().map_or(0, |a| a.peak_pages());
        Usage {
            user,
            system,
            maxrss_pages: self.cpu.maxrss_pages.load(Ordering::Relaxed).max(now),
            counts: self.cpu.counts.get(),
        }
    }

    /// One live thread (the main thread while it lives).
    pub fn thread(&self) -> Option<Arc<sched::Thread>> {
        self.threads.lock().iter().find_map(Weak::upgrade)
    }

    /// The exit status if the whole process is going away (exit_group(2) or
    /// a fatal signal).
    pub fn exiting(&self) -> Option<i32> {
        *self.group_exit.lock()
    }

    /// Block until the process exits; returns its wait status. Used by the
    /// kernel for processes it started itself.
    pub fn wait(&self) -> i32 {
        self.exited.wait_until(|| self.status.lock().is_some());
        self.status.lock().unwrap()
    }

    fn set_argv(&self, argv: &[Vec<u8>], path: &str, exe: Arc<Dentry>) {
        let mut c = Vec::new();
        for a in argv {
            c.extend_from_slice(a);
            c.push(0);
        }
        *self.cmdline.lock() = c;
        let base = path.rsplit('/').next().unwrap_or(path);
        let name: String = base.chars().take(15).collect(); // TASK_COMM_LEN - 1
        *self.name.lock() = name;
        *self.exe.lock() = Some(exe);
    }
}

/// The process of the running thread, if it is a user thread.
pub fn current() -> Option<Arc<Process>> {
    sched::current().process.clone()
}

/// Look up a live or zombie process.
pub fn get(pid: Pid) -> Option<Arc<Process>> {
    TABLE.lock().get(&pid).cloned()
}

/// The PID namespace of the calling process (the initial one for the
/// kernel).
pub fn caller_pid_ns() -> Arc<ns::PidNs> {
    current().map_or_else(|| ns::initial().pid_for_children, |p| p.pid_ns())
}

/// The PID the calling process sees for host PID `pid` (`None` if it is
/// outside the caller's PID namespace).
pub fn pid_in_caller_ns(pid: Pid) -> Option<Pid> {
    let n = caller_pid_ns();
    if n.level == 0 {
        return Some(pid);
    }
    get(pid).and_then(|p| p.pid_in(&n))
}

/// Host PID `pid` as the caller sees it; 0 when it is outside the
/// caller's PID namespace (as getppid(2) reports such a parent).
pub fn pid_out(pid: Pid) -> Pid {
    if pid == 0 { 0 } else { pid_in_caller_ns(pid).unwrap_or(0) }
}

/// Whether the caller's PID namespace contains process `p`.
pub fn visible(p: &Process) -> bool {
    let n = caller_pid_ns();
    n.level == 0 || p.pid_in(&n).is_some()
}

/// A process-group or session ID given by the caller, as a host PID (the
/// leader's; groups whose leader is gone keep their number only in the
/// initial namespace).
pub fn pgid_in(pgid: Pid) -> Pid {
    if caller_pid_ns().level == 0 { pgid } else { find_in_caller_ns(pgid).map_or(0, |p| p.pid) }
}

/// The process the caller calls `pid`.
pub fn find_in_caller_ns(pid: Pid) -> Option<Arc<Process>> {
    let n = caller_pid_ns();
    if n.level == 0 {
        return get(pid);
    }
    all().into_iter().find(|p| p.pid_in(&n) == Some(pid))
}

fn root_dir_of(p: &Process) -> Arc<Dentry> {
    p.root_dir()
}

/// A process's root, working directory and umask, which processes made
/// with clone(CLONE_FS) share (a chroot in one applies to all of them).
#[derive(Debug)]
pub struct SharedFs {
    root: IrqSpinLock<Arc<Dentry>>,
    cwd: IrqSpinLock<Arc<Dentry>>,
    umask: AtomicU32,
}

/// A thread's own root, working directory and umask (unshare(CLONE_FS)).
#[derive(Clone, Debug)]
pub struct ThreadFs {
    pub root: Arc<Dentry>,
    pub cwd: Arc<Dentry>,
    pub umask: u32,
}

/// A process's or thread's ID in each of a chain of PID namespaces.
type NsPids = Vec<(Arc<ns::PidNs>, Pid)>;

/// All processes, in pid order.
pub fn all() -> Vec<Arc<Process>> {
    TABLE.lock().values().cloned().collect()
}

/// Start a process running `path` (from the root file system) with no
/// parent, stdin/stdout/stderr on the console, in its own session.
pub fn spawn(path: &str, argv: &[&[u8]], envp: &[&[u8]]) -> Result<Arc<Process>, Errno> {
    let root = vfs::root();
    let loaded = exec::load_path(&root, &root, path.as_bytes(), argv, envp, &cred::Cred::root())?;
    let p = Process::new(String::new(), Weak::new(), loaded.aspace, FdTable::with_console(), root.clone(), root);
    p.set_argv(&loaded.argv, &loaded.path, loaded.exe);
    p.set_abi(loaded.abi);
    p.set_domain(loaded.domain);
    p.grant.store(loaded.grant, Ordering::Relaxed);
    p.persona.store(loaded.persona, Ordering::Relaxed);
    p.exe_bias.store(loaded.image.bias, Ordering::Relaxed);
    p.jit.store(loaded.jit, Ordering::Relaxed);
    p.app.store(loaded.app, Ordering::Relaxed);
    p.keyslots.store(loaded.keyslots, Ordering::Relaxed);
    let image = loaded.image;
    start_thread(&p, u64::from(p.pid), move || {
        sched::current().arch.init_user();
        sched::UserEntry::Start { rip: image.entry, rsp: image.stack_pointer }
    });
    Ok(p)
}

fn start_thread(
    p: &Arc<Process>,
    tid: sched::Tid,
    f: impl FnOnce() -> sched::UserEntry + Send + 'static,
) -> Arc<sched::Thread> {
    let name = p.name.lock().clone();
    // Register the thread before it can run, so it always finds itself in
    // the list (exit relies on that).
    let mut list = p.threads.lock();
    let t = sched::spawn_user(&name, p.clone(), tid, f);
    list.push(Arc::downgrade(&t));
    t
}

/// fork(2)/vfork(2): duplicate the current process. The child resumes in
/// user mode from `frame` with a return value of 0. Returns the child.
pub fn fork(frame: &TrapFrame, vfork: bool) -> Result<Arc<Process>, Errno> {
    fork_with(frame, vfork, 0, false, false)
}

/// fork(2) with clone(2)'s `CLONE_NEW*` flags: the child starts in new
/// namespaces of those kinds.
/// `share_fs` (clone(CLONE_FS)): the child shares the parent's root and
/// working directory instead of copying them.
pub fn fork_with(
    frame: &TrapFrame,
    vfork: bool,
    ns_flags: u64,
    share_files: bool,
    share_fs: bool,
) -> Result<Arc<Process>, Errno> {
    let parent = current().ok_or(ESRCH)?;
    let (child_ns, child_cred) = if ns_flags & ns::ALL != 0 {
        let u = parent.namespaces().unshare(ns_flags, &parent.cred(), &parent.cgroup())?;
        (u.ns, u.cred)
    } else {
        (parent.namespaces(), None)
    };
    let cgroup = parent.cgroup();
    if !crate::fs::cgroup::may_fork(&cgroup) || !may_add_task(&parent) {
        return Err(EAGAIN);
    }
    // A PID namespace whose init has exited takes no new processes.
    if child_ns.pid_for_children.init.load(Ordering::Acquire) == ns::PID_NS_DEAD {
        return Err(ENOMEM);
    }
    // A vfork child of a single-threaded parent runs in the parent's own
    // memory (CLONE_VM): the parent is blocked until the child execs or
    // exits, so the address space moves to the child and back. Otherwise
    // the child gets a copy-on-write copy (a GAP for CLONE_VM then).
    let borrow = vfork && parent.threads().len() == 1;
    let child_space = if borrow {
        let space = parent.aspace.lock().take().ok_or(ESRCH)?;
        parent.root.store(paging::kernel_root().0, Ordering::Release);
        space
    } else {
        // Under strict accounting the child's copy is committed too (ADR
        // 0123).
        if crate::mm::commit::strict() {
            let need = parent.aspace.lock().as_ref().map_or(0, |a| a.committed_bytes());
            if !crate::mm::commit::enough(need, false) {
                return Err(ENOMEM);
            }
        }
        let space = {
            let mut g = parent.aspace.lock();
            g.as_mut().ok_or(ESRCH)?.fork().map_err(|_| ENOMEM)?
        };
        // The parent's writable pages just became copy-on-write: no CPU may
        // keep writing them through old translations.
        finish_vm_change(&parent);
        space
    };
    let files = parent.files.lock().clone();
    let cwd = parent.cwd();
    let root_dir = parent.root_dir();
    let child = Process::new(parent.name.lock().clone(), Arc::downgrade(&parent), child_space, files, cwd, root_dir);
    if share_fs {
        child.share_fs_with(&parent);
    }
    child.pgid.store(parent.pgid.load(Ordering::Relaxed), Ordering::Relaxed);
    child.sid.store(parent.sid.load(Ordering::Relaxed), Ordering::Relaxed);
    child.set_umask(parent.umask());
    child.dumpable.store(parent.dumpable.load(Ordering::Relaxed), Ordering::Relaxed);
    child.abi.store(parent.abi.load(Ordering::Relaxed), Ordering::Relaxed);
    child.domain.store(parent.domain.load(Ordering::Relaxed), Ordering::Relaxed);
    child.grant.store(parent.grant.load(Ordering::Relaxed), Ordering::Relaxed);
    child.persona.store(parent.persona.load(Ordering::Relaxed), Ordering::Relaxed);
    child.exe_bias.store(parent.exe_bias.load(Ordering::Relaxed), Ordering::Relaxed);
    child.jit.store(parent.jit.load(Ordering::Relaxed), Ordering::Relaxed);
    child.app.store(parent.app.load(Ordering::Relaxed), Ordering::Relaxed);
    child.keyslots.store(parent.keyslots.load(Ordering::Relaxed), Ordering::Relaxed);
    *child.service.lock() = parent.service.lock().clone();
    *child.box_tag.lock() = parent.box_tag.lock().clone();
    *child.seccomp.lock() = parent.seccomp.lock().clone();
    *child.limits.lock() = parent.limits.lock().clone();
    for i in 0..2 {
        child.cpu_limit_ns[i].store(parent.cpu_limit_ns[i].load(Ordering::Relaxed), Ordering::Relaxed);
    }
    child.oom_score_adj.store(parent.oom_score_adj.load(Ordering::Relaxed), Ordering::Relaxed);
    if share_files && vfork {
        *child.files_back.lock() = Some(Arc::downgrade(&parent));
    }
    if borrow {
        *child.aspace_lender.lock() = Some(Arc::downgrade(&parent));
    }
    *child.cred.lock() = match child_cred {
        Some(c) => Arc::new(c),
        None => parent.cred(),
    };
    child.set_ctty(parent.ctty());
    *child.cmdline.lock() = parent.cmdline.lock().clone();
    *child.exe.lock() = parent.exe.lock().clone();
    child.signals.inherit_from(&parent.signals);
    child.set_cgroup(cgroup);
    // PIDs in the child's PID namespace and each ancestor; the first
    // process in a new namespace is its init (pid_namespaces(7)).
    {
        let mut chain = Vec::new();
        let mut at = Some(child_ns.pid_for_children.clone());
        while let Some(n) = at {
            at = n.parent.clone();
            chain.push(n);
        }
        chain.reverse();
        let pids: Vec<(Arc<ns::PidNs>, Pid)> = chain
            .into_iter()
            .map(|n| {
                let local = if n.level == 0 { child.pid } else { n.alloc() };
                if local == 1 && n.level > 0 {
                    n.init.store(u64::from(child.pid), Ordering::Release);
                }
                (n, local)
            })
            .collect();
        *child.pids.lock() = pids;
    }
    if ns_flags & ns::CLONE_NEWNS != 0 {
        *child_ns.mnt.root.lock() = Some(root_dir_of(&child));
    }
    child.set_namespaces(child_ns);
    parent.children.lock().push(child.clone());

    let mut cframe = frame.clone();
    cframe.rax = 0;
    let user_state = sched::current().arch.fork_state();
    let mask = sched::current().signal_mask();
    // fork keeps the alternate signal stack (sigaltstack(2)); new threads
    // start without one.
    let altstack = *sched::current().altstack.lock();
    // fork keeps the rseq area too (the child's copy is at the same
    // address); new threads register their own (ADR 0115).
    let rseq = *sched::current().rseq.lock();
    // So does the I/O priority (ioprio_set(2)), for threads too.
    let ioprio = sched::current().ioprio.load(Ordering::Relaxed);
    start_thread(&child, u64::from(child.pid), move || {
        let me = sched::current();
        me.ioprio.store(ioprio, Ordering::Relaxed);
        me.arch.adopt(user_state);
        me.set_signal_mask(mask);
        *me.altstack.lock() = altstack;
        *me.rseq.lock() = rseq;
        sched::UserEntry::Return(cframe)
    });
    if vfork {
        child.vfork_done.wait_until(|| child.vfork_released.load(Ordering::Acquire));
    }
    Ok(child)
}

/// RLIMIT_NPROC: may `p` start another thread or process? The limit counts
/// the threads of every process with the caller's real user ID, and does
/// not apply to root or to holders of CAP_SYS_ADMIN or CAP_SYS_RESOURCE
/// (getrlimit(2)).
fn may_add_task(p: &Process) -> bool {
    let c = p.cred();
    let limit = p.rlimit(rlimit::RLIMIT_NPROC).cur;
    if limit == rlimit::RLIM_INFINITY
        || c.ruid == 0
        || c.capable(cred::CAP_SYS_ADMIN)
        || c.capable(cred::CAP_SYS_RESOURCE)
    {
        return true;
    }
    let tasks: usize =
        all().iter().filter(|q| !q.is_zombie() && q.cred().ruid == c.ruid).map(|q| q.threads.lock().len()).sum();
    (tasks as u64) < limit
}

/// Whether any process maps `inode` shared and writable (F_ADD_SEALS's
/// F_SEAL_WRITE is EBUSY then).
pub fn mapped_writable(inode: &Arc<dyn crate::fs::vfs::Inode>) -> bool {
    let id = Arc::as_ptr(inode).cast::<()>();
    all().iter().any(|p| {
        p.aspace.lock().as_ref().is_some_and(|a| {
            a.vmas().any(|v| {
                v.shared && v.prot.write && v.file.as_ref().is_some_and(|f| Arc::as_ptr(&f.inode).cast::<()>() == id)
            })
        })
    })
}

/// Flush stale TLB entries for `p`'s address space on other CPUs running
/// its threads, and on this one.
pub fn shootdown(p: &Process) {
    paging::flush_local();
    // A vfork child running in its parent's address space shares the page
    // tables with the CPU its parent last ran on, which may still have them
    // loaded: that CPU needs the flush as much as another thread's would.
    if p.threads.lock().len() > 1 || p.aspace_lender.lock().is_some() {
        crate::arch::tlb_shootdown(crate::mm::PhysAddr(p.root()));
    }
}

/// clone(2) flags. Source: musl `sched.h` (ADR 0009).
pub const CLONE_VM: u64 = 0x100;
pub const CLONE_FS: u64 = 0x200;
pub const CLONE_FILES: u64 = 0x400;
pub const CLONE_SIGHAND: u64 = 0x800;
pub const CLONE_VFORK: u64 = 0x4000;
pub const CLONE_THREAD: u64 = 0x10000;
pub const CLONE_SETTLS: u64 = 0x80000;
pub const CLONE_PARENT_SETTID: u64 = 0x100000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x200000;
pub const CLONE_CHILD_SETTID: u64 = 0x1000000;

/// Start a new thread in the current process (clone(2) with CLONE_THREAD).
/// It resumes in user mode from `frame` with rax = 0, on stack `stack`.
/// Returns its thread ID.
pub fn clone_thread(frame: &TrapFrame, flags: u64, stack: u64, ptid: u64, ctid: u64, tls: u64) -> Result<u64, Errno> {
    let p = current().ok_or(ESRCH)?;
    // A thread shares everything: these flags must come together.
    let need = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND;
    if flags & need != need {
        return Err(EINVAL);
    }
    if !may_add_task(&p) {
        return Err(EAGAIN);
    }
    let tid = sched::alloc_id();
    // In a PID namespace the thread gets an ID there too (and in each
    // ancestor below the initial one).
    let local: Vec<(Arc<ns::PidNs>, Pid)> =
        p.pids.lock().iter().filter(|(n, _)| n.level > 0).map(|(n, _)| (n.clone(), n.alloc())).collect();
    let seen = local.last().map_or(tid, |(_, l)| u64::from(*l));
    if !local.is_empty() {
        p.thread_ids.lock().push((tid, local));
    }
    if flags & CLONE_PARENT_SETTID != 0 {
        crate::arch::uaccess::write_user(ptid, &(seen as u32)).map_err(|_| EFAULT)?;
    }
    if flags & CLONE_CHILD_SETTID != 0 {
        crate::arch::uaccess::write_user(ctid, &(seen as u32)).map_err(|_| EFAULT)?;
    }
    let mut cframe = frame.clone();
    cframe.rax = 0;
    if stack != 0 {
        cframe.rsp = stack;
    }
    let mut user_state = sched::current().arch.fork_state();
    if flags & CLONE_SETTLS != 0 {
        user_state.set_fs_base(tls);
    }
    let mask = sched::current().signal_mask();
    let clear = if flags & CLONE_CHILD_CLEARTID != 0 { ctid } else { 0 };
    let ns = sched::current().ns.lock().clone();
    let cred = sched::current().cred.lock().clone();
    let fs = sched::current().fs.lock().clone();
    let ioprio = sched::current().ioprio.load(Ordering::Relaxed);
    start_thread(&p, tid, move || {
        let me = sched::current();
        me.ioprio.store(ioprio, Ordering::Relaxed);
        *me.ns.lock() = ns;
        *me.cred.lock() = cred;
        *me.fs.lock() = fs;
        me.arch.adopt(user_state);
        me.set_signal_mask(mask);
        me.clear_child_tid.store(clear, Ordering::Relaxed);
        sched::UserEntry::Return(cframe)
    });
    Ok(seen)
}

/// Ask every other thread of `p` to exit, and wait until they have.
fn kill_other_threads(p: &Arc<Process>) {
    let me = sched::current();
    for t in p.threads() {
        if !Arc::ptr_eq(&t, &me) {
            t.exit_requested.store(true, Ordering::Release);
            sched::wake(&t);
        }
    }
    p.exited.wait_until(|| p.threads.lock().iter().filter(|w| w.strong_count() > 0).count() <= 1);
}

/// Give a CLONE_VFORK | CLONE_FILES parent the child's descriptor table.
fn hand_back_files(p: &Process) {
    if let Some(parent) = p.files_back.lock().take().and_then(|w| w.upgrade()) {
        let table = p.files.lock().clone();
        *parent.files.lock() = table;
    }
}

/// Return a borrowed address space (vfork) to the parent; `None` if it
/// wasn't borrowed (the caller frees it).
fn return_aspace(
    p: &Process,
    space: Option<crate::mm::aspace::AddressSpace>,
) -> Option<crate::mm::aspace::AddressSpace> {
    if let Some(s) = &space {
        p.cpu.maxrss_pages.fetch_max(s.peak_pages(), Ordering::Relaxed);
    }
    let lender = p.aspace_lender.lock().take().and_then(|w| w.upgrade());
    match (lender, space) {
        (Some(parent), Some(space)) => {
            parent.root.store(space.root().0, Ordering::Release);
            *parent.aspace.lock() = Some(space);
            None
        }
        (_, space) => space,
    }
}

fn release_vfork(p: &Process) {
    p.vfork_released.store(true, Ordering::Release);
    p.vfork_done.wake_all();
}

/// execve(2) for the current process: replace its image. Only returns on
/// failure; on success the thread continues at the new entry point.
pub fn execve(path: &[u8], argv: &[&[u8]], envp: &[&[u8]]) -> Result<exec::Image, Errno> {
    let Some(cwd) = current().map(|p| p.cwd()) else { return Err(ESRCH) };
    execve_at(&cwd, path, argv, envp)
}

/// Start the image a successful execve loaded: the system call returns
/// into it through `frame`.
pub fn begin_image(frame: &mut TrapFrame, image: exec::Image) {
    sched::current().arch.init_user();
    syscall::begin_image(frame, image.entry, image.stack_pointer);
}

/// execve with relative paths resolved from `cwd` (execveat(2)); an empty
/// path executes `cwd` itself (AT_EMPTY_PATH: the caller checked the flag).
/// Returns the new image, for [`begin_image`] (the caller's system call
/// returns into it: nothing on the kernel stack is left behind).
pub fn execve_at(cwd: &Arc<Dentry>, path: &[u8], argv: &[&[u8]], envp: &[&[u8]]) -> Result<exec::Image, Errno> {
    let Some(p) = current() else { return Err(ESRCH) };
    let cwd = cwd.clone();
    let path = if path.is_empty() { b"." } else { path };
    let root_dir = p.root_dir();
    let loaded = match exec::load_path(&root_dir, &cwd, path, argv, envp, &p.cred()) {
        Ok(l) => l,
        // Linux programs never see Slate's own error code.
        Err(e) if e == domain::LINUX_OFF && p.abi() != Abi::Native => return Err(EACCES),
        Err(e) => return Err(e),
    };
    // Point of no return: the other threads go, then the old image.
    kill_other_threads(&p);
    p.adopt_thread_namespaces();
    let new_root = loaded.aspace.root();
    // Publish the new root before the old tables go (see
    // sched::wait_root_unused, which AddressSpace's drop calls).
    p.root.store(new_root.0, Ordering::SeqCst);
    sched::switch_root(new_root);
    let old = p.aspace.lock().replace(loaded.aspace);
    drop(return_aspace(&p, old));
    hand_back_files(&p);
    p.files.lock().close_on_exec();
    // Into the Linux domain: what must stay in the Slate one does (ADR 0098).
    if p.domain() == domain::Domain::Slate && loaded.domain == domain::Domain::Linux {
        let closed = p.files.lock().close_for_linux();
        if closed > 0 {
            domain::log_kept_back(&loaded.path, closed);
        }
    }
    p.signals.reset_on_exec();
    *sched::current().altstack.lock() = (0, 0, sched::ALTSTACK_DISABLED);
    *sched::current().rseq.lock() = None;
    // A program that changed the IDs or gave capabilities makes the
    // process not dumpable; any other makes it dumpable again (prctl(2)).
    let old = p.cred();
    let gained = loaded.cred.cap_permitted & !old.cap_permitted != 0;
    let set_id = (old.euid, old.egid) != (loaded.cred.euid, loaded.cred.egid);
    p.set_cred_all(loaded.cred);
    p.dumpable.store(!set_id && !gained, Ordering::Relaxed);
    p.set_argv(&loaded.argv, &loaded.path, loaded.exe);
    p.set_abi(loaded.abi);
    p.set_domain(loaded.domain);
    p.grant.store(loaded.grant, Ordering::Relaxed);
    p.persona.store(loaded.persona, Ordering::Relaxed);
    p.exe_bias.store(loaded.image.bias, Ordering::Relaxed);
    p.jit.store(loaded.jit, Ordering::Relaxed);
    p.app.store(loaded.app, Ordering::Relaxed);
    p.keyslots.store(loaded.keyslots, Ordering::Relaxed);
    release_vfork(&p);
    Ok(loaded.image)
}

/// Arm ITIMER_REAL: SIGALRM after `value_ns` (0 disarms), then every
/// `interval_ns`. Returns the old (remaining, interval) in ns.
pub fn set_real_timer(p: &Arc<Process>, value_ns: u64, interval_ns: u64) -> (u64, u64) {
    let now = crate::time::monotonic_ns();
    let mut t = p.real_timer.lock();
    let old = (t.deadline.map_or(0, |d| d.saturating_sub(now).max(1)), t.interval);
    if let Some(id) = t.pending.take() {
        crate::time::cancel_timer(id);
    }
    t.generation += 1;
    t.interval = interval_ns;
    t.deadline = (value_ns != 0).then(|| now + value_ns);
    if let Some(d) = t.deadline {
        t.pending = Some(arm_real_timer(Arc::downgrade(p), d, t.generation));
    }
    old
}

/// Current ITIMER_REAL (remaining, interval) in ns.
pub fn real_timer(p: &Process) -> (u64, u64) {
    let t = p.real_timer.lock();
    (t.deadline.map_or(0, |d| d.saturating_sub(crate::time::monotonic_ns()).max(1)), t.interval)
}

fn arm_real_timer(p: Weak<Process>, at: u64, generation: u64) -> crate::time::TimerId {
    crate::time::add_timer(at, move || {
        let Some(proc) = p.upgrade() else { return };
        {
            let mut t = proc.real_timer.lock();
            if t.generation != generation {
                return;
            }
            if t.interval > 0 {
                let next = at + t.interval;
                t.deadline = Some(next);
                t.pending = Some(arm_real_timer(Arc::downgrade(&proc), next, generation));
            } else {
                t.deadline = None;
                t.pending = None;
            }
        }
        signal::send_to_process(&proc, signal::SIGALRM);
    })
}

/// Options for [`wait_child`] (wait4(2)). Source: musl `sys/wait.h`.
pub const WNOHANG: u32 = 1;
pub const WUNTRACED: u32 = 2;
pub const WCONTINUED: u32 = 8;
/// waitid(2): leave the child waitable (report without reaping).
pub const WNOWAIT: u32 = 0x0100_0000;

/// Wait status of a process stopped by `sig` (WIFSTOPPED/WSTOPSIG).
pub fn wait_status_stopped(sig: u32) -> i32 {
    ((sig as i32) << 8) | 0x7F
}

/// Wait status of a continued process (WIFCONTINUED).
pub const WAIT_STATUS_CONTINUED: i32 = 0xFFFF;

/// Stop the current process for signal `sig` until SIGCONT or SIGKILL
/// (signal(7), "Stop"), telling the parent.
pub fn stop_current(sig: u32) {
    let Some(p) = current() else { return };
    {
        let mut j = p.job.lock();
        j.stopped = true;
        j.report = Some(wait_status_stopped(sig));
    }
    notify_parent_of_job_change(&p);
    // The other threads stop when they next come by `deliver`.
    for t in p.threads() {
        sched::wake(&t);
    }
    wait_while_stopped(&p);
}

/// Block the current thread while `p` is stopped (until SIGCONT, SIGKILL or
/// an exit request).
pub fn wait_while_stopped(p: &Arc<Process>) {
    p.continued
        .wait_until(|| !p.job.lock().stopped || p.signals.pending() & signal::bit(signal::SIGKILL) != 0 || must_exit());
}

/// Resume a stopped process (SIGCONT).
pub fn continue_process(p: &Arc<Process>) {
    let was_stopped = {
        let mut j = p.job.lock();
        let was = j.stopped;
        if was {
            j.stopped = false;
            j.report = Some(WAIT_STATUS_CONTINUED);
        }
        was
    };
    if was_stopped {
        p.continued.wake_all();
        notify_parent_of_job_change(p);
    }
}

fn notify_parent_of_job_change(p: &Arc<Process>) {
    if let Some(parent) = p.parent() {
        // SA_NOCLDSTOP (sigaction(2)) suppresses SIGCHLD for stops/continues.
        if parent.signals.action(signal::SIGCHLD).flags & 1 == 0 {
            signal::send_to_process(&parent, signal::SIGCHLD);
        }
        parent.child_event.wake_all();
    }
    crate::fs::poll_notify();
}

/// Whether process group `pgid` is orphaned: no member has a parent in a
/// different group of the same session (POSIX.1-2017 XBD 3.296).
pub fn is_orphaned_pgrp(pgid: Pid) -> bool {
    all().iter().filter(|p| p.pgid.load(Ordering::Relaxed) == pgid && !p.is_zombie()).all(|p| {
        p.parent().is_none_or(|q| {
            q.pgid.load(Ordering::Relaxed) == pgid || q.sid.load(Ordering::Relaxed) != p.sid.load(Ordering::Relaxed)
        })
    })
}

/// When a group becomes orphaned with stopped members, POSIX requires
/// SIGHUP then SIGCONT so they are not stuck forever.
fn hangup_orphaned(pgids: &[Pid]) {
    for &g in pgids {
        let stopped = all().iter().any(|p| p.pgid.load(Ordering::Relaxed) == g && p.is_stopped());
        if stopped && is_orphaned_pgrp(g) {
            signal::send_to_group(g, signal::SIGHUP);
            signal::send_to_group(g, signal::SIGCONT);
        }
    }
}

/// Which children wait4(2) may collect.
#[derive(Clone, Copy, Debug)]
pub enum WaitFor {
    Any,
    Pid(Pid),
    Group(Pid),
}

/// What getrusage(2) counts besides CPU time, for a thread or a
/// process: page faults without and with I/O, 512-byte blocks read and
/// written on the thread's own behalf, and context switches made by
/// blocking and by preemption.
#[derive(Debug, Default)]
pub struct Counts {
    pub minflt: AtomicU64,
    pub majflt: AtomicU64,
    pub inblock: AtomicU64,
    pub oublock: AtomicU64,
    pub nvcsw: AtomicU64,
    pub nivcsw: AtomicU64,
    /// Bytes through read and write calls, and the calls (proc(5)'s
    /// /proc/PID/io: rchar, wchar, syscr, syscw; not getrusage's).
    pub rchar: AtomicU64,
    pub wchar: AtomicU64,
    pub syscr: AtomicU64,
    pub syscw: AtomicU64,
}

impl Counts {
    /// [minflt, majflt, inblock, oublock, nvcsw, nivcsw].
    pub fn get(&self) -> [u64; 6] {
        [&self.minflt, &self.majflt, &self.inblock, &self.oublock, &self.nvcsw, &self.nivcsw]
            .map(|c| c.load(Ordering::Relaxed))
    }

    fn add(&self, v: [u64; 6]) {
        let all = [&self.minflt, &self.majflt, &self.inblock, &self.oublock, &self.nvcsw, &self.nivcsw];
        for (c, n) in all.into_iter().zip(v) {
            c.fetch_add(n, Ordering::Relaxed);
        }
    }
}

/// One getrusage(2) answer: CPU time in nanoseconds, the largest resident
/// set in pages and the [`Counts`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Usage {
    pub user: u64,
    pub system: u64,
    pub maxrss_pages: u64,
    pub counts: [u64; 6],
}

/// CPU time in nanoseconds (getrusage(2), times(2)), and the rest of what
/// getrusage counts.
#[derive(Debug, Default)]
pub struct CpuTimes {
    pub user: AtomicU64,
    pub system: AtomicU64,
    /// Totals of the waited-for children (and, recursively, theirs).
    pub children_user: AtomicU64,
    pub children_system: AtomicU64,
    pub counts: Counts,
    pub children_counts: Counts,
    /// The largest resident set of the address spaces it left behind
    /// (exec, exit), in pages; the current one's is its own peak.
    pub maxrss_pages: AtomicU64,
    /// The largest of the waited-for children's (and theirs).
    pub children_maxrss_pages: AtomicU64,
}

impl CpuTimes {
    /// (user, system) of the process itself.
    pub fn own(&self) -> (u64, u64) {
        (self.user.load(Ordering::Relaxed), self.system.load(Ordering::Relaxed))
    }

    /// (user, system) of the waited-for children.
    pub fn children(&self) -> (u64, u64) {
        (self.children_user.load(Ordering::Relaxed), self.children_system.load(Ordering::Relaxed))
    }

    /// (user, system) of the process and its waited-for children: what its
    /// parent collects when it waits for it.
    pub fn total(&self) -> (u64, u64) {
        let ((u, s), (cu, cs)) = (self.own(), self.children());
        (u + cu, s + cs)
    }

    /// The waited-for children's usage (RUSAGE_CHILDREN).
    pub fn children_usage(&self) -> Usage {
        let (user, system) = self.children();
        Usage {
            user,
            system,
            maxrss_pages: self.children_maxrss_pages.load(Ordering::Relaxed),
            counts: self.children_counts.get(),
        }
    }

    /// A process that exited, with its waited-for children: what its
    /// parent collects (wait4(2)) and adds to its children's.
    fn total_usage(&self) -> Usage {
        let (user, system) = self.total();
        let (own, children) = (self.counts.get(), self.children_counts.get());
        Usage {
            user,
            system,
            maxrss_pages: self
                .maxrss_pages
                .load(Ordering::Relaxed)
                .max(self.children_maxrss_pages.load(Ordering::Relaxed)),
            counts: core::array::from_fn(|i| own[i] + children[i]),
        }
    }

    fn add_child(&self, u: &Usage) {
        self.children_user.fetch_add(u.user, Ordering::Relaxed);
        self.children_system.fetch_add(u.system, Ordering::Relaxed);
        self.children_counts.add(u.counts);
        self.children_maxrss_pages.fetch_max(u.maxrss_pages, Ordering::Relaxed);
    }
}

/// wait4(2) for the current process. Returns (pid in the caller's PID
/// namespace, status, what a reaped child used), or pid 0 with WNOHANG
/// when no child has exited yet. Stopped and
/// continued children report no time. With WNOWAIT an exited child is
/// reported and stays waitable.
pub fn wait_child(which: WaitFor, options: u32) -> Result<(Pid, i32, Usage), Errno> {
    let me = current().ok_or(ESRCH)?;
    loop {
        let found = {
            let children = me.children.lock();
            let matching: Vec<&Arc<Process>> = children
                .iter()
                .filter(|c| match which {
                    WaitFor::Any => true,
                    WaitFor::Pid(p) => c.pid == p,
                    WaitFor::Group(g) => c.pgid.load(Ordering::Relaxed) == g,
                })
                .collect();
            if matching.is_empty() {
                return Err(ECHILD);
            }
            if let Some(c) = matching.iter().find(|c| c.is_zombie()) {
                Some((*c).clone())
            } else {
                // Stopped or continued children, when asked for (WUNTRACED,
                // WCONTINUED).
                let reported = matching.iter().find_map(|c| {
                    let mut j = c.job.lock();
                    let wanted = match j.report {
                        Some(WAIT_STATUS_CONTINUED) => options & WCONTINUED != 0,
                        Some(_) => options & WUNTRACED != 0,
                        None => false,
                    };
                    if wanted { j.report.take().map(|s| (c.pid_in(&me.pid_ns()).unwrap_or(0), s)) } else { None }
                });
                if let Some((pid, status)) = reported {
                    return Ok((pid, status, Usage::default()));
                }
                None
            }
        };
        if let Some(c) = found {
            let status = c.status.lock().unwrap();
            if options & WNOWAIT != 0 {
                return Ok((c.pid_in(&me.pid_ns()).unwrap_or(0), status, Usage::default()));
            }
            me.children.lock().retain(|x| !Arc::ptr_eq(x, &c));
            TABLE.lock().remove(&c.pid);
            let used = c.cpu.total_usage();
            me.cpu.add_child(&used);
            return Ok((c.pid_in(&me.pid_ns()).unwrap_or(0), status, used));
        }
        if options & WNOHANG != 0 {
            return Ok((0, 0, Usage::default()));
        }
        // Wake for what this call would report: a matching child that
        // exited, or one whose stop or continue it asked for. Counting
        // other reports would spin here (a child stopped while its parent
        // waits without WUNTRACED), never seeing the caller's own signals.
        let interrupted = me.child_event.wait_until_interruptible(|| {
            me.children.lock().iter().any(|c| {
                let matches = match which {
                    WaitFor::Any => true,
                    WaitFor::Pid(p) => c.pid == p,
                    WaitFor::Group(g) => c.pgid.load(Ordering::Relaxed) == g,
                };
                matches
                    && (c.is_zombie()
                        || match c.job.lock().report {
                            Some(WAIT_STATUS_CONTINUED) => options & WCONTINUED != 0,
                            Some(_) => options & WUNTRACED != 0,
                            None => false,
                        })
            })
        });
        if interrupted {
            return Err(signal::ERESTARTSYS);
        }
    }
}

/// Remove a kernel-started (parentless) process from the table once the
/// kernel has collected its status.
pub fn reap(p: &Arc<Process>) {
    TABLE.lock().remove(&p.pid);
}

/// Demand paging and copy-on-write for the current process. Returns true
/// if the fault was resolved and the access should be retried.
pub fn handle_page_fault(addr: u64, write: bool, exec: bool, from_user: bool) -> bool {
    if !sched::started() {
        return false;
    }
    let Some(p) = current() else { return false };
    use crate::mm::aspace::Fault;
    let result = {
        let mut guard = p.aspace.lock();
        guard.as_mut().map_or(Fault::Bad, |a| a.handle_fault(addr, write, exec))
    };
    // Out of memory: retried once memory was found (the killer may have
    // chosen this process: its SIGKILL is then delivered before the
    // retry). A kernel access for a dying process fails instead (EFAULT).
    let no_memory = || {
        let freed = oom::out_of_memory(&p);
        let dying = must_exit() || p.signals.pending() & signal::bit(signal::SIGKILL) != 0;
        freed && (from_user || !dying)
    };
    let me = sched::current();
    match result {
        Fault::Bad => false,
        Fault::NoMemory => no_memory(),
        Fault::Fixed => {
            me.count(|c| &c.minflt, 1);
            true
        }
        Fault::FixedReplaced => {
            me.count(|c| &c.minflt, 1);
            finish_vm_change(&p);
            true
        }
        Fault::NeedsFlush => {
            finish_vm_change(&p);
            true
        }
        // Reading the file may sleep (disk I/O, the file system's lock), so
        // it happens without the address-space lock. It is a major fault
        // if the thread read the disk for it.
        Fault::NeedsFile { page, file, shared } => {
            let read = me.counts.inblock.load(Ordering::Relaxed);
            let f = if shared { file.shared_page() } else { file.read_page() };
            let major = me.counts.inblock.load(Ordering::Relaxed) != read;
            me.count(if major { |c| &c.majflt } else { |c| &c.minflt }, 1);
            let Some(f) = f else { return !shared && no_memory() };
            let mapped = p.aspace.lock().as_mut().is_some_and(|a| a.install_file_page(page, f, &file));
            if !mapped {
                crate::mm::frame::put_user_page(f);
            }
            true
        }
    }
}

/// After page-table changes in `p` (unmap, protect, copy-on-write): flush
/// stale translations everywhere, then free the frames that were unmapped.
/// Call with no address-space lock held.
pub fn finish_vm_change(p: &Process) {
    let covered = p.aspace.lock().as_ref().map_or(0, |a| a.removals);
    shootdown(p);
    let frames = p
        .aspace
        .lock()
        .as_mut()
        .map(|a| {
            a.flushed = a.flushed.max(covered);
            a.take_pending_free(covered)
        })
        .unwrap_or_default();
    for f in frames {
        crate::mm::frame::put_user_page(f);
    }
}

/// Create mappings in `p`'s address space with `f` once every shootdown
/// another thread began is finished, so no CPU still holds translations for
/// addresses about to be reused. The check and `f` run under one lock:
/// checking first and mapping after let another thread's munmap free a
/// range in between, and a new mapping placed there could be written
/// through a stale translation of the old one. `None`: no address space.
pub fn with_settled_vm<R>(p: &Process, f: impl FnOnce(&mut AddressSpace) -> R) -> Option<R> {
    let mut f = Some(f);
    loop {
        {
            let mut g = p.aspace.lock();
            let a = g.as_mut()?;
            if a.removals == a.flushed {
                return f.take().map(|f| f(a));
            }
        }
        finish_vm_change(p);
    }
}

/// A user-mode exception: queue the signal Linux would deliver (SIGSEGV,
/// SIGILL, SIGFPE, SIGTRAP). It is delivered on the way back to user mode.
pub fn user_exception(vector: u64, error: u64, rip: u64, rsp: u64, addr: u64) {
    use signal::*;
    let sig = match vector {
        0 => SIGFPE,
        6 => SIGILL,
        3 | 1 => SIGTRAP,
        16 | 19 => SIGFPE,
        _ => SIGSEGV,
    };
    // si_code and si_addr (sigaction(2)): page faults report the address
    // and whether anything is mapped there (SEGV_ACCERR: mapped, but not
    // for this access); #DE and #UD report the instruction.
    let mapped = |a: u64| current().is_some_and(|p| p.aspace.lock().as_ref().is_some_and(|s| s.find(a).is_some()));
    let (code, addr) = match vector {
        14 => (if mapped(addr) { SEGV_ACCERR } else { SEGV_MAPERR }, addr),
        0 => (FPE_INTDIV, rip),
        6 => (ILL_ILLOPN, rip),
        _ => (SI_KERNEL, 0),
    };
    if let Some(p) = current() {
        let fatal_default = !p.signals.has_handler(sig);
        if fatal_default {
            log_warn!(
                "pid {} ({}): {} at rip {rip:#x}, address {addr:#x}, error {error:#x}",
                p.pid,
                *p.name.lock(),
                signal_name(sig)
            );
            // The top of the stack (return addresses among it) says where
            // the fault came from.
            let mut words = [0u64; 8];
            let mut stack = String::new();
            for (i, w) in words.iter_mut().enumerate() {
                match crate::arch::uaccess::read_user::<u64>(rsp + 8 * i as u64) {
                    Ok(v) => *w = v,
                    Err(_) => break,
                }
                let _ = core::fmt::Write::write_fmt(&mut stack, format_args!(" {:#x}", *w));
            }
            log_warn!("pid {}: rsp {rsp:#x}, {} threads, stack:{stack}", p.pid, p.threads().len());
        }
    }
    signal::force_signal(sig, code, addr);
}

/// After a fatal user fault (logged by `user_exception`): the registers,
/// and for each that points into the address space its physical frame and
/// the 32 bytes before and after, to tell what the faulting code read.
pub fn log_fault_registers(regs: &[(&str, u64)]) {
    let Some(p) = current() else { return };
    if p.signals.has_handler(signal::SIGSEGV) {
        return;
    }
    let mut line = String::new();
    for (name, v) in regs {
        let _ = core::fmt::Write::write_fmt(&mut line, format_args!(" {name}={v:#x}"));
    }
    log_warn!("pid {}:{line}", p.pid);
    log_warn!(
        "pid {}: on CPU {}, cr3 {:#x}, root {:#x}, shootdowns (requested, served) {:?}",
        p.pid,
        crate::arch::cpu_id(),
        crate::arch::cpu::read_cr3(),
        p.root(),
        crate::arch::tlb_counters()
    );
    for &(name, v) in regs {
        if !(0x1000..0x8000_0000_0000).contains(&v) {
            continue;
        }
        let at = (v & !7).saturating_sub(32);
        let phys = p.aspace.lock().as_ref().and_then(|a| a.translate(v)).map_or(0, |f| f.0);
        let flags = p.aspace.lock().as_ref().and_then(|a| a.leaf_flags(v));
        let mut words = String::new();
        for i in 0..8 {
            match crate::arch::uaccess::read_user::<u64>(at + 8 * i) {
                Ok(w) => {
                    let _ = core::fmt::Write::write_fmt(&mut words, format_args!(" {w:#x}"));
                }
                Err(_) => words.push_str(" ?"),
            }
        }
        // The word itself, read through this CPU's translation and through
        // the frame the page table names: a difference is a stale TLB.
        let via_tlb = crate::arch::uaccess::read_user::<u64>(v & !7).ok();
        let via_frame = (phys != 0).then(|| {
            // SAFETY: `phys` is a mapped user frame of this process (the
            // page table says so); the direct map covers it.
            unsafe { ((crate::mm::PhysAddr(phys & !7)).to_virt() as *const u64).read_volatile() }
        });
        log_warn!(
            "pid {}: {name} {v:#x} (frame {phys:#x} {flags:?}; word via TLB {via_tlb:x?}, via frame {via_frame:x?}), from {at:#x}:{words}",
            p.pid
        );
    }
}

/// End the current thread (exit(2)). The last thread out ends the process
/// with `status`, unless a group exit set another one.
pub fn exit_thread(status: i32) -> ! {
    let p = current().expect("exit without a process");
    let me = sched::current();
    // PI futexes it owns go to their waiters; robust locks it holds are
    // marked as their owner having died.
    if p.aspace.lock().is_some() {
        futex::exit_thread(&p);
    }
    // CLONE_CHILD_CLEARTID: zero the TID word and wake a joiner
    // (set_tid_address(2)).
    let ctid = me.clear_child_tid.swap(0, Ordering::Relaxed);
    if ctid != 0 && p.aspace.lock().is_some() {
        let _ = crate::arch::uaccess::write_user(ctid, &0u32);
        futex::wake_address(&p, ctid, 1);
    }
    let last = {
        let mut list = p.threads.lock();
        list.retain(|w| w.upgrade().is_some_and(|t| !Arc::ptr_eq(&t, &me)));
        list.is_empty()
    };
    p.thread_ids.lock().retain(|(t, _)| *t != me.tid);
    p.exited.wake_all();
    drop(me);
    if last {
        let status = p.exiting().unwrap_or(status);
        finish_process(p, status);
    } else {
        drop(p);
    }
    sched::exit()
}

/// Terminate the whole process (exit_group(2), fatal signals): every
/// thread leaves; the process ends with wait status `status`.
pub fn exit_current(status: i32) -> ! {
    let p = current().expect("exit without a process");
    let status = {
        let mut g = p.group_exit.lock();
        *g.get_or_insert(status)
    };
    let me = sched::current();
    for t in p.threads() {
        if !Arc::ptr_eq(&t, &me) {
            t.exit_requested.store(true, Ordering::Release);
            sched::wake(&t);
        }
    }
    drop(me);
    drop(p);
    exit_thread(status)
}

/// Tear down a process whose last thread just left.
fn finish_process(p: Arc<Process>, status: i32) {
    // Leave the address space before freeing it; CPUs still on it (other
    // threads of the process, leaving) are waited for when it is dropped.
    p.root.store(paging::kernel_root().0, Ordering::SeqCst);
    sched::switch_root(paging::kernel_root());
    let aspace = p.aspace.lock().take();
    drop(return_aspace(&p, aspace));
    hand_back_files(&p);
    p.files.lock().close_all();
    release_vfork(&p);

    // A session leader's exit hangs up its terminal (credentials(7)).
    if p.sid.load(Ordering::Relaxed) == p.pid
        && let Some(t) = p.ctty()
        && t.session() == p.pid
    {
        t.hangup();
    }
    p.set_ctty(None);
    let mut affected: Vec<Pid> = p.children.lock().iter().map(|c| c.pgid.load(Ordering::Relaxed)).collect();
    affected.push(p.pgid.load(Ordering::Relaxed));

    // The init of a PID namespace takes every other process in it along
    // (pid_namespaces(7)); no process can enter it afterwards.
    let pns = p.pid_ns();
    let ns_init = pns.init.load(Ordering::Acquire);
    if pns.level > 0 && ns_init == u64::from(p.pid) {
        pns.init.store(ns::PID_NS_DEAD, Ordering::Release);
        for q in all() {
            if q.pid != p.pid && q.pid_in(&pns).is_some() && !q.is_zombie() {
                signal::send_to_process(&q, signal::SIGKILL);
            }
        }
    }
    // Orphans go to the nearest living subreaper ancestor in the same PID
    // namespace, else the init of their PID namespace (or of the nearest
    // one still alive), which reaps them. They get their parent-death
    // signal (PR_SET_PDEATHSIG).
    let orphans: Vec<Arc<Process>> = core::mem::take(&mut *p.children.lock());
    if !orphans.is_empty() {
        for c in &orphans {
            let s = c.pdeath_signal.load(Ordering::Relaxed);
            if s != 0 && !c.is_zombie() {
                signal::send_to_process(c, s);
            }
        }
        let mut reaper = 0;
        let mut anc = p.parent();
        while let Some(a) = anc {
            if a.pid_in(&pns).is_none() {
                break;
            }
            if a.subreaper.load(Ordering::Relaxed) && !a.is_zombie() {
                reaper = a.pid;
                break;
            }
            anc = a.parent();
        }
        let mut at = Some(pns);
        while let Some(n) = at.filter(|_| reaper == 0) {
            let i = n.init.load(Ordering::Acquire);
            if n.level == 0 || (i != ns::PID_NS_DEAD && i != 0 && i != u64::from(p.pid)) {
                reaper = if n.level == 0 { 1 } else { i as Pid };
                break;
            }
            at = n.parent.clone();
        }
        let init = get(reaper).filter(|i| !Arc::ptr_eq(i, &p) && !i.is_zombie());
        for c in orphans {
            match &init {
                Some(i) => {
                    *c.parent.lock() = Arc::downgrade(i);
                    let zombie = c.is_zombie();
                    i.children.lock().push(c);
                    if zombie {
                        // An orphan that has already ended is announced to
                        // its new reaper as its ending would have been
                        // (prctl(2), PR_SET_CHILD_SUBREAPER: the reaper
                        // "will receive a SIGCHLD"); a reaper waiting for
                        // the signal would otherwise never collect it.
                        signal::send_to_process(i, signal::SIGCHLD);
                        i.child_event.wake_all();
                    }
                }
                None => {
                    *c.parent.lock() = Weak::new();
                    if c.is_zombie() {
                        TABLE.lock().remove(&c.pid);
                    }
                }
            }
        }
    }

    *p.status.lock() = Some(status);
    affected.sort_unstable();
    affected.dedup();
    hangup_orphaned(&affected);
    crate::log_debug!("pid {} ({}) exited with status {status:#x}", p.pid, *p.name.lock());
    p.exited.wake_all();
    match p.parent() {
        Some(parent) => {
            signal::send_to_process(&parent, signal::SIGCHLD);
            parent.child_event.wake_all();
        }
        None => {
            TABLE.lock().remove(&p.pid);
        }
    }
    crate::fs::poll_notify();
}

/// Whether the current thread must exit now (exit_group by another thread,
/// a fatal signal, or another thread's execve).
pub fn must_exit() -> bool {
    let t = sched::current();
    t.exit_requested.load(Ordering::Acquire) || t.process.as_ref().is_some_and(|p| p.exiting().is_some())
}

/// The most refusals logged for one process of a Linux box.
const BOX_REFUSALS_LOGGED: u32 = 16;

/// A system call `call` refused (`e`, EPERM or EACCES) to the calling
/// process: logged with its box when it runs in one (ADR 0183's phase 5:
/// what a box's programs try and are refused is on the record), the first
/// few of each process.
pub fn note_box_refusal(call: &str, e: crate::abi::linux::errno::Errno) {
    let Some(p) = current() else { return };
    let Some(tag) = p.box_tag.lock().clone() else { return };
    let n = p.box_refusals.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if n >= BOX_REFUSALS_LOGGED {
        return;
    }
    let name = p.name.lock().clone();
    let what = if e == crate::abi::linux::errno::EPERM { "EPERM" } else { "EACCES" };
    crate::log_warn!("box {tag}: {name} (pid {}) refused {call} ({what})", p.pid);
    if n + 1 == BOX_REFUSALS_LOGGED {
        crate::log_warn!("box {tag}: pid {}: its further refusals aren't logged", p.pid);
    }
}
