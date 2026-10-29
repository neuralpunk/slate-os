// SPDX-License-Identifier: MIT OR Apache-2.0

//! POSIX signals (signal(7)): dispositions, masks, pending sets, delivery
//! through an `rt_sigframe` on the user stack, and sigreturn.
//!
//! Signal numbers and default actions are from signal(7); flag values and
//! the `ucontext_t`/`mcontext_t` layout from musl's `signal.h` and
//! `bits/signal.h` (ADR 0009). The kernel-side `sigaction` layout is
//! musl's `struct k_sigaction` (handler, flags, restorer, mask).

use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use super::{Process, current, exit_current, wait_status_signaled};
use crate::abi::linux::errno::{EFAULT, EINTR, Errno};
use crate::arch::trap::TrapFrame;
use crate::arch::uaccess::{copy_from_user, copy_to_user, read_user, write_user};
use crate::sched;
use crate::sync::IrqSpinLock;

// The full table from signal(7); not every signal has a kernel source yet.
#[allow(dead_code)]
pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGQUIT: u32 = 3;
pub const SIGILL: u32 = 4;
pub const SIGTRAP: u32 = 5;
pub const SIGABRT: u32 = 6;
pub const SIGBUS: u32 = 7;
pub const SIGFPE: u32 = 8;
pub const SIGKILL: u32 = 9;
#[allow(dead_code)]
pub const SIGUSR1: u32 = 10;
pub const SIGSEGV: u32 = 11;
#[allow(dead_code)]
pub const SIGUSR2: u32 = 12;
pub const SIGPIPE: u32 = 13;
#[allow(dead_code)]
pub const SIGALRM: u32 = 14;
#[allow(dead_code)]
pub const SIGTERM: u32 = 15;
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;
pub const SIGSTOP: u32 = 19;
pub const SIGTSTP: u32 = 20;
pub const SIGTTIN: u32 = 21;
pub const SIGTTOU: u32 = 22;
pub const SIGURG: u32 = 23;
pub const SIGXCPU: u32 = 24;
pub const SIGXFSZ: u32 = 25;
pub const SIGWINCH: u32 = 28;
pub const SIGSYS: u32 = 31;
pub const NSIG: u32 = 64;

pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;

pub const SA_RESTART: u64 = 0x1000_0000;
pub const SA_NODEFER: u64 = 0x4000_0000;
pub const SA_RESETHAND: u64 = 0x8000_0000;
pub const SA_RESTORER: u64 = 0x0400_0000;
pub const SA_ONSTACK: u64 = 0x0800_0000;

pub const SIG_BLOCK: u64 = 0;
pub const SIG_UNBLOCK: u64 = 1;
pub const SIG_SETMASK: u64 = 2;

/// Internal "restart this system call" code (never seen by user space): a
/// syscall interrupted by a signal returns it, and delivery turns it into
/// EINTR or a restart per SA_RESTART.
pub const ERESTARTSYS: Errno = Errno(512);
/// Like ERESTARTSYS, but a handler always turns it into EINTR (SA_RESTART
/// does not apply): for sleeps, which must report their interruption.
pub const ERESTARTNOHAND: Errno = Errno(514);

/// Bit for signal `sig` in a sigset.
pub fn bit(sig: u32) -> u64 {
    1 << (sig - 1)
}

const UNBLOCKABLE: u64 = (1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1));

pub fn signal_name(sig: u32) -> String {
    let names = [
        "?",
        "SIGHUP",
        "SIGINT",
        "SIGQUIT",
        "SIGILL",
        "SIGTRAP",
        "SIGABRT",
        "SIGBUS",
        "SIGFPE",
        "SIGKILL",
        "SIGUSR1",
        "SIGSEGV",
        "SIGUSR2",
        "SIGPIPE",
        "SIGALRM",
        "SIGTERM",
        "SIGSTKFLT",
        "SIGCHLD",
        "SIGCONT",
        "SIGSTOP",
        "SIGTSTP",
        "SIGTTIN",
        "SIGTTOU",
        "SIGURG",
        "SIGXCPU",
        "SIGXFSZ",
        "SIGVTALRM",
        "SIGPROF",
        "SIGWINCH",
        "SIGIO",
        "SIGPWR",
        "SIGSYS",
    ];
    names.get(sig as usize).map_or_else(|| alloc::format!("SIGRT{}", sig - 32), |n| String::from(*n))
}

/// What happens by default (signal(7), "Signal dispositions").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Default {
    Terminate,
    Core,
    Ignore,
    Stop,
    Continue,
}

fn default_action(sig: u32) -> Default {
    match sig {
        SIGCHLD | SIGURG | SIGWINCH => Default::Ignore,
        SIGQUIT | SIGILL | SIGTRAP | SIGABRT | SIGBUS | SIGFPE | SIGSEGV | SIGXCPU | SIGXFSZ | SIGSYS => Default::Core,
        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => Default::Stop,
        SIGCONT => Default::Continue,
        _ => Default::Terminate,
    }
}

/// The kernel `struct sigaction` of rt_sigaction(2).
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct SigAction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

/// Process-wide signal state: dispositions and process-directed pending
/// signals. Masks and thread-directed signals live in the thread.
#[derive(Debug)]
pub struct ProcessSignals {
    actions: IrqSpinLock<[SigAction; NSIG as usize]>,
    pending: AtomicU64,
    /// What each pending process-directed signal carries for siginfo
    /// (the default when the kernel raised it).
    infos: IrqSpinLock<[Info; NSIG as usize]>,
}

/// What a pending signal's siginfo says beyond its number (sigaction(2)):
/// si_code, and for one a process sent si_pid and si_uid (as the receiver
/// sees them) and, from sigqueue(3), si_value. The default: raised by the
/// kernel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Info {
    pub code: i32,
    pub pid: u32,
    pub uid: u32,
    pub value: u64,
}

/// si_code for tkill(2) and tgkill(2) (sigaction(2)). Source: musl
/// `signal.h`.
pub const SI_TKILL: i32 = -6;

impl ProcessSignals {
    pub fn new() -> ProcessSignals {
        ProcessSignals {
            actions: IrqSpinLock::new([SigAction::default(); NSIG as usize]),
            pending: AtomicU64::new(0),
            infos: IrqSpinLock::new([Info::default(); NSIG as usize]),
        }
    }

    pub fn inherit_from(&self, parent: &ProcessSignals) {
        *self.actions.lock() = *parent.actions.lock();
    }

    /// execve(2): handlers reset to default; ignored signals stay ignored.
    pub fn reset_on_exec(&self) {
        for a in self.actions.lock().iter_mut() {
            if a.handler != SIG_IGN {
                *a = SigAction::default();
            }
        }
    }

    pub fn action(&self, sig: u32) -> SigAction {
        self.actions.lock()[sig as usize - 1]
    }

    pub fn set_action(&self, sig: u32, a: SigAction) {
        self.actions.lock()[sig as usize - 1] = a;
    }

    pub fn has_handler(&self, sig: u32) -> bool {
        self.action(sig).handler > SIG_IGN
    }

    fn ignored(&self, sig: u32) -> bool {
        let a = self.action(sig);
        a.handler == SIG_IGN || (a.handler == SIG_DFL && default_action(sig) == Default::Ignore)
    }

    pub fn pending(&self) -> u64 {
        self.pending.load(Ordering::Acquire)
    }
}

impl core::default::Default for ProcessSignals {
    fn default() -> Self {
        Self::new()
    }
}

/// Send `sig` to process `p` from the kernel. Ignored signals are
/// discarded.
pub fn send_to_process(p: &Arc<Process>, sig: u32) {
    send_with(p, sig, Info::default());
}

/// Send `sig` to process `p` (kill(2)) from the process with PID `pid`
/// and real UID `uid` (both as `p` sees them), for siginfo.
pub fn send_from_process(p: &Arc<Process>, sig: u32, pid: u32, uid: u32) {
    send_with(p, sig, Info { code: SI_USER, pid, uid, value: 0 });
}

/// Send `sig` to process `p` carrying `info` (rt_sigqueueinfo(2)).
pub fn send_with(p: &Arc<Process>, sig: u32, info: Info) {
    if sig == 0 || sig > NSIG || p.is_zombie() {
        return;
    }
    p.signals.infos.lock()[sig as usize - 1] = info;
    const STOPS: u64 = (1 << (SIGSTOP - 1)) | (1 << (SIGTSTP - 1)) | (1 << (SIGTTIN - 1)) | (1 << (SIGTTOU - 1));
    if sig == SIGCONT {
        // SIGCONT resumes the process whatever its disposition, and cancels
        // pending stops (signal(7)).
        p.signals.pending.fetch_and(!STOPS, Ordering::AcqRel);
        super::continue_process(p);
    } else if STOPS & bit(sig) != 0 {
        p.signals.pending.fetch_and(!bit(SIGCONT), Ordering::AcqRel);
    }
    if sig == SIGKILL {
        // Mark it pending before waking a stopped process, so it cannot
        // resume and stop again before seeing the kill.
        p.signals.pending.fetch_or(bit(sig), Ordering::AcqRel);
        super::continue_process(p);
    }
    // An ignored signal is discarded, unless it is blocked: then it stays
    // pending for sigwait or a signalfd to take (signal(7), as Linux does,
    // judged by the main thread's mask).
    let blocked = p.threads().first().is_some_and(|t| t.signal_mask() & bit(sig) != 0);
    if sig != SIGKILL && p.signals.ignored(sig) && !blocked {
        return;
    }
    p.signals.pending.fetch_or(bit(sig), Ordering::AcqRel);
    // Any thread that does not block the signal may take it; wake one (all
    // of them for SIGKILL and stops, which concern every thread).
    let threads = p.threads();
    if sig == SIGKILL || STOPS & bit(sig) != 0 || sig == SIGCONT {
        threads.iter().for_each(|t| {
            sched::wake(t);
        });
    } else if let Some(t) = threads.iter().find(|t| t.signal_mask() & bit(sig) == 0).or(threads.first()) {
        sched::wake(t);
    }
    crate::fs::poll_notify();
}

/// Send `sig` to one thread of `p` carrying `info` (tgkill(2),
/// rt_tgsigqueueinfo(2)).
pub fn send_to_thread_with(p: &Arc<Process>, t: &Arc<sched::Thread>, sig: u32, info: Info) {
    if sig == 0 || sig > NSIG || p.is_zombie() {
        return;
    }
    let blocked = t.signal_mask() & bit(sig) != 0;
    if sig == SIGKILL || sig == SIGCONT || (p.signals.ignored(sig) && !blocked) {
        // These act on the whole process anyway.
        send_with(p, sig, info);
        return;
    }
    {
        let mut infos = t.sig_info.lock();
        infos.retain(|(s, _)| *s != sig);
        if info != Info::default() {
            infos.push((sig, info));
        }
    }
    t.add_pending_signal(bit(sig));
    sched::wake(t);
    crate::fs::poll_notify();
}

/// Send `sig` to every process in process group `pgid`. Returns how many
/// processes it reached.
pub fn send_to_group(pgid: u32, sig: u32) -> usize {
    let mut n = 0;
    for p in super::all() {
        if p.pgid.load(Ordering::Relaxed) == pgid && !p.is_zombie() {
            send_to_process(&p, sig);
            n += 1;
        }
    }
    n
}

/// Take one process-directed pending signal from `mask` (signalfd,
/// sigtimedwait), with what it carries.
pub fn take_process_signal(p: &Arc<Process>, mask: u64) -> Option<(u32, Info)> {
    loop {
        let set = p.signals.pending() & mask;
        if set == 0 {
            return None;
        }
        let sig = set.trailing_zeros() + 1;
        if p.signals.pending.fetch_and(!bit(sig), Ordering::AcqRel) & bit(sig) != 0 {
            return Some((sig, core::mem::take(&mut p.signals.infos.lock()[sig as usize - 1])));
        }
    }
}

/// What thread `t`'s pending `sig` carries, taken with it.
fn take_thread_info(t: &sched::Thread, sig: u32) -> Info {
    let mut infos = t.sig_info.lock();
    let i = infos.iter().position(|(s, _)| *s == sig);
    i.map(|i| infos.swap_remove(i).1).unwrap_or_default()
}

/// Take one of thread `t`'s own pending signals from `mask`, with what it
/// carries.
pub fn take_thread_signal(t: &sched::Thread, mask: u64) -> Option<(u32, Info)> {
    let set = t.pending_signals() & mask;
    if set == 0 {
        return None;
    }
    let sig = set.trailing_zeros() + 1;
    t.take_pending_signal(bit(sig));
    Some((sig, take_thread_info(t, sig)))
}

/// Write the siginfo of `sig` carrying `info` at user address `addr`
/// (rt_sigtimedwait(2)).
pub fn write_siginfo(addr: u64, sig: u32, info: Info) -> Result<(), Errno> {
    let mut si = SigInfo { signo: sig as i32, errno: 0, code: info.code, _pad: 0, data: [0; 14] };
    si.data[0] = (u64::from(info.uid) << 32) | u64::from(info.pid);
    si.data[1] = info.value;
    crate::arch::uaccess::write_user(addr, &si).map_err(|_| EFAULT)
}

/// A synchronous fault signal for the current thread: it cannot be blocked
/// or ignored (a blocked or ignored fault signal reverts to default).
pub fn force_signal(sig: u32, code: i32, addr: u64) {
    force_signal_with(sig, code, addr, 0, 0);
}

/// [`force_signal`] with the second word of siginfo's union and si_errno
/// too.
pub fn force_signal_with(sig: u32, code: i32, addr: u64, extra: u64, errno: i32) {
    let Some(p) = current() else { return };
    let t = sched::current();
    *t.fault.lock() = Some(sched::Fault { sig, code, addr, extra, errno });
    if t.signal_mask() & bit(sig) != 0 || p.signals.action(sig).handler == SIG_IGN {
        t.set_signal_mask(t.signal_mask() & !bit(sig));
        p.signals.set_action(sig, SigAction::default());
    }
    t.add_pending_signal(bit(sig));
}

/// Whether the current thread has a deliverable signal (used to interrupt
/// blocking system calls).
pub fn pending_for_current() -> bool {
    let Some(p) = current() else { return false };
    let t = sched::current();
    super::must_exit()
        || (p.is_stopped() && !t.exit_requested.load(Ordering::Relaxed))
        || (p.signals.pending() | t.pending_signals()) & !(t.signal_mask() & !UNBLOCKABLE) != 0
}

// --- Signal frames -------------------------------------------------------

/// `stack_t` (sigaltstack(2)).
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct StackT {
    sp: u64,
    flags: i32,
    _pad: i32,
    size: u64,
}

/// musl `mcontext_t`: 23 general registers (REG_R8 = 0 ... REG_CR2 = 22),
/// an fpstate pointer and 8 reserved words.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct MContext {
    gregs: [u64; 23],
    fpstate: u64,
    reserved: [u64; 8],
}

/// The kernel part of `ucontext_t` (up to and including a 64-bit sigmask).
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct UContext {
    flags: u64,
    link: u64,
    stack: StackT,
    mcontext: MContext,
    sigmask: u64,
}

/// `siginfo_t` (sigaction(2)): 128 bytes; we fill signo, code and the
/// first union word (fault address, or sender pid).
#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct SigInfo {
    signo: i32,
    errno: i32,
    code: i32,
    _pad: i32,
    data: [u64; 14],
}

const RED_ZONE: u64 = 128;
pub const SI_USER: i32 = 0;
pub const SI_KERNEL: i32 = 0x80;
// si_code values for faults (sigaction(2)). Source: musl `signal.h`.
pub const SEGV_MAPERR: i32 = 1;
pub const SEGV_ACCERR: i32 = 2;
pub const ILL_ILLOPN: i32 = 2;
pub const FPE_INTDIV: i32 = 1;

// sigaltstack(2) flags and minimum size. Source: musl `signal.h`.
const SS_ONSTACK: u32 = 1;
const SS_DISABLE: u32 = sched::ALTSTACK_DISABLED;
const SS_AUTODISARM: u32 = 1 << 31;
const MINSIGSTKSZ: u64 = 2048;

/// Whether `sp` is on the alternate stack `(base, size, _)`.
fn on_stack(alt: (u64, u64, u32), sp: u64) -> bool {
    alt.2 & SS_DISABLE == 0 && sp > alt.0 && sp - alt.0 <= alt.1
}

/// sigaltstack(2) for the current thread; `sp` is its user stack pointer.
pub fn sigaltstack(new: u64, old: u64, sp: u64) -> Result<(), Errno> {
    use crate::abi::linux::errno::{EINVAL, ENOMEM, EPERM};
    let t = sched::current();
    let cur = *t.altstack.lock();
    let on = on_stack(cur, sp);
    if new != 0 {
        let ss: StackT = read_user(new).map_err(|_| EFAULT)?;
        let flags = ss.flags as u32;
        if on {
            return Err(EPERM);
        }
        if flags & !(SS_DISABLE | SS_AUTODISARM | SS_ONSTACK) != 0 {
            return Err(EINVAL);
        }
        *t.altstack.lock() = if flags & SS_DISABLE != 0 {
            (0, 0, SS_DISABLE)
        } else if ss.size < MINSIGSTKSZ {
            return Err(ENOMEM);
        } else {
            (ss.sp, ss.size, flags & SS_AUTODISARM)
        };
    }
    if old != 0 {
        let flags = if on { SS_ONSTACK } else { cur.2 };
        let ss = StackT { sp: cur.0, flags: flags as i32, _pad: 0, size: cur.1 };
        write_user(old, &ss).map_err(|_| EFAULT)?;
    }
    Ok(())
}

fn frame_to_gregs(f: &TrapFrame) -> [u64; 23] {
    let mut g = [0u64; 23];
    g[..16].copy_from_slice(&[
        f.r8, f.r9, f.r10, f.r11, f.r12, f.r13, f.r14, f.r15, f.rdi, f.rsi, f.rbp, f.rbx, f.rdx, f.rax, f.rcx, f.rsp,
    ]);
    g[16] = f.rip;
    g[17] = f.rflags;
    g[18] = (f.cs & 0xFFFF) | ((f.ss & 0xFFFF) << 48); // REG_CSGSFS: cs, gs, fs, ss
    g[19] = f.error_code;
    g[20] = f.vector;
    g
}

fn gregs_to_frame(g: &[u64; 23], f: &mut TrapFrame) {
    [f.r8, f.r9, f.r10, f.r11, f.r12, f.r13, f.r14, f.r15, f.rdi, f.rsi, f.rbp, f.rbx, f.rdx, f.rax, f.rcx, f.rsp] =
        g[..16].try_into().unwrap();
    f.rip = g[16];
    // Only the arithmetic and direction flags are the user's to set; IF stays
    // on and privileged bits stay clear.
    const USER_FLAGS: u64 = 0xCD5 | (1 << 10) | (1 << 18) | (1 << 21); // CF PF AF ZF SF TF DF OF, AC, ID
    f.rflags = (f.rflags & !USER_FLAGS) | (g[17] & USER_FLAGS) | 0x202;
}

/// Deliver pending signals before returning to user mode with `frame`.
/// `syscall_result` is the result of the system call being returned from,
/// if any (for SA_RESTART handling).
pub fn deliver(frame: &mut TrapFrame, in_syscall: bool) {
    let Some(p) = current() else { return };
    let t = sched::current();
    // rseq (ADR 0115): the area brought up to date after a switch, and an
    // interrupted critical section sent to its abort handler before a
    // signal's frame records where the thread was.
    let mask = t.signal_mask() & !UNBLOCKABLE;
    let signal = (t.pending_signals() | p.signals.pending()) & !mask != 0;
    super::rseq::before_user(frame, signal);
    loop {
        // Another thread ended the process, or is replacing its image.
        // (The exits never return: nothing may stay referenced here, or it
        // would never be dropped.)
        if super::must_exit() {
            drop((p, t));
            super::exit_thread(0);
        }
        // Another thread stopped the process: stop here too.
        if p.is_stopped() {
            super::wait_while_stopped(&p);
            continue;
        }
        let mask = t.signal_mask() & !UNBLOCKABLE;
        let thread_pending = t.pending_signals() & !mask;
        let proc_pending = p.signals.pending() & !mask;
        let set = if thread_pending != 0 { thread_pending } else { proc_pending };
        if set == 0 {
            break;
        }
        let sig = set.trailing_zeros() + 1;
        let info = if thread_pending != 0 {
            t.take_pending_signal(bit(sig));
            take_thread_info(&t, sig)
        } else if p.signals.pending.fetch_and(!bit(sig), Ordering::AcqRel) & bit(sig) == 0 {
            continue; // Another thread took it.
        } else {
            core::mem::take(&mut p.signals.infos.lock()[sig as usize - 1])
        };
        let action = p.signals.action(sig);
        if action.handler == SIG_IGN && sig != SIGKILL {
            continue;
        }
        if action.handler == SIG_DFL || sig == SIGKILL {
            match default_action(sig) {
                Default::Ignore | Default::Continue => continue,
                Default::Stop => {
                    // Terminal stops are discarded for orphaned groups (POSIX).
                    let pg = p.pgid.load(Ordering::Relaxed);
                    if sig != SIGSTOP && super::is_orphaned_pgrp(pg) {
                        continue;
                    }
                    super::stop_current(sig);
                    continue;
                }
                Default::Terminate | Default::Core => {
                    drop((p, t));
                    exit_current(wait_status_signaled(sig as i32));
                }
            }
        }
        // A user handler: decide what happens to an interrupted syscall.
        if in_syscall && frame.rax as i64 == -i64::from(ERESTARTNOHAND.0) {
            frame.rax = (-i64::from(EINTR.0)) as u64;
            t.take_restart_deadline();
        }
        if in_syscall && frame.rax as i64 == -i64::from(ERESTARTSYS.0) {
            if action.flags & SA_RESTART != 0 {
                frame.rax = frame.error_code; // original syscall number
                frame.rip -= 2; // re-execute `syscall`
            } else {
                frame.rax = (-i64::from(EINTR.0)) as u64;
            }
        }
        let restore_mask = t.take_saved_mask().unwrap_or(t.signal_mask());
        if setup_frame(frame, sig, &action, restore_mask, info).is_err() {
            // The stack is unusable: the process dies as Linux would.
            crate::log_warn!(
                "pid {} ({}): cannot deliver {} (stack at {:#x} unusable); killed by SIGSEGV",
                p.pid,
                *p.name.lock(),
                signal_name(sig),
                frame.rsp
            );
            drop((p, t));
            exit_current(wait_status_signaled(SIGSEGV as i32));
        }
        let mut new_mask = t.signal_mask() | action.mask;
        if action.flags & SA_NODEFER == 0 {
            new_mask |= bit(sig);
        }
        t.set_signal_mask(new_mask & !UNBLOCKABLE);
        // The handler goes back to the default; the flags stay, as Linux
        // was seen to keep them (SA_SIGINFO included).
        if action.flags & SA_RESETHAND != 0 {
            p.signals.set_action(sig, SigAction { handler: SIG_DFL, ..action });
        }
        return;
    }
    // No handler took over: undo a temporary mask, and restart an
    // interrupted syscall transparently.
    if let Some(m) = t.take_saved_mask() {
        t.set_signal_mask(m);
    }
    let r = frame.rax as i64;
    if in_syscall && (r == -i64::from(ERESTARTSYS.0) || r == -i64::from(ERESTARTNOHAND.0)) {
        frame.rax = frame.error_code;
        frame.rip -= 2;
    }
}

/// `info` is what the signal carries (the default if the kernel raised it).
fn setup_frame(frame: &mut TrapFrame, sig: u32, action: &SigAction, old_mask: u64, info_in: Info) -> Result<(), Errno> {
    if action.flags & SA_RESTORER == 0 {
        return Err(EFAULT); // x86-64 requires a restorer; libcs always set one.
    }
    let t = sched::current();
    let fpu = t.arch.save_fpu_for_signal();
    // SA_ONSTACK: switch to the alternate stack unless already on it.
    let alt = *t.altstack.lock();
    let on_alt = on_stack(alt, frame.rsp);
    let mut sp = if action.flags & SA_ONSTACK != 0 && alt.2 & SS_DISABLE == 0 && !on_alt {
        if alt.2 & SS_AUTODISARM != 0 {
            *t.altstack.lock() = (0, 0, SS_DISABLE);
        }
        alt.0 + alt.1
    } else {
        frame.rsp - RED_ZONE
    };
    sp = (sp - fpu.len() as u64) & !63;
    let fp_addr = sp;
    copy_to_user(fp_addr, &fpu).map_err(|_| EFAULT)?;
    let frame_size = (8 + size_of::<UContext>() + size_of::<SigInfo>()) as u64;
    sp = ((sp - frame_size) & !15) - 8;
    let uc_addr = sp + 8;
    let info_addr = uc_addr + size_of::<UContext>() as u64;

    let uc = UContext {
        flags: 0,
        link: 0,
        // The alternate stack as it was; sigreturn restores it from here.
        stack: StackT { sp: alt.0, flags: (if on_alt { SS_ONSTACK } else { alt.2 }) as i32, _pad: 0, size: alt.1 },
        mcontext: MContext { gregs: frame_to_gregs(frame), fpstate: fp_addr, reserved: [0; 8] },
        sigmask: old_mask,
    };
    let mut info = SigInfo { signo: sig as i32, errno: 0, code: info_in.code, _pad: 0, data: [0; 14] };
    // si_pid and si_uid (sigaction(2): offsets 16 and 20, the first union
    // word) for a signal another process sent, then sigqueue's si_value.
    info.data[0] = (u64::from(info_in.uid) << 32) | u64::from(info_in.pid);
    info.data[1] = info_in.value;
    if matches!(sig, SIGSEGV | SIGBUS | SIGILL | SIGFPE | SIGTRAP) && info_in == Info::default() {
        info.code = SI_KERNEL;
    }
    // A signal the kernel raised for this thread (a fault, a seccomp
    // trap): si_code and the first union words (si_addr; for SIGSYS also
    // si_syscall and si_arch) describe it.
    let fault = t.fault.lock().take();
    if let Some(f) = fault {
        if f.sig == sig {
            info.code = f.code;
            info.errno = f.errno;
            info.data[0] = f.addr;
            info.data[1] = f.extra;
        } else {
            // Another signal came first: keep it for its own.
            *t.fault.lock() = Some(f);
        }
    }
    write_user(sp, &action.restorer).map_err(|_| EFAULT)?;
    write_user(uc_addr, &uc).map_err(|_| EFAULT)?;
    write_user(info_addr, &info).map_err(|_| EFAULT)?;

    frame.rsp = sp;
    frame.rip = action.handler;
    frame.rdi = u64::from(sig);
    frame.rsi = info_addr;
    frame.rdx = uc_addr;
    frame.rax = 0;
    frame.rflags &= !(1 << 10 | 1 << 8); // clear DF and TF for the handler
    Ok(())
}

/// rt_sigreturn(2): restore the context saved by `setup_frame`. The user
/// stack pointer at the `syscall` points at the `ucontext`.
pub fn sigreturn(frame: &mut TrapFrame) -> Result<(), Errno> {
    let uc: UContext = read_user(frame.rsp).map_err(|_| EFAULT)?;
    gregs_to_frame(&uc.mcontext.gregs, frame);
    let t = sched::current();
    t.set_signal_mask(uc.sigmask & !UNBLOCKABLE);
    // The alternate stack saved in the frame comes back (as Linux does,
    // which re-arms an SS_AUTODISARM stack).
    let flags = uc.stack.flags as u32 & !SS_ONSTACK;
    if !on_stack(*t.altstack.lock(), frame.rsp) {
        *t.altstack.lock() = if flags & SS_DISABLE != 0 || uc.stack.size < MINSIGSTKSZ {
            (0, 0, SS_DISABLE)
        } else {
            (uc.stack.sp, uc.stack.size, flags)
        };
    }
    if uc.mcontext.fpstate != 0 {
        let mut buf = alloc::vec![0u8; crate::arch::fpu::area_size()];
        copy_from_user(&mut buf, uc.mcontext.fpstate).map_err(|_| EFAULT)?;
        t.arch.restore_fpu_from_signal(&buf);
    }
    Ok(())
}

/// The user `sigset_t` argument of rt_sigprocmask(2) and friends.
pub fn read_sigset(addr: u64) -> Result<u64, Errno> {
    read_user::<u64>(addr).map_err(|_| EFAULT)
}
