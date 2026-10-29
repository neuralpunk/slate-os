// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signals (signal(7)): numbers, dispositions, masks, and a simple
//! "caught" set for programs that poll for signals.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::errno::Result;
use crate::sys;

pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGILL: i32 = 4;
pub const SIGTRAP: i32 = 5;
pub const SIGABRT: i32 = 6;
pub const SIGBUS: i32 = 7;
pub const SIGFPE: i32 = 8;
pub const SIGKILL: i32 = 9;
pub const SIGUSR1: i32 = 10;
pub const SIGSEGV: i32 = 11;
pub const SIGUSR2: i32 = 12;
pub const SIGPIPE: i32 = 13;
pub const SIGALRM: i32 = 14;
pub const SIGTERM: i32 = 15;
pub const SIGCHLD: i32 = 17;
pub const SIGCONT: i32 = 18;
pub const SIGSTOP: i32 = 19;
pub const SIGTSTP: i32 = 20;
pub const SIGTTIN: i32 = 21;
pub const SIGPWR: i32 = 30;
pub const SIGTTOU: i32 = 22;
pub const SIGWINCH: i32 = 28;

/// Names without the SIG prefix, by number (kill -l order).
pub const NAMES: [&str; 32] = [
    "0", "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1", "SEGV", "USR2", "PIPE", "ALRM",
    "TERM", "STKFLT", "CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG", "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH",
    "IO", "PWR", "SYS",
];

pub fn by_name(name: &str) -> Option<i32> {
    let n = name.strip_prefix("SIG").unwrap_or(name);
    if let Ok(v) = n.parse::<i32>() {
        return (0..65).contains(&v).then_some(v);
    }
    NAMES.iter().position(|&s| s.eq_ignore_ascii_case(n)).map(|i| i as i32)
}

/// A short description, as shells print for terminated jobs.
pub fn describe(sig: i32) -> &'static str {
    match sig {
        SIGHUP => "Hangup",
        SIGINT => "Interrupt",
        SIGQUIT => "Quit",
        SIGILL => "Illegal instruction",
        SIGTRAP => "Trace/breakpoint trap",
        SIGABRT => "Aborted",
        SIGBUS => "Bus error",
        SIGFPE => "Floating point exception",
        SIGKILL => "Killed",
        SIGUSR1 => "User defined signal 1",
        SIGSEGV => "Segmentation fault",
        SIGUSR2 => "User defined signal 2",
        SIGPIPE => "Broken pipe",
        SIGALRM => "Alarm clock",
        SIGTERM => "Terminated",
        SIGSTOP | SIGTSTP => "Stopped",
        SIGTTIN => "Stopped (tty input)",
        SIGTTOU => "Stopped (tty output)",
        _ => "Signal",
    }
}

const SA_RESTART: u64 = 0x1000_0000;
const SA_RESTORER: u64 = 0x0400_0000;
const SIG_DFL: usize = 0;
const SIG_IGN: usize = 1;

/// The kernel's `struct sigaction` (x86-64): handler, flags, restorer, mask.
#[repr(C)]
struct KSigaction {
    handler: usize,
    flags: u64,
    restorer: usize,
    mask: u64,
}

#[unsafe(naked)]
unsafe extern "C" fn restorer() {
    // rt_sigreturn (15).
    core::arch::naked_asm!("mov eax, 15", "syscall", "ud2")
}

#[unsafe(naked)]
unsafe extern "C" fn native_restorer() {
    // The native sigreturn (slate_abi::nr::SIGRETURN).
    core::arch::naked_asm!("mov eax, 57", "syscall", "ud2")
}

const _: () = assert!(slate_abi::nr::SIGRETURN == 57);

/// Signals that arrived for `catch`ed numbers.
static CAUGHT: AtomicU64 = AtomicU64::new(0);

extern "C" fn record(sig: i32) {
    CAUGHT.fetch_or(1 << sig, Ordering::SeqCst);
}

pub(crate) fn init() {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    Default,
    Ignore,
    /// Record the signal for [`take`] (system calls are restarted).
    Catch,
    /// Record it, interrupting blocking system calls (EINTR).
    CatchInterrupt,
}

pub fn set(sig: i32, d: Disposition) -> Result<()> {
    let (handler, restart) = match d {
        Disposition::Default => (SIG_DFL, false),
        Disposition::Ignore => (SIG_IGN, false),
        Disposition::Catch => (record as *const () as usize, true),
        Disposition::CatchInterrupt => (record as *const () as usize, false),
    };
    set_handler(sig, handler, restart).map(|_| ())
}

/// Install `handler` (an `extern "C" fn(i32)`, or 0 for the default and 1
/// to ignore) for `sig`; `restart` restarts interrupted calls. Returns the
/// previous handler.
pub fn set_handler(sig: i32, handler: usize, restart: bool) -> Result<usize> {
    if sys::native() {
        let act = slate_abi::SigAction {
            handler: handler as u64,
            flags: if restart { slate_abi::sigaction::RESTART } else { 0 },
            _reserved: 0,
            mask: 0,
            restorer: native_restorer as *const () as u64,
        };
        let mut old = slate_abi::SigAction::default();
        crate::syscall!(
            slate_abi::nr::SIGACTION as usize,
            sig,
            &act as *const slate_abi::SigAction,
            &mut old as *mut slate_abi::SigAction
        )?;
        return Ok(old.handler as usize);
    }
    let flags = if restart { SA_RESTART } else { 0 } | SA_RESTORER;
    let act = KSigaction { handler, flags, restorer: restorer as *const () as usize, mask: 0 };
    let mut old = KSigaction { handler: 0, flags: 0, restorer: 0, mask: 0 };
    crate::syscall!(sys::RT_SIGACTION, sig, &act as *const KSigaction, &mut old as *mut KSigaction, 8)?;
    Ok(old.handler)
}

/// sigaction(2) flags as C sees them (Linux's values, musl `signal.h`,
/// ADR 0009); the native interface has its own (`slate_abi::sigaction`).
pub const SA_NOCLDSTOP: u32 = 1;
pub const SA_NOCLDWAIT: u32 = 2;
pub const SA_SIGINFO: u32 = 4;
pub const SA_ONSTACK: u32 = 0x0800_0000;
pub const SA_RESTART_C: u32 = 0x1000_0000;
pub const SA_NODEFER: u32 = 0x4000_0000;
pub const SA_RESETHAND: u32 = 0x8000_0000;

/// C's flags and the native ones, pairwise.
const NATIVE_FLAGS: [(u32, u32); 7] = [
    (SA_NOCLDSTOP, slate_abi::sigaction::NOCLDSTOP),
    (SA_NOCLDWAIT, slate_abi::sigaction::NOCLDWAIT),
    (SA_SIGINFO, slate_abi::sigaction::SIGINFO),
    (SA_ONSTACK, slate_abi::sigaction::ONSTACK),
    (SA_RESTART_C, slate_abi::sigaction::RESTART),
    (SA_NODEFER, slate_abi::sigaction::NODEFER),
    (SA_RESETHAND, slate_abi::sigaction::RESETHAND),
];

/// A signal's action: handler (0 default, 1 ignore, or a function),
/// C's `SA_*` flags, and the signals blocked while it runs (bit n-1 for
/// signal n).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Action {
    pub handler: usize,
    pub flags: u32,
    pub mask: u64,
}

/// Read and/or set `sig`'s action; returns the previous one.
pub fn action(sig: i32, new: Option<&Action>) -> Result<Action> {
    if sys::native() {
        let to_native = |f: u32| NATIVE_FLAGS.iter().filter(|(c, _)| f & c != 0).fold(0, |m, (_, n)| m | n);
        let act = new.map(|a| slate_abi::SigAction {
            handler: a.handler as u64,
            flags: to_native(a.flags),
            _reserved: 0,
            mask: a.mask,
            restorer: native_restorer as *const () as u64,
        });
        let mut old = slate_abi::SigAction::default();
        let p = act.as_ref().map_or(core::ptr::null(), |a| a as *const slate_abi::SigAction);
        crate::syscall!(slate_abi::nr::SIGACTION as usize, sig, p, &mut old as *mut slate_abi::SigAction)?;
        let flags = NATIVE_FLAGS.iter().filter(|(_, n)| old.flags & n != 0).fold(0, |m, (c, _)| m | c);
        return Ok(Action { handler: old.handler as usize, flags, mask: old.mask });
    }
    let act = new.map(|a| KSigaction {
        handler: a.handler,
        flags: u64::from(a.flags) | SA_RESTORER,
        restorer: restorer as *const () as usize,
        mask: a.mask,
    });
    let mut old = KSigaction { handler: 0, flags: 0, restorer: 0, mask: 0 };
    let p = act.as_ref().map_or(core::ptr::null(), |a| a as *const KSigaction);
    crate::syscall!(sys::RT_SIGACTION, sig, p, &mut old as *mut KSigaction, 8)?;
    Ok(Action { handler: old.handler, flags: (old.flags & !SA_RESTORER) as u32, mask: old.mask })
}

/// Caught signals since the last call, as a bit set (bit n = signal n).
pub fn take() -> u64 {
    CAUGHT.swap(0, Ordering::SeqCst)
}

pub fn pending(sig: i32) -> bool {
    CAUGHT.load(Ordering::SeqCst) & (1 << sig) != 0
}

const SIG_BLOCK: u32 = 0;
const SIG_UNBLOCK: u32 = 1;
const SIG_SETMASK: u32 = 2;

fn mask(how: u32, set: u64) -> Result<u64> {
    let mut old: u64 = 0;
    // The native sigmask takes the same operations (POSIX values).
    crate::syscall!(
        sys::pick(sys::RT_SIGPROCMASK, slate_abi::nr::SIGMASK),
        how,
        &set as *const u64,
        &mut old as *mut u64,
        8
    )?;
    Ok(old)
}

pub fn block(sigs: u64) -> Result<u64> {
    mask(SIG_BLOCK, sigs)
}
pub fn unblock(sigs: u64) -> Result<u64> {
    mask(SIG_UNBLOCK, sigs)
}
pub fn set_mask(sigs: u64) -> Result<u64> {
    mask(SIG_SETMASK, sigs)
}

pub fn bit(sig: i32) -> u64 {
    1 << (sig - 1)
}
