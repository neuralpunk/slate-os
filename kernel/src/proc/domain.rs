// SPDX-License-Identifier: MIT OR Apache-2.0

//! Slate mode and Linux compatibility mode (ADR 0022, ADR 0032): every
//! process is in the Slate or the Linux domain, and Linux-domain programs
//! may run only while compatibility mode is on.

use alloc::collections::BTreeSet;
use alloc::string::String;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::abi::linux::errno::Errno;
use crate::sync::IrqSpinLock;
use crate::{log_info, log_warn};

/// A process's domain, decided at exec and inherited on fork.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Domain {
    /// Native programs from the system tree (`vfs::in_system_tree`).
    Slate = 0,
    /// Everything else.
    Linux = 1,
}

impl Domain {
    pub fn name(self) -> &'static str {
        match self {
            Domain::Slate => "slate",
            Domain::Linux => "linux",
        }
    }
}

/// The error an exec into the Linux domain gets while compatibility mode
/// is off: Slate's own code (`slate_abi::error::LINUX_OFF`), outside the
/// Linux errno range. Linux callers see EACCES instead.
pub const LINUX_OFF: Errno = Errno(slate_abi::error::LINUX_OFF);

static COMPAT: AtomicBool = AtomicBool::new(false);

/// Developer mode (ADR 0090): root in the Slate domain may change the
/// system image without the system grant.
static DEVMODE: AtomicBool = AtomicBool::new(false);

/// Apply `slate.compat=on|off` (default off) and `slate.devmode` from the
/// kernel command line.
pub fn configure(cmdline: &str) {
    if let Some(v) = cmdline.split_ascii_whitespace().find_map(|w| w.strip_prefix("slate.compat=")) {
        COMPAT.store(matches!(v, "on" | "1" | "yes"), Ordering::Relaxed);
    }
    if cmdline.split_ascii_whitespace().any(|w| w == "slate.devmode" || w == "slate.devmode=1") {
        DEVMODE.store(true, Ordering::Relaxed);
        log_warn!("developer mode: root may change the system image (slate.devmode)");
    }
}

/// Whether developer mode is on.
pub fn devmode() -> bool {
    DEVMODE.load(Ordering::Acquire)
}

/// Turn developer mode off for the rest of the boot (there is no way
/// back on from a running system).
pub fn end_devmode() {
    if DEVMODE.swap(false, Ordering::AcqRel) {
        log_info!("developer mode off");
    }
}

/// Whether the caller may change the system image (ADR 0090): the kernel
/// itself, a process with the system grant, or root in the Slate domain
/// in developer mode. Never the Linux domain.
pub fn may_write_image() -> bool {
    match super::current() {
        None => true,
        Some(p) => p.domain() == Domain::Slate && (p.has_grant() || (devmode() && p.cred().euid == 0)),
    }
}

/// Whether the caller may write the encrypted root's key slots (ADR
/// 0130): the kernel, or a program signed KEYSLOTS run as root in the
/// Slate domain (slate-brokerd, login, passwd, chpasswd, slate-crypt).
pub fn may_write_key_slots() -> bool {
    match super::current() {
        None => true,
        Some(p) => p.domain() == Domain::Slate && p.cred().euid == 0 && p.has_keyslots(),
    }
}

/// Whether Linux compatibility mode is on.
pub fn compat() -> bool {
    COMPAT.load(Ordering::Acquire)
}

/// Turn compatibility mode on or off. Turning it off ends every process
/// in the Linux domain.
pub fn set_compat(on: bool) {
    let was = COMPAT.swap(on, Ordering::AcqRel);
    if was == on {
        return;
    }
    log_info!("Linux compatibility mode {}", if on { "on" } else { "off" });
    if !on {
        for p in super::all() {
            if p.domain() == Domain::Linux && !p.is_zombie() {
                log_info!("compatibility mode off: stopping pid {} ({})", p.pid, *p.name.lock());
                super::signal::send_to_process(&p, super::signal::SIGKILL);
            }
        }
    }
}

/// Whether the calling process is in the Linux domain (the kernel itself
/// is not).
pub fn linux_caller() -> bool {
    super::current().is_some_and(|p| p.domain() == Domain::Linux)
}

/// Whether `sender` may signal `target` as far as domains go: a Linux
/// process may not signal a Slate one (ADR 0032). Signals the kernel sends
/// itself (SIGCHLD, job control from the terminal) do not ask.
pub fn may_signal(sender: &super::Process, target: &super::Process) -> bool {
    !(sender.domain() == Domain::Linux && target.domain() == Domain::Slate)
}

/// Whether the calling process may see `target` in /proc: not across
/// the domain boundary from the Linux side, and only its own user's
/// processes unless privileged over the target's user namespace (ADR
/// 0032's restricted introspection; rootless containers see their own).
pub fn may_inspect(target: &super::Process) -> bool {
    let Some(me) = super::current() else { return true };
    if me.domain() == Domain::Linux && target.domain() == Domain::Slate {
        return false;
    }
    if me.pid == target.pid {
        return true;
    }
    let (m, t) = (me.cred(), target.cred());
    m.euid == t.euid || m.ruid == t.ruid || m.ns_capable(&t.user_ns, super::cred::CAP_SYS_PTRACE)
}

/// Whether the calling process may write and execute the same mapping:
/// never in the Slate domain (strict W^X, ADR 0032).
pub fn may_map_wx() -> bool {
    !super::current().is_some_and(|p| p.domain() == Domain::Slate)
}

/// A Linux-domain process in the initial mount namespace may not mount
/// on, unmount or pivot the system tree (other namespaces only change
/// their own view).
pub fn may_change_mounts(at: &alloc::sync::Arc<crate::fs::vfs::Dentry>) -> bool {
    match super::current() {
        Some(p) if p.domain() == Domain::Linux && p.mnt_ns_id() == 0 => !crate::fs::vfs::in_system_tree(at),
        _ => true,
    }
}

/// Program paths whose refusal was logged (logged once each).
static REFUSED: IrqSpinLock<BTreeSet<String>> = IrqSpinLock::new(BTreeSet::new());

/// Log that `path` was refused because compatibility mode is off.
/// Native programs found unsigned (or signed by an unknown key), logged
/// once each: they run in the Linux domain (ADR 0090).
static UNSIGNED: IrqSpinLock<BTreeSet<String>> = IrqSpinLock::new(BTreeSet::new());

/// Programs whose Slate-only descriptors were closed at exec (ADR 0098),
/// logged once each.
static KEPT_BACK: IrqSpinLock<BTreeSet<String>> = IrqSpinLock::new(BTreeSet::new());

pub fn log_kept_back(path: &str, n: usize) {
    let mut seen = KEPT_BACK.lock();
    if seen.len() < 64 && seen.insert(String::from(path)) {
        drop(seen);
        log_warn!("{path} runs in the Linux domain: {n} descriptor(s) the Slate domain keeps were closed");
    }
}

pub fn log_unsigned(path: &str) {
    let mut seen = UNSIGNED.lock();
    if seen.len() < 64 && seen.insert(String::from(path)) {
        drop(seen);
        log_warn!("{path} is a native program without a trusted signature: it runs in the Linux domain");
    }
}

pub fn log_refusal(path: &str) {
    let mut seen = REFUSED.lock();
    if seen.len() < 64 && seen.insert(String::from(path)) {
        drop(seen);
        log_warn!("{path} is a Linux program: Linux compatibility mode is off (turn it on with slate-compat on)");
    }
}
