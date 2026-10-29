// SPDX-License-Identifier: MIT OR Apache-2.0

//! Process-level calls: exit, IDs, uname, arch_prctl, resource limits,
//! getrandom.

use alloc::vec;

use super::errno::{EFAULT, EINVAL, ESRCH};
use super::{Args, Result};
use crate::arch::context;
use crate::arch::uaccess::{copy_to_user, write_user};
use crate::proc;
use crate::sync::IrqSpinLock;
use core::sync::atomic::Ordering;

/// exit(2): end the calling thread (the process ends with its last thread).
pub fn exit(a: Args) -> Result {
    proc::exit_thread(proc::wait_status_exited(a.0[0] as i32));
}

/// exit_group(2): end every thread of the process.
pub fn exit_group(a: Args) -> Result {
    proc::exit_current(proc::wait_status_exited(a.0[0] as i32));
}

// PIDs and thread IDs are shown as the caller's PID namespace sees them
// (pid_namespaces(7)).

pub fn getpid() -> Result {
    let p = proc::current().ok_or(ESRCH)?;
    Ok(u64::from(p.pid_in(&p.pid_ns()).unwrap_or(p.pid)))
}

/// The calling thread's ID in its PID namespace.
fn my_tid() -> u64 {
    let t = crate::sched::current();
    proc::current().and_then(|p| p.tid_in(t.tid, &p.pid_ns())).unwrap_or(t.tid)
}

pub fn gettid() -> Result {
    Ok(my_tid())
}

/// set_tid_address(2): remember where to clear the TID at thread exit.
pub fn set_tid_address(a: Args) -> Result {
    crate::sched::current().clear_child_tid.store(a.0[0], Ordering::Relaxed);
    Ok(my_tid())
}

// arch_prctl(2) codes, observed in musl's `__set_thread_area` (ADR 0009).
const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;
// ARCH_SET_GS (arch_prctl(2)), observed from Firefox's WebAssembly
// runtime, which keeps its sandbox's memory base in GS.
const ARCH_SET_GS: u64 = 0x1001;

/// arch_prctl codes already reported as unsupported.
static ARCH_PRCTL_REPORTED: IrqSpinLock<alloc::vec::Vec<u64>> = IrqSpinLock::new(alloc::vec::Vec::new());

pub fn arch_prctl(a: Args) -> Result {
    match a.0[0] {
        ARCH_SET_FS => {
            if a.0[1] >= crate::arch::uaccess::USER_END {
                return Err(super::errno::EPERM);
            }
            context::set_fs_base(a.0[1]);
            Ok(0)
        }
        ARCH_GET_FS => {
            write_user(a.0[1], &context::fs_base()).map_err(|_| EFAULT)?;
            Ok(0)
        }
        ARCH_SET_GS => {
            if a.0[1] >= crate::arch::uaccess::USER_END {
                return Err(super::errno::EPERM);
            }
            context::set_user_gs_base(a.0[1]);
            Ok(0)
        }
        code => {
            let mut seen = ARCH_PRCTL_REPORTED.lock();
            if !seen.contains(&code) {
                seen.push(code);
                let pid = proc::current().map_or(0, |p| p.pid);
                crate::log_warn!("pid {pid}: unsupported arch_prctl code {code:#x}");
            }
            Err(EINVAL)
        }
    }
}

/// personality(2): the persona is PER_LINUX (0) with flags; only
/// ADDR_NO_RANDOMIZE changes anything (ADR 0092), the other flags are kept
/// and logged once. 0xffffffff asks without changing it. Returns the
/// previous persona. Values from `sys/personality.h` (musl).
pub fn personality(a: Args) -> Result {
    const QUERY: u64 = 0xffff_ffff;
    const PER_MASK: u64 = 0xff;
    let p = proc::current().ok_or(ESRCH)?;
    let old = p.persona.load(Ordering::Relaxed);
    let new = a.0[0];
    if new != QUERY {
        if new & PER_MASK != 0 || new > u64::from(u32::MAX) {
            return Err(EINVAL);
        }
        let ignored = new as u32 & !proc::aslr::ADDR_NO_RANDOMIZE;
        if ignored != 0 && !PERSONA_LOGGED.swap(true, Ordering::Relaxed) {
            crate::log_warn!("pid {}: personality flags {ignored:#x} are kept but change nothing", p.pid);
        }
        p.persona.store(new as u32, Ordering::Relaxed);
    }
    Ok(u64::from(old))
}

static PERSONA_LOGGED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// `struct utsname` (uname(2)): six 65-byte fields.
pub(crate) const UTS_FIELD: usize = 65;

/// The Linux release whose interface Slate offers, as Linux programs are
/// told it (they parse it to decide which kernel features exist).
pub(crate) const LINUX_RELEASE: &str = "6.12.0-slate";
/// Slate's own release: the workspace's version (Cargo.toml).
pub(crate) const SLATE_RELEASE: &str = env!("CARGO_PKG_VERSION");

/// What the calling process is told the system is (ADR 0153): Slate's
/// own programs hear Slate; Linux programs hear a Linux-compatible kernel,
/// as distro binaries need (ADR 0010). (sysname, release, version, the
/// /proc/version line.)
pub(crate) fn identity() -> (&'static str, &'static str, &'static str, &'static str) {
    if proc::current().is_some_and(|p| p.domain() == proc::domain::Domain::Slate) {
        (
            "Slate",
            SLATE_RELEASE,
            "#1 SMP PREEMPT",
            concat!("Slate version ", env!("CARGO_PKG_VERSION"), " (slate@slate) #1 SMP PREEMPT\n"),
        )
    } else {
        (
            "Linux",
            LINUX_RELEASE,
            concat!("#1 SMP PREEMPT Slate ", env!("CARGO_PKG_VERSION")),
            concat!("Linux version 6.12.0-slate (slate@slate) #1 SMP PREEMPT Slate ", env!("CARGO_PKG_VERSION"), "\n"),
        )
    }
}

pub fn uname(a: Args) -> Result {
    let host = proc::current().map_or_else(alloc::vec::Vec::new, |p| p.namespaces().uts.hostname.lock().clone());
    let host = if host.is_empty() { "slate" } else { core::str::from_utf8(&host).unwrap_or("slate") };
    let (sysname, release, version, _) = identity();
    let fields: [&str; 6] = [sysname, host, release, version, "x86_64", "(none)"];
    let mut buf = [0u8; UTS_FIELD * 6];
    for (i, f) in fields.iter().enumerate() {
        buf[i * UTS_FIELD..i * UTS_FIELD + f.len()].copy_from_slice(f.as_bytes());
    }
    copy_to_user(a.0[0], &buf).map_err(|_| EFAULT)?;
    Ok(0)
}

/// syslog(2) (the system call, not the C library's): the kernel log ring
/// (ADR 0029). Supported actions: 3 READ_ALL, 4 READ_CLEAR, 5 CLEAR,
/// 9 SIZE_UNREAD and 10 SIZE_BUFFER; console-level actions (6-8) are
/// accepted and ignored. Clearing needs CAP_SYSLOG or CAP_SYS_ADMIN.
pub fn syslog(a: Args) -> Result {
    const READ_ALL: u64 = 3;
    const READ_CLEAR: u64 = 4;
    const CLEAR: u64 = 5;
    const CONSOLE_OFF: u64 = 6;
    const CONSOLE_LEVEL: u64 = 8;
    const SIZE_UNREAD: u64 = 9;
    const SIZE_BUFFER: u64 = 10;
    let (action, buf, len) = (a.0[0], a.0[1], a.0[2] as i64);
    let privileged = || {
        proc::current().is_some_and(|p| {
            let c = p.cred();
            c.capable(crate::proc::cred::CAP_SYSLOG) || c.capable(crate::proc::cred::CAP_SYS_ADMIN)
        })
    };
    // The kernel log is root's (ADR 0032; dmesg_restrict on Linux): only
    // the console-level actions are open to everyone.
    if !(CONSOLE_OFF..=CONSOLE_LEVEL).contains(&action) && !privileged() {
        return Err(super::errno::EPERM);
    }
    match action {
        READ_ALL | READ_CLEAR => {
            if len < 0 {
                return Err(EINVAL);
            }
            if action == READ_CLEAR && !privileged() {
                return Err(super::errno::EPERM);
            }
            let text = crate::log::contents();
            // The newest `len` bytes.
            let n = text.len().min(len as usize);
            copy_to_user(buf, &text[text.len() - n..]).map_err(|_| EFAULT)?;
            if action == READ_CLEAR {
                crate::log::clear();
            }
            Ok(n as u64)
        }
        CLEAR => {
            if !privileged() {
                return Err(super::errno::EPERM);
            }
            crate::log::clear();
            Ok(0)
        }
        CONSOLE_OFF..=CONSOLE_LEVEL => Ok(0),
        SIZE_UNREAD => Ok(crate::log::unread() as u64),
        SIZE_BUFFER => Ok(crate::log::RING_SIZE as u64),
        _ => Err(EINVAL),
    }
}

/// sethostname(2): CAP_SYS_ADMIN over the UTS namespace, at most 64
/// bytes (HOST_NAME_MAX).
pub fn sethostname(a: Args) -> Result {
    let p = proc::current().ok_or(ESRCH)?;
    if !p.cred().ns_capable(&p.namespaces().uts.owner, crate::proc::cred::CAP_SYS_ADMIN) {
        return Err(super::errno::EPERM);
    }
    let len = a.0[1] as usize;
    if len > UTS_FIELD - 1 {
        return Err(EINVAL);
    }
    let mut name = vec![0u8; len];
    crate::arch::uaccess::copy_from_user(&mut name, a.0[0]).map_err(|_| EFAULT)?;
    *p.namespaces().uts.hostname.lock() = name;
    Ok(0)
}

/// prlimit64(2) (and getrlimit(2), setrlimit(2)): read and set a
/// process's resource limits. Another process's need CAP_SYS_RESOURCE, or
/// its real, effective and saved IDs all being the caller's real ones;
/// raising a hard limit needs CAP_SYS_RESOURCE.
pub fn prlimit64(a: Args) -> Result {
    use proc::rlimit::*;
    let [pid, resource, new, old, ..] = a.0;
    let resource = resource as usize;
    if resource >= RLIM_NLIMITS {
        return Err(EINVAL);
    }
    let me = proc::current().ok_or(ESRCH)?;
    let target = if pid as u32 == 0 { me.clone() } else { proc::find_in_caller_ns(pid as u32).ok_or(ESRCH)? };
    let mine = me.cred();
    if !alloc::sync::Arc::ptr_eq(&target, &me) && !mine.capable(crate::proc::cred::CAP_SYS_RESOURCE) {
        let c = target.cred();
        let uids = [c.ruid, c.euid, c.suid].iter().all(|&u| u == mine.ruid);
        let gids = [c.rgid, c.egid, c.sgid].iter().all(|&g| g == mine.rgid);
        if !uids || !gids {
            return Err(super::errno::EPERM);
        }
    }
    let new = if new != 0 { Some(crate::arch::uaccess::read_user::<Rlimit>(new).map_err(|_| EFAULT)?) } else { None };
    let cur = target.rlimit(resource);
    if let Some(n) = new {
        if n.cur > n.max {
            return Err(EINVAL);
        }
        if n.max > cur.max && !mine.capable(crate::proc::cred::CAP_SYS_RESOURCE) {
            return Err(super::errno::EPERM);
        }
        if resource == RLIMIT_NOFILE && n.max != RLIM_INFINITY && n.max > NR_OPEN
            || resource == RLIMIT_NOFILE && n.max == RLIM_INFINITY
        {
            return Err(super::errno::EPERM);
        }
    }
    if old != 0 {
        write_user(old, &cur).map_err(|_| EFAULT)?;
    }
    if let Some(n) = new {
        target.set_rlimit(resource, n);
    }
    Ok(0)
}

/// setrlimit(2).
pub fn setrlimit(a: Args) -> Result {
    prlimit64(Args([0, a.0[0], a.0[1], 0, 0, 0]))
}

// getpriority(2) `which`. Source: musl `sys/resource.h` (ADR 0009).
const PRIO_PROCESS: u64 = 0;
const PRIO_PGRP: u64 = 1;
const PRIO_USER: u64 = 2;

/// A thread with its process.
type ThreadOf = (alloc::sync::Arc<proc::Process>, alloc::sync::Arc<crate::sched::Thread>);

/// The threads getpriority(2) and setpriority(2) name. PRIO_PROCESS names
/// one thread on Linux (the nice value is per thread); the others every
/// thread of the matching processes.
fn priority_targets(which: u64, who: u32) -> core::result::Result<alloc::vec::Vec<ThreadOf>, super::Errno> {
    let me = proc::current().ok_or(ESRCH)?;
    let out: alloc::vec::Vec<_> = match which {
        PRIO_PROCESS if who == 0 => vec![(me, crate::sched::current())],
        PRIO_PROCESS => vec![find_thread(0, u64::from(who))?],
        PRIO_PGRP | PRIO_USER => {
            let (pgid, uid) = match which {
                PRIO_PGRP if who == 0 => (me.pgid.load(Ordering::Relaxed), 0),
                PRIO_PGRP => (proc::pgid_in(who), 0),
                _ if who == 0 => (0, me.cred().ruid),
                _ => (0, me.cred().uid_in(who)?),
            };
            proc::all()
                .into_iter()
                .filter(|p| !p.is_zombie() && proc::visible(p))
                .filter(
                    |p| if which == PRIO_PGRP { p.pgid.load(Ordering::Relaxed) == pgid } else { p.cred().ruid == uid },
                )
                .flat_map(|p| p.threads().into_iter().map(move |t| (p.clone(), t)))
                .collect()
        }
        _ => return Err(EINVAL),
    };
    if out.is_empty() { Err(ESRCH) } else { Ok(out) }
}

/// getpriority(2): the system call returns 20 - nice (1 to 40), the best
/// of the targets.
pub fn getpriority(a: Args) -> Result {
    let targets = priority_targets(a.0[0], a.0[1] as u32)?;
    let nice = targets.iter().map(|(_, t)| t.sched_params().2).min().unwrap_or(0);
    Ok((20 - i64::from(nice)) as u64)
}

/// May the caller change `p`'s scheduling (setpriority(2),
/// sched_setscheduler(2))? The same user, or CAP_SYS_NICE.
fn may_reschedule(p: &proc::Process) -> bool {
    let mine = crate::proc::cred::current();
    let theirs = p.cred();
    mine.euid == theirs.ruid || mine.euid == theirs.euid || mine.capable(crate::proc::cred::CAP_SYS_NICE)
}

/// Whether the caller may raise a priority: CAP_SYS_NICE, or the target's
/// RLIMIT_NICE (`nice`) or RLIMIT_RTPRIO (`rt`) allows it.
fn may_raise(p: &proc::Process, nice: Option<i8>, rt: Option<u8>) -> bool {
    use proc::rlimit::{RLIMIT_NICE, RLIMIT_RTPRIO};
    if crate::proc::cred::current().capable(crate::proc::cred::CAP_SYS_NICE) {
        return true;
    }
    let nice_ok = nice.is_none_or(|n| 20 - i64::from(n) <= p.rlimit(RLIMIT_NICE).cur.min(40) as i64);
    let rt_ok = rt.is_none_or(|r| u64::from(r) <= p.rlimit(RLIMIT_RTPRIO).cur);
    nice_ok && rt_ok
}

// ioprio_set(2): IOPRIO_WHO_PROCESS, _PGRP and _USER (getpriority's
// PRIO_* plus one); the classes NONE, RT, BE and IDLE in the bits from 13,
// the level (0 to 7) below.
const IOPRIO_CLASS_SHIFT: u32 = 13;
const IOPRIO_CLASS_RT: u32 = 1;
const IOPRIO_CLASS_BE: u32 = 2;
const IOPRIO_CLASS_IDLE: u32 = 3;

/// A thread's I/O priority as ioprio_get(2) compares them: one without a
/// class of its own is best-effort at the level its nice value implies
/// ((nice + 20) / 5, as Linux was seen to report: 4 at nice 0). Lower
/// ranks first: real-time, best-effort, idle, then the level.
fn ioprio_effective(t: &crate::sched::Thread) -> u32 {
    let v = t.ioprio.load(Ordering::Relaxed);
    if v >> IOPRIO_CLASS_SHIFT != 0 {
        return v;
    }
    let level = ((i32::from(t.sched_params().2) + 20) / 5) as u32;
    (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | level.min(7)
}

/// ioprio_get(2): one thread's own value, or the highest priority among a
/// group's or a user's (ADR 0115).
pub fn ioprio_get(a: Args) -> Result {
    let which = a.0[0];
    if !(1..=3).contains(&which) {
        return Err(EINVAL);
    }
    let targets = priority_targets(which - 1, a.0[1] as u32)?;
    if which == 1 {
        return Ok(u64::from(targets[0].1.ioprio.load(Ordering::Relaxed)));
    }
    let best = targets.iter().map(|(_, t)| ioprio_effective(t)).min().unwrap_or(0);
    Ok(u64::from(best))
}

/// ioprio_set(2): kept per thread; the real-time class needs
/// CAP_SYS_ADMIN, another user's threads CAP_SYS_NICE (EPERM).
pub fn ioprio_set(a: Args) -> Result {
    let which = a.0[0];
    let value = a.0[2] as u32;
    let (class, level) = (value >> IOPRIO_CLASS_SHIFT, value & ((1 << IOPRIO_CLASS_SHIFT) - 1));
    if !(1..=3).contains(&which) || class > IOPRIO_CLASS_IDLE || level > 7 || a.0[2] >> 16 != 0 {
        return Err(EINVAL);
    }
    let cred = crate::proc::cred::current();
    if class == IOPRIO_CLASS_RT && !cred.capable(crate::proc::cred::CAP_SYS_ADMIN) {
        return Err(EPERM);
    }
    let targets = priority_targets(which - 1, a.0[1] as u32)?;
    for (p, t) in &targets {
        if !may_reschedule(p) {
            return Err(EPERM);
        }
        t.ioprio.store(value, Ordering::Relaxed);
    }
    Ok(0)
}

/// setpriority(2): set the nice value (clamped to -20..19). Lowering it
/// needs CAP_SYS_NICE or RLIMIT_NICE (EACCES).
pub fn setpriority(a: Args) -> Result {
    let nice = (a.0[2] as i32).clamp(-20, 19) as i8;
    let targets = priority_targets(a.0[0], a.0[1] as u32)?;
    for (p, t) in &targets {
        if !may_reschedule(p) {
            return Err(super::errno::EPERM);
        }
        let (policy, prio, old, reset) = t.sched_params();
        if nice < old && !may_raise(p, Some(nice), None) {
            return Err(super::errno::EACCES);
        }
        crate::sched::set_params(t, policy, prio, nice, reset);
    }
    Ok(0)
}

pub fn getrandom(a: Args) -> Result {
    let len = (a.0[1] as usize).min(1 << 20);
    let mut buf = vec![0u8; len];
    crate::random::fill(&mut buf);
    copy_to_user(a.0[0], &buf).map_err(|_| EFAULT)?;
    Ok(len as u64)
}

// --- process lifecycle ----------------------------------------------------

use super::errno::EPERM;
use super::fs::user_path;
use crate::arch::trap::TrapFrame;
use crate::proc::signal as sig;
use crate::proc::{WCONTINUED, WNOHANG, WUNTRACED, WaitFor};

/// clone(2) flags. Source: musl `sched.h` (ADR 0009).
use crate::proc::{CLONE_THREAD, CLONE_VFORK, CLONE_VM};

pub fn fork(frame: &TrapFrame) -> Result {
    Ok(u64::from(proc::pid_out(proc::fork(frame, false)?.pid)))
}

pub fn vfork(frame: &TrapFrame) -> Result {
    Ok(u64::from(proc::pid_out(proc::fork(frame, true)?.pid)))
}

/// clone(2): x86-64 argument order is (flags, stack, parent_tid,
/// child_tid, tls). CLONE_THREAD makes a thread; otherwise it is a fork
/// (CLONE_VM only together with CLONE_VFORK, as posix_spawn uses it).
pub fn clone(a: Args, frame: &TrapFrame) -> Result {
    let [flags, stack, ptid, ctid, tls, _] = a.0;
    do_clone(frame, flags, stack, ptid, ctid, tls)
}

fn do_clone(frame: &TrapFrame, flags: u64, stack: u64, ptid: u64, ctid: u64, tls: u64) -> Result {
    if flags & CLONE_THREAD != 0 {
        return proc::clone_thread(frame, flags, stack, ptid, ctid, tls);
    }
    if flags & CLONE_VM != 0 && flags & CLONE_VFORK == 0 {
        return Err(super::errno::ENOSYS);
    }
    let a = Args([flags, stack, 0, 0, 0, 0]);
    let mut f = frame.clone();
    if a.0[1] != 0 {
        f.rsp = a.0[1]; // child stack
    }
    if flags & proc::ns::ALL & !proc::ns::CLONE_NEWUSER != 0 && !ns_capable(flags) {
        return Err(super::errno::EPERM);
    }
    let child = proc::fork_with(
        &f,
        flags & CLONE_VFORK != 0,
        flags & proc::ns::ALL,
        flags & proc::CLONE_FILES != 0,
        flags & proc::CLONE_FS != 0,
    )?;
    // clone(2) returns the child's PID as the caller's namespace sees it.
    let pid = proc::pid_in_caller_ns(child.pid).unwrap_or(0);
    let _ = (ptid, ctid);
    Ok(u64::from(pid))
}

/// Creating namespaces other than user namespaces needs CAP_SYS_ADMIN in
/// the caller's user namespace, unless a new user namespace is created
/// along with them (which grants it).
fn ns_capable(flags: u64) -> bool {
    flags & proc::ns::CLONE_NEWUSER != 0 || crate::proc::cred::current().has(crate::proc::cred::CAP_SYS_ADMIN)
}

/// unshare(2): move the caller into new namespaces of the kinds in
/// `flags` (CLONE_NEWPID only affects its future children).
pub fn unshare(a: Args) -> Result {
    let flags = a.0[0];
    // New namespaces would let a confined app change what paths mean (ADR
    // 0130); sharing less of its own state is fine.
    if flags & !(proc::CLONE_FS | proc::CLONE_FILES) != 0 {
        crate::proc::apps::unconfined()?;
    }
    let p = proc::current().ok_or(ESRCH)?;
    // A new mount namespace implies an fs of its own (unshare(2)).
    if flags & (proc::CLONE_FS | proc::ns::CLONE_NEWNS) != 0 {
        p.unshare_fs();
    }
    if flags & proc::ns::ALL == 0 {
        return Ok(0); // CLONE_FILES/FS/SYSVSEM: nothing is shared to undo yet.
    }
    if flags & proc::ns::ALL & !proc::ns::CLONE_NEWUSER != 0 && !ns_capable(flags) {
        return Err(super::errno::EPERM);
    }
    if flags & proc::ns::CLONE_NEWUSER != 0 && p.threads().len() > 1 {
        return Err(EINVAL);
    }
    let u = p.namespaces().unshare(flags & proc::ns::ALL, &p.cred(), &p.cgroup())?;
    if flags & proc::ns::CLONE_NEWNS != 0 {
        *u.ns.mnt.root.lock() = Some(p.root_dir());
    }
    p.set_namespaces(u.ns);
    if let Some(c) = u.cred {
        p.set_cred(c);
    }
    Ok(0)
}

/// setns(2): join the namespace a /proc/<pid>/ns file names.
pub fn setns(a: Args) -> Result {
    crate::proc::apps::unconfined()?;
    let p = proc::current().ok_or(ESRCH)?;
    let f = p.files.lock().get(a.fd(0))?;
    let target = f.namespace().ok_or(EINVAL)?;
    let want = a.0[1];
    let cred = p.cred();
    let mut n = p.namespaces();
    use crate::fs::NsRef;
    use crate::proc::cred::CAP_SYS_ADMIN;
    // Joining needs CAP_SYS_ADMIN over the namespace's owner, and in the
    // caller's own user namespace for mount namespaces (setns(2)).
    let kind = match target {
        NsRef::Uts(x) => {
            n.uts = x;
            proc::ns::CLONE_NEWUTS
        }
        NsRef::Ipc(x) => {
            n.ipc = x;
            proc::ns::CLONE_NEWIPC
        }
        NsRef::Mnt(x) => {
            n.mnt = x;
            proc::ns::CLONE_NEWNS
        }
        NsRef::Net(x) => {
            n.net = x;
            proc::ns::CLONE_NEWNET
        }
        NsRef::Pid(x) => {
            n.pid_for_children = x;
            proc::ns::CLONE_NEWPID
        }
        NsRef::Cgroup(x) => {
            n.cgroup = x;
            proc::ns::CLONE_NEWCGROUP
        }
        NsRef::User(x) => {
            // Joining a user namespace: CAP_SYS_ADMIN in it, never our own
            // (EINVAL), and only single-threaded; full capabilities there.
            if want != 0 && want != proc::ns::CLONE_NEWUSER {
                return Err(EINVAL);
            }
            if alloc::sync::Arc::ptr_eq(&x, &cred.user_ns) || p.threads().len() > 1 {
                return Err(EINVAL);
            }
            if !cred.ns_capable(&x, CAP_SYS_ADMIN) {
                return Err(super::errno::EPERM);
            }
            let mut c = (*cred).clone();
            c.user_ns = x;
            c.cap_effective = crate::proc::cred::CAP_FULL;
            c.cap_permitted = crate::proc::cred::CAP_FULL;
            p.set_cred(c);
            return Ok(0);
        }
    };
    if want != 0 && want != kind {
        return Err(EINVAL);
    }
    let new_owner = match kind {
        proc::ns::CLONE_NEWUTS => n.uts.owner.clone(),
        proc::ns::CLONE_NEWIPC => n.ipc.owner.clone(),
        proc::ns::CLONE_NEWNS => n.mnt.owner.clone(),
        proc::ns::CLONE_NEWNET => n.net.owner.clone(),
        proc::ns::CLONE_NEWPID => n.pid_for_children.owner.clone(),
        _ => n.cgroup.owner.clone(),
    };
    if !cred.ns_capable(&new_owner, CAP_SYS_ADMIN) || (kind == proc::ns::CLONE_NEWNS && !cred.has(CAP_SYS_ADMIN)) {
        return Err(super::errno::EPERM);
    }
    let joined_mnt = kind == proc::ns::CLONE_NEWNS;
    p.set_namespaces(n);
    if joined_mnt {
        // Joining a mount namespace moves the root and working directory
        // to its root.
        let r = p.namespaces().mnt.root.lock().clone().unwrap_or_else(crate::fs::vfs::root);
        p.set_root_dir(r.clone());
        p.set_cwd(r);
    }
    Ok(0)
}

/// Read a NULL-terminated array of string pointers (argv/envp).
fn user_strings(addr: u64) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, super::Errno> {
    let mut out = alloc::vec::Vec::new();
    if addr == 0 {
        return Ok(out);
    }
    let mut total = 0;
    for i in 0.. {
        let ptr: u64 = crate::arch::uaccess::read_user(addr + i * 8).map_err(|_| EFAULT)?;
        if ptr == 0 {
            break;
        }
        let s = crate::arch::uaccess::read_user_cstr(ptr, 128 * 1024).map_err(|_| EFAULT)?;
        total += s.len() + 1;
        if total > 128 * 1024 || i > 32 * 1024 {
            return Err(super::errno::E2BIG);
        }
        out.push(s);
    }
    Ok(out)
}

/// `sizeof(struct robust_list_head)` (get_robust_list(2)): three words.
const ROBUST_LIST_HEAD_SIZE: u64 = 24;

/// set_robust_list(2): remember the list head (the list is not yet walked
/// when the thread dies: a GAP).
/// rseq(2): the calling thread's restartable-sequence area (ADR 0115).
pub fn rseq(a: Args) -> Result {
    crate::proc::rseq::rseq(a.0[0], a.0[1], a.0[2], a.0[3] as u32)
}

pub fn set_robust_list(a: Args) -> Result {
    if a.0[1] != ROBUST_LIST_HEAD_SIZE {
        return Err(EINVAL);
    }
    crate::sched::current().robust_list.store(a.0[0], Ordering::Relaxed);
    Ok(0)
}

/// get_robust_list(2): the list head of thread `pid` (0: the caller).
pub fn get_robust_list(a: Args) -> Result {
    let head = if a.0[0] == 0 {
        crate::sched::current().robust_list.load(Ordering::Relaxed)
    } else {
        let ns = proc::caller_pid_ns();
        let t = proc::all()
            .into_iter()
            .find_map(|p| p.threads().into_iter().find(|t| p.tid_in(t.tid, &ns) == Some(a.0[0])))
            .ok_or(ESRCH)?;
        t.robust_list.load(Ordering::Relaxed)
    };
    write_user(a.0[1], &head).map_err(|_| EFAULT)?;
    write_user(a.0[2], &ROBUST_LIST_HEAD_SIZE).map_err(|_| EFAULT)?;
    Ok(0)
}

// close_range(2) flags. Source: the man page.
const CLOSE_RANGE_UNSHARE: u64 = 2;
const CLOSE_RANGE_CLOEXEC: u64 = 4;

/// close_range(2). The descriptor table is never shared between
/// processes, so CLOSE_RANGE_UNSHARE has nothing to undo.
pub fn close_range(a: Args) -> Result {
    let (first, last, flags) = (a.0[0] as u32, a.0[1] as u32, a.0[2]);
    if first > last || flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    let p = proc::current().ok_or(ESRCH)?;
    let closed = p.files.lock().close_range(first as usize, last as usize, flags & CLOSE_RANGE_CLOEXEC != 0);
    drop(closed);
    Ok(0)
}

/// A pidfd (pidfd_open(2)): refers to a process; readable once it has
/// exited.
struct PidFd {
    proc: alloc::sync::Arc<proc::Process>,
    flags: u32,
}

impl crate::fs::File for PidFd {
    fn poll(&self) -> u16 {
        if self.proc.is_zombie() || self.proc.exiting().is_some() { crate::fs::POLLIN } else { 0 }
    }
    fn status_flags(&self) -> u32 {
        self.flags
    }
    fn stat(&self) -> core::result::Result<crate::fs::vfs::Metadata, super::Errno> {
        Ok(crate::fs::vfs::Metadata { mode: 0o600, nlink: 1, ..Default::default() })
    }
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

/// The process behind pidfd `fd`.
fn pidfd_process(fd: i32) -> core::result::Result<alloc::sync::Arc<proc::Process>, super::Errno> {
    let p = proc::current().ok_or(ESRCH)?;
    let files = p.files.lock();
    let f = files.peek(fd).ok_or(super::errno::EBADF)?;
    f.as_any().and_then(|a| a.downcast_ref::<PidFd>()).map(|x| x.proc.clone()).ok_or(EINVAL)
}

/// pidfd_open(2): PIDFD_NONBLOCK is O_NONBLOCK.
pub fn pidfd_open(a: Args) -> Result {
    let flags = a.0[1] as u32;
    if flags & !crate::fs::O_NONBLOCK != 0 {
        return Err(EINVAL);
    }
    let target = proc::find_in_caller_ns(a.0[0] as u32).ok_or(ESRCH)?;
    let f = alloc::sync::Arc::new(PidFd { proc: target, flags: crate::fs::O_RDWR | flags });
    Ok(proc::current().ok_or(ESRCH)?.files.lock().insert(f, true)? as u64)
}

/// pidfd_send_signal(2): kill(2) by pidfd, or with the caller's siginfo
/// as rt_sigqueueinfo(2) sends it; no flags.
pub fn pidfd_send_signal(a: Args) -> Result {
    let target = pidfd_process(a.fd(0))?;
    let signo = a.0[1] as u32;
    if signo > sig::NSIG || a.0[3] != 0 {
        return Err(EINVAL);
    }
    if target.is_zombie() {
        return Err(ESRCH);
    }
    let me = proc::current().ok_or(ESRCH)?;
    let info = match a.0[2] {
        0 => sender_info(&me, &target, sig::SI_USER, 0),
        addr => queued_info(addr, &me, &target)?,
    };
    if !super::cred::may_signal(&me, &target, signo) {
        return Err(EPERM);
    }
    if signo != 0 {
        sig::send_with(&target, signo, info);
    }
    Ok(0)
}

// waitid(2) id types and options; siginfo codes for SIGCHLD. Source: the
// man pages (waitid(2), sigaction(2)).
const P_ALL: u64 = 0;
const P_PID: u64 = 1;
const P_PGID: u64 = 2;
const P_PIDFD: u64 = 3;
const WEXITED: u64 = 4;
const CLD_EXITED: i32 = 1;
const CLD_KILLED: i32 = 2;
const CLD_DUMPED: i32 = 3;
const CLD_STOPPED: i32 = 5;
const CLD_CONTINUED: i32 = 6;

/// waitid(2): fills a siginfo_t (signo, code, pid, uid, status).
pub fn waitid(a: Args) -> Result {
    let (idtype, id, infop, options) = (a.0[0], a.0[1], a.0[2], a.0[3]);
    let which = match idtype {
        P_ALL => WaitFor::Any,
        P_PID => WaitFor::Pid(proc::find_in_caller_ns(id as u32).ok_or(super::errno::ECHILD)?.pid),
        P_PGID => {
            let g = if id == 0 {
                proc::current().ok_or(ESRCH)?.pgid.load(Ordering::Relaxed)
            } else {
                proc::pgid_in(id as u32)
            };
            WaitFor::Group(g)
        }
        P_PIDFD => WaitFor::Pid(pidfd_process(id as i32)?.pid),
        _ => return Err(EINVAL),
    };
    let known = WNOHANG | WUNTRACED | WCONTINUED | proc::WNOWAIT;
    if options & (WEXITED | u64::from(WUNTRACED | WCONTINUED)) == 0 || options & !(WEXITED | u64::from(known)) != 0 {
        return Err(EINVAL);
    }
    let (pid, status, used) = proc::wait_child(which, options as u32 & known)?;
    // The kernel's waitid takes a struct rusage as a fifth argument.
    if a.0[4] != 0 {
        write_user(a.0[4], &Rusage::from(used)).map_err(|_| EFAULT)?;
    }
    let (code, value) = match status {
        _ if pid == 0 => (0, 0),
        0xFFFF => (CLD_CONTINUED, sig::SIGCONT as i32),
        s if s & 0xFF == 0x7F => (CLD_STOPPED, (s >> 8) & 0xFF),
        s if s & 0x7F == 0 => (CLD_EXITED, (s >> 8) & 0xFF),
        s if s & 0x80 != 0 => (CLD_DUMPED, s & 0x7F),
        s => (CLD_KILLED, s & 0x7F),
    };
    if infop != 0 {
        // siginfo_t: si_signo, si_errno, si_code, then (at 16) si_pid,
        // si_uid, si_status. Unused bytes are zero.
        let mut info = [0u8; 128];
        if pid != 0 {
            info[..4].copy_from_slice(&(sig::SIGCHLD as i32).to_ne_bytes());
            info[8..12].copy_from_slice(&code.to_ne_bytes());
            info[16..20].copy_from_slice(&(pid as i32).to_ne_bytes());
            info[24..28].copy_from_slice(&value.to_ne_bytes());
        }
        copy_to_user(infop, &info).map_err(|_| EFAULT)?;
    }
    Ok(0)
}

// seccomp(2) operations and flags. Source: the man page.
const SECCOMP_SET_MODE_STRICT: u64 = 0;
const SECCOMP_SET_MODE_FILTER: u64 = 1;
const SECCOMP_GET_ACTION_AVAIL: u64 = 2;
const SECCOMP_GET_NOTIF_SIZES: u64 = 3;
const SECCOMP_FILTER_FLAG_TSYNC: u64 = 1;
const SECCOMP_FILTER_FLAG_LOG: u64 = 2;
const SECCOMP_FILTER_FLAG_SPEC_ALLOW: u64 = 4;
const SECCOMP_FILTER_FLAG_TSYNC_ESRCH: u64 = 16;

/// seccomp(2).
pub fn seccomp(op: u64, flags: u64, args: u64) -> Result {
    use crate::proc::seccomp::{self as sc, Filter, MODE_FILTER, MODE_STRICT};
    let p = proc::current().ok_or(ESRCH)?;
    match op {
        SECCOMP_SET_MODE_STRICT => {
            if flags != 0 || args != 0 {
                return Err(EINVAL);
            }
            let mut s = p.seccomp.lock();
            if s.mode == MODE_FILTER {
                return Err(EINVAL);
            }
            s.mode = MODE_STRICT;
            sc::IN_USE.store(true, Ordering::Release);
            Ok(0)
        }
        SECCOMP_SET_MODE_FILTER => {
            let known = SECCOMP_FILTER_FLAG_TSYNC
                | SECCOMP_FILTER_FLAG_LOG
                | SECCOMP_FILTER_FLAG_SPEC_ALLOW
                | SECCOMP_FILTER_FLAG_TSYNC_ESRCH;
            if flags & !known != 0 {
                return Err(EINVAL); // NEW_LISTENER: no user notification (a GAP).
            }
            // Unprivileged filters need no_new_privs (seccomp(2) EACCES).
            let cred = p.cred();
            if !cred.no_new_privs && !cred.has(crate::proc::cred::CAP_SYS_ADMIN) {
                return Err(super::errno::EACCES);
            }
            // struct sock_fprog { unsigned short len; struct sock_filter *filter; }
            let len: u16 = crate::arch::uaccess::read_user(args).map_err(|_| EFAULT)?;
            let ptr: u64 = crate::arch::uaccess::read_user(args + 8).map_err(|_| EFAULT)?;
            let len = usize::from(len);
            if len == 0 || len > slate_bpf::CBPF_MAX_INSNS {
                return Err(EINVAL);
            }
            let mut raw = vec![0u8; len * 8];
            crate::arch::uaccess::copy_from_user(&mut raw, ptr).map_err(|_| EFAULT)?;
            let prog: alloc::vec::Vec<slate_bpf::SockFilter> = raw
                .chunks(8)
                .map(|c| slate_bpf::SockFilter::from_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]))
                .collect();
            slate_bpf::check_cbpf(&prog, sc::DATA_LEN).map_err(|_| EINVAL)?;
            let mut s = p.seccomp.lock();
            if s.mode == MODE_STRICT {
                return Err(EINVAL);
            }
            let total: usize = s.filters.iter().map(|f| f.prog.len() + 4).sum::<usize>() + len;
            if total > sc::MAX_TOTAL_INSNS {
                return Err(super::errno::ENOMEM);
            }
            s.filters.push(alloc::sync::Arc::new(Filter { prog, log: flags & SECCOMP_FILTER_FLAG_LOG != 0 }));
            s.mode = MODE_FILTER;
            sc::IN_USE.store(true, Ordering::Release);
            Ok(0)
        }
        SECCOMP_GET_ACTION_AVAIL => {
            let action: u32 = crate::arch::uaccess::read_user(args).map_err(|_| EFAULT)?;
            match action {
                sc::RET_KILL_PROCESS
                | sc::RET_KILL_THREAD
                | sc::RET_TRAP
                | sc::RET_ERRNO
                | sc::RET_TRACE
                | sc::RET_LOG
                | sc::RET_ALLOW => Ok(0),
                _ => Err(super::errno::EOPNOTSUPP),
            }
        }
        SECCOMP_GET_NOTIF_SIZES => {
            // struct seccomp_notif_sizes: notif, notif_resp, data.
            write_user(args, &[80u16, 24, 64]).map_err(|_| EFAULT)?;
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

/// Apply the calling process's seccomp state to system call `nr`: `None`
/// to go ahead, else the result to return without running it.
pub fn seccomp_check(nr: u64, a: &Args, ip: u64) -> Option<Result> {
    use crate::proc::seccomp::{Verdict, judge};
    let p = proc::current()?;
    let verdict = {
        let s = p.seccomp.lock();
        if s.mode == 0 {
            return None;
        }
        judge(&s, nr, &a.0, ip)
    };
    match verdict {
        Verdict::Allow => None,
        Verdict::Errno(e) => Some(Err(super::Errno(i32::from(e)))),
        Verdict::NoSys => Some(Err(super::errno::ENOSYS)),
        Verdict::Trap(data) => {
            // SIGSYS with si_code SYS_SECCOMP (1), the call's address, its
            // number and AUDIT_ARCH_X86_64, and the filter's SECCOMP_RET_DATA
            // as si_errno (sigaction(2), seccomp(2)); sandboxes use the data
            // to pick the routine that emulates the call. The call is not
            // run: RAX keeps its number, as the handler (which may emulate
            // the call and put a result there) expects.
            let extra = (nr & 0xFFFF_FFFF) | (u64::from(crate::proc::seccomp::AUDIT_ARCH_X86_64) << 32);
            crate::proc::signal::force_signal_with(sig::SIGSYS, 1, ip, extra, i32::from(data));
            Some(Ok(nr))
        }
        Verdict::KillThread => {
            drop(p);
            proc::exit_thread(proc::wait_status_signaled(sig::SIGSYS as i32))
        }
        Verdict::KillProcess => {
            drop(p);
            proc::exit_current(proc::wait_status_signaled(sig::SIGSYS as i32))
        }
    }
}

// membarrier(2) commands. Source: membarrier(2).
const MEMBARRIER_CMD_QUERY: u64 = 0;
const MEMBARRIER_CMD_GLOBAL: u64 = 1;
const MEMBARRIER_CMD_GLOBAL_EXPEDITED: u64 = 2;
const MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED: u64 = 4;
const MEMBARRIER_CMD_PRIVATE_EXPEDITED: u64 = 8;
const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED: u64 = 16;
const MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE: u64 = 32;
const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: u64 = 64;

/// membarrier(2): an interrupt on every CPU running the threads concerned
/// (this process's, or every CPU for the global commands) is a full
/// barrier and serializes the core. Registration is accepted and not
/// required.
pub fn membarrier(a: Args) -> Result {
    let supported = MEMBARRIER_CMD_GLOBAL
        | MEMBARRIER_CMD_GLOBAL_EXPEDITED
        | MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED
        | MEMBARRIER_CMD_PRIVATE_EXPEDITED
        | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
        | MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE
        | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE;
    match a.0[0] {
        MEMBARRIER_CMD_QUERY => Ok(supported),
        // Every CPU flushes and acknowledges before this returns.
        MEMBARRIER_CMD_GLOBAL | MEMBARRIER_CMD_GLOBAL_EXPEDITED => {
            crate::arch::tlb_shootdown(crate::arch::paging::kernel_root());
            Ok(0)
        }
        MEMBARRIER_CMD_PRIVATE_EXPEDITED | MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE => {
            proc::shootdown(&*proc::current().ok_or(ESRCH)?);
            Ok(0)
        }
        MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED
        | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
        | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE => Ok(0),
        _ => Err(EINVAL),
    }
}

// execveat(2) flags. Source: musl `fcntl.h`.
const AT_EMPTY_PATH: u64 = 0x1000;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;

/// execveat(2): `path` relative to directory `dirfd`, or with AT_EMPTY_PATH
/// and an empty path the file `dirfd` itself (fexecve(3)).
pub fn execveat(a: Args, frame: &mut TrapFrame) -> Result {
    let p = proc::current().ok_or(ESRCH)?;
    let (dirfd, flags) = (a.0[0] as i32, a.0[4]);
    if flags & !(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) != 0 {
        return Err(EINVAL);
    }
    let path = user_path(a.0[1])?;
    if path.is_empty() && flags & AT_EMPTY_PATH == 0 {
        return Err(super::errno::ENOENT);
    }
    // An absolute path ignores dirfd (execveat(2)).
    let base = if (dirfd == super::fs::AT_FDCWD || path.starts_with('/')) && !path.is_empty() {
        p.cwd()
    } else {
        let f = p.files.lock().get(dirfd)?;
        f.dentry().ok_or(super::errno::EBADF)?
    };
    drop(p);
    let argv = user_strings(a.0[2])?;
    let envp = user_strings(a.0[3])?;
    let argv: alloc::vec::Vec<&[u8]> = argv.iter().map(|v| v.as_slice()).collect();
    let envp: alloc::vec::Vec<&[u8]> = envp.iter().map(|v| v.as_slice()).collect();
    let image = proc::execve_at(&base, path.as_bytes(), &argv, &envp)?;
    proc::begin_image(frame, image);
    Ok(0)
}

pub fn execve(a: Args, frame: &mut TrapFrame) -> Result {
    let path = user_path(a.0[0])?;
    let argv = user_strings(a.0[1])?;
    let envp = user_strings(a.0[2])?;
    let argv: alloc::vec::Vec<&[u8]> = argv.iter().map(|v| v.as_slice()).collect();
    let envp: alloc::vec::Vec<&[u8]> = envp.iter().map(|v| v.as_slice()).collect();
    let image = proc::execve(path.as_bytes(), &argv, &envp)?;
    proc::begin_image(frame, image);
    Ok(0)
}

// waitpid(2) options besides WNOHANG, WUNTRACED and WCONTINUED: __WNOTHREAD,
// __WALL and __WCLONE (accepted). Source: musl `sys/wait.h`.
const WAIT_LINUX_FLAGS: u32 = 0x2000_0000 | 0x4000_0000 | 0x8000_0000;

pub fn wait4(a: Args) -> Result {
    // Unknown options are EINVAL, children or not (waitpid(2)).
    if a.0[2] as u32 & !(WNOHANG | WUNTRACED | WCONTINUED | WAIT_LINUX_FLAGS) != 0 {
        return Err(EINVAL);
    }
    let (child, status, used) = wait_pid(a.0[0] as i32, a.0[2] as u32)?;
    if child != 0 && a.0[1] != 0 {
        write_user(a.0[1], &status).map_err(|_| EFAULT)?;
    }
    if a.0[3] != 0 {
        write_user(a.0[3], &Rusage::from(used)).map_err(|_| EFAULT)?;
    }
    Ok(u64::from(child))
}

/// Wait as waitpid(2) does for `pid` (-1 any child, 0 the caller's
/// group, < -1 group -pid); `options` are WNOHANG, WUNTRACED and
/// WCONTINUED. Returns the child (0 for none with WNOHANG), its Linux
/// wait status and what it used.
pub(crate) fn wait_pid(pid: i32, options: u32) -> core::result::Result<(u32, i32, proc::Usage), super::Errno> {
    let which = match pid {
        -1 => WaitFor::Any,
        0 => WaitFor::Group(proc::current().ok_or(ESRCH)?.pgid.load(Ordering::Relaxed)),
        p if p < -1 => WaitFor::Group(proc::pgid_in(p.unsigned_abs())),
        p => WaitFor::Pid(proc::find_in_caller_ns(p as u32).map_or(0, |c| c.pid)),
    };
    proc::wait_child(which, options & (WNOHANG | WUNTRACED | WCONTINUED))
}

pub fn kill(a: Args) -> Result {
    let (pid, signo) = (a.0[0] as i32, a.0[1] as u32);
    if signo > sig::NSIG {
        return Err(EINVAL);
    }
    let me = proc::current().ok_or(ESRCH)?;
    // Signal every process `pick` selects that we may signal; signal 0 only
    // checks. ESRCH if none matched, EPERM if none could be signaled.
    let send = |pick: &dyn Fn(&proc::Process) -> bool| -> Result {
        let (mut found, mut sent) = (0, 0);
        for p in proc::all() {
            if p.is_zombie() || !proc::visible(&p) || !pick(&p) {
                continue;
            }
            found += 1;
            if super::cred::may_signal(&me, &p, signo) {
                sent += 1;
                if signo != 0 {
                    let pid = me.pid_in(&p.pid_ns()).unwrap_or(0);
                    let uid = p.cred().uid_out(me.cred().ruid);
                    sig::send_from_process(&p, signo, pid, uid);
                }
            }
        }
        match (found, sent) {
            (0, _) => Err(ESRCH),
            (_, 0) => Err(EPERM),
            _ => Ok(0),
        }
    };
    let ns = me.pid_ns();
    match pid {
        p if p > 0 => {
            let host = proc::find_in_caller_ns(p as u32).ok_or(ESRCH)?.pid;
            send(&|t| t.pid == host)
        }
        0 => {
            let g = me.pgid.load(Ordering::Relaxed);
            send(&|t| t.pgid.load(Ordering::Relaxed) == g)
        }
        // Everyone but the caller and its namespace's init.
        -1 => send(&|t| t.pid_in(&ns).is_some_and(|l| l > 1) && t.pid != me.pid),
        p => {
            let g = proc::pgid_in(p.unsigned_abs());
            send(&|t| t.pgid.load(Ordering::Relaxed) == g)
        }
    }
}

/// tgkill(2)/tkill(2): with one thread per process, the tid is the pid.
/// Find the thread `tid` (in thread group `tgid`, or anywhere if 0).
fn find_thread(
    tgid: u32,
    tid: u64,
) -> core::result::Result<(alloc::sync::Arc<proc::Process>, alloc::sync::Arc<crate::sched::Thread>), super::Errno> {
    let candidates = if tgid != 0 { proc::find_in_caller_ns(tgid).into_iter().collect() } else { proc::all() };
    let ns = proc::caller_pid_ns();
    for p in candidates {
        if let Some(t) = p.threads().into_iter().find(|t| p.tid_in(t.tid, &ns) == Some(tid)) {
            return Ok((p, t));
        }
    }
    Err(ESRCH)
}

pub fn tgkill(a: Args) -> Result {
    let (tgid, tid, signo) = (a.0[0] as i32, a.0[1] as i32, a.0[2] as u32);
    if tgid <= 0 || tid <= 0 || signo > sig::NSIG {
        return Err(EINVAL);
    }
    let (p, t) = find_thread(tgid as u32, tid as u64)?;
    let me = proc::current().ok_or(ESRCH)?;
    if !super::cred::may_signal(&me, &p, signo) {
        return Err(EPERM);
    }
    if signo != 0 {
        sig::send_to_thread_with(&p, &t, signo, sender_info(&me, &p, sig::SI_TKILL, 0));
    }
    Ok(0)
}

/// siginfo for a signal `me` sends `p`: `code`, and its PID and real UID
/// as `p` sees them.
fn sender_info(me: &proc::Process, p: &proc::Process, code: i32, value: u64) -> sig::Info {
    let pid = me.pid_in(&p.pid_ns()).unwrap_or(0);
    sig::Info { code, pid, uid: p.cred().uid_out(me.cred().ruid), value }
}

/// `siginfo_t`'s head as rt_sigqueueinfo(2) reads it: signo, errno, code,
/// then si_pid, si_uid and si_value (sigaction(2)).
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct QueuedInfo {
    signo: i32,
    errno: i32,
    code: i32,
    _pad: i32,
    pid: u32,
    uid: u32,
    value: u64,
}

/// What rt_sigqueueinfo(2) and rt_tgsigqueueinfo(2) send: the caller's
/// siginfo, whose si_code must be a user one (negative, not SI_TKILL)
/// unless it signals itself (EPERM).
fn queued_info(addr: u64, me: &proc::Process, target: &proc::Process) -> core::result::Result<sig::Info, super::Errno> {
    let q: QueuedInfo = crate::arch::uaccess::read_user(addr).map_err(|_| EFAULT)?;
    if (q.code >= 0 || q.code == sig::SI_TKILL) && me.pid != target.pid {
        return Err(EPERM);
    }
    Ok(sig::Info { code: q.code, pid: q.pid, uid: q.uid, value: q.value })
}

/// rt_sigqueueinfo(2): `sig` with the caller's siginfo to process `tgid`.
pub fn rt_sigqueueinfo(a: Args) -> Result {
    let (tgid, signo) = (a.0[0] as i32, a.0[1] as u32);
    if tgid <= 0 || signo > sig::NSIG {
        return Err(EINVAL);
    }
    let p = proc::find_in_caller_ns(tgid as u32).filter(|p| !p.is_zombie()).ok_or(ESRCH)?;
    let me = proc::current().ok_or(ESRCH)?;
    let info = queued_info(a.0[2], &me, &p)?;
    if !super::cred::may_signal(&me, &p, signo) {
        return Err(EPERM);
    }
    if signo != 0 {
        sig::send_with(&p, signo, info);
    }
    Ok(0)
}

/// rt_tgsigqueueinfo(2): the same to one thread.
pub fn rt_tgsigqueueinfo(a: Args) -> Result {
    let (tgid, tid, signo) = (a.0[0] as i32, a.0[1] as i32, a.0[2] as u32);
    if tgid <= 0 || tid <= 0 || signo > sig::NSIG {
        return Err(EINVAL);
    }
    let (p, t) = find_thread(tgid as u32, tid as u64)?;
    let me = proc::current().ok_or(ESRCH)?;
    let info = queued_info(a.0[3], &me, &p)?;
    if !super::cred::may_signal(&me, &p, signo) {
        return Err(EPERM);
    }
    if signo != 0 {
        sig::send_to_thread_with(&p, &t, signo, info);
    }
    Ok(0)
}

/// rt_sigtimedwait(2): take a pending signal of `set` (the thread's own
/// first) with its siginfo, waiting for one until the timeout (EAGAIN);
/// another signal that interrupts is EINTR. The set is unblocked while
/// waiting so that its signals wake the thread, as Linux does it.
pub fn rt_sigtimedwait(a: Args) -> Result {
    let [set_addr, info_addr, timeout, size, ..] = a.0;
    if size != 8 {
        return Err(EINVAL);
    }
    let set = sig::read_sigset(set_addr)? & !(sig::bit(sig::SIGKILL) | sig::bit(sig::SIGSTOP));
    let deadline = super::fs::deadline_from_timespec(timeout)?;
    let p = proc::current().ok_or(ESRCH)?;
    let t = crate::sched::current();
    let take = || sig::take_thread_signal(&t, set).or_else(|| sig::take_process_signal(&p, set));
    let mut got = take();
    let mut timed_out = false;
    if got.is_none() {
        let old = t.signal_mask();
        t.set_signal_mask(old & !set);
        let ready = || (t.pending_signals() | p.signals.pending()) & set != 0;
        let q = crate::sched::wait::WaitQueue::new();
        let r = match deadline {
            Some(d) => q.wait_until_deadline(ready, d),
            None => {
                q.wait_until_interruptible(ready);
                crate::sched::wait::WaitResult::Ready
            }
        };
        t.set_signal_mask(old);
        got = take();
        timed_out = r == crate::sched::wait::WaitResult::TimedOut;
    }
    match got {
        Some((signo, info)) => {
            if info_addr != 0 {
                sig::write_siginfo(info_addr, signo, info)?;
            }
            Ok(u64::from(signo))
        }
        None if timed_out => Err(super::errno::EAGAIN),
        None => Err(super::errno::EINTR),
    }
}

pub fn tkill(a: Args) -> Result {
    let (tid, signo) = (a.0[0] as i32, a.0[1] as u32);
    if tid <= 0 || signo > sig::NSIG {
        return Err(EINVAL);
    }
    let (p, t) = find_thread(0, tid as u64)?;
    let me = proc::current().ok_or(ESRCH)?;
    if !super::cred::may_signal(&me, &p, signo) {
        return Err(EPERM);
    }
    if signo != 0 {
        sig::send_to_thread_with(&p, &t, signo, sender_info(&me, &p, sig::SI_TKILL, 0));
    }
    Ok(0)
}

/// `struct clone_args` (clone3(2)), the fields we use.
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
}

/// clone3(2): like clone, with the stack given as base and size.
pub fn clone3(a: Args, frame: &TrapFrame) -> Result {
    if (a.0[1] as usize) < size_of::<CloneArgs>() {
        return Err(EINVAL);
    }
    let c: CloneArgs = crate::arch::uaccess::read_user(a.0[0]).map_err(|_| EFAULT)?;
    let top = if c.stack != 0 { c.stack + c.stack_size } else { 0 };
    do_clone(frame, c.flags, top, c.parent_tid, c.child_tid, c.tls)
}

pub fn futex(a: Args) -> Result {
    use crate::proc::futex::*;
    let [uaddr, op, val, timeout, uaddr2, val3] = a.0;
    let p = proc::current().ok_or(ESRCH)?;
    let private = op as u32 & FUTEX_PRIVATE_FLAG != 0;
    let cmd = op as u32 & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    let deadline = |absolute: bool| -> core::result::Result<Option<u64>, super::Errno> {
        if timeout == 0 {
            return Ok(None);
        }
        #[derive(Clone, Copy, Default)]
        #[repr(C)]
        struct Ts {
            sec: i64,
            nsec: i64,
        }
        let ts: Ts = crate::arch::uaccess::read_user(timeout).map_err(|_| EFAULT)?;
        if ts.sec < 0 || !(0..1_000_000_000).contains(&ts.nsec) {
            return Err(EINVAL);
        }
        let ns = (ts.sec as u64).saturating_mul(1_000_000_000).saturating_add(ts.nsec as u64);
        let now = crate::time::monotonic_ns();
        Ok(Some(if absolute {
            // FUTEX_WAIT_BITSET deadlines are absolute; on CLOCK_REALTIME
            // convert to the monotonic clock.
            if op as u32 & FUTEX_CLOCK_REALTIME != 0 {
                let rt = crate::time::realtime_ns().max(0) as u64;
                now.saturating_add(ns.saturating_sub(rt))
            } else {
                ns
            }
        } else {
            now.saturating_add(ns)
        }))
    };
    let r = match cmd {
        FUTEX_WAIT => wait(&p, uaddr, val as u32, FUTEX_BITSET_MATCH_ANY, private, deadline(false)?),
        FUTEX_WAIT_BITSET => wait(&p, uaddr, val as u32, val3 as u32, private, deadline(true)?),
        FUTEX_WAKE => wake(&p, uaddr, val as u32, FUTEX_BITSET_MATCH_ANY, private),
        FUTEX_WAKE_BITSET => wake(&p, uaddr, val as u32, val3 as u32, private),
        // Negative counts are EINVAL (as Linux was seen to refuse them).
        FUTEX_REQUEUE | FUTEX_CMP_REQUEUE if (val as i32) < 0 || (timeout as i32) < 0 => Err(EINVAL),
        FUTEX_REQUEUE => requeue(&p, uaddr, val as u32, timeout as u32, uaddr2, None, private),
        FUTEX_CMP_REQUEUE => requeue(&p, uaddr, val as u32, timeout as u32, uaddr2, Some(val3 as u32), private),
        FUTEX_WAKE_OP => wake_op(&p, uaddr, val as u32, timeout as u32, uaddr2, val3 as u32, private),
        // FUTEX_LOCK_PI's timeout is absolute on CLOCK_REALTIME; LOCK_PI2's
        // on CLOCK_MONOTONIC unless FUTEX_CLOCK_REALTIME says otherwise.
        FUTEX_LOCK_PI => {
            let d = if timeout == 0 {
                None
            } else {
                let ts: [i64; 2] = crate::arch::uaccess::read_user(timeout).map_err(|_| EFAULT)?;
                if ts[0] < 0 || !(0..1_000_000_000).contains(&ts[1]) {
                    return Err(EINVAL);
                }
                let at = i128::from(ts[0]) * 1_000_000_000 + i128::from(ts[1]);
                let left = (at - crate::time::realtime_ns()).max(0) as u64;
                Some(crate::time::monotonic_ns().saturating_add(left))
            };
            lock_pi(&p, uaddr, private, d, false)
        }
        FUTEX_LOCK_PI2 => lock_pi(&p, uaddr, private, deadline(true)?, false),
        FUTEX_TRYLOCK_PI => lock_pi(&p, uaddr, private, None, true),
        FUTEX_UNLOCK_PI => unlock_pi(&p, uaddr, private),
        _ => Err(super::errno::ENOSYS),
    };
    // An interrupted wait restarts unless a handler ran (futex(2)).
    match r {
        Err(e) if e == super::errno::EINTR && timeout == 0 => Err(sig::ERESTARTSYS),
        r => r,
    }
}

/// chroot(2).
pub fn chroot(a: Args) -> Result {
    chroot_at(super::fs::AT_FDCWD, &super::fs::user_path(a.0[0])?)
}

pub(crate) fn chroot_at(dirfd: i32, path: &str) -> Result {
    crate::proc::apps::unconfined()?;
    let p = proc::current().ok_or(ESRCH)?;
    if !p.cred().has(crate::proc::cred::CAP_SYS_CHROOT) {
        return Err(EPERM);
    }
    let d = crate::fs::vfs::resolve(&super::fs::dir_for(&p, dirfd, path)?, path, true)?;
    if !d.is_dir() {
        return Err(super::errno::ENOTDIR);
    }
    p.set_root_dir(d);
    Ok(0)
}

pub fn getppid() -> Result {
    Ok(u64::from(proc::pid_out(proc::current().ok_or(ESRCH)?.ppid())))
}

pub fn getpgid(a: Args) -> Result {
    let p = if a.0[0] == 0 { proc::current() } else { proc::find_in_caller_ns(a.0[0] as u32) }.ok_or(ESRCH)?;
    Ok(u64::from(proc::pid_out(p.pgid.load(Ordering::Relaxed))))
}

pub fn getsid(a: Args) -> Result {
    let p = if a.0[0] == 0 { proc::current() } else { proc::find_in_caller_ns(a.0[0] as u32) }.ok_or(ESRCH)?;
    Ok(u64::from(proc::pid_out(p.sid.load(Ordering::Relaxed))))
}

/// setpgid(2): EINVAL for a negative group; ESRCH unless the target is
/// the caller or its child; EPERM for a child in another session, a
/// session leader, or a group not in the target's session.
pub fn setpgid(a: Args) -> Result {
    if (a.0[1] as i32) < 0 {
        return Err(EINVAL);
    }
    let me = proc::current().ok_or(ESRCH)?;
    let target = if a.0[0] == 0 { me.clone() } else { proc::find_in_caller_ns(a.0[0] as u32).ok_or(ESRCH)? };
    if target.pid != me.pid && target.ppid() != me.pid {
        return Err(ESRCH);
    }
    let sid = target.sid.load(Ordering::Relaxed);
    if sid != me.sid.load(Ordering::Relaxed) {
        return Err(EPERM);
    }
    let pgid = if a.0[1] == 0 { target.pid } else { proc::pgid_in(a.0[1] as u32) };
    if pgid == 0 {
        return Err(EPERM);
    }
    if sid == target.pid && target.pid != pgid {
        return Err(EPERM); // A session leader cannot change group.
    }
    // Another group must exist in the same session.
    if pgid != target.pid
        && !proc::all().iter().any(|q| q.pgid.load(Ordering::Relaxed) == pgid && q.sid.load(Ordering::Relaxed) == sid)
    {
        return Err(EPERM);
    }
    target.pgid.store(pgid, Ordering::Relaxed);
    Ok(0)
}

pub fn setsid() -> Result {
    let me = proc::current().ok_or(ESRCH)?;
    if me.pgid.load(Ordering::Relaxed) == me.pid {
        return Err(EPERM); // Already a group leader.
    }
    me.sid.store(me.pid, Ordering::Relaxed);
    me.pgid.store(me.pid, Ordering::Relaxed);
    me.set_ctty(None);
    Ok(u64::from(proc::pid_out(me.pid)))
}

// --- signals --------------------------------------------------------------

pub fn rt_sigaction(a: Args) -> Result {
    let (signo, act, old) = (a.0[0] as u32, a.0[1], a.0[2]);
    if signo == 0 || signo > sig::NSIG || a.0[3] != 8 {
        return Err(EINVAL);
    }
    let p = proc::current().ok_or(ESRCH)?;
    if old != 0 {
        write_user(old, &p.signals.action(signo)).map_err(|_| EFAULT)?;
    }
    if act != 0 {
        if signo == sig::SIGKILL || signo == sig::SIGSTOP {
            return Err(EINVAL);
        }
        let new: sig::SigAction = crate::arch::uaccess::read_user(act).map_err(|_| EFAULT)?;
        p.signals.set_action(signo, new);
    }
    Ok(0)
}

pub fn rt_sigprocmask(a: Args) -> Result {
    let (how, set, old) = (a.0[0], a.0[1], a.0[2]);
    if a.0[3] != 8 {
        return Err(EINVAL);
    }
    let t = crate::sched::current();
    let cur = t.signal_mask();
    if old != 0 {
        write_user(old, &cur).map_err(|_| EFAULT)?;
    }
    if set != 0 {
        let s = sig::read_sigset(set)?;
        let new = match how {
            sig::SIG_BLOCK => cur | s,
            sig::SIG_UNBLOCK => cur & !s,
            sig::SIG_SETMASK => s,
            _ => return Err(EINVAL),
        };
        t.set_signal_mask(new & !(sig::bit(sig::SIGKILL) | sig::bit(sig::SIGSTOP)));
    }
    Ok(0)
}

pub fn rt_sigpending(a: Args) -> Result {
    let t = crate::sched::current();
    let p = proc::current().ok_or(ESRCH)?;
    let pending = (t.pending_signals() | p.signals.pending()) & t.signal_mask();
    write_user(a.0[0], &pending).map_err(|_| EFAULT)?;
    Ok(0)
}

pub fn rt_sigreturn(frame: &mut TrapFrame) -> Result {
    sig::sigreturn(frame)?;
    // The restored rax is the interrupted context's; return it unchanged.
    Ok(frame.rax)
}

/// rt_sigsuspend(2): wait for a signal with a temporary mask; the old
/// mask comes back when the handler returns (it is saved in the frame).
pub fn rt_sigsuspend(a: Args) -> Result {
    let mask = sig::read_sigset(a.0[0])?;
    let t = crate::sched::current();
    t.save_mask_for_delivery(t.signal_mask());
    t.set_signal_mask(mask & !(sig::bit(sig::SIGKILL) | sig::bit(sig::SIGSTOP)));
    let q = crate::sched::wait::WaitQueue::new();
    q.wait_until_interruptible(|| false);
    Err(super::errno::EINTR)
}

pub fn pause() -> Result {
    let q = crate::sched::wait::WaitQueue::new();
    q.wait_until_interruptible(|| false);
    Err(super::errno::EINTR)
}

/// `struct sysinfo` (sysinfo(2)).
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Sysinfo {
    uptime: i64,
    loads: [u64; 3],
    totalram: u64,
    freeram: u64,
    sharedram: u64,
    bufferram: u64,
    totalswap: u64,
    freeswap: u64,
    procs: u16,
    _pad: u16,
    totalhigh: u64,
    freehigh: u64,
    mem_unit: u32,
    _reserved: [u8; 4],
}

pub fn sysinfo(a: Args) -> Result {
    let s = crate::mm::frame::stats();
    // Load averages in fixed point with SI_LOAD_SHIFT (16) fraction bits
    // (musl `sys/sysinfo.h`).
    let loads = crate::sched::load_average().map(|l| l << (16 - crate::sched::LOAD_FRACTION_BITS));
    let si = Sysinfo {
        uptime: (crate::time::monotonic_ns() / 1_000_000_000) as i64,
        loads,
        totalram: s.usable_frames * 4096,
        freeram: s.free_frames * 4096,
        procs: proc::all().len() as u16,
        mem_unit: 1,
        ..Default::default()
    };
    write_user(a.0[0], &si).map_err(|_| EFAULT)?;
    Ok(0)
}

/// The clock_t unit of times(2) (USER_HZ, 100 on x86-64 Linux;
/// sysconf(_SC_CLK_TCK)).
const USER_HZ: u64 = 100;

/// `struct rusage` (getrusage(2)): two timevals, then ru_maxrss (KiB),
/// ru_ixrss, ru_idrss, ru_isrss (unused on Linux), ru_minflt, ru_majflt,
/// ru_nswap (unused), ru_inblock, ru_oublock (512-byte units), ru_msgsnd,
/// ru_msgrcv, ru_nsignals (unused), ru_nvcsw and ru_nivcsw.
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Rusage {
    utime: [i64; 2],
    stime: [i64; 2],
    maxrss: i64,
    unused_rss: [i64; 3],
    minflt: i64,
    majflt: i64,
    nswap: i64,
    inblock: i64,
    oublock: i64,
    unused_msg: [i64; 3],
    nvcsw: i64,
    nivcsw: i64,
}

impl From<proc::Usage> for Rusage {
    fn from(u: proc::Usage) -> Rusage {
        let tv = |t: u64| [(t / 1_000_000_000) as i64, (t % 1_000_000_000 / 1000) as i64];
        let [minflt, majflt, inblock, oublock, nvcsw, nivcsw] = u.counts.map(|c| c as i64);
        Rusage {
            utime: tv(u.user),
            stime: tv(u.system),
            maxrss: (u.maxrss_pages * (crate::mm::PAGE_SIZE / 1024)) as i64,
            minflt,
            majflt,
            inblock,
            oublock,
            nvcsw,
            nivcsw,
            ..Default::default()
        }
    }
}

// getrusage(2) `who`. Source: musl `sys/resource.h`.
const RUSAGE_SELF: i32 = 0;
const RUSAGE_CHILDREN: i32 = -1;
const RUSAGE_THREAD: i32 = 1;

pub fn getrusage(a: Args) -> Result {
    let p = proc::current().ok_or(ESRCH)?;
    crate::sched::update_current_times();
    let used = match a.0[0] as i32 {
        RUSAGE_SELF => p.usage(),
        RUSAGE_CHILDREN => p.cpu.children_usage(),
        // The thread's own times and counts; the resident set is the
        // process's, as on Linux.
        RUSAGE_THREAD => {
            let t = crate::sched::current();
            let (user, system) = t.cpu_ns();
            proc::Usage { user, system, maxrss_pages: p.usage().maxrss_pages, counts: t.counts.get() }
        }
        _ => return Err(EINVAL),
    };
    write_user(a.0[1], &Rusage::from(used)).map_err(|_| EFAULT)?;
    Ok(0)
}

/// times(2): `struct tms` in clock ticks; returns the elapsed time.
pub fn times(a: Args) -> Result {
    if a.0[0] != 0 {
        let p = proc::current().ok_or(ESRCH)?;
        crate::sched::update_current_times();
        let ((u, s), (cu, cs)) = (p.cpu.own(), p.cpu.children());
        let tms = [u, s, cu, cs].map(|t| t / (1_000_000_000 / USER_HZ));
        write_user(a.0[0], &tms).map_err(|_| EFAULT)?;
    }
    Ok(crate::time::monotonic_ns() / (1_000_000_000 / USER_HZ))
}

// reboot(2) magic and commands. Source: musl `sys/reboot.h` (RB_*) and
// reboot(2) for the magic numbers.
pub(crate) const REBOOT_MAGIC1: u64 = 0xfee1_dead;
pub(crate) const REBOOT_MAGIC2: u64 = 672_274_793;
pub(crate) const RB_AUTOBOOT: u64 = 0x0123_4567;
pub(crate) const RB_HALT_SYSTEM: u64 = 0xcdef_0123;
pub(crate) const RB_POWER_OFF: u64 = 0x4321_fedc;
/// LINUX_REBOOT_CMD_CAD_ON / CAD_OFF (reboot(2)).
pub(crate) const RB_ENABLE_CAD: u64 = 0x89ab_cdef;
pub(crate) const RB_DISABLE_CAD: u64 = 0;

pub fn reboot(a: Args) -> Result {
    if !crate::proc::cred::current().capable(crate::proc::cred::CAP_SYS_BOOT) {
        return Err(EPERM);
    }
    if a.0[0] != REBOOT_MAGIC1 || a.0[1] as u32 as u64 != REBOOT_MAGIC2 & 0xFFFF_FFFF {
        return Err(EINVAL);
    }
    match a.0[2] as u32 as u64 {
        // Disk file systems are written out and marked clean first.
        RB_AUTOBOOT => {
            crate::log_info!("reboot requested");
            crate::fs::shutdown();
            crate::arch::power::reboot();
        }
        RB_POWER_OFF | RB_HALT_SYSTEM => {
            crate::log_info!("power off requested");
            crate::fs::shutdown();
            crate::arch::power::power_off();
            crate::arch::halt_forever();
        }
        RB_ENABLE_CAD | RB_DISABLE_CAD => {
            crate::arch::power::set_ctrl_alt_del(a.0[2] as u32 as u64 == RB_ENABLE_CAD);
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

// Scheduling policies (sched(7)): SCHED_OTHER 0, SCHED_FIFO 1,
// SCHED_RR 2, SCHED_BATCH 3, SCHED_IDLE 5, SCHED_DEADLINE 6; the
// real-time ones take priorities 1-99. Source: musl `sched.h`.
const SCHED_OTHER: u64 = 0;
const SCHED_FIFO: u64 = 1;
const SCHED_RR: u64 = 2;
const SCHED_BATCH: u64 = 3;
const SCHED_IDLE: u64 = 5;
const SCHED_DEADLINE: u64 = 6;
/// sched_reset_on_fork, or-ed into the policy.
const SCHED_RESET_ON_FORK: u64 = 0x4000_0000;

/// The thread a sched_* call names (0: the caller).
fn sched_target(
    tid: u64,
) -> core::result::Result<(alloc::sync::Arc<proc::Process>, alloc::sync::Arc<crate::sched::Thread>), super::Errno> {
    if tid as i32 == 0 {
        return Ok((proc::current().ok_or(ESRCH)?, crate::sched::current()));
    }
    if (tid as i32) < 0 {
        return Err(EINVAL);
    }
    find_thread(0, tid)
}

/// sched_get_priority_max(2) and sched_get_priority_min(2).
pub fn sched_priority_range(policy: u64, max: bool) -> Result {
    match policy {
        SCHED_FIFO | SCHED_RR => Ok(if max { 99 } else { 1 }),
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE => Ok(0),
        _ => Err(EINVAL),
    }
}

/// sched_getparam(2): the real-time priority (0 for the normal policies).
pub fn sched_getparam(a: Args) -> Result {
    let (_, t) = sched_target(a.0[0])?;
    if a.0[1] == 0 {
        return Err(EINVAL);
    }
    write_user(a.0[1], &i32::from(t.sched_params().1)).map_err(|_| EFAULT)?;
    Ok(0)
}

/// sched_getscheduler(2): the policy, with SCHED_RESET_ON_FORK or-ed in.
pub fn sched_getscheduler(a: Args) -> Result {
    let (_, t) = sched_target(a.0[0])?;
    let (policy, _, _, reset) = t.sched_params();
    Ok(u64::from(policy) | if reset { SCHED_RESET_ON_FORK } else { 0 })
}

/// sched_rr_get_interval(2): SCHED_RR's slice, the normal slice for the
/// normal policies, 0 for SCHED_FIFO (which has none).
pub fn sched_rr_get_interval(a: Args) -> Result {
    let (_, t) = sched_target(a.0[0])?;
    let ms = match u64::from(t.sched_params().0) {
        SCHED_FIFO => 0,
        SCHED_RR => u64::from(crate::sched::policy::RR_SLICE_TICKS),
        _ => 10,
    };
    write_user(a.0[1], &[(ms / 1000) as i64, (ms % 1000 * 1_000_000) as i64]).map_err(|_| EFAULT)?;
    Ok(0)
}

/// sched_setscheduler(2) (`policy` None: sched_setparam(2), keeping the
/// policy). Real-time policies take priorities 1 to 99, the others 0.
/// Raising a priority needs CAP_SYS_NICE or RLIMIT_RTPRIO; SCHED_DEADLINE
/// is not offered (EINVAL; GAPS).
pub fn sched_setscheduler(tid: u64, policy: Option<u64>, param: u64) -> Result {
    if param == 0 {
        return Err(EINVAL);
    }
    let prio: i32 = crate::arch::uaccess::read_user(param).map_err(|_| EFAULT)?;
    // An unknown policy is EINVAL before the target is looked up.
    if let Some(p) = policy
        && !matches!(p & !SCHED_RESET_ON_FORK, SCHED_FIFO | SCHED_RR | SCHED_OTHER | SCHED_BATCH | SCHED_IDLE)
    {
        return Err(EINVAL);
    }
    let (p, t) = sched_target(tid)?;
    let (old_policy, old_prio, nice, old_reset) = t.sched_params();
    let (policy, reset) = match policy {
        Some(p) => (p & !SCHED_RESET_ON_FORK, p & SCHED_RESET_ON_FORK != 0),
        None => (u64::from(old_policy), old_reset),
    };
    match policy {
        SCHED_FIFO | SCHED_RR if (1..=99).contains(&prio) => {}
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE if prio == 0 => {}
        _ => return Err(EINVAL),
    }
    if !may_reschedule(&p) {
        return Err(super::errno::EPERM);
    }
    let rt = matches!(policy, SCHED_FIFO | SCHED_RR);
    let was_rt = matches!(u64::from(old_policy), SCHED_FIFO | SCHED_RR);
    let raising = rt && (!was_rt || prio > i32::from(old_prio));
    if raising && !may_raise(&p, None, Some(prio as u8)) {
        return Err(super::errno::EPERM);
    }
    // Clearing SCHED_RESET_ON_FORK is a privileged change (sched(7)).
    if old_reset && !reset && !crate::proc::cred::current().capable(crate::proc::cred::CAP_SYS_NICE) {
        return Err(super::errno::EPERM);
    }
    crate::sched::set_params(&t, policy as u8, prio as u8, nice, reset);
    crate::proc::futex::priority_changed(&t);
    Ok(0)
}

/// The thread sched_setaffinity(2) and sched_getaffinity(2) name (0: the
/// caller), and whether the caller may change it.
fn affinity_target(tid: u64) -> core::result::Result<alloc::sync::Arc<crate::sched::Thread>, super::Errno> {
    if tid == 0 {
        return Ok(crate::sched::current());
    }
    let (p, t) = find_thread(0, tid)?;
    let me = proc::current().ok_or(ESRCH)?;
    let (mine, theirs) = (me.cred(), p.cred());
    // sched_setaffinity(2): the same user, or CAP_SYS_NICE.
    if mine.euid != theirs.ruid && mine.euid != theirs.euid && !mine.capable(crate::proc::cred::CAP_SYS_NICE) {
        return Err(super::errno::EPERM);
    }
    Ok(t)
}

/// sched_setaffinity(2): the CPUs a thread may run on (Slate keeps up to
/// 64); a mask naming no online CPU is EINVAL.
pub fn sched_setaffinity(a: Args) -> Result {
    let t = affinity_target(a.0[0])?;
    let len = (a.0[1] as usize).min(8);
    let mut raw = [0u8; 8];
    crate::arch::uaccess::copy_from_user(&mut raw[..len], a.0[2]).map_err(|_| EFAULT)?;
    let mask = u64::from_le_bytes(raw) & crate::sched::online_mask();
    if mask == 0 {
        return Err(EINVAL);
    }
    crate::sched::set_affinity(&t, mask);
    Ok(0)
}

pub fn sched_getaffinity(a: Args) -> Result {
    let t = affinity_target(a.0[0])?;
    let mask = t.affinity.load(Ordering::Relaxed) & crate::sched::online_mask();
    let len = (a.0[1] as usize).min(8);
    if len == 0 {
        return Err(EINVAL);
    }
    copy_to_user(a.0[2], &mask.to_le_bytes()[..len]).map_err(|_| EFAULT)?;
    Ok(8)
}

/// get_mempolicy(2): Slate has one memory node, so the policy is always
/// the default (mode 0) and node 0 holds every page; the node mask, when
/// asked for, is empty for the default policy, or node 0 for the nodes
/// allowed (any flag).
pub fn get_mempolicy(a: Args) -> Result {
    let [mode, nodemask, maxnode, _addr, flags, _] = a.0;
    if mode != 0 {
        write_user(mode, &0i32).map_err(|_| EFAULT)?;
    }
    if nodemask != 0 && maxnode > 0 {
        let words = maxnode.div_ceil(64) as usize;
        let mut m = alloc::vec![0u64; words];
        if flags != 0 {
            m[0] = 1;
        }
        for (i, w) in m.iter().enumerate() {
            write_user(nodemask + 8 * i as u64, w).map_err(|_| EFAULT)?;
        }
    }
    Ok(0)
}

/// set_mempolicy(2) and mbind(2): with one memory node every policy
/// places pages the same way, so they are accepted.
pub fn set_mempolicy(_a: Args) -> Result {
    Ok(0)
}

// prctl(2) options. Source: musl `sys/prctl.h`.
const PR_SET_NAME: u64 = 15;
const PR_GET_NAME: u64 = 16;
// prctl(2) option values (linux/prctl.h, as the man page lists them).
const PR_SET_PDEATHSIG: u64 = 1;
const PR_GET_PDEATHSIG: u64 = 2;
const PR_GET_DUMPABLE: u64 = 3;
const PR_SET_DUMPABLE: u64 = 4;
const PR_GET_KEEPCAPS: u64 = 7;
const PR_SET_KEEPCAPS: u64 = 8;
const PR_CAPBSET_READ: u64 = 23;
const PR_CAPBSET_DROP: u64 = 24;
const PR_GET_SECCOMP: u64 = 21;
const PR_SET_SECCOMP: u64 = 22;
const PR_GET_SECUREBITS: u64 = 27;
const PR_SET_SECUREBITS: u64 = 28;
const PR_SET_CHILD_SUBREAPER: u64 = 36;
const PR_GET_CHILD_SUBREAPER: u64 = 37;
const PR_SET_NO_NEW_PRIVS: u64 = 38;
const PR_GET_NO_NEW_PRIVS: u64 = 39;
const PR_CAP_AMBIENT: u64 = 47;
// PR_CAP_AMBIENT operations.
const PR_CAP_AMBIENT_IS_SET: u64 = 1;
const PR_CAP_AMBIENT_RAISE: u64 = 2;
const PR_CAP_AMBIENT_LOWER: u64 = 3;
const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 4;

/// Change the caller's credentials with `f`.
fn update_cred(p: &proc::Process, f: impl FnOnce(&mut crate::proc::cred::Cred)) {
    let mut c = (*p.cred()).clone();
    f(&mut c);
    p.set_cred(c);
}

pub fn prctl(a: Args) -> Result {
    let p = proc::current().ok_or(ESRCH)?;
    match a.0[0] {
        // The name is per thread (prctl(2)); the main thread's is the
        // process's (/proc/<pid>/comm).
        PR_SET_NAME => {
            let name = crate::arch::uaccess::read_user_cstr(a.0[1], 4096).map_err(|_| EFAULT)?;
            let name: alloc::string::String = alloc::string::String::from_utf8_lossy(&name).chars().take(15).collect();
            let t = crate::sched::current();
            if t.tid == u64::from(p.pid) {
                *p.name.lock() = name;
            } else {
                *t.comm.lock() = Some(name);
            }
            Ok(0)
        }
        PR_GET_NAME => {
            let mut buf = [0u8; 16];
            let n = crate::sched::current().comm.lock().clone().unwrap_or_else(|| p.name.lock().clone());
            buf[..n.len().min(15)].copy_from_slice(&n.as_bytes()[..n.len().min(15)]);
            copy_to_user(a.0[1], &buf).map_err(|_| EFAULT)?;
            Ok(0)
        }
        PR_GET_KEEPCAPS => super::cred::keepcaps(None),
        PR_SET_KEEPCAPS => super::cred::keepcaps(Some(a.0[1] != 0)),
        PR_SET_PDEATHSIG => {
            if a.0[1] > u64::from(sig::NSIG) {
                return Err(EINVAL);
            }
            p.pdeath_signal.store(a.0[1] as u32, Ordering::Relaxed);
            Ok(0)
        }
        PR_GET_PDEATHSIG => {
            write_user(a.0[1], &(p.pdeath_signal.load(Ordering::Relaxed) as i32)).map_err(|_| EFAULT)?;
            Ok(0)
        }
        PR_GET_DUMPABLE => Ok(u64::from(p.dumpable.load(Ordering::Relaxed))),
        PR_SET_DUMPABLE => {
            if a.0[1] > 1 {
                return Err(EINVAL);
            }
            p.dumpable.store(a.0[1] == 1, Ordering::Relaxed);
            Ok(0)
        }
        PR_CAPBSET_READ => {
            if a.0[1] > u64::from(crate::proc::cred::CAP_LAST) {
                return Err(EINVAL);
            }
            Ok((p.cred().cap_bounding >> a.0[1]) & 1)
        }
        PR_CAPBSET_DROP => {
            if a.0[1] > u64::from(crate::proc::cred::CAP_LAST) {
                return Err(EINVAL);
            }
            if !p.cred().has(crate::proc::cred::CAP_SETPCAP) {
                return Err(EPERM);
            }
            update_cred(&p, |c| c.cap_bounding &= !(1 << a.0[1]));
            Ok(0)
        }
        // No securebits are kept (a GAP): reading gives none, setting needs
        // CAP_SETPCAP and is ignored.
        PR_GET_SECUREBITS => Ok(0),
        PR_SET_SECUREBITS => {
            if p.cred().has(crate::proc::cred::CAP_SETPCAP) {
                Ok(0)
            } else {
                Err(EPERM)
            }
        }
        PR_SET_CHILD_SUBREAPER => {
            p.subreaper.store(a.0[1] != 0, Ordering::Relaxed);
            Ok(0)
        }
        PR_GET_CHILD_SUBREAPER => {
            write_user(a.0[1], &i32::from(p.subreaper.load(Ordering::Relaxed))).map_err(|_| EFAULT)?;
            Ok(0)
        }
        PR_SET_NO_NEW_PRIVS => {
            if a.0[1] != 1 || a.0[2..5].iter().any(|x| *x != 0) {
                return Err(EINVAL);
            }
            update_cred(&p, |c| c.no_new_privs = true);
            Ok(0)
        }
        PR_GET_NO_NEW_PRIVS => Ok(u64::from(p.cred().no_new_privs)),
        PR_GET_SECCOMP => Ok(u64::from(p.seccomp.lock().mode)),
        // Mode 1 is strict, 2 a filter (prctl(2)); the same as seccomp(2).
        PR_SET_SECCOMP => match a.0[1] {
            1 => seccomp(SECCOMP_SET_MODE_STRICT, 0, 0),
            2 => seccomp(SECCOMP_SET_MODE_FILTER, 0, a.0[2]),
            _ => Err(EINVAL),
        },
        PR_CAP_AMBIENT => {
            let cap = a.0[2];
            let bit = if cap <= u64::from(crate::proc::cred::CAP_LAST) { 1u64 << cap } else { 0 };
            match a.0[1] {
                PR_CAP_AMBIENT_IS_SET if bit != 0 => Ok(u64::from(p.cred().cap_ambient & bit != 0)),
                PR_CAP_AMBIENT_RAISE if bit != 0 => {
                    let c = p.cred();
                    if c.cap_permitted & c.cap_inheritable & bit == 0 {
                        return Err(EPERM);
                    }
                    update_cred(&p, |c| c.cap_ambient |= bit);
                    Ok(0)
                }
                PR_CAP_AMBIENT_LOWER if bit != 0 => {
                    update_cred(&p, |c| c.cap_ambient &= !bit);
                    Ok(0)
                }
                PR_CAP_AMBIENT_CLEAR_ALL => {
                    update_cred(&p, |c| c.cap_ambient = 0);
                    Ok(0)
                }
                _ => Err(EINVAL),
            }
        }
        _ => Err(EINVAL),
    }
}

/// `struct itimerval` (setitimer(2)).
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Itimerval {
    interval_sec: i64,
    interval_usec: i64,
    value_sec: i64,
    value_usec: i64,
}

const ITIMER_REAL: u64 = 0;

fn tv_ns(sec: i64, usec: i64) -> u64 {
    (sec.max(0) as u64).saturating_mul(1_000_000_000).saturating_add(usec.clamp(0, 999_999) as u64 * 1000)
}

fn itimerval(remaining: u64, interval: u64) -> Itimerval {
    Itimerval {
        interval_sec: (interval / 1_000_000_000) as i64,
        interval_usec: (interval % 1_000_000_000 / 1000) as i64,
        value_sec: (remaining / 1_000_000_000) as i64,
        value_usec: (remaining % 1_000_000_000 / 1000) as i64,
    }
}

pub fn setitimer(a: Args) -> Result {
    if a.0[0] != ITIMER_REAL {
        return Err(EINVAL); // Virtual and profiling timers need CPU-time accounting.
    }
    let p = proc::current().ok_or(ESRCH)?;
    let new: Itimerval = crate::arch::uaccess::read_user(a.0[1]).map_err(|_| EFAULT)?;
    let (rem, int) =
        proc::set_real_timer(&p, tv_ns(new.value_sec, new.value_usec), tv_ns(new.interval_sec, new.interval_usec));
    if a.0[2] != 0 {
        write_user(a.0[2], &itimerval(rem, int)).map_err(|_| EFAULT)?;
    }
    Ok(0)
}

pub fn getitimer(a: Args) -> Result {
    if a.0[0] != ITIMER_REAL {
        return Err(EINVAL);
    }
    let p = proc::current().ok_or(ESRCH)?;
    let (rem, int) = proc::real_timer(&p);
    write_user(a.0[1], &itimerval(rem, int)).map_err(|_| EFAULT)?;
    Ok(0)
}

/// alarm(2): returns the seconds that were left on the previous alarm.
pub fn alarm(a: Args) -> Result {
    let p = proc::current().ok_or(ESRCH)?;
    let (rem, _) = proc::set_real_timer(&p, a.0[0].saturating_mul(1_000_000_000), 0);
    Ok(rem.div_ceil(1_000_000_000))
}
