// SPDX-License-Identifier: MIT OR Apache-2.0

//! Native process, signal, system, memory and time calls.

use alloc::vec::Vec;

use slate_abi::{ExecArgs, Ids, NO_ID, SigAction, WaitStatus, sigaction as sa, wait as w};

use super::{path, translate, user_strs};
use crate::abi::linux::errno::*;
use crate::abi::linux::{Args, Result, cred, fs as lfs, mem, process as lp, time};
use crate::arch::uaccess::{read_user, write_user};
use crate::proc::{self, signal as sig};

/// Total size of the argument and environment strings (as for execve).
const ARG_MAX: usize = 128 * 1024;

/// exec(dir, path, len, *ExecArgs, flags).
pub(super) fn exec(a: Args, frame: &mut crate::arch::trap::TrapFrame) -> Result {
    let flags = a.0[4] as u32;
    if flags & !slate_abi::path::EMPTY_PATH != 0 {
        return Err(EINVAL);
    }
    let path = path(a, 1)?;
    let args: ExecArgs = read_user(a.0[3]).map_err(|_| EFAULT)?;
    let p = proc::current().ok_or(ESRCH)?;
    let base = if path.is_empty() {
        if flags & slate_abi::path::EMPTY_PATH == 0 {
            return Err(ENOENT);
        }
        p.files.lock().get(a.fd(0))?.dentry().ok_or(EBADF)?
    } else {
        lfs::dir_for(&p, a.fd(0), &path)?
    };
    drop(p);
    let argv = user_strs(args.argv, args.argc, ARG_MAX)?;
    let envp = user_strs(args.envp, args.envc, ARG_MAX)?;
    let argv: Vec<&[u8]> = argv.iter().map(|v| v.as_slice()).collect();
    let envp: Vec<&[u8]> = envp.iter().map(|v| v.as_slice()).collect();
    let image = proc::execve_at(&base, path.as_bytes(), &argv, &envp)?;
    proc::begin_image(frame, image);
    Ok(0)
}

/// A Linux wait status (wait(2)) as a [`WaitStatus`].
fn wait_status(pid: u32, status: i32) -> WaitStatus {
    let (kind, code) = if status & 0x7F == 0 {
        (w::EXITED, (status >> 8) & 0xFF)
    } else if status == 0xFFFF {
        (w::CONTINUED_KIND, 0)
    } else if status & 0xFF == 0x7F {
        (w::STOPPED, (status >> 8) & 0xFF)
    } else if status & 0x80 != 0 {
        (w::DUMPED, status & 0x7F)
    } else {
        (w::KILLED, status & 0x7F)
    };
    WaitStatus { pid: pid as i32, kind, code, _reserved: 0 }
}

/// wait(pid, *WaitStatus, options).
pub(super) fn wait(a: Args) -> Result {
    // waitpid(2) options (musl `sys/wait.h`): WNOHANG 1, WUNTRACED 2,
    // WCONTINUED 8.
    let options = translate(a.0[2] as u32, &[(w::NOHANG, 1), (w::UNTRACED, 2), (w::CONTINUED, 8)])?;
    let (child, status, _) = lp::wait_pid(a.0[0] as i32, options as u32)?;
    if child != 0 && a.0[1] != 0 {
        write_user(a.0[1], &wait_status(child, status)).map_err(|_| EFAULT)?;
    }
    Ok(u64::from(child))
}

pub(super) fn getids(a: Args) -> Result {
    let c = proc::current().ok_or(ESRCH)?.cred();
    let ids = Ids {
        ruid: c.uid_out(c.ruid),
        euid: c.uid_out(c.euid),
        suid: c.uid_out(c.suid),
        rgid: c.gid_out(c.rgid),
        egid: c.gid_out(c.egid),
        sgid: c.gid_out(c.sgid),
    };
    write_user(a.0[0], &ids).map_err(|_| EFAULT)?;
    Ok(0)
}

/// setids(*Ids): the user and group IDs together, each change allowed
/// by the credentials the call started with (so a process giving up root
/// can still set its groups), and all or nothing: if one is refused,
/// nothing changes. Every thread's change (unlike Linux's calls).
pub(super) fn setids(a: Args) -> Result {
    let ids: Ids = read_user(a.0[0]).map_err(|_| EFAULT)?;
    let arg = |v: u32| u64::from(if v == NO_ID { u32::MAX } else { v });
    let given = |v: [u32; 3]| v.iter().any(|&i| i != NO_ID).then(|| v.map(arg));
    let p = proc::current().ok_or(ESRCH)?;
    let old = (*p.cred()).clone();
    let c = cred::res_ids(&old, given([ids.ruid, ids.euid, ids.suid]), given([ids.rgid, ids.egid, ids.sgid]))?;
    cred::commit_all(&p, &old, c);
    Ok(0)
}

// sigaction(2) flags without a constant in proc::signal (musl `signal.h`).
const SA_NOCLDSTOP: u64 = 1;
const SA_NOCLDWAIT: u64 = 2;
const SA_SIGINFO: u64 = 4;

const SIGACTION_FLAGS: &[(u32, u64)] = &[
    (sa::SIGINFO, SA_SIGINFO),
    (sa::RESTART, sig::SA_RESTART),
    (sa::NODEFER, sig::SA_NODEFER),
    (sa::RESETHAND, sig::SA_RESETHAND),
    (sa::ONSTACK, sig::SA_ONSTACK),
    (sa::NOCLDSTOP, SA_NOCLDSTOP),
    (sa::NOCLDWAIT, SA_NOCLDWAIT),
];

/// sigaction(signal, *new, *old).
pub(super) fn sigaction(a: Args) -> Result {
    let (signo, new, old) = (a.0[0] as u32, a.0[1], a.0[2]);
    if signo == 0 || signo > sig::NSIG {
        return Err(EINVAL);
    }
    let p = proc::current().ok_or(ESRCH)?;
    if old != 0 {
        let cur = p.signals.action(signo);
        let flags = SIGACTION_FLAGS.iter().filter(|(_, l)| cur.flags & l != 0).fold(0, |m, (n, _)| m | n);
        let out = SigAction { handler: cur.handler, flags, _reserved: 0, mask: cur.mask, restorer: cur.restorer };
        write_user(old, &out).map_err(|_| EFAULT)?;
    }
    if new != 0 {
        if signo == sig::SIGKILL || signo == sig::SIGSTOP {
            return Err(EINVAL);
        }
        let act: SigAction = read_user(new).map_err(|_| EFAULT)?;
        // A handler must say where it returns to.
        if act.handler != sa::DEFAULT && act.handler != sa::IGNORE && act.restorer == 0 {
            return Err(EINVAL);
        }
        let flags = translate(act.flags, SIGACTION_FLAGS)? | sig::SA_RESTORER;
        p.signals
            .set_action(signo, sig::SigAction { handler: act.handler, flags, restorer: act.restorer, mask: act.mask });
    }
    Ok(0)
}

pub(super) fn getrandom(a: Args) -> Result {
    // Random bytes never block on Slate, so NONBLOCK changes nothing.
    translate(a.0[2] as u32, &[(slate_abi::random::NONBLOCK, 0)])?;
    lp::getrandom(Args([a.0[0], a.0[1], 0, 0, 0, 0]))
}

pub(super) fn reboot(a: Args) -> Result {
    use slate_abi::reboot as r;
    let cmd = match a.0[0] as u32 {
        r::RESTART => lp::RB_AUTOBOOT,
        r::HALT => lp::RB_HALT_SYSTEM,
        r::POWER_OFF => lp::RB_POWER_OFF,
        r::CAD_ON => lp::RB_ENABLE_CAD,
        r::CAD_OFF => lp::RB_DISABLE_CAD,
        _ => return Err(EINVAL),
    };
    lp::reboot(Args([lp::REBOOT_MAGIC1, lp::REBOOT_MAGIC2, cmd, 0, 0, 0]))
}

/// klog(op, buf, len): syslog(2) actions READ_ALL 3, READ_CLEAR 4,
/// CLEAR 5, SIZE_BUFFER 10.
pub(super) fn klog(a: Args) -> Result {
    use slate_abi::klog as l;
    let action = match a.0[0] as u32 {
        l::READ_ALL => 3,
        l::CLEAR => 5,
        l::SIZE => 10,
        l::READ_CLEAR => 4,
        l::READ_FROM => return klog_from(a),
        _ => return Err(EINVAL),
    };
    lp::syslog(Args([action, a.0[1], a.0[2], 0, 0, 0]))
}

/// klog(READ_FROM, buf, len, *mut u64): root's, like reading the whole log.
fn klog_from(a: Args) -> Result {
    let c = proc::cred::current();
    if !c.capable(proc::cred::CAP_SYSLOG) && !c.capable(proc::cred::CAP_SYS_ADMIN) {
        return Err(EPERM);
    }
    let pos: u64 = read_user(a.0[3]).map_err(|_| EFAULT)?;
    let (text, next) = crate::log::read_from(pos as usize, a.0[2] as usize);
    crate::arch::uaccess::copy_to_user(a.0[1], &text).map_err(|_| EFAULT)?;
    write_user(a.0[3], &(next as u64)).map_err(|_| EFAULT)?;
    Ok(text.len() as u64)
}

/// service(op, ...): init's tags for the processes of each service (ADR
/// 0060). Only pid 1 may use it.
pub(super) fn service(a: Args) -> Result {
    use slate_abi::service as s;
    let me = proc::current().ok_or(ESRCH)?;
    if me.pid != 1 {
        return Err(EPERM);
    }
    let name = |ptr: u64, len: u64| -> core::result::Result<alloc::string::String, Errno> {
        if len == 0 || len as usize > s::NAME_MAX {
            return Err(EINVAL);
        }
        let mut b = alloc::vec![0u8; len as usize];
        crate::arch::uaccess::copy_from_user(&mut b, ptr).map_err(|_| EFAULT)?;
        alloc::string::String::from_utf8(b).ok().filter(|n| n.bytes().all(|c| c.is_ascii_graphic())).ok_or(EINVAL)
    };
    match a.0[0] as u32 {
        s::SET => {
            let n = name(a.0[2], a.0[3])?;
            let child = proc::get(a.0[1] as proc::Pid).ok_or(ESRCH)?;
            if child.ppid() != 1 {
                return Err(EPERM);
            }
            *child.service.lock() = Some(alloc::sync::Arc::from(n.as_str()));
            Ok(0)
        }
        s::KILL => {
            let n = name(a.0[1], a.0[2])?;
            let signal = a.0[3] as u32;
            if signal > sig::NSIG {
                return Err(EINVAL);
            }
            let mut count = 0;
            for p in proc::all() {
                if p.pid != 1 && !p.is_zombie() && p.service.lock().as_deref() == Some(n.as_str()) {
                    sig::send_to_process(&p, signal);
                    count += 1;
                }
            }
            Ok(count)
        }
        _ => Err(EINVAL),
    }
}

/// unshare(flags): Slate's namespace kinds, as unshare(2)'s.
pub(super) fn unshare(a: Args) -> Result {
    use slate_abi::ns as n;
    // clone(2)'s CLONE_NEW* bits (kernel/src/proc/ns.rs, from musl's sched.h).
    use crate::proc::ns as k;
    let flags = translate(
        a.0[0] as u32,
        &[
            (n::USER, k::CLONE_NEWUSER),
            (n::MOUNT, k::CLONE_NEWNS),
            (n::PID, k::CLONE_NEWPID),
            (n::UTS, k::CLONE_NEWUTS),
            (n::IPC, k::CLONE_NEWIPC),
            (n::NET, k::CLONE_NEWNET),
        ],
    )?;
    lp::unshare(Args([flags, 0, 0, 0, 0, 0]))
}

/// box_tag(name, len): the caller is a process of Linux box `name` (ADR
/// 0183). Set once and inherited; Slate-domain callers only (any program
/// with Slate's note makes native calls, whatever its domain), so no
/// Linux program can tag or untag itself.
pub(super) fn box_tag(a: Args) -> Result {
    let me = proc::current().ok_or(ESRCH)?;
    if me.domain() != crate::proc::domain::Domain::Slate {
        crate::log_info!("box_tag: refused to pid {} (not in the Slate domain)", me.pid);
        return Err(EPERM);
    }
    let len = a.0[1] as usize;
    if len == 0 || len > slate_abi::box_tag::NAME_MAX {
        return Err(EINVAL);
    }
    let mut b = alloc::vec![0u8; len];
    crate::arch::uaccess::copy_from_user(&mut b, a.0[0]).map_err(|_| EFAULT)?;
    if !b.iter().all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(c)) {
        return Err(EINVAL);
    }
    let name = core::str::from_utf8(&b).map_err(|_| EINVAL)?;
    let mut tag = me.box_tag.lock();
    if tag.is_some() {
        return Err(EEXIST);
    }
    *tag = Some(alloc::sync::Arc::from(name));
    Ok(0)
}

/// Native protections (the same bits as Linux's PROT_*, mmap(2)).
fn prot(p: u64) -> core::result::Result<u64, Errno> {
    if p & !7 != 0 { Err(EINVAL) } else { Ok(p) }
}

pub(super) fn map(a: Args) -> Result {
    use slate_abi::map as m;
    let flags = translate(
        a.0[3] as u32,
        &[
            (m::SHARED, mem::MAP_SHARED),
            (m::PRIVATE, mem::MAP_PRIVATE),
            (m::FIXED, mem::MAP_FIXED),
            (m::ANONYMOUS, mem::MAP_ANONYMOUS),
            // Memory is never reserved ahead, so NORESERVE changes nothing.
            (m::NORESERVE, 0),
            (m::FIXED_NOREPLACE, mem::MAP_FIXED_NOREPLACE),
        ],
    )?;
    if flags & (mem::MAP_SHARED | mem::MAP_PRIVATE) == mem::MAP_SHARED | mem::MAP_PRIVATE {
        return Err(EINVAL);
    }
    mem::mmap(Args([a.0[0], a.0[1], prot(a.0[2])?, flags, a.0[4], a.0[5]]))
}

pub(super) fn protect(a: Args) -> Result {
    mem::mprotect(Args([a.0[0], a.0[1], prot(a.0[2])?, 0, 0, 0]))
}

pub(super) fn clock_get(a: Args) -> Result {
    use slate_abi::clock as c;
    let clock = match a.0[0] as u32 {
        c::REALTIME => time::CLOCK_REALTIME,
        c::MONOTONIC => time::CLOCK_MONOTONIC,
        c::BOOTTIME => time::CLOCK_BOOTTIME,
        c::PROCESS_CPU => time::CLOCK_PROCESS_CPUTIME_ID,
        _ => return Err(EINVAL),
    };
    time::clock_gettime(Args([clock, a.0[1], 0, 0, 0, 0]))
}

/// clock_set(clock, *Timespec): the wall clock only.
pub(super) fn clock_set(a: Args) -> Result {
    if a.0[0] as u32 != slate_abi::clock::REALTIME {
        return Err(EINVAL);
    }
    time::clock_settime(Args([time::CLOCK_REALTIME, a.0[1], 0, 0, 0, 0]))
}

/// clock_adjust(delta_ns, flags, *mut i64): slew the wall clock (ADR 0078).
pub(super) fn clock_adjust(a: Args) -> Result {
    let [delta, flags, out, ..] = a.0;
    if flags & !slate_abi::clock_adjust::SYNCED != 0 {
        return Err(EINVAL);
    }
    let left = time::clock_adjust(delta as i64, flags & slate_abi::clock_adjust::SYNCED != 0)?;
    if out != 0 {
        write_user(out, &left).map_err(|_| EFAULT)?;
    }
    Ok(0)
}

/// setids_of(pid, *Ids, groups, count): the privilege broker hands out
/// authority without set-user-ID programs (ADR 0032). The caller must be
/// root in the Slate domain, and the target a Slate-domain process at the
/// other end of one of the caller's Unix sockets, which is how the broker
/// knows it is answering that process's request.
pub(super) fn setids_of(a: Args) -> Result {
    use crate::proc::domain::Domain;
    let me = proc::current().ok_or(ESRCH)?;
    let mine = me.cred();
    if mine.euid != 0 || me.domain() != Domain::Slate {
        return Err(EPERM);
    }
    let target = proc::find_in_caller_ns(a.0[0] as u32).ok_or(ESRCH)?;
    if target.domain() != Domain::Slate {
        return Err(EPERM);
    }
    let connected = me.files.lock().iter().any(|(_, f)| {
        let any: &dyn core::any::Any = &**f;
        any.downcast_ref::<crate::net::unix::UnixSocket>().is_some_and(|u| u.peer_cred().pid as u32 == target.pid)
    });
    if !connected {
        return Err(EPERM);
    }
    let ids: Ids = read_user(a.0[1]).map_err(|_| EFAULT)?;
    let groups = if a.0[2] == 0 {
        None
    } else {
        let n = a.0[3] as usize;
        if n > crate::proc::cred::NGROUPS_MAX {
            return Err(EINVAL);
        }
        let mut raw = alloc::vec![0u8; n * 4];
        crate::arch::uaccess::copy_from_user(&mut raw, a.0[2]).map_err(|_| EFAULT)?;
        let mut g: Vec<u32> = raw
            .chunks(4)
            .map(|b| mine.gid_in(u32::from_ne_bytes([b[0], b[1], b[2], b[3]])))
            .collect::<core::result::Result<_, _>>()?;
        g.sort_unstable();
        g.dedup();
        Some(g)
    };
    let uid = |v: u32| if v == NO_ID { Ok(None) } else { mine.uid_in(v).map(Some) };
    let gid = |v: u32| if v == NO_ID { Ok(None) } else { mine.gid_in(v).map(Some) };
    let old = (*target.cred()).clone();
    let mut c = old.clone();
    c.ruid = uid(ids.ruid)?.unwrap_or(c.ruid);
    c.euid = uid(ids.euid)?.unwrap_or(c.euid);
    c.suid = uid(ids.suid)?.unwrap_or(c.suid);
    c.rgid = gid(ids.rgid)?.unwrap_or(c.rgid);
    c.egid = gid(ids.egid)?.unwrap_or(c.egid);
    c.sgid = gid(ids.sgid)?.unwrap_or(c.sgid);
    c.fsuid = c.euid;
    c.fsgid = c.egid;
    if let Some(g) = groups {
        c.groups = g;
    }
    // The grant is the user's whole authority, as if the process had run
    // a set-user-ID program of theirs (capabilities(7), "Capabilities and
    // execution of programs by root"): root's capabilities within the
    // bounding set, none for anyone else (ADR 0142: sudoedit works as
    // root before it executes anything).
    if c.is_root(c.euid) {
        c.cap_permitted = crate::proc::cred::CAP_FULL & c.cap_bounding;
        c.cap_effective = c.cap_permitted;
    } else {
        c.cap_permitted = 0;
        c.cap_effective = 0;
    }
    c.cap_ambient = 0;
    crate::log_info!(
        "setids_of: pid {} ({}) now uid {} gid {}, granted by pid {} ({})",
        target.pid,
        *target.name.lock(),
        c.euid,
        c.egid,
        me.pid,
        *me.name.lock()
    );
    crate::abi::linux::cred::commit_all(&target, &old, c);
    Ok(0)
}

/// Root in the Slate domain (ADR 0032), for the disk calls.
fn slate_root(me: &proc::Process) -> core::result::Result<(), Errno> {
    if me.cred().euid != 0 || me.domain() != crate::proc::domain::Domain::Slate {
        return Err(EPERM);
    }
    Ok(())
}

/// crypt_open(fd, slot, key, len): open the encrypted partition `fd` is
/// open on with the key for slot `slot` (ADR 0039); returns N of `dm-N`.
pub(super) fn crypt_open(a: Args) -> Result {
    let me = proc::current().ok_or(ESRCH)?;
    slate_root(&me)?;
    if a.0[3] != 32 {
        return Err(EINVAL);
    }
    let f = me.files.lock().get(a.fd(0))?;
    let dev = crate::block::block_device_of(&*f).ok_or(ENOTBLK)?;
    let mut kek = [0u8; 32];
    crate::arch::uaccess::copy_from_user(&mut kek, a.0[2]).map_err(|_| EFAULT)?;
    let r = crate::block::crypt::open_with_key(&dev, a.0[1] as usize, &kek);
    slatecrypt::wipe(&mut kek);
    r.map(u64::from)
}

/// discard(fd, offset, len): TRIM part of a block device (ADR 0039).
pub(super) fn discard(a: Args) -> Result {
    let me = proc::current().ok_or(ESRCH)?;
    let f = me.files.lock().get(a.fd(0))?;
    // The descriptor must allow writing.
    if f.status_flags() & crate::fs::O_ACCMODE == crate::fs::O_RDONLY {
        return Err(EBADF);
    }
    let dev = crate::block::block_device_of(&*f).ok_or(ENOTBLK)?;
    crate::block::discard_bytes(&dev, a.0[1], a.0[2]).map(|()| 0)
}

/// cpu_times(out): user and system CPU time of the caller and of its
/// waited-for children, in nanoseconds.
pub(super) fn cpu_times(a: Args) -> Result {
    let p = proc::current().ok_or(ESRCH)?;
    crate::sched::update_current_times();
    let ((u, s), (cu, cs)) = (p.cpu.own(), p.cpu.children());
    crate::arch::uaccess::write_user(a.0[0], &[u, s, cu, cs]).map_err(|_| EFAULT)?;
    Ok(0)
}

/// crypt_wrap(n, key, len, out, out_len): `dm-N`'s master key wrapped
/// under `key`, for a new key slot (ADR 0058).
pub(super) fn crypt_wrap(a: Args) -> Result {
    let me = proc::current().ok_or(ESRCH)?;
    slate_root(&me)?;
    if a.0[2] != 32 || a.0[4] != slatecrypt::WRAPPED_BYTES as u64 {
        return Err(EINVAL);
    }
    let mut kek = [0u8; 32];
    crate::arch::uaccess::copy_from_user(&mut kek, a.0[1]).map_err(|_| EFAULT)?;
    let r = crate::block::crypt::wrap_key(a.0[0] as u32, &kek);
    slatecrypt::wipe(&mut kek);
    let wrapped = r?;
    crate::arch::uaccess::copy_to_user(a.0[3], &wrapped).map_err(|_| EFAULT)?;
    Ok(0)
}

/// crypt_close(n): close `dm-N`.
pub(super) fn crypt_close(a: Args) -> Result {
    let me = proc::current().ok_or(ESRCH)?;
    slate_root(&me)?;
    crate::block::crypt::close(a.0[0] as u32).map(|()| 0)
}

/// unlock(slot, key, len): the boot's unlock program hands over the key
/// for key slot `slot` of the encrypted root (ADR 0038); the kernel checks
/// it by opening the slot.
pub(super) fn unlock(a: Args) -> Result {
    let me = proc::current().ok_or(ESRCH)?;
    if me.cred().euid != 0 {
        return Err(EPERM);
    }
    if a.0[2] != 32 {
        return Err(EINVAL);
    }
    let mut kek = [0u8; 32];
    crate::arch::uaccess::copy_from_user(&mut kek, a.0[1]).map_err(|_| EFAULT)?;
    let r = crate::block::crypt::hand_over(me.pid, a.0[0] as usize, &kek);
    slatecrypt::wipe(&mut kek);
    r.map(|()| 0)
}

// --- threads (ADR 0073) ---------------------------------------------------------

/// thread_start(entry, arg, stack top, tls, tid word): a thread of the
/// caller's process, over the kernel's clone of a thread.
pub(super) fn thread_start(a: Args, frame: &crate::arch::trap::TrapFrame) -> Result {
    use crate::arch::uaccess::USER_END;
    let [entry, arg, top, tls, tid, _] = a.0;
    if !(1..USER_END).contains(&entry) || top % 16 != 0 || !(16..=USER_END).contains(&top) || tls >= USER_END {
        return Err(EINVAL);
    }
    if tid % 4 != 0 {
        return Err(EINVAL);
    }
    // The zero return address `entry` sees, as if it had been called.
    write_user(top - 8, &0u64).map_err(|_| EFAULT)?;
    let mut f = frame.clone();
    f.rip = entry;
    f.rdi = arg;
    let mut flags = proc::CLONE_VM | proc::CLONE_FS | proc::CLONE_FILES | proc::CLONE_SIGHAND | proc::CLONE_THREAD;
    if tls != 0 {
        flags |= proc::CLONE_SETTLS;
    }
    if tid != 0 {
        flags |= proc::CLONE_CHILD_SETTID | proc::CLONE_CHILD_CLEARTID;
    }
    proc::clone_thread(&f, flags, top - 8, 0, tid, tls)
}

/// futex_wait(addr, expected, relative timeout or null).
pub(super) fn futex_wait(a: Args) -> Result {
    let [addr, expected, timeout, ..] = a.0;
    let p = proc::current().ok_or(ESRCH)?;
    let deadline = if timeout == 0 {
        None
    } else {
        let ts: slate_abi::Timespec = read_user(timeout).map_err(|_| EFAULT)?;
        if ts.sec < 0 || !(0..1_000_000_000).contains(&ts.nsec) {
            return Err(EINVAL);
        }
        let ns = (ts.sec as u64).saturating_mul(1_000_000_000).saturating_add(ts.nsec as u64);
        Some(crate::time::monotonic_ns().saturating_add(ns))
    };
    proc::futex::wait(&p, addr, expected as u32, proc::futex::FUTEX_BITSET_MATCH_ANY, true, deadline)
}

/// futex_wake(addr, count).
pub(super) fn futex_wake(a: Args) -> Result {
    let p = proc::current().ok_or(ESRCH)?;
    let n = u32::try_from(a.0[1]).unwrap_or(u32::MAX);
    proc::futex::wake(&p, a.0[0], n, proc::futex::FUTEX_BITSET_MATCH_ANY, true)
}

/// set_tls(base): the FS base (as arch_prctl(ARCH_SET_FS)).
pub(super) fn set_tls(a: Args) -> Result {
    if a.0[0] >= crate::arch::uaccess::USER_END {
        return Err(EPERM);
    }
    crate::arch::context::set_fs_base(a.0[0]);
    Ok(0)
}
