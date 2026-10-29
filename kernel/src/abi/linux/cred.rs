// SPDX-License-Identifier: MIT OR Apache-2.0

//! User and group ID system calls (setuid(2), setreuid(2), setresuid(2),
//! setfsuid(2), getgroups(2) and their group counterparts), capget(2) /
//! capset(2), and signal permission (kill(2)).

use alloc::vec::Vec;

use super::errno::*;
use super::{Args, Result};
use crate::arch::uaccess::{copy_from_user, read_user, write_user};
use crate::proc::cred::{CAP_FULL, CAP_KILL, CAP_SETGID, CAP_SETUID, Cred, NGROUPS_MAX};
use crate::proc::{self, Process};

fn me() -> core::result::Result<alloc::sync::Arc<Process>, Errno> {
    proc::current().ok_or(ESRCH)
}

/// -1 (as a u32) leaves an ID unchanged.
fn id(v: u64) -> Option<u32> {
    (v as u32 != u32::MAX).then_some(v as u32)
}

/// A uid argument as a kernel uid (None for -1; EINVAL if unmapped in the
/// caller's user namespace).
fn kuid(c: &Cred, v: u64) -> core::result::Result<Option<u32>, Errno> {
    id(v).map(|u| c.uid_in(u)).transpose()
}

fn kgid(c: &Cred, v: u64) -> core::result::Result<Option<u32>, Errno> {
    id(v).map(|g| c.gid_in(g)).transpose()
}

/// Replace the calling thread's credentials, fixing capabilities for the
/// ID change.
pub(crate) fn commit(p: &Process, old: &Cred, mut new: Cred) {
    new.fix_caps(old);
    p.set_cred(new);
}

/// [`commit`] for every thread of the process.
pub(crate) fn commit_all(p: &Process, old: &Cred, mut new: Cred) {
    new.fix_caps(old);
    p.set_cred_all(new);
}

pub fn getuid() -> Result {
    let c = me()?.cred();
    Ok(u64::from(c.uid_out(c.ruid)))
}
pub fn geteuid() -> Result {
    let c = me()?.cred();
    Ok(u64::from(c.uid_out(c.euid)))
}
pub fn getgid() -> Result {
    let c = me()?.cred();
    Ok(u64::from(c.gid_out(c.rgid)))
}
pub fn getegid() -> Result {
    let c = me()?.cred();
    Ok(u64::from(c.gid_out(c.egid)))
}

pub fn getresuid(a: Args) -> Result {
    let c = me()?.cred();
    for (ptr, v) in a.0[..3].iter().zip([c.ruid, c.euid, c.suid].map(|u| c.uid_out(u))) {
        write_user(*ptr, &v).map_err(|_| EFAULT)?;
    }
    Ok(0)
}

pub fn getresgid(a: Args) -> Result {
    let c = me()?.cred();
    for (ptr, v) in a.0[..3].iter().zip([c.rgid, c.egid, c.sgid].map(|g| c.gid_out(g))) {
        write_user(*ptr, &v).map_err(|_| EFAULT)?;
    }
    Ok(0)
}

/// setuid(2): with CAP_SETUID all IDs; otherwise only the effective one,
/// to the real or saved ID.
pub fn setuid(a: Args) -> Result {
    let p = me()?;
    let old = (*p.cred()).clone();
    let uid = kuid(&old, a.0[0])?.ok_or(EINVAL)?;
    let mut c = old.clone();
    if old.has(CAP_SETUID) {
        (c.ruid, c.euid, c.suid, c.fsuid) = (uid, uid, uid, uid);
    } else if uid == old.ruid || uid == old.suid {
        (c.euid, c.fsuid) = (uid, uid);
    } else {
        return Err(EPERM);
    }
    commit(&p, &old, c);
    Ok(0)
}

pub fn setgid(a: Args) -> Result {
    let p = me()?;
    let old = (*p.cred()).clone();
    let gid = kgid(&old, a.0[0])?.ok_or(EINVAL)?;
    let mut c = old.clone();
    if old.has(CAP_SETGID) {
        (c.rgid, c.egid, c.sgid, c.fsgid) = (gid, gid, gid, gid);
    } else if gid == old.rgid || gid == old.sgid {
        (c.egid, c.fsgid) = (gid, gid);
    } else {
        return Err(EPERM);
    }
    p.set_cred(c);
    Ok(0)
}

/// setreuid(2): unprivileged, the real ID may become the effective one and
/// the effective ID any of real, effective and saved. Setting the real ID,
/// or the effective one to something other than the old real ID, sets the
/// saved ID to the new effective ID.
pub fn setreuid(a: Args) -> Result {
    let p = me()?;
    let old = (*p.cred()).clone();
    let (r, e) = (kuid(&old, a.0[0])?, kuid(&old, a.0[1])?);
    let privileged = old.has(CAP_SETUID);
    if let Some(r) = r
        && !privileged
        && r != old.ruid
        && r != old.euid
    {
        return Err(EPERM);
    }
    if let Some(e) = e
        && !privileged
        && e != old.ruid
        && e != old.euid
        && e != old.suid
    {
        return Err(EPERM);
    }
    let mut c = old.clone();
    if let Some(r) = r {
        c.ruid = r;
    }
    if let Some(e) = e {
        c.euid = e;
    }
    if r.is_some() || e.is_some_and(|e| e != old.ruid) {
        c.suid = c.euid;
    }
    c.fsuid = c.euid;
    commit(&p, &old, c);
    Ok(0)
}

pub fn setregid(a: Args) -> Result {
    let p = me()?;
    let old = (*p.cred()).clone();
    let (r, e) = (kgid(&old, a.0[0])?, kgid(&old, a.0[1])?);
    let privileged = old.has(CAP_SETGID);
    if let Some(r) = r
        && !privileged
        && r != old.rgid
        && r != old.egid
    {
        return Err(EPERM);
    }
    if let Some(e) = e
        && !privileged
        && e != old.rgid
        && e != old.egid
        && e != old.sgid
    {
        return Err(EPERM);
    }
    let mut c = old.clone();
    if let Some(r) = r {
        c.rgid = r;
    }
    if let Some(e) = e {
        c.egid = e;
    }
    if r.is_some() || e.is_some_and(|e| e != old.rgid) {
        c.sgid = c.egid;
    }
    c.fsgid = c.egid;
    p.set_cred(c);
    Ok(0)
}

/// setresuid(2): unprivileged, each new ID must be one of the current
/// real, effective and saved IDs.
/// The credentials after setresuid(2) and setresgid(2) with these
/// arguments (`None`: that call isn't made), both checked against `old`:
/// a change that is refused changes nothing.
pub(crate) fn res_ids(old: &Cred, uids: Option<[u64; 3]>, gids: Option<[u64; 3]>) -> core::result::Result<Cred, Errno> {
    let mut c = old.clone();
    if let Some(g) = gids {
        let ids = [kgid(old, g[0])?, kgid(old, g[1])?, kgid(old, g[2])?];
        if !old.has(CAP_SETGID) && ids.iter().flatten().any(|&g| g != old.rgid && g != old.egid && g != old.sgid) {
            return Err(EPERM);
        }
        c.rgid = ids[0].unwrap_or(c.rgid);
        c.egid = ids[1].unwrap_or(c.egid);
        c.sgid = ids[2].unwrap_or(c.sgid);
        c.fsgid = c.egid;
    }
    if let Some(u) = uids {
        let ids = [kuid(old, u[0])?, kuid(old, u[1])?, kuid(old, u[2])?];
        if !old.has(CAP_SETUID) && ids.iter().flatten().any(|&u| u != old.ruid && u != old.euid && u != old.suid) {
            return Err(EPERM);
        }
        c.ruid = ids[0].unwrap_or(c.ruid);
        c.euid = ids[1].unwrap_or(c.euid);
        c.suid = ids[2].unwrap_or(c.suid);
        c.fsuid = c.euid;
    }
    Ok(c)
}

pub fn setresuid(a: Args) -> Result {
    let p = me()?;
    let old = (*p.cred()).clone();
    let c = res_ids(&old, Some([a.0[0], a.0[1], a.0[2]]), None)?;
    commit(&p, &old, c);
    Ok(0)
}

pub fn setresgid(a: Args) -> Result {
    let p = me()?;
    let old = (*p.cred()).clone();
    let c = res_ids(&old, None, Some([a.0[0], a.0[1], a.0[2]]))?;
    p.set_cred(c);
    Ok(0)
}

/// setfsuid(2): returns the old file-system ID; changes it only to the
/// real, effective, saved or current fs ID, or with CAP_SETUID.
pub fn setfsuid(a: Args) -> Result {
    let p = me()?;
    let old = (*p.cred()).clone();
    if let Some(u) = id(a.0[0]).and_then(|u| old.uid_in(u).ok())
        && (old.has(CAP_SETUID) || [old.ruid, old.euid, old.suid, old.fsuid].contains(&u))
    {
        let mut c = old.clone();
        c.fsuid = u;
        commit(&p, &old, c);
    }
    Ok(u64::from(old.uid_out(old.fsuid)))
}

pub fn setfsgid(a: Args) -> Result {
    let p = me()?;
    let old = (*p.cred()).clone();
    if let Some(g) = id(a.0[0]).and_then(|g| old.gid_in(g).ok())
        && (old.has(CAP_SETGID) || [old.rgid, old.egid, old.sgid, old.fsgid].contains(&g))
    {
        let mut c = old.clone();
        c.fsgid = g;
        p.set_cred(c);
    }
    Ok(u64::from(old.gid_out(old.fsgid)))
}

/// getgroups(2): size 0 asks for the count.
pub fn getgroups(a: Args) -> Result {
    let c = me()?.cred();
    let size = a.0[0] as i32;
    if size < 0 {
        return Err(EINVAL);
    }
    if size == 0 {
        return Ok(c.groups.len() as u64);
    }
    if (size as usize) < c.groups.len() {
        return Err(EINVAL);
    }
    for (i, g) in c.groups.iter().enumerate() {
        write_user(a.0[1] + 4 * i as u64, &c.gid_out(*g)).map_err(|_| EFAULT)?;
    }
    Ok(c.groups.len() as u64)
}

/// setgroups(2): CAP_SETGID only; in a user namespace only once its
/// gid_map is written and while /proc/<pid>/setgroups allows it
/// (user_namespaces(7)).
pub fn setgroups(a: Args) -> Result {
    set_groups(a, false)
}

/// setgroups(2), for the calling thread, or with `all` every thread
/// (Slate's native call).
pub(crate) fn set_groups(a: Args, all: bool) -> Result {
    let p = me()?;
    let old = p.cred();
    if !old.has(CAP_SETGID) {
        return Err(EPERM);
    }
    if old.user_ns.parent.is_some() && (!*old.user_ns.setgroups.lock() || old.user_ns.gid_map.lock().is_empty()) {
        return Err(EPERM);
    }
    let n = a.0[0] as usize;
    if n > NGROUPS_MAX {
        return Err(EINVAL);
    }
    let mut raw = alloc::vec![0u8; n * 4];
    if n > 0 {
        copy_from_user(&mut raw, a.0[1]).map_err(|_| EFAULT)?;
    }
    let mut groups: Vec<u32> = raw
        .chunks(4)
        .map(|b| old.gid_in(u32::from_ne_bytes([b[0], b[1], b[2], b[3]])))
        .collect::<core::result::Result<_, _>>()?;
    groups.sort_unstable();
    groups.dedup();
    let mut c = (*old).clone();
    c.groups = groups;
    if all {
        p.set_cred_all(c)
    } else {
        p.set_cred(c)
    }
    Ok(0)
}

// --- capabilities -----------------------------------------------------------

/// `struct __user_cap_header_struct` and `__user_cap_data_struct`
/// (capget(2)).
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// _LINUX_CAPABILITY_VERSION_3 (capget(2)): two data structures.
const CAP_V3: u32 = 0x2008_0522;
const CAP_V1: u32 = 0x1998_0330;
const CAP_V2: u32 = 0x2007_1026;

fn cap_header(ptr: u64) -> core::result::Result<CapHeader, Errno> {
    let h: CapHeader = read_user(ptr).map_err(|_| EFAULT)?;
    if h.version != CAP_V3 && h.version != CAP_V2 && h.version != CAP_V1 {
        // Report the version we prefer.
        let fixed = CapHeader { version: CAP_V3, pid: h.pid };
        write_user(ptr, &fixed).map_err(|_| EFAULT)?;
        return Err(EINVAL);
    }
    Ok(h)
}

pub fn capget(a: Args) -> Result {
    // With no data pointer an unknown version is a probe: the preferred
    // version is filled in and the call succeeds (capget(2)).
    let h = match cap_header(a.0[0]) {
        Err(EINVAL) if a.0[1] == 0 => return Ok(0),
        r => r?,
    };
    let target = if h.pid == 0 { me()? } else { proc::get(h.pid as u32).ok_or(ESRCH)? };
    let c = target.cred();
    if a.0[1] == 0 {
        return Ok(0);
    }
    let words = if h.version == CAP_V1 { 1 } else { 2 };
    for i in 0..words {
        let d = CapData {
            effective: (c.cap_effective >> (32 * i)) as u32,
            permitted: (c.cap_permitted >> (32 * i)) as u32,
            inheritable: (c.cap_inheritable >> (32 * i)) as u32,
        };
        write_user(a.0[1] + (i * size_of::<CapData>()) as u64, &d).map_err(|_| EFAULT)?;
    }
    Ok(0)
}

/// capset(2) on the calling process: permitted may only shrink, effective
/// must stay within permitted, inheritable within permitted plus the old
/// inheritable set.
pub fn capset(a: Args) -> Result {
    let h = cap_header(a.0[0])?;
    let p = me()?;
    if h.pid != 0 && h.pid as u32 != p.pid {
        return Err(EPERM);
    }
    let words = if h.version == CAP_V1 { 1 } else { 2 };
    let (mut e, mut pm, mut i) = (0u64, 0u64, 0u64);
    for k in 0..words {
        let d: CapData = read_user(a.0[1] + (k * size_of::<CapData>()) as u64).map_err(|_| EFAULT)?;
        e |= u64::from(d.effective) << (32 * k);
        pm |= u64::from(d.permitted) << (32 * k);
        i |= u64::from(d.inheritable) << (32 * k);
    }
    let old = p.cred();
    let (e, pm, i) = (e & CAP_FULL, pm & CAP_FULL, i & CAP_FULL);
    if pm & !old.cap_permitted != 0 || e & !pm != 0 || i & !(old.cap_inheritable | old.cap_permitted) != 0 {
        return Err(EPERM);
    }
    let mut c = (*old).clone();
    c.cap_effective = e;
    c.cap_permitted = pm;
    c.cap_inheritable = i;
    p.set_cred(c);
    Ok(0)
}

/// PR_SET_KEEPCAPS / PR_GET_KEEPCAPS (prctl(2)).
pub fn keepcaps(set: Option<bool>) -> Result {
    let p = me()?;
    let old = p.cred();
    match set {
        None => Ok(u64::from(old.keep_caps)),
        Some(k) => {
            let mut c = (*old).clone();
            c.keep_caps = k;
            p.set_cred(c);
            Ok(0)
        }
    }
}

// --- signals ------------------------------------------------------------------------

/// May `sender` signal `target` (kill(2) EPERM rules): CAP_KILL, a real or
/// effective ID matching the target's real or saved ID, or SIGCONT within
/// the session.
pub fn may_signal(sender: &Process, target: &Process, sig: u32) -> bool {
    if !crate::proc::domain::may_signal(sender, target) {
        return false;
    }
    let s = sender.cred();
    let t = target.cred();
    if s.ns_capable(&t.user_ns, CAP_KILL) {
        return true;
    }
    if [s.ruid, s.euid].iter().any(|u| *u == t.ruid || *u == t.suid) {
        return true;
    }
    sig == crate::proc::signal::SIGCONT
        && sender.sid.load(core::sync::atomic::Ordering::Relaxed)
            == target.sid.load(core::sync::atomic::Ordering::Relaxed)
}
