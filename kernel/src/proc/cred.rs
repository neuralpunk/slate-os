// SPDX-License-Identifier: MIT OR Apache-2.0

//! Process credentials (credentials(7)): real, effective, saved and
//! file-system user and group IDs, supplementary groups, and Linux
//! capability sets (capabilities(7)); and the file permission check
//! (POSIX.1-2017 XBD §4.5, "File Access Permissions").
//!
//! Threads share their process's credentials.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::abi::linux::errno::*;
use crate::fs::vfs::{FileType, Metadata};
use crate::proc::ns::UserNs;

// Capability numbers (capabilities(7), linux/capability.h values as listed
// in the man page).
pub const CAP_CHOWN: u32 = 0;
pub const CAP_DAC_OVERRIDE: u32 = 1;
pub const CAP_DAC_READ_SEARCH: u32 = 2;
pub const CAP_FOWNER: u32 = 3;
pub const CAP_FSETID: u32 = 4;
pub const CAP_KILL: u32 = 5;
pub const CAP_SETGID: u32 = 6;
pub const CAP_SETUID: u32 = 7;
pub const CAP_SETPCAP: u32 = 8;
pub const CAP_LINUX_IMMUTABLE: u32 = 9;
pub const CAP_NET_BIND_SERVICE: u32 = 10;
pub const CAP_NET_ADMIN: u32 = 12;
pub const CAP_NET_RAW: u32 = 13;
pub const CAP_SYS_CHROOT: u32 = 18;
pub const CAP_SYS_PTRACE: u32 = 19;
pub const CAP_SYS_ADMIN: u32 = 21;
pub const CAP_SYS_BOOT: u32 = 22;
pub const CAP_SYS_TIME: u32 = 25;
pub const CAP_SYS_NICE: u32 = 23;
pub const CAP_SYS_RESOURCE: u32 = 24;
pub const CAP_MKNOD: u32 = 27;
pub const CAP_SYSLOG: u32 = 34;
pub const CAP_SETFCAP: u32 = 31;
pub const CAP_MAC_OVERRIDE: u32 = 32;
/// CAP_CHECKPOINT_RESTORE, the highest capability capabilities(7) lists.
pub const CAP_LAST: u32 = 40;
pub const CAP_FULL: u64 = (1 << (CAP_LAST + 1)) - 1;

/// The capabilities that follow the file-system user ID (capabilities(7),
/// "Effect of user ID changes on capabilities").
const FS_CAPS: u64 = (1 << CAP_CHOWN)
    | (1 << CAP_DAC_OVERRIDE)
    | (1 << CAP_DAC_READ_SEARCH)
    | (1 << CAP_FOWNER)
    | (1 << CAP_FSETID)
    | (1 << CAP_LINUX_IMMUTABLE)
    | (1 << CAP_MKNOD)
    | (1 << CAP_MAC_OVERRIDE);

/// NGROUPS_MAX (limits.h; getgroups(2)).
pub const NGROUPS_MAX: usize = 65536;

/// Access requested in a permission check (bit values as in mode bits).
pub const MAY_READ: u32 = 4;
pub const MAY_WRITE: u32 = 2;
pub const MAY_EXEC: u32 = 1;

pub const S_ISUID: u32 = 0o4000;
pub const S_ISGID: u32 = 0o2000;
pub const S_ISVTX: u32 = 0o1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cred {
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
    pub fsuid: u32,
    pub rgid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsgid: u32,
    pub groups: Vec<u32>,
    pub cap_effective: u64,
    pub cap_permitted: u64,
    pub cap_inheritable: u64,
    /// The bounding set (PR_CAPBSET_DROP) and ambient set (PR_CAP_AMBIENT)
    /// (capabilities(7)).
    pub cap_bounding: u64,
    pub cap_ambient: u64,
    /// PR_SET_NO_NEW_PRIVS: execve never grants privileges (set-ID bits
    /// and capabilities are ignored).
    pub no_new_privs: bool,
    /// PR_SET_KEEPCAPS: keep permitted capabilities across setuid away
    /// from root.
    pub keep_caps: bool,
    /// The user namespace the capabilities count in (user_namespaces(7)).
    /// The IDs above are always kernel (initial-namespace) IDs.
    pub user_ns: Arc<UserNs>,
}

/// The overflow IDs unmapped IDs show as (user_namespaces(7),
/// /proc/sys/kernel/overflowuid default).
pub const OVERFLOW_ID: u32 = 65534;

impl Cred {
    pub fn root() -> Cred {
        Cred {
            ruid: 0,
            euid: 0,
            suid: 0,
            fsuid: 0,
            rgid: 0,
            egid: 0,
            sgid: 0,
            fsgid: 0,
            groups: Vec::new(),
            cap_effective: CAP_FULL,
            cap_permitted: CAP_FULL,
            cap_inheritable: 0,
            cap_bounding: CAP_FULL,
            cap_ambient: 0,
            no_new_privs: false,
            keep_caps: false,
            user_ns: crate::proc::ns::initial_user(),
        }
    }

    /// The capability over the whole system: only in the initial user
    /// namespace.
    pub fn capable(&self, cap: u32) -> bool {
        self.has(cap) && self.user_ns.parent.is_none()
    }

    /// The capability in the process's own user namespace.
    pub fn has(&self, cap: u32) -> bool {
        self.cap_effective & (1 << cap) != 0
    }

    /// The capability over things owned by user namespace `ns`: the
    /// capability in `ns` or an ancestor, or being the owner of `ns` (or of
    /// an ancestor below ours) while in its parent (user_namespaces(7),
    /// "Capabilities").
    pub fn ns_capable(&self, ns: &Arc<UserNs>, cap: u32) -> bool {
        let mut at = ns.clone();
        loop {
            if Arc::ptr_eq(&at, &self.user_ns) {
                return self.has(cap);
            }
            let Some(parent) = at.parent.clone() else { return false };
            if Arc::ptr_eq(&parent, &self.user_ns) && at.owner_uid == self.euid {
                return true;
            }
            at = parent;
        }
    }

    /// A capability over a file: in our namespace, and the file's owner and
    /// group are mapped in it (capabilities(7), "capable_wrt_inode_uidgid").
    pub fn capable_wrt(&self, meta: &Metadata, cap: u32) -> bool {
        self.has(cap)
            && (self.user_ns.parent.is_none()
                || (self.user_ns.uid_from_kernel(meta.uid).is_some()
                    && self.user_ns.gid_from_kernel(meta.gid).is_some()))
    }

    /// A kernel uid as this process sees it.
    pub fn uid_out(&self, kuid: u32) -> u32 {
        self.user_ns.uid_from_kernel(kuid).unwrap_or(OVERFLOW_ID)
    }

    pub fn gid_out(&self, kgid: u32) -> u32 {
        self.user_ns.gid_from_kernel(kgid).unwrap_or(OVERFLOW_ID)
    }

    /// A uid given by this process as a kernel uid (EINVAL if unmapped).
    pub fn uid_in(&self, uid: u32) -> Result<u32, Errno> {
        self.user_ns.uid_to_kernel(uid).ok_or(EINVAL)
    }

    pub fn gid_in(&self, gid: u32) -> Result<u32, Errno> {
        self.user_ns.gid_to_kernel(gid).ok_or(EINVAL)
    }

    /// Whether kernel uid `kuid` is root in our user namespace.
    pub(crate) fn is_root(&self, kuid: u32) -> bool {
        self.user_ns.uid_from_kernel(kuid) == Some(0)
    }

    /// Whether `gid` is the file-system group or a supplementary group.
    pub fn in_group(&self, gid: u32) -> bool {
        self.fsgid == gid || self.groups.contains(&gid)
    }

    /// Adjust capabilities after a user ID change from `old`
    /// (capabilities(7), "Effect of user ID changes on capabilities").
    pub fn fix_caps(&mut self, old: &Cred) {
        let ns = self.user_ns.clone();
        let r = |u| ns.uid_from_kernel(u) == Some(0);
        let was_root = r(old.ruid) || r(old.euid) || r(old.suid);
        let now_root = r(self.ruid) || r(self.euid) || r(self.suid);
        if was_root && !now_root && !self.keep_caps {
            self.cap_permitted = 0;
            self.cap_effective = 0;
        }
        if r(old.euid) && !r(self.euid) {
            self.cap_effective = 0;
        }
        if !r(old.euid) && r(self.euid) {
            self.cap_effective = self.cap_permitted;
        }
        if r(old.fsuid) && !r(self.fsuid) {
            self.cap_effective &= !FS_CAPS;
        }
        if !r(old.fsuid) && r(self.fsuid) {
            self.cap_effective |= self.cap_permitted & FS_CAPS;
        }
    }

    /// The credentials after executing a file with metadata `meta` and
    /// file capabilities `fcaps` (the caller leaves them out where they
    /// don't count: nosuid mounts, the Slate domain): set-ID bits apply
    /// (a set-group-ID file only if group-executable), and capabilities
    /// are recomputed (capabilities(7), "Transformation of capabilities
    /// during execve()"). Returns them and whether the exec is secure
    /// (AT_SECURE).
    pub fn after_exec(&self, meta: &Metadata, fcaps: Option<&crate::proc::fcaps::FileCaps>) -> (Cred, bool) {
        let mut c = self.clone();
        // Set-ID bits count unless no_new_privs is set or the owner is not
        // mapped in the caller's user namespace.
        if meta.mode & S_ISUID != 0 && !self.no_new_privs && self.user_ns.uid_from_kernel(meta.uid).is_some() {
            c.euid = meta.uid;
        }
        if meta.mode & S_ISGID != 0
            && meta.mode & 0o010 != 0
            && !self.no_new_privs
            && self.user_ns.gid_from_kernel(meta.gid).is_some()
        {
            c.egid = meta.gid;
        }
        let set_id = c.euid != self.euid || c.egid != self.egid;
        c.suid = c.euid;
        c.sgid = c.egid;
        c.fsuid = c.euid;
        c.fsgid = c.egid;
        c.keep_caps = false;
        // File capabilities count unless no_new_privs is set, and only
        // those set for the root of our user namespace or an ancestor's.
        let fcaps = fcaps.filter(|f| !self.no_new_privs && crate::proc::fcaps::applies(f.root, &self.user_ns));
        // Ambient capabilities don't survive a privileged program.
        if set_id || fcaps.is_some() {
            c.cap_ambient = 0;
        }
        // Root's programs are treated as having every file capability, and
        // as effective for an effective root ("Capabilities and execution
        // of programs by root").
        let (fp, fi, fe) = if c.is_root(c.euid) || c.is_root(c.ruid) {
            (CAP_FULL, CAP_FULL, c.is_root(c.euid))
        } else {
            fcaps.map_or((0, 0, false), |f| (f.permitted, f.inheritable, f.effective))
        };
        c.cap_permitted = ((c.cap_inheritable & fi) | (fp & c.cap_bounding) | c.cap_ambient) & CAP_FULL;
        c.cap_effective = if fe { c.cap_permitted } else { c.cap_ambient };
        let secure = c.euid != c.ruid || c.egid != c.rgid || (fcaps.is_some() && c.cap_permitted != 0);
        (c, secure)
    }

    /// The credentials access(2) checks with: the real IDs, and the
    /// capabilities of root only when the real user is root.
    pub fn for_access(&self) -> Cred {
        let mut c = self.clone();
        c.fsuid = self.ruid;
        c.fsgid = self.rgid;
        if !self.is_root(self.ruid) {
            c.cap_effective &= !FS_CAPS;
        } else {
            c.cap_effective |= c.cap_permitted & FS_CAPS;
        }
        c
    }

    /// The file permission check: `want` is a mask of MAY_READ, MAY_WRITE
    /// and MAY_EXEC.
    pub fn permission(&self, meta: &Metadata, want: u32) -> Result<(), Errno> {
        let mode = meta.mode & 0o777;
        let class = if self.fsuid == meta.uid {
            mode >> 6
        } else if self.in_group(meta.gid) {
            mode >> 3
        } else {
            mode
        } & 7;
        if class & want == want {
            return Ok(());
        }
        let dir = meta.file_type() == FileType::Directory;
        // CAP_DAC_OVERRIDE: everything, but executing a file still needs
        // one execute bit.
        if self.capable_wrt(meta, CAP_DAC_OVERRIDE) && (want & MAY_EXEC == 0 || dir || mode & 0o111 != 0) {
            return Ok(());
        }
        // CAP_DAC_READ_SEARCH: reading files, reading and searching
        // directories.
        if self.capable_wrt(meta, CAP_DAC_READ_SEARCH) && want & MAY_WRITE == 0 && (dir || want == MAY_READ) {
            return Ok(());
        }
        Err(EACCES)
    }

    /// Owner-only operations (chmod, utimes with explicit times, ...).
    pub fn owns(&self, meta: &Metadata) -> bool {
        self.fsuid == meta.uid || self.capable_wrt(meta, CAP_FOWNER)
    }

    /// Removing or renaming `victim` from directory `dir`: write and search
    /// permission on `dir`, and with the sticky bit only the owner of the
    /// file or directory may (POSIX "sticky bit", unlink(2) EPERM).
    pub fn may_delete(&self, dir: &Metadata, victim: &Metadata) -> Result<(), Errno> {
        self.permission(dir, MAY_WRITE | MAY_EXEC)?;
        if dir.mode & S_ISVTX != 0
            && self.fsuid != victim.uid
            && self.fsuid != dir.uid
            && !self.capable_wrt(victim, CAP_FOWNER)
        {
            return Err(EPERM);
        }
        Ok(())
    }

    /// Owner and group of a new file in directory `parent`: the fs IDs,
    /// or the directory's group under a set-group-ID directory.
    pub fn new_owner(&self, parent: &Metadata) -> (u32, u32) {
        let gid = if parent.mode & S_ISGID != 0 { parent.gid } else { self.fsgid };
        (self.fsuid, gid)
    }
}

/// ptrace(2)'s access check in PTRACE_MODE_READ_FSCREDS mode ("Ptrace
/// access mode checking", without a Linux security module): what reading
/// another process's /proc/<pid>/environ, maps, fd, cwd, exe, root and
/// ns needs. Its own process may; another only if its real, effective
/// and saved IDs are all the caller's file-system IDs and it is dumpable,
/// or with CAP_SYS_PTRACE over its user namespace.
pub fn ptrace_may_read(target: &crate::proc::Process) -> bool {
    let Some(me) = crate::proc::current() else { return true };
    if core::ptr::eq(Arc::as_ptr(&me), target) {
        return true;
    }
    let (c, t) = (me.cred(), target.cred());
    let cap = c.ns_capable(&t.user_ns, CAP_SYS_PTRACE);
    let same = [t.ruid, t.euid, t.suid].iter().all(|&u| u == c.fsuid)
        && [t.rgid, t.egid, t.sgid].iter().all(|&g| g == c.fsgid);
    cap || (same && target.dumpable.load(core::sync::atomic::Ordering::Relaxed))
}

/// The calling process's credentials; root for kernel threads.
pub fn current() -> Arc<Cred> {
    match crate::proc::current() {
        Some(p) => p.cred(),
        None => Arc::new(Cred::root()),
    }
}
