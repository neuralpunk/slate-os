// SPDX-License-Identifier: MIT OR Apache-2.0

//! Namespaces (namespaces(7), ADR 0028): each process points at one
//! namespace of each kind, inherited on fork; `clone`, `unshare` and
//! `setns` change them.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::abi::linux::errno::*;
use crate::sync::IrqSpinLock;

// clone(2) and unshare(2) namespace flags. Source: musl `sched.h`.
pub const CLONE_NEWTIME: u64 = 0x80;
pub const CLONE_NEWNS: u64 = 0x0002_0000;
pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
pub const CLONE_NEWPID: u64 = 0x2000_0000;
pub const CLONE_NEWNET: u64 = 0x4000_0000;
pub const ALL: u64 =
    CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET;

/// Inode numbers of namespace files; the initial namespaces use the
/// numbers Linux gives them (0xEFFFFFFB onward), the rest count up.
static NEXT_INO: AtomicU64 = AtomicU64::new(0xF000_0000);

fn next_ino() -> u64 {
    NEXT_INO.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug)]
pub struct UtsNs {
    pub ino: u64,
    /// The user namespace that owns it (capabilities over it count there).
    pub owner: Arc<UserNs>,
    pub hostname: IrqSpinLock<Vec<u8>>,
    pub domainname: IrqSpinLock<Vec<u8>>,
}

#[derive(Debug)]
pub struct IpcNs {
    pub ino: u64,
    /// The user namespace that owns it (capabilities over it count there).
    pub owner: Arc<UserNs>,
}

/// A mount namespace: its id keys the mount table (fs/vfs.rs).
#[derive(Debug)]
pub struct MntNs {
    pub ino: u64,
    pub id: u64,
    /// The user namespace that owns it (capabilities over it count there).
    pub owner: Arc<UserNs>,
    /// Where setns(2) puts a joining process: its creator's root directory,
    /// moved by pivot_root (`None`: the real root). ADR 0028.
    pub root: IrqSpinLock<Option<Arc<crate::fs::vfs::Dentry>>>,
}

impl Drop for MntNs {
    fn drop(&mut self) {
        // The last process left: its mounts go.
        crate::fs::vfs::drop_mounts(self.id);
    }
}

/// One line of a uid_map or gid_map: `inside outside count`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdMapping {
    pub inside: u32,
    pub outside: u32,
    pub count: u32,
}

pub struct UserNs {
    pub ino: u64,
    pub parent: Option<Arc<UserNs>>,
    /// The effective (kernel) uid of the creator: it has every capability
    /// in the namespace (user_namespaces(7)).
    pub owner_uid: u32,
    pub uid_map: IrqSpinLock<Vec<IdMapping>>,
    pub gid_map: IrqSpinLock<Vec<IdMapping>>,
    /// `/proc/<pid>/setgroups`: whether setgroups(2) is allowed.
    pub setgroups: IrqSpinLock<bool>,
    /// /proc/sys/user/max_user_namespaces in this namespace: how many user
    /// namespaces may live below it (ADR 0114). A new namespace's is
    /// INT_MAX, as observed on Linux; bubblewrap sets its sandbox's to 1.
    pub max_user_ns: AtomicU64,
    /// User namespaces living below this one (at any depth).
    pub user_ns_below: AtomicU64,
}

/// A new user namespace's limit (INT_MAX, as Linux shows it).
const MAX_USER_NS_CHILD: u64 = i32::MAX as u64;
/// The initial namespace's limit.
pub const MAX_USER_NS_INITIAL: u64 = 63000;
/// Counting and checking the limits happen together.
static USER_NS_COUNT: IrqSpinLock<()> = IrqSpinLock::new(());

impl Drop for UserNs {
    /// The namespace ends: it no longer counts against its ancestors.
    fn drop(&mut self) {
        let _turn = USER_NS_COUNT.lock();
        let mut at = self.parent.clone();
        while let Some(a) = at {
            a.user_ns_below.fetch_sub(1, Ordering::Relaxed);
            at = a.parent.clone();
        }
    }
}

impl core::fmt::Debug for UserNs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "user:[{}]", self.ino)
    }
}

/// User namespaces are equal only to themselves (credentials compare them).
impl PartialEq for UserNs {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self, other)
    }
}
impl Eq for UserNs {}

impl UserNs {
    pub fn level(&self) -> usize {
        self.parent.as_ref().map_or(0, |p| p.level() + 1)
    }

    /// Map an id seen inside this namespace to the parent's view.
    pub fn map_out(map: &[IdMapping], id: u32) -> Option<u32> {
        map.iter().find(|m| id >= m.inside && id - m.inside < m.count).map(|m| m.outside + (id - m.inside))
    }

    /// Map a parent id into this namespace.
    pub fn map_in(map: &[IdMapping], id: u32) -> Option<u32> {
        map.iter().find(|m| id >= m.outside && id - m.outside < m.count).map(|m| m.inside + (id - m.outside))
    }

    /// A kernel (initial-namespace) uid as seen in this namespace.
    pub fn uid_from_kernel(self: &Arc<Self>, kuid: u32) -> Option<u32> {
        match &self.parent {
            None => Some(kuid),
            Some(p) => p.uid_from_kernel(kuid).and_then(|id| Self::map_in(&self.uid_map.lock(), id)),
        }
    }

    pub fn gid_from_kernel(self: &Arc<Self>, kgid: u32) -> Option<u32> {
        match &self.parent {
            None => Some(kgid),
            Some(p) => p.gid_from_kernel(kgid).and_then(|id| Self::map_in(&self.gid_map.lock(), id)),
        }
    }

    /// A uid of this namespace as a kernel uid.
    pub fn uid_to_kernel(self: &Arc<Self>, uid: u32) -> Option<u32> {
        match &self.parent {
            None => Some(uid),
            Some(p) => Self::map_out(&self.uid_map.lock(), uid).and_then(|id| p.uid_to_kernel(id)),
        }
    }

    pub fn gid_to_kernel(self: &Arc<Self>, gid: u32) -> Option<u32> {
        match &self.parent {
            None => Some(gid),
            Some(p) => Self::map_out(&self.gid_map.lock(), gid).and_then(|id| p.gid_to_kernel(id)),
        }
    }
}

#[derive(Debug)]
pub struct CgroupNs {
    pub ino: u64,
    /// The user namespace that owns it (capabilities over it count there).
    pub owner: Arc<UserNs>,
    pub root: Arc<crate::fs::cgroup::Cgroup>,
}

#[derive(Debug)]
pub struct NetNs {
    pub ino: u64,
    /// Keys its network stack (kernel/src/net).
    pub id: u64,
    /// Its /proc/sys/net values that were changed, by path (an
    /// interface's own under `sys/net/ipv4/conf/NAME/KEY`).
    pub sysctl: IrqSpinLock<alloc::collections::BTreeMap<String, String>>,
    /// The user namespace that owns it (capabilities over it count there).
    pub owner: Arc<UserNs>,
    /// Routes added to the local table for addresses that are not its own
    /// (rtnetlink(7); pasta copies a namespace's routes): kept and listed,
    /// without effect (docs/GAPS.md). (address, prefix length, link,
    /// protocol).
    pub extra_local: IrqSpinLock<Vec<(slate_net::IpAddr, u8, u32, u8)>>,
}

impl Drop for NetNs {
    fn drop(&mut self) {
        crate::net::drop_ns(self.id);
    }
}

/// `PidNs::init` once the namespace's init has exited.
pub const PID_NS_DEAD: u64 = u64::MAX;

/// A PID namespace (pid_namespaces(7)).
#[derive(Debug)]
pub struct PidNs {
    pub ino: u64,
    /// The user namespace that owns it (capabilities over it count there).
    pub owner: Arc<UserNs>,
    pub parent: Option<Arc<PidNs>>,
    pub level: usize,
    next: AtomicU64,
    /// Host PID of the namespace's init (0 until it exists).
    pub init: AtomicU64,
}

impl PidNs {
    /// The next PID number inside this namespace.
    pub fn alloc(&self) -> u32 {
        self.next.fetch_add(1, Ordering::Relaxed) as u32
    }
}

/// The namespaces a process is in. `pid_for_children` is where its new
/// children go (unshare(CLONE_NEWPID) changes only that).
#[derive(Clone, Debug)]
pub struct Namespaces {
    pub uts: Arc<UtsNs>,
    pub ipc: Arc<IpcNs>,
    pub mnt: Arc<MntNs>,
    pub cgroup: Arc<CgroupNs>,
    pub net: Arc<NetNs>,
    pub pid_for_children: Arc<PidNs>,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

static INITIAL: slate_sync::Once<Namespaces> = slate_sync::Once::new();
static INITIAL_USER: slate_sync::Once<Arc<UserNs>> = slate_sync::Once::new();

/// The initial user namespace: every ID maps to itself.
pub fn initial_user() -> Arc<UserNs> {
    INITIAL_USER
        .call_once(|| {
            Arc::new(UserNs {
                ino: 0xEFFF_FFFD,
                parent: None,
                owner_uid: 0,
                uid_map: IrqSpinLock::new(alloc::vec![IdMapping { inside: 0, outside: 0, count: u32::MAX }]),
                gid_map: IrqSpinLock::new(alloc::vec![IdMapping { inside: 0, outside: 0, count: u32::MAX }]),
                setgroups: IrqSpinLock::new(true),
                max_user_ns: AtomicU64::new(MAX_USER_NS_INITIAL),
                user_ns_below: AtomicU64::new(0),
            })
        })
        .clone()
}

/// The namespaces of the initial processes.
pub fn initial() -> Namespaces {
    INITIAL
        .call_once(|| {
            let owner = initial_user();
            Namespaces {
                uts: Arc::new(UtsNs {
                    ino: 0xEFFF_FFFE,
                    owner: owner.clone(),
                    hostname: IrqSpinLock::new(Vec::new()),
                    domainname: IrqSpinLock::new(Vec::new()),
                }),
                ipc: Arc::new(IpcNs { ino: 0xEFFF_FFFF, owner: owner.clone() }),
                mnt: Arc::new(MntNs {
                    ino: 0xF000_0000 - 8,
                    id: 0,
                    owner: owner.clone(),
                    root: IrqSpinLock::new(None),
                }),
                cgroup: Arc::new(CgroupNs { ino: 0xEFFF_FFFB, owner: owner.clone(), root: crate::fs::cgroup::root() }),
                net: Arc::new(NetNs {
                    ino: 0xF000_0000 - 16,
                    id: 0,
                    sysctl: IrqSpinLock::new(alloc::collections::BTreeMap::new()),
                    owner: owner.clone(),
                    extra_local: IrqSpinLock::new(Vec::new()),
                }),
                pid_for_children: Arc::new(PidNs {
                    ino: 0xEFFF_FFFC,
                    owner,
                    parent: None,
                    level: 0,
                    next: AtomicU64::new(1),
                    init: AtomicU64::new(1),
                }),
            }
        })
        .clone()
}

/// What `Namespaces::unshare` made.
pub struct Unshared {
    pub ns: Namespaces,
    /// The new credentials, when a user namespace was created: full
    /// capabilities inside it.
    pub cred: Option<crate::proc::cred::Cred>,
}

impl Namespaces {
    /// Fresh namespaces for `flags`; the others are shared. `cred` is the
    /// creator's (it owns them), `cgroup` its cgroup.
    pub fn unshare(
        &self,
        flags: u64,
        cred: &crate::proc::cred::Cred,
        cgroup: &Arc<crate::fs::cgroup::Cgroup>,
    ) -> core::result::Result<Unshared, Errno> {
        if flags & CLONE_NEWTIME != 0 {
            return Err(EINVAL);
        }
        let mut n = self.clone();
        let mut new_mnt = None;
        let mut new_cred = None;
        let mut owner = cred.user_ns.clone();
        if flags & CLONE_NEWUSER != 0 {
            if owner.level() >= 32 {
                return Err(EUSERS);
            }
            // Within every ancestor's max_user_namespaces (ENOSPC beyond,
            // user_namespaces(7)); counted until the namespace ends.
            {
                let _turn = USER_NS_COUNT.lock();
                let mut at = Some(owner.clone());
                while let Some(a) = at {
                    if a.user_ns_below.load(Ordering::Relaxed) + 1 > a.max_user_ns.load(Ordering::Relaxed) {
                        return Err(ENOSPC);
                    }
                    at = a.parent.clone();
                }
                let mut at = Some(owner.clone());
                while let Some(a) = at {
                    a.user_ns_below.fetch_add(1, Ordering::Relaxed);
                    at = a.parent.clone();
                }
            }
            // A parent that denied setgroups passes "deny" on
            // (user_namespaces(7)); bubblewrap relies on it (ADR 0114).
            let setgroups = *owner.setgroups.lock();
            owner = Arc::new(UserNs {
                ino: next_ino(),
                parent: Some(owner),
                owner_uid: cred.euid,
                uid_map: IrqSpinLock::new(Vec::new()),
                gid_map: IrqSpinLock::new(Vec::new()),
                setgroups: IrqSpinLock::new(setgroups),
                max_user_ns: AtomicU64::new(MAX_USER_NS_CHILD),
                user_ns_below: AtomicU64::new(0),
            });
            // The creator gets every capability in the new namespace
            // (user_namespaces(7), "Capabilities").
            let mut c = cred.clone();
            c.user_ns = owner.clone();
            c.cap_effective = crate::proc::cred::CAP_FULL;
            c.cap_permitted = crate::proc::cred::CAP_FULL;
            new_cred = Some(c);
        }
        if flags & CLONE_NEWUTS != 0 {
            n.uts = Arc::new(UtsNs {
                ino: next_ino(),
                owner: owner.clone(),
                hostname: IrqSpinLock::new(self.uts.hostname.lock().clone()),
                domainname: IrqSpinLock::new(self.uts.domainname.lock().clone()),
            });
        }
        if flags & CLONE_NEWIPC != 0 {
            n.ipc = Arc::new(IpcNs { ino: next_ino(), owner: owner.clone() });
        }
        if flags & CLONE_NEWNS != 0 {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            n.mnt = Arc::new(MntNs { ino: next_ino(), id, owner: owner.clone(), root: IrqSpinLock::new(None) });
            new_mnt = Some(self.mnt.id);
        }
        if flags & CLONE_NEWCGROUP != 0 {
            n.cgroup = Arc::new(CgroupNs { ino: next_ino(), owner: owner.clone(), root: cgroup.clone() });
        }
        if flags & CLONE_NEWNET != 0 {
            // A stack of its own, with loopback only, made on first use.
            n.net = Arc::new(NetNs {
                ino: next_ino(),
                id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
                sysctl: IrqSpinLock::new(alloc::collections::BTreeMap::new()),
                owner: owner.clone(),
                extra_local: IrqSpinLock::new(Vec::new()),
            });
        }
        if flags & CLONE_NEWPID != 0 {
            let parent = self.pid_for_children.clone();
            if parent.level >= 32 {
                return Err(EUSERS);
            }
            n.pid_for_children = Arc::new(PidNs {
                ino: next_ino(),
                owner: owner.clone(),
                level: parent.level + 1,
                parent: Some(parent),
                next: AtomicU64::new(1),
                init: AtomicU64::new(0),
            });
        }
        // The new mount namespace copies the old one's mounts.
        if let Some(old) = new_mnt {
            crate::fs::vfs::copy_mounts(old, n.mnt.id);
        }
        Ok(Unshared { ns: n, cred: new_cred })
    }
}

/// The kinds of namespace files in /proc/<pid>/ns.
pub const KINDS: &[&str] = &["cgroup", "ipc", "mnt", "net", "pid", "pid_for_children", "user", "uts"];

/// The name and inode of the namespace of `kind` in `n` (namespaces of
/// process `p` or one of its threads), as readlink shows it:
/// `uts:[4026531838]`.
pub fn link(p: &super::Process, n: &Namespaces, kind: &str) -> Option<String> {
    let ino = match kind {
        "cgroup" => n.cgroup.ino,
        "ipc" => n.ipc.ino,
        "mnt" => n.mnt.ino,
        "net" => n.net.ino,
        "pid" => p.pid_ns().ino,
        "pid_for_children" => n.pid_for_children.ino,
        "user" => p.cred().user_ns.ino,
        "uts" => n.uts.ino,
        _ => return None,
    };
    let name = if kind == "pid_for_children" { "pid" } else { kind };
    Some(alloc::format!("{name}:[{ino}]"))
}
