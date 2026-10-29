// SPDX-License-Identifier: MIT OR Apache-2.0

//! bpf(2), the part container runtimes need: cgroup device programs
//! (BPF_PROG_TYPE_CGROUP_DEVICE) are loaded, attached to, queried on and
//! detached from cgroups, and run by slate-bpf's interpreter when a device
//! is opened or made (fs/cgroup.rs). Other program types and maps are
//! refused (EINVAL).

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::errno::*;
use super::{Args, Result};
use crate::arch::uaccess::{copy_from_user, write_user};
use crate::fs::File;
use crate::sync::IrqSpinLock;

// bpf(2) commands, program and attach types. Source: bpf(2) and its list
// of `enum bpf_cmd` / `enum bpf_prog_type` / `enum bpf_attach_type`.
const BPF_PROG_LOAD: u64 = 5;
const BPF_PROG_ATTACH: u64 = 8;
const BPF_PROG_DETACH: u64 = 9;
const BPF_PROG_GET_FD_BY_ID: u64 = 13;
const BPF_PROG_QUERY: u64 = 16;
const BPF_PROG_TYPE_CGROUP_DEVICE: u32 = 15;
const BPF_CGROUP_DEVICE: u32 = 6;
/// BPF_MAXINSNS (bpf(2)): the classic limit for unprivileged programs.
const MAX_INSNS: usize = 4096;
/// CAP_BPF (capabilities(7)).
const CAP_BPF: u32 = 39;

/// A loaded program.
#[derive(Debug)]
pub struct BpfProg {
    pub id: u32,
    /// The instructions, 8 bytes each.
    pub insns: Vec<u64>,
}

static NEXT_ID: AtomicU32 = AtomicU32::new(1);
static PROGS: IrqSpinLock<BTreeMap<u32, Weak<BpfProg>>> = IrqSpinLock::new(BTreeMap::new());

/// An open program (the descriptor BPF_PROG_LOAD returns).
struct ProgFile {
    prog: Arc<BpfProg>,
}

impl File for ProgFile {
    fn stat(&self) -> core::result::Result<crate::fs::vfs::Metadata, Errno> {
        Ok(crate::fs::vfs::Metadata { mode: 0o600, nlink: 1, ..Default::default() })
    }
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

/// Read `size` bytes of the attribute union, zero-extended to `N`.
fn attr<const N: usize>(addr: u64, size: u64) -> core::result::Result<[u8; N], Errno> {
    let mut b = [0u8; N];
    let n = (size as usize).min(N);
    copy_from_user(&mut b[..n], addr).map_err(|_| EFAULT)?;
    Ok(b)
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn u64_at(b: &[u8], off: usize) -> u64 {
    let mut x = [0u8; 8];
    x.copy_from_slice(&b[off..off + 8]);
    u64::from_ne_bytes(x)
}

fn install(p: Arc<BpfProg>) -> Result {
    let me = crate::proc::current().ok_or(ESRCH)?;
    Ok(me.files.lock().insert(Arc::new(ProgFile { prog: p }), true)? as u64)
}

fn prog_of_fd(fd: u32) -> core::result::Result<Arc<BpfProg>, Errno> {
    let f = crate::proc::current().ok_or(ESRCH)?.files.lock().get(fd as i32)?;
    f.as_any().and_then(|a| a.downcast_ref::<ProgFile>()).map(|pf| pf.prog.clone()).ok_or(EINVAL)
}

pub fn bpf(a: Args) -> Result {
    let (cmd, addr, size) = (a.0[0], a.0[1], a.0[2]);
    let cred = crate::proc::cred::current();
    if !cred.capable(crate::proc::cred::CAP_SYS_ADMIN) && !cred.capable(CAP_BPF) {
        return Err(EPERM);
    }
    match cmd {
        BPF_PROG_LOAD => {
            // union bpf_attr, BPF_PROG_LOAD: prog_type, insn_cnt, insns,
            // license, ... (bpf(2)).
            let b: [u8; 128] = attr(addr, size)?;
            let (prog_type, cnt, insns) = (u32_at(&b, 0), u32_at(&b, 4) as usize, u64_at(&b, 8));
            if prog_type != BPF_PROG_TYPE_CGROUP_DEVICE || cnt == 0 || cnt > MAX_INSNS {
                return Err(EINVAL);
            }
            let mut raw = alloc::vec![0u8; cnt * 8];
            copy_from_user(&mut raw, insns).map_err(|_| EFAULT)?;
            let insns = raw.chunks(8).map(|c| u64_at(c, 0)).collect();
            let p = Arc::new(BpfProg { id: NEXT_ID.fetch_add(1, Ordering::Relaxed), insns });
            PROGS.lock().insert(p.id, Arc::downgrade(&p));
            install(p)
        }
        BPF_PROG_ATTACH | BPF_PROG_DETACH => {
            // target_fd, attach_bpf_fd, attach_type, attach_flags.
            let b: [u8; 16] = attr(addr, size)?;
            if u32_at(&b, 8) != BPF_CGROUP_DEVICE {
                return Err(EINVAL);
            }
            let cg = cgroup_of_fd(u32_at(&b, 0))?;
            if cmd == BPF_PROG_ATTACH {
                cg.attach_device_prog(prog_of_fd(u32_at(&b, 4))?)?;
            } else {
                let id = prog_of_fd(u32_at(&b, 4)).ok().map(|p| p.id);
                cg.detach_device_prog(id)?;
            }
            Ok(0)
        }
        BPF_PROG_QUERY => {
            // target_fd, attach_type, query_flags, attach_flags, prog_ids,
            // prog_cnt.
            let b: [u8; 28] = attr(addr, size)?;
            if u32_at(&b, 4) != BPF_CGROUP_DEVICE {
                return Err(EINVAL);
            }
            let ids = cgroup_of_fd(u32_at(&b, 0))?.device_prog_ids();
            let (ids_ptr, room) = (u64_at(&b, 16), u32_at(&b, 24) as usize);
            if ids_ptr != 0 {
                for (i, id) in ids.iter().take(room).enumerate() {
                    write_user(ids_ptr + 4 * i as u64, id).map_err(|_| EFAULT)?;
                }
            }
            write_user(addr + 24, &(ids.len() as u32)).map_err(|_| EFAULT)?;
            if ids_ptr != 0 && ids.len() > room { Err(ENOSPC) } else { Ok(0) }
        }
        BPF_PROG_GET_FD_BY_ID => {
            let b: [u8; 4] = attr(addr, size)?;
            let p = PROGS.lock().get(&u32_at(&b, 0)).and_then(Weak::upgrade).ok_or(ENOENT)?;
            install(p)
        }
        _ => {
            static WARNED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
            if !WARNED.swap(true, Ordering::Relaxed) {
                crate::log_warn!("bpf: command {cmd} is not supported");
            }
            Err(EINVAL)
        }
    }
}

fn cgroup_of_fd(fd: u32) -> core::result::Result<Arc<crate::fs::cgroup::Cgroup>, Errno> {
    let f = crate::proc::current().ok_or(ESRCH)?.files.lock().get(fd as i32)?;
    let d = f.dentry().ok_or(EBADF)?;
    crate::fs::cgroup::of_inode(&d.inode).ok_or(EBADF)
}
