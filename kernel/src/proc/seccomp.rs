// SPDX-License-Identifier: MIT OR Apache-2.0

//! seccomp (seccomp(2), ADR 0028): strict mode, and classic BPF filters
//! (run by slate-bpf) that judge every system call from `struct
//! seccomp_data`. Filters are per process (a thread's filter applies to its
//! whole process, as with SECCOMP_FILTER_FLAG_TSYNC), inherited by fork and
//! kept across execve. USER_NOTIF and TRACE have no listener or tracer to
//! go to, so they fail the call with ENOSYS, as seccomp(2) says they do
//! then.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicBool;

use slate_bpf::SockFilter;

// Return actions (seccomp(2)). Source: the man page's list.
pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const RET_KILL_THREAD: u32 = 0x0000_0000;
pub const RET_TRAP: u32 = 0x0003_0000;
pub const RET_ERRNO: u32 = 0x0005_0000;
pub const RET_USER_NOTIF: u32 = 0x7FC0_0000;
pub const RET_TRACE: u32 = 0x7FF0_0000;
pub const RET_LOG: u32 = 0x7FFC_0000;
pub const RET_ALLOW: u32 = 0x7FFF_0000;
const RET_ACTION_FULL: u32 = 0xFFFF_0000;
const RET_DATA: u32 = 0x0000_FFFF;
/// AUDIT_ARCH_X86_64 (seccomp(2) examples).
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
/// `sizeof(struct seccomp_data)`.
pub const DATA_LEN: usize = 64;
/// The most instructions all of a process's filters may hold
/// (MAX_INSNS_PER_PATH, seccomp(2) ENOMEM).
pub const MAX_TOTAL_INSNS: usize = 32768;

pub const MODE_STRICT: u8 = 1;
pub const MODE_FILTER: u8 = 2;

#[derive(Debug)]
pub struct Filter {
    pub prog: Vec<SockFilter>,
    /// SECCOMP_FILTER_FLAG_LOG: log what isn't allowed.
    pub log: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Seccomp {
    pub mode: u8,
    /// Oldest first.
    pub filters: Vec<Arc<Filter>>,
}

/// Set once any process uses seccomp, so system calls skip the check
/// until then.
pub static IN_USE: AtomicBool = AtomicBool::new(false);

/// What to do with a system call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Errno(u16),
    /// Deliver SIGSYS and fail with ENOSYS.
    Trap(u16),
    /// Fail with ENOSYS (TRACE, USER_NOTIF without a tracer/listener).
    NoSys,
    KillThread,
    KillProcess,
}

/// Judge system call `nr` with `args` at `ip` under `s`.
pub fn judge(s: &Seccomp, nr: u64, args: &[u64; 6], ip: u64) -> Verdict {
    match s.mode {
        MODE_STRICT => {
            // read, write, exit, rt_sigreturn (seccomp(2) SECCOMP_SET_MODE_STRICT).
            return if matches!(nr, 0 | 1 | 60 | 15) { Verdict::Allow } else { Verdict::KillThread };
        }
        MODE_FILTER => {}
        _ => return Verdict::Allow,
    }
    let mut data = [0u8; DATA_LEN];
    data[..4].copy_from_slice(&(nr as u32).to_ne_bytes());
    data[4..8].copy_from_slice(&AUDIT_ARCH_X86_64.to_ne_bytes());
    data[8..16].copy_from_slice(&ip.to_ne_bytes());
    for (i, a) in args.iter().enumerate() {
        data[16 + 8 * i..24 + 8 * i].copy_from_slice(&a.to_ne_bytes());
    }
    // Every filter runs; the action with the highest precedence (lowest as
    // a signed value) wins.
    let mut best = RET_ALLOW;
    let mut log = false;
    for f in s.filters.iter().rev() {
        let r = slate_bpf::run_cbpf(&f.prog, &data);
        if ((r & RET_ACTION_FULL) as i32) < ((best & RET_ACTION_FULL) as i32) {
            best = r;
            log = f.log;
        }
    }
    let data_bits = (best & RET_DATA) as u16;
    let v = match best & RET_ACTION_FULL {
        RET_ALLOW => Verdict::Allow,
        RET_LOG => {
            crate::log_info!("seccomp: logged system call {nr}");
            Verdict::Allow
        }
        RET_ERRNO => Verdict::Errno(data_bits.min(4095)),
        RET_TRAP => Verdict::Trap(data_bits),
        RET_TRACE | RET_USER_NOTIF => Verdict::NoSys,
        RET_KILL_THREAD => Verdict::KillThread,
        _ => Verdict::KillProcess,
    };
    if log && v != Verdict::Allow {
        crate::log_info!("seccomp: system call {nr}: {v:?}");
    }
    v
}
