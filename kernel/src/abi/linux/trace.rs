// SPDX-License-Identifier: MIT OR Apache-2.0

//! System call tracing, for debugging compatibility problems: the calls of
//! selected processes and their results go to the kernel log, like a tiny
//! built-in strace. Selected by command name (or `pid:N`) on the kernel
//! command line (`slate.strace=cargo,rustc`) or at run time through
//! /proc/slate_strace (write a comma-separated list; an empty write stops).
//! `slate.strace_calls=mmap,munmap,clone` logs only the calls named.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};

use super::{Args, Result, nr};
use crate::sync::IrqSpinLock;

static ENABLED: AtomicBool = AtomicBool::new(false);
static FILTER: IrqSpinLock<Vec<String>> = IrqSpinLock::new(Vec::new());
/// The calls to log (all when empty).
static CALLS: IrqSpinLock<Vec<String>> = IrqSpinLock::new(Vec::new());

/// Trace the processes named in `spec` (comma-separated command names or
/// `pid:N`); an empty spec turns tracing off.
pub fn set(spec: &str) {
    let list: Vec<String> = spec.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect();
    ENABLED.store(!list.is_empty(), Ordering::Release);
    *FILTER.lock() = list;
}

/// The current selection, comma-separated.
pub fn get() -> String {
    FILTER.lock().join(",")
}

/// Apply `slate.strace=` from the kernel command line.
pub fn configure(cmdline: &str) {
    if let Some(spec) = cmdline.split_ascii_whitespace().find_map(|w| w.strip_prefix("slate.strace=")) {
        set(spec);
    }
    if let Some(spec) = cmdline.split_ascii_whitespace().find_map(|w| w.strip_prefix("slate.strace_calls=")) {
        *CALLS.lock() = spec.split(',').filter(|s| !s.is_empty()).map(String::from).collect();
    }
}

/// Whether the current process's calls are traced.
pub fn wanted() -> bool {
    if !ENABLED.load(Ordering::Acquire) {
        return false;
    }
    let Some(p) = crate::proc::current() else { return false };
    let name = p.name.lock().clone();
    // A name, `prefix*`, or `pid:N`.
    FILTER.lock().iter().any(|f| {
        *f == name
            || f.strip_suffix('*').is_some_and(|pre| name.starts_with(pre))
            || f.strip_prefix("pid:").and_then(|n| n.parse().ok()) == Some(p.pid)
    })
}

/// Index of an argument that is a path, for the calls where one is worth
/// showing.
fn path_arg(nr: u64) -> Option<usize> {
    match nr {
        nr::OPEN
        | nr::STAT
        | nr::LSTAT
        | nr::ACCESS
        | nr::EXECVE
        | nr::CHDIR
        | nr::MKDIR
        | nr::RMDIR
        | nr::UNLINK
        | nr::READLINK
        | nr::CHMOD
        | nr::CHOWN
        | nr::LCHOWN
        | nr::TRUNCATE
        | nr::CREAT
        | nr::STATFS
        | nr::CHROOT
        | nr::RENAME
        | nr::LINK
        | nr::SYMLINK
        | nr::MOUNT
        | nr::UMOUNT2
        | nr::PIVOT_ROOT => Some(0),
        nr::OPENAT
        | nr::NEWFSTATAT
        | nr::STATX
        | nr::FACCESSAT
        | nr::FACCESSAT2
        | nr::MKDIRAT
        | nr::UNLINKAT
        | nr::READLINKAT
        | nr::FCHMODAT
        | nr::FCHOWNAT
        | nr::UTIMENSAT
        | nr::RENAMEAT
        | nr::RENAMEAT2
        | nr::MKNODAT
        | nr::LINKAT
        | nr::EXECVEAT
        | nr::OPENAT2 => Some(1),
        _ => None,
    }
}

/// Log one finished call.
pub fn log(nr: u64, a: &Args, r: &Result) {
    {
        let calls = CALLS.lock();
        if !calls.is_empty() && !nr::name(nr).is_some_and(|n| calls.iter().any(|c| c.eq_ignore_ascii_case(n))) {
            return;
        }
    }
    let Some(p) = crate::proc::current() else { return };
    let mut s = String::new();
    let _ = write!(s, "strace {}/{} {}: ", p.pid, crate::sched::current().tid, *p.name.lock());
    match nr::name(nr) {
        Some(n) => s.push_str(&n.to_ascii_lowercase()),
        None => {
            let _ = write!(s, "syscall_{nr}");
        }
    }
    s.push('(');
    let path = path_arg(nr);
    for (i, v) in a.0.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        match crate::arch::uaccess::read_user_cstr(*v, 200) {
            Ok(bytes) if Some(i) == path => {
                let _ = write!(s, "{:?}", String::from_utf8_lossy(&bytes));
            }
            _ => {
                let _ = write!(s, "{v:#x}");
            }
        }
    }
    let _ = match r {
        Ok(v) => write!(s, ") = {v:#x}"),
        Err(e) => write!(s, ") = -{}", e.0),
    };
    crate::log_info!("{s}");
}
