// SPDX-License-Identifier: MIT OR Apache-2.0

//! System call personalities: the Linux x86-64 ABI, and Slate's native
//! ABI (ADR 0031). Each process uses one, chosen when it execs.

pub mod linux;
pub mod native;

use crate::arch::trap::TrapFrame;

// The kernel's own `Slate` note (ADR 0086): the native interface versions
// it serves, for `slate-update` to check a system's unlock program against
// before booting the two together. Owner "Slate" (namesz 6), descsz 8,
// type 2.
core::arch::global_asm!(
    ".pushsection .note.slate,\"a\",@note",
    ".balign 4",
    ".long 6",
    ".long 8",
    ".long {kind}",
    ".asciz \"Slate\"",
    ".balign 4",
    ".long {oldest}",
    ".long {newest}",
    ".popsection",
    kind = const slate_abi::NT_SLATE_KERNEL_ABI,
    oldest = const slate_abi::OLDEST_VERSION,
    newest = const slate_abi::VERSION,
);

/// Run the system call in `frame` through the caller's interface.
pub fn syscall(frame: &mut TrapFrame) {
    let native = crate::sched::current().process.as_ref().is_some_and(|p| p.abi() == crate::proc::Abi::Native);
    if native {
        native::syscall(frame)
    } else if crate::proc::domain::compat() {
        linux::syscall(frame)
    } else {
        // In Slate mode the Linux table is unreachable (ADR 0032): no Linux
        // program can start, and turning the mode off stopped the others.
        // A straggler is ended rather than served.
        if let Some(p) = crate::proc::current() {
            crate::log_warn!("pid {} ({}): Linux system call in Slate mode; ending it", p.pid, *p.name.lock());
        }
        crate::proc::exit_current(crate::proc::wait_status_signaled(crate::proc::signal::SIGKILL as i32));
    }
}
