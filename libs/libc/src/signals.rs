// SPDX-License-Identifier: MIT OR Apache-2.0

//! <signal.h>'s POSIX side (ADR 0075): sigaction with its flags and
//! handler mask, the signal masks (sigprocmask, pthread_sigmask; the
//! kernel keeps one per thread) and the set functions. A `sigset_t` is
//! one 64-bit word, bit n-1 for signal n, which is the kernel's mask.
//! There is no sigsuspend or pause: the native interface has no call to
//! wait with a mask atomically (docs/GAPS.md).

use core::ffi::c_int;

use slate_rt::Errno;
use slate_rt::signal::{self, Action};

use crate::set_errno;

/// `struct sigaction` as slate-libc's <signal.h> lays it out.
#[repr(C)]
pub struct SigAction {
    handler: usize,
    mask: u64,
    flags: c_int,
    restorer: usize,
}

const NSIG: c_int = 65;

fn valid(sig: c_int) -> bool {
    (1..NSIG).contains(&sig)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn sigaction(sig: c_int, act: *const SigAction, old: *mut SigAction) -> c_int {
    if !valid(sig) {
        set_errno(Errno::EINVAL);
        return -1;
    }
    // SAFETY: C passes null or a `struct sigaction`.
    let new = unsafe { act.as_ref() }.map(|a| Action { handler: a.handler, flags: a.flags as u32, mask: a.mask });
    match signal::action(sig, new.as_ref()) {
        Ok(prev) => {
            // SAFETY: C passes null or room for the old action.
            if let Some(o) = unsafe { old.as_mut() } {
                *o = SigAction { handler: prev.handler, mask: prev.mask, flags: prev.flags as c_int, restorer: 0 };
            }
            0
        }
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

/// sigprocmask's `how` (POSIX values, the kernel's too).
const SIG_BLOCK: c_int = 0;
const SIG_UNBLOCK: c_int = 1;
const SIG_SETMASK: c_int = 2;

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn sigprocmask(how: c_int, set: *const u64, old: *mut u64) -> c_int {
    // SAFETY: C passes null or a set.
    let r = match unsafe { set.as_ref() } {
        None => signal::block(0),
        Some(&s) => match how {
            SIG_BLOCK => signal::block(s),
            SIG_UNBLOCK => signal::unblock(s),
            SIG_SETMASK => signal::set_mask(s),
            _ => Err(Errno::EINVAL),
        },
    };
    match r {
        Ok(prev) => {
            if !old.is_null() {
                // SAFETY: C passes room for the old set.
                unsafe { *old = prev };
            }
            0
        }
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_sigmask(how: c_int, set: *const u64, old: *mut u64) -> c_int {
    // SAFETY: As for sigprocmask; the kernel's mask is per thread.
    if unsafe { sigprocmask(how, set, old) } == 0 { 0 } else { crate::errno() }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn sigemptyset(set: *mut u64) -> c_int {
    // SAFETY: C passes a set.
    unsafe { *set = 0 };
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn sigfillset(set: *mut u64) -> c_int {
    // SAFETY: C passes a set.
    unsafe { *set = u64::MAX };
    0
}

/// Change signal `sig`'s bit in `set`.
unsafe fn change(set: *mut u64, sig: c_int, on: bool) -> c_int {
    if !valid(sig) {
        set_errno(Errno::EINVAL);
        return -1;
    }
    let bit = 1u64 << (sig - 1);
    // SAFETY: C passes a set.
    unsafe {
        if on {
            *set |= bit;
        } else {
            *set &= !bit;
        }
    }
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn sigaddset(set: *mut u64, sig: c_int) -> c_int {
    // SAFETY: Forwarded.
    unsafe { change(set, sig, true) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn sigdelset(set: *mut u64, sig: c_int) -> c_int {
    // SAFETY: Forwarded.
    unsafe { change(set, sig, false) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn sigismember(set: *const u64, sig: c_int) -> c_int {
    if !valid(sig) {
        set_errno(Errno::EINVAL);
        return -1;
    }
    // SAFETY: C passes a set.
    c_int::from(unsafe { *set } & (1 << (sig - 1)) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets() {
        let mut s = 7u64;
        // SAFETY: A local set.
        unsafe {
            sigemptyset(&mut s);
            assert_eq!(sigaddset(&mut s, 10), 0);
            assert_eq!(sigismember(&s, 10), 1);
            assert_eq!(sigismember(&s, 11), 0);
            assert_eq!(sigdelset(&mut s, 10), 0);
            assert_eq!(s, 0);
            assert_eq!(sigaddset(&mut s, 0), -1);
            sigfillset(&mut s);
            assert_eq!(sigismember(&s, 64), 1);
        }
    }
}
