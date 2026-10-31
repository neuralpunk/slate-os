// SPDX-License-Identifier: MIT OR Apache-2.0

//! Virtual consoles (ADR 0185): `/dev/tty1` to `/dev/tty12` on the one
//! screen, the one in front drawn by the framebuffer console and given the
//! keyboard. VT 1 is the console (`/dev/console`, mirrored to the serial
//! port); `/dev/tty0` is whichever is in front.
//!
//! Switching follows console_ioctl(2): a VT in VT_PROCESS mode belongs to
//! a process that is sent its release signal when the VT is to go and
//! allows it with VT_RELDISP, and its acquire signal when the VT comes
//! back; a VT in VT_AUTO mode lets go at once. KD_GRAPHICS keeps the
//! console from drawing a VT, K_OFF from giving it the keyboard. Ctrl+Alt
//! and F1 to F12 (or Alt and an F key) switch while the console reads the
//! keyboard.
//!
//! The ioctl numbers, structures and values are console_ioctl(2)'s.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::tty::Tty;
use super::vfs::Result;
use crate::abi::linux::errno::{EFAULT, EINTR, EINVAL, ENXIO, EPERM};
use crate::arch::uaccess::{read_user, write_user};
use crate::sched::wait::WaitResult;
use crate::sync::IrqSpinLock;

/// How many virtual consoles there are.
pub const COUNT: usize = 12;

// console_ioctl(2).
pub const KDGKBTYPE: u32 = 0x4B33;
pub const KDSETMODE: u32 = 0x4B3A;
pub const KDGETMODE: u32 = 0x4B3B;
pub const KDGKBMODE: u32 = 0x4B44;
pub const KDSKBMODE: u32 = 0x4B45;
pub const VT_OPENQRY: u32 = 0x5600;
pub const VT_GETMODE: u32 = 0x5601;
pub const VT_SETMODE: u32 = 0x5602;
pub const VT_GETSTATE: u32 = 0x5603;
pub const VT_RELDISP: u32 = 0x5605;
pub const VT_ACTIVATE: u32 = 0x5606;
pub const VT_WAITACTIVE: u32 = 0x5607;
/// KDGKBTYPE's answer: a 101-key keyboard.
const KB_101: u8 = 0x02;
pub const KD_TEXT: u32 = 0x00;
pub const KD_GRAPHICS: u32 = 0x01;
/// Keyboard modes: K_UNICODE (the default here) and K_OFF.
pub const K_UNICODE: u32 = 0x03;
pub const K_OFF: u32 = 0x04;
pub const VT_AUTO: u8 = 0x00;
pub const VT_PROCESS: u8 = 0x01;
pub const VT_ACKACQ: u64 = 0x02;

/// `struct vt_mode`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VtMode {
    pub mode: u8,
    pub waitv: u8,
    pub relsig: i16,
    pub acqsig: i16,
    pub frsig: i16,
}

/// `struct vt_stat`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct VtStat {
    v_active: u16,
    v_signal: u16,
    v_state: u16,
}

#[derive(Clone, Copy, Debug, Default)]
struct Vt {
    mode: VtMode,
    /// The process that set VT_PROCESS.
    owner: u32,
    graphics: bool,
    kbmode: u32,
    /// Open files on it (VT 1, the console, counts as always open).
    opens: u32,
}

struct State {
    /// The VT in front (1 to 12).
    active: usize,
    /// A switch waiting for the VT in front's owner to let go.
    pending: Option<usize>,
    vts: [Vt; COUNT + 1],
}

static STATE: IrqSpinLock<State> = IrqSpinLock::new(State {
    active: 1,
    pending: None,
    vts: [Vt {
        mode: VtMode { mode: VT_AUTO, waitv: 0, relsig: 0, acqsig: 0, frsig: 0 },
        owner: 0,
        graphics: false,
        kbmode: K_UNICODE,
        opens: 0,
    }; COUNT + 1],
});

/// VTs 2 to 12's terminals, made when first opened.
static TTYS: IrqSpinLock<Vec<Option<Arc<Tty>>>> = IrqSpinLock::new(Vec::new());

/// Virtual console `n`'s terminal (VT 1 is the console).
pub fn tty(n: usize) -> Option<Arc<Tty>> {
    if n == 1 {
        return Some(super::tty::console().clone());
    }
    if !(2..=COUNT).contains(&n) {
        return None;
    }
    let mut t = TTYS.lock();
    while t.len() <= n {
        t.push(None);
    }
    Some(t[n].get_or_insert_with(|| super::tty::new_vt(n as u8)).clone())
}

/// The VT in front's terminal, if it has been made, for the keyboard.
fn front_tty() -> Option<Arc<Tty>> {
    let n = active();
    if n == 1 {
        return super::tty::console_if_ready().cloned();
    }
    TTYS.lock().get(n).cloned().flatten()
}

/// The VT in front.
pub fn active() -> usize {
    STATE.lock().active
}

/// A file was opened on VT `n`, or closed.
pub fn opened(n: usize, open: bool) {
    let mut s = STATE.lock();
    if let Some(v) = s.vts.get_mut(n) {
        if open {
            v.opens += 1;
        } else {
            v.opens = v.opens.saturating_sub(1);
        }
    }
}

/// Whether the console gives the keyboard to the VT in front (it isn't in
/// K_OFF).
pub fn keyboard_on() -> bool {
    let s = STATE.lock();
    s.vts[s.active].kbmode != K_OFF
}

/// Ask for VT `n` to come to the front: at once, or once the VT in
/// front's owner lets go.
pub fn activate(n: usize) -> Result<()> {
    if !(1..=COUNT).contains(&n) {
        return Err(ENXIO);
    }
    let mut s = STATE.lock();
    if s.active == n {
        s.pending = None;
        return Ok(());
    }
    let cur = s.vts[s.active];
    if cur.mode.mode == VT_PROCESS {
        if let Some(owner) = crate::proc::get(cur.owner) {
            s.pending = Some(n);
            drop(s);
            crate::proc::signal::send_to_process(&owner, cur.mode.relsig as u32);
            return Ok(());
        }
        // Its owner is gone: the VT is the system's again.
        let a = s.active;
        s.vts[a].mode = VtMode::default();
        s.vts[a].owner = 0;
    }
    drop(s);
    complete(n);
    Ok(())
}

/// Put VT `n` in front: draw it, wake who waits for it, and tell its
/// owner it has it.
fn complete(n: usize) {
    let new = {
        let mut s = STATE.lock();
        s.active = n;
        s.pending = None;
        s.vts[n]
    };
    crate::drivers::fbcon::switch(n);
    super::poll_notify();
    if new.mode.mode == VT_PROCESS
        && let Some(owner) = crate::proc::get(new.owner)
    {
        crate::proc::signal::send_to_process(&owner, new.mode.acqsig as u32);
    }
}

/// Alt, as the console's keyboard has it now (Ctrl with it changes
/// nothing).
static ALT: AtomicBool = AtomicBool::new(false);

/// A key from a keyboard in scan code set 1 (`code`'s top bit: released),
/// before the console types it: Alt (with or without Ctrl) and F1 to F12
/// switch VTs while the console reads the keyboard (`console`) and the VT
/// in front isn't in K_OFF. Returns whether it was taken for that.
pub fn key(code: u8, extended: bool, console: bool) -> bool {
    let down = code & 0x80 == 0;
    match code & 0x7F {
        0x38 => ALT.store(down, Ordering::Relaxed),
        // F1 to F10 are 0x3B to 0x44, F11 0x57, F12 0x58.
        k @ (0x3B..=0x44 | 0x57 | 0x58) if !extended && console && keyboard_on() && ALT.load(Ordering::Relaxed) => {
            if down {
                let n = match k {
                    0x57 => 11,
                    0x58 => 12,
                    k => usize::from(k - 0x3B) + 1,
                };
                let _ = activate(n);
            }
            return true;
        }
        _ => {}
    }
    false
}

/// Type `bytes` on the VT in front (the console reads the keyboard).
pub fn type_bytes(bytes: &[u8]) {
    if !keyboard_on() {
        return;
    }
    if let Some(t) = front_tty() {
        for &b in bytes {
            t.receive(b);
        }
    }
}

/// May the caller change VT `n`: root (CAP_SYS_TTY_CONFIG is held by
/// root here), or a process whose controlling terminal it is.
fn may_change(n: usize) -> bool {
    let Some(p) = crate::proc::current() else { return true };
    if p.cred().capable(crate::proc::cred::CAP_SYS_ADMIN) {
        return true;
    }
    p.ctty().is_some_and(|c| tty(n).is_some_and(|t| Arc::ptr_eq(&c, &t)))
}

/// The VT ioctls on a file of VT `n`; `None`: not one of them.
pub fn ioctl(n: usize, cmd: u32, arg: u64) -> Option<Result<u64>> {
    if !matches!(
        cmd,
        KDGKBTYPE
            | KDGETMODE
            | KDSETMODE
            | KDGKBMODE
            | KDSKBMODE
            | VT_OPENQRY
            | VT_GETSTATE
            | VT_GETMODE
            | VT_SETMODE
            | VT_RELDISP
            | VT_ACTIVATE
            | VT_WAITACTIVE
    ) {
        return None;
    }
    let fault = |_| EFAULT;
    Some((|| -> Result<u64> {
        match cmd {
            KDGKBTYPE => write_user(arg, &KB_101).map_err(fault)?,
            KDGETMODE => {
                let m = if STATE.lock().vts[n].graphics { KD_GRAPHICS } else { KD_TEXT };
                write_user(arg, &m).map_err(fault)?;
            }
            KDSETMODE => {
                if !may_change(n) {
                    return Err(EPERM);
                }
                let on = match arg as u32 {
                    KD_TEXT => false,
                    KD_GRAPHICS => true,
                    _ => return Err(EINVAL),
                };
                STATE.lock().vts[n].graphics = on;
                crate::drivers::fbcon::set_graphics(n, on);
            }
            KDGKBMODE => {
                let m = STATE.lock().vts[n].kbmode;
                write_user(arg, &m).map_err(fault)?;
            }
            KDSKBMODE => {
                if !may_change(n) {
                    return Err(EPERM);
                }
                // K_RAW, K_XLATE, K_MEDIUMRAW, K_UNICODE are typed the same
                // here (the console makes characters); K_OFF types nothing.
                if arg > u64::from(K_OFF) {
                    return Err(EINVAL);
                }
                STATE.lock().vts[n].kbmode = arg as u32;
            }
            VT_OPENQRY => {
                let s = STATE.lock();
                let free = (2..=COUNT).find(|&i| s.vts[i].opens == 0).map_or(-1, |i| i as i32);
                drop(s);
                write_user(arg, &free).map_err(fault)?;
            }
            VT_GETSTATE => {
                let s = STATE.lock();
                // VT 1, the console, is always open.
                let state =
                    s.vts.iter().enumerate().skip(2).filter(|(_, v)| v.opens > 0).fold(1u16, |m, (i, _)| m | 1 << i);
                let st = VtStat { v_active: s.active as u16, v_signal: 0, v_state: state };
                drop(s);
                write_user(arg, &st).map_err(fault)?;
            }
            VT_GETMODE => {
                let m = STATE.lock().vts[n].mode;
                write_user(arg, &m).map_err(fault)?;
            }
            VT_SETMODE => {
                if !may_change(n) {
                    return Err(EPERM);
                }
                let m: VtMode = read_user(arg).map_err(fault)?;
                if m.mode > VT_PROCESS {
                    return Err(EINVAL);
                }
                let owner = crate::proc::current().map_or(0, |p| p.pid);
                let mut s = STATE.lock();
                s.vts[n].mode = m;
                s.vts[n].owner = if m.mode == VT_PROCESS { owner } else { 0 };
                // Back to VT_AUTO while a switch waits: it goes ahead.
                if m.mode == VT_AUTO
                    && s.active == n
                    && let Some(to) = s.pending
                {
                    drop(s);
                    complete(to);
                }
            }
            VT_RELDISP => {
                let mut s = STATE.lock();
                if s.vts[n].mode.mode != VT_PROCESS {
                    return Err(EINVAL);
                }
                match arg {
                    VT_ACKACQ => {}
                    0 => s.pending = None,
                    _ => {
                        if let Some(to) = s.pending.filter(|_| s.active == n) {
                            drop(s);
                            complete(to);
                        }
                    }
                }
            }
            VT_ACTIVATE => {
                if !may_change(n) {
                    return Err(EPERM);
                }
                activate(arg as usize)?;
            }
            VT_WAITACTIVE => {
                let want = arg as usize;
                if !(1..=COUNT).contains(&want) {
                    return Err(ENXIO);
                }
                loop {
                    let seen = super::poll_generation();
                    if active() == want {
                        break;
                    }
                    if let WaitResult::Interrupted = super::poll_wait(seen, None) {
                        return Err(EINTR);
                    }
                }
            }
            _ => return Err(EINVAL),
        }
        Ok(0)
    })())
}
