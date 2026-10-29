// SPDX-License-Identifier: MIT OR Apache-2.0

//! <termios.h> and the window size from <sys/ioctl.h> (termios(3),
//! ioctl_tty(2); ADR 0075). `struct termios` begins with the kernel's
//! 36-byte layout (four flag words, the line discipline, 19 control
//! characters), so the TCGETS/TCSETS requests read and write it in place;
//! slate-libc's struct has room for 32 control characters and two speed
//! words after that. Speeds live in c_cflag's CBAUD bits, as on Linux.
//! Request numbers and flag values are Linux's, which Slate's native
//! interface shares (from musl `bits/ioctl.h` and `bits/termios.h`,
//! ADR 0009).

use core::ffi::c_int;

use slate_rt::{Errno, io};

use crate::ret;

const TCGETS: u32 = 0x5401;
const TCSETS: u32 = 0x5402;
const TCSETSW: u32 = 0x5403;
const TCSETSF: u32 = 0x5404;
const TIOCGWINSZ: u32 = 0x5413;
const TIOCSWINSZ: u32 = 0x5414;
const TIOCGPGRP: u32 = 0x540F;
const TIOCSPGRP: u32 = 0x5410;

/// `struct termios`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Termios {
    iflag: u32,
    oflag: u32,
    cflag: u32,
    lflag: u32,
    line: u8,
    cc: [u8; 32],
    ispeed: u32,
    ospeed: u32,
}

// c_iflag
const IGNBRK: u32 = 0o1;
const BRKINT: u32 = 0o2;
const PARMRK: u32 = 0o10;
const ISTRIP: u32 = 0o40;
const INLCR: u32 = 0o100;
const IGNCR: u32 = 0o200;
const ICRNL: u32 = 0o400;
const IXON: u32 = 0o2000;
// c_oflag
const OPOST: u32 = 0o1;
// c_cflag
const CBAUD: u32 = 0o10017;
const CSIZE: u32 = 0o60;
const CS8: u32 = 0o60;
const PARENB: u32 = 0o400;
// c_lflag
const ISIG: u32 = 0o1;
const ICANON: u32 = 0o2;
const ECHO: u32 = 0o10;
const ECHONL: u32 = 0o100;
const IEXTEN: u32 = 0o100000;
// c_cc
const VTIME: usize = 5;
const VMIN: usize = 6;

/// tcsetattr's actions.
const TCSANOW: c_int = 0;
const TCSADRAIN: c_int = 1;
const TCSAFLUSH: c_int = 2;

/// tcflush's queues.
const TCIFLUSH: c_int = 0;
const TCOFLUSH: c_int = 1;
const TCIOFLUSH: c_int = 2;

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcgetattr(fd: c_int, t: *mut Termios) -> c_int {
    // SAFETY: C passes a `struct termios`; the kernel fills its first 36
    // bytes.
    ret(io::ioctl(fd, TCGETS, t as usize).map(|_| {
        // SAFETY: As above.
        unsafe {
            let speed = (*t).cflag & CBAUD;
            (*t).ispeed = speed;
            (*t).ospeed = speed;
        }
        0
    }))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcsetattr(fd: c_int, action: c_int, t: *const Termios) -> c_int {
    let req = match action {
        TCSANOW => TCSETS,
        TCSADRAIN => TCSETSW,
        TCSAFLUSH => TCSETSF,
        _ => return ret::<c_int>(Err(Errno::EINVAL)),
    };
    ret(io::ioctl(fd, req, t as usize).map(|_| 0))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn cfmakeraw(t: *mut Termios) {
    // SAFETY: C passes a `struct termios`.
    let t = unsafe { &mut *t };
    t.iflag &= !(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    t.oflag &= !OPOST;
    t.lflag &= !(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    t.cflag = (t.cflag & !(CSIZE | PARENB)) | CS8;
    t.cc[VMIN] = 1;
    t.cc[VTIME] = 0;
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn cfgetospeed(t: *const Termios) -> u32 {
    // SAFETY: C passes a `struct termios`.
    unsafe { (*t).cflag & CBAUD }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn cfgetispeed(t: *const Termios) -> u32 {
    // SAFETY: As above.
    unsafe { cfgetospeed(t) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetospeed(t: *mut Termios, speed: u32) -> c_int {
    if speed & !CBAUD != 0 {
        return ret::<c_int>(Err(Errno::EINVAL));
    }
    // SAFETY: C passes a `struct termios`.
    unsafe {
        (*t).cflag = ((*t).cflag & !CBAUD) | speed;
        (*t).ispeed = speed;
        (*t).ospeed = speed;
    }
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetispeed(t: *mut Termios, speed: u32) -> c_int {
    // One speed for both directions; 0 means "the output speed".
    if speed == 0 {
        return 0;
    }
    // SAFETY: Forwarded.
    unsafe { cfsetospeed(t, speed) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetspeed(t: *mut Termios, speed: u32) -> c_int {
    // SAFETY: Forwarded.
    unsafe { cfsetospeed(t, speed) }
}

/// The terminal's attributes set again with `req` (TCSETSW waits for
/// output to drain; TCSETSF also discards pending input).
fn reapply(fd: c_int, req: u32) -> c_int {
    let mut t = core::mem::MaybeUninit::<Termios>::zeroed();
    // SAFETY: Room for the attributes, read then written back.
    if unsafe { tcgetattr(fd, t.as_mut_ptr()) } != 0 {
        return -1;
    }
    ret(io::ioctl(fd, req, t.as_ptr() as usize).map(|_| 0))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn tcdrain(fd: c_int) -> c_int {
    reapply(fd, TCSETSW)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn tcflush(fd: c_int, queue: c_int) -> c_int {
    match queue {
        // Output is written as it comes; only input can be pending.
        TCIFLUSH | TCIOFLUSH => reapply(fd, TCSETSF),
        TCOFLUSH => reapply(fd, TCSETS),
        _ => ret::<c_int>(Err(Errno::EINVAL)),
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn tcsendbreak(fd: c_int, _duration: c_int) -> c_int {
    // Slate's terminals have no line to break: only check it is one.
    reapply(fd, TCSETS)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn tcgetpgrp(fd: c_int) -> c_int {
    let mut pg: c_int = 0;
    match io::ioctl(fd, TIOCGPGRP, &mut pg as *mut c_int as usize) {
        Ok(_) => pg,
        Err(e) => ret::<c_int>(Err(e)),
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn tcsetpgrp(fd: c_int, pgrp: c_int) -> c_int {
    ret(io::ioctl(fd, TIOCSPGRP, &pgrp as *const c_int as usize).map(|_| 0))
}

/// ioctl(2) for C (<sys/ioctl.h>): the request and one argument.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn ioctl(fd: c_int, request: core::ffi::c_ulong, mut args: ...) -> c_int {
    // SAFETY: Every ioctl takes at most one argument, an integer or a
    // pointer; a missing one reads as whatever is in its register.
    let arg = unsafe { args.next_arg::<usize>() };
    ret(io::ioctl(fd, request as u32, arg).map(|v| v as c_int))
}

/// The window-size requests, for the header's comment and the tests.
pub const WINSIZE_REQUESTS: [u32; 2] = [TIOCGWINSZ, TIOCSWINSZ];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_and_speeds() {
        let mut t = Termios {
            iflag: ICRNL | IXON,
            oflag: OPOST,
            cflag: 0o15,
            lflag: ECHO | ICANON | ISIG,
            line: 0,
            cc: [0; 32],
            ispeed: 0,
            ospeed: 0,
        };
        // SAFETY: A local struct.
        unsafe {
            cfmakeraw(&mut t);
            assert_eq!((t.iflag, t.oflag, t.lflag & (ECHO | ICANON | ISIG), t.cflag & CSIZE), (0, 0, 0, CS8));
            assert_eq!((t.cc[VMIN], t.cc[VTIME]), (1, 0));
            assert_eq!(cfgetospeed(&t), 0o15);
            assert_eq!(cfsetospeed(&mut t, 0o10002), 0);
            assert_eq!((cfgetispeed(&t), t.cflag & CS8), (0o10002, CS8));
            assert_eq!(cfsetospeed(&mut t, 0o40), -1);
        }
        assert_eq!(core::mem::size_of::<Termios>(), 60);
    }
}
