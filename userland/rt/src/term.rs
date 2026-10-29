// SPDX-License-Identifier: MIT OR Apache-2.0

//! Terminals: termios (the kernel's 36-byte `struct termios`), window size
//! and foreground process groups. Request numbers and flag values from
//! musl `bits/ioctl.h` and `bits/termios.h` (ADR 0009).

use crate::errno::Result;
use crate::sys;

const TCGETS: usize = 0x5401;
const TCSETS: usize = 0x5402;
const TCSETSW: usize = 0x5403;
const TIOCGPGRP: usize = 0x540F;
const TIOCSPGRP: usize = 0x5410;
const TIOCGWINSZ: usize = 0x5413;
const TIOCSCTTY: usize = 0x540E;
const TIOCSWINSZ: usize = 0x5414;
const TIOCGPTN: usize = 0x8004_5430;
const TIOCSPTLCK: usize = 0x4004_5431;

// c_lflag
pub const ISIG: u32 = 0o1;
pub const ICANON: u32 = 0o2;
pub const ECHO: u32 = 0o10;
pub const ECHOE: u32 = 0o20;
pub const ECHOK: u32 = 0o40;
pub const ECHONL: u32 = 0o100;
pub const IEXTEN: u32 = 0o100000;
// c_iflag
pub const ICRNL: u32 = 0o400;
pub const IXON: u32 = 0o2000;
// c_oflag
pub const OPOST: u32 = 0o1;
pub const ONLCR: u32 = 0o4;
// c_cc indexes
pub const VINTR: usize = 0;
pub const VERASE: usize = 2;
pub const VEOF: usize = 4;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Termios {
    pub iflag: u32,
    pub oflag: u32,
    pub cflag: u32,
    pub lflag: u32,
    pub line: u8,
    pub cc: [u8; 19],
}

pub fn get(fd: i32) -> Result<Termios> {
    let mut t = Termios::default();
    crate::syscall!(sys::pick(sys::IOCTL, slate_abi::nr::IOCTL), fd, TCGETS, &mut t as *mut Termios)?;
    Ok(t)
}

/// Set terminal attributes (after output drains when `drain`).
pub fn set(fd: i32, t: &Termios, drain: bool) -> Result<()> {
    crate::syscall!(
        sys::pick(sys::IOCTL, slate_abi::nr::IOCTL),
        fd,
        if drain { TCSETSW } else { TCSETS },
        t as *const Termios
    )
    .map(|_| ())
}

pub fn isatty(fd: i32) -> bool {
    get(fd).is_ok()
}

/// (rows, columns), if `fd` is a terminal that knows its size.
pub fn size(fd: i32) -> Option<(u16, u16)> {
    let mut ws = [0u16; 4];
    crate::syscall!(sys::pick(sys::IOCTL, slate_abi::nr::IOCTL), fd, TIOCGWINSZ, ws.as_mut_ptr()).ok()?;
    (ws[1] != 0).then_some((ws[0], ws[1]))
}

pub fn foreground(fd: i32) -> Result<i32> {
    let mut pg: i32 = 0;
    crate::syscall!(sys::pick(sys::IOCTL, slate_abi::nr::IOCTL), fd, TIOCGPGRP, &mut pg as *mut i32)?;
    Ok(pg)
}

pub fn set_foreground(fd: i32, pgrp: i32) -> Result<()> {
    crate::syscall!(sys::pick(sys::IOCTL, slate_abi::nr::IOCTL), fd, TIOCSPGRP, &pgrp as *const i32).map(|_| ())
}

/// Make `fd` the calling session leader's controlling terminal.
pub fn set_controlling(fd: i32) -> Result<()> {
    crate::syscall!(sys::pick(sys::IOCTL, slate_abi::nr::IOCTL), fd, TIOCSCTTY, 0).map(|_| ())
}

/// Like [`set_controlling`], taking the terminal from another session if
/// need be (root only).
pub fn steal_controlling(fd: i32) -> Result<()> {
    crate::syscall!(sys::pick(sys::IOCTL, slate_abi::nr::IOCTL), fd, TIOCSCTTY, 1).map(|_| ())
}

/// Set the window size on `fd` (TIOCSWINSZ, `struct winsize`).
pub fn set_size(fd: i32, rows: u16, cols: u16) -> Result<()> {
    let ws: [u16; 4] = [rows, cols, 0, 0];
    crate::syscall!(sys::pick(sys::IOCTL, slate_abi::nr::IOCTL), fd, TIOCSWINSZ, ws.as_ptr()).map(|_| ())
}

/// A new pseudo-terminal (pty(7)): the master's descriptor and the
/// slave's path, unlocked.
pub fn open_pty() -> Result<(i32, alloc::vec::Vec<u8>)> {
    let m = crate::fs::open(b"/dev/ptmx", crate::fs::O_RDWR | crate::fs::O_CLOEXEC | crate::fs::O_NOCTTY, 0)?;
    let unlock: i32 = 0;
    let mut n: u32 = 0;
    let r = crate::syscall!(sys::pick(sys::IOCTL, slate_abi::nr::IOCTL), m, TIOCSPTLCK, &unlock as *const i32)
        .and_then(|_| crate::syscall!(sys::pick(sys::IOCTL, slate_abi::nr::IOCTL), m, TIOCGPTN, &mut n as *mut u32));
    if let Err(e) = r {
        let _ = crate::io::close(m);
        return Err(e);
    }
    Ok((m, alloc::format!("/dev/pts/{n}").into_bytes()))
}
