// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(dead_code)] // ABI reference table: not every entry is used yet.

//! Terminal ioctl numbers and structures. Source: musl `bits/ioctl.h`
//! (ADR 0009); semantics per ioctl_tty(2).

pub const TCGETS: u32 = 0x5401;
pub const TCSETS: u32 = 0x5402;
pub const TCSETSW: u32 = 0x5403;
pub const TCSETSF: u32 = 0x5404;
pub const TIOCSCTTY: u32 = 0x540E;
pub const TIOCGPGRP: u32 = 0x540F;
pub const TIOCSPGRP: u32 = 0x5410;
pub const TIOCGWINSZ: u32 = 0x5413;
pub const TIOCSWINSZ: u32 = 0x5414;
pub const FIONREAD: u32 = 0x541B;
pub const FIONBIO: u32 = 0x5421;
pub const TIOCNOTTY: u32 = 0x5422;
pub const FIONCLEX: u32 = 0x5450;
pub const FIOCLEX: u32 = 0x5451;
pub const TIOCGSID: u32 = 0x5429;
pub const TIOCGPTN: u32 = 0x8004_5430;
pub const TIOCSPTLCK: u32 = 0x4004_5431;
pub const TIOCGPTLCK: u32 = 0x8004_5439;

/// `struct winsize` (ioctl_tty(2)).
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct Winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}
