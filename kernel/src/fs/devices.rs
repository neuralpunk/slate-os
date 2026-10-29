// SPDX-License-Identifier: MIT OR Apache-2.0

//! Character devices, by Linux device number (devices.txt numbering, as
//! observed in `ls -l /dev` on Linux: mem devices are major 1, ttys 4/5).

use alloc::sync::Arc;

use super::File;
use super::vfs::{Result, major, minor};
use crate::abi::linux::errno::{ENOSPC, ENXIO};

pub const MEM_MAJOR: u32 = 1;
pub const NULL_MINOR: u32 = 3;
pub const ZERO_MINOR: u32 = 5;
pub const FULL_MINOR: u32 = 7;
pub const RANDOM_MINOR: u32 = 8;
pub const URANDOM_MINOR: u32 = 9;
pub const TTY_MAJOR: u32 = 4;
pub const TTYS0_MINOR: u32 = 64;
pub const TTYAUX_MAJOR: u32 = 5;
pub const TTY_MINOR: u32 = 0;
pub const CONSOLE_MINOR: u32 = 1;
/// /dev/net/tun (devices.txt: misc major 10, minor 200).
pub const MISC_MAJOR: u32 = 10;
pub const TUN_MINOR: u32 = 200;

/// Open the device `rdev`.
pub fn open(rdev: u64, flags: u32) -> Result<Arc<dyn File>> {
    use super::tty;
    Ok(match (major(rdev), minor(rdev)) {
        (MEM_MAJOR, NULL_MINOR) => Arc::new(Null),
        (MEM_MAJOR, ZERO_MINOR) => Arc::new(Zero),
        (MEM_MAJOR, FULL_MINOR) => Arc::new(Full),
        (MEM_MAJOR, RANDOM_MINOR | URANDOM_MINOR) => Arc::new(Random),
        // /dev/tty is the caller's controlling terminal (tty(4)).
        (TTYAUX_MAJOR, TTY_MINOR) => {
            let ctty = crate::proc::current().and_then(|p| p.ctty()).ok_or(ENXIO)?;
            tty::open_tty(ctty, flags | super::O_NOCTTY)
        }
        (TTYAUX_MAJOR, CONSOLE_MINOR) | (TTY_MAJOR, TTYS0_MINOR) => tty::open_tty(tty::console().clone(), flags),
        (tty::PTMX_MAJOR, tty::PTMX_MINOR) => tty::open_master(flags)?,
        (tty::PTS_MAJOR, n) => tty::open_slave(n, flags)?,
        (MISC_MAJOR, TUN_MINOR) => crate::net::tun::open(flags)?,
        // Bluetooth controllers, /dev/hci0... (ADR 0113).
        (MISC_MAJOR, n) if n >= crate::drivers::usb::btusb::HCI_MINOR_BASE => {
            crate::drivers::usb::btusb::open(n, flags)?
        }
        (crate::drivers::drm::DRM_MAJOR, n) => crate::drivers::drm::open(n, flags)?,
        (crate::drivers::input::INPUT_MAJOR, n) => crate::drivers::input::open(n, flags)?,
        _ => return Err(ENXIO),
    })
}

/// /dev/null: reads end immediately, writes vanish.
struct Null;
impl File for Null {
    fn read(&self, _buf: &mut [u8]) -> Result<usize> {
        Ok(0)
    }
    fn write(&self, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }
    fn seek(&self, _o: i64, _w: u32) -> Result<u64> {
        Ok(0)
    }
}

/// /dev/zero: an endless supply of zeros.
struct Zero;
impl File for Zero {
    /// A read fills the buffer, as on Linux.
    fn fills_reads(&self) -> bool {
        true
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        buf.fill(0);
        Ok(buf.len())
    }
    fn write(&self, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }
    fn seek(&self, _o: i64, _w: u32) -> Result<u64> {
        Ok(0)
    }
}

/// /dev/full: reads zeros, writes fail with ENOSPC.
struct Full;
impl File for Full {
    /// A read fills the buffer, as on Linux.
    fn fills_reads(&self) -> bool {
        true
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        buf.fill(0);
        Ok(buf.len())
    }
    fn write(&self, _buf: &[u8]) -> Result<usize> {
        Err(ENOSPC)
    }
}

/// /dev/random and /dev/urandom: the kernel CSPRNG (random(4)).
struct Random;
impl File for Random {
    /// A read fills the buffer, up to 32 MiB (random(4): "Since Linux
    /// 3.16, a read(2) from /dev/urandom will return at most 32 MB").
    fn fills_reads(&self) -> bool {
        true
    }
    fn read_limit(&self) -> u64 {
        32 << 20
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        crate::random::fill(buf);
        Ok(buf.len())
    }
    fn write(&self, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }
}
