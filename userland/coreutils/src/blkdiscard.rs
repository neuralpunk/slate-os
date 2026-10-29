// SPDX-License-Identifier: MIT OR Apache-2.0

//! `blkdiscard [-o OFFSET] [-l LENGTH] [-v] DEVICE` (util-linux's
//! interface): tell a block device that bytes hold nothing any more (TRIM,
//! ADR 0039), through the native call `discard`. OFFSET defaults to 0,
//! LENGTH to the rest of the device; both take K, M, G and T (powers of
//! 1024) and must be whole 512-byte sectors.

use alloc::vec::Vec;

use slate_rt::{fs, io, lossy, process};

use crate::util::{Opt, Parser, bad_option, error, error_path};

/// BLKGETSIZE64 (musl `sys/mount.h`, ADR 0009).
const BLKGETSIZE64: u32 = 0x8008_1272;

/// `123`, `64K`, `1M`...
pub fn parse_size(s: &[u8]) -> Option<u64> {
    let (num, mul) = match s.last()? {
        b'K' | b'k' => (&s[..s.len() - 1], 1 << 10),
        b'M' | b'm' => (&s[..s.len() - 1], 1 << 20),
        b'G' | b'g' => (&s[..s.len() - 1], 1 << 30),
        b'T' | b't' => (&s[..s.len() - 1], 1 << 40),
        _ => (s, 1),
    };
    core::str::from_utf8(num).ok()?.parse::<u64>().ok()?.checked_mul(mul)
}

pub fn blkdiscard(args: &[Vec<u8>]) -> i32 {
    let (mut offset, mut length, mut verbose) = (0u64, None, false);
    let mut device = None;
    let mut p = Parser::new(args, b"ol");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(c @ (b'o' | b'l')) => {
                let Some(v) = p.value() else { return bad_option(&o) };
                let Some(n) = parse_size(&v) else {
                    error(format_args!("invalid size: '{}'", lossy(&v)));
                    return 1;
                };
                if c == b'o' { offset = n } else { length = Some(n) }
            }
            Opt::Short(b'v') => verbose = true,
            Opt::Operand(d) if device.is_none() => device = Some(d),
            o => return bad_option(&o),
        }
    }
    let Some(dev) = device else {
        error("no device given");
        return 1;
    };
    let fd = match fs::open(&dev, fs::O_WRONLY | fs::O_CLOEXEC, 0) {
        Ok(fd) => fd,
        Err(e) => {
            error_path(&dev, e);
            return 1;
        }
    };
    let mut size = 0u64;
    if let Err(e) = io::ioctl(fd, BLKGETSIZE64, &mut size as *mut u64 as usize) {
        error_path(&dev, e);
        return 1;
    }
    let length = length.unwrap_or_else(|| size.saturating_sub(offset));
    let r = process::discard(fd, offset, length);
    let _ = io::close(fd);
    match r {
        Ok(()) => {
            if verbose {
                slate_rt::println!("{}: Discarded {length} bytes from the offset {offset}", lossy(&dev));
            }
            0
        }
        Err(e) => {
            error(format_args!("{}: BLKDISCARD ioctl failed: {e}", lossy(&dev)));
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_size(b"512"), Some(512));
        assert_eq!(parse_size(b"64K"), Some(65536));
        assert_eq!(parse_size(b"1M"), Some(1 << 20));
        assert_eq!(parse_size(b"x"), None);
    }
}
