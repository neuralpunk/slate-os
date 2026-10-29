// SPDX-License-Identifier: MIT OR Apache-2.0

//! `fstrim [-v] [-o OFFSET] [-l LENGTH] [-m MINIMUM] MOUNTPOINT` and
//! `fstrim -a [-v]` (util-linux's interface): discard the free space of a
//! mounted file system (FITRIM), so the device can reuse it (ADR 0042).
//! `-a` trims every mounted ext4 and SlateFS file system whose device
//! takes discards. Sizes take K, M, G and T (powers of 1024).
//!
//! `fstrim --every DAYS [-v] [--once]` is Slate's own (ADR 0122): it does
//! what `-a` does whenever DAYS have passed since the last time (kept in
//! [`STAMP`]), checking every hour, for the `fstrim` service; `--once`
//! checks once, at once, and returns.

use alloc::vec::Vec;

use slate_rt::{Errno, fs, io, lossy, println};

use crate::blkdiscard::parse_size;
use crate::util::{Opt, Parser, bad_option, error, error_path};

/// FITRIM, `_IOWR('X', 121, struct fstrim_range)`. Observed on the host
/// (`strace -X raw fstrim`): request 0xc0185879, argument
/// `{start, len, minlen}` (three u64); `len` comes back as the bytes
/// trimmed.
const FITRIM: u32 = 0xC018_5879;

/// When `--every` last trimmed: seconds since the epoch, as text.
pub const STAMP: &[u8] = b"/var/lib/slate/fstrim";
/// How long the service waits after starting before its first check
/// (not during boot), and between checks.
const FIRST_CHECK_SECS: u64 = 600;
const CHECK_SECS: u64 = 3600;

/// Whether a periodic trim is due at `now` (seconds) after one at `last`
/// (none yet: due); a clock that went back makes it due too.
pub fn due(now: i64, last: Option<i64>, days: u64) -> bool {
    last.is_none_or(|l| now < l || (now - l) as u64 >= days.saturating_mul(86_400))
}

/// `1.5 GiB`-style sizes for -v.
fn human(n: u64) -> alloc::string::String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { alloc::format!("{n} B") } else { alloc::format!("{v:.1} {}", UNITS[u]) }
}

/// Trim `path`; the bytes trimmed, or the error number.
fn trim(path: &[u8], range: [u64; 3]) -> Result<u64, Errno> {
    let fd = fs::open(path, fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC, 0)?;
    let mut r = range;
    let res = io::ioctl(fd, FITRIM, r.as_mut_ptr() as usize);
    let _ = io::close(fd);
    res.map(|_| r[1])
}

/// `-a`: every mounted file system that can be trimmed.
fn trim_all(range: [u64; 3], verbose: bool) -> i32 {
    let mounts = fs::read_file(b"/proc/mounts").unwrap_or_default();
    let mut status = 0;
    for line in mounts.split(|&c| c == b'\n') {
        let f: Vec<&[u8]> = line.split(|&c| c == b' ').collect();
        if f.len() < 3 || !matches!(f[2], b"ext4" | b"slatefs") {
            continue;
        }
        match trim(f[1], range) {
            Ok(n) if verbose => println!("{}: {} ({n} bytes) trimmed on {}", lossy(f[1]), human(n), lossy(f[0])),
            Ok(_) => {}
            Err(e) if e == Errno::ENOTTY || e == Errno::EOPNOTSUPP => {}
            Err(e) => {
                error_path(f[1], e);
                status = 1;
            }
        }
    }
    status
}

/// `--every DAYS`: trim when due, record it, and (unless `once`) wait for
/// the next check, forever.
fn every(days: u64, verbose: bool, once: bool) -> i32 {
    if !once {
        slate_rt::time::sleep_ns(FIRST_CHECK_SECS * 1_000_000_000);
    }
    loop {
        let now = slate_rt::time::now(slate_rt::time::CLOCK_REALTIME).0;
        let last = fs::read_file(STAMP).ok().and_then(|t| lossy(&t).trim().parse::<i64>().ok());
        let mut status = 0;
        if due(now, last, days) {
            status = trim_all([0, u64::MAX, 0], verbose);
            let _ = fs::mkdir(b"/var/lib", 0o755);
            let _ = fs::mkdir(b"/var/lib/slate", 0o755);
            if let Err(e) = fs::write_file(STAMP, alloc::format!("{now}\n").as_bytes(), 0o644) {
                error_path(STAMP, e);
            }
        } else if verbose {
            println!("fstrim: not due yet");
        }
        if once {
            return status;
        }
        slate_rt::time::sleep_ns(CHECK_SECS * 1_000_000_000);
    }
}

pub fn fstrim(args: &[Vec<u8>]) -> i32 {
    let (mut range, mut verbose, mut all) = ([0u64, u64::MAX, 0u64], false, false);
    let (mut period, mut once) = (None, false);
    let mut target = None;
    let mut p = Parser::new(args, b"olm");
    while let Some(o) = p.next() {
        match o {
            Opt::Long(l) if l == "every" => {
                match p.value().and_then(|v| lossy(&v).parse::<u64>().ok()).filter(|d| *d > 0) {
                    Some(d) => period = Some(d),
                    None => {
                        error("--every needs a number of days");
                        return 1;
                    }
                }
            }
            Opt::Long(l) if l == "once" => once = true,
            Opt::Short(c @ (b'o' | b'l' | b'm')) => {
                let Some(v) = p.value() else { return bad_option(&o) };
                let Some(n) = parse_size(&v) else {
                    error(format_args!("invalid size: '{}'", lossy(&v)));
                    return 1;
                };
                range[usize::from(c == b'l') + 2 * usize::from(c == b'm')] = n;
            }
            Opt::Short(b'v') => verbose = true,
            Opt::Short(b'a') => all = true,
            Opt::Operand(d) if target.is_none() && !all => target = Some(d),
            o => return bad_option(&o),
        }
    }
    if let Some(days) = period {
        return every(days, verbose, once);
    }
    if all {
        return trim_all(range, verbose);
    }
    let Some(path) = target else {
        error("no mountpoint specified");
        return 1;
    };
    match trim(&path, range) {
        Ok(n) => {
            if verbose {
                println!("{}: {} ({n} bytes) trimmed", lossy(&path), human(n));
            }
            0
        }
        Err(e) if e == Errno::ENOTTY || e == Errno::EOPNOTSUPP => {
            error(format_args!("{}: the discard operation is not supported", lossy(&path)));
            1
        }
        Err(e) => {
            error_path(&path, e);
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periodic_trims_due() {
        let week = 7 * 86_400;
        assert!(due(1000, None, 7));
        assert!(!due(1000 + week - 1, Some(1000), 7));
        assert!(due(1000 + week, Some(1000), 7));
        // A clock set back: trim, and start counting again.
        assert!(due(500, Some(1000), 7));
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human(512), "512 B");
        assert_eq!(human(1536), "1.5 KiB");
        assert_eq!(human(3 << 30), "3.0 GiB");
    }
}
