// SPDX-License-Identifier: MIT OR Apache-2.0

//! dd: copy blocks between files, converting on the way (POSIX dd, with
//! GNU's input and output flags and `status=`). The record counts and the
//! summary follow what GNU's dd prints, and SIGUSR1 asks for them on the
//! way (ADR 0145). The conversions go in the order GNU's dd was seen to
//! apply them: swab; ascii's table and the case; block or unblock to
//! `cbs`-byte records; ebcdic's or ibm's table.

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::signal::{self, Disposition};
use slate_rt::{Errno, eprint, eprintln, fs, io, lossy, time};

use crate::od::format_g;
use crate::util::error;

/// POSIX dd's conversion tables (XCU dd, conv=ascii, ebcdic and ibm),
/// byte for byte as GNU's dd converts each value.
const EBCDIC_TO_ASCII: [u8; 256] = [
    0x00, 0x01, 0x02, 0x03, 0x9c, 0x09, 0x86, 0x7f, 0x97, 0x8d, 0x8e, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
    0x13, 0x9d, 0x85, 0x08, 0x87, 0x18, 0x19, 0x92, 0x8f, 0x1c, 0x1d, 0x1e, 0x1f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x0a,
    0x17, 0x1b, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x05, 0x06, 0x07, 0x90, 0x91, 0x16, 0x93, 0x94, 0x95, 0x96, 0x04, 0x98,
    0x99, 0x9a, 0x9b, 0x14, 0x15, 0x9e, 0x1a, 0x20, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xd5, 0x2e,
    0x3c, 0x28, 0x2b, 0x7c, 0x26, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0x21, 0x24, 0x2a, 0x29, 0x3b,
    0x7e, 0x2d, 0x2f, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xcb, 0x2c, 0x25, 0x5f, 0x3e, 0x3f, 0xba, 0xbb,
    0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0x60, 0x3a, 0x23, 0x40, 0x27, 0x3d, 0x22, 0xc3, 0x61, 0x62, 0x63, 0x64,
    0x65, 0x66, 0x67, 0x68, 0x69, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
    0x71, 0x72, 0x5e, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xe5, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0xd2,
    0xd3, 0xd4, 0x5b, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0x5d,
    0xe6, 0xe7, 0x7b, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0x7d,
    0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0x5c, 0x9f, 0x53, 0x54,
    0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x37, 0x38, 0x39, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
];

const ASCII_TO_EBCDIC: [u8; 256] = [
    0x00, 0x01, 0x02, 0x03, 0x37, 0x2d, 0x2e, 0x2f, 0x16, 0x05, 0x25, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
    0x13, 0x3c, 0x3d, 0x32, 0x26, 0x18, 0x19, 0x3f, 0x27, 0x1c, 0x1d, 0x1e, 0x1f, 0x40, 0x5a, 0x7f, 0x7b, 0x5b, 0x6c,
    0x50, 0x7d, 0x4d, 0x5d, 0x5c, 0x4e, 0x6b, 0x60, 0x4b, 0x61, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0x7a, 0x5e, 0x4c, 0x7e, 0x6e, 0x6f, 0x7c, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xd1, 0xd2,
    0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xad, 0xe0, 0xbd, 0x9a,
    0x6d, 0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
    0x99, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xc0, 0x4f, 0xd0, 0x5f, 0x07, 0x20, 0x21, 0x22, 0x23, 0x24,
    0x15, 0x06, 0x17, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x09, 0x0a, 0x1b, 0x30, 0x31, 0x1a, 0x33, 0x34, 0x35, 0x36, 0x08,
    0x38, 0x39, 0x3a, 0x3b, 0x04, 0x14, 0x3e, 0xe1, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x51, 0x52,
    0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x70, 0x71, 0x72, 0x73,
    0x74, 0x75, 0x76, 0x77, 0x78, 0x80, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x6a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xaa, 0xab, 0xac, 0x4a, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
    0xbc, 0xa1, 0xbe, 0xbf, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xea, 0xeb, 0xec,
    0xed, 0xee, 0xef, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
];

const ASCII_TO_IBM: [u8; 256] = [
    0x00, 0x01, 0x02, 0x03, 0x37, 0x2d, 0x2e, 0x2f, 0x16, 0x05, 0x25, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
    0x13, 0x3c, 0x3d, 0x32, 0x26, 0x18, 0x19, 0x3f, 0x27, 0x1c, 0x1d, 0x1e, 0x1f, 0x40, 0x5a, 0x7f, 0x7b, 0x5b, 0x6c,
    0x50, 0x7d, 0x4d, 0x5d, 0x5c, 0x4e, 0x6b, 0x60, 0x4b, 0x61, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0x7a, 0x5e, 0x4c, 0x7e, 0x6e, 0x6f, 0x7c, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xd1, 0xd2,
    0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xad, 0xe0, 0xbd, 0x5f,
    0x6d, 0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
    0x99, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xc0, 0x4f, 0xd0, 0xa1, 0x07, 0x20, 0x21, 0x22, 0x23, 0x24,
    0x15, 0x06, 0x17, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x09, 0x0a, 0x1b, 0x30, 0x31, 0x1a, 0x33, 0x34, 0x35, 0x36, 0x08,
    0x38, 0x39, 0x3a, 0x3b, 0x04, 0x14, 0x3e, 0xe1, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x51, 0x52,
    0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x70, 0x71, 0x72, 0x73,
    0x74, 0x75, 0x76, 0x77, 0x78, 0x80, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
    0xbc, 0xbd, 0xbe, 0xbf, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xea, 0xeb, 0xec,
    0xed, 0xee, 0xef, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Charset {
    Same,
    Ascii,
    Ebcdic,
    Ibm,
}

#[derive(Default)]
struct Conv {
    charset: Option<Charset>,
    block: bool,
    unblock: bool,
    lcase: bool,
    ucase: bool,
    swab: bool,
    sync: bool,
    noerror: bool,
    notrunc: bool,
    excl: bool,
    nocreat: bool,
    fsync: bool,
    fdatasync: bool,
    sparse: bool,
}

#[derive(Default)]
struct Flags {
    append: bool,
    sync: bool,
    dsync: bool,
    nonblock: bool,
    nofollow: bool,
    fullblock: bool,
    count_bytes: bool,
    skip_bytes: bool,
    seek_bytes: bool,
    direct: bool,
    noatime: bool,
}

/// A number with dd's suffixes (c w b kB K MB M GB G ...), and `x`
/// products (`2x512`).
fn number(s: &[u8]) -> Option<u64> {
    let mut total: u64 = 1;
    for part in s.split(|&c| c == b'x') {
        let p = core::str::from_utf8(part).ok()?;
        let end = p.find(|c: char| !c.is_ascii_digit()).unwrap_or(p.len());
        if end == 0 {
            return None;
        }
        let n: u64 = p[..end].parse().ok()?;
        let mult: u64 = match &p[end..] {
            "" | "c" => 1,
            "w" => 2,
            "b" => 512,
            "kB" => 1000,
            "K" | "k" | "KiB" => 1024,
            "MB" => 1_000_000,
            "M" | "MiB" => 1 << 20,
            "GB" => 1_000_000_000,
            "G" | "GiB" => 1 << 30,
            "TB" => 1_000_000_000_000,
            "T" | "TiB" => 1 << 40,
            _ => return None,
        };
        total = total.checked_mul(n.checked_mul(mult)?)?;
    }
    Some(total)
}

/// `3.1 MB` style: one decimal under 10, rounded to the nearest.
fn human(n: u64, base: f64, units: &[&str]) -> String {
    let mut v = n as f64;
    let mut u = 0;
    while v >= base && u + 1 < units.len() {
        v /= base;
        u += 1;
    }
    if v < 10.0 {
        let r = round1(v);
        if r >= 10.0 { alloc::format!("{r:.0} {}", units[u]) } else { alloc::format!("{r:.1} {}", units[u]) }
    } else {
        alloc::format!("{v:.0} {}", units[u])
    }
}

fn round1(v: f64) -> f64 {
    let t = v * 10.0 + 0.5;
    (t as u64) as f64 / 10.0
}

/// `%g` with six digits, as GNU's dd prints the elapsed time.
fn seconds(t: f64) -> String {
    let e = alloc::format!("{t:.5e}");
    let (m, x) = e.split_once('e').unwrap_or((&e, "0"));
    let m = if m.contains('.') { m.trim_end_matches('0').trim_end_matches('.') } else { m };
    format_g(t, &alloc::format!("{m}e{x}"), 6)
}

struct Stats {
    full_in: u64,
    part_in: u64,
    full_out: u64,
    part_out: u64,
    /// Lines conv=block cut short.
    truncated: u64,
    bytes: u64,
    start: (i64, i64),
}

impl Stats {
    fn elapsed(&self) -> f64 {
        let now = time::now(time::CLOCK_MONOTONIC);
        (now.0 - self.start.0) as f64 + (now.1 - self.start.1) as f64 / 1e9
    }

    fn transfer(&self) -> String {
        let t = self.elapsed();
        let b = self.bytes;
        let size = if b < 1000 {
            alloc::format!("{b} byte{} copied", if b == 1 { "" } else { "s" })
        } else {
            alloc::format!(
                "{b} bytes ({}, {}) copied",
                human(b, 1000.0, &["B", "kB", "MB", "GB", "TB", "PB", "EB"]),
                human(b, 1024.0, &["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"])
            )
        };
        let rate = if t > 0.0 {
            let r = b as f64 / t;
            if r < 1000.0 {
                alloc::format!("{r:.0} B/s")
            } else {
                alloc::format!("{}/s", human(r as u64, 1000.0, &["B", "kB", "MB", "GB", "TB", "PB", "EB"]))
            }
        } else {
            String::from("Infinity B/s")
        };
        alloc::format!("{size}, {} s, {rate}", seconds(t))
    }

    fn report(&self, status: &[u8]) {
        if status == b"none" {
            return;
        }
        eprintln!("{}+{} records in", self.full_in, self.part_in);
        eprintln!("{}+{} records out", self.full_out, self.part_out);
        if self.truncated > 0 {
            eprintln!("{} truncated record{}", self.truncated, if self.truncated == 1 { "" } else { "s" });
        }
        if status != b"noxfer" {
            eprintln!("{}", self.transfer());
        }
    }
}

fn parse_list<T>(v: &[u8], what: &str, out: &mut T, set: fn(&mut T, &[u8]) -> bool) -> Result<(), ()> {
    for f in v.split(|&c| c == b',') {
        if !set(out, f) {
            error(format_args!("invalid {what}: '{}'", lossy(f)));
            return Err(());
        }
    }
    Ok(())
}

fn set_conv(c: &mut Conv, f: &[u8]) -> bool {
    match f {
        b"ascii" | b"ebcdic" | b"ibm" => {
            let set = match f {
                b"ascii" => Charset::Ascii,
                b"ebcdic" => Charset::Ebcdic,
                _ => Charset::Ibm,
            };
            // Two of them is an error, reported once all are read.
            c.charset = Some(if c.charset.is_some_and(|x| x != set) { Charset::Same } else { set });
        }
        b"block" => c.block = true,
        b"unblock" => c.unblock = true,
        b"lcase" => c.lcase = true,
        b"ucase" => c.ucase = true,
        b"swab" => c.swab = true,
        b"sync" => c.sync = true,
        b"noerror" => c.noerror = true,
        b"notrunc" => c.notrunc = true,
        b"excl" => c.excl = true,
        b"nocreat" => c.nocreat = true,
        b"fsync" => c.fsync = true,
        b"fdatasync" => c.fdatasync = true,
        b"sparse" => c.sparse = true,
        _ => return false,
    }
    true
}

fn set_flag(fl: &mut Flags, f: &[u8]) -> bool {
    match f {
        b"append" => fl.append = true,
        b"sync" => fl.sync = true,
        b"dsync" => fl.dsync = true,
        b"nonblock" => fl.nonblock = true,
        b"nofollow" => fl.nofollow = true,
        b"fullblock" => fl.fullblock = true,
        b"count_bytes" => fl.count_bytes = true,
        b"skip_bytes" => fl.skip_bytes = true,
        b"seek_bytes" => fl.seek_bytes = true,
        b"direct" => fl.direct = true,
        b"noatime" => fl.noatime = true,
        // Accepted by GNU and meaningless here: no terminal is taken over
        // and nothing is cached on Slate's behalf.
        b"noctty" | b"nocache" | b"binary" | b"text" => {}
        _ => return false,
    }
    true
}

fn open_flags(fl: &Flags) -> u32 {
    let mut f = fs::O_CLOEXEC;
    if fl.append {
        f |= fs::O_APPEND;
    }
    if fl.sync {
        f |= fs::O_SYNC;
    }
    if fl.dsync {
        f |= fs::O_DSYNC;
    }
    if fl.nonblock {
        f |= fs::O_NONBLOCK;
    }
    if fl.nofollow {
        f |= fs::O_NOFOLLOW;
    }
    if fl.direct {
        f |= fs::O_DIRECT;
    }
    if fl.noatime {
        f |= fs::O_NOATIME;
    }
    f
}

/// conv=block and unblock (POSIX dd): newline-ended lines become records
/// of `cbs` bytes, padded with spaces or cut short (counted); or records
/// of `cbs` bytes become lines, their trailing spaces dropped. Records
/// run across input blocks.
enum Shape {
    Same,
    Block { cbs: usize, col: usize, cutting: bool },
    Unblock { cbs: usize, record: Vec<u8> },
}

impl Shape {
    fn feed(&mut self, data: &[u8], out: &mut Vec<u8>, truncated: &mut u64) {
        match self {
            Shape::Same => out.extend_from_slice(data),
            Shape::Block { cbs, col, cutting } => {
                for &b in data {
                    if b == b'\n' {
                        out.resize(out.len() + (*cbs - *col), b' ');
                        (*col, *cutting) = (0, false);
                    } else if *col < *cbs {
                        out.push(b);
                        *col += 1;
                    } else if !*cutting {
                        *truncated += 1;
                        *cutting = true;
                    }
                }
            }
            Shape::Unblock { cbs, record } => {
                for &b in data {
                    record.push(b);
                    if record.len() == *cbs {
                        Shape::line(record, out);
                    }
                }
            }
        }
    }

    /// The end of input: a last line, or a last short record.
    fn finish(&mut self, out: &mut Vec<u8>) {
        match self {
            Shape::Same => {}
            Shape::Block { cbs, col, .. } => {
                if *col > 0 {
                    out.resize(out.len() + (*cbs - *col), b' ');
                    *col = 0;
                }
            }
            Shape::Unblock { record, .. } => {
                if !record.is_empty() {
                    Shape::line(record, out);
                }
            }
        }
    }

    fn line(record: &mut Vec<u8>, out: &mut Vec<u8>) {
        let end = record.iter().rposition(|&c| c != b' ').map_or(0, |i| i + 1);
        out.extend_from_slice(&record[..end]);
        out.push(b'\n');
        record.clear();
    }
}

/// Read up to `buf.len()` bytes; with `fullblock`, keep reading until the
/// block is full or input ends. A signal (SIGUSR1) interrupting a read
/// gets `on_signal` called before it goes on.
/// A buffer that starts on a page, as O_DIRECT's transfers need (open(2);
/// ADR 0162).
struct Aligned {
    v: Vec<u8>,
    at: usize,
}

impl Aligned {
    fn new(len: usize) -> Aligned {
        let v = alloc::vec![0u8; len + 4096];
        let at = v.as_ptr().align_offset(4096).min(4096);
        Aligned { v, at }
    }

    fn get(&mut self, len: usize) -> &mut [u8] {
        &mut self.v[self.at..self.at + len]
    }
}

/// Take O_DIRECT off `fd`: a block shorter than the output's goes out
/// without it, its length being no multiple of the device's (as GNU's dd
/// was seen to do).
fn undirect(fd: i32) {
    use slate_rt::process::{F_GETFL, F_SETFL, fcntl};
    if let Ok(fl) = fcntl(fd, F_GETFL, 0) {
        let _ = fcntl(fd, F_SETFL, fl & !(fs::O_DIRECT as usize));
    }
}

fn read_block(fd: i32, buf: &mut [u8], fullblock: bool, on_signal: &mut dyn FnMut()) -> Result<usize, Errno> {
    let mut got = 0;
    loop {
        match io::read_interruptible(fd, &mut buf[got..]) {
            Ok(0) => return Ok(got),
            Ok(n) => {
                got += n;
                if !fullblock || got == buf.len() {
                    return Ok(got);
                }
            }
            Err(Errno::EINTR) => on_signal(),
            Err(e) => return Err(e),
        }
    }
}

/// Skip `n` bytes of input: seek if possible, otherwise read them.
fn skip_input(fd: i32, n: u64, name: &[u8]) -> Result<(), ()> {
    if n == 0 {
        return Ok(());
    }
    if io::lseek(fd, n as i64, io::SEEK_CUR).is_ok() {
        return Ok(());
    }
    let mut left = n;
    let mut buf = alloc::vec![0u8; 64 * 1024];
    while left > 0 {
        let want = (left as usize).min(buf.len());
        match io::read(fd, &mut buf[..want]) {
            Ok(0) => {
                error(format_args!("'{}': cannot skip to specified offset", lossy(name)));
                return Ok(());
            }
            Ok(k) => left -= k as u64,
            Err(e) => {
                error(format_args!("'{}': cannot skip: {e}", lossy(name)));
                return Err(());
            }
        }
    }
    Ok(())
}

pub fn main(args: &[Vec<u8>]) -> i32 {
    let (mut input, mut output) = (None::<Vec<u8>>, None::<Vec<u8>>);
    let (mut ibs, mut obs) = (512u64, 512u64);
    let (mut count, mut skip, mut seek) = (None::<u64>, 0u64, 0u64);
    let mut conv = Conv::default();
    let (mut iflag, mut oflag) = (Flags::default(), Flags::default());
    let mut status: Vec<u8> = Vec::new();
    let mut cbs: Option<u64> = None;
    for a in &args[1..] {
        let Some(eq) = a.iter().position(|&c| c == b'=') else {
            error(format_args!("unrecognized operand '{}'", lossy(a)));
            eprintln!("Try '{} --help' for more information.", slate_rt::prog_name());
            return 1;
        };
        let (k, v) = (&a[..eq], &a[eq + 1..]);
        let num = |v: &[u8], zero_ok: bool| -> Result<u64, i32> {
            match number(v) {
                Some(n) if zero_ok || n > 0 => Ok(n),
                _ => {
                    error(format_args!("invalid number: '{}'", lossy(v)));
                    Err(1)
                }
            }
        };
        let r = match k {
            b"if" => {
                input = Some(v.to_vec());
                Ok(())
            }
            b"of" => {
                output = Some(v.to_vec());
                Ok(())
            }
            b"bs" => num(v, false).map(|n| {
                ibs = n;
                obs = n;
            }),
            b"ibs" => num(v, false).map(|n| ibs = n),
            b"obs" => num(v, false).map(|n| obs = n),
            b"count" => num(v, true).map(|n| count = Some(n)),
            b"skip" | b"iseek" => num(v, true).map(|n| skip = n),
            b"seek" | b"oseek" => num(v, true).map(|n| seek = n),
            b"conv" => parse_list(v, "conversion", &mut conv, set_conv).map_err(|()| 1),
            b"iflag" => parse_list(v, "input flag", &mut iflag, set_flag).map_err(|()| 1),
            b"oflag" => parse_list(v, "output flag", &mut oflag, set_flag).map_err(|()| 1),
            b"status" => match v {
                b"none" | b"noxfer" | b"progress" => {
                    status = v.to_vec();
                    Ok(())
                }
                _ => {
                    error(format_args!("invalid status level: '{}'", lossy(v)));
                    eprintln!("Try '{} --help' for more information.", slate_rt::prog_name());
                    Err(1)
                }
            },
            b"cbs" => num(v, false).map(|n| cbs = Some(n)),
            _ => {
                error(format_args!("unrecognized operand '{}'", lossy(a)));
                eprintln!("Try '{} --help' for more information.", slate_rt::prog_name());
                Err(1)
            }
        };
        if let Err(s) = r {
            return s;
        }
    }
    if conv.lcase && conv.ucase {
        error("cannot combine lcase and ucase");
        return 1;
    }
    if conv.excl && conv.nocreat {
        error("cannot combine excl and nocreat");
        return 1;
    }
    if conv.charset == Some(Charset::Same) {
        error("cannot combine any two of {ascii,ebcdic,ibm}");
        return 1;
    }
    if conv.block && conv.unblock {
        error("cannot combine block and unblock");
        return 1;
    }
    // The tables: ascii's before the records are shaped, the case with
    // it; ebcdic's and ibm's after, the case before them.
    let case = |b: u8| {
        if conv.lcase {
            b.to_ascii_lowercase()
        } else if conv.ucase {
            b.to_ascii_uppercase()
        } else {
            b
        }
    };
    let (mut before, mut after) = ([0u8; 256], [0u8; 256]);
    for i in 0..256 {
        let b = i as u8;
        (before[i], after[i]) = match conv.charset {
            Some(Charset::Ascii) => (case(EBCDIC_TO_ASCII[i]), b),
            Some(Charset::Ebcdic) => (b, ASCII_TO_EBCDIC[usize::from(case(b))]),
            Some(Charset::Ibm) => (b, ASCII_TO_IBM[usize::from(case(b))]),
            _ => (case(b), b),
        };
    }
    let translate_after = matches!(conv.charset, Some(Charset::Ebcdic | Charset::Ibm));
    // With cbs: ascii unblocks, ebcdic and ibm block; without, block and
    // unblock do nothing (as GNU's dd).
    let mut shape = match cbs.map(|c| c as usize) {
        Some(c) if conv.unblock || (!conv.block && conv.charset == Some(Charset::Ascii)) => {
            Shape::Unblock { cbs: c, record: Vec::new() }
        }
        Some(c) if conv.block || translate_after => Shape::Block { cbs: c, col: 0, cutting: false },
        _ => Shape::Same,
    };
    // SIGUSR1 prints the statistics so far (and copying goes on).
    let _ = signal::set(signal::SIGUSR1, Disposition::CatchInterrupt);
    let in_name = input.clone().unwrap_or_else(|| b"standard input".to_vec());
    let out_name = output.clone().unwrap_or_else(|| b"standard output".to_vec());
    let ifd = match &input {
        Some(p) => match fs::open(p, fs::O_RDONLY | open_flags(&iflag), 0) {
            Ok(fd) => fd,
            Err(e) => {
                error(format_args!("failed to open '{}': {e}", lossy(p)));
                return 1;
            }
        },
        None => io::STDIN,
    };
    let ofd = match &output {
        Some(p) => {
            let mut f = fs::O_WRONLY | open_flags(&oflag);
            if !conv.nocreat {
                f |= fs::O_CREAT;
            }
            if conv.excl {
                f |= fs::O_EXCL;
            }
            // Truncate only when nothing before the seek point is kept.
            if !conv.notrunc && !oflag.append && seek == 0 {
                f |= fs::O_TRUNC;
            }
            match fs::open(p, f, 0o666) {
                Ok(fd) => fd,
                Err(e) => {
                    error(format_args!("failed to open '{}': {e}", lossy(p)));
                    return 1;
                }
            }
        }
        None => io::STDOUT,
    };
    let skip_bytes = if iflag.skip_bytes { skip } else { skip * ibs };
    let seek_bytes = if oflag.seek_bytes { seek } else { seek * obs };
    if skip_input(ifd, skip_bytes, &in_name).is_err() {
        return 1;
    }
    if seek_bytes > 0 {
        if io::lseek(ofd, seek_bytes as i64, io::SEEK_SET).is_err() {
            // A pipe: write zeros instead.
            let zeros = alloc::vec![0u8; 64 * 1024];
            let mut left = seek_bytes;
            while left > 0 {
                let n = (left as usize).min(zeros.len());
                if io::write_all(ofd, &zeros[..n]).is_err() {
                    break;
                }
                left -= n as u64;
            }
        } else if !conv.notrunc && !oflag.append {
            let _ = fs::ftruncate(ofd, seek_bytes);
        }
    }
    let mut st = Stats {
        full_in: 0,
        part_in: 0,
        full_out: 0,
        part_out: 0,
        truncated: 0,
        bytes: 0,
        start: time::now(time::CLOCK_MONOTONIC),
    };
    let mut shaped: Vec<u8> = Vec::new();
    // Page-aligned buffers, for O_DIRECT.
    let mut inbuf = Aligned::new(ibs as usize);
    let buf = inbuf.get(ibs as usize);
    let mut outbuf = oflag.direct.then(|| Aligned::new(obs as usize));
    let mut direct_out = oflag.direct;
    let mut pending: Vec<u8> = Vec::new();
    let mut code = 0;
    let mut write_failed = false;
    let mut in_left = count.map(|c| if iflag.count_bytes { c } else { c * ibs });
    let mut last_progress = 0.0;
    let mut write_out = |data: &[u8], st: &mut Stats, last: bool| -> Result<(), Errno> {
        pending.extend_from_slice(data);
        let mut off = 0;
        while pending.len() - off >= obs as usize || (last && off < pending.len()) {
            let n = (pending.len() - off).min(obs as usize);
            let chunk = &pending[off..off + n];
            if conv.sparse && chunk.iter().all(|&b| b == 0) && io::lseek(ofd, n as i64, io::SEEK_CUR).is_ok() {
                // A hole instead of zeros.
            } else if let Some(a) = outbuf.as_mut() {
                if n != obs as usize && direct_out {
                    undirect(ofd);
                    direct_out = false;
                }
                let out = a.get(n);
                out.copy_from_slice(chunk);
                io::write_all(ofd, out)?;
            } else {
                io::write_all(ofd, chunk)?;
            }
            st.bytes += n as u64;
            if n == obs as usize {
                st.full_out += 1;
            } else {
                st.part_out += 1;
            }
            off += n;
        }
        pending.drain(..off);
        Ok(())
    };
    loop {
        let want = match in_left {
            Some(0) => break,
            Some(l) => (l.min(ibs)) as usize,
            None => ibs as usize,
        };
        if signal::take() & (1 << signal::SIGUSR1) != 0 {
            st.report(&status);
        }
        let r = read_block(ifd, &mut buf[..want], iflag.fullblock, &mut || {
            if signal::take() & (1 << signal::SIGUSR1) != 0 {
                st.report(&status);
            }
        });
        let n = match r {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                error(format_args!("error reading '{}': {e}", lossy(&in_name)));
                code = 1;
                if conv.noerror {
                    st.part_in += 1;
                    if conv.sync {
                        buf[..want].fill(0);
                        if let Err(e) = write_out(&buf[..want], &mut st, false) {
                            error(format_args!("error writing '{}': {e}", lossy(&out_name)));
                            write_failed = true;
                            break;
                        }
                    }
                    continue;
                }
                break;
            }
        };
        if let Some(l) = in_left.as_mut() {
            *l -= if iflag.count_bytes { n as u64 } else { (*l).min(ibs) };
        }
        if n == ibs as usize {
            st.full_in += 1;
        } else {
            st.part_in += 1;
        }
        let mut len = n;
        if conv.sync && n < ibs as usize {
            // Spaces when records are shaped (POSIX dd, conv=sync).
            buf[n..ibs as usize].fill(if matches!(shape, Shape::Same) { 0 } else { b' ' });
            len = ibs as usize;
        }
        let block = &mut buf[..len];
        if conv.swab {
            for pair in block.as_chunks_mut::<2>().0 {
                pair.swap(0, 1);
            }
        }
        for b in block.iter_mut() {
            *b = before[usize::from(*b)];
        }
        shaped.clear();
        shape.feed(block, &mut shaped, &mut st.truncated);
        if translate_after {
            for b in shaped.iter_mut() {
                *b = after[usize::from(*b)];
            }
        }
        if let Err(e) = write_out(&shaped, &mut st, false) {
            error(format_args!("error writing '{}': {e}", lossy(&out_name)));
            code = 1;
            write_failed = true;
            break;
        }
        if status == b"progress" {
            let t = st.elapsed();
            if t - last_progress >= 1.0 {
                last_progress = t;
                eprint!("\r{}", st.transfer());
            }
        }
    }
    shaped.clear();
    shape.finish(&mut shaped);
    if translate_after {
        for b in shaped.iter_mut() {
            *b = after[usize::from(*b)];
        }
    }
    // After a write error the rest stays unwritten (and unsaid).
    if !write_failed && let Err(e) = write_out(&shaped, &mut st, true) {
        error(format_args!("error writing '{}': {e}", lossy(&out_name)));
        code = 1;
    }
    if conv.sparse {
        // A trailing hole still needs the file's size.
        if let Ok(pos) = io::lseek(ofd, 0, io::SEEK_CUR) {
            let _ = fs::ftruncate(ofd, pos);
        }
    }
    if (conv.fsync || conv.fdatasync)
        && let Err(e) = fs::fsync(ofd)
    {
        error(format_args!("fsync failed for '{}': {e}", lossy(&out_name)));
        code = 1;
    }
    if status == b"progress" && last_progress > 0.0 {
        eprint!("\n");
    }
    if input.is_some() {
        let _ = io::close(ifd);
    }
    if output.is_some() {
        let _ = io::close(ofd);
    }
    st.report(&status);
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        assert_eq!(number(b"512"), Some(512));
        assert_eq!(number(b"1K"), Some(1024));
        assert_eq!(number(b"1kB"), Some(1000));
        assert_eq!(number(b"2x512"), Some(1024));
        assert_eq!(number(b"1x2"), Some(2));
        assert_eq!(number(b"3b"), Some(1536));
        assert_eq!(number(b"x"), None);
    }

    #[test]
    fn summaries() {
        assert_eq!(human(3_145_728, 1000.0, &["B", "kB", "MB"]), "3.1 MB");
        assert_eq!(human(3_145_728, 1024.0, &["B", "KiB", "MiB"]), "3.0 MiB");
        assert_eq!(human(3000, 1024.0, &["B", "KiB", "MiB"]), "2.9 KiB");
        assert_eq!(human(2_000_000_000, 1024.0, &["B", "KiB", "MiB", "GiB"]), "1.9 GiB");
        assert_eq!(seconds(0.000583056), "0.000583056");
        assert_eq!(seconds(3.8234e-5), "3.8234e-05");
        assert_eq!(seconds(0.0335552), "0.0335552");
    }
}
