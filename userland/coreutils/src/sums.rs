// SPDX-License-Identifier: MIT OR Apache-2.0

//! The checksum programs (ADR 0148): md5sum, sha1sum, the sha2 family
//! and b2sum (`HASH  FILE`, `--tag` for `NAME (FILE) = HASH`, `-c`);
//! cksum, POSIX's CRC by default and with `-a` any of sysv, bsd, crc,
//! crc32b, md5, sha1, sha224, sha256, sha384, sha512, sha2 and sha3 (with
//! `-l`), blake2b and sm3 (tagged lines by default, `--untagged`,
//! `--base64`, `--raw`, `-l`, `-c`); and sum's BSD (`-r`, the default) and System V (`-s`)
//! checksums. Hashes come from libs/hash, files are read a block at a
//! time, and the output follows what GNU's programs print.

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{Errno, fs, io, lossy, println};

use crate::util::{Opt, Parser, bad_option, error, error_path, lines, read_input};

pub use slate_hash::{hex, md5, sha1, sha224, sha256, sha384, sha512};

/// A checksum or digest algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algo {
    Sysv,
    Bsd,
    Crc,
    Crc32b,
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    /// BLAKE2b with a digest of this many bytes.
    Blake2b(usize),
    /// SHA-3 with a digest of this many bytes.
    Sha3(usize),
    Sm3,
}

impl Algo {
    fn by_name(n: &[u8]) -> Option<Algo> {
        Some(match n {
            b"sysv" => Algo::Sysv,
            b"bsd" => Algo::Bsd,
            b"crc" => Algo::Crc,
            b"crc32b" => Algo::Crc32b,
            b"md5" => Algo::Md5,
            b"sha1" => Algo::Sha1,
            b"sha224" => Algo::Sha224,
            b"sha256" => Algo::Sha256,
            b"sha384" => Algo::Sha384,
            b"sha512" => Algo::Sha512,
            b"blake2b" => Algo::Blake2b(64),
            b"sm3" => Algo::Sm3,
            _ => return None,
        })
    }

    /// Whether it is a digest (a hash printed as hexadecimal) rather than
    /// one of the old checksums.
    fn is_digest(self) -> bool {
        !matches!(self, Algo::Sysv | Algo::Bsd | Algo::Crc | Algo::Crc32b)
    }

    /// The name tagged lines start with.
    fn tag(self) -> String {
        match self {
            Algo::Md5 => String::from("MD5"),
            Algo::Sha1 => String::from("SHA1"),
            Algo::Sha224 => String::from("SHA224"),
            Algo::Sha256 => String::from("SHA256"),
            Algo::Sha384 => String::from("SHA384"),
            Algo::Sha512 => String::from("SHA512"),
            Algo::Blake2b(64) => String::from("BLAKE2b"),
            Algo::Blake2b(n) => alloc::format!("BLAKE2b-{}", n * 8),
            Algo::Sha3(n) => alloc::format!("SHA3-{}", n * 8),
            Algo::Sm3 => String::from("SM3"),
            _ => String::new(),
        }
    }

    /// The algorithm a tagged line names.
    fn by_tag(t: &[u8]) -> Option<Algo> {
        Some(match t {
            b"MD5" => Algo::Md5,
            b"SHA1" => Algo::Sha1,
            b"SHA224" => Algo::Sha224,
            b"SHA256" => Algo::Sha256,
            b"SHA384" => Algo::Sha384,
            b"SHA512" => Algo::Sha512,
            b"SM3" => Algo::Sm3,
            b"BLAKE2b" => Algo::Blake2b(64),
            b"SHA3-224" => Algo::Sha3(28),
            b"SHA3-256" => Algo::Sha3(32),
            b"SHA3-384" => Algo::Sha3(48),
            b"SHA3-512" => Algo::Sha3(64),
            _ => {
                let bits: usize = core::str::from_utf8(t.strip_prefix(b"BLAKE2b-")?).ok()?.parse().ok()?;
                if bits == 0 || bits % 8 != 0 || bits > 512 {
                    return None;
                }
                Algo::Blake2b(bits / 8)
            }
        })
    }
}

/// POSIX cksum's CRC (XCU cksum): polynomial 0x04C11DB7, most significant
/// bit first, over the data and then its length in as few bytes as hold
/// it, least significant first; the result complemented.
struct PosixCrc {
    crc: u32,
    len: u64,
}

fn posix_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    for (i, e) in t.iter_mut().enumerate() {
        let mut c = (i as u32) << 24;
        for _ in 0..8 {
            c = if c & 0x8000_0000 != 0 { (c << 1) ^ 0x04C1_1DB7 } else { c << 1 };
        }
        *e = c;
    }
    t
}

impl PosixCrc {
    fn update(&mut self, t: &[u32; 256], data: &[u8]) {
        for &b in data {
            self.crc = (self.crc << 8) ^ t[((self.crc >> 24) as u8 ^ b) as usize];
        }
        self.len += data.len() as u64;
    }

    fn finish(mut self, t: &[u32; 256]) -> u32 {
        let mut n = self.len;
        while n > 0 {
            let len = self.len;
            self.update(t, &[n as u8]);
            self.len = len;
            n >>= 8;
        }
        !self.crc
    }
}

enum State {
    Sysv(u32),
    Bsd(u16),
    Crc(PosixCrc, alloc::boxed::Box<[u32; 256]>),
    Crc32b(u32),
    Md5(slate_hash::Md5),
    Sha1(slate_hash::Sha1),
    Sha256(slate_hash::Sha256),
    Sha224(slate_hash::Sha256),
    Sha512(slate_hash::Sha512),
    Sha384(slate_hash::Sha512),
    Blake2b(slate_hash::Blake2b),
    Sha3(slate_hash::Sha3),
    Sm3(slate_hash::Sm3),
}

/// What a file sums to: a digest, or a checksum and its block count.
#[derive(Debug, PartialEq, Eq)]
pub enum Sum {
    Digest(Vec<u8>),
    /// Checksum, and the size in bytes.
    Check(u32, u64),
}

/// Sum all of `fd`.
fn sum_fd(fd: i32, algo: Algo) -> Result<Sum, Errno> {
    let mut st = match algo {
        Algo::Sysv => State::Sysv(0),
        Algo::Bsd => State::Bsd(0),
        Algo::Crc => State::Crc(PosixCrc { crc: 0, len: 0 }, alloc::boxed::Box::new(posix_table())),
        Algo::Crc32b => State::Crc32b(0),
        Algo::Md5 => State::Md5(slate_hash::Md5::new()),
        Algo::Sha1 => State::Sha1(slate_hash::Sha1::new()),
        Algo::Sha224 => State::Sha224(slate_hash::Sha256::new_224()),
        Algo::Sha256 => State::Sha256(slate_hash::Sha256::new()),
        Algo::Sha384 => State::Sha384(slate_hash::Sha512::new_384()),
        Algo::Sha512 => State::Sha512(slate_hash::Sha512::new()),
        Algo::Blake2b(n) => State::Blake2b(slate_hash::Blake2b::new(n)),
        Algo::Sha3(n) => State::Sha3(slate_hash::Sha3::new(n)),
        Algo::Sm3 => State::Sm3(slate_hash::Sm3::new()),
    };
    let mut buf = alloc::vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = io::read(fd, &mut buf)?;
        if n == 0 {
            break;
        }
        let d = &buf[..n];
        size += n as u64;
        match &mut st {
            State::Sysv(s) => *s = d.iter().fold(*s, |a, &b| a.wrapping_add(u32::from(b))),
            // BSD sum: rotate right one bit, then add the byte.
            State::Bsd(s) => {
                for &b in d {
                    *s = s.rotate_right(1).wrapping_add(u16::from(b));
                }
            }
            State::Crc(c, t) => c.update(t, d),
            State::Crc32b(c) => *c = slate_flate::crc32_update(*c, d),
            State::Md5(h) => h.update(d),
            State::Sha1(h) => h.update(d),
            State::Sha256(h) | State::Sha224(h) => h.update(d),
            State::Sha512(h) | State::Sha384(h) => h.update(d),
            State::Blake2b(h) => h.update(d),
            State::Sha3(h) => h.update(d),
            State::Sm3(h) => h.update(d),
        }
    }
    Ok(match st {
        // System V sum: the bytes' sum folded to 16 bits, twice.
        State::Sysv(s) => {
            let r = (s & 0xffff) + (s >> 16);
            Sum::Check((r & 0xffff) + (r >> 16), size)
        }
        State::Bsd(s) => Sum::Check(u32::from(s), size),
        State::Crc(c, t) => Sum::Check(c.finish(&t), size),
        State::Crc32b(c) => Sum::Check(c, size),
        State::Md5(h) => Sum::Digest(h.finish().to_vec()),
        State::Sha1(h) => Sum::Digest(h.finish().to_vec()),
        State::Sha256(h) => Sum::Digest(h.finish().to_vec()),
        State::Sha224(h) => Sum::Digest(h.finish()[..28].to_vec()),
        State::Sha512(h) => Sum::Digest(h.finish().to_vec()),
        State::Sha384(h) => Sum::Digest(h.finish()[..48].to_vec()),
        State::Blake2b(h) => Sum::Digest(h.finish()),
        State::Sha3(h) => Sum::Digest(h.finish()),
        State::Sm3(h) => Sum::Digest(h.finish().to_vec()),
    })
}

/// Sum file `name` (`-` is standard input).
fn sum_file(name: &[u8], algo: Algo) -> Result<Sum, Errno> {
    if name == b"-" {
        return sum_fd(io::STDIN, algo);
    }
    let fd = fs::open(name, fs::O_RDONLY | fs::O_CLOEXEC, 0)?;
    if fs::fstat(fd).is_ok_and(|s| s.is_dir()) {
        let _ = io::close(fd);
        return Err(Errno::EISDIR);
    }
    let r = sum_fd(fd, algo);
    let _ = io::close(fd);
    r
}

/// RFC 4648 base64, padded.
fn base64(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in b.chunks(3) {
        let v =
            (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                s.push(char::from(A[(v >> (18 - 6 * i) & 63) as usize]));
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// How a digest is written.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Style {
    /// `HASH  FILE`.
    Untagged,
    /// `NAME (FILE) = HASH`.
    Tagged,
}

/// One file's line: `name` is None for standard input given as no file
/// (the checksums leave it out).
fn line(algo: Algo, sum: &Sum, name: Option<&[u8]>, style: Style, b64: bool) -> String {
    match sum {
        Sum::Digest(d) => {
            let hash = if b64 { base64(d) } else { hex(d) };
            let name = lossy(name.unwrap_or(b"-")).into_owned();
            match style {
                Style::Tagged => alloc::format!("{} ({name}) = {hash}", algo.tag()),
                Style::Untagged => alloc::format!("{hash}  {name}"),
            }
        }
        Sum::Check(c, size) => {
            let mut l = match algo {
                Algo::Bsd => alloc::format!("{c:05} {:5}", size.div_ceil(1024)),
                Algo::Sysv => alloc::format!("{c} {}", size.div_ceil(512)),
                _ => alloc::format!("{c} {size}"),
            };
            if let Some(n) = name {
                l.push(' ');
                l.push_str(&lossy(n));
            }
            l
        }
    }
}

/// `-c`: check the lines of each file, `algo` the program's own (None:
/// cksum's, which reads the algorithm from each tagged line).
fn check(files: &[Vec<u8>], algo: Option<Algo>, quiet: bool, status_only: bool) -> i32 {
    let mut status = 0;
    for file in files {
        let data = match read_input(file) {
            Ok(d) => d,
            Err(e) => {
                error_path(file, e);
                status = 1;
                continue;
            }
        };
        let mut bad = 0;
        for l in lines(&data, b'\n') {
            // `NAME (FILE) = HASH`, or `HASH  FILE` for a program's own.
            let tagged = l.iter().position(|&c| c == b' ').and_then(|sp| {
                let a = Algo::by_tag(&l[..sp])?;
                let r = l[sp..].strip_prefix(b" (")?;
                let eq = r.windows(4).rposition(|w| w == b") = ")?;
                Some((a, &r[eq + 4..], &r[..eq]))
            });
            let (a, want, target): (Algo, &[u8], &[u8]) = match (tagged, algo) {
                (Some((a, _, _)), Some(own))
                    if !matches!((a, own), (Algo::Blake2b(_), Algo::Blake2b(_))) && a != own =>
                {
                    continue;
                }
                (Some(t), _) => t,
                (None, Some(own)) => {
                    let Some(sp) = l.iter().position(|&c| c == b' ') else { continue };
                    let (want, rest) = (&l[..sp], &l[sp..]);
                    let target = rest.strip_prefix(b"  ").or_else(|| rest.strip_prefix(b" *")).unwrap_or(rest);
                    // b2sum's length is the digest's.
                    let own = match own {
                        Algo::Blake2b(_) if want.len() % 2 == 0 && want.len() <= 128 => Algo::Blake2b(want.len() / 2),
                        o => o,
                    };
                    (own, want, target)
                }
                (None, None) => continue,
            };
            let ok = match sum_file(target, a) {
                Ok(Sum::Digest(d)) => hex(&d).as_bytes() == want || base64(&d).as_bytes() == want,
                _ => false,
            };
            if !ok {
                bad += 1;
            }
            if !status_only && (!ok || !quiet) {
                println!("{}: {}", lossy(target), if ok { "OK" } else { "FAILED" });
            }
        }
        if bad > 0 {
            if !status_only {
                error(format_args!(
                    "WARNING: {bad} computed checksum{} did NOT match",
                    if bad == 1 { "" } else { "s" }
                ));
            }
            status = 1;
        }
    }
    io::flush_stdout();
    status
}

/// md5sum, sha*sum and b2sum (`blake2b`: `-l BITS` is allowed).
fn sum_main(args: &[Vec<u8>], mut algo: Algo) -> i32 {
    let (mut checking, mut quiet, mut status_only, mut tag) = (false, false, false, false);
    let mut files = Vec::new();
    let blake = matches!(algo, Algo::Blake2b(_));
    let mut p = Parser::new(args, if blake { b"l" } else { b"" });
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'c') => checking = true,
            Opt::Short(b'b' | b't') => {}
            Opt::Short(b'l') if blake => match length(&p.value().unwrap_or_default()) {
                Some(n) => algo = Algo::Blake2b(n),
                None => return 1,
            },
            Opt::Long(l) if l == "length" && blake => match length(&p.value().unwrap_or_default()) {
                Some(n) => algo = Algo::Blake2b(n),
                None => return 1,
            },
            Opt::Long(l) if l == "check" => checking = true,
            Opt::Long(l) if l == "quiet" => quiet = true,
            Opt::Long(l) if l == "status" => status_only = true,
            Opt::Long(l) if l == "tag" => tag = true,
            Opt::Long(l) if l == "binary" || l == "text" || l == "untagged" => {}
            Opt::Operand(x) => files.push(x),
            o => return bad_option(&o),
        }
    }
    if files.is_empty() {
        files.push(b"-".to_vec());
    }
    if checking {
        return check(&files, Some(algo), quiet, status_only);
    }
    let style = if tag { Style::Tagged } else { Style::Untagged };
    let mut status = 0;
    for file in &files {
        match sum_file(file, algo) {
            Ok(s) => println!("{}", line(algo, &s, Some(file), style, false)),
            Err(e) => {
                error_path(file, e);
                status = 1;
            }
        }
    }
    io::flush_stdout();
    status
}

/// A BLAKE2b length in bits: a multiple of 8, at most 512 (0 is 512).
fn length(v: &[u8]) -> Option<usize> {
    let n: usize = match core::str::from_utf8(v).ok().and_then(|s| s.parse().ok()) {
        Some(n) => n,
        None => {
            error(format_args!("invalid length: '{}'", lossy(v)));
            return None;
        }
    };
    if n > 512 {
        error(format_args!("invalid length: '{}'", lossy(v)));
        error("maximum digest length for 'BLAKE2b' is 512 bits");
        return None;
    }
    if n % 8 != 0 {
        error(format_args!("invalid length: '{}'", lossy(v)));
        error("length is not a multiple of 8");
        return None;
    }
    Some(if n == 0 { 64 } else { n / 8 })
}

pub fn md5sum(args: &[Vec<u8>]) -> i32 {
    sum_main(args, Algo::Md5)
}

pub fn sha1sum(args: &[Vec<u8>]) -> i32 {
    sum_main(args, Algo::Sha1)
}

pub fn sha224sum(args: &[Vec<u8>]) -> i32 {
    sum_main(args, Algo::Sha224)
}

pub fn sha384sum(args: &[Vec<u8>]) -> i32 {
    sum_main(args, Algo::Sha384)
}

pub fn sha256sum(args: &[Vec<u8>]) -> i32 {
    sum_main(args, Algo::Sha256)
}

pub fn sha512sum(args: &[Vec<u8>]) -> i32 {
    sum_main(args, Algo::Sha512)
}

pub fn b2sum(args: &[Vec<u8>]) -> i32 {
    sum_main(args, Algo::Blake2b(64))
}

/// What `-a` names: an algorithm, or sha2 and sha3, which need `-l`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Named {
    One(Algo),
    Sha2,
    Sha3,
}

/// cksum: POSIX's CRC, or `-a`'s algorithm.
pub fn cksum(args: &[Vec<u8>]) -> i32 {
    let mut named = Named::One(Algo::Crc);
    let (mut checking, mut quiet, mut status_only) = (false, false, false);
    let (mut untagged, mut b64, mut raw) = (false, false, false);
    let mut length_arg: Option<Vec<u8>> = None;
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"al");
    while let Some(o) = p.next() {
        let algorithm = |v: Vec<u8>| -> Option<Named> {
            match v.as_slice() {
                b"sha2" => Some(Named::Sha2),
                b"sha3" => Some(Named::Sha3),
                _ => match Algo::by_name(&v) {
                    Some(a) => Some(Named::One(a)),
                    None => {
                        error(format_args!("invalid argument '{}' for '--algorithm'", lossy(&v)));
                        let mut list = String::from("Valid arguments are:");
                        for a in [
                            "bsd", "sysv", "crc", "crc32b", "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
                            "sha2", "sha3", "blake2b", "sm3",
                        ] {
                            list.push_str(&alloc::format!("\n  - '{a}'"));
                        }
                        slate_rt::eprintln!("{list}");
                        slate_rt::eprintln!("Try '{} --help' for more information.", slate_rt::prog_name());
                        None
                    }
                },
            }
        };
        match o {
            Opt::Short(b'a') => match algorithm(p.value().unwrap_or_default()) {
                Some(n) => named = n,
                None => return 1,
            },
            Opt::Long(l) if l == "algorithm" => match algorithm(p.value().unwrap_or_default()) {
                Some(n) => named = n,
                None => return 1,
            },
            Opt::Short(b'l') => length_arg = p.value(),
            Opt::Long(l) if l == "length" => length_arg = p.value(),
            Opt::Short(b'c') => checking = true,
            Opt::Long(l) if l == "check" => checking = true,
            Opt::Long(l) if l == "quiet" => quiet = true,
            Opt::Long(l) if l == "status" => status_only = true,
            Opt::Long(l) if l == "untagged" => untagged = true,
            Opt::Long(l) if l == "tag" => untagged = false,
            Opt::Long(l) if l == "base64" => b64 = true,
            Opt::Long(l) if l == "raw" => raw = true,
            Opt::Operand(x) => files.push(x),
            o => return bad_option(&o),
        }
    }
    // -l: BLAKE2b's length, or which of SHA-2 and SHA-3.
    let algo = match (named, &length_arg) {
        (Named::One(Algo::Blake2b(_)), Some(v)) => match length(v) {
            Some(n) => Algo::Blake2b(n),
            None => return 1,
        },
        (Named::One(_), Some(_)) => {
            error("--length is only supported with --algorithm blake2b, sha2, or sha3");
            return 1;
        }
        (Named::One(a), None) => a,
        (Named::Sha2 | Named::Sha3, None) => {
            let n = if named == Named::Sha2 { "sha2" } else { "sha3" };
            error(format_args!("--algorithm={n} requires specifying --length 224, 256, 384, or 512"));
            return 1;
        }
        (Named::Sha2 | Named::Sha3, Some(v)) => {
            let bits = core::str::from_utf8(v).ok().and_then(|s| s.parse::<usize>().ok());
            match (named, bits) {
                (Named::Sha2, Some(224)) => Algo::Sha224,
                (Named::Sha2, Some(256)) => Algo::Sha256,
                (Named::Sha2, Some(384)) => Algo::Sha384,
                (Named::Sha2, Some(512)) => Algo::Sha512,
                (Named::Sha3, Some(b @ (224 | 256 | 384 | 512))) => Algo::Sha3(b / 8),
                _ => {
                    error(format_args!("invalid length: '{}'", lossy(v)));
                    error(format_args!(
                        "digest length for '{}' must be 224, 256, 384, or 512",
                        if named == Named::Sha2 { "SHA2" } else { "SHA3" }
                    ));
                    return 1;
                }
            }
        }
    };
    let named = !files.is_empty();
    if files.is_empty() {
        files.push(b"-".to_vec());
    }
    if checking {
        if !algo.is_digest() && algo != Algo::Crc {
            error("--check is not supported with --algorithm={bsd,sysv,crc,crc32b}");
            return 1;
        }
        return check(&files, if algo == Algo::Crc { None } else { Some(algo) }, quiet, status_only);
    }
    if raw && files.len() > 1 {
        error("the --raw option is not supported with multiple files");
        return 1;
    }
    let style = if untagged { Style::Untagged } else { Style::Tagged };
    let mut status = 0;
    for file in &files {
        match sum_file(file, algo) {
            Ok(s) if raw => {
                let bytes = match &s {
                    Sum::Digest(d) => d.clone(),
                    Sum::Check(c, _) if matches!(algo, Algo::Bsd | Algo::Sysv) => (*c as u16).to_be_bytes().to_vec(),
                    Sum::Check(c, _) => c.to_be_bytes().to_vec(),
                };
                io::out(&bytes);
            }
            Ok(s) => println!("{}", line(algo, &s, named.then_some(file.as_slice()), style, b64)),
            Err(e) => {
                error_path(file, e);
                status = 1;
            }
        }
    }
    io::flush_stdout();
    status
}

/// sum: BSD's checksum (`-r`, the default) or System V's (`-s`).
pub fn sum(args: &[Vec<u8>]) -> i32 {
    let mut algo = Algo::Bsd;
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'r') => algo = Algo::Bsd,
            Opt::Short(b's') => algo = Algo::Sysv,
            Opt::Long(l) if l == "sysv" => algo = Algo::Sysv,
            Opt::Operand(x) => files.push(x),
            o => return bad_option(&o),
        }
    }
    let named = !files.is_empty();
    if files.is_empty() {
        files.push(b"-".to_vec());
    }
    let mut status = 0;
    for file in &files {
        match sum_file(file, algo) {
            Ok(s) => println!("{}", line(algo, &s, named.then_some(file.as_slice()), Style::Untagged, false)),
            Err(e) => {
                error_path(file, e);
                status = 1;
            }
        }
    }
    io::flush_stdout();
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_digests() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"The quick brown fox jumps over the lazy dog")), "9e107d9d372bb6826bd81d3542a419d6");
        assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(hex(&sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(
            hex(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(hex(&sha512(&[b'a'; 200])).len(), 128);
    }

    #[test]
    fn crc_and_names() {
        // POSIX's CRC of "hello\n" and of nothing (cksum printed both).
        let t = posix_table();
        let mut c = PosixCrc { crc: 0, len: 0 };
        c.update(&t, b"hello\n");
        assert_eq!(c.finish(&t), 3_015_617_425);
        assert_eq!(PosixCrc { crc: 0, len: 0 }.finish(&t), 4_294_967_295);
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(Algo::by_tag(b"BLAKE2b-256"), Some(Algo::Blake2b(32)));
        assert_eq!(Algo::by_tag(b"BLAKE2b-7"), None);
        assert_eq!(Algo::Blake2b(16).tag(), "BLAKE2b-128");
    }
}
