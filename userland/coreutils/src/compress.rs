// SPDX-License-Identifier: MIT OR Apache-2.0

//! The compressors' front end: gzip (gunzip, zcat), bzip2 (bunzip2,
//! bzcat), xz (unxz, xzcat), lzma (unlzma, lzcat) and zstd (unzstd,
//! zstdcat), streaming from
//! descriptor to descriptor so files of any size take little memory. One
//! driver serves every format's command line:
//!
//! `NAME [-cdfklnNqrtvV1-9] [-S SUF] [FILE...]`: compress each FILE to
//! FILE.SUF (or decompress with -d), giving the new file the old one's
//! mode and times and removing the old one unless -k; with no FILE or
//! `-`, standard input to standard output. -t tests, -l lists sizes, -r
//! walks directories. Each format's messages and statuses are its own
//! program's (GNU gzip's, bzip2's, xz's, zstd's), as observed; zstd
//! keeps its input unless --rm, and says what it did unless -q.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use slate_rt::{Errno, eprintln, fs, io, lossy, process};

use crate::util::{Opt, Parser, bad_option, error_path};

/// Suffixes a format takes off, each with what replaces it.
type Suffixes = &'static [(&'static [u8], &'static [u8])];

/// A compressed format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Gzip,
    Bzip2,
    Xz,
    Lzma,
    Zstd,
}

impl Format {
    pub fn tool(self) -> &'static str {
        match self {
            Format::Gzip => "gzip",
            Format::Bzip2 => "bzip2",
            Format::Xz => "xz",
            Format::Lzma => "lzma",
            Format::Zstd => "zstd",
        }
    }

    /// The name its messages start with: gzip's are always gzip's; bzip2
    /// and xz say the name they were run by (`bunzip2: ...`).
    fn prefix(self) -> String {
        match self {
            Format::Gzip => String::from("gzip"),
            Format::Zstd => String::from("zstd"),
            _ => slate_rt::prog_name(),
        }
    }

    /// The suffix it adds, and the ones it takes off with what they stand
    /// for (`.tgz` is `.tar.gz`).
    fn suffixes(self) -> (&'static [u8], Suffixes) {
        match self {
            Format::Gzip => {
                (b".gz", &[(b".gz", b""), (b".tgz", b".tar"), (b".taz", b".tar"), (b"-gz", b""), (b".z", b"")])
            }
            Format::Bzip2 => (b".bz2", &[(b".bz2", b""), (b".bz", b""), (b".tbz2", b".tar"), (b".tbz", b".tar")]),
            Format::Xz => (b".xz", &[(b".xz", b""), (b".txz", b".tar")]),
            Format::Lzma => (b".lzma", &[(b".lzma", b""), (b".tlz", b".tar")]),
            Format::Zstd => (b".zst", &[(b".zst", b""), (b".tzst", b".tar")]),
        }
    }

    pub fn default_level(self) -> u8 {
        match self {
            Format::Gzip | Format::Xz | Format::Lzma => 6,
            Format::Bzip2 => 9,
            Format::Zstd => 3,
        }
    }

    /// The format whose magic `data` starts with.
    pub fn sniff(data: &[u8]) -> Option<Format> {
        if data.starts_with(&[0x1F, 0x8B]) {
            return Some(Format::Gzip);
        }
        if data.starts_with(b"BZh") {
            return Some(Format::Bzip2);
        }
        if data.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0]) {
            return Some(Format::Xz);
        }
        if data.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
            return Some(Format::Zstd);
        }
        // lzma has no magic: its usual properties byte and a dictionary
        // size that is a power of two (or 2^n + 2^(n-1)).
        if data.len() >= 13 && data[0] == 0x5D {
            let d = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            if d.count_ones() <= 2 && d >= 4096 {
                return Some(Format::Lzma);
            }
        }
        None
    }

    /// What its programs call standard input in messages.
    fn stdin_name(self) -> &'static str {
        match self {
            Format::Gzip => "stdin",
            Format::Zstd => "/*stdin*\\",
            Format::Bzip2 | Format::Xz | Format::Lzma => "(stdin)",
        }
    }
}

/// Reading from a descriptor, keeping its error.
#[derive(Debug)]
pub struct FdIn {
    pub fd: i32,
    pub err: Option<Errno>,
    pub count: u64,
}

impl FdIn {
    pub fn new(fd: i32) -> FdIn {
        FdIn { fd, err: None, count: 0 }
    }

    /// Read up to `buf.len()` bytes (0 at the end).
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, Errno> {
        match io::read(self.fd, buf) {
            Ok(n) => {
                self.count += n as u64;
                Ok(n)
            }
            Err(e) => {
                self.err = Some(e);
                Err(e)
            }
        }
    }
}

impl slate_flate::Source for &mut FdIn {
    fn fill(&mut self, buf: &mut [u8]) -> Result<usize, slate_flate::Error> {
        self.read(buf).map_err(|_| slate_flate::Error::Io)
    }
}

/// Writing to a descriptor (or nowhere, for -t), keeping its error.
#[derive(Debug)]
pub struct FdOut {
    pub fd: Option<i32>,
    pub err: Option<Errno>,
    pub count: u64,
}

impl FdOut {
    pub fn new(fd: Option<i32>) -> FdOut {
        FdOut { fd, err: None, count: 0 }
    }

    pub fn put(&mut self, data: &[u8]) -> Result<(), Errno> {
        self.count += data.len() as u64;
        if let Some(fd) = self.fd
            && let Err(e) = io::write_all(fd, data)
        {
            self.err = Some(e);
            return Err(e);
        }
        Ok(())
    }
}

impl slate_flate::Sink for FdOut {
    fn write(&mut self, data: &[u8]) -> Result<(), slate_flate::Error> {
        self.put(data).map_err(|_| slate_flate::Error::Io)
    }
}

/// Why a stream failed.
#[derive(Debug)]
pub enum Failure {
    Read(Errno),
    Write(Errno),
    /// The input is not in the format.
    NotFormat,
    /// The data is damaged (what was wrong, in gzip's words).
    Corrupt(&'static str),
    /// The data ends early.
    Truncated,
    /// Options or filters this program does not have.
    Unsupported,
}

/// What a decompression found.
#[derive(Debug, Default)]
pub struct Found {
    /// xz's streams and blocks and its check.
    pub streams: u32,
    pub blocks: u32,
    pub check: Option<slate_xz::Check>,
    /// A gzip member's saved name and time.
    pub name: Option<Vec<u8>>,
    pub mtime: Option<i64>,
    /// The format's own bytes around the data (gzip's header and trailer),
    /// which `-l`'s ratio leaves out.
    pub overhead: u64,
}

const CHUNK: usize = 128 * 1024;

/// The error behind a codec's I/O failure.
fn io_failure(input: &FdIn, out: &FdOut) -> Failure {
    match (input.err, out.err) {
        (Some(e), _) => Failure::Read(e),
        (_, Some(e)) => Failure::Write(e),
        _ => Failure::Truncated,
    }
}

/// Feed all of `input` to a compressor's `write`, its output to `out`.
fn pump(input: &mut FdIn, out: &mut FdOut, mut write: impl FnMut(&[u8], &mut Vec<u8>)) -> Result<(), Failure> {
    let mut buf = vec![0u8; CHUNK];
    let mut packed = Vec::with_capacity(CHUNK);
    loop {
        let n = input.read(&mut buf).map_err(Failure::Read)?;
        if n == 0 {
            break;
        }
        write(&buf[..n], &mut packed);
        out.put(&packed).map_err(Failure::Write)?;
        packed.clear();
    }
    Ok(())
}

/// How to compress: the level, and xz's check.
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub level: u8,
    pub check: slate_xz::Check,
}

impl Settings {
    pub fn new(fmt: Format) -> Settings {
        Settings { level: fmt.default_level(), check: slate_xz::Check::Crc64 }
    }
}

/// Compress all of `input` into `out` (gzip keeps `name` and its time).
pub fn compress(
    fmt: Format,
    input: &mut FdIn,
    out: &mut FdOut,
    set: Settings,
    name: Option<(&[u8], u32)>,
) -> Result<(), Failure> {
    let level = set.level;
    match fmt {
        Format::Gzip => {
            let h = slate_flate::Header { name: name.map(|n| n.0.to_vec()), mtime: name.map_or(0, |n| n.1) };
            let mut w = slate_flate::GzipWriter::new(&h, level);
            pump(input, out, |d, o| w.write(d, o))?;
            let mut tail = Vec::new();
            w.finish(&mut tail);
            out.put(&tail).map_err(Failure::Write)
        }
        Format::Bzip2 => {
            let mut c = slate_bzip2::Compressor::new(level);
            let mut tail = Vec::new();
            pump(input, out, |d, o| c.write(d, o))?;
            c.finish(&mut tail);
            out.put(&tail).map_err(Failure::Write)
        }
        Format::Xz => {
            let mut w = slate_xz::XzWriter::new(u32::from(level), set.check);
            let mut tail = Vec::new();
            pump(input, out, |d, o| w.write(d, o))?;
            w.finish(&mut tail);
            out.put(&tail).map_err(Failure::Write)
        }
        Format::Lzma => {
            let mut w = slate_xz::LzmaWriter::new(u32::from(level));
            let mut tail = Vec::new();
            pump(input, out, |d, o| w.write(d, o))?;
            w.finish(&mut tail);
            out.put(&tail).map_err(Failure::Write)
        }
        Format::Zstd => {
            let mut w = slate_zstd::Writer::new(i32::from(level));
            let mut tail = Vec::new();
            pump(input, out, |d, o| w.write(d, o))?;
            w.finish(&mut tail);
            out.put(&tail).map_err(Failure::Write)
        }
    }
}

/// A source that gives back bytes already read before the rest.
struct Prefixed<'a> {
    prefix: Vec<u8>,
    at: usize,
    rest: &'a mut FdIn,
}

impl slate_flate::Source for Prefixed<'_> {
    fn fill(&mut self, buf: &mut [u8]) -> Result<usize, slate_flate::Error> {
        if self.at < self.prefix.len() {
            let n = buf.len().min(self.prefix.len() - self.at);
            buf[..n].copy_from_slice(&self.prefix[self.at..self.at + n]);
            self.at += n;
            return Ok(n);
        }
        self.rest.read(buf).map_err(|_| slate_flate::Error::Io)
    }
}

fn xz_failure(e: slate_xz::Error, input: &FdIn, out: &FdOut) -> Failure {
    match e {
        slate_xz::Error::Io => io_failure(input, out),
        slate_xz::Error::NotXz => Failure::NotFormat,
        slate_xz::Error::Truncated => Failure::Truncated,
        slate_xz::Error::UnsupportedFilter => Failure::Unsupported,
        _ => Failure::Corrupt("corrupt"),
    }
}

/// Decompress all of `input` into `out`.
pub fn decompress(fmt: Format, input: &mut FdIn, out: &mut FdOut) -> Result<Found, Failure> {
    decompress_after(fmt, Vec::new(), input, out)
}

/// Decompress `prefix` (bytes already read from `input`, as a caller
/// that looked at the magic number has) and the rest of `input`.
pub fn decompress_after(fmt: Format, mut prefix: Vec<u8>, input: &mut FdIn, out: &mut FdOut) -> Result<Found, Failure> {
    // xz tells its two formats apart by the first six bytes.
    if matches!(fmt, Format::Xz | Format::Lzma) {
        while prefix.len() < 6 {
            let mut b = [0u8; 6];
            match input.read(&mut b[..6 - prefix.len()]).map_err(Failure::Read)? {
                0 => break,
                n => prefix.extend_from_slice(&b[..n]),
            }
        }
    }
    let head = prefix.clone();
    let src = Prefixed { prefix, at: 0, rest: &mut *input };
    match fmt {
        Format::Gzip => match slate_flate::gunzip_stream(src, out) {
            Ok(r) => Ok(Found {
                streams: 1,
                blocks: 1,
                check: None,
                name: r.header.name,
                mtime: (r.header.mtime != 0).then_some(i64::from(r.header.mtime)),
                overhead: r.overhead,
            }),
            Err(slate_flate::Error::Io) => Err(io_failure(input, out)),
            Err(slate_flate::Error::NotGzip) => Err(Failure::NotFormat),
            Err(slate_flate::Error::Truncated) => Err(Failure::Truncated),
            Err(slate_flate::Error::Checksum) => Err(Failure::Corrupt("crc error")),
            Err(_) => Err(Failure::Corrupt("format violated")),
        },
        Format::Bzip2 => match slate_bzip2::decompress_stream(src, out) {
            Ok(_) => Ok(Found::default()),
            Err(slate_bzip2::Error::Io) => Err(io_failure(input, out)),
            Err(slate_bzip2::Error::NotBzip2) => Err(Failure::NotFormat),
            Err(slate_bzip2::Error::Truncated) => Err(Failure::Truncated),
            Err(_) => Err(Failure::Corrupt("crc error")),
        },
        Format::Zstd => match slate_zstd::decompress_stream(src, out) {
            Ok(i) => Ok(Found {
                streams: i.frames,
                blocks: 0,
                check: i.checksum.then_some(slate_xz::Check::Crc64),
                ..Found::default()
            }),
            Err(slate_zstd::Error::Io) => Err(io_failure(input, out)),
            Err(slate_zstd::Error::NotZstd) => Err(Failure::NotFormat),
            Err(slate_zstd::Error::Truncated) => Err(Failure::Truncated),
            Err(slate_zstd::Error::Checksum) => Err(Failure::Corrupt("checksum")),
            Err(slate_zstd::Error::Dictionary | slate_zstd::Error::TooLarge) => Err(Failure::Unsupported),
            Err(_) => Err(Failure::Corrupt("corrupt")),
        },
        // xz takes lzma files too (its format "auto"); lzma takes only
        // lzma.
        Format::Xz | Format::Lzma => {
            let is_xz = head.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0]);
            if fmt == Format::Xz && is_xz {
                let r = slate_xz::decompress_stream(src, out);
                let info = r.map_err(|e| xz_failure(e, input, out))?;
                return Ok(Found { streams: info.streams, blocks: info.blocks, check: info.check, ..Found::default() });
            }
            if fmt == Format::Xz && head.len() < 6 {
                return Err(Failure::NotFormat);
            }
            let r = slate_xz::decompress_lzma_stream(src, out);
            r.map_err(|e| xz_failure(e, input, out))?;
            Ok(Found { streams: 1, blocks: 1, ..Found::default() })
        }
    }
}

/// What `fmt`'s program says when its data fails, for a caller (tar)
/// that runs it on a stream named `name`.
pub fn failure_message(fmt: Format, name: &str, f: Failure) -> String {
    match (fmt, f) {
        (_, Failure::Read(e)) | (_, Failure::Write(e)) => format!("{}: {name}: {e}", fmt.tool()),
        (Format::Gzip, Failure::NotFormat) => format!("gzip: {name}: not in gzip format"),
        (Format::Gzip, Failure::Corrupt(w)) => format!("gzip: {name}: invalid compressed data--{w}"),
        (Format::Gzip, _) => format!("gzip: {name}: unexpected end of file"),
        (Format::Bzip2, Failure::NotFormat) => format!("bzip2: {name} is not a bzip2 file."),
        (Format::Bzip2, _) => format!("bzip2: {name}: data integrity (CRC) error in data"),
        (Format::Xz | Format::Lzma, Failure::NotFormat) => format!("xz: {name}: File format not recognized"),
        (Format::Xz | Format::Lzma, Failure::Truncated) => format!("xz: {name}: Unexpected end of input"),
        (Format::Xz | Format::Lzma, _) => format!("xz: {name}: Compressed data is corrupt"),
        (Format::Zstd, Failure::NotFormat) => format!("zstd: {name}: unsupported format "),
        (Format::Zstd, _) => format!("zstd: {name} : Decoding error (36) : Data corruption detected "),
    }
}

/// The format a file name says (`.tar.gz`, `.tgz`...), for tar's -a.
pub fn by_suffix(name: &[u8]) -> Option<Format> {
    let lower = name.to_ascii_lowercase();
    let ends = |s: &[u8]| lower.ends_with(s);
    if ends(b".gz") || ends(b".tgz") || ends(b".taz") {
        Some(Format::Gzip)
    } else if ends(b".bz2") || ends(b".tbz") || ends(b".tbz2") || ends(b".tb2") {
        Some(Format::Bzip2)
    } else if ends(b".xz") || ends(b".txz") {
        Some(Format::Xz)
    } else if ends(b".lzma") || ends(b".tlz") {
        Some(Format::Lzma)
    } else if ends(b".zst") || ends(b".tzst") {
        Some(Format::Zstd)
    } else {
        None
    }
}

/// The options shared by every format's command.
#[derive(Clone, Debug)]
struct Opts {
    decompress: bool,
    stdout: bool,
    keep: bool,
    force: bool,
    test: bool,
    list: bool,
    recursive: bool,
    verbose: bool,
    quiet: bool,
    /// Save (compressing) or restore (decompressing) the name and time.
    name: Option<bool>,
    set: Settings,
    suffix: Option<Vec<u8>>,
    /// zstd's -o.
    output: Option<Vec<u8>>,
}

pub fn gzip(args: &[Vec<u8>]) -> i32 {
    run(Format::Gzip, args, false, false)
}

pub fn gunzip(args: &[Vec<u8>]) -> i32 {
    run(Format::Gzip, args, true, false)
}

pub fn zcat(args: &[Vec<u8>]) -> i32 {
    run(Format::Gzip, args, true, true)
}

pub fn bzip2(args: &[Vec<u8>]) -> i32 {
    run(Format::Bzip2, args, false, false)
}

pub fn bunzip2(args: &[Vec<u8>]) -> i32 {
    run(Format::Bzip2, args, true, false)
}

pub fn bzcat(args: &[Vec<u8>]) -> i32 {
    run(Format::Bzip2, args, true, true)
}

pub fn xz(args: &[Vec<u8>]) -> i32 {
    run(Format::Xz, args, false, false)
}

pub fn unxz(args: &[Vec<u8>]) -> i32 {
    run(Format::Xz, args, true, false)
}

pub fn xzcat(args: &[Vec<u8>]) -> i32 {
    run(Format::Xz, args, true, true)
}

pub fn lzma(args: &[Vec<u8>]) -> i32 {
    run(Format::Lzma, args, false, false)
}

pub fn unlzma(args: &[Vec<u8>]) -> i32 {
    run(Format::Lzma, args, true, false)
}

pub fn lzcat(args: &[Vec<u8>]) -> i32 {
    run(Format::Lzma, args, true, true)
}

pub fn zstd(args: &[Vec<u8>]) -> i32 {
    run(Format::Zstd, args, false, false)
}

pub fn unzstd(args: &[Vec<u8>]) -> i32 {
    run(Format::Zstd, args, true, false)
}

pub fn zstdcat(args: &[Vec<u8>]) -> i32 {
    run(Format::Zstd, args, true, true)
}

/// xz's `--check` names.
fn check_named(n: &[u8]) -> Option<slate_xz::Check> {
    match n {
        b"none" => Some(slate_xz::Check::None),
        b"crc32" => Some(slate_xz::Check::Crc32),
        b"crc64" => Some(slate_xz::Check::Crc64),
        b"sha256" => Some(slate_xz::Check::Sha256),
        _ => None,
    }
}

fn run(mut fmt: Format, args: &[Vec<u8>], decompress: bool, stdout: bool) -> i32 {
    let xzlike = matches!(fmt, Format::Xz | Format::Lzma);
    let mut o = Opts {
        decompress,
        stdout,
        keep: false,
        force: false,
        test: false,
        list: false,
        recursive: false,
        verbose: false,
        quiet: false,
        name: None,
        set: Settings::new(fmt),
        suffix: None,
        output: None,
    };
    // zstd keeps what it compresses unless --rm.
    o.keep = fmt == Format::Zstd;
    let zstd = fmt == Format::Zstd;
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"SFCTMo");
    let prefix = fmt.prefix();
    let bad_value = |what: &str, v: &[u8]| {
        io::err(format!("{prefix}: {}: {what}\n", lossy(v)).as_bytes());
        1
    };
    while let Some(opt) = p.next() {
        match opt {
            Opt::Short(b'd') => o.decompress = true,
            Opt::Short(b'z') => o.decompress = false,
            Opt::Short(b'c') => o.stdout = true,
            Opt::Short(b'k') => o.keep = true,
            Opt::Short(b'f') => o.force = true,
            Opt::Short(b'n') if fmt == Format::Gzip => o.name = Some(false),
            Opt::Short(b'N') if fmt == Format::Gzip => o.name = Some(true),
            Opt::Short(b'q') => o.quiet = true,
            Opt::Short(b'v') => o.verbose = true,
            Opt::Short(b't') => o.test = true,
            Opt::Short(b'l') if fmt == Format::Gzip => o.list = true,
            Opt::Short(b'r') if fmt == Format::Gzip => o.recursive = true,
            Opt::Short(b'l') if xzlike => o.list = true,
            Opt::Short(b'S') if fmt == Format::Gzip || xzlike => o.suffix = p.value(),
            Opt::Short(b'e') if xzlike => {}
            Opt::Short(b'o') if zstd => o.output = p.value(),
            Opt::Short(b'T') if zstd => {}
            Opt::Short(b'r') if zstd => o.recursive = true,
            Opt::Short(b'l') if zstd => o.list = true,
            Opt::Short(b'T' | b'M') if xzlike => {
                p.value();
            }
            Opt::Short(b'Q') if xzlike => {}
            Opt::Short(b'C') if xzlike => {
                let v = p.value().unwrap_or_default();
                match check_named(&v) {
                    Some(c) => o.set.check = c,
                    None => return bad_value("Unsupported integrity check type", &v),
                }
            }
            Opt::Short(b'F') if xzlike => {
                let v = p.value().unwrap_or_default();
                match v.as_slice() {
                    b"xz" | b"auto" => fmt = Format::Xz,
                    b"lzma" | b"alone" => fmt = Format::Lzma,
                    _ => return bad_value("Unknown file format type", &v),
                }
            }
            // bzip2's: less memory; repair is not offered.
            Opt::Short(b's') if fmt == Format::Bzip2 => {}
            Opt::Short(b'V' | b'L') => {
                io::out(format!("{} (Slate) 0.1\n", fmt.tool()).as_bytes());
                return 0;
            }
            // zstd's levels go past 9: -19 is one option.
            Opt::Short(c) if c.is_ascii_digit() && zstd => {
                let mut n = c - b'0';
                while let Some(d) = p.peek_short().filter(u8::is_ascii_digit) {
                    p.next();
                    n = (n * 10 + (d - b'0')).min(22);
                }
                o.set.level = n.max(1);
            }
            Opt::Short(c) if c.is_ascii_digit() => o.set.level = if xzlike { c - b'0' } else { (c - b'0').max(1) },
            Opt::Long(l) => match l.as_str() {
                "decompress" | "uncompress" => o.decompress = true,
                "compress" => o.decompress = false,
                "stdout" | "to-stdout" => o.stdout = true,
                "keep" => o.keep = true,
                "force" => o.force = true,
                "no-name" => o.name = Some(false),
                "name" => o.name = Some(true),
                "quiet" | "silent" => o.quiet = true,
                "verbose" => o.verbose = true,
                "test" => o.test = true,
                "list" => o.list = true,
                "recursive" => o.recursive = true,
                "suffix" => o.suffix = p.value(),
                "small" | "extreme" | "no-warn" | "no-sparse" => {}
                "rm" if zstd => o.keep = false,
                "ultra" | "no-check" | "check" | "no-progress" | "progress" | "sparse" if zstd => {}
                "output" if zstd => o.output = p.value(),
                "fast" => {
                    if zstd {
                        p.inline_value();
                    }
                    o.set.level = if xzlike { 0 } else { 1 };
                }
                "best" => o.set.level = 9,
                "threads" | "memlimit" | "memory" => {
                    p.value();
                }
                "check" if xzlike => {
                    let v = p.value().unwrap_or_default();
                    match check_named(&v) {
                        Some(c) => o.set.check = c,
                        None => return bad_value("Unsupported integrity check type", &v),
                    }
                }
                "format" if xzlike => {
                    let v = p.value().unwrap_or_default();
                    match v.as_slice() {
                        b"xz" | b"auto" => fmt = Format::Xz,
                        b"lzma" | b"alone" => fmt = Format::Lzma,
                        _ => return bad_value("Unknown file format type", &v),
                    }
                }
                "version" | "license" => {
                    io::out(format!("{} (Slate) 0.1\n", fmt.tool()).as_bytes());
                    return 0;
                }
                _ => return bad_option(&Opt::Long(l)),
            },
            Opt::Operand(f) => files.push(f),
            other => return bad_option(&other),
        }
    }
    if o.test || o.list {
        o.decompress = true;
    }
    if files.is_empty() {
        files.push(b"-".to_vec());
    }
    if zstd && o.list && files.iter().any(|f| f == b"-") {
        io::err(b"zstd: --list does not support reading from standard input \nNo files given \n");
        return 1;
    }
    let mut status = 0;
    let mut totals = Totals::default();
    for f in &files {
        status = status.max(one(fmt, f, &o, &mut totals));
    }
    if o.list && totals.files > 1 && zstd {
        io::out(format!("{} \n", "-".repeat(65)).as_bytes());
        let check = totals.checks.join(",");
        zstd_list_line(totals.streams, totals.packed, totals.plain, &check, &format!("{} files", totals.files));
    } else if o.list && totals.files > 1 {
        if xzlike {
            io::out(format!("{}\n", "-".repeat(79)).as_bytes());
            let checks = totals.checks.join(",");
            xz_list_line(
                totals.streams,
                totals.blocks,
                totals.packed,
                totals.plain,
                &checks,
                &format!("{} files", totals.files),
            );
        } else {
            list_line(totals.packed, totals.plain, totals.overhead, "(totals)");
        }
    }
    status
}

/// A size as xz shows it: bytes, KiB, MiB... (whichever stays under
/// 10 000), one decimal past bytes, thousands separated by commas.
fn xz_size(n: u64) -> String {
    let group = |s: &str| {
        let (int, frac) = s.split_once('.').map_or((s, None), |(a, b)| (a, Some(b)));
        let mut g = String::new();
        for (i, c) in int.chars().enumerate() {
            if i > 0 && (int.len() - i) % 3 == 0 {
                g.push(',');
            }
            g.push(c);
        }
        if let Some(f) = frac {
            g.push('.');
            g.push_str(f);
        }
        g
    };
    if n < 10000 {
        return format!("{} B", group(&format!("{n}")));
    }
    let mut v = n as f64 / 1024.0;
    for unit in ["KiB", "MiB", "GiB", "TiB"] {
        let shown = format!("{v:.1}");
        if shown.parse::<f64>().unwrap_or(v) < 10000.0 || unit == "TiB" {
            return format!("{} {unit}", group(&shown));
        }
        v /= 1024.0;
    }
    format!("{n} B")
}

/// A size as zstd shows it: three significant figures in B, KiB, MiB...,
/// the number `width` wide.
fn zstd_size(n: u64, width: usize) -> String {
    if n < 1024 {
        return format!("{n:>width$} B");
    }
    let mut v = n as f64 / 1024.0;
    for unit in ["KiB", "MiB", "GiB", "TiB"] {
        if v < 1024.0 || unit == "TiB" {
            let num = if v < 10.0 {
                format!("{v:.2}")
            } else if v < 100.0 {
                format!("{v:.1}")
            } else {
                format!("{v:.0}")
            };
            return format!("{num:>width$} {unit}");
        }
        v /= 1024.0;
    }
    format!("{n} B")
}

/// `zstd -l`'s line.
fn zstd_list_line(frames: u32, packed: u64, plain: u64, check: &str, name: &str) {
    let ratio = if packed == 0 { 0.0 } else { plain as f64 / packed as f64 };
    let unit = |n: u64| {
        let s = zstd_size(n, 0);
        match s.strip_suffix(" B") {
            Some(num) => format!("{num}   B"),
            None => s,
        }
    };
    io::out(
        format!("{frames:6} {:6} {:>11} {:>13}  {ratio:.3}  {check}  {name}\n", 0, unit(packed), unit(plain))
            .as_bytes(),
    );
}

/// `xz -l`'s line.
fn xz_list_line(streams: u32, blocks: u32, packed: u64, plain: u64, check: &str, name: &str) {
    let ratio = if plain == 0 || packed as f64 / plain as f64 > 9.999 {
        String::from("---")
    } else {
        format!("{:.3}", packed as f64 / plain as f64)
    };
    io::out(
        format!(
            "{streams:5} {blocks:7} {:>12} {:>12} {ratio:>6}  {check:<7} {name}\n",
            xz_size(packed),
            xz_size(plain)
        )
        .as_bytes(),
    );
}

/// The name a compressed file decompresses to, if it has a known suffix.
fn plain_name(fmt: Format, f: &[u8], o: &Opts) -> Option<Vec<u8>> {
    if let Some(s) = &o.suffix
        && let Some(base) = f.strip_suffix(s.as_slice())
        && !base.is_empty()
    {
        return Some(base.to_vec());
    }
    let (_, known) = fmt.suffixes();
    let lower = f.to_ascii_lowercase();
    for (suf, rep) in known {
        if lower.ends_with(suf) && f.len() > suf.len() {
            return Some([&f[..f.len() - suf.len()], rep].concat());
        }
    }
    None
}

/// `-l`'s line; the ratio leaves out the format's `overhead` (as gzip's
/// does).
fn list_line(compressed: u64, plain: u64, overhead: u64, name: &str) {
    let data = compressed as f64 - overhead as f64;
    let ratio = if plain == 0 { 0.0 } else { (plain as f64 - data) * 100.0 / plain as f64 };
    io::out(format!("{compressed:>19} {plain:>19} {ratio:>5.1}% {name}\n").as_bytes());
}

/// `-l`'s sums (the overhead is the last file's, as gzip shows it; xz
/// counts streams and blocks and names the checks seen).
#[derive(Debug, Default)]
struct Totals {
    packed: u64,
    plain: u64,
    overhead: u64,
    files: usize,
    streams: u32,
    blocks: u32,
    checks: Vec<&'static str>,
}

/// Something to tell the user, in each program's words.
#[derive(Debug)]
enum Event<'a> {
    IsDirectory(&'a [u8]),
    NotRegular(&'a [u8]),
    CantOpen(&'a [u8], Errno),
    UnknownSuffix(&'a [u8]),
    HasSuffix(&'a [u8], &'a [u8]),
    Exists(&'a [u8]),
    Failed(&'a str, &'a [u8], Failure),
}

/// Say `e` as `fmt`'s program does; the status it gives (1 error, 2
/// warning).
fn say(fmt: Format, o: &Opts, e: Event<'_>) -> i32 {
    let tool = fmt.prefix();
    let quiet_warning = |o: &Opts| o.quiet;
    let (msg, status): (String, i32) = match (fmt, e) {
        (Format::Gzip, Event::IsDirectory(f)) => (format!("{} is a directory -- ignored", lossy(f)), 2),
        (Format::Zstd, Event::IsDirectory(f)) => (format!("{} is a directory -- ignored ", lossy(f)), 1),
        (Format::Zstd, Event::NotRegular(f)) => (format!("{} is not a regular file -- ignored ", lossy(f)), 1),
        (Format::Zstd, Event::CantOpen(f, err)) => (format!("can't stat {} : {err} -- ignored ", lossy(f)), 1),
        (Format::Zstd, Event::UnknownSuffix(f)) => (
            format!(
                "{}: unknown suffix (.zst/.tzst expected). Can't derive the output file name. Specify it with -o dstFileName. Ignoring.",
                lossy(f)
            ),
            1,
        ),
        (Format::Zstd, Event::HasSuffix(..)) => (String::new(), 0),
        (Format::Zstd, Event::Exists(t)) => (format!("{} already exists; not overwritten  ", lossy(t)), 1),
        (Format::Zstd, Event::Failed(n, _, f)) => match f {
            Failure::NotFormat => (format!("{n}: unsupported format "), 1),
            Failure::Truncated => (format!("{n} : Read error (39) : premature end "), 1),
            Failure::Unsupported => {
                (format!("{n} : Decoding error (36) : Frame requires too much memory for decoding "), 1)
            }
            Failure::Corrupt("checksum") => {
                (format!("{n} : Decoding error (36) : Restored data doesn't match checksum "), 1)
            }
            _ => (format!("{n} : Decoding error (36) : Data corruption detected "), 1),
        },
        (Format::Xz | Format::Lzma, Event::IsDirectory(f)) => (format!("{}: Is a directory, skipping", lossy(f)), 2),
        (Format::Xz | Format::Lzma, Event::NotRegular(f)) => (format!("{}: Not a regular file, skipping", lossy(f)), 2),
        (Format::Xz | Format::Lzma, Event::CantOpen(f, err)) => (format!("{}: {err}", lossy(f)), 1),
        (Format::Xz | Format::Lzma, Event::UnknownSuffix(f)) => {
            (format!("{}: Filename has an unknown suffix, skipping", lossy(f)), 2)
        }
        (Format::Xz | Format::Lzma, Event::HasSuffix(f, s)) => {
            (format!("{}: File already has '{}' suffix, skipping", lossy(f), lossy(s)), 2)
        }
        (Format::Xz | Format::Lzma, Event::Exists(t)) => (format!("{}: File exists", lossy(t)), 1),
        (Format::Xz | Format::Lzma, Event::Failed(n, _, f)) => match f {
            Failure::NotFormat => (format!("{n}: File format not recognized"), 1),
            Failure::Unsupported => (format!("{n}: Unsupported filter chain or filter options"), 1),
            Failure::Truncated => (format!("{n}: Unexpected end of input"), 1),
            _ => (format!("{n}: Compressed data is corrupt"), 1),
        },
        (Format::Bzip2, Event::IsDirectory(f)) => (format!("Input file {} is a directory.", lossy(f)), 1),
        (Format::Gzip, Event::NotRegular(f)) => {
            (format!("{} is not a directory or a regular file - ignored", lossy(f)), 2)
        }
        (Format::Bzip2, Event::NotRegular(f)) => (format!("Input file {} is not a normal file.", lossy(f)), 1),
        (Format::Gzip, Event::CantOpen(f, err)) => (format!("{}: {err}", lossy(f)), 1),
        (Format::Bzip2, Event::CantOpen(f, err)) => (format!("Can't open input file {}: {err}.", lossy(f)), 1),
        (Format::Gzip, Event::UnknownSuffix(f)) => (format!("{}: unknown suffix -- ignored", lossy(f)), 2),
        (Format::Bzip2, Event::UnknownSuffix(f)) => {
            let f = lossy(f);
            (format!("Can't guess original name for {f} -- using {f}.out"), 0)
        }
        (Format::Gzip, Event::HasSuffix(f, s)) => {
            (format!("{} already has {} suffix -- unchanged", lossy(f), lossy(s)), 2)
        }
        (Format::Bzip2, Event::HasSuffix(f, s)) => {
            (format!("Input file {} already has {} suffix.", lossy(f), lossy(s)), 1)
        }
        (Format::Gzip, Event::Exists(t)) => (format!("{} already exists; not overwritten", lossy(t)), 2),
        (Format::Bzip2, Event::Exists(t)) => (format!("Output file {} already exists.", lossy(t)), 1),
        (_, Event::Failed(_, f, Failure::Read(err))) => (format!("{}: {err}", lossy(f)), 1),
        (_, Event::Failed(_, _, Failure::Write(err))) => (format!("{err}"), 1),
        (Format::Gzip, Event::Failed(n, _, f)) => match f {
            Failure::NotFormat => (format!("{n}: not in gzip format"), 1),
            Failure::Corrupt(why) => (format!("{n}: invalid compressed data--{why}"), 1),
            _ => (format!("{n}: unexpected end of file"), 1),
        },
        (Format::Bzip2, Event::Failed(n, _, f)) => match f {
            Failure::NotFormat if o.test => (
                format!(
                    "{n}: bad magic number (file not created by bzip2)\n\nYou can use the `bzip2recover' program to attempt to recover\ndata from undamaged sections of corrupted files.\n"
                ),
                2,
            ),
            Failure::NotFormat => (format!("{n} is not a bzip2 file."), 2),
            Failure::Corrupt(_) => (format!("{n}: data integrity (CRC) error in data"), 2),
            _ => (format!("{n}: file ends unexpectedly"), 2),
        },
    };
    if (status != 1 && quiet_warning(o)) || msg.is_empty() {
        return status;
    }
    io::flush_stdout();
    io::err(format!("{tool}: {msg}\n").as_bytes());
    status
}

/// Compress, decompress, test or list one operand; its status.
fn one(fmt: Format, f: &[u8], o: &Opts, totals: &mut Totals) -> i32 {
    let is_stdin = f == b"-";
    if !is_stdin {
        match fs::stat(f) {
            Ok(s) if s.mode & 0o170000 == 0o040000 => {
                if !o.recursive {
                    return say(fmt, o, Event::IsDirectory(f));
                }
                let mut kids: Vec<Vec<u8>> = fs::read_dir(f).unwrap_or_default().into_iter().map(|d| d.name).collect();
                kids.sort();
                let mut st = 0;
                for k in kids.iter().filter(|k| *k != b"." && *k != b"..") {
                    st = st.max(one(fmt, &fs::join(f, k), o, totals));
                }
                return st;
            }
            Ok(s) if s.mode & 0o170000 != 0o100000 && !o.stdout && !o.test && !o.list && !o.force => {
                return say(fmt, o, Event::NotRegular(f));
            }
            Ok(_) => {}
            Err(e) => return say(fmt, o, Event::CantOpen(f, e)),
        }
    }
    let to_stdout = o.stdout || is_stdin;
    // Where the result goes.
    let target: Option<Vec<u8>> = if o.test || o.list {
        None
    } else if let Some(out) = &o.output {
        (out != b"-").then(|| out.clone())
    } else if to_stdout {
        None
    } else if o.decompress {
        match plain_name(fmt, f, o) {
            Some(t) => Some(t),
            None if fmt == Format::Bzip2 => {
                say(fmt, o, Event::UnknownSuffix(f));
                Some([f, b".out"].concat())
            }
            // xz looks at what the file holds before at its name.
            None if matches!(fmt, Format::Xz | Format::Lzma) && !holds(f, fmt) => {
                return say(fmt, o, Event::Failed(&lossy(f), f, Failure::NotFormat));
            }
            None => return say(fmt, o, Event::UnknownSuffix(f)),
        }
    } else {
        let suf = o.suffix.clone().unwrap_or_else(|| fmt.suffixes().0.to_vec());
        // zstd compresses what it is given whatever its name.
        if fmt != Format::Zstd && (plain_name(fmt, f, o).is_some() || f.ends_with(&suf)) {
            let shown =
                fmt.suffixes().1.iter().find(|s| f.to_ascii_lowercase().ends_with(s.0)).map_or(&suf[..], |s| s.0);
            return say(fmt, o, Event::HasSuffix(f, shown));
        }
        Some([f, suf.as_slice()].concat())
    };
    let in_fd = if is_stdin {
        io::STDIN
    } else {
        match fs::open(f, fs::O_RDONLY | fs::O_CLOEXEC, 0) {
            Ok(fd) => fd,
            Err(e) => return say(fmt, o, Event::CantOpen(f, e)),
        }
    };
    let st = if is_stdin { fs::fstat(io::STDIN).ok() } else { fs::stat(f).ok() };
    // The output: a new file made exclusively, replacing one only with -f.
    let out_fd = match &target {
        None if o.test || o.list => None,
        None => Some(io::STDOUT),
        Some(t) => {
            if fs::lstat(t).is_ok() {
                if !o.force {
                    close(in_fd, is_stdin);
                    return say(fmt, o, Event::Exists(t));
                }
                let _ = fs::unlink(t);
            }
            match fs::open(t, fs::O_WRONLY | fs::O_CREAT | fs::O_EXCL | fs::O_CLOEXEC, 0o600) {
                Ok(fd) => Some(fd),
                Err(e) => {
                    error_path(t, e);
                    close(in_fd, is_stdin);
                    return 1;
                }
            }
        }
    };
    let mut input = FdIn::new(in_fd);
    let mut out = FdOut::new(out_fd);
    let save_name = o.name.unwrap_or(!o.decompress) && !is_stdin;
    let r = if o.decompress {
        decompress(fmt, &mut input, &mut out).map(Some)
    } else {
        let mtime = st.as_ref().map_or(0, |s| s.mtime as u32);
        compress(fmt, &mut input, &mut out, o.set, save_name.then(|| (fs::basename(f), mtime))).map(|()| None)
    };
    close(in_fd, is_stdin);
    if let Some(fd) = out_fd
        && target.is_some()
    {
        let _ = io::close(fd);
    }
    let name_shown = if is_stdin { String::from(fmt.stdin_name()) } else { String::from(lossy(f)) };
    let found = match r {
        Ok(found) => found,
        Err(e) => {
            if let Some(t) = &target {
                let _ = fs::unlink(t);
            }
            if o.test && fmt == Format::Gzip {
                eprintln!("");
            }
            return say(fmt, o, Event::Failed(&name_shown, f, e));
        }
    };
    let (packed, plain) = if o.decompress { (input.count, out.count) } else { (out.count, input.count) };
    if o.list && fmt == Format::Zstd {
        if totals.files == 0 {
            io::out(b"Frames  Skips  Compressed  Uncompressed  Ratio  Check  Filename\n");
        }
        let fd = found.unwrap_or_default();
        let check = if fd.check.is_some() { "XXH64" } else { "None" };
        zstd_list_line(fd.streams, packed, plain, check, &name_shown);
        totals.packed += packed;
        totals.plain += plain;
        totals.streams += fd.streams;
        if !totals.checks.contains(&check) {
            totals.checks.push(check);
        }
        totals.files += 1;
        return 0;
    }
    if o.list && matches!(fmt, Format::Xz | Format::Lzma) {
        if totals.files == 0 {
            io::out(b"Strms  Blocks   Compressed Uncompressed  Ratio  Check   Filename\n");
        }
        let fd = found.unwrap_or_default();
        let check = fd.check.map_or("None", |c| c.name());
        xz_list_line(fd.streams, fd.blocks, packed, plain, check, &name_shown);
        totals.packed += packed;
        totals.plain += plain;
        totals.streams += fd.streams;
        totals.blocks += fd.blocks;
        if !totals.checks.contains(&check) {
            totals.checks.push(check);
        }
        totals.files += 1;
        return 0;
    }
    if o.list {
        if totals.files == 0 {
            io::out(b"         compressed        uncompressed  ratio uncompressed_name\n");
        }
        let shown = if is_stdin {
            String::from("stdout")
        } else {
            String::from(lossy(&plain_name(fmt, f, o).unwrap_or_else(|| f.to_vec())))
        };
        let overhead = found.as_ref().map_or(0, |f| f.overhead);
        list_line(packed, plain, overhead, &shown);
        totals.packed += packed;
        totals.plain += plain;
        totals.overhead = overhead;
        totals.files += 1;
        return 0;
    }
    if o.test && fmt == Format::Zstd {
        if !o.quiet {
            eprintln!("{name_shown:<20}: {plain} bytes ");
        }
        return 0;
    }
    if o.test {
        if o.verbose {
            match fmt {
                Format::Gzip => eprintln!("{name_shown}:\t OK"),
                Format::Bzip2 => eprintln!("  {name_shown}: ok"),
                Format::Xz | Format::Lzma => {
                    eprintln!("{name_shown}: {} / {}", xz_size(packed), xz_size(plain));
                }
                Format::Zstd => eprintln!("{name_shown:<20}: {plain} bytes "),
            }
        }
        return 0;
    }
    // zstd says what it made (unless -q).
    if fmt == Format::Zstd
        && !o.quiet
        && let Some(t) = &target
    {
        if o.decompress {
            eprintln!("{name_shown:<20}: {plain} bytes ");
        } else {
            let pct = if plain == 0 { 0.0 } else { packed as f64 * 100.0 / plain as f64 };
            eprintln!(
                "{name_shown:<20} :{pct:6.2}%   ({} => {}, {}) ",
                zstd_size(plain, 6),
                zstd_size(packed, 6),
                lossy(t)
            );
        }
    }
    let Some(t) = target else { return 0 };
    // The new file takes the old one's mode, owner and times (with -N a
    // decompressed one its saved time).
    if let Some(s) = &st {
        let _ = fs::chmod(&t, s.mode & 0o7777);
        if process::geteuid() == 0 {
            let _ = fs::chown(&t, s.uid, s.gid);
        }
        let mtime = match found.as_ref().and_then(|f| f.mtime) {
            Some(m) if o.name == Some(true) => (m, 0),
            _ => (s.mtime, s.mtime_nsec),
        };
        let _ = fs::set_times(&t, Some(Some((s.atime, s.atime_nsec))), Some(Some(mtime)), true);
    }
    if !o.keep
        && let Err(e) = fs::unlink(f)
    {
        error_path(f, e);
        return 1;
    }
    if o.verbose {
        let ratio = if plain == 0 { 0.0 } else { (plain as f64 - packed as f64) * 100.0 / plain as f64 };
        match fmt {
            Format::Gzip => {
                let what = if o.keep { "created" } else { "replaced with" };
                eprintln!("{}:\t{ratio:5.1}% -- {what} {}", lossy(f), lossy(&t));
            }
            Format::Bzip2 if o.decompress => eprintln!("  {}: done", lossy(f)),
            Format::Bzip2 => {
                let cr = if packed == 0 { 0.0 } else { plain as f64 / packed as f64 };
                let bpb = if plain == 0 { 0.0 } else { packed as f64 * 8.0 / plain as f64 };
                eprintln!(
                    "  {}: {cr:6.3}:1, {bpb:6.3} bits/byte, {ratio:5.2}% saved, {plain} in, {packed} out.",
                    lossy(f)
                );
            }
            Format::Zstd => {}
            Format::Xz | Format::Lzma => {
                let r = if plain == 0 || packed as f64 / plain as f64 > 9.999 {
                    String::from("> 9.999")
                } else {
                    format!("= {:.3}", packed as f64 / plain as f64)
                };
                eprintln!("{}: {} / {} {r}", lossy(f), xz_size(packed), xz_size(plain));
            }
        }
    }
    0
}

/// Whether file `f` starts as `fmt`'s files do (xz: either of its two).
fn holds(f: &[u8], fmt: Format) -> bool {
    let Ok(fd) = fs::open(f, fs::O_RDONLY | fs::O_CLOEXEC, 0) else { return false };
    let mut head = [0u8; 13];
    let n = io::read(fd, &mut head).unwrap_or(0);
    let _ = io::close(fd);
    match Format::sniff(&head[..n]) {
        Some(Format::Xz) => fmt == Format::Xz,
        Some(Format::Lzma) => true,
        _ => false,
    }
}

fn close(fd: i32, stdin: bool) {
    if !stdin {
        let _ = io::close(fd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> Opts {
        Opts {
            decompress: true,
            stdout: false,
            keep: false,
            force: false,
            test: false,
            list: false,
            recursive: false,
            verbose: false,
            quiet: false,
            name: None,
            set: Settings::new(Format::Gzip),
            suffix: None,
            output: None,
        }
    }

    #[test]
    fn suffixes() {
        let o = opts();
        assert_eq!(plain_name(Format::Gzip, b"a.gz", &o).as_deref(), Some(&b"a"[..]));
        assert_eq!(plain_name(Format::Gzip, b"a.tgz", &o).as_deref(), Some(&b"a.tar"[..]));
        assert_eq!(plain_name(Format::Gzip, b"A.GZ", &o).as_deref(), Some(&b"A"[..]));
        assert_eq!(plain_name(Format::Gzip, b"a.txt", &o), None);
        assert_eq!(plain_name(Format::Bzip2, b"a.tbz2", &o).as_deref(), Some(&b"a.tar"[..]));
        let s = Opts { suffix: Some(b".zz".to_vec()), ..opts() };
        assert_eq!(plain_name(Format::Gzip, b"a.zz", &s).as_deref(), Some(&b"a"[..]));
        assert_eq!(Format::sniff(&[0x1F, 0x8B, 8]), Some(Format::Gzip));
        assert_eq!(Format::sniff(b"BZh9"), Some(Format::Bzip2));
    }
}
