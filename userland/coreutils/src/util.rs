// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared pieces: GNU-style option parsing, messages, input files.

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{Errno, eprintln, fs, io, lossy};

/// One parsed command-line item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Opt {
    Short(u8),
    Long(String),
    Operand(Vec<u8>),
}

/// Options and operands in GNU style: options may follow operands (until
/// `--`), short options bundle (`-la`), long options take `--x=v` or a
/// following argument.
#[derive(Debug)]
pub struct Parser<'a> {
    args: &'a [Vec<u8>],
    i: usize,
    /// Inside a bundle of short options: the rest of it.
    bundle: Vec<u8>,
    long_value: Option<Vec<u8>>,
    done: bool,
    /// Accept `-NUM` as a numeric option (head, tail).
    pub numeric: bool,
}

impl<'a> Parser<'a> {
    /// `_takes` lists the short options that take a value (for readers:
    /// callers fetch values with [`Parser::value`]).
    pub fn new(args: &'a [Vec<u8>], _takes: &'a [u8]) -> Parser<'a> {
        Parser { args, i: 1, bundle: Vec::new(), long_value: None, done: false, numeric: false }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Opt> {
        if !self.bundle.is_empty() {
            let c = self.bundle.remove(0);
            return Some(Opt::Short(c));
        }
        let a = self.args.get(self.i)?;
        self.i += 1;
        if self.done || a.len() < 2 || a[0] != b'-' {
            return Some(Opt::Operand(a.clone()));
        }
        if a == b"--" {
            self.done = true;
            return self.next();
        }
        if let Some(long) = a.strip_prefix(b"--") {
            return Some(match long.iter().position(|&c| c == b'=') {
                Some(eq) => {
                    self.long_value = Some(long[eq + 1..].to_vec());
                    Opt::Long(String::from_utf8_lossy(&long[..eq]).into_owned())
                }
                None => {
                    self.long_value = None;
                    Opt::Long(String::from_utf8_lossy(long).into_owned())
                }
            });
        }
        if self.numeric && a[1].is_ascii_digit() {
            return Some(Opt::Long(String::from_utf8_lossy(&a[1..]).into_owned()));
        }
        self.bundle = a[2..].to_vec();
        Some(Opt::Short(a[1]))
    }

    /// The value of the option just returned: the rest of a short-option
    /// bundle, `--x=value`, or the next argument.
    pub fn value(&mut self) -> Option<Vec<u8>> {
        if let Some(v) = self.long_value.take() {
            return Some(v);
        }
        if !self.bundle.is_empty() {
            return Some(core::mem::take(&mut self.bundle));
        }
        let v = self.args.get(self.i)?.clone();
        self.i += 1;
        Some(v)
    }

    /// The rest of the current short-option bundle, possibly empty
    /// (`-i.bak`: an optional attached value).
    pub fn inline_bundle(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.bundle)
    }

    /// The next short option of the current bundle, not yet taken.
    pub fn peek_short(&self) -> Option<u8> {
        self.bundle.first().copied()
    }

    /// The `=value` of the long option just returned, if it had one.
    pub fn inline_value(&mut self) -> Option<Vec<u8>> {
        self.long_value.take()
    }
}

/// Whether the locale's characters are UTF-8 (the first of LC_ALL,
/// LC_CTYPE and LANG that is set names a UTF-8 codeset): regular
/// expressions then match characters, not bytes.
pub fn utf8_locale() -> bool {
    [b"LC_ALL".as_slice(), b"LC_CTYPE", b"LANG"]
        .iter()
        .find_map(|n| slate_rt::env::var(n).filter(|v| !v.is_empty()))
        .is_some_and(|v| {
            let v = v.to_ascii_lowercase();
            v.windows(5).any(|w| w == b"utf-8") || v.windows(4).any(|w| w == b"utf8")
        })
}

/// A name as awk and the shells spell variables.
pub fn is_name(s: &[u8]) -> bool {
    !s.is_empty() && !s[0].is_ascii_digit() && s.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

/// `prog: message` on standard error.
pub fn error(msg: impl core::fmt::Display) {
    eprintln!("{}: {}", slate_rt::prog_name(), msg);
}

/// `prog: 'path': strerror` on standard error.
pub fn error_path(path: &[u8], e: Errno) {
    error(format_args!("{}: {}", lossy(path), e));
}

pub fn bad_option(o: &Opt) -> i32 {
    match o {
        Opt::Short(c) => error(format_args!("invalid option -- '{}'", *c as char)),
        Opt::Long(l) => error(format_args!("unrecognized option '--{l}'")),
        Opt::Operand(_) => error("extra operand"),
    }
    eprintln!("Try '{} --help' for more information.", slate_rt::prog_name());
    2
}

pub fn missing_value(c: impl core::fmt::Display) -> i32 {
    error(format_args!("option requires an argument -- '{c}'"));
    2
}

/// Open an input operand: `-` is standard input.
pub fn open_input(path: &[u8]) -> Result<i32, Errno> {
    if path == b"-" {
        return Ok(io::STDIN);
    }
    fs::open(path, fs::O_RDONLY | fs::O_CLOEXEC, 0)
}

pub fn close_input(fd: i32) {
    if fd != io::STDIN {
        let _ = io::close(fd);
    }
}

/// Read a whole input operand.
pub fn read_input(path: &[u8]) -> Result<Vec<u8>, Errno> {
    let fd = open_input(path)?;
    let r = io::read_to_end(fd);
    close_input(fd);
    r
}

/// Feed an input operand to `f` in chunks, without holding all of it;
/// `f` returns false to stop early (head).
pub fn stream_chunks(path: &[u8], mut f: impl FnMut(&[u8]) -> bool) -> Result<(), Errno> {
    let fd = open_input(path)?;
    let mut buf = alloc::vec![0u8; 64 * 1024];
    let r = loop {
        match io::read(fd, &mut buf) {
            Ok(0) => break Ok(()),
            Ok(n) => {
                if !f(&buf[..n]) {
                    break Ok(());
                }
            }
            Err(e) => break Err(e),
        }
    };
    close_input(fd);
    r
}

/// Feed an input operand to `f` one record at a time (the record without
/// its `delim`, and whether it had one); `f` returns false to stop.
pub fn stream_lines(path: &[u8], delim: u8, mut f: impl FnMut(&[u8], bool) -> bool) -> Result<(), Errno> {
    let fd = open_input(path)?;
    let mut r = io::Reader::new(fd);
    let res = loop {
        match r.split(delim) {
            Ok(Some(l)) => {
                let had = l.last() == Some(&delim);
                let body = if had { &l[..l.len() - 1] } else { &l[..] };
                if !f(body, had) {
                    break Ok(());
                }
            }
            Ok(None) => break Ok(()),
            Err(e) => break Err(e),
        }
    };
    close_input(fd);
    res
}

pub fn parse_num<T: core::str::FromStr>(b: &[u8]) -> Option<T> {
    core::str::from_utf8(b).ok()?.trim().parse().ok()
}

/// Split `data` into lines on `delim`, without the delimiters; a final
/// unterminated line counts.
pub fn lines(data: &[u8], delim: u8) -> Vec<&[u8]> {
    let mut v: Vec<&[u8]> = data.split(|&c| c == delim).collect();
    if data.last() == Some(&delim) || data.is_empty() {
        v.pop();
    }
    v
}

/// Escape processing for echo -e and printf (backslash sequences).
/// Returns the bytes and whether `\c` ended output.
pub fn unescape(s: &[u8], printf_octal: bool) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if s[i] != b'\\' || i + 1 >= s.len() {
            out.push(s[i]);
            i += 1;
            continue;
        }
        i += 1;
        let c = s[i];
        i += 1;
        match c {
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'r' => out.push(b'\r'),
            b'a' => out.push(7),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'v' => out.push(11),
            b'e' | b'E' => out.push(27),
            b'\\' => out.push(b'\\'),
            b'c' => return (out, true),
            b'0'..=b'7' => {
                // echo: \0NNN; printf: \NNN.
                let mut v: u32 = 0;
                let mut n = 0;
                let (start, max) = if c == b'0' && !printf_octal { (i, 3) } else { (i - 1, 3) };
                i = start;
                while n < max && i < s.len() && (b'0'..=b'7').contains(&s[i]) {
                    v = v * 8 + u32::from(s[i] - b'0');
                    i += 1;
                    n += 1;
                }
                out.push(v as u8);
            }
            b'x' => {
                let mut v: u32 = 0;
                let mut n = 0;
                while n < 2 && i < s.len() && s[i].is_ascii_hexdigit() {
                    v = v * 16 + (s[i] as char).to_digit(16).unwrap();
                    i += 1;
                    n += 1;
                }
                if n == 0 {
                    out.extend_from_slice(b"\\x");
                } else {
                    out.push(v as u8);
                }
            }
            other => {
                out.push(b'\\');
                out.push(other);
            }
        }
    }
    (out, false)
}

/// Format a byte count as GNU's `-h`: 1023, 1.0K, 9.9M, 10M ...
pub fn human(n: u64) -> String {
    const UNITS: [char; 7] = ['K', 'M', 'G', 'T', 'P', 'E', 'Z'];
    if n < 1024 {
        return alloc::format!("{n}");
    }
    let mut v = n as f64;
    let mut u = 0;
    v /= 1024.0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    // GNU rounds up.
    if v < 10.0 {
        let t = ceil(v * 10.0) / 10.0;
        if t >= 10.0 { alloc::format!("{}{}", ceil(t) as u64, UNITS[u]) } else { alloc::format!("{t:.1}{}", UNITS[u]) }
    } else {
        alloc::format!("{}{}", ceil(v) as u64, UNITS[u])
    }
}

pub fn ceil(x: f64) -> f64 {
    let t = x as i64 as f64;
    if t < x { t + 1.0 } else { t }
}
