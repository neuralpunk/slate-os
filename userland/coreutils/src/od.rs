// SPDX-License-Identifier: MIT OR Apache-2.0

//! od: dump files in octal, hexadecimal, decimal, characters or floating
//! point (POSIX od, with GNU's options). The layout follows what GNU's od
//! prints: every output type of a line gets the same width, the extra
//! columns going to the leading items of each group.

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{io, lossy};

use crate::util::{Opt, Parser, bad_option, close_input, error, error_path, missing_value, open_input};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// Named characters (`-t a`).
    Named,
    /// Characters with C escapes (`-t c`).
    Char,
    Signed,
    Unsigned,
    Octal,
    Hex,
    Float,
}

#[derive(Clone, Copy, Debug)]
struct Spec {
    kind: Kind,
    size: usize,
    /// Printable characters after the line (`z` suffix).
    z: bool,
}

impl Spec {
    /// Digits of the widest value.
    fn width(&self) -> usize {
        match (self.kind, self.size) {
            (Kind::Named | Kind::Char, _) => 3,
            (Kind::Octal, n) => (n * 8).div_ceil(3),
            (Kind::Hex, n) => n * 2,
            (Kind::Unsigned, 1) => 3,
            (Kind::Unsigned, 2) => 5,
            (Kind::Unsigned, 4) => 10,
            (Kind::Unsigned, _) => 20,
            (Kind::Signed, 1) => 4,
            (Kind::Signed, 2) => 6,
            (Kind::Signed, 4) => 11,
            (Kind::Signed, _) => 20,
            (Kind::Float, 4) => 15,
            (Kind::Float, 8) => 24,
            (Kind::Float, _) => 29,
        }
    }
}

/// Parse a `-t` type string (`x1`, `d4`, `oS`, `f8`, `cz`, ...) into specs.
fn parse_types(s: &[u8], out: &mut Vec<Spec>) -> Result<(), String> {
    let mut i = 0;
    while i < s.len() {
        let kind = match s[i] {
            b'a' => Kind::Named,
            b'c' => Kind::Char,
            b'd' => Kind::Signed,
            b'u' => Kind::Unsigned,
            b'o' => Kind::Octal,
            b'x' => Kind::Hex,
            b'f' => Kind::Float,
            _ => return Err(alloc::format!("invalid character '{}' in type string '{}'", s[i] as char, lossy(s))),
        };
        i += 1;
        let mut size = match kind {
            Kind::Named | Kind::Char => 1,
            Kind::Float => 8,
            _ => 4,
        };
        if matches!(kind, Kind::Signed | Kind::Unsigned | Kind::Octal | Kind::Hex | Kind::Float) && i < s.len() {
            let c = s[i];
            let letter = match (kind, c) {
                (Kind::Float, b'F') => Some(4),
                (Kind::Float, b'D') => Some(8),
                (Kind::Float, b'L') => Some(16),
                (Kind::Float, _) => None,
                (_, b'C') => Some(1),
                (_, b'S') => Some(2),
                (_, b'I') => Some(4),
                (_, b'L') => Some(8),
                _ => None,
            };
            if let Some(n) = letter {
                size = n;
                i += 1;
            } else if c.is_ascii_digit() {
                let start = i;
                while i < s.len() && s[i].is_ascii_digit() {
                    i += 1;
                }
                size = core::str::from_utf8(&s[start..i]).ok().and_then(|t| t.parse().ok()).unwrap_or(0);
            }
        }
        let ok = match kind {
            Kind::Float => matches!(size, 4 | 8 | 16),
            Kind::Named | Kind::Char => true,
            _ => matches!(size, 1 | 2 | 4 | 8),
        };
        if !ok {
            let what = if kind == Kind::Float { "floating point" } else { "integral" };
            return Err(alloc::format!(
                "invalid type string '{}';\nthis system doesn't provide a {size}-byte {what} type",
                lossy(s)
            ));
        }
        let z = s.get(i) == Some(&b'z');
        if z {
            i += 1;
        }
        out.push(Spec { kind, size, z });
    }
    Ok(())
}

/// A byte count: decimal, 0x hexadecimal or leading-0 octal, with GNU's
/// multiplier suffixes.
pub fn parse_size(s: &[u8]) -> Option<u64> {
    let s = core::str::from_utf8(s).ok()?;
    let (digits, radix) = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        (h, 16)
    } else if s.len() > 1 && s.starts_with('0') && s.as_bytes()[1].is_ascii_digit() {
        (&s[1..], 8)
    } else {
        (s, 10)
    };
    let end = digits.find(|c: char| !c.is_digit(radix)).unwrap_or(digits.len());
    if end == 0 {
        return None;
    }
    let n = u64::from_str_radix(&digits[..end], radix).ok()?;
    let mult: u64 = match &digits[end..] {
        "" => 1,
        "b" => 512,
        "kB" => 1000,
        "K" | "KiB" | "k" => 1024,
        "MB" => 1000 * 1000,
        "M" | "MiB" => 1 << 20,
        "GB" => 1000 * 1000 * 1000,
        "G" | "GiB" => 1 << 30,
        "TB" => 1_000_000_000_000,
        "T" | "TiB" => 1 << 40,
        _ => return None,
    };
    n.checked_mul(mult)
}

const NAMES: [&str; 33] = [
    "nul", "soh", "stx", "etx", "eot", "enq", "ack", "bel", "bs", "ht", "nl", "vt", "ff", "cr", "so", "si", "dle",
    "dc1", "dc2", "dc3", "dc4", "nak", "syn", "etb", "can", "em", "sub", "esc", "fs", "gs", "rs", "us", "sp",
];

/// A float as GNU's od prints it: the shortest digits that read back as
/// the same value, laid out as `%g` would with `p` digits of precision.
/// `e` is the value's shortest `{:e}` form (of the f32 or the f64).
pub fn format_g(x: f64, e: &str, p: usize) -> String {
    if x.is_nan() {
        return String::from(if x.is_sign_negative() { "-nan" } else { "nan" });
    }
    if x.is_infinite() {
        return String::from(if x < 0.0 { "-inf" } else { "inf" });
    }
    if x == 0.0 {
        return String::from(if x.is_sign_negative() { "-0" } else { "0" });
    }
    let (mant, exp) = e.split_once('e').unwrap_or((e, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    if exp < -4 || exp >= p as i32 {
        let sign = if exp < 0 { '-' } else { '+' };
        return alloc::format!("{mant}e{sign}{:02}", exp.unsigned_abs());
    }
    // Fixed notation with the same digits.
    let neg = mant.starts_with('-');
    let digits: String = mant.chars().filter(char::is_ascii_digit).collect();
    let mut s = String::from(if neg { "-" } else { "" });
    if exp < 0 {
        s.push_str("0.");
        s.extend(core::iter::repeat_n('0', (-exp - 1) as usize));
        s.push_str(&digits);
    } else {
        let int = exp as usize + 1;
        if digits.len() <= int {
            s.push_str(&digits);
            s.extend(core::iter::repeat_n('0', int - digits.len()));
        } else {
            s.push_str(&digits[..int]);
            s.push('.');
            s.push_str(&digits[int..]);
        }
    }
    s
}

/// A little arbitrary-precision unsigned integer (32-bit limbs, least
/// significant first), for long doubles' exact decimal forms.
#[derive(Clone, PartialEq, Eq)]
struct Big(Vec<u32>);

impl Big {
    fn from(v: u64) -> Big {
        let mut b = Big(alloc::vec![v as u32, (v >> 32) as u32]);
        b.trim();
        b
    }

    fn trim(&mut self) {
        while self.0.last() == Some(&0) {
            self.0.pop();
        }
    }

    fn mul(&mut self, m: u32) {
        let mut carry = 0u64;
        for l in self.0.iter_mut() {
            let v = u64::from(*l) * u64::from(m) + carry;
            *l = v as u32;
            carry = v >> 32;
        }
        if carry > 0 {
            self.0.push(carry as u32);
        }
    }

    fn mul_pow(&mut self, base: u32, mut n: u32) {
        // The largest power of `base` that fits in a limb, as often as it goes.
        let (mut big, mut k) = (base, 1);
        while u64::from(big) * u64::from(base) <= u64::from(u32::MAX) {
            big *= base;
            k += 1;
        }
        while n >= k {
            self.mul(big);
            n -= k;
        }
        for _ in 0..n {
            self.mul(base);
        }
    }

    fn shl(&mut self, bits: u32) {
        let (words, rest) = ((bits / 32) as usize, bits % 32);
        if rest > 0 {
            self.mul(1 << rest);
        }
        self.0.splice(0..0, core::iter::repeat_n(0, words));
    }

    fn cmp(&self, o: &Big) -> core::cmp::Ordering {
        self.0.len().cmp(&o.0.len()).then_with(|| self.0.iter().rev().cmp(o.0.iter().rev()))
    }

    /// `self - o`, `self` not smaller.
    fn sub(&self, o: &Big) -> Big {
        let mut out = self.0.clone();
        let mut borrow = 0i64;
        for (i, l) in out.iter_mut().enumerate() {
            let v = i64::from(*l) - i64::from(*o.0.get(i).unwrap_or(&0)) - borrow;
            borrow = i64::from(v < 0);
            *l = (v + (borrow << 32)) as u32;
        }
        let mut b = Big(out);
        b.trim();
        b
    }

    fn decimal(&self) -> String {
        let mut v = self.0.clone();
        let mut parts = Vec::new();
        while !v.is_empty() {
            let mut rem = 0u64;
            for l in v.iter_mut().rev() {
                let cur = (rem << 32) | u64::from(*l);
                *l = (cur / 1_000_000_000) as u32;
                rem = cur % 1_000_000_000;
            }
            while v.last() == Some(&0) {
                v.pop();
            }
            parts.push(rem as u32);
        }
        let mut s = match parts.pop() {
            Some(top) => alloc::format!("{top}"),
            None => String::from("0"),
        };
        for p in parts.iter().rev() {
            s.push_str(&alloc::format!("{p:09}"));
        }
        s
    }
}

/// An x86 80-bit extended value (`long double`, the first 10 of its 16
/// bytes) as GNU's od prints it: the shortest of 18 or more significant
/// digits (1 or more below the smallest normal value) that reads back as
/// the same value, laid out as `%g`.
fn long_double(b: &[u8]) -> String {
    let mant = u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]));
    let se = u16::from_le_bytes([b[8], b[9]]);
    let neg = se & 0x8000 != 0;
    let exp = i32::from(se & 0x7fff);
    let sign = if neg { "-" } else { "" };
    if exp == 0x7fff {
        return if mant << 1 == 0 { alloc::format!("{sign}inf") } else { alloc::format!("{sign}nan") };
    }
    // Without its integer bit a normal exponent is invalid (an unnormal).
    if exp != 0 && mant >> 63 == 0 {
        return alloc::format!("{sign}nan");
    }
    if mant == 0 {
        return alloc::format!("{sign}0");
    }
    // The value is mant * 2^q.
    let q = if exp == 0 { 1 - 16383 - 63 } else { exp - 16383 - 63 };
    let (digits, point) = if q >= 0 {
        let mut n = Big::from(mant);
        n.shl(q as u32);
        let d = n.decimal();
        let len = d.len() as i32;
        (d, len)
    } else {
        let mut n = Big::from(mant);
        n.mul_pow(5, (-q) as u32);
        let d = n.decimal();
        let len = d.len() as i32;
        (d, len + q)
    };
    // Scientific exponent of the exact value.
    let e10 = point - 1;
    let start = if exp == 0 { 1 } else { 18 };
    let digits = digits.as_bytes();
    for p in start..=40usize {
        // Round the exact digits to p, half to even.
        let mut d: Vec<u8> = digits.iter().take(p).map(|c| c - b'0').collect();
        d.resize(p, 0);
        let rest = digits.get(p..).unwrap_or_default();
        let first = rest.first().map_or(0, |c| c - b'0');
        let beyond = rest.iter().skip(1).any(|&c| c != b'0');
        let up = first > 5 || (first == 5 && (beyond || d.last().is_some_and(|x| x % 2 == 1)));
        let mut e = e10;
        if up {
            let mut i = p;
            loop {
                if i == 0 {
                    d.insert(0, 1);
                    d.pop();
                    e += 1;
                    break;
                }
                i -= 1;
                if d[i] == 9 {
                    d[i] = 0;
                } else {
                    d[i] += 1;
                    break;
                }
            }
        }
        // Reads back if within half a unit (2^(q-1)) of the value, a tie
        // only when the mantissa is even (rounding to even).
        let k = e - (p as i32 - 1);
        let (a, bb) = (0.max(-k) as u32, 0.max(1 - q) as u32);
        let mut c = Big::from(0);
        for &x in &d {
            c.mul(10);
            c = add_small(c, u32::from(x));
        }
        c.mul_pow(10, (k + a as i32) as u32);
        c.shl(bb);
        let mut v = Big::from(mant);
        v.shl((q + bb as i32) as u32);
        v.mul_pow(10, a);
        let mut h = Big::from(1);
        h.shl((q - 1 + bb as i32) as u32);
        h.mul_pow(10, a);
        let diff = if c.cmp(&v).is_ge() { c.sub(&v) } else { v.sub(&c) };
        let fits = match diff.cmp(&h) {
            core::cmp::Ordering::Less => true,
            core::cmp::Ordering::Equal => mant % 2 == 0,
            core::cmp::Ordering::Greater => false,
        };
        if fits {
            while d.len() > 1 && d.last() == Some(&0) {
                d.pop();
            }
            let mut m = String::from(sign);
            m.push(char::from(b'0' + d[0]));
            if d.len() > 1 {
                m.push('.');
                m.extend(d[1..].iter().map(|x| char::from(b'0' + x)));
            }
            return format_g(if neg { -1.0 } else { 1.0 }, &alloc::format!("{m}e{e}"), p);
        }
    }
    alloc::format!("{sign}nan")
}

fn add_small(mut b: Big, x: u32) -> Big {
    let mut carry = u64::from(x);
    for l in b.0.iter_mut() {
        if carry == 0 {
            break;
        }
        let v = u64::from(*l) + carry;
        *l = v as u32;
        carry = v >> 32;
    }
    if carry > 0 {
        b.0.push(carry as u32);
    }
    b
}

fn item(spec: &Spec, b: &[u8], big_endian: bool) -> String {
    // --endian=big: each value's bytes the other way round.
    let mut own = [0u8; 16];
    let n = spec.size.min(16);
    own[..b.len().min(n)].copy_from_slice(&b[..b.len().min(n)]);
    if big_endian && spec.size > 1 {
        own[..spec.size.min(16)].reverse();
    }
    if spec.kind == Kind::Float && spec.size == 16 {
        return long_double(&own[..10]);
    }
    let b = &own[..];
    let n = spec.size.min(8);
    let mut buf = [0u8; 8];
    buf[..n].copy_from_slice(&b[..n]);
    let u = u64::from_le_bytes(buf);
    match spec.kind {
        Kind::Named => {
            let c = b[0] & 0x7f;
            match c {
                0..=32 => String::from(NAMES[usize::from(c)]),
                127 => String::from("del"),
                c => alloc::format!("{}", c as char),
            }
        }
        Kind::Char => match b[0] {
            0 => String::from("\\0"),
            7 => String::from("\\a"),
            8 => String::from("\\b"),
            b'\t' => String::from("\\t"),
            b'\n' => String::from("\\n"),
            11 => String::from("\\v"),
            12 => String::from("\\f"),
            b'\r' => String::from("\\r"),
            c @ 0x20..=0x7e => alloc::format!("{}", c as char),
            c => alloc::format!("{c:03o}"),
        },
        Kind::Unsigned => alloc::format!("{u}"),
        Kind::Signed => {
            let shift = 64 - 8 * n as u32;
            alloc::format!("{}", ((u << shift) as i64) >> shift)
        }
        Kind::Octal => alloc::format!("{u:0w$o}", w = spec.width()),
        Kind::Hex => alloc::format!("{u:0w$x}", w = spec.width()),
        Kind::Float => {
            if n == 4 {
                let f = f32::from_bits(u as u32);
                format_g(f64::from(f), &alloc::format!("{f:e}"), 8)
            } else {
                let f = f64::from_bits(u);
                format_g(f, &alloc::format!("{f:e}"), 17)
            }
        }
    }
}

fn lcm(a: usize, b: usize) -> usize {
    let (mut x, mut y) = (a, b);
    while y != 0 {
        (x, y) = (y, x % y);
    }
    a / x * b
}

struct Layout {
    specs: Vec<Spec>,
    big_endian: bool,
    /// `--traditional`'s label: shown in parentheses after each address,
    /// this far from it.
    label: Option<u64>,
    /// Bytes per output line.
    width: usize,
    /// Columns per group of `group` bytes.
    group: usize,
    block_cols: usize,
    radix: u8,
}

impl Layout {
    fn addr(&self, a: u64) -> String {
        let one = |a: u64| match self.radix {
            b'o' => alloc::format!("{a:07o}"),
            b'd' => alloc::format!("{a:07}"),
            b'x' => alloc::format!("{a:06x}"),
            _ => String::new(),
        };
        match self.label {
            Some(d) if self.radix != b'n' => alloc::format!("{} ({})", one(a), one(a.wrapping_add(d))),
            _ => one(a),
        }
    }

    fn line(&self, out: &mut Vec<u8>, a: u64, data: &[u8]) {
        let indent = self.addr(a).len();
        for (si, spec) in self.specs.iter().enumerate() {
            if si == 0 {
                out.extend_from_slice(self.addr(a).as_bytes());
            } else {
                out.resize(out.len() + indent, b' ');
            }
            let per_group = self.group / spec.size;
            let pad = self.block_cols - per_group * (spec.width() + 1);
            let mut cols = 0;
            for (k, chunk) in data.chunks(spec.size).enumerate() {
                // The group's spare columns spread evenly over its items,
                // as GNU's od lays them out.
                let j = k % per_group;
                let extra = (pad * (j + 1)).div_ceil(per_group) - (pad * j).div_ceil(per_group);
                let w = spec.width() + 1 + extra;
                let s = item(spec, chunk, self.big_endian);
                out.resize(out.len() + w.saturating_sub(s.len()), b' ');
                out.extend_from_slice(s.as_bytes());
                cols += w;
            }
            if spec.z {
                let full = self.width / self.group * self.block_cols;
                out.resize(out.len() + full - cols, b' ');
                out.extend_from_slice(b"  >");
                out.extend(data.iter().map(|&c| if (0x20..0x7f).contains(&c) { c } else { b'.' }));
                out.push(b'<');
            }
            out.push(b'\n');
        }
    }
}

/// `[+]OFFSET[.][b]`, as od's older form takes offsets and labels: octal,
/// decimal with a `.`, times 512 with `b` (hexadecimal is not one).
fn old_offset(s: &[u8]) -> Option<u64> {
    let s = s.strip_prefix(b"+").unwrap_or(s);
    let (s, times) = match s.strip_suffix(b"b") {
        Some(r) => (r, 512),
        None => (s, 1),
    };
    let (s, radix) = match s.strip_suffix(b".") {
        Some(r) => (r, 10),
        None => (s, 8),
    };
    if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    u64::from_str_radix(core::str::from_utf8(s).ok()?, radix).ok()?.checked_mul(times)
}

pub fn main(args: &[Vec<u8>]) -> i32 {
    let mut specs = Vec::new();
    let (mut big_endian, mut traditional) = (false, false);
    let (mut radix, mut skip, mut limit, mut width, mut verbose) = (b'o', 0u64, None::<u64>, None::<usize>, false);
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"AjNtw");
    let legacy = |c: u8| -> &'static [u8] {
        match c {
            b'b' => b"o1",
            b'c' => b"c",
            b'd' => b"u2",
            b'o' => b"o2",
            b's' => b"d2",
            b'x' => b"x2",
            b'i' => b"dI",
            b'l' => b"dL",
            b'f' => b"fF",
            _ => b"",
        }
    };
    while let Some(o) = p.next() {
        let (name, v) = match &o {
            Opt::Short(c @ (b'A' | b'j' | b'N' | b't')) => match p.value() {
                Some(v) => (*c, v),
                None => return missing_value(*c as char),
            },
            Opt::Short(b'w') => (b'w', p.inline_bundle()),
            Opt::Short(b'v') => {
                verbose = true;
                continue;
            }
            Opt::Short(c) if !legacy(*c).is_empty() => (b't', legacy(*c).to_vec()),
            Opt::Long(l) => {
                let c = match l.as_str() {
                    "address-radix" => b'A',
                    "skip-bytes" => b'j',
                    "read-bytes" => b'N',
                    "format" => b't',
                    "width" => b'w',
                    "output-duplicates" => {
                        verbose = true;
                        continue;
                    }
                    "traditional" => {
                        traditional = true;
                        continue;
                    }
                    "endian" => {
                        let v = p.inline_value().or_else(|| p.value()).unwrap_or_default();
                        match v.as_slice() {
                            b"big" => big_endian = true,
                            b"little" => big_endian = false,
                            _ => {
                                error(format_args!("invalid argument '{}' for '--endian'", lossy(&v)));
                                slate_rt::eprintln!("Valid arguments are:\n  - 'little'\n  - 'big'");
                                slate_rt::eprintln!("Try '{} --help' for more information.", slate_rt::prog_name());
                                return 1;
                            }
                        }
                        continue;
                    }
                    _ => return bad_option(&o),
                };
                let v = if c == b'w' {
                    p.inline_value().unwrap_or_default()
                } else {
                    match p.value() {
                        Some(v) => v,
                        None => return missing_value(l),
                    }
                };
                (c, v)
            }
            Opt::Operand(x) => {
                files.push(x.clone());
                continue;
            }
            o => return bad_option(o),
        };
        match name {
            b'A' => match v.as_slice() {
                [r @ (b'o' | b'd' | b'x' | b'n')] => radix = *r,
                _ => {
                    error(format_args!(
                        "invalid output address radix '{}'; it must be one character from [doxn]",
                        lossy(&v)
                    ));
                    return 1;
                }
            },
            b'j' | b'N' => match parse_size(&v) {
                Some(n) if name == b'j' => skip = n,
                Some(n) => limit = Some(n),
                None => {
                    error(format_args!("invalid {} argument '{}'", if name == b'j' { "-j" } else { "-N" }, lossy(&v)));
                    return 1;
                }
            },
            b't' => {
                if let Err(e) = parse_types(&v, &mut specs) {
                    error(e);
                    return 1;
                }
            }
            _ => match if v.is_empty() { Some(32) } else { crate::util::parse_num::<usize>(&v) } {
                Some(n) if n > 0 => width = Some(n),
                _ => {
                    error(format_args!("invalid -w argument '{}'", lossy(&v)));
                    return 1;
                }
            },
        }
    }
    if specs.is_empty() {
        specs.push(Spec { kind: Kind::Octal, size: 2, z: false });
    }
    let group = specs.iter().fold(1, |g, s| lcm(g, s.size));
    let mut width = width.unwrap_or(16.max(group));
    if width % group != 0 {
        let fixed = (width - width % group).max(group);
        error(format_args!("warning: invalid width {width}; using {fixed} instead"));
        width = fixed;
    }
    let block_cols = specs.iter().map(|s| group / s.size * (s.width() + 1)).max().unwrap_or(0);
    // The older form: `od [FILE] [+]OFFSET`, and with --traditional
    // `od [FILE] [[+]OFFSET [[+]LABEL]]` (an offset is one when it reads
    // as one; without --traditional, one alone must start with `+`, a
    // second with `+` or a digit).
    let mut label = None;
    let offset_at = |i: usize, files: &[Vec<u8>]| files.get(i).and_then(|f| old_offset(f));
    let digit_or_plus = |f: &[u8]| matches!(f.first(), Some(b'+' | b'0'..=b'9'));
    let old: Option<(usize, u64, Option<u64>)> = match files.len() {
        1 if (traditional || files[0].starts_with(b"+")) && offset_at(0, &files).is_some() => {
            Some((0, offset_at(0, &files).unwrap_or(0), None))
        }
        2 if traditional && offset_at(0, &files).is_some() && offset_at(1, &files).is_some() => {
            Some((0, offset_at(0, &files).unwrap_or(0), offset_at(1, &files)))
        }
        2 if (traditional || digit_or_plus(&files[1])) && offset_at(1, &files).is_some() => {
            Some((1, offset_at(1, &files).unwrap_or(0), None))
        }
        3 if traditional && offset_at(1, &files).is_some() && offset_at(2, &files).is_some() => {
            Some((1, offset_at(1, &files).unwrap_or(0), offset_at(2, &files)))
        }
        _ => None,
    };
    if let Some((keep, offset, lab)) = old {
        files.truncate(keep);
        skip = offset;
        label = lab.map(|l| l.wrapping_sub(offset));
    }
    let layout = Layout { specs, big_endian, label, width, group, block_cols, radix };
    if files.is_empty() {
        files.push(b"-".to_vec());
    }

    // Read the inputs as one stream, skipping `skip` bytes and stopping
    // after `limit`.
    let mut status = 0;
    let mut read_any = false;
    let mut data: Vec<u8> = Vec::new();
    let mut to_skip = skip;
    let mut left = limit.unwrap_or(u64::MAX);
    let mut addr = skip;
    let mut prev: Option<Vec<u8>> = None;
    let mut starred = false;
    let mut out = Vec::new();
    let mut buf = alloc::vec![0u8; 64 * 1024];
    let emit = |data: &[u8], addr: u64, out: &mut Vec<u8>, prev: &mut Option<Vec<u8>>, starred: &mut bool| {
        if !verbose && data.len() == width && prev.as_deref() == Some(data) {
            if !*starred {
                out.extend_from_slice(b"*\n");
                *starred = true;
            }
        } else {
            layout.line(out, addr, data);
            *starred = false;
        }
        *prev = Some(data.to_vec());
        if out.len() > 32 * 1024 {
            io::out(out);
            out.clear();
        }
    };
    'files: for f in &files {
        let fd = match open_input(f) {
            Ok(fd) => fd,
            Err(e) => {
                // What came before goes out first.
                io::out(&out);
                out.clear();
                io::flush_stdout();
                error_path(f, e);
                status = 1;
                continue;
            }
        };
        loop {
            if left == 0 {
                close_input(fd);
                break 'files;
            }
            let n = match io::read(fd, &mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    error_path(f, e);
                    status = 1;
                    break;
                }
            };
            read_any = true;
            let mut chunk = &buf[..n];
            if to_skip > 0 {
                let s = (to_skip as usize).min(chunk.len());
                chunk = &chunk[s..];
                to_skip -= s as u64;
            }
            let take = (left as usize).min(chunk.len());
            left -= take as u64;
            data.extend_from_slice(&chunk[..take]);
            let full = data.len() / width * width;
            for line in data[..full].chunks(width) {
                emit(line, addr, &mut out, &mut prev, &mut starred);
                addr += width as u64;
            }
            data.drain(..full);
        }
        close_input(fd);
    }
    if to_skip > 0 {
        io::out(&out);
        error("cannot skip past end of combined input");
        io::flush_stdout();
        return 1;
    }
    if !data.is_empty() {
        layout.line(&mut out, addr, &data);
        addr += data.len() as u64;
    }
    if radix != b'n' && (read_any || status == 0) {
        out.extend_from_slice(layout.addr(addr).as_bytes());
        out.push(b'\n');
    }
    io::out(&out);
    io::flush_stdout();
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g_format() {
        let g = |x: f64| format_g(x, &alloc::format!("{x:e}"), 17);
        assert_eq!(g(8.765776478827897e228), "8.765776478827897e+228");
        assert_eq!(g(0.5), "0.5");
        assert_eq!(g(123456.0), "123456");
        assert_eq!(g(-12.25), "-12.25");
        assert_eq!(g(0.0001), "0.0001");
        assert_eq!(g(0.00001), "1e-05");
        let f = 4.782196e30f32;
        assert_eq!(format_g(f64::from(f), &alloc::format!("{f:e}"), 8), "4.782196e+30");
    }

    #[test]
    fn sizes_and_types() {
        assert_eq!(parse_size(b"0x10"), Some(16));
        assert_eq!(parse_size(b"2k"), Some(2048));
        assert_eq!(parse_size(b"1kB"), Some(1000));
        assert_eq!(parse_size(b"010"), Some(8));
        let mut v = Vec::new();
        parse_types(b"x1zd2oL", &mut v).unwrap();
        assert_eq!(v.len(), 3);
        assert!(v[0].z && v[1].size == 2 && v[2].size == 8);
        assert!(parse_types(b"x3", &mut v).is_err());
    }

    #[test]
    fn padding_follows_the_widest_type() {
        let mut specs = Vec::new();
        parse_types(b"x1o2", &mut specs).unwrap();
        let l = Layout { specs, big_endian: false, label: None, width: 4, group: 2, block_cols: 7, radix: b'o' };
        let mut out = Vec::new();
        l.line(&mut out, 0, b"hell");
        assert_eq!(out, b"0000000  68 65  6c 6c\n        062550 066154\n");
    }
}
