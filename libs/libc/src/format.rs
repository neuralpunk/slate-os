// SPDX-License-Identifier: MIT OR Apache-2.0

//! The printf family's formatting (C11 7.21.6.1): flags `-+ #0`, field
//! width and precision (also `*`), length modifiers `hh h l ll j z t`,
//! and the conversions `d i u o x X c s p %` and `f F e E g G a A`
//! (exact, from [`crate::float`]). `L` (long double) is not supported:
//! such a conversion is printed as written and its argument not consumed.

use alloc::vec::Vec;

/// Where the arguments come from: a C `va_list`, or a test's list.
pub trait Args {
    /// The next `int`-sized (or promoted) argument.
    fn int(&mut self) -> i32;
    /// The next `long`-sized argument.
    fn long(&mut self) -> i64;
    /// The next pointer.
    fn ptr(&mut self) -> usize;
    /// The next `double` (floats are promoted to it).
    fn double(&mut self) -> f64;
}

impl Args for core::ffi::VaList<'_> {
    fn int(&mut self) -> i32 {
        // SAFETY: The format string says an int comes next (C's contract).
        unsafe { self.next_arg::<i32>() }
    }
    fn long(&mut self) -> i64 {
        // SAFETY: As above, for a long.
        unsafe { self.next_arg::<i64>() }
    }
    fn ptr(&mut self) -> usize {
        // SAFETY: As above, for a pointer.
        unsafe { self.next_arg::<usize>() }
    }
    fn double(&mut self) -> f64 {
        // SAFETY: As above, for a double.
        unsafe { self.next_arg::<f64>() }
    }
}

#[derive(Clone, Default)]
struct Spec {
    left: bool,
    plus: bool,
    space: bool,
    alt: bool,
    zero: bool,
    width: usize,
    precision: Option<usize>,
}

impl Spec {
    /// Pad `body` (after `prefix`, such as a sign or "0x") to the width.
    fn emit(&self, out: &mut Vec<u8>, prefix: &[u8], body: &[u8], numeric: bool) {
        let len = prefix.len() + body.len();
        let pad = self.width.saturating_sub(len);
        // The 0 flag is ignored with `-`, and for integers with a precision.
        let zero = self.zero && !self.left && numeric && self.precision.is_none();
        if !self.left && !zero {
            out.resize(out.len() + pad, b' ');
        }
        out.extend_from_slice(prefix);
        if zero {
            out.resize(out.len() + pad, b'0');
        }
        out.extend_from_slice(body);
        if self.left {
            out.resize(out.len() + pad, b' ');
        }
    }
}

/// Digits of `v` in `base`, at least `min` of them (a precision of 0 and
/// a value of 0 print nothing).
fn digits(mut v: u64, base: u64, upper: bool, min: Option<usize>) -> Vec<u8> {
    let set: &[u8] = if upper { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    let mut d = Vec::new();
    while v > 0 {
        d.push(set[(v % base) as usize]);
        v /= base;
    }
    let min = min.unwrap_or(1);
    while d.len() < min {
        d.push(b'0');
    }
    d.reverse();
    d
}

/// Format `fmt` with `args`; returns the bytes (without a NUL).
///
/// # Safety
///
/// `%s` arguments must be NUL-terminated strings (or null, printed as
/// "(null)"), and the arguments must match the conversions.
pub unsafe fn format(fmt: &[u8], args: &mut dyn Args) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < fmt.len() {
        let c = fmt[i];
        if c != b'%' {
            out.push(c);
            i += 1;
            continue;
        }
        let start = i;
        i += 1;
        let mut s = Spec::default();
        while let Some(&f) = fmt.get(i) {
            match f {
                b'-' => s.left = true,
                b'+' => s.plus = true,
                b' ' => s.space = true,
                b'#' => s.alt = true,
                b'0' => s.zero = true,
                _ => break,
            }
            i += 1;
        }
        if fmt.get(i) == Some(&b'*') {
            let w = args.int();
            if w < 0 {
                s.left = true;
            }
            s.width = w.unsigned_abs() as usize;
            i += 1;
        } else {
            while let Some(d) = fmt.get(i).filter(|d| d.is_ascii_digit()) {
                s.width = s.width * 10 + usize::from(d - b'0');
                i += 1;
            }
        }
        if fmt.get(i) == Some(&b'.') {
            i += 1;
            if fmt.get(i) == Some(&b'*') {
                let p = args.int();
                s.precision = (p >= 0).then_some(p as usize);
                i += 1;
            } else {
                let mut p = 0;
                while let Some(d) = fmt.get(i).filter(|d| d.is_ascii_digit()) {
                    p = p * 10 + usize::from(d - b'0');
                    i += 1;
                }
                s.precision = Some(p);
            }
        }
        // Length: 0 int, 1 short, 2 char, 3 long (l ll j z t all 64-bit).
        let mut len = 0;
        loop {
            match fmt.get(i) {
                Some(b'h') => len = if len == 1 { 2 } else { 1 },
                Some(b'l' | b'j' | b'z' | b't') => len = 3,
                _ => break,
            }
            i += 1;
        }
        let Some(&conv) = fmt.get(i) else {
            out.extend_from_slice(&fmt[start..]);
            break;
        };
        i += 1;
        let signed = |a: &mut dyn Args| -> i64 {
            match len {
                3 => a.long(),
                1 => i64::from(a.int() as i16),
                2 => i64::from(a.int() as i8),
                _ => i64::from(a.int()),
            }
        };
        let unsigned = |a: &mut dyn Args| -> u64 {
            match len {
                3 => a.long() as u64,
                1 => u64::from(a.int() as u16),
                2 => u64::from(a.int() as u8),
                _ => u64::from(a.int() as u32),
            }
        };
        match conv {
            b'd' | b'i' => {
                let v = signed(args);
                let sign: &[u8] = if v < 0 {
                    b"-"
                } else if s.plus {
                    b"+"
                } else if s.space {
                    b" "
                } else {
                    b""
                };
                let body = digits(v.unsigned_abs(), 10, false, s.precision);
                s.emit(&mut out, sign, &body, true);
            }
            b'u' | b'o' | b'x' | b'X' => {
                let v = unsigned(args);
                let base = match conv {
                    b'u' => 10,
                    b'o' => 8,
                    _ => 16,
                };
                let mut body = digits(v, base, conv == b'X', s.precision);
                let mut prefix: &[u8] = b"";
                if s.alt && conv == b'o' && body.first() != Some(&b'0') {
                    body.insert(0, b'0');
                }
                if s.alt && v != 0 && conv == b'x' {
                    prefix = b"0x";
                }
                if s.alt && v != 0 && conv == b'X' {
                    prefix = b"0X";
                }
                s.emit(&mut out, prefix, &body, true);
            }
            b'c' => {
                let ch = [args.int() as u8];
                s.emit(&mut out, b"", &ch, false);
            }
            b's' => {
                let p = args.ptr() as *const core::ffi::c_char;
                let text: &[u8] = if p.is_null() {
                    b"(null)"
                } else {
                    // A precision bounds how much is read (the string need
                    // not be NUL-terminated then).
                    // SAFETY: The caller guarantees a valid string.
                    unsafe {
                        let n = match s.precision {
                            Some(max) => crate::string::strnlen(p, max),
                            None => crate::string::strlen(p),
                        };
                        core::slice::from_raw_parts(p as *const u8, n)
                    }
                };
                s.emit(&mut out, b"", text, false);
            }
            b'p' => {
                let v = args.ptr();
                if v == 0 {
                    s.emit(&mut out, b"", b"(nil)", false);
                } else {
                    s.emit(&mut out, b"0x", &digits(v as u64, 16, false, None), false);
                }
            }
            b'f' | b'F' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A' => {
                let (neg, finite, mut body) = crate::float::format(args.double(), conv, s.precision, s.alt);
                let sign: &[u8] = if neg {
                    b"-"
                } else if s.plus {
                    b"+"
                } else if s.space {
                    b" "
                } else {
                    b""
                };
                // Zeros pad after the sign (and after %a's 0x), with or
                // without a precision; never for inf and nan.
                let mut prefix = sign.to_vec();
                if finite && conv.eq_ignore_ascii_case(&b'a') {
                    prefix.extend(body.drain(..2));
                }
                let mut t = s.clone();
                t.precision = None;
                t.emit(&mut out, &prefix, &body, finite);
            }
            b'%' => out.push(b'%'),
            _ => out.extend_from_slice(&fmt[start..i]),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Arguments from a list of words.
    struct List(Vec<u64>);

    impl Args for List {
        fn int(&mut self) -> i32 {
            self.0.remove(0) as i32
        }
        fn long(&mut self) -> i64 {
            self.0.remove(0) as i64
        }
        fn ptr(&mut self) -> usize {
            self.0.remove(0) as usize
        }
        fn double(&mut self) -> f64 {
            f64::from_bits(self.0.remove(0))
        }
    }

    fn f(fmt: &str, args: &[u64]) -> std::string::String {
        // SAFETY: The tests pass valid strings for %s.
        let out = unsafe { format(fmt.as_bytes(), &mut List(args.to_vec())) };
        std::string::String::from_utf8(out).unwrap()
    }

    #[test]
    fn integers() {
        assert_eq!(f("%d|%5d|%-5d|%05d", &[42, (-7i64) as u64, 3, 9]), "42|   -7|3    |00009");
        assert_eq!(f("%+d % d %.3d", &[5, 5, 7]), "+5  5 007");
        assert_eq!(f("%u %x %X %#x %o %#o", &[4_294_967_295, 255, 255, 255, 8, 8]), "4294967295 ff FF 0xff 10 010");
        assert_eq!(f("%ld %lu %zu", &[(-1i64) as u64, u64::MAX, 12]), "-1 18446744073709551615 12");
        assert_eq!(f("%hhd %hu", &[0x1ff, 0x1_0005]), "-1 5");
        assert_eq!(f("%*d|%-*d", &[4, 1, 3, 2]), "   1|2  ");
        assert_eq!(f("%.0d|", &[0]), "|");
    }

    #[test]
    fn floats() {
        let b = |x: f64| x.to_bits();
        assert_eq!(
            f("%f|%.2f|%8.3f|%-8.1f|", &[b(3.25159), b(2.005), b(-1.5), b(0.25)]),
            "3.251590|2.00|  -1.500|0.2     |"
        );
        assert_eq!(
            f("%e|%.0E|%g|%G", &[b(12345.678), b(5e-10), b(0.0001), b(1e20)]),
            "1.234568e+04|5E-10|0.0001|1E+20"
        );
        assert_eq!(
            f("%+08.2f|% f|%#.0f|%010a", &[b(-3.5), b(1.0), b(7.0), b(1.0)]),
            "-0003.50| 1.000000|7.|0x00001p+0"
        );
        assert_eq!(f("%05f|%-6f|%F", &[b(f64::INFINITY), b(f64::NAN), b(f64::NEG_INFINITY)]), "  inf|nan   |-INF");
    }

    #[test]
    fn strings_and_others() {
        let s = c"hello";
        assert_eq!(f("[%s] [%8s] [%-8s] [%.2s]", &[s.as_ptr() as u64; 4]), "[hello] [   hello] [hello   ] [he]");
        assert_eq!(f("%s", &[0]), "(null)");
        assert_eq!(f("%c%c 100%%", &[b'o' as u64, b'k' as u64]), "ok 100%");
        assert_eq!(f("%p %p", &[0x1000, 0]), "0x1000 (nil)");
        // Unsupported conversions are printed as written.
        assert_eq!(f("%Lf %d", &[3]), "%Lf 3");
        assert_eq!(f("trailing %", &[]), "trailing %");
    }
}
