// SPDX-License-Identifier: MIT OR Apache-2.0

//! awk values (XCU awk, "Expressions in awk"): numbers, strings, numeric
//! strings from input, and the uninitialized value; their conversions and
//! printf-style formatting.

use alloc::string::String;
use alloc::vec::Vec;

use super::big::Big;
use super::math;

/// `-M`: integers are exact however large (ADR 0165).
pub static BIGNUM: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// A UTF-8 locale: `%c` writes characters past 127 in UTF-8 and takes a
/// string's first character (not byte), as gawk does there.
pub static UTF8: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[derive(Clone, Debug, Default)]
pub enum Value {
    /// Never given a value (gawk's typeof: "untyped").
    #[default]
    Uninit,
    /// A variable read before it had a value ("unassigned"); otherwise as
    /// `Uninit`.
    Unassigned,
    Num(f64),
    Str(Vec<u8>),
    /// Input text that looks numeric (fields, getline, split, ARGV...).
    StrNum(Vec<u8>),
    /// gawk's typed regexp (`@/re/`): its pattern, a string elsewhere.
    Regex(Vec<u8>),
    /// `-M`'s exact integer.
    Big(Big),
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 11 | 12)
}

/// The length of the longest prefix of `s` that is a decimal number
/// (after optional sign), and its value.
fn number_prefix(s: &[u8]) -> (usize, f64) {
    let mut i = 0;
    let mut sign = false;
    if matches!(s.first(), Some(b'+' | b'-')) {
        i = 1;
        sign = true;
    }
    // +inf, -nan (gawk accepts them only with a sign).
    if sign && s.len() >= i + 3 {
        let w = &s[i..i + 3];
        if w.eq_ignore_ascii_case(b"inf") || w.eq_ignore_ascii_case(b"nan") {
            let neg = s[0] == b'-';
            let v = if w.eq_ignore_ascii_case(b"inf") { f64::INFINITY } else { f64::NAN };
            let mut n = i + 3;
            if w.eq_ignore_ascii_case(b"inf") && s.len() >= i + 8 && s[i..i + 8].eq_ignore_ascii_case(b"infinity") {
                n = i + 8;
            }
            return (n, if neg { -v } else { v });
        }
    }
    let digits_start = i;
    while s.get(i).is_some_and(u8::is_ascii_digit) {
        i += 1;
    }
    let mut digits = i > digits_start;
    if s.get(i) == Some(&b'.') {
        let save = i;
        i += 1;
        let fs = i;
        while s.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i > fs {
            digits = true;
        } else if !digits {
            i = save;
        }
    }
    if !digits {
        return (0, 0.0);
    }
    if matches!(s.get(i), Some(b'e' | b'E')) {
        let mut j = i + 1;
        if matches!(s.get(j), Some(b'+' | b'-')) {
            j += 1;
        }
        if s.get(j).is_some_and(u8::is_ascii_digit) {
            while s.get(j).is_some_and(u8::is_ascii_digit) {
                j += 1;
            }
            i = j;
        }
    }
    let v = core::str::from_utf8(&s[..i]).ok().and_then(|t| t.parse::<f64>().ok()).unwrap_or(0.0);
    (i, v)
}

/// strtod-like: leading blanks, then the longest numeric prefix.
pub fn str_to_num(s: &[u8]) -> f64 {
    let start = s.iter().position(|&c| !is_space(c)).unwrap_or(s.len());
    number_prefix(&s[start..]).1
}

/// Whether input text is a numeric string (blanks around a number).
pub fn looks_numeric(s: &[u8]) -> bool {
    let start = s.iter().position(|&c| !is_space(c)).unwrap_or(s.len());
    let end = s.iter().rposition(|&c| !is_space(c)).map_or(start, |e| e + 1);
    if start >= end {
        return false;
    }
    let (n, _) = number_prefix(&s[start..end]);
    n == end - start
}

impl Value {
    pub fn from_input(text: Vec<u8>) -> Value {
        if looks_numeric(&text) { Value::StrNum(text) } else { Value::Str(text) }
    }

    pub fn num(&self) -> f64 {
        match self {
            // A typed regexp is 0 as a number (gawk).
            Value::Uninit | Value::Unassigned | Value::Regex(_) => 0.0,
            Value::Num(n) => *n,
            Value::Big(b) => b.to_f64(),
            Value::Str(s) | Value::StrNum(s) => str_to_num(s),
        }
    }

    /// The string value, numbers converted with `convfmt`.
    pub fn text(&self, convfmt: &[u8]) -> Vec<u8> {
        match self {
            Value::Uninit | Value::Unassigned => Vec::new(),
            Value::Num(n) => num_to_str(*n, convfmt),
            Value::Big(b) => b.text().into_bytes(),
            Value::Str(s) | Value::StrNum(s) | Value::Regex(s) => s.clone(),
        }
    }

    pub fn truthy(&self) -> bool {
        match self {
            Value::Uninit | Value::Unassigned => false,
            Value::Num(n) => *n != 0.0,
            Value::Big(b) => !b.is_zero(),
            Value::StrNum(s) => str_to_num(s) != 0.0,
            Value::Str(s) | Value::Regex(s) => !s.is_empty(),
        }
    }

    /// Compared as a number (numbers, numeric strings, uninitialized).
    pub fn numeric(&self) -> bool {
        !matches!(self, Value::Str(_) | Value::Regex(_))
    }
}

/// A number as a string: integers exactly, others through `fmt`.
pub fn num_to_str(n: f64, fmt: &[u8]) -> Vec<u8> {
    if n.is_finite() && n == math::trunc(n) {
        if n.abs() < 1e18 {
            return alloc::format!("{}", n as i64).into_bytes();
        }
        return alloc::format!("{n:.0}").into_bytes();
    }
    sprintf(fmt, &[Value::Num(n)], b"%.6g")
}

/// Formatting of one float conversion (`e E f F g G`).
pub fn float(conv: u8, v: f64, prec: usize, alt: bool) -> String {
    let upper = conv.is_ascii_uppercase();
    if !v.is_finite() {
        let s = if v.is_nan() {
            if v.is_sign_negative() { "-nan" } else { "nan" }
        } else if v < 0.0 {
            "-inf"
        } else {
            "inf"
        };
        return if upper { s.to_ascii_uppercase() } else { String::from(s) };
    }
    let sci = |v: f64, p: usize| -> String {
        let s = alloc::format!("{v:.p$e}");
        let (m, e) = s.split_at(s.find('e').unwrap_or(s.len()));
        let e: i32 = e.get(1..).and_then(|x| x.parse().ok()).unwrap_or(0);
        let mut m = String::from(m);
        if alt && p == 0 {
            m.push('.');
        }
        alloc::format!("{m}{}{}{:02}", if upper { 'E' } else { 'e' }, if e < 0 { '-' } else { '+' }, e.unsigned_abs())
    };
    match conv.to_ascii_lowercase() {
        b'f' => {
            let mut s = alloc::format!("{v:.prec$}");
            if alt && prec == 0 {
                s.push('.');
            }
            s
        }
        b'e' => sci(v, prec),
        _ => {
            let p = prec.max(1);
            let probe = alloc::format!("{v:.*e}", p - 1);
            let x: i32 = probe.split('e').nth(1).and_then(|e| e.parse().ok()).unwrap_or(0);
            let mut s = if x < -4 || x >= p as i32 {
                sci(v, p - 1)
            } else {
                let d = (p as i32 - 1 - x).max(0) as usize;
                alloc::format!("{v:.d$}")
            };
            if !alt {
                // Drop trailing zeros of the fraction.
                let (body, exp) = match s.find(['e', 'E']) {
                    Some(i) => (String::from(&s[..i]), String::from(&s[i..])),
                    None => (s.clone(), String::new()),
                };
                let body = if body.contains('.') {
                    String::from(body.trim_end_matches('0').trim_end_matches('.'))
                } else {
                    body
                };
                s = body + &exp;
            }
            s
        }
    }
}

fn pad(s: &[u8], width: usize, left: bool, zero: bool, out: &mut Vec<u8>) {
    if s.len() >= width {
        out.extend_from_slice(s);
        return;
    }
    let fill = width - s.len();
    if left {
        out.extend_from_slice(s);
        out.resize(out.len() + fill, b' ');
    } else if zero {
        // Zeros go after a sign.
        let sign = s.first().is_some_and(|c| matches!(c, b'-' | b'+' | b' '));
        let (head, rest) = if sign { s.split_at(1) } else { s.split_at(0) };
        out.extend_from_slice(head);
        out.resize(out.len() + fill, b'0');
        out.extend_from_slice(rest);
    } else {
        out.resize(out.len() + fill, b' ');
        out.extend_from_slice(s);
    }
}

/// An integer's decimal text (exact for large magnitudes).
fn int_text(v: f64) -> String {
    let t = math::trunc(v);
    if t.abs() < 9.2e18 { alloc::format!("{}", (t as i64).unsigned_abs()) } else { alloc::format!("{:.0}", t.abs()) }
}

/// sprintf with awk's conversions.
pub fn sprintf(fmt: &[u8], args: &[Value], convfmt: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut next = 0;
    let mut take = || {
        let v = args.get(next).cloned().unwrap_or_default();
        next += 1;
        v
    };
    let mut i = 0;
    while i < fmt.len() {
        let c = fmt[i];
        i += 1;
        if c != b'%' {
            out.push(c);
            continue;
        }
        if fmt.get(i) == Some(&b'%') {
            out.push(b'%');
            i += 1;
            continue;
        }
        let (mut left, mut zero, mut plus, mut space, mut alt) = (false, false, false, false, false);
        while let Some(&f) = fmt.get(i) {
            match f {
                b'-' => left = true,
                b'0' => zero = true,
                b'+' => plus = true,
                b' ' => space = true,
                b'#' => alt = true,
                _ => break,
            }
            i += 1;
        }
        let mut width = 0usize;
        if fmt.get(i) == Some(&b'*') {
            i += 1;
            let w = take().num() as i64;
            if w < 0 {
                left = true;
            }
            width = w.unsigned_abs() as usize;
        } else {
            while let Some(d) = fmt.get(i).filter(|d| d.is_ascii_digit()) {
                width = width * 10 + (d - b'0') as usize;
                i += 1;
            }
        }
        let mut prec: Option<usize> = None;
        if fmt.get(i) == Some(&b'.') {
            i += 1;
            if fmt.get(i) == Some(&b'*') {
                i += 1;
                prec = Some(take().num().max(0.0) as usize);
            } else {
                let mut p = 0;
                while let Some(d) = fmt.get(i).filter(|d| d.is_ascii_digit()) {
                    p = p * 10 + (d - b'0') as usize;
                    i += 1;
                }
                prec = Some(p);
            }
        }
        // Length modifiers are accepted and ignored.
        while matches!(fmt.get(i), Some(b'h' | b'l' | b'L' | b'q' | b'j' | b'z' | b't')) {
            i += 1;
        }
        let Some(&conv) = fmt.get(i) else {
            out.push(b'%');
            break;
        };
        i += 1;
        match conv {
            b'd' | b'i' => {
                let val = take();
                let v = val.num();
                let mut s = String::new();
                if v.is_nan() || v.is_infinite() {
                    s = float(b'f', v, 0, false);
                } else {
                    // -M's integers keep every digit.
                    let (neg, mut digits) = match &val {
                        Value::Big(b) => {
                            let t = b.text();
                            (t.starts_with('-'), String::from(t.trim_start_matches('-')))
                        }
                        _ => (v < 0.0 && math::trunc(v) != 0.0, int_text(v)),
                    };
                    if let Some(p) = prec {
                        if digits.len() < p {
                            digits = "0".repeat(p - digits.len()) + &digits;
                        }
                        if p == 0 && digits == "0" {
                            digits.clear();
                        }
                    }
                    if neg {
                        s.push('-');
                    } else if plus {
                        s.push('+');
                    } else if space {
                        s.push(' ');
                    }
                    s.push_str(&digits);
                }
                pad(s.as_bytes(), width, left, zero && prec.is_none(), &mut out);
            }
            b'o' | b'x' | b'X' | b'u' => {
                let v = take().num();
                let t = math::trunc(v);
                let u = if t < 0.0 {
                    (t as i64) as u64
                } else if t < 1.8e19 {
                    t as u64
                } else {
                    u64::MAX
                };
                let mut s = match conv {
                    b'o' => alloc::format!("{u:o}"),
                    b'x' => alloc::format!("{u:x}"),
                    b'X' => alloc::format!("{u:X}"),
                    _ => alloc::format!("{u}"),
                };
                if let Some(p) = prec
                    && s.len() < p
                {
                    s = "0".repeat(p - s.len()) + &s;
                }
                if alt && u != 0 {
                    s = match conv {
                        b'o' => alloc::format!("0{s}"),
                        b'x' => alloc::format!("0x{s}"),
                        b'X' => alloc::format!("0X{s}"),
                        _ => s,
                    };
                }
                pad(s.as_bytes(), width, left, zero && prec.is_none(), &mut out);
            }
            b'e' | b'E' | b'f' | b'F' | b'g' | b'G' => {
                let v = take().num();
                let mut s = float(conv, v, prec.unwrap_or(6), alt);
                if v >= 0.0 && !s.starts_with('-') {
                    if plus {
                        s.insert(0, '+');
                    } else if space {
                        s.insert(0, ' ');
                    }
                }
                pad(s.as_bytes(), width, left, zero && v.is_finite(), &mut out);
            }
            b'c' => {
                let v = take();
                let utf8 = UTF8.load(core::sync::atomic::Ordering::Relaxed);
                let s: Vec<u8> = match &v {
                    Value::Num(_) | Value::StrNum(_) => {
                        let n = v.num() as i64;
                        match u32::try_from(n).ok().and_then(char::from_u32) {
                            Some(c) if utf8 && n > 127 => c.encode_utf8(&mut [0u8; 4]).as_bytes().to_vec(),
                            // The C locale's character: the code's low byte, as
                            // awk was seen to print it with LC_ALL=C.
                            _ => alloc::vec![n as u8],
                        }
                    }
                    other => {
                        let t = other.text(convfmt);
                        let len = match t.first() {
                            Some(&c) if utf8 && c >= 0xC0 => {
                                1 + t[1..].iter().take_while(|&&b| b & 0xC0 == 0x80).count()
                            }
                            Some(_) => 1,
                            None => 0,
                        };
                        t[..len].to_vec()
                    }
                };
                pad(&s, width, left, false, &mut out);
            }
            b's' => {
                let mut s = take().text(convfmt);
                if let Some(p) = prec {
                    s.truncate(p);
                }
                pad(&s, width, left, false, &mut out);
            }
            other => {
                // Unknown conversions are copied through.
                out.push(b'%');
                out.push(other);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversions() {
        assert_eq!(str_to_num(b" 12abc"), 12.0);
        assert_eq!(str_to_num(b".5"), 0.5);
        assert_eq!(str_to_num(b"1e3x"), 1000.0);
        assert_eq!(str_to_num(b"0x1A"), 0.0);
        assert!(looks_numeric(b" 10.0 "));
        assert!(!looks_numeric(b"10a"));
        assert!(!looks_numeric(b""));
        assert_eq!(num_to_str(3.0, b"%.6g"), b"3");
        assert_eq!(num_to_str(0.1 + 0.2, b"%.6g"), b"0.3");
        assert_eq!(num_to_str(1234567.5, b"%.6g"), b"1.23457e+06");
        assert_eq!(num_to_str(1e20, b"%.6g"), b"100000000000000000000");
        assert_eq!(num_to_str(1e-5, b"%.6g"), b"1e-05");
        let f = |fmt: &str, v: Vec<Value>| String::from_utf8(sprintf(fmt.as_bytes(), &v, b"%.6g")).unwrap();
        assert_eq!(
            f(
                "%5.2f|%-5s|%05d|%x|%e|%G",
                alloc::vec![
                    Value::Num(3.14159),
                    Value::Str(b"ab".to_vec()),
                    Value::Num(42.0),
                    Value::Num(255.0),
                    Value::Num(12345.678),
                    Value::Num(0.00001234)
                ]
            ),
            " 3.14|ab   |00042|ff|1.234568e+04|1.234E-05"
        );
        assert_eq!(
            f("%d %d %i", alloc::vec![Value::Num(1e20), Value::Num(-3.9), Value::Str(b"12abc".to_vec())]),
            "100000000000000000000 -3 12"
        );
        assert_eq!(f("%c%c", alloc::vec![Value::Num(65.0), Value::Str(b"hello".to_vec())]), "Ah");
        assert_eq!(
            f("%*d|%-*d|", alloc::vec![Value::Num(4.0), Value::Num(7.0), Value::Num(3.0), Value::Num(1.0)]),
            "   7|1  |"
        );
        assert_eq!(
            f("%.3s|%+d|% d", alloc::vec![Value::Str(b"abcdef".to_vec()), Value::Num(5.0), Value::Num(5.0)]),
            "abc|+5| 5"
        );
        assert_eq!(
            f("%g %g %g", alloc::vec![Value::Num(100000.0), Value::Num(1000000.0), Value::Num(0.0001)]),
            "100000 1e+06 0.0001"
        );
    }
}
