// SPDX-License-Identifier: MIT OR Apache-2.0

//! printf(1) as POSIX describes it: the format is reused until the
//! arguments run out; `%b` expands backslash escapes in its argument;
//! numeric arguments may be character constants (`'a`). `%q` quotes for
//! the shell, as GNU's printf does or (for chalk's builtin) as bash's;
//! the builtin also has bash's `%(datefmt)T`.

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{io, lossy};

use crate::util::{error, unescape};

pub fn main(args: &[Vec<u8>]) -> i32 {
    let mut i = 1;
    if args.get(1).map(Vec::as_slice) == Some(b"--") {
        i = 2;
    }
    let Some(fmt) = args.get(i) else {
        error("missing operand");
        return 1;
    };
    let mut out = Vec::new();
    let status = format(fmt, &args[i + 1..], &mut out);
    io::out(&out);
    status
}

/// Whose printf this is: GNU's (the program), or bash's (chalk's
/// builtin, with the time the shell started for `%(...)T`'s -2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    Gnu,
    Bash { start: i64 },
}

/// Format `args` with `fmt` into `out`; returns the exit status.
pub fn format(fmt: &[u8], args: &[Vec<u8>], out: &mut Vec<u8>) -> i32 {
    format_as(fmt, args, out, Style::Gnu)
}

/// Format as `style`'s printf does.
pub fn format_as(fmt: &[u8], args: &[Vec<u8>], out: &mut Vec<u8>, style: Style) -> i32 {
    let mut status = 0;
    let mut next = 0;
    loop {
        let start = next;
        let (stop, used) = one_pass(fmt, &args[next.min(args.len())..], out, &mut status, style);
        next += used;
        if stop || next >= args.len() || used == 0 && next == start {
            break;
        }
    }
    status
}

fn num_arg(a: Option<&Vec<u8>>, status: &mut i32) -> i64 {
    let Some(a) = a else { return 0 };
    if let Some(rest) = a.strip_prefix(b"'").or_else(|| a.strip_prefix(b"\"")) {
        return rest.first().map_or(0, |&c| i64::from(c));
    }
    let s = lossy(a);
    let t = s.trim();
    let (neg, digits) = match t.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let v = if let Some(h) = digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        i64::from_str_radix(h, 16)
    } else if digits.len() > 1 && digits.starts_with('0') {
        i64::from_str_radix(&digits[1..], 8)
    } else {
        digits.parse::<i64>()
    };
    match v {
        Ok(v) => {
            if neg {
                -v
            } else {
                v
            }
        }
        Err(_) => {
            error(format_args!("'{}': expected a numeric value", s));
            *status = 1;
            0
        }
    }
}

fn float_arg(a: Option<&Vec<u8>>, status: &mut i32) -> f64 {
    let Some(a) = a else { return 0.0 };
    match lossy(a).trim().parse::<f64>() {
        Ok(v) => v,
        Err(_) => {
            error(format_args!("'{}': expected a numeric value", lossy(a)));
            *status = 1;
            0.0
        }
    }
}

/// Pad `s` to `width` (left-aligned with `-`, zero-padded with `0`).
fn pad(s: &[u8], width: usize, left: bool, zero: bool, out: &mut Vec<u8>) {
    if s.len() >= width {
        out.extend_from_slice(s);
    } else if left {
        out.extend_from_slice(s);
        out.resize(out.len() + width - s.len(), b' ');
    } else if zero {
        // Zeros go after a sign.
        let (sign, rest) =
            if s.first().is_some_and(|c| *c == b'-' || *c == b'+') { (&s[..1], &s[1..]) } else { (&s[..0], s) };
        out.extend_from_slice(sign);
        out.resize(out.len() + width - s.len(), b'0');
        out.extend_from_slice(rest);
    } else {
        out.resize(out.len() + width - s.len(), b' ');
        out.extend_from_slice(s);
    }
}

/// One pass over the format; returns (stop requested by \c, arguments used).
fn one_pass(fmt: &[u8], args: &[Vec<u8>], out: &mut Vec<u8>, status: &mut i32, style: Style) -> (bool, usize) {
    let mut used = 0;
    let mut i = 0;
    while i < fmt.len() {
        let c = fmt[i];
        if c == b'\\' {
            // A single escape.
            let end = (i + 4).min(fmt.len());
            let mut j = i + 2;
            if fmt.get(i + 1).is_some_and(|d| (b'0'..=b'7').contains(d)) {
                while j < end && (b'0'..=b'7').contains(&fmt[j]) {
                    j += 1;
                }
            } else if fmt.get(i + 1) == Some(&b'x') {
                while j < (i + 4).min(fmt.len()) && fmt[j].is_ascii_hexdigit() {
                    j += 1;
                }
            }
            let j = j.min(fmt.len());
            let (b, stop) = unescape(&fmt[i..j], true);
            out.extend_from_slice(&b);
            if stop {
                return (true, used);
            }
            i = j;
            continue;
        }
        if c != b'%' {
            out.push(c);
            i += 1;
            continue;
        }
        i += 1;
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
            let w = num_arg(args.get(used), status);
            used += 1;
            if w < 0 {
                left = true;
            }
            width = w.unsigned_abs() as usize;
            i += 1;
        }
        while let Some(d) = fmt.get(i).filter(|d| d.is_ascii_digit()) {
            width = width * 10 + usize::from(d - b'0');
            i += 1;
        }
        let mut prec: Option<usize> = None;
        if fmt.get(i) == Some(&b'.') {
            i += 1;
            let mut p = 0;
            if fmt.get(i) == Some(&b'*') {
                p = num_arg(args.get(used), status).max(0) as usize;
                used += 1;
                i += 1;
            }
            while let Some(d) = fmt.get(i).filter(|d| d.is_ascii_digit()) {
                p = p * 10 + usize::from(d - b'0');
                i += 1;
            }
            prec = Some(p);
        }
        // `%(datefmt)T` (bash): a time.
        if let Style::Bash { start } = style
            && fmt.get(i) == Some(&b'(')
            && let Some(close) = fmt[i..].iter().position(|&c| c == b')').map(|p| i + p)
            && fmt.get(close + 1) == Some(&b'T')
        {
            let tfmt = if close == i + 1 { &b"%X"[..] } else { &fmt[i + 1..close] };
            let arg = args.get(used);
            used += 1;
            let t = match arg.map(|a| lossy(a).trim().parse::<i64>()) {
                None => -1,
                Some(Ok(v)) => v,
                Some(Err(_)) => {
                    error(format_args!("'{}': invalid number", lossy(arg.unwrap())));
                    *status = 1;
                    -1
                }
            };
            let t = match t {
                -1 => slate_rt::time::unix(),
                -2 => start,
                t => t,
            };
            let mut s = String::new();
            slate_rt::time::format(&slate_rt::tz::localtime(t), &lossy(tfmt), &mut s);
            let mut s = s.into_bytes();
            if let Some(p) = prec {
                s.truncate(p);
            }
            pad(&s, width, left, false, out);
            i = close + 2;
            continue;
        }
        // Length modifiers are accepted and ignored.
        while fmt.get(i).is_some_and(|c| b"hlLjzt".contains(c)) {
            i += 1;
        }
        let Some(&conv) = fmt.get(i) else {
            out.push(b'%');
            break;
        };
        i += 1;
        let arg = args.get(used);
        match conv {
            b's' => {
                used += 1;
                let mut s = arg.cloned().unwrap_or_default();
                if let Some(p) = prec {
                    s.truncate(p);
                }
                pad(&s, width, left, false, out);
            }
            b'b' => {
                used += 1;
                let (mut s, stop) = unescape(arg.map_or(&[][..], |a| a.as_slice()), false);
                if let Some(p) = prec {
                    s.truncate(p);
                }
                pad(&s, width, left, false, out);
                if stop {
                    return (true, used);
                }
            }
            b'c' => {
                used += 1;
                let s: Vec<u8> = arg.and_then(|a| a.first().copied()).into_iter().collect();
                pad(&s, width, left, false, out);
            }
            b'q' => {
                used += 1;
                let a = arg.map_or(&[][..], |a| a.as_slice());
                match style {
                    Style::Gnu if width > 0 || prec.is_some() => {
                        error(format_args!("%{}q: invalid conversion specification", width));
                        *status = 1;
                        return (true, used);
                    }
                    Style::Gnu => out.extend(quote_gnu(a)),
                    Style::Bash { .. } => {
                        let mut s = quote_bash(a);
                        if let Some(p) = prec {
                            s.truncate(p);
                        }
                        pad(&s, width, left, false, out);
                    }
                }
            }
            b'd' | b'i' => {
                used += 1;
                let v = num_arg(arg, status);
                let mut s = String::new();
                if v >= 0 && plus {
                    s.push('+');
                } else if v >= 0 && space {
                    s.push(' ');
                }
                let digits = alloc::format!("{}", v.unsigned_abs());
                let digits = match prec {
                    Some(p) if digits.len() < p => alloc::format!("{}{digits}", "0".repeat(p - digits.len())),
                    Some(0) if v == 0 => String::new(),
                    _ => digits,
                };
                if v < 0 {
                    s.push('-');
                }
                s.push_str(&digits);
                pad(s.as_bytes(), width, left, zero && prec.is_none(), out);
            }
            b'u' | b'o' | b'x' | b'X' => {
                used += 1;
                let v = num_arg(arg, status) as u64;
                let mut s = match conv {
                    b'o' => alloc::format!("{v:o}"),
                    b'x' => alloc::format!("{v:x}"),
                    b'X' => alloc::format!("{v:X}"),
                    _ => alloc::format!("{v}"),
                };
                if let Some(p) = prec
                    && s.len() < p
                {
                    s = alloc::format!("{}{s}", "0".repeat(p - s.len()));
                }
                if alt && v != 0 {
                    s = match conv {
                        b'o' => alloc::format!("0{s}"),
                        b'x' => alloc::format!("0x{s}"),
                        b'X' => alloc::format!("0X{s}"),
                        _ => s,
                    };
                }
                pad(s.as_bytes(), width, left, zero && prec.is_none(), out);
            }
            b'f' | b'F' | b'e' | b'E' | b'g' | b'G' => {
                used += 1;
                let v = float_arg(arg, status);
                let p = prec.unwrap_or(6);
                let mut s = match conv {
                    b'e' | b'E' => sci(v, p, conv == b'E'),
                    b'g' | b'G' => general(v, p.max(1), conv == b'G', alt),
                    _ => alloc::format!("{v:.p$}"),
                };
                if v >= 0.0 && plus {
                    s.insert(0, '+');
                } else if v >= 0.0 && space {
                    s.insert(0, ' ');
                }
                pad(s.as_bytes(), width, left, zero, out);
            }
            other => {
                error(format_args!("%{}: invalid conversion specification", other as char));
                *status = 1;
                return (true, used);
            }
        }
    }
    (false, used)
}

/// `%e`: d.ddde±XX.
fn sci(v: f64, p: usize, upper: bool) -> String {
    if v == 0.0 {
        let m = alloc::format!("{:.p$}", 0.0);
        return alloc::format!("{m}{}+00", if upper { 'E' } else { 'e' });
    }
    let mut exp = 0i32;
    let mut m = v.abs();
    while m >= 10.0 {
        m /= 10.0;
        exp += 1;
    }
    while m < 1.0 {
        m *= 10.0;
        exp -= 1;
    }
    let mut ms = alloc::format!("{m:.p$}");
    if ms.starts_with("10") {
        m /= 10.0;
        exp += 1;
        ms = alloc::format!("{m:.p$}");
    }
    let sign = if v < 0.0 { "-" } else { "" };
    let e = if upper { 'E' } else { 'e' };
    alloc::format!("{sign}{ms}{e}{}{:02}", if exp < 0 { '-' } else { '+' }, exp.unsigned_abs())
}

/// `%g`: the shorter of %e and %f, without trailing zeros.
fn general(v: f64, p: usize, upper: bool, alt: bool) -> String {
    if v == 0.0 {
        return String::from("0");
    }
    let mut exp = 0i32;
    let mut m = v.abs();
    while m >= 10.0 {
        m /= 10.0;
        exp += 1;
    }
    while m < 1.0 {
        m *= 10.0;
        exp -= 1;
    }
    let trim = |s: String| -> String {
        if alt || !s.contains('.') {
            return s;
        }
        let t = s.trim_end_matches('0');
        String::from(t.trim_end_matches('.'))
    };
    if exp < -4 || exp >= p as i32 {
        let s = sci(v, p - 1, upper);
        let (mant, e) = s.split_at(s.find(['e', 'E']).unwrap());
        alloc::format!("{}{e}", trim(String::from(mant)))
    } else {
        let decimals = (p as i32 - 1 - exp).max(0) as usize;
        trim(alloc::format!("{v:.decimals$}"))
    }
}

/// A byte the shell's quoting writes as an escape: control characters,
/// DEL and (in the C locale) everything past ASCII.
fn unprintable(c: u8) -> bool {
    !(0x20..0x7F).contains(&c)
}

/// `\n`-style escapes inside `$'...'`, octal for the rest; `esc` is the
/// letter for ESC (bash `E`), or none (GNU writes `\033`).
fn ansi_c(c: u8, esc: Option<u8>, out: &mut Vec<u8>) {
    let named = match c {
        7 => Some(b'a'),
        8 => Some(b'b'),
        9 => Some(b't'),
        10 => Some(b'n'),
        11 => Some(b'v'),
        12 => Some(b'f'),
        13 => Some(b'r'),
        0x1B => esc,
        _ => None,
    };
    match named {
        Some(l) => out.extend_from_slice(&[b'\\', l]),
        None => out.extend_from_slice(alloc::format!("\\{c:03o}").as_bytes()),
    }
}

/// bash's `%q` (observed, bash 5.3 in the C locale): `''` for nothing,
/// `$'...'` when anything is unprintable, else backslashes before the
/// characters the shell treats specially (`#` and `~` only first).
pub fn quote_bash(s: &[u8]) -> Vec<u8> {
    if s.is_empty() {
        return b"''".to_vec();
    }
    let mut out = Vec::new();
    if s.iter().any(|&c| unprintable(c)) {
        out.extend_from_slice(b"$'");
        for &c in s {
            match c {
                b'\\' | b'\'' => out.extend_from_slice(&[b'\\', c]),
                c if unprintable(c) => ansi_c(c, Some(b'E'), &mut out),
                c => out.push(c),
            }
        }
        out.push(b'\'');
        return out;
    }
    for (i, &c) in s.iter().enumerate() {
        if b" !\"$&'()*,;<>?[\\]^`{|}".contains(&c) || i == 0 && (c == b'#' || c == b'~') {
            out.push(b'\\');
        }
        out.push(c);
    }
    out
}

/// GNU's `%q` (its shell-escape quoting, observed): bare when nothing
/// needs quoting, `"..."` for a quote among otherwise plain text, else
/// single quotes, with unprintable bytes as `$'...'` pieces between them.
pub fn quote_gnu(s: &[u8]) -> Vec<u8> {
    if s.is_empty() {
        return b"''".to_vec();
    }
    let special = |i: usize, c: u8| b" \t!\"$&'()*;<=>?[\\^`|".contains(&c) || i == 0 && (c == b'#' || c == b'~');
    if !s.iter().any(|&c| unprintable(c)) {
        if !s.iter().enumerate().any(|(i, &c)| special(i, c)) {
            return s.to_vec();
        }
        if s.contains(&b'\'') && !s.iter().any(|c| b"\"$`\\!".contains(c)) {
            return [b"\"", s, b"\""].concat();
        }
    }
    let mut out = alloc::vec![b'\''];
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if unprintable(c) {
            out.extend_from_slice(b"'$'");
            while i < s.len() && unprintable(s[i]) {
                ansi_c(s[i], None, &mut out);
                i += 1;
            }
            out.extend_from_slice(b"''");
            continue;
        }
        if c == b'\'' {
            out.extend_from_slice(b"'\\''");
        } else {
            out.push(c);
        }
        i += 1;
    }
    out.push(b'\'');
    // The empty pair a trailing escape leaves goes.
    if out.ends_with(b"''") && out.len() > 2 {
        out.truncate(out.len() - 2);
    }
    out
}

#[cfg(test)]
mod quote_tests {
    use super::*;

    #[test]
    fn bash_quoting() {
        // As bash 5.3's printf %q gives them (C locale).
        let q = |s: &[u8]| String::from_utf8(quote_bash(s)).unwrap();
        assert_eq!(q(b"a b"), "a\\ b");
        assert_eq!(q(b"it's"), "it\\'s");
        assert_eq!(q(b""), "''");
        assert_eq!(q(b"a\nb"), "$'a\\nb'");
        assert_eq!(q(b"~x"), "\\~x");
        assert_eq!(q(b"x~#"), "x~#");
        assert_eq!(q(b"a,b=c"), "a\\,b=c");
        assert_eq!(q("é".as_bytes()), "$'\\303\\251'");
        assert_eq!(q(b"\x1b"), "$'\\E'");
    }

    #[test]
    fn gnu_quoting() {
        // As GNU coreutils' printf %q gives them (C locale).
        let q = |s: &[u8]| String::from_utf8(quote_gnu(s)).unwrap();
        assert_eq!(q(b"a b"), "'a b'");
        assert_eq!(q(b"it's"), "\"it's\"");
        assert_eq!(q(b"it's!"), "'it'\\''s!'");
        assert_eq!(q(b"a'b\"c"), "'a'\\''b\"c'");
        assert_eq!(q(b"a=b"), "'a=b'");
        assert_eq!(q(b"a~"), "a~");
        assert_eq!(q(b"a]{}"), "a]{}");
        assert_eq!(q(b"a\tb"), "'a'$'\\t''b'");
        assert_eq!(q(b"a b\n"), "'a b'$'\\n'");
        assert_eq!(q("é".as_bytes()), "''$'\\303\\251'");
        assert_eq!(q(b"\x1b"), "''$'\\033'");
        assert_eq!(q(b"it's\n"), "'it'\\''s'$'\\n'");
    }
}
