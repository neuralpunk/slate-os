// SPDX-License-Identifier: MIT OR Apache-2.0

//! The scanf family's matching (C11 7.21.6.2; ADR 0074): white space,
//! ordinary characters, and the conversions `d i u o x X c s [ p n %` and
//! `f F e E g G a A`, with assignment suppression (`*`), field widths and
//! the length modifiers `hh h l ll j z t`. Wide characters (`%lc`, `%ls`)
//! and long double (`%Lf`) are not supported (docs/GAPS.md).

use alloc::vec::Vec;
use core::ffi::c_int;

use crate::format::Args;

/// Where the characters come from; one character of pushback is all C
/// promises, and all this needs.
pub trait Source {
    fn peek(&mut self) -> Option<u8>;
    fn bump(&mut self);
}

/// A C string.
pub struct Bytes<'a> {
    pub s: &'a [u8],
    pub pos: usize,
}

impl Source for Bytes<'_> {
    fn peek(&mut self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }
    fn bump(&mut self) {
        self.pos += 1;
    }
}

fn is_space(c: u8) -> bool {
    c == b' ' || (b'\t'..=b'\r').contains(&c)
}

/// Reads with a count of what was consumed (for `%n`).
struct Input<'a> {
    src: &'a mut dyn Source,
    used: usize,
}

impl Input<'_> {
    fn peek(&mut self) -> Option<u8> {
        self.src.peek()
    }
    fn take(&mut self) -> Option<u8> {
        let c = self.src.peek()?;
        self.src.bump();
        self.used += 1;
        Some(c)
    }
    fn skip_space(&mut self) {
        while self.peek().is_some_and(is_space) {
            self.take();
        }
    }
}

/// The longest prefix of an integer in `base` (0: by prefix), up to
/// `width` characters.
fn collect_int(inp: &mut Input<'_>, mut base: u32, width: usize) -> Vec<u8> {
    let mut s = Vec::new();
    let room = |s: &Vec<u8>| s.len() < width;
    if let Some(c) = inp.peek().filter(|&c| (c == b'+' || c == b'-') && room(&s)) {
        s.push(c);
        inp.take();
    }
    if (base == 0 || base == 16) && room(&s) && inp.peek() == Some(b'0') {
        s.push(b'0');
        inp.take();
        if room(&s) && matches!(inp.peek(), Some(b'x' | b'X')) {
            s.push(inp.take().unwrap_or(b'x'));
            base = 16;
        } else if base == 0 {
            base = 8;
        }
    }
    if base == 0 {
        base = 10;
    }
    while room(&s) && inp.peek().is_some_and(|c| (c as char).is_digit(base)) {
        s.push(inp.take().unwrap_or(b'0'));
    }
    s
}

/// The value of an integer as collected; None if there are no digits.
fn int_value(s: &[u8], base: u32) -> Option<u64> {
    let (neg, mut d) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let mut base = base;
    if (base == 0 || base == 16) && d.len() >= 2 && d[0] == b'0' && (d[1] | 0x20) == b'x' {
        d = &d[2..];
        base = 16;
        if d.is_empty() {
            // "0x" alone: the 0 matched, the x did not.
            return Some(0);
        }
    } else if base == 0 {
        base = if d.first() == Some(&b'0') { 8 } else { 10 };
    }
    if d.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for &c in d {
        v = v.wrapping_mul(u64::from(base)).wrapping_add(u64::from((c as char).to_digit(base)?));
    }
    Some(if neg { v.wrapping_neg() } else { v })
}

/// The longest prefix of a floating-point number, up to `width`.
fn collect_float(inp: &mut Input<'_>, width: usize) -> Vec<u8> {
    let mut s: Vec<u8> = Vec::new();
    let push = |inp: &mut Input<'_>, s: &mut Vec<u8>| -> bool {
        if s.len() < width
            && let Some(c) = inp.take()
        {
            s.push(c);
            return true;
        }
        false
    };
    let room = |s: &Vec<u8>| s.len() < width;
    if inp.peek().is_some_and(|c| c == b'+' || c == b'-') && room(&s) {
        push(inp, &mut s);
    }
    // inf, infinity, nan: as far as the letters match.
    let word = |inp: &mut Input<'_>, s: &mut Vec<u8>, w: &[u8]| {
        for &l in w {
            if s.len() < width && inp.peek().is_some_and(|c| c.to_ascii_lowercase() == l) {
                s.push(inp.take().unwrap_or(l));
            } else {
                break;
            }
        }
    };
    match inp.peek().map(|c| c.to_ascii_lowercase()) {
        Some(b'i') => {
            word(inp, &mut s, b"inf");
            if s.len() >= 3 && inp.peek().is_some_and(|c| c.eq_ignore_ascii_case(&b'i')) {
                word(inp, &mut s, b"inity");
            }
            return s;
        }
        Some(b'n') => {
            word(inp, &mut s, b"nan");
            return s;
        }
        _ => {}
    }
    let mut hex = false;
    if room(&s) && inp.peek() == Some(b'0') {
        push(inp, &mut s);
        if room(&s) && matches!(inp.peek(), Some(b'x' | b'X')) {
            push(inp, &mut s);
            hex = true;
        }
    }
    let digit = |c: u8| if hex { c.is_ascii_hexdigit() } else { c.is_ascii_digit() };
    let mut point = false;
    while room(&s) {
        match inp.peek() {
            Some(c) if digit(c) => {
                push(inp, &mut s);
            }
            Some(b'.') if !point => {
                point = true;
                push(inp, &mut s);
            }
            _ => break,
        }
    }
    let e = if hex { b'p' } else { b'e' };
    if room(&s) && inp.peek().is_some_and(|c| c.to_ascii_lowercase() == e) {
        push(inp, &mut s);
        if room(&s) && inp.peek().is_some_and(|c| c == b'+' || c == b'-') {
            push(inp, &mut s);
        }
        while room(&s) && inp.peek().is_some_and(|c| c.is_ascii_digit()) {
            push(inp, &mut s);
        }
    }
    s
}

/// A scanset: the bytes `[...]` accepts.
fn scanset(fmt: &[u8], i: &mut usize) -> [bool; 256] {
    let mut set = [false; 256];
    let mut neg = false;
    if fmt.get(*i) == Some(&b'^') {
        neg = true;
        *i += 1;
    }
    let mut first = true;
    while let Some(&c) = fmt.get(*i) {
        if c == b']' && !first {
            *i += 1;
            break;
        }
        first = false;
        if fmt.get(*i + 1) == Some(&b'-') && fmt.get(*i + 2).is_some_and(|&e| e != b']') {
            let e = fmt[*i + 2];
            for b in c..=e.max(c) {
                set[b as usize] = true;
            }
            *i += 3;
        } else {
            set[c as usize] = true;
            *i += 1;
        }
    }
    if neg {
        for v in set.iter_mut() {
            *v = !*v;
        }
    }
    set
}

/// Store an integer through the next pointer, sized by the length
/// modifier (0 int, 1 short, 2 char, 3 long and wider).
///
/// # Safety
///
/// The pointer must be valid for the size.
unsafe fn store_int(args: &mut dyn Args, len: u8, v: u64) {
    let p = args.ptr();
    // SAFETY: The caller vouches for the pointer and its size.
    unsafe {
        match len {
            2 => *(p as *mut u8) = v as u8,
            1 => *(p as *mut u16) = v as u16,
            3 => *(p as *mut u64) = v,
            _ => *(p as *mut u32) = v as u32,
        }
    }
}

/// Match `fmt` against `src`, storing through `args`. Returns the number
/// of assignments, or EOF (-1) if the input ended before the first
/// conversion.
///
/// # Safety
///
/// The arguments must be pointers of the types the conversions name, with
/// room for what they receive.
pub unsafe fn scan(fmt: &[u8], src: &mut dyn Source, args: &mut dyn Args) -> c_int {
    let mut inp = Input { src, used: 0 };
    let mut count: c_int = 0;
    let mut i = 0;
    // Whether a conversion has been attempted (EOF only before one).
    let mut converted = false;
    let eof = |count: c_int, converted: bool| if converted { count } else { -1 };
    while i < fmt.len() {
        let c = fmt[i];
        if is_space(c) {
            inp.skip_space();
            i += 1;
            continue;
        }
        if c != b'%' || fmt.get(i + 1) == Some(&b'%') {
            if c == b'%' {
                inp.skip_space();
                i += 1;
            }
            match inp.peek() {
                Some(x) if x == c => {
                    inp.take();
                    i += 1;
                    continue;
                }
                Some(_) => return count,
                None => return eof(count, converted),
            }
        }
        i += 1;
        let suppress = fmt.get(i) == Some(&b'*');
        if suppress {
            i += 1;
        }
        let mut width = 0usize;
        while let Some(d) = fmt.get(i).filter(|d| d.is_ascii_digit()) {
            width = width * 10 + usize::from(d - b'0');
            i += 1;
        }
        let mut len = 0u8;
        loop {
            match fmt.get(i) {
                Some(b'h') => len = if len == 1 { 2 } else { 1 },
                Some(b'l' | b'j' | b'z' | b't' | b'q') => len = 3,
                Some(b'L') => len = 4,
                _ => break,
            }
            i += 1;
        }
        let Some(&conv) = fmt.get(i) else { break };
        i += 1;
        if !matches!(conv, b'[' | b'c' | b'n') {
            inp.skip_space();
        }
        if conv != b'n' && inp.peek().is_none() {
            return eof(count, converted);
        }
        converted = true;
        match conv {
            b'd' | b'i' | b'u' | b'o' | b'x' | b'X' | b'p' => {
                let base = match conv {
                    b'd' | b'u' => 10,
                    b'i' => 0,
                    b'o' => 8,
                    _ => 16,
                };
                let s = collect_int(&mut inp, base, if width == 0 { usize::MAX } else { width });
                let Some(v) = int_value(&s, base) else { return count };
                if !suppress {
                    // SAFETY: The caller's pointers (see the function).
                    unsafe { store_int(args, if conv == b'p' { 3 } else { len }, v) };
                    count += 1;
                }
            }
            b'f' | b'F' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A' => {
                let s = collect_float(&mut inp, if width == 0 { usize::MAX } else { width });
                let fmt_ = if len == 3 { crate::float::DOUBLE } else { crate::float::SINGLE };
                let (bits, used, _) = crate::float::parse(&s, fmt_);
                if used == 0 || used != s.len() {
                    return count;
                }
                if !suppress {
                    if len == 4 {
                        // long double: not supported; stop as on a mismatch.
                        return count;
                    }
                    let p = args.ptr();
                    // SAFETY: A float or double pointer per the length.
                    unsafe {
                        if len == 3 {
                            *(p as *mut u64) = bits;
                        } else {
                            *(p as *mut u32) = bits as u32;
                        }
                    }
                    count += 1;
                }
            }
            b'c' => {
                let n = if width == 0 { 1 } else { width };
                let p = if suppress { 0 } else { args.ptr() };
                let mut got = 0;
                while got < n {
                    let Some(ch) = inp.take() else { break };
                    if p != 0 {
                        // SAFETY: Room for `n` characters.
                        unsafe { *(p as *mut u8).add(got) = ch };
                    }
                    got += 1;
                }
                if got < n {
                    return eof(count, got > 0 || count > 0);
                }
                if !suppress {
                    count += 1;
                }
            }
            b's' | b'[' => {
                let set = if conv == b'[' { Some(scanset(fmt, &mut i)) } else { None };
                let ok = |c: u8| match &set {
                    Some(s) => s[c as usize],
                    None => !is_space(c),
                };
                let max = if width == 0 { usize::MAX } else { width };
                let p = if suppress { 0 } else { args.ptr() };
                let mut got = 0;
                while got < max && inp.peek().is_some_and(ok) {
                    let ch = inp.take().unwrap_or(0);
                    if p != 0 {
                        // SAFETY: Room for the field and a NUL.
                        unsafe { *(p as *mut u8).add(got) = ch };
                    }
                    got += 1;
                }
                if got == 0 {
                    return count;
                }
                if p != 0 {
                    // SAFETY: As above.
                    unsafe { *(p as *mut u8).add(got) = 0 };
                    count += 1;
                }
            }
            b'n' => {
                if !suppress {
                    // SAFETY: The caller's pointer.
                    unsafe { store_int(args, len, inp.used as u64) };
                }
            }
            _ => return count,
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pointers as arguments.
    struct Ptrs(Vec<usize>);

    impl Args for Ptrs {
        fn int(&mut self) -> i32 {
            0
        }
        fn long(&mut self) -> i64 {
            0
        }
        fn ptr(&mut self) -> usize {
            self.0.remove(0)
        }
        fn double(&mut self) -> f64 {
            0.0
        }
    }

    fn scan_str(input: &str, fmt: &str, ptrs: Vec<usize>) -> c_int {
        let mut src = Bytes { s: input.as_bytes(), pos: 0 };
        // SAFETY: The tests pass pointers of the right types.
        unsafe { scan(fmt.as_bytes(), &mut src, &mut Ptrs(ptrs)) }
    }

    #[test]
    fn integers_and_strings() {
        let (mut a, mut b, mut c) = (0i32, 0u32, 0i64);
        let mut s = [0u8; 16];
        let n = scan_str(
            "  -42 0x1f 077 word rest",
            "%d %x %lo %s",
            std::vec![
                &mut a as *mut _ as usize,
                &mut b as *mut _ as usize,
                &mut c as *mut _ as usize,
                s.as_mut_ptr() as usize
            ],
        );
        assert_eq!((n, a, b, c), (4, -42, 0x1f, 0o77));
        assert_eq!(&s[..5], b"word\0");
        let (mut x, mut y) = (0i32, 0i32);
        assert_eq!(scan_str("0x10 010", "%i %i", std::vec![&mut x as *mut _ as usize, &mut y as *mut _ as usize]), 2);
        assert_eq!((x, y), (16, 8));
        assert_eq!(scan_str("12345", "%3d%d", std::vec![&mut x as *mut _ as usize, &mut y as *mut _ as usize]), 2);
        assert_eq!((x, y), (123, 45));
        // A literal mismatch stops; the end of input before anything is EOF.
        assert_eq!(scan_str("a=1", "b=%d", std::vec![&mut x as *mut _ as usize]), 0);
        assert_eq!(scan_str("   ", "%d", std::vec![&mut x as *mut _ as usize]), -1);
        assert_eq!(scan_str("7 x", "%d %d", std::vec![&mut x as *mut _ as usize, &mut y as *mut _ as usize]), 1);
        assert_eq!(scan_str_noargs("5", "%*d"), 0);
    }

    fn scan_str_noargs(input: &str, fmt: &str) -> c_int {
        scan_str(input, fmt, std::vec![])
    }

    #[test]
    fn sets_chars_and_counts() {
        let mut s = [0u8; 16];
        let mut t = [0u8; 16];
        let mut n = 0i32;
        let r = scan_str(
            "abc123:xyz",
            "%[a-z]%*[0-9]%n:%c",
            std::vec![s.as_mut_ptr() as usize, &mut n as *mut _ as usize, t.as_mut_ptr() as usize],
        );
        assert_eq!((r, n), (2, 6));
        assert_eq!(&s[..4], b"abc\0");
        assert_eq!(t[0], b'x');
        assert_eq!(scan_str("]x", "%[]x]", std::vec![s.as_mut_ptr() as usize]), 1);
        assert_eq!(&s[..3], b"]x\0");
        assert_eq!(scan_str("hello, world", "%[^,]", std::vec![s.as_mut_ptr() as usize]), 1);
        assert_eq!(&s[..6], b"hello\0");
        assert_eq!(scan_str_noargs("100%", "100%%"), 0);
    }

    #[test]
    fn floats() {
        let (mut f, mut d) = (0f32, 0f64);
        assert_eq!(
            scan_str("3.25 -1e-3", "%f %lf", std::vec![&mut f as *mut _ as usize, &mut d as *mut _ as usize]),
            2
        );
        assert_eq!((f, d), (3.25, -1e-3));
        assert_eq!(
            scan_str("inf 0x1p4", "%lf %le", std::vec![&mut d as *mut _ as usize, &mut d as *mut _ as usize]),
            2
        );
        assert_eq!(d, 16.0);
        assert_eq!(scan_str("1e+", "%lf", std::vec![&mut d as *mut _ as usize]), 0);
        assert_eq!(scan_str("2.5x", "%3lf", std::vec![&mut d as *mut _ as usize]), 1);
        assert_eq!(d, 2.5);
    }
}
