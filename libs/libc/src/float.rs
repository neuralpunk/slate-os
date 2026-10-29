// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exact conversions between binary floating point and text (ADR 0074):
//! printf's `f e g a` conversions (C11 7.21.6.1) and strtod/strtof
//! (7.22.1.3).
//!
//! Both directions work on exact big integers, so every result is
//! correctly rounded (to nearest, ties to even, the default IEEE 754
//! rounding C assumes):
//!
//! - a double is m·2^e, and its exact decimal expansion is finite (at most
//!   767 significant digits). printf takes the whole expansion and rounds
//!   it as text;
//! - text is D·10^E. strtod forms D·10^E (or D·2^k/10^-E) as a big
//!   integer, keeps 66 or more of its leading bits, and rounds with a
//!   sticky bit for whatever lies below.
//!
//! This is slower than the shortest-digit algorithms, but it is simple
//! and needs no tables.

use alloc::vec;
use alloc::vec::Vec;

// --- big integers -------------------------------------------------------------

/// A non-negative integer, little-endian 32-bit limbs, no high zero limbs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Big(Vec<u32>);

impl Big {
    pub(crate) fn from_u128(mut v: u128) -> Big {
        let mut l = Vec::new();
        while v != 0 {
            l.push(v as u32);
            v >>= 32;
        }
        Big(l)
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.0.is_empty()
    }

    fn trim(&mut self) {
        while self.0.last() == Some(&0) {
            self.0.pop();
        }
    }

    pub(crate) fn bits(&self) -> u32 {
        match self.0.last() {
            Some(&top) => (self.0.len() as u32 - 1) * 32 + (32 - top.leading_zeros()),
            None => 0,
        }
    }

    /// self = self·m + a.
    fn mul_add(&mut self, m: u32, a: u32) {
        let mut carry = u64::from(a);
        for l in self.0.iter_mut() {
            let v = u64::from(*l) * u64::from(m) + carry;
            *l = v as u32;
            carry = v >> 32;
        }
        if carry != 0 {
            self.0.push(carry as u32);
        }
    }

    /// self = self / d; the remainder.
    fn div_small(&mut self, d: u32) -> u32 {
        let mut rem = 0u64;
        for l in self.0.iter_mut().rev() {
            let v = (rem << 32) | u64::from(*l);
            *l = (v / u64::from(d)) as u32;
            rem = v % u64::from(d);
        }
        self.trim();
        rem as u32
    }

    pub(crate) fn shl(&mut self, n: u32) {
        if self.is_zero() {
            return;
        }
        let (words, bits) = ((n / 32) as usize, n % 32);
        if bits != 0 {
            let mut carry = 0;
            for l in self.0.iter_mut() {
                let v = (*l << bits) | carry;
                carry = *l >> (32 - bits);
                *l = v;
            }
            if carry != 0 {
                self.0.push(carry);
            }
        }
        self.0.splice(0..0, core::iter::repeat_n(0, words));
    }

    /// Bit `i`.
    fn bit(&self, i: u32) -> bool {
        self.0.get((i / 32) as usize).is_some_and(|l| l >> (i % 32) & 1 != 0)
    }

    /// Whether any bit below `i` is set.
    pub(crate) fn any_below(&self, i: u32) -> bool {
        let (w, b) = ((i / 32) as usize, i % 32);
        self.0.iter().take(w).any(|&l| l != 0) || (b != 0 && self.0.get(w).is_some_and(|&l| l & ((1 << b) - 1) != 0))
    }

    /// Bits `lo..lo + 128` as a number.
    pub(crate) fn window(&self, lo: u32) -> u128 {
        (0..128).filter(|&i| self.bit(lo + i)).fold(0u128, |v, i| v | 1 << i)
    }

    /// Keep the bits below `n`.
    fn truncate_bits(&mut self, n: u32) {
        let (w, b) = ((n / 32) as usize, n % 32);
        if w < self.0.len() {
            if b == 0 {
                self.0.truncate(w);
            } else {
                self.0.truncate(w + 1);
                self.0[w] &= (1 << b) - 1;
            }
        }
        self.trim();
    }

    pub(crate) fn cmp(&self, o: &Big) -> core::cmp::Ordering {
        self.0.len().cmp(&o.0.len()).then_with(|| self.0.iter().rev().cmp(o.0.iter().rev()))
    }

    /// self -= o (o ≤ self).
    pub(crate) fn sub(&mut self, o: &Big) {
        let mut borrow = 0i64;
        for (i, l) in self.0.iter_mut().enumerate() {
            let v = i64::from(*l) - i64::from(o.0.get(i).copied().unwrap_or(0)) - borrow;
            borrow = i64::from(v < 0);
            *l = v.rem_euclid(1 << 32) as u32;
        }
        self.trim();
    }

    /// 10^n.
    fn pow10(n: u32) -> Big {
        let mut b = Big(vec![1]);
        let mut left = n;
        while left >= 9 {
            b.mul_add(1_000_000_000, 0);
            left -= 9;
        }
        b.mul_add(10u32.pow(left), 0);
        b
    }

    /// The decimal digits (ASCII), most significant first.
    fn decimal(&self) -> Vec<u8> {
        let mut v = self.clone();
        let mut out = Vec::new();
        while !v.is_zero() {
            let mut r = v.div_small(1_000_000_000);
            let last = v.is_zero();
            for _ in 0..9 {
                out.push(b'0' + (r % 10) as u8);
                r /= 10;
                if last && r == 0 {
                    break;
                }
            }
        }
        while out.len() > 1 && out.last() == Some(&b'0') {
            out.pop();
        }
        out.reverse();
        out
    }
}

// --- printf -------------------------------------------------------------------

/// A finite non-negative value as 0.DIGITS × 10^point, without leading or
/// trailing zero digits (no digits: zero).
#[derive(Clone, Debug)]
struct Decimal {
    digits: Vec<u8>,
    point: i32,
}

impl Decimal {
    /// The exact expansion of `x` (finite).
    fn exact(x: f64) -> Decimal {
        let bits = x.to_bits() & !(1 << 63);
        let (exp, frac) = ((bits >> 52) as i32, bits & ((1 << 52) - 1));
        let (m, e) = if exp == 0 { (frac, -1074) } else { (frac | 1 << 52, exp - 1075) };
        if m == 0 {
            return Decimal { digits: Vec::new(), point: 0 };
        }
        let (mut digits, point) = if e >= 0 {
            let mut n = Big::from_u128(u128::from(m));
            n.shl(e as u32);
            let digits = n.decimal();
            let point = digits.len() as i32;
            (digits, point)
        } else {
            let fbits = (-e) as u32;
            let int = if fbits >= 64 { 0 } else { m >> fbits };
            let mut frac = Big::from_u128(u128::from(m));
            frac.truncate_bits(fbits);
            let mut digits = if int == 0 { Vec::new() } else { Big::from_u128(u128::from(int)).decimal() };
            let mut p = digits.len() as i32;
            let mut leading = digits.is_empty();
            while !frac.is_zero() {
                frac.mul_add(10, 0);
                let d = (0..4).filter(|&i| frac.bit(fbits + i)).fold(0u8, |v, i| v | 1 << i);
                frac.truncate_bits(fbits);
                if leading && d == 0 {
                    p -= 1;
                    continue;
                }
                leading = false;
                digits.push(b'0' + d);
            }
            (digits, p)
        };
        while digits.last() == Some(&b'0') {
            digits.pop();
        }
        Decimal { digits, point }
    }

    /// Keep `keep` digits, rounding to nearest with ties to even.
    fn round(&mut self, keep: i32) {
        if keep >= self.digits.len() as i32 {
            return;
        }
        if keep < 0 {
            self.digits.clear();
            return;
        }
        let k = keep as usize;
        let next = self.digits[k];
        let rest = self.digits[k + 1..].iter().any(|&d| d != b'0');
        let odd = k > 0 && (self.digits[k - 1] - b'0') % 2 == 1;
        let up = next > b'5' || (next == b'5' && (rest || odd));
        self.digits.truncate(k);
        if up {
            let mut i = k;
            loop {
                if i == 0 {
                    self.digits.insert(0, b'1');
                    self.point += 1;
                    break;
                }
                i -= 1;
                if self.digits[i] == b'9' {
                    self.digits[i] = b'0';
                } else {
                    self.digits[i] += 1;
                    break;
                }
            }
        }
        while self.digits.last() == Some(&b'0') {
            self.digits.pop();
        }
        if self.digits.is_empty() {
            self.point = 0;
        }
    }

    /// Digit `i` of 0.DIGITS (zero past the end).
    fn at(&self, i: i32) -> u8 {
        if i < 0 { b'0' } else { self.digits.get(i as usize).copied().unwrap_or(b'0') }
    }

    /// Style f with `prec` fraction digits.
    fn fixed(mut self, prec: usize, alt: bool) -> Vec<u8> {
        self.round(self.point + prec as i32);
        let mut out = Vec::new();
        if self.point <= 0 {
            out.push(b'0');
        } else {
            out.extend((0..self.point).map(|i| self.at(i)));
        }
        if prec > 0 || alt {
            out.push(b'.');
        }
        out.extend((0..prec as i32).map(|i| self.at(self.point + i)));
        out
    }

    /// Style e with `prec` fraction digits.
    fn sci(mut self, prec: usize, alt: bool, upper: bool) -> Vec<u8> {
        self.round(prec as i32 + 1);
        let x = if self.digits.is_empty() { 0 } else { self.point - 1 };
        let mut out = vec![self.at(0)];
        if prec > 0 || alt {
            out.push(b'.');
        }
        out.extend((1..=prec as i32).map(|i| self.at(i)));
        out.push(if upper { b'E' } else { b'e' });
        out.push(if x < 0 { b'-' } else { b'+' });
        let e = x.unsigned_abs();
        if e < 10 {
            out.push(b'0');
        }
        out.extend(Big::from_u128(u128::from(e)).decimal().iter().filter(|_| e != 0));
        if e == 0 {
            out.push(b'0');
        }
        out
    }
}

/// Drop trailing fraction zeros (and then the point) from `body`, leaving
/// any exponent.
fn strip_zeros(body: &mut Vec<u8>) {
    let Some(dot) = body.iter().position(|&c| c == b'.') else { return };
    let end = body.iter().position(|&c| c == b'e' || c == b'E').unwrap_or(body.len());
    let mut cut = end;
    while cut > dot + 1 && body[cut - 1] == b'0' {
        cut -= 1;
    }
    if cut == dot + 1 {
        cut = dot;
    }
    body.drain(cut..end);
}

/// Style a: hexadecimal, `prec` hex digits after the point (None: as many
/// as needed).
fn hex(x: f64, prec: Option<usize>, alt: bool, upper: bool) -> Vec<u8> {
    let bits = x.to_bits() & !(1 << 63);
    let (exp, frac) = ((bits >> 52) as i32, bits & ((1 << 52) - 1));
    let (mut lead, e) = if exp == 0 { (0u64, if frac == 0 { 0 } else { -1022 }) } else { (1, exp - 1023) };
    let mut frac = frac;
    let mut nd = 13;
    if let Some(p) = prec.filter(|&p| p < 13) {
        // Round the 52 fraction bits to 4p, ties to even.
        let drop = 52 - 4 * p as u32;
        let rest = frac & ((1 << drop) - 1);
        let half = 1 << (drop - 1);
        frac >>= drop;
        if rest > half || (rest == half && frac & 1 == 1) || (rest == half && p == 0 && lead & 1 == 1) {
            frac += 1;
            if frac >> (4 * p) != 0 {
                frac = 0;
                lead += 1;
            }
        }
        nd = p;
    } else if prec.is_none() {
        while nd > 0 && frac & 0xf == 0 {
            frac >>= 4;
            nd -= 1;
        }
    }
    let set: &[u8] = if upper { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    let mut out = Vec::new();
    out.extend_from_slice(if upper { b"0X" } else { b"0x" });
    out.push(set[lead as usize]);
    let extra = prec.map_or(0, |p| p.saturating_sub(13));
    if nd > 0 || extra > 0 || alt {
        out.push(b'.');
    }
    for i in (0..nd).rev() {
        out.push(set[(frac >> (4 * i) & 0xf) as usize]);
    }
    out.resize(out.len() + extra, b'0');
    out.push(if upper { b'P' } else { b'p' });
    out.push(if e < 0 { b'-' } else { b'+' });
    out.extend(Big::from_u128(u128::from(e.unsigned_abs())).decimal());
    if e == 0 {
        out.push(b'0');
    }
    out
}

/// The body of a printf floating-point conversion (`conv` one of
/// `fFeEgGaA`) of `x`, without its sign: (negative, finite, body).
pub fn format(x: f64, conv: u8, prec: Option<usize>, alt: bool) -> (bool, bool, Vec<u8>) {
    let neg = x.is_sign_negative();
    let upper = conv.is_ascii_uppercase();
    if !x.is_finite() {
        let t: &[u8] = match (x.is_nan(), upper) {
            (true, false) => b"nan",
            (true, true) => b"NAN",
            (false, false) => b"inf",
            (false, true) => b"INF",
        };
        return (neg, false, t.to_vec());
    }
    let body = match conv.to_ascii_lowercase() {
        b'f' => Decimal::exact(x).fixed(prec.unwrap_or(6), alt),
        b'e' => Decimal::exact(x).sci(prec.unwrap_or(6), alt, upper),
        b'g' => {
            let p = match prec {
                Some(0) => 1,
                Some(p) => p,
                None => 6,
            };
            let d = Decimal::exact(x);
            let mut r = d.clone();
            r.round(p as i32);
            let ex = if r.digits.is_empty() { 0 } else { r.point - 1 };
            let mut body = if (p as i32) > ex && ex >= -4 {
                d.fixed((p as i32 - 1 - ex) as usize, alt)
            } else {
                d.sci(p - 1, alt, upper)
            };
            if !alt {
                strip_zeros(&mut body);
            }
            body
        }
        _ => hex(x, prec, alt, upper),
    };
    (neg, true, body)
}

// --- strtod -------------------------------------------------------------------

/// A binary floating-point format: fraction bits, minimum and maximum
/// exponents of normal numbers.
#[derive(Clone, Copy)]
pub struct Format {
    frac: u32,
    emin: i32,
    emax: i32,
}

pub const DOUBLE: Format = Format { frac: 52, emin: -1022, emax: 1023 };
pub const SINGLE: Format = Format { frac: 23, emin: -126, emax: 127 };

/// q·2^exp (plus something less than one unit of q when `sticky`) rounded
/// to the format: (bits, out of range).
pub(crate) fn round_bits(q: u128, exp: i32, sticky: bool, f: Format) -> (u64, bool) {
    if q == 0 {
        return (0, sticky);
    }
    let nb = 128 - q.leading_zeros() as i32;
    // The leading bit's weight, and how many bits the result can keep.
    let lead = exp + nb - 1;
    let keep = if lead < f.emin { f.frac as i32 + 1 - (f.emin - lead) } else { f.frac as i32 + 1 };
    let shift = nb - keep;
    let mut m: u128;
    let mut inexact = sticky;
    if shift <= 0 {
        m = q << (-shift) as u32;
    } else if shift > 127 {
        m = 0;
        inexact = true;
    } else {
        m = q >> shift as u32;
        let rest = q & ((1u128 << shift as u32) - 1);
        let half = 1u128 << (shift - 1) as u32;
        inexact |= rest != 0;
        if rest > half || (rest == half && (sticky || m & 1 == 1)) {
            m += 1;
        }
    }
    // The value is m·2^(lead - keep + 1); work out the stored exponent.
    let mut e = lead - (keep - 1) + f.frac as i32;
    if m >> (f.frac + 1) != 0 {
        m >>= 1;
        e += 1;
    }
    let tiny = m >> f.frac == 0;
    if tiny {
        let bits = m as u64;
        return (bits, inexact && (bits >> f.frac) == 0);
    }
    if e > f.emax {
        return (((1u64 << exp_bits(f)) - 1) << f.frac, true);
    }
    let biased = (e + (1 << (exp_bits(f) - 1)) - 1) as u64;
    ((biased << f.frac) | (m as u64 & ((1 << f.frac) - 1)), false)
}

fn exp_bits(f: Format) -> i32 {
    if f.frac == 52 { 11 } else { 8 }
}

/// Significant decimal digits kept; beyond them only "something nonzero
/// follows" counts (more than any halfway case can need).
const MAX_DIGITS: usize = 800;

/// D·10^e10 (D the digits, `sticky` for dropped nonzero digits) rounded.
fn decimal_bits(digits: &[u8], e10: i32, sticky: bool, f: Format) -> (u64, bool) {
    let mut d = Big(Vec::new());
    for chunk in digits.chunks(9) {
        let v = chunk.iter().fold(0u32, |v, &c| v * 10 + u32::from(c - b'0'));
        d.mul_add(10u32.pow(chunk.len() as u32), v);
    }
    if d.is_zero() {
        return (0, false);
    }
    let order = digits.len() as i32 + e10;
    if order > 330 {
        return round_bits(1, 2000, false, f);
    }
    if order < -400 {
        return (0, true);
    }
    if e10 >= 0 {
        let p = Big::pow10(e10 as u32);
        let mut n = Big(Vec::new());
        for (i, &l) in p.0.iter().enumerate() {
            let mut t = d.clone();
            t.mul_add(l, 0);
            t.0.splice(0..0, core::iter::repeat_n(0, i));
            n = add(&n, &t);
        }
        let nb = n.bits();
        let lo = nb.saturating_sub(128);
        let q = n.window(lo);
        round_bits(q, lo as i32, sticky || n.any_below(lo), f)
    } else {
        let mut m = Big::pow10((-e10) as u32);
        // Scale so that the quotient has 65 to 67 bits.
        let k = m.bits() as i32 - d.bits() as i32 + 66;
        let mut n = d;
        if k >= 0 {
            n.shl(k as u32);
        } else {
            m.shl((-k) as u32);
        }
        // Long division by shifts: the quotient has at most ~67 bits.
        let mut q = 0u128;
        for b in (0..=70u32).rev() {
            let mut t = m.clone();
            t.shl(b);
            if n.cmp(&t) != core::cmp::Ordering::Less {
                n.sub(&t);
                q |= 1 << b;
            }
        }
        round_bits(q, -k, sticky || !n.is_zero(), f)
    }
}

pub(crate) fn add(a: &Big, b: &Big) -> Big {
    let mut out = Vec::with_capacity(a.0.len().max(b.0.len()) + 1);
    let mut carry = 0u64;
    for i in 0..a.0.len().max(b.0.len()) {
        let v = u64::from(a.0.get(i).copied().unwrap_or(0)) + u64::from(b.0.get(i).copied().unwrap_or(0)) + carry;
        out.push(v as u32);
        carry = v >> 32;
    }
    if carry != 0 {
        out.push(carry as u32);
    }
    let mut r = Big(out);
    r.trim();
    r
}

/// strtod's parse of `s` in format `f`: (bits with the sign, bytes used
/// (0 if there is no number), out of range).
pub fn parse(s: &[u8], f: Format) -> (u64, usize, bool) {
    let sign_bit = if f.frac == 52 { 1u64 << 63 } else { 1 << 31 };
    let mut i = 0;
    while s.get(i).is_some_and(|&c| c == b' ' || (b'\t'..=b'\r').contains(&c)) {
        i += 1;
    }
    let mut neg = false;
    if let Some(&c) = s.get(i).filter(|&&c| c == b'+' || c == b'-') {
        neg = c == b'-';
        i += 1;
    }
    let sign = if neg { sign_bit } else { 0 };
    let rest = &s[i..];
    let starts = |w: &[u8]| rest.len() >= w.len() && rest[..w.len()].eq_ignore_ascii_case(w);
    let inf = ((f.emax + (1 << (exp_bits(f) - 1))) as u64) << f.frac;
    if starts(b"infinity") {
        return (sign | inf, i + 8, false);
    }
    if starts(b"inf") {
        return (sign | inf, i + 3, false);
    }
    if starts(b"nan") {
        let mut n = i + 3;
        // nan(n-char-sequence)
        if s.get(n) == Some(&b'(') {
            let mut j = n + 1;
            while s.get(j).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_') {
                j += 1;
            }
            if s.get(j) == Some(&b')') {
                n = j + 1;
            }
        }
        return (sign | inf | 1 << (f.frac - 1), n, false);
    }
    if (starts(b"0x"))
        && s.get(i + 2).is_some_and(|c| {
            c.is_ascii_hexdigit() || (*c == b'.' && s.get(i + 3).is_some_and(|c| c.is_ascii_hexdigit()))
        })
    {
        let (bits, used, range) = parse_hex(&s[i + 2..], f);
        return (sign | bits, i + 2 + used, range);
    }
    // Decimal: digits, a point, digits, an exponent.
    let mut digits = Vec::new();
    let mut sticky = false;
    let mut e10: i64 = 0;
    let mut seen = false;
    let mut point = false;
    let mut j = i;
    while let Some(&c) = s.get(j) {
        if c.is_ascii_digit() {
            seen = true;
            if digits.is_empty() && c == b'0' {
                if point {
                    e10 -= 1;
                }
            } else if digits.len() < MAX_DIGITS {
                digits.push(c);
                if point {
                    e10 -= 1;
                }
            } else {
                sticky |= c != b'0';
                if !point {
                    e10 += 1;
                }
            }
        } else if c == b'.' && !point {
            point = true;
        } else {
            break;
        }
        j += 1;
    }
    if !seen {
        return (0, 0, false);
    }
    if matches!(s.get(j), Some(b'e' | b'E')) {
        let mut k = j + 1;
        let mut eneg = false;
        if let Some(&c) = s.get(k).filter(|&&c| c == b'+' || c == b'-') {
            eneg = c == b'-';
            k += 1;
        }
        if s.get(k).is_some_and(|c| c.is_ascii_digit()) {
            let mut v: i64 = 0;
            while let Some(c) = s.get(k).filter(|c| c.is_ascii_digit()) {
                v = (v * 10 + i64::from(c - b'0')).min(1 << 40);
                k += 1;
            }
            e10 += if eneg { -v } else { v };
            j = k;
        }
    }
    let e10 = e10.clamp(-100_000, 100_000) as i32;
    let (bits, range) = decimal_bits(&digits, e10, sticky, f);
    (sign | bits, j, range)
}

/// The hexadecimal form after "0x": digits, a point, digits, then an
/// optional binary exponent `p±d`.
fn parse_hex(s: &[u8], f: Format) -> (u64, usize, bool) {
    let mut q: u128 = 0;
    let mut exp: i64 = 0;
    let mut sticky = false;
    let mut point = false;
    let mut j = 0;
    while let Some(&c) = s.get(j) {
        if let Some(v) = (c as char).to_digit(16) {
            if q >> 120 == 0 {
                q = q << 4 | u128::from(v);
                if point {
                    exp -= 4;
                }
            } else {
                sticky |= v != 0;
                if !point {
                    exp += 4;
                }
            }
        } else if c == b'.' && !point {
            point = true;
        } else {
            break;
        }
        j += 1;
    }
    if matches!(s.get(j), Some(b'p' | b'P')) {
        let mut k = j + 1;
        let mut eneg = false;
        if let Some(&c) = s.get(k).filter(|&&c| c == b'+' || c == b'-') {
            eneg = c == b'-';
            k += 1;
        }
        if s.get(k).is_some_and(|c| c.is_ascii_digit()) {
            let mut v: i64 = 0;
            while let Some(c) = s.get(k).filter(|c| c.is_ascii_digit()) {
                v = (v * 10 + i64::from(c - b'0')).min(1 << 40);
                k += 1;
            }
            exp += if eneg { -v } else { v };
            j = k;
        }
    }
    let exp = exp.clamp(-100_000, 100_000) as i32;
    let (bits, range) = round_bits(q, exp, sticky, f);
    (bits, j, range)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::String;

    fn fmt(x: f64, conv: u8, prec: Option<usize>, alt: bool) -> String {
        let (neg, _, body) = format(x, conv, prec, alt);
        let mut s = String::from(if neg { "-" } else { "" });
        s.push_str(core::str::from_utf8(&body).unwrap());
        s
    }

    unsafe extern "C" {
        /// The host's C library, to compare with.
        #[link_name = "snprintf"]
        fn host_snprintf(buf: *mut u8, n: usize, fmt: *const u8, ...) -> i32;
    }

    fn host(x: f64, conv: u8, prec: Option<usize>, alt: bool) -> String {
        let mut f = String::from("%");
        if alt {
            f.push('#');
        }
        if let Some(p) = prec {
            f.push_str(&std::format!(".{p}"));
        }
        f.push(conv as char);
        f.push('\0');
        let mut buf = [0u8; 2048];
        // SAFETY: A NUL-terminated format with one double.
        let n = unsafe { host_snprintf(buf.as_mut_ptr(), buf.len(), f.as_ptr(), x) };
        String::from_utf8(buf[..n as usize].to_vec()).unwrap()
    }

    /// A deterministic spread of doubles: random bit patterns, plus
    /// numbers near decimal boundaries.
    fn samples() -> Vec<f64> {
        let mut v = vec![
            0.0,
            -0.0,
            1.0,
            0.5,
            1.5,
            2.5,
            0.125,
            9.5,
            99.5,
            0.05,
            0.15,
            0.25,
            0.35,
            1e-5,
            123456.789,
            1e21,
            1e22,
            1e100,
            5e-324,
            2.2250738585072014e-308,
            1.7976931348623157e308,
            0.1,
            0.2,
            0.3,
            2.0 / 3.0,
            999999.5,
            9.999999e9,
            1e-300,
            4.35,
            0.000123456,
            1234567890123456789.0,
        ];
        let mut s: u64 = 0x9e3779b97f4a7c15;
        for _ in 0..1000 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let x = f64::from_bits(s);
            if x.is_finite() {
                v.push(x);
            }
            // Ordinary magnitudes too.
            v.push((s >> 11) as f64 / (1u64 << 30) as f64 * if s & 1 == 1 { 1e-3 } else { 1e3 });
        }
        v
    }

    #[test]
    fn matches_host_printf() {
        for x in samples() {
            for &conv in b"fegEGa" {
                for prec in [None, Some(0), Some(3), Some(17)] {
                    if conv == b'f' && x.abs() > 1e30 && prec == Some(17) {
                        continue;
                    }
                    for alt in [false, true] {
                        // glibc drops %#g's zeros when rounding carries into
                        // a new digit ("1.e+06" for 999999.5); C11 keeps them.
                        let want = host(x, conv, prec, alt);
                        if alt && (want.contains(".e") || want.contains(".E")) {
                            continue;
                        }
                        assert_eq!(
                            fmt(x, conv, prec, alt),
                            host(x, conv, prec, alt),
                            "{x:e} %{} {prec:?} {alt}",
                            conv as char
                        );
                    }
                }
            }
        }
        for x in [f64::INFINITY, f64::NEG_INFINITY, f64::NAN] {
            assert_eq!(fmt(x, b'f', None, false), host(x, b'f', None, false));
            assert_eq!(fmt(x, b'G', None, false), host(x, b'G', None, false));
        }
    }

    #[test]
    fn exact_digits() {
        assert_eq!(fmt(0.1, b'f', Some(30), false), "0.100000000000000005551115123126");
        assert_eq!(fmt(5e-324, b'e', Some(5), false), "4.94066e-324");
        assert_eq!(fmt(1e23, b'f', Some(0), false), "99999999999999991611392");
        assert_eq!(fmt(0.5, b'f', Some(0), false), "0");
        assert_eq!(fmt(1.5, b'f', Some(0), false), "2");
        assert_eq!(fmt(2.5, b'f', Some(0), false), "2");
        assert_eq!(fmt(100.0, b'g', None, false), "100");
        assert_eq!(fmt(1e-5, b'g', None, false), "1e-05");
        assert_eq!(fmt(1.0, b'a', None, false), "0x1p+0");
    }

    fn strtod(s: &str) -> (f64, usize, bool) {
        let (b, n, r) = parse(s.as_bytes(), DOUBLE);
        (f64::from_bits(b), n, r)
    }

    #[test]
    fn parses_like_rust() {
        // Rust's own parser rounds correctly; the printed forms of the
        // samples must come back to the same bits.
        for x in samples() {
            for t in [std::format!("{x:e}"), std::format!("{x:.25e}"), std::format!("{x}"), fmt(x, b'a', None, false)] {
                let (y, n, _) = strtod(&t);
                assert_eq!((y.to_bits(), n), (x.to_bits(), t.len()), "{t}");
            }
        }
        for t in [
            "1.00000000000000011102230246251565404236316680908203125",
            "2.2250738585072011e-308",
            "9007199254740993",
            "0.1e-320",
            "1e-400",
            "123e-2",
        ] {
            let want: f64 = t.parse().unwrap();
            assert_eq!(strtod(t).0.to_bits(), want.to_bits(), "{t}");
        }
        assert_eq!(strtod("  -12.5e1xyz"), (-125.0, 9, false));
        assert_eq!(strtod("1e999"), (f64::INFINITY, 5, true));
        assert_eq!(strtod("1e-999"), (0.0, 6, true));
        assert_eq!(strtod("-inf").0, f64::NEG_INFINITY);
        assert_eq!(strtod("INFINITY").1, 8);
        assert!(strtod("nan(abc)").0.is_nan() && strtod("nan(abc)").1 == 8);
        assert_eq!(strtod("0x1.8p1"), (3.0, 7, false));
        assert_eq!(strtod("0x"), (0.0, 1, false));
        assert_eq!(strtod("."), (0.0, 0, false));
        assert_eq!(strtod("1e"), (1.0, 1, false));
        let (b, n, _) = parse(b"0.1", SINGLE);
        assert_eq!((f32::from_bits(b as u32), n), (0.1f32, 3));
        let (b, _, _) = parse(b"3.4028236e38", SINGLE);
        assert!(f32::from_bits(b as u32).is_infinite());
        for x in samples() {
            let x = x as f32;
            if x.is_finite() {
                let t = std::format!("{x:e}");
                let (b, _, _) = parse(t.as_bytes(), SINGLE);
                assert_eq!(b as u32, x.to_bits(), "{t}");
            }
        }
    }
}
