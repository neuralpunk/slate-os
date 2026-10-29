// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integers of any size, for `awk -M` (ADR 0165): gawk's arbitrary
//! precision, where integers stay exact however large and other numbers
//! are doubles (PREC's default, 53 bits, is a double's precision).

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

/// An integer: a sign and the magnitude's 32-bit limbs, lowest first (no
/// high zero limbs; zero is no limbs and not negative).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Big {
    neg: bool,
    mag: Vec<u32>,
}

fn trim(mut m: Vec<u32>) -> Vec<u32> {
    while m.last() == Some(&0) {
        m.pop();
    }
    m
}

fn cmp_mag(a: &[u32], b: &[u32]) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.iter().rev().cmp(b.iter().rev()))
}

fn add_mag(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(a.len().max(b.len()) + 1);
    let mut carry = 0u64;
    for i in 0..a.len().max(b.len()) {
        let s = u64::from(*a.get(i).unwrap_or(&0)) + u64::from(*b.get(i).unwrap_or(&0)) + carry;
        out.push(s as u32);
        carry = s >> 32;
    }
    if carry > 0 {
        out.push(carry as u32);
    }
    out
}

/// `a - b` for `a >= b`.
fn sub_mag(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(a.len());
    let mut borrow = 0i64;
    for (i, &x) in a.iter().enumerate() {
        let mut d = i64::from(x) - i64::from(*b.get(i).unwrap_or(&0)) - borrow;
        borrow = 0;
        if d < 0 {
            d += 1 << 32;
            borrow = 1;
        }
        out.push(d as u32);
    }
    trim(out)
}

fn mul_mag(a: &[u32], b: &[u32]) -> Vec<u32> {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    let mut out = alloc::vec![0u32; a.len() + b.len()];
    for (i, &x) in a.iter().enumerate() {
        let mut carry = 0u64;
        for (j, &y) in b.iter().enumerate() {
            let t = u64::from(x) * u64::from(y) + u64::from(out[i + j]) + carry;
            out[i + j] = t as u32;
            carry = t >> 32;
        }
        out[i + b.len()] = carry as u32;
    }
    trim(out)
}

/// `a / d` and `a % d` for a one-limb divisor.
fn divmod_small(a: &[u32], d: u32) -> (Vec<u32>, u32) {
    let mut q = alloc::vec![0u32; a.len()];
    let mut r = 0u64;
    for i in (0..a.len()).rev() {
        let cur = (r << 32) | u64::from(a[i]);
        q[i] = (cur / u64::from(d)) as u32;
        r = cur % u64::from(d);
    }
    (trim(q), r as u32)
}

fn bits(a: &[u32]) -> usize {
    a.last().map_or(0, |&top| (a.len() - 1) * 32 + (32 - top.leading_zeros() as usize))
}

fn bit(a: &[u32], i: usize) -> bool {
    a.get(i / 32).is_some_and(|&l| l >> (i % 32) & 1 == 1)
}

/// `a / b` and `a % b` (b not zero), by shifting and subtracting.
fn divmod_mag(a: &[u32], b: &[u32]) -> (Vec<u32>, Vec<u32>) {
    if cmp_mag(a, b) == Ordering::Less {
        return (Vec::new(), a.to_vec());
    }
    if b.len() == 1 {
        let (q, r) = divmod_small(a, b[0]);
        return (q, trim(alloc::vec![r]));
    }
    let n = bits(a);
    let mut q = alloc::vec![0u32; a.len()];
    let mut r: Vec<u32> = Vec::new();
    for i in (0..n).rev() {
        // r = r * 2 + bit i of a.
        let mut carry = u32::from(bit(a, i));
        for l in r.iter_mut() {
            let next = *l >> 31;
            *l = (*l << 1) | carry;
            carry = next;
        }
        if carry > 0 {
            r.push(carry);
        }
        if cmp_mag(&r, b) != Ordering::Less {
            r = sub_mag(&r, b);
            q[i / 32] |= 1 << (i % 32);
        }
    }
    (trim(q), trim(r))
}

impl Big {
    pub fn from_i64(v: i64) -> Big {
        let m = v.unsigned_abs();
        Big { neg: v < 0, mag: trim(alloc::vec![m as u32, (m >> 32) as u32]) }
    }

    /// An integral, finite double exactly.
    pub fn from_f64(v: f64) -> Option<Big> {
        if !v.is_finite() || v != libm_trunc(v) {
            return None;
        }
        let neg = v < 0.0;
        let bits = v.abs().to_bits();
        let exp = ((bits >> 52) & 0x7ff) as i32;
        if exp == 0 {
            return Some(Big::default());
        }
        let mant = (bits & ((1 << 52) - 1)) | (1 << 52);
        let shift = exp - 1075;
        let mut b = Big { neg: false, mag: trim(alloc::vec![mant as u32, (mant >> 32) as u32]) };
        if shift >= 0 {
            b = b.shl(shift as usize);
        } else {
            b.mag = trim(divmod_mag(&b.mag, &Big::from_i64(1).shl((-shift) as usize).mag).0);
        }
        b.neg = neg && !b.mag.is_empty();
        Some(b)
    }

    fn shl(mut self, n: usize) -> Big {
        let (limbs, bits) = (n / 32, n % 32);
        if bits > 0 {
            let mut carry = 0u32;
            for l in self.mag.iter_mut() {
                let next = *l >> (32 - bits);
                *l = (*l << bits) | carry;
                carry = next;
            }
            if carry > 0 {
                self.mag.push(carry);
            }
        }
        let mut m = alloc::vec![0u32; limbs];
        m.extend(self.mag);
        self.mag = trim(m);
        self
    }

    /// Decimal digits (an optional sign, blanks around), or `0x` hex.
    pub fn parse(s: &[u8]) -> Option<Big> {
        let s = s.trim_ascii();
        let (neg, digits) = match s.split_first()? {
            (b'-', r) => (true, r),
            (b'+', r) => (false, r),
            _ => (false, s),
        };
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let mut mag: Vec<u32> = Vec::new();
        for &d in digits {
            mag = mul_mag(&mag, &[10]);
            mag = add_mag(&mag, &[u32::from(d - b'0')]);
            mag = trim(mag);
        }
        Some(Big { neg: neg && !mag.is_empty(), mag })
    }

    pub fn is_zero(&self) -> bool {
        self.mag.is_empty()
    }

    pub fn to_f64(&self) -> f64 {
        let v = self.mag.iter().rev().fold(0.0f64, |acc, &l| acc * 4_294_967_296.0 + f64::from(l));
        if self.neg { -v } else { v }
    }

    pub fn neg(mut self) -> Big {
        self.neg = !self.neg && !self.mag.is_empty();
        self
    }

    pub fn add(&self, o: &Big) -> Big {
        if self.neg == o.neg {
            return Big { neg: self.neg, mag: trim(add_mag(&self.mag, &o.mag)) };
        }
        match cmp_mag(&self.mag, &o.mag) {
            Ordering::Equal => Big::default(),
            Ordering::Greater => Big { neg: self.neg, mag: sub_mag(&self.mag, &o.mag) },
            Ordering::Less => Big { neg: o.neg, mag: sub_mag(&o.mag, &self.mag) },
        }
    }

    pub fn sub(&self, o: &Big) -> Big {
        self.add(&o.clone().neg())
    }

    pub fn mul(&self, o: &Big) -> Big {
        let mag = mul_mag(&self.mag, &o.mag);
        Big { neg: self.neg != o.neg && !mag.is_empty(), mag }
    }

    /// Quotient and remainder, truncated toward zero (C's, awk's `%`);
    /// None for a zero divisor.
    pub fn divmod(&self, o: &Big) -> Option<(Big, Big)> {
        if o.is_zero() {
            return None;
        }
        let (q, r) = divmod_mag(&self.mag, &o.mag);
        let q = Big { neg: self.neg != o.neg && !q.is_empty(), mag: q };
        let r = Big { neg: self.neg && !r.is_empty(), mag: r };
        Some((q, r))
    }

    pub fn pow(&self, mut e: u64) -> Big {
        let (mut base, mut acc) = (self.clone(), Big::from_i64(1));
        while e > 0 {
            if e & 1 == 1 {
                acc = acc.mul(&base);
            }
            e >>= 1;
            if e > 0 {
                base = base.mul(&base);
            }
        }
        acc
    }

    pub fn cmp(&self, o: &Big) -> Ordering {
        match (self.neg, o.neg) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (false, false) => cmp_mag(&self.mag, &o.mag),
            (true, true) => cmp_mag(&o.mag, &self.mag),
        }
    }

    /// The decimal digits, with a `-` when negative.
    pub fn text(&self) -> String {
        if self.mag.is_empty() {
            return String::from("0");
        }
        let mut chunks = Vec::new();
        let mut m = self.mag.clone();
        while !m.is_empty() {
            let (q, r) = divmod_small(&m, 1_000_000_000);
            chunks.push(r);
            m = q;
        }
        let mut s = String::from(if self.neg { "-" } else { "" });
        s.push_str(&alloc::format!("{}", chunks.pop().unwrap_or(0)));
        for c in chunks.iter().rev() {
            s.push_str(&alloc::format!("{c:09}"));
        }
        s
    }
}

fn libm_trunc(v: f64) -> f64 {
    super::math::trunc(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(s: &str) -> Big {
        Big::parse(s.as_bytes()).unwrap()
    }

    #[test]
    fn arithmetic() {
        assert_eq!(Big::from_i64(2).pow(100).text(), "1267650600228229401496703205376");
        let f = (1..=30).fold(Big::from_i64(1), |acc, i| acc.mul(&Big::from_i64(i)));
        assert_eq!(f.text(), "265252859812191058636308480000000");
        let x = b("123456789012345678901234567890");
        let y = b("-987654321098765432109876543210");
        assert_eq!(x.add(&y).text(), "-864197532086419753208641975320");
        assert_eq!(x.sub(&y).text(), "1111111110111111111011111111100");
        let (q, r) = y.divmod(&b("12345678901234567")).unwrap();
        assert_eq!((q.text(), r.text()), (String::from("-80000000729000"), String::from("-153109877200210")));
        assert_eq!(q.mul(&b("12345678901234567")).add(&r), y, "q * d + r");
        assert!(x.divmod(&Big::default()).is_none());
        assert_eq!(x.cmp(&y), Ordering::Greater);
        assert_eq!(Big::from_f64(1e20).unwrap().text(), "100000000000000000000");
        assert_eq!(Big::from_f64(-3.0).unwrap().text(), "-3");
        assert!(Big::from_f64(0.5).is_none());
        assert_eq!(b("-0").text(), "0");
        assert!((b("4611686018427387904").to_f64() - 4.611686018427388e18).abs() < 1.0);
    }
}
