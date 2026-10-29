// SPDX-License-Identifier: MIT OR Apache-2.0

//! Slate's floating-point functions (ADR 0074): the core of slate-libc's
//! <math.h>, for Rust programs too (the calculator, ADR 0104). The names
//! end in `_` as they did inside slate-libc; [`f64`]-only, no errno
//! (slate-libc sets it). The algorithms, from the textbook methods:
//!
//! - argument reduction by a multiple of ln 2 or π/2, with the constant
//!   split so that the products are exact (Cody and Waite). Sines of huge
//!   arguments use 1536 bits of 2/π (Payne and Hanek);
//! - Taylor series on the reduced range, carried far enough that the
//!   truncation is below the last bit;
//! - double-double arithmetic (error-free sums and products, Dekker's
//!   split, since the baseline x86-64 has no fused multiply-add) where
//!   one extra word of precision is needed: log and exp under pow, exp2,
//!   log2, log10, log1p, hypot, cbrt's last step;
//! - exact integer arithmetic for fmod, remainder and fma.
//!
//! The constants (ln 2, π/2, 2/π and the like) were computed to 400 bits
//! with mpmath and rounded. Results are within one or two units in the
//! last place of the correctly rounded value (the tests compare with the
//! host's C library over many arguments), not always correctly rounded.
//!
//! Domain errors give NaN, and poles and overflows infinities; slate-libc
//! turns them into `errno`.

#![no_std]

// --- constants ----------------------------------------------------------------

/// ln 2 rounded to 32 bits (so k·LN2_HI is exact for |k| < 2^21), and the
/// rest.
pub const LN2_HI: f64 = 0.6931471806019545;
pub const LN2_LO: f64 = -4.2009150726810846e-11;
/// ln 2 as a double-double.
pub const LN2: f64 = core::f64::consts::LN_2;
pub const LN2_DLO: f64 = 2.3190468138462996e-17;
/// 1/ln 2 and 1/ln 10 as double-doubles.
pub const INV_LN2: f64 = core::f64::consts::LOG2_E;
pub const INV_LN2_LO: f64 = 2.0355273740931033e-17;
pub const INV_LN10: f64 = core::f64::consts::LOG10_E;
pub const INV_LN10_LO: f64 = 1.098319650216765e-17;
/// π/2 in pieces of 33, 33 and 53 bits, and what is left.
pub const PIO2_1: f64 = 1.5707963267341256;
pub const PIO2_2: f64 = 6.077100506303966e-11;
pub const PIO2_3: f64 = 2.0222662487959506e-21;
pub const PIO2_3LO: f64 = 1.0085854035872483e-37;
/// π/2, π, π/4, atan(1/2) and atan(3/2) as double-doubles.
pub const PIO2_HI: f64 = core::f64::consts::FRAC_PI_2;
pub const PIO2_LO: f64 = 6.123233995736766e-17;
pub const PI_HI: f64 = core::f64::consts::PI;
pub const PI_LO: f64 = 1.2246467991473532e-16;
pub const PIO4_HI: f64 = core::f64::consts::FRAC_PI_4;
pub const PIO4_LO: f64 = 3.061616997868383e-17;
pub const ATAN_HALF_HI: f64 = 0.4636476090008061;
pub const ATAN_HALF_LO: f64 = 2.2698777452961687e-17;
pub const ATAN_3HALF_HI: f64 = 0.982793723247329;
pub const ATAN_3HALF_LO: f64 = 1.3903311031230998e-17;
pub const TWO_OVER_PI: f64 = core::f64::consts::FRAC_2_PI;
pub const SQRT2: f64 = core::f64::consts::SQRT_2;

/// 2/π: 1536 bits after the binary point, most significant first.
pub const TWO_OVER_PI_BITS: [u32; 48] = [
    0xa2f9836e, 0x4e441529, 0xfc2757d1, 0xf534ddc0, 0xdb629599, 0x3c439041, 0xfe5163ab, 0xdebbc561, 0xb7246e3a,
    0x424dd2e0, 0x06492eea, 0x09d1921c, 0xfe1deb1c, 0xb129a73e, 0xe88235f5, 0x2ebb4484, 0xe99c7026, 0xb45f7e41,
    0x3991d639, 0x835339f4, 0x9c845f8b, 0xbdf9283b, 0x1ff897ff, 0xde05980f, 0xef2f118b, 0x5a0a6d1f, 0x6d367ecf,
    0x27cb09b7, 0x4f463f66, 0x9e5fea2d, 0x7527bac7, 0xebe5f17b, 0x3d0739f7, 0x8a5292ea, 0x6bfb5fb1, 0x1f8d5d08,
    0x56033046, 0xfc7b6bab, 0xf0cfbc20, 0x9af4361d, 0xa9e39161, 0x5ee61b08, 0x6599855f, 0x14a06840, 0x8dffd880,
    0x4d732731, 0x06061556, 0xca73a8c9,
];

/// 1/n! for n = 0..=18 (the factorials are exact doubles).
pub const INV_FACT: [f64; 19] = [
    1.0,
    1.0,
    1.0 / 2.0,
    1.0 / 6.0,
    1.0 / 24.0,
    1.0 / 120.0,
    1.0 / 720.0,
    1.0 / 5040.0,
    1.0 / 40320.0,
    1.0 / 362880.0,
    1.0 / 3628800.0,
    1.0 / 39916800.0,
    1.0 / 479001600.0,
    1.0 / 6227020800.0,
    1.0 / 87178291200.0,
    1.0 / 1307674368000.0,
    1.0 / 20922789888000.0,
    1.0 / 355687428096000.0,
    1.0 / 6402373705728000.0,
];

// --- double-double arithmetic -------------------------------------------------

/// a + b exactly, as (sum, error).
#[inline]
pub fn two_sum(a: f64, b: f64) -> (f64, f64) {
    let s = a + b;
    let bb = s - a;
    (s, (a - (s - bb)) + (b - bb))
}

/// As [`two_sum`], for |a| ≥ |b|.
#[inline]
pub fn fast_two_sum(a: f64, b: f64) -> (f64, f64) {
    let s = a + b;
    (s, b - (s - a))
}

/// a = hi + lo, each with at most 26 significant bits (Dekker).
#[inline]
pub fn split(a: f64) -> (f64, f64) {
    let c = 134217729.0 * a;
    let hi = c - (c - a);
    (hi, a - hi)
}

/// a·b exactly, as (product, error).
#[inline]
pub fn two_prod(a: f64, b: f64) -> (f64, f64) {
    let p = a * b;
    let (ah, al) = split(a);
    let (bh, bl) = split(b);
    (p, ((ah * bh - p) + ah * bl + al * bh) + al * bl)
}

/// A polynomial in Horner form: c[0] + x·(c[1] + x·(...)).
#[inline]
pub fn poly(x: f64, c: &[f64]) -> f64 {
    c.iter().rev().fold(0.0, |acc, &k| acc * x + k)
}

// --- bits ---------------------------------------------------------------------

pub fn copysign_(x: f64, s: f64) -> f64 {
    f64::from_bits((x.to_bits() & !(1 << 63)) | (s.to_bits() & (1 << 63)))
}

pub fn fabs_(x: f64) -> f64 {
    f64::from_bits(x.to_bits() & !(1 << 63))
}

/// x·2^n, rounding once.
pub fn ldexp_(mut x: f64, mut n: i32) -> f64 {
    const P1023: f64 = f64::from_bits(0x7fe0_0000_0000_0000);
    // 2^-969: 2^-1022·2^53, staying clear of subnormals until the last step.
    const M969: f64 = f64::from_bits(0x0360_0000_0000_0000);
    if n > 1023 {
        x *= P1023;
        n -= 1023;
        if n > 1023 {
            x *= P1023;
            n = (n - 1023).min(1023);
        }
    } else if n < -1022 {
        x *= M969;
        n += 969;
        if n < -1022 {
            x *= M969;
            n = (n + 969).max(-1022);
        }
    }
    x * f64::from_bits(((0x3ff + n) as u64) << 52)
}

/// x = m·2^e with m an integer (53 bits for normal numbers).
pub fn mant_exp(x: f64) -> (u64, i32) {
    let b = x.to_bits() & !(1 << 63);
    let (exp, frac) = ((b >> 52) as i32, b & ((1 << 52) - 1));
    if exp == 0 { (frac, -1074) } else { (frac | 1 << 52, exp - 1075) }
}

pub fn trunc_(x: f64) -> f64 {
    let b = x.to_bits();
    let e = ((b >> 52) & 0x7ff) as i32 - 1023;
    if e >= 52 {
        return x;
    }
    if e < 0 {
        return f64::from_bits(b & 1 << 63);
    }
    f64::from_bits(b & !((1u64 << (52 - e)) - 1))
}

pub fn floor_(x: f64) -> f64 {
    let t = trunc_(x);
    if t > x { t - 1.0 } else { t }
}

pub fn ceil_(x: f64) -> f64 {
    let t = trunc_(x);
    if t < x { t + 1.0 } else { t }
}

/// Halfway cases away from zero.
pub fn round_(x: f64) -> f64 {
    let t = trunc_(x);
    if fabs_(x - t) >= 0.5 { t + copysign_(1.0, x) } else { t }
}

/// To nearest, ties to even (the default rounding).
pub fn rint_(x: f64) -> f64 {
    const TWO52: f64 = 4503599627370496.0;
    if x.is_nan() || fabs_(x) >= TWO52 {
        return x;
    }
    let t = copysign_(TWO52, x);
    copysign_((x + t) - t, x)
}

pub fn is_int(x: f64) -> bool {
    x.is_finite() && trunc_(x) == x
}

pub fn is_odd_int(x: f64) -> bool {
    is_int(x) && fabs_(x) < 9007199254740992.0 && (x as i64) & 1 == 1
}

pub fn sqrt_(x: f64) -> f64 {
    let mut r = x;
    // SAFETY: sqrtsd only reads and writes the register (SSE2 is the
    // target's baseline).
    unsafe { core::arch::asm!("sqrtsd {0}, {0}", inout(xmm_reg) r, options(pure, nomem, nostack)) };
    r
}

// --- exp ----------------------------------------------------------------------

/// exp(x + xlo) = 2^k·(1 + q): (k, q). |x| up to about 746.
pub fn exp_core(x: f64, xlo: f64) -> (i32, f64) {
    let k = rint_(x * INV_LN2);
    let hi = x - k * LN2_HI;
    let lo = k * LN2_LO - xlo;
    let r = hi - lo;
    let c = (hi - r) - lo;
    // expm1(r) = r + r²·(1/2! + r/3! + ... + r^11/13!), |r| ≤ 0.35.
    let p = poly(r, &INV_FACT[2..14]);
    (k as i32, r + (c + c * r + r * r * p))
}

pub const EXP_MAX: f64 = 709.782712893384;
pub const EXP_MIN: f64 = -745.1332191019412;

pub fn exp_(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    if x > EXP_MAX {
        return f64::INFINITY;
    }
    if x < EXP_MIN {
        return 0.0;
    }
    if fabs_(x) < 1.0e-18 {
        return 1.0 + x;
    }
    let (k, q) = exp_core(x, 0.0);
    ldexp_(1.0 + q, k)
}

/// exp(hi + lo) for a double-double exponent.
pub fn exp_dd(hi: f64, lo: f64) -> f64 {
    if hi > EXP_MAX + 1.0 {
        return f64::INFINITY;
    }
    if hi < EXP_MIN - 1.0 {
        return 0.0;
    }
    let (k, q) = exp_core(hi, lo);
    ldexp_(1.0 + q, k)
}

pub fn expm1_(x: f64) -> f64 {
    if x.is_nan() || fabs_(x) < 5.5e-17 {
        return x;
    }
    if x > EXP_MAX {
        return f64::INFINITY;
    }
    if x < -38.0 {
        return -1.0;
    }
    let (k, q) = exp_core(x, 0.0);
    if k == 0 {
        return q;
    }
    if !(-53..=56).contains(&k) {
        return ldexp_(1.0 + q, k) - 1.0;
    }
    let two = ldexp_(1.0, k);
    (two - 1.0) + two * q
}

pub fn exp2_(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    if x >= 1024.0 {
        return f64::INFINITY;
    }
    if x < -1080.0 {
        return 0.0;
    }
    if is_int(x) {
        return ldexp_(1.0, x as i32);
    }
    let (p, e) = two_prod(x, LN2);
    exp_dd(p, e + x * LN2_DLO)
}

// --- log ----------------------------------------------------------------------

/// log(x) for finite x > 0, as a double-double, and whether x is a power
/// of two (then log2 is exactly k).
pub fn log_dd(x: f64) -> (f64, f64, i32, bool) {
    let (mut m, mut k) = (x, 0);
    if x.to_bits() < 1 << 52 {
        m *= 18014398509481984.0; // 2^54
        k = -54;
    }
    let b = m.to_bits();
    k += (b >> 52) as i32 - 1023;
    let pow2 = b & ((1 << 52) - 1) == 0;
    let mut m = f64::from_bits((b & ((1 << 52) - 1)) | 0x3ff << 52);
    if m > SQRT2 {
        m *= 0.5;
        k += 1;
    }
    // log m = 2·atanh(s), s = f/(2 + f), f = m - 1 (exact).
    let f = m - 1.0;
    let (d, dlo) = fast_two_sum(2.0, f);
    let s = f / d;
    let (p, pe) = two_prod(s, d);
    let slo = (((f - p) - pe) - s * dlo) / d;
    let z = s * s;
    // 2s³·(1/3 + z/5 + ... + z^10/23), |s| ≤ 0.172.
    const C: [f64; 11] = [
        1.0 / 3.0,
        1.0 / 5.0,
        1.0 / 7.0,
        1.0 / 9.0,
        1.0 / 11.0,
        1.0 / 13.0,
        1.0 / 15.0,
        1.0 / 17.0,
        1.0 / 19.0,
        1.0 / 21.0,
        1.0 / 23.0,
    ];
    let t = 2.0 * s * z * poly(z, &C);
    let (hi, lo) = fast_two_sum(2.0 * s, 2.0 * slo + t);
    let kf = k as f64;
    let (a, ae) = two_sum(kf * LN2_HI, hi);
    let (rh, rl) = fast_two_sum(a, ae + lo + kf * LN2_LO);
    (rh, rl, k, pow2)
}

/// The special cases shared by the logarithms: Some(result) for x ≤ 0,
/// infinities and NaN.
pub fn log_special(x: f64) -> Option<f64> {
    if x.is_nan() || x == f64::INFINITY {
        Some(x)
    } else if x == 0.0 {
        Some(f64::NEG_INFINITY)
    } else if x < 0.0 {
        Some(f64::NAN)
    } else {
        None
    }
}

pub fn log_(x: f64) -> f64 {
    if let Some(r) = log_special(x) {
        return r;
    }
    if x == 1.0 {
        return 0.0;
    }
    log_dd(x).0
}

pub fn log2_(x: f64) -> f64 {
    if let Some(r) = log_special(x) {
        return r;
    }
    let (hi, lo, k, pow2) = log_dd(x);
    if pow2 {
        return k as f64;
    }
    let (p, e) = two_prod(hi, INV_LN2);
    p + (e + hi * INV_LN2_LO + lo * INV_LN2)
}

pub fn log10_(x: f64) -> f64 {
    if let Some(r) = log_special(x) {
        return r;
    }
    // Exact powers of ten give their exponent.
    let mut p = 1.0;
    for n in 0..=22 {
        if x == p {
            return n as f64;
        }
        p *= 10.0;
    }
    let (hi, lo, _, _) = log_dd(x);
    let (p, e) = two_prod(hi, INV_LN10);
    p + (e + hi * INV_LN10_LO + lo * INV_LN10)
}

pub fn log1p_(x: f64) -> f64 {
    if x.is_nan() || x == f64::INFINITY {
        return x;
    }
    if x == -1.0 {
        return f64::NEG_INFINITY;
    }
    if x < -1.0 {
        return f64::NAN;
    }
    if fabs_(x) < 5.5e-17 {
        return x;
    }
    // u = 1 + x exactly as a double-double; log(u) + ulo/u.
    let (u, ulo) = two_sum(1.0, x);
    let (hi, lo, _, _) = log_dd(u);
    hi + (lo + ulo / u)
}

// --- pow ----------------------------------------------------------------------

pub fn pow_(x: f64, y: f64) -> f64 {
    if y == 0.0 || x == 1.0 {
        return 1.0;
    }
    if x.is_nan() || y.is_nan() {
        return f64::NAN;
    }
    let y_odd = is_odd_int(y);
    if x == 0.0 {
        return match (y < 0.0, y_odd) {
            (true, true) => copysign_(f64::INFINITY, x),
            (true, false) => f64::INFINITY,
            (false, true) => x,
            (false, false) => 0.0,
        };
    }
    if y.is_infinite() {
        let ax = fabs_(x);
        return if ax == 1.0 {
            1.0
        } else if (ax < 1.0) == (y < 0.0) {
            f64::INFINITY
        } else {
            0.0
        };
    }
    if x.is_infinite() {
        let neg = x < 0.0 && y_odd;
        let r = if y < 0.0 { 0.0 } else { f64::INFINITY };
        return if neg { -r } else { r };
    }
    if x < 0.0 && !is_int(y) {
        return f64::NAN;
    }
    let sign = if x < 0.0 && y_odd { -1.0 } else { 1.0 };
    let ax = fabs_(x);
    let (lh, ll, k, pow2) = log_dd(ax);
    // A power of two to an integer power is exact.
    if pow2 && is_int(y) && fabs_(y) < 1e5 {
        return sign * ldexp_(1.0, (k as f64 * y).clamp(-3000.0, 3000.0) as i32);
    }
    let p = y * lh;
    if p > EXP_MAX + 1.0 {
        return sign * f64::INFINITY;
    }
    if p < EXP_MIN - 1.0 {
        return sign * 0.0;
    }
    let (zh, ze) = two_prod(y, lh);
    let (zh, zl) = fast_two_sum(zh, ze + y * ll);
    let mut r = exp_dd(zh, zl);
    // An integer to a non-negative integer power is an integer: when it
    // fits, the error above cannot reach half a unit, so rounding to the
    // nearest integer gives it exactly.
    if is_int(ax) && is_int(y) && y > 0.0 && r < 9007199254740992.0 {
        r = rint_(r);
    }
    sign * r
}

// --- trigonometry -------------------------------------------------------------

/// Bit `j` (weight 2^-j, j ≥ 1) of 2/π.
pub fn two_over_pi_bit(j: i32) -> u32 {
    if j < 1 || j > 32 * TWO_OVER_PI_BITS.len() as i32 {
        return 0;
    }
    let i = (j - 1) as usize;
    TWO_OVER_PI_BITS[i / 32] >> (31 - i % 32) & 1
}

/// Reduce a large |x| (finite): x·2/π mod 4 from enough bits of 2/π
/// (Payne and Hanek). Returns (k mod 4, r as a double-double) with
/// x = k·π/2 + r, |r| ≤ π/4.
pub fn reduce_large(x: f64) -> (i32, f64, f64) {
    let (m, e) = mant_exp(x);
    // Bits j0..j0+191; bits before j0 only add multiples of 4.
    let j0 = e - 1;
    let mut f = [0u32; 6];
    for i in 0..192 {
        if two_over_pi_bit(j0 + i) != 0 {
            let p = 191 - i;
            f[(p / 32) as usize] |= 1 << (p % 32);
        }
    }
    // P = m·F (m < 2^53): eight 32-bit limbs.
    let mut prod = [0u32; 8];
    let (m0, m1) = (m & 0xffff_ffff, m >> 32);
    for (mi, mv) in [(0, m0), (1, m1)] {
        let mut carry = 0u64;
        for (fi, &fv) in f.iter().enumerate() {
            let v = u64::from(prod[mi + fi]) + mv * u64::from(fv) + carry;
            prod[mi + fi] = v as u32;
            carry = v >> 32;
        }
        let mut at = mi + 6;
        while carry != 0 && at < 8 {
            let v = u64::from(prod[at]) + carry;
            prod[at] = v as u32;
            carry = v >> 32;
            at += 1;
        }
    }
    // x·2/π = P·2^-190: the integer part's low bits, then the fraction's
    // top 128 bits (bits 62..190).
    let bit = |i: u32| u128::from(prod[(i / 32) as usize] >> (i % 32) & 1);
    let mut k = (bit(190) | bit(191) << 1) as i32;
    let t = (0..128).fold(0u128, |v, i| v | bit(62 + i) << i);
    let (u, neg) = if t >> 127 != 0 {
        k += 1;
        (t.wrapping_neg(), true)
    } else {
        (t, false)
    };
    // u·2^-128 as a double-double, times π/2.
    let hi = u as f64;
    let lo = u.wrapping_sub(hi as u128) as i128 as f64;
    let scale = f64::from_bits(((1023 - 128) as u64) << 52);
    let (fh, fl) = (hi * scale, lo * scale);
    let (p, pe) = two_prod(fh, PIO2_HI);
    let (mut rh, mut rl) = fast_two_sum(p, pe + fh * PIO2_LO + fl * PIO2_HI);
    if neg {
        rh = -rh;
        rl = -rl;
    }
    (k & 3, rh, rl)
}

/// x = k·π/2 + r with |r| ≤ about π/4: (k mod 4, r as a double-double).
pub fn reduce(x: f64) -> (i32, f64, f64) {
    let ax = fabs_(x);
    if ax <= PIO4_HI {
        return (0, x, 0.0);
    }
    if ax < 1647099.0 {
        // 2^20·π/2: the products with the 33-bit pieces are exact.
        let k = rint_(x * TWO_OVER_PI);
        let a = x - k * PIO2_1;
        let b = k * PIO2_2;
        let (r1, e1) = two_sum(a, -b);
        let (c, ce) = two_prod(k, PIO2_3);
        let (s, se) = two_sum(r1, -c);
        let (hi, lo) = fast_two_sum(s, se + e1 - ce - k * PIO2_3LO);
        return ((k as i64 & 3) as i32, hi, lo);
    }
    let (k, hi, lo) = reduce_large(ax);
    if x < 0.0 { ((4 - k) & 3, -hi, -lo) } else { (k, hi, lo) }
}

/// sin(x + y) for |x| ≤ about π/4, y a small correction.
pub fn sin_k(x: f64, y: f64) -> f64 {
    let z = x * x;
    // sin x = x + x³·(-1/3! + z/5! - ... + z^7/17!)
    const S: [f64; 8] = [
        -INV_FACT[3],
        INV_FACT[5],
        -INV_FACT[7],
        INV_FACT[9],
        -INV_FACT[11],
        INV_FACT[13],
        -INV_FACT[15],
        INV_FACT[17],
    ];
    x + (z * x * poly(z, &S) + (y - 0.5 * z * y))
}

/// cos(x + y) for |x| ≤ about π/4.
pub fn cos_k(x: f64, y: f64) -> f64 {
    let z = x * x;
    // cos x = 1 - z/2 + z²·(1/4! - z/6! + ... + z^7/18!)
    const C: [f64; 8] = [
        INV_FACT[4],
        -INV_FACT[6],
        INV_FACT[8],
        -INV_FACT[10],
        INV_FACT[12],
        -INV_FACT[14],
        INV_FACT[16],
        -INV_FACT[18],
    ];
    let hz = 0.5 * z;
    let w = 1.0 - hz;
    w + (((1.0 - w) - hz) + (z * z * poly(z, &C) - x * y))
}

pub fn sin_(x: f64) -> f64 {
    if !x.is_finite() {
        return f64::NAN;
    }
    if fabs_(x) < 1.0e-8 {
        return x;
    }
    let (n, hi, lo) = reduce(x);
    match n {
        0 => sin_k(hi, lo),
        1 => cos_k(hi, lo),
        2 => -sin_k(hi, lo),
        _ => -cos_k(hi, lo),
    }
}

pub fn cos_(x: f64) -> f64 {
    if !x.is_finite() {
        return f64::NAN;
    }
    let (n, hi, lo) = reduce(x);
    match n {
        0 => cos_k(hi, lo),
        1 => -sin_k(hi, lo),
        2 => -cos_k(hi, lo),
        _ => sin_k(hi, lo),
    }
}

pub fn tan_(x: f64) -> f64 {
    if !x.is_finite() {
        return f64::NAN;
    }
    if fabs_(x) < 1.0e-8 {
        return x;
    }
    let (n, hi, lo) = reduce(x);
    let (s, c) = (sin_k(hi, lo), cos_k(hi, lo));
    if n & 1 == 0 { s / c } else { -c / s }
}

/// atan t = t + t·z·(-1/3 + z/5 - ... + z^21/45), z = t², |t| ≤ 7/16.
pub const ATAN_C: [f64; 22] = {
    let mut c = [0.0; 22];
    let mut i = 0;
    while i < 22 {
        let v = 1.0 / (2 * i + 3) as f64;
        c[i] = if i % 2 == 0 { -v } else { v };
        i += 1;
    }
    c
};

/// atan for x ≥ 0 (finite).
pub fn atan_pos(x: f64) -> f64 {
    if x < 1.0e-9 {
        return x;
    }
    if x > 1.0e17 {
        return PIO2_HI;
    }
    // Reduce with atan(x) = atan(c) + atan((x - c)/(1 + x·c)).
    let (bh, bl, t) = if x < 7.0 / 16.0 {
        (0.0, 0.0, x)
    } else if x < 11.0 / 16.0 {
        (ATAN_HALF_HI, ATAN_HALF_LO, (2.0 * x - 1.0) / (2.0 + x))
    } else if x < 19.0 / 16.0 {
        (PIO4_HI, PIO4_LO, (x - 1.0) / (x + 1.0))
    } else if x < 39.0 / 16.0 {
        (ATAN_3HALF_HI, ATAN_3HALF_LO, (x - 1.5) / (1.0 + 1.5 * x))
    } else {
        (PIO2_HI, PIO2_LO, -1.0 / x)
    };
    let z = t * t;
    let q = t * z * poly(z, &ATAN_C);
    bh + (t + (q + bl))
}

pub fn atan_(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    copysign_(atan_pos(fabs_(x)), x)
}

pub fn atan2_(y: f64, x: f64) -> f64 {
    if x.is_nan() || y.is_nan() {
        return f64::NAN;
    }
    let left = x.is_sign_negative();
    if y == 0.0 {
        return if left { copysign_(PI_HI, y) } else { y };
    }
    if x == 0.0 {
        return copysign_(PIO2_HI, y);
    }
    if x.is_infinite() {
        return match (y.is_infinite(), left) {
            (true, false) => copysign_(PIO4_HI, y),
            (true, true) => copysign_(3.0 * PIO4_HI, y),
            (false, false) => copysign_(0.0, y),
            (false, true) => copysign_(PI_HI, y),
        };
    }
    if y.is_infinite() {
        return copysign_(PIO2_HI, y);
    }
    let q = fabs_(y / x);
    let a = if q.is_infinite() { PIO2_HI } else { atan_pos(q) };
    let r = if left { PI_HI - (a - PI_LO) } else { a };
    copysign_(r, y)
}

pub fn asin_(x: f64) -> f64 {
    let ax = fabs_(x);
    if x.is_nan() {
        return x;
    }
    if ax > 1.0 {
        return f64::NAN;
    }
    if ax < 1.0e-8 {
        return x;
    }
    atan2_(x, sqrt_((1.0 - ax) * (1.0 + ax)))
}

pub fn acos_(x: f64) -> f64 {
    let ax = fabs_(x);
    if x.is_nan() {
        return x;
    }
    if ax > 1.0 {
        return f64::NAN;
    }
    atan2_(sqrt_((1.0 - ax) * (1.0 + ax)), x)
}

// --- hyperbolic ---------------------------------------------------------------

pub fn sinh_(x: f64) -> f64 {
    let ax = fabs_(x);
    if !x.is_finite() || ax < 1.0e-8 {
        return x;
    }
    let r = if ax < 22.0 {
        let e = expm1_(ax);
        0.5 * (e + e / (e + 1.0))
    } else if ax < EXP_MAX {
        0.5 * exp_(ax)
    } else {
        // exp(ax)/2 without overflowing early.
        let h = exp_(0.5 * ax);
        0.5 * h * h
    };
    copysign_(r, x)
}

pub fn cosh_(x: f64) -> f64 {
    let ax = fabs_(x);
    if x.is_nan() {
        return x;
    }
    if ax < 0.3465 {
        let e = expm1_(ax);
        return 1.0 + e * e / (2.0 * (1.0 + e));
    }
    if ax < 22.0 {
        let e = exp_(ax);
        return 0.5 * e + 0.5 / e;
    }
    if ax < EXP_MAX {
        return 0.5 * exp_(ax);
    }
    let h = exp_(0.5 * ax);
    0.5 * h * h
}

pub fn tanh_(x: f64) -> f64 {
    let ax = fabs_(x);
    if x.is_nan() || ax < 1.0e-9 {
        return x;
    }
    let r = if ax < 22.0 {
        let e = expm1_(2.0 * ax);
        e / (e + 2.0)
    } else {
        1.0
    };
    copysign_(r, x)
}

pub fn asinh_(x: f64) -> f64 {
    let ax = fabs_(x);
    if !x.is_finite() || ax < 1.0e-9 {
        return x;
    }
    let r = if ax > 2.7e8 {
        log_(ax) + LN2
    } else if ax > 2.0 {
        log_(2.0 * ax + 1.0 / (sqrt_(ax * ax + 1.0) + ax))
    } else {
        let z = ax * ax;
        log1p_(ax + z / (1.0 + sqrt_(1.0 + z)))
    };
    copysign_(r, x)
}

pub fn acosh_(x: f64) -> f64 {
    if x.is_nan() || x == f64::INFINITY {
        return x;
    }
    if x < 1.0 {
        return f64::NAN;
    }
    if x > 2.7e8 {
        return log_(x) + LN2;
    }
    if x > 2.0 {
        return log_(2.0 * x - 1.0 / (x + sqrt_(x * x - 1.0)));
    }
    let t = x - 1.0;
    log1p_(t + sqrt_(2.0 * t + t * t))
}

pub fn atanh_(x: f64) -> f64 {
    let ax = fabs_(x);
    if x.is_nan() || ax < 1.0e-9 {
        return x;
    }
    if ax > 1.0 {
        return f64::NAN;
    }
    if ax == 1.0 {
        return copysign_(f64::INFINITY, x);
    }
    let r = if ax < 0.5 {
        let t = ax + ax;
        0.5 * log1p_(t + t * ax / (1.0 - ax))
    } else {
        0.5 * log1p_((ax + ax) / (1.0 - ax))
    };
    copysign_(r, x)
}

// --- roots, remainders, the rest ----------------------------------------------

pub fn cbrt_(x: f64) -> f64 {
    if x == 0.0 || !x.is_finite() {
        return x;
    }
    let mut ax = fabs_(x);
    let mut adj = 1.0;
    if ax < f64::MIN_POSITIVE {
        ax *= 18014398509481984.0; // 2^54
        adj = 1.0 / 262144.0; // 2^-18
    }
    // A first guess from the exponent bits divided by three, then Newton.
    let mut t = f64::from_bits(ax.to_bits() / 3 + 0x2aa0_0000_0000_0000);
    for _ in 0..6 {
        t -= (t * t * t - ax) / (3.0 * t * t);
    }
    // One last step with the residual computed exactly.
    let (r2, r2e) = two_prod(t, t);
    let (r3, r3e) = two_prod(r2, t);
    let res = ((ax - r3) - r3e) - r2e * t;
    t += res / (3.0 * t * t);
    copysign_(t * adj, x)
}

pub fn hypot_(x: f64, y: f64) -> f64 {
    if x.is_infinite() || y.is_infinite() {
        return f64::INFINITY;
    }
    if x.is_nan() || y.is_nan() {
        return f64::NAN;
    }
    let (mut a, mut b) = (fabs_(x), fabs_(y));
    if a < b {
        core::mem::swap(&mut a, &mut b);
    }
    if b == 0.0 {
        return a;
    }
    if a / b > 1.0e18 {
        return a + b;
    }
    // Scale by a power of two near a's, so the squares cannot overflow.
    let e = ((a.to_bits() >> 52) as i32 - 1023).clamp(-1000, 1000);
    let (a, b) = (ldexp_(a, -e), ldexp_(b, -e));
    let (aa, aae) = two_prod(a, a);
    let (bb, bbe) = two_prod(b, b);
    let (s, se) = two_sum(aa, bb);
    let sl = se + aae + bbe;
    let r = sqrt_(s);
    // One Newton step on the double-double sum.
    let (rr, rre) = two_prod(r, r);
    let r = r + (((s - rr) - rre) + sl) / (2.0 * r);
    ldexp_(r, e)
}

/// |x| mod |y| for finite x and nonzero finite y with |x| ≥ |y|, as
/// (remainder's mantissa, its exponent, the quotient's lowest bit).
pub fn rem_core(ax: f64, ay: f64) -> (u64, i32, bool) {
    let (mx, ex) = mant_exp(ax);
    let (my, ey) = mant_exp(ay);
    let mut r = mx;
    let mut q = r / my;
    r %= my;
    let mut left = ex - ey;
    while left > 0 {
        let s = left.min(10);
        r <<= s;
        q = r / my;
        r %= my;
        left -= s;
    }
    (r, ey, q & 1 == 1)
}

pub fn fmod_(x: f64, y: f64) -> f64 {
    if x.is_nan() || y.is_nan() || x.is_infinite() || y == 0.0 {
        return f64::NAN;
    }
    if y.is_infinite() {
        return x;
    }
    let (ax, ay) = (fabs_(x), fabs_(y));
    if ax < ay {
        return x;
    }
    let (r, e, _) = rem_core(ax, ay);
    copysign_(ldexp_(r as f64, e), x)
}

pub fn remainder_(x: f64, y: f64) -> f64 {
    if x.is_nan() || y.is_nan() || x.is_infinite() || y == 0.0 {
        return f64::NAN;
    }
    if y.is_infinite() {
        return x;
    }
    let (ax, ay) = (fabs_(x), fabs_(y));
    let r = if ax < ay {
        // The quotient is 0 or 1.
        if ax > 0.5 * ay { ax - ay } else { ax }
    } else {
        let (r, e, odd) = rem_core(ax, ay);
        let (my, _) = mant_exp(ay);
        let twice = 2 * r;
        let rf = ldexp_(r as f64, e);
        if twice > my || (twice == my && odd) { rf - ay } else { rf }
    };
    if x < 0.0 { -r } else { r }
}

pub fn frexp_(x: f64) -> (f64, i32) {
    if x == 0.0 || !x.is_finite() {
        return (x, 0);
    }
    let (mut m, mut e) = (x, 0);
    if fabs_(x) < f64::MIN_POSITIVE {
        m *= 18014398509481984.0;
        e = -54;
    }
    let b = m.to_bits();
    e += ((b >> 52) & 0x7ff) as i32 - 1022;
    (f64::from_bits((b & !(0x7ff << 52)) | (1022 << 52)), e)
}
