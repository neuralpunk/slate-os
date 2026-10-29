// SPDX-License-Identifier: MIT OR Apache-2.0

//! The elementary functions awk needs, for a target without libm: range
//! reduction followed by Taylor series (accurate to about 1 ulp, plenty for
//! awk's `%.6g` output).

const LN2_HI: f64 = 6.931_471_803_691_238e-1;
const LN2_LO: f64 = 1.908_214_929_270_587_7e-10;
const LN2: f64 = core::f64::consts::LN_2;
const PI: f64 = core::f64::consts::PI;
const FRAC_PI_2: f64 = core::f64::consts::FRAC_PI_2;
/// π/2 in three parts (Cody–Waite reduction).
const PIO2_1: f64 = 1.570_796_326_734_125_6;
const PIO2_2: f64 = 6.077_100_506_303_966e-11;
const PIO2_3: f64 = 2.022_266_248_711_166_5e-21;

const TWO52: f64 = 4_503_599_627_370_496.0;

pub fn trunc(x: f64) -> f64 {
    if !x.is_finite() || x.abs() >= TWO52 {
        return x;
    }
    (x as i64) as f64
}

pub fn floor(x: f64) -> f64 {
    let t = trunc(x);
    if t > x { t - 1.0 } else { t }
}

/// Round half away from zero.
pub fn round(x: f64) -> f64 {
    if x < 0.0 { -floor(-x + 0.5) } else { floor(x + 0.5) }
}

/// 2^k as a float (k in the normal range, else via two steps).
fn pow2(k: i64) -> f64 {
    if k > 1023 {
        return f64::INFINITY;
    }
    if k < -1022 {
        return pow2(k + 1000) * pow2(-1000);
    }
    f64::from_bits(((k + 1023) as u64) << 52)
}

pub fn sqrt(x: f64) -> f64 {
    if x.is_nan() || x < 0.0 {
        return f64::NAN;
    }
    if x == 0.0 || x.is_infinite() {
        return x;
    }
    // A first guess from the exponent, then Newton's iteration.
    let mut y = f64::from_bits((x.to_bits() >> 1) + (1023u64 << 51));
    for _ in 0..8 {
        y = 0.5 * (y + x / y);
    }
    y
}

pub fn exp(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    if x > 709.782_712_893_384 {
        return f64::INFINITY;
    }
    if x < -745.133_219_101_941_1 {
        return 0.0;
    }
    let k = round(x / LN2);
    let r = (x - k * LN2_HI) - k * LN2_LO;
    // e^r for |r| <= ln2/2.
    let mut term = 1.0;
    let mut sum = 1.0;
    for n in 1..28 {
        term *= r / n as f64;
        sum += term;
        if term.abs() < 1e-18 {
            break;
        }
    }
    sum * pow2(k as i64)
}

pub fn log(x: f64) -> f64 {
    if x.is_nan() || x < 0.0 {
        return f64::NAN;
    }
    if x == 0.0 {
        return f64::NEG_INFINITY;
    }
    if x.is_infinite() {
        return x;
    }
    let mut bits = x.to_bits();
    let mut e = ((bits >> 52) & 0x7FF) as i64;
    if e == 0 {
        // Subnormal: scale up first.
        let y = x * pow2(54);
        bits = y.to_bits();
        e = ((bits >> 52) & 0x7FF) as i64 - 54;
    }
    let mut e = e - 1023;
    let mut m = f64::from_bits((bits & ((1u64 << 52) - 1)) | (1023u64 << 52));
    if m > core::f64::consts::SQRT_2 {
        m /= 2.0;
        e += 1;
    }
    // log(m) = 2 atanh(s), s = (m-1)/(m+1), |s| < 0.172.
    let s = (m - 1.0) / (m + 1.0);
    let s2 = s * s;
    let mut term = s;
    let mut sum = 0.0;
    let mut n = 1.0;
    for _ in 0..30 {
        sum += term / n;
        term *= s2;
        n += 2.0;
        if term.abs() < 1e-20 {
            break;
        }
    }
    let ef = e as f64;
    ef * LN2_HI + (2.0 * sum + ef * LN2_LO)
}

/// sin and cos of r, |r| <= π/4.
fn sin_k(r: f64) -> f64 {
    let r2 = r * r;
    let mut term = r;
    let mut sum = r;
    let mut n = 1.0;
    for _ in 0..12 {
        term *= -r2 / ((n + 1.0) * (n + 2.0));
        sum += term;
        n += 2.0;
    }
    sum
}

fn cos_k(r: f64) -> f64 {
    let r2 = r * r;
    let mut term = 1.0;
    let mut sum = 1.0;
    let mut n = 0.0;
    for _ in 0..12 {
        term *= -r2 / ((n + 1.0) * (n + 2.0));
        sum += term;
        n += 2.0;
    }
    sum
}

/// x = k·π/2 + r: (r, k mod 4).
fn reduce(x: f64) -> (f64, i64) {
    let k = round(x / FRAC_PI_2);
    let r = ((x - k * PIO2_1) - k * PIO2_2) - k * PIO2_3;
    (r, (k as i64).rem_euclid(4))
}

pub fn sin(x: f64) -> f64 {
    if !x.is_finite() {
        return f64::NAN;
    }
    let (r, q) = reduce(x);
    match q {
        0 => sin_k(r),
        1 => cos_k(r),
        2 => -sin_k(r),
        _ => -cos_k(r),
    }
}

pub fn cos(x: f64) -> f64 {
    if !x.is_finite() {
        return f64::NAN;
    }
    let (r, q) = reduce(x);
    match q {
        0 => cos_k(r),
        1 => -sin_k(r),
        2 => -cos_k(r),
        _ => sin_k(r),
    }
}

/// atan for 0 <= x <= 1.
fn atan_k(x: f64) -> f64 {
    // tan(π/12) = 2 - √3; above it, atan(x) = π/6 + atan((√3x - 1)/(x + √3)).
    const TAN_PI_12: f64 = 0.267_949_192_431_122_7;
    const SQRT3: f64 = 1.732_050_807_568_877_2;
    if x > TAN_PI_12 {
        return PI / 6.0 + atan_k((SQRT3 * x - 1.0) / (x + SQRT3));
    }
    let x2 = x * x;
    let mut term = x;
    let mut sum = 0.0;
    let mut n = 1.0;
    for _ in 0..40 {
        sum += term / n;
        term *= -x2;
        n += 2.0;
        if term.abs() < 1e-20 {
            break;
        }
    }
    sum
}

pub fn atan(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    let (neg, a) = (x < 0.0, x.abs());
    let r = if a > 1.0 { FRAC_PI_2 - atan_k(1.0 / a) } else { atan_k(a) };
    if neg { -r } else { r }
}

pub fn atan2(y: f64, x: f64) -> f64 {
    if x.is_nan() || y.is_nan() {
        return f64::NAN;
    }
    if x > 0.0 {
        atan(y / x)
    } else if x < 0.0 {
        if y >= 0.0 && !(y == 0.0 && y.is_sign_negative()) { atan(y / x) + PI } else { atan(y / x) - PI }
    } else if y > 0.0 {
        FRAC_PI_2
    } else if y < 0.0 {
        -FRAC_PI_2
    } else if x.is_sign_negative() {
        if y.is_sign_negative() { -PI } else { PI }
    } else {
        y
    }
}

pub fn pow(x: f64, y: f64) -> f64 {
    if y == 0.0 {
        return 1.0;
    }
    if y == trunc(y) && y.abs() < 2147483648.0 {
        // Exact for integer exponents (repeated squaring).
        let mut n = y.abs() as u64;
        let mut base = x;
        let mut r = 1.0;
        while n > 0 {
            if n & 1 == 1 {
                r *= base;
            }
            base *= base;
            n >>= 1;
        }
        return if y < 0.0 { 1.0 / r } else { r };
    }
    if x < 0.0 {
        return f64::NAN;
    }
    if x == 0.0 {
        return if y > 0.0 { 0.0 } else { f64::INFINITY };
    }
    exp(y * log(x))
}

/// fmod: the remainder with the sign of x.
pub fn fmod(x: f64, y: f64) -> f64 {
    if y == 0.0 || !x.is_finite() || y.is_nan() {
        return f64::NAN;
    }
    if y.is_infinite() {
        return x;
    }
    let q = trunc(x / y);
    let r = x - q * y;
    // Correct an off-by-one quotient from rounding in x / y.
    if r != 0.0 && (r < 0.0) != (x < 0.0) {
        return r + if (r < 0.0) == (y < 0.0) { -y } else { y };
    }
    if r.abs() >= y.abs() {
        return r - if (r < 0.0) == (y < 0.0) { y } else { -y };
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() <= 1e-14 * b.abs().max(1.0)
    }

    #[test]
    fn functions() {
        assert!(close(sqrt(2.0), core::f64::consts::SQRT_2));
        assert!(close(exp(1.0), core::f64::consts::E));
        assert!(close(log(10.0), core::f64::consts::LN_10));
        assert!(close(sin(1.0), 0.841_470_984_807_896_5));
        assert!(close(cos(1.0), 0.540_302_305_868_139_8));
        assert!(close(atan2(1.0, 2.0), 0.463_647_609_000_806_1));
        assert!(close(atan2(0.0, -1.0), PI));
        assert!(close(pow(2.0, 0.5), core::f64::consts::SQRT_2));
        assert_eq!(pow(2.0, 10.0), 1024.0);
        assert_eq!(fmod(-10.0, 3.0), -1.0);
        assert_eq!(fmod(5.5, 2.0), 1.5);
        assert!(close(sin(100.0), -0.506_365_641_109_758_8));
        assert!(close(exp(-20.0), 2.061_153_622_438_558e-9));
        assert!(close(log(1e-300), -690.775_527_898_213_7));
        assert_eq!(floor(-3.5), -4.0);
        assert_eq!(trunc(-3.7), -3.0);
    }
}
