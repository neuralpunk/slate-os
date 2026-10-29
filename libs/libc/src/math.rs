// SPDX-License-Identifier: MIT OR Apache-2.0

//! <math.h> (C11 7.12 and annex F; ADR 0074): the C interface over
//! slate-math's functions (`libs/math`, which describes the algorithms),
//! with fma, the float versions, and errno. The float functions compute
//! in double and round once more.
//!
//! Domain errors set `errno` to EDOM, and poles and overflows to ERANGE
//! (`math_errhandling` is MATH_ERRNO).

use core::ffi::c_int;

use slate_math::*;
use slate_rt::Errno;

/// x·y + z with a single rounding, from the exact integer sum.
fn fma_(x: f64, y: f64, z: f64) -> f64 {
    if !x.is_finite() || !y.is_finite() || !z.is_finite() || x == 0.0 || y == 0.0 || z == 0.0 {
        return x * y + z;
    }
    let (mx, ex) = mant_exp(x);
    let (my, ey) = mant_exp(y);
    let (mz, ez) = mant_exp(z);
    let p_neg = x.is_sign_negative() != y.is_sign_negative();
    let z_neg = z.is_sign_negative();
    let ep = ex + ey;
    let e0 = ep.min(ez);
    let mut a = crate::float::Big::from_u128(u128::from(mx) * u128::from(my));
    a.shl((ep - e0) as u32);
    let mut b = crate::float::Big::from_u128(u128::from(mz));
    b.shl((ez - e0) as u32);
    let (sum, neg) = if p_neg == z_neg {
        (crate::float::add(&a, &b), p_neg)
    } else {
        match a.cmp(&b) {
            core::cmp::Ordering::Equal => return 0.0,
            core::cmp::Ordering::Greater => {
                a.sub(&b);
                (a, p_neg)
            }
            core::cmp::Ordering::Less => {
                b.sub(&a);
                (b, z_neg)
            }
        }
    };
    let lo = sum.bits().saturating_sub(128);
    let (bits, _) = crate::float::round_bits(sum.window(lo), lo as i32 + e0, sum.any_below(lo), crate::float::DOUBLE);
    let r = f64::from_bits(bits);
    if neg { -r } else { r }
}

// --- the C interface ----------------------------------------------------------

/// Set errno for a result: EDOM for a NaN from numbers, ERANGE for an
/// infinity from finite numbers (a pole or an overflow).
fn check(r: f64, args: &[f64]) -> f64 {
    if r.is_nan() && !args.iter().any(|a| a.is_nan()) {
        crate::set_errno(Errno::EDOM);
    } else if r.is_infinite() && args.iter().all(|a| a.is_finite()) {
        crate::set_errno(Errno::ERANGE);
    }
    r
}

macro_rules! unary {
    ($($name:ident, $namef:ident => $f:expr;)*) => {$(
        #[cfg_attr(target_os = "none", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f64) -> f64 {
            check($f(x), &[x])
        }
        #[cfg_attr(target_os = "none", unsafe(no_mangle))]
        pub extern "C" fn $namef(x: f32) -> f32 {
            let r = $f(f64::from(x)) as f32;
            check(f64::from(r), &[f64::from(x)]) as f32
        }
    )*};
}

macro_rules! binary {
    ($($name:ident, $namef:ident => $f:expr;)*) => {$(
        #[cfg_attr(target_os = "none", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f64, y: f64) -> f64 {
            check($f(x, y), &[x, y])
        }
        #[cfg_attr(target_os = "none", unsafe(no_mangle))]
        pub extern "C" fn $namef(x: f32, y: f32) -> f32 {
            let r = $f(f64::from(x), f64::from(y)) as f32;
            check(f64::from(r), &[f64::from(x), f64::from(y)]) as f32
        }
    )*};
}

unary! {
    sqrt, sqrtf => |x: f64| if x < 0.0 { f64::NAN } else { sqrt_(x) };
    fabs, fabsf => fabs_;
    floor, floorf => floor_;
    ceil, ceilf => ceil_;
    trunc, truncf => trunc_;
    round, roundf => round_;
    rint, rintf => rint_;
    nearbyint, nearbyintf => rint_;
    exp, expf => exp_;
    exp2, exp2f => exp2_;
    expm1, expm1f => expm1_;
    log, logf => log_;
    log2, log2f => log2_;
    log10, log10f => log10_;
    log1p, log1pf => log1p_;
    sin, sinf => sin_;
    cos, cosf => cos_;
    tan, tanf => tan_;
    asin, asinf => asin_;
    acos, acosf => acos_;
    atan, atanf => atan_;
    sinh, sinhf => sinh_;
    cosh, coshf => cosh_;
    tanh, tanhf => tanh_;
    asinh, asinhf => asinh_;
    acosh, acoshf => acosh_;
    atanh, atanhf => atanh_;
    cbrt, cbrtf => cbrt_;
    logb, logbf => |x: f64| if x == 0.0 { f64::NEG_INFINITY } else if !x.is_finite() { fabs_(x) } else { (frexp_(x).1 - 1) as f64 };
}

binary! {
    pow, powf => pow_;
    atan2, atan2f => atan2_;
    hypot, hypotf => hypot_;
    fmod, fmodf => fmod_;
    remainder, remainderf => remainder_;
    copysign, copysignf => copysign_;
    fmin, fminf => |x: f64, y: f64| if x.is_nan() || y < x { y } else { x };
    fmax, fmaxf => |x: f64, y: f64| if x.is_nan() || y > x { y } else { x };
    fdim, fdimf => |x: f64, y: f64| if x.is_nan() || y.is_nan() { f64::NAN } else if x > y { x - y } else { 0.0 };
    nextafter, nextafterf => nextafter_;
}

fn nextafter_(x: f64, y: f64) -> f64 {
    if x.is_nan() || y.is_nan() {
        return f64::NAN;
    }
    if x == y {
        return y;
    }
    if x == 0.0 {
        return copysign_(f64::from_bits(1), y);
    }
    let b = x.to_bits();
    let up = (y > x) == (x > 0.0);
    f64::from_bits(if up { b + 1 } else { b - 1 })
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn fma(x: f64, y: f64, z: f64) -> f64 {
    check(fma_(x, y, z), &[x, y, z])
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn fmaf(x: f32, y: f32, z: f32) -> f32 {
    // The double product of two floats is exact; one rounding of the sum
    // to double, then to float, can differ from a single rounding only in
    // halfway cases.
    (f64::from(x) * f64::from(y) + f64::from(z)) as f32
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn ldexp(x: f64, n: c_int) -> f64 {
    check(ldexp_(x, n), &[x])
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn ldexpf(x: f32, n: c_int) -> f32 {
    check(ldexp_(f64::from(x), n) as f32 as f64, &[f64::from(x)]) as f32
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn scalbn(x: f64, n: c_int) -> f64 {
    ldexp(x, n)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn scalbnf(x: f32, n: c_int) -> f32 {
    ldexpf(x, n)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn frexp(x: f64, e: *mut c_int) -> f64 {
    let (m, n) = frexp_(x);
    // SAFETY: C passes room for the exponent.
    unsafe { *e = n };
    m
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn frexpf(x: f32, e: *mut c_int) -> f32 {
    let (m, n) = frexp_(f64::from(x));
    // SAFETY: As above.
    unsafe { *e = n };
    m as f32
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn modf(x: f64, ip: *mut f64) -> f64 {
    let i = trunc_(x);
    // SAFETY: C passes room for the integer part.
    unsafe { *ip = i };
    if x.is_infinite() { copysign_(0.0, x) } else { copysign_(x - i, x) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn modff(x: f32, ip: *mut f32) -> f32 {
    let mut i = 0.0;
    // SAFETY: A local for the double result; C passes room for its own.
    let f = unsafe { modf(f64::from(x), &mut i) };
    // SAFETY: As above.
    unsafe { *ip = i as f32 };
    f as f32
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn ilogb(x: f64) -> c_int {
    if x == 0.0 || x.is_nan() {
        crate::set_errno(Errno::EDOM);
        return if x == 0.0 { c_int::MIN } else { c_int::MAX };
    }
    if x.is_infinite() {
        crate::set_errno(Errno::EDOM);
        return c_int::MAX;
    }
    frexp_(x).1 - 1
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn lround(x: f64) -> i64 {
    round_(x) as i64
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn llround(x: f64) -> i64 {
    round_(x) as i64
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn lrint(x: f64) -> i64 {
    rint_(x) as i64
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn llrint(x: f64) -> i64 {
    rint_(x) as i64
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn nan(_tag: *const core::ffi::c_char) -> f64 {
    f64::NAN
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn nanf(_tag: *const core::ffi::c_char) -> f32 {
    f32::NAN
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    // The host C library's, where Rust's own f64 methods are not it
    // (Rust computes asinh, acosh and atanh itself, less exactly).
    unsafe extern "C" {
        #[link_name = "asinh"]
        safe fn host_asinh(x: f64) -> f64;
        #[link_name = "acosh"]
        safe fn host_acosh(x: f64) -> f64;
        #[link_name = "atanh"]
        safe fn host_atanh(x: f64) -> f64;
    }

    /// Distance in units in the last place.
    fn ulps(a: f64, b: f64) -> u64 {
        if a.is_nan() && b.is_nan() || a == b {
            return 0;
        }
        if a.is_nan() || b.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
            return u64::MAX;
        }
        a.to_bits().abs_diff(b.to_bits())
    }

    /// Arguments: a deterministic spread over `lo..hi`, with a share of
    /// small, integer and boundary values.
    fn args(lo: f64, hi: f64, n: usize) -> Vec<f64> {
        let mut v = Vec::new();
        let mut s: u64 = 0x2545f4914f6cdd1d;
        for i in 0..n {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let u = (s >> 11) as f64 / (1u64 << 53) as f64;
            v.push(match i % 4 {
                0 => lo + (hi - lo) * u,
                // Logarithmic spread over the magnitudes in range.
                1 if lo >= 0.0 && lo < hi => {
                    let a = lo.max(1e-300).ln();
                    (a + (hi.ln() - a) * u).exp()
                }
                2 => ((lo + (hi - lo) * u) * 8.0).round() / 8.0,
                _ => lo + (hi - lo) * u * u,
            });
        }
        v.retain(|x| (lo..=hi).contains(x));
        v
    }

    fn compare(name: &str, ours: fn(f64) -> f64, host: fn(f64) -> f64, lo: f64, hi: f64, max: u64) {
        let mut worst = (0, 0.0);
        for x in args(lo, hi, 20000) {
            let d = ulps(ours(x), host(x));
            if d > worst.0 {
                worst = (d, x);
            }
        }
        assert!(
            worst.0 <= max,
            "{name}({:e}): {} ulps (ours {:e}, host {:e})",
            worst.1,
            worst.0,
            ours(worst.1),
            host(worst.1)
        );
    }

    #[test]
    fn unary_functions_match_the_host() {
        compare("sqrt", sqrt_, f64::sqrt, 0.0, 1e300, 0);
        compare("exp", exp_, f64::exp, -745.0, 709.0, 1);
        compare("exp_small", exp_, f64::exp, -1.0, 1.0, 1);
        compare("expm1", expm1_, f64::exp_m1, -40.0, 40.0, 1);
        compare("expm1_small", expm1_, f64::exp_m1, -1e-3, 1e-3, 1);
        compare("exp2", exp2_, f64::exp2, -1070.0, 1023.0, 1);
        compare("log", log_, f64::ln, 1e-300, 1e300, 1);
        compare("log_near1", log_, f64::ln, 0.9, 1.1, 1);
        compare("log2", log2_, f64::log2, 1e-300, 1e300, 1);
        compare("log10", log10_, f64::log10, 1e-300, 1e300, 1);
        compare("log1p", log1p_, f64::ln_1p, -0.999, 1e10, 1);
        compare("log1p_small", log1p_, f64::ln_1p, -1e-6, 1e-6, 1);
        compare("sin", sin_, f64::sin, -100.0, 100.0, 1);
        compare("cos", cos_, f64::cos, -100.0, 100.0, 1);
        compare("tan", tan_, f64::tan, -100.0, 100.0, 2);
        compare("sin_big", sin_, f64::sin, 1e6, 1e300, 1);
        compare("cos_big", cos_, f64::cos, 1e6, 1e300, 1);
        compare("sin_mid", sin_, f64::sin, 1e3, 2e6, 1);
        compare("atan", atan_, f64::atan, -1e20, 1e20, 1);
        compare("atan_unit", atan_, f64::atan, -3.0, 3.0, 1);
        compare("asin", asin_, f64::asin, -1.0, 1.0, 2);
        compare("acos", acos_, f64::acos, -1.0, 1.0, 2);
        compare("sinh", sinh_, f64::sinh, -710.0, 710.0, 2);
        compare("cosh", cosh_, f64::cosh, -710.0, 710.0, 2);
        compare("tanh", tanh_, f64::tanh, -30.0, 30.0, 2);
        compare("asinh", asinh_, |x| host_asinh(x), -1e10, 1e10, 2);
        compare("acosh", acosh_, |x| host_acosh(x), 1.0, 1e10, 2);
        compare("atanh", atanh_, |x| host_atanh(x), -0.999999, 0.999999, 2);
        compare("cbrt", cbrt_, f64::cbrt, -1e300, 1e300, 1);
        compare("floor", floor_, f64::floor, -1e17, 1e17, 0);
        compare("ceil", ceil_, f64::ceil, -1e17, 1e17, 0);
        compare("round", round_, f64::round, -1e17, 1e17, 0);
        compare("trunc", trunc_, f64::trunc, -1e17, 1e17, 0);
        compare("rint", rint_, f64::round_ties_even, -1e17, 1e17, 0);
    }

    #[test]
    fn binary_functions_match_the_host() {
        let xs = args(-50.0, 50.0, 3000);
        let ys = args(-30.0, 30.0, 3000);
        for (&x, &y) in xs.iter().zip(&ys) {
            assert!(ulps(atan2_(y, x), y.atan2(x)) <= 2, "atan2({y}, {x})");
            assert!(ulps(hypot_(x, y), x.hypot(y)) <= 1, "hypot({x}, {y})");
            let (m, want) = (fmod_(x, y), x % y);
            assert!(m.to_bits() == want.to_bits() || (m.is_nan() && want.is_nan()), "fmod({x}, {y})");
            let ax = x.abs();
            assert!(ulps(pow_(ax, y), ax.powf(y)) <= 1, "pow({ax}, {y})");
            let (a, b, c) = (x * 1e10, y, x / 3.0);
            assert_eq!(fma_(a, b, c).to_bits(), a.mul_add(b, c).to_bits(), "fma({a}, {b}, {c})");
        }
        for (x, y) in [
            (2.0, 10.0),
            (10.0, 5.0),
            (3.0, 3.0),
            (0.5, 3.0),
            (-2.0, 3.0),
            (-8.0, 1.0 / 3.0),
            (0.0, -1.0),
            (-0.0, -3.0),
        ] {
            let (a, b) = (pow_(x, y), f64::powf(x, y));
            assert!(a.to_bits() == b.to_bits() || (a.is_nan() && b.is_nan()), "pow({x}, {y}): {a} {b}");
        }
        assert_eq!(remainder_(5.0, 2.0), 1.0);
        assert_eq!(remainder_(7.0, 2.0), -1.0);
        assert_eq!(remainder_(-7.5, 2.0), 0.5);
        assert_eq!(remainder_(1.0, 3.0), 1.0);
        assert_eq!(remainder_(2.0, 3.0), -1.0);
        assert_eq!(fmod_(1e300, 3.0), 1e300 % 3.0);
        assert_eq!(fmod_(5e-324, 3e-324), 5e-324 % 3e-324);
        assert_eq!(frexp_(8.0), (0.5, 4));
        assert_eq!(frexp_(5e-324), (0.5, -1073));
        assert_eq!(ldexp_(1.0, -1074), 5e-324);
        assert_eq!(ldexp_(1.5, 1023), 1.5 * 2f64.powi(1023));
        assert_eq!(log10_(1000.0), 3.0);
        assert_eq!(log2_(1024.0), 10.0);
        assert_eq!(exp2_(-1074.0), 5e-324);
        assert_eq!(nextafter_(1.0, 2.0), 1.0 + f64::EPSILON);
        assert_eq!(nextafter_(0.0, -1.0), -5e-324);
    }
}
