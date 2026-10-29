/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0074): <math.h> (C11 7.12). Double and float
 * functions; no long double ones. Errors set errno (MATH_ERRNO). */
#ifndef _MATH_H
#define _MATH_H

#define HUGE_VAL (__builtin_huge_val())
#define HUGE_VALF (__builtin_huge_valf())
#define INFINITY (__builtin_inff())
#define NAN (__builtin_nanf(""))
#define MATH_ERRNO 1
#define MATH_ERREXCEPT 2
#define math_errhandling MATH_ERRNO
#define FP_NAN 0
#define FP_INFINITE 1
#define FP_ZERO 2
#define FP_SUBNORMAL 3
#define FP_NORMAL 4
#define FP_ILOGB0 (-2147483647 - 1)
#define FP_ILOGBNAN 2147483647
typedef double double_t;
typedef float float_t;

#define fpclassify(x) __builtin_fpclassify(FP_NAN, FP_INFINITE, FP_NORMAL, FP_SUBNORMAL, FP_ZERO, x)
#define isnan(x) __builtin_isnan(x)
#define isinf(x) __builtin_isinf_sign(x)
#define isfinite(x) __builtin_isfinite(x)
#define isnormal(x) __builtin_isnormal(x)
#define signbit(x) __builtin_signbit(x)
#define isgreater(x, y) __builtin_isgreater(x, y)
#define isgreaterequal(x, y) __builtin_isgreaterequal(x, y)
#define isless(x, y) __builtin_isless(x, y)
#define islessequal(x, y) __builtin_islessequal(x, y)
#define islessgreater(x, y) __builtin_islessgreater(x, y)
#define isunordered(x, y) __builtin_isunordered(x, y)

#define M_E 2.7182818284590452354
#define M_LOG2E 1.4426950408889634074
#define M_LOG10E 0.43429448190325182765
#define M_LN2 0.69314718055994530942
#define M_LN10 2.30258509299404568402
#define M_PI 3.14159265358979323846
#define M_PI_2 1.57079632679489661923
#define M_PI_4 0.78539816339744830962
#define M_1_PI 0.31830988618379067154
#define M_2_PI 0.63661977236758134308
#define M_2_SQRTPI 1.12837916709551257390
#define M_SQRT2 1.41421356237309504880
#define M_SQRT1_2 0.70710678118654752440

#define __SLATE_MATH1(name) double name(double); float name##f(float);
#define __SLATE_MATH2(name) double name(double, double); float name##f(float, float);
__SLATE_MATH1(sqrt)
__SLATE_MATH1(fabs)
__SLATE_MATH1(floor)
__SLATE_MATH1(ceil)
__SLATE_MATH1(trunc)
__SLATE_MATH1(round)
__SLATE_MATH1(rint)
__SLATE_MATH1(nearbyint)
__SLATE_MATH1(exp)
__SLATE_MATH1(exp2)
__SLATE_MATH1(expm1)
__SLATE_MATH1(log)
__SLATE_MATH1(log2)
__SLATE_MATH1(log10)
__SLATE_MATH1(log1p)
__SLATE_MATH1(logb)
__SLATE_MATH1(sin)
__SLATE_MATH1(cos)
__SLATE_MATH1(tan)
__SLATE_MATH1(asin)
__SLATE_MATH1(acos)
__SLATE_MATH1(atan)
__SLATE_MATH1(sinh)
__SLATE_MATH1(cosh)
__SLATE_MATH1(tanh)
__SLATE_MATH1(asinh)
__SLATE_MATH1(acosh)
__SLATE_MATH1(atanh)
__SLATE_MATH1(cbrt)
__SLATE_MATH2(pow)
__SLATE_MATH2(atan2)
__SLATE_MATH2(hypot)
__SLATE_MATH2(fmod)
__SLATE_MATH2(remainder)
__SLATE_MATH2(copysign)
__SLATE_MATH2(fmin)
__SLATE_MATH2(fmax)
__SLATE_MATH2(fdim)
__SLATE_MATH2(nextafter)
#undef __SLATE_MATH1
#undef __SLATE_MATH2
double fma(double x, double y, double z);
float fmaf(float x, float y, float z);
double ldexp(double x, int n);
float ldexpf(float x, int n);
double scalbn(double x, int n);
float scalbnf(float x, int n);
double frexp(double x, int *e);
float frexpf(float x, int *e);
double modf(double x, double *ip);
float modff(float x, float *ip);
int ilogb(double x);
long lround(double x);
long long llround(double x);
long lrint(double x);
long long llrint(double x);
double nan(const char *tag);
float nanf(const char *tag);
#endif
