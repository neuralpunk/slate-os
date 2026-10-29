// SPDX-License-Identifier: MIT OR Apache-2.0
//
// slate-libc's floating point (ADR 0074), checked from C: printf's and
// scanf's floating-point conversions, strtod, and <math.h>. Built by
// tools/slate-cc, run on Slate (native calls) and on the Linux host (cargo
// xtask check). Prints one line per check and exits with the number of
// failures. A file goes under /tmp/nmath-PID.

#include <errno.h>
#include <float.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;

static void check(const char *name, int ok) {
    printf("native-math: %s %s\n", ok ? "ok" : "FAIL", name);
    if (!ok)
        failures++;
}

// Through volatile, so the compiler computes nothing at build time.
static volatile double v_half = 0.5, v_two = 2.0, v_ten = 10.0, v_zero = 0.0, v_one = 1.0, v_neg = -1.0;

static int near(double a, double b, double rel) {
    if (a == b)
        return 1;
    double d = fabs(a - b);
    return d <= rel * fabs(b);
}

static void formatting(void) {
    char buf[128];
    snprintf(buf, sizeof buf, "%f %.2f %.0f %.0f", 3.14159, 2.675, 0.5, 1.5);
    check("printf_f", strcmp(buf, "3.141590 2.67 0 2") == 0);
    snprintf(buf, sizeof buf, "%e %.3E %g %g %g", 12345.678, 0.000123456, 100000.0, 1000000.0, 1e-5);
    check("printf_e_g", strcmp(buf, "1.234568e+04 1.235E-04 100000 1e+06 1e-05") == 0);
    snprintf(buf, sizeof buf, "%a %A %.1a", 1.0, 0.5, 1.75);
    check("printf_a", strcmp(buf, "0x1p+0 0X1P-1 0x1.cp+0") == 0);
    snprintf(buf, sizeof buf, "[%08.3f] [%-8.2e] [%+g] [% .1f]", -3.14159, 1.5, 2.0, 0.25);
    check("printf_flags", strcmp(buf, "[-003.142] [1.50e+00] [+2] [ 0.2]") == 0);
    snprintf(buf, sizeof buf, "%f %F %f %e", v_one / v_zero, -v_one / v_zero, v_zero / v_zero, -0.0);
    check("printf_special", strcmp(buf, "inf -INF nan -0.000000e+00") == 0 || strcmp(buf, "inf -INF -nan -0.000000e+00") == 0);
    snprintf(buf, sizeof buf, "%.17g %.20f", 0.1, 0.1);
    check("printf_exact", strcmp(buf, "0.10000000000000001 0.10000000000000000555") == 0);
    snprintf(buf, sizeof buf, "%.3f %g", DBL_MAX / 1e300, DBL_MIN);
    check("printf_extremes", strcmp(buf, "179769313.486 2.22507e-308") == 0);
    float f = 1.1f;
    snprintf(buf, sizeof buf, "%f %.10f", f, f);
    check("printf_float_promoted", strcmp(buf, "1.100000 1.1000000238") == 0);
}

static void parsing(void) {
    char *end;
    check("strtod", strtod("  -12.5e1xyz", &end) == -125.0 && strcmp(end, "xyz") == 0);
    check("strtod_hex", strtod("0x1.8p1", NULL) == 3.0);
    check("strtod_exact", strtod("2.2250738585072011e-308", NULL) == 2.2250738585072011e-308 &&
                              strtod("9007199254740993", NULL) == 9007199254740992.0);
    errno = 0;
    check("strtod_overflow", strtod("1e999", NULL) == HUGE_VAL && errno == ERANGE);
    errno = 0;
    check("strtod_underflow", strtod("1e-999", NULL) == 0.0 && errno == ERANGE);
    check("strtod_inf_nan", isinf(strtod("-Infinity", NULL)) && isnan(strtod("nan", NULL)));
    check("strtod_none", strtod("abc", &end) == 0.0 && strcmp(end, "abc") == 0);
    check("strtof", strtof("0.1", NULL) == 0.1f && atof("2.5") == 2.5);

    int i, n;
    double d;
    float g;
    char word[16], rest[16];
    check("sscanf_mixed", sscanf("42 3.25 hello 1e3", "%d %lf %15s %f", &i, &d, word, &g) == 4 && i == 42 && d == 3.25 &&
                              strcmp(word, "hello") == 0 && g == 1000.0f);
    check("sscanf_set", sscanf("key=value;", "%15[^=]=%15[^;]%n", word, rest, &n) == 2 && strcmp(word, "key") == 0 &&
                            strcmp(rest, "value") == 0 && n == 9);
    check("sscanf_fail", sscanf("x1", "%d", &i) == 0 && sscanf("", "%d", &i) == EOF);
    unsigned u;
    check("sscanf_hex_width", sscanf("ff12", "%2x%d", &u, &i) == 2 && u == 255 && i == 12);

    char path[64];
    snprintf(path, sizeof path, "/tmp/nmath-%d", (int)getpid());
    FILE *out = fopen(path, "w");
    fprintf(out, "1 2.5\n3 4.5\nend\n");
    fclose(out);
    FILE *in = fopen(path, "r");
    double sum = 0;
    int k;
    while (fscanf(in, "%d %lf", &k, &d) == 2)
        sum += k + d;
    int stopped = fscanf(in, "%15s", word) == 1 && strcmp(word, "end") == 0;
    check("fscanf", sum == 11.0 && stopped && fscanf(in, "%d", &k) == EOF);
    fclose(in);
    unlink(path);
}

static void math(void) {
    check("sqrt", sqrt(v_two) == 1.4142135623730951 && sqrtf(2.0f) == 1.41421354f);
    check("rounding", floor(-2.5) == -3.0 && ceil(-2.5) == -2.0 && round(2.5) == 3.0 && round(-2.5) == -3.0 &&
                          trunc(-2.7) == -2.0 && rint(2.5) == 2.0 && rint(3.5) == 4.0 && lround(-1.5) == -2);
    check("exp_log", exp(v_one) == M_E && log(M_E) == 1.0 && exp(v_zero) == 1.0 && log(v_one) == 0.0);
    check("log2_log10", log2(1024.0) == 10.0 && log10(1000.0) == 3.0 && log10(v_half) == -0.3010299956639812);
    check("pow", pow(v_two, v_ten) == 1024.0 && pow(10.0, 5.0) == 100000.0 && pow(v_half, 3.0) == 0.125 &&
                     pow(-2.0, 3.0) == -8.0 && pow(4.0, v_half) == 2.0 && near(pow(1.0001, 10000.0), 2.7181459268249255, 1e-15));
    check("trig", sin(v_zero) == 0.0 && cos(v_zero) == 1.0 && near(sin(M_PI / 6), 0.5, 1e-15) &&
                      near(cos(M_PI / 3), 0.5, 1e-15) && near(tan(M_PI / 4), 1.0, 1e-15));
    check("trig_big", near(sin(1e22), -0.8522008497671888, 1e-15) && near(cos(1e6), 0.9367521275331447, 1e-15));
    check("inverse_trig", atan(v_one) == M_PI_4 && asin(v_one) == M_PI_2 && acos(v_neg) == M_PI &&
                              atan2(v_one, v_neg) == 3 * M_PI_4 && atan2(-0.0, -1.0) == -M_PI);
    check("hyperbolic", sinh(v_zero) == 0.0 && cosh(v_zero) == 1.0 && near(tanh(v_half), 0.46211715726000974, 1e-15) &&
                            near(asinh(v_one), 0.881373587019543, 1e-15) && near(atanh(v_half), 0.5493061443340549, 1e-15));
    check("small_args", expm1(1e-10) == 1.00000000005e-10 && log1p(1e-10) == 9.999999999500001e-11);
    check("cbrt_hypot", cbrt(27.0) == 3.0 && cbrt(-8.0) == -2.0 && hypot(3.0, 4.0) == 5.0 && hypot(1e300, 1e300) == 1.4142135623730952e300);
    int e;
    double m = frexp(48.0, &e), ip;
    check("frexp_ldexp_modf", m == 0.75 && e == 6 && ldexp(0.75, 6) == 48.0 && modf(-3.25, &ip) == -0.25 && ip == -3.0);
    check("fmod_remainder", fmod(10.0, 3.0) == 1.0 && fmod(-10.0, 3.0) == -1.0 && remainder(10.0, 3.0) == 1.0 &&
                                remainder(11.0, 3.0) == -1.0);
    check("fma", fma(0.1, 10.0, -1.0) == 5.551115123125783e-17);
    check("min_max", fmin(v_one, NAN) == 1.0 && fmax(NAN, v_two) == 2.0 && copysign(3.0, -0.0) == -3.0);
    check("classify", isnan(NAN) && isinf(INFINITY) && !isfinite(HUGE_VAL) && fpclassify(DBL_TRUE_MIN) == FP_SUBNORMAL &&
                          signbit(-0.0) && isnormal(1.0));
    check("float_versions", sinf(0.5f) == 0.47942554f && expf(1.0f) == 2.7182817f && powf(2.0f, 0.5f) == 1.4142135f);
    errno = 0;
    double r = sqrt(v_neg);
    check("edom", isnan(r) && errno == EDOM);
    errno = 0;
    r = log(v_zero);
    check("pole", isinf(r) && r < 0 && errno == ERANGE);
    errno = 0;
    r = exp(1000.0 * v_one);
    check("erange", isinf(r) && errno == ERANGE);
}

int main(void) {
    formatting();
    parsing();
    math();
    printf("native-math: %d failures\n", failures);
    return failures;
}
