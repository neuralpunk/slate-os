/* SPDX-License-Identifier: MIT OR Apache-2.0 */
#include <math.h>

#include "stats.h"

unsigned long long sum_squares(unsigned long long from, unsigned long long to) {
    unsigned long long s = 0;
    for (unsigned long long i = from; i < to; i++) s += i * i;
    return s;
}

double rms(const double *values, size_t n) {
    double s = 0;
    for (size_t i = 0; i < n; i++) s += values[i] * values[i];
    return n ? sqrt(s / (double)n) : 0;
}
