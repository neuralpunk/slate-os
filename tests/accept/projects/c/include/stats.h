/* SPDX-License-Identifier: MIT OR Apache-2.0 */
#ifndef STATS_H
#define STATS_H

#include <stddef.h>

/* Sum of i*i for i in [from, to). */
unsigned long long sum_squares(unsigned long long from, unsigned long long to);
double rms(const double *values, size_t n);

#endif
