// SPDX-License-Identifier: MIT OR Apache-2.0
// Keeps values in SSE registers across many timer preemptions; run several
// copies at once to check that FPU/SIMD state is saved per thread.
#include <stdio.h>
#include <time.h>

int main(void) {
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    double a = 1.0, b = 0.5;
    long iterations = 0;
    for (;;) {
        // Each step keeps a + 2b == 2 exactly in binary floating point.
        a += 0.25;
        b -= 0.125;
        if (a + 2 * b != 2.0) {
            printf("SLATE-TEST: FAIL user::fpu_state (a=%f b=%f after %ld)\n", a, b, iterations);
            return 1;
        }
        a -= 0.25;
        b += 0.125;
        iterations++;
        if ((iterations & 0xFFFF) == 0) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            if ((now.tv_sec - start.tv_sec) * 1000000000L + (now.tv_nsec - start.tv_nsec) > 300000000L)
                break;
        }
    }
    return 0;
}
