// SPDX-License-Identifier: MIT OR Apache-2.0
// Dereferences NULL; the kernel must kill it with SIGSEGV.
#include <stdio.h>

int main(void) {
    volatile int *p = 0;
    printf("about to fault\n");
    return *p;
}
