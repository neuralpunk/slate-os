// SPDX-License-Identifier: MIT OR Apache-2.0
// A Linux binary in a quarry package (abi: linux, ADR 0022).
#include <stdio.h>

int main(void) {
    printf("qhello: a Linux binary from quarry\n");
    return 0;
}
