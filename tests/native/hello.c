// SPDX-License-Identifier: MIT OR Apache-2.0
// The smallest slate-libc program (ADR 0031): built by tools/slate-cc.
#include <stdio.h>

int main(void) {
    printf("Hello from slate-libc, %s!\n", "native Slate");
    return 0;
}
