# User-space test programs

Small C programs built on the host with Fedora's `musl-gcc` (static) by
`cargo xtask`, and booted as Limine modules (later: from the initramfs).
They are test loads, not part of Slate.

Each program reports results with `SLATE-TEST: PASS|FAIL user::<name>`
lines, like the in-kernel tests, and exits with the number of failures.
