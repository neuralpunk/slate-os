#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The host tools building SlateOS needs (`make deps`); with --run, also
# those for running it in QEMU. Says what is missing and how to install
# it, and fails if anything is.

missing=""
need() { # command, what it is for
    command -v "$1" >/dev/null 2>&1 || missing="$missing\n  $1 ($2)"
}

need rustup "installs the pinned Rust toolchain from rust-toolchain.toml: https://rustup.rs"
need cargo "Rust's build tool, from rustup"
need git "fetches the Limine bootloader for the ISO"
need cc "builds Limine's small host tool"
need objcopy "binutils: the BIOS bootloader's images"
need nm "binutils: the BIOS bootloader's symbols"
need curl "downloads"
need tar "unpacks downloads"

if [ "$1" = "--run" ]; then
    need qemu-system-x86_64 "runs SlateOS in a virtual machine"
    ovmf="${SLATE_OVMF_CODE:-}"
    # The places tools/xtask/src/qemu.rs looks (OVMF).
    for f in /usr/share/edk2/ovmf/OVMF_CODE.fd /usr/share/OVMF/OVMF_CODE.fd \
             /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/edk2/x64/OVMF_CODE.4m.fd; do
        [ -e "$f" ] && ovmf="$f"
    done
    [ -n "$ovmf" ] || missing="$missing\n  OVMF (UEFI firmware for QEMU)"
fi

if [ -n "$missing" ]; then
    printf 'SlateOS needs these to build:%b\n\n' "$missing" >&2
    cat >&2 <<'EOF'
On Fedora:         sudo dnf install git gcc binutils curl tar qemu-system-x86 edk2-ovmf
On Debian/Ubuntu:  sudo apt install git gcc binutils curl tar qemu-system-x86 ovmf
On Arch:           sudo pacman -S git gcc binutils curl tar qemu-system-x86 edk2-ovmf
Rust:              https://rustup.rs (the pinned nightly then installs itself)
EOF
    exit 1
fi
