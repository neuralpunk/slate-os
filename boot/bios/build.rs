// SPDX-License-Identifier: MIT OR Apache-2.0

//! Each binary has its own linker script: the boot sector at 0x7C00, the
//! loader at 0x8000 (ADR 0089).

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg-bin=slate-loader-mbr=-T{dir}/mbr.ld");
    println!("cargo:rustc-link-arg-bin=slate-loader-bios=-T{dir}/stage2.ld");
    println!("cargo:rerun-if-changed=mbr.ld");
    println!("cargo:rerun-if-changed=stage2.ld");
}
