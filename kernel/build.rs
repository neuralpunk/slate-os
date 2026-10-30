// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::Path;
use std::process::Command;

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if os == "none" && arch == "x86_64" {
        println!("cargo:rustc-link-arg-bins=-T{dir}/linker-x86_64.ld");
        println!("cargo:rerun-if-changed=linker-x86_64.ld");
    }
    let out = std::env::var("OUT_DIR").unwrap();
    build_vdso(Path::new(&dir), Path::new(&out));
    trusted_keys(Path::new(&out));
}

/// The public keys the kernel trusts for signed programs (ADR 0090), from
/// the file `SLATE_TRUSTED_KEYS` names (xtask sets it to the checkout's
/// development key), into `$OUT_DIR/trusted.keys`. Without it, none.
fn trusted_keys(out: &Path) {
    println!("cargo:rerun-if-env-changed=SLATE_TRUSTED_KEYS");
    let keys = match std::env::var("SLATE_TRUSTED_KEYS") {
        Ok(p) => {
            println!("cargo:rerun-if-changed={p}");
            std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("SLATE_TRUSTED_KEYS={p}: {e}"))
        }
        Err(_) => String::new(),
    };
    std::fs::write(out.join("trusted.keys"), keys).unwrap();
}

/// Build the vDSO (kernel/vdso) as a shared object for x86-64 Linux user
/// space and leave it at `$OUT_DIR/vdso.so`, where the kernel embeds it.
/// It must be position-independent with no relocations, and its file
/// offsets must equal its addresses, so the kernel can map the file as is.
fn build_vdso(dir: &Path, out: &Path) {
    let vdso = dir.join("vdso");
    for f in ["Cargo.toml", "vdso.lds", "layout.lds", "src/lib.rs"] {
        println!("cargo:rerun-if-changed={}", vdso.join(f).display());
    }
    let script = vdso.join("vdso.lds");
    let layout = vdso.join("layout.lds");
    let target_dir = out.join("vdso-target");
    let mut c = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    // Nothing from the kernel's own build may leak into this one.
    for v in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WORKSPACE_WRAPPER", "RUSTC_WRAPPER", "CARGO_BUILD_TARGET"]
    {
        c.env_remove(v);
    }
    c.current_dir(dir).args(["rustc", "--quiet", "--package", "slate-vdso", "--release"]);
    c.args(["--target", "x86_64-unknown-linux-gnu", "--target-dir"]).arg(&target_dir);
    c.args(["--", "-C", "panic=abort", "-C", "relocation-model=pic", "-C", "debuginfo=0"]);
    for a in [
        "-nostdlib".to_string(),
        "-Wl,-soname=linux-vdso.so.1".into(),
        format!("-Wl,--version-script={}", script.display()),
        // One read-only, executable segment, the dynamic section in it
        // (its DYNAMIC header read-only: glibc relocates a writable one).
        format!("-Wl,-T,{}", layout.display()),
        "-Wl,--hash-style=both".into(),
        "-Wl,-z,max-page-size=4096".into(),
        "-Wl,-z,norelro".into(),
        "-Wl,--no-rosegment".into(),
        "-Wl,--build-id=none".into(),
        "-Wl,--strip-all".into(),
    ] {
        c.args(["-C", &format!("link-arg={a}")]);
    }
    let status = c.status().expect("failed to run cargo for the vDSO");
    assert!(status.success(), "building the vDSO failed");
    let built = target_dir.join("x86_64-unknown-linux-gnu/release/libslate_vdso.so");
    let image = std::fs::read(&built).expect("reading the vDSO");
    assert!(
        !has_relocations(&image),
        "the vDSO needs relocations (a call into a compiler helper such as 128-bit division?): \
         nothing applies them, so they would crash at run time"
    );
    std::fs::copy(&built, out.join("vdso.so")).expect("copying the vDSO");
}

/// Whether an ELF64 image has a non-empty SHT_RELA (4) or SHT_REL (9)
/// section (ELF specification: section header table at e_shoff, e_shnum
/// entries of e_shentsize; sh_type at +4, sh_size at +32).
fn has_relocations(elf: &[u8]) -> bool {
    let u16_at = |o: usize| u16::from_le_bytes([elf[o], elf[o + 1]]) as usize;
    let u32_at = |o: usize| u32::from_le_bytes(elf[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(elf[o..o + 8].try_into().unwrap());
    let (shoff, shentsize, shnum) = (u64_at(0x28) as usize, u16_at(0x3A), u16_at(0x3C));
    (0..shnum).any(|i| {
        let sh = shoff + i * shentsize;
        matches!(u32_at(sh + 4), 4 | 9) && u64_at(sh + 32) > 0
    })
}
