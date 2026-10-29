// SPDX-License-Identifier: MIT OR Apache-2.0

//! Building the user-space test programs in `tests/user` with the host's
//! `musl-gcc` (static). They are test loads, not part of Slate. The
//! programs in `tests/native` use Slate's native interface (ADR 0031):
//! those at the top are built with slate-libc by `tools/slate-cc`, those
//! in `tests/native/raw` freestanding (their own system calls). Both land
//! in /test as `native-NAME`.

use std::path::PathBuf;
use std::process::Command;

use crate::{Result, root, run_cmd, target_dir};

/// Extra variants built from the same source with different flags.
const VARIANTS: &[(&str, &str, &[&str])] = &[
    ("hello-pie", "hello.c", &["-static-pie", "-fPIE"]),
    // Measures the layout's randomization (ADR 0092): its own code must move.
    ("aslr-pie", "aslr.c", &["-static-pie", "-fPIE"]),
];

/// Flags for the native programs: no C library, no start files.
const NATIVE_FLAGS: &[&str] = &["-static", "-nostdlib", "-ffreestanding", "-fno-stack-protector", "-fno-builtin"];

fn sources(dir: &std::path::Path) -> Result<Vec<PathBuf>> {
    let mut sources: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "c"))
        .collect();
    sources.sort();
    Ok(sources)
}

fn compile(src: &std::path::Path, out: &std::path::Path, flags: &[&str]) -> Result {
    let fresh = match (std::fs::metadata(src), std::fs::metadata(out)) {
        (Ok(s), Ok(o)) => o.modified().ok() >= s.modified().ok(),
        _ => false,
    };
    if fresh {
        return Ok(());
    }
    let cc = std::env::var("SLATE_MUSL_CC").unwrap_or_else(|_| "musl-gcc".into());
    let mut c = Command::new(cc);
    c.args(["-O2", "-Wall", "-Wextra", "-Werror"]);
    if flags.is_empty() {
        c.arg("-static");
    } else {
        c.args(flags);
    }
    run_cmd(c.arg(src).arg("-o").arg(out))
}

/// The programs in `tests/native` built with slate-libc, as (name, path).
/// They also run on the host (slate-rt makes Linux calls there).
pub fn build_native_libc() -> Result<Vec<(String, PathBuf)>> {
    let sysroot = crate::userland::sysroot()?;
    let out_dir = target_dir().join("user");
    std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for src in sources(&root().join("tests/native"))? {
        let name = format!("native-{}", src.file_stem().unwrap().to_string_lossy());
        let bin = out_dir.join(&name);
        let mut c = Command::new(root().join("tools/slate-cc"));
        c.env("SLATE_SYSROOT", &sysroot).args(["-O2", "-Wall", "-Wextra", "-Werror"]);
        run_cmd(c.arg(&src).arg("-o").arg(&bin))?;
        out.push((name, bin));
    }
    Ok(out)
}

/// Build every program; returns (module name, binary path) pairs.
pub fn build() -> Result<Vec<(String, PathBuf)>> {
    static BUILT: std::sync::OnceLock<Result<Vec<(String, PathBuf)>>> = std::sync::OnceLock::new();
    crate::once(&BUILT, build_now)
}

fn build_now() -> Result<Vec<(String, PathBuf)>> {
    let src_dir = root().join("tests/user");
    let out_dir = target_dir().join("user");
    std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for src in sources(&src_dir)? {
        let name = src.file_stem().unwrap().to_string_lossy().into_owned();
        let bin = out_dir.join(&name);
        compile(&src, &bin, &[])?;
        out.push((name, bin));
    }
    for (name, src, flags) in VARIANTS {
        let bin = out_dir.join(name);
        compile(&src_dir.join(src), &bin, flags)?;
        out.push((name.to_string(), bin));
    }
    for src in sources(&root().join("tests/native/raw"))? {
        let name = format!("native-{}", src.file_stem().unwrap().to_string_lossy());
        let bin = out_dir.join(&name);
        compile(&src, &bin, NATIVE_FLAGS)?;
        out.push((name, bin));
    }
    out.extend(build_native_libc()?);
    Ok(out)
}
