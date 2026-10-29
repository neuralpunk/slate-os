// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Linux Test Project as a test load (ADR 0047): a pinned release,
//! built on the host with musl-gcc, statically, and the tests listed in
//! `tests/ltp/subset.txt` put in the test image under `/test/ltp`.
//!
//! LTP is GPL-2.0 and a test load only (handoff §3): nothing of it is
//! part of Slate, and its sources are never read to write Slate's. It is
//! compiled against the host's Linux UAPI headers, which musl leaves out;
//! only the third-party build sees them (ADR 0047), never Slate's code.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Result, root, run_cmd, target_dir};

const VERSION: &str = "20260529";
const URL: &str = "https://github.com/linux-test-project/ltp/releases/download/20260529/ltp-full-20260529.tar.xz";
const SHA256: &str = "685d83c6e370ac09201fb79593412f868fe031ee2890e204b5727fedcf51fb47";

/// The tests of the subset, as `directory/name` under
/// `testcases/kernel/syscalls`, each with whether it is only a helper
/// another test runs (marked `# helper`: installed, not run).
pub fn subset() -> Result<Vec<(String, bool)>> {
    let list = std::fs::read_to_string(root().join("tests/ltp/subset.txt")).map_err(|e| e.to_string())?;
    Ok(list
        .lines()
        .filter_map(|l| {
            let (entry, comment) = l.split_once('#').unwrap_or((l, ""));
            let entry = entry.trim();
            (!entry.is_empty()).then(|| (entry.to_string(), comment.trim() == "helper"))
        })
        .collect())
}

fn src_dir() -> PathBuf {
    target_dir().join(format!("ltp-{VERSION}/ltp-full-{VERSION}"))
}

/// Download and unpack the release, once.
fn fetch() -> Result<PathBuf> {
    let base = target_dir().join(format!("ltp-{VERSION}"));
    let src = src_dir();
    if src.join("configure").exists() {
        return Ok(src);
    }
    std::fs::create_dir_all(&base).map_err(|e| e.to_string())?;
    let tarball = base.join("ltp.tar.xz");
    run_cmd(Command::new("curl").args(["-fsSL", "-o"]).arg(&tarball).arg(URL))?;
    let out = Command::new("sha256sum").arg(&tarball).output().map_err(|e| e.to_string())?;
    let sum = String::from_utf8_lossy(&out.stdout);
    if sum.split_whitespace().next() != Some(SHA256) {
        let _ = std::fs::remove_file(&tarball);
        return Err(format!("LTP checksum mismatch: {sum}"));
    }
    run_cmd(Command::new("tar").arg("-xf").arg(&tarball).arg("-C").arg(&base))?;
    Ok(src)
}

/// Configure and build LTP's library, once.
fn configure(src: &Path) -> Result {
    if src.join("lib/libltp.a").exists() {
        return Ok(());
    }
    // Only the UAPI directories, not the host's whole /usr/include (glibc's
    // headers must not mix with musl's).
    let uapi = src.parent().unwrap().join("uapi");
    std::fs::create_dir_all(&uapi).map_err(|e| e.to_string())?;
    for d in ["linux", "asm", "asm-generic", "mtd"] {
        let link = uapi.join(d);
        if !link.exists() {
            std::os::unix::fs::symlink(Path::new("/usr/include").join(d), &link).map_err(|e| e.to_string())?;
        }
    }
    let cc = std::env::var("SLATE_MUSL_CC").unwrap_or_else(|_| "musl-gcc".into());
    let mut c = Command::new("./configure");
    c.current_dir(src)
        .env("CC", cc)
        .env("CFLAGS", format!("-O2 -isystem {}", uapi.display()))
        .env("LDFLAGS", "-static")
        .args([
            "--without-numa",
            "--without-tirpc",
            "--without-libcap",
            "--without-keyutils",
            "--without-selinux",
            "--without-libacl",
            "--without-libaio",
        ]);
    run_cmd(&mut c)?;
    run_cmd(Command::new("make").current_dir(src).args(["-j8", "-C", "lib"]))
}

/// Build the subset; returns (name, stripped binary, helper) triples.
pub fn build() -> Result<Vec<(String, PathBuf, bool)>> {
    let src = fetch()?;
    configure(&src)?;
    let subset = subset()?;
    let tests: Vec<String> = subset.iter().map(|(t, _)| t.clone()).collect();
    let syscalls = src.join("testcases/kernel/syscalls");
    let out_dir = target_dir().join(format!("ltp-{VERSION}/bin"));
    std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let mut dirs: Vec<&str> = tests.iter().filter_map(|t| t.split('/').next()).collect();
    dirs.sort_unstable();
    dirs.dedup();
    for d in dirs {
        let missing = tests.iter().any(|t| t.starts_with(&format!("{d}/")) && !syscalls.join(t).exists());
        if missing {
            run_cmd(Command::new("make").current_dir(syscalls.join(d)).arg("-j8"))?;
        }
    }
    let mut out = Vec::new();
    for (t, helper) in &subset {
        let name = t.rsplit('/').next().unwrap_or(t).to_string();
        let bin = out_dir.join(&name);
        let built = syscalls.join(t);
        let fresh = match (std::fs::metadata(&built), std::fs::metadata(&bin)) {
            (Ok(s), Ok(o)) => o.modified().ok() >= s.modified().ok(),
            _ => false,
        };
        if !fresh {
            std::fs::copy(&built, &bin).map_err(|e| format!("{}: {e}", built.display()))?;
            run_cmd(Command::new("strip").arg(&bin))?;
        }
        out.push((name, bin, *helper));
    }
    Ok(out)
}
