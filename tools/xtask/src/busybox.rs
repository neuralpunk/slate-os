// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fetching a static BusyBox as a test load (handoff §3: third-party
//! software is a test load, never part of Slate).
//!
//! The binary comes from Alpine Linux's `busybox-static` package, pinned by
//! version and SHA-256. The applet list (`busybox --list-full`) is checked
//! in as `busybox-applets.txt`, so the build never runs the binary on the
//! host.

use std::path::PathBuf;
use std::process::Command;

use crate::{Result, root, run_cmd, target_dir};

const VERSION: &str = "1.37.0-r20";
const URL: &str = "https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/busybox-static-1.37.0-r20.apk";
const SHA256: &str = "488ad6efd04b5a722719e79f8e0dcc2c24afd6758867af3ce41b04839e60c74b";

/// Path of the extracted static BusyBox, downloading it on first use.
pub fn fetch() -> Result<PathBuf> {
    let dir = target_dir().join(format!("busybox-{VERSION}"));
    let bin = dir.join("bin/busybox.static");
    if bin.exists() {
        return Ok(bin);
    }
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let apk = dir.join("busybox-static.apk");
    run_cmd(Command::new("curl").args(["-fsSL", "-o"]).arg(&apk).arg(URL))?;
    let out = Command::new("sha256sum").arg(&apk).output().map_err(|e| e.to_string())?;
    let sum = String::from_utf8_lossy(&out.stdout);
    if sum.split_whitespace().next() != Some(SHA256) {
        let _ = std::fs::remove_file(&apk);
        return Err(format!("busybox-static checksum mismatch: {sum}"));
    }
    // An .apk is a concatenation of gzipped tar streams; GNU tar reads them all.
    run_cmd(
        Command::new("tar")
            .args(["--warning=no-unknown-keyword", "-xzf"])
            .arg(&apk)
            .arg("-C")
            .arg(&dir)
            .arg("bin/busybox.static"),
    )?;
    Ok(bin)
}

/// Install paths of every applet, relative to `/`.
pub fn applets() -> Result<Vec<String>> {
    let list = std::fs::read_to_string(root().join("tools/xtask/busybox-applets.txt")).map_err(|e| e.to_string())?;
    Ok(list.lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect())
}
