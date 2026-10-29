// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Alpine Linux minirootfs, a test load for dynamic linking and chroot
//! (M8). Pinned by version and SHA-256; extracted with the host's tar.

use std::path::PathBuf;
use std::process::Command;

use crate::{Result, run_cmd, target_dir};

const VERSION: &str = "3.22.6";
const URL: &str = "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/alpine-minirootfs-3.22.6-x86_64.tar.gz";
const SHA256: &str = "27694aaa55fd7a9e3ef596e0ad4eb66802308bb20172b17030cd5f4d8ae9bac2";

/// Directory holding the extracted root file system, fetching it on first use.
pub fn fetch() -> Result<PathBuf> {
    let base = target_dir().join(format!("alpine-{VERSION}"));
    let root = base.join("rootfs");
    if root.join("etc/alpine-release").exists() {
        return Ok(root);
    }
    let tarball = tarball()?;
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    run_cmd(Command::new("tar").args(["-xzf"]).arg(&tarball).arg("-C").arg(&root).arg("--no-same-owner"))?;
    Ok(root)
}

/// The minirootfs tarball, fetched and checked against the pin (which
/// `slate-linux setup` pins too: userland/linux-app/src/setup.rs).
pub fn tarball() -> Result<PathBuf> {
    let base = target_dir().join(format!("alpine-{VERSION}"));
    std::fs::create_dir_all(&base).map_err(|e| e.to_string())?;
    let tarball = base.join("minirootfs.tar.gz");
    if !tarball.exists() {
        run_cmd(Command::new("curl").args(["-fsSL", "-o"]).arg(&tarball).arg(URL))?;
    }
    let out = Command::new("sha256sum").arg(&tarball).output().map_err(|e| e.to_string())?;
    let sum = String::from_utf8_lossy(&out.stdout);
    if sum.split_whitespace().next() != Some(SHA256) {
        let _ = std::fs::remove_file(&tarball);
        return Err(format!("alpine minirootfs checksum mismatch: {sum}"));
    }
    Ok(tarball)
}
