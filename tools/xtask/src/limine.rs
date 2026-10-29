// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fetching the pinned Limine binary release and building its host utility.
//!
//! Limine is a third-party bootloader (BSD-2-Clause) that we use, not code we
//! ship as part of Slate's own sources; see docs/adr/0003-limine.md.

use std::path::PathBuf;
use std::process::Command;

use crate::{Result, run_cmd, target_dir};

pub const VERSION: &str = "11.2.1";
const REPO: &str = "https://codeberg.org/Limine/Limine.git";
/// The commit the `v11.2.1-binary` tag points to. A mismatch means the tag
/// moved or the download was tampered with, and the build stops.
const COMMIT: &str = "deba356b4a70ee183ec3214864f0ba2ffe510b8c";

/// A checked-out Limine binary release.
#[derive(Debug)]
pub struct Limine {
    pub dir: PathBuf,
}

impl Limine {
    pub fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// The host `limine` utility (used for `bios-install`).
    pub fn tool(&self) -> PathBuf {
        self.dir.join("limine")
    }

    /// The BIOS stages 1 and 2 for disks (`limine-bios-hdd.bin`), which the
    /// release carries as a C array in `limine-bios-hdd.h` (the host tool
    /// embeds it); the installer writes them (ADR 0039).
    pub fn bios_hdd(&self) -> Result<Vec<u8>> {
        let src = std::fs::read_to_string(self.file("limine-bios-hdd.h")).map_err(|e| e.to_string())?;
        let body = src
            .split_once('{')
            .and_then(|(_, b)| b.split_once('}'))
            .map(|(b, _)| b)
            .ok_or("limine-bios-hdd.h: no array")?;
        body.split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(|t| {
                u8::from_str_radix(t.trim_start_matches("0x"), 16).map_err(|e| format!("limine-bios-hdd.h: {t}: {e}"))
            })
            .collect()
    }
}

/// Fetch (once) and verify the Limine release, then build the host utility.
pub fn fetch() -> Result<Limine> {
    let dir = target_dir().join(format!("limine-{VERSION}"));
    if !dir.join(".git").exists() {
        let tag = format!("v{VERSION}-binary");
        let tmp = target_dir().join(format!("limine-{VERSION}.partial"));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(target_dir()).map_err(|e| e.to_string())?;
        run_cmd(
            Command::new("git")
                .args(["-c", "advice.detachedHead=false", "clone", "--quiet", "--depth", "1", "--branch", &tag, REPO])
                .arg(&tmp),
        )?;
        std::fs::rename(&tmp, &dir).map_err(|e| e.to_string())?;
    }

    let out =
        Command::new("git").arg("-C").arg(&dir).args(["rev-parse", "HEAD"]).output().map_err(|e| e.to_string())?;
    let head = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if head != COMMIT {
        return Err(format!("{} is at {head}, expected pinned commit {COMMIT}", dir.display()));
    }

    let limine = Limine { dir };
    if !limine.tool().exists() {
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
        run_cmd(
            Command::new(cc).current_dir(&limine.dir).args(["-O2", "-pipe", "-std=c99", "limine.c", "-o", "limine"]),
        )?;
    }
    Ok(limine)
}
