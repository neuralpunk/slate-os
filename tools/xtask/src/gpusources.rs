// SPDX-License-Identifier: MIT OR Apache-2.0

//! `cargo xtask gpu-sources`: the GPU drivers' sources (ADR 0157 and its
//! addendum; docs/gpu/SOURCES.md), fetched for reading into
//! `target/gpu/sources/NAME@VERSION`, never into the tree. Each is a
//! shallow, sparse clone at a pinned version, so a citation's "file and
//! version" can be looked up again. `SLATE_GPU_SOURCES=amd,nvidia,intel,dp`
//! fetches some families only (all by default). Needs the internet.
//!
//! Linux is read for GPU drivers only (the addendum), and only these
//! directories are fetched; and, family `mediatek` (not fetched by
//! default), drivers/bluetooth for MediaTek's Bluetooth firmware download,
//! of which only btmtk.c, btmtk.h and btusb.c's MediaTek parts may be read
//! (ADR 0176); and, family `intel-nic` (not fetched by default),
//! drivers/net/ethernet/intel/igc for Intel's I225 and I226 network
//! controllers (ADR 0178).

use std::path::Path;
use std::process::Command;

use crate::{Result, run_cmd, target_dir};

struct Source {
    family: &'static str,
    name: &'static str,
    url: &'static str,
    /// A tag or a commit.
    version: &'static str,
    paths: &'static [&'static str],
}

/// The pins: Linux at the version the reference PC's Fedora runs (so what is read
/// matches the state observed there), NVIDIA's at their latest when M32
/// began (2026-10-28).
const SOURCES: &[Source] = &[
    Source {
        family: "nvidia",
        name: "open-gpu-doc",
        url: "https://github.com/NVIDIA/open-gpu-doc",
        version: "9fdf5c4062007929d9f4e6cbad9c9771fe61b880",
        paths: &[],
    },
    Source {
        family: "nvidia",
        name: "open-gpu-kernel-modules",
        url: "https://github.com/NVIDIA/open-gpu-kernel-modules",
        version: "615.78.08",
        paths: &["src/common/sdk", "src/common/inc", "src/nvidia/inc", "src/nvidia/arch", "src/nvidia/generated"],
    },
    Source {
        family: "nvidia",
        name: "linux",
        url: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
        version: "v7.2.12",
        paths: &["drivers/gpu/drm/nouveau", "drivers/gpu/drm/nova"],
    },
    Source {
        family: "amd",
        name: "linux",
        url: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
        version: "v7.2.12",
        paths: &["drivers/gpu/drm/amd/display", "drivers/gpu/drm/amd/include", "drivers/gpu/drm/amd/amdgpu"],
    },
    Source {
        family: "intel",
        name: "linux",
        url: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
        version: "v7.2.12",
        paths: &["drivers/gpu/drm/i915/display", "drivers/gpu/drm/xe"],
    },
    Source {
        family: "mediatek",
        name: "linux",
        url: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
        version: "v7.2.12",
        paths: &["drivers/bluetooth"],
    },
    Source {
        family: "intel-nic",
        name: "linux",
        url: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
        version: "v7.2.12",
        paths: &["drivers/net/ethernet/intel/igc"],
    },
    Source {
        family: "dp",
        name: "linux",
        url: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
        version: "v7.2.12",
        paths: &["drivers/gpu/drm/display", "include/drm/display"],
    },
];

pub fn fetch() -> Result {
    let want = std::env::var("SLATE_GPU_SOURCES").unwrap_or_else(|_| "amd,nvidia,intel,dp".into());
    let want: Vec<&str> = want.split(',').map(str::trim).collect();
    let base = target_dir().join("gpu/sources");
    std::fs::create_dir_all(&base).map_err(|e| e.to_string())?;
    // Sources sharing a clone (Linux) get the union of every family's paths
    // (a sparse checkout set to one family's would drop the others').
    let mut done: Vec<&str> = Vec::new();
    for s in SOURCES.iter().filter(|s| want.contains(&s.family)) {
        if done.contains(&s.name) {
            continue;
        }
        done.push(s.name);
        let mut paths: Vec<&str> =
            SOURCES.iter().filter(|o| o.name == s.name).flat_map(|o| o.paths.iter().copied()).collect();
        paths.dedup();
        let dir = base.join(format!("{}@{}", s.name, s.version));
        clone(s, &dir, &paths)?;
        println!("xtask: gpu-sources: {} ({}) in {}", s.name, s.version, dir.display());
    }
    Ok(())
}

fn git(dir: &Path) -> Command {
    let mut c = Command::new("git");
    c.arg("-C").arg(dir);
    c
}

/// A shallow clone of one version, only `paths` checked out (all of it
/// when empty). Fetching again adds paths to what is there.
fn clone(s: &Source, dir: &Path, paths: &[&str]) -> Result {
    if !dir.join(".git").exists() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        run_cmd(Command::new("git").args(["init", "-q"]).arg(dir))?;
        run_cmd(git(dir).args(["remote", "add", "origin", s.url]))?;
    }
    if !paths.is_empty() {
        run_cmd(git(dir).args(["sparse-checkout", "set", "--cone"]).args(paths))?;
    }
    run_cmd(git(dir).args(["fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", s.version]))?;
    run_cmd(git(dir).args(["checkout", "-q", "FETCH_HEAD"]))
}
