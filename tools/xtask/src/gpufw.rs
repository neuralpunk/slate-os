// SPDX-License-Identifier: MIT OR Apache-2.0

//! AMD's firmware for full graphics (ADR 0173): the files Slate's AMD
//! driver loads, from linux-firmware on the build machine (Fedora's
//! `amd-gpu-firmware`, xz-compressed in /usr/lib/firmware; another
//! directory with `SLATE_LINUX_FIRMWARE`), decompressed once into
//! target/gpu/firmware, never committed (ADR 0012's firmware exception),
//! for the `slate-firmware-gpu` package.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::target_dir;

/// The files, by their names under /lib/firmware: DCN 3.1.5's DMCUB,
/// MP0 13.0.5's TOC (the display, ADR 0171), GC 10.3.6's and SDMA
/// 5.2.6's (the shaders and the copy engine, ADR 0172).
pub const FILES: [&str; 9] = [
    "amdgpu/dcn_3_1_5_dmcub.bin",
    "amdgpu/psp_13_0_5_toc.bin",
    "amdgpu/sdma_5_2_6.bin",
    "amdgpu/gc_10_3_6_ce.bin",
    "amdgpu/gc_10_3_6_pfp.bin",
    "amdgpu/gc_10_3_6_me.bin",
    "amdgpu/gc_10_3_6_mec.bin",
    "amdgpu/gc_10_3_6_mec2.bin",
    "amdgpu/gc_10_3_6_rlc.bin",
];

/// AMD's licence for them, as linux-firmware ships it.
const LICENSES: [&str; 2] =
    ["/usr/share/licenses/amd-gpu-firmware/LICENSE.amdgpu", "/usr/share/licenses/linux-firmware/LICENSE.amdgpu"];

fn source() -> PathBuf {
    std::env::var_os("SLATE_LINUX_FIRMWARE").map_or_else(|| PathBuf::from("/usr/lib/firmware"), PathBuf::from)
}

/// The decompressed file `name`, from the cache or the source.
fn file(name: &str) -> Option<Vec<u8>> {
    linux_firmware(name, "gpu/firmware")
}

/// linux-firmware's file `name`, decompressed (it may be xz'd) and kept in
/// target/`cache`.
pub fn linux_firmware(name: &str, cache: &str) -> Option<Vec<u8>> {
    let cached = target_dir().join(cache).join(name);
    if let Ok(b) = std::fs::read(&cached) {
        return Some(b);
    }
    let src = source().join(name);
    let data = if src.exists() {
        std::fs::read(&src).ok()?
    } else {
        let xz = PathBuf::from(format!("{}.xz", src.display()));
        let out = Command::new("xz").arg("-dc").arg(&xz).output().ok()?;
        if !out.status.success() || out.stdout.is_empty() {
            return None;
        }
        out.stdout
    };
    std::fs::create_dir_all(cached.parent()?).ok()?;
    std::fs::write(&cached, &data).ok()?;
    Some(data)
}

/// Every file and the licence (its path in the package, its bytes), or
/// none if any is missing.
pub fn files() -> Option<Vec<(String, Vec<u8>)>> {
    let mut v: Vec<(String, Vec<u8>)> =
        FILES.iter().map(|n| file(n).map(|d| (format!("lib/firmware/{n}"), d))).collect::<Option<_>>()?;
    let licence = LICENSES.iter().find_map(|p| std::fs::read(Path::new(p)).ok())?;
    v.push(("usr/share/licenses/slate-firmware-gpu/LICENSE.amdgpu".into(), licence));
    Some(v)
}
