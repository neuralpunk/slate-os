// SPDX-License-Identifier: MIT OR Apache-2.0

//! Slate's own bootloader (ADR 0089): building slate-loader for UEFI and
//! BIOS, or taking Limine's instead with `SLATE_LOADER=limine`, and
//! putting BIOS stages on a disk image.

use std::path::PathBuf;
use std::process::Command;

use crate::{Result, cargo, limine, run_cmd, target_dir};

pub const UEFI_TARGET: &str = "x86_64-unknown-uefi";

/// Images carry Limine instead of slate-loader (`SLATE_LOADER=limine`).
pub fn limine_wanted() -> bool {
    std::env::var("SLATE_LOADER").is_ok_and(|v| v == "limine")
}

/// slate-loader's UEFI executable, built for release (the menu draws in
/// software); Limine's with `SLATE_LOADER=limine`.
pub fn uefi() -> Result<PathBuf> {
    static BUILT: std::sync::OnceLock<Result<PathBuf>> = std::sync::OnceLock::new();
    crate::once(&BUILT, uefi_now)
}

fn uefi_now() -> Result<PathBuf> {
    if limine_wanted() {
        return Ok(limine::fetch()?.file("BOOTX64.EFI"));
    }
    run_cmd(
        cargo()
            .args(["build", "--release", "--package", "slate-loader-uefi", "--target", UEFI_TARGET])
            .args(["-Zbuild-std=core,alloc", "-Zbuild-std-features=compiler-builtins-mem"]),
    )?;
    Ok(target_dir().join(UEFI_TARGET).join("release/slate-loader-uefi.efi"))
}

/// The BIOS loader's files: the boot sector and what it loads, as one
/// image (`hdd`, the boot sector first), and Limine's stage 3 for its ESP
/// when Limine is used.
#[derive(Debug, Clone)]
pub struct Bios {
    pub hdd: Vec<u8>,
    pub sys: Option<Vec<u8>>,
}

/// slate-loader for BIOS: the boot sector with the loader's length filled
/// in, then the loader (ADR 0089); Limine's with `SLATE_LOADER=limine`.
pub fn bios() -> Result<Bios> {
    static BUILT: std::sync::OnceLock<Result<Bios>> = std::sync::OnceLock::new();
    crate::once(&BUILT, bios_now)
}

fn bios_now() -> Result<Bios> {
    if limine_wanted() {
        let l = limine::fetch()?;
        let sys = std::fs::read(l.file("limine-bios.sys")).map_err(|e| format!("limine-bios.sys: {e}"))?;
        return Ok(Bios { hdd: l.bios_hdd()?, sys: Some(sys) });
    }
    // The userland's target, static: the real-mode code needs absolute
    // addresses (the userland's own is position-independent, ADR 0092).
    let target = crate::root().join("tools/x86_64-slate-loader.json");
    run_cmd(cargo().args(["build", "--release", "--package", "slate-loader-bios", "--target"]).arg(&target).args([
        "-Zjson-target-spec",
        "-Zbuild-std=core,alloc",
        "-Zbuild-std-features=compiler-builtins-mem",
    ]))?;
    let dir = target_dir().join("x86_64-slate-loader/release");
    let (mbr, stage2) = (dir.join("slate-loader-mbr.bin"), dir.join("slate-loader-bios.bin"));
    run_cmd(Command::new("objcopy").args(["-O", "binary", "-j", ".boot"]).arg(dir.join("slate-loader-mbr")).arg(&mbr))?;
    run_cmd(Command::new("objcopy").args(["-O", "binary"]).arg(dir.join("slate-loader-bios")).arg(&stage2))?;
    let mut hdd = std::fs::read(&mbr).map_err(|e| e.to_string())?;
    let loader = std::fs::read(&stage2).map_err(|e| e.to_string())?;
    if hdd.len() != 512 || hdd[510..] != [0x55, 0xAA] || hdd[218..224].iter().any(|&b| b != 0) {
        return Err("slate-loader's boot sector is not 512 bytes, or its code reaches byte 218".into());
    }
    // The loader and its bss end below 0x70000 (boot/bios/src/rm.rs).
    let nm = Command::new("nm").arg(dir.join("slate-loader-bios")).output().map_err(|e| format!("nm: {e}"))?;
    let end = String::from_utf8_lossy(&nm.stdout)
        .lines()
        .find(|l| l.ends_with(" __bss_end"))
        .and_then(|l| u64::from_str_radix(l.split(' ').next()?, 16).ok())
        .ok_or("slate-loader-bios: no __bss_end")?;
    if end > 0x7_0000 {
        return Err(format!("slate-loader-bios ends at {end:#x}, past 0x70000"));
    }
    let sectors = loader.len().div_ceil(512) as u16;
    hdd[0x1AC..0x1AE].copy_from_slice(&sectors.to_le_bytes());
    hdd.extend_from_slice(&loader);
    hdd.resize(512 + sectors as usize * 512, 0);
    Ok(Bios { hdd, sys: None })
}

/// Put BIOS stages (a boot sector, then what it loads) on a disk image, as
/// the installer does (`write_bios_stages`): the boot sector keeps the
/// disk's timestamp and partition table and gets the byte offset of the
/// rest, which goes at sector `lba` (the BIOS boot partition, or the gap
/// before the first partition).
pub fn bios_install(img: &std::path::Path, lba: u64, hdd: &[u8], room_sectors: u64) -> Result {
    use std::os::unix::fs::FileExt;
    if (hdd.len() as u64 - 512).div_ceil(512) > room_sectors {
        return Err(format!("the BIOS stages ({} bytes) do not fit {room_sectors} sectors", hdd.len() - 512));
    }
    let f = std::fs::OpenOptions::new().read(true).write(true).open(img).map_err(|e| e.to_string())?;
    let mut old = [0u8; 512];
    f.read_exact_at(&mut old, 0).map_err(|e| e.to_string())?;
    let mut mbr = [0u8; 512];
    mbr.copy_from_slice(&hdd[..512]);
    mbr[0x1A4..0x1AC].copy_from_slice(&(lba * 512).to_le_bytes());
    mbr[218..224].copy_from_slice(&old[218..224]);
    mbr[440..510].copy_from_slice(&old[440..510]);
    f.write_all_at(&hdd[512..], lba * 512).map_err(|e| e.to_string())?;
    f.write_all_at(&mbr, 0).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())
}
