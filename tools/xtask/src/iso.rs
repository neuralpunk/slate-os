// SPDX-License-Identifier: MIT OR Apache-2.0

//! The install media: a hybrid ISO image (ADR 0029, ADR 0039).
//!
//! One file that boots as a CD/DVD and when written raw to a USB stick,
//! with BIOS and with UEFI firmware:
//!
//! ```text
//! bytes 0..32K   ISO 9660 system area: an MBR (Limine's BIOS stage 1 and,
//!                after it, stage 2, put there by `limine bios-install`)
//!                whose one partition, type EFh, is limine-uefi-cd.bin
//! sector 16      primary volume descriptor          (ECMA-119 §8.4)
//! sector 17      El Torito boot record              (El Torito 1.0 §2.0)
//! sector 18      volume descriptor set terminator   (ECMA-119 §8.3)
//! sectors 19-20  path tables (L and M)              (ECMA-119 §9.4)
//! then           the directories, the boot catalog and the files
//! ```
//!
//! The tree, with Rock Ridge names (RRIP 1.12 `NM` entries, announced by
//! SUSP's `SP` and `ER` in the root):
//!
//! ```text
//! /boot/limine/limine-bios-cd.bin   El Torito's BIOS entry (no emulation,
//!                                   with mkisofs's boot info table)
//! /boot/limine/limine-uefi-cd.bin   El Torito's UEFI entry: a small FAT
//!                                   image with Limine's EFI executables
//! /boot/limine/limine-bios.sys      Limine's BIOS stage 3
//! /boot/limine/limine.conf
//! /boot/slate/kernel
//! /boot/slate/modules/initramfs     the live system, with the installer
//! ```
//!
//! Either way Limine reads its menu, the kernel and the live initramfs from
//! the ISO 9660 tree. The UEFI image is under 3 MiB, so the boot catalog's
//! 16-bit sector count describes it: firmware that reads the count (the
//! reference PC's AMI UEFI) loads all of it. The live system runs from the
//! initramfs, so nothing reads the medium after boot.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Opts, Result, image, initramfs, limine, quarry, run_cmd, target_dir};

const SECTOR: usize = 2048;
const PVD: usize = 16;
const BOOT_RECORD: usize = 17;
const TERMINATOR: usize = 18;
const L_PATH: usize = 19;
const M_PATH: usize = 20;
/// The first directory's sector.
const DIRS: usize = 21;
/// 2026-01-01 00:00:00 UTC: fixed, so images are reproducible.
const DATE_DIR: [u8; 7] = [126, 1, 1, 0, 0, 0, 0];
const DATE_TEXT: &[u8; 17] = b"2026010100000000\0";
/// The El Torito images' paths in the tree.
pub const BIOS_IMAGE: &str = "boot/limine/limine-bios-cd.bin";
pub const UEFI_IMAGE: &str = "boot/limine/limine-uefi-cd.bin";

fn both16(v: u16) -> [u8; 4] {
    let (l, b) = (v.to_le_bytes(), v.to_be_bytes());
    [l[0], l[1], b[0], b[1]]
}

fn both32(v: u32) -> [u8; 8] {
    let (l, b) = (v.to_le_bytes(), v.to_be_bytes());
    [l[0], l[1], l[2], l[3], b[0], b[1], b[2], b[3]]
}

/// ECMA-119's identifier for `name`: upper case d-characters (anything else
/// becomes `_`), files with a version (`;1`).
fn iso_name(name: &str, dir: bool) -> Vec<u8> {
    let mut id: Vec<u8> = name
        .bytes()
        .map(|b| match b.to_ascii_uppercase() {
            c @ (b'A'..=b'Z' | b'0'..=b'9' | b'_') => c,
            b'.' if !dir => b'.',
            _ => b'_',
        })
        .collect();
    id.truncate(30);
    if !dir {
        id.extend_from_slice(b";1");
    }
    id
}

/// A directory record (ECMA-119 §9.1) with `system_use` after the name.
fn dir_record(id: &[u8], extent: usize, len: usize, dir: bool, system_use: &[u8]) -> Vec<u8> {
    let base = 33 + id.len() + (id.len() + 1) % 2;
    let mut r = vec![0u8; base + system_use.len() + (base + system_use.len()) % 2];
    r[0] = r.len() as u8;
    r[2..10].copy_from_slice(&both32(extent as u32));
    r[10..18].copy_from_slice(&both32(len as u32));
    r[18..25].copy_from_slice(&DATE_DIR);
    r[25] = if dir { 0x02 } else { 0 };
    r[28..32].copy_from_slice(&both16(1));
    r[32] = id.len() as u8;
    r[33..33 + id.len()].copy_from_slice(id);
    r[base..base + system_use.len()].copy_from_slice(system_use);
    r
}

/// Rock Ridge's alternate name (RRIP 1.12 §4.1.4): `NM`, length, version 1,
/// flags 0, the name.
fn rr_name(name: &str) -> Vec<u8> {
    let mut e = vec![b'N', b'M', (5 + name.len()) as u8, 1, 0];
    e.extend_from_slice(name.as_bytes());
    e
}

/// The root's `.` system use: SUSP's `SP` (IEEE P1281 §5.3: check bytes
/// BEh EFh, nothing skipped) and `ER` naming Rock Ridge (§5.5).
fn susp_root() -> Vec<u8> {
    let mut e = vec![b'S', b'P', 7, 1, 0xBE, 0xEF, 0];
    let id = b"RRIP_1991A";
    e.extend_from_slice(&[b'E', b'R', (8 + id.len()) as u8, 1, id.len() as u8, 0, 0, 1]);
    e.extend_from_slice(id);
    e
}

/// A directory of the tree being laid out.
#[derive(Default)]
struct Dir {
    name: String,
    /// Index of the parent in the directory list (the root is its own).
    parent: usize,
    subdirs: Vec<usize>,
    /// (name, index in the file list)
    files: Vec<(String, usize)>,
    sector: usize,
    len: usize,
}

/// The directories for `paths`, breadth first (the path tables' order:
/// ECMA-119 §9.4.4, by level, then parent, then name).
fn directories(paths: &[&str]) -> Vec<Dir> {
    let mut dirs = vec![Dir::default()];
    for (fi, path) in paths.iter().enumerate() {
        let parts: Vec<&str> = path.split('/').collect();
        let mut at = 0;
        for part in &parts[..parts.len() - 1] {
            at = match dirs[at].subdirs.iter().find(|&&d| dirs[d].name == *part) {
                Some(&d) => d,
                None => {
                    dirs.push(Dir { name: (*part).to_string(), parent: at, ..Dir::default() });
                    let d = dirs.len() - 1;
                    dirs[at].subdirs.push(d);
                    d
                }
            };
        }
        dirs[at].files.push((parts[parts.len() - 1].to_string(), fi));
    }
    // Renumber breadth first, children by name.
    let mut order = vec![0];
    let mut i = 0;
    while i < order.len() {
        let mut kids = dirs[order[i]].subdirs.clone();
        kids.sort_by(|a, b| iso_name(&dirs[*a].name, true).cmp(&iso_name(&dirs[*b].name, true)));
        order.extend(kids);
        i += 1;
    }
    let new_index: std::collections::HashMap<usize, usize> = order.iter().enumerate().map(|(n, &o)| (o, n)).collect();
    let mut out: Vec<Dir> = Vec::new();
    for &o in &order {
        let d = std::mem::take(&mut dirs[o]);
        out.push(Dir { parent: new_index[&d.parent], subdirs: d.subdirs.iter().map(|s| new_index[s]).collect(), ..d });
    }
    out
}

/// One directory's records: `.`, `..`, then its entries by identifier.
fn dir_records(dirs: &[Dir], d: usize, file_at: &[(usize, usize)]) -> Vec<Vec<u8>> {
    let me = &dirs[d];
    let parent = &dirs[me.parent];
    let mut recs = vec![
        dir_record(&[0], me.sector, me.len, true, &if d == 0 { susp_root() } else { Vec::new() }),
        dir_record(&[1], parent.sector, parent.len, true, &[]),
    ];
    let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for &s in &me.subdirs {
        let sd = &dirs[s];
        let id = iso_name(&sd.name, true);
        entries.push((id.clone(), dir_record(&id, sd.sector, sd.len, true, &rr_name(&sd.name))));
    }
    for (name, fi) in &me.files {
        let id = iso_name(name, false);
        let (sector, len) = file_at[*fi];
        entries.push((id.clone(), dir_record(&id, sector, len, false, &rr_name(name))));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    recs.extend(entries.into_iter().map(|e| e.1));
    recs
}

/// Records laid into sectors (a record never crosses a sector, ECMA-119
/// §6.8.1.1); the length in whole sectors.
fn dir_bytes(recs: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for r in recs {
        if out.len() / SECTOR != (out.len() + r.len() - 1) / SECTOR {
            out.resize(out.len().div_ceil(SECTOR) * SECTOR, 0);
        }
        out.extend_from_slice(r);
    }
    out.resize(out.len().div_ceil(SECTOR).max(1) * SECTOR, 0);
    out
}

fn text(field: &mut [u8], s: &str) {
    field.fill(b' ');
    field[..s.len()].copy_from_slice(s.as_bytes());
}

/// The ISO image of `files` (paths and contents), booting through the El
/// Torito images at [`BIOS_IMAGE`] and [`UEFI_IMAGE`], which must be among
/// them, with an MBR whose EFI partition is the UEFI image.
pub fn hybrid(files: &[(&str, Vec<u8>)], volume_id: &str) -> Result<Vec<u8>> {
    let paths: Vec<&str> = files.iter().map(|f| f.0).collect();
    let find = |p: &str| paths.iter().position(|x| *x == p).ok_or_else(|| format!("the ISO needs {p}"));
    let (bios_i, uefi_i) = (find(BIOS_IMAGE)?, find(UEFI_IMAGE)?);
    let mut dirs = directories(&paths);
    // Directory sizes depend only on names, so lay them out first.
    let mut next = DIRS;
    let dummy: Vec<(usize, usize)> = vec![(0, 0); files.len()];
    for d in 0..dirs.len() {
        let len = dir_bytes(&dir_records(&dirs, d, &dummy)).len();
        dirs[d].sector = next;
        dirs[d].len = len;
        next += len / SECTOR;
    }
    let catalog = next;
    next += 1;
    let mut file_at = Vec::new();
    for (_, data) in files {
        file_at.push((next, data.len()));
        next += data.len().div_ceil(SECTOR).max(1);
    }
    let volume_sectors = next;
    let total = (volume_sectors * SECTOR).div_ceil(1 << 20) << 20;
    let mut iso = vec![0u8; total];

    // Primary volume descriptor.
    let path_table_len = dirs.iter().map(|d| 8 + d.name.len().max(1) + d.name.len().max(1) % 2).sum::<usize>();
    {
        let d = &mut iso[PVD * SECTOR..(PVD + 1) * SECTOR];
        d[0] = 1;
        d[1..6].copy_from_slice(b"CD001");
        d[6] = 1;
        text(&mut d[8..40], "");
        text(&mut d[40..72], volume_id);
        d[80..88].copy_from_slice(&both32(volume_sectors as u32));
        d[120..124].copy_from_slice(&both16(1));
        d[124..128].copy_from_slice(&both16(1));
        d[128..132].copy_from_slice(&both16(SECTOR as u16));
        d[132..140].copy_from_slice(&both32(path_table_len as u32));
        d[140..144].copy_from_slice(&(L_PATH as u32).to_le_bytes());
        d[148..152].copy_from_slice(&(M_PATH as u32).to_be_bytes());
        let root = dir_record(&[0], dirs[0].sector, dirs[0].len, true, &[]);
        d[156..156 + root.len()].copy_from_slice(&root);
        for (a, b) in [(190, 318), (318, 446), (446, 574), (574, 702), (702, 739), (739, 776), (776, 813)] {
            text(&mut d[a..b], "");
        }
        text(&mut d[318..446], "SLATE");
        text(&mut d[574..702], "SLATE INSTALLER");
        for at in [813, 830, 864] {
            d[at..at + 17].copy_from_slice(DATE_TEXT);
        }
        d[847..864].copy_from_slice(b"0000000000000000\0");
        d[881] = 1;
    }
    // El Torito boot record: the catalog's location.
    {
        let d = &mut iso[BOOT_RECORD * SECTOR..(BOOT_RECORD + 1) * SECTOR];
        d[1..6].copy_from_slice(b"CD001");
        d[6] = 1;
        d[7..30].copy_from_slice(b"EL TORITO SPECIFICATION");
        d[71..75].copy_from_slice(&(catalog as u32).to_le_bytes());
    }
    // Terminator.
    {
        let d = &mut iso[TERMINATOR * SECTOR..(TERMINATOR + 1) * SECTOR];
        d[0] = 255;
        d[1..6].copy_from_slice(b"CD001");
        d[6] = 1;
    }
    // Path tables (ECMA-119 §9.4): every directory, with its parent's number
    // (from 1).
    for (at, be) in [(L_PATH, false), (M_PATH, true)] {
        let mut t = Vec::new();
        for d in &dirs {
            let id: Vec<u8> = if d.name.is_empty() { vec![0] } else { iso_name(&d.name, true) };
            t.push(id.len() as u8);
            t.push(0);
            let (loc, parent) = (d.sector as u32, d.parent as u16 + 1);
            t.extend_from_slice(&if be { loc.to_be_bytes() } else { loc.to_le_bytes() });
            t.extend_from_slice(&if be { parent.to_be_bytes() } else { parent.to_le_bytes() });
            t.extend_from_slice(&id);
            if id.len() % 2 == 1 {
                t.push(0);
            }
        }
        if t.len() > SECTOR {
            return Err("the ISO's path table outgrew its sector".into());
        }
        iso[at * SECTOR..at * SECTOR + t.len()].copy_from_slice(&t);
    }
    for d in 0..dirs.len() {
        let bytes = dir_bytes(&dir_records(&dirs, d, &file_at));
        let at = dirs[d].sector * SECTOR;
        iso[at..at + bytes.len()].copy_from_slice(&bytes);
    }
    for ((_, data), (sector, _)) in files.iter().zip(&file_at) {
        iso[sector * SECTOR..sector * SECTOR + data.len()].copy_from_slice(data);
    }
    // The BIOS image's boot info table (mkisofs(8), -boot-info-table): at
    // byte 8, the primary volume descriptor's sector, the image's sector
    // and length, and the 32-bit sum of the image from byte 64.
    {
        let (sector, len) = file_at[bios_i];
        let img = &mut iso[sector * SECTOR..sector * SECTOR + len];
        let sum = img[64..].chunks(4).fold(0u32, |s, w| {
            let mut b = [0u8; 4];
            b[..w.len()].copy_from_slice(w);
            s.wrapping_add(u32::from_le_bytes(b))
        });
        img[8..12].copy_from_slice(&(PVD as u32).to_le_bytes());
        img[12..16].copy_from_slice(&(sector as u32).to_le_bytes());
        img[16..20].copy_from_slice(&(len as u32).to_le_bytes());
        img[20..24].copy_from_slice(&sum.to_le_bytes());
        img[24..64].fill(0);
    }
    // Boot catalog (El Torito 1.0 §2.1-2.4): the validation entry (x86,
    // its 16-bit words summing to zero), the default entry (BIOS, no
    // emulation, four 512-byte sectors loaded), then a final section of
    // one UEFI (EFh) entry.
    {
        let (bios_sector, _) = file_at[bios_i];
        let (uefi_sector, uefi_len) = file_at[uefi_i];
        let uefi_count = u16::try_from(uefi_len.div_ceil(512)).map_err(|_| "the UEFI El Torito image is too big")?;
        let c = &mut iso[catalog * SECTOR..catalog * SECTOR + 128];
        c[0] = 1;
        c[1] = 0;
        c[4..9].copy_from_slice(b"SLATE");
        c[30] = 0x55;
        c[31] = 0xAA;
        let sum = c[..32].chunks(2).fold(0u16, |s, w| s.wrapping_add(u16::from_le_bytes([w[0], w[1]])));
        c[28..30].copy_from_slice(&0u16.wrapping_sub(sum).to_le_bytes());
        c[32] = 0x88;
        c[38..40].copy_from_slice(&4u16.to_le_bytes());
        c[40..44].copy_from_slice(&(bios_sector as u32).to_le_bytes());
        c[64] = 0x91;
        c[65] = 0xEF;
        c[66..68].copy_from_slice(&1u16.to_le_bytes());
        c[96] = 0x88;
        c[102..104].copy_from_slice(&uefi_count.to_le_bytes());
        c[104..108].copy_from_slice(&(uefi_sector as u32).to_le_bytes());
    }
    // The MBR (UEFI 2.10 §5.2.1): partition record 0, type EFh, over the
    // UEFI image, for firmware booting the image as a disk.
    {
        let (uefi_sector, uefi_len) = file_at[uefi_i];
        iso[440..444].copy_from_slice(&0x534C_4154u32.to_le_bytes());
        let e = &mut iso[446..462];
        e[1..4].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
        e[4] = 0xEF;
        e[5..8].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
        e[8..12].copy_from_slice(&((uefi_sector * SECTOR / 512) as u32).to_le_bytes());
        e[12..16].copy_from_slice(&(uefi_len.div_ceil(512) as u32).to_le_bytes());
        iso[510] = 0x55;
        iso[511] = 0xAA;
    }
    Ok(iso)
}

/// Limine's menu on the install media: the graphical installer, and the
/// text installer (ADR 0034), which `text` makes the default.
fn limine_conf(text: bool) -> String {
    // Limine configuration syntax: CONFIG.md in the Limine repository.
    // SLATE_LIVE_CMDLINE adds kernel arguments (a development build that
    // installs a machine remotely may need `slate.ip=`).
    let extra = std::env::var("SLATE_LIVE_CMDLINE").map(|e| format!(" {e}")).unwrap_or_default();
    let entry = |name: &str, args: &str| {
        format!(
            "/{name}\n\
             \x20   protocol: limine\n\
             \x20   path: boot():/boot/slate/kernel\n\
             \x20   cmdline: slate.live quiet{args}{extra}\n\
             \x20   module_path: boot():/boot/slate/modules/initramfs\n\
             \x20   module_cmdline: initramfs\n"
        )
    };
    let default = if text { "default_entry: 2\n" } else { "" };
    format!(
        "timeout: 3\n{default}\n{}\n{}\n{}",
        entry("Install Slate", ""),
        entry("Install Slate (text mode)", " slate.installer=text"),
        // "Try SlateOS" keeps the live session's files on the stick (ADR
        // 0118's addendum).
        entry("Install or try Slate, keeping your files on this stick", " slate.live.keep")
    )
}

/// The install media's files (paths in the FAT volume): the loaders, the
/// menu, the kernel, and the live initramfs with the signed payload. The
/// kernel is there once: the installer copies the running one, which the
/// live system shows as /proc/slate_kernel.
fn live_files(o: &Opts, text: bool) -> Result<Vec<(&'static str, Vec<u8>)>> {
    let kernel = std::fs::read(crate::boot_kernel(o.release)?).map_err(|e| e.to_string())?;
    let limine = limine::fetch()?;
    // slate-loader (ADR 0089) for the USB image and installed disks; the
    // ISO's own boot stays Limine's (its BIOS stage 3 is on the media).
    let efi_app = std::fs::read(crate::loader::uefi()?).map_err(|e| e.to_string())?;
    let limine_sys = std::fs::read(limine.file("limine-bios.sys")).map_err(|e| e.to_string())?;
    let bios = crate::loader::bios()?;
    let system = initramfs::system_archive()?;
    let signature = quarry::sign_detached(&system)?;
    let mut extra = vec![
        ("install/system.cpio", 0o644, system),
        ("install/system.sig", 0o644, signature),
        ("install/boot/BOOTX64.EFI", 0o644, efi_app.clone()),
        ("install/boot/bios-hdd.bin", 0o644, bios.hdd),
    ];
    if let Some(sys) = bios.sys {
        extra.push(("install/boot/limine-bios.sys", 0o644, sys));
    }
    // SLATE_LIVE_AUTHORIZED_KEYS: a public key file that may log in to the
    // live system as root over SSH, for installing or debugging a machine
    // remotely. Development builds only; never set for release media.
    if let Ok(keys) = std::env::var("SLATE_LIVE_AUTHORIZED_KEYS") {
        extra.push(("root/.ssh/authorized_keys", 0o600, std::fs::read(&keys).map_err(|e| format!("{keys}: {e}"))?));
    }
    // SLATE_LIVE_OVERLAY: a directory whose files join the live system, as
    // tools/refpc/live-overlay's boot dump (ADR 0076). Development builds
    // only; never set for release media.
    if let Ok(dir) = std::env::var("SLATE_LIVE_OVERLAY") {
        for (path, mode, data) in overlay_files(Path::new(&dir))? {
            // The archive's paths live as long as the build.
            extra.push((Box::leak(path.into_boxed_str()), mode, data));
        }
    }
    let live = initramfs::live_archive(&extra)?;
    Ok(vec![
        ("EFI/BOOT/BOOTX64.EFI", efi_app),
        ("boot/limine/limine.conf", limine_conf(text).into_bytes()),
        ("boot/limine/limine-bios.sys", limine_sys),
        ("boot/slate/kernel", kernel),
        ("boot/slate/modules/initramfs", live),
    ])
}

/// The files under `dir` as (path in the archive, mode, contents);
/// executable files keep 0755.
fn overlay_files(dir: &Path) -> Result<Vec<(String, u32, Vec<u8>)>> {
    use std::os::unix::fs::PermissionsExt;
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for e in std::fs::read_dir(&d).map_err(|e| format!("{}: {e}", d.display()))? {
            let p = e.map_err(|e| e.to_string())?.path();
            let meta = std::fs::metadata(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            if meta.is_dir() {
                todo.push(p);
                continue;
            }
            let rel = p.strip_prefix(dir).map_err(|e| e.to_string())?.to_string_lossy().into_owned();
            let mode = if meta.permissions().mode() & 0o111 != 0 { 0o755 } else { 0o644 };
            out.push((rel, mode, std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?));
        }
    }
    Ok(out)
}

/// Build `target/slate.iso`: the live system with the installer and the
/// signed system payload, booting with BIOS and UEFI.
pub fn build(o: &Opts) -> Result<PathBuf> {
    let _turn = crate::build_lock();
    let limine = limine::fetch()?;
    let read = |name: &str| std::fs::read(limine.file(name)).map_err(|e| format!("{name}: {e}"));
    let mut files: Vec<(&str, Vec<u8>)> =
        live_files(o, false)?.into_iter().filter(|(p, _)| !p.starts_with("EFI/")).collect();
    files.push((BIOS_IMAGE, read("limine-bios-cd.bin")?));
    files.push((UEFI_IMAGE, read("limine-uefi-cd.bin")?));
    let iso = hybrid(&files, "SLATE")?;
    let out = target_dir().join("slate.iso");
    std::fs::write(&out, iso).map_err(|e| format!("{}: {e}", out.display()))?;
    // Limine's BIOS stages for booting the image as a disk (a USB stick).
    run_cmd(Command::new(limine.tool()).arg("bios-install").arg("--quiet").arg(&out))?;
    Ok(out)
}

const USB_ESP_FIRST: u64 = 2048;
/// 300 MiB: over 260 MiB, so FAT32 uses 4 KiB clusters, as on the
/// installed disk's ESP.
const USB_ESP_BYTES: u64 = 300 << 20;

/// Build the install media as a disk image for a USB stick (written raw
/// like the ISO): an MBR partition table (UEFI 2.10 §5.2.1, the legacy
/// MBR) with one active EFI System Partition (type EFh) at 1 MiB holding
/// the same files. Not GPT: a GPT made for an image has its backup at the
/// image's end, not at the end of the larger stick, and some firmware
/// (the reference PC's AMI UEFI) then rejects the stick without a word.
/// The partition's FAT volume label `SLATE-LIVE` marks it for the
/// installer. With `fatfs`, the ESP is written by the third-party `fatfs`
/// crate instead of `slate-fat` (a diagnostic for firmware FAT drivers).
pub fn usb(o: &Opts, fatfs: bool) -> Result<PathBuf> {
    usb_with(o, fatfs, false)
}

/// The USB image built and copied to `to` (a scenario's own stick) in one
/// turn of the build lock, so another scenario's build can't change it
/// half way through the copy.
pub fn usb_copy(o: &Opts, text: bool, to: &std::path::Path) -> Result<PathBuf> {
    let _turn = crate::build_lock();
    let image = usb_with(o, false, text)?;
    std::fs::copy(&image, to).map_err(|e| format!("{}: {e}", to.display()))?;
    Ok(to.to_path_buf())
}

/// A copy of the USB image that starts the entry keeping the live
/// session's files (the try scenario).
pub fn usb_copy_keeping(o: &Opts, to: &std::path::Path) -> Result<PathBuf> {
    use std::io::{Read, Write};
    let out = usb_copy(o, false, to)?;
    let io = |e: std::io::Error| format!("{}: {e}", to.display());
    let mut f = std::fs::OpenOptions::new().read(true).write(true).open(to).map_err(io)?;
    let slice = image::Slice::new(&mut f, USB_ESP_FIRST * 512, USB_ESP_BYTES);
    let fs = fatfs::FileSystem::new(slice, fatfs::FsOptions::new()).map_err(io)?;
    let root = fs.root_dir();
    let mut conf = String::new();
    root.open_file("boot/limine/limine.conf").map_err(io)?.read_to_string(&mut conf).map_err(io)?;
    let conf = conf.replacen("timeout: 3\n", "timeout: 3\ndefault_entry: 3\n", 1);
    let mut w = root.create_file("boot/limine/limine.conf").map_err(io)?;
    w.truncate().map_err(io)?;
    w.write_all(conf.as_bytes()).map_err(io)?;
    drop(w);
    drop(root);
    fs.unmount().map_err(io)?;
    Ok(out)
}

/// What the stick holds at `path` in its FAT volume, if anything.
pub fn usb_read(image: &std::path::Path, path: &str) -> Result<Option<Vec<u8>>> {
    use std::io::Read;
    let io = |e: std::io::Error| format!("{}: {e}", image.display());
    let mut f = std::fs::OpenOptions::new().read(true).write(true).open(image).map_err(io)?;
    let slice = image::Slice::new(&mut f, USB_ESP_FIRST * 512, USB_ESP_BYTES);
    let fs = fatfs::FileSystem::new(slice, fatfs::FsOptions::new()).map_err(io)?;
    let root = fs.root_dir();
    let Ok(mut file) = root.open_file(path) else { return Ok(None) };
    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(io)?;
    Ok(Some(data))
}

/// The USB image; with `text`, the text installer is the menu's default
/// (`target/slate-usb-text.img`, for the text-installer scenario).
pub fn usb_with(o: &Opts, fatfs: bool, text: bool) -> Result<PathBuf> {
    use std::io::Write;
    let _turn = crate::build_lock();
    let files = live_files(o, text)?;
    let name = match (fatfs, text) {
        (true, _) => "slate-usb-fatfs.img",
        (false, true) => "slate-usb-text.img",
        (false, false) => "slate-usb.img",
    };
    let out = target_dir().join(name);
    let total = USB_ESP_FIRST * 512 + USB_ESP_BYTES;
    let mut mbr = [0u8; 512];
    // Disk signature (bytes 440-443), then partition record 0: active,
    // CHS fields at their "use LBA" maximum, type EFh, first LBA, size.
    mbr[440..444].copy_from_slice(&0x534C_4154u32.to_le_bytes());
    let e = &mut mbr[446..462];
    e[0] = 0x80;
    e[1..4].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    e[4] = 0xEF;
    e[5..8].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    e[8..12].copy_from_slice(&(USB_ESP_FIRST as u32).to_le_bytes());
    e[12..16].copy_from_slice(&((USB_ESP_BYTES / 512) as u32).to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    let _ = std::fs::remove_file(&out);
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&out)
        .map_err(|e| format!("{}: {e}", out.display()))?;
    let io = |e: std::io::Error| format!("{}: {e}", out.display());
    f.set_len(total).map_err(io)?;
    f.write_all(&mbr).map_err(io)?;
    let base = USB_ESP_FIRST * 512;
    if fatfs {
        let mut slice = image::Slice::new(&mut f, base, USB_ESP_BYTES);
        fatfs::format_volume(
            &mut slice,
            fatfs::FormatVolumeOptions::new().fat_type(fatfs::FatType::Fat32).volume_label(*b"SLATE-LIVE "),
        )
        .map_err(io)?;
        let fs = fatfs::FileSystem::new(slice, fatfs::FsOptions::new()).map_err(io)?;
        let root = fs.root_dir();
        for (path, data) in &files {
            let mut dir = String::new();
            for part in path.split('/').take(path.split('/').count() - 1) {
                dir = if dir.is_empty() { part.to_string() } else { format!("{dir}/{part}") };
                let _ = root.create_dir(&dir);
            }
            let mut w = root.create_file(path).map_err(io)?;
            w.truncate().map_err(io)?;
            w.write_all(data).map_err(io)?;
        }
        drop(root);
        fs.unmount().map_err(io)?;
    } else {
        let mut vol = slate_fat::Volume::new();
        let fat = |e: slate_fat::Error| format!("install media FAT: {e:?}");
        for (path, data) in files {
            vol.add_file(path, data).map_err(fat)?;
        }
        let mut sink = image::FileSink { file: &mut f, base };
        slate_fat::write(&vol, USB_ESP_BYTES, "SLATE-LIVE", 0x534C_4956, USB_ESP_FIRST as u32, &mut sink)
            .map_err(fat)?;
    }
    f.sync_all().map_err(io)?;
    drop(f);
    // The BIOS stages: the boot sector in the MBR's boot code, the loader
    // in the gap before the partition.
    let bios = crate::loader::bios()?;
    crate::loader::bios_install(&out, 1, &bios.hdd, USB_ESP_FIRST - 1)?;
    Ok(out)
}
