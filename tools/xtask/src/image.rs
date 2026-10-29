// SPDX-License-Identifier: MIT OR Apache-2.0

//! Building a bootable GPT disk image.
//!
//! Layout (512-byte blocks):
//!
//! ```text
//! 0          protective MBR (slate-loader's boot sector in its boot code)
//! 1..34      primary GPT header and entry array
//! 2048..4095 BIOS boot partition (slate-loader for BIOS, ADR 0089)
//! 4096..     EFI System Partition (128 MiB), FAT32, label SLATE-ESP
//!              /EFI/BOOT/BOOTX64.EFI        slate-loader for UEFI
//!              /boot/limine/limine.conf     the menu (Limine's syntax)
//!              /boot/slate/kernel           with the initramfs as the root, or
//!              /boot/slate/system-1/kernel  with a SlateFS root (ADR 0086)
//!              /boot/slate/modules/initramfs the initial root file system (cpio),
//!                                           when not booting from the root partition
//! ..         root partition "slate-root": SlateFS with the same tree as the
//!            initramfs in subvolume system-1, plus home and var (ADR 0027;
//!            empty in test images)
//! end-33..   backup GPT
//! ```

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use slate_gpt::{BLOCK_SIZE, Guid, Partition};

use crate::{Opts, Result, boot_kernel, target_dir};

const DISK_BYTES: u64 = 512 * 1024 * 1024;
/// The image `cargo xtask run` and `image` make, for trying Slate: room
/// for the Linux runtime and Flatpak's apps (sparse, so free until used).
const RUN_DISK_BYTES: u64 = 8 << 30;
const BIOS_BOOT_FIRST_LBA: u64 = 2048;
const ESP_FIRST_LBA: u64 = 4096;
const ESP_BLOCKS: u64 = 128 * 2048;
const ROOT_FIRST_LBA: u64 = ESP_FIRST_LBA + ESP_BLOCKS;
/// GPT partition name of the root file system (`root=PARTLABEL=...`).
pub const ROOT_LABEL: &str = "slate-root";

/// Byte offset of the root partition in an image.
pub const ROOT_OFFSET: u64 = ROOT_FIRST_LBA * BLOCK_SIZE as u64;

/// Where the root file system comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Root {
    /// The initramfs (a tmpfs root); the root partition stays empty.
    Initramfs,
    /// SlateFS on the root partition.
    Disk,
}

/// Images for real use (`cargo xtask run`, the acceptance runs): the
/// others are tests, and keep off the internet's clocks.
const REAL_USE: &[&str] = &["slate.img", "slate-accept.img", "slate-desktop.img"];

/// Build the kernel and a disk image named `name` in `target/` whose boot
/// entry passes `cmdline` to the kernel.
pub fn build(o: &Opts, cmdline: &str, name: &str, root: Root) -> Result<PathBuf> {
    let _turn = crate::build_lock();
    let kernel = boot_kernel(o.release)?;
    let user = crate::user::build()?;
    let img = target_dir().join(name);
    // Images with the test load (BusyBox, Alpine, the Linux test programs)
    // boot with Linux compatibility mode on (ADR 0032).
    let compat = (root == Root::Initramfs || o.test_load) && !cmdline.contains("slate.compat=");
    let cmdline = if compat { format!("{cmdline} slate.compat=on") } else { cmdline.to_string() };
    let cmdline = cmdline.as_str();
    let (modules, cmdline) = match root {
        Root::Initramfs => (vec![("initramfs".to_string(), crate::initramfs::build(&user)?)], cmdline.to_string()),
        Root::Disk => (Vec::new(), format!("{cmdline} root=PARTLABEL={ROOT_LABEL}").trim().to_string()),
    };
    let disk = if name == "slate.img" { RUN_DISK_BYTES } else { DISK_BYTES };
    let root_size = write_image(&img, &kernel, &cmdline, &modules, root == Root::Disk, disk)
        .map_err(|e| format!("writing {}: {e}", img.display()))?;
    if root == Root::Disk {
        let stage = crate::initramfs::stage(o.test_load.then_some(user.as_slice()))?;
        // Only images for real use set the clock from the internet; test
        // images get no time servers.
        if !REAL_USE.contains(&name) {
            std::fs::write(stage.join("etc/slate/ntp"), crate::initramfs::TEST_NTP).map_err(|e| e.to_string())?;
        }
        // The GPU bench's image carries AMD's display firmware, from
        // the reference PC (ADR 0171; never committed, never in other images).
        if name == crate::refpc::IMAGE {
            crate::refpc::stage_firmware(&stage)?;
        }
        // The system carries its own kernel (ADR 0086).
        let boot = stage.join("boot/slate");
        std::fs::create_dir_all(&boot).map_err(|e| e.to_string())?;
        std::fs::copy(&kernel, boot.join("kernel")).map_err(|e| format!("{}: {e}", kernel.display()))?;
        crate::slatefsimg::make_root(&img, ROOT_OFFSET, root_size, &stage)?;
    }
    let bios = crate::loader::bios()?;
    crate::loader::bios_install(&img, BIOS_BOOT_FIRST_LBA, &bios.hdd, ESP_FIRST_LBA - BIOS_BOOT_FIRST_LBA)?;
    Ok(img)
}

fn limine_conf(cmdline: &str, modules: &[(String, PathBuf)], disk_root: bool) -> String {
    // A SlateFS root boots system-1's own kernel, as an install does (ADR
    // 0086); slate-update adds the previous system after an update. No
    // wait in the menu.
    if disk_root {
        return slate_esp::first_config(cmdline, "system-1", false).replacen("timeout: 3", "timeout: 0", 1);
    }
    // Limine configuration syntax: CONFIG.md in the Limine repository.
    let mut s = format!(
        "timeout: 0\n\
         \n\
         /Slate\n\
         \x20   protocol: limine\n\
         \x20   path: boot():/boot/slate/kernel\n\
         \x20   cmdline: {cmdline}\n"
    );
    for (name, _) in modules {
        s += &format!("    module_path: boot():/boot/slate/modules/{name}\n    module_cmdline: {name}\n");
    }
    s
}

/// A deterministic GUID derived from a label, so identical inputs produce
/// identical images.
pub fn guid_for(label: &str) -> Guid {
    let mut seed = [0u8; 16];
    // FNV-1a over the label, spread across two 64-bit halves.
    for (half, chunk) in seed.chunks_mut(8).enumerate() {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ half as u64;
        for b in label.bytes() {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
        chunk.copy_from_slice(&h.to_le_bytes());
    }
    Guid::from_seed(seed)
}

/// Write the GPT, the ESP and the boot files; returns the root partition's
/// size in bytes.
fn write_image(
    img: &Path,
    kernel: &Path,
    cmdline: &str,
    modules: &[(String, PathBuf)],
    disk_root: bool,
    disk_bytes: u64,
) -> io::Result<u64> {
    let total_blocks = disk_bytes / BLOCK_SIZE as u64;
    let layout = slate_gpt::Layout::for_disk(total_blocks).map_err(gpt_err)?;
    let esp_last = ROOT_FIRST_LBA - 1;
    // End the root partition on a 1 MiB boundary inside the usable range.
    let root_last = (layout.last_usable + 1) / 2048 * 2048 - 1;
    let root_part = Partition {
        type_guid: Guid::LINUX_FILESYSTEM,
        unique_guid: guid_for("slate-root"),
        first_lba: ROOT_FIRST_LBA,
        last_lba: root_last,
        attributes: 0,
        name: ROOT_LABEL,
    };
    let esp = Partition {
        type_guid: Guid::EFI_SYSTEM,
        unique_guid: guid_for("slate-esp"),
        first_lba: ESP_FIRST_LBA,
        last_lba: esp_last,
        attributes: 0,
        name: "EFI system partition",
    };
    let bios_boot = Partition {
        type_guid: Guid::BIOS_BOOT,
        unique_guid: guid_for("slate-bios-boot"),
        first_lba: BIOS_BOOT_FIRST_LBA,
        last_lba: ESP_FIRST_LBA - 1,
        attributes: 0,
        name: "BIOS boot partition",
    };
    let gpt = slate_gpt::encode(total_blocks, guid_for("slate-disk"), &[esp, bios_boot, root_part]).map_err(gpt_err)?;

    let _ = std::fs::remove_file(img);
    let mut f = OpenOptions::new().read(true).write(true).create_new(true).open(img)?;
    f.set_len(disk_bytes)?;
    let at = |lba: u64| SeekFrom::Start(lba * BLOCK_SIZE as u64);
    f.seek(at(0))?;
    f.write_all(&gpt.protective_mbr)?;
    f.write_all(&gpt.primary_header)?;
    f.write_all(&gpt.entries)?;
    f.seek(at(gpt.backup_entries_lba))?;
    f.write_all(&gpt.entries)?;
    f.seek(at(gpt.backup_header_lba))?;
    f.write_all(&gpt.backup_header)?;

    let esp_bytes = (esp_last - ESP_FIRST_LBA + 1) * BLOCK_SIZE as u64;
    let mut vol = slate_fat::Volume::new();
    let add = |vol: &mut slate_fat::Volume, dest: &str, data: Vec<u8>| -> io::Result<()> {
        vol.add_file(dest, data).map_err(|e| io::Error::other(format!("{dest}: {e:?}")))
    };
    let uefi = crate::loader::uefi().map_err(io::Error::other)?;
    add(&mut vol, "EFI/BOOT/BOOTX64.EFI", std::fs::read(uefi)?)?;
    if let Some(sys) = crate::loader::bios().map_err(io::Error::other)?.sys {
        add(&mut vol, "boot/limine/limine-bios.sys", sys)?;
    }
    add(&mut vol, "boot/limine/limine.conf", limine_conf(cmdline, modules, disk_root).into_bytes())?;
    let kernel_at = if disk_root { "boot/slate/system-1/kernel" } else { "boot/slate/kernel" };
    add(&mut vol, kernel_at, std::fs::read(kernel)?)?;
    vol.add_dir("boot/slate/modules").map_err(|e| io::Error::other(format!("{e:?}")))?;
    for (name, path) in modules {
        add(&mut vol, &format!("boot/slate/modules/{name}"), std::fs::read(path)?)?;
    }
    let mut sink = FileSink { file: &mut f, base: ESP_FIRST_LBA * BLOCK_SIZE as u64 };
    slate_fat::write(&vol, esp_bytes, "SLATE-ESP", 0x534C_4154, ESP_FIRST_LBA as u32, &mut sink)
        .map_err(|e| io::Error::other(format!("ESP: {e:?}")))?;
    f.sync_all()?;
    Ok((root_last - ROOT_FIRST_LBA + 1) * BLOCK_SIZE as u64)
}

/// Rewrite the first boot entry's kernel command line in an existing
/// image's ESP (`edit` gets the current line's value), in whichever of
/// Limine's two configuration files it reads (ADR 0086).
pub fn edit_cmdline(img: &Path, edit: impl FnOnce(&str) -> String) -> Result {
    edit_menu(img, |conf| {
        let key = "    cmdline: ";
        let at = conf.find(key).ok_or_else(|| io::Error::other("no cmdline in limine.conf"))? + key.len();
        let end = conf[at..].find('\n').map_or(conf.len(), |e| at + e);
        Ok(format!("{}{}{}", &conf[..at], edit(&conf[at..end]), &conf[end..]))
    })
    .map_err(|e| format!("editing the boot entry of {}: {e}", img.display()))
}

/// Ask slate-loader for a screen mode in an existing image's menu
/// (`interface_resolution`, ADR 0111): for firmware that publishes no
/// EDID, such as QEMU's (the bench's 4K screen, ADR 0157).
pub fn set_resolution(img: &Path, w: u32, h: u32) -> Result {
    edit_menu(img, |conf| Ok(format!("interface_resolution: {w}x{h}\n{conf}")))
        .map_err(|e| format!("setting the resolution of {}: {e}", img.display()))
}

/// Rewrite the menu file slate-loader reads in an image's ESP.
fn edit_menu(img: &Path, edit: impl FnOnce(&str) -> io::Result<String>) -> io::Result<()> {
    let mut f = OpenOptions::new().read(true).write(true).open(img)?;
    let esp_bytes = (ROOT_FIRST_LBA - ESP_FIRST_LBA) * BLOCK_SIZE as u64;
    let slice = Slice::new(&mut f, ESP_FIRST_LBA * BLOCK_SIZE as u64, esp_bytes);
    let fs = fatfs::FileSystem::new(slice, fatfs::FsOptions::new())?;
    let root = fs.root_dir();
    let mut conf = String::new();
    let path = [slate_esp::CONF_FIRST, slate_esp::CONF_SECOND]
        .into_iter()
        .find(|p| root.open_file(p).is_ok())
        .ok_or_else(|| io::Error::other("no limine.conf"))?;
    root.open_file(path)?.read_to_string(&mut conf)?;
    let new = edit(&conf)?;
    let mut w = root.create_file(path)?;
    w.truncate()?;
    w.write_all(new.as_bytes())?;
    drop(w);
    drop(root);
    fs.unmount()
}

/// The kernels an image's boot menu lists, in order (the `path:` of each
/// entry in the configuration in force).
pub fn menu_kernels(img: &Path) -> Result<Vec<String>> {
    let run = || -> io::Result<Vec<String>> {
        let mut f = OpenOptions::new().read(true).write(true).open(img)?;
        let esp_bytes = (ROOT_FIRST_LBA - ESP_FIRST_LBA) * BLOCK_SIZE as u64;
        let slice = Slice::new(&mut f, ESP_FIRST_LBA * BLOCK_SIZE as u64, esp_bytes);
        let fs = fatfs::FileSystem::new(slice, fatfs::FsOptions::new())?;
        let root = fs.root_dir();
        let path = [slate_esp::CONF_FIRST, slate_esp::CONF_SECOND]
            .into_iter()
            .find(|p| root.open_file(p).is_ok())
            .ok_or_else(|| io::Error::other("no limine.conf"))?;
        let mut conf = String::new();
        root.open_file(path)?.read_to_string(&mut conf)?;
        Ok(conf.lines().filter_map(|l| l.trim().strip_prefix("path: boot():/")).map(String::from).collect())
    };
    run().map_err(|e| format!("reading the boot menu of {}: {e}", img.display()))
}

/// Check an image's EFI System Partition with dosfstools' fsck.fat, if
/// the host has it (ADR 0086: slate-update changes it in place).
pub fn fsck_esp(img: &Path) -> Result {
    if Command::new("fsck.fat").arg("--help").output().is_err() {
        return Ok(());
    }
    let mut f = File::open(img).map_err(|e| e.to_string())?;
    let mut esp = vec![0u8; ((ROOT_FIRST_LBA - ESP_FIRST_LBA) * BLOCK_SIZE as u64) as usize];
    f.seek(SeekFrom::Start(ESP_FIRST_LBA * BLOCK_SIZE as u64)).map_err(|e| e.to_string())?;
    f.read_exact(&mut esp).map_err(|e| e.to_string())?;
    let copy = img.with_extension("esp");
    std::fs::write(&copy, esp).map_err(|e| e.to_string())?;
    let out = Command::new("fsck.fat").arg("-n").arg(&copy).output().map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&copy);
    if !out.status.success() {
        return Err(format!(
            "fsck.fat found problems on {}'s boot partition: {}",
            img.display(),
            String::from_utf8_lossy(&out.stdout)
        ));
    }
    Ok(())
}

fn gpt_err(e: slate_gpt::Error) -> io::Error {
    io::Error::other(format!("GPT: {e:?}"))
}

/// Writes a FAT volume into a file at `base`.
pub struct FileSink<'a> {
    pub file: &'a mut File,
    pub base: u64,
}

impl slate_fat::Sink for FileSink<'_> {
    fn write(&mut self, offset: u64, data: &[u8]) -> core::result::Result<(), slate_fat::Error> {
        self.file.seek(SeekFrom::Start(self.base + offset)).map_err(|_| slate_fat::Error::Io)?;
        self.file.write_all(data).map_err(|_| slate_fat::Error::Io)
    }
}

/// A window `[start, start + len)` of a file, as its own seekable stream.
pub struct Slice<'a> {
    file: &'a mut File,
    start: u64,
    len: u64,
    pos: u64,
}

impl<'a> Slice<'a> {
    pub fn new(file: &'a mut File, start: u64, len: u64) -> Self {
        Slice { file, start, len, pos: 0 }
    }

    fn remaining(&self, want: usize) -> usize {
        want.min(self.len.saturating_sub(self.pos) as usize)
    }
}

impl Read for Slice<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.remaining(buf.len());
        self.file.seek(SeekFrom::Start(self.start + self.pos))?;
        let n = self.file.read(&mut buf[..n])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Write for Slice<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.remaining(buf.len());
        if n == 0 && !buf.is_empty() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "write past end of partition"));
        }
        self.file.seek(SeekFrom::Start(self.start + self.pos))?;
        let n = self.file.write(&buf[..n])?;
        self.pos += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Seek for Slice<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
        };
        match new {
            Some(p) if p <= self.len => {
                self.pos = p;
                Ok(p)
            }
            _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "seek outside partition")),
        }
    }
}
