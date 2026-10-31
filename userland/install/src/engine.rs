// SPDX-License-Identifier: MIT OR Apache-2.0

//! The install engine (ADR 0023, ADR 0029): everything an installer does,
//! with no user interface. It plans the disk, writes the GPT, the EFI
//! System Partition (FAT32, Limine and the kernel) and the SlateFS root
//! with the system copied from the signed payload, and sets up the
//! accounts (the first user; root locked or with a password, ADR 0035)
//! and the computer's name, language and keyboard. The root partition may
//! be encrypted (ADR 0036): its header first, the file system's sectors
//! encrypted behind it. Front ends (the text
//! and the graphical installer) only ask questions and show progress.
//!
//! The installed disk:
//!
//! ```text
//! LBA 0..33       protective MBR (its boot code is Limine's BIOS stage
//!                 1), primary GPT
//! LBA 34..2047    BIOS boot partition: Limine's BIOS stage 2 (ADR 0039)
//! 1 MiB..513 MiB  EFI System Partition: /EFI/BOOT/BOOTX64.EFI (Limine),
//!                 /boot/limine/limine-bios.sys (Limine's BIOS stage 3),
//!                 /boot/limine/limine.conf, /boot/slate/system-1/kernel,
//!                 and with an encrypted root /boot/slate/system-1/unlock
//!                 (ADR 0038); `slate-update` keeps a kernel per bootable
//!                 system there (ADR 0086)
//! 513 MiB..end    "slate-root": SlateFS with system-1, home and var
//!                 (ADR 0026, ADR 0027)
//! end-33..end     backup GPT
//! ```
//!
//! Beside another system (ADR 0116, [`layout`]) the disk keeps its table
//! and partitions: SlateOS's root goes in a free space, with an EFI System
//! Partition of its own before it unless it shares the disk's (its loader
//! in `EFI/slate/`, its menu and kernels in `boot/` as above). Other
//! systems' loaders are on its menu. The table changes last, so an install
//! that fails leaves the disk as it was. No BIOS boot code: it boots on
//! UEFI firmware.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use slate_gpt::{Guid, Partition};
use slatefs::{BootState, Fs, ROOT_INO};

pub const SECTOR: u64 = 512;
const MIB: u64 = 1 << 20;
pub const ESP_BYTES: u64 = 512 * MIB;
/// Smaller disks are not offered.
pub const MIN_DISK: u64 = 2 << 30;
/// GPT partition name of the root file system.
pub const ROOT_LABEL: &str = "slate-root";

/// What can go wrong, in words a person can act on.
#[derive(Debug)]
pub struct Error(pub String);

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

pub mod layout;
pub use layout::{Beside, DiskMap, Part, Row, Table, plan_beside, scan};

fn err(s: impl Into<String>) -> Error {
    Error(s.into())
}

/// The disk being installed to, addressed in bytes.
pub trait Device {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()>;
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<()>;
    fn flush(&mut self) -> Result<()>;
}

/// The files the installer brings.
#[derive(Debug)]
pub struct Payload<'a> {
    /// The system as a cpio (newc) archive.
    pub system: &'a [u8],
    pub kernel: &'a [u8],
    /// Limine's UEFI executable.
    pub efi: &'a [u8],
    /// Limine's BIOS stages, for BIOS firmware.
    pub bios: Option<BiosBoot<'a>>,
}

/// The BIOS boot files: the boot sector and what it loads (`bios-hdd.bin`:
/// slate-loader for BIOS, ADR 0089, or Limine's stages 1 and 2), and
/// Limine's stage 3 for the EFI System Partition when Limine is used.
#[derive(Clone, Copy, Debug)]
pub struct BiosBoot<'a> {
    pub hdd: &'a [u8],
    pub sys: Option<&'a [u8]>,
}

/// Where everything goes.
#[derive(Clone, Debug)]
pub struct Plan {
    pub disk_bytes: u64,
    pub disk_guid: Guid,
    pub esp: (u64, u64),
    pub esp_guid: Guid,
    /// The BIOS boot partition (first and last LBA) in the gap before the
    /// ESP (a whole disk only).
    pub bios: Option<(u64, u64)>,
    pub root: (u64, u64),
    pub root_guid: Guid,
    /// The root partition's GPT name.
    pub root_label: String,
    /// The whole disk, or beside what it keeps (ADR 0116).
    pub layout: Layout,
    /// Other systems' loaders, on the menu after SlateOS (ADR 0116).
    pub others: Vec<slate_esp::Other>,
    pub fs_uuid: [u8; 16],
    /// More kernel arguments for the boot entries (for example a fixed
    /// address, `slate.ip=...`).
    pub cmdline_extra: String,
    /// Keys that may log in as root over SSH (authorized_keys text).
    pub root_keys: Option<Vec<u8>>,
    /// Turn on Linux compatibility mode in the new system (ADR 0032).
    pub linux_compat: bool,
    /// The first user, an administrator (ADR 0035).
    pub account: Option<Account>,
    /// The computer's name (/etc/hostname).
    pub hostname: Option<String>,
    /// The locale, `en_US.UTF-8` (/etc/locale.conf's LANG).
    pub locale: Option<String>,
    /// The keyboard layout, `us`, `de`, `us(intl)` (/etc/slate/keyboard).
    pub keyboard: Option<String>,
    /// The time zone, `Europe/Berlin` (/etc/slate/timezone, ADR 0117).
    pub timezone: Option<String>,
    /// Encrypt the root partition (ADR 0036).
    pub encryption: Option<Encryption>,
    /// Install the Strata desktop (ADR 0037); without it, its programs and
    /// fonts stay out and the system is command line only.
    pub desktop: bool,
    /// Full graphics (ADR 0173): AMD's firmware, `slate-firmware-gpu`
    /// from the payload's own repository, installed as quarry would, its
    /// first start on trial, and the boot menu's standard-graphics entry.
    pub full_graphics: bool,
    /// The network settings (ADR 0054): this section replaces its
    /// namesake in /etc/slate/network (`*` for every card); None keeps the
    /// system's (DHCP).
    pub network: Option<slate_netconf::Card>,
    /// The live system's Bluetooth pairings, carried to the new system so
    /// a Bluetooth mouse goes on working after the first restart (ADR
    /// 0176): each file of /var/lib/slate/bluetooth (its path there and
    /// contents).
    pub bluetooth: Vec<(String, Vec<u8>)>,
    /// Install the Bluetooth controllers' firmware package (the machine
    /// has a controller that needs it; ADR 0176). A medium without the
    /// package installs without it.
    pub bluetooth_firmware: bool,
}

/// How the disk is laid out.
#[derive(Clone, Debug)]
pub enum Layout {
    /// The whole disk, erased.
    Whole,
    /// Beside the partitions the disk keeps (ADR 0116).
    Beside(Beside),
}

/// Where the payload records Strata's packages, `slate-desktop` and its
/// apps, `slate-apps`, as quarry does (ADR 0069, ADR 0071, ADR 0104).
pub const DESKTOP_RECORDS: [&str; 2] = ["usr/lib/quarry/db/slate-desktop", "usr/lib/quarry/db/slate-apps"];

/// Strata's paths in the system payload, left out of a command-line-only
/// install (ADR 0037): what its package's record (`files`, one entry per
/// line, the path last) lists. The record goes too, so the installed
/// system knows Strata is not there and can add it.
pub fn desktop_paths(files: &[u8]) -> BTreeSet<String> {
    String::from_utf8_lossy(files).lines().filter_map(|l| l.splitn(4, ' ').nth(3)).map(String::from).collect()
}

/// Whether a payload path belongs to the Strata desktop or its apps.
pub fn is_desktop_path(path: &str, desktop: &BTreeSet<String>) -> bool {
    desktop.contains(path)
        || DESKTOP_RECORDS.iter().any(|rec| path.strip_prefix(rec).is_some_and(|r| r.is_empty() || r.starts_with('/')))
}

/// An encrypted root: the header for the start of the partition (made by
/// the front end, which knows the password) and the key it guards, wiped
/// when dropped.
#[derive(Clone)]
pub struct Encryption {
    pub header: alloc::boxed::Box<[u8; slatecrypt::HEADER_BYTES]>,
    pub key: [u8; slatecrypt::KEY_BYTES],
}

impl Drop for Encryption {
    fn drop(&mut self) {
        slatecrypt::wipe(&mut self.key);
    }
}

impl core::fmt::Debug for Encryption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Encryption(..)")
    }
}

/// The first user: an administrator in the wheel group, who approves
/// system changes with their own password (ADR 0035).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Account {
    pub username: String,
    /// The passwd(5) comment field.
    pub full_name: String,
    /// The crypt(3) hash of the password.
    pub hash: String,
}

/// The first free user ID from 1000 in a passwd(5) file (the usual range
/// for people's accounts).
pub fn next_uid(passwd: &[u8]) -> u32 {
    let used: Vec<u32> = String::from_utf8_lossy(passwd)
        .lines()
        .filter_map(|l| l.split(':').nth(2).and_then(|u| u.parse().ok()))
        .collect();
    (1000..).find(|u| !used.contains(u)).unwrap_or(1000)
}

/// /etc/passwd with the account added (passwd(5): name, password, UID,
/// GID, comment, home, shell); the comment may hold neither `:`, `,` nor
/// a newline.
pub fn add_passwd(passwd: &[u8], a: &Account, uid: u32) -> Vec<u8> {
    let comment: String = a.full_name.chars().filter(|c| !matches!(c, ':' | ',' | '\n' | '\r')).collect();
    let mut out = String::from_utf8_lossy(passwd).into_owned();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out += &format!("{0}:x:{uid}:{uid}:{comment}:/home/{0}:/bin/sh\n", a.username);
    out.into_bytes()
}

/// /etc/group with the account's own group added and the account in wheel
/// (an administrator) and seat (seatd gives it the screen and input; ADR
/// 0035, ADR 0037) (group(5): name, password, GID, members).
pub fn add_group(group: &[u8], name: &str, gid: u32) -> Vec<u8> {
    let mut out = String::new();
    for line in String::from_utf8_lossy(group).lines() {
        let f: Vec<&str> = line.splitn(4, ':').collect();
        if f.len() == 4 && (f[0] == "wheel" || f[0] == "seat") {
            let members = if f[3].is_empty() { String::from(name) } else { format!("{},{name}", f[3]) };
            out += &format!("{}:{}:{}:{members}\n", f[0], f[1], f[2]);
        } else {
            out += &format!("{line}\n");
        }
    }
    out += &format!("{name}:x:{gid}:\n");
    out.into_bytes()
}

/// /etc/shadow with the account added (shadow(5): last change in days
/// since 1970, no minimum age, 99999 maximum, 7 days' warning).
pub fn add_shadow(shadow: &[u8], name: &str, hash: &str, days: i64) -> Vec<u8> {
    let mut out = String::from_utf8_lossy(shadow).into_owned();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out += &format!("{name}:{hash}:{days}:0:99999:7:::\n");
    out.into_bytes()
}

impl Plan {
    /// The root partition as `root=PARTUUID=` names it.
    pub fn root_partuuid(&self) -> String {
        guid_text(self.root_guid)
    }

    /// The EFI System Partition's number.
    pub fn esp_number(&self) -> u32 {
        match &self.layout {
            Layout::Whole => 1,
            Layout::Beside(b) => match b.esp_slot {
                Some(s) => s + 1,
                None => b.kept.iter().find(|p| p.guid == self.esp_guid).map_or(1, |p| p.number),
            },
        }
    }

    /// The root partition's number.
    pub fn root_number(&self) -> u32 {
        match &self.layout {
            Layout::Whole => 2,
            Layout::Beside(b) => b.root_slot + 1,
        }
    }

    /// Where the UEFI loader is on the EFI System Partition: its own
    /// directory on a shared one.
    pub fn loader_path(&self) -> &'static str {
        match &self.layout {
            Layout::Beside(b) if b.shared_esp => SHARED_LOADER,
            _ => "EFI/BOOT/BOOTX64.EFI",
        }
    }
}

/// The loader's place on an EFI System Partition shared with another
/// system (ADR 0116).
pub const SHARED_LOADER: &str = "EFI/slate/BOOTX64.EFI";

pub fn guid_text(g: Guid) -> String {
    format!("{g}")
}

/// Lay out a disk of `disk_bytes`; `random` makes the GUIDs and the file
/// system's UUID unique.
pub fn plan(disk_bytes: u64, random: &[u8; 64]) -> Result<Plan> {
    if disk_bytes < MIN_DISK {
        return Err(err(format!("the disk is too small ({} MiB; Slate needs 2 GiB)", disk_bytes / MIB)));
    }
    let blocks = disk_bytes / SECTOR;
    let layout = slate_gpt::Layout::for_disk(blocks).map_err(|e| err(format!("GPT: {e:?}")))?;
    let esp_first = MIB / SECTOR;
    let esp_last = esp_first + ESP_BYTES / SECTOR - 1;
    let root_first = esp_last + 1;
    // End on a 1 MiB boundary inside the usable range.
    let root_last = (layout.last_usable + 1) / (MIB / SECTOR) * (MIB / SECTOR) - 1;
    let guid = |i: usize| Guid::from_seed(random[i * 16..i * 16 + 16].try_into().unwrap());
    let bios = Some((layout.first_usable, esp_first - 1));
    Ok(plan_with(disk_bytes, guid(0), (esp_first, esp_last), guid(1), bios, (root_first, root_last), guid(2), random))
}

/// A plan with these places and the rest as it starts.
#[allow(clippy::too_many_arguments)]
fn plan_with(
    disk_bytes: u64,
    disk_guid: Guid,
    esp: (u64, u64),
    esp_guid: Guid,
    bios: Option<(u64, u64)>,
    root: (u64, u64),
    root_guid: Guid,
    random: &[u8; 64],
) -> Plan {
    Plan {
        disk_bytes,
        disk_guid,
        esp,
        esp_guid,
        bios,
        root,
        root_guid,
        root_label: String::from(ROOT_LABEL),
        layout: Layout::Whole,
        others: Vec::new(),
        fs_uuid: random[48..64].try_into().unwrap(),
        cmdline_extra: String::new(),
        root_keys: None,
        linux_compat: false,
        account: None,
        hostname: None,
        locale: None,
        keyboard: None,
        timezone: None,
        encryption: None,
        desktop: false,
        full_graphics: false,
        network: None,
        bluetooth: Vec::new(),
        bluetooth_firmware: false,
    }
}

/// Whether this machine has a Bluetooth controller that needs its
/// firmware from Slate: a MediaTek USB device (vendor 0e8d) with a
/// Bluetooth interface (class e0), from /sys/bus/usb/devices.
pub fn needs_bluetooth_firmware() -> bool {
    let read = |p: &str| slate_rt::fs::read_file(p.as_bytes()).map(|b| String::from(slate_rt::lossy(&b).trim())).ok();
    let Ok(entries) = slate_rt::fs::read_dir(b"/sys/bus/usb/devices") else { return false };
    let names: Vec<String> = entries.iter().map(|e| String::from(slate_rt::lossy(&e.name))).collect();
    names.iter().filter(|n| !n.contains(':')).any(|dev| {
        read(&format!("/sys/bus/usb/devices/{dev}/idVendor")).as_deref() == Some("0e8d")
            && names
                .iter()
                .filter(|i| i.starts_with(&format!("{dev}:")))
                .any(|i| read(&format!("/sys/bus/usb/devices/{i}/bInterfaceClass")).as_deref() == Some("e0"))
    })
}

/// Where slate-btd keeps its pairings, in the var subvolume.
const BLUETOOTH: &str = "lib/slate/bluetooth";

/// The running system's Bluetooth pairings ([`Plan::bluetooth`]): the
/// settings, the identity key and each paired device's file.
pub fn live_pairings() -> Vec<(String, Vec<u8>)> {
    let dir = format!("/var/{BLUETOOTH}");
    let mut out = Vec::new();
    for f in ["settings", "irk"] {
        if let Ok(d) = slate_rt::fs::read_file(format!("{dir}/{f}").as_bytes()) {
            out.push((String::from(f), d));
        }
    }
    if let Ok(entries) = slate_rt::fs::read_dir(format!("{dir}/devices").as_bytes()) {
        for e in entries {
            let name = String::from(slate_rt::lossy(&e.name));
            if name.starts_with('.') || name.contains('/') {
                continue;
            }
            if let Ok(d) = slate_rt::fs::read_file(format!("{dir}/devices/{name}").as_bytes()) {
                out.push((format!("devices/{name}"), d));
            }
        }
    }
    out
}

/// The pairings in the new system: root's alone (0700 folders, 0600
/// files), as slate-btd keeps them.
fn put_pairings(fs: &mut Fs<Region<'_>>, var: u64, files: &[(String, Vec<u8>)], now: i64) -> Result<()> {
    let fail = |p: &str, e: slatefs::Error| err(format!("/var/{BLUETOOTH}/{p}: {e:?}"));
    let mut dir = ROOT_INO;
    for d in BLUETOOTH.split('/') {
        let mode = if d == "bluetooth" { 0o700 } else { 0o755 };
        dir = match fs.lookup(var, dir, d.as_bytes()) {
            Ok(i) => i,
            Err(_) => fs.mkdir(var, dir, d.as_bytes(), mode, 0, 0).map_err(|e| fail(d, e))?,
        };
    }
    let devices = match fs.lookup(var, dir, b"devices") {
        Ok(i) => i,
        Err(_) => fs.mkdir(var, dir, b"devices", 0o700, 0, 0).map_err(|e| fail("devices", e))?,
    };
    for (path, data) in files {
        let (parent, name) = match path.strip_prefix("devices/") {
            Some(n) => (devices, n),
            None => (dir, path.as_str()),
        };
        if name.is_empty() || name.contains('/') || name.starts_with('.') {
            continue;
        }
        if fs.lookup(var, parent, name.as_bytes()).is_ok() {
            fs.unlink(var, parent, name.as_bytes()).map_err(|e| fail(path, e))?;
        }
        let ino = fs.create(var, parent, name.as_bytes(), 0o100_600, 0, 0, 0).map_err(|e| fail(path, e))?;
        fs.write(var, ino, 0, data).map_err(|e| fail(path, e))?;
        fs.set_times(var, ino, None, Some((now, 0))).map_err(|e| fail(path, e))?;
    }
    Ok(())
}

/// The steps, for progress reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Partition,
    BootPartition,
    FileSystem,
    /// Files copied so far, of the total.
    Copy(usize, usize),
    Account,
    Finish,
}

/// Limine's configuration for the installed system: one entry, system-1
/// with its kernel (`slate-update` adds the previous system after an
/// update, ADR 0086). An encrypted root loads the unlock archive, and the
/// keyboard layout goes on the command line for the unlock screen (ADR
/// 0038). A system with the desktop boots `quiet`, behind the boot splash
/// (ADR 0186).
pub fn limine_conf(plan: &Plan) -> String {
    let mut extra = plan.cmdline_extra.clone();
    if plan.desktop && !extra.split_whitespace().any(|w| w == "quiet") {
        extra = format!("quiet {extra}").trim_end().into();
    }
    if plan.encryption.is_some()
        && let Some(k) = plan.keyboard.as_deref().filter(|k| *k != "us")
    {
        extra = format!("{extra} slate.keyboard={k}").trim_start().into();
    }
    let cmdline = format!("root=PARTUUID={} {extra}", plan.root_partuuid());
    let conf =
        slate_esp::first_config_with(cmdline.trim_end(), FIRST_SYSTEM, plan.encryption.is_some(), plan.full_graphics);
    slate_esp::with_others(&conf, &plan.others)
}

/// The installed system's subvolume (ADR 0027).
const FIRST_SYSTEM: &str = "system-1";

pub use slate_esp::{UNLOCK_FONTS, UNLOCK_PROGRAM};

/// The boot's unlock archive (ADR 0038), from the system with `get` (a
/// path without the leading slash).
pub fn unlock_archive(get: &mut dyn FnMut(&str) -> Option<Vec<u8>>) -> Result<Vec<u8>> {
    slate_esp::unlock_archive(get).map_err(err)
}

/// A partition of the device as a SlateFS disk or a FAT sink.
struct Region<'a> {
    dev: &'a mut dyn Device,
    base: u64,
    len: u64,
    now: (i64, u32),
    /// Encrypted sectors (ADR 0036), numbered from `base`.
    xts: Option<&'a slatecrypt::Xts>,
}

/// Partition `p` (first and last sector) of the device, unencrypted.
fn part_region(dev: &mut dyn Device, p: (u64, u64), now: (i64, u32)) -> Region<'_> {
    Region { dev, base: p.0 * SECTOR, len: (p.1 + 1 - p.0) * SECTOR, now, xts: None }
}

impl Region<'_> {
    fn in_bounds(&self, offset: u64, len: usize) -> bool {
        let whole = self.xts.is_none() || (offset % SECTOR == 0 && len as u64 % SECTOR == 0);
        whole && offset + len as u64 <= self.len
    }
}

impl slatefs::Disk for Region<'_> {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> slatefs::Result<()> {
        if !self.in_bounds(offset, buf.len()) {
            return Err(slatefs::Error::Io);
        }
        self.dev.read(self.base + offset, buf).map_err(|_| slatefs::Error::Io)?;
        if let Some(x) = self.xts {
            x.decrypt(offset / SECTOR, buf);
        }
        Ok(())
    }
    fn write(&mut self, offset: u64, buf: &[u8]) -> slatefs::Result<()> {
        if !self.in_bounds(offset, buf.len()) {
            return Err(slatefs::Error::Io);
        }
        match self.xts {
            Some(x) => {
                let mut sealed = buf.to_vec();
                x.encrypt(offset / SECTOR, &mut sealed);
                self.dev.write(self.base + offset, &sealed)
            }
            None => self.dev.write(self.base + offset, buf),
        }
        .map_err(|_| slatefs::Error::Io)
    }
    fn flush(&mut self) -> slatefs::Result<()> {
        self.dev.flush().map_err(|_| slatefs::Error::Io)
    }
    fn now(&self) -> (i64, u32) {
        self.now
    }
}

impl slate_fat::edit::Disk for Region<'_> {
    fn read(&mut self, sector: u64, buf: &mut [u8; 512]) -> core::result::Result<(), slate_fat::Error> {
        if (sector + 1) * SECTOR > self.len {
            return Err(slate_fat::Error::Io);
        }
        self.dev.read(self.base + sector * SECTOR, buf).map_err(|_| slate_fat::Error::Io)
    }
    fn write(&mut self, sector: u64, data: &[u8; 512]) -> core::result::Result<(), slate_fat::Error> {
        if (sector + 1) * SECTOR > self.len {
            return Err(slate_fat::Error::Io);
        }
        self.dev.write(self.base + sector * SECTOR, data).map_err(|_| slate_fat::Error::Io)
    }
    fn flush(&mut self) -> core::result::Result<(), slate_fat::Error> {
        self.dev.flush().map_err(|_| slate_fat::Error::Io)
    }
}

impl slate_fat::Sink for Region<'_> {
    fn write(&mut self, offset: u64, data: &[u8]) -> core::result::Result<(), slate_fat::Error> {
        if offset + data.len() as u64 > self.len {
            return Err(slate_fat::Error::TooSmall);
        }
        self.dev.write(self.base + offset, data).map_err(|_| slate_fat::Error::Io)
    }
}

/// The BIOS boot partition's unique GUID: the disk's, with its last byte
/// changed (the plan's randomness is spent).
fn bios_guid(plan: &Plan) -> Guid {
    let mut b = plan.disk_guid.to_bytes();
    b[15] ^= 0x5A;
    Guid::from_bytes(&b)
}

/// Install the BIOS stages as Limine's `bios-install` does (slate-loader's
/// boot sector takes the same places, ADR 0089): the first 512
/// bytes of `hdd` become the boot sector, keeping the disk's timestamp
/// (bytes 218-223) and partition table (440-509); the rest goes at the
/// start of the BIOS boot partition `part`, whose byte offset the boot
/// sector holds at 0x1A4.
pub fn write_bios_stages(dev: &mut dyn Device, part: (u64, u64), hdd: &[u8]) -> Result<()> {
    let room = (part.1 + 1 - part.0) * SECTOR;
    if hdd.len() <= 512 || hdd[510..512] != [0x55, 0xAA] {
        return Err(err("the BIOS stages are not a boot sector image"));
    }
    if hdd.len() as u64 - 512 > room {
        return Err(err(format!("the BIOS stages ({} bytes) do not fit the BIOS boot partition", hdd.len())));
    }
    let mut old = [0u8; 512];
    dev.read(0, &mut old)?;
    let mut mbr = [0u8; 512];
    mbr.copy_from_slice(&hdd[..512]);
    mbr[0x1A4..0x1AC].copy_from_slice(&(part.0 * SECTOR).to_le_bytes());
    mbr[218..224].copy_from_slice(&old[218..224]);
    mbr[440..510].copy_from_slice(&old[440..510]);
    dev.write(part.0 * SECTOR, &hdd[512..])?;
    dev.write(0, &mbr)
}

/// Write the GPT: protective MBR, primary header and entries, backups.
fn write_gpt(dev: &mut dyn Device, plan: &Plan) -> Result<()> {
    let parts = [
        Partition {
            type_guid: Guid::EFI_SYSTEM,
            unique_guid: plan.esp_guid,
            first_lba: plan.esp.0,
            last_lba: plan.esp.1,
            attributes: 0,
            name: "EFI system partition",
        },
        Partition {
            type_guid: Guid::LINUX_FILESYSTEM,
            unique_guid: plan.root_guid,
            first_lba: plan.root.0,
            last_lba: plan.root.1,
            attributes: 0,
            name: &plan.root_label,
        },
    ];
    let mut parts = parts.to_vec();
    // Third, so that the ESP and the root keep their numbers.
    if let Some(bios) = plan.bios {
        parts.push(Partition {
            type_guid: Guid::BIOS_BOOT,
            unique_guid: bios_guid(plan),
            first_lba: bios.0,
            last_lba: bios.1,
            attributes: 0,
            name: "BIOS boot partition",
        });
    }
    let gpt =
        slate_gpt::encode(plan.disk_bytes / SECTOR, plan.disk_guid, &parts).map_err(|e| err(format!("GPT: {e:?}")))?;
    // Clear the first MiB too: old boot code and partition tables go.
    let mut head = vec![0u8; MIB as usize];
    head[..512].copy_from_slice(&gpt.protective_mbr);
    head[512..1024].copy_from_slice(&gpt.primary_header);
    head[1024..1024 + gpt.entries.len()].copy_from_slice(&gpt.entries);
    dev.write(0, &head)?;
    dev.write(gpt.backup_entries_lba * SECTOR, &gpt.entries)?;
    dev.write(gpt.backup_header_lba * SECTOR, &gpt.backup_header)?;
    Ok(())
}

/// Write a disk's table beside what it keeps (ADR 0116): the kept
/// partitions in their slots, as they were, and SlateOS's; the protective
/// MBR (and its boot code) stays, unless the disk had no table.
fn write_table_beside(dev: &mut dyn Device, plan: &Plan, b: &Beside) -> Result<()> {
    let mut parts: Vec<(u32, Partition<'_>)> = b
        .kept
        .iter()
        .map(|p| {
            let part = Partition {
                type_guid: p.type_guid,
                unique_guid: p.guid,
                first_lba: p.first,
                last_lba: p.last,
                attributes: p.attributes,
                name: &p.name,
            };
            (p.number - 1, part)
        })
        .collect();
    if let Some(slot) = b.esp_slot {
        let esp = Partition {
            type_guid: Guid::EFI_SYSTEM,
            unique_guid: plan.esp_guid,
            first_lba: plan.esp.0,
            last_lba: plan.esp.1,
            attributes: 0,
            name: "EFI system partition",
        };
        parts.push((slot, esp));
    }
    let root = Partition {
        type_guid: Guid::LINUX_FILESYSTEM,
        unique_guid: plan.root_guid,
        first_lba: plan.root.0,
        last_lba: plan.root.1,
        attributes: 0,
        name: &plan.root_label,
    };
    parts.push((b.root_slot, root));
    let gpt = slate_gpt::encode_slots(plan.disk_bytes / SECTOR, plan.disk_guid, &parts)
        .map_err(|e| err(format!("GPT: {e:?}")))?;
    // The backup first: the primary is what systems read.
    dev.write(gpt.backup_entries_lba * SECTOR, &gpt.entries)?;
    dev.write(gpt.backup_header_lba * SECTOR, &gpt.backup_header)?;
    dev.write(2 * SECTOR, &gpt.entries)?;
    dev.write(SECTOR, &gpt.primary_header)?;
    if b.new_table {
        dev.write(0, &gpt.protective_mbr)?;
    }
    Ok(())
}

fn write_esp(
    dev: &mut dyn Device,
    plan: &Plan,
    payload: &Payload<'_>,
    unlock: Option<&[u8]>,
    now: (i64, u32),
) -> Result<()> {
    if let Layout::Beside(b) = &plan.layout
        && b.shared_esp
    {
        return add_to_esp(dev, plan, payload, unlock, now);
    }
    let serial = u32::from_le_bytes(plan.fs_uuid[..4].try_into().unwrap());
    write_boot(dev, plan.esp, &limine_conf(plan), payload, unlock, serial, now)?;
    match (payload.bios, plan.bios) {
        (Some(b), Some(part)) => write_bios_stages(dev, part, b.hdd),
        _ => Ok(()),
    }
}

/// SlateOS's files on an EFI System Partition another system uses (ADR
/// 0116): only added, nothing of the other's changed. Its loader goes in
/// `EFI/slate/`, and on the removable media path too when that is free.
fn add_to_esp(
    dev: &mut dyn Device,
    plan: &Plan,
    payload: &Payload<'_>,
    unlock: Option<&[u8]>,
    now: (i64, u32),
) -> Result<()> {
    let fat = |e: slate_fat::Error| err(format!("the EFI System Partition: {e:?}"));
    let mut fs = slate_fat::edit::Fs::open(part_region(dev, plan.esp, now)).map_err(fat)?;
    if [slate_esp::CONF_FIRST, slate_esp::CONF_SECOND, "boot/slate"].iter().any(|p| fs.exists(p)) {
        return Err(err("the EFI System Partition has another SlateOS on it"));
    }
    let need = 2 * payload.efi.len() + payload.kernel.len() + unlock.map_or(0, <[u8]>::len);
    if fs.free_bytes() < need as u64 + MIB {
        return Err(err(format!("the EFI System Partition is full ({} MiB free)", fs.free_bytes() / MIB)));
    }
    fs.mkdir("EFI/slate").map_err(fat)?;
    fs.write(SHARED_LOADER, payload.efi).map_err(fat)?;
    if !fs.exists("EFI/BOOT/BOOTX64.EFI") {
        fs.mkdir("EFI/BOOT").map_err(fat)?;
        fs.write("EFI/BOOT/BOOTX64.EFI", payload.efi).map_err(fat)?;
    }
    let dir = slate_esp::system_dir(FIRST_SYSTEM);
    fs.mkdir(&dir).map_err(fat)?;
    fs.write(&format!("{dir}/kernel"), payload.kernel).map_err(fat)?;
    if let Some(u) = unlock {
        fs.write(&format!("{dir}/unlock"), u).map_err(fat)?;
    }
    fs.mkdir("boot/limine").map_err(fat)?;
    fs.write(slate_esp::CONF_FIRST, limine_conf(plan).as_bytes()).map_err(fat)
}

/// Write the EFI System Partition `esp` (first and last LBA): Limine, its
/// menu `conf`, and system-1's kernel and unlock archive (if there is
/// one) in their directory (ADR 0086).
fn write_boot(
    dev: &mut dyn Device,
    esp: (u64, u64),
    conf: &str,
    payload: &Payload<'_>,
    unlock: Option<&[u8]>,
    serial: u32,
    now: (i64, u32),
) -> Result<()> {
    let mut vol = slate_fat::Volume::new();
    let fat = |e: slate_fat::Error| err(format!("boot partition: {e:?}"));
    vol.add_file("EFI/BOOT/BOOTX64.EFI", payload.efi.to_vec()).map_err(fat)?;
    vol.add_file("boot/limine/limine.conf", conf.as_bytes().to_vec()).map_err(fat)?;
    if let Some(sys) = payload.bios.and_then(|b| b.sys) {
        vol.add_file("boot/limine/limine-bios.sys", sys.to_vec()).map_err(fat)?;
    }
    let dir = slate_esp::system_dir(FIRST_SYSTEM);
    vol.add_file(&format!("{dir}/kernel"), payload.kernel.to_vec()).map_err(fat)?;
    if let Some(u) = unlock {
        vol.add_file(&format!("{dir}/unlock"), u.to_vec()).map_err(fat)?;
    }
    let base = esp.0 * SECTOR;
    let len = (esp.1 + 1 - esp.0) * SECTOR;
    let mut r = Region { dev, base, len, now, xts: None };
    slate_fat::write(&vol, len, "SLATE-ESP", serial, esp.0 as u32, &mut r).map_err(fat)
}

/// The partitions of a GPT disk: (type, unique GUID, first LBA, last LBA).
pub fn partitions(dev: &mut dyn Device) -> Result<Vec<(Guid, Guid, u64, u64)>> {
    Ok(gpt_entries(dev)?.into_iter().map(|e| (e.type_guid, e.unique_guid, e.first_lba, e.last_lba)).collect())
}

/// The used entries of a GPT disk.
fn gpt_entries(dev: &mut dyn Device) -> Result<Vec<slate_gpt::Entry>> {
    let mut header = [0u8; 512];
    dev.read(SECTOR, &mut header)?;
    let h = slate_gpt::parse_header(&header).map_err(|e| err(format!("no GPT ({e:?})")))?;
    let len = h.entry_count as usize * h.entry_size as usize;
    if len > MIB as usize {
        return Err(err("GPT entry array too large"));
    }
    let mut array = vec![0u8; len];
    dev.read(h.entries_lba * SECTOR, &mut array)?;
    let entries = slate_gpt::parse_entries(&h, &array).map_err(|e| err(format!("bad GPT ({e:?})")))?;
    Ok(entries.collect())
}

/// SlateOS's EFI System Partition on a disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OurEsp {
    pub number: u32,
    /// First and last sector.
    pub range: (u64, u64),
    pub guid: Guid,
    /// It is another system's too: SlateOS's loader is in `EFI/slate/`.
    pub shared: bool,
    /// It is the disk's first EFI System Partition.
    pub first: bool,
}

/// SlateOS's EFI System Partition on `dev` (a disk may hold another
/// system's too, ADR 0116): the one whose menu boots the root `root`
/// (its PARTUUID), or without one, the first with SlateOS's menu; the
/// only one in any case.
pub fn find_esp(dev: &mut dyn Device, root: Option<&str>) -> Result<OurEsp> {
    let esps: Vec<slate_gpt::Entry> =
        gpt_entries(dev)?.into_iter().filter(|e| e.type_guid == Guid::EFI_SYSTEM).collect();
    let mut found = None;
    for (i, e) in esps.iter().enumerate() {
        let Ok(mut fs) = slate_fat::edit::Fs::open(part_region(&mut *dev, (e.first_lba, e.last_lba), (0, 0))) else {
            continue;
        };
        let Some((_, conf)) = slate_esp::active(&mut fs) else { continue };
        let ours = root.is_none_or(|r| boots_root(&conf, r));
        if ours {
            found = Some((i, fs.exists(SHARED_LOADER)));
            break;
        }
    }
    let (i, shared) = match (found, esps.len()) {
        (Some(f), _) => f,
        (None, 1) => (0, false),
        (None, 0) => return Err(err("no EFI System Partition")),
        (None, _) => return Err(err("no EFI System Partition boots this system")),
    };
    let e = &esps[i];
    Ok(OurEsp { number: e.index + 1, range: (e.first_lba, e.last_lba), guid: e.unique_guid, shared, first: i == 0 })
}

/// Whether a menu boots the root `partuuid`: one of its entries names it.
fn boots_root(conf: &str, partuuid: &str) -> bool {
    conf.lines()
        .filter_map(|l| l.trim().strip_prefix("cmdline:"))
        .flat_map(str::split_ascii_whitespace)
        .any(|w| w.strip_prefix("root=PARTUUID=").is_some_and(|u| u.eq_ignore_ascii_case(partuuid)))
}

/// Replace Limine on an installed disk, in place: its UEFI executable and
/// BIOS stage 3, each in one write (ADR 0086), and its BIOS stages 1 and
/// 2. Kernels are not this: each system carries its own, and
/// `slate-update` puts them on the partition. On a disk with another
/// system (ADR 0116) the EFI System Partition is the one whose menu boots
/// this root; on one shared with another system, the loader is in
/// `EFI/slate/` (and on the removable media path while that is SlateOS's
/// copy), and the BIOS boot code is the other system's.
pub fn update_boot(dev: &mut dyn Device, root_partuuid: &str, payload: &Payload<'_>, now: (i64, u32)) -> Result<()> {
    let parts = partitions(dev)?;
    if !parts.iter().any(|p| guid_text(p.1).eq_ignore_ascii_case(root_partuuid)) {
        return Err(err(format!("this disk does not hold the root partition {root_partuuid}")));
    }
    let esp = find_esp(dev, Some(root_partuuid))?;
    {
        let fat = |e: slate_fat::Error| err(format!("boot partition: {e:?}"));
        let mut fs = slate_fat::edit::Fs::open(part_region(&mut *dev, esp.range, now)).map_err(fat)?;
        if esp.shared {
            let old = fs.read(SHARED_LOADER).ok();
            fs.write(SHARED_LOADER, payload.efi).map_err(fat)?;
            if old.is_some() && fs.read("EFI/BOOT/BOOTX64.EFI").ok() == old {
                fs.write("EFI/BOOT/BOOTX64.EFI", payload.efi).map_err(fat)?;
            }
        } else {
            fs.mkdir("EFI/BOOT").map_err(fat)?;
            fs.write("EFI/BOOT/BOOTX64.EFI", payload.efi).map_err(fat)?;
            match payload.bios.map(|b| b.sys) {
                Some(Some(sys)) => {
                    fs.mkdir("boot/limine").map_err(fat)?;
                    fs.write("boot/limine/limine-bios.sys", sys).map_err(fat)?;
                }
                // slate-loader needs no file there: Limine's goes.
                Some(None) if fs.exists("boot/limine/limine-bios.sys") => {
                    fs.remove("boot/limine/limine-bios.sys").map_err(fat)?;
                }
                _ => {}
            }
        }
    }
    // Disks installed before BIOS boot (ADR 0039) have no BIOS boot
    // partition, and stay UEFI only; the boot code belongs to the system
    // on the disk's first EFI System Partition.
    let bios_part = parts.iter().find(|p| p.0 == Guid::BIOS_BOOT);
    if let (Some(b), Some(part), false, true) = (payload.bios, bios_part, esp.shared, esp.first) {
        write_bios_stages(dev, (part.2, part.3), b.hdd)?;
    }
    dev.flush()
}

/// The payload's repository (ADR 0071), which holds AMD's firmware
/// package when the build had it (ADR 0173).
const MEDIA_PKGS: &str = "var/lib/quarry/install/pkgs";

/// Where quarry keeps its record of installed packages (ADR 0069).
const QUARRY_DB: &str = "usr/lib/quarry/db";

/// The mark that keeps the first start with full graphics on trial
/// (userland/slatefs's `update::GRAPHICS_TRIAL`, ADR 0173's addendum),
/// in the var subvolume.
const GRAPHICS_TRIAL: &str = "lib/slate/graphics-trial";

/// `slate-firmware-gpu` from the payload's repository, its signature
/// checked against the system's quarry keys.
pub fn firmware_package(entries: &[slate_cpio::Entry<'_>]) -> Result<slate_qpkg::archive::Package> {
    media_package(entries, slate_display::graphics::PACKAGE, "AMD's firmware package").map_err(|e| {
        if e.0.contains("no such") { err("this medium has no full graphics (no AMD firmware package)") } else { e }
    })
}

/// The Bluetooth controllers' firmware package (ADR 0176), installed when
/// the machine has a controller that needs it.
pub const BLUETOOTH_FIRMWARE: &str = "slate-firmware-bt";

/// Package `want` from the payload's repository, its signature checked
/// against the system's quarry keys (`what` names it in errors).
fn media_package(entries: &[slate_cpio::Entry<'_>], want: &str, what: &str) -> Result<slate_qpkg::archive::Package> {
    let name = |e: &slate_cpio::Entry<'_>| String::from(e.name.trim_start_matches("./"));
    let keys: Vec<slate_qpkg::PublicKey> = entries
        .iter()
        .filter(|e| name(e).starts_with("usr/share/quarry/keys/") && name(e).ends_with(".pub"))
        .filter_map(|e| slate_qpkg::PublicKey::parse(&String::from_utf8_lossy(e.data)).ok())
        .collect();
    let prefix = format!("{MEDIA_PKGS}/{want}-");
    let qpk = entries
        .iter()
        .find(|e| name(e).starts_with(&prefix) && name(e).ends_with(".qpk"))
        .ok_or_else(|| err(format!("no such package on this medium: {want}")))?;
    let pkg = slate_qpkg::archive::read(qpk.data, &slate_qpkg::Keyring::new(keys))
        .map_err(|e| err(format!("{what}: {e}")))?;
    if pkg.manifest.name != want {
        return Err(err(format!("{what} is {}", pkg.manifest.name)));
    }
    Ok(pkg)
}

/// Full graphics (ADR 0173): the firmware package installed, and the
/// trial mark.
fn install_firmware(
    fs: &mut Fs<Region<'_>>,
    svs: &BTreeMap<&str, u64>,
    entries: &[slate_cpio::Entry<'_>],
    now: i64,
) -> Result<()> {
    install_package(fs, svs, firmware_package(entries)?, now)?;
    put_file(fs, svs["var"], GRAPHICS_TRIAL, b"full\n", now)
}

/// A package's files in the system and quarry's record of them (as
/// `quarry install` leaves it, so Settings and quarry can remove it).
fn install_package(
    fs: &mut Fs<Region<'_>>,
    svs: &BTreeMap<&str, u64>,
    pkg: slate_qpkg::archive::Package,
    now: i64,
) -> Result<()> {
    use slate_qpkg::Kind;
    let sys = svs["system-1"];
    let mut record = String::new();
    for e in &pkg.entries {
        let fail = |x: slatefs::Error| err(format!("/{}: {x:?}", e.path));
        let (parent, name) = make_parents(fs, sys, &e.path)?;
        let old = fs.lookup(sys, parent, name.as_bytes()).ok();
        let ino = match e.kind {
            Kind::Dir => match old {
                Some(i) => i,
                None => fs.mkdir(sys, parent, name.as_bytes(), e.mode & 0o7777, 0, 0).map_err(fail)?,
            },
            Kind::File | Kind::Symlink => {
                if old.is_some() {
                    fs.unlink(sys, parent, name.as_bytes()).map_err(fail)?;
                }
                if e.kind == Kind::Symlink {
                    fs.symlink(sys, parent, name.as_bytes(), &e.data, 0, 0).map_err(fail)?
                } else {
                    let ino = fs
                        .create(sys, parent, name.as_bytes(), 0o100_000 | (e.mode & 0o7777), 0, 0, 0)
                        .map_err(fail)?;
                    fs.write(sys, ino, 0, &e.data).map_err(fail)?;
                    ino
                }
            }
        };
        fs.set_times(sys, ino, None, Some((now, 0))).map_err(fail)?;
        // quarry's files record: kind, mode, SHA-256 and path.
        let (kind, mode, sha) = match e.kind {
            Kind::Dir => ('d', e.mode, String::from("-")),
            Kind::Symlink => ('l', 0o777, String::from("-")),
            Kind::File => {
                let c = if pkg.manifest.config.contains(&e.path) { 'c' } else { 'f' };
                (c, e.mode, slate_hash::hex(&slate_hash::sha256(&e.data)))
            }
        };
        record += &format!("{kind} {mode:o} {sha} {}\n", e.path);
    }
    let db = format!("{QUARRY_DB}/{}", pkg.manifest.name);
    let manifest = pkg.manifest.to_text();
    let files: [(&str, &[u8]); 3] =
        [("manifest", manifest.as_bytes()), ("files", record.as_bytes()), ("reason", b"explicit\n")];
    for (f, data) in files {
        put_file(fs, sys, &format!("{db}/{f}"), data, now)?;
    }
    Ok(())
}

/// The directory holding `path` in subvolume `sv` (made, 0755, where
/// missing) and the path's last name.
fn make_parents<'p>(fs: &mut Fs<Region<'_>>, sv: u64, path: &'p str) -> Result<(u64, &'p str)> {
    let (dirs, name) = path.rsplit_once('/').unwrap_or(("", path));
    let mut dir = ROOT_INO;
    for d in dirs.split('/').filter(|d| !d.is_empty()) {
        dir = match fs.lookup(sv, dir, d.as_bytes()) {
            Ok(i) => i,
            Err(_) => fs.mkdir(sv, dir, d.as_bytes(), 0o755, 0, 0).map_err(|e| err(format!("/{path}: {e:?}")))?,
        };
    }
    Ok((dir, name))
}

/// `data` as the file `path` (0644, root's) in subvolume `sv`.
fn put_file(fs: &mut Fs<Region<'_>>, sv: u64, path: &str, data: &[u8], now: i64) -> Result<()> {
    let fail = |e: slatefs::Error| err(format!("/{path}: {e:?}"));
    let (dir, name) = make_parents(fs, sv, path)?;
    if fs.lookup(sv, dir, name.as_bytes()).is_ok() {
        fs.unlink(sv, dir, name.as_bytes()).map_err(fail)?;
    }
    let ino = fs.create(sv, dir, name.as_bytes(), 0o100_644, 0, 0, 0).map_err(fail)?;
    fs.write(sv, ino, 0, data).map_err(fail)?;
    fs.set_times(sv, ino, None, Some((now, 0))).map_err(fail)
}

/// The subvolume a payload path goes to, and its path there: /home and
/// /var have their own (ADR 0027).
fn place(path: &str) -> (&'static str, &str) {
    for sv in ["home", "var"] {
        if let Some(rest) = path.strip_prefix(sv).and_then(|r| r.strip_prefix('/')) {
            return (sv, rest);
        }
    }
    ("system-1", path)
}

/// Replace root's password hash in an /etc/shadow (shadow(5)).
pub fn set_root_hash(shadow: &[u8], hash: &str) -> Vec<u8> {
    let text = String::from_utf8_lossy(shadow);
    let mut out = String::new();
    for line in text.lines() {
        match line.split_once(':') {
            Some(("root", rest)) => {
                let after = rest.split_once(':').map_or("", |(_, a)| a);
                out += &format!("root:{hash}:{after}\n");
            }
            _ => out += &format!("{line}\n"),
        }
    }
    out.into_bytes()
}

/// The system's files as the plan changes them: root's password, the
/// first user, the computer's name, the network settings.
fn customize(path: &str, data: &[u8], plan: &Plan, root_hash: &str, uid: u32, days: i64) -> Vec<u8> {
    let a = plan.account.as_ref();
    match path {
        "etc/shadow" => {
            let s = set_root_hash(data, root_hash);
            a.map_or(s.clone(), |a| add_shadow(&s, &a.username, &a.hash, days))
        }
        "etc/passwd" => a.map_or_else(|| data.to_vec(), |a| add_passwd(data, a, uid)),
        "etc/group" => a.map_or_else(|| data.to_vec(), |a| add_group(data, &a.username, uid)),
        "etc/hostname" => plan.hostname.as_ref().map_or_else(|| data.to_vec(), |h| format!("{h}\n").into_bytes()),
        "etc/slate/network" => plan
            .network
            .as_ref()
            .map_or_else(|| data.to_vec(), |c| slate_netconf::set_card(&String::from_utf8_lossy(data), c).into_bytes()),
        _ => data.to_vec(),
    }
}

/// Install: partition, boot partition, file system, system, accounts and
/// settings. `root_hash` is root's crypt(3) hash, or `!` to lock root
/// (shadow(5)); `log` lands in /var/log/install.log.
pub fn install(
    dev: &mut dyn Device,
    plan: &Plan,
    payload: &Payload<'_>,
    root_hash: &str,
    log: &[u8],
    now: (i64, u32),
    progress: &mut dyn FnMut(Step),
) -> Result<()> {
    let entries: Vec<slate_cpio::Entry<'_>> = slate_cpio::entries(payload.system)
        .collect::<core::result::Result<_, _>>()
        .map_err(|e| err(format!("the system image is damaged ({e:?})")))?;
    let passwd = entries.iter().find(|e| e.name.trim_start_matches("./") == "etc/passwd").map_or(&[][..], |e| e.data);
    let uid = next_uid(passwd);
    let days = now.0 / 86400;

    progress(Step::Partition);
    // Beside another system the table changes last (ADR 0116).
    if let Layout::Whole = plan.layout {
        write_gpt(dev, plan)?;
    }
    progress(Step::BootPartition);
    let unlock = match plan.encryption {
        Some(_) => Some(unlock_archive(&mut |p| {
            entries.iter().find(|e| e.name.trim_start_matches("./") == p).map(|e| e.data.to_vec())
        })?),
        None => None,
    };
    write_esp(dev, plan, payload, unlock.as_deref(), now)?;

    progress(Step::FileSystem);
    let mut base = plan.root.0 * SECTOR;
    let mut len = (plan.root.1 + 1 - plan.root.0) * SECTOR;
    // An encrypted root: the header, then the encrypted file system.
    let xts = plan.encryption.as_ref().map(|e| slatecrypt::Xts::new(&e.key));
    if let Some(e) = &plan.encryption {
        let mut area = vec![0u8; (slatecrypt::DATA_OFFSET * SECTOR) as usize];
        area[..slatecrypt::HEADER_BYTES].copy_from_slice(&e.header[..]);
        // And its copy (ADR 0039).
        let copy = (slatecrypt::BACKUP_OFFSET * SECTOR) as usize;
        area[copy..copy + slatecrypt::HEADER_BYTES].copy_from_slice(&e.header[..]);
        dev.write(base, &area)?;
        base += slatecrypt::DATA_OFFSET * SECTOR;
        len -= slatecrypt::DATA_OFFSET * SECTOR;
    }
    let blocks = len / slatefs::layout::BLOCK as u64;
    let fsr = |e: slatefs::Error| err(format!("file system: {e:?}"));
    let region = Region { dev, base, len, now, xts: xts.as_ref() };
    let mut fs = slatefs::mkfs(region, blocks, ROOT_LABEL, plan.fs_uuid, "system-1").map_err(fsr)?;
    let mut svs = BTreeMap::new();
    svs.insert("system-1", fs.subvol_by_name("system-1").ok_or_else(|| err("no system subvolume"))?);
    for name in ["home", "var"] {
        svs.insert(name, fs.create_subvolume(name).map_err(fsr)?);
    }

    // Copy the payload: directories first come first in the archive.
    let records: Vec<String> = DESKTOP_RECORDS.iter().map(|r| format!("{r}/files")).collect();
    let desktop: BTreeSet<String> = entries
        .iter()
        .filter(|e| records.iter().any(|r| e.name.trim_start_matches("./") == r))
        .flat_map(|e| desktop_paths(e.data))
        .collect();
    let total = entries.len();
    let mut inodes: BTreeMap<(&str, String), u64> = BTreeMap::new();
    for (done, e) in entries.iter().enumerate() {
        let path = e.name.trim_start_matches("./").trim_end_matches('/');
        if path.is_empty() || path == "." || (!plan.desktop && is_desktop_path(path, &desktop)) {
            continue;
        }
        let (sv_name, rel) = place(path);
        let sv = svs[sv_name];
        let fail = |x: slatefs::Error| err(format!("/{path}: {x:?}"));
        let kind = e.mode & 0o170_000;
        // /home and /var: a mount point in the system, and the subvolume's
        // root takes the same mode.
        if sv_name == "system-1" && (path == "home" || path == "var") {
            fs.set_mode(svs[path], ROOT_INO, e.mode & 0o7777).map_err(fail)?;
        }
        let (parent, name) = match rel.rsplit_once('/') {
            Some((p, n)) => (
                inodes.get(&(sv_name, String::from(p))).copied().ok_or_else(|| err(format!("/{path}: no parent")))?,
                n,
            ),
            None => (ROOT_INO, rel),
        };
        // An archive may name a directory twice (merge) or a file twice
        // (the later one wins), as the kernel's initramfs unpacking does.
        if let Ok(old) = fs.lookup(sv, parent, name.as_bytes()) {
            if kind == 0o040_000 && fs.stat(sv, old).map_err(fail)?.mode & 0o170_000 == 0o040_000 {
                fs.set_mode(sv, old, e.mode & 0o7777).map_err(fail)?;
                inodes.insert((sv_name, String::from(rel)), old);
                continue;
            }
            fs.unlink(sv, parent, name.as_bytes()).map_err(fail)?;
        }
        let ino = match kind {
            0o040_000 => fs.mkdir(sv, parent, name.as_bytes(), e.mode & 0o7777, e.uid, e.gid).map_err(fail)?,
            0o120_000 => fs.symlink(sv, parent, name.as_bytes(), e.data, e.uid, e.gid).map_err(fail)?,
            0o100_000 => {
                let data = customize(path, e.data, plan, root_hash, uid, days);
                let ino = fs.create(sv, parent, name.as_bytes(), e.mode, e.uid, e.gid, 0).map_err(fail)?;
                fs.write(sv, ino, 0, &data).map_err(fail)?;
                ino
            }
            _ => {
                let rdev = (u64::from(e.rdev_major) << 8) | u64::from(e.rdev_minor);
                fs.create(sv, parent, name.as_bytes(), e.mode, e.uid, e.gid, rdev).map_err(fail)?
            }
        };
        let mtime = Some((i64::from(e.mtime), 0));
        fs.set_times(sv, ino, None, mtime).map_err(fail)?;
        inodes.insert((sv_name, String::from(rel)), ino);
        if done % 64 == 0 {
            progress(Step::Copy(done, total));
        }
    }
    progress(Step::Copy(total, total));
    if plan.full_graphics {
        install_firmware(&mut fs, &svs, &entries, now.0)?;
    }
    if plan.bluetooth_firmware {
        // A medium built without it installs without it.
        if let Ok(pkg) = media_package(&entries, BLUETOOTH_FIRMWARE, "the Bluetooth firmware package") {
            install_package(&mut fs, &svs, pkg, now.0)?;
        }
    }
    if !plan.bluetooth.is_empty() {
        put_pairings(&mut fs, svs["var"], &plan.bluetooth, now.0)?;
    }

    progress(Step::Account);
    // The installer's record of what happened: the kernel log.
    let var = svs["var"];
    let logdir = match fs.lookup(var, ROOT_INO, b"log") {
        Ok(i) => i,
        Err(_) => fs.mkdir(var, ROOT_INO, b"log", 0o755, 0, 0).map_err(fsr)?,
    };
    let ino = fs.create(var, logdir, b"install.log", 0o100_640, 0, 0, 0).map_err(fsr)?;
    fs.write(var, ino, 0, log).map_err(fsr)?;

    // The system's own kernel (ADR 0086): each system version carries the
    // one it boots, and `slate-update` puts it on the boot partition.
    if !payload.kernel.is_empty() {
        let sys = svs["system-1"];
        let mut dir = ROOT_INO;
        for name in [&b"boot"[..], b"slate"] {
            dir = match fs.lookup(sys, dir, name) {
                Ok(i) => i,
                Err(_) => fs.mkdir(sys, dir, name, 0o755, 0, 0).map_err(fsr)?,
            };
        }
        if fs.lookup(sys, dir, b"kernel").is_ok() {
            fs.unlink(sys, dir, b"kernel").map_err(fsr)?;
        }
        let ino = fs.create(sys, dir, b"kernel", 0o100_644, 0, 0, 0).map_err(fsr)?;
        fs.write(sys, ino, 0, payload.kernel).map_err(fsr)?;
    }

    // Linux compatibility mode, read by rc.sysinit (ADR 0032).
    {
        let sys = svs["system-1"];
        let etc = fs.lookup(sys, ROOT_INO, b"etc").map_err(fsr)?;
        let dir = match fs.lookup(sys, etc, b"slate") {
            Ok(i) => i,
            Err(_) => fs.mkdir(sys, etc, b"slate", 0o755, 0, 0).map_err(fsr)?,
        };
        let ino = fs.create(sys, dir, b"linux-compat", 0o100_644, 0, 0, 0).map_err(fsr)?;
        fs.write(sys, ino, 0, if plan.linux_compat { b"on\n" } else { b"off\n" }).map_err(fsr)?;
        // The desktop to start at login (/etc/profile reads it).
        if plan.desktop {
            let ino = fs.create(sys, dir, b"session", 0o100_644, 0, 0, 0).map_err(fsr)?;
            fs.write(sys, ino, 0, b"strata\n").map_err(fsr)?;
        }
        if let Some(k) = &plan.keyboard {
            let ino = fs.create(sys, dir, b"keyboard", 0o100_644, 0, 0, 0).map_err(fsr)?;
            fs.write(sys, ino, 0, format!("{k}\n").as_bytes()).map_err(fsr)?;
        }
        // The time zone, by name (slate_rt::tz reads it).
        if let Some(z) = &plan.timezone {
            if fs.lookup(sys, dir, b"timezone").is_ok() {
                fs.unlink(sys, dir, b"timezone").map_err(fsr)?;
            }
            let ino = fs.create(sys, dir, b"timezone", 0o100_644, 0, 0, 0).map_err(fsr)?;
            fs.write(sys, ino, 0, format!("{z}\n").as_bytes()).map_err(fsr)?;
        }
        // The locale (locale.conf(5)'s format).
        if let Some(l) = &plan.locale {
            let ino = fs.create(sys, etc, b"locale.conf", 0o100_644, 0, 0, 0).map_err(fsr)?;
            fs.write(sys, ino, 0, format!("LANG={l}\n").as_bytes()).map_err(fsr)?;
        }
    }

    // The first user's home, in the home subvolume.
    if let Some(a) = &plan.account {
        let home = svs["home"];
        let name = a.username.as_bytes();
        if fs.lookup(home, ROOT_INO, name).is_err() {
            fs.mkdir(home, ROOT_INO, name, 0o700, uid, uid).map_err(fsr)?;
        }
    }

    if let Some(keys) = &plan.root_keys {
        let sys = svs["system-1"];
        let home = fs.lookup(sys, ROOT_INO, b"root").map_err(fsr)?;
        let ssh = match fs.lookup(sys, home, b".ssh") {
            Ok(i) => i,
            Err(_) => fs.mkdir(sys, home, b".ssh", 0o700, 0, 0).map_err(fsr)?,
        };
        let ino = fs.create(sys, ssh, b"authorized_keys", 0o100_600, 0, 0, 0).map_err(fsr)?;
        fs.write(sys, ino, 0, keys).map_err(fsr)?;
    }

    progress(Step::Finish);
    let sys = svs["system-1"];
    fs.set_boot(BootState { default: sys, fallback: 0, tries: 0, pending: false }).map_err(fsr)?;
    fs.sync().map_err(fsr)?;
    // Read it all back: fsck must find nothing.
    let mut check = Fs::mount(fs.into_disk(), true).map_err(fsr)?;
    let problems = check.check().map_err(fsr)?;
    if !problems.is_empty() {
        return Err(err(format!("the new file system has problems: {}", problems.join("; "))));
    }
    let disk = check.into_disk();
    if let Layout::Beside(b) = &plan.layout {
        disk.dev.flush()?;
        write_table_beside(disk.dev, plan, b)?;
    }
    disk.dev.flush()
}

/// Check the payload's detached signature against the trusted keys.
pub fn verify(system: &[u8], signature: &[u8], keys: &slate_qpkg::Keyring) -> Result<()> {
    slate_qpkg::archive::verify_detached(system, signature, keys)
        .map(|_| ())
        .map_err(|e| err(format!("the system image is not signed by a trusted key ({e:?})")))
}

#[cfg(test)]
mod tests;
