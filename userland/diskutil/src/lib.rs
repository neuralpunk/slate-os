// SPDX-License-Identifier: MIT OR Apache-2.0

//! `slate-disk` (ADR 0112): what Disks changes on a disk, run as root by
//! the privilege broker's `disk=WORDS` action after the system approval
//! dialog. The words are one of:
//!
//! - `table DISK`: a new, empty GPT (everything on the disk is lost);
//! - `add DISK START SIZE FORMAT NAME...`: a partition at START MiB, SIZE
//!   MiB long, named NAME, then formatted;
//! - `format PART FORMAT [LABEL...]`: a new, empty file system;
//! - `delete PART`: the partition goes from the table;
//! - `name PART NAME...`: the partition's name in the table;
//! - `mount PART`: mounted at `/run/media/USER/LABEL`, without set-user-ID
//!   programs or devices (SlateFS and ext2/3/4: the kernel has no FAT
//!   driver);
//! - `unmount PART`: one mounted there, unmounted;
//! - `poweroff DISK`: a removable disk with nothing on it in use made
//!   ready to unplug and let go, as if unplugged (ADR 0108's second
//!   addendum; a partition's name stands for its disk);
//!
//! where FORMAT is `fat32` (for other systems and cameras), `slatefs`, or
//! `empty` (none). The broker and Disks parse them here too, so all three
//! agree on what is allowed. The broker puts `--for UID` before the words:
//! the person asking, whose folder a mount goes in and whose a new
//! SlateFS's top folder is (ADR 0112's addendum).
//!
//! Nothing in use is touched: a disk or partition that is mounted, or
//! unlocked, or holds the running system, is refused ([`in_use`]), and
//! the kernel keeps raw writes off the system's disk anyway (ADR 0090).
//! After a change the kernel reads the table again (BLKRRPART) and looks
//! at what each partition holds (BLKFLSBUF, ADR 0112), so /sys/block and
//! Disks show it at once.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_sysinfo::block::{Disk, Mapped};
use slate_sysinfo::load::Mount;

/// Partitions start on whole MiB (2048 sectors).
pub const ALIGN: u64 = 2048;
const SECTOR: u64 = 512;
const MIB: u64 = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Fat32,
    SlateFs,
    Empty,
}

impl Format {
    pub const ALL: [Format; 3] = [Format::Fat32, Format::SlateFs, Format::Empty];

    pub fn word(self) -> &'static str {
        match self {
            Format::Fat32 => "fat32",
            Format::SlateFs => "slatefs",
            Format::Empty => "empty",
        }
    }

    /// The name people read.
    pub fn name(self) -> &'static str {
        match self {
            Format::Fat32 => "FAT32",
            Format::SlateFs => "SlateFS",
            Format::Empty => "Nothing",
        }
    }

    /// What it is for.
    pub fn purpose(self) -> &'static str {
        match self {
            Format::Fat32 => "Readable by other systems, cameras and TVs",
            Format::SlateFs => "Slate's own, with snapshots",
            Format::Empty => "Leave the space unformatted",
        }
    }

    fn parse(w: &str) -> Result<Format, String> {
        Format::ALL.iter().copied().find(|f| f.word() == w).ok_or_else(|| format!("{w}: fat32, slatefs or empty"))
    }

    /// The longest label it takes.
    pub fn max_label(self) -> usize {
        match self {
            Format::Fat32 => 11,
            Format::SlateFs => 63,
            Format::Empty => 0,
        }
    }

    /// `label` as this format keeps it: FAT labels are upper case.
    pub fn label(self, label: &str) -> String {
        match self {
            Format::Fat32 => label.to_ascii_uppercase(),
            _ => label.to_string(),
        }
    }
}

/// A change to a disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Table { disk: String },
    Add { disk: String, start_mib: u64, size_mib: u64, format: Format, name: String },
    Format { part: String, format: Format, label: String },
    Delete { part: String },
    Name { part: String, name: String },
    Mount { part: String },
    Unmount { part: String },
    PowerOff { disk: String },
}

/// A device's name as /dev has it: `sdb`, `nvme1n1p2`.
fn device(w: Option<&str>) -> Result<String, String> {
    let w = w.ok_or("which disk?")?;
    let ok = (2..=32).contains(&w.len())
        && w.starts_with(|c: char| c.is_ascii_lowercase())
        && w.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    if ok { Ok(w.to_string()) } else { Err(format!("{w}: not a disk's name")) }
}

/// Whether `label` suits `format` (FAT: letters, digits, spaces, `-`
/// and `_`; others: printable, no `/`).
pub fn label_ok(format: Format, label: &str) -> Result<(), String> {
    if label.chars().count() > format.max_label() {
        return Err(format!("A {} label has at most {} characters.", format.name(), format.max_label()));
    }
    let ok = match format {
        Format::Fat32 => label.chars().all(|c| c.is_ascii_alphanumeric() || " -_".contains(c)),
        _ => label.chars().all(|c| !c.is_control() && c != '/'),
    };
    if ok { Ok(()) } else { Err(format!("That label has characters {} labels can't have.", format.name())) }
}

/// Whether `name` suits a GPT partition name (Slate writes ASCII).
pub fn name_ok(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 36 {
        return Err("A partition's name has 1 to 36 characters.".into());
    }
    if !name.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
        return Err("A partition's name is plain letters, digits and signs.".into());
    }
    Ok(())
}

/// The words after `disk=`.
pub fn parse(words: &str) -> Result<Change, String> {
    let mut w = words.split(' ');
    let op = w.next().unwrap_or("");
    let num = |v: Option<&str>| -> Result<u64, String> {
        v.and_then(|v| v.parse::<u64>().ok()).filter(|n| *n > 0 && *n < 1 << 40).ok_or_else(|| "a size in MiB".into())
    };
    let rest = |w: &mut core::str::Split<'_, char>| w.collect::<Vec<_>>().join(" ");
    let c = match op {
        "table" => Change::Table { disk: device(w.next())? },
        "add" => {
            let disk = device(w.next())?;
            let start_mib = num(w.next())?;
            let size_mib = num(w.next())?;
            let format = Format::parse(w.next().unwrap_or(""))?;
            let name = rest(&mut w);
            name_ok(&name)?;
            Change::Add { disk, start_mib, size_mib, format, name }
        }
        "format" => {
            let part = device(w.next())?;
            let format = Format::parse(w.next().unwrap_or(""))?;
            let label = rest(&mut w);
            label_ok(format, &label)?;
            Change::Format { part, format, label }
        }
        "delete" => Change::Delete { part: device(w.next())? },
        "name" => {
            let part = device(w.next())?;
            let name = rest(&mut w);
            name_ok(&name)?;
            Change::Name { part, name }
        }
        "mount" => Change::Mount { part: device(w.next())? },
        "unmount" => Change::Unmount { part: device(w.next())? },
        "poweroff" => Change::PowerOff { disk: device(w.next())? },
        _ => return Err(format!("disk={words}: table, add, format, delete, name, mount, unmount or poweroff")),
    };
    if matches!(op, "table" | "delete" | "mount" | "unmount" | "poweroff") && w.next().is_some() {
        return Err(format!("disk={words}: too many words"));
    }
    Ok(c)
}

impl Change {
    /// The words for `disk=`.
    pub fn words(&self) -> String {
        match self {
            Change::Table { disk } => format!("table {disk}"),
            Change::Add { disk, start_mib, size_mib, format, name } => {
                format!("add {disk} {start_mib} {size_mib} {} {name}", format.word())
            }
            Change::Format { part, format, label } => {
                format!("format {part} {} {label}", format.word()).trim_end().to_string()
            }
            Change::Delete { part } => format!("delete {part}"),
            Change::Name { part, name } => format!("name {part} {name}"),
            Change::Mount { part } => format!("mount {part}"),
            Change::Unmount { part } => format!("unmount {part}"),
            Change::PowerOff { disk } => format!("poweroff {disk}"),
        }
    }

    /// Whether it only mounts, unmounts or powers off (nothing on the
    /// disk changes).
    pub fn mounting(&self) -> bool {
        matches!(self, Change::Mount { .. } | Change::Unmount { .. } | Change::PowerOff { .. })
    }

    /// The device it changes.
    pub fn target(&self) -> &str {
        match self {
            Change::Table { disk } | Change::Add { disk, .. } | Change::PowerOff { disk } => disk,
            Change::Format { part, .. }
            | Change::Delete { part }
            | Change::Name { part, .. }
            | Change::Mount { part }
            | Change::Unmount { part } => part,
        }
    }
}

/// The free spaces of a disk `sectors` long with partitions `parts`
/// (first sector, sectors), each starting and ending on a MiB, at least
/// one MiB (`slate_gpt::free_regions`).
pub fn free_regions(sectors: u64, parts: &[(u64, u64)]) -> Vec<(u64, u64)> {
    slate_gpt::free_regions(sectors, parts, ALIGN)
}

/// The disk `name` is on (itself for a disk).
pub fn disk_of<'a>(disks: &'a [Disk], name: &str) -> Option<&'a Disk> {
    disks.iter().find(|d| d.name == name || d.parts.iter().any(|p| p.name == name))
}

/// Whether `target` (a disk or partition) is on a removable disk: the
/// broker mounts those for the person at the machine without asking.
pub fn removable(target: &str) -> bool {
    let (disks, _) = slate_sysinfo::block::read(&slate_sysinfo::block::RealSys);
    disk_of(&disks, target).is_some_and(|d| d.removable)
}

/// The file systems the kernel mounts, by udev's name.
pub fn mountable(fs: &str) -> bool {
    matches!(fs, "slatefs" | "ext4" | "ext3" | "ext2")
}

/// Where removable disks are mounted, under a folder per person.
pub const MEDIA: &str = "/run/media";

/// A folder name for a mount: the label (or the device) without `/` and
/// control characters, not `.` or `..`.
pub fn mount_name(label: &str, part: &str) -> String {
    let s: String = label.chars().filter(|c| *c != '/' && !c.is_control()).collect();
    let s = s.trim();
    if s.is_empty() || s == "." || s == ".." { part.to_string() } else { s.to_string() }
}

/// Why `target` (a disk or a partition) can't be changed now, if it
/// can't: it, or a partition on it, is mounted or unlocked, or holds the
/// running system.
pub fn in_use(target: &str, disks: &[Disk], mapped: &[Mapped], mounts: &[Mount]) -> Option<String> {
    let Some(disk) = disk_of(disks, target) else { return Some(format!("There is no disk {target}.")) };
    if disk.read_only {
        return Some("This disk can only be read.".into());
    }
    let mounted = |dev: &str| mounts.iter().find(|m| m.source == format!("/dev/{dev}")).map(|m| m.path.clone());
    // Where a device is mounted, directly or unlocked.
    let used = |dev: &str| -> Option<String> {
        if let Some(at) = mounted(dev) {
            return Some(at);
        }
        let m = mapped.iter().find(|m| m.under == dev)?;
        Some(mounted(&m.name).unwrap_or_else(|| format!("unlocked as {}", m.name)))
    };
    let all: Vec<&str> =
        core::iter::once(disk.name.as_str()).chain(disk.parts.iter().map(|p| p.name.as_str())).collect();
    if all.iter().any(|d| used(d).as_deref() == Some("/")) {
        return Some("This is the system's disk: Slate runs from it.".into());
    }
    let whole = target == disk.name;
    for d in all.into_iter().filter(|d| whole || *d == target) {
        if let Some(at) = used(d) {
            let what = if d == target { String::from("It") } else { d.to_string() };
            return Some(if at.starts_with('/') {
                format!("{what} is in use, at {at}.")
            } else {
                format!("{what} is in use, {at}.")
            });
        }
    }
    None
}

// --- Doing it (as root) ---------------------------------------------------

/// Block device ioctls (musl's `sys/mount.h`, ADR 0009).
const BLKRRPART: u32 = 0x125F;
const BLKFLSBUF: u32 = 0x1261;

type Res<T = ()> = Result<T, String>;

pub fn main() -> i32 {
    let mut args: Vec<String> =
        slate_rt::env::args().iter().skip(1).map(|a| String::from(slate_rt::lossy(a))).collect();
    // The person asking (the broker says; root otherwise).
    let mut person = 0u32;
    if args.first().map(String::as_str) == Some("--for") && args.len() > 1 {
        person = args[1].parse().unwrap_or(0);
        args.drain(..2);
    }
    let r = parse(&args.join(" ")).and_then(|c| run(&c, person));
    match r {
        Ok(said) => {
            slate_rt::println!("{said}");
            0
        }
        Err(e) => {
            slate_rt::eprintln!("slate-disk: {e}");
            1
        }
    }
}

fn state() -> (Vec<Disk>, Vec<Mapped>, Vec<Mount>) {
    let (d, m) = slate_sysinfo::block::read(&slate_sysinfo::block::RealSys);
    (d, m, slate_sysinfo::load::mounts(&slate_sysinfo::load::read("/proc/mounts")))
}

fn run(c: &Change, person: u32) -> Res<String> {
    if slate_rt::process::geteuid() != 0 {
        return Err("must run as root (Disks asks the privilege broker)".into());
    }
    let (disks, mapped, mounts) = state();
    if let Change::Unmount { part } = c {
        return unmount(part, &mounts);
    }
    if let Change::PowerOff { disk } = c {
        return power_off(disk, &disks, &mapped, &mounts);
    }
    if let Some(why) = in_use(c.target(), &disks, &mapped, &mounts) {
        return Err(why);
    }
    let disk = disk_of(&disks, c.target()).ok_or("no such disk")?.clone();
    match c {
        Change::Table { .. } => {
            let mut guid = [0u8; 16];
            let _ = slate_rt::process::random(&mut guid);
            let dev = Dev::open(&disk.name)?;
            // The old tables and boot code go with the first MiB; the
            // backup GPT is overwritten.
            dev.zero(0, MIB)?;
            write_table(&dev, disk.sectors, slate_gpt::Guid::from_seed(guid), &[])?;
            dev.rescan()?;
            Ok(format!("{}: a new GPT partition table", disk.name))
        }
        Change::Add { start_mib, size_mib, format, name, .. } => {
            let dev = Dev::open(&disk.name)?;
            let (guid, mut parts) = read_table(&dev)?;
            let first = start_mib * ALIGN;
            let count = size_mib * ALIGN;
            let free = free_regions(
                disk.sectors,
                &parts.iter().map(|p| (p.1.first, p.1.last + 1 - p.1.first)).collect::<Vec<_>>(),
            );
            if !free.iter().any(|&(s, n)| first >= s && first + count <= s + n) {
                return Err(format!("There is no free space of {size_mib} MiB at {start_mib} MiB."));
            }
            let slot = (0..128u32).find(|s| !parts.iter().any(|p| p.0 == *s)).ok_or("The table is full.")?;
            let mut uuid = [0u8; 16];
            let _ = slate_rt::process::random(&mut uuid);
            let kind =
                if *format == Format::Fat32 { slate_gpt::Guid::BASIC_DATA } else { slate_gpt::Guid::LINUX_FILESYSTEM };
            parts.push((
                slot,
                Owned {
                    kind,
                    uuid: slate_gpt::Guid::from_seed(uuid),
                    first,
                    last: first + count - 1,
                    attributes: 0,
                    name: name.clone(),
                },
            ));
            // Nothing old shows through the new partition.
            dev.zero(first * SECTOR, MIB.min(count * SECTOR))?;
            write_table(&dev, disk.sectors, guid, &parts)?;
            dev.rescan()?;
            let part = part_name(&disk.name, slot + 1);
            let made = format!("{part}: {size_mib} MiB, \"{name}\"");
            if *format == Format::Empty {
                return Ok(made);
            }
            // The partition's name labels the file system too, as far as
            // the format allows.
            let label: String = match format {
                Format::Fat32 => format
                    .label(name)
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || " -_".contains(*c))
                    .take(11)
                    .collect(),
                _ => name.chars().take(format.max_label()).collect(),
            };
            let f = make_fs(&part, *format, label.trim(), first, person)?;
            Ok(format!("{made}, {f}"))
        }
        Change::Format { part, format, label } => {
            let p = disk
                .parts
                .iter()
                .find(|p| p.name == *part)
                .ok_or_else(|| format!("{part} is a whole disk: give it a partition first"))?;
            make_fs(part, *format, &format.label(label), p.start, person)
        }
        Change::Name { part, name } => {
            let p = disk.parts.iter().find(|p| p.name == *part).ok_or_else(|| format!("{part} is not a partition"))?;
            let dev = Dev::open(&disk.name)?;
            let (guid, mut parts) = read_table(&dev)?;
            let entry =
                parts.iter_mut().find(|q| q.0 + 1 == p.number).ok_or_else(|| format!("{part} is not in the GPT"))?;
            entry.1.name = name.clone();
            write_table(&dev, disk.sectors, guid, &parts)?;
            // The kernel reads the table again when nothing on the disk is
            // in use; otherwise at the next change or start.
            let _ = dev.rescan();
            Ok(format!("{part}: named \"{name}\""))
        }
        Change::Mount { part } => mount(part, &disk, person),
        Change::Unmount { .. } | Change::PowerOff { .. } => unreachable!(),
        Change::Delete { part } => {
            let p = disk.parts.iter().find(|p| p.name == *part).ok_or_else(|| format!("{part} is not a partition"))?;
            let dev = Dev::open(&disk.name)?;
            let (guid, mut parts) = read_table(&dev)?;
            let before = parts.len();
            parts.retain(|q| q.0 + 1 != p.number);
            if parts.len() == before {
                return Err(format!("{part} is not in the GPT"));
            }
            write_table(&dev, disk.sectors, guid, &parts)?;
            dev.rescan()?;
            Ok(format!("{part}: deleted"))
        }
    }
}

/// A person's name, user ID and group ID, from /etc/passwd.
fn person_of(uid: u32) -> Res<(String, u32, u32)> {
    let text = slate_rt::fs::read_file(b"/etc/passwd").map(|t| String::from(slate_rt::lossy(&t))).unwrap_or_default();
    text.lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() >= 4 && f[2].parse() == Ok(uid)).then(|| (f[0].to_string(), uid, f[3].parse().unwrap_or(uid)))
        })
        .ok_or_else(|| format!("user {uid} has no account"))
}

/// Mount `part` (on `disk`) for `person` at `/run/media/USER/LABEL`.
fn mount(part: &str, disk: &Disk, person: u32) -> Res<String> {
    let holds = match disk.parts.iter().find(|p| p.name == part) {
        Some(p) => p.holds.clone(),
        None if disk.name == part => disk.holds.clone(),
        None => return Err(format!("There is no {part}.")),
    };
    let Some(h) = holds else { return Err("Nothing Slate can read is on it.".into()) };
    if !mountable(&h.fs) {
        return Err(match h.fs.as_str() {
            "vfat" => String::from("Slate can't open FAT32 yet: the kernel has no FAT driver."),
            "slatecrypt" => String::from("It is encrypted: opening other encrypted disks isn't offered yet."),
            _ => format!("Slate can't open {} file systems.", h.kind),
        });
    }
    let (user, uid, gid) = person_of(person)?;
    let top = format!("{MEDIA}/{user}");
    let _ = slate_rt::fs::mkdir(MEDIA.as_bytes(), 0o755);
    let _ = slate_rt::fs::mkdir(top.as_bytes(), 0o750);
    let _ = slate_rt::fs::chown(top.as_bytes(), uid, gid);
    let base = mount_name(&h.label, part);
    let mut at = format!("{top}/{base}");
    let mut k = 2;
    while slate_rt::fs::mkdir(at.as_bytes(), 0o755).is_err() {
        // Taken (an earlier mount): beside it.
        if k > 99 {
            return Err(format!("{top}: no free name"));
        }
        at = format!("{top}/{base} {k}");
        k += 1;
    }
    let flags = slate_rt::fs::MS_NOSUID | slate_rt::fs::MS_NODEV;
    if let Err(e) = slate_rt::fs::mount(format!("/dev/{part}").as_bytes(), at.as_bytes(), h.fs.as_bytes(), flags, b"") {
        let _ = slate_rt::fs::rmdir(at.as_bytes());
        return Err(format!("{part}: {e}"));
    }
    Ok(format!("{part}: mounted at {at}"))
}

/// Unmount `part` from under /run/media (nothing else is undone here).
fn unmount(part: &str, mounts: &[Mount]) -> Res<String> {
    let dev = format!("/dev/{part}");
    let m = mounts
        .iter()
        .find(|m| m.source == dev && m.path.starts_with(&format!("{MEDIA}/")))
        .ok_or_else(|| format!("{part} isn't mounted in {MEDIA}."))?;
    slate_rt::fs::umount(m.path.as_bytes()).map_err(|e| match e {
        slate_rt::Errno::EBUSY => String::from("It is in use: close what has files open on it first."),
        e => format!("{}: {e}", m.path),
    })?;
    let _ = slate_rt::fs::rmdir(m.path.as_bytes());
    Ok(format!("{part}: unmounted from {}", m.path))
}

/// Eject the medium and let the device go (ioctl_cdrom(2); for a USB
/// disk the kernel disables its port too).
const CDROMEJECT: u32 = 0x5309;

/// Power off removable disk `name` (or the disk partition `name` is on):
/// refused while anything on it is mounted or unlocked.
fn power_off(name: &str, disks: &[Disk], mapped: &[Mapped], mounts: &[Mount]) -> Res<String> {
    let disk = disk_of(disks, name).ok_or_else(|| format!("There is no disk {name}."))?;
    if !disk.removable {
        return Err(format!("{} isn't removable.", disk.name));
    }
    if let Some(why) = busy(disk, mapped, mounts) {
        return Err(why);
    }
    let dev = Dev::open(&disk.name)?;
    slate_rt::io::ioctl(dev.fd, CDROMEJECT, 0).map_err(|e| match e {
        slate_rt::Errno::ENOTTY => format!("{} can't be powered off.", disk.name),
        e => format!("{}: {e}", disk.name),
    })?;
    Ok(format!("{}: powered off; it can be removed", disk.name))
}

/// Why nothing on `disk` may be let go now: a partition of it (or the
/// disk) mounted or unlocked.
fn busy(disk: &Disk, mapped: &[Mapped], mounts: &[Mount]) -> Option<String> {
    let devs: Vec<&str> =
        core::iter::once(disk.name.as_str()).chain(disk.parts.iter().map(|p| p.name.as_str())).collect();
    for d in devs {
        if let Some(m) = mounts.iter().find(|m| m.source == format!("/dev/{d}")) {
            return Some(format!("{d} is in use, at {}: unmount it first.", m.path));
        }
        if let Some(m) = mapped.iter().find(|m| m.under == d) {
            return Some(format!("{d} is in use, unlocked as {}.", m.name));
        }
    }
    None
}

fn part_name(disk: &str, n: u32) -> String {
    if disk.ends_with(|c: char| c.is_ascii_digit()) { format!("{disk}p{n}") } else { format!("{disk}{n}") }
}

/// A partition read from a table, to write back.
#[derive(Clone, Debug)]
struct Owned {
    kind: slate_gpt::Guid,
    uuid: slate_gpt::Guid,
    first: u64,
    last: u64,
    attributes: u64,
    name: String,
}

/// An open block device.
struct Dev {
    fd: i32,
    name: String,
}

impl Dev {
    fn open(name: &str) -> Res<Dev> {
        Dev::at(&format!("/dev/{name}"), name)
    }

    fn at(path: &str, name: &str) -> Res<Dev> {
        let fd = slate_rt::fs::open(path.as_bytes(), slate_rt::fs::O_RDWR | slate_rt::fs::O_CLOEXEC, 0)
            .map_err(|e| format!("{path}: {e}"))?;
        Ok(Dev { fd, name: name.to_string() })
    }

    fn read(&self, at: u64, buf: &mut [u8]) -> Res {
        let n = slate_rt::io::pread(self.fd, buf, at).map_err(|e| format!("{}: {e}", self.name))?;
        if n == buf.len() { Ok(()) } else { Err(format!("{}: short read", self.name)) }
    }

    fn write(&self, at: u64, buf: &[u8]) -> Res {
        let mut done = 0;
        while done < buf.len() {
            let n = slate_rt::io::pwrite(self.fd, &buf[done..], at + done as u64).map_err(|e| match e {
                slate_rt::Errno::EPERM => format!("{}: the system's disk can't be written", self.name),
                e => format!("{}: {e}", self.name),
            })?;
            if n == 0 {
                return Err(format!("{}: short write", self.name));
            }
            done += n;
        }
        Ok(())
    }

    fn zero(&self, at: u64, len: u64) -> Res {
        let chunk = alloc::vec![0u8; MIB as usize];
        let mut off = 0;
        while off < len {
            let n = (len - off).min(MIB) as usize;
            self.write(at + off, &chunk[..n])?;
            off += n as u64;
        }
        Ok(())
    }

    /// Flush, and let the kernel look at what it holds now.
    fn flush(&self) -> Res {
        slate_rt::io::ioctl(self.fd, BLKFLSBUF, 0).map(|_| ()).map_err(|e| format!("{}: flush: {e}", self.name))
    }

    /// Flush, and have the kernel read the partition table again.
    fn rescan(&self) -> Res {
        self.flush()?;
        slate_rt::io::ioctl(self.fd, BLKRRPART, 0)
            .map(|_| ())
            .map_err(|e| format!("{}: reading the table again: {e}", self.name))
    }
}

impl Drop for Dev {
    fn drop(&mut self) {
        let _ = slate_rt::io::close(self.fd);
    }
}

fn read_table(dev: &Dev) -> Res<(slate_gpt::Guid, Vec<(u32, Owned)>)> {
    let mut header = alloc::vec![0u8; 512];
    dev.read(512, &mut header)?;
    let h =
        slate_gpt::parse_header(&header).map_err(|_| "The disk has no GPT: give it a new partition table first.")?;
    let len = (h.entry_count as usize * h.entry_size as usize).div_ceil(512) * 512;
    if len > 1 << 20 {
        return Err("The GPT is too large.".into());
    }
    let mut array = alloc::vec![0u8; len];
    dev.read(h.entries_lba * SECTOR, &mut array)?;
    let entries = slate_gpt::parse_entries(&h, &array).map_err(|e| format!("The GPT is damaged ({e:?})."))?;
    let parts = entries
        .map(|e| {
            let name: String = char::decode_utf16(e.name_utf16.iter().copied().take_while(|&c| c != 0))
                .map(|c| c.ok().filter(|c| c.is_ascii() && !c.is_ascii_control()).unwrap_or('?'))
                .collect();
            (
                e.index,
                Owned {
                    kind: e.type_guid,
                    uuid: e.unique_guid,
                    first: e.first_lba,
                    last: e.last_lba,
                    attributes: e.attributes,
                    name,
                },
            )
        })
        .collect();
    Ok((h.disk_guid, parts))
}

fn write_table(dev: &Dev, sectors: u64, guid: slate_gpt::Guid, parts: &[(u32, Owned)]) -> Res {
    let list: Vec<(u32, slate_gpt::Partition<'_>)> = parts
        .iter()
        .map(|(slot, p)| {
            (
                *slot,
                slate_gpt::Partition {
                    type_guid: p.kind,
                    unique_guid: p.uuid,
                    first_lba: p.first,
                    last_lba: p.last,
                    attributes: p.attributes,
                    name: &p.name,
                },
            )
        })
        .collect();
    let gpt = slate_gpt::encode_slots(sectors, guid, &list).map_err(|e| format!("GPT: {e:?}"))?;
    dev.write(0, &gpt.protective_mbr)?;
    dev.write(512, &gpt.primary_header)?;
    dev.write(1024, &gpt.entries)?;
    dev.write(gpt.backup_entries_lba * SECTOR, &gpt.entries)?;
    dev.write(gpt.backup_header_lba * SECTOR, &gpt.backup_header)
}

/// FAT32's writes, at a partition's offsets.
struct Sink<'a>(&'a Dev);

impl slate_fat::Sink for Sink<'_> {
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), slate_fat::Error> {
        self.0.write(offset, data).map_err(|_| slate_fat::Error::TooSmall)
    }
}

/// A new file system on partition `part` (whose first sector on its
/// disk is `start`); what was made.
fn make_fs(part: &str, format: Format, label: &str, start: u64, person: u32) -> Res<String> {
    let dev = Dev::open(part)?;
    let bytes = slate_rt::io::lseek(dev.fd, 0, 2).map_err(|e| format!("{part}: {e}"))?;
    // What was there goes: its signatures (SlateFS keeps a second
    // superblock at 4 KiB, SlateCrypt a header copy at 512 KiB).
    dev.zero(0, MIB.min(bytes))?;
    let made = match format {
        Format::Fat32 => {
            let mut serial = [0u8; 4];
            let _ = slate_rt::process::random(&mut serial);
            slate_fat::write(
                &slate_fat::Volume::new(),
                bytes,
                label,
                u32::from_le_bytes(serial),
                start as u32,
                &mut Sink(&dev),
            )
            .map_err(|e| match e {
                slate_fat::Error::TooSmall => String::from("FAT32 needs at least 33 MiB."),
                e => format!("FAT32: {e:?}"),
            })?;
            format!("FAT32 \"{label}\"")
        }
        Format::SlateFs => {
            dev.flush()?;
            let mut argv: Vec<Vec<u8>> =
                ["slatefs", "mkfs", "-s", "data"].iter().map(|a| a.as_bytes().to_vec()).collect();
            if !label.is_empty() {
                argv.push(b"-L".to_vec());
                argv.push(label.as_bytes().to_vec());
            }
            // Its top folder is the person's who asked: an empty folder of
            // theirs is its contents.
            let empty = format!("/run/slate-disk.{}", slate_rt::process::getpid());
            let owner = person_of(person).ok();
            if let Some((_, uid, gid)) = owner {
                slate_rt::fs::mkdir(empty.as_bytes(), 0o755).map_err(|e| format!("{empty}: {e}"))?;
                argv.extend([b"-d".to_vec(), empty.clone().into_bytes(), b"--owner".to_vec()]);
                argv.push(format!("{uid}:{gid}").into_bytes());
            }
            argv.push(format!("/dev/{part}").into_bytes());
            let r = slate_rt::process::run(b"/bin/slatefs", &argv);
            if owner.is_some() {
                let _ = slate_rt::fs::rmdir(empty.as_bytes());
            }
            match r {
                Ok(0) => format!("SlateFS \"{label}\""),
                _ => return Err(format!("{part}: slatefs mkfs failed")),
            }
        }
        Format::Empty => String::from("left empty"),
    };
    dev.flush()?;
    Ok(made)
}

#[cfg(test)]
mod tests {
    use super::*;
    use slate_sysinfo::block::Part;

    #[test]
    fn words() {
        let c = parse("add sdb 1 100 fat32 Holiday photos").unwrap();
        assert_eq!(
            c,
            Change::Add {
                disk: "sdb".into(),
                start_mib: 1,
                size_mib: 100,
                format: Format::Fat32,
                name: "Holiday photos".into()
            }
        );
        assert_eq!(c.words(), "add sdb 1 100 fat32 Holiday photos");
        assert_eq!(parse("format sdb1 slatefs").unwrap().words(), "format sdb1 slatefs");
        assert_eq!(parse("format sdb1 fat32 MY STICK").unwrap().target(), "sdb1");
        assert!(parse("format sdb1 fat32 much too long label").is_err());
        assert!(parse("format sdb1 fat32 a/b").is_err());
        assert!(parse("table ../sda").is_err());
        assert!(parse("table sda sdb").is_err());
        assert!(parse("add sdb 0 100 fat32 x").is_err());
        assert!(parse("add sdb 1 100 ntfs x").is_err());
        assert!(parse("add sdb 1 100 empty").is_err(), "a name");
        assert_eq!(parse("delete nvme1n1p2").unwrap(), Change::Delete { part: "nvme1n1p2".into() });
        assert!(parse("wipe sda").is_err());
        assert_eq!(
            parse("name sdb2 Photos 2026").unwrap(),
            Change::Name { part: "sdb2".into(), name: "Photos 2026".into() }
        );
        assert!(parse("name sdb2").is_err(), "a name");
        assert_eq!(parse("mount sdb1").unwrap().words(), "mount sdb1");
        assert!(parse("mount sdb1 /etc").is_err());
        assert!(parse("unmount sdb1").unwrap().mounting());
        assert_eq!(parse("poweroff sdb").unwrap(), Change::PowerOff { disk: "sdb".into() });
        assert!(parse("poweroff sdb").unwrap().mounting());
        assert!(parse("poweroff sdb sdc").is_err());
        assert_eq!(mount_name("My Disk/2", "sdb1"), "My Disk2");
        assert_eq!(mount_name("..", "sdb1"), "sdb1");
        assert!(mountable("ext4") && !mountable("vfat"));
        assert_eq!(Format::Fat32.label("Stick"), "STICK");
    }

    #[test]
    fn free_space() {
        // 100 MiB: usable from sector 34 to 204766.
        let s = 100 * ALIGN;
        assert_eq!(free_regions(s, &[]), [(2048, 202752 - 2048)]);
        let parts = [(2048, 20 * ALIGN), (40 * ALIGN, 10 * ALIGN)];
        assert_eq!(free_regions(s, &parts), [(21 * ALIGN, 19 * ALIGN), (50 * ALIGN, 49 * ALIGN)]);
        // Less than a MiB between them is no space; the MiB at the end is.
        assert_eq!(free_regions(s, &[(2048, 2048), (4096 + 100, 196000)]), [(98 * ALIGN, ALIGN)]);
    }

    #[test]
    fn tables_keep_numbers() {
        let path = std::env::temp_dir().join(format!("slate-diskutil-{}", std::process::id()));
        let sectors = 64 * ALIGN;
        std::fs::write(&path, std::vec![0u8; (sectors * SECTOR) as usize]).unwrap();
        let dev = Dev::at(path.to_str().unwrap(), "test").unwrap();
        let part = |first: u64, name: &str| Owned {
            kind: slate_gpt::Guid::BASIC_DATA,
            uuid: slate_gpt::Guid::from_seed([first as u8; 16]),
            first,
            last: first + 10 * ALIGN - 1,
            attributes: 0,
            name: name.into(),
        };
        let guid = slate_gpt::Guid::from_seed([7; 16]);
        write_table(&dev, sectors, guid, &[(0, part(ALIGN, "one")), (2, part(30 * ALIGN, "three"))]).unwrap();
        let (g, parts) = read_table(&dev).unwrap();
        assert_eq!(g, guid);
        let got: Vec<(u32, &str, u64)> = parts.iter().map(|(s, p)| (*s, p.name.as_str(), p.first)).collect();
        assert_eq!(got, [(0, "one", ALIGN), (2, "three", 30 * ALIGN)]);
        // Overlaps are refused.
        assert!(write_table(&dev, sectors, guid, &[(0, part(ALIGN, "a")), (1, part(5 * ALIGN, "b"))]).is_err());
        drop(dev);
        std::fs::remove_file(&path).unwrap();
    }

    fn disk(name: &str, parts: &[&str]) -> Disk {
        Disk {
            name: name.into(),
            sectors: 1 << 20,
            parts: parts.iter().map(|p| Part { name: (*p).into(), ..Part::default() }).collect(),
            ..Disk::default()
        }
    }

    fn mount(src: &str, at: &str) -> Mount {
        Mount { source: src.into(), path: at.into(), fs: "slatefs".into() }
    }

    #[test]
    fn what_is_in_use() {
        let disks = [disk("vda", &["vda1", "vda2"]), disk("vdb", &["vdb1", "vdb2"]), disk("vdc", &[])];
        let mapped = [
            Mapped { name: "dm-0".into(), under: "vda2".into(), holds: None },
            Mapped { name: "dm-1".into(), under: "vdb2".into(), holds: None },
        ];
        let mounts = [mount("/dev/dm-0", "/"), mount("/dev/vdb1", "/run/media/ada/stick")];
        let why = |t: &str| in_use(t, &disks, &mapped, &mounts);
        assert_eq!(why("vda").as_deref(), Some("This is the system's disk: Slate runs from it."));
        assert_eq!(why("vda1").as_deref(), Some("This is the system's disk: Slate runs from it."));
        assert_eq!(why("vdb").as_deref(), Some("vdb1 is in use, at /run/media/ada/stick."));
        assert_eq!(why("vdb1").as_deref(), Some("It is in use, at /run/media/ada/stick."));
        assert_eq!(why("vdb2").as_deref(), Some("It is in use, unlocked as dm-1."));
        assert_eq!(why("vdc"), None);
        assert_eq!(why("vdz").as_deref(), Some("There is no disk vdz."));
        // Powering off: anything on the disk mounted or unlocked.
        assert_eq!(
            busy(&disks[1], &mapped, &mounts).as_deref(),
            Some("vdb1 is in use, at /run/media/ada/stick: unmount it first.")
        );
        assert_eq!(busy(&disks[2], &mapped, &mounts), None);
        let only_unlocked = [mount("/dev/dm-0", "/")];
        assert_eq!(busy(&disks[1], &mapped, &only_unlocked).as_deref(), Some("vdb2 is in use, unlocked as dm-1."));
    }
}
