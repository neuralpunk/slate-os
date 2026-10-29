// SPDX-License-Identifier: MIT OR Apache-2.0

//! Block devices: disks registered by drivers, their GPT partitions, and
//! the `/dev` files that expose them.
//!
//! Devices count in 512-byte sectors. Disks are named and numbered as on
//! Linux (devices.txt in the kernel documentation; `ls -l /dev` on a Linux
//! host): virtio disks `vda`... (major 253), SATA and USB disks `sda`...
//! (major 8), NVMe namespaces `nvme0n1`... (major 259), each disk taking 16
//! minors (its partitions are minors 1-15 after the disk's). A partition's
//! name adds `p` when the disk's name ends in a digit (`nvme0n1p2`).
//! Unlocked encrypted partitions are `dm-0`... (major 254, one minor
//! each; ADR 0036), named as Linux names its device-mapper devices.

pub mod cache;
pub mod crypt;
pub mod elevator;
pub mod stats;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use slate_gpt::Guid;

use crate::abi::linux::errno::{EBUSY, EFAULT, EINVAL, EIO, ENOTTY, ENXIO, EOPNOTSUPP, EPERM, EROFS};
use crate::arch::uaccess::write_user;
use crate::fs::vfs::{Result, major, makedev, minor};
use crate::fs::{File, SEEK_CUR, SEEK_END, SEEK_SET};
use crate::sched::wait::Mutex;
use crate::sync::IrqSpinLock;
use crate::{log_info, log_warn};

pub const SECTOR: usize = 512;
pub const VIRTBLK_MAJOR: u32 = 253;
pub const SCSI_DISK_MAJOR: u32 = 8;
pub const BLKEXT_MAJOR: u32 = 259;
/// Mapped devices (devices.txt leaves 240-254 to local use; Linux gives
/// device-mapper a dynamic major, often this one).
pub const MAPPED_MAJOR: u32 = 254;
const MINORS_PER_DISK: u32 = 16;

/// Which naming and numbering scheme a disk follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Virtio,
    /// SATA (AHCI) and USB mass storage.
    Scsi,
    Nvme,
}

impl Family {
    fn major(self) -> u32 {
        match self {
            Family::Virtio => VIRTBLK_MAJOR,
            Family::Scsi => SCSI_DISK_MAJOR,
            Family::Nvme => BLKEXT_MAJOR,
        }
    }
}

/// A failed transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoError;

pub trait BlockDevice: Send + Sync {
    fn name(&self) -> &str;
    /// Size in 512-byte sectors.
    fn sectors(&self) -> u64;
    fn read_only(&self) -> bool;
    /// Read `buf.len()` bytes (a multiple of 512) from `sector`.
    fn read(&self, sector: u64, buf: &mut [u8]) -> core::result::Result<(), IoError>;
    /// [`BlockDevice::read`] from the device itself, leaving nothing in a
    /// cache on the way (O_DIRECT, ADR 0162).
    fn read_uncached(&self, sector: u64, buf: &mut [u8]) -> core::result::Result<(), IoError> {
        self.read(sector, buf)
    }
    /// Write `buf.len()` bytes (a multiple of 512) at `sector`.
    fn write(&self, sector: u64, buf: &[u8]) -> core::result::Result<(), IoError>;
    /// Make completed writes durable.
    fn flush(&self) -> core::result::Result<(), IoError>;
    /// The device's model name, as /sys/block/<disk>/device/model shows it.
    fn model(&self) -> String {
        String::new()
    }
    /// Removable media (a USB stick).
    fn removable(&self) -> bool {
        false
    }
    /// Whether the device takes discards (TRIM, ADR 0039).
    fn can_discard(&self) -> bool {
        false
    }
    /// The machine is about to lose power: get ready (after a flush). NVMe
    /// controllers get the shutdown notification, ATA disks park.
    fn shutdown(&self) {}
    /// Tell the device that `count` sectors from `sector` hold nothing any
    /// more (TRIM, deallocation); their contents become undefined.
    fn discard(&self, _sector: u64, _count: u64) -> core::result::Result<(), IoError> {
        Err(IoError)
    }
    /// How many commands the device runs at once: 1 gets the I/O
    /// scheduler (`elevator`), more orders its own queue.
    fn queue_depth(&self) -> usize {
        1
    }
    /// The device was unplugged: everything after this fails.
    fn detach(&self) {}
    /// Get the device ready to be unplugged and let it go: its cache
    /// written, its medium stopped, and (a USB disk) the device removed as
    /// if unplugged, its port disabled. `None` when it can't be.
    fn power_off(&self) -> Option<core::result::Result<(), IoError>> {
        None
    }
}

/// A GPT partition: a window onto its disk.
pub struct Partition {
    name: String,
    disk: Arc<dyn BlockDevice>,
    first: u64,
    count: u64,
}

impl BlockDevice for Partition {
    fn name(&self) -> &str {
        &self.name
    }
    fn sectors(&self) -> u64 {
        self.count
    }
    fn read_only(&self) -> bool {
        self.disk.read_only()
    }
    fn read(&self, sector: u64, buf: &mut [u8]) -> core::result::Result<(), IoError> {
        if sector + (buf.len() / SECTOR) as u64 > self.count {
            return Err(IoError);
        }
        self.disk.read(self.first + sector, buf)
    }
    fn read_uncached(&self, sector: u64, buf: &mut [u8]) -> core::result::Result<(), IoError> {
        if sector + (buf.len() / SECTOR) as u64 > self.count {
            return Err(IoError);
        }
        self.disk.read_uncached(self.first + sector, buf)
    }
    fn write(&self, sector: u64, buf: &[u8]) -> core::result::Result<(), IoError> {
        if sector + (buf.len() / SECTOR) as u64 > self.count {
            return Err(IoError);
        }
        self.disk.write(self.first + sector, buf)
    }
    fn flush(&self) -> core::result::Result<(), IoError> {
        self.disk.flush()
    }
    fn removable(&self) -> bool {
        self.disk.removable()
    }
    fn can_discard(&self) -> bool {
        self.disk.can_discard()
    }
    fn discard(&self, sector: u64, count: u64) -> core::result::Result<(), IoError> {
        if sector.checked_add(count).is_none_or(|end| end > self.count) {
            return Err(IoError);
        }
        self.disk.discard(self.first + sector, count)
    }
}

struct Entry {
    rdev: u64,
    dev: Arc<dyn BlockDevice>,
    /// The whole disk's device number (its own for a disk).
    disk: u64,
    /// First sector on the disk (0 for a disk).
    start: u64,
    /// GPT partition name, for `root=PARTLABEL=...`.
    label: Option<String>,
    /// GPT unique partition GUID, for `root=PARTUUID=...`.
    uuid: Option<Guid>,
    /// The partition's type: a GPT type GUID, or an MBR type byte
    /// (`0x0c`).
    ptype: Option<String>,
    /// For a disk: its partition table, `gpt` or `mbr` (ADR 0112).
    table: Option<&'static str>,
    /// What the device holds (ADR 0112), from its first bytes.
    holds: Option<slate_fsprobe::Found>,
    /// Its I/O, for /proc/diskstats (disks and mapped devices).
    stats: Option<Arc<stats::Stats>>,
}

static DEVICES: IrqSpinLock<Vec<Entry>> = IrqSpinLock::new(Vec::new());

/// What /proc/partitions and /sys/block show about one device.
pub struct Info {
    pub name: String,
    pub rdev: u64,
    pub sectors: u64,
    /// The disk's name, for a partition.
    pub parent: Option<String>,
    pub start: u64,
    pub read_only: bool,
    pub removable: bool,
    pub model: String,
    pub ptype: Option<String>,
    pub table: Option<&'static str>,
    pub holds: Option<slate_fsprobe::Found>,
}

fn info(e: &Entry, all: &[Entry]) -> Info {
    let parent = (e.disk != e.rdev).then(|| all.iter().find(|d| d.rdev == e.disk).map(|d| String::from(d.dev.name())));
    Info {
        name: String::from(e.dev.name()),
        rdev: e.rdev,
        sectors: e.dev.sectors(),
        parent: parent.flatten(),
        start: e.start,
        read_only: e.dev.read_only(),
        removable: e.dev.removable(),
        model: e.dev.model(),
        ptype: e.ptype.clone(),
        table: e.table,
        holds: e.holds.clone(),
    }
}

/// /proc/diskstats: disks and mapped devices, in registration order.
pub fn diskstats(s: &mut String) {
    for e in DEVICES.lock().iter() {
        if let Some(st) = &e.stats {
            s.push_str(&st.line(major(e.rdev), minor(e.rdev), e.dev.name()));
        }
    }
}

/// What `dev` holds, from its first bytes.
fn probe(dev: &dyn BlockDevice) -> Option<slate_fsprobe::Found> {
    let sectors = (slate_fsprobe::PROBE_BYTES / SECTOR).min(dev.sectors() as usize);
    if sectors == 0 {
        return None;
    }
    let mut head = vec![0u8; sectors * SECTOR];
    dev.read(0, &mut head).ok()?;
    slate_fsprobe::probe(&head)
}

/// Look at what device `rdev` holds again (after a program wrote a file
/// system on it and flushed it, BLKFLSBUF), and show it in /sys/block.
pub fn reprobe(rdev: u64) {
    let Some(dev) = by_rdev(rdev) else { return };
    let holds = probe(&*dev);
    let changed = {
        let mut devs = DEVICES.lock();
        let Some(e) = devs.iter_mut().find(|e| e.rdev == rdev) else { return };
        let changed = e.holds != holds;
        e.holds = holds;
        changed
    };
    if changed {
        crate::fs::block_changed(dev.name());
    }
}

/// Every registered disk and partition, in registration order.
pub fn list() -> Vec<Info> {
    let devs = DEVICES.lock();
    devs.iter().map(|e| info(e, &devs)).collect()
}

/// Number of whole disks of `family` registered so far.
/// The name the next disk of `family` gets: `vda`, `sdb`, `sdaa`...,
/// the first no disk has (one unplugged frees its own, as on Linux).
/// (NVMe drivers name their namespaces themselves.)
pub fn next_name(family: Family) -> String {
    name_for(family, &DEVICES.lock())
}

fn name_for(family: Family, devs: &[Entry]) -> String {
    (0..1024)
        .map(|n| letters_name(family, n))
        .find(|name| !devs.iter().any(|e| e.dev.name() == name))
        .unwrap_or_default()
}

fn letters_name(family: Family, n: usize) -> String {
    let letters = if n < 26 {
        format!("{}", (b'a' + n as u8) as char)
    } else {
        format!("{}{}", (b'a' + (n / 26 - 1) as u8) as char, (b'a' + (n % 26) as u8) as char)
    };
    match family {
        Family::Virtio => format!("vd{letters}"),
        Family::Scsi | Family::Nvme => format!("sd{letters}"),
    }
}

/// Register a disk and its partitions: behind the I/O scheduler if it runs
/// one command at a time, and behind the block cache (ADR 0080).
pub fn register_disk(dev: Arc<dyn BlockDevice>, family: Family) {
    register_named(family, |_| dev);
}

/// Register a disk named with the first free name of its family, given
/// to `make` in the same step as the disk is added, so disks found at
/// once on two controllers never get the same name. It takes the lowest
/// device number of its family not in use.
pub fn register_named(family: Family, make: impl FnOnce(String) -> Arc<dyn BlockDevice>) {
    let (dev, rdev) = {
        let mut devs = DEVICES.lock();
        let dev = make(name_for(family, &devs));
        let dev: Arc<dyn BlockDevice> =
            if dev.queue_depth() <= 1 { Arc::new(elevator::Elevator::new(dev)) } else { dev };
        // Counted below the cache: what the device itself does (ADR 0112).
        let counted = stats::Counted::new(dev);
        let stats = counted.stats.clone();
        let dev: Arc<dyn BlockDevice> = Arc::new(cache::Cached::new(Arc::new(counted)));
        let rdev = (0..)
            .map(|i: u32| makedev(family.major(), i * MINORS_PER_DISK))
            .find(|&r| !devs.iter().any(|e| e.rdev == r))
            .unwrap_or(0);
        devs.push(Entry {
            rdev,
            dev: dev.clone(),
            disk: rdev,
            start: 0,
            label: None,
            uuid: None,
            ptype: None,
            table: None,
            holds: None,
            stats: Some(stats),
        });
        (dev, rdev)
    };
    let (table, found) = partitions(&dev);
    let holds = if table.is_none() { probe(&*dev) } else { None };
    if let Some(e) = DEVICES.lock().iter_mut().find(|e| e.rdev == rdev) {
        e.table = table;
        e.holds = holds;
    }
    crate::fs::block_added(dev.name(), rdev);
    add_partitions(&dev, rdev, found);
}

/// Take disk `name` and its partitions away (the device was unplugged or
/// is being ejected): their /dev and /sys entries go, and I/O through
/// files still open on them, or file systems still mounted, fails.
/// Returns whether there was such a disk.
pub fn unregister_disk(name: &str) -> bool {
    let gone: Vec<Entry> = {
        let mut devs = DEVICES.lock();
        let Some(disk) = devs.iter().find(|e| e.rdev == e.disk && e.dev.name() == name).map(|e| e.disk) else {
            return false;
        };
        let (gone, kept) = devs.drain(..).partition(|e| e.disk == disk);
        *devs = kept;
        gone
    };
    // Partitions first, then the disk.
    for e in gone.iter().rev() {
        e.dev.detach();
        crate::fs::block_removed(e.dev.name());
    }
    log_info!("/dev/{name}: removed");
    true
}

/// Before power-off or reboot: flush every device's write cache (mapped
/// devices first, as they write to disks), then let the disks get ready
/// (M19, ADR 0044). Every disk is flushed before any is shut down: the
/// namespaces of one NVMe controller share it.
pub fn shutdown_all() {
    let devs: Vec<(u64, u64, Arc<dyn BlockDevice>)> =
        DEVICES.lock().iter().map(|e| (e.rdev, e.disk, e.dev.clone())).collect();
    let mapped = |rdev: u64| crate::fs::vfs::major(rdev) == MAPPED_MAJOR;
    for (_, _, d) in devs.iter().filter(|(rdev, _, _)| mapped(*rdev)) {
        if d.flush().is_err() {
            crate::log_warn!("{}: cache flush at power-off failed", d.name());
        }
    }
    let disks = || devs.iter().filter(|(rdev, disk, _)| rdev == disk && !mapped(*rdev));
    for (_, _, d) in disks() {
        if d.flush().is_err() {
            crate::log_warn!("{}: cache flush at power-off failed", d.name());
        }
    }
    for (_, _, d) in disks() {
        d.shutdown();
    }
}

/// The lowest free mapped device number (`dm-N`): numbers are reused
/// after a device is closed.
fn free_mapped_number(devs: &[Entry]) -> u32 {
    (0..).find(|n| !devs.iter().any(|e| e.rdev == makedev(MAPPED_MAJOR, *n))).unwrap_or(0)
}

/// The name the next mapped device gets: `dm-0`, `dm-1`...
pub fn next_mapped_name() -> String {
    format!("dm-{}", free_mapped_number(&DEVICES.lock()))
}

/// Register a mapped device (an unlocked encrypted partition); no
/// partition table is read from it. Returns its device number.
pub fn register_mapped(dev: Arc<dyn BlockDevice>, stats: Arc<stats::Stats>) -> u64 {
    let holds = probe(&*dev);
    let rdev = {
        let mut devs = DEVICES.lock();
        let rdev = makedev(MAPPED_MAJOR, free_mapped_number(&devs));
        devs.push(Entry {
            rdev,
            dev: dev.clone(),
            disk: rdev,
            start: 0,
            label: None,
            uuid: None,
            ptype: None,
            table: None,
            holds,
            stats: Some(stats),
        });
        rdev
    };
    crate::fs::block_added(dev.name(), rdev);
    rdev
}

/// Remove mapped device `rdev` unless something still uses it (`users`
/// references besides the registry's own); EBUSY then.
pub fn unregister_mapped(rdev: u64, users: usize) -> Result<()> {
    let name = {
        let mut devs = DEVICES.lock();
        let i = devs.iter().position(|e| e.rdev == rdev && major(rdev) == MAPPED_MAJOR).ok_or(ENXIO)?;
        if Arc::strong_count(&devs[i].dev) > users + 1 {
            return Err(EBUSY);
        }
        String::from(devs.remove(i).dev.name())
    };
    crate::fs::block_removed(&name);
    Ok(())
}

/// Discard `len` bytes at byte `start` of `dev` (the native call
/// `discard`, ADR 0039): whole sectors, inside the device.
pub fn discard_bytes(dev: &Arc<dyn BlockDevice>, start: u64, len: u64) -> Result<()> {
    let bytes = dev.sectors() * SECTOR as u64;
    if start % SECTOR as u64 != 0 || len % SECTOR as u64 != 0 || start.checked_add(len).is_none_or(|e| e > bytes) {
        return Err(EINVAL);
    }
    if dev.read_only() {
        return Err(EROFS);
    }
    if !dev.can_discard() {
        return Err(EOPNOTSUPP);
    }
    if len > 0 {
        dev.discard(start / SECTOR as u64, len / SECTOR as u64).map_err(|_| EIO)?;
    }
    Ok(())
}

/// The device an open block device file reads and writes.
pub fn block_device_of(f: &dyn File) -> Option<Arc<dyn BlockDevice>> {
    f.as_any().and_then(|a| a.downcast_ref::<BlockFile>()).map(|b| b.dev.clone())
}

fn partition_name(disk: &str, n: u32) -> String {
    if disk.ends_with(|c: char| c.is_ascii_digit()) { format!("{disk}p{n}") } else { format!("{disk}{n}") }
}

/// A partition found in a table: its number, first sector, length,
/// the GPT's name and unique GUID (an MBR has neither), and its type.
struct Found {
    number: u32,
    first: u64,
    count: u64,
    label: Option<String>,
    uuid: Option<Guid>,
    ptype: String,
}

/// The partition table of `dev` (`gpt` or `mbr`) and its partitions: its
/// GPT's, else its MBR's (primary partitions 1 to 4, logical ones from 5;
/// the extended container itself is not a device).
fn partitions(dev: &Arc<dyn BlockDevice>) -> (Option<&'static str>, Vec<Found>) {
    let gpt: Vec<Found> = read_gpt(dev)
        .into_iter()
        .map(|p| {
            let label = String::from_utf16_lossy(&p.name_utf16);
            Found {
                number: p.index + 1,
                first: p.first_lba,
                count: p.last_lba + 1 - p.first_lba,
                label: Some(String::from(label.trim_end_matches('\0'))),
                uuid: Some(p.unique_guid),
                ptype: guid_text(p.type_guid),
            }
        })
        .collect();
    if !gpt.is_empty() {
        return (Some("gpt"), gpt);
    }
    let mut header = vec![0u8; SECTOR];
    // A GPT without partitions (a disk just given a new table).
    if dev.sectors() >= 3 && dev.read(1, &mut header).is_ok() && slate_gpt::parse_header(&header).is_ok() {
        return (Some("gpt"), Vec::new());
    }
    let mut first = vec![0u8; SECTOR];
    if dev.sectors() == 0 || dev.read(0, &mut first).is_err() {
        return (None, Vec::new());
    }
    let slate_mbr::Table::Mbr { primary, .. } = slate_mbr::parse(&first, dev.sectors()) else {
        return (None, Vec::new());
    };
    let found = |p: &slate_mbr::Partition| Found {
        number: p.number,
        first: p.start,
        count: p.sectors,
        label: None,
        uuid: None,
        ptype: format!("0x{:02x}", p.kind),
    };
    let mut out = Vec::new();
    for p in &primary {
        if slate_mbr::extended(p) {
            let read = |n: u64| {
                let mut b = [0u8; SECTOR];
                dev.read(n, &mut b).ok().map(|()| b)
            };
            out.extend(slate_mbr::logical(p, read).iter().map(found));
        } else {
            out.push(found(p));
        }
    }
    (Some("mbr"), out)
}

fn add_partitions(dev: &Arc<dyn BlockDevice>, disk: u64, found: Vec<Found>) {
    for p in found {
        let n = p.number;
        if n >= MINORS_PER_DISK {
            continue;
        }
        let name = partition_name(dev.name(), n);
        match &p.label {
            Some(label) => log_info!("/dev/{name}: {} MiB, \"{label}\"", p.count / 2048),
            None => log_info!("/dev/{name}: {} MiB (MBR)", p.count / 2048),
        }
        let part = Partition { name, disk: dev.clone(), first: p.first, count: p.count };
        let holds = probe(&part);
        let rdev = makedev(major(disk), minor(disk) + n);
        let name = part.name.clone();
        DEVICES.lock().push(Entry {
            rdev,
            dev: Arc::new(part),
            disk,
            start: p.first,
            label: p.label,
            uuid: p.uuid,
            ptype: Some(p.ptype),
            table: None,
            holds,
            stats: None,
        });
        crate::fs::block_added(&name, rdev);
    }
}

/// Read a disk's partition table again (BLKRRPART). Refused while one of
/// its partitions is open elsewhere or mounted.
pub fn rescan(disk: u64) -> Result<()> {
    let dev = {
        let devs = DEVICES.lock();
        let e = devs.iter().find(|e| e.rdev == disk && e.disk == disk).ok_or(EINVAL)?;
        // A partition in use holds an extra reference: the registry has one,
        // and /dev's open files or a mounted file system hold the others.
        if devs.iter().any(|p| p.disk == disk && p.rdev != disk && Arc::strong_count(&p.dev) > 1) {
            return Err(EBUSY);
        }
        e.dev.clone()
    };
    let removed: Vec<String> = {
        let mut devs = DEVICES.lock();
        let names =
            devs.iter().filter(|p| p.disk == disk && p.rdev != disk).map(|p| String::from(p.dev.name())).collect();
        devs.retain(|p| p.disk != disk || p.rdev == disk);
        names
    };
    for name in &removed {
        crate::fs::block_removed(name);
    }
    // The disk's own table, and what it holds without one, may have
    // changed too (ADR 0112).
    let (table, found) = partitions(&dev);
    let holds = if table.is_none() { probe(&*dev) } else { None };
    if let Some(e) = DEVICES.lock().iter_mut().find(|e| e.rdev == disk) {
        e.table = table;
        e.holds = holds;
    }
    crate::fs::block_changed(dev.name());
    add_partitions(&dev, disk, found);
    Ok(())
}

/// The partitions in `dev`'s GPT (primary header only).
fn read_gpt(dev: &Arc<dyn BlockDevice>) -> Vec<slate_gpt::Entry> {
    let mut header = vec![0u8; SECTOR];
    if dev.sectors() < 3 || dev.read(1, &mut header).is_err() {
        return Vec::new();
    }
    let Ok(h) = slate_gpt::parse_header(&header) else { return Vec::new() };
    let len = (h.entry_count as usize * h.entry_size as usize).div_ceil(SECTOR) * SECTOR;
    if len > 1 << 20 {
        return Vec::new();
    }
    let mut array = vec![0u8; len];
    if dev.read(h.entries_lba, &mut array).is_err() {
        return Vec::new();
    }
    match slate_gpt::parse_entries(&h, &array) {
        Ok(entries) => entries.filter(|e| e.last_lba >= e.first_lba && e.last_lba < dev.sectors()).collect(),
        Err(e) => {
            log_warn!("{}: bad GPT entries: {e:?}", dev.name());
            Vec::new()
        }
    }
}

/// (name, device number) of every block device, for /dev.
pub fn nodes() -> Vec<(String, u64)> {
    DEVICES.lock().iter().map(|e| (String::from(e.dev.name()), e.rdev)).collect()
}

/// A block device (and its number) by `/dev` name, like `vda2`.
pub fn find(name: &str) -> Option<(Arc<dyn BlockDevice>, u64)> {
    DEVICES.lock().iter().find(|e| e.dev.name() == name).map(|e| (e.dev.clone(), e.rdev))
}

/// Partition `name`'s GPT partition name.
pub fn label_of(name: &str) -> Option<String> {
    DEVICES.lock().iter().find(|e| e.dev.name() == name).and_then(|e| e.label.clone())
}

/// A partition by GPT partition name.
pub fn find_label(label: &str) -> Option<(Arc<dyn BlockDevice>, u64)> {
    DEVICES.lock().iter().find(|e| e.label.as_deref() == Some(label)).map(|e| (e.dev.clone(), e.rdev))
}

/// A partition by GPT unique partition GUID, written as Linux's PARTUUID
/// (`0fc63daf-8483-4772-8e79-3d69d8477de4`, any case).
pub fn find_uuid(text: &str) -> Option<(Arc<dyn BlockDevice>, u64)> {
    DEVICES
        .lock()
        .iter()
        .find(|e| e.uuid.is_some_and(|u| guid_text(u).eq_ignore_ascii_case(text)))
        .map(|e| (e.dev.clone(), e.rdev))
}

/// A GUID in the usual 8-4-4-4-12 form.
pub fn guid_text(g: Guid) -> String {
    let d = g.data4;
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g.data1, g.data2, g.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
    )
}

pub fn by_rdev(rdev: u64) -> Option<Arc<dyn BlockDevice>> {
    DEVICES.lock().iter().find(|e| e.rdev == rdev).map(|e| e.dev.clone())
}

/// The devices the root is on (ADR 0090): whole disks (and so every
/// partition of them), and mappings over them.
static PROTECTED: IrqSpinLock<Vec<u64>> = IrqSpinLock::new(Vec::new());

/// Keep raw writes off `rdev` and, for a partition, its whole disk: the
/// root (and the EFI System Partition beside it) is there.
pub fn protect(rdev: u64) {
    let disk = DEVICES.lock().iter().find(|e| e.rdev == rdev).map_or(rdev, |e| e.disk);
    let mut p = PROTECTED.lock();
    for r in [rdev, disk] {
        if !p.contains(&r) {
            p.push(r);
        }
    }
}

/// Whether raw writes to `rdev` are kept for the system grant.
pub fn is_protected(rdev: u64) -> bool {
    let disk = DEVICES.lock().iter().find(|e| e.rdev == rdev).map_or(rdev, |e| e.disk);
    let p = PROTECTED.lock();
    p.contains(&rdev) || p.contains(&disk)
}

/// The encrypted root partition and the length of its header area, in
/// bytes (ADR 0090): the key slots there change with users' passwords
/// (ADR 0058), and hold no part of the image.
static KEY_AREA: IrqSpinLock<Option<(u64, u64)>> = IrqSpinLock::new(None);

/// Let the programs that keep the key slots (signed KEYSLOTS, run as root:
/// ADR 0130) write the first `bytes` of `rdev`, the encrypted root's header
/// area, without the system grant.
pub fn open_key_area(rdev: u64, bytes: u64) {
    *KEY_AREA.lock() = Some((rdev, bytes));
}

/// Open block device `rdev` as a file. Writing the disk the root is on
/// needs the system grant (ADR 0090), but for the key slots.
pub fn open(rdev: u64, flags: u32) -> Result<Arc<dyn File>> {
    if ![VIRTBLK_MAJOR, SCSI_DISK_MAJOR, BLKEXT_MAJOR, MAPPED_MAJOR].contains(&major(rdev)) {
        return Err(ENXIO);
    }
    let write = flags & crate::fs::O_ACCMODE != crate::fs::O_RDONLY;
    let mut limit = None;
    if write && is_protected(rdev) && !crate::proc::domain::may_write_image() {
        match *KEY_AREA.lock() {
            Some((dev, bytes)) if dev == rdev && crate::proc::domain::may_write_key_slots() => limit = Some(bytes),
            _ => return Err(EPERM),
        }
    }
    let dev = by_rdev(rdev).ok_or(ENXIO)?;
    let flags =
        AtomicU32::new(flags & !(crate::fs::O_CREAT | crate::fs::O_EXCL | crate::fs::O_TRUNC | crate::fs::O_CLOEXEC));
    Ok(Arc::new(BlockFile { dev, rdev, offset: Mutex::new(0), limit, flags }))
}

/// Byte-granular access to a block device, through whole-sector
/// transfers; `direct` reads past the block cache (O_DIRECT).
fn read_bytes(dev: &dyn BlockDevice, offset: u64, buf: &mut [u8], direct: bool) -> Result<usize> {
    let size = dev.sectors() * SECTOR as u64;
    if offset >= size {
        return Ok(0);
    }
    let len = buf.len().min((size - offset) as usize);
    let mut done = 0;
    let mut bounce = vec![0u8; 64 * 1024];
    while done < len {
        let pos = offset + done as u64;
        let first = pos / SECTOR as u64;
        let skip = (pos % SECTOR as u64) as usize;
        let want = (len - done).min(bounce.len() - skip);
        let span = (skip + want).div_ceil(SECTOR) * SECTOR;
        let r =
            if direct { dev.read_uncached(first, &mut bounce[..span]) } else { dev.read(first, &mut bounce[..span]) };
        r.map_err(|_| EIO)?;
        buf[done..done + want].copy_from_slice(&bounce[skip..skip + want]);
        done += want;
    }
    Ok(len)
}

pub fn write_bytes(dev: &dyn BlockDevice, offset: u64, buf: &[u8]) -> Result<usize> {
    if dev.read_only() {
        return Err(EROFS);
    }
    let size = dev.sectors() * SECTOR as u64;
    if offset >= size {
        return Err(crate::abi::linux::errno::ENOSPC);
    }
    let len = buf.len().min((size - offset) as usize);
    let mut done = 0;
    let mut bounce = vec![0u8; 64 * 1024];
    while done < len {
        let pos = offset + done as u64;
        let first = pos / SECTOR as u64;
        let skip = (pos % SECTOR as u64) as usize;
        let want = (len - done).min(bounce.len() - skip);
        let span = (skip + want).div_ceil(SECTOR) * SECTOR;
        // Partial sectors at either end: read them first.
        if skip != 0 || want % SECTOR != 0 {
            if skip != 0 {
                dev.read(first, &mut bounce[..SECTOR]).map_err(|_| EIO)?;
            }
            if (skip + want) % SECTOR != 0 {
                let last = span - SECTOR;
                dev.read(first + (last / SECTOR) as u64, &mut bounce[last..span]).map_err(|_| EIO)?;
            }
        }
        bounce[skip..skip + want].copy_from_slice(&buf[done..done + want]);
        dev.write(first, &bounce[..span]).map_err(|_| EIO)?;
        done += want;
    }
    Ok(len)
}

struct BlockFile {
    dev: Arc<dyn BlockDevice>,
    rdev: u64,
    offset: Mutex<u64>,
    /// Writes must end by this byte (the key area, see `open`).
    limit: Option<u64>,
    /// The access mode and status flags (F_GETFL, F_SETFL).
    flags: AtomicU32,
}

impl BlockFile {
    fn may_write(&self, offset: u64, len: usize) -> Result<()> {
        match self.limit {
            Some(end) if offset.checked_add(len as u64).is_none_or(|e| e > end) => Err(EPERM),
            _ => Ok(()),
        }
    }

    fn direct(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & crate::fs::O_DIRECT != 0
    }

    /// O_DIRECT's offsets are whole sectors (open(2): EINVAL).
    fn aligned(&self, offset: u64) -> Result<()> {
        if self.direct() && offset % SECTOR as u64 != 0 { Err(EINVAL) } else { Ok(()) }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        // At or past the end there is nothing to read, aligned or not.
        if offset < self.dev.sectors() * SECTOR as u64 {
            self.aligned(offset)?;
        }
        read_bytes(&*self.dev, offset, buf, self.direct())
    }

    /// A write; with O_DIRECT it is on the disk when this returns.
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        self.aligned(offset)?;
        self.may_write(offset, buf.len())?;
        let n = write_bytes(&*self.dev, offset, buf)?;
        if self.direct() {
            self.dev.flush().map_err(|_| EIO)?;
        }
        Ok(n)
    }
}

// Block device ioctls (musl `sys/mount.h`, ADR 0009).
const BLKRRPART: u32 = 0x125F;
const BLKGETSIZE: u32 = 0x1260;
const BLKFLSBUF: u32 = 0x1261;
const BLKSSZGET: u32 = 0x1268;
const BLKBSZGET: u32 = 0x8008_1270;
const BLKGETSIZE64: u32 = 0x8008_1272;
/// Eject the medium (ioctl_cdrom(2), `linux/cdrom.h`); what eject(1)
/// asks first. For a removable disk Slate also lets the device go, as
/// "power off" does on other desktops (ADR 0108's second addendum).
const CDROMEJECT: u32 = 0x5309;

impl File for BlockFile {
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
    fn fills_reads(&self) -> bool {
        true
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut off = self.offset.lock();
        let n = self.read_at(*off, buf)?;
        *off += n as u64;
        Ok(n)
    }
    fn write(&self, buf: &[u8]) -> Result<usize> {
        let mut off = self.offset.lock();
        let n = self.write_at(*off, buf)?;
        *off += n as u64;
        Ok(n)
    }
    fn pread(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.read_at(offset, buf)
    }
    fn pwrite(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        self.write_at(offset, buf)
    }
    fn status_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }
    fn set_status_flags(&self, flags: u32) {
        let old = self.flags.load(Ordering::Relaxed);
        self.flags.store((old & !crate::fs::SETFL_MASK) | (flags & crate::fs::SETFL_MASK), Ordering::Relaxed);
    }
    fn direct_align(&self) -> Option<u64> {
        self.direct().then_some(SECTOR as u64)
    }
    fn seek(&self, offset: i64, whence: u32) -> Result<u64> {
        let mut off = self.offset.lock();
        let base = match whence {
            SEEK_SET => 0,
            SEEK_CUR => *off as i64,
            SEEK_END => (self.dev.sectors() * SECTOR as u64) as i64,
            _ => return Err(EINVAL),
        };
        let new = base.checked_add(offset).filter(|&n| n >= 0).ok_or(EINVAL)?;
        *off = new as u64;
        Ok(*off)
    }
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64> {
        let bytes = self.dev.sectors() * SECTOR as u64;
        match cmd {
            BLKGETSIZE64 => write_user(arg, &bytes).map_err(|_| EFAULT)?,
            BLKGETSIZE => write_user(arg, &self.dev.sectors()).map_err(|_| EFAULT)?,
            BLKSSZGET => write_user(arg, &(SECTOR as i32)).map_err(|_| EFAULT)?,
            BLKBSZGET => write_user(arg, &4096u64).map_err(|_| EFAULT)?,
            BLKFLSBUF => {
                self.dev.flush().map_err(|_| EIO)?;
                // What it holds now shows in /sys/block (ADR 0112).
                reprobe(self.rdev);
            }
            BLKRRPART => {
                // The open file's own reference is not a user of a partition.
                let dev = self.rdev;
                rescan(dev)?
            }
            CDROMEJECT => match self.dev.power_off() {
                Some(r) => r.map_err(|_| EIO)?,
                None => return Err(ENOTTY),
            },
            _ => return Err(ENOTTY),
        }
        Ok(0)
    }
}
