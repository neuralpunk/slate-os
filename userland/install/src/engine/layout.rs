// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a disk holds, and where SlateOS goes beside it (ADR 0116).
//!
//! [`scan`] reads a disk's partition table and looks at each partition:
//! what file system it holds ([`slate_fsprobe`]) and, for an EFI System
//! Partition, its free space and the other systems' loaders on it. The
//! free spaces between partitions are on whole MiB. [`DiskMap::without`]
//! is manual partitioning's deleting; [`plan_beside`] puts SlateOS's root
//! (and its own EFI System Partition, when it cannot share one) in a free
//! space, keeping every other partition where and as it is.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_esp::Other;
use slate_gpt::Guid;

use super::{Device, ESP_BYTES, MIB, Plan, ROOT_LABEL, Result, SECTOR, err, guid_text, part_region};

/// Partitions start and end on whole MiB.
pub const ALIGN: u64 = MIB / SECTOR;
/// The smallest root SlateOS is put in beside another system.
pub const MIN_ROOT: u64 = 2 << 30;
/// What SlateOS needs free on an EFI System Partition it shares: its
/// loader twice, and the kernels and unlock archives of the systems on its
/// menu (ADR 0086).
pub const ESP_ROOM: u64 = 64 * MIB;

/// A disk's partition table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Table {
    /// None at all: a new disk.
    Empty,
    Gpt(Guid),
    /// An MBR (DOS) table: SlateOS goes only on GPT disks beside others.
    Mbr,
    /// A GPT that cannot be read (its checksums are wrong).
    Damaged,
}

/// What an EFI System Partition holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EspInfo {
    pub free: u64,
    /// SlateOS's menu or kernels are on it already (another SlateOS).
    pub slate: bool,
    /// Other systems' loaders on it: (title, path).
    pub loaders: Vec<(String, String)>,
}

/// A partition, as found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    /// Its number (`sda3` is 3): its slot in the GPT plus one.
    pub number: u32,
    pub type_guid: Guid,
    pub guid: Guid,
    /// First and last sector.
    pub first: u64,
    pub last: u64,
    pub attributes: u64,
    /// The GPT's name for it.
    pub name: String,
    pub holds: Option<slate_fsprobe::Found>,
    /// For an EFI System Partition that can be read, what is on it.
    pub esp: Option<EspInfo>,
}

/// Microsoft's reserved partition (UEFI 2.10 doesn't list it; its GUID is
/// the one Windows' documentation gives).
const MICROSOFT_RESERVED: &str = "e3c9e316-0b5c-4db8-817d-f92df00215ae";
/// Windows' recovery partition (the same documentation).
const WINDOWS_RECOVERY: &str = "de94bba4-06d1-4d40-a16a-bfd50179d6ac";

impl Part {
    pub fn bytes(&self) -> u64 {
        (self.last + 1 - self.first) * SECTOR
    }

    pub fn is_esp(&self) -> bool {
        self.type_guid == Guid::EFI_SYSTEM
    }

    /// What it is, for people: "EFI System Partition", "NTFS “Windows”",
    /// "Microsoft reserved".
    pub fn describe(&self) -> String {
        let kind = guid_text(self.type_guid);
        if self.is_esp() {
            return String::from("EFI System Partition");
        }
        if self.type_guid == Guid::BIOS_BOOT {
            return String::from("BIOS boot");
        }
        if kind.eq_ignore_ascii_case(MICROSOFT_RESERVED) {
            return String::from("Microsoft reserved");
        }
        let recovery = kind.eq_ignore_ascii_case(WINDOWS_RECOVERY).then_some("Windows recovery");
        match (&self.holds, recovery) {
            (_, Some(r)) => String::from(r),
            (Some(f), _) if !f.label.is_empty() => format!("{} \u{201c}{}\u{201d}", f.kind.name(), f.label),
            (Some(f), _) => String::from(f.kind.name()),
            (None, _) if !self.name.is_empty() => format!("\u{201c}{}\u{201d}", self.name),
            (None, _) => String::from("Unknown"),
        }
    }
}

/// What is on a disk now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskMap {
    pub bytes: u64,
    pub table: Table,
    /// In the order of their places on the disk.
    pub parts: Vec<Part>,
    /// Free spaces: (first sector, sectors), on whole MiB.
    pub free: Vec<(u64, u64)>,
}

impl DiskMap {
    fn sectors(&self) -> u64 {
        self.bytes / SECTOR
    }

    fn with_free(mut self) -> DiskMap {
        self.parts.sort_by_key(|p| p.first);
        let used: Vec<(u64, u64)> = self.parts.iter().map(|p| (p.first, p.last + 1 - p.first)).collect();
        self.free = match self.table {
            Table::Empty | Table::Gpt(_) => slate_gpt::free_regions(self.sectors(), &used, ALIGN),
            Table::Mbr | Table::Damaged => Vec::new(),
        };
        self
    }

    /// The map with partitions `numbers` deleted (manual partitioning):
    /// their space is free.
    pub fn without(&self, numbers: &[u32]) -> DiskMap {
        let mut m = self.clone();
        m.parts.retain(|p| !numbers.contains(&p.number));
        m.with_free()
    }

    /// The largest free space: (first sector, sectors).
    pub fn largest_free(&self) -> Option<(u64, u64)> {
        self.free.iter().copied().max_by_key(|f| f.1)
    }

    /// Whether SlateOS can go beside what is here: a GPT (or none) and
    /// room in a free space.
    pub fn room_beside(&self) -> bool {
        matches!(self.table, Table::Gpt(_) | Table::Empty)
            && self.largest_free().is_some_and(|(first, n)| fit(self, first, n * SECTOR).is_ok())
    }

    /// The EFI System Partition SlateOS would share: one with room that
    /// holds no SlateOS yet.
    pub fn shared_esp(&self) -> Option<&Part> {
        self.parts.iter().find(|p| p.esp.as_ref().is_some_and(|e| !e.slate && e.free >= ESP_ROOM))
    }

    /// Other systems' loaders, for SlateOS's menu: on the partition it
    /// shares (`shared`), from its own; on another, by that one's GUID.
    pub fn others(&self, shared: Option<u32>) -> Vec<Other> {
        let mut out: Vec<Other> = Vec::new();
        for p in &self.parts {
            for (title, path) in p.esp.iter().flat_map(|e| &e.loaders) {
                let volume = (shared != Some(p.number)).then(|| guid_text(p.guid));
                // Titles name entries (`slate-update next`): no two alike.
                let mut t = title.clone();
                let mut n = 2;
                while out.iter().any(|o| o.title == t) {
                    t = format!("{title} ({n})");
                    n += 1;
                }
                out.push(Other { title: t, volume, path: path.clone() });
            }
        }
        out
    }
}

/// A line of a disk's map, in the disk's order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Row<'a> {
    Part(&'a Part),
    /// A free space: first sector, sectors.
    Free(u64, u64),
}

impl DiskMap {
    /// The partitions and free spaces, in the order they are on the disk.
    pub fn rows(&self) -> Vec<Row<'_>> {
        let mut rows: Vec<(u64, Row<'_>)> = self.parts.iter().map(|p| (p.first, Row::Part(p))).collect();
        rows.extend(self.free.iter().map(|&(f, n)| (f, Row::Free(f, n))));
        rows.sort_by_key(|r| r.0);
        rows.into_iter().map(|r| r.1).collect()
    }
}

/// Where a SlateOS root of `bytes` goes in the free space starting at
/// `first` (sectors long `n`): the new EFI System Partition's sectors (when
/// no ESP is shared) and the root's.
type Fit = (Option<(u64, u64)>, (u64, u64));

fn fit(map: &DiskMap, first: u64, room: u64) -> Result<Fit> {
    let esp = map.shared_esp().is_none().then_some(ESP_BYTES);
    let need = MIN_ROOT + esp.unwrap_or(0);
    if room < need {
        return Err(err(format!("the free space is too small ({} MiB; SlateOS needs {} MiB)", room / MIB, need / MIB)));
    }
    let esp_range = esp.map(|b| (first, first + b / SECTOR - 1));
    let root_first = esp_range.map_or(first, |e| e.1 + 1);
    Ok((esp_range, (root_first, first + room / SECTOR - 1)))
}

/// Read `dev`'s table and look at its partitions.
pub fn scan(dev: &mut dyn Device, bytes: u64) -> Result<DiskMap> {
    let sectors = bytes / SECTOR;
    let mut s0 = [0u8; 512];
    dev.read(0, &mut s0)?;
    let mbr = slate_mbr::parse(&s0, sectors);
    let empty = DiskMap { bytes, table: Table::Empty, parts: Vec::new(), free: Vec::new() };
    if let slate_mbr::Table::Mbr { .. } = mbr {
        return Ok(DiskMap { table: Table::Mbr, ..empty }.with_free());
    }
    let mut header = [0u8; 512];
    dev.read(SECTOR, &mut header)?;
    let h = match slate_gpt::parse_header(&header) {
        Ok(h) => h,
        Err(slate_gpt::Error::BadSignature) if mbr == slate_mbr::Table::None => return Ok(empty.with_free()),
        Err(_) => return Ok(DiskMap { table: Table::Damaged, ..empty }),
    };
    let len = h.entry_count as usize * h.entry_size as usize;
    if len > MIB as usize {
        return Ok(DiskMap { table: Table::Damaged, ..empty });
    }
    let mut array = alloc::vec![0u8; len];
    dev.read(h.entries_lba * SECTOR, &mut array)?;
    let Ok(entries) = slate_gpt::parse_entries(&h, &array) else {
        return Ok(DiskMap { table: Table::Damaged, ..empty });
    };
    let entries: Vec<slate_gpt::Entry> = entries.collect();
    let mut parts = Vec::new();
    for e in entries {
        if e.last_lba < e.first_lba || e.last_lba >= sectors {
            return Ok(DiskMap { table: Table::Damaged, ..empty });
        }
        let end = e.name_utf16.iter().position(|&u| u == 0).unwrap_or(36);
        let name = char::decode_utf16(e.name_utf16[..end].iter().copied()).map(|c| c.unwrap_or('\u{fffd}')).collect();
        let span = (e.last_lba + 1 - e.first_lba) * SECTOR;
        let mut head = alloc::vec![0u8; (slate_fsprobe::PROBE_BYTES as u64).min(span) as usize];
        dev.read(e.first_lba * SECTOR, &mut head)?;
        let holds = slate_fsprobe::probe(&head);
        let esp = (e.type_guid == Guid::EFI_SYSTEM)
            .then(|| slate_fat::edit::Fs::open(part_region(dev, (e.first_lba, e.last_lba), (0, 0))).ok())
            .flatten()
            .map(|mut fs| esp_info(&mut fs));
        parts.push(Part {
            number: e.index + 1,
            type_guid: e.type_guid,
            guid: e.unique_guid,
            first: e.first_lba,
            last: e.last_lba,
            attributes: e.attributes,
            name,
            holds,
            esp,
        });
    }
    Ok(DiskMap { bytes, table: Table::Gpt(h.disk_guid), parts, free: Vec::new() }.with_free())
}

/// The name of a directory entry in `dir` matching `name` in any case
/// (FAT's names are case-insensitive).
fn entry_named<D: slate_fat::edit::Disk>(
    fs: &mut slate_fat::edit::Fs<D>,
    dir: &str,
    name: &str,
    want_dir: bool,
) -> Option<String> {
    fs.list(dir).ok()?.into_iter().find(|e| e.dir == want_dir && e.name.eq_ignore_ascii_case(name)).map(|e| e.name)
}

/// The loaders systems are known by, in the order they are preferred
/// within a directory: shim before what it loads.
const LOADERS: [&str; 4] = ["shimx64.efi", "grubx64.efi", "systemd-bootx64.efi", "bootmgfw.efi"];

/// A directory's title on the menu.
fn title_of(dir: &str) -> String {
    let known = [
        ("Microsoft", "Windows Boot Manager"),
        ("fedora", "Fedora"),
        ("ubuntu", "Ubuntu"),
        ("debian", "Debian"),
        ("opensuse", "openSUSE"),
        ("systemd", "Linux Boot Manager"),
    ];
    if let Some((_, t)) = known.iter().find(|(d, _)| d.eq_ignore_ascii_case(dir)) {
        return String::from(*t);
    }
    let mut c = dir.chars();
    c.next().map(|f| f.to_uppercase().chain(c).collect()).unwrap_or_default()
}

/// What an EFI System Partition holds (`EFI/<system>/...` loaders,
/// UEFI 2.10 §13.3.1.3's directory convention).
fn esp_info<D: slate_fat::edit::Disk>(fs: &mut slate_fat::edit::Fs<D>) -> EspInfo {
    let slate = ["boot/limine", "boot/limine.conf", "boot/slate"].iter().any(|p| fs.exists(p));
    let mut loaders = Vec::new();
    let dirs: Vec<String> = fs.list("EFI").unwrap_or_default().into_iter().filter(|e| e.dir).map(|e| e.name).collect();
    // `BOOT` holds the removable media path, `Linux` systemd-boot's
    // kernels, `slate` SlateOS's own.
    for d in dirs.iter().filter(|d| !["BOOT", "Linux", "slate", ".", ".."].iter().any(|x| x.eq_ignore_ascii_case(d))) {
        let dir = format!("EFI/{d}");
        let mut found = None;
        let boot = entry_named(fs, &dir, "Boot", true).map(|b| format!("{dir}/{b}"));
        for sub in core::iter::once(dir.clone()).chain(boot) {
            found = found
                .or_else(|| LOADERS.iter().find_map(|l| entry_named(fs, &sub, l, false).map(|n| format!("{sub}/{n}"))));
        }
        let any = || {
            fs.list(&dir)
                .ok()?
                .into_iter()
                .find(|e| !e.dir && e.name.to_ascii_lowercase().ends_with(".efi"))
                .map(|e| format!("{dir}/{}", e.name))
        };
        if let Some(path) = found.or_else(any) {
            loaders.push((title_of(d), path));
        }
    }
    let fallback = entry_named(fs, "EFI", "BOOT", true)
        .and_then(|b| entry_named(fs, &format!("EFI/{b}"), "BOOTX64.EFI", false).map(|f| format!("EFI/{b}/{f}")));
    if loaders.is_empty()
        && let Some(path) = fallback
    {
        let title = if slate { "SlateOS (another installation)" } else { "Other system" };
        loaders.push((String::from(title), path));
    }
    EspInfo { free: fs.free_bytes(), slate, loaders }
}

/// How SlateOS goes beside what a disk keeps.
#[derive(Clone, Debug)]
pub struct Beside {
    /// The partitions that stay, as they are (and where they are).
    pub kept: Vec<Part>,
    /// The EFI System Partition is a kept one, shared: SlateOS adds its
    /// files (`EFI/slate/`, `boot/`).
    pub shared_esp: bool,
    /// The slots (number - 1) of the new partitions: the ESP's (None when
    /// shared) and the root's.
    pub esp_slot: Option<u32>,
    pub root_slot: u32,
    /// The disk had no table: it gets a protective MBR too.
    pub new_table: bool,
}

/// Lay SlateOS out in the free space of `map` that starts at sector
/// `region`, keeping every partition the map has: the root takes
/// `root_bytes` of it (all of it with None), after a 512 MiB EFI System
/// Partition of its own unless one with room can be shared. `random`
/// makes the new GUIDs and the file system's UUID unique.
pub fn plan_beside(map: &DiskMap, region: u64, root_bytes: Option<u64>, random: &[u8; 64]) -> Result<Plan> {
    let disk_guid = match map.table {
        Table::Gpt(g) => g,
        // A disk without a table gets one, keeping nothing.
        Table::Empty => Guid::from_seed(random[..16].try_into().unwrap()),
        Table::Mbr => {
            return Err(err("SlateOS goes beside other systems only on GPT disks; this one has an MBR table"));
        }
        Table::Damaged => return Err(err("the disk's partition table is damaged")),
    };
    let &(first, n) =
        map.free.iter().find(|f| f.0 == region).ok_or_else(|| err("there is no free space there any more"))?;
    let room = match root_bytes {
        Some(b) => {
            let esp = if map.shared_esp().is_some() { 0 } else { ESP_BYTES };
            let want = (b / MIB * MIB).max(MIN_ROOT) + esp;
            if want > n * SECTOR {
                return Err(err(format!("{} MiB does not fit the free space ({} MiB)", want / MIB, n * SECTOR / MIB)));
            }
            want
        }
        None => n * SECTOR,
    };
    let (new_esp, root) = fit(map, first, room)?;
    let shared = map.shared_esp().filter(|_| new_esp.is_none());
    let mut slots = (0..slate_gpt::ENTRY_COUNT).filter(|s| !map.parts.iter().any(|p| p.number == s + 1));
    let esp_slot = match new_esp {
        Some(_) => Some(slots.next().ok_or_else(|| err("the partition table is full"))?),
        None => None,
    };
    let root_slot = slots.next().ok_or_else(|| err("the partition table is full"))?;
    let guid = |i: usize| Guid::from_seed(random[i * 16..i * 16 + 16].try_into().unwrap());
    // A name of its own: images boot `root=PARTLABEL=slate-root`.
    let mut root_label = String::from(ROOT_LABEL);
    let mut k = 2;
    while map.parts.iter().any(|p| p.name == root_label) {
        root_label = format!("{ROOT_LABEL}-{k}");
        k += 1;
    }
    let (esp, esp_guid) = match (shared, new_esp) {
        (Some(p), _) => ((p.first, p.last), p.guid),
        (None, Some(e)) => (e, guid(1)),
        (None, None) => return Err(err("no EFI System Partition")),
    };
    let mut plan = super::plan_with(map.bytes, disk_guid, esp, esp_guid, None, root, guid(2), random);
    plan.root_label = root_label;
    plan.others = map.others(shared.map(|p| p.number));
    plan.layout = super::Layout::Beside(Beside {
        kept: map.parts.clone(),
        shared_esp: shared.is_some(),
        esp_slot,
        root_slot,
        new_table: map.table == Table::Empty,
    });
    Ok(plan)
}

#[cfg(test)]
mod tests;
