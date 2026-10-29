// SPDX-License-Identifier: MIT OR Apache-2.0

//! The disks, their partitions and what each holds (ADR 0112), from
//! /sys/block: sysfs-block(5)'s files, and Slate's own `slate_table`,
//! `slate_type` and `slate_fs*`, which the kernel writes from what it
//! finds on each device. Disks reads them; it never opens a disk.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// What a device holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Holds {
    /// udev's name: `slatefs`, `vfat`, `slatecrypt`...
    pub fs: String,
    /// The name people read: `SlateFS`, `FAT32`...
    pub kind: String,
    pub label: String,
    pub uuid: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Part {
    /// `sda1`, `nvme0n1p2`.
    pub name: String,
    pub number: u32,
    /// First sector and length, in 512-byte sectors.
    pub start: u64,
    pub sectors: u64,
    /// The GPT's name for it.
    pub label: String,
    /// A GPT type GUID, or an MBR type byte (`0x0c`).
    pub ptype: String,
    pub holds: Option<Holds>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Disk {
    pub name: String,
    pub model: String,
    pub sectors: u64,
    pub removable: bool,
    pub read_only: bool,
    /// `gpt`, `mbr`, or None for no table.
    pub table: Option<String>,
    /// What the whole disk holds, without a table.
    pub holds: Option<Holds>,
    pub parts: Vec<Part>,
}

/// An unlocked encrypted partition (`dm-0`): what it is over and holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mapped {
    pub name: String,
    pub under: String,
    pub holds: Option<Holds>,
}

/// How sysfs is read: a file's text, and a directory's names (tests give
/// their own).
pub trait Sys {
    fn file(&self, path: &str) -> Option<String>;
    fn dir(&self, path: &str) -> Vec<String>;
}

/// The real /sys.
#[derive(Debug)]
pub struct RealSys;

impl Sys for RealSys {
    fn file(&self, path: &str) -> Option<String> {
        slate_rt::fs::read_file(path.as_bytes()).ok().map(|b| String::from(slate_rt::lossy(&b).trim_end_matches('\n')))
    }
    fn dir(&self, path: &str) -> Vec<String> {
        let mut v: Vec<String> = slate_rt::fs::read_dir(path.as_bytes())
            .map(|e| e.iter().map(|e| String::from(slate_rt::lossy(&e.name))).filter(|n| !n.starts_with('.')).collect())
            .unwrap_or_default();
        v.sort();
        v
    }
}

fn holds(sys: &dyn Sys, dir: &str) -> Option<Holds> {
    let f = |n: &str| sys.file(&alloc::format!("{dir}/{n}")).unwrap_or_default().trim().to_string();
    let fs = f("slate_fs");
    (!fs.is_empty()).then(|| Holds {
        fs,
        kind: f("slate_fs_kind"),
        label: f("slate_fs_label"),
        uuid: f("slate_fs_uuid"),
    })
}

/// The disks (not RAM disks or loops), with their partitions in order,
/// and the mapped devices.
pub fn read(sys: &dyn Sys) -> (Vec<Disk>, Vec<Mapped>) {
    let mut disks = Vec::new();
    let mut mapped = Vec::new();
    for name in sys.dir("/sys/block") {
        if ["ram", "loop", "zram"].iter().any(|p| name.starts_with(p)) {
            continue;
        }
        let dir = alloc::format!("/sys/block/{name}");
        let num = |n: &str| sys.file(&alloc::format!("{dir}/{n}")).and_then(|v| v.trim().parse::<u64>().ok());
        if name.starts_with("dm-") {
            let under = sys.dir(&alloc::format!("{dir}/slaves")).into_iter().next().unwrap_or_default();
            mapped.push(Mapped { holds: holds(sys, &dir), name, under });
            continue;
        }
        let sectors = num("size").unwrap_or(0);
        if sectors == 0 {
            continue;
        }
        let table =
            sys.file(&alloc::format!("{dir}/slate_table")).map(|t| t.trim().to_string()).filter(|t| !t.is_empty());
        let mut parts: Vec<Part> = sys
            .dir(&dir)
            .into_iter()
            .filter(|p| p.starts_with(name.as_str()) && *p != name)
            .filter_map(|p| {
                let pd = alloc::format!("{dir}/{p}");
                let pn = |n: &str| sys.file(&alloc::format!("{pd}/{n}")).and_then(|v| v.trim().parse::<u64>().ok());
                let uevent = sys.file(&alloc::format!("{pd}/uevent")).unwrap_or_default();
                let label = uevent.lines().find_map(|l| l.strip_prefix("PARTNAME=")).unwrap_or("").to_string();
                Some(Part {
                    number: pn("partition")? as u32,
                    start: pn("start")?,
                    sectors: pn("size")?,
                    label,
                    ptype: sys.file(&alloc::format!("{pd}/slate_type")).unwrap_or_default().trim().to_string(),
                    holds: holds(sys, &pd),
                    name: p,
                })
            })
            .collect();
        parts.sort_by_key(|p| p.start);
        disks.push(Disk {
            model: sys.file(&alloc::format!("{dir}/device/model")).unwrap_or_default().trim().to_string(),
            sectors,
            removable: num("removable") == Some(1),
            read_only: num("ro") == Some(1),
            holds: if table.is_none() { holds(sys, &dir) } else { None },
            table,
            parts,
            name,
        });
    }
    (disks, mapped)
}

/// A partition type's name (the UEFI specification's table 5.7 and the
/// types other systems document for their own partitions).
pub fn type_name(ptype: &str) -> &'static str {
    match ptype.to_ascii_lowercase().as_str() {
        "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" => "EFI System",
        "21686148-6449-6e6f-744e-656564454649" => "BIOS boot",
        "0fc63daf-8483-4772-8e79-3d69d8477de4" => "Linux file system",
        "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f" => "Linux swap",
        "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" => "Basic data",
        "e3c9e316-0b5c-4db8-817d-f92df00215ae" => "Microsoft reserved",
        "de94bba4-06d1-4d40-a16a-bfd50179d6ac" => "Windows recovery",
        "48465300-0000-11aa-aa11-00306543ecac" => "Apple HFS+",
        "7c3457ef-0000-11aa-aa11-00306543ecac" => "Apple APFS",
        "0x0c" | "0x0b" => "FAT32",
        "0x06" | "0x0e" => "FAT16",
        "0x07" => "NTFS or exFAT",
        "0x83" => "Linux",
        "0x82" => "Linux swap",
        "0xef" => "EFI System",
        "" => "",
        _ => "Other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct Fake(BTreeMap<&'static str, &'static str>);

    impl Sys for Fake {
        fn file(&self, path: &str) -> Option<String> {
            self.0.get(path).map(|s| s.to_string())
        }
        fn dir(&self, path: &str) -> Vec<String> {
            let prefix = alloc::format!("{path}/");
            let mut v: Vec<String> = self
                .0
                .keys()
                .filter_map(|k| k.strip_prefix(prefix.as_str()))
                .map(|r| r.split('/').next().unwrap().to_string())
                .collect();
            v.dedup();
            v
        }
    }

    #[test]
    fn disks_from_sysfs() {
        let sys = Fake(BTreeMap::from([
            ("/sys/block/sda/size", "1000000\n"),
            ("/sys/block/sda/removable", "1\n"),
            ("/sys/block/sda/ro", "0\n"),
            ("/sys/block/sda/device/model", "Stick\n"),
            ("/sys/block/sda/slate_table", "gpt\n"),
            ("/sys/block/sda/sda2/size", "500000\n"),
            ("/sys/block/sda/sda2/start", "402048\n"),
            ("/sys/block/sda/sda2/partition", "2\n"),
            ("/sys/block/sda/sda2/slate_fs", "\n"),
            ("/sys/block/sda/sda1/size", "400000\n"),
            ("/sys/block/sda/sda1/start", "2048\n"),
            ("/sys/block/sda/sda1/partition", "1\n"),
            ("/sys/block/sda/sda1/uevent", "MAJOR=8\nDEVTYPE=partition\nPARTN=1\nPARTNAME=photos\n"),
            ("/sys/block/sda/sda1/slate_type", "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7\n"),
            ("/sys/block/sda/sda1/slate_fs", "vfat\n"),
            ("/sys/block/sda/sda1/slate_fs_kind", "FAT32\n"),
            ("/sys/block/sda/sda1/slate_fs_label", "PHOTOS\n"),
            ("/sys/block/vdb/size", "2048\n"),
            ("/sys/block/vdb/slate_table", "\n"),
            ("/sys/block/vdb/slate_fs", "slatefs\n"),
            ("/sys/block/vdb/slate_fs_kind", "SlateFS\n"),
            ("/sys/block/dm-0/size", "1000\n"),
            ("/sys/block/dm-0/slaves/vda2", ""),
            ("/sys/block/dm-0/slate_fs", "slatefs\n"),
            ("/sys/block/loop0/size", "10\n"),
        ]));
        let (disks, mapped) = read(&sys);
        assert_eq!(disks.len(), 2);
        let sda = &disks[0];
        assert_eq!((sda.model.as_str(), sda.removable, sda.table.as_deref()), ("Stick", true, Some("gpt")));
        assert_eq!(sda.parts.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), ["sda1", "sda2"]);
        let p = &sda.parts[0];
        assert_eq!(
            (p.label.as_str(), type_name(&p.ptype), p.holds.as_ref().unwrap().label.as_str()),
            ("photos", "Basic data", "PHOTOS")
        );
        assert_eq!(sda.parts[1].holds, None);
        assert_eq!(
            (disks[1].table.as_deref(), disks[1].holds.as_ref().map(|h| h.kind.as_str())),
            (None, Some("SlateFS"))
        );
        assert_eq!((mapped[0].name.as_str(), mapped[0].under.as_str()), ("dm-0", "vda2"));
    }
}
