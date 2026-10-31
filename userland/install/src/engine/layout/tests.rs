// SPDX-License-Identifier: MIT OR Apache-2.0

//! Installing beside another system (ADR 0116), on sparse image files.

extern crate std;

use std::io::Read;
use std::os::unix::fs::FileExt;
use std::string::String;
use std::vec::Vec;

use super::super::*;
use super::*;

/// A sparse image file as the device; writes may be made to fail from
/// a byte offset on (a disk that dies during the install).
struct FileDev {
    file: std::fs::File,
    path: std::path::PathBuf,
    fail_from: Option<u64>,
}

impl FileDev {
    fn new(name: &str, size: u64) -> FileDev {
        // Tests run at once: a file each.
        static N: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(std::format!("slate-beside-{name}-{}-{n}.img", std::process::id()));
        let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path).unwrap();
        file.set_len(size).unwrap();
        FileDev { file, path, fail_from: None }
    }

    fn bytes(&mut self, first: u64, sectors: u64) -> Vec<u8> {
        let mut b = std::vec![0u8; (sectors * SECTOR) as usize];
        self.read(first * SECTOR, &mut b).unwrap();
        b
    }
}

impl Drop for FileDev {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Device for FileDev {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.file.read_exact_at(buf, offset).map_err(|e| err(std::format!("{e}")))
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        if self.fail_from.is_some_and(|f| offset + data.len() as u64 > f) {
            return Err(err("I/O error"));
        }
        self.file.write_all_at(data, offset).map_err(|e| err(std::format!("{e}")))
    }
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

const MIB_S: u64 = MIB / SECTOR;

/// A FAT32 file system on sectors `first..first + sectors` with `files`.
fn fat(dev: &mut FileDev, first: u64, sectors: u64, files: &[(&str, &[u8])]) {
    let mut v = slate_fat::Volume::new();
    for (p, d) in files {
        v.add_file(p, d.to_vec()).unwrap();
    }
    let mut r = part_region(dev, (first, first + sectors - 1), (0, 0));
    slate_fat::write(&v, sectors * SECTOR, "SYSTEM", 7, first as u32, &mut r).unwrap();
}

fn fat_files(dev: &mut FileDev, first: u64, last: u64) -> fatfs::FileSystem<std::io::Cursor<Vec<u8>>> {
    let data = dev.bytes(first, last + 1 - first);
    fatfs::FileSystem::new(std::io::Cursor::new(data), fatfs::FsOptions::new()).unwrap()
}

fn read_file(fs: &fatfs::FileSystem<std::io::Cursor<Vec<u8>>>, path: &str) -> Vec<u8> {
    let mut s = Vec::new();
    fs.root_dir().open_file(path).unwrap().read_to_end(&mut s).unwrap();
    s
}

fn fsck_fat(dev: &mut FileDev, first: u64, last: u64) {
    let data = dev.bytes(first, last + 1 - first);
    let path = std::env::temp_dir().join(std::format!("slate-beside-esp-{}-{first}.img", std::process::id()));
    std::fs::write(&path, data).unwrap();
    let out = std::process::Command::new("fsck.fat").arg("-n").arg(&path).output();
    let _ = std::fs::remove_file(&path);
    if let Ok(out) = out {
        assert!(out.status.success(), "fsck.fat: {}", String::from_utf8_lossy(&out.stdout));
    }
}

fn mib(n: u64) -> u64 {
    n * MIB_S
}

fn system() -> Vec<u8> {
    let mut w = slate_cpio::Writer::new();
    for d in ["bin", "etc", "home", "root", "var", "etc/slate"] {
        w.dir(d, 0o755);
    }
    w.file("etc/shadow", 0o600, b"root::20000:0:99999:7:::\n");
    w.file("etc/passwd", 0o644, b"root:x:0:0:root:/root:/bin/sh\n");
    w.file("etc/group", 0o644, b"root:x:0:\nwheel:x:10:root\n");
    w.file("bin/hello", 0o755, b"hi\n");
    w.file("bin/slate-unlock", 0o755, b"UNLOCK");
    w.finish()
}

const PAYLOAD_EFI: &[u8] = b"SLATE LOADER";

fn payload(sys: &[u8]) -> Payload<'_> {
    Payload { system: sys, kernel: b"KERNEL", efi: PAYLOAD_EFI, bios: None }
}

/// A disk as Windows leaves it: its EFI System Partition (with Windows'
/// loader, and its own copy on the removable media path), the reserved
/// partition, C: (NTFS) and the recovery partition at the end, with free
/// space between (C: was shrunk for SlateOS). Partition 4's slot is free.
fn windows_disk(size: u64) -> FileDev {
    let mut dev = FileDev::new("windows", size);
    let sectors = size / SECTOR;
    let msr = Guid::from_bytes(&[
        0x16, 0xe3, 0xc9, 0xe3, 0x5c, 0x0b, 0xb8, 0x4d, 0x81, 0x7d, 0xf9, 0x2d, 0xf0, 0x02, 0x15, 0xae,
    ]);
    let recovery = Guid::from_bytes(&[
        0xa4, 0xbb, 0x94, 0xde, 0xd1, 0x06, 0x40, 0x4d, 0xa1, 0x6a, 0xbf, 0xd5, 0x01, 0x79, 0xd6, 0xac,
    ]);
    let g = |n: u8| Guid::from_seed([n; 16]);
    let part = |t, u, first, last, name| slate_gpt::Partition {
        type_guid: t,
        unique_guid: u,
        first_lba: first,
        last_lba: last,
        attributes: 0,
        name,
    };
    let end = sectors / ALIGN * ALIGN - mib(1);
    let parts = [
        (0, part(Guid::EFI_SYSTEM, g(1), mib(1), mib(101) - 1, "EFI system partition")),
        (1, part(msr, g(2), mib(101), mib(117) - 1, "Microsoft reserved partition")),
        (2, part(Guid::BASIC_DATA, g(3), mib(117), mib(117 + 8192) - 1, "Partição básica de dados")),
        (4, slate_gpt::Partition { attributes: 1, ..part(recovery, g(5), end - mib(64), end - 1, "") }),
    ];
    let gpt = slate_gpt::encode_slots(sectors, g(9), &parts).unwrap();
    // Windows' boot code in the protective MBR.
    let mut mbr = gpt.protective_mbr;
    mbr[..440].copy_from_slice(&[0x33; 440]);
    dev.write(0, &mbr).unwrap();
    dev.write(SECTOR, &gpt.primary_header).unwrap();
    dev.write(2 * SECTOR, &gpt.entries).unwrap();
    dev.write(gpt.backup_entries_lba * SECTOR, &gpt.entries).unwrap();
    dev.write(gpt.backup_header_lba * SECTOR, &gpt.backup_header).unwrap();
    fat(
        &mut dev,
        mib(1),
        mib(100),
        &[("EFI/Microsoft/Boot/bootmgfw.efi", b"WINDOWS BOOT MANAGER"), ("EFI/Boot/bootx64.efi", b"WINDOWS FALLBACK")],
    );
    let mut ntfs = std::vec![0x5Au8; MIB as usize];
    ntfs[3..11].copy_from_slice(b"NTFS    ");
    dev.write(mib(117) * SECTOR, &ntfs).unwrap();
    dev.write((mib(117 + 8192) - 1) * SECTOR, &[0xC3; 512]).unwrap();
    dev.write((end - mib(64)) * SECTOR, &[0x77; 4096]).unwrap();
    dev
}

/// What must not change: the boot sector, the GPT entries of partitions
/// 1, 2, 3 and 5, and the bytes of 2, 3 (its ends) and 5.
fn windows_parts(dev: &mut FileDev) -> Vec<Vec<u8>> {
    let size = dev.file.metadata().unwrap().len();
    let map = scan(dev, size).unwrap();
    let mut out = std::vec![dev.bytes(0, 1)];
    let mut header = [0u8; 512];
    dev.read(SECTOR, &mut header).unwrap();
    let h = slate_gpt::parse_header(&header).unwrap();
    let entries = dev.bytes(h.entries_lba, 32);
    for slot in [0usize, 1, 2, 4] {
        out.push(entries[slot * 128..slot * 128 + 128].to_vec());
    }
    for p in map.parts.iter().filter(|p| [2, 5].contains(&p.number)) {
        out.push(dev.bytes(p.first, p.last + 1 - p.first));
    }
    let c = map.parts.iter().find(|p| p.number == 3).unwrap().clone();
    out.push(dev.bytes(c.first, mib(1)));
    out.push(dev.bytes(c.last - mib(1) + 1, mib(1)));
    out
}

#[test]
fn windows_disk_is_read() {
    let size = 64u64 << 30;
    let mut dev = windows_disk(size);
    let map = scan(&mut dev, size).unwrap();
    assert_eq!(map.table, Table::Gpt(Guid::from_seed([9; 16])));
    let numbers: Vec<u32> = map.parts.iter().map(|p| p.number).collect();
    assert_eq!(numbers, [1, 2, 3, 5]);
    let what: Vec<String> = map.parts.iter().map(Part::describe).collect();
    assert_eq!(what, ["EFI System Partition", "Microsoft reserved", "NTFS", "Windows recovery"]);
    assert_eq!(map.parts[2].name, "Partição básica de dados");
    let esp = map.parts[0].esp.as_ref().unwrap();
    assert!(!esp.slate && esp.free > 90 * MIB);
    assert_eq!(esp.loaders, [(String::from("Windows Boot Manager"), String::from("EFI/Microsoft/Boot/bootmgfw.efi"))]);
    // One free space: between C: and the recovery partition.
    assert_eq!(map.free.len(), 1);
    assert_eq!(map.free[0].0, mib(117 + 8192));
    assert!(map.room_beside());
    assert_eq!(map.shared_esp().map(|p| p.number), Some(1));
}

#[test]
fn beside_windows_shares_its_esp() {
    let size = 64u64 << 30;
    let mut dev = windows_disk(size);
    let before = windows_parts(&mut dev);
    let map = scan(&mut dev, size).unwrap();
    let mut plan = plan_beside(&map, map.free[0].0, None, &[5u8; 64]).unwrap();
    assert_eq!((plan.esp_number(), plan.root_number(), plan.loader_path()), (1, 4, SHARED_LOADER));
    assert_eq!(plan.root, (map.free[0].0, map.free[0].0 + map.free[0].1 - 1));
    plan.cmdline_extra = "quiet".into();
    let sys = system();
    install(&mut dev, &plan, &payload(&sys), "!", b"log\n", (1_800_000_000, 0), &mut |_| {}).unwrap();

    assert_eq!(windows_parts(&mut dev), before, "Windows' partitions, entries and boot code stay");
    let after = scan(&mut dev, size).unwrap();
    let numbers: Vec<u32> = after.parts.iter().map(|p| p.number).collect();
    assert_eq!(numbers, [1, 2, 3, 4, 5]);
    let root = &after.parts[3];
    assert_eq!((root.guid, root.name.as_str()), (plan.root_guid, "slate-root"));
    assert_eq!(root.holds.as_ref().map(|f| f.kind), Some(slate_fsprobe::Kind::SlateFs));
    // Windows' files stay; SlateOS's are added beside them.
    let esp = fat_files(&mut dev, mib(1), mib(101) - 1);
    assert_eq!(read_file(&esp, "EFI/Microsoft/Boot/bootmgfw.efi"), b"WINDOWS BOOT MANAGER");
    assert_eq!(read_file(&esp, "EFI/Boot/bootx64.efi"), b"WINDOWS FALLBACK");
    assert_eq!(read_file(&esp, "EFI/slate/BOOTX64.EFI"), PAYLOAD_EFI);
    assert_eq!(read_file(&esp, "boot/slate/system-1/kernel"), b"KERNEL");
    let conf = String::from_utf8(read_file(&esp, "boot/limine/limine.conf")).unwrap();
    assert_eq!(slate_esp::titles(&conf), ["Slate", "Windows Boot Manager"]);
    assert!(conf.contains(&std::format!("cmdline: root=PARTUUID={} quiet\n", plan.root_partuuid())), "{conf}");
    // With the desktop, quiet once (the boot splash, ADR 0186); without
    // it or anything else, nothing more.
    let quiet = crate::engine::limine_conf(&crate::engine::Plan { desktop: true, ..plan.clone() });
    assert!(quiet.contains(&std::format!("cmdline: root=PARTUUID={} quiet\n", plan.root_partuuid())), "{quiet}");
    let plain = crate::engine::Plan { desktop: true, cmdline_extra: String::new(), ..plan.clone() };
    assert!(
        crate::engine::limine_conf(&plain).contains(&std::format!("root=PARTUUID={} quiet\n", plan.root_partuuid()))
    );
    let text = crate::engine::Plan { desktop: false, cmdline_extra: String::new(), ..plan.clone() };
    assert!(!crate::engine::limine_conf(&text).contains("quiet"));
    assert!(
        conf.ends_with("/Windows Boot Manager\n    protocol: efi\n    path: boot():/EFI/Microsoft/Boot/bootmgfw.efi\n")
    );
    drop(esp);
    fsck_fat(&mut dev, mib(1), mib(101) - 1);
    let mut fs = Fs::mount(part_region(&mut dev, plan.root, (0, 0)), true).unwrap();
    assert!(fs.check().unwrap().is_empty());
    drop(fs);
    // The ESP has SlateOS now: another goes beside with an ESP of its own.
    let again = scan(&mut dev, size).unwrap();
    assert!(again.parts[0].esp.as_ref().unwrap().slate);
    assert!(again.shared_esp().is_none());
    // An update of the loader changes SlateOS's copy only.
    let new = Payload { system: &[], kernel: &[], efi: b"SLATE LOADER 2", bios: None };
    update_boot(&mut dev, &plan.root_partuuid(), &new, (0, 0)).unwrap();
    let esp = fat_files(&mut dev, mib(1), mib(101) - 1);
    assert_eq!(read_file(&esp, "EFI/slate/BOOTX64.EFI"), b"SLATE LOADER 2");
    assert_eq!(read_file(&esp, "EFI/Boot/bootx64.efi"), b"WINDOWS FALLBACK");
}

#[test]
fn a_disk_that_fails_keeps_its_table() {
    let size = 64u64 << 30;
    let mut dev = windows_disk(size);
    let map = scan(&mut dev, size).unwrap();
    let table = dev.bytes(0, 34);
    let plan = plan_beside(&map, map.free[0].0, Some(8 << 30), &[5u8; 64]).unwrap();
    assert_eq!(plan.root.1 + 1 - plan.root.0, mib(8192));
    // The disk fails halfway through the root.
    dev.fail_from = Some((plan.root.0 + mib(64)) * SECTOR);
    let sys = system();
    assert!(install(&mut dev, &plan, &payload(&sys), "!", b"", (0, 0), &mut |_| {}).is_err());
    assert_eq!(dev.bytes(0, 34), table, "nothing in the table changed");
}

/// A disk with SlateOS on it already, grown (its GPT names a smaller
/// disk): another SlateOS goes beside it with an EFI System Partition of
/// its own, and the first one's menu, kernel and boot code stay its own.
#[test]
fn beside_another_slate() {
    let size = 16u64 << 30;
    let mut dev = FileDev::new("slate", size);
    let first = plan(4 << 30, &[1u8; 64]).unwrap();
    let mut hdd: Vec<u8> = (0..20000u32).map(|i| (i * 13 + 1) as u8).collect();
    hdd[510..512].copy_from_slice(&[0x55, 0xAA]);
    let sys = system();
    let old = Payload {
        system: &sys,
        kernel: b"OLD KERNEL",
        efi: b"OLD LOADER",
        bios: Some(BiosBoot { hdd: &hdd, sys: None }),
    };
    install(&mut dev, &first, &old, "!", b"", (0, 0), &mut |_| {}).unwrap();
    let old_esp = dev.bytes(first.esp.0, first.esp.1 + 1 - first.esp.0);
    let old_head = dev.bytes(0, 2048);
    let old_root = dev.bytes(first.root.0, mib(64));

    let map = scan(&mut dev, size).unwrap();
    assert_eq!(
        map.parts.iter().map(Part::describe).collect::<Vec<_>>(),
        ["BIOS boot", "EFI System Partition", "SlateFS “slate-root”"]
    );
    let info = map.parts[1].esp.as_ref().unwrap();
    assert!(info.slate);
    assert_eq!(info.loaders, [(String::from("SlateOS (another installation)"), String::from("EFI/BOOT/BOOTX64.EFI"))]);
    // The first system's root ends a MiB before its disk did.
    let (at, n) = map.largest_free().unwrap();
    assert_eq!(at, (4 << 21) - mib(1));
    let plan = plan_beside(&map, at, None, &[2u8; 64]).unwrap();
    assert_eq!((plan.esp_number(), plan.root_number(), plan.loader_path()), (4, 5, "EFI/BOOT/BOOTX64.EFI"));
    assert_eq!(plan.root_label, "slate-root-2");
    assert_eq!(plan.esp, (at, at + mib(512) - 1));
    assert_eq!(plan.root.1, at + n - 1);
    let new = Payload {
        system: &sys,
        kernel: b"NEW KERNEL",
        efi: b"NEW LOADER",
        bios: Some(BiosBoot { hdd: &hdd, sys: None }),
    };
    install(&mut dev, &plan, &new, "!", b"", (0, 0), &mut |_| {}).unwrap();

    assert_eq!(dev.bytes(first.esp.0, first.esp.1 + 1 - first.esp.0), old_esp);
    assert_eq!(dev.bytes(0, 1), old_head[..512], "the boot code stays the first system's");
    assert_eq!(dev.bytes(34, 2048 - 34), old_head[34 * 512..], "and its BIOS stages");
    assert_eq!(dev.bytes(first.root.0, mib(64)), old_root);
    let esp = fat_files(&mut dev, plan.esp.0, plan.esp.1);
    assert_eq!(read_file(&esp, "EFI/BOOT/BOOTX64.EFI"), b"NEW LOADER");
    let conf = String::from_utf8(read_file(&esp, "boot/limine/limine.conf")).unwrap();
    assert_eq!(slate_esp::titles(&conf), ["Slate", "SlateOS (another installation)"]);
    let other = std::format!("path: guid({}):/EFI/BOOT/BOOTX64.EFI\n", guid_text(map.parts[1].guid));
    assert!(conf.ends_with(&other), "{conf}");
    drop(esp);
    // The two systems' loaders update on their own partitions.
    let newer =
        Payload { system: &[], kernel: &[], efi: b"NEWER LOADER", bios: Some(BiosBoot { hdd: &hdd, sys: None }) };
    update_boot(&mut dev, &plan.root_partuuid(), &newer, (0, 0)).unwrap();
    assert_eq!(dev.bytes(first.esp.0, first.esp.1 + 1 - first.esp.0), old_esp);
    assert_eq!(read_file(&fat_files(&mut dev, plan.esp.0, plan.esp.1), "EFI/BOOT/BOOTX64.EFI"), b"NEWER LOADER");
    update_boot(&mut dev, &first.root_partuuid(), &newer, (0, 0)).unwrap();
    assert_eq!(read_file(&fat_files(&mut dev, first.esp.0, first.esp.1), "EFI/BOOT/BOOTX64.EFI"), b"NEWER LOADER");
    // Both roots read back clean.
    for root in [first.root, plan.root] {
        let mut fs = Fs::mount(part_region(&mut dev, root, (0, 0)), true).unwrap();
        assert!(fs.check().unwrap().is_empty());
    }
}

/// Manual partitioning: a partition deleted, the root a size of its own.
#[test]
fn manual_partitioning() {
    let size = 64u64 << 30;
    let mut dev = windows_disk(size);
    let map = scan(&mut dev, size).unwrap();
    // C: deleted: its space joins the free space after it.
    let edited = map.without(&[3]);
    assert_eq!(edited.parts.len(), 3);
    assert_eq!(edited.free, [(mib(117), map.free[0].0 + map.free[0].1 - mib(117))]);
    let plan = plan_beside(&edited, mib(117), Some(20 << 30), &[4u8; 64]).unwrap();
    assert_eq!(plan.root, (mib(117), mib(117) + mib(20 * 1024) - 1));
    assert_eq!(plan.root_number(), 3, "the first free slot");
    let sys = system();
    install(&mut dev, &plan, &payload(&sys), "!", b"", (0, 0), &mut |_| {}).unwrap();
    let after = scan(&mut dev, size).unwrap();
    let what: Vec<String> = after.parts.iter().map(Part::describe).collect();
    assert_eq!(what, ["EFI System Partition", "Microsoft reserved", "SlateFS “slate-root”", "Windows recovery"]);
    // Sizes that don't fit, spaces that aren't free, too small a root.
    assert!(plan_beside(&map, map.free[0].0, Some(size), &[4u8; 64]).is_err());
    assert!(plan_beside(&map, mib(117), None, &[4u8; 64]).is_err());
    let tiny = DiskMap { free: std::vec![(mib(200), mib(1024))], ..map.clone() };
    assert!(plan_beside(&tiny, mib(200), None, &[4u8; 64]).unwrap_err().0.contains("too small"));
}

#[test]
fn tables_beside_which_slate_does_not_go() {
    // An MBR disk.
    let mut dev = FileDev::new("mbr", 8 << 30);
    let mut mbr = [0u8; 512];
    mbr[446 + 4] = 0x07;
    mbr[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
    mbr[446 + 12..446 + 16].copy_from_slice(&(1u32 << 20).to_le_bytes());
    mbr[510..].copy_from_slice(&[0x55, 0xAA]);
    dev.write(0, &mbr).unwrap();
    let map = scan(&mut dev, 8 << 30).unwrap();
    assert_eq!(map.table, Table::Mbr);
    assert!(!map.room_beside());
    assert!(plan_beside(&map, 2048, None, &[0; 64]).unwrap_err().0.contains("MBR"));
    // A damaged GPT.
    let mut dev = windows_disk(64 << 30);
    dev.write(2 * SECTOR, &[1, 2, 3]).unwrap();
    assert_eq!(scan(&mut dev, 64 << 30).unwrap().table, Table::Damaged);
}

/// A new disk: SlateOS beside nothing, in part of it.
#[test]
fn an_empty_disk_gets_a_table() {
    let size = 32u64 << 30;
    let mut dev = FileDev::new("empty", size);
    let map = scan(&mut dev, size).unwrap();
    assert_eq!((map.table, map.free.len()), (Table::Empty, 1));
    let plan = plan_beside(&map, map.free[0].0, Some(8 << 30), &[6u8; 64]).unwrap();
    let sys = system();
    install(&mut dev, &plan, &payload(&sys), "!", b"", (0, 0), &mut |_| {}).unwrap();
    let after = scan(&mut dev, size).unwrap();
    assert!(matches!(after.table, Table::Gpt(_)));
    assert_eq!(after.parts.iter().map(|p| p.number).collect::<Vec<_>>(), [1, 2]);
    assert!(after.free[0].1 > mib(20 * 1024), "the rest stays free");
}
