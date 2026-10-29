// SPDX-License-Identifier: MIT OR Apache-2.0

use std::string::String;
use std::vec::Vec;

use super::*;

/// A minimal ELF file whose one PT_NOTE segment holds a `Slate` note of
/// type `kind` with descriptor `desc` (gABI: header, program header, note).
fn elf_with_note(kind: u32, desc: &[u8]) -> Vec<u8> {
    let mut note = Vec::new();
    note.extend_from_slice(&6u32.to_le_bytes());
    note.extend_from_slice(&(desc.len() as u32).to_le_bytes());
    note.extend_from_slice(&kind.to_le_bytes());
    note.extend_from_slice(b"Slate\0\0\0");
    note.extend_from_slice(desc);
    let mut e = std::vec![0u8; 64 + 56];
    e[..4].copy_from_slice(b"\x7fELF");
    e[4] = 2;
    e[5] = 1;
    e[6] = 1;
    e[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    e[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    e[20..24].copy_from_slice(&1u32.to_le_bytes());
    e[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    e[52..54].copy_from_slice(&64u16.to_le_bytes());
    e[54..56].copy_from_slice(&56u16.to_le_bytes());
    e[56..58].copy_from_slice(&1u16.to_le_bytes());
    let ph = &mut e[64..120];
    ph[..4].copy_from_slice(&slate_elf::PT_NOTE.to_le_bytes());
    ph[8..16].copy_from_slice(&120u64.to_le_bytes()); // p_offset
    ph[32..40].copy_from_slice(&(note.len() as u64).to_le_bytes()); // p_filesz
    ph[40..48].copy_from_slice(&(note.len() as u64).to_le_bytes());
    ph[48..56].copy_from_slice(&4u64.to_le_bytes()); // p_align
    e.extend_from_slice(&note);
    e
}

fn kernel(oldest: u32, newest: u32, tag: u8) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&oldest.to_le_bytes());
    d.extend_from_slice(&newest.to_le_bytes());
    let mut k = elf_with_note(slate_abi::NT_SLATE_KERNEL_ABI, &d);
    k.extend(std::iter::repeat_n(tag, 50_000));
    k
}

#[test]
fn the_kernel_and_the_unlock_program_agree() {
    let unlock_v1 = elf_with_note(slate_abi::NT_SLATE_ABI, &1u32.to_le_bytes());
    let unlock_v3 = elf_with_note(slate_abi::NT_SLATE_ABI, &3u32.to_le_bytes());
    assert_eq!(kernel_range(&kernel(1, 2, 0)), Some((1, 2)));
    assert_eq!(program_version(&unlock_v3), Some(3));
    assert!(check_unlock(&kernel(1, 2, 0), &unlock_v1).is_ok());
    let e = check_unlock(&kernel(1, 2, 0), &unlock_v3).unwrap_err();
    assert!(e.contains("versions 1 to 2") && e.contains("needs 3"), "{e}");
    // A kernel from before ADR 0086 has no note and serves version 1.
    assert!(check_unlock(b"not even an ELF file", &unlock_v1).is_ok());
    assert!(check_unlock(&kernel(1, 1, 0), b"\x7fELF but not").is_err());
}

#[test]
fn the_command_line_loses_only_the_system_choice() {
    assert_eq!(
        base_cmdline(
            "root=PARTUUID=ab quiet slate.system=system-2 slate.ip=10.0.0.5/24 slate.boot=fallback slate.boot=rollback"
        ),
        "root=PARTUUID=ab quiet slate.ip=10.0.0.5/24"
    );
}

/// A partition as the installer writes it: Limine, `system-1`'s kernel and
/// the first configuration (or the layout before ADR 0086, `legacy`).
fn installed(legacy: bool) -> Vec<u8> {
    let mut v = slate_fat::Volume::new();
    v.add_file("EFI/BOOT/BOOTX64.EFI", std::vec![1; 10_000]).unwrap();
    v.add_file("boot/limine/limine-bios.sys", std::vec![2; 5_000]).unwrap();
    if legacy {
        v.add_file(LEGACY_KERNEL, kernel(1, 1, 9)).unwrap();
        v.add_file(CONF_FIRST, b"timeout: 3\n/Slate\n    path: boot():/boot/slate/kernel\n".to_vec()).unwrap();
    } else {
        v.add_file("boot/slate/system-1/kernel", kernel(1, 1, 1)).unwrap();
        v.add_file(CONF_FIRST, first_config("root=PARTUUID=ab", "system-1", false).into_bytes()).unwrap();
    }
    let size = v.min_size(32 << 20);
    let mut img = std::vec![0u8; size as usize];
    slate_fat::write(&v, size, "SLATE-ESP", 1, 2048, &mut img).unwrap();
    img
}

fn boot(system: &str, k: Option<Vec<u8>>) -> Boot {
    Boot { system: String::from(system), kernel: k, unlock: None, source: None, kept: None, full_graphics: false }
}

fn fsck_clean(img: &[u8]) {
    if std::process::Command::new("fsck.fat").arg("--help").output().is_err() {
        return;
    }
    let path = std::env::temp_dir().join(std::format!("slate-esp-test-{}-{:p}.img", std::process::id(), img));
    std::fs::write(&path, img).unwrap();
    let out = std::process::Command::new("fsck.fat").arg("-n").arg(&path).output().unwrap();
    let _ = std::fs::remove_file(&path);
    assert!(out.status.success(), "fsck.fat: {}", String::from_utf8_lossy(&out.stdout));
}

#[test]
fn update_rollback_and_prune() {
    let mut fs = slate_fat::edit::Fs::open(installed(false)).unwrap();
    let (k1, k2, k3) = (kernel(1, 1, 1), kernel(1, 1, 2), kernel(1, 1, 3));
    // An update: system-2 boots first with its own kernel.
    let r = sync(
        &mut fs,
        "root=PARTUUID=ab quiet",
        &boot("system-2", Some(k2.clone())),
        Some(&boot("system-1", Some(k1.clone()))),
        &[],
        None,
    )
    .unwrap();
    assert_eq!(r.written, ["boot/slate/system-2/kernel"]);
    assert!(r.switched);
    let (path, conf) = active(&mut fs).unwrap();
    assert_eq!(path, CONF_SECOND);
    assert!(!fs.exists(CONF_FIRST));
    let first_entry = conf.split("\n/").nth(1).unwrap();
    assert!(first_entry.starts_with("Slate\n"), "{conf}");
    assert!(first_entry.contains("path: boot():/boot/slate/system-2/kernel"), "{conf}");
    assert!(first_entry.contains("cmdline: root=PARTUUID=ab quiet\n"), "{conf}");
    assert!(conf.contains("cmdline: root=PARTUUID=ab quiet slate.system=system-1\n"), "{conf}");
    assert!(
        conf.contains("/Slate (previous system)\n    protocol: limine\n    path: boot():/boot/slate/system-1/kernel")
    );
    assert_eq!(fs.read("boot/slate/system-2/kernel").unwrap(), k2);
    // The same again changes nothing.
    let r = sync(
        &mut fs,
        "root=PARTUUID=ab quiet",
        &boot("system-2", Some(k2.clone())),
        Some(&boot("system-1", Some(k1.clone()))),
        &[],
        None,
    )
    .unwrap();
    assert_eq!(r, Report::default());
    assert!(in_step(&mut fs, "system-2", Some("system-1"), &[], None));
    assert!(!in_step(&mut fs, "system-1", Some("system-2"), &[], None));
    assert!(!in_step(&mut fs, "system-2", None, &[], None));
    // A rollback: system-1 first again, through the first file.
    sync(
        &mut fs,
        "root=PARTUUID=ab quiet",
        &boot("system-1", Some(k1.clone())),
        Some(&boot("system-2", Some(k2))),
        &[],
        None,
    )
    .unwrap();
    assert_eq!(active(&mut fs).unwrap().0, CONF_FIRST);
    assert!(!fs.exists(CONF_SECOND));
    // Another update: system-2's directory goes.
    let r = sync(
        &mut fs,
        "root=PARTUUID=ab quiet",
        &boot("system-3", Some(k3)),
        Some(&boot("system-1", Some(k1))),
        &[],
        None,
    )
    .unwrap();
    assert_eq!(r.removed, ["system-2"]);
    assert!(!fs.exists("boot/slate/system-2"));
    assert_eq!(fs.read("EFI/BOOT/BOOTX64.EFI").unwrap(), std::vec![1; 10_000]);
    // The menu's wait stays what it was.
    assert!(active(&mut fs).unwrap().1.starts_with("timeout: 3\n"));
    switch(&mut fs, "timeout: 0\n").unwrap();
    sync(&mut fs, "root=PARTUUID=ab", &boot("system-3", Some(kernel(1, 1, 3))), None, &[], None).unwrap();
    assert!(active(&mut fs).unwrap().1.starts_with("timeout: 0\n"));
    fsck_clean(&fs.into_disk());
}

#[test]
fn a_disk_from_before_keeps_its_kernel_for_old_systems() {
    let mut fs = slate_fat::edit::Fs::open(installed(true)).unwrap();
    let k2 = kernel(1, 1, 2);
    sync(&mut fs, "root=PARTUUID=ab", &boot("system-2", Some(k2.clone())), Some(&boot("system-1", None)), &[], None)
        .unwrap();
    let conf = active(&mut fs).unwrap().1;
    assert!(
        conf.contains("/Slate (previous system)\n    protocol: limine\n    path: boot():/boot/slate/kernel"),
        "{conf}"
    );
    assert!(fs.exists(LEGACY_KERNEL));
    // Once no entry needs it, it goes.
    let r = sync(
        &mut fs,
        "root=PARTUUID=ab",
        &boot("system-3", Some(kernel(1, 1, 3))),
        Some(&boot("system-2", Some(k2))),
        &[],
        None,
    )
    .unwrap();
    assert!(r.removed.contains(&String::from(LEGACY_KERNEL)));
    assert!(!fs.exists(LEGACY_KERNEL));
    // A system with no kernel, and none left on the partition, is refused.
    assert!(sync(&mut fs, "root=PARTUUID=ab", &boot("system-1", None), None, &[], None).is_err());
    fsck_clean(&fs.into_disk());
}

/// A disk that loses every write after the first `keep`.
struct Cut {
    img: Vec<u8>,
    keep: usize,
    writes: usize,
}

impl Disk for Cut {
    fn read(&mut self, sector: u64, buf: &mut [u8; slate_fat::SECTOR]) -> Result<(), slate_fat::Error> {
        Disk::read(&mut self.img, sector, buf)
    }
    fn write(&mut self, sector: u64, data: &[u8; slate_fat::SECTOR]) -> Result<(), slate_fat::Error> {
        self.writes += 1;
        if self.writes <= self.keep { Disk::write(&mut self.img, sector, data) } else { Ok(()) }
    }
    fn flush(&mut self) -> Result<(), slate_fat::Error> {
        Ok(())
    }
}

/// Cut off anywhere in an update: Limine finds a whole configuration
/// naming kernels that are whole.
#[test]
fn a_crash_during_an_update_boots_one_system_or_the_other() {
    let base = installed(false);
    let (k1, k2) = (kernel(1, 1, 1), kernel(1, 1, 2));
    let run = |d: &mut Cut| {
        let mut fs = slate_fat::edit::Fs::open(d).unwrap();
        let _ = sync(
            &mut fs,
            "root=PARTUUID=ab",
            &boot("system-2", Some(k2.clone())),
            Some(&boot("system-1", Some(k1.clone()))),
            &[],
            None,
        );
    };
    let mut full = Cut { img: base.clone(), keep: usize::MAX, writes: 0 };
    run(&mut full);
    for keep in 0..=full.writes {
        let mut cut = Cut { img: base.clone(), keep, writes: 0 };
        run(&mut cut);
        let mut fs = slate_fat::edit::Fs::open(cut.img).unwrap();
        let (_, conf) = active(&mut fs).unwrap_or_else(|| panic!("cut at {keep}: no configuration"));
        let first = conf.split("path: boot():/").nth(1).and_then(|r| r.lines().next()).unwrap().to_string();
        let k = fs.read(&first).unwrap_or_else(|e| panic!("cut at {keep}: {first}: {e:?}"));
        assert!(k == k1 || k == k2, "cut at {keep}: {first} is neither kernel");
    }
}

#[test]
fn an_archive_keeps_its_fonts() {
    let mut files: std::collections::BTreeMap<&str, Vec<u8>> = std::collections::BTreeMap::new();
    files.insert(UNLOCK_PROGRAM, b"PROGRAM".to_vec());
    for (i, f) in UNLOCK_FONTS.iter().enumerate() {
        files.insert(f, std::vec![i as u8; 10]);
    }
    let full = unlock_archive(&mut |p| files.get(p).cloned()).unwrap();
    let fonts = archive_fonts(&full);
    assert_eq!(fonts.len(), UNLOCK_FONTS.len());
    // A system without fonts, given the old archive's, makes the same one.
    let again = unlock_archive(&mut |p| {
        if p == UNLOCK_PROGRAM {
            Some(b"PROGRAM".to_vec())
        } else {
            fonts.iter().find(|(n, _)| n == p).map(|(_, d)| d.clone())
        }
    })
    .unwrap();
    assert_eq!(again, full);
}

/// Every system version on the menu (ADR 0089): the older ones after the
/// default and the fallback, newest first, as long as they fit.
#[test]
fn older_systems_on_the_menu() {
    let mut fs = slate_fat::edit::Fs::open(installed(false)).unwrap();
    let k = |n: u8| kernel(1, 1, n);
    let older = [boot("system-2", Some(k(2))), boot("system-1", Some(k(1))), boot("system-0", None)];
    sync(&mut fs, "root=PARTUUID=ab", &boot("system-4", Some(k(4))), Some(&boot("system-3", Some(k(3)))), &older, None)
        .unwrap();
    let conf = active(&mut fs).unwrap().1;
    let titles: Vec<&str> = conf.split("\n/").skip(1).map(|e| e.lines().next().unwrap()).collect();
    assert_eq!(titles, ["Slate", "Slate (previous system)", OLDER_TITLE, OLDER_TITLE]);
    assert!(
        conf.contains("path: boot():/boot/slate/system-1/kernel\n    cmdline: root=PARTUUID=ab slate.system=system-1")
    );
    assert!(in_step(&mut fs, "system-4", Some("system-3"), &["system-2", "system-1"], None));
    assert!(!in_step(&mut fs, "system-4", Some("system-3"), &["system-2"], None));
    // Pruned: system-1 goes from the menu and the partition.
    let r = sync(
        &mut fs,
        "root=PARTUUID=ab",
        &boot("system-4", Some(k(4))),
        Some(&boot("system-3", Some(k(3)))),
        &older[..1],
        None,
    )
    .unwrap();
    assert_eq!(r.removed, ["system-1"]);
    // What does not fit stays off, the rest boots.
    let huge = boot("system-1", Some(std::vec![7; 64 << 20]));
    sync(
        &mut fs,
        "root=PARTUUID=ab",
        &boot("system-4", Some(k(4))),
        Some(&boot("system-3", Some(k(3)))),
        &[older[0].clone(), huge],
        None,
    )
    .unwrap();
    assert!(in_step(&mut fs, "system-4", Some("system-3"), &["system-2"], None));
    assert!(!fs.exists("boot/slate/system-1"));
    fsck_clean(&fs.into_disk());
}

/// The loader's count follows the trial (ADR 0089).
#[test]
fn the_tries_file_follows_the_trial() {
    let mut fs = slate_fat::edit::Fs::open(installed(false)).unwrap();
    let (k1, k2) = (kernel(1, 1, 1), kernel(1, 1, 2));
    let (b1, b2) = (boot("system-1", Some(k1)), boot("system-2", Some(k2)));
    let r = sync(&mut fs, "root=PARTUUID=ab", &b2, Some(&b1), &[], Some("system-2")).unwrap();
    assert!(r.written.contains(&String::from(TRIES)));
    assert_eq!(parse_tries(&fs.read(TRIES).unwrap()), Some((String::from("system-2"), TRIAL_BOOTS)));
    assert!(in_step(&mut fs, "system-2", Some("system-1"), &[], Some("system-2")));
    assert!(!in_step(&mut fs, "system-2", Some("system-1"), &[], None));
    // The loader counted a boot: a sync during the trial keeps its count.
    fs.write(TRIES, tries_text("system-2", 0).as_bytes()).unwrap();
    sync(&mut fs, "root=PARTUUID=ab", &b2, Some(&b1), &[], Some("system-2")).unwrap();
    assert_eq!(parse_tries(&fs.read(TRIES).unwrap()), Some((String::from("system-2"), 0)));
    // Confirmed: the count goes.
    let r = sync(&mut fs, "root=PARTUUID=ab", &b2, Some(&b1), &[], None).unwrap();
    assert_eq!(r.removed, [TRIES]);
    assert!(in_step(&mut fs, "system-2", Some("system-1"), &[], None));
    assert_eq!(parse_tries(b"system-3 x\n"), None);
    fsck_clean(&fs.into_disk());
}

/// Other systems' entries stay on the menu through updates (ADR 0116),
/// and a menu with them is still in step.
#[test]
fn other_systems_stay_on_the_menu() {
    let mut fs = slate_fat::edit::Fs::open(installed(false)).unwrap();
    let others = [
        Other { title: "Windows Boot Manager".into(), volume: None, path: "EFI/Microsoft/Boot/bootmgfw.efi".into() },
        Other {
            title: "Fedora".into(),
            volume: Some("01234567-89ab-cdef-0123-456789abcdef".into()),
            path: "EFI/fedora/shimx64.efi".into(),
        },
    ];
    let first = with_others(&first_config("root=PARTUUID=ab", "system-1", false), &others);
    switch(&mut fs, &first).unwrap();
    assert_eq!(titles(&first), ["Slate", "Windows Boot Manager", "Fedora"]);
    assert!(first.contains(
        "/Fedora\n    protocol: efi\n    path: guid(01234567-89ab-cdef-0123-456789abcdef):/EFI/fedora/shimx64.efi\n"
    ));
    assert!(in_step(&mut fs, "system-1", None, &[], None));
    let (k1, k2) = (kernel(1, 1, 1), kernel(1, 1, 2));
    sync(&mut fs, "root=PARTUUID=ab", &boot("system-2", Some(k2)), Some(&boot("system-1", Some(k1))), &[], None)
        .unwrap();
    let conf = active(&mut fs).unwrap().1;
    assert_eq!(titles(&conf), ["Slate", "Slate (previous system)", "Windows Boot Manager", "Fedora"]);
    assert!(conf.ends_with("path: guid(01234567-89ab-cdef-0123-456789abcdef):/EFI/fedora/shimx64.efi\n"), "{conf}");
    assert!(in_step(&mut fs, "system-2", Some("system-1"), &[], None));
    fsck_clean(&fs.into_disk());
}

/// A system's files are recorded with what they were made from; a sync
/// that finds the same source keeps them without reading or writing them,
/// and a different source, or a file of the wrong size, writes them anew.
#[test]
fn source_records_keep_files_unread() {
    let mut fs = slate_fat::edit::Fs::open(installed(false)).unwrap();
    let (k1, k2) = (kernel(1, 1, 1), kernel(1, 1, 2));
    let with = |system: &str, k: &[u8], unlock: Option<&[u8]>, src: &str| Boot {
        system: String::from(system),
        kernel: Some(k.to_vec()),
        unlock: unlock.map(<[u8]>::to_vec),
        source: Some(String::from(src)),
        kept: None,
        full_graphics: false,
    };
    let kept = |system: &str, src: &str, unlock: bool| Boot {
        system: String::from(system),
        kernel: None,
        unlock: None,
        source: Some(String::from(src)),
        kept: Some(unlock),
        full_graphics: false,
    };
    let r = sync(
        &mut fs,
        "root=PARTUUID=ab",
        &with("system-2", &k2, Some(b"ARCHIVE"), "s2 a"),
        Some(&with("system-1", &k1, None, "s1 a")),
        &[],
        None,
    )
    .unwrap();
    // The record isn't news in the report.
    assert_eq!(r.written, ["boot/slate/system-2/kernel", "boot/slate/system-2/unlock"]);
    assert!(fs.exists("boot/slate/system-2/source"));
    assert_eq!(current_from(&mut fs, "system-2", "s2 a"), Some(true));
    assert_eq!(current_from(&mut fs, "system-1", "s1 a"), Some(false));
    assert_eq!(current_from(&mut fs, "system-1", "s1 b"), None);
    let (_, before) = active(&mut fs).unwrap();
    // Kept: nothing written, and the menu the same (the unlock archive
    // still named).
    let r = sync(
        &mut fs,
        "root=PARTUUID=ab",
        &kept("system-2", "s2 a", true),
        Some(&kept("system-1", "s1 a", false)),
        &[],
        None,
    )
    .unwrap();
    assert!(r.written.is_empty() && !r.switched, "{r:?}");
    assert_eq!(active(&mut fs).unwrap().1, before);
    assert!(before.contains("boot():/boot/slate/system-2/unlock"), "{before}");
    // Another source: written again, the record last.
    let r = sync(
        &mut fs,
        "root=PARTUUID=ab",
        &with("system-2", &k1, Some(b"ARCHIVE"), "s2 b"),
        Some(&kept("system-1", "s1 a", false)),
        &[],
        None,
    )
    .unwrap();
    assert!(r.written.iter().any(|p| p == "boot/slate/system-2/kernel"), "{:?}", r.written);
    assert_eq!(current_from(&mut fs, "system-2", "s2 a"), None);
    assert_eq!(current_from(&mut fs, "system-2", "s2 b"), Some(true));
    // A kernel cut short is not current.
    fs.write("boot/slate/system-2/kernel", b"short").unwrap();
    assert_eq!(current_from(&mut fs, "system-2", "s2 b"), None);
}

/// A system with full graphics (ADR 0173) gets a standard-graphics entry
/// right after its own, with the AMD driver off and no system named (it
/// follows the boot state as the first does); the fallback after it.
#[test]
fn standard_graphics_entry() {
    let conf = first_config_with("root=PARTUUID=ab", "system-1", false, true);
    assert_eq!(titles(&conf), ["Slate", STANDARD_TITLE]);
    assert!(conf.contains("cmdline: root=PARTUUID=ab slate.disable=amd-display\n"));
    assert_eq!(titles(&first_config("root=PARTUUID=ab", "system-1", false)), ["Slate"]);
    let mut fs = slate_fat::edit::Fs::open(installed(false)).unwrap();
    let mut b = boot("system-2", Some(kernel(1, 1, 1)));
    b.full_graphics = true;
    let f = boot("system-1", Some(kernel(1, 1, 2)));
    sync(&mut fs, "root=PARTUUID=ab", &b, Some(&f), &[], Some("system-2")).unwrap();
    let (_, conf) = active(&mut fs).unwrap();
    assert_eq!(titles(&conf), ["Slate", STANDARD_TITLE, "Slate (previous system)"]);
    assert!(conf.contains("cmdline: root=PARTUUID=ab slate.disable=amd-display\n"));
    assert!(conf.contains("cmdline: root=PARTUUID=ab slate.system=system-1\n"));
}
