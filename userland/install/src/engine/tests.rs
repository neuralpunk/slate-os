// SPDX-License-Identifier: MIT OR Apache-2.0

extern crate std;

use std::io::Read;
use std::os::unix::fs::FileExt;
use std::string::String;
use std::vec::Vec;

use super::*;

/// A sparse image file as the device.
struct FileDev(std::fs::File);

impl Device for FileDev {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.0.read_exact_at(buf, offset).map_err(|e| err(format!("{e}")))
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        self.0.write_all_at(data, offset).map_err(|e| err(format!("{e}")))
    }
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

fn system() -> Vec<u8> {
    system_with(|_| {})
}

/// [`system`] with `more` added at its end.
fn system_with(more: impl FnOnce(&mut slate_cpio::Writer)) -> Vec<u8> {
    let mut w = slate_cpio::Writer::new();
    for d in ["bin", "etc", "home", "root", "var", "var/lib", "etc"] {
        w.dir(d, if d == "home" { 0o751 } else { 0o755 });
    }
    w.file("etc/hostname", 0o644, b"replaced below\n");
    w.file("bin/hello", 0o755, b"#!/bin/sh\necho hi\n");
    w.symlink("bin/sh", "hello");
    w.file("etc/shadow", 0o600, b"root::20000:0:99999:7:::\nslate:!:20000::::::\n");
    w.file("etc/passwd", 0o644, b"root:x:0:0:root:/root:/bin/sh\ntester:x:1000:100::/home/tester:/bin/sh\n");
    w.file("etc/group", 0o644, b"root:x:0:\nwheel:x:10:root\nusers:x:100:\nseat:x:64:\n");
    w.dir("usr", 0o755);
    w.dir("usr/share", 0o755);
    w.dir("usr/share/strata", 0o755);
    w.file("usr/share/strata/terminal.app", 0o644, b"name=Terminal\n");
    w.file("bin/strata", 0o755, b"STRATA");
    // quarry's record of the desktop package (ADR 0071).
    for d in ["usr/lib", "usr/lib/quarry", "usr/lib/quarry/db", "usr/lib/quarry/db/slate-desktop"] {
        w.dir(d, 0o755);
    }
    w.file(
        "usr/lib/quarry/db/slate-desktop/files",
        0o644,
        b"f 755 aa bin/strata\nd 755 - usr/share/strata\nf 644 bb usr/share/strata/terminal.app\n",
    );
    w.file("bin/slate-unlock", 0o755, b"UNLOCK");
    w.dir("etc/slate", 0o755);
    w.file("etc/slate/network", 0o644, b"# Settings\n[*]\nmethod = dhcp\n");
    w.file("etc/hostname", 0o644, b"slate\n");
    w.file("var/lib/state", 0o644, b"var data\n");
    more(&mut w);
    w.finish()
}

struct Image {
    path: std::path::PathBuf,
}

impl Drop for Image {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[test]
fn installs_a_disk_that_reads_back() {
    let size = 3u64 << 30;
    let img = Image { path: std::env::temp_dir().join(std::format!("slate-install-test-{}.img", std::process::id())) };
    let f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&img.path).unwrap();
    f.set_len(size).unwrap();
    let mut dev = FileDev(f);
    let random = [7u8; 64];
    let mut plan = plan(size, &random).unwrap();
    plan.cmdline_extra = "slate.ip=10.0.0.5/24,10.0.0.1".into();
    plan.root_keys = Some(b"ssh-ed25519 AAAA test\n".to_vec());
    plan.linux_compat = true;
    plan.account = Some(Account { username: "ada".into(), full_name: "Ada Lovelace".into(), hash: "$6$s$u".into() });
    plan.hostname = Some("ada-slate".into());
    plan.locale = Some("en_GB.UTF-8".into());
    plan.keyboard = Some("gb".into());
    plan.timezone = Some("Europe/London".into());
    let words = ["*", "static", "10.0.0.5/24", "gateway", "10.0.0.1", "dns", "9.9.9.9"];
    plan.network = Some(slate_netconf::Card::from_words(&words).unwrap());
    let sys = system();
    let mut hdd: Vec<u8> = (0..22261u32).map(|i| (i * 7 + 3) as u8).collect();
    hdd[510..512].copy_from_slice(&[0x55, 0xAA]);
    let bios = BiosBoot { hdd: &hdd, sys: Some(b"STAGE 3") };
    let payload = Payload { system: &sys, kernel: b"KERNEL", efi: b"EFI APP", bios: Some(bios) };
    let mut steps = Vec::new();
    install(&mut dev, &plan, &payload, "!", b"the kernel log\n", (1_800_000_000, 0), &mut |s| steps.push(s)).unwrap();
    assert_eq!(steps.first(), Some(&Step::Partition));
    assert_eq!(steps.last(), Some(&Step::Finish));

    // The GPT names the partitions the plan chose.
    let mut header = [0u8; 512];
    dev.read(512, &mut header).unwrap();
    let h = slate_gpt::parse_header(&header).unwrap();
    let mut array = std::vec![0u8; 128 * 128];
    dev.read(h.entries_lba * 512, &mut array).unwrap();
    let parts: Vec<_> = slate_gpt::parse_entries(&h, &array).unwrap().collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[1].unique_guid, plan.root_guid);
    assert_eq!((parts[1].first_lba, parts[1].last_lba), plan.root);
    assert_eq!(parts[2].type_guid, Guid::BIOS_BOOT);
    assert_eq!((parts[2].first_lba, parts[2].last_lba), (34, 2047));

    // Limine's BIOS stages, placed as its bios-install places them: the
    // boot sector from the image with the partition table kept and stage
    // 2's byte offset at 0x1A4, stage 2 at the BIOS boot partition.
    let mut mbr = [0u8; 512];
    dev.read(0, &mut mbr).unwrap();
    assert_eq!(&mbr[..218], &hdd[..218]);
    assert_eq!(&mbr[218..224], &[0; 6], "the disk's timestamp stays");
    assert_eq!(&mbr[224..0x1A4], &hdd[224..0x1A4]);
    assert_eq!(u64::from_le_bytes(mbr[0x1A4..0x1AC].try_into().unwrap()), 34 * 512);
    assert_eq!(mbr[450], 0xEE, "the protective MBR's partition record stays");
    assert_eq!(&mbr[510..], &[0x55, 0xAA]);
    let mut stage2 = std::vec![0u8; hdd.len() - 512];
    dev.read(34 * 512, &mut stage2).unwrap();
    assert_eq!(stage2, &hdd[512..]);

    // The ESP, read by another FAT implementation.
    let esp_len = (plan.esp.1 + 1 - plan.esp.0) * 512;
    let mut esp = std::vec![0u8; esp_len as usize];
    dev.read(plan.esp.0 * 512, &mut esp).unwrap();
    let fat = fatfs::FileSystem::new(std::io::Cursor::new(esp), fatfs::FsOptions::new()).unwrap();
    let read = |p: &str| {
        let mut s = Vec::new();
        fat.root_dir().open_file(p).unwrap().read_to_end(&mut s).unwrap();
        s
    };
    assert_eq!(read("EFI/BOOT/BOOTX64.EFI"), b"EFI APP");
    assert_eq!(read("boot/limine/limine-bios.sys"), b"STAGE 3");
    // system-1's kernel in its own directory (ADR 0086), one menu entry.
    assert_eq!(read("boot/slate/system-1/kernel"), b"KERNEL");
    let conf = String::from_utf8(read("boot/limine/limine.conf")).unwrap();
    assert!(
        conf.contains(&std::format!(
            "path: boot():/boot/slate/system-1/kernel\n    cmdline: root=PARTUUID={} slate.ip=10.0.0.5/24,10.0.0.1\n",
            plan.root_partuuid()
        )),
        "{conf}"
    );
    assert_eq!(conf.matches("protocol: limine").count(), 1, "{conf}");

    // SlateFS: the subvolumes, the files, root's password, the log.
    let base = plan.root.0 * 512;
    let len = (plan.root.1 + 1 - plan.root.0) * 512;
    let mut fs = Fs::mount(Region { dev: &mut dev, base, len, now: (0, 0), xts: None }, true).unwrap();
    assert!(fs.check().unwrap().is_empty());
    let sys = fs.subvol_by_name("system-1").unwrap();
    assert_eq!(fs.boot().default, sys);
    let cat = |fs: &mut Fs<Region<'_>>, sv: u64, path: &str| -> Vec<u8> {
        let mut ino = ROOT_INO;
        for part in path.split('/') {
            ino = fs.lookup(sv, ino, part.as_bytes()).unwrap();
        }
        let size = fs.stat(sv, ino).unwrap().size as usize;
        let mut buf = std::vec![0u8; size];
        fs.read(sv, ino, 0, &mut buf).unwrap();
        buf
    };
    assert_eq!(cat(&mut fs, sys, "bin/hello"), b"#!/bin/sh\necho hi\n");
    assert_eq!(cat(&mut fs, sys, "root/.ssh/authorized_keys"), b"ssh-ed25519 AAAA test\n");
    assert_eq!(cat(&mut fs, sys, "etc/slate/linux-compat"), b"on\n");
    // Root locked, the first user an administrator (ADR 0035).
    assert_eq!(
        String::from_utf8(cat(&mut fs, sys, "etc/shadow")).unwrap(),
        "root:!:20000:0:99999:7:::\nslate:!:20000::::::\nada:$6$s$u:20833:0:99999:7:::\n"
    );
    assert!(
        String::from_utf8(cat(&mut fs, sys, "etc/passwd"))
            .unwrap()
            .ends_with("tester:x:1000:100::/home/tester:/bin/sh\nada:x:1001:1001:Ada Lovelace:/home/ada:/bin/sh\n")
    );
    assert_eq!(
        cat(&mut fs, sys, "etc/group"),
        b"root:x:0:\nwheel:x:10:root,ada\nusers:x:100:\nseat:x:64:ada\nada:x:1001:\n"
    );
    // A command-line-only install: no Strata, no session to start.
    let bin = fs.lookup(sys, ROOT_INO, b"bin").unwrap();
    assert!(fs.lookup(sys, bin, b"strata").is_err());
    let usr = fs.lookup(sys, ROOT_INO, b"usr").unwrap();
    let share = fs.lookup(sys, usr, b"share").unwrap();
    assert!(fs.lookup(sys, share, b"strata").is_err());
    let etc = fs.lookup(sys, ROOT_INO, b"etc").unwrap();
    let slate = fs.lookup(sys, etc, b"slate").unwrap();
    assert!(fs.lookup(sys, slate, b"session").is_err());
    // Nor quarry's record of it, so Strata can be added later.
    let lib = fs.lookup(sys, usr, b"lib").unwrap();
    let quarry = fs.lookup(sys, lib, b"quarry").unwrap();
    let db = fs.lookup(sys, quarry, b"db").unwrap();
    assert!(fs.lookup(sys, db, b"slate-desktop").is_err());
    assert_eq!(cat(&mut fs, sys, "etc/hostname"), b"ada-slate\n");
    assert_eq!(cat(&mut fs, sys, "etc/locale.conf"), b"LANG=en_GB.UTF-8\n");
    assert_eq!(cat(&mut fs, sys, "etc/slate/keyboard"), b"gb\n");
    assert_eq!(cat(&mut fs, sys, "etc/slate/timezone"), b"Europe/London\n");
    assert_eq!(
        cat(&mut fs, sys, "etc/slate/network"),
        b"# Settings\n[*]\nmethod = static\naddress = 10.0.0.5/24\ngateway = 10.0.0.1\ndns = 9.9.9.9\n"
    );
    let bin = fs.lookup(sys, ROOT_INO, b"bin").unwrap();
    let sh = fs.lookup(sys, bin, b"sh").unwrap();
    assert_eq!(fs.readlink(sys, sh).unwrap(), b"hello");
    let var = fs.subvol_by_name("var").unwrap();
    assert_eq!(cat(&mut fs, var, "lib/state"), b"var data\n");
    assert_eq!(cat(&mut fs, var, "log/install.log"), b"the kernel log\n");
    // The system carries its own kernel.
    assert_eq!(cat(&mut fs, sys, "boot/slate/kernel"), b"KERNEL");
    let home = fs.subvol_by_name("home").unwrap();
    assert_eq!(fs.stat(home, ROOT_INO).unwrap().mode & 0o7777, 0o751);
    let ada = fs.lookup(home, ROOT_INO, b"ada").unwrap();
    let ada = fs.stat(home, ada).unwrap();
    assert_eq!((ada.mode & 0o7777, ada.uid, ada.gid), (0o700, 1001, 1001));
    // /home and /var are empty mount points in the system.
    let h = fs.lookup(sys, ROOT_INO, b"home").unwrap();
    assert!(fs.readdir(sys, h).unwrap().is_empty());
}

#[test]
fn boot_partition_updates() {
    let size = 3u64 << 30;
    let img = Image { path: std::env::temp_dir().join(std::format!("slate-update-boot-{}.img", std::process::id())) };
    let f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&img.path).unwrap();
    f.set_len(size).unwrap();
    let mut dev = FileDev(f);
    let plan = plan(size, &[3u8; 64]).unwrap();
    let sys = system();
    let old = Payload { system: &sys, kernel: b"THE KERNEL", efi: b"EFI 1", bios: None };
    install(&mut dev, &plan, &old, "x", b"", (0, 0), &mut |_| {}).unwrap();
    // Only Limine changes, in place (ADR 0086): kernels follow the systems.
    let new = Payload { system: &[], kernel: &[], efi: b"EFI 2, LONGER", bios: None };
    assert!(update_boot(&mut dev, "00000000-0000-4000-8000-000000000000", &new, (0, 0)).is_err());
    let root = plan.root_partuuid().to_uppercase();
    update_boot(&mut dev, &root, &new, (0, 0)).unwrap();
    let esp_len = (plan.esp.1 + 1 - plan.esp.0) * 512;
    let mut esp = std::vec![0u8; esp_len as usize];
    dev.read(plan.esp.0 * 512, &mut esp).unwrap();
    let fat = fatfs::FileSystem::new(std::io::Cursor::new(esp), fatfs::FsOptions::new()).unwrap();
    let read = |p: &str| {
        let mut s = Vec::new();
        fat.root_dir().open_file(p).unwrap().read_to_end(&mut s).unwrap();
        s
    };
    assert_eq!(read("EFI/BOOT/BOOTX64.EFI"), b"EFI 2, LONGER");
    assert_eq!(read("boot/slate/system-1/kernel"), b"THE KERNEL");
    assert!(String::from_utf8(read("boot/limine/limine.conf")).unwrap().contains("boot():/boot/slate/system-1/kernel"));
    // The root file system was not touched.
    let base = plan.root.0 * 512;
    let len = (plan.root.1 + 1 - plan.root.0) * 512;
    let mut fs = Fs::mount(Region { dev: &mut dev, base, len, now: (0, 0), xts: None }, true).unwrap();
    assert!(fs.check().unwrap().is_empty());
}

#[test]
fn small_disks_are_refused() {
    assert!(plan(1 << 30, &[0; 64]).is_err());
}

#[test]
fn shadow_root_line() {
    assert_eq!(set_root_hash(b"root::1:0:2:3:::\nx:y:z\n", "H"), b"root:H:1:0:2:3:::\nx:y:z\n");
}

#[test]
fn account_files() {
    let a = Account { username: "bo".into(), full_name: "Bo, Jr: x".into(), hash: "H".into() };
    assert_eq!(next_uid(b"root:x:0:0::/:\nu:x:1000:1000::/:\n"), 1001);
    assert_eq!(next_uid(b""), 1000);
    assert_eq!(
        add_passwd(b"root:x:0:0::/root:/bin/sh", &a, 1000),
        b"root:x:0:0::/root:/bin/sh\nbo:x:1000:1000:Bo Jr x:/home/bo:/bin/sh\n"
    );
    assert_eq!(add_group(b"wheel:x:10:\n", "bo", 1000), b"wheel:x:10:bo\nbo:x:1000:\n");
    assert_eq!(add_shadow(b"", "bo", "H", 5), b"bo:H:5:0:99999:7:::\n");
}

/// An encrypted root (ADR 0036): the header opens with the password, the
/// file system reads back through the key, and none of it is plain on the
/// disk.
#[test]
fn encrypted_root() {
    let size = 3u64 << 30;
    let img = Image { path: std::env::temp_dir().join(std::format!("slate-crypt-test-{}.img", std::process::id())) };
    let f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&img.path).unwrap();
    f.set_len(size).unwrap();
    let mut dev = FileDev(f);
    let mut plan = plan(size, &[5u8; 64]).unwrap();
    // Small Argon2 costs keep the test quick.
    let quick = slatecrypt::Params { memory_kib: 64, passes: 1, lanes: 1 };
    let mut memory = std::vec![slatecrypt::Block::default(); quick.blocks()];
    let key: [u8; 64] = core::array::from_fn(|i| (i * 7) as u8);
    let mut h = slatecrypt::Header::new(plan.root.1 + 1 - plan.root.0, [1; 16]);
    h.slots[0] = Some(slatecrypt::new_slot(&key, b"hunter22", [2; 32], quick, &mut memory).unwrap());
    plan.encryption = Some(Encryption { header: std::boxed::Box::new(h.to_bytes()), key });
    plan.keyboard = Some("gb".into());
    let sys = system();
    let payload = Payload { system: &sys, kernel: b"KERNEL", efi: b"EFI APP", bios: None };
    install(&mut dev, &plan, &payload, "!", b"log\n", (0, 0), &mut |_| {}).unwrap();
    // The boot partition has the unlock archive (ADR 0038): the program,
    // without fonts here; the menu loads it and names the layout.
    let esp_len = (plan.esp.1 + 1 - plan.esp.0) * 512;
    let mut esp = std::vec![0u8; esp_len as usize];
    dev.read(plan.esp.0 * 512, &mut esp).unwrap();
    let fat = fatfs::FileSystem::new(std::io::Cursor::new(esp), fatfs::FsOptions::new()).unwrap();
    let read = |p: &str| {
        let mut s = Vec::new();
        fat.root_dir().open_file(p).unwrap().read_to_end(&mut s).unwrap();
        s
    };
    let archive = read("boot/slate/system-1/unlock");
    let files: Vec<(String, Vec<u8>)> =
        slate_cpio::entries(&archive).map(|e| e.unwrap()).map(|e| (String::from(e.name), e.data.to_vec())).collect();
    assert_eq!(files, [("bin".into(), Vec::new()), ("bin/slate-unlock".into(), b"UNLOCK".to_vec())]);
    let conf = String::from_utf8(read("boot/limine/limine.conf")).unwrap();
    assert!(conf.contains(" slate.keyboard=gb\n    module_path: boot():/boot/slate/system-1/unlock\n"), "{conf}");
    drop(fat);

    let base = plan.root.0 * 512;
    let mut head = std::vec![0u8; slatecrypt::HEADER_BYTES];
    dev.read(base, &mut head).unwrap();
    let back = slatecrypt::Header::parse(&head).unwrap();
    assert_eq!(back.unlock(b"hunter22", &mut memory), Ok(key));
    // No plain file data or SlateFS structures on the disk.
    let len = (plan.root.1 + 1 - plan.root.0) * 512;
    let mut raw = std::vec![0u8; 64 << 20];
    dev.read(base + (1 << 20), &mut raw).unwrap();
    let plain = |raw: &[u8], p: &[u8]| raw.windows(p.len()).any(|w| w == p);
    assert!(!plain(&raw, b"#!/bin/sh\necho hi\n") && !plain(&raw, b"var data\n"));
    // Decrypted, the same bytes hold the file: the search can find it.
    let xts = slatecrypt::Xts::new(&key);
    xts.decrypt(0, &mut raw);
    assert!(plain(&raw, b"#!/bin/sh\necho hi\n"));
    let data = base + slatecrypt::DATA_OFFSET * 512;
    let region = Region { dev: &mut dev, base: data, len: len - (1 << 20), now: (0, 0), xts: Some(&xts) };
    let mut fs = Fs::mount(region, true).unwrap();
    assert!(fs.check().unwrap().is_empty());
    let sv = fs.subvol_by_name("system-1").unwrap();
    let bin = fs.lookup(sv, ROOT_INO, b"bin").unwrap();
    let hello = fs.lookup(sv, bin, b"hello").unwrap();
    let mut buf = [0u8; 18];
    fs.read(sv, hello, 0, &mut buf).unwrap();
    assert_eq!(&buf, b"#!/bin/sh\necho hi\n");
}

#[test]
fn desktop_paths_from_the_record() {
    let d = super::desktop_paths(b"f 755 aa bin/strata\nd 755 - usr/share/fonts/slate\nf 644 bb a path with spaces\n");
    assert!(is_desktop_path("bin/strata", &d));
    assert!(is_desktop_path("usr/share/fonts/slate", &d));
    assert!(is_desktop_path("a path with spaces", &d));
    assert!(is_desktop_path("usr/lib/quarry/db/slate-desktop/files", &d));
    assert!(is_desktop_path("usr/lib/quarry/db/slate-apps/manifest", &d));
    assert!(!is_desktop_path("bin/strata-other", &d));
    assert!(!is_desktop_path("usr/share/fonts", &d));
    assert!(!is_desktop_path("usr/lib/quarry/db/slate-desktopx", &d));
}

/// With the desktop: Strata's files, and the session file.
#[test]
fn desktop_install() {
    let size = 3u64 << 30;
    let img = Image { path: std::env::temp_dir().join(std::format!("slate-desktop-test-{}.img", std::process::id())) };
    let f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&img.path).unwrap();
    f.set_len(size).unwrap();
    let mut dev = FileDev(f);
    let mut plan = plan(size, &[9u8; 64]).unwrap();
    plan.desktop = true;
    let sys = system();
    let payload = Payload { system: &sys, kernel: b"K", efi: b"E", bios: None };
    install(&mut dev, &plan, &payload, "!", b"", (0, 0), &mut |_| {}).unwrap();
    let base = plan.root.0 * 512;
    let len = (plan.root.1 + 1 - plan.root.0) * 512;
    let mut fs = Fs::mount(Region { dev: &mut dev, base, len, now: (0, 0), xts: None }, true).unwrap();
    let sv = fs.subvol_by_name("system-1").unwrap();
    let bin = fs.lookup(sv, ROOT_INO, b"bin").unwrap();
    assert!(fs.lookup(sv, bin, b"strata").is_ok());
    let mut db = ROOT_INO;
    for part in [&b"usr"[..], b"lib", b"quarry", b"db"] {
        db = fs.lookup(sv, db, part).unwrap();
    }
    assert!(fs.lookup(sv, db, b"slate-desktop").is_ok());
    let etc = fs.lookup(sv, ROOT_INO, b"etc").unwrap();
    let slate = fs.lookup(sv, etc, b"slate").unwrap();
    let session = fs.lookup(sv, slate, b"session").unwrap();
    let mut buf = [0u8; 7];
    fs.read(sv, session, 0, &mut buf).unwrap();
    assert_eq!(&buf, b"strata\n");
}

/// `system()` with AMD's firmware package in its repository, signed by
/// `signer`, and `trusted`'s public key among quarry's.
fn system_with_firmware(signer: [u8; 32], trusted: [u8; 32]) -> Vec<u8> {
    use slate_qpkg::{Entry, Kind, Manifest, SecretKey, archive};
    let mut m = Manifest::new("slate-firmware-gpu", "1.0");
    m.arch = "x86_64".into();
    let dir = |p: &str| Entry { path: p.into(), kind: Kind::Dir, mode: 0o755, data: Vec::new() };
    let entries = [
        dir("lib"),
        dir("lib/firmware"),
        dir("lib/firmware/amdgpu"),
        Entry {
            path: "lib/firmware/amdgpu/dcn_3_1_5_dmcub.bin".into(),
            kind: Kind::File,
            mode: 0o644,
            data: b"DMCUB".to_vec(),
        },
    ];
    let qpk = archive::write(&m, &entries, &SecretKey::from_seed(signer)).unwrap();
    system_with(|w| {
        for d in ["usr/share/quarry", "usr/share/quarry/keys", "var/lib/quarry", "var/lib/quarry/install"] {
            w.dir(d, 0o755);
        }
        w.dir("var/lib/quarry/install/pkgs", 0o755);
        w.file("usr/share/quarry/keys/test.pub", 0o644, SecretKey::from_seed(trusted).public().to_text().as_bytes());
        w.file(&std::format!("var/lib/quarry/install/pkgs/{}", m.file_name()), 0o644, &qpk);
    })
}

/// Full graphics (ADR 0173): the firmware's files, quarry's record of
/// them, the trial mark and the boot menu's standard-graphics entry; a
/// package signed by a key the system doesn't trust stops the install.
#[test]
fn full_graphics_install() {
    let size = 3u64 << 30;
    let img = Image { path: std::env::temp_dir().join(std::format!("slate-gfx-test-{}.img", std::process::id())) };
    let f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&img.path).unwrap();
    f.set_len(size).unwrap();
    let mut dev = FileDev(f);
    let mut plan = plan(size, &[5u8; 64]).unwrap();
    plan.full_graphics = true;
    assert!(limine_conf(&plan).contains(slate_esp::STANDARD_TITLE));
    plan.full_graphics = false;
    assert!(!limine_conf(&plan).contains(slate_esp::STANDARD_TITLE));
    plan.full_graphics = true;

    let wrong = system_with_firmware([1; 32], [2; 32]);
    let payload = Payload { system: &wrong, kernel: b"K", efi: b"E", bios: None };
    let e = install(&mut dev, &plan, &payload, "!", b"", (0, 0), &mut |_| {}).unwrap_err();
    assert!(e.0.contains("firmware package"), "{}", e.0);
    let plain = system();
    let payload = Payload { system: &plain, kernel: b"K", efi: b"E", bios: None };
    assert!(install(&mut dev, &plan, &payload, "!", b"", (0, 0), &mut |_| {}).is_err(), "no package");

    let sys = system_with_firmware([1; 32], [1; 32]);
    let payload = Payload { system: &sys, kernel: b"K", efi: b"E", bios: None };
    // A machine wanting Bluetooth firmware, on a medium without it:
    // installed without it (ADR 0176).
    plan.bluetooth_firmware = true;
    // The live system's Bluetooth pairings come along (ADR 0176).
    plan.bluetooth = std::vec![
        (String::from("irk"), b"00112233445566778899aabbccddeeff\n".to_vec()),
        (String::from("devices/DA:DB:00:8C:D8:E5"), b"name=Mouse\nle=random\n".to_vec()),
        (String::from("devices/../../etc/passwd"), b"no".to_vec()),
    ];
    install(&mut dev, &plan, &payload, "!", b"", (0, 0), &mut |_| {}).unwrap();
    let base = plan.root.0 * 512;
    let len = (plan.root.1 + 1 - plan.root.0) * 512;
    let mut fs = Fs::mount(Region { dev: &mut dev, base, len, now: (0, 0), xts: None }, true).unwrap();
    let mut read = |sv: &str, path: &str| -> Vec<u8> {
        let sv = fs.subvol_by_name(sv).unwrap();
        let mut ino = ROOT_INO;
        for part in path.split('/') {
            ino = fs.lookup(sv, ino, part.as_bytes()).unwrap_or_else(|_| panic!("no {path}"));
        }
        let mut buf = std::vec![0u8; 4096];
        let n = fs.read(sv, ino, 0, &mut buf).unwrap();
        buf.truncate(n);
        buf
    };
    assert_eq!(read("system-1", "lib/firmware/amdgpu/dcn_3_1_5_dmcub.bin"), b"DMCUB");
    let files = String::from_utf8(read("system-1", "usr/lib/quarry/db/slate-firmware-gpu/files")).unwrap();
    let sha = slate_hash::hex(&slate_hash::sha256(b"DMCUB"));
    assert!(files.contains(&std::format!("f 644 {sha} lib/firmware/amdgpu/dcn_3_1_5_dmcub.bin\n")), "{files}");
    assert!(files.starts_with("d 755 - lib\n"), "{files}");
    assert!(
        String::from_utf8(read("system-1", "usr/lib/quarry/db/slate-firmware-gpu/manifest"))
            .unwrap()
            .contains("slate-firmware-gpu")
    );
    assert_eq!(read("system-1", "usr/lib/quarry/db/slate-firmware-gpu/reason"), b"explicit\n");
    assert_eq!(read("var", "lib/slate/graphics-trial"), b"full\n");
    assert_eq!(read("var", "lib/slate/bluetooth/devices/DA:DB:00:8C:D8:E5"), b"name=Mouse\nle=random\n");
    let var = fs.subvol_by_name("var").unwrap();
    let mut ino = ROOT_INO;
    for part in ["lib", "slate", "bluetooth"] {
        ino = fs.lookup(var, ino, part.as_bytes()).unwrap();
    }
    assert_eq!(fs.stat(var, ino).unwrap().mode & 0o777, 0o700, "root's alone");
    let devices = fs.lookup(var, ino, b"devices").unwrap();
    assert_eq!(fs.stat(var, devices).unwrap().mode & 0o777, 0o700);
}
