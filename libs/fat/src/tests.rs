// SPDX-License-Identifier: MIT OR Apache-2.0

extern crate std;

use std::io::Read;
use std::string::String;
use std::vec::Vec;

use super::*;

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

fn sample() -> (Volume, Vec<(String, Vec<u8>)>) {
    let mut v = Volume::new();
    let mut files = Vec::new();
    let mut add = |v: &mut Volume, path: &str, data: Vec<u8>| {
        v.add_file(path, data.clone()).unwrap();
        files.push((String::from(path), data));
    };
    add(&mut v, "EFI/BOOT/BOOTX64.EFI", pattern(70_000, 1));
    add(&mut v, "boot/limine/limine.conf", b"timeout: 0\n".to_vec());
    add(&mut v, "boot/slate/kernel", pattern(3 << 20, 7));
    add(&mut v, "boot/slate/modules/initramfs", pattern(1_234_567, 9));
    add(&mut v, "empty", Vec::new());
    add(&mut v, "A rather long file name.with.dots.txt", b"long".to_vec());
    // Enough entries to need several directory clusters.
    for i in 0..60 {
        add(&mut v, &std::format!("many/file-number-{i}.dat"), pattern(i * 37, i as u8));
    }
    v.add_dir("boot/empty-dir").unwrap();
    (v, files)
}

fn image(v: &Volume) -> Vec<u8> {
    let size = v.min_size(1 << 20);
    let mut img = std::vec![0u8; size as usize];
    write(v, size, "SLATE-TEST", 0x1234_5678, 2048, &mut img).unwrap();
    img
}

#[test]
fn another_implementation_reads_it() {
    let (v, files) = sample();
    let img = image(&v);
    let fs = fatfs::FileSystem::new(std::io::Cursor::new(img), fatfs::FsOptions::new()).unwrap();
    assert_eq!(fs.fat_type(), fatfs::FatType::Fat32);
    assert_eq!(fs.volume_label().trim(), "SLATE-TEST");
    let root = fs.root_dir();
    for (path, data) in &files {
        let mut got = Vec::new();
        root.open_file(path).unwrap_or_else(|e| panic!("{path}: {e}")).read_to_end(&mut got).unwrap();
        assert_eq!(&got, data, "{path}");
    }
    // Case-insensitive lookup through the long names, and listing.
    assert!(root.open_file("efi/boot/bootx64.efi").is_ok());
    let names: Vec<String> = root.open_dir("many").unwrap().iter().map(|e| e.unwrap().file_name()).collect();
    assert!(names.iter().any(|n| n == "file-number-59.dat"));
    assert_eq!(names.iter().filter(|n| n.starts_with("file-number-")).count(), 60);
    assert!(root.open_dir("boot/empty-dir").is_ok());
}

#[test]
fn dosfsck_finds_nothing() {
    let Ok(fsck) = std::process::Command::new("fsck.fat").arg("--help").output() else { return };
    let _ = fsck;
    let (v, _) = sample();
    let img = image(&v);
    let path = std::env::temp_dir().join(std::format!("slate-fat-test-{}.img", std::process::id()));
    std::fs::write(&path, &img).unwrap();
    let out = std::process::Command::new("fsck.fat").arg("-n").arg("-v").arg(&path).output().unwrap();
    let _ = std::fs::remove_file(&path);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "fsck.fat: {text}{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn names() {
    assert_eq!(&short_name_exact("BOOTX64.EFI").unwrap(), b"BOOTX64 EFI");
    assert!(short_name_exact("kernel").is_none());
    assert_eq!(&short_name_generated("limine-bios.sys", 1), b"LIMINE~1SYS");
    assert_eq!(entries_for("limine.conf"), 2);
    assert_eq!(Volume::new().add_file("a/b:c", Vec::new()), Err(Error::BadName));
    let mut v = Volume::new();
    v.add_file("x", Vec::new()).unwrap();
    assert_eq!(v.add_file("X", Vec::new()), Err(Error::Exists));
    assert_eq!(v.add_file("x/y", Vec::new()), Err(Error::Exists));
}

#[test]
fn too_small() {
    let (v, _) = sample();
    let mut img = std::vec![0u8; 20 << 20];
    assert_eq!(write(&v, 20 << 20, "X", 0, 0, &mut img), Err(Error::TooSmall));
}

mod editing {
    use super::*;
    use crate::edit::{Disk, Fs};

    fn read_all(img: &[u8], path: &str) -> Option<Vec<u8>> {
        let fs = fatfs::FileSystem::new(std::io::Cursor::new(img.to_vec()), fatfs::FsOptions::new()).ok()?;
        let mut got = Vec::new();
        fs.root_dir().open_file(path).ok()?.read_to_end(&mut got).ok()?;
        Some(got)
    }

    fn fsck_clean(img: &[u8]) {
        if std::process::Command::new("fsck.fat").arg("--help").output().is_err() {
            return;
        }
        let path = std::env::temp_dir().join(std::format!("slate-fat-edit-{}-{:p}.img", std::process::id(), img));
        std::fs::write(&path, img).unwrap();
        let out = std::process::Command::new("fsck.fat").arg("-n").arg(&path).output().unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(
            out.status.success(),
            "fsck.fat: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn changes_another_implementation_reads() {
        let (v, _) = sample();
        let mut fs = Fs::open(image(&v)).unwrap();
        // ADR 0086's layout: a kernel per system, the second configuration.
        fs.mkdir("boot/slate/system-2").unwrap();
        let kernel = pattern(3 << 20, 42);
        fs.write("boot/slate/system-2/kernel", &kernel).unwrap();
        fs.write("boot/limine.conf", b"timeout: 3\n").unwrap();
        fs.remove("boot/limine/limine.conf").unwrap();
        fs.write("boot/slate/kernel", b"replaced").unwrap();
        fs.remove_tree("boot/slate/modules").unwrap();
        fs.remove("empty").unwrap();
        assert_eq!(fs.read("boot/slate/system-2/kernel").unwrap(), kernel);
        assert!(fs.exists("BOOT/SLATE/SYSTEM-2"));
        assert_eq!(fs.remove("boot"), Err(Error::NotEmpty));
        assert_eq!(fs.read("nope"), Err(Error::NotFound));
        let names: Vec<String> = fs.list("boot/slate").unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["kernel", "system-2"]);
        let img = fs.into_disk();
        assert_eq!(read_all(&img, "boot/slate/system-2/kernel").unwrap(), kernel);
        assert_eq!(read_all(&img, "boot/limine.conf").unwrap(), b"timeout: 3\n");
        assert_eq!(read_all(&img, "boot/slate/kernel").unwrap(), b"replaced");
        assert!(read_all(&img, "boot/limine/limine.conf").is_none());
        assert!(read_all(&img, "boot/slate/modules/initramfs").is_none());
        assert_eq!(read_all(&img, "EFI/BOOT/BOOTX64.EFI").unwrap(), pattern(70_000, 1));
        fsck_clean(&img);
    }

    #[test]
    fn read_into_a_buffer_of_its_size() {
        let (v, _) = sample();
        let mut fs = Fs::open(image(&v)).unwrap();
        // Whole clusters, a partial last one, a cluster and a byte, empty.
        for (i, len) in [3 << 20, 70_001, 4097, 0].into_iter().enumerate() {
            let data = pattern(len, 7 + i as u8);
            let path = std::format!("f{i}");
            fs.write(&path, &data).unwrap();
            assert_eq!(fs.size(&path).unwrap(), len as u64);
            let mut buf = alloc::vec![0xAAu8; len];
            fs.read_into(&path, &mut buf).unwrap();
            assert_eq!(buf, data);
            assert_eq!(fs.read_into(&path, &mut alloc::vec![0u8; len + 1]), Err(Error::Io));
        }
        assert_eq!(fs.size("boot"), Err(Error::Exists));
    }

    #[test]
    fn free_space_follows_writes() {
        let (v, _) = sample();
        let mut fs = Fs::open(image(&v)).unwrap();
        let before = fs.free_bytes();
        fs.write("big", &pattern(1 << 20, 3)).unwrap();
        let used = before - fs.free_bytes();
        assert!((1 << 20..(1 << 20) + 64 * 1024).contains(&used), "{used}");
        fs.remove("big").unwrap();
        assert_eq!(fs.free_bytes(), before);
    }

    #[test]
    fn directories_grow() {
        let mut v = Volume::new();
        v.add_dir("d").unwrap();
        let mut fs = Fs::open(image(&v)).unwrap();
        for i in 0..300 {
            fs.write(&std::format!("d/a file with a long name {i}.data"), &pattern(i, i as u8)).unwrap();
        }
        for i in (0..300).step_by(3) {
            fs.remove(&std::format!("d/a file with a long name {i}.data")).unwrap();
        }
        fs.write("d/after the holes", b"x").unwrap();
        assert_eq!(fs.list("d").unwrap().len(), 201);
        let img = fs.into_disk();
        assert_eq!(read_all(&img, "d/a file with a long name 299.data").unwrap(), pattern(299, 43));
        assert!(read_all(&img, "d/a file with a long name 297.data").is_none());
        fsck_clean(&img);
    }

    /// A disk that loses every write after the first `keep`.
    struct Cut {
        img: Vec<u8>,
        keep: usize,
        writes: usize,
    }

    impl Disk for Cut {
        fn read(&mut self, sector: u64, buf: &mut [u8; SECTOR]) -> Result<(), Error> {
            Disk::read(&mut self.img, sector, buf)
        }
        fn write(&mut self, sector: u64, data: &[u8; SECTOR]) -> Result<(), Error> {
            self.writes += 1;
            if self.writes <= self.keep { Disk::write(&mut self.img, sector, data) } else { Ok(()) }
        }
        fn flush(&mut self) -> Result<(), Error> {
            Ok(())
        }
    }

    /// Cut off after every write a change makes: the file reads as it was
    /// or as it became, never anything else.
    #[test]
    fn a_crash_leaves_the_old_or_the_new() {
        let (v, _) = sample();
        let base = image(&v);
        let old = b"timeout: 0\n".to_vec();
        let new = pattern(20_000, 5);
        // How many writes the change takes.
        let mut full = Cut { img: base.clone(), keep: usize::MAX, writes: 0 };
        {
            let mut fs = Fs::open(&mut full).unwrap();
            fs.write("boot/limine/limine.conf", &new).unwrap();
            fs.write("boot/limine.conf", &new).unwrap();
            fs.remove("boot/limine/limine.conf").unwrap();
        }
        let total = full.writes;
        assert!(total > 5);
        for keep in 0..=total {
            let mut cut = Cut { img: base.clone(), keep, writes: 0 };
            {
                let mut fs = Fs::open(&mut cut).unwrap();
                fs.write("boot/limine/limine.conf", &new).unwrap();
                fs.write("boot/limine.conf", &new).unwrap();
                fs.remove("boot/limine/limine.conf").unwrap();
            }
            let a = read_all(&cut.img, "boot/limine/limine.conf");
            let b = read_all(&cut.img, "boot/limine.conf");
            assert!(a.is_none() || a.as_ref() == Some(&old) || a.as_ref() == Some(&new), "cut at {keep}: {a:?}");
            assert!(b.is_none() || b.as_ref() == Some(&new), "cut at {keep}");
            // Limine takes the first: there is always one, whole.
            assert!(a.is_some() || b.is_some(), "cut at {keep}: no configuration");
        }
    }
}
