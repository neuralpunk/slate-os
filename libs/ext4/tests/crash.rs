// SPDX-License-Identifier: MIT OR Apache-2.0

//! Crash consistency of Slate's journaled writes (ADR 0042): a workload
//! runs on an image made by mkfs.ext4 and the power is cut after every
//! few disk writes. Two models of what reached the disk:
//! - every write before the cut (in order), and
//! - only what was flushed (writes since the last flush are lost).
//!
//! After each cut, both e2fsck (replaying the journal) and slate-ext4's own
//! mount must leave a file system that `e2fsck -fn` finds clean. Skipped
//! when e2fsprogs is missing.

use std::path::{Path, PathBuf};
use std::process::Command;

use slate_ext4::layout::S_IFREG;
use slate_ext4::{Disk, Error, Fs, Options};

/// A disk in memory that stops taking writes after `cut` of them.
struct CrashDisk {
    current: Vec<u8>,
    /// What the disk held at the last flush.
    durable: Vec<u8>,
    writes: usize,
    cut: Option<usize>,
    /// The state at the cut: (everything written, only what was flushed).
    at_cut: Option<(Vec<u8>, Vec<u8>)>,
}

impl CrashDisk {
    fn new(img: Vec<u8>, cut: Option<usize>) -> CrashDisk {
        CrashDisk { durable: img.clone(), current: img, writes: 0, cut, at_cut: None }
    }

    fn dead(&self) -> bool {
        self.at_cut.is_some()
    }
}

impl Disk for CrashDisk {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> slate_ext4::Result<()> {
        let at = offset as usize;
        buf.copy_from_slice(self.current.get(at..at + buf.len()).ok_or(Error::Io)?);
        Ok(())
    }
    fn write(&mut self, offset: u64, buf: &[u8]) -> slate_ext4::Result<()> {
        if self.dead() {
            return Ok(()); // The power is off: nothing lands any more.
        }
        if Some(self.writes) == self.cut {
            self.at_cut = Some((self.current.clone(), self.durable.clone()));
            return Ok(());
        }
        self.writes += 1;
        let at = offset as usize;
        self.current.get_mut(at..at + buf.len()).ok_or(Error::Io)?.copy_from_slice(buf);
        Ok(())
    }
    fn flush(&mut self) -> slate_ext4::Result<()> {
        if !self.dead() {
            self.durable.clone_from(&self.current);
        }
        Ok(())
    }
    fn now(&self) -> (i64, u32) {
        (1_750_000_000, 0)
    }
}

fn have_e2fsprogs() -> bool {
    let ok = Command::new("mkfs.ext4").arg("-V").output().is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("skipping: mkfs.ext4 not available");
    }
    ok
}

fn tmp(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ext4-crash");
    std::fs::create_dir_all(&d).unwrap();
    d.join(name)
}

fn mkfs(name: &str, size: &str, extra: &[&str]) -> Vec<u8> {
    let img = tmp(name);
    let _ = std::fs::remove_file(&img);
    let out = Command::new("mkfs.ext4")
        .args(["-q", "-F", "-E", "root_owner=0:0"])
        .args(extra)
        .arg(&img)
        .arg(size)
        .output()
        .unwrap();
    assert!(out.status.success(), "mkfs.ext4 failed: {}", String::from_utf8_lossy(&out.stderr));
    std::fs::read(&img).unwrap()
}

fn e2fsck(img: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new("e2fsck").args(args).arg(img).output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

/// What `e2fsck -p` prints when it only recovers (journal and orphans).
fn recovery_line(l: &str) -> bool {
    let msg = l.split_once(": ").map_or(l, |(_, m)| m);
    l.trim().is_empty()
        || msg.starts_with("recovering journal")
        || msg.starts_with("Clearing orphaned inode")
        || msg.ends_with("was not cleanly unmounted, check forced.")
        || msg.contains(" files (")
        || msg.starts_with("clean,")
}

fn pattern(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// Creates, writes, renames, links, truncates and removes files, leaves
/// unlinked files open (orphans), and commits now and then; never
/// unmounts. Stops at the first error (after the cut, reads may see a disk
/// that no longer matches).
fn workload(fs: &mut Fs<CrashDisk>) -> Result<(), Error> {
    let root = 2;
    let dirs: Vec<u32> =
        (0..4).map(|i| fs.mkdir(root, format!("d{i}").as_bytes(), 0o755, 0, 0)).collect::<Result<_, _>>()?;
    for i in 0..48u32 {
        let dir = dirs[i as usize % dirs.len()];
        let name = format!("f{i}");
        let f = fs.create(dir, name.as_bytes(), S_IFREG | 0o644, 0, 0, 0)?;
        let len = [10, 5000, 40_000, 200_000][i as usize % 4];
        fs.write(f, 0, &pattern(len, i))?;
        match i % 6 {
            1 => {
                fs.rename(dir, name.as_bytes(), root, format!("moved{i}").as_bytes())?;
            }
            2 => fs.link(root, format!("link{i}").as_bytes(), f)?,
            3 => fs.truncate(f, 1234)?,
            4 => {
                // Unlinked while "open": an orphan until the end.
                fs.unlink(dir, name.as_bytes())?;
            }
            5 => {
                let gone = fs.unlink(dir, name.as_bytes())?;
                fs.evict(gone)?;
            }
            _ => {}
        }
        if i % 5 == 4 {
            fs.commit()?;
        }
    }
    // Many entries in one directory, then most of them removed.
    let many = fs.mkdir(root, b"many", 0o755, 0, 0)?;
    for i in 0..300 {
        fs.create(many, format!("entry-with-a-longer-name-{i}").as_bytes(), S_IFREG | 0o644, 0, 0, 0)?;
    }
    fs.commit()?;
    for i in (0..300).filter(|i| i % 3 != 0) {
        let gone = fs.unlink(many, format!("entry-with-a-longer-name-{i}").as_bytes())?;
        fs.evict(gone)?;
    }
    fs.commit()
}

/// Run the workload with a cut after `cut` writes; returns the disk.
fn run(img: &[u8], cut: Option<usize>) -> CrashDisk {
    let mut fs = Fs::mount(CrashDisk::new(img.to_vec(), cut), Options::default()).unwrap();
    let _ = workload(&mut fs);
    fs.into_disk()
}

/// After a crash: e2fsck replays the journal, and so does our mount; either
/// way the result must be clean.
fn check_recovers(state: &[u8], tag: &str, what: &str) {
    // e2fsck's own recovery (and orphan processing), then a strict check.
    let a = tmp(&format!("crashed-e2fsck-{tag}.img"));
    std::fs::write(&a, state).unwrap();
    let (_, replay) = e2fsck(&a, &["-p"]);
    // Recovery may only replay the journal and free orphans: anything else
    // e2fsck had to fix is damage.
    let unexpected: Vec<&str> = replay.lines().filter(|l| !recovery_line(l)).collect();
    assert!(unexpected.is_empty(), "{what}: e2fsck fixed more than recovery:\n{replay}");
    let (ok, text) = e2fsck(&a, &["-fn"]);
    assert!(ok, "{what}: not clean after e2fsck's recovery:\n{replay}\n{text}");
    // slate-ext4's recovery: mount, release orphans, unmount.
    let mut fs = Fs::mount(CrashDisk::new(state.to_vec(), None), Options::default())
        .unwrap_or_else(|e| panic!("{what}: mount after the crash: {e:?}"));
    fs.sync_and_close().unwrap();
    let b = tmp(&format!("crashed-slate-{tag}.img"));
    std::fs::write(&b, &fs.into_disk().current).unwrap();
    let (ok, text) = e2fsck(&b, &["-fn"]);
    assert!(ok, "{what}: not clean after slate-ext4's recovery:\n{text}");
}

fn crash_everywhere(img: &[u8], tag: &str, label: &str) {
    let total = run(img, None).writes;
    assert!(total > 100, "the workload wrote only {total} times");
    let step = (total / 60).max(1);
    let mut cuts: Vec<usize> = (0..total).step_by(step).collect();
    cuts.extend(total.saturating_sub(5)..total);
    for cut in cuts {
        let disk = run(img, Some(cut));
        let (written, flushed) = disk.at_cut.expect("the cut happened");
        check_recovers(&written, tag, &format!("{label}: cut after {cut} of {total} writes"));
        check_recovers(&flushed, tag, &format!("{label}: cut after {cut} of {total} writes, unflushed lost"));
    }
}

#[test]
fn survives_power_cuts_4k() {
    if !have_e2fsprogs() {
        return;
    }
    let img = mkfs("crash-4k.img", "32M", &[]);
    crash_everywhere(&img, "4k", "4 KiB blocks");
}

#[test]
fn survives_power_cuts_1k_no_csum() {
    if !have_e2fsprogs() {
        return;
    }
    let img = mkfs("crash-1k.img", "16M", &["-b", "1024", "-O", "^metadata_csum,^64bit"]);
    crash_everywhere(&img, "1k", "1 KiB blocks");
}

/// Without a cut the files are all there after recovery, as written.
#[test]
fn committed_data_survives() {
    if !have_e2fsprogs() {
        return;
    }
    let img = mkfs("crash-full.img", "32M", &[]);
    let disk = run(&img, None);
    // The power goes after the last commit: nothing was unmounted.
    let mut fs = Fs::mount(CrashDisk::new(disk.durable, None), Options::default()).unwrap();
    let d0 = fs.lookup(2, b"d0").unwrap();
    let f0 = fs.lookup(d0, b"f0").unwrap();
    let mut buf = vec![0u8; 10];
    assert_eq!(fs.read(f0, 0, &mut buf).unwrap(), 10);
    assert_eq!(buf, pattern(10, 0));
    let moved = fs.lookup(2, b"moved7").unwrap();
    let mut buf = vec![0u8; 5000];
    assert_eq!(fs.read(moved, 0, &mut buf).unwrap(), 5000);
    assert_eq!(buf, pattern(5000, 7));
    // Orphans were released at mount: f4's name is gone and so is its inode.
    assert_eq!(fs.lookup(d0, b"f4"), Err(Error::NotFound));
    let many = fs.lookup(2, b"many").unwrap();
    assert_eq!(fs.read_dir(many).unwrap().len(), 2 + 100);
    fs.sync_and_close().unwrap();
    let b = tmp("full-after.img");
    std::fs::write(&b, &fs.into_disk().current).unwrap();
    let (ok, text) = e2fsck(&b, &["-fn"]);
    assert!(ok, "not clean:\n{text}");
}
