// SPDX-License-Identifier: MIT OR Apache-2.0

//! Host tests: operations, persistence, a randomized model check, snapshots,
//! crash consistency at every write prefix, and corruption detection.

use std::cell::RefCell;
use std::collections::BTreeMap as Map;
use std::rc::Rc;
use std::string::String;
use std::vec::Vec;

use super::*;

type WriteLog = Rc<RefCell<Vec<(u64, Vec<u8>)>>>;

/// An in-memory disk. Clones share the bytes; `log` records every write.
#[derive(Clone)]
struct MemDisk {
    data: Rc<RefCell<Vec<u8>>>,
    log: Option<WriteLog>,
}

std::thread_local! {
    /// Discards [`MemDisk`]s took: (offset, length) in bytes.
    static DISCARDS: RefCell<Vec<(u64, u64)>> = const { RefCell::new(Vec::new()) };
}

impl MemDisk {
    fn new(blocks: u64) -> MemDisk {
        MemDisk { data: Rc::new(RefCell::new(std::vec![0u8; blocks as usize * BLOCK])), log: None }
    }

    fn snapshot(&self) -> MemDisk {
        MemDisk { data: Rc::new(RefCell::new(self.data.borrow().clone())), log: None }
    }
}

impl Disk for MemDisk {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let d = self.data.borrow();
        let o = offset as usize;
        buf.copy_from_slice(d.get(o..o + buf.len()).ok_or(Error::Io)?);
        Ok(())
    }
    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        if let Some(l) = &self.log {
            l.borrow_mut().push((offset, buf.to_vec()));
        }
        let mut d = self.data.borrow_mut();
        let o = offset as usize;
        d.get_mut(o..o + buf.len()).ok_or(Error::Io)?.copy_from_slice(buf);
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
    fn now(&self) -> (i64, u32) {
        (1_700_000_000, 0)
    }
    /// Discarded bytes read back as zeros (so discarding anything in use
    /// shows up as checksum errors).
    fn discard(&mut self, offset: u64, len: u64) -> Result<()> {
        DISCARDS.with(|d| d.borrow_mut().push((offset, len)));
        let mut d = self.data.borrow_mut();
        let o = offset as usize;
        d.get_mut(o..o + len as usize).ok_or(Error::Io)?.fill(0);
        Ok(())
    }
}

fn new_fs(blocks: u64) -> Fs<MemDisk> {
    mkfs(MemDisk::new(blocks), blocks, "test", [7; 16], "root").unwrap()
}

const SV: u64 = 1;

fn read_all(fs: &mut Fs<MemDisk>, sv: u64, ino: u64) -> Vec<u8> {
    let size = fs.stat(sv, ino).unwrap().size as usize;
    let mut b = std::vec![0u8; size];
    assert_eq!(fs.read(sv, ino, 0, &mut b).unwrap(), size);
    b
}

fn assert_clean(fs: &mut Fs<MemDisk>) {
    let p = fs.check().unwrap();
    assert!(p.is_empty(), "fsck: {p:?}");
}

#[test]
fn files_directories_links() {
    let mut fs = new_fs(2048);
    let d = fs.mkdir(SV, ROOT_INO, b"etc", 0o755, 0, 0).unwrap();
    let f = fs.create(SV, d, b"passwd", 0o644, 0, 0, 0).unwrap();
    assert_eq!(fs.write(SV, f, 0, b"root:x:0:0\n").unwrap(), 11);
    assert_eq!(read_all(&mut fs, SV, f), b"root:x:0:0\n");
    assert_eq!(fs.lookup(SV, d, b"passwd").unwrap(), f);
    assert_eq!(fs.create(SV, d, b"passwd", 0o644, 0, 0, 0), Err(Error::Exists));
    // Multi-block, partial and sparse writes.
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let g = fs.create(SV, ROOT_INO, b"big", 0o644, 0, 0, 0).unwrap();
    fs.write(SV, g, 0, &big).unwrap();
    fs.write(SV, g, 5000, b"PATCH").unwrap();
    let mut want = big.clone();
    want[5000..5005].copy_from_slice(b"PATCH");
    assert_eq!(read_all(&mut fs, SV, g), want);
    let h = fs.create(SV, ROOT_INO, b"sparse", 0o644, 0, 0, 0).unwrap();
    fs.write(SV, h, 1 << 20, b"end").unwrap();
    let s = read_all(&mut fs, SV, h);
    assert_eq!(s.len(), (1 << 20) + 3);
    assert!(s[..1 << 20].iter().all(|&b| b == 0));
    // Truncate and grow again: the tail reads as zeros.
    fs.truncate(SV, g, 4100).unwrap();
    fs.truncate(SV, g, 9000).unwrap();
    let t = read_all(&mut fs, SV, g);
    assert_eq!(&t[..4100], &want[..4100]);
    assert!(t[4100..].iter().all(|&b| b == 0));
    // Links, symlinks, rename, unlink, rmdir.
    fs.link(SV, ROOT_INO, b"passwd-link", f).unwrap();
    assert_eq!(fs.stat(SV, f).unwrap().nlink, 2);
    let l = fs.symlink(SV, ROOT_INO, b"p", b"etc/passwd", 0, 0).unwrap();
    assert_eq!(fs.readlink(SV, l).unwrap(), b"etc/passwd");
    let sub = fs.mkdir(SV, d, b"sub", 0o700, 0, 0).unwrap();
    assert_eq!(fs.stat(SV, d).unwrap().nlink, 3);
    fs.rename(SV, d, b"sub", ROOT_INO, b"moved").unwrap();
    assert_eq!(fs.stat(SV, sub).unwrap().parent, ROOT_INO);
    assert_eq!(fs.stat(SV, d).unwrap().nlink, 2);
    assert_eq!(fs.rename(SV, ROOT_INO, b"moved", sub, b"x"), Err(Error::Invalid));
    assert_eq!(fs.rmdir(SV, ROOT_INO, b"etc"), Err(Error::NotEmpty));
    let gone = fs.unlink(SV, d, b"passwd").unwrap();
    assert_eq!(fs.stat(SV, gone).unwrap().nlink, 1);
    assert_eq!(fs.unlink(SV, ROOT_INO, b"passwd-link").unwrap(), f);
    fs.evict(SV, f).unwrap();
    assert_eq!(fs.stat(SV, f), Err(Error::NotFound));
    fs.rmdir(SV, ROOT_INO, b"etc").unwrap();
    // Replacing rename leaves the old target an orphan to evict.
    let a = fs.create(SV, ROOT_INO, b"a", 0o644, 0, 0, 0).unwrap();
    let b = fs.create(SV, ROOT_INO, b"b", 0o644, 0, 0, 0).unwrap();
    assert_eq!(fs.rename(SV, ROOT_INO, b"a", ROOT_INO, b"b").unwrap(), Some(b));
    fs.evict(SV, b).unwrap();
    assert_eq!(fs.lookup(SV, ROOT_INO, b"b").unwrap(), a);
    assert_clean(&mut fs);
    fs.commit().unwrap();
    assert_clean(&mut fs);
}

#[test]
fn persists_across_mounts() {
    let mut fs = new_fs(1024);
    let f = fs.create(SV, ROOT_INO, b"note", 0o600, 1000, 1000, 0).unwrap();
    fs.write(SV, f, 0, b"kept").unwrap();
    fs.commit().unwrap();
    let generation = fs.generation();
    let disk = fs.into_disk();
    let mut fs = Fs::mount(disk.clone(), false).unwrap();
    assert_eq!(fs.generation(), generation);
    let f = fs.lookup(SV, ROOT_INO, b"note").unwrap();
    assert_eq!(read_all(&mut fs, SV, f), b"kept");
    assert_eq!(fs.stat(SV, f).unwrap().uid, 1000);
    // Uncommitted changes are lost on a "crash" (remount without commit).
    fs.write(SV, f, 0, b"lost").unwrap();
    let mut fs = Fs::mount(disk, false).unwrap();
    let f = fs.lookup(SV, ROOT_INO, b"note").unwrap();
    assert_eq!(read_all(&mut fs, SV, f), b"kept");
}

/// A tiny deterministic generator for the randomized tests.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Everything visible in a subvolume: path -> contents (directories end in '/').
fn listing(fs: &mut Fs<MemDisk>, sv: u64) -> Map<String, Vec<u8>> {
    let mut out = Map::new();
    let mut stack = std::vec![(ROOT_INO, String::new())];
    while let Some((dir, path)) = stack.pop() {
        for (_, d) in fs.readdir(sv, dir).unwrap() {
            let p = std::format!("{path}/{}", String::from_utf8_lossy(&d.name));
            if d.kind == DT_DIR {
                out.insert(std::format!("{p}/"), Vec::new());
                stack.push((d.ino, p));
            } else if d.kind == DT_LNK {
                out.insert(p, fs.readlink(sv, d.ino).unwrap());
            } else {
                out.insert(p, read_all(fs, sv, d.ino));
            }
        }
    }
    out
}

#[test]
fn random_operations_match_a_model() {
    let mut rng = Rng(0x5eed_1234);
    let mut disk = MemDisk::new(8192);
    let mut fs = mkfs(disk.clone(), 8192, "m", [1; 16], "root").unwrap();
    let mut model: Map<String, Vec<u8>> = Map::new();
    let names: Vec<String> = (0..40).map(|i| std::format!("f{i}")).collect();
    for step in 0..3000 {
        let name = &names[rng.below(names.len() as u64) as usize];
        let path = std::format!("/{name}");
        match rng.below(10) {
            0..=3 => {
                // Write somewhere in the file (maybe creating it).
                let ino = match fs.lookup(SV, ROOT_INO, name.as_bytes()) {
                    Ok(i) => i,
                    Err(_) => fs.create(SV, ROOT_INO, name.as_bytes(), 0o644, 0, 0, 0).unwrap(),
                };
                let content = model.entry(path.clone()).or_default();
                let off = rng.below(20_000) as usize;
                let len = rng.below(9000) as usize + 1;
                let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                fs.write(SV, ino, off as u64, &data).unwrap();
                if content.len() < off + len {
                    content.resize(off + len, 0);
                }
                content[off..off + len].copy_from_slice(&data);
            }
            4 => {
                if let Ok(ino) = fs.lookup(SV, ROOT_INO, name.as_bytes()) {
                    let size = rng.below(25_000);
                    fs.truncate(SV, ino, size).unwrap();
                    model.get_mut(&path).unwrap().resize(size as usize, 0);
                }
            }
            5 => {
                if let Ok(ino) = fs.unlink(SV, ROOT_INO, name.as_bytes()) {
                    fs.evict(SV, ino).unwrap();
                    model.remove(&path);
                }
            }
            6 => {
                let other = &names[rng.below(names.len() as u64) as usize];
                if other != name && model.contains_key(&path) {
                    if let Ok(Some(old)) = fs.rename(SV, ROOT_INO, name.as_bytes(), ROOT_INO, other.as_bytes()) {
                        fs.evict(SV, old).unwrap();
                    }
                    let v = model.remove(&path).unwrap();
                    model.insert(std::format!("/{other}"), v);
                }
            }
            7 => fs.commit().unwrap(),
            8 if step % 7 == 0 => {
                fs.commit().unwrap();
                disk = fs.into_disk();
                fs = Fs::mount(disk.clone(), false).unwrap();
            }
            _ => {}
        }
        if step % 500 == 0 {
            assert_eq!(listing(&mut fs, SV), model, "step {step}");
            assert_clean(&mut fs);
        }
    }
    fs.commit().unwrap();
    assert_eq!(listing(&mut fs, SV), model);
    assert_clean(&mut fs);
    // Deleting everything gives the space back.
    for name in &names {
        if let Ok(ino) = fs.unlink(SV, ROOT_INO, name.as_bytes()) {
            fs.evict(SV, ino).unwrap();
        }
    }
    fs.commit().unwrap();
    let free = fs.totals().free;
    assert!(free > 8192 - 16, "free {free}");
}

#[test]
fn snapshots_are_isolated() {
    let mut fs = new_fs(4096);
    let f = fs.create(SV, ROOT_INO, b"file", 0o644, 0, 0, 0).unwrap();
    fs.write(SV, f, 0, &std::vec![1u8; 50_000]).unwrap();
    let ro = fs.snapshot(SV, "snap", true).unwrap();
    assert_eq!(fs.write(ro, f, 0, b"x"), Err(Error::ReadOnly));
    let rw = fs.snapshot(SV, "clone", false).unwrap();
    fs.write(SV, f, 0, &std::vec![2u8; 50_000]).unwrap();
    fs.unlink(SV, ROOT_INO, b"file").unwrap();
    fs.evict(SV, f).unwrap();
    fs.write(rw, f, 100, b"clone-only").unwrap();
    fs.commit().unwrap();
    assert!(read_all(&mut fs, ro, f).iter().all(|&b| b == 1));
    let c = read_all(&mut fs, rw, f);
    assert_eq!(&c[100..110], b"clone-only");
    assert_eq!(fs.lookup(SV, ROOT_INO, b"file"), Err(Error::NotFound));
    assert_clean(&mut fs);
    // After a remount everything is still there.
    let mut fs = Fs::mount(fs.into_disk(), false).unwrap();
    assert!(read_all(&mut fs, ro, f).iter().all(|&b| b == 1));
    assert_eq!(fs.subvolumes().iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["root", "snap", "clone"]);
    // Deleting the snapshots frees their blocks.
    let before = fs.totals().free;
    fs.delete_subvolume(ro).unwrap();
    fs.delete_subvolume(rw).unwrap();
    fs.commit().unwrap();
    assert!(fs.totals().free > before + 12, "{} -> {}", before, fs.totals().free);
    assert_clean(&mut fs);
}

/// Mount every prefix of the writes of a commit sequence: each must give
/// one of the committed states.
#[test]
fn crash_at_every_write_mounts_a_committed_state() {
    let base = new_fs(512);
    let start = base.into_disk();
    let mut disk = start.snapshot();
    let log = Rc::new(RefCell::new(Vec::new()));
    disk.log = Some(log.clone());
    let mut fs = Fs::mount(disk, false).unwrap();
    let mut states = std::vec![listing(&mut fs, SV)];
    let mut rng = Rng(99);
    for round in 0..4 {
        for i in 0..3 {
            let name = std::format!("r{round}f{i}");
            let ino = fs.create(SV, ROOT_INO, name.as_bytes(), 0o644, 0, 0, 0).unwrap();
            let data: Vec<u8> = (0..rng.below(20_000) + 1).map(|_| rng.next() as u8).collect();
            fs.write(SV, ino, 0, &data).unwrap();
        }
        if round > 0 {
            let victim = std::format!("r{}f0", round - 1);
            let ino = fs.unlink(SV, ROOT_INO, victim.as_bytes()).unwrap();
            fs.evict(SV, ino).unwrap();
        }
        fs.commit().unwrap();
        states.push(listing(&mut fs, SV));
    }
    let writes = log.borrow().clone();
    assert!(writes.len() > 20);
    for n in 0..=writes.len() {
        let mut d = start.snapshot();
        for (off, data) in &writes[..n] {
            d.write(*off, data).unwrap();
        }
        let mut fs = Fs::mount(d, true).unwrap_or_else(|e| panic!("prefix {n}: mount failed: {e:?}"));
        let l = listing(&mut fs, SV);
        assert!(states.contains(&l), "prefix {n} mounted a state that was never committed");
        assert_clean(&mut fs);
    }
}

#[test]
fn corruption_is_detected() {
    let mut fs = new_fs(1024);
    let f = fs.create(SV, ROOT_INO, b"data", 0o644, 0, 0, 0).unwrap();
    fs.write(SV, f, 0, &std::vec![9u8; 10_000]).unwrap();
    fs.commit().unwrap();
    // Find the file's first data block and damage it.
    let (_, e) = fs.extent_at(SV, f, 0).unwrap().unwrap();
    let disk = fs.into_disk();
    disk.data.borrow_mut()[e.start as usize * BLOCK + 10] ^= 0xff;
    let mut fs = Fs::mount(disk.clone(), false).unwrap();
    let mut b = std::vec![0u8; 10_000];
    assert_eq!(fs.read(SV, f, 0, &mut b), Err(Error::Checksum(e.start)));
    // Damage the newest superblock: the older one takes over.
    let generation = fs.generation();
    disk.data.borrow_mut()[(generation % 2) as usize * BLOCK + 100] ^= 0xff;
    let fs = Fs::mount(disk.clone(), true).unwrap();
    assert_eq!(fs.generation(), generation - 1);
}

#[test]
fn full_disk_and_orphans() {
    let mut fs = new_fs(256);
    let f = fs.create(SV, ROOT_INO, b"fill", 0o644, 0, 0, 0).unwrap();
    let chunk = std::vec![3u8; BLOCK];
    let mut off = 0u64;
    loop {
        match fs.write(SV, f, off, &chunk) {
            Ok(_) => off += BLOCK as u64,
            Err(Error::NoSpace) => break,
            Err(e) => panic!("{e:?}"),
        }
    }
    assert!(off > 100 * BLOCK as u64);
    // Unlinked but still open at a crash: freed at the next mount.
    fs.truncate(SV, f, 0).unwrap();
    fs.write(SV, f, 0, &std::vec![4u8; 20 * BLOCK]).unwrap();
    fs.unlink(SV, ROOT_INO, b"fill").unwrap();
    fs.commit().unwrap();
    assert!(fs.stat(SV, f).is_ok());
    let mut fs = Fs::mount(fs.into_disk(), false).unwrap();
    assert_eq!(fs.stat(SV, f), Err(Error::NotFound));
    assert!(fs.totals().free > 256 - 48);
    assert_clean(&mut fs);
}

#[test]
fn readdir_positions_are_stable() {
    let mut fs = new_fs(2048);
    for i in 0..400 {
        fs.create(SV, ROOT_INO, std::format!("n{i}").as_bytes(), 0o644, 0, 0, 0).unwrap();
    }
    let all = fs.readdir(SV, ROOT_INO).unwrap();
    assert_eq!(all.len(), 400);
    // Delete every other entry while "iterating": the rest keep positions.
    let mut seen = 0;
    for (i, (pos, d)) in all.iter().enumerate() {
        if i % 2 == 0 {
            let ino = fs.unlink(SV, ROOT_INO, &d.name).unwrap();
            fs.evict(SV, ino).unwrap();
        }
        let now = fs.readdir(SV, ROOT_INO).unwrap();
        assert!(now.iter().filter(|(p, _)| p > pos).all(|(_, x)| all.iter().any(|(_, y)| y.name == x.name)));
        seen += 1;
    }
    assert_eq!(seen, 400);
    assert_eq!(fs.readdir(SV, ROOT_INO).unwrap().len(), 200);
    assert_clean(&mut fs);
}

#[test]
fn many_files_in_deep_trees() {
    let mut fs = new_fs(16384);
    let mut dirs = std::vec![ROOT_INO];
    for i in 0..30 {
        let parent = dirs[i / 3];
        dirs.push(fs.mkdir(SV, parent, std::format!("d{i}").as_bytes(), 0o755, 0, 0).unwrap());
    }
    let mut files = Vec::new();
    for i in 0..3000u32 {
        let d = dirs[(i as usize * 7) % dirs.len()];
        let name = std::format!("file-{i}-{}", "x".repeat((i % 40) as usize));
        let ino = fs.create(SV, d, name.as_bytes(), 0o644, i, i, 0).unwrap();
        fs.write(SV, ino, 0, &i.to_le_bytes().repeat((i % 300 + 1) as usize)).unwrap();
        files.push((d, name, ino, i));
        if i % 700 == 0 {
            fs.commit().unwrap();
        }
    }
    fs.commit().unwrap();
    assert_clean(&mut fs);
    let mut fs = Fs::mount(fs.into_disk(), false).unwrap();
    for (d, name, ino, i) in files.iter().step_by(37) {
        assert_eq!(fs.lookup(SV, *d, name.as_bytes()).unwrap(), *ino);
        assert_eq!(read_all(&mut fs, SV, *ino), i.to_le_bytes().repeat((*i % 300 + 1) as usize));
    }
    // Remove nine in ten; the trees shrink and stay consistent.
    let before = fs.totals().free;
    for (d, name, _, i) in &files {
        if i % 10 != 0 {
            let ino = fs.unlink(SV, *d, name.as_bytes()).unwrap();
            fs.evict(SV, ino).unwrap();
        }
    }
    fs.commit().unwrap();
    assert!(fs.totals().free > before + 1000, "{before} -> {}", fs.totals().free);
    assert_clean(&mut fs);
    let total: usize = dirs.iter().map(|d| fs.readdir(SV, *d).unwrap().len()).sum();
    assert_eq!(total, 300 + 30);
}

#[test]
fn extended_attributes() {
    let mut fs = new_fs(1024);
    let f = fs.create(SV, ROOT_INO, b"f", 0o644, 0, 0, 0).unwrap();
    let d = fs.mkdir(SV, ROOT_INO, b"d", 0o755, 0, 0).unwrap();
    fs.set_xattr(SV, d, b"trusted.overlay.opaque", b"y", 0).unwrap();
    fs.set_xattr(SV, f, b"user.a", b"1", 0).unwrap();
    fs.set_xattr(SV, f, b"user.b", b"22", 0).unwrap();
    assert_eq!(fs.get_xattr(SV, d, b"trusted.overlay.opaque").unwrap(), b"y");
    assert_eq!(fs.set_xattr(SV, f, b"user.a", b"x", Fs::<MemDisk>::XATTR_CREATE), Err(Error::Exists));
    assert_eq!(fs.set_xattr(SV, f, b"user.c", b"x", Fs::<MemDisk>::XATTR_REPLACE), Err(Error::NotFound));
    fs.set_xattr(SV, f, b"user.a", b"replaced", Fs::<MemDisk>::XATTR_REPLACE).unwrap();
    let mut names = fs.list_xattrs(SV, f).unwrap();
    names.sort();
    assert_eq!(names, std::vec![b"user.a".to_vec(), b"user.b".to_vec()]);
    // One bucket holds a limited amount.
    assert_eq!(fs.set_xattr(SV, f, b"user.big", &[0u8; 4000], 0), Err(Error::NoSpace));
    fs.remove_xattr(SV, f, b"user.b").unwrap();
    assert_eq!(fs.get_xattr(SV, f, b"user.b"), Err(Error::NotFound));
    fs.commit().unwrap();
    // Kept across a remount; checked; gone with the inode.
    let mut fs = Fs::mount(fs.into_disk(), false).unwrap();
    assert_eq!(fs.get_xattr(SV, f, b"user.a").unwrap(), b"replaced");
    assert!(fs.check().unwrap().is_empty());
    fs.unlink(SV, ROOT_INO, b"f").unwrap();
    fs.evict(SV, f).unwrap();
    fs.commit().unwrap();
    assert!(fs.check().unwrap().is_empty());
    assert_eq!(fs.list_xattrs(SV, d).unwrap(), std::vec![b"trusted.overlay.opaque".to_vec()]);
}

/// A sparse disk: only written blocks take memory.
#[derive(Clone, Default)]
struct SparseDisk(Rc<RefCell<Map<u64, Vec<u8>>>>);

impl Disk for SparseDisk {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let d = self.0.borrow();
        for (i, chunk) in buf.chunks_mut(BLOCK).enumerate() {
            let b = offset / BLOCK as u64 + i as u64;
            match d.get(&b) {
                Some(data) => chunk.copy_from_slice(&data[..chunk.len()]),
                None => chunk.fill(0),
            }
        }
        Ok(())
    }
    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        let mut d = self.0.borrow_mut();
        for (i, chunk) in buf.chunks(BLOCK).enumerate() {
            d.insert(offset / BLOCK as u64 + i as u64, chunk.to_vec());
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
    fn now(&self) -> (i64, u32) {
        (1_700_000_000, 0)
    }
}

/// A 256 GiB file system (the reference PC's SSD is this size): no
/// bitmap allocation may exceed the kernel heap's largest block, and the
/// whole cycle (mkfs, write, commit, mount, fsck) works.
#[test]
fn large_file_system_keeps_allocations_small() {
    let blocks = (256u64 << 30) / BLOCK as u64;
    let disk = SparseDisk::default();
    let mut f = mkfs(disk.clone(), blocks, "big", [9; 16], "system-1").unwrap();
    assert!(f.space.used.largest_chunk() <= 512 * 1024);
    assert!(f.space.txn.largest_chunk() <= 512 * 1024);
    let sv = f.subvol_by_name("system-1").unwrap();
    let ino = f.create(sv, ROOT_INO, b"hello", 0o100_644, 0, 0, 0).unwrap();
    f.write(sv, ino, 0, b"on a big disk").unwrap();
    f.sync().unwrap();
    let mut g = Fs::mount(disk, false).unwrap();
    assert!(g.space.used.largest_chunk() <= 512 * 1024);
    let ino = g.lookup(sv, ROOT_INO, b"hello").unwrap();
    let mut buf = [0u8; 13];
    g.read(sv, ino, 0, &mut buf).unwrap();
    assert_eq!(&buf, b"on a big disk");
    assert!(g.check().unwrap().is_empty());
    assert!(g.totals().free > blocks - 1000);
}

#[test]
fn repair_fixes_what_check_finds() {
    let mut fs = new_fs(4096);
    let sv = fs.subvol_by_name("root").unwrap();
    let keep = fs.create(sv, ROOT_INO, b"keep", 0o644, 0, 0, 0).unwrap();
    fs.write(sv, keep, 0, b"precious").unwrap();
    let a = fs.mkdir(sv, ROOT_INO, b"a", 0o755, 0, 0).unwrap();
    let b = fs.mkdir(sv, ROOT_INO, b"b", 0o755, 0, 0).unwrap();
    let lost = fs.create(sv, a, b"lost", 0o644, 0, 0, 0).unwrap();
    fs.write(sv, lost, 0, b"found again").unwrap();
    let gone = fs.create(sv, ROOT_INO, b"gone", 0o644, 0, 0, 0).unwrap();
    fs.write(sv, gone, 0, &[9u8; 10000]).unwrap();
    fs.set_xattr(sv, gone, b"user.x", b"1", 0).unwrap();
    fs.commit().unwrap();
    assert_clean(&mut fs);
    // The damage: a name with no inode, an inode with no name, a wrong
    // link count and parent, an entry under the wrong hash, an inode gone
    // with its extents and attributes left.
    fs.add_entry(sv, ROOT_INO, b"ghost", 9999, DT_REG).unwrap();
    fs.remove_entry(sv, a, b"lost").unwrap();
    let mut k = fs.stat(sv, keep).unwrap();
    k.nlink = 5;
    fs.put_inode(sv, keep, &k).unwrap();
    let mut ai = fs.stat(sv, a).unwrap();
    ai.parent = b;
    fs.put_inode(sv, a, &ai).unwrap();
    let misplaced = fs.create(sv, b, b"misplaced", 0o644, 0, 0, 0).unwrap();
    fs.remove_entry(sv, b, b"misplaced").unwrap();
    let entry = Dirent { ino: misplaced, kind: DT_REG, name: b"misplaced".to_vec() };
    fs.put(sv, Key::new(b, KIND_DIRENT, 12345), encode_dirents(&[entry])).unwrap();
    fs.del(sv, Key::new(gone, KIND_INODE, 0)).unwrap();
    fs.commit().unwrap();
    let found = fs.check().unwrap();
    assert!(found.len() >= 7, "{found:?}");

    let (done, left) = fs.repair().unwrap();
    assert!(left.is_empty(), "left: {left:?}\ndone: {done:?}");
    assert!(done.len() >= 7, "{done:?}");
    assert_eq!(fs.lookup(sv, ROOT_INO, b"ghost"), Err(Error::NotFound));
    assert_eq!(fs.lookup(sv, ROOT_INO, b"gone"), Err(Error::NotFound));
    assert_eq!(fs.stat(sv, keep).unwrap().nlink, 1);
    assert_eq!(fs.stat(sv, a).unwrap().parent, ROOT_INO);
    assert_eq!(fs.lookup(sv, b, b"misplaced").unwrap(), misplaced);
    let lf = fs.lookup(sv, ROOT_INO, b"lost+found").unwrap();
    let back = fs.lookup(sv, lf, std::format!("#{lost}").as_bytes()).unwrap();
    assert_eq!(read_all(&mut fs, sv, back), b"found again");
    assert_eq!(fs.stat(sv, back).unwrap().nlink, 1);
    assert_eq!(read_all(&mut fs, sv, keep), b"precious");
    // Mounted again: still clean, and the lost blocks are free again.
    let free = fs.totals().free;
    let mut fs = Fs::mount(fs.into_disk(), false).unwrap();
    assert_clean(&mut fs);
    assert_eq!(fs.totals().free, free);
}

#[test]
fn discards_only_what_no_superblock_uses() {
    let mut fs = new_fs(4096);
    fs.set_discard(true);
    let sv = fs.subvol_by_name("root").unwrap();
    let mut kept = Vec::new();
    for i in 0..30u8 {
        let f = fs.create(sv, ROOT_INO, std::format!("f{i}").as_bytes(), 0o644, 0, 0, 0).unwrap();
        fs.write(sv, f, 0, &std::vec![i; 20_000 + usize::from(i) * 100]).unwrap();
        kept.push((f, i));
    }
    fs.commit().unwrap();
    for i in (0..30u8).step_by(3) {
        let gone = fs.unlink(sv, ROOT_INO, std::format!("f{i}").as_bytes()).unwrap();
        fs.evict(sv, gone).unwrap();
    }
    kept.retain(|&(_, i)| i % 3 != 0);
    DISCARDS.with(|d| d.borrow_mut().clear());
    fs.commit().unwrap();
    // Freed by this commit: the previous generation may still need them.
    assert!(DISCARDS.with(|d| d.borrow().is_empty()));
    // The next commit (with a change, or there is nothing to commit).
    let t = fs.create(sv, ROOT_INO, b"tick", 0o644, 0, 0, 0).unwrap();
    fs.write(sv, t, 0, b"x").unwrap();
    fs.commit().unwrap();
    // Two commits on, nothing refers to them.
    let online: u64 = DISCARDS.with(|d| d.borrow().iter().map(|&(_, n)| n).sum());
    assert!(online >= 10 * 20_000, "only {online} bytes discarded");
    let trimmed = fs.trim(0, u64::MAX, 0).unwrap();
    assert!(trimmed > 8 << 20, "trimmed only {trimmed}");
    for &(f, i) in &kept {
        assert_eq!(read_all(&mut fs, sv, f), std::vec![i; 20_000 + usize::from(i) * 100]);
    }
    assert_clean(&mut fs);
    let mut fs = Fs::mount(fs.into_disk(), false).unwrap();
    assert_clean(&mut fs);
    for &(f, i) in &kept {
        assert_eq!(read_all(&mut fs, sv, f), std::vec![i; 20_000 + usize::from(i) * 100]);
    }
}

/// Changes made while a commit is written and walked elsewhere (as the
/// kernel does without the lock) wait for the next commit, and never land
/// in blocks the commit in flight uses.
#[test]
fn changes_during_a_commit_wait_for_the_next() {
    during_a_commit(false);
    during_a_commit(true);
}

/// With free space from what the transaction dropped, or from a walk.
fn during_a_commit(walk: bool) {
    let disk = MemDisk::new(4096);
    let mut fs = mkfs(disk.clone(), 4096, "test", [7; 16], "root").unwrap();
    let a = fs.create(SV, ROOT_INO, b"a", 0o644, 0, 0, 0).unwrap();
    fs.write(SV, a, 0, &std::vec![1; 50_000]).unwrap();
    let c = fs.begin_commit().unwrap().unwrap();
    // a's blocks were allocated in this transaction, but the commit holds
    // them now: b must not get them.
    fs.truncate(SV, a, 0).unwrap();
    let b = fs.create(SV, ROOT_INO, b"b", 0o644, 0, 0, 0).unwrap();
    fs.write(SV, b, 0, &std::vec![2; 200_000]).unwrap();
    assert!(fs.begin_commit().is_err(), "two commits at once");
    let mut other = disk.clone();
    c.write(&mut other).unwrap();
    let reach = (walk || c.needs_walk()).then(|| c.reachable(&mut other).unwrap());
    fs.write(SV, b, 200_000, &std::vec![3; 10_000]).unwrap();
    fs.end_commit(c, reach);

    let mut seen = Fs::mount(disk.snapshot(), true).unwrap();
    assert_eq!(read_all(&mut seen, SV, a), std::vec![1; 50_000]);
    assert!(seen.lookup(SV, ROOT_INO, b"b").is_err());
    assert_clean(&mut seen);

    fs.commit().unwrap();
    assert_clean(&mut fs);
    let free = fs.totals().free;
    let mut fs = Fs::mount(fs.into_disk(), false).unwrap();
    assert_eq!(fs.totals().free, free, "free space differs from a fresh count");
    assert!(read_all(&mut fs, SV, a).is_empty());
    let mut want = std::vec![2; 200_000];
    want.extend(std::vec![3; 10_000]);
    assert_eq!(read_all(&mut fs, SV, b), want);
    assert_clean(&mut fs);
}

/// A commit given up (its writes failed) leaves the old state, and the
/// next one writes everything.
#[test]
fn an_aborted_commit_is_written_by_the_next() {
    let mut fs = new_fs(4096);
    let a = fs.create(SV, ROOT_INO, b"a", 0o644, 0, 0, 0).unwrap();
    fs.write(SV, a, 0, b"first").unwrap();
    let c = fs.begin_commit().unwrap().unwrap();
    fs.abort_commit(c);
    let b = fs.create(SV, ROOT_INO, b"b", 0o644, 0, 0, 0).unwrap();
    fs.write(SV, b, 0, b"second").unwrap();
    assert_eq!(read_all(&mut fs, SV, a), b"first");
    fs.commit().unwrap();
    let mut fs = Fs::mount(fs.into_disk(), false).unwrap();
    assert_eq!(read_all(&mut fs, SV, a), b"first");
    assert_eq!(read_all(&mut fs, SV, b), b"second");
    assert_clean(&mut fs);
}

/// Free space kept from what transactions drop, with snapshots taken,
/// written (writable ones) and deleted at random: every commit is checked
/// against a walk (`Fs::end_commit` under test), and each snapshot keeps
/// what it held.
#[test]
fn incremental_free_space_with_snapshots() {
    for seed in [0xf4ee_5ace, 0x5eed_0001, 0x5eed_0002, 0x5eed_0003] {
        snapshots_at_random(seed, false);
        snapshots_at_random(seed, true);
    }
}

/// `each`: commit after every step (so the step that breaks a count is
/// the one that fails).
fn snapshots_at_random(seed: u64, each: bool) {
    let mut rng = Rng(seed);
    let mut disk = MemDisk::new(16384);
    let mut fs = mkfs(disk.clone(), 16384, "s", [3; 16], "root").unwrap();
    let names: Vec<String> = (0..24).map(|i| std::format!("f{i}")).collect();
    // Each subvolume's expected contents, by id.
    let mut models: Map<u64, Map<String, Vec<u8>>> = Map::new();
    models.insert(SV, Map::new());
    let mut snaps = 0;
    for step in 0..2500 {
        let ids: Vec<u64> = models.keys().copied().collect();
        let sv = ids[rng.below(ids.len() as u64) as usize];
        let ro = fs.subvolumes().iter().any(|s| s.id == sv && s.readonly);
        let name = &names[rng.below(names.len() as u64) as usize];
        match rng.below(12) {
            0..=4 if !ro => {
                let ino = match fs.lookup(sv, ROOT_INO, name.as_bytes()) {
                    Ok(i) => i,
                    Err(_) => fs.create(sv, ROOT_INO, name.as_bytes(), 0o644, 0, 0, 0).unwrap(),
                };
                let content = models.get_mut(&sv).unwrap().entry(std::format!("/{name}")).or_default();
                let off = rng.below(30_000) as usize;
                let len = rng.below(12_000) as usize + 1;
                let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                fs.write(sv, ino, off as u64, &data).unwrap();
                if content.len() < off + len {
                    content.resize(off + len, 0);
                }
                content[off..off + len].copy_from_slice(&data);
            }
            5 if !ro => {
                if let Ok(ino) = fs.lookup(sv, ROOT_INO, name.as_bytes()) {
                    let size = rng.below(20_000);
                    fs.truncate(sv, ino, size).unwrap();
                    models.get_mut(&sv).unwrap().get_mut(&std::format!("/{name}")).unwrap().resize(size as usize, 0);
                }
            }
            6 if !ro => {
                if let Ok(ino) = fs.unlink(sv, ROOT_INO, name.as_bytes()) {
                    fs.evict(sv, ino).unwrap();
                    models.get_mut(&sv).unwrap().remove(&std::format!("/{name}"));
                }
            }
            7 if models.len() < 6 => {
                snaps += 1;
                let id = fs.snapshot(sv, &std::format!("s{snaps}"), rng.below(2) == 0).unwrap();
                let copy = models[&sv].clone();
                models.insert(id, copy);
            }
            8 if sv != SV && rng.below(3) == 0 => {
                fs.delete_subvolume(sv).unwrap();
                models.remove(&sv);
            }
            9 => fs.commit().unwrap(),
            10 if step % 5 == 0 => {
                fs.commit().unwrap();
                disk = fs.into_disk();
                fs = Fs::mount(disk.clone(), false).unwrap();
            }
            _ => {}
        }
        if each {
            fs.commit().unwrap();
        }
        if step % 250 == 0 {
            for (&id, m) in &models {
                assert_eq!(&listing(&mut fs, id), m, "subvolume {id}, step {step}");
            }
            assert_clean(&mut fs);
        }
    }
    fs.commit().unwrap();
    for (&id, m) in &models {
        assert_eq!(&listing(&mut fs, id), m, "subvolume {id}");
    }
    assert_clean(&mut fs);
    let free = fs.totals().free;
    let fs = Fs::mount(fs.into_disk(), false).unwrap();
    assert_eq!(fs.totals().free, free, "free space differs from a fresh count");
}

/// A subvolume's usage: all it reaches and what is its own, shared
/// blocks counted out as a snapshot diverges (ADR 0183's phase 6).
#[test]
fn usage_of_snapshots() {
    let mut fs = new_fs(8192);
    let f = fs.create(SV, ROOT_INO, b"file", 0o644, 0, 0, 0).unwrap();
    fs.write(SV, f, 0, &std::vec![1u8; 400_000]).unwrap();
    let (all, own) = fs.usage(SV).unwrap();
    assert!(all >= 400_000 && own == all, "{all} {own}");
    // A snapshot shares everything: neither has much of its own.
    let snap = fs.snapshot(SV, "snap", false).unwrap();
    let (a2, o2) = fs.usage(SV).unwrap();
    let (sa, so) = fs.usage(snap).unwrap();
    assert_eq!(a2, all);
    assert_eq!(sa, all);
    assert!(o2 < 4 * 4096 && so < 4 * 4096, "{o2} {so}");
    // A new file in the snapshot is its own.
    let g = fs.create(snap, ROOT_INO, b"new", 0o644, 0, 0, 0).unwrap();
    fs.write(snap, g, 0, &std::vec![2u8; 200_000]).unwrap();
    let (_, so2) = fs.usage(snap).unwrap();
    assert!(so2 >= 200_000, "{so2}");
    // Deleting it frees about what it said was its own.
    let before = fs.totals().free;
    fs.delete_subvolume(snap).unwrap();
    fs.commit().unwrap();
    let freed = (fs.totals().free - before) * 4096;
    assert!(freed + 8 * 4096 >= so2 && freed <= so2 + 8 * 4096, "freed {freed}, said {so2}");
    assert_eq!(fs.usage(snap), Err(Error::NotFound));
    assert_clean(&mut fs);
}
