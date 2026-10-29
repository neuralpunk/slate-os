// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests against real ext4 images: made by the host's mkfs.ext4 (with -d to
//! populate them), read and modified through slate-ext4, then checked by
//! e2fsck and read back by debugfs. Skipped when e2fsprogs is missing.

use std::collections::BTreeMap;
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use slate_ext4::layout::{S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};
use slate_ext4::{Disk, Error, Fs, Options, SetAttr};

struct FileDisk(std::fs::File);

impl Disk for FileDisk {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> slate_ext4::Result<()> {
        self.0.read_exact_at(buf, offset).map_err(|_| Error::Io)
    }
    fn write(&mut self, offset: u64, buf: &[u8]) -> slate_ext4::Result<()> {
        self.0.write_all_at(buf, offset).map_err(|_| Error::Io)
    }
    fn flush(&mut self) -> slate_ext4::Result<()> {
        Ok(())
    }
    fn now(&self) -> (i64, u32) {
        let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
        (d.as_secs() as i64, d.subsec_nanos())
    }
    /// Discarded bytes read back as zeros (so discarding anything in use
    /// shows up as damage).
    fn discard(&mut self, offset: u64, len: u64) -> slate_ext4::Result<()> {
        self.0.write_all_at(&vec![0u8; len as usize], offset).map_err(|_| Error::Io)
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
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ext4-tests");
    std::fs::create_dir_all(&d).unwrap();
    d.join(name)
}

/// Make an image of `size` with `mkfs.ext4 extra... [-d src]`.
fn mkfs(name: &str, size: &str, extra: &[&str], src: Option<&Path>) -> PathBuf {
    let img = tmp(name);
    let _ = std::fs::remove_file(&img);
    let mut c = Command::new("mkfs.ext4");
    c.args(["-q", "-F", "-E", "root_owner=0:0"]).args(extra);
    if let Some(s) = src {
        c.arg("-d").arg(s);
    }
    c.arg(&img).arg(size);
    let out = c.output().unwrap();
    assert!(out.status.success(), "mkfs.ext4 failed: {}", String::from_utf8_lossy(&out.stderr));
    img
}

fn mount(img: &Path, read_only: bool) -> Fs<FileDisk> {
    let f = std::fs::OpenOptions::new().read(true).write(true).open(img).unwrap();
    Fs::mount(FileDisk(f), Options { read_only }).unwrap()
}

/// `e2fsck -fn`: must find nothing to fix.
fn fsck_clean(img: &Path) {
    let out = Command::new("e2fsck").args(["-f", "-n"]).arg(img).output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "e2fsck found problems:\n{text}");
}

fn debugfs(img: &Path, cmd: &str) -> Vec<u8> {
    let out = Command::new("debugfs").args(["-R", cmd]).arg(img).output().unwrap();
    out.stdout
}

fn resolve(fs: &mut Fs<FileDisk>, path: &str) -> u32 {
    let mut ino = 2;
    for part in path.split('/').filter(|p| !p.is_empty()) {
        ino = fs.lookup(ino, part.as_bytes()).unwrap_or_else(|e| panic!("lookup {part} in {path}: {e:?}"));
    }
    ino
}

fn read_all(fs: &mut Fs<FileDisk>, ino: u32) -> Vec<u8> {
    let size = fs.stat(ino).unwrap().size as usize;
    let mut buf = vec![0u8; size];
    // Odd-sized reads exercise partial blocks.
    let mut done = 0;
    while done < size {
        let n = (size - done).min(7777);
        assert_eq!(fs.read(ino, done as u64, &mut buf[done..done + n]).unwrap(), n);
        done += n;
    }
    buf
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

/// A source tree: files of assorted sizes, symlinks, a hard link, nested
/// and big directories.
fn make_tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let _ = std::fs::remove_dir_all(root);
    std::fs::create_dir_all(root.join("sub/deeper")).unwrap();
    std::fs::create_dir_all(root.join("big")).unwrap();
    let mut files = BTreeMap::new();
    let sizes = [0usize, 1, 100, 1023, 1024, 4095, 4096, 4097, 70_000, 1_500_000];
    for (i, &n) in sizes.iter().enumerate() {
        let name = format!("f{i}");
        let data = pattern(n, i as u32);
        std::fs::write(root.join(&name), &data).unwrap();
        files.insert(name, data);
    }
    let deep = pattern(12_345, 99);
    std::fs::write(root.join("sub/deeper/file"), &deep).unwrap();
    files.insert("sub/deeper/file".into(), deep);
    for i in 0..600 {
        let name = format!("big/entry-with-a-longish-name-{i:04}");
        std::fs::write(root.join(&name), i.to_string()).unwrap();
        files.insert(name, i.to_string().into_bytes());
    }
    std::os::unix::fs::symlink("f2", root.join("short-link")).unwrap();
    std::os::unix::fs::symlink("x".repeat(200), root.join("long-link")).unwrap();
    std::fs::hard_link(root.join("f3"), root.join("hard")).unwrap();
    files.insert("hard".into(), files["f3"].clone());
    std::fs::set_permissions(root.join("f1"), std::fs::Permissions::from_mode(0o751)).unwrap();
    files
}

fn check_tree(fs: &mut Fs<FileDisk>, files: &BTreeMap<String, Vec<u8>>) {
    for (path, data) in files {
        let ino = resolve(fs, path);
        let st = fs.stat(ino).unwrap();
        assert_eq!(st.mode & S_IFMT, S_IFREG, "{path}");
        assert_eq!(&read_all(fs, ino), data, "contents of {path}");
    }
    let f1 = resolve(fs, "f1");
    assert_eq!(fs.stat(f1).unwrap().mode & 0o7777, 0o751);
    let short = resolve(fs, "short-link");
    assert_eq!(fs.stat(short).unwrap().mode & S_IFMT, S_IFLNK);
    assert_eq!(fs.readlink(short).unwrap(), b"f2");
    let long = resolve(fs, "long-link");
    assert_eq!(fs.readlink(long).unwrap(), "x".repeat(200).as_bytes());
    assert_eq!(resolve(fs, "hard"), resolve(fs, "f3"));
    let f3 = resolve(fs, "f3");
    assert_eq!(fs.stat(f3).unwrap().links, 2);
    let big = resolve(fs, "big");
    assert_eq!(fs.read_dir(big).unwrap().len(), 602);
    assert_eq!(fs.lookup(big, b"missing"), Err(Error::NotFound));
}

#[test]
fn reads_mkfs_populated_images() {
    if !have_e2fsprogs() {
        return;
    }
    let src = tmp("tree-read");
    let files = make_tree(&src);
    for (bs, extra) in [("4096", &[][..]), ("1024", &[][..]), ("4096", &["-O", "^metadata_csum,^64bit"][..])] {
        let mut args = vec!["-b", bs];
        args.extend_from_slice(extra);
        let img = mkfs(&format!("read-{bs}-{}.img", extra.len()), "64M", &args, Some(&src));
        let mut fs = mount(&img, true);
        check_tree(&mut fs, &files);
        assert_eq!(fs.label(), b"");
    }
}

#[test]
fn modifies_images_consistently() {
    if !have_e2fsprogs() {
        return;
    }
    let src = tmp("tree-write");
    let files = make_tree(&src);
    for bs in ["4096", "1024"] {
        let img = mkfs(&format!("write-{bs}.img"), "64M", &["-b", bs], Some(&src));
        let mut fs = mount(&img, false);
        let root = 2;
        // New files, written in pieces and overwritten in the middle.
        let a = fs.create(root, b"new-file", S_IFREG | 0o644, 0, 0, 0).unwrap();
        let data = pattern(300_001, 7);
        for chunk in data.chunks(65_536).enumerate() {
            fs.write(a, (chunk.0 * 65_536) as u64, chunk.1).unwrap();
        }
        let patch = pattern(5000, 8);
        fs.write(a, 10_000, &patch).unwrap();
        let mut expect = data.clone();
        expect[10_000..15_000].copy_from_slice(&patch);
        // A fragmented file: every other block, for a multi-level tree.
        let frag = fs.create(root, b"fragmented", S_IFREG | 0o600, 1000, 1000, 0).unwrap();
        let block = fs.block_size() as u64;
        let filler = fs.create(root, b"filler", S_IFREG | 0o600, 0, 0, 0).unwrap();
        for i in 0..1500u64 {
            fs.write(frag, i * 2 * block, &pattern(block as usize, i as u32)).unwrap();
            // Interleave another file's blocks so extents cannot merge.
            fs.write(filler, i * block, &[1u8; 1]).unwrap();
        }
        // Directories: nested, renamed, removed.
        let d = fs.mkdir(root, b"dir", 0o755, 0, 0).unwrap();
        let d2 = fs.mkdir(d, b"inner", 0o700, 0, 0).unwrap();
        fs.create(d2, b"leaf", S_IFREG | 0o644, 0, 0, 0).unwrap();
        fs.mkdir(root, b"gone", 0o755, 0, 0).unwrap();
        let gone = fs.rmdir(root, b"gone").unwrap();
        fs.evict(gone).unwrap();
        assert_eq!(fs.rmdir(d, b"inner"), Err(Error::NotEmpty));
        fs.rename(d, b"inner", root, b"moved").unwrap();
        let moved = resolve(&mut fs, "moved");
        assert_eq!(fs.lookup(moved, b"..").unwrap(), root);
        // Rename over an existing file, in the same directory.
        let victim = fs.rename(root, b"f4", root, b"f5").unwrap().unwrap();
        fs.evict(victim).unwrap();
        // Symlinks, hard links, device nodes, unlink, truncate.
        fs.symlink(d, b"s", b"../new-file", 0, 0).unwrap();
        fs.symlink(d, b"l", "y".repeat(300).as_bytes(), 0, 0).unwrap();
        fs.link(d, b"hl", a).unwrap();
        fs.create(d, b"null", 0o020666, 0, 0, slate_ext4::makedev(1, 3)).unwrap();
        fs.create(d, b"bigdev", 0o060600, 0, 0, slate_ext4::makedev(259, 70000)).unwrap();
        let f6 = resolve(&mut fs, "f6");
        fs.truncate(f6, 10).unwrap();
        let f9 = resolve(&mut fs, "f9");
        fs.truncate(f9, 100_000).unwrap();
        let f0 = resolve(&mut fs, "f0");
        fs.truncate(f0, 1 << 20).unwrap(); // Sparse growth.
        for i in 0..300 {
            let n = format!("big/entry-with-a-longish-name-{i:04}");
            let (dir, leaf) = n.split_once('/').unwrap();
            let dino = resolve(&mut fs, dir);
            let ino = fs.unlink(dino, leaf.as_bytes()).unwrap();
            fs.evict(ino).unwrap();
        }
        let bigd = resolve(&mut fs, "big");
        for i in 0..200 {
            fs.create(bigd, format!("added-{i}").as_bytes(), S_IFREG | 0o644, 0, 0, 0).unwrap();
        }
        fs.set_attr(
            a,
            SetAttr {
                mode: Some(0o640),
                uid: Some(5),
                gid: Some(6),
                mtime: Some((1_000_000, 5)),
                ..Default::default()
            },
        )
        .unwrap();
        fs.sync_and_close().unwrap();
        drop(fs);
        fsck_clean(&img);

        // Read everything back, and let debugfs read it too.
        let mut fs = mount(&img, true);
        assert_eq!(read_all(&mut fs, a), expect);
        assert_eq!(debugfs(&img, "cat /new-file"), expect);
        for i in 0..1500u64 {
            let mut b = vec![0u8; block as usize];
            fs.read(frag, i * 2 * block, &mut b).unwrap();
            assert_eq!(b, pattern(block as usize, i as u32));
            if i < 1499 {
                fs.read(frag, (i * 2 + 1) * block, &mut b).unwrap();
                assert!(b.iter().all(|&x| x == 0), "hole {i} not zero");
            }
        }
        assert_eq!(debugfs(&img, "cat /fragmented").len() as u64, 2999 * block);
        let st = fs.stat(a).unwrap();
        assert_eq!((st.mode & 0o7777, st.uid, st.gid, st.mtime), (0o640, 5, 6, (1_000_000, 5)));
        assert_eq!(st.links, 2);
        assert_eq!(read_all(&mut fs, f6), files["f6"][..10]);
        assert_eq!(read_all(&mut fs, f9), files["f9"][..100_000]);
        let z = read_all(&mut fs, f0);
        assert!(z.len() == 1 << 20 && z.iter().all(|&b| b == 0));
        let f5 = resolve(&mut fs, "f5");
        assert_eq!(read_all(&mut fs, f5), files["f4"]);
        assert_eq!(fs.lookup(root, b"f4"), Err(Error::NotFound));
        let dir = resolve(&mut fs, "dir");
        let s = fs.lookup(dir, b"s").unwrap();
        assert_eq!(fs.readlink(s).unwrap(), b"../new-file");
        let l = fs.lookup(dir, b"l").unwrap();
        assert_eq!(fs.readlink(l).unwrap(), "y".repeat(300).as_bytes());
        let bigdev = fs.lookup(dir, b"bigdev").unwrap();
        let dev = fs.stat(bigdev).unwrap();
        assert_eq!((slate_ext4::dev_major(dev.rdev), slate_ext4::dev_minor(dev.rdev)), (259, 70000));
        let big = resolve(&mut fs, "big");
        assert_eq!(fs.read_dir(big).unwrap().len(), 2 + 300 + 200);
        assert_eq!(fs.stat(root).unwrap().mode & S_IFMT, S_IFDIR);
        assert!(debugfs(&img, "ls -l /dir").windows(4).any(|w| w == b"null"));
    }
}

#[test]
fn fills_and_empties_a_small_image() {
    if !have_e2fsprogs() {
        return;
    }
    let img = mkfs("full.img", "8M", &["-b", "1024"], None);
    let mut fs = mount(&img, false);
    let before = fs.totals();
    let f = fs.create(2, b"fill", S_IFREG | 0o644, 0, 0, 0).unwrap();
    let chunk = vec![0xA5u8; 64 * 1024];
    let mut off = 0u64;
    loop {
        match fs.write(f, off, &chunk) {
            Ok(n) => off += n as u64,
            Err(Error::NoSpace) => break,
            Err(e) => panic!("{e:?}"),
        }
    }
    assert!(fs.totals().free_blocks < 64);
    fs.sync_and_close().unwrap();
    drop(fs);
    fsck_clean(&img);
    let mut fs = mount(&img, false);
    let ino = fs.unlink(2, b"fill").unwrap();
    fs.evict(ino).unwrap();
    assert_eq!(fs.totals().free_blocks, before.free_blocks);
    assert_eq!(fs.totals().free_inodes, before.free_inodes);
    fs.sync_and_close().unwrap();
    drop(fs);
    fsck_clean(&img);
}

#[test]
fn refuses_unsupported_and_read_only() {
    if !have_e2fsprogs() {
        return;
    }
    let img = mkfs("inline.img", "16M", &["-O", "inline_data"], None);
    let f = std::fs::File::open(&img).unwrap();
    let f2 = std::fs::OpenOptions::new().read(true).write(true).open(&img).unwrap();
    assert!(matches!(Fs::mount(FileDisk(f), Options::default()), Err(Error::Unsupported("inline_data"))));
    drop(f2);
    let img = mkfs("ro.img", "16M", &[], None);
    let mut fs = mount(&img, true);
    assert_eq!(fs.create(2, b"x", S_IFREG | 0o644, 0, 0, 0), Err(Error::ReadOnly));
}

#[test]
fn reads_and_modifies_hashed_directories() {
    if !have_e2fsprogs() {
        return;
    }
    let src = tmp("tree-htree");
    let files = make_tree(&src);
    for bs in ["4096", "1024"] {
        let img = mkfs(&format!("htree-{bs}.img"), "64M", &["-b", bs], Some(&src));
        // e2fsck -D builds hash indexes for multi-block directories.
        let out = Command::new("e2fsck").args(["-f", "-y", "-D"]).arg(&img).output().unwrap();
        assert!(out.status.code().unwrap_or(8) <= 1, "e2fsck -D failed");
        let dump = debugfs(&img, "htree /big");
        assert!(String::from_utf8_lossy(&dump).contains("Root node dump"), "/big is not indexed");
        let mut fs = mount(&img, false);
        check_tree(&mut fs, &files);
        let big = resolve(&mut fs, "big");
        for i in (0..600).step_by(3) {
            let ino = fs.unlink(big, format!("entry-with-a-longish-name-{i:04}").as_bytes()).unwrap();
            fs.evict(ino).unwrap();
        }
        for i in 0..100 {
            fs.create(big, format!("new-{i}").as_bytes(), S_IFREG | 0o644, 0, 0, 0).unwrap();
        }
        fs.sync_and_close().unwrap();
        drop(fs);
        fsck_clean(&img);
        let mut fs = mount(&img, true);
        let names: Vec<_> = fs.read_dir(big).unwrap().into_iter().map(|e| e.name_lossy()).collect();
        assert_eq!(names.len(), 2 + 400 + 100);
        assert!(names.iter().any(|n| n == "new-99") && !names.iter().any(|n| n == "entry-with-a-longish-name-0003"));
        assert_eq!(fs.lookup(big, b"entry-with-a-longish-name-0004").map(|_| ()), Ok(()));
    }
}

/// Physical blocks of `path` (debugfs `blocks`).
fn blocks_of(img: &Path, path: &str) -> Vec<u64> {
    String::from_utf8_lossy(&debugfs(img, &format!("blocks {path}")))
        .split_whitespace()
        .map(|b| b.parse().unwrap())
        .collect()
}

/// Run debugfs commands in read-write mode.
fn debugfs_w(img: &Path, cmds: &str) {
    use std::io::Write;
    let mut c = Command::new("debugfs")
        .args(["-w", "-f", "-"])
        .arg(img)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(cmds.as_bytes()).unwrap();
    assert!(c.wait().unwrap().success());
}

fn block_bytes(img: &Path, blk: u64) -> Vec<u8> {
    let f = std::fs::File::open(img).unwrap();
    let mut b = vec![0u8; 4096];
    f.read_exact_at(&mut b, blk * 4096).unwrap();
    b
}

fn needs_recovery(img: &Path) -> bool {
    let out = Command::new("dumpe2fs").arg("-h").arg(img).output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|l| l.starts_with("Filesystem features:") && l.contains("needs_recovery"))
}

#[test]
fn replays_journals() {
    if !have_e2fsprogs() {
        return;
    }
    let src = tmp("tree-journal");
    let _ = std::fs::remove_dir_all(&src);
    std::fs::create_dir_all(&src).unwrap();
    for name in ["a", "b", "c"] {
        std::fs::write(src.join(name), format!("original {name}\n").repeat(300)).unwrap();
    }
    let payload = |tag: &[u8]| {
        let mut p = tag.to_vec();
        p.resize(4096, b'.');
        p
    };
    // Plain journal, then checksummed (v3) journals with a revoke and an
    // escaped block (one starting with the jbd2 magic number).
    for csum in [false, true] {
        let img = mkfs(&format!("journal-{csum}.img"), "32M", &["-b", "4096"], Some(&src));
        let (a, b, c) = (blocks_of(&img, "/a")[0], blocks_of(&img, "/b")[0], blocks_of(&img, "/c")[0]);
        let dir = tmp(&format!("journal-payloads-{csum}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pa"), payload(b"JOURNAL-A")).unwrap();
        std::fs::write(dir.join("pb"), payload(b"JOURNAL-B")).unwrap();
        let mut magic = vec![0xC0, 0x3B, 0x39, 0x98];
        magic.extend_from_slice(b"ESCAPED");
        std::fs::write(dir.join("pc"), payload(&magic)).unwrap();
        let o = if csum { "-c" } else { "" };
        let d = dir.display();
        // Transaction 1 logs a and c; transaction 2 revokes a and logs b.
        debugfs_w(&img, &format!("jo {o}\njw -b {a},{c} {d}/pa\njc\njo\njw -b {b} {d}/pb\njw -r {a} /dev/null\njc\n"));
        // The c block gets the escaped payload in a third transaction.
        debugfs_w(&img, &format!("jo\njw -b {c} {d}/pc\njc\n"));
        assert!(needs_recovery(&img));
        // Reference: e2fsck replays a copy.
        let reference = tmp(&format!("journal-ref-{csum}.img"));
        std::fs::copy(&img, &reference).unwrap();
        let _ = Command::new("e2fsck").args(["-f", "-y"]).arg(&reference).output().unwrap();

        // Read-only mounts refuse to skip recovery.
        let f = std::fs::File::open(&img).unwrap();
        assert!(matches!(Fs::mount(FileDisk(f), Options { read_only: true }), Err(Error::ReadOnly)));
        let mut fs = mount(&img, false);
        fs.sync_and_close().unwrap();
        drop(fs);
        assert!(!needs_recovery(&img));
        fsck_clean(&img);
        for blk in [a, b, c] {
            assert_eq!(
                block_bytes(&img, blk),
                block_bytes(&reference, blk),
                "block {blk} differs from e2fsck's replay"
            );
        }
        assert!(block_bytes(&img, a).starts_with(b"original a"), "revoked block was replayed");
        assert!(block_bytes(&img, b).starts_with(b"JOURNAL-B"));
        assert!(block_bytes(&img, c).starts_with(&magic), "escaped block not restored");
    }
}

#[test]
fn discards_only_free_space() {
    if !have_e2fsprogs() {
        return;
    }
    let img = mkfs("trim.img", "32M", &[], None);
    let mut fs = mount(&img, false);
    fs.set_discard(true);
    let mut kept = Vec::new();
    for i in 0..20u32 {
        let f = fs.create(2, format!("f{i}").as_bytes(), S_IFREG | 0o644, 0, 0, 0).unwrap();
        fs.write(f, 0, &pattern(30_000 + i as usize * 1000, i)).unwrap();
        kept.push((f, i));
    }
    fs.commit().unwrap();
    // Online discard: the blocks of removed files go once the free commits.
    for i in (0..20).step_by(2) {
        let gone = fs.unlink(2, format!("f{i}").as_bytes()).unwrap();
        fs.evict(gone).unwrap();
    }
    fs.commit().unwrap();
    kept.retain(|&(_, i)| i % 2 == 1);
    // FITRIM over everything, then over a window with a minimum length.
    let all = fs.trim(0, u64::MAX, 0).unwrap();
    assert!(all > 16 << 20, "trimmed only {all} bytes");
    assert!(fs.trim(1 << 20, 4 << 20, 1 << 20).unwrap() <= 4 << 20);
    for &(f, i) in &kept {
        assert_eq!(read_all(&mut fs, f), pattern(30_000 + i as usize * 1000, i));
    }
    fs.sync_and_close().unwrap();
    drop(fs);
    fsck_clean(&img);
    let mut fs = mount(&img, true);
    for &(f, i) in &kept {
        assert_eq!(read_all(&mut fs, f), pattern(30_000 + i as usize * 1000, i));
    }
}
