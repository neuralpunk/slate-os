// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use std::process::Command;
use std::string::String;

fn entry<'a>(path: &str, kind: Kind, data: &'a [u8]) -> Entry<'a> {
    Entry {
        path: path.as_bytes().to_vec(),
        link: Vec::new(),
        kind,
        mode: if kind == Kind::Dir { 0o755 } else { 0o644 },
        uid: 1000,
        gid: 1000,
        mtime: 1_700_000_000,
        uname: b"ada".to_vec(),
        gname: b"ada".to_vec(),
        dev: (0, 0),
        data,
    }
}

#[test]
fn round_trip() {
    let long = std::format!("deep/{}/file.txt", "d".repeat(130));
    let longest = "x".repeat(200);
    let mut b = Builder::new();
    b.add(&entry("dir", Kind::Dir, b""));
    b.add(&entry("dir/hello.txt", Kind::File, b"hello\n"));
    b.add(&entry(&long, Kind::File, b"long\n"));
    b.add(&entry(&longest, Kind::File, b"longest\n"));
    let mut l = entry("dir/link", Kind::Symlink, b"");
    l.link = b"hello.txt".to_vec();
    b.add(&l);
    let a = b.finish();
    assert_eq!(a.len() % 10240, 0);
    let es = entries(&a).unwrap();
    let names: std::vec::Vec<&[u8]> = es.iter().map(|e| e.path.as_slice()).collect();
    assert_eq!(names, [b"dir/".as_slice(), b"dir/hello.txt", long.as_bytes(), longest.as_bytes(), b"dir/link"]);
    assert_eq!(es[1].data, b"hello\n");
    assert_eq!((es[1].mode, es[1].uid, es[1].mtime), (0o644, 1000, 1_700_000_000));
    assert_eq!(es[0].kind, Kind::Dir);
    assert_eq!((es[4].kind, es[4].link.as_slice()), (Kind::Symlink, b"hello.txt".as_slice()));
}

/// GNU tar reads ours, and we read GNU tar's (gnu and pax formats, long
/// names). Skipped without a host tar.
#[test]
fn against_host_tar() {
    let dir = std::env::temp_dir().join(std::format!("slate-tar-{}", std::process::id()));
    let src = dir.join("src");
    let deep = src.join("a").join("b".repeat(120));
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(src.join("a/one.txt"), b"one\n").unwrap();
    std::fs::write(deep.join("two.txt"), b"two\n").unwrap();
    std::os::unix::fs::symlink("one.txt", src.join("a/sym")).unwrap();
    for format in ["gnu", "pax", "ustar"] {
        let out = dir.join(std::format!("{format}.tar"));
        let Ok(s) =
            Command::new("tar").args(["--format", format, "-cf"]).arg(&out).arg("-C").arg(&src).arg("a").status()
        else {
            return;
        };
        if !s.success() {
            // ustar can't hold the long directory name.
            continue;
        }
        let bytes = std::fs::read(&out).unwrap();
        let es = entries(&bytes).unwrap();
        let two = std::format!("a/{}/two.txt", "b".repeat(120));
        assert!(es.iter().any(|e| e.path == two.as_bytes() && e.data == b"two\n"), "{format}");
        assert!(es.iter().any(|e| e.path == b"a/sym" && e.kind == Kind::Symlink && e.link == b"one.txt"));
    }
    // Ours, listed by GNU tar.
    let mut b = Builder::new();
    let long = std::format!("z/{}/f", "q".repeat(150));
    b.add(&entry(&long, Kind::File, b"data"));
    b.add(&entry("plain.txt", Kind::File, b"plain"));
    let ours = dir.join("ours.tar");
    std::fs::write(&ours, b.finish()).unwrap();
    let o = Command::new("tar").arg("-tf").arg(&ours).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(String::from_utf8_lossy(&o.stdout), std::format!("{long}\nplain.txt\n"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bad_archives() {
    let mut b = Builder::new();
    b.add(&entry("f", Kind::File, b"0123456789"));
    let mut a = b.finish();
    a[0] ^= 1;
    assert_eq!(entries(&a), Err(Error::Checksum));
    a[0] ^= 1;
    assert_eq!(entries(&a[..515]), Err(Error::Truncated));
}

/// A reader over an archive, an entry at a time.
fn read_all(a: &[u8]) -> std::vec::Vec<(Header, std::vec::Vec<u8>)> {
    let mut r = Reader::new(SliceSource::new(a));
    let mut out = std::vec::Vec::new();
    while let Some(h) = r.next().unwrap() {
        let mut d = std::vec::Vec::new();
        let mut buf = [0u8; 100];
        loop {
            let n = r.read_data(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            d.extend_from_slice(&buf[..n]);
        }
        out.push((h, d));
    }
    out
}

/// Sparse files from GNU tar in both its formats; ours read back by it;
/// extended attributes both ways. Skipped without a host tar.
#[test]
fn sparse_and_xattrs() {
    let dir = std::env::temp_dir().join(std::format!("slate-tar-sparse-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // 1 MiB with data at 0, 300 KiB and the end.
    let mut f = std::vec![0u8; 1 << 20];
    f[..5].copy_from_slice(b"start");
    f[300 << 10..(300 << 10) + 6].copy_from_slice(b"middle");
    let n = f.len();
    f[n - 3..].copy_from_slice(b"end");
    {
        // Holes on disk: only the pieces written.
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::File::create(dir.join("holes")).unwrap();
        file.set_len(f.len() as u64).unwrap();
        for (o, d) in [(0u64, &b"start"[..]), (300 << 10, b"middle"), ((1 << 20) - 3, b"end")] {
            file.seek(SeekFrom::Start(o)).unwrap();
            file.write_all(d).unwrap();
        }
    }
    for format in ["gnu", "pax"] {
        let out = dir.join(std::format!("{format}.tar"));
        let Ok(s) = Command::new("tar")
            .args(["--format", format, "-S", "-cf"])
            .arg(&out)
            .arg("-C")
            .arg(&dir)
            .arg("holes")
            .status()
        else {
            return;
        };
        assert!(s.success());
        let es = read_all(&std::fs::read(&out).unwrap());
        let (h, data) = &es[0];
        assert_eq!(h.path, b"holes", "{format}");
        let (real, map) = h.sparse.clone().expect("a sparse entry");
        assert_eq!(real, 1 << 20);
        // Lay the pieces (each on a block) out and compare.
        let mut back = std::vec![0u8; real as usize];
        let mut at = 0usize;
        for (o, l) in map {
            back[o as usize..(o + l) as usize].copy_from_slice(&data[at..at + l as usize]);
            at += l as usize + padding(l);
        }
        assert_eq!(back, f, "{format}");
    }
    // Ours, sparse and with an attribute, extracted by GNU tar.
    let map = std::vec![(0u64, 5u64), (300 << 10, 6), ((1 << 20) - 3, 3)];
    let mut pieces = std::vec::Vec::new();
    for p in [&b"start"[..], b"middle", b"end"] {
        pieces.extend_from_slice(p);
        pieces.resize(pieces.len() + padding(p.len() as u64), 0);
    }
    let h = Header {
        path: b"ours".to_vec(),
        kind: Some(Kind::File),
        mode: 0o644,
        mtime: 1_700_000_000,
        size: pieces.len() as u64,
        sparse: Some((1 << 20, map)),
        xattrs: std::vec![(b"user.note".to_vec(), b"hi".to_vec())],
        ..Header::default()
    };
    let mut a = header(&h);
    a.extend_from_slice(&pieces);
    a.extend_from_slice(&END);
    std::fs::write(dir.join("ours.tar"), &a).unwrap();
    let x = dir.join("x");
    std::fs::create_dir_all(&x).unwrap();
    let o = Command::new("tar").args(["--xattrs", "-xf"]).arg(dir.join("ours.tar")).arg("-C").arg(&x).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(std::fs::read(x.join("ours")).unwrap(), f);
    // GNU tar's xattr records read back.
    let back = read_all(&a);
    assert_eq!(back[0].0.xattrs, [(b"user.note".to_vec(), b"hi".to_vec())]);
    let _ = std::fs::remove_dir_all(&dir);
}
