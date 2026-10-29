// SPDX-License-Identifier: MIT OR Apache-2.0

//! The cpio "newc" (SVR4, no CRC) archive format, as used for initramfs.
//!
//! Format from cpio(5) ("New ASCII Format"): a 110-byte header of the magic
//! `070701` and thirteen 8-digit hexadecimal fields, then the NUL-terminated
//! name, padded to a multiple of 4 bytes, then the data, padded likewise.
//! The archive ends with an entry named `TRAILER!!!`.

#![no_std]

#[cfg(any(test, feature = "alloc"))]
extern crate alloc;
#[cfg(test)]
extern crate std;

pub const MAGIC: &[u8; 6] = b"070701";
pub const HEADER_LEN: usize = 110;
pub const TRAILER: &str = "TRAILER!!!";

/// File type bits of `mode` (inode(7)).
pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFCHR: u32 = 0o020000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BadMagic,
    BadHeader,
    Truncated,
}

/// One archive member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub name: &'a str,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u32,
    pub rdev_major: u32,
    pub rdev_minor: u32,
    /// File contents, or the link target for symlinks.
    pub data: &'a [u8],
}

fn hex(field: &[u8]) -> Result<u32, Error> {
    let s = core::str::from_utf8(field).map_err(|_| Error::BadHeader)?;
    u32::from_str_radix(s, 16).map_err(|_| Error::BadHeader)
}

fn pad4(n: usize) -> usize {
    n.div_ceil(4) * 4
}

/// Iterate the members of an archive, stopping at the trailer.
pub fn entries(archive: &[u8]) -> impl Iterator<Item = Result<Entry<'_>, Error>> {
    let mut rest = archive;
    let mut done = false;
    core::iter::from_fn(move || {
        if done || rest.is_empty() {
            return None;
        }
        let r = parse_one(rest);
        match r {
            Ok((e, used)) => {
                rest = &rest[used..];
                if e.name == TRAILER {
                    done = true;
                    return None;
                }
                Some(Ok(e))
            }
            Err(err) => {
                done = true;
                Some(Err(err))
            }
        }
    })
}

fn parse_one(b: &[u8]) -> Result<(Entry<'_>, usize), Error> {
    let h = b.get(..HEADER_LEN).ok_or(Error::Truncated)?;
    if &h[..6] != MAGIC {
        return Err(Error::BadMagic);
    }
    let f = |i: usize| hex(&h[6 + 8 * i..14 + 8 * i]);
    let (mode, uid, gid, mtime, size) = (f(1)?, f(2)?, f(3)?, f(5)?, f(6)? as usize);
    let (rdev_major, rdev_minor, namesize) = (f(9)?, f(10)?, f(11)? as usize);
    if namesize == 0 {
        return Err(Error::BadHeader);
    }
    let name_end = HEADER_LEN + namesize;
    let name_bytes = b.get(HEADER_LEN..name_end - 1).ok_or(Error::Truncated)?;
    let name = core::str::from_utf8(name_bytes).map_err(|_| Error::BadHeader)?;
    let data_start = pad4(name_end);
    let data = b.get(data_start..data_start + size).ok_or(Error::Truncated)?;
    let used = pad4(data_start + size).min(b.len());
    Ok((Entry { name, mode, uid, gid, mtime, rdev_major, rdev_minor, data }, used))
}

/// Builds an archive (host side).
#[cfg(any(test, feature = "alloc"))]
#[derive(Debug, Default)]
pub struct Writer {
    out: alloc::vec::Vec<u8>,
    next_ino: u32,
}

#[cfg(any(test, feature = "alloc"))]
impl Writer {
    pub fn new() -> Writer {
        Writer { out: alloc::vec::Vec::new(), next_ino: 1 }
    }

    fn header(&mut self, name: &str, mode: u32, size: usize, rdev: (u32, u32)) {
        self.header_owned(name, mode, (0, 0), size, rdev);
    }

    fn header_owned(&mut self, name: &str, mode: u32, owner: (u32, u32), size: usize, rdev: (u32, u32)) {
        use core::fmt::Write;
        let mut s = alloc::string::String::new();
        let nlink = if mode & S_IFMT == S_IFDIR { 2 } else { 1 };
        let ino = self.next_ino;
        self.next_ino += 1;
        let fields =
            [ino, mode, owner.0, owner.1, nlink, 0, size as u32, 0, 0, rdev.0, rdev.1, name.len() as u32 + 1, 0];
        s.push_str("070701");
        for v in fields {
            let _ = write!(s, "{v:08X}");
        }
        self.out.extend_from_slice(s.as_bytes());
        self.out.extend_from_slice(name.as_bytes());
        self.out.push(0);
        self.out.resize(pad4(self.out.len()), 0);
    }

    fn data(&mut self, data: &[u8]) {
        self.out.extend_from_slice(data);
        self.out.resize(pad4(self.out.len()), 0);
    }

    pub fn dir(&mut self, name: &str, perm: u32) {
        self.header(name, S_IFDIR | perm, 0, (0, 0));
    }

    pub fn file(&mut self, name: &str, perm: u32, data: &[u8]) {
        self.header(name, S_IFREG | perm, data.len(), (0, 0));
        self.data(data);
    }

    pub fn symlink(&mut self, name: &str, target: &str) {
        self.header(name, S_IFLNK | 0o777, target.len(), (0, 0));
        self.data(target.as_bytes());
    }

    /// A member with its owner: `mode` includes the type bits (a file's
    /// contents or a link's target in `data`; nothing for a directory).
    pub fn owned(&mut self, name: &str, mode: u32, uid: u32, gid: u32, data: &[u8]) {
        self.header_owned(name, mode, (uid, gid), data.len(), (0, 0));
        self.data(data);
    }

    pub fn char_device(&mut self, name: &str, perm: u32, major: u32, minor: u32) {
        self.header(name, S_IFCHR | perm, 0, (major, minor));
    }

    pub fn finish(mut self) -> alloc::vec::Vec<u8> {
        self.header(TRAILER, 0, 0, (0, 0));
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn round_trip() {
        let mut w = Writer::new();
        w.dir("bin", 0o755);
        w.file("bin/hello", 0o755, b"#!/bin/sh\necho hi\n");
        w.symlink("bin/sh", "busybox");
        w.char_device("dev/null", 0o666, 1, 3);
        w.file("empty", 0o644, b"");
        let a = w.finish();
        assert_eq!(a.len() % 4, 0);
        let es: Vec<_> = entries(&a).collect::<Result<_, _>>().unwrap();
        assert_eq!(es.len(), 5);
        assert_eq!(es[0].name, "bin");
        assert_eq!(es[0].mode & S_IFMT, S_IFDIR);
        assert_eq!(es[1].data, b"#!/bin/sh\necho hi\n");
        assert_eq!(es[1].mode & 0o777, 0o755);
        assert_eq!((es[2].mode & S_IFMT, es[2].data), (S_IFLNK, &b"busybox"[..]));
        assert_eq!((es[3].rdev_major, es[3].rdev_minor), (1, 3));
        assert_eq!(es[4].data, b"");
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(entries(b"hello world").next(), Some(Err(Error::Truncated)));
        let mut bad = Writer::new();
        bad.file("x", 0o644, b"abc");
        let mut a = bad.finish();
        a[0] = b'9';
        assert_eq!(entries(&a).next(), Some(Err(Error::BadMagic)));
    }

    #[test]
    fn parses_host_cpio_output_if_available() {
        // Cross-check against the host's GNU cpio when present.
        let dir = std::env::temp_dir().join(std::format!("slate-cpio-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(dir.join("d"));
        std::fs::write(dir.join("d/f"), b"data").unwrap();
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg("cd \"$0\" && printf 'd\\nd/f\\n' | cpio -o -H newc 2>/dev/null")
            .arg(&dir)
            .output();
        let _ = std::fs::remove_dir_all(&dir);
        let Ok(out) = out else { return };
        if !out.status.success() || out.stdout.is_empty() {
            return;
        }
        let es: Vec<_> = entries(&out.stdout).collect::<Result<_, _>>().unwrap();
        assert_eq!(es.iter().map(|e| e.name).collect::<Vec<_>>(), ["d", "d/f"]);
        assert_eq!(es[1].data, b"data");
    }
}
