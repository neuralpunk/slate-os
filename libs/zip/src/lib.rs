// SPDX-License-Identifier: MIT OR Apache-2.0

//! The zip format (PKWARE's APPNOTE.TXT, version 6.3.10): reading and
//! writing, ours.
//!
//! - [`entries`] reads the central directory (§4.3.12), found from the
//!   end of central directory record (§4.3.16) or its Zip64 form
//!   (§4.3.14, §4.3.15, the extra field of §4.5.3), and each entry's
//!   data, stored (method 0) or deflated (method 8, over slate-flate),
//!   checking its CRC-32. Encrypted entries and other methods are
//!   refused.
//! - [`Writer`] makes an archive: local headers (§4.3.7), the data
//!   deflated when that makes it smaller, the central directory and its
//!   end. Names are UTF-8 (flag bit 11, §4.4.4); Unix modes go in the
//!   external attributes, as "made by" 3 (Unix, §4.4.2) says.
//!
//! Archives come from anywhere: every offset and size is checked, and a
//! member is inflated only up to the size it claims.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not a zip archive (no end of central directory record).
    NotZip,
    Truncated,
    /// A record or a size that doesn't hold together.
    Invalid,
    /// Encrypted, split over several disks, or compressed another way.
    Unsupported,
    /// The data doesn't match its CRC-32.
    Crc,
}

const LOCAL: u32 = 0x0403_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const END: u32 = 0x0605_4b50;
const END64: u32 = 0x0606_4b50;
const LOCATOR64: u32 = 0x0706_4b50;

/// An entry in the central directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    /// 0 stored, 8 deflated.
    pub method: u16,
    pub crc: u32,
    pub compressed: u64,
    pub size: u64,
    /// The Unix mode, if the archive was made on Unix (else 0).
    pub mode: u32,
    /// Modification time (seconds since the epoch, from the DOS fields,
    /// as local time taken as UTC).
    pub mtime: i64,
    offset: u64,
    flags: u16,
}

impl Entry {
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/') || self.mode & 0o170_000 == 0o040_000
    }

    pub fn is_symlink(&self) -> bool {
        self.mode & 0o170_000 == 0o120_000
    }
}

fn le16(d: &[u8], at: usize) -> Result<u16, Error> {
    let b = d.get(at..at + 2).ok_or(Error::Truncated)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn le32(d: &[u8], at: usize) -> Result<u32, Error> {
    let b = d.get(at..at + 4).ok_or(Error::Truncated)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn le64(d: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from(le32(d, at)?) | u64::from(le32(d, at + 4)?) << 32)
}

/// §4.4.6: MS-DOS date and time, to seconds since the epoch.
fn dos_time(time: u16, date: u16) -> i64 {
    let (y, m, d) =
        (1980 + i64::from(date >> 9), u32::from((date >> 5) & 15).clamp(1, 12), u32::from(date & 31).max(1));
    let days = days_from_civil(y, m, d);
    days * 86_400 + i64::from(time >> 11) * 3600 + i64::from((time >> 5) & 63) * 60 + i64::from(time & 31) * 2
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Seconds since the epoch to DOS (time, date), from 1980 on.
fn to_dos(t: i64) -> (u16, u16) {
    let t = t.max(315_532_800);
    let (days, secs) = (t.div_euclid(86_400), t.rem_euclid(86_400));
    // The civil date of `days`.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let y = (y - 1980).clamp(0, 127);
    let time = (secs / 3600) << 11 | ((secs / 60) % 60) << 5 | ((secs % 60) / 2);
    (time as u16, (y << 9 | m << 5 | d) as u16)
}

/// The end of central directory: (entries, size, offset).
fn end_record(d: &[u8]) -> Result<(u64, u64, u64), Error> {
    if d.len() < 22 {
        return Err(Error::NotZip);
    }
    // The record is 22 bytes and a comment of up to 65535.
    let lowest = d.len().saturating_sub(22 + 65_535);
    let at = (lowest..=d.len() - 22).rev().find(|&i| le32(d, i) == Ok(END)).ok_or(Error::NotZip)?;
    if le16(d, at + 4)? != 0 || le16(d, at + 6)? != 0 {
        return Err(Error::Unsupported);
    }
    let (n, size, offset) = (u64::from(le16(d, at + 10)?), u64::from(le32(d, at + 12)?), u64::from(le32(d, at + 16)?));
    // §4.3.15: Zip64, when any field is at its largest.
    if (n == 0xFFFF || size == 0xFFFF_FFFF || offset == 0xFFFF_FFFF) && at >= 20 && le32(d, at - 20)? == LOCATOR64 {
        let rec = usize::try_from(le64(d, at - 20 + 8)?).map_err(|_| Error::Invalid)?;
        if le32(d, rec)? != END64 {
            return Err(Error::Invalid);
        }
        return Ok((le64(d, rec + 32)?, le64(d, rec + 40)?, le64(d, rec + 48)?));
    }
    Ok((n, size, offset))
}

/// The archive's entries, from its central directory.
pub fn entries(d: &[u8]) -> Result<Vec<Entry>, Error> {
    let (n, size, offset) = end_record(d)?;
    let start = usize::try_from(offset).map_err(|_| Error::Invalid)?;
    let end = start.checked_add(usize::try_from(size).map_err(|_| Error::Invalid)?).ok_or(Error::Invalid)?;
    if end > d.len() || n > (size / 46) {
        return Err(Error::Invalid);
    }
    let mut out = Vec::new();
    let mut at = start;
    for _ in 0..n {
        if le32(d, at)? != CENTRAL {
            return Err(Error::Invalid);
        }
        let made_by = le16(d, at + 4)?;
        let flags = le16(d, at + 8)?;
        let method = le16(d, at + 10)?;
        let (time, date) = (le16(d, at + 12)?, le16(d, at + 14)?);
        let crc = le32(d, at + 16)?;
        let mut compressed = u64::from(le32(d, at + 20)?);
        let mut usize_ = u64::from(le32(d, at + 24)?);
        let (nl, el, cl) =
            (usize::from(le16(d, at + 28)?), usize::from(le16(d, at + 30)?), usize::from(le16(d, at + 32)?));
        let external = le32(d, at + 38)?;
        let mut local = u64::from(le32(d, at + 42)?);
        let name = d.get(at + 46..at + 46 + nl).ok_or(Error::Truncated)?;
        let extra = d.get(at + 46 + nl..at + 46 + nl + el).ok_or(Error::Truncated)?;
        // §4.5.3: the Zip64 extra field holds the fields at their largest,
        // in this order.
        let mut e = 0;
        while e + 4 <= extra.len() {
            let (id, len) = (le16(extra, e)?, usize::from(le16(extra, e + 2)?));
            if id == 1 {
                let mut p = e + 4;
                for field in [&mut usize_, &mut compressed, &mut local] {
                    if *field == 0xFFFF_FFFF {
                        *field = le64(extra, p)?;
                        p += 8;
                    }
                }
            }
            e += 4 + len;
        }
        // Names are UTF-8 with flag bit 11, else CP437; their ASCII part
        // is the same, and anything else is shown as it decodes.
        let name = String::from_utf8_lossy(name).into_owned();
        let mode = if made_by >> 8 == 3 { external >> 16 } else { 0 };
        out.push(Entry {
            name,
            method,
            crc,
            compressed,
            size: usize_,
            mode,
            mtime: dos_time(time, date),
            offset: local,
            flags,
        });
        at += 46 + nl + el + cl;
    }
    Ok(out)
}

/// An entry's data, uncompressed and checked.
pub fn read(d: &[u8], e: &Entry) -> Result<Vec<u8>, Error> {
    if e.flags & 1 != 0 {
        return Err(Error::Unsupported);
    }
    let at = usize::try_from(e.offset).map_err(|_| Error::Invalid)?;
    if le32(d, at)? != LOCAL {
        return Err(Error::Invalid);
    }
    let data_at = at + 30 + usize::from(le16(d, at + 26)?) + usize::from(le16(d, at + 28)?);
    let len = usize::try_from(e.compressed).map_err(|_| Error::Invalid)?;
    let raw = d.get(data_at..data_at.checked_add(len).ok_or(Error::Invalid)?).ok_or(Error::Truncated)?;
    let size = usize::try_from(e.size).map_err(|_| Error::Invalid)?;
    let out = match e.method {
        0 => raw.to_vec(),
        8 => slate_flate::inflate_raw_limited(raw, size).map(|(v, _)| v).map_err(|_| Error::Invalid)?,
        _ => return Err(Error::Unsupported),
    };
    if out.len() != size {
        return Err(Error::Invalid);
    }
    if slate_flate::crc32(&out) != e.crc {
        return Err(Error::Crc);
    }
    Ok(out)
}

/// Making an archive in memory.
#[derive(Debug, Default)]
pub struct Writer {
    out: Vec<u8>,
    central: Vec<u8>,
    count: u64,
}

impl Writer {
    pub fn new() -> Writer {
        Writer::default()
    }

    fn header(&mut self, name: &str, mode: u32, mtime: i64, data: &[u8]) {
        let (time, date) = to_dos(mtime);
        let crc = slate_flate::crc32(data);
        let deflated = if data.is_empty() { Vec::new() } else { slate_flate::deflate(data) };
        let (method, body): (u16, &[u8]) =
            if !data.is_empty() && deflated.len() < data.len() { (8, &deflated) } else { (0, data) };
        let offset = self.out.len() as u64;
        // Sizes and offsets past 4 GiB would need Zip64; an archive made
        // in memory stays below.
        let (c, s, o) = (body.len() as u32, data.len() as u32, offset as u32);
        let flags: u16 = 1 << 11;
        let mut local = Vec::with_capacity(30 + name.len());
        local.extend_from_slice(&LOCAL.to_le_bytes());
        for v in [20u16, flags, method, time, date] {
            local.extend_from_slice(&v.to_le_bytes());
        }
        for v in [crc, c, s] {
            local.extend_from_slice(&v.to_le_bytes());
        }
        local.extend_from_slice(&(name.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(name.as_bytes());
        self.out.extend_from_slice(&local);
        self.out.extend_from_slice(body);
        let cd = &mut self.central;
        cd.extend_from_slice(&CENTRAL.to_le_bytes());
        for v in [3 << 8 | 20u16, 20, flags, method, time, date] {
            cd.extend_from_slice(&v.to_le_bytes());
        }
        for v in [crc, c, s] {
            cd.extend_from_slice(&v.to_le_bytes());
        }
        for v in [name.len() as u16, 0, 0, 0, 0] {
            cd.extend_from_slice(&v.to_le_bytes());
        }
        cd.extend_from_slice(&(mode << 16).to_le_bytes());
        cd.extend_from_slice(&o.to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
        self.count += 1;
    }

    pub fn file(&mut self, name: &str, mode: u32, mtime: i64, data: &[u8]) {
        self.header(name, 0o100_000 | (mode & 0o7777), mtime, data);
    }

    /// A directory: its name ends with `/`.
    pub fn dir(&mut self, name: &str, mode: u32, mtime: i64) {
        let name = if name.ends_with('/') { String::from(name) } else { alloc::format!("{name}/") };
        self.header(&name, 0o040_000 | (mode & 0o7777), mtime, &[]);
    }

    pub fn symlink(&mut self, name: &str, target: &str, mtime: i64) {
        self.header(name, 0o120_777, mtime, target.as_bytes());
    }

    pub fn finish(mut self) -> Vec<u8> {
        let (cd_at, cd_len) = (self.out.len() as u32, self.central.len() as u32);
        self.out.extend_from_slice(&self.central);
        self.out.extend_from_slice(&END.to_le_bytes());
        let n = self.count.min(0xFFFF) as u16;
        for v in [0u16, 0, n, n] {
            self.out.extend_from_slice(&v.to_le_bytes());
        }
        self.out.extend_from_slice(&cd_len.to_le_bytes());
        self.out.extend_from_slice(&cd_at.to_le_bytes());
        self.out.extend_from_slice(&0u16.to_le_bytes());
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(std::format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    /// tests/fixtures/make.sh makes these with Info-ZIP's zip.
    #[test]
    fn reads_what_zip_writes() {
        let d = fixture("tree.zip");
        let es = entries(&d).unwrap();
        let mut names: Vec<&str> = es.iter().map(|e| e.name.as_str()).collect();
        names.sort();
        assert_eq!(names, ["tree/", "tree/a.txt", "tree/empty", "tree/link", "tree/sub/", "tree/sub/b.bin"]);
        let by = |n: &str| es.iter().find(|e| e.name == n).unwrap();
        let a = es.iter().find(|e| e.name == "tree/a.txt").unwrap();
        assert_eq!((a.method, a.mode & 0o777), (8, 0o644));
        assert!(read(&d, a).unwrap().starts_with(b"hello, zip\n"));
        let b = es.iter().find(|e| e.name == "tree/sub/b.bin").unwrap();
        assert_eq!(read(&d, b).unwrap(), (0..4096u32).map(|i| (i * 7 % 251) as u8).collect::<Vec<_>>());
        let l = es.iter().find(|e| e.name == "tree/link").unwrap();
        assert!(l.is_symlink() && read(&d, l).unwrap() == b"a.txt");
        assert!(by("tree/").is_dir() && by("tree/sub/").is_dir() && !a.is_dir());
        assert_eq!((by("tree/empty").size, read(&d, by("tree/empty")).unwrap().len()), (0, 0));
        let stored = entries(&fixture("stored.zip")).unwrap();
        assert_eq!(stored[0].method, 0);
        assert_eq!(read(&fixture("stored.zip"), &stored[0]).unwrap(), b"stored, not deflated\n");
    }

    #[test]
    fn writes_what_unzip_reads() {
        let mut w = Writer::new();
        w.dir("out", 0o755, 1_792_879_170);
        w.file("out/notes.txt", 0o640, 1_792_879_170, b"made by Slate\n");
        let big: Vec<u8> = (0..20_000u32).map(|i| (i % 13) as u8).collect();
        w.file("out/big.bin", 0o644, 1_792_879_170, &big);
        w.symlink("out/link", "notes.txt", 1_792_879_170);
        let zip = w.finish();
        let es = entries(&zip).unwrap();
        assert_eq!(es.len(), 4);
        assert_eq!(es[2].method, 8, "repetitive data is deflated");
        assert_eq!(read(&zip, &es[2]).unwrap(), big);
        // DOS times count in two seconds; this one is even.
        assert_eq!(es[1].mtime, 1_792_879_170);
        let dir = std::env::temp_dir().join(std::format!("slate-zip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("made.zip");
        std::fs::write(&path, &zip).unwrap();
        let t = Command::new("unzip").arg("-t").arg(&path).output().expect("unzip (Info-ZIP) on the host");
        let text = std::string::String::from_utf8_lossy(&t.stdout);
        assert!(t.status.success() && text.contains("No errors detected"), "{text}");
        let l = Command::new("unzip").arg("-Z").arg(&path).output().unwrap();
        let text = std::string::String::from_utf8_lossy(&l.stdout);
        assert!(text.contains("-rw-r-----") && text.contains("lrwxrwxrwx"), "{text}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn damage_is_an_error() {
        let d = fixture("tree.zip");
        for n in 0..d.len() {
            if let Ok(es) = entries(&d[..n]) {
                for e in &es {
                    let _ = read(&d[..n], e);
                }
            }
        }
        let mut bad = d.clone();
        let es = entries(&d).unwrap();
        let a = es.iter().find(|e| e.name == "tree/a.txt").unwrap();
        // A byte of the deflated data changed: the CRC or the inflater
        // says so.
        let at = a.offset as usize + 30 + a.name.len() + 5;
        bad[at] ^= 0x55;
        assert!(read(&bad, a).is_err());
        assert_eq!(entries(b"PK not really"), Err(Error::NotZip));
    }

    #[test]
    fn dos_times() {
        let (t, d) = to_dos(1_792_879_170);
        assert_eq!(dos_time(t, d), 1_792_879_170);
        assert_eq!(dos_time(0, 0x21), 315_532_800, "1980-01-01");
    }
}
