// SPDX-License-Identifier: MIT OR Apache-2.0

//! Writing FAT32 volumes: a tree of directories and files laid out in one
//! pass, for EFI System Partitions (ADR 0029), and changing them in place
//! ([`edit`], ADR 0086).
//!
//! Written from Microsoft's "FAT: General Overview of On-Disk Format"
//! (fatgen103): the BIOS parameter block and FSInfo sector (§3, §5), the
//! FAT and cluster chains (§4), directory entries (§6) and long names
//! (§7). Every file is stored contiguously. Names that are not plain
//! upper-case 8.3 names get long-name entries plus a generated `NAME~N`
//! short name.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub const SECTOR: usize = 512;
/// Fewer clusters than this is FAT16 by definition (§3.5).
pub const MIN_CLUSTERS: u64 = 65_525;
const RESERVED_SECTORS: u64 = 32;
const FATS: u64 = 2;
const ROOT_CLUSTER: u32 = 2;
const END_OF_CHAIN: u32 = 0x0FFF_FFFF;

const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_LONG_NAME: u8 = 0x0F;

/// 2026-01-01 00:00: every entry gets this date, so images are
/// reproducible.
const DATE: u16 = ((2026 - 1980) << 9) | (1 << 5) | 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The volume is too small for FAT32 or for the files.
    TooSmall,
    TooLarge,
    BadName,
    /// A path names a file where a directory is needed, or twice.
    Exists,
    NotFound,
    /// A directory to delete still holds something.
    NotEmpty,
    Io,
}

/// Where the volume goes, addressed in bytes from its start.
pub trait Sink {
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), Error>;
}

impl Sink for Vec<u8> {
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), Error> {
        let end = offset as usize + data.len();
        if end > self.len() {
            return Err(Error::TooSmall);
        }
        self[offset as usize..end].copy_from_slice(data);
        Ok(())
    }
}

#[derive(Debug, Default)]
struct Dir {
    entries: Vec<(String, Node)>,
}

#[derive(Debug)]
enum Node {
    Dir(Dir),
    File(Vec<u8>),
}

/// The tree to write.
#[derive(Debug, Default)]
pub struct Volume {
    root: Dir,
}

impl Volume {
    pub fn new() -> Volume {
        Volume::default()
    }

    fn dir_mut(&mut self, path: &str) -> Result<&mut Dir, Error> {
        let mut d = &mut self.root;
        for part in path.split('/').filter(|p| !p.is_empty()) {
            check_name(part)?;
            let i = match d.entries.iter().position(|(n, _)| n.eq_ignore_ascii_case(part)) {
                Some(i) => i,
                None => {
                    d.entries.push((String::from(part), Node::Dir(Dir::default())));
                    d.entries.len() - 1
                }
            };
            d = match &mut d.entries[i].1 {
                Node::Dir(sub) => sub,
                Node::File(_) => return Err(Error::Exists),
            };
        }
        Ok(d)
    }

    /// Add a directory (and its parents).
    pub fn add_dir(&mut self, path: &str) -> Result<(), Error> {
        self.dir_mut(path).map(|_| ())
    }

    /// Add a file at `path` (`dir/sub/name`), creating its directories.
    pub fn add_file(&mut self, path: &str, data: Vec<u8>) -> Result<(), Error> {
        let (dir, name) = path.trim_start_matches('/').rsplit_once('/').unwrap_or(("", path));
        check_name(name)?;
        let d = self.dir_mut(dir)?;
        if d.entries.iter().any(|(n, _)| n.eq_ignore_ascii_case(name)) {
            return Err(Error::Exists);
        }
        d.entries.push((String::from(name), Node::File(data)));
        Ok(())
    }

    /// Bytes the files and directories need with `cluster`-byte clusters.
    fn data_bytes(&self, cluster: u64) -> u64 {
        fn walk(d: &Dir, cluster: u64, root: bool) -> u64 {
            let mut n = clusters(dir_bytes(d, root), cluster).max(1) * cluster;
            for (_, node) in &d.entries {
                n += match node {
                    Node::Dir(sub) => walk(sub, cluster, false),
                    Node::File(data) => clusters(data.len() as u64, cluster) * cluster,
                };
            }
            n
        }
        walk(&self.root, cluster, true)
    }

    /// The smallest volume size (a multiple of 1 MiB) that holds this tree
    /// as FAT32 with `slack` bytes to spare.
    pub fn min_size(&self, slack: u64) -> u64 {
        // At least enough clusters to be FAT32 at all.
        let mut size: u64 = 33 << 20;
        loop {
            if let Ok(l) = layout(size)
                && l.clusters * l.cluster >= self.data_bytes(l.cluster) + slack
            {
                return size;
            }
            size += (size / 16).div_ceil(1 << 20).max(1) << 20;
        }
    }
}

fn check_name(n: &str) -> Result<(), Error> {
    let bad = |c: char| c < ' ' || "\"*/:<>?\\|".contains(c) || !c.is_ascii();
    if n.is_empty() || n.len() > 255 || n == "." || n == ".." || n.chars().any(bad) {
        return Err(Error::BadName);
    }
    Ok(())
}

fn clusters(bytes: u64, cluster: u64) -> u64 {
    bytes.div_ceil(cluster)
}

/// Directory entries a name takes: long-name entries plus the short one.
fn entries_for(name: &str) -> usize {
    if short_name_exact(name).is_some() { 1 } else { 1 + name.len().div_ceil(13) }
}

fn dir_bytes(d: &Dir, root: bool) -> u64 {
    let fixed = if root { 1 } else { 2 }; // Volume label, or "." and "..".
    ((fixed + d.entries.iter().map(|(n, _)| entries_for(n)).sum::<usize>()) * 32) as u64
}

fn short_char(c: u8) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_digit() || b"!#$%&'()-@^_`{}~".contains(&c)
}

/// The 11-byte short name, when `name` already is a valid upper-case 8.3
/// name.
fn short_name_exact(name: &str) -> Option<[u8; 11]> {
    let (base, ext) = name.split_once('.').unwrap_or((name, ""));
    if base.is_empty() || base.len() > 8 || ext.len() > 3 || ext.contains('.') {
        return None;
    }
    if !base.bytes().chain(ext.bytes()).all(short_char) {
        return None;
    }
    let mut out = [b' '; 11];
    out[..base.len()].copy_from_slice(base.as_bytes());
    out[8..8 + ext.len()].copy_from_slice(ext.as_bytes());
    Some(out)
}

/// A generated short name `BASE~N.EXT` for a long name (§7.4, simplified:
/// the numeric tail makes it unique within the directory).
fn short_name_generated(name: &str, n: usize) -> [u8; 11] {
    let (base, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i + 1..]),
        _ => (name, ""),
    };
    let clean = |s: &str, max: usize| -> Vec<u8> {
        s.bytes().map(|c| c.to_ascii_uppercase()).filter(|&c| short_char(c)).take(max).collect()
    };
    let tail = alloc::format!("~{n}");
    let mut b = clean(base, 8 - tail.len());
    if b.is_empty() {
        b.push(b'_');
    }
    b.extend_from_slice(tail.as_bytes());
    let e = clean(ext, 3);
    let mut out = [b' '; 11];
    out[..b.len()].copy_from_slice(&b);
    out[8..8 + e.len()].copy_from_slice(&e);
    out
}

/// The long-name checksum of a short name (§7.2).
fn checksum(short: &[u8; 11]) -> u8 {
    short.iter().fold(0u8, |sum, &c| ((sum >> 1) | ((sum & 1) << 7)).wrapping_add(c))
}

fn entry(short: &[u8; 11], attr: u8, cluster: u32, size: u32) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[..11].copy_from_slice(short);
    e[11] = attr;
    e[16..18].copy_from_slice(&DATE.to_le_bytes()); // Creation date.
    e[18..20].copy_from_slice(&DATE.to_le_bytes()); // Access date.
    e[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
    e[24..26].copy_from_slice(&DATE.to_le_bytes()); // Write date.
    e[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
    e[28..32].copy_from_slice(&size.to_le_bytes());
    e
}

/// Long-name entries for `name`, last part first, as they are stored.
fn long_entries(name: &str, short: &[u8; 11]) -> Vec<[u8; 32]> {
    let mut units: Vec<u16> = name.bytes().map(u16::from).collect();
    let count = units.len().div_ceil(13);
    if units.len() % 13 != 0 {
        units.push(0);
    }
    units.resize(count * 13, 0xFFFF);
    let sum = checksum(short);
    let mut out = Vec::new();
    for i in (0..count).rev() {
        let mut e = [0u8; 32];
        e[0] = (i as u8 + 1) | if i == count - 1 { 0x40 } else { 0 };
        e[11] = ATTR_LONG_NAME;
        e[13] = sum;
        let part = &units[i * 13..i * 13 + 13];
        let slots = (1..11).step_by(2).chain((14..26).step_by(2)).chain((28..32).step_by(2));
        for (u, at) in part.iter().zip(slots) {
            e[at..at + 2].copy_from_slice(&u.to_le_bytes());
        }
        out.push(e);
    }
    out
}

struct Layout {
    cluster: u64,
    fat_sectors: u64,
    clusters: u64,
}

impl Layout {
    fn data_start(&self) -> u64 {
        (RESERVED_SECTORS + FATS * self.fat_sectors) * SECTOR as u64
    }

    fn cluster_offset(&self, c: u32) -> u64 {
        self.data_start() + u64::from(c - 2) * self.cluster
    }
}

fn layout(bytes: u64) -> Result<Layout, Error> {
    let total = bytes / SECTOR as u64;
    // Cluster sizes by volume size, as fatgen103's table for FAT32.
    let spc = match bytes {
        b if b < 260 << 20 => 1,
        b if b < 8 << 30 => 8,
        b if b < 16 << 30 => 16,
        _ => 32,
    };
    let mut fat_sectors = ((total / spc + 2) * 4).div_ceil(SECTOR as u64);
    let mut clusters = 0;
    for _ in 0..4 {
        let data = total.checked_sub(RESERVED_SECTORS + FATS * fat_sectors).ok_or(Error::TooSmall)?;
        clusters = data / spc;
        fat_sectors = ((clusters + 2) * 4).div_ceil(SECTOR as u64);
    }
    if clusters < MIN_CLUSTERS {
        return Err(Error::TooSmall);
    }
    if clusters > 0x0FFF_FFF5 {
        return Err(Error::TooLarge);
    }
    Ok(Layout { cluster: spc * SECTOR as u64, fat_sectors, clusters })
}

/// Write `vol` as a FAT32 volume of `bytes` bytes. `hidden` is the number
/// of sectors before the volume on its disk (the partition's first LBA).
pub fn write(
    vol: &Volume,
    bytes: u64,
    label: &str,
    serial: u32,
    hidden: u32,
    sink: &mut dyn Sink,
) -> Result<(), Error> {
    let l = layout(bytes)?;
    let mut fat = vec![0u32; l.clusters as usize + 2];
    fat[0] = 0x0FFF_FFF8;
    fat[1] = END_OF_CHAIN;
    let mut next = ROOT_CLUSTER;
    let mut alloc = |n: u64, fat: &mut Vec<u32>| -> Result<u32, Error> {
        if n == 0 {
            return Ok(0);
        }
        let first = next;
        if u64::from(first) + n > l.clusters + 2 {
            return Err(Error::TooSmall);
        }
        for i in 0..n as u32 {
            fat[(first + i) as usize] = if i + 1 == n as u32 { END_OF_CHAIN } else { first + i + 1 };
        }
        next += n as u32;
        Ok(first)
    };

    let mut label11 = [b' '; 11];
    for (d, s) in label11.iter_mut().zip(label.bytes().map(|c| c.to_ascii_uppercase())) {
        *d = s;
    }
    // Directories breadth-first: allocate each one's clusters, then its
    // files' and subdirectories'.
    let root_clusters = clusters(dir_bytes(&vol.root, true), l.cluster).max(1);
    let root_first = alloc(root_clusters, &mut fat)?;
    debug_assert_eq!(root_first, ROOT_CLUSTER);
    let mut queue: Vec<(&Dir, u32, u32, u64)> = vec![(&vol.root, root_first, 0, root_clusters)];
    let mut qi = 0;
    while qi < queue.len() {
        let (dir, me, parent, n) = queue[qi];
        qi += 1;
        let mut raw: Vec<u8> = Vec::new();
        if me == ROOT_CLUSTER {
            raw.extend_from_slice(&entry(&label11, ATTR_VOLUME_ID, 0, 0));
        } else {
            raw.extend_from_slice(&entry(b".          ", ATTR_DIRECTORY, me, 0));
            raw.extend_from_slice(&entry(b"..         ", ATTR_DIRECTORY, parent, 0));
        }
        let mut used: Vec<[u8; 11]> = Vec::new();
        for (name, node) in &dir.entries {
            let short = match short_name_exact(name) {
                Some(s) => s,
                None => (1..)
                    .map(|i| short_name_generated(name, i))
                    .find(|s| !used.contains(s) && dir.entries.iter().all(|(n, _)| short_name_exact(n) != Some(*s)))
                    .unwrap(),
            };
            used.push(short);
            if short_name_exact(name).is_none() {
                for e in long_entries(name, &short) {
                    raw.extend_from_slice(&e);
                }
            }
            match node {
                Node::Dir(sub) => {
                    let n = clusters(dir_bytes(sub, false), l.cluster).max(1);
                    let first = alloc(n, &mut fat)?;
                    raw.extend_from_slice(&entry(&short, ATTR_DIRECTORY, first, 0));
                    queue.push((sub, first, if me == ROOT_CLUSTER { 0 } else { me }, n));
                }
                Node::File(data) => {
                    let size = u32::try_from(data.len()).map_err(|_| Error::TooLarge)?;
                    let first = alloc(clusters(data.len() as u64, l.cluster), &mut fat)?;
                    raw.extend_from_slice(&entry(&short, ATTR_ARCHIVE, first, size));
                    if first != 0 {
                        sink.write(l.cluster_offset(first), data)?;
                        let tail = (data.len() as u64 % l.cluster) as usize;
                        if tail != 0 {
                            let pad = vec![0u8; l.cluster as usize - tail];
                            sink.write(l.cluster_offset(first) + data.len() as u64, &pad)?;
                        }
                    }
                }
            }
        }
        raw.resize((n * l.cluster) as usize, 0);
        sink.write(l.cluster_offset(me), &raw)?;
    }

    // The FATs, both copies.
    let mut fat_bytes = vec![0u8; (l.fat_sectors as usize) * SECTOR];
    for (i, v) in fat.iter().enumerate() {
        fat_bytes[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    for copy in 0..FATS {
        sink.write((RESERVED_SECTORS + copy * l.fat_sectors) * SECTOR as u64, &fat_bytes)?;
    }

    // The reserved area: boot sector and FSInfo, and their backups at
    // sectors 6 and 7 (§3.1-§3.3, §5).
    let total = bytes / SECTOR as u64;
    let mut reserved = vec![0u8; RESERVED_SECTORS as usize * SECTOR];
    let bs = &mut reserved[..SECTOR];
    bs[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    bs[3..11].copy_from_slice(b"SLATE   ");
    bs[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
    bs[13] = (l.cluster / SECTOR as u64) as u8;
    bs[14..16].copy_from_slice(&(RESERVED_SECTORS as u16).to_le_bytes());
    bs[16] = FATS as u8;
    bs[21] = 0xF8;
    bs[24..26].copy_from_slice(&32u16.to_le_bytes());
    bs[26..28].copy_from_slice(&64u16.to_le_bytes());
    bs[28..32].copy_from_slice(&hidden.to_le_bytes());
    bs[32..36].copy_from_slice(&u32::try_from(total).map_err(|_| Error::TooLarge)?.to_le_bytes());
    bs[36..40].copy_from_slice(&(l.fat_sectors as u32).to_le_bytes());
    bs[44..48].copy_from_slice(&ROOT_CLUSTER.to_le_bytes());
    bs[48..50].copy_from_slice(&1u16.to_le_bytes());
    bs[50..52].copy_from_slice(&6u16.to_le_bytes());
    bs[64] = 0x80;
    bs[66] = 0x29;
    bs[67..71].copy_from_slice(&serial.to_le_bytes());
    bs[71..82].copy_from_slice(&label11);
    bs[82..90].copy_from_slice(b"FAT32   ");
    bs[510] = 0x55;
    bs[511] = 0xAA;
    let free = (l.clusters + 2 - u64::from(next)) as u32;
    let fsinfo = &mut reserved[SECTOR..2 * SECTOR];
    fsinfo[0..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
    fsinfo[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
    fsinfo[488..492].copy_from_slice(&free.to_le_bytes());
    fsinfo[492..496].copy_from_slice(&next.to_le_bytes());
    fsinfo[508..512].copy_from_slice(&0xAA55_0000u32.to_le_bytes());
    let (head, tail) = reserved.split_at_mut(6 * SECTOR);
    tail[..2 * SECTOR].copy_from_slice(&head[..2 * SECTOR]);
    sink.write(0, &reserved)
}

pub mod edit;

#[cfg(test)]
mod tests;
