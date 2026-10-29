// SPDX-License-Identifier: MIT OR Apache-2.0

//! Changing a FAT32 volume in place (ADR 0086): reading, listing,
//! creating, replacing and deleting files and directories, with long
//! names, both FATs kept alike.
//!
//! The order of writes keeps every step whole across a crash, because
//! a directory entry's 32 bytes sit inside one sector and change with
//! one sector write (fatgen103 §6):
//! - a new file's data and FAT chain are written, and flushed, before the
//!   short-name entry that makes it visible;
//! - a replaced file gets a new chain, and its entry then points at it
//!   in one write; the old chain is freed after;
//! - a deleted file's short-name entry is marked free first, its long
//!   name and chain after.
//!
//! A crash can leave clusters allocated to no file or long-name entries
//! with no short one; fsck.fat tidies those, and no file is ever seen
//! half written.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::{
    ATTR_ARCHIVE, ATTR_DIRECTORY, ATTR_LONG_NAME, ATTR_VOLUME_ID, DATE, END_OF_CHAIN, Error, SECTOR, check_name,
    checksum, entry, long_entries, short_name_exact, short_name_generated,
};

/// The disk the volume is on, in 512-byte sectors from the volume's
/// start.
pub trait Disk {
    fn read(&mut self, sector: u64, buf: &mut [u8; SECTOR]) -> Result<(), Error>;
    fn write(&mut self, sector: u64, data: &[u8; SECTOR]) -> Result<(), Error>;
    /// Make what was written durable (a cache flush).
    fn flush(&mut self) -> Result<(), Error>;
    /// Read the sectors from `sector` on into `buf` (whole sectors): one
    /// call for a cluster or a run of them. The default reads them one by
    /// one.
    fn read_run(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), Error> {
        for (i, chunk) in buf.as_chunks_mut::<SECTOR>().0.iter_mut().enumerate() {
            self.read(sector + i as u64, chunk)?;
        }
        Ok(())
    }
    /// Write whole sectors from `sector` on. The default writes them one
    /// by one.
    fn write_run(&mut self, sector: u64, data: &[u8]) -> Result<(), Error> {
        for (i, chunk) in data.as_chunks::<SECTOR>().0.iter().enumerate() {
            self.write(sector + i as u64, chunk)?;
        }
        Ok(())
    }
}

impl Disk for Vec<u8> {
    fn read(&mut self, sector: u64, buf: &mut [u8; SECTOR]) -> Result<(), Error> {
        let at = sector as usize * SECTOR;
        buf.copy_from_slice(self.get(at..at + SECTOR).ok_or(Error::Io)?);
        Ok(())
    }
    fn write(&mut self, sector: u64, data: &[u8; SECTOR]) -> Result<(), Error> {
        let at = sector as usize * SECTOR;
        self.get_mut(at..at + SECTOR).ok_or(Error::Io)?.copy_from_slice(data);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

impl<T: Disk + ?Sized> Disk for &mut T {
    fn read(&mut self, sector: u64, buf: &mut [u8; SECTOR]) -> Result<(), Error> {
        (**self).read(sector, buf)
    }
    fn write(&mut self, sector: u64, data: &[u8; SECTOR]) -> Result<(), Error> {
        (**self).write(sector, data)
    }
    fn flush(&mut self) -> Result<(), Error> {
        (**self).flush()
    }
    fn read_run(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), Error> {
        (**self).read_run(sector, buf)
    }
    fn write_run(&mut self, sector: u64, data: &[u8]) -> Result<(), Error> {
        (**self).write_run(sector, data)
    }
}

/// What a directory holds, by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub dir: bool,
    pub size: u32,
}

/// A directory entry found on the disk.
#[derive(Clone, Debug)]
struct Found {
    name: String,
    attr: u8,
    cluster: u32,
    size: u32,
    /// Where the short-name entry is: the directory cluster's index in
    /// the chain is not kept, only the absolute byte offset.
    short_at: u64,
    /// The long-name entries before it.
    long_at: Vec<u64>,
}

/// A FAT32 volume opened for changes.
pub struct Fs<D: Disk> {
    disk: D,
    sectors_per_cluster: u64,
    reserved: u64,
    fats: u64,
    fat_sectors: u64,
    root: u32,
    /// Clusters 2.. of the data area.
    clusters: u32,
    fsinfo: u64,
    fat: Vec<u32>,
    /// Where to look for a free cluster next.
    hint: u32,
    date: u16,
    time: u16,
}

impl<D: Disk> core::fmt::Debug for Fs<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Fs").field("clusters", &self.clusters).field("root", &self.root).finish_non_exhaustive()
    }
}

impl<D: Disk> Fs<D> {
    /// Open a FAT32 volume (fatgen103 §3: the BPB with a FAT32 extension).
    pub fn open(mut disk: D) -> Result<Fs<D>, Error> {
        let mut bs = [0u8; SECTOR];
        disk.read(0, &mut bs)?;
        let u16_at = |o: usize| u64::from(u16::from_le_bytes([bs[o], bs[o + 1]]));
        let u32_at = |o: usize| u64::from(u32::from_le_bytes([bs[o], bs[o + 1], bs[o + 2], bs[o + 3]]));
        if bs[510..512] != [0x55, 0xAA] || u16_at(11) != SECTOR as u64 || u16_at(22) != 0 || u32_at(36) == 0 {
            return Err(Error::Io);
        }
        let spc = u64::from(bs[13]);
        let (reserved, fats, fat_sectors) = (u16_at(14), u64::from(bs[16]), u32_at(36));
        let total = if u16_at(19) != 0 { u16_at(19) } else { u32_at(32) };
        if spc == 0 || fats == 0 || reserved == 0 {
            return Err(Error::Io);
        }
        let data = total.checked_sub(reserved + fats * fat_sectors).ok_or(Error::Io)?;
        let clusters = u32::try_from(data / spc).map_err(|_| Error::Io)?;
        let mut fs = Fs {
            disk,
            sectors_per_cluster: spc,
            reserved,
            fats,
            fat_sectors,
            root: u32_at(44) as u32,
            clusters,
            fsinfo: u16_at(48),
            fat: Vec::new(),
            hint: 2,
            date: DATE,
            time: 0,
        };
        // The whole first FAT, as far as clusters reach.
        let wanted = (clusters as usize + 2) * 4;
        let mut raw = vec![0u8; wanted.div_ceil(SECTOR) * SECTOR];
        fs.disk.read_run(reserved, &mut raw)?;
        fs.fat = raw[..wanted]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]) & 0x0FFF_FFFF)
            .collect();
        Ok(fs)
    }

    /// The date and time new and changed entries get (fatgen103 §6.1:
    /// date = (year - 1980) << 9 | month << 5 | day; time = hours << 11 |
    /// minutes << 5 | seconds / 2).
    pub fn set_time(&mut self, date: u16, time: u16) {
        self.date = date;
        self.time = time;
    }

    pub fn into_disk(self) -> D {
        self.disk
    }

    /// The bytes the free clusters hold (a zero in the FAT, fatgen103 §4).
    pub fn free_bytes(&self) -> u64 {
        let free = self.fat.iter().skip(2).take(self.clusters as usize).filter(|&&e| e == 0).count();
        free as u64 * self.cluster_bytes() as u64
    }

    fn cluster_bytes(&self) -> usize {
        self.sectors_per_cluster as usize * SECTOR
    }

    fn cluster_sector(&self, c: u32) -> u64 {
        self.reserved + self.fats * self.fat_sectors + u64::from(c - 2) * self.sectors_per_cluster
    }

    fn valid(&self, c: u32) -> bool {
        (2..self.clusters + 2).contains(&c)
    }

    /// The clusters of the chain starting at `first`.
    fn chain(&self, first: u32) -> Result<Vec<u32>, Error> {
        let mut out = Vec::new();
        let mut c = first;
        while self.valid(c) {
            if out.len() > self.clusters as usize {
                return Err(Error::Io); // A loop.
            }
            out.push(c);
            c = self.fat[c as usize];
        }
        Ok(out)
    }

    fn read_cluster(&mut self, c: u32) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; self.cluster_bytes()];
        self.disk.read_run(self.cluster_sector(c), &mut out)?;
        Ok(out)
    }

    fn write_cluster(&mut self, c: u32, data: &[u8]) -> Result<(), Error> {
        self.write_clusters(c, data)
    }

    /// Write `data` to the clusters from `c` on, consecutive on the disk;
    /// the last one padded with zeros.
    fn write_clusters(&mut self, c: u32, data: &[u8]) -> Result<(), Error> {
        let whole = data.len() / SECTOR * SECTOR;
        let first = self.cluster_sector(c);
        if whole > 0 {
            self.disk.write_run(first, &data[..whole])?;
        }
        if whole < data.len() {
            let mut s = [0u8; SECTOR];
            s[..data.len() - whole].copy_from_slice(&data[whole..]);
            self.disk.write(first + (whole / SECTOR) as u64, &s)?;
        }
        Ok(())
    }

    /// The chain from `first` as runs of consecutive clusters (start, count).
    fn runs(&self, first: u32) -> Result<Vec<(u32, u32)>, Error> {
        let mut out: Vec<(u32, u32)> = Vec::new();
        for c in self.chain(first)? {
            match out.last_mut() {
                Some((s, n)) if *s + *n == c => *n += 1,
                _ => out.push((c, 1)),
            }
        }
        Ok(out)
    }

    /// Write FAT entries `cs` (their current values) to both FATs.
    fn write_fat(&mut self, cs: &[u32]) -> Result<(), Error> {
        let mut sectors: Vec<u64> = cs.iter().map(|&c| u64::from(c) * 4 / SECTOR as u64).collect();
        sectors.sort_unstable();
        sectors.dedup();
        for s in sectors {
            let mut buf = [0u8; SECTOR];
            let first = (s as usize * SECTOR) / 4;
            for (i, chunk) in buf.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                let v = self.fat.get(first + i).copied().unwrap_or(0);
                chunk.copy_from_slice(&v.to_le_bytes());
            }
            for copy in 0..self.fats {
                self.disk.write(self.reserved + copy * self.fat_sectors + s, &buf)?;
            }
        }
        Ok(())
    }

    /// Allocate `n` clusters as a chain (not yet written to the disk).
    fn allocate(&mut self, n: usize) -> Result<Vec<u32>, Error> {
        let mut got = Vec::new();
        let mut c = self.hint;
        let mut scanned = 0;
        while got.len() < n {
            if scanned > self.clusters {
                // Give back what was taken.
                for &g in &got {
                    self.fat[g as usize] = 0;
                }
                return Err(Error::TooSmall);
            }
            if !self.valid(c) {
                c = 2;
            }
            if self.fat[c as usize] == 0 {
                got.push(c);
                self.fat[c as usize] = END_OF_CHAIN; // Taken; linked below.
            }
            c += 1;
            scanned += 1;
        }
        for w in got.windows(2) {
            self.fat[w[0] as usize] = w[1];
        }
        if let Some(&last) = got.last() {
            self.fat[last as usize] = END_OF_CHAIN;
            self.hint = last + 1;
        }
        Ok(got)
    }

    fn free_chain(&mut self, first: u32) -> Result<(), Error> {
        let cs = self.chain(first)?;
        for &c in &cs {
            self.fat[c as usize] = 0;
        }
        self.write_fat(&cs)
    }

    /// The FSInfo sector's free count and next-free hint (§5), kept right.
    fn write_fsinfo(&mut self) -> Result<(), Error> {
        if self.fsinfo == 0 || self.fsinfo == 0xFFFF {
            return Ok(());
        }
        let mut s = [0u8; SECTOR];
        self.disk.read(self.fsinfo, &mut s)?;
        if s[0..4] != 0x4161_5252u32.to_le_bytes() {
            return Ok(());
        }
        let free = self.fat[2..].iter().filter(|&&v| v == 0).count() as u32;
        s[488..492].copy_from_slice(&free.to_le_bytes());
        s[492..496].copy_from_slice(&self.hint.to_le_bytes());
        self.disk.write(self.fsinfo, &s)
    }

    /// Every entry of the directory whose chain starts at `first`.
    fn entries(&mut self, first: u32) -> Result<Vec<Found>, Error> {
        let mut out = Vec::new();
        let mut long: Vec<(u8, u8, Vec<u16>, u64)> = Vec::new();
        for c in self.chain(first)? {
            let data = self.read_cluster(c)?;
            let base = self.cluster_sector(c) * SECTOR as u64;
            for (i, e) in data.as_chunks::<32>().0.iter().enumerate() {
                let at = base + i as u64 * 32;
                match e[0] {
                    0 => return Ok(out),
                    0xE5 => {
                        long.clear();
                        continue;
                    }
                    _ => {}
                }
                if e[11] & 0x3F == ATTR_LONG_NAME {
                    let mut units = Vec::new();
                    for o in (1..11).step_by(2).chain((14..26).step_by(2)).chain((28..32).step_by(2)) {
                        units.push(u16::from_le_bytes([e[o], e[o + 1]]));
                    }
                    long.push((e[0] & 0x1F, e[13], units, at));
                    continue;
                }
                let short: [u8; 11] = e[..11].try_into().unwrap();
                let parts = core::mem::take(&mut long);
                if e[11] & ATTR_VOLUME_ID != 0 || short[0] == b'.' {
                    continue;
                }
                // The long name if its pieces are whole and match (§7).
                let sum = checksum(&short);
                let whole = !parts.is_empty()
                    && parts.iter().all(|p| p.1 == sum)
                    && parts.iter().rev().enumerate().all(|(k, p)| usize::from(p.0) == k + 1);
                let name = if whole {
                    let units: Vec<u16> = parts.iter().rev().flat_map(|p| p.2.iter().copied()).collect();
                    let end = units.iter().position(|&u| u == 0 || u == 0xFFFF).unwrap_or(units.len());
                    char::decode_utf16(units[..end].iter().copied()).map(|r| r.unwrap_or('?')).collect()
                } else {
                    short_display(&short, e[12])
                };
                let cluster =
                    u32::from(u16::from_le_bytes([e[20], e[21]])) << 16 | u32::from(u16::from_le_bytes([e[26], e[27]]));
                out.push(Found {
                    name,
                    attr: e[11],
                    cluster,
                    size: u32::from_le_bytes([e[28], e[29], e[30], e[31]]),
                    short_at: at,
                    long_at: if whole { parts.iter().map(|p| p.3).collect() } else { Vec::new() },
                });
            }
        }
        Ok(out)
    }

    /// The directory `path` names: its first cluster.
    fn dir_cluster(&mut self, path: &str) -> Result<u32, Error> {
        let mut c = self.root;
        for part in parts(path) {
            let f = self.entries(c)?.into_iter().find(|f| f.name.eq_ignore_ascii_case(part)).ok_or(Error::NotFound)?;
            if f.attr & ATTR_DIRECTORY == 0 {
                return Err(Error::Exists);
            }
            c = if f.cluster == 0 { self.root } else { f.cluster };
        }
        Ok(c)
    }

    fn find(&mut self, path: &str) -> Result<(u32, Option<Found>), Error> {
        let (dir, name) = split(path);
        let c = self.dir_cluster(dir)?;
        let f = self.entries(c)?.into_iter().find(|f| f.name.eq_ignore_ascii_case(name));
        Ok((c, f))
    }

    /// What directory `path` holds.
    pub fn list(&mut self, path: &str) -> Result<Vec<DirEntry>, Error> {
        let c = self.dir_cluster(path)?;
        Ok(self
            .entries(c)?
            .into_iter()
            .map(|f| DirEntry { name: f.name, dir: f.attr & ATTR_DIRECTORY != 0, size: f.size })
            .collect())
    }

    /// Whether `path` exists (a file or a directory).
    pub fn exists(&mut self, path: &str) -> bool {
        matches!(self.find(path), Ok((_, Some(_))))
    }

    /// The contents of file `path`.
    pub fn read(&mut self, path: &str) -> Result<Vec<u8>, Error> {
        let f = self.find(path)?.1.ok_or(Error::NotFound)?;
        if f.attr & ATTR_DIRECTORY != 0 {
            return Err(Error::Exists);
        }
        let mut out = Vec::with_capacity(f.size as usize);
        let cb = self.cluster_bytes();
        for (c, n) in self.runs(f.cluster)? {
            // Only as much of the run as the file still needs.
            let want = (f.size as usize).saturating_sub(out.len()).div_ceil(cb).min(n as usize);
            let at = out.len();
            out.resize(at + want * cb, 0);
            self.disk.read_run(self.cluster_sector(c), &mut out[at..])?;
            if out.len() >= f.size as usize {
                break;
            }
        }
        if out.len() < f.size as usize {
            return Err(Error::Io);
        }
        out.truncate(f.size as usize);
        Ok(out)
    }

    /// The size of file `path`.
    pub fn size(&mut self, path: &str) -> Result<u64, Error> {
        let f = self.find(path)?.1.ok_or(Error::NotFound)?;
        if f.attr & ATTR_DIRECTORY != 0 {
            return Err(Error::Exists);
        }
        Ok(u64::from(f.size))
    }

    /// Read file `path` into `buf`, which must hold exactly its size (a
    /// file too large for memory in two copies, such as an initramfs).
    pub fn read_into(&mut self, path: &str, buf: &mut [u8]) -> Result<(), Error> {
        let f = self.find(path)?.1.ok_or(Error::NotFound)?;
        if f.attr & ATTR_DIRECTORY != 0 {
            return Err(Error::Exists);
        }
        if buf.len() != f.size as usize {
            return Err(Error::Io);
        }
        let cb = self.cluster_bytes();
        let mut done = 0;
        for (c, n) in self.runs(f.cluster)? {
            if done == buf.len() {
                break;
            }
            // Whole clusters straight into `buf`, a last partial one
            // through a cluster of its own.
            let whole = ((buf.len() - done) / cb).min(n as usize);
            if whole > 0 {
                self.disk.read_run(self.cluster_sector(c), &mut buf[done..done + whole * cb])?;
                done += whole * cb;
            }
            if whole < n as usize && done < buf.len() {
                let mut last = vec![0u8; cb];
                self.disk.read_run(self.cluster_sector(c + whole as u32), &mut last)?;
                let k = buf.len() - done;
                buf[done..].copy_from_slice(&last[..k]);
                done += k;
            }
        }
        if done < buf.len() {
            return Err(Error::Io);
        }
        Ok(())
    }

    /// Write a new chain holding `data` (data, then the FAT), and return its
    /// first cluster (0 for no data).
    fn store(&mut self, data: &[u8]) -> Result<u32, Error> {
        if data.is_empty() {
            return Ok(0);
        }
        let cs = self.allocate(data.len().div_ceil(self.cluster_bytes()))?;
        let cb = self.cluster_bytes();
        // Consecutive clusters in one write each.
        let mut i = 0;
        while i < cs.len() {
            let mut n = 1;
            while i + n < cs.len() && cs[i + n] == cs[i] + n as u32 {
                n += 1;
            }
            let end = ((i + n) * cb).min(data.len());
            self.write_clusters(cs[i], &data[i * cb..end])?;
            i += n;
        }
        self.write_fat(&cs)?;
        Ok(cs[0])
    }

    /// Change the 32 bytes at `at` (inside one sector) with `f`.
    fn patch(&mut self, at: u64, f: impl FnOnce(&mut [u8])) -> Result<(), Error> {
        let sector = at / SECTOR as u64;
        let mut s = [0u8; SECTOR];
        self.disk.read(sector, &mut s)?;
        let o = (at % SECTOR as u64) as usize;
        f(&mut s[o..o + 32]);
        self.disk.write(sector, &s)
    }

    /// Free slots for `n` entries in directory `dir` (growing it by a zeroed
    /// cluster if it is full): their byte offsets, consecutive.
    fn slots(&mut self, dir: u32, n: usize) -> Result<Vec<u64>, Error> {
        let mut run: Vec<u64> = Vec::new();
        let chain = self.chain(dir)?;
        for &c in &chain {
            let data = self.read_cluster(c)?;
            let base = self.cluster_sector(c) * SECTOR as u64;
            for (i, e) in data.as_chunks::<32>().0.iter().enumerate() {
                if e[0] == 0 || e[0] == 0xE5 {
                    run.push(base + i as u64 * 32);
                    if run.len() == n {
                        return Ok(run);
                    }
                } else {
                    run.clear();
                }
            }
        }
        // A new cluster, zeroed (end-of-directory marks), linked last.
        let new = self.allocate(1)?[0];
        self.write_cluster(new, &vec![0u8; self.cluster_bytes()])?;
        let last = *chain.last().ok_or(Error::Io)?;
        self.fat[last as usize] = new;
        self.write_fat(&[new, last])?;
        self.disk.flush()?;
        let base = self.cluster_sector(new) * SECTOR as u64;
        // Slots that ran on to the old end continue into the new cluster
        // only if they reached it; start afresh otherwise.
        let reaches_end = run
            .last()
            .is_some_and(|&a| a + 32 == self.cluster_sector(last) * SECTOR as u64 + self.cluster_bytes() as u64);
        if !reaches_end {
            run.clear();
        }
        let mut k = 0;
        while run.len() < n {
            run.push(base + k * 32);
            k += 1;
        }
        Ok(run)
    }

    /// A short name for `name` not yet used in directory `dir`.
    fn short_for(&mut self, dir: u32, name: &str) -> Result<([u8; 11], bool), Error> {
        let used: Vec<[u8; 11]> = {
            let mut v = Vec::new();
            for c in self.chain(dir)? {
                let data = self.read_cluster(c)?;
                for e in data.as_chunks::<32>().0 {
                    if e[0] == 0 {
                        break;
                    }
                    if e[0] != 0xE5 && e[11] & 0x3F != ATTR_LONG_NAME {
                        v.push(e[..11].try_into().unwrap());
                    }
                }
            }
            v
        };
        if let Some(s) = short_name_exact(name) {
            return Ok((s, false));
        }
        let s =
            (1..1_000_000).map(|i| short_name_generated(name, i)).find(|s| !used.contains(s)).ok_or(Error::TooLarge)?;
        Ok((s, true))
    }

    /// Add an entry for `name` in directory `dir`: long-name entries first,
    /// the short one (which makes it visible) last.
    fn add_entry(&mut self, dir: u32, name: &str, attr: u8, cluster: u32, size: u32) -> Result<(), Error> {
        let (short, long) = self.short_for(dir, name)?;
        let longs = if long { long_entries(name, &short) } else { Vec::new() };
        let at = self.slots(dir, longs.len() + 1)?;
        for (e, &a) in longs.iter().zip(&at) {
            self.patch(a, |s| s.copy_from_slice(e))?;
        }
        if !longs.is_empty() {
            self.disk.flush()?;
        }
        let mut e = entry(&short, attr, cluster, size);
        self.stamp(&mut e);
        self.patch(at[longs.len()], |s| s.copy_from_slice(&e))?;
        self.disk.flush()
    }

    fn stamp(&self, e: &mut [u8; 32]) {
        e[14..16].copy_from_slice(&self.time.to_le_bytes());
        e[16..18].copy_from_slice(&self.date.to_le_bytes());
        e[18..20].copy_from_slice(&self.date.to_le_bytes());
        e[22..24].copy_from_slice(&self.time.to_le_bytes());
        e[24..26].copy_from_slice(&self.date.to_le_bytes());
    }

    /// Create directory `path`, and its parents.
    pub fn mkdir(&mut self, path: &str) -> Result<(), Error> {
        let mut done = String::new();
        for part in parts(path) {
            check_name(part)?;
            let here = alloc::format!("{done}/{part}");
            match self.find(&here)?.1 {
                Some(f) if f.attr & ATTR_DIRECTORY != 0 => {}
                Some(_) => return Err(Error::Exists),
                None => {
                    let parent = self.dir_cluster(&done)?;
                    let me = self.allocate(1)?[0];
                    let mut raw = vec![0u8; self.cluster_bytes()];
                    let mut dot = entry(b".          ", ATTR_DIRECTORY, me, 0);
                    // ".." names the root as cluster 0 (§6.4).
                    let mut dotdot =
                        entry(b"..         ", ATTR_DIRECTORY, if parent == self.root { 0 } else { parent }, 0);
                    self.stamp(&mut dot);
                    self.stamp(&mut dotdot);
                    raw[..32].copy_from_slice(&dot);
                    raw[32..64].copy_from_slice(&dotdot);
                    self.write_cluster(me, &raw)?;
                    self.write_fat(&[me])?;
                    self.disk.flush()?;
                    self.add_entry(parent, part, ATTR_DIRECTORY, me, 0)?;
                }
            }
            done = here;
        }
        self.write_fsinfo()?;
        self.disk.flush()
    }

    /// Write file `path` (its directory must exist): a new file appears
    /// whole, a replaced one changes from the old contents to the new in
    /// one sector write.
    pub fn write(&mut self, path: &str, data: &[u8]) -> Result<(), Error> {
        let (_, name) = split(path);
        check_name(name)?;
        let size = u32::try_from(data.len()).map_err(|_| Error::TooLarge)?;
        let (dc, old) = self.find(path)?;
        if old.as_ref().is_some_and(|f| f.attr & ATTR_DIRECTORY != 0) {
            return Err(Error::Exists);
        }
        let first = self.store(data)?;
        self.disk.flush()?;
        match old {
            Some(f) => {
                let (date, time) = (self.date, self.time);
                self.patch(f.short_at, |e| {
                    e[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
                    e[26..28].copy_from_slice(&(first as u16).to_le_bytes());
                    e[28..32].copy_from_slice(&size.to_le_bytes());
                    e[22..24].copy_from_slice(&time.to_le_bytes());
                    e[24..26].copy_from_slice(&date.to_le_bytes());
                })?;
                self.disk.flush()?;
                if f.cluster != 0 {
                    self.free_chain(f.cluster)?;
                }
            }
            None => self.add_entry(dc, name, ATTR_ARCHIVE, first, size)?,
        }
        self.write_fsinfo()?;
        self.disk.flush()
    }

    /// Delete file or empty directory `path`: its short-name entry goes
    /// first, in one write.
    pub fn remove(&mut self, path: &str) -> Result<(), Error> {
        let f = self.find(path)?.1.ok_or(Error::NotFound)?;
        if f.attr & ATTR_DIRECTORY != 0 && !self.entries(f.cluster)?.is_empty() {
            return Err(Error::NotEmpty);
        }
        self.patch(f.short_at, |e| e[0] = 0xE5)?;
        self.disk.flush()?;
        for &a in &f.long_at {
            self.patch(a, |e| e[0] = 0xE5)?;
        }
        if f.cluster != 0 {
            self.free_chain(f.cluster)?;
        }
        self.write_fsinfo()?;
        self.disk.flush()
    }

    /// Delete `path` and everything under it.
    pub fn remove_tree(&mut self, path: &str) -> Result<(), Error> {
        let f = self.find(path)?.1.ok_or(Error::NotFound)?;
        if f.attr & ATTR_DIRECTORY != 0 {
            for e in self.entries(f.cluster)? {
                self.remove_tree(&alloc::format!("{}/{}", path.trim_end_matches('/'), e.name))?;
            }
        }
        self.remove(path)
    }
}

fn parts(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|p| !p.is_empty())
}

fn split(path: &str) -> (&str, &str) {
    let p = path.trim_matches('/');
    p.rsplit_once('/').unwrap_or(("", p))
}

/// A short name as text: `NAME.EXT`, lower-cased where the entry says so
/// (byte 12, bits 3 and 4, as Windows NT writes them).
fn short_display(s: &[u8; 11], case: u8) -> String {
    let lower = |b: &[u8], on: bool| -> String {
        let t = core::str::from_utf8(b).unwrap_or("?").trim_end();
        if on { t.to_ascii_lowercase() } else { String::from(t) }
    };
    let base = lower(&s[..8], case & 0x08 != 0);
    let ext = lower(&s[8..], case & 0x10 != 0);
    if ext.is_empty() { base } else { alloc::format!("{base}.{ext}") }
}
