// SPDX-License-Identifier: MIT OR Apache-2.0

//! The tar format, ours: POSIX.1-2001 ustar headers and pax extended
//! headers (the `pax` utility's description in POSIX, "pax Interchange
//! Format"), and GNU tar's additions as its documentation describes
//! them: long-name entries (`L`, `K`), base-256 numbers, sparse files
//! (the old `S` entries and pax formats 0.1 and 1.0) and extended
//! attributes in `SCHILY.xattr.` records.
//!
//! A header is 512 bytes: name[100] mode[8] uid[8] gid[8] size[12]
//! mtime[12] chksum[8] typeflag[1] linkname[100] magic[6] version[2]
//! uname[32] gname[32] devmajor[8] devminor[8] prefix[155]; numbers are
//! octal; the checksum is the sum of the header's bytes with its own field
//! as spaces. Data follows in 512-byte blocks; two zero blocks end the
//! archive.
//!
//! [`Reader`] reads an archive from a source an entry at a time, its data
//! in pieces; [`header`] writes an entry's headers. [`entries`] and
//! [`Builder`] do the same with whole archives in memory.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec;
use alloc::vec::Vec;

pub use slate_flate::{SliceSource, Source};

pub const BLOCK: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The archive ends inside a header or an entry's data.
    Truncated,
    /// A header whose checksum is wrong.
    Checksum,
    /// A number or pax record that does not parse.
    Malformed,
    /// The source failed.
    Io,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    HardLink,
    Symlink,
    Char,
    Block,
    Dir,
    Fifo,
}

impl Kind {
    fn flag(self) -> u8 {
        match self {
            Kind::File => b'0',
            Kind::HardLink => b'1',
            Kind::Symlink => b'2',
            Kind::Char => b'3',
            Kind::Block => b'4',
            Kind::Dir => b'5',
            Kind::Fifo => b'6',
        }
    }
}

/// An entry's facts (its data comes separately).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub path: Vec<u8>,
    pub link: Vec<u8>,
    pub kind: Option<Kind>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
    pub uname: Vec<u8>,
    pub gname: Vec<u8>,
    pub dev: (u32, u32),
    /// Bytes of data the archive holds for it.
    pub size: u64,
    /// For a sparse file: its length and where its data lies (offset,
    /// length), the archive holding only those pieces, each starting on
    /// a block (padded with zeros to 512 bytes, as GNU tar reads them).
    pub sparse: Option<(u64, Vec<(u64, u64)>)>,
    /// Extended attributes (name, value).
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Header {
    pub fn kind(&self) -> Kind {
        self.kind.unwrap_or(Kind::File)
    }

    /// The file's length (a sparse one's whole length).
    pub fn real_size(&self) -> u64 {
        self.sparse.as_ref().map_or(self.size, |s| s.0)
    }
}

/// An entry: its facts and data (for files), for [`entries`] and
/// [`Builder`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub path: Vec<u8>,
    pub link: Vec<u8>,
    pub kind: Kind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
    pub uname: Vec<u8>,
    pub gname: Vec<u8>,
    pub dev: (u32, u32),
    pub data: &'a [u8],
}

fn field(h: &[u8]) -> &[u8] {
    &h[..h.iter().position(|&b| b == 0).unwrap_or(h.len())]
}

/// An octal number, or GNU's base-256 form (high bit of the first byte).
fn number(h: &[u8]) -> Result<u64, Error> {
    if h.first().is_some_and(|b| b & 0x80 != 0) {
        let mut v = u64::from(h[0] & 0x7F);
        for &b in &h[1..] {
            v = v.checked_mul(256).ok_or(Error::Malformed)? | u64::from(b);
        }
        return Ok(v);
    }
    let s = field(h);
    let s: Vec<u8> = s.iter().copied().filter(|b| *b != b' ').collect();
    if s.is_empty() {
        return Ok(0);
    }
    let mut v = 0u64;
    for &b in &s {
        if !(b'0'..=b'7').contains(&b) {
            return Err(Error::Malformed);
        }
        v = v.checked_mul(8).ok_or(Error::Malformed)? + u64::from(b - b'0');
    }
    Ok(v)
}

fn checksum(h: &[u8]) -> u64 {
    h.iter().enumerate().map(|(i, &b)| if (148..156).contains(&i) { 32 } else { u64::from(b) }).sum()
}

/// pax records (`LEN key=value\n`): the overrides they give.
#[derive(Clone, Default)]
struct Pax {
    path: Option<Vec<u8>>,
    link: Option<Vec<u8>>,
    size: Option<u64>,
    mtime: Option<i64>,
    uid: Option<u32>,
    gid: Option<u32>,
    uname: Option<Vec<u8>>,
    gname: Option<Vec<u8>>,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    /// GNU's sparse records: format version, the name, the length, and
    /// version 0.1's map.
    sparse_major: Option<u64>,
    sparse_name: Option<Vec<u8>>,
    sparse_size: Option<u64>,
    sparse_map: Option<Vec<(u64, u64)>>,
}

fn decimal(v: &[u8]) -> Option<u64> {
    let s = core::str::from_utf8(v).ok()?;
    s.split('.').next()?.parse().ok()
}

fn signed(v: &[u8]) -> Option<i64> {
    let s = core::str::from_utf8(v).ok()?;
    s.split('.').next()?.parse().ok()
}

fn parse_pax(mut d: &[u8], p: &mut Pax) -> Result<(), Error> {
    while !d.is_empty() {
        let sp = d.iter().position(|&b| b == b' ').ok_or(Error::Malformed)?;
        let len: usize = core::str::from_utf8(&d[..sp]).ok().and_then(|s| s.parse().ok()).ok_or(Error::Malformed)?;
        if len <= sp || len > d.len() {
            return Err(Error::Malformed);
        }
        let rec = &d[sp + 1..len - 1];
        let eq = rec.iter().position(|&b| b == b'=').ok_or(Error::Malformed)?;
        let (k, v) = (&rec[..eq], &rec[eq + 1..]);
        match k {
            b"path" => p.path = Some(v.to_vec()),
            b"linkpath" => p.link = Some(v.to_vec()),
            b"size" => p.size = decimal(v),
            b"mtime" => p.mtime = signed(v),
            b"uid" => p.uid = decimal(v).map(|n| n as u32),
            b"gid" => p.gid = decimal(v).map(|n| n as u32),
            b"uname" => p.uname = Some(v.to_vec()),
            b"gname" => p.gname = Some(v.to_vec()),
            b"GNU.sparse.major" => p.sparse_major = decimal(v),
            b"GNU.sparse.name" => p.sparse_name = Some(v.to_vec()),
            b"GNU.sparse.realsize" | b"GNU.sparse.size" => p.sparse_size = decimal(v),
            b"GNU.sparse.map" => {
                let nums: Option<Vec<u64>> = v.split(|&c| c == b',').map(decimal).collect();
                let nums = nums.ok_or(Error::Malformed)?;
                p.sparse_map = Some(nums.chunks(2).filter(|c| c.len() == 2).map(|c| (c[0], c[1])).collect());
                p.sparse_major.get_or_insert(0);
            }
            _ => {
                if let Some(name) = k.strip_prefix(b"SCHILY.xattr.") {
                    p.xattrs.push((name.to_vec(), v.to_vec()));
                }
            }
        }
        d = &d[len..];
    }
    Ok(())
}

/// Reading an archive from a source, an entry at a time.
pub struct Reader<S: Source> {
    src: S,
    buf: Vec<u8>,
    pos: usize,
    len: usize,
    eof: bool,
    /// Bytes taken from the source.
    taken: u64,
    /// The current entry's data still to be read, and the padding after it.
    left: u64,
    pad: u64,
    global: Pax,
    /// Where the last header (or the end) started.
    header_at: u64,
}

impl<S: Source> core::fmt::Debug for Reader<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reader").field("taken", &self.taken).finish()
    }
}

impl<S: Source> Reader<S> {
    pub fn new(src: S) -> Reader<S> {
        Reader {
            src,
            buf: vec![0; 64 * 1024],
            pos: 0,
            len: 0,
            eof: false,
            taken: 0,
            left: 0,
            pad: 0,
            global: Pax::default(),
            header_at: 0,
        }
    }

    fn fill(&mut self) -> Result<bool, Error> {
        if self.pos < self.len {
            return Ok(true);
        }
        if self.eof {
            return Ok(false);
        }
        self.len = self.src.fill(&mut self.buf).map_err(|_| Error::Io)?;
        self.pos = 0;
        if self.len == 0 {
            self.eof = true;
        }
        Ok(self.len > 0)
    }

    /// Up to `out.len()` bytes; fewer only at the end.
    fn read_raw(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        let mut n = 0;
        while n < out.len() && self.fill()? {
            let k = (out.len() - n).min(self.len - self.pos);
            out[n..n + k].copy_from_slice(&self.buf[self.pos..self.pos + k]);
            self.pos += k;
            n += k;
        }
        self.taken += n as u64;
        Ok(n)
    }

    fn skip_raw(&mut self, mut n: u64) -> Result<(), Error> {
        while n > 0 {
            if !self.fill()? {
                return Err(Error::Truncated);
            }
            let k = (n as usize).min(self.len - self.pos);
            self.pos += k;
            self.taken += k as u64;
            n -= k as u64;
        }
        Ok(())
    }

    fn block(&mut self) -> Result<Option<[u8; BLOCK]>, Error> {
        let mut b = [0u8; BLOCK];
        match self.read_raw(&mut b)? {
            0 => Ok(None),
            BLOCK => Ok(Some(b)),
            _ => Err(Error::Truncated),
        }
    }

    /// A whole small entry's data (pax records, long names), with its
    /// padding.
    fn small_data(&mut self, size: u64) -> Result<Vec<u8>, Error> {
        if size > 16 << 20 {
            return Err(Error::Malformed);
        }
        let mut d = vec![0u8; size as usize];
        if self.read_raw(&mut d)? != d.len() {
            return Err(Error::Truncated);
        }
        self.skip_raw(size.div_ceil(BLOCK as u64) * BLOCK as u64 - size)?;
        Ok(d)
    }

    /// Where the last entry's header began, or the end of the archive
    /// once [`next`](Self::next) has said there are no more.
    pub fn header_offset(&self) -> u64 {
        self.header_at
    }

    /// Bytes read from the source so far.
    pub fn offset(&self) -> u64 {
        self.taken
    }

    /// The next entry's header, skipping what was left of the last one's
    /// data; None at the end of the archive.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Header>, Error> {
        let rest = self.left + self.pad;
        self.left = 0;
        self.pad = 0;
        self.skip_raw(rest)?;
        let mut pax = Pax::default();
        let (mut long_name, mut long_link): (Option<Vec<u8>>, Option<Vec<u8>>) = (None, None);
        let mut first = true;
        loop {
            let at = self.taken;
            if first {
                self.header_at = at;
                first = false;
            }
            let Some(h) = self.block()? else {
                // Archives that end without their two zero blocks are common.
                self.header_at = at;
                return Ok(None);
            };
            if h.iter().all(|&b| b == 0) {
                self.header_at = at;
                return Ok(None);
            }
            if number(&h[148..156])? != checksum(&h) {
                return Err(Error::Checksum);
            }
            let flag = h[156];
            let size = match pax.size {
                Some(s) if !matches!(flag, b'x' | b'g') => s,
                _ => number(&h[124..136])?,
            };
            match flag {
                b'x' => {
                    let d = self.small_data(size)?;
                    parse_pax(&d, &mut pax)?;
                    continue;
                }
                b'g' => {
                    let d = self.small_data(size)?;
                    parse_pax(&d, &mut self.global)?;
                    continue;
                }
                b'L' => {
                    long_name = Some(field(&self.small_data(size)?).to_vec());
                    continue;
                }
                b'K' => {
                    long_link = Some(field(&self.small_data(size)?).to_vec());
                    continue;
                }
                _ => {}
            }
            let kind = match flag {
                b'1' => Kind::HardLink,
                b'2' => Kind::Symlink,
                b'3' => Kind::Char,
                b'4' => Kind::Block,
                b'5' => Kind::Dir,
                b'6' => Kind::Fifo,
                _ => Kind::File,
            };
            let ustar = &h[257..262] == b"ustar";
            let mut path = field(&h[..100]).to_vec();
            // GNU's own format puts the access and change times where
            // ustar has the prefix.
            let gnu = &h[257..265] == b"ustar  \0";
            if ustar && !gnu && h[345] != 0 {
                let mut p = field(&h[345..500]).to_vec();
                p.push(b'/');
                p.extend_from_slice(&path);
                path = p;
            }
            let path = pax.path.take().or(long_name.take()).or(self.global.path.clone()).unwrap_or(path);
            let link = pax.link.take().or(long_link.take()).unwrap_or_else(|| field(&h[157..257]).to_vec());
            let kind = if kind == Kind::File && path.ends_with(b"/") { Kind::Dir } else { kind };
            let mut hd = Header {
                path,
                link,
                kind: Some(kind),
                mode: number(&h[100..108])? as u32 & 0o7777,
                uid: pax.uid.or(self.global.uid).map_or_else(|| number(&h[108..116]).map(|n| n as u32), Ok)?,
                gid: pax.gid.or(self.global.gid).map_or_else(|| number(&h[116..124]).map(|n| n as u32), Ok)?,
                mtime: pax.mtime.map_or_else(|| number(&h[136..148]).map(|n| n as i64), Ok)?,
                uname: pax
                    .uname
                    .take()
                    .unwrap_or_else(|| if ustar { field(&h[265..297]).to_vec() } else { Vec::new() }),
                gname: pax
                    .gname
                    .take()
                    .unwrap_or_else(|| if ustar { field(&h[297..329]).to_vec() } else { Vec::new() }),
                dev: if ustar { (number(&h[329..337])? as u32, number(&h[337..345])? as u32) } else { (0, 0) },
                size: if matches!(kind, Kind::File) || flag == b'S' { size } else { 0 },
                sparse: None,
                xattrs: core::mem::take(&mut pax.xattrs),
            };
            if flag == b'S' {
                hd.sparse = Some(self.old_gnu_sparse(&h)?);
            } else if let Some(major) = pax.sparse_major {
                let real = pax.sparse_size.unwrap_or(hd.size);
                if let Some(n) = pax.sparse_name.take() {
                    hd.path = n;
                }
                let map = match (major, pax.sparse_map.take()) {
                    (0, Some(m)) => m,
                    // 1.0: the map starts the data, decimal numbers a
                    // line, padded to a block.
                    (1, _) => {
                        let (map, used) = self.sparse_map_1()?;
                        hd.size = hd.size.checked_sub(used).ok_or(Error::Malformed)?;
                        map
                    }
                    _ => return Err(Error::Malformed),
                };
                hd.sparse = Some((real, map));
            }
            self.left = hd.size;
            self.pad = size.div_ceil(BLOCK as u64) * BLOCK as u64 - size;
            if !matches!(kind, Kind::File) && flag != b'S' {
                // Data that does not belong to the entry is skipped.
                self.pad += size;
            }
            return Ok(Some(hd));
        }
    }

    /// The old GNU sparse header's map (and its extension blocks).
    fn old_gnu_sparse(&mut self, h: &[u8; BLOCK]) -> Result<(u64, Vec<(u64, u64)>), Error> {
        let mut map = Vec::new();
        let take = |blk: &[u8], n: usize, map: &mut Vec<(u64, u64)>| -> Result<(), Error> {
            for i in 0..n {
                let e = &blk[i * 24..i * 24 + 24];
                if e[0] == 0 {
                    break;
                }
                map.push((number(&e[..12])?, number(&e[12..])?));
            }
            Ok(())
        };
        take(&h[386..482], 4, &mut map)?;
        let real = number(&h[483..495])?;
        let mut more = h[482] != 0;
        while more {
            let b = self.block()?.ok_or(Error::Truncated)?;
            take(&b[..504], 21, &mut map)?;
            more = b[504] != 0;
        }
        Ok((real, map))
    }

    /// Format 1.0's map at the start of the data: the bytes it took.
    fn sparse_map_1(&mut self) -> Result<(Vec<(u64, u64)>, u64), Error> {
        let mut used = 0u64;
        let mut line = Vec::new();
        let mut nums = Vec::new();
        let mut want: Option<u64> = None;
        loop {
            let b = self.block()?.ok_or(Error::Truncated)?;
            used += BLOCK as u64;
            for &c in b.iter() {
                if c == b'\n' {
                    let v = decimal(&line).ok_or(Error::Malformed)?;
                    line.clear();
                    match want {
                        None => want = Some(v * 2),
                        Some(_) => nums.push(v),
                    }
                    if want.is_some_and(|w| nums.len() as u64 == w) {
                        let map = nums.chunks(2).map(|c| (c[0], c[1])).collect();
                        return Ok((map, used));
                    }
                } else {
                    line.push(c);
                }
            }
            if used > 64 << 20 {
                return Err(Error::Malformed);
            }
        }
    }

    /// Read the current entry's data (a sparse file's stored pieces, one
    /// after another); 0 at its end.
    pub fn read_data(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        let want = (self.left as usize).min(out.len());
        if want == 0 {
            return Ok(0);
        }
        let n = self.read_raw(&mut out[..want])?;
        if n == 0 {
            return Err(Error::Truncated);
        }
        self.left -= n as u64;
        Ok(n)
    }
}

// --- Writing -------------------------------------------------------------------

fn octal(field: &mut [u8], v: u64) {
    let n = field.len() - 1;
    let s = alloc::format!("{v:0n$o}");
    let s = s.as_bytes();
    if s.len() <= n {
        field[..n].copy_from_slice(s);
        field[n] = 0;
    } else {
        // Too large for octal: base-256.
        field.fill(0);
        let mut x = v;
        for b in field.iter_mut().rev() {
            *b = x as u8;
            x >>= 8;
        }
        field[0] |= 0x80;
    }
}

/// One pax record (`LEN key=value\n`, LEN counting itself).
fn record(out: &mut Vec<u8>, k: &[u8], v: &[u8]) {
    let body_len = 1 + k.len() + 1 + v.len() + 1;
    let mut len = body_len + 1;
    while alloc::format!("{len}").len() + body_len != len {
        len = alloc::format!("{len}").len() + body_len;
    }
    out.extend_from_slice(alloc::format!("{len} ").as_bytes());
    out.extend_from_slice(k);
    out.push(b'=');
    out.extend_from_slice(v);
    out.push(b'\n');
}

fn raw_header(h: &Header, name: &[u8], prefix: &[u8], link: &[u8], flag: u8, size: u64) -> [u8; BLOCK] {
    let mut b = [0u8; BLOCK];
    b[..name.len().min(100)].copy_from_slice(&name[..name.len().min(100)]);
    octal(&mut b[100..108], u64::from(h.mode));
    octal(&mut b[108..116], u64::from(h.uid));
    octal(&mut b[116..124], u64::from(h.gid));
    octal(&mut b[124..136], size);
    octal(&mut b[136..148], h.mtime.max(0) as u64);
    b[156] = flag;
    b[157..157 + link.len().min(100)].copy_from_slice(&link[..link.len().min(100)]);
    b[257..263].copy_from_slice(b"ustar\0");
    b[263..265].copy_from_slice(b"00");
    b[265..265 + h.uname.len().min(31)].copy_from_slice(&h.uname[..h.uname.len().min(31)]);
    b[297..297 + h.gname.len().min(31)].copy_from_slice(&h.gname[..h.gname.len().min(31)]);
    octal(&mut b[329..337], u64::from(h.dev.0));
    octal(&mut b[337..345], u64::from(h.dev.1));
    b[345..345 + prefix.len()].copy_from_slice(prefix);
    let sum = checksum(&b);
    b[148..156].copy_from_slice(&alloc::format!("{sum:06o}\0 ").into_bytes());
    b
}

/// The bytes that start entry `h`: a pax header when ustar's fields
/// cannot hold its facts (long names, large numbers, extended attributes,
/// a sparse map), then its ustar header, then for a sparse file the
/// start of its data (format 1.0's map). `h.size` is the bytes of data
/// that follow (a sparse file's pieces, each padded to a block).
pub fn header(h: &Header) -> Vec<u8> {
    let kind = h.kind();
    let mut path = h.path.clone();
    if kind == Kind::Dir && !path.ends_with(b"/") {
        path.push(b'/');
    }
    let mut records = Vec::new();
    let mut map_block = Vec::new();
    let mut size = if matches!(kind, Kind::File) { h.size } else { 0 };
    if let Some((real, map)) = &h.sparse {
        record(&mut records, b"GNU.sparse.major", b"1");
        record(&mut records, b"GNU.sparse.minor", b"0");
        record(&mut records, b"GNU.sparse.name", &path);
        record(&mut records, b"GNU.sparse.realsize", alloc::format!("{real}").as_bytes());
        map_block.extend_from_slice(alloc::format!("{}\n", map.len()).as_bytes());
        for (o, l) in map {
            map_block.extend_from_slice(alloc::format!("{o}\n{l}\n").as_bytes());
        }
        map_block.resize(map_block.len().div_ceil(BLOCK) * BLOCK, 0);
        size += map_block.len() as u64;
        // The ustar name is one GNU tar's convention gives such files.
        let base = path.rsplit(|&c| c == b'/').next().unwrap_or(&path).to_vec();
        let dir_len = path.len() - base.len();
        path = [&path[..dir_len], b"GNUSparseFile.0/", &base].concat();
    }
    // A long name splits into prefix/name at a slash, else goes in a pax
    // record; so does a long link target.
    let split = (path.len() > 100)
        .then(|| (1..path.len().min(156)).rev().find(|&i| path[i] == b'/' && path.len() - i - 1 <= 100))
        .flatten();
    if path.len() > 100 && split.is_none() {
        record(&mut records, b"path", &path);
    }
    if h.link.len() > 100 {
        record(&mut records, b"linkpath", &h.link);
    }
    if size >= 1 << 33 {
        record(&mut records, b"size", alloc::format!("{size}").as_bytes());
    }
    if h.mtime < 0 || h.mtime >= 1 << 33 {
        record(&mut records, b"mtime", alloc::format!("{}", h.mtime).as_bytes());
    }
    if h.uid >= 1 << 21 {
        record(&mut records, b"uid", alloc::format!("{}", h.uid).as_bytes());
    }
    if h.gid >= 1 << 21 {
        record(&mut records, b"gid", alloc::format!("{}", h.gid).as_bytes());
    }
    if h.uname.len() > 31 {
        record(&mut records, b"uname", &h.uname);
    }
    if h.gname.len() > 31 {
        record(&mut records, b"gname", &h.gname);
    }
    for (k, v) in &h.xattrs {
        record(&mut records, &[b"SCHILY.xattr.".as_slice(), k].concat(), v);
    }
    let mut out = Vec::new();
    if !records.is_empty() {
        let ph = Header { uname: Vec::new(), gname: Vec::new(), ..h.clone() };
        out.extend_from_slice(&raw_header(&ph, b"././@PaxHeader", b"", b"", b'x', records.len() as u64));
        out.extend_from_slice(&records);
        out.resize(out.len().div_ceil(BLOCK) * BLOCK, 0);
    }
    let (prefix, name) = match split {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => (&b""[..], &path[..path.len().min(100)]),
    };
    out.extend_from_slice(&raw_header(h, name, prefix, &h.link, kind.flag(), size));
    out.extend_from_slice(&map_block);
    out
}

/// The zeros that round `size` bytes of data up to whole blocks.
pub fn padding(size: u64) -> usize {
    (size.div_ceil(BLOCK as u64) * BLOCK as u64 - size) as usize
}

/// The archive's end: two zero blocks.
pub const END: [u8; 2 * BLOCK] = [0; 2 * BLOCK];

// --- Whole archives in memory -----------------------------------------------------

/// The entries of `archive`, in order (a sparse file's data is its
/// pieces as stored, each padded to a block).
pub fn entries(archive: &[u8]) -> Result<Vec<Entry<'_>>, Error> {
    let mut r = Reader::new(SliceSource::new(archive));
    let mut out = Vec::new();
    while let Some(h) = r.next()? {
        let start = r.offset() as usize;
        let data = archive.get(start..start + h.size as usize).ok_or(Error::Truncated)?;
        out.push(Entry {
            path: h.path.clone(),
            link: h.link.clone(),
            kind: h.kind(),
            mode: h.mode,
            uid: h.uid,
            gid: h.gid,
            mtime: h.mtime,
            uname: h.uname.clone(),
            gname: h.gname.clone(),
            dev: h.dev,
            data: if h.kind() == Kind::File { data } else { &[] },
        });
    }
    Ok(out)
}

/// Writing an archive in memory.
#[derive(Debug, Default)]
pub struct Builder {
    out: Vec<u8>,
}

impl Builder {
    pub fn new() -> Builder {
        Builder::default()
    }

    /// Add an entry (`e.data` for files).
    pub fn add(&mut self, e: &Entry<'_>) {
        let h = Header {
            path: e.path.clone(),
            link: e.link.clone(),
            kind: Some(e.kind),
            mode: e.mode,
            uid: e.uid,
            gid: e.gid,
            mtime: e.mtime,
            uname: e.uname.clone(),
            gname: e.gname.clone(),
            dev: e.dev,
            size: if e.kind == Kind::File { e.data.len() as u64 } else { 0 },
            sparse: None,
            xattrs: Vec::new(),
        };
        self.out.extend(header(&h));
        if e.kind == Kind::File {
            self.out.extend_from_slice(e.data);
            self.out.resize(self.out.len() + padding(e.data.len() as u64), 0);
        }
    }

    /// The archive: two zero blocks, padded to a 10240-byte record (the
    /// usual blocking factor of 20).
    pub fn finish(mut self) -> Vec<u8> {
        self.out.extend_from_slice(&END);
        let n = self.out.len().div_ceil(10240) * 10240;
        self.out.resize(n, 0);
        self.out
    }
}

#[cfg(test)]
mod tests;
