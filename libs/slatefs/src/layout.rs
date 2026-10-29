// SPDX-License-Identifier: MIT OR Apache-2.0

//! On-disk structures (ADR 0026): the superblock, keys, checksummed block
//! pointers, and the records stored in trees. Little-endian throughout.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{Error, Result};

pub const BLOCK: usize = 4096;
pub const MAGIC: &[u8; 8] = b"SLATEFS1";
pub const VERSION: u32 = 1;

/// Item kinds in keys (`(object id, kind, offset)`).
pub const KIND_INODE: u8 = 1;
pub const KIND_DIRENT: u8 = 2;
pub const KIND_EXTENT: u8 = 3;
pub const KIND_INLINE: u8 = 4;
pub const KIND_ORPHAN: u8 = 5;
pub const KIND_SUBVOL: u8 = 6;
/// Extended attributes: `(inode, KIND_XATTR, name_hash(name))` holds the
/// attributes whose names share that hash.
pub const KIND_XATTR: u8 = 7;

/// The root directory of every subvolume.
pub const ROOT_INO: u64 = 1;
/// Longest extent, in blocks.
pub const MAX_EXTENT: u64 = 32;
/// Longest symlink target.
pub const MAX_INLINE: usize = 2048;
pub const NAME_MAX: usize = 255;

pub fn get_u16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
pub fn get_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
pub fn get_u64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
pub fn put_u16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
pub fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
pub fn put_u64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// A tree key, ordered by (object id, kind, offset).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Key {
    pub object: u64,
    pub kind: u8,
    pub offset: u64,
}

pub const KEY_LEN: usize = 17;

impl Key {
    pub const fn new(object: u64, kind: u8, offset: u64) -> Key {
        Key { object, kind, offset }
    }

    pub fn encode(&self, b: &mut [u8]) {
        put_u64(b, 0, self.object);
        b[8] = self.kind;
        put_u64(b, 9, self.offset);
    }

    pub fn decode(b: &[u8]) -> Key {
        Key { object: get_u64(b, 0), kind: b[8], offset: get_u64(b, 9) }
    }
}

/// A pointer to a tree node: where, which commit wrote it, and the node's
/// CRC-32C.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct BlockPtr {
    pub block: u64,
    pub generation: u64,
    pub crc: u32,
}

pub const PTR_LEN: usize = 20;

impl BlockPtr {
    pub fn encode(&self, b: &mut [u8]) {
        put_u64(b, 0, self.block);
        put_u64(b, 8, self.generation);
        put_u32(b, 16, self.crc);
    }

    pub fn decode(b: &[u8]) -> BlockPtr {
        BlockPtr { block: get_u64(b, 0), generation: get_u64(b, 8), crc: get_u32(b, 16) }
    }
}

/// Boot state for atomic updates (ADR 0027).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct BootState {
    /// Subvolume to boot (0: none chosen yet).
    pub default: u64,
    /// The previous system, booted after failed tries or on request.
    pub fallback: u64,
    /// Boots left before falling back.
    pub tries: u8,
    /// The default has not been confirmed good yet.
    pub pending: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Superblock {
    pub blocks: u64,
    pub generation: u64,
    pub root: BlockPtr,
    pub next_subvol: u64,
    pub uuid: [u8; 16],
    pub label: String,
    pub boot: BootState,
}

impl Superblock {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = alloc::vec![0u8; BLOCK];
        b[..8].copy_from_slice(MAGIC);
        put_u32(&mut b, 8, VERSION);
        put_u32(&mut b, 12, BLOCK as u32);
        put_u64(&mut b, 16, self.blocks);
        put_u64(&mut b, 24, self.generation);
        self.root.encode(&mut b[32..]);
        put_u64(&mut b, 56, self.next_subvol);
        b[64..80].copy_from_slice(&self.uuid);
        let label = self.label.as_bytes();
        let n = label.len().min(63);
        b[80] = n as u8;
        b[81..81 + n].copy_from_slice(&label[..n]);
        put_u64(&mut b, 144, self.boot.default);
        put_u64(&mut b, 152, self.boot.fallback);
        b[160] = self.boot.tries;
        b[161] = u8::from(self.boot.pending);
        let crc = slate_hash::crc32c(&b[..BLOCK - 4]);
        put_u32(&mut b, BLOCK - 4, crc);
        b
    }

    pub fn decode(b: &[u8]) -> Result<Superblock> {
        if b.len() != BLOCK || &b[..8] != MAGIC {
            return Err(Error::Corrupt("not a SlateFS superblock"));
        }
        if get_u32(b, BLOCK - 4) != slate_hash::crc32c(&b[..BLOCK - 4]) {
            return Err(Error::Corrupt("superblock checksum"));
        }
        if get_u32(b, 8) != VERSION || get_u32(b, 12) != BLOCK as u32 {
            return Err(Error::Unsupported("SlateFS version or block size"));
        }
        let n = usize::from(b[80]).min(63);
        Ok(Superblock {
            blocks: get_u64(b, 16),
            generation: get_u64(b, 24),
            root: BlockPtr::decode(&b[32..]),
            next_subvol: get_u64(b, 56),
            uuid: b[64..80].try_into().unwrap(),
            label: String::from_utf8_lossy(&b[81..81 + n]).into_owned(),
            boot: BootState {
                default: get_u64(b, 144),
                fallback: get_u64(b, 152),
                tries: b[160],
                pending: b[161] != 0,
            },
        })
    }
}

/// File types in modes (inode(7)).
pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;

/// An inode record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Inode {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub size: u64,
    pub atime: (i64, u32),
    pub mtime: (i64, u32),
    pub ctime: (i64, u32),
    pub rdev: u64,
    /// The directory a directory lives in (itself for the root).
    pub parent: u64,
}

pub const INODE_LEN: usize = 88;

impl Inode {
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = alloc::vec![0u8; INODE_LEN];
        put_u32(&mut b, 0, self.mode);
        put_u32(&mut b, 4, self.uid);
        put_u32(&mut b, 8, self.gid);
        put_u32(&mut b, 12, self.nlink);
        put_u64(&mut b, 16, self.size);
        for (i, t) in [self.atime, self.mtime, self.ctime].iter().enumerate() {
            put_u64(&mut b, 24 + i * 12, t.0 as u64);
            put_u32(&mut b, 32 + i * 12, t.1);
        }
        put_u64(&mut b, 60, self.rdev);
        put_u64(&mut b, 68, self.parent);
        b
    }

    pub fn decode(b: &[u8]) -> Result<Inode> {
        if b.len() < INODE_LEN {
            return Err(Error::Corrupt("short inode record"));
        }
        let t = |i: usize| (get_u64(b, 24 + i * 12) as i64, get_u32(b, 32 + i * 12));
        Ok(Inode {
            mode: get_u32(b, 0),
            uid: get_u32(b, 4),
            gid: get_u32(b, 8),
            nlink: get_u32(b, 12),
            size: get_u64(b, 16),
            atime: t(0),
            mtime: t(1),
            ctime: t(2),
            rdev: get_u64(b, 60),
            parent: get_u64(b, 68),
        })
    }
}

/// An extent: `len` blocks of a file starting at disk block `start`, with
/// each block's CRC-32C.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extent {
    pub start: u64,
    pub crcs: Vec<u32>,
}

impl Extent {
    pub fn len(&self) -> u64 {
        self.crcs.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.crcs.is_empty()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = alloc::vec![0u8; 10 + self.crcs.len() * 4];
        put_u64(&mut b, 0, self.start);
        put_u16(&mut b, 8, self.crcs.len() as u16);
        for (i, c) in self.crcs.iter().enumerate() {
            put_u32(&mut b, 10 + i * 4, *c);
        }
        b
    }

    pub fn decode(b: &[u8]) -> Result<Extent> {
        if b.len() < 10 {
            return Err(Error::Corrupt("short extent"));
        }
        let n = usize::from(get_u16(b, 8));
        if n == 0 || n as u64 > MAX_EXTENT || b.len() < 10 + n * 4 {
            return Err(Error::Corrupt("bad extent length"));
        }
        Ok(Extent { start: get_u64(b, 0), crcs: (0..n).map(|i| get_u32(b, 10 + i * 4)).collect() })
    }
}

/// One directory entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dirent {
    pub ino: u64,
    /// `DT_*` file type (dirent(5)).
    pub kind: u8,
    pub name: Vec<u8>,
}

pub fn encode_dirents(list: &[Dirent]) -> Vec<u8> {
    let mut b = Vec::new();
    for d in list {
        b.extend_from_slice(&d.ino.to_le_bytes());
        b.push(d.kind);
        b.push(d.name.len() as u8);
        b.extend_from_slice(&d.name);
    }
    b
}

pub fn decode_dirents(mut b: &[u8]) -> Result<Vec<Dirent>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        if b.len() < 10 {
            return Err(Error::Corrupt("short directory entry"));
        }
        let n = usize::from(b[9]);
        if b.len() < 10 + n || n == 0 {
            return Err(Error::Corrupt("bad directory entry"));
        }
        out.push(Dirent { ino: get_u64(b, 0), kind: b[8], name: b[10..10 + n].to_vec() });
        b = &b[10 + n..];
    }
    Ok(out)
}

/// One extended attribute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Xattr {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

/// A bucket of attributes: per entry, name length (u8), value length
/// (u16), name, value.
pub fn encode_xattrs(list: &[Xattr]) -> Vec<u8> {
    let mut b = Vec::new();
    for x in list {
        b.push(x.name.len() as u8);
        b.extend_from_slice(&(x.value.len() as u16).to_le_bytes());
        b.extend_from_slice(&x.name);
        b.extend_from_slice(&x.value);
    }
    b
}

pub fn decode_xattrs(mut b: &[u8]) -> Result<Vec<Xattr>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        if b.len() < 3 {
            return Err(Error::Corrupt("short extended attribute"));
        }
        let (n, v) = (usize::from(b[0]), usize::from(get_u16(b, 1)));
        if n == 0 || b.len() < 3 + n + v {
            return Err(Error::Corrupt("bad extended attribute"));
        }
        out.push(Xattr { name: b[3..3 + n].to_vec(), value: b[3 + n..3 + n + v].to_vec() });
        b = &b[3 + n + v..];
    }
    Ok(out)
}

/// The hash a name is filed under: FNV-1a 64, low 8 bits clear (room for
/// a collision index in readdir positions) and the top bit clear.
pub fn name_hash(name: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &c in name {
        h = (h ^ u64::from(c)).wrapping_mul(0x0100_0000_01b3);
    }
    h & 0x7fff_ffff_ffff_ff00
}

/// A subvolume record in the root tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubvolRecord {
    pub root: BlockPtr,
    pub readonly: bool,
    pub parent: u64,
    pub created: i64,
    pub next_ino: u64,
    pub name: String,
}

impl SubvolRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = alloc::vec![0u8; 48];
        self.root.encode(&mut b);
        b[20] = u8::from(self.readonly);
        put_u64(&mut b, 24, self.parent);
        put_u64(&mut b, 32, self.created as u64);
        put_u64(&mut b, 40, self.next_ino);
        b.extend_from_slice(self.name.as_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Result<SubvolRecord> {
        if b.len() < 48 {
            return Err(Error::Corrupt("short subvolume record"));
        }
        Ok(SubvolRecord {
            root: BlockPtr::decode(b),
            readonly: b[20] != 0,
            parent: get_u64(b, 24),
            created: get_u64(b, 32) as i64,
            next_ino: get_u64(b, 40),
            name: String::from_utf8(b[48..].to_vec()).map_err(|_| Error::Corrupt("subvolume name"))?,
        })
    }
}
