// SPDX-License-Identifier: MIT OR Apache-2.0

//! On-disk structures (ext4 on-disk format documentation: "The Super
//! Block", "Block Group Descriptors", "Index Nodes", "The Contents of
//! inode.i_block", "Directory Entries"). Structures are kept as their raw
//! little-endian bytes, with accessors, so fields Slate does not interpret
//! survive a read-modify-write untouched.

use alloc::vec;
use alloc::vec::Vec;

pub fn get16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
pub fn get32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
pub fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
pub fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

pub const SUPERBLOCK_OFFSET: u64 = 1024;
pub const SUPERBLOCK_SIZE: usize = 1024;
pub const MAGIC: u16 = 0xEF53;

// Feature flags.
pub mod feature {
    pub const COMPAT_HAS_JOURNAL: u32 = 0x4;
    pub const COMPAT_EXT_ATTR: u32 = 0x8;
    pub const COMPAT_RESIZE_INODE: u32 = 0x10;
    pub const COMPAT_DIR_INDEX: u32 = 0x20;
    pub const COMPAT_SPARSE_SUPER2: u32 = 0x200;
    pub const COMPAT_ORPHAN_FILE: u32 = 0x1000;

    pub const INCOMPAT_FILETYPE: u32 = 0x2;
    pub const INCOMPAT_RECOVER: u32 = 0x4;
    pub const INCOMPAT_JOURNAL_DEV: u32 = 0x8;
    pub const INCOMPAT_META_BG: u32 = 0x10;
    pub const INCOMPAT_EXTENTS: u32 = 0x40;
    pub const INCOMPAT_64BIT: u32 = 0x80;
    pub const INCOMPAT_MMP: u32 = 0x100;
    pub const INCOMPAT_FLEX_BG: u32 = 0x200;
    pub const INCOMPAT_EA_INODE: u32 = 0x400;
    pub const INCOMPAT_DIRDATA: u32 = 0x1000;
    pub const INCOMPAT_CSUM_SEED: u32 = 0x2000;
    pub const INCOMPAT_LARGEDIR: u32 = 0x4000;
    pub const INCOMPAT_INLINE_DATA: u32 = 0x8000;
    pub const INCOMPAT_ENCRYPT: u32 = 0x10000;
    pub const INCOMPAT_CASEFOLD: u32 = 0x20000;

    pub const RO_COMPAT_SPARSE_SUPER: u32 = 0x1;
    pub const RO_COMPAT_LARGE_FILE: u32 = 0x2;
    pub const RO_COMPAT_HUGE_FILE: u32 = 0x8;
    pub const RO_COMPAT_GDT_CSUM: u32 = 0x10;
    pub const RO_COMPAT_DIR_NLINK: u32 = 0x20;
    pub const RO_COMPAT_EXTRA_ISIZE: u32 = 0x40;
    pub const RO_COMPAT_METADATA_CSUM: u32 = 0x400;
    pub const RO_COMPAT_ORPHAN_PRESENT: u32 = 0x10000;

    /// Incompatible features Slate can read.
    pub const READ_INCOMPAT: u32 = INCOMPAT_FILETYPE
        | INCOMPAT_RECOVER
        | INCOMPAT_EXTENTS
        | INCOMPAT_64BIT
        | INCOMPAT_FLEX_BG
        | INCOMPAT_CSUM_SEED
        | INCOMPAT_LARGEDIR
        | INCOMPAT_MMP;
    /// Incompatible features Slate can also write with.
    pub const WRITE_INCOMPAT: u32 = INCOMPAT_FILETYPE
        | INCOMPAT_EXTENTS
        | INCOMPAT_64BIT
        | INCOMPAT_FLEX_BG
        | INCOMPAT_CSUM_SEED
        | INCOMPAT_LARGEDIR;
    /// Read-only-compatible features Slate keeps consistent when writing.
    pub const WRITE_RO_COMPAT: u32 = RO_COMPAT_SPARSE_SUPER
        | RO_COMPAT_LARGE_FILE
        | RO_COMPAT_HUGE_FILE
        | RO_COMPAT_GDT_CSUM
        | RO_COMPAT_DIR_NLINK
        | RO_COMPAT_EXTRA_ISIZE
        | RO_COMPAT_METADATA_CSUM;
}

/// The superblock, as raw bytes.
#[derive(Clone, Debug)]
pub struct Superblock(pub Vec<u8>);

macro_rules! field32 {
    ($get:ident, $set:ident, $off:expr) => {
        pub fn $get(&self) -> u32 {
            get32(&self.0, $off)
        }
        #[allow(dead_code)]
        pub fn $set(&mut self, v: u32) {
            put32(&mut self.0, $off, v)
        }
    };
}

impl Superblock {
    field32!(inodes_count, set_inodes_count, 0x00);
    field32!(free_inodes, set_free_inodes, 0x10);
    field32!(first_data_block, set_first_data_block, 0x14);
    field32!(log_block_size, set_log_block_size, 0x18);
    field32!(blocks_per_group, set_blocks_per_group, 0x20);
    field32!(clusters_per_group, set_clusters_per_group, 0x24);
    field32!(inodes_per_group, set_inodes_per_group, 0x28);
    field32!(mtime, set_mtime, 0x2C);
    field32!(wtime, set_wtime, 0x30);
    field32!(rev_level, set_rev_level, 0x4C);
    field32!(first_ino_raw, set_first_ino, 0x54);
    field32!(compat, set_compat, 0x5C);
    field32!(incompat, set_incompat, 0x60);
    field32!(ro_compat, set_ro_compat, 0x64);
    field32!(journal_inum, set_journal_inum, 0xE0);
    // Start of the list of orphan inodes (linked through `i_dtime`).
    field32!(last_orphan, set_last_orphan, 0xE8);
    field32!(hash_seed0, set_hash_seed0, 0xEC);
    field32!(checksum_seed, set_checksum_seed, 0x270);
    field32!(orphan_file_inum, set_orphan_file_inum, 0x280);

    pub fn blocks_count(&self) -> u64 {
        let hi = if self.incompat() & feature::INCOMPAT_64BIT != 0 { get32(&self.0, 0x150) } else { 0 };
        u64::from(get32(&self.0, 0x04)) | (u64::from(hi) << 32)
    }
    pub fn free_blocks(&self) -> u64 {
        let hi = if self.incompat() & feature::INCOMPAT_64BIT != 0 { get32(&self.0, 0x158) } else { 0 };
        u64::from(get32(&self.0, 0x0C)) | (u64::from(hi) << 32)
    }
    pub fn set_free_blocks(&mut self, v: u64) {
        put32(&mut self.0, 0x0C, v as u32);
        if self.incompat() & feature::INCOMPAT_64BIT != 0 {
            put32(&mut self.0, 0x158, (v >> 32) as u32);
        }
    }
    pub fn magic(&self) -> u16 {
        get16(&self.0, 0x38)
    }
    pub fn state(&self) -> u16 {
        get16(&self.0, 0x3A)
    }
    pub fn set_state(&mut self, v: u16) {
        put16(&mut self.0, 0x3A, v)
    }
    pub fn mnt_count(&self) -> u16 {
        get16(&self.0, 0x34)
    }
    pub fn set_mnt_count(&mut self, v: u16) {
        put16(&mut self.0, 0x34, v)
    }
    pub fn inode_size(&self) -> u16 {
        if self.rev_level() == 0 { 128 } else { get16(&self.0, 0x58) }
    }
    pub fn first_ino(&self) -> u32 {
        if self.rev_level() == 0 { 11 } else { self.first_ino_raw() }
    }
    pub fn uuid(&self) -> &[u8] {
        &self.0[0x68..0x78]
    }
    pub fn volume_name(&self) -> &[u8] {
        let n = &self.0[0x78..0x88];
        &n[..n.iter().position(|&b| b == 0).unwrap_or(16)]
    }
    pub fn reserved_gdt_blocks(&self) -> u16 {
        get16(&self.0, 0xCE)
    }
    pub fn def_hash_version(&self) -> u8 {
        self.0[0xFC]
    }
    pub fn desc_size(&self) -> usize {
        if self.incompat() & feature::INCOMPAT_64BIT != 0 { usize::from(get16(&self.0, 0xFE)).max(32) } else { 32 }
    }
    pub fn want_extra_isize(&self) -> u16 {
        get16(&self.0, 0x15E)
    }
    pub fn log_groups_per_flex(&self) -> u8 {
        self.0[0x174]
    }
    pub fn checksum_type(&self) -> u8 {
        self.0[0x175]
    }
    pub fn backup_bgs(&self) -> [u32; 2] {
        [get32(&self.0, 0x24C), get32(&self.0, 0x250)]
    }
    pub fn stored_checksum(&self) -> u32 {
        get32(&self.0, 0x3FC)
    }
    pub fn set_checksum(&mut self, v: u32) {
        put32(&mut self.0, 0x3FC, v)
    }
    pub fn hash_seed(&self) -> [u32; 4] {
        [get32(&self.0, 0xEC), get32(&self.0, 0xF0), get32(&self.0, 0xF4), get32(&self.0, 0xF8)]
    }
    pub fn has_compat(&self, f: u32) -> bool {
        self.compat() & f != 0
    }
    pub fn has_incompat(&self, f: u32) -> bool {
        self.incompat() & f != 0
    }
    pub fn has_ro_compat(&self, f: u32) -> bool {
        self.ro_compat() & f != 0
    }
}

/// Block group descriptor flags.
pub const BG_INODE_UNINIT: u16 = 0x1;
pub const BG_BLOCK_UNINIT: u16 = 0x2;
pub const BG_INODE_ZEROED: u16 = 0x4;

/// A block group descriptor, as raw bytes (32 or `desc_size` bytes).
#[derive(Clone, Debug)]
pub struct GroupDesc(pub Vec<u8>);

impl GroupDesc {
    fn lohi(&self, lo: usize, hi: usize) -> u64 {
        let h = if self.0.len() >= 64 { get32(&self.0, hi) } else { 0 };
        u64::from(get32(&self.0, lo)) | (u64::from(h) << 32)
    }
    fn lohi16(&self, lo: usize, hi: usize) -> u32 {
        let h = if self.0.len() >= 64 { get16(&self.0, hi) } else { 0 };
        u32::from(get16(&self.0, lo)) | (u32::from(h) << 16)
    }
    fn set_lohi16(&mut self, lo: usize, hi: usize, v: u32) {
        put16(&mut self.0, lo, v as u16);
        if self.0.len() >= 64 {
            put16(&mut self.0, hi, (v >> 16) as u16);
        }
    }
    pub fn block_bitmap(&self) -> u64 {
        self.lohi(0x00, 0x20)
    }
    pub fn inode_bitmap(&self) -> u64 {
        self.lohi(0x04, 0x24)
    }
    pub fn inode_table(&self) -> u64 {
        self.lohi(0x08, 0x28)
    }
    pub fn free_blocks(&self) -> u32 {
        self.lohi16(0x0C, 0x2C)
    }
    pub fn set_free_blocks(&mut self, v: u32) {
        self.set_lohi16(0x0C, 0x2C, v)
    }
    pub fn free_inodes(&self) -> u32 {
        self.lohi16(0x0E, 0x2E)
    }
    pub fn set_free_inodes(&mut self, v: u32) {
        self.set_lohi16(0x0E, 0x2E, v)
    }
    pub fn used_dirs(&self) -> u32 {
        self.lohi16(0x10, 0x30)
    }
    pub fn set_used_dirs(&mut self, v: u32) {
        self.set_lohi16(0x10, 0x30, v)
    }
    pub fn flags(&self) -> u16 {
        get16(&self.0, 0x12)
    }
    pub fn set_flags(&mut self, v: u16) {
        put16(&mut self.0, 0x12, v)
    }
    pub fn itable_unused(&self) -> u32 {
        self.lohi16(0x1C, 0x32)
    }
    pub fn set_itable_unused(&mut self, v: u32) {
        self.set_lohi16(0x1C, 0x32, v)
    }
    pub fn set_block_bitmap_csum(&mut self, v: u32) {
        self.set_lohi16(0x18, 0x38, v)
    }
    pub fn block_bitmap_csum(&self) -> u32 {
        self.lohi16(0x18, 0x38)
    }
    pub fn set_inode_bitmap_csum(&mut self, v: u32) {
        self.set_lohi16(0x1A, 0x3A, v)
    }
    pub fn inode_bitmap_csum(&self) -> u32 {
        self.lohi16(0x1A, 0x3A)
    }
    pub fn checksum(&self) -> u16 {
        get16(&self.0, 0x1E)
    }
    pub fn set_checksum(&mut self, v: u16) {
        put16(&mut self.0, 0x1E, v)
    }
}

// Inode mode bits (file type).
pub const S_IFMT: u16 = 0o170000;
pub const S_IFSOCK: u16 = 0o140000;
pub const S_IFLNK: u16 = 0o120000;
pub const S_IFREG: u16 = 0o100000;
pub const S_IFBLK: u16 = 0o060000;
pub const S_IFDIR: u16 = 0o040000;
pub const S_IFCHR: u16 = 0o020000;
pub const S_IFIFO: u16 = 0o010000;

// Inode flags.
pub const INDEX_FL: u32 = 0x1000;
pub const HUGE_FILE_FL: u32 = 0x40000;
pub const EXTENTS_FL: u32 = 0x80000;
pub const EA_INODE_FL: u32 = 0x200000;
pub const INLINE_DATA_FL: u32 = 0x1000_0000;

/// Reserved inode numbers.
pub const ROOT_INO: u32 = 2;

/// An inode, as its raw on-disk bytes (`inode_size` of them).
#[derive(Clone, Debug)]
pub struct RawInode(pub Vec<u8>);

impl RawInode {
    pub fn new(size: usize) -> RawInode {
        RawInode(vec![0; size])
    }
    pub fn mode(&self) -> u16 {
        get16(&self.0, 0x00)
    }
    pub fn set_mode(&mut self, v: u16) {
        put16(&mut self.0, 0x00, v)
    }
    pub fn file_type(&self) -> u16 {
        self.mode() & S_IFMT
    }
    pub fn is_dir(&self) -> bool {
        self.file_type() == S_IFDIR
    }
    pub fn uid(&self) -> u32 {
        u32::from(get16(&self.0, 0x02)) | (u32::from(get16(&self.0, 0x78)) << 16)
    }
    pub fn set_uid(&mut self, v: u32) {
        put16(&mut self.0, 0x02, v as u16);
        put16(&mut self.0, 0x78, (v >> 16) as u16);
    }
    pub fn gid(&self) -> u32 {
        u32::from(get16(&self.0, 0x18)) | (u32::from(get16(&self.0, 0x7A)) << 16)
    }
    pub fn set_gid(&mut self, v: u32) {
        put16(&mut self.0, 0x18, v as u16);
        put16(&mut self.0, 0x7A, (v >> 16) as u16);
    }
    pub fn size(&self) -> u64 {
        u64::from(get32(&self.0, 0x04)) | (u64::from(get32(&self.0, 0x6C)) << 32)
    }
    pub fn set_size(&mut self, v: u64) {
        put32(&mut self.0, 0x04, v as u32);
        put32(&mut self.0, 0x6C, (v >> 32) as u32);
    }
    pub fn links(&self) -> u16 {
        get16(&self.0, 0x1A)
    }
    pub fn set_links(&mut self, v: u16) {
        put16(&mut self.0, 0x1A, v)
    }
    /// `i_blocks` in 512-byte units (or file system blocks with HUGE_FILE_FL).
    pub fn blocks_raw(&self) -> u64 {
        u64::from(get32(&self.0, 0x1C)) | (u64::from(get16(&self.0, 0x74)) << 32)
    }
    pub fn set_blocks_raw(&mut self, v: u64) {
        put32(&mut self.0, 0x1C, v as u32);
        put16(&mut self.0, 0x74, (v >> 32) as u16);
    }
    pub fn flags(&self) -> u32 {
        get32(&self.0, 0x20)
    }
    pub fn set_flags(&mut self, v: u32) {
        put32(&mut self.0, 0x20, v)
    }
    pub fn generation(&self) -> u32 {
        get32(&self.0, 0x64)
    }
    pub fn set_generation(&mut self, v: u32) {
        put32(&mut self.0, 0x64, v)
    }
    pub fn file_acl(&self) -> u64 {
        u64::from(get32(&self.0, 0x68)) | (u64::from(get16(&self.0, 0x76)) << 32)
    }
    pub fn set_file_acl(&mut self, v: u64) {
        put32(&mut self.0, 0x68, v as u32);
        put16(&mut self.0, 0x76, (v >> 32) as u16);
    }
    pub fn dtime(&self) -> u32 {
        get32(&self.0, 0x14)
    }
    pub fn set_dtime(&mut self, v: u32) {
        put32(&mut self.0, 0x14, v)
    }
    pub fn i_block(&self) -> &[u8] {
        &self.0[0x28..0x64]
    }
    pub fn i_block_mut(&mut self) -> &mut [u8] {
        &mut self.0[0x28..0x64]
    }
    pub fn extra_isize(&self) -> u16 {
        if self.0.len() > 128 { get16(&self.0, 0x80) } else { 0 }
    }
    pub fn set_extra_isize(&mut self, v: u16) {
        if self.0.len() > 128 {
            put16(&mut self.0, 0x80, v)
        }
    }

    /// Time stamp `which` (0 atime, 1 ctime, 2 mtime, 3 crtime) as (seconds,
    /// nanoseconds). The extra fields hold two epoch bits and the nanoseconds.
    pub fn time(&self, which: usize) -> (i64, u32) {
        let (base, extra) = TIME_FIELDS[which];
        let secs = if base == 0x90 && self.extra_isize() < 0x18 { 0 } else { get32(&self.0, base) as i32 as i64 };
        if self.extra_isize() as usize + 128 >= extra + 4 {
            let e = get32(&self.0, extra);
            let epoch = i64::from(e & 3);
            (secs + (epoch << 32), e >> 2)
        } else {
            (secs, 0)
        }
    }
    pub fn set_time(&mut self, which: usize, secs: i64, nsec: u32) {
        let (base, extra) = TIME_FIELDS[which];
        if base == 0x90 && self.extra_isize() < 0x18 {
            return;
        }
        put32(&mut self.0, base, secs as u32);
        if self.extra_isize() as usize + 128 >= extra + 4 {
            let epoch = ((secs - i64::from(secs as i32)) >> 32) as u32 & 3;
            put32(&mut self.0, extra, (nsec << 2) | epoch);
        }
    }
}

/// (base offset, extra offset) of atime, ctime, mtime, crtime.
const TIME_FIELDS: [(usize, usize); 4] = [(0x08, 0x8C), (0x0C, 0x84), (0x10, 0x88), (0x90, 0x94)];

// Extent tree (ext4 on-disk format documentation, "Extent Tree").
pub const EXTENT_MAGIC: u16 = 0xF30A;
pub const EXTENT_HEADER: usize = 12;
pub const EXTENT_ENTRY: usize = 12;
/// Lengths above this mark uninitialized (preallocated) extents.
pub const EXTENT_INIT_MAX: u32 = 32768;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtentHeader {
    pub entries: u16,
    pub max: u16,
    pub depth: u16,
}

impl ExtentHeader {
    pub fn read(b: &[u8]) -> Option<ExtentHeader> {
        (get16(b, 0) == EXTENT_MAGIC).then(|| ExtentHeader {
            entries: get16(b, 2),
            max: get16(b, 4),
            depth: get16(b, 6),
        })
    }
    pub fn write(&self, b: &mut [u8]) {
        put16(b, 0, EXTENT_MAGIC);
        put16(b, 2, self.entries);
        put16(b, 4, self.max);
        put16(b, 6, self.depth);
    }
}

/// A leaf entry: `len` blocks from logical `block` at physical `start`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    pub block: u32,
    pub len: u32,
    pub start: u64,
    pub uninit: bool,
}

impl Extent {
    pub fn read(b: &[u8]) -> Extent {
        let raw_len = u32::from(get16(b, 4));
        let (len, uninit) =
            if raw_len > EXTENT_INIT_MAX { (raw_len - EXTENT_INIT_MAX, true) } else { (raw_len, false) };
        Extent { block: get32(b, 0), len, start: u64::from(get32(b, 8)) | (u64::from(get16(b, 6)) << 32), uninit }
    }
    pub fn write(&self, b: &mut [u8]) {
        put32(b, 0, self.block);
        put16(b, 4, (if self.uninit { self.len + EXTENT_INIT_MAX } else { self.len }) as u16);
        put16(b, 6, (self.start >> 32) as u16);
        put32(b, 8, self.start as u32);
    }
    pub fn end(&self) -> u32 {
        self.block + self.len
    }
}

/// An index entry: the subtree at physical block `leaf` covers logical
/// blocks from `block`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtentIndex {
    pub block: u32,
    pub leaf: u64,
}

impl ExtentIndex {
    pub fn read(b: &[u8]) -> ExtentIndex {
        ExtentIndex { block: get32(b, 0), leaf: u64::from(get32(b, 4)) | (u64::from(get16(b, 8)) << 32) }
    }
    pub fn write(&self, b: &mut [u8]) {
        put32(b, 0, self.block);
        put32(b, 4, self.leaf as u32);
        put16(b, 8, (self.leaf >> 32) as u16);
        put16(b, 10, 0);
    }
}

// Directory entries.
pub const DIRENT_HEADER: usize = 8;
/// The checksum tail at the end of each directory leaf block with
/// metadata_csum: a fake entry (inode 0, rec_len 12, name_len 0, type 0xDE).
pub const DIRENT_TAIL: usize = 12;
pub const DIRENT_TAIL_TYPE: u8 = 0xDE;

// Directory entry file types.
pub const FT_UNKNOWN: u8 = 0;
pub const FT_REG: u8 = 1;
pub const FT_DIR: u8 = 2;
pub const FT_CHR: u8 = 3;
pub const FT_BLK: u8 = 4;
pub const FT_FIFO: u8 = 5;
pub const FT_SOCK: u8 = 6;
pub const FT_SYMLINK: u8 = 7;

pub fn file_type_of_mode(mode: u16) -> u8 {
    match mode & S_IFMT {
        S_IFREG => FT_REG,
        S_IFDIR => FT_DIR,
        S_IFCHR => FT_CHR,
        S_IFBLK => FT_BLK,
        S_IFIFO => FT_FIFO,
        S_IFSOCK => FT_SOCK,
        S_IFLNK => FT_SYMLINK,
        _ => FT_UNKNOWN,
    }
}

/// Space a directory entry with an `n`-byte name needs (4-byte aligned).
pub fn dirent_len(n: usize) -> usize {
    (DIRENT_HEADER + n).next_multiple_of(4)
}
