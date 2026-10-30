// SPDX-License-Identifier: MIT OR Apache-2.0

//! SlateFS (ADR 0026): a copy-on-write file system with checksummed
//! metadata and data, subvolumes and snapshots, crash-safe by shadow
//! paging. This crate is the whole file system, without I/O of its own:
//! the caller provides a [`Disk`]. Every operation names the subvolume it
//! works in; a mount is one subvolume.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod layout;
pub mod tree;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use layout::*;
pub use layout::{BootState, Dirent, Inode, ROOT_INO};
use tree::{Body, Child, Load, Node};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Io,
    NotFound,
    Exists,
    NotDir,
    IsDir,
    NotEmpty,
    NoSpace,
    Invalid,
    NameTooLong,
    ReadOnly,
    TooBig,
    Unsupported(&'static str),
    Corrupt(&'static str),
    /// A block's contents do not match its checksum.
    Checksum(u64),
}

pub type Result<T> = core::result::Result<T, Error>;

/// Storage the file system lives on, addressed in bytes; transfers are
/// whole 4 KiB blocks.
pub trait Disk {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()>;
    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<()>;
    /// Make written data durable.
    fn flush(&mut self) -> Result<()>;
    /// Wall-clock time (seconds since the epoch, nanoseconds).
    fn now(&self) -> (i64, u32);
    /// The bytes hold nothing any more (TRIM); whole blocks. Disks that
    /// cannot take it do nothing.
    fn discard(&mut self, _offset: u64, _len: u64) -> Result<()> {
        Ok(())
    }
}

/// Blocks kept free for commits (file data cannot use them).
const RESERVE: u64 = 32;

/// The largest file size (16 TiB).
pub const MAX_FILE_SIZE: u64 = 1 << 44;

/// `DT_*` file types (dirent(5)).
pub const DT_FIFO: u8 = 1;
pub const DT_CHR: u8 = 2;
pub const DT_DIR: u8 = 4;
pub const DT_BLK: u8 = 6;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;
pub const DT_SOCK: u8 = 12;

fn dt_of(mode: u32) -> u8 {
    match mode & S_IFMT {
        0o010000 => DT_FIFO,
        0o020000 => DT_CHR,
        S_IFDIR => DT_DIR,
        0o060000 => DT_BLK,
        S_IFLNK => DT_LNK,
        0o140000 => DT_SOCK,
        _ => DT_REG,
    }
}

/// A subvolume as listed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subvol {
    pub id: u64,
    pub name: String,
    pub readonly: bool,
    pub parent: u64,
    pub created: i64,
}

/// File-system totals (statfs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Totals {
    pub blocks: u64,
    pub free: u64,
}

/// Words per bitmap chunk: 512 KiB, so even a multi-terabyte file system
/// needs no allocation larger than the kernel heap's largest block (4 MiB).
const CHUNK_WORDS: usize = 64 * 1024;

/// A set of block numbers, kept in fixed-size chunks.
#[derive(Clone, Debug)]
struct Bitmap(Vec<Vec<u64>>);

impl Bitmap {
    fn new(n: u64) -> Bitmap {
        let mut words = n.div_ceil(64) as usize;
        let mut chunks = Vec::with_capacity(words.div_ceil(CHUNK_WORDS));
        while words > 0 {
            let w = words.min(CHUNK_WORDS);
            chunks.push(vec![0; w]);
            words -= w;
        }
        Bitmap(chunks)
    }
    fn word(&self, b: u64) -> Option<&u64> {
        let w = (b / 64) as usize;
        self.0.get(w / CHUNK_WORDS)?.get(w % CHUNK_WORDS)
    }
    fn word_mut(&mut self, b: u64) -> Option<&mut u64> {
        let w = (b / 64) as usize;
        self.0.get_mut(w / CHUNK_WORDS)?.get_mut(w % CHUNK_WORDS)
    }
    fn get(&self, b: u64) -> bool {
        self.word(b).is_some_and(|w| w & (1 << (b % 64)) != 0)
    }
    fn set(&mut self, b: u64) {
        if let Some(w) = self.word_mut(b) {
            *w |= 1 << (b % 64);
        }
    }
    fn clear(&mut self, b: u64) {
        if let Some(w) = self.word_mut(b) {
            *w &= !(1 << (b % 64));
        }
    }
    fn count(&self) -> u64 {
        self.0.iter().flatten().map(|w| u64::from(w.count_ones())).sum()
    }
    /// The largest single allocation this bitmap made, in bytes.
    #[cfg(test)]
    fn largest_chunk(&self) -> usize {
        self.0.iter().map(|c| c.len() * 8).max().unwrap_or(0)
    }
}

/// Free-space state: blocks reachable from the last commit, blocks
/// allocated since, and how many are busy in all.
#[derive(Clone, Debug)]
struct Space {
    used: Bitmap,
    txn: Bitmap,
    busy: u64,
    cursor: u64,
    blocks: u64,
}

impl Space {
    fn new(used: Bitmap, blocks: u64) -> Space {
        let busy = used.count();
        Space { used, txn: Bitmap::new(blocks), busy, cursor: 2, blocks }
    }

    fn free(&self) -> u64 {
        self.blocks.saturating_sub(self.busy)
    }

    fn alloc(&mut self) -> Result<u64> {
        for _ in 0..self.blocks {
            let b = self.cursor;
            self.cursor = if b + 1 >= self.blocks { 2 } else { b + 1 };
            if b >= 2 && !self.used.get(b) && !self.txn.get(b) {
                self.txn.set(b);
                self.busy += 1;
                return Ok(b);
            }
        }
        Err(Error::NoSpace)
    }

    fn release(&mut self, b: u64) {
        if self.txn.get(b) && !self.used.get(b) {
            self.txn.clear(b);
            self.busy -= 1;
        }
    }

    /// A commit has begun: what this transaction allocated belongs to it
    /// now, so it is neither reused nor overwritten in place until the
    /// commit ends.
    fn freeze(&mut self) {
        let txn = core::mem::replace(&mut self.txn, Bitmap::new(self.blocks));
        for (u, t) in self.used.0.iter_mut().flatten().zip(txn.0.iter().flatten()) {
            *u |= t;
        }
    }
}

/// Node loading with a cache of decoded clean nodes, and the nodes a
/// commit has placed but not yet written.
struct Store<'a, D: Disk> {
    disk: &'a mut D,
    cache: &'a mut BTreeMap<u64, Node>,
    unwritten: &'a BTreeMap<u64, Vec<u8>>,
    free: &'a mut Free,
}

const CACHE_NODES: usize = 4096;

impl<D: Disk> Load for Store<'_, D> {
    fn load(&mut self, ptr: &BlockPtr) -> Result<Node> {
        if let Some(n) = self.cache.get(&ptr.block) {
            return Ok(n.clone());
        }
        let n = match self.unwritten.get(&ptr.block) {
            Some(b) => Node::decode(b, ptr)?,
            None => {
                let mut b = vec![0u8; BLOCK];
                self.disk.read(ptr.block * BLOCK as u64, &mut b)?;
                Node::decode(&b, ptr)?
            }
        };
        if self.cache.len() >= CACHE_NODES {
            self.cache.clear();
        }
        self.cache.insert(ptr.block, n.clone());
        Ok(n)
    }

    fn dropped(&mut self, ptr: &BlockPtr, node: &Node) {
        self.free.dropped(ptr.block, node);
    }
}

/// What makes free space incremental (ADR 0026's addendum): the blocks
/// the transaction stopped using, and how many parents link each block
/// that more than one does (snapshots share subtrees). A block dropped by
/// its last parent is free after the commit. A shared node that is copied
/// loses a parent, and what it links gains one (the copy), so counts
/// follow a subtree as it diverges. The counts live in memory only: the
/// walk at mount finds them.
#[derive(Clone, Debug, Default)]
struct Free {
    /// References beyond the first, for blocks linked more than once.
    extra: BTreeMap<u64, u32>,
    /// Blocks whose last reference went since the last commit began.
    dropped: Vec<u64>,
    /// The next commit must walk every tree (after a repair).
    walk: bool,
}

impl Free {
    fn share(&mut self, b: u64) {
        *self.extra.entry(b).or_insert(0) += 1;
    }

    /// One reference to `b` went: true if others remain.
    fn unshare(&mut self, b: u64) -> bool {
        match self.extra.get_mut(&b) {
            Some(n) => {
                *n -= 1;
                if *n == 0 {
                    self.extra.remove(&b);
                }
                true
            }
            None => false,
        }
    }

    /// Node `block` (`node`) lost the parent it was linked from; a copy
    /// may link what it links.
    fn dropped(&mut self, block: u64, node: &Node) {
        if !self.unshare(block) {
            self.dropped.push(block);
            return;
        }
        // Another parent keeps it: the copy links its children too.
        match &node.body {
            Body::Internal(children) => {
                for (_, c) in children {
                    if let Child::Disk(p) = c {
                        self.share(p.block);
                    }
                }
            }
            Body::Leaf(items) => {
                for (k, v) in items {
                    if k.kind == KIND_EXTENT
                        && let Ok(e) = Extent::decode(v)
                    {
                        for b in e.start..e.start + e.len() {
                            self.share(b);
                        }
                    }
                }
            }
        }
    }
}

/// Node loading straight from the disk, for a walk that visits each node
/// once.
struct Uncached<'a, D: Disk>(&'a mut D);

impl<D: Disk> Load for Uncached<'_, D> {
    fn load(&mut self, ptr: &BlockPtr) -> Result<Node> {
        let mut b = vec![0u8; BLOCK];
        self.0.read(ptr.block * BLOCK as u64, &mut b)?;
        Node::decode(&b, ptr)
    }
}

/// A commit begun by [`Fs::begin_commit`]: the nodes to write and the
/// superblock that makes them current. Writing it and finding the blocks
/// it reaches need nothing from the [`Fs`], so the caller can do both
/// without the lock that guards it while other operations go on
/// (ADR 0026's addendum); [`Fs::end_commit`] then takes the result.
#[derive(Debug)]
pub struct Commit {
    sb: Superblock,
    /// (block, bytes), every node the trees point at that isn't on the
    /// disk yet.
    writes: Vec<(u64, Vec<u8>)>,
    /// Blocks the transaction stopped using.
    dropped: Vec<u64>,
    /// Free space must be found by walking every tree.
    walk: bool,
}

/// The blocks a committed superblock reaches, and the references beyond
/// the first of those reached more than once.
#[derive(Debug)]
pub struct Reach(Bitmap, BTreeMap<u64, u32>);

impl Commit {
    /// Write the nodes, then the superblock, each followed by a flush: a
    /// crash at any point leaves the old or the new state.
    pub fn write<D: Disk>(&self, disk: &mut D) -> Result<()> {
        for (b, bytes) in &self.writes {
            disk.write(b * BLOCK as u64, bytes)?;
        }
        disk.flush()?;
        disk.write((self.sb.generation % 2) * BLOCK as u64, &self.sb.encode())?;
        disk.flush()
    }

    /// Whether [`Fs::end_commit`] needs [`Commit::reachable`]: free space
    /// is otherwise known from what the transaction dropped.
    pub fn needs_walk(&self) -> bool {
        self.walk
    }

    /// The blocks the written commit reaches, read from `disk`. Nothing
    /// the commit reaches can change meanwhile: the blocks are in use
    /// until [`Fs::end_commit`].
    pub fn reachable<D: Disk>(&self, disk: &mut D) -> Result<Reach> {
        reach(&self.sb, &mut Uncached(disk))
    }

    pub fn generation(&self) -> u64 {
        self.sb.generation
    }
}

/// Blocks reachable from superblock `sb`, and how often those reached
/// more than once are.
fn reach(sb: &Superblock, st: &mut dyn Load) -> Result<Reach> {
    let mut used = Bitmap::new(sb.blocks);
    let mut extra = BTreeMap::new();
    used.set(0);
    used.set(1);
    mark(&sb.root, st, &mut used, &mut extra, sb.blocks)?;
    Ok(Reach(used, extra))
}

pub struct Fs<D: Disk> {
    disk: D,
    sb: Superblock,
    root_tree: Child,
    /// Each subvolume's tree as currently modified.
    trees: BTreeMap<u64, Child>,
    records: BTreeMap<u64, SubvolRecord>,
    dirty_subvols: BTreeSet<u64>,
    dirty: bool,
    space: Space,
    cache: BTreeMap<u64, Node>,
    read_only: bool,
    /// Online discard: blocks are discarded once no superblock refers to
    /// them any more.
    discard: bool,
    /// Blocks the last commit freed, which the previous generation (the
    /// other superblock slot) may still use: (first block, count).
    recently_freed: Vec<(u64, u64)>,
    /// Nodes placed by a commit and not yet written (written by
    /// [`Commit::write`], forgotten at [`Fs::end_commit`]).
    unwritten: BTreeMap<u64, Vec<u8>>,
    /// A [`Commit`] is between [`Fs::begin_commit`] and its end.
    in_flight: bool,
    free: Free,
}

impl<D: Disk> core::fmt::Debug for Fs<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Fs").field("generation", &self.sb.generation).finish_non_exhaustive()
    }
}

/// Make an empty file system of `blocks` blocks with one subvolume named
/// `subvol` (holding an empty root directory owned by root, mode 0755).
pub fn mkfs<D: Disk>(mut disk: D, blocks: u64, label: &str, uuid: [u8; 16], subvol: &str) -> Result<Fs<D>> {
    if blocks < 64 {
        return Err(Error::NoSpace);
    }
    let sb = Superblock {
        blocks,
        generation: 0,
        root: BlockPtr::default(),
        next_subvol: 1,
        uuid,
        label: label.into(),
        boot: BootState::default(),
    };
    // Invalidate the other slot, then start from an empty root tree.
    disk.write(BLOCK as u64, &vec![0u8; BLOCK])?;
    let mut fs = Fs {
        disk,
        sb,
        root_tree: Child::Mem(alloc::boxed::Box::new(Node::empty_leaf())),
        trees: BTreeMap::new(),
        records: BTreeMap::new(),
        dirty_subvols: BTreeSet::new(),
        dirty: true,
        space: Space::new(Bitmap::new(blocks), blocks),
        cache: BTreeMap::new(),
        read_only: false,
        discard: false,
        recently_freed: Vec::new(),
        unwritten: BTreeMap::new(),
        in_flight: false,
        free: Free::default(),
    };
    let mut used = Bitmap::new(blocks);
    used.set(0);
    used.set(1);
    fs.space = Space::new(used, blocks);
    fs.create_subvolume(subvol)?;
    fs.commit()?;
    Ok(fs)
}

impl<D: Disk> Fs<D> {
    /// Mount: the newest valid superblock, then free space, then orphans.
    pub fn mount(mut disk: D, read_only: bool) -> Result<Fs<D>> {
        let mut best: Option<Superblock> = None;
        for slot in 0..2u64 {
            let mut b = vec![0u8; BLOCK];
            disk.read(slot * BLOCK as u64, &mut b)?;
            if let Ok(sb) = Superblock::decode(&b)
                && best.as_ref().is_none_or(|x| sb.generation > x.generation)
            {
                best = Some(sb);
            }
        }
        let sb = best.ok_or(Error::Corrupt("no valid superblock"))?;
        let blocks = sb.blocks;
        let mut fs = Fs {
            disk,
            root_tree: Child::Disk(sb.root),
            sb,
            trees: BTreeMap::new(),
            records: BTreeMap::new(),
            dirty_subvols: BTreeSet::new(),
            dirty: false,
            space: Space::new(Bitmap::new(blocks), blocks),
            cache: BTreeMap::new(),
            read_only,
            discard: false,
            recently_freed: Vec::new(),
            unwritten: BTreeMap::new(),
            in_flight: false,
            free: Free::default(),
        };
        fs.load_records()?;
        let Reach(used, extra) = fs.reachable()?;
        fs.space = Space::new(used, blocks);
        fs.free.extra = extra;
        if !read_only {
            let ids: Vec<u64> = fs.records.iter().filter(|(_, r)| !r.readonly).map(|(id, _)| *id).collect();
            for sv in ids {
                for ino in fs.orphans(sv)? {
                    fs.evict(sv, ino)?;
                }
            }
            fs.commit()?;
        }
        Ok(fs)
    }

    fn load_records(&mut self) -> Result<()> {
        let mut recs = Vec::new();
        let mut st =
            Store { disk: &mut self.disk, cache: &mut self.cache, unwritten: &self.unwritten, free: &mut self.free };
        tree::for_each(&self.root_tree, &mut st, &mut |k, v| {
            if k.kind == KIND_SUBVOL {
                recs.push((k.object, SubvolRecord::decode(v)?));
            }
            Ok(())
        })?;
        for (id, r) in recs {
            self.trees.insert(id, Child::Disk(r.root));
            self.records.insert(id, r);
        }
        Ok(())
    }

    pub fn into_disk(self) -> D {
        self.disk
    }

    pub fn generation(&self) -> u64 {
        self.sb.generation
    }

    pub fn label(&self) -> &str {
        &self.sb.label
    }

    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// Blocks reachable from the committed superblock.
    fn reachable(&mut self) -> Result<Reach> {
        let mut st =
            Store { disk: &mut self.disk, cache: &mut self.cache, unwritten: &self.unwritten, free: &mut self.free };
        reach(&self.sb, &mut st)
    }

    pub fn totals(&self) -> Totals {
        Totals { blocks: self.sb.blocks, free: self.space.free() }
    }

    /// A block for file data. A reserve stays free so that a commit can
    /// always write its metadata.
    fn alloc(&mut self) -> Result<u64> {
        if self.space.free() <= RESERVE {
            return Err(Error::NoSpace);
        }
        self.space.alloc()
    }

    /// Blocks dropped from a file: those allocated in this transaction are
    /// referenced by nothing committed, so they are free again at once;
    /// others are after the commit, unless a snapshot has them too. Call
    /// it after the extent's item is out of the tree (or changed): the
    /// leaf's copy is what counts a snapshot's reference.
    fn release(&mut self, start: u64, len: u64) {
        for b in start..start + len {
            if self.space.txn.get(b) && !self.space.used.get(b) {
                self.space.release(b);
            } else if !self.free.unshare(b) {
                self.free.dropped.push(b);
            }
        }
    }

    /// Whether [`Fs::write`] can write file `ino` (`TooBig` past
    /// [`MAX_FILE_SIZE`] aside): a page cache asks before it accepts writes
    /// it will only hand over later.
    pub fn check_write(&mut self, sv: u64, ino: u64) -> Result<()> {
        self.writable(sv)?;
        if self.stat(sv, ino)?.is_dir() {
            return Err(Error::IsDir);
        }
        Ok(())
    }

    fn writable(&self, sv: u64) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        match self.records.get(&sv) {
            Some(r) if r.readonly => Err(Error::ReadOnly),
            Some(_) => Ok(()),
            None => Err(Error::NotFound),
        }
    }

    // --- Tree access ----------------------------------------------------

    fn get(&mut self, sv: u64, key: Key) -> Result<Option<Vec<u8>>> {
        let t = self.trees.get(&sv).ok_or(Error::NotFound)?;
        let mut st =
            Store { disk: &mut self.disk, cache: &mut self.cache, unwritten: &self.unwritten, free: &mut self.free };
        tree::get(t, &key, &mut st)
    }

    fn ceil(&mut self, sv: u64, key: Key) -> Result<Option<(Key, Vec<u8>)>> {
        let t = self.trees.get(&sv).ok_or(Error::NotFound)?;
        let mut st =
            Store { disk: &mut self.disk, cache: &mut self.cache, unwritten: &self.unwritten, free: &mut self.free };
        tree::ceil(t, &key, &mut st)
    }

    fn floor(&mut self, sv: u64, key: Key) -> Result<Option<(Key, Vec<u8>)>> {
        let t = self.trees.get(&sv).ok_or(Error::NotFound)?;
        let mut st =
            Store { disk: &mut self.disk, cache: &mut self.cache, unwritten: &self.unwritten, free: &mut self.free };
        tree::floor(t, &key, &mut st)
    }

    fn put(&mut self, sv: u64, key: Key, value: Vec<u8>) -> Result<()> {
        let t = self.trees.get_mut(&sv).ok_or(Error::NotFound)?;
        let mut st =
            Store { disk: &mut self.disk, cache: &mut self.cache, unwritten: &self.unwritten, free: &mut self.free };
        tree::insert(t, key, value, &mut st)?;
        self.dirty_subvols.insert(sv);
        self.dirty = true;
        Ok(())
    }

    fn del(&mut self, sv: u64, key: Key) -> Result<bool> {
        let t = self.trees.get_mut(&sv).ok_or(Error::NotFound)?;
        let mut st =
            Store { disk: &mut self.disk, cache: &mut self.cache, unwritten: &self.unwritten, free: &mut self.free };
        let found = tree::delete(t, &key, &mut st)?;
        if found {
            self.dirty_subvols.insert(sv);
            self.dirty = true;
        }
        Ok(found)
    }

    /// All items of `object` with `kind`, in order.
    fn items(&mut self, sv: u64, object: u64, kind: u8) -> Result<Vec<(Key, Vec<u8>)>> {
        let mut out = Vec::new();
        let mut at = Key::new(object, kind, 0);
        while let Some((k, v)) = self.ceil(sv, at)? {
            if k.object != object || k.kind != kind {
                break;
            }
            out.push((k, v));
            match k.offset.checked_add(1) {
                Some(o) => at = Key::new(object, kind, o),
                None => break,
            }
        }
        Ok(out)
    }

    // --- Commit ----------------------------------------------------------

    /// Write all changes and switch the superblock to them.
    pub fn commit(&mut self) -> Result<()> {
        let Some(c) = self.begin_commit()? else { return Ok(()) };
        let walked = c.write(&mut self.disk).and_then(|()| {
            if !c.walk {
                return Ok(None);
            }
            let mut st = Store {
                disk: &mut self.disk,
                cache: &mut self.cache,
                unwritten: &self.unwritten,
                free: &mut self.free,
            };
            reach(&c.sb, &mut st).map(Some)
        });
        match walked {
            Ok(walked) => {
                self.end_commit(c, walked);
                Ok(())
            }
            Err(e) => {
                self.abort_commit(c);
                Err(e)
            }
        }
    }

    /// Begin a commit (none when nothing changed): place the changed
    /// nodes in new blocks and make the superblock that points at them.
    /// Changes made before [`Fs::end_commit`] or [`Fs::abort_commit`]
    /// belong to the next commit. One commit at a time.
    pub fn begin_commit(&mut self) -> Result<Option<Commit>> {
        if self.in_flight {
            return Err(Error::Unsupported("a commit is already in flight"));
        }
        if !self.dirty || self.read_only {
            return Ok(None);
        }
        let generation = self.sb.generation + 1;
        let blocks = self.sb.blocks;
        let ids: Vec<u64> = self.dirty_subvols.iter().copied().collect();
        for sv in ids {
            let Some(mut t) = self.trees.remove(&sv) else { continue };
            let ptr = self.flush_tree(&mut t, generation, sv, blocks);
            self.trees.insert(sv, t);
            let ptr = ptr?;
            if let Some(r) = self.records.get_mut(&sv) {
                r.root = ptr;
                let rec = r.encode();
                let mut st = Store {
                    disk: &mut self.disk,
                    cache: &mut self.cache,
                    unwritten: &self.unwritten,
                    free: &mut self.free,
                };
                tree::insert(&mut self.root_tree, Key::new(sv, KIND_SUBVOL, 0), rec, &mut st)?;
            }
            self.dirty_subvols.remove(&sv);
        }
        let mut root = core::mem::replace(&mut self.root_tree, Child::Disk(BlockPtr::default()));
        let root_ptr = self.flush_tree(&mut root, generation, 0, blocks);
        self.root_tree = root;
        let mut sb = self.sb.clone();
        sb.generation = generation;
        sb.root = root_ptr?;
        self.dirty = false;
        self.space.freeze();
        self.in_flight = true;
        let writes = self.unwritten.iter().map(|(b, bytes)| (*b, bytes.clone())).collect();
        let dropped = core::mem::take(&mut self.free.dropped);
        let walk = core::mem::take(&mut self.free.walk);
        Ok(Some(Commit { sb, writes, dropped, walk }))
    }

    /// End a commit that was written: its superblock is current, and the
    /// blocks it doesn't reach (nor anything changed since it began) are
    /// free again: those the transaction dropped the last reference to,
    /// or with `walked` (which [`Commit::needs_walk`] asks for: only a
    /// repair, which commits at once) all it didn't reach.
    pub fn end_commit(&mut self, c: Commit, walked: Option<Reach>) {
        self.in_flight = false;
        let used = match walked {
            Some(Reach(used, extra)) => {
                self.free.extra = extra;
                used
            }
            None => {
                let mut used = self.space.used.clone();
                for &b in &c.dropped {
                    used.clear(b);
                }
                used
            }
        };
        for (b, _) in &c.writes {
            self.unwritten.remove(b);
        }
        // The fields changed since the commit began stay for the next one.
        self.sb.generation = c.sb.generation;
        self.sb.root = c.sb.root;
        // What this commit freed; what the one before freed is now used by
        // neither superblock (unless allocated again since).
        let freed = freed_runs(&self.space.used, &used);
        let before = core::mem::replace(&mut self.recently_freed, freed);
        if self.discard {
            for (start, n) in before {
                let txn = &self.space.txn;
                for (s, c) in runs_in(start, start + n, |b| !used.get(b) && !txn.get(b)) {
                    let _ = self.disk.discard(s * BLOCK as u64, c * BLOCK as u64);
                }
            }
        }
        let txn = core::mem::replace(&mut self.space.txn, Bitmap::new(0));
        self.space = Space::new(used, self.sb.blocks);
        self.space.busy += txn.count();
        self.space.txn = txn;
        // The host tests check every commit against a walk.
        #[cfg(test)]
        {
            let Reach(walked, extra) = self.reachable().expect("walk after a commit");
            for b in 0..self.sb.blocks {
                assert_eq!(self.space.used.get(b), walked.get(b), "block {b} after commit {}", self.sb.generation);
            }
            if !self.dirty {
                assert_eq!(self.free.extra, extra, "references after commit {}", self.sb.generation);
            }
        }
    }

    /// Give up a commit that could not be written: the old superblock
    /// stays current, and the next commit writes its nodes again.
    pub fn abort_commit(&mut self, c: Commit) {
        self.in_flight = false;
        self.dirty = true;
        self.free.dropped.extend(c.dropped);
        self.free.walk |= c.walk;
    }

    /// Online discard (the `discard` mount option).
    pub fn set_discard(&mut self, on: bool) {
        self.discard = on;
    }

    /// FITRIM: discard every free run of at least `min_len` bytes within
    /// `[start, start + len)` (bytes), except blocks the previous
    /// generation may still use; returns the bytes discarded.
    pub fn trim(&mut self, start: u64, len: u64, min_len: u64) -> Result<u64> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        let bs = BLOCK as u64;
        let first = start.div_ceil(bs).max(2);
        let end = (start.saturating_add(len) / bs).min(self.sb.blocks);
        let min_blocks = min_len.div_ceil(bs).max(1);
        let recent = &self.recently_freed;
        let space = &self.space;
        let free = runs_in(first, end, |b| {
            !space.used.get(b) && !space.txn.get(b) && !recent.iter().any(|&(s, n)| b >= s && b < s + n)
        });
        let mut trimmed = 0;
        for (s, n) in free {
            if n >= min_blocks {
                self.disk.discard(s * bs, n * bs)?;
                trimmed += n * bs;
            }
        }
        Ok(trimmed)
    }

    /// Place a tree's changed nodes in new blocks, for the commit to
    /// write.
    fn flush_tree(&mut self, t: &mut Child, generation: u64, owner: u64, _blocks: u64) -> Result<BlockPtr> {
        let (unwritten, cache, space) = (&mut self.unwritten, &mut self.cache, &mut self.space);
        let mut fresh: Vec<(u64, Node)> = Vec::new();
        let ptr = tree::flush(
            t,
            generation,
            owner,
            &mut |bytes| {
                let b = space.alloc()?;
                unwritten.insert(b, bytes.to_vec());
                Ok(b)
            },
            &mut |b, n| fresh.push((b, n)),
        );
        // Even after a failure: the tree points at the nodes placed so far.
        for (b, n) in fresh {
            // A node cached under a block that was freed and used again
            // must not stay.
            if cache.len() < CACHE_NODES {
                cache.insert(b, n);
            } else {
                cache.remove(&b);
            }
        }
        ptr
    }

    /// Commit, then make the device durable.
    pub fn sync(&mut self) -> Result<()> {
        self.commit()?;
        self.disk.flush()
    }

    pub fn pending(&self) -> bool {
        self.dirty
    }

    // --- Subvolumes ------------------------------------------------------

    pub fn subvolumes(&self) -> Vec<Subvol> {
        self.records
            .iter()
            .map(|(id, r)| Subvol {
                id: *id,
                name: r.name.clone(),
                readonly: r.readonly,
                parent: r.parent,
                created: r.created,
            })
            .collect()
    }

    pub fn subvol_by_name(&self, name: &str) -> Option<u64> {
        self.records.iter().find(|(_, r)| r.name == name).map(|(id, _)| *id)
    }

    fn check_subvol_name(&self, name: &str) -> Result<()> {
        if name.is_empty() || name.len() > 200 || name.contains('/') || name.contains('\0') {
            return Err(Error::Invalid);
        }
        if self.subvol_by_name(name).is_some() {
            return Err(Error::Exists);
        }
        Ok(())
    }

    /// A new, empty subvolume.
    pub fn create_subvolume(&mut self, name: &str) -> Result<u64> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        self.check_subvol_name(name)?;
        let id = self.sb.next_subvol;
        self.sb.next_subvol += 1;
        let now = self.disk.now();
        self.records.insert(
            id,
            SubvolRecord {
                root: BlockPtr::default(),
                readonly: false,
                parent: 0,
                created: now.0,
                next_ino: ROOT_INO + 1,
                name: name.into(),
            },
        );
        self.trees.insert(id, Child::Mem(alloc::boxed::Box::new(Node::empty_leaf())));
        let root = Inode {
            mode: S_IFDIR | 0o755,
            nlink: 2,
            atime: now,
            mtime: now,
            ctime: now,
            parent: ROOT_INO,
            ..Default::default()
        };
        self.put(id, Key::new(ROOT_INO, KIND_INODE, 0), root.encode())?;
        Ok(id)
    }

    /// Snapshot subvolume `src` as `name` (committing first).
    pub fn snapshot(&mut self, src: u64, name: &str, readonly: bool) -> Result<u64> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        self.check_subvol_name(name)?;
        self.commit()?;
        let s = self.records.get(&src).ok_or(Error::NotFound)?.clone();
        let id = self.sb.next_subvol;
        self.sb.next_subvol += 1;
        let rec = SubvolRecord {
            root: s.root,
            readonly,
            parent: src,
            created: self.disk.now().0,
            next_ino: s.next_ino,
            name: name.into(),
        };
        self.trees.insert(id, Child::Disk(s.root));
        self.records.insert(id, rec);
        // Two trees start at that root now.
        self.free.share(s.root.block);
        self.dirty_subvols.insert(id);
        self.dirty = true;
        self.commit()?;
        Ok(id)
    }

    /// Delete a subvolume; its space comes back at the next commit. The
    /// subvolume set to boot cannot go; a deleted fallback is forgotten.
    pub fn delete_subvolume(&mut self, id: u64) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        if !self.records.contains_key(&id) {
            return Err(Error::NotFound);
        }
        if self.sb.boot.default == id {
            return Err(Error::Invalid);
        }
        if self.sb.boot.fallback == id {
            self.sb.boot.fallback = 0;
        }
        self.records.remove(&id);
        let tree = self.trees.remove(&id);
        self.dirty_subvols.remove(&id);
        let mut st =
            Store { disk: &mut self.disk, cache: &mut self.cache, unwritten: &self.unwritten, free: &mut self.free };
        tree::delete(&mut self.root_tree, &Key::new(id, KIND_SUBVOL, 0), &mut st)?;
        // What only this subvolume had is free after the commit; what
        // others share loses a reference.
        if let Some(t) = tree {
            self.release_tree(t)?;
        }
        self.dirty = true;
        Ok(())
    }

    /// A tree no parent links any more: drop its references, freeing what
    /// no one else links.
    fn release_tree(&mut self, t: Child) -> Result<()> {
        let node = match t {
            Child::Mem(n) => *n,
            Child::Disk(p) => {
                if self.free.unshare(p.block) {
                    return Ok(());
                }
                self.free.dropped.push(p.block);
                let mut st = Store {
                    disk: &mut self.disk,
                    cache: &mut self.cache,
                    unwritten: &self.unwritten,
                    free: &mut self.free,
                };
                st.load(&p)?
            }
        };
        match node.body {
            Body::Internal(children) => {
                for (_, c) in children {
                    self.release_tree(c)?;
                }
            }
            Body::Leaf(items) => {
                for (k, v) in items {
                    if k.kind == KIND_EXTENT {
                        let e = Extent::decode(&v)?;
                        self.release(e.start, e.len());
                    }
                }
            }
        }
        Ok(())
    }

    /// How much of the disk subvolume `id` holds, in bytes: (all it
    /// reaches, what is its own). A block is its own when it and every
    /// node above it have one parent (counts in [`Free`]): deleting the
    /// subvolume frees about that much (Linux boxes, ADR 0183's phase 6).
    /// Commits first, so every node is on the disk.
    pub fn usage(&mut self, id: u64) -> Result<(u64, u64)> {
        if !self.read_only {
            self.commit()?;
        }
        let root = match self.trees.get(&id).ok_or(Error::NotFound)? {
            Child::Disk(p) => *p,
            Child::Mem(_) => return Err(Error::Invalid),
        };
        let (mut all, mut own) = (0u64, 0u64);
        let mut stack = vec![(root, true)];
        while let Some((p, above_own)) = stack.pop() {
            let mine = above_own && !self.free.extra.contains_key(&p.block);
            all += 1;
            own += u64::from(mine);
            let node = {
                let mut st = Store {
                    disk: &mut self.disk,
                    cache: &mut self.cache,
                    unwritten: &self.unwritten,
                    free: &mut self.free,
                };
                st.load(&p)?
            };
            match node.body {
                Body::Internal(children) => {
                    for (_, c) in children {
                        if let Child::Disk(cp) = c {
                            stack.push((cp, mine));
                        }
                    }
                }
                Body::Leaf(items) => {
                    for (k, v) in items {
                        if k.kind == KIND_EXTENT {
                            let e = Extent::decode(&v)?;
                            all += e.len();
                            if mine {
                                own += (e.start..e.start + e.len()).filter(|b| !self.free.extra.contains_key(b)).count()
                                    as u64;
                            }
                        }
                    }
                }
            }
        }
        Ok((all * BLOCK as u64, own * BLOCK as u64))
    }

    pub fn set_readonly(&mut self, id: u64, readonly: bool) -> Result<()> {
        let r = self.records.get_mut(&id).ok_or(Error::NotFound)?;
        r.readonly = readonly;
        self.dirty_subvols.insert(id);
        self.dirty = true;
        Ok(())
    }

    pub fn boot(&self) -> BootState {
        self.sb.boot
    }

    pub fn set_boot(&mut self, b: BootState) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        self.sb.boot = b;
        self.dirty = true;
        Ok(())
    }

    // --- Inodes ----------------------------------------------------------

    pub fn stat(&mut self, sv: u64, ino: u64) -> Result<Inode> {
        let v = self.get(sv, Key::new(ino, KIND_INODE, 0))?.ok_or(Error::NotFound)?;
        Inode::decode(&v)
    }

    fn put_inode(&mut self, sv: u64, ino: u64, i: &Inode) -> Result<()> {
        self.put(sv, Key::new(ino, KIND_INODE, 0), i.encode())
    }

    fn new_ino(&mut self, sv: u64) -> Result<u64> {
        let r = self.records.get_mut(&sv).ok_or(Error::NotFound)?;
        let ino = r.next_ino;
        r.next_ino += 1;
        self.dirty_subvols.insert(sv);
        Ok(ino)
    }

    pub fn set_mode(&mut self, sv: u64, ino: u64, mode: u32) -> Result<()> {
        self.writable(sv)?;
        let mut i = self.stat(sv, ino)?;
        i.mode = (i.mode & S_IFMT) | (mode & 0o7777);
        i.ctime = self.disk.now();
        self.put_inode(sv, ino, &i)
    }

    pub fn set_owner(&mut self, sv: u64, ino: u64, uid: Option<u32>, gid: Option<u32>) -> Result<()> {
        self.writable(sv)?;
        let mut i = self.stat(sv, ino)?;
        i.uid = uid.unwrap_or(i.uid);
        i.gid = gid.unwrap_or(i.gid);
        i.ctime = self.disk.now();
        self.put_inode(sv, ino, &i)
    }

    pub fn set_times(&mut self, sv: u64, ino: u64, atime: Option<(i64, u32)>, mtime: Option<(i64, u32)>) -> Result<()> {
        self.writable(sv)?;
        let mut i = self.stat(sv, ino)?;
        i.atime = atime.unwrap_or(i.atime);
        i.mtime = mtime.unwrap_or(i.mtime);
        i.ctime = self.disk.now();
        self.put_inode(sv, ino, &i)
    }

    /// Set the access time alone (a read's update): the change time stays.
    pub fn set_atime(&mut self, sv: u64, ino: u64, atime: (i64, u32)) -> Result<()> {
        self.writable(sv)?;
        let mut i = self.stat(sv, ino)?;
        i.atime = atime;
        self.put_inode(sv, ino, &i)
    }

    // --- Directories -----------------------------------------------------

    fn check_name(name: &[u8]) -> Result<()> {
        if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') || name.contains(&0) {
            return Err(Error::Invalid);
        }
        if name.len() > NAME_MAX {
            return Err(Error::NameTooLong);
        }
        Ok(())
    }

    fn dir(&mut self, sv: u64, dir: u64) -> Result<Inode> {
        let d = self.stat(sv, dir)?;
        if !d.is_dir() {
            return Err(Error::NotDir);
        }
        Ok(d)
    }

    fn bucket(&mut self, sv: u64, dir: u64, name: &[u8]) -> Result<(Key, Vec<Dirent>)> {
        let k = Key::new(dir, KIND_DIRENT, name_hash(name));
        let list = match self.get(sv, k)? {
            Some(v) => decode_dirents(&v)?,
            None => Vec::new(),
        };
        Ok((k, list))
    }

    pub fn lookup(&mut self, sv: u64, dir: u64, name: &[u8]) -> Result<u64> {
        self.dir(sv, dir)?;
        let (_, list) = self.bucket(sv, dir, name)?;
        list.iter().find(|d| d.name == name).map(|d| d.ino).ok_or(Error::NotFound)
    }

    fn add_entry(&mut self, sv: u64, dir: u64, name: &[u8], ino: u64, kind: u8) -> Result<()> {
        let (k, mut list) = self.bucket(sv, dir, name)?;
        if list.iter().any(|d| d.name == name) {
            return Err(Error::Exists);
        }
        if list.len() >= 255 {
            return Err(Error::NoSpace);
        }
        list.push(Dirent { ino, kind, name: name.to_vec() });
        self.put(sv, k, encode_dirents(&list))?;
        let now = self.disk.now();
        let mut d = self.stat(sv, dir)?;
        d.mtime = now;
        d.ctime = now;
        self.put_inode(sv, dir, &d)
    }

    fn remove_entry(&mut self, sv: u64, dir: u64, name: &[u8]) -> Result<u64> {
        let (k, mut list) = self.bucket(sv, dir, name)?;
        let i = list.iter().position(|d| d.name == name).ok_or(Error::NotFound)?;
        let ino = list.remove(i).ino;
        if list.is_empty() {
            self.del(sv, k)?;
        } else {
            self.put(sv, k, encode_dirents(&list))?;
        }
        let now = self.disk.now();
        let mut d = self.stat(sv, dir)?;
        d.mtime = now;
        d.ctime = now;
        self.put_inode(sv, dir, &d)?;
        Ok(ino)
    }

    /// Entries with their stable positions (hash plus collision index).
    pub fn readdir(&mut self, sv: u64, dir: u64) -> Result<Vec<(u64, Dirent)>> {
        self.dir(sv, dir)?;
        let mut out = Vec::new();
        for (k, v) in self.items(sv, dir, KIND_DIRENT)? {
            for (i, d) in decode_dirents(&v)?.into_iter().enumerate() {
                out.push((k.offset + i as u64, d));
            }
        }
        Ok(out)
    }

    fn make(&mut self, sv: u64, dir: u64, name: &[u8], mut i: Inode) -> Result<u64> {
        self.writable(sv)?;
        Self::check_name(name)?;
        self.dir(sv, dir)?;
        if self.lookup(sv, dir, name).is_ok() {
            return Err(Error::Exists);
        }
        let ino = self.new_ino(sv)?;
        let now = self.disk.now();
        (i.atime, i.mtime, i.ctime) = (now, now, now);
        self.put_inode(sv, ino, &i)?;
        self.add_entry(sv, dir, name, ino, dt_of(i.mode))?;
        Ok(ino)
    }

    /// A regular file, device node, FIFO or socket (by `mode`).
    #[allow(clippy::too_many_arguments)]
    pub fn create(&mut self, sv: u64, dir: u64, name: &[u8], mode: u32, uid: u32, gid: u32, rdev: u64) -> Result<u64> {
        let mode = if mode & S_IFMT == 0 { mode | S_IFREG } else { mode };
        if mode & S_IFMT == S_IFDIR || mode & S_IFMT == S_IFLNK {
            return Err(Error::Invalid);
        }
        self.make(sv, dir, name, Inode { mode, uid, gid, nlink: 1, rdev, ..Default::default() })
    }

    pub fn mkdir(&mut self, sv: u64, dir: u64, name: &[u8], mode: u32, uid: u32, gid: u32) -> Result<u64> {
        let ino = self.make(
            sv,
            dir,
            name,
            Inode { mode: S_IFDIR | (mode & 0o7777), uid, gid, nlink: 2, parent: dir, ..Default::default() },
        )?;
        let mut d = self.stat(sv, dir)?;
        d.nlink += 1;
        self.put_inode(sv, dir, &d)?;
        Ok(ino)
    }

    pub fn symlink(&mut self, sv: u64, dir: u64, name: &[u8], target: &[u8], uid: u32, gid: u32) -> Result<u64> {
        if target.is_empty() || target.len() > tree::MAX_VALUE.min(MAX_INLINE) {
            return Err(Error::NameTooLong);
        }
        let ino = self.make(
            sv,
            dir,
            name,
            Inode { mode: S_IFLNK | 0o777, uid, gid, nlink: 1, size: target.len() as u64, ..Default::default() },
        )?;
        self.put(sv, Key::new(ino, KIND_INLINE, 0), target.to_vec())?;
        Ok(ino)
    }

    pub fn readlink(&mut self, sv: u64, ino: u64) -> Result<Vec<u8>> {
        let i = self.stat(sv, ino)?;
        if i.mode & S_IFMT != S_IFLNK {
            return Err(Error::Invalid);
        }
        self.get(sv, Key::new(ino, KIND_INLINE, 0))?.ok_or(Error::Corrupt("symlink without target"))
    }

    pub fn link(&mut self, sv: u64, dir: u64, name: &[u8], ino: u64) -> Result<()> {
        self.writable(sv)?;
        Self::check_name(name)?;
        let mut i = self.stat(sv, ino)?;
        if i.is_dir() {
            return Err(Error::IsDir);
        }
        self.dir(sv, dir)?;
        self.add_entry(sv, dir, name, ino, dt_of(i.mode))?;
        i.nlink += 1;
        i.ctime = self.disk.now();
        self.put_inode(sv, ino, &i)
    }

    /// Drop one link from `ino`; with none left it becomes an orphan until
    /// [`Fs::evict`] (the caller does that when nobody has it open).
    fn drop_link(&mut self, sv: u64, ino: u64) -> Result<()> {
        let mut i = self.stat(sv, ino)?;
        i.nlink = if i.is_dir() { 0 } else { i.nlink.saturating_sub(1) };
        i.ctime = self.disk.now();
        self.put_inode(sv, ino, &i)?;
        if i.nlink == 0 {
            self.put(sv, Key::new(0, KIND_ORPHAN, ino), Vec::new())?;
        }
        Ok(())
    }

    /// Remove a non-directory name; returns its inode.
    pub fn unlink(&mut self, sv: u64, dir: u64, name: &[u8]) -> Result<u64> {
        self.writable(sv)?;
        let ino = self.lookup(sv, dir, name)?;
        if self.stat(sv, ino)?.is_dir() {
            return Err(Error::IsDir);
        }
        self.remove_entry(sv, dir, name)?;
        self.drop_link(sv, ino)?;
        Ok(ino)
    }

    pub fn rmdir(&mut self, sv: u64, dir: u64, name: &[u8]) -> Result<u64> {
        self.writable(sv)?;
        let ino = self.lookup(sv, dir, name)?;
        if !self.stat(sv, ino)?.is_dir() {
            return Err(Error::NotDir);
        }
        if !self.items(sv, ino, KIND_DIRENT)?.is_empty() {
            return Err(Error::NotEmpty);
        }
        self.remove_entry(sv, dir, name)?;
        self.drop_link(sv, ino)?;
        let mut d = self.stat(sv, dir)?;
        d.nlink = d.nlink.saturating_sub(1);
        self.put_inode(sv, dir, &d)?;
        Ok(ino)
    }

    /// Rename; returns the inode a replaced target lost its last link from.
    pub fn rename(&mut self, sv: u64, odir: u64, oname: &[u8], ndir: u64, nname: &[u8]) -> Result<Option<u64>> {
        self.writable(sv)?;
        Self::check_name(nname)?;
        let ino = self.lookup(sv, odir, oname)?;
        let src = self.stat(sv, ino)?;
        self.dir(sv, ndir)?;
        if src.is_dir() {
            // A directory cannot move under itself.
            let mut at = ndir;
            loop {
                if at == ino {
                    return Err(Error::Invalid);
                }
                if at == ROOT_INO {
                    break;
                }
                at = self.stat(sv, at)?.parent;
            }
        }
        let mut replaced = None;
        if let Ok(t) = self.lookup(sv, ndir, nname) {
            if t == ino {
                return Ok(None);
            }
            let ti = self.stat(sv, t)?;
            match (src.is_dir(), ti.is_dir()) {
                (true, false) => return Err(Error::NotDir),
                (false, true) => return Err(Error::IsDir),
                (true, true) if !self.items(sv, t, KIND_DIRENT)?.is_empty() => return Err(Error::NotEmpty),
                _ => {}
            }
            self.remove_entry(sv, ndir, nname)?;
            self.drop_link(sv, t)?;
            if ti.is_dir() {
                let mut d = self.stat(sv, ndir)?;
                d.nlink = d.nlink.saturating_sub(1);
                self.put_inode(sv, ndir, &d)?;
            }
            if self.stat(sv, t)?.nlink == 0 {
                replaced = Some(t);
            }
        }
        self.remove_entry(sv, odir, oname)?;
        self.add_entry(sv, ndir, nname, ino, dt_of(src.mode))?;
        let mut i = self.stat(sv, ino)?;
        i.ctime = self.disk.now();
        if src.is_dir() && odir != ndir {
            i.parent = ndir;
            let mut o = self.stat(sv, odir)?;
            o.nlink = o.nlink.saturating_sub(1);
            self.put_inode(sv, odir, &o)?;
            let mut n = self.stat(sv, ndir)?;
            n.nlink += 1;
            self.put_inode(sv, ndir, &n)?;
        }
        self.put_inode(sv, ino, &i)?;
        Ok(replaced)
    }

    fn orphans(&mut self, sv: u64) -> Result<Vec<u64>> {
        Ok(self.items(sv, 0, KIND_ORPHAN)?.into_iter().map(|(k, _)| k.offset).collect())
    }

    // --- Extended attributes ---------------------------------------------

    /// `set_xattr` flags (the values setxattr(2) uses).
    pub const XATTR_CREATE: u32 = 1;
    pub const XATTR_REPLACE: u32 = 2;

    fn xattr_bucket(&mut self, sv: u64, ino: u64, name: &[u8]) -> Result<(Key, Vec<Xattr>)> {
        self.stat(sv, ino)?;
        if name.is_empty() || name.len() > NAME_MAX {
            return Err(Error::Invalid);
        }
        let k = Key::new(ino, KIND_XATTR, name_hash(name));
        let list = match self.get(sv, k)? {
            Some(v) => decode_xattrs(&v)?,
            None => Vec::new(),
        };
        Ok((k, list))
    }

    pub fn get_xattr(&mut self, sv: u64, ino: u64, name: &[u8]) -> Result<Vec<u8>> {
        let (_, list) = self.xattr_bucket(sv, ino, name)?;
        list.into_iter().find(|x| x.name == name).map(|x| x.value).ok_or(Error::NotFound)
    }

    /// Set an attribute: XATTR_CREATE fails if it exists (Exists),
    /// XATTR_REPLACE if it doesn't (NotFound). Attributes sharing a hash
    /// live in one tree item, so their total is limited (NoSpace).
    pub fn set_xattr(&mut self, sv: u64, ino: u64, name: &[u8], value: &[u8], flags: u32) -> Result<()> {
        self.writable(sv)?;
        let (k, mut list) = self.xattr_bucket(sv, ino, name)?;
        let at = list.iter().position(|x| x.name == name);
        match at {
            Some(_) if flags & Self::XATTR_CREATE != 0 => return Err(Error::Exists),
            None if flags & Self::XATTR_REPLACE != 0 => return Err(Error::NotFound),
            Some(i) => list[i].value = value.to_vec(),
            None => list.push(Xattr { name: name.to_vec(), value: value.to_vec() }),
        }
        let encoded = encode_xattrs(&list);
        if encoded.len() > tree::MAX_VALUE || value.len() > usize::from(u16::MAX) {
            return Err(Error::NoSpace);
        }
        self.put(sv, k, encoded)?;
        self.touch_ctime(sv, ino)
    }

    pub fn remove_xattr(&mut self, sv: u64, ino: u64, name: &[u8]) -> Result<()> {
        self.writable(sv)?;
        let (k, mut list) = self.xattr_bucket(sv, ino, name)?;
        let i = list.iter().position(|x| x.name == name).ok_or(Error::NotFound)?;
        list.remove(i);
        if list.is_empty() {
            self.del(sv, k)?;
        } else {
            self.put(sv, k, encode_xattrs(&list))?;
        }
        self.touch_ctime(sv, ino)
    }

    /// The names of an inode's attributes.
    pub fn list_xattrs(&mut self, sv: u64, ino: u64) -> Result<Vec<Vec<u8>>> {
        self.stat(sv, ino)?;
        let mut out = Vec::new();
        for (_, v) in self.items(sv, ino, KIND_XATTR)? {
            out.extend(decode_xattrs(&v)?.into_iter().map(|x| x.name));
        }
        Ok(out)
    }

    fn touch_ctime(&mut self, sv: u64, ino: u64) -> Result<()> {
        let mut i = self.stat(sv, ino)?;
        i.ctime = self.disk.now();
        self.put_inode(sv, ino, &i)
    }

    /// Free an inode with no links left (its data and record).
    pub fn evict(&mut self, sv: u64, ino: u64) -> Result<()> {
        self.writable(sv)?;
        let Ok(i) = self.stat(sv, ino) else {
            self.del(sv, Key::new(0, KIND_ORPHAN, ino))?;
            return Ok(());
        };
        if i.nlink != 0 {
            return Ok(());
        }
        for (k, v) in self.items(sv, ino, KIND_EXTENT)? {
            let e = Extent::decode(&v)?;
            self.del(sv, k)?;
            self.release(e.start, e.len());
        }
        for (k, _) in self.items(sv, ino, KIND_XATTR)? {
            self.del(sv, k)?;
        }
        self.del(sv, Key::new(ino, KIND_INLINE, 0))?;
        self.del(sv, Key::new(ino, KIND_INODE, 0))?;
        self.del(sv, Key::new(0, KIND_ORPHAN, ino))?;
        Ok(())
    }

    // --- File data -------------------------------------------------------

    /// The extent covering file block `b`: its key and contents.
    fn extent_at(&mut self, sv: u64, ino: u64, b: u64) -> Result<Option<(u64, Extent)>> {
        match self.floor(sv, Key::new(ino, KIND_EXTENT, b))? {
            Some((k, v)) if k.object == ino && k.kind == KIND_EXTENT => {
                let e = Extent::decode(&v)?;
                Ok((b < k.offset + e.len()).then_some((k.offset, e)))
            }
            _ => Ok(None),
        }
    }

    pub fn read(&mut self, sv: u64, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let i = self.stat(sv, ino)?;
        if i.is_dir() {
            return Err(Error::IsDir);
        }
        if offset >= i.size {
            return Ok(0);
        }
        let n = buf.len().min((i.size - offset) as usize);
        let mut done = 0;
        while done < n {
            let pos = offset + done as u64;
            let b = pos / BLOCK as u64;
            let within = (pos % BLOCK as u64) as usize;
            match self.extent_at(sv, ino, b)? {
                None => {
                    // A hole: zeros up to the next block.
                    let take = (BLOCK - within).min(n - done);
                    buf[done..done + take].fill(0);
                    done += take;
                }
                Some((first, e)) => {
                    // Read the rest of the extent (or what is wanted) at once.
                    let idx = (b - first) as usize;
                    let want_blocks = (within + (n - done)).div_ceil(BLOCK).min(e.crcs.len() - idx);
                    let mut data = vec![0u8; want_blocks * BLOCK];
                    self.disk.read((e.start + idx as u64) * BLOCK as u64, &mut data)?;
                    for (j, chunk) in data.chunks(BLOCK).enumerate() {
                        if slate_hash::crc32c(chunk) != e.crcs[idx + j] {
                            return Err(Error::Checksum(e.start + (idx + j) as u64));
                        }
                    }
                    let take = (want_blocks * BLOCK - within).min(n - done);
                    buf[done..done + take].copy_from_slice(&data[within..within + take]);
                    done += take;
                }
            }
        }
        Ok(n)
    }

    /// Point file block `b` at disk block `phys` (whose CRC is `crc`),
    /// splitting the extent that covered it and merging with a contiguous
    /// neighbour.
    fn map_block(&mut self, sv: u64, ino: u64, b: u64, phys: u64, crc: u32) -> Result<()> {
        if let Some((first, e)) = self.extent_at(sv, ino, b)? {
            self.del(sv, Key::new(ino, KIND_EXTENT, first))?;
            let idx = (b - first) as usize;
            self.release(e.start + idx as u64, 1);
            if idx > 0 {
                let left = Extent { start: e.start, crcs: e.crcs[..idx].to_vec() };
                self.put(sv, Key::new(ino, KIND_EXTENT, first), left.encode())?;
            }
            if idx + 1 < e.crcs.len() {
                let right = Extent { start: e.start + idx as u64 + 1, crcs: e.crcs[idx + 1..].to_vec() };
                self.put(sv, Key::new(ino, KIND_EXTENT, b + 1), right.encode())?;
            }
        }
        let mut start_b = b;
        let mut ext = Extent { start: phys, crcs: vec![crc] };
        if b > 0
            && let Some((first, left)) = self.extent_at(sv, ino, b - 1)?
            && first + left.len() == b
            && left.start + left.len() == phys
            && left.len() < MAX_EXTENT
        {
            self.del(sv, Key::new(ino, KIND_EXTENT, first))?;
            start_b = first;
            let mut crcs = left.crcs;
            crcs.push(crc);
            ext = Extent { start: left.start, crcs };
        }
        self.put(sv, Key::new(ino, KIND_EXTENT, start_b), ext.encode())
    }

    pub fn write(&mut self, sv: u64, ino: u64, offset: u64, data: &[u8]) -> Result<usize> {
        self.writable(sv)?;
        let mut i = self.stat(sv, ino)?;
        if i.is_dir() {
            return Err(Error::IsDir);
        }
        let end = offset.checked_add(data.len() as u64).ok_or(Error::TooBig)?;
        if end > MAX_FILE_SIZE {
            return Err(Error::TooBig);
        }
        let mut done = 0;
        while done < data.len() {
            let pos = offset + done as u64;
            let b = pos / BLOCK as u64;
            let within = (pos % BLOCK as u64) as usize;
            let take = (BLOCK - within).min(data.len() - done);
            let existing = self.extent_at(sv, ino, b)?;
            let mut block = vec![0u8; BLOCK];
            if take < BLOCK
                && let Some((first, e)) = &existing
            {
                let phys = e.start + (b - first);
                self.disk.read(phys * BLOCK as u64, &mut block)?;
                if slate_hash::crc32c(&block) != e.crcs[(b - first) as usize] {
                    return Err(Error::Checksum(phys));
                }
            }
            block[within..within + take].copy_from_slice(&data[done..done + take]);
            let crc = slate_hash::crc32c(&block);
            match existing {
                // Allocated in this transaction: nothing committed refers to it.
                Some((first, mut e)) if self.space.txn.get(e.start + (b - first)) => {
                    let phys = e.start + (b - first);
                    self.disk.write(phys * BLOCK as u64, &block)?;
                    e.crcs[(b - first) as usize] = crc;
                    self.put(sv, Key::new(ino, KIND_EXTENT, first), e.encode())?;
                }
                _ => {
                    let phys = self.alloc()?;
                    self.disk.write(phys * BLOCK as u64, &block)?;
                    self.map_block(sv, ino, b, phys, crc)?;
                }
            }
            done += take;
        }
        let now = self.disk.now();
        i = self.stat(sv, ino)?;
        i.size = i.size.max(end);
        i.mtime = now;
        i.ctime = now;
        self.put_inode(sv, ino, &i)?;
        Ok(data.len())
    }

    pub fn truncate(&mut self, sv: u64, ino: u64, size: u64) -> Result<()> {
        self.writable(sv)?;
        let mut i = self.stat(sv, ino)?;
        if i.is_dir() {
            return Err(Error::IsDir);
        }
        if size < i.size {
            let keep_blocks = size.div_ceil(BLOCK as u64);
            for (k, v) in self.items(sv, ino, KIND_EXTENT)? {
                let e = Extent::decode(&v)?;
                // Out of the tree first: copying a leaf a snapshot shares
                // gives its extents their second reference.
                if k.offset >= keep_blocks {
                    self.del(sv, k)?;
                    self.release(e.start, e.len());
                } else if k.offset + e.len() > keep_blocks {
                    let n = (keep_blocks - k.offset) as usize;
                    self.put(sv, k, Extent { start: e.start, crcs: e.crcs[..n].to_vec() }.encode())?;
                    self.release(e.start + n as u64, e.len() - n as u64);
                }
            }
            // Zero the tail of a partial last block (so a later grow reads zeros).
            let tail = (size % BLOCK as u64) as usize;
            if tail != 0 && self.extent_at(sv, ino, size / BLOCK as u64)?.is_some() {
                i.size = size;
                self.put_inode(sv, ino, &i)?;
                self.write(sv, ino, size, &vec![0u8; BLOCK - tail])?;
            }
        }
        let now = self.disk.now();
        i = self.stat(sv, ino)?;
        i.size = size;
        i.mtime = now;
        i.ctime = now;
        self.put_inode(sv, ino, &i)
    }

    // --- Checking ----------------------------------------------------------

    /// Check everything reachable: checksums, key order, and in each
    /// subvolume that entries point at inodes, link counts add up, and
    /// extents stay on the device. Returns the problems found.
    pub fn check(&mut self) -> Result<Vec<String>> {
        let mut problems = Vec::new();
        let ids: Vec<u64> = self.records.keys().copied().collect();
        for sv in ids {
            problems.extend(self.scan(sv)?.into_iter().map(|(text, _)| text));
        }
        Ok(problems)
    }

    /// Fix what [`Fs::check`] finds where the fix is safe, then commit;
    /// returns what was done and what is left. Entries pointing at nothing
    /// or stored under the wrong hash, extents off the device or overlapping
    /// others, attributes of missing inodes, wrong parents and link counts
    /// are repaired; inodes nothing links to go to `/lost+found` as `#INO`
    /// (read-only snapshots are repaired too). Unreadable trees are only
    /// reported.
    pub fn repair(&mut self) -> Result<(Vec<String>, Vec<String>)> {
        // Removed extents and entries are found free by a walk.
        self.free.walk = true;
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        let mut done = Vec::new();
        let ids: Vec<u64> = self.records.keys().copied().collect();
        for sv in ids {
            let name = self.records[&sv].name.clone();
            // Entries and data first; link counts and lost files once those
            // are right.
            for pass in 0..2 {
                for (text, fix) in self.scan(sv)? {
                    let Some(fix) = fix else { continue };
                    let late = matches!(fix, Fix::Nlink { .. } | Fix::Unreachable { .. });
                    if late != (pass == 1) {
                        continue;
                    }
                    self.apply(sv, fix)?;
                    done.push(alloc::format!("fixed: {text}"));
                }
            }
            if !done.is_empty() {
                self.dirty_subvols.insert(sv);
                self.dirty = true;
            }
            let _ = name;
        }
        self.commit()?;
        let left = self.check()?;
        Ok((done, left))
    }

    fn apply(&mut self, sv: u64, fix: Fix) -> Result<()> {
        match fix {
            Fix::Rehash { dir, offset, entry } => {
                self.remove_dirent(sv, dir, offset, &entry.name)?;
                if self.add_entry(sv, dir, &entry.name, entry.ino, entry.kind).is_err() {
                    // A same-named entry already lives where this one belongs.
                    let mut i = self.stat(sv, entry.ino)?;
                    i.nlink = i.nlink.saturating_sub(1);
                    self.put_inode(sv, entry.ino, &i)?;
                }
            }
            Fix::Dangling { dir, offset, name } => self.remove_dirent(sv, dir, offset, &name)?,
            Fix::Extent { ino, offset } => {
                self.del(sv, Key::new(ino, KIND_EXTENT, offset))?;
            }
            Fix::Xattrs { ino } => {
                for (k, _) in self.items(sv, ino, KIND_XATTR)? {
                    self.del(sv, k)?;
                }
            }
            Fix::Parent { ino, parent } => {
                let mut i = self.stat(sv, ino)?;
                i.parent = parent;
                self.put_inode(sv, ino, &i)?;
            }
            Fix::Nlink { ino, want } => {
                let mut i = self.stat(sv, ino)?;
                i.nlink = want;
                self.put_inode(sv, ino, &i)?;
            }
            Fix::Unreachable { ino } => {
                let lf = self.lost_and_found(sv)?;
                let mut i = self.stat(sv, ino)?;
                let name = alloc::format!("#{ino}");
                self.add_entry(sv, lf, name.as_bytes(), ino, dt_of(i.mode))?;
                if i.is_dir() {
                    i.parent = lf;
                    let mut d = self.stat(sv, lf)?;
                    d.nlink += 1;
                    self.put_inode(sv, lf, &d)?;
                }
                // The count follows on the next scan; at least one link now.
                i.nlink = i.nlink.max(if i.is_dir() { 2 } else { 1 });
                self.put_inode(sv, ino, &i)?;
                self.del(sv, Key::new(0, KIND_ORPHAN, ino))?;
            }
        }
        Ok(())
    }

    /// Remove entry `name` from the dirent item at `offset` of `dir`.
    fn remove_dirent(&mut self, sv: u64, dir: u64, offset: u64, name: &[u8]) -> Result<()> {
        let k = Key::new(dir, KIND_DIRENT, offset);
        let Some(v) = self.get(sv, k)? else { return Ok(()) };
        let mut list = decode_dirents(&v)?;
        list.retain(|d| d.name != name);
        if list.is_empty() {
            self.del(sv, k)?;
        } else {
            self.put(sv, k, encode_dirents(&list))?;
        }
        Ok(())
    }

    /// The subvolume's `/lost+found`, made if missing.
    fn lost_and_found(&mut self, sv: u64) -> Result<u64> {
        if let Ok(ino) = self.lookup(sv, ROOT_INO, b"lost+found") {
            return Ok(ino);
        }
        let ino = self.new_ino(sv)?;
        let now = self.disk.now();
        let i = Inode {
            mode: S_IFDIR | 0o700,
            nlink: 2,
            parent: ROOT_INO,
            atime: now,
            mtime: now,
            ctime: now,
            ..Default::default()
        };
        self.put_inode(sv, ino, &i)?;
        self.add_entry(sv, ROOT_INO, b"lost+found", ino, DT_DIR)?;
        let mut root = self.stat(sv, ROOT_INO)?;
        root.nlink += 1;
        self.put_inode(sv, ROOT_INO, &root)?;
        Ok(ino)
    }

    /// Check one subvolume: each problem, with its fix where one is safe.
    fn scan(&mut self, sv: u64) -> Result<Vec<(String, Option<Fix>)>> {
        let mut problems: Vec<(String, Option<Fix>)> = Vec::new();
        let name = self.records[&sv].name.clone();
        let mut inodes: BTreeMap<u64, Inode> = BTreeMap::new();
        let mut links: BTreeMap<u64, u32> = BTreeMap::new();
        let mut subdirs: BTreeMap<u64, u32> = BTreeMap::new();
        let mut extents: Vec<(u64, u64, u64)> = Vec::new();
        let mut entries: Vec<(u64, u64, Dirent)> = Vec::new();
        let mut orphans: BTreeSet<u64> = BTreeSet::new();
        let mut xattr_owners: BTreeSet<u64> = BTreeSet::new();
        let t = self.trees[&sv].clone();
        let mut st =
            Store { disk: &mut self.disk, cache: &mut self.cache, unwritten: &self.unwritten, free: &mut self.free };
        let blocks = self.sb.blocks;
        let r = tree::for_each(&t, &mut st, &mut |k, v| {
            match k.kind {
                KIND_INODE => {
                    inodes.insert(k.object, Inode::decode(v)?);
                }
                KIND_DIRENT => {
                    for d in decode_dirents(v)? {
                        entries.push((k.object, k.offset, d));
                    }
                }
                KIND_EXTENT => {
                    let e = Extent::decode(v)?;
                    if e.start < 2 || e.start + e.len() > blocks {
                        problems.push((
                            alloc::format!("{name}: inode {} extent outside the device", k.object),
                            Some(Fix::Extent { ino: k.object, offset: k.offset }),
                        ));
                    } else {
                        extents.push((k.object, k.offset, e.len()));
                    }
                }
                KIND_ORPHAN => {
                    orphans.insert(k.offset);
                }
                KIND_XATTR => {
                    for x in decode_xattrs(v)? {
                        if name_hash(&x.name) != k.offset {
                            problems.push((
                                alloc::format!("{name}: inode {} attribute under the wrong hash", k.object),
                                None,
                            ));
                        }
                    }
                    xattr_owners.insert(k.object);
                }
                _ => {}
            }
            Ok(())
        });
        if let Err(e) = r {
            problems.push((alloc::format!("{name}: tree unreadable: {e:?}"), None));
            return Ok(problems);
        }
        for ino in &xattr_owners {
            if !inodes.contains_key(ino) {
                problems.push((
                    alloc::format!("{name}: attributes of missing inode {ino}"),
                    Some(Fix::Xattrs { ino: *ino }),
                ));
            }
        }
        for (dir, offset, d) in &entries {
            let shown = String::from_utf8_lossy(&d.name);
            if !inodes.get(dir).is_some_and(Inode::is_dir) {
                problems.push((
                    alloc::format!("{name}: entries in {dir}, which is not a directory"),
                    Some(Fix::Dangling { dir: *dir, offset: *offset, name: d.name.clone() }),
                ));
                continue;
            }
            let Some(i) = inodes.get(&d.ino) else {
                problems.push((
                    alloc::format!("{name}: entry {shown:?} in {dir} points at missing inode {}", d.ino),
                    Some(Fix::Dangling { dir: *dir, offset: *offset, name: d.name.clone() }),
                ));
                continue;
            };
            if name_hash(&d.name) != *offset {
                problems.push((
                    alloc::format!("{name}: entry {shown:?} under the wrong hash"),
                    Some(Fix::Rehash { dir: *dir, offset: *offset, entry: d.clone() }),
                ));
            }
            *links.entry(d.ino).or_insert(0) += 1;
            if i.is_dir() {
                *subdirs.entry(*dir).or_insert(0) += 1;
                if i.parent != *dir {
                    problems.push((
                        alloc::format!("{name}: directory {} has parent {} but lives in {dir}", d.ino, i.parent),
                        Some(Fix::Parent { ino: d.ino, parent: *dir }),
                    ));
                }
            }
        }
        for (ino, i) in &inodes {
            let reachable = *ino == ROOT_INO || links.contains_key(ino);
            if !reachable && !orphans.contains(ino) {
                problems.push((
                    alloc::format!("{name}: inode {ino} is unreachable and not an orphan"),
                    Some(Fix::Unreachable { ino: *ino }),
                ));
                continue;
            }
            let want = if i.is_dir() {
                if reachable { 2 + subdirs.get(ino).copied().unwrap_or(0) } else { 0 }
            } else {
                links.get(ino).copied().unwrap_or(0)
            };
            if i.nlink != want {
                problems.push((
                    alloc::format!("{name}: inode {ino} has nlink {} but {want} links", i.nlink),
                    Some(Fix::Nlink { ino: *ino, want }),
                ));
            }
        }
        extents.sort();
        let mut end_of: BTreeMap<u64, u64> = BTreeMap::new();
        for &(ino, offset, len) in &extents {
            if !inodes.contains_key(&ino) {
                problems
                    .push((alloc::format!("{name}: extent of missing inode {ino}"), Some(Fix::Extent { ino, offset })));
                continue;
            }
            let end = end_of.entry(ino).or_insert(0);
            if offset < *end {
                problems.push((
                    alloc::format!("{name}: inode {ino} has overlapping extents"),
                    Some(Fix::Extent { ino, offset }),
                ));
            } else {
                *end = offset + len;
            }
        }
        Ok(problems)
    }
}

/// Mark everything reachable from `ptr`; shared subtrees are visited once.
fn mark(
    ptr: &BlockPtr,
    st: &mut dyn Load,
    used: &mut Bitmap,
    extra: &mut BTreeMap<u64, u32>,
    blocks: u64,
) -> Result<()> {
    if ptr.block >= blocks {
        return Err(Error::Corrupt("pointer outside the device"));
    }
    // Reached again: another parent links it (its subtree was counted).
    if used.get(ptr.block) {
        *extra.entry(ptr.block).or_insert(0) += 1;
        return Ok(());
    }
    used.set(ptr.block);
    let node = st.load(ptr)?;
    match node.body {
        Body::Internal(children) => {
            for (_, c) in children {
                if let Child::Disk(p) = c {
                    mark(&p, st, used, extra, blocks)?;
                }
            }
        }
        Body::Leaf(items) => {
            for (k, v) in items {
                match k.kind {
                    KIND_EXTENT => {
                        let e = Extent::decode(&v)?;
                        for b in e.start..(e.start + e.len()).min(blocks) {
                            if used.get(b) {
                                *extra.entry(b).or_insert(0) += 1;
                            }
                            used.set(b);
                        }
                    }
                    KIND_SUBVOL => mark(&SubvolRecord::decode(&v)?.root, st, used, extra, blocks)?,
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

/// Runs of blocks in `old_used` but not in `used` (what a commit freed),
/// a word at a time.
fn freed_runs(old_used: &Bitmap, used: &Bitmap) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    let words = old_used.0.iter().flatten().zip(used.0.iter().flatten());
    for (w, (&a, &u)) in words.enumerate() {
        let mut freed = a & !u;
        while freed != 0 {
            let b = w as u64 * 64 + u64::from(freed.trailing_zeros());
            freed &= freed - 1;
            match out.last_mut() {
                Some((s, n)) if *s + *n == b => *n += 1,
                _ => out.push((b, 1)),
            }
        }
    }
    out
}

/// Runs of blocks in `[first, end)` where `f` holds: (first, count).
fn runs_in(first: u64, end: u64, f: impl Fn(u64) -> bool) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for b in first..end {
        if f(b) {
            match out.last_mut() {
                Some((s, n)) if *s + *n == b => *n += 1,
                _ => out.push((b, 1)),
            }
        }
    }
    out
}

/// A repair [`Fs::repair`] can make.
enum Fix {
    /// Re-file an entry stored under the wrong name hash.
    Rehash {
        dir: u64,
        offset: u64,
        entry: Dirent,
    },
    /// Remove an entry (it points at nothing, or lives in a non-directory).
    Dangling {
        dir: u64,
        offset: u64,
        name: Vec<u8>,
    },
    /// Remove an extent (off the device, or overlapping the one before).
    Extent {
        ino: u64,
        offset: u64,
    },
    /// Remove the attributes of a missing inode.
    Xattrs {
        ino: u64,
    },
    Parent {
        ino: u64,
        parent: u64,
    },
    Nlink {
        ino: u64,
        want: u32,
    },
    /// Link an inode nothing links to into /lost+found.
    Unreachable {
        ino: u64,
    },
}

#[cfg(test)]
mod tests;
