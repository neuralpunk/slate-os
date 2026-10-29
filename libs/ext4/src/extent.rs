// SPDX-License-Identifier: MIT OR Apache-2.0

//! Mapping file blocks to disk blocks: extent trees (read and write) and
//! the older direct/indirect block maps (read only).
//!
//! An extent tree's root is the 60-byte `i_block` (a header and up to four
//! entries); deeper nodes are whole blocks ending in a checksum tail.
//! Index entries always carry the first logical block of their subtree.

use alloc::vec;
use alloc::vec::Vec;

use crate::layout::*;
use crate::{Disk, Error, Fs, Result, crc};

/// A mapped run: `len` blocks of the file from the queried block on, at
/// physical `start` (or a hole of `len` blocks when `start` is `None`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Run {
    pub start: Option<u64>,
    pub len: u32,
    pub uninit: bool,
}

/// A tree node being edited: the root (in the inode) or a block.
struct Node {
    /// `None` for the root.
    block: Option<u64>,
    data: Vec<u8>,
}

impl Node {
    fn header(&self) -> Result<ExtentHeader> {
        ExtentHeader::read(&self.data).ok_or(Error::Corrupt("bad extent header"))
    }
    fn set_entries(&mut self, n: u16) {
        put16(&mut self.data, 2, n);
    }
    fn entry(&self, i: usize) -> &[u8] {
        let at = EXTENT_HEADER + i * EXTENT_ENTRY;
        &self.data[at..at + EXTENT_ENTRY]
    }
    fn entry_mut(&mut self, i: usize) -> &mut [u8] {
        let at = EXTENT_HEADER + i * EXTENT_ENTRY;
        &mut self.data[at..at + EXTENT_ENTRY]
    }
    /// Make room at `i` by shifting later entries up.
    fn insert_gap(&mut self, i: usize, count: usize) {
        let at = EXTENT_HEADER + i * EXTENT_ENTRY;
        let end = EXTENT_HEADER + count * EXTENT_ENTRY;
        self.data.copy_within(at..end, at + EXTENT_ENTRY);
    }
    fn remove_entry(&mut self, i: usize, count: usize) {
        let at = EXTENT_HEADER + i * EXTENT_ENTRY;
        let end = EXTENT_HEADER + count * EXTENT_ENTRY;
        self.data.copy_within(at + EXTENT_ENTRY..end, at);
    }
    fn first_block(&self, depth: u16) -> u32 {
        if depth == 0 { Extent::read(self.entry(0)).block } else { ExtentIndex::read(self.entry(0)).block }
    }
}

impl<D: Disk> Fs<D> {
    fn uses_extents(raw: &RawInode) -> bool {
        raw.flags() & EXTENTS_FL != 0
    }

    pub(crate) fn extent_block_max(&self) -> u16 {
        ((self.block_size as usize - EXTENT_HEADER - 4) / EXTENT_ENTRY) as u16
    }

    fn extent_block_csum(&self, ino: u32, raw: &RawInode, data: &[u8]) -> u32 {
        let max = usize::from(get16(data, 4));
        let len = EXTENT_HEADER + max * EXTENT_ENTRY;
        crc::crc32c(self.inode_seed(ino, raw.generation()), &data[..len])
    }

    fn read_extent_block(&mut self, ino: u32, raw: &RawInode, blk: u64) -> Result<Vec<u8>> {
        let data = self.read_block(blk)?;
        let h = ExtentHeader::read(&data).ok_or(Error::Corrupt("bad extent block header"))?;
        if h.max == 0 || EXTENT_HEADER + usize::from(h.max) * EXTENT_ENTRY + 4 > data.len() || h.entries > h.max {
            return Err(Error::Corrupt("bad extent block geometry"));
        }
        if self.metadata_csum {
            let at = EXTENT_HEADER + usize::from(h.max) * EXTENT_ENTRY;
            if get32(&data, at) != self.extent_block_csum(ino, raw, &data) {
                return Err(Error::Corrupt("extent block checksum"));
            }
        }
        Ok(data)
    }

    fn write_extent_block(&mut self, ino: u32, raw: &RawInode, blk: u64, data: &mut [u8]) -> Result<()> {
        if self.metadata_csum {
            let max = usize::from(get16(data, 4));
            let c = self.extent_block_csum(ino, raw, data);
            put32(data, EXTENT_HEADER + max * EXTENT_ENTRY, c);
        }
        self.write_block(blk, data)
    }

    /// Map logical block `lblk` of an inode.
    pub(crate) fn map(&mut self, ino: u32, raw: &RawInode, lblk: u32) -> Result<Run> {
        if Self::uses_extents(raw) { self.map_extent(ino, raw, lblk) } else { self.map_indirect(raw, lblk) }
    }

    fn map_extent(&mut self, ino: u32, raw: &RawInode, lblk: u32) -> Result<Run> {
        let mut node: Vec<u8> = raw.i_block().to_vec();
        for _ in 0..8 {
            let h = ExtentHeader::read(&node).ok_or(Error::Corrupt("bad extent header"))?;
            let n = usize::from(h.entries);
            let at = |i: usize| EXTENT_HEADER + i * EXTENT_ENTRY;
            if h.depth == 0 {
                // The extent containing lblk, else the hole up to the next one.
                let mut next_start = u32::MAX;
                for i in 0..n {
                    let e = Extent::read(&node[at(i)..]);
                    if lblk >= e.block && lblk < e.end() {
                        let off = lblk - e.block;
                        return Ok(Run { start: Some(e.start + u64::from(off)), len: e.len - off, uninit: e.uninit });
                    }
                    if e.block > lblk {
                        next_start = next_start.min(e.block);
                    }
                }
                return Ok(Run { start: None, len: next_start - lblk, uninit: false });
            }
            // Last index whose first block is <= lblk.
            let mut chosen = None;
            for i in 0..n {
                let ix = ExtentIndex::read(&node[at(i)..]);
                if ix.block <= lblk || chosen.is_none() {
                    chosen = Some(ix);
                }
                if ix.block > lblk {
                    break;
                }
            }
            let Some(ix) = chosen else { return Ok(Run { start: None, len: u32::MAX - lblk, uninit: false }) };
            node = self.read_extent_block(ino, raw, ix.leaf)?;
        }
        Err(Error::Corrupt("extent tree too deep"))
    }

    /// Direct, indirect, double and triple indirect blocks (ext2/ext3 files).
    fn map_indirect(&mut self, raw: &RawInode, lblk: u32) -> Result<Run> {
        let per = self.block_size / 4;
        let ib = raw.i_block();
        let mut l = lblk;
        let lookup = |fs: &mut Self, mut blk: u32, levels: u32, mut idx: u32| -> Result<u32> {
            for level in (0..levels).rev() {
                if blk == 0 {
                    return Ok(0);
                }
                let div = per.pow(level);
                let b = fs.read_block(u64::from(blk))?;
                blk = get32(&b, ((idx / div) * 4) as usize);
                idx %= div;
            }
            Ok(blk)
        };
        let phys = if l < 12 {
            get32(ib, (l * 4) as usize)
        } else {
            l -= 12;
            if l < per {
                lookup(self, get32(ib, 48), 1, l)?
            } else {
                l -= per;
                if l < per * per {
                    lookup(self, get32(ib, 52), 2, l)?
                } else {
                    l -= per * per;
                    lookup(self, get32(ib, 56), 3, l)?
                }
            }
        };
        Ok(if phys == 0 {
            Run { start: None, len: 1, uninit: false }
        } else {
            Run { start: Some(u64::from(phys)), len: 1, uninit: false }
        })
    }

    // --- writing ----------------------------------------------------------

    pub(crate) fn init_extent_root(raw: &mut RawInode) {
        let ib = raw.i_block_mut();
        ib.fill(0);
        ExtentHeader { entries: 0, max: 4, depth: 0 }.write(ib);
        raw.set_flags(raw.flags() | EXTENTS_FL);
    }

    fn add_blocks_count(&self, raw: &mut RawInode, blocks: i64) {
        let unit = self.blocks_unit(raw) as i64;
        let delta = blocks * i64::from(self.block_size) / unit;
        raw.set_blocks_raw((raw.blocks_raw() as i64 + delta).max(0) as u64);
    }

    fn load(&mut self, ino: u32, raw: &RawInode, block: Option<u64>) -> Result<Node> {
        Ok(match block {
            None => Node { block: None, data: raw.i_block().to_vec() },
            Some(b) => Node { block: Some(b), data: self.read_extent_block(ino, raw, b)? },
        })
    }

    fn store(&mut self, ino: u32, raw: &mut RawInode, node: &mut Node) -> Result<()> {
        match node.block {
            None => {
                raw.i_block_mut().copy_from_slice(&node.data[..60]);
                Ok(())
            }
            Some(b) => {
                let r = raw.clone();
                self.write_extent_block(ino, &r, b, &mut node.data)
            }
        }
    }

    /// Path from the root to the leaf that should hold `lblk`: the nodes
    /// and, for each index node, the entry taken.
    fn path(&mut self, ino: u32, raw: &RawInode, lblk: u32) -> Result<Vec<(Node, usize)>> {
        let mut path = Vec::new();
        let mut node = self.load(ino, raw, None)?;
        for _ in 0..8 {
            let h = node.header()?;
            if h.depth == 0 {
                path.push((node, 0));
                return Ok(path);
            }
            let mut idx = 0;
            for i in 0..usize::from(h.entries) {
                if ExtentIndex::read(node.entry(i)).block <= lblk {
                    idx = i;
                }
            }
            if h.entries == 0 {
                return Err(Error::Corrupt("empty extent index node"));
            }
            let child = ExtentIndex::read(node.entry(idx)).leaf;
            path.push((node, idx));
            node = self.load(ino, raw, Some(child))?;
        }
        Err(Error::Corrupt("extent tree too deep"))
    }

    /// Record that file blocks `lblk..lblk+len` live at `start..`. The range
    /// must currently be unmapped.
    pub(crate) fn insert_extent(&mut self, ino: u32, raw: &mut RawInode, ext: Extent) -> Result<()> {
        for _ in 0..16 {
            let mut path = self.path(ino, raw, ext.block)?;
            let (leaf, _) = path.last_mut().unwrap();
            let h = leaf.header()?;
            let n = usize::from(h.entries);
            // Position: first extent starting after ext.block.
            let pos = (0..n).find(|&i| Extent::read(leaf.entry(i)).block > ext.block).unwrap_or(n);
            // Merge with the previous extent when physically contiguous.
            if pos > 0 {
                let mut prev = Extent::read(leaf.entry(pos - 1));
                if !prev.uninit
                    && !ext.uninit
                    && prev.end() == ext.block
                    && prev.start + u64::from(prev.len) == ext.start
                    && prev.len + ext.len <= EXTENT_INIT_MAX
                {
                    prev.len += ext.len;
                    prev.write(leaf.entry_mut(pos - 1));
                    let mut leaf = path.pop().unwrap().0;
                    return self.store(ino, raw, &mut leaf);
                }
            }
            if n < usize::from(h.max) {
                leaf.insert_gap(pos, n);
                ext.write(leaf.entry_mut(pos));
                leaf.set_entries(h.entries + 1);
                return self.store_path_after_insert(ino, raw, path, pos == 0);
            }
            // Full: make room, then retry.
            self.split(ino, raw, path)?;
        }
        Err(Error::Corrupt("extent insertion did not converge"))
    }

    /// Write back a path whose leaf changed; when the leaf's first entry
    /// changed, the index entries above it are updated to match.
    fn store_path_after_insert(
        &mut self,
        ino: u32,
        raw: &mut RawInode,
        mut path: Vec<(Node, usize)>,
        first_changed: bool,
    ) -> Result<()> {
        let (mut leaf, _) = path.pop().unwrap();
        let mut first = leaf.first_block(0);
        self.store(ino, raw, &mut leaf)?;
        let mut changed = first_changed;
        while let Some((mut node, idx)) = path.pop() {
            if !changed {
                break;
            }
            let mut ix = ExtentIndex::read(node.entry(idx));
            if ix.block != first {
                ix.block = first;
                ix.write(node.entry_mut(idx));
                let depth = node.header()?.depth;
                first = node.first_block(depth);
                changed = idx == 0;
                self.store(ino, raw, &mut node)?;
            } else {
                break;
            }
        }
        Ok(())
    }

    /// Make room in the full last node of `path`: split it in two (adding an
    /// index entry to its parent, splitting that first if needed), or, if it
    /// is the root, move its entries into a new block one level down.
    fn split(&mut self, ino: u32, raw: &mut RawInode, mut path: Vec<(Node, usize)>) -> Result<()> {
        // Find the lowest node on the path whose parent has room (or the root).
        let mut level = path.len() - 1;
        loop {
            if level == 0 {
                return self.grow_root(ino, raw);
            }
            let ph = path[level - 1].0.header()?;
            if ph.entries < ph.max {
                break;
            }
            level -= 1;
        }
        let goal = path[level].0.block.unwrap_or(0) + 1;
        let (newblk, _) = self.alloc_blocks(goal, 1)?;
        self.add_blocks_count(raw, 1);
        let (node, _) = &mut path[level];
        let h = node.header()?;
        let n = usize::from(h.entries);
        let keep = n / 2;
        let mut new = Node { block: Some(newblk), data: vec![0u8; self.block_size as usize] };
        ExtentHeader { entries: (n - keep) as u16, max: self.extent_block_max(), depth: h.depth }.write(&mut new.data);
        for i in keep..n {
            let src = node.entry(i).to_vec();
            new.entry_mut(i - keep).copy_from_slice(&src);
        }
        node.set_entries(keep as u16);
        let new_first = new.first_block(h.depth);
        let mut node = core::mem::replace(&mut path[level].0, Node { block: None, data: Vec::new() });
        self.store(ino, raw, &mut new)?;
        self.store(ino, raw, &mut node)?;
        // Insert the index entry for the new node into the parent.
        let (parent, idx) = &mut path[level - 1];
        let ph = parent.header()?;
        let pn = usize::from(ph.entries);
        parent.insert_gap(*idx + 1, pn);
        ExtentIndex { block: new_first, leaf: newblk }.write(parent.entry_mut(*idx + 1));
        parent.set_entries(ph.entries + 1);
        let mut parent = core::mem::replace(&mut path[level - 1].0, Node { block: None, data: Vec::new() });
        self.store(ino, raw, &mut parent)
    }

    /// Move the root's entries into a new block and make the root a single
    /// index entry pointing at it (the tree grows one level).
    fn grow_root(&mut self, ino: u32, raw: &mut RawInode) -> Result<()> {
        let root = self.load(ino, raw, None)?;
        let h = root.header()?;
        let (blk, _) = self.alloc_blocks(self.goal_for_inode(ino), 1)?;
        self.add_blocks_count(raw, 1);
        let mut child = Node { block: Some(blk), data: vec![0u8; self.block_size as usize] };
        ExtentHeader { entries: h.entries, max: self.extent_block_max(), depth: h.depth }.write(&mut child.data);
        for i in 0..usize::from(h.entries) {
            let src = root.entry(i).to_vec();
            child.entry_mut(i).copy_from_slice(&src);
        }
        let first = if h.entries > 0 { root.first_block(h.depth) } else { 0 };
        self.store(ino, raw, &mut child)?;
        let mut new_root = Node { block: None, data: vec![0u8; 60] };
        ExtentHeader { entries: 1, max: 4, depth: h.depth + 1 }.write(&mut new_root.data);
        ExtentIndex { block: first, leaf: blk }.write(new_root.entry_mut(0));
        self.store(ino, raw, &mut new_root)
    }

    /// Mark the extent containing `lblk` initialized, after zeroing its
    /// blocks on disk (writes into preallocated space).
    pub(crate) fn initialize_extent_at(&mut self, ino: u32, raw: &mut RawInode, lblk: u32) -> Result<()> {
        let mut path = self.path(ino, raw, lblk)?;
        let (leaf, _) = path.last_mut().unwrap();
        let h = leaf.header()?;
        for i in 0..usize::from(h.entries) {
            let mut e = Extent::read(leaf.entry(i));
            if lblk >= e.block && lblk < e.end() && e.uninit {
                let zeros = vec![0u8; self.block_size as usize];
                for b in e.start..e.start + u64::from(e.len) {
                    self.write_data(b, &zeros)?;
                }
                e.uninit = false;
                e.write(leaf.entry_mut(i));
                let mut leaf = path.pop().unwrap().0;
                return self.store(ino, raw, &mut leaf);
            }
        }
        Ok(())
    }

    /// Free every block of the file from logical block `from` on, including
    /// tree nodes that become empty.
    pub(crate) fn truncate_blocks(&mut self, ino: u32, raw: &mut RawInode, from: u32) -> Result<()> {
        if !Self::uses_extents(raw) {
            return self.truncate_indirect(raw, from);
        }
        let mut root = self.load(ino, raw, None)?;
        self.truncate_node(ino, raw, &mut root, from)?;
        let h = root.header()?;
        if h.entries == 0 {
            // An empty tree is a depth-0 root.
            ExtentHeader { entries: 0, max: 4, depth: 0 }.write(&mut root.data);
        }
        self.store(ino, raw, &mut root)
    }

    /// Returns whether `node` is empty afterwards.
    fn truncate_node(&mut self, ino: u32, raw: &mut RawInode, node: &mut Node, from: u32) -> Result<bool> {
        let h = node.header()?;
        let mut n = usize::from(h.entries);
        let mut i = 0;
        while i < n {
            if h.depth == 0 {
                let mut e = Extent::read(node.entry(i));
                if e.block >= from {
                    self.free_blocks(e.start, u64::from(e.len))?;
                    self.add_blocks_count(raw, -i64::from(e.len));
                    node.remove_entry(i, n);
                    n -= 1;
                    continue;
                } else if e.end() > from {
                    let keep = from - e.block;
                    self.free_blocks(e.start + u64::from(keep), u64::from(e.len - keep))?;
                    self.add_blocks_count(raw, -i64::from(e.len - keep));
                    e.len = keep;
                    e.write(node.entry_mut(i));
                }
            } else {
                let ix = ExtentIndex::read(node.entry(i));
                let next_start = if i + 1 < n { ExtentIndex::read(node.entry(i + 1)).block } else { u32::MAX };
                // Children wholly before `from` are untouched.
                if next_start > from {
                    let mut child = self.load(ino, raw, Some(ix.leaf))?;
                    if self.truncate_node(ino, raw, &mut child, from)? {
                        self.free_blocks(ix.leaf, 1)?;
                        self.add_blocks_count(raw, -1);
                        node.remove_entry(i, n);
                        n -= 1;
                        continue;
                    }
                }
            }
            i += 1;
        }
        node.set_entries(n as u16);
        // Block nodes are written here (unless about to be freed); the
        // caller writes the root.
        if node.block.is_some() && n > 0 {
            self.store(ino, raw, node)?;
        }
        Ok(n == 0)
    }

    /// Truncating block-mapped files: only freeing everything is supported
    /// (unlink of an ext2/ext3 file).
    fn truncate_indirect(&mut self, raw: &mut RawInode, from: u32) -> Result<()> {
        if from != 0 {
            return Err(Error::Unsupported("truncating a block-mapped file"));
        }
        let ib: Vec<u32> = (0..15).map(|i| get32(raw.i_block(), i * 4)).collect();
        for (i, &b) in ib.iter().enumerate() {
            if b != 0 {
                let levels = if i < 12 { 0 } else { i as u32 - 11 };
                self.free_indirect(u64::from(b), levels)?;
            }
        }
        raw.i_block_mut().fill(0);
        raw.set_blocks_raw(0);
        Ok(())
    }

    fn free_indirect(&mut self, blk: u64, levels: u32) -> Result<()> {
        if levels > 0 {
            let b = self.read_block(blk)?;
            for i in 0..self.block_size as usize / 4 {
                let c = get32(&b, i * 4);
                if c != 0 {
                    self.free_indirect(u64::from(c), levels - 1)?;
                }
            }
        }
        self.free_blocks(blk, 1)
    }
}
