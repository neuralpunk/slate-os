// SPDX-License-Identifier: MIT OR Apache-2.0

//! Block and inode allocation through the per-group bitmaps, including
//! groups whose bitmaps were never initialized (BLOCK_UNINIT and
//! INODE_UNINIT, from mkfs's lazy initialization).

use alloc::vec;
use alloc::vec::Vec;

use crate::layout::*;
use crate::{Disk, Error, Fs, Result, crc};

fn bit(map: &[u8], i: usize) -> bool {
    map[i / 8] & (1 << (i % 8)) != 0
}
fn set_bit(map: &mut [u8], i: usize, v: bool) {
    if v {
        map[i / 8] |= 1 << (i % 8);
    } else {
        map[i / 8] &= !(1 << (i % 8));
    }
}

impl<D: Disk> Fs<D> {
    fn first_block_of(&self, g: u32) -> u64 {
        u64::from(self.sb.first_data_block()) + u64::from(g) * u64::from(self.sb.blocks_per_group())
    }

    fn blocks_in_group(&self, g: u32) -> u32 {
        let start = self.first_block_of(g);
        (self.sb.blocks_count() - start).min(u64::from(self.sb.blocks_per_group())) as u32
    }

    /// Whether group `g` holds a superblock backup (sparse_super: groups 0,
    /// 1 and powers of 3, 5 and 7; sparse_super2: the two listed groups).
    pub(crate) fn has_super_backup(&self, g: u32) -> bool {
        if g == 0 {
            return true;
        }
        if self.sb.has_compat(feature::COMPAT_SPARSE_SUPER2) {
            return self.sb.backup_bgs().contains(&g);
        }
        if !self.sb.has_ro_compat(feature::RO_COMPAT_SPARSE_SUPER) || g == 1 {
            return true;
        }
        [3u32, 5, 7].iter().any(|&p| {
            let mut n = p;
            while n < g {
                n = n.saturating_mul(p);
            }
            n == g
        })
    }

    /// The block bitmap of an uninitialized group, computed: the group's own
    /// superblock backup and descriptor blocks, plus any group's bitmaps
    /// and inode tables that live inside it (flex_bg places them anywhere).
    fn synthesize_block_bitmap(&self, g: u32) -> Vec<u8> {
        let mut map = vec![0u8; self.block_size as usize];
        let start = self.first_block_of(g);
        let n = self.blocks_in_group(g) as usize;
        if self.has_super_backup(g) {
            let ds = self.sb.desc_size() as u64;
            let gdt_blocks = (u64::from(self.group_count) * ds).div_ceil(u64::from(self.block_size));
            let meta = 1 + gdt_blocks + u64::from(self.sb.reserved_gdt_blocks());
            for i in 0..meta as usize {
                set_bit(&mut map, i, true);
            }
        }
        let itable_blocks = (u64::from(self.sb.inodes_per_group()) * u64::from(self.sb.inode_size()))
            .div_ceil(u64::from(self.block_size));
        for d in &self.groups {
            let mut mark = |b: u64, count: u64| {
                for x in b..b + count {
                    if x >= start && x < start + n as u64 {
                        set_bit(&mut map, (x - start) as usize, true);
                    }
                }
            };
            mark(d.block_bitmap(), 1);
            mark(d.inode_bitmap(), 1);
            mark(d.inode_table(), itable_blocks);
        }
        // Bits past the end of a short last group are set.
        for i in n..self.block_size as usize * 8 {
            set_bit(&mut map, i, true);
        }
        map
    }

    fn block_bitmap(&mut self, g: u32) -> Result<Vec<u8>> {
        let d = &self.groups[g as usize];
        if d.flags() & BG_BLOCK_UNINIT != 0 {
            return Ok(self.synthesize_block_bitmap(g));
        }
        let b = d.block_bitmap();
        self.read_block(b)
    }

    fn inode_bitmap(&mut self, g: u32) -> Result<Vec<u8>> {
        let d = &self.groups[g as usize];
        if d.flags() & BG_INODE_UNINIT != 0 {
            let mut map = vec![0u8; self.block_size as usize];
            for i in self.sb.inodes_per_group() as usize..self.block_size as usize * 8 {
                set_bit(&mut map, i, true);
            }
            return Ok(map);
        }
        let b = d.inode_bitmap();
        self.read_block(b)
    }

    fn write_block_bitmap(&mut self, g: u32, map: &[u8]) -> Result<()> {
        let blk = self.groups[g as usize].block_bitmap();
        if self.metadata_csum {
            let len = self.sb.clusters_per_group() as usize / 8;
            let c = crc::crc32c(self.csum_seed, &map[..len]);
            let d = &mut self.groups[g as usize];
            d.set_block_bitmap_csum(if d.0.len() >= 64 { c } else { c & 0xFFFF });
        }
        let d = &mut self.groups[g as usize];
        d.set_flags(d.flags() & !BG_BLOCK_UNINIT);
        self.write_block(blk, map)
    }

    fn write_inode_bitmap(&mut self, g: u32, map: &[u8]) -> Result<()> {
        let blk = self.groups[g as usize].inode_bitmap();
        if self.metadata_csum {
            let len = self.sb.inodes_per_group() as usize / 8;
            let c = crc::crc32c(self.csum_seed, &map[..len]);
            let d = &mut self.groups[g as usize];
            d.set_inode_bitmap_csum(if d.0.len() >= 64 { c } else { c & 0xFFFF });
        }
        let d = &mut self.groups[g as usize];
        d.set_flags(d.flags() & !BG_INODE_UNINIT);
        self.write_block(blk, map)
    }

    /// Allocate up to `want` contiguous blocks, near `goal` if possible.
    /// Returns (first block, count >= 1). When the disk is full but the
    /// running transaction freed blocks, it is committed to get them back.
    pub(crate) fn alloc_blocks(&mut self, goal: u64, want: u32) -> Result<(u64, u32)> {
        match self.alloc_blocks_once(goal, want) {
            Err(Error::NoSpace) if !self.txn.deferred.is_empty() && !self.txn.committing => {
                self.commit_txn(true)?;
                self.alloc_blocks_once(goal, want)
            }
            r => r,
        }
    }

    fn alloc_blocks_once(&mut self, goal: u64, want: u32) -> Result<(u64, u32)> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        if self.sb.free_blocks() == 0 {
            return Err(Error::NoSpace);
        }
        let bpg = u64::from(self.sb.blocks_per_group());
        let first = u64::from(self.sb.first_data_block());
        let goal = if goal >= first && goal < self.sb.blocks_count() { goal } else { self.last_alloc.max(first) };
        let goal_group = ((goal - first) / bpg) as u32;
        for i in 0..self.group_count {
            let g = (goal_group + i) % self.group_count;
            if self.groups[g as usize].free_blocks() == 0 {
                continue;
            }
            let mut map = self.block_bitmap(g)?;
            let n = self.blocks_in_group(g) as usize;
            let start_bit = if i == 0 { ((goal - first) % bpg) as usize } else { 0 };
            // First free bit at or after the goal, then wrap within the group.
            let found = (start_bit..n).chain(0..start_bit).find(|&b| !bit(&map, b));
            let Some(b) = found else { continue };
            let mut count = 1u32;
            while count < want && b + (count as usize) < n && !bit(&map, b + count as usize) {
                count += 1;
            }
            for x in b..b + count as usize {
                set_bit(&mut map, x, true);
            }
            self.write_block_bitmap(g, &map)?;
            let d = &mut self.groups[g as usize];
            d.set_free_blocks(d.free_blocks() - count);
            self.write_group(g)?;
            let fb = self.sb.free_blocks();
            self.sb.set_free_blocks(fb - u64::from(count));
            self.write_superblock()?;
            let blk = self.first_block_of(g) + b as u64;
            self.last_alloc = blk + u64::from(count);
            return Ok((blk, count));
        }
        Err(Error::NoSpace)
    }

    /// Free `count` blocks starting at `blk` (all in one group or spanning
    /// groups). With a journal they are freed by the next commit: until
    /// then a crash could bring back the state that uses them, so nothing
    /// may reuse them; their contents no longer matter and are not logged.
    pub(crate) fn free_blocks(&mut self, blk: u64, count: u64) -> Result<()> {
        if self.journal.is_none() {
            return self.free_blocks_now(blk, count);
        }
        if blk < u64::from(self.sb.first_data_block()) || blk.saturating_add(count) > self.sb.blocks_count() {
            return Err(Error::Corrupt("freeing a block out of range"));
        }
        for b in blk..blk + count {
            self.txn.blocks.remove(&b);
            self.cache.remove(b);
        }
        self.txn.deferred.push((blk, count));
        Ok(())
    }

    /// Free blocks at once (see [`Fs::free_blocks`]). With online discard
    /// they are discarded once that is durable: after the commit, or at once
    /// without a journal.
    pub(crate) fn free_blocks_now(&mut self, blk: u64, count: u64) -> Result<()> {
        self.free_blocks_inner(blk, count)?;
        if self.discard {
            self.to_discard.push((blk, count));
            if self.journal.is_none() {
                self.issue_discards();
            }
        }
        Ok(())
    }

    /// Free runs of blocks in `[first, end)`: (first block, count).
    pub(crate) fn free_runs(&mut self, first: u64, end: u64) -> Result<Vec<(u64, u64)>> {
        let mut runs: Vec<(u64, u64)> = Vec::new();
        let bpg = u64::from(self.sb.blocks_per_group());
        let base = u64::from(self.sb.first_data_block());
        if first >= end {
            return Ok(runs);
        }
        for g in ((first - base) / bpg) as u32..=((end - 1 - base) / bpg) as u32 {
            if g >= self.group_count || self.groups[g as usize].free_blocks() == 0 {
                continue;
            }
            let map = self.block_bitmap(g)?;
            let g0 = self.first_block_of(g);
            for i in 0..self.blocks_in_group(g) as usize {
                let b = g0 + i as u64;
                if b < first || b >= end || bit(&map, i) {
                    continue;
                }
                match runs.last_mut() {
                    Some((s, n)) if *s + *n == b => *n += 1,
                    _ => runs.push((b, 1)),
                }
            }
        }
        Ok(runs)
    }

    fn free_blocks_inner(&mut self, blk: u64, count: u64) -> Result<()> {
        let bpg = u64::from(self.sb.blocks_per_group());
        let first = u64::from(self.sb.first_data_block());
        let mut b = blk;
        let end = blk + count;
        while b < end {
            if b < first || b >= self.sb.blocks_count() {
                return Err(Error::Corrupt("freeing a block out of range"));
            }
            let g = ((b - first) / bpg) as u32;
            let group_end = (self.first_block_of(g) + bpg).min(end);
            let mut map = self.block_bitmap(g)?;
            let mut freed = 0;
            for x in b..group_end {
                let i = (x - self.first_block_of(g)) as usize;
                if bit(&map, i) {
                    set_bit(&mut map, i, false);
                    freed += 1;
                }
                self.cache.remove(x);
            }
            self.write_block_bitmap(g, &map)?;
            let d = &mut self.groups[g as usize];
            d.set_free_blocks(d.free_blocks() + freed);
            self.write_group(g)?;
            let fb = self.sb.free_blocks();
            self.sb.set_free_blocks(fb + u64::from(freed));
            b = group_end;
        }
        self.write_superblock()
    }

    /// Allocate an inode, preferring `near_group` (or, for directories, the
    /// group with the most free inodes, to spread directories out).
    pub(crate) fn alloc_inode(&mut self, near_group: u32, dir: bool) -> Result<u32> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        if self.sb.free_inodes() == 0 {
            return Err(Error::NoSpace);
        }
        let start = if dir {
            (0..self.group_count).max_by_key(|&g| self.groups[g as usize].free_inodes()).unwrap_or(0)
        } else {
            near_group.min(self.group_count - 1)
        };
        let ipg = self.sb.inodes_per_group();
        for i in 0..self.group_count {
            let g = (start + i) % self.group_count;
            if self.groups[g as usize].free_inodes() == 0 {
                continue;
            }
            let was_uninit = self.groups[g as usize].flags() & BG_INODE_UNINIT != 0;
            let mut map = self.inode_bitmap(g)?;
            let first_ok = if g == 0 { self.sb.first_ino() as usize - 1 } else { 0 };
            let Some(idx) = (first_ok..ipg as usize).find(|&b| !bit(&map, b)) else { continue };
            set_bit(&mut map, idx, true);
            self.write_inode_bitmap(g, &map)?;
            let d = &mut self.groups[g as usize];
            d.set_free_inodes(d.free_inodes() - 1);
            if dir {
                d.set_used_dirs(d.used_dirs() + 1);
            }
            if self.metadata_csum || self.gdt_csum {
                // Inodes past the high-water mark are never read by fsck.
                let unused = if was_uninit { ipg } else { d.itable_unused() };
                let used_upto = ipg - unused;
                if idx as u32 >= used_upto {
                    d.set_itable_unused(ipg - idx as u32 - 1);
                }
            }
            self.write_group(g)?;
            let fi = self.sb.free_inodes();
            self.sb.set_free_inodes(fi - 1);
            self.write_superblock()?;
            return Ok(g * ipg + idx as u32 + 1);
        }
        Err(Error::NoSpace)
    }

    pub(crate) fn free_inode(&mut self, ino: u32, dir: bool) -> Result<()> {
        let ipg = self.sb.inodes_per_group();
        let g = (ino - 1) / ipg;
        let idx = ((ino - 1) % ipg) as usize;
        let mut map = self.inode_bitmap(g)?;
        if !bit(&map, idx) {
            return Err(Error::Corrupt("freeing a free inode"));
        }
        set_bit(&mut map, idx, false);
        self.write_inode_bitmap(g, &map)?;
        let d = &mut self.groups[g as usize];
        d.set_free_inodes(d.free_inodes() + 1);
        if dir {
            d.set_used_dirs(d.used_dirs().saturating_sub(1));
        }
        self.write_group(g)?;
        let fi = self.sb.free_inodes();
        self.sb.set_free_inodes(fi + 1);
        self.write_superblock()
    }

    /// Whether inode `ino` is allocated in its group's bitmap.
    pub(crate) fn inode_in_use(&mut self, ino: u32) -> Result<bool> {
        if ino == 0 || ino > self.sb.inodes_count() {
            return Err(Error::Corrupt("inode number out of range"));
        }
        let ipg = self.sb.inodes_per_group();
        let g = (ino - 1) / ipg;
        if self.groups[g as usize].flags() & BG_INODE_UNINIT != 0 {
            return Ok(false);
        }
        let map = self.inode_bitmap(g)?;
        Ok(bit(&map, ((ino - 1) % ipg) as usize))
    }

    pub(crate) fn group_of_inode(&self, ino: u32) -> u32 {
        (ino - 1) / self.sb.inodes_per_group()
    }

    /// First block of the group holding `ino`'s inode (a data placement goal).
    pub(crate) fn goal_for_inode(&self, ino: u32) -> u64 {
        self.first_block_of(self.group_of_inode(ino))
    }
}
