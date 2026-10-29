// SPDX-License-Identifier: MIT OR Apache-2.0

//! A small cache of metadata blocks. Writes go through to the disk, so
//! entries are never dirty and eviction is free.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;

/// Most blocks kept (4 MiB with 4 KiB blocks).
const CAPACITY: usize = 1024;

#[derive(Debug)]
pub struct Cache {
    blocks: BTreeMap<u64, (Box<[u8]>, u64)>,
    clock: u64,
}

impl Cache {
    pub fn new() -> Cache {
        Cache { blocks: BTreeMap::new(), clock: 0 }
    }

    pub fn get(&mut self, blk: u64) -> Option<&[u8]> {
        self.clock += 1;
        let now = self.clock;
        self.blocks.get_mut(&blk).map(|(b, used)| {
            *used = now;
            &**b
        })
    }

    pub fn insert(&mut self, blk: u64, data: &[u8]) {
        self.clock += 1;
        if let Some((b, used)) = self.blocks.get_mut(&blk) {
            b.copy_from_slice(data);
            *used = self.clock;
            return;
        }
        if self.blocks.len() >= CAPACITY {
            // Evict the least recently used eighth in one pass.
            let mut ages: alloc::vec::Vec<(u64, u64)> = self.blocks.iter().map(|(&k, &(_, u))| (u, k)).collect();
            ages.sort_unstable();
            for &(_, k) in &ages[..CAPACITY / 8] {
                self.blocks.remove(&k);
            }
        }
        self.blocks.insert(blk, (data.into(), self.clock));
    }

    pub fn remove(&mut self, blk: u64) {
        self.blocks.remove(&blk);
    }
}
