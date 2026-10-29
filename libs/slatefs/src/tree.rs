// SPDX-License-Identifier: MIT OR Apache-2.0

//! The copy-on-write B+tree (ADR 0026). Nodes on disk are immutable; a
//! change copies the nodes on its path into memory (`Child::Mem`), so a
//! subtree shared with a snapshot is never modified. A commit writes the
//! dirty nodes bottom-up to new blocks.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::layout::{BLOCK, BlockPtr, KEY_LEN, Key, PTR_LEN, get_u16, get_u64, put_u16, put_u64};
use crate::{Error, Result};

const NODE_MAGIC: &[u8; 4] = b"SNOD";
const HEADER: usize = 24;
const LEAF_ITEM: usize = KEY_LEN + 4;
const INTERNAL_ITEM: usize = KEY_LEN + PTR_LEN;
/// Children per internal node.
pub const MAX_CHILDREN: usize = (BLOCK - HEADER) / INTERNAL_ITEM;
/// Largest value a leaf item may hold (two always fit in a leaf).
pub const MAX_VALUE: usize = 1800;

/// A link to a node: on disk, or a modified copy in memory.
#[derive(Clone, Debug)]
pub enum Child {
    Disk(BlockPtr),
    Mem(Box<Node>),
}

#[derive(Clone, Debug)]
pub struct Node {
    pub level: u8,
    pub body: Body,
}

#[derive(Clone, Debug)]
pub enum Body {
    Leaf(Vec<(Key, Vec<u8>)>),
    /// Each child with the smallest key it held when it was linked (the
    /// first child's key acts as minus infinity).
    Internal(Vec<(Key, Child)>),
}

/// Reads nodes from disk (through a cache), checking them against their
/// pointers.
pub trait Load {
    fn load(&mut self, ptr: &BlockPtr) -> Result<Node>;

    /// The node at `ptr`, loaded as `node`, is no longer linked from where
    /// it was: it was copied to be changed, or merged into its sibling
    /// (free space is kept from this, ADR 0026's addendum).
    fn dropped(&mut self, _ptr: &BlockPtr, _node: &Node) {}
}

impl Node {
    pub fn empty_leaf() -> Node {
        Node { level: 0, body: Body::Leaf(Vec::new()) }
    }

    fn leaf_size(items: &[(Key, Vec<u8>)]) -> usize {
        HEADER + items.iter().map(|(_, v)| LEAF_ITEM + v.len()).sum::<usize>()
    }

    /// Encode a node whose children are all on disk.
    pub fn encode(&self, generation: u64, owner: u64) -> Result<Vec<u8>> {
        let mut b = alloc::vec![0u8; BLOCK];
        b[..4].copy_from_slice(NODE_MAGIC);
        b[4] = self.level;
        put_u64(&mut b, 8, generation);
        put_u64(&mut b, 16, owner);
        match &self.body {
            Body::Leaf(items) => {
                if Self::leaf_size(items) > BLOCK {
                    return Err(Error::Corrupt("leaf overflow"));
                }
                put_u16(&mut b, 6, items.len() as u16);
                let mut end = BLOCK;
                for (i, (k, v)) in items.iter().enumerate() {
                    end -= v.len();
                    b[end..end + v.len()].copy_from_slice(v);
                    let at = HEADER + i * LEAF_ITEM;
                    k.encode(&mut b[at..]);
                    put_u16(&mut b, at + KEY_LEN, end as u16);
                    put_u16(&mut b, at + KEY_LEN + 2, v.len() as u16);
                }
            }
            Body::Internal(children) => {
                put_u16(&mut b, 6, children.len() as u16);
                for (i, (k, c)) in children.iter().enumerate() {
                    let Child::Disk(p) = c else { return Err(Error::Corrupt("encoding a node with dirty children")) };
                    let at = HEADER + i * INTERNAL_ITEM;
                    k.encode(&mut b[at..]);
                    p.encode(&mut b[at + KEY_LEN..]);
                }
            }
        }
        Ok(b)
    }

    /// Decode a node read for `ptr`: the checksum and generation must match.
    pub fn decode(b: &[u8], ptr: &BlockPtr) -> Result<Node> {
        if b.len() != BLOCK || &b[..4] != NODE_MAGIC {
            return Err(Error::Corrupt("not a tree node"));
        }
        if slate_hash::crc32c(b) != ptr.crc || get_u64(b, 8) != ptr.generation {
            return Err(Error::Checksum(ptr.block));
        }
        let level = b[4];
        let n = usize::from(get_u16(b, 6));
        let body = if level == 0 {
            if HEADER + n * LEAF_ITEM > BLOCK {
                return Err(Error::Corrupt("leaf item count"));
            }
            let mut items = Vec::with_capacity(n);
            for i in 0..n {
                let at = HEADER + i * LEAF_ITEM;
                let k = Key::decode(&b[at..]);
                let (off, len) = (usize::from(get_u16(b, at + KEY_LEN)), usize::from(get_u16(b, at + KEY_LEN + 2)));
                if off < HEADER + n * LEAF_ITEM || off + len > BLOCK {
                    return Err(Error::Corrupt("leaf value bounds"));
                }
                items.push((k, b[off..off + len].to_vec()));
            }
            Body::Leaf(items)
        } else {
            if n == 0 || n > MAX_CHILDREN {
                return Err(Error::Corrupt("internal node child count"));
            }
            let children = (0..n)
                .map(|i| {
                    let at = HEADER + i * INTERNAL_ITEM;
                    (Key::decode(&b[at..]), Child::Disk(BlockPtr::decode(&b[at + KEY_LEN..])))
                })
                .collect();
            Body::Internal(children)
        };
        let node = Node { level, body };
        if !node.sorted() {
            return Err(Error::Corrupt("keys out of order"));
        }
        Ok(node)
    }

    fn sorted(&self) -> bool {
        match &self.body {
            Body::Leaf(items) => items.windows(2).all(|w| w[0].0 < w[1].0),
            Body::Internal(c) => c.windows(2).all(|w| w[0].0 < w[1].0),
        }
    }

    /// Index of the child whose subtree would hold `key`.
    fn child_for(children: &[(Key, Child)], key: &Key) -> usize {
        children.partition_point(|(k, _)| k <= key).saturating_sub(1)
    }
}

/// The node behind a child: borrowed when in memory, loaded otherwise.
enum View<'a> {
    Mem(&'a Node),
    Owned(Node),
}

impl View<'_> {
    fn node(&self) -> &Node {
        match self {
            View::Mem(n) => n,
            View::Owned(n) => n,
        }
    }
}

fn view<'a>(c: &'a Child, s: &mut dyn Load) -> Result<View<'a>> {
    match c {
        Child::Mem(n) => Ok(View::Mem(n)),
        Child::Disk(p) => Ok(View::Owned(s.load(p)?)),
    }
}

/// The value at `key`.
pub fn get(root: &Child, key: &Key, s: &mut dyn Load) -> Result<Option<Vec<u8>>> {
    let v = view(root, s)?;
    match &v.node().body {
        Body::Leaf(items) => Ok(items.binary_search_by(|(k, _)| k.cmp(key)).ok().map(|i| items[i].1.clone())),
        Body::Internal(c) => get(&c[Node::child_for(c, key)].1, key, s),
    }
}

/// The smallest item with a key >= `key`.
pub fn ceil(root: &Child, key: &Key, s: &mut dyn Load) -> Result<Option<(Key, Vec<u8>)>> {
    let v = view(root, s)?;
    match &v.node().body {
        Body::Leaf(items) => {
            let i = items.partition_point(|(k, _)| k < key);
            Ok(items.get(i).cloned())
        }
        Body::Internal(c) => {
            for (_, ch) in c.iter().skip(Node::child_for(c, key)) {
                if let Some(r) = ceil(ch, key, s)? {
                    return Ok(Some(r));
                }
            }
            Ok(None)
        }
    }
}

/// The largest item with a key <= `key`.
pub fn floor(root: &Child, key: &Key, s: &mut dyn Load) -> Result<Option<(Key, Vec<u8>)>> {
    let v = view(root, s)?;
    match &v.node().body {
        Body::Leaf(items) => {
            let i = items.partition_point(|(k, _)| k <= key);
            Ok(if i == 0 { None } else { Some(items[i - 1].clone()) })
        }
        Body::Internal(c) => {
            for i in (0..=Node::child_for(c, key)).rev() {
                if let Some(r) = floor(&c[i].1, key, s)? {
                    return Ok(Some(r));
                }
            }
            Ok(None)
        }
    }
}

/// Make `c` a modifiable in-memory copy and return it.
fn make_mut<'a>(c: &'a mut Child, s: &mut dyn Load) -> Result<&'a mut Node> {
    if let Child::Disk(p) = c {
        let n = s.load(p)?;
        s.dropped(p, &n);
        *c = Child::Mem(Box::new(n));
    }
    match c {
        Child::Mem(n) => Ok(n),
        Child::Disk(_) => unreachable!(),
    }
}

/// Insert or replace `key`.
pub fn insert(root: &mut Child, key: Key, value: Vec<u8>, s: &mut dyn Load) -> Result<()> {
    if value.len() > MAX_VALUE {
        return Err(Error::TooBig);
    }
    if let Some((sep, right)) = insert_in(root, key, value, s)? {
        let left = core::mem::replace(root, Child::Mem(Box::new(Node::empty_leaf())));
        let level = view(&left, s)?.node().level + 1;
        let first = first_key(&left, s)?;
        *root = Child::Mem(Box::new(Node { level, body: Body::Internal(alloc::vec![(first, left), (sep, right)]) }));
    }
    Ok(())
}

fn first_key(c: &Child, s: &mut dyn Load) -> Result<Key> {
    let v = view(c, s)?;
    Ok(match &v.node().body {
        Body::Leaf(items) => items.first().map(|(k, _)| *k).unwrap_or_default(),
        Body::Internal(ch) => ch[0].0,
    })
}

/// Returns a new right sibling (with its first key) if the node split.
fn insert_in(c: &mut Child, key: Key, value: Vec<u8>, s: &mut dyn Load) -> Result<Option<(Key, Child)>> {
    let node = make_mut(c, s)?;
    let level = node.level;
    match &mut node.body {
        Body::Leaf(items) => {
            match items.binary_search_by(|(k, _)| k.cmp(&key)) {
                Ok(i) => items[i].1 = value,
                Err(i) => items.insert(i, (key, value)),
            }
            if Node::leaf_size(items) <= BLOCK {
                return Ok(None);
            }
            // Split by size.
            let total = Node::leaf_size(items) - HEADER;
            let mut acc = 0;
            let mut at = 0;
            while at < items.len() - 1 && acc + LEAF_ITEM + items[at].1.len() <= total / 2 {
                acc += LEAF_ITEM + items[at].1.len();
                at += 1;
            }
            let at = at.max(1);
            let right: Vec<(Key, Vec<u8>)> = items.split_off(at);
            let sep = right[0].0;
            Ok(Some((sep, Child::Mem(Box::new(Node { level, body: Body::Leaf(right) })))))
        }
        Body::Internal(children) => {
            let i = Node::child_for(children, &key);
            if key < children[i].0 {
                children[i].0 = key;
            }
            if let Some((sep, right)) = insert_in(&mut children[i].1, key, value, s)? {
                children.insert(i + 1, (sep, right));
            }
            if children.len() <= MAX_CHILDREN {
                return Ok(None);
            }
            let right = children.split_off(children.len() / 2);
            let sep = right[0].0;
            Ok(Some((sep, Child::Mem(Box::new(Node { level, body: Body::Internal(right) })))))
        }
    }
}

/// Remove `key`; returns whether it was there.
pub fn delete(root: &mut Child, key: &Key, s: &mut dyn Load) -> Result<bool> {
    let found = delete_in(root, key, s)?;
    // An internal root with one child gives way to it.
    loop {
        let node = make_mut(root, s)?;
        match &mut node.body {
            Body::Internal(c) if c.len() == 1 => {
                let only = c.pop().unwrap().1;
                *root = only;
            }
            Body::Internal(c) if c.is_empty() => {
                *root = Child::Mem(Box::new(Node::empty_leaf()));
            }
            _ => break,
        }
    }
    Ok(found)
}

fn is_empty(c: &Child, s: &mut dyn Load) -> Result<bool> {
    let v = view(c, s)?;
    Ok(match &v.node().body {
        Body::Leaf(i) => i.is_empty(),
        Body::Internal(c) => c.is_empty(),
    })
}

fn delete_in(c: &mut Child, key: &Key, s: &mut dyn Load) -> Result<bool> {
    // Look before copying: a miss must not dirty the path.
    if get(c, key, s)?.is_none() {
        return Ok(false);
    }
    let node = make_mut(c, s)?;
    match &mut node.body {
        Body::Leaf(items) => {
            let i = items.binary_search_by(|(k, _)| k.cmp(key)).map_err(|_| Error::Corrupt("vanished key"))?;
            items.remove(i);
            Ok(true)
        }
        Body::Internal(children) => {
            let i = Node::child_for(children, key);
            let found = delete_in(&mut children[i].1, key, s)?;
            if is_empty(&children[i].1, s)? {
                children.remove(i);
            } else {
                merge_small(children, i, s)?;
            }
            Ok(found)
        }
    }
}

/// Merge child `i` into a neighbour when both fit in one node, so trees
/// shrink as they empty.
fn merge_small(children: &mut Vec<(Key, Child)>, i: usize, s: &mut dyn Load) -> Result<()> {
    if children.len() < 2 {
        return Ok(());
    }
    let (l, r) = if i + 1 < children.len() { (i, i + 1) } else { (i - 1, i) };
    let fits = {
        let (lv, rv) = (view(&children[l].1, s)?, view(&children[r].1, s)?);
        match (&lv.node().body, &rv.node().body) {
            (Body::Leaf(a), Body::Leaf(b)) => Node::leaf_size(a) + Node::leaf_size(b) - HEADER <= BLOCK * 3 / 4,
            (Body::Internal(a), Body::Internal(b)) => a.len() + b.len() <= MAX_CHILDREN * 3 / 4,
            _ => false,
        }
    };
    if !fits {
        return Ok(());
    }
    let (_, right) = children.remove(r);
    let right = match right {
        Child::Mem(n) => *n,
        Child::Disk(p) => {
            let n = s.load(&p)?;
            s.dropped(&p, &n);
            n
        }
    };
    let left = make_mut(&mut children[l].1, s)?;
    match (&mut left.body, right.body) {
        (Body::Leaf(a), Body::Leaf(b)) => a.extend(b),
        (Body::Internal(a), Body::Internal(b)) => a.extend(b),
        _ => unreachable!(),
    }
    Ok(())
}

/// Write the dirty nodes under `c` bottom-up; `c` becomes a disk pointer.
pub fn flush(
    c: &mut Child,
    generation: u64,
    owner: u64,
    write: &mut dyn FnMut(&[u8]) -> Result<u64>,
    cache: &mut dyn FnMut(u64, Node),
) -> Result<BlockPtr> {
    let Child::Mem(node) = c else {
        let Child::Disk(p) = c else { unreachable!() };
        return Ok(*p);
    };
    if let Body::Internal(children) = &mut node.body {
        for (_, ch) in children.iter_mut() {
            flush(ch, generation, owner, write, cache)?;
        }
    }
    let bytes = node.encode(generation, owner)?;
    let block = write(&bytes)?;
    let ptr = BlockPtr { block, generation, crc: slate_hash::crc32c(&bytes) };
    let Child::Mem(node) = core::mem::replace(c, Child::Disk(ptr)) else { unreachable!() };
    cache(block, *node);
    Ok(ptr)
}

/// Every item in key order (for walks and checks).
pub fn for_each(c: &Child, s: &mut dyn Load, f: &mut dyn FnMut(&Key, &[u8]) -> Result<()>) -> Result<()> {
    let v = view(c, s)?;
    match &v.node().body {
        Body::Leaf(items) => {
            for (k, val) in items {
                f(k, val)?;
            }
        }
        Body::Internal(children) => {
            for (_, ch) in children {
                for_each(ch, s, f)?;
            }
        }
    }
    Ok(())
}
