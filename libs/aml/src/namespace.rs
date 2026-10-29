// SPDX-License-Identifier: MIT OR Apache-2.0

//! The namespace (§5.3): a tree of named objects, kept in an arena.

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::name::{NameSeg, Path, seg_text};
use crate::value::Value;
use crate::{Error, Result, Space};

/// A node's index in the namespace.
pub type NodeId = usize;
/// The root, `\`.
pub const ROOT: NodeId = 0;

/// A method: where its body is and how it is called (§19.6.85).
#[derive(Clone, Debug)]
pub struct Method {
    pub table: usize,
    pub start: usize,
    pub end: usize,
    pub args: u8,
    pub serialized: bool,
}

/// An operation region (§19.6.100). Offset and length were evaluated
/// when it was declared, as the spec says.
#[derive(Clone, Debug)]
pub struct Region {
    pub space: Space,
    pub offset: u64,
    pub len: u64,
}

/// What a field's bits live in.
#[derive(Clone, Debug)]
pub enum FieldKind {
    /// A field of an operation region (§19.6.48).
    Region(NodeId),
    /// IndexField (§19.6.64): the byte offset goes to `index`, the data
    /// comes through `data` (both fields).
    Index { index: NodeId, data: NodeId },
    /// BankField (§19.6.7): `value` is written to the `bank` field first.
    Bank { region: NodeId, bank: NodeId, value: u64 },
}

/// A field unit: bits of a region (or of an index or bank field pair).
#[derive(Clone, Debug)]
pub struct Field {
    pub kind: FieldKind,
    pub bit_offset: u64,
    pub bit_len: u64,
    /// AccessType (§19.6.48): 0 any, 1 byte, 2 word, 3 dword, 4 qword,
    /// 5 buffer.
    pub access: u8,
    /// UpdateRule: 0 preserve, 1 write as ones, 2 write as zeros.
    pub update: u8,
}

#[derive(Clone, Debug)]
pub enum Object {
    /// A scope with no object of its own (the root, `\_SB`...).
    Scope,
    Device,
    Processor {
        id: u8,
        pblk: u32,
        pblk_len: u8,
    },
    PowerResource {
        level: u8,
        order: u16,
    },
    ThermalZone,
    Method(Method),
    /// Name(...) and the objects data is stored in.
    Data(Value),
    Region(Region),
    Field(Field),
    /// CreateXField (§19.6.18): bits of a buffer.
    BufferField {
        buffer: Rc<RefCell<Vec<u8>>>,
        bit_offset: u64,
        bit_len: u64,
    },
    Mutex {
        sync: u8,
    },
    Event {
        count: u64,
    },
    Alias(NodeId),
    /// Declared by External, not (yet) defined.
    External {
        kind: u8,
        args: u8,
    },
    /// `\_OSI`, answered by the interpreter (ADR 0079).
    Osi,
}

impl Object {
    /// ObjectType's number (§19.6.97).
    pub fn type_number(&self) -> u64 {
        match self {
            Object::Scope | Object::External { .. } | Object::Alias(_) => 0,
            Object::Data(v) => v.type_number(),
            Object::Field(_) => 5,
            Object::Device => 6,
            Object::Event { .. } => 7,
            Object::Method(_) | Object::Osi => 8,
            Object::Mutex { .. } => 9,
            Object::Region(_) => 10,
            Object::PowerResource { .. } => 11,
            Object::Processor { .. } => 12,
            Object::ThermalZone => 13,
            Object::BufferField { .. } => 14,
        }
    }

    /// Whether it opens a scope that can hold names.
    pub fn is_scope(&self) -> bool {
        matches!(
            self,
            Object::Scope
                | Object::Device
                | Object::Processor { .. }
                | Object::PowerResource { .. }
                | Object::ThermalZone
                | Object::Method(_)
                | Object::External { .. }
        )
    }
}

#[derive(Debug)]
pub struct Node {
    pub seg: NameSeg,
    pub parent: NodeId,
    pub children: BTreeMap<NameSeg, NodeId>,
    pub object: Object,
    /// Taken out of the namespace (a method's temporary object after it
    /// returned); its slot is not reused, so stale ids stay harmless.
    pub gone: bool,
}

#[derive(Debug)]
pub struct Namespace {
    pub nodes: Vec<Node>,
}

impl Namespace {
    pub fn new() -> Namespace {
        Namespace {
            nodes: alloc::vec![Node {
                seg: *b"\\___",
                parent: ROOT,
                children: BTreeMap::new(),
                object: Object::Scope,
                gone: false,
            }],
        }
    }

    pub fn get(&self, id: NodeId) -> &Node {
        &self.nodes[id]
    }

    pub fn child(&self, scope: NodeId, seg: &NameSeg) -> Option<NodeId> {
        self.nodes[scope].children.get(seg).copied().filter(|&c| !self.nodes[c].gone)
    }

    /// Add `seg` under `parent`. An External placeholder is replaced by
    /// the real object; anything else already there is an error.
    pub fn add(&mut self, parent: NodeId, seg: NameSeg, object: Object) -> Result<NodeId> {
        if let Some(existing) = self.child(parent, &seg) {
            if matches!(self.nodes[existing].object, Object::External { .. }) {
                self.nodes[existing].object = object;
                return Ok(existing);
            }
            if matches!(object, Object::External { .. }) {
                return Ok(existing);
            }
            return Err(Error::Exists(self.path_of(existing)));
        }
        let id = self.nodes.len();
        self.nodes.push(Node { seg, parent, children: BTreeMap::new(), object, gone: false });
        self.nodes[parent].children.insert(seg, id);
        Ok(id)
    }

    /// Take `id` (and what is under it) out of the namespace.
    pub fn remove(&mut self, id: NodeId) {
        let parent = self.nodes[id].parent;
        let seg = self.nodes[id].seg;
        if self.nodes[parent].children.get(&seg) == Some(&id) {
            self.nodes[parent].children.remove(&seg);
        }
        let mut todo = alloc::vec![id];
        while let Some(n) = todo.pop() {
            self.nodes[n].gone = true;
            todo.extend(self.nodes[n].children.values().copied());
        }
    }

    /// The scope a path's last segment goes in, and that segment (for
    /// declarations: `Name(\_SB.FOO, ...)` adds FOO under \_SB).
    pub fn parent_for(&self, scope: NodeId, path: &Path) -> Result<(NodeId, NameSeg)> {
        let last = *path.segs.last().ok_or(Error::BadType("empty name"))?;
        let mut at = self.start(scope, path);
        for seg in &path.segs[..path.segs.len() - 1] {
            at = self.child(at, seg).ok_or_else(|| Error::NotFound(alloc::format!("{path}")))?;
        }
        Ok((at, last))
    }

    fn start(&self, scope: NodeId, path: &Path) -> NodeId {
        if path.root {
            return ROOT;
        }
        let mut at = scope;
        for _ in 0..path.up {
            at = self.nodes[at].parent;
        }
        at
    }

    /// Find an existing object (§5.3: a single segment with no prefix is
    /// looked for in the scope and then each enclosing one; anything
    /// else is followed from where it starts).
    pub fn resolve(&self, scope: NodeId, path: &Path) -> Option<NodeId> {
        if path.segs.is_empty() {
            return Some(self.start(scope, path));
        }
        if path.is_single() {
            let mut at = scope;
            loop {
                if let Some(c) = self.child(at, &path.segs[0]) {
                    return Some(c);
                }
                if at == ROOT {
                    return None;
                }
                at = self.nodes[at].parent;
            }
        }
        let mut at = self.start(scope, path);
        for seg in &path.segs {
            at = self.child(at, seg)?;
        }
        Some(at)
    }

    /// A node's full path, `\_SB.PCI0.LPC0`.
    pub fn path_of(&self, id: NodeId) -> String {
        if id == ROOT {
            return String::from("\\");
        }
        let mut segs = Vec::new();
        let mut at = id;
        while at != ROOT {
            segs.push(seg_text(&self.nodes[at].seg));
            at = self.nodes[at].parent;
        }
        segs.reverse();
        alloc::format!("\\{}", segs.join("."))
    }
}
