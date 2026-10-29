// SPDX-License-Identifier: MIT OR Apache-2.0

//! Running AML (§20.2.5): term lists, named objects, the type 1
//! (statements) and type 2 (expressions) opcodes, fields over operation
//! regions, and method calls.

use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::name::{self, Path, starts_name};
use crate::namespace::{Field, FieldKind, Method, Namespace, NodeId, Object, ROOT, Region};
use crate::value::{self, Value};
use crate::{Address, Error, Host, Result, Space};

/// How deep method calls may nest, and how often a While may loop.
const MAX_DEPTH: usize = 48;
const MAX_LOOPS: u64 = 4_000_000;

/// A term that could not be run while loading: the table (in load
/// order), the offset of the term, and the scope it was in.
#[derive(Clone, Debug)]
pub struct Problem {
    pub table: usize,
    pub offset: usize,
    pub scope: String,
    pub error: Error,
}

#[derive(Debug)]
struct Table {
    bytes: Rc<[u8]>,
    /// Revision 2 and later have 64-bit integers (§19.6.30).
    wide: bool,
}

/// A position in a table's bytes.
struct Cur {
    table: usize,
    b: Rc<[u8]>,
    pos: usize,
    end: usize,
    wide: bool,
}

impl Cur {
    fn byte(&mut self) -> Result<u8> {
        if self.pos >= self.end {
            return Err(Error::Truncated);
        }
        let v = *self.b.get(self.pos).ok_or(Error::Truncated)?;
        self.pos += 1;
        Ok(v)
    }

    fn peek(&self) -> Result<u8> {
        if self.pos >= self.end {
            return Err(Error::Truncated);
        }
        self.b.get(self.pos).copied().ok_or(Error::Truncated)
    }

    fn peek_at(&self, n: usize) -> Option<u8> {
        if self.pos + n >= self.end { None } else { self.b.get(self.pos + n).copied() }
    }

    fn le(&mut self, n: usize) -> Result<u64> {
        let mut v = 0u64;
        for i in 0..n {
            v |= u64::from(self.byte()?) << (8 * i);
        }
        Ok(v)
    }

    /// A PkgLength: the end of the package it starts.
    fn pkg(&mut self) -> Result<usize> {
        let start = self.pos;
        let len = name::pkg_length(&self.b, &mut self.pos)?;
        let end = start + len;
        if end > self.end || len == 0 {
            return Err(Error::Truncated);
        }
        Ok(end)
    }

    fn name(&mut self) -> Result<Path> {
        name::parse(&self.b, &mut self.pos, self.end)
    }

    fn mask(&self) -> u64 {
        if self.wide { u64::MAX } else { 0xFFFF_FFFF }
    }

    fn width(&self) -> usize {
        if self.wide { 8 } else { 4 }
    }
}

/// A method's (or a table load's) state.
struct Frame {
    args: [Value; 7],
    locals: [Value; 8],
    scope: NodeId,
    /// Objects a method created, removed when it returns.
    created: Vec<NodeId>,
    in_method: bool,
}

impl Frame {
    fn new(scope: NodeId, in_method: bool) -> Frame {
        Frame { args: Default::default(), locals: Default::default(), scope, created: Vec::new(), in_method }
    }
}

enum Flow {
    Normal,
    Return(Value),
    Break,
    Continue,
}

/// Where a Store goes.
enum Target {
    None,
    Local(usize),
    Arg(usize),
    Debug,
    Node(NodeId),
    Element(Rc<RefCell<Vec<Value>>>, usize),
    Byte(Rc<RefCell<Vec<u8>>>, usize),
}

/// The interpreter: a namespace, the tables loaded into it, and a host.
#[derive(Debug)]
pub struct Interpreter<H: Host> {
    pub host: H,
    ns: Namespace,
    tables: Vec<Table>,
    problems: Vec<Problem>,
    depth: usize,
    loading: bool,
    /// Where the last failed evaluation failed: each method it unwound
    /// through, innermost first, with the offset reached in its body.
    trace: Vec<(String, usize)>,
}

/// What `\_OSI` answers true for (ADR 0079): the feature strings of ACPI
/// 6.5 §5.7.2 and the Windows versions Microsoft documents for _OSI.
const OSI: &[&str] = &[
    "Module Device",
    "Processor Device",
    "3.0 Thermal Model",
    "3.0 _SCP Extensions",
    "Processor Aggregator Device",
    "Extended Address Space Descriptor",
    "Windows 2000",
    "Windows 2001",
    "Windows 2001 SP1",
    "Windows 2001.1",
    "Windows 2001 SP2",
    "Windows 2001.1 SP1",
    "Windows 2006",
    "Windows 2006.1",
    "Windows 2006 SP1",
    "Windows 2006 SP2",
    "Windows 2009",
    "Windows 2012",
    "Windows 2013",
    "Windows 2015",
    "Windows 2016",
    "Windows 2017",
    "Windows 2017.2",
    "Windows 2018",
    "Windows 2018.2",
    "Windows 2019",
    "Windows 2020",
    "Windows 2021",
    "Windows 2022",
];

impl<H: Host> Interpreter<H> {
    /// An interpreter with the predefined namespace (§5.3.1): the root
    /// scopes, `\_OSI`, `\_OS`, `\_REV` and `\_GL`.
    pub fn new(host: H) -> Interpreter<H> {
        let mut ns = Namespace::new();
        for seg in [b"_GPE", b"_PR_", b"_SB_", b"_SI_", b"_TZ_"] {
            let _ = ns.add(ROOT, *seg, Object::Scope);
        }
        let _ = ns.add(ROOT, *b"_OSI", Object::Osi);
        let _ = ns.add(ROOT, *b"_OS_", Object::Data(Value::string(b"Microsoft Windows NT")));
        let _ = ns.add(ROOT, *b"_REV", Object::Data(Value::Integer(2)));
        let _ = ns.add(ROOT, *b"_GL_", Object::Mutex { sync: 0 });
        Interpreter { host, ns, tables: Vec::new(), problems: Vec::new(), depth: 0, loading: false, trace: Vec::new() }
    }

    /// Load a definition block: the DSDT or an SSDT, header included
    /// (§5.2.11). Terms that fail are recorded in [`problems`].
    ///
    /// [`problems`]: Interpreter::problems
    pub fn load(&mut self, table: &[u8]) -> Result<()> {
        if table.len() < 36 {
            return Err(Error::Truncated);
        }
        let len = u32::from_le_bytes(table[4..8].try_into().unwrap()) as usize;
        if len < 36 || len > table.len() {
            return Err(Error::Truncated);
        }
        let index = self.tables.len();
        let bytes: Rc<[u8]> = Rc::from(&table[..len]);
        let wide = table[8] >= 2;
        self.tables.push(Table { bytes: bytes.clone(), wide });
        let mut c = Cur { table: index, b: bytes, pos: 36, end: len, wide };
        let mut f = Frame::new(ROOT, false);
        self.loading = true;
        let r = self.body(&mut c, &mut f, ROOT, len);
        self.loading = false;
        r.map(|_| ())
    }

    /// A method's body as it is in its table (for debugging).
    pub fn method_body(&self, id: NodeId) -> Option<&[u8]> {
        match &self.ns.get(id).object {
            Object::Method(m) => self.tables.get(m.table).map(|t| &t.bytes[m.start..m.end]),
            _ => None,
        }
    }

    /// Where the last failed evaluation failed (methods, innermost first,
    /// with the offset reached in each body).
    pub fn trace(&self) -> &[(String, usize)] {
        &self.trace
    }

    /// What loading could not run.
    pub fn problems(&self) -> &[Problem] {
        &self.problems
    }

    /// An object by its full path (`\_SB.PCI0._PRT`).
    pub fn find(&self, path: &str) -> Option<NodeId> {
        let p = Path::parse_text(path)?;
        self.ns.resolve(ROOT, &p).map(|id| self.follow(id))
    }

    /// A child of `id` by name (no search up the scopes).
    pub fn child(&self, id: NodeId, seg: &str) -> Option<NodeId> {
        let p = Path::parse_text(seg)?;
        let seg = *p.segs.first()?;
        self.ns.child(id, &seg).map(|c| self.follow(c))
    }

    pub fn children(&self, id: NodeId) -> Vec<NodeId> {
        self.ns.get(id).children.values().copied().filter(|&c| !self.ns.get(c).gone).collect()
    }

    /// The scope `id` is in (`None` for the root).
    pub fn parent(&self, id: NodeId) -> Option<NodeId> {
        (id != ROOT).then(|| self.ns.get(id).parent)
    }

    pub fn object(&self, id: NodeId) -> &Object {
        &self.ns.get(id).object
    }

    pub fn path(&self, id: NodeId) -> String {
        self.ns.path_of(id)
    }

    /// The number of objects in the namespace.
    pub fn len(&self) -> usize {
        self.ns.nodes.iter().filter(|n| !n.gone).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() <= 1
    }

    fn follow(&self, mut id: NodeId) -> NodeId {
        for _ in 0..8 {
            match self.ns.get(id).object {
                Object::Alias(to) => id = to,
                _ => break,
            }
        }
        id
    }

    /// Evaluate an object by path: call a method (with `args`), or read
    /// data, a field or a buffer field.
    pub fn evaluate(&mut self, path: &str, args: Vec<Value>) -> Result<Value> {
        let id = self.find(path).ok_or_else(|| Error::NotFound(String::from(path)))?;
        self.evaluate_node(id, args)
    }

    pub fn evaluate_node(&mut self, id: NodeId, args: Vec<Value>) -> Result<Value> {
        if self.depth == 0 {
            self.trace.clear();
        }
        let id = self.follow(id);
        match &self.ns.get(id).object {
            Object::Method(_) | Object::Osi => self.call(id, args),
            _ => {
                let v = self.read_node(id)?;
                self.resolve_value(v)
            }
        }
    }

    /// Evaluate `name` under `id` if it is there (`_STA`, `_HID`...).
    pub fn evaluate_child(&mut self, id: NodeId, name: &str, args: Vec<Value>) -> Result<Option<Value>> {
        match self.child(id, name) {
            Some(c) => self.evaluate_node(c, args).map(Some),
            None => Ok(None),
        }
    }

    /// The devices' initialization (§6.5.1): `\_SB._INI`, then `_STA` of
    /// every device and `_INI` of those present, depth first; a device
    /// neither present nor functional is skipped with what is under it.
    /// `_REG` is called for PCI configuration space, which is always
    /// there. Returns how many `_INI` methods ran.
    pub fn initialize(&mut self) -> usize {
        let mut ran = 0;
        let regs: Vec<NodeId> = (0..self.ns.nodes.len())
            .filter(|&i| !self.ns.nodes[i].gone && &self.ns.nodes[i].seg == b"_REG")
            .filter(|&i| matches!(self.ns.nodes[i].object, Object::Method(_)))
            .collect();
        for r in regs {
            let parent = self.ns.get(r).parent;
            let has_pci = self
                .children(parent)
                .iter()
                .any(|&c| matches!(&self.ns.get(c).object, Object::Region(Region { space: Space::PciConfig, .. })));
            if has_pci {
                let _ = self.call(r, alloc::vec![Value::Integer(2), Value::Integer(1)]);
            }
        }
        if let Some(sb) = self.find("\\_SB_") {
            if let Ok(Some(_)) = self.evaluate_child(sb, "_INI", Vec::new()) {
                ran += 1;
            }
            ran += self.init_under(sb);
        }
        ran
    }

    fn init_under(&mut self, scope: NodeId) -> usize {
        let mut ran = 0;
        for c in self.children(scope) {
            if !matches!(self.ns.get(c).object, Object::Device | Object::Processor { .. }) {
                continue;
            }
            let sta = self.status(c);
            if sta & 1 != 0 && self.evaluate_child(c, "_INI", Vec::new()).ok().flatten().is_some() {
                ran += 1;
            }
            if sta & 0x9 != 0 {
                ran += self.init_under(c);
            }
        }
        ran
    }

    /// `_STA` (§6.3.7): 0x0F when there is none.
    pub fn status(&mut self, dev: NodeId) -> u64 {
        match self.evaluate_child(dev, "_STA", Vec::new()) {
            Ok(Some(v)) => self.int_of(&v).unwrap_or(0),
            Ok(None) => 0x0F,
            Err(_) => 0,
        }
    }

    // --- Term lists ---------------------------------------------------------

    /// Run `c` up to `end` in `scope`. While loading, a term that fails is
    /// recorded and skipped when it has a package length; otherwise the
    /// rest of this list is.
    fn body(&mut self, c: &mut Cur, f: &mut Frame, scope: NodeId, end: usize) -> Result<Flow> {
        let saved = (c.end, f.scope);
        c.end = end;
        f.scope = scope;
        let r = self.term_list(c, f);
        c.end = saved.0;
        f.scope = saved.1;
        if c.pos < end && r.is_ok() {
            c.pos = end;
        }
        match r {
            Err(e) if self.loading => {
                self.problem(c.table, c.pos, scope, e);
                c.pos = end;
                Ok(Flow::Normal)
            }
            r => {
                if r.is_err() {
                    c.pos = end;
                }
                r
            }
        }
    }

    fn problem(&mut self, table: usize, offset: usize, scope: NodeId, error: Error) {
        if self.problems.len() < 1000 {
            let scope = self.ns.path_of(scope);
            self.problems.push(Problem { table, offset, scope, error });
        }
    }

    fn term_list(&mut self, c: &mut Cur, f: &mut Frame) -> Result<Flow> {
        while c.pos < c.end {
            let start = c.pos;
            match self.term(c, f) {
                Ok(Flow::Normal) => {}
                Ok(flow) => return Ok(flow),
                Err(e) if self.loading => match self.package_end(c, start) {
                    Some(end) => {
                        self.problem(c.table, start, f.scope, e);
                        c.pos = end;
                    }
                    None => return Err(e),
                },
                Err(e) => return Err(e),
            }
        }
        Ok(Flow::Normal)
    }

    /// Where a term with a package length ends, for skipping it.
    fn package_end(&self, c: &Cur, start: usize) -> Option<usize> {
        let b = &c.b;
        let op = *b.get(start)?;
        let at = match op {
            0x10 | 0x11 | 0x12 | 0x13 | 0x14 | 0xA0 | 0xA1 | 0xA2 => start + 1,
            0x5B if matches!(b.get(start + 1), Some(0x81..=0x87)) => start + 2,
            _ => return None,
        };
        let mut p = at;
        let len = name::pkg_length(b, &mut p).ok()?;
        let end = at + len;
        (end <= c.end && end > start).then_some(end)
    }

    fn term(&mut self, c: &mut Cur, f: &mut Frame) -> Result<Flow> {
        let op = c.peek()?;
        match op {
            0x10 => {
                c.pos += 1;
                let end = c.pkg()?;
                let path = c.name()?;
                let scope = self.ns.resolve(f.scope, &path).ok_or_else(|| Error::NotFound(alloc::format!("{path}")))?;
                self.body(c, f, scope, end)
            }
            0x08 => {
                c.pos += 1;
                let path = c.name()?;
                let v = self.term_arg(c, f)?;
                self.declare(f, &path, Object::Data(v))?;
                Ok(Flow::Normal)
            }
            0x06 => {
                c.pos += 1;
                let source = c.name()?;
                let alias = c.name()?;
                let to =
                    self.ns.resolve(f.scope, &source).ok_or_else(|| Error::NotFound(alloc::format!("{source}")))?;
                self.declare(f, &alias, Object::Alias(to))?;
                Ok(Flow::Normal)
            }
            0x14 => {
                c.pos += 1;
                let end = c.pkg()?;
                let path = c.name()?;
                let flags = c.byte()?;
                let m = Method { table: c.table, start: c.pos, end, args: flags & 7, serialized: flags & 8 != 0 };
                self.declare(f, &path, Object::Method(m))?;
                c.pos = end;
                Ok(Flow::Normal)
            }
            0x15 => {
                c.pos += 1;
                let path = c.name()?;
                let kind = c.byte()?;
                let args = c.byte()?;
                // An External for an object already defined is a no-op.
                if self.ns.resolve(f.scope, &path).is_none() {
                    self.declare(f, &path, Object::External { kind, args })?;
                }
                Ok(Flow::Normal)
            }
            0x8A..=0x8D | 0x8F => {
                c.pos += 1;
                let buf = self.term_arg(c, f)?;
                let index = self.int_arg(c, f)?;
                let path = c.name()?;
                let (bit_offset, bit_len) = match op {
                    0x8A => (index * 8, 32),
                    0x8B => (index * 8, 16),
                    0x8C => (index * 8, 8),
                    0x8D => (index, 1),
                    _ => (index * 8, 64),
                };
                self.buffer_field(f, &path, buf, bit_offset, bit_len)?;
                Ok(Flow::Normal)
            }
            0xA0 => self.if_else(c, f),
            0xA2 => self.while_loop(c, f),
            0xA4 => {
                c.pos += 1;
                let v = self.term_arg(c, f)?;
                Ok(Flow::Return(v))
            }
            0xA5 => {
                c.pos += 1;
                Ok(Flow::Break)
            }
            0x9F => {
                c.pos += 1;
                Ok(Flow::Continue)
            }
            0xA3 | 0xCC => {
                c.pos += 1;
                Ok(Flow::Normal)
            }
            0x86 => {
                c.pos += 1;
                let t = self.target(c, f)?;
                let v = self.int_arg(c, f)?;
                if let Target::Node(id) = t {
                    let p = self.ns.path_of(id);
                    self.host.notify(&p, v);
                }
                Ok(Flow::Normal)
            }
            0x5B => self.ext_term(c, f),
            _ => {
                self.term_arg(c, f)?;
                Ok(Flow::Normal)
            }
        }
    }

    fn ext_term(&mut self, c: &mut Cur, f: &mut Frame) -> Result<Flow> {
        let ext = c.peek_at(1).ok_or(Error::Truncated)?;
        match ext {
            0x01 => {
                c.pos += 2;
                let path = c.name()?;
                let sync = c.byte()?;
                self.declare(f, &path, Object::Mutex { sync })?;
            }
            0x02 => {
                c.pos += 2;
                let path = c.name()?;
                self.declare(f, &path, Object::Event { count: 0 })?;
            }
            0x80 => {
                c.pos += 2;
                let path = c.name()?;
                let space = Space::from_byte(c.byte()?);
                let offset = self.int_arg(c, f)?;
                let len = self.int_arg(c, f)?;
                self.declare(f, &path, Object::Region(Region { space, offset, len }))?;
            }
            0x81 => {
                c.pos += 2;
                let end = c.pkg()?;
                let region = c.name()?;
                let flags = c.byte()?;
                let r = self.resolve(f, &region)?;
                self.field_list(c, f, end, FieldKind::Region(r), flags)?;
            }
            0x86 => {
                c.pos += 2;
                let end = c.pkg()?;
                let index = c.name()?;
                let data = c.name()?;
                let flags = c.byte()?;
                let (index, data) = (self.resolve(f, &index)?, self.resolve(f, &data)?);
                self.field_list(c, f, end, FieldKind::Index { index, data }, flags)?;
            }
            0x87 => {
                c.pos += 2;
                let end = c.pkg()?;
                let region = c.name()?;
                let bank = c.name()?;
                let value = self.int_arg(c, f)?;
                let flags = c.byte()?;
                let (region, bank) = (self.resolve(f, &region)?, self.resolve(f, &bank)?);
                self.field_list(c, f, end, FieldKind::Bank { region, bank, value }, flags)?;
            }
            0x82..=0x85 => {
                c.pos += 2;
                let end = c.pkg()?;
                let path = c.name()?;
                let object = match ext {
                    0x82 => Object::Device,
                    0x83 => {
                        let id = c.byte()?;
                        let pblk = c.le(4)? as u32;
                        let pblk_len = c.byte()?;
                        Object::Processor { id, pblk, pblk_len }
                    }
                    0x84 => {
                        let level = c.byte()?;
                        let order = c.le(2)? as u16;
                        Object::PowerResource { level, order }
                    }
                    _ => Object::ThermalZone,
                };
                let id = self.declare(f, &path, object)?;
                return self.body(c, f, id, end);
            }
            0x88 => {
                c.pos += 2;
                let path = c.name()?;
                let sig = self.bytes_arg(c, f)?;
                let oem = self.bytes_arg(c, f)?;
                let table = self.bytes_arg(c, f)?;
                let (offset, len) = self.host.find_table(&sig, &oem, &table).unwrap_or((0, 0));
                self.declare(f, &path, Object::Region(Region { space: Space::SystemMemory, offset, len }))?;
            }
            0x13 => {
                c.pos += 2;
                let buf = self.term_arg(c, f)?;
                let bit = self.int_arg(c, f)?;
                let bits = self.int_arg(c, f)?;
                let path = c.name()?;
                self.buffer_field(f, &path, buf, bit, bits)?;
            }
            0x27 | 0x26 => {
                // Release and Reset: one thread, no waiters.
                c.pos += 2;
                self.target(c, f)?;
            }
            0x24 => {
                c.pos += 2;
                if let Target::Node(id) = self.target(c, f)?
                    && let Object::Event { count } = &mut self.ns.nodes[id].object
                {
                    *count += 1;
                }
            }
            0x22 => {
                c.pos += 2;
                let ms = self.int_arg(c, f)?;
                self.host.sleep(ms);
            }
            0x21 => {
                c.pos += 2;
                let us = self.int_arg(c, f)?;
                self.host.stall(us);
            }
            0x32 => {
                c.pos += 2;
                let kind = c.byte()?;
                let code = c.le(4)? as u32;
                let arg = self.int_arg(c, f)?;
                return Err(Error::Fatal(kind, code, arg));
            }
            0x20 | 0x2A => return Err(Error::Unsupported("Load and Unload")),
            _ => {
                self.term_arg(c, f)?;
            }
        }
        Ok(Flow::Normal)
    }

    /// Add a named object. Objects a method creates go when it returns.
    fn declare(&mut self, f: &mut Frame, path: &Path, object: Object) -> Result<NodeId> {
        let (parent, seg) = self.ns.parent_for(f.scope, path)?;
        let id = self.ns.add(parent, seg, object)?;
        if f.in_method {
            f.created.push(id);
        }
        Ok(id)
    }

    fn resolve(&self, f: &Frame, path: &Path) -> Result<NodeId> {
        self.ns
            .resolve(f.scope, path)
            .map(|id| self.follow(id))
            .ok_or_else(|| Error::NotFound(alloc::format!("{path}")))
    }

    fn field_list(&mut self, c: &mut Cur, f: &mut Frame, end: usize, kind: FieldKind, flags: u8) -> Result<()> {
        let mut bit = 0u64;
        let mut access = flags & 0x0F;
        let update = (flags >> 5) & 3;
        while c.pos < end {
            match c.peek()? {
                0x00 => {
                    c.pos += 1;
                    bit += name::pkg_length(&c.b, &mut c.pos)? as u64;
                }
                0x01 => {
                    c.pos += 1;
                    access = c.byte()? & 0x0F;
                    c.byte()?;
                }
                0x02 => {
                    // ConnectField: a GPIO or serial bus connection.
                    c.pos += 1;
                    if c.peek()? == 0x11 {
                        self.term_arg(c, f)?;
                    } else {
                        c.name()?;
                    }
                }
                0x03 => {
                    c.pos += 1;
                    access = c.byte()? & 0x0F;
                    c.byte()?;
                    c.byte()?;
                }
                _ => {
                    if c.pos + 4 > end {
                        return Err(Error::Truncated);
                    }
                    let seg: [u8; 4] = c.b[c.pos..c.pos + 4].try_into().unwrap();
                    c.pos += 4;
                    let len = name::pkg_length(&c.b, &mut c.pos)? as u64;
                    let field = Field { kind: kind.clone(), bit_offset: bit, bit_len: len, access, update };
                    let p = Path { root: false, up: 0, segs: alloc::vec![seg] };
                    self.declare(f, &p, Object::Field(field))?;
                    bit += len;
                }
            }
        }
        c.pos = end;
        Ok(())
    }

    fn buffer_field(&mut self, f: &mut Frame, path: &Path, buf: Value, bit_offset: u64, bit_len: u64) -> Result<()> {
        let buf = match self.resolve_value(buf)? {
            Value::Buffer(b) => b,
            _ => return Err(Error::BadType("CreateField of a non-buffer")),
        };
        if bit_offset + bit_len > buf.borrow().len() as u64 * 8 {
            return Err(Error::OutOfRange);
        }
        self.declare(f, path, Object::BufferField { buffer: buf, bit_offset, bit_len })?;
        Ok(())
    }

    fn if_else(&mut self, c: &mut Cur, f: &mut Frame) -> Result<Flow> {
        c.pos += 1;
        let end = c.pkg()?;
        let pred = self.int_arg(c, f)?;
        let else_end = if end < c.end && c.b.get(end) == Some(&0xA1) {
            let mut p = end + 1;
            let len = name::pkg_length(&c.b, &mut p)?;
            Some((p, end + 1 + len))
        } else {
            None
        };
        let flow = if pred != 0 {
            let scope = f.scope;
            self.block(c, f, scope, end)?
        } else {
            Flow::Normal
        };
        match else_end {
            Some((start, e)) => {
                if pred == 0 {
                    c.pos = start;
                    let scope = f.scope;
                    let flow = self.block(c, f, scope, e)?;
                    c.pos = e;
                    return Ok(flow);
                }
                c.pos = e;
            }
            None => c.pos = end,
        }
        Ok(flow)
    }

    /// A block inside If, Else or While: like [`body`] but its scope is
    /// the enclosing one.
    fn block(&mut self, c: &mut Cur, f: &mut Frame, scope: NodeId, end: usize) -> Result<Flow> {
        self.body(c, f, scope, end)
    }

    fn while_loop(&mut self, c: &mut Cur, f: &mut Frame) -> Result<Flow> {
        c.pos += 1;
        let end = c.pkg()?;
        let pred_at = c.pos;
        let mut n = 0u64;
        loop {
            c.pos = pred_at;
            if self.int_arg(c, f)? == 0 {
                break;
            }
            n += 1;
            if n > MAX_LOOPS {
                c.pos = end;
                return Err(Error::Limit("While"));
            }
            let scope = f.scope;
            match self.block(c, f, scope, end)? {
                Flow::Break => break,
                Flow::Return(v) => {
                    c.pos = end;
                    return Ok(Flow::Return(v));
                }
                Flow::Normal | Flow::Continue => {}
            }
        }
        c.pos = end;
        Ok(Flow::Normal)
    }

    // --- Expressions --------------------------------------------------------

    fn int_arg(&mut self, c: &mut Cur, f: &mut Frame) -> Result<u64> {
        let v = self.term_arg(c, f)?;
        self.int_of(&v)
    }

    fn bytes_arg(&mut self, c: &mut Cur, f: &mut Frame) -> Result<Vec<u8>> {
        let v = self.term_arg(c, f)?;
        self.bytes_of(&v, 8)
    }

    fn term_arg(&mut self, c: &mut Cur, f: &mut Frame) -> Result<Value> {
        let op = c.peek()?;
        if starts_name(op) {
            return self.name_value(c, f);
        }
        c.pos += 1;
        let mask = c.mask();
        let v = match op {
            0x00 => Value::Integer(0),
            0x01 => Value::Integer(1),
            0xFF => Value::Integer(mask),
            0x0A => Value::Integer(c.le(1)?),
            0x0B => Value::Integer(c.le(2)?),
            0x0C => Value::Integer(c.le(4)?),
            0x0E => Value::Integer(c.le(8)? & mask),
            0x0D => {
                let start = c.pos;
                while c.byte()? != 0 {}
                Value::string(&c.b[start..c.pos - 1])
            }
            0x11 => {
                let end = c.pkg()?;
                let size = self.int_arg(c, f)? as usize;
                if size > 1 << 24 {
                    return Err(Error::Limit("buffer size"));
                }
                let init = &c.b[c.pos..end];
                let mut b = alloc::vec![0u8; size.max(init.len())];
                b[..init.len()].copy_from_slice(init);
                c.pos = end;
                Value::buffer(b)
            }
            0x12 | 0x13 => {
                let end = c.pkg()?;
                let n = if op == 0x12 { u64::from(c.byte()?) } else { self.int_arg(c, f)? };
                let mut elems = Vec::new();
                while c.pos < end {
                    if starts_name(c.peek()?) {
                        let p = c.name()?;
                        elems.push(match self.ns.resolve(f.scope, &p) {
                            Some(id) => Value::Node(self.follow(id)),
                            None => Value::Unresolved(f.scope, p),
                        });
                    } else {
                        elems.push(self.term_arg(c, f)?);
                    }
                }
                c.pos = end;
                elems.resize(n.min(65536) as usize, Value::Uninitialized);
                Value::package(elems)
            }
            0x60..=0x67 => f.locals[usize::from(op - 0x60)].clone(),
            0x68..=0x6E => f.args[usize::from(op - 0x68)].clone(),
            0x70 => {
                let v = self.term_arg(c, f)?;
                let v = self.resolve_value(v)?;
                let t = self.target(c, f)?;
                self.store(t, v.clone(), f, c.width())?;
                v
            }
            0x71 => match self.super_name(c, f, false)? {
                Target::Node(id) => Value::Node(id),
                Target::Element(p, i) => Value::PackageElement(p, i),
                Target::Byte(b, i) => Value::BufferByte(b, i),
                Target::Local(i) => f.locals[i].clone(),
                Target::Arg(i) => f.args[i].clone(),
                _ => return Err(Error::BadType("RefOf")),
            },
            0x72 | 0x74 | 0x77 | 0x79 | 0x7A | 0x7B | 0x7C | 0x7D | 0x7E | 0x7F | 0x85 => {
                let a = self.int_arg(c, f)?;
                let b = self.int_arg(c, f)?;
                let r = match op {
                    0x72 => a.wrapping_add(b),
                    0x74 => a.wrapping_sub(b),
                    0x77 => a.wrapping_mul(b),
                    0x79 => {
                        if b >= 64 {
                            0
                        } else {
                            a << b
                        }
                    }
                    0x7A => {
                        if b >= 64 {
                            0
                        } else {
                            a >> b
                        }
                    }
                    0x7B => a & b,
                    0x7C => !(a & b),
                    0x7D => a | b,
                    0x7E => !(a | b),
                    0x7F => a ^ b,
                    _ => a.checked_rem(b).ok_or(Error::DivideByZero)?,
                } & mask;
                let t = self.target(c, f)?;
                self.store(t, Value::Integer(r), f, c.width())?;
                Value::Integer(r)
            }
            0x75 | 0x76 => {
                let at = c.pos;
                let v = self.term_arg(c, f)?;
                let n = self.int_of(&v)?;
                let r = if op == 0x75 { n.wrapping_add(1) } else { n.wrapping_sub(1) } & mask;
                c.pos = at;
                let t = self.target(c, f)?;
                self.store(t, Value::Integer(r), f, c.width())?;
                Value::Integer(r)
            }
            0x78 => {
                let a = self.int_arg(c, f)?;
                let b = self.int_arg(c, f)?;
                if b == 0 {
                    return Err(Error::DivideByZero);
                }
                let rem = self.target(c, f)?;
                let quot = self.target(c, f)?;
                self.store(rem, Value::Integer(a % b), f, c.width())?;
                self.store(quot, Value::Integer(a / b), f, c.width())?;
                Value::Integer(a / b)
            }
            0x80..=0x82 => {
                let a = self.int_arg(c, f)?;
                let r = match op {
                    0x80 => !a & mask,
                    0x81 => {
                        if a == 0 {
                            0
                        } else {
                            64 - u64::from(a.leading_zeros())
                        }
                    }
                    _ => {
                        if a == 0 {
                            0
                        } else {
                            u64::from(a.trailing_zeros()) + 1
                        }
                    }
                };
                let t = self.target(c, f)?;
                self.store(t, Value::Integer(r), f, c.width())?;
                Value::Integer(r)
            }
            0x73 => {
                let a = self.term_arg(c, f)?;
                let a = self.resolve_value(a)?;
                let b = self.term_arg(c, f)?;
                let b = self.resolve_value(b)?;
                let r = match &a {
                    Value::Integer(x) => {
                        let mut v = value::int_to_bytes(*x, c.width());
                        v.extend(value::int_to_bytes(self.int_of(&b)?, c.width()));
                        Value::buffer(v)
                    }
                    Value::String(s) => {
                        let mut v = s.borrow().clone();
                        v.extend(self.text_of(&b, c.width())?);
                        Value::string(&v)
                    }
                    _ => {
                        let mut v = self.bytes_of(&a, c.width())?;
                        v.extend(self.bytes_of(&b, c.width())?);
                        Value::buffer(v)
                    }
                };
                let t = self.target(c, f)?;
                self.store(t, r.clone(), f, c.width())?;
                r
            }
            0x84 => {
                let a = self.bytes_arg(c, f)?;
                let b = self.bytes_arg(c, f)?;
                // Two resource templates: the first's end tag (0x79 and a
                // checksum) goes, the second's stays (§19.6.23).
                let mut v = a;
                if v.len() >= 2 && v[v.len() - 2] == 0x79 {
                    v.truncate(v.len() - 2);
                }
                v.extend(b);
                let r = Value::buffer(v);
                let t = self.target(c, f)?;
                self.store(t, r.clone(), f, c.width())?;
                r
            }
            0x83 => {
                let v = self.term_arg(c, f)?;
                self.deref(v, f)?
            }
            0x87 => {
                let t = self.target(c, f)?;
                let v = self.target_value(&t, f)?;
                Value::Integer(match self.resolve_value(v)? {
                    Value::String(s) => s.borrow().len() as u64,
                    Value::Buffer(b) => b.borrow().len() as u64,
                    Value::Package(p) => p.borrow().len() as u64,
                    _ => return Err(Error::BadType("SizeOf")),
                })
            }
            0x88 => {
                let src = self.term_arg(c, f)?;
                let src = self.resolve_value(src)?;
                let i = self.int_arg(c, f)? as usize;
                let r = match src {
                    Value::Package(p) => {
                        if i >= p.borrow().len() {
                            return Err(Error::OutOfRange);
                        }
                        Value::PackageElement(p, i)
                    }
                    Value::Buffer(b) | Value::String(b) => {
                        if i >= b.borrow().len() {
                            return Err(Error::OutOfRange);
                        }
                        Value::BufferByte(b, i)
                    }
                    _ => return Err(Error::BadType("Index")),
                };
                let t = self.target(c, f)?;
                self.store_ref(t, r.clone(), f)?;
                r
            }
            0x89 => {
                let pkg = self.term_arg(c, f)?;
                let pkg = self.resolve_value(pkg)?;
                let op1 = c.byte()?;
                let v1 = self.int_arg(c, f)?;
                let op2 = c.byte()?;
                let v2 = self.int_arg(c, f)?;
                let start = self.int_arg(c, f)? as usize;
                let Value::Package(p) = pkg else { return Err(Error::BadType("Match")) };
                let elems = p.borrow().clone();
                let mut found = mask;
                for (i, e) in elems.iter().enumerate().skip(start) {
                    let Ok(x) = self.int_of(e) else { continue };
                    if matches(op1, x, v1) && matches(op2, x, v2) {
                        found = i as u64;
                        break;
                    }
                }
                Value::Integer(found)
            }
            0x8E => {
                let at = c.pos;
                let t = match self.super_name(c, f, false) {
                    Ok(t) => t,
                    Err(Error::NotFound(_)) => {
                        c.pos = at;
                        c.name()?;
                        return Ok(Value::Integer(0));
                    }
                    Err(e) => return Err(e),
                };
                Value::Integer(match t {
                    Target::Node(id) => self.ns.get(id).object.type_number(),
                    Target::Debug => 16,
                    t => self.target_value(&t, f)?.type_number(),
                })
            }
            0x90 | 0x91 => {
                let a = self.int_arg(c, f)?;
                let b = self.int_arg(c, f)?;
                let r = if op == 0x90 { a != 0 && b != 0 } else { a != 0 || b != 0 };
                Value::Integer(if r { mask } else { 0 })
            }
            0x92 => {
                let a = self.int_arg(c, f)?;
                Value::Integer(if a == 0 { mask } else { 0 })
            }
            0x93..=0x95 => {
                let a = self.term_arg(c, f)?;
                let a = self.resolve_value(a)?;
                let b = self.term_arg(c, f)?;
                let b = self.resolve_value(b)?;
                let ord = match &a {
                    Value::String(_) | Value::Buffer(_) => {
                        let x = self.raw_bytes_of(&a)?;
                        let y = self.raw_bytes_of(&b)?;
                        value::compare_bytes(&x, &y)
                    }
                    _ => self.int_of(&a)?.cmp(&self.int_of(&b)?),
                };
                let r = match op {
                    0x93 => ord.is_eq(),
                    0x94 => ord.is_gt(),
                    _ => ord.is_lt(),
                };
                Value::Integer(if r { mask } else { 0 })
            }
            0x96 => {
                let a = self.term_arg(c, f)?;
                let r = Value::buffer(self.bytes_of(&a, c.width())?);
                let t = self.target(c, f)?;
                self.store(t, r.clone(), f, c.width())?;
                r
            }
            0x97 | 0x98 => {
                let a = self.term_arg(c, f)?;
                let a = self.resolve_value(a)?;
                let s: String = match (&a, op) {
                    (Value::Integer(i), 0x97) => value::decimal(*i),
                    (Value::Integer(i), _) => alloc::format!("0x{}", value::hex(*i, c.width() * 2)),
                    (Value::Buffer(b), 0x97) => {
                        b.borrow().iter().map(|&x| value::decimal(u64::from(x))).collect::<Vec<_>>().join(",")
                    }
                    (Value::Buffer(b), _) => b
                        .borrow()
                        .iter()
                        .map(|&x| alloc::format!("0x{}", value::hex(u64::from(x), 2)))
                        .collect::<Vec<_>>()
                        .join(","),
                    (Value::String(s), _) => String::from_utf8_lossy(&s.borrow()).into_owned(),
                    _ => return Err(Error::BadType("ToString")),
                };
                let r = Value::string(s.as_bytes());
                let t = self.target(c, f)?;
                self.store(t, r.clone(), f, c.width())?;
                r
            }
            0x99 => {
                let a = self.term_arg(c, f)?;
                let a = self.resolve_value(a)?;
                let r = match &a {
                    Value::String(s) => value::string_to_int(&s.borrow(), false) & mask,
                    v => self.int_of(v)?,
                };
                let t = self.target(c, f)?;
                self.store(t, Value::Integer(r), f, c.width())?;
                Value::Integer(r)
            }
            0x9C => {
                let a = self.bytes_arg(c, f)?;
                let len = self.int_arg(c, f)?;
                let mut s: Vec<u8> = a.into_iter().take_while(|&b| b != 0).collect();
                if len != mask && (len as usize) < s.len() {
                    s.truncate(len as usize);
                }
                let r = Value::string(&s);
                let t = self.target(c, f)?;
                self.store(t, r.clone(), f, c.width())?;
                r
            }
            0x9D => {
                let v = self.term_arg(c, f)?;
                let v = self.resolve_value(v)?.deep_copy();
                match self.target(c, f)? {
                    Target::Node(id) => self.ns.nodes[id].object = Object::Data(v.clone()),
                    Target::Local(i) => f.locals[i] = v.clone(),
                    Target::Arg(i) => f.args[i] = v.clone(),
                    t => self.store(t, v.clone(), f, c.width())?,
                }
                v
            }
            0x9E => {
                let src = self.term_arg(c, f)?;
                let src = self.resolve_value(src)?;
                let i = self.int_arg(c, f)? as usize;
                let n = self.int_arg(c, f)? as usize;
                let (bytes, is_string) = match &src {
                    Value::String(s) => (s.borrow().clone(), true),
                    v => (self.bytes_of(v, c.width())?, false),
                };
                let from = i.min(bytes.len());
                let to = from.saturating_add(n).min(bytes.len());
                let part = &bytes[from..to];
                let r = if is_string { Value::string(part) } else { Value::buffer(part.to_vec()) };
                let t = self.target(c, f)?;
                self.store(t, r.clone(), f, c.width())?;
                r
            }
            0x5B => return self.ext_value(c, f),
            _ => return Err(Error::BadOpcode(u16::from(op))),
        };
        Ok(v)
    }

    fn ext_value(&mut self, c: &mut Cur, f: &mut Frame) -> Result<Value> {
        let ext = c.byte()?;
        let mask = c.mask();
        Ok(match ext {
            0x12 => {
                // CondRefOf: the name need not exist.
                let at = c.pos;
                let found = match self.super_name(c, f, false) {
                    Ok(Target::Node(id)) => Some(Value::Node(id)),
                    Ok(_) => None,
                    Err(Error::NotFound(_)) => {
                        c.pos = at;
                        c.name()?;
                        None
                    }
                    Err(e) => return Err(e),
                };
                let t = self.target(c, f)?;
                match found {
                    Some(r) => {
                        self.store_ref(t, r, f)?;
                        Value::Integer(mask)
                    }
                    None => Value::Integer(0),
                }
            }
            0x23 => {
                self.target(c, f)?;
                c.le(2)?;
                // One thread: every Acquire succeeds.
                Value::Integer(0)
            }
            0x25 => {
                let t = self.target(c, f)?;
                self.int_arg(c, f)?;
                let got = match t {
                    Target::Node(id) => match &mut self.ns.nodes[id].object {
                        Object::Event { count } if *count > 0 => {
                            *count -= 1;
                            true
                        }
                        _ => false,
                    },
                    _ => false,
                };
                Value::Integer(if got { 0 } else { mask })
            }
            0x28 | 0x29 => {
                let a = self.int_arg(c, f)?;
                let r = if ext == 0x28 { from_bcd(a) } else { to_bcd(a) } & mask;
                let t = self.target(c, f)?;
                self.store(t, Value::Integer(r), f, c.width())?;
                Value::Integer(r)
            }
            0x30 => Value::Integer(1),
            0x33 => Value::Integer(self.host.timer()),
            0x1F => {
                for _ in 0..6 {
                    self.term_arg(c, f)?;
                }
                Value::Integer(0)
            }
            _ => return Err(Error::BadOpcode(0x5B00 | u16::from(ext))),
        })
    }

    /// A NameString as a value: a method call (with as many arguments as
    /// it takes), or the object's value.
    fn name_value(&mut self, c: &mut Cur, f: &mut Frame) -> Result<Value> {
        let path = c.name()?;
        if path.segs.is_empty() && !path.root {
            return Ok(Value::Uninitialized);
        }
        let id = self.resolve(f, &path)?;
        let args = match &self.ns.get(id).object {
            Object::Method(m) => Some(m.args),
            Object::Osi => Some(1),
            Object::External { kind: 8, args } => Some(*args),
            _ => None,
        };
        match args {
            Some(n) => {
                let mut v = Vec::new();
                for _ in 0..n {
                    v.push(self.term_arg(c, f)?);
                }
                if let Object::External { .. } = self.ns.get(id).object {
                    return Err(Error::NotFound(alloc::format!("{path} (External, never defined)")));
                }
                self.call(id, v)
            }
            None => self.read_node(id),
        }
    }

    fn call(&mut self, id: NodeId, args: Vec<Value>) -> Result<Value> {
        let m = match &self.ns.get(id).object {
            Object::Osi => {
                let s = args.first().cloned().unwrap_or_default();
                let s = self.resolve_value(s)?;
                let yes = s.as_string().is_some_and(|t| OSI.contains(&t.as_str()));
                return Ok(Value::Integer(if yes { u64::MAX } else { 0 }));
            }
            Object::Method(m) => m.clone(),
            _ => return Err(Error::BadType("call of a non-method")),
        };
        if self.depth >= MAX_DEPTH {
            return Err(Error::Limit("call depth"));
        }
        let t = &self.tables[m.table];
        let mut c = Cur { table: m.table, b: t.bytes.clone(), pos: m.start, end: m.end, wide: t.wide };
        let mut f = Frame::new(id, true);
        for (i, a) in args.into_iter().take(7).enumerate() {
            f.args[i] = a;
        }
        let was_loading = self.loading;
        self.loading = false;
        self.depth += 1;
        let r = self.term_list(&mut c, &mut f);
        self.depth -= 1;
        self.loading = was_loading;
        for n in f.created.into_iter().rev() {
            self.ns.remove(n);
        }
        if r.is_err() && self.trace.len() < 32 {
            let path = self.ns.path_of(id);
            self.trace.push((path, c.pos - m.start));
        }
        match r? {
            Flow::Return(v) => self.resolve_value(v),
            _ => Ok(Value::Integer(0)),
        }
    }

    // --- Targets and stores -------------------------------------------------

    fn target(&mut self, c: &mut Cur, f: &mut Frame) -> Result<Target> {
        self.super_name(c, f, true)
    }

    /// A SuperName: with `call`, a method named here is called and its
    /// result is the target (UserTermObj, §20.2.5.4); RefOf, CondRefOf
    /// and ObjectType name the method itself.
    fn super_name(&mut self, c: &mut Cur, f: &mut Frame, call: bool) -> Result<Target> {
        let op = c.peek()?;
        Ok(match op {
            0x00 => {
                c.pos += 1;
                Target::None
            }
            0x60..=0x67 => {
                c.pos += 1;
                Target::Local(usize::from(op - 0x60))
            }
            0x68..=0x6E => {
                c.pos += 1;
                Target::Arg(usize::from(op - 0x68))
            }
            0x5B if c.peek_at(1) == Some(0x31) => {
                c.pos += 2;
                Target::Debug
            }
            _ if starts_name(op) => {
                let path = c.name()?;
                let id = self.resolve(f, &path)?;
                match &self.ns.get(id).object {
                    Object::Method(_) if call => {
                        c.pos -= encoded_len(&path);
                        let v = self.name_value(c, f)?;
                        self.target_of(v)?
                    }
                    _ => Target::Node(id),
                }
            }
            _ => {
                let v = self.term_arg(c, f)?;
                self.target_of(v)?
            }
        })
    }

    fn target_of(&self, v: Value) -> Result<Target> {
        Ok(match v {
            Value::Node(id) => Target::Node(id),
            Value::PackageElement(p, i) => Target::Element(p, i),
            Value::BufferByte(b, i) => Target::Byte(b, i),
            _ => return Err(Error::BadType("not a reference")),
        })
    }

    fn target_value(&mut self, t: &Target, f: &Frame) -> Result<Value> {
        Ok(match t {
            Target::None | Target::Debug => Value::Uninitialized,
            Target::Local(i) => f.locals[*i].clone(),
            Target::Arg(i) => f.args[*i].clone(),
            Target::Node(id) => self.read_node(*id)?,
            Target::Element(p, i) => p.borrow().get(*i).cloned().unwrap_or_default(),
            Target::Byte(b, i) => Value::Integer(u64::from(b.borrow().get(*i).copied().unwrap_or(0))),
        })
    }

    /// Store a reference (Index, RefOf, CondRefOf's target): the
    /// reference itself goes to a local or argument.
    fn store_ref(&mut self, t: Target, r: Value, f: &mut Frame) -> Result<()> {
        match t {
            Target::None => Ok(()),
            Target::Local(i) => {
                f.locals[i] = r;
                Ok(())
            }
            Target::Arg(i) => {
                f.args[i] = r;
                Ok(())
            }
            t => {
                let v = self.deref(r, f)?;
                self.store(t, v, f, 8)
            }
        }
    }

    fn store(&mut self, t: Target, v: Value, f: &mut Frame, width: usize) -> Result<()> {
        match t {
            Target::None => Ok(()),
            Target::Local(i) => {
                f.locals[i] = v.deep_copy();
                Ok(())
            }
            Target::Arg(i) => match f.args[i].clone() {
                r @ (Value::Node(_) | Value::PackageElement(..) | Value::BufferByte(..)) => {
                    let t = self.target_of(r)?;
                    self.store(t, v, f, width)
                }
                _ => {
                    f.args[i] = v.deep_copy();
                    Ok(())
                }
            },
            Target::Debug => {
                let text = match &v {
                    Value::Integer(i) => alloc::format!("0x{}", value::hex(*i, 16)),
                    Value::String(s) => String::from_utf8_lossy(&s.borrow()).into_owned(),
                    other => alloc::format!("{other:?}"),
                };
                self.host.debug(&text);
                Ok(())
            }
            Target::Element(p, i) => {
                let v = v.deep_copy();
                if let Some(e) = p.borrow_mut().get_mut(i) {
                    *e = v;
                }
                Ok(())
            }
            Target::Byte(b, i) => {
                let x = self.int_of(&v)? as u8;
                if let Some(e) = b.borrow_mut().get_mut(i) {
                    *e = x;
                }
                Ok(())
            }
            Target::Node(id) => self.store_node(self.follow(id), v, width),
        }
    }

    /// Store into a named object, converting to its type (§19.3.5.8).
    fn store_node(&mut self, id: NodeId, v: Value, width: usize) -> Result<()> {
        let object = self.ns.get(id).object.clone();
        match object {
            Object::Data(Value::Integer(_)) => {
                let i = self.int_of(&v)?;
                self.ns.nodes[id].object = Object::Data(Value::Integer(i));
            }
            Object::Data(Value::String(_)) => {
                let s = self.text_of(&v, width)?;
                self.ns.nodes[id].object = Object::Data(Value::string(&s));
            }
            Object::Data(Value::Buffer(b)) => {
                let src = self.bytes_of(&v, width)?;
                let mut dst = b.borrow_mut();
                let n = dst.len();
                dst.iter_mut().for_each(|x| *x = 0);
                let k = n.min(src.len());
                dst[..k].copy_from_slice(&src[..k]);
            }
            Object::Data(_) => self.ns.nodes[id].object = Object::Data(v.deep_copy()),
            Object::Field(fld) => {
                let bytes = self.bytes_of(&v, width)?;
                self.write_field(&fld, &bytes)?;
            }
            Object::BufferField { buffer, bit_offset, bit_len } => {
                let bytes = self.bytes_of(&v, width)?;
                write_bits(&mut buffer.borrow_mut(), bit_offset, bit_len, &bytes);
            }
            Object::External { .. } => self.ns.nodes[id].object = Object::Data(v.deep_copy()),
            _ => return Err(Error::BadType("store into this object")),
        }
        Ok(())
    }

    // --- Reading objects ----------------------------------------------------

    fn read_node(&mut self, id: NodeId) -> Result<Value> {
        let id = self.follow(id);
        let object = self.ns.get(id).object.clone();
        Ok(match object {
            Object::Data(v) => v,
            Object::Field(fld) => {
                let bytes = self.read_field(&fld)?;
                if fld.bit_len <= 64 { Value::Integer(value::buffer_to_int(&bytes, 8)) } else { Value::buffer(bytes) }
            }
            Object::BufferField { buffer, bit_offset, bit_len } => {
                let bytes = read_bits(&buffer.borrow(), bit_offset, bit_len);
                if bit_len <= 64 { Value::Integer(value::buffer_to_int(&bytes, 8)) } else { Value::buffer(bytes) }
            }
            Object::Method(_) | Object::Osi => self.call(id, Vec::new())?,
            _ => Value::Node(id),
        })
    }

    /// Follow a value to data: references, unresolved package names.
    fn resolve_value(&mut self, v: Value) -> Result<Value> {
        match v {
            Value::Unresolved(scope, p) => {
                let id = self.ns.resolve(scope, &p).ok_or_else(|| Error::NotFound(alloc::format!("{p}")))?;
                Ok(Value::Node(self.follow(id)))
            }
            v => Ok(v),
        }
    }

    fn deref(&mut self, v: Value, _f: &Frame) -> Result<Value> {
        match self.resolve_value(v)? {
            Value::Node(id) => self.read_node(id),
            Value::PackageElement(p, i) => {
                let e = p.borrow().get(i).cloned().unwrap_or_default();
                self.resolve_value(e)
            }
            Value::BufferByte(b, i) => Ok(Value::Integer(u64::from(b.borrow().get(i).copied().unwrap_or(0)))),
            Value::String(s) => {
                // DerefOf a string: the object it names (§19.6.31).
                let text = String::from_utf8_lossy(&s.borrow()).into_owned();
                let p = Path::parse_text(&text).ok_or(Error::BadType("DerefOf of a string"))?;
                let id = self.ns.resolve(ROOT, &p).ok_or(Error::NotFound(text))?;
                self.read_node(id)
            }
            other => Ok(other),
        }
    }

    // --- Conversions --------------------------------------------------------

    fn int_of(&mut self, v: &Value) -> Result<u64> {
        Ok(match v {
            Value::Integer(i) => *i,
            Value::String(s) => value::string_to_int(&s.borrow(), true),
            Value::Buffer(b) => value::buffer_to_int(&b.borrow(), 8),
            Value::Node(_) | Value::PackageElement(..) | Value::BufferByte(..) | Value::Unresolved(..) => {
                let d = self.deref(v.clone(), &Frame::new(ROOT, false))?;
                if matches!(d, Value::Node(_)) {
                    return Err(Error::BadType("an object, not a number"));
                }
                self.int_of(&d)?
            }
            Value::Uninitialized => return Err(Error::BadType("uninitialized")),
            Value::Package(_) => return Err(Error::BadType("a package, not a number")),
        })
    }

    fn bytes_of(&mut self, v: &Value, width: usize) -> Result<Vec<u8>> {
        Ok(match v {
            Value::Integer(i) => value::int_to_bytes(*i, width),
            Value::String(s) => {
                let mut b = s.borrow().clone();
                b.push(0);
                b
            }
            Value::Buffer(b) => b.borrow().clone(),
            Value::Node(_) | Value::PackageElement(..) | Value::BufferByte(..) | Value::Unresolved(..) => {
                let d = self.deref(v.clone(), &Frame::new(ROOT, false))?;
                if matches!(d, Value::Node(_)) {
                    return Err(Error::BadType("an object, not data"));
                }
                self.bytes_of(&d, width)?
            }
            _ => return Err(Error::BadType("not a buffer")),
        })
    }

    /// Bytes for comparing: a string without its terminator.
    fn raw_bytes_of(&mut self, v: &Value) -> Result<Vec<u8>> {
        Ok(match v {
            Value::String(s) => s.borrow().clone(),
            v => self.bytes_of(v, 8)?,
        })
    }

    /// Text for Concat and stores into strings: an integer as hex digits,
    /// a buffer as its bytes up to a NUL.
    fn text_of(&mut self, v: &Value, width: usize) -> Result<Vec<u8>> {
        Ok(match v {
            Value::Integer(i) => value::hex(*i, width * 2).into_bytes(),
            Value::String(s) => s.borrow().clone(),
            Value::Buffer(b) => b.borrow().iter().copied().take_while(|&x| x != 0).collect(),
            other => {
                let d = self.deref(other.clone(), &Frame::new(ROOT, false))?;
                if matches!(d, Value::Node(_)) {
                    return Err(Error::BadType("an object, not text"));
                }
                self.text_of(&d, width)?
            }
        })
    }

    // --- Fields -------------------------------------------------------------

    fn access_bits(fld: &Field) -> u64 {
        match fld.access {
            2 => 16,
            3 => 32,
            4 => 64,
            _ => 8,
        }
    }

    fn read_field(&mut self, fld: &Field) -> Result<Vec<u8>> {
        let w = Self::access_bits(fld);
        let mut out = alloc::vec![0u8; fld.bit_len.div_ceil(8) as usize];
        let first = fld.bit_offset / w;
        let last = (fld.bit_offset + fld.bit_len).div_ceil(w);
        for unit in first..last {
            let raw = self.access(&fld.kind, unit * w / 8, w as u8, None)?;
            let unit_start = unit * w;
            let lo = fld.bit_offset.max(unit_start);
            let hi = (fld.bit_offset + fld.bit_len).min(unit_start + w);
            for bit in lo..hi {
                if raw >> (bit - unit_start) & 1 != 0 {
                    let o = bit - fld.bit_offset;
                    out[(o / 8) as usize] |= 1 << (o % 8);
                }
            }
        }
        Ok(out)
    }

    fn write_field(&mut self, fld: &Field, src: &[u8]) -> Result<()> {
        let w = Self::access_bits(fld);
        let first = fld.bit_offset / w;
        let last = (fld.bit_offset + fld.bit_len).div_ceil(w);
        for unit in first..last {
            let unit_start = unit * w;
            let lo = fld.bit_offset.max(unit_start);
            let hi = (fld.bit_offset + fld.bit_len).min(unit_start + w);
            let unit_mask = if w == 64 { u64::MAX } else { (1u64 << w) - 1 };
            let covered = (lo..hi).fold(0u64, |m, b| m | (1 << (b - unit_start)));
            let base = if covered == unit_mask {
                0
            } else {
                match fld.update {
                    1 => unit_mask,
                    2 => 0,
                    _ => self.access(&fld.kind, unit * w / 8, w as u8, None)?,
                }
            };
            let mut v = base & !covered;
            for bit in lo..hi {
                let o = bit - fld.bit_offset;
                if src.get((o / 8) as usize).is_some_and(|b| b >> (o % 8) & 1 != 0) {
                    v |= 1 << (bit - unit_start);
                }
            }
            self.access(&fld.kind, unit * w / 8, w as u8, Some(v))?;
        }
        Ok(())
    }

    /// Read (`write` None) or write one access unit at byte `offset` of a
    /// field's space.
    fn access(&mut self, kind: &FieldKind, offset: u64, width: u8, write: Option<u64>) -> Result<u64> {
        match kind {
            FieldKind::Region(r) => self.region_access(*r, offset, width, write),
            FieldKind::Index { index, data } => {
                let (index, data) = (*index, *data);
                self.store_node(index, Value::Integer(offset), 8)?;
                match write {
                    Some(v) => {
                        self.store_node(data, Value::Integer(v), 8)?;
                        Ok(0)
                    }
                    None => {
                        let v = self.read_node(data)?;
                        self.int_of(&v)
                    }
                }
            }
            FieldKind::Bank { region, bank, value } => {
                let (region, bank, value) = (*region, *bank, *value);
                self.store_node(bank, Value::Integer(value), 8)?;
                self.region_access(region, offset, width, write)
            }
        }
    }

    fn region_access(&mut self, region: NodeId, offset: u64, width: u8, write: Option<u64>) -> Result<u64> {
        let Object::Region(r) = self.ns.get(region).object.clone() else {
            return Err(Error::BadType("field of a non-region"));
        };
        let at = match r.space {
            Space::SystemMemory => Address::Memory(r.offset + offset),
            Space::SystemIo => Address::Io((r.offset + offset) as u16),
            Space::PciConfig => {
                let (segment, bus, device, function) = self.pci_address(region);
                Address::Pci { segment, bus, device, function, offset: (r.offset + offset) as u16 }
            }
            s => Address::Other(s, r.offset + offset),
        };
        match write {
            Some(v) => self.host.write(at, width, v).map(|()| 0),
            None => self.host.read(at, width),
        }
    }

    /// The PCI function a PCI_Config region belongs to (§6.5.6): `_ADR`
    /// of its device (device << 16 | function), `_BBN` and `_SEG` of the
    /// host bridge above it (0 without them).
    fn pci_address(&mut self, region: NodeId) -> (u16, u8, u8, u8) {
        let mut at = self.ns.get(region).parent;
        let adr = self.int_child(at, "_ADR").unwrap_or(0);
        let (mut bus, mut seg) = (0u64, 0u64);
        while at != ROOT {
            let hid = self.child(at, "_HID").or_else(|| self.child(at, "_CID"));
            let bridge = hid.is_some_and(|h| {
                let v = self.evaluate_node(h, Vec::new()).ok();
                v.is_some_and(|v| eisa_is(&v, &[b"PNP0A03", b"PNP0A08"]))
            });
            if bridge {
                bus = self.int_child(at, "_BBN").unwrap_or(0);
                seg = self.int_child(at, "_SEG").unwrap_or(0);
                break;
            }
            at = self.ns.get(at).parent;
        }
        (seg as u16, bus as u8, (adr >> 16) as u8, (adr & 0xFFFF) as u8)
    }

    fn int_child(&mut self, id: NodeId, name: &str) -> Option<u64> {
        let v = self.evaluate_child(id, name, Vec::new()).ok()??;
        self.int_of(&v).ok()
    }
}

/// Whether a _HID or _CID value names one of `ids` (an EISA ID integer,
/// §6.1.5, or a string).
fn eisa_is(v: &Value, ids: &[&[u8]]) -> bool {
    match v {
        Value::Integer(i) => ids.iter().any(|id| eisa_id(id) == Some(*i as u32)),
        Value::String(s) => ids.iter().any(|id| s.borrow().as_slice() == *id),
        _ => false,
    }
}

/// The compressed EISA ID of `PNP0A03`-style text (§6.1.5).
pub fn eisa_id(id: &[u8]) -> Option<u32> {
    if id.len() != 7 {
        return None;
    }
    let l = |c: u8| u32::from(c.wrapping_sub(b'@')) & 0x1F;
    let letters = (l(id[0]) << 10) | (l(id[1]) << 5) | l(id[2]);
    let hex = core::str::from_utf8(&id[3..]).ok().and_then(|h| u32::from_str_radix(h, 16).ok())?;
    let v = (letters << 16) | hex;
    // Stored big-endian in a little-endian dword.
    Some(v.swap_bytes())
}

fn matches(op: u8, x: u64, v: u64) -> bool {
    match op {
        0 => true,
        1 => x == v,
        2 => x <= v,
        3 => x < v,
        4 => x >= v,
        5 => x > v,
        _ => false,
    }
}

fn from_bcd(mut v: u64) -> u64 {
    let (mut r, mut m) = (0, 1);
    while v != 0 {
        r += (v & 0xF) * m;
        m *= 10;
        v >>= 4;
    }
    r
}

fn to_bcd(mut v: u64) -> u64 {
    let (mut r, mut s) = (0, 0);
    while v != 0 && s < 64 {
        r |= (v % 10) << s;
        v /= 10;
        s += 4;
    }
    r
}

fn read_bits(b: &[u8], offset: u64, len: u64) -> Vec<u8> {
    let mut out = alloc::vec![0u8; len.div_ceil(8) as usize];
    for i in 0..len {
        let bit = offset + i;
        if b.get((bit / 8) as usize).is_some_and(|x| x >> (bit % 8) & 1 != 0) {
            out[(i / 8) as usize] |= 1 << (i % 8);
        }
    }
    out
}

fn write_bits(b: &mut [u8], offset: u64, len: u64, src: &[u8]) {
    for i in 0..len {
        let bit = offset + i;
        let on = src.get((i / 8) as usize).is_some_and(|x| x >> (i % 8) & 1 != 0);
        if let Some(x) = b.get_mut((bit / 8) as usize) {
            if on {
                *x |= 1 << (bit % 8);
            } else {
                *x &= !(1 << (bit % 8));
            }
        }
    }
}

/// The encoded length of a NameString (to step back over one).
fn encoded_len(p: &Path) -> usize {
    let prefix = usize::from(p.root) + p.up;
    prefix
        + match p.segs.len() {
            0 => 1,
            1 => 4,
            2 => 9,
            n => 2 + 4 * n,
        }
}
