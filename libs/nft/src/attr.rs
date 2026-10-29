// SPDX-License-Identifier: MIT OR Apache-2.0

//! Netlink messages and their attributes (netlink(7)): a 16-byte header
//! (length, type, flags, sequence number, port), then for nfnetlink a
//! 4-byte `nfgenmsg` (family, version, resource id: big-endian), then
//! attributes, each a 4-byte header (length, type) and its value padded
//! to four bytes. nf_tables' integers are big-endian.

use alloc::vec::Vec;

use crate::consts::*;

/// A message's header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub len: usize,
    pub kind: u16,
    pub flags: u16,
    pub seq: u32,
    pub port: u32,
}

/// The messages in a datagram: each header and its payload (after the
/// 16-byte header).
pub fn messages(b: &[u8]) -> Vec<(Header, &[u8])> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 16 <= b.len() {
        let len = u32::from_ne_bytes(b[at..at + 4].try_into().unwrap()) as usize;
        if len < 16 || at + len > b.len() {
            break;
        }
        let h = Header {
            len,
            kind: u16::from_ne_bytes([b[at + 4], b[at + 5]]),
            flags: u16::from_ne_bytes([b[at + 6], b[at + 7]]),
            seq: u32::from_ne_bytes(b[at + 8..at + 12].try_into().unwrap()),
            port: u32::from_ne_bytes(b[at + 12..at + 16].try_into().unwrap()),
        };
        out.push((h, &b[at + 16..at + len]));
        at += len.next_multiple_of(4);
    }
    out
}

/// One attribute: its type (flags cleared) and value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attr<'a> {
    pub kind: u16,
    pub value: &'a [u8],
}

impl<'a> Attr<'a> {
    pub fn u8(&self) -> Option<u8> {
        self.value.first().copied()
    }

    pub fn u32(&self) -> Option<u32> {
        Some(u32::from_be_bytes(self.value.get(..4)?.try_into().ok()?))
    }

    pub fn i32(&self) -> Option<i32> {
        self.u32().map(|v| v as i32)
    }

    pub fn u64(&self) -> Option<u64> {
        Some(u64::from_be_bytes(self.value.get(..8)?.try_into().ok()?))
    }

    /// A string attribute, without its terminating NUL.
    pub fn str(&self) -> Option<&'a [u8]> {
        let v = self.value;
        let end = v.iter().position(|&c| c == 0).unwrap_or(v.len());
        (end > 0).then_some(&v[..end])
    }

    /// The attributes nested in this one.
    pub fn nested(&self) -> Attrs<'a> {
        Attrs(self.value)
    }
}

/// A run of attributes.
#[derive(Clone, Copy, Debug)]
pub struct Attrs<'a>(pub &'a [u8]);

impl<'a> Attrs<'a> {
    /// The first attribute of type `kind`.
    pub fn get(&self, kind: u16) -> Option<Attr<'a>> {
        self.iter().find(|a| a.kind == kind)
    }

    pub fn iter(&self) -> impl Iterator<Item = Attr<'a>> + 'a {
        let b = self.0;
        let mut at = 0;
        core::iter::from_fn(move || {
            if at + 4 > b.len() {
                return None;
            }
            let len = usize::from(u16::from_ne_bytes([b[at], b[at + 1]]));
            let kind = u16::from_ne_bytes([b[at + 2], b[at + 3]]) & NLA_TYPE_MASK;
            if len < 4 || at + len > b.len() {
                return None;
            }
            let a = Attr { kind, value: &b[at + 4..at + len] };
            at += len.next_multiple_of(4);
            Some(a)
        })
    }

    /// Whether the run parses to its end (no truncated attribute).
    pub fn well_formed(&self) -> bool {
        let mut at = 0;
        while at < self.0.len() {
            if at + 4 > self.0.len() {
                return false;
            }
            let len = usize::from(u16::from_ne_bytes([self.0[at], self.0[at + 1]]));
            if len < 4 || at + len > self.0.len() {
                return false;
            }
            at += len.next_multiple_of(4);
        }
        true
    }
}

/// A message being built: header, `nfgenmsg`, attributes; nests are
/// closed in order.
#[derive(Debug)]
pub struct Msg {
    b: Vec<u8>,
    open: Vec<usize>,
}

impl Msg {
    /// A message with an `nfgenmsg` of `family` and resource id `res`.
    pub fn new(kind: u16, flags: u16, seq: u32, port: u32, family: u8, res: u16) -> Msg {
        let mut m = Msg::bare(kind, flags, seq, port);
        m.b.extend_from_slice(&[family, 0]);
        m.b.extend_from_slice(&res.to_be_bytes());
        m
    }

    /// A message with nothing after its header.
    pub fn bare(kind: u16, flags: u16, seq: u32, port: u32) -> Msg {
        let mut b = Vec::with_capacity(64);
        b.extend_from_slice(&0u32.to_ne_bytes());
        b.extend_from_slice(&kind.to_ne_bytes());
        b.extend_from_slice(&flags.to_ne_bytes());
        b.extend_from_slice(&seq.to_ne_bytes());
        b.extend_from_slice(&port.to_ne_bytes());
        Msg { b, open: Vec::new() }
    }

    pub fn raw(&mut self, data: &[u8]) -> &mut Msg {
        self.b.extend_from_slice(data);
        self
    }

    pub fn attr(&mut self, kind: u16, value: &[u8]) -> &mut Msg {
        let len = 4 + value.len();
        self.b.extend_from_slice(&(len as u16).to_ne_bytes());
        self.b.extend_from_slice(&kind.to_ne_bytes());
        self.b.extend_from_slice(value);
        self.b.resize(self.b.len().next_multiple_of(4), 0);
        self
    }

    pub fn u32(&mut self, kind: u16, v: u32) -> &mut Msg {
        self.attr(kind, &v.to_be_bytes())
    }

    pub fn u64(&mut self, kind: u16, v: u64) -> &mut Msg {
        self.attr(kind, &v.to_be_bytes())
    }

    /// A string with its NUL.
    pub fn str(&mut self, kind: u16, s: &[u8]) -> &mut Msg {
        let mut v = Vec::with_capacity(s.len() + 1);
        v.extend_from_slice(s);
        v.push(0);
        self.attr(kind, &v)
    }

    /// Start a nested attribute (without the nested flag, as Linux's dumps
    /// have it).
    pub fn nest(&mut self, kind: u16) -> &mut Msg {
        self.open.push(self.b.len());
        self.b.extend_from_slice(&[0, 0]);
        self.b.extend_from_slice(&kind.to_ne_bytes());
        self
    }

    pub fn end(&mut self) -> &mut Msg {
        let at = self.open.pop().expect("a nest to end");
        let len = (self.b.len() - at) as u16;
        self.b[at..at + 2].copy_from_slice(&len.to_ne_bytes());
        self
    }

    pub fn finish(mut self) -> Vec<u8> {
        let len = self.b.len() as u32;
        self.b[..4].copy_from_slice(&len.to_ne_bytes());
        self.b
    }
}

/// An acknowledgement (`errno` 0) or an error of request `req` with body
/// `body` (netlink(7): `struct nlmsgerr`, observed on the host): an
/// acknowledgement quotes only the request's header (NLM_F_CAPPED), an
/// error all of it, then, when `bad` names one of its attributes, that
/// attribute's offset in it (NLM_F_ACK_TLVS, NLMSGERR_ATTR_OFFS), which
/// nft underlines.
pub fn ack(req: &Header, body: &[u8], errno: i32, port: u32, bad: Option<u16>) -> Vec<u8> {
    const NLM_F_CAPPED: u16 = 0x100;
    const NLM_F_ACK_TLVS: u16 = 0x200;
    const NLMSGERR_ATTR_OFFS: u16 = 2;
    let offset = bad.filter(|_| errno != 0).and_then(|k| attr_offset(body, k));
    let flags = if errno == 0 {
        NLM_F_CAPPED
    } else if offset.is_some() {
        NLM_F_ACK_TLVS
    } else {
        0
    };
    let mut m = Msg::bare(NLMSG_ERROR, flags, req.seq, port);
    m.raw(&(-errno).to_ne_bytes());
    m.raw(&(req.len as u32).to_ne_bytes());
    m.raw(&req.kind.to_ne_bytes());
    m.raw(&req.flags.to_ne_bytes());
    m.raw(&req.seq.to_ne_bytes());
    m.raw(&req.port.to_ne_bytes());
    if errno != 0 {
        m.raw(body);
        if let Some(o) = offset {
            m.attr(NLMSGERR_ATTR_OFFS, &o.to_ne_bytes());
        }
    }
    m.finish()
}

/// Where attribute `kind` starts in a whole nfnetlink message whose body
/// (after the 16-byte header, `nfgenmsg` first) is `body`.
fn attr_offset(body: &[u8], kind: u16) -> Option<u32> {
    let mut at = 4;
    while at + 4 <= body.len() {
        let len = usize::from(u16::from_ne_bytes([body[at], body[at + 1]]));
        if len < 4 {
            return None;
        }
        if u16::from_ne_bytes([body[at + 2], body[at + 3]]) & NLA_TYPE_MASK == kind {
            return Some((16 + at) as u32);
        }
        at += len.next_multiple_of(4);
    }
    None
}

/// The end of a dump: NLMSG_DONE carrying an int 0 (observed on the host).
pub fn done(seq: u32, port: u32) -> Vec<u8> {
    let mut m = Msg::bare(NLMSG_DONE, NLM_F_MULTI, seq, port);
    m.raw(&0i32.to_ne_bytes());
    m.finish()
}
