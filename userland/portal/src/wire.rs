// SPDX-License-Identifier: MIT OR Apache-2.0

//! D-Bus messages, as the D-Bus Specification ("Message Protocol",
//! "Marshaling (Wire Format)") describes them: a header (endianness,
//! type, flags, version 1, the body's length, a serial, then an array of
//! header fields `a(yv)`), padded to 8, then the body. Every value starts
//! at a multiple of its alignment: 1 for `y` and `g`; 4 for `b`, `i`,
//! `u`, `s`, `o` and an array's length; 8 for `d`, `x`, `t`, structs and
//! dictionary entries. Strings are a length, the bytes and a NUL; a
//! signature a byte length, the bytes and a NUL; a variant its signature,
//! then its value. Only little-endian messages are made; both are read.

use alloc::string::String;
use alloc::vec::Vec;

/// A value, as much of the type system as the portal needs.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Byte(u8),
    Bool(bool),
    I32(i32),
    U32(u32),
    Double(f64),
    Str(String),
    Path(String),
    Sig(String),
    Variant(alloc::boxed::Box<Value>),
    /// An array: its elements' signature, and the elements.
    Array(String, Vec<Value>),
    Struct(Vec<Value>),
    /// A dictionary entry `{kv}`.
    Entry(alloc::boxed::Box<Value>, alloc::boxed::Box<Value>),
}

impl Value {
    /// Its type signature.
    pub fn signature(&self) -> String {
        match self {
            Value::Byte(_) => "y".into(),
            Value::Bool(_) => "b".into(),
            Value::I32(_) => "i".into(),
            Value::U32(_) => "u".into(),
            Value::Double(_) => "d".into(),
            Value::Str(_) => "s".into(),
            Value::Path(_) => "o".into(),
            Value::Sig(_) => "g".into(),
            Value::Variant(_) => "v".into(),
            Value::Array(e, _) => alloc::format!("a{e}"),
            Value::Struct(v) => alloc::format!("({})", v.iter().map(Value::signature).collect::<String>()),
            Value::Entry(k, v) => alloc::format!("{{{}{}}}", k.signature(), v.signature()),
        }
    }

    pub fn str(&self) -> Option<&str> {
        match self {
            Value::Str(s) | Value::Path(s) | Value::Sig(s) => Some(s),
            _ => None,
        }
    }

    /// A variant holding `v`.
    pub fn variant(v: Value) -> Value {
        Value::Variant(alloc::boxed::Box::new(v))
    }
}

/// Bytes being written, with alignment counted from the message's start.
#[derive(Debug, Default)]
pub struct Out(pub Vec<u8>);

impl Out {
    fn pad(&mut self, to: usize) {
        while self.0.len() % to != 0 {
            self.0.push(0);
        }
    }
    fn u32(&mut self, x: u32) {
        self.pad(4);
        self.0.extend_from_slice(&x.to_le_bytes());
    }
    pub fn value(&mut self, v: &Value) {
        match v {
            Value::Byte(b) => self.0.push(*b),
            Value::Bool(b) => self.u32(u32::from(*b)),
            Value::I32(i) => self.u32(*i as u32),
            Value::U32(u) => self.u32(*u),
            Value::Double(d) => {
                self.pad(8);
                self.0.extend_from_slice(&d.to_bits().to_le_bytes());
            }
            Value::Str(s) | Value::Path(s) => {
                self.u32(s.len() as u32);
                self.0.extend_from_slice(s.as_bytes());
                self.0.push(0);
            }
            Value::Sig(s) => {
                self.0.push(s.len() as u8);
                self.0.extend_from_slice(s.as_bytes());
                self.0.push(0);
            }
            Value::Variant(inner) => {
                self.value(&Value::Sig(inner.signature()));
                self.value(inner);
            }
            Value::Array(elem, items) => {
                self.u32(0);
                let len_at = self.0.len() - 4;
                // The elements start aligned, after any padding the length
                // doesn't count.
                self.pad(align_of_sig(elem));
                let start = self.0.len();
                for i in items {
                    self.value(i);
                }
                let n = (self.0.len() - start) as u32;
                self.0[len_at..len_at + 4].copy_from_slice(&n.to_le_bytes());
            }
            Value::Struct(fields) => {
                self.pad(8);
                for f in fields {
                    self.value(f);
                }
            }
            Value::Entry(k, v) => {
                self.pad(8);
                self.value(k);
                self.value(v);
            }
        }
    }
}

/// The alignment of a value whose signature starts `sig`.
fn align_of_sig(sig: &str) -> usize {
    match sig.as_bytes().first() {
        Some(b'y' | b'g' | b'v') => 1,
        Some(b'n' | b'q') => 2,
        Some(b'b' | b'i' | b'u' | b's' | b'o' | b'a' | b'h') => 4,
        _ => 8,
    }
}

/// The first complete type in `sig`, and the rest.
pub fn split_type(sig: &str) -> Option<(&str, &str)> {
    let b = sig.as_bytes();
    let end = match *b.first()? {
        b'a' => 1 + split_type(&sig[1..])?.0.len(),
        open @ (b'(' | b'{') => {
            let close = if open == b'(' { b')' } else { b'}' };
            let mut depth = 0;
            let mut i = 0;
            loop {
                match b.get(i)? {
                    c if *c == open => depth += 1,
                    c if *c == close => {
                        depth -= 1;
                        if depth == 0 {
                            break i + 1;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
        }
        _ => 1,
    };
    Some((&sig[..end], &sig[end..]))
}

/// Reading values, alignment counted from the message's start.
#[derive(Debug)]
pub struct In<'a> {
    buf: &'a [u8],
    pub at: usize,
    big: bool,
}

impl<'a> In<'a> {
    pub fn new(buf: &'a [u8], at: usize, big: bool) -> In<'a> {
        In { buf, at, big }
    }
    fn align(&mut self, to: usize) {
        self.at = self.at.div_ceil(to) * to;
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.buf.get(self.at..self.at + n)?;
        self.at += n;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> {
        self.align(4);
        let b: [u8; 4] = self.take(4)?.try_into().ok()?;
        Some(if self.big { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) })
    }
    /// One value of the single complete type `sig`.
    pub fn value(&mut self, sig: &str) -> Option<Value> {
        Some(match sig.as_bytes().first()? {
            b'y' => Value::Byte(*self.take(1)?.first()?),
            b'b' => Value::Bool(self.u32()? != 0),
            b'i' => Value::I32(self.u32()? as i32),
            b'u' => Value::U32(self.u32()?),
            b'd' => {
                self.align(8);
                let b: [u8; 8] = self.take(8)?.try_into().ok()?;
                Value::Double(f64::from_bits(if self.big { u64::from_be_bytes(b) } else { u64::from_le_bytes(b) }))
            }
            c @ (b's' | b'o') => {
                let n = self.u32()? as usize;
                let s = String::from(core::str::from_utf8(self.take(n)?).ok()?);
                self.take(1)?;
                if *c == b's' { Value::Str(s) } else { Value::Path(s) }
            }
            b'g' => {
                let n = *self.take(1)?.first()? as usize;
                let s = String::from(core::str::from_utf8(self.take(n)?).ok()?);
                self.take(1)?;
                Value::Sig(s)
            }
            b'v' => {
                let Value::Sig(s) = self.value("g")? else { return None };
                let (one, rest) = split_type(&s)?;
                if !rest.is_empty() {
                    return None;
                }
                Value::variant(self.value(one)?)
            }
            b'a' => {
                let n = self.u32()? as usize;
                let elem = &sig[1..];
                self.align(align_of_sig(elem));
                let end = self.at.checked_add(n)?;
                if end > self.buf.len() {
                    return None;
                }
                let mut items = Vec::new();
                while self.at < end {
                    items.push(self.value(elem)?);
                }
                Value::Array(String::from(elem), items)
            }
            b'(' => {
                self.align(8);
                let mut inner = &sig[1..sig.len() - 1];
                let mut fields = Vec::new();
                while !inner.is_empty() {
                    let (one, rest) = split_type(inner)?;
                    fields.push(self.value(one)?);
                    inner = rest;
                }
                Value::Struct(fields)
            }
            b'{' => {
                self.align(8);
                let (k, v) = split_type(&sig[1..sig.len() - 1])?;
                Value::Entry(alloc::boxed::Box::new(self.value(k)?), alloc::boxed::Box::new(self.value(v)?))
            }
            _ => return None,
        })
    }
    /// The values of a body whose signature is `sig`.
    pub fn values(&mut self, mut sig: &str) -> Option<Vec<Value>> {
        let mut out = Vec::new();
        while !sig.is_empty() {
            let (one, rest) = split_type(sig)?;
            out.push(self.value(one)?);
            sig = rest;
        }
        Some(out)
    }
}

/// A message the format doesn't allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadMessage;

/// Message types.
pub const METHOD_CALL: u8 = 1;
pub const METHOD_RETURN: u8 = 2;
pub const ERROR: u8 = 3;
pub const SIGNAL: u8 = 4;
/// Flag: no reply is wanted.
pub const NO_REPLY: u8 = 1;

/// A message.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Message {
    pub kind: u8,
    pub flags: u8,
    pub serial: u32,
    pub path: Option<String>,
    pub interface: Option<String>,
    pub member: Option<String>,
    pub error: Option<String>,
    pub reply_to: Option<u32>,
    pub destination: Option<String>,
    pub sender: Option<String>,
    pub body: Vec<Value>,
}

impl Message {
    pub fn call(serial: u32, dest: &str, path: &str, iface: &str, member: &str, body: Vec<Value>) -> Message {
        Message {
            kind: METHOD_CALL,
            serial,
            path: Some(path.into()),
            interface: Some(iface.into()),
            member: Some(member.into()),
            destination: Some(dest.into()),
            body,
            ..Message::default()
        }
    }

    /// The answer to `call`.
    pub fn reply(serial: u32, call: &Message, body: Vec<Value>) -> Message {
        Message {
            kind: METHOD_RETURN,
            serial,
            reply_to: Some(call.serial),
            destination: call.sender.clone(),
            body,
            ..Message::default()
        }
    }

    /// An error in answer to `call`.
    pub fn error(serial: u32, call: &Message, name: &str, text: &str) -> Message {
        Message {
            kind: ERROR,
            serial,
            reply_to: Some(call.serial),
            destination: call.sender.clone(),
            error: Some(name.into()),
            body: alloc::vec![Value::Str(text.into())],
            ..Message::default()
        }
    }

    pub fn signal(serial: u32, path: &str, iface: &str, member: &str, body: Vec<Value>) -> Message {
        Message {
            kind: SIGNAL,
            serial,
            path: Some(path.into()),
            interface: Some(iface.into()),
            member: Some(member.into()),
            body,
            ..Message::default()
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let sig: String = self.body.iter().map(Value::signature).collect();
        let mut body = Out::default();
        for v in &self.body {
            body.value(v);
        }
        let mut fields = Vec::new();
        let mut field =
            |code: u8, v: Value| fields.push(Value::Struct(alloc::vec![Value::Byte(code), Value::variant(v)]));
        if let Some(p) = &self.path {
            field(1, Value::Path(p.clone()));
        }
        if let Some(i) = &self.interface {
            field(2, Value::Str(i.clone()));
        }
        if let Some(m) = &self.member {
            field(3, Value::Str(m.clone()));
        }
        if let Some(e) = &self.error {
            field(4, Value::Str(e.clone()));
        }
        if let Some(r) = self.reply_to {
            field(5, Value::U32(r));
        }
        if let Some(d) = &self.destination {
            field(6, Value::Str(d.clone()));
        }
        if !sig.is_empty() {
            field(8, Value::Sig(sig));
        }
        let mut h = Out(alloc::vec![b'l', self.kind, self.flags, 1]);
        h.u32(body.0.len() as u32);
        h.u32(self.serial);
        h.value(&Value::Array(String::from("(yv)"), fields));
        h.pad(8);
        h.0.extend_from_slice(&body.0);
        h.0
    }

    /// The first whole message in `buf`, with its length; Ok(None) if it
    /// isn't all there.
    pub fn decode(buf: &[u8]) -> Result<Option<(Message, usize)>, BadMessage> {
        if buf.len() < 16 {
            return Ok(None);
        }
        let big = match buf[0] {
            b'l' => false,
            b'B' => true,
            _ => return Err(BadMessage),
        };
        let word = |at: usize| {
            let b = [buf[at], buf[at + 1], buf[at + 2], buf[at + 3]];
            if big { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }
        };
        let (body_len, serial, fields_len) = (word(4) as usize, word(8), word(12) as usize);
        if body_len > 1 << 27 || fields_len > 1 << 26 {
            return Err(BadMessage);
        }
        let body_at = (16 + fields_len).div_ceil(8) * 8;
        let total = body_at + body_len;
        if buf.len() < total {
            return Ok(None);
        }
        let mut m = Message { kind: buf[1], flags: buf[2], serial, ..Message::default() };
        let mut r = In::new(&buf[..total], 12, big);
        let Some(Value::Array(_, fields)) = r.value("a(yv)") else { return Err(BadMessage) };
        let mut sig = String::new();
        for f in fields {
            let Value::Struct(v) = f else { return Err(BadMessage) };
            let (Some(Value::Byte(code)), Some(Value::Variant(val))) = (v.first(), v.get(1)) else {
                return Err(BadMessage);
            };
            let s = val.str().map(String::from);
            match (code, &**val) {
                (1, _) => m.path = s,
                (2, _) => m.interface = s,
                (3, _) => m.member = s,
                (4, _) => m.error = s,
                (5, Value::U32(n)) => m.reply_to = Some(*n),
                (6, _) => m.destination = s,
                (7, _) => m.sender = s,
                (8, _) => sig = s.unwrap_or_default(),
                _ => {}
            }
        }
        let mut b = In::new(&buf[..total], body_at, big);
        m.body = b.values(&sig).ok_or(BadMessage)?;
        Ok(Some((m, total)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::vec;

    #[test]
    fn signatures() {
        assert_eq!(split_type("a{sv}u"), Some(("a{sv}", "u")));
        assert_eq!(split_type("(ddd)s"), Some(("(ddd)", "s")));
        assert_eq!(split_type("a(yv)"), Some(("a(yv)", "")));
        let v = Value::Array("{sv}".into(), vec![]);
        assert_eq!(v.signature(), "a{sv}");
    }

    #[test]
    fn a_call_as_the_specification_lays_it_out() {
        // Hello to the bus: the header's fields, padded to 8; no body.
        let m =
            Message::call(1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello", vec![]);
        let b = m.encode();
        assert_eq!(&b[..4], &[b'l', METHOD_CALL, 0, 1]);
        assert_eq!(u32::from_le_bytes([b[4], b[5], b[6], b[7]]), 0, "no body");
        assert_eq!(u32::from_le_bytes([b[8], b[9], b[10], b[11]]), 1, "serial");
        assert_eq!(b.len() % 8, 0);
        // The first field: code 1, the variant's signature "o", the path.
        assert_eq!(&b[16..20], &[1, 1, b'o', 0]);
        assert_eq!(u32::from_le_bytes([b[20], b[21], b[22], b[23]]), 21);
        assert_eq!(&b[24..45], b"/org/freedesktop/DBus");
        let (back, n) = Message::decode(&b).unwrap().unwrap();
        assert_eq!(n, b.len());
        assert_eq!(back, m);
    }

    #[test]
    fn nested_values_round_trip() {
        let accent = Value::Struct(vec![Value::Double(0.5), Value::Double(0.25), Value::Double(1.0)]);
        let dict = Value::Array(
            "{sv}".into(),
            vec![
                Value::Entry(Box::new(Value::Str("color-scheme".into())), Box::new(Value::variant(Value::U32(1)))),
                Value::Entry(Box::new(Value::Str("accent-color".into())), Box::new(Value::variant(accent))),
            ],
        );
        let all = Value::Array(
            "{sa{sv}}".into(),
            vec![Value::Entry(Box::new(Value::Str("org.freedesktop.appearance".into())), Box::new(dict))],
        );
        let mut call = Message::call(7, "x.y", "/a", "x.y", "M", vec![]);
        call.sender = Some(":1.4".into());
        let r = Message::reply(9, &call, vec![all.clone(), Value::variant(Value::variant(Value::Str("dark".into())))]);
        let bytes = r.encode();
        let (back, _) = Message::decode(&bytes).unwrap().unwrap();
        assert_eq!(back.body, r.body);
        assert_eq!((back.kind, back.reply_to, back.destination.as_deref()), (METHOD_RETURN, Some(7), Some(":1.4")));
        // Not all there yet.
        assert_eq!(Message::decode(&bytes[..bytes.len() - 1]), Ok(None));
        assert_eq!(Message::decode(b"x123456789abcdefghij"), Err(BadMessage));
    }

    #[test]
    fn big_endian_messages_are_read() {
        // A signal with one string, laid out by hand big-endian.
        let mut b = vec![b'B', SIGNAL, 0, 1];
        // The body: "hi" as a string, 4 + 2 + 1 bytes.
        b.extend_from_slice(&7u32.to_be_bytes());
        b.extend_from_slice(&5u32.to_be_bytes());
        // One field: the body's signature "s" (code 8, a variant of "g").
        let fields = [8u8, 1, b'g', 0, 1, b's', 0];
        b.extend_from_slice(&(fields.len() as u32).to_be_bytes());
        b.extend_from_slice(&fields);
        while b.len() % 8 != 0 {
            b.push(0);
        }
        b.extend_from_slice(&2u32.to_be_bytes());
        b.extend_from_slice(b"hi\0");
        let (m, n) = Message::decode(&b).unwrap().unwrap();
        assert_eq!(n, b.len());
        assert_eq!((m.kind, m.serial), (SIGNAL, 5));
        assert_eq!(m.body, vec![Value::Str("hi".into())]);
    }
}
