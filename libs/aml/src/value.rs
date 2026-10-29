// SPDX-License-Identifier: MIT OR Apache-2.0

//! AML data (§19.3.5): integers, strings, buffers and packages, and
//! references. Buffers and packages are shared, as the spec's reference
//! semantics need (Index into a package names that element).

use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::namespace::NodeId;

#[derive(Clone, Debug, Default)]
pub enum Value {
    #[default]
    Uninitialized,
    Integer(u64),
    String(Rc<RefCell<Vec<u8>>>),
    Buffer(Rc<RefCell<Vec<u8>>>),
    Package(Rc<RefCell<Vec<Value>>>),
    /// A named object (a device, a method, a region...), as a package
    /// element naming it or RefOf gives.
    Node(NodeId),
    /// A name in a package that did not resolve when the package was
    /// made (a forward reference): the scope it was written in and the
    /// path.
    Unresolved(NodeId, crate::Path),
    /// Index(...) into a package: that element.
    PackageElement(Rc<RefCell<Vec<Value>>>, usize),
    /// Index(...) into a buffer or string: that byte.
    BufferByte(Rc<RefCell<Vec<u8>>>, usize),
}

impl Value {
    pub fn string(s: &[u8]) -> Value {
        Value::String(Rc::new(RefCell::new(s.to_vec())))
    }

    pub fn buffer(b: Vec<u8>) -> Value {
        Value::Buffer(Rc::new(RefCell::new(b)))
    }

    pub fn package(v: Vec<Value>) -> Value {
        Value::Package(Rc::new(RefCell::new(v)))
    }

    /// ObjectType's number (§19.6.97).
    pub fn type_number(&self) -> u64 {
        match self {
            Value::Uninitialized | Value::Unresolved(..) => 0,
            Value::Integer(_) => 1,
            Value::String(_) => 2,
            Value::Buffer(_) => 3,
            Value::Package(_) => 4,
            Value::Node(_) | Value::PackageElement(..) | Value::BufferByte(..) => 0,
        }
    }

    pub fn as_int(&self) -> Option<u64> {
        match self {
            Value::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// The text of a string value.
    pub fn as_string(&self) -> Option<String> {
        match self {
            Value::String(s) => Some(String::from_utf8_lossy(&s.borrow()).into_owned()),
            _ => None,
        }
    }

    /// A deep copy (CopyObject and stores into new objects copy, §19.3.5.8).
    pub fn deep_copy(&self) -> Value {
        match self {
            Value::String(s) => Value::String(Rc::new(RefCell::new(s.borrow().clone()))),
            Value::Buffer(b) => Value::Buffer(Rc::new(RefCell::new(b.borrow().clone()))),
            Value::Package(p) => Value::package(p.borrow().iter().map(Value::deep_copy).collect()),
            v => v.clone(),
        }
    }
}

/// Bytes as an integer, little-endian, at most `width` of them (implicit
/// conversion of a buffer, §19.3.5.7).
pub fn buffer_to_int(b: &[u8], width: usize) -> u64 {
    b.iter().take(width).enumerate().fold(0, |v, (i, &x)| v | (u64::from(x) << (8 * i)))
}

/// A string as an integer: hexadecimal digits, with or without `0x`, up
/// to the first character that is not one (§19.3.5.7: the implicit
/// conversion reads hex).
pub fn string_to_int(s: &[u8], hex_only: bool) -> u64 {
    let t: &[u8] = match s {
        [b'0', b'x' | b'X', rest @ ..] => rest,
        _ if !hex_only && s.iter().all(|c| c.is_ascii_digit()) => {
            return s.iter().fold(0u64, |v, &c| v.wrapping_mul(10).wrapping_add(u64::from(c - b'0')));
        }
        _ => s,
    };
    let mut v = 0u64;
    for &c in t {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => break,
        };
        v = (v << 4) | u64::from(d);
    }
    v
}

/// An integer's bytes, `width` of them, little-endian.
pub fn int_to_bytes(v: u64, width: usize) -> Vec<u8> {
    v.to_le_bytes()[..width].to_vec()
}

/// Upper-case hex, no prefix (ToHexString of an integer writes it so).
pub fn hex(v: u64, digits: usize) -> String {
    let mut s = String::new();
    for i in (0..digits).rev() {
        let d = ((v >> (4 * i)) & 0xF) as u8;
        s.push(char::from(if d < 10 { b'0' + d } else { b'A' + d - 10 }));
    }
    s
}

pub fn decimal(mut v: u64) -> String {
    let mut digits = Vec::new();
    loop {
        digits.push(b'0' + (v % 10) as u8);
        v /= 10;
        if v == 0 {
            break;
        }
    }
    digits.reverse();
    String::from_utf8(digits).unwrap()
}

/// Ordering of two buffers or strings as the logical operators compare
/// them (§19.6.70: byte by byte, then by length).
pub fn compare_bytes(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    a.cmp(b)
}
