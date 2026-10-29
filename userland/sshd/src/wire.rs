// SPDX-License-Identifier: MIT OR Apache-2.0

//! SSH data types (RFC 4251 §5): byte, boolean, uint32, string, mpint and
//! name-list, and base64 (RFC 4648 §4) for keys in text form.

use alloc::string::String;
use alloc::vec::Vec;

/// Building a message.
#[derive(Debug, Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn new(msg: u8) -> Writer {
        Writer(alloc::vec![msg])
    }
    pub fn byte(&mut self, b: u8) -> &mut Self {
        self.0.push(b);
        self
    }
    pub fn bool(&mut self, b: bool) -> &mut Self {
        self.0.push(u8::from(b));
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn string(&mut self, s: &[u8]) -> &mut Self {
        self.u32(s.len() as u32);
        self.0.extend_from_slice(s);
        self
    }
    /// An unsigned integer given as big-endian bytes, as an mpint: no
    /// leading zero bytes, but a zero byte before a set top bit.
    pub fn mpint(&mut self, be: &[u8]) -> &mut Self {
        let start = be.iter().position(|&b| b != 0).unwrap_or(be.len());
        let v = &be[start..];
        if v.first().is_some_and(|&b| b & 0x80 != 0) {
            self.u32(v.len() as u32 + 1);
            self.0.push(0);
        } else {
            self.u32(v.len() as u32);
        }
        self.0.extend_from_slice(v);
        self
    }
    pub fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
    pub fn finish(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.0)
    }
}

/// The message is shorter than its fields say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Short;

/// Reading a message.
#[derive(Debug)]
pub struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b, at: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Short> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.b.len()).ok_or(Short)?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }
    pub fn byte(&mut self) -> Result<u8, Short> {
        Ok(self.take(1)?[0])
    }
    pub fn bool(&mut self) -> Result<bool, Short> {
        Ok(self.byte()? != 0)
    }
    pub fn u32(&mut self) -> Result<u32, Short> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64, Short> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn string(&mut self) -> Result<&'a [u8], Short> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    pub fn name_list(&mut self) -> Result<Vec<&'a [u8]>, Short> {
        let s = self.string()?;
        Ok(if s.is_empty() { Vec::new() } else { s.split(|&c| c == b',').collect() })
    }
    pub fn rest(&self) -> &'a [u8] {
        &self.b[self.at..]
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64(data: &[u8], pad: bool) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        let chars = chunk.len() + 1;
        for i in 0..4 {
            if i < chars {
                out.push(B64[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

pub fn unbase64(text: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for &c in text {
        let v = match c {
            b'=' => break,
            _ => B64.iter().position(|&x| x == c)? as u32,
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}
