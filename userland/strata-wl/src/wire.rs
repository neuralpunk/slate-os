// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Wayland wire format (the Wayland protocol documentation, "Wire
//! Format"): a message is the object's id (32 bits), then the message
//! size in bytes (upper 16 bits, header included) and the opcode (lower
//! 16 bits), then the arguments, each a multiple of 4 bytes in the host's
//! byte order. A string is its length including the NUL, the bytes, the
//! NUL and padding; an array its length, the bytes and padding; fixed is
//! a signed 24.8 number; file descriptors travel beside the message
//! (SCM_RIGHTS), not in it.

use alloc::string::String;
use alloc::vec::Vec;

/// A message being built.
#[derive(Debug)]
pub struct Out(Vec<u8>);

fn pad(n: usize) -> usize {
    n.div_ceil(4) * 4
}

impl Out {
    pub fn new(object: u32, opcode: u16) -> Out {
        let mut v = Vec::with_capacity(32);
        v.extend_from_slice(&object.to_ne_bytes());
        v.extend_from_slice(&(u32::from(opcode)).to_ne_bytes());
        Out(v)
    }
    pub fn uint(mut self, x: u32) -> Out {
        self.0.extend_from_slice(&x.to_ne_bytes());
        self
    }
    pub fn int(self, x: i32) -> Out {
        self.uint(x as u32)
    }
    pub fn fixed(self, x: f32) -> Out {
        self.int((x * 256.0) as i32)
    }
    pub fn string(mut self, s: &str) -> Out {
        self.0.extend_from_slice(&((s.len() + 1) as u32).to_ne_bytes());
        self.0.extend_from_slice(s.as_bytes());
        self.0.push(0);
        let n = pad(self.0.len());
        self.0.resize(n, 0);
        self
    }
    /// The message, with its size filled in.
    pub fn done(mut self) -> Vec<u8> {
        let size = self.0.len() as u32;
        let op = u32::from_ne_bytes([self.0[4], self.0[5], self.0[6], self.0[7]]);
        self.0[4..8].copy_from_slice(&((size << 16) | (op & 0xFFFF)).to_ne_bytes());
        self.0
    }
}

/// A message received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Msg {
    pub object: u32,
    pub opcode: u16,
    pub body: Vec<u8>,
}

/// A message whose size the format does not allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadSize;

/// The next whole message at the start of `buf`, removed from it; None if
/// it is not all there.
pub fn next(buf: &mut Vec<u8>) -> Result<Option<Msg>, BadSize> {
    if buf.len() < 8 {
        return Ok(None);
    }
    let object = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let word = u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let size = (word >> 16) as usize;
    if size < 8 || size % 4 != 0 {
        return Err(BadSize);
    }
    if buf.len() < size {
        return Ok(None);
    }
    let body = buf[8..size].to_vec();
    buf.drain(..size);
    Ok(Some(Msg { object, opcode: (word & 0xFFFF) as u16, body }))
}

/// Reading a message's arguments in order.
#[derive(Debug)]
pub struct Args<'a>(&'a [u8]);

impl<'a> Args<'a> {
    pub fn new(body: &'a [u8]) -> Args<'a> {
        Args(body)
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    pub fn uint(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn int(&mut self) -> Option<i32> {
        self.uint().map(|x| x as i32)
    }
    pub fn fixed(&mut self) -> Option<f32> {
        self.int().map(|x| x as f32 / 256.0)
    }
    pub fn string(&mut self) -> Option<String> {
        let n = self.uint()? as usize;
        if n == 0 {
            return Some(String::new());
        }
        let b = self.take(pad(n))?;
        core::str::from_utf8(&b[..n - 1]).ok().map(String::from)
    }
    pub fn array(&mut self) -> Option<&'a [u8]> {
        let n = self.uint()? as usize;
        let b = self.take(pad(n))?;
        Some(&b[..n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let m = Out::new(3, 0).uint(7).string("wl_shm").uint(1).int(-2).fixed(1.5).done();
        // 8 header + 4 + (4 + 8 "wl_shm\0" padded) + 4 + 4 + 4.
        assert_eq!(m.len(), 36);
        assert_eq!(u32::from_ne_bytes([m[4], m[5], m[6], m[7]]), (36 << 16));
        let mut buf = m.clone();
        buf.extend_from_slice(&m[..10]);
        let got = next(&mut buf).unwrap().unwrap();
        assert_eq!((got.object, got.opcode), (3, 0));
        let mut a = Args::new(&got.body);
        assert_eq!(a.uint(), Some(7));
        assert_eq!(a.string().as_deref(), Some("wl_shm"));
        assert_eq!((a.uint(), a.int(), a.fixed()), (Some(1), Some(-2), Some(1.5)));
        assert_eq!(a.uint(), None);
        // The rest waits for its other bytes.
        assert_eq!(next(&mut buf), Ok(None));
        assert_eq!(buf.len(), 10);
        let mut bad = alloc::vec![1, 0, 0, 0, 0, 0, 3, 0];
        assert_eq!(next(&mut bad), Err(BadSize));
    }
}
