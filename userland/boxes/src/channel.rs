// SPDX-License-Identifier: MIT OR Apache-2.0

//! The channel between a box and Slate (ADR 0183's phase 4): the one way a
//! box's programs reach SlateOS, and only for a few named requests.
//!
//! Each session has a key of its own: 32 random bytes slate-box writes in
//! a folder bound into the box at `/run/slate-host` (`key`, the box user's,
//! 0600), beside the socket slate-box answers on (`socket`). A connection
//! starts with the box's 32 random bytes, then Slate's; each direction's
//! key is HKDF-SHA-256 (RFC 5869) over the session key, salted with both.
//! Every message after is a frame: its length (4 bytes, big-endian), then
//! the message sealed with ChaCha20-Poly1305 (RFC 8439), its nonce the
//! frame's number in that direction, the direction its associated data.
//! A frame that doesn't open (forged, replayed, out of order, another
//! session's) ends the connection, and slate-box logs it.
//!
//! Requests (text): `info`; `begin\tLABEL\tCOMMAND` and `end` (an install
//! receipt around a command as the box's root). Answers: `ok\tTEXT` or
//! `error\tTEXT`.

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::io;
use slate_tls::crypto::{self, AeadAlg, HashAlg};

/// Where the channel is in a box.
pub const IN_BOX: &str = "/run/slate-host";
/// The longest message.
pub const MAX: usize = 64 << 10;

/// A frame that didn't open, or a connection that ended or failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused;

/// One end's keys and frame counters.
pub struct Sealed {
    send: Vec<u8>,
    recv: Vec<u8>,
    sent: u64,
    received: u64,
    /// The direction byte of what this end sends (`c` the box, `s` Slate).
    me: u8,
}

impl core::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never the keys.
        write!(f, "Sealed {{ sent: {}, received: {} }}", self.sent, self.received)
    }
}

impl Sealed {
    /// The keys for a connection: `secret` the session's, `box_nonce` and
    /// `slate_nonce` the two ends' random bytes; `in_box` for the box's end.
    pub fn new(secret: &[u8], box_nonce: &[u8; 32], slate_nonce: &[u8; 32], in_box: bool) -> Sealed {
        let mut salt = Vec::with_capacity(64);
        salt.extend_from_slice(box_nonce);
        salt.extend_from_slice(slate_nonce);
        let prk = crypto::hkdf_extract(HashAlg::Sha256, &salt, secret);
        let to_slate = crypto::hkdf_expand(HashAlg::Sha256, &prk, b"slate-host box to slate", 32);
        let to_box = crypto::hkdf_expand(HashAlg::Sha256, &prk, b"slate-host slate to box", 32);
        let (send, recv, me) = if in_box { (to_slate, to_box, b'c') } else { (to_box, to_slate, b's') };
        Sealed { send, recv, sent: 0, received: 0, me }
    }

    fn nonce(n: u64) -> [u8; 12] {
        let mut x = [0u8; 12];
        x[4..].copy_from_slice(&n.to_be_bytes());
        x
    }

    /// `msg` as a frame (length and sealed message).
    pub fn seal(&mut self, msg: &[u8]) -> Vec<u8> {
        let mut data = msg.to_vec();
        crypto::seal(AeadAlg::ChaCha20Poly1305, &self.send, &Self::nonce(self.sent), &[self.me], &mut data);
        self.sent += 1;
        let mut frame = (data.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&data);
        frame
    }

    /// A frame's sealed part opened: the message, or Err when it isn't the
    /// next one from the other end under this key.
    pub fn open(&mut self, sealed: &[u8]) -> Result<Vec<u8>, Refused> {
        let other = if self.me == b'c' { b's' } else { b'c' };
        let mut data = sealed.to_vec();
        crypto::open(AeadAlg::ChaCha20Poly1305, &self.recv, &Self::nonce(self.received), &[other], &mut data)
            .map_err(|_| Refused)?;
        self.received += 1;
        Ok(data)
    }
}

/// Read exactly `buf.len()` bytes (Err at the end or on an error).
pub fn read_exact(fd: i32, buf: &mut [u8]) -> Result<(), Refused> {
    let mut got = 0;
    while got < buf.len() {
        match io::read(fd, &mut buf[got..]) {
            Ok(0) => return Err(Refused),
            Ok(n) => got += n,
            Err(slate_rt::Errno::EINTR) => {}
            Err(_) => return Err(Refused),
        }
    }
    Ok(())
}

/// A frame's sealed part from `fd`.
pub fn read_frame(fd: i32) -> Result<Vec<u8>, Refused> {
    let mut len = [0u8; 4];
    read_exact(fd, &mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX + crypto::TAG_LEN {
        return Err(Refused);
    }
    let mut data = alloc::vec![0u8; n];
    read_exact(fd, &mut data)?;
    Ok(data)
}

/// The box's end: connect, agree on keys, ask `request`; the answer.
pub fn ask(request: &str) -> Result<String, String> {
    let secret = slate_rt::fs::read_file(alloc::format!("{IN_BOX}/key").as_bytes())
        .map_err(|e| alloc::format!("the channel's key: {e}"))?;
    let fd = slate_rt::net::connect_path(alloc::format!("{IN_BOX}/socket").as_bytes())
        .map_err(|e| alloc::format!("the channel: {e}"))?;
    let r = (|| {
        let mut mine = [0u8; 32];
        slate_rt::process::random(&mut mine).map_err(|e| alloc::format!("random bytes: {e}"))?;
        io::write_all(fd, &mine).map_err(|e| alloc::format!("the channel: {e}"))?;
        let mut theirs = [0u8; 32];
        read_exact(fd, &mut theirs).map_err(|Refused| String::from("the channel closed"))?;
        let mut s = Sealed::new(&secret, &mine, &theirs, true);
        io::write_all(fd, &s.seal(request.as_bytes())).map_err(|e| alloc::format!("the channel: {e}"))?;
        let frame = read_frame(fd).map_err(|Refused| String::from("the channel closed"))?;
        let answer = s.open(&frame).map_err(|Refused| String::from("an answer that didn't open"))?;
        Ok(String::from(slate_rt::lossy(&answer)))
    })();
    let _ = io::close(fd);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_ends() {
        let secret = [9u8; 32];
        let (b, s) = ([1u8; 32], [2u8; 32]);
        let mut boxed = Sealed::new(&secret, &b, &s, true);
        let mut slate = Sealed::new(&secret, &b, &s, false);
        let f1 = boxed.seal(b"info");
        assert_eq!(slate.open(&f1[4..]).unwrap(), b"info");
        // Replayed: the counter has moved on.
        assert!(slate.open(&f1[4..]).is_err());
        // Forged: a bit changed.
        let mut f2 = boxed.seal(b"begin\thello\tmake install");
        let last = f2.len() - 1;
        f2[last] ^= 1;
        assert!(slate.open(&f2[4..]).is_err());
        // The answer the other way, under the other key.
        let a = slate.seal(b"ok\tbox dev");
        assert_eq!(boxed.open(&a[4..]).unwrap(), b"ok\tbox dev");
        // Another session's key opens nothing.
        let mut other = Sealed::new(&[8u8; 32], &b, &s, false);
        assert!(other.open(&boxed.seal(b"info")[4..]).is_err());
        // Nor does a message reflected back to its sender.
        let mut again = Sealed::new(&secret, &b, &s, true);
        assert!(again.open(&again.clone_seal(b"info")[4..]).is_err());
    }

    impl Sealed {
        fn clone_seal(&self, msg: &[u8]) -> Vec<u8> {
            let mut c = Sealed { send: self.send.clone(), recv: self.recv.clone(), sent: 0, received: 0, me: self.me };
            c.seal(msg)
        }
    }
}
