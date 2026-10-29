// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signed Slate programs (ADR 0090). A signed program ends with an
//! 88-byte trailer after its ELF contents:
//!
//! ```text
//! 0   8  "SLATESIG"
//! 8   4  flags (little-endian): ANYWHERE, UPDATER
//! 12  4  zero
//! 16  8  the key's ID (quarry's: SHA-256 of the public key, first 8 bytes)
//! 24  64 Ed25519 signature
//! ```
//!
//! The signature is quarry's (ADR 0025): Ed25519 over a SHA-512 digest,
//! here of the program (everything before the trailer) followed by the
//! trailer's first 24 bytes, so the flags are signed too. ELF loading
//! reads what the program headers name, so the trailer changes nothing
//! else.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;

pub use slate_qpkg::{KeyId, Keyring, PublicKey, SecretKey};

pub const MAGIC: &[u8; 8] = b"SLATESIG";
pub const TRAILER: usize = 88;
/// The part of the trailer the signature covers.
pub const SIGNED_HEADER: usize = 24;

/// The program may run in the Slate domain from outside the system tree.
pub const ANYWHERE: u32 = 1;
/// The program may change the system image (the system grant).
pub const UPDATER: u32 = 2;
/// The program may generate code: map a file executable beside a
/// writable mapping of it (ADR 0093).
pub const JIT: u32 = 4;
/// The program may write the encrypted root's key slots (ADR 0130).
pub const KEYSLOTS: u32 = 8;

/// A trailer as read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Trailer {
    pub flags: u32,
    pub key: KeyId,
    pub sig: [u8; 64],
}

impl Trailer {
    /// The trailer in `b` (the file's last 88 bytes), if it is one.
    pub fn parse(b: &[u8]) -> Option<Trailer> {
        if b.len() != TRAILER || &b[..8] != MAGIC || b[12..16] != [0; 4] {
            return None;
        }
        Some(Trailer {
            flags: u32::from_le_bytes(b[8..12].try_into().ok()?),
            key: b[16..24].try_into().ok()?,
            sig: b[24..88].try_into().ok()?,
        })
    }

    /// The signed header: magic, flags, zero, key ID.
    pub fn header(&self) -> [u8; SIGNED_HEADER] {
        header(self.flags, &self.key)
    }
}

fn header(flags: u32, key: &KeyId) -> [u8; SIGNED_HEADER] {
    let mut h = [0u8; SIGNED_HEADER];
    h[..8].copy_from_slice(MAGIC);
    h[8..12].copy_from_slice(&flags.to_le_bytes());
    h[16..24].copy_from_slice(key);
    h
}

/// The digest of a program and a header, fed in pieces.
#[derive(Debug, Default)]
pub struct Digest(slate_hash::Sha512);

impl Digest {
    pub fn new() -> Digest {
        Digest(slate_hash::Sha512::new())
    }
    /// The program's bytes, in order.
    pub fn update(&mut self, program: &[u8]) {
        self.0.update(program);
    }
    /// The trailer's signed header, last.
    pub fn finish(mut self, header: &[u8; SIGNED_HEADER]) -> [u8; 64] {
        self.0.update(header);
        self.0.finish()
    }
}

/// The program without its trailer, if it has one.
pub fn unsigned(file: &[u8]) -> &[u8] {
    match file.len().checked_sub(TRAILER) {
        Some(at) if Trailer::parse(&file[at..]).is_some() => &file[..at],
        _ => file,
    }
}

/// `file` signed with `key` and `flags` (an old trailer replaced).
pub fn sign(file: &[u8], flags: u32, key: &SecretKey) -> Vec<u8> {
    let program = unsigned(file);
    let id = key.public().id();
    let h = header(flags, &id);
    let mut d = Digest::new();
    d.update(program);
    let sig = key.sign(&d.finish(&h));
    let mut out = Vec::with_capacity(program.len() + TRAILER);
    out.extend_from_slice(program);
    out.extend_from_slice(&h);
    out.extend_from_slice(&sig);
    out
}

/// Why a program is not signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No trailer.
    Unsigned,
    /// Signed by a key not in the keyring.
    UnknownKey(KeyId),
    /// The signature does not match the program.
    BadSignature,
}

/// Check a trailer against the digest of what precedes it: its flags.
pub fn check(t: &Trailer, digest: &[u8; 64], keys: &Keyring) -> Result<u32, Error> {
    keys.verify(&t.key, digest, &t.sig).map_err(|e| match e {
        slate_qpkg::Error::UnknownKey(k) => Error::UnknownKey(k),
        _ => Error::BadSignature,
    })?;
    Ok(t.flags)
}

/// Check a whole file in memory: its flags.
pub fn verify(file: &[u8], keys: &Keyring) -> Result<u32, Error> {
    let at = file.len().checked_sub(TRAILER).ok_or(Error::Unsigned)?;
    let t = Trailer::parse(&file[at..]).ok_or(Error::Unsigned)?;
    let mut d = Digest::new();
    d.update(&file[..at]);
    check(&t, &d.finish(&t.header()), keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> SecretKey {
        SecretKey::from_seed([n; 32])
    }

    #[test]
    fn signed_programs_check_out() {
        let prog: Vec<u8> = (0..10_000u32).map(|i| (i * 7) as u8).collect();
        let k = key(1);
        let keys = Keyring::new(alloc::vec![k.public()]);
        let s = sign(&prog, ANYWHERE | UPDATER, &k);
        assert_eq!(s.len(), prog.len() + TRAILER);
        assert_eq!(&s[..prog.len()], &prog[..]);
        assert_eq!(verify(&s, &keys), Ok(ANYWHERE | UPDATER));
        assert_eq!(unsigned(&s), &prog[..]);
        // Signing again replaces the trailer.
        assert_eq!(sign(&s, 0, &k).len(), s.len());
        assert_eq!(verify(&sign(&s, 0, &k), &keys), Ok(0));
        // Deterministic, as Ed25519 is.
        assert_eq!(sign(&prog, 1, &k), sign(&prog, 1, &k));
    }

    #[test]
    fn tampering_is_caught() {
        let prog = alloc::vec![0x90u8; 4096];
        let k = key(2);
        let keys = Keyring::new(alloc::vec![k.public()]);
        let s = sign(&prog, ANYWHERE, &k);
        let mut body = s.clone();
        body[100] ^= 1;
        assert_eq!(verify(&body, &keys), Err(Error::BadSignature));
        // The flags are signed: UPDATER cannot be added afterwards.
        let mut flags = s.clone();
        let at = flags.len() - TRAILER + 8;
        flags[at] |= UPDATER as u8;
        assert_eq!(verify(&flags, &keys), Err(Error::BadSignature));
        assert_eq!(verify(&prog, &keys), Err(Error::Unsigned));
        let other = Keyring::new(alloc::vec![key(3).public()]);
        assert_eq!(verify(&s, &other), Err(Error::UnknownKey(k.public().id())));
    }

    #[test]
    fn streaming_digest_matches() {
        let prog: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        let k = key(4);
        let s = sign(&prog, 0, &k);
        let t = Trailer::parse(&s[s.len() - TRAILER..]).unwrap();
        let mut d = Digest::new();
        for c in prog.chunks(4093) {
            d.update(c);
        }
        let keys = Keyring::new(alloc::vec![k.public()]);
        assert_eq!(check(&t, &d.finish(&t.header()), &keys), Ok(0));
    }
}
