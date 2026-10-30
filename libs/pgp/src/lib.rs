// SPDX-License-Identifier: MIT OR Apache-2.0

//! OpenPGP detached signatures, as far as checking a distribution's
//! release needs (ADR 0183), from RFC 9580:
//!
//! - packets with either header format (§4.2), read until the first
//!   signature (tag 2) or public key (tag 6); partial lengths are refused;
//! - a version 4 signature (§5.2.3) of a binary document (type 0x00),
//!   EdDSA in its legacy form (algorithm 22, r and s as MPIs, §5.2.3.3)
//!   or Ed25519 (algorithm 27, 64 bytes), over SHA-256 or SHA-512;
//!   what is signed is the document, the signature's version through its
//!   hashed subpackets, then `04 FF` and that part's length (§5.2.4);
//! - a version 4 public key (§5.5.2) of either algorithm: legacy EdDSA
//!   names the curve by OID (1.3.6.1.4.1.11591.15.1, Ed25519) and gives
//!   the point as an MPI with the 0x40 prefix (§5.5.5.5); its fingerprint
//!   is SHA-1 over `99`, the body's length in two bytes and the body
//!   (§5.5.4.2).
//!
//! [`sign`] and [`public_key`] make the same kinds of packets, for test
//! distributions (xtask signs the boxes scenario's with a test key).

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;

use ed25519_dalek::{Signature as EdSignature, Signer, SigningKey, VerifyingKey};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes aren't the packets this reads.
    Format(&'static str),
    /// A kind of signature or key this doesn't check.
    Unsupported(&'static str),
    /// The signature was made by another key.
    WrongKey,
    /// The signature doesn't match the document.
    Bad,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Format(w) => write!(f, "not an OpenPGP signature or key: {w}"),
            Error::Unsupported(w) => write!(f, "unsupported OpenPGP signature or key: {w}"),
            Error::WrongKey => f.write_str("signed by another key"),
            Error::Bad => f.write_str("the signature doesn't match"),
        }
    }
}

// Algorithm numbers (RFC 9580 §9.1, §9.5).
const EDDSA_LEGACY: u8 = 22;
const ED25519: u8 = 27;
const SHA256: u8 = 8;
const SHA512: u8 = 10;
/// Ed25519's OID in legacy EdDSA keys (§9.2).
const ED25519_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
// Subpacket types (§5.2.3.7).
const SUB_CREATED: u8 = 2;
const SUB_ISSUER_ID: u8 = 16;
const SUB_ISSUER_FPR: u8 = 33;

/// The first packet of `bytes` with tag `want`: its body.
fn packet(bytes: &[u8], want: u8) -> Result<&[u8], Error> {
    let mut at = 0;
    while at < bytes.len() {
        let ctb = bytes[at];
        if ctb & 0x80 == 0 {
            return Err(Error::Format("a packet header without its high bit"));
        }
        let (tag, len, head) = if ctb & 0x40 == 0 {
            // The old format: the tag in bits 5..2, the length's size in 1..0.
            let tag = (ctb >> 2) & 0x0F;
            let n = match ctb & 3 {
                0 => 1,
                1 => 2,
                2 => 4,
                _ => return Err(Error::Unsupported("an indeterminate length")),
            };
            let l = bytes.get(at + 1..at + 1 + n).ok_or(Error::Format("a cut header"))?;
            (tag, l.iter().fold(0usize, |a, &b| (a << 8) | b as usize), 1 + n)
        } else {
            let tag = ctb & 0x3F;
            let b0 = *bytes.get(at + 1).ok_or(Error::Format("a cut header"))? as usize;
            match b0 {
                0..=191 => (tag, b0, 2),
                192..=223 => {
                    let b1 = *bytes.get(at + 2).ok_or(Error::Format("a cut header"))? as usize;
                    (tag, ((b0 - 192) << 8) + b1 + 192, 3)
                }
                255 => {
                    let l = bytes.get(at + 2..at + 6).ok_or(Error::Format("a cut header"))?;
                    (tag, l.iter().fold(0usize, |a, &b| (a << 8) | b as usize), 6)
                }
                _ => return Err(Error::Unsupported("a partial length")),
            }
        };
        let body = bytes.get(at + head..at + head + len).ok_or(Error::Format("a cut packet"))?;
        if tag == want {
            return Ok(body);
        }
        at += head + len;
    }
    Err(Error::Format("no packet of the kind wanted"))
}

/// An MPI's value (§3.2) at the start of `b`, and the rest.
fn mpi(b: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let bits = u16::from_be_bytes([
        *b.first().ok_or(Error::Format("a cut MPI"))?,
        *b.get(1).ok_or(Error::Format("a cut MPI"))?,
    ]);
    let n = (bits as usize).div_ceil(8);
    let v = b.get(2..2 + n).ok_or(Error::Format("a cut MPI"))?;
    Ok((v, &b[2 + n..]))
}

/// `v` right-aligned in 32 bytes (an MPI drops leading zeros).
fn pad32(v: &[u8]) -> Result<[u8; 32], Error> {
    if v.len() > 32 {
        return Err(Error::Format("an Ed25519 value longer than 32 bytes"));
    }
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(v);
    Ok(out)
}

/// A public key: its fingerprint and Ed25519 point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    pub fingerprint: [u8; 20],
    pub point: [u8; 32],
}

impl Key {
    /// The first public key in `bytes` (a key packet, or a whole
    /// transferable key as `gpg --export` writes it).
    pub fn parse(bytes: &[u8]) -> Result<Key, Error> {
        Key::from_body(packet(bytes, 6)?)
    }

    /// A key from its packet's body.
    pub fn from_body(body: &[u8]) -> Result<Key, Error> {
        if body.first() != Some(&4) {
            return Err(Error::Unsupported("a key that isn't version 4"));
        }
        let alg = *body.get(5).ok_or(Error::Format("a cut key"))?;
        let rest = &body[6..];
        let point = match alg {
            EDDSA_LEGACY => {
                let n = *rest.first().ok_or(Error::Format("a cut key"))? as usize;
                if rest.get(1..1 + n) != Some(ED25519_OID) {
                    return Err(Error::Unsupported("an EdDSA key on a curve other than Ed25519"));
                }
                let (q, _) = mpi(&rest[1 + n..])?;
                if q.len() != 33 || q[0] != 0x40 {
                    return Err(Error::Format("an Ed25519 point without its 0x40 prefix"));
                }
                q[1..].try_into().unwrap()
            }
            ED25519 => rest.get(..32).ok_or(Error::Format("a cut key"))?.try_into().unwrap(),
            _ => return Err(Error::Unsupported("a key that isn't Ed25519")),
        };
        let mut h = slate_hash::Sha1::new();
        h.update(&[0x99, (body.len() >> 8) as u8, body.len() as u8]);
        h.update(body);
        Ok(Key { fingerprint: h.finish(), point })
    }

    /// The fingerprint as 40 hex digits, upper case (as gpg shows it).
    pub fn fingerprint_hex(&self) -> alloc::string::String {
        slate_hash::hex(&self.fingerprint).to_ascii_uppercase()
    }
}

/// A signature's digest, fed the document.
pub enum Hasher {
    Sha256(slate_hash::Sha256),
    Sha512(slate_hash::Sha512),
}

impl core::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Hasher::Sha256(_) => "Hasher(SHA-256)",
            Hasher::Sha512(_) => "Hasher(SHA-512)",
        })
    }
}

impl Hasher {
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha256(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
        }
    }

    fn finish(self) -> Vec<u8> {
        match self {
            Hasher::Sha256(h) => h.finish().to_vec(),
            Hasher::Sha512(h) => h.finish().to_vec(),
        }
    }
}

/// A version 4 signature of a binary document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub hash_alg: u8,
    /// The issuer's fingerprint and key ID, when the signature names them.
    pub issuer_fingerprint: Option<[u8; 20]>,
    pub issuer_id: Option<[u8; 8]>,
    /// When it was made (seconds since 1970), when it says.
    pub created: Option<u32>,
    /// The hashed part: version through the hashed subpackets.
    hashed: Vec<u8>,
    left16: [u8; 2],
    sig: [u8; 64],
}

impl Signature {
    /// The first signature packet in `bytes` (a `.sig` file).
    pub fn parse(bytes: &[u8]) -> Result<Signature, Error> {
        let b = packet(bytes, 2)?;
        if b.first() != Some(&4) {
            return Err(Error::Unsupported("a signature that isn't version 4"));
        }
        let cut = Error::Format("a cut signature");
        let (kind, alg, hash_alg) = (*b.get(1).ok_or(cut)?, *b.get(2).ok_or(cut)?, *b.get(3).ok_or(cut)?);
        if kind != 0x00 {
            return Err(Error::Unsupported("a signature of something other than a binary document"));
        }
        if hash_alg != SHA256 && hash_alg != SHA512 {
            return Err(Error::Unsupported("a digest other than SHA-256 or SHA-512"));
        }
        let hlen = u16::from_be_bytes([*b.get(4).ok_or(cut)?, *b.get(5).ok_or(cut)?]) as usize;
        let hashed_subs = b.get(6..6 + hlen).ok_or(cut)?;
        let hashed = b[..6 + hlen].to_vec();
        let at = 6 + hlen;
        let ulen = u16::from_be_bytes([*b.get(at).ok_or(cut)?, *b.get(at + 1).ok_or(cut)?]) as usize;
        let unhashed_subs = b.get(at + 2..at + 2 + ulen).ok_or(cut)?;
        let at = at + 2 + ulen;
        let left16 = [*b.get(at).ok_or(cut)?, *b.get(at + 1).ok_or(cut)?];
        let rest = &b[at + 2..];
        let sig = match alg {
            EDDSA_LEGACY => {
                let (r, rest) = mpi(rest)?;
                let (s, _) = mpi(rest)?;
                let mut sig = [0u8; 64];
                sig[..32].copy_from_slice(&pad32(r)?);
                sig[32..].copy_from_slice(&pad32(s)?);
                sig
            }
            ED25519 => rest.get(..64).ok_or(cut)?.try_into().unwrap(),
            _ => return Err(Error::Unsupported("a signature that isn't Ed25519")),
        };
        let mut s =
            Signature { hash_alg, issuer_fingerprint: None, issuer_id: None, created: None, hashed, left16, sig };
        // Only the hashed subpackets are the signer's word; the unhashed
        // ones are hints (the key ID).
        s.subpackets(hashed_subs, true)?;
        s.subpackets(unhashed_subs, false)?;
        Ok(s)
    }

    fn subpackets(&mut self, mut b: &[u8], hashed: bool) -> Result<(), Error> {
        while !b.is_empty() {
            let (len, head) = match b[0] {
                l @ 0..=191 => (l as usize, 1),
                l @ 192..=254 => {
                    ((((l as usize) - 192) << 8) + *b.get(1).ok_or(Error::Format("a cut subpacket"))? as usize + 192, 2)
                }
                255 => {
                    let l = b.get(1..5).ok_or(Error::Format("a cut subpacket"))?;
                    (l.iter().fold(0usize, |a, &x| (a << 8) | x as usize), 5)
                }
            };
            let body = b.get(head..head + len).ok_or(Error::Format("a cut subpacket"))?;
            let (&t, data) = body.split_first().ok_or(Error::Format("an empty subpacket"))?;
            match t & 0x7F {
                SUB_CREATED if hashed && data.len() == 4 => {
                    self.created = Some(u32::from_be_bytes(data.try_into().unwrap()))
                }
                SUB_ISSUER_FPR if data.len() == 21 && data[0] == 4 && (hashed || self.issuer_fingerprint.is_none()) => {
                    self.issuer_fingerprint = Some(data[1..].try_into().unwrap());
                }
                SUB_ISSUER_ID if data.len() == 8 && self.issuer_id.is_none() => {
                    self.issuer_id = Some(data.try_into().unwrap());
                }
                _ => {}
            }
            b = &b[head + len..];
        }
        Ok(())
    }

    /// A digest to feed the document to.
    pub fn hasher(&self) -> Hasher {
        if self.hash_alg == SHA256 {
            Hasher::Sha256(slate_hash::Sha256::new())
        } else {
            Hasher::Sha512(slate_hash::Sha512::new())
        }
    }

    /// Check the signature: `h` has been fed the whole document.
    pub fn check(&self, mut h: Hasher, key: &Key) -> Result<(), Error> {
        let names_another = self.issuer_fingerprint.is_some_and(|f| f != key.fingerprint)
            || self.issuer_id.is_some_and(|id| id != key.fingerprint[12..]);
        if names_another {
            return Err(Error::WrongKey);
        }
        h.update(&self.hashed);
        h.update(&[4, 0xFF]);
        h.update(&(self.hashed.len() as u32).to_be_bytes());
        let digest = h.finish();
        if digest[..2] != self.left16 {
            return Err(Error::Bad);
        }
        let vk = VerifyingKey::from_bytes(&key.point).map_err(|_| Error::Format("an Ed25519 point off the curve"))?;
        vk.verify_strict(&digest, &EdSignature::from_bytes(&self.sig)).map_err(|_| Error::Bad)
    }

    /// Check the signature of a document in memory.
    pub fn check_bytes(&self, document: &[u8], key: &Key) -> Result<(), Error> {
        let mut h = self.hasher();
        h.update(document);
        self.check(h, key)
    }
}

/// An old-format packet: tag and body.
fn old_packet(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 3);
    if body.len() < 256 {
        out.extend_from_slice(&[0x80 | (tag << 2), body.len() as u8]);
    } else {
        out.push(0x80 | (tag << 2) | 1);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(body);
    out
}

/// An MPI of `v` (leading zeros dropped).
fn put_mpi(out: &mut Vec<u8>, v: &[u8]) {
    let v = &v[v.iter().position(|&b| b != 0).unwrap_or(v.len())..];
    let bits = match v.first() {
        Some(&b) => (v.len() - 1) * 8 + (8 - b.leading_zeros() as usize),
        None => 0,
    };
    out.extend_from_slice(&(bits as u16).to_be_bytes());
    out.extend_from_slice(v);
}

/// The public key packet (legacy EdDSA) of a 32-byte Ed25519 seed,
/// made at `created`.
pub fn public_key(seed: &[u8; 32], created: u32) -> Vec<u8> {
    let point = SigningKey::from_bytes(seed).verifying_key().to_bytes();
    let mut body = alloc::vec![4];
    body.extend_from_slice(&created.to_be_bytes());
    body.push(EDDSA_LEGACY);
    body.push(ED25519_OID.len() as u8);
    body.extend_from_slice(ED25519_OID);
    let mut q = alloc::vec![0x40];
    q.extend_from_slice(&point);
    put_mpi(&mut body, &q);
    old_packet(6, &body)
}

/// A detached signature (legacy EdDSA over SHA-512) of `document` by the
/// key of `seed`, made at `created`.
pub fn sign(document: &[u8], seed: &[u8; 32], created: u32) -> Vec<u8> {
    let key = Key::parse(&public_key(seed, created)).expect("our own key packet");
    let mut subs = Vec::new();
    subs.extend_from_slice(&[22, SUB_ISSUER_FPR, 4]);
    subs.extend_from_slice(&key.fingerprint);
    subs.extend_from_slice(&[5, SUB_CREATED]);
    subs.extend_from_slice(&created.to_be_bytes());
    let mut hashed = alloc::vec![4, 0x00, EDDSA_LEGACY, SHA512];
    hashed.extend_from_slice(&(subs.len() as u16).to_be_bytes());
    hashed.extend_from_slice(&subs);
    let mut h = slate_hash::Sha512::new();
    h.update(document);
    h.update(&hashed);
    h.update(&[4, 0xFF]);
    h.update(&(hashed.len() as u32).to_be_bytes());
    let digest = h.finish();
    let sig = SigningKey::from_bytes(seed).sign(&digest).to_bytes();
    let mut body = hashed;
    let mut unhashed = alloc::vec![9, SUB_ISSUER_ID];
    unhashed.extend_from_slice(&key.fingerprint[12..]);
    body.extend_from_slice(&(unhashed.len() as u16).to_be_bytes());
    body.extend_from_slice(&unhashed);
    body.extend_from_slice(&digest[..2]);
    put_mpi(&mut body, &sig[..32]);
    put_mpi(&mut body, &sig[32..]);
    old_packet(2, &body)
}

#[cfg(test)]
mod tests;
