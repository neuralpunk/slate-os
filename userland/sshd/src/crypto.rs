// SPDX-License-Identifier: MIT OR Apache-2.0

//! The algorithms slate-sshd speaks, on vetted crates (ADR 0030):
//!
//! - key exchange `mlkem768x25519-sha256` (draft-ietf-sshm-mlkem-hybrid-kex;
//!   ML-KEM-768 from the `ml-kem` crate, ADR 0061) and `curve25519-sha256`
//!   (RFC 8731): X25519 through curve25519-dalek's Montgomery form,
//!   SHA-256 from `libs/hash`
//! - host and user keys `ssh-ed25519` (RFC 8709) through ed25519-dalek
//! - the cipher `chacha20-poly1305@openssh.com` (OpenSSH's
//!   PROTOCOL.chacha20poly1305): two ChaCha20 keys (the original 64-bit
//!   nonce variant, nonce = the packet sequence number), one for the
//!   length field and one for the payload, with a Poly1305 tag keyed from
//!   the payload key's first block

use alloc::vec::Vec;

use chacha20::ChaCha20Legacy;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use poly1305::Poly1305;
use poly1305::universal_hash::KeyInit;

use crate::wire::Writer;

pub const KEX_MLKEM: &[u8] = b"mlkem768x25519-sha256";
pub const KEX: &[u8] = b"curve25519-sha256";
pub const KEX_LIBSSH: &[u8] = b"curve25519-sha256@libssh.org";
pub const HOST_KEY: &[u8] = b"ssh-ed25519";
pub const CIPHER: &[u8] = b"chacha20-poly1305@openssh.com";
pub const TAG: usize = 16;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    slate_hash::sha256(data)
}

/// X25519 (RFC 7748 §5): our public value for `secret`, and the shared
/// secret with the peer's public value.
pub fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(*secret).to_bytes()
}

pub fn x25519_shared(secret: &[u8; 32], peer: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint(*peer).mul_clamped(*secret).to_bytes()
}

/// ML-KEM-768 sizes (FIPS 203 table 3): encapsulation key, ciphertext.
pub const MLKEM_EK: usize = 1184;
pub const MLKEM_CT: usize = 1088;

/// Encapsulate a shared secret to the client's ML-KEM-768 key with the
/// 32 random bytes `m` → (ciphertext, shared secret); None for a key that
/// fails FIPS 203's input check.
pub fn mlkem768_encapsulate(ek: &[u8], m: &[u8; 32]) -> Option<(Vec<u8>, [u8; 32])> {
    use ml_kem::EncapsulationKey768;
    let key = ml_kem::Key::<EncapsulationKey768>::try_from(ek).ok()?;
    let ek = EncapsulationKey768::new(&key).ok()?;
    let (ct, shared) = ek.encapsulate_deterministic(&ml_kem::B32::from(*m));
    Some((ct.to_vec(), shared.into()))
}

/// An Ed25519 host key.
pub struct HostKey {
    key: SigningKey,
}

impl HostKey {
    pub fn from_seed(seed: &[u8; 32]) -> HostKey {
        HostKey { key: SigningKey::from_bytes(seed) }
    }

    pub fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// The public key blob: string "ssh-ed25519", string key.
    pub fn blob(&self) -> Vec<u8> {
        Writer::default().string(HOST_KEY).string(&self.public()).finish()
    }

    /// A signature blob: string "ssh-ed25519", string signature.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let sig = self.key.sign(data).to_bytes();
        Writer::default().string(HOST_KEY).string(&sig).finish()
    }
}

/// What a key exchange needs of the host key: its public blob and a
/// signature. The host key itself, or (before authentication, ADR 0061)
/// a request to the privileged process that holds it.
pub trait HostSign {
    fn blob(&self) -> Vec<u8>;
    fn sign(&self, data: &[u8]) -> Vec<u8>;
}

impl HostSign for HostKey {
    fn blob(&self) -> Vec<u8> {
        HostKey::blob(self)
    }
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        HostKey::sign(self, data)
    }
}

impl core::fmt::Debug for HostKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HostKey(..)")
    }
}

/// Check an Ed25519 signature by the key with raw bytes `public`.
pub fn ed25519_verify(public: &[u8], data: &[u8], sig: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (<[u8; 32]>::try_from(public), <[u8; 64]>::try_from(sig)) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return false };
    vk.verify_strict(data, &Signature::from_bytes(&sig)).is_ok()
}

/// One direction of chacha20-poly1305@openssh.com.
#[derive(Clone)]
pub struct Chacha {
    /// The 64 derived bytes it was made from (to hand the connection on).
    pub raw: [u8; 64],
    /// K_2: the payload key (the first half of the 64 derived bytes).
    main: [u8; 32],
    /// K_1: the length key (the second half).
    header: [u8; 32],
}

impl core::fmt::Debug for Chacha {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Chacha(..)")
    }
}

fn stream(key: &[u8; 32], seq: u32) -> ChaCha20Legacy {
    let nonce = u64::from(seq).to_be_bytes();
    ChaCha20Legacy::new(key.into(), &nonce.into())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Chacha {
    pub fn new(key: &[u8; 64]) -> Chacha {
        Chacha { raw: *key, main: key[..32].try_into().unwrap(), header: key[32..].try_into().unwrap() }
    }

    fn poly_key(&self, seq: u32) -> [u8; 32] {
        let mut k = [0u8; 32];
        stream(&self.main, seq).apply_keystream(&mut k);
        k
    }

    /// Encrypt a packet (`length || body`) in place and append its tag.
    pub fn seal(&self, seq: u32, packet: &mut Vec<u8>) {
        stream(&self.header, seq).apply_keystream(&mut packet[..4]);
        let mut c = stream(&self.main, seq);
        c.seek(64u64);
        c.apply_keystream(&mut packet[4..]);
        let tag = Poly1305::new(&self.poly_key(seq).into()).compute_unpadded(packet);
        packet.extend_from_slice(&tag);
    }

    /// The packet length from its encrypted first four bytes.
    pub fn length(&self, seq: u32, enc: &[u8; 4]) -> u32 {
        let mut l = *enc;
        stream(&self.header, seq).apply_keystream(&mut l);
        u32::from_be_bytes(l)
    }

    /// Check the tag of `packet` (`enc length || enc body || tag`) and
    /// return the decrypted body.
    pub fn open(&self, seq: u32, packet: &[u8]) -> Option<Vec<u8>> {
        let (data, tag) = packet.split_at(packet.len().checked_sub(TAG)?);
        let want = Poly1305::new(&self.poly_key(seq).into()).compute_unpadded(data);
        if !ct_eq(&want, tag) {
            return None;
        }
        let mut body = data[4..].to_vec();
        let mut c = stream(&self.main, seq);
        c.seek(64u64);
        c.apply_keystream(&mut body);
        Some(body)
    }
}
