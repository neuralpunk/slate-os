// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ed25519 signatures over SHA-512 digests (ADR 0025), through the vetted
//! `ed25519-dalek` crate. Keys are stored as hex text.

use alloc::string::String;
use alloc::vec::Vec;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::Error;

/// The first 8 bytes of SHA-256 over a public key.
pub type KeyId = [u8; 8];

pub const SECRET_PREFIX: &str = "quarry-secret-key ";
pub const PUBLIC_PREFIX: &str = "quarry-public-key ";

/// A public key that signatures are checked against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    key: [u8; 32],
}

impl PublicKey {
    pub fn id(&self) -> KeyId {
        slate_hash::sha256(&self.key)[..8].try_into().unwrap()
    }

    /// `quarry-public-key <64 hex digits>`.
    pub fn parse(text: &str) -> Result<PublicKey, Error> {
        let hex = text.trim().strip_prefix(PUBLIC_PREFIX).ok_or(Error::Format("not a quarry public key"))?;
        Ok(PublicKey { key: unhex::<32>(hex.trim())? })
    }

    pub fn to_text(&self) -> String {
        alloc::format!("{PUBLIC_PREFIX}{}\n", slate_hash::hex(&self.key))
    }

    /// Whether `sig` is this key's signature of `digest`.
    pub fn verify(&self, digest: &[u8; 64], sig: &[u8; 64]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&self.key) else { return false };
        vk.verify_strict(digest, &Signature::from_bytes(sig)).is_ok()
    }
}

/// A signing key (the 32-byte seed).
#[derive(Clone)]
pub struct SecretKey {
    seed: [u8; 32],
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

impl SecretKey {
    /// A key from 32 random bytes (the caller supplies the randomness).
    pub fn from_seed(seed: [u8; 32]) -> SecretKey {
        SecretKey { seed }
    }

    pub fn parse(text: &str) -> Result<SecretKey, Error> {
        let hex = text.trim().strip_prefix(SECRET_PREFIX).ok_or(Error::Format("not a quarry secret key"))?;
        Ok(SecretKey { seed: unhex::<32>(hex.trim())? })
    }

    pub fn to_text(&self) -> String {
        alloc::format!("{SECRET_PREFIX}{}\n", slate_hash::hex(&self.seed))
    }

    pub fn public(&self) -> PublicKey {
        PublicKey { key: SigningKey::from_bytes(&self.seed).verifying_key().to_bytes() }
    }

    pub fn sign(&self, digest: &[u8; 64]) -> [u8; 64] {
        SigningKey::from_bytes(&self.seed).sign(digest).to_bytes()
    }
}

fn unhex<const N: usize>(s: &str) -> Result<[u8; N], Error> {
    let b = s.as_bytes();
    if b.len() != N * 2 {
        return Err(Error::Format("bad key length"));
    }
    let digit = |c: u8| -> Result<u8, Error> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(Error::Format("bad hex digit")),
        }
    };
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = digit(b[i * 2])? << 4 | digit(b[i * 2 + 1])?;
    }
    Ok(out)
}

/// A set of trusted keys.
#[derive(Clone, Debug, Default)]
pub struct Keyring {
    keys: Vec<PublicKey>,
}

impl Keyring {
    pub fn new(keys: Vec<PublicKey>) -> Keyring {
        Keyring { keys }
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Check a signature by key id: unknown keys and bad signatures fail.
    pub fn verify(&self, id: &KeyId, digest: &[u8; 64], sig: &[u8; 64]) -> Result<(), Error> {
        let key = self.keys.iter().find(|k| &k.id() == id).ok_or(Error::UnknownKey(*id))?;
        if key.verify(digest, sig) { Ok(()) } else { Err(Error::BadSignature) }
    }
}
