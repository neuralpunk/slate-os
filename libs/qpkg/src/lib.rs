// SPDX-License-Identifier: MIT OR Apache-2.0

//! quarry's package format (ADR 0025): manifests and versions, the `.qpk`
//! container with its Ed25519 signature, signed repository indexes, and
//! dependency resolution. No I/O: the quarry program reads and writes the
//! bytes.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod archive;
pub mod index;
pub mod manifest;
pub mod resolve;
pub mod sign;
pub mod version;

use alloc::string::String;

pub use archive::{Entry, Kind, Package};
pub use manifest::{Abi, Dep, Manifest};
pub use sign::{KeyId, Keyring, PublicKey, SecretKey};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Malformed input.
    Format(&'static str),
    /// No signature where one is required.
    Unsigned,
    /// Signed by a key that is not trusted.
    UnknownKey(KeyId),
    /// The signature does not match.
    BadSignature,
    /// No available package satisfies the dependency.
    Missing(Dep),
    /// Two requirements disagree: the dependency, and the version already chosen.
    Conflict(Dep, String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Format(why) => write!(f, "{why}"),
            Error::Unsigned => write!(f, "not signed"),
            Error::UnknownKey(id) => write!(f, "signed by an untrusted key {}", slate_hash::hex(id)),
            Error::BadSignature => write!(f, "bad signature"),
            Error::Missing(d) => write!(f, "nothing provides {d}"),
            Error::Conflict(d, v) => write!(f, "{d} conflicts with version {v} already chosen"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn key(n: u8) -> SecretKey {
        SecretKey::from_seed([n; 32])
    }

    fn sample() -> (Manifest, alloc::vec::Vec<Entry>) {
        let mut m = Manifest::new("hello", "1.0");
        m.abi = Abi::Any;
        let entries = vec![
            Entry { path: "usr".into(), kind: Kind::Dir, mode: 0o755, data: vec![] },
            Entry {
                path: "usr/bin/hello".into(),
                kind: Kind::File,
                mode: 0o755,
                data: b"#!/bin/sh\necho hi\n".to_vec(),
            },
            Entry { path: "usr/bin/hi".into(), kind: Kind::Symlink, mode: 0o777, data: b"hello".to_vec() },
        ];
        (m, entries)
    }

    #[test]
    fn signed_packages_round_trip() {
        let (m, entries) = sample();
        let k = key(1);
        let bytes = archive::write(&m, &entries, &k).unwrap();
        let ring = Keyring::new(vec![k.public()]);
        let p = archive::read(&bytes, &ring).unwrap();
        assert_eq!(p.manifest, m);
        assert_eq!(p.entries, entries);
        assert_eq!(p.signer, k.public().id());
        assert_eq!(SecretKey::parse(&k.to_text()).unwrap().public(), k.public());
        assert_eq!(PublicKey::parse(&k.public().to_text()).unwrap(), k.public());
    }

    #[test]
    fn rejects_unsigned_untrusted_and_tampered() {
        let (m, entries) = sample();
        let k = key(1);
        let bytes = archive::write(&m, &entries, &k).unwrap();
        let ring = Keyring::new(vec![k.public()]);
        // Unsigned: everything but the signature record.
        let unsigned = &bytes[..bytes.len() - (1 + 8 + archive::SIGNATURE_LEN)];
        assert_eq!(archive::read(unsigned, &ring).unwrap_err(), Error::Unsigned);
        // Untrusted key.
        let other = Keyring::new(vec![key(2).public()]);
        assert!(matches!(archive::read(&bytes, &other), Err(Error::UnknownKey(_))));
        // Any flipped byte before the signature breaks it.
        for at in [20, 40, bytes.len() / 2, bytes.len() - 80] {
            let mut t = bytes.clone();
            t[at] ^= 1;
            assert!(archive::read(&t, &ring).is_err(), "byte {at}");
        }
        // Trailing data after the signature is refused.
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(archive::read(&extra, &ring).is_err());
    }

    #[test]
    fn signed_index() {
        let (mut m, _) = sample();
        m.file = "pkgs/hello-1.0.noarch.qpk".into();
        m.sha256 = "ab".repeat(32);
        m.size = 10;
        let text = index::to_text(&[m.clone()]);
        assert_eq!(index::parse(&text).unwrap(), [m]);
        let k = key(3);
        let sig = archive::sign_trailer(text.as_bytes(), &k);
        let ring = Keyring::new(vec![k.public()]);
        assert!(archive::verify_detached(text.as_bytes(), &sig, &ring).is_ok());
        let mut changed = text.clone().into_bytes();
        changed[20] ^= 1;
        assert_eq!(archive::verify_detached(&changed, &sig, &ring).unwrap_err(), Error::BadSignature);
        assert!(index::parse("quarry-index 1\n\nname: x\nversion: 1\nabi: any\n").is_err());
    }
}
