// SPDX-License-Identifier: MIT OR Apache-2.0

//! The cryptography TLS 1.3 needs (ADR 0053). Ours: the hash interface,
//! HMAC (RFC 2104), HKDF (RFC 5869) and the key schedule's labels (RFC
//! 8446 §7.1), and the ChaCha20-Poly1305 AEAD's construction (RFC 8439
//! §2.8) from its two primitives. The primitives themselves are vetted
//! crates: SHA-2 (slate-hash), AES-GCM, ChaCha20, Poly1305, X25519,
//! P-256, ECDSA, RSA and Ed25519.

use alloc::vec;
use alloc::vec::Vec;

use crate::Error;

/// The two hashes TLS 1.3's cipher suites use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
}

impl HashAlg {
    /// The hash's size in bytes.
    pub fn size(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
        }
    }

    fn block(self) -> usize {
        match self {
            HashAlg::Sha256 => 64,
            HashAlg::Sha384 => 128,
        }
    }

    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        let mut h = Hasher::new(self);
        h.update(data);
        h.finish()
    }
}

/// A running hash (the handshake's transcript).
#[derive(Clone, Debug)]
pub enum Hasher {
    Sha256(slate_hash::Sha256),
    Sha384(slate_hash::Sha512),
}

impl Hasher {
    pub fn new(alg: HashAlg) -> Hasher {
        match alg {
            HashAlg::Sha256 => Hasher::Sha256(slate_hash::Sha256::new()),
            HashAlg::Sha384 => Hasher::Sha384(slate_hash::Sha512::new_384()),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha256(h) => h.update(data),
            Hasher::Sha384(h) => h.update(data),
        }
    }

    pub fn finish(self) -> Vec<u8> {
        match self {
            Hasher::Sha256(h) => h.finish().to_vec(),
            Hasher::Sha384(h) => h.finish()[..48].to_vec(),
        }
    }

    /// The hash so far, the running hash going on.
    pub fn peek(&self) -> Vec<u8> {
        self.clone().finish()
    }
}

/// HMAC (RFC 2104).
pub fn hmac(alg: HashAlg, key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut k = if key.len() > alg.block() { alg.hash(key) } else { key.to_vec() };
    k.resize(alg.block(), 0);
    let mut inner = Hasher::new(alg);
    inner.update(&k.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>());
    inner.update(data);
    let mut outer = Hasher::new(alg);
    outer.update(&k.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>());
    outer.update(&inner.finish());
    outer.finish()
}

/// HKDF-Extract (RFC 5869 §2.2).
pub fn hkdf_extract(alg: HashAlg, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let zero = vec![0u8; alg.size()];
    hmac(alg, if salt.is_empty() { &zero } else { salt }, ikm)
}

/// HKDF-Expand (RFC 5869 §2.3).
pub fn hkdf_expand(alg: HashAlg, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut i = 1u8;
    while out.len() < len {
        let mut m = t.clone();
        m.extend_from_slice(info);
        m.push(i);
        t = hmac(alg, prk, &m);
        out.extend_from_slice(&t);
        i += 1;
    }
    out.truncate(len);
    out
}

/// HKDF-Expand-Label (RFC 8446 §7.1): the label gets "tls13 ".
pub fn expand_label(alg: HashAlg, secret: &[u8], label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(4 + label.len() + context.len() + 6);
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(alg, secret, &info, len)
}

/// Derive-Secret (RFC 8446 §7.1), over a transcript's hash.
pub fn derive_secret(alg: HashAlg, secret: &[u8], label: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    expand_label(alg, secret, label, transcript_hash, alg.size())
}

/// The record ciphers of TLS 1.3's cipher suites.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadAlg {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl AeadAlg {
    pub fn key_len(self) -> usize {
        match self {
            AeadAlg::Aes128Gcm => 16,
            AeadAlg::Aes256Gcm | AeadAlg::ChaCha20Poly1305 => 32,
        }
    }
}

pub const TAG_LEN: usize = 16;

/// Seal `data` in place (the tag appended), with `nonce` and `aad`.
pub fn seal(alg: AeadAlg, key: &[u8], nonce: &[u8; 12], aad: &[u8], data: &mut Vec<u8>) {
    use aes_gcm::aead::AeadInPlace;
    use aes_gcm::aead::KeyInit as _;
    match alg {
        AeadAlg::Aes128Gcm => {
            let c = aes_gcm::Aes128Gcm::new_from_slice(key).expect("key length");
            c.encrypt_in_place(nonce.into(), aad, data).expect("sealing in memory");
        }
        AeadAlg::Aes256Gcm => {
            let c = aes_gcm::Aes256Gcm::new_from_slice(key).expect("key length");
            c.encrypt_in_place(nonce.into(), aad, data).expect("sealing in memory");
        }
        AeadAlg::ChaCha20Poly1305 => {
            let (otk, mut stream) = chacha(key, nonce);
            use chacha20::cipher::StreamCipher;
            stream.apply_keystream(data);
            let tag = chacha_tag(&otk, aad, data);
            data.extend_from_slice(&tag);
        }
    }
}

/// Open `data` in place (its tag removed); an error if it was not sealed
/// with this key, nonce and `aad`.
pub fn open(alg: AeadAlg, key: &[u8], nonce: &[u8; 12], aad: &[u8], data: &mut Vec<u8>) -> Result<(), Error> {
    use aes_gcm::aead::AeadInPlace;
    use aes_gcm::aead::KeyInit as _;
    if data.len() < TAG_LEN {
        return Err(Error::BadRecordMac);
    }
    match alg {
        AeadAlg::Aes128Gcm => {
            let c = aes_gcm::Aes128Gcm::new_from_slice(key).map_err(|_| Error::Internal)?;
            c.decrypt_in_place(nonce.into(), aad, data).map_err(|_| Error::BadRecordMac)
        }
        AeadAlg::Aes256Gcm => {
            let c = aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| Error::Internal)?;
            c.decrypt_in_place(nonce.into(), aad, data).map_err(|_| Error::BadRecordMac)
        }
        AeadAlg::ChaCha20Poly1305 => {
            let split = data.len() - TAG_LEN;
            let (otk, mut stream) = chacha(key, nonce);
            let want = chacha_tag(&otk, aad, &data[..split]);
            // Compared in constant time: the tag is a secret until it matches.
            let diff = want.iter().zip(&data[split..]).fold(0u8, |d, (a, b)| d | (a ^ b));
            if diff != 0 {
                return Err(Error::BadRecordMac);
            }
            data.truncate(split);
            use chacha20::cipher::StreamCipher;
            stream.apply_keystream(data);
            Ok(())
        }
    }
}

/// ChaCha20 for RFC 8439's AEAD: the one-time Poly1305 key (block 0) and
/// the stream from block 1.
fn chacha(key: &[u8], nonce: &[u8; 12]) -> ([u8; 32], chacha20::ChaCha20) {
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    let key: &[u8; 32] = key.try_into().expect("a 32-byte key");
    let mut c = chacha20::ChaCha20::new(key.into(), nonce.into());
    let mut otk = [0u8; 32];
    c.apply_keystream(&mut otk);
    c.seek(64u64);
    (otk, c)
}

/// RFC 8439 §2.8: Poly1305 over aad, padding, ciphertext, padding and
/// both lengths.
fn chacha_tag(otk: &[u8; 32], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    use poly1305::universal_hash::KeyInit;
    let pad = |n: usize| (16 - n % 16) % 16;
    let mut m = Vec::with_capacity(aad.len() + ct.len() + 48);
    m.extend_from_slice(aad);
    m.resize(m.len() + pad(aad.len()), 0);
    m.extend_from_slice(ct);
    m.resize(m.len() + pad(ct.len()), 0);
    m.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    m.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    poly1305::Poly1305::new(otk.into()).compute_unpadded(&m).into()
}

/// The key-exchange groups offered (RFC 8446 §4.2.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    X25519,
    Secp256r1,
    Secp384r1,
}

impl Group {
    pub fn code(self) -> u16 {
        match self {
            Group::X25519 => 0x001d,
            Group::Secp256r1 => 0x0017,
            Group::Secp384r1 => 0x0018,
        }
    }

    pub fn from_code(c: u16) -> Option<Group> {
        match c {
            0x001d => Some(Group::X25519),
            0x0017 => Some(Group::Secp256r1),
            0x0018 => Some(Group::Secp384r1),
            _ => None,
        }
    }
}

/// An ephemeral key share: the secret and what goes to the server.
pub struct KeyShare {
    pub group: Group,
    secret: [u8; 32],
    pub public: Vec<u8>,
}

impl core::fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "KeyShare({:?})", self.group)
    }
}

impl KeyShare {
    /// A share in `group` from 32 random bytes.
    pub fn new(group: Group, random: [u8; 32]) -> Result<KeyShare, Error> {
        let public = match group {
            Group::X25519 => {
                curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(random).to_bytes().to_vec()
            }
            Group::Secp256r1 => {
                let sk = p256::SecretKey::from_slice(&random).map_err(|_| Error::Internal)?;
                // An uncompressed point (RFC 8446 §4.2.8.2).
                p256::EncodedPoint::from(sk.public_key()).as_bytes().to_vec()
            }
            Group::Secp384r1 => p384::EncodedPoint::from(p384_secret(&random)?.public_key()).as_bytes().to_vec(),
        };
        Ok(KeyShare { group, secret: random, public })
    }

    /// The shared secret with the server's share.
    pub fn agree(&self, peer: &[u8]) -> Result<Vec<u8>, Error> {
        match self.group {
            Group::X25519 => {
                let p: [u8; 32] = peer.try_into().map_err(|_| Error::Illegal("a bad X25519 share"))?;
                let s = curve25519_dalek::montgomery::MontgomeryPoint(p).mul_clamped(self.secret).to_bytes();
                // An all-zero result means a point of small order (RFC 7748 §6.1).
                if s == [0u8; 32] {
                    return Err(Error::Illegal("a bad X25519 share"));
                }
                Ok(s.to_vec())
            }
            Group::Secp256r1 => {
                let sk = p256::SecretKey::from_slice(&self.secret).map_err(|_| Error::Internal)?;
                let pk = p256::PublicKey::from_sec1_bytes(peer).map_err(|_| Error::Illegal("a bad P-256 share"))?;
                let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
                Ok(shared.raw_secret_bytes().to_vec())
            }
            Group::Secp384r1 => {
                let sk = p384_secret(&self.secret)?;
                let pk = p384::PublicKey::from_sec1_bytes(peer).map_err(|_| Error::Illegal("a bad P-384 share"))?;
                let shared = p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
                Ok(shared.raw_secret_bytes().to_vec())
            }
        }
    }
}

/// A P-384 secret from 32 random bytes: their SHA-384 (48 bytes, a scalar
/// below the order but for a 2^-192 chance, which is refused).
fn p384_secret(random: &[u8; 32]) -> Result<p384::SecretKey, Error> {
    p384::SecretKey::from_slice(&HashAlg::Sha384.hash(random)).map_err(|_| Error::Internal)
}

/// A signature scheme (RFC 8446 §4.2.3), as TLS names it and as
/// certificates use it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    EcdsaP256Sha256,
    EcdsaP256Sha384,
    EcdsaP384Sha256,
    EcdsaP384Sha384,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
    Ed25519,
}

impl Scheme {
    /// An ECDSA scheme's hash.
    pub fn ecdsa_hash(self) -> Option<HashAlg> {
        match self {
            Scheme::EcdsaP256Sha256 | Scheme::EcdsaP384Sha256 => Some(HashAlg::Sha256),
            Scheme::EcdsaP256Sha384 | Scheme::EcdsaP384Sha384 => Some(HashAlg::Sha384),
            _ => None,
        }
    }

    /// Whether TLS lets this scheme sign a handshake with `key` (RFC 8446
    /// §4.2.3: an ECDSA scheme names its curve).
    pub fn fits(self, key: &PublicKey) -> bool {
        matches!(
            (self, key),
            (Scheme::EcdsaP256Sha256, PublicKey::P256(_))
                | (Scheme::EcdsaP384Sha384, PublicKey::P384(_))
                | (Scheme::Ed25519, PublicKey::Ed25519(_))
                | (Scheme::RsaPssSha256 | Scheme::RsaPssSha384 | Scheme::RsaPssSha512, PublicKey::Rsa(_))
        )
    }
}

fn ecdsa_digest(s: Scheme, msg: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    match s.ecdsa_hash() {
        Some(HashAlg::Sha384) => sha2::Sha384::digest(msg).to_vec(),
        _ => sha2::Sha256::digest(msg).to_vec(),
    }
}

/// What TLS 1.3 accepts in CertificateVerify (RFC 8446 §4.4.3: no PKCS#1
/// v1.5), in our order of preference.
pub const HANDSHAKE_SCHEMES: &[(u16, Scheme)] = &[
    (0x0403, Scheme::EcdsaP256Sha256),
    (0x0503, Scheme::EcdsaP384Sha384),
    (0x0807, Scheme::Ed25519),
    (0x0804, Scheme::RsaPssSha256),
    (0x0805, Scheme::RsaPssSha384),
    (0x0806, Scheme::RsaPssSha512),
];

/// What certificates may be signed with as well.
pub const CERT_SCHEMES: &[(u16, Scheme)] =
    &[(0x0401, Scheme::RsaPkcs1Sha256), (0x0501, Scheme::RsaPkcs1Sha384), (0x0601, Scheme::RsaPkcs1Sha512)];

/// A public key from a certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    /// PKCS#1 RSAPublicKey (DER).
    Rsa(Vec<u8>),
    /// An uncompressed or compressed point.
    P256(Vec<u8>),
    P384(Vec<u8>),
    Ed25519([u8; 32]),
}

/// Check `sig` by `key` over `msg` with `scheme`.
pub fn verify(key: &PublicKey, scheme: Scheme, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    use sha2::Digest;
    let bad = Err(Error::BadSignature);
    match (key, scheme) {
        (PublicKey::Rsa(der), s) => {
            use rsa::pkcs1::DecodeRsaPublicKey;
            let k = rsa::RsaPublicKey::from_pkcs1_der(der).map_err(|_| Error::BadCertificate("a bad RSA key"))?;
            // Below 2048 bits is not trusted (as browsers do).
            if rsa::traits::PublicKeyParts::size(&k) < 256 {
                return Err(Error::BadCertificate("an RSA key under 2048 bits"));
            }
            let r = match s {
                Scheme::RsaPkcs1Sha256 => {
                    k.verify(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &sha2::Sha256::digest(msg), sig)
                }
                Scheme::RsaPkcs1Sha384 => {
                    k.verify(rsa::Pkcs1v15Sign::new::<sha2::Sha384>(), &sha2::Sha384::digest(msg), sig)
                }
                Scheme::RsaPkcs1Sha512 => {
                    k.verify(rsa::Pkcs1v15Sign::new::<sha2::Sha512>(), &sha2::Sha512::digest(msg), sig)
                }
                Scheme::RsaPssSha256 => k.verify(rsa::Pss::new::<sha2::Sha256>(), &sha2::Sha256::digest(msg), sig),
                Scheme::RsaPssSha384 => k.verify(rsa::Pss::new::<sha2::Sha384>(), &sha2::Sha384::digest(msg), sig),
                Scheme::RsaPssSha512 => k.verify(rsa::Pss::new::<sha2::Sha512>(), &sha2::Sha512::digest(msg), sig),
                _ => return bad,
            };
            r.map_err(|_| Error::BadSignature)
        }
        // In certificates, an ECDSA algorithm names only its hash (RFC
        // 5758 §3.2): either curve with either hash. TLS's
        // CertificateVerify pairs them (the client checks that).
        (PublicKey::P256(point), s) if s.ecdsa_hash().is_some() => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .map_err(|_| Error::BadCertificate("a bad P-256 key"))?;
            let sig = p256::ecdsa::Signature::from_der(sig).map_err(|_| Error::BadSignature)?;
            vk.verify_prehash(&ecdsa_digest(s, msg), &sig).map_err(|_| Error::BadSignature)
        }
        (PublicKey::P384(point), s) if s.ecdsa_hash().is_some() => {
            use p384::ecdsa::signature::hazmat::PrehashVerifier;
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .map_err(|_| Error::BadCertificate("a bad P-384 key"))?;
            let sig = p384::ecdsa::Signature::from_der(sig).map_err(|_| Error::BadSignature)?;
            vk.verify_prehash(&ecdsa_digest(s, msg), &sig).map_err(|_| Error::BadSignature)
        }
        (PublicKey::Ed25519(k), Scheme::Ed25519) => {
            let vk =
                ed25519_dalek::VerifyingKey::from_bytes(k).map_err(|_| Error::BadCertificate("a bad Ed25519 key"))?;
            let s: [u8; 64] = sig.try_into().map_err(|_| Error::BadSignature)?;
            vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&s)).map_err(|_| Error::BadSignature)
        }
        _ => bad,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: alloc::string::String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn hkdf_rfc5869_case_1() {
        let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = unhex("000102030405060708090a0b0c");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");
        let prk = hkdf_extract(HashAlg::Sha256, &salt, &ikm);
        assert_eq!(prk, unhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
        let okm = hkdf_expand(HashAlg::Sha256, &prk, &info, 42);
        assert_eq!(okm, unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
    }

    #[test]
    fn hmac_rfc4231_case_2() {
        let mac = hmac(HashAlg::Sha384, b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            mac,
            unhex("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649")
        );
    }

    #[test]
    fn chacha20_poly1305_rfc8439() {
        // RFC 8439 §2.8.2.
        let key = unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce: [u8; 12] = unhex("070000004041424344454647").try_into().unwrap();
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut d = pt.to_vec();
        seal(AeadAlg::ChaCha20Poly1305, &key, &nonce, &aad, &mut d);
        assert_eq!(&d[d.len() - 16..], &unhex("1ae10b594f09e26a7e902ecbd0600691")[..]);
        assert_eq!(&d[..8], &unhex("d31a8d34648e60db")[..]);
        open(AeadAlg::ChaCha20Poly1305, &key, &nonce, &aad, &mut d).unwrap();
        assert_eq!(d, pt);
        let mut t = pt.to_vec();
        seal(AeadAlg::ChaCha20Poly1305, &key, &nonce, &aad, &mut t);
        t[3] ^= 1;
        assert_eq!(open(AeadAlg::ChaCha20Poly1305, &key, &nonce, &aad, &mut t), Err(Error::BadRecordMac));
    }

    #[test]
    fn aes_gcm_round_trip() {
        for alg in [AeadAlg::Aes128Gcm, AeadAlg::Aes256Gcm] {
            let key = vec![7u8; alg.key_len()];
            let mut d = b"some record".to_vec();
            seal(alg, &key, &[1; 12], b"hdr", &mut d);
            assert_eq!(d.len(), 11 + TAG_LEN);
            assert!(open(alg, &key, &[1; 12], b"hdx", &mut d.clone()).is_err());
            open(alg, &key, &[1; 12], b"hdr", &mut d).unwrap();
            assert_eq!(d, b"some record");
        }
    }

    #[test]
    fn key_shares_agree() {
        for g in [Group::X25519, Group::Secp256r1] {
            let a = KeyShare::new(g, [3; 32]).unwrap();
            let b = KeyShare::new(g, [5; 32]).unwrap();
            assert_eq!(a.agree(&b.public).unwrap(), b.agree(&a.public).unwrap());
        }
        assert!(KeyShare::new(Group::X25519, [3; 32]).unwrap().agree(&[0; 32]).is_err());
    }
}
