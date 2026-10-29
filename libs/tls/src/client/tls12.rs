// SPDX-License-Identifier: MIT OR Apache-2.0

//! TLS 1.2 (RFC 5246), for servers that speak nothing newer (ADR 0135).
//! Only what keeps TLS 1.3's guarantees: ECDHE key exchange (RFC 8422)
//! over X25519 or P-256, AEAD cipher suites (AES-GCM, RFC 5288 and 5289;
//! ChaCha20-Poly1305, RFC 7905), the extended master secret (RFC 7627),
//! the empty renegotiation_info of RFC 5746 (and no renegotiation), and
//! TLS 1.3's downgrade check (RFC 8446 §4.1.3). No static RSA, no CBC, no
//! compression.

use alloc::vec::Vec;

use super::{
    CERTIFICATE, CHANGE_CIPHER_SPEC, Client, DECODE, FINISHED, HANDSHAKE, Keys, MAX_PLAIN, Reader, State, message,
    put24, record,
};
use crate::Error;
use crate::crypto::{self, AeadAlg, Group, HashAlg, Hasher, KeyShare, PublicKey, Scheme, TAG_LEN};
use crate::x509;

// Handshake messages TLS 1.2 adds (RFC 5246 §7.4).
pub(super) const HELLO_REQUEST: u8 = 0;
const SERVER_KEY_EXCHANGE: u8 = 12;
const CERTIFICATE_REQUEST: u8 = 13;
const SERVER_HELLO_DONE: u8 = 14;
const CLIENT_KEY_EXCHANGE: u8 = 16;
const CERTIFICATE_STATUS: u8 = 22;
// Extensions a TLS 1.2 server may answer (RFC 8422 §5.2, RFC 7627 §5.1,
// RFC 5746 §3.6, RFC 6066 §3).
pub(super) const EC_POINT_FORMATS: u16 = 11;
pub(super) const EXTENDED_MASTER_SECRET: u16 = 23;
pub(super) const RENEGOTIATION_INFO: u16 = 0xff01;
const SERVER_NAME: u16 = 0;
const STATUS_REQUEST: u16 = 5;
/// The last eight bytes of a TLS 1.3 server's random when it settles for
/// 1.2 (RFC 8446 §4.1.3): a client that offered 1.3 must refuse it.
const DOWNGRADE_12: &[u8; 8] = b"DOWNGRD\x01";
/// The alert a client sends to a HelloRequest it won't follow (RFC 5246
/// §7.2.2: no_renegotiation, a warning).
const NO_RENEGOTIATION: u8 = 100;

/// Which kind of key the certificate must hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kx {
    Ecdsa,
    Rsa,
}

/// The TLS 1.2 cipher suites offered, after 1.3's, in order of preference
/// (codes from RFC 5289 §3.2 and RFC 7905 §2).
pub(super) const SUITES12: &[(u16, AeadAlg, HashAlg, Kx)] = &[
    (0xc02b, AeadAlg::Aes128Gcm, HashAlg::Sha256, Kx::Ecdsa),
    (0xc02f, AeadAlg::Aes128Gcm, HashAlg::Sha256, Kx::Rsa),
    (0xcca9, AeadAlg::ChaCha20Poly1305, HashAlg::Sha256, Kx::Ecdsa),
    (0xcca8, AeadAlg::ChaCha20Poly1305, HashAlg::Sha256, Kx::Rsa),
    (0xc02c, AeadAlg::Aes256Gcm, HashAlg::Sha384, Kx::Ecdsa),
    (0xc030, AeadAlg::Aes256Gcm, HashAlg::Sha384, Kx::Rsa),
];

/// What a TLS 1.2 handshake keeps.
#[derive(Debug)]
pub(super) struct Tls12 {
    kx: Kx,
    server_random: [u8; 32],
    ems: bool,
    master: Vec<u8>,
    /// The server's key share, from ServerKeyExchange.
    server_share: Option<(Group, Vec<u8>)>,
    cert_requested: bool,
    /// The server's keys, used from its ChangeCipherSpec on.
    pending_read: Option<Keys>,
}

/// TLS 1.2's PRF (RFC 5246 §5): P_hash over HMAC with the suite's hash.
pub fn prf(hash: HashAlg, secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut s = Vec::with_capacity(label.len() + seed.len());
    s.extend_from_slice(label);
    s.extend_from_slice(seed);
    let mut out = Vec::with_capacity(len + hash.size());
    let mut a = crypto::hmac(hash, secret, &s);
    while out.len() < len {
        let mut m = a.clone();
        m.extend_from_slice(&s);
        out.extend(crypto::hmac(hash, secret, &m));
        a = crypto::hmac(hash, secret, &a);
    }
    out.truncate(len);
    out
}

/// Whether TLS 1.2 lets `scheme` sign a ServerKeyExchange with `key`: an
/// ECDSA scheme there names only its hash (RFC 5246 §7.4.1.4.1), and RSA
/// may use PKCS#1 v1.5.
fn fits12(scheme: Scheme, key: &PublicKey) -> bool {
    match key {
        PublicKey::Rsa(_) => matches!(
            scheme,
            Scheme::RsaPkcs1Sha256
                | Scheme::RsaPkcs1Sha384
                | Scheme::RsaPkcs1Sha512
                | Scheme::RsaPssSha256
                | Scheme::RsaPssSha384
                | Scheme::RsaPssSha512
        ),
        PublicKey::P256(_) | PublicKey::P384(_) => scheme.ecdsa_hash().is_some(),
        PublicKey::Ed25519(_) => scheme == Scheme::Ed25519,
    }
}

/// A record's keys from the key block: the AEAD's key and its fixed IV
/// (GCM's 4-byte salt, followed by zeros for the explicit part; all 12
/// bytes for ChaCha20-Poly1305).
fn keys(key: &[u8], iv: &[u8]) -> Keys {
    let mut v = [0u8; 12];
    v[..iv.len()].copy_from_slice(iv);
    Keys { secret: Vec::new(), key: key.to_vec(), iv: v, seq: 0 }
}

fn iv_len(aead: AeadAlg) -> usize {
    if aead == AeadAlg::ChaCha20Poly1305 { 12 } else { 4 }
}

/// The additional data a TLS 1.2 AEAD record is sealed with (RFC 5246
/// §6.2.3.3): the sequence number, the type, the version, the
/// plaintext's length.
fn aad(seq: u64, kind: u8, len: usize) -> [u8; 13] {
    let mut a = [0u8; 13];
    a[..8].copy_from_slice(&seq.to_be_bytes());
    a[8] = kind;
    a[9..11].copy_from_slice(&0x0303u16.to_be_bytes());
    a[11..13].copy_from_slice(&(len as u16).to_be_bytes());
    a
}

/// Open a TLS 1.2 record (`rec`: header and body).
pub(super) fn open(aead: AeadAlg, k: &mut Keys, rec: &[u8]) -> Result<Vec<u8>, Error> {
    let (kind, body) = (rec[0], &rec[5..]);
    let seq = k.seq;
    let (nonce, ct) = if aead == AeadAlg::ChaCha20Poly1305 {
        (k.nonce(), body)
    } else {
        // GCM: the salt, then the record's explicit nonce.
        if body.len() < 8 {
            return Err(Error::BadRecordMac);
        }
        k.seq += 1;
        let mut n = k.iv;
        n[4..].copy_from_slice(&body[..8]);
        (n, &body[8..])
    };
    let len = ct.len().checked_sub(TAG_LEN).ok_or(Error::BadRecordMac)?;
    if len > MAX_PLAIN {
        return Err(Error::Illegal("a record too long"));
    }
    let mut d = ct.to_vec();
    crypto::open(aead, &k.key, &nonce, &aad(seq, kind, len), &mut d)?;
    Ok(d)
}

/// Seal `data` as TLS 1.2 records of `kind`.
pub(super) fn seal(aead: AeadAlg, k: &mut Keys, kind: u8, data: &[u8], out: &mut Vec<u8>) {
    for chunk in data.chunks(MAX_PLAIN) {
        let seq = k.seq;
        let nonce = k.nonce();
        let mut d = chunk.to_vec();
        crypto::seal(aead, &k.key, &nonce, &aad(seq, kind, chunk.len()), &mut d);
        // GCM's explicit nonce is the sequence number (RFC 5288 §3).
        let explicit: &[u8] = if aead == AeadAlg::ChaCha20Poly1305 { &[] } else { &nonce[4..] };
        out.push(kind);
        out.extend_from_slice(&0x0303u16.to_be_bytes());
        out.extend_from_slice(&((explicit.len() + d.len()) as u16).to_be_bytes());
        out.extend_from_slice(explicit);
        out.extend_from_slice(&d);
    }
}

impl Client {
    /// A TLS 1.2 ServerHello (its fields read by the caller): the suite,
    /// the extensions it may answer, the downgrade check.
    pub(super) fn server_hello12(
        &mut self,
        msg: &[u8],
        random: &[u8],
        suite_code: u16,
        exts: &[(u16, &[u8])],
    ) -> Result<(), Error> {
        // A TLS 1.3 server that settles for 1.2 says so; we offered 1.3,
        // so someone took it out (RFC 8446 §4.1.3).
        if random[24..] == DOWNGRADE_12[..] {
            return Err(Error::Illegal("a downgrade from TLS 1.3"));
        }
        let (_, aead, hash, kx) =
            *SUITES12.iter().find(|(c, ..)| *c == suite_code).ok_or(Error::Illegal("a cipher suite not offered"))?;
        let mut ems = false;
        for (kind, body) in exts {
            match *kind {
                RENEGOTIATION_INFO if *body != [0] => return Err(Error::Illegal("a renegotiation to follow")),
                RENEGOTIATION_INFO | SERVER_NAME | EC_POINT_FORMATS => {}
                // A CertificateStatus will follow its Certificate.
                STATUS_REQUEST => self.status_promised = true,
                EXTENDED_MASTER_SECRET => ems = true,
                _ => return Err(Error::Illegal("an extension the server may not send")),
            }
        }
        self.suite = Some((aead, hash));
        let mut t = Hasher::new(hash);
        t.update(&self.first_hello);
        t.update(msg);
        self.transcript = Some(t);
        self.tls12 = Some(Tls12 {
            kx,
            server_random: random.try_into().unwrap(),
            ems,
            master: Vec::new(),
            server_share: None,
            cert_requested: false,
            pending_read: None,
        });
        self.state = State::Certificate12;
        Ok(())
    }

    fn t12(&mut self) -> Result<&mut Tls12, Error> {
        self.tls12.as_mut().ok_or(Error::Internal)
    }

    /// The handshake messages of TLS 1.2, by state.
    pub(super) fn handshake12(&mut self, msg: &[u8]) -> Result<(), Error> {
        let (kind, body) = (msg[0], &msg[4..]);
        match (self.state, kind) {
            (State::Certificate12, CERTIFICATE) => {
                let mut r = Reader { b: body };
                let mut list = Reader { b: r.vec24()? };
                r.done()?;
                let mut chain = Vec::new();
                while !list.b.is_empty() {
                    chain.push(list.vec24()?.to_vec());
                }
                let v = x509::verify_full(&chain, &self.roots, &self.host, self.now)?;
                let key = v.key;
                (self.issuer, self.must_staple) = (v.issuer, v.must_staple);
                let want = self.t12()?.kx;
                let ok = match key {
                    PublicKey::Rsa(_) => want == Kx::Rsa,
                    _ => want == Kx::Ecdsa,
                };
                if !ok {
                    return Err(Error::Illegal("a certificate key for another cipher suite"));
                }
                self.server_key = Some(key);
                self.chain = chain;
                self.transcript()?.update(msg);
                self.state = State::KeyExchange12;
                Ok(())
            }
            (State::KeyExchange12, CERTIFICATE_STATUS) if self.status_promised => {
                self.status_promised = false;
                self.stapled(body)?;
                self.transcript()?.update(msg);
                Ok(())
            }
            (State::KeyExchange12, SERVER_KEY_EXCHANGE) => {
                self.staple_needed()?;
                self.server_key_exchange(msg)
            }
            (State::HelloDone12, CERTIFICATE_REQUEST) => {
                // Certificate types, signature algorithms, authorities:
                // none of ours is given (an empty Certificate goes back).
                let mut r = Reader { b: body };
                r.vec8()?;
                r.vec16()?;
                r.vec16()?;
                r.done()?;
                self.t12()?.cert_requested = true;
                self.transcript()?.update(msg);
                Ok(())
            }
            (State::HelloDone12, SERVER_HELLO_DONE) => {
                if !body.is_empty() {
                    return Err(DECODE);
                }
                self.transcript()?.update(msg);
                self.client_flight12()
            }
            (State::Finished12, FINISHED) => self.finished12(msg),
            // Renegotiation isn't followed (RFC 5746 makes it safe to say no).
            (State::Connected, HELLO_REQUEST) => {
                self.send(super::ALERT, &[1, NO_RENEGOTIATION]);
                Ok(())
            }
            _ => Err(Error::Illegal("an unexpected handshake message")),
        }
    }

    /// ServerKeyExchange (RFC 8422 §5.4): a named curve, the server's
    /// point, signed with the certificate's key over both randoms and the
    /// parameters.
    fn server_key_exchange(&mut self, msg: &[u8]) -> Result<(), Error> {
        let body = &msg[4..];
        let mut r = Reader { b: body };
        if r.u8()? != 3 {
            return Err(Error::Illegal("key exchange parameters not a named curve"));
        }
        let group = Group::from_code(r.u16()?).ok_or(Error::Unsupported("a key exchange group"))?;
        let point = r.vec8()?.to_vec();
        let params = &body[..body.len() - r.b.len()];
        let code = r.u16()?;
        let sig = r.vec16()?;
        r.done()?;
        let scheme = crypto::HANDSHAKE_SCHEMES
            .iter()
            .chain(crypto::CERT_SCHEMES)
            .find(|(c, _)| *c == code)
            .map(|(_, s)| *s)
            .ok_or(Error::Illegal("a signature scheme not offered"))?;
        let key = self.server_key.as_ref().ok_or(Error::Internal)?;
        if !fits12(scheme, key) {
            return Err(Error::Illegal("a signature scheme that does not fit the key"));
        }
        let mut signed = Vec::with_capacity(64 + params.len());
        signed.extend_from_slice(&self.random);
        signed.extend_from_slice(&self.t12()?.server_random);
        signed.extend_from_slice(params);
        let key = self.server_key.as_ref().ok_or(Error::Internal)?;
        crypto::verify(key, scheme, &signed, sig).map_err(|_| Error::BadSignature)?;
        self.t12()?.server_share = Some((group, point));
        self.transcript()?.update(msg);
        self.state = State::HelloDone12;
        Ok(())
    }

    /// Our flight: an empty Certificate if one was asked for,
    /// ClientKeyExchange, ChangeCipherSpec, Finished; the keys from the
    /// master secret.
    fn client_flight12(&mut self) -> Result<(), Error> {
        let (aead, hash) = self.suite.ok_or(Error::Internal)?;
        let (group, point) = self.t12()?.server_share.take().ok_or(Error::Illegal("no ServerKeyExchange"))?;
        // Our share in the server's group: the hello's, or a fresh one.
        if self.share.group != group {
            self.share = KeyShare::new(group, self.spare)?;
        }
        let shared = self.share.agree(&point)?;
        if self.t12()?.cert_requested {
            let mut b = Vec::new();
            put24(&mut b, 0);
            let m = message(CERTIFICATE, &b);
            self.transcript()?.update(&m);
            self.send(HANDSHAKE, &m);
        }
        let mut cke = Vec::with_capacity(self.share.public.len() + 1);
        cke.push(self.share.public.len() as u8);
        cke.extend_from_slice(&self.share.public);
        let cke = message(CLIENT_KEY_EXCHANGE, &cke);
        self.transcript()?.update(&cke);
        self.send(HANDSHAKE, &cke);
        let server_random = self.t12()?.server_random;
        let master = if self.t12()?.ems {
            // The session hash: the handshake through ClientKeyExchange.
            let session = self.transcript()?.peek();
            prf(hash, &shared, b"extended master secret", &session, 48)
        } else {
            let mut seed = self.random.to_vec();
            seed.extend_from_slice(&server_random);
            prf(hash, &shared, b"master secret", &seed, 48)
        };
        // The key block (RFC 5246 §6.3): the client's key, the server's,
        // the client's IV, the server's.
        let (kl, il) = (aead.key_len(), iv_len(aead));
        let mut seed = server_random.to_vec();
        seed.extend_from_slice(&self.random);
        let block = prf(hash, &master, b"key expansion", &seed, 2 * (kl + il));
        let write = keys(&block[..kl], &block[2 * kl..2 * kl + il]);
        let read = keys(&block[kl..2 * kl], &block[2 * kl + il..]);
        self.output.extend(record(CHANGE_CIPHER_SPEC, 0x0303, &[1]));
        self.write = Some(write);
        let th = self.transcript()?.peek();
        let fin = message(FINISHED, &prf(hash, &master, b"client finished", &th, 12));
        self.transcript()?.update(&fin);
        self.send(HANDSHAKE, &fin);
        let t = self.t12()?;
        t.master = master;
        t.pending_read = Some(read);
        self.state = State::ChangeCipherSpec12;
        Ok(())
    }

    /// The server's ChangeCipherSpec: its keys from now on.
    pub(super) fn change_cipher_spec12(&mut self, body: &[u8]) -> Result<(), Error> {
        if self.state != State::ChangeCipherSpec12 || body != [1] {
            return Err(Error::Illegal("an unexpected change_cipher_spec"));
        }
        let k = self.t12()?.pending_read.take().ok_or(Error::Internal)?;
        self.set_read(k);
        self.state = State::Finished12;
        Ok(())
    }

    fn finished12(&mut self, msg: &[u8]) -> Result<(), Error> {
        let hash = self.hash()?;
        let th = self.transcript()?.peek();
        let want = prf(hash, &self.t12()?.master, b"server finished", &th, 12);
        let got = &msg[4..];
        let diff = want.iter().zip(got).fold((want.len() != got.len()) as u8, |d, (a, b)| d | (a ^ b));
        if diff != 0 {
            return Err(Error::BadSignature);
        }
        self.transcript()?.update(msg);
        self.state = State::Connected;
        Ok(())
    }

    /// A TLS 1.2 record (after the server's ChangeCipherSpec, sealed).
    pub(super) fn record12(&mut self, kind: u8, rec: &[u8]) -> Result<(u8, Vec<u8>), Error> {
        let (aead, _) = self.suite.ok_or(Error::Internal)?;
        match &mut self.read {
            None => Ok((kind, rec[5..].to_vec())),
            Some(k) => Ok((kind, open(aead, k, rec)?)),
        }
    }
}
