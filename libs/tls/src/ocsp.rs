// SPDX-License-Identifier: MIT OR Apache-2.0

//! OCSP responses (RFC 6960) as servers staple them (RFC 6066 §8, RFC 8446
//! §4.4.2.1; ADR 0137): whether the server's certificate is good, revoked
//! or unknown to its authority, by a response the authority (or a
//! responder it delegated, RFC 6960 §4.2.2.2) signed, about this
//! certificate, and not out of date.

use alloc::vec::Vec;

use crate::Error;
use crate::der::{self, Der};
use crate::x509::{self, Cert};

/// id-pkix-ocsp-basic (RFC 6960 §4.2.1).
const OCSP_BASIC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
/// SHA-1 (RFC 3279 §2.2.1) and SHA-256 (RFC 5758 §2), CertID's hashes.
const SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// How far clocks may disagree (seconds).
const SKEW: i64 = 300;
/// A response with no nextUpdate is taken for this long after its
/// thisUpdate (seconds: four days, about how often authorities sign).
const NO_NEXT_UPDATE: i64 = 4 * 86_400;

/// What a response says of the certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Good,
    Revoked,
    Unknown,
}

const BAD: Error = Error::BadCertificate("an OCSP response that cannot be read");

/// The status `resp` (an OCSPResponse) gives `leaf`, issued by `issuer`,
/// at `now`; an error if it isn't a successful, signed, matching and
/// current response.
pub fn check(resp: &[u8], leaf: &Cert<'_>, issuer: &Cert<'_>, now: i64) -> Result<Status, Error> {
    // OCSPResponse: responseStatus (0: successful), responseBytes [0].
    let mut d = Der::new(Der::new(resp).expect(der::SEQUENCE)?);
    if d.expect(0x0a)? != [0] {
        return Err(Error::BadCertificate("an OCSP response that is not a success"));
    }
    let mut rb = Der::new(Der::new(d.expect(der::explicit(0))?).expect(der::SEQUENCE)?);
    if rb.expect(der::OID)? != OCSP_BASIC {
        return Err(BAD);
    }
    // BasicOCSPResponse: tbsResponseData, signatureAlgorithm, signature,
    // certs [0].
    let mut b = Der::new(Der::new(rb.expect(der::OCTET_STRING)?).expect(der::SEQUENCE)?);
    let tbs = b.tlv()?;
    let alg = b.expect(der::SEQUENCE)?;
    let sig = der::bits(b.expect(der::BIT_STRING)?)?;
    let certs: Vec<&[u8]> = match b.optional(der::explicit(0))? {
        Some(c) => {
            let mut list = Der::new(Der::new(c).expect(der::SEQUENCE)?);
            let mut v = Vec::new();
            while !list.is_empty() {
                v.push(list.tlv()?.whole);
            }
            v
        }
        None => Vec::new(),
    };
    // Signed by the issuer, or by a responder the issuer certified for
    // OCSP signing.
    let scheme = x509::scheme_of(alg)?.ok_or(Error::BadCertificate("an OCSP signature Slate does not take"))?;
    let by_issuer = issuer.key.as_ref().is_some_and(|k| crate::crypto::verify(k, scheme, tbs.whole, sig).is_ok());
    let by_responder = || {
        certs.iter().filter_map(|c| Cert::parse(c).ok()).any(|r| {
            r.ocsp_signing()
                && r.issuer == issuer.subject
                && r.checked_by(issuer)
                && r.valid_at(now)
                && r.key.as_ref().is_some_and(|k| crate::crypto::verify(k, scheme, tbs.whole, sig).is_ok())
        })
    };
    if !by_issuer && !by_responder() {
        return Err(Error::BadSignature);
    }
    // ResponseData: version [0], responderID, producedAt, responses.
    let mut r = Der::new(tbs.value);
    r.optional(der::explicit(0))?;
    r.tlv()?;
    r.tlv()?;
    let mut responses = Der::new(r.expect(der::SEQUENCE)?);
    while !responses.is_empty() {
        let mut s = Der::new(responses.expect(der::SEQUENCE)?);
        // CertID: hash algorithm, the issuer's name and key hashed, serial.
        let mut id = Der::new(s.expect(der::SEQUENCE)?);
        let hash = Der::new(id.expect(der::SEQUENCE)?).expect(der::OID)?;
        let (name_hash, key_hash, serial) =
            (id.expect(der::OCTET_STRING)?, id.expect(der::OCTET_STRING)?, id.expect(der::INTEGER)?);
        let digest = |b: &[u8]| -> Option<Vec<u8>> {
            match hash {
                SHA1 => Some(slate_hash::sha1(b).to_vec()),
                SHA256 => Some(crate::crypto::HashAlg::Sha256.hash(b)),
                _ => None,
            }
        };
        let ours = serial == leaf.serial
            && digest(leaf.issuer).as_deref() == Some(name_hash)
            && digest(issuer.key_bits).as_deref() == Some(key_hash);
        if !ours {
            continue;
        }
        let status = match s.tlv()?.tag {
            0x80 => Status::Good,
            0xa1 => Status::Revoked,
            0x82 => Status::Unknown,
            _ => return Err(BAD),
        };
        let this_update = der::time(s.tlv()?)?;
        let next_update = match s.optional(der::explicit(0))? {
            Some(n) => der::time(Der::new(n).tlv()?)?,
            None => this_update + NO_NEXT_UPDATE,
        };
        if this_update > now + SKEW || next_update < now - SKEW {
            return Err(Error::BadCertificate("an OCSP response out of date"));
        }
        return Ok(status);
    }
    Err(Error::BadCertificate("an OCSP response about another certificate"))
}
