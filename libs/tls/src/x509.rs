// SPDX-License-Identifier: MIT OR Apache-2.0

//! X.509 certificates (RFC 5280) and the checks a TLS client makes on a
//! server's chain: each certificate signed by the next, ending at a
//! trusted root; every one valid now; issuers are certificate
//! authorities (basic constraints, path length, key usage); the server's
//! certificate is for the host asked for (its subjectAltName, RFC 6125
//! §6, with a wildcard only as the whole leftmost label) and for server
//! authentication if it says what it is for; the name constraints of the
//! authorities above it (RFC 5280 §4.2.1.10: DNS names, IP addresses and
//! directory names) allow its names. A critical extension we do not
//! understand fails the chain.

use alloc::vec::Vec;

use crate::Error;
use crate::crypto::{PublicKey, Scheme, verify};
use crate::der::{self, Der};

// Object identifiers, DER-encoded contents (RFC 5280, RFC 3279, RFC 4055,
// RFC 5480, RFC 5758, RFC 8410).
const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const SHA384_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const SHA512_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
const RSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const EXT_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
const EXT_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const EXT_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
const EXT_NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
/// id-kp-OCSPSigning (RFC 6960 §4.2.2.2) and the TLS feature extension
/// (RFC 7633 §6: must-staple when it lists status_request, 5).
const OCSP_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];
const EXT_TLS_FEATURE: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18];
const ANY_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
/// keyUsage's keyCertSign bit (bit 5, RFC 5280 §4.2.1.3).
const KEY_CERT_SIGN: u16 = 1 << 5;
/// The longest chain looked for.
const MAX_DEPTH: usize = 8;

/// A parsed certificate (borrowing its DER).
#[derive(Clone, Debug)]
pub struct Cert<'a> {
    pub der: &'a [u8],
    tbs: &'a [u8],
    /// How the issuer signed it (None: an algorithm we do not take).
    sig_scheme: Option<Scheme>,
    sig: &'a [u8],
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    /// The serial number (INTEGER contents) and the subject public key's
    /// bits, as OCSP's CertID names them.
    pub serial: &'a [u8],
    pub key_bits: &'a [u8],
    /// extKeyUsage lists OCSP signing.
    ocsp_signing: bool,
    /// The TLS feature extension asks for a stapled status (RFC 7633).
    pub must_staple: bool,
    pub not_before: i64,
    pub not_after: i64,
    /// None: a key type we do not take (the certificate can still be in
    /// a chain we do not use).
    pub key: Option<PublicKey>,
    /// basicConstraints: a CA, and its path length limit.
    ca: Option<(bool, Option<u32>)>,
    key_usage: Option<u16>,
    /// extKeyUsage allows server authentication (None: no extension).
    server_auth: Option<bool>,
    dns_names: Vec<&'a [u8]>,
    ip_addresses: Vec<&'a [u8]>,
    /// Name constraints: (permitted, excluded) subtrees' base names, as
    /// GeneralName elements (tag and value).
    constraints: Option<(Vec<der::Tlv<'a>>, Vec<der::Tlv<'a>>)>,
}

const BAD: Error = Error::BadCertificate("cannot be read");

fn rsa_pss_scheme(params: &[u8]) -> Option<Scheme> {
    // RSASSA-PSS-params (RFC 4055 §3.1): [0] hashAlgorithm, [1]
    // maskGenAlgorithm, [2] saltLength. The hash decides; the others must
    // match TLS's use (MGF1 with the same hash, a salt the hash's length),
    // which `rsa` checks when verifying.
    let mut d = Der::new(params);
    let seq = d.expect(der::SEQUENCE).ok()?;
    let mut p = Der::new(seq);
    // Absent, the hash is SHA-1 (the default): not taken.
    let h = p.optional(der::explicit(0)).ok()??;
    let alg = Der::new(h).expect(der::SEQUENCE).ok()?;
    let oid = Der::new(alg).expect(der::OID).ok()?;
    match oid {
        SHA256 => Some(Scheme::RsaPssSha256),
        SHA384 => Some(Scheme::RsaPssSha384),
        SHA512 => Some(Scheme::RsaPssSha512),
        _ => None,
    }
}

/// The signature scheme an AlgorithmIdentifier names (its contents).
pub(crate) fn scheme_of(alg: &[u8]) -> Result<Option<Scheme>, Error> {
    sig_algorithm(alg)
}

fn sig_algorithm(alg: &[u8]) -> Result<Option<Scheme>, Error> {
    let mut d = Der::new(alg);
    let oid = d.expect(der::OID)?;
    Ok(match oid {
        SHA256_RSA => Some(Scheme::RsaPkcs1Sha256),
        SHA384_RSA => Some(Scheme::RsaPkcs1Sha384),
        SHA512_RSA => Some(Scheme::RsaPkcs1Sha512),
        ECDSA_SHA256 => Some(Scheme::EcdsaP256Sha256),
        ECDSA_SHA384 => Some(Scheme::EcdsaP384Sha384),
        ED25519 => Some(Scheme::Ed25519),
        RSA_PSS => {
            let rest = alg.get(oid.len() + 2..).unwrap_or(&[]);
            rsa_pss_scheme(rest)
        }
        _ => None,
    })
}

fn public_key(spki: &[u8]) -> Result<Option<PublicKey>, Error> {
    let mut d = Der::new(spki);
    let alg = d.expect(der::SEQUENCE)?;
    let key = der::bits(d.expect(der::BIT_STRING)?)?;
    let mut a = Der::new(alg);
    let oid = a.expect(der::OID)?;
    Ok(match oid {
        RSA_ENCRYPTION => Some(PublicKey::Rsa(key.to_vec())),
        EC_PUBLIC_KEY => match a.expect(der::OID)? {
            P256 => Some(PublicKey::P256(key.to_vec())),
            P384 => Some(PublicKey::P384(key.to_vec())),
            _ => None,
        },
        ED25519 => Some(PublicKey::Ed25519(key.try_into().map_err(|_| BAD)?)),
        _ => None,
    })
}

impl<'a> Cert<'a> {
    pub fn parse(der_bytes: &'a [u8]) -> Result<Cert<'a>, Error> {
        let mut outer = Der::new(der_bytes);
        let cert = outer.expect(der::SEQUENCE)?;
        if !outer.is_empty() {
            return Err(BAD);
        }
        let mut c = Der::new(cert);
        let tbs_tlv = c.tlv()?;
        if tbs_tlv.tag != der::SEQUENCE {
            return Err(BAD);
        }
        let outer_alg = c.expect(der::SEQUENCE)?;
        let sig = der::bits(c.expect(der::BIT_STRING)?)?;
        let mut t = Der::new(tbs_tlv.value);
        let version = match t.optional(der::explicit(0))? {
            Some(v) => *Der::new(v).expect(der::INTEGER)?.first().ok_or(BAD)?,
            None => 0,
        };
        let serial = t.expect(der::INTEGER)?;
        let inner_alg = t.expect(der::SEQUENCE)?;
        // RFC 5280 §4.1.1.2: the two algorithm identifiers must agree.
        if inner_alg != outer_alg {
            return Err(Error::BadCertificate("its two signature algorithms differ"));
        }
        let issuer = t.tlv()?.whole;
        let validity = t.expect(der::SEQUENCE)?;
        let mut v = Der::new(validity);
        let not_before = der::time(v.tlv()?)?;
        let not_after = der::time(v.tlv()?)?;
        let subject = t.tlv()?.whole;
        let spki = t.expect(der::SEQUENCE)?;
        let key = public_key(spki)?;
        let key_bits = {
            let mut s = Der::new(spki);
            s.expect(der::SEQUENCE)?;
            der::bits(s.expect(der::BIT_STRING)?)?
        };
        let mut cert = Cert {
            der: der_bytes,
            tbs: tbs_tlv.whole,
            sig_scheme: sig_algorithm(outer_alg)?,
            sig,
            issuer,
            subject,
            serial,
            key_bits,
            ocsp_signing: false,
            must_staple: false,
            not_before,
            not_after,
            key,
            ca: None,
            key_usage: None,
            server_auth: None,
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            constraints: None,
        };
        // Unique identifiers, then the extensions (version 3).
        t.optional(0x81)?;
        t.optional(0x82)?;
        if let Some(exts) = t.optional(der::explicit(3))? {
            if version != 2 {
                return Err(BAD);
            }
            let mut e = Der::new(Der::new(exts).expect(der::SEQUENCE)?);
            while !e.is_empty() {
                let mut x = Der::new(e.expect(der::SEQUENCE)?);
                let oid = x.expect(der::OID)?;
                let critical = match x.optional(der::BOOLEAN)? {
                    Some(b) => b == [0xff],
                    None => false,
                };
                let value = x.expect(der::OCTET_STRING)?;
                if !cert.extension(oid, value)? && critical {
                    return Err(Error::BadCertificate("a critical extension Slate does not know"));
                }
            }
        }
        Ok(cert)
    }

    /// Read a known extension; false if it is not one we know.
    fn extension(&mut self, oid: &[u8], value: &'a [u8]) -> Result<bool, Error> {
        match oid {
            EXT_BASIC_CONSTRAINTS => {
                let mut d = Der::new(Der::new(value).expect(der::SEQUENCE)?);
                let ca = d.optional(der::BOOLEAN)?.is_some_and(|b| b == [0xff]);
                let len = match d.optional(der::INTEGER)? {
                    Some(n) if n.len() <= 4 => Some(n.iter().fold(0u32, |a, &b| (a << 8) | u32::from(b))),
                    Some(_) => return Err(BAD),
                    None => None,
                };
                self.ca = Some((ca, len));
            }
            EXT_KEY_USAGE => {
                let b = Der::new(value).expect(der::BIT_STRING)?;
                let (unused, bytes) = b.split_first().ok_or(BAD)?;
                if *unused > 7 {
                    return Err(BAD);
                }
                // Bit 0 is the first byte's most significant bit.
                let mut bits = 0u16;
                for (i, byte) in bytes.iter().take(2).enumerate() {
                    for j in 0..8 {
                        if byte & (0x80 >> j) != 0 {
                            bits |= 1 << (i * 8 + j);
                        }
                    }
                }
                self.key_usage = Some(bits);
            }
            EXT_EXTENDED_KEY_USAGE => {
                let mut d = Der::new(Der::new(value).expect(der::SEQUENCE)?);
                let mut ok = false;
                while !d.is_empty() {
                    let o = d.expect(der::OID)?;
                    ok |= o == SERVER_AUTH || o == ANY_EXTENDED_KEY_USAGE;
                    self.ocsp_signing |= o == OCSP_SIGNING;
                }
                self.server_auth = Some(ok);
            }
            EXT_NAME_CONSTRAINTS => {
                // NameConstraints: permittedSubtrees [0], excludedSubtrees
                // [1], each GeneralSubtrees: SEQUENCE { base, minimum,
                // maximum } (minimum 0 and no maximum, as RFC 5280 wants).
                let mut d = Der::new(Der::new(value).expect(der::SEQUENCE)?);
                let mut sets = (Vec::new(), Vec::new());
                while !d.is_empty() {
                    let t = d.tlv()?;
                    let into = match t.tag {
                        0xa0 => &mut sets.0,
                        0xa1 => &mut sets.1,
                        _ => return Err(BAD),
                    };
                    let mut subtrees = Der::new(t.value);
                    while !subtrees.is_empty() {
                        let mut s = Der::new(subtrees.expect(der::SEQUENCE)?);
                        into.push(s.tlv()?);
                    }
                }
                self.constraints = Some(sets);
            }
            EXT_TLS_FEATURE => {
                let mut d = Der::new(Der::new(value).expect(der::SEQUENCE)?);
                while !d.is_empty() {
                    self.must_staple |= d.expect(der::INTEGER)? == [5];
                }
            }
            EXT_SUBJECT_ALT_NAME => {
                let mut d = Der::new(Der::new(value).expect(der::SEQUENCE)?);
                while !d.is_empty() {
                    let n = d.tlv()?;
                    match n.tag {
                        0x82 => self.dns_names.push(n.value),
                        0x87 => self.ip_addresses.push(n.value),
                        _ => {}
                    }
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Whether `issuer`'s key signed this certificate.
    fn signed_by(&self, issuer: &Cert<'_>) -> Result<(), Error> {
        let key = issuer.key.as_ref().ok_or(Error::BadCertificate("an issuer key Slate does not take"))?;
        let scheme = self.sig_scheme.ok_or(Error::BadCertificate("a signature algorithm Slate does not take"))?;
        verify(key, scheme, self.tbs, self.sig)
    }

    pub(crate) fn valid_at(&self, now: i64) -> bool {
        self.not_before <= now && now <= self.not_after
    }

    /// Whether `issuer`'s key signed this certificate.
    pub(crate) fn checked_by(&self, issuer: &Cert<'_>) -> bool {
        self.signed_by(issuer).is_ok()
    }

    /// Whether it may sign OCSP responses for its issuer.
    pub(crate) fn ocsp_signing(&self) -> bool {
        self.ocsp_signing
    }

    /// May sign certificates `below` levels down (intermediates under it).
    fn may_issue(&self, below: u32) -> bool {
        match self.ca {
            Some((true, limit)) => {
                limit.is_none_or(|l| below <= l) && self.key_usage.is_none_or(|u| u & KEY_CERT_SIGN != 0)
            }
            _ => false,
        }
    }

    /// Whether this certificate names `host` (RFC 6125 §6: its
    /// subjectAltName only).
    pub fn names(&self, host: &str) -> bool {
        if let Some(ip) = ip_literal(host) {
            return self.ip_addresses.contains(&ip.as_slice());
        }
        let host = host.trim_end_matches('.').as_bytes();
        self.dns_names.iter().any(|n| dns_matches(n, host))
    }
}

/// The relative distinguished names of a Name (each RDN's encoding).
fn rdns(name: &[u8]) -> Option<Vec<&[u8]>> {
    let mut d = Der::new(Der::new(name).expect(der::SEQUENCE).ok()?);
    let mut out = Vec::new();
    while !d.is_empty() {
        out.push(d.tlv().ok()?.whole);
    }
    Some(out)
}

/// Whether name `n` (of the leaf: a GeneralName tag and value) falls in
/// the subtree `base` (the same form): a DNS name in the domain or under
/// it (RFC 5280 §4.2.1.10: "example.com" takes it and its subdomains,
/// ".example.com" only subdomains), an address in the range, a directory
/// name under the base's RDNs. None: another form (not for this base).
fn within(tag: u8, n: &[u8], base: &der::Tlv<'_>) -> Option<bool> {
    if base.tag != tag {
        return None;
    }
    Some(match tag {
        0x82 => {
            let (n, b) = (n.strip_suffix(b".").unwrap_or(n), base.value);
            if b.is_empty() {
                true
            } else if let Some(rest) = b.strip_prefix(b".") {
                n.len() > rest.len()
                    && n[n.len() - rest.len()..].eq_ignore_ascii_case(rest)
                    && n[n.len() - rest.len() - 1] == b'.'
            } else {
                n.eq_ignore_ascii_case(b)
                    || (n.len() > b.len()
                        && n[n.len() - b.len()..].eq_ignore_ascii_case(b)
                        && n[n.len() - b.len() - 1] == b'.')
            }
        }
        // An address and its mask, as many bytes each.
        0x87 => {
            let half = base.value.len() / 2;
            half == n.len()
                && n.iter().zip(&base.value[..half]).zip(&base.value[half..]).all(|((a, b), m)| a & m == b & m)
        }
        _ => match (rdns(n), Der::new(base.value).tlv().ok().and_then(|t| rdns(t.whole))) {
            (Some(n), Some(b)) => n.len() >= b.len() && n[..b.len()] == b[..],
            _ => false,
        },
    })
}

/// Whether `leaf`'s names are allowed by `ca`'s name constraints: none
/// excluded, and every name of a form the permitted subtrees name in one
/// of them.
fn allowed_by(leaf: &Cert<'_>, ca: &Cert<'_>) -> bool {
    let Some((permitted, excluded)) = &ca.constraints else { return true };
    // The subject as a directory name (an [4] element's contents).
    let mut names: Vec<(u8, &[u8])> = leaf.dns_names.iter().map(|n| (0x82, *n)).collect();
    names.extend(leaf.ip_addresses.iter().map(|n| (0x87, *n)));
    names.push((0xa4, leaf.subject));
    for (tag, n) in names {
        if tag == 0xa4 && rdns(n).is_some_and(|r| r.is_empty()) {
            continue;
        }
        if excluded.iter().any(|b| within(tag, n, b) == Some(true)) {
            return false;
        }
        let of_form: Vec<bool> = permitted.iter().filter_map(|b| within(tag, n, b)).collect();
        if !of_form.is_empty() && !of_form.contains(&true) {
            return false;
        }
    }
    true
}

/// `host` as an IP address's bytes, if it is a literal.
fn ip_literal(host: &str) -> Option<Vec<u8>> {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    if h.contains(':') {
        let a = parse_v6(h)?;
        return Some(a.to_vec());
    }
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    parts.iter().map(|p| p.parse::<u8>().ok()).collect()
}

fn parse_v6(s: &str) -> Option<[u8; 16]> {
    let (head, tail) = match s.split_once("::") {
        Some((h, t)) => (h, Some(t)),
        None => (s, None),
    };
    let words = |p: &str| -> Option<Vec<u16>> {
        if p.is_empty() { Some(Vec::new()) } else { p.split(':').map(|w| u16::from_str_radix(w, 16).ok()).collect() }
    };
    let h = words(head)?;
    let t = match tail {
        Some(t) => words(t)?,
        None => Vec::new(),
    };
    if (tail.is_none() && h.len() != 8) || h.len() + t.len() > 8 {
        return None;
    }
    let mut w = [0u16; 8];
    w[..h.len()].copy_from_slice(&h);
    w[8 - t.len()..].copy_from_slice(&t);
    let mut out = [0u8; 16];
    for (i, x) in w.iter().enumerate() {
        out[i * 2..i * 2 + 2].copy_from_slice(&x.to_be_bytes());
    }
    Some(out)
}

/// RFC 6125 §6.4: names compare without case; `*` stands for exactly one
/// whole label, and only the leftmost.
fn dns_matches(pattern: &[u8], host: &[u8]) -> bool {
    let p = pattern.strip_suffix(b".").unwrap_or(pattern);
    if let Some(rest) = p.strip_prefix(b"*.") {
        // At least two labels after the wildcard (no `*.com`).
        if !rest.contains(&b'.') {
            return false;
        }
        let Some(dot) = host.iter().position(|&c| c == b'.') else { return false };
        return dot > 0 && host[dot + 1..].eq_ignore_ascii_case(rest);
    }
    !p.contains(&b'*') && p.eq_ignore_ascii_case(host)
}

/// The trusted certificate authorities.
#[derive(Clone, Debug, Default)]
pub struct Roots {
    certs: Vec<Vec<u8>>,
}

impl Roots {
    pub fn new(certs: Vec<Vec<u8>>) -> Roots {
        Roots { certs }
    }

    /// From PEM bundles (as /etc/ssl/certs holds them).
    pub fn from_pem(text: &[u8]) -> Roots {
        Roots { certs: crate::pem::certificates(text) }
    }

    pub fn add_pem(&mut self, text: &[u8]) {
        self.certs.extend(crate::pem::certificates(text));
    }

    pub fn len(&self) -> usize {
        self.certs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }

    /// Roots whose subject is `name` (and that can be read).
    fn named<'s>(&'s self, name: &[u8]) -> impl Iterator<Item = Cert<'s>> + 's {
        let name = name.to_vec();
        self.certs.iter().filter_map(move |c| Cert::parse(c).ok().filter(|c| c.subject == name.as_slice()))
    }
}

/// Check a server's `chain` (its certificate first, then what it sent to
/// help) for `host` at `now`: the server certificate's key, if the chain
/// leads to a root.
pub fn verify_chain(chain: &[Vec<u8>], roots: &Roots, host: &str, now: i64) -> Result<PublicKey, Error> {
    verify_full(chain, roots, host, now).map(|v| v.key)
}

/// A chain that checked out: the server's key, its certificate's issuer
/// (for OCSP), and whether it must come with a stapled status.
#[derive(Clone, Debug)]
pub struct Verified {
    pub key: PublicKey,
    pub issuer: Vec<u8>,
    pub must_staple: bool,
}

/// [`verify_chain`], with what OCSP needs.
pub fn verify_full(chain: &[Vec<u8>], roots: &Roots, host: &str, now: i64) -> Result<Verified, Error> {
    let leaf_der = chain.first().ok_or(Error::BadCertificate("none sent"))?;
    let leaf = Cert::parse(leaf_der)?;
    if !leaf.names(host) {
        return Err(Error::WrongName);
    }
    if leaf.server_auth == Some(false) {
        return Err(Error::BadCertificate("not for server authentication"));
    }
    if !leaf.valid_at(now) {
        return Err(Error::Expired);
    }
    let key = leaf.key.clone().ok_or(Error::BadCertificate("a key type Slate does not take"))?;
    let must_staple = leaf.must_staple;
    let others: Vec<Cert<'_>> = chain[1..].iter().filter_map(|c| Cert::parse(c).ok()).collect();
    let mut used = alloc::vec![false; others.len()];
    let mut current = leaf;
    let mut expired = false;
    let mut issuer: Option<Vec<u8>> = None;
    let leaf_cert = Cert::parse(leaf_der)?;
    for depth in 0..MAX_DEPTH as u32 {
        // A root that signed it ends the chain, if its constraints allow
        // the server's names too.
        for root in roots.named(current.issuer) {
            if root.valid_at(now) && current.signed_by(&root).is_ok() {
                if !allowed_by(&leaf_cert, &root) {
                    return Err(Error::BadCertificate("a name its authority may not certify"));
                }
                let issuer = issuer.unwrap_or_else(|| root.der.to_vec());
                return Ok(Verified { key, issuer, must_staple });
            }
        }
        // Else an intermediate the server sent.
        let next = others.iter().enumerate().find(|(i, c)| {
            !used[*i] && c.subject == current.issuer && c.may_issue(depth) && current.signed_by(c).is_ok()
        });
        match next {
            Some((i, c)) => {
                if !c.valid_at(now) {
                    expired = true;
                    break;
                }
                if !allowed_by(&leaf_cert, c) {
                    return Err(Error::BadCertificate("a name its authority may not certify"));
                }
                used[i] = true;
                if issuer.is_none() {
                    issuer = Some(c.der.to_vec());
                }
                current = c.clone();
            }
            None => break,
        }
    }
    Err(if expired { Error::Expired } else { Error::UnknownCa })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_names() {
        assert!(dns_matches(b"example.com", b"EXAMPLE.com"));
        assert!(dns_matches(b"*.example.com", b"www.example.com"));
        assert!(!dns_matches(b"*.example.com", b"example.com"));
        assert!(!dns_matches(b"*.example.com", b"a.b.example.com"));
        assert!(!dns_matches(b"*.com", b"example.com"));
        assert!(!dns_matches(b"w*.example.com", b"www.example.com"));
        assert!(!dns_matches(b"example.com", b"example.org"));
        assert_eq!(ip_literal("10.0.2.2"), Some(alloc::vec![10, 0, 2, 2]));
        assert_eq!(ip_literal("[::1]").unwrap()[15], 1);
        assert_eq!(ip_literal("fec0::2").unwrap()[..2], [0xfe, 0xc0]);
        assert_eq!(ip_literal("example.com"), None);
    }

    #[test]
    fn name_constraint_subtrees() {
        let base = |tag: u8, value: &'static [u8]| der::Tlv { tag, value, whole: &[] };
        // A domain takes itself and what is under it, a leading dot only
        // what is under it; labels, not suffixes.
        let d = base(0x82, b"example.com");
        assert_eq!(within(0x82, b"example.com", &d), Some(true));
        assert_eq!(within(0x82, b"www.EXAMPLE.com", &d), Some(true));
        assert_eq!(within(0x82, b"badexample.com", &d), Some(false));
        let dot = base(0x82, b".example.com");
        assert_eq!(within(0x82, b"example.com", &dot), Some(false));
        assert_eq!(within(0x82, b"a.example.com", &dot), Some(true));
        // An address range: 10.0.0.0/8.
        let ip = base(0x87, &[10, 0, 0, 0, 255, 0, 0, 0]);
        assert_eq!(within(0x87, &[10, 1, 2, 3], &ip), Some(true));
        assert_eq!(within(0x87, &[11, 1, 2, 3], &ip), Some(false));
        // Another form is not this base's business.
        assert_eq!(within(0x87, &[10, 1, 2, 3], &d), None);
    }
}
