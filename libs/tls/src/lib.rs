// SPDX-License-Identifier: MIT OR Apache-2.0

//! Slate's TLS 1.3 client (RFC 8446; ADR 0053). The protocol, the key
//! schedule, DER and X.509 parsing and certificate path validation (RFC
//! 5280, names per RFC 6125) are ours; the primitives are vetted crates
//! (`crypto`). There is no I/O: [`client::Client`] takes the bytes that
//! arrived and says what to send, so it is tested on the host, and
//! slate-web runs it over a socket.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod client;
pub mod crypto;
pub mod der;
pub mod ocsp;
pub mod pem;
pub mod x509;

/// What went wrong. Each maps to the alert sent (if any).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The server broke the protocol (malformed or unexpected data).
    Illegal(&'static str),
    /// A record that does not open (forged, damaged, or the wrong key).
    BadRecordMac,
    /// A signature that does not verify.
    BadSignature,
    /// A certificate that cannot be read or used.
    BadCertificate(&'static str),
    /// No chain to a trusted certificate authority.
    UnknownCa,
    /// A certificate in the chain is not valid now.
    Expired,
    /// The server's certificate was revoked (its stapled OCSP status).
    Revoked,
    /// The certificate is not for the host asked for.
    WrongName,
    /// The server offered nothing we accept (a version, a cipher suite, a
    /// group).
    Unsupported(&'static str),
    /// The server sent this alert (RFC 8446 §6).
    Alert(u8),
    /// Something that cannot happen did.
    Internal,
}

impl Error {
    /// The alert to send for it (RFC 8446 §6.2).
    pub fn alert(&self) -> u8 {
        match self {
            Error::Illegal(_) => 47,
            Error::BadRecordMac => 20,
            Error::BadSignature => 51,
            Error::BadCertificate(_) => 42,
            Error::UnknownCa => 48,
            Error::Expired => 45,
            Error::Revoked => 44,
            Error::WrongName => 42,
            Error::Unsupported(_) => 40,
            Error::Alert(_) | Error::Internal => 80,
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Illegal(w) => write!(f, "the server broke TLS ({w})"),
            Error::BadRecordMac => write!(f, "a damaged or forged TLS record"),
            Error::BadSignature => write!(f, "a signature does not verify"),
            Error::BadCertificate(w) => write!(f, "a bad certificate ({w})"),
            Error::UnknownCa => write!(f, "the certificate is not from a trusted authority"),
            Error::Expired => write!(f, "a certificate is not valid now (expired, or not yet valid)"),
            Error::Revoked => write!(f, "the certificate was revoked (its authority says so)"),
            Error::WrongName => write!(f, "the certificate is for another name"),
            Error::Unsupported(w) => write!(f, "the server offers nothing Slate accepts ({w})"),
            Error::Alert(a) => write!(f, "the server ended TLS with alert {a} ({})", alert_name(*a)),
            Error::Internal => write!(f, "an internal TLS error"),
        }
    }
}

/// An alert's name (RFC 8446 §6).
pub fn alert_name(a: u8) -> &'static str {
    match a {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        40 => "handshake_failure",
        42 => "bad_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        109 => "missing_extension",
        110 => "unsupported_extension",
        112 => "unrecognized_name",
        116 => "certificate_required",
        120 => "no_application_protocol",
        _ => "unknown",
    }
}
