// SPDX-License-Identifier: MIT OR Apache-2.0

//! PEM (RFC 7468): the `CERTIFICATE` blocks of a bundle, base64 (RFC 4648
//! §4) decoded.

use alloc::vec::Vec;

/// Every certificate in `text`, as DER. Other blocks and text between
/// them are skipped; a block that does not decode is left out.
pub fn certificates(text: &[u8]) -> Vec<Vec<u8>> {
    let text = core::str::from_utf8(text).unwrap_or("");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let body = &rest[start + 27..];
        let Some(end) = body.find("-----END CERTIFICATE-----") else { break };
        if let Some(der) = base64(&body[..end]) {
            out.push(der);
        }
        rest = &body[end + 25..];
    }
    out
}

/// Base64 with whitespace allowed between characters.
pub fn base64(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let chars: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    if chars.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(chars.len() / 4 * 3);
    for (i, q) in chars.chunks(4).enumerate() {
        let last = i == chars.len() / 4 - 1;
        let pad = q.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &q[..4 - pad] {
            n = (n << 6) | val(c)?;
        }
        n <<= 6 * pad as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes() {
        assert_eq!(base64("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(base64("Zm9v\nYmE=").unwrap(), b"fooba");
        assert_eq!(base64("Zg==").unwrap(), b"f");
        assert!(base64("Zg=").is_none());
        assert!(base64("Zg==Zg==").is_none());
        let pem = b"junk\n-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\nmore\n\
                    -----BEGIN CERTIFICATE-----\nYmFy\n-----END CERTIFICATE-----\n";
        assert_eq!(certificates(pem), [b"foo".to_vec(), b"bar".to_vec()]);
    }
}
