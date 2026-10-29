// SPDX-License-Identifier: MIT OR Apache-2.0

//! A DER reader (ITU-T X.690 §8, §10): tag, length, value. Only what
//! certificates use: single-byte tags, definite lengths of up to four
//! bytes, and nothing longer than its container.

use crate::Error;

pub const BOOLEAN: u8 = 0x01;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;
pub const UTC_TIME: u8 = 0x17;
pub const GENERALIZED_TIME: u8 = 0x18;
pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;

/// A context-specific constructed tag `[n]`.
pub const fn explicit(n: u8) -> u8 {
    0xa0 | n
}

/// One element: its tag, its value, and the whole encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
    pub whole: &'a [u8],
}

/// Elements one after another.
#[derive(Clone, Copy, Debug)]
pub struct Der<'a> {
    b: &'a [u8],
}

const BAD: Error = Error::BadCertificate("bad DER");

impl<'a> Der<'a> {
    pub fn new(b: &'a [u8]) -> Der<'a> {
        Der { b }
    }

    pub fn is_empty(&self) -> bool {
        self.b.is_empty()
    }

    pub fn peek(&self) -> Option<u8> {
        self.b.first().copied()
    }

    /// The next element.
    pub fn tlv(&mut self) -> Result<Tlv<'a>, Error> {
        let b = self.b;
        let tag = *b.first().ok_or(BAD)?;
        if tag & 0x1f == 0x1f {
            return Err(BAD);
        }
        let first = *b.get(1).ok_or(BAD)?;
        let (len, head) = if first < 0x80 {
            (usize::from(first), 2)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 4 {
                return Err(BAD);
            }
            let bytes = b.get(2..2 + n).ok_or(BAD)?;
            // DER: the shortest length form.
            if bytes[0] == 0 || (n == 1 && bytes[0] < 0x80) {
                return Err(BAD);
            }
            (bytes.iter().fold(0usize, |l, &x| (l << 8) | usize::from(x)), 2 + n)
        };
        let end = head.checked_add(len).filter(|&e| e <= b.len()).ok_or(BAD)?;
        self.b = &b[end..];
        Ok(Tlv { tag, value: &b[head..end], whole: &b[..end] })
    }

    /// The next element, which must have `tag`; its value.
    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8], Error> {
        let t = self.tlv()?;
        if t.tag != tag {
            return Err(BAD);
        }
        Ok(t.value)
    }

    /// The next element if it has `tag`.
    pub fn optional(&mut self, tag: u8) -> Result<Option<&'a [u8]>, Error> {
        if self.peek() == Some(tag) { self.expect(tag).map(Some) } else { Ok(None) }
    }
}

/// A BIT STRING's bits (whole bytes only, as keys and signatures are).
pub fn bits(v: &[u8]) -> Result<&[u8], Error> {
    match v.split_first() {
        Some((0, rest)) => Ok(rest),
        _ => Err(BAD),
    }
}

/// A time (UTCTime or GeneralizedTime, `Z` only, as RFC 5280 §4.1.2.5
/// requires) in seconds since 1970.
pub fn time(t: Tlv<'_>) -> Result<i64, Error> {
    let s = core::str::from_utf8(t.value).map_err(|_| BAD)?;
    let (year, rest) = match t.tag {
        UTC_TIME if s.len() == 13 => {
            let y: i64 = s[..2].parse().map_err(|_| BAD)?;
            (if y >= 50 { 1900 + y } else { 2000 + y }, &s[2..])
        }
        GENERALIZED_TIME if s.len() == 15 => (s[..4].parse().map_err(|_| BAD)?, &s[4..]),
        _ => return Err(BAD),
    };
    if !rest.ends_with('Z') || !rest[..10].bytes().all(|c| c.is_ascii_digit()) {
        return Err(BAD);
    }
    let n = |i: usize| rest[i..i + 2].parse::<i64>().map_err(|_| BAD);
    let (mo, d, h, mi, sec) = (n(0)?, n(2)?, n(4)?, n(6)?, n(8)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return Err(BAD);
    }
    Ok(days_from_civil(year, mo, d) * 86_400 + h * 3600 + mi * 60 + sec)
}

/// Days from 1970-01-01 to a date of the proleptic Gregorian calendar.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_tlvs() {
        let b = [0x30, 0x06, 0x02, 0x01, 0x05, 0x04, 0x01, 0xff, 0x05, 0x00];
        let mut d = Der::new(&b);
        let seq = d.expect(SEQUENCE).unwrap();
        let mut inner = Der::new(seq);
        assert_eq!(inner.expect(INTEGER).unwrap(), [5]);
        assert_eq!(inner.optional(BOOLEAN).unwrap(), None);
        assert_eq!(inner.expect(OCTET_STRING).unwrap(), [0xff]);
        assert!(inner.is_empty());
        assert_eq!(d.expect(NULL).unwrap(), []);
        // Too long, long form for a short length, indefinite length.
        assert!(Der::new(&[0x04, 0x05, 1]).tlv().is_err());
        assert!(Der::new(&[0x04, 0x81, 0x01, 1]).tlv().is_err());
        assert!(Der::new(&[0x30, 0x80, 0, 0]).tlv().is_err());
        let mut long = std::vec![0x04, 0x81, 0x80];
        long.extend([7u8; 0x80]);
        assert_eq!(Der::new(&long).expect(OCTET_STRING).unwrap().len(), 0x80);
    }

    #[test]
    fn times() {
        let t = |tag, s: &str| time(Tlv { tag, value: s.as_bytes(), whole: &[] });
        assert_eq!(t(UTC_TIME, "700101000000Z"), Ok(0));
        assert_eq!(t(UTC_TIME, "491231235959Z"), Ok(2_524_607_999));
        assert_eq!(t(GENERALIZED_TIME, "20261022120000Z"), Ok(1_792_670_400));
        assert!(t(UTC_TIME, "7001010000Z").is_err());
        assert!(t(GENERALIZED_TIME, "20261322120000Z").is_err());
    }
}
