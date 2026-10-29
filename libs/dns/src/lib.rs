// SPDX-License-Identifier: MIT OR Apache-2.0

//! DNS messages from RFC 1035 §4: building a recursive query for a host's
//! IPv4 or IPv6 addresses (type A, class IN; type AAAA, RFC 3596) and
//! reading the answer, following CNAMEs within the response; reading a
//! query's question and an answer's lifetime (for a cache), and building
//! replies. No I/O; the caller sends the bytes over UDP to a name server
//! (port 53) and passes the reply back.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;

pub const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
/// Header flag: recursion desired (§4.1.1).
const RD: u16 = 1 << 8;
/// Header flag: this is a response.
const QR: u16 = 1 << 15;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The name cannot be encoded (empty label, label over 63 bytes, name over 253).
    BadName,
    /// The reply is not a well-formed answer to our query.
    Malformed,
    /// The server reported an error (RCODE, §4.1.1): 3 is "no such name".
    Rcode(u8),
}

/// A query with `id` for the A records of `name`.
pub fn query(id: u16, name: &str) -> Result<Vec<u8>, Error> {
    query_type(id, name, TYPE_A)
}

/// A query with `id` for the records of `qtype` (class IN) of `name`.
pub fn query_type(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, Error> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return Err(Error::BadName);
    }
    let mut m = Vec::with_capacity(18 + name.len());
    for v in [id, RD, 1, 0, 0, 0] {
        m.extend_from_slice(&v.to_be_bytes());
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(Error::BadName);
        }
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(m)
}

fn u16_at(m: &[u8], at: usize) -> Result<u16, Error> {
    m.get(at..at + 2).map(|b| u16::from_be_bytes([b[0], b[1]])).ok_or(Error::Malformed)
}

/// Read a (possibly compressed, §4.1.4) name at `at`; returns it in
/// lowercase and the offset after it in the message.
fn read_name(m: &[u8], mut at: usize) -> Result<(Vec<u8>, usize), Error> {
    let mut name = Vec::new();
    let mut end = None;
    for _ in 0..128 {
        let len = *m.get(at).ok_or(Error::Malformed)?;
        match len >> 6 {
            0 if len == 0 => return Ok((name, end.unwrap_or(at + 1))),
            0 => {
                let label = m.get(at + 1..at + 1 + usize::from(len)).ok_or(Error::Malformed)?;
                if !name.is_empty() {
                    name.push(b'.');
                }
                name.extend(label.iter().map(u8::to_ascii_lowercase));
                at += 1 + usize::from(len);
            }
            3 => {
                let ptr = usize::from(u16_at(m, at)? & 0x3fff);
                end.get_or_insert(at + 2);
                at = ptr;
            }
            _ => return Err(Error::Malformed),
        }
    }
    Err(Error::Malformed) // A pointer loop.
}

/// The IPv4 addresses in `reply` to the query with `id` for `name`.
pub fn answer(reply: &[u8], id: u16, name: &str) -> Result<Vec<[u8; 4]>, Error> {
    Ok(answer_type(reply, id, name, TYPE_A)?.into_iter().filter_map(|d| d.try_into().ok()).collect())
}

/// The IPv6 addresses in `reply` (AAAA records, RFC 3596).
pub fn answer6(reply: &[u8], id: u16, name: &str) -> Result<Vec<[u8; 16]>, Error> {
    Ok(answer_type(reply, id, name, TYPE_AAAA)?.into_iter().filter_map(|d| d.try_into().ok()).collect())
}

/// The data of `qtype` records for `name` (after its CNAMEs) in `reply`.
fn answer_type(reply: &[u8], id: u16, name: &str, qtype: u16) -> Result<Vec<Vec<u8>>, Error> {
    if u16_at(reply, 0)? != id {
        return Err(Error::Malformed);
    }
    let flags = u16_at(reply, 2)?;
    if flags & QR == 0 {
        return Err(Error::Malformed);
    }
    let rcode = (flags & 0xf) as u8;
    if rcode != 0 {
        return Err(Error::Rcode(rcode));
    }
    let (qd, an) = (u16_at(reply, 4)?, u16_at(reply, 6)?);
    let mut at = 12;
    for _ in 0..qd {
        at = read_name(reply, at)?.1 + 4;
    }
    let mut want: Vec<u8> = name.strip_suffix('.').unwrap_or(name).bytes().map(|b| b.to_ascii_lowercase()).collect();
    let mut records = Vec::new();
    for _ in 0..an {
        let (owner, after) = read_name(reply, at)?;
        let (ty, class) = (u16_at(reply, after)?, u16_at(reply, after + 2)?);
        let len = usize::from(u16_at(reply, after + 8)?);
        let data = after + 10;
        if data + len > reply.len() {
            return Err(Error::Malformed);
        }
        records.push((owner, ty, class, data, len));
        at = data + len;
    }
    // Follow CNAMEs (in any order) to the final name, then collect its A records.
    for _ in 0..8 {
        let next = records.iter().find(|r| r.0 == want && r.1 == TYPE_CNAME && r.2 == CLASS_IN);
        match next {
            Some(r) => want = read_name(reply, r.3)?.0,
            None => break,
        }
    }
    Ok(records
        .iter()
        .filter(|r| r.0 == want && r.1 == qtype && r.2 == CLASS_IN)
        .map(|r| reply[r.3..r.3 + r.4].to_vec())
        .collect())
}

/// A query's question (§4.1.2): its ID, name (lowercase), type and class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub id: u16,
    pub name: Vec<u8>,
    pub qtype: u16,
    pub qclass: u16,
}

/// Read the one question of a query (the message must not be a response).
pub fn question(m: &[u8]) -> Result<Question, Error> {
    if u16_at(m, 2)? & QR != 0 || u16_at(m, 4)? != 1 {
        return Err(Error::Malformed);
    }
    let (name, at) = read_name(m, 12)?;
    Ok(Question { id: u16_at(m, 0)?, name, qtype: u16_at(m, at)?, qclass: u16_at(m, at + 2)? })
}

/// How long an answer may be kept: the smallest TTL of its records
/// (§4.1.3), None if it has none (an error or an empty answer).
pub fn ttl(reply: &[u8]) -> Option<u32> {
    let (qd, an) = (u16_at(reply, 4).ok()?, u16_at(reply, 6).ok()?);
    let mut at = 12;
    for _ in 0..qd {
        at = read_name(reply, at).ok()?.1 + 4;
    }
    let mut min: Option<u32> = None;
    for _ in 0..an {
        let after = read_name(reply, at).ok()?.1;
        let ttl = u32::from(u16_at(reply, after + 4).ok()?) << 16 | u32::from(u16_at(reply, after + 6).ok()?);
        min = Some(min.map_or(ttl, |m| m.min(ttl)));
        at = after + 10 + usize::from(u16_at(reply, after + 8).ok()?);
    }
    min
}

/// The response code of a reply.
pub fn rcode(reply: &[u8]) -> Option<u8> {
    u16_at(reply, 2).ok().map(|f| (f & 0xf) as u8)
}

/// A reply to `query` (its ID and question kept) with `rcode` and answer
/// records for the question's name: (type, data, TTL) each.
pub fn reply(query: &[u8], rcode: u8, answers: &[(u16, &[u8], u32)]) -> Result<Vec<u8>, Error> {
    let q = question(query)?;
    let end = read_name(query, 12)?.1 + 4;
    let mut r = query[..end].to_vec();
    // QR, RD as asked, RA; the code.
    r[2] = 0x80 | (query[2] & 0x01);
    r[3] = 0x80 | (rcode & 0xf);
    r[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
    r[8..12].fill(0);
    let _ = q;
    for (ty, data, ttl) in answers {
        // The owner: a pointer to the question's name (§4.1.4).
        r.extend_from_slice(&[0xc0, 12]);
        r.extend_from_slice(&ty.to_be_bytes());
        r.extend_from_slice(&CLASS_IN.to_be_bytes());
        r.extend_from_slice(&ttl.to_be_bytes());
        r.extend_from_slice(&(data.len() as u16).to_be_bytes());
        r.extend_from_slice(data);
    }
    Ok(r)
}

/// Parse a dotted-quad IPv4 address.
pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = s.split('.');
    for o in &mut out {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        *o = p.parse().ok()?;
    }
    parts.next().is_none().then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_bytes() {
        let q = query(0x1234, "a.bc").unwrap();
        assert_eq!(q, [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 2, b'b', b'c', 0, 0, 1, 0, 1]);
        assert_eq!(query(1, ""), Err(Error::BadName));
        assert_eq!(query(1, "a..b"), Err(Error::BadName));
    }

    /// A reply: the question, a CNAME (compressed pointer to the question's
    /// name) and an A record for the canonical name.
    fn reply() -> Vec<u8> {
        let mut r = query(7, "www.example.com").unwrap();
        r[2] = 0x81;
        r[3] = 0x80; // QR, RD, RA
        r[7] = 2; // ANCOUNT
        // CNAME: owner = pointer to offset 12; data = "cdn" + pointer to "example.com" (offset 16).
        r.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6, 3, b'c', b'd', b'n', 0xc0, 16]);
        let cname_at = r.len() - 6;
        // A: owner = pointer to the CNAME's data.
        r.extend_from_slice(&[0xc0, cname_at as u8, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        r
    }

    #[test]
    fn follows_cname() {
        assert_eq!(answer(&reply(), 7, "WWW.Example.com."), Ok(std::vec![[93, 184, 216, 34]]));
        assert_eq!(answer(&reply(), 8, "www.example.com"), Err(Error::Malformed));
        let mut nx = reply();
        nx[3] = 0x83;
        assert_eq!(answer(&nx, 7, "www.example.com"), Err(Error::Rcode(3)));
        assert!(answer(&reply()[..30], 7, "www.example.com").is_err());
    }

    #[test]
    fn aaaa_cache_and_replies() {
        let q = query_type(9, "host.slate.test", TYPE_AAAA).unwrap();
        let question = question(&q).unwrap();
        assert_eq!((question.id, question.name.as_slice(), question.qtype), (9, &b"host.slate.test"[..], TYPE_AAAA));
        let v6 = [0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let r = super::reply(&q, 0, &[(TYPE_AAAA, &v6, 300), (TYPE_AAAA, &v6, 120)]).unwrap();
        assert_eq!(answer6(&r, 9, "host.slate.test"), Ok(std::vec![v6, v6]));
        assert_eq!(answer(&r, 9, "host.slate.test"), Ok(std::vec![]));
        assert_eq!(ttl(&r), Some(120));
        let nx = super::reply(&q, 3, &[]).unwrap();
        assert_eq!((rcode(&nx), ttl(&nx)), (Some(3), None));
        assert_eq!(answer6(&nx, 9, "host.slate.test"), Err(Error::Rcode(3)));
        // A response is not a question.
        assert!(super::question(&r).is_err());
    }

    #[test]
    fn ipv4() {
        assert_eq!(parse_ipv4("10.0.2.2"), Some([10, 0, 2, 2]));
        assert_eq!(parse_ipv4("256.1.1.1"), None);
        assert_eq!(parse_ipv4("1.2.3"), None);
        assert_eq!(parse_ipv4("example.com"), None);
    }
}
