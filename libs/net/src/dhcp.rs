// SPDX-License-Identifier: MIT OR Apache-2.0

//! DHCP messages (RFC 2131, options from RFC 2132).

use alloc::vec::Vec;

use crate::wire::{Ipv4, Mac, get32, ip_at, put16, put32};

pub const SERVER_PORT: u16 = 67;
pub const CLIENT_PORT: u16 = 68;
const COOKIE: [u8; 4] = [99, 130, 83, 99];
const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;

// Message types (option 53).
pub const DISCOVER: u8 = 1;
pub const OFFER: u8 = 2;
pub const REQUEST: u8 = 3;
pub const ACK: u8 = 5;
pub const NAK: u8 = 6;

// Options.
const OPT_SUBNET: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_HOSTNAME: u8 = 12;
const OPT_DOMAIN: u8 = 15;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE: u8 = 51;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAMS: u8 = 55;
/// The time zone as a tz database name (RFC 4833 §2, "TCode").
const OPT_TCODE: u8 = 101;
const OPT_END: u8 = 255;
const OPT_PAD: u8 = 0;

/// The parts of a server reply the client uses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reply {
    pub xid: u32,
    pub kind: u8,
    pub your_ip: Ipv4,
    pub server: Option<Ipv4>,
    pub subnet: Option<Ipv4>,
    pub router: Option<Ipv4>,
    pub dns: Vec<Ipv4>,
    pub lease_secs: Option<u32>,
    pub domain: Vec<u8>,
    /// The tz database name the server gives, if any (RFC 4833).
    pub timezone: Vec<u8>,
}

/// A client message: DISCOVER, or REQUEST for `requested` from `server`.
pub fn client_message(
    kind: u8,
    xid: u32,
    mac: Mac,
    requested: Option<Ipv4>,
    server: Option<Ipv4>,
    hostname: &[u8],
) -> Vec<u8> {
    build_client(kind, xid, mac, None, requested, server, hostname)
}

/// A REQUEST that renews or rebinds the lease of `ciaddr` (RFC 2131
/// §4.3.2, "RENEWING" and "REBINDING": the address in `ciaddr`, neither
/// the requested address nor a server identifier).
pub fn renew_message(xid: u32, mac: Mac, ciaddr: Ipv4, hostname: &[u8]) -> Vec<u8> {
    build_client(REQUEST, xid, mac, Some(ciaddr), None, None, hostname)
}

fn build_client(
    kind: u8,
    xid: u32,
    mac: Mac,
    ciaddr: Option<Ipv4>,
    requested: Option<Ipv4>,
    server: Option<Ipv4>,
    hostname: &[u8],
) -> Vec<u8> {
    let mut m = alloc::vec![0u8; 236];
    m[0] = BOOTREQUEST;
    m[1] = 1; // Ethernet
    m[2] = 6;
    put32(&mut m, 4, xid);
    match ciaddr {
        // A client with an address takes replies there.
        Some(ip) => m[12..16].copy_from_slice(&ip.0),
        None => put16(&mut m, 10, 0x8000), // Replies by broadcast: we have no address yet.
    }
    m[28..34].copy_from_slice(&mac.0);
    m.extend_from_slice(&COOKIE);
    m.extend_from_slice(&[OPT_MSG_TYPE, 1, kind]);
    if let Some(ip) = requested {
        m.extend_from_slice(&[OPT_REQUESTED_IP, 4]);
        m.extend_from_slice(&ip.0);
    }
    if let Some(s) = server {
        m.extend_from_slice(&[OPT_SERVER_ID, 4]);
        m.extend_from_slice(&s.0);
    }
    if !hostname.is_empty() && hostname.len() < 64 {
        m.extend_from_slice(&[OPT_HOSTNAME, hostname.len() as u8]);
        m.extend_from_slice(hostname);
    }
    m.extend_from_slice(&[OPT_PARAMS, 6, OPT_SUBNET, OPT_ROUTER, OPT_DNS, OPT_DOMAIN, OPT_LEASE, OPT_TCODE]);
    m.push(OPT_END);
    // Some servers want the 300-byte BOOTP minimum.
    if m.len() < 300 {
        m.resize(300, 0);
    }
    m
}

/// Parse a server reply addressed to `mac`.
pub fn parse_reply(m: &[u8], mac: Mac) -> Option<Reply> {
    if m.len() < 240 || m[0] != BOOTREPLY || m[236..240] != COOKIE || m[28..34] != mac.0 {
        return None;
    }
    let mut r = Reply { xid: get32(m, 4), your_ip: ip_at(m, 16), ..Default::default() };
    let mut at = 240;
    while at < m.len() {
        let code = m[at];
        if code == OPT_END {
            break;
        }
        if code == OPT_PAD {
            at += 1;
            continue;
        }
        let len = usize::from(*m.get(at + 1)?);
        let v = m.get(at + 2..at + 2 + len)?;
        match (code, len) {
            (OPT_MSG_TYPE, 1) => r.kind = v[0],
            (OPT_SERVER_ID, 4) => r.server = Some(ip_at(v, 0)),
            (OPT_SUBNET, 4) => r.subnet = Some(ip_at(v, 0)),
            (OPT_ROUTER, l) if l >= 4 => r.router = Some(ip_at(v, 0)),
            (OPT_DNS, l) if l >= 4 => r.dns = v.as_chunks::<4>().0.iter().map(|c| Ipv4(*c)).collect(),
            (OPT_LEASE, 4) => r.lease_secs = Some(get32(v, 0)),
            (OPT_DOMAIN, _) => r.domain = v.to_vec(),
            (OPT_TCODE, _) => r.timezone = v.to_vec(),
            _ => {}
        }
        at += 2 + len;
    }
    (r.kind != 0).then_some(r)
}

/// A server message, for tests: `kind` for `xid` offering `ip`.
pub fn server_message(kind: u8, xid: u32, mac: Mac, ip: Ipv4, server: Ipv4, router: Ipv4, dns: Ipv4) -> Vec<u8> {
    let mut m = alloc::vec![0u8; 236];
    m[0] = BOOTREPLY;
    m[1] = 1;
    m[2] = 6;
    put32(&mut m, 4, xid);
    m[16..20].copy_from_slice(&ip.0);
    m[28..34].copy_from_slice(&mac.0);
    m.extend_from_slice(&COOKIE);
    m.extend_from_slice(&[OPT_MSG_TYPE, 1, kind, OPT_SERVER_ID, 4]);
    m.extend_from_slice(&server.0);
    m.extend_from_slice(&[OPT_SUBNET, 4, 255, 255, 255, 0, OPT_ROUTER, 4]);
    m.extend_from_slice(&router.0);
    m.extend_from_slice(&[OPT_DNS, 4]);
    m.extend_from_slice(&dns.0);
    m.extend_from_slice(&[OPT_LEASE, 4, 0, 1, 0x51, 0x80, OPT_END]);
    m
}

/// `message` with option `code` added before its end (tests).
pub fn with_option(message: &[u8], code: u8, value: &[u8]) -> Vec<u8> {
    let mut m = message.to_vec();
    if m.last() == Some(&OPT_END) {
        m.pop();
    }
    m.extend_from_slice(&[code, value.len() as u8]);
    m.extend_from_slice(value);
    m.push(OPT_END);
    m
}

/// The message type of a client message, and its requested address (tests).
pub fn parse_client(m: &[u8]) -> Option<(u8, u32, Option<Ipv4>)> {
    if m.len() < 240 || m[0] != BOOTREQUEST || m[236..240] != COOKIE {
        return None;
    }
    let (mut kind, mut req) = (0, None);
    let mut at = 240;
    while at + 1 < m.len() && m[at] != OPT_END {
        if m[at] == OPT_PAD {
            at += 1;
            continue;
        }
        let len = usize::from(m[at + 1]);
        match m[at] {
            OPT_MSG_TYPE => kind = m[at + 2],
            OPT_REQUESTED_IP => req = Some(ip_at(m, at + 2)),
            _ => {}
        }
        at += 2 + len;
    }
    Some((kind, get32(m, 4), req))
}
