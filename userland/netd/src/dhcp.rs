// SPDX-License-Identifier: MIT OR Apache-2.0

//! netd's DHCP client for one card (RFC 2131 §4.4), as a state machine
//! with no I/O: the daemon feeds it the time and the server's replies, and
//! carries out what it asks (send a message, configure the card, remove
//! the configuration). The messages are `slate_net::dhcp`'s.
//!
//! INIT sends DISCOVER and takes the first OFFER; REQUESTING asks for it
//! and on ACK the card is configured (BOUND). At T1 (half the lease) the
//! client renews with the server that gave the lease, at T2 (7/8) with any
//! server, retrying halfway to the next deadline but at least a minute
//! apart (§4.4.5); when the lease ends, or a server says NAK, the card's
//! address goes and the client starts over.

use alloc::vec::Vec;

use slate_net::dhcp;
use slate_net::{Ipv4, Mac};

/// What the server gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub addr: Ipv4,
    pub prefix_len: u8,
    pub router: Option<Ipv4>,
    pub dns: Vec<Ipv4>,
    pub domain: Vec<u8>,
    pub server: Option<Ipv4>,
    pub secs: u32,
    /// The time zone's tz database name, if the server gave one.
    pub timezone: Vec<u8>,
}

/// What the client wants done.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Send this message from port 68 to port 67 at `to` (the broadcast
    /// address, or the server when renewing).
    Send { to: Ipv4, message: Vec<u8> },
    /// Configure the card with the lease (new, or renewed).
    Configure(Lease),
    /// Remove what the last lease configured.
    Deconfigure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum State {
    Init {
        next: u64,
        tries: u32,
    },
    Requesting {
        offer: dhcp::Reply,
        next: u64,
        tries: u32,
    },
    /// `t1`, `t2` and `end` are times (ms); renewing past T1 sends at `next`.
    Bound {
        lease: Lease,
        t1: u64,
        t2: u64,
        end: u64,
        next: u64,
    },
}

#[derive(Debug)]
pub struct Client {
    mac: Mac,
    hostname: Vec<u8>,
    xid: u32,
    seed: u32,
    state: State,
}

/// Retransmission waits in INIT and REQUESTING: 4, 8, 16, 32, then 64
/// seconds (§4.1 asks for about 4 s doubling to 64 s); the first retry
/// comes sooner, as servers that just came up may miss the first.
fn backoff(tries: u32) -> u64 {
    match tries {
        0 => 2000,
        t => 4000 << (t - 1).min(4),
    }
}

impl Client {
    pub fn new(mac: Mac, hostname: &[u8], seed: u32) -> Client {
        let mut c = Client {
            mac,
            hostname: hostname.to_vec(),
            xid: 0,
            seed: seed | 1,
            state: State::Init { next: 0, tries: 0 },
        };
        c.xid = c.rand();
        c
    }

    fn rand(&mut self) -> u32 {
        let mut x = self.seed;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.seed = x;
        x
    }

    /// When the client next needs [`Client::tick`].
    pub fn next(&self) -> u64 {
        match &self.state {
            State::Init { next, .. } | State::Requesting { next, .. } => *next,
            State::Bound { next, end, .. } => (*next).min(*end),
        }
    }

    pub fn lease(&self) -> Option<&Lease> {
        match &self.state {
            State::Bound { lease, .. } => Some(lease),
            _ => None,
        }
    }

    fn restart(&mut self, now: u64) {
        self.xid = self.rand();
        self.state = State::Init { next: now, tries: 0 };
    }

    /// Run timers: retransmit, renew, rebind, or give up the lease.
    pub fn tick(&mut self, now: u64) -> Vec<Action> {
        let mut out = Vec::new();
        match self.state.clone() {
            State::Init { next, tries } if now >= next => {
                let m = dhcp::client_message(dhcp::DISCOVER, self.xid, self.mac, None, None, &self.hostname);
                out.push(Action::Send { to: Ipv4::BROADCAST, message: m });
                self.state = State::Init { next: now + backoff(tries), tries: tries + 1 };
            }
            State::Requesting { tries, .. } if tries >= 4 => {
                // No answer to the request: start over.
                self.restart(now);
                out.extend(self.tick(now));
            }
            State::Requesting { offer, next, tries } if now >= next => {
                let m = dhcp::client_message(
                    dhcp::REQUEST,
                    self.xid,
                    self.mac,
                    Some(offer.your_ip),
                    offer.server,
                    &self.hostname,
                );
                out.push(Action::Send { to: Ipv4::BROADCAST, message: m });
                self.state = State::Requesting { offer, next: now + backoff(tries), tries: tries + 1 };
            }
            State::Bound { end, .. } if now >= end => {
                out.push(Action::Deconfigure);
                self.restart(now);
                out.extend(self.tick(now));
            }
            State::Bound { lease, t1, t2, end, next } if now >= next && now >= t1 => {
                // RENEWING (unicast to the server) until T2, then REBINDING
                // (broadcast). Retry halfway to the next deadline, at least
                // a minute apart.
                let (to, deadline) = match lease.server {
                    Some(s) if now < t2 => (s, t2),
                    _ => (Ipv4::BROADCAST, end),
                };
                self.xid = self.rand();
                let m = dhcp::renew_message(self.xid, self.mac, lease.addr, &self.hostname);
                out.push(Action::Send { to, message: m });
                let wait = ((deadline.saturating_sub(now)) / 2).max(60_000);
                self.state = State::Bound { lease, t1, t2, end, next: now + wait };
            }
            _ => {}
        }
        out
    }

    /// A message from the server.
    pub fn receive(&mut self, message: &[u8], now: u64) -> Vec<Action> {
        let Some(r) = dhcp::parse_reply(message, self.mac) else { return Vec::new() };
        if r.xid != self.xid {
            return Vec::new();
        }
        let mut out = Vec::new();
        match self.state.clone() {
            State::Init { .. } if r.kind == dhcp::OFFER => {
                self.state = State::Requesting { offer: r, next: now, tries: 0 };
                out.extend(self.tick(now));
            }
            State::Requesting { .. } | State::Bound { .. } if r.kind == dhcp::ACK => {
                let mask = r.subnet.unwrap_or(Ipv4([255, 255, 255, 0])).to_u32();
                let secs = r.lease_secs.unwrap_or(86400).max(60);
                let lease = Lease {
                    addr: r.your_ip,
                    prefix_len: mask.leading_ones() as u8,
                    router: r.router,
                    dns: r.dns,
                    domain: r.domain,
                    server: r.server,
                    secs,
                    timezone: r.timezone,
                };
                let ms = u64::from(secs) * 1000;
                // T1 and T2 at 1/2 and 7/8 of the lease (§4.4.5).
                let (t1, t2, end) = (now + ms / 2, now + ms * 7 / 8, now + ms);
                if self.lease().is_some_and(|old| old.addr != lease.addr) {
                    out.push(Action::Deconfigure);
                }
                out.push(Action::Configure(lease.clone()));
                self.state = State::Bound { lease, t1, t2, end, next: t1 };
            }
            State::Requesting { .. } | State::Bound { .. } if r.kind == dhcp::NAK => {
                if self.lease().is_some() {
                    out.push(Action::Deconfigure);
                }
                self.restart(now);
                out.extend(self.tick(now));
            }
            _ => {}
        }
        out
    }
}
