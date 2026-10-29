// SPDX-License-Identifier: MIT OR Apache-2.0

//! netd's DNS cache (ADR 0052): a forwarding resolver on 127.0.0.53, port
//! 53, that `/run/resolv.conf` names. Queries go to the name servers the
//! cards have (in card order, each tried for 1.5 s in turn, over IPv4 or
//! IPv6); answers are kept for their smallest TTL (at most an hour),
//! "no such name" and empty answers for a minute (RFC 2308's negative
//! caching, with a fixed time). When no server answers, the client gets
//! SERVFAIL.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use slate_dns::Question;
use slate_net::IpAddr;
use slate_rt::{io, net};

use crate::config::Server;

/// Where the cache listens.
pub const ADDRESS: [u8; 4] = [127, 0, 0, 53];
const MAX_ENTRIES: usize = 1024;
const MAX_TTL: u32 = 3600;
const NEGATIVE_TTL: u32 = 60;
const TRY_MS: u64 = 1500;
const MAX_PENDING: usize = 256;
const SERVFAIL: u8 = 2;

type Key = (Vec<u8>, u16, u16);

/// Answers by question, each with when it lapses (ms).
#[derive(Debug, Default)]
pub struct Cache {
    entries: BTreeMap<Key, (Vec<u8>, u64)>,
}

fn key(q: &Question) -> Key {
    (q.name.clone(), q.qtype, q.qclass)
}

impl Cache {
    /// The kept answer to `q`, with `q`'s ID.
    pub fn get(&self, q: &Question, now: u64) -> Option<Vec<u8>> {
        let (r, until) = self.entries.get(&key(q))?;
        (now < *until).then(|| {
            let mut r = r.clone();
            r[..2].copy_from_slice(&q.id.to_be_bytes());
            r
        })
    }

    /// Keep an answer for as long as it may be kept.
    pub fn put(&mut self, q: &Question, reply: &[u8], now: u64) {
        let life = match (slate_dns::rcode(reply), slate_dns::ttl(reply)) {
            (Some(0), Some(t)) => t.min(MAX_TTL),
            (Some(0 | 3), None) => NEGATIVE_TTL,
            _ => return, // Server failures are not kept.
        };
        if life == 0 {
            return;
        }
        if self.entries.len() >= MAX_ENTRIES {
            self.entries.retain(|_, (_, until)| *until > now);
        }
        if self.entries.len() >= MAX_ENTRIES
            && let Some(k) = self.entries.iter().min_by_key(|(_, (_, until))| *until).map(|(k, _)| k.clone())
        {
            self.entries.remove(&k);
        }
        self.entries.insert(key(q), (reply.to_vec(), now + u64::from(life) * 1000));
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A query waiting for a server.
#[derive(Debug)]
struct Pending {
    client: net::Peer,
    query: Vec<u8>,
    question: Question,
    /// The server tried now (an index into the list), and until when.
    server: usize,
    deadline: u64,
}

#[derive(Debug)]
pub struct Resolver {
    listen: i32,
    up4: i32,
    up6: Option<i32>,
    cache: Cache,
    pending: BTreeMap<u16, Pending>,
    next_id: u16,
}

fn peer(s: &Server) -> net::Peer {
    match s.addr {
        IpAddr::V4(a) => net::Peer::V4(a.0, s.port),
        IpAddr::V6(a) => net::Peer::V6(a.0, s.port, 0),
    }
}

impl Resolver {
    /// Listen on 127.0.0.53:53; None if that is taken.
    pub fn start(seed: u16) -> Option<Resolver> {
        let at = net::Peer::V4(ADDRESS, 53);
        let listen = net::socket_for(&at, 2, 0).ok()?;
        if net::bind_peer(listen, &at).is_err() {
            let _ = io::close(listen);
            return None;
        }
        let up4 = net::udp_socket().ok()?;
        let up6 = net::socket_for(&net::Peer::V6([0; 16], 0, 0), 2, 0).ok();
        Some(Resolver { listen, up4, up6, cache: Cache::default(), pending: BTreeMap::new(), next_id: seed })
    }

    pub fn fds(&self) -> Vec<i32> {
        let mut v = alloc::vec![self.listen, self.up4];
        v.extend(self.up6);
        v
    }

    /// When a waiting query next needs attention.
    pub fn next(&self) -> Option<u64> {
        self.pending.values().map(|p| p.deadline).min()
    }

    /// Something to read on `fd` (one of [`Resolver::fds`]).
    pub fn ready(&mut self, fd: i32, servers: &[Server], now: u64) {
        let mut buf = [0u8; 4096];
        let Ok((n, Some(from))) = net::recv_from_peer(fd, &mut buf) else { return };
        let msg = &buf[..n];
        if fd == self.listen {
            self.query(msg, from, servers, now);
        } else {
            self.answer(msg, from, servers, now);
        }
    }

    fn query(&mut self, msg: &[u8], client: net::Peer, servers: &[Server], now: u64) {
        let Ok(q) = slate_dns::question(msg) else { return };
        if let Some(r) = self.cache.get(&q, now) {
            let _ = net::send_to_peer(self.listen, &r, &client);
            return;
        }
        if servers.is_empty() || self.pending.len() >= MAX_PENDING {
            self.fail(msg, &client);
            return;
        }
        self.next_id = self.next_id.wrapping_mul(25173).wrapping_add(13849);
        let id = self.next_id;
        let mut query = msg.to_vec();
        query[..2].copy_from_slice(&id.to_be_bytes());
        let p = Pending { client, query, question: q, server: 0, deadline: now + TRY_MS };
        self.send(&p, servers);
        self.pending.insert(id, p);
    }

    fn send(&self, p: &Pending, servers: &[Server]) {
        let Some(s) = servers.get(p.server) else { return };
        let fd = match s.addr {
            IpAddr::V4(_) => Some(self.up4),
            IpAddr::V6(_) => self.up6,
        };
        if let Some(fd) = fd {
            let _ = net::send_to_peer(fd, &p.query, &peer(s));
        }
    }

    /// SERVFAIL for a query no server answered.
    fn fail(&self, query: &[u8], client: &net::Peer) {
        if let Ok(r) = slate_dns::reply(query, SERVFAIL, &[]) {
            let _ = net::send_to_peer(self.listen, &r, client);
        }
    }

    fn answer(&mut self, msg: &[u8], from: net::Peer, servers: &[Server], now: u64) {
        if msg.len() < 12 {
            return;
        }
        let id = u16::from_be_bytes([msg[0], msg[1]]);
        let Some(p) = self.pending.get(&id) else { return };
        // Only from the server it was asked of.
        if servers.get(p.server).map(peer) != Some(from) {
            return;
        }
        let p = self.pending.remove(&id).unwrap();
        let mut r = msg.to_vec();
        r[..2].copy_from_slice(&p.question.id.to_be_bytes());
        self.cache.put(&p.question, &r, now);
        let _ = net::send_to_peer(self.listen, &r, &p.client);
    }

    /// Queries whose server did not answer in time go to the next one, or
    /// fail when none is left.
    pub fn tick(&mut self, servers: &[Server], now: u64) {
        let late: Vec<u16> = self.pending.iter().filter(|(_, p)| now >= p.deadline).map(|(id, _)| *id).collect();
        for id in late {
            let Some(mut p) = self.pending.remove(&id) else { continue };
            p.server += 1;
            if p.server >= servers.len() {
                let mut q = p.query.clone();
                q[..2].copy_from_slice(&p.question.id.to_be_bytes());
                self.fail(&q, &p.client);
                continue;
            }
            p.deadline = now + TRY_MS;
            self.send(&p, servers);
            self.pending.insert(id, p);
        }
    }
}
