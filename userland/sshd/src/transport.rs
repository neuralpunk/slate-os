// SPDX-License-Identifier: MIT OR Apache-2.0

//! The transport layer (RFC 4253): version exchange, the binary packet
//! protocol, algorithm negotiation and key exchange, and keys (§7.2).
//! Strict key exchange (OpenSSH's kex-strict, the Terrapin fix) is
//! supported: sequence numbers restart at each NEWKEYS, and nothing but
//! key exchange messages may come before the first one. The server
//! starts a new key exchange itself after a set amount of data or time
//! (ADR 0061), queueing what the client sends meanwhile.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::io;

use crate::crypto::{self, Chacha, HostSign};
use crate::wire::{Reader, Writer};

pub const VERSION: &[u8] = b"SSH-2.0-SlateSSH_0.1";

// Message numbers (RFC 4250 §4.1).
pub const MSG_DISCONNECT: u8 = 1;
pub const MSG_IGNORE: u8 = 2;
pub const MSG_UNIMPLEMENTED: u8 = 3;
pub const MSG_DEBUG: u8 = 4;
pub const MSG_KEXINIT: u8 = 20;
pub const MSG_NEWKEYS: u8 = 21;
pub const MSG_KEX_ECDH_INIT: u8 = 30;
pub const MSG_KEX_ECDH_REPLY: u8 = 31;

/// Disconnect reasons (RFC 4250 §4.2.2).
pub const PROTOCOL_ERROR: u32 = 2;
pub const KEY_EXCHANGE_FAILED: u32 = 3;
pub const MAC_ERROR: u32 = 5;
pub const NO_MORE_AUTH_METHODS: u32 = 14;
pub const BY_APPLICATION: u32 = 11;

const MAX_PACKET: usize = 256 * 1024;
const KEX_STRICT_C: &[u8] = b"kex-strict-c-v00@openssh.com";
const KEX_STRICT_S: &[u8] = b"kex-strict-s-v00@openssh.com";

/// Why the connection ends.
#[derive(Debug)]
pub struct Error(pub String);

pub type Result<T> = core::result::Result<T, Error>;

pub fn err<T>(s: impl Into<String>) -> Result<T> {
    Err(Error(s.into()))
}

impl From<crate::wire::Short> for Error {
    fn from(_: crate::wire::Short) -> Error {
        Error("a message was too short".into())
    }
}

/// A byte stream: the socket (or a test double).
pub trait Stream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
    fn write_all(&mut self, data: &[u8]) -> Result<()>;
    /// Wait up to `ms` for something to read; false on a timeout.
    fn wait(&mut self, _ms: i32) -> Result<bool> {
        Ok(true)
    }
}

/// A connected socket.
#[derive(Debug)]
pub struct Fd(pub i32);

impl Stream for Fd {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            match io::read(self.0, buf) {
                Err(slate_rt::Errno::EINTR) => continue,
                r => return r.map_err(|e| Error(format!("reading: {e}"))),
            }
        }
    }
    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        io::write_all(self.0, data).map_err(|e| Error(format!("writing: {e}")))
    }
    fn wait(&mut self, ms: i32) -> Result<bool> {
        let mut p = [io::PollFd { fd: self.0, events: io::POLLIN, revents: 0 }];
        match io::poll(&mut p, ms) {
            Ok(n) => Ok(n > 0),
            Err(slate_rt::Errno::EINTR) => Ok(false),
            Err(e) => err(format!("poll: {e}")),
        }
    }
}

/// One SSH connection's transport.
#[derive(Debug)]
pub struct Transport<S: Stream> {
    pub stream: S,
    buf: Vec<u8>,
    seq_in: u32,
    seq_out: u32,
    cipher_in: Option<Chacha>,
    cipher_out: Option<Chacha>,
    pub session_id: Option<[u8; 32]>,
    strict: bool,
    client_version: Vec<u8>,
    random: [u8; 32],
    /// The key exchange methods offered, best first.
    pub kex_methods: Vec<&'static [u8]>,
    /// Bytes sent and received since the last key exchange, and when it
    /// ended (monotonic seconds).
    pub bytes_since_kex: u64,
    pub kex_time: i64,
    /// Messages that came while a key exchange we started was waiting
    /// for the client's KEXINIT.
    queued: VecDeque<Vec<u8>>,
    /// Reading fails after this time (monotonic seconds): LoginGraceTime.
    pub deadline: Option<i64>,
}

fn now_secs() -> i64 {
    slate_rt::time::now(slate_rt::time::CLOCK_MONOTONIC).0
}

impl<S: Stream> Transport<S> {
    /// Send our version and read the client's (RFC 4253 §4.2; lines
    /// before the version line are ignored).
    pub fn start(mut stream: S, random: [u8; 32]) -> Result<Transport<S>> {
        let mut hello = VERSION.to_vec();
        hello.extend_from_slice(b"\r\n");
        stream.write_all(&hello)?;
        let mut t = Transport {
            stream,
            buf: Vec::new(),
            seq_in: 0,
            seq_out: 0,
            cipher_in: None,
            cipher_out: None,
            session_id: None,
            strict: false,
            client_version: Vec::new(),
            random,
            kex_methods: alloc::vec![crypto::KEX_MLKEM, crypto::KEX, crypto::KEX_LIBSSH],
            bytes_since_kex: 0,
            kex_time: now_secs(),
            queued: VecDeque::new(),
            deadline: None,
        };
        for _ in 0..50 {
            let line = t.line()?;
            if line.starts_with(b"SSH-") {
                if !line.starts_with(b"SSH-2.0-") && !line.starts_with(b"SSH-1.99-") {
                    return err("the client does not speak SSH 2");
                }
                t.client_version = line;
                return Ok(t);
            }
        }
        err("no SSH version line from the client")
    }

    fn fill(&mut self, n: usize) -> Result<()> {
        while self.buf.len() < n {
            if let Some(d) = self.deadline {
                let left = d - now_secs();
                if left <= 0 || !self.stream.wait((left * 1000).min(i64::from(i32::MAX)) as i32)? {
                    if now_secs() >= d {
                        return err("the client did not log in in time");
                    }
                    continue;
                }
            }
            let mut chunk = [0u8; 16384];
            let got = self.stream.read(&mut chunk)?;
            if got == 0 {
                return err("the client closed the connection");
            }
            self.buf.extend_from_slice(&chunk[..got]);
        }
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<Vec<u8>> {
        self.fill(n)?;
        Ok(self.buf.drain(..n).collect())
    }

    fn line(&mut self) -> Result<Vec<u8>> {
        loop {
            if let Some(i) = self.buf.iter().position(|&c| c == b'\n') {
                let mut l: Vec<u8> = self.buf.drain(..=i).collect();
                l.pop();
                if l.last() == Some(&b'\r') {
                    l.pop();
                }
                return Ok(l);
            }
            if self.buf.len() > 255 {
                return err("the client's version line is too long");
            }
            let have = self.buf.len();
            self.fill(have + 1)?;
        }
    }

    fn random_bytes(&mut self, out: &mut [u8]) {
        if slate_rt::process::random(out).is_err() {
            // Never reached on Slate; keep going with a hashed counter.
            let h = crypto::sha256(&self.random);
            self.random = h;
            for (o, b) in out.iter_mut().zip(h.iter().cycle()) {
                *o = *b;
            }
        }
    }

    /// Send one message (§6: length, padding length, payload, padding).
    pub fn send(&mut self, payload: &[u8]) -> Result<()> {
        // With the AEAD cipher the length field is not part of the padded
        // block; without one it is. Blocks are 8 bytes; padding ≥ 4.
        let aead = self.cipher_out.is_some();
        let covered = payload.len() + 1 + if aead { 0 } else { 4 };
        let mut pad = 8 - covered % 8;
        if pad < 4 {
            pad += 8;
        }
        let mut packet = Vec::with_capacity(5 + payload.len() + pad + crypto::TAG);
        packet.extend_from_slice(&((payload.len() + 1 + pad) as u32).to_be_bytes());
        packet.push(pad as u8);
        packet.extend_from_slice(payload);
        let mut padding = alloc::vec![0u8; pad];
        self.random_bytes(&mut padding);
        packet.extend_from_slice(&padding);
        if let Some(c) = &self.cipher_out {
            c.seal(self.seq_out, &mut packet);
        }
        self.seq_out = self.seq_out.wrapping_add(1);
        self.bytes_since_kex += packet.len() as u64;
        self.stream.write_all(&packet)
    }

    /// Receive one message's payload, skipping IGNORE and DEBUG.
    pub fn recv(&mut self) -> Result<Vec<u8>> {
        if let Some(m) = self.queued.pop_front() {
            return Ok(m);
        }
        self.recv_wire()
    }

    /// Whether messages are waiting: read but not yet handled (the caller
    /// may poll the socket only when there are none).
    pub fn pending(&self) -> bool {
        !self.queued.is_empty() || !self.buf.is_empty()
    }

    fn recv_wire(&mut self) -> Result<Vec<u8>> {
        loop {
            let p = self.recv_any()?;
            match p.first() {
                Some(&MSG_IGNORE | &MSG_DEBUG) if !(self.strict && self.cipher_in.is_none()) => continue,
                Some(&MSG_DISCONNECT) => {
                    let mut r = Reader::new(&p[1..]);
                    let _ = r.u32();
                    let why = r.string().map(|s| String::from_utf8_lossy(s).into_owned()).unwrap_or_default();
                    return err(format!("the client disconnected: {why}"));
                }
                None => return err("an empty message"),
                _ => return Ok(p),
            }
        }
    }

    fn recv_any(&mut self) -> Result<Vec<u8>> {
        let seq = self.seq_in;
        self.seq_in = self.seq_in.wrapping_add(1);
        let body = if let Some(c) = self.cipher_in.clone() {
            let head = self.take(4)?;
            let len = c.length(seq, &head[..4].try_into().unwrap()) as usize;
            if !(8..=MAX_PACKET).contains(&len) {
                return err("bad packet length");
            }
            let rest = self.take(len + crypto::TAG)?;
            let mut packet = head;
            packet.extend_from_slice(&rest);
            match c.open(seq, &packet) {
                Some(b) => b,
                None => {
                    let _ = self.disconnect(MAC_ERROR, "corrupt packet");
                    return err("a packet failed its integrity check");
                }
            }
        } else {
            let head = self.take(4)?;
            let len = u32::from_be_bytes(head[..4].try_into().unwrap()) as usize;
            if !(8..=MAX_PACKET).contains(&len) {
                return err("bad packet length");
            }
            self.take(len)?
        };
        self.bytes_since_kex += body.len() as u64 + 4;
        let pad = usize::from(body[0]);
        if pad + 1 > body.len() {
            return err("bad padding");
        }
        Ok(body[1..body.len() - pad].to_vec())
    }

    pub fn disconnect(&mut self, reason: u32, text: &str) -> Result<()> {
        let m = Writer::new(MSG_DISCONNECT).u32(reason).string(text.as_bytes()).string(b"").finish();
        self.send(&m)
    }

    fn kexinit(&mut self) -> Vec<u8> {
        let mut cookie = [0u8; 16];
        self.random_bytes(&mut cookie);
        let mut kex = self.kex_methods.join(&b',');
        if self.session_id.is_none() {
            kex.extend_from_slice(b",");
            kex.extend_from_slice(KEX_STRICT_S);
        }
        Writer::new(MSG_KEXINIT)
            .raw(&cookie)
            .string(&kex)
            .string(crypto::HOST_KEY)
            .string(crypto::CIPHER)
            .string(crypto::CIPHER)
            // No MAC is used with the AEAD cipher; a name must still match.
            .string(b"hmac-sha2-256,hmac-sha2-512,hmac-sha1")
            .string(b"hmac-sha2-256,hmac-sha2-512,hmac-sha1")
            .string(b"none")
            .string(b"none")
            .string(b"")
            .string(b"")
            .bool(false)
            .u32(0)
            .finish()
    }

    /// The connection's state, to continue it in another process after
    /// authentication (ADR 0061): sequence numbers, keys, the session
    /// identifier, and what was read but not handled.
    pub fn export(&self) -> Vec<u8> {
        let key = |c: &Option<Chacha>| c.as_ref().map_or_else(Vec::new, |c| c.raw.to_vec());
        let mut w = Writer::default();
        w.u32(self.seq_in)
            .u32(self.seq_out)
            .bool(self.strict)
            .string(self.session_id.as_ref().map_or(&[][..], |s| &s[..]))
            .string(&key(&self.cipher_in))
            .string(&key(&self.cipher_out))
            .string(&self.client_version)
            .string(&self.buf)
            .u64(self.bytes_since_kex)
            .u64(self.kex_time as u64)
            .u32(self.queued.len() as u32);
        for m in &self.queued {
            w.string(m);
        }
        w.finish()
    }

    /// A transport on `stream` from `export`'s bytes.
    pub fn import(stream: S, state: &[u8], kex_methods: Vec<&'static [u8]>) -> Result<Transport<S>> {
        let mut r = Reader::new(state);
        let (seq_in, seq_out, strict) = (r.u32()?, r.u32()?, r.bool()?);
        let sid = r.string()?;
        let cipher = |k: &[u8]| -> Result<Option<Chacha>> {
            match k.len() {
                0 => Ok(None),
                64 => Ok(Some(Chacha::new(k.try_into().unwrap()))),
                _ => err("bad key in the connection's state"),
            }
        };
        let (cin, cout) = (cipher(r.string()?)?, cipher(r.string()?)?);
        let client_version = r.string()?.to_vec();
        let buf = r.string()?.to_vec();
        let (bytes_since_kex, kex_time) = (r.u64()?, r.u64()? as i64);
        let mut queued = VecDeque::new();
        for _ in 0..r.u32()? {
            queued.push_back(r.string()?.to_vec());
        }
        Ok(Transport {
            stream,
            buf,
            seq_in,
            seq_out,
            cipher_in: cin,
            cipher_out: cout,
            session_id: <[u8; 32]>::try_from(sid).ok(),
            strict,
            client_version,
            random: [0; 32],
            kex_methods,
            bytes_since_kex,
            kex_time,
            queued,
            deadline: None,
        })
    }

    /// Whether a key exchange is due: past `bytes` of traffic, or
    /// `secs` seconds (0: no time limit).
    pub fn rekey_due(&self, bytes: u64, secs: i64) -> bool {
        self.session_id.is_some() && (self.bytes_since_kex >= bytes || (secs > 0 && now_secs() - self.kex_time >= secs))
    }

    /// Start a key exchange (§9): our KEXINIT, then the client's; what
    /// it sent before that is kept for later.
    pub fn rekey(&mut self, host: &dyn HostSign) -> Result<()> {
        let ours = self.kexinit();
        self.send(&ours)?;
        loop {
            let m = self.recv_wire()?;
            if m[0] == MSG_KEXINIT {
                return self.exchange(host, ours, m);
            }
            if self.queued.len() > 1000 {
                return err("the client did not answer a key exchange");
            }
            self.queued.push_back(m);
        }
    }

    /// Run a key exchange (§7, RFC 8731). `client_kexinit` is the
    /// client's KEXINIT if it has already arrived (a rekey).
    pub fn key_exchange(&mut self, host: &dyn HostSign, client_kexinit: Option<Vec<u8>>) -> Result<()> {
        let ours = self.kexinit();
        self.send(&ours)?;
        let theirs = match client_kexinit {
            Some(k) => k,
            None => {
                let k = self.recv()?;
                if k[0] != MSG_KEXINIT {
                    return err("the client did not start with KEXINIT");
                }
                k
            }
        };
        self.exchange(host, ours, theirs)
    }

    fn exchange(&mut self, host: &dyn HostSign, ours: Vec<u8>, theirs: Vec<u8>) -> Result<()> {
        if theirs.len() < 17 {
            return err("a short KEXINIT");
        }
        let mut r = Reader::new(&theirs[17..]);
        let lists: Vec<Vec<&[u8]>> = (0..10).map(|_| r.name_list()).collect::<core::result::Result<_, _>>()?;
        let follows = r.bool()?;
        let first = self.session_id.is_none();
        if first && lists[0].contains(&KEX_STRICT_C) {
            self.strict = true;
        }
        fn pick<'a>(client: &[&'a [u8]], ours: &[&[u8]]) -> Option<&'a [u8]> {
            client.iter().find(|c| ours.contains(c)).copied()
        }
        let methods = self.kex_methods.clone();
        let kex = pick(&lists[0], &methods);
        let hostkey = pick(&lists[1], &[crypto::HOST_KEY]);
        let c2s = pick(&lists[2], &[crypto::CIPHER]);
        let s2c = pick(&lists[3], &[crypto::CIPHER]);
        let macs: [&[u8]; 3] = [b"hmac-sha2-256", b"hmac-sha2-512", b"hmac-sha1"];
        let (mac1, mac2) = (pick(&lists[4], &macs), pick(&lists[5], &macs));
        let (comp1, comp2) = (pick(&lists[6], &[b"none"]), pick(&lists[7], &[b"none"]));
        if kex.is_none() || hostkey.is_none() || c2s.is_none() || s2c.is_none() {
            let _ = self.disconnect(KEY_EXCHANGE_FAILED, "no common algorithms");
            return err("no common key exchange, host key or cipher algorithm");
        }
        if mac1.is_none() || mac2.is_none() || comp1.is_none() || comp2.is_none() {
            let _ = self.disconnect(KEY_EXCHANGE_FAILED, "no common algorithms");
            return err("no common MAC or compression algorithm");
        }
        if follows && lists[0].first() != kex.as_ref() {
            // A guessed packet for another method: ignore it (§7.1).
            self.recv_wire()?;
        }

        // KEX_ECDH_INIT and KEX_HYBRID_INIT share the number.
        let init = self.recv_wire()?;
        if init[0] != MSG_KEX_ECDH_INIT {
            return err("expected KEX_ECDH_INIT");
        }
        let c_init = Reader::new(&init[1..]).string()?.to_vec();
        let hybrid = kex == Some(crypto::KEX_MLKEM);
        // The client's X25519 value: all of it, or after the ML-KEM key.
        let want = if hybrid { crypto::MLKEM_EK + 32 } else { 32 };
        if c_init.len() != want {
            return err("bad client key exchange value");
        }
        let q_c: [u8; 32] = c_init[c_init.len() - 32..].try_into().unwrap();
        let mut secret = [0u8; 32];
        self.random_bytes(&mut secret);
        let q_s = crypto::x25519_public(&secret);
        let shared = crypto::x25519_shared(&secret, &q_c);
        if shared == [0; 32] {
            return err("the client's X25519 value is degenerate");
        }
        // Curve25519: K is the X25519 secret as an mpint (RFC 8731 §3).
        // Hybrid: the ML-KEM ciphertext goes before our X25519 value, and
        // K is SHA-256(ML-KEM secret || X25519 secret) as a string.
        let (k, s_reply) = if hybrid {
            let mut m = [0u8; 32];
            self.random_bytes(&mut m);
            let Some((ct, k_pq)) = crypto::mlkem768_encapsulate(&c_init[..crypto::MLKEM_EK], &m) else {
                let _ = self.disconnect(KEY_EXCHANGE_FAILED, "bad ML-KEM key");
                return err("the client's ML-KEM key is invalid");
            };
            let k = crypto::sha256(&[k_pq.as_slice(), &shared].concat());
            (Writer::default().string(&k).finish(), [ct.as_slice(), &q_s].concat())
        } else {
            (Writer::default().mpint(&shared).finish(), q_s.to_vec())
        };
        let k_s = host.blob();
        let mut hash_in = Writer::default();
        hash_in
            .string(&self.client_version)
            .string(VERSION)
            .string(&theirs)
            .string(&ours)
            .string(&k_s)
            .string(&c_init)
            .string(&s_reply)
            .raw(&k);
        let h = crypto::sha256(&hash_in.0);
        let session_id = *self.session_id.get_or_insert(h);
        let reply = Writer::new(MSG_KEX_ECDH_REPLY).string(&k_s).string(&s_reply).string(&host.sign(&h)).finish();
        self.send(&reply)?;
        self.send(&[MSG_NEWKEYS])?;
        // Keys (§7.2): HASH(K || H || letter || session_id), extended by
        // HASH(K || H || K1) to the 64 bytes the cipher needs.
        let derive = |letter: u8| -> [u8; 64] {
            let k1 = crypto::sha256(&[&k[..], &h, &[letter], &session_id].concat());
            let k2 = crypto::sha256(&[&k[..], &h, &k1].concat());
            let mut out = [0u8; 64];
            out[..32].copy_from_slice(&k1);
            out[32..].copy_from_slice(&k2);
            out
        };
        self.cipher_out = Some(Chacha::new(&derive(b'D')));
        if self.strict {
            self.seq_out = 0;
        }
        let nk = self.recv_wire()?;
        if nk != [MSG_NEWKEYS] {
            return err("expected NEWKEYS");
        }
        self.cipher_in = Some(Chacha::new(&derive(b'C')));
        if self.strict {
            self.seq_in = 0;
        }
        self.bytes_since_kex = 0;
        self.kex_time = now_secs();
        Ok(())
    }
}
