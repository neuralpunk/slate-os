// SPDX-License-Identifier: MIT OR Apache-2.0

//! The TLS client handshake and records (RFC 8446, and RFC 5246 for
//! servers without 1.3), without I/O. The caller sends what
//! [`Client::take_output`] gives, feeds what arrives to [`Client::feed`],
//! and reads application data with [`Client::read`].
//!
//! What it offers: TLS 1.3 with the cipher suites TLS_AES_128_GCM_SHA256,
//! TLS_AES_256_GCM_SHA384 and TLS_CHACHA20_POLY1305_SHA256; an X25519 key
//! share, and secp256r1 if the server asks for it in a
//! HelloRetryRequest; the signature schemes of `crypto`. TLS 1.2 with
//! ECDHE and AEAD suites only (`tls12`, ADR 0135). TLS 1.3 sessions are
//! resumed with the tickets a server gives ([`Ticket`], ADR 0136: a
//! pre-shared key with a new key share). No early data or client
//! certificates (a server that asks for one gets none).

mod tls12;

use alloc::string::String;
use alloc::vec::Vec;

use crate::Error;
use crate::crypto::{
    self, AeadAlg, CERT_SCHEMES, Group, HANDSHAKE_SCHEMES, HashAlg, Hasher, KeyShare, Scheme, TAG_LEN,
};
use crate::x509::{self, Roots};

// Record content types (RFC 8446 §5.1).
const CHANGE_CIPHER_SPEC: u8 = 20;
const ALERT: u8 = 21;
const HANDSHAKE: u8 = 22;
const APPLICATION_DATA: u8 = 23;
// Handshake message types (§4).
const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;
const NEW_SESSION_TICKET: u8 = 4;
const ENCRYPTED_EXTENSIONS: u8 = 8;
const CERTIFICATE: u8 = 11;
const CERTIFICATE_REQUEST: u8 = 13;
const CERTIFICATE_VERIFY: u8 = 15;
const FINISHED: u8 = 20;
const KEY_UPDATE: u8 = 24;
const MESSAGE_HASH: u8 = 254;
// Extensions (§4.2).
const SERVER_NAME: u16 = 0;
/// status_request (RFC 6066 §8): a stapled OCSP response, please.
const STATUS_REQUEST: u16 = 5;
const SUPPORTED_GROUPS: u16 = 10;
const SIGNATURE_ALGORITHMS: u16 = 13;
const SUPPORTED_VERSIONS: u16 = 43;
const COOKIE: u16 = 44;
const KEY_SHARE: u16 = 51;
const PRE_SHARED_KEY: u16 = 41;
const PSK_KEY_EXCHANGE_MODES: u16 = 45;
/// psk_dhe_ke (§4.2.9): the key share still made, for forward secrecy.
const PSK_DHE_KE: u8 = 1;
/// The longest a ticket is kept (§4.6.1: seven days).
const TICKET_LIFETIME_MAX: u32 = 604_800;
const TLS13: u16 = 0x0304;
/// A ServerHello with this random is a HelloRetryRequest (§4.1.3).
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11,
    0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];
/// The cipher suites offered (§B.4), in order of preference.
const SUITES: &[(u16, AeadAlg, HashAlg)] = &[
    (0x1301, AeadAlg::Aes128Gcm, HashAlg::Sha256),
    (0x1303, AeadAlg::ChaCha20Poly1305, HashAlg::Sha256),
    (0x1302, AeadAlg::Aes256Gcm, HashAlg::Sha384),
];
/// The most plaintext a record holds (§5.1), and the most ciphertext.
const MAX_PLAIN: usize = 1 << 14;
const MAX_RECORD: usize = MAX_PLAIN + 256;

/// One direction's record protection.
#[derive(Debug)]
struct Keys {
    secret: Vec<u8>,
    key: Vec<u8>,
    iv: [u8; 12],
    seq: u64,
}

impl Keys {
    fn new(aead: AeadAlg, hash: HashAlg, secret: Vec<u8>) -> Keys {
        let key = crypto::expand_label(hash, &secret, b"key", b"", aead.key_len());
        let iv: [u8; 12] = crypto::expand_label(hash, &secret, b"iv", b"", 12).try_into().unwrap();
        Keys { secret, key, iv, seq: 0 }
    }

    /// The next record's nonce (§5.3).
    fn nonce(&mut self) -> [u8; 12] {
        let mut n = self.iv;
        for (i, b) in self.seq.to_be_bytes().iter().enumerate() {
            n[4 + i] ^= b;
        }
        self.seq += 1;
        n
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    ServerHello,
    EncryptedExtensions,
    Certificate,
    CertificateVerify,
    Finished,
    // TLS 1.2: the server's Certificate, then its key exchange (or
    // certificate status), then a certificate request or the end of its
    // flight; after ours, its ChangeCipherSpec and Finished.
    Certificate12,
    KeyExchange12,
    HelloDone12,
    ChangeCipherSpec12,
    Finished12,
    Connected,
    Closed,
}

/// A session ticket (RFC 8446 §4.6.1): what resumes a session with the
/// same host later, as a pre-shared key.
#[derive(Clone)]
pub struct Ticket {
    pub host: String,
    hash: HashAlg,
    psk: Vec<u8>,
    ticket: Vec<u8>,
    /// When it came (seconds since 1970), and for how long it lasts.
    issued: i64,
    lifetime: u32,
    age_add: u32,
}

impl core::fmt::Debug for Ticket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ticket({}, {}s)", self.host, self.lifetime)
    }
}

impl Ticket {
    /// Whether it may resume a session with `host` at `now`.
    pub fn usable(&self, host: &str, now: i64) -> bool {
        self.host == host && now >= self.issued && now - self.issued < i64::from(self.lifetime)
    }
}

/// A TLS connection's client side.
pub struct Client {
    host: String,
    roots: Roots,
    now: i64,
    state: State,
    random: [u8; 32],
    session_id: [u8; 32],
    /// The secret for a second key share, if the server asks for one.
    spare: [u8; 32],
    share: KeyShare,
    /// The ClientHello as sent, until the cipher suite (and so the hash)
    /// is known.
    first_hello: Vec<u8>,
    retried: bool,
    suite: Option<(AeadAlg, HashAlg)>,
    transcript: Option<Hasher>,
    handshake_secret: Vec<u8>,
    client_hs: Vec<u8>,
    server_hs: Vec<u8>,
    read: Option<Keys>,
    /// How many times the read keys changed.
    epoch: u32,
    write: Option<Keys>,
    /// Records not yet whole.
    incoming: Vec<u8>,
    /// Handshake messages not yet whole.
    messages: Vec<u8>,
    chain: Vec<Vec<u8>>,
    server_key: Option<crypto::PublicKey>,
    cert_requested: Option<Vec<u8>>,
    app: Vec<u8>,
    output: Vec<u8>,
    /// A TLS 1.2 handshake's state, once the server chose 1.2.
    tls12: Option<tls12::Tls12>,
    /// The ticket offered, and whether the server took it.
    offered: Option<Ticket>,
    resumed: bool,
    /// The master secret, then the resumption secret (§7.1).
    master: Vec<u8>,
    resumption: Vec<u8>,
    /// Tickets received, for the caller to take.
    tickets: Vec<Ticket>,
    /// The server certificate's issuer (for its OCSP status), whether
    /// the certificate must come with a status, and whether a good one
    /// came (ADR 0137).
    issuer: Vec<u8>,
    must_staple: bool,
    staple_good: bool,
    /// TLS 1.2: the server said it will send a CertificateStatus.
    status_promised: bool,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Client({}, {:?})", self.host, self.state)
    }
}

/// Bytes read one field at a time.
struct Reader<'a> {
    b: &'a [u8],
}

const DECODE: Error = Error::Illegal("a message that does not decode");

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.b.len() < n {
            return Err(DECODE);
        }
        let (a, rest) = self.b.split_at(n);
        self.b = rest;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u24(&mut self) -> Result<usize, Error> {
        let b = self.take(3)?;
        Ok(usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]))
    }
    fn vec8(&mut self) -> Result<&'a [u8], Error> {
        let n = usize::from(self.u8()?);
        self.take(n)
    }
    fn vec16(&mut self) -> Result<&'a [u8], Error> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }
    fn vec24(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u24()?;
        self.take(n)
    }
    fn done(&self) -> Result<(), Error> {
        if self.b.is_empty() { Ok(()) } else { Err(DECODE) }
    }
}

fn put16(out: &mut Vec<u8>, v: usize) {
    out.extend_from_slice(&(v as u16).to_be_bytes());
}

fn put24(out: &mut Vec<u8>, v: usize) {
    out.extend_from_slice(&(v as u32).to_be_bytes()[1..]);
}

/// A handshake message: its type, a 24-bit length, the body.
fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(body.len() + 4);
    m.push(kind);
    put24(&mut m, body.len());
    m.extend_from_slice(body);
    m
}

fn extension(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
    put16(out, usize::from(kind));
    put16(out, body.len());
    out.extend_from_slice(body);
}

/// A plaintext record (the ClientHello's, alerts before keys).
fn record(kind: u8, version: u16, body: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(body.len() + 5);
    r.push(kind);
    r.extend_from_slice(&version.to_be_bytes());
    put16(&mut r, body.len());
    r.extend_from_slice(body);
    r
}

impl Client {
    /// Start a connection to `host` (a name, or an IP literal), trusting
    /// `roots`, at `now` (seconds since 1970). `random` is 96 random
    /// bytes: the hello's random, the session id and the key share's
    /// secret; `spare` another 32 for a second share.
    pub fn new(host: &str, roots: Roots, now: i64, random: [u8; 96], spare: [u8; 32]) -> Result<Client, Error> {
        Client::resume(host, roots, now, random, spare, None)
    }

    /// [`Client::new`], offering `ticket` (from an earlier connection to
    /// the same host) to resume its session; the server may decline.
    pub fn resume(
        host: &str,
        roots: Roots,
        now: i64,
        random: [u8; 96],
        spare: [u8; 32],
        ticket: Option<Ticket>,
    ) -> Result<Client, Error> {
        let share = KeyShare::new(Group::X25519, random[64..96].try_into().unwrap())?;
        let mut c = Client {
            host: String::from(host),
            roots,
            now,
            state: State::ServerHello,
            random: random[..32].try_into().unwrap(),
            session_id: random[32..64].try_into().unwrap(),
            spare,
            share,
            first_hello: Vec::new(),
            retried: false,
            suite: None,
            transcript: None,
            handshake_secret: Vec::new(),
            client_hs: Vec::new(),
            server_hs: Vec::new(),
            read: None,
            epoch: 0,
            write: None,
            incoming: Vec::new(),
            messages: Vec::new(),
            chain: Vec::new(),
            server_key: None,
            cert_requested: None,
            app: Vec::new(),
            output: Vec::new(),
            tls12: None,
            offered: ticket.filter(|t| t.usable(host, now)),
            resumed: false,
            master: Vec::new(),
            resumption: Vec::new(),
            tickets: Vec::new(),
            issuer: Vec::new(),
            must_staple: false,
            staple_good: false,
            status_promised: false,
        };
        let hello = c.client_hello(None, None);
        c.first_hello = hello.clone();
        // The first record says TLS 1.0 for old middleboxes (§5.1).
        c.output.extend(record(HANDSHAKE, 0x0301, &hello));
        Ok(c)
    }

    /// The ClientHello; with a ticket, its binder over the hello so far
    /// (`prefix`: the transcript before it, after a retry).
    fn client_hello(&self, cookie: Option<&[u8]>, prefix: Option<&Hasher>) -> Vec<u8> {
        let mut b = Vec::with_capacity(512);
        b.extend_from_slice(&0x0303u16.to_be_bytes());
        b.extend_from_slice(&self.random);
        b.push(32);
        b.extend_from_slice(&self.session_id);
        put16(&mut b, (SUITES.len() + tls12::SUITES12.len()) * 2);
        for (code, _, _) in SUITES {
            b.extend_from_slice(&code.to_be_bytes());
        }
        for (code, ..) in tls12::SUITES12 {
            b.extend_from_slice(&code.to_be_bytes());
        }
        b.extend_from_slice(&[1, 0]); // no compression
        let mut ext = Vec::new();
        let ip = self.host.contains(':') || self.host.bytes().all(|c| c.is_ascii_digit() || c == b'.');
        if !ip {
            // server_name (RFC 6066 §3): one host_name.
            let name = self.host.trim_end_matches('.').as_bytes();
            let mut sni = Vec::new();
            put16(&mut sni, name.len() + 3);
            sni.push(0);
            put16(&mut sni, name.len());
            sni.extend_from_slice(name);
            extension(&mut ext, SERVER_NAME, &sni);
        }
        extension(&mut ext, SUPPORTED_VERSIONS, &[4, 0x03, 0x04, 0x03, 0x03]);
        // status_request: OCSP, no responder ids, no request extensions.
        extension(&mut ext, STATUS_REQUEST, &[1, 0, 0, 0, 0]);
        // For TLS 1.2: uncompressed points only, the extended master
        // secret, no renegotiation so far.
        extension(&mut ext, tls12::EC_POINT_FORMATS, &[1, 0]);
        extension(&mut ext, tls12::EXTENDED_MASTER_SECRET, &[]);
        extension(&mut ext, tls12::RENEGOTIATION_INFO, &[0]);
        // P-384 too: a TLS 1.2 server's ECDSA certificate must be on a
        // listed curve (RFC 8422 §5.1.1).
        let mut groups = Vec::new();
        put16(&mut groups, 6);
        for g in [Group::X25519, Group::Secp256r1, Group::Secp384r1] {
            groups.extend_from_slice(&g.code().to_be_bytes());
        }
        extension(&mut ext, SUPPORTED_GROUPS, &groups);
        let mut sigs = Vec::new();
        let all: Vec<u16> = HANDSHAKE_SCHEMES.iter().chain(CERT_SCHEMES).map(|(c, _)| *c).collect();
        put16(&mut sigs, all.len() * 2);
        for c in all {
            sigs.extend_from_slice(&c.to_be_bytes());
        }
        extension(&mut ext, SIGNATURE_ALGORITHMS, &sigs);
        let mut ks = Vec::new();
        put16(&mut ks, self.share.public.len() + 4);
        ks.extend_from_slice(&self.share.group.code().to_be_bytes());
        put16(&mut ks, self.share.public.len());
        ks.extend_from_slice(&self.share.public);
        extension(&mut ext, KEY_SHARE, &ks);
        if let Some(c) = cookie {
            let mut v = Vec::new();
            put16(&mut v, c.len());
            v.extend_from_slice(c);
            extension(&mut ext, COOKIE, &v);
        }
        // A ticket: psk_dhe_ke, then pre_shared_key, last of all (§4.2.11):
        // its identity, the ticket's age as the server will see it, and a
        // binder, filled in below.
        let hash_len = self.offered.as_ref().map_or(0, |t| t.hash.size());
        if let Some(t) = &self.offered {
            extension(&mut ext, PSK_KEY_EXCHANGE_MODES, &[1, PSK_DHE_KE]);
            let age = ((self.now - t.issued).max(0) as u32).wrapping_mul(1000).wrapping_add(t.age_add);
            let mut ids = Vec::new();
            put16(&mut ids, t.ticket.len());
            ids.extend_from_slice(&t.ticket);
            ids.extend_from_slice(&age.to_be_bytes());
            let mut psk = Vec::new();
            put16(&mut psk, ids.len());
            psk.extend_from_slice(&ids);
            put16(&mut psk, hash_len + 1);
            psk.push(hash_len as u8);
            psk.resize(psk.len() + hash_len, 0);
            extension(&mut ext, PRE_SHARED_KEY, &psk);
        }
        put16(&mut b, ext.len());
        b.extend_from_slice(&ext);
        let mut hello = message(CLIENT_HELLO, &b);
        if let Some(t) = &self.offered {
            // The binder (§4.2.11.2): HMAC with the binder key's finished
            // key over the transcript up to the binders.
            let cut = hello.len() - hash_len - 3;
            let mut h = prefix.cloned().unwrap_or_else(|| Hasher::new(t.hash));
            h.update(&hello[..cut]);
            let early = crypto::hkdf_extract(t.hash, &[], &t.psk);
            let binder_key = crypto::derive_secret(t.hash, &early, b"res binder", &t.hash.hash(b""));
            let key = crypto::expand_label(t.hash, &binder_key, b"finished", b"", t.hash.size());
            let binder = crypto::hmac(t.hash, &key, &h.peek());
            let n = hello.len();
            hello[n - hash_len..].copy_from_slice(&binder);
        }
        hello
    }

    /// Whether the server resumed the session of the ticket offered.
    pub fn resumed(&self) -> bool {
        self.resumed
    }

    /// The tickets the server gave so far (taken), for resuming later.
    pub fn take_tickets(&mut self) -> Vec<Ticket> {
        core::mem::take(&mut self.tickets)
    }

    /// The bytes to send now.
    pub fn take_output(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.output)
    }

    /// Whether the handshake is done (application data can go both ways).
    pub fn is_connected(&self) -> bool {
        self.state == State::Connected
    }

    /// Whether the server closed the connection (close_notify).
    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// Application data received so far (taken).
    pub fn read(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.app)
    }

    /// Take bytes from the server. On an error the matching alert is
    /// queued in the output; the connection is then over.
    pub fn feed(&mut self, data: &[u8]) -> Result<(), Error> {
        let r = self.feed_inner(data);
        if let Err(e) = &r
            && !matches!(e, Error::Alert(_))
        {
            self.alert(e.alert());
            self.state = State::Closed;
        }
        r
    }

    fn feed_inner(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.state == State::Closed {
            return Ok(());
        }
        self.incoming.extend_from_slice(data);
        loop {
            if self.incoming.len() < 5 {
                return Ok(());
            }
            let kind = self.incoming[0];
            let len = usize::from(u16::from_be_bytes([self.incoming[3], self.incoming[4]]));
            if len > MAX_RECORD {
                return Err(Error::Illegal("a record too long"));
            }
            if self.incoming.len() < 5 + len {
                return Ok(());
            }
            let rec: Vec<u8> = self.incoming.drain(..5 + len).collect();
            self.record(kind, &rec)?;
            if self.state == State::Closed {
                return Ok(());
            }
        }
    }

    fn record(&mut self, kind: u8, rec: &[u8]) -> Result<(), Error> {
        let body = &rec[5..];
        if self.tls12.is_some() {
            if kind == CHANGE_CIPHER_SPEC {
                return self.change_cipher_spec12(body);
            }
            let (kind, plain) = self.record12(kind, rec)?;
            return self.content(kind, plain);
        }
        // A change_cipher_spec of one byte may come during the handshake
        // and is ignored (§5).
        if kind == CHANGE_CIPHER_SPEC {
            return if body == [1] && self.state != State::Connected {
                Ok(())
            } else {
                Err(Error::Illegal("an unexpected change_cipher_spec"))
            };
        }
        let (kind, plain) = match &mut self.read {
            None => (kind, body.to_vec()),
            Some(keys) => {
                if kind != APPLICATION_DATA {
                    return Err(Error::Illegal("a plaintext record after the keys"));
                }
                let (aead, _) = self.suite.ok_or(Error::Internal)?;
                let mut d = body.to_vec();
                let nonce = keys.nonce();
                crypto::open(aead, &keys.key, &nonce, &rec[..5], &mut d)?;
                // The content type is the last byte that is not padding.
                let end = d.iter().rposition(|&b| b != 0).ok_or(Error::Illegal("a record with no content type"))?;
                let inner = d[end];
                d.truncate(end);
                if d.len() > MAX_PLAIN {
                    return Err(Error::Illegal("a record too long"));
                }
                (inner, d)
            }
        };
        self.content(kind, plain)
    }

    /// A record's content, by type.
    fn content(&mut self, kind: u8, plain: Vec<u8>) -> Result<(), Error> {
        match kind {
            ALERT => self.alert_received(&plain),
            HANDSHAKE => {
                self.messages.extend_from_slice(&plain);
                self.handshake_messages()
            }
            APPLICATION_DATA if self.state == State::Connected => {
                self.app.extend_from_slice(&plain);
                Ok(())
            }
            _ => Err(Error::Illegal("an unexpected record")),
        }
    }

    fn alert_received(&mut self, b: &[u8]) -> Result<(), Error> {
        if b.len() != 2 {
            return Err(DECODE);
        }
        if b[1] == 0 {
            self.state = State::Closed;
            return Ok(());
        }
        self.state = State::Closed;
        Err(Error::Alert(b[1]))
    }

    /// Queue an alert (encrypted once there are keys).
    fn alert(&mut self, desc: u8) {
        let level = if desc == 0 { 1 } else { 2 };
        self.send(ALERT, &[level, desc]);
    }

    /// Queue `data` as records of `kind`.
    fn send(&mut self, kind: u8, data: &[u8]) {
        let Some((aead, _)) = self.suite else {
            self.output.extend(record(kind, 0x0303, data));
            return;
        };
        let Some(keys) = &mut self.write else {
            self.output.extend(record(kind, 0x0303, data));
            return;
        };
        if self.tls12.is_some() {
            tls12::seal(aead, keys, kind, data, &mut self.output);
            return;
        }
        for chunk in data.chunks(MAX_PLAIN) {
            let mut inner = Vec::with_capacity(chunk.len() + 1 + TAG_LEN);
            inner.extend_from_slice(chunk);
            inner.push(kind);
            let mut head = Vec::with_capacity(5);
            head.push(APPLICATION_DATA);
            head.extend_from_slice(&0x0303u16.to_be_bytes());
            put16(&mut head, inner.len() + TAG_LEN);
            let nonce = keys.nonce();
            crypto::seal(aead, &keys.key, &nonce, &head, &mut inner);
            self.output.extend_from_slice(&head);
            self.output.extend_from_slice(&inner);
        }
    }

    /// Queue application data (after the handshake).
    pub fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.state != State::Connected {
            return Err(Error::Internal);
        }
        self.send(APPLICATION_DATA, data);
        Ok(())
    }

    /// Say goodbye (close_notify).
    pub fn close(&mut self) {
        if self.state == State::Connected {
            self.alert(0);
        }
    }

    fn handshake_messages(&mut self) -> Result<(), Error> {
        loop {
            if self.messages.len() < 4 {
                return Ok(());
            }
            let len = usize::from(self.messages[1]) << 16
                | usize::from(self.messages[2]) << 8
                | usize::from(self.messages[3]);
            if len > 1 << 20 {
                return Err(Error::Illegal("a handshake message too long"));
            }
            if self.messages.len() < 4 + len {
                return Ok(());
            }
            let msg: Vec<u8> = self.messages.drain(..4 + len).collect();
            let epoch = self.epoch;
            self.handshake(&msg)?;
            // Keys change only between records (§5.1).
            if self.epoch != epoch && !self.messages.is_empty() {
                return Err(Error::Illegal("data after a key change in the same record"));
            }
        }
    }

    fn transcript(&mut self) -> Result<&mut Hasher, Error> {
        self.transcript.as_mut().ok_or(Error::Internal)
    }

    fn hash(&self) -> Result<HashAlg, Error> {
        self.suite.map(|(_, h)| h).ok_or(Error::Internal)
    }

    fn handshake(&mut self, msg: &[u8]) -> Result<(), Error> {
        if self.tls12.is_some() {
            return self.handshake12(msg);
        }
        let kind = msg[0];
        let body = &msg[4..];
        match (self.state, kind) {
            (State::ServerHello, SERVER_HELLO) => self.server_hello(msg),
            (State::EncryptedExtensions, ENCRYPTED_EXTENSIONS) => {
                let mut r = Reader { b: body };
                r.vec16()?;
                r.done()?;
                self.transcript()?.update(msg);
                // A resumed session has no certificate (§2.2).
                self.state = if self.resumed { State::Finished } else { State::Certificate };
                Ok(())
            }
            (State::Certificate, CERTIFICATE_REQUEST) => {
                let mut r = Reader { b: body };
                self.cert_requested = Some(r.vec8()?.to_vec());
                self.transcript()?.update(msg);
                Ok(())
            }
            (State::Certificate, CERTIFICATE) => self.certificate(msg),
            (State::CertificateVerify, CERTIFICATE_VERIFY) => self.certificate_verify(msg),
            (State::Finished, FINISHED) => self.finished(msg),
            (State::Connected, NEW_SESSION_TICKET) => self.new_session_ticket(body),
            (State::Connected, KEY_UPDATE) => self.key_update(body),
            _ => Err(Error::Illegal("an unexpected handshake message")),
        }
    }

    fn server_hello(&mut self, msg: &[u8]) -> Result<(), Error> {
        let mut r = Reader { b: &msg[4..] };
        match r.u16()? {
            0x0303 => {}
            v if v < 0x0303 => return Err(Error::Unsupported("TLS 1.2 or 1.3 (the server speaks only older)")),
            _ => return Err(Error::Illegal("a bad legacy version")),
        }
        let random = r.take(32)?;
        let session_id = r.vec8()?;
        let suite_code = r.u16()?;
        if r.u8()? != 0 {
            return Err(Error::Illegal("compression"));
        }
        let ext_bytes = r.vec16()?;
        r.done()?;
        // No supported_versions: TLS 1.2 (RFC 8446 §4.2.1).
        let mut all = Vec::new();
        let mut scan = Reader { b: ext_bytes };
        while !scan.b.is_empty() {
            all.push((scan.u16()?, scan.vec16()?));
        }
        if !all.iter().any(|(k, _)| *k == SUPPORTED_VERSIONS) && !self.retried {
            return self.server_hello12(msg, random, suite_code, &all);
        }
        if session_id != self.session_id {
            return Err(Error::Illegal("a session id not ours"));
        }
        let mut exts = Reader { b: ext_bytes };
        let (mut version, mut share, mut selected, mut cookie, mut psk) = (None, None, None, None, None);
        let retry = random == HRR_RANDOM;
        while !exts.b.is_empty() {
            let kind = exts.u16()?;
            let mut e = Reader { b: exts.vec16()? };
            match kind {
                SUPPORTED_VERSIONS => version = Some(e.u16()?),
                KEY_SHARE if retry => selected = Some(e.u16()?),
                KEY_SHARE => {
                    let g = e.u16()?;
                    share = Some((g, e.vec16()?.to_vec()));
                }
                COOKIE if retry => cookie = Some(e.vec16()?.to_vec()),
                PRE_SHARED_KEY if !retry && self.offered.is_some() => psk = Some(e.u16()?),
                _ => return Err(Error::Illegal("an extension the server may not send")),
            }
            e.done()?;
        }
        if version != Some(TLS13) {
            return Err(Error::Unsupported("TLS 1.3"));
        }
        let (_, aead, hash) =
            *SUITES.iter().find(|(c, _, _)| *c == suite_code).ok_or(Error::Illegal("a cipher suite not offered"))?;
        if let Some((a, h)) = self.suite
            && (a, h) != (aead, hash)
        {
            return Err(Error::Illegal("the cipher suite changed after a retry"));
        }
        self.suite = Some((aead, hash));
        if retry {
            return self.retry(msg, hash, selected, cookie);
        }
        let mut t = match self.transcript.take() {
            Some(t) => t,
            None => {
                let mut t = Hasher::new(hash);
                t.update(&self.first_hello);
                t
            }
        };
        t.update(msg);
        let (group, key) = share.ok_or(Error::Illegal("no key share"))?;
        if group != self.share.group.code() {
            return Err(Error::Illegal("a key share in a group not offered"));
        }
        let shared = self.share.agree(&key)?;
        // The key schedule (§7.1), from the ticket's key if the server took
        // it (the first identity, with the same hash), else from zeros.
        let zero = alloc::vec![0u8; hash.size()];
        let ikm = match (psk, &self.offered) {
            (None, _) => zero.clone(),
            (Some(0), Some(t)) if t.hash == hash => {
                self.resumed = true;
                t.psk.clone()
            }
            _ => return Err(Error::Illegal("a pre-shared key not offered")),
        };
        let early = crypto::hkdf_extract(hash, &[], &ikm);
        let empty = hash.hash(b"");
        let derived = crypto::derive_secret(hash, &early, b"derived", &empty);
        self.handshake_secret = crypto::hkdf_extract(hash, &derived, &shared);
        let th = t.peek();
        self.client_hs = crypto::derive_secret(hash, &self.handshake_secret, b"c hs traffic", &th);
        self.server_hs = crypto::derive_secret(hash, &self.handshake_secret, b"s hs traffic", &th);
        self.set_read(Keys::new(aead, hash, self.server_hs.clone()));
        self.transcript = Some(t);
        self.state = State::EncryptedExtensions;
        Ok(())
    }

    /// A HelloRetryRequest (§4.1.4): a share in the group asked for, once.
    fn retry(
        &mut self,
        msg: &[u8],
        hash: HashAlg,
        selected: Option<u16>,
        cookie: Option<Vec<u8>>,
    ) -> Result<(), Error> {
        if self.retried {
            return Err(Error::Illegal("a second HelloRetryRequest"));
        }
        self.retried = true;
        let group = selected.and_then(Group::from_code).ok_or(Error::Unsupported("a key exchange group"))?;
        if group == self.share.group {
            return Err(Error::Illegal("a retry for the group already offered"));
        }
        self.share = KeyShare::new(group, self.spare)?;
        // The transcript starts with the first hello's hash (§4.4.1).
        let mut t = Hasher::new(hash);
        let h = hash.hash(&self.first_hello);
        t.update(&message(MESSAGE_HASH, &h));
        t.update(msg);
        // The binder covers the transcript so far (§4.2.11.2), unless the
        // retry's suite has another hash than the ticket's: then no ticket.
        if self.offered.as_ref().is_some_and(|tk| tk.hash != hash) {
            self.offered = None;
        }
        let hello = self.client_hello(cookie.as_deref(), Some(&t));
        t.update(&hello);
        self.transcript = Some(t);
        // A compatibility change_cipher_spec, then the second hello.
        self.output.extend(record(CHANGE_CIPHER_SPEC, 0x0303, &[1]));
        self.output.extend(record(HANDSHAKE, 0x0303, &hello));
        Ok(())
    }

    fn certificate(&mut self, msg: &[u8]) -> Result<(), Error> {
        let mut r = Reader { b: &msg[4..] };
        if !r.vec8()?.is_empty() {
            return Err(Error::Illegal("a certificate request context"));
        }
        let mut list = Reader { b: r.vec24()? };
        r.done()?;
        let mut chain = Vec::new();
        let mut status = None;
        while !list.b.is_empty() {
            chain.push(list.vec24()?.to_vec());
            // Per-certificate extensions: the server certificate's OCSP
            // status (RFC 8446 §4.4.2.1); others (SCT) unused.
            let mut exts = Reader { b: list.vec16()? };
            while !exts.b.is_empty() {
                let (kind, body) = (exts.u16()?, exts.vec16()?);
                if kind == STATUS_REQUEST && chain.len() == 1 {
                    status = Some(body.to_vec());
                }
            }
        }
        let v = x509::verify_full(&chain, &self.roots, &self.host, self.now)?;
        self.server_key = Some(v.key);
        self.issuer = v.issuer;
        self.must_staple = v.must_staple;
        self.chain = chain;
        if let Some(s) = status {
            self.stapled(&s)?;
        }
        self.staple_needed()?;
        self.transcript()?.update(msg);
        self.state = State::CertificateVerify;
        Ok(())
    }

    fn certificate_verify(&mut self, msg: &[u8]) -> Result<(), Error> {
        let mut r = Reader { b: &msg[4..] };
        let code = r.u16()?;
        let sig = r.vec16()?;
        r.done()?;
        let scheme: Scheme = HANDSHAKE_SCHEMES
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, s)| *s)
            .ok_or(Error::Illegal("a signature scheme not offered"))?;
        // §4.4.3: 64 spaces, the context string, a zero, the transcript.
        let th = self.transcript()?.peek();
        let mut content = alloc::vec![0x20u8; 64];
        content.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
        content.extend_from_slice(&th);
        let key = self.server_key.as_ref().ok_or(Error::Internal)?;
        if !scheme.fits(key) {
            return Err(Error::Illegal("a signature scheme that does not fit the key"));
        }
        crypto::verify(key, scheme, &content, sig).map_err(|_| Error::BadSignature)?;
        self.transcript()?.update(msg);
        self.state = State::Finished;
        Ok(())
    }

    fn finished(&mut self, msg: &[u8]) -> Result<(), Error> {
        let hash = self.hash()?;
        let (aead, _) = self.suite.ok_or(Error::Internal)?;
        let th = self.transcript()?.peek();
        let key = crypto::expand_label(hash, &self.server_hs, b"finished", b"", hash.size());
        let want = crypto::hmac(hash, &key, &th);
        let got = &msg[4..];
        let diff = want.iter().zip(got).fold((want.len() != got.len()) as u8, |d, (a, b)| d | (a ^ b));
        if diff != 0 {
            return Err(Error::BadSignature);
        }
        self.transcript()?.update(msg);
        // The application secrets come from the transcript to here.
        let th = self.transcript()?.peek();
        let zero = alloc::vec![0u8; hash.size()];
        let empty = hash.hash(b"");
        let derived = crypto::derive_secret(hash, &self.handshake_secret, b"derived", &empty);
        let master = crypto::hkdf_extract(hash, &derived, &zero);
        let client_ap = crypto::derive_secret(hash, &master, b"c ap traffic", &th);
        let server_ap = crypto::derive_secret(hash, &master, b"s ap traffic", &th);
        // Our flight under the handshake keys: a compatibility
        // change_cipher_spec, an empty Certificate if one was asked for,
        // and Finished.
        self.output.extend(record(CHANGE_CIPHER_SPEC, 0x0303, &[1]));
        self.write = Some(Keys::new(aead, hash, self.client_hs.clone()));
        if let Some(context) = self.cert_requested.take() {
            let mut b = Vec::new();
            b.push(context.len() as u8);
            b.extend_from_slice(&context);
            put24(&mut b, 0);
            let m = message(CERTIFICATE, &b);
            self.transcript()?.update(&m);
            self.send(HANDSHAKE, &m);
        }
        let th = self.transcript()?.peek();
        let key = crypto::expand_label(hash, &self.client_hs, b"finished", b"", hash.size());
        let fin = message(FINISHED, &crypto::hmac(hash, &key, &th));
        self.send(HANDSHAKE, &fin);
        // The resumption secret: the transcript through our Finished.
        self.transcript()?.update(&fin);
        let th = self.transcript()?.peek();
        self.resumption = crypto::derive_secret(hash, &master, b"res master", &th);
        self.master = master;
        self.write = Some(Keys::new(aead, hash, client_ap));
        self.set_read(Keys::new(aead, hash, server_ap));
        self.state = State::Connected;
        Ok(())
    }

    /// A NewSessionTicket (§4.6.1): its key from the resumption secret and
    /// the ticket's nonce; kept (the four newest) for the caller.
    fn new_session_ticket(&mut self, body: &[u8]) -> Result<(), Error> {
        let mut r = Reader { b: body };
        let lifetime = r.u32()?;
        let age_add = r.u32()?;
        let nonce = r.vec8()?;
        let ticket = r.vec16()?;
        r.vec16()?; // extensions (early data): unused
        r.done()?;
        if ticket.is_empty() || lifetime == 0 || self.resumption.is_empty() {
            return Ok(());
        }
        let hash = self.hash()?;
        let psk = crypto::expand_label(hash, &self.resumption, b"resumption", nonce, hash.size());
        if self.tickets.len() >= 4 {
            self.tickets.remove(0);
        }
        self.tickets.push(Ticket {
            host: self.host.clone(),
            hash,
            psk,
            ticket: ticket.to_vec(),
            issued: self.now,
            lifetime: lifetime.min(TICKET_LIFETIME_MAX),
            age_add,
        });
        Ok(())
    }

    /// A KeyUpdate (§4.6.3): new read keys, and new write keys too if the
    /// server asks.
    fn key_update(&mut self, body: &[u8]) -> Result<(), Error> {
        let request = match body {
            [0] => false,
            [1] => true,
            _ => return Err(DECODE),
        };
        let hash = self.hash()?;
        let (aead, _) = self.suite.ok_or(Error::Internal)?;
        let read = self.read.as_ref().ok_or(Error::Internal)?;
        let next = crypto::expand_label(hash, &read.secret, b"traffic upd", b"", hash.size());
        self.set_read(Keys::new(aead, hash, next));
        if request {
            self.send(HANDSHAKE, &message(KEY_UPDATE, &[0]));
            let write = self.write.as_ref().ok_or(Error::Internal)?;
            let next = crypto::expand_label(hash, &write.secret, b"traffic upd", b"", hash.size());
            self.write = Some(Keys::new(aead, hash, next));
        }
        Ok(())
    }

    /// A stapled status (CertificateStatus: type 1, OCSP, then the
    /// response): revoked ends the connection; good is noted; one that
    /// can't be used (unknown, unreadable, out of date) is as if none came
    /// (ADR 0137).
    fn stapled(&mut self, body: &[u8]) -> Result<(), Error> {
        let mut r = Reader { b: body };
        if r.u8()? != 1 {
            return Ok(());
        }
        let resp = r.vec24()?;
        r.done()?;
        let (Some(leaf), Ok(issuer)) = (self.chain.first(), crate::x509::Cert::parse(&self.issuer)) else {
            return Ok(());
        };
        let leaf = crate::x509::Cert::parse(leaf)?;
        match crate::ocsp::check(resp, &leaf, &issuer, self.now) {
            Ok(crate::ocsp::Status::Revoked) => Err(Error::Revoked),
            Ok(crate::ocsp::Status::Good) => {
                self.staple_good = true;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// A must-staple certificate (RFC 7633) with no good status: refused.
    fn staple_needed(&self) -> Result<(), Error> {
        if self.must_staple && !self.staple_good {
            return Err(Error::BadCertificate("must come with its OCSP status, and didn't"));
        }
        Ok(())
    }

    fn set_read(&mut self, k: Keys) {
        self.read = Some(k);
        self.epoch += 1;
    }

    /// The server's certificates, as it sent them.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.chain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(parts: &[&str]) -> Vec<u8> {
        let s: String = parts.concat();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // RFC 8448 §3, "Simple 1-RTT Handshake": the keys, the hellos, and the
    // server's encrypted flight.
    const CLIENT_PRIV: &[&str] = &["49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005"];
    const SERVER_PUB: &[&str] = &["c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f"];
    const CH: &[&str] = &[
        "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece700000613011303130201",
        "0000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400",
        "230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b00",
        "03020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c",
        "00024001",
    ];
    const SH: &[&str] = &[
        "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024",
        "001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304",
    ];
    const ENC_RECORD: &[&str] = &[
        "17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40aa40aa2b8ea73f848a7ca",
        "07612ef9f945cb960b4068905123ea78b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13b",
        "d9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9d7477609aee6e122a4cf51427325250c",
        "7d0e509289444c9b3a648f1d71035d2ed65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd61092",
        "8d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead686945ba246ab66e5edd8044b4c6de3fcf2a8",
        "9441ac66272fd8fb330ef8190579b3684596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f",
        "4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26f59ecaba9acbbb317b66d902f4f292a3",
        "6ac1b639c637ce343117b659622245317b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e",
        "1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da8c87c843f5e56eb4c5e8280a2b48052c",
        "f93b16499a66db7cca71e4599426f7d461e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe",
        "5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb992f2b992f67f8afe67f76913fa388cb",
        "5630c8ca01e0c65d11c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038",
        "ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b845e275592c12335ee340bbc4fddd50278",
        "4016e4b3be7ef04dda49f4b440a30cb5d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e",
        "750edc53370d2b",
    ];
    const PLAIN_FLIGHT: &[&str] = &[
        "080000240022000a00140012001d00170018001901000101010201030104001c00024001000000000b0001b9000001b5",
        "0001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a0603550403130372",
        "7361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372",
        "736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c",
        "0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0cc",
        "b0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a",
        "8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0",
        "300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594",
        "365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1",
        "fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b4",
        "2b4de100000f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc",
        "90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671",
        "459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3140000",
        "209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718",
    ];

    #[test]
    fn rfc8448_key_schedule_and_records() {
        let h = HashAlg::Sha256;
        let share = KeyShare::new(Group::X25519, unhex(CLIENT_PRIV).try_into().unwrap()).unwrap();
        let shared = share.agree(&unhex(SERVER_PUB)).unwrap();
        assert_eq!(shared, unhex(&["8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"]));
        let early = crypto::hkdf_extract(h, &[], &[0; 32]);
        assert_eq!(early, unhex(&["33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"]));
        let derived = crypto::derive_secret(h, &early, b"derived", &h.hash(b""));
        assert_eq!(derived, unhex(&["6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"]));
        let hs = crypto::hkdf_extract(h, &derived, &shared);
        assert_eq!(hs, unhex(&["1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"]));
        let mut t = Hasher::new(h);
        t.update(&unhex(CH));
        t.update(&unhex(SH));
        let th = t.peek();
        assert_eq!(th, unhex(&["860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"]));
        let c_hs = crypto::derive_secret(h, &hs, b"c hs traffic", &th);
        assert_eq!(c_hs, unhex(&["b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"]));
        let s_hs = crypto::derive_secret(h, &hs, b"s hs traffic", &th);
        assert_eq!(s_hs, unhex(&["b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"]));
        let mut k = Keys::new(AeadAlg::Aes128Gcm, h, s_hs);
        assert_eq!(k.key, unhex(&["3fce516009c21727d0f2e4e86ee403bc"]));
        assert_eq!(k.iv.to_vec(), unhex(&["5d313eb2671276ee13000b30"]));
        // The server's first encrypted record opens to its flight, the
        // inner content type (handshake) last.
        let rec = unhex(ENC_RECORD);
        let mut d = rec[5..].to_vec();
        let nonce = k.nonce();
        crypto::open(AeadAlg::Aes128Gcm, &k.key, &nonce, &rec[..5], &mut d).unwrap();
        assert_eq!(d.pop(), Some(HANDSHAKE));
        assert_eq!(d, unhex(PLAIN_FLIGHT));
        let derived = crypto::derive_secret(h, &hs, b"derived", &h.hash(b""));
        let master = crypto::hkdf_extract(h, &derived, &[0; 32]);
        assert_eq!(master, unhex(&["18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"]));
    }

    #[test]
    fn hello_is_well_formed() {
        let c = Client::new("example.com", Roots::default(), 0, [7; 96], [8; 32]).unwrap();
        let mut c = c;
        let out = c.take_output();
        assert_eq!(&out[..3], &[HANDSHAKE, 3, 1]);
        let len = usize::from(u16::from_be_bytes([out[3], out[4]]));
        assert_eq!(out.len(), 5 + len);
        assert_eq!(out[5], CLIENT_HELLO);
        // The server name is in it, and TLS 1.3 and 1.2 are the versions
        // offered.
        assert!(out.windows(11).any(|w| w == b"example.com"));
        assert!(out.windows(9).any(|w| w == [0, 43, 0, 5, 4, 3, 4, 3, 3]));
        // A server that answers with nonsense gets an alert.
        assert!(c.feed(&[22, 3, 3, 0, 4, 2, 0, 0, 0]).is_err());
        assert_eq!(c.take_output()[0], ALERT);
        assert!(c.is_closed());
    }

    /// A ServerHello for TLS 1.2 (no supported_versions) with `random`
    /// and the suite `suite`, as a record.
    fn hello12(random: [u8; 32], suite: u16) -> Vec<u8> {
        let mut b = alloc::vec![3, 3];
        b.extend_from_slice(&random);
        b.push(0);
        b.extend_from_slice(&suite.to_be_bytes());
        b.push(0);
        b.extend_from_slice(&[0, 0]);
        record(HANDSHAKE, 0x0303, &message(SERVER_HELLO, &b))
    }

    #[test]
    fn tls12_downgrade_refused() {
        // A TLS 1.3 server says it settled for 1.2 (RFC 8446 §4.1.3).
        let mut c = Client::new("example.com", Roots::default(), 0, [7; 96], [8; 32]).unwrap();
        c.take_output();
        let mut random = [9u8; 32];
        random[24..].copy_from_slice(b"DOWNGRD\x01");
        assert_eq!(c.feed(&hello12(random, 0xc02f)), Err(Error::Illegal("a downgrade from TLS 1.3")));
        // A plain TLS 1.2 server goes on to its Certificate.
        let mut c = Client::new("example.com", Roots::default(), 0, [7; 96], [8; 32]).unwrap();
        c.take_output();
        assert_eq!(c.feed(&hello12([9; 32], 0xc02f)), Ok(()));
        assert_eq!(c.state, State::Certificate12);
        // A suite not offered (static RSA, CBC) is refused.
        let mut c = Client::new("example.com", Roots::default(), 0, [7; 96], [8; 32]).unwrap();
        c.take_output();
        assert!(c.feed(&hello12([9; 32], 0x003c)).is_err());
    }

    #[test]
    fn tls12_prf() {
        // RFC 5246's PRF with SHA-256, checked against the expansion done
        // by hand: P_SHA256(secret, label + seed), A(1) = HMAC(secret,
        // label + seed).
        let (secret, label, seed) = (b"secret".as_slice(), b"label".as_slice(), b"seed".as_slice());
        let out = tls12::prf(HashAlg::Sha256, secret, label, seed, 40);
        let mut ls = label.to_vec();
        ls.extend_from_slice(seed);
        let a1 = crypto::hmac(HashAlg::Sha256, secret, &ls);
        let a2 = crypto::hmac(HashAlg::Sha256, secret, &a1);
        let mut m1 = a1.clone();
        m1.extend_from_slice(&ls);
        let mut m2 = a2.clone();
        m2.extend_from_slice(&ls);
        let mut want = crypto::hmac(HashAlg::Sha256, secret, &m1);
        want.extend(crypto::hmac(HashAlg::Sha256, secret, &m2));
        assert_eq!(out, want[..40]);
    }
}
