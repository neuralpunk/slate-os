// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Security Manager Protocol (Core 5.4, Vol 3, Part H): pairing an LE
//! device, without I/O of its own (ADR 0176). Slate pairs as the
//! initiator ([`Initiator`]); [`Responder`] is the other side, for the
//! simulated devices in [`crate::sim`].
//!
//! Both sides use Just Works: Slate has no IO capability for LE pairing
//! (a mouse has none either), so nothing is displayed or typed. LE Secure
//! Connections (§2.3.5.6: P-256 ECDH, the functions f4, f5 and f6) when
//! both sides offer it, else legacy pairing (§2.3.5.5: TK 0, c1 and s1).
//! After the link is encrypted, each side hands out the keys the other
//! asked for (§3.6): the long-term key for legacy pairing, and identity
//! keys.
//!
//! The functions take and give their values as the specification writes
//! them, most significant octet first; PDUs carry them least significant
//! octet first (§3.1), and are turned round at the edge.

use alloc::vec::Vec;

use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, NonZeroScalar, PublicKey};

use crate::BdAddr;

/// SMP's fixed L2CAP channel on LE links (Vol 3, Part A, §2.1).
pub const CID: u16 = 0x0006;

// Command codes (§3.3).
pub const PAIRING_REQUEST: u8 = 0x01;
pub const PAIRING_RESPONSE: u8 = 0x02;
pub const PAIRING_CONFIRM: u8 = 0x03;
pub const PAIRING_RANDOM: u8 = 0x04;
pub const PAIRING_FAILED: u8 = 0x05;
pub const ENCRYPTION_INFORMATION: u8 = 0x06;
pub const CENTRAL_IDENTIFICATION: u8 = 0x07;
pub const IDENTITY_INFORMATION: u8 = 0x08;
pub const IDENTITY_ADDRESS_INFORMATION: u8 = 0x09;
pub const SIGNING_INFORMATION: u8 = 0x0A;
pub const SECURITY_REQUEST: u8 = 0x0B;
pub const PAIRING_PUBLIC_KEY: u8 = 0x0C;
pub const PAIRING_DHKEY_CHECK: u8 = 0x0D;

// Pairing Failed reasons (§3.5.5).
pub const ERR_AUTH_REQUIREMENTS: u8 = 0x03;
pub const ERR_CONFIRM_VALUE: u8 = 0x04;
pub const ERR_PAIRING_NOT_SUPPORTED: u8 = 0x05;
pub const ERR_ENCRYPTION_KEY_SIZE: u8 = 0x06;
pub const ERR_UNSPECIFIED: u8 = 0x08;
pub const ERR_INVALID_PARAMETERS: u8 = 0x0A;
pub const ERR_DHKEY_CHECK: u8 = 0x0B;

/// IO capability NoInputNoOutput (§3.5.1, table 3.4).
pub const IO_NO_INPUT_NO_OUTPUT: u8 = 0x03;
/// AuthReq bits (§3.5.1): bonding, MITM, Secure Connections.
pub const AUTH_BONDING: u8 = 0x01;
pub const AUTH_MITM: u8 = 0x04;
pub const AUTH_SC: u8 = 0x08;
/// Key distribution bits (§3.6.1): the encryption key (legacy LTK, EDIV
/// and Rand), the identity key (IRK and identity address), the signing key.
pub const KEY_ENC: u8 = 0x01;
pub const KEY_ID: u8 = 0x02;
pub const KEY_SIGN: u8 = 0x04;

/// The smallest encryption key size accepted (octets): 16, as Slate asks;
/// a device that can't do 16 doesn't pair (§2.3.4 lets 7 to 16).
pub const MIN_KEY_SIZE: u8 = 16;

// --- The functions (§2.2) --------------------------------------------------

/// The security function e: AES-128 of `plain` with `key` (§2.2.1).
pub fn e(key: &[u8; 16], plain: &[u8; 16]) -> [u8; 16] {
    let cipher = aes::Aes128::new(GenericArray::from_slice(key));
    let mut block = *GenericArray::from_slice(plain);
    cipher.encrypt_block(&mut block);
    block.into()
}

/// AES-CMAC (RFC 4493) of `msg` with `key` (§2.2.5).
pub fn aes_cmac(key: &[u8; 16], msg: &[u8]) -> [u8; 16] {
    // The subkeys (RFC 4493 §2.3): L = AES(K, 0), doubled in GF(2^128).
    let double = |b: [u8; 16]| -> [u8; 16] {
        let mut out = [0u8; 16];
        for i in 0..16 {
            out[i] = (b[i] << 1) | if i < 15 { b[i + 1] >> 7 } else { 0 };
        }
        if b[0] & 0x80 != 0 {
            out[15] ^= 0x87;
        }
        out
    };
    let k1 = double(e(key, &[0; 16]));
    let k2 = double(k1);
    let n = msg.len().div_ceil(16).max(1);
    let complete = !msg.is_empty() && msg.len().is_multiple_of(16);
    let mut x = [0u8; 16];
    for i in 0..n - 1 {
        for j in 0..16 {
            x[j] ^= msg[i * 16 + j];
        }
        x = e(key, &x);
    }
    let mut last = [0u8; 16];
    let tail = &msg[(n - 1) * 16..];
    last[..tail.len()].copy_from_slice(tail);
    if complete {
        for j in 0..16 {
            last[j] ^= k1[j];
        }
    } else {
        last[tail.len()] = 0x80;
        for j in 0..16 {
            last[j] ^= k2[j];
        }
    }
    for j in 0..16 {
        x[j] ^= last[j];
    }
    e(key, &x)
}

fn xor(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    core::array::from_fn(|i| a[i] ^ b[i])
}

/// Legacy pairing's confirm value function c1 (§2.2.3): `preq` and `pres`
/// the pairing request and response as sent (their code first),
/// `iat`/`rat` the address types (1: random), `ia`/`ra` the addresses.
#[allow(clippy::too_many_arguments)]
pub fn c1(
    k: &[u8; 16],
    r: &[u8; 16],
    preq: &[u8; 7],
    pres: &[u8; 7],
    iat: u8,
    ia: BdAddr,
    rat: u8,
    ra: BdAddr,
) -> [u8; 16] {
    // p1 = pres || preq || rat' || iat', p2 = padding || ia || ra, each
    // most significant octet first (the commands' last octet first).
    let mut p1 = [0u8; 16];
    for i in 0..7 {
        p1[i] = pres[6 - i];
        p1[7 + i] = preq[6 - i];
    }
    p1[14] = rat & 1;
    p1[15] = iat & 1;
    let mut p2 = [0u8; 16];
    p2[4..10].copy_from_slice(&ia.0);
    p2[10..16].copy_from_slice(&ra.0);
    e(k, &xor(&e(k, &xor(r, &p1)), &p2))
}

/// Legacy pairing's key generation function s1 (§2.2.4): the short-term
/// key from the two randoms' low halves.
pub fn s1(k: &[u8; 16], r1: &[u8; 16], r2: &[u8; 16]) -> [u8; 16] {
    let mut r = [0u8; 16];
    r[..8].copy_from_slice(&r1[8..]);
    r[8..].copy_from_slice(&r2[8..]);
    e(k, &r)
}

/// LE Secure Connections' confirm value function f4 (§2.2.6).
pub fn f4(u: &[u8; 32], v: &[u8; 32], x: &[u8; 16], z: u8) -> [u8; 16] {
    let mut m = Vec::with_capacity(65);
    m.extend_from_slice(u);
    m.extend_from_slice(v);
    m.push(z);
    aes_cmac(x, &m)
}

/// A device's 56-bit address for f5 and f6: its type, then the address.
pub fn addr56(kind: u8, a: BdAddr) -> [u8; 7] {
    let mut out = [0u8; 7];
    out[0] = kind & 1;
    out[1..].copy_from_slice(&a.0);
    out
}

/// LE Secure Connections' key generation function f5 (§2.2.7): (MacKey,
/// LTK) from the Diffie-Hellman key and both sides' nonces and addresses.
pub fn f5(w: &[u8; 32], n1: &[u8; 16], n2: &[u8; 16], a1: &[u8; 7], a2: &[u8; 7]) -> ([u8; 16], [u8; 16]) {
    const SALT: [u8; 16] =
        [0x6C, 0x88, 0x83, 0x91, 0xAA, 0xF5, 0xA5, 0x38, 0x60, 0x37, 0x0B, 0xDB, 0x5A, 0x60, 0x83, 0xBE];
    let t = aes_cmac(&SALT, w);
    let block = |counter: u8| {
        let mut m = Vec::with_capacity(53);
        m.push(counter);
        m.extend_from_slice(b"btle");
        m.extend_from_slice(n1);
        m.extend_from_slice(n2);
        m.extend_from_slice(a1);
        m.extend_from_slice(a2);
        m.extend_from_slice(&[0x01, 0x00]);
        aes_cmac(&t, &m)
    };
    (block(0), block(1))
}

/// LE Secure Connections' check value function f6 (§2.2.8).
#[allow(clippy::too_many_arguments)]
pub fn f6(
    w: &[u8; 16],
    n1: &[u8; 16],
    n2: &[u8; 16],
    r: &[u8; 16],
    io_cap: &[u8; 3],
    a1: &[u8; 7],
    a2: &[u8; 7],
) -> [u8; 16] {
    let mut m = Vec::with_capacity(65);
    for part in [&n1[..], n2, r, io_cap, a1, a2] {
        m.extend_from_slice(part);
    }
    aes_cmac(w, &m)
}

/// A value as a PDU carries it (least significant octet first), or back.
fn turned<const N: usize>(v: &[u8; N]) -> [u8; N] {
    let mut out = *v;
    out.reverse();
    out
}

fn array<const N: usize>(b: &[u8]) -> Option<[u8; N]> {
    b.get(..N)?.try_into().ok()
}

// --- P-256 (§2.3.5.6.1) -------------------------------------------------------

/// A P-256 key pair: the secret, and the public key's X and Y, most
/// significant octet first.
struct KeyPair {
    secret: NonZeroScalar,
    x: [u8; 32],
    y: [u8; 32],
}

impl KeyPair {
    fn new(rng: &mut dyn FnMut(&mut [u8])) -> KeyPair {
        let secret = loop {
            let mut b = [0u8; 32];
            rng(&mut b);
            if let Some(s) = Option::<NonZeroScalar>::from(NonZeroScalar::from_repr(b.into())) {
                break s;
            }
        };
        let p = PublicKey::from_secret_scalar(&secret).to_encoded_point(false);
        let (x, y) = (array::<32>(p.x().map_or(&[][..], |v| &v[..])), array::<32>(p.y().map_or(&[][..], |v| &v[..])));
        KeyPair { secret, x: x.unwrap_or([0; 32]), y: y.unwrap_or([0; 32]) }
    }

    /// The Pairing Public Key command for it.
    fn pdu(&self) -> Vec<u8> {
        let mut p = alloc::vec![PAIRING_PUBLIC_KEY];
        p.extend_from_slice(&turned(&self.x));
        p.extend_from_slice(&turned(&self.y));
        p
    }

    /// The Diffie-Hellman key with the peer's public key (X, Y most
    /// significant octet first); None if that isn't a point on the curve
    /// (§2.3.5.6.1: the pairing then fails).
    fn dhkey(&self, x: &[u8; 32], y: &[u8; 32]) -> Option<[u8; 32]> {
        let point = EncodedPoint::from_affine_coordinates(&(*x).into(), &(*y).into(), false);
        let peer = Option::<PublicKey>::from(PublicKey::from_encoded_point(&point))?;
        let shared = p256::ecdh::diffie_hellman(self.secret, peer.as_affine());
        array::<32>(shared.raw_secret_bytes())
    }
}

/// The peer's public key from a Pairing Public Key command.
fn peer_key(pdu: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if pdu.len() != 65 {
        return None;
    }
    Some((turned(&array::<32>(&pdu[1..33])?), turned(&array::<32>(&pdu[33..65])?)))
}

// --- Keys and steps -----------------------------------------------------------

/// What pairing leaves: the long-term key (as LE Start Encryption takes
/// it, least significant octet first) with its EDIV and Rand (both 0 for
/// Secure Connections), and the peer's identity if it gave it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Keys {
    pub ltk: [u8; 16],
    pub ediv: u16,
    pub rand: u64,
    /// Whether it came from LE Secure Connections.
    pub secure: bool,
    /// The peer's identity resolving key (least significant octet first).
    pub irk: Option<[u8; 16]>,
    /// The peer's identity address: its type and the address.
    pub identity: Option<(u8, BdAddr)>,
}

/// What to do next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Send this SMP command on the link.
    Send(Vec<u8>),
    /// Encrypt the link with this key (the initiator's LE Start
    /// Encryption; the responder's controller checks it).
    Encrypt { ltk: [u8; 16], ediv: u16, rand: u64 },
    /// Paired: the keys to keep.
    Done(Keys),
    /// Pairing failed, for this reason (a Pairing Failed has been queued
    /// when it was this side's to say).
    Failed(u8),
}

/// The pairing features both sides exchanged.
#[derive(Clone, Copy, Debug, Default)]
struct Features {
    preq: [u8; 7],
    pres: [u8; 7],
}

impl Features {
    fn secure(&self) -> bool {
        self.preq[3] & AUTH_SC != 0 && self.pres[3] & AUTH_SC != 0
    }
    fn key_size(&self) -> u8 {
        self.preq[4].min(self.pres[4])
    }
    /// The keys the responder hands out, and the initiator's (§3.6.1:
    /// what both asked for; in Secure Connections the encryption key isn't
    /// sent).
    fn responder_keys(&self) -> u8 {
        let k = self.preq[6] & self.pres[6];
        if self.secure() { k & !KEY_ENC } else { k }
    }
    fn initiator_keys(&self) -> u8 {
        let k = self.preq[5] & self.pres[5];
        if self.secure() { k & !KEY_ENC } else { k }
    }
    /// IOcap for f6 (§2.2.8): AuthReq, OOB data flag, IO capability.
    fn io_cap(cmd: &[u8; 7]) -> [u8; 3] {
        [cmd[3], cmd[2], cmd[1]]
    }
}

fn failed(reason: u8) -> Vec<Step> {
    alloc::vec![Step::Send(alloc::vec![PAIRING_FAILED, reason]), Step::Failed(reason)]
}

/// A key the specification's way (most significant octet first) cut to
/// `size` octets (§2.3.4: the most significant octets zeroed).
fn masked(key: [u8; 16], size: u8) -> [u8; 16] {
    let mut k = key;
    for b in k.iter_mut().take(16 - usize::from(size.min(16))) {
        *b = 0;
    }
    k
}

/// The identity this side hands out: its IRK, and its address with the
/// address's type (0 public, 1 static random).
#[derive(Clone, Copy, Debug)]
pub struct Identity {
    pub irk: [u8; 16],
    pub addr_type: u8,
    pub addr: BdAddr,
}

fn identity_pdus(id: &Identity) -> [Vec<u8>; 2] {
    let mut info = alloc::vec![IDENTITY_INFORMATION];
    info.extend_from_slice(&id.irk);
    let mut addr = alloc::vec![IDENTITY_ADDRESS_INFORMATION, id.addr_type & 1];
    addr.extend_from_slice(&id.addr.wire());
    [info, addr]
}

/// The peer's key distribution, as it comes: what is still awaited.
#[derive(Clone, Debug, Default)]
struct Receiving {
    want: u8,
    keys: Keys,
    /// Encryption Information came; Central Identification completes it.
    ltk_seen: bool,
}

impl Receiving {
    /// Take a key distribution command; false if it wasn't one expected.
    fn take(&mut self, pdu: &[u8]) -> bool {
        match (pdu.first().copied(), pdu.len()) {
            (Some(ENCRYPTION_INFORMATION), 17) if self.want & KEY_ENC != 0 => {
                self.keys.ltk = array(&pdu[1..]).unwrap_or_default();
                self.ltk_seen = true;
            }
            (Some(CENTRAL_IDENTIFICATION), 11) if self.want & KEY_ENC != 0 && self.ltk_seen => {
                self.keys.ediv = u16::from_le_bytes([pdu[1], pdu[2]]);
                self.keys.rand = u64::from_le_bytes(array(&pdu[3..]).unwrap_or_default());
                self.want &= !KEY_ENC;
            }
            (Some(IDENTITY_INFORMATION), 17) if self.want & KEY_ID != 0 => {
                self.keys.irk = array(&pdu[1..]);
            }
            (Some(IDENTITY_ADDRESS_INFORMATION), 8) if self.want & KEY_ID != 0 && self.keys.irk.is_some() => {
                let a = BdAddr::from_wire(&pdu[2..8]).unwrap_or_default();
                self.keys.identity = Some((pdu[1] & 1, a));
                self.want &= !KEY_ID;
            }
            (Some(SIGNING_INFORMATION), 17) if self.want & KEY_SIGN != 0 => self.want &= !KEY_SIGN,
            _ => return false,
        }
        true
    }
}

// --- The initiator ------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IState {
    /// Pairing Request sent.
    Requested,
    /// Legacy: Pairing Confirm sent, the responder's awaited.
    LegacyConfirm,
    /// Legacy: Pairing Random sent, the responder's awaited.
    LegacyRandom,
    /// Secure Connections: public key sent, the responder's awaited.
    ScKey,
    /// The responder's confirm awaited.
    ScConfirm,
    /// Our random sent, the responder's awaited.
    ScRandom,
    /// Our DHKey check sent, the responder's awaited.
    ScCheck,
    /// Encryption asked for.
    Encrypting,
    /// The responder's keys awaited.
    Keys,
    Over,
}

/// Slate's side of pairing: it asks, as the central.
pub struct Initiator {
    state: IState,
    own: (u8, BdAddr),
    peer: (u8, BdAddr),
    features: Features,
    identity: Identity,
    pair: Option<KeyPair>,
    peer_key: Option<([u8; 32], [u8; 32])>,
    dhkey: [u8; 32],
    /// Our random (Mrand or Na) and the responder's; its confirm.
    ours: [u8; 16],
    theirs: [u8; 16],
    confirm: [u8; 16],
    mackey: [u8; 16],
    /// The key the link is encrypted with (the specification's order).
    key: [u8; 16],
    receiving: Receiving,
    /// Keys the responder handed out before this side heard the link was
    /// encrypted: over USB, data and events come on different endpoints,
    /// so the data can come first. Taken once it has.
    early: Vec<Vec<u8>>,
}

// (Debug by hand: the secret key stays out of logs.)
impl core::fmt::Debug for Initiator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Initiator").field("state", &self.state).field("peer", &self.peer).finish_non_exhaustive()
    }
}

impl Initiator {
    /// Start pairing with `peer` (its address type, 1 for random, and
    /// address) from `own`: the Pairing Request to send.
    pub fn start(own: (u8, BdAddr), peer: (u8, BdAddr), identity: Identity) -> (Initiator, Vec<u8>) {
        // NoInputNoOutput, no OOB data, bonding with Secure Connections,
        // 16-octet keys; the responder's encryption and identity keys, our
        // identity.
        let preq = [PAIRING_REQUEST, IO_NO_INPUT_NO_OUTPUT, 0, AUTH_BONDING | AUTH_SC, 16, KEY_ID, KEY_ENC | KEY_ID];
        let i = Initiator {
            state: IState::Requested,
            own,
            peer,
            features: Features { preq, pres: [0; 7] },
            identity,
            pair: None,
            peer_key: None,
            dhkey: [0; 32],
            ours: [0; 16],
            theirs: [0; 16],
            confirm: [0; 16],
            mackey: [0; 16],
            key: [0; 16],
            receiving: Receiving::default(),
            early: Vec::new(),
        };
        (i, preq.to_vec())
    }

    /// Whether pairing is over (done or failed).
    pub fn over(&self) -> bool {
        self.state == IState::Over
    }

    fn fail(&mut self, reason: u8) -> Vec<Step> {
        self.state = IState::Over;
        failed(reason)
    }

    fn c1(&self, r: &[u8; 16]) -> [u8; 16] {
        let f = &self.features;
        c1(&[0; 16], r, &f.preq, &f.pres, self.own.0, self.own.1, self.peer.0, self.peer.1)
    }

    /// An SMP command from the responder.
    pub fn received(&mut self, pdu: &[u8], rng: &mut dyn FnMut(&mut [u8])) -> Vec<Step> {
        let Some(&code) = pdu.first() else { return Vec::new() };
        if code == PAIRING_FAILED {
            self.state = IState::Over;
            return alloc::vec![Step::Failed(pdu.get(1).copied().unwrap_or(ERR_UNSPECIFIED))];
        }
        match (self.state, code) {
            (IState::Requested, PAIRING_RESPONSE) if pdu.len() == 7 => {
                self.features.pres = array(pdu).unwrap_or_default();
                if self.features.key_size() < MIN_KEY_SIZE {
                    return self.fail(ERR_ENCRYPTION_KEY_SIZE);
                }
                if self.features.secure() {
                    let pair = KeyPair::new(rng);
                    let pk = pair.pdu();
                    self.pair = Some(pair);
                    self.state = IState::ScKey;
                    alloc::vec![Step::Send(pk)]
                } else {
                    // Legacy Just Works: TK 0 (§2.3.5.2).
                    rng(&mut self.ours);
                    let m = self.c1(&self.ours);
                    self.state = IState::LegacyConfirm;
                    let mut p = alloc::vec![PAIRING_CONFIRM];
                    p.extend_from_slice(&turned(&m));
                    alloc::vec![Step::Send(p)]
                }
            }
            (IState::LegacyConfirm, PAIRING_CONFIRM) if pdu.len() == 17 => {
                self.confirm = turned(&array(&pdu[1..]).unwrap_or_default());
                self.state = IState::LegacyRandom;
                let mut p = alloc::vec![PAIRING_RANDOM];
                p.extend_from_slice(&turned(&self.ours));
                alloc::vec![Step::Send(p)]
            }
            (IState::LegacyRandom, PAIRING_RANDOM) if pdu.len() == 17 => {
                self.theirs = turned(&array(&pdu[1..]).unwrap_or_default());
                if self.c1(&self.theirs) != self.confirm {
                    return self.fail(ERR_CONFIRM_VALUE);
                }
                // STK = s1(TK, Srand, Mrand), cut to the key size.
                self.key = masked(s1(&[0; 16], &self.theirs, &self.ours), self.features.key_size());
                self.state = IState::Encrypting;
                alloc::vec![Step::Encrypt { ltk: turned(&self.key), ediv: 0, rand: 0 }]
            }
            (IState::ScKey, PAIRING_PUBLIC_KEY) => {
                let Some((x, y)) = peer_key(pdu) else { return self.fail(ERR_INVALID_PARAMETERS) };
                let Some(dh) = self.pair.as_ref().and_then(|p| p.dhkey(&x, &y)) else {
                    return self.fail(ERR_DHKEY_CHECK);
                };
                self.dhkey = dh;
                self.peer_key = Some((x, y));
                self.state = IState::ScConfirm;
                Vec::new()
            }
            (IState::ScConfirm, PAIRING_CONFIRM) if pdu.len() == 17 => {
                self.confirm = turned(&array(&pdu[1..]).unwrap_or_default());
                rng(&mut self.ours);
                self.state = IState::ScRandom;
                let mut p = alloc::vec![PAIRING_RANDOM];
                p.extend_from_slice(&turned(&self.ours));
                alloc::vec![Step::Send(p)]
            }
            (IState::ScRandom, PAIRING_RANDOM) if pdu.len() == 17 => {
                self.theirs = turned(&array(&pdu[1..]).unwrap_or_default());
                let (Some(pair), Some((px, _))) = (&self.pair, &self.peer_key) else {
                    return self.fail(ERR_UNSPECIFIED);
                };
                // Cb = f4(PKbx, PKax, Nb, 0) for Just Works (§2.3.5.6.2).
                if f4(px, &pair.x, &self.theirs, 0) != self.confirm {
                    return self.fail(ERR_CONFIRM_VALUE);
                }
                let (a, b) = (addr56(self.own.0, self.own.1), addr56(self.peer.0, self.peer.1));
                let (mackey, ltk) = f5(&self.dhkey, &self.ours, &self.theirs, &a, &b);
                self.mackey = mackey;
                self.key = masked(ltk, self.features.key_size());
                let ea =
                    f6(&mackey, &self.ours, &self.theirs, &[0; 16], &Features::io_cap(&self.features.preq), &a, &b);
                self.state = IState::ScCheck;
                let mut p = alloc::vec![PAIRING_DHKEY_CHECK];
                p.extend_from_slice(&turned(&ea));
                alloc::vec![Step::Send(p)]
            }
            (IState::ScCheck, PAIRING_DHKEY_CHECK) if pdu.len() == 17 => {
                let eb = turned(&array(&pdu[1..]).unwrap_or_default());
                let (a, b) = (addr56(self.own.0, self.own.1), addr56(self.peer.0, self.peer.1));
                let io = Features::io_cap(&self.features.pres);
                if f6(&self.mackey, &self.theirs, &self.ours, &[0; 16], &io, &b, &a) != eb {
                    return self.fail(ERR_DHKEY_CHECK);
                }
                self.state = IState::Encrypting;
                alloc::vec![Step::Encrypt { ltk: turned(&self.key), ediv: 0, rand: 0 }]
            }
            (IState::Keys, _) if self.receiving.take(pdu) => self.maybe_done(),
            (IState::Encrypting, ENCRYPTION_INFORMATION..=SIGNING_INFORMATION) if self.early.len() < 8 => {
                self.early.push(pdu.to_vec());
                Vec::new()
            }
            _ => self.fail(ERR_UNSPECIFIED),
        }
    }

    /// The link is encrypted with the key from [`Step::Encrypt`]: the
    /// responder's keys come next (or came already), then ours.
    pub fn encrypted(&mut self) -> Vec<Step> {
        if self.state != IState::Encrypting {
            return Vec::new();
        }
        let secure = self.features.secure();
        self.receiving = Receiving {
            want: self.features.responder_keys(),
            keys: Keys { secure, ..Keys::default() },
            ltk_seen: false,
        };
        if secure {
            self.receiving.keys.ltk = turned(&self.key);
        }
        self.state = IState::Keys;
        for p in core::mem::take(&mut self.early) {
            if !self.receiving.take(&p) {
                return self.fail(ERR_UNSPECIFIED);
            }
        }
        self.maybe_done()
    }

    fn maybe_done(&mut self) -> Vec<Step> {
        if self.receiving.want != 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        if self.features.initiator_keys() & KEY_ID != 0 {
            out.extend(identity_pdus(&self.identity).into_iter().map(Step::Send));
        }
        self.state = IState::Over;
        out.push(Step::Done(self.receiving.keys.clone()));
        out
    }
}

// --- The responder (the simulated devices) --------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RState {
    Idle,
    LegacyConfirm,
    LegacyRandom,
    ScKey,
    ScRandom,
    ScCheck,
    /// Waiting for the initiator to encrypt.
    Encrypting,
    /// The initiator's keys awaited.
    Keys,
    Over,
}

/// A device's side of pairing, Just Works: as a mouse would answer.
pub struct Responder {
    state: RState,
    own: (u8, BdAddr),
    peer: (u8, BdAddr),
    /// Whether it offers Secure Connections.
    sc: bool,
    features: Features,
    identity: Identity,
    pair: Option<KeyPair>,
    dhkey: [u8; 32],
    peer_x: [u8; 32],
    ours: [u8; 16],
    theirs: [u8; 16],
    confirm: [u8; 16],
    mackey: [u8; 16],
    key: [u8; 16],
    /// What legacy pairing hands out (LTK least significant octet first).
    ltk: [u8; 16],
    ediv: u16,
    rand: u64,
    receiving: Receiving,
}

impl core::fmt::Debug for Responder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Responder").field("state", &self.state).field("peer", &self.peer).finish_non_exhaustive()
    }
}

impl Responder {
    pub fn new(own: (u8, BdAddr), peer: (u8, BdAddr), sc: bool, identity: Identity) -> Responder {
        Responder {
            state: RState::Idle,
            own,
            peer,
            sc,
            features: Features::default(),
            identity,
            pair: None,
            dhkey: [0; 32],
            peer_x: [0; 32],
            ours: [0; 16],
            theirs: [0; 16],
            confirm: [0; 16],
            mackey: [0; 16],
            key: [0; 16],
            ltk: [0; 16],
            ediv: 0,
            rand: 0,
            receiving: Receiving::default(),
        }
    }

    /// The key the initiator must encrypt with (as LE Start Encryption
    /// gives it), once agreed.
    pub fn expected_key(&self) -> Option<[u8; 16]> {
        (self.state == RState::Encrypting).then(|| turned(&self.key))
    }

    fn fail(&mut self, reason: u8) -> Vec<Step> {
        self.state = RState::Over;
        failed(reason)
    }

    fn c1(&self, r: &[u8; 16]) -> [u8; 16] {
        let f = &self.features;
        c1(&[0; 16], r, &f.preq, &f.pres, self.peer.0, self.peer.1, self.own.0, self.own.1)
    }

    /// An SMP command from the initiator.
    pub fn received(&mut self, pdu: &[u8], rng: &mut dyn FnMut(&mut [u8])) -> Vec<Step> {
        let Some(&code) = pdu.first() else { return Vec::new() };
        if code == PAIRING_FAILED {
            self.state = RState::Over;
            return alloc::vec![Step::Failed(pdu.get(1).copied().unwrap_or(ERR_UNSPECIFIED))];
        }
        match (self.state, code) {
            (RState::Idle | RState::Over, PAIRING_REQUEST) if pdu.len() == 7 => {
                let preq: [u8; 7] = array(pdu).unwrap_or_default();
                let auth = AUTH_BONDING | if self.sc { AUTH_SC } else { 0 };
                let pres = [
                    PAIRING_RESPONSE,
                    IO_NO_INPUT_NO_OUTPUT,
                    0,
                    auth,
                    16,
                    preq[5] & KEY_ID,
                    preq[6] & (KEY_ENC | KEY_ID),
                ];
                self.features = Features { preq, pres };
                self.state = if self.features.secure() { RState::ScKey } else { RState::LegacyConfirm };
                alloc::vec![Step::Send(pres.to_vec())]
            }
            (RState::LegacyConfirm, PAIRING_CONFIRM) if pdu.len() == 17 => {
                self.confirm = turned(&array(&pdu[1..]).unwrap_or_default());
                rng(&mut self.ours);
                let s = self.c1(&self.ours);
                self.state = RState::LegacyRandom;
                let mut p = alloc::vec![PAIRING_CONFIRM];
                p.extend_from_slice(&turned(&s));
                alloc::vec![Step::Send(p)]
            }
            (RState::LegacyRandom, PAIRING_RANDOM) if pdu.len() == 17 => {
                self.theirs = turned(&array(&pdu[1..]).unwrap_or_default());
                if self.c1(&self.theirs) != self.confirm {
                    return self.fail(ERR_CONFIRM_VALUE);
                }
                self.key = masked(s1(&[0; 16], &self.ours, &self.theirs), self.features.key_size());
                self.state = RState::Encrypting;
                let mut p = alloc::vec![PAIRING_RANDOM];
                p.extend_from_slice(&turned(&self.ours));
                alloc::vec![Step::Send(p)]
            }
            (RState::ScKey, PAIRING_PUBLIC_KEY) => {
                let Some((x, y)) = peer_key(pdu) else { return self.fail(ERR_INVALID_PARAMETERS) };
                let pair = KeyPair::new(rng);
                let Some(dh) = pair.dhkey(&x, &y) else { return self.fail(ERR_DHKEY_CHECK) };
                self.dhkey = dh;
                self.peer_x = x;
                rng(&mut self.ours);
                // Cb = f4(PKbx, PKax, Nb, 0).
                let cb = f4(&pair.x, &x, &self.ours, 0);
                let pk = pair.pdu();
                self.pair = Some(pair);
                self.state = RState::ScRandom;
                let mut p = alloc::vec![PAIRING_CONFIRM];
                p.extend_from_slice(&turned(&cb));
                alloc::vec![Step::Send(pk), Step::Send(p)]
            }
            (RState::ScRandom, PAIRING_RANDOM) if pdu.len() == 17 => {
                self.theirs = turned(&array(&pdu[1..]).unwrap_or_default());
                let (a, b) = (addr56(self.peer.0, self.peer.1), addr56(self.own.0, self.own.1));
                let (mackey, ltk) = f5(&self.dhkey, &self.theirs, &self.ours, &a, &b);
                self.mackey = mackey;
                self.key = masked(ltk, self.features.key_size());
                self.state = RState::ScCheck;
                let mut p = alloc::vec![PAIRING_RANDOM];
                p.extend_from_slice(&turned(&self.ours));
                alloc::vec![Step::Send(p)]
            }
            (RState::ScCheck, PAIRING_DHKEY_CHECK) if pdu.len() == 17 => {
                let ea = turned(&array(&pdu[1..]).unwrap_or_default());
                let (a, b) = (addr56(self.peer.0, self.peer.1), addr56(self.own.0, self.own.1));
                let f = self.features;
                if f6(&self.mackey, &self.theirs, &self.ours, &[0; 16], &Features::io_cap(&f.preq), &a, &b) != ea {
                    return self.fail(ERR_DHKEY_CHECK);
                }
                let eb = f6(&self.mackey, &self.ours, &self.theirs, &[0; 16], &Features::io_cap(&f.pres), &b, &a);
                self.state = RState::Encrypting;
                let mut p = alloc::vec![PAIRING_DHKEY_CHECK];
                p.extend_from_slice(&turned(&eb));
                alloc::vec![Step::Send(p)]
            }
            (RState::Keys, _) if self.receiving.take(pdu) => self.maybe_done(),
            _ => self.fail(ERR_UNSPECIFIED),
        }
    }

    /// The link is encrypted: hand out the keys, then await the
    /// initiator's.
    pub fn encrypted(&mut self, rng: &mut dyn FnMut(&mut [u8])) -> Vec<Step> {
        if self.state != RState::Encrypting {
            return Vec::new();
        }
        let mut out = Vec::new();
        let give = self.features.responder_keys();
        if give & KEY_ENC != 0 {
            rng(&mut self.ltk);
            let mut b = [0u8; 10];
            rng(&mut b);
            self.ediv = u16::from_le_bytes([b[0], b[1]]);
            self.rand = u64::from_le_bytes(array(&b[2..]).unwrap_or_default());
            let mut info = alloc::vec![ENCRYPTION_INFORMATION];
            info.extend_from_slice(&self.ltk);
            let mut ident = alloc::vec![CENTRAL_IDENTIFICATION];
            ident.extend_from_slice(&self.ediv.to_le_bytes());
            ident.extend_from_slice(&self.rand.to_le_bytes());
            out.push(Step::Send(info));
            out.push(Step::Send(ident));
        }
        if give & KEY_ID != 0 {
            out.extend(identity_pdus(&self.identity).into_iter().map(Step::Send));
        }
        self.receiving = Receiving { want: self.features.initiator_keys(), ..Receiving::default() };
        self.state = RState::Keys;
        out.extend(self.maybe_done());
        out
    }

    fn maybe_done(&mut self) -> Vec<Step> {
        if self.receiving.want != 0 {
            return Vec::new();
        }
        self.state = RState::Over;
        let secure = self.features.secure();
        // The key a later connection is encrypted with: the one handed out
        // (legacy), or the pairing's own (Secure Connections).
        let (ltk, ediv, rand) = if secure { (turned(&self.key), 0, 0) } else { (self.ltk, self.ediv, self.rand) };
        alloc::vec![Step::Done(Keys {
            ltk,
            ediv,
            rand,
            secure,
            irk: self.receiving.keys.irk,
            identity: self.receiving.keys.identity
        })]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h<const N: usize>(s: &str) -> [u8; N] {
        let v: Vec<u8> = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect();
        v.try_into().unwrap()
    }

    /// RFC 4493's examples, and Core 5.4 Vol 3 Part H Appendix D's sample
    /// data for c1, s1, f4, f5 and f6.
    #[test]
    fn functions() {
        let k: [u8; 16] = h("2b7e151628aed2a6abf7158809cf4f3c");
        assert_eq!(aes_cmac(&k, &[]), h::<16>("bb1d6929e95937287fa37d129b756746"));
        let m: [u8; 16] = h("6bc1bee22e409f96e93d7e117393172a");
        assert_eq!(aes_cmac(&k, &m), h::<16>("070a16b46b4d4144f79bdd9dd04a287c"));
        let m40: [u8; 40] = h("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");
        assert_eq!(aes_cmac(&k, &m40), h::<16>("dfa66747de9ae63030ca32611497c827"));

        let r: [u8; 16] = h("5783D52156AD6F0E6388274EC6702EE0");
        // preq and pres as sent (their code first).
        let preq = [0x01, 0x01, 0x00, 0x00, 0x10, 0x07, 0x07];
        let pres = [0x02, 0x03, 0x00, 0x00, 0x08, 0x00, 0x05];
        let ia = BdAddr(h("A1A2A3A4A5A6"));
        let ra = BdAddr(h("B1B2B3B4B5B6"));
        assert_eq!(c1(&[0; 16], &r, &preq, &pres, 1, ia, 0, ra), h::<16>("1e1e3fef878988ead2a74dc5bef13b86"));
        let r1: [u8; 16] = h("000F0E0D0C0B0A091122334455667788");
        let r2: [u8; 16] = h("010203040506070899AABBCCDDEEFF00");
        assert_eq!(s1(&[0; 16], &r1, &r2), h::<16>("9a1fe1f0e8b0f49b5b4216ae796da062"));

        let u: [u8; 32] = h("20b003d2f297be2c5e2c83a7e9f9a5b9eff49111acf4fddbcc0301480e359de6");
        let v: [u8; 32] = h("55188b3d32f6bb9a900afcfbeed4e72a59cb9ac2f19d7cfb6b4fdd49f47fc5fd");
        let x: [u8; 16] = h("d5cb8454d177733effffb2ec712baeab");
        assert_eq!(f4(&u, &v, &x, 0), h::<16>("f2c916f107a9bd1cf1eda1bea974872d"));
        let w: [u8; 32] = h("ec0234a357c8ad05341010a60a397d9b99796b13b4f866f1868d34f373bfa698");
        let n2: [u8; 16] = h("a6e8e7cc25a75f6e216583f7ff3dc4cf");
        let a1 = addr56(0, BdAddr(h("56123737bfce")));
        let a2 = addr56(0, BdAddr(h("a713702dcfc1")));
        let (mackey, ltk) = f5(&w, &x, &n2, &a1, &a2);
        assert_eq!(mackey, h::<16>("2965f176a1084a02fd3f6a20ce636e20"));
        assert_eq!(ltk, h::<16>("6986791169d7cd23980522b594750a38"));
        let rr: [u8; 16] = h("12a3343bb453bb5408da42d20c2d0fc8");
        assert_eq!(f6(&mackey, &x, &n2, &rr, &[1, 1, 2], &a1, &a2), h::<16>("e3c473989cd0e8c5d26c0b09da958f61"));
        // Key sizes under 16 zero the most significant octets.
        assert_eq!(masked([0xFF; 16], 7)[..9], [0; 9]);
    }

    /// A deterministic source of randomness for the tests.
    fn rng_from(seed: u8) -> impl FnMut(&mut [u8]) {
        let mut n = seed;
        move |b: &mut [u8]| {
            for x in b.iter_mut() {
                n = n.wrapping_mul(97).wrapping_add(31);
                *x = n;
            }
        }
    }

    /// Run a whole pairing between the two sides; their keys.
    fn pair(sc: bool) -> (Keys, Keys) {
        pair_with(sc, false)
    }

    /// [`pair`], the responder's keys reaching the initiator before it
    /// hears the link is encrypted when `keys_first` (USB's endpoints).
    fn pair_with(sc: bool, keys_first: bool) -> (Keys, Keys) {
        let central = (0, BdAddr(h("001122334455")));
        let mouse = (1, BdAddr(h("DADB008CD8E5")));
        let (mut i, first) =
            Initiator::start(central, mouse, Identity { irk: [7; 16], addr_type: 0, addr: BdAddr(h("001122334455")) });
        let mut r = Responder::new(
            mouse,
            central,
            sc,
            Identity { irk: [9; 16], addr_type: 1, addr: BdAddr(h("C0FFEE000001")) },
        );
        let (mut ri, mut rr) = (rng_from(1), rng_from(2));
        let mut to_r: Vec<Vec<u8>> = alloc::vec![first];
        let mut to_i: Vec<Vec<u8>> = Vec::new();
        let (mut ik, mut rk) = (None, None);
        for _ in 0..40 {
            for p in core::mem::take(&mut to_r) {
                for s in r.received(&p, &mut rr) {
                    match s {
                        Step::Send(p) => to_i.push(p),
                        Step::Done(k) => rk = Some(k),
                        s => panic!("responder: {s:?}"),
                    }
                }
            }
            for p in core::mem::take(&mut to_i) {
                for s in i.received(&p, &mut ri) {
                    match s {
                        Step::Send(p) => to_r.push(p),
                        Step::Encrypt { ltk, .. } => {
                            // The responder's controller checks the key.
                            assert_eq!(r.expected_key(), Some(ltk));
                            for s in r.encrypted(&mut rr) {
                                match s {
                                    Step::Send(p) => to_i.push(p),
                                    Step::Done(k) => rk = Some(k),
                                    s => panic!("responder: {s:?}"),
                                }
                            }
                            if keys_first {
                                for p in core::mem::take(&mut to_i) {
                                    assert_eq!(i.received(&p, &mut ri), [], "held");
                                }
                            }
                            for s in i.encrypted() {
                                match s {
                                    Step::Send(p) => to_r.push(p),
                                    Step::Done(k) => ik = Some(k),
                                    s => panic!("initiator: {s:?}"),
                                }
                            }
                        }
                        Step::Done(k) => ik = Some(k),
                        s => panic!("initiator: {s:?}"),
                    }
                }
            }
            if ik.is_some() && rk.is_some() && to_r.is_empty() && to_i.is_empty() {
                break;
            }
        }
        (ik.expect("the initiator finished"), rk.expect("the responder finished"))
    }

    #[test]
    fn secure_connections() {
        let (i, r) = pair(true);
        assert!(i.secure && r.secure);
        // Both derived the same key; nothing was handed out for it.
        assert_eq!((i.ltk, i.ediv, i.rand), (r.ltk, 0, 0));
        assert_eq!(i.irk, Some([9; 16]));
        assert_eq!(i.identity, Some((1, BdAddr(h("C0FFEE000001")))));
        assert_eq!(r.identity, Some((0, BdAddr(h("001122334455")))));
    }

    #[test]
    fn keys_before_the_encryption_event() {
        for sc in [true, false] {
            let (i, r) = pair_with(sc, true);
            assert_eq!((i.ltk, i.ediv, i.rand), (r.ltk, r.ediv, r.rand));
            assert!(i.identity.is_some());
        }
    }

    #[test]
    fn legacy() {
        let (i, r) = pair(false);
        assert!(!i.secure);
        // The key the responder handed out, with its EDIV and Rand.
        assert_eq!((i.ltk, i.ediv, i.rand), (r.ltk, r.ediv, r.rand));
        assert_ne!(i.ltk, [0; 16]);
    }

    #[test]
    fn failures() {
        let central = (0, BdAddr(h("001122334455")));
        let mouse = (1, BdAddr(h("DADB008CD8E5")));
        let id = Identity { irk: [0; 16], addr_type: 0, addr: central.1 };
        let mut rng = rng_from(3);
        // A key smaller than 16 octets is refused.
        let (mut i, _) = Initiator::start(central, mouse, id);
        let steps = i.received(&[PAIRING_RESPONSE, 3, 0, 1, 7, 0, 3], &mut rng);
        assert_eq!(steps.last(), Some(&Step::Failed(ERR_ENCRYPTION_KEY_SIZE)));
        // A wrong confirm value fails legacy pairing.
        let (mut i, _) = Initiator::start(central, mouse, id);
        i.received(&[PAIRING_RESPONSE, 3, 0, 1, 16, 0, 3], &mut rng);
        i.received(&[[PAIRING_CONFIRM].as_slice(), &[0x55; 16]].concat(), &mut rng);
        let steps = i.received(&[[PAIRING_RANDOM].as_slice(), &[0x66; 16]].concat(), &mut rng);
        assert_eq!(steps.last(), Some(&Step::Failed(ERR_CONFIRM_VALUE)));
        assert!(i.over());
        // A public key off the curve fails Secure Connections.
        let (mut i, _) = Initiator::start(central, mouse, id);
        i.received(&[PAIRING_RESPONSE, 3, 0, 9, 16, 0, 3], &mut rng);
        let steps = i.received(&[[PAIRING_PUBLIC_KEY].as_slice(), &[1; 64]].concat(), &mut rng);
        assert_eq!(steps.last(), Some(&Step::Failed(ERR_DHKEY_CHECK)));
        // The device's Pairing Failed ends it.
        let (mut i, _) = Initiator::start(central, mouse, id);
        assert_eq!(i.received(&[PAIRING_FAILED, ERR_PAIRING_NOT_SUPPORTED], &mut rng), [Step::Failed(5)]);
    }
}
