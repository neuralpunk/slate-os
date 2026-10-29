// SPDX-License-Identifier: MIT OR Apache-2.0

//! Slate's disk encryption format (ADR 0036). An encrypted partition
//! starts with a 4 KiB header; its data follows at 1 MiB, every 512-byte
//! sector encrypted with AES-256 in XTS mode (IEEE 1619), the tweak being
//! the sector's number from the start of the data. The 64-byte master key
//! is stored in up to four key slots, each wrapped (AES key wrap, RFC 3394)
//! with a key derived from a password by Argon2id (RFC 9106).
//!
//! The primitives are RustCrypto's vetted `aes`, `aes-kw` and `argon2`
//! crates (ADR 0012's exception); XTS is the IEEE 1619 construction over
//! AES, checked against OpenSSL's `aes-256-xts`.
//!
//! The header (little-endian):
//!
//! ```text
//! 0    8   magic "SLCRYPT\0"
//! 8    4   version (1)
//! 12   4   cipher (1: AES-256-XTS, 512-byte sectors)
//! 16   8   data offset, in sectors (2048)
//! 24   8   data length, in sectors
//! 32   16  UUID
//! 48   4   CRC-32C of the header with this field zero (0: none,
//!          headers written before ADR 0039)
//! 52   4   flags (bit 0: the CRC is there)
//! 64   4 × 256  key slots:
//!          0   4   state (1: a password, 2: a recovery key)
//!          4   4   KDF (1: Argon2id, version 0x13)
//!          8   4   memory, KiB
//!          12  4   passes
//!          16  4   lanes
//!          20  4   owner: the account's UID + 1 (0: not known; ADR
//!                  0058), so a password reset by root can find the
//!                  account's own slot
//!          32  32  salt
//!          64  72  the master key, wrapped
//! ```
//!
//! A copy of the header sits at 512 KiB (ADR 0039): when the first 4 KiB
//! are damaged (no magic, or a CRC that doesn't match), the copy is read.
//!
//! A recovery key (ADR 0039) is 160 random bits written as 32 characters
//! of Crockford's base32 in eight groups of four, `XXXX-XXXX-...`. Typed,
//! it is normalized (case, dashes and spaces, O for 0, I and L for 1) and
//! then opens its slot as a password would, with lighter Argon2id costs
//! (it needs no stretching).
//!
//! Keys and passwords are wiped from memory after use ([`wipe`]); the AES
//! key schedules and Argon2's memory wipe themselves (the crates'
//! `zeroize` features).

#![no_std]

use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

#[cfg(feature = "password")]
pub use argon2::Block;

pub const MAGIC: [u8; 8] = *b"SLCRYPT\0";
pub const VERSION: u32 = 1;
pub const CIPHER_AES_XTS: u32 = 1;
pub const KDF_ARGON2ID: u32 = 1;
pub const HEADER_BYTES: usize = 4096;
pub const SECTOR: usize = 512;
/// Where the data starts: 1 MiB in, room for the header and later
/// additions.
pub const DATA_OFFSET: u64 = 2048;
pub const SLOTS: usize = 4;
/// Where the header's copy is, in sectors (512 KiB).
pub const BACKUP_OFFSET: u64 = 1024;
const CRC_AT: usize = 48;
const FLAGS_AT: usize = 52;
const FLAG_CRC: u32 = 1;
const STATE_PASSWORD: u32 = 1;
const STATE_RECOVERY: u32 = 2;
const SLOT_AT: usize = 64;
const SLOT_BYTES: usize = 256;
pub const KEY_BYTES: usize = 64;
pub const WRAPPED_BYTES: usize = KEY_BYTES + 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NotEncrypted,
    Unsupported,
    BadParams,
    /// The password fits no key slot.
    WrongPassword,
    /// Both copies of the header are damaged.
    Damaged,
    /// Not enough memory was given for the key derivation.
    Memory,
}

/// Argon2id's costs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
}

impl Params {
    /// 64 MiB and 3 passes, RFC 9106's second recommended option (§4),
    /// in one lane: the kernel derives on one CPU at boot.
    pub const DEFAULT: Params = Params { memory_kib: 64 * 1024, passes: 3, lanes: 1 };
    /// For recovery keys: 160 random bits need no stretching, so the
    /// derivation is cheap (8 MiB, one pass).
    pub const RECOVERY: Params = Params { memory_kib: 8 * 1024, passes: 1, lanes: 1 };

    /// How many 1 KiB blocks the derivation needs.
    pub fn blocks(&self) -> usize {
        self.memory_kib as usize
    }
}

/// What opens a key slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotKind {
    Password,
    RecoveryKey,
}

/// A key slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    pub kind: SlotKind,
    pub params: Params,
    pub salt: [u8; 32],
    pub wrapped: [u8; WRAPPED_BYTES],
    /// The UID of the account whose password this is, if known.
    pub owner: Option<u32>,
}

/// A parsed header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub data_offset: u64,
    pub data_sectors: u64,
    pub uuid: [u8; 16],
    pub slots: [Option<Slot>; SLOTS],
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut x = [0u8; 8];
    x.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(x)
}

/// Whether a partition starting with `first` (at least 8 bytes) is
/// encrypted this way.
pub fn is_encrypted(first: &[u8]) -> bool {
    first.len() >= MAGIC.len() && first[..MAGIC.len()] == MAGIC
}

impl Header {
    /// A header for a partition of `sectors` with no key slots yet.
    pub fn new(sectors: u64, uuid: [u8; 16]) -> Header {
        Header { data_offset: DATA_OFFSET, data_sectors: sectors - DATA_OFFSET, uuid, slots: [None; SLOTS] }
    }

    /// The header from its first copy, or from the backup when the first
    /// is damaged (`backup` may be empty when it can't be read).
    pub fn parse_either(first: &[u8], backup: &[u8]) -> Result<Header, Error> {
        match Header::parse(first) {
            Err(Error::NotEncrypted | Error::Damaged) => Header::parse(backup).map_err(|e| match e {
                Error::NotEncrypted if is_encrypted(first) => Error::Damaged,
                e => e,
            }),
            r => r,
        }
    }

    pub fn parse(b: &[u8]) -> Result<Header, Error> {
        if b.len() < HEADER_BYTES || !is_encrypted(b) {
            return Err(Error::NotEncrypted);
        }
        if u32_at(b, FLAGS_AT) & FLAG_CRC != 0 && u32_at(b, CRC_AT) != header_crc(&b[..HEADER_BYTES]) {
            return Err(Error::Damaged);
        }
        if u32_at(b, 8) != VERSION || u32_at(b, 12) != CIPHER_AES_XTS {
            return Err(Error::Unsupported);
        }
        let mut slots = [None; SLOTS];
        for (i, s) in slots.iter_mut().enumerate() {
            let at = SLOT_AT + i * SLOT_BYTES;
            let kind = match u32_at(b, at) {
                STATE_PASSWORD => SlotKind::Password,
                STATE_RECOVERY => SlotKind::RecoveryKey,
                _ => continue,
            };
            if u32_at(b, at + 4) != KDF_ARGON2ID {
                return Err(Error::Unsupported);
            }
            let params =
                Params { memory_kib: u32_at(b, at + 8), passes: u32_at(b, at + 12), lanes: u32_at(b, at + 16) };
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&b[at + 32..at + 64]);
            let mut wrapped = [0u8; WRAPPED_BYTES];
            wrapped.copy_from_slice(&b[at + 64..at + 64 + WRAPPED_BYTES]);
            let owner = u32_at(b, at + 20).checked_sub(1);
            *s = Some(Slot { kind, params, salt, wrapped, owner });
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&b[32..48]);
        Ok(Header { data_offset: u64_at(b, 16), data_sectors: u64_at(b, 24), uuid, slots })
    }

    pub fn to_bytes(&self) -> [u8; HEADER_BYTES] {
        let mut b = [0u8; HEADER_BYTES];
        b[..8].copy_from_slice(&MAGIC);
        b[8..12].copy_from_slice(&VERSION.to_le_bytes());
        b[12..16].copy_from_slice(&CIPHER_AES_XTS.to_le_bytes());
        b[16..24].copy_from_slice(&self.data_offset.to_le_bytes());
        b[24..32].copy_from_slice(&self.data_sectors.to_le_bytes());
        b[32..48].copy_from_slice(&self.uuid);
        for (i, s) in self.slots.iter().enumerate() {
            let Some(s) = s else { continue };
            let at = SLOT_AT + i * SLOT_BYTES;
            let state = match s.kind {
                SlotKind::Password => STATE_PASSWORD,
                SlotKind::RecoveryKey => STATE_RECOVERY,
            };
            b[at..at + 4].copy_from_slice(&state.to_le_bytes());
            b[at + 4..at + 8].copy_from_slice(&KDF_ARGON2ID.to_le_bytes());
            b[at + 8..at + 12].copy_from_slice(&s.params.memory_kib.to_le_bytes());
            b[at + 12..at + 16].copy_from_slice(&s.params.passes.to_le_bytes());
            b[at + 16..at + 20].copy_from_slice(&s.params.lanes.to_le_bytes());
            let owner = s.owner.map_or(0, |u| u.saturating_add(1));
            b[at + 20..at + 24].copy_from_slice(&owner.to_le_bytes());
            b[at + 32..at + 64].copy_from_slice(&s.salt);
            b[at + 64..at + 64 + WRAPPED_BYTES].copy_from_slice(&s.wrapped);
        }
        b[FLAGS_AT..FLAGS_AT + 4].copy_from_slice(&FLAG_CRC.to_le_bytes());
        let crc = header_crc(&b);
        b[CRC_AT..CRC_AT + 4].copy_from_slice(&crc.to_le_bytes());
        b
    }

    /// The free slot with the lowest number.
    pub fn free_slot(&self) -> Option<usize> {
        self.slots.iter().position(Option::is_none)
    }

    #[cfg(feature = "password")]
    /// The master key, from the first slot `password` opens.
    pub fn unlock(&self, password: &[u8], memory: &mut [Block]) -> Result<[u8; KEY_BYTES], Error> {
        self.unlock_slot(password, memory).map(|(_, k)| k)
    }

    #[cfg(feature = "password")]
    /// The first slot `typed` opens and the master key: password slots
    /// with the text as typed, recovery-key slots with it normalized.
    pub fn unlock_slot(&self, typed: &[u8], memory: &mut [Block]) -> Result<(usize, [u8; KEY_BYTES]), Error> {
        let mut recovery = normalize_recovery_key(typed);
        let mut result = Err(Error::WrongPassword);
        for (i, s) in self.slots.iter().enumerate() {
            let Some(s) = s else { continue };
            let secret: &[u8] = match (s.kind, &recovery) {
                (SlotKind::Password, _) => typed,
                (SlotKind::RecoveryKey, Some(r)) => r,
                (SlotKind::RecoveryKey, None) => continue,
            };
            match open_slot(s, secret, memory) {
                Ok(k) => {
                    result = Ok((i, k));
                    break;
                }
                Err(Error::WrongPassword) => continue,
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        if let Some(r) = recovery.as_mut() {
            wipe(r);
        }
        result
    }
}

#[cfg(feature = "password")]
/// The key-encryption key for a password (Argon2id).
fn derive(password: &[u8], salt: &[u8; 32], p: Params, memory: &mut [Block]) -> Result<[u8; 32], Error> {
    let params = argon2::Params::new(p.memory_kib, p.passes, p.lanes, Some(32)).map_err(|_| Error::BadParams)?;
    let blocks = params.block_count();
    if memory.len() < blocks {
        return Err(Error::Memory);
    }
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    a.hash_password_into_with_memory(password, salt, &mut out, &mut memory[..blocks]).map_err(|_| Error::BadParams)?;
    Ok(out)
}

#[cfg(feature = "password")]
/// A slot of `kind` holding `master` under `secret` (a password, or a
/// recovery key as [`recovery_key`] writes it).
pub fn new_slot_of(
    kind: SlotKind,
    master: &[u8; KEY_BYTES],
    secret: &[u8],
    salt: [u8; 32],
    memory: &mut [Block],
) -> Result<Slot, Error> {
    let params = match kind {
        SlotKind::Password => Params::DEFAULT,
        SlotKind::RecoveryKey => Params::RECOVERY,
    };
    let mut normalized = match kind {
        SlotKind::RecoveryKey => Some(normalize_recovery_key(secret).ok_or(Error::BadParams)?),
        SlotKind::Password => None,
    };
    let s = new_slot(master, normalized.as_ref().map_or(secret, |n| n.as_slice()), salt, params, memory);
    if let Some(n) = normalized.as_mut() {
        wipe(n);
    }
    s.map(|s| Slot { kind, ..s })
}

#[cfg(feature = "password")]
/// A password slot holding `master` under `password`.
pub fn new_slot(
    master: &[u8; KEY_BYTES],
    password: &[u8],
    salt: [u8; 32],
    params: Params,
    memory: &mut [Block],
) -> Result<Slot, Error> {
    let mut k = derive(password, &salt, params, memory)?;
    let wrapped = wrap(master, &k);
    wipe(&mut k);
    Ok(Slot { kind: SlotKind::Password, params, salt, wrapped: wrapped?, owner: None })
}

/// `master` wrapped under `kek` (AES key wrap): what a slot keeps. The
/// kernel does this for a mapped device's key (ADR 0058), so the key
/// stays in the kernel.
pub fn wrap(master: &[u8; KEY_BYTES], kek: &[u8; 32]) -> Result<[u8; WRAPPED_BYTES], Error> {
    let kw = aes_kw::KekAes256::from(*kek);
    let mut wrapped = [0u8; WRAPPED_BYTES];
    kw.wrap(master, &mut wrapped).map_err(|_| Error::BadParams)?;
    Ok(wrapped)
}

#[cfg(feature = "password")]
/// The key a new slot with `salt` and `params` would wrap under, for
/// `password`: the costly half of [`new_slot`] (Argon2id), done in user
/// space before the kernel's [`wrap`].
pub fn new_slot_key(password: &[u8], salt: &[u8; 32], params: Params, memory: &mut [Block]) -> Result<[u8; 32], Error> {
    derive(password, salt, params, memory)
}

#[cfg(feature = "password")]
/// The master key in `slot`, if `password` opens it (the key wrap's
/// integrity check tells).
pub fn open_slot(slot: &Slot, password: &[u8], memory: &mut [Block]) -> Result<[u8; KEY_BYTES], Error> {
    let mut kek = slot_key(slot, password, memory)?;
    let key = unwrap_slot(slot, &kek);
    wipe(&mut kek);
    key
}

#[cfg(feature = "password")]
/// The key that would open `slot` if `password` is right: the costly half
/// of [`open_slot`] (Argon2id), which the boot's unlock program does in
/// user space (ADR 0038).
pub fn slot_key(slot: &Slot, password: &[u8], memory: &mut [Block]) -> Result<[u8; 32], Error> {
    derive(password, &slot.salt, slot.params, memory)
}

/// The master key in `slot`, if `kek` (from [`slot_key`]) opens it: the
/// cheap half of [`open_slot`], which the kernel does.
pub fn unwrap_slot(slot: &Slot, kek: &[u8; 32]) -> Result<[u8; KEY_BYTES], Error> {
    let kw = aes_kw::KekAes256::from(*kek);
    let mut key = [0u8; KEY_BYTES];
    kw.unwrap(&slot.wrapped, &mut key).map_err(|_| Error::WrongPassword)?;
    Ok(key)
}

/// Overwrite secret bytes with zeros in a way the compiler keeps (volatile
/// writes, then a fence).
pub fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        // SAFETY: `x` is a valid, aligned, exclusive reference to a byte.
        unsafe { core::ptr::write_volatile(x, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// CRC-32C (Castagnoli, the reflected polynomial 82F63B78h) of `header`
/// with its CRC field taken as zero.
fn header_crc(header: &[u8]) -> u32 {
    let mut crc = !0u32;
    for (i, &byte) in header.iter().enumerate() {
        let b = if (CRC_AT..CRC_AT + 4).contains(&i) { 0 } else { byte };
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82F6_3B78 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

/// Crockford's base32 alphabet (no I, L, O or U).
const BASE32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// A recovery key's length as written: 8 groups of 4 and 7 dashes.
pub const RECOVERY_KEY_LEN: usize = 39;

/// A recovery key from 20 random bytes: `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`.
pub fn recovery_key(random: &[u8; 20]) -> [u8; RECOVERY_KEY_LEN] {
    let mut out = [b'-'; RECOVERY_KEY_LEN];
    for i in 0..32 {
        // Character i takes bits 5i..5i+5, most significant first.
        let bit = i * 5;
        let v = ((u16::from(random[bit / 8]) << 8 | u16::from(*random.get(bit / 8 + 1).unwrap_or(&0)))
            >> (11 - bit % 8))
            & 0x1F;
        out[i + i / 4] = BASE32[usize::from(v)];
    }
    out
}

/// What was typed, as a recovery key's 32 characters, if it is one: case,
/// dashes and spaces don't matter, O reads as 0, I and L as 1.
pub fn normalize_recovery_key(typed: &[u8]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let mut n = 0;
    for &c in typed {
        let c = match c.to_ascii_uppercase() {
            b'-' | b' ' => continue,
            b'O' => b'0',
            b'I' | b'L' => b'1',
            c if BASE32.contains(&c) => c,
            _ => return None,
        };
        *out.get_mut(n)? = c;
        n += 1;
    }
    (n == 32).then_some(out)
}

#[cfg(feature = "password")]
/// Memory for the key derivation viewed as Argon2 blocks: `bytes` must be
/// aligned to 64 bytes (a page-aligned mapping is).
pub fn blocks_from_bytes(bytes: &mut [u8]) -> Option<&mut [Block]> {
    let size = core::mem::size_of::<Block>();
    if !(bytes.as_ptr() as usize).is_multiple_of(core::mem::align_of::<Block>()) {
        return None;
    }
    // SAFETY: Block is a plain array of u64 (`[u64; 128]`, 1 KiB) for which
    // every bit pattern is valid; the pointer is aligned for it (checked
    // above), the length is rounded down to whole blocks, and the returned
    // slice borrows `bytes` mutably for its whole life.
    Some(unsafe { core::slice::from_raw_parts_mut(bytes.as_mut_ptr().cast::<Block>(), bytes.len() / size) })
}

#[cfg(target_arch = "x86_64")]
pub mod aesni;

/// AES-256-XTS over 512-byte sectors (IEEE 1619-2007 §5.3), with AES-NI
/// where the CPU has it (ADR 0039), else the aes crate's constant-time
/// software AES.
pub struct Xts {
    data: Aes256,
    tweak: Aes256,
    /// The AES-NI round keys (data, tweak).
    #[cfg(target_arch = "x86_64")]
    ni: Option<(aesni::Keys, aesni::Keys)>,
}

impl core::fmt::Debug for Xts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Xts(..)")
    }
}

/// Multiply the tweak by α in GF(2^128) (IEEE 1619 §5.2: little-endian,
/// reduction by x^128 + x^7 + x^2 + x + 1).
fn times_alpha(t: &mut [u8; 16]) {
    let carry = t[15] >> 7;
    for i in (1..16).rev() {
        t[i] = (t[i] << 1) | (t[i - 1] >> 7);
    }
    t[0] = (t[0] << 1) ^ (0x87 * carry);
}

impl Xts {
    /// From the 64-byte master key: the data key, then the tweak key.
    /// AES-NI is used where the CPU has it: in the kernel, encrypt and
    /// decrypt then overwrite the vector registers, which the caller saves
    /// (see [`Xts::accelerated`]).
    pub fn new(key: &[u8; KEY_BYTES]) -> Xts {
        #[cfg(target_arch = "x86_64")]
        let ni = aesni::available();
        #[cfg(not(target_arch = "x86_64"))]
        let ni = false;
        Xts::with_aesni(key, ni)
    }

    /// As [`Xts::new`], with AES-NI only when `ni` (and the CPU has it).
    pub fn with_aesni(key: &[u8; KEY_BYTES], ni: bool) -> Xts {
        let _ = ni;
        Xts {
            data: Aes256::new(GenericArray::from_slice(&key[..32])),
            tweak: Aes256::new(GenericArray::from_slice(&key[32..])),
            #[cfg(target_arch = "x86_64")]
            ni: (ni && aesni::available()).then(|| {
                let (d, t) = key.split_at(32);
                (aesni::Keys::new(d.try_into().unwrap_or(&[0; 32])), aesni::Keys::new(t.try_into().unwrap_or(&[0; 32])))
            }),
        }
    }

    /// Whether sectors go through AES-NI, which overwrites the vector
    /// registers.
    pub fn accelerated(&self) -> bool {
        #[cfg(target_arch = "x86_64")]
        return self.ni.is_some();
        #[cfg(not(target_arch = "x86_64"))]
        return false;
    }

    /// One sector with AES-NI. The tweaks and the XORs work on 128-bit
    /// little-endian words (the tweak's bytes are IEEE 1619's
    /// little-endian polynomial, so α is a shift with the carry folded
    /// back as 0x87).
    #[cfg(target_arch = "x86_64")]
    fn sector_ni(&self, keys: &(aesni::Keys, aesni::Keys), n: u64, data: &mut [u8; SECTOR], encrypt: bool) {
        let mut t = [[0u8; 16]; 1];
        t[0][..8].copy_from_slice(&n.to_le_bytes());
        // SAFETY: `ni` is only set when the CPU has AES-NI; the vector
        // registers are the caller's to give (`Xts::new`).
        unsafe { keys.1.crypt(&mut t, true) };
        let mut tweak = u128::from_le_bytes(t[0]);
        let mut tweaks = [0u128; SECTOR / 16];
        let mut blocks = [[0u8; 16]; SECTOR / 16];
        for (i, chunk) in data.as_chunks::<16>().0.iter().enumerate() {
            tweaks[i] = tweak;
            blocks[i] = (u128::from_le_bytes(*chunk) ^ tweak).to_le_bytes();
            tweak = (tweak << 1) ^ (0x87 * (tweak >> 127));
        }
        // SAFETY: as above.
        unsafe { keys.0.crypt(&mut blocks, encrypt) };
        for (i, chunk) in data.as_chunks_mut::<16>().0.iter_mut().enumerate() {
            *chunk = (u128::from_le_bytes(blocks[i]) ^ tweaks[i]).to_le_bytes();
        }
    }

    fn sector(&self, n: u64, data: &mut [u8; SECTOR], encrypt: bool) {
        #[cfg(target_arch = "x86_64")]
        if let Some(k) = &self.ni {
            return self.sector_ni(k, n, data, encrypt);
        }
        let mut t = GenericArray::from([0u8; 16]);
        t[..8].copy_from_slice(&n.to_le_bytes());
        self.tweak.encrypt_block(&mut t);
        let mut tweak: [u8; 16] = t.into();
        let mut tweaks = [[0u8; 16]; SECTOR / 16];
        let mut blocks = [GenericArray::from([0u8; 16]); SECTOR / 16];
        for (i, chunk) in data.as_chunks::<16>().0.iter().enumerate() {
            tweaks[i] = tweak;
            for j in 0..16 {
                blocks[i][j] = chunk[j] ^ tweak[j];
            }
            times_alpha(&mut tweak);
        }
        if encrypt {
            self.data.encrypt_blocks(&mut blocks);
        } else {
            self.data.decrypt_blocks(&mut blocks);
        }
        for (i, chunk) in data.as_chunks_mut::<16>().0.iter_mut().enumerate() {
            for j in 0..16 {
                chunk[j] = blocks[i][j] ^ tweaks[i][j];
            }
        }
    }

    /// Encrypt whole sectors in place, the first being sector `first`
    /// (a partial sector at the end is left alone).
    pub fn encrypt(&self, first: u64, data: &mut [u8]) {
        for (i, s) in data.as_chunks_mut::<SECTOR>().0.iter_mut().enumerate() {
            self.sector(first + i as u64, s, true);
        }
    }

    pub fn decrypt(&self, first: u64, data: &mut [u8]) {
        for (i, s) in data.as_chunks_mut::<SECTOR>().0.iter_mut().enumerate() {
            self.sector(first + i as u64, s, false);
        }
    }
}

#[cfg(test)]
mod tests;
