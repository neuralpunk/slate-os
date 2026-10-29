// SPDX-License-Identifier: MIT OR Apache-2.0

//! The kernel random number generator.
//!
//! A ChaCha20 keystream (RFC 8439 §2.3) keyed from hardware entropy (RDSEED
//! or RDRAND when present, otherwise TSC jitter mixed in). After each request
//! the key is replaced with fresh keystream, so earlier outputs cannot be
//! recovered from a later state (fast key erasure). This backs
//! `getrandom(2)`, `/dev/urandom` and `AT_RANDOM`.

use crate::arch::cpu::cpuid;
use crate::sync::IrqSpinLock;

fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// One 64-byte ChaCha20 block (RFC 8439 §2.3.2).
fn chacha20_block(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [u8; 64] {
    let mut init = [0u32; 16];
    init[..4].copy_from_slice(&[0x6170_7865, 0x3320_646E, 0x7962_2D32, 0x6B20_6574]);
    init[4..12].copy_from_slice(key);
    init[12] = counter;
    init[13..].copy_from_slice(nonce);
    let mut s = init;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&s[i].wrapping_add(init[i]).to_le_bytes());
    }
    out
}

#[derive(Debug)]
struct State {
    key: [u32; 8],
    nonce: u64,
    seeded: bool,
}

static STATE: IrqSpinLock<State> = IrqSpinLock::new(State { key: [0; 8], nonce: 0, seeded: false });

fn hw_u64() -> Option<u64> {
    let (_, ebx7, _, _) = cpuid(7, 0);
    let ecx1 = cpuid(1, 0).2;
    for _ in 0..10 {
        let (v, ok): (u64, u8);
        if ebx7 & (1 << 18) != 0 {
            // SAFETY: RDSEED is supported (CPUID.7.EBX[18]); it has no side effects.
            unsafe { core::arch::asm!("rdseed {}", "setc {}", out(reg) v, out(reg_byte) ok, options(nomem, nostack)) };
        } else if ecx1 & (1 << 30) != 0 {
            // SAFETY: RDRAND is supported (CPUID.1.ECX[30]).
            unsafe { core::arch::asm!("rdrand {}", "setc {}", out(reg) v, out(reg_byte) ok, options(nomem, nostack)) };
        } else {
            return None;
        }
        if ok != 0 {
            return Some(v);
        }
    }
    None
}

fn seed(s: &mut State) {
    for (i, k) in s.key.iter_mut().enumerate() {
        let jitter = crate::arch::tsc::read().rotate_left(i as u32 * 7);
        *k ^= (hw_u64().unwrap_or(0) ^ jitter) as u32;
    }
    s.seeded = true;
}

/// Fill `buf` with cryptographically strong random bytes.
pub fn fill(buf: &mut [u8]) {
    let mut s = STATE.lock();
    if !s.seeded {
        seed(&mut s);
    }
    s.nonce += 1;
    let nonce = [s.nonce as u32, (s.nonce >> 32) as u32, 0];
    // Block 0 becomes the next key; blocks 1.. are output.
    let next = chacha20_block(&s.key, 0, &nonce);
    for (i, chunk) in buf.chunks_mut(64).enumerate() {
        let block = chacha20_block(&s.key, i as u32 + 1, &nonce);
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
    for (i, k) in s.key.iter_mut().enumerate() {
        *k = u32::from_le_bytes(next[i * 4..i * 4 + 4].try_into().unwrap());
    }
}

/// RFC 8439 §2.3.2 test vector, for the in-kernel tests.
pub fn self_test() -> bool {
    let key: [u32; 8] =
        core::array::from_fn(|i| u32::from_le_bytes([4 * i as u8, 4 * i as u8 + 1, 4 * i as u8 + 2, 4 * i as u8 + 3]));
    let nonce = [0x0900_0000, 0x4A00_0000, 0];
    let out = chacha20_block(&key, 1, &nonce);
    out[..4] == [0x10, 0xF1, 0xE7, 0xE4] && out[60..] == [0xA2, 0x50, 0x3C, 0x4E]
}
