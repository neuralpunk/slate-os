// SPDX-License-Identifier: MIT OR Apache-2.0

//! AES-256 with the AES-NI instructions (Intel SDM vol. 2: AESENC,
//! AESENCLAST, AESDEC, AESDECLAST; the Intel AES-NI white paper's
//! "equivalent inverse cipher" round keys), for XTS (ADR 0039).
//!
//! The key schedule is FIPS-197's KeyExpansion (§5.2) in plain Rust, the
//! decryption keys its InvMixColumns of the middle round keys (§5.3.5);
//! only the rounds are assembly. The aes crate's own AES-NI code does not
//! compile for the soft-float `x86_64-unknown-none` target, so this is
//! written in `asm!` with the vector registers named inside the template:
//! where the compiler has no SSE (that target) it never holds values in
//! them, and a caller in the kernel saves and restores them around the
//! call (`arch::fpu::with_vectors`); where it has SSE (the host) they are
//! declared clobbered.

#![allow(clippy::needless_range_loop)]

/// AES-256's 15 round keys, and the decryption's: 16-byte aligned, as
/// the rounds read some from memory (SSE's memory operands must be).
#[derive(Clone)]
#[repr(C, align(16))]
pub struct Keys {
    enc: [[u8; 16]; 15],
    dec: [[u8; 16]; 15],
}

impl core::fmt::Debug for Keys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Keys(..)")
    }
}

impl Drop for Keys {
    fn drop(&mut self) {
        for k in self.enc.iter_mut().chain(self.dec.iter_mut()) {
            crate::wipe(k);
        }
    }
}

/// Whether the CPU has AES-NI (CPUID.01H:ECX bit 25).
pub fn available() -> bool {
    core::arch::x86_64::__cpuid(1).ecx & (1 << 25) != 0
}

/// Multiplication in GF(2^8) with AES's polynomial x^8 + x^4 + x^3 + x + 1.
fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

/// The S-box (FIPS-197 §5.1.1): the multiplicative inverse, then the
/// affine transformation.
fn sbox(x: u8) -> u8 {
    // x^254 is x's inverse (0 for 0).
    let mut inv = 1u8;
    for _ in 0..254 {
        inv = mul(inv, x);
    }
    if x == 0 {
        inv = 0;
    }
    inv ^ inv.rotate_left(1) ^ inv.rotate_left(2) ^ inv.rotate_left(3) ^ inv.rotate_left(4) ^ 0x63
}

/// InvMixColumns of one round key (FIPS-197 §5.3.3), column by column.
fn inv_mix(k: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for c in 0..4 {
        let a = &k[4 * c..4 * c + 4];
        for r in 0..4 {
            out[4 * c + r] = mul(a[r], 14) ^ mul(a[(r + 1) % 4], 11) ^ mul(a[(r + 2) % 4], 13) ^ mul(a[(r + 3) % 4], 9);
        }
    }
    out
}

impl Keys {
    /// From a 256-bit key.
    pub fn new(key: &[u8; 32]) -> Keys {
        let mut table = [0u8; 256];
        for (i, t) in table.iter_mut().enumerate() {
            *t = sbox(i as u8);
        }
        // KeyExpansion with Nk = 8, Nr = 14: 60 words.
        let mut w = [[0u8; 4]; 60];
        for i in 0..8 {
            w[i].copy_from_slice(&key[4 * i..4 * i + 4]);
        }
        let mut rcon = 1u8;
        for i in 8..60 {
            let mut t = w[i - 1];
            if i % 8 == 0 {
                t = [table[t[1] as usize] ^ rcon, table[t[2] as usize], table[t[3] as usize], table[t[0] as usize]];
                rcon = mul(rcon, 2);
            } else if i % 8 == 4 {
                t = t.map(|b| table[b as usize]);
            }
            for j in 0..4 {
                w[i][j] = w[i - 8][j] ^ t[j];
            }
        }
        let mut enc = [[0u8; 16]; 15];
        for (r, k) in enc.iter_mut().enumerate() {
            for c in 0..4 {
                k[4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
            }
        }
        for x in w.iter_mut() {
            crate::wipe(x);
        }
        let mut dec = [[0u8; 16]; 15];
        dec[0] = enc[14];
        dec[14] = enc[0];
        for r in 1..14 {
            dec[r] = inv_mix(&enc[14 - r]);
        }
        Keys { enc, dec }
    }

    /// Encrypt (or decrypt) `blocks` in place.
    ///
    /// # Safety
    ///
    /// The CPU has AES-NI ([`available`]), and in the kernel the caller
    /// has saved the vector registers (they are overwritten).
    pub unsafe fn crypt(&self, blocks: &mut [[u8; 16]], encrypt: bool) {
        if blocks.is_empty() {
            return;
        }
        let keys = if encrypt { &self.enc } else { &self.dec };
        // SAFETY: `keys` is 15 × 16 readable bytes and `blocks` n × 16
        // writable ones; the loop reads and writes only those. The vector
        // registers are the caller's to give (see above); the general ones
        // used are declared.
        unsafe { run(keys.as_ptr().cast(), blocks.as_mut_ptr().cast(), blocks.len(), encrypt) }
    }
}

/// The rounds for `n` blocks at `data` with round keys at `keys`: xmm0 to
/// xmm3 hold blocks, xmm4 to xmm15 the first 12 keys.
///
/// # Safety
///
/// As for [`Keys::crypt`]; `keys` and `data` point at 240 (16-byte
/// aligned) and 16 × `n` bytes, `n` at least 1.
#[allow(clippy::too_many_lines)]
unsafe fn run(keys: *const u8, data: *mut u8, n: usize, encrypt: bool) {
    // Four blocks at a time while there are four (AESENC's latency is
    // several cycles, its throughput one a cycle: independent blocks keep
    // the unit busy), then one at a time. xmm4 to xmm15 hold round keys 0
    // to 11; 12 to 14 are read from memory (aligned: `Keys` is).
    macro_rules! rounds {
        ($round:literal, $last:literal) => {
            concat!(
                "movdqu xmm4, [{k} + 0]\n",
                "movdqu xmm5, [{k} + 16]\n",
                "movdqu xmm6, [{k} + 32]\n",
                "movdqu xmm7, [{k} + 48]\n",
                "movdqu xmm8, [{k} + 64]\n",
                "movdqu xmm9, [{k} + 80]\n",
                "movdqu xmm10, [{k} + 96]\n",
                "movdqu xmm11, [{k} + 112]\n",
                "movdqu xmm12, [{k} + 128]\n",
                "movdqu xmm13, [{k} + 144]\n",
                "movdqu xmm14, [{k} + 160]\n",
                "movdqu xmm15, [{k} + 176]\n",
                "cmp {n}, 4\n",
                "jb 3f\n",
                "2:\n",
                "movdqu xmm0, [{d} + 0]\n",
                "movdqu xmm1, [{d} + 16]\n",
                "movdqu xmm2, [{d} + 32]\n",
                "movdqu xmm3, [{d} + 48]\n",
                "pxor xmm0, xmm4\n",
                "pxor xmm1, xmm4\n",
                "pxor xmm2, xmm4\n",
                "pxor xmm3, xmm4\n",
                $round,
                " xmm0, xmm5\n",
                $round,
                " xmm1, xmm5\n",
                $round,
                " xmm2, xmm5\n",
                $round,
                " xmm3, xmm5\n",
                $round,
                " xmm0, xmm6\n",
                $round,
                " xmm1, xmm6\n",
                $round,
                " xmm2, xmm6\n",
                $round,
                " xmm3, xmm6\n",
                $round,
                " xmm0, xmm7\n",
                $round,
                " xmm1, xmm7\n",
                $round,
                " xmm2, xmm7\n",
                $round,
                " xmm3, xmm7\n",
                $round,
                " xmm0, xmm8\n",
                $round,
                " xmm1, xmm8\n",
                $round,
                " xmm2, xmm8\n",
                $round,
                " xmm3, xmm8\n",
                $round,
                " xmm0, xmm9\n",
                $round,
                " xmm1, xmm9\n",
                $round,
                " xmm2, xmm9\n",
                $round,
                " xmm3, xmm9\n",
                $round,
                " xmm0, xmm10\n",
                $round,
                " xmm1, xmm10\n",
                $round,
                " xmm2, xmm10\n",
                $round,
                " xmm3, xmm10\n",
                $round,
                " xmm0, xmm11\n",
                $round,
                " xmm1, xmm11\n",
                $round,
                " xmm2, xmm11\n",
                $round,
                " xmm3, xmm11\n",
                $round,
                " xmm0, xmm12\n",
                $round,
                " xmm1, xmm12\n",
                $round,
                " xmm2, xmm12\n",
                $round,
                " xmm3, xmm12\n",
                $round,
                " xmm0, xmm13\n",
                $round,
                " xmm1, xmm13\n",
                $round,
                " xmm2, xmm13\n",
                $round,
                " xmm3, xmm13\n",
                $round,
                " xmm0, xmm14\n",
                $round,
                " xmm1, xmm14\n",
                $round,
                " xmm2, xmm14\n",
                $round,
                " xmm3, xmm14\n",
                $round,
                " xmm0, xmm15\n",
                $round,
                " xmm1, xmm15\n",
                $round,
                " xmm2, xmm15\n",
                $round,
                " xmm3, xmm15\n",
                $round,
                " xmm0, [{k} + 192]\n",
                $round,
                " xmm1, [{k} + 192]\n",
                $round,
                " xmm2, [{k} + 192]\n",
                $round,
                " xmm3, [{k} + 192]\n",
                $round,
                " xmm0, [{k} + 208]\n",
                $round,
                " xmm1, [{k} + 208]\n",
                $round,
                " xmm2, [{k} + 208]\n",
                $round,
                " xmm3, [{k} + 208]\n",
                $last,
                " xmm0, [{k} + 224]\n",
                $last,
                " xmm1, [{k} + 224]\n",
                $last,
                " xmm2, [{k} + 224]\n",
                $last,
                " xmm3, [{k} + 224]\n",
                "movdqu [{d} + 0], xmm0\n",
                "movdqu [{d} + 16], xmm1\n",
                "movdqu [{d} + 32], xmm2\n",
                "movdqu [{d} + 48], xmm3\n",
                "add {d}, 64\n",
                "sub {n}, 4\n",
                "cmp {n}, 4\n",
                "jae 2b\n",
                "3:\n",
                "test {n}, {n}\n",
                "jz 5f\n",
                "4:\n",
                "movdqu xmm0, [{d}]\n",
                "pxor xmm0, xmm4\n",
                $round,
                " xmm0, xmm5\n",
                $round,
                " xmm0, xmm6\n",
                $round,
                " xmm0, xmm7\n",
                $round,
                " xmm0, xmm8\n",
                $round,
                " xmm0, xmm9\n",
                $round,
                " xmm0, xmm10\n",
                $round,
                " xmm0, xmm11\n",
                $round,
                " xmm0, xmm12\n",
                $round,
                " xmm0, xmm13\n",
                $round,
                " xmm0, xmm14\n",
                $round,
                " xmm0, xmm15\n",
                $round,
                " xmm0, [{k} + 192]\n",
                $round,
                " xmm0, [{k} + 208]\n",
                $last,
                " xmm0, [{k} + 224]\n",
                "movdqu [{d}], xmm0\n",
                "add {d}, 16\n",
                "dec {n}\n",
                "jnz 4b\n",
                "5:\n",
            )
        };
    }
    #[cfg(target_feature = "sse2")]
    macro_rules! go {
        ($t:expr) => {
            // SAFETY: as for the function.
            unsafe {
                core::arch::asm!(
                    $t, k = in(reg) keys, d = inout(reg) data => _, n = inout(reg) n => _,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _, out("xmm4") _,
                    out("xmm5") _, out("xmm6") _, out("xmm7") _, out("xmm8") _, out("xmm9") _,
                    out("xmm10") _, out("xmm11") _, out("xmm12") _, out("xmm13") _, out("xmm14") _,
                    out("xmm15") _, options(nostack)
                )
            }
        };
    }
    #[cfg(not(target_feature = "sse2"))]
    macro_rules! go {
        ($t:expr) => {
            // SAFETY: as for the function; without SSE the compiler keeps
            // nothing in the vector registers.
            unsafe {
                core::arch::asm!($t, k = in(reg) keys, d = inout(reg) data => _, n = inout(reg) n => _,
                    options(nostack))
            }
        };
    }
    if encrypt {
        go!(rounds!("aesenc", "aesenclast"));
    } else {
        go!(rounds!("aesdec", "aesdeclast"));
    }
}
