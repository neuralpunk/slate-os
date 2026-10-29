// SPDX-License-Identifier: MIT OR Apache-2.0

//! MD5 (RFC 1321), SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 (FIPS
//! 180-4), SHA-3 (FIPS 202), BLAKE2b (RFC 7693) and SM3 (GB/T
//! 32905-2016, as draft-sca-cfrg-sm3 gives it), written from the
//! specifications. Each has
//! a streaming hasher (`update` as data arrives, then `finish`) and a
//! one-shot function. Also CRC-32C (Castagnoli), the checksum SlateFS
//! uses for blocks.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::string::String;

/// Lowercase hexadecimal.
pub fn hex(b: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(DIGITS[usize::from(x >> 4)] as char);
        s.push(DIGITS[usize::from(x & 15)] as char);
    }
    s
}

/// Buffers input into `N`-byte blocks for a compression function.
#[derive(Clone, Debug)]
struct Blocks<const N: usize> {
    buf: [u8; N],
    len: usize,
    total: u128,
}

impl<const N: usize> Blocks<N> {
    const fn new() -> Self {
        Blocks { buf: [0; N], len: 0, total: 0 }
    }

    fn update(&mut self, mut data: &[u8], mut f: impl FnMut(&[u8; N])) {
        self.total += data.len() as u128;
        if self.len > 0 {
            let n = data.len().min(N - self.len);
            self.buf[self.len..self.len + n].copy_from_slice(&data[..n]);
            self.len += n;
            data = &data[n..];
            if self.len < N {
                return;
            }
            f(&self.buf);
            self.len = 0;
        }
        let (blocks, rest) = data.as_chunks::<N>();
        for b in blocks {
            f(b);
        }
        self.buf[..rest.len()].copy_from_slice(rest);
        self.len = rest.len();
    }

    /// Merkle-Damgard padding: 0x80, zeros, then the bit length in the last
    /// `len_bytes` bytes (big- or little-endian).
    fn finish(&mut self, len_bytes: usize, big_endian: bool, mut f: impl FnMut(&[u8; N])) {
        let bits = self.total.wrapping_mul(8);
        let mut pad = [0u8; 256];
        pad[0] = 0x80;
        let used = self.len + 1;
        let zeros = (N + N - len_bytes - used % N) % N;
        let mut tail = alloc::vec::Vec::with_capacity(1 + zeros + len_bytes);
        tail.extend_from_slice(&pad[..1 + zeros]);
        let be = bits.to_be_bytes();
        let le = bits.to_le_bytes();
        if big_endian {
            tail.extend_from_slice(&be[16 - len_bytes..]);
        } else {
            tail.extend_from_slice(&le[..len_bytes]);
        }
        let total = self.total;
        self.update(&tail, &mut f);
        self.total = total;
        debug_assert_eq!(self.len, 0);
    }
}

// --- CRC-32C ---------------------------------------------------------------

const fn crc32c_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            // The reflected Castagnoli polynomial (RFC 3720 §B.4).
            c = if c & 1 != 0 { (c >> 1) ^ 0x82F6_3B78 } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static CRC32C: [u32; 256] = crc32c_table();

/// CRC-32C of `data` (with the standard initial and final inversion).
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc = CRC32C[((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

// --- MD5 -----------------------------------------------------------------

/// Streaming MD5.
#[derive(Clone, Debug)]
pub struct Md5 {
    h: [u32; 4],
    blocks: Blocks<64>,
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5 {
    pub const fn new() -> Self {
        Md5 { h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476], blocks: Blocks::new() }
    }

    pub fn update(&mut self, data: &[u8]) {
        let h = &mut self.h;
        self.blocks.update(data, |b| md5_block(h, b));
    }

    pub fn finish(mut self) -> [u8; 16] {
        let h = &mut self.h;
        self.blocks.finish(8, false, |b| md5_block(h, b));
        let mut out = [0u8; 16];
        for (i, w) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

fn md5_block(h: &mut [u32; 4], block: &[u8; 64]) {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14,
        20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6,
        10, 15, 21,
    ];
    // K[i] = floor(abs(sin(i + 1)) * 2^32), the table in RFC 1321 §3.4.
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8,
        0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
        0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87,
        0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039,
        0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
        0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    let m: [u32; 16] = core::array::from_fn(|i| u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap()));
    let [mut a, mut b, mut c, mut d] = *h;
    for i in 0..64 {
        let (f, g) = match i / 16 {
            0 => ((b & c) | (!b & d), i),
            1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
            2 => (b ^ c ^ d, (3 * i + 5) % 16),
            _ => (c ^ (b | !d), (7 * i) % 16),
        };
        let t = d;
        d = c;
        c = b;
        b = b.wrapping_add(a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]).rotate_left(S[i]));
        a = t;
    }
    *h = [h[0].wrapping_add(a), h[1].wrapping_add(b), h[2].wrapping_add(c), h[3].wrapping_add(d)];
}

pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut m = Md5::new();
    m.update(data);
    m.finish()
}

// --- SHA-1 ---------------------------------------------------------------

/// Streaming SHA-1 (FIPS 180-4 §6.1). Broken for collision resistance;
/// here for `sha1sum` and the formats that still name it.
#[derive(Clone, Debug)]
pub struct Sha1 {
    h: [u32; 5],
    blocks: Blocks<64>,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    pub const fn new() -> Self {
        // FIPS 180-4 §5.3.1.
        Sha1 { h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0], blocks: Blocks::new() }
    }

    pub fn update(&mut self, data: &[u8]) {
        let h = &mut self.h;
        self.blocks.update(data, |b| sha1_block(h, b));
    }

    pub fn finish(mut self) -> [u8; 20] {
        let h = &mut self.h;
        self.blocks.finish(8, true, |b| sha1_block(h, b));
        let mut out = [0u8; 20];
        for (i, w) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }
}

fn sha1_block(h: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *h;
    for (i, &wi) in w.iter().enumerate() {
        // The functions and constants of FIPS 180-4 §4.1.1 and §4.2.1.
        let (f, k) = match i {
            0..20 => ((b & c) | (!b & d), 0x5a827999),
            20..40 => (b ^ c ^ d, 0x6ed9eba1),
            40..60 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
            _ => (b ^ c ^ d, 0xca62c1d6),
        };
        let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    for (x, v) in h.iter_mut().zip([a, b, c, d, e]) {
        *x = x.wrapping_add(v);
    }
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut s = Sha1::new();
    s.update(data);
    s.finish()
}

// --- SHA-256 -------------------------------------------------------------

/// Streaming SHA-256.
#[derive(Clone, Debug)]
pub struct Sha256 {
    h: [u32; 8],
    blocks: Blocks<64>,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub const fn new() -> Self {
        Sha256 {
            h: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
            blocks: Blocks::new(),
        }
    }

    /// SHA-224: SHA-256 with its own initial value (FIPS 180-4 §5.3.2);
    /// keep the first 28 bytes of [`Sha256::finish`].
    pub const fn new_224() -> Self {
        Sha256 {
            h: [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4],
            blocks: Blocks::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let h = &mut self.h;
        self.blocks.update(data, |b| sha256_block(h, b));
    }

    pub fn finish(mut self) -> [u8; 32] {
        let h = &mut self.h;
        self.blocks.finish(8, true, |b| sha256_block(h, b));
        let mut out = [0u8; 32];
        for (i, w) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }
}

fn sha256_block(h: &mut [u32; 8], block: &[u8; 64]) {
    // The first 32 bits of the fractional parts of the cube roots of the
    // first 64 primes (FIPS 180-4 §4.2.2).
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
        0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
        0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let mut v = *h;
    for i in 0..64 {
        let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
        let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
        let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
        let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        let t2 = s0.wrapping_add(maj);
        v = [t1.wrapping_add(t2), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]];
    }
    for i in 0..8 {
        h[i] = h[i].wrapping_add(v[i]);
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update(data);
    s.finish()
}

pub fn sha224(data: &[u8]) -> [u8; 28] {
    let mut s = Sha256::new_224();
    s.update(data);
    s.finish()[..28].try_into().unwrap()
}

// --- SHA-512 -------------------------------------------------------------

/// Streaming SHA-512.
#[derive(Clone, Debug)]
pub struct Sha512 {
    h: [u64; 8],
    blocks: Blocks<128>,
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    pub const fn new() -> Self {
        // The first 64 bits of the fractional parts of the square roots of
        // the first 8 primes (FIPS 180-4 §5.3.5).
        Sha512 {
            h: [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
            blocks: Blocks::new(),
        }
    }

    /// SHA-384: SHA-512 with its own initial value (FIPS 180-4 §5.3.4);
    /// keep the first 48 bytes of [`Sha512::finish`].
    pub const fn new_384() -> Self {
        Sha512 {
            h: [
                0xcbbb9d5dc1059ed8,
                0x629a292a367cd507,
                0x9159015a3070dd17,
                0x152fecd8f70e5939,
                0x67332667ffc00b31,
                0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7,
                0x47b5481dbefa4fa4,
            ],
            blocks: Blocks::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let h = &mut self.h;
        self.blocks.update(data, |b| sha512_block(h, b));
    }

    pub fn finish(mut self) -> [u8; 64] {
        let h = &mut self.h;
        self.blocks.finish(16, true, |b| sha512_block(h, b));
        let mut out = [0u8; 64];
        for (i, w) in self.h.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&w.to_be_bytes());
        }
        out
    }
}

fn sha512_block(h: &mut [u64; 8], block: &[u8; 128]) {
    // The first 64 bits of the fractional parts of the cube roots of the
    // first 80 primes (FIPS 180-4 §4.2.3).
    const K: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];
    let mut w = [0u64; 80];
    for i in 0..16 {
        w[i] = u64::from_be_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
    }
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let mut v = *h;
    for i in 0..80 {
        let s1 = v[4].rotate_right(14) ^ v[4].rotate_right(18) ^ v[4].rotate_right(41);
        let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
        let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = v[0].rotate_right(28) ^ v[0].rotate_right(34) ^ v[0].rotate_right(39);
        let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        let t2 = s0.wrapping_add(maj);
        v = [t1.wrapping_add(t2), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]];
    }
    for i in 0..8 {
        h[i] = h[i].wrapping_add(v[i]);
    }
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut s = Sha512::new();
    s.update(data);
    s.finish()
}

pub fn sha384(data: &[u8]) -> [u8; 48] {
    let mut s = Sha512::new_384();
    s.update(data);
    s.finish()[..48].try_into().unwrap()
}

// --- BLAKE2b ---------------------------------------------------------------

/// Streaming BLAKE2b (RFC 7693), unkeyed, with a digest of 1 to 64 bytes.
#[derive(Clone, Debug)]
pub struct Blake2b {
    h: [u64; 8],
    /// Bytes compressed so far.
    t: u128,
    /// The last block is kept until more data or the end arrives: it must
    /// be compressed with the final flag.
    buf: [u8; 128],
    len: usize,
    out: usize,
}

/// RFC 7693 §2.6: SHA-512's initial value.
const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// RFC 7693 §2.7: the message word schedule of each round.
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

impl Blake2b {
    /// A hasher for `out` bytes of digest (1 to 64; RFC 7693 §2.5).
    pub fn new(out: usize) -> Self {
        assert!((1..=64).contains(&out));
        let mut h = BLAKE2B_IV;
        // The parameter block: digest length, no key, fanout and depth 1.
        h[0] ^= 0x0101_0000 ^ out as u64;
        Blake2b { h, t: 0, buf: [0; 128], len: 0, out }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.len == 128 {
                self.t += 128;
                let block = self.buf;
                self.compress(&block, false);
                self.len = 0;
            }
            let n = data.len().min(128 - self.len);
            self.buf[self.len..self.len + n].copy_from_slice(&data[..n]);
            self.len += n;
            data = &data[n..];
        }
    }

    /// The digest, `out` bytes of it.
    pub fn finish(mut self) -> alloc::vec::Vec<u8> {
        self.t += self.len as u128;
        let mut block = self.buf;
        block[self.len..].fill(0);
        self.compress(&block, true);
        let mut out = alloc::vec::Vec::with_capacity(64);
        for w in self.h {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out.truncate(self.out);
        out
    }

    /// RFC 7693 §3.2, F.
    fn compress(&mut self, block: &[u8; 128], last: bool) {
        let mut m = [0u64; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
        }
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&BLAKE2B_IV);
        v[12] ^= self.t as u64;
        v[13] ^= (self.t >> 64) as u64;
        if last {
            v[14] = !v[14];
        }
        // RFC 7693 §3.1, G, with its rotations 32, 24, 16 and 63.
        let g = |v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64| {
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
            v[d] = (v[d] ^ v[a]).rotate_right(32);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(24);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(63);
        };
        for round in 0..12 {
            let s = &SIGMA[round % 10];
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}

/// BLAKE2b of `data`, `out` bytes of digest.
pub fn blake2b(data: &[u8], out: usize) -> alloc::vec::Vec<u8> {
    let mut b = Blake2b::new(out);
    b.update(data);
    b.finish()
}

// --- SM3 -------------------------------------------------------------------

/// Streaming SM3 (GB/T 32905-2016; draft-sca-cfrg-sm3).
#[derive(Clone, Debug)]
pub struct Sm3 {
    v: [u32; 8],
    blocks: Blocks<64>,
}

impl Default for Sm3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sm3 {
    pub const fn new() -> Self {
        // The initial value (§4.1).
        Sm3 {
            v: [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e],
            blocks: Blocks::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let v = &mut self.v;
        self.blocks.update(data, |b| sm3_block(v, b));
    }

    /// Padded as SHA-256 is (§5.2), the length big-endian.
    pub fn finish(mut self) -> [u8; 32] {
        let v = &mut self.v;
        self.blocks.finish(8, true, |b| sm3_block(v, b));
        let mut out = [0u8; 32];
        for (i, w) in self.v.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }
}

/// The compression function (§5.3).
fn sm3_block(v: &mut [u32; 8], block: &[u8; 64]) {
    let p0 = |x: u32| x ^ x.rotate_left(9) ^ x.rotate_left(17);
    let p1 = |x: u32| x ^ x.rotate_left(15) ^ x.rotate_left(23);
    let mut w = [0u32; 68];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for j in 16..68 {
        w[j] = p1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15)) ^ w[j - 13].rotate_left(7) ^ w[j - 6];
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *v;
    for j in 0..64 {
        let t: u32 = if j < 16 { 0x79cc4519 } else { 0x7a879d8a };
        let ss1 = a.rotate_left(12).wrapping_add(e).wrapping_add(t.rotate_left(j as u32 % 32)).rotate_left(7);
        let ss2 = ss1 ^ a.rotate_left(12);
        let (ff, gg) = if j < 16 { (a ^ b ^ c, e ^ f ^ g) } else { ((a & b) | (a & c) | (b & c), (e & f) | (!e & g)) };
        let tt1 = ff.wrapping_add(d).wrapping_add(ss2).wrapping_add(w[j] ^ w[j + 4]);
        let tt2 = gg.wrapping_add(h).wrapping_add(ss1).wrapping_add(w[j]);
        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
    }
    for (x, n) in v.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *x ^= n;
    }
}

pub fn sm3(data: &[u8]) -> [u8; 32] {
    let mut s = Sm3::new();
    s.update(data);
    s.finish()
}

// --- SHA-3 ---------------------------------------------------------------

/// Streaming SHA3-224, -256, -384 or -512 (FIPS 202): Keccak-f[1600] as
/// a sponge, rate 200 minus twice the digest's bytes.
#[derive(Clone, Debug)]
pub struct Sha3 {
    a: [u64; 25],
    buf: [u8; 144],
    len: usize,
    rate: usize,
    out: usize,
}

impl Sha3 {
    /// A hasher for `out` bytes of digest: 28, 32, 48 or 64.
    pub fn new(out: usize) -> Self {
        assert!(matches!(out, 28 | 32 | 48 | 64));
        Sha3 { a: [0; 25], buf: [0; 144], len: 0, rate: 200 - 2 * out, out }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let n = data.len().min(self.rate - self.len);
            self.buf[self.len..self.len + n].copy_from_slice(&data[..n]);
            self.len += n;
            data = &data[n..];
            if self.len == self.rate {
                self.absorb();
            }
        }
    }

    fn absorb(&mut self) {
        for i in 0..self.rate / 8 {
            self.a[i] ^= u64::from_le_bytes(self.buf[i * 8..i * 8 + 8].try_into().unwrap());
        }
        keccak_f(&mut self.a);
        self.len = 0;
    }

    /// The digest: SHA-3's domain bits (01), then pad10*1 (FIPS 202 §6.1,
    /// §5.1).
    pub fn finish(mut self) -> alloc::vec::Vec<u8> {
        self.buf[self.len..self.rate].fill(0);
        self.buf[self.len] ^= 0x06;
        self.buf[self.rate - 1] ^= 0x80;
        self.absorb();
        let mut out = alloc::vec::Vec::with_capacity(self.out);
        for w in &self.a[..self.out.div_ceil(8)] {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out.truncate(self.out);
        out
    }
}

/// Keccak-f[1600] (FIPS 202 §3.3, §3.4): 24 rounds of θ, ρ, π, χ and ι;
/// lane (x, y) is `a[x + 5y]`.
fn keccak_f(a: &mut [u64; 25]) {
    const RC: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808A,
        0x8000000080008000,
        0x000000000000808B,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008A,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000A,
        0x000000008000808B,
        0x800000000000008B,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800A,
        0x800000008000000A,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];
    // ρ's offsets, [x][y] (§3.2.2's table).
    const R: [[u32; 5]; 5] =
        [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]];
    for rc in RC {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(R[x][y]);
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }
        a[0] ^= rc;
    }
}

/// SHA-3 of `data`, `out` bytes of digest (28, 32, 48 or 64).
pub fn sha3(data: &[u8], out: usize) -> alloc::vec::Vec<u8> {
    let mut s = Sha3::new(out);
    s.update(data);
    s.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS 180-4 examples ("abc" and the two-block messages) and RFC 1321
    // §A.5's test suite.
    #[test]
    fn known_answers() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(&md5(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890")),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
        assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            hex(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd\
             454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(
            hex(&sha512(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            )),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433a\
             c7d329eeb6dd26545e96e55b874be909"
        );
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hex(&sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(hex(&sha224(b"abc")), "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
        assert_eq!(
            hex(&sha384(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn crc32c_check_value() {
        // The check value for "123456789" (RFC 3720 §B.4, the CRC catalogue).
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn blake2b_and_sm3() {
        // RFC 7693 Appendix A: BLAKE2b-512("abc").
        assert_eq!(
            hex(&blake2b(b"abc", 64)),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
        assert_eq!(
            hex(&blake2b(b"", 64)),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
             d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
        // Streamed in pieces around the 128-byte blocks, and short digests.
        let data: std::vec::Vec<u8> = (0..1000u32).map(|i| (i * 13 % 251) as u8).collect();
        for split in [0, 1, 127, 128, 129, 256, 999] {
            let mut b = Blake2b::new(32);
            b.update(&data[..split]);
            b.update(&data[split..]);
            assert_eq!(b.finish(), blake2b(&data, 32), "split {split}");
        }
        // FIPS 202's examples (NIST's published vectors).
        assert_eq!(hex(&sha3(b"", 32)), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        assert_eq!(hex(&sha3(b"abc", 32)), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
        assert_eq!(
            hex(&sha3(b"abc", 64)),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
             10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
        for split in [0, 1, 71, 72, 73, 135, 136, 137, 999] {
            let mut h = Sha3::new(48);
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finish(), sha3(&data, 48), "sha3 split {split}");
        }
        // The SM3 draft's examples: "abc", and "abcd" sixteen times.
        assert_eq!(hex(&sm3(b"abc")), "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
        assert_eq!(hex(&sm3(&b"abcd".repeat(16))), "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732");
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data: std::vec::Vec<u8> = (0..10_000u32).map(|i| (i * 7 % 251) as u8).collect();
        for split in [0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 1000, 9999] {
            let (a, b) = data.split_at(split);
            let mut m = Md5::new();
            m.update(a);
            m.update(b);
            assert_eq!(m.finish(), md5(&data), "md5 split {split}");
            let mut s = Sha256::new();
            s.update(a);
            s.update(b);
            assert_eq!(s.finish(), sha256(&data), "sha256 split {split}");
            let mut s = Sha512::new();
            s.update(a);
            s.update(b);
            assert_eq!(s.finish(), sha512(&data), "sha512 split {split}");
        }
        // Lengths around the padding boundaries agree with a byte-at-a-time feed.
        for len in 50..140 {
            let mut s = Sha512::new();
            data[..len].iter().for_each(|b| s.update(core::slice::from_ref(b)));
            assert_eq!(s.finish(), sha512(&data[..len]), "len {len}");
        }
    }
}
