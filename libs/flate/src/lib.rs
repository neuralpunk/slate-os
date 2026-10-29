// SPDX-License-Identifier: MIT OR Apache-2.0

//! DEFLATE (RFC 1951) and gzip (RFC 1952), ours.
//!
//! - Inflating reads all three block types (stored, fixed and dynamic
//!   Huffman codes) through a lookup table, from a [`Source`] into a
//!   [`Sink`] with only the 32 KiB window in memory ([`inflate_stream`]),
//!   or from and into memory ([`inflate`], [`inflate_raw_limited`]).
//! - [`Deflater`] compresses as it is fed: LZ77 over a 32 KiB window
//!   (hash chains, lazy matching as the level asks), each block in
//!   whichever of stored, fixed or dynamic Huffman codes is smallest,
//!   the dynamic codes limited to 15 bits. Levels 1 to 9 trade time for
//!   size as gzip's do.
//! - [`gunzip_stream`] reads every member of a gzip stream, checking each
//!   one's CRC-32 and length; [`GzipWriter`] writes one member.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec;
use alloc::vec::Vec;

/// What went wrong reading compressed data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The data ended in the middle.
    Truncated,
    /// A block type, code or distance the format does not allow.
    Invalid,
    /// Not a gzip stream (wrong magic or method).
    NotGzip,
    /// A member's CRC-32 or length does not match its data.
    Checksum,
    /// The data inflates to more than the limit it was given.
    TooLarge,
    /// The source or the sink failed (its own error was kept by it).
    Io,
}

/// Where compressed input comes from: `fill` reads some bytes into
/// `buf`, 0 at the end.
pub trait Source {
    fn fill(&mut self, buf: &mut [u8]) -> Result<usize, Error>;
}

/// Where output goes.
pub trait Sink {
    fn write(&mut self, data: &[u8]) -> Result<(), Error>;
}

impl Sink for Vec<u8> {
    fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.extend_from_slice(data);
        Ok(())
    }
}

/// A source over bytes in memory.
#[derive(Debug)]
pub struct SliceSource<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SliceSource<'a> {
    pub fn new(data: &'a [u8]) -> SliceSource<'a> {
        SliceSource { data, pos: 0 }
    }
}

impl Source for SliceSource<'_> {
    fn fill(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let n = buf.len().min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

// --- CRC-32 (ISO 3309, as RFC 1952 §8 computes it) ----------------------

const fn crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[n] = c;
        n += 1;
    }
    t
}

/// Eight tables for taking eight bytes a step ("slicing by eight"):
/// table k gives a byte's CRC after k more zero bytes.
const fn crc_tables() -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    t[0] = crc_table();
    let mut k = 1;
    while k < 8 {
        let mut n = 0;
        while n < 256 {
            let prev = t[k - 1][n];
            t[k][n] = (prev >> 8) ^ t[0][(prev & 0xFF) as usize];
            n += 1;
        }
        k += 1;
    }
    t
}

static CRC_TABLES: [[u32; 256]; 8] = crc_tables();

/// CRC-32 of `data`, continuing from `crc` (0 to start).
pub fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    let t = &CRC_TABLES;
    let mut c = !crc;
    let (words, rest) = data.as_chunks::<8>();
    for w in words {
        let lo = c ^ u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        c = t[7][(lo & 0xFF) as usize]
            ^ t[6][((lo >> 8) & 0xFF) as usize]
            ^ t[5][((lo >> 16) & 0xFF) as usize]
            ^ t[4][(lo >> 24) as usize]
            ^ t[3][usize::from(w[4])]
            ^ t[2][usize::from(w[5])]
            ^ t[1][usize::from(w[6])]
            ^ t[0][usize::from(w[7])];
    }
    for &b in rest {
        c = t[0][((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

pub fn crc32(data: &[u8]) -> u32 {
    crc32_update(0, data)
}

// --- Reading bits ----------------------------------------------------------

/// A source read a buffer at a time, bits least significant first (RFC
/// 1951 §3.1.1).
#[derive(Debug)]
pub struct Input<S: Source> {
    src: S,
    buf: Vec<u8>,
    pos: usize,
    len: usize,
    eof: bool,
    bit: u64,
    nbits: u32,
    /// Bytes taken from the buffer so far (for what a stream used).
    taken: u64,
}

impl<S: Source> Input<S> {
    pub fn new(src: S) -> Input<S> {
        Input { src, buf: vec![0; 64 * 1024], pos: 0, len: 0, eof: false, bit: 0, nbits: 0, taken: 0 }
    }

    /// The next byte from the buffer or the source, None at the end.
    fn next_byte(&mut self) -> Result<Option<u8>, Error> {
        if self.pos == self.len {
            if self.eof {
                return Ok(None);
            }
            self.len = self.src.fill(&mut self.buf)?;
            self.pos = 0;
            if self.len == 0 {
                self.eof = true;
                return Ok(None);
            }
        }
        self.pos += 1;
        self.taken += 1;
        Ok(Some(self.buf[self.pos - 1]))
    }

    /// Have at least `n` bits (up to 56) if the input has them.
    fn want(&mut self, n: u32) -> Result<(), Error> {
        if self.nbits >= n {
            return Ok(());
        }
        // Whole bytes straight from the buffer while they last.
        while self.nbits <= 56 && self.pos < self.len {
            self.bit |= u64::from(self.buf[self.pos]) << self.nbits;
            self.pos += 1;
            self.taken += 1;
            self.nbits += 8;
        }
        while self.nbits < n {
            match self.next_byte()? {
                Some(b) => {
                    self.bit |= u64::from(b) << self.nbits;
                    self.nbits += 8;
                }
                None => return Ok(()),
            }
        }
        Ok(())
    }

    fn bits(&mut self, n: u32) -> Result<u32, Error> {
        if n == 0 {
            return Ok(0);
        }
        self.want(n)?;
        if self.nbits < n {
            return Err(Error::Truncated);
        }
        let v = (self.bit & ((1u64 << n) - 1)) as u32;
        self.bit >>= n;
        self.nbits -= n;
        Ok(v)
    }

    /// Drop to a byte boundary.
    fn align(&mut self) {
        let drop = self.nbits % 8;
        self.bit >>= drop;
        self.nbits -= drop;
    }

    /// A whole byte (after [`align`](Self::align)).
    pub fn byte(&mut self) -> Result<Option<u8>, Error> {
        self.align();
        if self.nbits >= 8 {
            let b = self.bit as u8;
            self.bit >>= 8;
            self.nbits -= 8;
            return Ok(Some(b));
        }
        self.next_byte()
    }

    /// Bytes of input used so far.
    pub fn used(&self) -> u64 {
        self.taken - u64::from(self.nbits / 8)
    }
}

// --- Huffman decoding --------------------------------------------------------

/// Codes up to this many bits are decoded with one table lookup.
const FAST_BITS: u32 = 10;

/// A canonical Huffman code (RFC 1951 §3.2.2): a lookup table for short
/// codes (symbol << 4 | length; 0 for none), and counts and symbols in
/// code order for the long ones.
struct Huffman {
    fast: Vec<u16>,
    counts: [u16; 16],
    symbols: Vec<u16>,
}

fn reverse(code: u32, len: u32) -> u32 {
    code.reverse_bits() >> (32 - len)
}

impl Huffman {
    fn new(lengths: &[u8]) -> Result<Huffman, Error> {
        let mut counts = [0u16; 16];
        for &l in lengths {
            counts[usize::from(l)] += 1;
        }
        counts[0] = 0;
        // Over-subscribed codes are invalid; incomplete ones are allowed
        // (a code with one symbol).
        let mut left = 1i32;
        for c in &counts[1..] {
            left = (left << 1) - i32::from(*c);
            if left < 0 {
                return Err(Error::Invalid);
            }
        }
        let mut offs = [0u16; 16];
        for i in 1..15 {
            offs[i + 1] = offs[i] + counts[i];
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (s, &l) in lengths.iter().enumerate() {
            if l != 0 {
                symbols[usize::from(offs[usize::from(l)])] = s as u16;
                offs[usize::from(l)] += 1;
            }
        }
        // The fast table: each short code, bit-reversed, at every index
        // whose low bits it is.
        let mut fast = vec![0u16; 1 << FAST_BITS];
        let mut code = 0u32;
        let mut k = 0usize;
        for len in 1..=15u32 {
            for _ in 0..counts[len as usize] {
                if len <= FAST_BITS {
                    let r = reverse(code, len);
                    let entry = (symbols[k] << 4) | len as u16;
                    let mut i = r;
                    while i < 1 << FAST_BITS {
                        fast[i as usize] = entry;
                        i += 1 << len;
                    }
                }
                code += 1;
                k += 1;
            }
            code <<= 1;
        }
        Ok(Huffman { fast, counts, symbols })
    }

    fn decode<S: Source>(&self, b: &mut Input<S>) -> Result<u16, Error> {
        b.want(FAST_BITS)?;
        let e = self.fast[(b.bit & ((1 << FAST_BITS) - 1)) as usize];
        if e != 0 {
            let len = u32::from(e & 15);
            if b.nbits < len {
                return Err(Error::Truncated);
            }
            b.bit >>= len;
            b.nbits -= len;
            return Ok(e >> 4);
        }
        // A long code: bit by bit.
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..16 {
            code |= b.bits(1)? as i32;
            let count = i32::from(self.counts[len]);
            if code - count < first {
                return Ok(self.symbols[(index + (code - first)) as usize]);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err(Error::Invalid)
    }
}

// Lengths and distances: base values and extra bits (RFC 1951 §3.2.5).
const LEN_BASE: [u16; 29] =
    [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] =
    [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
/// The order code length code lengths come in (§3.2.7).
const CL_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

fn fixed_lengths() -> ([u8; 288], [u8; 30]) {
    let mut l = [0u8; 288];
    l[..144].fill(8);
    l[144..256].fill(9);
    l[256..280].fill(7);
    l[280..].fill(8);
    (l, [5u8; 30])
}

fn fixed_codes() -> Result<(Huffman, Huffman), Error> {
    let (l, d) = fixed_lengths();
    Ok((Huffman::new(&l)?, Huffman::new(&d)?))
}

fn dynamic_codes<S: Source>(b: &mut Input<S>) -> Result<(Huffman, Huffman), Error> {
    let hlit = b.bits(5)? as usize + 257;
    let hdist = b.bits(5)? as usize + 1;
    let hclen = b.bits(4)? as usize + 4;
    if hlit > 286 || hdist > 30 {
        return Err(Error::Invalid);
    }
    let mut cl = [0u8; 19];
    for &i in CL_ORDER.iter().take(hclen) {
        cl[i] = b.bits(3)? as u8;
    }
    let clh = Huffman::new(&cl)?;
    let mut lengths = vec![0u8; hlit + hdist];
    let mut i = 0;
    while i < lengths.len() {
        let sym = clh.decode(b)?;
        let (value, repeat) = match sym {
            0..=15 => (sym as u8, 1),
            16 => {
                let prev = *lengths.get(i.wrapping_sub(1)).ok_or(Error::Invalid)?;
                (prev, 3 + b.bits(2)? as usize)
            }
            17 => (0, 3 + b.bits(3)? as usize),
            _ => (0, 11 + b.bits(7)? as usize),
        };
        if i + repeat > lengths.len() {
            return Err(Error::Invalid);
        }
        lengths[i..i + repeat].fill(value);
        i += repeat;
    }
    if lengths[256] == 0 {
        return Err(Error::Invalid);
    }
    Ok((Huffman::new(&lengths[..hlit])?, Huffman::new(&lengths[hlit..])?))
}

// --- Inflate -------------------------------------------------------------

const WINDOW: usize = 32 * 1024;

/// Output with the window back-references reach: written to the sink in
/// pieces, the last 32 KiB kept.
struct Window<'k, K: Sink> {
    buf: Vec<u8>,
    sink: &'k mut K,
    /// Bytes written in all.
    total: u64,
    limit: u64,
    crc: Option<u32>,
}

impl<K: Sink> Window<'_, K> {
    fn flush_old(&mut self) -> Result<(), Error> {
        if self.buf.len() >= 4 * WINDOW {
            let n = self.buf.len() - WINDOW;
            self.emit(n)?;
        }
        Ok(())
    }

    /// Hand the first `n` bytes to the sink.
    fn emit(&mut self, n: usize) -> Result<(), Error> {
        if let Some(c) = self.crc.as_mut() {
            *c = crc32_update(*c, &self.buf[..n]);
        }
        self.sink.write(&self.buf[..n])?;
        self.buf.drain(..n);
        Ok(())
    }

    fn room(&self, n: usize) -> Result<(), Error> {
        if self.total + n as u64 > self.limit { Err(Error::TooLarge) } else { Ok(()) }
    }
}

/// Inflate one raw DEFLATE stream from `input` into `sink`, at most
/// `limit` bytes; returns the bytes written and (if asked) their CRC-32.
fn inflate_into<S: Source, K: Sink>(
    input: &mut Input<S>,
    sink: &mut K,
    limit: u64,
    want_crc: bool,
) -> Result<(u64, u32), Error> {
    let mut w = Window { buf: Vec::with_capacity(5 * WINDOW), sink, total: 0, limit, crc: want_crc.then_some(0) };
    loop {
        let last = input.bits(1)? == 1;
        match input.bits(2)? {
            0 => {
                input.align();
                let len = input.bits(16)? as usize;
                let nlen = input.bits(16)? as usize;
                if len != !nlen & 0xFFFF {
                    return Err(Error::Invalid);
                }
                w.room(len)?;
                for _ in 0..len {
                    let b = input.byte()?.ok_or(Error::Truncated)?;
                    w.buf.push(b);
                }
                w.total += len as u64;
                w.flush_old()?;
            }
            t @ (1 | 2) => {
                let (lit, dist) = if t == 1 { fixed_codes()? } else { dynamic_codes(input)? };
                loop {
                    let sym = lit.decode(input)?;
                    match sym {
                        0..=255 => {
                            w.room(1)?;
                            w.buf.push(sym as u8);
                            w.total += 1;
                        }
                        256 => break,
                        257..=285 => {
                            let i = usize::from(sym - 257);
                            let len = usize::from(LEN_BASE[i]) + input.bits(u32::from(LEN_EXTRA[i]))? as usize;
                            let d = usize::from(dist.decode(input)?);
                            if d >= 30 {
                                return Err(Error::Invalid);
                            }
                            let back = usize::from(DIST_BASE[d]) + input.bits(u32::from(DIST_EXTRA[d]))? as usize;
                            if back > w.buf.len() {
                                return Err(Error::Invalid);
                            }
                            w.room(len)?;
                            let from = w.buf.len() - back;
                            if back >= len {
                                w.buf.extend_from_within(from..from + len);
                            } else {
                                for k in 0..len {
                                    let c = w.buf[from + k];
                                    w.buf.push(c);
                                }
                            }
                            w.total += len as u64;
                        }
                        _ => return Err(Error::Invalid),
                    }
                    if w.buf.len() >= 4 * WINDOW {
                        w.flush_old()?;
                    }
                }
            }
            _ => return Err(Error::Invalid),
        }
        if last {
            let n = w.buf.len();
            w.emit(n)?;
            return Ok((w.total, w.crc.unwrap_or(0)));
        }
    }
}

/// Inflate a raw DEFLATE stream from `src` into `sink`; the bytes
/// written.
pub fn inflate_stream<S: Source, K: Sink>(src: S, sink: &mut K) -> Result<u64, Error> {
    let mut input = Input::new(src);
    inflate_into(&mut input, sink, u64::MAX, false).map(|r| r.0)
}

/// Inflate a raw DEFLATE stream; the data and how many input bytes it
/// used.
pub fn inflate_raw(data: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    inflate_raw_limited(data, usize::MAX)
}

/// [`inflate_raw`], failing with [`Error::TooLarge`] as soon as the
/// output would pass `limit` bytes (data not yet trusted cannot make the
/// reader use more memory than the limit).
pub fn inflate_raw_limited(data: &[u8], limit: usize) -> Result<(Vec<u8>, usize), Error> {
    let mut input = Input::new(SliceSource::new(data));
    let mut out = Vec::with_capacity(data.len().saturating_mul(3).min(limit).min(64 << 20));
    inflate_into(&mut input, &mut out, limit as u64, false)?;
    Ok((out, input.used() as usize))
}

pub fn inflate(data: &[u8]) -> Result<Vec<u8>, Error> {
    inflate_raw(data).map(|(d, _)| d)
}

// --- Writing bits ------------------------------------------------------------

/// Bits written least significant first.
#[derive(Debug)]
struct Bits {
    buf: Vec<u8>,
    bit: u64,
    nbits: u32,
}

impl Bits {
    fn put(&mut self, v: u32, n: u32) {
        self.bit |= u64::from(v) << self.nbits;
        self.nbits += n;
        while self.nbits >= 8 {
            self.buf.push(self.bit as u8);
            self.bit >>= 8;
            self.nbits -= 8;
        }
    }

    /// Pad to a byte boundary.
    fn align(&mut self) {
        if self.nbits > 0 {
            self.put(0, 8 - self.nbits);
        }
    }
}

// --- Huffman codes for writing -----------------------------------------------

/// Code lengths for `freqs`, none longer than `limit`: Huffman's
/// construction, then lengths over the limit cut down and the code
/// rebalanced (longer codes for the rarest symbols until Kraft's sum
/// fits). Symbols never used get no code; a lone symbol gets length 1.
fn code_lengths(freqs: &[u32], limit: u32) -> Vec<u8> {
    let mut lengths = vec![0u8; freqs.len()];
    let used: Vec<usize> = (0..freqs.len()).filter(|&i| freqs[i] > 0).collect();
    match used.len() {
        0 => return lengths,
        1 => {
            lengths[used[0]] = 1;
            return lengths;
        }
        _ => {}
    }
    // Nodes: leaves first, then merged ones; a sorted queue of each.
    let mut weight: Vec<u64> = used.iter().map(|&i| u64::from(freqs[i])).collect();
    let mut parent: Vec<usize> = vec![usize::MAX; used.len()];
    let mut leaves: Vec<usize> = (0..used.len()).collect();
    leaves.sort_by_key(|&i| (weight[i], i));
    let mut merged: Vec<usize> = Vec::new();
    let (mut li, mut mi) = (0, 0);
    let take = |weight: &Vec<u64>, merged: &Vec<usize>, li: &mut usize, mi: &mut usize| -> usize {
        let l = leaves.get(*li).copied();
        let m = merged.get(*mi).copied();
        match (l, m) {
            (Some(a), Some(b)) if weight[a] <= weight[b] => {
                *li += 1;
                a
            }
            (_, Some(b)) => {
                *mi += 1;
                b
            }
            (Some(a), None) => {
                *li += 1;
                a
            }
            (None, None) => usize::MAX,
        }
    };
    for _ in 0..used.len() - 1 {
        let a = take(&weight, &merged, &mut li, &mut mi);
        let b = take(&weight, &merged, &mut li, &mut mi);
        let n = weight.len();
        weight.push(weight[a] + weight[b]);
        parent.push(usize::MAX);
        parent[a] = n;
        parent[b] = n;
        merged.push(n);
    }
    let root = weight.len() - 1;
    let mut depth = vec![0u32; weight.len()];
    for n in (0..root).rev() {
        depth[n] = depth[parent[n]] + 1;
    }
    let mut lens: Vec<u32> = (0..used.len()).map(|k| depth[k]).collect();
    if lens.iter().any(|&l| l > limit) {
        for l in lens.iter_mut() {
            *l = (*l).min(limit);
        }
        // Kraft's sum in units of 2^-limit; lengthen the rarest symbols
        // whose codes can still grow until it is at most 1.
        let kraft = |lens: &[u32]| -> u64 { lens.iter().map(|&l| 1u64 << (limit - l)).sum() };
        let mut order: Vec<usize> = (0..used.len()).collect();
        order.sort_by_key(|&k| (freqs[used[k]], core::cmp::Reverse(k)));
        let mut sum = kraft(&lens);
        while sum > 1u64 << limit {
            let Some(&k) = order.iter().find(|&&k| lens[k] < limit) else { break };
            sum -= 1u64 << (limit - lens[k] - 1);
            lens[k] += 1;
        }
        // Room left over: shorten the commonest codes where it fits.
        for &k in order.iter().rev() {
            while lens[k] > 1 && sum + (1u64 << (limit - lens[k])) <= 1u64 << limit {
                sum += 1u64 << (limit - lens[k]);
                lens[k] -= 1;
            }
        }
    }
    for (k, &i) in used.iter().enumerate() {
        lengths[i] = lens[k] as u8;
    }
    lengths
}

/// Canonical codes for lengths (§3.2.2), bit-reversed for writing.
fn codes(lengths: &[u8]) -> Vec<u32> {
    let mut count = [0u32; 16];
    for &l in lengths {
        count[usize::from(l)] += 1;
    }
    count[0] = 0;
    let mut next = [0u32; 16];
    let mut code = 0;
    for b in 1..16 {
        code = (code + count[b - 1]) << 1;
        next[b] = code;
    }
    lengths
        .iter()
        .map(|&l| {
            if l == 0 {
                return 0;
            }
            let c = next[usize::from(l)];
            next[usize::from(l)] += 1;
            reverse(c, u32::from(l))
        })
        .collect()
}

// --- Deflate ---------------------------------------------------------------

/// A symbol of a block: a literal, or a match's length and distance.
#[derive(Clone, Copy, Debug)]
enum Sym {
    Lit(u8),
    Match(u16, u16),
}

fn len_index(len: usize) -> usize {
    LEN_BASE.iter().rposition(|&b| usize::from(b) <= len).unwrap_or(0)
}

fn dist_index(dist: usize) -> usize {
    DIST_BASE.iter().rposition(|&b| usize::from(b) <= dist).unwrap_or(0)
}

/// How hard a level looks for matches: chain length, the length that
/// ends the search, and whether to try the next position first.
fn level_params(level: u8) -> (usize, usize, bool) {
    match level {
        0 | 1 => (4, 8, false),
        2 => (8, 16, false),
        3 => (16, 32, false),
        4 => (16, 16, true),
        5 => (32, 32, true),
        6 => (128, 128, true),
        7 => (256, 128, true),
        8 => (1024, 258, true),
        _ => (4096, 258, true),
    }
}

const HASH_BITS: u32 = 15;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
/// Symbols per block before it is written.
const BLOCK_SYMS: usize = 16 * 1024;

fn hash3(d: &[u8], i: usize) -> usize {
    let v = (u32::from(d[i]) << 16) | (u32::from(d[i + 1]) << 8) | u32::from(d[i + 2]);
    (v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize
}

/// A DEFLATE compressor fed in pieces: `write` takes input and appends
/// what is ready to `out`; `finish` ends the stream.
#[derive(Debug)]
pub struct Deflater {
    level: u8,
    /// Input not yet dropped: the window before `pos` and what follows.
    data: Vec<u8>,
    /// The absolute offset of `data[0]`.
    base: usize,
    /// The absolute position compression has reached, and where the
    /// current block's input starts.
    pos: usize,
    block_start: usize,
    head: Vec<usize>,
    prev: Vec<usize>,
    syms: Vec<Sym>,
    out: Bits,
}

impl Deflater {
    /// A compressor at `level` (1 fastest, 9 smallest; 0 stores).
    pub fn new(level: u8) -> Deflater {
        Deflater {
            level: level.min(9),
            data: Vec::new(),
            base: 0,
            pos: 0,
            block_start: 0,
            head: vec![usize::MAX; 1 << HASH_BITS],
            prev: vec![usize::MAX; WINDOW],
            syms: Vec::new(),
            out: Bits { buf: Vec::new(), bit: 0, nbits: 0 },
        }
    }

    /// Compress `input`; whole bytes ready so far go to `out`.
    pub fn write(&mut self, input: &[u8], out: &mut Vec<u8>) {
        self.data.extend_from_slice(input);
        self.compress(false);
        out.append(&mut self.out.buf);
        // Keep the window before both the position and the block.
        let keep_from = self.pos.min(self.block_start).saturating_sub(WINDOW);
        if keep_from > self.base + 256 * 1024 {
            self.data.drain(..keep_from - self.base);
            self.base = keep_from;
        }
    }

    /// End the stream: the rest of the input and the final block.
    pub fn finish(mut self, out: &mut Vec<u8>) {
        self.compress(true);
        self.block(true);
        self.out.align();
        out.append(&mut self.out.buf);
    }

    fn at(&self, abs: usize) -> u8 {
        self.data[abs - self.base]
    }

    fn insert(&mut self, abs: usize) {
        let i = abs - self.base;
        if i + MIN_MATCH <= self.data.len() {
            let h = hash3(&self.data, i);
            self.prev[abs % WINDOW] = self.head[h];
            self.head[h] = abs;
        }
    }

    /// The longest match at `abs` (length, distance), looking at most
    /// `chain` candidates.
    fn longest(&self, abs: usize, chain: usize, nice: usize) -> (usize, usize) {
        let i = abs - self.base;
        let end = self.data.len();
        if i + MIN_MATCH > end {
            return (0, 0);
        }
        let max = (end - i).min(MAX_MATCH);
        let mut cand = self.head[hash3(&self.data, i)];
        let (mut best_len, mut best_dist) = (0, 0);
        let mut n = 0;
        while cand != usize::MAX && cand < abs && abs - cand <= WINDOW && cand >= self.base && n < chain {
            let c = cand - self.base;
            if self.data[c + best_len.min(max - 1)] == self.data[i + best_len.min(max - 1)] {
                let mut l = 0;
                while l < max && self.data[c + l] == self.data[i + l] {
                    l += 1;
                }
                if l > best_len {
                    (best_len, best_dist) = (l, abs - cand);
                    if l >= nice || l == max {
                        break;
                    }
                }
            }
            let next = self.prev[cand % WINDOW];
            if next == usize::MAX || next >= cand {
                break;
            }
            cand = next;
            n += 1;
        }
        if best_len >= MIN_MATCH { (best_len, best_dist) } else { (0, 0) }
    }

    /// Turn input into symbols, keeping `MAX_MATCH` bytes of lookahead
    /// unless this is the end.
    fn compress(&mut self, last: bool) {
        let end = self.base + self.data.len();
        let stop = if last { end } else { end.saturating_sub(MAX_MATCH + MIN_MATCH) };
        let (chain, nice, lazy) = level_params(self.level);
        if self.level == 0 {
            while self.pos < stop {
                let b = self.at(self.pos);
                self.syms.push(Sym::Lit(b));
                self.pos += 1;
                if self.syms.len() >= BLOCK_SYMS {
                    self.block(false);
                }
            }
            return;
        }
        while self.pos < stop {
            let (mut len, mut dist) = self.longest(self.pos, chain, nice);
            if lazy && len > 0 && len < nice && self.pos + 1 < stop {
                self.insert(self.pos);
                let (l2, d2) = self.longest(self.pos + 1, chain, nice);
                if l2 > len {
                    let b = self.at(self.pos);
                    self.syms.push(Sym::Lit(b));
                    self.pos += 1;
                    self.insert(self.pos);
                    (len, dist) = (l2, d2);
                }
                // The match's first position is in the chains already.
                self.syms.push(Sym::Match(len as u16, dist as u16));
                for k in 1..len {
                    self.insert(self.pos + k);
                }
                self.pos += len;
            } else if len > 0 {
                self.syms.push(Sym::Match(len as u16, dist as u16));
                for k in 0..len {
                    self.insert(self.pos + k);
                }
                self.pos += len;
            } else {
                let b = self.at(self.pos);
                self.syms.push(Sym::Lit(b));
                self.insert(self.pos);
                self.pos += 1;
            }
            if self.syms.len() >= BLOCK_SYMS {
                self.block(false);
            }
        }
    }

    /// Write the symbols gathered as one block, in the smallest of the
    /// three forms.
    fn block(&mut self, last: bool) {
        let syms = core::mem::take(&mut self.syms);
        let raw_start = self.block_start;
        let raw_end = self.pos;
        self.block_start = self.pos;
        let mut lf = vec![0u32; 286];
        let mut df = vec![0u32; 30];
        for s in &syms {
            match *s {
                Sym::Lit(b) => lf[usize::from(b)] += 1,
                Sym::Match(l, d) => {
                    lf[257 + len_index(usize::from(l))] += 1;
                    df[dist_index(usize::from(d))] += 1;
                }
            }
        }
        lf[256] = 1;
        // Dynamic codes and their header.
        let ll = code_lengths(&lf, 15);
        let mut dl = code_lengths(&df, 15);
        if dl.iter().all(|&l| l == 0) {
            dl[0] = 1;
        }
        let hlit = (257..=286).rev().find(|&n| ll[n - 1] != 0).unwrap_or(257).max(257);
        let hdist = (1..=30).rev().find(|&n| dl[n - 1] != 0).unwrap_or(1).max(1);
        let all: Vec<u8> = ll[..hlit].iter().chain(&dl[..hdist]).copied().collect();
        let rle = rle_lengths(&all);
        let mut cf = vec![0u32; 19];
        for &(s, _) in &rle {
            cf[usize::from(s)] += 1;
        }
        let cl = code_lengths(&cf, 7);
        let hclen = (4..=19).rev().find(|&n| cl[CL_ORDER[n - 1]] != 0).unwrap_or(4);
        let extra_bits = |s: u8| match s {
            16 => 2,
            17 => 3,
            18 => 7,
            _ => 0,
        };
        let body_bits = |ll: &[u8], dl: &[u8]| -> u64 {
            let mut n = 0u64;
            for (s, &f) in lf.iter().enumerate() {
                n += u64::from(f) * u64::from(ll[s]);
                if s >= 257 {
                    n += u64::from(f) * u64::from(LEN_EXTRA[s - 257]);
                }
            }
            for (d, &f) in df.iter().enumerate() {
                n += u64::from(f) * (u64::from(dl[d]) + u64::from(DIST_EXTRA[d]));
            }
            n
        };
        let dyn_bits = 17
            + 3 * hclen as u64
            + rle.iter().map(|&(s, _)| u64::from(cl[usize::from(s)]) + extra_bits(s)).sum::<u64>()
            + body_bits(&ll, &dl);
        let (fl, fd) = fixed_lengths();
        let fixed_bits = 3 + body_bits(&fl, &fd);
        let raw_len = raw_end - raw_start;
        let stored_ok = raw_start >= self.base;
        let stored_bits = (raw_len as u64 + 5 * raw_len.div_ceil(65535).max(1) as u64) * 8 + 8;
        let o = &mut self.out;
        if stored_ok && (self.level == 0 || stored_bits < dyn_bits.min(fixed_bits)) {
            let raw = &self.data[raw_start - self.base..raw_end - self.base];
            let pieces: Vec<&[u8]> = if raw.is_empty() { vec![&raw[..0]] } else { raw.chunks(65535).collect() };
            let n = pieces.len();
            for (i, piece) in pieces.into_iter().enumerate() {
                o.put(u32::from(last && i + 1 == n), 1);
                o.put(0, 2);
                o.align();
                o.put(piece.len() as u32, 16);
                o.put(!(piece.len() as u32) & 0xFFFF, 16);
                o.buf.extend_from_slice(piece);
            }
            return;
        }
        let (ll, dl) = if fixed_bits <= dyn_bits {
            o.put(u32::from(last), 1);
            o.put(1, 2);
            (fl.to_vec(), fd.to_vec())
        } else {
            o.put(u32::from(last), 1);
            o.put(2, 2);
            o.put((hlit - 257) as u32, 5);
            o.put((hdist - 1) as u32, 5);
            o.put((hclen - 4) as u32, 4);
            for &i in CL_ORDER.iter().take(hclen) {
                o.put(u32::from(cl[i]), 3);
            }
            let cc = codes(&cl);
            for &(s, extra) in &rle {
                o.put(cc[usize::from(s)], u32::from(cl[usize::from(s)]));
                o.put(u32::from(extra), extra_bits(s) as u32);
            }
            (ll, dl)
        };
        let lc = codes(&ll);
        let dc = codes(&dl);
        for s in &syms {
            match *s {
                Sym::Lit(b) => o.put(lc[usize::from(b)], u32::from(ll[usize::from(b)])),
                Sym::Match(l, d) => {
                    let (l, d) = (usize::from(l), usize::from(d));
                    let li = len_index(l);
                    o.put(lc[257 + li], u32::from(ll[257 + li]));
                    o.put((l - usize::from(LEN_BASE[li])) as u32, u32::from(LEN_EXTRA[li]));
                    let di = dist_index(d);
                    o.put(dc[di], u32::from(dl[di]));
                    o.put((d - usize::from(DIST_BASE[di])) as u32, u32::from(DIST_EXTRA[di]));
                }
            }
        }
        o.put(lc[256], u32::from(ll[256]));
    }
}

/// Code lengths run-length coded (§3.2.7): (symbol, extra bits' value).
fn rle_lengths(l: &[u8]) -> Vec<(u8, u8)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < l.len() {
        let v = l[i];
        let mut run = 1;
        while i + run < l.len() && l[i + run] == v {
            run += 1;
        }
        let mut left = run;
        if v == 0 {
            while left >= 11 {
                let n = left.min(138);
                out.push((18, (n - 11) as u8));
                left -= n;
            }
            if left >= 3 {
                out.push((17, (left - 3) as u8));
                left = 0;
            }
        } else {
            out.push((v, 0));
            left -= 1;
            while left >= 3 {
                let n = left.min(6);
                out.push((16, (n - 3) as u8));
                left -= n;
            }
        }
        for _ in 0..left {
            out.push((v, 0));
        }
        i += run;
    }
    out
}

/// Compress `data` into a raw DEFLATE stream at level 6.
pub fn deflate(data: &[u8]) -> Vec<u8> {
    deflate_level(data, 6)
}

/// Compress `data` at `level` (0 to 9).
pub fn deflate_level(data: &[u8], level: u8) -> Vec<u8> {
    let mut d = Deflater::new(level);
    let mut out = Vec::with_capacity(data.len() / 2 + 64);
    for chunk in data.chunks(1 << 20) {
        d.write(chunk, &mut out);
    }
    d.finish(&mut out);
    out
}

// --- gzip ---------------------------------------------------------------

const FTEXT_HCRC: u8 = 0x02;
const FEXTRA: u8 = 0x04;
const FNAME: u8 = 0x08;
const FCOMMENT: u8 = 0x10;

/// A gzip member's header facts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub name: Option<Vec<u8>>,
    pub mtime: u32,
}

/// What a gzip stream held.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Gunzipped {
    /// The first member's header.
    pub header: Header,
    /// Uncompressed bytes in all.
    pub size: u64,
    /// Bytes of input read.
    pub used: u64,
    /// The last member's header and trailer, in bytes.
    pub overhead: u64,
}

/// One member's header, after its two magic bytes; None at the end of
/// the stream (or of what is only zero padding).
fn member_header<S: Source>(input: &mut Input<S>, first: bool) -> Result<Option<Header>, Error> {
    let Some(a) = input.byte()? else {
        return if first { Err(Error::NotGzip) } else { Ok(None) };
    };
    let b = input.byte()?;
    if !first && a == 0 && b.is_none_or(|b| b == 0) {
        // Zero padding some tools add after the last member.
        while let Some(z) = input.byte()? {
            if z != 0 {
                return Err(Error::NotGzip);
            }
        }
        return Ok(None);
    }
    let Some(b) = b else {
        return Err(if first { Error::NotGzip } else { Error::Truncated });
    };
    let m = input.byte()?;
    if a != 0x1F || b != 0x8B || m != Some(8) {
        return Err(Error::NotGzip);
    }
    let mut rest = [0u8; 7];
    for r in rest.iter_mut() {
        *r = input.byte()?.ok_or(Error::Truncated)?;
    }
    let flags = rest[0];
    let mtime = u32::from_le_bytes([rest[1], rest[2], rest[3], rest[4]]);
    if flags & FEXTRA != 0 {
        let lo = input.byte()?.ok_or(Error::Truncated)?;
        let hi = input.byte()?.ok_or(Error::Truncated)?;
        for _ in 0..u16::from_le_bytes([lo, hi]) {
            input.byte()?.ok_or(Error::Truncated)?;
        }
    }
    let mut name = None;
    let zstring = |input: &mut Input<S>| -> Result<Vec<u8>, Error> {
        let mut s = Vec::new();
        loop {
            match input.byte()?.ok_or(Error::Truncated)? {
                0 => return Ok(s),
                c => s.push(c),
            }
        }
    };
    if flags & FNAME != 0 {
        name = Some(zstring(input)?);
    }
    if flags & FCOMMENT != 0 {
        zstring(input)?;
    }
    if flags & FTEXT_HCRC != 0 {
        input.byte()?.ok_or(Error::Truncated)?;
        input.byte()?.ok_or(Error::Truncated)?;
    }
    Ok(Some(Header { name, mtime }))
}

/// Decompress every member of a gzip stream (RFC 1952 §2.2) from `src`
/// into `sink`.
pub fn gunzip_stream<S: Source, K: Sink>(src: S, sink: &mut K) -> Result<Gunzipped, Error> {
    gunzip_limited(src, sink, u64::MAX)
}

fn gunzip_limited<S: Source, K: Sink>(src: S, sink: &mut K, limit: u64) -> Result<Gunzipped, Error> {
    let mut input = Input::new(src);
    let mut result: Option<Gunzipped> = None;
    let mut start = 0;
    while let Some(h) = member_header(&mut input, result.is_none())? {
        let header_len = input.used() - start;
        let left = limit - result.as_ref().map_or(0, |r| r.size);
        let (n, crc) = inflate_into(&mut input, sink, left, true)?;
        let mut tail = [0u8; 8];
        for t in tail.iter_mut() {
            *t = input.byte()?.ok_or(Error::Truncated)?;
        }
        let want_crc = u32::from_le_bytes([tail[0], tail[1], tail[2], tail[3]]);
        let want_size = u32::from_le_bytes([tail[4], tail[5], tail[6], tail[7]]);
        if want_crc != crc || want_size != n as u32 {
            return Err(Error::Checksum);
        }
        let r = result.get_or_insert(Gunzipped { header: h, size: 0, used: 0, overhead: 0 });
        r.size += n;
        r.overhead = header_len + 8;
        start = input.used();
    }
    let mut r = result.ok_or(Error::NotGzip)?;
    r.used = input.used();
    Ok(r)
}

/// Decompress every member of a gzip stream; the first member's header.
pub fn gunzip(data: &[u8]) -> Result<(Vec<u8>, Header), Error> {
    let mut out = Vec::with_capacity(data.len().saturating_mul(4).min(256 << 20));
    let g = gunzip_stream(SliceSource::new(data), &mut out)?;
    Ok((out, g.header))
}

/// [`gunzip`], failing with [`Error::TooLarge`] past `limit` bytes.
pub fn gunzip_limited_vec(data: &[u8], limit: usize) -> Result<(Vec<u8>, Header), Error> {
    let mut out = Vec::new();
    let g = gunzip_limited(SliceSource::new(data), &mut out, limit as u64)?;
    Ok((out, g.header))
}

/// A gzip member written as it is fed.
#[derive(Debug)]
pub struct GzipWriter {
    deflater: Deflater,
    crc: u32,
    size: u32,
    header: Option<Vec<u8>>,
}

impl GzipWriter {
    /// A member with `h`'s name and time (OS 3, Unix), at `level`.
    pub fn new(h: &Header, level: u8) -> GzipWriter {
        let xfl = match level {
            9 => 2,
            1 => 4,
            _ => 0,
        };
        let mut head = vec![0x1F, 0x8B, 8, if h.name.is_some() { FNAME } else { 0 }];
        head.extend_from_slice(&h.mtime.to_le_bytes());
        head.extend_from_slice(&[xfl, 3]);
        if let Some(n) = &h.name {
            head.extend_from_slice(n);
            head.push(0);
        }
        GzipWriter { deflater: Deflater::new(level), crc: 0, size: 0, header: Some(head) }
    }

    pub fn write(&mut self, data: &[u8], out: &mut Vec<u8>) {
        if let Some(h) = self.header.take() {
            out.extend_from_slice(&h);
        }
        self.crc = crc32_update(self.crc, data);
        self.size = self.size.wrapping_add(data.len() as u32);
        self.deflater.write(data, out);
    }

    pub fn finish(mut self, out: &mut Vec<u8>) {
        if let Some(h) = self.header.take() {
            out.extend_from_slice(&h);
        }
        self.deflater.finish(out);
        out.extend_from_slice(&self.crc.to_le_bytes());
        out.extend_from_slice(&self.size.to_le_bytes());
    }
}

/// One gzip member holding `data` (with its original name and time, if
/// given), at level 6.
pub fn gzip(data: &[u8], h: &Header) -> Vec<u8> {
    gzip_level(data, h, 6)
}

pub fn gzip_level(data: &[u8], h: &Header, level: u8) -> Vec<u8> {
    let mut w = GzipWriter::new(h, level);
    let mut out = Vec::with_capacity(data.len() / 2 + 64);
    for chunk in data.chunks(1 << 20) {
        w.write(chunk, &mut out);
    }
    w.finish(&mut out);
    out
}

#[cfg(test)]
mod tests;
