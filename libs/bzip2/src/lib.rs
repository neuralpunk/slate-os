// SPDX-License-Identifier: MIT OR Apache-2.0

//! The bzip2 format, ours, from its public description (the format's
//! layout as documented for interoperability; no implementation's source
//! was consulted), and checked against the host's bzip2 both ways.
//!
//! A stream is `BZh` and a level digit (blocks of up to level × 100 000
//! bytes), blocks, then an end marker with the CRC of the blocks' CRCs;
//! bits go most significant first. Each block undoes, in order:
//!
//! 1. runs of 4 to 255 equal bytes, written as four bytes and a count;
//! 2. the Burrows–Wheeler transform (the block's rotations sorted; the
//!    last column is stored, with the row the original block is in);
//! 3. move-to-front over the bytes the block uses;
//! 4. zero runs, written as bijective base-2 numbers in RUNA and RUNB;
//! 5. Huffman codes, 2 to 6 tables, each group of 50 symbols choosing one
//!    (the choices move-to-front coded too).
//!
//! The CRC is CRC-32 with the polynomial 0x04C11DB7 taken most significant
//! bit first. Streams may follow one another (as parallel compressors
//! write them). Blocks in the old "randomised" form are refused.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec;
use alloc::vec::Vec;

pub use slate_flate::{Sink, SliceSource, Source};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not a bzip2 stream.
    NotBzip2,
    /// The data ended in the middle.
    Truncated,
    /// Something the format does not allow.
    Invalid,
    /// A block's CRC, or the stream's, does not match.
    Checksum,
    /// A block in the old randomised form.
    Randomised,
    /// The source or the sink failed.
    Io,
}

fn io(e: slate_flate::Error) -> Error {
    match e {
        slate_flate::Error::Io => Error::Io,
        _ => Error::Invalid,
    }
}

// --- CRC ---------------------------------------------------------------------

const fn crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = (n as u32) << 24;
        let mut k = 0;
        while k < 8 {
            c = if c & 0x8000_0000 != 0 { (c << 1) ^ 0x04C1_1DB7 } else { c << 1 };
            k += 1;
        }
        t[n] = c;
        n += 1;
    }
    t
}

static CRC: [u32; 256] = crc_table();

/// bzip2's CRC of `data`, continuing from `crc` (0 to start).
pub fn crc32(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    for &b in data {
        c = (c << 8) ^ CRC[((c >> 24) ^ u32::from(b)) as usize];
    }
    !c
}

// --- Bits, most significant first ----------------------------------------------

struct In<S: Source> {
    src: S,
    buf: Vec<u8>,
    pos: usize,
    len: usize,
    bit: u64,
    nbits: u32,
}

impl<S: Source> In<S> {
    fn new(src: S) -> In<S> {
        In { src, buf: vec![0; 64 * 1024], pos: 0, len: 0, bit: 0, nbits: 0 }
    }

    /// A byte from the source, None at its end.
    fn byte(&mut self) -> Result<Option<u8>, Error> {
        if self.pos == self.len {
            self.len = self.src.fill(&mut self.buf).map_err(io)?;
            self.pos = 0;
            if self.len == 0 {
                return Ok(None);
            }
        }
        self.pos += 1;
        Ok(Some(self.buf[self.pos - 1]))
    }

    fn bits(&mut self, n: u32) -> Result<u32, Error> {
        while self.nbits < n {
            let b = self.byte()?.ok_or(Error::Truncated)?;
            self.bit = (self.bit << 8) | u64::from(b);
            self.nbits += 8;
        }
        self.nbits -= n;
        Ok(((self.bit >> self.nbits) & ((1u64 << n) - 1)) as u32)
    }

    fn bit(&mut self) -> Result<u32, Error> {
        self.bits(1)
    }

    /// The next `n` bits without taking them, zeros past the end.
    fn peek(&mut self, n: u32) -> Result<u32, Error> {
        while self.nbits < n {
            match self.byte()? {
                Some(b) => {
                    self.bit = (self.bit << 8) | u64::from(b);
                    self.nbits += 8;
                }
                None => return Ok(((self.bit << (n - self.nbits)) & ((1u64 << n) - 1)) as u32),
            }
        }
        Ok(((self.bit >> (self.nbits - n)) & ((1u64 << n) - 1)) as u32)
    }

    fn skip(&mut self, n: u32) -> Result<(), Error> {
        if self.nbits < n {
            return Err(Error::Truncated);
        }
        self.nbits -= n;
        Ok(())
    }

    /// Drop the bits left in the current byte.
    fn align(&mut self) {
        self.nbits -= self.nbits % 8;
    }
}

struct Out {
    buf: Vec<u8>,
    bit: u64,
    nbits: u32,
}

impl Out {
    fn new() -> Out {
        Out { buf: Vec::new(), bit: 0, nbits: 0 }
    }

    fn put(&mut self, v: u32, n: u32) {
        self.bit = (self.bit << n) | u64::from(v & ((1u64 << n) - 1) as u32);
        self.nbits += n;
        while self.nbits >= 8 {
            self.nbits -= 8;
            self.buf.push((self.bit >> self.nbits) as u8);
        }
    }

    fn align(&mut self) {
        if self.nbits > 0 {
            let pad = 8 - self.nbits;
            self.put(0, pad);
        }
    }
}

const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
const END_MAGIC: u64 = 0x1772_4538_5090;
const GROUP: usize = 50;
const MAX_TABLES: usize = 6;
const MAX_CODE: u32 = 20;

// --- Decompression -------------------------------------------------------------

/// Codes this short decode with one table lookup.
const FAST: u32 = 10;

/// A canonical Huffman code read most significant bit first: a table for
/// short codes (symbol << 5 | length), and for each length the largest
/// code of that length and where its symbols start.
struct Decoder {
    fast: Vec<u16>,
    min: u32,
    max: u32,
    limit: [i32; 22],
    base: [i32; 22],
    perm: Vec<u16>,
}

impl Decoder {
    fn new(lengths: &[u8]) -> Result<Decoder, Error> {
        // An over-subscribed code is no code.
        let kraft: u64 = lengths.iter().map(|&l| 1u64 << (MAX_CODE - u32::from(l).min(MAX_CODE))).sum();
        if kraft > 1u64 << MAX_CODE {
            return Err(Error::Invalid);
        }
        let min = u32::from(*lengths.iter().min().ok_or(Error::Invalid)?);
        let max = u32::from(*lengths.iter().max().ok_or(Error::Invalid)?);
        let mut perm = Vec::with_capacity(lengths.len());
        for l in min..=max {
            for (s, &x) in lengths.iter().enumerate() {
                if u32::from(x) == l {
                    perm.push(s as u16);
                }
            }
        }
        let (mut limit, mut base) = ([-1i32; 22], [0i32; 22]);
        let mut code = 0i32;
        let mut index = 0i32;
        for l in min..=max {
            let count = lengths.iter().filter(|&&x| u32::from(x) == l).count() as i32;
            base[l as usize] = index - code;
            code += count;
            index += count;
            limit[l as usize] = code - 1;
            code <<= 1;
        }
        let mut fast = vec![0u16; 1 << FAST];
        let mut code = 0u32;
        let mut k = 0;
        for l in min..=max {
            for _ in lengths.iter().filter(|&&x| u32::from(x) == l) {
                if l <= FAST {
                    let first = (code << (FAST - l)) as usize;
                    let entry = (perm[k] << 5) | l as u16;
                    fast[first..first + (1 << (FAST - l))].fill(entry);
                }
                code += 1;
                k += 1;
            }
            code <<= 1;
        }
        Ok(Decoder { fast, min, max, limit, base, perm })
    }

    fn decode<S: Source>(&self, b: &mut In<S>) -> Result<u16, Error> {
        let e = self.fast[b.peek(FAST)? as usize];
        if e != 0 {
            b.skip(u32::from(e & 31))?;
            return Ok(e >> 5);
        }
        let mut len = self.min;
        let mut code = b.bits(len)? as i32;
        loop {
            if code <= self.limit[len as usize] {
                let i = (self.base[len as usize] + code) as usize;
                return self.perm.get(i).copied().ok_or(Error::Invalid);
            }
            len += 1;
            if len > self.max {
                return Err(Error::Invalid);
            }
            code = (code << 1) | b.bit()? as i32;
        }
    }
}

/// Read one block (after its magic): its CRC and its data, through the
/// first run-length step's undoing.
fn read_block<S: Source>(b: &mut In<S>, max_size: usize) -> Result<(u32, Vec<u8>), Error> {
    let crc = b.bits(32)?;
    if b.bit()? != 0 {
        return Err(Error::Randomised);
    }
    let orig = b.bits(24)? as usize;
    // The bytes used, in two levels of 16.
    let ranges = b.bits(16)?;
    let mut used = Vec::new();
    for r in 0..16 {
        if ranges & (0x8000 >> r) != 0 {
            let bits = b.bits(16)?;
            for k in 0..16 {
                if bits & (0x8000 >> k) != 0 {
                    used.push((r * 16 + k) as u8);
                }
            }
        }
    }
    if used.is_empty() {
        return Err(Error::Invalid);
    }
    let alpha = used.len() + 2;
    let ntables = b.bits(3)? as usize;
    if !(2..=MAX_TABLES).contains(&ntables) {
        return Err(Error::Invalid);
    }
    let nsel = b.bits(15)? as usize;
    if nsel == 0 {
        return Err(Error::Invalid);
    }
    let mut mtf: Vec<u8> = (0..ntables as u8).collect();
    let mut selectors = Vec::with_capacity(nsel);
    for _ in 0..nsel {
        let mut j = 0;
        while b.bit()? == 1 {
            j += 1;
            if j >= ntables {
                return Err(Error::Invalid);
            }
        }
        let t = mtf.remove(j);
        mtf.insert(0, t);
        selectors.push(t);
    }
    let mut tables = Vec::with_capacity(ntables);
    for _ in 0..ntables {
        let mut len = b.bits(5)? as i32;
        let mut lengths = vec![0u8; alpha];
        for l in lengths.iter_mut() {
            loop {
                if !(1..=MAX_CODE as i32).contains(&len) {
                    return Err(Error::Invalid);
                }
                if b.bit()? == 0 {
                    break;
                }
                if b.bit()? == 0 {
                    len += 1;
                } else {
                    len -= 1;
                }
            }
            *l = len as u8;
        }
        tables.push(Decoder::new(&lengths)?);
    }
    // Symbols: zero runs, move-to-front, the end of block.
    let eob = (alpha - 1) as u16;
    let mut order: Vec<u8> = used.clone();
    let mut last: Vec<u8> = Vec::with_capacity(max_size);
    let mut run = 0usize;
    let mut run_bit = 0u32;
    let mut sym_count = 0usize;
    loop {
        let sel = *selectors.get(sym_count / GROUP).ok_or(Error::Invalid)?;
        let s = tables[usize::from(sel)].decode(b)?;
        sym_count += 1;
        if s <= 1 {
            run += (usize::from(s) + 1) << run_bit;
            run_bit += 1;
            if run > max_size {
                return Err(Error::Invalid);
            }
            continue;
        }
        if run > 0 {
            if last.len() + run > max_size {
                return Err(Error::Invalid);
            }
            let c = order[0];
            last.resize(last.len() + run, c);
            run = 0;
            run_bit = 0;
        }
        if s == eob {
            break;
        }
        let i = usize::from(s - 1);
        if i >= order.len() || last.len() >= max_size {
            return Err(Error::Invalid);
        }
        let c = to_front(&mut order, i);
        last.push(c);
    }
    if orig >= last.len().max(1) {
        return Err(Error::Invalid);
    }
    // The inverse transform: next pointers from the byte counts.
    let n = last.len();
    let mut count = [0usize; 256];
    for &c in &last {
        count[usize::from(c)] += 1;
    }
    let mut start = [0usize; 256];
    let mut sum = 0;
    for (s, c) in start.iter_mut().zip(count) {
        *s = sum;
        sum += c;
    }
    let mut next = vec![0u32; n];
    for (i, &c) in last.iter().enumerate() {
        next[start[usize::from(c)]] = i as u32;
        start[usize::from(c)] += 1;
    }
    let mut out = Vec::with_capacity(n + n / 4);
    let mut pos = next[orig] as usize;
    // Undo the first run-length step as the bytes come out.
    let (mut prev, mut same) = (-1i32, 0);
    for _ in 0..n {
        let c = last[pos];
        pos = next[pos] as usize;
        if same == 4 {
            let p = prev as u8;
            out.resize(out.len() + usize::from(c), p);
            same = 0;
            prev = -1;
            continue;
        }
        if i32::from(c) == prev {
            same += 1;
        } else {
            prev = i32::from(c);
            same = 1;
        }
        out.push(c);
    }
    Ok((crc, out))
}

/// Move `order[i]` to the front, the ones before it one place on; the
/// byte moved. (Positions are mostly small: a plain loop beats memmove.)
fn to_front(order: &mut [u8], i: usize) -> u8 {
    let c = order[i];
    let mut j = i;
    while j >= 4 {
        order[j] = order[j - 1];
        order[j - 1] = order[j - 2];
        order[j - 2] = order[j - 3];
        order[j - 3] = order[j - 4];
        j -= 4;
    }
    while j > 0 {
        order[j] = order[j - 1];
        j -= 1;
    }
    order[0] = c;
    c
}

/// What a bzip2 stream held.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Decompressed {
    pub size: u64,
    pub streams: u32,
}

/// Decompress every stream from `src` into `sink`.
pub fn decompress_stream<S: Source, K: Sink>(src: S, sink: &mut K) -> Result<Decompressed, Error> {
    let mut b = In::new(src);
    let mut result = Decompressed::default();
    loop {
        // A stream's header, or the end (zero padding allowed after one).
        let Some(m) = b.byte()? else {
            return if result.streams == 0 { Err(Error::NotBzip2) } else { Ok(result) };
        };
        if result.streams > 0 && m == 0 {
            while let Some(z) = b.byte()? {
                if z != 0 {
                    return Err(Error::Invalid);
                }
            }
            return Ok(result);
        }
        let z = b.byte()?;
        let h = b.byte()?;
        let level = b.byte()?;
        let (Some(b'Z'), Some(b'h'), Some(l @ b'1'..=b'9')) = (z, h, level) else {
            return Err(if result.streams == 0 { Error::NotBzip2 } else { Error::Invalid });
        };
        if m != b'B' {
            return Err(if result.streams == 0 { Error::NotBzip2 } else { Error::Invalid });
        }
        let max = usize::from(l - b'0') * 100_000;
        let mut combined = 0u32;
        loop {
            let magic = (u64::from(b.bits(24)?) << 24) | u64::from(b.bits(24)?);
            if magic == END_MAGIC {
                let want = b.bits(32)?;
                if want != combined {
                    return Err(Error::Checksum);
                }
                b.align();
                break;
            }
            if magic != BLOCK_MAGIC {
                return Err(Error::Invalid);
            }
            let (crc, data) = read_block(&mut b, max)?;
            if crc32(0, &data) != crc {
                return Err(Error::Checksum);
            }
            combined = combined.rotate_left(1) ^ crc;
            sink.write(&data).map_err(io)?;
            result.size += data.len() as u64;
        }
        result.streams += 1;
    }
}

/// Decompress a whole bzip2 file in memory.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    decompress_stream(SliceSource::new(data), &mut out)?;
    Ok(out)
}

// --- Compression ---------------------------------------------------------------

/// The sorted order of `s`'s rotations (prefix doubling over cyclic
/// shifts, a counting sort a round).
fn sort_rotations(s: &[u8]) -> Vec<u32> {
    let n = s.len();
    let mut p = vec![0u32; n];
    let mut c = vec![0u32; n];
    let mut cnt = vec![0usize; 256.max(n)];
    for &x in s {
        cnt[usize::from(x)] += 1;
    }
    for i in 1..256 {
        cnt[i] += cnt[i - 1];
    }
    for i in (0..n).rev() {
        let x = usize::from(s[i]);
        cnt[x] -= 1;
        p[cnt[x]] = i as u32;
    }
    let mut classes = 1;
    c[p[0] as usize] = 0;
    for i in 1..n {
        if s[p[i] as usize] != s[p[i - 1] as usize] {
            classes += 1;
        }
        c[p[i] as usize] = classes - 1;
    }
    let mut pn = vec![0u32; n];
    let mut cn = vec![0u32; n];
    let mut h = 1usize;
    while h < n && (classes as usize) < n {
        for i in 0..n {
            let x = p[i] as usize;
            pn[i] = (if x >= h { x - h } else { x + n - h }) as u32;
        }
        cnt[..classes as usize].fill(0);
        for &x in &pn {
            cnt[c[x as usize] as usize] += 1;
        }
        for i in 1..classes as usize {
            cnt[i] += cnt[i - 1];
        }
        for i in (0..n).rev() {
            let k = c[pn[i] as usize] as usize;
            cnt[k] -= 1;
            p[cnt[k]] = pn[i];
        }
        cn[p[0] as usize] = 0;
        classes = 1;
        for i in 1..n {
            let (a, b) = (p[i] as usize, p[i - 1] as usize);
            let wrap = |x: usize| if x + h >= n { x + h - n } else { x + h };
            if c[a] != c[b] || c[wrap(a)] != c[wrap(b)] {
                classes += 1;
            }
            cn[a] = classes - 1;
        }
        core::mem::swap(&mut c, &mut cn);
        h <<= 1;
    }
    p
}

/// Code lengths for `freqs`, none over `limit`: Huffman's construction
/// on frequencies flattened until it fits (each round halves them).
fn lengths(freqs: &[u32], limit: u32) -> Vec<u8> {
    let mut f: Vec<u64> = freqs.iter().map(|&x| u64::from(x.max(1))).collect();
    loop {
        // Nodes: (weight, index); parents of leaves and merged nodes.
        let n = f.len();
        let mut weight: Vec<u64> = f.clone();
        let mut parent = vec![usize::MAX; n];
        let mut heap: Vec<(u64, usize)> = (0..n).map(|i| (f[i], i)).collect();
        heap.sort_unstable_by(|a, b| b.cmp(a));
        // A sorted list used as a priority queue (alphabets are small).
        while heap.len() > 1 {
            let a = heap.pop().unwrap_or((0, 0));
            let b = heap.pop().unwrap_or((0, 0));
            let id = weight.len();
            weight.push(a.0 + b.0);
            parent.push(usize::MAX);
            parent[a.1] = id;
            parent[b.1] = id;
            let item = (a.0 + b.0, id);
            let at = heap.partition_point(|x| *x > item);
            heap.insert(at, item);
        }
        let mut depth = vec![0u32; weight.len()];
        for k in (0..weight.len() - 1).rev() {
            depth[k] = depth[parent[k]] + 1;
        }
        let out: Vec<u8> = (0..n).map(|i| depth[i].max(1) as u8).collect();
        if out.iter().all(|&l| u32::from(l) <= limit) {
            return out;
        }
        for x in f.iter_mut() {
            *x = (*x >> 1) + 1;
        }
    }
}

/// Canonical codes for lengths, in the decoder's order.
fn codes(lengths: &[u8]) -> Vec<u32> {
    let min = lengths.iter().copied().min().unwrap_or(1);
    let max = lengths.iter().copied().max().unwrap_or(1);
    let mut out = vec![0u32; lengths.len()];
    let mut code = 0u32;
    for l in min..=max {
        for (s, &x) in lengths.iter().enumerate() {
            if x == l {
                out[s] = code;
                code += 1;
            }
        }
        code <<= 1;
    }
    out
}

/// Encode one block (after the first run-length step) into `o`; its CRC
/// is of the original bytes.
fn write_block(o: &mut Out, block: &[u8], crc: u32) {
    let n = block.len();
    let p = sort_rotations(block);
    let mut orig = 0;
    let mut last = Vec::with_capacity(n);
    for (i, &r) in p.iter().enumerate() {
        if r == 0 {
            orig = i;
        }
        last.push(block[(r as usize + n - 1) % n]);
    }
    // The bytes used, and move-to-front with zero runs.
    let mut in_use = [false; 256];
    for &c in &last {
        in_use[usize::from(c)] = true;
    }
    let used: Vec<u8> = (0..=255u8).filter(|&c| in_use[usize::from(c)]).collect();
    let alpha = used.len() + 2;
    let eob = (alpha - 1) as u16;
    let mut order = used.clone();
    let mut syms: Vec<u16> = Vec::with_capacity(n + 1);
    let mut run = 0usize;
    let flush = |syms: &mut Vec<u16>, run: &mut usize| {
        let mut r = *run;
        while r > 0 {
            if r & 1 == 1 {
                syms.push(0);
                r = (r - 1) / 2;
            } else {
                syms.push(1);
                r = (r - 2) / 2;
            }
        }
        *run = 0;
    };
    for &c in &last {
        let i = order.iter().position(|&x| x == c).unwrap_or(0);
        if i == 0 {
            run += 1;
            continue;
        }
        flush(&mut syms, &mut run);
        to_front(&mut order, i);
        syms.push(i as u16 + 1);
    }
    flush(&mut syms, &mut run);
    syms.push(eob);
    // Tables: as many as the symbol count warrants, refined a few times.
    let ntables = match syms.len() {
        0..200 => 2,
        200..600 => 3,
        600..1200 => 4,
        1200..2400 => 5,
        _ => 6,
    };
    let groups = syms.len().div_ceil(GROUP);
    let mut freq = vec![0u32; alpha];
    for &s in &syms {
        freq[usize::from(s)] += 1;
    }
    // A first guess: each table covers a slice of the alphabet holding
    // about an equal share of the symbols.
    let mut tables: Vec<Vec<u8>> = Vec::new();
    let total: u32 = freq.iter().sum();
    let mut lo = 0;
    for t in 0..ntables {
        let share = total * (t as u32 + 1) / ntables as u32 - total * t as u32 / ntables as u32;
        let mut hi = lo;
        let mut acc = 0;
        while hi < alpha && (acc < share || hi == lo) {
            acc += freq[hi];
            hi += 1;
        }
        if t + 1 == ntables {
            hi = alpha;
        }
        let lens: Vec<u8> = (0..alpha).map(|s| if (lo..hi).contains(&s) { 0 } else { 15 }).collect();
        tables.push(lens);
        lo = hi;
    }
    let mut selectors = vec![0u8; groups];
    for _ in 0..4 {
        let mut tf = vec![vec![0u32; alpha]; ntables];
        for (g, sel) in selectors.iter_mut().enumerate() {
            let group = &syms[g * GROUP..((g + 1) * GROUP).min(syms.len())];
            let best = (0..ntables)
                .min_by_key(|&t| group.iter().map(|&s| u32::from(tables[t][usize::from(s)])).sum::<u32>())
                .unwrap_or(0);
            *sel = best as u8;
            for &s in group {
                tf[best][usize::from(s)] += 1;
            }
        }
        for t in 0..ntables {
            tables[t] = lengths(&tf[t], 17);
        }
    }
    let table_codes: Vec<Vec<u32>> = tables.iter().map(|l| codes(l)).collect();
    // The block.
    o.put((BLOCK_MAGIC >> 24) as u32, 24);
    o.put(BLOCK_MAGIC as u32 & 0xFF_FFFF, 24);
    o.put(crc, 32);
    o.put(0, 1);
    o.put(orig as u32, 24);
    let mut ranges = 0u32;
    for r in 0..16 {
        if (0..16).any(|k| in_use[r * 16 + k]) {
            ranges |= 0x8000 >> r;
        }
    }
    o.put(ranges, 16);
    for r in 0..16 {
        if ranges & (0x8000 >> r) != 0 {
            let mut bits = 0;
            for k in 0..16 {
                if in_use[r * 16 + k] {
                    bits |= 0x8000 >> k;
                }
            }
            o.put(bits, 16);
        }
    }
    o.put(ntables as u32, 3);
    o.put(groups as u32, 15);
    let mut mtf: Vec<u8> = (0..ntables as u8).collect();
    for &s in &selectors {
        let j = mtf.iter().position(|&x| x == s).unwrap_or(0);
        for _ in 0..j {
            o.put(1, 1);
        }
        o.put(0, 1);
        mtf.remove(j);
        mtf.insert(0, s);
    }
    for t in &tables {
        let mut cur = u32::from(t[0]);
        o.put(cur, 5);
        for &l in t {
            let l = u32::from(l);
            while cur < l {
                o.put(0b10, 2);
                cur += 1;
            }
            while cur > l {
                o.put(0b11, 2);
                cur -= 1;
            }
            o.put(0, 1);
        }
    }
    for (g, &sel) in selectors.iter().enumerate() {
        let (lens, cs) = (&tables[usize::from(sel)], &table_codes[usize::from(sel)]);
        for &s in &syms[g * GROUP..((g + 1) * GROUP).min(syms.len())] {
            o.put(cs[usize::from(s)], u32::from(lens[usize::from(s)]));
        }
    }
}

/// A bzip2 compressor fed in pieces.
#[derive(Debug)]
pub struct Compressor {
    /// The block being filled, after the first run-length step.
    block: Vec<u8>,
    /// The CRC of the original bytes in it.
    crc: u32,
    combined: u32,
    max: usize,
    /// A run being counted: its byte and length.
    run: Option<(u8, usize)>,
    out: Out,
    started: bool,
    level: u8,
}

impl core::fmt::Debug for Out {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Out").field("bytes", &self.buf.len()).finish()
    }
}

impl Compressor {
    /// Blocks of `level` × 100 000 bytes (1 to 9).
    pub fn new(level: u8) -> Compressor {
        let level = level.clamp(1, 9);
        Compressor {
            block: Vec::new(),
            crc: 0,
            combined: 0,
            // Room for a run's five bytes at the end.
            max: usize::from(level) * 100_000 - 19,
            run: None,
            out: Out::new(),
            started: false,
            level,
        }
    }

    fn header(&mut self) {
        if !self.started {
            self.started = true;
            self.out.buf.extend_from_slice(&[b'B', b'Z', b'h', b'0' + self.level]);
        }
    }

    /// Write a run into the block (four bytes and a count past four).
    fn put_run(&mut self, c: u8, len: usize) {
        let k = len.min(4);
        self.block.extend(core::iter::repeat_n(c, k));
        if len >= 4 {
            self.block.push((len - 4) as u8);
        }
    }

    fn end_block(&mut self) {
        if let Some((c, len)) = self.run.take() {
            self.put_run(c, len);
        }
        if self.block.is_empty() {
            return;
        }
        let block = core::mem::take(&mut self.block);
        write_block(&mut self.out, &block, self.crc);
        self.combined = self.combined.rotate_left(1) ^ self.crc;
        self.crc = 0;
    }

    /// Compress `data`; whole bytes ready go to `out`.
    pub fn write(&mut self, data: &[u8], out: &mut Vec<u8>) {
        self.header();
        for &b in data {
            // A full block ends before the byte that would overflow it.
            if self.block.len() >= self.max {
                self.end_block();
            }
            self.crc = crc_byte(self.crc, b);
            match self.run {
                Some((c, len)) if c == b && len < 255 => self.run = Some((c, len + 1)),
                Some((c, len)) => {
                    self.put_run(c, len);
                    self.run = Some((b, 1));
                }
                None => self.run = Some((b, 1)),
            }
        }
        out.append(&mut self.out.buf);
    }

    /// End the stream.
    pub fn finish(mut self, out: &mut Vec<u8>) {
        self.header();
        self.end_block();
        self.out.put((END_MAGIC >> 24) as u32, 24);
        self.out.put(END_MAGIC as u32 & 0xFF_FFFF, 24);
        self.out.put(self.combined, 32);
        self.out.align();
        out.append(&mut self.out.buf);
    }
}

fn crc_byte(crc: u32, b: u8) -> u32 {
    let c = !crc;
    !((c << 8) ^ CRC[((c >> 24) ^ u32::from(b)) as usize])
}

/// Compress `data` at `level`.
pub fn compress(data: &[u8], level: u8) -> Vec<u8> {
    let mut c = Compressor::new(level);
    let mut out = Vec::new();
    c.write(data, &mut out);
    c.finish(&mut out);
    out
}

#[cfg(test)]
mod tests;
