// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 8878's entropy coders: finite state entropy (FSE) tables, read
//! from their descriptions or the predefined distributions, and the
//! Huffman coding of literals; bit streams read backwards from their end
//! (after the final 1 bit) and written forwards to be read that way.

use alloc::vec;
use alloc::vec::Vec;

use crate::Error;

fn highbit(v: u32) -> u32 {
    31 - v.leading_zeros()
}

/// A bit stream read from its end towards its start, most recent bits
/// first; bits past the start read as zeros, and `overflowed` tells.
pub(crate) struct BitsBack<'a> {
    d: &'a [u8],
    pos: i64,
}

impl<'a> BitsBack<'a> {
    pub(crate) fn new(d: &'a [u8]) -> Result<BitsBack<'a>, Error> {
        let last = *d.last().ok_or(Error::Corrupt)?;
        if last == 0 {
            return Err(Error::Corrupt);
        }
        Ok(BitsBack { d, pos: 8 * (d.len() as i64 - 1) + i64::from(highbit(u32::from(last))) })
    }

    fn extract(&self, start: i64, n: u32) -> u64 {
        if n == 0 {
            return 0;
        }
        if start < 0 {
            let have = i64::from(n) + start;
            if have <= 0 {
                return 0;
            }
            return self.extract(0, have as u32) << (-start);
        }
        let byte = (start / 8) as usize;
        let mut w = 0u64;
        for (k, &b) in self.d.iter().skip(byte).take(8).enumerate() {
            w |= u64::from(b) << (8 * k);
        }
        (w >> (start % 8)) & ((1u64 << n) - 1)
    }

    pub(crate) fn read(&mut self, n: u32) -> u64 {
        let start = self.pos - i64::from(n);
        let v = self.extract(start, n);
        self.pos = start;
        v
    }

    pub(crate) fn peek(&self, n: u32) -> u64 {
        self.extract(self.pos - i64::from(n), n)
    }

    pub(crate) fn skip(&mut self, n: u32) {
        self.pos -= i64::from(n);
    }

    pub(crate) fn overflowed(&self) -> bool {
        self.pos < 0
    }

    /// Every bit read, none past the start.
    pub(crate) fn done(&self) -> bool {
        self.pos == 0
    }
}

// --- FSE decoding ----------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Cell {
    pub(crate) sym: u8,
    pub(crate) bits: u8,
    pub(crate) base: u16,
}

#[derive(Clone, Debug)]
pub(crate) struct FseTable {
    pub(crate) log: u32,
    pub(crate) cells: Vec<Cell>,
}

/// Where each symbol's cells go: the spread every FSE table shares
/// (RFC 8878 §4.1.1): "less than one" symbols at the top, the others
/// stepped through the rest.
pub(crate) fn spread(probs: &[i16], log: u32) -> Result<Vec<u8>, Error> {
    let size = 1usize << log;
    let mut syms = vec![0u8; size];
    let mut high = size - 1;
    for (s, &p) in probs.iter().enumerate() {
        if p == -1 {
            syms[high] = s as u8;
            high = high.checked_sub(1).ok_or(Error::Corrupt)?;
        }
    }
    let step = (size >> 1) + (size >> 3) + 3;
    let mask = size - 1;
    let mut pos = 0;
    for (s, &p) in probs.iter().enumerate() {
        for _ in 0..p.max(0) {
            syms[pos] = s as u8;
            loop {
                pos = (pos + step) & mask;
                if pos <= high {
                    break;
                }
            }
        }
    }
    if pos != 0 {
        return Err(Error::Corrupt);
    }
    Ok(syms)
}

impl FseTable {
    pub(crate) fn build(probs: &[i16], log: u32) -> Result<FseTable, Error> {
        let size = 1usize << log;
        let syms = spread(probs, log)?;
        let mut next: Vec<u32> = probs.iter().map(|&p| if p == -1 { 1 } else { p.max(0) as u32 }).collect();
        let mut cells = vec![Cell::default(); size];
        for (u, cell) in cells.iter_mut().enumerate() {
            let s = usize::from(syms[u]);
            let n = next[s];
            next[s] += 1;
            if n == 0 {
                return Err(Error::Corrupt);
            }
            let bits = log - highbit(n);
            *cell = Cell { sym: syms[u], bits: bits as u8, base: ((n << bits) - size as u32) as u16 };
        }
        Ok(FseTable { log, cells })
    }

    /// A table of one symbol (RLE mode).
    pub(crate) fn rle(sym: u8) -> FseTable {
        FseTable { log: 0, cells: vec![Cell { sym, bits: 0, base: 0 }] }
    }
}

/// An FSE table description (§4.1.1): the probabilities and the bytes it
/// took.
pub(crate) fn read_dist(d: &[u8], max_sym: usize, max_log: u32) -> Result<(Vec<i16>, u32, usize), Error> {
    let mut bitpos = 0usize;
    let peek = |bitpos: usize, n: u32| -> Result<u32, Error> {
        let mut v = 0u64;
        for k in 0..5 {
            v |= u64::from(*d.get(bitpos / 8 + k).unwrap_or(&0)) << (8 * k);
        }
        if bitpos / 8 >= d.len() {
            return Err(Error::Truncated);
        }
        Ok(((v >> (bitpos % 8)) & ((1u64 << n) - 1)) as u32)
    };
    let log = peek(0, 4)? + 5;
    bitpos += 4;
    if log > max_log {
        return Err(Error::Corrupt);
    }
    let mut probs = vec![0i16; max_sym + 1];
    let mut remaining = (1i32 << log) + 1;
    let mut threshold = 1i32 << log;
    let mut nbits = log + 1;
    let mut sym = 0usize;
    while remaining > 1 {
        if sym > max_sym {
            return Err(Error::Corrupt);
        }
        let max = 2 * threshold - 1 - remaining;
        let low = peek(bitpos, nbits - 1)? as i32;
        let mut v;
        if low < max {
            v = low;
            bitpos += (nbits - 1) as usize;
        } else {
            v = peek(bitpos, nbits)? as i32;
            if v >= threshold {
                v -= max;
            }
            bitpos += nbits as usize;
        }
        let p = v - 1;
        remaining -= p.abs();
        probs[sym] = p as i16;
        sym += 1;
        if p == 0 {
            loop {
                let r = peek(bitpos, 2)? as usize;
                bitpos += 2;
                sym += r;
                if r != 3 {
                    break;
                }
            }
        }
        while remaining < threshold && threshold > 1 {
            nbits -= 1;
            threshold >>= 1;
        }
    }
    if remaining != 1 || sym > max_sym + 1 {
        return Err(Error::Corrupt);
    }
    probs.truncate(sym.max(1));
    Ok((probs, log, bitpos.div_ceil(8)))
}

// The predefined distributions (§3.1.1.3.2.2).
pub(crate) const LL_DEFAULT: [i16; 36] =
    [4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1];
pub(crate) const ML_DEFAULT: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
pub(crate) const OF_DEFAULT: [i16; 29] =
    [1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1];

// Literal and match length codes: base and extra bits (§3.1.1.3.2.1).
pub(crate) const LL_BASE: [u32; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024,
    2048, 4096, 8192, 16384, 32768, 65536,
];
pub(crate) const LL_BITS: [u8; 36] =
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
pub(crate) const ML_BASE: [u32; 53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539,
];
pub(crate) const ML_BITS: [u8; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2,
    3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];

// --- Huffman decoding ----------------------------------------------------------------

#[derive(Clone, Debug)]
pub(crate) struct Huff {
    pub(crate) max_bits: u32,
    /// Indexed by the next `max_bits` bits: (symbol, bits).
    table: Vec<(u8, u8)>,
}

impl Huff {
    fn from_weights(mut weights: Vec<u8>) -> Result<Huff, Error> {
        let total: u32 = weights.iter().filter(|&&w| w > 0).map(|&w| 1u32 << (w - 1)).sum();
        if total == 0 || weights.iter().any(|&w| w > 11) {
            return Err(Error::Corrupt);
        }
        let max_bits = highbit(total) + 1;
        if max_bits > 11 {
            return Err(Error::Corrupt);
        }
        let left = (1u32 << max_bits) - total;
        if !left.is_power_of_two() {
            return Err(Error::Corrupt);
        }
        weights.push((highbit(left) + 1) as u8);
        let mut table = vec![(0u8, 0u8); 1 << max_bits];
        let mut at = 0usize;
        for w in 1..=max_bits as u8 {
            for (s, &x) in weights.iter().enumerate() {
                if x == w {
                    let n = 1usize << (w - 1);
                    let bits = (max_bits + 1 - u32::from(w)) as u8;
                    table.get_mut(at..at + n).ok_or(Error::Corrupt)?.fill((s as u8, bits));
                    at += n;
                }
            }
        }
        Ok(Huff { max_bits, table })
    }

    /// A tree description (§4.2.1): the table and the bytes it took.
    pub(crate) fn read(d: &[u8]) -> Result<(Huff, usize), Error> {
        let h = usize::from(*d.first().ok_or(Error::Truncated)?);
        if h >= 128 {
            let n = h - 127;
            let bytes = n.div_ceil(2);
            let body = d.get(1..1 + bytes).ok_or(Error::Truncated)?;
            let weights = (0..n).map(|i| if i % 2 == 0 { body[i / 2] >> 4 } else { body[i / 2] & 15 }).collect();
            return Ok((Huff::from_weights(weights)?, 1 + bytes));
        }
        let body = d.get(1..1 + h).ok_or(Error::Truncated)?;
        let (probs, log, used) = read_dist(body, 255, 6)?;
        let t = FseTable::build(&probs, log)?;
        let mut b = BitsBack::new(body.get(used..).ok_or(Error::Corrupt)?)?;
        let mut s1 = b.read(log) as usize;
        let mut s2 = b.read(log) as usize;
        let mut w = Vec::new();
        loop {
            let c = t.cells[s1];
            w.push(c.sym);
            s1 = usize::from(c.base) + b.read(u32::from(c.bits)) as usize;
            if b.overflowed() {
                w.push(t.cells[s2].sym);
                break;
            }
            let c = t.cells[s2];
            w.push(c.sym);
            s2 = usize::from(c.base) + b.read(u32::from(c.bits)) as usize;
            if b.overflowed() {
                w.push(t.cells[s1].sym);
                break;
            }
            if w.len() > 255 {
                return Err(Error::Corrupt);
            }
        }
        Ok((Huff::from_weights(w)?, 1 + h))
    }

    /// Decode `n` literals from one stream into `out`.
    pub(crate) fn stream(&self, d: &[u8], n: usize, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut b = BitsBack::new(d)?;
        for _ in 0..n {
            let (s, bits) = self.table[b.peek(self.max_bits) as usize];
            b.skip(u32::from(bits));
            out.push(s);
        }
        if !b.done() {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
}

// --- Writing --------------------------------------------------------------------------

/// Bits written least significant first, to be read backwards.
pub(crate) struct BitsOut {
    pub(crate) buf: Vec<u8>,
    acc: u64,
    n: u32,
}

impl BitsOut {
    pub(crate) fn new() -> BitsOut {
        BitsOut { buf: Vec::new(), acc: 0, n: 0 }
    }

    pub(crate) fn put(&mut self, v: u64, bits: u32) {
        if bits == 0 {
            return;
        }
        self.acc |= (v & ((1u64 << bits) - 1)) << self.n;
        self.n += bits;
        while self.n >= 8 {
            self.buf.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }

    /// The bits written, the last byte padded with zeros (for streams
    /// read forwards).
    pub(crate) fn bytes(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.buf.push(self.acc as u8);
        }
        self.buf
    }

    /// The final 1 bit the reader starts after, then padding.
    pub(crate) fn close(mut self) -> Vec<u8> {
        self.put(1, 1);
        if self.n > 0 {
            self.buf.push(self.acc as u8);
        }
        self.buf
    }
}

/// An FSE table for writing: the state table and each symbol's
/// transform.
pub(crate) struct FseEncoder {
    log: u32,
    states: Vec<u16>,
    /// (delta of bits, delta to find the state)
    tt: Vec<(i64, i64)>,
}

impl FseEncoder {
    pub(crate) fn new(probs: &[i16], log: u32) -> Result<FseEncoder, Error> {
        let size = 1usize << log;
        let syms = spread(probs, log)?;
        let mut cumul = vec![0usize; probs.len() + 1];
        for (s, &p) in probs.iter().enumerate() {
            cumul[s + 1] = cumul[s] + if p == -1 { 1 } else { p.max(0) as usize };
        }
        let mut states = vec![0u16; size];
        let mut fill = cumul.clone();
        for (u, &s) in syms.iter().enumerate() {
            let s = usize::from(s);
            states[fill[s]] = (size + u) as u16;
            fill[s] += 1;
        }
        let mut tt = vec![(0i64, 0i64); probs.len()];
        let mut total = 0i64;
        for (s, &p) in probs.iter().enumerate() {
            let log = i64::from(log);
            match p {
                0 => tt[s] = (((log + 1) << 16) - (1 << log), 0),
                -1 | 1 => {
                    tt[s] = ((log << 16) - (1 << log), total - 1);
                    total += 1;
                }
                p => {
                    let p = i64::from(p);
                    let max_out = log - i64::from(highbit((p - 1) as u32));
                    let min_plus = p << max_out;
                    tt[s] = ((max_out << 16) - min_plus, total - p);
                    total += p;
                }
            }
        }
        Ok(FseEncoder { log, states, tt })
    }

    /// The state a stream starts in for its last symbol.
    pub(crate) fn init(&self, s: u8) -> u32 {
        let (dnb, dfs) = self.tt[usize::from(s)];
        let nb = ((dnb + (1 << 15)) >> 16) as u32;
        let value = ((i64::from(nb) << 16) - dnb) as u64;
        u32::from(self.states[((value >> nb) as i64 + dfs) as usize])
    }

    /// Code `s` from `state`: its bits go out, the new state comes back.
    pub(crate) fn encode(&self, state: u32, s: u8, out: &mut BitsOut) -> u32 {
        let (dnb, dfs) = self.tt[usize::from(s)];
        let nb = ((i64::from(state) + dnb) >> 16) as u32;
        out.put(u64::from(state), nb);
        u32::from(self.states[((u64::from(state) >> nb) as i64 + dfs) as usize])
    }

    pub(crate) fn flush(&self, state: u32, out: &mut BitsOut) {
        out.put(u64::from(state), self.log);
    }
}

/// Literal code lengths for `freqs`: a complete prefix code no longer
/// than `limit` bits (Huffman's construction, the longest cut and the
/// rest rebalanced until Kraft's sum is exactly one). None if fewer than
/// two symbols are used.
pub(crate) fn huff_lengths(freqs: &[u32; 256], limit: u32) -> Option<[u8; 256]> {
    let used: Vec<usize> = (0..256).filter(|&s| freqs[s] > 0).collect();
    if used.len() < 2 {
        return None;
    }
    let n = used.len();
    let mut weight: Vec<u64> = used.iter().map(|&s| u64::from(freqs[s])).collect();
    let mut parent = vec![usize::MAX; n];
    let mut queue: Vec<(u64, usize)> = (0..n).map(|i| (weight[i], i)).collect();
    queue.sort_unstable_by(|a, b| b.cmp(a));
    while queue.len() > 1 {
        let a = queue.pop()?;
        let b = queue.pop()?;
        let id = weight.len();
        weight.push(a.0 + b.0);
        parent.push(usize::MAX);
        parent[a.1] = id;
        parent[b.1] = id;
        let item = (a.0 + b.0, id);
        let at = queue.partition_point(|x| *x > item);
        queue.insert(at, item);
    }
    let mut depth = vec![0u32; weight.len()];
    for k in (0..weight.len() - 1).rev() {
        depth[k] = depth[parent[k]] + 1;
    }
    let mut lens: Vec<u32> = (0..n).map(|k| depth[k].clamp(1, limit)).collect();
    let full = 1u64 << limit;
    let mut sum: u64 = lens.iter().map(|&l| 1u64 << (limit - l)).sum();
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by_key(|&k| (freqs[used[k]], core::cmp::Reverse(used[k])));
    while sum > full {
        let k = *order.iter().find(|&&k| lens[k] < limit)?;
        sum -= 1u64 << (limit - lens[k] - 1);
        lens[k] += 1;
    }
    // Make the code complete: shorten the commonest codes while it fits.
    while sum < full {
        let k = *order.iter().rev().find(|&&k| lens[k] > 1 && sum + (1u64 << (limit - lens[k])) <= full)?;
        sum += 1u64 << (limit - lens[k]);
        lens[k] -= 1;
    }
    let mut out = [0u8; 256];
    for (k, &s) in used.iter().enumerate() {
        out[s] = lens[k] as u8;
    }
    Some(out)
}

/// The codes for literal lengths, as the decoder's table assigns them:
/// (code, bits) per symbol.
pub(crate) fn huff_codes(lens: &[u8; 256]) -> (u32, [(u32, u8); 256]) {
    let max = u32::from(*lens.iter().max().unwrap_or(&0));
    let mut codes = [(0u32, 0u8); 256];
    let mut at = 0u32;
    for w in 1..=max {
        let bits = max + 1 - w;
        for s in 0..256 {
            if lens[s] != 0 && u32::from(lens[s]) == bits {
                codes[s] = (at >> (w - 1), bits as u8);
                at += 1 << (w - 1);
            }
        }
    }
    (max, codes)
}
