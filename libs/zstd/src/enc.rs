// SPDX-License-Identifier: MIT OR Apache-2.0

//! The zstd encoder: blocks of up to 128 KiB, matches from hash chains
//! (the repeated offsets tried first), literals Huffman coded when that
//! pays (weights written directly or through FSE), sequences coded with
//! the predefined tables or ones made for the block, whichever is
//! smaller; a block that does not shrink is stored.

use alloc::vec;
use alloc::vec::Vec;

use crate::MAGIC;
use crate::fse::{
    BitsOut, FseEncoder, LL_BASE, LL_BITS, LL_DEFAULT, ML_BASE, ML_BITS, ML_DEFAULT, OF_DEFAULT, huff_codes,
    huff_lengths,
};
use crate::xxh::Xxh64;

const BLOCK: usize = 128 << 10;
const MIN_MATCH: usize = 4;
const HASH_BITS: u32 = 17;
const NONE: u64 = u64::MAX;

fn highbit(v: u32) -> u32 {
    31 - v.leading_zeros()
}

/// How a level searches: the window's log, chain length, the length that
/// ends the search.
fn level_params(level: i32) -> (u32, usize, usize) {
    match level {
        ..=1 => (19, 2, 16),
        2 => (20, 4, 24),
        3 => (21, 8, 32),
        4..=6 => (21, 16, 48),
        7..=9 => (22, 32, 64),
        10..=15 => (22, 64, 128),
        _ => (22, 256, 256),
    }
}

/// One sequence: literals before it, the match's offset value (offset +
/// 3, or 1 to 3 for a repeated one) and length.
#[derive(Clone, Copy, Debug)]
struct Seq {
    ll: u32,
    of_value: u32,
    ml: u32,
}

fn ll_code(ll: u32) -> u8 {
    if ll < 16 {
        return ll as u8;
    }
    LL_BASE.iter().rposition(|&b| b <= ll).unwrap_or(0) as u8
}

fn ml_code(ml: u32) -> u8 {
    if ml < 35 {
        return (ml - 3) as u8;
    }
    ML_BASE.iter().rposition(|&b| b <= ml).unwrap_or(0) as u8
}

/// Counts made into probabilities summing to 2^log (each used symbol at
/// least "less than one").
fn normalize(counts: &[u32], log: u32) -> Vec<i16> {
    let total: u64 = counts.iter().map(|&c| u64::from(c)).sum();
    let scale = 1i64 << log;
    let mut probs: Vec<i16> = counts
        .iter()
        .map(|&c| {
            if c == 0 {
                0
            } else {
                let p = (u64::from(c) * scale as u64 / total) as i16;
                if p == 0 { -1 } else { p }
            }
        })
        .collect();
    let sum: i64 = probs.iter().map(|&p| if p == -1 { 1 } else { i64::from(p) }).sum();
    let largest = (0..probs.len()).max_by_key(|&i| probs[i]).unwrap_or(0);
    probs[largest] += (scale - sum) as i16;
    while let Some(&l) = probs.last() {
        if l != 0 || probs.len() == 1 {
            break;
        }
        probs.pop();
    }
    probs
}

/// An FSE table description (the inverse of the decoder's reading).
fn write_dist(probs: &[i16], log: u32) -> Vec<u8> {
    let mut o = BitsOut::new();
    o.put(u64::from(log - 5), 4);
    let mut remaining = (1i32 << log) + 1;
    let mut threshold = 1i32 << log;
    let mut nbits = log + 1;
    let mut s = 0;
    while s < probs.len() && remaining > 1 {
        let count = i32::from(probs[s]);
        let v = count + 1;
        let max = 2 * threshold - 1 - remaining;
        if v < max {
            o.put(v as u64, nbits - 1);
        } else if v < threshold {
            o.put(v as u64, nbits);
        } else {
            o.put((v + max) as u64, nbits);
        }
        remaining -= count.abs();
        s += 1;
        if count == 0 {
            let mut z = 0;
            while s + z < probs.len() && probs[s + z] == 0 {
                z += 1;
            }
            s += z;
            while z >= 3 {
                o.put(3, 2);
                z -= 3;
            }
            o.put(z as u64, 2);
        }
        while remaining < threshold && threshold > 1 {
            nbits -= 1;
            threshold >>= 1;
        }
    }
    // Whole bytes; the reader stops when the probabilities add up.
    o.bytes()
}

/// A sequence table for a block: predefined, or made from the codes.
struct Table {
    enc: FseEncoder,
    /// The description, empty for the predefined table.
    desc: Vec<u8>,
    mode: u8,
}

fn choose_table(codes: &[u8], default: &[i16], default_log: u32, max_log: u32) -> Option<Table> {
    let fits_default = codes.iter().all(|&c| usize::from(c) < default.len() && default[usize::from(c)] != 0);
    let predefined = || FseEncoder::new(default, default_log).ok().map(|enc| Table { enc, desc: Vec::new(), mode: 0 });
    // Few sequences: a description would cost more than it saves.
    if codes.len() < 64 && fits_default {
        return predefined();
    }
    let max = usize::from(*codes.iter().max()?);
    let mut counts = vec![0u32; max + 1];
    for &c in codes {
        counts[usize::from(c)] += 1;
    }
    let used = counts.iter().filter(|&&c| c > 0).count() as u32;
    let log = (highbit(codes.len() as u32) + 1).max(highbit(used) + 2).clamp(5, max_log);
    let probs = normalize(&counts, log);
    match FseEncoder::new(&probs, log) {
        Ok(enc) => Some(Table { enc, desc: write_dist(&probs, log), mode: 2 }),
        Err(_) if fits_default => predefined(),
        Err(_) => None,
    }
}

/// The literals section for `lits`.
fn literals(lits: &[u8]) -> Vec<u8> {
    let n = lits.len();
    let raw = |kind: u8, body: &[u8]| -> Vec<u8> {
        let mut h = if n < 32 {
            vec![kind | ((n as u8) << 3)]
        } else if n < 4096 {
            vec![kind | (1 << 2) | ((n as u8 & 15) << 4), (n >> 4) as u8]
        } else {
            vec![kind | (3 << 2) | ((n as u8 & 15) << 4), (n >> 4) as u8, (n >> 12) as u8]
        };
        h.extend_from_slice(body);
        h
    };
    if n > 0 && lits.iter().all(|&b| b == lits[0]) {
        return raw(1, &lits[..1]);
    }
    let plain = raw(0, lits);
    if n < 64 {
        return plain;
    }
    let mut freqs = [0u32; 256];
    for &b in lits {
        freqs[usize::from(b)] += 1;
    }
    let Some(lens) = huff_lengths(&freqs, 11) else { return plain };
    let (max_bits, codes) = huff_codes(&lens);
    let Some(tree) = tree_description(&lens, max_bits) else { return plain };
    // One stream for small literal sets, else four.
    let streams: Vec<Vec<u8>> = if n <= 1023 {
        vec![huff_stream(lits, &codes)]
    } else {
        let seg = n.div_ceil(4);
        (0..4).map(|k| huff_stream(&lits[(k * seg).min(n)..((k + 1) * seg).min(n)], &codes)).collect()
    };
    let mut body = tree;
    if streams.len() == 4 {
        for s in &streams[..3] {
            if s.len() > 0xFFFF {
                return plain;
            }
            body.extend_from_slice(&(s.len() as u16).to_le_bytes());
        }
    }
    for s in &streams {
        body.extend_from_slice(s);
    }
    let comp = body.len();
    let (sf, bits) = match (streams.len(), n.max(comp)) {
        (1, m) if m <= 1023 => (0u64, 10),
        (_, m) if m <= 1023 => (1, 10),
        (_, m) if m <= 16383 => (2, 14),
        (_, m) if m < 1 << 18 => (3, 18),
        _ => return plain,
    };
    let v = 2 | (sf << 2) | ((n as u64) << 4) | ((comp as u64) << (4 + bits));
    let head_len = match sf {
        0 | 1 => 3,
        2 => 4,
        _ => 5,
    };
    let mut out: Vec<u8> = v.to_le_bytes()[..head_len].to_vec();
    out.extend_from_slice(&body);
    if out.len() >= plain.len() { plain } else { out }
}

/// One Huffman stream: symbols last first, so the reader gets them in
/// order.
fn huff_stream(lits: &[u8], codes: &[(u32, u8); 256]) -> Vec<u8> {
    let mut o = BitsOut::new();
    for &b in lits.iter().rev() {
        let (c, n) = codes[usize::from(b)];
        o.put(u64::from(c), u32::from(n));
    }
    o.close()
}

/// The tree description: weights directly (up to 128 of them) or through
/// FSE; the last used symbol's weight is left out (the reader works it
/// out).
fn tree_description(lens: &[u8; 256], max_bits: u32) -> Option<Vec<u8>> {
    let last = (0..256).rev().find(|&s| lens[s] != 0)?;
    let weights: Vec<u8> =
        (0..last).map(|s| if lens[s] == 0 { 0 } else { (max_bits + 1 - u32::from(lens[s])) as u8 }).collect();
    if weights.is_empty() {
        return None;
    }
    if let Some(f) = fse_weights(&weights)
        && (weights.len() > 128 || f.len() < weights.len().div_ceil(2))
    {
        return Some(f);
    }
    if weights.len() > 128 {
        return None;
    }
    let mut out = vec![(127 + weights.len()) as u8];
    for pair in weights.chunks(2) {
        out.push((pair[0] << 4) | pair.get(1).copied().unwrap_or(0));
    }
    Some(out)
}

/// Weights through FSE: a table description and two interleaved states.
fn fse_weights(w: &[u8]) -> Option<Vec<u8>> {
    let mut counts = vec![0u32; 13];
    for &x in w {
        counts[usize::from(x)] += 1;
    }
    // One symbol takes the whole table: its state would never advance.
    if counts.iter().filter(|&&c| c > 0).count() < 2 || w.len() < 2 {
        return None;
    }
    let log = 6;
    let probs = normalize(&counts, log);
    let enc = FseEncoder::new(&probs, log).ok()?;
    let mut desc = write_dist(&probs, log);
    let mut o = BitsOut::new();
    let n = w.len();
    let mut i = n;
    let (mut s1, mut s2);
    if n % 2 == 1 {
        i -= 1;
        s1 = enc.init(w[i]);
        i -= 1;
        s2 = enc.init(w[i]);
        i -= 1;
        s1 = enc.encode(s1, w[i], &mut o);
    } else {
        i -= 1;
        s2 = enc.init(w[i]);
        i -= 1;
        s1 = enc.init(w[i]);
    }
    while i > 0 {
        i -= 1;
        s2 = enc.encode(s2, w[i], &mut o);
        i -= 1;
        s1 = enc.encode(s1, w[i], &mut o);
    }
    enc.flush(s2, &mut o);
    enc.flush(s1, &mut o);
    desc.extend(o.close());
    if desc.len() > 127 {
        return None;
    }
    let mut out = vec![desc.len() as u8];
    out.extend(desc);
    Some(out)
}

/// The sequences section; None if a table cannot be made for its codes.
fn sequences(seqs: &[Seq]) -> Option<Vec<u8>> {
    let n = seqs.len();
    let mut out = Vec::new();
    if n < 128 {
        out.push(n as u8);
    } else if n < 0x7F00 {
        out.push(((n >> 8) + 128) as u8);
        out.push(n as u8);
    } else {
        out.push(255);
        out.extend_from_slice(&((n - 0x7F00) as u16).to_le_bytes());
    }
    if n == 0 {
        return Some(out);
    }
    let llc: Vec<u8> = seqs.iter().map(|s| ll_code(s.ll)).collect();
    let mlc: Vec<u8> = seqs.iter().map(|s| ml_code(s.ml)).collect();
    let ofc: Vec<u8> = seqs.iter().map(|s| highbit(s.of_value) as u8).collect();
    let ll = choose_table(&llc, &LL_DEFAULT, 6, 9)?;
    let of = choose_table(&ofc, &OF_DEFAULT, 5, 8)?;
    let ml = choose_table(&mlc, &ML_DEFAULT, 6, 9)?;
    out.push((ll.mode << 6) | (of.mode << 4) | (ml.mode << 2));
    out.extend_from_slice(&ll.desc);
    out.extend_from_slice(&of.desc);
    out.extend_from_slice(&ml.desc);
    let extras = |i: usize, o: &mut BitsOut| {
        let s = seqs[i];
        let (l, m, f) = (usize::from(llc[i]), usize::from(mlc[i]), u32::from(ofc[i]));
        o.put(u64::from(s.ll - LL_BASE[l]), u32::from(LL_BITS[l]));
        o.put(u64::from(s.ml - ML_BASE[m]), u32::from(ML_BITS[m]));
        o.put(u64::from(s.of_value - (1 << f)), f);
    };
    let mut o = BitsOut::new();
    let last = n - 1;
    let mut sml = ml.enc.init(mlc[last]);
    let mut sof = of.enc.init(ofc[last]);
    let mut sll = ll.enc.init(llc[last]);
    extras(last, &mut o);
    for i in (0..last).rev() {
        sof = of.enc.encode(sof, ofc[i], &mut o);
        sml = ml.enc.encode(sml, mlc[i], &mut o);
        sll = ll.enc.encode(sll, llc[i], &mut o);
        extras(i, &mut o);
    }
    ml.enc.flush(sml, &mut o);
    of.enc.flush(sof, &mut o);
    ll.enc.flush(sll, &mut o);
    out.extend(o.close());
    Some(out)
}

/// A zstd frame written as it is fed: one frame, its size unknown, a
/// checksum at the end.
pub struct Writer {
    level: i32,
    window_log: u32,
    data: Vec<u8>,
    base: u64,
    pos: u64,
    head: Vec<u64>,
    chain: Vec<u64>,
    depth: usize,
    nice: usize,
    reps: [u32; 3],
    hash: Xxh64,
    started: bool,
}

impl core::fmt::Debug for Writer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Writer").field("level", &self.level).field("pos", &self.pos).finish()
    }
}

impl Writer {
    pub fn new(level: i32) -> Writer {
        let (window_log, depth, nice) = level_params(level);
        Writer {
            level,
            window_log,
            data: Vec::new(),
            base: 0,
            pos: 0,
            head: vec![NONE; 1 << HASH_BITS],
            chain: vec![NONE; 1 << window_log],
            depth,
            nice,
            reps: [1, 4, 8],
            hash: Xxh64::new(0),
            started: false,
        }
    }

    fn header(&mut self, out: &mut Vec<u8>) {
        if self.started {
            return;
        }
        self.started = true;
        out.extend_from_slice(&MAGIC.to_le_bytes());
        // No content size, a checksum, no dictionary; the window.
        out.push(0x04);
        out.push(((self.window_log - 10) << 3) as u8);
    }

    pub fn write(&mut self, data: &[u8], out: &mut Vec<u8>) {
        self.header(out);
        self.hash.update(data);
        self.data.extend_from_slice(data);
        while self.base + self.data.len() as u64 - self.pos > BLOCK as u64 {
            self.block(out, false, self.pos + BLOCK as u64);
        }
        let window = 1u64 << self.window_log;
        let keep_from = self.pos.saturating_sub(window);
        if keep_from > self.base + (4 << 20) {
            let n = (keep_from - self.base) as usize;
            self.data.drain(..n);
            self.base = keep_from;
        }
    }

    pub fn finish(mut self, out: &mut Vec<u8>) {
        self.header(out);
        let end = self.base + self.data.len() as u64;
        loop {
            let stop = (self.pos + BLOCK as u64).min(end);
            let last = stop == end;
            self.block(out, last, stop);
            if last {
                break;
            }
        }
        out.extend_from_slice(&(self.hash.finish() as u32).to_le_bytes());
    }

    fn at(&self, abs: u64) -> usize {
        (abs - self.base) as usize
    }

    fn hash4(&self, abs: u64) -> Option<usize> {
        let i = self.at(abs);
        let d = self.data.get(i..i + 4)?;
        let v = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
        Some((v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize)
    }

    fn insert(&mut self, abs: u64) {
        if let Some(h) = self.hash4(abs) {
            let mask = (1u64 << self.window_log) - 1;
            self.chain[(abs & mask) as usize] = self.head[h];
            self.head[h] = abs;
        }
    }

    /// Match length at `abs` against `dist` bytes back, up to `end`.
    fn match_len(&self, abs: u64, dist: u64, end: u64) -> usize {
        if dist == 0 || dist > abs || abs - dist < self.base || dist > 1u64 << self.window_log {
            return 0;
        }
        let (i, j) = (self.at(abs), self.at(abs - dist));
        let max = (end - abs) as usize;
        let mut l = 0;
        while l < max && self.data[i + l] == self.data[j + l] {
            l += 1;
        }
        l
    }

    /// The best match at `abs`: (length, offset, repeated index if one).
    fn find(&self, abs: u64, end: u64, ll: u32) -> (usize, u64) {
        let mut best = (0usize, 0u64);
        // The repeated offsets as the decoder will see them.
        let reps: [u64; 3] = self.reps.map(u64::from);
        let _ = ll;
        for &r in &reps {
            let l = self.match_len(abs, r, end);
            if l > best.0 {
                best = (l, r);
            }
        }
        if best.0 >= self.nice {
            return best;
        }
        let Some(h) = self.hash4(abs) else { return best };
        let mask = (1u64 << self.window_log) - 1;
        let lowest = abs.saturating_sub(1u64 << self.window_log).max(self.base);
        let mut cand = self.head[h];
        let mut n = 0;
        while cand != NONE && cand < abs && cand >= lowest && n < self.depth {
            let l = self.match_len(abs, abs - cand, end);
            // A new offset must beat a repeated one by more than a byte.
            if l > best.0 + 1 || (l > best.0 && reps.iter().all(|&r| r != best.1)) {
                best = (l, abs - cand);
                if l >= self.nice {
                    break;
                }
            }
            let next = self.chain[(cand & mask) as usize];
            if next == NONE || next >= cand {
                break;
            }
            cand = next;
            n += 1;
        }
        best
    }

    /// The offset value for a match at `offset` after `ll` literals,
    /// updating the repeated offsets as the decoder will.
    fn offset_value(&mut self, offset: u32, ll: u32) -> u32 {
        let r = self.reps;
        let pick = if ll > 0 {
            [(r[0], 1u32), (r[1], 2), (r[2], 3)].iter().find(|x| x.0 == offset).map(|x| x.1)
        } else {
            [(r[1], 1u32), (r[2], 2), (r[0].wrapping_sub(1), 3)].iter().find(|x| x.0 == offset && x.0 > 0).map(|x| x.1)
        };
        match pick {
            Some(v) => {
                let k = v - 1 + u32::from(ll == 0);
                match k {
                    0 => {}
                    1 => self.reps.swap(0, 1),
                    2 => self.reps = [r[2], r[0], r[1]],
                    _ => self.reps = [offset, r[0], r[1]],
                }
                v
            }
            None => {
                self.reps = [offset, r[0], r[1]];
                offset + 3
            }
        }
    }

    /// Code input from the position to `stop` as one block.
    fn block(&mut self, out: &mut Vec<u8>, last: bool, stop: u64) {
        let start = self.pos;
        let raw: Vec<u8> = self.data[self.at(start)..self.at(stop)].to_vec();
        let header = |kind: u32, size: usize| -> [u8; 3] {
            let h = u32::from(last) | (kind << 1) | ((size as u32) << 3);
            [h as u8, (h >> 8) as u8, (h >> 16) as u8]
        };
        if raw.is_empty() {
            out.extend_from_slice(&header(0, 0));
            return;
        }
        if raw.iter().all(|&b| b == raw[0]) && raw.len() > 1 {
            // Still feed the chains: later blocks may match into it.
            for p in start..stop {
                self.insert(p);
            }
            self.pos = stop;
            out.extend_from_slice(&header(1, raw.len()));
            out.push(raw[0]);
            return;
        }
        let saved_reps = self.reps;
        let mut seqs = Vec::new();
        let mut lits = Vec::new();
        let mut lit_start = start;
        let mut p = start;
        while p < stop {
            let ll = (p - lit_start) as u32;
            let (len, off) = if stop - p >= MIN_MATCH as u64 { self.find(p, stop, ll) } else { (0, 0) };
            if len >= MIN_MATCH || (len >= 3 && self.reps.contains(&(off as u32))) {
                lits.extend_from_slice(&self.data[self.at(lit_start)..self.at(p)]);
                let ov = self.offset_value(off as u32, ll);
                seqs.push(Seq { ll, of_value: ov, ml: len as u32 });
                for k in 0..len as u64 {
                    self.insert(p + k);
                }
                p += len as u64;
                lit_start = p;
            } else {
                self.insert(p);
                p += 1;
            }
        }
        lits.extend_from_slice(&self.data[self.at(lit_start)..self.at(stop)]);
        self.pos = stop;
        let mut body = literals(&lits);
        let seq_section = sequences(&seqs);
        let ok = seq_section.is_some();
        body.extend(seq_section.unwrap_or_default());
        if !ok || body.len() >= raw.len() || body.len() > BLOCK {
            // Stored; the decoder's repeated offsets did not move.
            self.reps = saved_reps;
            out.extend_from_slice(&header(0, raw.len()));
            out.extend_from_slice(&raw);
        } else {
            out.extend_from_slice(&header(2, body.len()));
            out.extend_from_slice(&body);
        }
    }
}

/// Compress `data` into one zstd frame at `level`.
pub fn compress(data: &[u8], level: i32) -> Vec<u8> {
    let mut w = Writer::new(level);
    let mut out = Vec::new();
    for chunk in data.chunks(1 << 20) {
        w.write(chunk, &mut out);
    }
    w.finish(&mut out);
    out
}
