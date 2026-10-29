// SPDX-License-Identifier: MIT OR Apache-2.0

//! LZMA and LZMA2: the range coder, the model (twelve states, literal
//! coders by context, length and distance coders, four repeated
//! distances), a decoder writing into a dictionary, and an encoder
//! choosing matches greedily from hash chains, its output cut into
//! LZMA2's chunks.

use alloc::vec;
use alloc::vec::Vec;

use crate::{Error, Input, Source};

const PROB_INIT: u16 = 1024;
const MOVE_BITS: u32 = 5;
const TOTAL_BITS: u32 = 11;
const TOP: u32 = 1 << 24;
const STATES: usize = 12;
const POS_STATES_MAX: usize = 16;
const MATCH_MIN: usize = 2;
/// The longest match: 2 + 8 + 8 + 256 - 1.
pub(crate) const MATCH_MAX: usize = 273;
const END_POS_MODEL: u32 = 14;
const FULL_DISTANCES: usize = 128;
const ALIGN_BITS: u32 = 4;

// --- Range decoder -----------------------------------------------------------

pub(crate) struct RangeDecoder {
    range: u32,
    code: u32,
    /// Bytes read since the coder started.
    pub(crate) read: u64,
}

impl RangeDecoder {
    pub(crate) fn new<S: Source>(input: &mut Input<S>) -> Result<RangeDecoder, Error> {
        let mut rc = RangeDecoder { range: 0xFFFF_FFFF, code: 0, read: 0 };
        if rc.byte(input)? != 0 {
            return Err(Error::Corrupt);
        }
        for _ in 0..4 {
            rc.code = (rc.code << 8) | u32::from(rc.byte(input)?);
        }
        if rc.code == rc.range {
            return Err(Error::Corrupt);
        }
        Ok(rc)
    }

    fn byte<S: Source>(&mut self, input: &mut Input<S>) -> Result<u8, Error> {
        self.read += 1;
        input.byte()?.ok_or(Error::Truncated)
    }

    fn normalize<S: Source>(&mut self, input: &mut Input<S>) -> Result<(), Error> {
        if self.range < TOP {
            self.range <<= 8;
            self.code = (self.code << 8) | u32::from(self.byte(input)?);
        }
        Ok(())
    }

    fn bit<S: Source>(&mut self, input: &mut Input<S>, p: &mut u16) -> Result<u32, Error> {
        let bound = (self.range >> TOTAL_BITS) * u32::from(*p);
        let b = if self.code < bound {
            self.range = bound;
            *p += ((1 << TOTAL_BITS) - *p) >> MOVE_BITS;
            0
        } else {
            self.range -= bound;
            self.code -= bound;
            *p -= *p >> MOVE_BITS;
            1
        };
        self.normalize(input)?;
        Ok(b)
    }

    fn direct<S: Source>(&mut self, input: &mut Input<S>, n: u32) -> Result<u32, Error> {
        let mut v = 0u32;
        for _ in 0..n {
            self.range >>= 1;
            self.code = self.code.wrapping_sub(self.range);
            let t = 0u32.wrapping_sub(self.code >> 31);
            self.code = self.code.wrapping_add(self.range & t);
            if self.code == self.range {
                return Err(Error::Corrupt);
            }
            self.normalize(input)?;
            v = (v << 1).wrapping_add(t.wrapping_add(1));
        }
        Ok(v)
    }

    fn tree<S: Source>(&mut self, input: &mut Input<S>, probs: &mut [u16], bits: u32) -> Result<u32, Error> {
        let mut m = 1usize;
        for _ in 0..bits {
            m = (m << 1) + self.bit(input, &mut probs[m])? as usize;
        }
        Ok(m as u32 - (1 << bits))
    }

    fn reverse<S: Source>(&mut self, input: &mut Input<S>, probs: &mut [u16], bits: u32) -> Result<u32, Error> {
        let (mut m, mut sym) = (1usize, 0u32);
        for i in 0..bits {
            let b = self.bit(input, &mut probs[m])?;
            m = (m << 1) + b as usize;
            sym |= b << i;
        }
        Ok(sym)
    }

    /// A stream that ended cleanly leaves the code at zero.
    pub(crate) fn finished(&self) -> bool {
        self.code == 0
    }
}

// --- Range encoder -------------------------------------------------------------

pub(crate) struct RangeEncoder {
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u64,
    pub(crate) out: Vec<u8>,
}

impl RangeEncoder {
    pub(crate) fn new() -> RangeEncoder {
        RangeEncoder { low: 0, range: 0xFFFF_FFFF, cache: 0, cache_size: 1, out: Vec::new() }
    }

    fn shift_low(&mut self) {
        if self.low < 0xFF00_0000 || self.low > 0xFFFF_FFFF {
            let carry = (self.low >> 32) as u8;
            let mut temp = self.cache;
            loop {
                self.out.push(temp.wrapping_add(carry));
                temp = 0xFF;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = (self.low >> 24) as u8;
        }
        self.cache_size += 1;
        self.low = (self.low & 0x00FF_FFFF) << 8;
    }

    fn bit(&mut self, p: &mut u16, b: u32) {
        let bound = (self.range >> TOTAL_BITS) * u32::from(*p);
        if b == 0 {
            self.range = bound;
            *p += ((1 << TOTAL_BITS) - *p) >> MOVE_BITS;
        } else {
            self.low += u64::from(bound);
            self.range -= bound;
            *p -= *p >> MOVE_BITS;
        }
        while self.range < TOP {
            self.range <<= 8;
            self.shift_low();
        }
    }

    fn direct(&mut self, v: u32, n: u32) {
        for i in (0..n).rev() {
            self.range >>= 1;
            if (v >> i) & 1 == 1 {
                self.low += u64::from(self.range);
            }
            while self.range < TOP {
                self.range <<= 8;
                self.shift_low();
            }
        }
    }

    fn tree(&mut self, probs: &mut [u16], bits: u32, v: u32) {
        let mut m = 1usize;
        for i in (0..bits).rev() {
            let b = (v >> i) & 1;
            self.bit(&mut probs[m], b);
            m = (m << 1) + b as usize;
        }
    }

    fn reverse(&mut self, probs: &mut [u16], bits: u32, v: u32) {
        let mut m = 1usize;
        for i in 0..bits {
            let b = (v >> i) & 1;
            self.bit(&mut probs[m], b);
            m = (m << 1) + b as usize;
        }
    }

    /// The bytes it will have written once flushed (at most).
    pub(crate) fn pending(&self) -> usize {
        self.out.len() + self.cache_size as usize + 4
    }

    pub(crate) fn finish(mut self) -> Vec<u8> {
        for _ in 0..5 {
            self.shift_low();
        }
        self.out
    }
}

// --- The model -------------------------------------------------------------------

#[derive(Clone)]
struct LenProbs {
    choice: u16,
    choice2: u16,
    low: [[u16; 8]; POS_STATES_MAX],
    mid: [[u16; 8]; POS_STATES_MAX],
    high: [u16; 256],
}

impl LenProbs {
    fn new() -> LenProbs {
        LenProbs {
            choice: PROB_INIT,
            choice2: PROB_INIT,
            low: [[PROB_INIT; 8]; POS_STATES_MAX],
            mid: [[PROB_INIT; 8]; POS_STATES_MAX],
            high: [PROB_INIT; 256],
        }
    }

    fn decode<S: Source>(&mut self, rc: &mut RangeDecoder, input: &mut Input<S>, ps: usize) -> Result<usize, Error> {
        if rc.bit(input, &mut self.choice)? == 0 {
            return Ok(rc.tree(input, &mut self.low[ps], 3)? as usize);
        }
        if rc.bit(input, &mut self.choice2)? == 0 {
            return Ok(8 + rc.tree(input, &mut self.mid[ps], 3)? as usize);
        }
        Ok(16 + rc.tree(input, &mut self.high, 8)? as usize)
    }

    fn encode(&mut self, rc: &mut RangeEncoder, len: usize, ps: usize) {
        let l = (len - MATCH_MIN) as u32;
        if l < 8 {
            rc.bit(&mut self.choice, 0);
            rc.tree(&mut self.low[ps], 3, l);
        } else if l < 16 {
            rc.bit(&mut self.choice, 1);
            rc.bit(&mut self.choice2, 0);
            rc.tree(&mut self.mid[ps], 3, l - 8);
        } else {
            rc.bit(&mut self.choice, 1);
            rc.bit(&mut self.choice2, 1);
            rc.tree(&mut self.high, 8, l - 16);
        }
    }
}

/// lc, lp and pb: the bits of the previous byte and of the position the
/// literal and match coders are chosen by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Props {
    pub lc: u32,
    pub lp: u32,
    pub pb: u32,
}

impl Props {
    pub(crate) fn from_byte(b: u8) -> Result<Props, Error> {
        if b >= 9 * 5 * 5 {
            return Err(Error::Corrupt);
        }
        let b = u32::from(b);
        Ok(Props { lc: b % 9, lp: (b / 9) % 5, pb: b / 45 })
    }

    pub(crate) fn byte(self) -> u8 {
        ((self.pb * 5 + self.lp) * 9 + self.lc) as u8
    }
}

#[derive(Clone)]
pub(crate) struct Model {
    props: Props,
    literal: Vec<u16>,
    is_match: [u16; STATES * POS_STATES_MAX],
    is_rep: [u16; STATES],
    is_rep_g0: [u16; STATES],
    is_rep_g1: [u16; STATES],
    is_rep_g2: [u16; STATES],
    is_rep0_long: [u16; STATES * POS_STATES_MAX],
    pos_slot: [[u16; 64]; 4],
    pos_special: [u16; 1 + FULL_DISTANCES - END_POS_MODEL as usize],
    align: [u16; 1 << ALIGN_BITS],
    len: LenProbs,
    rep_len: LenProbs,
    state: usize,
    reps: [u32; 4],
}

impl Model {
    pub(crate) fn new(props: Props) -> Model {
        Model {
            props,
            literal: vec![PROB_INIT; 0x300 << (props.lc + props.lp)],
            is_match: [PROB_INIT; STATES * POS_STATES_MAX],
            is_rep: [PROB_INIT; STATES],
            is_rep_g0: [PROB_INIT; STATES],
            is_rep_g1: [PROB_INIT; STATES],
            is_rep_g2: [PROB_INIT; STATES],
            is_rep0_long: [PROB_INIT; STATES * POS_STATES_MAX],
            pos_slot: [[PROB_INIT; 64]; 4],
            pos_special: [PROB_INIT; 1 + FULL_DISTANCES - END_POS_MODEL as usize],
            align: [PROB_INIT; 1 << ALIGN_BITS],
            len: LenProbs::new(),
            rep_len: LenProbs::new(),
            state: 0,
            reps: [0; 4],
        }
    }

    pub(crate) fn props_of(&self) -> Props {
        self.props
    }

    fn literal_base(&self, pos: u64, prev: u8) -> usize {
        let p = self.props;
        let ctx = (((pos as u32) & ((1 << p.lp) - 1)) << p.lc) + (u32::from(prev) >> (8 - p.lc));
        0x300 * ctx as usize
    }

    fn pos_state(&self, pos: u64) -> usize {
        (pos as usize) & ((1 << self.props.pb) - 1)
    }
}

fn after_literal(s: usize) -> usize {
    if s < 4 {
        0
    } else if s < 10 {
        s - 3
    } else {
        s - 6
    }
}

fn after_match(s: usize) -> usize {
    if s < 7 { 7 } else { 10 }
}

fn after_rep(s: usize) -> usize {
    if s < 7 { 8 } else { 11 }
}

fn after_short_rep(s: usize) -> usize {
    if s < 7 { 9 } else { 11 }
}

// --- The dictionary -------------------------------------------------------------

/// Decoded bytes with the window matches reach, written out in pieces:
/// `out_from` is where the bytes not yet written start.
pub(crate) struct Dict {
    pub(crate) buf: Vec<u8>,
    size: usize,
    out_from: usize,
    /// Bytes decoded in all, and since the last dictionary reset.
    pub(crate) total: u64,
    pub(crate) since_reset: u64,
}

impl Dict {
    pub(crate) fn new(size: usize) -> Dict {
        Dict { buf: Vec::new(), size: size.max(4096), out_from: 0, total: 0, since_reset: 0 }
    }

    pub(crate) fn reset(&mut self) {
        self.since_reset = 0;
    }

    fn get(&self, dist: usize) -> u8 {
        self.buf[self.buf.len() - dist - 1]
    }

    fn push(&mut self, b: u8) {
        self.buf.push(b);
        self.total += 1;
        self.since_reset += 1;
    }

    /// Whether the buffer has grown enough to be written out.
    pub(crate) fn full(&self) -> bool {
        self.buf.len() >= 2 * self.size + (1 << 20)
    }

    /// Write the bytes not yet written to `out`, keeping the window.
    pub(crate) fn flush(&mut self, out: &mut dyn FnMut(&[u8]) -> Result<(), Error>) -> Result<(), Error> {
        out(&self.buf[self.out_from..])?;
        let drop = self.buf.len().saturating_sub(self.size);
        self.buf.drain(..drop);
        self.out_from = self.buf.len();
        Ok(())
    }

    pub(crate) fn copy_in(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        self.total += data.len() as u64;
        self.since_reset += data.len() as u64;
    }
}

// --- Decoding ----------------------------------------------------------------------

impl Model {
    /// Decode until `want` more bytes are in the dictionary (or, with
    /// `marker`, an end marker); true if the end marker was seen.
    pub(crate) fn decode<S: Source>(
        &mut self,
        rc: &mut RangeDecoder,
        input: &mut Input<S>,
        dict: &mut Dict,
        want: Option<u64>,
        marker: bool,
        flush: &mut dyn FnMut(&mut Dict) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        let end = want.map(|w| dict.total + w);
        loop {
            if end.is_some_and(|e| dict.total >= e) {
                return Ok(false);
            }
            if dict.full() {
                flush(dict)?;
            }
            let pos = dict.total;
            let ps = self.pos_state(pos);
            let s = self.state;
            if rc.bit(input, &mut self.is_match[s * POS_STATES_MAX + ps])? == 0 {
                let prev = if dict.since_reset > 0 { dict.get(0) } else { 0 };
                let base = self.literal_base(pos, prev);
                let probs = &mut self.literal[base..base + 0x300];
                let mut sym = 1usize;
                if s >= 7 {
                    let mut mb = u32::from(dict.get(self.reps[0] as usize));
                    while sym < 0x100 {
                        let match_bit = ((mb >> 7) & 1) as usize;
                        mb <<= 1;
                        let b = rc.bit(input, &mut probs[((1 + match_bit) << 8) + sym])? as usize;
                        sym = (sym << 1) | b;
                        if match_bit != b {
                            break;
                        }
                    }
                }
                while sym < 0x100 {
                    sym = (sym << 1) | rc.bit(input, &mut probs[sym])? as usize;
                }
                dict.push(sym as u8);
                self.state = after_literal(s);
                continue;
            }
            let len;
            if rc.bit(input, &mut self.is_rep[s])? == 1 {
                if dict.since_reset == 0 {
                    return Err(Error::Corrupt);
                }
                if rc.bit(input, &mut self.is_rep_g0[s])? == 0 {
                    if rc.bit(input, &mut self.is_rep0_long[s * POS_STATES_MAX + ps])? == 0 {
                        self.state = after_short_rep(s);
                        let b = dict.get(self.reps[0] as usize);
                        dict.push(b);
                        continue;
                    }
                } else {
                    let dist;
                    if rc.bit(input, &mut self.is_rep_g1[s])? == 0 {
                        dist = self.reps[1];
                    } else {
                        if rc.bit(input, &mut self.is_rep_g2[s])? == 0 {
                            dist = self.reps[2];
                        } else {
                            dist = self.reps[3];
                            self.reps[3] = self.reps[2];
                        }
                        self.reps[2] = self.reps[1];
                    }
                    self.reps[1] = self.reps[0];
                    self.reps[0] = dist;
                }
                len = self.rep_len.decode(rc, input, ps)?;
                self.state = after_rep(s);
            } else {
                self.reps[3] = self.reps[2];
                self.reps[2] = self.reps[1];
                self.reps[1] = self.reps[0];
                len = self.len.decode(rc, input, ps)?;
                self.state = after_match(s);
                let d = self.distance(rc, input, len)?;
                if d == 0xFFFF_FFFF {
                    return if marker { Ok(true) } else { Err(Error::Corrupt) };
                }
                self.reps[0] = d;
            }
            let dist = self.reps[0] as usize;
            if dist as u64 >= dict.since_reset || dist >= dict.size || dist >= dict.buf.len() {
                return Err(Error::Corrupt);
            }
            let len = len + MATCH_MIN;
            if end.is_some_and(|e| dict.total + len as u64 > e) {
                return Err(Error::Corrupt);
            }
            let from = dict.buf.len() - dist - 1;
            if dist + 1 >= len {
                dict.buf.extend_from_within(from..from + len);
            } else {
                for k in 0..len {
                    let b = dict.buf[from + k];
                    dict.buf.push(b);
                }
            }
            dict.total += len as u64;
            dict.since_reset += len as u64;
        }
    }

    fn distance<S: Source>(&mut self, rc: &mut RangeDecoder, input: &mut Input<S>, len: usize) -> Result<u32, Error> {
        let len_state = len.min(3);
        let slot = rc.tree(input, &mut self.pos_slot[len_state], 6)?;
        if slot < 4 {
            return Ok(slot);
        }
        let direct = (slot >> 1) - 1;
        let mut dist = (2 | (slot & 1)) << direct;
        if slot < END_POS_MODEL {
            let base = (dist - slot) as usize;
            dist += rc.reverse(input, &mut self.pos_special[base..], direct)?;
        } else {
            dist += rc.direct(input, direct - ALIGN_BITS)? << ALIGN_BITS;
            dist += rc.reverse(input, &mut self.align, ALIGN_BITS)?;
        }
        Ok(dist)
    }
}

// --- Encoding ------------------------------------------------------------------------

fn pos_slot(dist: u32) -> u32 {
    if dist < 4 {
        return dist;
    }
    let n = 31 - dist.leading_zeros();
    (n << 1) | ((dist >> (n - 1)) & 1)
}

impl Model {
    fn encode_literal(&mut self, rc: &mut RangeEncoder, pos: u64, prev: u8, byte: u8, match_byte: Option<u8>) {
        let s = self.state;
        let ps = self.pos_state(pos);
        rc.bit(&mut self.is_match[s * POS_STATES_MAX + ps], 0);
        let base = self.literal_base(pos, prev);
        let probs = &mut self.literal[base..base + 0x300];
        let mut sym = 1usize;
        let mut i = 8;
        if let Some(mb) = match_byte.filter(|_| s >= 7) {
            let mut mb = u32::from(mb);
            let mut same = true;
            while i > 0 {
                i -= 1;
                let b = (u32::from(byte) >> i) & 1;
                if same {
                    let match_bit = ((mb >> 7) & 1) as usize;
                    mb <<= 1;
                    rc.bit(&mut probs[((1 + match_bit) << 8) + sym], b);
                    sym = (sym << 1) | b as usize;
                    same = match_bit == b as usize;
                } else {
                    rc.bit(&mut probs[sym], b);
                    sym = (sym << 1) | b as usize;
                }
            }
        } else {
            while i > 0 {
                i -= 1;
                let b = (u32::from(byte) >> i) & 1;
                rc.bit(&mut probs[sym], b);
                sym = (sym << 1) | b as usize;
            }
        }
        self.state = after_literal(s);
    }

    fn encode_match(&mut self, rc: &mut RangeEncoder, pos: u64, dist: u32, len: usize) {
        let s = self.state;
        let ps = self.pos_state(pos);
        rc.bit(&mut self.is_match[s * POS_STATES_MAX + ps], 1);
        rc.bit(&mut self.is_rep[s], 0);
        self.len.encode(rc, len, ps);
        let len_state = (len - MATCH_MIN).min(3);
        let slot = pos_slot(dist);
        rc.tree(&mut self.pos_slot[len_state], 6, slot);
        if slot >= 4 {
            let direct = (slot >> 1) - 1;
            let base = (2 | (slot & 1)) << direct;
            let rest = dist - base;
            if slot < END_POS_MODEL {
                rc.reverse(&mut self.pos_special[(base - slot) as usize..], direct, rest);
            } else {
                rc.direct(rest >> ALIGN_BITS, direct - ALIGN_BITS);
                rc.reverse(&mut self.align, ALIGN_BITS, rest & ((1 << ALIGN_BITS) - 1));
            }
        }
        self.reps = [dist, self.reps[0], self.reps[1], self.reps[2]];
        self.state = after_match(s);
    }

    /// A match at repeated distance `rep` (0 to 3); length 1 at rep 0 is
    /// a short rep.
    fn encode_rep(&mut self, rc: &mut RangeEncoder, pos: u64, rep: usize, len: usize) {
        let s = self.state;
        let ps = self.pos_state(pos);
        rc.bit(&mut self.is_match[s * POS_STATES_MAX + ps], 1);
        rc.bit(&mut self.is_rep[s], 1);
        if rep == 0 {
            rc.bit(&mut self.is_rep_g0[s], 0);
            rc.bit(&mut self.is_rep0_long[s * POS_STATES_MAX + ps], u32::from(len != 1));
            if len == 1 {
                self.state = after_short_rep(s);
                return;
            }
        } else {
            rc.bit(&mut self.is_rep_g0[s], 1);
            if rep == 1 {
                rc.bit(&mut self.is_rep_g1[s], 0);
            } else {
                rc.bit(&mut self.is_rep_g1[s], 1);
                rc.bit(&mut self.is_rep_g2[s], u32::from(rep == 3));
            }
            let d = self.reps[rep];
            for k in (1..=rep).rev() {
                self.reps[k] = self.reps[k - 1];
            }
            self.reps[0] = d;
        }
        self.rep_len.encode(rc, len, ps);
        self.state = after_rep(s);
    }

    /// The end marker (a match of distance 2^32 - 1).
    pub(crate) fn encode_end(&mut self, rc: &mut RangeEncoder, pos: u64) {
        let s = self.state;
        let ps = self.pos_state(pos);
        rc.bit(&mut self.is_match[s * POS_STATES_MAX + ps], 1);
        rc.bit(&mut self.is_rep[s], 0);
        self.len.encode(rc, MATCH_MIN, ps);
        rc.tree(&mut self.pos_slot[0], 6, 63);
        rc.direct(0x3FF_FFFF, 26);
        rc.reverse(&mut self.align, ALIGN_BITS, 15);
    }
}

/// How a level searches: dictionary size, chain length, the length that
/// ends the search, and whether to look one byte ahead first.
pub(crate) fn level_params(level: u32) -> (usize, usize, usize, bool) {
    match level {
        0 => (256 << 10, 4, 32, false),
        1 => (1 << 20, 8, 32, false),
        2 => (2 << 20, 16, 48, false),
        3 => (4 << 20, 16, 64, true),
        4 => (4 << 20, 32, 64, true),
        5 => (8 << 20, 48, 96, true),
        6 => (8 << 20, 64, 128, true),
        7 => (16 << 20, 96, 192, true),
        8 => (32 << 20, 128, 273, true),
        _ => (64 << 20, 256, 273, true),
    }
}

const HASH_BITS: u32 = 18;

/// The encoder's view of the input: the window, hash chains of
/// four-byte prefixes, and where encoding has reached (absolute
/// offsets).
pub(crate) struct Window {
    pub(crate) data: Vec<u8>,
    pub(crate) base: u64,
    pub(crate) pos: u64,
    dict_size: usize,
    head: Vec<u64>,
    /// The last position of each three-byte prefix (for short matches).
    head3: Vec<u64>,
    chain: Vec<u64>,
    depth: usize,
    nice: usize,
    lazy: bool,
}

const NONE: u64 = u64::MAX;

impl Window {
    pub(crate) fn new(level: u32) -> Window {
        let (dict_size, depth, nice, lazy) = level_params(level);
        Window {
            data: Vec::new(),
            base: 0,
            pos: 0,
            dict_size,
            head: vec![NONE; 1 << HASH_BITS],
            head3: vec![NONE; 1 << 16],
            chain: vec![NONE; dict_size],
            depth,
            nice,
            lazy,
        }
    }

    pub(crate) fn dict_size(&self) -> usize {
        self.dict_size
    }

    fn at(&self, abs: u64) -> u8 {
        self.data[(abs - self.base) as usize]
    }

    fn end(&self) -> u64 {
        self.base + self.data.len() as u64
    }

    fn hash(&self, abs: u64) -> Option<usize> {
        let i = (abs - self.base) as usize;
        let d = self.data.get(i..i + 4)?;
        let v = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
        Some((v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize)
    }

    fn hash3(&self, abs: u64) -> Option<usize> {
        let i = (abs - self.base) as usize;
        let d = self.data.get(i..i + 3)?;
        let v = u32::from(d[0]) | u32::from(d[1]) << 8 | u32::from(d[2]) << 16;
        Some((v.wrapping_mul(0x9E37_79B1) >> 16) as usize)
    }

    fn insert(&mut self, abs: u64) {
        if let Some(h) = self.hash3(abs) {
            self.head3[h] = abs;
        }
        if let Some(h) = self.hash(abs) {
            self.chain[(abs % self.dict_size as u64) as usize] = self.head[h];
            self.head[h] = abs;
        }
    }

    /// The length of the match at `abs` with distance `dist` + 1, at most
    /// `max`.
    fn match_len(&self, abs: u64, dist: u64, max: usize) -> usize {
        if dist + 1 > abs - self.base.max(abs.saturating_sub(self.dict_size as u64)) {
            return 0;
        }
        let i = (abs - self.base) as usize;
        let j = i - dist as usize - 1;
        let mut l = 0;
        while l < max && self.data[j + l] == self.data[i + l] {
            l += 1;
        }
        l
    }

    /// The longest match at `abs` from the chains: (length, distance - 1).
    fn longest(&self, abs: u64, max: usize) -> (usize, u32) {
        let (mut best, mut best_dist) = (0, 0u32);
        let lowest = abs.saturating_sub(self.dict_size as u64).max(self.base);
        // A three-byte match from the short table, if one is near.
        if let Some(h3) = self.hash3(abs) {
            let c = self.head3[h3];
            if c != NONE && c < abs && c >= lowest {
                let dist = abs - c - 1;
                let l = self.match_len(abs, dist, max);
                if l >= 3 {
                    (best, best_dist) = (l, dist as u32);
                }
            }
        }
        let Some(h) = self.hash(abs) else { return (best, best_dist) };
        let mut cand = self.head[h];
        let mut n = 0;
        while cand != NONE && cand < abs && cand >= lowest && n < self.depth {
            let dist = abs - cand - 1;
            let l = self.match_len(abs, dist, max);
            if l > best {
                best = l;
                best_dist = dist as u32;
                if l >= self.nice || l == max {
                    break;
                }
            }
            let next = self.chain[(cand % self.dict_size as u64) as usize];
            if next == NONE || next >= cand {
                break;
            }
            cand = next;
            n += 1;
        }
        (best, best_dist)
    }
}

/// One step's choice.
#[derive(Clone, Copy, Debug)]
enum Op {
    Literal,
    Match(u32, usize),
    Rep(usize, usize),
}

impl Model {
    /// Choose what to code at the window's position: the longest of the
    /// repeated distances and the chains' match, preferring a repeat that
    /// is nearly as long (it costs far less), else a literal or a short
    /// rep.
    fn choose(&self, w: &Window, max: usize) -> Op {
        let pos = w.pos;
        let (mut rep_len, mut rep_i) = (0, 0);
        for (i, &r) in self.reps.iter().enumerate() {
            let l = w.match_len(pos, u64::from(r), max);
            if l > rep_len {
                (rep_len, rep_i) = (l, i);
            }
        }
        if rep_len >= w.nice {
            return Op::Rep(rep_i, rep_len);
        }
        let (len, dist) = w.longest(pos, max);
        if len >= w.nice {
            return Op::Match(dist, len);
        }
        if rep_len >= 2 && rep_len + 1 >= len {
            return Op::Rep(rep_i, rep_len);
        }
        // Short matches far away cost more than literals.
        let worth = len >= 4 || (len == 3 && dist < 1 << 14) || (len == 2 && dist < 128);
        if worth {
            return Op::Match(dist, len);
        }
        if rep_len >= 2 {
            return Op::Rep(rep_i, rep_len);
        }
        if self.state >= 7 && w.match_len(pos, u64::from(self.reps[0]), 1) == 1 {
            return Op::Rep(0, 1);
        }
        Op::Literal
    }

    /// Code one step at the window's position into `rc`; the bytes it
    /// covered.
    pub(crate) fn step(&mut self, w: &mut Window, rc: &mut RangeEncoder, end: u64) -> usize {
        let max = ((end - w.pos) as usize).min(MATCH_MAX);
        let mut op = if max >= MATCH_MIN { self.choose(w, max) } else { Op::Literal };
        // Lazy: a better match one byte on makes this a literal.
        if w.lazy
            && let Op::Match(_, len) = op
            && len < w.nice
            && w.pos + 1 < end
        {
            w.insert(w.pos);
            w.pos += 1;
            let next_max = ((end - w.pos) as usize).min(MATCH_MAX);
            let (l2, _) = if next_max >= MATCH_MIN { w.longest(w.pos, next_max) } else { (0, 0) };
            w.pos -= 1;
            if l2 > len + 1 {
                op = Op::Literal;
            }
            return self.emit(w, rc, op, true);
        }
        self.emit(w, rc, op, false)
    }

    fn emit(&mut self, w: &mut Window, rc: &mut RangeEncoder, op: Op, inserted: bool) -> usize {
        let pos = w.pos;
        let prev = if pos > 0 && pos > w.base { w.at(pos - 1) } else { 0 };
        let n = match op {
            Op::Literal => {
                let mb = (pos > u64::from(self.reps[0]))
                    .then(|| w.data.get((pos - w.base) as usize - self.reps[0] as usize - 1).copied())
                    .flatten();
                self.encode_literal(rc, pos, prev, w.at(pos), mb);
                1
            }
            Op::Match(dist, len) => {
                self.encode_match(rc, pos, dist, len);
                len
            }
            Op::Rep(i, len) => {
                self.encode_rep(rc, pos, i, len);
                len
            }
        };
        for k in u64::from(inserted)..n as u64 {
            w.insert(pos + k);
        }
        w.pos += n as u64;
        n
    }
}

/// An LZMA2 encoder: input in, chunks out.
pub(crate) struct Lzma2Encoder {
    pub(crate) w: Window,
    model: Model,
    props: Props,
    /// The next chunk resets the dictionary, sends the properties, or
    /// resets the state.
    dict_reset: bool,
    need_props: bool,
    state_reset: bool,
}

/// An LZMA chunk holds at most 2 MiB of input and 64 KiB of output.
const CHUNK_IN: u64 = 1 << 21;
const CHUNK_OUT: usize = 1 << 16;

impl Lzma2Encoder {
    pub(crate) fn new(level: u32) -> Lzma2Encoder {
        let props = Props { lc: 3, lp: 0, pb: 2 };
        Lzma2Encoder {
            w: Window::new(level),
            model: Model::new(props),
            props,
            dict_reset: true,
            need_props: true,
            state_reset: true,
        }
    }

    /// The dictionary size property byte (the next size this format can
    /// say that is not smaller).
    pub(crate) fn dict_byte(&self) -> u8 {
        let size = self.w.dict_size() as u64;
        (0..40u8).find(|&b| (2 | u64::from(b & 1)) << (b / 2 + 11) >= size).unwrap_or(40)
    }

    pub(crate) fn write(&mut self, data: &[u8], out: &mut Vec<u8>) {
        self.w.data.extend_from_slice(data);
        // Keep MATCH_MAX bytes ahead so matches can run their full length.
        while self.w.end() - self.w.pos > (CHUNK_IN + MATCH_MAX as u64) {
            self.chunk(out, self.w.pos + CHUNK_IN);
        }
        self.trim();
    }

    pub(crate) fn finish(&mut self, out: &mut Vec<u8>) {
        while self.w.pos < self.w.end() {
            let end = self.w.end().min(self.w.pos + CHUNK_IN);
            self.chunk(out, end);
        }
        out.push(0);
    }

    /// Drop input the window no longer needs.
    fn trim(&mut self) {
        let keep_from = self.w.pos.saturating_sub(self.w.dict_size as u64 + 1);
        if keep_from > self.w.base + (8 << 20) {
            let n = (keep_from - self.w.base) as usize;
            self.w.data.drain(..n);
            self.w.base = keep_from;
        }
    }

    /// Code input up to `limit` (or until the chunk's output is full) as
    /// one chunk.
    fn chunk(&mut self, out: &mut Vec<u8>, limit: u64) {
        let start = self.w.pos;
        if self.state_reset {
            self.model = Model::new(self.props);
        }
        let mut rc = RangeEncoder::new();
        // Matches stop at the limit, so a chunk never takes too much.
        let end = self.w.end().min(limit);
        while self.w.pos < end && rc.pending() < CHUNK_OUT - 64 {
            self.model.step(&mut self.w, &mut rc, end);
        }
        let unpacked = (self.w.pos - start) as usize;
        let packed = rc.finish();
        let raw = &self.w.data[(start - self.w.base) as usize..(self.w.pos - self.w.base) as usize];
        if packed.len() >= unpacked || packed.len() > CHUNK_OUT {
            // Stored: in pieces of up to 64 KiB, the dictionary taking
            // them; the model's work on them is lost, so the next LZMA
            // chunk starts its state afresh.
            for (i, piece) in raw.chunks(CHUNK_OUT).enumerate() {
                out.push(if self.dict_reset && i == 0 { 1 } else { 2 });
                out.extend_from_slice(&((piece.len() - 1) as u16).to_be_bytes());
                out.extend_from_slice(piece);
            }
            self.dict_reset = false;
            self.state_reset = true;
            return;
        }
        let reset = if self.dict_reset {
            3
        } else if self.need_props {
            2
        } else if self.state_reset {
            1
        } else {
            0
        };
        let u = (unpacked - 1) as u32;
        out.push(0x80 | (reset << 5) | ((u >> 16) as u8 & 0x1F));
        out.extend_from_slice(&(u as u16).to_be_bytes());
        out.extend_from_slice(&((packed.len() - 1) as u16).to_be_bytes());
        if reset >= 2 {
            out.push(self.props.byte());
        }
        out.extend_from_slice(&packed);
        self.dict_reset = false;
        self.need_props = false;
        self.state_reset = false;
    }
}

/// An LZMA (`.lzma`) encoder: one range coder for the whole stream, an
/// end marker at the end.
pub(crate) struct LzmaEncoder {
    pub(crate) w: Window,
    model: Model,
    rc: RangeEncoder,
}

impl LzmaEncoder {
    pub(crate) fn new(level: u32) -> LzmaEncoder {
        LzmaEncoder { w: Window::new(level), model: Model::new(Props { lc: 3, lp: 0, pb: 2 }), rc: RangeEncoder::new() }
    }

    pub(crate) fn write(&mut self, data: &[u8], out: &mut Vec<u8>) {
        self.w.data.extend_from_slice(data);
        while self.w.end() - self.w.pos > MATCH_MAX as u64 {
            let end = self.w.end();
            self.model.step(&mut self.w, &mut self.rc, end);
        }
        // Bytes the coder will not change any more.
        let safe = self.rc.out.len();
        out.extend(self.rc.out.drain(..safe));
        let keep_from = self.w.pos.saturating_sub(self.w.dict_size as u64 + 1);
        if keep_from > self.w.base + (8 << 20) {
            let n = (keep_from - self.w.base) as usize;
            self.w.data.drain(..n);
            self.w.base = keep_from;
        }
    }

    pub(crate) fn finish(mut self, out: &mut Vec<u8>) {
        while self.w.pos < self.w.end() {
            let end = self.w.end();
            self.model.step(&mut self.w, &mut self.rc, end);
        }
        let pos = self.w.pos;
        self.model.encode_end(&mut self.rc, pos);
        out.extend(self.rc.finish());
    }
}
