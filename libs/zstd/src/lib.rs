// SPDX-License-Identifier: MIT OR Apache-2.0

//! Zstandard, ours, from RFC 8878, checked against the host's zstd.
//!
//! - A frame is a header (window size, content size and dictionary when
//!   given, whether a checksum follows), blocks (raw, a repeated byte, or
//!   compressed) and the low 32 bits of the content's XXH64. Skippable
//!   frames are skipped; frames that need a dictionary are refused.
//! - A compressed block is its literals (raw, repeated, or Huffman coded
//!   in one or four streams) and sequences: literal length, match length
//!   and offset codes, each coded by FSE with a predefined, repeated,
//!   single-symbol or described table, executed against the window.
//! - The encoder ([`Writer`]) finds matches in hash chains, using the
//!   repeated offsets first, and codes them with tables made for each
//!   block when that is smaller than the predefined ones; literals are
//!   Huffman coded when that pays.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod enc;
mod fse;
mod xxh;

use alloc::vec;
use alloc::vec::Vec;

pub use slate_flate::{Input, Sink, SliceSource, Source};

pub use crate::enc::{Writer, compress};
use crate::fse::{BitsBack, FseTable, Huff, LL_BASE, LL_BITS, LL_DEFAULT, ML_BASE, ML_BITS, ML_DEFAULT, OF_DEFAULT};
pub use crate::xxh::{Xxh64, xxh64};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not a zstd frame.
    NotZstd,
    Truncated,
    /// Something the format does not allow.
    Corrupt,
    /// The content's checksum does not match.
    Checksum,
    /// The frame needs a dictionary.
    Dictionary,
    /// The frame's window is larger than allowed.
    TooLarge,
    Io,
}

impl From<slate_flate::Error> for Error {
    fn from(e: slate_flate::Error) -> Error {
        match e {
            slate_flate::Error::Io => Error::Io,
            _ => Error::Corrupt,
        }
    }
}

pub const MAGIC: u32 = 0xFD2F_B528;
/// The largest window decoded without asking (zstd's default limit,
/// 2^27).
pub const MAX_WINDOW: u64 = 1 << 27;
const BLOCK_MAX: usize = 128 << 10;

fn need<S: Source>(input: &mut Input<S>) -> Result<u8, Error> {
    input.byte()?.ok_or(Error::Truncated)
}

fn read_le<S: Source>(input: &mut Input<S>, n: usize) -> Result<u64, Error> {
    let mut v = 0u64;
    for i in 0..n {
        v |= u64::from(need(input)?) << (8 * i);
    }
    Ok(v)
}

/// The decoder's state through a frame.
struct Frame {
    /// The window: output not yet written and the history matches reach.
    buf: Vec<u8>,
    out_from: usize,
    window: usize,
    total: u64,
    reps: [u64; 3],
    huff: Option<Huff>,
    ll: Option<FseTable>,
    of: Option<FseTable>,
    ml: Option<FseTable>,
    hash: Option<Xxh64>,
}

impl Frame {
    fn flush(&mut self, sink: &mut dyn FnMut(&[u8]) -> Result<(), Error>, keep: bool) -> Result<(), Error> {
        let data = &self.buf[self.out_from..];
        if let Some(h) = self.hash.as_mut() {
            h.update(data);
        }
        sink(data)?;
        let drop = if keep { self.buf.len().saturating_sub(self.window) } else { self.buf.len() };
        self.buf.drain(..drop);
        self.out_from = self.buf.len();
        Ok(())
    }
}

/// The literals section of a compressed block; the bytes it took.
fn literals(d: &[u8], f: &mut Frame, out: &mut Vec<u8>) -> Result<usize, Error> {
    let b0 = *d.first().ok_or(Error::Corrupt)?;
    let kind = b0 & 3;
    let sf = (b0 >> 2) & 3;
    let byte = |i: usize| -> Result<u32, Error> { d.get(i).map(|&b| u32::from(b)).ok_or(Error::Corrupt) };
    if kind < 2 {
        let (size, head) = match sf {
            0 | 2 => (u32::from(b0 >> 3), 1),
            1 => ((u32::from(b0) >> 4) | (byte(1)? << 4), 2),
            _ => ((u32::from(b0) >> 4) | (byte(1)? << 4) | (byte(2)? << 12), 3),
        };
        let size = size as usize;
        if size > BLOCK_MAX {
            return Err(Error::Corrupt);
        }
        if kind == 0 {
            out.extend_from_slice(d.get(head..head + size).ok_or(Error::Corrupt)?);
            return Ok(head + size);
        }
        let b = *d.get(head).ok_or(Error::Corrupt)?;
        out.resize(out.len() + size, b);
        return Ok(head + 1);
    }
    let (regen, comp, head, streams) = match sf {
        0 | 1 => {
            let v = u32::from(b0) | (byte(1)? << 8) | (byte(2)? << 16);
            ((v >> 4) & 0x3FF, (v >> 14) & 0x3FF, 3, if sf == 0 { 1 } else { 4 })
        }
        2 => {
            let v = u32::from(b0) | (byte(1)? << 8) | (byte(2)? << 16) | (byte(3)? << 24);
            ((v >> 4) & 0x3FFF, v >> 18, 4, 4)
        }
        _ => {
            let v = u64::from(b0)
                | (u64::from(byte(1)?) << 8)
                | (u64::from(byte(2)?) << 16)
                | (u64::from(byte(3)?) << 24)
                | (u64::from(byte(4)?) << 32);
            (((v >> 4) & 0x3FFFF) as u32, ((v >> 22) & 0x3FFFF) as u32, 5, 4)
        }
    };
    let (regen, comp) = (regen as usize, comp as usize);
    if regen > BLOCK_MAX {
        return Err(Error::Corrupt);
    }
    let body = d.get(head..head + comp).ok_or(Error::Corrupt)?;
    let mut at = 0;
    if kind == 2 {
        let (h, used) = Huff::read(body)?;
        f.huff = Some(h);
        at = used;
    }
    let huff = f.huff.as_ref().ok_or(Error::Corrupt)?;
    let rest = &body[at..];
    if streams == 1 {
        huff.stream(rest, regen, out)?;
    } else {
        let jump = rest.get(..6).ok_or(Error::Corrupt)?;
        let sizes = [
            usize::from(u16::from_le_bytes([jump[0], jump[1]])),
            usize::from(u16::from_le_bytes([jump[2], jump[3]])),
            usize::from(u16::from_le_bytes([jump[4], jump[5]])),
        ];
        let data = &rest[6..];
        let seg = regen.div_ceil(4);
        let mut start = 0;
        for (k, size) in [Some(sizes[0]), Some(sizes[1]), Some(sizes[2]), None].into_iter().enumerate() {
            let end = size.map_or(data.len(), |n| start + n);
            let n = if k < 3 { seg } else { regen.checked_sub(3 * seg).ok_or(Error::Corrupt)? };
            huff.stream(data.get(start..end).ok_or(Error::Corrupt)?, n, out)?;
            start = end;
        }
    }
    Ok(head + comp)
}

/// What a sequence table may be: its predefined distribution and log,
/// its largest code and log.
struct Kind {
    default: &'static [i16],
    default_log: u32,
    max_sym: usize,
    max_log: u32,
}

const LL_KIND: Kind = Kind { default: &LL_DEFAULT, default_log: 6, max_sym: 35, max_log: 9 };
const OF_KIND: Kind = Kind { default: &OF_DEFAULT, default_log: 5, max_sym: 31, max_log: 8 };
const ML_KIND: Kind = Kind { default: &ML_DEFAULT, default_log: 6, max_sym: 52, max_log: 9 };

/// One of the three sequence tables, as the modes byte says.
fn table(mode: u8, d: &[u8], at: &mut usize, prev: &mut Option<FseTable>, k: &Kind) -> Result<(), Error> {
    let (default, default_log, max_sym, max_log) = (k.default, k.default_log, k.max_sym, k.max_log);
    match mode {
        0 => *prev = Some(FseTable::build(default, default_log)?),
        1 => {
            let s = *d.get(*at).ok_or(Error::Corrupt)?;
            if usize::from(s) > max_sym {
                return Err(Error::Corrupt);
            }
            *at += 1;
            *prev = Some(FseTable::rle(s));
        }
        2 => {
            let (probs, log, used) = fse::read_dist(d.get(*at..).ok_or(Error::Corrupt)?, max_sym, max_log)?;
            *at += used;
            *prev = Some(FseTable::build(&probs, log)?);
        }
        _ => {
            if prev.is_none() {
                return Err(Error::Corrupt);
            }
        }
    }
    Ok(())
}

/// Decode and run a compressed block's sequences.
fn block(d: &[u8], f: &mut Frame) -> Result<(), Error> {
    let mut lits = Vec::new();
    let mut at = literals(d, f, &mut lits)?;
    let b0 = usize::from(*d.get(at).ok_or(Error::Corrupt)?);
    let byte = |i: usize| -> Result<usize, Error> { d.get(i).map(|&b| usize::from(b)).ok_or(Error::Corrupt) };
    let nseq = if b0 == 0 {
        at += 1;
        0
    } else if b0 < 128 {
        at += 1;
        b0
    } else if b0 < 255 {
        at += 2;
        ((b0 - 128) << 8) + byte(at - 1)?
    } else {
        at += 3;
        byte(at - 2)? + (byte(at - 1)? << 8) + 0x7F00
    };
    if nseq == 0 {
        f.buf.extend_from_slice(&lits);
        f.total += lits.len() as u64;
        return Ok(());
    }
    let modes = *d.get(at).ok_or(Error::Corrupt)?;
    at += 1;
    if modes & 3 != 0 {
        return Err(Error::Corrupt);
    }
    table(modes >> 6, d, &mut at, &mut f.ll, &LL_KIND)?;
    table((modes >> 4) & 3, d, &mut at, &mut f.of, &OF_KIND)?;
    table((modes >> 2) & 3, d, &mut at, &mut f.ml, &ML_KIND)?;
    let (ll, of, ml) = (
        f.ll.as_ref().ok_or(Error::Corrupt)?,
        f.of.as_ref().ok_or(Error::Corrupt)?,
        f.ml.as_ref().ok_or(Error::Corrupt)?,
    );
    let mut b = BitsBack::new(d.get(at..).ok_or(Error::Corrupt)?)?;
    let mut sll = b.read(ll.log) as usize;
    let mut sof = b.read(of.log) as usize;
    let mut sml = b.read(ml.log) as usize;
    let mut lit_at = 0usize;
    for i in 0..nseq {
        let (cll, cof, cml) = (ll.cells[sll], of.cells[sof], ml.cells[sml]);
        let ofc = u32::from(cof.sym);
        if ofc > 31 {
            return Err(Error::Corrupt);
        }
        let of_value = (1u64 << ofc) + b.read(ofc);
        let mlc = usize::from(cml.sym);
        let llc = usize::from(cll.sym);
        if mlc >= ML_BASE.len() || llc >= LL_BASE.len() {
            return Err(Error::Corrupt);
        }
        let mlen = ML_BASE[mlc] as usize + b.read(u32::from(ML_BITS[mlc])) as usize;
        let llen = LL_BASE[llc] as usize + b.read(u32::from(LL_BITS[llc])) as usize;
        // The offset, through the repeated ones (§3.1.1.5).
        let offset = if of_value > 3 {
            let o = of_value - 3;
            f.reps = [o, f.reps[0], f.reps[1]];
            o
        } else {
            let k = of_value as usize - 1 + usize::from(llen == 0);
            match k {
                0 => f.reps[0],
                1 => {
                    f.reps.swap(0, 1);
                    f.reps[0]
                }
                2 => {
                    let o = f.reps[2];
                    f.reps = [o, f.reps[0], f.reps[1]];
                    o
                }
                _ => {
                    let o = f.reps[0].checked_sub(1).filter(|&o| o > 0).ok_or(Error::Corrupt)?;
                    f.reps = [o, f.reps[0], f.reps[1]];
                    o
                }
            }
        };
        if i + 1 < nseq {
            sll = usize::from(cll.base) + b.read(u32::from(cll.bits)) as usize;
            sml = usize::from(cml.base) + b.read(u32::from(cml.bits)) as usize;
            sof = usize::from(cof.base) + b.read(u32::from(cof.bits)) as usize;
        }
        // Literals, then the match.
        let l = lits.get(lit_at..lit_at + llen).ok_or(Error::Corrupt)?;
        f.buf.extend_from_slice(l);
        lit_at += llen;
        f.total += llen as u64;
        let offset = offset as usize;
        if offset as u64 > f.total || offset > f.window || offset > f.buf.len() || offset == 0 {
            return Err(Error::Corrupt);
        }
        let from = f.buf.len() - offset;
        if offset >= mlen {
            f.buf.extend_from_within(from..from + mlen);
        } else {
            for k in 0..mlen {
                let c = f.buf[from + k];
                f.buf.push(c);
            }
        }
        f.total += mlen as u64;
    }
    if !b.done() {
        return Err(Error::Corrupt);
    }
    f.buf.extend_from_slice(&lits[lit_at..]);
    f.total += (lits.len() - lit_at) as u64;
    Ok(())
}

/// What a decompression found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Info {
    pub frames: u32,
    pub size: u64,
    /// Whether every frame carried a checksum.
    pub checksum: bool,
    pub used: u64,
}

/// Decompress every frame from `src` into `sink`, refusing windows over
/// `max_window`.
pub fn decompress_stream_limited<S: Source, K: Sink>(src: S, sink: &mut K, max_window: u64) -> Result<Info, Error> {
    let mut input = Input::new(src);
    let mut info = Info { checksum: true, ..Info::default() };
    let mut out = |d: &[u8]| sink.write(d).map_err(Error::from);
    loop {
        let mut m = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match input.byte()? {
                Some(b) => {
                    m[got] = b;
                    got += 1;
                }
                None => break,
            }
        }
        if got == 0 && info.frames > 0 {
            break;
        }
        if got < 4 {
            return Err(if info.frames == 0 { Error::NotZstd } else { Error::Truncated });
        }
        let magic = u32::from_le_bytes(m);
        if magic & 0xFFFF_FFF0 == 0x184D_2A50 {
            let n = read_le(&mut input, 4)?;
            for _ in 0..n {
                need(&mut input)?;
            }
            info.frames += 1;
            continue;
        }
        if magic != MAGIC {
            return Err(if info.frames == 0 { Error::NotZstd } else { Error::Corrupt });
        }
        let fhd = need(&mut input)?;
        if fhd & 0x08 != 0 {
            return Err(Error::Corrupt);
        }
        let single = fhd & 0x20 != 0;
        let window_desc = if single { None } else { Some(need(&mut input)?) };
        let did_len = [0, 1, 2, 4][usize::from(fhd & 3)];
        if read_le(&mut input, did_len)? != 0 {
            return Err(Error::Dictionary);
        }
        let fcs_len = match fhd >> 6 {
            0 => usize::from(single),
            1 => 2,
            2 => 4,
            _ => 8,
        };
        let mut content = if fcs_len > 0 { Some(read_le(&mut input, fcs_len)?) } else { None };
        if fcs_len == 2 {
            content = content.map(|c| c + 256);
        }
        let window = match window_desc {
            Some(w) => {
                let base = 1u64 << (10 + (w >> 3));
                base + (base / 8) * u64::from(w & 7)
            }
            None => content.unwrap_or(0),
        };
        if window > max_window {
            return Err(Error::TooLarge);
        }
        let checksum = fhd & 4 != 0;
        info.checksum &= checksum;
        let mut f = Frame {
            buf: Vec::new(),
            out_from: 0,
            window: window as usize,
            total: 0,
            reps: [1, 4, 8],
            huff: None,
            ll: None,
            of: None,
            ml: None,
            hash: checksum.then(|| Xxh64::new(0)),
        };
        let block_max = BLOCK_MAX.min((window as usize).max(1));
        loop {
            let h = read_le(&mut input, 3)? as u32;
            let last = h & 1 != 0;
            let size = (h >> 3) as usize;
            match (h >> 1) & 3 {
                0 => {
                    if size > block_max {
                        return Err(Error::Corrupt);
                    }
                    for _ in 0..size {
                        let b = need(&mut input)?;
                        f.buf.push(b);
                    }
                    f.total += size as u64;
                }
                1 => {
                    if size > block_max {
                        return Err(Error::Corrupt);
                    }
                    let b = need(&mut input)?;
                    f.buf.resize(f.buf.len() + size, b);
                    f.total += size as u64;
                }
                2 => {
                    if size > block_max {
                        return Err(Error::Corrupt);
                    }
                    let mut d = vec![0u8; size];
                    for x in d.iter_mut() {
                        *x = need(&mut input)?;
                    }
                    let before = f.total;
                    block(&d, &mut f)?;
                    if f.total - before > block_max as u64 {
                        return Err(Error::Corrupt);
                    }
                }
                _ => return Err(Error::Corrupt),
            }
            if f.buf.len() >= 2 * f.window.max(BLOCK_MAX) + (1 << 20) {
                f.flush(&mut out, true)?;
            }
            if last {
                break;
            }
        }
        f.flush(&mut out, false)?;
        if content.is_some_and(|c| c != f.total) {
            return Err(Error::Corrupt);
        }
        if let Some(h) = f.hash.take() {
            let want = read_le(&mut input, 4)? as u32;
            if h.finish() as u32 != want {
                return Err(Error::Checksum);
            }
        }
        info.size += f.total;
        info.frames += 1;
    }
    info.used = input.used();
    Ok(info)
}

pub fn decompress_stream<S: Source, K: Sink>(src: S, sink: &mut K) -> Result<Info, Error> {
    decompress_stream_limited(src, sink, MAX_WINDOW)
}

/// Decompress a whole zstd file in memory.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    decompress_stream(SliceSource::new(data), &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests;
