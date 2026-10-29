// SPDX-License-Identifier: MIT OR Apache-2.0

//! The xz format and the older lzma one, ours: written from the xz file
//! format specification (version 1.x, public) and the LZMA and LZMA2
//! descriptions published with it, checked against the host's xz.
//!
//! - An xz stream is a header (magic, flags, CRC32), blocks, an index of
//!   their sizes and a footer; streams may follow one another with zero
//!   padding between. A block names its filters (LZMA2 last, delta
//!   before it is taken; branch converters are not) and ends with a
//!   check of its data: CRC32, CRC64 or SHA-256 (others are skipped
//!   unchecked, as xz does).
//! - LZMA2 cuts LZMA into chunks of at most 2 MiB in and 64 KiB out, each
//!   resetting what it says (dictionary, properties, state) or stored.
//! - An lzma (`.lzma`) file is properties, dictionary size and length
//!   (or "unknown", then an end marker) before one LZMA stream.
//!
//! The encoder chooses matches greedily (with one byte of look-ahead at
//! the higher levels) from hash chains over the dictionary, not by the
//! cost search xz's own encoder makes, so its files are somewhat larger.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod lzma;

use alloc::vec;
use alloc::vec::Vec;

pub use slate_flate::{Input, Sink, SliceSource, Source};

use crate::lzma::{Dict, Lzma2Encoder, LzmaEncoder, Model, Props, RangeDecoder};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not an xz (or lzma) stream.
    NotXz,
    Truncated,
    /// Something the format does not allow.
    Corrupt,
    /// A block's check, or a header's CRC, does not match.
    Checksum,
    /// A filter this decoder does not have.
    UnsupportedFilter,
    /// The data needs more memory than allowed.
    TooLarge,
    Io,
}

impl From<slate_flate::Error> for Error {
    fn from(e: slate_flate::Error) -> Error {
        match e {
            slate_flate::Error::Io => Error::Io,
            slate_flate::Error::Truncated => Error::Truncated,
            _ => Error::Corrupt,
        }
    }
}

// --- Checks --------------------------------------------------------------------

const fn crc64_table() -> [u64; 256] {
    let mut t = [0u64; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u64;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xC96C_5795_D787_0F42 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[n] = c;
        n += 1;
    }
    t
}

static CRC64: [u64; 256] = crc64_table();

/// CRC-64 (ECMA-182, reflected, as xz uses it), continuing from `crc`.
pub fn crc64(crc: u64, data: &[u8]) -> u64 {
    let mut c = !crc;
    for &b in data {
        c = CRC64[((c ^ u64::from(b)) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

/// An integrity check's kind (the stream flags' low nibble).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    None,
    Crc32,
    Crc64,
    Sha256,
    /// One this decoder cannot compute: skipped, of this many bytes.
    Other(u8),
}

impl Check {
    fn from_id(id: u8) -> Check {
        match id {
            0 => Check::None,
            1 => Check::Crc32,
            4 => Check::Crc64,
            10 => Check::Sha256,
            n => Check::Other(n),
        }
    }

    fn id(self) -> u8 {
        match self {
            Check::None => 0,
            Check::Crc32 => 1,
            Check::Crc64 => 4,
            Check::Sha256 => 10,
            Check::Other(n) => n,
        }
    }

    fn size(self) -> usize {
        [0, 4, 4, 4, 8, 8, 8, 16, 16, 16, 32, 32, 32, 64, 64, 64][usize::from(self.id() & 15)]
    }

    pub fn name(self) -> &'static str {
        match self {
            Check::None => "None",
            Check::Crc32 => "CRC32",
            Check::Crc64 => "CRC64",
            Check::Sha256 => "SHA-256",
            Check::Other(_) => "Unknown",
        }
    }
}

/// A check being computed.
#[derive(Clone, Debug)]
enum Checker {
    None,
    Crc32(u32),
    Crc64(u64),
    Sha256(slate_hash::Sha256),
}

impl Checker {
    fn new(c: Check) -> Checker {
        match c {
            Check::Crc32 => Checker::Crc32(0),
            Check::Crc64 => Checker::Crc64(0),
            Check::Sha256 => Checker::Sha256(slate_hash::Sha256::new()),
            _ => Checker::None,
        }
    }

    fn update(&mut self, d: &[u8]) {
        match self {
            Checker::None => {}
            Checker::Crc32(c) => *c = slate_flate::crc32_update(*c, d),
            Checker::Crc64(c) => *c = crc64(*c, d),
            Checker::Sha256(h) => h.update(d),
        }
    }

    fn finish(self) -> Vec<u8> {
        match self {
            Checker::None => Vec::new(),
            Checker::Crc32(c) => c.to_le_bytes().to_vec(),
            Checker::Crc64(c) => c.to_le_bytes().to_vec(),
            Checker::Sha256(h) => h.finish().to_vec(),
        }
    }
}

// --- Reading -----------------------------------------------------------------------

const MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0];
const FOOTER_MAGIC: [u8; 2] = *b"YZ";
const FILTER_DELTA: u64 = 0x03;
const FILTER_LZMA2: u64 = 0x21;

fn need<S: Source>(input: &mut Input<S>) -> Result<u8, Error> {
    input.byte()?.ok_or(Error::Truncated)
}

fn read_n<S: Source>(input: &mut Input<S>, n: usize) -> Result<Vec<u8>, Error> {
    (0..n).map(|_| need(input)).collect()
}

/// A variable-length integer (seven bits a byte, least significant first).
fn varint(d: &[u8], at: &mut usize) -> Result<u64, Error> {
    let mut v = 0u64;
    for i in 0..9 {
        let b = *d.get(*at).ok_or(Error::Corrupt)?;
        *at += 1;
        v |= u64::from(b & 0x7F) << (7 * i);
        if b & 0x80 == 0 {
            if i > 0 && b == 0 {
                return Err(Error::Corrupt);
            }
            return Ok(v);
        }
    }
    Err(Error::Corrupt)
}

fn read_varint<S: Source>(input: &mut Input<S>, raw: &mut Vec<u8>) -> Result<u64, Error> {
    let mut v = 0u64;
    for i in 0..9 {
        let b = need(input)?;
        raw.push(b);
        v |= u64::from(b & 0x7F) << (7 * i);
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(Error::Corrupt)
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push(v as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// The dictionary size LZMA2's property byte stands for.
fn dict_size(b: u8) -> Result<usize, Error> {
    match b {
        0..40 => Ok(((2 | u64::from(b & 1)) << (b / 2 + 11)) as usize),
        40 => Ok(u32::MAX as usize),
        _ => Err(Error::Corrupt),
    }
}

/// Decoded data on its way out: through the delta filter if there is
/// one, into the check and the sink.
struct BlockOut<'k, K: Sink> {
    sink: &'k mut K,
    delta: Option<(usize, [u8; 256], u8)>,
    check: Checker,
    size: u64,
    scratch: Vec<u8>,
}

impl<K: Sink> BlockOut<'_, K> {
    fn put(&mut self, data: &[u8]) -> Result<(), Error> {
        let data = match &mut self.delta {
            Some((dist, hist, pos)) => {
                self.scratch.clear();
                for &b in data {
                    let v = b.wrapping_add(hist[usize::from(pos.wrapping_add(*dist as u8))]);
                    hist[usize::from(*pos)] = v;
                    *pos = pos.wrapping_sub(1);
                    self.scratch.push(v);
                }
                &self.scratch[..]
            }
            None => data,
        };
        self.check.update(data);
        self.size += data.len() as u64;
        self.sink.write(data).map_err(Error::from)
    }
}

/// Decode LZMA2 chunks until the end marker.
fn lzma2<S: Source>(
    input: &mut Input<S>,
    dict_bytes: usize,
    out: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut dict = Dict::new(dict_bytes);
    let mut model: Option<Model> = None;
    let mut first = true;
    loop {
        let control = need(input)?;
        if control == 0 {
            dict.flush(out)?;
            return Ok(());
        }
        if control == 1 || control == 2 {
            if first && control != 1 {
                return Err(Error::Corrupt);
            }
            if control == 1 {
                dict.reset();
            }
            let n = usize::from(u16::from_be_bytes([need(input)?, need(input)?])) + 1;
            let data = read_n(input, n)?;
            dict.copy_in(&data);
            if dict.full() {
                dict.flush(out)?;
            }
            first = false;
            continue;
        }
        if control < 0x80 {
            return Err(Error::Corrupt);
        }
        let reset = (control >> 5) & 3;
        if first && reset != 3 {
            return Err(Error::Corrupt);
        }
        first = false;
        let unpacked =
            ((u64::from(control & 0x1F) << 16) | u64::from(u16::from_be_bytes([need(input)?, need(input)?]))) + 1;
        let packed = u64::from(u16::from_be_bytes([need(input)?, need(input)?])) + 1;
        if reset >= 2 {
            let props = Props::from_byte(need(input)?)?;
            if props.lc + props.lp > 4 {
                return Err(Error::Corrupt);
            }
            model = Some(Model::new(props));
        } else if reset == 1 {
            let props = model.as_ref().map(|m| m.props_of()).ok_or(Error::Corrupt)?;
            model = Some(Model::new(props));
        }
        if reset == 3 {
            dict.reset();
        }
        let m = model.as_mut().ok_or(Error::Corrupt)?;
        let mut rc = RangeDecoder::new(input)?;
        let mut flush = |d: &mut Dict| d.flush(out);
        m.decode(&mut rc, input, &mut dict, Some(unpacked), false, &mut flush)?;
        if rc.read != packed || !rc.finished() {
            return Err(Error::Corrupt);
        }
    }
}

/// What a decompression found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Info {
    pub streams: u32,
    pub blocks: u32,
    pub size: u64,
    /// The last stream's check.
    pub check: Option<Check>,
    /// Bytes of input read.
    pub used: u64,
}

/// Decompress every xz stream from `src` into `sink`.
pub fn decompress_stream<S: Source, K: Sink>(src: S, sink: &mut K) -> Result<Info, Error> {
    let mut input = Input::new(src);
    let mut info = Info::default();
    loop {
        // A stream header, stream padding, or the end.
        let mut first = match input.byte()? {
            None if info.streams > 0 => break,
            None => return Err(Error::NotXz),
            Some(b) => b,
        };
        if info.streams > 0 {
            let mut zeros = 0u64;
            while first == 0 {
                zeros += 1;
                match input.byte()? {
                    Some(b) => first = b,
                    None if zeros % 4 == 0 => {
                        info.used = input.used();
                        return Ok(info);
                    }
                    None => return Err(Error::Corrupt),
                }
            }
            if zeros % 4 != 0 {
                return Err(Error::Corrupt);
            }
        }
        let mut head = vec![first];
        for _ in 0..11 {
            match input.byte()? {
                Some(b) => head.push(b),
                None if info.streams == 0 => return Err(Error::NotXz),
                None => return Err(Error::Truncated),
            }
        }
        if head[..6] != MAGIC {
            return Err(if info.streams == 0 { Error::NotXz } else { Error::Corrupt });
        }
        if slate_flate::crc32(&head[6..8]) != u32::from_le_bytes([head[8], head[9], head[10], head[11]]) {
            return Err(Error::Checksum);
        }
        if head[6] != 0 || head[7] & 0xF0 != 0 {
            return Err(Error::Corrupt);
        }
        let check = Check::from_id(head[7]);
        info.check = Some(check);
        let mut records: Vec<(u64, u64)> = Vec::new();
        // Blocks until the index's zero byte.
        loop {
            let size_byte = need(&mut input)?;
            if size_byte == 0 {
                break;
            }
            let header_len = (usize::from(size_byte) + 1) * 4;
            let mut h = vec![size_byte];
            h.extend(read_n(&mut input, header_len - 1)?);
            let body = &h[..header_len - 4];
            let crc = u32::from_le_bytes([h[header_len - 4], h[header_len - 3], h[header_len - 2], h[header_len - 1]]);
            if slate_flate::crc32(body) != crc {
                return Err(Error::Checksum);
            }
            let flags = h[1];
            if flags & 0x3C != 0 {
                return Err(Error::Corrupt);
            }
            let mut at = 2;
            let csize = if flags & 0x40 != 0 { Some(varint(body, &mut at)?) } else { None };
            let usize_ = if flags & 0x80 != 0 { Some(varint(body, &mut at)?) } else { None };
            let nfilters = usize::from(flags & 3) + 1;
            let mut delta = None;
            let mut dict_bytes = None;
            for i in 0..nfilters {
                let id = varint(body, &mut at)?;
                let plen = varint(body, &mut at)? as usize;
                let props = body.get(at..at + plen).ok_or(Error::Corrupt)?;
                at += plen;
                match id {
                    FILTER_LZMA2 if i + 1 == nfilters && plen == 1 => dict_bytes = Some(dict_size(props[0])?),
                    FILTER_DELTA if i + 1 < nfilters && plen == 1 && delta.is_none() => {
                        delta = Some((usize::from(props[0]) + 1, [0u8; 256], 0u8));
                    }
                    FILTER_LZMA2 | FILTER_DELTA => return Err(Error::Corrupt),
                    _ => return Err(Error::UnsupportedFilter),
                }
            }
            if body[at..].iter().any(|&b| b != 0) {
                return Err(Error::Corrupt);
            }
            let dict_bytes = dict_bytes.ok_or(Error::Corrupt)?;
            let data_start = input.used();
            let mut bo = BlockOut { sink, delta, check: Checker::new(check), size: 0, scratch: Vec::new() };
            lzma2(&mut input, dict_bytes, &mut |d| bo.put(d))?;
            let compressed = input.used() - data_start;
            if csize.is_some_and(|c| c != compressed) || usize_.is_some_and(|u| u != bo.size) {
                return Err(Error::Corrupt);
            }
            for _ in 0..(4 - compressed % 4) % 4 {
                if need(&mut input)? != 0 {
                    return Err(Error::Corrupt);
                }
            }
            let want = read_n(&mut input, check.size())?;
            let got = bo.check.finish();
            if !got.is_empty() && got != want {
                return Err(Error::Checksum);
            }
            info.size += bo.size;
            info.blocks += 1;
            // The unpadded size: header, data and check, without padding.
            records.push((header_len as u64 + compressed + check.size() as u64, bo.size));
        }
        // The index: its records must be the blocks'.
        let mut raw = vec![0u8];
        let count = read_varint(&mut input, &mut raw)?;
        if count != records.len() as u64 {
            return Err(Error::Corrupt);
        }
        for &(unpadded, size) in &records {
            if read_varint(&mut input, &mut raw)? != unpadded || read_varint(&mut input, &mut raw)? != size {
                return Err(Error::Corrupt);
            }
        }
        while raw.len() % 4 != 0 {
            let b = need(&mut input)?;
            if b != 0 {
                return Err(Error::Corrupt);
            }
            raw.push(b);
        }
        let crc = u32::from_le_bytes([need(&mut input)?, need(&mut input)?, need(&mut input)?, need(&mut input)?]);
        if slate_flate::crc32(&raw) != crc {
            return Err(Error::Checksum);
        }
        let index_size = raw.len() as u64 + 4;
        let foot = read_n(&mut input, 12)?;
        if foot[10..] != FOOTER_MAGIC
            || slate_flate::crc32(&foot[4..10]) != u32::from_le_bytes([foot[0], foot[1], foot[2], foot[3]])
        {
            return Err(Error::Corrupt);
        }
        let backward = (u64::from(u32::from_le_bytes([foot[4], foot[5], foot[6], foot[7]])) + 1) * 4;
        if backward != index_size || foot[8..10] != head[6..8] {
            return Err(Error::Corrupt);
        }
        info.streams += 1;
    }
    info.used = input.used();
    Ok(info)
}

/// Decompress a whole xz file in memory.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    decompress_stream(SliceSource::new(data), &mut out)?;
    Ok(out)
}

/// Decompress an lzma (`.lzma`) stream from `src` into `sink`.
pub fn decompress_lzma_stream<S: Source, K: Sink>(src: S, sink: &mut K) -> Result<u64, Error> {
    let mut input = Input::new(src);
    let mut head = Vec::new();
    for _ in 0..13 {
        head.push(input.byte()?.ok_or(Error::NotXz)?);
    }
    let props = Props::from_byte(head[0]).map_err(|_| Error::NotXz)?;
    let dict = u32::from_le_bytes([head[1], head[2], head[3], head[4]]);
    let size = u64::from_le_bytes([head[5], head[6], head[7], head[8], head[9], head[10], head[11], head[12]]);
    // Plausible sizes only (the format has no magic number).
    if size != u64::MAX && size > 1 << 56 {
        return Err(Error::NotXz);
    }
    let mut d = Dict::new((dict as usize).max(4096));
    let mut model = Model::new(props);
    let mut rc = RangeDecoder::new(&mut input)?;
    let mut out = |data: &[u8]| sink.write(data).map_err(Error::from);
    {
        let mut flush = |dd: &mut Dict| dd.flush(&mut out);
        let want = (size != u64::MAX).then_some(size);
        model.decode(&mut rc, &mut input, &mut d, want, want.is_none(), &mut flush)?;
    }
    let total = d.total;
    d.flush(&mut out)?;
    Ok(total)
}

pub fn decompress_lzma(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    decompress_lzma_stream(SliceSource::new(data), &mut out)?;
    Ok(out)
}

// --- Writing ------------------------------------------------------------------------

/// An xz stream written as it is fed: one block of LZMA2.
pub struct XzWriter {
    enc: Lzma2Encoder,
    check: Check,
    checker: Checker,
    started: bool,
    any: bool,
    /// The block's sizes so far: its header, compressed and plain.
    header_len: u64,
    compressed: u64,
    size: u64,
}

impl core::fmt::Debug for XzWriter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XzWriter").field("size", &self.size).finish()
    }
}

impl XzWriter {
    /// A writer at preset `level` (0 to 9) with `check`.
    pub fn new(level: u32, check: Check) -> XzWriter {
        XzWriter {
            enc: Lzma2Encoder::new(level),
            check,
            checker: Checker::new(check),
            started: false,
            any: false,
            header_len: 0,
            compressed: 0,
            size: 0,
        }
    }

    fn stream_header(&mut self, out: &mut Vec<u8>) {
        if self.started {
            return;
        }
        self.started = true;
        out.extend_from_slice(&MAGIC);
        let flags = [0, self.check.id()];
        out.extend_from_slice(&flags);
        out.extend_from_slice(&slate_flate::crc32(&flags).to_le_bytes());
    }

    fn block_header(&mut self, out: &mut Vec<u8>) {
        let mut h = vec![0u8, 0x00];
        put_varint(&mut h, FILTER_LZMA2);
        put_varint(&mut h, 1);
        h.push(self.enc.dict_byte());
        while (h.len() + 4) % 4 != 0 {
            h.push(0);
        }
        h[0] = ((h.len() + 4) / 4 - 1) as u8;
        let crc = slate_flate::crc32(&h);
        h.extend_from_slice(&crc.to_le_bytes());
        self.header_len = h.len() as u64;
        out.extend_from_slice(&h);
    }

    pub fn write(&mut self, data: &[u8], out: &mut Vec<u8>) {
        self.stream_header(out);
        if data.is_empty() {
            return;
        }
        if !self.any {
            self.any = true;
            self.block_header(out);
        }
        self.checker.update(data);
        self.size += data.len() as u64;
        let before = out.len();
        self.enc.write(data, out);
        self.compressed += (out.len() - before) as u64;
    }

    pub fn finish(mut self, out: &mut Vec<u8>) {
        self.stream_header(out);
        let mut records = Vec::new();
        if self.any {
            let before = out.len();
            self.enc.finish(out);
            self.compressed += (out.len() - before) as u64;
            out.extend(core::iter::repeat_n(0u8, ((4 - self.compressed % 4) % 4) as usize));
            let check = core::mem::replace(&mut self.checker, Checker::None).finish();
            out.extend_from_slice(&check);
            records.push((self.header_len + self.compressed + check.len() as u64, self.size));
        }
        let mut index = vec![0u8];
        put_varint(&mut index, records.len() as u64);
        for (u, s) in &records {
            put_varint(&mut index, *u);
            put_varint(&mut index, *s);
        }
        while index.len() % 4 != 0 {
            index.push(0);
        }
        let crc = slate_flate::crc32(&index);
        index.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&index);
        let mut foot = Vec::new();
        foot.extend_from_slice(&((index.len() / 4 - 1) as u32).to_le_bytes());
        foot.extend_from_slice(&[0, self.check.id()]);
        out.extend_from_slice(&slate_flate::crc32(&foot).to_le_bytes());
        out.extend_from_slice(&foot);
        out.extend_from_slice(&FOOTER_MAGIC);
    }
}

/// Compress `data` as an xz file at `level`, with a CRC64 check.
pub fn compress(data: &[u8], level: u32) -> Vec<u8> {
    let mut w = XzWriter::new(level, Check::Crc64);
    let mut out = Vec::new();
    for chunk in data.chunks(4 << 20) {
        w.write(chunk, &mut out);
    }
    w.finish(&mut out);
    out
}

/// An lzma (`.lzma`) file written as it is fed: its length unknown, so
/// the stream ends with an end marker.
pub struct LzmaWriter {
    enc: Option<LzmaEncoder>,
    started: bool,
}

impl core::fmt::Debug for LzmaWriter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LzmaWriter").finish()
    }
}

impl LzmaWriter {
    pub fn new(level: u32) -> LzmaWriter {
        LzmaWriter { enc: Some(LzmaEncoder::new(level)), started: false }
    }

    fn header(&mut self, out: &mut Vec<u8>) {
        if self.started {
            return;
        }
        self.started = true;
        let dict = self.enc.as_ref().map_or(1 << 23, |e| e.w.dict_size()) as u32;
        out.push(Props { lc: 3, lp: 0, pb: 2 }.byte());
        out.extend_from_slice(&dict.to_le_bytes());
        out.extend_from_slice(&u64::MAX.to_le_bytes());
    }

    pub fn write(&mut self, data: &[u8], out: &mut Vec<u8>) {
        self.header(out);
        if let Some(e) = self.enc.as_mut() {
            e.write(data, out);
        }
    }

    pub fn finish(mut self, out: &mut Vec<u8>) {
        self.header(out);
        if let Some(e) = self.enc.take() {
            e.finish(out);
        }
    }
}

pub fn compress_lzma(data: &[u8], level: u32) -> Vec<u8> {
    let mut w = LzmaWriter::new(level);
    let mut out = Vec::new();
    w.write(data, &mut out);
    w.finish(&mut out);
    out
}

/// What `xz -l` shows of a file: its streams, blocks, sizes and check.
pub fn list(data: &[u8]) -> Result<Info, Error> {
    let mut sink = Counter(0);
    let mut info = decompress_stream(SliceSource::new(data), &mut sink)?;
    info.size = sink.0;
    Ok(info)
}

struct Counter(u64);

impl Sink for Counter {
    fn write(&mut self, d: &[u8]) -> Result<(), slate_flate::Error> {
        self.0 += d.len() as u64;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
