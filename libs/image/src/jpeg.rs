// SPDX-License-Identifier: MIT OR Apache-2.0

//! JPEG (ITU-T T.81): Huffman-coded DCT images, baseline, extended
//! (SOF1) and progressive (SOF2), with one component (grey) or three
//! (YCbCr as JFIF 1.02 defines it, or RGB when an Adobe APP14 segment
//! says so), any sampling factors, and restart intervals. Exif's
//! orientation tag turns the picture upright.
//!
//! Every scan decodes into each component's coefficients; the inverse
//! DCT (A.3.3) runs once at the end, so baseline and progressive take
//! the same path. Chroma planes are upsampled by interpolating between
//! sample centres (JFIF's siting).
//!
//! Not read: arithmetic coding, lossless and hierarchical modes, 12-bit
//! samples, four components (CMYK).

use alloc::vec::Vec;

use crate::{Error, Image, Reader, argb};

/// Figure A.6: the zig-zag order, as natural (row-major) indices.
const ZIGZAG: [u8; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21,
    28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54,
    47, 55, 62, 63,
];

/// Bits of a lookup in a Huffman table's fast path.
const FAST: u32 = 9;

/// A Huffman table (C.2, F.2.2.3): codes up to [`FAST`] bits by lookup,
/// longer ones by the per-length code ranges.
#[derive(Clone, Debug)]
struct Huffman {
    /// For each FAST-bit prefix: the code's length (0: longer) and value.
    fast: Vec<(u8, u8)>,
    /// For lengths 1..=16: the largest code (-1: none), the first code,
    /// and the index of its value.
    maxcode: [i32; 17],
    mincode: [i32; 17],
    valptr: [usize; 17],
    values: Vec<u8>,
}

impl Huffman {
    fn new(counts: &[u8; 16], values: &[u8]) -> Result<Huffman, Error> {
        let mut h = Huffman {
            fast: alloc::vec![(0, 0); 1 << FAST],
            maxcode: [-1; 17],
            mincode: [0; 17],
            valptr: [0; 17],
            values: values.to_vec(),
        };
        let mut code = 0i32;
        let mut k = 0usize;
        for len in 1..=16usize {
            let n = usize::from(counts[len - 1]);
            h.valptr[len] = k;
            h.mincode[len] = code;
            for _ in 0..n {
                if code >= 1 << len {
                    return Err(Error::Invalid);
                }
                if len as u32 <= FAST {
                    let shift = FAST - len as u32;
                    let start = (code as usize) << shift;
                    for e in &mut h.fast[start..start + (1 << shift)] {
                        *e = (len as u8, values[k]);
                    }
                }
                code += 1;
                k += 1;
            }
            if n > 0 {
                h.maxcode[len] = code - 1;
            }
            code <<= 1;
        }
        Ok(h)
    }
}

/// The entropy-coded data's bits (F.2.2.5), with stuffed zero bytes
/// taken out. At a marker, or the data's end, it reads zeros (a damaged
/// stream decodes to something, never past the slice).
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    acc: u32,
    n: u32,
    at_marker: bool,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8], pos: usize) -> Bits<'a> {
        Bits { data, pos, acc: 0, n: 0, at_marker: false }
    }

    fn fill(&mut self) {
        while self.n <= 24 {
            let mut b = 0u8;
            if !self.at_marker {
                match self.data.get(self.pos) {
                    Some(&0xFF) => {
                        if self.data.get(self.pos + 1) == Some(&0) {
                            self.pos += 2;
                            b = 0xFF;
                        } else {
                            self.at_marker = true;
                        }
                    }
                    Some(&v) => {
                        self.pos += 1;
                        b = v;
                    }
                    None => self.at_marker = true,
                }
            }
            self.acc |= u32::from(b) << (24 - self.n);
            self.n += 8;
        }
    }

    fn peek(&mut self, k: u32) -> u32 {
        self.fill();
        self.acc >> (32 - k)
    }

    fn skip(&mut self, k: u32) {
        self.acc <<= k;
        self.n -= k;
    }

    fn bits(&mut self, k: u32) -> u32 {
        if k == 0 {
            return 0;
        }
        let v = self.peek(k);
        self.skip(k);
        v
    }

    fn bit(&mut self) -> bool {
        self.bits(1) == 1
    }

    /// F.2.2.1 RECEIVE and EXTEND: `s` bits as a signed value.
    fn receive_extend(&mut self, s: u32) -> i32 {
        if s == 0 || s > 16 {
            return 0;
        }
        let v = self.bits(s) as i32;
        if v < 1 << (s - 1) { v - (1 << s) + 1 } else { v }
    }

    /// F.16 DECODE.
    fn decode(&mut self, h: &Huffman) -> Result<u8, Error> {
        let p = self.peek(16);
        let (len, v) = h.fast[(p >> (16 - FAST)) as usize];
        if len > 0 {
            self.skip(u32::from(len));
            return Ok(v);
        }
        for len in FAST as usize + 1..=16 {
            let code = (p >> (16 - len)) as i32;
            if code <= h.maxcode[len] {
                self.skip(len as u32);
                let i = h.valptr[len] + (code - h.mincode[len]) as usize;
                return h.values.get(i).copied().ok_or(Error::Invalid);
            }
        }
        Err(Error::Invalid)
    }

    /// At a restart interval's end: past the RSTn marker (E.2.4), the
    /// bits thrown away.
    fn restart(&mut self) {
        self.acc = 0;
        self.n = 0;
        self.at_marker = false;
        // Skip to the marker (fill bytes 0xFF may come before it).
        while self.pos + 1 < self.data.len() {
            if self.data[self.pos] == 0xFF && (0xD0..=0xD7).contains(&self.data[self.pos + 1]) {
                self.pos += 2;
                return;
            }
            if self.data[self.pos] == 0xFF && self.data[self.pos + 1] != 0 && self.data[self.pos + 1] != 0xFF {
                // Another marker: the data is short; leave it.
                return;
            }
            self.pos += 1;
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Component {
    id: u8,
    h: usize,
    v: usize,
    tq: usize,
    /// Blocks per line and lines of blocks, padded to whole MCUs.
    bw: usize,
    bh: usize,
    /// The coefficients, 64 a block in natural order.
    coef: Vec<i16>,
    /// DC prediction, and the tables of the scan under way.
    pred: i32,
    td: usize,
    ta: usize,
}

struct Frame {
    width: usize,
    height: usize,
    progressive: bool,
    comps: Vec<Component>,
    hmax: usize,
    vmax: usize,
    mcux: usize,
    mcuy: usize,
}

struct Scan {
    comps: Vec<usize>,
    ss: usize,
    se: usize,
    ah: u32,
    al: u32,
}

struct Decoder {
    frame: Frame,
    dc: [Option<Huffman>; 4],
    ac: [Option<Huffman>; 4],
    eobrun: u32,
}

impl Decoder {
    fn block(&mut self, bits: &mut Bits<'_>, scan: &Scan, ci: usize, bx: usize, by: usize) -> Result<(), Error> {
        let c = &mut self.frame.comps[ci];
        let at = (by * c.bw + bx) * 64;
        let Some(coef) = c.coef.get_mut(at..at + 64) else { return Ok(()) };
        if !self.frame.progressive {
            // F.2.2: a whole block, DC then AC.
            let dc = self.dc[c.td].as_ref().ok_or(Error::Invalid)?;
            let t = u32::from(bits.decode(dc)?);
            c.pred += bits.receive_extend(t);
            coef[0] = c.pred as i16;
            let ac = self.ac[c.ta].as_ref().ok_or(Error::Invalid)?;
            let mut k = 1;
            while k < 64 {
                let rs = bits.decode(ac)?;
                let (r, s) = (usize::from(rs >> 4), u32::from(rs & 15));
                if s == 0 {
                    if r != 15 {
                        break;
                    }
                    k += 16;
                    continue;
                }
                k += r;
                if k > 63 {
                    return Err(Error::Invalid);
                }
                coef[usize::from(ZIGZAG[k])] = bits.receive_extend(s) as i16;
                k += 1;
            }
            return Ok(());
        }
        // G.1.2: progressive scans.
        if scan.ss == 0 {
            if scan.ah == 0 {
                let dc = self.dc[c.td].as_ref().ok_or(Error::Invalid)?;
                let t = u32::from(bits.decode(dc)?);
                c.pred += bits.receive_extend(t);
                coef[0] = (c.pred << scan.al) as i16;
            } else if bits.bit() {
                coef[0] |= 1 << scan.al;
            }
            return Ok(());
        }
        let ac = self.ac[c.ta].as_ref().ok_or(Error::Invalid)?;
        if scan.ah == 0 {
            // G.1.2.2: the first pass over a band.
            if self.eobrun > 0 {
                self.eobrun -= 1;
                return Ok(());
            }
            let mut k = scan.ss;
            while k <= scan.se {
                let rs = bits.decode(ac)?;
                let (r, s) = (u32::from(rs >> 4), u32::from(rs & 15));
                if s == 0 {
                    if r < 15 {
                        self.eobrun = (1 << r) - 1 + bits.bits(r);
                        break;
                    }
                    k += 16;
                    continue;
                }
                k += r as usize;
                if k > 63 {
                    return Err(Error::Invalid);
                }
                coef[usize::from(ZIGZAG[k])] = (bits.receive_extend(s) << scan.al) as i16;
                k += 1;
            }
            return Ok(());
        }
        // G.1.2.3: refining a band, one bit more of every coefficient.
        let p1 = 1i16 << scan.al;
        let m1 = -1i16 << scan.al;
        let refine = |c: &mut i16, bits: &mut Bits<'_>| {
            if bits.bit() && *c & p1 == 0 {
                *c += if *c >= 0 { p1 } else { m1 };
            }
        };
        let mut k = scan.ss;
        if self.eobrun == 0 {
            while k <= scan.se {
                let rs = bits.decode(ac)?;
                let (mut r, s) = (u32::from(rs >> 4), rs & 15);
                let mut value = 0i16;
                if s == 0 {
                    if r < 15 {
                        self.eobrun = (1 << r) + bits.bits(r);
                        break;
                    }
                } else {
                    value = if bits.bit() { p1 } else { m1 };
                }
                while k <= scan.se {
                    let z = usize::from(ZIGZAG[k]);
                    if coef[z] != 0 {
                        refine(&mut coef[z], bits);
                    } else {
                        if r == 0 {
                            if value != 0 {
                                coef[z] = value;
                            }
                            k += 1;
                            break;
                        }
                        r -= 1;
                    }
                    k += 1;
                }
            }
        }
        if self.eobrun > 0 {
            while k <= scan.se {
                let z = usize::from(ZIGZAG[k]);
                if coef[z] != 0 {
                    refine(&mut coef[z], bits);
                }
                k += 1;
            }
            self.eobrun -= 1;
        }
        Ok(())
    }

    /// Decode one scan's entropy-coded data from `pos`; where it ended.
    fn scan(&mut self, data: &[u8], pos: usize, scan: &Scan, restart: usize) -> Result<usize, Error> {
        let mut bits = Bits::new(data, pos);
        self.eobrun = 0;
        for &ci in &scan.comps {
            self.frame.comps[ci].pred = 0;
        }
        let f = &self.frame;
        let (units, single) = if scan.comps.len() == 1 {
            // A non-interleaved scan covers the component's own blocks,
            // not the MCUs' padding (A.2.2).
            let c = &f.comps[scan.comps[0]];
            let w = (f.width * c.h).div_ceil(f.hmax).div_ceil(8);
            let h = (f.height * c.v).div_ceil(f.vmax).div_ceil(8);
            ((w, h), true)
        } else {
            ((f.mcux, f.mcuy), false)
        };
        let mut count = 0usize;
        for uy in 0..units.1 {
            for ux in 0..units.0 {
                if restart > 0 && count > 0 && count % restart == 0 {
                    bits.restart();
                    self.eobrun = 0;
                    for &ci in &scan.comps {
                        self.frame.comps[ci].pred = 0;
                    }
                }
                count += 1;
                if single {
                    self.block(&mut bits, scan, scan.comps[0], ux, uy)?;
                } else {
                    for &ci in &scan.comps {
                        let (h, v) = (self.frame.comps[ci].h, self.frame.comps[ci].v);
                        for y in 0..v {
                            for x in 0..h {
                                self.block(&mut bits, scan, ci, ux * h + x, uy * v + y)?;
                            }
                        }
                    }
                }
            }
        }
        // The data runs to the next marker.
        let mut p = bits.pos;
        while p + 1 < data.len() && !(data[p] == 0xFF && data[p + 1] != 0 && !(0xD0..=0xD7).contains(&data[p + 1])) {
            p += 1;
        }
        Ok(p)
    }
}

/// A.3.3: the inverse DCT's cosines, C(u)/2 · cos((2x+1)uπ/16).
fn idct_table() -> [[f32; 8]; 8] {
    let mut t = [[0.0f32; 8]; 8];
    for (x, row) in t.iter_mut().enumerate() {
        for (u, v) in row.iter_mut().enumerate() {
            let c = if u == 0 { core::f64::consts::FRAC_1_SQRT_2 } else { 1.0 };
            let a = (2 * x + 1) as f64 * u as f64 * core::f64::consts::PI / 16.0;
            *v = (c / 2.0 * slate_math::cos_(a)) as f32;
        }
    }
    t
}

/// One block's samples from its dequantized coefficients.
fn idct(t: &[[f32; 8]; 8], f: &[f32; 64], out: &mut [u8], stride: usize) {
    let mut tmp = [0.0f32; 64];
    // Rows of the result over columns of frequencies, then the other way.
    for v in 0..8 {
        for x in 0..8 {
            let mut s = 0.0;
            for u in 0..8 {
                s += t[x][u] * f[v * 8 + u];
            }
            tmp[v * 8 + x] = s;
        }
    }
    for y in 0..8 {
        for x in 0..8 {
            let mut s = 0.0;
            for v in 0..8 {
                s += t[y][v] * tmp[v * 8 + x];
            }
            out[y * stride + x] = (s + 128.5).clamp(0.0, 255.0) as u8;
        }
    }
}

/// Exif's orientation (TIFF tag 0x0112 in IFD0 of an APP1 "Exif"
/// segment), 1 to 8.
fn exif_orientation(app1: &[u8]) -> Option<u16> {
    let tiff = app1.strip_prefix(b"Exif\0\0")?;
    let le = match tiff.get(..2)? {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    let u16_at = |p: usize| -> Option<u16> {
        let b = tiff.get(p..p + 2)?;
        Some(if le { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) })
    };
    let u32_at = |p: usize| -> Option<u32> {
        let b = tiff.get(p..p + 4)?;
        let a = [b[0], b[1], b[2], b[3]];
        Some(if le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) })
    };
    let ifd = u32_at(4)? as usize;
    let n = usize::from(u16_at(ifd)?);
    for i in 0..n.min(512) {
        let e = ifd + 2 + i * 12;
        if u16_at(e)? == 0x0112 {
            return u16_at(e + 8).filter(|o| (1..=8).contains(o));
        }
    }
    None
}

pub fn decode(data: &[u8]) -> Result<Image, Error> {
    let mut r = Reader::new(data);
    if r.be16()? != 0xFFD8 {
        return Err(Error::Unknown);
    }
    let mut quant = [[0u16; 64]; 4];
    let mut d = Decoder { frame: Frame::empty(), dc: Default::default(), ac: Default::default(), eobrun: 0 };
    let mut have_frame = false;
    let mut restart = 0usize;
    let mut adobe: Option<u8> = None;
    let mut orientation = 1u16;
    let mut scans = 0;
    loop {
        // Fill bytes (0xFF) may come before a marker.
        let mut m = r.u8()?;
        if m != 0xFF {
            return Err(Error::Invalid);
        }
        while m == 0xFF {
            m = r.u8()?;
        }
        match m {
            0xD9 => break,
            0xD0..=0xD7 | 0x01 => continue,
            _ => {}
        }
        let len = usize::from(r.be16()?);
        let body = r.bytes(len.checked_sub(2).ok_or(Error::Invalid)?)?;
        let mut b = Reader::new(body);
        match m {
            // DQT (B.2.4.1): tables in zig-zag order, 8 or 16 bits.
            0xDB => {
                while b.pos < body.len() {
                    let pq_tq = b.u8()?;
                    let t = usize::from(pq_tq & 15);
                    if t > 3 {
                        return Err(Error::Invalid);
                    }
                    for k in 0..64 {
                        let q = if pq_tq >> 4 == 0 { u16::from(b.u8()?) } else { b.be16()? };
                        quant[t][usize::from(ZIGZAG[k])] = q;
                    }
                }
            }
            // DHT (B.2.4.2).
            0xC4 => {
                while b.pos < body.len() {
                    let tc_th = b.u8()?;
                    let (class, th) = (tc_th >> 4, usize::from(tc_th & 15));
                    if class > 1 || th > 3 {
                        return Err(Error::Invalid);
                    }
                    let counts: [u8; 16] = b.bytes(16)?.try_into().map_err(|_| Error::Truncated)?;
                    let n: usize = counts.iter().map(|&c| usize::from(c)).sum();
                    if n > 256 {
                        return Err(Error::Invalid);
                    }
                    let h = Huffman::new(&counts, b.bytes(n)?)?;
                    if class == 0 {
                        d.dc[th] = Some(h);
                    } else {
                        d.ac[th] = Some(h);
                    }
                }
            }
            // DRI (B.2.4.4).
            0xDD => restart = usize::from(b.be16()?),
            0xE1 => {
                if let Some(o) = exif_orientation(body) {
                    orientation = o;
                }
            }
            // Adobe's APP14: its transform flag says whether three
            // components are YCbCr (1) or RGB (0).
            0xEE if body.starts_with(b"Adobe") && body.len() >= 12 => adobe = Some(body[11]),
            0xC0..=0xC2 => {
                if have_frame {
                    return Err(Error::Invalid);
                }
                let precision = b.u8()?;
                let (height, width) = (usize::from(b.be16()?), usize::from(b.be16()?));
                let n = usize::from(b.u8()?);
                if precision != 8 {
                    return Err(Error::Unsupported);
                }
                if height == 0 {
                    // A height given later by DNL (B.2.5): not read.
                    return Err(Error::Unsupported);
                }
                crate::check_size(width as u32, height as u32)?;
                if n != 1 && n != 3 {
                    return Err(Error::Unsupported);
                }
                let mut comps = Vec::new();
                for _ in 0..n {
                    let (id, hv, tq) = (b.u8()?, b.u8()?, b.u8()?);
                    let (h, v) = (usize::from(hv >> 4), usize::from(hv & 15));
                    if !(1..=4).contains(&h) || !(1..=4).contains(&v) || tq > 3 {
                        return Err(Error::Invalid);
                    }
                    comps.push(Component { id, h, v, tq: usize::from(tq), ..Component::default() });
                }
                // A single component is never interleaved: its blocks
                // are its own, whatever its factors say (A.2.2).
                if n == 1 {
                    comps[0].h = 1;
                    comps[0].v = 1;
                }
                let hmax = comps.iter().map(|c| c.h).max().unwrap_or(1);
                let vmax = comps.iter().map(|c| c.v).max().unwrap_or(1);
                let (mcux, mcuy) = (width.div_ceil(8 * hmax), height.div_ceil(8 * vmax));
                let mut total = 0usize;
                for c in &mut comps {
                    c.bw = mcux * c.h;
                    c.bh = mcuy * c.v;
                    total += c.bw * c.bh * 64;
                }
                if total as u64 > crate::MAX_PIXELS * 4 {
                    return Err(Error::TooLarge);
                }
                for c in &mut comps {
                    c.coef = alloc::vec![0; c.bw * c.bh * 64];
                }
                d.frame = Frame { width, height, progressive: m == 0xC2, comps, hmax, vmax, mcux, mcuy };
                have_frame = true;
            }
            // Other frame types: lossless, hierarchical, arithmetic.
            0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF => return Err(Error::Unsupported),
            // SOS (B.2.3).
            0xDA => {
                if !have_frame {
                    return Err(Error::Invalid);
                }
                let ns = usize::from(b.u8()?);
                if ns == 0 || ns > 4 {
                    return Err(Error::Invalid);
                }
                let mut sc = Vec::new();
                for _ in 0..ns {
                    let (id, tables) = (b.u8()?, b.u8()?);
                    let ci = d.frame.comps.iter().position(|c| c.id == id).ok_or(Error::Invalid)?;
                    let (td, ta) = (usize::from(tables >> 4), usize::from(tables & 15));
                    if td > 3 || ta > 3 {
                        return Err(Error::Invalid);
                    }
                    d.frame.comps[ci].td = td;
                    d.frame.comps[ci].ta = ta;
                    sc.push(ci);
                }
                let (ss, se, a) = (usize::from(b.u8()?), usize::from(b.u8()?), b.u8()?);
                let scan = Scan { comps: sc, ss, se, ah: u32::from(a >> 4), al: u32::from(a & 15) };
                if d.frame.progressive {
                    // G.1.1.1.1: DC scans alone, AC scans of one component.
                    if se > 63 || ss > se || (ss == 0 && se != 0) || (ss > 0 && ns != 1) || scan.al > 13 {
                        return Err(Error::Invalid);
                    }
                } else if ss != 0 || se != 63 {
                    return Err(Error::Invalid);
                }
                let end = d.scan(data, r.pos, &scan, restart)?;
                r.pos = end;
                scans += 1;
            }
            _ => {}
        }
    }
    if scans == 0 {
        return Err(Error::Truncated);
    }
    let img = pixels(&d.frame, &quant, adobe)?;
    Ok(match orientation {
        2 => img.flip(),
        3 => img.rotate(2),
        4 => img.rotate(2).flip(),
        5 => img.rotate(1).flip(),
        6 => img.rotate(1),
        7 => img.rotate(3).flip(),
        8 => img.rotate(3),
        _ => img,
    })
}

impl Frame {
    fn empty() -> Frame {
        Frame { width: 0, height: 0, progressive: false, comps: Vec::new(), hmax: 1, vmax: 1, mcux: 0, mcuy: 0 }
    }
}

/// Dequantize, transform and upsample each component; convert to RGB.
fn pixels(f: &Frame, quant: &[[u16; 64]; 4], adobe: Option<u8>) -> Result<Image, Error> {
    let t = idct_table();
    let planes: Vec<(Vec<u8>, usize, usize)> = f
        .comps
        .iter()
        .map(|c| {
            let (pw, ph) = (c.bw * 8, c.bh * 8);
            let mut plane = alloc::vec![0u8; pw * ph];
            let q = &quant[c.tq];
            let mut fq = [0.0f32; 64];
            for by in 0..c.bh {
                for bx in 0..c.bw {
                    let blk = &c.coef[(by * c.bw + bx) * 64..][..64];
                    for k in 0..64 {
                        fq[k] = f32::from(blk[k]) * f32::from(q[k]);
                    }
                    idct(&t, &fq, &mut plane[by * 8 * pw + bx * 8..], pw);
                }
            }
            (plane, pw, ph)
        })
        .collect();
    let mut img = Image::new(f.width as u32, f.height as u32)?;
    // A component's sample at full-resolution (x, y): interpolated
    // between its sample centres when it is subsampled.
    let sample = |ci: usize, x: usize, y: usize| -> u8 {
        let c = &f.comps[ci];
        let (plane, pw, ph) = (&planes[ci].0, planes[ci].1, planes[ci].2);
        if c.h == f.hmax && c.v == f.vmax {
            return plane[y * pw + x];
        }
        let (sx, sy) = (f.hmax / c.h, f.vmax / c.v);
        let fx = ((x as f32 + 0.5) / sx as f32 - 0.5).max(0.0);
        let fy = ((y as f32 + 0.5) / sy as f32 - 0.5).max(0.0);
        // The samples that exist: within the component's own size.
        let cw = (f.width * c.h).div_ceil(f.hmax).min(pw);
        let ch = (f.height * c.v).div_ceil(f.vmax).min(ph);
        let (x0, y0) = ((fx as usize).min(cw - 1), (fy as usize).min(ch - 1));
        let (x1, y1) = ((x0 + 1).min(cw - 1), (y0 + 1).min(ch - 1));
        let (tx, ty) = (fx - x0 as f32, fy - y0 as f32);
        let p = |x: usize, y: usize| f32::from(plane[y * pw + x]);
        let v = p(x0, y0) * (1.0 - tx) * (1.0 - ty)
            + p(x1, y0) * tx * (1.0 - ty)
            + p(x0, y1) * (1.0 - tx) * ty
            + p(x1, y1) * tx * ty;
        (v + 0.5).clamp(0.0, 255.0) as u8
    };
    let rgb = f.comps.len() == 3 && adobe == Some(0);
    for y in 0..f.height {
        for x in 0..f.width {
            img.pixels[y * f.width + x] = if f.comps.len() == 1 {
                let g = sample(0, x, y);
                argb(g, g, g, 255)
            } else if rgb {
                argb(sample(0, x, y), sample(1, x, y), sample(2, x, y), 255)
            } else {
                // JFIF 1.02: YCbCr to RGB.
                let yy = f32::from(sample(0, x, y));
                let cb = f32::from(sample(1, x, y)) - 128.0;
                let cr = f32::from(sample(2, x, y)) - 128.0;
                let c = |v: f32| (v + 0.5).clamp(0.0, 255.0) as u8;
                argb(c(yy + 1.402 * cr), c(yy - 0.344_136 * cb - 0.714_136 * cr), c(yy + 1.772 * cb), 255)
            };
        }
    }
    Ok(img)
}

#[cfg(test)]
mod tests {
    use crate::testdata::{check, fixtures, truncations};

    #[test]
    fn baseline_progressive_subsampled_and_restarts() {
        for name in fixtures("jpg") {
            // Decoders round the IDCT and the upsampling differently, by a
            // few levels at most.
            check(&name, super::decode, 3);
        }
    }

    #[test]
    fn damage_is_never_a_panic() {
        truncations("photo420-progressive.jpg", super::decode);
        truncations("photo420-restart.jpg", super::decode);
    }

    #[test]
    fn exif_orientation() {
        // Big-endian TIFF, one IFD0 entry: Orientation = 6.
        let mut app1 = std::vec::Vec::from(&b"Exif\0\0MM\0\x2a\0\0\0\x08\0\x01"[..]);
        app1.extend_from_slice(&[0x01, 0x12, 0x00, 0x03, 0, 0, 0, 1, 0x00, 0x06, 0, 0]);
        assert_eq!(super::exif_orientation(&app1), Some(6));
        assert_eq!(super::exif_orientation(b"Exif\0\0II*\0"), None);
    }
}
