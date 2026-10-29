// SPDX-License-Identifier: MIT OR Apache-2.0

//! PNG (W3C, Portable Network Graphics, third edition): every colour type
//! and bit depth, the five filters, Adam7 interlacing, palettes and
//! `tRNS` transparency. Sixteen-bit samples are rounded to eight; gamma
//! and colour profiles are not applied. Chunk CRCs are checked (§5.3).

use alloc::vec::Vec;

use crate::{Error, Image, Reader, argb};

/// §5.2: the signature.
pub const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// §11.2.2 IHDR.
#[derive(Clone, Copy, Debug)]
struct Header {
    width: u32,
    height: u32,
    depth: u8,
    /// 0 grey, 2 truecolour, 3 indexed, 4 grey with alpha, 6 truecolour
    /// with alpha.
    colour: u8,
    interlaced: bool,
}

impl Header {
    fn channels(&self) -> usize {
        match self.colour {
            2 => 3,
            4 => 2,
            6 => 4,
            _ => 1,
        }
    }

    /// Bits per pixel.
    fn bpp_bits(&self) -> usize {
        self.channels() * usize::from(self.depth)
    }

    /// Bytes per row of `w` pixels, without the filter byte.
    fn row_bytes(&self, w: usize) -> usize {
        (w * self.bpp_bits()).div_ceil(8)
    }
}

/// zlib (RFC 1950): the header checked, the DEFLATE data inflated, at
/// most `limit` bytes.
fn zlib(data: &[u8], limit: usize) -> Result<Vec<u8>, Error> {
    let (&cmf, rest) = data.split_first().ok_or(Error::Truncated)?;
    let (&flg, rest) = rest.split_first().ok_or(Error::Truncated)?;
    // §2.2: method 8, a window of at most 32 KiB, the check, no
    // preset dictionary.
    if cmf & 0x0F != 8 || cmf >> 4 > 7 || (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0 || flg & 0x20 != 0 {
        return Err(Error::Invalid);
    }
    slate_flate::inflate_raw_limited(rest, limit).map(|(d, _)| d).map_err(|e| match e {
        slate_flate::Error::Truncated => Error::Truncated,
        slate_flate::Error::TooLarge => Error::TooLarge,
        _ => Error::Invalid,
    })
}

/// §7.3: undo one row's filter, given the row above (zeros for the first).
fn unfilter(kind: u8, row: &mut [u8], above: &[u8], bpp: usize) -> Result<(), Error> {
    match kind {
        0 => {}
        1 => {
            for i in bpp..row.len() {
                row[i] = row[i].wrapping_add(row[i - bpp]);
            }
        }
        2 => {
            for (r, a) in row.iter_mut().zip(above) {
                *r = r.wrapping_add(*a);
            }
        }
        3 => {
            for i in 0..row.len() {
                let left = if i >= bpp { u16::from(row[i - bpp]) } else { 0 };
                row[i] = row[i].wrapping_add(((left + u16::from(above[i])) / 2) as u8);
            }
        }
        4 => {
            for i in 0..row.len() {
                let a = if i >= bpp { i16::from(row[i - bpp]) } else { 0 };
                let b = i16::from(above[i]);
                let c = if i >= bpp { i16::from(above[i - bpp]) } else { 0 };
                // §9.4: the Paeth predictor.
                let p = a + b - c;
                let (pa, pb, pc) = ((p - a).abs(), (p - b).abs(), (p - c).abs());
                let pred = if pa <= pb && pa <= pc {
                    a
                } else if pb <= pc {
                    b
                } else {
                    c
                };
                row[i] = row[i].wrapping_add(pred as u8);
            }
        }
        _ => return Err(Error::Invalid),
    }
    Ok(())
}

/// The pixels a scanline holds, unpacked into the image at (x0 + i·dx, y).
struct Ctx<'a> {
    h: Header,
    palette: &'a [u32],
    /// The transparent grey or colour (tRNS for types 0 and 2), in
    /// samples of the image's depth.
    key: Option<[u16; 3]>,
}

impl Ctx<'_> {
    fn sample(&self, row: &[u8], i: usize) -> u16 {
        let d = usize::from(self.h.depth);
        match d {
            16 => u16::from_be_bytes([row[2 * i], row[2 * i + 1]]),
            8 => u16::from(row[i]),
            _ => {
                let bit = i * d;
                let byte = row[bit / 8];
                let shift = 8 - d - bit % 8;
                u16::from((byte >> shift) & ((1u8 << d) - 1))
            }
        }
    }

    /// A sample as 8 bits.
    fn to8(&self, v: u16) -> u8 {
        match self.h.depth {
            16 => ((u32::from(v) * 255 + 32767) / 65535) as u8,
            8 => v as u8,
            d => (u32::from(v) * 255 / ((1u32 << d) - 1)) as u8,
        }
    }

    fn pixel(&self, row: &[u8], x: usize) -> u32 {
        let c = self.h.channels();
        let s = |k: usize| self.sample(row, x * c + k);
        match self.h.colour {
            0 => {
                let g = s(0);
                let a = if self.key.is_some_and(|k| k[0] == g) { 0 } else { 255 };
                let g = self.to8(g);
                argb(g, g, g, a)
            }
            2 => {
                let (r, g, b) = (s(0), s(1), s(2));
                let a = if self.key == Some([r, g, b]) { 0 } else { 255 };
                argb(self.to8(r), self.to8(g), self.to8(b), a)
            }
            3 => self.palette.get(usize::from(s(0))).copied().unwrap_or(0xFF00_0000),
            4 => {
                let g = self.to8(s(0));
                argb(g, g, g, self.to8(s(1)))
            }
            _ => argb(self.to8(s(0)), self.to8(s(1)), self.to8(s(2)), self.to8(s(3))),
        }
    }
}

/// §8.2: Adam7's passes, as (x0, y0, dx, dy).
const ADAM7: [(usize, usize, usize, usize); 7] =
    [(0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)];

pub fn decode(data: &[u8]) -> Result<Image, Error> {
    let mut r = Reader::new(data);
    if r.bytes(8)? != SIGNATURE {
        return Err(Error::Unknown);
    }
    let mut header: Option<Header> = None;
    let mut palette: Vec<u32> = Vec::new();
    let mut trns: Option<&[u8]> = None;
    let mut idat: Vec<u8> = Vec::new();
    loop {
        let len = r.be32()? as usize;
        let kind = r.bytes(4)?;
        let body = r.bytes(len)?;
        let crc = r.be32()?;
        let mut whole = Vec::with_capacity(4 + body.len());
        whole.extend_from_slice(kind);
        whole.extend_from_slice(body);
        if slate_flate::crc32(&whole) != crc {
            return Err(Error::Invalid);
        }
        match kind {
            b"IHDR" => {
                let mut b = Reader::new(body);
                let (width, height) = (b.be32()?, b.be32()?);
                let (depth, colour, method, filter, interlace) = (b.u8()?, b.u8()?, b.u8()?, b.u8()?, b.u8()?);
                // §11.2.2: the allowed depths for each colour type.
                let ok = match colour {
                    0 => matches!(depth, 1 | 2 | 4 | 8 | 16),
                    3 => matches!(depth, 1 | 2 | 4 | 8),
                    2 | 4 | 6 => matches!(depth, 8 | 16),
                    _ => false,
                };
                if !ok || method != 0 || filter != 0 || interlace > 1 {
                    return Err(Error::Invalid);
                }
                crate::check_size(width, height)?;
                header = Some(Header { width, height, depth, colour, interlaced: interlace == 1 });
            }
            b"PLTE" => {
                if body.len() % 3 != 0 || body.len() > 768 {
                    return Err(Error::Invalid);
                }
                palette = body.as_chunks::<3>().0.iter().map(|c| argb(c[0], c[1], c[2], 255)).collect();
            }
            b"tRNS" => trns = Some(body),
            b"IDAT" => {
                if idat.len().saturating_add(body.len()) > (crate::MAX_PIXELS as usize) * 8 {
                    return Err(Error::TooLarge);
                }
                idat.extend_from_slice(body);
            }
            b"IEND" => break,
            // Ancillary chunks (lower case first letter) are skipped; an
            // unknown critical one can't be.
            k if k[0].is_ascii_uppercase() => return Err(Error::Unsupported),
            _ => {}
        }
    }
    let h = header.ok_or(Error::Invalid)?;
    if h.colour == 3 && palette.is_empty() {
        return Err(Error::Invalid);
    }
    let mut key = None;
    if let Some(t) = trns {
        match h.colour {
            3 => {
                for (i, a) in t.iter().enumerate().take(palette.len()) {
                    palette[i] = (palette[i] & 0x00FF_FFFF) | u32::from(*a) << 24;
                }
            }
            0 if t.len() >= 2 => key = Some([u16::from_be_bytes([t[0], t[1]]), 0, 0]),
            2 if t.len() >= 6 => {
                let v = |i: usize| u16::from_be_bytes([t[i], t[i + 1]]);
                key = Some([v(0), v(2), v(4)]);
            }
            _ => {}
        }
    }
    let (w, ht) = (h.width as usize, h.height as usize);
    let bpp = h.bpp_bits().div_ceil(8);
    // The decompressed size is known: each pass's rows, one filter byte
    // each.
    let passes: Vec<(usize, usize, usize, usize)> =
        if h.interlaced { ADAM7.to_vec() } else { alloc::vec![(0, 0, 1, 1)] };
    let pass_size = |&(x0, y0, dx, dy): &(usize, usize, usize, usize)| {
        let pw = w.saturating_sub(x0).div_ceil(dx);
        let ph = ht.saturating_sub(y0).div_ceil(dy);
        (pw, ph)
    };
    let expected: usize = passes
        .iter()
        .map(pass_size)
        .map(|(pw, ph)| if pw == 0 || ph == 0 { 0 } else { ph * (1 + h.row_bytes(pw)) })
        .sum();
    let raw = zlib(&idat, expected)?;
    if raw.len() < expected {
        return Err(Error::Truncated);
    }
    let mut img = Image::new(h.width, h.height)?;
    let ctx = Ctx { h, palette: &palette, key };
    let mut at = 0;
    for p in &passes {
        let (pw, ph) = pass_size(p);
        if pw == 0 || ph == 0 {
            continue;
        }
        let rb = h.row_bytes(pw);
        let mut above = alloc::vec![0u8; rb];
        for py in 0..ph {
            let kind = raw[at];
            let mut row = raw[at + 1..at + 1 + rb].to_vec();
            at += 1 + rb;
            unfilter(kind, &mut row, &above, bpp)?;
            let y = p.1 + py * p.3;
            for px in 0..pw {
                let x = p.0 + px * p.2;
                img.pixels[y * w + x] = ctx.pixel(&row, px);
            }
            above = row;
        }
    }
    Ok(img)
}

#[cfg(test)]
mod tests {
    use crate::testdata::{check, fixtures};

    #[test]
    fn every_colour_type_and_depth() {
        for name in fixtures("png") {
            check(&name, super::decode, 0);
        }
    }

    #[test]
    fn damage_is_an_error() {
        crate::testdata::truncations("rgba8.png", super::decode);
        let mut bad = crate::testdata::load("rgb8.png");
        bad[40] ^= 0xFF;
        assert!(super::decode(&bad).is_err());
    }
}
