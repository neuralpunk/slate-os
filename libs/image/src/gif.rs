// SPDX-License-Identifier: MIT OR Apache-2.0

//! GIF (the GIF89a specification): the first image, on the logical
//! screen, with its local or global colour table, interlacing, and the
//! Graphic Control Extension's transparent colour. Animations show their
//! first frame; the rest is not read.

use alloc::vec::Vec;

use crate::{Error, Image, Reader, argb};

/// §22: LZW with variable-length codes, least significant bit first, up
/// to 12 bits.
fn lzw(data: &[u8], min_size: u8, limit: usize) -> Result<Vec<u8>, Error> {
    if !(2..=11).contains(&min_size) {
        return Err(Error::Invalid);
    }
    let clear = 1usize << min_size;
    let end = clear + 1;
    // Each entry: its previous code (or none) and its last byte, and its
    // first byte and length, to write it out backwards.
    let mut prefix: Vec<u16> = alloc::vec![0; 4096];
    let mut suffix: Vec<u8> = alloc::vec![0; 4096];
    let mut first: Vec<u8> = alloc::vec![0; 4096];
    let mut length: Vec<u16> = alloc::vec![0; 4096];
    for i in 0..clear {
        suffix[i] = i as u8;
        first[i] = i as u8;
        length[i] = 1;
    }
    let mut next = end + 1;
    let mut size = u32::from(min_size) + 1;
    let mut prev: Option<usize> = None;
    let mut out = Vec::new();
    let (mut acc, mut nbits, mut pos) = (0u32, 0u32, 0usize);
    loop {
        while nbits < size {
            let Some(&b) = data.get(pos) else { return Ok(out) };
            acc |= u32::from(b) << nbits;
            nbits += 8;
            pos += 1;
        }
        let code = (acc & ((1 << size) - 1)) as usize;
        acc >>= size;
        nbits -= size;
        if code == clear {
            next = end + 1;
            size = u32::from(min_size) + 1;
            prev = None;
            continue;
        }
        if code == end {
            return Ok(out);
        }
        let Some(p) = prev else {
            if code >= clear {
                return Err(Error::Invalid);
            }
            out.push(code as u8);
            prev = Some(code);
            continue;
        };
        // A known code, or the one about to be made (KwKwK).
        let (entry, extra) = if code < next {
            (code, None)
        } else if code == next {
            (p, Some(first[p]))
        } else {
            return Err(Error::Invalid);
        };
        let start = out.len();
        let n = usize::from(length[entry]);
        if start + n + usize::from(extra.is_some()) > limit {
            return Err(Error::TooLarge);
        }
        out.resize(start + n, 0);
        let mut e = entry;
        for i in (0..n).rev() {
            out[start + i] = suffix[e];
            e = usize::from(prefix[e]);
        }
        if let Some(b) = extra {
            out.push(b);
        }
        if next < 4096 {
            prefix[next] = p as u16;
            suffix[next] = if extra.is_some() { first[p] } else { first[code] };
            first[next] = first[p];
            length[next] = length[p] + 1;
            next += 1;
            if next == 1 << size && size < 12 {
                size += 1;
            }
        }
        prev = Some(code);
    }
}

fn colour_table(r: &mut Reader<'_>, flags: u8) -> Result<Vec<u32>, Error> {
    let n = 2usize << (flags & 7);
    Ok(r.bytes(3 * n)?.as_chunks::<3>().0.iter().map(|c| argb(c[0], c[1], c[2], 255)).collect())
}

pub fn decode(data: &[u8]) -> Result<Image, Error> {
    let mut r = Reader::new(data);
    let sig = r.bytes(6)?;
    if sig != b"GIF87a" && sig != b"GIF89a" {
        return Err(Error::Unknown);
    }
    // §18: the Logical Screen Descriptor.
    let (sw, sh) = (u32::from(r.le16()?), u32::from(r.le16()?));
    let (flags, _background, _aspect) = (r.u8()?, r.u8()?, r.u8()?);
    let global = if flags & 0x80 != 0 { colour_table(&mut r, flags)? } else { Vec::new() };
    let mut transparent: Option<u8> = None;
    loop {
        match r.u8()? {
            // §23: the Graphic Control Extension; others are skipped.
            0x21 => {
                let label = r.u8()?;
                loop {
                    let n = usize::from(r.u8()?);
                    if n == 0 {
                        break;
                    }
                    let block = r.bytes(n)?;
                    if label == 0xF9 && n >= 4 && block[0] & 1 != 0 {
                        transparent = Some(block[3]);
                    }
                }
            }
            // §20: the Image Descriptor.
            0x2C => {
                let (left, top) = (u32::from(r.le16()?), u32::from(r.le16()?));
                let (w, h) = (u32::from(r.le16()?), u32::from(r.le16()?));
                let flags = r.u8()?;
                let local = if flags & 0x80 != 0 { Some(colour_table(&mut r, flags)?) } else { None };
                let table = local.as_deref().unwrap_or(&global);
                if table.is_empty() {
                    return Err(Error::Invalid);
                }
                let min = r.u8()?;
                let mut lzw_data = Vec::new();
                loop {
                    let n = usize::from(r.u8()?);
                    if n == 0 {
                        break;
                    }
                    lzw_data.extend_from_slice(r.bytes(n)?);
                }
                let n = crate::check_size(w.max(1), h.max(1))?;
                let indices = lzw(&lzw_data, min, n)?;
                // The screen is the frame's own size when it says less.
                let (cw, ch) = (sw.max(left + w), sh.max(top + h));
                let mut img = Image::new(cw, ch)?;
                // §25 (Appendix E): the interlaced rows' order.
                let rows: Vec<u32> = if flags & 0x40 != 0 {
                    [(0, 8), (4, 8), (2, 4), (1, 2)].iter().flat_map(|&(s, step)| (s..h).step_by(step)).collect()
                } else {
                    (0..h).collect()
                };
                for (i, &y) in rows.iter().enumerate() {
                    for x in 0..w {
                        let Some(&idx) = indices.get(i * w as usize + x as usize) else { continue };
                        if Some(idx) == transparent {
                            continue;
                        }
                        let c = table.get(usize::from(idx)).copied().unwrap_or(0xFF00_0000);
                        img.pixels[((top + y) * cw + left + x) as usize] = c;
                    }
                }
                return Ok(img);
            }
            0x3B => return Err(Error::Truncated),
            _ => return Err(Error::Invalid),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::testdata::{check, fixtures, truncations};

    #[test]
    fn frames() {
        for name in fixtures("gif") {
            check(&name, super::decode, 0);
        }
        truncations("gif-interlaced.gif", super::decode);
    }

    #[test]
    fn lzw_codes() {
        // Min size 2: clear, 0, 1 (making 6 = "01"), 7 (the code being
        // made: "1" + "1", KwKwK), end. The code size grows to 4 bits at 8.
        let bits: u32 = 4 | 1 << 6 | 7 << 9 | 5 << 12;
        let data = bits.to_le_bytes();
        assert_eq!(super::lzw(&data[..2], 2, 100), Ok(std::vec![0, 1, 1, 1]));
    }
}
