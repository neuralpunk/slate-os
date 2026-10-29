// SPDX-License-Identifier: MIT OR Apache-2.0

//! BMP (Microsoft's BITMAPFILEHEADER, BITMAPINFOHEADER, BITMAPV4HEADER
//! and BITMAPV5HEADER documentation): 1, 4 and 8 bits through a colour
//! table, 16, 24 and 32 bits (with BI_BITFIELDS masks, and an alpha mask
//! from the V4 and V5 headers), RLE8 and RLE4, bottom-up and top-down.
//! The OS/2 1.x header (12 bytes) is read too. JPEG and PNG inside a BMP
//! are not.

use alloc::vec::Vec;

use crate::{Error, Image, Reader, argb};

/// A channel from a bit mask, scaled to 8 bits.
fn masked(v: u32, mask: u32) -> u8 {
    if mask == 0 {
        return 0;
    }
    let shift = mask.trailing_zeros();
    let bits = (mask >> shift).count_ones();
    let x = (v & mask) >> shift;
    if bits >= 8 { (x >> (bits - 8)) as u8 } else { ((x * 255 + ((1 << bits) - 1) / 2) / ((1 << bits) - 1)) as u8 }
}

pub fn decode(data: &[u8]) -> Result<Image, Error> {
    let mut r = Reader::new(data);
    if r.bytes(2)? != b"BM" {
        return Err(Error::Unknown);
    }
    let _size = r.le32()?;
    let _reserved = r.le32()?;
    let offset = r.le32()? as usize;
    let header = r.le32()? as usize;
    let (width, height, bpp, compression, colours);
    let mut masks = [0u32; 4];
    if header == 12 {
        // BITMAPCOREHEADER.
        width = i32::from(r.le16()?);
        height = i32::from(r.le16()? as i16);
        let _planes = r.le16()?;
        bpp = r.le16()?;
        compression = 0;
        colours = 0;
    } else if header >= 40 {
        width = r.le32()? as i32;
        height = r.le32()? as i32;
        let _planes = r.le16()?;
        bpp = r.le16()?;
        compression = r.le32()?;
        let _image_size = r.le32()?;
        let _ppm = (r.le32()?, r.le32()?);
        colours = r.le32()? as usize;
        let _important = r.le32()?;
        if compression == 3 || compression == 6 || header >= 108 {
            // The masks follow (as part of a V2+ header, or after a plain
            // one for BI_BITFIELDS).
            masks = [r.le32()?, r.le32()?, r.le32()?, if header >= 56 || compression == 6 { r.le32()? } else { 0 }];
        }
    } else {
        return Err(Error::Invalid);
    }
    let top_down = height < 0;
    let (w, h) = (width.unsigned_abs(), height.unsigned_abs());
    if width <= 0 {
        return Err(Error::Invalid);
    }
    crate::check_size(w, h)?;
    // The colour table: after the header (and the masks a plain header
    // with BI_BITFIELDS carries).
    let table_at = 14 + header + if header == 40 && matches!(compression, 3 | 6) { 12 } else { 0 };
    let entry = if header == 12 { 3 } else { 4 };
    let table: Vec<u32> = if bpp <= 8 {
        let n = if colours == 0 || colours > 256 { 1 << bpp } else { colours };
        let t = data.get(table_at..table_at + n * entry).ok_or(Error::Truncated)?;
        t.chunks_exact(entry).map(|c| argb(c[2], c[1], c[0], 255)).collect()
    } else {
        Vec::new()
    };
    let pixels = data.get(offset..).ok_or(Error::Truncated)?;
    let mut img = Image::new(w, h)?;
    let (w, h) = (w as usize, h as usize);
    let row_of = |y: usize| if top_down { y } else { h - 1 - y };
    match (compression, bpp) {
        (0 | 3 | 6, 1 | 4 | 8 | 16 | 24 | 32) => {
            let stride = (w * usize::from(bpp)).div_ceil(32) * 4;
            // 16 bits without masks are 5-5-5; 32 without are BGRx.
            if compression == 0 {
                masks = match bpp {
                    16 => [0x7C00, 0x03E0, 0x001F, 0],
                    32 => [0x00FF_0000, 0x0000_FF00, 0x0000_00FF, 0],
                    _ => masks,
                };
            }
            for y in 0..h {
                let row = pixels.get(y * stride..y * stride + stride).ok_or(Error::Truncated)?;
                let out = row_of(y) * w;
                for x in 0..w {
                    img.pixels[out + x] = match bpp {
                        24 => argb(row[3 * x + 2], row[3 * x + 1], row[3 * x], 255),
                        16 | 32 => {
                            let v = if bpp == 16 {
                                u32::from(u16::from_le_bytes([row[2 * x], row[2 * x + 1]]))
                            } else {
                                u32::from_le_bytes([row[4 * x], row[4 * x + 1], row[4 * x + 2], row[4 * x + 3]])
                            };
                            let a = if masks[3] != 0 { masked(v, masks[3]) } else { 255 };
                            argb(masked(v, masks[0]), masked(v, masks[1]), masked(v, masks[2]), a)
                        }
                        _ => {
                            let b = usize::from(bpp);
                            let bit = x * b;
                            let i = (row[bit / 8] >> (8 - b - bit % 8)) & ((1u16 << b) - 1) as u8;
                            table.get(usize::from(i)).copied().unwrap_or(0xFF00_0000)
                        }
                    };
                }
            }
        }
        (1, 8) | (2, 4) => rle(pixels, &mut img, &table, bpp == 4, &row_of)?,
        _ => return Err(Error::Unsupported),
    }
    Ok(img)
}

/// RLE8 and RLE4: runs and absolute stretches; end of line, end of
/// bitmap and delta escapes. Pixels not written stay transparent.
fn rle(data: &[u8], img: &mut Image, table: &[u32], four: bool, row_of: &dyn Fn(usize) -> usize) -> Result<(), Error> {
    let (w, h) = (img.width as usize, img.height as usize);
    let mut put = |x: usize, y: usize, i: u8| {
        if x < w && y < h {
            img.pixels[row_of(y) * w + x] = table.get(usize::from(i)).copied().unwrap_or(0xFF00_0000);
        }
    };
    let mut r = Reader::new(data);
    let (mut x, mut y) = (0usize, 0usize);
    while y < h {
        let (n, v) = (r.u8()?, r.u8()?);
        if n > 0 {
            for k in 0..usize::from(n) {
                let i = if four { if k % 2 == 0 { v >> 4 } else { v & 15 } } else { v };
                put(x, y, i);
                x += 1;
            }
            continue;
        }
        match v {
            0 => {
                x = 0;
                y += 1;
            }
            1 => return Ok(()),
            2 => {
                x += usize::from(r.u8()?);
                y += usize::from(r.u8()?);
            }
            n => {
                let n = usize::from(n);
                let bytes = if four { n.div_ceil(2) } else { n };
                let b = r.bytes(bytes)?;
                for k in 0..n {
                    let i = if four { if k % 2 == 0 { b[k / 2] >> 4 } else { b[k / 2] & 15 } } else { b[k] };
                    put(x, y, i);
                    x += 1;
                }
                // Absolute runs end on a 16-bit boundary.
                if bytes % 2 == 1 {
                    r.u8()?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::testdata::{check, fixtures, truncations};

    #[test]
    fn depths_and_rle() {
        for name in fixtures("bmp") {
            check(&name, super::decode, 0);
        }
        truncations("bmp8-rle.bmp", super::decode);
        truncations("bmp32.bmp", super::decode);
    }
}
