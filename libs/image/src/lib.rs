// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading images (M28, ADR 0105): PNG, JPEG, GIF and BMP into 32-bit
//! pixels, 0xAARRGGBB, not premultiplied (slate-ui's colours), and
//! scaling them for the screen.
//!
//! Each format is written from its specification:
//!
//! - PNG: the W3C's Portable Network Graphics specification (third
//!   edition), with zlib (RFC 1950) over slate-flate;
//! - JPEG: ITU-T T.81 (baseline and progressive Huffman DCT), JFIF 1.02
//!   for the colours, and Exif 2.32's orientation tag;
//! - GIF: the GIF89a specification (its first frame);
//! - BMP: Microsoft's BITMAPINFOHEADER and BITMAPV4/V5HEADER
//!   documentation.
//!
//! Images come from anywhere, so nothing in them is trusted: sizes are
//! checked before memory is taken, every index is checked, and bad data
//! is an [`Error`], never a panic.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;

pub mod bmp;
pub mod gif;
pub mod jpeg;
pub mod png;

/// Why an image could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not a format this reads.
    Unknown,
    /// The data ended early.
    Truncated,
    /// Data the format does not allow (a bad chunk, code or table).
    Invalid,
    /// Allowed by the format but not read here (12-bit JPEG, arithmetic
    /// coding, RLE bitmaps...).
    Unsupported,
    /// Larger than [`MAX_PIXELS`] or [`MAX_SIDE`].
    TooLarge,
}

/// The largest image read: 16384 pixels a side, 64 million in all (256
/// MiB of pixels).
pub const MAX_SIDE: u32 = 16384;
pub const MAX_PIXELS: u64 = 64 << 20;

/// An image's pixels, row by row from the top, 0xAARRGGBB.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u32>,
}

/// What an image file is, by its first bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Png,
    Jpeg,
    Gif,
    Bmp,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::Png => "PNG",
            Format::Jpeg => "JPEG",
            Format::Gif => "GIF",
            Format::Bmp => "BMP",
        }
    }
}

pub fn format(data: &[u8]) -> Option<Format> {
    if data.starts_with(&png::SIGNATURE) {
        Some(Format::Png)
    } else if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some(Format::Jpeg)
    } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        Some(Format::Gif)
    } else if data.starts_with(b"BM") {
        Some(Format::Bmp)
    } else {
        None
    }
}

/// Read an image in any of the formats.
pub fn decode(data: &[u8]) -> Result<Image, Error> {
    match format(data).ok_or(Error::Unknown)? {
        Format::Png => png::decode(data),
        Format::Jpeg => jpeg::decode(data),
        Format::Gif => gif::decode(data),
        Format::Bmp => bmp::decode(data),
    }
}

/// Check a size before taking memory for it.
pub(crate) fn check_size(width: u32, height: u32) -> Result<usize, Error> {
    if width == 0 || height == 0 {
        return Err(Error::Invalid);
    }
    if width > MAX_SIDE || height > MAX_SIDE || u64::from(width) * u64::from(height) > MAX_PIXELS {
        return Err(Error::TooLarge);
    }
    Ok(width as usize * height as usize)
}

pub(crate) fn argb(r: u8, g: u8, b: u8, a: u8) -> u32 {
    u32::from(a) << 24 | u32::from(r) << 16 | u32::from(g) << 8 | u32::from(b)
}

impl Image {
    pub(crate) fn new(width: u32, height: u32) -> Result<Image, Error> {
        let n = check_size(width, height)?;
        Ok(Image { width, height, pixels: alloc::vec![0; n] })
    }

    /// Whether any pixel is not opaque.
    pub fn has_alpha(&self) -> bool {
        self.pixels.iter().any(|p| p >> 24 != 0xFF)
    }

    /// Turned by a quarter `turns` times clockwise.
    pub fn rotate(&self, turns: u32) -> Image {
        let (w, h) = (self.width as usize, self.height as usize);
        match turns % 4 {
            0 => self.clone(),
            2 => Image { width: self.width, height: self.height, pixels: self.pixels.iter().rev().copied().collect() },
            t => {
                let mut out = alloc::vec![0u32; w * h];
                for y in 0..h {
                    for x in 0..w {
                        // Clockwise: (x, y) goes to (h-1-y, x); counter: (y, w-1-x).
                        let (nx, ny) = if t == 1 { (h - 1 - y, x) } else { (y, w - 1 - x) };
                        out[ny * h + nx] = self.pixels[y * w + x];
                    }
                }
                Image { width: self.height, height: self.width, pixels: out }
            }
        }
    }

    /// Mirrored left to right.
    pub fn flip(&self) -> Image {
        let w = self.width as usize;
        let pixels = self.pixels.chunks(w.max(1)).flat_map(|r| r.iter().rev().copied()).collect();
        Image { width: self.width, height: self.height, pixels }
    }

    /// Scaled to `width` × `height`: averaging the source pixels each
    /// output pixel covers when it shrinks (so detail doesn't shimmer),
    /// between the nearest four when it grows. Colours are weighted by
    /// their alpha, so transparent pixels don't darken the edges.
    pub fn scaled(&self, width: u32, height: u32) -> Image {
        let (width, height) = (width.max(1), height.max(1));
        if (width, height) == (self.width, self.height) {
            return self.clone();
        }
        let (sw, sh) = (self.width as usize, self.height as usize);
        let mut out = alloc::vec![0u32; width as usize * height as usize];
        let fx = sw as f32 / width as f32;
        let fy = sh as f32 / height as f32;
        let channels = |p: u32| {
            let a = (p >> 24) as f32;
            [((p >> 16) & 0xFF) as f32 * a, ((p >> 8) & 0xFF) as f32 * a, (p & 0xFF) as f32 * a, a]
        };
        let pack = |s: [f32; 4], weight: f32| {
            let a = s[3] / weight;
            if a <= 0.0 {
                return 0;
            }
            let c = |v: f32| ((v / s[3]).clamp(0.0, 255.0) + 0.5) as u8;
            argb(c(s[0]), c(s[1]), c(s[2]), (a.clamp(0.0, 255.0) + 0.5) as u8)
        };
        for oy in 0..height as usize {
            for ox in 0..width as usize {
                let mut s = [0.0f32; 4];
                let weight = if fx >= 1.0 && fy >= 1.0 {
                    // Shrinking: the box of source pixels, by coverage.
                    let (x0, x1) = (ox as f32 * fx, (ox + 1) as f32 * fx);
                    let (y0, y1) = (oy as f32 * fy, (oy + 1) as f32 * fy);
                    let mut w_sum = 0.0;
                    let mut y = y0 as usize;
                    while (y as f32) < y1 && y < sh {
                        let wy = ((y + 1) as f32).min(y1) - (y as f32).max(y0);
                        let mut x = x0 as usize;
                        while (x as f32) < x1 && x < sw {
                            let wx = ((x + 1) as f32).min(x1) - (x as f32).max(x0);
                            let c = channels(self.pixels[y * sw + x]);
                            for k in 0..4 {
                                s[k] += c[k] * wx * wy;
                            }
                            w_sum += wx * wy;
                            x += 1;
                        }
                        y += 1;
                    }
                    w_sum
                } else {
                    // Growing (or one way each): bilinear between centres.
                    let sx = ((ox as f32 + 0.5) * fx - 0.5).clamp(0.0, (sw - 1) as f32);
                    let sy = ((oy as f32 + 0.5) * fy - 0.5).clamp(0.0, (sh - 1) as f32);
                    let (x0, y0) = (sx as usize, sy as usize);
                    let (x1, y1) = ((x0 + 1).min(sw - 1), (y0 + 1).min(sh - 1));
                    let (tx, ty) = (sx - x0 as f32, sy - y0 as f32);
                    for (x, y, w) in [
                        (x0, y0, (1.0 - tx) * (1.0 - ty)),
                        (x1, y0, tx * (1.0 - ty)),
                        (x0, y1, (1.0 - tx) * ty),
                        (x1, y1, tx * ty),
                    ] {
                        let c = channels(self.pixels[y * sw + x]);
                        for k in 0..4 {
                            s[k] += c[k] * w;
                        }
                    }
                    1.0
                };
                out[oy * width as usize + ox] = pack(s, weight.max(f32::MIN_POSITIVE));
            }
        }
        Image { width, height, pixels: out }
    }
}

/// A big-endian or little-endian reader over a slice, failing with
/// [`Error::Truncated`] at its end.
pub(crate) struct Reader<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, pos: 0 }
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let b = self.data.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(b)
    }

    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.bytes(1)?[0])
    }

    pub fn be16(&mut self) -> Result<u16, Error> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn be32(&mut self) -> Result<u32, Error> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn le16(&mut self) -> Result<u16, Error> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn le32(&mut self) -> Result<u32, Error> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

#[cfg(test)]
pub(crate) mod testdata;

#[cfg(test)]
mod tests {
    use super::*;

    /// `SLATE_IMAGE_BENCH=FILE cargo test --release -p slate-image bench -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn bench() {
        let path = std::env::var("SLATE_IMAGE_BENCH").unwrap();
        let data = std::fs::read(&path).unwrap();
        let t = std::time::Instant::now();
        let img = decode(&data).unwrap();
        let decoded = t.elapsed();
        let small = img.scaled(img.width / 4, img.height / 4);
        std::println!(
            "{path}: {}x{} in {decoded:?}, scaled to {}x{} in {:?}",
            img.width,
            img.height,
            small.width,
            small.height,
            t.elapsed() - decoded
        );
    }

    #[test]
    fn scaling_and_turning() {
        let img = Image { width: 2, height: 1, pixels: alloc::vec![0xFF00_0000, 0xFFFF_FFFF] };
        let half = img.scaled(1, 1);
        assert_eq!(half.pixels, [0xFF80_8080]);
        // A transparent neighbour doesn't darken the colour.
        let edge = Image { width: 2, height: 1, pixels: alloc::vec![0x00000000, 0xFFFF_0000] };
        let e = edge.scaled(1, 1).pixels[0];
        assert_eq!((e >> 16) & 0xFF, 0xFF);
        assert_eq!(e >> 24, 0x80);
        let big = img.scaled(4, 2);
        assert_eq!((big.width, big.height, big.pixels[0], big.pixels[3]), (4, 2, 0xFF00_0000, 0xFFFF_FFFF));
        let tall = img.rotate(1);
        assert_eq!((tall.width, tall.height, tall.pixels.clone()), (1, 2, alloc::vec![0xFF00_0000, 0xFFFF_FFFF]));
        assert_eq!(img.rotate(3).pixels, [0xFFFF_FFFF, 0xFF00_0000]);
        assert_eq!(img.flip().pixels, [0xFFFF_FFFF, 0xFF00_0000]);
        assert_eq!(format(b"nothing"), None);
        assert_eq!(decode(b"nothing"), Err(Error::Unknown));
    }
}
