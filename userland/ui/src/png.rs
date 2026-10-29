// SPDX-License-Identifier: MIT OR Apache-2.0

//! A minimal PNG writer (RFC 2083, the PNG specification): 8-bit RGB,
//! no filtering, zlib (RFC 1950) with stored deflate blocks (RFC 1951
//! §3.2.4). Big but simple: for test output and screenshots.

use alloc::vec::Vec;

use crate::canvas::Canvas;

pub fn encode(c: &Canvas) -> Vec<u8> {
    let mut raw = Vec::with_capacity((c.width * 3 + 1) as usize * c.height as usize);
    for y in 0..c.height {
        raw.push(0); // filter: none
        for x in 0..c.width {
            let p = c.pixel(x, y);
            raw.extend_from_slice(&[(p >> 16) as u8, (p >> 8) as u8, p as u8]);
        }
    }
    let mut out = Vec::from(&b"\x89PNG\r\n\x1a\n"[..]);
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&(c.width as u32).to_be_bytes());
    ihdr.extend_from_slice(&(c.height as u32).to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &zlib_stored(&raw));
    chunk(&mut out, b"IEND", &[]);
    out
}

fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let start = out.len();
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let crc = crc32(&out[start..]);
    out.extend_from_slice(&crc.to_be_bytes());
}

fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::from(&[0x78, 0x01][..]);
    let mut blocks = data.chunks(65_535).peekable();
    if blocks.peek().is_none() {
        out.extend_from_slice(&[1, 0, 0, 0xFF, 0xFF]);
    }
    while let Some(b) = blocks.next() {
        out.push(if blocks.peek().is_none() { 1 } else { 0 });
        let len = b.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(b);
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

/// CRC-32 (ISO 3309, reflected polynomial 0xEDB88320).
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + x as u32) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums() {
        assert_eq!(crc32(b"IEND"), 0xAE42_6082);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }
}
