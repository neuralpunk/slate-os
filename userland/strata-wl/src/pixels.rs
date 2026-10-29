// SPDX-License-Identifier: MIT OR Apache-2.0

//! Copying a screencopy frame into the window: wl_shm's formats
//! (wayland.xml) as 32-bit words in the host's byte order. XRGB8888 and
//! ARGB8888 are 0xAARRGGBB already (alpha made opaque); XBGR8888 and
//! ABGR8888 swap red and blue. A frame flagged y-inverted is read bottom
//! up. A frame larger than the window is cut; a smaller one leaves the
//! rest black.

/// wl_shm formats (wayland.xml, wl_shm.format).
pub const ARGB8888: u32 = 0;
pub const XRGB8888: u32 = 1;
pub const ABGR8888: u32 = 0x3432_4241;
pub const XBGR8888: u32 = 0x3432_4258;

/// Whether this program can read frames in `format`.
pub fn supported(format: u32) -> bool {
    matches!(format, ARGB8888 | XRGB8888 | ABGR8888 | XBGR8888)
}

/// A frame: its pixels (bytes), size, stride, format and orientation.
#[derive(Clone, Copy, Debug)]
pub struct Frame<'a> {
    pub data: &'a [u8],
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: u32,
    pub y_invert: bool,
}

/// Copy the rows `top..bottom` of `f` into `out` (`width` wide).
pub fn copy(f: &Frame<'_>, out: &mut [u32], width: u32, height: u32, top: u32, bottom: u32) {
    let w = f.width.min(width) as usize;
    let swap = matches!(f.format, ABGR8888 | XBGR8888);
    for y in top..bottom.min(height) {
        let row = &mut out[(y * width) as usize..((y + 1) * width) as usize];
        if y >= f.height {
            row.fill(0xFF00_0000);
            continue;
        }
        let src_y = if f.y_invert { f.height - 1 - y } else { y };
        let at = (src_y * f.stride) as usize;
        let Some(src) = f.data.get(at..at + w * 4) else { break };
        for (d, s) in row.iter_mut().zip(src.as_chunks::<4>().0) {
            let p = u32::from_ne_bytes(*s);
            let p = if swap { (p & 0xFF00_FF00) | ((p >> 16) & 0xFF) | ((p & 0xFF) << 16) } else { p };
            *d = p | 0xFF00_0000;
        }
        row[w..].fill(0xFF00_0000);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn formats_and_sizes() {
        // A 2 x 2 frame, stride 12 (padded), XBGR: red is the low byte.
        let mut data = Vec::new();
        for p in [0x0000_00FFu32, 0x0000_FF00, 0, 0x00FF_0000, 0x0000_00FF, 0] {
            data.extend_from_slice(&p.to_ne_bytes());
        }
        let f = Frame { data: &data, width: 2, height: 2, stride: 12, format: XBGR8888, y_invert: false };
        let mut out = alloc::vec![0u32; 3 * 3];
        copy(&f, &mut out, 3, 3, 0, 3);
        assert_eq!(out[..3], [0xFFFF_0000, 0xFF00_FF00, 0xFF00_0000]);
        assert_eq!(out[3..6], [0xFF00_00FF, 0xFFFF_0000, 0xFF00_0000]);
        assert_eq!(out[6..], [0xFF00_0000; 3]);
        // Read bottom up.
        let f = Frame { y_invert: true, format: XRGB8888, ..f };
        copy(&f, &mut out, 3, 3, 0, 1);
        assert_eq!(out[0], 0xFFFF_0000 & 0xFF00_0000 | 0x00FF_0000);
        assert!(supported(ARGB8888) && !supported(7));
    }
}
