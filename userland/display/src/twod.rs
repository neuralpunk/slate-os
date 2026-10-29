// SPDX-License-Identifier: MIT OR Apache-2.0

//! A card's 2D requests (ADR 0172's addendum): the kernel's `drm::twod`
//! ioctls (Slate's own, in DRM's driver range; their structures are in
//! kernel/src/drivers/drm/twod.rs), for a program that draws on the CPU
//! and lets the card copy, fill and blend where it can. Images are the
//! program's own pixels (32-bit, premultiplied ARGB), registered by
//! address; each request is done when the call returns. A card without
//! them is `None` from [`TwoD::open`], and the program draws as before.

use alloc::vec::Vec;

use slate_rt::io;

const IMAGE: u32 = 0x40;
const FREE: u32 = 0x41;
const SUBMIT: u32 = 0x42;

const COPY: u32 = 1;
const FILL: u32 = 2;
const BLEND: u32 = 3;
const BLEND_STRAIGHT: u32 = 4;

/// The ENOTTY of a card without 2D requests.
const ENOTTY: i32 = 25;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct ImageReq {
    addr: u64,
    handle: u32,
    width: u32,
    height: u32,
    pitch: u32,
    id: u32,
    pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct SubmitReq {
    ops: u64,
    count: u32,
    pad: u32,
}

/// One request (the kernel's `twod::Op`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Op {
    kind: u32,
    src: u32,
    dst: u32,
    value: u32,
    sx: i32,
    sy: i32,
    w: i32,
    h: i32,
    dx: i32,
    dy: i32,
    pad: [u32; 2],
}

impl Op {
    /// The `w` x `h` pixels at `from` of image `src` to `to` of `dst`.
    pub fn copy(src: u32, from: (i32, i32), dst: u32, to: (i32, i32), (w, h): (i32, i32)) -> Op {
        Op { kind: COPY, src, dst, sx: from.0, sy: from.1, w, h, dx: to.0, dy: to.1, ..Op::default() }
    }

    /// That rectangle of `dst` filled with `pixel`.
    pub fn fill(dst: u32, to: (i32, i32), (w, h): (i32, i32), pixel: u32) -> Op {
        Op { kind: FILL, dst, value: pixel, w, h, dx: to.0, dy: to.1, ..Op::default() }
    }

    /// `src` (premultiplied) over `dst` at `opacity` (0 to 1).
    pub fn blend(src: u32, from: (i32, i32), dst: u32, to: (i32, i32), (w, h): (i32, i32), opacity: f32) -> Op {
        let value = opacity.to_bits();
        Op { kind: BLEND, src, dst, value, sx: from.0, sy: from.1, w, h, dx: to.0, dy: to.1, ..Op::default() }
    }

    /// [`Op::blend`] for a `src` that isn't premultiplied (slate-ui's
    /// colours, as `Canvas::draw_image` blends them).
    pub fn blend_straight(src: u32, from: (i32, i32), dst: u32, to: (i32, i32), size: (i32, i32), opacity: f32) -> Op {
        Op { kind: BLEND_STRAIGHT, ..Op::blend(src, from, dst, to, size, opacity) }
    }
}

const fn iowr(nr: u32, size: usize) -> u32 {
    0xC000_0000 | ((size as u32) << 16) | ((b'd' as u32) << 8) | nr
}

const fn iow(nr: u32, size: usize) -> u32 {
    0x4000_0000 | ((size as u32) << 16) | ((b'd' as u32) << 8) | nr
}

/// The card open on `fd`, if it does 2D requests.
#[derive(Debug)]
pub struct TwoD {
    fd: i32,
}

impl TwoD {
    /// Asked with an image the kernel must refuse (no buffer 0): ENOTTY
    /// means no 2D requests, any other answer that it has them.
    pub fn open(fd: i32) -> Option<TwoD> {
        let mut r = ImageReq { width: 1, height: 1, pitch: 4, ..ImageReq::default() };
        match io::ioctl(fd, iowr(IMAGE, core::mem::size_of::<ImageReq>()), &mut r as *mut ImageReq as usize) {
            Err(e) if e.0 == ENOTTY => None,
            Ok(_) => {
                let _ = io::ioctl(fd, iow(FREE, 4), &mut r.id as *mut u32 as usize);
                Some(TwoD { fd })
            }
            Err(_) => Some(TwoD { fd }),
        }
    }

    /// `pixels` (`width` x `height`, rows `width` apart) as an image; its
    /// id. The pixels must stay where they are while it lives.
    pub fn image(&self, pixels: &[u32], width: i32, height: i32) -> Option<u32> {
        if width <= 0 || height <= 0 || pixels.len() < (width * height) as usize {
            return None;
        }
        let mut r = ImageReq {
            addr: pixels.as_ptr() as u64,
            width: width as u32,
            height: height as u32,
            pitch: width as u32 * 4,
            ..ImageReq::default()
        };
        io::ioctl(self.fd, iowr(IMAGE, core::mem::size_of::<ImageReq>()), &mut r as *mut ImageReq as usize).ok()?;
        Some(r.id)
    }

    pub fn free(&self, mut id: u32) {
        let _ = io::ioctl(self.fd, iow(FREE, 4), &mut id as *mut u32 as usize);
    }

    /// The requests, in order; whether they were all done.
    pub fn submit(&self, ops: &[Op]) -> bool {
        ops.chunks(64).all(|c| {
            let mut r = SubmitReq { ops: c.as_ptr() as u64, count: c.len() as u32, pad: 0 };
            io::ioctl(self.fd, iow(SUBMIT, core::mem::size_of::<SubmitReq>()), &mut r as *mut SubmitReq as usize)
                .is_ok()
        })
    }
}

/// Images of a program's pixel buffers, looked up by the buffer's own
/// key (one never reused), where its pixels are and their size, and freed
/// once [`Images::end_frame`] has passed
/// [`Images::KEEP`] times without them (a window outside a frame's damage
/// isn't drawn, but its buffer stays).
#[derive(Debug, Default)]
pub struct Images {
    kept: Vec<(u64, u64, i32, i32, u32, u32)>,
}

impl Images {
    pub const KEEP: u32 = 120;

    /// The image of buffer `key`'s `pixels`, registered the first time.
    pub fn of(&mut self, t: &TwoD, key: u64, pixels: &[u32], w: i32, h: i32) -> Option<u32> {
        let at = pixels.as_ptr() as u64;
        if let Some(k) = self.kept.iter_mut().find(|k| (k.0, k.1, k.2, k.3) == (key, at, w, h)) {
            k.5 = 0;
            return Some(k.4);
        }
        let id = t.image(pixels, w, h)?;
        self.kept.push((key, at, w, h, id, 0));
        Some(id)
    }

    /// A frame drawn: images unused for [`Images::KEEP`] of them freed.
    pub fn end_frame(&mut self, t: &TwoD) {
        self.kept.retain_mut(|k| {
            k.5 += 1;
            let keep = k.5 <= Self::KEEP;
            if !keep {
                t.free(k.4);
            }
            keep
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kernels_layouts() {
        // kernel/src/drivers/drm/twod.rs: ImageReq 32 bytes, SubmitReq 16,
        // Op 48; the numbers in DRM's driver range.
        assert_eq!(core::mem::size_of::<ImageReq>(), 32);
        assert_eq!(core::mem::size_of::<SubmitReq>(), 16);
        assert_eq!(core::mem::size_of::<Op>(), 48);
        assert_eq!(iowr(IMAGE, 32), 0xC020_6440);
        assert_eq!(iow(SUBMIT, 16), 0x4010_6442);
        let b = Op::blend(1, (2, 3), 4, (5, 6), (7, 8), 0.5);
        assert_eq!((b.kind, b.value, b.sx, b.dy, b.h), (BLEND, 0.5f32.to_bits(), 2, 6, 8));
    }
}
