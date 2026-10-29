// SPDX-License-Identifier: MIT OR Apache-2.0

//! A card's 2D requests (ADR 0172's addendum, M32 phase 6): Slate's own
//! driver-private DRM ioctls, in DRM's driver range (DRM_COMMAND_BASE,
//! 40h, on; libdrm's drm.h). A client registers images (a dumb buffer by
//! handle, or its own memory by address: the pages pinned for as long as
//! the image lives) and asks for copies, fills and blends between them;
//! each request is done when the ioctl returns. Cards without a GPU that
//! does them answer ENOTTY, and the client draws on the CPU.
//!
//! The structures (all little-endian, `#[repr(C)]`, no padding holes):
//! - `SLATE_2D_IMAGE` (40h, read and write): `struct { u64 addr; u32
//!   handle; u32 width; u32 height; u32 pitch; u32 id; u32 pad; }`:
//!   `addr` the image's first byte in the caller's memory, or 0 and
//!   `handle` a dumb buffer's; its size in pixels (32-bit), its pitch in
//!   bytes; `id` back.
//! - `SLATE_2D_FREE` (41h, write): `u32 id`.
//! - `SLATE_2D_SUBMIT` (42h, write): `struct { u64 ops; u32 count; u32
//!   pad; }`, `ops` pointing at `count` (up to 64) `struct { u32 kind;
//!   u32 src; u32 dst; u32 value; i32 sx, sy, w, h; i32 dx, dy; u32
//!   pad[2]; }`: COPY 1 (`w` x `h` pixels from (`sx`, `sy`) of `src` to
//!   (`dx`, `dy`) of `dst`), FILL 2 (that rectangle of `dst` with the
//!   pixel `value`), BLEND 3 (premultiplied `src` over `dst`, `value` the
//!   opacity as an f32's bits), BLEND_STRAIGHT 4 (the same for a `src`
//!   that isn't premultiplied, slate-ui's colours). Rectangles must be
//!   inside their images.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::Buffer;
use crate::mm::{PAGE_SIZE, PhysAddr, frame};

pub const IMAGE: u32 = 0x40;
pub const FREE: u32 = 0x41;
pub const SUBMIT: u32 = 0x42;

pub const COPY: u32 = 1;
pub const FILL: u32 = 2;
pub const BLEND: u32 = 3;
pub const BLEND_STRAIGHT: u32 = 4;

/// The most requests one SUBMIT carries.
pub const MAX_OPS: u32 = 64;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ImageReq {
    pub addr: u64,
    pub handle: u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub id: u32,
    pub pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SubmitReq {
    pub ops: u64,
    pub count: u32,
    pub pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Op {
    pub kind: u32,
    pub src: u32,
    pub dst: u32,
    pub value: u32,
    pub sx: i32,
    pub sy: i32,
    pub w: i32,
    pub h: i32,
    pub dx: i32,
    pub dy: i32,
    pub pad: [u32; 2],
}

/// An image: its pages (in order; the image starts `offset` bytes into
/// the first), its size in pixels and its pitch in bytes. A dumb buffer's
/// image keeps the buffer; one of user memory holds a reference on each
/// page until it drops.
pub struct Image {
    pub frames: Vec<PhysAddr>,
    pub offset: u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pinned: bool,
    _buffer: Option<Arc<Buffer>>,
}

impl Drop for Image {
    fn drop(&mut self) {
        if self.pinned {
            for f in &self.frames {
                crate::mm::pins::unpin(*f);
                frame::put_user_page(*f);
            }
        }
    }
}

impl Image {
    /// The bytes the image spans, from its first.
    fn span(width: u32, height: u32, pitch: u32) -> Option<u64> {
        if width == 0 || height == 0 || width > 16384 || height > 16384 || pitch < width * 4 || pitch % 4 != 0 {
            return None;
        }
        Some(u64::from(pitch) * u64::from(height - 1) + u64::from(width) * 4)
    }

    /// A dumb buffer's image.
    pub fn of_buffer(b: Arc<Buffer>, width: u32, height: u32, pitch: u32) -> Option<Image> {
        let span = Self::span(width, height, pitch)?;
        if span > b.size {
            return None;
        }
        Some(Image { frames: b.frames().to_vec(), offset: 0, width, height, pitch, pinned: false, _buffer: Some(b) })
    }

    /// The caller's memory at `addr`: each page faulted in for writing,
    /// then its frame held and pinned (`mm::pins`: a fork copies it for the
    /// child, so it stays the process's; one the process unmaps and maps
    /// again is no longer the image's).
    pub fn of_user(addr: u64, width: u32, height: u32, pitch: u32) -> Option<Image> {
        let span = Self::span(width, height, pitch)?;
        if addr % 4 != 0 {
            return None;
        }
        let (first, last) = (addr & !(PAGE_SIZE - 1), (addr + span - 1) & !(PAGE_SIZE - 1));
        let proc = crate::proc::current()?;
        let mut img = Image {
            frames: Vec::new(),
            offset: (addr - first) as u32,
            width,
            height,
            pitch,
            pinned: true,
            _buffer: None,
        };
        for page in (first..=last).step_by(PAGE_SIZE as usize) {
            if !crate::proc::handle_page_fault(page, true, false, false) {
                return None;
            }
            let guard = proc.aspace.lock();
            let f = guard.as_ref()?.translate(page)?;
            frame::get_user_page(f);
            crate::mm::pins::pin(f);
            img.frames.push(f);
        }
        Some(img)
    }

    /// Whether the `w` x `h` rectangle at (`x`, `y`) is inside.
    pub fn holds(&self, x: i32, y: i32, w: i32, h: i32) -> bool {
        x >= 0 && y >= 0 && w > 0 && h > 0 && (x + w) as u32 <= self.width && (y + h) as u32 <= self.height
    }
}

/// A request with its source image (none for a fill) and destination.
pub type Request = (Op, Option<Arc<Image>>, Arc<Image>);

/// What a card does with its 2D requests ([`super::Display::twod`]).
pub trait TwoD: Send + Sync {
    /// Image `id` registered (the card maps it).
    fn image(&self, id: u32, image: &Arc<Image>) -> bool;
    /// Image `id` gone (the card unmaps it, its requests all done).
    fn free(&self, id: u32);
    /// The requests, in order, each with its source and destination
    /// images (checked to hold their rectangles); done when it returns.
    /// False: they failed (the client draws on the CPU).
    fn submit(&self, ops: &[Request]) -> bool;
}
